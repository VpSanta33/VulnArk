package database

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
	"vulnark/pkg/utils"
)

const adminCredentialsFile = "admin_credentials.txt"

// SchemaMigration records failures as well as successes. MySQL DDL is not
// transactional, so every migration must also be safe to retry after a failure.
type SchemaMigration struct {
	Version    string `gorm:"primaryKey;size:32"`
	Name       string `gorm:"size:150;not null"`
	Status     string `gorm:"size:20;not null"`
	StartedAt  time.Time
	FinishedAt *time.Time
	Error      string `gorm:"type:text"`
}

func (SchemaMigration) TableName() string { return "schema_migrations" }

// MigrationManager only mutates the database when RunMigrations is explicitly
// invoked. CheckMigrations is suitable for a runtime account without DDL grants.
type MigrationManager struct {
	db              *gorm.DB
	credentialsPath string
}

func NewMigrationManager() *MigrationManager {
	return &MigrationManager{db: DB, credentialsPath: adminCredentialsFile}
}

func RunMigrations() error   { return NewMigrationManager().RunMigrations() }
func CheckMigrations() error { return NewMigrationManager().CheckMigrations() }

type MigrationStep struct {
	Version  string
	Name     string
	Function func() error
}

func (m *MigrationManager) steps() []MigrationStep {
	return []MigrationStep{
		{"2026102801", "additive application schema", m.migrateSchema},
		{"2026102802", "knowledge tag associations and usage counts", m.backfillKnowledgeTags},
		{"2026102803", "canonical role permissions and authentication state", m.backfillAuthentication},
		{"2026102804", "missing default records and first administrator", m.seedInitialData},
		{"2026102805", "additive SLA retest and duplicate schema", m.migrateSchema},
		{"2026102806", "default SLA policies and feature permissions", m.seedFeatureDefaults},
		{"2026110301", "analytics and audit retention range indexes", m.addQueryIndexes},
		{"2026111001", "additive risk scoring and threat intelligence schema", m.migrateSchema},
		{"2026111002", "risk scoring permission", m.seedRiskDefaults},
	}
}

func (m *MigrationManager) addQueryIndexes() error {
	for _, value := range []interface{}{&model.Vulnerability{}, &model.Asset{}, &model.Report{}, &model.User{}, &model.AuditLog{}} {
		if err := createMissingIndexes(m.db, value); err != nil {
			return err
		}
	}
	return nil
}

func (m *MigrationManager) RunMigrations() error {
	if m.db == nil {
		return fmt.Errorf("数据库连接未初始化")
	}
	// MySQL advisory locks are connection-scoped. Pin the entire migration run
	// to that connection so two deployment processes cannot seed concurrently.
	if m.db.Dialector.Name() == "mysql" {
		return m.db.Connection(func(conn *gorm.DB) (result error) {
			// Connection supplies a mutable DB instance. Start a fresh session so
			// record-not-found/statement state cannot leak into following steps.
			conn = conn.Session(&gorm.Session{NewDB: true})
			var locked int
			if err := conn.Raw("SELECT GET_LOCK(CONCAT('vulnark:migrate:', LEFT(SHA2(DATABASE(), 256), 40)), 10)").Scan(&locked).Error; err != nil {
				return fmt.Errorf("获取迁移锁失败: %w", err)
			}
			if locked != 1 {
				return fmt.Errorf("另一个数据库迁移正在执行")
			}
			defer func() {
				var released int
				err := conn.Raw("SELECT RELEASE_LOCK(CONCAT('vulnark:migrate:', LEFT(SHA2(DATABASE(), 256), 40)))").Scan(&released).Error
				if err != nil {
					result = errors.Join(result, fmt.Errorf("释放迁移锁失败: %w", err))
				} else if released != 1 {
					result = errors.Join(result, fmt.Errorf("迁移锁未正常释放"))
				}
			}()
			copy := *m
			copy.db = conn
			return copy.runMigrations()
		})
	}
	return m.runMigrations()
}

func (m *MigrationManager) runMigrations() error {
	if err := m.db.AutoMigrate(&SchemaMigration{}); err != nil {
		return fmt.Errorf("创建迁移记录表失败: %w", err)
	}
	for _, step := range m.steps() {
		var previous SchemaMigration
		err := m.db.First(&previous, "version = ?", step.Version).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("读取迁移记录 %s 失败: %w", step.Version, err)
		}
		if err == nil && previous.Status == "applied" {
			continue
		}
		record := SchemaMigration{Version: step.Version, Name: step.Name, Status: "running", StartedAt: time.Now()}
		if err := m.db.Save(&record).Error; err != nil {
			return fmt.Errorf("记录迁移开始 %s 失败: %w", step.Version, err)
		}
		log.Printf("执行数据库迁移 %s (%s)", step.Version, step.Name)
		stepErr := step.Function()
		finished := time.Now()
		changes := map[string]interface{}{"status": "applied", "finished_at": finished, "error": ""}
		if stepErr != nil {
			changes["status"] = "failed"
			changes["error"] = stepErr.Error()
		}
		if err := m.db.Model(&SchemaMigration{}).Where("version = ?", step.Version).Updates(changes).Error; err != nil {
			return errors.Join(stepErr, fmt.Errorf("记录迁移结果 %s 失败: %w", step.Version, err))
		}
		if stepErr != nil {
			return fmt.Errorf("迁移 %s (%s) 失败，修复后重新运行 -migrate: %w", step.Version, step.Name, stepErr)
		}
	}
	return m.CheckMigrations()
}

// CheckMigrations performs SELECT/metadata queries only. It never creates the
// version table, seeds users, or repairs schema during normal startup.
func (m *MigrationManager) CheckMigrations() error {
	if m.db == nil {
		return fmt.Errorf("数据库连接未初始化")
	}
	if !m.db.Migrator().HasTable(&SchemaMigration{}) {
		return fmt.Errorf("数据库尚未迁移，请先使用部署账号执行 -migrate")
	}
	var records []SchemaMigration
	if err := m.db.Find(&records).Error; err != nil {
		return fmt.Errorf("读取迁移状态失败: %w", err)
	}
	statuses := make(map[string]string, len(records))
	for _, record := range records {
		statuses[record.Version] = record.Status
	}
	for _, step := range m.steps() {
		if statuses[step.Version] != "applied" {
			return fmt.Errorf("迁移 %s 未完成 (状态 %q)，请执行 -migrate", step.Version, statuses[step.Version])
		}
	}
	for _, value := range migrationModels() {
		stmt := &gorm.Statement{DB: m.db}
		if err := stmt.Parse(value); err != nil {
			return err
		}
		columns, err := m.db.Migrator().ColumnTypes(value)
		if err != nil {
			return fmt.Errorf("检查表 %s 失败，请执行 -migrate: %w", stmt.Table, err)
		}
		found := make(map[string]bool, len(columns))
		for _, column := range columns {
			found[column.Name()] = true
		}
		for _, field := range stmt.Schema.Fields {
			if field.DBName != "" && !field.IgnoreMigration && !found[field.DBName] {
				return fmt.Errorf("缺少字段 %s.%s，请执行 -migrate", stmt.Table, field.DBName)
			}
		}
		if err := ensureModelIndexes(m.db, value, false); err != nil {
			return err
		}
	}
	return nil
}

func migrationModels() []interface{} {
	return []interface{}{
		&model.Role{}, &model.User{}, &model.MFAChallenge{},
		&model.SystemSettings{}, &model.NotificationSettings{},
		&model.Asset{}, &model.OWASPCategory{}, &model.Vulnerability{},
		&model.VulnerabilityAttachment{}, &model.VulnerabilityAssignment{},
		&model.VulnerabilityTimeline{}, &model.AssignmentRule{},
		&model.KnowledgeBase{}, &model.Tag{}, &model.KnowledgeTag{}, &model.Template{},
		&model.Report{}, &model.ReportComment{}, &model.FileAttachment{}, &model.FileCleanupTask{},
		&model.Notification{}, &model.NotificationSetting{}, &model.EmailTemplate{}, &model.EmailLog{},
		&model.Permission{}, &model.RolePermission{}, &model.SystemConfig{}, &model.AuditLog{},
		&model.AIConfiguration{}, &model.AIProvider{}, &model.AIConversation{}, &model.AIMessage{},
		&model.SLAPolicy{}, &model.VulnerabilityRetest{}, &model.VulnerabilityDuplicateLink{}, &model.VulnerabilityDuplicateIgnore{},
		&model.RiskScoringConfig{}, &model.EPSSScore{}, &model.KEVEntry{}, &model.ThreatIntelSyncState{},
	}
}

// Use GORM's own naming strategy, including acronym handling and pluralization.
func getModelTableName(value interface{}) string {
	db := DB
	if db == nil {
		return getTableName(value)
	}
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(value); err != nil {
		return ""
	}
	return stmt.Table
}

func (m *MigrationManager) migrateSchema() error {
	if err := m.diagnoseIdentityDuplicates(); err != nil {
		return err
	}
	if m.db.Migrator().HasTable(&model.AIConversation{}) {
		var duplicates []struct {
			UserID    uint
			SessionID string
			Count     int64
		}
		if err := m.db.Model(&model.AIConversation{}).Select("user_id, session_id, COUNT(*) AS count").Group("user_id, session_id").Having("COUNT(*) > 1").Limit(10).Scan(&duplicates).Error; err != nil {
			return fmt.Errorf("检查AI会话唯一性失败: %w", err)
		}
		if len(duplicates) > 0 {
			return fmt.Errorf("ai_conversations(user_id, session_id) 有重复数据 %v，请人工合并后重试", duplicates)
		}
	}
	// Existing tables receive only missing columns/indexes. In particular, never
	// ask AutoMigrate to reinterpret and DROP legacy users/roles unique indexes.
	db := m.db.Session(&gorm.Session{})
	db.Config.IgnoreRelationshipsWhenMigrating = true
	db.Config.DisableForeignKeyConstraintWhenMigrating = true
	for _, value := range migrationModels() {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(value); err != nil {
			return err
		}
		if !db.Migrator().HasTable(value) {
			if err := db.Migrator().CreateTable(value); err != nil {
				return fmt.Errorf("创建表 %s 失败: %w", stmt.Table, err)
			}
			continue
		}
		columns, err := db.Migrator().ColumnTypes(value)
		if err != nil {
			return err
		}
		found := make(map[string]bool, len(columns))
		for _, column := range columns {
			found[column.Name()] = true
		}
		for _, field := range stmt.Schema.Fields {
			if field.DBName != "" && !field.IgnoreMigration && !found[field.DBName] {
				if err := db.Migrator().AddColumn(value, field.DBName); err != nil {
					return fmt.Errorf("添加字段 %s.%s 失败: %w", stmt.Table, field.DBName, err)
				}
			}
		}
		// Historical tag pairs must be cleaned before their unique index exists.
		if stmt.Table == "knowledge_tags" || stmt.Table == "tags" {
			continue
		}
		if err := createMissingIndexes(db, value); err != nil {
			return err
		}
	}
	return nil
}

func createMissingIndexes(db *gorm.DB, value interface{}) error {
	return ensureModelIndexes(db, value, true)
}

func ensureModelIndexes(db *gorm.DB, value interface{}, create bool) error {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(value); err != nil {
		return err
	}
	expected := stmt.Schema.ParseIndexes()
	if len(expected) == 0 {
		return nil
	}
	indexes, err := db.Migrator().GetIndexes(value)
	if err != nil {
		return fmt.Errorf("检查表 %s 索引失败: %w", stmt.Table, err)
	}
	byName := make(map[string]gorm.Index, len(indexes))
	for _, index := range indexes {
		byName[index.Name()] = index
	}
	for _, index := range expected {
		actual := byName[index.Name]
		if actual == nil {
			if !create {
				return fmt.Errorf("缺少索引 %s.%s，请执行 -migrate", stmt.Table, index.Name)
			}
			if err := db.Migrator().CreateIndex(value, index.Name); err != nil {
				return fmt.Errorf("创建索引 %s.%s 失败: %w", stmt.Table, index.Name, err)
			}
			continue
		}
		columns := actual.Columns()
		valid := len(columns) == len(index.Fields)
		for i, field := range index.Fields {
			if i >= len(columns) || columns[i] != field.DBName {
				valid = false
			}
		}
		if index.Class == "UNIQUE" {
			unique, known := actual.Unique()
			valid = valid && known && unique
		}
		if !valid {
			return fmt.Errorf("索引 %s.%s 的列或唯一性与模型不一致；请人工修复，迁移不会删除旧索引", stmt.Table, index.Name)
		}
	}
	return nil
}

func (m *MigrationManager) diagnoseIdentityDuplicates() error {
	for _, item := range []struct{ table, column string }{{"roles", "name"}, {"users", "username"}, {"users", "email"}} {
		if !m.db.Migrator().HasTable(item.table) || !m.db.Migrator().HasColumn(item.table, item.column) {
			continue
		}
		var duplicates []struct {
			Value string
			Count int64
		}
		if err := m.db.Table(item.table).Select("`" + item.column + "` AS value, COUNT(*) AS count").
			Group("`" + item.column + "`").Having("COUNT(*) > 1").Limit(10).Scan(&duplicates).Error; err != nil {
			return fmt.Errorf("检查 %s.%s 重复值失败: %w", item.table, item.column, err)
		}
		if len(duplicates) > 0 {
			return fmt.Errorf("%s.%s 有重复数据 %v；请人工修复后重试，迁移不会删除用户或角色", item.table, item.column, duplicates)
		}
		var emptyCount int64
		if err := m.db.Table(item.table).Where("`" + item.column + "` IS NULL OR TRIM(`" + item.column + "`) = ''").Count(&emptyCount).Error; err != nil {
			return err
		}
		if emptyCount > 0 {
			return fmt.Errorf("%s.%s 有 %d 条空值；请人工修复后重试", item.table, item.column, emptyCount)
		}
	}
	return nil
}

func (m *MigrationManager) backfillKnowledgeTags() error {
	if err := m.db.Transaction(func(tx *gorm.DB) error {
		// Select only scalar columns: old JSON scanners are irrelevant to this migration.
		var knowledge []struct {
			ID       uint
			Tags     string
			AuthorID uint
		}
		if err := tx.Model(&model.KnowledgeBase{}).Select("id, tags, author_id").Order("id").Scan(&knowledge).Error; err != nil {
			return err
		}
		var tags []model.Tag
		if err := tx.Order("id").Find(&tags).Error; err != nil {
			return err
		}
		var links []model.KnowledgeTag
		if err := tx.Select("id, knowledge_id, tag_id").Order("id").Find(&links).Error; err != nil {
			return err
		}
		validKnowledge := make(map[uint]bool, len(knowledge))
		for _, entry := range knowledge {
			validKnowledge[entry.ID] = true
		}
		canonical := make(map[string]*model.Tag)
		byID := make(map[uint]*model.Tag)
		aliases := make(map[uint]uint)
		var blankTagIDs []uint
		for i := range tags {
			tag := &tags[i]
			name := strings.TrimSpace(tag.Name)
			if name == "" {
				blankTagIDs = append(blankTagIDs, tag.ID)
				continue
			}
			existing := canonical[name]
			if existing == nil {
				// Respect the database's collation as well as Go's whitespace
				// normalization (MySQL names are commonly case-insensitive).
				var first model.Tag
				err := tx.Where("TRIM(name) = ?", name).Order("id").First(&first).Error
				if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				if err == nil {
					existing = byID[first.ID]
				}
			}
			if existing != nil {
				aliases[tag.ID] = existing.ID
				canonical[name] = existing
				continue
			}
			canonical[name] = tag
			byID[tag.ID] = tag
		}
		// Remove old links first so legacy foreign keys permit tag deduplication.
		// The transaction restores them if any later backfill operation fails.
		if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&model.KnowledgeTag{}).Error; err != nil {
			return err
		}
		if len(blankTagIDs) > 0 {
			if err := tx.Delete(&model.Tag{}, blankTagIDs).Error; err != nil {
				return err
			}
		}
		// Merge exact/trimmed duplicate tag records before canonicalizing names.
		for oldID, newID := range aliases {
			for i := range links {
				if links[i].TagID == oldID {
					links[i].TagID = newID
				}
			}
			if err := tx.Delete(&model.Tag{}, oldID).Error; err != nil {
				return err
			}
		}
		for _, tag := range byID {
			name := strings.TrimSpace(tag.Name)
			if tag.Name != name {
				if err := tx.Model(&model.Tag{}).Where("id = ?", tag.ID).Update("name", name).Error; err != nil {
					return err
				}
				tag.Name = name
			}
		}
		pairs := make(map[[2]uint]bool)
		ordered := make(map[uint][]uint)
		add := func(knowledgeID, tagID uint) {
			pair := [2]uint{knowledgeID, tagID}
			if !pairs[pair] {
				pairs[pair] = true
				ordered[knowledgeID] = append(ordered[knowledgeID], tagID)
			}
		}
		// Text retains its order; valid relational-only tags are appended below.
		for _, entry := range knowledge {
			for _, raw := range strings.Split(entry.Tags, ",") {
				name := strings.TrimSpace(raw)
				if name == "" {
					continue
				}
				tag := canonical[name]
				if tag == nil {
					// Database lookup respects MySQL's configured name collation.
					var found model.Tag
					err := tx.Where("name = ?", name).First(&found).Error
					if errors.Is(err, gorm.ErrRecordNotFound) {
						found = model.Tag{Name: name, DisplayName: name, CreatorID: entry.AuthorID}
						if err := tx.Create(&found).Error; err != nil {
							return err
						}
					} else if err != nil {
						return err
					}
					tag = &found
					canonical[name] = tag
					byID[tag.ID] = tag
				}
				add(entry.ID, tag.ID)
			}
		}
		for _, link := range links {
			if validKnowledge[link.KnowledgeID] && byID[link.TagID] != nil {
				add(link.KnowledgeID, link.TagID)
			}
		}
		// Rebuild inside one transaction, eliminating duplicate and orphan pairs.
		counts := make(map[uint]int)
		for _, entry := range knowledge {
			var names []string
			for _, tagID := range ordered[entry.ID] {
				if err := tx.Omit(clause.Associations).Create(&model.KnowledgeTag{KnowledgeID: entry.ID, TagID: tagID}).Error; err != nil {
					return err
				}
				names = append(names, byID[tagID].Name)
				counts[tagID]++
			}
			if err := tx.Model(&model.KnowledgeBase{}).Where("id = ?", entry.ID).UpdateColumn("tags", strings.Join(names, ",")).Error; err != nil {
				return err
			}
		}
		if err := tx.Model(&model.Tag{}).Where("1 = 1").UpdateColumn("usage_count", 0).Error; err != nil {
			return err
		}
		for tagID, count := range counts {
			if err := tx.Model(&model.Tag{}).Where("id = ?", tagID).UpdateColumn("usage_count", count).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := createMissingIndexes(m.db, &model.Tag{}); err != nil {
		return err
	}
	return createMissingIndexes(m.db, &model.KnowledgeTag{})
}

func (m *MigrationManager) backfillAuthentication() error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		var roles []struct {
			ID          uint
			Permissions interface{}
		}
		// database/sql can return JSON as either a string or []byte.
		rows, err := tx.Model(&model.Role{}).Select("id, permissions").Rows()
		if err != nil {
			return err
		}
		for rows.Next() {
			var role struct {
				ID          uint
				Permissions interface{}
			}
			if err := rows.Scan(&role.ID, &role.Permissions); err != nil {
				_ = rows.Close()
				return err
			}
			roles = append(roles, role)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, role := range roles {
			var permissions []string
			switch value := role.Permissions.(type) {
			case []byte:
				if len(value) > 0 {
					if err := json.Unmarshal(value, &permissions); err != nil {
						return fmt.Errorf("角色 %d 权限JSON无效: %w", role.ID, err)
					}
				}
			case string:
				if strings.TrimSpace(value) != "" {
					if err := json.Unmarshal([]byte(value), &permissions); err != nil {
						return fmt.Errorf("角色 %d 权限JSON无效: %w", role.ID, err)
					}
				}
			case nil:
			default:
				return fmt.Errorf("角色 %d 权限JSON类型不支持", role.ID)
			}
			if len(permissions) == 0 {
				if err := tx.Table("permissions").Select("permissions.name").
					Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
					Where("role_permissions.role_id = ? AND permissions.is_active = ?", role.ID, true).
					Order("permissions.id").Pluck("permissions.name", &permissions).Error; err != nil {
					return err
				}
			}
			canonical := make(model.Permissions, 0, len(permissions))
			seen := make(map[string]bool)
			for _, permission := range permissions {
				// Do not trim or discard explicit entries: turning " * " into "*"
				// would grant new authority, while emptying non-empty JSON could
				// resurrect legacy join grants after a retried failed migration.
				permission = model.NormalizePermission(permission)
				if !seen[permission] {
					canonical = append(canonical, permission)
					seen[permission] = true
				}
			}
			if err := tx.Model(&model.Role{}).Where("id = ?", role.ID).UpdateColumn("permissions", canonical).Error; err != nil {
				return err
			}
		}
		if err := tx.Model(&model.User{}).Where("token_version IS NULL OR token_version < 1").UpdateColumn("token_version", 1).Error; err != nil {
			return err
		}
		// HEX makes prefix comparison byte-exact even under MySQL's default
		// case-insensitive collation; the encryption decoder accepts only v1:.
		return tx.Model(&model.User{}).Where("two_factor_enabled = ? AND (two_factor_secret IS NULL OR HEX(SUBSTR(two_factor_secret, 1, 3)) <> ?)", true, "76313A").UpdateColumn("two_factor_needs_rebind", true).Error
	})
}

func (m *MigrationManager) seedInitialData() error {
	if err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := seedPermissions(tx); err != nil {
			return err
		}
		for _, role := range []model.Role{
			{Name: "管理员", Description: "系统管理员，拥有所有权限", Permissions: model.Permissions{"*"}},
			{Name: "开发工程师", Description: "开发工程师，可以管理漏洞和资产", Permissions: model.Permissions{"vuln:*", "asset:*", "report:read", "knowledge:*"}},
			{Name: "普通用户", Description: "普通用户，只能查看和提交漏洞", Permissions: model.Permissions{"vuln:read", "vuln:create", "asset:read", "report:read", "knowledge:read"}},
		} {
			if err := tx.Where("name = ?", role.Name).FirstOrCreate(&role).Error; err != nil {
				return err
			}
		}
		return seedSystemConfigs(tx)
	}); err != nil {
		return err
	}
	// An existing installation must never gain an unexpected admin account.
	var userCount int64
	if err := m.db.Model(&model.User{}).Count(&userCount).Error; err != nil {
		return err
	}
	if userCount > 0 {
		return nil
	}
	var role model.Role
	if err := m.db.Where("name = ?", "管理员").First(&role).Error; err != nil {
		return err
	}
	if len(role.Permissions) != 1 || role.Permissions[0] != "*" {
		return fmt.Errorf("现有管理员角色为自定义权限，请人工创建首位用户")
	}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("生成管理员随机密码失败: %w", err)
	}
	password := base64.RawURLEncoding.EncodeToString(secret)
	hash, err := utils.HashPassword(password)
	if err != nil {
		return err
	}
	// Fail before creating an account if credentials cannot be saved. O_EXCL
	// prevents overwriting previous credentials or following a symlink.
	path := m.credentialsPath
	if path == "" {
		path = adminCredentialsFile
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("创建管理员凭证文件失败 (不会覆盖已有文件): %w", err)
	}
	content := fmt.Sprintf("VulnArk 管理员凭证\n生成时间: %s\n用户名: admin\n密码: %s\n邮箱: admin@vulnark.local\n请首次登录后修改密码并删除此文件。\n", time.Now().Format(time.RFC3339), password)
	if _, err = file.WriteString(content); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.Join(fmt.Errorf("保存管理员凭证失败: %w", err), removeFailedCredentials(path))
	}
	admin := &model.User{Username: "admin", Email: "admin@vulnark.local", RealName: "系统管理员", PasswordHash: hash, RoleID: role.ID, Department: "系统管理", Status: 1, TokenVersion: 1}
	if err := m.db.Omit(clause.Associations).Create(admin).Error; err != nil {
		return errors.Join(fmt.Errorf("创建首位管理员失败: %w", err), removeFailedCredentials(path))
	}
	log.Printf("已创建首位管理员；凭证保存在 %s (0600)，首次登录后请修改密码并删除文件", path)
	return nil
}

func removeFailedCredentials(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清理未生效的管理员凭证文件失败: %w", err)
	}
	return nil
}

func seedPermissions(tx *gorm.DB) error {
	modules := map[string][]string{
		"user":         {"create", "read", "update", "delete", "manage"},
		"role":         {"create", "read", "update", "delete", "assign", "manage"},
		"asset":        {"create", "read", "update", "delete", "import", "export"},
		"vuln":         {"create", "read", "update", "delete", "manage", "assign"},
		"report":       {"create", "read", "update", "delete", "review", "download"},
		"knowledge":    {"create", "read", "update", "delete"},
		"notification": {"create", "read", "manage"},
		"email":        {"manage"},
		"tag":          {"manage"},
		"template":     {"manage"},
		"analytics":    {"read", "export"},
		"api":          {"test"},
		"system":       {"config", "audit", "permission"},
	}
	keys := make([]string, 0, len(modules))
	for module := range modules {
		keys = append(keys, module)
	}
	sort.Strings(keys)
	for _, module := range keys {
		for _, action := range modules[module] {
			permission := model.Permission{Name: module + ":" + action, DisplayName: module + ":" + action, Module: module, Action: action, Resource: module, IsActive: true}
			if module == "vuln" {
				permission.Resource = "vulnerability"
			}
			if err := tx.Where("name = ?", permission.Name).FirstOrCreate(&permission).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *MigrationManager) seedFeatureDefaults() error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		for _, permission := range []model.Permission{
			{Name: "sla:manage", DisplayName: "管理SLA策略", Module: "sla", Action: "manage", Resource: "sla", IsActive: true},
			{Name: "vuln:verify", DisplayName: "复测漏洞", Module: "vuln", Action: "verify", Resource: "vulnerability", IsActive: true},
		} {
			if err := tx.Where("name = ?", permission.Name).FirstOrCreate(&permission).Error; err != nil {
				return err
			}
		}

		for _, policy := range []model.SLAPolicy{
			{Name: "严重漏洞默认SLA", SeverityLevel: model.SeverityCritical, ResponseHours: 1, FixHours: 24, Enabled: true},
			{Name: "高危漏洞默认SLA", SeverityLevel: model.SeverityHigh, ResponseHours: 4, FixHours: 72, Enabled: true},
			{Name: "中危漏洞默认SLA", SeverityLevel: model.SeverityMedium, ResponseHours: 24, FixHours: 168, Enabled: true},
			{Name: "低危漏洞默认SLA", SeverityLevel: model.SeverityLow, ResponseHours: 72, FixHours: 720, Enabled: true},
		} {
			var existing model.SLAPolicy
			err := tx.Where("severity_level = ? AND asset_id IS NULL AND department = ''", policy.SeverityLevel).First(&existing).Error
			if err == nil {
				continue
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if err := tx.Create(&policy).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// seedRiskDefaults only adds the permission to the catalog. The scoring model
// falls back to built-in defaults until an administrator saves one, and
// existing vulnerabilities are scored by the background pass after start-up.
func (m *MigrationManager) seedRiskDefaults() error {
	permission := model.Permission{Name: "risk:manage", DisplayName: "管理风险评分模型", Module: "risk", Action: "manage", Resource: "risk", IsActive: true}
	return m.db.Where("name = ?", permission.Name).FirstOrCreate(&permission).Error
}

func seedSystemConfigs(tx *gorm.DB) error {
	for _, cfg := range []model.SystemConfig{
		{Key: "system.name", Value: model.ConfigValue{"value": "VulnArk漏洞管理系统"}, Type: model.ConfigTypeString, Category: model.ConfigCategorySystem, DisplayName: "系统名称", IsPublic: true, IsEditable: true, DefaultValue: model.ConfigValue{"value": "VulnArk漏洞管理系统"}},
		{Key: "system.version", Value: model.ConfigValue{"value": "1.0.0"}, Type: model.ConfigTypeString, Category: model.ConfigCategorySystem, DisplayName: "系统版本", IsPublic: true, IsEditable: false, DefaultValue: model.ConfigValue{"value": "1.0.0"}},
		{Key: "security.password_min_length", Value: model.ConfigValue{"value": 8}, Type: model.ConfigTypeInt, Category: model.ConfigCategorySecurity, DisplayName: "密码最小长度", IsEditable: true, DefaultValue: model.ConfigValue{"value": 8}},
	} {
		if err := tx.Where("`key` = ?", cfg.Key).FirstOrCreate(&cfg).Error; err != nil {
			return err
		}
	}
	return nil
}
