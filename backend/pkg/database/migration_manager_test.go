package database

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
	"vulnark/pkg/utils"
)

var migrationTestSequence atomic.Uint64

func newMigrationTestManager(t *testing.T) *MigrationManager {
	t.Helper()
	dsn := fmt.Sprintf("file:migration_test_%d?mode=memory&cache=shared", migrationTestSequence.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	pool, err := db.DB()
	require.NoError(t, err)
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	return &MigrationManager{db: db, credentialsPath: filepath.Join(t.TempDir(), adminCredentialsFile)}
}

func migrationCount(t *testing.T, db *gorm.DB, value interface{}) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(value).Count(&count).Error)
	return count
}

func TestMigrationsEmptyDatabaseAndIdempotentAdministrator(t *testing.T) {
	m := newMigrationTestManager(t)
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.CheckMigrations())
	require.EqualValues(t, len(m.steps()), migrationCount(t, m.db, &SchemaMigration{}))
	require.EqualValues(t, 1, migrationCount(t, m.db, &model.User{}))
	for _, value := range []interface{}{&model.KnowledgeTag{}, &model.MFAChallenge{}, &model.FileCleanupTask{}, &model.AIConversation{}} {
		require.True(t, m.db.Migrator().HasTable(value))
	}
	info, err := os.Stat(m.credentialsPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	credentials, err := os.ReadFile(m.credentialsPath)
	require.NoError(t, err)
	password := ""
	for _, line := range strings.Split(string(credentials), "\n") {
		if strings.HasPrefix(line, "密码: ") {
			password = strings.TrimPrefix(line, "密码: ")
		}
	}
	require.Len(t, password, 32)
	require.NotContains(t, output.String(), password)
	var admin model.User
	require.NoError(t, m.db.First(&admin, "username = ?", "admin").Error)
	require.True(t, utils.CheckPassword(password, admin.PasswordHash))
	require.EqualValues(t, 1, admin.TokenVersion)
	require.NoError(t, m.RunMigrations())
	require.EqualValues(t, 1, migrationCount(t, m.db, &model.User{}))
	unchanged, err := os.ReadFile(m.credentialsPath)
	require.NoError(t, err)
	require.Equal(t, credentials, unchanged)
	var again model.User
	require.NoError(t, m.db.First(&again, admin.ID).Error)
	require.Equal(t, admin.PasswordHash, again.PasswordHash)
}

func TestMigrationsCheckDoesNotWrite(t *testing.T) {
	m := newMigrationTestManager(t)
	require.ErrorContains(t, m.CheckMigrations(), "-migrate")
	require.False(t, m.db.Migrator().HasTable(&SchemaMigration{}))
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.db.Exec("PRAGMA query_only = ON").Error)
	require.NoError(t, m.CheckMigrations())
	require.Error(t, m.db.Exec("CREATE TABLE forbidden_write (id integer)").Error)
}

func TestMigrationsDuplicateIdentityStopsAndRecordsFailure(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.db.Exec("CREATE TABLE users (id integer PRIMARY KEY, username text, email text)").Error)
	require.NoError(t, m.db.Exec("INSERT INTO users VALUES (1, 'duplicate', 'first@example.com'), (2, 'duplicate', 'second@example.com')").Error)
	err := m.RunMigrations()
	require.ErrorContains(t, err, "users.username")
	require.EqualValues(t, 2, migrationCount(t, m.db, &model.User{}))
	require.False(t, m.db.Migrator().HasTable(&model.KnowledgeBase{}))
	require.Error(t, m.CheckMigrations())
	var records []SchemaMigration
	require.NoError(t, m.db.Find(&records).Error)
	require.Len(t, records, 1)
	require.Equal(t, "failed", records[0].Status)
	require.Contains(t, records[0].Error, "users.username")
	require.NotNil(t, records[0].FinishedAt)
	require.NoError(t, m.db.Exec("UPDATE users SET username = 'resolved' WHERE id = 2").Error)
	// Diagnostic success does not delete either identity.
	require.NoError(t, m.diagnoseIdentityDuplicates())
	require.EqualValues(t, 2, migrationCount(t, m.db, &model.User{}))
}

func seedMigrationIdentity(t *testing.T, m *MigrationManager) uint {
	t.Helper()
	role := &model.Role{Name: "custom", Permissions: model.Permissions{"knowledge:read"}}
	require.NoError(t, m.db.Create(role).Error)
	user := &model.User{Username: "existing", Email: "existing@example.com", PasswordHash: "unchanged", RealName: "Existing", RoleID: role.ID, TokenVersion: 1}
	require.NoError(t, m.db.Create(user).Error)
	return user.ID
}

func TestMigrationSeedsFillMissingRecordsPreserveExistingRolesAndUsers(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.migrateSchema())
	seedMigrationIdentity(t, m)
	custom := &model.Role{Name: "管理员", Description: "custom description", Permissions: model.Permissions{"vuln:read"}}
	require.NoError(t, m.db.Create(custom).Error)
	permission := &model.Permission{Name: "vuln:read", DisplayName: "custom display", Module: "vuln", Action: "read", Resource: "vulnerability", IsActive: false}
	require.NoError(t, m.db.Create(permission).Error)
	require.NoError(t, m.db.Model(permission).UpdateColumn("is_active", false).Error)
	require.NoError(t, m.seedInitialData())
	require.NoError(t, m.seedInitialData())
	var role model.Role
	require.NoError(t, m.db.First(&role, custom.ID).Error)
	require.Equal(t, custom.Permissions, role.Permissions)
	require.Equal(t, "custom description", role.Description)
	var existing model.Permission
	require.NoError(t, m.db.First(&existing, permission.ID).Error)
	require.False(t, existing.IsActive)
	require.Equal(t, "custom display", existing.DisplayName)
	for _, action := range []string{"create", "read", "update", "delete", "assign", "manage"} {
		var count int64
		require.NoError(t, m.db.Model(&model.Permission{}).Where("name = ?", "vuln:"+action).Count(&count).Error)
		require.EqualValues(t, 1, count)
	}
	require.EqualValues(t, 1, migrationCount(t, m.db, &model.User{}))
	_, err := os.Stat(m.credentialsPath)
	require.True(t, os.IsNotExist(err))
}

func TestMigrationCredentialsNeverOverwrite(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.migrateSchema())
	require.NoError(t, os.WriteFile(m.credentialsPath, []byte("existing credentials"), 0600))
	require.ErrorContains(t, m.seedInitialData(), "不会覆盖")
	require.Zero(t, migrationCount(t, m.db, &model.User{}))
	content, err := os.ReadFile(m.credentialsPath)
	require.NoError(t, err)
	require.Equal(t, "existing credentials", string(content))
}

func TestMigrationKnowledgeTagsBackfillDeduplicateAndRecount(t *testing.T) {
	m := newMigrationTestManager(t)
	// Simulate old association/tag tables that never had unique indexes.
	require.NoError(t, m.db.Exec("CREATE TABLE knowledge_tags (id integer PRIMARY KEY, knowledge_id integer NOT NULL, tag_id integer NOT NULL)").Error)
	require.NoError(t, m.db.Exec("CREATE TABLE tags (id integer PRIMARY KEY, name text NOT NULL)").Error)
	require.NoError(t, m.migrateSchema())
	userID := seedMigrationIdentity(t, m)
	require.NoError(t, m.db.Exec("INSERT INTO tags(id,name,display_name,creator_id,usage_count) VALUES (1,' alpha ','alpha',?,99), (2,'alpha','alpha',?,99), (3,'beta','beta',?,99), (4,'orphan','orphan',?,99)", userID, userID, userID, userID).Error)
	first := &model.KnowledgeBase{Title: "first", Content: "body", Category: "security", Type: "article", AuthorID: userID, Tags: " alpha,alpha, beta ,new,,new "}
	second := &model.KnowledgeBase{Title: "second", Content: "body", Category: "security", Type: "article", AuthorID: userID, Tags: "beta"}
	require.NoError(t, m.db.Create(first).Error)
	require.NoError(t, m.db.Create(second).Error)
	require.NoError(t, m.db.Exec("INSERT INTO knowledge_tags(knowledge_id,tag_id) VALUES (?,1),(?,2),(?,3),(?,3),(?,4),(999,4),(?,999)", first.ID, first.ID, first.ID, first.ID, second.ID, first.ID).Error)
	require.NoError(t, m.backfillKnowledgeTags())
	require.NoError(t, m.backfillKnowledgeTags())
	var texts []struct {
		ID   uint
		Tags string
	}
	require.NoError(t, m.db.Model(&model.KnowledgeBase{}).Select("id,tags").Order("id").Scan(&texts).Error)
	require.Equal(t, "alpha,beta,new", texts[0].Tags)
	require.Equal(t, "beta,orphan", texts[1].Tags)
	require.EqualValues(t, 5, migrationCount(t, m.db, &model.KnowledgeTag{}))
	var tags []model.Tag
	require.NoError(t, m.db.Order("id").Find(&tags).Error)
	counts := map[string]int{}
	for _, tag := range tags {
		counts[tag.Name] = tag.UsageCount
	}
	require.Equal(t, map[string]int{"alpha": 1, "beta": 2, "new": 1, "orphan": 1}, counts)
	require.Error(t, m.db.Create(&model.KnowledgeTag{KnowledgeID: first.ID, TagID: 1}).Error)
}

func TestMigrationRoleJSONIsAuthorityAndMFABackfill(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.migrateSchema())
	userID := seedMigrationIdentity(t, m)
	read := &model.Permission{Name: "vulnerability:read", DisplayName: "read", Module: "vulnerability", Action: "read", Resource: "vulnerability", IsActive: true}
	write := &model.Permission{Name: "vuln:delete", DisplayName: "delete", Module: "vuln", Action: "delete", Resource: "vulnerability", IsActive: true}
	require.NoError(t, m.db.Create(read).Error)
	require.NoError(t, m.db.Create(write).Error)
	explicit := &model.Role{Name: "explicit", Permissions: model.Permissions{"vulnerability:read"}}
	empty := &model.Role{Name: "legacy", Permissions: model.Permissions{}}
	require.NoError(t, m.db.Create(explicit).Error)
	require.NoError(t, m.db.Create(empty).Error)
	for _, link := range []model.RolePermission{{RoleID: explicit.ID, PermissionID: write.ID}, {RoleID: empty.ID, PermissionID: read.ID}, {RoleID: empty.ID, PermissionID: read.ID}} {
		require.NoError(t, m.db.Create(&link).Error)
	}
	require.NoError(t, m.db.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]interface{}{"token_version": 0, "two_factor_enabled": true, "two_factor_secret": "old-fake-secret"}).Error)
	require.NoError(t, m.backfillAuthentication())
	require.NoError(t, m.backfillAuthentication())
	for _, id := range []uint{explicit.ID, empty.ID} {
		var role model.Role
		require.NoError(t, m.db.First(&role, id).Error)
		require.Equal(t, model.Permissions{"vuln:read"}, role.Permissions)
	}
	var user model.User
	require.NoError(t, m.db.First(&user, userID).Error)
	require.EqualValues(t, 1, user.TokenVersion)
	require.True(t, user.TwoFactorNeedsRebind)
	require.Empty(t, user.TwoFactorPendingSecret)

	// Unknown entries remain explicit deny-like entries; whitespace cannot turn
	// into a wildcard or empty JSON eligible for old relation backfill.
	require.NoError(t, m.db.Model(explicit).UpdateColumn("permissions", model.Permissions{" * ", "", " "}).Error)
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.RunMigrations())
	var explicitAgain model.Role
	require.NoError(t, m.db.First(&explicitAgain, explicit.ID).Error)
	require.Equal(t, model.Permissions{" * ", "", " "}, explicitAgain.Permissions)
	require.False(t, model.PermissionGranted(explicitAgain.Permissions, "vuln:delete"))
}

func TestMigrationUsesGORMNamesAndPreservesLegacyUniqueIndexes(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.db.Exec("CREATE TABLE roles(id integer PRIMARY KEY, name text NOT NULL)").Error)
	require.NoError(t, m.db.Exec("CREATE UNIQUE INDEX uni_roles_name ON roles(name)").Error)
	require.NoError(t, m.db.Exec("CREATE TABLE users(id integer PRIMARY KEY, username text NOT NULL, email text NOT NULL)").Error)
	require.NoError(t, m.db.Exec("CREATE UNIQUE INDEX uni_users_username ON users(username)").Error)
	require.NoError(t, m.db.Exec("CREATE UNIQUE INDEX uni_users_email ON users(email)").Error)
	require.NoError(t, m.migrateSchema())
	require.NoError(t, m.migrateSchema())
	for _, item := range []struct {
		model interface{}
		index string
	}{{&model.Role{}, "uni_roles_name"}, {&model.User{}, "uni_users_username"}, {&model.User{}, "uni_users_email"}} {
		require.True(t, m.db.Migrator().HasIndex(item.model, item.index))
	}
	require.Equal(t, "file_cleanup_tasks", getTableName(&model.FileCleanupTask{}))
	require.Equal(t, "ai_conversations", getTableName(&model.AIConversation{}))
	require.Equal(t, "ai_configurations", getTableName(&model.AIConfiguration{}))
}

func TestMigrationRejectsWrongNamedUniqueIndex(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.db.Exec("CREATE TABLE roles(id integer PRIMARY KEY, name text NOT NULL)").Error)
	require.NoError(t, m.db.Exec("CREATE INDEX idx_role_name ON roles(name)").Error)
	require.ErrorContains(t, m.RunMigrations(), "唯一性与模型不一致")
	// A misleading non-unique index must never be accepted based on name alone.
	indexes, err := m.db.Migrator().GetIndexes(&model.Role{})
	require.NoError(t, err)
	require.Len(t, indexes, 1)
	unique, ok := indexes[0].Unique()
	require.True(t, ok)
	require.False(t, unique)
}

func TestMigrationTagBackfillFailureRollsBackTextLinksAndCounts(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.migrateSchema())
	userID := seedMigrationIdentity(t, m)
	tag := &model.Tag{Name: "existing", DisplayName: "existing", CreatorID: userID, UsageCount: 7}
	require.NoError(t, m.db.Create(tag).Error)
	knowledge := &model.KnowledgeBase{Title: "legacy", Content: "body", Category: "security", Type: "article", AuthorID: userID, Tags: "new,existing,existing"}
	require.NoError(t, m.db.Create(knowledge).Error)
	require.NoError(t, m.db.Create(&model.KnowledgeTag{KnowledgeID: knowledge.ID, TagID: tag.ID}).Error)
	require.NoError(t, m.db.Exec("CREATE TRIGGER reject_tag_recount BEFORE UPDATE OF usage_count ON tags BEGIN SELECT RAISE(ABORT, 'forced recount failure'); END").Error)
	require.ErrorContains(t, m.backfillKnowledgeTags(), "forced recount failure")
	var original struct{ Tags string }
	require.NoError(t, m.db.Model(&model.KnowledgeBase{}).Select("tags").First(&original, knowledge.ID).Error)
	require.Equal(t, knowledge.Tags, original.Tags)
	require.EqualValues(t, 1, migrationCount(t, m.db, &model.Tag{}))
	require.EqualValues(t, 1, migrationCount(t, m.db, &model.KnowledgeTag{}))
	var count int
	require.NoError(t, m.db.Model(tag).Select("usage_count").Scan(&count).Error)
	require.Equal(t, 7, count)
}

func TestMigrationUpgradesAppliedFirstFourVersionsAdditively(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.migrateSchema())
	userID := seedMigrationIdentity(t, m)
	var user model.User
	require.NoError(t, m.db.Preload("Role").First(&user, userID).Error)

	asset := &model.Asset{Name: "legacy-asset", Type: "server", Status: 1}
	require.NoError(t, m.db.Create(asset).Error)
	discoveredAt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	vulnerability := &model.Vulnerability{Title: "legacy-vuln", SeverityLevel: model.SeverityCritical, AssetID: asset.ID, Status: model.StatusNew, DiscoveredAt: discoveredAt}
	require.NoError(t, m.db.Create(vulnerability).Error)
	// Remove only columns and tables introduced after versions 01-04.
	require.NoError(t, m.db.Migrator().DropIndex(&model.Notification{}, "idx_notifications_dedup_key"))
	require.NoError(t, m.db.Migrator().DropColumn(&model.Notification{}, "DedupKey"))
	for _, column := range []string{
		"ResponseDueAt", "FixDueAt", "FirstResponseAt", "PausedSeconds", "PauseStartedAt", "PauseEndedAt",
		"ResponseOverdue", "FixOverdue", "ResponseOverdueLevel", "FixOverdueLevel", "SLAPolicyID", "SLAPolicyName", "SLACycle",
	} {
		require.NoError(t, m.db.Migrator().DropColumn(&model.Vulnerability{}, column))
	}
	require.NoError(t, m.db.Migrator().DropTable(&model.VulnerabilityRetest{}, &model.VulnerabilityDuplicateIgnore{}, &model.VulnerabilityDuplicateLink{}, &model.SLAPolicy{}))
	require.NoError(t, m.db.AutoMigrate(&SchemaMigration{}))
	for _, step := range m.steps()[:4] {
		record := SchemaMigration{Version: step.Version, Name: step.Name, Status: "applied", StartedAt: time.Now(), FinishedAt: ptrTime(time.Now())}
		require.NoError(t, m.db.Create(&record).Error)
	}

	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.CheckMigrations())
	for _, value := range []interface{}{
		&model.SLAPolicy{}, &model.VulnerabilityRetest{}, &model.VulnerabilityDuplicateLink{}, &model.VulnerabilityDuplicateIgnore{},
	} {
		require.True(t, m.db.Migrator().HasTable(value))
	}
	for _, column := range []string{"response_due_at", "fix_due_at", "sla_policy_id", "sla_policy_name", "sla_cycle"} {
		require.True(t, m.db.Migrator().HasColumn(&model.Vulnerability{}, column), column)
	}
	require.True(t, m.db.Migrator().HasColumn(&model.Notification{}, "dedup_key"))

	var preservedUser model.User
	require.NoError(t, m.db.Preload("Role").First(&preservedUser, userID).Error)
	require.Equal(t, "existing", preservedUser.Username)
	require.Equal(t, model.Permissions{"knowledge:read"}, preservedUser.Role.Permissions)
	var preservedVulnerability model.Vulnerability
	require.NoError(t, m.db.First(&preservedVulnerability, vulnerability.ID).Error)
	require.Equal(t, "legacy-vuln", preservedVulnerability.Title)
	require.Equal(t, model.StatusNew, preservedVulnerability.Status)
	require.Nil(t, preservedVulnerability.ResponseDueAt)
	require.Nil(t, preservedVulnerability.FixDueAt)
	require.False(t, preservedVulnerability.ResponseOverdue)
	require.False(t, preservedVulnerability.FixOverdue)

	for _, expected := range []struct{ severity, response, fix int }{{1, 1, 24}, {2, 4, 72}, {3, 24, 168}, {4, 72, 720}} {
		var policies []model.SLAPolicy
		require.NoError(t, m.db.Where("severity_level = ? AND asset_id IS NULL AND department = ''", expected.severity).Find(&policies).Error)
		require.Len(t, policies, 1)
		require.Equal(t, expected.response, policies[0].ResponseHours)
		require.Equal(t, expected.fix, policies[0].FixHours)
	}
	for _, name := range []string{"sla:manage", "vuln:verify"} {
		var count int64
		require.NoError(t, m.db.Model(&model.Permission{}).Where("name = ?", name).Count(&count).Error)
		require.EqualValues(t, 1, count)
	}
	require.NoError(t, m.RunMigrations())
	require.EqualValues(t, 4, migrationCount(t, m.db, &model.SLAPolicy{}))
}

func TestFeatureDefaultsPreserveExistingPoliciesAndPermissions(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.migrateSchema())
	custom := &model.SLAPolicy{Name: "custom critical SLA", SeverityLevel: model.SeverityCritical, ResponseHours: 9, FixHours: 99, Enabled: false}
	require.NoError(t, m.db.Create(custom).Error)
	role := &model.Role{Name: "custom role", Permissions: model.Permissions{"vuln:read"}}
	require.NoError(t, m.db.Create(role).Error)

	require.NoError(t, m.seedFeatureDefaults())
	require.NoError(t, m.seedFeatureDefaults())
	var preserved model.SLAPolicy
	require.NoError(t, m.db.First(&preserved, custom.ID).Error)
	require.Equal(t, "custom critical SLA", preserved.Name)
	require.Equal(t, 9, preserved.ResponseHours)
	require.Equal(t, 99, preserved.FixHours)
	require.False(t, preserved.Enabled)
	var count int64
	require.NoError(t, m.db.Model(&model.SLAPolicy{}).Where("severity_level = ? AND asset_id IS NULL AND department = ''", model.SeverityCritical).Count(&count).Error)
	require.EqualValues(t, 1, count)
	var unchanged model.Role
	require.NoError(t, m.db.First(&unchanged, role.ID).Error)
	require.Equal(t, model.Permissions{"vuln:read"}, unchanged.Permissions)
	require.EqualValues(t, 4, migrationCount(t, m.db, &model.SLAPolicy{}))
}

func ptrTime(value time.Time) *time.Time { return &value }

func TestMigrationInvalidPermissionJSONStopsBeforeSeeding(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.migrateSchema())
	seedMigrationIdentity(t, m)
	require.NoError(t, m.db.Exec("UPDATE roles SET permissions = '{bad json'").Error)
	require.ErrorContains(t, m.RunMigrations(), "权限JSON无效")
	require.Zero(t, migrationCount(t, m.db, &model.Permission{}))
	var record SchemaMigration
	require.NoError(t, m.db.First(&record, "version = ?", "2026102803").Error)
	require.Equal(t, "failed", record.Status)
	var seedSteps int64
	require.NoError(t, m.db.Model(&SchemaMigration{}).Where("version = ?", "2026102804").Count(&seedSteps).Error)
	require.Zero(t, seedSteps)
	// Repairing the cause allows the failed version and following steps to run
	// without replaying applied versions or replacing the existing identity.
	require.NoError(t, m.db.Exec("UPDATE roles SET permissions = '[]'").Error)
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.CheckMigrations())
	require.EqualValues(t, 1, migrationCount(t, m.db, &model.User{}))
	var existing model.User
	require.NoError(t, m.db.First(&existing, "username = ?", "existing").Error)
	require.Equal(t, "unchanged", existing.PasswordHash)
}

func TestQueryIndexMigrationRepairsOlderSchemaWithoutChangingData(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.RunMigrations())
	models := []struct {
		model interface{}
		name  string
	}{
		{&model.Vulnerability{}, "idx_vulnerability_created_at"}, {&model.Vulnerability{}, "idx_vulnerability_fixed_at"},
		{&model.Asset{}, "idx_asset_created_at"}, {&model.Report{}, "idx_report_created_at"},
		{&model.User{}, "idx_user_created_at"}, {&model.AuditLog{}, "idx_auditlog_created_at"},
	}
	for _, index := range models {
		require.NoError(t, m.db.Migrator().DropIndex(index.model, index.name))
	}
	require.NoError(t, m.db.Exec("DELETE FROM schema_migrations WHERE version = ?", "2026110301").Error)
	require.Error(t, m.CheckMigrations())
	before := migrationCount(t, m.db, &model.User{})
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.CheckMigrations())
	require.Equal(t, before, migrationCount(t, m.db, &model.User{}))
	for _, index := range models {
		require.True(t, m.db.Migrator().HasIndex(index.model, index.name))
	}
	require.NoError(t, m.RunMigrations())
}

func TestRiskMigrationUpgradesExistingDatabaseWithoutChangingData(t *testing.T) {
	m := newMigrationTestManager(t)
	require.NoError(t, m.RunMigrations())
	asset := model.Asset{Name: "legacy-asset", Type: model.AssetTypeServer, ImportanceLevel: model.ImportanceLevelHigh, Status: 1}
	require.NoError(t, m.db.Create(&asset).Error)
	vulnerability := model.Vulnerability{Title: "legacy finding", AssetID: asset.ID, SeverityLevel: model.SeverityHigh, Status: model.StatusNew}
	require.NoError(t, m.db.Create(&vulnerability).Error)

	// Rewind to the schema that existed before the risk module.
	for _, table := range []interface{}{&model.RiskScoringConfig{}, &model.EPSSScore{}, &model.KEVEntry{}, &model.ThreatIntelSyncState{}} {
		require.NoError(t, m.db.Migrator().DropTable(table))
	}
	require.NoError(t, m.db.Migrator().DropIndex(&model.Vulnerability{}, "idx_vulnerability_risk_score"))
	for _, column := range []string{"risk_score", "risk_priority", "risk_epss", "risk_kev", "risk_scored_at"} {
		require.NoError(t, m.db.Migrator().DropColumn(&model.Vulnerability{}, column))
	}
	for _, column := range []string{"internet_facing", "network_zone"} {
		require.NoError(t, m.db.Migrator().DropColumn(&model.Asset{}, column))
	}
	require.NoError(t, m.db.Exec("DELETE FROM permissions WHERE name = ?", "risk:manage").Error)
	require.NoError(t, m.db.Exec("DELETE FROM schema_migrations WHERE version IN ?", []string{"2026111001", "2026111002"}).Error)
	require.Error(t, m.CheckMigrations())

	users := migrationCount(t, m.db, &model.User{})
	require.NoError(t, m.RunMigrations())
	require.NoError(t, m.CheckMigrations())
	require.Equal(t, users, migrationCount(t, m.db, &model.User{}))
	for _, table := range []interface{}{&model.RiskScoringConfig{}, &model.EPSSScore{}, &model.KEVEntry{}, &model.ThreatIntelSyncState{}} {
		require.True(t, m.db.Migrator().HasTable(table))
	}
	require.True(t, m.db.Migrator().HasIndex(&model.Vulnerability{}, "idx_vulnerability_risk_score"))
	require.EqualValues(t, 1, migrationCount(t, m.db.Where("name = ?", "risk:manage"), &model.Permission{}))

	// Existing rows stay readable: unscored, internal and not internet-facing.
	var storedAsset model.Asset
	require.NoError(t, m.db.First(&storedAsset, asset.ID).Error)
	require.False(t, storedAsset.InternetFacing)
	require.Equal(t, model.NetworkZoneInternal, storedAsset.EffectiveNetworkZone())
	require.Equal(t, model.ImportanceLevelHigh, storedAsset.ImportanceLevel)
	var stored model.Vulnerability
	require.NoError(t, m.db.First(&stored, vulnerability.ID).Error)
	require.Equal(t, "legacy finding", stored.Title)
	require.Nil(t, stored.RiskScore)
	require.Nil(t, stored.RiskScoredAt)
	require.False(t, stored.RiskKEV)

	// The migration never grants the new permission to existing custom roles.
	var roles []model.Role
	require.NoError(t, m.db.Find(&roles).Error)
	for _, role := range roles {
		for _, permission := range role.Permissions {
			require.NotEqual(t, "risk:manage", permission)
		}
	}
	require.NoError(t, m.RunMigrations())
	require.EqualValues(t, 1, migrationCount(t, m.db.Where("name = ?", "risk:manage"), &model.Permission{}))
}
