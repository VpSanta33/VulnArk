package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// SLAService owns policy CRUD, deadline/timer lifecycle and the bounded overdue scan.
type SLAService interface {
	CreatePolicy(req *model.SLAPolicyCreateRequest) (*model.SLAPolicy, error)
	GetPolicy(id uint) (*model.SLAPolicy, error)
	UpdatePolicy(id uint, req *model.SLAPolicyUpdateRequest) error
	DeletePolicy(id uint) error
	ListPolicies(req *model.SLAPolicySearchRequest) (*model.PaginationResponse, error)
	MatchPolicy(severity int, assetID uint, department string) (*model.SLAPolicy, error)
	ApplyDeadlines(vulnerability *model.Vulnerability, now time.Time) error
	ApplyDeadlinesByID(vulnerabilityID uint, now time.Time) error
	RecordStatusTransition(vulnerabilityID uint, oldStatus, newStatus string, now time.Time) error
	UpdateLifecycleFields(vulnerabilityID uint, fields map[string]interface{}, now time.Time) error
	GetState(vulnerabilityID uint, now time.Time) (*model.SLAState, error)
	ListOverdue(ctx context.Context, now time.Time, limit int) ([]model.VulnerabilityInfo, error)
	Pause(vulnerabilityID uint, now time.Time) error
	Resume(vulnerabilityID uint, now time.Time) error
	PauseWithReason(vulnerabilityID, actorID uint, reason string, now time.Time) error
	ResumeWithActor(vulnerabilityID, actorID uint, now time.Time) error
	ScanOverdue(ctx context.Context, now time.Time, limit int) (*model.SLAScanResult, error)
}

type slaService struct {
	db               *gorm.DB
	policyRepo       repository.SLARepository
	notificationRepo repository.NotificationRepository
	scanMu           sync.Mutex
	scanCursor       uint
}

// NewSLAService is intentionally independent from the application container so
// callers can wire it when the migration and routes are ready.
func NewSLAService(db *gorm.DB, policyRepo repository.SLARepository, notificationRepo repository.NotificationRepository) SLAService {
	return &slaService{db: db, policyRepo: policyRepo, notificationRepo: notificationRepo}
}

func (s *slaService) CreatePolicy(req *model.SLAPolicyCreateRequest) (*model.SLAPolicy, error) {
	if err := validateSLAPolicyCreate(req); err != nil {
		return nil, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	policy := &model.SLAPolicy{Name: strings.TrimSpace(req.Name), SeverityLevel: req.SeverityLevel, AssetID: req.AssetID, Department: strings.TrimSpace(req.Department), ResponseHours: req.ResponseHours, FixHours: req.FixHours, Enabled: enabled}
	if err := s.policyRepo.CreatePolicy(policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *slaService) GetPolicy(id uint) (*model.SLAPolicy, error) {
	return s.policyRepo.GetPolicyByID(id)
}

func (s *slaService) UpdatePolicy(id uint, req *model.SLAPolicyUpdateRequest) error {
	if req == nil {
		return errors.New("缺少SLA策略数据")
	}
	policy, err := s.policyRepo.GetPolicyByID(id)
	if err != nil {
		return err
	}
	if req.Name != "" {
		policy.Name = req.Name
	}
	if req.SeverityLevel != nil {
		policy.SeverityLevel = *req.SeverityLevel
	}
	if req.AssetIDSet || req.AssetID != nil {
		policy.AssetID = req.AssetID
	}
	if req.DepartmentSet || req.Department != "" {
		policy.Department = strings.TrimSpace(req.Department)
	}
	if req.ResponseHours != nil {
		policy.ResponseHours = *req.ResponseHours
	}
	if req.FixHours != nil {
		policy.FixHours = *req.FixHours
	}
	if req.Enabled != nil {
		policy.Enabled = *req.Enabled
	}
	if err := validateSLAPolicy(policy); err != nil {
		return err
	}
	return s.policyRepo.UpdatePolicy(policy)
}

func (s *slaService) DeletePolicy(id uint) error {
	if _, err := s.policyRepo.GetPolicyByID(id); err != nil {
		return err
	}
	return s.policyRepo.DeletePolicy(id)
}

func (s *slaService) ListPolicies(req *model.SLAPolicySearchRequest) (*model.PaginationResponse, error) {
	policies, total, err := s.policyRepo.ListPolicies(req)
	if err != nil {
		return nil, err
	}
	page, pageSize := 1, 20
	if req != nil {
		if req.Page > 0 {
			page = req.Page
		}
		if req.PageSize > 0 {
			pageSize = req.PageSize
		}
	}
	return model.NewPaginationResponse(total, page, pageSize, policies), nil
}

func (s *slaService) MatchPolicy(severity int, assetID uint, department string) (*model.SLAPolicy, error) {
	if severity < 1 || severity > 4 || assetID == 0 {
		return nil, errors.New("无效的SLA匹配参数")
	}
	return s.policyRepo.MatchPolicy(severity, assetID, department)
}

func (s *slaService) ApplyDeadlines(vulnerability *model.Vulnerability, now time.Time) error {
	if vulnerability == nil {
		return errors.New("漏洞不能为空")
	}
	department := vulnerability.Asset.Department
	if department == "" && vulnerability.AssetID != 0 && s.db != nil {
		var asset model.Asset
		if err := s.db.First(&asset, vulnerability.AssetID).Error; err != nil {
			return err
		}
		department = asset.Department
	}
	policy, err := s.MatchPolicy(vulnerability.SeverityLevel, vulnerability.AssetID, department)
	if err != nil {
		return err
	}
	if policy == nil {
		return nil
	}
	base := vulnerability.DiscoveredAt
	if base.IsZero() {
		base = now
	}
	if vulnerability.ResponseDueAt == nil && vulnerability.FixDueAt == nil {
		policyID := policy.ID
		vulnerability.SLAPolicyID = &policyID
		vulnerability.SLAPolicyName = policy.Name
	}
	if vulnerability.ResponseDueAt == nil {
		due := base.Add(time.Duration(policy.ResponseHours) * time.Hour).Add(time.Duration(vulnerability.PausedSeconds) * time.Second)
		vulnerability.ResponseDueAt = &due
	}
	if vulnerability.FixDueAt == nil {
		due := base.Add(time.Duration(policy.FixHours) * time.Hour).Add(time.Duration(vulnerability.PausedSeconds) * time.Second)
		vulnerability.FixDueAt = &due
	}
	return nil
}

func (s *slaService) ApplyDeadlinesByID(vulnerabilityID uint, now time.Time) error {
	if s.db == nil {
		return errors.New("SLA服务未配置数据库")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		repo := repository.NewSLARepository(tx)
		vulnerability, err := repo.GetVulnerabilityForUpdate(vulnerabilityID)
		if err != nil {
			return err
		}
		oldResponse, oldFix := vulnerability.ResponseDueAt, vulnerability.FixDueAt
		if err := (&slaService{db: tx, policyRepo: repo}).ApplyDeadlines(vulnerability, now); err != nil {
			return err
		}
		fields := map[string]interface{}{}
		if oldResponse == nil && vulnerability.ResponseDueAt != nil {
			fields["response_due_at"] = vulnerability.ResponseDueAt
			fields["sla_policy_id"] = vulnerability.SLAPolicyID
			fields["sla_policy_name"] = vulnerability.SLAPolicyName
		}
		if oldFix == nil && vulnerability.FixDueAt != nil {
			fields["fix_due_at"] = vulnerability.FixDueAt
		}
		return repo.UpdateVulnerabilityFields(vulnerabilityID, fields)
	})
}

func (s *slaService) GetState(vulnerabilityID uint, now time.Time) (*model.SLAState, error) {
	if s.db == nil {
		return nil, errors.New("SLA服务未配置数据库")
	}
	var vulnerability model.Vulnerability
	if err := s.db.Preload("Asset").First(&vulnerability, vulnerabilityID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("漏洞不存在")
		}
		return nil, err
	}
	state := SLAStateAt(&vulnerability, now)
	return &state, nil
}

func (s *slaService) ListOverdue(ctx context.Context, now time.Time, limit int) ([]model.VulnerabilityInfo, error) {
	vulnerabilities, err := s.policyRepo.ListOverdueVulnerabilities(ctx, now, limit)
	if err != nil {
		return nil, err
	}
	items := make([]model.VulnerabilityInfo, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		info := vulnerability.ToVulnerabilityInfo()
		populateVulnerabilitySLA(&info, vulnerability, now)
		items = append(items, info)
	}
	return items, nil
}

// UpdateLifecycleFields locks the latest vulnerability and writes its business
// status and SLA clock fields in the same transaction.
func (s *slaService) UpdateLifecycleFields(vulnerabilityID uint, fields map[string]interface{}, now time.Time) error {
	if s.db == nil {
		return errors.New("SLA服务未配置数据库")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		repo := repository.NewSLARepository(tx)
		vulnerability, err := repo.GetVulnerabilityForUpdate(vulnerabilityID)
		if err != nil {
			return err
		}
		updates := make(map[string]interface{}, len(fields)+10)
		for key, value := range fields {
			updates[key] = value
		}
		if status, ok := updates["status"].(string); ok {
			if err := validateDirectVulnerabilityTransition(vulnerability.Status, status); err != nil {
				return err
			}
			for key, value := range repository.VulnerabilityLifecycleFields(vulnerability, status, now) {
				updates[key] = value
			}
		}
		return repo.UpdateVulnerabilityFields(vulnerabilityID, updates)
	})
}

// RecordStatusTransition remains an explicit lifecycle API. Ordinary update
// services use UpdateLifecycleFields so a caller never gets a half commit.
func (s *slaService) RecordStatusTransition(vulnerabilityID uint, oldStatus, newStatus string, now time.Time) error {
	return s.UpdateLifecycleFields(vulnerabilityID, map[string]interface{}{"status": newStatus}, now)
}

func validateDirectVulnerabilityTransition(oldStatus, newStatus string) error {
	return repository.ValidateDirectVulnerabilityTransition(oldStatus, newStatus)
}

func (s *slaService) Pause(vulnerabilityID uint, now time.Time) error {
	return s.PauseWithReason(vulnerabilityID, 0, "", now)
}

func (s *slaService) PauseWithReason(vulnerabilityID, actorID uint, reason string, now time.Time) error {
	if utf8.RuneCountInString(reason) > 500 {
		return errors.New("暂停原因不能超过500字符")
	}
	if s.db == nil {
		return errors.New("SLA服务未配置数据库")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		repo := repository.NewSLARepository(tx)
		vulnerability, err := repo.GetVulnerabilityForUpdate(vulnerabilityID)
		if err != nil {
			return err
		}
		if isTerminalStatus(vulnerability.Status) {
			return errors.New("已结束的漏洞不能暂停SLA")
		}
		if vulnerability.PauseStartedAt != nil {
			return errors.New("SLA已经处于暂停状态")
		}
		if err := repo.UpdateVulnerabilityFields(vulnerabilityID, map[string]interface{}{"pause_started_at": now, "pause_ended_at": nil}); err != nil {
			return err
		}
		if actorID == 0 {
			return nil
		}
		return tx.Create(&model.VulnerabilityTimeline{CreatedAt: now, VulnerabilityID: vulnerabilityID, Action: "sla_paused", Description: strings.TrimSpace(reason), OldValue: "running", NewValue: "paused", UserID: actorID}).Error
	})
}

func (s *slaService) Resume(vulnerabilityID uint, now time.Time) error {
	return s.ResumeWithActor(vulnerabilityID, 0, now)
}

func (s *slaService) ResumeWithActor(vulnerabilityID, actorID uint, now time.Time) error {
	if s.db == nil {
		return errors.New("SLA服务未配置数据库")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		repo := repository.NewSLARepository(tx)
		vulnerability, err := repo.GetVulnerabilityForUpdate(vulnerabilityID)
		if err != nil {
			return err
		}
		if vulnerability.PauseStartedAt == nil {
			return errors.New("SLA当前未暂停")
		}
		if now.Before(*vulnerability.PauseStartedAt) {
			return errors.New("恢复时间不能早于暂停时间")
		}
		paused := int64(now.Sub(*vulnerability.PauseStartedAt).Seconds())
		fields := map[string]interface{}{
			"paused_seconds":   vulnerability.PausedSeconds + paused,
			"pause_ended_at":   now,
			"pause_started_at": nil,
		}
		if vulnerability.ResponseDueAt != nil && vulnerability.FirstResponseAt == nil {
			due := vulnerability.ResponseDueAt.Add(now.Sub(*vulnerability.PauseStartedAt))
			fields["response_due_at"] = due
		}
		if vulnerability.FixDueAt != nil {
			due := vulnerability.FixDueAt.Add(now.Sub(*vulnerability.PauseStartedAt))
			fields["fix_due_at"] = due
		}
		if err := repo.UpdateVulnerabilityFields(vulnerabilityID, fields); err != nil {
			return err
		}
		if actorID == 0 {
			return nil
		}
		return tx.Create(&model.VulnerabilityTimeline{CreatedAt: now, VulnerabilityID: vulnerabilityID, Action: "sla_resumed", Description: fmt.Sprintf("恢复SLA计时，本次暂停%d秒", paused), OldValue: "paused", NewValue: "running", UserID: actorID}).Error
	})
}

// ScanOverdue advances an ID cursor between bounded calls. Already-notified low
// IDs cannot starve later vulnerabilities; reaching the end starts a new pass.
// The cursor is only an optimization: database unique keys enforce idempotency
// across processes and restarts.
func (s *slaService) ScanOverdue(ctx context.Context, now time.Time, limit int) (*model.SLAScanResult, error) {
	if s.notificationRepo == nil || s.db == nil {
		return nil, errors.New("SLA数据库或通知仓储未配置")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	vulnerabilities, err := s.policyRepo.ListOverdueAfter(ctx, now, s.scanCursor, limit)
	if err != nil {
		return nil, err
	}
	if len(vulnerabilities) == 0 && s.scanCursor != 0 {
		s.scanCursor = 0
		vulnerabilities, err = s.policyRepo.ListOverdueAfter(ctx, now, 0, limit)
		if err != nil {
			return nil, err
		}
	}
	result := &model.SLAScanResult{}
	for _, candidate := range vulnerabilities {
		created := 0
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			repo := repository.NewSLARepository(tx)
			vulnerability, err := repo.GetVulnerabilityForUpdate(candidate.ID)
			if err != nil {
				if errors.Is(err, repository.ErrSLAVulnerabilityNotFound) {
					return nil
				}
				return err
			}
			if vulnerability.PauseStartedAt != nil || isTerminalStatus(vulnerability.Status) {
				return nil
			}
			state := SLAStateAt(vulnerability, now)
			if err := repo.UpdateVulnerabilityFields(vulnerability.ID, map[string]interface{}{
				"response_overdue": state.ResponseOverdue, "fix_overdue": state.FixOverdue,
				"response_overdue_level": state.ResponseOverdueLevel, "fix_overdue_level": state.FixOverdueLevel,
			}); err != nil {
				return err
			}
			for _, item := range overdueItems(vulnerability, state, now) {
				recipients, err := slaRecipients(tx, vulnerability, item.level)
				if err != nil {
					return err
				}
				for _, recipientID := range recipients {
					allowed, err := slaSystemPushEnabled(tx, recipientID)
					if err != nil {
						return err
					}
					if !allowed {
						continue
					}
					key := fmt.Sprintf("sla:%d:%d:%s:%d:%d", vulnerability.ID, vulnerability.SLACycle, item.kind, item.level, recipientID)
					notification := &model.Notification{Title: "SLA逾期提醒", Content: item.content, Type: model.NotificationTypeSecurity, Level: item.levelName, RecipientID: recipientID, EntityType: "vulnerability", EntityID: &vulnerability.ID, DedupKey: &key, Data: model.NotificationData{"vulnerability_id": vulnerability.ID, "stage": item.kind, "overdue_level": item.level, "sla_cycle": vulnerability.SLACycle}}
					inserted, err := repository.NewNotificationRepository(tx).CreateIfAbsentContext(ctx, notification)
					if err != nil {
						return err
					}
					if inserted {
						created++
					}
				}
			}
			return nil
		})
		if err != nil {
			return result, err
		}
		result.Processed++
		result.Created += created
		s.scanCursor = candidate.ID
	}
	if len(vulnerabilities) < limit {
		s.scanCursor = 0
	}
	return result, nil
}

func slaSystemPushEnabled(db *gorm.DB, userID uint) (bool, error) {
	var setting struct{ SystemPush bool }
	result := db.Model(&model.NotificationSettings{}).Select("system_push").Where("user_id = ?", userID).Take(&setting)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return true, nil
	}
	return setting.SystemPush, result.Error
}

func slaRecipients(db *gorm.DB, v *model.Vulnerability, level int) ([]uint, error) {
	ids := make([]uint, 0, 4)
	seen := map[uint]bool{}
	add := func(id *uint) {
		if id != nil && *id > 0 && !seen[*id] {
			ids = append(ids, *id)
			seen[*id] = true
		}
	}
	if v.AssigneeID != nil {
		add(v.AssigneeID)
	} else if v.DiscovererID != nil {
		add(v.DiscovererID)
	} else {
		add(v.Asset.OwnerID)
	}
	if level >= 24 {
		add(v.Asset.OwnerID)
	}
	if level >= 72 {
		var roles []model.Role
		if err := db.Select("id", "permissions").Order("id").Limit(200).Find(&roles).Error; err != nil {
			return nil, err
		}
		var adminRoles []uint
		for _, role := range roles {
			if model.PermissionGranted(role.Permissions, "*") {
				adminRoles = append(adminRoles, role.ID)
			}
		}
		if len(adminRoles) > 0 {
			var admins []model.User
			if err := db.Select("id").Where("role_id IN ? AND status = ?", adminRoles, 1).Order("id").Limit(100).Find(&admins).Error; err != nil {
				return nil, err
			}
			for _, admin := range admins {
				id := admin.ID
				add(&id)
			}
		}
	}
	if len(ids) == 0 {
		return ids, nil
	}
	var active []model.User
	if err := db.Select("id").Where("id IN ? AND status = ?", ids, 1).Order("id").Find(&active).Error; err != nil {
		return nil, err
	}
	ids = ids[:0]
	for _, user := range active {
		ids = append(ids, user.ID)
	}
	return ids, nil
}

type overdueItem struct {
	kind, levelName, content string
	level                    int
}

func overdueItems(v *model.Vulnerability, state model.SLAState, now time.Time) []overdueItem {
	items := make([]overdueItem, 0, 2)
	if state.ResponseOverdue && v.FirstResponseAt == nil && v.ResponseDueAt != nil {
		level := overdueLevel(now.Sub(*v.ResponseDueAt))
		items = append(items, overdueItem{"response", overdueLevelName(level), fmt.Sprintf("漏洞%s响应SLA已逾期%d小时", v.Title, int(now.Sub(*v.ResponseDueAt).Hours())), level})
	}
	if state.FixOverdue && v.FixDueAt != nil && !isTerminalStatus(v.Status) {
		level := overdueLevel(now.Sub(*v.FixDueAt))
		items = append(items, overdueItem{"fix", overdueLevelName(level), fmt.Sprintf("漏洞%s修复SLA已逾期%d小时", v.Title, int(now.Sub(*v.FixDueAt).Hours())), level})
	}
	return items
}
func overdueLevel(d time.Duration) int {
	if d >= 72*time.Hour {
		return 72
	}
	if d >= 24*time.Hour {
		return 24
	}
	return 1
}
func overdueLevelName(level int) string {
	if level >= 72 {
		return model.NotificationLevelError
	}
	if level >= 24 {
		return model.NotificationLevelWarning
	}
	return model.NotificationLevelInfo
}
func isTerminalStatus(status string) bool {
	return status == model.StatusFixed || status == model.StatusVerified || status == model.StatusClosed
}
func validateSLAPolicyCreate(req *model.SLAPolicyCreateRequest) error {
	if req == nil {
		return errors.New("缺少SLA策略数据")
	}
	return validateSLAPolicy(&model.SLAPolicy{Name: req.Name, SeverityLevel: req.SeverityLevel, AssetID: req.AssetID, Department: req.Department, ResponseHours: req.ResponseHours, FixHours: req.FixHours})
}
func validateSLAPolicy(policy *model.SLAPolicy) error {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Department = strings.TrimSpace(policy.Department)
	if policy.Name == "" || utf8.RuneCountInString(policy.Name) > 100 {
		return errors.New("SLA策略名称必须为1-100字符")
	}
	if policy.SeverityLevel < 1 || policy.SeverityLevel > 4 {
		return errors.New("SLA严重程度必须为1-4")
	}
	if policy.AssetID != nil && *policy.AssetID == 0 {
		return errors.New("资产ID必须为正整数")
	}
	if utf8.RuneCountInString(policy.Department) > 100 {
		return errors.New("部门不能超过100字符")
	}
	if policy.ResponseHours <= 0 || policy.FixHours <= 0 || policy.ResponseHours > 876000 || policy.FixHours > 876000 {
		return errors.New("SLA小时数必须为1-876000")
	}
	return nil
}

// SLAStateAt computes dynamic due/overdue/remaining values without mutating DB.
func SLAStateAt(v *model.Vulnerability, now time.Time) model.SLAState {
	state := model.SLAState{Status: "none", SLAPolicyID: v.SLAPolicyID, SLAPolicyName: v.SLAPolicyName, SLACycle: v.SLACycle, ResponseDueAt: v.ResponseDueAt, FixDueAt: v.FixDueAt, FirstResponseAt: v.FirstResponseAt, PausedSeconds: v.PausedSeconds, PauseStartedAt: v.PauseStartedAt, PauseEndedAt: v.PauseEndedAt}
	if v.ResponseDueAt == nil && v.FixDueAt == nil {
		return state
	}
	state.Status = "within"
	clock := now
	if v.PauseStartedAt != nil {
		clock = *v.PauseStartedAt
		if now.After(clock) {
			state.PausedSeconds += int64(now.Sub(clock) / time.Second)
		}
	}
	responseClock := clock
	if v.FirstResponseAt != nil {
		responseClock = *v.FirstResponseAt
	}
	if v.ResponseDueAt != nil {
		remaining := int64(v.ResponseDueAt.Sub(responseClock) / time.Second)
		state.ResponseRemainingSeconds = &remaining
		state.ResponseOverdue = responseClock.After(*v.ResponseDueAt)
		if state.ResponseOverdue {
			state.ResponseOverdueLevel = overdueLevel(responseClock.Sub(*v.ResponseDueAt))
		}
	}
	fixClock := clock
	if isTerminalStatus(v.Status) && v.FixedAt != nil {
		fixClock = *v.FixedAt
	}
	if v.FixDueAt != nil {
		remaining := int64(v.FixDueAt.Sub(fixClock) / time.Second)
		state.FixRemainingSeconds = &remaining
		state.FixOverdue = fixClock.After(*v.FixDueAt)
		if state.FixOverdue {
			state.FixOverdueLevel = overdueLevel(fixClock.Sub(*v.FixDueAt))
		}
	}
	if (state.ResponseOverdue && v.FirstResponseAt == nil) || state.FixOverdue {
		state.Status = "overdue"
	}
	if v.PauseStartedAt != nil {
		state.Status = "paused"
	}
	if isTerminalStatus(v.Status) {
		state.Status = "completed"
	}
	return state
}

func populateVulnerabilitySLA(info *model.VulnerabilityInfo, v *model.Vulnerability, now time.Time) {
	state := SLAStateAt(v, now)
	info.SLAStatus = state.Status
	info.ResponseOverdue = state.ResponseOverdue
	info.FixOverdue = state.FixOverdue
	info.ResponseOverdueLevel = state.ResponseOverdueLevel
	info.FixOverdueLevel = state.FixOverdueLevel
	info.ResponseRemainingSeconds = state.ResponseRemainingSeconds
	info.FixRemainingSeconds = state.FixRemainingSeconds
	info.PausedSeconds = state.PausedSeconds
}
