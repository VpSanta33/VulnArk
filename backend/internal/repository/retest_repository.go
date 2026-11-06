package repository

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
)

var (
	ErrRetestNotFound        = errors.New("复测记录不存在")
	ErrRetestInvalidStatus   = errors.New("当前漏洞状态不允许复测")
	ErrRetestAlreadyVerified = errors.New("漏洞已验证，无需重复通过复测")
	ErrRetestConflict        = errors.New("漏洞状态已被其他复测修改，请重试")
	ErrRetestTesterAssignee  = errors.New("复测人不能是当前修复负责人")
	ErrRetestScopeDenied     = errors.New("无权复测该漏洞")
)

// VulnerabilityRetestRepository persists retests and their state transition.
// CreateRetestAndTransition is the only write entry point so the retest,
// vulnerability status, and timeline event share one transaction.
type RetestAccess struct {
	Global bool
}

type VulnerabilityRetestRepository interface {
	CreateRetestAndTransition(retest *model.VulnerabilityRetest, access ...RetestAccess) error
	ListRetests(vulnerabilityID uint) ([]*model.VulnerabilityRetest, error)
}

type vulnerabilityRetestRepository struct {
	db *gorm.DB
}

func NewVulnerabilityRetestRepository(db *gorm.DB) VulnerabilityRetestRepository {
	return &vulnerabilityRetestRepository{db: db}
}

// NewRetestRepository is a short constructor alias for route/container wiring.
func NewRetestRepository(db *gorm.DB) VulnerabilityRetestRepository {
	return NewVulnerabilityRetestRepository(db)
}

func (r *vulnerabilityRetestRepository) CreateRetestAndTransition(retest *model.VulnerabilityRetest, access ...RetestAccess) error {
	if retest == nil || retest.VulnerabilityID == 0 || retest.TesterID == 0 {
		return errors.New("复测数据无效")
	}
	if retest.Result != model.RetestResultPass && retest.Result != model.RetestResultFail {
		return errors.New("复测结果必须为pass或fail")
	}
	if retest.Summary == "" {
		return errors.New("复测摘要不能为空")
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		var vulnerability model.Vulnerability
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&vulnerability, retest.VulnerabilityID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errors.New("漏洞不存在")
			}
			return err
		}

		global := len(access) > 0 && access[0].Global
		participant := (vulnerability.DiscovererID != nil && *vulnerability.DiscovererID == retest.TesterID) ||
			(vulnerability.AssigneeID != nil && *vulnerability.AssigneeID == retest.TesterID)
		if !global && !participant {
			var owned int64
			if err := tx.Model(&model.Asset{}).Where("id = ? AND owner_id = ?", vulnerability.AssetID, retest.TesterID).Count(&owned).Error; err != nil {
				return err
			}
			participant = owned > 0
		}
		if !global && !participant {
			var previous int64
			if err := tx.Model(&model.VulnerabilityRetest{}).Where("vulnerability_id = ? AND (tester_id = ? OR fixer_id = ?)", vulnerability.ID, retest.TesterID, retest.TesterID).Count(&previous).Error; err != nil {
				return err
			}
			participant = previous > 0
		}
		if !global && !participant {
			return ErrRetestScopeDenied
		}
		if vulnerability.AssigneeID != nil && *vulnerability.AssigneeID == retest.TesterID {
			return ErrRetestTesterAssignee
		}
		retest.FixerID = vulnerability.AssigneeID
		var tester model.User
		if err := tx.First(&tester, retest.TesterID).Error; err != nil || !tester.IsActive() {
			return errors.New("复测人不存在或已停用")
		}
		retest.Tester = tester
		newStatus, err := retestStatusTransition(vulnerability.Status, retest.Result)
		if err != nil {
			return err
		}
		retest.PreviousStatus = vulnerability.Status
		retest.NewStatus = newStatus
		retest.CreatedAt = time.Now()
		if err := tx.Omit("Vulnerability", "Tester").Create(retest).Error; err != nil {
			return err
		}

		now := time.Now()
		updates := map[string]interface{}{
			"status":     newStatus,
			"updated_at": now,
		}
		for key, value := range VulnerabilityLifecycleFields(&vulnerability, newStatus, now) {
			updates[key] = value
		}
		if retest.Result == model.RetestResultPass {
			updates["verified_at"] = now
		}
		result := tx.Model(&model.Vulnerability{}).
			Where("id = ? AND status = ?", vulnerability.ID, vulnerability.Status).
			Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrRetestConflict
		}

		description := fmt.Sprintf("漏洞复测%s：%s", retestResultText(retest.Result), retest.Summary)
		timeline := &model.VulnerabilityTimeline{
			VulnerabilityID: vulnerability.ID,
			Action:          model.TimelineActionRetested,
			Description:     description,
			OldValue:        vulnerability.Status,
			NewValue:        newStatus,
			UserID:          retest.TesterID,
		}
		if err := tx.Create(timeline).Error; err != nil {
			return err
		}
		return createRetestNotifications(tx, &vulnerability, retest)
	})
}

// The event and its in-app notifications commit together. Missing preferences
// preserve the default enabled behavior; query or notification errors abort the
// entire retest. No email or other external delivery occurs in this transaction.
func createRetestNotifications(tx *gorm.DB, vulnerability *model.Vulnerability, retest *model.VulnerabilityRetest) error {
	seen := map[uint]bool{retest.TesterID: true}
	for _, recipient := range []*uint{vulnerability.AssigneeID, vulnerability.DiscovererID} {
		if recipient == nil || *recipient == 0 || seen[*recipient] {
			continue
		}
		seen[*recipient] = true
		var preferences struct{ SystemPush bool }
		err := tx.Model(&model.NotificationSettings{}).Select("system_push").Where("user_id = ?", *recipient).Take(&preferences).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && !preferences.SystemPush {
			continue
		}
		level := model.NotificationLevelSuccess
		if retest.Result == model.RetestResultFail {
			level = model.NotificationLevelWarning
		}
		key := fmt.Sprintf("retest:%d:%d", retest.ID, *recipient)
		notification := &model.Notification{
			Title:       "漏洞复测" + retestResultText(retest.Result),
			Content:     fmt.Sprintf("漏洞「%s」复测%s，当前状态：%s。", vulnerability.Title, retestResultText(retest.Result), retest.NewStatus),
			Type:        model.NotificationTypeVulnerability,
			Level:       level,
			RecipientID: *recipient,
			SenderID:    &retest.TesterID,
			EntityType:  "vulnerability",
			EntityID:    &vulnerability.ID,
			DedupKey:    &key,
			Data: model.NotificationData{
				"vulnerability_id": vulnerability.ID,
				"section":          "retests",
				"retest_id":        retest.ID,
				"result":           retest.Result,
			},
		}
		if _, err := NewNotificationRepository(tx).CreateIfAbsentContext(tx.Statement.Context, notification); err != nil {
			return err
		}
	}
	return nil
}

func retestStatusTransition(status, result string) (string, error) {
	// A pass confirms a fixed vulnerability as verified. A second concurrent
	// pass observes verified/closed after the row lock and is rejected, so the
	// workflow cannot create duplicate successful verification records.
	if result == model.RetestResultPass {
		if status == model.StatusFixed {
			return model.StatusVerified, nil
		}
		if status == model.StatusVerified || status == model.StatusClosed {
			return "", ErrRetestAlreadyVerified
		}
		return "", ErrRetestInvalidStatus
	}

	// There is no reopened status in the existing state enum. Failed retests
	// therefore move fixed, verified, or closed vulnerabilities to processing,
	// which is the existing work-in-progress/reopen state.
	switch status {
	case model.StatusFixed, model.StatusVerified, model.StatusClosed:
		return model.StatusProcessing, nil
	default:
		return "", ErrRetestInvalidStatus
	}
}

func retestResultText(result string) string {
	if result == model.RetestResultPass {
		return "通过"
	}
	return "失败"
}

func (r *vulnerabilityRetestRepository) ListRetests(vulnerabilityID uint) ([]*model.VulnerabilityRetest, error) {
	var retests []*model.VulnerabilityRetest
	if err := r.db.Preload("Tester").Where("vulnerability_id = ?", vulnerabilityID).
		Order("created_at DESC, id DESC").Find(&retests).Error; err != nil {
		return nil, err
	}
	return retests, nil
}
