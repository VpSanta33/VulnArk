package repository

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
)

// SLARepository stores SLA policies and provides bounded vulnerability scans.
type SLARepository interface {
	CreatePolicy(policy *model.SLAPolicy) error
	GetPolicyByID(id uint) (*model.SLAPolicy, error)
	UpdatePolicy(policy *model.SLAPolicy) error
	DeletePolicy(id uint) error
	ListPolicies(req *model.SLAPolicySearchRequest) ([]*model.SLAPolicy, int64, error)
	MatchPolicy(severity int, assetID uint, department string) (*model.SLAPolicy, error)
	GetVulnerabilityForUpdate(id uint) (*model.Vulnerability, error)
	UpdateVulnerabilityFields(id uint, fields map[string]interface{}) error
	ListOverdueVulnerabilities(ctx context.Context, now time.Time, limit int) ([]*model.Vulnerability, error)
	ListOverdueAfter(ctx context.Context, now time.Time, afterID uint, limit int) ([]*model.Vulnerability, error)
}

var ErrSLAVulnerabilityNotFound = errors.New("漏洞不存在")

type slaRepository struct{ db *gorm.DB }

func NewSLARepository(db *gorm.DB) SLARepository { return &slaRepository{db: db} }

func (r *slaRepository) CreatePolicy(policy *model.SLAPolicy) error { return r.db.Create(policy).Error }

func (r *slaRepository) GetPolicyByID(id uint) (*model.SLAPolicy, error) {
	var policy model.SLAPolicy
	if err := r.db.First(&policy, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("SLA策略不存在")
		}
		return nil, err
	}
	return &policy, nil
}

func (r *slaRepository) UpdatePolicy(policy *model.SLAPolicy) error { return r.db.Save(policy).Error }

func (r *slaRepository) DeletePolicy(id uint) error { return r.db.Delete(&model.SLAPolicy{}, id).Error }

func (r *slaRepository) ListPolicies(req *model.SLAPolicySearchRequest) ([]*model.SLAPolicy, int64, error) {
	var policies []*model.SLAPolicy
	var total int64
	query := r.db.Model(&model.SLAPolicy{})
	if req != nil {
		if req.SeverityLevel != "" {
			if severity, err := strconv.Atoi(req.SeverityLevel); err == nil {
				query = query.Where("severity_level = ?", severity)
			}
		}
		if req.AssetID != "" {
			if assetID, err := strconv.ParseUint(req.AssetID, 10, 32); err == nil {
				query = query.Where("asset_id = ?", uint(assetID))
			}
		}
		if req.Department != "" {
			query = query.Where("department = ?", req.Department)
		}
		if req.Enabled != "" {
			if enabled, err := strconv.ParseBool(req.Enabled); err == nil {
				query = query.Where("enabled = ?", enabled)
			}
		}
	}
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
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
	if err := query.Order("severity_level, department DESC, asset_id DESC, created_at DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&policies).Error; err != nil {
		return nil, 0, err
	}
	return policies, total, nil
}

func (r *slaRepository) MatchPolicy(severity int, assetID uint, department string) (*model.SLAPolicy, error) {
	var policy model.SLAPolicy
	query := r.db.Where("enabled = ? AND severity_level = ?", true, severity).
		Where("(asset_id = ? OR asset_id IS NULL)", assetID).
		Where("(department = ? OR department = '')", department).
		Order("CASE WHEN asset_id IS NULL THEN 0 ELSE 1 END DESC, CASE WHEN department = '' THEN 0 ELSE 1 END DESC, created_at DESC")
	if err := query.First(&policy).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &policy, nil
}

func (r *slaRepository) GetVulnerabilityForUpdate(id uint) (*model.Vulnerability, error) {
	var vulnerability model.Vulnerability
	if err := r.db.Clauses(clause.Locking{Strength: "UPDATE"}).Preload("Asset").First(&vulnerability, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSLAVulnerabilityNotFound
		}
		return nil, err
	}
	return &vulnerability, nil
}

func (r *slaRepository) UpdateVulnerabilityFields(id uint, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	fields["updated_at"] = time.Now()
	return r.db.Model(&model.Vulnerability{}).Where("id = ?", id).Updates(fields).Error
}

func (r *slaRepository) ListOverdueVulnerabilities(ctx context.Context, now time.Time, limit int) ([]*model.Vulnerability, error) {
	return r.ListOverdueAfter(ctx, now, 0, limit)
}

func (r *slaRepository) ListOverdueAfter(ctx context.Context, now time.Time, afterID uint, limit int) ([]*model.Vulnerability, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var vulnerabilities []*model.Vulnerability
	query := r.db.WithContext(ctx).Preload("Asset").Preload("Assignee").Preload("Discoverer").
		Where("id > ?", afterID).
		Where("status NOT IN ?", []string{model.StatusFixed, model.StatusVerified, model.StatusClosed}).
		Where("pause_started_at IS NULL").
		Where("(response_due_at IS NOT NULL AND first_response_at IS NULL AND response_due_at < ?) OR (fix_due_at IS NOT NULL AND fix_due_at < ?)", now, now).
		Order("id ASC").Limit(limit)
	if err := query.Find(&vulnerabilities).Error; err != nil {
		return nil, err
	}
	return vulnerabilities, nil
}
