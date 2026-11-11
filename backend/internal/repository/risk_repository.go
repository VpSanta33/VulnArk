package repository

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
)

// ErrRiskVulnerabilityNotFound is returned when a vulnerability to score is gone.
var ErrRiskVulnerabilityNotFound = errors.New("漏洞不存在")

// RiskRescoreScope narrows a batch rescoring pass.
type RiskRescoreScope struct {
	AssetID      uint
	OnlyUnscored bool
	OnlyWithCVE  bool
}

// RiskRepository stores the scoring configuration, the local EPSS/KEV caches
// and the per-vulnerability score snapshot.
type RiskRepository interface {
	GetConfig() (*model.RiskScoringConfig, error)
	SaveConfig(configJSON string, actorID uint) (*model.RiskScoringConfig, error)
	GetEPSS(cveIDs []string) (map[string]model.EPSSScore, error)
	GetKEV(cveIDs []string) (map[string]model.KEVEntry, error)
	UpsertEPSS(scores []model.EPSSScore) error
	ReplaceKEV(entries []model.KEVEntry, syncedAt time.Time) error
	CountKEV() (int64, error)
	GetSyncState(source string) (*model.ThreatIntelSyncState, error)
	SaveSyncState(state *model.ThreatIntelSyncState) error
	ListVulnerabilityCVEIDs(limit int) ([]string, error)
	ListVulnerabilitiesAfter(afterID uint, limit int, scope RiskRescoreScope) ([]*model.Vulnerability, error)
	GetVulnerability(id uint) (*model.Vulnerability, error)
	UpdateRisk(id uint, fields map[string]interface{}) error
}

type riskRepository struct{ db *gorm.DB }

func NewRiskRepository(db *gorm.DB) RiskRepository { return &riskRepository{db: db} }

const riskLookupChunk = 500

// GetConfig returns nil when no configuration has been saved yet.
func (r *riskRepository) GetConfig() (*model.RiskScoringConfig, error) {
	// Find with a limit instead of First: "no row yet" is the normal state on
	// every scoring call and must not be logged as an error.
	var rows []model.RiskScoringConfig
	if err := r.db.Order("id").Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

func (r *riskRepository) SaveConfig(configJSON string, actorID uint) (*model.RiskScoringConfig, error) {
	var saved model.RiskScoringConfig
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var rows []model.RiskScoringConfig
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Order("id").Limit(1).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) > 0 {
			saved = rows[0]
		}
		saved.Config = configJSON
		saved.UpdatedBy = nil
		if actorID != 0 {
			saved.UpdatedBy = &actorID
		}
		return tx.Save(&saved).Error
	})
	if err != nil {
		return nil, err
	}
	return &saved, nil
}

func (r *riskRepository) GetEPSS(cveIDs []string) (map[string]model.EPSSScore, error) {
	result := make(map[string]model.EPSSScore, len(cveIDs))
	for start := 0; start < len(cveIDs); start += riskLookupChunk {
		end := min(start+riskLookupChunk, len(cveIDs))
		var rows []model.EPSSScore
		if err := r.db.Where("cve_id IN ?", cveIDs[start:end]).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[row.CVEID] = row
		}
	}
	return result, nil
}

func (r *riskRepository) GetKEV(cveIDs []string) (map[string]model.KEVEntry, error) {
	result := make(map[string]model.KEVEntry, len(cveIDs))
	for start := 0; start < len(cveIDs); start += riskLookupChunk {
		end := min(start+riskLookupChunk, len(cveIDs))
		var rows []model.KEVEntry
		if err := r.db.Where("cve_id IN ?", cveIDs[start:end]).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[row.CVEID] = row
		}
	}
	return result, nil
}

func (r *riskRepository) UpsertEPSS(scores []model.EPSSScore) error {
	if len(scores) == 0 {
		return nil
	}
	return r.db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "cve_id"}}, UpdateAll: true}).CreateInBatches(scores, 200).Error
}

// ReplaceKEV swaps the cached catalog atomically: readers see either the old
// or the new catalog, and a failure leaves the previous one in place.
func (r *riskRepository) ReplaceKEV(entries []model.KEVEntry, syncedAt time.Time) error {
	if len(entries) == 0 {
		return errors.New("拒绝用空目录替换KEV缓存")
	}
	// Whole seconds survive every supported datetime precision, so the cleanup
	// comparison below can never match the rows written in this transaction.
	syncedAt = syncedAt.UTC().Truncate(time.Second)
	for i := range entries {
		entries[i].SyncedAt = syncedAt
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "cve_id"}}, UpdateAll: true}).CreateInBatches(entries, 200).Error; err != nil {
			return err
		}
		return tx.Where("synced_at < ?", syncedAt).Delete(&model.KEVEntry{}).Error
	})
}

func (r *riskRepository) CountKEV() (int64, error) {
	var count int64
	err := r.db.Model(&model.KEVEntry{}).Count(&count).Error
	return count, err
}

// GetSyncState returns an empty state for a source that has never been attempted.
func (r *riskRepository) GetSyncState(source string) (*model.ThreatIntelSyncState, error) {
	var states []model.ThreatIntelSyncState
	if err := r.db.Where("source = ?", source).Limit(1).Find(&states).Error; err != nil {
		return nil, err
	}
	if len(states) == 0 {
		return &model.ThreatIntelSyncState{Source: source}, nil
	}
	return &states[0], nil
}

func (r *riskRepository) SaveSyncState(state *model.ThreatIntelSyncState) error {
	return r.db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "source"}}, UpdateAll: true}).Create(state).Error
}

// ListVulnerabilityCVEIDs returns the raw, distinct identifiers in use. The
// caller normalizes them; free text never reaches an external feed.
func (r *riskRepository) ListVulnerabilityCVEIDs(limit int) ([]string, error) {
	var ids []string
	err := r.db.Model(&model.Vulnerability{}).Where("cve_id IS NOT NULL AND cve_id <> ''").Distinct("cve_id").Order("cve_id").Limit(limit).Pluck("cve_id", &ids).Error
	return ids, err
}

func (r *riskRepository) ListVulnerabilitiesAfter(afterID uint, limit int, scope RiskRescoreScope) ([]*model.Vulnerability, error) {
	query := r.db.Preload("Asset").Where("id > ?", afterID)
	if scope.AssetID != 0 {
		query = query.Where("asset_id = ?", scope.AssetID)
	}
	if scope.OnlyUnscored {
		query = query.Where("risk_scored_at IS NULL")
	}
	if scope.OnlyWithCVE {
		query = query.Where("cve_id IS NOT NULL AND cve_id <> ''")
	}
	var vulnerabilities []*model.Vulnerability
	err := query.Order("id").Limit(limit).Find(&vulnerabilities).Error
	return vulnerabilities, err
}

func (r *riskRepository) GetVulnerability(id uint) (*model.Vulnerability, error) {
	var vulnerability model.Vulnerability
	err := r.db.Preload("Asset").First(&vulnerability, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRiskVulnerabilityNotFound
	}
	if err != nil {
		return nil, err
	}
	return &vulnerability, nil
}

// UpdateRisk writes only the score snapshot. UpdateColumns leaves updated_at
// alone: a background rescoring pass is not an edit of the vulnerability.
func (r *riskRepository) UpdateRisk(id uint, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	return r.db.Model(&model.Vulnerability{}).Where("id = ?", id).UpdateColumns(fields).Error
}
