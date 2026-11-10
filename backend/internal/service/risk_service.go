package service

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/sirupsen/logrus"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// RiskService scores vulnerabilities from locally cached data only. It never
// calls an external feed, so scoring keeps working when EPSS or KEV is down.
type RiskService interface {
	GetConfig() (*model.RiskConfigResponse, error)
	UpdateConfig(ctx context.Context, cfg *model.RiskConfig, actorID uint, now time.Time) (*model.RiskRescoreResult, error)
	// Apply scores an in-memory vulnerability before it is first written.
	Apply(vulnerability *model.Vulnerability, now time.Time) error
	RescoreVulnerability(id uint, now time.Time) error
	Rescore(ctx context.Context, scope repository.RiskRescoreScope, now time.Time) (int, error)
	GetVulnerabilityRisk(id uint, now time.Time) (*model.VulnerabilityRisk, error)
	// RequestIntel asks the background sync to fetch a CVE that is not cached yet.
	RequestIntel(cveID string)
}

type riskService struct {
	repo  repository.RiskRepository
	nudge func()
}

func NewRiskService(repo repository.RiskRepository) RiskService {
	return &riskService{repo: repo}
}

// ConfigureRiskIntelNudge connects scoring to the background sync without
// making either depend on the other's constructor.
func ConfigureRiskIntelNudge(risk RiskService, nudge func()) {
	if implementation, ok := risk.(*riskService); ok {
		implementation.nudge = nudge
	}
}

const riskRescoreBatch = 200

// slaAlignmentTolerance absorbs storage precision: discovered_at is stored in
// whole seconds while SLA deadlines keep milliseconds, so equal budgets can
// differ by a fraction of a second.
const slaAlignmentTolerance = time.Minute

// loadConfig never fails scoring because of a missing or damaged row: the
// defaults are a complete, valid model.
func (s *riskService) loadConfig() (model.RiskConfig, *model.RiskScoringConfig, error) {
	row, err := s.repo.GetConfig()
	if err != nil {
		return model.DefaultRiskConfig(), nil, err
	}
	if row == nil {
		return model.DefaultRiskConfig(), nil, nil
	}
	var cfg model.RiskConfig
	if err := json.Unmarshal([]byte(row.Config), &cfg); err != nil || cfg.Validate() != nil {
		logrus.Warn("风险评分配置无法解析，已回退到默认配置")
		return model.DefaultRiskConfig(), nil, nil
	}
	return cfg, row, nil
}

func (s *riskService) GetConfig() (*model.RiskConfigResponse, error) {
	cfg, row, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	response := &model.RiskConfigResponse{Config: cfg, Defaults: model.DefaultRiskConfig()}
	if row != nil {
		updatedAt := row.UpdatedAt
		response.UpdatedAt, response.UpdatedBy = &updatedAt, row.UpdatedBy
	}
	return response, nil
}

// UpdateConfig saves the model and rescores every vulnerability so the list
// order always reflects the configuration in force.
func (s *riskService) UpdateConfig(ctx context.Context, cfg *model.RiskConfig, actorID uint, now time.Time) (*model.RiskRescoreResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, errors.New("风险评分配置无法保存")
	}
	if _, err := s.repo.SaveConfig(string(data), actorID); err != nil {
		return nil, err
	}
	rescored, err := s.Rescore(ctx, repository.RiskRescoreScope{}, now)
	if err != nil {
		return &model.RiskRescoreResult{Rescored: rescored}, err
	}
	return &model.RiskRescoreResult{Rescored: rescored}, nil
}

type riskIntel struct {
	epss      map[string]model.EPSSScore
	kev       map[string]model.KEVEntry
	kevLoaded bool
}

func (s *riskService) loadIntel(cveIDs []string) (riskIntel, error) {
	intel := riskIntel{epss: map[string]model.EPSSScore{}, kev: map[string]model.KEVEntry{}}
	state, err := s.repo.GetSyncState(model.ThreatIntelSourceKEV)
	if err != nil {
		return intel, err
	}
	intel.kevLoaded = state.LastSuccessAt != nil
	if len(cveIDs) == 0 {
		return intel, nil
	}
	if intel.epss, err = s.repo.GetEPSS(cveIDs); err != nil {
		return intel, err
	}
	if intel.kev, err = s.repo.GetKEV(cveIDs); err != nil {
		return intel, err
	}
	return intel, nil
}

func riskInputFor(vulnerability *model.Vulnerability, intel riskIntel) RiskInput {
	input := RiskInput{
		CVEID: model.NormalizeCVEID(vulnerability.CVEID), CVSS: vulnerability.CVSSScore, SeverityLevel: vulnerability.SeverityLevel,
		KEVCatalogLoaded: intel.kevLoaded, AssetImportance: vulnerability.Asset.ImportanceLevel,
		InternetFacing: vulnerability.Asset.InternetFacing, NetworkZone: vulnerability.Asset.NetworkZone,
	}
	if input.CVEID == "" {
		return input
	}
	if score, ok := intel.epss[input.CVEID]; ok {
		input.EPSS = &score
	}
	if entry, ok := intel.kev[input.CVEID]; ok {
		input.KEV = &entry
	}
	return input
}

// applyAssessment copies the snapshot onto the model and reports the columns to
// write, or nil when the stored snapshot is already identical.
func applyAssessment(vulnerability *model.Vulnerability, assessment model.RiskAssessment, now time.Time) map[string]interface{} {
	unchanged := vulnerability.RiskScoredAt != nil && vulnerability.RiskScore != nil &&
		math.Abs(*vulnerability.RiskScore-assessment.Score) < 0.005 &&
		vulnerability.RiskPriority == assessment.Priority && vulnerability.RiskKEV == assessment.KEVListed &&
		((vulnerability.RiskEPSS == nil) == (assessment.EPSS == nil)) &&
		(assessment.EPSS == nil || math.Abs(*vulnerability.RiskEPSS-*assessment.EPSS) < 0.00001)
	if unchanged {
		return nil
	}
	score, scoredAt := assessment.Score, now
	vulnerability.RiskScore, vulnerability.RiskPriority = &score, assessment.Priority
	vulnerability.RiskEPSS, vulnerability.RiskKEV, vulnerability.RiskScoredAt = assessment.EPSS, assessment.KEVListed, &scoredAt
	fields := map[string]interface{}{
		"risk_score": score, "risk_priority": assessment.Priority, "risk_kev": assessment.KEVListed,
		"risk_epss": nil, "risk_scored_at": scoredAt,
	}
	if assessment.EPSS != nil {
		fields["risk_epss"] = *assessment.EPSS
	}
	return fields
}

func cveIDsOf(vulnerabilities ...*model.Vulnerability) []string {
	seen := make(map[string]bool, len(vulnerabilities))
	ids := make([]string, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		if id := model.NormalizeCVEID(vulnerability.CVEID); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

func (s *riskService) Apply(vulnerability *model.Vulnerability, now time.Time) error {
	if vulnerability == nil {
		return errors.New("漏洞不能为空")
	}
	cfg, _, err := s.loadConfig()
	if err != nil {
		return err
	}
	intel, err := s.loadIntel(cveIDsOf(vulnerability))
	if err != nil {
		return err
	}
	applyAssessment(vulnerability, AssessRisk(riskInputFor(vulnerability, intel), cfg), now)
	return nil
}

func (s *riskService) RescoreVulnerability(id uint, now time.Time) error {
	vulnerability, err := s.repo.GetVulnerability(id)
	if err != nil {
		return err
	}
	cfg, _, err := s.loadConfig()
	if err != nil {
		return err
	}
	intel, err := s.loadIntel(cveIDsOf(vulnerability))
	if err != nil {
		return err
	}
	return s.repo.UpdateRisk(id, applyAssessment(vulnerability, AssessRisk(riskInputFor(vulnerability, intel), cfg), now))
}

// Rescore walks the scope in ID order in bounded batches and returns how many
// vulnerabilities were evaluated. It is safe to interrupt and to repeat.
func (s *riskService) Rescore(ctx context.Context, scope repository.RiskRescoreScope, now time.Time) (int, error) {
	cfg, _, err := s.loadConfig()
	if err != nil {
		return 0, err
	}
	evaluated, cursor := 0, uint(0)
	for {
		if err := ctx.Err(); err != nil {
			return evaluated, err
		}
		batch, err := s.repo.ListVulnerabilitiesAfter(cursor, riskRescoreBatch, scope)
		if err != nil {
			return evaluated, err
		}
		if len(batch) == 0 {
			return evaluated, nil
		}
		intel, err := s.loadIntel(cveIDsOf(batch...))
		if err != nil {
			return evaluated, err
		}
		for _, vulnerability := range batch {
			if err := s.repo.UpdateRisk(vulnerability.ID, applyAssessment(vulnerability, AssessRisk(riskInputFor(vulnerability, intel), cfg), now)); err != nil {
				return evaluated, err
			}
			evaluated++
			cursor = vulnerability.ID
		}
		if len(batch) < riskRescoreBatch {
			return evaluated, nil
		}
	}
}

// GetVulnerabilityRisk explains the score from the current inputs. If the
// stored snapshot has drifted, it is refreshed so the list and the detail page
// never disagree after a look at the detail.
func (s *riskService) GetVulnerabilityRisk(id uint, now time.Time) (*model.VulnerabilityRisk, error) {
	vulnerability, err := s.repo.GetVulnerability(id)
	if err != nil {
		return nil, err
	}
	cfg, _, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	intel, err := s.loadIntel(cveIDsOf(vulnerability))
	if err != nil {
		return nil, err
	}
	assessment := AssessRisk(riskInputFor(vulnerability, intel), cfg)
	if fields := applyAssessment(vulnerability, assessment, now); fields != nil {
		if err := s.repo.UpdateRisk(id, fields); err != nil {
			logrus.WithError(err).Warn("刷新风险评分快照失败")
		}
	}
	base := vulnerability.DiscoveredAt
	if base.IsZero() {
		base = vulnerability.CreatedAt
	}
	risk := &model.VulnerabilityRisk{
		VulnerabilityID: id, RiskAssessment: assessment, ScoredAt: now,
		RecommendedFixDueAt: base.Add(time.Duration(assessment.RecommendedSLAHours) * time.Hour),
		CurrentFixDueAt:     vulnerability.FixDueAt, SLAAlignment: "none", Thresholds: cfg.Thresholds,
	}
	if vulnerability.FixDueAt != nil {
		risk.SLAAlignment = "aligned"
		if vulnerability.FixDueAt.After(risk.RecommendedFixDueAt.Add(slaAlignmentTolerance)) {
			risk.SLAAlignment = "later"
		}
	}
	return risk, nil
}

func (s *riskService) RequestIntel(cveID string) {
	id := model.NormalizeCVEID(cveID)
	if id == "" || s.nudge == nil {
		return
	}
	cached, err := s.repo.GetEPSS([]string{id})
	if err != nil {
		return
	}
	if _, ok := cached[id]; !ok {
		s.nudge()
	}
}
