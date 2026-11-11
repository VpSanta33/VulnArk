package model

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Risk priority tiers, highest first.
const (
	RiskPriorityP1 = "P1"
	RiskPriorityP2 = "P2"
	RiskPriorityP3 = "P3"
	RiskPriorityP4 = "P4"
)

// Risk factor keys used in configuration and in the score breakdown.
const (
	RiskFactorCVSS            = "cvss"
	RiskFactorEPSS            = "epss"
	RiskFactorKEV             = "kev"
	RiskFactorAssetImportance = "asset_importance"
	RiskFactorExposure        = "exposure"
)

// Network zones describe where an asset lives. An empty value is read as internal.
const (
	NetworkZoneInternal   = "internal"
	NetworkZoneDMZ        = "dmz"
	NetworkZoneProduction = "production"
	NetworkZoneOT         = "ot"
	NetworkZoneTest       = "test"
)

// Threat-intelligence sources cached locally.
const (
	ThreatIntelSourceEPSS = "epss"
	ThreatIntelSourceKEV  = "kev"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// NormalizeCVEID returns the canonical upper-case identifier, or "" when the
// value is not a well-formed CVE ID. Free-text placeholders such as "N/A" must
// never be sent to an external feed or matched against the caches.
func NormalizeCVEID(value string) string {
	id := strings.ToUpper(strings.TrimSpace(value))
	if !cvePattern.MatchString(id) {
		return ""
	}
	return id
}

// NetworkZoneText returns the display name of a zone.
func NetworkZoneText(zone string) string {
	switch zone {
	case NetworkZoneOT:
		return "OT/工控网段"
	case NetworkZoneProduction:
		return "生产网段"
	case NetworkZoneDMZ:
		return "DMZ"
	case NetworkZoneTest:
		return "测试/开发网段"
	default:
		return "内部办公网段"
	}
}

// RiskPriorityText returns the display name of a priority tier.
func RiskPriorityText(priority string) string {
	switch priority {
	case RiskPriorityP1:
		return "紧急"
	case RiskPriorityP2:
		return "高"
	case RiskPriorityP3:
		return "中"
	case RiskPriorityP4:
		return "低"
	default:
		return "未评分"
	}
}

// RiskWeights are relative. They are rescaled over the factors that apply to a
// vulnerability, so they do not have to add up to 100.
type RiskWeights struct {
	CVSS            float64 `json:"cvss"`
	EPSS            float64 `json:"epss"`
	KEV             float64 `json:"kev"`
	AssetImportance float64 `json:"asset_importance"`
	Exposure        float64 `json:"exposure"`
}

// RiskThresholds are the minimum scores (0-100) for P1, P2 and P3.
type RiskThresholds struct {
	P1 float64 `json:"p1"`
	P2 float64 `json:"p2"`
	P3 float64 `json:"p3"`
}

// RiskSLAHours are the recommended fix deadlines per priority tier.
type RiskSLAHours struct {
	P1 int `json:"p1"`
	P2 int `json:"p2"`
	P3 int `json:"p3"`
	P4 int `json:"p4"`
}

// RiskConfig is the administrator-editable scoring model.
type RiskConfig struct {
	Weights    RiskWeights    `json:"weights"`
	Thresholds RiskThresholds `json:"thresholds"`
	SLAHours   RiskSLAHours   `json:"sla_hours"`
	// KEVMinPriority is the lowest tier a KEV-listed vulnerability may receive.
	// Empty disables the floor.
	KEVMinPriority string `json:"kev_min_priority"`
}

// DefaultRiskConfig is used until an administrator saves a configuration.
func DefaultRiskConfig() RiskConfig {
	return RiskConfig{
		Weights:        RiskWeights{CVSS: 30, EPSS: 20, KEV: 15, AssetImportance: 20, Exposure: 15},
		Thresholds:     RiskThresholds{P1: 80, P2: 60, P3: 40},
		SLAHours:       RiskSLAHours{P1: 24, P2: 72, P3: 168, P4: 720},
		KEVMinPriority: RiskPriorityP2,
	}
}

// Validate rejects configurations that cannot rank every vulnerability.
func (c *RiskConfig) Validate() error {
	if c == nil {
		return errors.New("缺少风险评分配置")
	}
	for _, weight := range []float64{c.Weights.CVSS, c.Weights.EPSS, c.Weights.KEV, c.Weights.AssetImportance, c.Weights.Exposure} {
		if weight != weight || weight < 0 || weight > 100 {
			return errors.New("权重必须在0-100之间")
		}
	}
	// Findings without a CVE are scored from these three factors alone.
	if c.Weights.CVSS+c.Weights.AssetImportance+c.Weights.Exposure <= 0 {
		return errors.New("CVSS、资产重要性、暴露面三项权重不能同时为0")
	}
	t := c.Thresholds
	if t.P1 != t.P1 || t.P2 != t.P2 || t.P3 != t.P3 || t.P3 <= 0 || t.P2 <= t.P3 || t.P1 <= t.P2 || t.P1 > 100 {
		return errors.New("档位阈值必须满足 0 < P3 < P2 < P1 <= 100")
	}
	h := c.SLAHours
	if h.P1 < 1 || h.P2 < h.P1 || h.P3 < h.P2 || h.P4 < h.P3 || h.P4 > 876000 {
		return errors.New("建议修复期限必须为正整数小时，且 P1 <= P2 <= P3 <= P4")
	}
	switch c.KEVMinPriority {
	case "", RiskPriorityP1, RiskPriorityP2, RiskPriorityP3:
	default:
		return errors.New("KEV保底优先级只能为空、P1、P2或P3")
	}
	return nil
}

// SLAHoursFor returns the recommended fix deadline for a priority tier.
func (c RiskConfig) SLAHoursFor(priority string) int {
	switch priority {
	case RiskPriorityP1:
		return c.SLAHours.P1
	case RiskPriorityP2:
		return c.SLAHours.P2
	case RiskPriorityP3:
		return c.SLAHours.P3
	default:
		return c.SLAHours.P4
	}
}

// RiskScoringConfig stores the single active configuration as JSON.
type RiskScoringConfig struct {
	ID        uint      `json:"id" gorm:"primarykey"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Config    string    `json:"config" gorm:"type:text;not null"`
	UpdatedBy *uint     `json:"updated_by"`
}

func (RiskScoringConfig) TableName() string { return "risk_scoring_configs" }

// EPSSScore caches one FIRST EPSS record. Found=false is a negative cache entry
// for a CVE that FIRST does not score, so it is not requested on every pass.
type EPSSScore struct {
	CVEID      string    `json:"cve_id" gorm:"primaryKey;size:32"`
	Found      bool      `json:"found"`
	EPSS       float64   `json:"epss" gorm:"type:decimal(6,5)"`
	Percentile float64   `json:"percentile" gorm:"type:decimal(6,5)"`
	ScoreDate  string    `json:"score_date" gorm:"size:10"`
	FetchedAt  time.Time `json:"fetched_at" gorm:"index:idx_threat_intel_epss_fetched_at"`
}

func (EPSSScore) TableName() string { return "threat_intel_epss" }

// KEVEntry caches one record of the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVEID              string    `json:"cve_id" gorm:"primaryKey;size:32"`
	VendorProject      string    `json:"vendor_project" gorm:"size:255"`
	Product            string    `json:"product" gorm:"size:255"`
	VulnerabilityName  string    `json:"vulnerability_name" gorm:"size:500"`
	DateAdded          string    `json:"date_added" gorm:"size:10"`
	DueDate            string    `json:"due_date" gorm:"size:10"`
	KnownRansomwareUse string    `json:"known_ransomware_use" gorm:"size:20"`
	SyncedAt           time.Time `json:"synced_at"`
}

func (KEVEntry) TableName() string { return "threat_intel_kev" }

// ThreatIntelSyncState records the outcome of the last synchronization attempt
// per source. A failed attempt never clears the cached data.
type ThreatIntelSyncState struct {
	Source              string     `json:"source" gorm:"primaryKey;size:20"`
	LastAttemptAt       *time.Time `json:"last_attempt_at"`
	LastSuccessAt       *time.Time `json:"last_success_at"`
	LastError           string     `json:"last_error" gorm:"size:500"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	RecordCount         int        `json:"record_count"`
	SourceVersion       string     `json:"source_version" gorm:"size:64"`
}

func (ThreatIntelSyncState) TableName() string { return "threat_intel_sync_states" }

// RiskFactor is one row of the explanation shown on the detail page.
type RiskFactor struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Applicable is false when the factor has no data for this vulnerability;
	// its weight is then redistributed over the applicable factors.
	Applicable bool `json:"applicable"`
	// Weight is the configured relative weight.
	Weight float64 `json:"weight"`
	// EffectiveWeight is the maximum number of points this factor can add to
	// this vulnerability. Effective weights of applicable factors sum to 100.
	EffectiveWeight float64 `json:"effective_weight"`
	// Value is the normalized factor value between 0 and 1.
	Value float64 `json:"value"`
	// Contribution is EffectiveWeight * Value, in points.
	Contribution float64 `json:"contribution"`
	RawValue     string  `json:"raw_value"`
	Detail       string  `json:"detail"`
}

// RiskAssessment is the result of scoring one vulnerability.
type RiskAssessment struct {
	Score float64 `json:"score"`
	// BasePriority follows the thresholds only; Priority also applies rules
	// such as the KEV floor. Adjustments explains every difference.
	BasePriority        string       `json:"base_priority"`
	Priority            string       `json:"priority"`
	PriorityText        string       `json:"priority_text"`
	RecommendedSLAHours int          `json:"recommended_sla_hours"`
	Factors             []RiskFactor `json:"factors"`
	Adjustments         []string     `json:"adjustments"`
	CVEID               string       `json:"cve_id"`
	EPSS                *float64     `json:"epss"`
	EPSSPercentile      *float64     `json:"epss_percentile"`
	EPSSDate            string       `json:"epss_date"`
	KEVListed           bool         `json:"kev_listed"`
	KEV                 *KEVEntry    `json:"kev,omitempty"`
}

// VulnerabilityRisk is the detail-page response: the assessment plus how the
// recommended deadline compares with the SLA deadline currently in force.
type VulnerabilityRisk struct {
	VulnerabilityID uint `json:"vulnerability_id"`
	RiskAssessment
	ScoredAt            time.Time  `json:"scored_at"`
	RecommendedFixDueAt time.Time  `json:"recommended_fix_due_at"`
	CurrentFixDueAt     *time.Time `json:"current_fix_due_at"`
	// SLAAlignment is none (no SLA deadline), aligned (the SLA deadline is not
	// later than the recommendation) or later.
	SLAAlignment string         `json:"sla_alignment"`
	Thresholds   RiskThresholds `json:"thresholds"`
}

// ThreatIntelSourceStatus is the per-source state shown in settings.
type ThreatIntelSourceStatus struct {
	Source              string     `json:"source"`
	Name                string     `json:"name"`
	LastAttemptAt       *time.Time `json:"last_attempt_at"`
	LastSuccessAt       *time.Time `json:"last_success_at"`
	LastError           string     `json:"last_error"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	RecordCount         int        `json:"record_count"`
	SourceVersion       string     `json:"source_version"`
	// Stale is true when there has been no success within two sync intervals.
	Stale bool `json:"stale"`
}

// ThreatIntelStatus summarizes the local EPSS/KEV caches.
type ThreatIntelStatus struct {
	Enabled           bool                      `json:"enabled"`
	SyncIntervalHours int                       `json:"sync_interval_hours"`
	Sources           []ThreatIntelSourceStatus `json:"sources"`
}

// ThreatIntelSyncResult is returned by a manual synchronization.
type ThreatIntelSyncResult struct {
	KEVEntries  int      `json:"kev_entries"`
	EPSSUpdated int      `json:"epss_updated"`
	Rescored    int      `json:"rescored"`
	Errors      []string `json:"errors"`
}

// RiskConfigResponse is the configuration together with its defaults.
type RiskConfigResponse struct {
	Config    RiskConfig `json:"config"`
	Defaults  RiskConfig `json:"defaults"`
	UpdatedAt *time.Time `json:"updated_at"`
	UpdatedBy *uint      `json:"updated_by"`
}

// RiskRescoreResult reports how many vulnerabilities were rescored.
type RiskRescoreResult struct {
	Rescored int `json:"rescored"`
}
