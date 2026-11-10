package service

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
)

func ptrFloat(value float64) *float64 { return &value }

func riskFactor(t *testing.T, assessment model.RiskAssessment, key string) model.RiskFactor {
	t.Helper()
	for _, factor := range assessment.Factors {
		if factor.Key == key {
			return factor
		}
	}
	t.Fatalf("factor %s missing", key)
	return model.RiskFactor{}
}

// The three shapes of finding the model must rank sensibly.
var (
	kevOnExposedProduction = RiskInput{
		CVEID: "CVE-2021-44228", CVSS: ptrFloat(10), SeverityLevel: model.SeverityCritical,
		EPSS:             &model.EPSSScore{CVEID: "CVE-2021-44228", Found: true, EPSS: 0.94, Percentile: 0.999, ScoreDate: "2026-11-09"},
		KEV:              &model.KEVEntry{CVEID: "CVE-2021-44228", DateAdded: "2021-12-10", DueDate: "2021-12-24", KnownRansomwareUse: "Known"},
		KEVCatalogLoaded: true, AssetImportance: model.ImportanceLevelHigh, InternetFacing: true, NetworkZone: model.NetworkZoneProduction,
	}
	criticalCVSSButUnlikely = RiskInput{
		CVEID: "CVE-2024-00001", CVSS: ptrFloat(9.8), SeverityLevel: model.SeverityCritical,
		EPSS:             &model.EPSSScore{CVEID: "CVE-2024-00001", Found: true, EPSS: 0.0004, Percentile: 0.12},
		KEVCatalogLoaded: true, AssetImportance: model.ImportanceLevelMedium, NetworkZone: model.NetworkZoneInternal,
	}
	pentestFindingWithoutCVE = RiskInput{
		CVSS: ptrFloat(7.5), SeverityLevel: model.SeverityHigh,
		AssetImportance: model.ImportanceLevelHigh, InternetFacing: true, NetworkZone: model.NetworkZoneProduction,
	}
)

func TestAssessRiskRanksRepresentativeFindings(t *testing.T) {
	cfg := model.DefaultRiskConfig()
	kev := AssessRisk(kevOnExposedProduction, cfg)
	unlikely := AssessRisk(criticalCVSSButUnlikely, cfg)
	pentest := AssessRisk(pentestFindingWithoutCVE, cfg)

	require.Equal(t, model.RiskPriorityP1, kev.Priority)
	require.Greater(t, kev.Score, pentest.Score)
	require.Greater(t, pentest.Score, unlikely.Score)
	// A "critical" CVSS 9.8 that is unlikely to be exploited on an internal
	// asset must not outrank findings with real exposure.
	require.Equal(t, model.RiskPriorityP3, unlikely.Priority)
	require.True(t, kev.KEVListed)
	require.NotNil(t, kev.EPSS)
	require.Equal(t, cfg.SLAHours.P1, kev.RecommendedSLAHours)
	require.Equal(t, cfg.SLAHours.P3, unlikely.RecommendedSLAHours)
}

func TestAssessRiskScoresFindingWithoutCVEFromThreeFactors(t *testing.T) {
	assessment := AssessRisk(pentestFindingWithoutCVE, model.DefaultRiskConfig())
	require.Empty(t, assessment.CVEID)
	require.False(t, assessment.KEVListed)
	require.Nil(t, assessment.EPSS)
	for _, key := range []string{model.RiskFactorEPSS, model.RiskFactorKEV} {
		factor := riskFactor(t, assessment, key)
		require.False(t, factor.Applicable, key)
		require.Zero(t, factor.Contribution, key)
		require.Zero(t, factor.EffectiveWeight, key)
	}
	effective, contributions := 0.0, 0.0
	for _, key := range []string{model.RiskFactorCVSS, model.RiskFactorAssetImportance, model.RiskFactorExposure} {
		factor := riskFactor(t, assessment, key)
		require.True(t, factor.Applicable, key)
		effective += factor.EffectiveWeight
		contributions += factor.Contribution
	}
	// 30 : 20 : 15 rescaled to 100.
	require.InDelta(t, 100, effective, 0.05)
	require.InDelta(t, 46.15, riskFactor(t, assessment, model.RiskFactorCVSS).EffectiveWeight, 0.01)
	require.InDelta(t, assessment.Score, contributions, 0.1)
	// (0.75*30 + 1.0*20 + 0.92*15) / 65 * 100
	require.InDelta(t, 86.6, assessment.Score, 0.05)
	require.Len(t, assessment.Adjustments, 1)
	require.Contains(t, assessment.Adjustments[0], "无可用数据")
}

func TestAssessRiskContributionsAlwaysAddUpToScore(t *testing.T) {
	cfg := model.DefaultRiskConfig()
	for _, input := range []RiskInput{kevOnExposedProduction, criticalCVSSButUnlikely, pentestFindingWithoutCVE} {
		for _, zone := range []string{"", model.NetworkZoneOT, model.NetworkZoneDMZ, model.NetworkZoneTest} {
			for _, importance := range []int{0, 1, 2, 3} {
				input.NetworkZone, input.AssetImportance = zone, importance
				assessment := AssessRisk(input, cfg)
				sum := 0.0
				for _, factor := range assessment.Factors {
					require.GreaterOrEqual(t, factor.Value, 0.0)
					require.LessOrEqual(t, factor.Value, 1.0)
					sum += factor.Contribution
				}
				require.InDelta(t, assessment.Score, sum, 0.1)
				require.GreaterOrEqual(t, assessment.Score, 0.0)
				require.LessOrEqual(t, assessment.Score, 100.0)
			}
		}
	}
}

func TestEPSSUsesLogScale(t *testing.T) {
	for probability, expected := range map[float64]float64{0: 0, 0.0005: 0, 0.001: 0, 0.01: 1.0 / 3, 0.1: 2.0 / 3, 1: 1, 1.5: 1} {
		require.InDelta(t, expected, normalizeEPSS(probability), 1e-9, "epss %v", probability)
	}
	require.Zero(t, normalizeEPSS(math.NaN()))
	low := criticalCVSSButUnlikely
	high := low
	high.EPSS = &model.EPSSScore{CVEID: low.CVEID, Found: true, EPSS: 0.6, Percentile: 0.98}
	cfg := model.DefaultRiskConfig()
	require.Greater(t, AssessRisk(high, cfg).Score, AssessRisk(low, cfg).Score+15)
}

func TestKEVFloorRaisesPriorityAndExplainsWhy(t *testing.T) {
	input := RiskInput{
		CVEID: "CVE-2023-11111", CVSS: ptrFloat(5.3), SeverityLevel: model.SeverityMedium,
		EPSS:             &model.EPSSScore{CVEID: "CVE-2023-11111", Found: true, EPSS: 0.02, Percentile: 0.8},
		KEV:              &model.KEVEntry{CVEID: "CVE-2023-11111"},
		KEVCatalogLoaded: true, AssetImportance: model.ImportanceLevelLow, NetworkZone: model.NetworkZoneTest,
	}
	cfg := model.DefaultRiskConfig()
	floored := AssessRisk(input, cfg)
	require.Equal(t, model.RiskPriorityP3, floored.BasePriority)
	require.Equal(t, model.RiskPriorityP2, floored.Priority)
	require.Equal(t, cfg.SLAHours.P2, floored.RecommendedSLAHours)
	require.Len(t, floored.Adjustments, 1)
	require.Contains(t, floored.Adjustments[0], "KEV")

	cfg.KEVMinPriority = model.RiskPriorityP1
	require.Equal(t, model.RiskPriorityP1, AssessRisk(input, cfg).Priority)

	cfg.KEVMinPriority = ""
	unfloored := AssessRisk(input, cfg)
	require.Equal(t, model.RiskPriorityP3, unfloored.Priority)
	require.Empty(t, unfloored.Adjustments)
	// The floor never lowers a priority that is already higher.
	cfg.KEVMinPriority = model.RiskPriorityP3
	require.Equal(t, model.RiskPriorityP1, AssessRisk(kevOnExposedProduction, cfg).Priority)
}

func TestMissingThreatIntelIsExcludedNotScoredAsSafe(t *testing.T) {
	cfg := model.DefaultRiskConfig()
	known := criticalCVSSButUnlikely
	unknown := known
	unknown.EPSS, unknown.KEVCatalogLoaded = nil, false
	withData, withoutData := AssessRisk(known, cfg), AssessRisk(unknown, cfg)
	require.False(t, riskFactor(t, withoutData, model.RiskFactorEPSS).Applicable)
	require.False(t, riskFactor(t, withoutData, model.RiskFactorKEV).Applicable)
	// Unknown must not rank below "known to be unlikely".
	require.Greater(t, withoutData.Score, withData.Score)

	negativeCache := known
	negativeCache.EPSS = &model.EPSSScore{CVEID: known.CVEID, Found: false}
	assessment := AssessRisk(negativeCache, cfg)
	require.False(t, riskFactor(t, assessment, model.RiskFactorEPSS).Applicable)
	require.True(t, riskFactor(t, assessment, model.RiskFactorKEV).Applicable)
	require.Nil(t, assessment.EPSS)
}

func TestWeightsAndThresholdsAreConfigurable(t *testing.T) {
	cfg := model.DefaultRiskConfig()
	base := AssessRisk(criticalCVSSButUnlikely, cfg)

	cvssOnly := cfg
	cvssOnly.Weights = model.RiskWeights{CVSS: 100}
	assessment := AssessRisk(criticalCVSSButUnlikely, cvssOnly)
	require.InDelta(t, 98, assessment.Score, 0.05)
	require.Equal(t, model.RiskPriorityP1, assessment.Priority)

	lenient := cfg
	lenient.Thresholds = model.RiskThresholds{P1: 40, P2: 30, P3: 20}
	require.Equal(t, base.Score, AssessRisk(criticalCVSSButUnlikely, lenient).Score)
	require.Equal(t, model.RiskPriorityP1, AssessRisk(criticalCVSSButUnlikely, lenient).Priority)

	strict := cfg
	strict.Thresholds = model.RiskThresholds{P1: 99.9, P2: 99, P3: 98}
	strict.KEVMinPriority = ""
	require.Equal(t, model.RiskPriorityP4, AssessRisk(pentestFindingWithoutCVE, strict).Priority)
	require.Equal(t, strict.SLAHours.P4, AssessRisk(pentestFindingWithoutCVE, strict).RecommendedSLAHours)
}

func TestCVSSFallsBackToSeverityLevel(t *testing.T) {
	cfg := model.DefaultRiskConfig()
	scores := make([]float64, 0, 4)
	for _, level := range []int{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		assessment := AssessRisk(RiskInput{SeverityLevel: level, AssetImportance: model.ImportanceLevelMedium}, cfg)
		factor := riskFactor(t, assessment, model.RiskFactorCVSS)
		require.True(t, factor.Applicable)
		require.Contains(t, factor.Detail, "估算")
		scores = append(scores, assessment.Score)
	}
	require.IsDecreasing(t, scores)
}

func TestExposureCombinesReachabilityAndZone(t *testing.T) {
	cfg := model.DefaultRiskConfig()
	value := func(internetFacing bool, zone string) float64 {
		input := RiskInput{CVSS: ptrFloat(5), InternetFacing: internetFacing, NetworkZone: zone}
		return riskFactor(t, AssessRisk(input, cfg), model.RiskFactorExposure).Value
	}
	require.InDelta(t, 1.0, value(true, model.NetworkZoneOT), 1e-9)
	require.InDelta(t, 0.92, value(true, model.NetworkZoneProduction), 1e-9)
	require.InDelta(t, 0.4, value(false, model.NetworkZoneOT), 1e-9)
	require.InDelta(t, 0.16, value(false, ""), 1e-9)
	require.InDelta(t, value(false, model.NetworkZoneInternal), value(false, "unknown-zone"), 1e-9)
	require.Greater(t, value(false, model.NetworkZoneProduction), value(false, model.NetworkZoneTest))
}

func TestRiskConfigValidation(t *testing.T) {
	valid := model.DefaultRiskConfig()
	require.NoError(t, valid.Validate())
	mutate := func(change func(*model.RiskConfig)) error {
		cfg := model.DefaultRiskConfig()
		change(&cfg)
		return cfg.Validate()
	}
	require.NoError(t, mutate(func(c *model.RiskConfig) { c.Weights.EPSS, c.Weights.KEV = 0, 0 }))
	require.NoError(t, mutate(func(c *model.RiskConfig) { c.KEVMinPriority = "" }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.Weights.CVSS = -1 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.Weights.EPSS = 101 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.Weights.KEV = math.NaN() }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.Weights.CVSS, c.Weights.AssetImportance, c.Weights.Exposure = 0, 0, 0 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.Thresholds.P2 = c.Thresholds.P1 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.Thresholds.P3 = 0 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.Thresholds.P1 = 100.5 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.SLAHours.P1 = 0 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.SLAHours.P2 = c.SLAHours.P1 - 1 }))
	require.Error(t, mutate(func(c *model.RiskConfig) { c.KEVMinPriority = "P4" }))
	require.Error(t, (*model.RiskConfig)(nil).Validate())
}

func TestNormalizeCVEIDRejectsFreeText(t *testing.T) {
	require.Equal(t, "CVE-2021-44228", model.NormalizeCVEID(" cve-2021-44228 "))
	require.Equal(t, "CVE-2026-102895", model.NormalizeCVEID("CVE-2026-102895"))
	for _, value := range []string{"", "N/A", "CVE-2026-1", "CVE-2021-44228,CVE-2021-45046", "CVE-2021-44228&x=1", "CNVD-2021-12345"} {
		require.Empty(t, model.NormalizeCVEID(value), value)
	}
}
