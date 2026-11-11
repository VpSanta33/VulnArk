package service

import (
	"fmt"
	"math"
	"strings"

	"vulnark/internal/model"
)

// RiskInput is everything the scoring model reads. It contains no database or
// network handles: AssessRisk is a pure function of this input and the config.
type RiskInput struct {
	// CVEID is the normalized identifier, or "" for findings without a CVE.
	CVEID         string
	CVSS          *float64
	SeverityLevel int
	// EPSS is nil when the local cache has no score for the CVE.
	EPSS *model.EPSSScore
	// KEV is nil when the CVE is not in the cached catalog.
	KEV *model.KEVEntry
	// KEVCatalogLoaded is false until the catalog has been synchronized once;
	// "not listed" cannot be told apart from "unknown" before that.
	KEVCatalogLoaded bool
	AssetImportance  int
	InternetFacing   bool
	NetworkZone      string
}

// epssFloor is the EPSS probability mapped to 0. EPSS is heavily right-skewed
// (most CVEs are below 1%), so the factor uses a log scale: 0.1% -> 0,
// 1% -> 1/3, 10% -> 2/3, 100% -> 1.
const epssFloor = 0.001

// Exposure combines reachability and the sensitivity of the network zone.
const (
	exposureReachShare = 0.6
	exposureZoneShare  = 0.4
)

func normalizeEPSS(probability float64) float64 {
	if probability <= epssFloor {
		return 0
	}
	if probability >= 1 {
		return 1
	}
	return clampUnit(1 - math.Log10(probability)/math.Log10(epssFloor))
}

func clampUnit(value float64) float64 {
	if value != value || value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func roundTo(value float64, digits int) float64 {
	scale := math.Pow(10, float64(digits))
	return math.Round(value*scale) / scale
}

// severityFallbackCVSS estimates a base score for findings recorded without one.
func severityFallbackCVSS(level int) float64 {
	switch level {
	case model.SeverityCritical:
		return 9.5
	case model.SeverityHigh:
		return 8.0
	case model.SeverityMedium:
		return 5.5
	default:
		return 2.0
	}
}

func assetImportanceValue(level int) (float64, string) {
	switch level {
	case model.ImportanceLevelHigh:
		return 1.0, "高"
	case model.ImportanceLevelMedium:
		return 0.6, "中"
	default:
		return 0.3, "低"
	}
}

func zoneSensitivity(zone string) float64 {
	switch zone {
	case model.NetworkZoneOT:
		return 1.0
	case model.NetworkZoneProduction:
		return 0.8
	case model.NetworkZoneDMZ:
		return 0.6
	case model.NetworkZoneTest:
		return 0.2
	default:
		return 0.4
	}
}

func riskPriorityRank(priority string) int {
	switch priority {
	case model.RiskPriorityP1:
		return 1
	case model.RiskPriorityP2:
		return 2
	case model.RiskPriorityP3:
		return 3
	default:
		return 4
	}
}

func priorityForScore(score float64, thresholds model.RiskThresholds) string {
	switch {
	case score >= thresholds.P1:
		return model.RiskPriorityP1
	case score >= thresholds.P2:
		return model.RiskPriorityP2
	case score >= thresholds.P3:
		return model.RiskPriorityP3
	default:
		return model.RiskPriorityP4
	}
}

// AssessRisk computes a 0-100 score as a weighted sum of five factors, each
// normalized to 0-1. A factor without data (EPSS/KEV for a finding with no CVE,
// or a CVE the caches do not know yet) is excluded and the remaining weights
// are rescaled to 100, so "unknown" is never scored as "safe".
func AssessRisk(in RiskInput, cfg model.RiskConfig) model.RiskAssessment {
	factors := make([]model.RiskFactor, 0, 5)

	cvss := model.RiskFactor{Key: model.RiskFactorCVSS, Label: "CVSS 技术严重性", Applicable: true, Weight: cfg.Weights.CVSS}
	if in.CVSS != nil {
		score := math.Min(math.Max(*in.CVSS, 0), 10)
		cvss.Value = score / 10
		cvss.RawValue = fmt.Sprintf("%.1f", score)
		cvss.Detail = fmt.Sprintf("CVSS 基础分 %.1f / 10", score)
	} else {
		score := severityFallbackCVSS(in.SeverityLevel)
		cvss.Value = score / 10
		cvss.RawValue = fmt.Sprintf("≈%.1f", score)
		cvss.Detail = fmt.Sprintf("未填写 CVSS，按严重等级估算为 %.1f / 10", score)
	}
	factors = append(factors, cvss)

	epss := model.RiskFactor{Key: model.RiskFactorEPSS, Label: "EPSS 利用可能性", Weight: cfg.Weights.EPSS}
	switch {
	case in.CVEID == "":
		epss.RawValue, epss.Detail = "不适用", "无 CVE 编号，不参与计分"
	case in.EPSS == nil || !in.EPSS.Found:
		epss.RawValue, epss.Detail = "暂无数据", "本地缓存中没有该 CVE 的 EPSS 分数（尚未同步或 FIRST 未收录），不参与计分"
	default:
		epss.Applicable = true
		epss.Value = normalizeEPSS(in.EPSS.EPSS)
		epss.RawValue = fmt.Sprintf("%.2f%%", in.EPSS.EPSS*100)
		epss.Detail = fmt.Sprintf("未来30天被利用概率 %.2f%%，高于 %.1f%% 的 CVE；按对数刻度折算", in.EPSS.EPSS*100, in.EPSS.Percentile*100)
		if in.EPSS.ScoreDate != "" {
			epss.Detail += "（数据日期 " + in.EPSS.ScoreDate + "）"
		}
	}
	factors = append(factors, epss)

	kev := model.RiskFactor{Key: model.RiskFactorKEV, Label: "CISA KEV 已知被利用", Weight: cfg.Weights.KEV}
	switch {
	case in.CVEID == "":
		kev.RawValue, kev.Detail = "不适用", "无 CVE 编号，不参与计分"
	case in.KEV != nil:
		kev.Applicable = true
		kev.Value = 1
		kev.RawValue = "已收录"
		parts := []string{"已收录于 CISA KEV 目录"}
		if in.KEV.DateAdded != "" {
			parts = append(parts, in.KEV.DateAdded+" 加入")
		}
		if in.KEV.DueDate != "" {
			parts = append(parts, "CISA 要求 "+in.KEV.DueDate+" 前修复")
		}
		if strings.EqualFold(in.KEV.KnownRansomwareUse, "Known") {
			parts = append(parts, "已知被勒索软件利用")
		}
		kev.Detail = strings.Join(parts, "，")
	case !in.KEVCatalogLoaded:
		kev.RawValue, kev.Detail = "暂无数据", "KEV 目录尚未同步到本地，不参与计分"
	default:
		kev.Applicable = true
		kev.RawValue, kev.Detail = "未收录", "未收录于 CISA KEV 目录"
	}
	factors = append(factors, kev)

	importanceValue, importanceText := assetImportanceValue(in.AssetImportance)
	factors = append(factors, model.RiskFactor{
		Key: model.RiskFactorAssetImportance, Label: "资产重要性", Applicable: true, Weight: cfg.Weights.AssetImportance,
		Value: importanceValue, RawValue: importanceText, Detail: "资产重要性等级：" + importanceText,
	})

	reach, reachText := 0.0, "不对外"
	if in.InternetFacing {
		reach, reachText = 1.0, "对外暴露"
	}
	zone := (&model.Asset{NetworkZone: in.NetworkZone}).EffectiveNetworkZone()
	exposureValue := exposureReachShare*reach + exposureZoneShare*zoneSensitivity(zone)
	factors = append(factors, model.RiskFactor{
		Key: model.RiskFactorExposure, Label: "暴露面", Applicable: true, Weight: cfg.Weights.Exposure,
		Value: clampUnit(exposureValue), RawValue: reachText + " · " + model.NetworkZoneText(zone),
		Detail: fmt.Sprintf("互联网可达性占 %.0f%%（%s），网络区域占 %.0f%%（%s）", exposureReachShare*100, reachText, exposureZoneShare*100, model.NetworkZoneText(zone)),
	})

	applicableWeight := 0.0
	for _, factor := range factors {
		if factor.Applicable {
			applicableWeight += factor.Weight
		}
	}
	score := 0.0
	for i := range factors {
		factor := &factors[i]
		if !factor.Applicable || applicableWeight <= 0 {
			factor.Value = 0
			continue
		}
		effective := factor.Weight / applicableWeight * 100
		contribution := effective * factor.Value
		score += contribution
		factor.EffectiveWeight = roundTo(effective, 2)
		factor.Contribution = roundTo(contribution, 2)
		factor.Value = roundTo(factor.Value, 4)
	}
	// Tiers are decided on the displayed value so 79.96 shown as 80.0 is P1.
	score = roundTo(math.Min(math.Max(score, 0), 100), 1)

	assessment := model.RiskAssessment{Score: score, Factors: factors, Adjustments: []string{}, CVEID: in.CVEID}
	assessment.BasePriority = priorityForScore(score, cfg.Thresholds)
	assessment.Priority = assessment.BasePriority
	if in.EPSS != nil && in.EPSS.Found && in.CVEID != "" {
		value, percentile := in.EPSS.EPSS, in.EPSS.Percentile
		assessment.EPSS, assessment.EPSSPercentile, assessment.EPSSDate = &value, &percentile, in.EPSS.ScoreDate
	}
	if in.KEV != nil && in.CVEID != "" {
		entry := *in.KEV
		assessment.KEVListed, assessment.KEV = true, &entry
		if floor := cfg.KEVMinPriority; floor != "" && riskPriorityRank(assessment.Priority) > riskPriorityRank(floor) {
			assessment.Adjustments = append(assessment.Adjustments, fmt.Sprintf("已收录于 CISA KEV 目录（存在在野利用），优先级由 %s 提升至保底档位 %s", assessment.Priority, floor))
			assessment.Priority = floor
		}
	}
	if excluded := excludedFactorLabels(factors); len(excluded) > 0 {
		assessment.Adjustments = append(assessment.Adjustments, strings.Join(excluded, "、")+" 无可用数据，其权重已按比例分配给其余因子")
	}
	assessment.PriorityText = model.RiskPriorityText(assessment.Priority)
	assessment.RecommendedSLAHours = cfg.SLAHoursFor(assessment.Priority)
	return assessment
}

func excludedFactorLabels(factors []model.RiskFactor) []string {
	labels := make([]string, 0, 2)
	for _, factor := range factors {
		if !factor.Applicable && factor.Weight > 0 {
			labels = append(labels, factor.Label)
		}
	}
	return labels
}
