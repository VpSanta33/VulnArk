package repository

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"vulnark/internal/model"
)

// AnalyticsRepository 统计分析仓储接口。趋势的结束时间为不包含的上界。
type AnalyticsRepository interface {
	GetDashboardStats() (*model.DashboardStats, error)
	GetVulnerabilityAnalytics(req *model.AnalyticsRequest) (*model.VulnerabilityAnalytics, error)
	GetVulnerabilityTrend(startDate, endDate time.Time, granularity string, filters ...*model.AnalyticsRequest) ([]model.TrendPoint, error)
	GetSeverityTrend(startDate, endDate time.Time, filters ...*model.AnalyticsRequest) ([]model.SeverityTrendPoint, error)
	GetAssetAnalytics(req *model.AnalyticsRequest) (*model.AssetAnalytics, error)
	GetAssetGrowthTrend(startDate, endDate time.Time, granularity string) ([]model.TrendPoint, error)
	GetAssetRiskAssessment() ([]model.AssetRiskCount, error)
	GetReportAnalytics(req *model.AnalyticsRequest) (*model.ReportAnalytics, error)
	GetReportSubmissionTrend(startDate, endDate time.Time, granularity string) ([]model.TrendPoint, error)
	GetUserAnalytics(req *model.AnalyticsRequest) (*model.UserAnalytics, error)
	GetUserLoginTrend(startDate, endDate time.Time, granularity string) ([]model.TrendPoint, error)
	GetTimeRangeStats(tableName, dateColumn string) (*model.TimeRangeStats, error)
	GetMonthlyVulnerabilityTrends() ([]model.MonthlyTrendPoint, error)
}

type analyticsRepository struct{ db *gorm.DB }

func NewAnalyticsRepository(db *gorm.DB) AnalyticsRepository { return &analyticsRepository{db: db} }

func validateGranularity(granularity string) (string, error) {
	switch granularity {
	case "day":
		return "%Y-%m-%d", nil
	case "week":
		// ISO week-year must accompany the ISO week number at year boundaries.
		return "%x-%v", nil
	case "month":
		return "%Y-%m", nil
	default:
		return "", errors.New("无效的时间粒度参数")
	}
}

// Each sub-statistic calls this factory again instead of mutating a shared GORM statement.
func (r *analyticsRepository) filteredQuery(table, alias string, req *model.AnalyticsRequest) (*gorm.DB, error) {
	q := r.db.Table(table + " " + alias)
	if table == "vulnerabilities" {
		q = q.Joins("LEFT JOIN owasp_categories o ON o.id = " + alias + ".owasp_category_id")
	}
	if req == nil {
		return q, nil
	}
	var start, end time.Time
	var err error
	if req.StartDate != "" {
		start, err = time.Parse("2006-01-02", req.StartDate)
		if err != nil {
			return nil, fmt.Errorf("无效的开始日期格式: %s", req.StartDate)
		}
		q = q.Where(alias+".created_at >= ?", start)
	}
	if req.EndDate != "" {
		end, err = time.Parse("2006-01-02", req.EndDate)
		if err != nil {
			return nil, fmt.Errorf("无效的结束日期格式: %s", req.EndDate)
		}
		if !start.IsZero() && start.After(end) {
			return nil, errors.New("开始日期不能晚于结束日期")
		}
		q = q.Where(alias+".created_at < ?", end.AddDate(0, 0, 1))
	}
	if req.Granularity != "" {
		if _, err := validateGranularity(req.Granularity); err != nil {
			return nil, err
		}
	}
	// Identifiers are values, never SQL fragments; reject malformed IDs early.
	for _, id := range []string{req.AssetID, req.UserID} {
		if id != "" {
			n, err := strconv.ParseUint(id, 10, 64)
			if err != nil || n == 0 {
				return nil, errors.New("无效的资产或用户ID")
			}
		}
	}
	switch table {
	case "vulnerabilities":
		if req.AssetID != "" {
			q = q.Where(alias+".asset_id = ?", req.AssetID)
		}
		if req.UserID != "" {
			q = q.Where(alias+".discoverer_id = ?", req.UserID)
		}
		if req.Severity != "" {
			levels := map[string]int{"critical": 1, "high": 2, "medium": 3, "low": 4, "1": 1, "2": 2, "3": 3, "4": 4}
			level, ok := levels[req.Severity]
			if !ok {
				return nil, errors.New("无效的严重程度")
			}
			q = q.Where(alias+".severity_level = ?", level)
		}
		if req.Status != "" {
			statuses := []string{req.Status}
			switch req.Status {
			case "open":
				statuses = []string{"new"}
			case "in_progress":
				statuses = []string{"assigned", "in_progress", "processing"}
			case "resolved":
				statuses = []string{"fixed", "verified"}
			case "new", "assigned", "processing", "fixed", "verified", "closed":
			default:
				return nil, errors.New("无效的漏洞状态")
			}
			q = q.Where(alias+".status IN ?", statuses)
		}
		if req.Category != "" {
			q = q.Where("(o.code = ? OR o.name = ? OR CAST(o.id AS CHAR) = ?)", req.Category, req.Category, req.Category)
		}
	case "assets":
		if req.AssetID != "" {
			q = q.Where(alias+".id = ?", req.AssetID)
		}
		if req.UserID != "" {
			q = q.Where(alias+".owner_id = ?", req.UserID)
		}
		if req.Category != "" {
			q = q.Where(alias+".category = ?", req.Category)
		}
		if req.Status != "" {
			q = q.Where(alias+".status = ?", req.Status)
		}
	case "reports":
		if req.UserID != "" {
			q = q.Where(alias+".uploader_id = ?", req.UserID)
		}
		if req.AssetID != "" {
			q = q.Where("JSON_CONTAINS("+alias+".asset_ids, ?)", req.AssetID)
		}
		if req.Status != "" {
			q = q.Where(alias+".status = ?", req.Status)
		}
		if req.Severity != "" {
			q = q.Where(alias+".severity = ?", req.Severity)
		}
		if req.Category != "" {
			q = q.Where(alias+".type = ?", req.Category)
		}
	case "users":
		if req.UserID != "" {
			q = q.Where(alias+".id = ?", req.UserID)
		}
		if req.Status != "" {
			status := req.Status
			if status == "active" {
				status = "1"
			}
			if status == "inactive" {
				status = "0"
			}
			q = q.Where(alias+".status = ?", status)
		}
	}
	return q, nil
}

type analyticsQuery func() *gorm.DB

func (r *analyticsRepository) queryFactory(table, alias string, req *model.AnalyticsRequest) (analyticsQuery, error) {
	q, err := r.filteredQuery(table, alias, req)
	if err != nil {
		return nil, err
	}
	return func() *gorm.DB { return q.Session(&gorm.Session{}) }, nil
}

func severityName(level int) string {
	switch level {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	case 4:
		return "low"
	default:
		return "unknown"
	}
}

// Keep the analytics response vocabulary while reading actual workflow states.
func analyticsStatus(status string) string {
	switch status {
	case "new":
		return "open"
	case "assigned", "in_progress", "processing":
		return "in_progress"
	case "fixed", "verified":
		return "resolved"
	default:
		return status
	}
}

const analyticsCategory = "COALESCE(NULLIF(o.code, ''), o.name, '未分类')"

func (r *analyticsRepository) GetDashboardStats() (*model.DashboardStats, error) {
	stats := &model.DashboardStats{}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		repo := &analyticsRepository{db: tx}
		for _, c := range []struct {
			table string
			count *int64
		}{
			{"vulnerabilities", &stats.TotalVulnerabilities}, {"assets", &stats.TotalAssets}, {"users", &stats.TotalUsers}, {"reports", &stats.TotalReports},
		} {
			if err := tx.Table(c.table).Count(c.count).Error; err != nil {
				return err
			}
		}
		// Join existing assets so orphan vulnerability references cannot inflate coverage.
		if err := tx.Table("assets a").Joins("JOIN vulnerabilities v ON v.asset_id = a.id").Distinct("a.id").Count(&stats.AssetsWithVulnerabilities).Error; err != nil {
			return err
		}
		var statuses []struct {
			Status string
			Count  int64
		}
		if err := tx.Table("vulnerabilities").Select("status, COUNT(*) AS count").Group("status").Scan(&statuses).Error; err != nil {
			return err
		}
		for _, s := range statuses {
			switch analyticsStatus(s.Status) {
			case "open":
				stats.VulnerabilityStats.Open += s.Count
			case "in_progress":
				stats.VulnerabilityStats.InProgress += s.Count
			case "resolved":
				stats.VulnerabilityStats.Resolved += s.Count
			case "closed":
				stats.VulnerabilityStats.Closed += s.Count
			}
		}
		var severities []struct {
			SeverityLevel int
			Count         int64
		}
		if err := tx.Table("vulnerabilities").Select("severity_level, COUNT(*) AS count").Group("severity_level").Order("severity_level").Scan(&severities).Error; err != nil {
			return err
		}
		for _, s := range severities {
			name := severityName(s.SeverityLevel)
			stats.SeverityStats = append(stats.SeverityStats, model.SeverityCount{Severity: name, Count: s.Count, Color: model.GetSeverityColor(name)})
		}
		if err := tx.Table("assets").Select("type, COUNT(*) AS count").Group("type").Order("type").Scan(&stats.AssetTypeStats).Error; err != nil {
			return err
		}
		if err := tx.Table("vulnerabilities v").Select(analyticsCategory + " AS type, COUNT(*) AS count").Joins("LEFT JOIN owasp_categories o ON o.id = v.owasp_category_id").Group(analyticsCategory).Order("count DESC, type").Limit(10).Scan(&stats.TopVulnerabilityTypes).Error; err != nil {
			return err
		}
		if err := tx.Table("vulnerabilities v").Select("u.id AS user_id, u.username, u.real_name, COUNT(*) AS activity_count").Joins("JOIN users u ON u.id = v.discoverer_id").Where("v.created_at >= ?", time.Now().AddDate(0, 0, -30)).Group("u.id, u.username, u.real_name").Order("activity_count DESC, u.id").Limit(10).Scan(&stats.ActiveUsers).Error; err != nil {
			return err
		}
		for _, c := range []struct {
			table string
			dest  *model.TimeRangeStats
		}{
			{"vulnerabilities", &stats.VulnerabilityTimeStats}, {"assets", &stats.AssetTimeStats}, {"users", &stats.UserTimeStats}, {"reports", &stats.ReportTimeStats},
		} {
			value, err := repo.GetTimeRangeStats(c.table, "created_at")
			if err != nil {
				return err
			}
			*c.dest = *value
		}
		end := time.Now()
		start := end.AddDate(0, 0, -7)
		var err error
		stats.RecentTrends.VulnerabilityTrend, err = repo.GetVulnerabilityTrend(start, end, "day")
		if err != nil {
			return err
		}
		stats.RecentTrends.AssetTrend, err = repo.GetAssetGrowthTrend(start, end, "day")
		if err != nil {
			return err
		}
		stats.RecentTrends.ReportTrend, err = repo.GetReportSubmissionTrend(start, end, "day")
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("获取仪表盘统计失败: %w", err)
	}
	return stats, nil
}

func (r *analyticsRepository) GetVulnerabilityAnalytics(req *model.AnalyticsRequest) (*model.VulnerabilityAnalytics, error) {
	base, err := r.queryFactory("vulnerabilities", "v", req)
	if err != nil {
		return nil, err
	}
	a := &model.VulnerabilityAnalytics{}
	ts, err := timeRangeStats(base, "v.created_at", time.Now())
	if err != nil {
		return nil, err
	}
	a.TimeRangeStats = *ts
	var statuses []struct {
		Status string
		Count  int64
	}
	if err := base().Select("v.status, COUNT(*) AS count").Group("v.status").Scan(&statuses).Error; err != nil {
		return nil, err
	}
	counts := map[string]int64{}
	for _, s := range statuses {
		counts[analyticsStatus(s.Status)] += s.Count
	}
	keys := make([]string, 0, len(counts))
	for s := range counts {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	for _, s := range keys {
		a.StatusDistribution = append(a.StatusDistribution, model.StatusCount{Status: s, Count: counts[s], Color: model.GetStatusColor(s)})
	}
	if err := base().Select(analyticsCategory + " AS category, COUNT(*) AS count").Group(analyticsCategory).Order("count DESC, category").Scan(&a.OWASPStats).Error; err != nil {
		return nil, err
	}
	if err := base().Select("a.id AS asset_id, a.name AS asset_name, a.type AS asset_type, COUNT(*) AS count").Joins("JOIN assets a ON a.id = v.asset_id").Group("a.id, a.name, a.type").Order("count DESC, a.id").Limit(20).Scan(&a.AssetVulnerabilityDistribution).Error; err != nil {
		return nil, err
	}
	var durations []struct {
		CreatedAt time.Time
		FixedAt   time.Time
	}
	if err := base().Select("v.created_at, v.fixed_at").Where("v.status IN ? AND v.fixed_at IS NOT NULL", []string{"fixed", "verified", "closed"}).Scan(&durations).Error; err != nil {
		return nil, err
	}
	fixTimes := make([]float64, 0, len(durations))
	ranges := make([]int64, 5)
	for _, d := range durations {
		days := calendarDays(d.CreatedAt, d.FixedAt)
		fixTimes = append(fixTimes, days)
		switch {
		case days <= 1:
			ranges[0]++
		case days <= 7:
			ranges[1]++
		case days <= 30:
			ranges[2]++
		case days <= 90:
			ranges[3]++
		default:
			ranges[4]++
		}
	}
	a.FixTimeStats.AverageFixTime, a.FixTimeStats.MedianFixTime = durationStats(fixTimes)
	labels := []string{"1天内", "1-7天", "1-4周", "1-3个月", "3个月以上"}
	for i, n := range ranges {
		if n > 0 {
			a.FixTimeStats.FixTimeRanges = append(a.FixTimeStats.FixTimeRanges, model.FixTimeRangeCount{Range: labels[i], Count: n})
		}
	}
	if err := base().Select("u.id AS discoverer_id, u.username, u.real_name, COUNT(*) AS count").Joins("JOIN users u ON u.id = v.discoverer_id").Group("u.id, u.username, u.real_name").Order("count DESC, u.id").Limit(10).Scan(&a.DiscovererStats).Error; err != nil {
		return nil, err
	}
	a.SeverityTrend, err = severityTrend(base, "v.created_at")
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Match MySQL DATEDIFF's calendar-day semantics, independent of time-of-day/DST.
func calendarDays(start, end time.Time) float64 {
	s := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
	e := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)
	return e.Sub(s).Hours() / 24
}

func durationStats(values []float64) (average, median float64) {
	if len(values) == 0 {
		return 0, 0
	}
	for _, v := range values {
		average += v
	}
	average /= float64(len(values))
	sort.Float64s(values)
	mid := len(values) / 2
	if len(values)%2 == 0 {
		median = (values[mid-1] + values[mid]) / 2
	} else {
		median = values[mid]
	}
	return
}

func trendQuery(q *gorm.DB, column, granularity string) ([]model.TrendPoint, error) {
	format, err := validateGranularity(granularity)
	if err != nil {
		return nil, err
	}
	var trends []model.TrendPoint
	err = q.Select(fmt.Sprintf("DATE_FORMAT(%s, '%s') AS date, COUNT(*) AS count", column, format)).Group("date").Order("date").Scan(&trends).Error
	return trends, err
}

func firstAnalyticsFilter(filters []*model.AnalyticsRequest) *model.AnalyticsRequest {
	if len(filters) > 0 {
		return filters[0]
	}
	return nil
}

func (r *analyticsRepository) GetVulnerabilityTrend(start, end time.Time, granularity string, filters ...*model.AnalyticsRequest) ([]model.TrendPoint, error) {
	q, err := r.filteredQuery("vulnerabilities", "v", firstAnalyticsFilter(filters))
	if err != nil {
		return nil, err
	}
	return trendQuery(q.Where("v.created_at >= ? AND v.created_at < ?", start, end), "v.created_at", granularity)
}

func severityTrend(base analyticsQuery, column string) ([]model.SeverityTrendPoint, error) {
	var rows []struct {
		Date          string
		SeverityLevel int
		Count         int64
	}
	if err := base().Select("DATE_FORMAT(" + column + ", '%Y-%m-%d') AS date, v.severity_level, COUNT(*) AS count").Group("date, v.severity_level").Order("date, v.severity_level").Scan(&rows).Error; err != nil {
		return nil, err
	}
	trends := make([]model.SeverityTrendPoint, 0)
	for _, row := range rows {
		if len(trends) == 0 || trends[len(trends)-1].Date != row.Date {
			trends = append(trends, model.SeverityTrendPoint{Date: row.Date})
		}
		p := &trends[len(trends)-1]
		switch row.SeverityLevel {
		case 1:
			p.Critical += row.Count
		case 2:
			p.High += row.Count
		case 3:
			p.Medium += row.Count
		case 4:
			p.Low += row.Count
		}
	}
	return trends, nil
}

func (r *analyticsRepository) GetSeverityTrend(start, end time.Time, filters ...*model.AnalyticsRequest) ([]model.SeverityTrendPoint, error) {
	q, err := r.filteredQuery("vulnerabilities", "v", firstAnalyticsFilter(filters))
	if err != nil {
		return nil, err
	}
	q = q.Where("v.created_at >= ? AND v.created_at < ?", start, end)
	return severityTrend(func() *gorm.DB { return q.Session(&gorm.Session{}) }, "v.created_at")
}

func validateTableAndColumn(table, column string) error {
	valid := map[string][]string{"vulnerabilities": {"created_at", "updated_at", "fixed_at"}, "assets": {"created_at", "updated_at"}, "reports": {"created_at", "reviewed_at"}, "users": {"created_at", "last_login_at"}}
	for _, c := range valid[table] {
		if c == column {
			return nil
		}
	}
	return errors.New("无效的表名或列名")
}

func (r *analyticsRepository) GetTimeRangeStats(table, column string) (*model.TimeRangeStats, error) {
	if err := validateTableAndColumn(table, column); err != nil {
		return nil, err
	}
	return timeRangeStats(func() *gorm.DB { return r.db.Table(table) }, column, time.Now())
}

func timeRangeStats(base analyticsQuery, column string, now time.Time) (*model.TimeRangeStats, error) {
	stats := &model.TimeRangeStats{}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	week := today.AddDate(0, 0, -(int(today.Weekday())+6)%7)
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	periods := []struct {
		start, end time.Time
		alias      string
	}{
		{today, today.AddDate(0, 0, 1), "today"}, {today.AddDate(0, 0, -1), today, "yesterday"},
		{week, week.AddDate(0, 0, 7), "this_week"}, {week.AddDate(0, 0, -7), week, "last_week"},
		{month, month.AddDate(0, 1, 0), "this_month"}, {month.AddDate(0, -1, 0), month, "last_month"},
	}
	selections := make([]string, 0, len(periods))
	args := make([]interface{}, 0, len(periods)*2)
	earliest, latest := periods[0].start, periods[0].end
	for _, period := range periods {
		selections = append(selections, "COALESCE(SUM(CASE WHEN "+column+" >= ? AND "+column+" < ? THEN 1 ELSE 0 END), 0) AS "+period.alias)
		args = append(args, period.start, period.end)
		if period.start.Before(earliest) {
			earliest = period.start
		}
		if period.end.After(latest) {
			latest = period.end
		}
	}
	err := base().Select(strings.Join(selections, ", "), args...).Where(column+" >= ? AND "+column+" < ?", earliest, latest).Scan(stats).Error
	return stats, err
}

func (r *analyticsRepository) GetAssetAnalytics(req *model.AnalyticsRequest) (*model.AssetAnalytics, error) {
	base, err := r.queryFactory("assets", "a", req)
	if err != nil {
		return nil, err
	}
	a := &model.AssetAnalytics{}
	if err := base().Select("a.type, COUNT(*) AS count").Group("a.type").Order("a.type").Scan(&a.TypeDistribution).Error; err != nil {
		return nil, err
	}
	var importance []struct {
		Level int
		Count int64
	}
	if err := base().Select("a.importance_level AS level, COUNT(*) AS count").Group("a.importance_level").Order("a.importance_level").Scan(&importance).Error; err != nil {
		return nil, err
	}
	for _, s := range importance {
		name := map[int]string{1: "high", 2: "medium", 3: "low"}[s.Level]
		if name == "" {
			name = "unknown"
		}
		a.ImportanceDistribution = append(a.ImportanceDistribution, model.ImportanceCount{Importance: name, Count: s.Count, Color: model.GetImportanceColor(name)})
	}
	if err := base().Select("a.status, COUNT(*) AS count").Group("a.status").Order("a.status").Scan(&a.StatusDistribution).Error; err != nil {
		return nil, err
	}
	a.RiskAssessment, err = assetRiskAssessment(base, req)
	if err != nil {
		return nil, err
	}
	a.GrowthTrend, err = trendQuery(base(), "a.created_at", requestGranularity(req))
	if err != nil {
		return nil, err
	}
	return a, nil
}

func requestGranularity(req *model.AnalyticsRequest) string {
	if req != nil && req.Granularity != "" {
		return req.Granularity
	}
	return "day"
}

func (r *analyticsRepository) GetAssetGrowthTrend(start, end time.Time, granularity string) ([]model.TrendPoint, error) {
	return trendQuery(r.db.Table("assets a").Where("a.created_at >= ? AND a.created_at < ?", start, end), "a.created_at", granularity)
}

// Restrict related activity to the same requested event window as the cohort.
func analyticsDateJoin(condition, alias string, req *model.AnalyticsRequest) (string, []interface{}) {
	var args []interface{}
	if req != nil && req.StartDate != "" {
		condition += " AND " + alias + ".created_at >= ?"
		args = append(args, req.StartDate)
	}
	if req != nil && req.EndDate != "" {
		end, _ := time.Parse("2006-01-02", req.EndDate) // Already validated by queryFactory.
		condition += " AND " + alias + ".created_at < ?"
		args = append(args, end.AddDate(0, 0, 1))
	}
	return condition, args
}

func assetRiskAssessment(base analyticsQuery, req *model.AnalyticsRequest) ([]model.AssetRiskCount, error) {
	var risks []model.AssetRiskCount
	join, args := analyticsDateJoin("LEFT JOIN vulnerabilities v ON a.id = v.asset_id", "v", req)
	err := base().Select(`a.id AS asset_id, a.name AS asset_name, a.type AS asset_type,
		COUNT(v.id) AS vulnerability_count,
		SUM(CASE WHEN v.severity_level = 1 THEN 1 ELSE 0 END) AS critical_count,
		SUM(CASE WHEN v.severity_level = 2 THEN 1 ELSE 0 END) AS high_count`).
		Joins(join, args...).Group("a.id, a.name, a.type").Having("COUNT(v.id) > 0").
		Order("critical_count DESC, high_count DESC, vulnerability_count DESC, a.id").Limit(20).Scan(&risks).Error
	if err != nil {
		return nil, err
	}
	for i := range risks {
		risks[i].RiskScore = int(risks[i].CriticalCount*10 + risks[i].HighCount*5 + risks[i].VulnerabilityCount)
	}
	return risks, nil
}

func (r *analyticsRepository) GetAssetRiskAssessment() ([]model.AssetRiskCount, error) {
	return assetRiskAssessment(func() *gorm.DB { return r.db.Table("assets a") }, nil)
}

func (r *analyticsRepository) GetReportAnalytics(req *model.AnalyticsRequest) (*model.ReportAnalytics, error) {
	base, err := r.queryFactory("reports", "r", req)
	if err != nil {
		return nil, err
	}
	a := &model.ReportAnalytics{}
	if err := base().Select("r.status, COUNT(*) AS count").Group("r.status").Order("r.status").Scan(&a.StatusDistribution).Error; err != nil {
		return nil, err
	}
	if err := base().Select("r.type, COUNT(*) AS count").Group("r.type").Order("r.type").Scan(&a.TypeDistribution).Error; err != nil {
		return nil, err
	}
	a.SubmissionTrend, err = trendQuery(base(), "r.created_at", requestGranularity(req))
	if err != nil {
		return nil, err
	}
	var durations []struct {
		CreatedAt  time.Time
		ReviewedAt time.Time
	}
	if err := base().Select("r.created_at, r.reviewed_at").Where("r.status IN ? AND r.reviewed_at IS NOT NULL", []string{"approved", "rejected"}).Scan(&durations).Error; err != nil {
		return nil, err
	}
	values := make([]float64, 0, len(durations))
	for _, d := range durations {
		values = append(values, calendarDays(d.CreatedAt, d.ReviewedAt))
	}
	a.ReviewTimeStats.AverageReviewTime, a.ReviewTimeStats.MedianReviewTime = durationStats(values)
	if err := base().Select("u.id AS submitter_id, u.username, u.real_name, COUNT(*) AS count").Joins("JOIN users u ON u.id = r.uploader_id").Group("u.id, u.username, u.real_name").Order("count DESC, u.id").Limit(10).Scan(&a.SubmitterStats).Error; err != nil {
		return nil, err
	}
	return a, nil
}

func (r *analyticsRepository) GetReportSubmissionTrend(start, end time.Time, granularity string) ([]model.TrendPoint, error) {
	return trendQuery(r.db.Table("reports r").Where("r.created_at >= ? AND r.created_at < ?", start, end), "r.created_at", granularity)
}

func (r *analyticsRepository) GetUserAnalytics(req *model.AnalyticsRequest) (*model.UserAnalytics, error) {
	base, err := r.queryFactory("users", "u", req)
	if err != nil {
		return nil, err
	}
	a := &model.UserAnalytics{}
	if err := base().Select("r.id AS role_id, r.name AS role_name, COUNT(*) AS count").Joins("JOIN roles r ON r.id = u.role_id").Group("r.id, r.name").Order("r.id").Scan(&a.RoleDistribution).Error; err != nil {
		return nil, err
	}
	statusExpr := "CASE WHEN u.status = 1 THEN 'active' ELSE 'inactive' END"
	if err := base().Select(statusExpr + " AS status, COUNT(*) AS count").Group(statusExpr).Order("status").Scan(&a.StatusDistribution).Error; err != nil {
		return nil, err
	}
	vulnJoin, vulnArgs := analyticsDateJoin("LEFT JOIN vulnerabilities v ON v.discoverer_id = u.id", "v", req)
	reportJoin, reportArgs := analyticsDateJoin("LEFT JOIN reports r ON r.uploader_id = u.id", "r", req)
	if err := base().Select(`u.id AS user_id, u.username, u.real_name,
		COUNT(DISTINCT v.id) AS vulnerabilities_found, COUNT(DISTINCT r.id) AS reports_submitted, u.last_login_at`).
		Joins(vulnJoin, vulnArgs...).Joins(reportJoin, reportArgs...).
		Group("u.id, u.username, u.real_name, u.last_login_at").Having("COUNT(DISTINCT v.id) > 0 OR COUNT(DISTINCT r.id) > 0").
		Order("vulnerabilities_found DESC, reports_submitted DESC, u.id").Limit(20).Scan(&a.ActivityStats).Error; err != nil {
		return nil, err
	}
	login := base().Where("u.last_login_at IS NOT NULL")
	if req != nil && req.StartDate != "" {
		login = login.Where("u.last_login_at >= ?", req.StartDate)
	}
	if req != nil && req.EndDate != "" {
		end, _ := time.Parse("2006-01-02", req.EndDate)
		login = login.Where("u.last_login_at < ?", end.AddDate(0, 0, 1))
	}
	a.LoginTrend, err = trendQuery(login, "u.last_login_at", requestGranularity(req))
	if err != nil {
		return nil, err
	}
	if err := base().Select("u.department, COUNT(*) AS count").Where("u.department <> ''").Group("u.department").Order("u.department").Scan(&a.DepartmentDistribution).Error; err != nil {
		return nil, err
	}
	return a, nil
}

func (r *analyticsRepository) GetUserLoginTrend(start, end time.Time, granularity string) ([]model.TrendPoint, error) {
	return trendQuery(r.db.Table("users u").Where("u.last_login_at >= ? AND u.last_login_at < ?", start, end), "u.last_login_at", granularity)
}

func (r *analyticsRepository) GetMonthlyVulnerabilityTrends() ([]model.MonthlyTrendPoint, error) {
	return r.monthlyVulnerabilityTrendsAt(time.Now())
}

func (r *analyticsRepository) monthlyVulnerabilityTrendsAt(now time.Time) ([]model.MonthlyTrendPoint, error) {
	start := time.Date(now.Year(), now.Month()-5, 1, 0, 0, 0, 0, now.Location())
	end := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
	discovered, err := trendQuery(r.db.Table("vulnerabilities").Where("created_at >= ? AND created_at < ?", start, end), "created_at", "month")
	if err != nil {
		return nil, err
	}
	resolved, err := trendQuery(r.db.Table("vulnerabilities").Where("status IN ? AND fixed_at >= ? AND fixed_at < ?", []string{"fixed", "verified", "closed"}, start, end), "fixed_at", "month")
	if err != nil {
		return nil, err
	}
	discoveredByMonth, resolvedByMonth := map[string]int64{}, map[string]int64{}
	for _, point := range discovered {
		discoveredByMonth[point.Date] = point.Count
	}
	for _, point := range resolved {
		resolvedByMonth[point.Date] = point.Count
	}
	trends := make([]model.MonthlyTrendPoint, 0, 6)
	for i := 0; i < 6; i++ {
		month := start.AddDate(0, i, 0)
		key := month.Format("2006-01")
		trends = append(trends, model.MonthlyTrendPoint{Month: month.Format("1月"), Vulnerabilities: discoveredByMonth[key], Resolved: resolvedByMonth[key]})
	}
	return trends, nil
}
