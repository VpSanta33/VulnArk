package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
)

var analyticsSQLiteDriver sync.Once

// Only tests register these compatibility functions. Production SQL stays MySQL.
func analyticsSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	analyticsSQLiteDriver.Do(func() {
		sql.Register("analytics_sqlite", &sqlite3.SQLiteDriver{ConnectHook: func(c *sqlite3.SQLiteConn) error {
			if err := c.RegisterFunc("DATE_FORMAT", func(value, format string) string {
				date, err := time.Parse("2006-01-02", value[:min(len(value), 10)])
				if err != nil {
					return ""
				}
				switch format {
				case "%Y-%m-%d":
					return date.Format("2006-01-02")
				case "%Y-%m":
					return date.Format("2006-01")
				case "%x-%v":
					year, week := date.ISOWeek()
					return fmt.Sprintf("%04d-%02d", year, week)
				default:
					return ""
				}
			}, true); err != nil {
				return err
			}
			return c.RegisterFunc("JSON_CONTAINS", func(document, candidate string) bool {
				var values []uint
				if json.Unmarshal([]byte(document), &values) != nil {
					return false
				}
				for _, value := range values {
					if fmt.Sprint(value) == candidate {
						return true
					}
				}
				return false
			}, true)
		}})
	})
	db, err := gorm.Open(sqlite.Dialector{DriverName: "analytics_sqlite", DSN: ":memory:"}, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	conn, err := db.DB()
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	analyticsSchema(t, db, false)
	return db
}

// This suite never reads application config or shared testutil. A dedicated DSN
// with an explicit test-database name is required; all fixtures are connection-
// local TEMPORARY tables and disappear when the test connection closes.
func TestAnalyticsRepositoryMySQL(t *testing.T) {
	dsn := os.Getenv("VULNARK_ANALYTICS_TEST_DSN")
	if dsn == "" {
		t.Skip("set VULNARK_ANALYTICS_TEST_DSN to an explicit MySQL test database DSN")
	}
	cfg, err := mysqldriver.ParseDSN(dsn)
	require.NoError(t, err)
	name := strings.ToLower(cfg.DBName)
	require.True(t, strings.HasSuffix(name, "_test") || strings.HasPrefix(name, "test_") || strings.Contains(name, "_test_"), "MySQL DSN database must contain an explicit _test marker")
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	db, err := gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	conn, err := db.DB()
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	analyticsSchema(t, db, true)
	analyticsFixtureAssertions(t, db)
	require.NoError(t, db.Exec("DELETE FROM vulnerabilities").Error)
	require.NoError(t, db.Exec("DELETE FROM assets").Error)
	analyticsOptimizationAssertions(t, db)
}

func TestAnalyticsRepositorySQLite(t *testing.T) { analyticsFixtureAssertions(t, analyticsSQLiteDB(t)) }

func analyticsSchema(t *testing.T, db *gorm.DB, temporary bool) {
	t.Helper()
	prefix := "CREATE TABLE "
	if temporary {
		prefix = "CREATE TEMPORARY TABLE "
	}
	definitions := []string{
		"owasp_categories (id BIGINT PRIMARY KEY, code VARCHAR(20), name VARCHAR(100), severity_level INT)",
		"roles (id BIGINT PRIMARY KEY, name VARCHAR(50))",
		"users (id BIGINT PRIMARY KEY, created_at DATETIME(6), username VARCHAR(50), real_name VARCHAR(50), role_id BIGINT, department VARCHAR(100), status INT, last_login_at DATETIME(6))",
		"assets (id BIGINT PRIMARY KEY, created_at DATETIME(6), name VARCHAR(100), type VARCHAR(50), category VARCHAR(50), owner_id BIGINT, importance_level INT, status INT)",
		"vulnerabilities (id BIGINT PRIMARY KEY, created_at DATETIME(6), updated_at DATETIME(6), status VARCHAR(20), severity_level INT, asset_id BIGINT, discoverer_id BIGINT, owasp_category_id BIGINT, fixed_at DATETIME(6))",
		"reports (id BIGINT PRIMARY KEY, created_at DATETIME(6), reviewed_at DATETIME(6), status VARCHAR(20), type VARCHAR(50), severity VARCHAR(20), uploader_id BIGINT, asset_ids JSON)",
	}
	for _, def := range definitions {
		if !temporary {
			def = strings.ReplaceAll(def, "DATETIME(6)", "DATETIME")
		}
		require.NoError(t, db.Exec(prefix+def).Error)
	}
}

func analyticsFixtureAssertions(t *testing.T, db *gorm.DB) {
	t.Helper()
	stamp := func(day int) time.Time { return time.Date(2025, 1, day, 12, 0, 0, 0, time.UTC) }
	insert := func(table string, values map[string]interface{}) {
		t.Helper()
		require.NoError(t, db.Table(table).Create(values).Error)
	}
	insert("owasp_categories", map[string]interface{}{"id": 1, "code": "A01", "name": "Access control"})
	insert("owasp_categories", map[string]interface{}{"id": 2, "code": "A02", "name": "Cryptography"})
	insert("roles", map[string]interface{}{"id": 1, "name": "Analyst"})
	insert("roles", map[string]interface{}{"id": 2, "name": "Reader"})
	for i := 1; i <= 3; i++ {
		created := stamp(2)
		if i == 3 {
			created = stamp(1).AddDate(0, -1, 0)
		}
		insert("users", map[string]interface{}{"id": i, "created_at": created, "username": fmt.Sprintf("user%d", i), "real_name": "Analyst", "role_id": (i-1)%2 + 1, "department": fmt.Sprintf("dept%d", i), "status": i % 2, "last_login_at": stamp(4)})
		insert("assets", map[string]interface{}{"id": i, "created_at": created, "name": fmt.Sprintf("asset%d", i), "type": []string{"server", "database", "application"}[i-1], "category": "production", "owner_id": i, "importance_level": i, "status": 1})
	}
	addVuln := func(id, day, fix, level, asset, user, category int, status string) {
		var fixed interface{}
		if fix > 0 {
			fixed = stamp(fix)
		}
		insert("vulnerabilities", map[string]interface{}{"id": id, "created_at": stamp(day), "updated_at": stamp(25), "fixed_at": fixed, "severity_level": level, "asset_id": asset, "discoverer_id": user, "owasp_category_id": category, "status": status})
	}
	// Desired cohort has durations [8,1,4], deliberately not sorted by duration.
	addVuln(1, 2, 10, 1, 1, 1, 1, "fixed")
	addVuln(2, 3, 4, 1, 1, 1, 1, "fixed")
	addVuln(3, 4, 8, 1, 1, 1, 1, "verified")
	require.NoError(t, db.Table("vulnerabilities").Where("id = 3").Update("created_at", time.Date(2025, 1, 4, 23, 59, 59, 999000000, time.UTC)).Error)
	addVuln(4, 4, 5, 2, 1, 1, 1, "fixed")
	addVuln(5, 3, 6, 1, 2, 1, 1, "fixed")
	addVuln(6, 3, 6, 1, 1, 2, 1, "fixed")
	addVuln(7, 3, 6, 1, 1, 1, 2, "fixed")
	addVuln(8, 3, 0, 1, 1, 1, 1, "new")
	addVuln(9, 5, 8, 1, 1, 1, 1, "fixed")
	addVuln(10, 1, 4, 1, 1, 1, 1, "fixed")
	addVuln(11, 3, 0, 3, 2, 2, 2, "assigned")
	addVuln(12, 3, 0, 4, 2, 2, 2, "in_progress")
	addVuln(13, 3, 6, 4, 2, 2, 2, "closed")
	for i, days := range []int{8, 1, 4} {
		day := i + 2
		insert("reports", map[string]interface{}{"id": i + 1, "created_at": stamp(day), "reviewed_at": stamp(day + days), "status": "approved", "type": "audit", "severity": "high", "uploader_id": 1, "asset_ids": "[1]"})
	}
	insert("reports", map[string]interface{}{"id": 4, "created_at": stamp(5), "reviewed_at": stamp(20), "status": "approved", "type": "other", "severity": "low", "uploader_id": 1, "asset_ids": "[2]"})
	insert("reports", map[string]interface{}{"id": 5, "created_at": stamp(3), "reviewed_at": stamp(20), "status": "rejected", "type": "other", "severity": "low", "uploader_id": 2, "asset_ids": "[2]"})
	repo := NewAnalyticsRepository(db)
	req := &model.AnalyticsRequest{StartDate: "2025-01-02", EndDate: "2025-01-04", Severity: "critical", Status: "resolved", AssetID: "1", UserID: "1", Category: "A01"}
	a, err := repo.GetVulnerabilityAnalytics(req)
	require.NoError(t, err)
	require.Equal(t, []model.StatusCount{{Status: "resolved", Count: 3, Color: model.GetStatusColor("resolved")}}, a.StatusDistribution)
	require.Equal(t, []model.OWASPCount{{Category: "A01", Count: 3}}, a.OWASPStats)
	filteredBase, err := repo.(*analyticsRepository).queryFactory("vulnerabilities", "v", req)
	require.NoError(t, err)
	filteredTimeStats, err := timeRangeStats(filteredBase, "v.created_at", stamp(3))
	require.NoError(t, err)
	require.Equal(t, &model.TimeRangeStats{Today: 1, Yesterday: 1, ThisWeek: 3, ThisMonth: 3}, filteredTimeStats)
	require.Len(t, a.AssetVulnerabilityDistribution, 1)
	require.EqualValues(t, 3, a.AssetVulnerabilityDistribution[0].Count)
	require.Len(t, a.DiscovererStats, 1)
	require.EqualValues(t, 3, a.DiscovererStats[0].Count)
	require.InDelta(t, 13.0/3, a.FixTimeStats.AverageFixTime, 0.0001)
	require.Equal(t, 4.0, a.FixTimeStats.MedianFixTime)
	require.Equal(t, []model.FixTimeRangeCount{{Range: "1天内", Count: 1}, {Range: "1-7天", Count: 1}, {Range: "1-4周", Count: 1}}, a.FixTimeStats.FixTimeRanges)
	require.Len(t, a.SeverityTrend, 3)
	require.EqualValues(t, 1, a.SeverityTrend[2].Critical)
	require.Equal(t, "2025-01-04", a.SeverityTrend[2].Date)
	trend, err := repo.GetVulnerabilityTrend(stamp(2).Add(-12*time.Hour), stamp(5).Add(-12*time.Hour), "day", req)
	require.NoError(t, err)
	require.Equal(t, []model.TrendPoint{{Date: "2025-01-02", Count: 1}, {Date: "2025-01-03", Count: 1}, {Date: "2025-01-04", Count: 1}}, trend)
	severity, err := repo.GetSeverityTrend(stamp(2).Add(-12*time.Hour), stamp(5).Add(-12*time.Hour), req)
	require.NoError(t, err)
	require.Equal(t, a.SeverityTrend, severity)
	weekTrend, err := repo.GetVulnerabilityTrend(stamp(2).Add(-12*time.Hour), stamp(5).Add(-12*time.Hour), "week", req)
	require.NoError(t, err)
	require.Equal(t, []model.TrendPoint{{Date: "2025-01", Count: 3}}, weekTrend)
	monthTrend, err := repo.GetVulnerabilityTrend(stamp(2).Add(-12*time.Hour), stamp(5).Add(-12*time.Hour), "month", req)
	require.NoError(t, err)
	require.Equal(t, []model.TrendPoint{{Date: "2025-01", Count: 3}}, monthTrend)
	endOnly := &model.AnalyticsRequest{EndDate: "2025-01-01"}
	early, err := repo.GetVulnerabilityAnalytics(endOnly)
	require.NoError(t, err)
	require.Len(t, early.DiscovererStats, 1)
	require.EqualValues(t, 1, early.DiscovererStats[0].Count)
	startOnly, err := repo.GetVulnerabilityAnalytics(&model.AnalyticsRequest{StartDate: "2025-01-05"})
	require.NoError(t, err)
	require.Len(t, startOnly.OWASPStats, 1)
	require.EqualValues(t, 1, startOnly.OWASPStats[0].Count)
	all, err := repo.GetDashboardStats()
	require.NoError(t, err)
	require.EqualValues(t, 13, all.TotalVulnerabilities)
	require.EqualValues(t, 3, all.TotalAssets)
	require.EqualValues(t, 2, all.AssetsWithVulnerabilities)
	require.EqualValues(t, 1, all.VulnerabilityStats.Open)
	require.EqualValues(t, 2, all.VulnerabilityStats.InProgress)
	require.EqualValues(t, 9, all.VulnerabilityStats.Resolved)
	require.EqualValues(t, 1, all.VulnerabilityStats.Closed)
	require.Len(t, all.TopVulnerabilityTypes, 2)
	risk, err := repo.GetAssetRiskAssessment()
	require.NoError(t, err)
	require.Len(t, risk, 2)
	require.EqualValues(t, 1, risk[0].AssetID)
	require.EqualValues(t, 8, risk[0].CriticalCount)
	require.EqualValues(t, 1, risk[0].HighCount)
	assets, err := repo.GetAssetAnalytics(&model.AnalyticsRequest{StartDate: "2025-01-02", EndDate: "2025-01-04", AssetID: "1"})
	require.NoError(t, err)
	require.Equal(t, []model.AssetTypeCount{{Type: "server", Count: 1}}, assets.TypeDistribution)
	require.Len(t, assets.ImportanceDistribution, 1)
	require.Equal(t, "high", assets.ImportanceDistribution[0].Importance)
	require.Len(t, assets.StatusDistribution, 1)
	require.Len(t, assets.RiskAssessment, 1)
	require.EqualValues(t, 7, assets.RiskAssessment[0].VulnerabilityCount)
	reports, err := repo.GetReportAnalytics(&model.AnalyticsRequest{StartDate: "2025-01-02", EndDate: "2025-01-04", UserID: "1", Status: "approved", Severity: "high", AssetID: "1", Category: "audit"})
	require.NoError(t, err)
	require.Equal(t, []model.ReportTypeCount{{Type: "audit", Count: 3}}, reports.TypeDistribution)
	require.Len(t, reports.SubmitterStats, 1)
	require.EqualValues(t, 1, reports.SubmitterStats[0].SubmitterID)
	require.EqualValues(t, 3, reports.SubmitterStats[0].Count)
	require.Equal(t, 4.0, reports.ReviewTimeStats.MedianReviewTime)
	require.Len(t, reports.SubmissionTrend, 3)
	users, err := repo.GetUserAnalytics(&model.AnalyticsRequest{StartDate: "2025-01-02", EndDate: "2025-01-04", UserID: "1"})
	require.NoError(t, err)
	require.Len(t, users.RoleDistribution, 1)
	require.Equal(t, []model.UserStatusCount{{Status: "active", Count: 1}}, users.StatusDistribution)
	require.Len(t, users.DepartmentDistribution, 1)
	require.Len(t, users.ActivityStats, 1)
	require.EqualValues(t, 7, users.ActivityStats[0].VulnerabilitiesFound)
	require.EqualValues(t, 3, users.ActivityStats[0].ReportsSubmitted)
	require.Len(t, users.LoginTrend, 1)
	// Month of fixing differs from the last update. Fractional end-of-month
	// timestamps must be counted without subtracting one second from the bound.
	now := time.Now()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	previous := month.AddDate(0, -1, 0)
	require.NoError(t, db.Table("vulnerabilities").Create(map[string]interface{}{"id": 100, "created_at": previous.Add(12 * time.Hour), "updated_at": month.Add(12 * time.Hour), "fixed_at": month.Add(-time.Millisecond), "status": "closed", "severity_level": 4, "asset_id": 1, "discoverer_id": 1}).Error)
	monthly, err := repo.GetMonthlyVulnerabilityTrends()
	require.NoError(t, err)
	require.Len(t, monthly, 6)
	require.EqualValues(t, 1, monthly[4].Resolved)
	require.EqualValues(t, 0, monthly[5].Resolved)
	// Coverage counts existing assets once, independently of the Top20 risk list.
	for id := 1000; id < 1025; id++ {
		insert("assets", map[string]interface{}{"id": id, "created_at": stamp(2), "name": fmt.Sprint(id), "type": "server", "importance_level": 3, "status": 1})
		insert("vulnerabilities", map[string]interface{}{"id": id, "created_at": stamp(2), "asset_id": id, "severity_level": 4, "status": "new"})
	}
	for id, assetID := range map[int]int{3000: 1000, 3001: 9999} {
		insert("vulnerabilities", map[string]interface{}{"id": id, "created_at": stamp(2), "asset_id": assetID, "severity_level": 4, "status": "new"})
	}
	coverage, err := repo.GetDashboardStats()
	require.NoError(t, err)
	require.EqualValues(t, 28, coverage.TotalAssets)
	require.EqualValues(t, 27, coverage.AssetsWithVulnerabilities)
}

func TestAnalyticsCalendarPeriodsAndErrors(t *testing.T) {
	db := analyticsSQLiteDB(t)
	now := time.Date(2025, 1, 2, 12, 0, 0, 0, time.UTC)
	for i, date := range []string{"2024-12-23", "2024-12-31", "2025-01-01", "2025-01-02"} {
		require.NoError(t, db.Table("vulnerabilities").Create(map[string]interface{}{"id": i + 1, "created_at": date + " 12:00:00"}).Error)
	}
	base := func() *gorm.DB { return db.Table("vulnerabilities") }
	stats, err := timeRangeStats(base, "created_at", now)
	require.NoError(t, err)
	require.Equal(t, &model.TimeRangeStats{Today: 1, Yesterday: 1, ThisWeek: 3, LastWeek: 1, ThisMonth: 2, LastMonth: 2}, stats)
	repo := NewAnalyticsRepository(db)
	for _, req := range []*model.AnalyticsRequest{{StartDate: "bad"}, {EndDate: "2025-02-30"}, {StartDate: "2025-02-02", EndDate: "2025-02-01"}, {Granularity: "day'); DROP TABLE users; --"}, {Severity: "unknown"}, {Status: "imaginary"}, {AssetID: "1 OR 1=1"}} {
		_, err := repo.GetVulnerabilityAnalytics(req)
		require.Error(t, err)
	}
	_, err = repo.GetTimeRangeStats("vulnerabilities", "resolved_at")
	require.Error(t, err)
	_, err = repo.GetTimeRangeStats("users; DROP TABLE users", "created_at")
	require.Error(t, err)
	// Missing related table must be an error, rather than successful partial stats.
	require.NoError(t, db.Exec("DROP TABLE owasp_categories").Error)
	_, err = repo.GetDashboardStats()
	require.Error(t, err)
	_, err = repo.GetVulnerabilityAnalytics(&model.AnalyticsRequest{})
	require.Error(t, err)
	conn, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	for _, call := range []func() error{
		func() error { _, e := repo.GetDashboardStats(); return e }, func() error { _, e := repo.GetVulnerabilityAnalytics(nil); return e },
		func() error { _, e := repo.GetVulnerabilityTrend(now, now.AddDate(0, 0, 1), "day"); return e }, func() error { _, e := repo.GetSeverityTrend(now, now.AddDate(0, 0, 1)); return e },
		func() error { _, e := repo.GetAssetAnalytics(nil); return e }, func() error { _, e := repo.GetAssetGrowthTrend(now, now.AddDate(0, 0, 1), "day"); return e }, func() error { _, e := repo.GetAssetRiskAssessment(); return e },
		func() error { _, e := repo.GetReportAnalytics(nil); return e }, func() error { _, e := repo.GetReportSubmissionTrend(now, now.AddDate(0, 0, 1), "day"); return e },
		func() error { _, e := repo.GetUserAnalytics(nil); return e }, func() error { _, e := repo.GetUserLoginTrend(now, now.AddDate(0, 0, 1), "day"); return e },
		func() error { _, e := repo.GetTimeRangeStats("assets", "created_at"); return e }, func() error { _, e := repo.GetMonthlyVulnerabilityTrends(); return e },
	} {
		require.Error(t, call())
	}
}

func TestAnalyticsDurationMedian(t *testing.T) {
	for _, tc := range []struct {
		values          []float64
		average, median float64
	}{{nil, 0, 0}, {[]float64{8, 1, 4}, 13.0 / 3, 4}, {[]float64{10, 1, 8, 2}, 5.25, 5}} {
		avg, median := durationStats(tc.values)
		require.Equal(t, tc.average, avg)
		require.Equal(t, tc.median, median)
	}
}
