package repository

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
)

type selectCounter struct {
	logger.Interface
	count atomic.Int64
}

func (l *selectCounter) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, _ := fc()
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "SELECT") {
		l.count.Add(1)
	}
}

func TestAnalyticsBoundedQueryCountsAndEmptyResults(t *testing.T) {
	db := analyticsSQLiteDB(t)
	analyticsOptimizationAssertions(t, db)
}

func analyticsOptimizationAssertions(t *testing.T, db *gorm.DB) {
	t.Helper()
	counter := &selectCounter{Interface: logger.Default.LogMode(logger.Silent)}
	repo := &analyticsRepository{db: db.Session(&gorm.Session{Logger: counter})}
	_, err := repo.GetDashboardStats()
	require.NoError(t, err)
	require.EqualValues(t, 17, counter.count.Load())
	counter.count.Store(0)
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	trends, err := repo.monthlyVulnerabilityTrendsAt(now)
	require.NoError(t, err)
	require.Len(t, trends, 6)
	require.EqualValues(t, 2, counter.count.Load())
	require.Equal(t, "8月", trends[0].Month)
	require.Equal(t, "1月", trends[5].Month)
	for _, trend := range trends {
		require.Zero(t, trend.Vulnerabilities)
		require.Zero(t, trend.Resolved)
	}
	// Creation and resolution belong to their respective month, even across a year boundary.
	for i, stamp := range []time.Time{time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)} {
		require.NoError(t, db.Table("vulnerabilities").Create(map[string]interface{}{"id": 100 + i, "created_at": stamp, "fixed_at": now, "status": "fixed"}).Error)
	}
	trends, err = repo.monthlyVulnerabilityTrendsAt(now)
	require.NoError(t, err)
	require.EqualValues(t, 1, trends[0].Vulnerabilities)
	require.EqualValues(t, 1, trends[4].Vulnerabilities)
	require.EqualValues(t, 3, trends[5].Resolved)
	require.Zero(t, trends[5].Vulnerabilities)
	// Compare the single aggregate against independent reference counts at all six boundaries.
	for i, stamp := range []time.Time{now.AddDate(0, 0, -1), now, now.AddDate(0, 0, -8), now.AddDate(0, -1, 0)} {
		require.NoError(t, db.Table("assets").Create(map[string]interface{}{"id": 200 + i, "created_at": stamp, "name": "time"}).Error)
	}
	stats, err := timeRangeStats(func() *gorm.DB { return db.Table("assets") }, "created_at", now)
	require.NoError(t, err)
	today := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	week := today.AddDate(0, 0, -3)
	month := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, period := range []struct {
		start, end time.Time
		got        int64
	}{
		{today, today.AddDate(0, 0, 1), stats.Today}, {today.AddDate(0, 0, -1), today, stats.Yesterday},
		{week, week.AddDate(0, 0, 7), stats.ThisWeek}, {week.AddDate(0, 0, -7), week, stats.LastWeek},
		{month, month.AddDate(0, 1, 0), stats.ThisMonth}, {month.AddDate(0, -1, 0), month, stats.LastMonth},
	} {
		var expected int64
		require.NoError(t, db.Table("assets").Where("created_at >= ? AND created_at < ?", period.start, period.end).Count(&expected).Error)
		require.Equal(t, expected, period.got)
	}
	require.NoError(t, db.Exec("DELETE FROM assets").Error)
	empty, err := timeRangeStats(func() *gorm.DB { return db.Table("assets") }, "created_at", now)
	require.NoError(t, err)
	require.Equal(t, &model.TimeRangeStats{}, empty)
}
