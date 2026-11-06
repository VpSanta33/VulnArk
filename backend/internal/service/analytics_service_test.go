package service

import (
	"encoding/csv"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

type analyticsRepoStub struct {
	repository.AnalyticsRepository
	fail        error
	request     *model.AnalyticsRequest
	start, end  time.Time
	granularity string
}

func (r *analyticsRepoStub) GetDashboardStats() (*model.DashboardStats, error) {
	return &model.DashboardStats{TotalVulnerabilities: 12, TotalAssets: 3, TotalUsers: 2, TotalReports: 4}, r.fail
}
func (r *analyticsRepoStub) GetVulnerabilityAnalytics(req *model.AnalyticsRequest) (*model.VulnerabilityAnalytics, error) {
	r.request = req
	return &model.VulnerabilityAnalytics{OWASPStats: []model.OWASPCount{{Category: "A01", Count: 2}}}, r.fail
}
func (r *analyticsRepoStub) GetAssetAnalytics(req *model.AnalyticsRequest) (*model.AssetAnalytics, error) {
	r.request = req
	return &model.AssetAnalytics{}, r.fail
}
func (r *analyticsRepoStub) GetReportAnalytics(req *model.AnalyticsRequest) (*model.ReportAnalytics, error) {
	r.request = req
	return &model.ReportAnalytics{}, r.fail
}
func (r *analyticsRepoStub) GetUserAnalytics(req *model.AnalyticsRequest) (*model.UserAnalytics, error) {
	r.request = req
	return &model.UserAnalytics{}, r.fail
}
func (r *analyticsRepoStub) GetVulnerabilityTrend(start, end time.Time, granularity string, filters ...*model.AnalyticsRequest) ([]model.TrendPoint, error) {
	r.start = start
	r.end = end
	r.granularity = granularity
	if len(filters) > 0 {
		r.request = filters[0]
	}
	return nil, r.fail
}
func (r *analyticsRepoStub) GetSeverityTrend(start, end time.Time, filters ...*model.AnalyticsRequest) ([]model.SeverityTrendPoint, error) {
	r.start = start
	r.end = end
	if len(filters) > 0 {
		r.request = filters[0]
	}
	return nil, r.fail
}

func TestAnalyticsServiceTimeRange(t *testing.T) {
	repo := &analyticsRepoStub{}
	s := &analyticsService{analyticsRepo: repo}
	req := &model.AnalyticsRequest{StartDate: "2025-01-04", EndDate: "2025-01-04", Severity: "high", AssetID: "12"}
	_, err := s.GetVulnerabilityTrend(req)
	require.NoError(t, err)
	require.Equal(t, time.Date(2025, 1, 4, 0, 0, 0, 0, time.UTC), repo.start)
	require.Equal(t, time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC), repo.end)
	require.Equal(t, "day", repo.granularity)
	require.Same(t, req, repo.request)
	_, err = s.GetSeverityTrend(req)
	require.NoError(t, err)
	require.Same(t, req, repo.request)
	_, _, err = s.parseTimeRange(&model.AnalyticsRequest{EndDate: "2020-01-01"})
	require.NoError(t, err)
	for _, req := range []*model.AnalyticsRequest{nil, {StartDate: "bad"}, {EndDate: "2025-02-30"}, {StartDate: "2025-01-05", EndDate: "2025-01-04"}} {
		_, _, err := s.parseTimeRange(req)
		require.Error(t, err)
	}
}

func TestAnalyticsCSVFiles(t *testing.T) {
	previousDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() { require.NoError(t, os.Chdir(previousDir)) })
	repo := &analyticsRepoStub{}
	s := NewAnalyticsService(repo)
	for _, kind := range []string{"dashboard", "vulnerability", "asset", "report", "user"} {
		req := &model.ExportRequest{Type: kind, Format: "csv", StartDate: "2025-01-01", EndDate: "2025-01-31"}
		if kind != "dashboard" {
			req.Filters = map[string]interface{}{"asset_id": float64(1), "severity": "high"}
		}
		response, err := s.ExportData(req)
		require.NoError(t, err)
		data, err := os.ReadFile(filepath.Join("exports", response.FileName))
		require.NoError(t, err)
		require.NotEmpty(t, data)
		require.EqualValues(t, len(data), response.FileSize)
		downloadURL, err := url.Parse(response.FileURL)
		require.NoError(t, err)
		require.Equal(t, "/api/v1/analytics/export", downloadURL.Path)
		require.Equal(t, kind, downloadURL.Query().Get("type"))
		require.Equal(t, "csv", downloadURL.Query().Get("format"))
		require.Equal(t, req.StartDate, downloadURL.Query().Get("start_date"))
		require.Equal(t, req.EndDate, downloadURL.Query().Get("end_date"))
		if kind != "dashboard" {
			require.Equal(t, "1", downloadURL.Query().Get("asset_id"))
			require.Equal(t, "high", downloadURL.Query().Get("severity"))
		}
		file, err := os.Open(filepath.Join("exports", response.FileName))
		require.NoError(t, err)
		reader := csv.NewReader(file)
		reader.FieldsPerRecord = -1
		rows, err := reader.ReadAll()
		require.NoError(t, err)
		require.NotEmpty(t, rows)
		require.NoError(t, file.Close())
		if kind != "dashboard" {
			require.Equal(t, "1", repo.request.AssetID)
			require.Equal(t, "high", repo.request.Severity)
			require.Equal(t, req.EndDate, repo.request.EndDate)
		}
	}
	first, err := s.ExportData(&model.ExportRequest{Type: "dashboard", Format: "csv"})
	require.NoError(t, err)
	second, err := s.ExportData(&model.ExportRequest{Type: "dashboard", Format: "csv"})
	require.NoError(t, err)
	require.NotEqual(t, first.FileName, second.FileName)
	before, err := os.ReadDir("exports")
	require.NoError(t, err)
	repo.fail = errors.New("database unavailable")
	_, err = s.ExportData(&model.ExportRequest{Type: "vulnerability", Format: "csv"})
	require.ErrorIs(t, err, repo.fail)
	after, err := os.ReadDir("exports")
	require.NoError(t, err)
	require.Len(t, after, len(before))
	for _, req := range []*model.ExportRequest{nil, {Type: "../outside", Format: "csv"}, {Type: "dashboard", Format: "excel"}, {Type: "dashboard", Format: "pdf"}, {Type: "dashboard", Format: "zip"}, {Type: "vulnerability", Format: "csv", Filters: map[string]interface{}{"unknown": true}}} {
		_, err = s.ExportData(req)
		require.Error(t, err)
	}
}

type analyticsFailWriter struct{}

func (analyticsFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestAnalyticsCSVWriteError(t *testing.T) {
	s := &analyticsService{analyticsRepo: &analyticsRepoStub{}}
	writer := csv.NewWriter(analyticsFailWriter{})
	err := s.exportDashboardToCSV(writer, &model.ExportRequest{Type: "dashboard", Format: "csv"})
	require.NoError(t, err)
	writer.Flush()
	require.ErrorIs(t, writer.Error(), io.ErrClosedPipe)
}
