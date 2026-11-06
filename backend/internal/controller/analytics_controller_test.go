package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/internal/service"
)

type analyticsExportServiceStub struct {
	service.AnalyticsService
	request  *model.ExportRequest
	response *model.ExportResponse
	err      error
	calls    int
}

func (s *analyticsExportServiceStub) ExportData(req *model.ExportRequest) (*model.ExportResponse, error) {
	s.request = req
	s.calls++
	return s.response, s.err
}

type analyticsPermissionStub struct {
	service.PermissionService
	allowed    bool
	err        error
	userID     uint
	permission string
	calls      int
}

func (s *analyticsPermissionStub) CheckUserPermission(userID uint, permission string) (bool, error) {
	s.calls++
	s.userID, s.permission = userID, permission
	return s.allowed, s.err
}

type analyticsRoundTripRepo struct {
	repository.AnalyticsRepository
	request *model.AnalyticsRequest
	calls   int
}

func (r *analyticsRoundTripRepo) GetVulnerabilityAnalytics(req *model.AnalyticsRequest) (*model.VulnerabilityAnalytics, error) {
	r.request = req
	r.calls++
	return &model.VulnerabilityAnalytics{OWASPStats: []model.OWASPCount{{Category: req.Category, Count: 2}}}, nil
}

func TestAnalyticsExportMetadataRoundTrip(t *testing.T) {
	previousDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() { require.NoError(t, os.Chdir(previousDir)) })
	repo := &analyticsRoundTripRepo{}
	controller := NewAnalyticsController(service.NewAnalyticsService(repo))
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/analytics/export", controller.ExportData)
	r.GET("/api/v1/analytics/export", controller.DownloadExport)
	body := `{"type":"vulnerability","format":"csv","start_date":"2025-01-01","end_date":"2025-01-31","filters":{"asset_id":2,"user_id":"3","severity":"high","status":"resolved","category":"A01 & access","granularity":"week"}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/analytics/export", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, request)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var metadata struct {
		Data model.ExportResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &metadata))
	require.Positive(t, metadata.Data.FileSize)
	_, err = os.Stat(filepath.Join("exports", metadata.Data.FileName))
	require.True(t, os.IsNotExist(err))
	parsed, err := url.Parse(metadata.Data.FileURL)
	require.NoError(t, err)
	require.Equal(t, "/api/v1/analytics/export", parsed.Path)
	require.Equal(t, "A01 & access", parsed.Query().Get("category"))
	require.Equal(t, "2", parsed.Query().Get("asset_id"))
	require.Equal(t, "week", parsed.Query().Get("granularity"))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, metadata.Data.FileURL, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	require.Contains(t, w.Body.String(), "A01 & access")
	require.Equal(t, 2, repo.calls)
	require.Equal(t, "2025-01-31", repo.request.EndDate)
	require.Equal(t, "resolved", repo.request.Status)
	require.Equal(t, "high", repo.request.Severity)
	require.Equal(t, "3", repo.request.UserID)
	entries, err := os.ReadDir("exports")
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestAnalyticsUserExportPermission(t *testing.T) {
	previousDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() { require.NoError(t, os.Chdir(previousDir)) })
	require.NoError(t, os.Mkdir("exports", 0700))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, tc := range []struct {
			name            string
			userID          uint
			inject, allowed bool
			checkErr        error
			want            int
		}{
			{"missing identity", 0, true, true, nil, http.StatusUnauthorized},
			{"missing checker", 7, false, false, nil, http.StatusForbidden},
			{"denied", 7, true, false, nil, http.StatusForbidden},
			{"checker failure", 7, true, false, errors.New("database failure"), http.StatusInternalServerError},
			{"allowed", 7, true, true, nil, http.StatusOK},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				name := "user_test.csv"
				s := &analyticsExportServiceStub{response: &model.ExportResponse{FileName: name, FileURL: "/api/v1/analytics/export?type=user&format=csv", FileSize: 4}}
				permission := &analyticsPermissionStub{allowed: tc.allowed, err: tc.checkErr}
				controller := NewAnalyticsController(s)
				if tc.inject {
					controller = NewAnalyticsController(s, permission)
				}
				r := gin.New()
				r.Use(func(ctx *gin.Context) {
					if tc.userID != 0 {
						ctx.Set("user_id", tc.userID)
					}
					ctx.Next()
				})
				r.GET("/api/v1/analytics/export", controller.DownloadExport)
				r.POST("/api/v1/analytics/export", controller.ExportData)
				var request *http.Request
				if method == http.MethodGet {
					request = httptest.NewRequest(method, "/api/v1/analytics/export?type=user", nil)
				} else {
					request = httptest.NewRequest(method, "/api/v1/analytics/export", strings.NewReader(`{"type":"user","format":"csv"}`))
					request.Header.Set("Content-Type", "application/json")
				}
				if tc.want == http.StatusOK {
					require.NoError(t, os.WriteFile(filepath.Join("exports", name), []byte("a,b\n"), 0600))
				}
				w := httptest.NewRecorder()
				r.ServeHTTP(w, request)
				require.Equal(t, tc.want, w.Code, w.Body.String())
				if tc.want == http.StatusOK {
					require.Equal(t, 1, s.calls)
				} else {
					require.Zero(t, s.calls)
				}
				if tc.inject && tc.userID != 0 {
					require.Equal(t, "user:manage", permission.permission)
					require.Equal(t, tc.userID, permission.userID)
					require.Equal(t, 1, permission.calls)
				}
			})
		}
	}
}

func TestAnalyticsAssetCoverage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stats *model.DashboardStats
		want  float64
	}{
		{"no stats", nil, 0},
		{"no assets", &model.DashboardStats{}, 0},
		{"no vulnerability records", &model.DashboardStats{TotalAssets: 3}, 0},
		{"two of three assets", &model.DashboardStats{TotalAssets: 3, AssetsWithVulnerabilities: 2}, 200.0 / 3},
		{"all assets", &model.DashboardStats{TotalAssets: 3, AssetsWithVulnerabilities: 3}, 100},
	} {
		t.Run(tc.name, func(t *testing.T) { require.InDelta(t, tc.want, calculateAssetCoverage(tc.stats), 0.00001) })
	}
}

func TestAnalyticsDownloadExport(t *testing.T) {
	previousDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(t.TempDir()))
	t.Cleanup(func() { require.NoError(t, os.Chdir(previousDir)) })
	require.NoError(t, os.Mkdir("exports", 0700))
	payload := "指标,数值\n总漏洞数,12\n"
	name := "dashboard_test.csv"
	path := filepath.Join("exports", name)
	require.NoError(t, os.WriteFile(path, []byte(payload), 0600))
	s := &analyticsExportServiceStub{response: &model.ExportResponse{FileName: name, FileURL: "/exports/" + name, FileSize: int64(len(payload))}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/analytics/export", NewAnalyticsController(s).DownloadExport)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/analytics/export?type=dashboard&start_date=2025-01-01&end_date=2025-01-31&severity=critical&asset_id=2", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, payload, w.Body.String())
	require.Equal(t, "text/csv; charset=utf-8", w.Header().Get("Content-Type"))
	require.Equal(t, strconv.Itoa(len(payload)), w.Header().Get("Content-Length"))
	require.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
	require.Contains(t, w.Header().Get("Content-Disposition"), name)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	require.Equal(t, "csv", s.request.Format)
	require.Equal(t, "dashboard", s.request.Type)
	require.Equal(t, "2025-01-31", s.request.EndDate)
	require.Equal(t, "critical", s.request.Filters["severity"])
	require.Equal(t, "2", s.request.Filters["asset_id"])
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
	for _, query := range []string{"type=overview", "type=../outside", "type=dashboard&format=excel", "type=dashboard&format=pdf", "type=dashboard&format=zip"} {
		previous := s.calls
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/analytics/export?"+query, nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, previous, s.calls)
		require.Contains(t, w.Header().Get("Content-Type"), "application/json")
	}
	s.err = errors.New("统计查询失败")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/analytics/export?type=vulnerability", nil))
	require.Equal(t, http.StatusBadRequest, w.Code)
	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.Equal(t, "统计查询失败", response["message"])
	s.err = nil
	s.response = &model.ExportResponse{FileName: "../private.csv"}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/analytics/export?type=dashboard", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	s.response = &model.ExportResponse{FileName: "missing.csv"}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/analytics/export?type=dashboard", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code)
}
