package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"vulnark/internal/config"
	"vulnark/internal/container"
	"vulnark/internal/model"
	"vulnark/pkg/auth"
	"vulnark/pkg/database"
	"vulnark/pkg/testutil"
)

func TestRiskRoutesEnforcePermissionsAndRankByRisk(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldConfig, oldDB := config.AppConfig, database.DB
	t.Cleanup(func() { config.AppConfig, database.DB = oldConfig, oldDB })
	// RiskIntel is left disabled: scoring and every route must work without feeds.
	config.AppConfig = &config.Config{JWT: config.JWTConfig{Secret: strings.Repeat("j", 48), ExpireTime: 3600}, Security: config.SecurityConfig{MFAEncryptionKey: strings.Repeat("m", 32)}, Storage: config.StorageConfig{LocalPath: t.TempDir()}}
	db := testutil.NewTestDB(t)
	database.DB = db
	require.NoError(t, db.AutoMigrate(&model.Notification{}, &model.NotificationSettings{}, &model.VulnerabilityTimeline{}, &model.VulnerabilityAssignment{}))
	roles := []model.Role{
		{Name: "risk-admin", Permissions: model.Permissions{"*"}},
		{Name: "risk-reader", Permissions: model.Permissions{"vuln:read"}},
		{Name: "risk-asset-only", Permissions: model.Permissions{"asset:read"}},
		{Name: "risk-manager", Permissions: model.Permissions{"risk:manage"}},
	}
	tokens := make([]string, len(roles))
	for i := range roles {
		require.NoError(t, db.Create(&roles[i]).Error)
		user := model.User{Username: fmt.Sprintf("risk%d", i), Email: fmt.Sprintf("risk%d@example.test", i), RealName: "Risk", RoleID: roles[i].ID, Status: 1, TokenVersion: 1}
		require.NoError(t, db.Create(&user).Error)
		var err error
		tokens[i], _, err = auth.NewJWTManager().GenerateAccessToken(user.ID, user.Username, user.RoleID, 1)
		require.NoError(t, err)
	}
	admin, reader, assetOnly, manager := tokens[0], tokens[1], tokens[2], tokens[3]
	r := gin.New()
	SetupRoutes(r, container.NewContainer())
	request := func(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			require.NoError(t, err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(payload))
		req.RemoteAddr = "192.0.2.33:12345"
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, target interface{}) {
		t.Helper()
		var response struct {
			Data json.RawMessage `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response), w.Body.String())
		require.NoError(t, json.Unmarshal(response.Data, target), w.Body.String())
	}

	createAsset := func(body map[string]interface{}) uint {
		w := request("POST", "/api/v1/assets", body, admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var asset model.Asset
		decode(w, &asset)
		return asset.ID
	}
	exposed := createAsset(map[string]interface{}{"name": "payment-gateway", "type": "application", "importance_level": 1, "internet_facing": true, "network_zone": "production"})
	internal := createAsset(map[string]interface{}{"name": "wiki", "type": "application", "importance_level": 3})
	require.Equal(t, http.StatusBadRequest, request("POST", "/api/v1/assets", map[string]interface{}{"name": "bad-zone", "type": "server", "network_zone": "moon"}, admin).Code)
	var storedInternal model.Asset
	require.NoError(t, db.First(&storedInternal, internal).Error)
	require.Equal(t, model.NetworkZoneInternal, storedInternal.NetworkZone)
	require.False(t, storedInternal.InternetFacing)

	createVulnerability := func(body map[string]interface{}) uint {
		w := request("POST", "/api/v1/vulnerabilities", body, admin)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var created model.Vulnerability
		decode(w, &created)
		require.NotNil(t, created.RiskScore, "created vulnerability must be scored")
		return created.ID
	}
	low := createVulnerability(map[string]interface{}{"title": "verbose errors", "asset_id": internal, "severity_level": 4, "cvss_score": 3.1})
	high := createVulnerability(map[string]interface{}{"title": "pentest: auth bypass", "asset_id": exposed, "severity_level": 1, "cvss_score": 9.1})
	mid := createVulnerability(map[string]interface{}{"title": "internal CVE", "asset_id": internal, "severity_level": 2, "cvss_score": 8.8, "cve_id": "CVE-2024-00001"})

	listIDs := func(query, token string) []uint {
		t.Helper()
		w := request("GET", "/api/v1/vulnerabilities?"+query, nil, token)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var page struct {
			Data []model.VulnerabilityInfo `json:"data"`
		}
		decode(w, &page)
		ids := make([]uint, 0, len(page.Data))
		for _, item := range page.Data {
			require.NotNil(t, item.RiskScore)
			require.NotEmpty(t, item.RiskPriorityText)
			ids = append(ids, item.ID)
		}
		return ids
	}
	require.Equal(t, []uint{mid, high, low}, listIDs("", reader))
	require.Equal(t, []uint{high, mid, low}, listIDs("sort_by=risk_score&sort_order=desc", reader))
	require.Equal(t, []uint{high}, listIDs("sort_by=risk_score&risk_priority=P1", reader))
	require.Equal(t, []uint{high, mid}, listIDs("sort_by=risk_score&min_risk_score=40", reader))
	require.Empty(t, listIDs("kev_only=true", reader))
	for _, query := range []string{"sort_by=title", "sort_by=risk_score;DROP", "sort_order=sideways", "risk_priority=P9", "kev_only=maybe", "min_risk_score=abc"} {
		require.Equal(t, http.StatusBadRequest, request("GET", "/api/v1/vulnerabilities?"+strings.ReplaceAll(query, ";", "%3B"), nil, reader).Code, query)
	}

	riskPath := fmt.Sprintf("/api/v1/vulnerabilities/%d/risk", high)
	require.Equal(t, http.StatusUnauthorized, request("GET", riskPath, nil, "").Code)
	require.Equal(t, http.StatusForbidden, request("GET", riskPath, nil, assetOnly).Code)
	require.Equal(t, http.StatusForbidden, request("GET", riskPath, nil, manager).Code)
	require.Equal(t, http.StatusNotFound, request("GET", "/api/v1/vulnerabilities/99999/risk", nil, reader).Code)
	require.Equal(t, http.StatusBadRequest, request("GET", "/api/v1/vulnerabilities/0/risk", nil, reader).Code)
	explained := request("GET", riskPath, nil, reader)
	require.Equal(t, http.StatusOK, explained.Code, explained.Body.String())
	var risk model.VulnerabilityRisk
	decode(explained, &risk)
	require.Equal(t, model.RiskPriorityP1, risk.Priority)
	require.Len(t, risk.Factors, 5)
	require.Equal(t, 24, risk.RecommendedSLAHours)
	sum := 0.0
	for _, factor := range risk.Factors {
		sum += factor.Contribution
	}
	require.InDelta(t, risk.Score, sum, 0.1)

	require.Equal(t, http.StatusUnauthorized, request("GET", "/api/v1/risk/config", nil, "").Code)
	require.Equal(t, http.StatusForbidden, request("GET", "/api/v1/risk/config", nil, assetOnly).Code)
	current := request("GET", "/api/v1/risk/config", nil, reader)
	require.Equal(t, http.StatusOK, current.Code, current.Body.String())
	var configResponse model.RiskConfigResponse
	decode(current, &configResponse)
	require.Equal(t, model.DefaultRiskConfig(), configResponse.Config)

	strict := model.DefaultRiskConfig()
	strict.Thresholds = model.RiskThresholds{P1: 99, P2: 95, P3: 90}
	require.Equal(t, http.StatusForbidden, request("PUT", "/api/v1/risk/config", strict, reader).Code)
	invalid := model.DefaultRiskConfig()
	invalid.Thresholds.P3 = invalid.Thresholds.P1
	require.Equal(t, http.StatusBadRequest, request("PUT", "/api/v1/risk/config", invalid, admin).Code)
	require.Equal(t, http.StatusBadRequest, request("PUT", "/api/v1/risk/config", "not an object", admin).Code)
	saved := request("PUT", "/api/v1/risk/config", strict, manager)
	require.Equal(t, http.StatusOK, saved.Code, saved.Body.String())
	var rescored model.RiskRescoreResult
	decode(saved, &rescored)
	require.Equal(t, 3, rescored.Rescored)
	// The stricter thresholds are in force immediately, without changing the scores.
	require.Empty(t, listIDs("risk_priority=P1", reader))
	require.Equal(t, []uint{high, mid, low}, listIDs("sort_by=risk_score", reader))
	require.Equal(t, http.StatusOK, request("PUT", "/api/v1/risk/config", model.DefaultRiskConfig(), admin).Code)
	require.Equal(t, []uint{high}, listIDs("risk_priority=P1", reader))

	// Changing an asset's exposure re-ranks its vulnerabilities.
	require.Equal(t, http.StatusOK, request("PUT", fmt.Sprintf("/api/v1/assets/%d", internal), map[string]interface{}{"internet_facing": true, "network_zone": "ot", "importance_level": 1}, admin).Code)
	require.ElementsMatch(t, []uint{high, mid}, listIDs("risk_priority=P1&sort_by=risk_score", reader))

	require.Equal(t, http.StatusForbidden, request("POST", "/api/v1/risk/recalculate", nil, reader).Code)
	require.Equal(t, http.StatusOK, request("POST", "/api/v1/risk/recalculate", nil, admin).Code)

	require.Equal(t, http.StatusForbidden, request("GET", "/api/v1/risk/intel/status", nil, assetOnly).Code)
	statusResponse := request("GET", "/api/v1/risk/intel/status", nil, reader)
	require.Equal(t, http.StatusOK, statusResponse.Code, statusResponse.Body.String())
	var status model.ThreatIntelStatus
	decode(statusResponse, &status)
	require.False(t, status.Enabled)
	require.Len(t, status.Sources, 2)
	require.Equal(t, http.StatusForbidden, request("POST", "/api/v1/risk/intel/sync", nil, reader).Code)
	// Disabled in configuration: reported clearly, and nothing is contacted.
	require.Equal(t, http.StatusBadRequest, request("POST", "/api/v1/risk/intel/sync", nil, admin).Code)
}
