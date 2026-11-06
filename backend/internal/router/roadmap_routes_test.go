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

func TestRoadmapActualRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldConfig, oldDB := config.AppConfig, database.DB
	t.Cleanup(func() { config.AppConfig, database.DB = oldConfig, oldDB })
	config.AppConfig = &config.Config{JWT: config.JWTConfig{Secret: strings.Repeat("j", 48), ExpireTime: 3600}, Security: config.SecurityConfig{MFAEncryptionKey: strings.Repeat("m", 32)}, Storage: config.StorageConfig{LocalPath: t.TempDir()}}
	db := testutil.NewTestDB(t)
	database.DB = db
	require.NoError(t, db.AutoMigrate(&model.SLAPolicy{}, &model.VulnerabilityRetest{}, &model.VulnerabilityDuplicateLink{}, &model.Notification{}, &model.NotificationSettings{}, &model.VulnerabilityTimeline{}, &model.VulnerabilityAssignment{}))
	roles := []model.Role{
		{Name: "roadmap-admin", Permissions: model.Permissions{"*"}},
		{Name: "roadmap-reader", Permissions: model.Permissions{"vuln:read"}},
		{Name: "roadmap-fixer", Permissions: model.Permissions{"vuln:read", "vuln:create", "vuln:update"}},
		{Name: "roadmap-verifier", Permissions: model.Permissions{"vuln:read", "vuln:verify"}},
	}
	for i := range roles {
		require.NoError(t, db.Create(&roles[i]).Error)
	}
	users := make([]model.User, len(roles))
	tokens := make([]string, len(roles))
	for i := range roles {
		users[i] = model.User{Username: fmt.Sprintf("roadmap%d", i), Email: fmt.Sprintf("roadmap%d@example.test", i), RealName: "Roadmap", RoleID: roles[i].ID, Status: 1, TokenVersion: 1}
		require.NoError(t, db.Create(&users[i]).Error)
		var err error
		tokens[i], _, err = auth.NewJWTManager().GenerateAccessToken(users[i].ID, users[i].Username, users[i].RoleID, 1)
		require.NoError(t, err)
	}
	asset := model.Asset{Name: "roadmap-asset", Type: "application", OwnerID: &users[3].ID, Status: 1}
	require.NoError(t, db.Create(&asset).Error)
	r := gin.New()
	SetupRoutes(r, container.NewContainer())
	request := func(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.RemoteAddr = "192.0.2.22:12345"
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	decodeData := func(w *httptest.ResponseRecorder) map[string]interface{} {
		var response struct {
			Data map[string]interface{} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		return response.Data
	}
	policy := map[string]interface{}{"name": "critical-roadmap", "severity_level": 1, "response_hours": 1, "fix_hours": 24, "enabled": true}
	require.Equal(t, http.StatusUnauthorized, request("GET", "/api/v1/sla-policies", nil, "").Code)
	require.Equal(t, http.StatusForbidden, request("POST", "/api/v1/sla-policies", policy, tokens[1]).Code)
	createdPolicy := request("POST", "/api/v1/sla-policies", policy, tokens[0])
	require.Equal(t, http.StatusOK, createdPolicy.Code, createdPolicy.Body.String())
	createBody := map[string]interface{}{"title": "Roadmap SQL Injection", "asset_id": asset.ID, "severity_level": 1, "cve_id": "CVE-2026-12345", "assignee_id": users[2].ID}
	created := request("POST", "/api/v1/vulnerabilities", createBody, tokens[0])
	require.Equal(t, http.StatusOK, created.Code, created.Body.String())
	id := uint(decodeData(created)["id"].(float64))
	var stored model.Vulnerability
	require.NoError(t, db.First(&stored, id).Error)
	require.NotNil(t, stored.ResponseDueAt)
	require.NotNil(t, stored.FixDueAt)
	base := fmt.Sprintf("/api/v1/vulnerabilities/%d", id)
	require.Equal(t, http.StatusOK, request("GET", base+"/sla", nil, tokens[1]).Code)
	require.Equal(t, http.StatusForbidden, request("POST", base+"/sla/pause", map[string]string{"reason": "waiting"}, tokens[1]).Code)
	require.Equal(t, http.StatusOK, request("POST", base+"/sla/pause", map[string]string{"reason": "waiting for maintenance window"}, tokens[0]).Code)
	require.Equal(t, http.StatusOK, request("POST", base+"/sla/resume", nil, tokens[0]).Code)
	for _, path := range []string{base, base + "/status"} {
		for _, status := range []string{"verified", "closed"} {
			w := request("PUT", path, map[string]string{"status": status}, tokens[2])
			require.NotEqual(t, http.StatusOK, w.Code, path+" bypassed retest")
		}
	}
	require.Equal(t, http.StatusOK, request("PUT", base+"/status", map[string]string{"status": "fixed"}, tokens[2]).Code)
	proof := map[string]string{"result": "pass", "summary": "Independent verification confirms the fix"}
	require.Equal(t, http.StatusForbidden, request("POST", base+"/retest", proof, tokens[2]).Code)
	passed := request("POST", base+"/retest", proof, tokens[3])
	require.Equal(t, http.StatusCreated, passed.Code, passed.Body.String())
	require.NoError(t, db.First(&stored, id).Error)
	require.Equal(t, model.StatusVerified, stored.Status)
	require.Equal(t, http.StatusConflict, request("POST", base+"/retest", proof, tokens[3]).Code)
	require.Equal(t, http.StatusOK, request("GET", base+"/retests", nil, tokens[2]).Code)
	require.Equal(t, http.StatusOK, request("PUT", base+"/status", map[string]string{"status": "closed"}, tokens[2]).Code)
	var closed model.Vulnerability
	require.NoError(t, db.First(&closed, id).Error)
	require.Equal(t, model.StatusClosed, closed.Status)
	failed := request("POST", base+"/retest", map[string]string{"result": "fail", "summary": "Regression remains reproducible"}, tokens[3])
	require.Equal(t, http.StatusCreated, failed.Code, failed.Body.String())
	stored = model.Vulnerability{}
	require.NoError(t, db.First(&stored, id).Error)
	require.Equal(t, model.StatusProcessing, stored.Status)
	require.Nil(t, stored.FixedAt)
	require.Nil(t, stored.VerifiedAt)
	var attempts int64
	require.NoError(t, db.Model(&model.VulnerabilityRetest{}).Where("vulnerability_id = ?", id).Count(&attempts).Error)
	require.EqualValues(t, 2, attempts)

	// Suggestions are advisory; ignore/link operations never rewrite either finding.
	secondBody := map[string]interface{}{"title": "Roadmap SQL Injection second endpoint", "asset_id": asset.ID, "severity_level": 1, "cve_id": "CVE-2026-12345", "assignee_id": users[2].ID}
	second := request("POST", "/api/v1/vulnerabilities", secondBody, tokens[0])
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	secondID := uint(decodeData(second)["id"].(float64))
	query := fmt.Sprintf("/api/v1/vulnerabilities/duplicates/candidates?asset_id=%d&vulnerability_id=%d&cve_id=CVE-2026-12345", asset.ID, id)
	candidates := func() []model.DuplicateCandidate {
		w := request("GET", query, nil, tokens[2])
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var response struct {
			Data []model.DuplicateCandidate `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		return response.Data
	}
	require.Len(t, candidates(), 1)
	pair := fmt.Sprintf("%s/duplicates/%d", base, secondID)
	require.Equal(t, http.StatusForbidden, request("POST", pair+"/link", map[string]string{"reason": "same root cause"}, tokens[1]).Code)
	require.Equal(t, http.StatusOK, request("POST", pair+"/ignore", map[string]string{"reason": "different endpoint under review"}, tokens[2]).Code)
	require.Empty(t, candidates())
	require.Equal(t, http.StatusOK, request("DELETE", pair+"/ignore", nil, tokens[2]).Code)
	require.Len(t, candidates(), 1)
	require.Equal(t, http.StatusOK, request("POST", pair+"/link", map[string]string{"relation_type": "duplicate", "reason": "same root cause"}, tokens[2]).Code)
	require.Empty(t, candidates())
	links := request("GET", base+"/duplicates", nil, tokens[2])
	require.Equal(t, http.StatusOK, links.Code, links.Body.String())
	require.Contains(t, links.Body.String(), "linked")
	require.Equal(t, http.StatusOK, request("DELETE", pair+"/link", map[string]string{"reason": "confirmed independent issue"}, tokens[2]).Code)
	var unchanged model.Vulnerability
	require.NoError(t, db.First(&unchanged, secondID).Error)
	require.Equal(t, secondBody["title"], unchanged.Title)
	require.Equal(t, "CVE-2026-12345", unchanged.CVEID)
	require.Equal(t, model.StatusProcessing, unchanged.Status)
}
