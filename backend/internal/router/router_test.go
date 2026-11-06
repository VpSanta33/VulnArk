package router

import (
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

func TestActualRoutesEnforceAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previousConfig, previousDB := config.AppConfig, database.DB
	t.Cleanup(func() { config.AppConfig, database.DB = previousConfig, previousDB })
	config.AppConfig = &config.Config{
		JWT:      config.JWTConfig{Secret: strings.Repeat("j", 48), ExpireTime: 3600},
		Security: config.SecurityConfig{MFAEncryptionKey: strings.Repeat("m", 32)},
		Storage:  config.StorageConfig{LocalPath: t.TempDir()},
	}
	db := testutil.NewTestDB(t)
	database.DB = db
	require.NoError(t, db.AutoMigrate(&model.Notification{}))
	role := model.Role{Name: "read-only", Permissions: model.Permissions{"asset:read", "vuln:read", "knowledge:read", "report:read"}}
	require.NoError(t, db.Create(&role).Error)
	user := model.User{Username: "reader", Email: "reader@example.test", RealName: "Reader", RoleID: role.ID, Status: 1, TokenVersion: 1}
	require.NoError(t, db.Create(&user).Error)
	other := model.User{Username: "other", Email: "other@example.test", RealName: "Other", RoleID: role.ID, Status: 1, TokenVersion: 1}
	require.NoError(t, db.Create(&other).Error)
	note := model.Notification{RecipientID: other.ID, Title: "private", Content: "private", Type: "system", Level: "info"}
	require.NoError(t, db.Create(&note).Error)
	manager := auth.NewJWTManager()
	token, _, err := manager.GenerateAccessToken(user.ID, user.Username, role.ID, 1)
	require.NoError(t, err)
	r := gin.New()
	require.NoError(t, r.SetTrustedProxies(nil))
	SetupRoutes(r, container.NewContainer())
	request := func(method, path, body, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.10:12345"
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/v1/assets"}, {"PUT", "/api/v1/assets/1"}, {"DELETE", "/api/v1/assets/1"},
		{"POST", "/api/v1/vulnerabilities"}, {"PUT", "/api/v1/vulnerabilities/1"}, {"DELETE", "/api/v1/vulnerabilities/1"},
		{"POST", "/api/v1/vulnerabilities/1/assign"}, {"POST", "/api/v1/vulnerabilities/auto-assign"},
		{"POST", "/api/v1/role-permissions/1"}, {"PUT", "/api/v1/system/configs/system.name"},
		{"POST", "/api/v1/reports/1/review"}, {"POST", "/api/v1/email-templates"},
		{"POST", "/api/v1/knowledge"}, {"POST", "/api/v1/settings/database/optimize"},
		{"GET", "/api/v1/analytics/export"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			require.Equal(t, http.StatusForbidden, request(tc.method, tc.path, "{}", token).Code)
		})
	}
	require.Equal(t, http.StatusUnauthorized, request("GET", "/api/v1/profile", "", "").Code)
	require.Equal(t, http.StatusOK, request("GET", "/api/v1/profile", "", token).Code)
	require.Equal(t, http.StatusBadRequest, request("PUT", "/api/v1/profile", `{"role_id":1}`, token).Code)
	require.Equal(t, http.StatusNotFound, request("GET", "/api/v1/notifications/1", "", token).Code)
	require.Equal(t, http.StatusOK, request("GET", "/api/v1/vulnerabilities/asset-options", "", token).Code)

	// Managing records does not grant the ability to change authorization.
	managerPermissions := model.Permissions{"user:manage", "role:manage", "vuln:read"}
	setPermissions := func(permissions model.Permissions) {
		encoded, err := json.Marshal(permissions)
		require.NoError(t, err)
		require.NoError(t, db.Model(&model.Role{}).Where("id = ?", role.ID).Update("permissions", string(encoded)).Error)
	}
	setPermissions(managerPermissions)
	adminRole := model.Role{Name: "administrator", Permissions: model.Permissions{"*"}}
	require.NoError(t, db.Create(&adminRole).Error)
	rolePath := fmt.Sprintf("/api/v1/roles/%d", role.ID)
	userPath := fmt.Sprintf("/api/v1/users/%d", user.ID)
	grantBody := fmt.Sprintf(`{"role_id":%d}`, adminRole.ID)
	newUserBody := fmt.Sprintf(`{"username":"created-user","email":"created@example.test","password":"test-password-123","real_name":"Created","role_id":%d}`, adminRole.ID)
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", rolePath, `{"permissions":["*"]}`},
		{"PUT", rolePath, `{"permissions":[]}`},
		{"POST", "/api/v1/roles", `{"name":"unauthorized-role","permissions":["*"]}`},
		{"PUT", userPath, grantBody},
		{"POST", "/api/v1/users", newUserBody},
	} {
		t.Run("authorization "+tc.method+tc.path+tc.body, func(t *testing.T) {
			require.Equal(t, http.StatusForbidden, request(tc.method, tc.path, tc.body, token).Code)
		})
	}
	var storedRole model.Role
	require.NoError(t, db.First(&storedRole, role.ID).Error)
	require.Equal(t, managerPermissions, storedRole.Permissions)
	var storedUser model.User
	require.NoError(t, db.First(&storedUser, user.ID).Error)
	require.Equal(t, role.ID, storedUser.RoleID)
	var count int64
	require.NoError(t, db.Model(&model.Role{}).Where("name = ?", "unauthorized-role").Count(&count).Error)
	require.Zero(t, count)
	require.NoError(t, db.Model(&model.User{}).Where("username = ?", "created-user").Count(&count).Error)
	require.Zero(t, count)
	// Metadata and resubmitting an unchanged role remain available.
	require.Equal(t, http.StatusOK, request("PUT", rolePath, `{"description":"metadata only"}`, token).Code)
	require.Equal(t, http.StatusOK, request("POST", "/api/v1/roles", `{"name":"empty-role"}`, token).Code)
	require.Equal(t, http.StatusOK, request("PUT", userPath, fmt.Sprintf(`{"real_name":"Renamed","role_id":%d}`, role.ID), token).Code)
	setPermissions(append(managerPermissions, "system:permission"))
	require.Equal(t, http.StatusOK, request("POST", "/api/v1/roles", `{"name":"authorized-role","permissions":["asset:read"]}`, token).Code)
	require.Equal(t, http.StatusOK, request("POST", "/api/v1/users", newUserBody, token).Code)
	require.Equal(t, http.StatusOK, request("PUT", rolePath, `{"permissions":["*"]}`, token).Code)
	require.Equal(t, http.StatusOK, request("PUT", userPath, grantBody, token).Code)
	// Reissue after the authorized role change; the previous token was revoked.
	require.Equal(t, http.StatusUnauthorized, request("GET", "/api/v1/profile", "", token).Code)
	require.NoError(t, db.First(&storedUser, user.ID).Error)
	token, _, err = manager.GenerateAccessToken(user.ID, user.Username, storedUser.RoleID, storedUser.TokenVersion)
	require.NoError(t, err)
	limited, _, err := manager.GenerateRebindToken(user.ID, user.Username, storedUser.RoleID, storedUser.TokenVersion)
	require.NoError(t, err)
	require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.ID).Update("two_factor_needs_rebind", true).Error)
	require.Equal(t, http.StatusUnauthorized, request("GET", "/api/v1/profile", "", limited).Code)
	require.Equal(t, http.StatusOK, request("GET", "/api/v1/settings/2fa/status", "", limited).Code)
	require.Equal(t, http.StatusUnauthorized, request("DELETE", "/api/v1/settings/2fa", `{"code":"123456"}`, limited).Code)
	require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{"two_factor_needs_rebind": false, "status": 0}).Error)
	require.Equal(t, http.StatusUnauthorized, request("GET", "/api/v1/profile", "", token).Code)
}
