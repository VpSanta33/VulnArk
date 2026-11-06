package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"vulnark/internal/middleware"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/internal/service"
	"vulnark/pkg/auth"
	"vulnark/pkg/testutil"
)

func TestProfileWhitelistAndLiveSessionChecks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testutil.NewTestDB(t)
	role := &model.Role{Name: "reader", Permissions: model.Permissions{"vulnerability:read"}}
	require.NoError(t, db.Create(role).Error)
	user := &model.User{Username: "alice", Email: "alice@example.test", RealName: "Alice", RoleID: role.ID, Status: 1, TokenVersion: 1}
	require.NoError(t, db.Create(user).Error)
	repo := repository.NewUserRepository(db)
	manager, err := auth.NewJWTManagerWithConfig(strings.Repeat("s", 32), time.Hour, "vulnark")
	require.NoError(t, err)
	token, _, err := manager.GenerateAccessToken(user.ID, user.Username, user.RoleID, user.TokenVersion)
	require.NoError(t, err)
	users := service.NewUserServiceWithAuth(repo, repository.NewRoleRepository(db), manager, nil)
	ctrl := NewUserController(users, nil)
	settings := NewSettingsController(service.NewSettingsService(repo, nil))
	router := gin.New()
	protected := router.Group("", middleware.AuthMiddleware(repo, manager))
	protected.PUT("/profile", ctrl.UpdateProfile)
	protected.PUT("/settings/profile", settings.UpdateProfile)
	protected.GET("/profile", ctrl.GetProfile)
	protected.POST("/revoke-all", ctrl.RevokeAllSessions)
	protected.POST("/logout", ctrl.Logout)
	request := func(method, path, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		return res.Code
	}
	for _, path := range []string{"/profile", "/settings/profile"} {
		for _, body := range []string{`{"role_id":999}`, `{"status":0}`, `{"real_name":"Mallory","role_id":1}`, `{"real_name":"Alice"} {"role_id":1}`} {
			require.Equal(t, http.StatusBadRequest, request(http.MethodPut, path, body))
		}
	}
	require.Equal(t, http.StatusOK, request(http.MethodPut, "/profile", `{"real_name":"Updated","phone":"123"}`))
	stored, err := repo.GetByID(user.ID)
	require.NoError(t, err)
	require.Equal(t, "Updated", stored.RealName)
	require.Equal(t, role.ID, stored.RoleID)
	require.Equal(t, 1, stored.Status)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/revoke-all", ``))
	require.Equal(t, http.StatusUnauthorized, request(http.MethodGet, "/profile", ``))
	stored, err = repo.GetByID(user.ID)
	require.NoError(t, err)
	token, _, err = manager.GenerateAccessToken(stored.ID, stored.Username, stored.RoleID, stored.TokenVersion)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, request(http.MethodPost, "/logout", ``))
	require.Equal(t, http.StatusUnauthorized, request(http.MethodGet, "/profile", ``))
	stored, err = repo.GetByID(user.ID)
	require.NoError(t, err)
	token, _, err = manager.GenerateAccessToken(stored.ID, stored.Username, stored.RoleID, stored.TokenVersion)
	require.NoError(t, err)
	zero := 0
	require.NoError(t, repo.Update(user.ID, &model.UserUpdateRequest{Status: &zero}))
	require.Equal(t, http.StatusUnauthorized, request(http.MethodGet, "/profile", ``))
}

func TestRestrictedRebindTokenCannotEnterBusinessRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testutil.NewTestDB(t)
	role := &model.Role{Name: "reader"}
	require.NoError(t, db.Create(role).Error)
	user := &model.User{Username: "legacy", Email: "legacy@example.test", RealName: "Legacy", RoleID: role.ID, Status: 1, TokenVersion: 1, TwoFactorEnabled: true, TwoFactorNeedsRebind: true}
	require.NoError(t, db.Create(user).Error)
	repo := repository.NewUserRepository(db)
	manager, err := auth.NewJWTManagerWithConfig(strings.Repeat("s", 32), time.Hour, "vulnark")
	require.NoError(t, err)
	token, _, err := manager.GenerateRebindToken(user.ID, user.Username, user.RoleID, 1)
	require.NoError(t, err)
	router := gin.New()
	ok := func(c *gin.Context) { c.Status(http.StatusNoContent) }
	router.GET("/business", middleware.AuthMiddleware(repo, manager), ok)
	router.GET("/mfa", middleware.MFARebindMiddleware(repo, manager), ok)
	for path, want := range map[string]int{"/business": http.StatusUnauthorized, "/mfa": http.StatusNoContent} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		require.Equal(t, want, res.Code)
	}
}
