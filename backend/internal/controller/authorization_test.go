package controller

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"vulnark/internal/service"
)

type permissionChangeStub struct {
	service.PermissionService
	allowed bool
	err     error
	calls   int
}

func (s *permissionChangeStub) CheckUserPermission(id uint, permission string) (bool, error) {
	s.calls++
	if id != 7 || permission != "system:permission" {
		return false, errors.New("unexpected permission check")
	}
	return s.allowed, s.err
}

func TestPermissionChangesFailClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name        string
		userID      uint
		permissions *permissionChangeStub
		status      int
	}{
		{"missing identity", 0, &permissionChangeStub{allowed: true}, http.StatusUnauthorized},
		{"missing service", 7, nil, http.StatusForbidden},
		{"denied", 7, &permissionChangeStub{}, http.StatusForbidden},
		{"lookup failure", 7, &permissionChangeStub{err: errors.New("database unavailable")}, http.StatusInternalServerError},
		{"allowed", 7, &permissionChangeStub{allowed: true}, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.POST("/grant", func(ctx *gin.Context) {
				if tc.userID != 0 {
					ctx.Set("user_id", tc.userID)
				}
				var checker service.PermissionService
				if tc.permissions != nil {
					checker = tc.permissions
				}
				if allowPermissionChanges(ctx, checker) {
					ctx.Status(http.StatusNoContent)
				}
			})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/grant", nil))
			require.Equal(t, tc.status, w.Code)
			if tc.permissions != nil && tc.userID != 0 {
				require.Equal(t, 1, tc.permissions.calls)
			}
			require.NotContains(t, w.Body.String(), "database unavailable")
		})
	}
}
