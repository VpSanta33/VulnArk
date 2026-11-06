package controller

import (
	"encoding/json"
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
	"vulnark/pkg/testutil"
)

type slaTestPermissions struct{ service.PermissionService }

func (p *slaTestPermissions) CheckUserPermission(userID uint, permission string) (bool, error) {
	return userID == 1 || (userID == 2 && permission == "vuln:read"), nil
}

func TestSLAControllerRequiresRoutePermissionsAndRecordsPauseActor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := testutil.NewTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.SLAPolicy{}, &model.VulnerabilityTimeline{}, &model.Notification{}))
	testutil.SeedTestData(db)
	require.NoError(t, db.Create(&model.Asset{ID: 1, Name: "asset", Type: "server"}).Error)
	due := time.Now().Add(time.Hour)
	v := &model.Vulnerability{ID: 1, Title: "SLA", AssetID: 1, SeverityLevel: 1, Status: model.StatusNew, ResponseDueAt: &due, FixDueAt: &due}
	require.NoError(t, db.Create(v).Error)
	controller := NewSLAController(service.NewSLAService(db, repository.NewSLARepository(db), nil))
	router := gin.New()
	router.Use(func(c *gin.Context) {
		switch c.GetHeader("Authorization") {
		case "admin":
			c.Set("user_id", uint(1))
		case "reader":
			c.Set("user_id", uint(2))
		}
	})
	permission := &slaTestPermissions{}
	router.GET("/vulnerabilities/:id/sla", middleware.RequirePermission("vuln:read", permission), controller.GetState)
	router.GET("/vulnerabilities/sla/overdue", middleware.RequirePermission("vuln:read", permission), controller.ListOverdue)
	router.POST("/vulnerabilities/:id/sla/pause", middleware.RequirePermission("sla:manage", permission), controller.Pause)
	router.POST("/vulnerabilities/:id/sla/resume", middleware.RequirePermission("sla:manage", permission), controller.Resume)
	router.POST("/sla-policies", middleware.RequirePermission("sla:manage", permission), controller.CreatePolicy)
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", token)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	require.Equal(t, http.StatusUnauthorized, request("GET", "/vulnerabilities/1/sla", "", "").Code)
	require.Equal(t, http.StatusForbidden, request("POST", "/vulnerabilities/1/sla/pause", "reader", "{}").Code)
	require.Equal(t, http.StatusForbidden, request("POST", "/sla-policies", "reader", "{}").Code)
	stateResponse := request("GET", "/vulnerabilities/1/sla", "reader", "")
	require.Equal(t, http.StatusOK, stateResponse.Code)
	var envelope struct {
		Data model.SLAState `json:"data"`
	}
	require.NoError(t, json.Unmarshal(stateResponse.Body.Bytes(), &envelope))
	require.Equal(t, "within", envelope.Data.Status)
	require.NotNil(t, envelope.Data.ResponseRemainingSeconds)
	require.Equal(t, http.StatusBadRequest, request("GET", "/vulnerabilities/sla/overdue?limit=1001", "reader", "").Code)
	require.Equal(t, http.StatusOK, request("POST", "/vulnerabilities/1/sla/pause", "admin", `{"reason":"waiting for maintenance"}`).Code)
	require.Equal(t, http.StatusOK, request("POST", "/vulnerabilities/1/sla/resume", "admin", "").Code)
	var entries []model.VulnerabilityTimeline
	require.NoError(t, db.Order("id").Find(&entries).Error)
	require.Len(t, entries, 2)
	require.Equal(t, "sla_paused", entries[0].Action)
	require.Equal(t, "waiting for maintenance", entries[0].Description)
	require.EqualValues(t, 1, entries[0].UserID)
	require.Equal(t, "sla_resumed", entries[1].Action)
}
