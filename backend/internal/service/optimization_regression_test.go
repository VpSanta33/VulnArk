package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
)

func TestAIConfigurationKeepsReplacesAndClearsSecret(t *testing.T) {
	db := newAIServiceTestDB(t)
	repo := seedAIServiceConfig(t, db, "https://api.openai.com")
	svc := NewAIService(repo)
	request := &model.AIConfigurationRequest{Provider: "openai", Model: "changed", Enabled: true}
	require.NoError(t, svc.SaveAIConfiguration(7, request))
	saved, err := repo.GetAIConfiguration(7)
	require.NoError(t, err)
	require.Equal(t, "test", saved.APIKey)
	require.Equal(t, "changed", saved.Model)
	encoded, err := json.Marshal(saved)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "\"api_key\":")
	request.APIKey = "replacement"
	require.NoError(t, svc.SaveAIConfiguration(7, request))
	saved, err = repo.GetAIConfiguration(7)
	require.NoError(t, err)
	require.Equal(t, "replacement", saved.APIKey)
	request.ClearAPIKey = true
	require.Error(t, svc.SaveAIConfiguration(7, request))
	request.APIKey = ""
	require.Error(t, svc.SaveAIConfiguration(7, request), "clear while enabled is rejected")
	request.Enabled = false
	require.NoError(t, svc.SaveAIConfiguration(7, request))
	saved, err = repo.GetAIConfiguration(7)
	require.NoError(t, err)
	require.Empty(t, saved.APIKey)
	request.ClearAPIKey = false
	request.Enabled = true
	require.Error(t, svc.SaveAIConfiguration(7, request), "cannot enable without a stored or supplied key")
	require.Error(t, svc.SaveAIConfiguration(99, request))
}

func TestAIRejectsUnapprovedLocalProviderAndOversizedResponses(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(strings.Repeat("x", (4<<20)+1)))
	}))
	defer provider.Close()
	repo := seedAIServiceConfig(t, newAIServiceTestDB(t), provider.URL)
	_, err := NewAIService(repo).SendMessage(7, &model.AIChatRequest{Message: "blocked"})
	require.Error(t, err)
	require.Zero(t, calls.Load())
	_, err = testAIService(repo).SendMessage(7, &model.AIChatRequest{Message: "bounded"})
	require.ErrorContains(t, err, "大小限制")
	require.EqualValues(t, 1, calls.Load())
}

func TestAuditRetentionHonorsSettingBoundaryBatchesAndCancellation(t *testing.T) {
	db := newAIServiceTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.AuditLog{}, &model.SystemConfig{}))
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&model.SystemConfig{Key: "audit.log_retention_days", Value: model.ConfigValue{"value": 30}, Type: "number", Category: "audit", DisplayName: "Retention"}).Error)
	old := make([]model.AuditLog, 1005)
	for i := range old {
		old[i] = model.AuditLog{CreatedAt: now.AddDate(0, 0, -31), Action: "old", Resource: "test"}
	}
	require.NoError(t, db.CreateInBatches(old, 100).Error)
	for _, stamp := range []time.Time{now.AddDate(0, 0, -30), now.AddDate(0, 0, -29), now} {
		require.NoError(t, db.Create(&model.AuditLog{CreatedAt: stamp, Action: "retain", Resource: "test"}).Error)
	}
	require.NoError(t, CleanupAuditLogs(context.Background(), db, now))
	var count int64
	require.NoError(t, db.Model(&model.AuditLog{}).Count(&count).Error)
	require.EqualValues(t, 3, count)
	require.NoError(t, CleanupAuditLogs(context.Background(), db, now))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, CleanupAuditLogs(ctx, db, now), context.Canceled)
}
