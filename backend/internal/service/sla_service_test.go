package service

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/testutil"
)

func slaTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := testutil.NewTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.SLAPolicy{}, &model.Notification{}, &model.NotificationSettings{}))
	testutil.SeedTestData(db)
	require.NoError(t, db.Create(&model.Asset{ID: 10, Name: "app", Type: model.AssetTypeApplication, Department: "security"}).Error)
	return db
}

func TestSLAPolicyMatchingPrefersAssetAndDepartmentOverrides(t *testing.T) {
	db := slaTestDB(t)
	assetID := uint(10)
	base := &model.SLAPolicy{Name: "critical-default", SeverityLevel: 1, ResponseHours: 24, FixHours: 72, Enabled: true}
	department := &model.SLAPolicy{Name: "security-critical", SeverityLevel: 1, Department: "security", ResponseHours: 4, FixHours: 24, Enabled: true}
	asset := &model.SLAPolicy{Name: "app-critical", SeverityLevel: 1, AssetID: &assetID, ResponseHours: 1, FixHours: 8, Enabled: true}
	require.NoError(t, db.Create(base).Error)
	require.NoError(t, db.Create(department).Error)
	require.NoError(t, db.Create(asset).Error)
	svc := NewSLAService(db, repository.NewSLARepository(db), nil)
	matched, err := svc.MatchPolicy(1, assetID, "security")
	require.NoError(t, err)
	require.Equal(t, asset.ID, matched.ID)
	matched, err = svc.MatchPolicy(1, 999, "security")
	require.NoError(t, err)
	require.Equal(t, department.ID, matched.ID)
}

func TestSLAPauseResumeExtendsDeadlinesByPausedDuration(t *testing.T) {
	db := slaTestDB(t)
	base := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	vulnerability := &model.Vulnerability{Title: "paused", AssetID: 10, SeverityLevel: 3, Status: model.StatusProcessing, DiscoveredAt: base, ResponseDueAt: ptrTime(base.Add(time.Hour)), FixDueAt: ptrTime(base.Add(2 * time.Hour))}
	require.NoError(t, db.Create(vulnerability).Error)
	svc := NewSLAService(db, repository.NewSLARepository(db), nil)
	require.NoError(t, svc.Pause(vulnerability.ID, base.Add(30*time.Minute)))
	require.NoError(t, svc.Resume(vulnerability.ID, base.Add(90*time.Minute)))
	var stored model.Vulnerability
	require.NoError(t, db.First(&stored, vulnerability.ID).Error)
	require.Equal(t, int64(time.Hour/time.Second), stored.PausedSeconds)
	require.Equal(t, base.Add(2*time.Hour), stored.ResponseDueAt.UTC())
	require.Equal(t, base.Add(3*time.Hour), stored.FixDueAt.UTC())
	state := SLAStateAt(&stored, base.Add(110*time.Minute))
	require.False(t, state.ResponseOverdue)
	require.NotNil(t, state.ResponseRemainingSeconds)
}

func TestSLAOverdueScanIsIdempotentAndBounded(t *testing.T) {
	db := slaTestDB(t)
	due := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	assignee := uint(1)
	vulnerability := &model.Vulnerability{Title: "overdue", AssetID: 10, SeverityLevel: 1, Status: model.StatusProcessing, AssigneeID: &assignee, ResponseDueAt: &due, FixDueAt: ptrTime(due.Add(time.Hour))}
	require.NoError(t, db.Create(vulnerability).Error)
	svc := NewSLAService(db, repository.NewSLARepository(db), repository.NewNotificationRepository(db))
	now := due.Add(73 * time.Hour)
	first, err := svc.ScanOverdue(context.Background(), now, 1)
	require.NoError(t, err)
	require.Equal(t, 1, first.Processed)
	require.Equal(t, 2, first.Created)
	second, err := svc.ScanOverdue(context.Background(), now, 1)
	require.NoError(t, err)
	require.Equal(t, 0, second.Created)
	var count int64
	require.NoError(t, db.Model(&model.Notification{}).Count(&count).Error)
	require.Equal(t, int64(2), count)
}

func TestSLAPolicyCRUDPreservesDisabledAndClearsOverrides(t *testing.T) {
	db := slaTestDB(t)
	svc := NewSLAService(db, repository.NewSLARepository(db), nil)
	assetID, disabled := uint(10), false
	policy, err := svc.CreatePolicy(&model.SLAPolicyCreateRequest{Name: " scoped ", SeverityLevel: 2, AssetID: &assetID, Department: "security", ResponseHours: 4, FixHours: 24, Enabled: &disabled})
	require.NoError(t, err)
	require.False(t, policy.Enabled)
	stored, err := svc.GetPolicy(policy.ID)
	require.NoError(t, err)
	require.False(t, stored.Enabled)
	matched, err := svc.MatchPolicy(2, assetID, "security")
	require.NoError(t, err)
	require.Nil(t, matched)
	var update model.SLAPolicyUpdateRequest
	require.NoError(t, json.Unmarshal([]byte(`{"asset_id":null,"department":"","enabled":true}`), &update))
	require.NoError(t, svc.UpdatePolicy(policy.ID, &update))
	matched, err = svc.MatchPolicy(2, 123, "other")
	require.NoError(t, err)
	require.NotNil(t, matched)
	require.Nil(t, matched.AssetID)
	require.Equal(t, "", matched.Department)
	for _, hours := range []int{-1, 0, 876001} {
		_, err = svc.CreatePolicy(&model.SLAPolicyCreateRequest{Name: "invalid", SeverityLevel: 1, ResponseHours: hours, FixHours: 24})
		require.Error(t, err)
	}
	require.NoError(t, svc.DeletePolicy(policy.ID))
	_, err = svc.GetPolicy(policy.ID)
	require.Error(t, err)
}

func TestSLAOverdueScanVisitsEveryBatchAndHonorsContext(t *testing.T) {
	db := slaTestDB(t)
	due, assignee := time.Now().UTC().Add(-2*time.Hour), uint(1)
	for i := 0; i < 5; i++ {
		require.NoError(t, db.Create(&model.Vulnerability{Title: fmt.Sprintf("overdue-%d", i), AssetID: 10, SeverityLevel: 3, Status: model.StatusProcessing, AssigneeID: &assignee, FirstResponseAt: ptrTime(due.Add(-time.Hour)), FixDueAt: &due}).Error)
	}
	svc := NewSLAService(db, repository.NewSLARepository(db), repository.NewNotificationRepository(db))
	for _, want := range []int{2, 2, 1, 0} {
		result, err := svc.ScanOverdue(context.Background(), time.Now().UTC(), 2)
		require.NoError(t, err)
		require.LessOrEqual(t, result.Processed, 2)
		require.Equal(t, want, result.Created)
	}
	var count int64
	require.NoError(t, db.Model(&model.Notification{}).Count(&count).Error)
	require.EqualValues(t, 5, count)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.ScanOverdue(ctx, time.Now(), 2)
	require.ErrorIs(t, err, context.Canceled)
	// Inbox deserialization accepts SQLite's string JSON as well as []byte.
	notifications, err := repository.NewNotificationRepository(db).GetByRecipientID(1, 20)
	require.NoError(t, err)
	require.Len(t, notifications, 5)
}

func TestSLAScanEscalatesRecipientsAndRespectsPushPreferences(t *testing.T) {
	db := slaTestDB(t)
	role := &model.Role{Name: "developer", Permissions: model.Permissions{"vuln:read"}}
	require.NoError(t, db.Create(role).Error)
	for _, id := range []uint{2, 3} {
		require.NoError(t, db.Create(&model.User{ID: id, Username: fmt.Sprintf("user%d", id), Email: fmt.Sprintf("user%d@example.test", id), RealName: "user", RoleID: role.ID, Status: 1}).Error)
	}
	require.NoError(t, db.Model(&model.Asset{}).Where("id = ?", 10).Update("owner_id", 3).Error)
	assignee := uint(2)
	due := time.Now().UTC().Add(-time.Hour)
	v := &model.Vulnerability{Title: "escalate", AssetID: 10, SeverityLevel: 1, Status: model.StatusProcessing, AssigneeID: &assignee, FirstResponseAt: ptrTime(due.Add(-time.Hour)), FixDueAt: &due}
	require.NoError(t, db.Create(v).Error)
	svc := NewSLAService(db, repository.NewSLARepository(db), repository.NewNotificationRepository(db))
	for _, step := range []struct {
		age     time.Duration
		created int
	}{{time.Hour, 1}, {25 * time.Hour, 2}, {73 * time.Hour, 3}, {73 * time.Hour, 0}} {
		result, err := svc.ScanOverdue(context.Background(), due.Add(step.age), 10)
		require.NoError(t, err)
		require.Equal(t, step.created, result.Created)
	}
	// A new assignee gets a separate key even at an already-notified level.
	require.NoError(t, db.Model(v).Update("assignee_id", 1).Error)
	result, err := svc.ScanOverdue(context.Background(), due.Add(2*time.Hour), 10)
	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
	// SystemPush defaults to enabled when absent, and explicit false suppresses.
	setting := &model.NotificationSettings{UserID: 1}
	require.NoError(t, db.Create(setting).Error)
	require.NoError(t, db.Model(setting).Update("system_push", false).Error)
	require.NoError(t, db.Model(v).Update("sla_cycle", 1).Error)
	result, err = svc.ScanOverdue(context.Background(), due.Add(2*time.Hour), 10)
	require.NoError(t, err)
	require.Zero(t, result.Created)
	require.NoError(t, db.Model(setting).Update("system_push", true).Error)
	result, err = svc.ScanOverdue(context.Background(), due.Add(2*time.Hour), 10)
	require.NoError(t, err)
	require.Equal(t, 1, result.Created)
	var stored model.Vulnerability
	require.NoError(t, db.First(&stored, v.ID).Error)
	require.Equal(t, model.StatusProcessing, stored.Status)
	require.True(t, stored.FixOverdue)
}

func TestSLALifecycleIsAtomicAndPreservesRemainingBudgetOnReopen(t *testing.T) {
	db := slaTestDB(t)
	base := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	v := &model.Vulnerability{Title: "lifecycle", AssetID: 10, SeverityLevel: 1, Status: model.StatusNew, ResponseDueAt: ptrTime(base.Add(time.Hour)), FixDueAt: ptrTime(base.Add(4 * time.Hour))}
	require.NoError(t, db.Create(v).Error)
	svc := NewSLAService(db, repository.NewSLARepository(db), nil)
	require.NoError(t, svc.UpdateLifecycleFields(v.ID, map[string]interface{}{"status": model.StatusProcessing}, base.Add(30*time.Minute)))
	require.NoError(t, db.Exec(`CREATE TRIGGER fail_sla_transition BEFORE UPDATE ON vulnerabilities WHEN NEW.status = 'fixed' BEGIN SELECT RAISE(ABORT, 'injected failure'); END`).Error)
	require.Error(t, svc.UpdateLifecycleFields(v.ID, map[string]interface{}{"status": model.StatusFixed, "title": "not committed"}, base.Add(time.Hour)))
	var current model.Vulnerability
	require.NoError(t, db.First(&current, v.ID).Error)
	require.Equal(t, model.StatusProcessing, current.Status)
	require.Equal(t, "lifecycle", current.Title)
	require.Nil(t, current.FixedAt)
	require.NoError(t, db.Exec("DROP TRIGGER fail_sla_transition").Error)
	require.NoError(t, svc.Pause(v.ID, base.Add(time.Hour)))
	require.NoError(t, svc.UpdateLifecycleFields(v.ID, map[string]interface{}{"status": model.StatusFixed}, base.Add(2*time.Hour)))
	current = model.Vulnerability{}
	require.NoError(t, db.First(&current, v.ID).Error)
	require.Nil(t, current.PauseStartedAt)
	require.EqualValues(t, 3600, current.PausedSeconds)
	require.Equal(t, base.Add(5*time.Hour), current.FixDueAt.UTC())
	// Repeated fix is idempotent; moving back to processing creates a new cycle.
	require.NoError(t, svc.UpdateLifecycleFields(v.ID, map[string]interface{}{"status": model.StatusFixed}, base.Add(3*time.Hour)))
	require.NoError(t, svc.UpdateLifecycleFields(v.ID, map[string]interface{}{"status": model.StatusProcessing}, base.Add(6*time.Hour)))
	current = model.Vulnerability{}
	require.NoError(t, db.First(&current, v.ID).Error)
	require.Nil(t, current.FixedAt)
	require.Equal(t, base.Add(9*time.Hour), current.FixDueAt.UTC())
	require.Equal(t, 1, current.SLACycle)
	require.Equal(t, base.Add(30*time.Minute), current.FirstResponseAt.UTC())
	state := SLAStateAt(&current, base.Add(7*time.Hour))
	require.Equal(t, "within", state.Status)
	require.EqualValues(t, 7200, *state.FixRemainingSeconds)
}

func TestSLAAssignmentInitializesDeadlinesAndPreservesFirstResponse(t *testing.T) {
	db := newBusinessTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.SLAPolicy{}))
	v := seedBusinessVulnerability(t, db, "SLA assignment")
	policy := &model.SLAPolicy{Name: "default", SeverityLevel: v.SeverityLevel, ResponseHours: 4, FixHours: 24, Enabled: true}
	require.NoError(t, db.Create(policy).Error)
	svc := newAssignmentTransactionService(db)
	ConfigureAssignmentSLA(svc, NewSLAService(db, repository.NewSLARepository(db), nil))
	require.NoError(t, svc.AssignVulnerability(v.ID, &model.VulnerabilityAssignRequest{AssigneeID: 3}, 1))
	var first model.Vulnerability
	require.NoError(t, db.First(&first, v.ID).Error)
	require.NotNil(t, first.ResponseDueAt)
	require.NotNil(t, first.FixDueAt)
	require.NotNil(t, first.FirstResponseAt)
	require.NotNil(t, first.SLAPolicyID)
	require.Equal(t, policy.ID, *first.SLAPolicyID)
	require.Equal(t, policy.Name, first.SLAPolicyName)
	require.NoError(t, svc.ReassignVulnerability(v.ID, 2, 1, "handoff"))
	var reassigned model.Vulnerability
	require.NoError(t, db.First(&reassigned, v.ID).Error)
	require.Equal(t, first.FirstResponseAt, reassigned.FirstResponseAt)
	require.Equal(t, first.FixDueAt, reassigned.FixDueAt)
	require.NoError(t, db.Model(&model.Vulnerability{}).Where("id = ?", v.ID).Update("status", model.StatusClosed).Error)
	require.Error(t, svc.ReassignVulnerability(v.ID, 3, 1, "cannot reopen"))
}

func TestSLAVulnerabilityListFiltersCurrentSLAState(t *testing.T) {
	db := slaTestDB(t)
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	for _, v := range []model.Vulnerability{
		{Title: "none", AssetID: 10, SeverityLevel: 1, Status: model.StatusNew},
		{Title: "within", AssetID: 10, SeverityLevel: 1, Status: model.StatusNew, FixDueAt: &future},
		{Title: "overdue", AssetID: 10, SeverityLevel: 1, Status: model.StatusProcessing, FixDueAt: &past},
		{Title: "paused", AssetID: 10, SeverityLevel: 1, Status: model.StatusProcessing, FixDueAt: &past, PauseStartedAt: &past},
		{Title: "completed", AssetID: 10, SeverityLevel: 1, Status: model.StatusFixed, FixDueAt: &past, FixedAt: &past},
	} {
		require.NoError(t, db.Create(&v).Error)
	}
	svc := NewVulnerabilityService(repository.NewVulnerabilityRepository(db), nil, nil, nil)
	for _, status := range []string{"none", "within", "overdue", "paused", "completed"} {
		response, err := svc.GetVulnerabilityList(&model.VulnerabilitySearchRequest{SLAStatus: status, PaginationRequest: model.PaginationRequest{Page: 1, PageSize: 10}})
		require.NoError(t, err)
		require.EqualValues(t, 1, response.Total)
		items := response.Data.([]model.VulnerabilityInfo)
		require.Len(t, items, 1)
		require.Equal(t, status, items[0].SLAStatus)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
