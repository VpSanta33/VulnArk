package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/testutil"
)

func newRetestTestService(t *testing.T) (*gorm.DB, VulnerabilityRetestService) {
	t.Helper()
	db := testutil.NewTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.VulnerabilityRetest{}, &model.VulnerabilityTimeline{}, &model.FileCleanupTask{}, &model.Notification{}, &model.NotificationSettings{}))
	roles := []model.Role{
		{ID: 1, Name: "retester", Permissions: model.Permissions{"vuln:verify", "vuln:read"}},
		{ID: 2, Name: "fixer", Permissions: model.Permissions{"vuln:update", "vuln:read"}},
		{ID: 3, Name: "unrelated", Permissions: model.Permissions{"vuln:read"}},
		{ID: 4, Name: "manager", Permissions: model.Permissions{"vuln:read", "vuln:manage"}},
		{ID: 5, Name: "verify only", Permissions: model.Permissions{"vuln:verify"}},
	}
	for _, role := range roles {
		require.NoError(t, db.Create(&role).Error)
	}
	for _, user := range []model.User{
		{ID: 1, Username: "tester", Email: "tester@retest.test", RealName: "Tester", PasswordHash: "hash", RoleID: 1},
		{ID: 2, Username: "fixer", Email: "fixer@retest.test", RealName: "Fixer", PasswordHash: "hash", RoleID: 2},
		{ID: 3, Username: "outsider", Email: "outsider@retest.test", RealName: "Outsider", PasswordHash: "hash", RoleID: 3},
		{ID: 4, Username: "manager", Email: "manager@retest.test", RealName: "Manager", PasswordHash: "hash", RoleID: 4},
		{ID: 5, Username: "verifyonly", Email: "verify@retest.test", RealName: "Verifier", PasswordHash: "hash", RoleID: 5},
	} {
		require.NoError(t, db.Create(&user).Error)
	}
	tester := uint(1)
	require.NoError(t, db.Create(&model.Asset{ID: 1, Name: "retest asset", Type: model.AssetTypeApplication, OwnerID: &tester}).Error)
	permissions := NewPermissionService(repository.NewPermissionRepository(db), repository.NewRolePermissionRepository(db), repository.NewRoleRepository(db), repository.NewUserRepository(db))
	svc := NewRetestService(repository.NewRetestRepository(db), repository.NewVulnerabilityRepository(db), permissions)
	return db, svc
}

func seedRetestVulnerability(t *testing.T, db *gorm.DB, status string) *model.Vulnerability {
	t.Helper()
	assignee, discoverer := uint(2), uint(3)
	fixed := time.Now().Add(-2 * time.Hour)
	due := time.Now().Add(2 * time.Hour)
	vulnerability := &model.Vulnerability{Title: "retest", AssetID: 1, SeverityLevel: 2, Status: status, AssigneeID: &assignee, DiscovererID: &discoverer, FixedAt: &fixed, FixDueAt: &due}
	if status == model.StatusVerified || status == model.StatusClosed {
		vulnerability.VerifiedAt = &fixed
	}
	if status == model.StatusClosed {
		vulnerability.ClosedAt = &fixed
	}
	require.NoError(t, db.Create(vulnerability).Error)
	return vulnerability
}

func TestRetestPassFailAndPrivateEvidence(t *testing.T) {
	db, svc := newRetestTestService(t)
	v := seedRetestVulnerability(t, db, model.StatusFixed)
	result, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{
		Result: model.RetestResultPass, Summary: " remediation confirmed ",
		EvidenceAttachments: []model.VulnerabilityRetestEvidenceRequest{{Path: "attachments/private.png", Filename: "private.png", OriginalName: "proof.png", FileSize: 42, MimeType: "image/png"}},
	})
	require.NoError(t, err)
	require.Equal(t, model.StatusVerified, result.NewStatus)
	require.Equal(t, model.StatusFixed, result.PreviousStatus)
	require.Equal(t, "remediation confirmed", result.Summary)
	require.Equal(t, uint(2), *result.FixerID)
	require.Equal(t, "Tester", result.TesterName)
	var saved model.VulnerabilityRetest
	require.NoError(t, db.First(&saved, result.ID).Error)
	require.Equal(t, "attachments/private.png", saved.EvidenceAttachments[0].FilePath)
	body, err := json.Marshal(saved)
	require.NoError(t, err)
	require.NotContains(t, string(body), "attachments/private.png")
	require.NotContains(t, string(body), `"path"`)
	require.NoError(t, db.First(v, v.ID).Error)
	require.Equal(t, model.StatusVerified, v.Status)
	require.NotNil(t, v.VerifiedAt)

	failed, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: model.RetestResultFail, Summary: "still reproducible"})
	require.NoError(t, err)
	require.Equal(t, model.StatusProcessing, failed.NewStatus)
	var reopened model.Vulnerability
	require.NoError(t, db.First(&reopened, v.ID).Error)
	require.Nil(t, reopened.FixedAt)
	require.Nil(t, reopened.VerifiedAt)
	require.Nil(t, reopened.ClosedAt)
	require.Equal(t, 1, reopened.SLACycle)
	require.True(t, reopened.FixDueAt.After(*v.FixDueAt))
	var timeline []model.VulnerabilityTimeline
	require.NoError(t, db.Where("vulnerability_id = ?", v.ID).Order("id").Find(&timeline).Error)
	require.Len(t, timeline, 2)
	require.Equal(t, model.TimelineActionRetested, timeline[1].Action)
	require.Equal(t, model.StatusVerified, timeline[1].OldValue)
	require.Equal(t, model.StatusProcessing, timeline[1].NewValue)
	require.Contains(t, timeline[1].Description, "still reproducible")
}

func TestRetestStatesAndDuplicateRequests(t *testing.T) {
	for _, status := range []string{model.StatusNew, model.StatusProcessing, "unknown"} {
		t.Run(status, func(t *testing.T) {
			db, svc := newRetestTestService(t)
			v := seedRetestVulnerability(t, db, status)
			for _, result := range []string{model.RetestResultPass, model.RetestResultFail} {
				_, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: result, Summary: "test"})
				require.ErrorIs(t, err, repository.ErrRetestInvalidStatus)
			}
		})
	}
	for _, status := range []string{model.StatusFixed, model.StatusVerified, model.StatusClosed} {
		t.Run("fail "+status, func(t *testing.T) {
			db, svc := newRetestTestService(t)
			v := seedRetestVulnerability(t, db, status)
			_, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: model.RetestResultFail, Summary: "test"})
			require.NoError(t, err)
			require.NoError(t, db.First(v, v.ID).Error)
			require.Equal(t, model.StatusProcessing, v.Status)
		})
	}
	db, svc := newRetestTestService(t)
	v := seedRetestVulnerability(t, db, model.StatusFixed)
	start := make(chan struct{})
	results := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: model.RetestResultPass, Summary: "concurrent pass"})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			require.ErrorIs(t, err, repository.ErrRetestAlreadyVerified)
		}
	}
	require.Equal(t, 1, succeeded)
	var count int64
	require.NoError(t, db.Model(&model.VulnerabilityRetest{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
	require.NoError(t, db.Model(&model.VulnerabilityTimeline{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestRetestRollbackOnTimelineOrRecordFailure(t *testing.T) {
	for _, table := range []string{"vulnerability_retests", "vulnerability_timeline", "notifications"} {
		t.Run(table, func(t *testing.T) {
			db, svc := newRetestTestService(t)
			v := seedRetestVulnerability(t, db, model.StatusFixed)
			require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:retest-fail", func(tx *gorm.DB) {
				if tx.Statement.Table == table {
					// Fail the second notification to prove the first recipient's
					// successful insert is also rolled back with the retest.
					if notification, ok := tx.Statement.Dest.(*model.Notification); ok && notification.RecipientID != 3 {
						return
					}
					tx.AddError(errors.New("injected failure"))
				}
			}))
			t.Cleanup(func() { require.NoError(t, db.Callback().Create().Remove("test:retest-fail")) })
			_, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: model.RetestResultFail, Summary: "rollback"})
			require.Error(t, err)
			require.NoError(t, db.First(v, v.ID).Error)
			require.Equal(t, model.StatusFixed, v.Status)
			require.NotNil(t, v.FixedAt)
			var count int64
			require.NoError(t, db.Model(&model.VulnerabilityRetest{}).Count(&count).Error)
			require.Zero(t, count)
			require.NoError(t, db.Model(&model.VulnerabilityTimeline{}).Count(&count).Error)
			require.Zero(t, count)
			require.NoError(t, db.Model(&model.Notification{}).Count(&count).Error)
			require.Zero(t, count)
		})
	}
}

func TestRetestServicePermissionAndReadScopes(t *testing.T) {
	db, svc := newRetestTestService(t)
	v := seedRetestVulnerability(t, db, model.StatusFixed)
	request := &model.VulnerabilityRetestRequest{Result: model.RetestResultPass, Summary: "test"}
	_, err := svc.CreateRetest(v.ID, 2, request)
	require.ErrorIs(t, err, ErrRetestPermissionDenied)
	// Even an assignee with verify permission may not verify their own work.
	require.NoError(t, db.Model(&model.User{}).Where("id = ?", 2).Update("role_id", 1).Error)
	_, err = svc.CreateRetest(v.ID, 2, request)
	require.ErrorIs(t, err, repository.ErrRetestTesterAssignee)
	_, err = svc.CreateRetest(v.ID, 0, request)
	require.ErrorIs(t, err, ErrRetestPermissionDenied)
	_, err = svc.CreateRetest(v.ID, 1, request)
	require.NoError(t, err)
	for _, user := range []uint{1, 2, 3, 4} {
		items, err := svc.GetRetests(v.ID, user)
		require.NoError(t, err)
		require.Len(t, items, 1)
	}
	_, err = svc.GetRetests(v.ID, 5)
	require.ErrorIs(t, err, ErrRetestPermissionDenied)
	// A reader who is not involved cannot enumerate private evidence/history.
	require.NoError(t, db.Model(&model.Vulnerability{}).Where("id = ?", v.ID).Update("discoverer_id", nil).Error)
	_, err = svc.GetRetests(v.ID, 3)
	require.ErrorIs(t, err, ErrRetestAccessDenied)
	noPermissions := NewRetestService(repository.NewRetestRepository(db), repository.NewVulnerabilityRepository(db), nil)
	_, err = noPermissions.CreateRetest(v.ID, 1, request)
	require.ErrorIs(t, err, ErrRetestPermissionDenied)
}

func TestRetestCannotCreateItsOwnEvidenceAccess(t *testing.T) {
	db, svc := newRetestTestService(t)
	v := seedRetestVulnerability(t, db, model.StatusFixed)
	record, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: "pass", Summary: "authorized verification", EvidenceAttachments: []model.VulnerabilityRetestEvidenceRequest{{Path: "attachments/private.png", Filename: "private.png", OriginalName: "private.png", FileSize: 42}}})
	require.NoError(t, err)
	outsider := model.User{ID: 6, Username: "unrelated-verifier", Email: "outsider-verifier@test.test", RealName: "Outsider", RoleID: 1}
	require.NoError(t, db.Create(&outsider).Error)
	_, err = svc.GetRetests(v.ID, outsider.ID)
	require.ErrorIs(t, err, ErrRetestAccessDenied)
	_, err = svc.CreateRetest(v.ID, outsider.ID, &model.VulnerabilityRetestRequest{Result: "fail", Summary: "attempt to acquire evidence access"})
	require.ErrorIs(t, err, ErrRetestAccessDenied)
	_, err = svc.GetRetestEvidence(v.ID, record.ID, 0, outsider.ID)
	require.ErrorIs(t, err, ErrRetestAccessDenied)
	var stored model.Vulnerability
	require.NoError(t, db.First(&stored, v.ID).Error)
	require.Equal(t, model.StatusVerified, stored.Status)
	var count int64
	require.NoError(t, db.Model(&model.VulnerabilityRetest{}).Where("vulnerability_id = ?", v.ID).Count(&count).Error)
	require.EqualValues(t, 1, count)
	// The transaction repeats scope authorization if participation changed after preflight.
	direct := &model.VulnerabilityRetest{VulnerabilityID: v.ID, TesterID: outsider.ID, Result: "fail", Summary: "direct repository call"}
	require.ErrorIs(t, repository.NewRetestRepository(db).CreateRetestAndTransition(direct), repository.ErrRetestScopeDenied)
}

func TestRetestNotificationsRespectRecipientsAndSystemPush(t *testing.T) {
	for _, result := range []string{model.RetestResultPass, model.RetestResultFail} {
		t.Run(result, func(t *testing.T) {
			db, svc := newRetestTestService(t)
			require.NoError(t, db.AutoMigrate(&model.EmailLog{}))
			v := seedRetestVulnerability(t, db, model.StatusFixed)
			created, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: result, Summary: "notification test"})
			require.NoError(t, err)
			var notifications []model.Notification
			require.NoError(t, db.Order("recipient_id").Find(&notifications).Error)
			require.Len(t, notifications, 2) // No settings row defaults to enabled.
			for i, notification := range notifications {
				require.Equal(t, uint(i+2), notification.RecipientID)
				require.Equal(t, uint(1), *notification.SenderID)
				require.Equal(t, "vulnerability", notification.EntityType)
				require.Equal(t, v.ID, *notification.EntityID)
				require.Equal(t, "retests", notification.Data["section"])
				require.Equal(t, float64(created.ID), notification.Data["retest_id"])
				require.Equal(t, result, notification.Data["result"])
				require.Equal(t, fmt.Sprintf("retest:%d:%d", created.ID, notification.RecipientID), *notification.DedupKey)
			}
			var emails int64
			require.NoError(t, db.Model(&model.EmailLog{}).Count(&emails).Error)
			require.Zero(t, emails)
		})
	}
	for _, tc := range []struct {
		name       string
		discoverer uint
		disable    bool
		count      int
	}{
		{"same recipient deduplicated", 2, false, 1},
		{"tester excluded", 1, false, 1},
		{"push disabled", 2, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, svc := newRetestTestService(t)
			v := seedRetestVulnerability(t, db, model.StatusFixed)
			require.NoError(t, db.Model(&model.Vulnerability{}).Where("id = ?", v.ID).Update("discoverer_id", tc.discoverer).Error)
			if tc.disable {
				preferences := model.NotificationSettings{UserID: 2}
				require.NoError(t, db.Create(&preferences).Error)
				require.NoError(t, db.Model(&preferences).Update("system_push", false).Error)
			}
			_, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: model.RetestResultPass, Summary: "test"})
			require.NoError(t, err)
			var notifications []model.Notification
			require.NoError(t, db.Find(&notifications).Error)
			require.Len(t, notifications, tc.count)
		})
	}
}

func TestRetestCannotUseLegacyUpdateToVerify(t *testing.T) {
	db, _ := newRetestTestService(t)
	v := seedRetestVulnerability(t, db, model.StatusFixed)
	legacy := NewVulnerabilityService(repository.NewVulnerabilityRepository(db), nil, nil, nil)
	for _, target := range []string{model.StatusVerified, model.StatusClosed} {
		require.Error(t, legacy.UpdateVulnerabilityStatus(v.ID, target, 1))
		require.Error(t, legacy.UpdateVulnerability(v.ID, &model.VulnerabilityUpdateRequest{Status: target}))
	}
	require.NoError(t, db.First(v, v.ID).Error)
	require.Equal(t, model.StatusFixed, v.Status)
	for _, current := range []string{model.StatusVerified, model.StatusClosed} {
		require.NoError(t, db.Model(&model.Vulnerability{}).Where("id = ?", v.ID).Update("status", current).Error)
		for _, target := range []string{model.StatusNew, model.StatusProcessing, model.StatusFixed} {
			require.Error(t, legacy.UpdateVulnerabilityStatus(v.ID, target, 1))
			require.Error(t, legacy.UpdateVulnerability(v.ID, &model.VulnerabilityUpdateRequest{Status: target}))
		}
	}
}

func TestRetestDeleteQueuesPrivateEvidenceAtomically(t *testing.T) {
	db, svc := newRetestTestService(t)
	v := seedRetestVulnerability(t, db, model.StatusFixed)
	_, err := svc.CreateRetest(v.ID, 1, &model.VulnerabilityRetestRequest{Result: model.RetestResultPass, Summary: "test", EvidenceAttachments: []model.VulnerabilityRetestEvidenceRequest{{Path: "attachments/private.png", FileSize: 20}}})
	require.NoError(t, err)
	failCleanup := true
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:retest-cleanup", func(tx *gorm.DB) {
		if failCleanup && tx.Statement.Table == "file_cleanup_tasks" {
			tx.AddError(errors.New("cleanup outbox unavailable"))
		}
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Create().Remove("test:retest-cleanup")) })
	require.Error(t, repository.NewVulnerabilityRepository(db).Delete(v.ID))
	var parent model.Vulnerability
	require.NoError(t, db.First(&parent, v.ID).Error)
	var retained int64
	require.NoError(t, db.Model(&model.VulnerabilityRetest{}).Where("vulnerability_id = ?", v.ID).Count(&retained).Error)
	require.EqualValues(t, 1, retained)
	failCleanup = false
	require.NoError(t, repository.NewVulnerabilityRepository(db).Delete(v.ID))
	var records int64
	require.NoError(t, db.Model(&model.VulnerabilityRetest{}).Count(&records).Error)
	require.Zero(t, records)
	var cleanup model.FileCleanupTask
	require.NoError(t, db.First(&cleanup).Error)
	require.Equal(t, "attachments/private.png", cleanup.FilePath)
}
