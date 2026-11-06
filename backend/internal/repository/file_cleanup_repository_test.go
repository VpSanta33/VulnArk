package repository

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
)

func seedReportCleanup(t *testing.T, db *gorm.DB) (model.Report, model.ReportComment) {
	t.Helper()
	report := model.Report{Title: "cleanup", FilePath: filepath.Join(t.TempDir(), "report.pdf"), FileName: "report.pdf", UploaderID: 7, Type: "other"}
	require.NoError(t, os.WriteFile(report.FilePath, []byte("keep until commit"), 0600))
	// NULL JSON columns keep this test compatible with SQLite's text driver.
	require.NoError(t, db.Omit("AssetIDs", "Tags", clause.Associations).Create(&report).Error)
	comment := model.ReportComment{ReportID: report.ID, UserID: 7, Content: "comment"}
	require.NoError(t, db.Omit(clause.Associations).Create(&comment).Error)
	for _, attachment := range []model.FileAttachment{
		{EntityType: model.EntityTypeReport, EntityID: report.ID, FilePath: "reports/attachment.pdf", Filename: "attachment.pdf", OriginalName: "attachment.pdf", UploaderID: 7},
		{EntityType: "report_comment", EntityID: comment.ID, FilePath: "reports/comment.pdf", Filename: "comment.pdf", OriginalName: "comment.pdf", UploaderID: 7},
	} {
		require.NoError(t, db.Omit(clause.Associations).Create(&attachment).Error)
	}
	return report, comment
}

func cleanupCount(t *testing.T, db *gorm.DB, model interface{}) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(model).Count(&count).Error)
	return count
}

func TestReportDeleteAtomicallyEnqueuesAndRemovesDependents(t *testing.T) {
	db := newAIRepositoryTestDB(t)
	report, _ := seedReportCleanup(t, db)
	require.NoError(t, NewReportRepository(db).Delete(report.ID))
	require.Zero(t, cleanupCount(t, db, &model.Report{}))
	require.Zero(t, cleanupCount(t, db, &model.ReportComment{}))
	require.Zero(t, cleanupCount(t, db, &model.FileAttachment{}))
	require.EqualValues(t, 3, cleanupCount(t, db, &model.FileCleanupTask{}))
	_, err := os.Stat(report.FilePath)
	require.NoError(t, err, "repository must never touch physical files")
	// An updater holding the old object cannot recreate a deleted report.
	require.ErrorIs(t, NewReportRepository(db).Update(&report), gorm.ErrRecordNotFound)
	require.Zero(t, cleanupCount(t, db, &model.Report{}))
}

func TestReportDeleteRollbackRetainsFilesAndDependents(t *testing.T) {
	for _, failAt := range []string{"file_cleanup_tasks", "reports"} {
		t.Run(failAt, func(t *testing.T) {
			db := newAIRepositoryTestDB(t)
			report, _ := seedReportCleanup(t, db)
			if failAt == "file_cleanup_tasks" {
				require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:cleanup-fail", func(tx *gorm.DB) {
					if tx.Statement.Table == failAt {
						tx.AddError(errors.New("injected cleanup insertion failure"))
					}
				}))
			} else {
				require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register("test:report-fail", func(tx *gorm.DB) {
					if tx.Statement.Table == failAt {
						tx.AddError(errors.New("injected report deletion failure"))
					}
				}))
			}
			err := NewReportRepository(db).Delete(report.ID)
			require.ErrorContains(t, err, "injected")
			require.EqualValues(t, 1, cleanupCount(t, db, &model.Report{}))
			require.EqualValues(t, 1, cleanupCount(t, db, &model.ReportComment{}))
			require.EqualValues(t, 2, cleanupCount(t, db, &model.FileAttachment{}))
			require.Zero(t, cleanupCount(t, db, &model.FileCleanupTask{}))
			content, err := os.ReadFile(report.FilePath)
			require.NoError(t, err)
			require.Equal(t, "keep until commit", string(content))
		})
	}
}

func TestReportCommentOwnershipAndParentDeletion(t *testing.T) {
	db := newAIRepositoryTestDB(t)
	report, comment := seedReportCleanup(t, db)
	repo := NewReportCommentRepository(db)
	require.ErrorIs(t, repo.DeleteOwned(comment.ID, 8), gorm.ErrRecordNotFound)
	require.EqualValues(t, 1, cleanupCount(t, db, &model.ReportComment{}))
	require.NoError(t, repo.DeleteOwned(comment.ID, 7))
	require.Zero(t, cleanupCount(t, db, &model.ReportComment{}))
	require.EqualValues(t, 1, cleanupCount(t, db, &model.FileCleanupTask{}))
	require.NoError(t, NewReportRepository(db).Delete(report.ID))
	require.ErrorIs(t, repo.Create(&model.ReportComment{ReportID: report.ID, UserID: 7, Content: "orphan"}), gorm.ErrRecordNotFound)
	require.ErrorIs(t, NewFileAttachmentRepository(db).Create(&model.FileAttachment{EntityType: model.EntityTypeReport, EntityID: report.ID, FilePath: "late"}), gorm.ErrRecordNotFound)
}

func TestFileCleanupClaimFencingAndRecovery(t *testing.T) {
	runFileCleanupClaimFencingAndRecovery(t, newAIRepositoryTestDB(t))
}

func runFileCleanupClaimFencingAndRecovery(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, EnqueueFileCleanup(db, "one", "one", "", "two"))
	repo := NewFileCleanupRepository(db)
	ctx := context.Background()
	first, err := repo.Claim(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, first, 1)
	other, err := NewFileCleanupRepository(db).Claim(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, other, 1)
	require.NotEqual(t, first[0].ID, other[0].ID)
	require.NoError(t, repo.Complete(ctx, other[0]))
	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, db.Model(&model.FileCleanupTask{}).Where("id = ?", first[0].ID).Update("lease_until", past).Error)
	// Another repository/process can recover a crashed worker's expired task.
	recovered, err := NewFileCleanupRepository(db).Claim(ctx, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, first[0].ID, recovered[0].ID)
	require.EqualValues(t, 2, recovered[0].Attempts)
	require.ErrorIs(t, repo.Complete(ctx, first[0]), ErrFileCleanupLeaseLost)
	require.ErrorIs(t, repo.Retry(ctx, first[0], time.Second, errors.New("stale")), ErrFileCleanupLeaseLost)
	require.NoError(t, repo.Complete(ctx, recovered[0]))
	require.Zero(t, cleanupCount(t, db, &model.FileCleanupTask{}))
}
