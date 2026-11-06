package service

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysqlconfig "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

type cleanupDeleteFunc func(string) error

func (f cleanupDeleteFunc) DeleteFile(path string) error { return f(path) }

func cleanupTasks(t *testing.T, db *gorm.DB) []model.FileCleanupTask {
	t.Helper()
	var tasks []model.FileCleanupTask
	require.NoError(t, db.Order("id").Find(&tasks).Error)
	return tasks
}

func TestFileCleanupWorkerFailureRetryAndRestart(t *testing.T) {
	db := newAIServiceTestDB(t)
	require.NoError(t, repository.EnqueueFileCleanup(db, "one"))
	repo := repository.NewFileCleanupRepository(db)
	calls := 0
	failing := cleanupDeleteFunc(func(string) error { calls++; return errors.New("storage unavailable") })
	worker := NewFileCleanupWorker(repo, failing, FileCleanupWorkerOptions{RetryBase: time.Minute})
	require.ErrorContains(t, worker.RunBatch(context.Background()), "storage unavailable")
	tasks := cleanupTasks(t, db)
	require.Len(t, tasks, 1)
	require.EqualValues(t, 1, tasks[0].Attempts)
	require.Empty(t, tasks[0].LeaseToken)
	require.Contains(t, tasks[0].LastError, "storage unavailable")
	require.True(t, tasks[0].NextAttempt.After(time.Now().UTC().Add(45*time.Second)))
	require.NoError(t, worker.RunBatch(context.Background()))
	require.Equal(t, 1, calls, "not retried before the persisted due date")
	// Force the durable due date rather than sleeping; recreate both components
	// to show the queue is recoverable without in-memory state.
	require.NoError(t, db.Model(&model.FileCleanupTask{}).Where("id = ?", tasks[0].ID).Update("next_attempt", time.Now().UTC().Add(-time.Minute)).Error)
	restarted := NewFileCleanupWorker(repository.NewFileCleanupRepository(db), cleanupDeleteFunc(func(path string) error {
		require.Equal(t, "one", path)
		return nil
	}), FileCleanupWorkerOptions{})
	require.NoError(t, restarted.RunBatch(context.Background()))
	require.Empty(t, cleanupTasks(t, db))
}

func TestFileCleanupWorkerCrashAfterDeletionIsIdempotent(t *testing.T) {
	db := newAIServiceTestDB(t)
	require.NoError(t, repository.EnqueueFileCleanup(db, "already-removed"))
	repo := repository.NewFileCleanupRepository(db)
	claimed, err := repo.Claim(context.Background(), 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	// Model a crash after unlink but before deleting the queue row.
	require.NoError(t, db.Model(&model.FileCleanupTask{}).Where("id = ?", claimed[0].ID).Update("lease_until", time.Now().UTC().Add(-time.Minute)).Error)
	worker := NewFileCleanupWorker(repository.NewFileCleanupRepository(db), cleanupDeleteFunc(func(string) error { return fs.ErrNotExist }), FileCleanupWorkerOptions{})
	require.NoError(t, worker.RunBatch(context.Background()))
	require.Empty(t, cleanupTasks(t, db))
}

func TestFileCleanupWorkerBatchBoundAndCancellation(t *testing.T) {
	db := newAIServiceTestDB(t)
	require.NoError(t, repository.EnqueueFileCleanup(db, "one", "two", "three"))
	calls := 0
	worker := NewFileCleanupWorker(repository.NewFileCleanupRepository(db), cleanupDeleteFunc(func(string) error { calls++; return nil }), FileCleanupWorkerOptions{BatchSize: 1})
	require.NoError(t, worker.RunBatch(context.Background()))
	require.Equal(t, 1, calls)
	require.Len(t, cleanupTasks(t, db), 2)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, worker.RunBatch(ctx), context.Canceled)
	require.ErrorIs(t, worker.Run(ctx), context.Canceled)
	require.Equal(t, 1, calls)
}

func TestFileCleanupWorkerCancellationBetweenFiles(t *testing.T) {
	db := newAIServiceTestDB(t)
	require.NoError(t, repository.EnqueueFileCleanup(db, "one", "two"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	worker := NewFileCleanupWorker(repository.NewFileCleanupRepository(db), cleanupDeleteFunc(func(string) error {
		calls++
		cancel()
		return nil
	}), FileCleanupWorkerOptions{BatchSize: 2})
	require.ErrorIs(t, worker.RunBatch(ctx), context.Canceled)
	require.Equal(t, 1, calls)
	require.Len(t, cleanupTasks(t, db), 2, "cancelled completion and unprocessed claim survive expiry")
}

func TestFileCleanupWorkerRecoveryAfterDatabaseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "durable.db")
	open := func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		require.NoError(t, err)
		return db
	}
	firstDB := open()
	require.NoError(t, firstDB.AutoMigrate(&model.FileCleanupTask{}))
	require.NoError(t, repository.EnqueueFileCleanup(firstDB, "survives-restart"))
	claims, err := repository.NewFileCleanupRepository(firstDB).Claim(context.Background(), 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	require.NoError(t, firstDB.Model(&model.FileCleanupTask{}).Where("id = ?", claims[0].ID).Update("lease_until", time.Now().UTC().Add(-time.Minute)).Error)
	firstSQL, err := firstDB.DB()
	require.NoError(t, err)
	require.NoError(t, firstSQL.Close())
	secondDB := open()
	secondSQL, err := secondDB.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, secondSQL.Close()) })
	worker := NewFileCleanupWorker(repository.NewFileCleanupRepository(secondDB), cleanupDeleteFunc(func(path string) error {
		require.Equal(t, "survives-restart", path)
		return nil
	}), FileCleanupWorkerOptions{})
	require.NoError(t, worker.RunBatch(context.Background()))
	require.Empty(t, cleanupTasks(t, secondDB))
}

func TestFileCleanupWorkerMySQLIntegration(t *testing.T) {
	dsn := os.Getenv("VULNARK_AI_CLEANUP_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set VULNARK_AI_CLEANUP_MYSQL_TEST_DSN to an isolated test schema")
	}
	cfg, err := mysqlconfig.ParseDSN(dsn)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(cfg.DBName, "vulnark_ai_cleanup_test_"), "refuse non-test schema")
	cfg.ParseTime = true
	open := func() *gorm.DB {
		db, err := gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		require.NoError(t, err)
		return db
	}
	db := open()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()
	if !db.Migrator().HasTable(&model.FileCleanupTask{}) {
		require.NoError(t, db.AutoMigrate(&model.FileCleanupTask{}))
	}
	require.Empty(t, cleanupTasks(t, db), "refuse to process preexisting cleanup tasks")
	require.NoError(t, repository.EnqueueFileCleanup(db, "mysql/retry-after-restart"))
	worker := NewFileCleanupWorker(repository.NewFileCleanupRepository(db), cleanupDeleteFunc(func(string) error {
		return errors.New("injected storage failure")
	}), FileCleanupWorkerOptions{RetryBase: time.Minute})
	require.ErrorContains(t, worker.RunBatch(context.Background()), "injected storage failure")
	tasks := cleanupTasks(t, db)
	require.Len(t, tasks, 1)
	require.EqualValues(t, 1, tasks[0].Attempts)
	require.Empty(t, tasks[0].LeaseToken)
	require.Contains(t, tasks[0].LastError, "injected storage failure")
	var delaySeconds int
	require.NoError(t, db.Raw("SELECT TIMESTAMPDIFF(SECOND, CURRENT_TIMESTAMP(6), next_attempt) FROM file_cleanup_tasks WHERE id = ?", tasks[0].ID).Scan(&delaySeconds).Error)
	require.GreaterOrEqual(t, delaySeconds, 45)
	require.NoError(t, db.Model(&model.FileCleanupTask{}).Where("id = ?", tasks[0].ID).Update("next_attempt", gorm.Expr("CURRENT_TIMESTAMP(6) - INTERVAL 1 MINUTE")).Error)
	require.NoError(t, sqlDB.Close())
	// Reopen a distinct SQL connection pool, then recover the persisted retry.
	reopened := open()
	reopenedSQL, err := reopened.DB()
	require.NoError(t, err)
	defer reopenedSQL.Close()
	restarted := NewFileCleanupWorker(repository.NewFileCleanupRepository(reopened), cleanupDeleteFunc(func(path string) error {
		require.Equal(t, "mysql/retry-after-restart", path)
		return fs.ErrNotExist
	}), FileCleanupWorkerOptions{})
	require.NoError(t, restarted.RunBatch(context.Background()))
	require.Empty(t, cleanupTasks(t, reopened))
	// Retain an inspectable future retry as integration evidence. No DROP,
	// TRUNCATE or post-test cleanup is performed against the isolated schema.
	require.NoError(t, repository.EnqueueFileCleanup(reopened, "mysql/retained-retry-evidence"))
	evidence := NewFileCleanupWorker(repository.NewFileCleanupRepository(reopened), cleanupDeleteFunc(func(string) error {
		return errors.New("retained integration retry evidence")
	}), FileCleanupWorkerOptions{RetryBase: time.Hour})
	require.ErrorContains(t, evidence.RunBatch(context.Background()), "retained integration retry evidence")
	t.Logf("retaining retry evidence in schema %s", cfg.DBName)
}

func TestFileCleanupWorkerBackoffCap(t *testing.T) {
	worker := NewFileCleanupWorker(nil, nil, FileCleanupWorkerOptions{RetryBase: time.Second, RetryMax: time.Minute})
	require.Equal(t, time.Second, worker.retryDelay(1))
	require.Equal(t, 2*time.Second, worker.retryDelay(2))
	require.Equal(t, time.Minute, worker.retryDelay(1000000))
}
