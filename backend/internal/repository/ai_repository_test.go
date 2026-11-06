package repository

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mysqlconfig "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
)

func newAIRepositoryTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")+"?_busy_timeout=5000&_journal_mode=WAL"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), DisableForeignKeyConstraintWhenMigrating: true, IgnoreRelationshipsWhenMigrating: true,
	})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&model.AIConversation{}, &model.FileCleanupTask{}, &model.Report{}, &model.ReportComment{}, &model.FileAttachment{}))
	return db
}

func TestAIConversationLeaseContention(t *testing.T) {
	runAILeaseContention(t, newAIRepositoryTestDB(t))
}

func runAILeaseContention(t *testing.T, db *gorm.DB) {
	t.Helper()
	repo := NewAIRepository(db)
	conversation, err := repo.CreateConversation(7, "lease")
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Distinct repository objects represent independent request handlers.
			_, err := NewAIRepository(db.Session(&gorm.Session{})).AcquireConversation(context.Background(), 7, conversation.SessionID, time.Minute)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else {
			require.ErrorIs(t, err, ErrAIConversationBusy)
		}
	}
	require.Equal(t, 1, winners)
	_, err = repo.AcquireConversation(context.Background(), 8, conversation.SessionID, time.Minute)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestAIConversationFencingHistoryAndTokens(t *testing.T) {
	runAIFencingHistoryAndTokens(t, newAIRepositoryTestDB(t))
}

func runAIFencingHistoryAndTokens(t *testing.T, db *gorm.DB) {
	t.Helper()
	repo := NewAIRepository(db)
	conversation, err := repo.CreateConversation(7, "fencing")
	require.NoError(t, err)
	ctx := context.Background()
	first, err := repo.AcquireConversation(ctx, 7, conversation.SessionID, time.Minute)
	require.NoError(t, err)
	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, db.Model(&model.AIConversation{}).Where("id = ?", conversation.ID).Update("lease_until", past).Error)
	messages := []model.AIMessage{{Role: "user", Content: "one"}, {Role: "assistant", Content: "answer", Tokens: 11}}
	require.ErrorIs(t, repo.CommitConversation(ctx, 7, first.SessionID, first.LeaseToken, first.Version, messages, 11), ErrAILeaseLost)
	second, err := NewAIRepository(db).AcquireConversation(ctx, 7, conversation.SessionID, time.Minute)
	require.NoError(t, err)
	require.Greater(t, second.Version, first.Version)
	require.NotEqual(t, first.LeaseToken, second.LeaseToken)
	require.ErrorIs(t, repo.CommitConversation(ctx, 7, first.SessionID, first.LeaseToken, first.Version, messages, 11), ErrAILeaseLost)
	require.NoError(t, repo.ReleaseConversation(ctx, 7, first.SessionID, first.LeaseToken, first.Version))
	require.ErrorIs(t, repo.CommitConversation(ctx, 8, second.SessionID, second.LeaseToken, second.Version, messages, 11), ErrAILeaseLost)
	require.NoError(t, repo.CommitConversation(ctx, 7, second.SessionID, second.LeaseToken, second.Version, messages, 11))
	require.ErrorIs(t, repo.CommitConversation(ctx, 7, second.SessionID, second.LeaseToken, second.Version, messages, 11), ErrAILeaseLost)
	third, err := repo.AcquireConversation(ctx, 7, conversation.SessionID, time.Minute)
	require.NoError(t, err)
	var history []model.AIMessage
	require.NoError(t, json.Unmarshal([]byte(third.Messages), &history))
	require.Equal(t, messages, history)
	history = append(history, model.AIMessage{Role: "user", Content: "two"}, model.AIMessage{Role: "assistant", Content: "second"})
	require.NoError(t, repo.CommitConversation(ctx, 7, third.SessionID, third.LeaseToken, third.Version, history, 5))
	stored, err := repo.GetConversation(7, conversation.SessionID)
	require.NoError(t, err)
	require.Equal(t, 16, stored.TokensUsed)
	require.NoError(t, json.Unmarshal([]byte(stored.Messages), &history))
	require.Len(t, history, 4)
}

func TestAIConversationDeletionAndArchiveFenceInflight(t *testing.T) {
	runAIDeletionAndArchiveFenceInflight(t, newAIRepositoryTestDB(t))
}

func runAIDeletionAndArchiveFenceInflight(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, status := range []string{"deleted", "archived"} {
		t.Run(status, func(t *testing.T) {
			repo := NewAIRepository(db)
			conversation, err := repo.CreateConversation(7, status)
			require.NoError(t, err)
			leased, err := repo.AcquireConversation(context.Background(), 7, conversation.SessionID, time.Minute)
			require.NoError(t, err)
			if status == "deleted" {
				require.NoError(t, repo.DeleteConversation(7, conversation.SessionID))
			} else {
				require.NoError(t, repo.ArchiveConversation(7, conversation.SessionID))
			}
			require.ErrorIs(t, repo.CommitConversation(context.Background(), 7, leased.SessionID, leased.LeaseToken, leased.Version, []model.AIMessage{{Role: "assistant", Content: "late"}}, 4), ErrAILeaseLost)
			_, err = repo.AcquireConversation(context.Background(), 7, conversation.SessionID, time.Minute)
			require.ErrorIs(t, err, ErrAIConversationInactive)
			stored, err := repo.GetConversation(7, conversation.SessionID)
			require.NoError(t, err)
			require.Equal(t, "[]", stored.Messages)
			require.Zero(t, stored.TokensUsed)
		})
	}
}

// Optional integration requires a dedicated, initially empty schema. This never
// reads application configuration or connects to its configured business DB.
func TestAIConversationMySQLIntegration(t *testing.T) {
	dsn := os.Getenv("VULNARK_AI_CLEANUP_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set VULNARK_AI_CLEANUP_MYSQL_TEST_DSN to an isolated empty test schema")
	}
	cfg, err := mysqlconfig.ParseDSN(dsn)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(cfg.DBName, "vulnark_ai_cleanup_test_"), "refuse non-test schema")
	cfg.ParseTime = true
	db, err := gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), DisableForeignKeyConstraintWhenMigrating: true, IgnoreRelationshipsWhenMigrating: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.False(t, db.Migrator().HasTable(&model.AIConversation{}), "test schema must not contain AI data")
	require.False(t, db.Migrator().HasTable(&model.FileCleanupTask{}), "test schema must not contain cleanup data")
	require.NoError(t, db.AutoMigrate(&model.AIConversation{}, &model.FileCleanupTask{}))
	// Keep the isolated schema and its evidence. Never DROP or TRUNCATE here.
	t.Logf("retaining integration evidence in schema %s", cfg.DBName)
	t.Run("contention", func(t *testing.T) { runAILeaseContention(t, db) })
	t.Run("fencing_history_tokens", func(t *testing.T) { runAIFencingHistoryAndTokens(t, db) })
	t.Run("delete_archive", func(t *testing.T) { runAIDeletionAndArchiveFenceInflight(t, db) })
	t.Run("cleanup_claim_recovery", func(t *testing.T) { runFileCleanupClaimFencingAndRecovery(t, db) })
}

func TestAISettingsBlankKeyDoesNotOverwriteConcurrentRotation(t *testing.T) {
	db := newAIRepositoryTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.AIConfiguration{}))
	repo := NewAIRepository(db)
	require.NoError(t, repo.UpdateAIConfiguration(7, &model.AIConfigurationRequest{Provider: "openai", APIKey: "old-key"}))
	// Simulate another request rotating the key after this request reads the row,
	// before its UPDATE is issued.
	require.NoError(t, db.Callback().Update().Before("gorm:begin_transaction").Register("test:rotate-key", func(tx *gorm.DB) {
		if tx.Statement.Table == "ai_configurations" {
			require.NoError(t, db.Exec("UPDATE ai_configurations SET api_key = ? WHERE user_id = ?", "rotated-key", 7).Error)
		}
	}))
	require.NoError(t, repo.UpdateAIConfiguration(7, &model.AIConfigurationRequest{Provider: "openai", Model: "changed"}))
	require.NoError(t, db.Callback().Update().Remove("test:rotate-key"))
	saved, err := repo.GetAIConfiguration(7)
	require.NoError(t, err)
	require.Equal(t, "rotated-key", saved.APIKey)
	require.Equal(t, "changed", saved.Model)
}
