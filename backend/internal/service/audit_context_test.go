package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

func TestAuditServicePropagatesCancellationToGORM(t *testing.T) {
	// database/sql may discard a connection after cancelling a transaction;
	// a temporary file preserves the schema across replacement connections.
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "audit.sqlite")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	pool, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	require.NoError(t, db.AutoMigrate(&model.AuditLog{}))
	service := NewAuditLogService(repository.NewAuditLogRepository(db))
	contextual, ok := service.(interface {
		CreateAuditLogContext(context.Context, *model.AuditLog) error
	})
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = contextual.CreateAuditLogContext(ctx, &model.AuditLog{Action: "cancelled-before-write", Resource: "test"})
	require.ErrorIs(t, err, context.Canceled)

	// Cancel after the service call has reached GORM, proving the repository
	// propagates the same context instead of checking it only at service entry.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:cancel-audit-write", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_logs" {
			require.Same(t, ctx, tx.Statement.Context)
			cancel()
		}
	}))
	err = contextual.CreateAuditLogContext(ctx, &model.AuditLog{Action: "cancelled-during-write", Resource: "test"})
	// GORM can append a rollback error after database/sql has already rolled
	// back the cancelled transaction; retain the cancellation assertion.
	require.ErrorContains(t, err, context.Canceled.Error())
	require.NoError(t, db.Callback().Create().Remove("test:cancel-audit-write"))

	var count int64
	require.NoError(t, db.Model(&model.AuditLog{}).Count(&count).Error)
	require.Zero(t, count)
	require.NoError(t, contextual.CreateAuditLogContext(context.Background(), &model.AuditLog{Action: "written", Resource: "test"}))
	require.NoError(t, db.Model(&model.AuditLog{}).Count(&count).Error)
	require.Equal(t, int64(1), count)
}
