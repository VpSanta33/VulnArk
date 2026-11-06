package service

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// CleanupAuditLogs honors the configured retention and releases database locks
// between small batches. The caller supplies a bounded, cancellable context.
func CleanupAuditLogs(ctx context.Context, db *gorm.DB, now time.Time) error {
	days := 90
	var setting model.SystemConfig
	err := db.WithContext(ctx).Select("value").Where("`key` = ?", "audit.log_retention_days").First(&setting).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if err == nil && setting.Value.GetInt("value") > 0 {
		days = setting.Value.GetInt("value")
	}
	before := now.AddDate(0, 0, -days)
	repo := repository.NewAuditLogRepository(db).(repository.ContextAuditLogCleanupRepository)
	for {
		count, err := repo.DeleteOldLogsBatch(ctx, before, 1000)
		if err != nil || count < 1000 {
			return err
		}
	}
}
