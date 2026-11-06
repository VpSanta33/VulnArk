package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"vulnark/internal/model"
)

var ErrFileCleanupLeaseLost = errors.New("file cleanup lease lost")

// EnqueueFileCleanup must receive the transaction deleting the business metadata.
// An insertion failure must be returned from that transaction so deletion rolls back.
func EnqueueFileCleanup(tx *gorm.DB, paths ...string) error {
	seen := make(map[string]bool, len(paths))
	tasks := make([]model.FileCleanupTask, 0, len(paths))
	now, err := databaseNow(tx)
	if err != nil {
		return err
	}
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		tasks = append(tasks, model.FileCleanupTask{FilePath: path, NextAttempt: now})
	}
	if len(tasks) == 0 {
		return nil
	}
	return tx.Create(&tasks).Error
}

type FileCleanupRepository interface {
	Claim(ctx context.Context, limit int, lease time.Duration) ([]model.FileCleanupTask, error)
	Complete(ctx context.Context, task model.FileCleanupTask) error
	Retry(ctx context.Context, task model.FileCleanupTask, delay time.Duration, cause error) error
}

type fileCleanupRepository struct{ db *gorm.DB }

func NewFileCleanupRepository(db *gorm.DB) FileCleanupRepository {
	return &fileCleanupRepository{db: db}
}

// Claim uses conditional updates for contention; no filesystem I/O is performed
// inside a transaction. Expired claims become eligible after a process restart.
func (r *fileCleanupRepository) Claim(ctx context.Context, limit int, lease time.Duration) ([]model.FileCleanupTask, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("cleanup batch size must be between 1 and 100")
	}
	if lease <= 0 || lease > 10*time.Minute {
		return nil, errors.New("invalid cleanup lease duration")
	}
	db := r.db.WithContext(ctx)
	now, err := databaseNow(db)
	if err != nil {
		return nil, err
	}
	var candidates []model.FileCleanupTask
	if err := db.Where("next_attempt <= ? AND (lease_until IS NULL OR lease_until <= ?)", now, now).
		Order("next_attempt, id").Limit(limit).Find(&candidates).Error; err != nil {
		return nil, err
	}
	claimed := make([]model.FileCleanupTask, 0, len(candidates))
	for _, task := range candidates {
		token, err := generateSessionID()
		if err != nil {
			return claimed, err
		}
		until := now.Add(lease)
		result := db.Model(&model.FileCleanupTask{}).
			Where("id = ? AND next_attempt <= ? AND (lease_until IS NULL OR lease_until <= ?)", task.ID, now, now).
			Updates(map[string]interface{}{"lease_token": token, "lease_until": until, "attempts": gorm.Expr("attempts + 1")})
		if result.Error != nil {
			return claimed, result.Error
		}
		if result.RowsAffected == 1 {
			task.LeaseToken, task.LeaseUntil = token, &until
			task.Attempts++
			claimed = append(claimed, task)
		}
	}
	return claimed, nil
}

func (r *fileCleanupRepository) owned(ctx context.Context, task model.FileCleanupTask) (*gorm.DB, error) {
	if task.LeaseToken == "" {
		return nil, ErrFileCleanupLeaseLost
	}
	db := r.db.WithContext(ctx)
	now, err := databaseNow(db)
	if err != nil {
		return nil, err
	}
	return db.Model(&model.FileCleanupTask{}).Where("id = ? AND lease_token = ? AND lease_until > ?", task.ID, task.LeaseToken, databaseClockExpression(db, now)), nil
}

func (r *fileCleanupRepository) Complete(ctx context.Context, task model.FileCleanupTask) error {
	db, err := r.owned(ctx, task)
	if err != nil {
		return err
	}
	result := db.Delete(&model.FileCleanupTask{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrFileCleanupLeaseLost
	}
	return nil
}

func (r *fileCleanupRepository) Retry(ctx context.Context, task model.FileCleanupTask, delay time.Duration, cause error) error {
	db, err := r.owned(ctx, task)
	if err != nil {
		return err
	}
	now, err := databaseNow(r.db.WithContext(ctx))
	if err != nil {
		return err
	}
	message := ""
	if cause != nil {
		runes := []rune(cause.Error())
		if len(runes) > 512 {
			runes = runes[:512]
		}
		message = string(runes)
	}
	result := db.Updates(map[string]interface{}{
		"next_attempt": now.Add(delay), "last_error": message,
		"lease_token": "", "lease_until": nil,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrFileCleanupLeaseLost
	}
	return nil
}
