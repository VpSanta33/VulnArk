package model

import "time"

// FileCleanupTask is an outbox entry written in the same transaction as the
// metadata deletion. Completed entries are removed; failures survive restarts.
type FileCleanupTask struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	FilePath    string     `json:"-" gorm:"size:500;not null"`
	Attempts    uint       `json:"attempts" gorm:"not null;default:0"`
	NextAttempt time.Time  `json:"next_attempt" gorm:"not null;index"`
	LeaseToken  string     `json:"-" gorm:"size:64;not null;default:''"`
	LeaseUntil  *time.Time `json:"-" gorm:"index"`
	LastError   string     `json:"-" gorm:"type:text"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}
