package testutil

import (
	"fmt"
	"sync/atomic"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
)

var testDatabaseSequence atomic.Uint64

// NewTestDB creates an isolated in-memory database backed by a single connection.
// Passing t registers Close automatically; the optional argument preserves older
// callers that defer CleanupTestData themselves.
func NewTestDB(tests ...testing.TB) *gorm.DB {
	name := fmt.Sprintf("file:vulnark_test_%d?mode=memory&cache=shared", testDatabaseSequence.Add(1))
	db, err := gorm.Open(sqlite.Open(name), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		panic("failed to connect test database: " + err.Error())
	}
	pool, err := db.DB()
	if err != nil {
		panic("failed to get test connection: " + err.Error())
	}
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	// No connection expiration: closing the last connection destroys SQLite RAM.
	if err := db.AutoMigrate(
		&model.Role{}, &model.User{}, &model.MFAChallenge{}, &model.Asset{},
		&model.OWASPCategory{}, &model.Vulnerability{}, &model.VulnerabilityAttachment{},
		&model.SLAPolicy{}, &model.VulnerabilityRetest{}, &model.VulnerabilityDuplicateLink{},
		&model.VulnerabilityDuplicateIgnore{},
		&model.RiskScoringConfig{}, &model.EPSSScore{}, &model.KEVEntry{}, &model.ThreatIntelSyncState{},
	); err != nil {
		_ = pool.Close()
		panic("failed to migrate test database: " + err.Error())
	}
	for _, t := range tests {
		t.Helper()
		t.Cleanup(func() {
			if err := pool.Close(); err != nil {
				t.Errorf("close test database: %v", err)
			}
		})
	}
	return db
}

func SeedTestData(db *gorm.DB) {
	role := &model.Role{ID: 1, Name: "测试管理员", Description: "测试管理员角色", Permissions: model.Permissions{"*"}}
	if err := db.Create(role).Error; err != nil {
		panic("seed test role: " + err.Error())
	}
	user := &model.User{ID: 1, Username: "testuser", Email: "test@example.com", PasswordHash: "$2a$10$example_hash", RealName: "测试用户", RoleID: 1, Status: 1}
	if err := db.Create(user).Error; err != nil {
		panic("seed test user: " + err.Error())
	}
}

// Closing the only pool discards every table and releases its memory. DELETEs
// alone kept connections alive and made cleanup depend on foreign-key ordering.
func CleanupTestData(db *gorm.DB) {
	if db == nil {
		return
	}
	pool, err := db.DB()
	if err != nil {
		panic("get test connection for cleanup: " + err.Error())
	}
	if err := pool.Close(); err != nil {
		panic("close test database: " + err.Error())
	}
}
