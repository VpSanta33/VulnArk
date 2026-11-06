package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/pkg/testutil"
)

func newBusinessTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := testutil.NewTestDB()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&model.VulnerabilityAssignment{}, &model.VulnerabilityTimeline{}, &model.AssignmentRule{}, &model.KnowledgeBase{}, &model.Tag{}, &model.KnowledgeTag{}))
	role := &model.Role{ID: 1, Name: "business-test", Permissions: model.Permissions{"*"}}
	require.NoError(t, db.Create(role).Error)
	for _, user := range []model.User{
		{ID: 1, Username: "operator", Email: "operator@example.com", RealName: "Operator", PasswordHash: "hash", RoleID: 1},
		{ID: 2, Username: "old", Email: "old@example.com", RealName: "Old owner", PasswordHash: "hash", RoleID: 1},
		{ID: 3, Username: "new", Email: "new@example.com", RealName: "New owner", PasswordHash: "hash", RoleID: 1},
	} {
		require.NoError(t, db.Create(&user).Error)
	}
	return db
}

func seedBusinessVulnerability(t *testing.T, db *gorm.DB, name string) *model.Vulnerability {
	t.Helper()
	asset := &model.Asset{Name: name, Type: model.AssetTypeServer}
	require.NoError(t, db.Create(asset).Error)
	oldOwner := uint(2)
	vulnerability := &model.Vulnerability{Title: name, AssetID: asset.ID, SeverityLevel: 2, Status: model.StatusNew, AssigneeID: &oldOwner}
	require.NoError(t, db.Create(vulnerability).Error)
	return vulnerability
}

func businessRowCount(t *testing.T, db *gorm.DB, row interface{}) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(row).Count(&count).Error)
	return count
}

func failBusinessCreate(t *testing.T, db *gorm.DB, table string) {
	t.Helper()
	name := "test:fail:" + table
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Table == table {
			tx.AddError(errors.New("injected " + table + " failure"))
		}
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Create().Remove(name)) })
}
