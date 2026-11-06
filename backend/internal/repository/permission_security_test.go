package repository

import (
	"testing"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/pkg/testutil"
)

func TestPermissionsUseRoleJSONAndIgnoreLegacyAssociations(t *testing.T) {
	db := testutil.NewTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.Permission{}, &model.RolePermission{}))
	read := &model.Permission{Name: "vuln:read", DisplayName: "Read", Module: "vuln", Action: "read", Resource: "vuln", IsActive: true}
	write := &model.Permission{Name: "vuln:update", DisplayName: "Write", Module: "vuln", Action: "update", Resource: "vuln", IsActive: true}
	require.NoError(t, db.Create(read).Error)
	require.NoError(t, db.Create(write).Error)
	role := &model.Role{Name: "readonly", Permissions: model.Permissions{"vulnerability:read"}}
	require.NoError(t, db.Create(role).Error)
	user := &model.User{Username: "reader", Email: "reader@example.test", RealName: "Reader", RoleID: role.ID, Status: 1}
	require.NoError(t, db.Create(user).Error)
	require.NoError(t, db.Create(&model.RolePermission{RoleID: role.ID, PermissionID: write.ID}).Error)
	repo := NewPermissionRepository(db)
	allowed, err := repo.CheckUserPermission(user.ID, "vuln:read")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = repo.CheckUserPermission(user.ID, "vulnerability:update")
	require.NoError(t, err)
	require.False(t, allowed)
	permissions, err := repo.GetUserPermissions(user.ID)
	require.NoError(t, err)
	require.Len(t, permissions, 1)
	require.Equal(t, read.ID, permissions[0].ID)

	rolePermissions := NewRolePermissionRepository(db)
	require.NoError(t, rolePermissions.AssignPermissions(role.ID, []uint{write.ID}))
	permissions, err = rolePermissions.GetRolePermissions(role.ID)
	require.NoError(t, err)
	require.Len(t, permissions, 1)
	require.Equal(t, write.ID, permissions[0].ID)
	allowed, err = repo.CheckUserPermission(user.ID, "vuln:read")
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = repo.CheckUserPermission(user.ID, "vulnerability:update")
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, rolePermissions.AssignPermissions(role.ID, []uint{}))
	allowed, err = repo.CheckUserPermission(user.ID, "vuln:update")
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestRoleMetadataUpdatePreservesRevocations(t *testing.T) {
	db := testutil.NewTestDB(t)
	role := &model.Role{Name: "operator", Permissions: model.Permissions{"*"}}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, NewRolePermissionRepository(db).ClearRolePermissions(role.ID))
	repo := NewRoleRepository(db)
	require.NoError(t, repo.Update(&model.Role{ID: role.ID, Description: "metadata only"}))
	stored, err := repo.GetByID(role.ID)
	require.NoError(t, err)
	require.Empty(t, stored.Permissions)
	require.Equal(t, "metadata only", stored.Description)
	require.NoError(t, repo.Update(&model.Role{ID: role.ID, Permissions: model.Permissions{"vuln:read"}}))
	require.NoError(t, repo.Update(&model.Role{ID: role.ID, Permissions: model.Permissions{}}))
	stored, err = repo.GetByID(role.ID)
	require.NoError(t, err)
	require.Empty(t, stored.Permissions)
	require.NoError(t, db.Delete(role).Error)
	require.NoError(t, repo.Update(&model.Role{ID: role.ID, Description: "must not recreate"}))
	var count int64
	require.NoError(t, db.Model(&model.Role{}).Where("id = ?", role.ID).Count(&count).Error)
	require.Zero(t, count)
}

func TestRolePermissionReplaceIsAtomic(t *testing.T) {
	db := testutil.NewTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.Permission{}))
	role := &model.Role{Name: "readonly", Permissions: model.Permissions{"vuln:read"}}
	require.NoError(t, db.Create(role).Error)
	err := NewRolePermissionRepository(db).AssignPermissions(role.ID, []uint{999})
	require.Error(t, err)
	stored, err := NewRoleRepository(db).GetByID(role.ID)
	require.NoError(t, err)
	require.Equal(t, model.Permissions{"vuln:read"}, stored.Permissions)
}
