package service

import (
	"testing"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

func TestAssetOwnerChangeOmitsLoadedAssociation(t *testing.T) {
	db := newBusinessTestDB(t)
	oldOwner, newOwner := uint(2), uint(3)
	asset := &model.Asset{Name: "owned", Type: model.AssetTypeServer, OwnerID: &oldOwner}
	require.NoError(t, db.Create(asset).Error)
	svc := NewAssetService(repository.NewAssetRepository(db), repository.NewUserRepository(db))
	status := 0
	require.NoError(t, svc.UpdateAsset(asset.ID, &model.AssetUpdateRequest{OwnerID: &newOwner, Status: &status}))
	stored, err := repository.NewAssetRepository(db).GetByID(asset.ID)
	require.NoError(t, err)
	require.Equal(t, newOwner, *stored.OwnerID)
	require.Equal(t, newOwner, stored.Owner.ID)
	require.Zero(t, stored.Status)
	var oldUser model.User
	require.NoError(t, db.First(&oldUser, oldOwner).Error)
	require.Equal(t, "Old owner", oldUser.RealName)
}

func TestAssetDeleteRejectsReferencedAsset(t *testing.T) {
	db := newBusinessTestDB(t)
	vulnerability := seedBusinessVulnerability(t, db, "referenced")
	svc := NewAssetService(repository.NewAssetRepository(db), repository.NewUserRepository(db))
	require.ErrorContains(t, svc.DeleteAsset(vulnerability.AssetID), "关联漏洞")
	var stored model.Asset
	require.NoError(t, db.First(&stored, vulnerability.AssetID).Error)
	require.NoError(t, db.First(&model.Vulnerability{}, vulnerability.ID).Error)
	unused := &model.Asset{Name: "unused", Type: model.AssetTypeServer}
	require.NoError(t, db.Create(unused).Error)
	require.NoError(t, svc.DeleteAsset(unused.ID))
	require.Error(t, db.First(&model.Asset{}, unused.ID).Error)
}
