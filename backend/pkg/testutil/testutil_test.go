package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
)

func TestNewTestDBIsolatesMemoryAndClosesAtCleanup(t *testing.T) {
	first := NewTestDB(t)
	second := NewTestDB(t)
	SeedTestData(first)
	var count int64
	require.NoError(t, second.Model(&model.User{}).Count(&count).Error)
	require.Zero(t, count)
	pool, err := first.DB()
	require.NoError(t, err)
	require.Equal(t, 1, pool.Stats().MaxOpenConnections)
	CleanupTestData(first)
	require.Error(t, pool.Ping())
	// Closing an independent database cannot destroy another fixture.
	SeedTestData(second)
	require.NoError(t, second.Model(&model.User{}).Count(&count).Error)
	require.EqualValues(t, 1, count)
}

func TestNewTestDBRegistersAutomaticClose(t *testing.T) {
	var ping func() error
	t.Run("fixture", func(t *testing.T) {
		db := NewTestDB(t)
		pool, err := db.DB()
		require.NoError(t, err)
		ping = pool.Ping
		require.NoError(t, ping())
	})
	require.Error(t, ping())
}
