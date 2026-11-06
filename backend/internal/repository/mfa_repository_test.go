package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/pkg/testutil"
)

func TestCleanupMFAChallengesIsBoundedAndContextAware(t *testing.T) {
	db := testutil.NewTestDB(t)
	repo := NewUserRepository(db)
	now := time.Now()
	for i := 0; i < 5; i++ {
		require.NoError(t, db.Create(&model.MFAChallenge{ID: fmt.Sprintf("expired-%d", i), TokenHash: fmt.Sprintf("expired-token-%d", i), UserID: 1, TokenVersion: 1, ExpiresAt: now.Add(-time.Hour)}).Error)
	}
	for i := 0; i < 2; i++ {
		require.NoError(t, db.Create(&model.MFAChallenge{ID: fmt.Sprintf("live-%d", i), TokenHash: fmt.Sprintf("live-token-%d", i), UserID: 1, TokenVersion: 1, ExpiresAt: now.Add(time.Hour)}).Error)
	}
	removed, err := repo.CleanupMFAChallenges(context.Background(), now, 2)
	require.NoError(t, err)
	require.Equal(t, int64(2), removed)
	var remaining int64
	require.NoError(t, db.Model(&model.MFAChallenge{}).Where("expires_at < ?", now).Count(&remaining).Error)
	require.Equal(t, int64(3), remaining)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = repo.CleanupMFAChallenges(ctx, now, 2)
	require.ErrorIs(t, err, context.Canceled)
	_, err = repo.CleanupMFAChallenges(context.Background(), now, 0)
	require.Error(t, err)
}

func TestMFAProofRollbackAndConcurrentRecoveryUse(t *testing.T) {
	db := testutil.NewTestDB(t)
	role := &model.Role{Name: "reader"}
	require.NoError(t, db.Create(role).Error)
	hashes, _ := json.Marshal([]string{"one-time-recovery-hash"})
	user := &model.User{Username: "alice", Email: "alice@example.test", RealName: "Alice", RoleID: role.ID, Status: 1, TokenVersion: 1, TwoFactorEnabled: true, TwoFactorSecret: "v1:encrypted", TwoFactorLastUsedStep: 100, TwoFactorRecoveryCodes: string(hashes)}
	require.NoError(t, db.Create(user).Error)
	repo := NewUserRepository(db)
	// An invalid challenge rolls back consumption of an otherwise valid code.
	err := repo.UseMFAProof(user.ID, 1, "missing-challenge", 101, "", false)
	require.Error(t, err)
	stored, err := repo.GetByID(user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(100), stored.TwoFactorLastUsedStep)
	err = repo.UseMFAProof(user.ID, 1, "missing-challenge", -1, "one-time-recovery-hash", false)
	require.Error(t, err)
	stored, err = repo.GetByID(user.ID)
	require.NoError(t, err)
	require.Equal(t, string(hashes), stored.TwoFactorRecoveryCodes)

	for _, hash := range []string{"challenge-a", "challenge-b"} {
		require.NoError(t, repo.CreateMFAChallenge(&model.MFAChallenge{ID: hash, TokenHash: hash, UserID: user.ID, TokenVersion: 1, ExpiresAt: time.Now().Add(time.Minute)}))
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, hash := range []string{"challenge-a", "challenge-b"} {
		wg.Add(1)
		go func(hash string) {
			defer wg.Done()
			results <- repo.UseMFAProof(user.ID, 1, hash, -1, "one-time-recovery-hash", false)
		}(hash)
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	stored, err = repo.GetByID(user.ID)
	require.NoError(t, err)
	require.Equal(t, "[]", stored.TwoFactorRecoveryCodes)
}
