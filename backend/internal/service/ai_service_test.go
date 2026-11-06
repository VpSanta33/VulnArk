package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/outbound"
)

func testAIService(repo repository.AIRepository) AIService {
	saved, err := repo.GetAIConfiguration(7)
	if err != nil {
		panic(err)
	}
	policy := outbound.Policy{PrivateOrigins: []string{saved.APIURL}}
	return &aiService{aiRepo: repo, policy: policy, client: outbound.NewClient(0, policy)}
}

func newAIServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "state.db")+"?_busy_timeout=5000&_journal_mode=WAL"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), DisableForeignKeyConstraintWhenMigrating: true, IgnoreRelationshipsWhenMigrating: true,
	})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sqlDB.Close()) })
	require.NoError(t, db.AutoMigrate(&model.AIConfiguration{}, &model.AIConversation{}, &model.FileCleanupTask{}))
	return db
}

func seedAIServiceConfig(t *testing.T, db *gorm.DB, apiURL string) repository.AIRepository {
	t.Helper()
	repo := repository.NewAIRepository(db)
	require.NoError(t, repo.UpdateAIConfiguration(7, &model.AIConfigurationRequest{Provider: "openai", APIURL: apiURL, APIKey: "test", Model: "test", Timeout: 1, Enabled: true}))
	return repo
}

func TestAIServiceContentionAndHistory(t *testing.T) {
	db := newAIServiceTestDB(t)
	started, proceed := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(proceed) }) }
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
			<-proceed
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"answer"}}],"usage":{"total_tokens":3}}`))
	}))
	defer provider.Close()
	defer resume()
	repo := seedAIServiceConfig(t, db, provider.URL)
	conversation, err := repo.CreateConversation(7, "test")
	require.NoError(t, err)
	svc := testAIService(repo)
	result := make(chan error, 1)
	go func() {
		_, err := svc.SendMessage(7, &model.AIChatRequest{SessionID: conversation.SessionID, Message: "one"})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not start")
	}
	// A separate service instance must not enter the provider for the same session.
	_, err = testAIService(repository.NewAIRepository(db)).SendMessage(7, &model.AIChatRequest{SessionID: conversation.SessionID, Message: "duplicate"})
	require.ErrorIs(t, err, repository.ErrAIConversationBusy)
	require.EqualValues(t, 1, calls.Load())
	resume()
	require.NoError(t, <-result)
	_, err = svc.SendMessage(7, &model.AIChatRequest{SessionID: conversation.SessionID, Message: "two"})
	require.NoError(t, err)
	stored, err := repo.GetConversation(7, conversation.SessionID)
	require.NoError(t, err)
	var history []model.AIMessage
	require.NoError(t, json.Unmarshal([]byte(stored.Messages), &history))
	require.Len(t, history, 4)
	require.Equal(t, "one", history[0].Content)
	require.Equal(t, "two", history[2].Content)
	require.Equal(t, 6, stored.TokensUsed)
}

func TestAIServiceInflightDeleteRejectsLateResponse(t *testing.T) {
	db := newAIServiceTestDB(t)
	started, proceed := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	resume := func() { resumeOnce.Do(func() { close(proceed) }) }
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-proceed
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"late"}}],"usage":{"total_tokens":7}}`))
	}))
	defer provider.Close()
	defer resume()
	repo := seedAIServiceConfig(t, db, provider.URL)
	conversation, err := repo.CreateConversation(7, "late")
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		_, err := testAIService(repo).SendMessage(7, &model.AIChatRequest{SessionID: conversation.SessionID, Message: "delete me"})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not start")
	}
	// This write succeeds while provider I/O is blocked: there is no held tx.
	require.NoError(t, repo.DeleteConversation(7, conversation.SessionID))
	resume()
	require.ErrorIs(t, <-result, repository.ErrAILeaseLost)
	stored, err := repo.GetConversation(7, conversation.SessionID)
	require.NoError(t, err)
	require.Equal(t, "deleted", stored.Status)
	require.Equal(t, "[]", stored.Messages)
	require.Zero(t, stored.TokensUsed)
}

func TestAIServiceProviderFailureReleasesLease(t *testing.T) {
	db := newAIServiceTestDB(t)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer provider.Close()
	repo := seedAIServiceConfig(t, db, provider.URL)
	conversation, err := repo.CreateConversation(7, "error")
	require.NoError(t, err)
	_, err = testAIService(repo).SendMessage(7, &model.AIChatRequest{SessionID: conversation.SessionID, Message: "retry"})
	require.Error(t, err)
	leased, err := repo.AcquireConversation(context.Background(), 7, conversation.SessionID, time.Minute)
	require.NoError(t, err)
	require.Equal(t, "[]", leased.Messages)
	require.Zero(t, leased.TokensUsed)
}

func TestAIServiceCancellationDoesNotCommitAndReleasesLease(t *testing.T) {
	db := newAIServiceTestDB(t)
	started, finish := make(chan struct{}), make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-finish:
		}
	}))
	defer provider.Close()
	defer close(finish)
	repo := seedAIServiceConfig(t, db, provider.URL)
	conversation, err := repo.CreateConversation(7, "cancel")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := testAIService(repo).SendMessageContext(ctx, 7, &model.AIChatRequest{SessionID: conversation.SessionID, Message: "cancel"})
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("send did not stop after cancellation")
	}
	leased, err := repo.AcquireConversation(context.Background(), 7, conversation.SessionID, time.Minute)
	require.NoError(t, err)
	require.Equal(t, "[]", leased.Messages)
	require.Zero(t, leased.TokensUsed)
}

func TestAIRequestTimeoutBounds(t *testing.T) {
	for _, seconds := range []int{-1, 0, 1, 30, 120, 121, int(^uint(0) >> 1)} {
		timeout := aiRequestTimeout(seconds)
		require.Positive(t, timeout)
		require.LessOrEqual(t, timeout, maxAIRequestTimeout)
	}
}
