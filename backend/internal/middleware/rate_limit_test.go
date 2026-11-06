package middleware

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type limiterTestClock struct {
	mutex sync.Mutex
	now   time.Time
}

func newLimiterTestClock() *limiterTestClock { return &limiterTestClock{now: time.Unix(1700000000, 0)} }
func (c *limiterTestClock) Now() time.Time   { c.mutex.Lock(); defer c.mutex.Unlock(); return c.now }
func (c *limiterTestClock) Advance(d time.Duration) {
	c.mutex.Lock()
	c.now = c.now.Add(d)
	c.mutex.Unlock()
}

func TestTokenBucketPreservesFractionalRefillUnderFrequentRequests(t *testing.T) {
	clock := newLimiterTestClock()
	limiter := NewTokenBucketLimiterWithClock(5.0/60.0, 10, clock.Now)
	for i := 0; i < 10; i++ {
		if !limiter.Allow("login") {
			t.Fatal("initial capacity not available")
		}
	}
	for i := 0; i < 119; i++ {
		clock.Advance(100 * time.Millisecond)
		if limiter.Allow("login") {
			t.Fatalf("login token refilled early at step %d", i)
		}
	}
	clock.Advance(100 * time.Millisecond)
	if !limiter.Allow("login") {
		t.Fatal("fractional refill was lost at twelve-second boundary")
	}
	if limiter.Allow("login") {
		t.Fatal("refill exceeded one token")
	}
}

func TestLoginAndUploadRatesArePerMinute(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rate     float64
		capacity int
		interval time.Duration
	}{
		{"login", loginLimiter.rate, loginLimiter.capacity, 12 * time.Second},
		{"upload", uploadLimiter.rate, uploadLimiter.capacity, 6 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newLimiterTestClock()
			limiter := NewTokenBucketLimiterWithClock(tc.rate, tc.capacity, clock.Now)
			for i := 0; i < tc.capacity; i++ {
				if !limiter.Allow("key") {
					t.Fatal("incorrect capacity")
				}
			}
			if limiter.Allow("key") {
				t.Fatal("bucket overflow")
			}
			clock.Advance(time.Second)
			if limiter.Allow("key") {
				t.Fatal("rate interpreted per second")
			}
			clock.Advance(tc.interval - time.Second)
			if !limiter.Allow("key") {
				t.Fatal("minute refill failed")
			}
			clock.Advance(time.Hour)
			for i := 0; i < tc.capacity; i++ {
				if !limiter.Allow("key") {
					t.Fatal("full refill failed")
				}
			}
			if limiter.Allow("key") {
				t.Fatal("capacity exceeded after long idle")
			}
		})
	}
	if loginLimiter.capacity != 10 || uploadLimiter.capacity != 20 {
		t.Fatal("incorrect security limiter capacities")
	}
}

func TestTokenBucketKeysResetClockAndCapacity(t *testing.T) {
	clock := newLimiterTestClock()
	limiter := NewTokenBucketLimiterWithClock(1, 1, clock.Now)
	if !limiter.Allow("one") || !limiter.Allow("two") {
		t.Fatal("keys unexpectedly share capacity")
	}
	if limiter.Allow("one") {
		t.Fatal("exhausted key allowed")
	}
	clock.Advance(-time.Minute)
	if limiter.Allow("one") {
		t.Fatal("backward clock created tokens")
	}
	clock.Advance(time.Minute + time.Second)
	if !limiter.Allow("one") {
		t.Fatal("refill after backward clock failed")
	}
	limiter.Reset("one")
	if !limiter.Allow("one") {
		t.Fatal("reset failed")
	}
}

func TestTokenBucketConcurrentCapacity(t *testing.T) {
	clock := newLimiterTestClock()
	limiter := NewTokenBucketLimiterWithClock(1, 10, clock.Now)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Allow("same") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 10 {
		t.Fatalf("concurrent capacity got %d, want 10", got)
	}
}

func TestTokenBucketCleanupAndMemoryBound(t *testing.T) {
	clock := newLimiterTestClock()
	limiter := NewTokenBucketLimiterWithClock(1, 1, clock.Now)
	for i := 0; i < maxLimiterBuckets; i++ {
		if !limiter.Allow(strconv.Itoa(i)) {
			t.Fatal("capacity reached early")
		}
	}
	if limiter.Allow("overflow") {
		t.Fatal("bucket memory bound not enforced")
	}
	clock.Advance(bucketIdleTimeout + time.Second)
	if !limiter.Allow("new") {
		t.Fatal("lazy cleanup did not reclaim expired buckets")
	}
	if len(limiter.buckets) != 1 {
		t.Fatalf("expired buckets remain: %d", len(limiter.buckets))
	}

	slow := NewTokenBucketLimiterWithClock(1.0/3600.0, 1, clock.Now)
	if !slow.Allow("slow") {
		t.Fatal("slow bucket capacity missing")
	}
	clock.Advance(11 * time.Minute)
	slow.cleanup()
	if slow.Allow("slow") {
		t.Fatal("cleanup reset bucket before complete refill")
	}
}

func TestRateLimitRetryAfterUsesActualRefillTime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	clock := newLimiterTestClock()
	limiter := NewTokenBucketLimiterWithClock(5.0/60.0, 1, clock.Now)
	router := gin.New()
	router.GET("/login", RateLimitMiddleware(limiter, func(*gin.Context) string { return "key" }), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login", nil))
		return response
	}
	if got := request().Code; got != http.StatusNoContent {
		t.Fatalf("first request: %d", got)
	}
	response := request()
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "12" {
		t.Fatalf("unexpected rate limit: %d %v", response.Code, response.Header())
	}
	clock.Advance(time.Second)
	if got := request().Header().Get("Retry-After"); got != "11" {
		t.Fatalf("Retry-After got %s", got)
	}
	clock.Advance(11 * time.Second)
	if got := request().Code; got != http.StatusNoContent {
		t.Fatalf("refilled request: %d", got)
	}
}

func TestRateLimitWrappersAreReadyBeforeFirstRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		handler gin.HandlerFunc
	}{
		{"global", GlobalRateLimit()}, {"api", APIRateLimit()},
		{"login", LoginRateLimit()}, {"upload", UploadRateLimit()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/ready", tc.handler, func(c *gin.Context) { c.Status(http.StatusNoContent) })
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/ready", nil)
			request.RemoteAddr = "192.0.2.19:1234"
			switch tc.name {
			case "global":
				globalLimiter.Reset("192.0.2.19")
			case "api":
				apiLimiter.Reset("192.0.2.19:/ready")
			case "login":
				loginLimiter.Reset("login:192.0.2.19")
			case "upload":
				uploadLimiter.Reset("upload:ip:192.0.2.19")
			}
			router.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent {
				t.Fatalf("uninitialized wrapper: %d", response.Code)
			}
		})
	}
}

func TestLimiterCleanupStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finished := make(chan struct{})
	go func() {
		runLimiterCleanup(ctx, time.Hour, func() { t.Error("cleanup ran after cancellation") })
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not stop")
	}
	// Both old and new public call forms remain valid.
	StartCleanupRoutine()
	StartCleanupRoutine(ctx)
}

func TestInvalidRateLimiterFailsClosed(t *testing.T) {
	for _, rate := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		if NewTokenBucketLimiter(rate, 1).Allow("key") {
			t.Fatal("invalid rate allowed request")
		}
	}
	var absent *TokenBucketLimiter
	if absent.Allow("key") {
		t.Fatal("nil limiter allowed request")
	}
}
