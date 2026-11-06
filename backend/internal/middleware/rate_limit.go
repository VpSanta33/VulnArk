package middleware

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"vulnark/pkg/utils"
)

const (
	bucketIdleTimeout = 10 * time.Minute
	maxLimiterBuckets = 10000
)

// RateLimiter 速率限制器接口。
type RateLimiter interface {
	Allow(key string) bool
	Reset(key string)
}

// TokenBucketLimiter 使用每秒的浮点速率，保留请求间积累的小数令牌。
// 同一个锁保护查找、取令牌和清理，避免清理与正在使用的桶发生竞争。
type TokenBucketLimiter struct {
	rate        float64
	capacity    int
	buckets     map[string]*TokenBucket
	mutex       sync.Mutex
	clock       func() time.Time
	nextCleanup time.Time
}

type TokenBucket struct {
	tokens   float64
	lastTime time.Time
}

func NewTokenBucketLimiter(rate float64, capacity int) *TokenBucketLimiter {
	return NewTokenBucketLimiterWithClock(rate, capacity, time.Now)
}

// NewTokenBucketLimiterWithClock 允许测试控制时间；clock必须支持并发调用。
// 非正数或非有限速率、非正数容量会创建拒绝所有请求的限制器。
func NewTokenBucketLimiterWithClock(rate float64, capacity int, clock func() time.Time) *TokenBucketLimiter {
	if clock == nil {
		clock = time.Now
	}
	if rate <= 0 || math.IsNaN(rate) || math.IsInf(rate, 0) || capacity <= 0 {
		rate, capacity = 0, 0
	}
	return &TokenBucketLimiter{
		rate: rate, capacity: capacity,
		buckets: make(map[string]*TokenBucket), clock: clock,
	}
}

func (tbl *TokenBucketLimiter) Allow(key string) bool {
	allowed, _ := tbl.allow(key)
	return allowed
}

func (tbl *TokenBucketLimiter) allow(key string) (bool, time.Duration) {
	if tbl == nil || tbl.rate <= 0 || tbl.capacity <= 0 {
		return false, time.Minute
	}
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()
	now := tbl.clock()
	if tbl.nextCleanup.IsZero() || !now.Before(tbl.nextCleanup) {
		tbl.cleanupLocked(now)
		tbl.nextCleanup = now.Add(time.Minute)
	}
	bucket, exists := tbl.buckets[key]
	if !exists {
		// Bound memory even when a caller supplies attacker-controlled keys.
		if len(tbl.buckets) >= maxLimiterBuckets {
			return false, time.Minute
		}
		bucket = &TokenBucket{tokens: float64(tbl.capacity), lastTime: now}
		tbl.buckets[key] = bucket
	}
	if now.After(bucket.lastTime) {
		bucket.tokens = math.Min(float64(tbl.capacity), bucket.tokens+now.Sub(bucket.lastTime).Seconds()*tbl.rate)
		bucket.lastTime = now
	}
	// Small floating-point roundoff must not delay an exact refill boundary.
	if bucket.tokens+1e-9 >= 1 {
		bucket.tokens = math.Max(0, bucket.tokens-1)
		return true, 0
	}
	return false, time.Duration(math.Ceil((1 - bucket.tokens) / tbl.rate * float64(time.Second)))
}

func (tbl *TokenBucketLimiter) Reset(key string) {
	if tbl == nil {
		return
	}
	tbl.mutex.Lock()
	delete(tbl.buckets, key)
	tbl.mutex.Unlock()
}

func (tbl *TokenBucketLimiter) cleanupLocked(now time.Time) {
	for key, bucket := range tbl.buckets {
		idle := now.Sub(bucket.lastTime)
		// Eviction must not reset a slowly refilling bucket before it is full.
		if idle >= bucketIdleTimeout && idle.Seconds()*tbl.rate >= float64(tbl.capacity) {
			delete(tbl.buckets, key)
		}
	}
}

func (tbl *TokenBucketLimiter) cleanup() {
	if tbl == nil {
		return
	}
	tbl.mutex.Lock()
	tbl.cleanupLocked(tbl.clock())
	tbl.mutex.Unlock()
}

// Eager construction prevents wrapper functions from capturing a nil limiter.
var (
	globalLimiter = NewTokenBucketLimiter(100, 200)
	apiLimiter    = NewTokenBucketLimiter(50, 100)
	loginLimiter  = NewTokenBucketLimiter(5.0/60.0, 10)
	uploadLimiter = NewTokenBucketLimiter(10.0/60.0, 20)
)

func RateLimitMiddleware(limiter *TokenBucketLimiter, keyFunc func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP()
		if keyFunc != nil {
			key = keyFunc(c)
		}
		allowed, retry := limiter.allow(key)
		if !allowed {
			capacity := 0
			if limiter != nil {
				capacity = limiter.capacity
			}
			c.Header("X-RateLimit-Limit", strconv.Itoa(capacity))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("Retry-After", strconv.Itoa(int(math.Max(1, math.Ceil(retry.Seconds())))))
			utils.TooManyRequestsResponse(c, "请求过于频繁，请稍后再试")
			c.Abort()
			return
		}
		c.Next()
	}
}

func GlobalRateLimit() gin.HandlerFunc {
	return RateLimitMiddleware(globalLimiter, func(c *gin.Context) string { return c.ClientIP() })
}

func APIRateLimit() gin.HandlerFunc {
	return RateLimitMiddleware(apiLimiter, func(c *gin.Context) string {
		return c.ClientIP() + ":" + rateLimitRoute(c)
	})
}

func LoginRateLimit() gin.HandlerFunc {
	return RateLimitMiddleware(loginLimiter, func(c *gin.Context) string { return "login:" + c.ClientIP() })
}

func UploadRateLimit() gin.HandlerFunc {
	return RateLimitMiddleware(uploadLimiter, func(c *gin.Context) string {
		if userID, exists := GetCurrentUserID(c); exists {
			return fmt.Sprintf("upload:user:%d", userID)
		}
		return "upload:ip:" + c.ClientIP()
	})
}

// UserBasedRateLimit、IPBasedRateLimit、EndpointRateLimit保持原接口，rate单位为每秒。
func UserBasedRateLimit(rate, capacity int) gin.HandlerFunc {
	return RateLimitMiddleware(NewTokenBucketLimiter(float64(rate), capacity), func(c *gin.Context) string {
		if userID, exists := GetCurrentUserID(c); exists {
			return fmt.Sprintf("user:%d", userID)
		}
		return "ip:" + c.ClientIP()
	})
}

func IPBasedRateLimit(rate, capacity int) gin.HandlerFunc {
	return RateLimitMiddleware(NewTokenBucketLimiter(float64(rate), capacity), func(c *gin.Context) string { return c.ClientIP() })
}

func EndpointRateLimit(rate, capacity int) gin.HandlerFunc {
	return RateLimitMiddleware(NewTokenBucketLimiter(float64(rate), capacity), func(c *gin.Context) string {
		return c.Request.Method + ":" + rateLimitRoute(c)
	})
}

func rateLimitRoute(c *gin.Context) string {
	if route := c.FullPath(); route != "" {
		return route
	}
	return "unmatched"
}

func CleanupExpiredBuckets() {
	for _, limiter := range []*TokenBucketLimiter{globalLimiter, apiLimiter, loginLimiter, uploadLimiter} {
		limiter.cleanup()
	}
}

// StartCleanupRoutine接受主程序的生命周期context；无参旧调用只执行一次清理。
// 每个限制器也会惰性清理，因此无参调用不会留下无法停止的后台协程。
func StartCleanupRoutine(contexts ...context.Context) {
	if len(contexts) == 0 || contexts[0] == nil {
		CleanupExpiredBuckets()
		return
	}
	ctx := contexts[0]
	if ctx.Err() != nil {
		return
	}
	go runLimiterCleanup(ctx, 5*time.Minute, CleanupExpiredBuckets)
}

func runLimiterCleanup(ctx context.Context, interval time.Duration, cleanup func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			cleanup()
		}
	}
}
