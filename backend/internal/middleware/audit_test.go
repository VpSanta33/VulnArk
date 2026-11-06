package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"vulnark/internal/model"
	"vulnark/internal/service"
)

type auditTestService struct {
	service.AuditLogService
	create func(*model.AuditLog) error
}

func (s *auditTestService) CreateAuditLog(log *model.AuditLog) error { return s.create(log) }

type unreadableAuditBody struct{ reads int }

func (body *unreadableAuditBody) Read([]byte) (int, error) {
	body.reads++
	return 0, errors.New("audit must never read this body")
}
func (*unreadableAuditBody) Close() error { return nil }

func TestAuditDoesNotReadRequestOrWrapResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var saved *model.AuditLog
	auditService := &auditTestService{create: func(log *model.AuditLog) error { saved = log; return nil }}
	router := gin.New()
	var originalWriter gin.ResponseWriter
	router.Use(func(c *gin.Context) { originalWriter = c.Writer; c.Next() })
	router.Use(AuditMiddleware(auditService))
	body := &unreadableAuditBody{}
	router.POST("/api/v1/upload", func(c *gin.Context) {
		if c.Writer != originalWriter {
			t.Error("audit wrapped response writer")
		}
		if c.Request.Body != body {
			t.Error("audit replaced request body")
		}
		c.String(http.StatusCreated, "response-mfa-token-secret")
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", nil)
	request.Body = body
	request.ContentLength = 1 << 40
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if body.reads != 0 {
		t.Fatalf("audit read large request body %d times", body.reads)
	}
	if response.Code != http.StatusCreated || response.Body.String() != "response-mfa-token-secret" {
		t.Fatal("audit changed response")
	}
	if saved == nil || saved.Request != "" || saved.Response != "" {
		t.Fatal("audit captured body")
	}
}

func TestAuditRecordsNumericResourceIDOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, id := range []string{"42", "secret-in-path", "0"} {
		t.Run(id, func(t *testing.T) {
			var saved *model.AuditLog
			router := gin.New()
			router.Use(AuditMiddleware(&auditTestService{create: func(log *model.AuditLog) error { saved = log; return nil }}))
			router.PUT("/api/v1/assets/:id", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/api/v1/assets/"+id, nil))
			if saved == nil {
				t.Fatal("audit not saved")
			}
			if id == "42" {
				if saved.ResourceID == nil || *saved.ResourceID != 42 {
					t.Fatal("numeric resource ID missing")
				}
			} else if saved.ResourceID != nil {
				t.Fatal("invalid resource ID was stored")
			}
			if saved.Path != "/api/v1/assets/:id" {
				t.Fatal("raw path was stored")
			}
		})
	}
}

func TestAuditMetadataExcludesSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const marker = "secret-marker-must-never-be-audited"
	var saved *model.AuditLog
	auditService := &auditTestService{create: func(log *model.AuditLog) error { saved = log; return nil }}
	router := gin.New()
	router.Use(AuditMiddleware(auditService))
	router.POST("/api/v1/users/:token/mfa", func(c *gin.Context) {
		c.Set("user_id", uint(7))
		c.Set("username", "authenticated-user")
		body, err := io.ReadAll(c.Request.Body)
		if err != nil || !strings.Contains(string(body), marker) {
			t.Error("handler did not receive intact body")
		}
		_ = c.Error(errors.New("handler error contains password " + marker))
		c.JSON(http.StatusBadRequest, gin.H{"token": marker, "mfa_secret": marker, "api_key": marker})
	})
	payload := `{"password":"` + marker + `","token":"` + marker + `","mfa_secret":"` + marker + `","api_key":"` + marker + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+marker+"/mfa?token="+marker, strings.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+marker)
	request.Header.Set("Cookie", "session="+marker)
	request.Header.Set("User-Agent", marker)
	request.Header.Set("X-API-Key", marker)
	request.RemoteAddr = "192.0.2.10:4567"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if saved == nil {
		t.Fatal("audit was not persisted before response returned")
	}
	encoded, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), marker) {
		t.Fatalf("secret leaked into audit record: %s", encoded)
	}
	if saved.Path != "/api/v1/users/:token/mfa" || saved.Method != http.MethodPost || saved.Status != http.StatusBadRequest || saved.IP != "192.0.2.10" {
		t.Fatalf("unexpected audit metadata: %+v", saved)
	}
	if saved.UserID == nil || *saved.UserID != 7 || saved.Username != "authenticated-user" {
		t.Fatal("authenticated identity metadata missing")
	}
	if saved.Error != "handler_error" || saved.UserAgent != "" || saved.Request != "" || saved.Response != "" {
		t.Fatal("unbounded data copied to audit")
	}
}

func TestAuditUnknownRouteDoesNotStoreRawPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var saved *model.AuditLog
	router := gin.New()
	router.Use(AuditMiddleware(&auditTestService{create: func(log *model.AuditLog) error { saved = log; return nil }}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/unknown/password-in-path?api_key=query-secret", nil))
	if saved == nil || saved.Path != "unmatched" {
		t.Fatalf("raw unknown path captured: %+v", saved)
	}
}

func TestAuditFailureIsObservableWithoutErrorDisclosure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	before := GetAuditPersistenceStats()
	const secret = "database-error-containing-api-key"
	var code any
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Next(); code, _ = c.Get(AuditErrorContextKey) })
	router.Use(AuditMiddleware(&auditTestService{create: func(*model.AuditLog) error { return errors.New(secret) }}))
	router.GET("/ok", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ok", nil))
	if response.Code != http.StatusNoContent || code != "write_failed" {
		t.Fatalf("failure not safely observed: %d %v", response.Code, code)
	}
	if strings.Contains(response.Body.String(), secret) {
		t.Fatal("persistence error disclosed")
	}
	if got := GetAuditPersistenceStats().Failed; got != before.Failed+1 {
		t.Fatal("failed audit count not incremented")
	}
}

func TestAuditPersistencePanicIsContained(t *testing.T) {
	gin.SetMode(gin.TestMode)
	before := GetAuditPersistenceStats()
	var code any
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Next(); code, _ = c.Get(AuditErrorContextKey) })
	router.Use(AuditMiddleware(&auditTestService{create: func(*model.AuditLog) error { panic("private database credential") }}))
	router.GET("/panic", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if response.Code != http.StatusNoContent || code != "write_failed" {
		t.Fatalf("panic was not safely contained: %d %v", response.Code, code)
	}
	if GetAuditPersistenceStats().Failed != before.Failed+1 {
		t.Fatal("panic not counted as persistence failure")
	}
}

func TestAuditRequestWaitIsBoundedWhenServiceStalls(t *testing.T) {
	gin.SetMode(gin.TestMode)
	release := make(chan struct{})
	finished := make(chan struct{})
	auditService := &auditTestService{create: func(*model.AuditLog) error { defer close(finished); <-release; return nil }}
	defer func() {
		close(release)
		<-finished
		deadline := time.Now().Add(time.Second)
		for len(auditWriteSlots) != 0 {
			if time.Now().After(deadline) {
				t.Error("stalled audit worker did not release slot")
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	var code any
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Next(); code, _ = c.Get(AuditErrorContextKey) })
	router.Use(AuditMiddleware(auditService))
	router.GET("/stall", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	response := httptest.NewRecorder()
	start := time.Now()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/stall", nil))
	if elapsed := time.Since(start); elapsed > auditWriteTimeout+time.Second {
		t.Fatalf("request exceeded bounded audit wait: %s", elapsed)
	}
	if code != "write_timeout_or_cancellation" || response.Code != http.StatusNoContent {
		t.Fatalf("stalled audit affected response: %d %v", response.Code, code)
	}
}

func TestAuditPersistenceConcurrencyIsBoundedAndCancellationReturns(t *testing.T) {
	gin.SetMode(gin.TestMode)
	release := make(chan struct{})
	entered := make(chan struct{}, maxConcurrentAuditWrites)
	var workers sync.WaitGroup
	workers.Add(maxConcurrentAuditWrites)
	var releaseOnce sync.Once
	cleanup := func() { releaseOnce.Do(func() { close(release) }); workers.Wait() }
	defer cleanup()
	auditService := &auditTestService{create: func(*model.AuditLog) error {
		defer workers.Done()
		entered <- struct{}{}
		<-release
		return nil
	}}
	var code any
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Next(); code, _ = c.Get(AuditErrorContextKey) })
	router.Use(AuditMiddleware(auditService))
	router.GET("/bounded", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	before := GetAuditPersistenceStats()
	for i := 0; i < maxConcurrentAuditWrites; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		request := httptest.NewRequest(http.MethodGet, "/bounded", nil).WithContext(ctx)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("audit worker did not enter")
		}
		if code != "write_timeout_or_cancellation" {
			t.Fatalf("cancellation not observed: %v", code)
		}
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bounded", nil))
	if code != "capacity_exhausted" {
		t.Fatalf("extra audit worker admitted: %v", code)
	}
	after := GetAuditPersistenceStats()
	if after.Dropped != before.Dropped+1 || after.TimedOut != before.TimedOut+maxConcurrentAuditWrites {
		t.Fatalf("unexpected audit counts: before %+v after %+v", before, after)
	}
	cleanup()
	// Wait until the slot-release defer has completed, rather than relying on sleeps.
	deadline := time.Now().Add(time.Second)
	for len(auditWriteSlots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("audit slots not released")
		}
		time.Sleep(time.Millisecond)
	}
}

type contextualAuditTestService struct {
	auditTestService
	called bool
}

func (s *contextualAuditTestService) CreateAuditLogContext(ctx context.Context, _ *model.AuditLog) error {
	s.called = true
	return nil
}

func TestAuditUsesContextAwareServiceWhenAvailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &contextualAuditTestService{auditTestService: auditTestService{create: func(*model.AuditLog) error { t.Error("context-aware method bypassed"); return nil }}}
	router := gin.New()
	router.Use(AuditMiddleware(s))
	router.GET("/context", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/context", nil))
	if !s.called {
		t.Fatal("context-aware audit service was not used")
	}
}

type permissionTestService struct {
	service.PermissionService
	allowed map[string]bool
	err     error
}

func (s *permissionTestService) CheckUserPermission(_ uint, permission string) (bool, error) {
	return s.allowed[permission], s.err
}

func TestRequireAnyPermissionAndExistingSinglePermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name        string
		signedIn    bool
		permissions []string
		allowed     map[string]bool
		err         error
		want        int
	}{
		{"unauthenticated", false, []string{"read"}, map[string]bool{"read": true}, nil, http.StatusUnauthorized},
		{"second permission", true, []string{"read", "write"}, map[string]bool{"write": true}, nil, http.StatusNoContent},
		{"no permission", true, []string{"read"}, nil, nil, http.StatusForbidden},
		{"empty set", true, nil, nil, nil, http.StatusForbidden},
		{"service error", true, []string{"read"}, nil, errors.New("secret permission error"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				if tc.signedIn {
					c.Set("user_id", uint(1))
				}
				c.Next()
			})
			router.GET("/permissions", RequireAnyPermission(tc.permissions, &permissionTestService{allowed: tc.allowed, err: tc.err}), func(c *gin.Context) { c.Status(http.StatusNoContent) })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/permissions", nil))
			if response.Code != tc.want {
				t.Fatalf("got %d, want %d", response.Code, tc.want)
			}
		})
	}
	_ = RequirePermission("read", &permissionTestService{})
}

func TestAuditSkipsStaticAndHealthButKeepsBusinessRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/health", false}, {"GET", "/api/health", false}, {"GET", "/api/v1/public/ping", false},
		{"GET", "/", false}, {"GET", "/assets/app.js", false}, {"GET", "/unknown/spa-page", false},
		{"GET", "/api/v1/assets", true}, {"POST", "/health", true}, {"GET", "/api/v1/unknown", true},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			saved := false
			router := gin.New()
			router.Use(AuditMiddleware(&auditTestService{create: func(*model.AuditLog) error { saved = true; return nil }}))
			router.GET("/health", func(c *gin.Context) { c.Status(200) })
			router.GET("/api/v1/assets", func(c *gin.Context) { c.Status(200) })
			router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.path, nil))
			if saved != tc.want {
				t.Fatalf("audited=%v, want %v", saved, tc.want)
			}
		})
	}
}
