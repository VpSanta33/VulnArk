package middleware

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"vulnark/internal/model"
	"vulnark/internal/service"
)

const (
	AuditErrorContextKey     = "audit_persistence_error"
	auditWriteTimeout        = 2 * time.Second
	maxConcurrentAuditWrites = 16
)

// AuditPersistenceStats exposes counts only, never raw persistence errors or payloads.
type AuditPersistenceStats struct {
	Saved    uint64
	Failed   uint64
	Dropped  uint64
	TimedOut uint64
}

var (
	auditWriteSlots = make(chan struct{}, maxConcurrentAuditWrites)
	auditSaved      atomic.Uint64
	auditFailed     atomic.Uint64
	auditDropped    atomic.Uint64
	auditTimedOut   atomic.Uint64
)

func GetAuditPersistenceStats() AuditPersistenceStats {
	return AuditPersistenceStats{
		Saved: auditSaved.Load(), Failed: auditFailed.Load(),
		Dropped: auditDropped.Load(), TimedOut: auditTimedOut.Load(),
	}
}

// AuditMiddleware records only bounded operation metadata. Bodies, query values,
// raw paths, headers, cookies, user agents and arbitrary errors are never captured.
// The existing service has no context parameter: bound both concurrent writes and
// request wait time. A stuck service can consume at most maxConcurrentAuditWrites
// workers. Its error text is never copied to Gin errors or any external logger.
func AuditMiddleware(auditService service.AuditLogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		if skipAudit(c) {
			return
		}

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		action, resource := determineActionAndResource(c.Request.Method, route)
		auditLog := &model.AuditLog{
			CreatedAt: start,
			Action:    boundedAuditText(action, 100), Resource: boundedAuditText(resource, 100),
			Method: auditMethod(c.Request.Method), Path: boundedAuditText(route, 255),
			Status: c.Writer.Status(), Duration: time.Since(start).Milliseconds(),
		}
		if id, err := strconv.ParseUint(c.Param("id"), 10, strconv.IntSize); err == nil && id != 0 {
			resourceID := uint(id)
			auditLog.ResourceID = &resourceID
		}
		if id, exists := GetCurrentUserID(c); exists {
			auditLog.UserID = &id
			if username, exists := GetCurrentUsername(c); exists {
				auditLog.Username = boundedAuditText(username, 50)
			}
		}
		if ip := net.ParseIP(c.ClientIP()); ip != nil {
			auditLog.IP = ip.String()
		}
		if len(c.Errors) > 0 {
			auditLog.Error = "handler_error"
		}
		persistAuditLog(c, auditService, auditLog)
	}
}

func skipAudit(c *gin.Context) bool {
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		return false
	}
	path := c.Request.URL.Path
	return path == "/health" || path == "/api/health" || path == "/api/v1/public/ping" ||
		path == "/" || path == "/vite.svg" || strings.HasPrefix(path, "/assets/") ||
		(c.FullPath() == "" && !strings.HasPrefix(path, "/api"))
}

func persistAuditLog(c *gin.Context, auditService service.AuditLogService, auditLog *model.AuditLog) {
	if auditService == nil {
		auditFailed.Add(1)
		c.Set(AuditErrorContextKey, "service_unavailable")
		return
	}
	select {
	case auditWriteSlots <- struct{}{}:
	default:
		auditDropped.Add(1)
		c.Set(AuditErrorContextKey, "capacity_exhausted")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), auditWriteTimeout)
	defer cancel()
	result := make(chan bool, 1)
	go func() {
		success := false
		defer func() {
			// Persistence panics cannot escape the worker or expose their payload.
			if recover() != nil {
				success = false
			}
			if success {
				auditSaved.Add(1)
			} else {
				auditFailed.Add(1)
			}
			<-auditWriteSlots
			result <- success
		}()
		if contextual, ok := auditService.(interface {
			CreateAuditLogContext(context.Context, *model.AuditLog) error
		}); ok {
			success = contextual.CreateAuditLogContext(ctx, auditLog) == nil
		} else {
			success = auditService.CreateAuditLog(auditLog) == nil
		}
	}()
	select {
	case success := <-result:
		if !success {
			c.Set(AuditErrorContextKey, "write_failed")
		}
	case <-ctx.Done():
		auditTimedOut.Add(1)
		c.Set(AuditErrorContextKey, "write_timeout_or_cancellation")
	}
}

func boundedAuditText(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < ' ' || r == 127 {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

func auditMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

// determineActionAndResource 确定操作动作和资源
func determineActionAndResource(method, path string) (string, string) {
	// 移除API前缀
	path = strings.TrimPrefix(path, "/api/v1")

	// 分割路径
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return "unknown", "unknown"
	}

	resource := parts[0]
	action := "unknown"

	// 根据HTTP方法和路径确定动作
	switch method {
	case "GET":
		if len(parts) == 1 {
			action = "list"
		} else {
			action = "read"
		}
	case "POST":
		if len(parts) > 1 {
			// 特殊操作
			switch parts[len(parts)-1] {
			case "login":
				action = "login"
			case "logout":
				action = "logout"
			case "assign":
				action = "assign"
			case "review":
				action = "review"
			case "submit":
				action = "submit"
			case "archive":
				action = "archive"
			case "import":
				action = "import"
			case "export":
				action = "export"
			default:
				action = "create"
			}
		} else {
			action = "create"
		}
	case "PUT":
		action = "update"
	case "DELETE":
		action = "delete"
	case "PATCH":
		action = "update"
	}

	// 特殊资源处理
	switch resource {
	case "login", "logout":
		return resource, "auth"
	case "profile":
		return "read", "profile"
	case "change-password":
		return "change_password", "user"
	case "public":
		if len(parts) > 1 {
			return "read", parts[1]
		}
		return "read", "public"
	}

	// 处理嵌套资源
	if len(parts) > 2 {
		// 例如: /users/1/roles -> resource: user_roles
		if parts[2] != "" && !isNumeric(parts[1]) {
			resource = parts[0] + "_" + parts[2]
		}
	}

	return action, resource
}

// isNumeric 检查字符串是否为数字
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// RequirePermission 权限检查中间件
func RequirePermission(permissionName string, permissionService service.PermissionService) gin.HandlerFunc {
	return RequireAnyPermission([]string{permissionName}, permissionService)
}

// RequireAnyPermission允许拥有任一指定权限的已认证用户；空集合拒绝访问。
func RequireAnyPermission(permissionNames []string, permissionService service.PermissionService) gin.HandlerFunc {
	permissions := append([]string(nil), permissionNames...)
	return func(c *gin.Context) {
		userID, exists := GetCurrentUserID(c)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "未登录"})
			return
		}
		if permissionService == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "权限检查失败"})
			return
		}
		for _, permission := range permissions {
			if permission == "" {
				continue
			}
			allowed, err := permissionService.CheckUserPermission(userID, permission)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "权限检查失败"})
				return
			}
			if allowed {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "权限不足"})
	}
}

// AuditLogCleanupTask 审计日志清理任务
func AuditLogCleanupTask(auditService service.AuditLogService, configService service.SystemConfigService) {

	// 获取日志保留天数配置
	config, err := configService.GetConfigByKey("audit.log_retention_days")
	if err != nil {
		// 使用默认值90天
		auditService.CleanupOldLogs(90)
		return
	}

	days := config.Value.GetInt("value")
	if days <= 0 {
		days = 90 // 默认90天
	}

	auditService.CleanupOldLogs(days)
}
