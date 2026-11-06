package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/auth"
	"vulnark/pkg/utils"
)

func AuthMiddleware(repo repository.UserRepository, managers ...*auth.JWTManager) gin.HandlerFunc {
	return authentication(repo, managers, false, false)
}

// MFARebindMiddleware accepts restricted rebind tokens only for the MFA routes.
func MFARebindMiddleware(repo repository.UserRepository, managers ...*auth.JWTManager) gin.HandlerFunc {
	return authentication(repo, managers, true, false)
}

func OptionalAuthMiddleware(repo repository.UserRepository, managers ...*auth.JWTManager) gin.HandlerFunc {
	return authentication(repo, managers, false, true)
}

func authentication(repo repository.UserRepository, managers []*auth.JWTManager, allowRebind, optional bool) gin.HandlerFunc {
	manager := auth.NewJWTManager()
	if len(managers) > 0 {
		manager = managers[0]
	}
	return func(c *gin.Context) {
		deny := func() {
			if !optional {
				utils.UnauthorizedResponse(c, "认证已失效，请重新登录")
				c.Abort()
			}
		}
		parts := strings.Fields(c.GetHeader("Authorization"))
		if len(parts) != 2 || parts[0] != "Bearer" || manager == nil || repo == nil {
			deny()
			return
		}
		purposes := []string{"access"}
		if allowRebind {
			purposes = append(purposes, "mfa_rebind")
		}
		claims, err := manager.ParsePurposeToken(parts[1], purposes...)
		if err != nil {
			deny()
			return
		}
		user, err := repo.GetByID(claims.UserID)
		if err != nil || !user.IsActive() || user.TokenVersion != claims.TokenVersion {
			deny()
			return
		}
		if claims.Purpose == "mfa_rebind" && !needsMFARebind(user) {
			deny()
			return
		}
		if claims.Purpose == "access" && needsMFARebind(user) {
			deny()
			return
		}
		c.Set("user_id", user.ID)
		c.Set("username", user.Username)
		c.Set("role_id", user.RoleID)
		c.Set("claims", claims)
		c.Next()
	}
}

func needsMFARebind(user *model.User) bool {
	return user.TwoFactorNeedsRebind || (user.TwoFactorEnabled && !strings.HasPrefix(user.TwoFactorSecret, "v1:"))
}

func GetCurrentUserID(c *gin.Context) (uint, bool) {
	value, exists := c.Get("user_id")
	id, ok := value.(uint)
	return id, exists && ok
}
func GetCurrentUsername(c *gin.Context) (string, bool) {
	value, exists := c.Get("username")
	name, ok := value.(string)
	return name, exists && ok
}
func GetCurrentRoleID(c *gin.Context) (uint, bool) {
	value, exists := c.Get("role_id")
	id, ok := value.(uint)
	return id, exists && ok
}
func GetCurrentClaims(c *gin.Context) (*auth.Claims, bool) {
	value, exists := c.Get("claims")
	claims, ok := value.(*auth.Claims)
	return claims, exists && ok
}
