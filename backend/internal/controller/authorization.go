package controller

import (
	"github.com/gin-gonic/gin"
	"vulnark/internal/middleware"
	"vulnark/internal/service"
	"vulnark/pkg/utils"
)

// Role assignment and permission changes use the same gate as role-permissions.
func allowPermissionChanges(ctx *gin.Context, permissions service.PermissionService) bool {
	userID, ok := middleware.GetCurrentUserID(ctx)
	if !ok || userID == 0 {
		utils.UnauthorizedResponse(ctx, "请先登录")
		return false
	}
	if permissions == nil {
		utils.ForbiddenResponse(ctx, "缺少权限分配权限")
		return false
	}
	allowed, err := permissions.CheckUserPermission(userID, "system:permission")
	if err != nil {
		utils.ServerErrorResponse(ctx, "权限检查失败")
		return false
	}
	if !allowed {
		utils.ForbiddenResponse(ctx, "缺少权限分配权限")
		return false
	}
	return true
}
