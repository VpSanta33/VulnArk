package controller

import (
	"github.com/gin-gonic/gin"
	"vulnark/internal/middleware"
	"vulnark/internal/model"
	"vulnark/internal/service"
	"vulnark/pkg/utils"
)

// SettingsController 设置控制器
type SettingsController struct {
	settingsService service.SettingsService
}

// NewSettingsController 创建设置控制器
func NewSettingsController(settingsService service.SettingsService) *SettingsController {
	return &SettingsController{
		settingsService: settingsService,
	}
}

// UpdateProfile 更新用户资料
// @Summary 更新用户资料
// @Description 更新当前用户的个人资料信息
// @Tags 设置管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.UserProfileUpdateRequest true "用户资料更新请求"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/profile [put]
func (c *SettingsController) UpdateProfile(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	var req model.UserProfileUpdateRequest
	if err := bindProfileRequest(ctx, &req); err != nil {
		return
	}

	if err := c.settingsService.UpdateProfile(userID, &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// ChangePassword 修改密码
// @Summary 修改密码
// @Description 修改当前用户的登录密码
// @Tags 设置管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.ChangePasswordRequest true "修改密码请求"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/password [put]
func (c *SettingsController) ChangePassword(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	var req model.ChangePasswordRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	if err := c.settingsService.ChangePassword(userID, &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// Setup2FA 设置双因素认证
// @Summary 设置双因素认证
// @Description 创建待验证的 TOTP 绑定，返回 qr_code_url、qr_code_data_url、otpauth_url、secret、expires_at；这些数据仅用于当前用户绑定认证器。Authorization 使用 Bearer 访问令牌或登录返回的 rebind_token。设置后须在有效期内调用 verify，当前步骤不会启用 MFA。
// @Tags 设置管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.TwoFactorSetupResponse}
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/2fa/setup [post]
func (c *SettingsController) Setup2FA(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	setupData, err := c.settingsService.Setup2FA(userID)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, setupData)
}

// Verify2FA 验证双因素认证
// @Summary 验证双因素认证
// @Description 使用 setup 后认证器生成的 6 位 code 完成绑定并启用 MFA；Authorization 使用 Bearer 访问令牌或 rebind_token。成功仅此次返回 recovery_codes 数组，请妥善保存；现有访问令牌与重绑定令牌失效，须重新登录。
// @Tags 设置管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.TwoFactorVerifyRequest true "2FA验证请求：code 为 6 位 TOTP"
// @Success 200 {object} model.Response{data=object{recovery_codes=[]string}}
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/2fa/verify [post]
func (c *SettingsController) Verify2FA(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	var req model.TwoFactorVerifyRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	codes, err := c.settingsService.Verify2FA(userID, req.Code)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, gin.H{"recovery_codes": codes})
}

// Disable2FA 禁用双因素认证
// @Summary 禁用双因素认证
// @Description 使用当前 TOTP 或未使用的恢复码（code 字段）禁用当前用户 MFA。须使用 Bearer 访问令牌；成功后当前用户所有会话失效，须重新登录。
// @Tags 设置管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body object{code=string} true "必填 code：当前 TOTP 或恢复码"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/2fa [delete]
func (c *SettingsController) Disable2FA(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}
	if err := c.settingsService.Disable2FA(userID, req.Code); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// Get2FAStatus 获取双因素认证状态
// @Summary 获取双因素认证状态
// @Description 返回 enabled、pending、needs_rebind、recovery_codes_remaining，不返回已保存的 MFA 秘密或恢复码。Authorization 使用 Bearer 访问令牌或登录返回的 rebind_token。
// @Tags 设置管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.TwoFactorStatusResponse}
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/2fa/status [get]
func (c *SettingsController) Get2FAStatus(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	status, err := c.settingsService.Get2FAStatus(userID)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, status)
}

// GetSystemSettings 获取系统设置
// @Summary 获取系统设置
// @Description 获取当前用户的系统设置
// @Tags 设置管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.SystemSettings}
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/system [get]
func (c *SettingsController) GetSystemSettings(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	settings, err := c.settingsService.GetSystemSettings(userID)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, settings)
}

// UpdateSystemSettings 更新系统设置
// @Summary 更新系统设置
// @Description 更新当前用户的系统设置
// @Tags 设置管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.SystemSettingsRequest true "系统设置更新请求"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/system [put]
func (c *SettingsController) UpdateSystemSettings(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	var req model.SystemSettingsRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	if err := c.settingsService.UpdateSystemSettings(userID, &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// GetNotificationSettings 获取通知设置
// @Summary 获取通知设置
// @Description 获取当前用户的通知设置
// @Tags 设置管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.NotificationSettings}
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/notifications [get]
func (c *SettingsController) GetNotificationSettings(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	settings, err := c.settingsService.GetNotificationSettings(userID)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, settings)
}

// UpdateNotificationSettings 更新通知设置
// @Summary 更新通知设置
// @Description 更新当前用户的通知设置
// @Tags 设置管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.NotificationSettingsRequest true "通知设置更新请求"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/notifications [put]
func (c *SettingsController) UpdateNotificationSettings(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	var req model.NotificationSettingsRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	if err := c.settingsService.UpdateNotificationSettings(userID, &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// ExportData 导出数据
// @Summary 导出数据
// @Description 导出用户数据
// @Tags 设置管理
// @Produce json
// @Security ApiKeyAuth
// @Param type query string true "数据类型" Enums(profile,settings,all)
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/export [get]
func (c *SettingsController) ExportData(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}
	dataType := ctx.Query("type")

	if dataType == "" {
		utils.BadRequestResponse(ctx, "请指定数据类型")
		return
	}

	data, err := c.settingsService.ExportUserData(userID, dataType)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	// 设置下载头
	ctx.Header("Content-Type", "application/json")
	ctx.Header("Content-Disposition", "attachment; filename=export_"+dataType+".json")
	ctx.Data(200, "application/json", data)
}

// ImportData 导入数据
// @Summary 导入数据
// @Description 导入用户数据
// @Tags 设置管理
// @Accept multipart/form-data
// @Produce json
// @Security ApiKeyAuth
// @Param file formData file true "数据文件"
// @Param type formData string true "数据类型"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/import [post]
func (c *SettingsController) ImportData(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}
	dataType := ctx.PostForm("type")

	if dataType == "" {
		utils.BadRequestResponse(ctx, "请指定数据类型")
		return
	}

	file, err := ctx.FormFile("file")
	if err != nil {
		utils.BadRequestResponse(ctx, "请选择文件")
		return
	}

	// 读取文件内容
	src, err := file.Open()
	if err != nil {
		utils.BadRequestResponse(ctx, "文件读取失败")
		return
	}
	defer src.Close()

	data := make([]byte, file.Size)
	if _, err := src.Read(data); err != nil {
		utils.BadRequestResponse(ctx, "文件读取失败")
		return
	}

	if err := c.settingsService.ImportUserData(userID, data, dataType); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// ClearCache 清理缓存
// @Summary 清理缓存
// @Description 清理用户相关缓存
// @Tags 设置管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/cache/clear [post]
func (c *SettingsController) ClearCache(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	if err := c.settingsService.ClearCache(userID); err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// OptimizeDatabase 优化数据库
// @Summary 优化数据库
// @Description 执行数据库优化操作
// @Tags 设置管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response
// @Failure 401 {object} model.Response
// @Router /api/v1/settings/database/optimize [post]
func (c *SettingsController) OptimizeDatabase(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "用户未登录")
		return
	}

	if err := c.settingsService.OptimizeDatabase(userID); err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}
