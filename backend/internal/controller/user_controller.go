package controller

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"vulnark/internal/middleware"
	"vulnark/internal/model"
	"vulnark/internal/service"
	"vulnark/pkg/utils"
)

// UserController 用户控制器
type UserController struct {
	userService       service.UserService
	roleService       service.RoleService
	permissionService service.PermissionService
}

// NewUserController 创建用户控制器
func NewUserController(userService service.UserService, roleService service.RoleService, permissions ...service.PermissionService) *UserController {
	c := &UserController{userService: userService, roleService: roleService}
	if len(permissions) > 0 {
		c.permissionService = permissions[0]
	}
	return c
}

// Login 用户登录
// @Summary 用户登录
// @Description 使用 username、password 登录；启用 MFA 时首次返回 mfa_required、challenge_token，随后携带相同凭据、challenge_token 及 totp_code 或 recovery_code 完成登录。需要重新绑定 MFA 时返回 mfa_rebind_required、rebind_token，该令牌仅用于 2FA setup、verify、status；重新绑定完成后须重新登录获取访问令牌。
// @Tags 用户管理
// @Accept json
// @Produce json
// @Param request body model.UserLoginRequest true "登录请求"
// @Success 200 {object} model.Response{data=model.UserLoginResponse}
// @Failure 400 {object} model.Response
// @Router /api/v1/login [post]
func (c *UserController) Login(ctx *gin.Context) {
	var req model.UserLoginRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	resp, err := c.userService.Login(&req)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, resp)
}

// GetProfile 获取用户资料
// @Summary 获取用户资料
// @Description 获取当前登录用户的资料
// @Tags 用户管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.UserInfo}
// @Failure 401 {object} model.Response
// @Router /api/v1/profile [get]
func (c *UserController) GetProfile(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "")
		return
	}

	profile, err := c.userService.GetProfile(userID)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, profile)
}

// UpdateProfile 更新用户资料
// @Summary 更新用户资料
// @Description 更新当前登录用户的资料
// @Tags 用户管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.UserProfileUpdateRequest true "更新请求"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Router /api/v1/profile [put]
func (c *UserController) UpdateProfile(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "")
		return
	}

	var req model.UserProfileUpdateRequest
	if err := bindProfileRequest(ctx, &req); err != nil {
		return
	}

	if err := c.userService.UpdateProfile(userID, &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// ChangePassword 修改密码
// @Summary 修改密码
// @Description 修改当前登录用户的密码
// @Tags 用户管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.ChangePasswordRequest true "修改密码请求"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Router /api/v1/change-password [post]
func (c *UserController) ChangePassword(ctx *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(ctx)
	if !exists {
		utils.UnauthorizedResponse(ctx, "")
		return
	}

	var req model.ChangePasswordRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	if err := c.userService.ChangePassword(userID, &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// CreateUser 创建用户
// @Summary 创建用户
// @Description 创建用户需要 user:manage 权限；通过必填 role_id 为新用户分配角色时额外需要 system:permission 权限。
// @Tags 用户管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.UserCreateRequest true "创建用户请求"
// @Success 200 {object} model.Response{data=model.User}
// @Failure 400 {object} model.Response
// @Router /api/v1/users [post]
func (c *UserController) CreateUser(ctx *gin.Context) {
	var req model.UserCreateRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	if !allowPermissionChanges(ctx, c.permissionService) {
		return
	}
	user, err := c.userService.CreateUser(&req)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, user)
}

// GetUserList 获取用户列表
// @Summary 获取用户列表
// @Description 获取用户列表（分页）
// @Tags 用户管理
// @Produce json
// @Security ApiKeyAuth
// @Param page query int false "页码" default(1)
// @Param page_size query int false "每页数量" default(10)
// @Param keyword query string false "搜索关键词"
// @Param status query string false "用户状态"
// @Success 200 {object} model.Response{data=model.PaginationResponse}
// @Failure 400 {object} model.Response
// @Router /api/v1/users [get]
func (c *UserController) GetUserList(ctx *gin.Context) {
	var req model.SearchRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}

	// 设置默认值
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 10
	}

	resp, err := c.userService.GetUserList(&req)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, resp)
}

// GetUser 获取用户详情
// @Summary 获取用户详情
// @Description 根据ID获取用户详情
// @Tags 用户管理
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "用户ID"
// @Success 200 {object} model.Response{data=model.UserInfo}
// @Failure 400 {object} model.Response
// @Router /api/v1/users/{id} [get]
func (c *UserController) GetUser(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		utils.BadRequestResponse(ctx, "无效的用户ID")
		return
	}

	user, err := c.userService.GetUserByID(uint(id))
	if err != nil {
		utils.NotFoundResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, user)
}

// UpdateUser 更新用户
// @Summary 更新用户
// @Description 更新用户需要 user:manage 权限；通过 role_id 分配或变更用户角色时额外需要 system:permission 权限。
// @Tags 用户管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "用户ID"
// @Param request body model.UserUpdateRequest true "更新请求"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Router /api/v1/users/{id} [put]
func (c *UserController) UpdateUser(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		utils.BadRequestResponse(ctx, "无效的用户ID")
		return
	}

	var req model.UserUpdateRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}

	if req.RoleID != 0 {
		current, err := c.userService.GetUserByID(uint(id))
		if err != nil {
			utils.NotFoundResponse(ctx, "用户不存在")
			return
		}
		if current.Role.ID == req.RoleID {
			// An unchanged role is not a grant; do not write a potentially stale role ID.
			req.RoleID = 0
		} else if !allowPermissionChanges(ctx, c.permissionService) {
			return
		}
	}
	if err := c.userService.UpdateUser(uint(id), &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// DeleteUser 删除用户
// @Summary 删除用户
// @Description 管理员删除用户
// @Tags 用户管理
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "用户ID"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response
// @Router /api/v1/users/{id} [delete]
func (c *UserController) DeleteUser(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		utils.BadRequestResponse(ctx, "无效的用户ID")
		return
	}

	if err := c.userService.DeleteUser(uint(id)); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, nil)
}

// GetDepartmentOptions 获取部门选项
// @Summary 获取部门选项
// @Description 获取可用的部门选项列表
// @Tags 用户管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=[]object{value=string,label=string}}
// @Router /api/v1/users/departments [get]
func (c *UserController) GetDepartmentOptions(ctx *gin.Context) {
	departments := []map[string]string{
		{"value": "IT部门", "label": "IT部门"},
		{"value": "安全部门", "label": "安全部门"},
		{"value": "开发部门", "label": "开发部门"},
		{"value": "测试部门", "label": "测试部门"},
		{"value": "运维部门", "label": "运维部门"},
		{"value": "产品部门", "label": "产品部门"},
		{"value": "设计部门", "label": "设计部门"},
		{"value": "市场部门", "label": "市场部门"},
		{"value": "销售部门", "label": "销售部门"},
		{"value": "人事部门", "label": "人事部门"},
		{"value": "财务部门", "label": "财务部门"},
		{"value": "法务部门", "label": "法务部门"},
	}

	utils.SuccessResponse(ctx, departments)
}

// bindProfileRequest rejects privileged and unknown fields before service dispatch.
func bindProfileRequest(ctx *gin.Context, req *model.UserProfileUpdateRequest) error {
	decoder := json.NewDecoder(ctx.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(req); err != nil {
		utils.BadRequestResponse(ctx, "资料请求含不允许的字段或格式错误")
		return err
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		utils.BadRequestResponse(ctx, "资料请求格式错误")
		return errors.New("invalid trailing JSON")
	}
	if err := binding.Validator.ValidateStruct(req); err != nil {
		utils.BadRequestResponse(ctx, "资料请求格式错误")
		return err
	}
	return nil
}

// RevokeAllSessions invalidates every previously issued access and rebind token.
// @Summary 退出所有会话
// @Description 撤销当前用户已签发的全部访问令牌与 MFA 重绑定令牌；/logout 和 /revoke-all 执行相同操作，成功后须重新登录。
// @Tags 用户管理
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response
// @Failure 401 {object} model.Response
// @Failure 500 {object} model.Response
// @Router /api/v1/revoke-all [post]
// @Router /api/v1/logout [post]
func (c *UserController) RevokeAllSessions(ctx *gin.Context) {
	userID, ok := middleware.GetCurrentUserID(ctx)
	if !ok {
		utils.UnauthorizedResponse(ctx, "")
		return
	}
	if err := c.userService.RevokeAllSessions(userID); err != nil {
		utils.ServerErrorResponse(ctx, "撤销会话失败")
		return
	}
	utils.SuccessResponse(ctx, nil)
}

func (c *UserController) Logout(ctx *gin.Context) { c.RevokeAllSessions(ctx) }
