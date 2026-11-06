package controller

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"vulnark/internal/middleware"
	"vulnark/internal/model"
	"vulnark/internal/service"
	"vulnark/pkg/utils"
)

// SLAController exposes policy CRUD and vulnerability timer controls. Routes
// should apply sla:manage to policy/timer writes and vuln:read to state/list reads.
type SLAController struct{ slaService service.SLAService }

func NewSLAController(slaService service.SLAService) *SLAController {
	return &SLAController{slaService: slaService}
}

// CreatePolicy 创建SLA策略
// @Summary 创建SLA策略
// @Description 需要 sla:manage 权限。按严重程度设置响应和修复时限，可限定资产或部门；enabled 省略时默认为 true。
// @Tags SLA管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.SLAPolicyCreateRequest true "SLA策略"
// @Success 200 {object} model.Response{data=model.SLAPolicy}
// @Failure 400 {object} model.Response "请求无效或创建失败"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少sla:manage权限"
// @Router /api/v1/sla-policies [post]
func (c *SLAController) CreatePolicy(ctx *gin.Context) {
	var req model.SLAPolicyCreateRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}
	policy, err := c.slaService.CreatePolicy(&req)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, policy)
}

// ListPolicies 获取SLA策略列表
// @Summary 获取SLA策略列表
// @Description 需要 sla:manage 权限。返回分页策略列表。
// @Tags SLA管理
// @Produce json
// @Security ApiKeyAuth
// @Param severity_level query int false "严重程度（1严重、2高危、3中危、4低危）" Enums(1,2,3,4)
// @Param asset_id query int false "资产ID" minimum(1)
// @Param department query string false "部门"
// @Param enabled query bool false "是否启用"
// @Param page query int false "页码" default(1) minimum(1) maximum(1000)
// @Param page_size query int false "每页数量" default(20) minimum(1) maximum(50)
// @Success 200 {object} model.Response{data=model.PaginationResponse{data=[]model.SLAPolicy}}
// @Failure 400 {object} model.Response "查询参数无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少sla:manage权限"
// @Failure 500 {object} model.Response "获取策略失败"
// @Router /api/v1/sla-policies [get]
func (c *SLAController) ListPolicies(ctx *gin.Context) {
	var req model.SLAPolicySearchRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 20
	}
	result, err := c.slaService.ListPolicies(&req)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, result)
}

// GetPolicy 获取SLA策略详情
// @Summary 获取SLA策略详情
// @Description 需要 sla:manage 权限。
// @Tags SLA管理
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "SLA策略ID" minimum(1)
// @Success 200 {object} model.Response{data=model.SLAPolicy}
// @Failure 400 {object} model.Response "策略ID无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少sla:manage权限"
// @Failure 404 {object} model.Response "SLA策略不存在"
// @Router /api/v1/sla-policies/{id} [get]
func (c *SLAController) GetPolicy(ctx *gin.Context) {
	id, err := parseSLAID(ctx)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	policy, err := c.slaService.GetPolicy(id)
	if err != nil {
		utils.NotFoundResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, policy)
}

// UpdatePolicy 更新SLA策略
// @Summary 更新SLA策略
// @Description 需要 sla:manage 权限。asset_id 设为 null 可清除资产限定，department 设为空字符串可清除部门限定；省略这些字段时保留现值。
// @Tags SLA管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "SLA策略ID" minimum(1)
// @Param request body model.SLAPolicyUpdateRequest true "策略更新字段"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response "策略ID、请求无效或更新失败"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少sla:manage权限"
// @Router /api/v1/sla-policies/{id} [put]
func (c *SLAController) UpdatePolicy(ctx *gin.Context) {
	id, err := parseSLAID(ctx)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	var req model.SLAPolicyUpdateRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}
	if err := c.slaService.UpdatePolicy(id, &req); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, nil)
}

// DeletePolicy 删除SLA策略
// @Summary 删除SLA策略
// @Description 需要 sla:manage 权限。
// @Tags SLA管理
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "SLA策略ID" minimum(1)
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response "策略ID无效或删除失败"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少sla:manage权限"
// @Router /api/v1/sla-policies/{id} [delete]
func (c *SLAController) DeletePolicy(ctx *gin.Context) {
	id, err := parseSLAID(ctx)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	if err := c.slaService.DeletePolicy(id); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, nil)
}

// GetState 获取漏洞SLA状态
// @Summary 获取漏洞SLA状态
// @Description 需要 vuln:read 权限。返回策略快照、当前计时周期、响应/修复期限及暂停信息。sla_status 为 none、within、paused、overdue 或 completed；剩余秒数可为空或负数，逾期等级为 0、1、24 或 72。
// @Tags SLA管理
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "漏洞ID" minimum(1)
// @Success 200 {object} model.Response{data=model.SLAState}
// @Failure 400 {object} model.Response "漏洞ID无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少vuln:read权限"
// @Failure 404 {object} model.Response "漏洞不存在或无法读取状态"
// @Router /api/v1/vulnerabilities/{id}/sla [get]
func (c *SLAController) GetState(ctx *gin.Context) {
	id, err := parseSLAID(ctx)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	state, err := c.slaService.GetState(id, time.Now())
	if err != nil {
		utils.NotFoundResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, state)
}

// ListOverdue 获取SLA逾期漏洞
// @Summary 获取SLA逾期漏洞
// @Description 需要 vuln:read 权限。返回响应或修复逾期且未暂停、未完成的漏洞；普通漏洞列表也支持 sla_status=overdue 筛选。
// @Tags SLA管理
// @Produce json
// @Security ApiKeyAuth
// @Param limit query int false "返回数量" default(100) minimum(1) maximum(1000)
// @Success 200 {object} model.Response{data=[]model.VulnerabilityInfo}
// @Failure 400 {object} model.Response "limit必须为1-1000"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少vuln:read权限"
// @Failure 500 {object} model.Response "获取逾期列表失败"
// @Router /api/v1/vulnerabilities/sla/overdue [get]
func (c *SLAController) ListOverdue(ctx *gin.Context) {
	limit := 100
	if raw := ctx.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			utils.BadRequestResponse(ctx, "limit必须为1-1000")
			return
		}
		limit = parsed
	}
	items, err := c.slaService.ListOverdue(ctx.Request.Context(), time.Now(), limit)
	if err != nil {
		utils.ServerErrorResponse(ctx, "获取SLA逾期列表失败")
		return
	}
	utils.SuccessResponse(ctx, items)
}

// Pause 暂停漏洞SLA计时
// @Summary 暂停漏洞SLA计时
// @Description 需要 vuln:read 和 sla:manage 权限；可选 JSON 请求体提供 reason（最长500字符），暂停原因和操作者记录在漏洞时间线。
// @Tags SLA管理
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "漏洞ID" minimum(1)
// @Param request body model.SLAPauseRequest false "暂停原因"
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response "漏洞ID无效或暂停失败"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少vuln:read或sla:manage权限"
// @Router /api/v1/vulnerabilities/{id}/sla/pause [post]
func (c *SLAController) Pause(ctx *gin.Context) {
	id, err := parseSLAID(ctx)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	actorID, ok := middleware.GetCurrentUserID(ctx)
	if !ok || actorID == 0 {
		utils.UnauthorizedResponse(ctx, "")
		return
	}
	var req model.SLAPauseRequest
	if ctx.Request.ContentLength != 0 {
		if err := utils.BindAndValidate(ctx, &req); err != nil {
			return
		}
	}
	if err := c.slaService.PauseWithReason(id, actorID, req.Reason, time.Now()); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, nil)
}

// Resume 恢复漏洞SLA计时
// @Summary 恢复漏洞SLA计时
// @Description 需要 vuln:read 和 sla:manage 权限，无需请求体；恢复后将暂停时长计入期限。
// @Tags SLA管理
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "漏洞ID" minimum(1)
// @Success 200 {object} model.Response
// @Failure 400 {object} model.Response "漏洞ID无效或恢复失败"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少vuln:read或sla:manage权限"
// @Router /api/v1/vulnerabilities/{id}/sla/resume [post]
func (c *SLAController) Resume(ctx *gin.Context) {
	id, err := parseSLAID(ctx)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	actorID, ok := middleware.GetCurrentUserID(ctx)
	if !ok || actorID == 0 {
		utils.UnauthorizedResponse(ctx, "")
		return
	}
	if err := c.slaService.ResumeWithActor(id, actorID, time.Now()); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	utils.SuccessResponse(ctx, nil)
}

func parseSLAID(ctx *gin.Context) (uint, error) {
	id, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil || id == 0 {
		return 0, &slaIDError{}
	}
	return uint(id), nil
}

type slaIDError struct{}

func (*slaIDError) Error() string { return "无效的SLA策略或漏洞ID" }
