package controller

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"vulnark/internal/middleware"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/internal/service"
	"vulnark/pkg/utils"
)

// RiskController exposes the risk score explanation, the scoring model and the
// state of the local threat-intelligence caches. Routes apply vuln:read to
// reads and risk:manage to every change.
type RiskController struct {
	riskService  service.RiskService
	intelService service.ThreatIntelService
}

func NewRiskController(riskService service.RiskService, intelService service.ThreatIntelService) *RiskController {
	return &RiskController{riskService: riskService, intelService: intelService}
}

// manualSyncTimeout stays below the default server write timeout so a slow
// feed produces an error response instead of a dropped connection.
const manualSyncTimeout = 100 * time.Second

// GetVulnerabilityRisk 获取漏洞风险评分构成
// @Summary 获取漏洞风险评分构成
// @Description 需要 vuln:read 权限。返回 0-100 的风险评分、优先级档位、各因子（CVSS、EPSS、KEV、资产重要性、暴露面）的权重、取值与贡献分，以及按档位建议的修复期限与当前 SLA 期限的对比。无数据的因子 applicable=false，其权重按比例分配给其余因子。评分只读取本地缓存，不访问外部接口。
// @Tags 风险优先级
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "漏洞ID" minimum(1)
// @Success 200 {object} model.Response{data=model.VulnerabilityRisk}
// @Failure 400 {object} model.Response "漏洞ID无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少vuln:read权限"
// @Failure 404 {object} model.Response "漏洞不存在"
// @Failure 500 {object} model.Response "评分失败"
// @Router /api/v1/vulnerabilities/{id}/risk [get]
func (c *RiskController) GetVulnerabilityRisk(ctx *gin.Context) {
	id, err := strconv.ParseUint(ctx.Param("id"), 10, 32)
	if err != nil || id == 0 {
		utils.BadRequestResponse(ctx, "无效的漏洞ID")
		return
	}
	risk, err := c.riskService.GetVulnerabilityRisk(uint(id), time.Now())
	if err != nil {
		if errors.Is(err, repository.ErrRiskVulnerabilityNotFound) {
			utils.NotFoundResponse(ctx, err.Error())
			return
		}
		utils.ServerErrorResponse(ctx, "获取风险评分失败")
		return
	}
	utils.SuccessResponse(ctx, risk)
}

// GetConfig 获取风险评分模型
// @Summary 获取风险评分模型
// @Description 需要 vuln:read 或 risk:manage 权限。返回当前权重、档位阈值、各档建议修复期限、KEV 保底档位及内置默认值；从未保存过时返回默认模型。
// @Tags 风险优先级
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.RiskConfigResponse}
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少权限"
// @Failure 500 {object} model.Response "读取配置失败"
// @Router /api/v1/risk/config [get]
func (c *RiskController) GetConfig(ctx *gin.Context) {
	config, err := c.riskService.GetConfig()
	if err != nil {
		utils.ServerErrorResponse(ctx, "读取风险评分配置失败")
		return
	}
	utils.SuccessResponse(ctx, config)
}

// UpdateConfig 更新风险评分模型
// @Summary 更新风险评分模型
// @Description 需要 risk:manage 权限。权重为 0-100 的相对值（无需合计 100），CVSS、资产重要性、暴露面三项不能同时为 0；阈值须满足 0 < P3 < P2 < P1 <= 100；建议期限为小时且 P1 <= P2 <= P3 <= P4；kev_min_priority 为空、P1、P2 或 P3。保存后立即按新模型重算全部漏洞并返回重算数量。
// @Tags 风险优先级
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.RiskConfig true "评分模型"
// @Success 200 {object} model.Response{data=model.RiskRescoreResult}
// @Failure 400 {object} model.Response "配置无效"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少risk:manage权限"
// @Failure 500 {object} model.Response "保存或重算失败"
// @Router /api/v1/risk/config [put]
func (c *RiskController) UpdateConfig(ctx *gin.Context) {
	actorID, ok := middleware.GetCurrentUserID(ctx)
	if !ok || actorID == 0 {
		utils.UnauthorizedResponse(ctx, "")
		return
	}
	var req model.RiskConfig
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}
	if err := req.Validate(); err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	result, err := c.riskService.UpdateConfig(ctx.Request.Context(), &req, actorID, time.Now())
	if err != nil {
		utils.ServerErrorResponse(ctx, "保存风险评分配置或重算评分失败")
		return
	}
	utils.SuccessResponse(ctx, result)
}

// Recalculate 重算全部漏洞的风险评分
// @Summary 重算全部漏洞的风险评分
// @Description 需要 risk:manage 权限。按当前模型和本地缓存重算全部漏洞，不访问外部接口。
// @Tags 风险优先级
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.RiskRescoreResult}
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少risk:manage权限"
// @Failure 429 {object} model.Response "请求过于频繁"
// @Failure 500 {object} model.Response "重算失败"
// @Router /api/v1/risk/recalculate [post]
func (c *RiskController) Recalculate(ctx *gin.Context) {
	rescored, err := c.riskService.Rescore(ctx.Request.Context(), repository.RiskRescoreScope{}, time.Now())
	if err != nil {
		utils.ServerErrorResponse(ctx, "重算风险评分失败")
		return
	}
	utils.SuccessResponse(ctx, model.RiskRescoreResult{Rescored: rescored})
}

// GetIntelStatus 获取威胁情报缓存状态
// @Summary 获取威胁情报缓存状态
// @Description 需要 vuln:read 或 risk:manage 权限。返回 EPSS 与 KEV 本地缓存的最近尝试、最近成功时间、最近错误、条目数和数据版本。同步失败时保留已有缓存，stale 表示超过两个同步周期没有成功。
// @Tags 风险优先级
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.ThreatIntelStatus}
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少权限"
// @Failure 500 {object} model.Response "读取状态失败"
// @Router /api/v1/risk/intel/status [get]
func (c *RiskController) GetIntelStatus(ctx *gin.Context) {
	status, err := c.intelService.Status()
	if err != nil {
		utils.ServerErrorResponse(ctx, "读取威胁情报状态失败")
		return
	}
	utils.SuccessResponse(ctx, status)
}

// SyncIntel 立即同步威胁情报
// @Summary 立即同步威胁情报
// @Description 需要 risk:manage 权限。立即刷新 KEV 目录和已录入 CVE 的 EPSS 分数，并重算带 CVE 的漏洞。单个数据源失败时在 errors 中说明，已有缓存保持不变；后台同步进行中返回 409，配置中禁用同步时返回 400。
// @Tags 风险优先级
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.ThreatIntelSyncResult}
// @Failure 400 {object} model.Response "同步已禁用"
// @Failure 401 {object} model.Response "未认证"
// @Failure 403 {object} model.Response "缺少risk:manage权限"
// @Failure 409 {object} model.Response "同步正在进行"
// @Failure 429 {object} model.Response "请求过于频繁"
// @Failure 500 {object} model.Response "同步失败"
// @Router /api/v1/risk/intel/sync [post]
func (c *RiskController) SyncIntel(ctx *gin.Context) {
	syncCtx, cancel := context.WithTimeout(ctx.Request.Context(), manualSyncTimeout)
	defer cancel()
	result, err := c.intelService.SyncNow(syncCtx)
	switch {
	case errors.Is(err, service.ErrThreatIntelDisabled):
		utils.BadRequestResponse(ctx, err.Error())
	case errors.Is(err, service.ErrThreatIntelBusy):
		utils.ErrorResponse(ctx, http.StatusConflict, err.Error())
	case err != nil:
		utils.ServerErrorResponse(ctx, "威胁情报同步失败")
	default:
		utils.SuccessResponse(ctx, result)
	}
}
