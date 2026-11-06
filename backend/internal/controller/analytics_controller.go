package controller

import (
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"vulnark/internal/middleware"
	"vulnark/internal/model"
	"vulnark/internal/service"
	"vulnark/pkg/utils"
)

// AnalyticsController 统计分析控制器
type AnalyticsController struct {
	analyticsService  service.AnalyticsService
	permissionService service.PermissionService
}

// NewAnalyticsController 创建统计分析控制器
func NewAnalyticsController(analyticsService service.AnalyticsService, permissions ...service.PermissionService) *AnalyticsController {
	c := &AnalyticsController{analyticsService: analyticsService}
	if len(permissions) > 0 {
		c.permissionService = permissions[0]
	}
	return c
}

func (c *AnalyticsController) allowExport(ctx *gin.Context, kind string) bool {
	if kind != model.ExportTypeUser {
		return true
	}
	userID, ok := middleware.GetCurrentUserID(ctx)
	if !ok || userID == 0 {
		utils.UnauthorizedResponse(ctx, "请先登录")
		return false
	}
	if c.permissionService == nil {
		utils.ForbiddenResponse(ctx, "缺少用户管理权限")
		return false
	}
	allowed, err := c.permissionService.CheckUserPermission(userID, "user:manage")
	if err != nil {
		utils.ServerErrorResponse(ctx, "权限检查失败")
		return false
	}
	if !allowed {
		utils.ForbiddenResponse(ctx, "缺少用户管理权限")
		return false
	}
	return true
}

// GetDashboardStats 获取仪表盘统计数据
// @Summary 获取仪表盘统计数据
// @Description 获取系统总体统计数据，包括漏洞、资产、用户、报告等统计信息
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=model.DashboardStats}
// @Failure 500 {object} model.Response
// @Router /api/v1/analytics/dashboard [get]
func (c *AnalyticsController) GetDashboardStats(ctx *gin.Context) {
	stats, err := c.analyticsService.GetDashboardStats()
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, stats)
}

// GetVulnerabilityAnalytics 获取漏洞分析数据
// @Summary 获取漏洞分析数据
// @Description 获取漏洞的详细分析数据，包括趋势、分布、统计等
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Param start_date query string false "开始日期 (YYYY-MM-DD)"
// @Param end_date query string false "结束日期 (YYYY-MM-DD)"
// @Param granularity query string false "时间粒度 (day/week/month)" default(day)
// @Param asset_id query string false "资产ID"
// @Param user_id query string false "用户ID"
// @Param severity query string false "严重程度"
// @Param status query string false "状态"
// @Param category query string false "分类"
// @Success 200 {object} model.Response{data=model.VulnerabilityAnalytics}
// @Failure 400 {object} model.Response
// @Router /api/v1/analytics/vulnerability [get]
func (c *AnalyticsController) GetVulnerabilityAnalytics(ctx *gin.Context) {
	var req model.AnalyticsRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}

	analytics, err := c.analyticsService.GetVulnerabilityAnalytics(&req)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, analytics)
}

// GetVulnerabilityTrend 获取漏洞趋势数据
// @Summary 获取漏洞趋势数据
// @Description 获取指定时间范围内的漏洞趋势数据
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Param start_date query string false "开始日期 (YYYY-MM-DD)"
// @Param end_date query string false "结束日期 (YYYY-MM-DD)"
// @Param granularity query string false "时间粒度 (day/week/month)" default(day)
// @Success 200 {object} model.Response{data=[]model.TrendPoint}
// @Failure 400 {object} model.Response
// @Router /api/v1/analytics/vulnerability/trend [get]
func (c *AnalyticsController) GetVulnerabilityTrend(ctx *gin.Context) {
	var req model.AnalyticsRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}

	trend, err := c.analyticsService.GetVulnerabilityTrend(&req)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, trend)
}

// GetSeverityTrend 获取严重程度趋势数据
// @Summary 获取严重程度趋势数据
// @Description 获取指定时间范围内各严重程度漏洞的趋势数据
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Param start_date query string false "开始日期 (YYYY-MM-DD)"
// @Param end_date query string false "结束日期 (YYYY-MM-DD)"
// @Success 200 {object} model.Response{data=[]model.SeverityTrendPoint}
// @Failure 400 {object} model.Response
// @Router /api/v1/analytics/vulnerability/severity-trend [get]
func (c *AnalyticsController) GetSeverityTrend(ctx *gin.Context) {
	var req model.AnalyticsRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}

	trend, err := c.analyticsService.GetSeverityTrend(&req)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, trend)
}

// GetMonthlyVulnerabilityTrends 获取月度漏洞趋势
// @Summary 获取月度漏洞趋势
// @Description 获取最近6个月的漏洞发现和解决趋势数据
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=[]model.MonthlyTrendPoint}
// @Failure 500 {object} model.Response
// @Router /api/v1/analytics/vulnerability/monthly-trends [get]
func (c *AnalyticsController) GetMonthlyVulnerabilityTrends(ctx *gin.Context) {
	trends, err := c.analyticsService.GetMonthlyVulnerabilityTrends()
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, trends)
}

// GetAssetAnalytics 获取资产分析数据
// @Summary 获取资产分析数据
// @Description 获取资产的详细分析数据，包括分布、风险评估等
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Param start_date query string false "开始日期 (YYYY-MM-DD)"
// @Param end_date query string false "结束日期 (YYYY-MM-DD)"
// @Param granularity query string false "时间粒度 (day/week/month)" default(day)
// @Success 200 {object} model.Response{data=model.AssetAnalytics}
// @Failure 400 {object} model.Response
// @Router /api/v1/analytics/asset [get]
func (c *AnalyticsController) GetAssetAnalytics(ctx *gin.Context) {
	var req model.AnalyticsRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}

	analytics, err := c.analyticsService.GetAssetAnalytics(&req)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, analytics)
}

// GetAssetRiskAssessment 获取资产风险评估
// @Summary 获取资产风险评估
// @Description 获取所有资产的风险评估数据
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=[]model.AssetRiskCount}
// @Failure 500 {object} model.Response
// @Router /api/v1/analytics/asset/risk [get]
func (c *AnalyticsController) GetAssetRiskAssessment(ctx *gin.Context) {
	risks, err := c.analyticsService.GetAssetRiskAssessment()
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, risks)
}

// GetReportAnalytics 获取报告分析数据
// @Summary 获取报告分析数据
// @Description 获取报告的详细分析数据，包括状态分布、类型分布等
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Param start_date query string false "开始日期 (YYYY-MM-DD)"
// @Param end_date query string false "结束日期 (YYYY-MM-DD)"
// @Param granularity query string false "时间粒度 (day/week/month)" default(day)
// @Success 200 {object} model.Response{data=model.ReportAnalytics}
// @Failure 400 {object} model.Response
// @Router /api/v1/analytics/report [get]
func (c *AnalyticsController) GetReportAnalytics(ctx *gin.Context) {
	var req model.AnalyticsRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}

	analytics, err := c.analyticsService.GetReportAnalytics(&req)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, analytics)
}

// GetUserAnalytics 获取用户分析数据
// @Summary 获取用户分析数据
// @Description 获取用户的详细分析数据，包括角色分布、活动统计等
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Param start_date query string false "开始日期 (YYYY-MM-DD)"
// @Param end_date query string false "结束日期 (YYYY-MM-DD)"
// @Param granularity query string false "时间粒度 (day/week/month)" default(day)
// @Success 200 {object} model.Response{data=model.UserAnalytics}
// @Failure 400 {object} model.Response
// @Router /api/v1/analytics/user [get]
func (c *AnalyticsController) GetUserAnalytics(ctx *gin.Context) {
	var req model.AnalyticsRequest
	if err := utils.BindQueryAndValidate(ctx, &req); err != nil {
		return
	}

	analytics, err := c.analyticsService.GetUserAnalytics(&req)
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	utils.SuccessResponse(ctx, analytics)
}

// ExportData 导出数据
// @Summary 导出数据
// @Description 创建统计 CSV 并返回 file_name、file_url、file_size，其中 file_url 是携带相同筛选条件的鉴权 GET 下载链接，下载时仍须提供 Authorization: Bearer 访问令牌。当前仅实现 csv，excel、pdf 请求返回 400。请求字段 type、format 必填，start_date、end_date 可选；filters 支持 asset_id、user_id、severity、status、category、granularity。需要 analytics:read、analytics:export 权限，type=user 额外需要 user:manage 权限。
// @Tags 统计分析
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body model.ExportRequest true "导出请求"
// @Success 200 {object} model.Response{data=model.ExportResponse}
// @Failure 400 {object} model.Response
// @Router /api/v1/analytics/export [post]
func (c *AnalyticsController) ExportData(ctx *gin.Context) {
	var req model.ExportRequest
	if err := utils.BindAndValidate(ctx, &req); err != nil {
		return
	}
	if !c.allowExport(ctx, req.Type) {
		return
	}
	response, err := c.analyticsService.ExportData(&req)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	if response == nil || response.FileName == "" || filepath.Base(response.FileName) != response.FileName || filepath.Ext(response.FileName) != ".csv" {
		utils.ServerErrorResponse(ctx, "无效的导出结果")
		return
	}
	// Metadata points to the authenticated generator, so the validation file is no longer needed.
	if err := os.Remove(filepath.Join("exports", response.FileName)); err != nil {
		utils.ServerErrorResponse(ctx, "清理导出失败")
		return
	}
	utils.SuccessResponse(ctx, response)
}

// DownloadExport returns a freshly generated CSV through the authenticated API.
// @Summary 下载统计CSV
// @Description 按筛选条件即时生成并返回 CSV 文件流，不接受文件路径参数。需要 analytics:read、analytics:export 权限，type=user 额外需要 user:manage 权限。
// @Tags 统计分析
// @Produce text/csv
// @Security ApiKeyAuth
// @Param type query string true "导出类型" Enums(dashboard,vulnerability,asset,report,user)
// @Param format query string false "当前仅支持 csv" default(csv) Enums(csv)
// @Param start_date query string false "开始日期 (YYYY-MM-DD)"
// @Param end_date query string false "结束日期 (YYYY-MM-DD)"
// @Param granularity query string false "时间粒度" Enums(day,week,month)
// @Param asset_id query string false "资产ID"
// @Param user_id query string false "用户ID"
// @Param severity query string false "严重程度"
// @Param status query string false "状态"
// @Param category query string false "分类"
// @Success 200 {file} file "CSV 文件流"
// @Header 200 {string} Content-Disposition "attachment; filename=导出文件名.csv"
// @Header 200 {string} Cache-Control "no-store"
// @Failure 400 {object} model.Response
// @Failure 401 {object} model.Response
// @Failure 403 {object} model.Response
// @Failure 500 {object} model.Response
// @Router /api/v1/analytics/export [get]
func (c *AnalyticsController) DownloadExport(ctx *gin.Context) {
	kind := ctx.Query("type")
	switch kind {
	case model.ExportTypeDashboard, model.ExportTypeVulnerability, model.ExportTypeAsset, model.ExportTypeReport, model.ExportTypeUser:
	default:
		utils.BadRequestResponse(ctx, "不支持的导出类型")
		return
	}
	if !c.allowExport(ctx, kind) {
		return
	}
	format := ctx.DefaultQuery("format", model.ExportFormatCSV)
	if format != model.ExportFormatCSV {
		utils.BadRequestResponse(ctx, "当前仅支持CSV导出")
		return
	}
	var filters model.AnalyticsRequest
	if err := utils.BindQueryAndValidate(ctx, &filters); err != nil {
		return
	}
	req := &model.ExportRequest{Type: kind, Format: format, StartDate: filters.StartDate, EndDate: filters.EndDate,
		Filters: map[string]interface{}{"asset_id": filters.AssetID, "user_id": filters.UserID, "severity": filters.Severity, "status": filters.Status, "category": filters.Category, "granularity": filters.Granularity}}
	response, err := c.analyticsService.ExportData(req)
	if err != nil {
		utils.BadRequestResponse(ctx, err.Error())
		return
	}
	// The name comes from the service, never from a requested filesystem path.
	if response == nil || response.FileName == "" || filepath.Base(response.FileName) != response.FileName || filepath.Ext(response.FileName) != ".csv" {
		utils.ServerErrorResponse(ctx, "无效的导出结果")
		return
	}
	path := filepath.Join("exports", response.FileName)
	file, err := os.Open(path)
	if err != nil {
		utils.ServerErrorResponse(ctx, "读取导出失败")
		return
	}
	defer file.Close()
	defer os.Remove(path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		utils.ServerErrorResponse(ctx, "读取导出失败")
		return
	}
	ctx.Header("Content-Type", "text/csv; charset=utf-8")
	ctx.Header("Content-Length", strconv.FormatInt(info.Size(), 10))
	ctx.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": response.FileName}))
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Status(http.StatusOK)
	if _, err := io.Copy(ctx.Writer, file); err != nil {
		_ = ctx.Error(err)
	}
}

// GetSystemOverview 获取系统概览
// @Summary 获取系统概览
// @Description 获取系统的整体概览信息，包括关键指标和趋势
// @Tags 统计分析
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} model.Response{data=map[string]interface{}}
// @Failure 500 {object} model.Response
// @Router /api/v1/analytics/overview [get]
func (c *AnalyticsController) GetSystemOverview(ctx *gin.Context) {
	// 获取仪表盘统计
	dashboardStats, err := c.analyticsService.GetDashboardStats()
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	// 获取资产风险评估
	assetRisks, err := c.analyticsService.GetAssetRiskAssessment()
	if err != nil {
		utils.ServerErrorResponse(ctx, err.Error())
		return
	}

	// 构建概览数据
	overview := map[string]interface{}{
		"dashboard_stats": dashboardStats,
		"top_risk_assets": assetRisks[:min(5, len(assetRisks))], // 取前5个高风险资产
		"system_health": map[string]interface{}{
			"vulnerability_resolution_rate": calculateResolutionRate(dashboardStats.VulnerabilityStats),
			"asset_coverage":                calculateAssetCoverage(dashboardStats),
			"user_activity_level":           calculateUserActivityLevel(dashboardStats.ActiveUsers),
		},
	}

	utils.SuccessResponse(ctx, overview)
}

// 辅助函数：计算漏洞解决率
func calculateResolutionRate(stats model.VulnerabilityStatusStats) float64 {
	total := stats.Open + stats.InProgress + stats.Resolved + stats.Closed + stats.Reopened
	if total == 0 {
		return 0
	}
	resolved := stats.Resolved + stats.Closed
	return float64(resolved) / float64(total) * 100
}

// 辅助函数：计算资产覆盖率
func calculateAssetCoverage(stats *model.DashboardStats) float64 {
	if stats == nil || stats.TotalAssets == 0 {
		return 0
	}
	return float64(stats.AssetsWithVulnerabilities) / float64(stats.TotalAssets) * 100
}

// 辅助函数：计算用户活跃度
func calculateUserActivityLevel(activeUsers []model.UserActivity) string {
	if len(activeUsers) == 0 {
		return "低"
	}
	if len(activeUsers) >= 10 {
		return "高"
	}
	if len(activeUsers) >= 5 {
		return "中"
	}
	return "低"
}

// 辅助函数：获取最小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
