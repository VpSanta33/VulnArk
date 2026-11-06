package service

import (
	"encoding/csv"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// AnalyticsService 统计分析服务接口
type AnalyticsService interface {
	// 仪表盘统计
	GetDashboardStats() (*model.DashboardStats, error)

	// 漏洞分析
	GetVulnerabilityAnalytics(req *model.AnalyticsRequest) (*model.VulnerabilityAnalytics, error)
	GetVulnerabilityTrend(req *model.AnalyticsRequest) ([]model.TrendPoint, error)
	GetSeverityTrend(req *model.AnalyticsRequest) ([]model.SeverityTrendPoint, error)
	GetMonthlyVulnerabilityTrends() ([]model.MonthlyTrendPoint, error)

	// 资产分析
	GetAssetAnalytics(req *model.AnalyticsRequest) (*model.AssetAnalytics, error)
	GetAssetRiskAssessment() ([]model.AssetRiskCount, error)

	// 报告分析
	GetReportAnalytics(req *model.AnalyticsRequest) (*model.ReportAnalytics, error)

	// 用户分析
	GetUserAnalytics(req *model.AnalyticsRequest) (*model.UserAnalytics, error)

	// 数据导出
	ExportData(req *model.ExportRequest) (*model.ExportResponse, error)
}

// analyticsService 统计分析服务实现
type analyticsService struct {
	analyticsRepo repository.AnalyticsRepository
}

// NewAnalyticsService 创建统计分析服务
func NewAnalyticsService(analyticsRepo repository.AnalyticsRepository) AnalyticsService {
	return &analyticsService{
		analyticsRepo: analyticsRepo,
	}
}

// GetDashboardStats 获取仪表盘统计数据
func (s *analyticsService) GetDashboardStats() (*model.DashboardStats, error) {
	return s.analyticsRepo.GetDashboardStats()
}

// GetVulnerabilityAnalytics 获取漏洞分析数据
func (s *analyticsService) GetVulnerabilityAnalytics(req *model.AnalyticsRequest) (*model.VulnerabilityAnalytics, error) {
	return s.analyticsRepo.GetVulnerabilityAnalytics(req)
}

// GetVulnerabilityTrend 获取漏洞趋势数据
func (s *analyticsService) GetVulnerabilityTrend(req *model.AnalyticsRequest) ([]model.TrendPoint, error) {
	startDate, endDate, err := s.parseTimeRange(req)
	if err != nil {
		return nil, err
	}

	granularity := req.Granularity
	if granularity == "" {
		granularity = model.GranularityDay
	}

	return s.analyticsRepo.GetVulnerabilityTrend(startDate, endDate, granularity, req)
}

// GetSeverityTrend 获取严重程度趋势数据
func (s *analyticsService) GetSeverityTrend(req *model.AnalyticsRequest) ([]model.SeverityTrendPoint, error) {
	startDate, endDate, err := s.parseTimeRange(req)
	if err != nil {
		return nil, err
	}

	return s.analyticsRepo.GetSeverityTrend(startDate, endDate, req)
}

// GetMonthlyVulnerabilityTrends 获取月度漏洞趋势
func (s *analyticsService) GetMonthlyVulnerabilityTrends() ([]model.MonthlyTrendPoint, error) {
	return s.analyticsRepo.GetMonthlyVulnerabilityTrends()
}

// GetAssetAnalytics 获取资产分析数据
func (s *analyticsService) GetAssetAnalytics(req *model.AnalyticsRequest) (*model.AssetAnalytics, error) {
	return s.analyticsRepo.GetAssetAnalytics(req)
}

// GetAssetRiskAssessment 获取资产风险评估
func (s *analyticsService) GetAssetRiskAssessment() ([]model.AssetRiskCount, error) {
	return s.analyticsRepo.GetAssetRiskAssessment()
}

// GetReportAnalytics 获取报告分析数据
func (s *analyticsService) GetReportAnalytics(req *model.AnalyticsRequest) (*model.ReportAnalytics, error) {
	return s.analyticsRepo.GetReportAnalytics(req)
}

// GetUserAnalytics 获取用户分析数据
func (s *analyticsService) GetUserAnalytics(req *model.AnalyticsRequest) (*model.UserAnalytics, error) {
	return s.analyticsRepo.GetUserAnalytics(req)
}

// ExportData 导出数据
func (s *analyticsService) ExportData(req *model.ExportRequest) (*model.ExportResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("导出请求不能为空")
	}
	switch req.Format {
	case model.ExportFormatCSV:
		return s.exportToCSV(req)
	case model.ExportFormatExcel:
		return s.exportToExcel(req)
	case model.ExportFormatPDF:
		return s.exportToPDF(req)
	default:
		return nil, fmt.Errorf("不支持的导出格式: %s", req.Format)
	}
}

// parseTimeRange 解析时间范围
func (s *analyticsService) parseTimeRange(req *model.AnalyticsRequest) (time.Time, time.Time, error) {
	if req == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("分析请求不能为空")
	}
	now := time.Now()
	endDate := now
	var err error
	if req.EndDate != "" {
		endDate, err = time.Parse("2006-01-02", req.EndDate)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("无效的结束日期格式: %s", req.EndDate)
		}
		// Explicit dates include the entire end day. Repository bounds are exclusive.
		endDate = endDate.AddDate(0, 0, 1)
	}
	startDate := endDate.AddDate(0, 0, -30)
	if req.StartDate != "" {
		startDate, err = time.Parse("2006-01-02", req.StartDate)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("无效的开始日期格式: %s", req.StartDate)
		}
	}
	if !startDate.Before(endDate) {
		return time.Time{}, time.Time{}, fmt.Errorf("开始日期不能晚于结束日期")
	}
	return startDate, endDate, nil
}

// exportToCSV 导出为CSV格式
func (s *analyticsService) exportToCSV(req *model.ExportRequest) (*model.ExportResponse, error) {
	filters, err := exportAnalyticsRequest(req)
	if err != nil {
		return nil, err
	}
	downloadQuery := url.Values{"type": {req.Type}, "format": {model.ExportFormatCSV}}
	for key, value := range map[string]string{
		"start_date": filters.StartDate, "end_date": filters.EndDate, "asset_id": filters.AssetID, "user_id": filters.UserID,
		"severity": filters.Severity, "status": filters.Status, "category": filters.Category, "granularity": filters.Granularity,
	} {
		if value != "" {
			downloadQuery.Set(key, value)
		}
	}
	var export func(*csv.Writer, *model.ExportRequest) error
	switch req.Type {
	case model.ExportTypeDashboard:
		export = s.exportDashboardToCSV
	case model.ExportTypeVulnerability:
		export = s.exportVulnerabilityToCSV
	case model.ExportTypeAsset:
		export = s.exportAssetToCSV
	case model.ExportTypeReport:
		export = s.exportReportToCSV
	case model.ExportTypeUser:
		export = s.exportUserToCSV
	default:
		return nil, fmt.Errorf("不支持的导出类型: %s", req.Type)
	}
	if err := os.MkdirAll("exports", 0700); err != nil {
		return nil, fmt.Errorf("创建导出目录失败: %w", err)
	}
	// Unique names avoid overwriting another concurrent export.
	file, err := os.CreateTemp("exports", req.Type+"_*.csv")
	if err != nil {
		return nil, fmt.Errorf("创建文件失败: %w", err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(file.Name())
		}
	}()
	writer := csv.NewWriter(file)
	if err := export(writer, req); err != nil {
		return nil, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("写入CSV失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("关闭CSV失败: %w", err)
	}
	response, err := s.createExportResponse(file.Name(), filepath.Base(file.Name()), "/api/v1/analytics/export?"+downloadQuery.Encode())
	if err != nil {
		return nil, err
	}
	complete = true
	return response, nil
}

func exportAnalyticsRequest(req *model.ExportRequest) (*model.AnalyticsRequest, error) {
	result := &model.AnalyticsRequest{StartDate: req.StartDate, EndDate: req.EndDate}
	fields := map[string]*string{"asset_id": &result.AssetID, "user_id": &result.UserID, "severity": &result.Severity, "status": &result.Status, "category": &result.Category, "granularity": &result.Granularity}
	for key, value := range req.Filters {
		field, ok := fields[key]
		if !ok {
			return nil, fmt.Errorf("不支持的导出筛选条件: %s", key)
		}
		switch v := value.(type) {
		case string:
			*field = v
		case float64:
			*field = strconv.FormatFloat(v, 'f', -1, 64)
		default:
			return nil, fmt.Errorf("无效的导出筛选条件: %s", key)
		}
	}
	return result, nil
}

// exportDashboardToCSV 导出仪表盘数据为CSV
func (s *analyticsService) exportDashboardToCSV(writer *csv.Writer, req *model.ExportRequest) error {
	stats, err := s.GetDashboardStats()
	if err != nil {
		return err
	}

	// 写入标题
	writer.Write([]string{"指标", "数值"})

	// 写入总体统计
	writer.Write([]string{"总漏洞数", strconv.FormatInt(stats.TotalVulnerabilities, 10)})
	writer.Write([]string{"总资产数", strconv.FormatInt(stats.TotalAssets, 10)})
	writer.Write([]string{"总用户数", strconv.FormatInt(stats.TotalUsers, 10)})
	writer.Write([]string{"总报告数", strconv.FormatInt(stats.TotalReports, 10)})

	// 写入漏洞状态统计
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"漏洞状态", "数量"})
	writer.Write([]string{"开放", strconv.FormatInt(stats.VulnerabilityStats.Open, 10)})
	writer.Write([]string{"处理中", strconv.FormatInt(stats.VulnerabilityStats.InProgress, 10)})
	writer.Write([]string{"已解决", strconv.FormatInt(stats.VulnerabilityStats.Resolved, 10)})
	writer.Write([]string{"已关闭", strconv.FormatInt(stats.VulnerabilityStats.Closed, 10)})
	writer.Write([]string{"重新开放", strconv.FormatInt(stats.VulnerabilityStats.Reopened, 10)})

	// 写入严重程度统计
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"严重程度", "数量"})
	for _, severity := range stats.SeverityStats {
		writer.Write([]string{severity.Severity, strconv.FormatInt(severity.Count, 10)})
	}

	return writer.Error()
}

// exportVulnerabilityToCSV 导出漏洞数据为CSV
func (s *analyticsService) exportVulnerabilityToCSV(writer *csv.Writer, req *model.ExportRequest) error {
	analyticsReq, err := exportAnalyticsRequest(req)
	if err != nil {
		return err
	}

	analytics, err := s.GetVulnerabilityAnalytics(analyticsReq)
	if err != nil {
		return err
	}

	// 写入时间范围统计
	writer.Write([]string{"时间范围", "数量"})
	writer.Write([]string{"今天", strconv.FormatInt(analytics.TimeRangeStats.Today, 10)})
	writer.Write([]string{"昨天", strconv.FormatInt(analytics.TimeRangeStats.Yesterday, 10)})
	writer.Write([]string{"本周", strconv.FormatInt(analytics.TimeRangeStats.ThisWeek, 10)})
	writer.Write([]string{"上周", strconv.FormatInt(analytics.TimeRangeStats.LastWeek, 10)})
	writer.Write([]string{"本月", strconv.FormatInt(analytics.TimeRangeStats.ThisMonth, 10)})
	writer.Write([]string{"上月", strconv.FormatInt(analytics.TimeRangeStats.LastMonth, 10)})

	// 写入状态分布
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"状态", "数量"})
	for _, status := range analytics.StatusDistribution {
		writer.Write([]string{status.Status, strconv.FormatInt(status.Count, 10)})
	}

	// 写入OWASP分类统计
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"OWASP分类", "数量"})
	for _, owasp := range analytics.OWASPStats {
		writer.Write([]string{owasp.Category, strconv.FormatInt(owasp.Count, 10)})
	}

	return writer.Error()
}

// exportAssetToCSV 导出资产数据为CSV
func (s *analyticsService) exportAssetToCSV(writer *csv.Writer, req *model.ExportRequest) error {
	analyticsReq, err := exportAnalyticsRequest(req)
	if err != nil {
		return err
	}

	analytics, err := s.GetAssetAnalytics(analyticsReq)
	if err != nil {
		return err
	}

	// 写入资产类型分布
	writer.Write([]string{"资产类型", "数量"})
	for _, assetType := range analytics.TypeDistribution {
		writer.Write([]string{assetType.Type, strconv.FormatInt(assetType.Count, 10)})
	}

	// 写入重要性分布
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"重要性级别", "数量"})
	for _, importance := range analytics.ImportanceDistribution {
		writer.Write([]string{importance.Importance, strconv.FormatInt(importance.Count, 10)})
	}

	// 写入风险评估
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"资产名称", "资产类型", "风险评分", "漏洞总数", "严重漏洞", "高危漏洞"})
	for _, risk := range analytics.RiskAssessment {
		writer.Write([]string{
			risk.AssetName,
			risk.AssetType,
			strconv.Itoa(risk.RiskScore),
			strconv.FormatInt(risk.VulnerabilityCount, 10),
			strconv.FormatInt(risk.CriticalCount, 10),
			strconv.FormatInt(risk.HighCount, 10),
		})
	}

	return writer.Error()
}

// exportReportToCSV 导出报告数据为CSV
func (s *analyticsService) exportReportToCSV(writer *csv.Writer, req *model.ExportRequest) error {
	analyticsReq, err := exportAnalyticsRequest(req)
	if err != nil {
		return err
	}

	analytics, err := s.GetReportAnalytics(analyticsReq)
	if err != nil {
		return err
	}

	// 写入状态分布
	writer.Write([]string{"报告状态", "数量"})
	for _, status := range analytics.StatusDistribution {
		writer.Write([]string{status.Status, strconv.FormatInt(status.Count, 10)})
	}

	// 写入类型分布
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"报告类型", "数量"})
	for _, reportType := range analytics.TypeDistribution {
		writer.Write([]string{reportType.Type, strconv.FormatInt(reportType.Count, 10)})
	}

	// 写入提交者统计
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"提交者", "真实姓名", "提交数量"})
	for _, submitter := range analytics.SubmitterStats {
		writer.Write([]string{
			submitter.Username,
			submitter.RealName,
			strconv.FormatInt(submitter.Count, 10),
		})
	}

	return writer.Error()
}

// exportUserToCSV 导出用户数据为CSV
func (s *analyticsService) exportUserToCSV(writer *csv.Writer, req *model.ExportRequest) error {
	analyticsReq, err := exportAnalyticsRequest(req)
	if err != nil {
		return err
	}

	analytics, err := s.GetUserAnalytics(analyticsReq)
	if err != nil {
		return err
	}

	// 写入角色分布
	writer.Write([]string{"用户角色", "数量"})
	for _, role := range analytics.RoleDistribution {
		writer.Write([]string{role.RoleName, strconv.FormatInt(role.Count, 10)})
	}

	// 写入状态分布
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"用户状态", "数量"})
	for _, status := range analytics.StatusDistribution {
		writer.Write([]string{status.Status, strconv.FormatInt(status.Count, 10)})
	}

	// 写入活动统计
	writer.Write([]string{""}) // 空行
	writer.Write([]string{"用户名", "真实姓名", "发现漏洞数", "提交报告数"})
	for _, activity := range analytics.ActivityStats {
		writer.Write([]string{
			activity.Username,
			activity.RealName,
			strconv.FormatInt(activity.VulnerabilitiesFound, 10),
			strconv.FormatInt(activity.ReportsSubmitted, 10),
		})
	}

	return writer.Error()
}

// exportToExcel 导出为Excel格式
func (s *analyticsService) exportToExcel(req *model.ExportRequest) (*model.ExportResponse, error) {
	// TODO: 实现Excel导出功能
	return nil, fmt.Errorf("Excel导出功能暂未实现")
}

// exportToPDF 导出为PDF格式
func (s *analyticsService) exportToPDF(req *model.ExportRequest) (*model.ExportResponse, error) {
	// TODO: 实现PDF导出功能
	return nil, fmt.Errorf("PDF导出功能暂未实现")
}

// createExportResponse 创建导出响应
func (s *analyticsService) createExportResponse(filePath, fileName, fileURL string) (*model.ExportResponse, error) {
	// 获取文件大小
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %v", err)
	}

	return &model.ExportResponse{
		FileName: fileName,
		FileURL:  fileURL,
		FileSize: fileInfo.Size(),
	}, nil
}
