import { apiClient, buildQueryString } from './api';
import {
  Report,
  ReportSearchParams,
  PaginatedResponse,
} from '../types/api';

export class ReportsService {
  // Get reports list with pagination and filtering
  async getReports(params: ReportSearchParams = {}, signal?: AbortSignal): Promise<PaginatedResponse<Report>> {
    const queryString = buildQueryString(params);
    const response = await apiClient.get<PaginatedResponse<Report>>(`/reports${queryString}`, { signal });
    return response.data!;
  }

  // Get report by ID
  async getReport(id: number): Promise<Report> {
    const response = await apiClient.get<Report>(`/reports/${id}`);
    return response.data!;
  }

  // Get report content/preview
  async getReportContent(id: number): Promise<string> {
    const response = await apiClient.get<string>(`/reports/${id}/content`, {
      headers: {
        'Accept': 'text/html,text/plain,*/*'
      }
    });
    return response.data!;
  }

  async getReportBlob(id: number, signal?: AbortSignal): Promise<Blob> {
    const response = await apiClient.getClient().get(`/reports/${id}/download`, { responseType: 'blob', signal });
    return response.data as Blob;
  }

  // Create new report (alias for uploadReport for consistency)
  async createReport(formData: FormData): Promise<Report> {
    const response = await apiClient.upload<Report>('/reports', formData);
    return response.data!;
  }

  // Upload new report
  async uploadReport(data: {
    file: File;
    title: string;
    description?: string;
    type: string;
    severity: string;
    asset_ids?: number[];
    tags?: string[];
    test_date?: string;
  }): Promise<Report> {
    const formData = new FormData();
    formData.append('file', data.file);
    formData.append('title', data.title);

    if (data.description) formData.append('description', data.description);
    formData.append('type', data.type);
    formData.append('severity', data.severity);

    if (data.asset_ids?.length) {
      data.asset_ids.forEach(id => formData.append('asset_ids', String(id)));
    }

    if (data.tags?.length) {
      data.tags.forEach(tag => formData.append('tags', tag));
    }

    if (data.test_date) formData.append('test_date', data.test_date);

    const response = await apiClient.upload<Report>('/reports', formData);
    return response.data!;
  }

  // Update report
  async updateReport(id: number, data: Partial<Report>): Promise<Report> {
    const response = await apiClient.put<Report>(`/reports/${id}`, data);
    return response.data!;
  }

  // Delete report
  async deleteReport(id: number): Promise<void> {
    await apiClient.delete(`/reports/${id}`);
  }

  // Download report
  async downloadReport(id: number, filename?: string): Promise<void> {
    await apiClient.download(`/reports/${id}/download`, filename);
  }

  // Get report statistics
  async getReportStats(): Promise<unknown> {
    const response = await apiClient.get('/reports/stats');
    return response.data!;
  }

  // Get report types
  getReportTypes(): Array<{ value: string; label: string }> {
    return [
      { value: 'penetration_test', label: '渗透测试' },
      { value: 'vulnerability_assessment', label: '漏洞评估' },
      { value: 'security_audit', label: '安全审计' },
      { value: 'compliance_check', label: '合规检查' },
      { value: 'other', label: '其他' },
    ];
  }

  // Get severity levels
  getSeverityLevels(): Array<{ value: string; label: string; color: string }> {
    return [
      { value: 'critical', label: '严重', color: 'red' },
      { value: 'high', label: '高危', color: 'orange' },
      { value: 'medium', label: '中危', color: 'yellow' },
      { value: 'low', label: '低危', color: 'blue' },
      { value: 'info', label: '信息', color: 'gray' },
    ];
  }
}

export const reportsService = new ReportsService();

// Re-export types for convenience
export type { ReportSearchParams } from '../types/api';
