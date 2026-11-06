import { apiClient, buildQueryString } from './api';
import { DashboardStats } from '../types/api';

export class AnalyticsService {
  // Get dashboard statistics
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await apiClient.get<DashboardStats>('/analytics/dashboard');
    return response.data!;
  }

  // Get monthly vulnerability trends
  async getMonthlyVulnerabilityTrends(): Promise<Array<{
    month: string;
    vulnerabilities: number;
    resolved: number;
  }>> {
    const response = await apiClient.get<Array<{ month: string; vulnerabilities: number; resolved: number }>>('/analytics/vulnerability/monthly-trends');
    return response.data!;
  }

  // Get system overview
  async getOverview(): Promise<unknown> {
    const response = await apiClient.get('/analytics/overview');
    return response.data!;
  }

  // Get vulnerability analytics
  async getVulnerabilityAnalytics(): Promise<unknown> {
    const response = await apiClient.get('/analytics/vulnerability');
    return response.data!;
  }

  // Get vulnerability trend data
  async getVulnerabilityTrend(params: {
    start_date?: string;
    end_date?: string;
    granularity?: 'day' | 'week' | 'month';
  } = {}): Promise<unknown> {
    const queryString = buildQueryString(params);
    const response = await apiClient.get(`/analytics/vulnerability/trend${queryString}`);
    return response.data!;
  }

  // Get asset analytics
  async getAssetAnalytics(): Promise<unknown> {
    const response = await apiClient.get('/analytics/asset');
    return response.data!;
  }

  // Export analytics data
  async exportData(params: {
    type: 'dashboard' | 'vulnerability' | 'asset' | 'report' | 'user';
    format?: 'csv';
    start_date?: string;
    end_date?: string;
  }): Promise<void> {
    const queryString = buildQueryString({ ...params, format: 'csv' });
    try {
      await apiClient.download(`/analytics/export${queryString}`, `analytics_${params.type}_${new Date().toISOString().split('T')[0]}.csv`);
    } catch (error: unknown) {
      // Blob responses also contain JSON API errors; preserve the server message.
      const apiError = error as { details?: unknown; message?: string };
      if (apiError.details instanceof Blob) {
        let message: string | undefined;
        try {
          const body = JSON.parse(await apiError.details.text()) as { message?: string };
          message = body.message;
        } catch {
          // Keep the existing API error when the response is not JSON.
        }
        if (message) throw new Error(message, { cause: error });
      }
      throw error;
    }
  }
}

export const analyticsService = new AnalyticsService();
