import axios from 'axios';
import { apiClient } from './api';
import { ApiResponse } from '../types/api';
import { getAuthError, TwoFactorSetup, TwoFactorStatus, TwoFactorVerification } from '../types/auth';

// 用户资料更新请求
export interface UserProfileUpdateRequest {
  username?: string;
  real_name?: string;
  email?: string;
  phone?: string;
  department?: string;
}

// 修改密码请求
export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
  confirm_password: string;
}

// 系统设置
export interface SystemSettings {
  id: number;
  user_id: number;
  theme: 'light' | 'dark' | 'system';
  language: 'zh-CN' | 'en-US';
  timezone: string;
  date_format: string;
  time_format: '12h' | '24h';
  created_at: string;
  updated_at: string;
}

// 系统设置更新请求
export interface SystemSettingsRequest {
  theme?: 'light' | 'dark' | 'system';
  language?: 'zh-CN' | 'en-US';
  timezone?: string;
  date_format?: string;
  time_format?: '12h' | '24h';
}

// 通知设置
export interface NotificationSettings {
  id: number;
  user_id: number;
  // 漏洞相关通知
  vuln_new_email: boolean;
  vuln_new_push: boolean;
  vuln_new_sms: boolean;
  vuln_assigned_email: boolean;
  vuln_assigned_push: boolean;
  vuln_assigned_sms: boolean;
  vuln_fixed_email: boolean;
  vuln_fixed_push: boolean;
  vuln_fixed_sms: boolean;
  // 报告相关通知
  report_email: boolean;
  report_push: boolean;
  report_sms: boolean;
  // 系统相关通知
  system_email: boolean;
  system_push: boolean;
  system_sms: boolean;
  // 社交相关通知
  social_email: boolean;
  social_push: boolean;
  social_sms: boolean;
  created_at: string;
  updated_at: string;
}

// 通知设置更新请求
export interface NotificationSettingsRequest {
  vuln_new_email?: boolean;
  vuln_new_push?: boolean;
  vuln_new_sms?: boolean;
  vuln_assigned_email?: boolean;
  vuln_assigned_push?: boolean;
  vuln_assigned_sms?: boolean;
  vuln_fixed_email?: boolean;
  vuln_fixed_push?: boolean;
  vuln_fixed_sms?: boolean;
  report_email?: boolean;
  report_push?: boolean;
  report_sms?: boolean;
  system_email?: boolean;
  system_push?: boolean;
  system_sms?: boolean;
  social_email?: boolean;
  social_push?: boolean;
  social_sms?: boolean;
}

class SettingsService {
  // 用户资料管理
  async updateProfile(data: UserProfileUpdateRequest): Promise<void> {
    const response = await apiClient.put<void>('/settings/profile', data);
    return response.data;
  }

  async changePassword(data: ChangePasswordRequest): Promise<void> {
    const response = await apiClient.put<void>('/settings/password', data);
    return response.data;
  }

  // 双因素认证管理
  private async rebindRequest<T>(path: string, token: string, data?: unknown): Promise<T> {
    const baseURL = import.meta.env.VITE_API_BASE_URL || (
      import.meta.env.MODE === 'production' ? '/api/v1' : 'http://localhost:8080/api/v1'
    );
    try {
      const response = await axios.post<ApiResponse<T>>(`${baseURL}${path}`, data, {
        timeout: 30000,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      });
      if (!response.data?.data) throw new Error(response.data?.message || '认证响应无效');
      return response.data.data;
    } catch (error: unknown) {
      const details = getAuthError(error, '认证请求失败');
      throw Object.assign(new Error(details.message), { code: details.code });
    }
  }

  async setup2FA(rebindToken?: string): Promise<TwoFactorSetup> {
    if (rebindToken) return this.rebindRequest<TwoFactorSetup>('/settings/2fa/setup', rebindToken);
    const response = await apiClient.post<TwoFactorSetup>('/settings/2fa/setup');
    return response.data!;
  }

  async verify2FA(code: string, rebindToken?: string): Promise<TwoFactorVerification> {
    if (rebindToken) {
      return this.rebindRequest<TwoFactorVerification>('/settings/2fa/verify', rebindToken, { code });
    }
    const response = await apiClient.post<TwoFactorVerification>('/settings/2fa/verify', { code });
    return response.data!;
  }

  async disable2FA(code: string): Promise<void> {
    await apiClient.delete('/settings/2fa', { data: { code } });
  }

  async get2FAStatus(): Promise<TwoFactorStatus> {
    const response = await apiClient.get<TwoFactorStatus>('/settings/2fa/status');
    return response.data!;
  }

  async revokeAllSessions(): Promise<void> {
    await apiClient.post('/revoke-all');
  }

  // 系统设置管理
  async getSystemSettings(): Promise<SystemSettings> {
    const response = await apiClient.get<SystemSettings>('/settings/system');
    return response.data!;
  }

  async updateSystemSettings(data: SystemSettingsRequest): Promise<void> {
    const response = await apiClient.put<void>('/settings/system', data);
    return response.data;
  }

  // 通知设置管理
  async getNotificationSettings(): Promise<NotificationSettings> {
    const response = await apiClient.get<NotificationSettings>('/settings/notifications');
    return response.data!;
  }

  async updateNotificationSettings(data: NotificationSettingsRequest): Promise<void> {
    const response = await apiClient.put<void>('/settings/notifications', data);
    return response.data;
  }

  // 数据管理
  async exportData(type: 'profile' | 'settings' | 'all'): Promise<Blob> {
    const response = await apiClient.get<Blob>(`/settings/export?type=${type}`, {
      responseType: 'blob',
    });
    return response.data!;
  }

  async importData(file: File, type: string): Promise<void> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('type', type);

    const response = await apiClient.post<void>('/settings/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  // 系统维护
  async clearCache(): Promise<void> {
    const response = await apiClient.post<void>('/settings/cache/clear');
    return response.data;
  }

  async optimizeDatabase(): Promise<void> {
    const response = await apiClient.post<void>('/settings/database/optimize');
    return response.data;
  }

  // 辅助方法
  downloadFile(blob: Blob, filename: string): void {
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }
}

export const settingsService = new SettingsService();
export default settingsService;
