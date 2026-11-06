import { apiClient } from './api';

export interface SystemInfo {
  name: string;
  version: string;
  status: string;
  first_deploy: boolean;
  has_admin_file: boolean;
}

export interface ClientConfig {
  system_name: string;
  version: string;
  first_deploy: boolean;
  has_admin_file: boolean;
  login_tips: {
    show_first_deploy_tip: boolean;
    admin_username: string;
    credential_file: string;
  };
}

class SystemService {
  // 获取系统信息
  async getSystemInfo(): Promise<SystemInfo> {
    const response = await apiClient.get<SystemInfo>('/public/system/info');
    return response.data!;
  }

  // 获取客户端配置
  async getClientConfig(): Promise<ClientConfig> {
    const response = await apiClient.get<ClientConfig>('/public/client-config');
    return response.data!;
  }

  // 获取公开配置
  async getPublicConfigs(): Promise<unknown[]> {
    const response = await apiClient.get<unknown[]>('/public/configs');
    return response.data!;
  }
}

export const systemService = new SystemService();