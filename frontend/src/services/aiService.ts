import { apiClient } from './api';

// AI配置相关类型
export interface AIConfiguration {
  id?: number;
  user_id?: number;
  provider: string;
  api_key?: string;
  has_api_key?: boolean;
  api_url?: string;
  model?: string;
  max_tokens: number;
  temperature: number;
  timeout: number;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface AIConfigurationRequest {
  provider: string;
  api_key?: string;
  clear_api_key?: boolean;
  api_url?: string;
  model?: string;
  max_tokens: number;
  temperature: number;
  timeout: number;
  enabled: boolean;
}

export interface AITestRequest {
  provider: string;
  api_key: string;
  api_url?: string;
  model?: string;
  test_message?: string;
}

export interface AIProvider {
  id: string;
  name: string;
  description: string;
  api_url: string;
  models: string[];
  default_model: string;
  requires_key: boolean;
}

export interface AIConversation {
  id: number;
  user_id: number;
  session_id: string;
  title: string;
  messages: string;
  tokens_used: number;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface AIChatRequest {
  session_id?: string;
  message: string;
  context?: string;
}

export interface AIChatResponse {
  session_id: string;
  message: string;
  tokens_used: number;
  suggestions?: string[];
}

export interface AIUsageStats {
  total_conversations: number;
  total_messages: number;
  total_tokens: number;
  active_sessions: number;
}

export interface AIMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  tokens?: number;
}

class AIService {
  // AI配置管理
  async getAIConfiguration(): Promise<AIConfiguration> {
    const response = await apiClient.get<AIConfiguration>('/ai/config');
    return response.data!;
  }

  async saveAIConfiguration(config: AIConfigurationRequest): Promise<void> {
    await apiClient.post('/ai/config', config);
  }

  async testAIConnection(testRequest: AITestRequest): Promise<void> {
    await apiClient.post('/ai/test', testRequest);
  }

  async getSupportedProviders(): Promise<AIProvider[]> {
    const response = await apiClient.get<AIProvider[]>('/ai/providers');
    return response.data!;
  }

  // AI对话管理
  async startConversation(title?: string): Promise<AIConversation> {
    const response = await apiClient.post<AIConversation>('/ai/conversation', { title });
    return response.data!;
  }

  async sendMessage(request: AIChatRequest): Promise<AIChatResponse> {
    const response = await apiClient.post<AIChatResponse>('/ai/chat', request);
    return response.data!;
  }

  async getConversations(page: number = 1, pageSize: number = 20): Promise<{
    items: AIConversation[];
    total: number;
    page: number;
    page_size: number;
  }> {
    const response = await apiClient.get<{ items: AIConversation[]; total: number; page: number; page_size: number }>('/ai/conversations', {
      params: { page, page_size: pageSize }
    });
    return response.data!;
  }

  async deleteConversation(sessionId: string): Promise<void> {
    await apiClient.delete(`/ai/conversation/${sessionId}`);
  }

  // AI使用统计
  async getUsageStats(): Promise<AIUsageStats> {
    const response = await apiClient.get<AIUsageStats>('/ai/stats');
    return response.data!;
  }

  // 辅助方法
  parseMessages(messagesJson: string): AIMessage[] {
    try {
      return JSON.parse(messagesJson || '[]');
    } catch {
      return [];
    }
  }

  formatTokenCount(tokens: number): string {
    if (tokens < 1000) {
      return tokens.toString();
    } else if (tokens < 1000000) {
      return `${(tokens / 1000).toFixed(1)}K`;
    } else {
      return `${(tokens / 1000000).toFixed(1)}M`;
    }
  }

  getProviderDisplayName(providerId: string): string {
    const providerNames: Record<string, string> = {
      'openai': 'OpenAI',
      'deepseek': 'DeepSeek',
      'qwen': '通义千问',
      'custom': '自定义'
    };
    return providerNames[providerId] || providerId;
  }

  getModelDisplayName(model: string): string {
    const modelNames: Record<string, string> = {
      'gpt-3.5-turbo': 'GPT-3.5 Turbo',
      'gpt-4': 'GPT-4',
      'gpt-4-turbo': 'GPT-4 Turbo',
      'gpt-4o': 'GPT-4o',
      'deepseek-chat': 'DeepSeek Chat',
      'deepseek-coder': 'DeepSeek Coder',
      'qwen-turbo': 'Qwen Turbo',
      'qwen-plus': 'Qwen Plus',
      'qwen-max': 'Qwen Max',
      'qwen-max-longcontext': 'Qwen Max (Long Context)'
    };
    return modelNames[model] || model;
  }

  validateConfiguration(config: AIConfigurationRequest, hasSavedKey = false): string[] {
    const errors: string[] = [];

    if (!config.provider) {
      errors.push('请选择AI提供商');
    }

    if (config.enabled && (!config.api_key && !hasSavedKey || config.clear_api_key)) {
      errors.push('启用AI助手时必须提供API密钥');
    }

    if (config.max_tokens < 1 || config.max_tokens > 32000) {
      errors.push('最大Token数必须在1-32000之间');
    }

    if (config.temperature < 0 || config.temperature > 2) {
      errors.push('温度参数必须在0-2之间');
    }

    if (config.timeout < 5 || config.timeout > 300) {
      errors.push('超时时间必须在5-300秒之间');
    }

    if (config.api_url && !this.isValidUrl(config.api_url)) {
      errors.push('API地址格式不正确');
    }

    return errors;
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  // 生成系统上下文信息
  generateSystemContext(): string {
    const context = {
      timestamp: new Date().toISOString(),
      page: window.location.pathname,
      userAgent: navigator.userAgent,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };

    return `当前系统信息：
- 时间：${context.timestamp}
- 页面：${context.page}
- 语言：${context.language}
- 时区：${context.timezone}`;
  }

  // 生成建议的配置问题
  getConfigurationSuggestions(): string[] {
    return [
      '如何选择合适的AI模型？',
      '不同提供商的特点是什么？',
      'Token数量如何影响响应质量？',
      '温度参数如何调节？',
      '如何优化API调用成本？'
    ];
  }

  // 生成系统管理建议问题
  getSystemManagementSuggestions(): string[] {
    return [
      '如何配置系统邮件通知？',
      '推荐的日期时间格式是什么？',
      '如何设置多语言支持？',
      '系统性能优化建议？',
      '如何备份系统配置？'
    ];
  }
}

export const aiService = new AIService();
