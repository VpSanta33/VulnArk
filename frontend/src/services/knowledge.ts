import { apiClient } from './api';

// Knowledge Base Types
export interface KnowledgeBase {
  id: number;
  created_at: string;
  updated_at: string;
  title: string;
  content: string;
  summary: string;
  category: string;
  category_text: string;
  type: string;
  type_text: string;
  severity: string;
  severity_text: string;
  status: string;
  status_text: string;
  view_count: number;
  like_count: number;
  author_id: number;
  reviewer_id?: number;
  reviewed_at?: string;
  published_at?: string;
  tags: TagInfo[];
  metadata: Record<string, unknown>;
  author: UserInfo;
  reviewer?: UserInfo;
}

export interface TagInfo {
  id: number;
  name: string;
  display_name: string;
  description: string;
  color: string;
  category: string;
  is_active: boolean;
}

export interface UserInfo {
  id: number;
  username: string;
  real_name: string;
  email: string;
  avatar?: string;
  department?: string;
}

export interface KnowledgeCreateRequest {
  title: string;
  content: string;
  summary?: string;
  category: string;
  type: string;
  severity?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface KnowledgeUpdateRequest {
  title?: string;
  content?: string;
  summary?: string;
  category?: string;
  type?: string;
  severity?: string;
  status?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface KnowledgeSearchRequest {
  page?: number;
  page_size?: number;
  keyword?: string;
  category?: string;
  type?: string;
  severity?: string;
  status?: string;
  author_id?: number;
  tags?: string[];
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export interface KnowledgeStats {
  total_count: number;
  published_count: number;
  draft_count: number;
  archived_count: number;
  category_stats: Array<{
    category: string;
    count: number;
  }>;
  type_stats: Array<{
    type: string;
    count: number;
  }>;
  popular_tags: Array<{
    tag: string;
    count: number;
  }>;
}

export interface Template {
  id: number;
  created_at: string;
  updated_at: string;
  name: string;
  display_name: string;
  description: string;
  type: string;
  category: string;
  content: string;
  variables: string;
  is_active: boolean;
  usage_count: number;
  creator_id: number;
}

export interface TemplateCreateRequest {
  name: string;
  display_name: string;
  description?: string;
  type: string;
  category: string;
  content: string;
  variables?: string;
}

class KnowledgeService {
  // Knowledge Base Management
  async createKnowledge(data: KnowledgeCreateRequest): Promise<KnowledgeBase> {
    const response = await apiClient.post<KnowledgeBase>('/knowledge', data);
    return response.data!;
  }

  async getKnowledgeList(params: KnowledgeSearchRequest = {}): Promise<{
    data: KnowledgeBase[];
    total: number;
    page: number;
    page_size: number;
  }> {
    const response = await apiClient.get<{ data: KnowledgeBase[]; total: number; page: number; page_size: number }>('/knowledge', { params });
    const result = response.data!;

    // Parse tags from string to array for each knowledge item
    if (result.data) {
      result.data = result.data.map((knowledge) => ({
        ...knowledge,
        tags: this.parseTagsFromString(knowledge.tags),
        category_text: this.getCategoryText(knowledge.category),
        type_text: this.getTypeText(knowledge.type),
        severity_text: knowledge.severity ? this.getSeverityText(knowledge.severity) : '',
        status_text: this.getStatusText(knowledge.status),
      }));
    }

    return result;
  }

  async getKnowledgeById(id: number): Promise<KnowledgeBase> {
    const response = await apiClient.get<KnowledgeBase>(`/knowledge/${id}`);
    const knowledge = response.data!;

    // Parse tags and add text fields
    return {
      ...knowledge,
      tags: this.parseTagsFromString(knowledge.tags),
      category_text: this.getCategoryText(knowledge.category),
      type_text: this.getTypeText(knowledge.type),
      severity_text: knowledge.severity ? this.getSeverityText(knowledge.severity) : '',
      status_text: this.getStatusText(knowledge.status),
    };
  }

  async updateKnowledge(id: number, data: KnowledgeUpdateRequest): Promise<void> {
    await apiClient.put(`/knowledge/${id}`, data);
  }

  async deleteKnowledge(id: number): Promise<void> {
    await apiClient.delete(`/knowledge/${id}`);
  }

  async getKnowledgeStats(): Promise<KnowledgeStats> {
    const response = await apiClient.get<KnowledgeStats>('/knowledge/stats');
    return response.data!;
  }

  // Knowledge Base Operations
  async likeKnowledge(id: number): Promise<void> {
    await apiClient.post(`/knowledge/${id}/like`);
  }

  async publishKnowledge(id: number): Promise<void> {
    await apiClient.post(`/knowledge/${id}/publish`);
  }

  async archiveKnowledge(id: number): Promise<void> {
    await apiClient.post(`/knowledge/${id}/archive`);
  }

  // Search and Recommendations
  async searchKnowledge(keyword: string, limit: number = 10): Promise<KnowledgeBase[]> {
    const response = await apiClient.get<KnowledgeBase[]>('/knowledge/search', {
      params: { q: keyword, limit }
    });
    return this.parseKnowledgeArray(response.data!);
  }

  async getPopularKnowledge(limit: number = 10): Promise<KnowledgeBase[]> {
    const response = await apiClient.get<KnowledgeBase[]>('/knowledge/popular', {
      params: { limit }
    });
    return this.parseKnowledgeArray(response.data!);
  }

  async getRecentKnowledge(limit: number = 10): Promise<KnowledgeBase[]> {
    const response = await apiClient.get<KnowledgeBase[]>('/knowledge/recent', {
      params: { limit }
    });
    return this.parseKnowledgeArray(response.data!);
  }

  async getRelatedKnowledge(id: number, limit: number = 5): Promise<KnowledgeBase[]> {
    const response = await apiClient.get<KnowledgeBase[]>(`/knowledge/${id}/related`, {
      params: { limit }
    });
    return this.parseKnowledgeArray(response.data!);
  }

  // Tags Management
  async getTags(): Promise<TagInfo[]> {
    const response = await apiClient.get<TagInfo[]>('/tags');
    return response.data!;
  }

  async createTag(data: { name: string; display_name: string; description?: string; color?: string; category?: string }): Promise<TagInfo> {
    const response = await apiClient.post<TagInfo>('/tags', data);
    return response.data!;
  }

  // Templates Management
  async getTemplates(): Promise<Template[]> {
    const response = await apiClient.get<Template[]>('/templates');
    return response.data!;
  }

  async getTemplateById(id: number): Promise<Template> {
    const response = await apiClient.get<Template>(`/templates/${id}`);
    return response.data!;
  }

  async createTemplate(data: TemplateCreateRequest): Promise<Template> {
    const response = await apiClient.post<Template>('/templates', data);
    return response.data!;
  }

  async updateTemplate(id: number, data: Partial<TemplateCreateRequest>): Promise<void> {
    await apiClient.put(`/templates/${id}`, data);
  }

  async deleteTemplate(id: number): Promise<void> {
    await apiClient.delete(`/templates/${id}`);
  }

  // Utility Methods
  getCategoryOptions() {
    return [
      { value: 'vulnerability', label: '漏洞相关' },
      { value: 'security', label: '安全防护' },
      { value: 'tool', label: '工具使用' },
      { value: 'guide', label: '操作指南' },
      { value: 'best_practice', label: '最佳实践' },
    ];
  }

  getTypeOptions() {
    return [
      { value: 'article', label: '技术文章' },
      { value: 'tutorial', label: '教程指南' },
      { value: 'faq', label: '常见问题' },
      { value: 'solution', label: '解决方案' },
      { value: 'reference', label: '参考资料' },
    ];
  }

  getSeverityOptions() {
    return [
      { value: 'low', label: '低' },
      { value: 'medium', label: '中' },
      { value: 'high', label: '高' },
      { value: 'critical', label: '严重' },
    ];
  }

  getStatusOptions() {
    return [
      { value: 'draft', label: '草稿' },
      { value: 'published', label: '已发布' },
      { value: 'archived', label: '已归档' },
    ];
  }

  // Helper methods for parsing and formatting
  parseKnowledgeArray(knowledgeArray: KnowledgeBase[]): KnowledgeBase[] {
    return knowledgeArray.map(knowledge => ({
      ...knowledge,
      tags: this.parseTagsFromString(knowledge.tags),
      category_text: this.getCategoryText(knowledge.category),
      type_text: this.getTypeText(knowledge.type),
      severity_text: knowledge.severity ? this.getSeverityText(knowledge.severity) : '',
      status_text: this.getStatusText(knowledge.status),
    }));
  }

  parseTagsFromString(tagsString: string | TagInfo[]): TagInfo[] {
    if (Array.isArray(tagsString)) {
      return tagsString;
    }

    if (!tagsString || typeof tagsString !== 'string') {
      return [];
    }

    return tagsString.split(',').map((tagName, index) => ({
      id: index + 1,
      name: tagName.trim(),
      display_name: tagName.trim(),
      description: '',
      color: '#3B82F6',
      category: 'general',
      is_active: true,
    }));
  }

  getCategoryText(category: string): string {
    const categoryMap: Record<string, string> = {
      vulnerability: '漏洞相关',
      security: '安全防护',
      tool: '工具使用',
      guide: '操作指南',
      best_practice: '最佳实践',
    };
    return categoryMap[category] || category;
  }

  getTypeText(type: string): string {
    const typeMap: Record<string, string> = {
      article: '技术文章',
      tutorial: '教程指南',
      faq: '常见问题',
      solution: '解决方案',
      reference: '参考资料',
    };
    return typeMap[type] || type;
  }

  getSeverityText(severity: string): string {
    const severityMap: Record<string, string> = {
      low: '低',
      medium: '中',
      high: '高',
      critical: '严重',
    };
    return severityMap[severity] || severity;
  }

  getStatusText(status: string): string {
    const statusMap: Record<string, string> = {
      draft: '草稿',
      published: '已发布',
      archived: '已归档',
    };
    return statusMap[status] || status;
  }
}

export const knowledgeService = new KnowledgeService();
export default knowledgeService;
