import { apiClient, buildQueryString } from './api';
import {
  Vulnerability,
  CreateVulnerabilityRequest,
  UpdateVulnerabilityRequest,
  OWASPCategory,
  AssigneeOption,
  VulnerabilityAssetOption,
  VulnerabilitySearchParams,
  PaginatedResponse,
} from '../types/api';

export class VulnerabilitiesService {
  // Get vulnerabilities list with pagination and filtering
  async getVulnerabilities(params: VulnerabilitySearchParams = {}, signal?: AbortSignal): Promise<PaginatedResponse<Vulnerability>> {
    const queryString = buildQueryString(params);
    const response = await apiClient.get<PaginatedResponse<Vulnerability>>(`/vulnerabilities${queryString}`, { signal });
    return response.data!;
  }

  // Get vulnerability by ID
  async getVulnerability(id: number): Promise<Vulnerability> {
    const response = await apiClient.get<Vulnerability>(`/vulnerabilities/${id}`);
    return response.data!;
  }

  // Create new vulnerability with optional screenshots
  async createVulnerability(data: CreateVulnerabilityRequest, screenshots?: File[]): Promise<Vulnerability> {
    if (!screenshots?.length) {
      const response = await apiClient.post<Vulnerability>('/vulnerabilities', data);
      return response.data!;
    }
    const formData = new FormData();
    formData.append('data', JSON.stringify(data));
    
    if (screenshots && screenshots.length > 0) {
      screenshots.forEach((file) => {
        formData.append('screenshots', file);
      });
    }
    
    const response = await apiClient.upload<Vulnerability>('/vulnerabilities', formData);
    return response.data!;
  }

  // Update vulnerability
  async updateVulnerability(id: number, data: UpdateVulnerabilityRequest): Promise<void> {
    await apiClient.put(`/vulnerabilities/${id}`, data);
  }

  async getOWASPCategories(): Promise<OWASPCategory[]> {
    const response = await apiClient.get<OWASPCategory[]>('/vulnerabilities/owasp-categories');
    return response.data || [];
  }

  async getAssetOptions(): Promise<VulnerabilityAssetOption[]> {
    const response = await apiClient.get<VulnerabilityAssetOption[]>('/vulnerabilities/asset-options');
    return response.data || [];
  }

  async getAssigneeOptions(): Promise<AssigneeOption[]> {
    const response = await apiClient.get<AssigneeOption[]>('/vulnerabilities/assignee-options');
    return response.data || [];
  }

  async getAttachmentBlob(vulnerabilityId: number, attachmentId: number, preview: boolean, signal?: AbortSignal): Promise<Blob> {
    const response = await apiClient.getClient().get<Blob>(
      `/vulnerabilities/${vulnerabilityId}/attachments/${attachmentId}/${preview ? 'preview' : 'download'}`,
      { responseType: 'blob', signal },
    );
    return response.data;
  }

  // Delete vulnerability
  async deleteVulnerability(id: number): Promise<void> {
    await apiClient.delete(`/vulnerabilities/${id}`);
  }

  // Update vulnerability status
  async updateVulnerabilityStatus(id: number, status: string): Promise<void> {
    await apiClient.put(`/vulnerabilities/${id}/status`, { status });
  }

  // Assign vulnerability to user
  async assignVulnerability(id: number, assigneeId: number): Promise<Vulnerability> {
    const response = await apiClient.post<Vulnerability>(`/vulnerabilities/${id}/assign`, {
      assignee_id: assigneeId,
    });
    return response.data!;
  }

  // Get vulnerability statistics
  async getVulnerabilityStats(): Promise<unknown> {
    const response = await apiClient.get('/vulnerabilities/stats');
    return response.data!;
  }

  // Get severity levels
  getSeverityLevels(): Array<{ value: number; label: string; color: string }> {
    return [
      { value: 1, label: '严重', color: 'red' },
      { value: 2, label: '高危', color: 'orange' },
      { value: 3, label: '中危', color: 'yellow' },
      { value: 4, label: '低危', color: 'blue' },
    ];
  }

  // Get CVSS score color
  getCvssScoreColor(score: number): string {
    if (score >= 9.0) return 'red';
    if (score >= 7.0) return 'orange';
    if (score >= 4.0) return 'yellow';
    return 'green';
  }
}

export const vulnerabilitiesService = new VulnerabilitiesService();
