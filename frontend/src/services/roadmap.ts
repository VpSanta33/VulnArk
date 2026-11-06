import { apiClient } from './api';
import type { PaginatedResponse } from '../types/api';
import type { SLAPolicy, SLAPolicyInput, SLAState, RetestRecord, DuplicateCandidate, DuplicateQuery, DuplicateRelation, InboxNotification, NotificationStats } from '../types/roadmap';
import { buildRetestForm } from '../lib/roadmap';

export const roadmapService = {
  async policies(): Promise<PaginatedResponse<SLAPolicy>> {
    const first = (await apiClient.get<PaginatedResponse<SLAPolicy>>('/sla-policies', { params: { page: 1, page_size: 50 } })).data!;
    const items = [...(first.data || [])];
    for (let page = 2; page <= first.total_pages; page++) {
      const next = (await apiClient.get<PaginatedResponse<SLAPolicy>>('/sla-policies', { params: { page, page_size: 50 } })).data!;
      items.push(...(next.data || []));
    }
    return { ...first, data: items };
  },
  async savePolicy(data: SLAPolicyInput, id?: number): Promise<void> {
    if (id) await apiClient.put(`/sla-policies/${id}`, data);
    else await apiClient.post('/sla-policies', data);
  },
  async deletePolicy(id: number): Promise<void> { await apiClient.delete(`/sla-policies/${id}`); },
  async sla(id: number): Promise<SLAState> { return (await apiClient.get<SLAState>(`/vulnerabilities/${id}/sla`)).data!; },
  async pauseSLA(id: number, reason = ''): Promise<void> { await apiClient.post(`/vulnerabilities/${id}/sla/pause`, { reason }); },
  async resumeSLA(id: number): Promise<void> { await apiClient.post(`/vulnerabilities/${id}/sla/resume`); },
  async retests(id: number): Promise<RetestRecord[]> { return (await apiClient.get<RetestRecord[]>(`/vulnerabilities/${id}/retests`)).data || []; },
  async retest(id: number, result: RetestRecord['result'], summary: string, evidence: File[]): Promise<RetestRecord> {
    return (await apiClient.upload<RetestRecord>(`/vulnerabilities/${id}/retest`, buildRetestForm(result, summary, evidence))).data!;
  },
  async downloadRetestEvidence(id: number, retestId: number, index: number, filename: string): Promise<void> {
    await apiClient.download(`/vulnerabilities/${id}/retests/${retestId}/evidence/${index}/download`, filename);
  },
  async candidates(query: DuplicateQuery, signal?: AbortSignal): Promise<DuplicateCandidate[]> {
    return (await apiClient.get<DuplicateCandidate[]>('/vulnerabilities/duplicates/candidates', { params: query, signal })).data || [];
  },
  async duplicates(id: number): Promise<DuplicateRelation[]> { return (await apiClient.get<DuplicateRelation[]>(`/vulnerabilities/${id}/duplicates`)).data || []; },
  async linkDuplicate(id: number, candidateId: number, reason = ''): Promise<void> {
    await apiClient.post(`/vulnerabilities/${id}/duplicates/${candidateId}/link`, { relation_type: 'duplicate', reason });
  },
  async unlinkDuplicate(id: number, candidateId: number, reason = ''): Promise<void> {
    await apiClient.delete(`/vulnerabilities/${id}/duplicates/${candidateId}/link`, { data: { reason } });
  },
  async ignoreDuplicate(id: number, candidateId: number, reason: string): Promise<void> {
    await apiClient.post(`/vulnerabilities/${id}/duplicates/${candidateId}/ignore`, { reason });
  },
  async restoreDuplicate(id: number, candidateId: number): Promise<void> {
    await apiClient.delete(`/vulnerabilities/${id}/duplicates/${candidateId}/ignore`);
  },
  async notifications(limit = 50): Promise<InboxNotification[]> { return (await apiClient.get<InboxNotification[]>('/notifications/my', { params: { limit } })).data || []; },
  async notificationStats(): Promise<NotificationStats> { return (await apiClient.get<NotificationStats>('/notifications/stats')).data!; },
  async readNotification(id: number): Promise<void> { await apiClient.post(`/notifications/${id}/read`); },
  async readAllNotifications(): Promise<void> { await apiClient.post('/notifications/read-all'); },
  async deleteNotification(id: number): Promise<void> { await apiClient.delete(`/notifications/${id}`); },
};
