import { apiClient } from './api';
import type { RiskConfig, RiskConfigResponse, ThreatIntelStatus, ThreatIntelSyncResult, VulnerabilityRisk } from '../types/risk';

export const riskService = {
  async vulnerabilityRisk(id: number, signal?: AbortSignal): Promise<VulnerabilityRisk> {
    return (await apiClient.get<VulnerabilityRisk>(`/vulnerabilities/${id}/risk`, { signal })).data!;
  },
  async config(): Promise<RiskConfigResponse> { return (await apiClient.get<RiskConfigResponse>('/risk/config')).data!; },
  /** Saving rescores every vulnerability; the result is how many were rescored. */
  async saveConfig(config: RiskConfig): Promise<number> {
    return (await apiClient.put<{ rescored: number }>('/risk/config', config)).data?.rescored ?? 0;
  },
  async recalculate(): Promise<number> {
    return (await apiClient.post<{ rescored: number }>('/risk/recalculate')).data?.rescored ?? 0;
  },
  async intelStatus(): Promise<ThreatIntelStatus> { return (await apiClient.get<ThreatIntelStatus>('/risk/intel/status')).data!; },
  async syncIntel(): Promise<ThreatIntelSyncResult> { return (await apiClient.post<ThreatIntelSyncResult>('/risk/intel/sync')).data!; },
};
