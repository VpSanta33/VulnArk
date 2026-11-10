import type { NetworkZone, RiskConfig, RiskFactorKey, RiskPriority } from '../types/risk';

export const riskPriorities: Array<{ value: RiskPriority; label: string; variant: 'destructive' | 'warning' | 'medium' | 'low' }> = [
  { value: 'P1', label: '紧急', variant: 'destructive' },
  { value: 'P2', label: '高', variant: 'warning' },
  { value: 'P3', label: '中', variant: 'medium' },
  { value: 'P4', label: '低', variant: 'low' },
];
export function riskPriorityMeta(priority?: string) {
  return riskPriorities.find(item => item.value === priority);
}

export const riskFactorLabels: Record<RiskFactorKey, string> = {
  cvss: 'CVSS 技术严重性',
  epss: 'EPSS 利用可能性',
  kev: 'CISA KEV 已知被利用',
  asset_importance: '资产重要性',
  exposure: '暴露面',
};
export const riskFactorKeys = Object.keys(riskFactorLabels) as RiskFactorKey[];

export const networkZones: Array<{ value: NetworkZone; label: string }> = [
  { value: 'internal', label: '内部办公网段' },
  { value: 'dmz', label: 'DMZ' },
  { value: 'production', label: '生产网段' },
  { value: 'ot', label: 'OT/工控网段' },
  { value: 'test', label: '测试/开发网段' },
];
export function networkZoneLabel(zone?: string): string {
  return networkZones.find(item => item.value === zone)?.label || networkZones[0].label;
}

/** EPSS is a probability; values under 0.01% would otherwise all read "0.00%". */
export function formatEPSS(value?: number | null): string {
  if (value == null || !Number.isFinite(value)) return '—';
  const percent = value * 100;
  return percent > 0 && percent < 0.01 ? '<0.01%' : `${percent.toFixed(2)}%`;
}
export function formatSLAHours(hours: number): string {
  if (!Number.isFinite(hours) || hours <= 0) return '—';
  if (hours < 48) return `${hours} 小时`;
  return hours % 24 === 0 ? `${hours / 24} 天` : `${(hours / 24).toFixed(1)} 天`;
}

/** Share of the total weight, as shown next to each weight input. */
export function weightShare(config: RiskConfig, key: RiskFactorKey): number {
  const total = riskFactorKeys.reduce((sum, item) => sum + (Number(config.weights[item]) || 0), 0);
  return total > 0 ? ((Number(config.weights[key]) || 0) / total) * 100 : 0;
}

/** Mirrors the server-side rules so mistakes are caught before saving. Returns '' when valid. */
export function validateRiskConfig(config: RiskConfig): string {
  const weights = riskFactorKeys.map(key => config.weights[key]);
  if (weights.some(weight => !Number.isFinite(weight) || weight < 0 || weight > 100)) return '权重必须在 0-100 之间';
  if (config.weights.cvss + config.weights.asset_importance + config.weights.exposure <= 0) return 'CVSS、资产重要性、暴露面三项权重不能同时为 0';
  const { p1, p2, p3 } = config.thresholds;
  if (![p1, p2, p3].every(Number.isFinite) || p3 <= 0 || p2 <= p3 || p1 <= p2 || p1 > 100) return '档位阈值必须满足 0 < P3 < P2 < P1 ≤ 100';
  const hours = config.sla_hours;
  if (![hours.p1, hours.p2, hours.p3, hours.p4].every(Number.isInteger) || hours.p1 < 1 || hours.p2 < hours.p1 || hours.p3 < hours.p2 || hours.p4 < hours.p3 || hours.p4 > 876000) return '建议修复期限必须为正整数小时，且 P1 ≤ P2 ≤ P3 ≤ P4';
  if (!['', 'P1', 'P2', 'P3'].includes(config.kev_min_priority)) return 'KEV 保底优先级无效';
  return '';
}
