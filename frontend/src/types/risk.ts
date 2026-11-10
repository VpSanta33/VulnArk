export type RiskPriority = 'P1' | 'P2' | 'P3' | 'P4';
export type RiskFactorKey = 'cvss' | 'epss' | 'kev' | 'asset_importance' | 'exposure';
export type NetworkZone = 'internal' | 'dmz' | 'production' | 'ot' | 'test';

export interface RiskFactor {
  key: RiskFactorKey;
  label: string;
  /** False when the factor has no data; its weight is spread over the others. */
  applicable: boolean;
  weight: number;
  /** Maximum points this factor can add for this vulnerability (applicable factors sum to 100). */
  effective_weight: number;
  /** Normalized 0-1. */
  value: number;
  /** effective_weight × value, in points. */
  contribution: number;
  raw_value: string;
  detail: string;
}
export interface KEVEntry {
  cve_id: string;
  vendor_project?: string;
  product?: string;
  vulnerability_name?: string;
  date_added?: string;
  due_date?: string;
  known_ransomware_use?: string;
}
export interface RiskThresholds { p1: number; p2: number; p3: number }
export interface VulnerabilityRisk {
  vulnerability_id: number;
  score: number;
  base_priority: RiskPriority;
  priority: RiskPriority;
  priority_text: string;
  recommended_sla_hours: number;
  factors: RiskFactor[];
  adjustments: string[];
  cve_id: string;
  epss: number | null;
  epss_percentile: number | null;
  epss_date: string;
  kev_listed: boolean;
  kev?: KEVEntry;
  scored_at: string;
  recommended_fix_due_at: string;
  current_fix_due_at: string | null;
  sla_alignment: 'none' | 'aligned' | 'later';
  thresholds: RiskThresholds;
}
export interface RiskConfig {
  weights: Record<RiskFactorKey, number>;
  thresholds: RiskThresholds;
  sla_hours: { p1: number; p2: number; p3: number; p4: number };
  kev_min_priority: '' | 'P1' | 'P2' | 'P3';
}
export interface RiskConfigResponse {
  config: RiskConfig;
  defaults: RiskConfig;
  updated_at: string | null;
  updated_by: number | null;
}
export interface ThreatIntelSourceStatus {
  source: 'epss' | 'kev';
  name: string;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_error: string;
  consecutive_failures: number;
  record_count: number;
  source_version: string;
  stale: boolean;
}
export interface ThreatIntelStatus {
  enabled: boolean;
  sync_interval_hours: number;
  sources: ThreatIntelSourceStatus[];
}
export interface ThreatIntelSyncResult {
  kev_entries: number;
  epss_updated: number;
  rescored: number;
  errors: string[];
}
