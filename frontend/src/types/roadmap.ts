export interface SLAPolicy {
  id: number;
  name: string;
  severity_level: number;
  asset_id?: number | null;
  department: string;
  response_hours: number;
  fix_hours: number;
  enabled: boolean;
}
export type SLAPolicyInput = Omit<SLAPolicy, 'id'>;
export interface SLAState {
  sla_status: 'none' | 'within' | 'paused' | 'overdue' | 'completed';
  sla_policy_id?: number | null;
  sla_policy_name?: string;
  sla_cycle?: number;
  response_due_at: string | null;
  fix_due_at: string | null;
  first_response_at: string | null;
  pause_started_at: string | null;
  pause_ended_at: string | null;
  paused_seconds: number;
  response_overdue: boolean;
  fix_overdue: boolean;
  response_overdue_level: number;
  fix_overdue_level: number;
  response_remaining_seconds: number | null;
  fix_remaining_seconds: number | null;
}
export interface RetestEvidence {
  filename: string;
  original_name: string;
  file_size: number;
  file_type: string;
  mime_type?: string;
}
export interface RetestRecord {
  id: number;
  vulnerability_id: number;
  created_at: string;
  tester_id: number;
  tester_name?: string;
  result: 'pass' | 'fail';
  summary: string;
  evidence_attachments?: RetestEvidence[];
  previous_status: string;
  new_status: string;
}
export interface DuplicateSummary {
  id: number;
  title: string;
  cve_id?: string;
  cnvd_id?: string;
  asset_id: number;
  severity_level: number;
  status: string;
}
export interface DuplicateCandidate extends DuplicateSummary {
  score: number;
  reasons: string[];
}
export interface DuplicateQuery {
  asset_id: number;
  title?: string;
  cve_id?: string;
  cnvd_id?: string;
  impact_scope?: string;
  vulnerability_id?: number;
  limit?: number;
}
export interface DuplicateRelation {
  other: DuplicateSummary;
  relation_type?: string;
  state: 'linked' | 'ignored';
  reason?: string;
  operator_id: number;
  occurred_at: string;
}
export interface InboxNotification {
  id: number;
  title: string;
  content: string;
  type: string;
  level: string;
  is_read: boolean;
  created_at: string;
  entity_type?: string;
  entity_id?: number | null;
  data?: Record<string, unknown>;
}
export interface NotificationStats {
  total: number;
  unread: number;
  by_type: Record<string, number>;
  by_level: Record<string, number>;
}
