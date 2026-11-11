// API Response Types
export interface ApiResponse<T = unknown> {
  code: number;
  message: string;
  data?: T;
}

export interface PaginatedResponse<T> {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  data: T[];
}

// Authentication Types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
  user: User;
}

export interface User {
  id: number;
  username: string;
  real_name: string;
  email: string;
  phone?: string;
  department?: string;
  avatar?: string;
  last_login_at?: string;
  role: Role;
  status?: number; // 1-正常，0-禁用
  created_at?: string;
  updated_at?: string;
}

export interface Role {
  id: number;
  name: string;
  description?: string;
  status?: number;
  permissions?: string[];
}

// Asset Types
export interface Asset {
  id: number;
  name: string;
  type: 'server' | 'database' | 'application' | 'network';
  category?: string;
  ip_address?: string;
  domain?: string;
  port?: string;
  os?: string;
  version?: string;
  department?: string;
  owner_id?: number;
  owner?: User; // Relationship field from backend
  business_line?: string;
  importance_level: 1 | 2 | 3; // 1-高，2-中，3-低
  description?: string;
  // Exposure inputs of the risk score.
  internet_facing?: boolean;
  network_zone?: 'internal' | 'dmz' | 'production' | 'ot' | 'test';
  created_at?: string;
  updated_at?: string;
}

export interface CreateAssetRequest {
  name: string;
  type: 'server' | 'database' | 'application' | 'network';
  category?: string;
  ip_address?: string;
  domain?: string;
  port?: string;
  os?: string;
  version?: string;
  department?: string;
  owner_id?: number;
  business_line?: string;
  importance_level?: 1 | 2 | 3;
  description?: string;
  internet_facing?: boolean;
  network_zone?: 'internal' | 'dmz' | 'production' | 'ot' | 'test';
}

// Vulnerability Types
export interface OWASPCategory {
  id: number;
  code: string;
  name: string;
  description?: string;
  year?: number;
}

export interface VulnerabilityAssetOption {
  id: number;
  name: string;
  ip_address: string;
  domain: string;
}

export interface AssigneeOption {
  id: number;
  username: string;
  real_name: string;
}

export interface VulnerabilityAttachment {
  id: number;
  vulnerability_id: number;
  filename: string;
  original_name: string;
  file_size: number;
  file_type: string;
  mime_type?: string;
  uploader_id: number;
  created_at: string;
}

export interface Vulnerability {
  id: number;
  title: string;
  description: string;
  cve_id?: string;
  cnvd_id?: string;
  owasp_category_id?: number;
  owasp_category?: OWASPCategory;
  attachments?: VulnerabilityAttachment[];
  severity_level_text?: string;
  status_text?: string;
  severity_level: 1 | 2 | 3 | 4; // 1-严重，2-高危，3-中危，4-低危
  cvss_score?: number;
  asset_id: number;
  discoverer_id?: number; // Who discovered the vulnerability
  assignee_id?: number;
  impact_scope?: string;
  reproduction_steps?: string;
  fix_suggestion?: string;
  status?: string;
  created_at?: string;
  updated_at?: string;
  // Timestamp fields for status tracking
  assigned_at?: string;
  discovered_at?: string;
  fixed_at?: string;
  verified_at?: string;
  closed_at?: string;
  asset?: Asset;
  discoverer?: User; // User who discovered the vulnerability
  assignee?: User;
  response_due_at?: string | null;
  fix_due_at?: string | null;
  first_response_at?: string | null;
  pause_started_at?: string | null;
  pause_ended_at?: string | null;
  paused_seconds?: number;
  response_overdue?: boolean;
  fix_overdue?: boolean;
  // Risk snapshot; null until the vulnerability has been scored.
  risk_score?: number | null;
  risk_priority?: '' | 'P1' | 'P2' | 'P3' | 'P4';
  risk_priority_text?: string;
  risk_epss?: number | null;
  risk_kev?: boolean;
  risk_scored_at?: string | null;
}

export interface CreateVulnerabilityRequest {
  title: string;
  description?: string;
  cve_id?: string;
  cnvd_id?: string;
  owasp_category_id?: number;
  severity_level: 1 | 2 | 3 | 4;
  cvss_score?: number;
  asset_id: number;
  assignee_id?: number;
  impact_scope?: string;
  reproduction_steps?: string;
  fix_suggestion?: string;
}

export interface UpdateVulnerabilityRequest extends Partial<CreateVulnerabilityRequest> {
  status?: string;
}

// Report Types
export interface Report {
  id: number;
  title: string;
  description?: string;
  type: 'penetration_test' | 'vulnerability_assessment' | 'security_audit' | 'compliance_check' | 'other';
  severity: string;
  file_type?: string;
  file_name?: string;
  file_size?: number;
  asset_ids?: number[];
  tags?: string[];
  test_date?: string;
  created_at?: string;
  updated_at?: string;
  assets?: Asset[];
}

// Analytics Types
export interface TimeRangeStats {
  today: number;
  yesterday: number;
  this_week: number;
  last_week: number;
  this_month: number;
  last_month: number;
}

export interface DashboardStats {
  total_assets: number;
  total_vulnerabilities: number;
  total_reports: number;
  total_users: number;
  // Time range statistics for percentage calculations
  vulnerability_time_stats: TimeRangeStats;
  asset_time_stats: TimeRangeStats;
  user_time_stats: TimeRangeStats;
  report_time_stats: TimeRangeStats;
  severity_stats: Array<{
    severity: string;
    count: number;
    color?: string;
  }>;
  asset_type_stats: Array<{
    type: string;
    count: number;
  }>;
  recent_trends: {
    vulnerability_trend: Array<{
      date: string;
      count: number;
    }>;
  };
}

// Query Parameters
export interface PaginationParams {
  page?: number;
  page_size?: number;
}

export interface SearchParams extends PaginationParams {
  keyword?: string;
}

export interface AssetSearchParams extends SearchParams {
  type?: string;
  importance_level?: number;
  owner_id?: number;
}

export interface VulnerabilitySearchParams extends SearchParams {
  severity_level?: number;
  status?: string;
  asset_id?: number;
  assignee_id?: number;
  discoverer_id?: number; // Filter by who discovered the vulnerability
  owasp_category_id?: number; // Filter by OWASP category
  start_date?: string; // Filter by date range
  end_date?: string; // Filter by date range
  sla_status?: '' | 'overdue' | 'paused' | 'within';
  risk_priority?: '' | 'P1' | 'P2' | 'P3' | 'P4';
  min_risk_score?: number;
  kev_only?: boolean;
  sort_by?: 'created_at' | 'risk_score';
  sort_order?: 'asc' | 'desc';
}

export interface ReportSearchParams extends SearchParams {
  type?: string;
  severity?: string;
}

// Permission Types
export interface Permission {
  id: number;
  code: string;
  name: string;
  description?: string;
  module: string;
  action: string;
}

// Error Types
export interface ApiError {
  code: number;
  message: string;
  details?: unknown;
}
