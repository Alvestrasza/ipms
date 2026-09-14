/**
 * File Name: security-types.ts
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Define the tenant security baseline catalog and assessment read model.
 */
export type SecurityBaselineTarget = "all" | "server" | "client";

export type SecurityBaselineSummary = {
  applicable: number;
  compliant: number;
  non_compliant: number;
  unknown: number;
  error: number;
  stale: number;
  assessed: number;
  compliance_percent: number | null;
  coverage_percent: number | null;
  last_assessed_at: string | null;
};

export type SecurityBaseline = {
  id: string;
  name: string;
  provider: "microsoft";
  platform: "windows";
  target: Exclude<SecurityBaselineTarget, "all">;
  release: string;
  revision: string;
  profiles: string[];
  source_url: string;
  package_name: string;
  verified_at: string;
  assessment_state: "catalog-only" | "native-read-only";
  summary: SecurityBaselineSummary;
};

export type SecurityBaselineCatalog = {
  catalog_revision: string;
  generated_at: string;
  hidden_count: number;
  capabilities: {
    assessment: boolean;
    deployment: boolean;
    collections: boolean;
  };
  inventory: {
    total: number;
    servers: number;
    clients: number;
    unclassified: number;
    unmatched: number;
  };
  results: SecurityBaseline[];
};

export type SecurityBaselineSetting = SecurityBaseline & {
  hidden: boolean;
  updated_at: string | null;
};

export type SecurityBaselineSettings = {
  catalog_revision: string;
  results: SecurityBaselineSetting[];
};

export type SecurityBaselineVisibility = {
  id: string;
  hidden: boolean;
  updated_at: string | null;
};

export type SecurityBaselineStatus =
  | "compliant"
  | "non_compliant"
  | "unknown"
  | "error"
  | "stale";

export type SecurityBaselineReason =
  | "not_assessed"
  | "partial"
  | "assessment_error"
  | "expired"
  | "baseline_changed"
  | "system_changed"
  | "agent_unavailable"
  | "complete";

export type SecurityBaselineSystem = {
  id: string;
  hostname: string;
  fqdn: string;
  operating_system: string;
  os_build: string;
  operating_system_role: string;
  server_type: string;
  status: SecurityBaselineStatus;
  reason: SecurityBaselineReason;
  assessed_at: string | null;
  assessment_id: string | null;
  controls: {
    total: number;
    passed: number;
    failed: number;
    unknown: number;
  } | null;
};

export type SecurityBaselineSystems = {
  baseline: SecurityBaseline;
  count: number;
  page: number;
  page_size: number;
  results: SecurityBaselineSystem[];
};

export type SecurityBaselineScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "expired";

export type SecurityBaselineScanJob = {
  id: string;
  system_id: string;
  hostname: string;
  status: SecurityBaselineScanStatus;
  requested_at: string;
  completed_at: string | null;
  error_code: string;
};

export type SecurityBaselineScans = {
  count: number;
  active: number;
  results: SecurityBaselineScanJob[];
};

export type SecurityBaselineScanReceipt = {
  queued: number;
  existing: number;
  unavailable: number;
  results: SecurityBaselineScanJob[];
};

export type SecurityFindingValue =
  | string
  | number
  | boolean
  | null
  | (string | number | boolean | null)[];

export type SecurityBaselineFinding = {
  control_id: string;
  label: string;
  scope: string;
  kind: string;
  status: "passed" | "failed" | "unknown";
  reason: string;
  expected: SecurityFindingValue;
  observed: SecurityFindingValue;
};

export type SecurityBaselineFindings = {
  assessment_id: string | null;
  assessed_at: string | null;
  scope_verified: boolean;
  status: SecurityBaselineStatus;
  reason: SecurityBaselineReason;
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
  unknown_controls: number;
  page: number;
  page_size: number;
  count: number;
  results: SecurityBaselineFinding[];
};
