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
  assessment_state: "catalog-only";
  summary: SecurityBaselineSummary;
};

export type SecurityBaselineCatalog = {
  catalog_revision: string;
  generated_at: string;
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
};

export type SecurityBaselineSystems = {
  baseline: SecurityBaseline;
  count: number;
  page: number;
  page_size: number;
  results: SecurityBaselineSystem[];
};
