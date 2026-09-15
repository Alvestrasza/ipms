/**
 * File Name: domain-security-types.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Define tenant domain configuration and bounded unlinked pilot import contracts.
 */
export type SecurityTier = "0" | "1" | "2";
export const SECURITY_TIERS: SecurityTier[] = ["0", "1", "2"];

export type DomainSecuritySettings = {
  id: string;
  domain_name: string;
  revision: number;
  tier_ous: Record<SecurityTier, string[]>;
  gpo_name_template: string;
  baseline_order: string[];
  updated_at: string;
  verification_status: "unverified";
  name_previews: {
    tier: SecurityTier;
    production: string;
    pilot: string;
  }[];
};

export type GpoBaselineOption = {
  id: string;
  name: string;
  provider: string;
  revision: string;
  profiles: string[];
  components: {
    id: string;
    name: string;
    scope: "machine" | "user" | "domain";
    purpose: string;
    artifact_sha256: string;
    available: boolean;
  }[];
};

export type DomainSecurityCatalog = {
  results: DomainSecuritySettings[];
  discovered_domains: string[];
  baseline_options: GpoBaselineOption[];
  default_name_template: string;
  catalog_revision: string;
};

export type GpoImportStatus =
  | "queued"
  | "awaiting_approval"
  | "running"
  | "staged"
  | "blocked"
  | "failed"
  | "expired"
  | "reconciliation_required";

export type GpoImportJob = {
  id: string;
  status: GpoImportStatus;
  baseline_id: string;
  backup_id: string;
  tier: SecurityTier;
  pilot_display_name: string;
  hostname: string;
  requested_at: string;
  completed_at: string | null;
  error_code: string;
  gpo_guid: string | null;
  approval_document: Record<string, unknown> | null;
  approval_mode: "local" | "portal";
  approved_by: string | null;
  approved_by_name: string | null;
  approved_at: string | null;
  four_eyes_required: boolean;
  policy_revision: number;
  can_approve: boolean;
  approval_blocker: string | null;
  requested_by: string | null;
  requested_by_name: string;
  expires_at: string;
  input_digest: string;
  dc_fqdn: string;
  review: GpoImportReview | null;
};

export type GpoImportReview = {
  component_name: string;
  artifact_sha256: string;
  files: { path: string; bytes: number; sha256: string }[];
  report_xml: string;
  changes: ["create_disabled_unlinked_pilot"];
};

export type GpoImportExecutor = {
  system_id: string;
  hostname: string;
  agent_version: string;
  state: string;
  domain_name: string;
  domain_guid: string;
  forest_name: string;
  dc_fqdn: string;
  eligible: boolean;
  last_seen: string | null;
};

export type DomainGpoImports = {
  results: GpoImportJob[];
  executors: GpoImportExecutor[];
};
