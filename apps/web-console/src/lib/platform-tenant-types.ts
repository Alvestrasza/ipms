/**
 * File Name: platform-tenant-types.ts
 * Version: v0.2.76 | Created: 2026-09-19 | Modified: 2026-09-20
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Define platform tenant metadata, service purpose and Agent onboarding readiness.
 */
export type TenantPurpose = "infrastructure" | "hgs";

export type PlatformTenant = {
  id: string;
  slug: string;
  display_name: string;
  purpose: TenantPurpose;
  status: "active" | "suspended" | "decommissioned";
  created_at: string;
  updated_at: string;
  needs_administrator: boolean;
};

export type AgentOnboardingStatus = {
  tenant_id: string;
  tenant_slug: string;
  tenant_purpose: TenantPurpose;
  administrator_ready: boolean;
  pki: {
    state: "missing" | "recovery_pending" | "ready" | "incomplete";
    trust_mode: string;
    gateway_dns_name: string;
    gateway_port: number;
    root_fingerprint_sha256: string;
    gateway_fingerprint_sha256: string;
    recovery_bundle_sha256: string;
    recovery_downloaded: boolean;
    recovery_confirmed_at: string | null;
  };
  gateway: {
    ready: boolean;
    last_verified_at: string | null;
    error: string;
  };
  package: {
    ready: boolean;
    reason: string;
    version: string;
    sha256: string;
    observed_sha256: string;
    filename: string;
    minimum_hgs_version: string;
  };
  ready_for_enrollment: boolean;
};
