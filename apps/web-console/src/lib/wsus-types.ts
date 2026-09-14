/**
 * File Name: wsus-types.ts
 * Version: v0.1.0
 * Created: 2026-09-13 | Modified: 2026-09-13
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Define tenant-scoped WSUS reception and comparison contracts.
 */

export type WsusSource = {
  id: string;
  name: string;
  scope: string;
  enabled: boolean;
  wsus_host: string;
  wsus_port: number;
  wsus_use_ssl: boolean;
  created_at: string;
  last_received_at: string | null;
  last_observed_at: string | null;
};

export type WsusUpdateState =
  | "unknown"
  | "not_applicable"
  | "not_installed"
  | "downloaded"
  | "installed"
  | "failed"
  | "installed_pending_reboot";

export type WsusServer = {
  server_id: string;
  hostname: string;
  fqdn: string;
  inventory_at: string | null;
  inventory_stale: boolean;
  match_status: "matched" | "unmatched" | "ambiguous" | "no-data";
  wsus_status:
    | "no-data"
    | "unknown"
    | "stale"
    | "missing"
    | "failed"
    | "reboot-required"
    | "current";
  reported_at: string | null;
  counts: Record<WsusUpdateState, number>;
  agent_evidence?: {
    status: "not-reported" | "collected" | "unavailable" | "limit-exceeded";
    observed_at: string | null;
    stale: boolean;
    installed_matches: number;
    revision_mismatches: number;
    unknown: number;
  };
  agent: {
    scan_status: string;
    last_scan_at: string | null;
    reboot_required: boolean | null;
    updates_available: number | null;
  } | null;
};

export type WsusComparison = {
  source: Pick<WsusSource, "id" | "name" | "scope" | "enabled">;
  snapshot: {
    id: string;
    observed_at: string;
    received_at: string;
    update_count: number;
    computer_count: number;
  } | null;
  count: number;
  page: number;
  page_size: number;
  results: WsusServer[];
  unmatched_computers: number;
  ambiguous_computers: number;
};

export type WsusServerUpdates = {
  count: number;
  page: number;
  page_size: number;
  results: {
    update_id: string;
    revision: number;
    title: string;
    kb_articles: string[];
    products: string[];
    classification: string;
    severity: string;
    state: WsusUpdateState;
    agent_state: "installed" | "revision-mismatch" | "unknown";
    agent_observed_at: string | null;
  }[];
};
