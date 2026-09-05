import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type AgentLifecycleJob = {
  id: string;
  action: "update" | "uninstall";
  status: "queued" | "delivered" | "running" | "succeeded" | "failed";
  target_version: string;
  result_code: string;
};

export type ManagedAgent = {
  enrollment_id: string;
  device_uri: string;
  platform: "windows" | "linux";
  fqdn: string;
  operating_system: string;
  os_version: string;
  agent_version: string;
  target_version: string;
  status: "online" | "stale" | "offline" | "not-seen" | "revoked";
  compliance: "current" | "outdated" | "unknown";
  lifecycle_capable: boolean;
  can_remove: boolean;
  last_seen_at: string | null;
  active_job: AgentLifecycleJob | null;
};

export async function getManagedAgents(tenantId: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}/api/v1/agents/`, {
      cache: "no-store",
      headers,
    });
    return {
      sessionValid: response.status !== 401,
      available: response.ok,
      agents: response.ok ? ((await response.json()) as ManagedAgent[]) : [],
    };
  } catch {
    return { sessionValid: true, available: false, agents: [] };
  }
}
