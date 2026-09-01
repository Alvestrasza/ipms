import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type WindowsServer = {
  id: string;
  tenant_id: string;
  connector_id: string | null;
  source_id: string;
  inventory_source: "agent" | "hyper-v";
  server_type: "physical" | "virtual" | "unknown";
  hostname: string;
  fqdn: string;
  domain_name: string;
  operating_system: string;
  os_version: string;
  os_build: string;
  architecture: string;
  manufacturer: string;
  model: string;
  serial_number: string;
  system_uuid: string;
  logical_processors: number | null;
  memory_bytes: number | null;
  cluster_name: string;
  hypervisor_host: string;
  agent_version: string;
  agent_state: "not-enrolled" | "online" | "stale" | "offline" | "unknown";
  health: "healthy" | "warning" | "critical" | "unknown";
  management_packs: string[];
  last_seen_at: string | null;
  discovered_at: string;
};

export async function getWindowsServers(
  tenantId: string,
  serverType: "physical" | "virtual",
) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  const query = new URLSearchParams({ server_type: serverType });
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/windows-servers/?${query}`,
      { cache: "no-store", headers },
    );
    return {
      sessionValid: ![401, 403].includes(response.status),
      available: response.ok,
      servers: response.ok ? ((await response.json()) as WindowsServer[]) : [],
    };
  } catch {
    return { sessionValid: true, available: false, servers: [] };
  }
}

export async function getWindowsServer(tenantId: string, id: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/windows-servers/${encodeURIComponent(id)}/`,
      { cache: "no-store", headers },
    );
    return {
      sessionValid: ![401, 403].includes(response.status),
      available: response.ok,
      notFound: response.status === 404,
      server: response.ok ? ((await response.json()) as WindowsServer) : null,
    };
  } catch {
    return {
      sessionValid: true,
      available: false,
      notFound: false,
      server: null,
    };
  }
}
