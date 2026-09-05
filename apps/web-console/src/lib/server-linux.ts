import "server-only";

import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type LinuxSystem = {
  id: string;
  source_id: string;
  hostname: string;
  fqdn: string;
  system_type: "physical" | "virtual";
  distribution: string;
  distribution_version: string;
  kernel_version: string;
  architecture: string;
  manufacturer: string;
  model: string;
  serial_number: string;
  logical_processors: number;
  memory_bytes: number;
  agent_version: string;
  health: "healthy" | "warning" | "critical" | "unknown";
  network_interfaces: Array<{
    interface_id: string;
    name: string;
    mac_address: string;
    status: string;
    addresses: Array<{ address: string; prefix_length: number }>;
  }>;
  fixed_volumes: Array<{
    name: string;
    filesystem: string;
    total_bytes: number;
    free_bytes: number;
    used_percent: number;
  }>;
  last_seen_at: string;
};

async function request(tenantId: string, path: string) {
  const cookie = (await cookies()).toString();
  return fetch(`${CONTROL_PLANE_URL}${path}`, {
    cache: "no-store",
    headers: controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId }),
  });
}

export async function getLinuxSystems(
  tenantId: string,
  systemType: "physical" | "virtual",
) {
  try {
    const response = await request(
      tenantId,
      `/api/v1/linux-systems/?system_type=${systemType}`,
    );
    return {
      sessionValid: response.status !== 401,
      available: response.ok,
      systems: response.ok ? ((await response.json()) as LinuxSystem[]) : [],
    };
  } catch {
    return { sessionValid: true, available: false, systems: [] };
  }
}

export async function getLinuxSystem(tenantId: string, id: string) {
  try {
    const response = await request(
      tenantId,
      `/api/v1/linux-systems/${encodeURIComponent(id)}/`,
    );
    return {
      sessionValid: ![401, 403].includes(response.status),
      available: response.ok,
      notFound: response.status === 404,
      system: response.ok ? ((await response.json()) as LinuxSystem) : null,
    };
  } catch {
    return {
      sessionValid: true,
      available: false,
      notFound: false,
      system: null,
    };
  }
}
