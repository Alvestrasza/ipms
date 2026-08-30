import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type ConnectorEndpoint = {
  id: string;
  tenant_id: string;
  connector_type: "ilo-redfish" | "hyper-v";
  display_name: string;
  base_url: string;
  enabled: boolean;
  health: "unknown" | "healthy" | "warning" | "critical";
  trust_mode: "certificate-pin" | "unconfigured";
  last_error_code: string;
  last_error_detail: {
    method?: string;
    path?: string;
    http_status?: number;
    token_state?: string;
    location_state?: string;
  };
  last_attempt_at: string | null;
  last_success_at: string | null;
};

export type PhysicalSystem = {
  id: string;
  tenant_id: string;
  connector_id: string;
  name: string;
  manufacturer: string;
  model: string;
  serial_number: string;
  power_state: string;
  health: "ok" | "warning" | "critical" | "unknown";
  processor_count: number | null;
  processor_model: string;
  total_cores: number | null;
  memory_bytes: number | null;
  bios_version: string;
  bmc_firmware_version: string;
  discovered_at: string;
};

export async function getPhysicalInfrastructure(tenantId: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const [connectorsResponse, systemsResponse] = await Promise.all([
      fetch(`${CONTROL_PLANE_URL}/api/v1/connectors/`, {
        cache: "no-store",
        headers,
      }),
      fetch(`${CONTROL_PLANE_URL}/api/v1/physical-systems/`, {
        cache: "no-store",
        headers,
      }),
    ]);
    return {
      sessionValid:
        ![401, 403].includes(connectorsResponse.status) &&
        ![401, 403].includes(systemsResponse.status),
      available: connectorsResponse.ok && systemsResponse.ok,
      connectors: connectorsResponse.ok
        ? ((await connectorsResponse.json()) as ConnectorEndpoint[])
        : [],
      systems: systemsResponse.ok
        ? ((await systemsResponse.json()) as PhysicalSystem[])
        : [],
    };
  } catch {
    return {
      sessionValid: true,
      available: false,
      connectors: [],
      systems: [],
    };
  }
}
