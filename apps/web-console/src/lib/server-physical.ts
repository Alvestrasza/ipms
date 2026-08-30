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
  bmc_family: "hpe-ilo4" | "hpe-ilo-modern" | "dell-idrac" | "generic-redfish";
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
    redfish_error_code?: string;
    redfish_message_id?: string;
    token_state?: string;
    location_state?: string;
  };
  last_attempt_at: string | null;
  last_success_at: string | null;
};

export type BmcCommunicationLog = {
  id: string;
  connector_id: string | null;
  bmc_name: string;
  bmc_family: ConnectorEndpoint["bmc_family"];
  severity: "debug" | "info" | "warning" | "error";
  event_type: string;
  method: string;
  resource_path: string;
  http_status: number | null;
  duration_ms: number | null;
  error_code: string;
  redfish_error_code: string;
  redfish_message_id: string;
  correlation_id: string | null;
  occurred_at: string;
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

export async function getBmcLogs(tenantId: string, queryString: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  const suffix = queryString ? `?${queryString}` : "";
  try {
    const [connectorsResponse, logsResponse] = await Promise.all([
      fetch(`${CONTROL_PLANE_URL}/api/v1/connectors/`, {
        cache: "no-store",
        headers,
      }),
      fetch(`${CONTROL_PLANE_URL}/api/v1/bmc-logs/${suffix}`, {
        cache: "no-store",
        headers,
      }),
    ]);
    return {
      sessionValid:
        ![401, 403].includes(connectorsResponse.status) &&
        ![401, 403].includes(logsResponse.status),
      available: connectorsResponse.ok && logsResponse.ok,
      connectors: connectorsResponse.ok
        ? ((await connectorsResponse.json()) as ConnectorEndpoint[])
        : [],
      logs: logsResponse.ok
        ? ((await logsResponse.json()) as BmcCommunicationLog[])
        : [],
    };
  } catch {
    return {
      sessionValid: true,
      available: false,
      connectors: [],
      logs: [],
    };
  }
}
