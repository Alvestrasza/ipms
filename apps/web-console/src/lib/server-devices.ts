import "server-only";

import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type ManagedConnector = {
  id: string;
  connector_type: "sophos-firewall" | "loadbalancer-org" | "hpe-comware";
  display_name: string;
  base_url: string;
  health: "healthy" | "warning" | "critical" | "unknown";
  last_error_code: string;
  last_attempt_at: string | null;
  last_success_at: string | null;
};

export type ManagedDevice = {
  id: string;
  connector_id: string;
  connector_type: ManagedConnector["connector_type"];
  category: "firewall" | "load-balancer" | "switch";
  name: string;
  vendor: string;
  product: string;
  model: string;
  software_version: string;
  serial_number: string;
  uptime_seconds: number | null;
  health: "healthy" | "warning" | "critical" | "unknown";
  interfaces: Array<Record<string, unknown>>;
  details: Record<string, unknown>;
  discovered_at: string;
};

export async function getManagedDevices(tenantId: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({
    cookie,
    "X-IPMS-Tenant-ID": tenantId,
  });
  try {
    const [connectorsResponse, devicesResponse] = await Promise.all([
      fetch(`${CONTROL_PLANE_URL}/api/v1/connectors/`, {
        cache: "no-store",
        headers,
      }),
      fetch(`${CONTROL_PLANE_URL}/api/v1/managed-devices/`, {
        cache: "no-store",
        headers,
      }),
    ]);
    const allConnectors = connectorsResponse.ok
      ? ((await connectorsResponse.json()) as ManagedConnector[])
      : [];
    return {
      available: connectorsResponse.ok && devicesResponse.ok,
      sessionValid:
        ![401, 403].includes(connectorsResponse.status) &&
        ![401, 403].includes(devicesResponse.status),
      connectors: allConnectors.filter((connector) =>
        ["sophos-firewall", "loadbalancer-org", "hpe-comware"].includes(
          connector.connector_type,
        ),
      ),
      devices: devicesResponse.ok
        ? ((await devicesResponse.json()) as ManagedDevice[])
        : [],
    };
  } catch {
    return {
      available: false,
      sessionValid: true,
      connectors: [],
      devices: [],
    };
  }
}
