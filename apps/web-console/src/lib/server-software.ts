import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type SoftwareSnapshot = {
  id: string;
  device_uri: string;
  platform: "windows" | "linux";
  reboot_required: boolean | null;
  update_scan_status:
    | "current"
    | "updates-available"
    | "unknown"
    | "unavailable";
  last_update_scan_at: string | null;
  last_update_install_at: string | null;
  package_count: number;
  updates_available: number;
  completed_at: string | null;
};

export type SoftwarePackage = {
  id: string;
  source_id: string;
  name: string;
  installed_version: string;
  available_version: string;
  publisher: string;
  package_type: string;
  update_state: "current" | "update-available" | "unknown";
  is_os_component: boolean;
};

export async function getSoftwareInventory(
  tenantId: string,
  deviceUri: string,
) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const query = new URLSearchParams({ device_uri: deviceUri });
    const snapshotsResponse = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/software-inventory/?${query}`,
      { cache: "no-store", headers },
    );
    if (!snapshotsResponse.ok) {
      return { available: false, snapshot: null, packages: [] };
    }
    const snapshots = (await snapshotsResponse.json()) as SoftwareSnapshot[];
    const snapshot = snapshots[0] ?? null;
    if (!snapshot) return { available: true, snapshot: null, packages: [] };
    const packagesResponse = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/software-inventory/${encodeURIComponent(snapshot.id)}/packages/`,
      { cache: "no-store", headers },
    );
    return {
      available: packagesResponse.ok,
      snapshot,
      packages: packagesResponse.ok
        ? ((await packagesResponse.json()) as SoftwarePackage[])
        : [],
    };
  } catch {
    return { available: false, snapshot: null, packages: [] };
  }
}
