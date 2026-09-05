import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type DiscoveryJob = {
  id: string;
  tenant_id: string;
  connector_type: "bmc-api" | "hyper-v";
  status: "queued" | "running" | "succeeded" | "failed";
  requested_by: string;
  result_summary: Record<string, unknown>;
  error_code: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type DashboardData = {
  checkedAt: string;
  controlPlaneReady: boolean;
  jobsAvailable: boolean;
  sessionValid: boolean;
  discoveryJobs: DiscoveryJob[];
};

export async function getDashboardData(
  tenantId: string,
): Promise<DashboardData> {
  const cookieHeader = (await cookies()).toString();
  const requestHeaders = controlPlaneHeaders({
    cookie: cookieHeader,
    "X-IPMS-Tenant-ID": tenantId,
  });

  try {
    const [readinessResponse, jobsResponse] = await Promise.all([
      fetch(`${CONTROL_PLANE_URL}/api/v1/health/ready/`, {
        cache: "no-store",
        headers: controlPlaneHeaders(),
      }),
      fetch(`${CONTROL_PLANE_URL}/api/v1/discovery-jobs/`, {
        cache: "no-store",
        headers: requestHeaders,
      }),
    ]);

    const sessionValid = jobsResponse.status !== 401;
    const jobsAvailable = jobsResponse.ok;
    const discoveryJobs = jobsAvailable
      ? ((await jobsResponse.json()) as DiscoveryJob[])
      : [];
    return {
      checkedAt: new Date().toISOString(),
      controlPlaneReady: readinessResponse.ok,
      jobsAvailable,
      sessionValid,
      discoveryJobs,
    };
  } catch {
    return {
      checkedAt: new Date().toISOString(),
      controlPlaneReady: false,
      jobsAvailable: false,
      sessionValid: true,
      discoveryJobs: [],
    };
  }
}
