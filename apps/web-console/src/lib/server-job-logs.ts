/**
 * File Name: server-job-logs.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Fetch tenant-authorized read-only history and protected pilot details.
 */
import "server-only";
import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import {
  isGpoImportLogDetail,
  isJobLogPage,
  isLogJobId,
  type JobLogScope,
} from "./job-log-types";

async function read<T>(
  path: string,
  tenantId: string,
  validate: (value: unknown) => value is T,
) {
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}${path}`, {
      cache: "no-store",
      headers: controlPlaneHeaders({
        cookie: (await cookies()).toString(),
        "X-IPMS-Tenant-ID": tenantId,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    const payload: unknown = response.ok ? await response.json() : null;
    return {
      data: validate(payload) ? payload : null,
      status: response.status,
    };
  } catch {
    return { data: null, status: 503 };
  }
}
export function getJobLogs(
  tenantId: string,
  scope: JobLogScope,
  query: string,
) {
  return read(
    `/api/v1/logs/${scope}/${query ? `?${query}` : ""}`,
    tenantId,
    isJobLogPage,
  );
}
export async function getGpoImportLog(tenantId: string, jobId: string) {
  if (!isLogJobId(jobId)) return { data: null, status: 400 };
  return read(
    `/api/v1/logs/gpo-imports/${jobId}/`,
    tenantId,
    isGpoImportLogDetail,
  );
}
