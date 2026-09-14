/**
 * File Name: server-wsus.ts
 * Version: v0.1.0
 * Created: 2026-09-13 | Modified: 2026-09-13
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Load WSUS source metadata and comparison within the selected tenant.
 */
import "server-only";

import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import type { WsusComparison, WsusSource } from "./wsus-types";

export async function getWsusOverview(
  tenantId: string,
  options: { includeComparison?: boolean; sourceId?: string } = {},
) {
  const headers = controlPlaneHeaders({
    cookie: (await cookies()).toString(),
    "X-IPMS-Tenant-ID": tenantId,
  });
  let sources: WsusSource[] = [];
  try {
    const sourceResponse = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/update-sources/`,
      {
        headers,
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!sourceResponse.ok) {
      return {
        sources,
        comparison: null,
        available: false,
        sessionValid: sourceResponse.status !== 401,
      };
    }
    sources = (await sourceResponse.json()) as WsusSource[];
    if (!Array.isArray(sources)) throw new Error("Invalid source response");
    const selectedSourceId =
      sources.find((source) => source.id === options.sourceId)?.id ??
      sources[0]?.id;
    if (!selectedSourceId || options.includeComparison === false)
      return {
        sources,
        selectedSourceId,
        comparison: null,
        available: true,
        sessionValid: true,
      };
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/update-sources/${encodeURIComponent(selectedSourceId)}/comparison/?page=1`,
      { headers, cache: "no-store", signal: AbortSignal.timeout(15_000) },
    );
    return {
      sources,
      selectedSourceId,
      comparison: response.ok
        ? ((await response.json()) as WsusComparison)
        : null,
      available: response.ok,
      sessionValid: response.status !== 401,
    };
  } catch {
    return {
      sources: Array.isArray(sources) ? sources : [],
      comparison: null,
      available: false,
      sessionValid: true,
    };
  }
}
