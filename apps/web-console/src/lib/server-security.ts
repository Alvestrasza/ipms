/**
 * File Name: server-security.ts
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Read security baselines through the authenticated tenant API.
 */
import "server-only";

import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import type {
  SecurityBaseline,
  SecurityBaselineCatalog,
  SecurityBaselineSystems,
  SecurityBaselineTarget,
} from "./security-types";

type SecurityResponse<T> = {
  data: T | null;
  available: boolean;
  sessionValid: boolean;
  forbidden: boolean;
  notFound: boolean;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isPercent(value: unknown): value is number | null {
  return (
    value === null ||
    (typeof value === "number" &&
      Number.isFinite(value) &&
      value >= 0 &&
      value <= 100)
  );
}

function isOptionalDate(value: unknown): value is string | null {
  return (
    value === null ||
    (typeof value === "string" && Number.isFinite(Date.parse(value)))
  );
}

function isSourceUrl(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}

function isBaseline(value: unknown): value is SecurityBaseline {
  if (!isRecord(value) || !isRecord(value.summary)) return false;
  const summary = value.summary;
  return (
    [
      "id",
      "name",
      "release",
      "source_url",
      "package_name",
      "verified_at",
    ].every((key) => typeof value[key] === "string" && value[key] !== "") &&
    typeof value.revision === "string" &&
    isSourceUrl(value.source_url) &&
    value.provider === "microsoft" &&
    value.platform === "windows" &&
    ["server", "client"].includes(value.target as string) &&
    value.assessment_state === "catalog-only" &&
    Array.isArray(value.profiles) &&
    value.profiles.every((profile) => typeof profile === "string") &&
    [
      "applicable",
      "compliant",
      "non_compliant",
      "unknown",
      "error",
      "stale",
      "assessed",
    ].every((key) => isCount(summary[key])) &&
    isPercent(summary.compliance_percent) &&
    isPercent(summary.coverage_percent) &&
    isOptionalDate(summary.last_assessed_at)
  );
}

function isCatalog(value: unknown): value is SecurityBaselineCatalog {
  if (
    !isRecord(value) ||
    !isRecord(value.inventory) ||
    !isRecord(value.capabilities)
  )
    return false;
  const inventory = value.inventory;
  const capabilities = value.capabilities;
  return (
    typeof value.catalog_revision === "string" &&
    typeof value.generated_at === "string" &&
    isOptionalDate(value.generated_at) &&
    ["total", "servers", "clients", "unclassified", "unmatched"].every((key) =>
      isCount(inventory[key]),
    ) &&
    ["assessment", "deployment", "collections"].every(
      (key) => typeof capabilities[key] === "boolean",
    ) &&
    Array.isArray(value.results) &&
    value.results.every(isBaseline)
  );
}

function isSystems(value: unknown): value is SecurityBaselineSystems {
  return (
    isRecord(value) &&
    isBaseline(value.baseline) &&
    isCount(value.count) &&
    isCount(value.page) &&
    value.page > 0 &&
    isCount(value.page_size) &&
    value.page_size > 0 &&
    Array.isArray(value.results) &&
    value.results.every(
      (system) =>
        isRecord(system) &&
        [
          "id",
          "hostname",
          "fqdn",
          "operating_system",
          "os_build",
          "operating_system_role",
          "server_type",
        ].every((key) => typeof system[key] === "string") &&
        ["compliant", "non_compliant", "unknown", "error", "stale"].includes(
          system.status as string,
        ) &&
        [
          "not_assessed",
          "partial",
          "assessment_error",
          "expired",
          "baseline_changed",
          "system_changed",
          "agent_unavailable",
          "complete",
        ].includes(system.reason as string) &&
        isOptionalDate(system.assessed_at),
    )
  );
}

async function readSecurity<T>(
  tenantId: string,
  path: string,
  valid: (value: unknown) => value is T,
): Promise<SecurityResponse<T>> {
  const headers = controlPlaneHeaders({
    cookie: (await cookies()).toString(),
    "X-IPMS-Tenant-ID": tenantId,
  });
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}${path}`, {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
    });
    const payload: unknown = response.ok ? await response.json() : null;
    const data = valid(payload) ? payload : null;
    return {
      data,
      available: response.ok && data !== null,
      sessionValid: response.status !== 401,
      forbidden: response.status === 403,
      notFound: response.status === 404,
    };
  } catch {
    return {
      data: null,
      available: false,
      sessionValid: true,
      forbidden: false,
      notFound: false,
    };
  }
}

export function getSecurityBaselineCatalog(
  tenantId: string,
  target: SecurityBaselineTarget = "all",
) {
  const query = new URLSearchParams({ target });
  return readSecurity(
    tenantId,
    `/api/v1/security/baselines/?${query}`,
    isCatalog,
  );
}

export function getSecurityBaselineSystems(
  tenantId: string,
  baselineId: string,
  page = 1,
) {
  const query = new URLSearchParams({ page: String(page) });
  return readSecurity(
    tenantId,
    `/api/v1/security/baselines/${encodeURIComponent(baselineId)}/systems/?${query}`,
    isSystems,
  );
}
