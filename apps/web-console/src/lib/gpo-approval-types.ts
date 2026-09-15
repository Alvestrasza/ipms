/**
 * File Name: gpo-approval-types.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Validate tenant approval rules and explicit domain/Tier authorizations.
 */
import type { SecurityTier } from "./domain-security-types";

export type GpoApprovalPolicy = {
  four_eyes_required: boolean;
  revision: number;
};

export type GpoDomainAuthorization = {
  revision: number;
  grants: { user_id: string; tiers: SecurityTier[] }[];
  members: {
    user_id: string;
    username: string;
    role: "tenant_admin" | "approver";
  }[];
};

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function revision(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

export function isGpoApprovalPolicy(
  value: unknown,
): value is GpoApprovalPolicy {
  return (
    record(value) &&
    revision(value.revision) &&
    typeof value.four_eyes_required === "boolean"
  );
}

export function isGpoDomainAuthorization(
  value: unknown,
): value is GpoDomainAuthorization {
  return (
    record(value) &&
    revision(value.revision) &&
    Array.isArray(value.grants) &&
    value.grants.length <= 1000 &&
    value.grants.every(
      (grant) =>
        record(grant) &&
        typeof grant.user_id === "string" &&
        grant.user_id.length > 0 &&
        Array.isArray(grant.tiers) &&
        grant.tiers.length <= 3 &&
        grant.tiers.every(
          (tier) => tier === "0" || tier === "1" || tier === "2",
        ) &&
        new Set(grant.tiers).size === grant.tiers.length,
    ) &&
    new Set(value.grants.map((grant) => grant.user_id)).size ===
      value.grants.length &&
    Array.isArray(value.members) &&
    value.members.length <= 1000 &&
    value.members.every(
      (member) =>
        record(member) &&
        typeof member.user_id === "string" &&
        member.user_id.length > 0 &&
        typeof member.username === "string" &&
        (member.role === "tenant_admin" || member.role === "approver"),
    ) &&
    new Set(value.members.map((member) => member.user_id)).size ===
      value.members.length
  );
}
