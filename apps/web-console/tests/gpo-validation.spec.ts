/**
 * File Name: gpo-validation.spec.ts
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Preserve failed inspection details while rejecting malformed observations.
 */
import { expect, test } from "@playwright/test";
import {
  isGpoImportJob,
  isGpoImportReview,
} from "../src/lib/domain-security-validation";
import { isGpoImportLogDetail } from "../src/lib/job-log-types";

const review = {
  component_name: "Domain Security",
  artifact_sha256: "a".repeat(64),
  report_xml: "<GPO/>",
  files: [],
  changes: ["inspect_managed_gpo"],
  expected_state: null,
  target_ous: ["DC=example,DC=test"],
  safety_review: { management_access: false, recovery_access: false },
};
const failed = {
  id: "11111111-1111-4111-8111-111111111111",
  baseline_id: "microsoft-windows-server-2025",
  backup_id: "fixture",
  pilot_display_name: "0-C-ALL-DomainSecurity_V1.0.0",
  hostname: "dc.example.test",
  error_code: "gpo_preflight_required",
  requested_by_name: "administrator",
  input_digest: "b".repeat(64),
  dc_fqdn: "dc.example.test",
  status: "failed",
  tier: "0",
  requested_at: "2026-09-16T00:00:00Z",
  completed_at: "2026-09-16T00:00:02Z",
  gpo_guid: null,
  requested_by: "1",
  approval_document: null,
  approval_mode: "inspection",
  operation: "inspect_managed_gpo",
  preflight_state: null,
  approved_by: null,
  approved_by_name: null,
  approved_at: null,
  four_eyes_required: false,
  policy_revision: 1,
  can_approve: false,
  approval_blocker: "inspection_only",
  expires_at: "2026-09-16T00:15:00Z",
  review,
  domain_id: "22222222-2222-4222-8222-222222222222",
  domain: "example.test",
};
test("failed inspection without a snapshot remains available in Logs", () => {
  expect(isGpoImportReview(review)).toBe(true);
  expect(isGpoImportJob(failed)).toBe(true);
  expect(isGpoImportLogDetail(failed)).toBe(true);
});
test("invalid observations are not treated as missing inspection state", () => {
  for (const expected_state of [{}, false, "null", { schema: 1, gpo: null }]) {
    expect(
      isGpoImportLogDetail({
        ...failed,
        review: { ...review, expected_state },
      }),
    ).toBe(false);
  }
});
