/**
 * File Name: security-override-validation.spec.ts
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify typed original-setting boundaries independently of the editor.
 */
import { expect, test } from "@playwright/test";
import { overrideReadonlyReason } from "../src/i18n/security-override-copy";
import {
  isOverrideCatalog,
  isOverrideReview,
  isSecurityOverride,
  type OverrideSetting,
  parseOverrideInput,
} from "../src/lib/security-override-types";

const setting: OverrideSetting = {
  setting_id: "a".repeat(64),
  label: "Original",
  category: "Policy",
  kind: "registry",
  file: "registry.pol",
  path: "Policy",
  name: "Original",
  scope: "machine",
  value_type: "integer",
  baseline_value: 1,
  editable: true,
  readonly_reason: "",
  min: 0,
  max: 3,
  max_length: 20,
  max_items: 2,
  enum_options: [],
};
test("structured original values explain the editor restriction in German and English", () => {
  const de = overrideReadonlyReason("structured_registry_value", "de");
  const en = overrideReadonlyReason("structured_registry_value", "en");
  expect(de).toContain("AppLocker-XML");
  expect(de).toContain("eigener Editor");
  expect(en).toContain("AppLocker XML");
  expect(en).toContain("dedicated editor");
  expect(de).not.toContain("structured_registry_value");
  expect(en).not.toContain("structured_registry_value");
  expect(
    overrideReadonlyReason("untrusted_backend_detail", "de"),
  ).not.toContain("untrusted_backend_detail");
});
test("integer editing preserves zero and rejects coercion, fractions and bounds", () => {
  expect(parseOverrideInput(setting, "0")).toBe(0);
  for (const input of ["", "true", "0x1", "1.1", "4", "-1", "NaN"])
    expect(parseOverrideInput(setting, input)).toBeNull();
});
test("structural settings are visible but cannot be edited", () => {
  const readonly = {
    ...setting,
    editable: false,
    value_type: "unsupported",
    readonly_reason: "structural_instruction",
    baseline_value: { hex: "" },
  };
  expect(
    isOverrideCatalog({
      baseline_id: "baseline",
      backup_id: "component",
      artifact_sha256: "b".repeat(64),
      settings: [readonly],
    }),
  ).toBe(true);
  expect(parseOverrideInput({ ...setting, editable: false }, "0")).toBeNull();
  expect(
    isOverrideCatalog({
      baseline_id: "baseline",
      backup_id: "component",
      artifact_sha256: "b".repeat(64),
      settings: [{ ...readonly, editable: true }],
    }),
  ).toBe(false);
});
test("enum and list editing enforce original constraints with deliberate empty list", () => {
  expect(
    parseOverrideInput(
      { ...setting, enum_options: [{ value: 0, label: "Off" }] },
      "1",
    ),
  ).toBeNull();
  const list = {
    ...setting,
    value_type: "string_list" as const,
    baseline_value: ["one"],
  };
  expect(parseOverrideInput(list, "")).toEqual([]);
  expect(parseOverrideInput(list, "one\ntwo")).toEqual(["one", "two"]);
  expect(parseOverrideInput(list, "one\ntwo\nthree")).toBeNull();
  expect(parseOverrideInput(list, "one\n")).toBeNull();
  expect(
    parseOverrideInput({ ...setting, value_type: "string" }, "bad\u0000value"),
  ).toBeNull();
});
test("duplicate or arbitrary override entries invalidate the server projection", () => {
  const row = {
    id: "11111111-1111-4111-8111-111111111111",
    name: "Example",
    baseline_id: "baseline",
    backup_id: "component",
    artifact_sha256: "b".repeat(64),
    revision: 1,
    enabled: true,
    sha256: "c".repeat(64),
    entries: [{ setting_id: setting.setting_id, value: 0 }],
  };
  expect(isSecurityOverride(row)).toBe(true);
  expect(
    isSecurityOverride({ ...row, entries: [...row.entries, ...row.entries] }),
  ).toBe(false);
  expect(
    isSecurityOverride({
      ...row,
      entries: [{ ...row.entries[0], path: "injected" }],
    }),
  ).toBe(false);
});

test("approval differences must match the immutable override entries", () => {
  const review = {
    override_id: "11111111-1111-4111-8111-111111111111",
    override_revision: 1,
    override_sha256: "a".repeat(64),
    override_entries: [{ setting_id: setting.setting_id, value: 0 }],
    settings: [
      {
        setting_id: setting.setting_id,
        label: "Original",
        category: "Policy",
        baseline_value: 1,
        value: 0,
      },
    ],
  };
  expect(isOverrideReview(review)).toBe(true);
  expect(
    isOverrideReview({
      ...review,
      settings: [{ ...review.settings[0], value: 2 }],
    }),
  ).toBe(false);
  expect(isOverrideReview({ ...review, settings: [] })).toBe(false);
});
