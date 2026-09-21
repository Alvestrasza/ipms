/**
 * File Name: hgs-workspace.spec.ts
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify HGS review, tenant scope and recovery UI using explicit local API fixtures.
 */
import { expect, type Page, test } from "@playwright/test";
import {
  deploymentId,
  makePlan,
  systemId,
  tenantId,
} from "./fixtures/hgs-portal.mjs";

async function open(
  page: Page,
  role = "admin",
  scenario = "ready",
  locale = "en",
) {
  await page.context().addCookies([
    { name: "hgs_fixture_role", value: role, domain: "127.0.0.1", path: "/" },
    {
      name: "hgs_fixture_scenario",
      value: scenario,
      domain: "127.0.0.1",
      path: "/",
    },
  ]);
  await page.goto(`/${locale}/security/hgs`);
}

test("exact plan review is required before execution; the response remains in progress", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await open(page);
  await expect(
    page.getByRole("heading", { name: "Host Guardian Service", exact: true }),
  ).toBeVisible();
  const execute = page.getByRole("button", {
    name: "Authorize and execute plan",
    exact: true,
  });
  await expect(execute).toBeDisabled();
  await expect(
    page.getByRole("heading", { name: "Planned steps", exact: true }),
  ).toBeVisible();
  const requests: unknown[] = [];
  await page.route(
    `**/api/v1/hgs/deployments/${deploymentId}/execute/`,
    async (route) => {
      requests.push(route.request().postDataJSON());
      expect(route.request().headers()["x-ipms-tenant-id"]).toBe(tenantId);
      expect(route.request().headers()["x-csrftoken"]).toBe("hgs-fixture-csrf");
      await route.fulfill({ status: 202, json: makePlan("running") });
    },
  );
  await page
    .getByRole("checkbox", { name: /I have reviewed these targets/ })
    .check();
  await expect(execute).toBeEnabled();
  await execute.click();
  await expect(page.getByRole("status")).toContainText(
    "Execution was authorized for this exact plan",
  );
  expect(requests).toEqual([{ plan_digest: "a".repeat(64), confirm: true }]);
  await expect(execute).toHaveCount(0);
  await expect(page.getByText("Running", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("expired plans cannot execute and reconciliation never offers write replay", async ({
  page,
}) => {
  await open(page, "admin", "expired");
  await expect(page.getByText(/This plan has expired/)).toBeVisible();
  await expect(
    page.getByRole("checkbox", { name: /I have reviewed/ }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Authorize and execute plan" }),
  ).toBeDisabled();
  await open(page, "admin", "reconciliation_required");
  await expect(
    page.getByRole("button", { name: "Authorize and execute plan" }),
  ).toHaveCount(0);
  await expect(
    page.getByText(/Fresh inspection does not authorize replay/),
  ).toBeVisible();
  await page.route(
    `**/api/v1/hgs/deployments/${deploymentId}/reconcile/`,
    async (route) => {
      expect(route.request().postDataJSON()).toEqual({});
      await route.fulfill({ status: 202, json: makePlan("inspecting") });
    },
  );
  await page
    .getByRole("button", { name: "Inspect for reconciliation" })
    .click();
  await expect(page.getByRole("status")).toContainText(
    "No write operation was replayed",
  );
});

test("lost execution reply locks mutation until an explicit state refresh", async ({
  page,
}) => {
  await open(page);
  let calls = 0;
  await page.route(
    `**/api/v1/hgs/deployments/${deploymentId}/execute/`,
    async (route) => {
      calls += 1;
      await route.abort("failed");
    },
  );
  await page.getByRole("checkbox", { name: /I have reviewed/ }).check();
  await page
    .getByRole("button", { name: "Authorize and execute plan" })
    .click();
  await expect(
    page.getByRole("button", { name: "Authorize and execute plan" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Inspect nodes" }),
  ).toBeDisabled();
  expect(calls).toBe(1);
});

test("verified recovery requires new consent for its exact evidence and never sends execute", async ({
  page,
}) => {
  await open(page, "admin", "resolvable");
  const resolve = page.getByRole("button", {
    name: "Accept verified state and resume",
  });
  await expect(resolve).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Authorize and execute plan" }),
  ).toHaveCount(0);
  await page.route(
    `**/api/v1/hgs/deployments/${deploymentId}/resolve/`,
    async (route) => {
      expect(route.request().postDataJSON()).toEqual({
        job_id: "50000000-0000-4000-8000-000000000001",
        plan_digest: "a".repeat(64),
        observation_digest: "e".repeat(64),
        confirm: true,
      });
      await route.fulfill({ status: 202, json: makePlan("running") });
    },
  );
  await page
    .getByRole("checkbox", { name: /I have reviewed the current evidence/ })
    .check();
  await resolve.click();
  await expect(page.getByRole("status")).toContainText(
    "the interrupted write was not replayed",
  );
});

test("German secure plan uses TPM and references only; existing VMs remain a separate operation", async ({
  page,
}) => {
  await open(page, "admin", "empty", "de");
  await page
    .getByRole("combobox", { name: "VM-Schutzprofil", exact: true })
    .selectOption("shielded");
  await expect(
    page.getByRole("combobox", { name: "Host-Attestierung", exact: true }),
  ).toHaveValue("tpm");
  await page.getByLabel("Name der Bereitstellung").fill("Shielded fixture");
  await page
    .getByLabel("DNS-Name des neuen HGS-Forests")
    .fill("hgs.example.test");
  await page.getByLabel("HGS-Dienstname", { exact: true }).fill("hgs");
  await page
    .getByLabel("Lokale Quelle der Windows-Features")
    .fill("D:\\Sources\\SxS");
  await page
    .getByLabel("Fingerabdruck des Signaturzertifikats")
    .fill("b".repeat(40));
  await page
    .getByLabel("Fingerabdruck des Verschlüsselungszertifikats")
    .fill("c".repeat(40));
  await page.getByLabel("Lokale DSRM-Geheimnisreferenz").fill("hgs-dsrm");
  await page.getByRole("checkbox", { name: /hgs-fixture-01/ }).check();
  await page
    .getByRole("checkbox", { name: /Geplante Windows-Neustarts/ })
    .check();
  await page.route("**/api/v1/hgs/deployments/", async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      name: "Shielded fixture",
      profile: "shielded",
      attestation_mode: "tpm",
      domain_name: "hgs.example.test",
      service_name: "hgs",
      feature_source: "D:\\Sources\\SxS",
      signing_thumbprint: "b".repeat(40),
      encryption_thumbprint: "c".repeat(40),
      dsrm_secret_ref: "hgs-dsrm",
      join_secret_ref: "",
      primary_server: "",
      allow_reboot: true,
      node_ids: [systemId],
    });
    await route.fulfill({
      status: 201,
      json: {
        ...makePlan("draft"),
        profile: "shielded",
        attestation_mode: "tpm",
        name: "Shielded fixture",
      },
    });
  });
  await page
    .getByRole("button", { name: "Plan erstellen", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Planprüfung: Shielded fixture" }),
  ).toBeVisible();
  await expect(
    page.getByText(/bestehende VMs werden nicht geändert/),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Knoten prüfen", exact: true }),
  ).toBeEnabled();
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
  await page.screenshot({
    path: test.info().outputPath("hgs-german-plan.png"),
    fullPage: true,
  });
});

test("reader cannot mutate, infrastructure tenant sees separation, platform cannot enter HGS", async ({
  page,
}) => {
  await open(page, "reader");
  await expect(page.getByText(/Your account can view HGS plans/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Inspect nodes" })).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: "Authorize and execute plan" }),
  ).toHaveCount(0);
  await open(page, "infrastructure");
  await expect(
    page.getByText(/Use a separate tenant with the purpose/),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Create plan" })).toHaveCount(
    0,
  );
  await open(page, "platform");
  await expect(page).toHaveURL(/\/en\/administration\/tenants$/);
  await expect(
    page.getByRole("columnheader", { name: "Tenant purpose" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Edit tenant Fixture HGS tenant" })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("combobox", { name: "Tenant purpose", exact: true }),
  ).toBeDisabled();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Cancel", exact: true })
    .last()
    .click();
  await page
    .getByRole("button", { name: "Create tenant", exact: true })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("combobox", { name: "Tenant purpose", exact: true }),
  ).toBeEnabled();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("combobox", { name: "Tenant purpose", exact: true }),
  ).toHaveValue("infrastructure");
});
