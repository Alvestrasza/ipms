/**
 * File Name: gpo-production.spec.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify separate production GPO requests through the real isolated Portal and synthetic native observations.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { expect, type Page, type Route, test } from "@playwright/test";
import type {
  DomainSecurityCatalog,
  GpoImportJob,
} from "../src/lib/domain-security-types";

const domainsApi = "/api/v1/security/domain-settings/";
const managementCheck =
  "I have checked that the proposed settings preserve IPMS and the required administrator access.";
const recoveryCheck =
  "I have verified an independent recovery access path for the affected domain and tier.";
type Fixture = { domain_id: string; domain_name: string; system_id: string };
type Headers = Record<string, string>;

function nativeFixture(mode: string, jobId?: string) {
  const python =
    process.env.IPMS_TEST_PYTHON ||
    path.resolve(
      "../../services/control-plane",
      process.platform === "win32"
        ? ".venv/Scripts/python.exe"
        : ".venv/bin/python",
    );
  return JSON.parse(
    execFileSync(
      python,
      [
        path.resolve("tests/fixtures/gpo-production.py"),
        mode,
        ...(jobId ? [jobId] : []),
      ],
      { encoding: "utf8", windowsHide: true },
    ),
  );
}

async function setup(page: Page) {
  const fixture: Fixture = nativeFixture("setup");
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill("e2e-admin");
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/?$/);
  const session = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  const tenant = session.tenants.find(
    (item: { slug: string }) => item.slug === "console-e2e",
  );
  const headers: Headers = {
    "X-CSRFToken": session.csrf_token,
    "X-IPMS-Tenant-ID": tenant.id,
  };
  const catalog: DomainSecurityCatalog = await (
    await page.request.get(domainsApi, { headers })
  ).json();
  const settings = catalog.results.find(
    (item) => item.id === fixture.domain_id,
  );
  if (!settings) throw new Error("Missing production fixture domain.");
  const baseline = catalog.baseline_options.find(
    (item) => item.id === "microsoft-windows-server-2025",
  );
  const component = baseline?.components.find(
    (item) => item.available && item.scope === "machine",
  );
  if (!baseline || !component)
    throw new Error("Verified machine GPO content is required.");
  return {
    fixture,
    headers,
    session,
    settings,
    baseline,
    component,
    endpoint: `${domainsApi}${fixture.domain_id}`,
  };
}

type Context = Awaited<ReturnType<typeof setup>>;
const panel = (page: Page) =>
  page.getByRole("region", { name: "GPO distribution", exact: true });

async function openWorkflow(page: Page, context: Context) {
  await page.goto(
    "/en/security/baseline?baseline=microsoft-windows-server-2025",
  );
  await page
    .getByRole("combobox", { name: "Configured domain", exact: true })
    .selectOption(context.fixture.domain_id);
  await expect(
    panel(page).getByRole("button", { name: "Inspect AD state", exact: true }),
  ).toBeEnabled();
  await panel(page)
    .getByRole("combobox", { name: "Component", exact: true })
    .selectOption(context.component.id);
}

async function inspect(page: Page, context: Context) {
  const pending = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${context.endpoint}/gpo-preflights/`) &&
      response.request().method() === "POST",
  );
  await panel(page)
    .getByRole("button", { name: "Inspect AD state", exact: true })
    .click();
  const response = await pending;
  expect(response.status()).toBe(202);
  const job: GpoImportJob = await response.json();
  expect(job.operation).toBe("inspect_managed_gpo");
  expect(job.approval_mode).toBe("inspection");
  expect(job.approved_at).toBeNull();
  expect(job.can_approve).toBe(false);
  const native = nativeFixture("inspect", job.id);
  expect(native.status).toBe("inspected");
  expect(native.approved_at).toBeNull();
  expect(native.claimed_at).toBeNull();
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(
    panel(page).getByRole("region", { name: "Verified AD state", exact: true }),
  ).toBeVisible();
  return job;
}

async function createRequest(
  page: Page,
  context: Context,
  preflight: GpoImportJob,
  operation: string,
  safety = false,
) {
  const pending = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${context.endpoint}/managed-gpos/`) &&
      response.request().method() === "POST",
  );
  await panel(page)
    .getByRole("button", { name: "Create approval request", exact: true })
    .click();
  const response = await pending;
  expect(response.status()).toBe(202);
  const body = response.request().postDataJSON();
  expect(body).toEqual({
    preflight_id: preflight.id,
    idempotency_key: expect.any(String),
    safety_review: { management_access: safety, recovery_access: safety },
  });
  expect(response.request().headers()["x-ipms-tenant-id"]).toBe(
    context.headers["X-IPMS-Tenant-ID"],
  );
  expect(response.request().headers()["x-csrftoken"]).toMatch(
    /^[a-zA-Z0-9]{64}$/,
  );
  const job: GpoImportJob = await response.json();
  expect(job.id).toBe(body.idempotency_key);
  expect(job.id).not.toBe(preflight.id);
  expect(job.operation).toBe(operation);
  expect(job.status).toBe("awaiting_approval");
  expect(job.approved_at).toBeNull();
  expect(job.approval_mode).toBe("portal");
  await expect(
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toBeDisabled();
  return job;
}

async function approveAndCompleteFixture(
  page: Page,
  context: Context,
  job: GpoImportJob,
) {
  const approved = await page.request.post(
    `/api/v1/security/gpo-imports/${job.id}/approve/`,
    {
      headers: context.headers,
      data: {
        input_digest: job.input_digest,
        policy_revision: job.policy_revision,
      },
    },
  );
  expect(approved.status()).toBe(200);
  return nativeFixture("complete", job.id);
}

async function seedPrepared(page: Page, context: Context) {
  const selection = {
    revision: context.settings.revision,
    system_id: context.fixture.system_id,
    baseline_id: context.baseline.id,
    backup_id: context.component.id,
    tier: "0",
    target: "ALL",
    version: "1.0.0",
    idempotency_key: randomUUID(),
    operation: "import_managed_gpo",
    managed_id: null,
    adopt_job_id: null,
  };
  const response = await page.request.post(
    `${context.endpoint}/gpo-preflights/`,
    { headers: context.headers, data: selection },
  );
  expect(response.status()).toBe(202);
  const preflight: GpoImportJob = await response.json();
  nativeFixture("inspect", preflight.id);
  const created = await page.request.post(`${context.endpoint}/managed-gpos/`, {
    headers: context.headers,
    data: {
      preflight_id: preflight.id,
      idempotency_key: randomUUID(),
      safety_review: { management_access: false, recovery_access: false },
    },
  });
  expect(created.status()).toBe(202);
  const job: GpoImportJob = await created.json();
  const receipt = await approveAndCompleteFixture(page, context, job);
  expect(receipt.status).toBe("staged");
  expect(receipt.state.gpo.computer_enabled).toBe(false);
  expect(receipt.state.gpo.user_enabled).toBe(false);
  expect(receipt.state.gpo.links).toEqual([]);
  return receipt;
}

async function completeFixtureAction(
  page: Page,
  context: Context,
  managedId: string,
  operation: "link_managed_gpo" | "activate_managed_gpo",
  version = "1.0.0",
) {
  const response = await page.request.post(
    `${context.endpoint}/gpo-preflights/`,
    {
      headers: context.headers,
      data: {
        revision: context.settings.revision,
        system_id: context.fixture.system_id,
        baseline_id: context.baseline.id,
        backup_id: context.component.id,
        tier: "0",
        target: "ALL",
        version,
        idempotency_key: randomUUID(),
        operation,
        managed_id: managedId,
        adopt_job_id: null,
      },
    },
  );
  expect(response.status()).toBe(202);
  const preflight: GpoImportJob = await response.json();
  nativeFixture("inspect", preflight.id);
  const active = operation === "activate_managed_gpo";
  const created = await page.request.post(`${context.endpoint}/managed-gpos/`, {
    headers: context.headers,
    data: {
      preflight_id: preflight.id,
      idempotency_key: randomUUID(),
      safety_review: { management_access: active, recovery_access: active },
    },
  });
  expect(created.status()).toBe(202);
  return approveAndCompleteFixture(page, context, await created.json());
}

test("preparing V2 keeps V1 visibly active until a separately approved activation", async ({
  page,
}) => {
  const context = await setup(page);
  const prepared = await seedPrepared(page, context);
  await completeFixtureAction(
    page,
    context,
    prepared.managed_id,
    "link_managed_gpo",
  );
  const active = await completeFixtureAction(
    page,
    context,
    prepared.managed_id,
    "activate_managed_gpo",
  );
  expect(active.status).toBe("activated");
  expect(active.state.gpo.name).toMatch(/_V1\.0\.0$/);
  await openWorkflow(page, context);
  const managed = panel(page).getByRole("combobox", {
    name: "Managed GPO",
    exact: true,
  });
  await managed.selectOption(prepared.managed_id);
  const option = managed.locator(`option[value="${prepared.managed_id}"]`);
  await expect(option).toHaveText(`${active.state.gpo.name} · Active`);
  await panel(page).getByLabel("Version", { exact: true }).fill("2.0.0");
  const preflight = await inspect(page, context);
  const imported = await createRequest(
    page,
    context,
    preflight,
    "import_managed_gpo",
  );
  const staged = await approveAndCompleteFixture(page, context, imported);
  expect(staged.state.gpo).toEqual(active.state.gpo);
  expect(staged.gpo_guid).toBe(active.gpo_guid);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  const desired = active.state.gpo.name.replace(/_V1\.0\.0$/, "_V2.0.0");
  await expect(option).toHaveText(
    `${active.state.gpo.name} · Active · Version prepared: ${desired}`,
  );
  await expect(option).not.toContainText(`${desired} · Active`);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.results[0]).toMatchObject({
    state: "active",
    active_display_name: active.state.gpo.name,
    display_name: desired,
    gpo_guid: active.gpo_guid,
  });
  const unverified = async (route: Route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.results[0].active_display_name = null;
    await route.fulfill({ response, json: body });
  };
  await page.route(`**${context.endpoint}/managed-gpos/`, unverified);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(option).toHaveText(
    `Active version not verified · Version prepared: ${desired}`,
  );
  await expect(option).not.toContainText(`${desired} · Active`);
  await page.unroute(`**${context.endpoint}/managed-gpos/`, unverified);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(option).toHaveText(
    `${active.state.gpo.name} · Active · Version prepared: ${desired}`,
  );
  await panel(page)
    .getByRole("combobox", { name: "Action", exact: true })
    .selectOption("activate_managed_gpo");
  const activationPreflight = await inspect(page, context);
  await panel(page)
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .check();
  await panel(page)
    .getByRole("checkbox", { name: recoveryCheck, exact: true })
    .check();
  const activation = await createRequest(
    page,
    context,
    activationPreflight,
    "activate_managed_gpo",
    true,
  );
  const activated = await approveAndCompleteFixture(page, context, activation);
  expect(activated.state.gpo.name).toBe(desired);
  expect(activated.gpo_guid).toBe(active.gpo_guid);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(option).toHaveText(`${desired} · Active`);
  await expect(option).not.toContainText("Version prepared:");
});

test("domain-wide account policies require an explicit root target for each separately approved action", async ({
  page,
}) => {
  const context = await setup(page);
  const domainComponent = context.baseline.components.find(
    (item) => item.available && item.scope === "domain",
  );
  if (!domainComponent)
    throw new Error("The fixture needs a domain-wide account policy.");
  context.component = domainComponent;
  const prepared = await seedPrepared(page, context);
  await openWorkflow(page, context);
  const workflow = panel(page);
  await workflow
    .getByRole("combobox", { name: "Managed GPO", exact: true })
    .selectOption(prepared.managed_id);
  await expect(workflow).toContainText(
    "Domain-wide account policies target the domain root with explicit Tier 0 authorization.",
  );
  const inspectButton = workflow.getByRole("button", {
    name: "Inspect AD state",
    exact: true,
  });
  const action = workflow.getByRole("combobox", {
    name: "Action",
    exact: true,
  });
  await action.selectOption("link_managed_gpo");
  const rootConfirmation = workflow.getByRole("checkbox", {
    name: "I confirm the domain root as the target for this domain-wide account policy. This confirmation does not approve its execution.",
    exact: true,
  });
  await expect(rootConfirmation).not.toBeChecked();
  await expect(inspectButton).toBeDisabled();
  const rootDn = context.fixture.domain_name
    .split(".")
    .map((part) => `DC=${part}`)
    .join(",");
  await expect(workflow).toContainText(rootDn);
  await rootConfirmation.check();
  const request = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      request.url().endsWith(`${context.endpoint}/gpo-preflights/`),
  );
  const linkInspection = await inspect(page, context);
  const selection = (await request).postDataJSON();
  expect(selection.domain_root_confirmed).toBe(true);
  expect(selection).not.toHaveProperty("target_ous");
  expect(selection).not.toHaveProperty("domain_root");
  const review = workflow.getByRole("region", {
    name: "Verified AD state",
    exact: true,
  });
  await expect(
    review.getByRole("heading", { name: "Domain root", exact: true }),
  ).toBeVisible();
  await expect(review).toContainText(rootDn);
  await expect(review).not.toContainText(context.settings.tier_ous["0"][0]);
  const linking = await createRequest(
    page,
    context,
    linkInspection,
    "link_managed_gpo",
  );
  const linked = await approveAndCompleteFixture(page, context, linking);
  expect(linked.state.gpo.links).toEqual([
    expect.objectContaining({
      kind: "domain",
      dn: rootDn,
      enabled: false,
      enforced: false,
    }),
  ]);
  await workflow.getByRole("button", { name: "Refresh", exact: true }).click();
  await action.selectOption("activate_managed_gpo");
  await expect(rootConfirmation).not.toBeChecked();
  await expect(inspectButton).toBeDisabled();
  await rootConfirmation.check();
  const activationInspection = await inspect(page, context);
  await expect(
    workflow.getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toBeDisabled();
  await workflow
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .check();
  await expect(
    workflow.getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toBeDisabled();
  await workflow
    .getByRole("checkbox", { name: recoveryCheck, exact: true })
    .check();
  const activation = await createRequest(
    page,
    context,
    activationInspection,
    "activate_managed_gpo",
    true,
  );
  const activated = await approveAndCompleteFixture(page, context, activation);
  expect(activated.gpo_guid).toBe(prepared.gpo_guid);
  expect(activated.state.gpo.links).toEqual([
    expect.objectContaining({
      kind: "domain",
      dn: rootDn,
      enabled: true,
      enforced: false,
    }),
  ]);
  await page.goto(`/de/security/baseline?baseline=${context.baseline.id}`);
  await page
    .getByRole("combobox", { name: "Konfigurierte Domäne", exact: true })
    .selectOption(context.fixture.domain_id);
  const german = page.getByRole("region", {
    name: "GPO-Verteilung",
    exact: true,
  });
  await german
    .getByRole("combobox", { name: "Verwaltete GPO", exact: true })
    .selectOption(prepared.managed_id);
  await german
    .getByRole("combobox", { name: "Aktion", exact: true })
    .selectOption("deactivate_managed_gpo");
  await expect(
    german.getByRole("checkbox", {
      name: "Ich bestätige die Domänenwurzel als Ziel dieser domänenweiten Kontorichtlinie. Diese Bestätigung gibt die Ausführung noch nicht frei.",
      exact: true,
    }),
  ).not.toBeChecked();
  await expect(
    german.getByRole("button", { name: "AD-Zustand prüfen", exact: true }),
  ).toBeDisabled();
});
test("inspection shows the short production name and creates a distinct unapproved import request", async ({
  page,
}) => {
  const context = await setup(page);
  const approvals: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/approve/"))
      approvals.push(request.url());
  });
  await openWorkflow(page, context);
  await expect(panel(page)).not.toContainText(/pilot/i);
  await expect(
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toHaveCount(0);
  const preflight = await inspect(page, context);
  expect(preflight.display_name).toMatch(
    /^0-C-ALL-MS-WS2025-[A-Za-z0-9-]+_V1\.0\.0$/,
  );
  expect(preflight.display_name?.length).toBeLessThan(80);
  expect(preflight.display_name).not.toMatch(/pilot|[a-f0-9]{8}-[a-f0-9]{4}/i);
  await expect(panel(page)).toContainText("New disabled, unlinked GPO");
  await expect(panel(page)).toContainText(
    "No target OUs selected for this import.",
  );
  const job = await createRequest(
    page,
    context,
    preflight,
    "import_managed_gpo",
  );
  const refreshed = await (
    await page.request.get(`/api/v1/security/gpo-imports/${preflight.id}/`, {
      headers: context.headers,
    })
  ).json();
  expect(refreshed.operation).toBe("inspect_managed_gpo");
  expect(refreshed.status).toBe("inspected");
  expect(refreshed.input_digest).toBe(preflight.input_digest);
  await panel(page)
    .getByRole("link", { name: "Review request in Logs", exact: true })
    .click();
  await expect(page).toHaveURL(new RegExp(`/logs/baselines\\?job=${job.id}$`));
  await expect(
    page.getByRole("heading", { name: job.display_name, exact: true }),
  ).toBeVisible();
  expect(approvals).toEqual([]);
});

test("OU linking and activation have separate requests and activation requires both access reviews", async ({
  page,
}) => {
  const context = await setup(page);
  const prepared = await seedPrepared(page, context);
  await openWorkflow(page, context);
  await panel(page)
    .getByRole("combobox", { name: "Managed GPO", exact: true })
    .selectOption(prepared.managed_id);
  await panel(page)
    .getByRole("combobox", { name: "Action", exact: true })
    .selectOption("link_managed_gpo");
  await expect(panel(page)).toContainText(
    "New links stay disabled until a separate activation is approved.",
  );
  const linkInspection = await inspect(page, context);
  await expect(panel(page)).toContainText(context.settings.tier_ous["0"][0]);
  await expect(panel(page).getByRole("checkbox")).toHaveCount(0);
  const linking = await createRequest(
    page,
    context,
    linkInspection,
    "link_managed_gpo",
  );
  const linked = await approveAndCompleteFixture(page, context, linking);
  expect(linked.status).toBe("linked");
  expect(linked.gpo_guid).toBe(prepared.gpo_guid);
  expect(linked.state.gpo.computer_enabled).toBe(false);
  expect(linked.state.gpo.links).toHaveLength(1);
  expect(linked.state.gpo.links[0]).toMatchObject({
    enabled: false,
    enforced: false,
  });
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await panel(page)
    .getByRole("combobox", { name: "Action", exact: true })
    .selectOption("activate_managed_gpo");
  const activationInspection = await inspect(page, context);
  const create = panel(page).getByRole("button", {
    name: "Create approval request",
    exact: true,
  });
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .check();
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: recoveryCheck, exact: true })
    .check();
  await expect(create).toBeEnabled();
  await panel(page)
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .uncheck();
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .check();
  const activation = await createRequest(
    page,
    context,
    activationInspection,
    "activate_managed_gpo",
    true,
  );
  expect(
    new Set([
      linkInspection.id,
      linking.id,
      activationInspection.id,
      activation.id,
    ]).size,
  ).toBe(4);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.results[0]).toMatchObject({
    gpo_guid: prepared.gpo_guid,
    state: "linked",
    active_job_id: null,
  });
  await page.goto(
    `/en/logs/baselines?domain=${context.fixture.domain_name}&kind=gpo_import`,
  );
  const status = page.getByRole("combobox", { name: "Status", exact: true });
  for (const [value, label] of [
    ["inspected", "AD state inspected"],
    ["linked", "Linked, inactive"],
    ["activated", "Activated"],
    ["deactivated", "Deactivated"],
  ]) {
    await expect(status.locator(`option[value="${value}"]`)).toHaveText(label);
  }
  await status.selectOption("linked");
  await page
    .getByRole("button", { name: "Apply filters", exact: true })
    .click();
  const table = page.getByRole("table", { name: "Baseline logs", exact: true });
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText("Linked, inactive");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export CSV", exact: true }).click();
  const downloaded = await download;
  const output = await downloaded.path();
  expect(output).not.toBeNull();
  const csv = await readFile(output as string, "utf8");
  expect(csv.trimEnd().split(/\r?\n/)).toHaveLength(2);
  expect(csv).toContain(linking.id);
  expect(csv).toContain("link_managed_gpo");
  expect(csv).not.toContain(activation.id);
  await status.selectOption("inspected");
  await page
    .getByRole("button", { name: "Apply filters", exact: true })
    .click();
  await expect(table.locator("tbody tr")).toHaveCount(3);
  await expect(table).toContainText("AD state inspected");
});

test("an uncertain inspection response reconciles the same persisted request without duplicate submission", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  let requestId = "";
  let attempts = 0;
  await page.route(`**${context.endpoint}/gpo-preflights/`, async (route) => {
    attempts += 1;
    requestId = route.request().postDataJSON().idempotency_key;
    const saved = await route.fetch();
    expect(saved.status()).toBe(202);
    await route.abort("connectionreset");
  });
  await panel(page)
    .getByRole("button", { name: "Inspect AD state", exact: true })
    .click();
  await expect(panel(page).getByRole("alert")).toContainText(
    "request result is uncertain",
  );
  await expect(
    panel(page).getByLabel("Target alias", { exact: true }),
  ).toBeDisabled();
  nativeFixture("inspect", requestId);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(
    panel(page).getByRole("region", { name: "Verified AD state", exact: true }),
  ).toBeVisible();
  await expect(
    panel(page).getByLabel("Target alias", { exact: true }),
  ).toBeEnabled();
  const jobs = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(
    jobs.jobs.filter((job: GpoImportJob) => job.id === requestId),
  ).toHaveLength(1);
  expect(attempts).toBe(1);
});

test("malformed inspection data is rejected before any approval request can be created", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await inspect(page, context);
  await page.route(`**${context.endpoint}/managed-gpos/`, async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    const inspected = body.jobs.find(
      (job: GpoImportJob) => job.status === "inspected",
    );
    inspected.preflight_state.schema = true;
    await route.fulfill({ response, json: body });
  });
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(panel(page).getByRole("alert")).toContainText(
    "GPO state could not be loaded",
  );
  await expect(
    panel(page).getByRole("region", { name: "Verified AD state", exact: true }),
  ).toHaveCount(0);
  await expect(
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toHaveCount(0);
});

test("an uncertain write response recovers its existing approval request without creating another", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  const preflight = await inspect(page, context);
  let requestId = "";
  let writes = 0;
  await page.route(`**${context.endpoint}/managed-gpos/`, async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    writes += 1;
    requestId = route.request().postDataJSON().idempotency_key;
    const response = await route.fetch();
    expect(response.status()).toBe(202);
    await route.abort("connectionreset");
  });
  await panel(page)
    .getByRole("button", { name: "Create approval request", exact: true })
    .click();
  await expect(panel(page).getByRole("alert")).toContainText(
    "request result is uncertain",
  );
  await expect(
    panel(page).getByRole("combobox", { name: "Action", exact: true }),
  ).toBeDisabled();
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(
    panel(page).getByRole("link", {
      name: "Review request in Logs",
      exact: true,
    }),
  ).toHaveAttribute("href", `/en/logs/baselines?job=${requestId}`);
  await expect(
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toBeDisabled();
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.jobs).toHaveLength(2);
  expect(
    listing.jobs.find((job: GpoImportJob) => job.id === requestId),
  ).toMatchObject({
    operation: "import_managed_gpo",
    status: "awaiting_approval",
    approved_at: null,
  });
  expect(requestId).not.toBe(preflight.id);
  expect(writes).toBe(1);
});

test("an expired inspection cannot create a write request even when its reported prepare flag is true", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await inspect(page, context);
  await page.route(`**${context.endpoint}/managed-gpos/`, async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    const inspected = body.jobs.find(
      (job: GpoImportJob) => job.status === "inspected",
    );
    inspected.inspection_expires_at = "2000-01-01T00:00:00Z";
    inspected.can_prepare = true;
    await route.fulfill({ response, json: body });
  });
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(panel(page).getByRole("alert")).toContainText(
    "Inspection is no longer current",
  );
  await expect(
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toBeDisabled();
});

test("changing the requested version clears the inspected state and safety review", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await inspect(page, context);
  await panel(page).getByLabel("Version", { exact: true }).fill("1.0.1");
  await expect(
    panel(page).getByRole("region", { name: "Verified AD state", exact: true }),
  ).toHaveCount(0);
  await expect(
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toHaveCount(0);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.jobs).toHaveLength(1);
  expect(listing.jobs[0].operation).toBe("inspect_managed_gpo");
});

test("revoking the domain grant after inspection blocks creating a write request", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await inspect(page, context);
  const endpoint = `${context.endpoint}/gpo-authorization/`;
  const authorization = await (
    await page.request.get(endpoint, { headers: context.headers })
  ).json();
  const saved = await page.request.put(endpoint, {
    headers: context.headers,
    data: { expected_revision: authorization.revision, grants: [] },
  });
  expect(saved.status()).toBe(200);
  const rejected = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${context.endpoint}/managed-gpos/`) &&
      response.request().method() === "POST",
  );
  await panel(page)
    .getByRole("button", { name: "Create approval request", exact: true })
    .click();
  expect([400, 403, 409]).toContain((await rejected).status());
  await expect(panel(page).getByRole("alert")).toContainText(
    "request was rejected",
  );
  await expect(
    panel(page).getByRole("region", { name: "Verified AD state", exact: true }),
  ).toHaveCount(0);
  await expect(
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toHaveCount(0);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(
    listing.jobs.every(
      (job: GpoImportJob) => job.operation === "inspect_managed_gpo",
    ),
  ).toBe(true);
});

test("switching tenants discards the inspected domain and cannot reuse its request", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await inspect(page, context);
  const other = context.session.tenants.find(
    (item: { slug: string }) => item.slug === "service-accounts-e2e",
  );
  await page
    .getByRole("combobox", { name: "Active tenant", exact: true })
    .selectOption(other.id);
  await expect(
    page.getByRole("region", { name: "Verified AD state", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Create approval request", exact: true }),
  ).toHaveCount(0);
  expect(
    (
      await page.request.get(`${context.endpoint}/managed-gpos/`, {
        headers: { ...context.headers, "X-IPMS-Tenant-ID": other.id },
      })
    ).status(),
  ).toBe(404);
});
