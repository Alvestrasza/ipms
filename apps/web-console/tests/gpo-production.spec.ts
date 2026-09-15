/**
 * File Name: gpo-production.spec.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify one-click import/link preparation and separate activation through the isolated Portal and synthetic native observations.
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
    panel(page).getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toBeEnabled();
  await panel(page)
    .getByRole("combobox", { name: "Component", exact: true })
    .selectOption(context.component.id);
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

async function beginRequest(page: Page, context: Context) {
  const pending = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${context.endpoint}/gpo-preflights/`) &&
      response.request().method() === "POST",
  );
  await panel(page)
    .getByRole("button", { name: "Create approval request", exact: true })
    .click();
  const response = await pending;
  expect(response.status()).toBe(202);
  const job: GpoImportJob = await response.json();
  expect(job.operation).toBe("inspect_managed_gpo");
  expect(job.approval_mode).toBe("inspection");
  expect(job.approved_at).toBeNull();
  return { job, selection: response.request().postDataJSON() };
}

async function finishInspection(
  page: Page,
  context: Context,
  inspection: GpoImportJob,
  operation = "import_and_link_managed_gpo",
) {
  const pending = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${context.endpoint}/managed-gpos/`) &&
      response.request().method() === "POST",
  );
  const observed = nativeFixture("inspect", inspection.id);
  expect(observed.status).toBe("inspected");
  expect(observed.approved_at).toBeNull();
  expect(observed.claimed_at).toBeNull();
  // The normal polling cycle must continue by itself; there is no second click.
  const response = await pending;
  expect(response.status()).toBe(202);
  const body = response.request().postDataJSON();
  expect(body.preflight_id).toBe(inspection.id);
  expect(body.safety_review).toEqual({
    management_access: operation === "activate_managed_gpo",
    recovery_access: operation === "activate_managed_gpo",
  });
  const job: GpoImportJob = await response.json();
  expect(job.id).toBe(body.idempotency_key);
  expect(job.id).not.toBe(inspection.id);
  expect(job.operation).toBe(operation);
  expect(job.status).toBe("awaiting_approval");
  expect(job.approved_at).toBeNull();
  expect(job.approval_mode).toBe("portal");
  await expect(
    panel(page).getByRole("link", {
      name: "Review request in Logs",
      exact: true,
    }),
  ).toHaveAttribute("href", `/en/logs/baselines?job=${job.id}`);
  return job;
}

async function createAutomatically(
  page: Page,
  context: Context,
  operation = "import_and_link_managed_gpo",
) {
  const inspection = await beginRequest(page, context);
  const job = await finishInspection(page, context, inspection.job, operation);
  return { ...inspection, write: job };
}

const rootCheck =
  "I confirm the domain root as the target for this domain-wide account policy. This confirmation does not approve its execution.";
async function activationChecks(page: Page) {
  await panel(page)
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .check();
  await panel(page)
    .getByRole("checkbox", { name: recoveryCheck, exact: true })
    .check();
}

test("one create action prepares exactly one combined import/link request and never approves or activates it", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await expect(
    panel(page).getByRole("combobox", { name: "Action", exact: true }),
  ).toHaveValue("import_and_link_managed_gpo");
  await expect(panel(page)).not.toContainText(/pilot/i);
  await expect(
    panel(page).getByRole("button", { name: "Inspect AD state", exact: true }),
  ).toHaveCount(0);
  const mutations: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().includes("/security/"))
      mutations.push(request.url());
  });
  const created = await createAutomatically(page, context);
  expect(created.selection.operation).toBe("import_and_link_managed_gpo");
  expect(
    mutations.filter((url) => url.endsWith("/gpo-preflights/")),
  ).toHaveLength(1);
  expect(
    mutations.filter((url) => url.endsWith("/managed-gpos/")),
  ).toHaveLength(1);
  expect(mutations.some((url) => url.endsWith("/approve/"))).toBe(false);
  expect(created.write.display_name).toMatch(
    /^0-C-ALL-MS-WS2025-[A-Za-z0-9-]+_V1\.0\.0$/,
  );
  expect(created.write.display_name?.length).toBeLessThan(80);
  const linked = await approveAndCompleteFixture(page, context, created.write);
  expect(linked.status).toBe("linked");
  expect(linked.state.gpo.computer_enabled).toBe(false);
  expect(linked.state.gpo.user_enabled).toBe(false);
  expect(linked.state.gpo.links).toEqual([
    expect.objectContaining({
      kind: "ou",
      dn: context.settings.tier_ous["0"][0],
      enabled: false,
      enforced: false,
    }),
  ]);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.jobs).toHaveLength(2);
  expect(listing.results[0]).toMatchObject({
    state: "linked",
    staged_job_id: created.write.id,
    active_job_id: null,
  });
  await page.goto(
    `/en/logs/baselines?domain=${context.fixture.domain_name}&kind=gpo_import&status=linked`,
  );
  const table = page.getByRole("table", { name: "Baseline logs", exact: true });
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText("Linked, inactive");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export CSV", exact: true }).click();
  const output = await (await download).path();
  const csv = await readFile(output as string, "utf8");
  expect(csv.trimEnd().split(/\r?\n/)).toHaveLength(2);
  expect(csv).toContain("import_and_link_managed_gpo");
  expect(csv).toContain(created.write.id);
});

test("domain-root confirmation precedes combined creation and activation is a separate request with both safety checks", async ({
  page,
}) => {
  const context = await setup(page);
  const component = context.baseline.components.find(
    (item) => item.available && item.scope === "domain",
  );
  if (!component)
    throw new Error("A domain-wide fixture component is required.");
  context.component = component;
  await openWorkflow(page, context);
  const create = panel(page).getByRole("button", {
    name: "Create approval request",
    exact: true,
  });
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: rootCheck, exact: true })
    .check();
  const combined = await createAutomatically(page, context);
  expect(combined.selection.domain_root_confirmed).toBe(true);
  expect(combined.selection).not.toHaveProperty("target_ous");
  const linked = await approveAndCompleteFixture(page, context, combined.write);
  const rootDn = context.fixture.domain_name
    .split(".")
    .map((part) => `DC=${part}`)
    .join(",");
  expect(linked.state.gpo.links).toEqual([
    expect.objectContaining({
      kind: "domain",
      dn: rootDn,
      enabled: false,
      enforced: false,
    }),
  ]);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await panel(page)
    .getByRole("combobox", { name: "Action", exact: true })
    .selectOption("activate_managed_gpo");
  await expect(
    panel(page).getByRole("checkbox", { name: rootCheck, exact: true }),
  ).not.toBeChecked();
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: rootCheck, exact: true })
    .check();
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .check();
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: recoveryCheck, exact: true })
    .check();
  const activation = await createAutomatically(
    page,
    context,
    "activate_managed_gpo",
  );
  expect(activation.write.id).not.toBe(combined.write.id);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.results[0]).toMatchObject({
    state: "linked",
    active_job_id: null,
  });
  expect(activation.write.approved_at).toBeNull();
});

test("Agent 0.2.35 remains available for existing operations but cannot import and link", async ({
  page,
}) => {
  const context = await setup(page);
  const prepared = await seedPrepared(page, context);
  nativeFixture("agent-035", context.fixture.domain_id);
  await page.goto(
    "/en/security/baseline?baseline=microsoft-windows-server-2025",
  );
  await page
    .getByRole("combobox", { name: "Configured domain", exact: true })
    .selectOption(context.fixture.domain_id);
  const create = panel(page).getByRole("button", {
    name: "Create approval request",
    exact: true,
  });
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("combobox", { name: "Managed GPO", exact: true })
    .selectOption(prepared.managed_id);
  await panel(page)
    .getByRole("combobox", { name: "Action", exact: true })
    .selectOption("import_managed_gpo");
  await expect(create).toBeEnabled();
  const imported = await createAutomatically(
    page,
    context,
    "import_managed_gpo",
  );
  expect(imported.write.status).toBe("awaiting_approval");
});

test("preparing V2 keeps V1 visibly active until its separately approved activation", async ({
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
  await openWorkflow(page, context);
  const managed = panel(page).getByRole("combobox", {
    name: "Managed GPO",
    exact: true,
  });
  await managed.selectOption(prepared.managed_id);
  await expect(
    panel(page).getByRole("combobox", { name: "Action", exact: true }),
  ).toHaveValue("import_managed_gpo");
  await panel(page).getByLabel("Version", { exact: true }).fill("2.0.0");
  const imported = await createAutomatically(
    page,
    context,
    "import_managed_gpo",
  );
  const staged = await approveAndCompleteFixture(page, context, imported.write);
  expect(staged.state.gpo).toEqual(active.state.gpo);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  const desired = active.state.gpo.name.replace(/_V1\.0\.0$/, "_V2.0.0");
  const option = managed.locator(`option[value="${prepared.managed_id}"]`);
  await expect(option).toHaveText(
    `${active.state.gpo.name} · Active · Version prepared: ${desired}`,
  );
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
  await page.unroute(`**${context.endpoint}/managed-gpos/`, unverified);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await panel(page)
    .getByRole("combobox", { name: "Action", exact: true })
    .selectOption("activate_managed_gpo");
  await activationChecks(page);
  const activation = await createAutomatically(
    page,
    context,
    "activate_managed_gpo",
  );
  const activated = await approveAndCompleteFixture(
    page,
    context,
    activation.write,
  );
  expect(activated.state.gpo.name).toBe(desired);
  expect(activated.gpo_guid).toBe(active.gpo_guid);
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  await expect(option).toHaveText(`${desired} · Active`);
});

test("a lost inspection response resumes the same ID and creates only one combined write", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  let inspectionId = "";
  let inspections = 0;
  let writes = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith(`${context.endpoint}/managed-gpos/`)
    )
      writes += 1;
  });
  await page.route(`**${context.endpoint}/gpo-preflights/`, async (route) => {
    inspections += 1;
    inspectionId = route.request().postDataJSON().idempotency_key;
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
    panel(page).getByLabel("Target alias", { exact: true }),
  ).toBeDisabled();
  nativeFixture("inspect", inspectionId);
  const created = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().endsWith(`${context.endpoint}/managed-gpos/`),
  );
  await panel(page)
    .getByRole("button", { name: "Refresh", exact: true })
    .click();
  expect((await created).status()).toBe(202);
  expect(inspections).toBe(1);
  expect(writes).toBe(1);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.jobs).toHaveLength(2);
});

test("a lost write response only retries explicitly with the same request ID", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  let writes = 0;
  let writeId = "";
  const submittedIds: string[] = [];
  await page.route(`**${context.endpoint}/managed-gpos/`, async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    writes += 1;
    writeId = route.request().postDataJSON().idempotency_key;
    submittedIds.push(writeId);
    const response = await route.fetch();
    expect(response.status()).toBe(202);
    if (writes === 1) await route.abort("connectionreset");
    else await route.fulfill({ response });
  });
  const inspection = await beginRequest(page, context);
  nativeFixture("inspect", inspection.job.id);
  await expect(panel(page).getByRole("alert")).toContainText(
    "request result is uncertain",
    { timeout: 15000 },
  );
  await expect(
    panel(page).getByRole("combobox", { name: "Action", exact: true }),
  ).toBeDisabled();
  await expect(
    panel(page).getByRole("button", {
      name: "Retry the same request",
      exact: true,
    }),
  ).toBeEnabled();
  expect(writes).toBe(1);
  await panel(page)
    .getByRole("button", { name: "Retry the same request", exact: true })
    .click();
  await expect(
    panel(page).getByRole("link", {
      name: "Review request in Logs",
      exact: true,
    }),
  ).toHaveAttribute("href", `/en/logs/baselines?job=${writeId}`);
  expect(writes).toBe(2);
  expect(submittedIds).toEqual([writeId, writeId]);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.jobs).toHaveLength(2);
  expect(
    listing.jobs.find((job: GpoImportJob) => job.id === writeId),
  ).toMatchObject({ status: "awaiting_approval", approved_at: null });
});

for (const failure of ["malformed", "expired"] as const) {
  test(`${failure} inspection cannot automatically create a write`, async ({
    page,
  }) => {
    const context = await setup(page);
    await openWorkflow(page, context);
    const inspection = await beginRequest(page, context);
    let writes = 0;
    page.on("request", (request) => {
      if (
        request.method() === "POST" &&
        request.url().endsWith(`${context.endpoint}/managed-gpos/`)
      )
        writes += 1;
    });
    await page.route(`**${context.endpoint}/managed-gpos/`, async (route) => {
      const response = await route.fetch();
      const body = await response.json();
      const found = body.jobs.find(
        (job: GpoImportJob) => job.id === inspection.job.id,
      );
      if (found?.status === "inspected") {
        if (failure === "malformed") found.preflight_state.schema = true;
        else {
          found.inspection_expires_at = "2000-01-01T00:00:00Z";
          found.can_prepare = true;
        }
      }
      await route.fulfill({ response, json: body });
    });
    nativeFixture("inspect", inspection.job.id);
    await expect(panel(page).getByRole("alert")).toContainText(
      failure === "malformed"
        ? "GPO state could not be loaded"
        : "Inspection is no longer current",
      { timeout: 15000 },
    );
    expect(writes).toBe(0);
    expect(
      (
        await (
          await page.request.get(`${context.endpoint}/managed-gpos/`, {
            headers: context.headers,
          })
        ).json()
      ).jobs,
    ).toHaveLength(1);
  });
}

test("a failed inspection creates no write and an explicit retry uses the reserved managed identity", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  const inspection = await beginRequest(page, context);
  nativeFixture("fail", inspection.job.id);
  await expect(panel(page).getByRole("alert")).toContainText(
    "gpo_provider_failed",
    { timeout: 15000 },
  );
  const retry = await createAutomatically(page, context);
  expect(retry.selection.managed_id).toBe(inspection.job.managed_id);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.results).toHaveLength(1);
  expect(listing.jobs).toHaveLength(3);
  expect(
    listing.jobs.filter(
      (job: GpoImportJob) => job.operation === "import_and_link_managed_gpo",
    ),
  ).toHaveLength(1);
});

test("authorization withdrawal between inspection and automatic write blocks the request", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await page.route(`**${context.endpoint}/managed-gpos/`, async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const endpoint = `${context.endpoint}/gpo-authorization/`;
    const grant = await (
      await page.request.get(endpoint, { headers: context.headers })
    ).json();
    expect(
      (
        await page.request.put(endpoint, {
          headers: context.headers,
          data: { expected_revision: grant.revision, grants: [] },
        })
      ).status(),
    ).toBe(200);
    await route.continue();
  });
  const inspection = await beginRequest(page, context);
  nativeFixture("inspect", inspection.job.id);
  await expect(panel(page).getByRole("alert")).toContainText(
    "request was rejected",
    { timeout: 15000 },
  );
  await expect(
    panel(page).getByRole("region", { name: "Verified AD state", exact: true }),
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

test("switching tenants during inspection aborts continuation and cannot create a cross-tenant write", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  const inspection = await beginRequest(page, context);
  const other = context.session.tenants.find(
    (item: { slug: string }) => item.slug === "service-accounts-e2e",
  );
  await page
    .getByRole("combobox", { name: "Active tenant", exact: true })
    .selectOption(other.id);
  await expect(panel(page)).toHaveCount(0);
  nativeFixture("inspect", inspection.job.id);
  // Observe beyond the former polling interval to catch an orphaned continuation.
  await page.waitForTimeout(4500);
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.jobs).toHaveLength(1);
  expect(
    (
      await page.request.get(`${context.endpoint}/managed-gpos/`, {
        headers: { ...context.headers, "X-IPMS-Tenant-ID": other.id },
      })
    ).status(),
  ).toBe(404);
});
