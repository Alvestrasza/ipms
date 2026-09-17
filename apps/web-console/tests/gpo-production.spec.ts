/**
 * File Name: gpo-production.spec.ts
 * Version: v0.2.0 | Created: 2026-09-15 | Modified: 2026-09-17
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify one-click import/link preparation and separate activation through the isolated Portal and synthetic native observations.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  expect,
  type Page,
  type Response,
  type Route,
  test,
} from "@playwright/test";
import type {
  DomainSecurityCatalog,
  GpoImportJob,
} from "../src/lib/domain-security-types";
import type { OverrideCatalog } from "../src/lib/security-override-types";

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

async function setup(page: Page, fourEyes = false) {
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
  const approvalPolicyUrl = "/api/v1/security/gpo-approval-policy/";
  const approvalPolicy = await (
    await page.request.get(approvalPolicyUrl, { headers })
  ).json();
  if (approvalPolicy.four_eyes_required !== fourEyes) {
    const updated = await page.request.put(approvalPolicyUrl, {
      headers,
      data: {
        expected_revision: approvalPolicy.revision,
        four_eyes_required: fourEyes,
      },
    });
    expect(updated.status()).toBe(200);
  }
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

function isApiResponse(response: Response, path: string) {
  return (
    new URL(response.url()).pathname.replace(/\/$/, "") ===
      path.replace(/\/$/, "") && ![307, 308].includes(response.status())
  );
}

async function openWorkflow(page: Page, context: Context) {
  await page.goto(
    "/en/security/windows-gpos?baseline=microsoft-windows-server-2025",
  );
  await page
    .getByRole("combobox", { name: "Domain", exact: true })
    .selectOption(context.fixture.domain_id);
  await expect(
    panel(page).getByRole("button", {
      name: "Submit action",
      exact: true,
    }),
  ).toBeEnabled();
  await panel(page)
    .getByRole("combobox", { name: "Component", exact: true })
    .selectOption(context.component.id);
}

async function approveAndCompleteFixture(
  _page: Page,
  _context: Context,
  job: GpoImportJob,
) {
  expect(job.approved_at).toBeTruthy();
  expect(job.approved_by).toBeTruthy();
  return nativeFixture("complete", job.id);
}

async function seedPrepared(page: Page, context: Context) {
  const selection = {
    revision: context.settings.revision,
    system_id: context.fixture.system_id,
    baseline_id: context.baseline.id,
    backup_id: context.component.id,
    tier: "0",
    target_ous: context.settings.tier_ous["0"],
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
        target_ous: context.settings.tier_ous["0"],
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
      isApiResponse(response, `${context.endpoint}/gpo-preflights/`) &&
      response.request().method() === "POST",
  );
  await panel(page)
    .getByRole("button", { name: "Submit action", exact: true })
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
      isApiResponse(response, `${context.endpoint}/managed-gpos/`) &&
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
  expect(job.status).toBe("queued");
  expect(job.approved_at).toBeTruthy();
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
  "I confirm the domain root as the only target for this GPO action. This confirmation does not approve its execution.";
async function activationChecks(page: Page) {
  await panel(page)
    .getByRole("checkbox", { name: managementCheck, exact: true })
    .check();
  await panel(page)
    .getByRole("checkbox", { name: recoveryCheck, exact: true })
    .check();
}

test("one submit action approves exactly one combined import/link request without a second approval or activation", async ({
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
  await expect(panel(page)).toContainText(
    "No additional approval in Logs is needed",
  );
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

test("central Windows GPO deployment submits only the selected configured OUs", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  await panel(page)
    .getByRole("combobox", { name: "Tier", exact: true })
    .selectOption("1");
  const targets = context.settings.tier_ous["1"];
  expect(targets).toHaveLength(2);
  await expect(
    panel(page).getByRole("checkbox", { name: targets[0], exact: true }),
  ).toBeChecked();
  await panel(page)
    .getByRole("checkbox", { name: targets[0], exact: true })
    .uncheck();
  const created = await createAutomatically(page, context);
  expect(created.selection.target_ous).toEqual([targets[1]]);
});

test("a configured domain root is an exclusive Tier 0 target for ordinary GPOs", async ({
  page,
}) => {
  const context = await setup(page);
  nativeFixture("agent-046", context.fixture.domain_id);
  const root = context.fixture.domain_name
    .split(".")
    .map((part) => `DC=${part}`)
    .join(",");
  const saved = await page.request.put(
    `${domainsApi}${context.fixture.domain_id}/`,
    {
      headers: context.headers,
      data: {
        expected_revision: context.settings.revision,
        domain_name: context.settings.domain_name,
        tier_ous: {
          ...context.settings.tier_ous,
          "0": [root, ...context.settings.tier_ous["0"]],
        },
        gpo_name_template: context.settings.gpo_name_template,
        baseline_order: context.settings.baseline_order,
      },
    },
  );
  expect(saved.status()).toBe(200);
  context.settings = await saved.json();
  await openWorkflow(page, context);
  const rootTarget = panel(page).getByRole("checkbox", {
    name: root,
    exact: true,
  });
  const ouTarget = panel(page).getByRole("checkbox", {
    name: context.settings.tier_ous["0"][1],
    exact: true,
  });
  await expect(ouTarget).toBeChecked();
  await expect(rootTarget).not.toBeChecked();
  await rootTarget.check();
  await expect(rootTarget).toBeChecked();
  await expect(ouTarget).not.toBeChecked();
  await expect(
    panel(page).getByRole("button", { name: "Submit action", exact: true }),
  ).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: rootCheck, exact: true })
    .check();
  const created = await createAutomatically(page, context);
  expect(created.selection).toMatchObject({
    tier: "0",
    target_ous: [root],
    domain_root_confirmed: true,
  });
  const linked = nativeFixture("complete", created.write.id);
  expect(linked.status).toBe("linked");
  expect(linked.state.gpo.links).toEqual([
    expect.objectContaining({ kind: "domain", dn: root, enabled: false }),
  ]);
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
    name: "Submit action",
    exact: true,
  });
  await expect(create).toBeDisabled();
  await panel(page)
    .getByRole("checkbox", { name: rootCheck, exact: true })
    .check();
  const combined = await createAutomatically(page, context);
  expect(combined.selection.domain_root_confirmed).toBe(true);
  const rootDn = context.fixture.domain_name
    .split(".")
    .map((part) => `DC=${part}`)
    .join(",");
  expect(combined.selection.target_ous).toEqual([rootDn]);
  const linked = await approveAndCompleteFixture(page, context, combined.write);
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
  expect(activation.write.approved_at).toBeTruthy();
});

test("Agent 0.2.35 remains available for existing operations but cannot import and link", async ({
  page,
}) => {
  const context = await setup(page);
  const prepared = await seedPrepared(page, context);
  nativeFixture("agent-035", context.fixture.domain_id);
  await page.goto(
    "/en/security/windows-gpos?baseline=microsoft-windows-server-2025",
  );
  await page
    .getByRole("combobox", { name: "Domain", exact: true })
    .selectOption(context.fixture.domain_id);
  const create = panel(page).getByRole("button", {
    name: "Submit action",
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
  expect(imported.write.status).toBe("queued");
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
    .getByRole("button", { name: "Submit action", exact: true })
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
      isApiResponse(response, `${context.endpoint}/managed-gpos/`),
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
  ).toMatchObject({ status: "queued" });
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
    "check AD connectivity, GPMC and the Agent service account",
    { timeout: 15000 },
  );
  await expect(
    panel(page).getByRole("link", {
      name: "Review request in Logs",
      exact: true,
    }),
  ).toHaveAttribute("href", `/en/logs/baselines?job=${inspection.job.id}`);
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
    "request was not authorized",
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

test("an unresolved write explains the domain lock and links its exact existing request", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  const { write } = await createAutomatically(page, context);
  expect(write.approved_at).toBeTruthy();
  expect(nativeFixture("reconcile", write.id).status).toBe(
    "reconciliation_required",
  );
  let listingReads = 0;
  await page.route(`**${context.endpoint}/managed-gpos/`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    listingReads += 1;
    const response = await route.fetch();
    const body = await response.json();
    if (listingReads === 1)
      body.jobs.find((job: GpoImportJob) => job.id === write.id).status =
        "queued";
    await route.fulfill({ response, json: body });
  });
  await openWorkflow(page, context);
  await panel(page)
    .getByRole("button", { name: "Submit action", exact: true })
    .click();
  await expect(panel(page).getByRole("alert")).toContainText(
    "changes may already have occurred",
  );
  const link = panel(page).getByRole("link", {
    name: "Review request in Logs",
    exact: true,
  });
  await expect(link).toHaveAttribute(
    "href",
    `/en/logs/baselines?job=${write.id}`,
  );
  expect(listingReads).toBe(2);
  await link.click();
  await expect(page).toHaveURL(
    new RegExp(`/en/logs/baselines\\?job=${write.id}$`),
  );
  await expect(
    page.getByRole("heading", {
      name: write.display_name ?? write.pilot_display_name,
      exact: true,
    }),
  ).toBeVisible();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "compare the actual GPO content and links with the approved request",
  );
  const listing = await (
    await page.request.get(`${context.endpoint}/managed-gpos/`, {
      headers: context.headers,
    })
  ).json();
  expect(listing.jobs).toHaveLength(2);
  expect(
    listing.jobs.find((job: GpoImportJob) => job.id === write.id).status,
  ).toBe("reconciliation_required");
});

test("API rejection codes explain causes and next steps without exposing backend details", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  let status = 409;
  let code = "security_gpo_domain_busy";
  let contextualReads = 0;
  page.on("request", (request) => {
    if (
      request.method() === "GET" &&
      request.url().endsWith(`${context.endpoint}/managed-gpos/`)
    )
      contextualReads += 1;
  });
  await page.route(`**${context.endpoint}/gpo-preflights/`, (route) =>
    route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code,
          message: "PRIVATE_BACKEND_DETAILS <script>private()</script>",
          correlation_id: "PRIVATE_CORRELATION",
        },
      }),
    }),
  );
  for (const [nextStatus, nextCode, expected] of [
    [409, "security_gpo_domain_busy", "Another GPO request is pending"],
    [
      409,
      "security_gpo_executor_unavailable",
      "import and link requires 0.2.36",
    ],
    [
      409,
      "security_gpo_artifact_unavailable",
      "integrity of this baseline package on the Appliance",
    ],
    [
      409,
      "security_gpo_job_limit",
      "tenant has reached its total GPO request limit",
    ],
    [409, "security_domain_revision_changed", "domain configuration changed"],
    [409, "security_gpo_name_collision", "configured naming scheme"],
    [409, "security_gpo_preflight_required", "new read-only inspection"],
    [403, "security_gpo_domain_busy", "An expired session or CSRF check"],
    [401, "authentication_failed", "Sign in again"],
    [429, "rate_limited", "Wait briefly"],
    [409, "__proto__", "could not accept this request"],
  ] as const) {
    status = nextStatus;
    code = nextCode;
    const beforeReads = contextualReads;
    await panel(page)
      .getByRole("button", { name: "Submit action", exact: true })
      .click();
    await expect(panel(page).getByRole("alert")).toContainText(expected);
    await expect(panel(page)).not.toContainText("PRIVATE_");
    await expect(panel(page)).not.toContainText("private()");
    expect(contextualReads - beforeReads).toBe(
      status === 409 && code === "security_gpo_domain_busy" ? 1 : 0,
    );
  }
  await page.goto(
    "/de/security/windows-gpos?baseline=microsoft-windows-server-2025",
  );
  await page
    .getByRole("combobox", { name: "Domäne", exact: true })
    .selectOption(context.fixture.domain_id);
  const german = page.getByRole("region", {
    name: "GPO-Verteilung",
    exact: true,
  });
  status = 409;
  code = "security_gpo_domain_busy";
  await german
    .getByRole("button", { name: "Aktion beauftragen", exact: true })
    .click();
  await expect(german.getByRole("alert")).toContainText(
    "Öffne die Baseline-Logs",
  );
  await expect(german).not.toContainText("PRIVATE_");
});

test("a 5xx response retains the request ID and ignores misleading backend error details", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  const keys: string[] = [];
  let contextualReads = 0;
  page.on("request", (request) => {
    if (
      request.method() === "GET" &&
      request.url().endsWith(`${context.endpoint}/managed-gpos/`)
    )
      contextualReads += 1;
  });
  await page.route(`**${context.endpoint}/gpo-preflights/`, (route) => {
    keys.push(route.request().postDataJSON().idempotency_key);
    return route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        error: {
          code: "security_gpo_domain_busy",
          message: "PRIVATE_BACKEND_DETAILS",
        },
      }),
    });
  });
  await panel(page)
    .getByRole("button", { name: "Submit action", exact: true })
    .click();
  await expect(panel(page).getByRole("alert")).toContainText(
    "request result is uncertain",
  );
  await expect(panel(page)).not.toContainText("already occupied");
  await expect(panel(page)).not.toContainText("PRIVATE_");
  await panel(page)
    .getByRole("button", { name: "Retry the same request", exact: true })
    .click();
  await expect(
    panel(page).getByRole("button", {
      name: "Retry the same request",
      exact: true,
    }),
  ).toBeEnabled();
  expect(keys).toHaveLength(2);
  expect(keys[0]).toBe(keys[1]);
  expect(contextualReads).toBe(0);
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

async function failedWriteForReconciliation(page: Page) {
  const context = await setup(page);
  await openWorkflow(page, context);
  const { write } = await createAutomatically(page, context);
  expect(write.approved_at).toBeTruthy();
  expect(nativeFixture("reconcile", write.id).status).toBe(
    "reconciliation_required",
  );
  await page.goto(`/en/logs/baselines?job=${write.id}`);
  const region = page.getByRole("region", {
    name: "Directory reconciliation",
    exact: true,
  });
  await expect(
    region.getByRole("button", { name: "Reconcile directory", exact: true }),
  ).toBeEnabled();
  return {
    ...context,
    write,
    region,
    reconciliationUrl: `/api/v1/security/gpo-imports/${write.id}/reconciliations/`,
  };
}
async function requestObservation(
  page: Page,
  context: Awaited<ReturnType<typeof failedWriteForReconciliation>>,
) {
  const response = page.waitForResponse(
    (r) =>
      isApiResponse(r, context.reconciliationUrl) &&
      r.request().method() === "POST",
  );
  await context.region
    .getByRole("button", { name: "Reconcile directory", exact: true })
    .click();
  const result = await response;
  expect(result.status()).toBe(202);
  const body = await result.json();
  expect(body.latest.id).toBe(result.request().postDataJSON().idempotency_key);
  expect(body.latest.status).toBe("requested");
  return body.latest;
}
test("directory reconciliation waits for observation, explicit acceptance and Agent acknowledgement without claiming import success", async ({
  page,
}) => {
  const context = await failedWriteForReconciliation(page);
  const mutations: string[] = [];
  page.on("request", (r) => {
    if (r.method() === "POST") mutations.push(r.url());
  });
  const request = await requestObservation(page, context);
  expect(nativeFixture("observe-reconciliation", context.write.id).status).toBe(
    "observed",
  );
  const accept = context.region.getByRole("button", {
    name: "Accept reconciliation",
    exact: true,
  });
  await expect(accept).toBeEnabled({ timeout: 15000 });
  await expect(context.region).toContainText("Approved target link missing");
  await expect(context.region).toContainText(
    "Baseline content import is not confirmed",
  );
  expect(mutations).toHaveLength(1);
  const acceptedResponse = page.waitForResponse((r) =>
    isApiResponse(r, `${context.reconciliationUrl}${request.id}/accept/`),
  );
  await accept.click();
  const accepted = await acceptedResponse;
  expect(accepted.status()).toBe(202);
  expect((await accepted.json()).latest.status).toBe("accept_requested");
  await expect(context.region).toContainText(
    "Awaiting Agent verification and acknowledgement",
  );
  const detail = await (
    await page.request.get(`/api/v1/logs/gpo-imports/${context.write.id}/`, {
      headers: context.headers,
    })
  ).json();
  expect(detail.status).toBe("reconciliation_required");
  const ack = nativeFixture("ack-reconciliation", context.write.id);
  expect(ack).toMatchObject({
    status: "accepted",
    job_status: "reconciled",
    error_code: "gpo_provider_failed",
    staged_job_id: null,
    active_job_id: null,
  });
  await expect(context.region).toContainText("Reconciliation accepted", {
    timeout: 15000,
  });
  await expect(page.getByRole("main")).toContainText(
    "Directory reconciled; import not confirmed",
  );
  expect(mutations).toHaveLength(2);
  await page.goto(
    `/en/logs/baselines?domain=${context.fixture.domain_name}&kind=gpo_import&status=reconciled`,
  );
  const table = page.getByRole("table", { name: "Baseline logs", exact: true });
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table).toContainText(
    "Directory reconciled; import not confirmed",
  );
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export CSV", exact: true }).click();
  const csv = await readFile((await (await download).path()) as string, "utf8");
  expect(csv).toContain("reconciled");
  expect(csv).toContain("gpo_provider_failed");
});

test("incomplete or malformed directory observations cannot be accepted or displayed as an absence of links", async ({
  page,
}) => {
  const context = await failedWriteForReconciliation(page);
  await requestObservation(page, context);
  nativeFixture("observe-unverifiable", context.write.id);
  const accept = context.region.getByRole("button", {
    name: "Accept reconciliation",
    exact: true,
  });
  await expect(accept).toBeDisabled({ timeout: 15000 });
  await expect(context.region).toContainText("Not fully determinable");
  await expect(context.region).not.toContainText(
    "Approved target link missing",
  );
  await expect(context.region).toContainText(
    "could not inspect all forest links",
  );
  await page.route(`**${context.reconciliationUrl}`, async (route) => {
    const response = await route.fetch();
    const payload = await response.json();
    payload.latest.observation.forest_complete = "true";
    payload.latest.can_accept = true;
    await route.fulfill({ response, json: payload });
  });
  await context.region
    .getByRole("button", { name: "Refresh reconciliation", exact: true })
    .click();
  await expect(context.region.getByRole("alert")).toContainText(
    "response is invalid",
  );
  await expect(accept).toHaveCount(0);
});

test("lost reconciliation responses retry the same request ID and exact observation digest", async ({
  page,
}) => {
  const context = await failedWriteForReconciliation(page);
  const keys: string[] = [];
  const digests: string[] = [];
  await page.route(`**${context.reconciliationUrl}**`, async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const body = route.request().postDataJSON();
    const values = route.request().url().endsWith("/accept/") ? digests : keys;
    values.push(body.observation_digest ?? body.idempotency_key);
    const response = await route.fetch();
    expect(response.status()).toBe(202);
    if (values.length === 1) await route.abort("connectionreset");
    else await route.fulfill({ response });
  });
  await context.region
    .getByRole("button", { name: "Reconcile directory", exact: true })
    .click();
  const retry = context.region.getByRole("button", {
    name: "Retry the same request",
    exact: true,
  });
  await expect(context.region.getByRole("alert")).toContainText(
    "request result is uncertain",
  );
  await retry.click();
  await expect(context.region.getByRole("status")).toContainText(
    "Agent observation requested",
  );
  expect(keys).toEqual([keys[0], keys[0]]);
  nativeFixture("observe-reconciliation", context.write.id);
  const accept = context.region.getByRole("button", {
    name: "Accept reconciliation",
    exact: true,
  });
  await expect(accept).toBeEnabled({ timeout: 15000 });
  await accept.click();
  await expect(context.region.getByRole("alert")).toContainText(
    "request result is uncertain",
  );
  await retry.click();
  await expect(context.region).toContainText(
    "Awaiting Agent verification and acknowledgement",
  );
  expect(digests).toEqual([digests[0], digests[0]]);
  const result = await (
    await page.request.get(context.reconciliationUrl, {
      headers: context.headers,
    })
  ).json();
  expect(result.latest.id).toBe(keys[0]);
  expect(result.latest.status).toBe("accept_requested");
});

test("reconciliation prerequisite and acceptance errors remain actionable and localized", async ({
  page,
}) => {
  const context = await failedWriteForReconciliation(page);
  nativeFixture("agent-035", context.fixture.domain_id);
  await context.region
    .getByRole("button", { name: "Refresh reconciliation", exact: true })
    .click();
  await expect(context.region).toContainText("version 0.2.37 or newer");
  await expect(
    context.region.getByRole("button", {
      name: "Reconcile directory",
      exact: true,
    }),
  ).toBeDisabled();
  nativeFixture("agent-037", context.fixture.domain_id);
  await context.region
    .getByRole("button", { name: "Refresh reconciliation", exact: true })
    .click();
  const request = await requestObservation(page, context);
  nativeFixture("observe-reconciliation", context.write.id);
  const accept = context.region.getByRole("button", {
    name: "Accept reconciliation",
    exact: true,
  });
  await expect(accept).toBeEnabled({ timeout: 15000 });
  await page.route(
    `**${context.reconciliationUrl}${request.id}/accept/`,
    (route) =>
      route.fulfill({
        status: 403,
        contentType: "application/json",
        body: JSON.stringify({
          error: {
            code: "security_gpo_reconciliation_four_eyes_required",
            message: "PRIVATE_BACKEND_DETAILS",
          },
        }),
      }),
  );
  await accept.click();
  await expect(context.region.getByRole("alert")).toContainText(
    "different administrator authorized for this domain and tier",
  );
  await expect(context.region).not.toContainText("PRIVATE_");
  const record = await (
    await page.request.get(context.reconciliationUrl, {
      headers: context.headers,
    })
  ).json();
  expect(record.latest.status).toBe("observed");
  await page.goto(`/de/logs/baselines?job=${context.write.id}`);
  const german = page.getByRole("region", {
    name: "Verzeichnisabgleich",
    exact: true,
  });
  await expect(
    german.getByRole("button", { name: "Abgleich übernehmen", exact: true }),
  ).toBeEnabled();
  await expect(german).toContainText(
    "Import des Baseline-Inhalts ist nicht bestätigt",
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await expect
    .poll(() =>
      page.evaluate(() => ({
        width: document.documentElement.scrollWidth,
        viewport: window.innerWidth,
        overflowing: [...document.querySelectorAll("body *")]
          .filter(
            (element) =>
              !element.closest(".table-scroll") &&
              element.getBoundingClientRect().right > window.innerWidth + 1,
          )
          .slice(0, 8)
          .map((element) => ({
            tag: element.tagName,
            class: element.className,
            right: element.getBoundingClientRect().right,
            text: element.textContent?.slice(0, 100),
          })),
      })),
    )
    .toEqual({ width: 390, viewport: 390, overflowing: [] });
});

test("an Agent-observed change after acceptance keeps the original domain fence", async ({
  page,
}) => {
  const context = await failedWriteForReconciliation(page);
  await requestObservation(page, context);
  nativeFixture("observe-reconciliation", context.write.id);
  const accept = context.region.getByRole("button", {
    name: "Accept reconciliation",
    exact: true,
  });
  await expect(accept).toBeEnabled({ timeout: 15000 });
  await accept.click();
  await expect(context.region).toContainText(
    "Awaiting Agent verification and acknowledgement",
  );
  expect(nativeFixture("drift-reconciliation", context.write.id).status).toBe(
    "stale",
  );
  await expect(context.region).toContainText("Observation no longer current", {
    timeout: 15000,
  });
  const detail = await (
    await page.request.get(`/api/v1/logs/gpo-imports/${context.write.id}/`, {
      headers: context.headers,
    })
  ).json();
  expect(detail.status).toBe("reconciliation_required");
  expect(detail.error_code).toBe("gpo_provider_failed");
});

test("switching tenant during reconciliation polling cannot continue the previous tenant action", async ({
  page,
}) => {
  const context = await failedWriteForReconciliation(page);
  await requestObservation(page, context);
  let requestsAfterSwitch = 0;
  const other = context.session.tenants.find(
    (tenant: { slug: string }) => tenant.slug === "service-accounts-e2e",
  );
  await page
    .getByRole("combobox", { name: "Active tenant", exact: true })
    .selectOption(other.id);
  await expect(context.region).toHaveCount(0);
  page.on("request", (request) => {
    if (request.url().includes(context.reconciliationUrl))
      requestsAfterSwitch += 1;
  });
  nativeFixture("observe-reconciliation", context.write.id);
  await page.waitForTimeout(4500);
  expect(requestsAfterSwitch).toBe(0);
  const status = await page.request.get(context.reconciliationUrl, {
    headers: { ...context.headers, "X-IPMS-Tenant-ID": other.id },
  });
  expect(status.status()).toBe(404);
});

test("four-eyes policy keeps submission pending for another administrator", async ({
  page,
}) => {
  const context = await setup(page, true);
  await openWorkflow(page, context);
  const inspection = await beginRequest(page, context);
  const pending = page.waitForResponse(
    (response) =>
      isApiResponse(response, `${context.endpoint}/managed-gpos/`) &&
      response.request().method() === "POST",
  );
  nativeFixture("inspect", inspection.job.id);
  const response = await pending;
  expect(response.status()).toBe(202);
  const job = await response.json();
  expect(job.status).toBe("awaiting_approval");
  expect(job.approved_at).toBeNull();
  expect(job.can_approve).toBe(false);
  await expect(panel(page)).toContainText(
    "Review and approve this exact action in Logs",
  );
  await expect(panel(page)).not.toContainText(
    "No additional approval in Logs is needed",
  );
});

test("failed inspection log detail shows the recorded cause instead of an access error", async ({
  page,
}) => {
  const context = await setup(page);
  await openWorkflow(page, context);
  const inspection = await beginRequest(page, context);
  nativeFixture("fail", inspection.job.id);
  await page.goto(`/en/logs/baselines?job=${inspection.job.id}`);
  await expect(
    page.getByText("Read-only inspection; no change approval is required.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Legacy local approval", exact: true }),
  ).toHaveCount(0);

  await expect(
    page.getByRole("heading", { name: "GPO request details", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("gpo_provider_failed", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByText(
      "This GPO request is unavailable for the selected tenant or your account.",
      { exact: true },
    ),
  ).toHaveCount(0);
  await expect(
    page.getByText(
      "The Agent could not complete the AD inspection or GPO operation.",
      { exact: false },
    ),
  ).toBeVisible();
});

test("override editor persists only deviations, restores baseline and deploys a separate scoped GPO", async ({
  page,
}) => {
  const context = await setup(page);
  const originalPolicy = await seedPrepared(page, context);
  nativeFixture("agent-043", context.fixture.domain_id);
  const catalogResponse = await page.request.get(
    `/api/v1/security/override-catalog/?${new URLSearchParams({ baseline_id: context.baseline.id, backup_id: context.component.id })}`,
    { headers: context.headers },
  );
  expect(catalogResponse.status()).toBe(200);
  const catalog: OverrideCatalog = await catalogResponse.json();
  const setting = catalog.settings.find(
    (s) =>
      s.editable &&
      s.value_type === "integer" &&
      !s.enum_options.length &&
      typeof s.baseline_value === "number" &&
      s.max > s.min,
  );
  if (!setting || typeof setting.baseline_value !== "number")
    throw new Error("An editable original integer setting is required.");
  const changed =
    setting.baseline_value === setting.min ? setting.min + 1 : setting.min;
  const name = `MS-WS2025-Defender-${randomUUID().slice(0, 8)}`;
  await page.goto("/en/security/override");
  await expect(
    page.getByRole("link", { name: "Overrides", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await page
    .getByRole("combobox", { name: "Override", exact: true })
    .selectOption("");
  const editor = page.getByRole("region", {
    name: "Baseline overrides",
    exact: true,
  });
  await editor
    .getByRole("combobox", { name: "Baseline", exact: true })
    .selectOption(context.baseline.id);
  await editor
    .getByRole("combobox", { name: "Component", exact: true })
    .selectOption(context.component.id);
  await editor.getByLabel("GPO purpose token", { exact: true }).fill(name);
  await editor
    .getByLabel("Search settings", { exact: true })
    .fill(setting.label);
  const row = editor
    .getByRole("row")
    .filter({ has: page.getByText(setting.label, { exact: true }) })
    .filter({ hasText: setting.category })
    .first();
  await row
    .getByRole("button", { name: "Override this setting", exact: true })
    .click();
  await row.getByRole("spinbutton").fill(String(changed));
  await expect(
    editor.getByRole("button", { name: "Save override", exact: true }),
  ).toBeDisabled();
  await row.getByRole("button", { name: "Use override", exact: true }).click();
  await expect(row).toContainText(JSON.stringify(changed));
  const saved = page.waitForResponse(
    (r) =>
      isApiResponse(r, "/api/v1/security/overrides/") &&
      r.request().method() === "POST",
  );
  await editor
    .getByRole("button", { name: "Save override", exact: true })
    .click();
  const response = await saved;
  expect(response.status()).toBe(201);
  const override = await response.json();
  expect(response.request().postDataJSON().entries).toEqual([
    { setting_id: setting.setting_id, value: changed },
  ]);
  expect(override.entries).toEqual([
    { setting_id: setting.setting_id, value: changed },
  ]);
  await expect(
    page.getByText("Override saved. Saving does not change AD.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    editor.getByRole("combobox", { name: "Baseline", exact: true }),
  ).toBeDisabled();
  await page.goto("/en/security/windows-gpos?source=override");
  await page
    .getByRole("combobox", { name: "Domain", exact: true })
    .selectOption(context.fixture.domain_id);
  await page
    .getByRole("combobox", { name: "Saved override", exact: true })
    .selectOption(override.id);
  const deployment = panel(page);
  await expect(
    deployment
      .getByRole("combobox", { name: "Managed GPO", exact: true })
      .locator(`option[value="${originalPolicy.managed_id}"]`),
  ).toHaveCount(0);
  const inspectionResponse = page.waitForResponse(
    (r) =>
      isApiResponse(r, `${context.endpoint}/gpo-preflights/`) &&
      r.request().method() === "POST",
  );
  await deployment
    .getByRole("button", { name: "Submit action", exact: true })
    .click();
  const inspection = await inspectionResponse;
  expect(inspection.status()).toBe(202);
  expect(inspection.request().postDataJSON()).toMatchObject({
    override_id: override.id,
    override_revision: override.revision,
    override_sha256: override.sha256,
  });
  const job = await inspection.json();
  expect(job.override_id).toBe(override.id);
  const writeResponse = page.waitForResponse(
    (r) =>
      isApiResponse(r, `${context.endpoint}/managed-gpos/`) &&
      r.request().method() === "POST",
  );
  expect(nativeFixture("inspect", job.id).status).toBe("inspected");
  const write = await writeResponse;
  expect(write.status()).toBe(202);
  const writeJob = await write.json();
  expect(writeJob.override_id).toBe(override.id);
  expect(writeJob.status).toBe("queued");
  expect(writeJob.display_name).toBe(`0-C-OVRD-${name}_V1.0.0`);
  expect(nativeFixture("complete", writeJob.id).status).toBe("linked");
  // Reopening then removing the value removes it from the sparse override GPO.
  await page.goto(`/en/logs/baselines?job=${writeJob.id}`);
  const review = page.getByRole("region", {
    name: "Baseline overrides",
    exact: true,
  });
  await expect(
    review.getByRole("row").filter({ hasText: setting.label }),
  ).toBeVisible();
  await expect(review).toContainText(JSON.stringify(changed));
  await page.goto("/en/security/override");
  await page
    .getByRole("combobox", { name: "Override", exact: true })
    .selectOption(override.id);
  await editor
    .getByLabel("Search settings", { exact: true })
    .fill(setting.label);
  await editor
    .getByRole("button", { name: "Remove override", exact: true })
    .click();
  const patched = page.waitForResponse(
    (r) =>
      isApiResponse(r, `/api/v1/security/overrides/${override.id}/`) &&
      r.request().method() === "PATCH",
  );
  await editor
    .getByRole("button", { name: "Save override", exact: true })
    .click();
  const patch = await patched;
  expect(patch.status()).toBe(200);
  expect(patch.request().postDataJSON().entries).toEqual([]);
  const currentOverride = await patch.json();
  expect(currentOverride.entries).toEqual([]);

  nativeFixture("agent-045", context.fixture.domain_id);
  await page.goto("/en/security/windows-gpos?source=override");
  await page
    .getByRole("combobox", { name: "Domain", exact: true })
    .selectOption(context.fixture.domain_id);
  await page
    .getByRole("combobox", { name: "Saved override", exact: true })
    .selectOption(override.id);
  const deletionPanel = panel(page);
  await deletionPanel
    .getByRole("combobox", { name: "Managed GPO", exact: true })
    .selectOption(writeJob.managed_id);
  await deletionPanel
    .getByRole("combobox", { name: "Action", exact: true })
    .selectOption("delete_managed_gpo");
  const deletionInspectionResponse = page.waitForResponse(
    (r) =>
      isApiResponse(r, `${context.endpoint}/gpo-preflights/`) &&
      r.request().method() === "POST",
  );
  await deletionPanel
    .getByRole("button", { name: "Submit action", exact: true })
    .click();
  const deletionInspection = await deletionInspectionResponse;
  expect(deletionInspection.status()).toBe(202);
  expect(deletionInspection.request().postDataJSON()).toEqual({
    revision: expect.any(Number),
    system_id: context.fixture.system_id,
    operation: "delete_managed_gpo",
    managed_id: writeJob.managed_id,
    domain_root_confirmed: false,
    idempotency_key: expect.any(String),
  });
  const deletionInspectionJob = await deletionInspection.json();
  expect(deletionInspectionJob.operation).toBe("inspect_managed_gpo");
  const deletionWriteResponse = page.waitForResponse(
    (r) =>
      isApiResponse(r, `${context.endpoint}/managed-gpos/`) &&
      r.request().method() === "POST",
  );
  expect(nativeFixture("inspect", deletionInspectionJob.id).status).toBe(
    "inspected",
  );
  const deletionWrite = await deletionWriteResponse;
  expect(deletionWrite.status()).toBe(202);
  const deletionJob = await deletionWrite.json();
  expect(deletionJob.operation).toBe("delete_managed_gpo");
  expect(nativeFixture("complete", deletionJob.id).status).toBe("deleted");

  await page.goto("/en/security/override");
  await page
    .getByRole("combobox", { name: "Override", exact: true })
    .selectOption(override.id);
  const deleteDefinition = editor.getByRole("button", {
    name: "Delete override",
    exact: true,
  });
  await deleteDefinition.click();
  const deletedDefinitionResponse = page.waitForResponse(
    (r) =>
      isApiResponse(r, `/api/v1/security/overrides/${override.id}/`) &&
      r.request().method() === "DELETE",
  );
  await editor
    .getByRole("button", { name: "Confirm deletion", exact: true })
    .click();
  expect((await deletedDefinitionResponse).status()).toBe(204);
  await expect(
    page.getByText(
      "Override definition deleted. Existing AD GPOs must be deleted first in Windows GPO deployment.",
      { exact: true },
    ),
  ).toBeVisible();
});

test("German Sample submission selection remains accepted before the override is saved", async ({
  page,
}) => {
  const context = await setup(page);
  const defender = context.baseline.components.find(
    (component) =>
      component.available && component.name.includes("Defender Antivirus"),
  );
  if (!defender) throw new Error("Defender baseline component required.");
  const catalogResponse = await page.request.get(
    `/api/v1/security/override-catalog/?${new URLSearchParams({ baseline_id: context.baseline.id, backup_id: defender.id })}`,
    { headers: context.headers },
  );
  expect(catalogResponse.status()).toBe(200);
  const catalog: OverrideCatalog = await catalogResponse.json();
  const setting = catalog.settings.find(
    (candidate) =>
      candidate.editable &&
      candidate.label === "Sample submission" &&
      candidate.enum_options.length > 1,
  );
  if (!setting) throw new Error("Editable Sample submission setting required.");
  const changed = setting.enum_options.find(
    (option) =>
      JSON.stringify(option.value) !== JSON.stringify(setting.baseline_value),
  );
  if (!changed)
    throw new Error("Alternative Sample submission value required.");

  await page.goto("/de/security/override");
  await page
    .getByRole("combobox", { name: "Override", exact: true })
    .selectOption("");
  const editor = page.getByRole("region", {
    name: "Baseline-Overrides",
    exact: true,
  });
  await editor
    .getByRole("combobox", { name: "Baseline", exact: true })
    .selectOption(context.baseline.id);
  await editor
    .getByRole("combobox", { name: "Komponente", exact: true })
    .selectOption(defender.id);
  await editor
    .getByLabel("GPO-Zweck ({purpose})", { exact: true })
    .fill(`Sample-submission-${randomUUID().slice(0, 8)}`);
  await editor
    .getByLabel("Einstellungen suchen", { exact: true })
    .fill(setting.label);
  const row = editor
    .getByRole("row")
    .filter({ has: page.getByText(setting.label, { exact: true }) })
    .first();
  await row
    .getByRole("button", {
      name: "Diese Einstellung überschreiben",
      exact: true,
    })
    .click();
  const value = row.getByRole("combobox", {
    name: `Override-Wert: ${setting.label}`,
    exact: true,
  });
  await expect(
    editor.getByRole("button", { name: "Override speichern", exact: true }),
  ).toBeDisabled();
  await value.selectOption(String(changed.value));
  await row
    .getByRole("button", { name: "Override übernehmen", exact: true })
    .click();
  await expect(value).toHaveCount(0);
  await expect(row).toContainText(changed.label);
  await expect(
    row.getByRole("button", { name: "Override entfernen", exact: true }),
  ).toBeVisible();
  await expect(
    editor.getByRole("button", { name: "Override speichern", exact: true }),
  ).toBeEnabled();

  const saved = page.waitForResponse(
    (response) =>
      isApiResponse(response, "/api/v1/security/overrides/") &&
      response.request().method() === "POST",
  );
  await editor
    .getByRole("button", { name: "Override speichern", exact: true })
    .click();
  const response = await saved;
  expect(response.status()).toBe(201);
  expect(response.request().postDataJSON().entries).toEqual([
    { setting_id: setting.setting_id, value: changed.value },
  ]);
});

test("structured baseline values remain read-only with localized explanations", async ({
  page,
}) => {
  const context = await setup(page);
  const component = context.baseline.components.find(
    (c) => c.available && c.name.includes("Domain Controller"),
  );
  if (!component)
    throw new Error("Domain Controller baseline component required.");
  const response = await page.request.get(
    `/api/v1/security/override-catalog/?${new URLSearchParams({ baseline_id: context.baseline.id, backup_id: component.id })}`,
    { headers: context.headers },
  );
  expect(response.status()).toBe(200);
  const catalog: OverrideCatalog = await response.json();
  const setting = catalog.settings.find(
    (s) => s.readonly_reason === "structured_registry_value",
  );
  if (!setting) throw new Error("Structured original setting required.");
  for (const locale of ["en", "de"] as const) {
    await page.goto(`/${locale}/security/override`);
    await page
      .getByRole("combobox", { name: "Override", exact: true })
      .selectOption("");
    const editor = page.getByRole("region", {
      name: locale === "de" ? "Baseline-Overrides" : "Baseline overrides",
      exact: true,
    });
    await editor
      .getByRole("combobox", { name: "Baseline", exact: true })
      .selectOption(context.baseline.id);
    await editor
      .getByRole("combobox", {
        name: locale === "de" ? "Komponente" : "Component",
        exact: true,
      })
      .selectOption(component.id);
    await editor
      .getByLabel(
        locale === "de" ? "Einstellungen suchen" : "Search settings",
        { exact: true },
      )
      .fill(setting.category);
    const row = editor
      .getByRole("row")
      .filter({ hasText: setting.category })
      .first();
    await expect(row).toContainText(
      locale === "de" ? "eigener Editor" : "dedicated editor",
    );
    await expect(row).not.toContainText("structured_registry_value");
    await expect(row.getByRole("button")).toHaveCount(0);
    await expect(row.getByRole("textbox")).toHaveCount(0);
  }
});
