/**
 * File Name: domain-security.spec.ts
 * Version: v0.1.2 | Created: 2026-09-14 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Exercise real tenant domain settings and bounded pilot requests in isolated fixtures.
 */
import { randomUUID } from "node:crypto";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import type {
  DomainSecurityCatalog,
  DomainSecuritySettings,
} from "../src/lib/domain-security-types";

const api = "/api/v1/security/domain-settings/";
const route = "/en/administration/security/domains";

async function login(page: Page, username = "e2e-admin") {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(
    username === "e2e-platform" ? /\/en\/administration\/tenants$/ : /\/en$/,
  );
  const session = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  const tenant = session.tenants.find(
    (item: { slug: string }) => item.slug === "console-e2e",
  );
  return {
    session,
    headers: {
      "X-CSRFToken": session.csrf_token,
      "X-IPMS-Tenant-ID": tenant?.id ?? "",
    },
  };
}

function paths(domain: string) {
  const suffix = domain
    .split(".")
    .map((label) => `DC=${label}`)
    .join(",");
  return {
    "0": [`OU=Domain Controllers,${suffix}`],
    "1": [`OU=Servers,${suffix}`, `OU=Applications,${suffix}`],
    "2": [`OU=Clients,${suffix}`],
  };
}

async function createDomain(
  page: Page,
  headers: Record<string, string>,
  domain = `gpo-${randomUUID().slice(0, 8)}.example.invalid`,
) {
  const response = await page.request.get(api, { headers });
  expect(response.status()).toBe(200);
  const catalog: DomainSecurityCatalog = await response.json();
  const document = {
    domain_name: domain,
    tier_ous: paths(domain),
    gpo_name_template: catalog.default_name_template,
    baseline_order: catalog.baseline_options.map((item) => item.id),
  };
  const created = await page.request.post(api, { headers, data: document });
  expect(created.status()).toBe(201);
  return {
    settings: (await created.json()) as DomainSecuritySettings,
    catalog,
    document,
  };
}

async function selectDomain(page: Page, domain: string) {
  await page.goto(route);
  await page.getByRole("button").filter({ hasText: domain }).click();
  await expect(page.getByLabel("Domain DNS name", { exact: true })).toHaveValue(
    domain,
  );
}

async function selectPolicyDomain(
  page: Page,
  settings: DomainSecuritySettings,
  locale = "en",
  baseline = "microsoft-windows-server-2025",
) {
  await page.goto(`/${locale}/security/windows-gpos?baseline=${baseline}`);
  await page
    .getByRole("combobox", {
      name: locale === "de" ? "Domäne" : "Domain",
      exact: true,
    })
    .selectOption(settings.id);
}

test("domain administration saves OUs and GPO names without exposing composition ordering", async ({
  page,
}) => {
  const { headers } = await login(page);
  const catalog: DomainSecurityCatalog = await (
    await page.request.get(api, { headers })
  ).json();
  expect(catalog.baseline_options.length).toBeGreaterThan(1);
  const domain = `gpo-form-${randomUUID().slice(0, 8)}.example.invalid`;
  const mappings = paths(domain);
  const imports: string[] = [];
  const executorReads: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().includes("/gpo-imports/"))
      imports.push(request.url());
    if (request.method() === "GET" && request.url().includes("/gpo-imports/"))
      executorReads.push(request.url());
  });
  await page.goto(route);
  await page.getByRole("button", { name: "Add domain", exact: true }).click();
  await page.getByLabel("Domain DNS name", { exact: true }).fill(domain);
  await page
    .getByLabel("Tier 0 OUs", { exact: true })
    .fill(mappings["0"].join("\n"));
  await page
    .getByLabel("Tier 1 OUs", { exact: true })
    .fill(mappings["1"].join("\n"));
  await page
    .getByLabel("Tier 2 OUs", { exact: true })
    .fill(mappings["2"].join("\n"));
  await expect(
    page.getByLabel("GPO naming template", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("list", { name: "Baseline composition order", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("heading", {
      name: "Domain GPO configuration",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Unlinked pilot GPOs", exact: true }),
  ).toHaveCount(0);
  const createdResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(api) && response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Save domain settings", exact: true })
    .click();
  const created = await createdResponse;
  expect(created.status()).toBe(201);
  const domainSettings: DomainSecuritySettings = await created.json();
  expect(domainSettings.tier_ous).toEqual(mappings);
  expect(domainSettings.gpo_name_template).toBe(catalog.default_name_template);
  expect(domainSettings.baseline_order).toEqual(
    catalog.baseline_options.map((item) => item.id),
  );
  await selectDomain(page, domain);
  await expect(page.getByLabel("Tier 1 OUs", { exact: true })).toHaveValue(
    mappings["1"].join("\n"),
  );
  expect(executorReads).toEqual([]);
  const template = "Corp-{tier}-{scope}-{target}-{purpose}_V{version}";
  await page.getByLabel("GPO naming template", { exact: true }).fill(template);
  await expect(
    page.getByRole("button", { name: "Add domain", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByText("Corp-1-C-ALL-Baseline_V1.0.0", { exact: true }),
  ).toBeVisible();
  const expectedOrder = catalog.baseline_options.map((item) => item.id);
  expect(imports).toEqual([]);
  const savedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${api}${domainSettings.id}/`) &&
      response.request().method() === "PUT",
  );
  await page
    .getByRole("button", { name: "Save domain settings", exact: true })
    .click();
  const response = await savedResponse;
  expect(response.status()).toBe(200);
  expect(response.request().postDataJSON().expected_revision).toBe(
    domainSettings.revision,
  );
  expect(response.request().headers()["x-csrftoken"]).toBeTruthy();
  expect(response.request().headers()["x-ipms-tenant-id"]).toBe(
    headers["X-IPMS-Tenant-ID"],
  );
  const saved: DomainSecuritySettings = await response.json();
  expect(saved.tier_ous).toEqual(mappings);
  expect(saved.baseline_order).toEqual(expectedOrder);
  expect(saved.gpo_name_template).toBe(template);
  expect(saved.verification_status).toBe("unverified");
  await expect(
    page.getByText(
      "Domain settings saved. No directory policies were applied.",
      { exact: true },
    ),
  ).toBeVisible();
  await selectDomain(page, domain);
  await expect(
    page.getByLabel("GPO naming template", { exact: true }),
  ).toHaveValue(template);
  expect(imports).toEqual([]);
  expect(executorReads).toEqual([]);
  expect(
    (
      await (
        await page.request.get(`${api}${saved.id}/gpo-imports/`, { headers })
      ).json()
    ).results,
  ).toEqual([]);
  await selectDomain(page, domain);
  const updatedTier1 = [
    `OU=ManagedServers,${domain
      .split(".")
      .map((part) => `DC=${part}`)
      .join(",")}`,
  ];
  await page
    .getByLabel("Tier 1 OUs", { exact: true })
    .fill(updatedTier1.join("\n"));
  const updatedResponse = page.waitForResponse(
    (reply) =>
      reply.url().endsWith(`${api}${saved.id}/`) &&
      reply.request().method() === "PUT",
  );
  await page
    .getByRole("button", { name: "Save domain settings", exact: true })
    .click();
  const updated = await updatedResponse;
  expect(updated.status()).toBe(200);
  const actual = await updated.json();
  expect(actual.gpo_name_template).toBe(template);
  expect(actual.baseline_order).toEqual(expectedOrder);
  expect(actual.tier_ous["1"]).toEqual(updatedTier1);
  expect(updated.request().postDataJSON().expected_revision).toBe(
    saved.revision,
  );
  expect(imports).toEqual([]);
  await selectPolicyDomain(page, actual);
  await expect(page.getByLabel("Domain DNS name", { exact: true })).toHaveCount(
    0,
  );
  await expect(page.getByLabel("Tier 1 OUs", { exact: true })).toHaveCount(0);
  await expect(
    page.getByLabel("GPO naming template", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("heading", {
      name: "Domain GPO configuration",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("list", { name: "Baseline composition order", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", {
      name: "Configure domains and tier OUs",
      exact: true,
    }),
  ).toHaveAttribute("href", route);
  expect(imports).toEqual([]);
});

test("switching baselines keeps the second domain while updating the selected package", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { catalog } = await createDomain(page, headers);
  await createDomain(page, headers);
  const initialBaseline = "microsoft-windows-server-2025";
  const nextBaseline = catalog.baseline_options.find(
    (item) => item.id === "microsoft-windows-server-2022",
  );
  if (!nextBaseline)
    throw new Error(
      "The fixture requires the Microsoft Windows Server 2022 catalog.",
    );
  await page.goto(`/en/security/windows-gpos?baseline=${initialBaseline}`);
  const domains = page.getByRole("combobox", {
    name: "Domain",
    exact: true,
  });
  const firstId = await domains.locator("option").first().getAttribute("value");
  const secondId = await domains.locator("option").nth(1).getAttribute("value");
  if (!secondId)
    throw new Error("The fixture requires a second configured domain.");
  expect(secondId).not.toBe(firstId);
  await domains.selectOption(secondId);
  const pilotPackage = page.getByRole("combobox", {
    name: "Baseline",
    exact: true,
  });
  await expect(pilotPackage).toHaveValue(initialBaseline);
  await expect(
    page.getByLabel("GPO naming template", { exact: true }),
  ).toHaveCount(0);
  await pilotPackage.selectOption(nextBaseline.id);
  await expect(pilotPackage).toHaveValue(nextBaseline.id);
  await expect(domains).toHaveValue(secondId);
  await expect(domains).toBeEnabled();
  await expect(pilotPackage).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Save domain settings", exact: true }),
  ).toHaveCount(0);
});

test("German form explains invalid fields and saves short root OU names as full paths", async ({
  page,
}) => {
  await login(page);
  const domain = `gpo-short-${randomUUID().slice(0, 8)}.example.invalid`;
  const suffix = domain
    .split(".")
    .map((label) => `DC=${label}`)
    .join(",");
  const imports: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().includes("/gpo-imports/"))
      imports.push(request.url());
  });
  await page.goto("/de/administration/security/domains");
  await page
    .getByRole("button", { name: "Domäne hinzufügen", exact: true })
    .click();
  await page.getByLabel("DNS-Name der Domäne", { exact: true }).fill(domain);
  await page.getByLabel("Tier 0 OUs", { exact: true }).fill("_T0");
  await page
    .getByLabel("Tier 1 OUs", { exact: true })
    .fill("OU=_T1,DC=other,DC=invalid");
  await page.getByLabel("Tier 2 OUs", { exact: true }).fill("_T2");
  const save = page.getByRole("button", {
    name: "Domäneneinstellungen speichern",
    exact: true,
  });
  const post = () =>
    page.waitForResponse(
      (response) =>
        response.url().endsWith(api) && response.request().method() === "POST",
    );
  let receipt = post();
  await save.click();
  expect((await receipt).status()).toBe(400);
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "Tier 1 OUs:",
  );
  await expect(page.getByLabel("Tier 0 OUs", { exact: true })).toHaveValue(
    "_T0",
  );
  await page.getByLabel("Tier 1 OUs", { exact: true }).fill("_T1");
  receipt = post();
  await save.click();
  const response = await receipt;
  expect(response.status()).toBe(201);
  const saved: DomainSecuritySettings = await response.json();
  expect(saved.tier_ous).toEqual({
    "0": [`OU=_T0,${suffix}`],
    "1": [`OU=_T1,${suffix}`],
    "2": [`OU=_T2,${suffix}`],
  });
  await expect(
    page.getByText(
      "Domäneneinstellungen gespeichert. Es wurden keine Verzeichnisrichtlinien angewendet.",
      { exact: true },
    ),
  ).toBeVisible();
  await page.reload();
  await page.getByRole("button").filter({ hasText: domain }).click();
  for (const tier of ["0", "1", "2"]) {
    await expect(
      page.getByLabel(`Tier ${tier} OUs`, { exact: true }),
    ).toHaveValue(`OU=_T${tier},${suffix}`);
  }
  await page
    .getByLabel("Vorlage für GPO-Namen", { exact: true })
    .fill("{unknown}");
  const invalidPolicy = page.waitForResponse(
    (reply) =>
      reply.url().endsWith(`${api}${saved.id}/`) &&
      reply.request().method() === "PUT",
  );
  await page
    .getByRole("button", {
      name: "Domäneneinstellungen speichern",
      exact: true,
    })
    .click();
  expect((await invalidPolicy).status()).toBe(400);
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "GPO-Namensschema:",
  );
  await expect(
    page.getByLabel("Vorlage für GPO-Namen", { exact: true }),
  ).toHaveValue("{unknown}");
  expect(imports).toEqual([]);
});

test("a stale revision preserves the draft and cannot overwrite another administrator", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings, document } = await createDomain(page, headers);
  await selectDomain(page, settings.domain_name);
  const draft = "Draft-{tier}-{scope}-{target}-{purpose}_V{version}";
  const concurrent = "Saved-{tier}-{scope}-{target}-{purpose}_V{version}";
  const concurrentOus = {
    ...settings.tier_ous,
    "1": [
      settings.tier_ous["1"][0].replace("OU=Servers", "OU=ConcurrentServers"),
    ],
  };
  await page.getByLabel("GPO naming template", { exact: true }).fill(draft);
  const update = await page.request.put(`${api}${settings.id}/`, {
    headers,
    data: {
      ...document,
      expected_revision: settings.revision,
      gpo_name_template: concurrent,
      tier_ous: concurrentOus,
    },
  });
  expect(update.status()).toBe(200);
  const conflict = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${api}${settings.id}/`) &&
      response.request().method() === "PUT",
  );
  await page
    .getByRole("button", { name: "Save domain settings", exact: true })
    .click();
  expect((await conflict).status()).toBe(409);
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "Your draft is retained",
  );
  await expect(
    page.getByLabel("GPO naming template", { exact: true }),
  ).toHaveValue(draft);
  await expect(
    page.getByRole("button", { name: "Save domain settings", exact: true }),
  ).toBeDisabled();
  const actual = await (
    await page.request.get(`${api}${settings.id}/`, { headers })
  ).json();
  expect(actual.gpo_name_template).toBe(concurrent);
  expect(actual.tier_ous).toEqual(concurrentOus);
});

test("stale OU edits cannot overwrite a concurrent policy configuration", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings, document } = await createDomain(page, headers);
  await selectDomain(page, settings.domain_name);
  const draftOu = settings.tier_ous["1"][0].replace(
    "OU=Servers",
    "OU=DraftServers",
  );
  await page.getByLabel("Tier 1 OUs", { exact: true }).fill(draftOu);
  const template = "Updated-{tier}-{scope}-{target}-{purpose}_V{version}";
  const concurrent = await page.request.put(`${api}${settings.id}/`, {
    headers,
    data: {
      ...document,
      expected_revision: settings.revision,
      gpo_name_template: template,
    },
  });
  expect(concurrent.status()).toBe(200);
  const conflict = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${api}${settings.id}/`) &&
      response.request().method() === "PUT",
  );
  await page
    .getByRole("button", { name: "Save domain settings", exact: true })
    .click();
  expect((await conflict).status()).toBe(409);
  await expect(page.getByLabel("Tier 1 OUs", { exact: true })).toHaveValue(
    draftOu,
  );
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "Your draft is retained",
  );
  const actual = await (
    await page.request.get(`${api}${settings.id}/`, { headers })
  ).json();
  expect(actual.gpo_name_template).toBe(template);
  expect(actual.tier_ous).toEqual(settings.tier_ous);
});

test("legacy import API remains scoped and new Portal controls require the production Agent", async ({
  page,
}) => {
  const { headers } = await login(page);
  const {
    settings: initialSettings,
    catalog,
    document,
  } = await createDomain(page, headers, "gpo-ui.example.invalid");
  const configured = await page.request.put(`${api}${initialSettings.id}/`, {
    headers,
    data: {
      ...document,
      expected_revision: initialSettings.revision,
      baseline_order: [...initialSettings.baseline_order].reverse(),
    },
  });
  expect(configured.status()).toBe(200);
  const settings: DomainSecuritySettings = await configured.json();
  const authorizationEndpoint = `${api}${settings.id}/gpo-authorization/`;
  const authorization = await (
    await page.request.get(authorizationEndpoint, { headers })
  ).json();
  const administrator = authorization.members.find(
    (member: { username: string }) => member.username === "e2e-admin",
  );
  expect(administrator).toBeTruthy();
  expect(
    (
      await page.request.put(authorizationEndpoint, {
        headers,
        data: {
          expected_revision: authorization.revision,
          grants: [{ user_id: administrator.user_id, tiers: ["0"] }],
        },
      })
    ).status(),
  ).toBe(200);
  const baseline = catalog.baseline_options.find(
    (item) => item.id === "microsoft-windows-server-2025",
  );
  if (!baseline)
    throw new Error(
      "The fixture requires the actual Microsoft Windows Server 2025 catalog.",
    );
  const component = baseline.components.find((item) => item.available);
  if (!component)
    throw new Error(
      "The fixture requires one staged, verified Microsoft GPO backup component.",
    );
  await selectPolicyDomain(page, settings);
  const workflow = page.getByRole("region", {
    name: "GPO distribution",
    exact: true,
  });
  // Existing 0.2.34 Agents retain the old API contract but cannot receive schema 3 writes.
  await expect(
    workflow.getByRole("combobox", {
      name: "Executing domain controller",
      exact: true,
    }),
  ).toContainText("No eligible Agent 0.2.36 or newer");
  await expect(
    workflow.getByRole("button", {
      name: "Create approval request",
      exact: true,
    }),
  ).toBeDisabled();
  const available = await (
    await page.request.get(`${api}${settings.id}/gpo-imports/`, { headers })
  ).json();
  const executor = available.executors.find(
    (entry: { eligible: boolean; hostname: string }) =>
      entry.eligible && entry.hostname === "gpo-ui-dc",
  );
  expect(executor).toBeTruthy();
  const selection = {
    revision: settings.revision,
    system_id: executor.system_id,
    baseline_id: baseline.id,
    backup_id: component.id,
    tier: "0",
    target: "ALL",
    version: "1.0.0",
    idempotency_key: randomUUID(),
  };
  const response = await page.request.post(
    `${api}${settings.id}/gpo-imports/`,
    { headers, data: selection },
  );
  expect(response.status()).toBe(202);
  const job = await response.json();
  expect(job.approval_mode).toBe("portal");
  expect(job.status).toBe("awaiting_approval");
  expect(job.approved_at).toBeNull();
  expect(job.gpo_guid).toBeFalsy();
  expect(job.approval_document).toBeTruthy();
  const retry = await page.request.post(`${api}${settings.id}/gpo-imports/`, {
    headers,
    data: selection,
  });
  expect(retry.status()).toBe(202);
  expect((await retry.json()).id).toBe(job.id);
  await expect(
    page.getByRole("table", { name: "Recent scan jobs", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "View scan logs", exact: true }),
  ).toHaveAttribute(
    "href",
    `/en/logs/baselines?baseline=${baseline.id}&kind=baseline_scan`,
  );
  await page.goto(`/en/logs/baselines?job=${job.id}`);
  await expect(
    page.getByRole("heading", { name: job.pilot_display_name, exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Approve this GPO action", exact: true }),
  ).toBeEnabled();
});
test("tenant scope and reader permissions protect domain settings", async ({
  page,
}) => {
  const { headers, session } = await login(page);
  const { settings } = await createDomain(page, headers);
  const otherTenant = session.tenants.find(
    (item: { slug: string }) => item.slug === "service-accounts-e2e",
  );
  const otherHeaders = { ...headers, "X-IPMS-Tenant-ID": otherTenant.id };
  expect(
    (
      await page.request.get(`${api}${settings.id}/`, { headers: otherHeaders })
    ).status(),
  ).toBe(404);
  const other = await (
    await page.request.get(api, { headers: otherHeaders })
  ).json();
  expect(
    other.results.some((item: { id: string }) => item.id === settings.id),
  ).toBe(false);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  const reader = await login(page, "e2e-self-tenant");
  expect(
    (await page.request.get(api, { headers: reader.headers })).status(),
  ).toBe(403);
  await page.goto(route);
  await expect(page).toHaveURL(/\/en\/security\/baseline$/);
  await expect(
    page.getByRole("link", { name: "Domains & tiers", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("heading", {
      name: "Domain GPO configuration",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", {
      name: "Request unlinked pilot import",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Save domain settings", exact: true }),
  ).toHaveCount(0);
});

test("German domain planning remains accessible in a narrow viewport", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings } = await createDomain(page, headers);
  await page.setViewportSize({ width: 1700, height: 1100 });
  await page.goto("/de/administration/security/domains");
  await expect(
    page.getByRole("heading", {
      name: "Domänen-Sicherheitseinstellungen",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Domänen & Tiers", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(
    page.getByLabel("Vorlage für GPO-Namen", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "GPO-Konfiguration der Domäne",
      exact: true,
    }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.screenshot({
    path: test.info().outputPath("domain-security-de-mobile-synthetic.png"),
    fullPage: true,
  });
  await selectPolicyDomain(page, settings, "de");
  await expect(
    page.getByLabel("Vorlage für GPO-Namen", { exact: true }),
  ).toHaveCount(0);
  await expect(page.getByLabel("Tier 1 OUs", { exact: true })).toHaveCount(0);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.screenshot({
    path: test.info().outputPath("baseline-policy-de-mobile-synthetic.png"),
    fullPage: true,
  });
});

test("platform accounts and service outages do not expose an editable empty domain plan", async ({
  page,
}) => {
  await login(page, "e2e-platform");
  await page.goto(route);
  await expect(page).toHaveURL(/\/en\/administration\/tenants$/);
  await expect(
    page.getByRole("button", { name: "Save domain settings", exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await login(page);
  await page.context().addCookies([
    {
      name: "fixture_security_outage",
      value: "1",
      url: "http://127.0.0.1:3116",
    },
  ]);
  await page.goto(route);
  await expect(page.getByRole("main").getByRole("alert")).toHaveText(
    "Domain security settings could not be loaded. Reload to try again.",
  );
  await expect(
    page.getByRole("button", { name: "Save domain settings", exact: true }),
  ).toHaveCount(0);
  await page.context().clearCookies({ name: "fixture_security_outage" });
  await page.getByRole("button", { name: "Reload data", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Configured domains", exact: true }),
  ).toBeVisible();
});
