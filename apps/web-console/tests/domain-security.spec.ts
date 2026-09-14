/**
 * File Name: domain-security.spec.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
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

test("domain plans persist OU lists, names and accessible order without importing policy", async ({
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
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().includes("/gpo-imports/"))
      imports.push(request.url());
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
  const template = "Corp-{tier}-{scope}-{target}-{purpose}_V{version}";
  await page.getByLabel("GPO naming template", { exact: true }).fill(template);
  await expect(
    page.getByText("Corp-1-C-ALL-Baseline_V1.0.0", { exact: true }),
  ).toBeVisible();
  const first = catalog.baseline_options[0];
  const second = catalog.baseline_options[1];
  await page
    .getByRole("button", { name: `Move down: ${first.name}`, exact: true })
    .focus();
  await page.keyboard.press("Enter");
  const order = page.getByRole("list", {
    name: "Baseline composition order",
    exact: true,
  });
  await expect(order.locator("li").first()).toHaveAttribute(
    "data-baseline-id",
    second.id,
  );
  const drag = page.getByRole("button", {
    name: `Drag to reorder: ${second.name}`,
    exact: true,
  });
  const dropTarget = order.locator("li").last();
  await drag.hover();
  const dragBox = await drag.boundingBox();
  if (!dragBox) throw new Error("The visible drag handle has no bounds.");
  await page.mouse.down();
  // Start native dragging before the offscreen drop target is scrolled into view.
  await page.mouse.move(
    dragBox.x + dragBox.width / 2 + 10,
    dragBox.y + dragBox.height / 2,
    { steps: 5 },
  );
  await dropTarget.hover();
  // A second pointer move delivers dragover before drop in Chromium.
  await dropTarget.hover();
  await page.mouse.up();
  await expect(order.locator("li").last()).toHaveAttribute(
    "data-baseline-id",
    second.id,
  );
  const expectedOrder = await order
    .locator("li")
    .evaluateAll((items) =>
      items.map((item) => item.getAttribute("data-baseline-id")),
    );
  expect(imports).toEqual([]);
  const savedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(api) && response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Save domain settings", exact: true })
    .click();
  const response = await savedResponse;
  expect(response.status()).toBe(201);
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
  await page.reload();
  await page.getByRole("button").filter({ hasText: domain }).click();
  await expect(page.getByLabel("Tier 1 OUs", { exact: true })).toHaveValue(
    mappings["1"].join("\n"),
  );
  await expect(
    page.getByLabel("GPO naming template", { exact: true }),
  ).toHaveValue(template);
  await expect(order.locator("li").last()).toHaveAttribute(
    "data-baseline-id",
    second.id,
  );
  expect(imports).toEqual([]);
  expect(
    (
      await (
        await page.request.get(`${api}${saved.id}/gpo-imports/`, { headers })
      ).json()
    ).results,
  ).toEqual([]);
});

test("a stale revision preserves the draft and cannot overwrite another administrator", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings, document } = await createDomain(page, headers);
  await selectDomain(page, settings.domain_name);
  const draft = "Draft-{tier}-{scope}-{target}-{purpose}_V{version}";
  const concurrent = "Saved-{tier}-{scope}-{target}-{purpose}_V{version}";
  await page.getByLabel("GPO naming template", { exact: true }).fill(draft);
  const update = await page.request.put(`${api}${settings.id}/`, {
    headers,
    data: {
      ...document,
      expected_revision: settings.revision,
      gpo_name_template: concurrent,
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
});

test("pilot import is an explicit separate request and reports local approval without application", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings, catalog } = await createDomain(
    page,
    headers,
    "gpo-ui.example.invalid",
  );
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
  await selectDomain(page, settings.domain_name);
  const posts: unknown[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/gpo-imports/"))
      posts.push(request.postDataJSON());
  });
  const executor = page.getByRole("combobox", {
    name: "Domain controller Agent",
    exact: true,
  });
  await expect(executor).toContainText("gpo-ui-dc");
  await page
    .getByRole("combobox", { name: "Baseline package", exact: true })
    .selectOption(baseline.id);
  await page
    .getByRole("combobox", { name: "GPO component", exact: true })
    .selectOption(component.id);
  await expect(
    page.getByRole("button", {
      name: "Request unlinked pilot import",
      exact: true,
    }),
  ).toBeEnabled();
  expect(posts).toEqual([]);
  const receipt = page.waitForResponse(
    (response) =>
      response.url().endsWith(`${api}${settings.id}/gpo-imports/`) &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Request unlinked pilot import", exact: true })
    .click();
  const response = await receipt;
  expect([200, 201, 202]).toContain(response.status());
  const job = await response.json();
  expect(["queued", "awaiting_approval"]).toContain(job.status);
  expect(job.gpo_guid).toBeFalsy();
  expect(job.approval_document).toBeTruthy();
  expect(posts).toHaveLength(1);
  expect(posts[0]).toMatchObject({
    revision: settings.revision,
    baseline_id: baseline.id,
    backup_id: component.id,
    tier: "0",
    target: "ALL",
    version: "1.0.0",
  });
  await expect(
    page.getByText(job.pilot_display_name, { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Pilot import request recorded. Local approval is required before the Agent can create the GPO.",
      { exact: true },
    ),
  ).toBeVisible();
  await page.getByText("Local approval document", { exact: true }).click();
  await expect(page.locator("pre")).toContainText(job.id);
  await page
    .getByRole("button", { name: "Refresh pilot jobs", exact: true })
    .click();
  await expect(
    page.getByText(job.pilot_display_name, { exact: true }),
  ).toBeVisible();
  expect(posts).toHaveLength(1);
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
    page.getByRole("link", { name: "Domains & GPOs", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Save domain settings", exact: true }),
  ).toHaveCount(0);
});

test("German domain planning remains accessible in a narrow viewport", async ({
  page,
}) => {
  const { headers } = await login(page);
  await createDomain(page, headers);
  await page.setViewportSize({ width: 1700, height: 1100 });
  await page.goto("/de/administration/security/domains");
  await expect(
    page.getByRole("heading", {
      name: "Domänen-Sicherheitseinstellungen",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Domänen & GPOs", exact: true }),
  ).toHaveAttribute("aria-current", "page");
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
