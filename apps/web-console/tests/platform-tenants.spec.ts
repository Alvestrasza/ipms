import { expect, type Page, test } from "@playwright/test";

async function login(
  page: Page,
  username: string,
  password = "test-only-password",
  destination = /\/en$/,
) {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(destination);
}
const platformUrl = /\/en\/administration\/tenants$/;

test("platform account lands without a tenant and cannot open operational routes", async ({
  page,
  context,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await context.addCookies([
    {
      name: "ipms_tenant",
      value: "10000000-0000-4000-8000-000000000001",
      domain: "127.0.0.1",
      path: "/",
    },
  ]);
  await login(page, "e2e-platform", undefined, platformUrl);
  const session = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  expect(session.user.is_platform_admin).toBe(true);
  expect(session.platform_permissions).toEqual(["tenants.manage"]);
  expect(session.tenants).toEqual([]);
  await expect(
    page.getByRole("heading", { name: "Tenants", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("combobox", { name: "Active tenant", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Add System", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "Service Accounts", exact: true }),
  ).toHaveCount(0);
  await expect(page.getByText(/does not initialize Agent PKI/)).toBeVisible();
  const archived = page
    .getByRole("row")
    .filter({ hasText: "Archived E2E tenant" });
  await expect(
    archived.getByRole("cell", { name: "Decommissioned", exact: true }),
  ).toBeVisible();
  await expect(archived.getByRole("button")).toHaveCount(0);
  for (const path of [
    "physical",
    "physical/servers",
    "physical/clients",
    "physical/linux",
    "physical/bmc",
    "physical/bmc/events",
    "physical/bmc/logs",
    "virtual",
    "virtual/clients",
    "virtual/linux",
    "virtual/hyper-v",
    "network",
    "administration/users",
    "administration/service-accounts",
    "administration/infrastructure/agents",
    "virtual/hyper-v/console/10000000-0000-4000-8000-000000000002?tenant=10000000-0000-4000-8000-000000000001",
  ]) {
    await page.goto(`/en/${path}`);
    await expect(page).toHaveURL(platformUrl);
  }
  const denied = await page.request.get("/api/v1/service-accounts/", {
    headers: { "X-IPMS-Tenant-ID": "10000000-0000-4000-8000-000000000001" },
  });
  expect([403, 404]).toContain(denied.status());
  const selection = await page.request.post("/api/tenant-selection", {
    headers: { Origin: "http://127.0.0.1:3107" },
    data: { tenantId: "10000000-0000-4000-8000-000000000001" },
  });
  expect(selection.status()).toBe(403);
  expect(errors).toEqual([]);
});

test("real platform tenant create edit suspend reactivate and one-time separate administrator setup", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1600, height: 1000 });
  await login(page, "e2e-platform", undefined, platformUrl);
  await page
    .getByRole("button", { name: "Create tenant", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByLabel("Tenant name", { exact: true })
    .fill("Platform browser fixture");
  await dialog
    .getByLabel("Tenant ID", { exact: true })
    .fill("platform-browser-fixture");
  const creation = page.waitForResponse(
    (response) =>
      response.url().endsWith("/platform/tenants/") &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Save tenant", exact: true })
    .click();
  const created = await creation;
  expect(created.status()).toBe(201);
  expect(created.request().headers()).not.toHaveProperty("x-ipms-tenant-id");
  const tenant = await created.json();
  expect(Object.keys(tenant).sort()).toEqual(
    [
      "id",
      "slug",
      "display_name",
      "status",
      "created_at",
      "updated_at",
      "needs_administrator",
    ].sort(),
  );
  expect(tenant.needs_administrator).toBe(true);
  await expect(dialog).toHaveCount(0);
  const row = page
    .getByRole("row")
    .filter({ hasText: "platform-browser-fixture" });
  await row
    .getByRole("button", {
      name: "Edit tenant Platform browser fixture",
      exact: true,
    })
    .click();
  await expect(dialog.getByLabel("Tenant ID", { exact: true })).toBeDisabled();
  await dialog
    .getByLabel("Tenant name", { exact: true })
    .fill("Renamed platform fixture");
  await dialog
    .getByRole("button", { name: "Save tenant", exact: true })
    .click();
  await expect(
    row.getByText("Renamed platform fixture", { exact: true }),
  ).toBeVisible();
  await row
    .getByRole("button", {
      name: "Suspend tenant Renamed platform fixture",
      exact: true,
    })
    .click();
  await expect(
    dialog.getByText(/Already dispatched actions cannot be recalled/),
  ).toBeVisible();
  await dialog
    .getByRole("button", { name: "Suspend tenant", exact: true })
    .click();
  await expect(
    row.getByRole("cell", { name: "Suspended", exact: true }),
  ).toBeVisible();
  await row
    .getByRole("button", {
      name: "Reactivate tenant Renamed platform fixture",
      exact: true,
    })
    .click();
  await dialog
    .getByRole("button", { name: "Reactivate tenant", exact: true })
    .click();
  await expect(
    row.getByRole("cell", { name: "Active", exact: true }),
  ).toBeVisible();
  await row
    .getByRole("button", {
      name: "Set up administrator Renamed platform fixture",
      exact: true,
    })
    .click();
  await expect(
    dialog.getByText(/You are not added to the tenant/),
  ).toBeVisible();
  await dialog
    .getByLabel("Username", { exact: true })
    .fill("fixture-new-tenant-admin");
  await dialog
    .getByLabel("Initial password", { exact: true })
    .fill("Fixture-Only!Tenant-9p7k");
  const initialization = page.waitForResponse(
    (response) =>
      response
        .url()
        .endsWith(`/platform/tenants/${tenant.id}/initial-administrator/`) &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Create separate administrator", exact: true })
    .click();
  const initialized = await initialization;
  expect(initialized.status()).toBe(201);
  const result = await initialized.json();
  expect(Object.keys(result)).toEqual(["tenant"]);
  expect(result.tenant.needs_administrator).toBe(false);
  expect(JSON.stringify(result)).not.toContain("Fixture-Only!Tenant-9p7k");
  await expect(
    page.getByText(/You remain signed in as platform administrator/),
  ).toBeVisible();
  await expect(
    row.getByRole("button", {
      name: "Set up administrator Renamed platform fixture",
      exact: true,
    }),
  ).toBeDisabled();
  const current = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  expect(current.user.username).toBe("e2e-platform");
  expect(current.tenants).toEqual([]);
  const repeated = await page.request.post(
    `/api/v1/platform/tenants/${tenant.id}/initial-administrator/`,
    {
      headers: { "X-CSRFToken": current.csrf_token },
      data: {
        username: "fixture-forbidden-second-admin",
        initial_password: "Fixture-Only!Never-2q9k",
      },
    },
  );
  expect(repeated.status()).toBe(409);
  expect((await repeated.json()).error.code).toBe(
    "tenant_administrator_already_initialized",
  );
  await page.screenshot({
    path: test.info().outputPath("platform-tenants.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/login$/);
  await login(page, "fixture-new-tenant-admin", "Fixture-Only!Tenant-9p7k");
  const tenantSession = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  expect(tenantSession.user.is_platform_admin).toBe(false);
  expect(tenantSession.platform_permissions).toEqual([]);
  expect(tenantSession.tenants.map((item: { id: string }) => item.id)).toEqual([
    tenant.id,
  ]);
  expect((await page.request.get("/api/v1/platform/tenants/")).status()).toBe(
    403,
  );
});

test("ordinary account without tenant access has a stable localized page and logout", async ({
  page,
}) => {
  await login(page, "e2e-unassigned", undefined, /\/en\/access-unavailable$/);
  await expect(
    page.getByRole("heading", { name: "Access unavailable", exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(page).toHaveURL(/\/en\/access-unavailable$/);
  await page.goto("/de");
  await expect(page).toHaveURL(/\/de\/access-unavailable$/);
  await expect(
    page.getByRole("heading", { name: "Kein Zugriff", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Abmelden", exact: true }).click();
  await expect(page).toHaveURL(/\/de\/login$/);
});

test("tenant administrator is denied platform pages and German platform dialog is centered", async ({
  page,
}) => {
  await login(page, "e2e-admin");
  expect((await page.request.get("/api/v1/platform/tenants/")).status()).toBe(
    403,
  );
  await page.goto("/en/administration/tenants");
  await expect(page).toHaveURL(/\/en\/access-unavailable$/);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/login$/);
  await login(page, "e2e-platform", undefined, platformUrl);
  await page.goto("/de/administration/tenants");
  await page
    .getByRole("button", { name: "Mandant erstellen", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByLabel("Mandantenname", { exact: true }),
  ).toBeVisible();
  const box = await dialog.boundingBox();
  const viewport = page.viewportSize();
  if (!box || !viewport)
    throw new Error("Expected visible dialog and viewport.");
  expect(Math.abs(box.x + box.width / 2 - viewport.width / 2)).toBeLessThan(2);
  expect(Math.abs(box.y + box.height / 2 - viewport.height / 2)).toBeLessThan(
    2,
  );
  await page.screenshot({
    path: test.info().outputPath("platform-tenant-german-dialog.png"),
  });
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});
