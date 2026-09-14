/**
 * File Name: wsus.spec.ts
 * Version: v0.1.0
 * Created: 2026-09-13 | Modified: 2026-09-13
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify WSUS reception and console behavior against an isolated API fixture.
 * Fixture: tests/fixtures/seed-wsus.py with a dedicated E2E SQLite database.
 */
import { randomUUID } from "node:crypto";
import { expect, type Page, test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

async function login(page: Page, username = "e2e-admin") {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en$/);
  await page
    .getByRole("link", { name: "Windows updates", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "WSUS update comparison", exact: true }),
  ).toBeVisible();
}

async function createSource(page: Page, prefix: string) {
  await configureSource(page);
  const name = `${prefix} ${randomUUID().slice(0, 8)}`;
  const scope = "Isolated Windows Server security test catalog";
  const form = page.getByRole("form", { name: "Create source", exact: true });
  await form.getByLabel("Source name", { exact: true }).fill(name);
  await form.getByLabel("Catalog scope", { exact: true }).fill(scope);
  await form
    .getByLabel("WSUS host", { exact: true })
    .fill("wsus.fixture.example.invalid");
  await expect(form.getByLabel("WSUS port", { exact: true })).toHaveValue(
    "8531",
  );
  await expect(
    form.getByRole("checkbox", { name: "Use HTTPS (TLS)", exact: true }),
  ).toBeChecked();
  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/update-sources/") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Create source", exact: true })
    .click();
  const response = await responsePromise;
  expect(response.status()).toBe(201);
  expect(response.request().headers()["x-csrftoken"]).toBeTruthy();
  expect(response.request().headers()["x-ipms-tenant-id"]).toBeTruthy();
  const source = (await response.json()) as {
    id: string;
    name: string;
    scope: string;
    token: string;
    wsus_host: string;
    wsus_port: number;
    wsus_use_ssl: boolean;
  };
  expect(response.request().postDataJSON()).toMatchObject({
    wsus_host: "wsus.fixture.example.invalid",
    wsus_port: 8531,
    wsus_use_ssl: true,
  });
  await expect(
    page.getByRole("textbox", { name: "Reception token", exact: true }),
  ).toHaveValue(source.token);
  await page
    .getByRole("button", { name: "Dismiss token", exact: true })
    .click();
  await expect(
    page.getByRole("textbox", { name: "Reception token", exact: true }),
  ).toHaveCount(0);
  await openComparison(page);
  await expect(
    page.getByText("No WSUS report has been received for this source.", {
      exact: true,
    }),
  ).toBeVisible();
  return source;
}

async function configureSource(page: Page) {
  await page
    .getByRole("link", { name: "Configure WSUS server", exact: true })
    .click();
  await expect(
    page.getByRole("heading", {
      name: "WSUS server configuration",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "WSUS server", exact: true }),
  ).toHaveAttribute("aria-current", "page");
}

async function openComparison(page: Page) {
  await page
    .getByRole("link", { name: "Open server comparison", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "WSUS update comparison", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Create source", exact: true }),
  ).toHaveCount(0);
}

function snapshot(scope: string, state: string, count = 1) {
  const observed = new Date().toISOString();
  const updates = Array.from({ length: count }, (_, index) => ({
    update_id: randomUUID(),
    revision: 1,
    title: `Fixture security update ${String(index + 1).padStart(2, "0")}`,
    kb_articles: [String(9000000 + index)],
    products: ["Windows Server"],
    classification: "Security Updates",
    severity: "Critical",
  }));
  return {
    schema_version: 1,
    snapshot_id: randomUUID(),
    observed_at: observed,
    complete: true,
    scope,
    updates,
    computers: [
      {
        computer_id: randomUUID(),
        fqdn: "CONSOLE-HOST.EXAMPLE.INVALID.",
        reported_at: observed,
        updates: updates.map((update, index) => ({
          update_id: update.update_id,
          revision: update.revision,
          state: index === 0 ? state : "installed",
        })),
      },
    ],
  };
}

async function receive(
  page: Page,
  source: { id: string; token: string },
  document: ReturnType<typeof snapshot>,
) {
  const response = await page.request.post(
    `/api/v1/update-sources/${source.id}/snapshots/`,
    {
      headers: { Authorization: `Bearer ${source.token}` },
      data: document,
    },
  );
  expect(response.status()).toBe(201);
  await page
    .getByRole("button", { name: "Reload received data", exact: true })
    .click();
  await expect(
    page.getByText("Loading received data…", { exact: true }),
  ).toHaveCount(0);
}

test("real source reception, scoped evidence, paging, source state and one-time tokens", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1700, height: 1100 });
  await login(page);
  const source = await createSource(page, "WSUS browser lifecycle");
  const document = snapshot(source.scope, "not_installed", 51);
  await receive(page, source, document);
  const row = page
    .getByRole("row")
    .filter({ hasText: "console-host.example.invalid" });
  await expect(row.getByText("Updates missing", { exact: true })).toBeVisible();
  await expect(row.getByText("Matched by FQDN", { exact: true })).toBeVisible();
  await expect(
    page.getByText(/Servers do not need to register with WSUS/),
  ).toBeVisible();
  await row
    .getByRole("button", { name: "View updates: console-host", exact: true })
    .click();
  const details = page.getByRole("region", {
    name: "Reported server updates",
    exact: true,
  });
  await expect(
    details.getByText("Fixture security update 01", { exact: true }),
  ).toBeVisible();
  await details.getByRole("button", { name: "Next page", exact: true }).click();
  await expect(
    details.getByText("Fixture security update 51", { exact: true }),
  ).toBeVisible();
  await expect(
    details.getByText("Fixture security update 01", { exact: true }),
  ).toHaveCount(0);
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    window.document.querySelectorAll(".table-scroll").forEach((element) => {
      element.scrollLeft = 0;
    });
  });
  await page.screenshot({
    path: test.info().outputPath("wsus-received-comparison.png"),
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Close update details", exact: true })
    .click();

  await configureSource(page);
  await page
    .getByRole("button", { name: "Disable reception", exact: true })
    .click();
  await expect(page.getByText(/Reception is disabled/)).toBeVisible();
  await openComparison(page);
  await expect(row.getByText("Stale", { exact: true })).toBeVisible();
  const rejected = await page.request.post(
    `/api/v1/update-sources/${source.id}/snapshots/`,
    {
      headers: { Authorization: `Bearer ${source.token}` },
      data: snapshot(source.scope, "installed"),
    },
  );
  expect(rejected.status()).toBe(401);
  await configureSource(page);
  await page
    .getByRole("button", { name: "Enable reception", exact: true })
    .click();
  await openComparison(page);
  await expect(row.getByText("Updates missing", { exact: true })).toBeVisible();
  await configureSource(page);
  await page
    .getByRole("button", { name: "Replace reception token", exact: true })
    .click();
  await expect(
    page.getByText(/immediately invalidates the previous token/),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Replace token now", exact: true })
    .click();
  const tokenField = page.getByRole("textbox", {
    name: "Reception token",
    exact: true,
  });
  await expect(tokenField).toBeVisible();
  const replacement = await tokenField.inputValue();
  expect(replacement).not.toBe(source.token);
  const oldToken = await page.request.post(
    `/api/v1/update-sources/${source.id}/snapshots/`,
    {
      headers: { Authorization: `Bearer ${source.token}` },
      data: snapshot(source.scope, "installed"),
    },
  );
  expect(oldToken.status()).toBe(401);
  await page
    .getByRole("button", { name: "Dismiss token", exact: true })
    .click();
  await openComparison(page);
  await receive(
    page,
    { ...source, token: replacement },
    snapshot(source.scope, "installed"),
  );
  await expect(
    row.getByText("Current in catalog scope", { exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("textbox", { name: "Reception token", exact: true }),
  ).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("real incomplete, stale, ambiguous and unmatched reports never appear current", async ({
  page,
}) => {
  await login(page);
  const source = await createSource(page, "WSUS browser evidence");
  const row = page
    .getByRole("row")
    .filter({ hasText: "console-host.example.invalid" });
  const incomplete = snapshot(source.scope, "installed");
  incomplete.computers[0].updates = [];
  await receive(page, source, incomplete);
  await expect(row.getByText("Unknown", { exact: true }).first()).toBeVisible();
  await expect(
    row.getByText("Current in catalog scope", { exact: true }),
  ).toHaveCount(0);
  const stale = snapshot(source.scope, "installed");
  stale.computers[0].reported_at = new Date(
    Date.now() - 25 * 60 * 60 * 1000,
  ).toISOString();
  await receive(page, source, stale);
  await expect(row.getByText("Stale", { exact: true })).toBeVisible();
  const ambiguous = snapshot(source.scope, "installed");
  ambiguous.computers.push({
    ...ambiguous.computers[0],
    computer_id: randomUUID(),
  });
  await receive(page, source, ambiguous);
  await expect(row.getByText("Ambiguous", { exact: true })).toBeVisible();
  await expect(
    row.getByRole("button", {
      name: "View updates: console-host",
      exact: true,
    }),
  ).toBeEnabled();
  const unmatched = snapshot(source.scope, "installed");
  unmatched.computers[0].fqdn = "unmanaged.example.invalid";
  await receive(page, source, unmatched);
  await expect(row.getByText("No match", { exact: true })).toBeVisible();
  await expect(
    row.getByText("Current in catalog scope", { exact: true }),
  ).toHaveCount(0);
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    window.document.querySelectorAll(".table-scroll").forEach((element) => {
      element.scrollLeft = 0;
    });
  });
  await page.screenshot({
    path: test.info().outputPath("wsus-unmatched-evidence.png"),
    fullPage: true,
  });
  const emptySource = await createSource(page, "WSUS browser empty");
  await expect(page.getByLabel("Source", { exact: true })).toHaveValue(
    emptySource.id,
  );
  await expect(
    page.getByText("No WSUS report has been received for this source.", {
      exact: true,
    }),
  ).toBeVisible();
  await page.getByLabel("Source", { exact: true }).selectOption(source.id);
  await expect(row.getByText("No match", { exact: true })).toBeVisible();
});

test("catalog-only reception compares local Agent evidence without WSUS client registration", async ({
  page,
}) => {
  await login(page);
  const source = await createSource(page, "WSUS browser catalog only");
  const document = snapshot(source.scope, "installed", 3);
  document.computers = [];
  document.updates[0].update_id = "61111111-1111-1111-1111-111111111111";
  document.updates[1].update_id = "62222222-2222-2222-2222-222222222222";
  document.updates[1].revision = 2;
  await receive(page, source, document);
  await expect(page.getByText(/Catalog-only source:/)).toBeVisible();
  const row = page
    .getByRole("row")
    .filter({ hasText: "console-host.example.invalid" });
  await expect(
    row.getByText("Local evidence collected", { exact: true }),
  ).toBeVisible();
  await expect(
    row
      .getByText("Installed catalog matches", { exact: true })
      .locator("..")
      .locator("dd"),
  ).toHaveText("1");
  await expect(
    row
      .getByText("Different installed revisions", { exact: true })
      .locator("..")
      .locator("dd"),
  ).toHaveText("1");
  await expect(
    row
      .getByText("Without installation evidence", { exact: true })
      .locator("..")
      .locator("dd"),
  ).toHaveText("1");
  await expect(
    row
      .getByText("Available updates", { exact: true })
      .locator("..")
      .locator("dd"),
  ).toHaveText("Not reported");
  await expect(
    row.getByText("Agent scan is stale or its timestamp is missing.", {
      exact: true,
    }),
  ).toBeVisible();
  await row
    .getByRole("button", { name: "View updates: console-host", exact: true })
    .click();
  const details = page.getByRole("region", {
    name: "Reported server updates",
    exact: true,
  });
  await expect(
    details
      .getByRole("row")
      .filter({ hasText: "Fixture security update 01" })
      .getByRole("cell", { name: /^Installed \(Agent evidence\)/ }),
  ).toBeVisible();
  await expect(
    details
      .getByRole("row")
      .filter({ hasText: "Fixture security update 02" })
      .getByRole("cell", { name: /^Different installed revision/ }),
  ).toBeVisible();
  await expect(
    details
      .getByRole("row")
      .filter({ hasText: "Fixture security update 03" })
      .getByRole("cell", { name: /^No installation evidence/ }),
  ).toBeVisible();
  await expect(
    page.getByText("Current in catalog scope", { exact: true }),
  ).toHaveCount(0);
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    window.document.querySelectorAll(".table-scroll").forEach((element) => {
      element.scrollLeft = 0;
    });
  });
  await page.screenshot({
    path: test.info().outputPath("wsus-catalog-only-agent-evidence.png"),
    fullPage: true,
  });
});

test("German reader view has no mutation controls and the real API denies source creation", async ({
  page,
}) => {
  await login(page, "e2e-reset-target");
  await page.goto("/de/updates/wsus");
  await expect(
    page.getByRole("heading", { name: "WSUS-Updateabgleich", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Windows-Updates", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Quelle anlegen", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Empfangstoken ersetzen", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "WSUS-Server konfigurieren", exact: true }),
  ).toHaveCount(0);
  await page.goto("/de/administration/updates/wsus");
  await expect(page).toHaveURL(/\/de\/updates\/wsus$/);
  const sessionResponse = await page.request.get("/api/v1/auth/session/");
  const session = await sessionResponse.json();
  const tenant = session.tenants.find(
    (item: { slug: string }) => item.slug === "console-e2e",
  );
  const response = await page.request.post("/api/v1/update-sources/", {
    headers: {
      "X-CSRFToken": session.csrf_token,
      "X-IPMS-Tenant-ID": tenant.id,
      Origin: new URL(page.url()).origin,
    },
    data: { name: "Forbidden reader source", scope: "Fixture" },
  });
  expect(response.status()).toBe(403);
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    window.document.querySelectorAll(".table-scroll").forEach((element) => {
      element.scrollLeft = 0;
    });
  });
  await page.screenshot({
    path: test.info().outputPath("wsus-german-reader.png"),
    fullPage: true,
  });
});

test("administration saves and edits the WSUS server without contacting it and clears the current report", async ({
  page,
}) => {
  await login(page);
  const source = await createSource(page, "WSUS browser server configuration");
  const beforeChange = snapshot(source.scope, "installed");
  beforeChange.computers = [];
  await receive(page, source, beforeChange);
  await page.getByRole("link", { name: "Administration", exact: true }).click();
  await page.getByRole("link", { name: "WSUS server", exact: true }).click();
  await page
    .getByRole("combobox", { name: "Source", exact: true })
    .selectOption(source.id);
  await openComparison(page);
  await configureSource(page);
  const form = page.getByRole("form", {
    name: "WSUS server settings",
    exact: true,
  });
  await expect(form.getByLabel("WSUS host", { exact: true })).toHaveValue(
    "wsus.fixture.example.invalid",
  );
  await page.reload();
  await expect(form.getByLabel("WSUS port", { exact: true })).toHaveValue(
    "8531",
  );
  await expect(
    form.getByRole("checkbox", { name: "Use HTTPS (TLS)", exact: true }),
  ).toBeChecked();
  await expect(
    page.getByText(/It does not connect to WSUS or start a synchronization/),
  ).toBeVisible();
  await expect(
    page.getByText(/A new report collected after the change is required/),
  ).toBeVisible();

  await form
    .getByLabel("WSUS host", { exact: true })
    .fill("https://wsus.fixture.example.invalid/path");
  await form
    .getByRole("button", { name: "Save WSUS server", exact: true })
    .click();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Enter a WSUS host without a URL" }),
  ).toBeVisible();
  await form.getByLabel("WSUS host", { exact: true }).fill("2001:db8::13");
  await form.getByLabel("WSUS port", { exact: true }).fill("0");
  expect(
    await form
      .getByLabel("WSUS port", { exact: true })
      .evaluate((input: HTMLInputElement) => input.validity.rangeUnderflow),
  ).toBe(true);
  await form.getByLabel("WSUS port", { exact: true }).fill("8530");
  await form
    .getByRole("checkbox", { name: "Use HTTPS (TLS)", exact: true })
    .uncheck();
  const requestedHosts: string[] = [];
  page.on("request", (request) =>
    requestedHosts.push(new URL(request.url()).hostname),
  );
  const savedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/api/v1/update-sources/${source.id}/`) &&
      response.request().method() === "PATCH",
  );
  await form
    .getByRole("button", { name: "Save WSUS server", exact: true })
    .click();
  const saved = await savedResponse;
  expect(saved.status()).toBe(200);
  expect(saved.request().postDataJSON()).toEqual({
    wsus_host: "2001:db8::13",
    wsus_port: 8530,
    wsus_use_ssl: false,
  });
  expect(saved.request().headers()["x-csrftoken"]).toBeTruthy();
  expect(saved.request().headers()["x-ipms-tenant-id"]).toBeTruthy();
  const savedSource = await saved.json();
  expect(savedSource).toMatchObject({
    id: source.id,
    scope: source.scope,
    wsus_host: "2001:db8::13",
    wsus_port: 8530,
    wsus_use_ssl: false,
    last_received_at: null,
  });
  expect(savedSource).not.toHaveProperty("token");
  expect(requestedHosts.every((host) => host === "127.0.0.1")).toBe(true);
  await page.reload();
  await expect(form.getByLabel("WSUS host", { exact: true })).toHaveValue(
    "2001:db8::13",
  );
  await expect(form.getByLabel("WSUS port", { exact: true })).toHaveValue(
    "8530",
  );
  await expect(
    form.getByRole("checkbox", { name: "Use HTTPS (TLS)", exact: true }),
  ).not.toBeChecked();
  await expect(
    page.getByRole("textbox", { name: "Reception token", exact: true }),
  ).toHaveCount(0);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: test.info().outputPath("wsus-admin-server-settings.png"),
    fullPage: true,
  });
  await openComparison(page);
  await expect(
    page.getByText("No WSUS report has been received for this source.", {
      exact: true,
    }),
  ).toBeVisible();
  const stale = await page.request.post(
    `/api/v1/update-sources/${source.id}/snapshots/`,
    {
      headers: { Authorization: `Bearer ${source.token}` },
      data: { ...beforeChange, snapshot_id: randomUUID() },
    },
  );
  expect(stale.status()).toBe(409);
  await receive(page, source, snapshot(source.scope, "installed"));
  await expect(
    page.getByText("No WSUS report has been received for this source.", {
      exact: true,
    }),
  ).toHaveCount(0);
  await configureSource(page);
  await page.goto(`/de/administration/updates/wsus?source=${source.id}`);
  await expect(
    page.getByRole("heading", {
      name: "WSUS-Serverkonfiguration",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page
      .getByRole("form", { name: "WSUS-Servereinstellungen", exact: true })
      .getByLabel("WSUS-Host", { exact: true }),
  ).toHaveValue("2001:db8::13");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: test.info().outputPath("wsus-admin-server-settings-german.png"),
    fullPage: true,
  });
});

test("platform administration grants no bypass into tenant WSUS configuration", async ({
  page,
}) => {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill("e2e-platform");
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/administration\/tenants$/);
  await page.goto("/en/administration/updates/wsus");
  await expect(page).toHaveURL(/\/en\/administration\/tenants$/);
  await expect(
    page.getByRole("heading", {
      name: "WSUS server configuration",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "WSUS server", exact: true }),
  ).toHaveCount(0);
});

test("a comparison transport failure clears previous evidence and offers a bounded retry", async ({
  page,
}) => {
  await login(page);
  await page.route("**/api/v1/update-sources/*/comparison/?page=1", (route) =>
    route.fulfill({ status: 503, contentType: "application/json", body: "{}" }),
  );
  await page
    .getByRole("button", { name: "Reload received data", exact: true })
    .click();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Received data could not be loaded." }),
  ).toHaveText("Received data could not be loaded. Reload to try again.");
  await expect(
    page.getByRole("heading", { name: "Server comparison", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Reload received data", exact: true }),
  ).toBeEnabled();
});
