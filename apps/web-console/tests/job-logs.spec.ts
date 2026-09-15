/**
 * File Name: job-logs.spec.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify real log filtering, exports, permissions and compatible navigation in isolated fixtures.
 */
import { readFile } from "node:fs/promises";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

const baseline = "microsoft-windows-server-2025";
const scanMarker = "logs-fixture-complete";
const pilotId = "75555555-5555-4555-8555-555555555555";
const pilotName =
  "0-C-ALL-LogsFixtureVeryLongWindowsServerBaselineComponentWithExtendedCustomerNamingAndAdditionalPolicyScope-Pilot-75555555_V1.0.0";

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
  return { session, headers: { "X-IPMS-Tenant-ID": tenant?.id ?? "" } };
}

async function expectAlert(page: Page, message: string) {
  const alert = page.getByRole("main").getByRole("alert");
  await expect(alert).toHaveText(message);
  await expect(alert).toBeVisible();
}

test("baseline URL filters, sort, pagination and full filtered CSV use real history", async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1600, height: 1000 });
  const { headers } = await login(page);
  const seeded = await page.request.get(
    `/api/v1/logs/baselines/?q=${scanMarker}&page_size=100`,
    { headers },
  );
  expect(seeded.status()).toBe(200);
  const seed = await seeded.json();
  expect(seed.count).toBe(30);
  const firstDay = seed.results.at(-1).requested_at.slice(0, 10);
  const lastDay = seed.results[0].requested_at.slice(0, 10);
  await page.goto("/en/logs/baselines");
  await page
    .getByRole("searchbox", { name: "Search", exact: true })
    .fill(scanMarker);
  await page
    .getByRole("combobox", { name: "Operation type", exact: true })
    .selectOption("baseline_scan");
  await page
    .getByRole("combobox", { name: "Status", exact: true })
    .selectOption("completed");
  await page.getByLabel("Baseline ID", { exact: true }).fill(baseline);
  await page.getByLabel("From (UTC)", { exact: true }).fill(firstDay);
  await page.getByLabel("To (UTC)", { exact: true }).fill(lastDay);
  await page
    .getByRole("button", { name: "Apply filters", exact: true })
    .click();
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("q") === scanMarker &&
      url.searchParams.get("kind") === "baseline_scan" &&
      url.searchParams.get("to") === lastDay,
  );
  const table = page.getByRole("table", { name: "Baseline logs", exact: true });
  await expect(table.locator("tbody tr")).toHaveCount(25);
  await expect(
    page.getByRole("navigation", { name: "Log pages", exact: true }),
  ).toContainText("30 entries");
  await page.getByRole("link", { name: "Next page", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(5);
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("page") === "2" &&
      url.searchParams.get("baseline") === baseline &&
      url.searchParams.get("status") === "completed",
  );
  await page.reload();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue(scanMarker);
  await expect(table.locator("tbody tr")).toHaveCount(5);

  const downloadPromise = page.waitForEvent("download");
  const exportRequest = page.waitForRequest((request) =>
    request.url().includes("/api/v1/logs/baselines/export/"),
  );
  await page.getByRole("button", { name: "Export CSV", exact: true }).click();
  const [download, request] = await Promise.all([
    downloadPromise,
    exportRequest,
  ]);
  const exportUrl = new URL(request.url());
  expect(exportUrl.searchParams.get("q")).toBe(scanMarker);
  expect(exportUrl.searchParams.has("page")).toBe(false);
  expect(exportUrl.searchParams.has("page_size")).toBe(false);
  expect(request.headers()["x-ipms-tenant-id"]).toBe(
    headers["X-IPMS-Tenant-ID"],
  );
  expect(download.suggestedFilename()).toBe("ipms-baselines-logs.csv");
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const bytes = await readFile(downloadPath as string);
  expect([...bytes.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
  const lines = bytes.toString("utf8").trimEnd().split(/\r?\n/);
  expect(lines).toHaveLength(31);
  expect(lines.slice(1).every((line) => line.includes(scanMarker))).toBe(true);

  await page
    .getByRole("link", { name: "Sort Requested (UTC) ascending", exact: true })
    .click();
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("sort") === "requested_at" &&
      url.searchParams.get("direction") === "asc" &&
      !url.searchParams.has("page"),
  );
  await expect(table.locator("thead th").first()).toHaveAttribute(
    "aria-sort",
    "ascending",
  );
  const dates = await table
    .locator("tbody tr td:first-child > time")
    .evaluateAll((elements) =>
      elements.map((element) =>
        Date.parse(element.getAttribute("datetime") || ""),
      ),
    );
  expect(dates).toEqual([...dates].sort((left, right) => left - right));
  await table.scrollIntoViewIfNeeded();
  await page.screenshot({
    path: testInfo.outputPath("logs-desktop.png"),
    fullPage: true,
  });
  await page.getByRole("link", { name: "Clear filters", exact: true }).click();
  await expect(
    page.getByRole("searchbox", { name: "Search", exact: true }),
  ).toHaveValue("");
  await expect(page.getByLabel("Baseline ID", { exact: true })).toHaveValue("");
});

test("Logs navigation groups authorized Agent and baseline histories beside Administration", async ({
  page,
}) => {
  await login(page);
  await page.getByRole("link", { name: "Logs", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Agent logs", exact: true }),
  ).toBeVisible();
  const sidebar = page.getByRole("complementary");
  for (const label of [
    "Agents",
    "Baselines",
    "BMC communication",
    "BMC events",
    "Administration",
  ])
    await expect(
      sidebar.getByRole("link", { name: label, exact: true }),
    ).toBeVisible();
  await page
    .getByRole("searchbox", { name: "Search", exact: true })
    .fill("logs-fixture");
  await page
    .getByRole("button", { name: "Apply filters", exact: true })
    .click();
  const table = page.getByRole("table", { name: "Agent logs", exact: true });
  await expect(table).toContainText("logs-fixture-deployment");
  await expect(table).toContainText("logs-fixture-admin");
  await page
    .getByRole("link", { name: "Sort System ascending", exact: true })
    .click();
  await expect(page).toHaveURL(
    (url) =>
      url.searchParams.get("sort") === "system" &&
      url.searchParams.get("q") === "logs-fixture",
  );
  await sidebar.getByRole("link", { name: "Baselines", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Baseline logs", exact: true }),
  ).toBeVisible();
});

test("pilot receipt and exact local approval can be inspected and copied without writes", async ({
  page,
  context,
}) => {
  await login(page);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const writes: string[] = [];
  page.on("request", (request) => {
    if (
      request.url().includes("/api/v1/") &&
      !["GET", "HEAD", "OPTIONS"].includes(request.method())
    )
      writes.push(request.url());
  });
  await page.goto(
    `/en/logs/baselines?baseline=${baseline}&kind=gpo_import&domain=logs.example.invalid`,
  );
  const row = page.getByRole("row").filter({ hasText: pilotName });
  await row
    .getByRole("link", { name: "View GPO request details", exact: true })
    .click();
  await expect(page).toHaveURL(
    (url) => url.searchParams.get("job") === pilotId,
  );
  await expect(
    page.getByRole("heading", { name: "GPO request details", exact: true }),
  ).toBeVisible();
  await expect(page.locator("pre")).toContainText("logs-fixture-approval");
  await expect(
    page.getByText("Awaiting local approval", { exact: true }).first(),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Copy approval document", exact: true })
    .click();
  await expect(
    page.getByRole("status").filter({ hasText: "Approval document copied." }),
  ).toBeVisible();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(JSON.parse(copied).approval_test_marker).toBe("logs-fixture-approval");
  expect(writes).toEqual([]);
  await page.getByRole("link", { name: "Close details", exact: true }).click();
  await expect(page).toHaveURL(
    (url) =>
      !url.searchParams.has("job") &&
      url.searchParams.get("domain") === "logs.example.invalid",
  );
  await expect(page.locator("pre")).toHaveCount(0);
});

test("long pilot names remain inside their column at desktop and mobile widths", async ({
  page,
}, testInfo) => {
  await login(page);
  await page.goto(
    `/en/logs/baselines?kind=gpo_import&domain=logs.example.invalid`,
  );
  const target = page
    .getByRole("row")
    .filter({ hasText: pilotName })
    .getByRole("cell")
    .nth(5);
  await expect(target).toContainText(pilotName);
  for (const width of [1600, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    const bounds = await target.evaluate((cell) => {
      const box = cell.getBoundingClientRect();
      const text = document.createRange();
      text.selectNodeContents(cell);
      const rects = [...text.getClientRects()];
      return {
        overflowRight: Math.max(...rects.map((rect) => rect.right)) - box.right,
        overflowLeft: box.left - Math.min(...rects.map((rect) => rect.left)),
      };
    });
    expect(
      bounds.overflowRight,
      `Long GPO name at ${width}px`,
    ).toBeLessThanOrEqual(1);
    expect(
      bounds.overflowLeft,
      `Long GPO name at ${width}px`,
    ).toBeLessThanOrEqual(1);
    await page.screenshot({
      path: testInfo.outputPath(`long-gpo-name-${width}.png`),
      fullPage: true,
    });
  }
});

test("reader sees scans but no GPO approval or restricted Agent maintenance", async ({
  page,
}) => {
  const { headers } = await login(page, "e2e-self-tenant");
  await page.goto(`/en/logs/baselines?q=${scanMarker}&job=${pilotId}`);
  await expect(
    page.getByRole("table", { name: "Baseline logs", exact: true }),
  ).toContainText(scanMarker);
  await expectAlert(
    page,
    "This GPO request is unavailable for the selected tenant or your account.",
  );
  await expect(
    page.getByRole("button", { name: "Copy approval document", exact: true }),
  ).toHaveCount(0);
  await expect(page.locator("pre")).toHaveCount(0);
  await expect(
    page
      .getByRole("combobox", { name: "Operation type", exact: true })
      .locator('option[value="gpo_import"]'),
  ).toHaveCount(0);
  expect(
    (
      await page.request.get(`/api/v1/logs/gpo-imports/${pilotId}/`, {
        headers,
      })
    ).status(),
  ).toBe(403);
  await page.goto("/en/logs/agents?q=logs-fixture");
  await expect(
    page.getByText("logs-fixture-deployment", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page
      .getByRole("combobox", { name: "Operation type", exact: true })
      .locator('option[value="agent_lifecycle"]'),
  ).toHaveCount(0);
});

test("invalid duplicate filters stay explicit and cross-tenant pilot details stay unavailable", async ({
  page,
}) => {
  const { session } = await login(page);
  await page.goto(`/en/logs/baselines?q=&q=${scanMarker}`);
  await expectAlert(
    page,
    "Some filters are invalid. Check dates, IDs and filter values, or clear the filters.",
  );
  await expect(
    page.getByRole("button", { name: "Export CSV", exact: true }),
  ).toBeDisabled();
  const other = session.tenants.find(
    (item: { slug: string }) => item.slug === "service-accounts-e2e",
  );
  const response = await page.request.get(
    `/api/v1/logs/gpo-imports/${pilotId}/`,
    { headers: { "X-IPMS-Tenant-ID": other.id } },
  );
  expect(response.status()).toBe(404);
  await page.goto(`/en/logs/baselines?job=invalid`);
  await expectAlert(
    page,
    "This GPO request is unavailable for the selected tenant or your account.",
  );
});

test("legacy BMC bookmarks retain repeated query values and reach the new Logs routes", async ({
  page,
}) => {
  await login(page);
  for (const [oldPath, newPath, query, multi] of [
    [
      "logs",
      "communication",
      "severity=info&severity=warning&q=legacy%20filter&sort=severity&direction=asc",
      "severity",
    ],
    [
      "events",
      "events",
      "log_type=ilo_event_log&log_type=integrated_management_log&severity=warning&sort=bmc&direction=desc",
      "log_type",
    ],
  ]) {
    await page.goto(`/en/physical/bmc/${oldPath}?${query}`);
    await expect(page).toHaveURL(
      (url) => url.pathname === `/en/logs/bmc/${newPath}`,
    );
    const actual = new URL(page.url()).searchParams;
    const expected = new URLSearchParams(query);
    expect(actual.getAll(multi)).toEqual(expected.getAll(multi));
    for (const [key, value] of expected.entries())
      expect(actual.getAll(key)).toContain(value);
    await expect(
      page.getByRole("complementary").getByRole("link", {
        name: newPath === "events" ? "BMC events" : "BMC communication",
        exact: true,
      }),
    ).toHaveAttribute("aria-current", "page");
    await expect(page.locator('input[name="sort"]')).toHaveValue(
      expected.get("sort") || "",
    );
  }
});

test("all Logs export paths explain the explicit row limit", async ({
  page,
}) => {
  await login(page);
  for (const [path, endpoint] of [
    [`/en/logs/baselines?q=${scanMarker}`, "/api/v1/logs/baselines/export/"],
    ["/en/logs/bmc/communication", "/api/v1/bmc-logs/export/"],
    ["/en/logs/bmc/events", "/api/v1/bmc-event-logs/export/"],
  ]) {
    await page.route(`**${endpoint}**`, (route) =>
      route.fulfill({
        status: 400,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "log_export_limit_exceeded" } }),
      }),
    );
    await page.goto(path);
    await page.getByRole("button", { name: /CSV/ }).click();
    await expectAlert(
      page,
      "More than 10,000 entries match. Narrow the filters and export again.",
    );
    await page.unroute(`**${endpoint}**`);
  }
});

test("German Logs remain accessible at mobile width", async ({
  page,
}, testInfo) => {
  await login(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`/de/logs/baselines?q=${scanMarker}`);
  await expect(
    page.getByRole("heading", { name: "Baseline-Protokolle", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Filter anwenden", exact: true }),
  ).toBeVisible();
  const violations = (
    await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze()
  ).violations;
  expect(violations).toEqual([]);
  const widths = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(widths.content).toBeLessThanOrEqual(widths.viewport + 1);
  await page
    .getByRole("table", { name: "Baseline-Protokolle", exact: true })
    .scrollIntoViewIfNeeded();
  await page.screenshot({
    path: testInfo.outputPath("logs-mobile-de.png"),
    fullPage: true,
  });
});

test("platform administrator opening Logs is redirected before tenant content", async ({
  page,
}) => {
  await login(page, "e2e-platform");
  await page.goto(`/en/logs/baselines?job=${pilotId}`);
  await expect(page).toHaveURL(/\/en\/administration\/tenants$/);
  await expect(page.getByText(pilotName, { exact: true })).toHaveCount(0);
});
