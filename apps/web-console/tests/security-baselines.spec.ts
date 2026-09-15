/**
 * File Name: security-baselines.spec.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify the Security baseline flow against real isolated Django fixture data.
 */

import { execFileSync } from "node:child_process";
import path from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

async function login(page: Page, username = "e2e-admin") {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en$/);
}

test("service outage is distinct from an empty catalog and reload recovers", async ({
  page,
}) => {
  await login(page);
  await page.context().addCookies([
    {
      name: "fixture_security_outage",
      value: "1",
      url: "http://127.0.0.1:3116",
    },
  ]);
  await page.goto("/en/security/baseline");
  await expect(
    page.getByText("Baseline data is currently unavailable.", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("table")).toHaveCount(0);
  await page.context().clearCookies({ name: "fixture_security_outage" });
  await page.getByRole("link", { name: "Reload data", exact: true }).click();
  await expect(
    page
      .getByRole("row")
      .filter({ hasText: "Microsoft Windows Server 2025" })
      .first(),
  ).toContainText("25%");
});

test("catalog navigation, true percentages, scope, tenant isolation and accessible details", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.setViewportSize({ width: 1700, height: 1100 });
  await login(page);
  await page
    .getByRole("link", { name: "Security", exact: true })
    .first()
    .click();
  await expect(
    page.getByRole("heading", {
      name: "Microsoft security baselines",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Baseline", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  const row = page
    .getByRole("row")
    .filter({ hasText: "Microsoft Windows Server 2025" })
    .first();
  await expect(row).toContainText("25%");
  await expect(row).toContainText("50%");
  const catalog = page.getByRole("region", {
    name: "Baseline catalog",
    exact: true,
  });
  await expect(catalog.locator("details")).toHaveCount(0);
  await expect(
    page.getByRole("combobox", { name: "Scan target", exact: true }),
  ).toHaveCount(0);
  await row
    .getByRole("link", { name: "Microsoft Windows Server 2025", exact: true })
    .click();
  const details = catalog.locator("details");
  await expect(details).toHaveAttribute("open", "");
  await expect(
    details.getByRole("heading", {
      name: "Baseline details Microsoft Windows Server 2025",
    }),
  ).toBeVisible();
  await expect(
    page.getByText("baseline-failed.example.invalid", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("baseline-unknown.example.invalid", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("hidden-other-tenant.example.invalid", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText("Windows Server 2025 Security Baseline - 2602.zip", {
      exact: true,
    }),
  ).toBeVisible();
  await details.locator("summary").click();
  await expect(details).not.toHaveAttribute("open");
  await expect(
    page.getByText("baseline-failed.example.invalid", { exact: true }),
  ).toBeHidden();
  await details.locator("summary").focus();
  await page.keyboard.press("Enter");
  await expect(details).toHaveAttribute("open", "");
  const violations = (
    await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze()
  ).violations;
  expect(violations).toEqual([]);
  await page.screenshot({
    path: test.info().outputPath("security-baseline-en-synthetic.png"),
    fullPage: true,
  });
  expect(errors).toEqual([]);
  await page
    .getByRole("link", { name: "Clear selection", exact: true })
    .click();
  await expect(catalog.locator("details")).toHaveCount(0);
});

test("application tiles group active releases and remain square", async ({
  page,
}) => {
  await login(page);
  await page.goto("/en/security/baseline");
  const tiles = page.getByRole("definition");
  const overview = page.locator('dl[aria-label="Baseline application"]');
  await expect(overview.locator(":scope > div")).toHaveCount(5);
  await expect(overview.locator("[data-application-group]")).toHaveCount(2);
  const server = overview.locator(
    '[data-application-group="microsoft:windows:server"]',
  );
  const client = overview.locator(
    '[data-application-group="microsoft:windows:client"]',
  );
  await expect(server).toContainText("Agent confirmed");
  await expect(server.locator("dd > strong")).toHaveText("3.2%");
  await expect(server).toContainText("1 / 31");
  await expect(client.locator("dd > strong")).toHaveText("—");
  await expect(client).toContainText("Unknown: 2");
  await expect(tiles.first()).toBeVisible();
  for (const width of [1700, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    const dimensions = await overview
      .locator(":scope > div")
      .evaluateAll((cards) =>
        cards.map((card) => {
          const rect = card.getBoundingClientRect();
          return {
            width: rect.width,
            height: rect.height,
            scrollHeight: card.scrollHeight,
            clientHeight: card.clientHeight,
          };
        }),
      );
    for (const size of dimensions) {
      expect(Math.abs(size.width - size.height)).toBeLessThan(2);
      expect(size.scrollHeight).toBeLessThanOrEqual(size.clientHeight + 1);
    }
  }
  await page.getByRole("link", { name: "Clients", exact: true }).click();
  await expect(overview.locator("[data-application-group]")).toHaveCount(2);
});

test("client unknown is not a zero score and empty baseline has no matching systems", async ({
  page,
}) => {
  await login(page, "e2e-self-tenant");
  await page.goto(
    "/en/security/baseline?target=client&baseline=microsoft-windows-11-25h2",
  );
  const row = page
    .getByRole("row")
    .filter({ hasText: "Microsoft Windows 11 25H2" })
    .first();
  await expect(row).toContainText("Not assessed");
  await expect(row).toContainText("0%");
  await expect(row.locator("meter")).toHaveCount(0);
  await expect(
    page.getByText("baseline-client.example.invalid", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("baseline-unmatched.example.invalid", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("row").filter({ hasText: "Microsoft Windows Server 2025" }),
  ).toHaveCount(0);
  await page.goto(
    "/en/security/baseline?baseline=microsoft-windows-server-2019",
  );
  await expect(
    page.getByText("No matching systems", { exact: true }).first(),
  ).toBeVisible();
  await page.reload();
  await expect(
    page.getByRole("heading", {
      name: "Microsoft security baselines",
      exact: true,
    }),
  ).toBeVisible();
});

test("real system pagination and invalid selection are safe", async ({
  page,
}) => {
  await login(page);
  await page.goto(
    "/en/security/baseline?target=server&baseline=microsoft-windows-server-2022",
  );
  await expect(
    page.getByText("baseline-2022-00.example.invalid", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("gpo-self-dc.gpo-self.example.invalid", { exact: true }),
  ).toHaveCount(0);
  await page.getByRole("link", { name: "Next", exact: true }).click();
  await expect(
    page.getByText("gpo-self-dc.gpo-self.example.invalid", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("baseline-2022-00.example.invalid", { exact: true }),
  ).toHaveCount(0);
  await page.goto("/en/security/baseline?baseline=unknown");
  await expect(
    page.getByText("The selected baseline is not in this catalog selection.", {
      exact: true,
    }),
  ).toBeVisible();
});

test("German copy and narrow viewport preserve readable scope", async ({
  page,
}) => {
  await login(page);
  await page.setViewportSize({ width: 1700, height: 1100 });
  await page.goto("/de/security/baseline");
  await expect(
    page.getByRole("link", { name: "Baseline", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  const row = page
    .getByRole("row")
    .filter({ hasText: "Microsoft Windows Server 2025" })
    .first();
  await expect(row).toContainText(/25\s*%/);
  await expect(row).toContainText(/50\s*%/);
  await page.screenshot({
    path: test.info().outputPath("security-baseline-de-synthetic.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: test.info().outputPath("security-baseline-mobile-synthetic.png"),
    fullPage: true,
  });
});

test("anonymous and platform accounts cannot see tenant baselines", async ({
  page,
}) => {
  await page.goto("/en/security/baseline");
  await expect(page).toHaveURL(/\/en\/login/);
  await page.getByLabel("Username", { exact: true }).fill("e2e-platform");
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/administration\/tenants/);
  await page.goto("/en/security/baseline");
  await expect(page).toHaveURL(/\/en\/administration\/tenants/);
  await expect(
    page.getByRole("link", { name: "Security", exact: true }),
  ).toHaveCount(0);
});

test("administrator hides and restores a baseline with persistent tenant settings", async ({
  page,
}) => {
  await login(page);
  await page.goto("/en/administration/security/baselines");
  await expect(
    page.getByRole("heading", { name: "Baseline visibility", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", {
      name: "Hide: Microsoft Windows Server 2019",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("button", {
      name: "Show: Microsoft Windows Server 2019",
      exact: true,
    }),
  ).toBeEnabled();
  await page.reload();
  await expect(
    page.getByRole("button", {
      name: "Show: Microsoft Windows Server 2019",
      exact: true,
    }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Open Security overview", exact: true })
    .click();
  await expect(
    page.getByRole("row").filter({ hasText: "Microsoft Windows Server 2019" }),
  ).toHaveCount(0);
  await expect(
    page.getByText("Hidden baselines in this selection: 1", { exact: true }),
  ).toBeVisible();
  await page.goto("/de/administration/security/baselines");
  await page
    .getByRole("button", {
      name: "Einblenden: Microsoft Windows Server 2019",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("button", {
      name: "Ausblenden: Microsoft Windows Server 2019",
      exact: true,
    }),
  ).toBeEnabled();
  const violations = (
    await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
      .analyze()
  ).violations;
  expect(violations).toEqual([]);
});

test("reader sees findings but cannot manage visibility or start scans", async ({
  page,
}) => {
  await login(page, "e2e-self-tenant");
  await page.goto("/en/security/baseline");
  await expect(
    page.getByRole("button", { name: "Request read-only scan", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("link", { name: "Manage baseline visibility", exact: true }),
  ).toHaveCount(0);
  await page.goto("/en/administration/security/baselines");
  await expect(
    page.getByRole("button", { name: /Hide: Microsoft/ }),
  ).toHaveCount(0);
});

test("read-only scan request reaches the real API and complete native-shaped evidence yields findings", async ({
  page,
}) => {
  await login(page, "e2e-operator");
  await page.goto(
    "/en/security/baseline?baseline=microsoft-windows-server-2025",
  );
  await page
    .getByRole("combobox", { name: "Scan target", exact: true })
    .selectOption({ label: "baseline-unknown" });
  await page
    .getByRole("button", { name: "Request read-only scan", exact: true })
    .click();
  await expect(
    page.getByText("Scan request received", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("table", { name: "Recent scan jobs", exact: true }),
  ).toHaveCount(0);
  await page.getByRole("link", { name: "View scan logs", exact: true }).click();
  await expect(page).toHaveURL(/\/logs\/baselines\?/);
  const scanRow = page
    .getByRole("table", { name: "Baseline logs", exact: true })
    .getByRole("row")
    .filter({ hasText: "baseline-unknown" });
  await expect(scanRow).toContainText("Queued");
  const python =
    process.env.IPMS_TEST_PYTHON ||
    path.resolve("../../services/control-plane/.venv/Scripts/python.exe");
  const receipt = JSON.parse(
    execFileSync(
      python,
      [path.resolve("tests/fixtures/complete-security-scan.py")],
      { encoding: "utf8" },
    ),
  );
  expect(receipt.status).toBe("completed");
  expect(receipt.controls).toBeGreaterThan(300);
  expect(receipt.failed).toBeGreaterThan(0);
  expect(receipt.unknown).toBeGreaterThan(0);
  await page.reload();
  await expect(scanRow).toContainText("Completed");
  await page.goto(
    "/en/security/baseline?baseline=microsoft-windows-server-2025",
  );
  const host = page
    .getByRole("row")
    .filter({ hasText: "baseline-unknown.example.invalid" });
  await expect(host).toContainText("Incomplete assessment");
  await host.getByRole("link", { name: "View findings", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Control findings", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Assessment scope incomplete", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("table")).toContainText("Expected");
  await page.getByRole("link", { name: "Next", exact: true }).click();
  await expect(page).toHaveURL(/page=2/);
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  await page.screenshot({
    path: test.info().outputPath("security-scan-findings-synthetic.png"),
    fullPage: true,
  });
});
