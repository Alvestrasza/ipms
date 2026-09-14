/**
 * File Name: security-baselines.spec.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify the Security baseline flow against real isolated Django fixture data.
 */
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
  await page.getByRole("link", { name: "Security", exact: true }).click();
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
    page.getByText("baseline-2022-25.example.invalid", { exact: true }),
  ).toHaveCount(0);
  await page.getByRole("link", { name: "Next", exact: true }).click();
  await expect(
    page.getByText("baseline-2022-25.example.invalid", { exact: true }),
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
