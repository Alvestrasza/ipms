import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

async function signIn(page: Page) {
  await page.goto("/en/login");
  const username = page.getByRole("textbox", { name: "Username" });
  await expect(username).toBeEnabled();
  await username.fill("e2e-admin");
  await page.getByLabel("Password").fill("test-only-password");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL("/en");
}

test("redirects an anonymous console request to sign in", async ({ page }) => {
  await page.goto("/");

  await expect(page).toHaveURL("/en/login");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("falls back to English for an unsupported browser language", async ({
  browser,
}) => {
  const context = await browser.newContext({ locale: "fr-FR" });
  const page = await context.newPage();

  await page.goto("/");
  await expect(page).toHaveURL("/en/login");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  await context.close();
});

test("keeps API and static asset paths outside locale routing", async ({
  request,
}) => {
  const health = await request.get("/api/health");
  expect(health.ok()).toBe(true);
  expect(new URL(health.url()).pathname).toBe("/api/health");

  const emblem = await request.get("/brand/alvestrasza-emblem.png");
  expect(emblem.ok()).toBe(true);
  expect(new URL(emblem.url()).pathname).toBe("/brand/alvestrasza-emblem.png");
});

test("detects German and persists an explicit language change", async ({
  browser,
}) => {
  const context = await browser.newContext({ locale: "de-DE" });
  const page = await context.newPage();

  await page.goto("/");
  await expect(page).toHaveURL("/de/login");
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  await expect(page.getByRole("heading", { name: "Anmelden" })).toBeVisible();
  await expect(page.getByLabel("Sprache").locator("option")).toHaveText([
    "EN",
    "DE",
  ]);

  await page.getByLabel("Sprache").selectOption("en");
  await expect(page).toHaveURL("/en/login");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");

  await page.goto("/de/login");
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  await page.goto("/");
  await expect(page).toHaveURL("/de/login");

  await context.close();
});

test("uses a generic message for invalid credentials", async ({ page }) => {
  await page.goto("/en/login");
  const username = page.getByRole("textbox", { name: "Username" });
  await expect(username).toBeEnabled();
  await username.fill("unknown");
  await page.getByLabel("Password").fill("incorrect");
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.locator(".form-error")).toHaveText(
    "Sign-in failed. Check your credentials and try again.",
  );
});

test("authenticates and renders the tenant-scoped overview", async ({
  page,
}) => {
  await signIn(page);

  await expect(
    page.getByRole("heading", { name: "Infrastructure at a glance" }),
  ).toBeVisible();
  await expect(page.getByText(/Live Control Plane data/)).toBeVisible();
  await expect(
    page.getByRole("article").filter({ hasText: "Physical systems" }),
  ).toContainText("0");
  await expect(page.getByLabel("Active tenant")).toHaveValue(/[0-9a-f-]{36}/);
  await expect(
    page.getByLabel("Active tenant").locator("option:checked"),
  ).toHaveText("E2E Development");
  await expect(
    page.getByRole("button", { name: "Run discovery" }),
  ).toBeDisabled();
});

test("provides dark and light semantic themes after sign-in", async ({
  page,
}) => {
  await signIn(page);

  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(
    page.getByRole("button", { name: "Switch to dark theme" }),
  ).toBeVisible();
});

test("has no automatically detectable critical accessibility violations", async ({
  page,
}) => {
  await signIn(page);

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) => violation.impact === "critical"),
  ).toEqual([]);
});
