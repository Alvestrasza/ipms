import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

async function signIn(page: Page) {
  await page.goto("/login");
  const username = page.getByRole("textbox", { name: "Username" });
  await expect(username).toBeEnabled();
  await username.fill("e2e-admin");
  await page.getByLabel("Password").fill("test-only-password");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL("/");
}

test("redirects an anonymous console request to sign in", async ({ page }) => {
  await page.goto("/");

  await expect(page).toHaveURL("/login");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("uses a generic message for invalid credentials", async ({ page }) => {
  await page.goto("/login");
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
