import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("renders the read-only management overview", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Infrastructure at a glance" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Preview dataset — no live infrastructure data is displayed yet.",
    ),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Recent discovery jobs" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Run discovery" }),
  ).toBeDisabled();
});

test("provides dark and light semantic themes", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(
    page.getByRole("button", { name: "Switch to dark theme" }),
  ).toBeVisible();
});

test("labels the login route as a non-credential preview", async ({ page }) => {
  await page.goto("/login");

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeDisabled();
  await expect(
    page.getByText("Development preview. Do not enter credentials."),
  ).toBeVisible();
});

test("has no automatically detectable critical accessibility violations", async ({
  page,
}) => {
  await page.goto("/");

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) => violation.impact === "critical"),
  ).toEqual([]);
});
