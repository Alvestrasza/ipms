import { expect, test } from "@playwright/test";

test("serves the anonymous sign-in experience without browser errors", async ({
  page,
}) => {
  const browserErrors: string[] = [];
  const failedResponses: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      const location = message.location();
      browserErrors.push(
        `${message.text()}${location.url ? ` [${location.url}]` : ""}`,
      );
    }
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));
  page.on("response", (response) => {
    if (response.status() >= 400) {
      failedResponses.push(`${response.status()} ${response.url()}`);
    }
  });

  await page.goto("/");
  await page.waitForLoadState("networkidle");

  await expect(page).toHaveURL(/\/login$/);
  await expect(
    page.getByRole("heading", {
      name: "Independent Platform Management System",
    }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByLabel("Username")).toBeEnabled();
  await expect(page.getByLabel("Password")).toBeEnabled();
  await expect(page.getByRole("button", { name: "Continue" })).toBeEnabled();
  expect(failedResponses).toEqual([]);
  expect(browserErrors).toEqual([]);
});
