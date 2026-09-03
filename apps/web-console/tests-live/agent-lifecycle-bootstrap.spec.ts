import { expect, test } from "@playwright/test";

const username = process.env.IPMS_LIVE_USERNAME;
const password = process.env.IPMS_LIVE_PASSWORD;

if (!username || !password) {
  throw new Error("IPMS_LIVE_USERNAME and IPMS_LIVE_PASSWORD are required.");
}

test("opens the identity-preserving bootstrap for a legacy Agent", async ({
  page,
}) => {
  await page.goto("/en/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL("/en");

  await page.goto("/en/administration/infrastructure/agents");
  const legacyRow = page
    .getByRole("row")
    .filter({ hasText: "One-time lifecycle bootstrap required" })
    .first();
  await expect(legacyRow).toBeVisible();

  await legacyRow
    .getByRole("button", { name: /Activate lifecycle management/ })
    .first()
    .click();

  const dialog = page.getByRole("dialog", { name: "Update legacy Agent" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel("DNS name or IP address")).not.toHaveValue("");
  await expect(dialog.getByLabel("Preferred HTTPS port")).toHaveValue("5986");
  await expect(
    dialog.getByRole("button", { name: "Check connection" }),
  ).toBeDisabled();
});
