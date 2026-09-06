import { expect, type Page, test } from "@playwright/test";

const initialPassword = "test-only-password";
const newPassword = "Fixture-Only!Updated-9k3p";
async function login(
  page: Page,
  username: string,
  password = initialPassword,
  destination = /\/en$/,
) {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(destination);
}
async function session(page: Page) {
  return (await page.request.get("/api/v1/auth/session/")).json();
}

for (const [username, destination] of [
  ["e2e-self-tenant", /\/en$/],
  ["e2e-self-platform", /\/en\/administration\/tenants$/],
  ["e2e-self-unassigned", /\/en\/access-unavailable$/],
  ["e2e-self-suspended", /\/en\/access-unavailable$/],
] as const) {
  test(`own username and password: ${username} without changing tenant authority`, async ({
    page,
    browser,
  }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await login(page, username, initialPassword, destination);
    const prior = await session(page);
    await page.getByRole("link", { name: "My account", exact: true }).click();
    await expect(page).toHaveURL(/\/en\/account$/);
    await expect(
      page.getByRole("heading", { name: "My account", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Add System", exact: true }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("combobox", { name: "Active tenant", exact: true }),
    ).toHaveCount(0);
    const otherContext = await browser.newContext({
      baseURL: "http://127.0.0.1:3107",
    });
    const other = await otherContext.newPage();
    try {
      await login(other, username, initialPassword, destination);
      await page
        .getByRole("button", { name: "Rename username", exact: true })
        .click();
      const dialog = page.getByRole("dialog");
      await dialog
        .getByLabel("New username", { exact: true })
        .fill(`${username}-renamed`);
      await dialog
        .getByLabel("Current password", { exact: true })
        .fill("wrong-current-password");
      await dialog
        .getByRole("button", { name: "Rename username", exact: true })
        .click();
      await expect(dialog.getByRole("alert")).toHaveText(
        "Your current password could not be verified.",
      );
      await expect(
        dialog.getByLabel("Current password", { exact: true }),
      ).toHaveValue("");
      await dialog
        .getByLabel("Current password", { exact: true })
        .fill(initialPassword);
      const renameResponse = page.waitForResponse(
        (response) =>
          response.url().endsWith("/auth/account/rename/") &&
          response.request().method() === "POST",
      );
      await dialog
        .getByRole("button", { name: "Rename username", exact: true })
        .click();
      const renamed = await renameResponse;
      expect(renamed.status()).toBe(200);
      expect(renamed.request().headers()).not.toHaveProperty(
        "x-ipms-tenant-id",
      );
      expect(await renamed.json()).toEqual({
        username: `${username}-renamed`,
        reauthentication_required: false,
      });
      await expect(
        page.getByRole("heading", { name: `${username}-renamed`, exact: true }),
      ).toBeVisible();
      const afterRename = await session(page);
      expect(afterRename.tenants).toEqual(prior.tenants);
      expect(afterRename.platform_permissions).toEqual(
        prior.platform_permissions,
      );
      expect((await session(other)).authenticated).toBe(true);
      await page
        .getByRole("button", { name: "Change password", exact: true })
        .click();
      await dialog
        .getByLabel("Current password", { exact: true })
        .fill(initialPassword);
      await dialog
        .getByLabel("New password", { exact: true })
        .fill(newPassword);
      await dialog
        .getByLabel("Confirm new password", { exact: true })
        .fill("Fixture-Only!Mismatch-7q4p");
      let submissions = 0;
      const count = (request: { url(): string; method(): string }) => {
        if (
          request.url().endsWith("/auth/account/password/") &&
          request.method() === "POST"
        )
          submissions++;
      };
      page.on("request", count);
      await dialog
        .getByRole("button", { name: "Change password", exact: true })
        .click();
      await expect(dialog.getByRole("alert")).toHaveText(
        "The new passwords do not match. Re-enter the password fields.",
      );
      expect(submissions).toBe(0);
      for (const label of [
        "Current password",
        "New password",
        "Confirm new password",
      ])
        await expect(dialog.getByLabel(label, { exact: true })).toHaveValue("");
      if (username === "e2e-self-platform")
        await page.screenshot({
          path: test.info().outputPath("own-account-password-dialog.png"),
        });
      await dialog
        .getByLabel("Current password", { exact: true })
        .fill(initialPassword);
      await dialog
        .getByLabel("New password", { exact: true })
        .fill(newPassword);
      await dialog
        .getByLabel("Confirm new password", { exact: true })
        .fill(newPassword);
      const passwordResponse = page.waitForResponse(
        (response) =>
          response.url().endsWith("/auth/account/password/") &&
          response.request().method() === "POST",
      );
      await dialog
        .getByRole("button", { name: "Change password", exact: true })
        .click();
      const changed = await passwordResponse;
      expect(changed.status()).toBe(200);
      // A successful self-change immediately hard-navigates. Assert observable
      // logout below; Chromium may release this response body during navigation.
      expect(submissions).toBe(1);
      expect(changed.request().postDataJSON()).not.toHaveProperty(
        "confirm_password",
      );
      await expect(page).toHaveURL(/\/en\/login\?notice=password-changed$/);
      await expect(page.getByRole("status")).toHaveText(
        "Your password was changed. Sign in again with your new password.",
      );
      expect((await session(other)).authenticated).toBe(false);
      await page
        .getByLabel("Username", { exact: true })
        .fill(`${username}-renamed`);
      await page.getByLabel("Password", { exact: true }).fill(initialPassword);
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      await expect(page.getByRole("alert")).toBeVisible();
      await page.getByLabel("Password", { exact: true }).fill(newPassword);
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      await expect(page).toHaveURL(destination);
      expect(errors).toEqual([]);
    } finally {
      await otherContext.close();
    }
  });
}

test("tenant administrator rename and reset require actor password and protect shared or external accounts", async ({
  page,
  browser,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await login(page, "e2e-admin");
  await page.goto("/en/administration/users");
  const rows = page.getByRole("row");
  for (const name of ["e2e-shared-target", "e2e-external-target"]) {
    const protectedRow = rows.filter({ hasText: name });
    await expect(
      protectedRow.getByRole("button", {
        name: `Rename username ${name}`,
        exact: true,
      }),
    ).toBeDisabled();
    await expect(
      protectedRow.getByRole("button", {
        name: `Reset password ${name}`,
        exact: true,
      }),
    ).toBeDisabled();
  }
  await expect(
    rows
      .filter({ hasText: "e2e-admin" })
      .getByRole("button", { name: "Reset password e2e-admin", exact: true }),
  ).toBeDisabled();
  const targetContext = await browser.newContext({
    baseURL: "http://127.0.0.1:3107",
  });
  const target = await targetContext.newPage();
  try {
    await login(target, "e2e-reset-target");
    const row = rows.filter({ hasText: "e2e-reset-target" });
    await row
      .getByRole("button", {
        name: "Rename username e2e-reset-target",
        exact: true,
      })
      .click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText(/Enter your own password/)).toBeVisible();
    await dialog
      .getByLabel("New username", { exact: true })
      .fill("e2e-reset-target-renamed");
    await dialog
      .getByLabel("Your administrator password", { exact: true })
      .fill(initialPassword);
    await dialog
      .getByRole("button", { name: "Rename username", exact: true })
      .click();
    await expect(row.locator("strong")).toHaveText("e2e-reset-target-renamed");
    expect((await session(target)).authenticated).toBe(true);
    await row
      .getByRole("button", {
        name: "Reset password e2e-reset-target-renamed",
        exact: true,
      })
      .click();
    await expect(
      dialog.getByText(/your own sign-in stays active/),
    ).toBeVisible();
    await page.screenshot({
      path: test.info().outputPath("tenant-password-reset-dialog.png"),
    });
    await dialog
      .getByLabel("Your administrator password", { exact: true })
      .fill("wrong-admin-password");
    await dialog.getByLabel("New password", { exact: true }).fill(newPassword);
    await dialog
      .getByLabel("Confirm new password", { exact: true })
      .fill(newPassword);
    await dialog
      .getByRole("button", { name: "Reset password", exact: true })
      .click();
    await expect(dialog.getByRole("alert")).toHaveText(
      "Your current password could not be verified.",
    );
    await expect(
      dialog.getByLabel("Your administrator password", { exact: true }),
    ).toHaveValue("");
    await dialog
      .getByLabel("Your administrator password", { exact: true })
      .fill(initialPassword);
    await dialog.getByLabel("New password", { exact: true }).fill(newPassword);
    await dialog
      .getByLabel("Confirm new password", { exact: true })
      .fill(newPassword);
    const response = page.waitForResponse(
      (item) =>
        /\/auth\/users\/[^/]+\/password\/$/.test(item.url()) &&
        item.request().method() === "POST",
    );
    await dialog
      .getByRole("button", { name: "Reset password", exact: true })
      .click();
    const reset = await response;
    expect(reset.status()).toBe(200);
    expect(await reset.json()).toEqual({ reauthentication_required: false });
    expect(reset.request().headers()).toHaveProperty("x-ipms-tenant-id");
    await expect(
      page.getByRole("status").filter({ hasText: /password was reset/ }),
    ).toBeVisible();
    expect((await session(target)).authenticated).toBe(false);
    expect((await session(page)).user.username).toBe("e2e-admin");
    await login(target, "e2e-reset-target-renamed", newPassword);
    await page.reload();
    expect(errors).toEqual([]);
  } finally {
    await targetContext.close();
  }
});

test("German own account dialog is centered and externally managed account stays read-only", async ({
  page,
}) => {
  await login(page, "e2e-external-target");
  await page.goto("/en/account");
  await expect(
    page.getByText(/managed by an external identity provider/),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Rename username", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Change password", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/login$/);
  await login(
    page,
    "e2e-platform",
    initialPassword,
    /\/en\/administration\/tenants$/,
  );
  await page.goto("/de/account");
  await expect(
    page.getByRole("heading", { name: "Mein Konto", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Passwort ändern", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByLabel("Aktuelles Passwort", { exact: true }),
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
    path: test.info().outputPath("own-account-german-dialog.png"),
  });
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});

for (const failure of ["rate-limit", "uncertain-transport"] as const) {
  test(`identity mutation ${failure} clears passwords without replay`, async ({
    page,
  }) => {
    await login(
      page,
      "e2e-platform",
      initialPassword,
      /\/en\/administration\/tenants$/,
    );
    await page.goto("/en/account");
    let requests = 0;
    await page.route("**/api/v1/auth/account/password/", async (route) => {
      requests++;
      if (failure === "rate-limit")
        await route.fulfill({
          status: 429,
          contentType: "application/json",
          headers: { "Retry-After": "60" },
          body: JSON.stringify({ error: { code: "rate_limited" } }),
        });
      else await route.abort("failed");
    });
    await page
      .getByRole("button", { name: "Change password", exact: true })
      .click();
    const dialog = page.getByRole("dialog");
    await dialog
      .getByLabel("Current password", { exact: true })
      .fill(initialPassword);
    await dialog.getByLabel("New password", { exact: true }).fill(newPassword);
    await dialog
      .getByLabel("Confirm new password", { exact: true })
      .fill(newPassword);
    await dialog
      .getByRole("button", { name: "Change password", exact: true })
      .click();
    await expect(dialog.getByRole("alert")).toHaveText(
      failure === "rate-limit"
        ? /Wait at least one minute/
        : /result may be uncertain/,
    );
    for (const label of [
      "Current password",
      "New password",
      "Confirm new password",
    ])
      await expect(dialog.getByLabel(label, { exact: true })).toHaveValue("");
    expect(requests).toBe(1);
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    expect(requests).toBe(1);
  });
}

test("administrator reset dialog footer is reachable with keyboard and scroll at 720 pixels", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await login(page, "e2e-admin");
  await page.goto("/en/administration/users");
  await page
    .getByRole("button", { name: "Reset password e2e-operator", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  const confirm = dialog.getByLabel("Confirm new password", { exact: true });
  await confirm.focus();
  await page.keyboard.press("Tab");
  const cancel = dialog
    .locator(".modal-card__actions")
    .getByRole("button", { name: "Cancel", exact: true });
  await expect(cancel).toBeFocused();
  await page.keyboard.press("Tab");
  const submit = dialog.getByRole("button", {
    name: "Reset password",
    exact: true,
  });
  await expect(submit).toBeFocused();
  const buttonBox = await submit.boundingBox();
  const dialogBox = await dialog.boundingBox();
  if (!buttonBox || !dialogBox)
    throw new Error("Expected visible dialog footer.");
  expect(buttonBox.y).toBeGreaterThanOrEqual(dialogBox.y);
  expect(buttonBox.y + buttonBox.height).toBeLessThanOrEqual(
    Math.min(720, dialogBox.y + dialogBox.height),
  );
  expect(await dialog.evaluate((element) => element.scrollTop)).toBeGreaterThan(
    0,
  );
  await page.screenshot({
    path: test.info().outputPath("tenant-password-reset-keyboard-footer.png"),
  });
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});
