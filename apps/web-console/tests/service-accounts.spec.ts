import { expect, type Page, test } from "@playwright/test";

async function login(page: Page, username = "e2e-admin") {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en$/);
}

test("service account CRUD and explicit host assignment use the real isolated API", async ({
  page,
}) => {
  const errors: string[] = [];
  await page.setViewportSize({ width: 1600, height: 1000 });
  page.on("pageerror", (error) => errors.push(error.message));
  await login(page);
  await page.goto("/en/administration/service-accounts");
  await expect(
    page.getByRole("heading", { name: "Service Accounts", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Service Accounts", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Add service account", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog
    .getByLabel("Account name", { exact: true })
    .fill("Fixture console account");
  await dialog.getByLabel("Username", { exact: true }).fill("fixture-console");
  await dialog.getByLabel("Domain (optional)", { exact: true }).fill("FIXTURE");
  await dialog
    .getByLabel("Password", { exact: true })
    .fill("fixture-only-console-password");
  const createdResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/service-accounts/") &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Save account", exact: true })
    .click();
  const created = await createdResponse;
  expect(created.status()).toBe(201);
  const account = await created.json();
  expect(Object.keys(account).sort()).toEqual(
    [
      "id",
      "name",
      "kind",
      "username",
      "domain",
      "host_count",
      "updated_at",
    ].sort(),
  );
  expect(JSON.stringify(account)).not.toContain(
    "fixture-only-console-password",
  );
  await expect(dialog).toHaveCount(0);
  const accountRow = page
    .getByRole("row")
    .filter({ hasText: "Fixture console account" })
    .first();
  await expect(accountRow).toBeVisible();

  await accountRow
    .getByRole("button", {
      name: "Edit service account Fixture console account",
      exact: true,
    })
    .click();
  await expect(dialog.getByLabel("Password", { exact: true })).toHaveValue("");
  await expect(
    dialog.getByText(/Changing credentials or host assignments closes/),
  ).toBeVisible();
  await dialog
    .getByLabel("Account name", { exact: true })
    .fill("Fixture renamed account");
  const editedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/service-accounts/${account.id}/`) &&
      response.request().method() === "PATCH",
  );
  await dialog
    .getByRole("button", { name: "Save account", exact: true })
    .click();
  const edited = await editedResponse;
  expect(edited.status()).toBe(200);
  expect(edited.request().postDataJSON()).toEqual({
    name: "Fixture renamed account",
  });
  await expect(dialog).toHaveCount(0);
  const renamedRow = page
    .getByRole("row")
    .filter({ hasText: "Fixture renamed account" })
    .first();
  await expect(renamedRow).toBeVisible();

  const host = page
    .getByRole("row")
    .filter({ hasText: "console-host.example.invalid" });
  await host.getByRole("combobox").selectOption(account.id);
  const assignedResponse = page.waitForResponse(
    (response) =>
      /\/service-accounts\/hosts\/[a-f0-9-]+\/$/.test(response.url()) &&
      response.request().method() === "PUT",
  );
  await host
    .getByRole("button", {
      name: "Save assignment console-host.example.invalid",
      exact: true,
    })
    .click();
  const assigned = await assignedResponse;
  expect(assigned.status()).toBe(200);
  expect((await assigned.json()).service_account_id).toBe(account.id);
  await expect(
    renamedRow.getByRole("button", {
      name: "Delete service account Fixture renamed account",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    renamedRow.getByText("Unassign hosts before deletion.", { exact: true }),
  ).toBeVisible();
  await page.reload();
  await expect(host.getByRole("combobox")).toHaveValue(account.id);

  await renamedRow
    .getByRole("button", {
      name: "Edit service account Fixture renamed account",
      exact: true,
    })
    .click();
  await dialog
    .getByLabel("Password", { exact: true })
    .fill("fixture-only-rotated-password");
  const rotatedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/service-accounts/${account.id}/`) &&
      response.request().method() === "PATCH",
  );
  await dialog
    .getByRole("button", { name: "Save account", exact: true })
    .click();
  const rotated = await rotatedResponse;
  expect(rotated.status()).toBe(200);
  expect(rotated.request().postDataJSON().password).toBe(
    "fixture-only-rotated-password",
  );
  expect(await rotated.text()).not.toContain("fixture-only-rotated-password");
  await expect(dialog).toHaveCount(0);
  await page.screenshot({
    path: test.info().outputPath("service-accounts-assigned.png"),
    fullPage: true,
  });

  await host
    .getByRole("button", {
      name: "Remove assignment console-host.example.invalid",
      exact: true,
    })
    .click();
  await expect(
    dialog.getByText(/Active native sessions will close/),
  ).toBeVisible();
  await dialog
    .getByRole("button", { name: "Cancel", exact: true })
    .last()
    .click();
  await expect(host.getByRole("combobox")).toHaveValue(account.id);
  await host
    .getByRole("button", {
      name: "Remove assignment console-host.example.invalid",
      exact: true,
    })
    .click();
  const removedResponse = page.waitForResponse(
    (response) =>
      /\/service-accounts\/hosts\/[a-f0-9-]+\/$/.test(response.url()) &&
      response.request().method() === "DELETE",
  );
  await dialog
    .getByRole("button", { name: "Remove assignment", exact: true })
    .click();
  expect((await removedResponse).status()).toBe(204);
  await expect(dialog).toHaveCount(0);
  await expect(host.getByRole("combobox")).toHaveValue("");
  await renamedRow
    .getByRole("button", {
      name: "Delete service account Fixture renamed account",
      exact: true,
    })
    .click();
  const deletedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/service-accounts/${account.id}/`) &&
      response.request().method() === "DELETE",
  );
  await dialog
    .getByRole("button", { name: "Delete service account", exact: true })
    .click();
  expect((await deletedResponse).status()).toBe(204);
  await expect(
    page.getByText("No service accounts configured.", { exact: true }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});

test("German service account page keeps the requested navigation title and translated controls", async ({
  page,
}) => {
  await login(page);
  await page.goto("/de/administration/service-accounts");
  await expect(
    page.getByRole("heading", { name: "Service Accounts", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Service Accounts", exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Dienstkonto hinzufügen", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Kontoname", { exact: true })).toBeVisible();
  await expect(dialog.getByLabel("Passwort", { exact: true })).toBeVisible();
  await page.screenshot({
    path: test.info().outputPath("service-accounts-german-dialog.png"),
  });
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});

test("operator cannot see or access service account administration", async ({
  page,
}) => {
  await login(page, "e2e-operator");
  await expect(
    page.getByRole("link", { name: "Service Accounts", exact: true }),
  ).toHaveCount(0);
  await page.goto("/en/administration/service-accounts");
  await expect(page).toHaveURL(/\/en$/);
  const session = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  const denied = await page.request.get("/api/v1/service-accounts/", {
    headers: { "X-IPMS-Tenant-ID": session.tenants[0].id },
  });
  expect(denied.status()).toBe(403);
});

test("switching a query-scoped tenant updates both the URL and real API context", async ({
  page,
}) => {
  await login(page);
  const session = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  const first = session.tenants.find(
    (tenant: { display_name: string }) => tenant.display_name === "Console E2E",
  );
  const second = session.tenants.find(
    (tenant: { display_name: string }) =>
      tenant.display_name === "Service Accounts E2E",
  );
  for (const origin of [undefined, "null", "https://foreign.example.invalid"]) {
    const rejected = await page.request.post("/api/tenant-selection", {
      data: { tenantId: second.id },
      headers: origin ? { Origin: origin } : {},
    });
    expect(rejected.status()).toBe(403);
    expect(rejected.headers()["set-cookie"]).toBeUndefined();
  }
  await page.goto(`/en/administration/service-accounts?tenant=${first.id}`);
  await expect(
    page.getByText("console-host.example.invalid", { exact: true }),
  ).toBeVisible();
  const tenantSelection = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/tenant-selection") &&
      response.request().method() === "POST",
  );
  await page
    .getByRole("combobox", { name: "Active tenant", exact: true })
    .selectOption(second.id);
  expect((await tenantSelection).status()).toBe(204);
  await expect(page).toHaveURL(new RegExp(`\\?tenant=${second.id}$`));
  await expect(
    page.getByText("No eligible or previously assigned Hyper-V hosts found.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByText("console-host.example.invalid", { exact: true }),
  ).toHaveCount(0);
  const refreshed = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v1/service-accounts/hosts/") &&
      response.request().headers()["x-ipms-tenant-id"] === second.id,
  );
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  expect((await refreshed).status()).toBe(200);
});
