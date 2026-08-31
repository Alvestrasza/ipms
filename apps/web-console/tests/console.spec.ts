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

test("opens the tenant-scoped physical infrastructure view", async ({
  page,
}) => {
  await signIn(page);

  await page.getByRole("link", { name: "Physical infrastructure" }).click();
  await expect(page).toHaveURL("/en/physical");
  await expect(
    page.getByRole("heading", { name: "Physical infrastructure" }),
  ).toBeVisible();
  await expect(page.getByText("No physical systems discovered")).toBeVisible();
  await expect(page.getByText("BMCs")).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Bare Metal Controller" }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Physical infrastructure" }),
  ).toHaveAttribute("aria-current", "page");
});

test("opens the tenant-scoped physical Windows server inventory", async ({
  page,
}) => {
  await signIn(page);

  await page.getByRole("link", { name: "Physical infrastructure" }).click();
  await page.getByRole("link", { name: "Windows servers" }).click();
  await expect(page).toHaveURL("/en/physical/servers");
  await expect(
    page.getByRole("heading", { name: "Physical Windows servers" }),
  ).toBeVisible();
  await expect(
    page.getByText("No physical Windows servers discovered"),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Windows servers" }),
  ).toHaveAttribute("aria-current", "page");
});

test("opens the tenant-scoped virtual Windows server inventory", async ({
  page,
}) => {
  await signIn(page);

  await page.getByRole("link", { name: "Virtual infrastructure" }).click();
  await expect(page).toHaveURL("/en/virtual");
  await expect(
    page.getByRole("heading", { name: "Virtual Windows servers" }),
  ).toBeVisible();
  await expect(
    page.getByText("No virtual Windows servers discovered"),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: "Virtual infrastructure" }),
  ).toHaveAttribute("aria-current", "page");
});

test("enrolls a BMC through certificate-aware guided portal wizard", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/en/physical/bmc");
  let submittedPassword = "";
  await page.route("**/api/v1/connectors/bmc/certificate/", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        certificate: {
          fingerprint_sha256: "0".repeat(64),
          subject: "CN=synthetic-bmc",
          issuer: "CN=synthetic-test-ca",
          serial_number: "1",
          valid_from: "2026-01-01T00:00:00Z",
          valid_until: "2027-01-01T00:00:00Z",
          dns_names: ["synthetic-bmc.invalid"],
          trusted_by_system: false,
        },
        requires_explicit_trust: true,
        certificate_trust_token: "test-only-signed-token",
      }),
    });
  });
  await page.route("**/api/v1/connectors/bmc/", async (route) => {
    const payload = route.request().postDataJSON();
    submittedPassword = payload.password;
    await route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({
        connector: { id: "00000000-0000-0000-0000-000000000001" },
        discovery_job: { status: "queued" },
      }),
    });
  });

  await page.getByRole("button", { name: "Add BMC" }).click();
  await page.getByLabel("BMC family").selectOption("hpe-ilo4");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByLabel("Display name").fill("Synthetic BMC");
  await page.getByLabel("Address").fill("192.0.2.40");
  await page.getByLabel("HTTPS port").fill("443");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByLabel("Username").fill("synthetic-reader");
  const password = page.getByLabel("Password", { exact: true });
  await expect(password).toHaveAttribute("type", "password");
  await password.fill("test-only-secret");
  await page.getByRole("button", { name: "Check certificate" }).click();

  await expect(
    page.getByRole("heading", { name: "Trust BMC certificate" }),
  ).toBeVisible();
  await expect(page.getByText("CN=synthetic-test-ca")).toBeVisible();
  await page.getByRole("button", { name: "Trust and add BMC" }).click();

  await expect(page.getByText(/first discovery job is queued/i)).toBeVisible();
  expect(submittedPassword).toBe("test-only-secret");
  await expect(page.getByText("test-only-secret")).toHaveCount(0);
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
