import { expect, test } from "@playwright/test";

test("opens an independent console window, orders input, warns on occupancy and releases its lease", async ({
  page,
  context,
}) => {
  const errors: string[] = [];
  const inputs: { type: string; payload: Record<string, unknown> }[] = [];
  let creates = 0;
  let sessionId = "";
  let framePolls = 0;
  context.on("page", (opened) =>
    opened.on("pageerror", (error) => errors.push(error.message)),
  );
  // Only the image producer is synthetic; authentication, tenant checks,
  // session exclusivity, input validation and close use the real test backend.
  await context.route("**/console-sessions/*/frame/?after=*", async (route) => {
    framePolls++;
    sessionId = new URL(route.request().url()).pathname.split("/")[5];
    const first =
      new URL(route.request().url()).searchParams.get("after") === "0";
    await route.fulfill({
      status: first ? 200 : 204,
      headers: {
        "Content-Type": "image/png",
        "Cache-Control": "private, no-store",
        "X-IPMS-Console-Status": "active",
        "X-IPMS-Console-Failure": "",
        "X-IPMS-Frame-Sequence": "1",
        "X-IPMS-Frame-Width": "1024",
        "X-IPMS-Frame-Height": "768",
      },
      body: first
        ? Buffer.from(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lRkAAAAASUVORK5CYII=",
            "base64",
          )
        : "",
    });
  });
  context.on("response", async (response) => {
    if (
      response.request().method() === "POST" &&
      response.url().includes("/virtual-machines/") &&
      response.url().endsWith("/console-sessions/")
    ) {
      creates++;
    }
  });
  context.on("request", (request) => {
    if (request.method() === "POST" && request.url().endsWith("/input/"))
      inputs.push(...request.postDataJSON().events);
  });
  await page.goto("/en/login");
  await page.getByLabel("Username").fill("e2e-admin");
  await page.getByLabel("Password").fill("test-only-password");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/en$/);
  await page.goto("/en/virtual/hyper-v");
  const popupEvent = page.waitForEvent("popup");
  await page
    .getByRole("cell", { name: "Console acceptance VM", exact: true })
    .dblclick();
  const popup = await popupEvent;
  await expect(popup.locator(".hyperv-console-surface img")).toBeVisible();
  await expect(popup.locator(".console-shell, .modal-backdrop")).toHaveCount(0);
  expect(creates).toBe(1);
  const url = popup.url();
  const tenantId = new URL(url).searchParams.get("tenant") ?? "";
  await popup.setViewportSize({ width: 900, height: 600 });
  const bounds = await popup.locator("main").boundingBox();
  expect(bounds?.width).toBe(900);
  expect(bounds?.height).toBe(600);
  await popup.screenshot({
    path: test.info().outputPath("console-window.png"),
  });
  await page
    .getByRole("cell", { name: "Console acceptance VM", exact: true })
    .dblclick();
  expect(context.pages()).toHaveLength(2);
  expect(creates).toBe(1);
  await page.goto("/en");
  await expect(popup.locator(".hyperv-console-surface")).toBeVisible();
  const surface = popup.locator(".hyperv-console-surface");
  await surface.click();
  await popup.keyboard.down("Shift");
  await popup.keyboard.up("Shift");
  await popup.mouse.wheel(0, 100);
  await popup
    .getByRole("button", { name: "Ctrl+Alt+Delete", exact: true })
    .click();
  await expect
    .poll(() => inputs.some((event) => event.type === "secure_attention"))
    .toBe(true);
  const keys = inputs.filter((event) => event.type === "key");
  expect(keys.map((event) => event.payload.is_down)).toEqual([true, false]);
  expect(inputs.some((event) => event.type === "mouse_button")).toBe(true);
  expect(inputs.some((event) => event.type === "mouse_wheel")).toBe(true);
  expect(framePolls).toBeGreaterThan(1);
  const second = await context.newPage();
  await second.goto(url);
  await expect(
    second.getByText("The virtual machine console is already in use", {
      exact: true,
    }),
  ).toBeVisible();
  await second.close();
  await popup
    .getByRole("button", { name: "Close console", exact: true })
    .click();
  await expect.poll(() => popup.isClosed()).toBe(true);
  expect(sessionId).toMatch(/^[0-9a-f-]{36}$/);
  await expect
    .poll(async () => {
      const response = await page.request.get(
        `/api/v1/hyper-v/console-sessions/${sessionId}/`,
        { headers: { "X-IPMS-Tenant-ID": tenantId } },
      );
      expect(
        response.ok(),
        `Unexpected console status HTTP ${response.status()}`,
      ).toBe(true);
      return (await response.json()).status;
    })
    .toBe("closed");
  expect(errors).toEqual([]);
});
