import { expect, test } from "@playwright/test";

const fingerprint = "a".repeat(64);
const nativeSession = "10000000-0000-4000-8000-000000000001";

for (const mode of [
  "render",
  "cancel",
  "operator",
  "configure",
  "failure",
] as const) {
  test(`native console ${mode}: scoped setup, explicit trust and cleanup`, async ({
    page,
    context,
  }) => {
    const messages: string[] = [];
    const creates: unknown[] = [];
    const errors: string[] = [];
    let socketClosed = false;
    let configured = mode !== "configure" && mode !== "operator";
    context.on("page", (opened) =>
      opened.on("pageerror", (error) => errors.push(error.message)),
    );
    // Real local fixture login and SSR inventory. Only native transport/config
    // collaborators are synthetic; no Agent, host or secret store is contacted.
    await context.route("**/console-configuration/", async (route) => {
      expect(route.request().method()).toBe("GET");
      await route.fulfill({
        json: {
          configured,
          can_manage: mode !== "operator",
          native_supported: true,
        },
      });
    });
    await context.route(
      "**/virtual-machines/*/console-sessions/",
      async (route) => {
        creates.push(route.request().postDataJSON());
        await route.fulfill({
          status: 201,
          json: {
            id: nativeSession,
            transport: "vmconnect",
            status: "requested",
          },
        });
      },
    );
    await context.route(`**/console-sessions/${nativeSession}/`, (route) =>
      route.fulfill({ status: 204 }),
    );
    await context.routeWebSocket("**/native-stream/", (socket) => {
      expect(new URL(socket.url()).search).toBe("");
      socket.onClose(() => {
        socketClosed = true;
      });
      socket.onMessage((data) => {
        const text = data.toString();
        messages.push(text);
        if (!text.startsWith("{")) {
          if (text.startsWith("0.,4.ping")) socket.send(text);
          return;
        }
        const message = JSON.parse(text);
        if (message.type === "connect")
          socket.send(
            JSON.stringify({
              type: "certificate",
              sha256: fingerprint,
              subject: "CN=Fixture host",
              issuer: "CN=Fixture issuer",
              not_before: "2026-01-01T00:00:00Z",
              not_after: "2027-01-01T00:00:00Z",
            }),
          );
        if (message.type === "trust") {
          expect(message).toEqual({ type: "trust", sha256: fingerprint });
          if (mode === "failure") {
            socket.send(
              JSON.stringify({
                type: "error",
                code: "native_authentication_failed",
              }),
            );
            return;
          }
          socket.send('{"type":"ready"}');
          socket.send(`0.,36.${nativeSession};`);
          socket.send(
            "4.size,1.0,3.640,3.480;4.rect,1.0,1.0,1.0,3.640,3.480;5.cfill,2.14,1.0,3.255,1.0,1.0,3.255;4.sync,1.1;",
          );
        }
      });
    });
    await page.goto("/en/login");
    await page.getByLabel("Username", { exact: true }).fill("e2e-admin");
    await page
      .getByLabel("Password", { exact: true })
      .fill("test-only-password");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await expect(page).toHaveURL(/\/en$/);
    await page.goto("/en/virtual/hyper-v");
    const opened = page.waitForEvent("popup");
    await page
      .getByRole("cell", { name: "Console acceptance VM", exact: true })
      .dblclick();
    const popup = await opened;
    await expect(
      popup.getByLabel("Native console", { exact: true }),
    ).toBeChecked();
    const connect = popup.getByRole("button", { name: "Connect", exact: true });
    await expect(connect).toBeDisabled();
    if (mode === "operator" || mode === "configure") {
      await expect(
        popup.getByText(
          "An administrator must assign a host account under Administration → Service Accounts. Reopen this console after the assignment.",
        ),
      ).toBeVisible();
      await expect(
        popup.locator('input[type="password"], input[name="username"]'),
      ).toHaveCount(0);
      const adminLink = popup.getByRole("link", {
        name: "Open Service Accounts",
        exact: true,
      });
      if (mode === "configure") {
        await expect(adminLink).toHaveAttribute(
          "href",
          /\/en\/administration\/service-accounts\?tenant=[a-f0-9-]+$/,
        );
        await expect(adminLink).toHaveAttribute("target", "_blank");
        configured = true;
        await popup
          .getByRole("button", { name: "Check assignment", exact: true })
          .click();
        await expect(
          popup.getByText(
            "A stored console account is available for this host.",
            { exact: true },
          ),
        ).toBeVisible();
        await expect(connect).toBeDisabled();
        expect(creates).toEqual([]);
      } else {
        await expect(adminLink).toHaveCount(0);
      }
      await popup
        .getByRole("button", { name: "Close console", exact: true })
        .click();
      expect(creates).toEqual([]);
      return;
    }
    await popup
      .getByLabel(
        "I understand that an external console session may be interrupted.",
      )
      .check();
    await connect.click();
    const certificate = popup.getByRole("alertdialog");
    await expect(certificate)
      .toBeVisible()
      .catch(async (error) => {
        await test.info().attach("native-setup-diagnostic", {
          contentType: "application/json",
          body: JSON.stringify({
            errors,
            messageCount: messages.length,
            runtime: await popup.evaluate(() => ({
              present: !!window.Guacamole,
              scripts: Array.from(document.scripts)
                .map((script) => script.src)
                .filter(Boolean),
            })),
          }),
        });
        throw error;
      });
    await expect(
      certificate.getByText(fingerprint, { exact: true }),
    ).toBeVisible();
    expect(messages.map((value) => JSON.parse(value).type)).toEqual([
      "connect",
    ]);
    expect(creates).toEqual([
      { transport: "vmconnect", external_session_acknowledged: true },
    ]);
    if (mode === "cancel") {
      await certificate
        .getByRole("button", { name: "Cancel", exact: true })
        .click();
      await expect.poll(() => popup.isClosed()).toBe(true);
      await expect.poll(() => socketClosed).toBe(true);
      expect(messages).toHaveLength(1);
      return;
    }
    await certificate
      .getByRole("button", {
        name: "Trust this certificate and connect",
        exact: true,
      })
      .click();
    if (mode === "failure") {
      await expect(
        popup.getByText(
          "The Hyper-V host rejected the stored console account.",
        ),
      ).toBeVisible();
      expect(creates).toHaveLength(1);
      await expect(popup.locator(".hyperv-console-surface img")).toHaveCount(0);
    } else {
      const surface = popup.getByRole("application");
      await expect(surface).toBeVisible();
      await expect
        .poll(async () =>
          popup
            .locator(".native-console-display canvas")
            .evaluateAll((canvases) =>
              canvases.some((element) => {
                const canvas = element as HTMLCanvasElement;
                const pixel = canvas
                  .getContext("2d")
                  ?.getImageData(10, 10, 1, 1).data;
                return (
                  pixel?.[0] === 255 &&
                  pixel?.[1] === 0 &&
                  pixel?.[2] === 0 &&
                  pixel?.[3] === 255
                );
              }),
            ),
        )
        .toBe(true);
      await surface.click();
      await popup.keyboard.down("Shift");
      await popup.keyboard.up("Shift");
      await popup.mouse.wheel(0, 100);
      await popup
        .getByRole("button", { name: "Ctrl+Alt+Delete", exact: true })
        .click();
      await expect
        .poll(() =>
          messages.some((value) => value === '{"type":"secure_attention"}'),
        )
        .toBe(true);
      expect(messages.some((value) => value.startsWith("3.key,"))).toBe(true);
      expect(messages.some((value) => value.startsWith("5.mouse,"))).toBe(true);
      await popup.setViewportSize({ width: 900, height: 600 });
      await expect(surface).toBeVisible();
      await popup.screenshot({
        path: test.info().outputPath(`native-${mode}.png`),
      });
    }
    await popup
      .getByRole("button", { name: "Close console", exact: true })
      .first()
      .click();
    await expect.poll(() => popup.isClosed()).toBe(true);
    await expect.poll(() => socketClosed).toBe(true);
    expect(errors).toEqual([]);
  });
}
