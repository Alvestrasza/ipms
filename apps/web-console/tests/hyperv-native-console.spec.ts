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
  test(`native console ${mode}: prompt-free binding, input and cleanup`, async ({
    page,
    context,
  }) => {
    const messages: string[] = [];
    const creates: unknown[] = [];
    const errors: string[] = [];
    let socketClosed = false;
    let configured = mode !== "configure" && mode !== "operator";
    const png = await page.evaluate(() => {
      const canvas = document.createElement("canvas");
      canvas.width = canvas.height = 64;
      const drawing = canvas.getContext("2d");
      if (!drawing) throw new Error("The fixture browser needs a 2D canvas.");
      drawing.fillStyle = "#ff0000";
      drawing.fillRect(0, 0, 64, 64);
      return canvas.toDataURL("image/png").split(",")[1];
    });
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
            `4.size,1.0,3.640,3.480;3.img,1.0,2.14,1.0,9.image/png,1.0,1.0;4.blob,1.0,${png.length}.${png};3.end,1.0;4.sync,1.1;`,
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
    await expect(popup.getByRole("checkbox")).toHaveCount(0);
    if (mode === "operator" || mode === "configure") {
      await expect(connect).toBeDisabled();
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
        await expect(connect).toBeEnabled();
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
    await expect(connect).toBeEnabled();
    if (mode === "cancel") {
      await popup.getByRole("button", { name: "Cancel", exact: true }).click();
      await expect.poll(() => popup.isClosed()).toBe(true);
      expect(messages).toHaveLength(0);
      expect(creates).toEqual([]);
      return;
    }
    await connect.click();
    await expect(popup.getByRole("alertdialog")).toHaveCount(0);
    await expect
      .poll(() =>
        messages.some(
          (value) =>
            value === JSON.stringify({ type: "trust", sha256: fingerprint }),
        ),
      )
      .toBe(true);
    expect(creates).toEqual([{ transport: "vmconnect" }]);
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
      await expect.poll(() => messages.includes("4.sync,1.1;")).toBe(true);
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
      const bounds = await surface.boundingBox();
      if (!bounds)
        throw new Error("The console surface has no visible bounds.");
      const beforeHover = messages.length;
      await popup.mouse.move(bounds.x + 100, bounds.y + 100);
      await popup.mouse.move(bounds.x + 120, bounds.y + 110);
      await expect
        .poll(() =>
          messages
            .slice(beforeHover)
            .some((value) => /^5\.mouse,\d+\.\d+,\d+\.\d+,1\.0;$/.test(value)),
        )
        .toBe(true);
      await expect(surface).toBeFocused();
      await popup.keyboard.down("Shift");
      await popup.keyboard.up("Shift");
      const keyMessages = messages.filter((value) =>
        value.startsWith("3.key,"),
      );
      expect(keyMessages).toContain("3.key,5.65505,1.1;");
      expect(keyMessages).toContain("3.key,5.65505,1.0;");
      await popup.mouse.down();
      await popup.mouse.up();
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
      // Genuine browser timers, not accelerated time. Keep an idle rendered
      // PNG connected beyond the old disconnect window without typing/clicks.
      await expect
        .poll(
          () =>
            messages.filter((value) => value.startsWith("0.,4.ping,")).length,
          { timeout: 50_000, intervals: [1000] },
        )
        .toBeGreaterThanOrEqual(45);
      await expect(surface).toBeVisible();
      expect(socketClosed).toBe(false);
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
