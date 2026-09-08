import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import type {
  ManagementJob,
  ManagementSnapshot,
} from "../src/lib/hyperv-management-types";

// Real isolated fixture authentication and SSR inventory; management transport
// is intercepted completely. These tests never submit work to an actual Agent.
const vmName = "Console acceptance VM";
const checkpointId = "40000000-0000-4000-8000-000000000001";
const descendantId = "40000000-0000-4000-8000-000000000002";
const jobId = "50000000-0000-4000-8000-000000000001";

function snapshot(): ManagementSnapshot {
  return {
    schema_version: 1,
    vm_source_id: "32222222-2222-2222-2222-222222222222",
    vm_name: vmName,
    state: "stopped",
    revision: "a".repeat(64),
    settings: {
      name: vmName,
      notes: "Fixture notes",
      configuration_version: "12.0",
      generation: 2,
      processor: {
        count: 4,
        reservation_milli_percent: 0,
        limit_milli_percent: 100000,
        weight: 100,
        compatibility_for_migration: false,
      },
      memory: {
        startup_mib: 4096,
        minimum_mib: 1024,
        maximum_mib: 8192,
        dynamic_enabled: true,
        buffer_percent: 20,
        weight: 5000,
      },
      automatic_start_action: 2,
      automatic_start_delay: null,
      automatic_stop_action: 4,
      checkpoint_policy: 5,
    },
    checkpoints: [
      {
        id: checkpointId,
        parent_id: null,
        name: "Root checkpoint",
        created_at: "2026-01-01T00:00:00Z",
        type: "standard",
        is_current: false,
        can_apply: true,
        can_delete: true,
      },
      {
        id: descendantId,
        parent_id: checkpointId,
        name: "Child checkpoint",
        created_at: "2026-01-02T00:00:00Z",
        type: "standard",
        is_current: true,
        can_apply: true,
        can_delete: true,
      },
    ],
    devices: { network_adapters: [], storage: [] },
    capabilities: {
      inspect: true,
      checkpoint_create: true,
      checkpoint_apply: true,
      checkpoint_delete: true,
      settings_update: true,
    },
    collection_status: {
      settings: "collected",
      checkpoints: "collected",
      devices: "not-reported",
    },
  };
}

async function setup(page: Page, username = "e2e-admin") {
  const posts: {
    url: string;
    document: Record<string, unknown>;
    tenant: string;
    csrf: string;
  }[] = [];
  const state = {
    snapshot: snapshot(),
    active: null as ManagementJob | null,
    latest: null as ManagementJob | null,
    abortMutation: false,
    finish: false,
  };
  await page.route(
    "**/api/v1/hyper-v/virtual-machines/*/management/**",
    async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      if (request.method() === "GET") {
        expect(url.pathname.endsWith("/management/")).toBe(true);
        await route.fulfill({
          json: {
            virtual_machine_id: url.pathname.split("/")[5],
            vm_source_id: state.snapshot.vm_source_id,
            vm_name: state.snapshot.vm_name,
            collection_status: "collected",
            snapshot: state.snapshot,
            observed_at: new Date().toISOString(),
            valid_until: new Date(Date.now() + 60_000).toISOString(),
            fresh: true,
            active_operation: state.active,
            latest_operation: state.latest,
          },
        });
        return;
      }
      expect(request.method()).toBe("POST");
      const document = request.postDataJSON();
      posts.push({
        url: url.pathname,
        document,
        tenant: request.headers()["x-ipms-tenant-id"],
        csrf: request.headers()["x-csrftoken"],
      });
      if (state.abortMutation && url.pathname.endsWith("/operations/")) {
        await route.abort("failed");
        return;
      }
      state.active = {
        id: jobId,
        request_id: document.request_id,
        virtual_machine_id: url.pathname.split("/")[5],
        operation: document.operation ?? "inspect",
        status: "running",
        phase: "observing",
        progress: 25,
        result_code: "provider_running",
        created_at: new Date().toISOString(),
        started_at: new Date().toISOString(),
        completed_at: null,
        can_cancel: false,
      };
      state.latest = state.active;
      await route.fulfill({ status: 202, json: state.active });
    },
  );
  await page.route("**/api/v1/hyper-v/management-jobs/*/", async (route) => {
    expect(route.request().method()).toBe("GET");
    if (state.finish && state.active) {
      state.latest = {
        ...state.active,
        status: "succeeded",
        progress: 100,
        phase: "completed",
        result_code: "operation_completed",
        completed_at: new Date().toISOString(),
      };
      state.active = null;
    }
    await route.fulfill({ json: state.active ?? state.latest });
  });
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en$/);
  await page.goto("/en/virtual/hyper-v");
  return { posts, state };
}

async function open(page: Page, section = "Checkpoints") {
  await page
    .getByRole("button", {
      name: `More virtual machine actions: ${vmName}`,
      exact: true,
    })
    .click();
  await page.getByRole("menuitem", { name: section, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: vmName, exact: true });
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Reload status", exact: true }),
  ).toBeEnabled();
  return dialog;
}

test("management opens centered in the native top layer without a host request and supports read-only users", async ({
  page,
}) => {
  const { posts } = await setup(page, "e2e-external-target");
  const dialog = await open(page, "Settings");
  expect(posts).toEqual([]);
  expect(await dialog.evaluate((element) => element.matches(":modal"))).toBe(
    true,
  );
  const bounds = await dialog.boundingBox();
  const viewport = page.viewportSize();
  expect(bounds).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(
    Math.abs(
      (bounds?.y ?? 0) +
        (bounds?.height ?? 0) / 2 -
        (viewport?.height ?? 0) / 2,
    ),
  ).toBeLessThan(3);
  await expect(dialog.getByLabel("Name", { exact: true })).toBeDisabled();
  await dialog
    .getByRole("button", { name: "Checkpoints", exact: true })
    .click();
  await expect(
    dialog.getByRole("button", { name: "Create checkpoint", exact: true }),
  ).toBeDisabled();
  await dialog
    .getByRole("button", { name: "Move virtual machine", exact: true })
    .click();
  await expect(
    dialog.getByRole("heading", {
      name: "Preflight not yet implemented",
      exact: true,
    }),
  ).toBeVisible();
  expect(posts).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
});

test("checkpoint deletion requires the exact selected subtree acknowledgement and remains visible after reopening", async ({
  page,
}) => {
  const { posts } = await setup(page);
  const dialog = await open(page);
  await dialog
    .getByRole("button", { name: "Root checkpoint", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "Delete checkpoint subtree", exact: true })
    .click();
  const confirmation = dialog.getByRole("region", {
    name: "Delete checkpoint subtree",
    exact: true,
  });
  await expect(
    confirmation.getByText(checkpointId, { exact: true }),
  ).toBeVisible();
  await expect(
    confirmation.getByText(descendantId, { exact: true }),
  ).toBeVisible();
  const remove = confirmation.getByRole("button", {
    name: "Delete checkpoint subtree",
    exact: true,
  });
  await expect(remove).toBeDisabled();
  await confirmation.getByRole("checkbox").check();
  await remove.click();
  await expect(
    dialog.getByText("Running", { exact: false }).first(),
  ).toBeVisible();
  expect(posts).toHaveLength(1);
  expect(posts[0].document).toMatchObject({
    operation: "checkpoint_delete",
    expected_revision: "a".repeat(64),
    parameters: {
      checkpoint_id: checkpointId,
      acknowledged_checkpoint_ids: [checkpointId, descendantId],
    },
  });
  expect(posts[0].tenant).toBeTruthy();
  expect(posts[0].csrf).toBeTruthy();
  await page.keyboard.press("Escape");
  const reopened = await open(page);
  await expect(
    reopened.getByText(/operation continues when this window is closed/),
  ).toBeVisible();
  await expect(
    reopened.getByRole("button", { name: "Create checkpoint", exact: true }),
  ).toBeDisabled();
  expect(posts).toHaveLength(1);
});

test("checkpoint apply requires both names verbatim", async ({ page }) => {
  const { posts } = await setup(page);
  const dialog = await open(page);
  await dialog
    .getByRole("button", { name: "Root checkpoint", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "Apply checkpoint", exact: true })
    .click();
  const confirmation = dialog.getByRole("region", {
    name: "Apply checkpoint",
    exact: true,
  });
  const apply = confirmation.getByRole("button", {
    name: "Apply checkpoint",
    exact: true,
  });
  await confirmation
    .getByLabel("Type the exact virtual machine name")
    .fill(`${vmName} `);
  await confirmation
    .getByLabel("Type the exact checkpoint name")
    .fill("Root checkpoint");
  await expect(apply).toBeDisabled();
  await confirmation
    .getByLabel("Type the exact virtual machine name")
    .fill(vmName);
  await apply.click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0].document).toMatchObject({
    operation: "checkpoint_apply",
    parameters: {
      checkpoint_id: checkpointId,
      confirmation_vm_name: vmName,
      confirmation_checkpoint_name: "Root checkpoint",
    },
  });
});

test("settings navigation shows one unduplicated section and preserves drafts", async ({
  page,
}) => {
  const { posts } = await setup(page);
  const dialog = await open(page, "Settings");
  await expect(
    dialog.getByRole("heading", { name: "General", exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "General", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(dialog.locator("dt").filter({ hasText: /^Name$/ })).toHaveCount(
    0,
  );
  await dialog
    .getByLabel("Notes", { exact: true })
    .fill("Unsaved general draft");
  await dialog.getByRole("button", { name: "Processor", exact: true }).click();
  await expect(
    dialog.getByRole("heading", { name: "Processor", exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Processor", exact: true }),
  ).toHaveAttribute("aria-current", "page");
  await expect(dialog.locator("button[aria-current=page]")).toHaveCount(1);
  await expect(dialog.getByLabel("Name", { exact: true })).toBeHidden();
  await expect(
    dialog.getByLabel("Virtual processors", { exact: true }),
  ).toHaveCount(1);
  await expect(
    dialog.locator("dt").filter({ hasText: /^Virtual processors$/ }),
  ).toHaveCount(0);
  await expect(
    dialog.getByRole("button", { name: "Apply this section", exact: true }),
  ).toHaveCount(1);
  await expect(
    dialog.getByRole("button", { name: "Apply this section", exact: true }),
  ).toBeDisabled();
  await dialog.getByRole("button", { name: "General", exact: true }).click();
  await expect(dialog.getByLabel("Notes", { exact: true })).toHaveValue(
    "Unsaved general draft",
  );
  expect(posts).toEqual([]);
});

test("each settings apply submits only one stopped-VM section", async ({
  page,
}) => {
  const { posts } = await setup(page);
  const dialog = await open(page, "Settings");
  await dialog
    .getByLabel("Notes", { exact: true })
    .fill("Do not submit this other draft");
  await dialog.getByRole("button", { name: "Processor", exact: true }).click();
  const processor = dialog.getByRole("group", {
    name: "Processor",
    exact: true,
  });
  await processor.getByLabel("Virtual processors", { exact: true }).fill("6");
  await dialog
    .getByRole("button", { name: "Apply this section", exact: true })
    .click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0].document).toMatchObject({
    operation: "settings_update",
    parameters: { section: "processor", values: { count: 6 } },
  });
  expect(
    Object.keys((posts[0].document.parameters as { values: object }).values),
  ).toEqual(["count"]);
});

test("settings stay read-only for running VMs and non-editable subareas", async ({
  page,
}) => {
  const { posts, state } = await setup(page);
  state.snapshot.state = "running";
  state.snapshot.capabilities.settings_update = false;
  const dialog = await open(page, "Settings");
  const warning = dialog.getByRole("status", {
    name: "Virtual machine power state",
  });
  await expect(warning).toHaveText("VM is powered on");
  await expect(warning.locator("svg")).toHaveCount(1);
  const host = dialog.locator(".hyperv-management-dialog__host");
  const hostBounds = await host.boundingBox();
  const warningBounds = await warning.boundingBox();
  if (!hostBounds || !warningBounds)
    throw new Error("Missing host-row geometry");
  expect(Math.abs(hostBounds.y - warningBounds.y)).toBeLessThan(8);
  expect(warningBounds.x).toBeGreaterThan(hostBounds.x + hostBounds.width);
  await expect(dialog.getByLabel("Name", { exact: true })).toBeDisabled();
  await dialog.getByRole("button", { name: "Memory", exact: true }).click();
  await expect(
    dialog.getByLabel("Startup memory (MiB)", { exact: true }),
  ).toBeDisabled();
  await expect(
    dialog.getByRole("button", { name: "Apply this section", exact: true }),
  ).toBeDisabled();
  await expect(
    dialog.locator("dt").filter({ hasText: /^Startup memory$/ }),
  ).toHaveCount(0);
  await dialog
    .getByRole("button", { name: "Automatic actions", exact: true })
    .click();
  await expect(
    dialog.getByRole("button", { name: "Apply this section", exact: true }),
  ).toHaveCount(0);
  await expect(dialog.getByText("Read-only", { exact: true })).toBeVisible();
  expect(posts).toEqual([]);
});

test("an observed start locks existing settings drafts even with an incorrect capability flag", async ({
  page,
}) => {
  const { posts, state } = await setup(page);
  const dialog = await open(page, "Settings");
  await dialog
    .getByLabel("Notes", { exact: true })
    .fill("Retained but not submitted while running");
  const apply = dialog.getByRole("button", {
    name: "Apply this section",
    exact: true,
  });
  await expect(apply).toBeEnabled();
  state.snapshot.state = "running";
  // Deliberately leave settings_update=true: state must independently block writes.
  await dialog
    .getByRole("button", { name: "Reload status", exact: true })
    .click();
  await expect(
    dialog.getByRole("status", { name: "Virtual machine power state" }),
  ).toBeVisible();
  await expect(dialog.getByLabel("Notes", { exact: true })).toBeDisabled();
  await expect(apply).toBeDisabled();
  await dialog
    .locator("form:visible")
    .evaluate((element) => (element as HTMLFormElement).requestSubmit());
  expect(posts).toEqual([]);
  await dialog.getByRole("button", { name: "Processor", exact: true }).click();
  await expect(
    dialog.getByLabel("Virtual processors", { exact: true }),
  ).toBeDisabled();
  state.snapshot.state = "stopped";
  await dialog
    .getByRole("button", { name: "Reload status", exact: true })
    .click();
  await expect(
    dialog.getByRole("status", { name: "Virtual machine power state" }),
  ).toHaveCount(0);
  await expect(
    dialog.getByLabel("Virtual processors", { exact: true }),
  ).toBeEnabled();
  expect(posts).toEqual([]);
});

test("German settings subarea is explicit and missing values remain unknown", async ({
  page,
}) => {
  const { posts, state } = await setup(page);
  state.snapshot.settings.memory.startup_mib = null;
  await page.goto("/de/virtual/hyper-v");
  await page
    .getByRole("button", {
      name: `Weitere VM-Aktionen: ${vmName}`,
      exact: true,
    })
    .click();
  await page
    .getByRole("menuitem", { name: "Einstellungen", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: vmName, exact: true });
  const memory = dialog.getByRole("button", {
    name: "Arbeitsspeicher",
    exact: true,
  });
  await memory.focus();
  await page.keyboard.press("Enter");
  await expect(memory).toHaveAttribute("aria-current", "page");
  await expect(
    dialog.getByRole("heading", { name: "Arbeitsspeicher", exact: true }),
  ).toBeVisible();
  await expect(
    dialog.getByLabel("Startarbeitsspeicher (MiB)", { exact: true }),
  ).toHaveValue("");
  await expect(
    dialog.getByLabel("Startarbeitsspeicher (MiB)", { exact: true }),
  ).toBeDisabled();
  await expect(
    dialog.getByRole("button", {
      name: "Diesen Bereich anwenden",
      exact: true,
    }),
  ).toBeDisabled();
  expect(posts).toEqual([]);
});

test("uncertain POST is never replayed or unlocked by a GET; an explicit successful inspect is required", async ({
  page,
}) => {
  const { posts, state } = await setup(page);
  state.abortMutation = true;
  const dialog = await open(page);
  await dialog
    .getByRole("button", { name: "Create checkpoint", exact: true })
    .click();
  await expect(
    dialog.getByText(/request outcome could not be confirmed/),
  ).toBeVisible();
  await dialog
    .getByRole("button", { name: "Reload status", exact: true })
    .click();
  await expect(
    dialog.getByRole("button", { name: "Reload status", exact: true }),
  ).toBeEnabled();
  await expect(
    dialog.getByRole("button", { name: "Create checkpoint", exact: true }),
  ).toBeDisabled();
  expect(posts).toHaveLength(1);
  state.abortMutation = false;
  state.finish = true;
  await dialog
    .getByRole("button", { name: "Refresh from host", exact: true })
    .click();
  await expect(
    dialog.getByRole("button", { name: "Create checkpoint", exact: true }),
  ).toBeEnabled();
  expect(posts).toHaveLength(2);
  expect(posts[1].url.endsWith("/refresh/")).toBe(true);
  expect(Object.keys(posts[1].document)).toEqual(["request_id"]);
});

test("Shift+F10 navigation and German labels expose unqualified production policy without fallback", async ({
  page,
}) => {
  const { posts, state } = await setup(page);
  state.snapshot.settings.checkpoint_policy = 4;
  state.snapshot.capabilities.checkpoint_create = false;
  await page.goto("/de/virtual/hyper-v");
  const row = page
    .getByRole("row")
    .filter({ has: page.getByRole("cell", { name: vmName, exact: true }) });
  await row.focus();
  await page.keyboard.press("Shift+F10");
  await page.getByRole("menuitem", { name: "Prüfpunkte", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: vmName, exact: true });
  await expect(
    dialog.getByText(/Erstellen von Produktionsprüfpunkten ist/),
  ).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Prüfpunkt erstellen", exact: true }),
  ).toBeDisabled();
  expect(posts).toEqual([]);
});

for (const variant of [
  { name: "dark-desktop", theme: "dark", width: 1440, height: 1000 },
  { name: "light-desktop", theme: "light", width: 1440, height: 1000 },
  { name: "dark-390px", theme: "dark", width: 390, height: 844 },
  { name: "light-390px", theme: "light", width: 390, height: 844 },
] as const) {
  test(`management visual and accessibility: ${variant.name}`, async ({
    page,
  }) => {
    await page.setViewportSize({
      width: variant.width,
      height: variant.height,
    });
    await page.emulateMedia({
      colorScheme: variant.theme,
      reducedMotion: "reduce",
    });
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const { posts, state } = await setup(page);
    const theme = await page.locator("html").getAttribute("data-theme");
    if (theme !== variant.theme) {
      await page
        .getByRole("button", {
          name: `Switch to ${variant.theme} theme`,
          exact: true,
        })
        .click();
    }
    await expect(page.locator("html")).toHaveAttribute(
      "data-theme",
      variant.theme,
    );
    const directory = resolve(
      process.cwd(),
      "..",
      "..",
      "build",
      "hyperv-settings-0237-e2e",
    );
    await mkdir(directory, { recursive: true });
    const backgroundLayout = await page.evaluate(() => ({
      viewport: window.innerWidth,
      pageOverflow:
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
      oversized: [...document.querySelectorAll<HTMLElement>("body [class]")]
        .filter(
          (element) =>
            element.getBoundingClientRect().width > window.innerWidth + 1,
        )
        .slice(0, 12)
        .map((element) => ({
          className: element.className,
          width: element.getBoundingClientRect().width,
          scrollWidth: element.scrollWidth,
          overflowX: getComputedStyle(element).overflowX,
          minWidth: getComputedStyle(element).minWidth,
        })),
    }));
    await test.info().attach(`background-layout-${variant.name}`, {
      body: JSON.stringify(backgroundLayout, null, 2),
      contentType: "application/json",
    });
    await writeFile(
      resolve(directory, `background-layout-${variant.name}.json`),
      JSON.stringify(backgroundLayout, null, 2),
    );
    const dialog = await open(page, "Settings");

    async function verifyAndCapture(section: string) {
      await page.screenshot({
        path: resolve(directory, `${section}-${variant.name}.png`),
        animations: "disabled",
      });
      const geometry = await dialog.evaluate((element) => {
        const box = element.getBoundingClientRect();
        const body = element.querySelector<HTMLElement>(
          ".hyperv-management-dialog__body",
        );
        return {
          modal: element.matches(":modal"),
          left: box.left,
          right: box.right,
          width: window.innerWidth,
          dialogOverflow: element.scrollWidth - element.clientWidth,
          bodyOverflow: body ? body.scrollWidth - body.clientWidth : 0,
          pageOverflow:
            document.documentElement.scrollWidth -
            document.documentElement.clientWidth,
          focusInside: element.contains(document.activeElement),
        };
      });
      expect.soft(geometry.modal, `${section}: native top layer`).toBe(true);
      expect
        .soft(geometry.left, `${section}: dialog left edge`)
        .toBeGreaterThanOrEqual(0);
      expect
        .soft(geometry.right, `${section}: dialog right edge`)
        .toBeLessThanOrEqual(geometry.width);
      expect
        .soft(geometry.dialogOverflow, `${section}: dialog horizontal overflow`)
        .toBeLessThanOrEqual(1);
      expect
        .soft(geometry.bodyOverflow, `${section}: content horizontal overflow`)
        .toBeLessThanOrEqual(1);
      expect
        .soft(geometry.pageOverflow, `${section}: page horizontal overflow`)
        .toBeLessThanOrEqual(1);
      expect
        .soft(
          geometry.focusInside,
          `${section}: keyboard focus remains in modal`,
        )
        .toBe(true);
      const accessibility = await new AxeBuilder({ page })
        .include("dialog.hyperv-management-dialog")
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze();
      expect
        .soft(accessibility.violations, `${section}: WCAG A/AA findings`)
        .toEqual([]);
    }

    await verifyAndCapture("settings");
    for (const [value, label] of [
      ["processor", "Processor"],
      ["memory", "Memory"],
      ["automatic", "Automatic actions"],
    ]) {
      if (variant.width < 650)
        await dialog
          .getByLabel("Current section", { exact: true })
          .selectOption(`settings:${value}`);
      else
        await dialog.getByRole("button", { name: label, exact: true }).click();
      await expect(
        dialog.getByRole("heading", { name: label, exact: true }),
      ).toBeVisible();
      if (value === "memory") {
        const body = dialog.locator(".hyperv-management-dialog__body");
        await body.evaluate((element) => {
          element.scrollTop = element.scrollHeight;
        });
        const heading = await dialog
          .getByRole("heading", { name: label, exact: true })
          .boundingBox();
        const viewport = await body.boundingBox();
        expect(heading).not.toBeNull();
        expect(viewport).not.toBeNull();
        if (!heading || !viewport)
          throw new Error("Missing visible settings geometry");
        expect(heading.y).toBeGreaterThanOrEqual(viewport.y);
        await body.evaluate((element) => {
          element.scrollTop = 0;
        });
      }
      await verifyAndCapture(value);
    }
    state.snapshot.state = "running";
    await dialog
      .getByRole("button", { name: "Reload status", exact: true })
      .click();
    await expect(
      dialog.getByRole("status", { name: "Virtual machine power state" }),
    ).toHaveText("VM is powered on");
    await verifyAndCapture("powered-on");
    state.snapshot.state = "stopped";
    await dialog
      .getByRole("button", { name: "Reload status", exact: true })
      .click();
    await expect(
      dialog.getByRole("status", { name: "Virtual machine power state" }),
    ).toHaveCount(0);
    if (variant.width < 650)
      await dialog
        .getByLabel("Current section", { exact: true })
        .selectOption("checkpoints");
    else
      await dialog
        .getByRole("button", { name: "Checkpoints", exact: true })
        .click();
    await dialog
      .getByRole("button", { name: "Root checkpoint", exact: true })
      .click();
    await verifyAndCapture("checkpoints");
    await dialog
      .getByRole("button", { name: "Delete checkpoint subtree", exact: true })
      .click();
    await verifyAndCapture("delete-confirmation");
    const confirmation = dialog.getByRole("region", {
      name: "Delete checkpoint subtree",
      exact: true,
    });
    await expect(
      confirmation.getByRole("button", {
        name: "Delete checkpoint subtree",
        exact: true,
      }),
    ).toBeDisabled();
    await confirmation.getByRole("checkbox").scrollIntoViewIfNeeded();
    await verifyAndCapture("delete-acknowledgement");
    await page.keyboard.press("Tab");
    expect(
      await dialog.evaluate((element) =>
        element.contains(document.activeElement),
      ),
    ).toBe(true);
    expect(errors).toEqual([]);
    expect(posts).toEqual([]);
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
  });
}
