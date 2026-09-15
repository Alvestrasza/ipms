/**
 * File Name: gpo-approval.spec.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Exercise real scoped Portal approval in isolated fixtures without an Agent or AD.
 */
import { randomUUID } from "node:crypto";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";
import type {
  DomainSecurityCatalog,
  DomainSecuritySettings,
  GpoImportJob,
} from "../src/lib/domain-security-types";
import type {
  GpoApprovalPolicy,
  GpoDomainAuthorization,
} from "../src/lib/gpo-approval-types";

const domainsApi = "/api/v1/security/domain-settings/";
const policyApi = "/api/v1/security/gpo-approval-policy/";
const administration = "/en/administration/security/domains";
type Headers = Record<string, string>;

async function login(page: Page, username = "e2e-admin") {
  await page.goto("/en/login");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill("test-only-password");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page).toHaveURL(/\/en\/?$/);
  const session = await (
    await page.request.get("/api/v1/auth/session/")
  ).json();
  const tenant = session.tenants.find(
    (entry: { slug: string }) => entry.slug === "console-e2e",
  );
  return {
    session,
    headers: {
      "X-CSRFToken": session.csrf_token,
      "X-IPMS-Tenant-ID": tenant.id,
    } as Headers,
  };
}

async function domain(page: Page, headers: Headers, name: string) {
  const response = await page.request.get(domainsApi, { headers });
  expect(response.status()).toBe(200);
  const catalog: DomainSecurityCatalog = await response.json();
  const settings = catalog.results.find((item) => item.domain_name === name);
  if (!settings) throw new Error(`Missing isolated domain fixture: ${name}`);
  return { catalog, settings };
}

async function setPolicy(page: Page, headers: Headers, fourEyes: boolean) {
  const read = await page.request.get(policyApi, { headers });
  expect(read.status()).toBe(200);
  const policy: GpoApprovalPolicy = await read.json();
  if (policy.four_eyes_required === fourEyes) return policy;
  const response = await page.request.put(policyApi, {
    headers,
    data: { expected_revision: policy.revision, four_eyes_required: fourEyes },
  });
  expect(response.status()).toBe(200);
  return (await response.json()) as GpoApprovalPolicy;
}

async function authorization(
  page: Page,
  headers: Headers,
  settings: DomainSecuritySettings,
) {
  const endpoint = `${domainsApi}${settings.id}/gpo-authorization/`;
  const response = await page.request.get(endpoint, { headers });
  expect(response.status()).toBe(200);
  return { endpoint, data: (await response.json()) as GpoDomainAuthorization };
}

async function grant(
  page: Page,
  headers: Headers,
  settings: DomainSecuritySettings,
  usernames: string[],
) {
  const { endpoint, data } = await authorization(page, headers, settings);
  const grants = usernames.map((username) => {
    const member = data.members.find((item) => item.username === username);
    if (!member)
      throw new Error(`Missing eligible fixture member: ${username}`);
    return { user_id: member.user_id, tiers: ["0"] };
  });
  const saved = await page.request.put(endpoint, {
    headers,
    data: { expected_revision: data.revision, grants },
  });
  expect(saved.status()).toBe(200);
}

async function requestImport(
  page: Page,
  headers: Headers,
  settings: DomainSecuritySettings,
  catalog: DomainSecurityCatalog,
) {
  const endpoint = `${domainsApi}${settings.id}/gpo-imports/`;
  const available = await (
    await page.request.get(endpoint, { headers })
  ).json();
  const executor = available.executors.find(
    (item: { eligible: boolean; domain_name: string }) =>
      item.eligible && item.domain_name === settings.domain_name,
  );
  expect(executor).toBeTruthy();
  const baseline = catalog.baseline_options.find(
    (item) => item.id === "microsoft-windows-server-2025",
  );
  const component = baseline?.components.find((item) => item.available);
  if (!baseline || !component)
    throw new Error("A verified isolated GPO package is required.");
  const response = await page.request.post(endpoint, {
    headers,
    data: {
      revision: settings.revision,
      system_id: executor.system_id,
      baseline_id: baseline.id,
      backup_id: component.id,
      tier: "0",
      target: "ALL",
      version: "1.0.0",
      idempotency_key: randomUUID(),
    },
  });
  expect([200, 201, 202]).toContain(response.status());
  const job: GpoImportJob = await response.json();
  expect(job.approval_mode).toBe("portal");
  expect(job.status).toBe("awaiting_approval");
  expect(job.approved_at).toBeNull();
  return job;
}

test("explicit domain scopes permit a single administrator to review and approve his own import", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings, catalog } = await domain(
    page,
    headers,
    "gpo-self.example.invalid",
  );
  const initial = await authorization(page, headers, settings);
  expect(initial.data.grants).toEqual([]);
  await setPolicy(page, headers, false);
  await page.goto(administration);
  const policyPanel = page.getByRole("region", {
    name: "GPO approval policy",
    exact: true,
  });
  await expect(
    policyPanel.getByRole("checkbox", {
      name: "Require a second administrator",
      exact: true,
    }),
  ).not.toBeChecked();
  await expect(policyPanel).toContainText(
    "an authorized tenant administrator may request and approve his own import",
  );
  await page
    .getByRole("button")
    .filter({ hasText: settings.domain_name })
    .click();
  const scopes = page.getByRole("region", {
    name: "GPO authorization by domain and Tier",
    exact: true,
  });
  await expect(scopes.getByRole("checkbox", { checked: true })).toHaveCount(0);
  await scopes
    .getByRole("checkbox", { name: "Tier 0: e2e-admin", exact: true })
    .check();
  await expect(
    page.getByRole("button", { name: "Add domain", exact: true }),
  ).toBeDisabled();
  const saved = page.waitForResponse(
    (response) =>
      response.url().endsWith(initial.endpoint) &&
      response.request().method() === "PUT",
  );
  await scopes
    .getByRole("button", { name: "Save GPO authorizations", exact: true })
    .click();
  const receipt = await saved;
  expect(receipt.status()).toBe(200);
  expect(receipt.request().postDataJSON()).toEqual({
    expected_revision: initial.data.revision,
    grants: [
      {
        user_id: initial.data.members.find(
          (member) => member.username === "e2e-admin",
        )?.user_id,
        tiers: ["0"],
      },
    ],
  });
  await expect(scopes.getByRole("checkbox", { checked: true })).toHaveCount(1);
  const unchanged = await (
    await page.request.get(`${domainsApi}${settings.id}/`, { headers })
  ).json();
  expect(unchanged.revision).toBe(settings.revision);
  expect(unchanged.tier_ous).toEqual(settings.tier_ous);
  const job = await requestImport(page, headers, settings, catalog);
  await page.goto(`/en/logs/baselines?job=${job.id}`);
  const review = page.getByRole("region", {
    name: "Review and approve GPO import",
    exact: true,
  });
  await expect(review).toContainText(
    "It does not link, activate or apply the baseline.",
  );
  await expect(
    page.getByRole("heading", { name: job.pilot_display_name, exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Copy approval document", exact: true }),
  ).toHaveCount(0);
  const detail = await (
    await page.request.get(`/api/v1/logs/gpo-imports/${job.id}/`, { headers })
  ).json();
  expect(detail.can_approve).toBe(true);
  expect(detail.requested_by_name).toBe("e2e-admin");
  await review
    .locator("summary")
    .filter({ hasText: "Exact GPO settings report (XML)" })
    .click();
  const xml = review.locator("pre").first();
  await expect(xml).toHaveText(detail.review.report_xml, {
    useInnerText: false,
  });
  // HTML parsing normalizes CRLF in server-rendered text nodes to LF.
  expect(await xml.textContent()).toBe(
    detail.review.report_xml.replace(/\r\n?/g, "\n"),
  );
  await expect(xml.locator("*")).toHaveCount(0);
  await review
    .locator("summary")
    .filter({ hasText: "Verified import files" })
    .click();
  await expect(review).toContainText(detail.review.files[0].sha256);
  const approvalResponse = page.waitForResponse((response) =>
    response.url().endsWith(`/security/gpo-imports/${job.id}/approve/`),
  );
  await page
    .getByRole("button", { name: "Approve this GPO action", exact: true })
    .click();
  const approved = await approvalResponse;
  expect(approved.status()).toBe(200);
  expect(approved.request().postDataJSON()).toEqual({
    input_digest: detail.input_digest,
    policy_revision: detail.policy_revision,
  });
  expect(approved.request().headers()["x-ipms-tenant-id"]).toBe(
    headers["X-IPMS-Tenant-ID"],
  );
  // Django re-masks this value for each session projection; the real POST
  // validates it against the cookie, so its rendered token need not be equal.
  expect(approved.request().headers()["x-csrftoken"]).toMatch(
    /^[a-zA-Z0-9]{64}$/,
  );
  const actual = await approved.json();
  expect(actual.status).toBe("queued");
  expect(actual.approved_by_name).toBe("e2e-admin");
  expect(actual.approved_at).toBeTruthy();
  expect(actual.gpo_guid).toBeNull();
  await expect(
    page.getByRole("button", {
      name: "Approve this GPO action",
      exact: true,
    }),
  ).toHaveCount(0);
});

test("four eyes blocks the requester and permits a separately scoped approver without administration rights", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings, catalog } = await domain(
    page,
    headers,
    "gpo-four-eyes.example.invalid",
  );
  await grant(page, headers, settings, ["e2e-admin", "e2e-gpo-approver"]);
  await page.goto(administration);
  const policy = page.getByRole("region", {
    name: "GPO approval policy",
    exact: true,
  });
  await policy
    .getByRole("checkbox", {
      name: "Require a second administrator",
      exact: true,
    })
    .check();
  const changed = page.waitForResponse(
    (response) =>
      response.url().endsWith(policyApi) &&
      response.request().method() === "PUT",
  );
  await policy
    .getByRole("button", { name: "Save approval policy", exact: true })
    .click();
  expect((await changed).status()).toBe(200);
  await expect(policy).toContainText(
    "There is no exception for a single administrator.",
  );
  const job = await requestImport(page, headers, settings, catalog);
  await page.goto(`/en/logs/baselines?job=${job.id}`);
  await expect(
    page.getByRole("button", {
      name: "Approve this GPO action",
      exact: true,
    }),
  ).toBeDisabled();
  await expect(
    page.getByText(
      "A different authorized administrator must approve this request.",
      { exact: true },
    ),
  ).toBeVisible();
  const denied = await page.request.post(
    `/api/v1/security/gpo-imports/${job.id}/approve/`,
    {
      headers,
      data: {
        input_digest: job.input_digest,
        policy_revision: job.policy_revision,
      },
    },
  );
  expect(denied.status()).toBe(403);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  const reviewer = await login(page, "e2e-gpo-approver");
  expect(
    (await page.request.get(policyApi, { headers: reviewer.headers })).status(),
  ).toBe(403);
  await page.goto(`/en/logs/baselines?job=${job.id}`);
  await expect(
    page.getByRole("button", {
      name: "Approve this GPO action",
      exact: true,
    }),
  ).toBeEnabled();
  await expect(
    page.getByRole("link", { name: "Domains & tiers", exact: true }),
  ).toHaveCount(0);
  const approved = page.waitForResponse((response) =>
    response.url().endsWith(`/security/gpo-imports/${job.id}/approve/`),
  );
  await page
    .getByRole("button", { name: "Approve this GPO action", exact: true })
    .click();
  const response = await approved;
  expect(response.status()).toBe(200);
  const receipt = await response.json();
  expect(receipt.status).toBe("queued");
  expect(receipt.approved_by_name).toBe("e2e-gpo-approver");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  const admin = await login(page);
  await setPolicy(page, admin.headers, false);
});

test("authorization conflicts retain the draft and cannot overwrite a concurrent Tier grant", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings } = await domain(
    page,
    headers,
    "gpo-errors.example.invalid",
  );
  const original = await authorization(page, headers, settings);
  await page.goto(administration);
  await page
    .getByRole("button")
    .filter({ hasText: settings.domain_name })
    .click();
  const scopes = page.getByRole("region", {
    name: "GPO authorization by domain and Tier",
    exact: true,
  });
  await scopes
    .getByRole("checkbox", { name: "Tier 0: e2e-admin", exact: true })
    .check();
  const approver = original.data.members.find(
    (member) => member.username === "e2e-gpo-approver",
  );
  const concurrent = await page.request.put(original.endpoint, {
    headers,
    data: {
      expected_revision: original.data.revision,
      grants: [{ user_id: approver?.user_id, tiers: ["1"] }],
    },
  });
  expect(concurrent.status()).toBe(200);
  const rejected = page.waitForResponse(
    (response) =>
      response.url().endsWith(original.endpoint) &&
      response.request().method() === "PUT",
  );
  await scopes
    .getByRole("button", { name: "Save GPO authorizations", exact: true })
    .click();
  expect((await rejected).status()).toBe(409);
  await expect(scopes.getByRole("alert")).toContainText(
    "Your draft is retained",
  );
  await expect(
    scopes.getByRole("checkbox", { name: "Tier 0: e2e-admin", exact: true }),
  ).toBeChecked();
  await expect(
    scopes.getByRole("button", {
      name: "Save GPO authorizations",
      exact: true,
    }),
  ).toBeDisabled();
  expect((await authorization(page, headers, settings)).data.grants).toEqual([
    { user_id: approver?.user_id, tiers: ["1"] },
  ]);
});

test("revoked authorization clears an old import preview and never retries approval", async ({
  page,
}) => {
  const { headers } = await login(page);
  const { settings, catalog } = await domain(
    page,
    headers,
    "gpo-errors.example.invalid",
  );
  await setPolicy(page, headers, false);
  await grant(page, headers, settings, ["e2e-admin"]);
  const job = await requestImport(page, headers, settings, catalog);
  await page.goto(`/en/logs/baselines?job=${job.id}`);
  await expect(
    page.getByRole("button", {
      name: "Approve this GPO action",
      exact: true,
    }),
  ).toBeEnabled();
  await grant(page, headers, settings, []);
  const attempts: string[] = [];
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith(`/security/gpo-imports/${job.id}/approve/`)
    )
      attempts.push(request.url());
  });
  const rejected = page.waitForResponse((response) =>
    response.url().endsWith(`/security/gpo-imports/${job.id}/approve/`),
  );
  await page
    .getByRole("button", { name: "Approve this GPO action", exact: true })
    .click();
  expect([400, 403, 409]).toContain((await rejected).status());
  await expect(page.getByRole("main").getByRole("alert")).toContainText(
    "previous preview has been cleared",
  );
  await expect(
    page.getByRole("heading", { name: job.pilot_display_name, exact: true }),
  ).toHaveCount(0);
  await expect(page.locator("pre")).toHaveCount(0);
  await expect(
    page.getByRole("button", {
      name: "Approve this GPO action",
      exact: true,
    }),
  ).toHaveCount(0);
  expect(attempts).toHaveLength(1);
});

test("tenant switches discard the previous domain authorization and mobile controls stay accessible", async ({
  page,
}) => {
  const { headers, session } = await login(page);
  const { settings } = await domain(page, headers, "gpo-self.example.invalid");
  await page.goto(administration);
  await page
    .getByRole("button")
    .filter({ hasText: settings.domain_name })
    .click();
  const scopes = page.getByRole("region", {
    name: "GPO authorization by domain and Tier",
    exact: true,
  });
  await expect(
    scopes.getByRole("checkbox", { name: "Tier 0: e2e-admin", exact: true }),
  ).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: test.info().outputPath("gpo-approval-scopes-mobile.png"),
    fullPage: true,
  });
  const other = session.tenants.find(
    (entry: { slug: string }) => entry.slug === "service-accounts-e2e",
  );
  const switched = page.waitForResponse((response) =>
    response.url().endsWith("/api/tenant-selection"),
  );
  await page
    .getByRole("combobox", { name: "Active tenant", exact: true })
    .selectOption(other.id);
  expect((await switched).status()).toBe(204);
  await expect(
    page.getByRole("button").filter({ hasText: settings.domain_name }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("checkbox", {
      name: "Tier 0: e2e-gpo-approver",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    page
      .getByRole("region", { name: "GPO approval policy", exact: true })
      .getByRole("checkbox", {
        name: "Require a second administrator",
        exact: true,
      }),
  ).not.toBeChecked();
  expect(
    (
      await page.request.get(`${domainsApi}${settings.id}/gpo-authorization/`, {
        headers: { ...headers, "X-IPMS-Tenant-ID": other.id },
      })
    ).status(),
  ).toBe(404);
});
