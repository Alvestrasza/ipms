import assert from "node:assert/strict";
import test from "node:test";
import {
  hasPermission,
  hasPlatformPermission,
  portalScope,
} from "../src/lib/auth-types.ts";
import { selectedTenant } from "../src/lib/tenant-selection.ts";

const tenant = {
  id: "tenant-a",
  role: "tenant_admin",
  permissions: ["inventory.view"],
};
const session = {
  authenticated: true,
  user: { is_platform_admin: false },
  platform_permissions: [],
  tenants: [tenant],
};
test("platform scope never becomes tenant scope even with stale tenant data", () => {
  const platform = {
    ...session,
    user: { is_platform_admin: true },
    platform_permissions: ["tenants.manage"],
  };
  assert.equal(portalScope(platform), "platform");
  assert.equal(
    selectedTenant(platform, { get: () => ({ value: "tenant-a" }) }),
    null,
  );
  assert.equal(hasPlatformPermission(platform, "tenants.manage"), true);
  assert.equal(hasPlatformPermission(session, "tenants.manage"), false);
});
test("anonymous and authenticated no-tenant states stay distinct", () => {
  assert.equal(portalScope(null), "anonymous");
  assert.equal(portalScope({ authenticated: false }), "anonymous");
  assert.equal(portalScope({ ...session, tenants: [] }), "no-tenant");
  assert.equal(portalScope(session), "tenant");
});
test("role names cannot grant implicit tenant or platform permissions", () => {
  assert.equal(
    hasPermission({ role: "platform_admin" }, "agents.manage"),
    false,
  );
  assert.equal(hasPermission({ role: "tenant_admin" }, "agents.manage"), false);
  assert.equal(hasPermission(tenant, "inventory.view"), true);
  assert.equal(
    hasPlatformPermission(
      { ...session, user: { is_platform_admin: true } },
      "tenants.manage",
    ),
    false,
  );
});
