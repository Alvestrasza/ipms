/**
 * File Name: hgs-portal.mjs
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Serve loopback-only HGS browser fixtures; never run Windows or Agent operations.
 */
import http from "node:http";

export const tenantId = "10000000-0000-4000-8000-000000000001";
export const nodeId = "20000000-0000-4000-8000-000000000001";
export const systemId = "30000000-0000-4000-8000-000000000001";
export const deploymentId = "40000000-0000-4000-8000-000000000001";
export function makePlan(status = "ready") {
  const now = Date.now();
  return {
    id: deploymentId,
    tenant_id: tenantId,
    name: "Fixture HGS",
    profile: "vtpm",
    attestation_mode: "host_key",
    status:
      status === "expired"
        ? "ready"
        : status === "resolvable"
          ? "reconciliation_required"
          : status,
    domain_name: "hgs.example.test",
    service_name: "hgs",
    plan_digest: "a".repeat(64),
    config: {
      feature_source: "D:\\Sources\\SxS",
      signing_thumbprint: "b".repeat(40),
      encryption_thumbprint: "c".repeat(40),
      dsrm_secret_ref: "hgs-dsrm",
      join_secret_ref: "",
      allow_reboot: true,
      primary_server: "",
    },
    plan_expires_at: new Date(
      now + (status === "expired" ? -60_000 : 86_400_000),
    ).toISOString(),
    approval_expires_at: null,
    created_at: new Date(now - 60_000).toISOString(),
    updated_at: new Date(now).toISOString(),
    blockers: [],
    nodes: [
      {
        id: nodeId,
        system_id: systemId,
        hostname: "hgs-fixture-01",
        role: "primary",
        status: "ready",
        readiness: { is_server: true, domain_joined: false },
        blockers: [],
        observed_at: new Date(now).toISOString(),
      },
    ],
    steps: [
      "install_role",
      "reboot",
      "create_forest",
      "reboot",
      "initialize",
      "verify",
    ].map((operation, index) => ({
      id: `${nodeId}:${index}`,
      operation,
      node_id: nodeId,
      hostname: "hgs-fixture-01",
      mutates: operation !== "verify",
      requires_reboot: operation === "reboot",
      status: "pending",
    })),
    jobs: [],
    reconciliation:
      status === "resolvable"
        ? {
            job_id: "50000000-0000-4000-8000-000000000001",
            observation_digest: "e".repeat(64),
            can_resolve: true,
            reason: "",
          }
        : null,
  };
}

function session(role) {
  return {
    authenticated: true,
    csrf_token: "hgs-fixture-csrf",
    user: {
      username: `fixture-${role}`,
      display_name: "HGS fixture",
      is_platform_admin: role === "platform",
    },
    platform_permissions: role === "platform" ? ["tenants.manage"] : [],
    tenants:
      role === "platform"
        ? []
        : [
            {
              id: tenantId,
              slug: "hgs-fixture",
              display_name: "HGS fixture",
              purpose: role === "infrastructure" ? "infrastructure" : "hgs",
              role: role === "reader" ? "reader" : "tenant_admin",
              permissions: [
                "inventory.view",
                ...(role !== "infrastructure" ? ["hgs.view"] : []),
                ...(role === "admin" ? ["hgs.manage"] : []),
              ],
            },
          ],
  };
}

export function startHgsFixtureServer() {
  return http
    .createServer((request, response) => {
      const path = new URL(request.url, "http://127.0.0.1").pathname.replace(
        /\/+$/,
        "",
      );
      const cookies = Object.fromEntries(
        (request.headers.cookie ?? "")
          .split(";")
          .map((value) => value.trim().split("=")),
      );
      const role = cookies.hgs_fixture_role ?? "admin";
      const scenario = cookies.hgs_fixture_scenario ?? "ready";
      const json = (status, value) => {
        response.writeHead(status, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        });
        response.end(JSON.stringify(value));
      };
      if (path === "/health") return json(200, { fixture: true });
      if (request.method !== "GET")
        return json(405, { error: { code: "fixture_read_only" } });
      if (path === "/api/v1/auth/session") return json(200, session(role));
      if (
        [
          "/api/v1/windows-server-roles",
          "/api/v1/windows-client-families",
        ].includes(path)
      )
        return json(200, []);
      if (path === "/api/v1/platform/tenants")
        return json(200, {
          results: [
            {
              id: tenantId,
              slug: "hgs-fixture",
              display_name: "Fixture HGS tenant",
              purpose: "hgs",
              status: "active",
              needs_administrator: false,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
          ],
        });
      if (
        path.startsWith("/api/v1/hgs") &&
        (role === "platform" ||
          request.headers["x-ipms-tenant-id"] !== tenantId)
      )
        return json(403, { error: { code: "forbidden" } });
      if (path === "/api/v1/hgs")
        return json(200, {
          tenant_purpose: "hgs",
          can_manage: role === "admin",
          profiles: [
            { id: "vtpm", label: "vTPM" },
            { id: "shielded", label: "Shielded VMs" },
          ],
          systems: [
            {
              id: systemId,
              hostname: "hgs-fixture-01",
              agent_version: "0.2.49",
              eligible: true,
              reason: "",
            },
          ],
          deployments: scenario === "empty" ? [] : [makePlan(scenario)],
          single_appliance_supported: true,
        });
      if (path === `/api/v1/hgs/deployments/${deploymentId}`)
        return json(200, makePlan(scenario));
      return json(404, { error: { code: "fixture_not_found" } });
    })
    .listen(3329, "127.0.0.1", () =>
      process.stdout.write("HGS frontend fixture listening on loopback 3329\n"),
    );
}
