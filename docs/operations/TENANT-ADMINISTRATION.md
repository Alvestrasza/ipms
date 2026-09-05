# Tenant Administration

Application target: **0.2.33**. Windows Agent remains **0.2.26** and Linux Agent
remains **0.2.13**.

## Platform workflow

1. Sign in with the IPMS platform-administrator account. The portal opens
   **Administration > Tenants**, without infrastructure navigation or a tenant
   selector.
2. Create a tenant with a unique slug and display name. The slug cannot later
   be changed. Creation does not add the platform account to that tenant.
3. Choose initial-administrator setup and enter a **different**, new local
   username and a strong initial password. No existing user is silently reused.
4. Sign out and sign in as the tenant administrator to work with that tenant's
   infrastructure, users and Service Accounts. The platform session never
   impersonates the new user.

The initial-administrator operation is available only before independent
administration has ever been established. It is not a password-reset feature.
An initialized tenant cannot be taken over by disabling its administrators.
Preserve a separately controlled recovery process for lost tenant access.

An upgrade from the historical shared bootstrap model removes the platform
account's tenant membership while preserving its password. Tenants without an
independent administrator show the initial-setup action. No tenant password is
invented, copied, printed, stored in browser persistence or included in audit
details. Existing data remains owned by its original tenant.

## Tenant and Service Account ownership

The tenant administrator opens **Administration > Service Accounts** inside the
selected tenant. Every new account is bound to that tenant, and host assignments
are restricted to it. A platform administrator cannot enter this operational
page, list tenant secrets or assign accounts to customer hosts. There is no
cross-tenant credential move or sharing operation.

Creating a tenant does **not** automatically create its Agent PKI, distribute
gateway trust, install Agents, configure BMCs, or enable future services. Follow
the separately accepted [PKI and Gateway setup](AGENT-PKI-AND-GATEWAY.md).
Automatic hosted multi-tenant gateway provisioning and granular per-service
write entitlements remain future work.

## Suspension

Suspend a tenant to deny its portal access and new operational work while
retaining inventory, identities, Service Accounts and audit history. Queued
operations are reauthorized before dispatch. A denied or cancelled operation
does not automatically resume when the tenant is reactivated.

Pending enrollments and unused enrollment tokens are invalidated and require
a fresh enrollment after reactivation. Active device identities are retained,
but suspension blocks enrollment, renewal, inventory, telemetry and console
traffic. Only authenticated result messages for previously delivered/running
Agent or VM-action jobs may settle their status; they cannot receive further
work or download artifacts. A long suspension may therefore require renewed
device enrollment if a certificate expires meanwhile.

Suspension cannot recall an operation already accepted by a remote system.
Use customer network controls for emergency traffic isolation. TCP 9419 stays
available under the existing deployment policy; application-level tenant
authorization is independent of the listening port.

No hard tenant deletion or automatic customer-data purge is offered.

## Upgrade safety

Back up the database, protected service environments and credential key. Stage
and validate the new application before stopping the old processes. Do not
apply the principal migration while old web, worker, Gateway or broker code is
still serving requests. Revalidate active operations immediately before cutover.

The broker needs only an additional SELECT grant on
`tenancy_platformadministrator` to apply the same authorization boundary. No
credential-key or CA-key permission is expanded.

Retain the migrated identity data on application rollback. Do not recreate old
staff flags, superuser flags or platform memberships. A downlevel release cannot
offer platform administration to the migrated login; use a corrected forward
release. Database restoration is disaster recovery, not the normal fallback.

The exact-version DEV helper is `scripts/deploy-tenancy-dev.sh`. A process-lifetime
exclusive lock prevents overlapping security cutovers. It refuses a
cutover with active consoles or nonterminal discovery, deployment, Agent or VM
jobs. It installs a persistent systemd start condition for the affected services
and timers. `/srv/ipms/shared/tenant-cutover.pending` blocks restarts, including
after reboot, while the security migration is incomplete. A failure before the
migration removes the marker and restarts the previous services. After migration
begins, failure preserves/recreates the marker and leaves execution fenced.

For forward recovery, verify the protected backup, exact candidate source and
version, build artifacts, migration state, broker grant, Nginx configuration and
`/srv/ipms/current` target first. Remove the marker only once a compatible forward
release is ready; never use its removal to restart the old authorization model.
Retain the systemd condition files after success; the absent marker has no normal
runtime effect. A staging failure retains the staged directory for inspection
and requires explicit recovery rather than automatic rerun over that directory.

## Verification status

Pre-deployment verification completed on 2026-09-05:

- Python 3.14 / Django 6.1: all 299 tests passed against an isolated PostgreSQL
  database, including real concurrent provisioning, membership and dispatch
  locking. The disposable test database was destroyed afterward.
- The same 299-test suite passed with SQLite; four PostgreSQL-only cases were
  skipped in that separate run. No missing migrations were detected.
- Web Console production build, TypeScript, Biome, and 38 Node tests passed.
- All 14 browser tests passed against a real isolated API, including platform
  separation, independent administrator setup, tenant denial, DE/EN and dialog
  layout. Server UTC/browser Europe-Berlin timestamp rendering was checked.
- Four inert deployment-recovery tests passed on Windows and Linux, including
  nested query failure propagation and the persistent forward-recovery fence.

DEV cutover and live acceptance remain pending at this source commit. Test
credentials and synthetic browser data were not copied to the DEV database.
Customer acceptance, automatic tenant PKI provisioning and PostgreSQL row-level
security are not claimed by this feature.

A separate pre-existing legacy-thumbnail input ordering defect was reproduced
with equal event timestamps in both the baseline and candidate. This tenant
change does not alter that coalescing algorithm or claim to fix the defect.

See [ADR-0012](../architecture/ADR-0012-PLATFORM-AND-TENANT-ADMINISTRATION.md) for
the authority model, upgrade boundary and remaining product scope.
