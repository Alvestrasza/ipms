# Service Accounts

Application target: **0.2.32**. Windows Agent remains **0.2.26** and Linux Agent
remains **0.2.13**. Implementation and verification status are recorded below.

## Administrator workflow

Open **Administration → Service Accounts** in the selected tenant. Create a
named account, choose its supported purpose, and enter its existing username,
optional domain and password. The initial supported purpose is the native
Hyper-V console. IPMS does not create the Windows account or grant Windows
permissions. Other connector credential stores are unchanged.

Assign the saved account explicitly to the intended enrolled Hyper-V hosts.
One account may serve multiple hosts in the same tenant. Separate accounts per
security boundary are recommended. Host re-enrollment never silently inherits
an old identity's assignment. Already-assigned inactive hosts remain visible
for cleanup, but cannot receive a new assignment.

Operators open a VM console using the account assigned to its host; no username
or password form appears in the console window. If configuration is missing,
the window directs administrators to Service Accounts and asks other operators
to contact an administrator. Certificate approval and the warning about an
external VMConnect session remain separate from account configuration.
An already-open unconfigured console can recheck its host assignment without
starting a session or changing the selected transport.

Editing an account can rotate its password; omitting the password preserves
the existing secret, while an explicitly empty password is rejected. A bound
account cannot be deleted. Remove its host assignments explicitly first.
A name-only edit preserves the credentials and active sessions.

## Security and compatibility

The new `service_accounts.manage` permission is limited to tenant and platform
administrators. Existing `agents.manage` permission alone does not authorize
secret management. All list, mutation and assignment endpoints enforce the
selected tenant and permission independently of navigation visibility.

Credentials are encrypted with the protected native-console key and a distinct
tenant/account-bound authenticated context. API responses contain safe account
metadata, never passwords, nonces or ciphertext. The console broker receives
only the additional table-read permission it needs; no broad database grants,
Agent CA-key access or new network exposure are introduced. TCP 9419 policy,
fixed host-local VMConnect and renderer certificate validation remain unchanged.

Tenant selection validates the browser Origin against the server-only
`IPMS_PUBLIC_ORIGIN`, not the internal standalone server URL or client-supplied
forwarding headers. Deployments configure their canonical HTTPS origin; missing
or invalid configuration fails closed. HTTP loopback origins are reserved for
isolated development. Missing or foreign request Origins are rejected. Changing
a tenant also updates an explicit tenant query parameter, keeping the displayed
tenant and account API context consistent.

Existing host-scoped credentials remain readable until an administrator
explicitly replaces or removes their assignment. A central assignment clears
the old per-host encrypted fields. Invalid central references never fall back
to an old secret. A database constraint also prevents an older application
writer from repopulating those legacy fields on a central assignment.

Removing or changing the account/host assignment invalidates affected active
native console sessions through the existing authorization checks. Windows
permissions are not changed by these operations.

## Deployment and rollback

Back up the database, protected configuration and credential key according to
the appliance backup policy. Apply additive migrations and grant the broker
SELECT on `agent_pki_serviceaccount` before restarting the candidate services.
Set `IPMS_PUBLIC_ORIGIN` in the protected Web Console environment and include
that environment in backup and rollback. Verify legitimate and rejected Origins
through the actual TLS front door using invalid tenant values (no selection).
Keep the previous application release and verify health, anonymous-access
denial, actual broker permissions and the existing Agent listener afterward.

Rollback does not restore an old database over newly collected inventory.
Legacy unassigned credentials remain compatible. Central assignments fail
closed in application 0.2.31; native access to those hosts requires returning
to the new application, not removing constraints or restoring stale secrets.
Keep the encryption key while records or backups depend on it.

If a console opens during deployment staging, the helper leaves the current
application running and retains the prepared release, backup, additive migration
and narrow broker grant. It deliberately rejects an automatic rerun over an
existing release directory. After the session is closed, an operator must
revalidate the exact staged commit, version, build artifacts, current release,
backup and absence of active sessions before a separately reviewed cutover using
that staged release. Retain the helper's rollback and post-cutover checks. Do not
delete the staged release, roll back the additive database, or bypass the session
check merely to rerun the helper.

## Acceptance record

Backend verification on Python 3.14.4 completed: 265 tests, with only the
PostgreSQL-specific concurrency case skipped in the SQLite run. Migration
consistency checks passed. A separate disposable PostgreSQL database passed
all 40 Service Accounts and native-console tests, including the real row-lock
race between password rotation and new console creation. Its removal was
verified afterward; the application database was not used for these tests.

Coverage includes admin/operator/tenant and CSRF checks, write-only passwords,
reusable assignments, rotation and withdrawal fencing, legacy preservation,
and the downlevel database constraint. Web formatting (112 files), TypeScript,
the production build and 35 deterministic Node tests passed. All ten browser
regressions passed against the isolated production-style fixture, independently
confirmed with the installed Chrome 152 browser. Account CRUD and host
assignments use real APIs and a synthetic database/key; native display transport
remains synthetic. German page/dialog screenshots were inspected.

The browser checks cover password preservation and rotation, name-only edits,
assignment/deletion protection, tenant switching with an explicit query context,
operator denial, manual configuration recheck and absence of a console password
form. The reverse-proxy Origin mismatch was also reproduced with an invalid
tenant request on the preceding DEV release; explicit public-origin validation
fixes that path without accepting forwarded headers.

The known DEV appliance now runs application 0.2.32 from commit
`1a5ca46a3edf385b8f3eb6d40c0162224ce99b05`. Its independent Linux production
build and additive migration passed. Protected database, configuration and
credential-key backups, plus the previous application release, were retained.

Post-cutover verification confirmed all application/Agent/console services
active, readiness endpoints healthy, anonymous account API access denied, and
the validated database constraint present. Authenticated read-only view checks
confirmed the account and assignable-host API contracts without creating a
real account or assignment. The TLS front-door Origin probes returned 400 for
the legitimate origin with an invalid tenant value, and 403 for foreign and
missing Origins; no tenant cookie was set by those probes.

Checks under the actual running broker identity confirmed the exact additional
table-read grant, denied unrelated database operations and key-file access,
and correct Unix socket permissions. The synthetic audit test transaction was
rolled back and its absence independently confirmed. Global TCP 9419 IPv4/IPv6
firewall allowances remain unchanged; external IPv6 routing was not asserted.
Local browser fixture helpers were stopped and their ports verified closed.
The pre-existing DEV HSTS warning remains unchanged.

Windows Agent 0.2.26 and Linux Agent 0.2.13 are unchanged; no Agent rollout was
performed. Administrator account entry and real-host authentication/display/
input/performance acceptance remain pending. Testing central credential
management does not establish those separate native-console acceptance layers.
