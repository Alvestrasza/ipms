# Native Hyper-V Console

Application target: **0.2.33**. Windows Agent minimum: **0.2.26**.
Linux Agent remains **0.2.13**. This document distinguishes implementation,
isolated verification, DEV deployment and real-host acceptance.

## Existing account configuration

Starting with 0.2.32, open **Administration → Service Accounts**, create the
existing console account and explicitly assign it to the enrolled Hyper-V
hosts. The detached console window uses that assignment and no longer asks
for username or password. See [Service Accounts](SERVICE-ACCOUNTS.md) for
rotation, assignment cleanup, legacy compatibility and the admin-only
`service_accounts.manage` permission.

Starting with 0.2.33 this is a tenant-administrator workflow. The IPMS platform
administrator has no console or Service Account access. See
[Tenant administration](TENANT-ADMINISTRATION.md).

The account form accepts username, password and optional domain. It does not
create a Windows account, change
group membership or alter host security policy. Grant the account only the
VMConnect access appropriate for the intended VMs and validate that access on
the customer's host. Do not use a Domain Administrator account by default.

An account belongs to the selected tenant and is explicitly assigned to an
enrolled Hyper-V host, not the guest VM. Credentials are encrypted with
AES-256-GCM and authenticated to the tenant/account identity. The console
reports only whether configuration exists; it
never returns the password or encrypted value. Re-enrollment under a new Agent
identity deliberately does not inherit old credentials. Back up the protected
credential key separately from the database, using the appliance backup policy.

Before connecting, explicitly acknowledge that IPMS cannot reliably discover
an independently opened MMC/VMConnect session. IPMS still permits only one of
its own sessions per VM. Review the observed certificate and approve its exact
SHA-256 fingerprint. A changed, expired or not-yet-valid certificate fails
closed. Native failure never silently switches to the legacy thumbnail path.

The console stays in a detached, resizable browser window with keyboard,
mouse and a secure-attention button. Closing it releases the exclusive lease.
Clipboard, file transfer, drive/printer/audio redirection and recording are
disabled. No guest network connection or guest account is required for the
basic VM console; the dedicated credential authenticates to the Hyper-V host.

## Deployment boundary

- The Windows Agent opens outbound mTLS to the existing Gateway on TCP 9419.
  Keep the established all-networks 9419 policy; do not replace it with a
  management-subnet-only rule.
- The Agent connects only to its own `127.0.0.1:2179`, after validating the full
  VM GUID preconnection packet and current local VM identity. Do not open host
  TCP 2179 to customer networks as part of this deployment.
- The browser connects through the existing HTTPS origin. Nginx forwards only
  the fixed native-console WebSocket route to `127.0.0.1:9420`.
- A separate `ipms-console-broker` identity owns the authorized session and a
  protected Unix socket shared with the Agent Gateway. It has an independently
  scoped database role and access to the native credential key, but not the
  Agent CA signing key.
- A separate `ipms-guacd` renderer listens on `127.0.0.1:4822`. It has no
  database credentials or credential decryption key. Systemd restricts it to
  loopback networking, read-only system files and bounded resources; core dumps
  and persistent renderer output are disabled.

## Pinned adapter and update path

The adapter uses the signed official Apache Guacamole 1.6.0 release, with the
small, reviewable adaptation in `deploy/native-console/`. The browser uses the
official release's JavaScript artifact, including its license and notice; no
unofficial npm repackaging is used. The build verifies the archive digest and
release signer before applying any patch.

The adaptation requires an explicit capability marker, basic VMConnect mode,
loopback target and exactly one certificate pin. It uses FreeRDP external
certificate management, accepting only the approved leaf with a valid time
window, independent of CA and known-host caches. Redirects are rejected.
Wake-on-LAN is compiled out. Small current-libc compatibility changes are
tracked alongside the certificate patch. The reviewed compatibility fixes move
GDI/rendering initialization to PostConnect after FreeRDP negotiation, and
initialize nested-socket state and both mutexes before exposing socket handlers.
Nested-socket cleanup also destroys the initialized locks. Per-session encoding
is capped at two workers; this cap does not measure total host or appliance
load. Host-console TLS is restricted to TLS 1.2 or newer, without weakening the
independent Agent/Gateway mTLS policy. C11 and compiler hardening remain enabled;
retained FreeRDP ABI deprecations remain visible as warnings.

The build requires the exact Ubuntu-provided FreeRDP **3.31.0** API baseline,
checked with `pkg-config --exact-version=3.31.0 freerdp3`. Apache 1.6.0 labels
its FreeRDP 3 support experimental. Therefore, a successful build is not a
claim of general host compatibility or production readiness. Review upstream
security updates and rerun strict pin, redirect and real console acceptance
before upgrading either component. Never replace the adapted renderer with a
stock binary merely because it advertises a fingerprint setting.

`scripts/build-native-console.sh` stages a new build without installing it or
restarting IPMS. `scripts/test-native-console-certificates.py` uses synthetic
loopback TLS peers and dummy credentials. Install only a reviewed, tested build
under `/srv/ipms/dependencies/guacamole-1.6.0-ipms1`, root-owned and not writable
by service accounts, with an exact `SHA256SUMS.runtime` manifest. Apply schema
migrations before `scripts/configure-native-console.sh`; the latter creates
only Appliance service identities, the protected key and broker DB grants.
Install the two service units and exact Nginx route, validate configuration,
then restart the scoped services in the documented DEV change window.

## Verification and rollback

Required gates before live use:

1. Backend permission, tenant, immutable owner, session-cookie and Origin tests;
   replay, concurrent attachment, revocation and bounded protocol tests.
2. Agent optimized build, preconnection/lease/identity tests, and independent
   heartbeat/telemetry regression.
3. Actual adapter TLS tests: approved certificate reaches authentication;
   mismatched self-signed or CA-trusted certificate does not. Expired/future
   certificates, redirects, wildcard/list pins and stale trust are rejected.
4. Detached-window browser tests with the actual vendored runtime; explicit
   certificate approval, input cleanup, keyboard/mouse and failure handling.
5. Known DEV runtime backup, additive migrations, protected key permissions,
   service isolation, loopback listeners and the unchanged 9419 firewall policy.
6. Real authorized host: account configured by the administrator, native screen,
   keyboard/mouse/secure attention, close/reopen, heartbeat and telemetry under
   load. Measure browser-visible delivery and latency; do not promise 15 FPS
   from protocol support alone.

Retain the previous release, database backup, Nginx configuration and protected
environment files before cutover. On failure, stop the broker and renderer,
restore the previous application symlink, environment files and Nginx route,
then restart only affected services. Additive native tables can remain unused;
do not restore an old database over newly collected inventory without a
separate recovery decision. Preserve the native credential key while encrypted
configuration remains in backups. Older Agents and the explicit legacy console
remain supported.

## Acceptance record

As of 2026-09-05, implementation and the following isolated checks passed:

| Layer | Final isolated evidence | Boundary |
| --- | --- | --- |
| Adapted renderer | Final build 11: 97 `make check` passes (75 + 11 + 11), zero failures/errors, with `MALLOC_PERTURB_=165` | Upstream test coverage, not a Hyper-V host session |
| Certificate policy | 9 helper cases and 6 actual loopback TLS cases passed | Synthetic peers and dummy credentials only |
| Backend | 246 tests passed, including 21 native-console tests, on Python 3.14.4 | Permission, protocol and isolated transport checks |
| Windows Agent | Optimized build and 6/6 CTest targets passed | Native guards and worker behavior; no real VM session |
| Browser | 27/27 deterministic Node tests; 6/6 Playwright scenarios; production build with 36/36 page-generation steps | Real vendored rendering of synthetic pixels; native broker/configuration mocked |

In the final renderer TLS fixture, the approved certificate reached 93
synthetic application bytes with TLS 1.3 and also with TLS 1.2. A different
self-signed certificate, a different CA-trusted leaf, an expired certificate
and a future-dated certificate each reached zero application bytes. These
results belong to the final corrected artifact, not just the earlier
intermediate graphics-initialization build.

The browser suite covers detached-window reuse/exclusivity, explicit trust and
cancellation, admin configuration/operator restrictions, authentication-error
handling without fallback, keyboard/mouse/secure attention, resize and cleanup.
The broker observation regression uses an accepted reverse stream to verify
TLS client mode on the actual stream direction. The browser's 200-pixel minimum
viewport matches the broker contract. Local fixture browsers and services were
stopped after verification.

The preceding 0.2.31 DEV deployment was verified at commit
`80667317d526795b3070246a8a48ddd73e70435e`. The Control Plane, web console, Agent
Gateway, broker and renderer are active. The broker and renderer bind only to
loopback, and the existing all-networks TCP 9419 policy is unchanged. The
served browser runtime's SHA-256 matches the pinned file in the release.

Post-deployment checks under the actual broker identity and PostgreSQL role
passed: ten allowed table reads, a zero-row session update and a synthetic
audit insert inside an unconditional rollback. Unrelated writes and issuer
reads were denied; an independent query confirmed no synthetic audit row
persisted. Key access succeeded only for the broker and Control Plane, not the
renderer or Gateway. The broker environment contains no unrelated master keys,
and the Unix socket has the expected owner/group and mode 0660. The anonymous
configuration endpoint returned HTTP 403. The canary configuration state is
`native_supported=true`, `can_manage=true`, `configured=false` for the
administrator: the existing account is deliberately still awaiting entry.

The first cutover attempt stopped before changing the application symlink;
configuration restoration and the previous services were verified. The external
`test` utility rejected supplementary-group file access while actual reading,
execution and Bash predicates succeeded. The deployment script now tests real
renderer execution and manifest reading under the service identity, without
broadening permissions. Its explicit `--resume` mode checks the exact staged
commit, unchanged tracked source and adapter manifest before continuing.
Protected database/configuration backups and the previous release are retained.

The authorized canary host's update completed with `succeeded/updated` and
reported Agent 0.2.26, with fresh heartbeat and telemetry. Other hosts were not
updated automatically. Native mode requires at least Agent 0.2.26.

Real-host native authentication, boot-console
display/input, close/reopen, heartbeat/telemetry under console load,
browser-visible frame rate, input latency and resource consumption are still
pending. The administrator selected portal configuration of an existing host
account; no account secret was supplied to this implementation session and no
Windows account was created. This record does not establish production
readiness or promise 15 genuinely new frames per second.

## References

- [Apache Hyper-V VMConnect configuration](https://guacamole.apache.org/doc/gug/configuring-guacamole.html#preconnection-pdu-hyper-v-vmconnect)
- [Microsoft VMConnect access assignment](https://learn.microsoft.com/en-us/powershell/module/hyper-v/grant-vmconnectaccess?view=windowsserver2025-ps)
- [Microsoft Virtual Machine Connection](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/virtual-machine-connection)
