# Portal Windows Agent Deployment

## Scope

IPMS 0.1.43 provides a development-grade portal bootstrap for Windows Agent
0.1.32. The workflow is tenant-scoped, audited, connection-approved, and
limited to a fixed installation operation. It is not a general-purpose remote
execution feature.

## Prerequisites

- The target resolves only to private addresses reachable from the Appliance.
- Windows remote management is enabled over HTTPS, normally on TCP 5986, or
  over HTTP on TCP 5985 for the explicitly approved fallback.
- HTTPS is preferred. A system-trusted certificate or an administrator-approved
  certificate pin is required before the deployment can be queued.
- The HTTP fallback requires NTLM and fail-closed WS-Man message encryption. It
  is not equivalent to HTTPS because it provides no TLS server identity.
- The supplied account is a local administrator on the target.
- A complete existing `IPMS Agent` must match a previously successful,
  tenant-scoped portal deployment and its active device identity before it can
  be updated. A narrowly identified incomplete portal installation may be
  repaired automatically before retry.
- The Appliance contains the pinned Windows Agent package whose SHA-256 digest
  matches its deployment configuration.

DNS names may resolve to multiple private IPv4 and IPv6 addresses. The
certificate probe preserves resolver order and tries each approved address
until one answers. A failed IPv6 path therefore does not hide a reachable IPv4
WinRM endpoint. The preflight still rejects the entire target when any resolved
address is public, loopback, link-local, multicast, reserved, or unspecified.

## Portal workflow

1. Select **Add System** in the top bar.
2. Select **Windows system**.
3. Enter a display name, DNS name or IP address, preferred HTTPS port,
   administrative username, and password.
4. Select **Check connection**. The preflight request contains no credential.
5. For HTTPS, inspect and confirm the certificate subject, issuer, validity,
   DNS names, serial number, and SHA-256 fingerprint. An untrusted certificate
   is pinned only to the approved deployment.
6. If HTTPS is unavailable and TCP 5985 exposes the Windows remote-management
   endpoint, review and explicitly approve the HTTP fallback warning.
7. Keep the dialog open to see queued, running, succeeded, or failed state.
8. After a successful installation, wait for the Agent to complete one-time
   enrollment and submit its first inventory through the mTLS Gateway. An
   existing managed Agent retains its device identity and reconnects after the
   update service restart.

The password is cleared from browser state after submission. The API never
returns it or the username. The encrypted queue secret is destroyed after one
worker attempt, so a failed deployment requires a new submission.

## Appliance components

- `ipms-agent-deployment-worker.timer` checks the queue every ten seconds.
- `ipms-agent-deployment-worker.service` runs a oneshot worker under its own
  unprivileged identity and systemd sandbox.
- `/srv/ipms/shared/agent-artifacts/` contains the immutable, hash-pinned Agent
  package and is readable only by the runtime group.
- The Control Plane stores only safe deployment state and error codes after the
  transient secret has been removed.

## Security and logging

Do not enable protocol debug logging in production. Remote output and exception
text can contain sensitive details and are intentionally not persisted by IPMS.
Audit events record tenant, actor, target endpoint, approved transport,
certificate trust mode, job identifier, outcome, and a bounded error code only.
The bounded error distinguishes initialization, package validation, endpoint
preflight, remote staging, transfer, extraction, service installation,
enrollment import, and service start without persisting exception messages or
remote protocol output.
Remote staging uses a quoted `ProgramData` child path and well-known Windows
security identifiers so paths with spaces and localized group names behave
consistently. Administrator-token, existing-service, directory-creation, and
ACL failures have separate bounded error codes.

Agent 0.1.32 also uses well-known security identifiers inside the package. It
detects Windows Server Core and skips Start Menu and Control Panel shell
integration while retaining the service and uninstall registration. A failed
new installation is rolled back only when the deployment-owned marker and the
expected service path prove ownership. An older incomplete installation is
eligible for repair only when the expected stopped or running `LocalSystem`
service, fixed file set, valid portal deployment-owner marker, absent enrolled
state, and either no uninstall registration or an exact IPMS registration for
the same install path all match. A stale one-time enrollment document is not
treated as an enrolled identity. The repair stops a running incomplete service
and removes only the known IPMS service, files, and registration before
applying the pinned package. Any other existing installation fails closed and
remains untouched.

A complete Agent from a previously successful deployment follows a separate
identity-preserving update path. IPMS requires the exact service path,
`LocalSystem` identity, registered install location, bounded file set, and
protected `device_uri` to match an active enrollment for the same tenant and
endpoint. Only the hash-pinned program files are replaced. The device key,
certificate, enrollment state, and local configuration remain untouched. The
worker keeps a protected local backup and restores the previous program files
if the updated service cannot be started.

Until the first inventory succeeds, Agent 0.1.32 retries enrollment every ten
seconds. After enrollment, inventory returns to its five-minute interval and
telemetry continues at ten-second intervals.

The long-running Agent Gateway closes obsolete Django database connections
before and after every synchronous PKI, inventory, and telemetry transaction.
This prevents a PostgreSQL idle-session closure from leaving the asynchronous
Gateway process alive but unable to validate later Agent certificates.

The Agent executables statically link the MSVC runtime. Minimal Windows Server
Core targets do not need a separately installed Visual C++ Redistributable.

The worker repeats the approved preflight before decrypting and using the
credential. HTTPS certificate pins must still match. HTTP always uses NTLM with
`encryption="always"`; disabling WS-Man message encryption is not supported.

The current development package is hash-pinned but not Authenticode-signed and
is not an MSI. Code signing, an identity-preserving MSI upgrade, and clean-VM
acceptance remain release gates. The bounded development update, rollback, and
incomplete-install recovery do not replace those release gates.
