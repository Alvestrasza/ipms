# ADR-0005: Portal Windows Agent Deployment

- Status: Accepted for the v0.1.0 development foundation
- Date: 2026-09-01

## Context

IPMS needs a guided portal path that can install the native Windows Agent on a
new server without turning either the Agent Gateway or the Agent into a generic
remote administration channel. The bootstrap account is highly privileged and
must not become a persistent inventory credential.

## Decision

The global **Add System** workflow offers BMC enrollment and Windows Agent
deployment. Windows deployment is available only to platform or tenant
administrators and is scoped to the selected tenant.

The Control Plane validates a private target before it creates a deployment.
HTTPS is preferred. The portal presents the observed certificate identity and
requires an administrator to approve it. A system-untrusted certificate is
pinned by SHA-256 fingerprint to the short-lived approval and deployment. If
HTTPS is unavailable, the portal may offer TCP 5985 only after it verifies the
Windows remote-management endpoint and presents a separate risk warning. The
administrator must explicitly approve either path.

The Control Plane then creates a short-lived one-time Agent enrollment and
stores the bootstrap account, password, and raw enrollment token in one
AES-256-GCM encrypted queue record. Associated data binds that ciphertext to
the tenant and deployment identifier. The connection approval is signed,
tenant-scoped, endpoint-scoped, transport-scoped, and expires after ten minutes.

A dedicated, sandboxed worker consumes each deployment once. It verifies the
approved endpoint again, verifies the pinned Windows package SHA-256 digest,
copies only that package and the one-time enrollment document, and executes a
compiled-in PowerShell installation sequence. HTTPS uses either system trust or
the approved certificate pin. HTTP uses NTLM with mandatory WS-Man message
encryption and cannot be configured for plaintext messages. No request field
can supply a command, script, executable, destination path, or installation
argument.

The package and worker use well-known Windows security identifiers so the
fixed installation is independent of the operating-system language. Shell
integration is omitted automatically on Windows Server Core. Package
extraction, service installation, enrollment import, and service start are
separate bounded phases. A deployment-owned marker permits rollback only for
the directory created by that job.

On a retry, the worker may repair an older incomplete portal installation only
when all fixed evidence matches: expected install path and file set, stopped
`LocalSystem` service with the expected binary path, no Agent state or pending
enrollment, and no uninstall registration. A complete, changed, running, or
otherwise ambiguous installation fails closed and remains untouched.

The worker deletes the encrypted bootstrap credential after the first attempt,
whether the attempt succeeds or fails. Failed jobs also invalidate the unused
enrollment token. Successful jobs leave only the server-side token digest until
the Agent consumes or expires it. Public job responses contain neither account
names, passwords, raw tokens, certificate material, nor remote command output.

The installed Agent retains the existing boundary: it opens the outbound mTLS
connection to TCP 9419 and exposes no inbound management listener. The temporary
Windows remote-management path exists only for initial installation.

## Consequences

- HTTPS remains the preferred and stronger transport because it authenticates
  the server before credentials are used.
- The HTTP fallback lacks TLS server identity and therefore retains NTLM relay
  and endpoint-identity risk despite mandatory message encryption. It requires
  explicit administrator approval and audit evidence for every deployment.
- A certificate or transport approval cannot be replayed for another tenant,
  endpoint, port, or transport and expires after ten minutes.
- A failed attempt requires the administrator to submit the credentials again.
- An interrupted new installation is rolled back when deployment ownership is
  proven; ambiguous existing Agent state is never overwritten.
- The standalone worker can reach only localhost and private address ranges.
- Agent deployment is not customer-release-ready until the package is delivered
  as a signed installer and clean-VM acceptance has passed.
- Future Linux and other system types require separate fixed deployment
  capabilities and cannot reuse an arbitrary shell abstraction.
