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

The Control Plane validates a private target and a trusted HTTPS server
certificate before it creates a deployment. It then creates a short-lived
one-time Agent enrollment and stores the bootstrap account, password, and raw
enrollment token in one AES-256-GCM encrypted queue record. Associated data
binds that ciphertext to the tenant and deployment identifier.

A dedicated, sandboxed worker consumes each deployment once. It verifies the
target certificate again, verifies the pinned Windows package SHA-256 digest,
copies only that package and the one-time enrollment document, and executes a
compiled-in PowerShell installation sequence. No request field can supply a
command, script, executable, destination path, or installation argument.

The worker deletes the encrypted bootstrap credential after the first attempt,
whether the attempt succeeds or fails. Failed jobs also invalidate the unused
enrollment token. Successful jobs leave only the server-side token digest until
the Agent consumes or expires it. Public job responses contain neither account
names, passwords, raw tokens, certificate material, nor remote command output.

The installed Agent retains the existing boundary: it opens the outbound mTLS
connection to TCP 9419 and exposes no inbound management listener. The temporary
Windows remote-management path exists only for initial installation.

## Consequences

- A target must provide HTTPS remote management with a certificate trusted by
  the Appliance and matching the supplied DNS name or IP address.
- A failed attempt requires the administrator to submit the credentials again.
- The standalone worker can reach only localhost and private address ranges.
- Agent deployment is not customer-release-ready until the package is delivered
  as a signed installer and clean-VM acceptance has passed.
- Future Linux and other system types require separate fixed deployment
  capabilities and cannot reuse an arbitrary shell abstraction.
