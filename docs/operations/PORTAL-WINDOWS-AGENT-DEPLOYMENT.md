# Portal Windows Agent Deployment

## Scope

IPMS 0.1.28 adds a development-grade portal bootstrap for Windows Agent 0.1.27.
The workflow is tenant-scoped, audited, certificate-validated, and limited to a
fixed installation operation. It is not a general-purpose remote execution
feature.

## Prerequisites

- The target resolves only to private addresses reachable from the Appliance.
- Windows HTTPS remote management is enabled on the target, normally on TCP
  5986.
- The target certificate is valid for the entered DNS name or IP address and
  chains to a CA in the Appliance trust store.
- The supplied account is a local administrator on the target.
- No existing `IPMS Agent` service or Agent installation directory is present.
- The Appliance contains the pinned Windows Agent package whose SHA-256 digest
  matches its deployment configuration.

## Portal workflow

1. Select **Add System** in the top bar.
2. Select **Windows system**.
3. Enter a display name, DNS name or IP address, HTTPS port, administrative
   username, and password.
4. Submit the deployment and keep the dialog open to see queued, running,
   succeeded, or failed state.
5. After a successful installation, wait for the Agent to complete one-time
   enrollment and submit its first inventory through the mTLS Gateway.

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
Audit events record tenant, actor, target endpoint, job identifier, outcome, and
a bounded error code only.

The current development package is hash-pinned but not Authenticode-signed and
is not an MSI. Code signing, a signed installer, clean-VM acceptance, upgrade,
rollback, and interrupted-copy recovery remain release gates.
