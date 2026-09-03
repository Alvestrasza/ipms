# ADR-0006: Agent-Initiated Lifecycle Channel

- Status: Accepted for the development foundation
- Decision date: 2026-09-03
- Application version: 0.1.47
- First lifecycle-capable Windows Agent: 0.1.32

## Context

IPMS administrators need one tenant-scoped inventory of installed Agents and a
safe way to update or remove them. Reusing stored Windows administrator
credentials or turning the Agent into a generic remote command channel would
expand the attack surface and conflict with the Agent contract.

Agents older than 0.1.32 do not understand lifecycle assignments. They require
one final bootstrap update through the existing administrator-approved Windows
deployment workflow before they can use this channel.

## Decision

The Web Console exposes **Administration > Infrastructure > Agents** only to a
platform administrator or the selected tenant's tenant administrator. The
Control Plane remains the authorization, tenant-isolation, validation, job,
and audit boundary.

The lifecycle protocol contains two fixed actions:

- `update`: replace only the native Agent service binary with the version
  assigned by the Control Plane;
- `uninstall`: remove the Agent service and installed program files while
  retaining historical inventory and the protected device identity for later
  administrative reconciliation.

No request contains a command line, script body, shell fragment, PowerShell,
environment override, destination path, or arbitrary URL. The Agent constructs
all paths and updater arguments from compiled constants and bounded identifiers.

The sequence is:

1. An authorized administrator creates a tenant- and device-bound durable job.
2. The Agent receives the fixed assignment in the response to its normal
   Agent-initiated mTLS inventory or telemetry request.
3. For an update, the same enrolled certificate requests the job-bound service
   binary from the Agent Gateway.
4. The Agent and the native updater independently verify the assigned SHA-256
   digest.
5. The updater stops the LocalSystem service, keeps a rollback binary, performs
   the fixed replacement, updates the local product version, and starts the
   service again.
6. The restarted Agent reports success. A failed replacement restores and
   restarts the previous binary before reporting failure.
7. For an uninstall, the native updater removes only the known IPMS service,
   registrations, shortcuts, and program files. It reports through the enrolled
   identity before scheduling the running binaries for deletion.

Only one active lifecycle job is allowed per enrollment. Job state is explicit:
`queued`, `delivered`, `running`, `succeeded`, `failed`, or `cancelled`.

## Security properties

- tenant and role checks are enforced by the Django API;
- the Gateway binds assignment and artifact access to the enrolled client
  certificate and device URI;
- the package ZIP is pinned on the Appliance and the extracted service binary
  receives its own immutable digest in each assignment;
- the Agent has no inbound listener and the Control Plane never dials it;
- lifecycle actions are audited without storing credentials, certificates, or
  payload bodies;
- updater paths, service names, registry keys, and removable files are fixed in
  native code;
- device private keys, certificates, configuration, and enrollment state are
  not replaced during an update.
- administrative removal is allowed only for offline, never-seen, or revoked
  records; an active certificate is revoked before the enrollment is hidden,
  and historical inventory plus audit evidence are retained.

## Development limitations

Version 0.1.47 proves the lifecycle control path and the identity-preserving
legacy bootstrap path but is not a customer release
channel. The current Windows binaries are not Authenticode-signed, the
assignment is authenticated by mTLS rather than by a separately signed update
manifest, and the package is ZIP-based rather than MSI-based.

Before customer release, IPMS must add a code-signing chain, signed manifests,
publisher and platform verification, an MSI-based identity-preserving upgrade,
expiry and anti-rollback policy, resumable downloads, timeout recovery, staged
rollout rings, and clean-VM update/uninstall acceptance.

## Consequences

Routine fleet lifecycle operations no longer require stored endpoint
administrator credentials after the one-time 0.1.32 bootstrap. The fixed
lifecycle actions are the only state-changing exception in the v0.1.0 Agent
foundation; they manage IPMS itself and do not change customer workloads,
Hyper-V configuration, BMCs, networks, storage, or backups.
