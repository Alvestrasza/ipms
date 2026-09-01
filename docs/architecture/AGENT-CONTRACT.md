# Agent Contract

## Scope

This contract defines the boundary between IPMS Control Plane and an enrolled IPMS Agent. It supplements the read-only connector contract; it does not turn agents into connector endpoints or generic management channels.

## Device identity and transport

- Each agent has a unique device identity, tenant association, and short-lived client certificate issued during a guided enrollment ceremony.
- The agent initiates one persistent mTLS connection to the IPMS Agent Gateway on TCP 9419. The server authenticates the device and the agent authenticates the Control Plane certificate chain.
- The authenticated connection is bidirectional. The Agent submits inventory, health, job status, acknowledgements, and audit-safe errors; the Gateway may send only signed Management Pack assignments, bounded inventory requests, certificate-rotation instructions, and signed agent-update manifests.
- Managed systems do not accept inbound Agent Gateway connections. The Control Plane pushes messages through the Agent-initiated stream; it never dials an agent.

The portal bootstrap in ADR-0005 is a narrowly scoped installation exception,
not an Agent transport change. A dedicated worker may use trusted HTTPS Windows
remote management once to install the pinned Agent package and import a
short-lived enrollment. It cannot run operator-supplied commands or scripts,
and the installed Agent still exposes no inbound listener.
- Enrollment, certificate renewal, revocation, and endpoint migration are durable, auditable operations. A revoked or expired identity sends no data and accepts no policy.
- Inventory is bounded, correlated, batched, retry-safe, and queued locally only for a documented retention period. Secrets and raw event contents are excluded from telemetry and diagnostic logs.

Agent identity, certificate profiles, trust modes, recovery, and external-CA
integration are defined by [ADR-0003](ADR-0003-AGENT-PKI-AND-ENROLLMENT.md).

On Windows, the local **IPMS Agent Configuration** application stores the
gateway hostname, port, and selected trust mode atomically in the protected
Agent configuration directory. This local configuration does not replace
enrollment. Until mTLS enrollment exists, the application must report that no
certificate is enrolled and must not claim a connected state. Its local UI
contract is defined by [ADR-0004](ADR-0004-LOCAL-AGENT-CONFIGURATION.md).

## Management Pack declaration

A management-pack assignment contains a pack ID, immutable version, minimum agent version, target device identity, tenant, expiry, dependency set, explicitly allowed built-in capabilities, collection cadence, signature, and correlation ID. The agent rejects an assignment that is unsigned, expired, assigned to another device or tenant, incompatible, cyclic, or outside its compiled capability registry.

An assignment is configuration, never executable content. It cannot contain shell text, PowerShell, binaries, dynamic libraries, certificate private keys, credentials, endpoint overrides, or arbitrary environment variables.

An update message is a signed manifest, not an executable payload. The Agent verifies the signer, target platform, version, artifact digest, compatibility, and rollback availability before downloading an update through the authenticated channel and applying it atomically.

## Initial capability registry

| Pack | Capabilities | Access |
| --- | --- | --- |
| `windows-server-core` | OS, hardware, storage, network, and installed role/feature inventory | Read-only |
| `hyper-v-host` | Hyper-V host, VM, and virtual-network inventory | Read-only |

`hyper-v-host` requires `windows-server-core`. Both packs are available only on Windows and neither performs a state-changing Hyper-V operation.

The Windows core pack separates five-minute configuration inventory from a
ten-second current utilization sample. Live telemetry is limited to native,
read-only CPU, physical-memory, and fixed-volume counters. The v0.1.0 Control
Plane retains only the latest sample per system; historical telemetry requires
the later dedicated telemetry storage boundary.

Installed Windows Server roles and features are five-minute configuration
inventory. The Agent queries the native Server Manager management provider and
reports only entries whose provider state is installed. Each entry is bounded
to a stable name, localized display name, parent name, and the normalized type
`role`, `role-service`, or `feature`. A separate collection status distinguishes
a successfully collected empty list from an unavailable provider and from an
older Agent that did not report this capability.

## Control-plane requirements

The Control Plane must persist pack assignment, acceptance, rejection, last inventory sequence, policy version, and audit attribution. It must enforce tenant and license policy before queueing any assignment. The Web Console only displays this state; it is not the authorization boundary.
