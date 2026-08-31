# Agent Contract

## Scope

This contract defines the boundary between IPMS Control Plane and an enrolled IPMS Agent. It supplements the read-only connector contract; it does not turn agents into connector endpoints or generic management channels.

## Device identity and transport

- Each agent has a unique device identity, tenant association, and short-lived client certificate issued during a guided enrollment ceremony.
- The agent initiates an outbound mTLS connection. The server authenticates the device and the agent authenticates the Control Plane certificate chain.
- Enrollment, certificate renewal, revocation, and endpoint migration are durable, auditable operations. A revoked or expired identity sends no data and accepts no policy.
- Inventory is bounded, correlated, batched, retry-safe, and queued locally only for a documented retention period. Secrets and raw event contents are excluded from telemetry and diagnostic logs.

## Management Pack declaration

A management-pack assignment contains a pack ID, immutable version, minimum agent version, target device identity, tenant, expiry, dependency set, explicitly allowed built-in capabilities, collection cadence, signature, and correlation ID. The agent rejects an assignment that is unsigned, expired, assigned to another device or tenant, incompatible, cyclic, or outside its compiled capability registry.

An assignment is configuration, never executable content. It cannot contain shell text, PowerShell, binaries, dynamic libraries, certificate private keys, credentials, endpoint overrides, or arbitrary environment variables.

## Initial capability registry

| Pack | Capabilities | Access |
| --- | --- | --- |
| `windows-server-core` | OS, hardware, storage, and network inventory | Read-only |
| `hyper-v-host` | Hyper-V host, VM, and virtual-network inventory | Read-only |

`hyper-v-host` requires `windows-server-core`. Both packs are available only on Windows and neither performs a state-changing Hyper-V operation.

## Control-plane requirements

The Control Plane must persist pack assignment, acceptance, rejection, last inventory sequence, policy version, and audit attribution. It must enforce tenant and license policy before queueing any assignment. The Web Console only displays this state; it is not the authorization boundary.
