# ADR-0008: Hyper-V Virtual Machine Lifecycle Actions

- Status: Accepted for the development foundation
- Decision date: 2026-09-04
- Application version: 0.2.6
- First capable Windows Agent: 0.2.6

## Context

IPMS must progress from Hyper-V inventory to controlled operations without
turning the Agent into a generic remote-administration channel. Administrators
need start, pause, resume, graceful shutdown, and stop directly from the VM
inventory, including a discoverable context menu. A stop can cause guest data
loss and must not be an accidental one-click operation.

## Decision

The Control Plane owns authorization, tenant isolation, transition validation,
durable job state, and append-only audit evidence. Only a platform
administrator or the selected tenant's tenant administrator can queue an
action. A VM permits one active action at a time.

The enrolled Windows Agent retrieves the assignment through its existing
Agent-initiated TCP 9419 mTLS connection. The assignment contains only:

- the durable job identifier;
- one literal action: `start`, `shutdown`, `stop`, `pause`, or `resume`;
- the normalized VM GUID;
- the inventory-recorded VM display name; and
- the expected normalized final state.

The native Agent independently validates the action, GUID, bounded display
name, expected state, and current state. It resolves the target by enumerating
the bounded local VM set with the same provider-safe projection used for
inventory and comparing normalized GUIDs instead of injecting the identifier
into a WMI expression. The matching provider object must also reproduce the
inventory-recorded display name; a mismatch is rejected as an identity
conflict. Start, stop, pause, and resume map to compiled-in
`Msvm_ComputerSystem.RequestStateChange` values. Graceful shutdown uses the
compiled-in `Msvm_ShutdownComponent.InitiateShutdown` method with `Force=false`
and a fixed audit-safe reason. The Agent polls the local provider for the final
state. No arbitrary WMI query, method, PowerShell, script, command, path, URL,
or free-form argument crosses the management boundary.

The Web Console exposes actions through a mouse context menu and the keyboard
context-menu gesture. Every action opens a confirmation dialog. Graceful
shutdown explains that it depends on the Hyper-V guest shutdown integration
service. Stop is styled as destructive and explicitly warns that it immediately
powers off the VM and may lose unsaved guest data.

## State contract

| Action | Allowed observed state | Expected state |
| --- | --- | --- |
| Start | Stopped | Running |
| Pause | Running | Paused |
| Resume | Paused | Running |
| Shut down | Running | Stopped |
| Stop | Running or paused | Stopped |

Jobs use `queued`, `delivered`, `running`, `succeeded`, `failed`, or
`cancelled`. A successful Agent result updates the inventory projection
immediately; the next inventory observation remains authoritative.

## Security and operational consequences

- The Agent keeps no inbound listener and the Control Plane never connects to
  a Hyper-V host directly.
- Agent identity, tenant, Hyper-V host inventory, VM GUID, recorded display
  name, and job are bound before delivery.
- Requests, deliveries, running acknowledgements, and terminal outcomes are
  audited without recording secrets or raw provider payloads.
- Failed identity lookup codes may include only bounded aggregate row counts;
  they never include VM names, identifiers, provider paths, or raw payloads.
- A terminal result that cannot be returned immediately is stored locally and
  retried through the next authenticated Agent cycle.
- Graceful shutdown never sets `Force=true`. A missing or unavailable guest
  shutdown integration service produces an explicit terminal failure and does
  not fall back to Stop.
- Stop is deliberately an immediate power-off and remains a separate,
  destructive choice.

## Acceptance boundary

Backend tests prove tenant and role isolation, transition validation, single
active-job enforcement, delivery, result handling, and inventory projection.
Native Windows build and contract tests prove the compiled Agent surface.
Customer release still requires live acceptance against supported Hyper-V
versions, signed Windows packages, and explicit failure testing for provider
timeouts and host failover.
