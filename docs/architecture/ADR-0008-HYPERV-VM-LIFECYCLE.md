# ADR-0008: Hyper-V Virtual Machine Lifecycle Actions

- Status: Accepted for the development foundation
- Decision date: 2026-09-04
- Application version: 0.2.2
- First capable Windows Agent: 0.2.2

## Context

IPMS must progress from Hyper-V inventory to controlled operations without
turning the Agent into a generic remote-administration channel. Administrators
need start, pause, resume, and stop directly from the VM inventory, including a
discoverable context menu. A stop can cause guest data loss and must not be an
accidental one-click operation.

## Decision

The Control Plane owns authorization, tenant isolation, transition validation,
durable job state, and append-only audit evidence. Only a platform
administrator or the selected tenant's tenant administrator can queue an
action. A VM permits one active action at a time.

The enrolled Windows Agent retrieves the assignment through its existing
Agent-initiated TCP 9419 mTLS connection. The assignment contains only:

- the durable job identifier;
- one literal action: `start`, `stop`, `pause`, or `resume`;
- the normalized VM GUID; and
- the expected normalized final state.

The native Agent independently validates the action, GUID, expected state, and
current state. It maps the action to a compiled-in
`Msvm_ComputerSystem.RequestStateChange` value and polls the local provider for
the final state. No arbitrary WMI query, method, PowerShell, script, command,
path, URL, or free-form argument crosses the management boundary.

The Web Console exposes actions through a mouse context menu and the keyboard
context-menu gesture. Every action opens a confirmation dialog. Stop is styled
as destructive and explicitly warns that it immediately powers off the VM and
may lose unsaved guest data.

## State contract

| Action | Allowed observed state | Expected state |
| --- | --- | --- |
| Start | Stopped | Running |
| Pause | Running | Paused |
| Resume | Paused | Running |
| Stop | Running or paused | Stopped |

Jobs use `queued`, `delivered`, `running`, `succeeded`, `failed`, or
`cancelled`. A successful Agent result updates the inventory projection
immediately; the next inventory observation remains authoritative.

## Security and operational consequences

- The Agent keeps no inbound listener and the Control Plane never connects to
  a Hyper-V host directly.
- Agent identity, tenant, Hyper-V host inventory, VM GUID, and job are bound
  before delivery.
- Requests, deliveries, running acknowledgements, and terminal outcomes are
  audited without recording secrets or raw provider payloads.
- A terminal result that cannot be returned immediately is stored locally and
  retried through the next authenticated Agent cycle.
- Stop is deliberately an immediate power-off. A separate guest-aware shutdown
  action requires its own integration-service detection and policy decision.

## Acceptance boundary

Backend tests prove tenant and role isolation, transition validation, single
active-job enforcement, delivery, result handling, and inventory projection.
Native Windows build and contract tests prove the compiled Agent surface.
Customer release still requires live acceptance against supported Hyper-V
versions, signed Windows packages, and explicit failure testing for provider
timeouts and host failover.
