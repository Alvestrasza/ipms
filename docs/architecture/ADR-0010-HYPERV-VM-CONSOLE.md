# ADR-0010: Hyper-V Virtual Machine Console

- Status: Accepted for the development foundation
- Decision date: 2026-09-05
- Application version: 0.2.25
- First compatible Windows Agent: 0.2.20

## Context

IPMS administrators need to view and directly control a Hyper-V virtual
machine without opening a separate VMConnect session. The console must work
before guest networking, remote desktop, or guest credentials are available.
It must preserve the existing Agent-initiated mTLS boundary and must not turn
the Agent into a generic remote-access or command-execution service.

Only one IPMS console session may control a virtual machine at a time. A second
operator must receive an explicit occupied-session warning instead of joining,
observing, or taking over the existing session. Keyboard and mouse input must
be direct, and the secure attention sequence must remain an explicit toolbar
operation.

## Decision

The browser opens a centered, tenant-scoped modal from the Hyper-V virtual
machine inventory. A double click or the **Open console** context-menu item
requests a session. The modal provides:

- a bounded current console image;
- a focusable surface for direct keyboard and absolute mouse input;
- mouse buttons and relative wheel input;
- a dedicated **Ctrl+Alt+Delete** toolbar button; and
- explicit connecting, occupied, expired, and failed states.

The Control Plane owns the session lease, authorization, tenant binding, input
queue, and latest frame. A conditional database uniqueness constraint permits
only one `requested` or `active` session for a tenant and VM identity.
This makes the rule valid in both standalone and scale-out deployments. A
30-second browser lease is renewed by authenticated status polling; abandoned
sessions expire and release the VM automatically.

The dedicated `virtual_machines.console.control` permission is granted to
platform administrators, tenant administrators, and operators. After session
creation, only the requesting user can read the session status or frame, submit
input, or close it. Another authorized user receives only the occupied-session
projection returned by the create attempt.

The enrolled Hyper-V host Agent obtains the assignment through the existing
outbound TCP 9419 mTLS channel. The assignment contains only:

- the session identifier;
- the inventory-bound VM GUID and display name;
- fixed frame dimensions; and
- typed input events: key, mouse move, mouse button, mouse wheel, or secure
  attention.

The native Agent revalidates the VM GUID, recorded display name, and running
state against the local Hyper-V V2 provider. It resolves the current setting
object through the documented `Msvm_SettingsDefineState` association, avoiding
ambiguous or truncated host-wide setting scans. It then uses the documented
`GetVirtualSystemThumbnailImage` method for a bounded RGB565 frame and Windows
Imaging Component for in-memory PNG encoding. It uses the fixed
`Msvm_Keyboard` and `Msvm_SyntheticMouse` methods for input, including the
dedicated `TypeCtrlAltDel` operation. The server cannot supply a WMI query,
class, method, path, command, script, executable, URL, or guest credential.

The Agent acknowledges input identifiers only after applying them. Until the
Control Plane receives an acknowledgement, the event remains eligible for
redelivery. The Control Plane keeps only the latest PNG frame, marks it
`private, no-store` at the HTTP boundary, and clears it when the session closes,
expires, or fails.

The Agent maps provider return values and local image-processing stages to a
bounded allowlist of failure codes. It never returns raw WMI objects, paths,
host data, or exception text to the portal.

## Explicit exclusions

The initial console does not provide:

- parallel, shared, or observer sessions;
- session takeover or administrative eviction;
- clipboard, file, drive, device, printer, audio, or smart-card redirection;
- guest RDP, guest network access, or guest authentication;
- frame history, recording, or screenshot export; or
- arbitrary remote commands or arbitrary WMI operations.

## Audit and privacy

Session open, close, and secure-attention operations create append-only audit
events. Raw screen frames and ordinary keystrokes are not written to the audit
log. The latest frame is operational transient data and is overwritten rather
than accumulated.

## Acceptance boundary

Control Plane tests prove permission and tenant isolation, single-session
enforcement, owner-only control, lease expiry, input validation, secure
attention auditing, Agent delivery, acknowledgement, and frame retrieval.
The native Windows build and contract tests prove that the console remains a
compiled-in capability. The web build proves the localized modal and input
surface compile as a production Next.js application.

Live acceptance has verified session exclusivity on a supported Hyper-V host.
Frame color, keyboard layout, mouse coordinate mapping, secure attention, host
failover behavior, and provider timeouts still require acceptance with the
0.2.20 Agent package.
