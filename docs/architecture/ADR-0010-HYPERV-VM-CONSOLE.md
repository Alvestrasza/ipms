# ADR-0010: Hyper-V Virtual Machine Console

- Status: Accepted for the development foundation
- Decision date: 2026-09-05
- Application version: 0.2.30
- First compatible Windows Agent: 0.2.21

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

The browser opens an independent, tenant-scoped window from the Hyper-V virtual
machine inventory. A double click or the **Open console** context-menu item
requests a session. It can be moved across monitors and resized using the
operating system's window controls. The original portal may navigate or close
independently. Browser popup policy is respected and blocked opens receive a
localized message. The window provides:

- a bounded current console image;
- a focusable surface for direct keyboard and absolute mouse input;
- mouse buttons and relative wheel input;
- a dedicated **Ctrl+Alt+Delete** toolbar button; and
- explicit connecting, occupied, expired, and failed states.

The Control Plane owns the session lease, authorization, tenant binding, input
queue, and latest frame. A conditional database uniqueness constraint permits
only one `requested` or `active` session for a tenant and VM identity.
This makes the rule valid in both standalone and scale-out deployments. A
30-second browser lease is renewed by authenticated frame or status polling; abandoned
sessions expire and release the VM automatically.

The dedicated `virtual_machines.console.control` permission is granted to
tenant administrators and operators; platform accounts are excluded by
[ADR-0012](ADR-0012-PLATFORM-AND-TENANT-ADMINISTRATION.md). After session
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
Imaging Component for in-memory PNG encoding. A provider result is accepted
only when its byte count matches the requested or reported current video-head
surface. The compatibility path also permits one observed fixed DWORD trailer,
which is never interpreted as image data. It uses the fixed
`Msvm_Keyboard` and `Msvm_SyntheticMouse` methods for input, including the
dedicated `TypeCtrlAltDel` operation. The server cannot supply a WMI query,
class, method, path, command, script, executable, URL, or guest credential.

Version 0.2.27 targets a bounded 150-ms browser frame cadence. One response
contains the latest image sequence, dimensions, state, and failure code.
Clients send their last sequence and receive an empty, uncached response for
unchanged frames. Lease writes are limited to once every five seconds during
continuous polling. There is at most one frame request in flight per window.

Input is batched within 25 ms and delivered sequentially in batches of at most
32 events. Consecutive mouse moves may be coalesced, but never across a click
or key event. Both browser and Control Plane bound their queues. A failed or
uncertain browser delivery stops the queue instead of replaying actions.
Agent 0.2.22 replaces per-byte Automation array calls with one validated bulk
copy, filters input-device queries to the validated VM GUID, and targets a
150-ms cycle including capture/exchange time, with a minimum 25-ms yield.
The achieved frame rate remains dependent on the provider and host workload.

Application 0.2.28 and Agent 0.2.23 additionally support opt-in HTTP keep-alive
only for authenticated console traffic. The Gateway revalidates the peer
certificate and device identity on every request, rejects route changes, and
closes the connection after at most 256 requests. Existing header/body timeouts
remain in force. One-shot clients remain compatible. The Agent binds its
connection pool to the Gateway hostname/port and client certificate, discards
failed or idle entries, and sends console headers/body together. Bootstrap
never uses this pool and still checks its explicit certificate pin before
sending the enrollment body.

The Agent acknowledges input identifiers only after applying them. Until the
Control Plane receives an acknowledgement, the event remains eligible for
redelivery. The Control Plane keeps only the latest PNG frame, marks it
`private, no-store` at the HTTP boundary, and clears it when the session closes,
expires, or fails.

Application 0.2.29 and Agent 0.2.24 split the console exchange into explicit
`frame` and `input` channels on the same fixed Gateway route and TCP 9419.
Legacy clients without a channel retain the combined contract. The frame
channel cannot acknowledge or claim inputs. A separate native input worker
owns its COM and HTTP handles and processes one ordered input batch at a time,
without waiting for image capture, encoding or upload. Each batch still
revalidates the inventoried VM GUID, display name and running state locally.

Input result posts acknowledge applied events immediately and never offer a
next batch. An uncertain result acknowledgement retains the receipt for retry,
without replaying the already-applied events. This in-process protection is
not a claim of exactly-once guest effects across a service or host crash.
Empty input polls wait asynchronously for at most one second, checking the
session queue every 25 ms without holding a transaction during the wait. The
Gateway revalidates certificates again before releasing a waited response.
Certificate validity dates are checked on every authenticated message, so an
already established connection cannot outlive the enrolled certificate.
Input queries defer image blobs and do not advance frame scheduling metadata.
Discrete browser inputs send immediately; only adjacent pointer motion uses
an eight-millisecond coalescing window.

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
compiled-in capability. The web build proves the localized detached window and input
surface compile as a production Next.js application.

Live acceptance with Agent 0.2.21 has verified session exclusivity, repeated
1024x768 PNG frames, absolute mouse movement, key press and release
acknowledgement, clean session release, and removal of the transient frame.
Frame color, keyboard layout, visual mouse-coordinate mapping, mouse buttons,
wheel input, secure attention, host failover behavior, and provider timeouts
remain explicit manual acceptance items.

The detached-window browser regression test uses real local authentication,
tenant authorization, session creation/exclusivity, input validation and
session close, with only the VM image producer replaced by a synthetic PNG.
It checks independent window lifetime, resizing, reuse, occupied-session
warnings, keyboard/mouse/wheel/secure-attention submission, and clean close.

Live comparison with Agent 0.2.23 reduced the median observed frame interval
from 1,084 ms to 298 ms on the same test VM. A further 45-second active sample
remained stable at a 305-ms median. These measurements describe Control Plane
frame arrival, not browser glass-to-glass latency. See the
[performance acceptance record](../operations/HYPERV-CONSOLE-PERFORMANCE.md)
for methodology, input acknowledgement samples and remaining manual checks.

## Heartbeat and collection isolation

Application 0.2.30 and Windows Agent 0.2.25 additionally separate the frame
worker from normal collection and introduce an independent ten-second
heartbeat. Presence does not imply metric freshness. A valid active console
lease blocks Agent removal; new and legacy contact evidence inform presence.
The existing port and trust boundary remain unchanged. See the
[heartbeat contract and pending live acceptance](../operations/AGENT-HEARTBEAT-ISOLATION.md).

Implementation references:

- [Microsoft SafeArrayAccessData](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-safearrayaccessdata)
- [MDN Window.open](https://developer.mozilla.org/en-US/docs/Web/API/Window/open)
- [Microsoft WinHTTP sessions](https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-sessions-overview)
- [Microsoft semisynchronous WMI methods](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execmethod)
