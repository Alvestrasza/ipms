# Hyper-V console implementation comparison

Status: researched design guidance, not a vendor performance benchmark.
Reviewed: 2026-09-08. Related work: issue #23, application 0.2.42,
Windows Agent 0.2.29.

## What other products actually document

| Product | Documented console approach | Implication for IPMS |
| --- | --- | --- |
| Microsoft VMConnect / Hyper-V Manager | VMConnect offers basic console access and an enhanced RDP session. Enhanced mode adds guest-dependent functionality such as resource redirection. [Microsoft](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enhanced-session-mode) | Basic console and enhanced guest session are different capabilities; enhanced mode is not a transparent performance switch. |
| System Center VMM | Console access works without a network connection to the VM. VMM 2019 and later support enhanced sessions. Host policy and supported guest Remote Desktop Services are prerequisites; switching modes closes and reopens the session. [Microsoft](https://learn.microsoft.com/en-us/system-center/vmm/enhanced-console-session?view=sc-vmm-2025) | Preserve basic console for boot/repair access. Add enhanced mode only as a separately specified, authorized feature. |
| Windows Admin Center | Offers an integrated Remote Desktop web console and an RDP file for mstsc.exe. Both connect through VMConnect on the Hyper-V host. The guide requires host administrator credentials for these workflows. [Microsoft](https://learn.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines#manage-a-virtual-machine-through-the-hyper-v-host-vmconnect) | A browser-based host-console path is viable. This guide does not identify a reusable rendering SDK, its license, implementation details, codec negotiation or measured FPS. |
| Royal TS for Windows | Its Remote Desktop connection uses Microsoft's RDP ActiveX control. Hyper-V support integrates console access without requiring vmconnect.exe, with host proxy port 2179 and a VM instance GUID. WMI is used for instance browsing. [Royal Apps](https://docs.royalapps.com/r2023/royalts/reference/connections/rdp.html#hyper-v) | A native Windows application can embed the Microsoft client directly. Inventory lookup and console transport are separate; browsing rights must not be confused with the minimum rights for a known-VM connection. |
| Devolutions Remote Desktop Manager | Current product documentation advertises Microsoft RDP connections from its Hyper-V dashboard. A vendor engineering reply documents an embedded Hyper-V RDP entry targeting a host and VM ID, primarily replacing VMConnect. [Product overview](https://devolutions.net/integration-center/hyper-v/), [vendor engineering explanation](https://forum.devolutions.net/topics/39393/win-1011-hyperv-vms) | Supports the host-plus-VM-ID approach. The engineering reply is historical, not a guarantee of every current implementation detail or a benchmark. |

The desktop integrations above do not establish that a normal web page can host
the Windows ActiveX control. Their observed product behavior also does not prove
which codec is negotiated for a specific basic or enhanced Hyper-V session.
No unverified SDK, proprietary implementation or redistribution right is assumed.

## IPMS assessment

IPMS already uses the native host endpoint rather than repeated screenshots:

```text
Browser display / input
  <-> authenticated IPMS console broker + RDP renderer
  <-> Agent-initiated mTLS relay
  <-> fixed loopback Hyper-V port 2179 + assigned VM GUID
```

This extra browser translation and relay can incur overhead compared with a
desktop client. That is an architectural inference, not proof that either layer
caused the reported delay. The inspected Agent did contain fixed 10 ms sleeps
in the asynchronous handshake and relay loop. Newly received input could wait
for another loop before being written to the local host socket. Removing those
avoidable waits is justified independently of any vendor benchmark.

The 0.2.29 candidate uses completion/readiness events, drains ready work without
an unconditional delay, and retains bounded buffers and deadlines.
[Microsoft's WSAEventSelect contract](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaeventselect)
requires correct readiness re-arming and atomic event consumption; this is
covered by local Winsock tests. TCP_NODELAY was already enabled on the Agent's
local console socket. No blanket network or timer-resolution change is made.

## Measurement and decision gates

1. Activate only after separate approval, then update one explicitly selected
   Hyper-V host Agent with no occupied IPMS console. Keep rollback binaries.
2. Compare identical guest content, resolution, host, client and measurement
   intervals. Include idle, window movement and ordinary typing in a disposable
   guest context. Never use a production application as the input fixture.
3. Record display-update FPS, browser-to-broker RTT, resource use and disconnects.
   The browser RTT excludes Agent/host/guest processing. End-to-end input delay
   still needs a separately controlled input-to-visible-result measurement.
4. Compare native VMConnect sequentially, not concurrently: external sessions
   can displace the active console. Separate basic from enhanced comparisons.
5. Only if the event-driven candidate remains inadequate, evaluate renderer
   negotiation and per-hop timings. Enhanced mode or a native Windows companion
   would be separate product decisions, not automatic fallbacks.

There is no evidence here that 15 FPS has been reached on a real host. A stationary
desktop legitimately needs few or no new display updates. More frequent pings
or empty synchronization messages must not inflate a reported frame rate.

## Security and product boundaries

No direct browser-to-host socket, public port 2179, new credential prompt,
credential export, host-policy change, guest RDP enablement, device redirection,
generic remote execution or automatic enhanced-mode switch is introduced.
Existing tenant authorization, exact-VM fencing, certificate binding and mTLS
remain in place. A future desktop companion would need its own tenant-aware,
short-lived authorization design; it must not expose stored host passwords to
the browser or bypass IPMS session ownership.

The display measurement uses the pinned client's completed `display.flush`
acknowledgment, not raw synchronization receipt or a network heartbeat.
See the [Apache Guacamole 1.6.0 client source](https://github.com/apache/guacamole-client/blob/1.6.0/guacamole-common-js/src/main/webapp/modules/Client.js)
and [IPMS verification boundary](../operations/NATIVE-CONSOLE-0242-VERIFICATION.md).
