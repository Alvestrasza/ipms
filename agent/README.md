# IPMS Agent

Windows candidate **0.2.47** additionally preserves valid Administrative Template comment schemas, verifies Domain Admins ownership, and safely confirms stale GPO absence before local cleanup. It also permits an exact configured domain
root as an exclusive Tier 0 target for managed machine or user GPOs. It treats
that target as a domain object in GPMC and LDAP while retaining the component's
machine or user activation scope. Candidate **0.2.45** validates schema-4 sparse
override jobs against a compiled Microsoft baseline catalog. It renders only the selected Registry.pol,
security template and audit records into a separate managed GPO. Caller-provided
paths, types and structured AppLocker XML are never accepted. The base GPO stays
unchanged and activation preserves the server-approved higher link priority. It
also supports deletion of an exact IPMS-managed baseline, override or custom GPO after a fresh complete
forest link inspection and protected backup. The operation removes only approved,
non-enforced links, rejects default and unmanaged policies, verifies the GPO is gone
and leaves the immutable job and backup evidence available for audit and recovery.

Windows **0.2.42** adds a separate read-only GPO reconciliation worker.
It observes the directory using the original protected job identity, retains the
original receipt, and binds observations and acceptance to that exact journal.
After Portal acceptance it checks the directory again before acknowledging the
resolution. Reconciliation cannot import, link, enable or repair a GPO. See
[the reconciliation workflow](../docs/operations/SECURITY-GPO-RECONCILIATION.md).

Windows **0.2.36** combines import and linking in one approved
`import_and_link_managed_gpo` request. It creates or explicitly adopts the GPO,
then creates disabled, non-enforced links at the approved targets. Activation
remains separate. The Agent checks the scope again between creation and linking;
partial failure retains the concrete GUID for reconciliation without recreating
or automatically enabling the GPO. Existing separate operations remain compatible.
The managed worker reads its executor identity directly inside its existing
isolated process, avoiding a nested worker launch that prevented inspections.

Windows **0.2.35** added schema-3 managed GPO operations: read-only
inspection, import, link, activation and deactivation. Each write requires its
own exact Portal approval and a fresh directory snapshot. Initial imports use
the final readable name but remain disabled and unlinked. Later imports only
prepare content; activation backs up and updates the stable GPO GUID. Links are
limited to configured tier OUs or the explicitly approved Tier 0 domain root for
compiled Domain Security components, non-enforced and initially disabled. Unrelated
links, default policies, ACLs and WMI filters are not changed. The Agent does not
accept commands or scripts. Existing schema-1/2 journals and receipts retain
their original interpretation; explicit legacy adoption verifies the previous
job identity and its still-disabled, unlinked GPO. See
[managed GPO operations](../docs/operations/SECURITY-MANAGED-GPOS.md).

The Agent verifies complete forest-wide link visibility before mutation, using
bounded signed/sealed LDAP DirSync and GPMC observations. Missing read rights or
an unreachable forest domain stop the operation. Domain-root actions verify the
root object GUID against the approved domain identity.

The production lifecycle implementation requires live domain acceptance.
Protected backups support operator-led recovery; a partial or uncertain write
is fenced for reconciliation and is never automatically replayed or restored.
The 15-second claim grant remains bounded: slow inspection or backup can stop
the action before its first write rather than silently extend authorization.

## Earlier compatible protocols

Windows candidate **0.2.34** accepts Portal approval for exact schema-2 pilot
jobs over the existing authenticated mTLS channel. Each approval binds the
job input digest, enrolled device, domain, tier, operation, requester, approver,
policy revision and expiry. When the tenant requires four eyes, requester and
approver must be different principals. The approval returned by the execution
claim must exactly match the approval observed during polling. A future-dated
approval waits for the local clock; validity is never extended for clock skew.

After a validated claim, the Agent writes a separate protected, one-use Portal
receipt. The fixed GPMC worker verifies and consumes that exact receipt before
creation. The 15-second monotonic execution grant and durable uncertainty fences
remain in force. Portal approval requires no interactive controller logon or
per-job local approval command. Legacy schema-1 jobs retain their exact local
approval flow; their approval files and CLI cannot authorize schema-2 jobs.

Current roles, tenant policy and revocation are enforced by the authenticated
Control Plane at claim time. This is the existing mTLS execution authority, not
an independent signature or security-zone boundary. No AD permissions or service
credentials are installed. The native worker still creates only a new disabled,
unlinked pilot GPO; effective write permissions and domain acceptance remain
separate checks. Deploy the compatible receiver before updating Agents.

Windows **0.2.33** adds read-only computer GPO processing evidence to
the existing core inventory. The fixed local worker combines RSoP eligibility,
per-extension processing status and the applied-GPO history for every extension.
It binds each observation to the local domain GUID and DNS name, GPO GUID and
version. A stable before/after snapshot is required; display names and resultant
setting values are never evidence that a baseline was applied. The oldest required
extension completion time is retained so the receiver can reject stale evidence.
An inconsistent domain between core inventory and the GPO observation clears
only GPO evidence, preserving the otherwise valid host inventory.

The worker has a 30-second deadline, 128-MiB process limit and 64-KiB output cap.
Disabled logging, unavailable APIs, excluded GPOs, failed processing and incomplete
or changing snapshots cannot produce a positive application confirmation. No
policy refresh, directory write, command or script is issued. Missing permissions
remain explicit; no interactive logon is requested by this read-only collector.
Deploy the compatible Portal receiver before updating Agents. This observation
feature is independent of the pilot import workflow.

Windows **0.2.32** introduced the legacy schema-1 native GPMC worker for creating a
new **disabled, unlinked pilot GPO** from one checksum-pinned Microsoft backup
component. The Portal first sends an immutable domain/DC-bound job. An elevated
administrator on that controller reviews its complete JSON and approves exactly
that job with `ipms-agent.exe --approve-gpo-pilot <reviewed-job.json>`. Approval
binds the current enrollment, domain, complete input digest and expiry and is
consumed before creation. It is not a permanent permission or a script channel.

The fixed child uses native GPMC COM interfaces with a 120-second deadline and
256-MiB limit. GPMC must already be installed and the local server must be a
writable domain controller. No feature, service account or permission is installed
automatically. The executor report proves prerequisites, not effective AD write
permission. Missing rights and GPMC failures are reported explicitly.

No existing GPO, default policy, ACL or policy link is selected for modification.
Both computer and user settings remain disabled after import. Delivery uses the
same outbound TLS gateway through fixed `/v1/security-gpo` and
`/v1/security-gpo-artifact` paths; the Agent exposes no new listener. The binary
package format contains only an exact compiled sequence of pinned data files.
It accepts no received path, program, command, script, archive or URL.

Protected journals under `%ProgramData%\Alvestrasza\IPMS Agent\gpo-management`
fence uncertain claim/create/import windows. A crash or timeout with an uncertain
write outcome produces `requires_reconciliation` and no automatic AD retry,
deletion or rollback. Immutable final receipts are flushed before the current
journal is replaced and replayed with their exact original outcome. Staging does
not apply policy, establish baseline compliance or validate domain replication.
Real domain acceptance remains separate from local build/contract verification.

Windows candidate **0.2.31** adds an independently scheduled read-only baseline
scan worker. The Portal may select only compiled Microsoft profiles and their
immutable content hashes. A fixed child process reads approved native Windows
settings with a 30-second deadline, 128-MiB memory limit and bounded paged
results. The Agent reports observations; the Control Plane evaluates them.
User/domain scope and unsupported controls remain unknown. No GPO, registry,
service or account policy is changed. Deploy the compatible receiver first.

Windows **0.2.30** added bounded local WUA-cache installed-update
identity evidence for the IPMS WSUS catalog comparison. It uses a fixed offline
query in an isolated subprocess; it does not register the server with WSUS,
change update policies or install updates. Deploy the schema-2 receiver first.
See [WSUS reception](../docs/operations/WSUS-METADATA-RECEPTION.md).

The Security scan uses its own authenticated `/v1/security-scan` channel.
Result pages bind the enrollment, job, attempt and manifest; failed transfers
retain one bounded observation set in memory and resend identical pages. A
restart causes a fresh server attempt. At most four pages are sent per worker
cycle; inventory, heartbeat, updates and Hyper-V retain their separate workers.
The executable accepts no external scan program, script, path, registry query,
expected value or remediation instruction. Package content is generated in
`include/ipms/agent/security_baseline_content.hpp` from the complete admitted
source manifests and remains traceable even when a reader is unsupported.

The native scan tests use synthetic observations and a dedicated fixture
executable; they do not read customer policy. They exercise typed registry
decoding, exact page completion, malformed/oversized/partial subprocess output,
termination, cancellation and heartbeat progress. Real SYSTEM/service-account
and customer-system scan acceptance is a separate deployment check.

The IPMS Agent is a native C++20 service for customer-managed Windows and Linux systems. It will establish an outbound, mutually authenticated connection to the IPMS Control Plane and collect only capabilities explicitly assigned to the enrolled device.

The implementation contains the pack registry and fixed read-only Windows and
Linux inventory capabilities. Windows build 0.2.29 and Linux build 0.2.13
include native services and bounded, paged installed-software and
update-posture inventory. Both platforms
use the same Agent-initiated TCP 9419 enrollment and mTLS trust boundary. The
Windows executable also reports roles/features and local Hyper-V VMs. Its
Hyper-V pack accepts only fixed start, graceful shutdown, stop, pause, and
resume assignments for an exact VM GUID; it never invokes `Win32_Product`,
PowerShell, or a server-supplied query or method.

## Event-driven native console relay

Windows Agent **0.2.29** replaces fixed 10 ms relay sleeps with WinHTTP completion
and Winsock readiness events. Ready work is drained immediately, while idle waits
remain bounded to 100 ms for cancellation and authorization checks. Fixed
loopback port 2179, exact VM preconnection validation, mTLS, lease enforcement,
bounded buffers and one outstanding asynchronous read/write are unchanged.
Application **0.2.42** adds display-update FPS and browser-to-broker RTT metrics;
these do not measure complete guest input latency. Real-host performance still
requires canary acceptance. See [verification](../docs/operations/NATIVE-CONSOLE-0242-VERIFICATION.md)
and [vendor research](../docs/architecture/HYPERV-CONSOLE-IMPLEMENTATION-COMPARISON.md).

## State-aware Hyper-V settings

Windows Agent **0.2.28** adds schema-2, power-state-bound Hyper-V settings patches.
Running VMs can receive fixed name/notes edits and directional Dynamic Memory
limits (minimum down, maximum up). CPU count, startup memory and memory mode
remain stopped-only in IPMS. Static hot-memory prerequisites are not yet attested.
The backend and native Agent independently validate every changed field; no
generic command interface is added. Deploy a schema-2-capable control plane
before upgrading an Agent. See the [field matrix](../docs/architecture/HYPERV-LIVE-SETTINGS-MATRIX.md)
and [0.2.39 verification boundary](../docs/operations/HYPERV-SETTINGS-0238-ACCEPTANCE.md).

## Heartbeat and scheduling isolation

Windows and Linux send a dedicated, fixed `heartbeat` message every ten seconds
over a fresh outbound mTLS request to `/v1/heartbeat`. The heartbeat worker never
collects inventory or metrics, creates enrollment credentials, performs renewal,
or consumes assignments. It reads only a committed enrolled identity and skips
the cycle while credentials are unavailable. HTTP operations have short bounded
timeouts: Windows uses two-second per-phase limits, not a two-second end-to-end
deadline; Linux uses a three-second request deadline with a two-second connect
limit. Slow work elsewhere cannot occupy this worker. Missed periods are
skipped rather than queued into a burst. A heartbeat confirms Agent contact,
not the freshness of CPU, memory, disk, or other inventory observations.

On Windows, frame capture/upload and ordered console input each have their own
worker. The main service loop continues its normal telemetry and inventory
cadence while a console is open. Late main-loop responses only wake a fresh
console poll; they never apply an old assignment or close a newer session.
Heartbeat, frame and input workers each own their transport objects. Enrollment
and lifecycle dispatch remain on the main thread. Service stop cancels each
worker and joins it before service-owned resources are released. Local WMI
connection/metadata calls still depend on provider health; the isolation is not
a guarantee that a wedged provider can be forcibly terminated inside the process.

## Installed roles and features

The Windows core pack queries the native `MSFT_ServerFeature` provider in
`Root\Windows\ServerManager`. It requests `State = 1` and emits only installed
roles, role services, and features. The payload contains the stable feature
name, localized display name, parent name, and normalized type. It never sends
available, removed, or unknown entries and never invokes PowerShell.

Collection has an explicit state. `collected` means the returned list is a
complete bounded observation, including a legitimate empty list. `unavailable`
means the Server Manager provider could not be queried, and `not-reported`
preserves compatibility with older Agents. Provider failures therefore cannot
silently erase previously understood meaning by masquerading as an empty host.
`not-applicable` is emitted for Windows clients, which do not participate in
Windows Server role navigation.

## Hyper-V virtual machines

When the local Hyper-V Virtual Machine Management service is installed, the Agent
queries the local `Root\Virtualization\V2` provider through fixed,
compiled WMI reads. It reports at most 128 virtual machines with stable ID,
name, normalized state, vCPU count, assigned or startup memory, uptime,
configuration version, and integration-service-reported IP addresses. A
45-second deadline, bounded related-object reads, and a 40-KiB JSON limit keep
the shared Gateway message below its transport ceiling.

Agent 0.2.12 provides a separate lifecycle capability. It maps `start`, `stop`,
`pause`, and `resume` to compiled-in `Msvm_ComputerSystem.RequestStateChange`
target states. Hyper-V WMI provider V2 pause requests `Quiesce` and normalizes
that stable observation to `paused`; resume requests the enabled state. `shutdown`
invokes the compiled-in `Msvm_ShutdownComponent`
`InitiateShutdown` contract with `Force=false` and a fixed reason. The Agent
normalizes and matches the VM GUID locally, verifies the current state, and
polls the resulting state before reporting success. The assignment contains no
WMI expression, method name, script, command, path, URL, or free-form argument.
Stop remains an immediate power-off operation.

Agent 0.2.26 provides the compiled-in `hyperv.vm.console` capability. Its retained
thumbnail transport validates the VM identity and
running state, captures a bounded console image through the local Hyper-V V2
provider, and applies only typed keyboard, mouse, or secure-attention input.
It resolves the provider's currently active VM setting object through the
documented `Msvm_SettingsDefineState` association instead of scanning the
host-wide settings collection.
Version 0.2.22 reads the validated contiguous image array with one bounded
copy, filters device queries to the exact VM, and targets a 150-ms console
cycle including work time. Busy hosts retain a minimum yield; this is not a
guaranteed frame rate. Existing console support starts with Agent 0.2.21.
Version 0.2.23 reuses the authenticated console HTTP transport and sends each
envelope with its headers. Pool entries are bound to the Gateway endpoint and
client certificate and invalidated on failure, identity change, or idle reuse.
Bootstrap retains its existing pin-before-body sequence.
Version 0.2.24 separates an ordered input worker from image capture/upload.
Only that worker may receive and apply typed input. Its acknowledgement receipt
survives transport failures and in-process worker restarts without replaying
applied events. A host or service process crash remains an explicit boundary,
not an exactly-once execution guarantee. Input methods use bounded
semisynchronous completion checks; local WMI connection/metadata calls can
still depend on provider health. An inactive response idles the worker.
Provider, image-array, and in-memory encoding failures are returned as bounded
codes so an administrator can distinguish compatibility failures without raw
WMI output or host details entering the portal.
The adapter keeps the MOF-level `uint16` range but supplies the frame dimensions
using the signed 32-bit Automation representation accepted by the Hyper-V WMI
method input object.
WMI service objects use their absolute path when available and fall back to
their provider-relative path, which is sufficient for local method execution.
The console uses the existing outbound mTLS channel and does not require guest
networking or guest credentials. It does not accept arbitrary WMI operations,
commands, scripts, paths, URLs, clipboard content, or device redirection.

## Software and update inventory

Windows reads machine-wide uninstall registration from both registry views and
bounded Windows Update history timestamps. It does not trigger Windows
Installer repair and does not start a Windows Update scan. Linux reads the
native dpkg database and uses a fixed, argument-only `apt-get` simulation to
derive pending package updates. Payloads are split into bounded pages before
they enter the common mTLS channel. See
[`CROSS-PLATFORM-SOFTWARE-INVENTORY.md`](../docs/architecture/CROSS-PLATFORM-SOFTWARE-INVENTORY.md).

## Linux installation

The Linux package contains the native binary, a hardened systemd unit, and an
installer. Its private key, certificate, and settings are stored under
`/var/lib/ipms-agent` with root-only permissions. See
[`LINUX-AGENT-INSTALLATION.md`](../docs/operations/LINUX-AGENT-INSTALLATION.md).

## Local configuration

`ipms-agent-config.exe` is the native **IPMS Agent Configuration** application.
The Windows installer registers it as the **Modify** action in Programs and
Features, adds an **IPMS Agent Configuration** item to All Control Panel Items,
and creates an IPMS Agent Start Menu entry. These Windows shell entries use the
Alvestrasza Corporation emblem. Programs and Features also displays the
publisher website and the estimated installed size. The application shows the
Windows service state, gateway transport intent, certificate enrollment state,
and built-in packs. An administrator can set the Management Server hostname,
the dedicated gateway port (default `9419`), and the future PKI trust mode.

Settings are written atomically to `%ProgramData%\Alvestrasza\IPMS Agent\agent-settings.ini`.
The versioned enrollment importer places a one-time bootstrap document into the
same protected directory without displaying its secret. The service consumes
and removes it after successful enrollment. See
`docs/operations/WINDOWS-AGENT-0.1.17-ENROLLMENT.md` for the complete flow.
The installer restricts that directory to `SYSTEM` and local Administrators.
The configuration application never displays or exports private keys. Until
Gateway enrollment is implemented, it truthfully reports `Not enrolled`; saving
settings does not claim that an mTLS connection was validated.

## Agent gateway

### Native Hyper-V console (Windows 0.2.26)

An explicitly selected `vmconnect` assignment opens an Agent-initiated mTLS
WebSocket on the fixed `/v1/hyperv-console-native` Gateway route. The immutable
session and stream-generation UUIDs are sent in fixed headers. This is separate
from the existing thumbnail transport; authentication, trust or protocol failures
never silently select another transport.

The Agent verifies the assigned VM GUID and exact name using fixed local WMI
metadata queries. It then validates the complete RDP preconnection PDU v2, with
zero flags/unused numerical ID and only the assigned GUID (optionally followed
by `;EnhancedMode=0`). Only after validation can bytes reach the compiled-in
`127.0.0.1:2179` endpoint. No hostname, port, credential, command or arbitrary
network target is accepted from a console payload. The broker handles host
authentication and explicit certificate trust; Agent enrollment is not host login.

The first valid Gateway lease is required before forwarding. Strict JSON lease
controls contain only `type`, `seconds` and `stream_generation`; durations are
1-15 seconds, generation must match, and an expired monotonic lease cannot be
revived. Replayed preconnection gates, oversized/invalid messages and changed
local identity fail closed. A binary message is at most 64 KiB, control messages
at most 256 bytes, and each direction has bounded buffering and backpressure.
There are no persisted display bytes, keystrokes or credentials.

One native attachment owns the frame worker. Gateway-controlled certificate
observation and authenticated display connections run sequentially, with a
500 ms minimum reconnect delay and a fresh assignment poll. Async callback
buffers remain owned until WinHTTP's final `HANDLE_CLOSING` notification;
another attachment cannot accumulate buffers before the previous one closes.
WebSocket upgrade is bounded by the initial 15-second deadline, preconnection
by 10 seconds, and local connect/write and Gateway write stalls by 2 seconds.
Service cancellation is checked throughout the I/O loop. A single independent,
read-only metadata worker checks the enrolled identity and local VM every five
seconds. Initial validation waits at most ten seconds; the relay closes if the
generation-bound last success becomes ten seconds old. No disk or WMI operation
runs inside the relay's lease/cancellation check. Delayed results cannot authorize
a replacement session, and requests replace one bounded slot instead of queuing.
A stuck COM provider is not forcibly cancelled: shutdown stops accepting work,
waits at most 100 ms for that worker, and otherwise lets its independently owned
state survive until the call returns or the service process exits. It never
retains socket ownership or causes additional metadata workers to be spawned.
This bounds socket/service shutdown without claiming that COM itself is bounded.
Inventory, telemetry and
the independent 10-second heartbeat remain on their existing separate workers.

The deterministic `native-console-guards` test covers every two-part PDU split,
wrong VM/mode/length/flags/ID/encoding, replay, control bounds, wrong generation,
duplicate JSON fields and non-monotonic/expired leases. It also proves that blocked
metadata cannot block lease expiry/worker stop and that stale-generation or
expired identity results cannot authorize a stream. These checks and a local
MSVC build do not establish live console rendering, host authentication, latency
or throughput acceptance. See [ADR-0011](../docs/architecture/ADR-0011-NATIVE-HYPERV-CONSOLE.md).

The Agent will initiate one persistent, mutually authenticated TLS connection
to the IPMS Agent Gateway on **TCP 9419**. It is bidirectional after
authentication: the Agent submits inventory and status while the gateway may
send signed Management Pack assignments, bounded collection requests,
certificate-rotation instructions, and signed update manifests. The Agent
never opens an inbound listener and never accepts commands, scripts, binaries,
or arbitrary update payloads through this channel.

TCP 9419 is the on-premises default. A future Cloud profile may use TCP 443
only as an explicitly configured egress fallback; it does not change the
on-premises gateway default.

## Build

Build with a current CMake release and a C++20 compiler. On Windows, use a Developer PowerShell for Visual Studio:

```powershell
cmake -S agent -B build/agent -G Ninja
cmake --build build/agent --config Release
ctest --test-dir build/agent --output-on-failure
```

The Windows target links only Windows SDK libraries. No package manager, runtime download, or third-party dependency is required for this foundation.

The Windows package also contains `ipms-agent-updater.exe`. It accepts only the
compiled `update` and `uninstall` lifecycle actions. It does not execute scripts,
shell commands, operator-provided paths, or arbitrary URLs. See
[`ADR-0006`](../docs/architecture/ADR-0006-AGENT-LIFECYCLE-CHANNEL.md).

## Windows installation

Run the versioned installer from an elevated PowerShell after verifying the
release artifact signature and hash. The script refuses to overwrite an
existing service and uses the Windows service default `LocalSystem` account.

```powershell
.\agent\scripts\install-windows-agent.ps1 -BinaryPath .\build\agent\ipms-agent.exe -ConfigBinaryPath .\build\agent\ipms-agent-config.exe -WhatIf
.\agent\scripts\install-windows-agent.ps1 -BinaryPath .\build\agent\ipms-agent.exe -ConfigBinaryPath .\build\agent\ipms-agent-config.exe
Get-CimInstance Win32_Service -Filter "Name='IPMS Agent'" | Select-Object Name, StartName, State
```

The uninstall script removes the service registration, Control Panel entry, and
Start Menu shortcut. It deliberately does not delete binaries, certificates,
or future agent state.

## Security boundary

The Windows service is designed to run as LocalSystem because read-only host and Hyper-V inventory can require privileged Windows APIs. LocalSystem is not permission to execute server-supplied commands. Management Packs are signed, versioned declarations that activate built-in capabilities only; they never contain executable code, PowerShell, or arbitrary command lines.

See [the agent contract](../docs/architecture/AGENT-CONTRACT.md) and [ADR-0002](../docs/architecture/ADR-0002-CXX-AGENT-AND-MANAGEMENT-PACKS.md).
