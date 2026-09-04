# IPMS Agent

The IPMS Agent is a native C++20 service for customer-managed Windows and Linux systems. It will establish an outbound, mutually authenticated connection to the IPMS Control Plane and collect only capabilities explicitly assigned to the enrolled device.

The implementation contains the pack registry and fixed read-only Windows and
Linux inventory capabilities. Windows build 0.2.19 and Linux build 0.2.12
include native services and bounded, paged installed-software and
update-posture inventory. Both platforms
use the same Agent-initiated TCP 9419 enrollment and mTLS trust boundary. The
Windows executable also reports roles/features and local Hyper-V VMs. Its
Hyper-V pack accepts only fixed start, graceful shutdown, stop, pause, and
resume assignments for an exact VM GUID; it never invokes `Win32_Product`,
PowerShell, or a server-supplied query or method.

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

Agent 0.2.19 provides the compiled-in `hyperv.vm.console` capability. For one
Control Plane lease-bound session, the Agent validates the VM identity and
running state, captures a bounded console image through the local Hyper-V V2
provider, and applies only typed keyboard, mouse, or secure-attention input.
It resolves the provider's currently active VM setting object through the
documented `Msvm_SettingsDefineState` association instead of scanning the
host-wide settings collection.
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
