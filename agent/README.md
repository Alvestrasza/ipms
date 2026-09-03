# IPMS Agent

The IPMS Agent is a native C++20 service for customer-managed Windows and Linux systems. It will establish an outbound, mutually authenticated connection to the IPMS Control Plane and collect only capabilities explicitly assigned to the enrolled device.

The initial implementation contains the pack registry and the read-only `windows-server-core` pack. The Windows executable can run in inventory-only diagnostic mode with `--console`, perform one bounded connection cycle with `--run-once`, or run as the `IPMS Agent` Windows service. Version 0.1.17 enrolls with a non-exportable LocalMachine ECDSA P-256 key, validates the one-time Gateway certificate pin, installs the dedicated Agent trust chain, and sends bounded inventory through TLS 1.3 and mTLS. Version 0.1.27 adds installed Windows Server roles, role services, and features to that inventory. Version 0.1.28 makes the installer language-independent, automatically omits shell integration on Windows Server Core, and rolls back newly created service artifacts when installation fails. Version 0.1.29 statically links the MSVC runtime so a minimal Windows Server Core installation does not require a separately installed Visual C++ Redistributable. Version 0.1.30 retries enrollment every ten seconds until the first inventory succeeds, while retaining the five-minute steady-state inventory interval. Version 0.1.31 normalizes unavailable Windows adapter link-speed sentinels so Hyper-V inventory remains valid. Version 0.1.32 adds the native fixed-action lifecycle updater, device-bound artifact retrieval, independent digest verification, rollback, and result reporting. Version 0.1.33 keeps the Server Manager query bounded to one minute while allowing slow provider initialization to complete. Version 0.1.34 waits for the service process to exit, retries bounded file replacement locks, reports terminal failure paths, restores the service after failed updates, and stages its hardened update runner from the current Agent binary so future lifecycle updates do not depend on an outdated helper executable. Version 0.1.35 adds bounded, non-sensitive failure classification for Windows Server role and feature collection so provider, timeout, result, and payload failures can be distinguished without exposing raw host diagnostics.

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
