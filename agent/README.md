# IPMS Agent

The IPMS Agent is a native C++20 service for customer-managed Windows and Linux systems. It will establish an outbound, mutually authenticated connection to the IPMS Control Plane and collect only capabilities explicitly assigned to the enrolled device.

The initial implementation contains the pack registry and the read-only `windows-server-core` pack. The Windows executable can run in an interactive diagnostic mode with `--console` or as the `IPMS Agent` Windows service. It does not yet enroll, persist data, or send inventory to a Control Plane; those operations remain deliberately blocked until the enrollment and transport contracts are implemented.

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
