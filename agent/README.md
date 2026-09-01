# IPMS Agent

The IPMS Agent is a native C++20 service for customer-managed Windows and Linux systems. It will establish an outbound, mutually authenticated connection to the IPMS Control Plane and collect only capabilities explicitly assigned to the enrolled device.

The initial implementation contains the pack registry and the read-only `windows-server-core` pack. The Windows executable can run in an interactive diagnostic mode with `--console` or as the `IPMS Agent` Windows service. It does not yet enroll, persist data, or send inventory to a Control Plane; those operations remain deliberately blocked until the enrollment and transport contracts are implemented.

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
.\agent\scripts\install-windows-agent.ps1 -BinaryPath .\build\agent\ipms-agent.exe -WhatIf
.\agent\scripts\install-windows-agent.ps1 -BinaryPath .\build\agent\ipms-agent.exe
Get-CimInstance Win32_Service -Filter "Name='IPMS Agent'" | Select-Object Name, StartName, State
```

The uninstall script removes only the service registration; it deliberately
does not delete binaries, certificates, or future agent state.

## Security boundary

The Windows service is designed to run as LocalSystem because read-only host and Hyper-V inventory can require privileged Windows APIs. LocalSystem is not permission to execute server-supplied commands. Management Packs are signed, versioned declarations that activate built-in capabilities only; they never contain executable code, PowerShell, or arbitrary command lines.

See [the agent contract](../docs/architecture/AGENT-CONTRACT.md) and [ADR-0002](../docs/architecture/ADR-0002-CXX-AGENT-AND-MANAGEMENT-PACKS.md).
