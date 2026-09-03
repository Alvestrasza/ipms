# Windows Agent Installation and Local Configuration

## Scope and current status

This runbook covers the native C++20 IPMS Agent for Windows Server and Windows
test systems. Agent build `0.1.36` provides:

- the `IPMS Agent` Windows service, installed as `LocalSystem`;
- the `windows-server-core` and `hyper-v-host` built-in read-only Management
  Pack declarations;
- a native `IPMS Agent Configuration` application;
- Programs and Features registration plus optional Control Panel and Start
  Menu integration on systems with the Windows shell; and
- local configuration for the Management Server hostname, TCP port, and PKI
  trust mode.

The Agent supports one-time enrollment with a non-exportable LocalMachine key,
outbound TCP 9419 mTLS transport, server-side inventory ingestion, and bounded
Windows and Hyper-V inventory collection. Signed update execution and a
release-grade MSI or equivalent installer remain incomplete.

## Build outputs

Build from a Visual Studio Developer PowerShell with a C++20 compiler and the
Windows SDK:

```powershell
cmake -S agent -B build/agent -G Ninja
cmake --build build/agent --config Release
ctest --test-dir build/agent --output-on-failure
```

The Windows build produces:

- `ipms-agent.exe` — console diagnostic host and Windows service executable;
- `ipms-agent-config.exe` — elevated local configuration application; and
- `ipms-agent-pack-tests.exe` — Management Pack and configuration contract
  tests.

The release build statically links the MSVC runtime. `ipms-agent.exe` and
`ipms-agent-config.exe` therefore require only Windows system libraries and do
not depend on a separately installed Visual C++ Redistributable. Release
acceptance must inspect the PE dependency table and reject imports of
`MSVCP140.dll`, `VCRUNTIME140.dll`, or `VCRUNTIME140_1.dll`.

The configuration executable embeds the Alvestrasza Corporation emblem as a
multi-resolution Windows icon and carries a `requireAdministrator` UAC
manifest. The source emblem remains the repository brand asset; the `.ico`
resource is a deterministic Windows packaging derivative.

## Test installation

Verify the release signature and digest before a packaged release is installed.
For the current source-build foundation, run the versioned script from an
elevated PowerShell:

```powershell
.\agent\scripts\install-windows-agent.ps1 `
  -BinaryPath .\build\agent\ipms-agent.exe `
  -ConfigBinaryPath .\build\agent\ipms-agent-config.exe `
  -WhatIf

.\agent\scripts\install-windows-agent.ps1 `
  -BinaryPath .\build\agent\ipms-agent.exe `
  -ConfigBinaryPath .\build\agent\ipms-agent-config.exe
```

The two executables must reside in the same installation directory. The
installer refuses to overwrite an existing service; a supported in-place
upgrade workflow is still pending. It uses well-known Windows security
identifiers rather than localized account names. If any step fails after
creating the service, it removes only the service and registrations created by
that invocation.

The service is registered with automatic start and the Windows built-in
`LocalSystem` identity. Installing as `LocalSystem` permits the read-only host
and Hyper-V APIs planned by the compiled capability registry; it does not
authorize arbitrary commands, scripts, PowerShell, SSH, or a remote shell.

## Windows shell integration and Server Core

The installer registers the following local entry points:

| Surface | Result |
| --- | --- |
| Programs and Features | `IPMS Agent`, A-Corp icon, publisher, version, website, computed size, Modify and Uninstall actions |
| All Control Panel Items | `IPMS Agent Configuration` with the A-Corp icon |
| Start Menu | `IPMS Agent Configuration` shortcut |

`-ShellIntegration Auto` is the default. It disables the Control Panel and
Start Menu registrations when `InstallationType` is `Server Core` or Explorer
is unavailable. The service, protected configuration directory, enrollment
importer, and uninstall registration remain available. Operators may select
`Enabled` or `Disabled` explicitly for controlled tests.

Programs and Features uses `https://www.alvestrasza.com` as the publisher
information URL. `EstimatedSize` is calculated in KiB from the service
executable, configuration executable, and installed uninstaller; it is not a
hard-coded workstation value.

The Control Panel namespace identity is
`{4B13D2F1-A647-4D4E-B0D7-7EE33E72F691}`. The class, icon, and open command are
machine-wide registrations. Windows may cache Control Panel and icon metadata;
close and reopen Control Panel after installation or upgrade before reporting
a missing item.

## Local settings

The application stores settings atomically at:

```text
%ProgramData%\Alvestrasza\IPMS Agent\agent-settings.ini
```

The installer removes inherited access and grants full control only to
`SYSTEM` and local Administrators. The application requests UAC elevation
before opening so it reads the protected effective configuration rather than
showing unauthenticated defaults.

The current settings are:

| Field | Meaning | Default |
| --- | --- | --- |
| `gateway_hostname` | IPMS Agent Gateway or Management Server DNS name | unset |
| `gateway_port` | Dedicated Agent Gateway TCP port | `9419` |
| `trust_mode` | PKI ownership and enrollment model | `ipms_managed` |

Supported trust-mode values are `ipms_managed`, `external_issuing_ca`, and
`external_certificates`. Selecting a trust mode does not enroll a certificate
in this foundation build.

Private keys, enrollment tokens, credentials, certificate bodies, and complete
certificate material must never be stored in this INI file or displayed by the
application. Once enrollment exists, the service owns the device key and the UI
receives bounded status through authenticated local IPC.

## Verification

After installation, verify from an elevated PowerShell:

```powershell
Get-CimInstance Win32_Service -Filter "Name='IPMS Agent'" |
  Select-Object Name, StartName, StartMode, State, PathName

Get-ItemProperty `
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\IPMSAgent' |
  Select-Object DisplayName, DisplayVersion, Publisher, URLInfoAbout,
    EstimatedSize, DisplayIcon, ModifyPath, UninstallString

Get-Acl "$env:ProgramData\Alvestrasza\IPMS Agent" |
  Format-List Owner, AccessToString
```

Acceptance must distinguish workstation shell integration from Server Core
service operation. Both require native compilation, contract tests,
`LocalSystem` registration, protected configuration storage, one-time
enrollment, service start, and an mTLS inventory cycle. Workstation acceptance
also verifies the optional Control Panel and Start Menu entry points. This does
not constitute signed-installer or production acceptance.

## Uninstall and preservation

Run the installed uninstaller or use Programs and Features from an elevated
session. It removes the service registration, Programs and Features entry,
Control Panel namespace, and Start Menu shortcut. It intentionally preserves
binaries, certificates, and Agent state so diagnostic or recovery material is
not silently destroyed.

Deleting preserved state requires a separate, explicit, reviewed operation.

## Related contracts

- [ADR-0002: Native C++ Agent and Management Pack Trust Model](../architecture/ADR-0002-CXX-AGENT-AND-MANAGEMENT-PACKS.md)
- [ADR-0003: Agent PKI and Enrollment Trust Model](../architecture/ADR-0003-AGENT-PKI-AND-ENROLLMENT.md)
- [ADR-0004: Local Agent Configuration and Control Panel Integration](../architecture/ADR-0004-LOCAL-AGENT-CONFIGURATION.md)
- [Agent contract](../architecture/AGENT-CONTRACT.md)
- [Agent PKI and mTLS Gateway operations](AGENT-PKI-AND-GATEWAY.md)
