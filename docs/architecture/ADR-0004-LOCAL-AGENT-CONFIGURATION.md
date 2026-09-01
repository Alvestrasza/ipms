# ADR-0004: Local Agent Configuration and Control Panel Integration

- Status: Accepted
- Date: 2026-09-01
- Decision owners: IPMS maintainers
- Scope: Windows IPMS Agent configuration surface

## Context

The IPMS Agent runs as `LocalSystem` to collect the explicitly permitted,
read-only Windows and Hyper-V inventory. Administrators still need a clear,
local way to inspect the Agent and set its Management Server endpoint and PKI
trust choice. A service account must not make those settings remotely mutable
outside the signed Agent protocol.

The product also needs a familiar Windows entry point. A service alone is hard
to inspect, and a generic Control Panel extension would be disproportionate for
the initial release.

## Decision

Ship a native Win32 companion application named **IPMS Agent Configuration**.
The Windows installer exposes it through:

- the Programs and Features `Modify` action;
- an **IPMS Agent Configuration** item in Control Panel, using the Alvestrasza
  Corporation emblem; and
- an `IPMS Agent Configuration` Start Menu shortcut.

The Programs and Features entry also publishes the configuration executable as
its icon, the Alvestrasza Corporation website, and an estimated
installed size derived from the installed Agent files.

The application displays service installation and running state, configured
Management Server hostname, the dedicated Agent Gateway port (default `9419`),
the selected PKI trust mode, intended agent-initiated bidirectional mTLS
transport, enrollment/certificate status, and built-in Management Packs.

The application carries a `requireAdministrator` Windows manifest because the
settings directory is intentionally unavailable to filtered, non-elevated
tokens. Configuration is written atomically to
`%ProgramData%\Alvestrasza\IPMS Agent\agent-settings.ini`. The installer
creates that directory with access limited to `SYSTEM` and local
Administrators. No private key, enrollment secret, or complete certificate
material is placed in the UI or settings file.

From 0.1.17, the UI derives a minimal enrolled/not-enrolled indication from the
protected public Agent state. Gateway enrollment and mTLS are owned by the
LocalSystem service. Saving a hostname, port, or trust mode remains a local
configuration action and never exports or replaces private key material.

## Consequences

This creates a discoverable and supportable local configuration surface without
requiring an MSI custom Control Panel extension. The installer can later be
replaced by an MSI/MSIX package while retaining the same executable and
settings contract.

When enrollment exists, the service must own the private key and expose status
to this application through authenticated local IPC. The UI may then display a
certificate subject, issuer, expiry, and a shortened public fingerprint. It
must not display, export, or accept private keys. A trust-mode change must
require explicit re-enrollment and retain the last known-good connection
configuration until validation succeeds.

This decision does not authorize remote shell access, scripts, PowerShell, SSH,
or arbitrary commands. All Agent capabilities remain constrained by signed,
versioned Management Packs and compiled-in allow-lists.

## Verification

- Build `ipms-agent-config.exe` with the native C++20 Windows build.
- Verify the installer creates the LocalSystem service, protected configuration
  directory, Start Menu entry, and Programs and Features registration.
- Verify every shell entry requests UAC elevation before reading or changing
  configuration.
- Verify that no private key or enrollment secret is present in the settings
  file or UI.
