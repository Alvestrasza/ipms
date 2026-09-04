# Cross-Platform Software and Update Inventory

## Scope

IPMS 0.2.0 adds tenant-scoped installed-software and operating-system update
posture to the native Windows and Linux Agents. Collection is read-only and
fixed in the Agent binary. The Control Plane accepts inventory only from the
authenticated device identity over the Agent-initiated mTLS Gateway.

## Windows

The Agent reads machine-wide uninstall registration from the native 32-bit and
64-bit registry views. It does not query `Win32_Product`, invoke Windows
Installer, run PowerShell, or trigger an update scan. Windows Update history
registry timestamps are reported when present. Individual Windows package
update state remains `unknown` until a bounded source can determine it without
starting a scan or changing endpoint state.

## Linux

The Agent reads `/etc/os-release`, the dpkg package database, kernel and DMI
identity, network interfaces, and fixed mounted file systems. Pending package
updates are derived from a fixed `apt-get -s` invocation using direct process
execution without a shell. Output, time, page count, package count, and field
sizes are bounded. Update installation is outside this read-only scope.

## Transport and persistence

- Software documents use schema version 1.
- Package arrays are divided into pages below the Gateway message limit.
- All pages must use the same snapshot identifier and page count.
- Duplicate, missing, oversized, cross-tenant, and inconsistent inputs are
  rejected.
- Incomplete snapshots are not presented as current inventory.
- Secrets, command output, raw registry values, and package-manager logs are
  never stored in the inventory model.

## Security boundary

Neither platform exposes arbitrary commands, scripts, WMI queries, registry
paths, package-manager arguments, file paths, or collection intervals to the
Control Plane. New collection capability requires reviewed native code, a
versioned schema, negative tests, and a new signed Agent release.
