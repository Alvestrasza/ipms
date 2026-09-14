<!--
File Name: CROSS-PLATFORM-SOFTWARE-INVENTORY.md
Version: v0.2.0
Created: 2026-09-04
Last Modified: 2026-09-13
Author: Alice Endelgard
Organization: Alvestrasza Corporation
Description: Native software inventory and versioned local Windows update evidence.
-->
# Cross-Platform Software and Update Inventory

## Scope

IPMS 0.2.0 adds tenant-scoped installed-software and operating-system update
posture to the native Windows and Linux Agents. Collection is read-only and
fixed in the Agent binary. The Control Plane accepts inventory only from the
authenticated device identity over the Agent-initiated mTLS Gateway.

## Windows

The Agent reads machine-wide uninstall registration from the native 32-bit and
64-bit registry views. It does not query `Win32_Product`, invoke Windows
Installer, run PowerShell, or trigger an online update scan. Windows Update history
registry timestamps are reported when present. Individual Windows package
update state remains `unknown` until a bounded source can determine it without
changing endpoint state.

Windows Agent candidate 0.2.30 additionally queries the local WUA cache for
installed software-update GUIDs and exact revisions. A fixed offline query runs
inside an isolated child process with a 15-second deadline, a 12 KiB output
limit and a maximum of 128 identities. Failed or oversized collections expose
no partial positive results. The query does not register a WSUS client, change
update sources or policies, or download/install updates. The observation time
is the local cache query time, not a new scan against Microsoft.

The [WSUS comparison](ADR-0014-WSUS-METADATA-RECEPTION.md) matches this evidence
against the received catalog, including catalogs without WSUS computer reports.
Absent identities remain unknown; they do not prove applicability or missing
installation. This evidence does not change the existing package update state.

## Linux

The Agent reads `/etc/os-release`, the dpkg package database, kernel and DMI
identity, network interfaces, and fixed mounted file systems. Pending package
updates are derived from a fixed `apt-get -s` invocation using direct process
execution without a shell. Output, time, page count, package count, and field
sizes are bounded. Update installation is outside this read-only scope.

## Transport and persistence

- Linux and older Windows software documents use schema version `"1"`.
- Windows candidate 0.2.30 uses schema version `"2"`, adding the bounded
  `windows_update_evidence` object documented in the
  [reception protocol](../operations/WSUS-METADATA-RECEPTION.md). Deploy the
  receiving Control Plane and additive database migration before this Agent.
- Package arrays are divided into pages below the Gateway message limit.
- All pages must use the same snapshot identifier and page count.
- Schema-2 evidence must also agree across all pages of a snapshot.
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
