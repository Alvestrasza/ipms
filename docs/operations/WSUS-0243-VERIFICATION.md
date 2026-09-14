# WSUS receiver 0.2.43 deployment verification

| Field | Value |
| --- | --- |
| Document version | 1.0.0 |
| Created / last modified | 2026-09-14 |
| Author | Alice Endelgard |
| Organization | Alvestrasza Corporation |
| Scope | Development deployment and bounded Agent acceptance |

Portal 0.2.43 and Windows Agent 0.2.30 were published from immutable source
`f010042d04eb3ec0c6dcab4d8bb2553931b93360`. The tags `v0.2.43` and
`windows-agent-v0.2.30` both resolve to that commit. The Windows package SHA-256 is
`771208b15b8d28a7417aa6edce1e9a2f3e2944cd2fb50ba8b3f2efb2539ecb47`.

## Build and database evidence

- The production Web Console build, TypeScript/Biome checks and seven browser
  cases passed. A fresh MSVC Release build passed 13 native tests with one
  existing privileged test skipped. Package membership, executable hashes,
  AMD64 architecture, system imports and three PowerShell scripts were checked.
- All 443 backend tests passed on PostgreSQL, with zero skips. Forward migration,
  reversal and reapplication also passed in disposable databases, which were
  removed after verification.
- The live receiver applied `discovery.0024_software_windows_update_evidence`,
  `updates.0001_initial` and `updates.0002_wsus_server_settings` as additive
  migrations. Receiver activation preceded the schema-2 Windows Agent rollout.

## Receiver activation

The first activation stopped at a post-migration permission check because
PostgreSQL evaluated `has_sequence_privilege` against a table before applying
the relation-type predicate. The deployment remained fenced with its previous
release link and protected recovery material intact.

A controlled forward recovery verified the backup digests, source, completed
migrations, ownership and permissions before activating the staged receiver.
Both sequence checks now guard the function call with `CASE WHEN relkind='S'`.
The corrected checks were also rerun in a read-only transaction against the
active database: exactly one owned application sequence and zero console-broker
sequence grants. Evaluation across matching tables, indexes and the sequence
completed without an invalid relation-type call.

All six Portal dependencies were active after activation. Version, readiness,
unauthenticated access controls, ingress and preserved configuration checks
passed. The authenticated Administration WSUS server page displayed version
0.2.43 and the expected hostname/IP, port and SSL controls.

## Windows Agent acceptance

The canary completed its ordinary Agent lifecycle update, reconnected as 0.2.30
and delivered a complete software inventory. The remaining server wave then
completed: all 25 Windows servers reported 0.2.30, successful update jobs, fresh
heartbeats and complete software inventories.

One older Windows client remained at 0.1.36 after an `update_failed` result.
Its downloaded replacement executable matched the published build. A bounded
local administrator repair was prepared with old-executable backup, hash and
service checks, enrollment/settings preservation and rollback. Its execution
and subsequent Portal acceptance remain open; the failed lifecycle result is
retained as history rather than rewritten.

## Linux appliance Agent acceptance

The existing Linux appliance Agent was built from the same immutable source.
Its transport version is 0.2.13; the shared CMake project version is 0.2.30.
All eight Linux native tests passed. The binary was checked against the actual
target libraries and is a development-host build, not a portable Linux release.

An initial immediate process check raced with systemd's `Type=simple` startup;
the old 0.2.1 binary was restored and fresh inventory confirmed recovery. After
adding a bounded wait for the expected executable, activation succeeded with
the new running binary hash, fresh 0.2.13 system and software inventories, and
three heartbeats spanning approximately 20 seconds. The enrolled identity,
service unit and all six other service states/process IDs remained unchanged.
Protected backups retain the previous executable and unit.

## Acceptance limits

Three Windows servers reported collected local Windows Update evidence with
zero identities; 22 reported that evidence as unavailable. This verifies
schema-2 inventory transport and conservative handling of absent evidence. It
does not demonstrate a positive installed-update GUID/revision match or patch
applicability against a live WSUS catalog.

No WSUS publisher or catalog was configured during this deployment. Real WSUS
metadata ingestion remains a separate acceptance step. Saving WSUS server
settings alone does not synchronize metadata. This release does not install OS
updates, change WSUS/GPO registration, schedule reboots or run remote scripts.
Private deployment receipts and recovery paths are intentionally kept outside
the repository.
