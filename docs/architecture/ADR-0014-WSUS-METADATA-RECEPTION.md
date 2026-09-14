<!--
File Name: ADR-0014-WSUS-METADATA-RECEPTION.md
Version: v0.2.0
Created: 2026-09-13
Last Modified: 2026-09-13
Author: Alice Endelgard
Organization: Alvestrasza Corporation
Description: First read-only WSUS ingestion and inventory comparison boundary.
-->
# ADR-0014: WSUS metadata reception and server comparison

Status: local candidate for the first read-only integration slice; live WSUS and deployment acceptance pending.

## Context

[Epic #25](https://github.com/Alvestrasza/ipms/issues/25) separates IPMS orchestration from update content downloads on a dedicated DMZ host. The first requested implementation receives WSUS metadata and compares reported installation states with known Windows servers. It does not implement the complete epic or close architecture #26, distribution #27 or Windows deployment #30.

## Decision

The user clarified that the existing DMZ WSUS downloads Microsoft updates but has no registered clients. Catalog-only reception (`computers: []`) is therefore the primary workflow. Managed servers do not need to register with WSUS. Server-side evidence comes from IPMS Agents.

Add a tenant-bound `updates` application to the existing Django Control Plane. A separately configured WSUS-side publisher sends a complete, normalized, explicitly scoped metadata snapshot to one fixed HTTPS endpoint. No WSUS endpoint credentials, download URL, update binary, executable task or raw provider response is accepted. The Control Plane makes no outbound WSUS or vendor request.

```text
WSUS read-only reporting API -> publisher -> HTTPS metadata reception -> IPMS database
                                                                        |
Native Agent inventory -------------------------------------> tenant comparison UI
```

The publisher uses a random source-bound reception token, stored hashed in IPMS, and has only metadata-write authority. A token cannot read inventory, configure sources, select a different tenant or submit jobs. Rotation/disable and tenant suspension revoke reception. Configuring sources requires an active tenant principal with `connectors.manage`; comparison requires `inventory.view`. Session mutations retain CSRF checks. The existing native Agent identity and mTLS channel are unchanged; this is a separate reporting-source credential, not an Agent management capability.

Each source has an immutable scope description. Catalog entries use the exact Microsoft update GUID and revision, not KB alone. Computer reports retain WSUS computer identity, normalized FQDN and the client's original report time. Successful transfer does not refresh old client evidence.

Tenant Administration records each source's WSUS host, port and HTTPS setting.
This is publisher configuration metadata; saving it makes no network request and
does not prove reachability or sender origin. The publisher must be configured
with the same values separately. Changing this endpoint resets the current catalog
pointer without deleting historical receipts and requires an observation collected
after the change. Identical settings preserve current data; replaying an old receipt
cannot restore it after a change. The existing source credential remains valid
until explicitly rotated. Legacy sources can retain an unset host until configured.

Validate the entire snapshot before an atomic publish under tenant/source row locks. Repeated identical snapshot IDs return the original receipt. Changed reuse, out-of-order observations and changed source scope are rejected. Preserve the last three full payloads and compact immutable receipts for older snapshots, up to 10,000 receipts per source; exhausting the limit blocks new import with an explicit error. Tenant limits and request/record limits bound the pilot. There is no silent truncation.

Match reports only to a unique normalized full DNS name inside the selected tenant. Include ordinary Windows servers and Domain Controllers, exclude Windows clients. Duplicate inventory FQDNs or duplicate WSUS reports with the same FQDN stay ambiguous. No inventory record is rewritten by reception.

Reported states and missing cells are preserved. Missing rows, empty catalogs, missing report timestamps and stale observations cannot prove currency. The 24-hour freshness threshold is explicit. `current` means all entries in this source's received catalog scope are reported installed/not applicable by WSUS; it is not global patch compliance or independent verification by the Agent. Failed/pending-reboot/missing counts can coexist with unknown entries and are displayed separately.

The new native Agent reads installed software-update identities from the local WUA cache with a fixed offline query, without changing its update source or policies. An isolated subprocess bounds runtime and output. Partial, failed and over-limit collections do not produce positive evidence. Software envelope schema 2 sends exact GUID/revision observations over the existing authenticated Agent channel; schema 1 remains accepted with no such evidence. Observation time is local cache query time, not the time of a new Microsoft scan. Exact installed matches, revision differences and unknown entries are shown separately from optional WSUS client reports. Missing evidence cannot prove that an update is applicable or missing.

Generic Agent scan/posture fields remain separate. No subtraction of counts or inference from OS build/package names is performed. Existing deployed Agents gain the new evidence capability only through a separately accepted rollout.

## Consequences and limits

- WSUS does not natively POST this IPMS format. `scripts/Export-IpmsWsusCatalog.ps1` prepares an explicit pilot selection and optional HTTPS transfer through the reporting API. Its WSUS execution requires live acceptance.
- This initial bounded pilot uses a maximum 1 MiB complete snapshot, 1,000 catalog revisions, 500 computers and 10,000 state cells. Larger deployments require staged/paged synchronization under #27, not truncated reports represented as complete.
- Retained snapshots provide evidence, not backup or patch rollback. API reads lock the source during projection; separate browser requests may see a later complete snapshot.
- No installation, update-content download, reboot, online scan trigger, WSUS approval change, GPO change, scheduler or remote script interface exists in this slice. The fixed offline cache query is local Agent inventory.
- Validate PostgreSQL locking, deployed ingress/authentication and actual WSUS export semantics separately from SQLite tests and local browser acceptance. This slice does not claim database RLS acceptance.
- Dedicated DMZ binary distribution, a production publisher identity profile and long-term archive/reset workflows remain later work.

## References

- [Reception protocol and operations](../operations/WSUS-METADATA-RECEPTION.md)
- [Microsoft WSUS installation states](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsusar/4d0adf02-5015-43bb-8aa0-d50c598c16f6)
- [Microsoft IComputerTarget](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa354292(v=vs.85))
- [Agent contract](AGENT-CONTRACT.md)
