<!--
File Name: WSUS-METADATA-RECEPTION.md
Version: v0.2.1
Created: 2026-09-13
Last Modified: 2026-09-14
Author: Alice Endelgard
Organization: Alvestrasza Corporation
Description: Operate and connect the first bounded, read-only WSUS receiver.
-->
# WSUS metadata reception

Portal 0.2.43 adds **Windows updates** to the tenant sidebar at `/en/updates/wsus` and `/de/updates/wsus`. It prepares the IPMS Appliance to receive a WSUS catalog and compare it with authenticated Agent observations. The existing DMZ WSUS has no clients: catalog-only reception works without registering any managed server with WSUS. Portal and Agent deployment was accepted in DEV on 2026-09-14; configuring and validating the real WSUS publisher remains a separate step.

## Operator flow

1. Open **Administration → WSUS server** (`/en/administration/updates/wsus`, German `/de/administration/updates/wsus`). A tenant administrator or authorized connector operator creates a source with a name, exact catalog scope, WSUS host, port and HTTPS setting. Use a DNS name or an unbracketed IPv4/IPv6 address, without URL, credentials, path or embedded port. Defaults are port 8531 and HTTPS. Scope is immutable; use a separate source for a different pilot scope. Only authorized tenant readers can inspect its reports.
2. Transfer the one-time reception token to the reporting publisher through a protected secret channel. IPMS never displays it again. Do not include it in URLs, command-line arguments, diagnostics or repository files.
3. Configure the publisher to read the WSUS reporting API using read-only rights and send the contract below over certificate-validated HTTPS. Use `scripts/Export-IpmsWsusCatalog.ps1` for an explicit bounded pilot selection. WSUS itself does not automatically speak this protocol. The publisher owns collection/scheduling; IPMS requests no vendor content.
4. Reload received data in IPMS. Inspect catalog observation/receipt times and each Agent's local cache evidence. Open **View updates** for installed matches, revision differences and unknown entries. WSUS-reported states are optional and remain unknown when the WSUS has no clients.
5. Rotate the source token if delivery credentials are lost or replaced. A lost token-creation response is not safely retrievable; use rotation. Disable reception to stop imports while preserving historical evidence. Suspension of a tenant also blocks imports.

Server settings are stored per source and tenant and can be edited in Administration.
Saving them performs no connection test, DNS lookup, synchronization or download.
Apply the same host/port/HTTPS settings to the WSUS-side publisher. This push-based
receiver cannot configure that external publisher remotely. Changing the endpoint
clears the currently displayed catalog while retaining history and immutable
receipts. A new collection after the configuration change is required; replaying an
old receipt cannot republish it. Saving the same normalized settings preserves the
current report. The source credential remains valid until explicitly rotated.

## HTTP contract

Session endpoints use existing IPMS session/CSRF protection and `X-IPMS-Tenant-ID`. They reject publisher credentials.

| Method and path (under `/api/v1/`) | Purpose |
| --- | --- |
| `GET update-sources/` | Tenant sources; no tokens/hashes |
| `POST update-sources/` | `{name, scope, wsus_host, wsus_port, wsus_use_ssl}`; returns source plus token once |
| `PATCH update-sources/{source_id}/` | `{enabled: boolean}` and/or all three WSUS endpoint fields |
| `POST update-sources/{source_id}/rotate-token/` | Returns replacement token once |
| `GET update-sources/{source_id}/comparison/?page=1` | Server inventory vs latest complete WSUS report, 50 servers/page |
| `GET update-sources/{source_id}/servers/{server_id}/updates/?page=1` | Catalog revision states, 50 updates/page |

Publisher endpoint: `POST /api/v1/update-sources/{source_id}/snapshots/`, `Content-Type: application/json`, `Authorization: Bearer <reception-token>`. Tenant identity comes exclusively from the configured source credential. A session login alone cannot publish. The main Appliance's existing HTTPS ingress routes this API to Django; no new inbound Agent port is introduced.

Success is `201` for a new complete snapshot or `200` with `duplicate: true` for an identical retained receipt. The response includes original snapshot/observation/receipt metadata. Receipt time is not client scan time. Responses containing credentials have `Cache-Control: no-store`.

Errors use the existing sanitized `error.code` envelope: `400` for invalid fields, incomplete data or source-scope mismatch, `401` for invalid/revoked/disabled-source or suspended-tenant credentials, `409` for changed snapshot reuse, out-of-order observations or exhausted receipt capacity, and `413` for oversized JSON. Failed validation preserves the last accepted snapshot. API field validation deliberately does not echo raw payloads.

Source reads return `wsus_host`, `wsus_port` and `wsus_use_ssl`. Existing sources
default to an empty host, port 8531 and HTTPS until explicitly configured. Legacy
`{name, scope}` source creation remains accepted. When supplied, endpoint fields
must be provided together: a nonempty host up to 253 characters, an integer port
from 1 to 65535, and a JSON boolean for HTTPS. This is a configuration record, not
proof of the sender's WSUS identity or network reachability. The reception token
continues to authenticate the publisher.

## Snapshot schema v1

For a download-only WSUS, send `computers: []`. Do not fabricate computer reports from catalog presence or expected OS versions. The optional computer example below describes the additional reporting path only if a future source actually has registered clients.

All fields shown are required; unknown fields and duplicate JSON keys are rejected. Lists may be empty; empty catalog/report coverage is explicitly unknown. `snapshot_id` must be a UUID persisted by the producer for retry. Use a new UUID and strictly newer `observed_at` only for a new collection. All dates need an explicit UTC offset; use UTC `Z`. Up to five minutes of future clock skew is allowed for observation. `reported_at` must not exceed observation and is `null` when WSUS has never received a status report.

```json
{
  "schema_version": 1,
  "snapshot_id": "b82cc832-6249-44a8-9c79-758b77262774",
  "observed_at": "2026-09-13T10:00:00Z",
  "complete": true,
  "scope": "Windows Server security pilot",
  "updates": [
    {
      "update_id": "97acaa21-c076-46d9-b60b-d6f1985978f8",
      "revision": 1,
      "title": "Synthetic security update for contract illustration",
      "kb_articles": ["1234567"],
      "products": ["Windows Server"],
      "classification": "Security Updates",
      "severity": "Critical"
    }
  ],
  "computers": [
    {
      "computer_id": "42c13cfb-a4f8-4cbc-8378-0e5672e4b5de",
      "fqdn": "server.example.invalid",
      "reported_at": "2026-09-13T09:30:00Z",
      "updates": [
        {
          "update_id": "97acaa21-c076-46d9-b60b-d6f1985978f8",
          "revision": 1,
          "state": "not_installed"
        }
      ]
    }
  ]
}
```

These GUIDs/KB/product descriptions are synthetic and are not Microsoft update identifiers. A real producer must use WSUS identities and original report times.

Bounds: 1,048,576 request bytes; 1,000 unique catalog `(update_id, revision)` pairs; 500 unique computer UUIDs; at most 1,000 cells per computer and 10,000 cells total. Maximum title 512 characters; 20 KB references of 1–12 digits; 20 product names of up to 128 characters; classification 128; severity 32; source name 128; scope 255. FQDNs use full DNS names (ASCII/punycode) with case/trailing-dot normalization, never short names. At most 20 sources per tenant and 10,000 immutable receipts per source. Do not split a single complete snapshot into multiple posts: later snapshots replace the declared scope. Staged large-catalog synchronization is separate work.

## WSUS producer mapping

The prepared exporter accepts `-WsusServer`, `-WsusPort` (8531 by default), `-WsusUseSsl` (true by default), `-UpdateId` (an explicit GUID selection), `-Scope` and `-OutputPath`. Match these values to the settings saved in Administration; for a WSUS reporting endpoint using HTTP, specify its port and `-WsusUseSsl:$false`. The IPMS reception endpoint always uses HTTPS. The exporter resolves the actual latest revision of each selected GUID and writes a new bounded UTF-8 file with `computers: []`; it refuses to overwrite existing files. No automatic selection, approvals, content downloads or WSUS synchronization are performed.

Optional `-ReceptionUri` and `-TokenFile` send the same bytes to the fixed HTTPS source endpoint. The credential comes from a protected file, not a command-line token value. Redirects are disabled. On uncertain delivery preserve and retransmit that exact completed file/snapshot ID rather than collecting a new observation merely to retry. Provider failures and oversized metadata abort instead of silently truncating. Only PowerShell syntax has been checked locally; WSUS assembly/API execution remains live acceptance work.

Use `Microsoft.UpdateServices.Administration` on a supported Windows WSUS/reporting host. No SQL access to SUSDB and no remote PowerShell initiated by IPMS are required. Read-only reporting under the WSUS Reporters role is sufficient for the intended API access; validate the exact deployment's API/security configuration.

| IPMS field | WSUS reporting evidence |
| --- | --- |
| `update_id`, `revision` | `IUpdate.Id.UpdateId` and `RevisionNumber`; pin a concrete revision >= 1 |
| `title`, `kb_articles`, `products` | `Title`, `KnowledgebaseArticles`, `ProductTitles` |
| `classification`, `severity` | `UpdateClassificationTitle`, `MsrcSeverity.ToString()` |
| `computer_id`, `fqdn` | `IComputerTarget.Id` (GUID-shaped string), `FullDomainName` |
| `reported_at` | `LastReportedStatusTime` in UTC; `DateTime.MinValue` means null |
| Per-computer update state | `GetUpdateInstallationInfoPerUpdate(UpdateScope)` |

`IUpdateInstallationInfo.UpdateId` is a GUID, not a revision identity. Resolve `GetUpdate().Id` and require the exact catalog GUID/revision; report unknown if that identity cannot be established. Do not attach a latest-catalog revision to a GUID-only old status. The standard UpdateScope does not have an UpdateIds filter; bounding output by a configured ID list alone does not bound the WSUS server query. Handle API result limits and provider failures explicitly; never mark an incomplete/truncated query complete.

| Microsoft state | JSON state |
| --- | --- |
| Unknown | `unknown` |
| NotApplicable | `not_applicable` |
| NotInstalled | `not_installed` |
| Downloaded | `downloaded` |
| Installed | `installed` |
| Failed | `failed` |
| InstalledPendingReboot | `installed_pending_reboot` |

Missing catalog cells stay unknown. A downloaded update is still missing installation; pending reboot is not complete. WSUS currency applies only to the explicit catalog scope and evidence time. It does not prove independent Agent agreement or current global Microsoft compliance.

## Deployment and acceptance

### Agent evidence without WSUS enrollment

Windows Agent candidate 0.2.30 adds `windows_update_evidence` to software schema `"2"`, repeated consistently across every page. Example observation (identities are synthetic):

```json
{
  "source": "wua-local-cache",
  "status": "collected",
  "observed_at": "2026-09-13T10:00:00Z",
  "updates": [{"update_id": "97acaa21-c076-46d9-b60b-d6f1985978f8", "revision": 1}]
}
```

Only complete authenticated Agent snapshots are visible. Invalid sources, inconsistent page evidence, duplicates, missing collection time and positive results with `unavailable`/`limit-exceeded` are rejected. Collection is bounded at 128 identities; failed/over-limit observations produce no partial positives. Older schema-1 Windows and Linux Agents remain supported and have no installed Windows update evidence.

The worker uses `Online=false` and a fixed installed-software search in an isolated subprocess. It cannot alter WSUS/GPO configuration or install/download updates. Exact GUID/revision matches mean installed evidence in the local cache; other revisions are explicit mismatches; absent entries remain unknown. Old observations are marked stale. This is not an applicability scan against the complete latest Microsoft catalog and cannot prove that absent entries need installation.

### Release sequence

Also apply the additive `discovery.0024_software_windows_update_evidence` migration before deploying a schema-2 Windows Agent. Deploy the receiving Control Plane before Agents so older receivers never receive the new schema. No existing Agent needs immediate upgrade merely to receive a WSUS catalog.

Apply the additive `updates.0001_initial` and `updates.0002_wsus_server_settings` migrations with the normal release process and include the `updates` app in the deployed settings. Keep PostgreSQL as the supported runtime database and the Control Plane's current network restrictions. No secret/environment variable is added merely by installing the code; a source token is created only through authorized configuration. Keep Authorization headers and request bodies out of access/debug logs. The existing ingress 1 MiB request cap matches the application cap.

Before live acceptance: validate the receiver with the real WSUS publisher, actual server FQDNs and original report times; verify its read-only role and absence of update installation/download traffic; rehearse token rotation and failures; verify PostgreSQL locking and migration rollback using a disposable database. Do not run SQLite/e2e settings on an Appliance. Rolling back the code can leave these additive tables in place; reversing this new migration deletes WSUS metadata and must not be confused with a non-destructive application rollback.

Local verification status is reported with the candidate, separately from deployment. No live source, Agent update, WSUS setting, server reboot or patch approval is changed by preparation.

### Local verification on 2026-09-13

Application candidate 0.2.43 and Windows Agent candidate 0.2.30 passed these
checks on the development workstation:

- Django suite after Administration settings: 443 cases, 432 passed and 11 skipped; includes all 31 WSUS
  cases. Isolated SQLite settings cover metadata validation, tenant and source
  authorization, token lifecycle, atomic failure, immutable receipt reuse,
  catalog-only reception, authenticated Agent evidence, server-setting persistence
  and validation, catalog reset after endpoint changes and conservative comparison.
- Migration drift check: no changes detected.
- Web Console: production build, TypeScript and targeted Biome checks passed.
  Seven browser cases passed; real isolated persistence covers the catalog-only
  workflow, source lifecycle, pagination, Administration save/edit/reload,
  endpoint validation and reader/platform-administrator denial. One case injects an
  HTTP transport failure. See [Console testing](../../apps/web-console/tests/CONSOLE-TESTING.md)
  for the fixture setup and registered WSUS suite.
- Native MSVC build: successful. Thirteen CTest cases passed; one existing
  protected-journal test skipped for lack of an administrator/LocalSystem token.
  The new evidence test exercises actual bounded child-process pipe delivery,
  invalid/oversized/nonzero-exit responses and timeout, using synthetic data.
- Exporter: PowerShell parser check passed; no WSUS API was called.

Run the backend suite from `services/control-plane` with `PYTHONPATH=src`:

```text
python manage.py test ipms.apps.core ipms.apps.tenancy ipms.apps.audit ipms.apps.discovery ipms.apps.agent_pki ipms.apps.updates --settings=ipms_control_plane.settings.test
python manage.py makemigrations --check --dry-run --settings=ipms_control_plane.settings.test
```

Run the native tests with `ctest --test-dir <configured-agent-build> --output-on-failure`
after building the Agent with the repository CMake setup. These checks do not
establish live WSUS, real target WUA, PostgreSQL or deployed Appliance acceptance.

### DEV deployment acceptance on 2026-09-14

Portal 0.2.43 and all 26 Windows Agents at 0.2.30 were verified after deployment.
All 443 backend tests passed on PostgreSQL with zero skips, including separate
disposable forward/reverse/reapply migration checks. Fresh Agent inventories,
service health and authenticated Administration settings were confirmed. The
existing Linux appliance Agent was separately updated to transport 0.2.13; this
does not implement phase-2 Linux patch management.

Three Windows servers collected zero local WUA identities, one client supplied
17 identities and 22 servers reported evidence unavailable. A real WSUS catalog
has not yet been received. These observations do not establish live update
applicability or complete server compliance. See the [deployment verification
record](WSUS-0243-VERIFICATION.md) for the exact source, recovery, client repair
and acceptance boundaries. The workstation-only results above remain historical.

## Primary references

- [WUA fixed offline search](https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nn-wuapi-iupdatesearcher)

- [IComputerTarget API](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa354292(v=vs.85))
- [Installation-state values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsusar/4d0adf02-5015-43bb-8aa0-d50c598c16f6)
- [Update identity on installation info](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/aa352319(v=vs.85))
- [Read-only WSUS access](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms744593(v=vs.85))
