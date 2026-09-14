<!--
File Name: LOGS-POLICY-0250-VERIFICATION.md
Version: v0.2.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Tenant policy workspace separation and centralized history acceptance.
-->
# Policy workspaces and Logs, Portal 0.2.50 and 0.2.51

The domain administration page now contains domain DNS names and Tier 0/1/2
OU mappings. The Security Baseline page owns the configured-domain selector,
GPO naming template, ordered baseline composition and explicit unlinked pilot
import. Each editor preserves the fields managed by the other workspace and
uses the existing revision check; concurrent changes cannot silently overwrite
one another. A selected baseline preselects a compatible import component.

The new Logs navigation contains Agents, Baselines, BMC communication and BMC
events. The former BMC URLs redirect while preserving filters. Baseline scan
and GPO import histories are removed from their action panels; those panels
link to Logs, including the exact pilot request when local approval is needed.
Current inventory freshness and assessment validity remain current-state
metadata, rather than additional chronological histories.

## Read and export contract

`GET /api/v1/logs/agents/` combines Agent maintenance, Windows deployment,
baseline scans, GPO pilot imports, Hyper-V power and Hyper-V management jobs.
`GET /api/v1/logs/baselines/` selects scans and GPO imports. Both preserve
the tenant boundary and each source's existing read permission. Hiding a
baseline does not erase or hide its historical jobs. Revoked or removed
enrollments retain their history. No history GET expires, claims or updates
jobs. Status is the recorded job state; displaying a history never acts as a
worker or a recovery operation.

Filters include operation type, status, search, baseline, domain, Agent identity
and request date range. A date without a time zone is accepted only in the
`YYYY-MM-DD` form and denotes a UTC day; the end date includes the entire day.
Full timestamps must include a time zone. Sortable columns include request
time, completion time, system, operation type and status. Kind and request ID
provide a stable tie break, with missing completion times last. Pagination
supports 25, 50 or 100 rows. Invalid or repeated query parameters are rejected.

The corresponding `/export/` endpoints export the full filtered, sorted result,
independent of the current page. CSV uses UTF-8 with BOM, quoted fields and
spreadsheet formula protection, including leading whitespace or control
characters. More than 10,000 matching rows returns
`log_export_limit_exceeded`; the user must narrow the filters. BMC list/export
uses the same allowed ordering, including severity level and missing dates
last. Existing BMC lists retain their explicit 500-row display limit.

Only named job metadata is selected for combined lists and CSV. Assignment
documents, result payloads, credentials, certificate material and command
parameters are excluded. `GET /api/v1/logs/gpo-imports/<uuid>/` separately
requires domain-management permission and exposes the existing exact-request
approval document only while it remains eligible for approval. It is never
included in CSV.

## Verification

The initial new API test returned HTTP 404 against the prior source, establishing
the missing behavior. The ten new job-log API tests then passed on local
Python 3.12/SQLite. They exercise all six source types, permission and tenant
boundaries, invalid dates and duplicate filters, stable cross-source pagination,
list/export parity, preserved hidden-baseline history, formula escaping,
explicit export limits and the absence of SQL writes during reads.

The broader local Control Plane run completed 544 tests with 11 platform-specific
skips before the final pagination regression was added. The final 17 core tests,
including all ten new log cases, passed. BMC ordering, export and adapter checks
passed. The final production Next build and TypeScript checks passed.

All 27 isolated browser tests passed against the actual Portal and Django API.
They cover separate editors and concurrent revision conflicts, policy draft
preservation, scan-to-log navigation, permission boundaries, URL filters,
sorting, pagination, the complete 30-row filtered CSV download, protected pilot
details and clipboard copy, BMC redirects and export limits. German mobile
accessibility passed after correcting the filter button contrast. Desktop and
mobile screenshots were inspected. Synthetic jobs never reached a live Agent.

The first supported PostgreSQL run executed all 545 tests and found one test
fixture error: a BMC integration case attempted to store NUL in a text column,
which PostgreSQL rejects. That fixture now uses a representable control
character; the pure CSV safety tests continue to cover NUL. No application
behavior was changed by this correction. The failed isolated test database
was removed normally. The corrected complete rerun passed all 545 tests in
171.440 seconds on Python 3.14.4/PostgreSQL 18.6 with zero skips. It ran as the
actual Control Plane OS account in an isolated PostgreSQL cluster, using only
synthetic data. Its test database was removed and its cluster stopped before
the source-bound acceptance receipt was issued.

Private evidence: `build/logs-0250-backend-before.log`,
`build/logs-0250-backend.log`, `build/logs-0250-full-backend.log`,
`build/logs-0250-core-final.log`, `build/logs-0250-web-build-final.log`,
`build/logs-0250-browser-final.log`,
`build/security-baseline-e2e/2026-09-14T21-57-38-469Z`.

## Deployment boundary

No schema migration, Agent binary, policy package or service credential change
is required. This software change does not create directory objects, import or
link a GPO, change firewall rules or apply a baseline. Existing independent
local approval and recovery requirements for actual pilot imports remain.

The required future operating model must allow routine GPO approval and
execution without an interactive Domain Controller logon. A portal approval
and independently trusted, domain- and tier-scoped execution service is under
discussion. This UI/log release does not implement that replacement or remove
the existing approval safeguard.

Portal 0.2.50 was activated on the authorized DEV appliance from immutable
commit `347f330857a99f56430fbc5342fed49d55e4bed8`. All seven services were healthy
at the 2026-09-14 22:26 UTC read-only evidence cutoff. Existing rows, schema,
privileges, configuration, policy content and Agent packages were preserved.
All 26 Windows Agents remained on 0.2.32; the Linux Agent remained on 0.2.13
with the same process and executable. No directory operation was performed.

Authenticated browser acceptance confirmed both policy workspaces, 550 combined
Agent history entries and 52 Baseline entries. A system filter returned the
expected three records and ascending request-time ordering. The filtered CSV
requests returned HTTP 200 and 1,060 bytes. Browser download-file inspection
was unavailable; actual CSV content and full-filter parity were verified by
the isolated browser suite. The existing pending GPO request had naturally
expired without being claimed before the release; the rollout did not cancel,
expire or execute it.

Private delivery evidence: `build/logs-0250-r2-stage.log`,
`build/logs-0250-r2-postgresql.log`,
`build/logs-0250-r2-supported-receipt.json.txt`,
`build/logs-0250-r2-activate.log`, `build/logs-0250-final-runtime.json.txt`,
`build/logs-0250-live-csv-response.json.txt`.

## Long-name correction, Portal 0.2.51

Live inspection found that an unusually long pilot GPO name overlapped the
adjacent result column. The global table no-wrap rule prevented the Logs
cell's existing word-break behavior. Logs data cells now explicitly allow
wrapping. A synthetic long-name fixture and a real DOM geometry assertion
cover column containment at desktop and mobile widths. This changes no API,
database, Agent or GPO execution behavior. Production build, seven core
version checks and all 28 real browser cases passed (1.8 minutes). The new
desktop and mobile screenshots were inspected. Evidence:
`build/logs-0251-web-build.log`, `build/logs-0251-core.log`,
`build/logs-0251-browser.log`,
`build/security-baseline-e2e/2026-09-14T22-38-17-777Z`.
Supported service-account and DEV acceptance remain pending for 0.2.51.
