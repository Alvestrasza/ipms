<!--
File Name: SECURITY-SCAN-0245-VERIFICATION.md
Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Evidence boundaries for tenant baseline visibility and native read-only scanning.
-->
# Security scan 0.2.45 verification

Candidate: Portal/Control Plane 0.2.45 and Windows Agent 0.2.31. Source
implementation is complete; live acceptance is recorded separately below.

- The complete local backend suite initially ran 484 tests: 473 passed and
  11 PostgreSQL-dependent tests skipped. New review regressions were added
  afterward and require supported PostgreSQL acceptance before activation.
- Security and heartbeat tests cover tenant/role/CSRF boundaries, stale mTLS
  identity, immutable manifests, full ID coverage, strict values and body limits,
  replay/attempt isolation, failure/expiry and evidence-preserving visibility.
- The importer passed 26 parser, provenance, pinned ZIP census and reproduction
  tests for all eight packages and twelve profiles.
- Next.js 16.3.3 production build and TypeScript passed. The isolated browser
  suite uses real Django session/API/database flow with explicit synthetic native
  observations. Results and screenshots remain private build artifacts.
- All nine isolated browser tests passed in 37.8 seconds after correcting a
  keyboard-focus issue in the horizontally scrollable findings table.
- The final focused Security suite passed 44 tests in 3.037 seconds; migration
  drift checks reported no changes.
- Native MSVC x64 tests cover process deadlines, memory/output limits,
  cancellation, child termination, independent heartbeat progress and typed
  values. A standard-user local read cannot establish SYSTEM/fleet coverage.
- Final native x64 CTest: 15 passed, one existing ACL-dependent skip, zero failed.
  A bounded local Windows 11 24H2 run produced 426 controls on 14 validated pages
  in 0.234 seconds: 22 matched, 13 different and 391 unknown. It used an unchanged
  non-elevated token. The installed local Agent service was separately verified
  as running under LocalSystem; the candidate was not installed by this test.
- Windows Agent ZIP SHA256:
  `20e1f22e8cd9b908fcdd962ed354829b318ecb1a27a5d4d0bf7adc8af926a38e`.
  The service binary SHA256 is
  `34546370b4332792dd9e66506abdef511a4fea14b6718535ff3beda10e14b009`.
  The standard six-file package was read back and its entry checksums verified.

Review corrections require a current nonempty content hash and exact census,
keep queue retries idempotent at capacity, and distinguish proven failures from
incomplete coverage. Missing values and ambiguous duration semantics stay unknown.

## Deployment boundary

The prior 0.2.44 Appliance release remains the rollback source until guarded
activation passes. The new guard preserves existing service/environment/ingress
configuration, configured Windows 0.2.30 package and running Linux Agent. A
staged 0.2.31 artifact is not a fleet upgrade or SYSTEM acceptance.

Schema rollback requires explicit reconciliation: new job/preferences tables
contain foreign keys unknown to the older ORM. Do not start the old release
against those tables without reviewing deletion behavior or reversing/restoring
the additive schema under the retained fence. Preserve new evidence before any
data-dropping reverse migration or database restore.

## Live acceptance

Pending for this candidate. No live compliance claim is inferred from isolated
synthetic tests or local non-elevated native observations.
