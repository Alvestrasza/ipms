<!--
File Name: SECURITY-SCAN-0245-VERIFICATION.md
Version: v0.2.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Evidence boundaries for tenant baseline visibility and native read-only scanning.
-->
# Security scan 0.2.45 verification

Portal/Control Plane 0.2.45 is deployed and verified on DEV. Windows Agent
0.2.31 is available for explicit update. Source/build acceptance and the
remaining actual Agent service/fleet acceptance are distinguished below.

- The complete local backend suite initially ran 484 tests: 473 passed and
  11 PostgreSQL-dependent tests skipped. New review regressions were added
  afterward. The final supported Python 3.14/PostgreSQL suite passed all
  487 tests with zero skips in 153.631 seconds before activation.
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
- The Linux Release compatibility build passed with GCC 15.2; all nine CTest
  targets passed in 0.33 seconds. The running Linux Agent was not replaced.
- Disposable PostgreSQL migration acceptance passed Security 0001 → 0003 →
  0001 → 0003, preserving three original assessment rows and the existing WSUS
  schema/history. Both disposable databases were removed.

Review corrections require a current nonempty content hash and exact census,
keep queue retries idempotent at capacity, and distinguish proven failures from
incomplete coverage. Missing values and ambiguous duration semantics stay unknown.

## Deployment boundary

The guarded Portal cutover preserved existing service/environment/ingress
configuration, the configured Windows 0.2.30 package and running Linux Agent.
A separate, verified package promotion subsequently changed only the three
artifact assignments in each Control Plane/Gateway environment to offer 0.2.31.
Original environment bytes, ownership and ACLs were backed up; running processes
were checked against the expected new artifact configuration. The prior ZIP was
retained and the lifecycle/deployment/scan job identity set stayed unchanged.
Package availability is not a fleet upgrade or SYSTEM acceptance.

Schema rollback requires explicit reconciliation: new job/preferences tables
contain foreign keys unknown to the older ORM. Do not start the old release
against those tables without reviewing deletion behavior or reversing/restoring
the additive schema under the retained fence. Preserve new evidence before any
data-dropping reverse migration or database restore.

## Live acceptance

On 2026-09-14, the exact-target DEV cutover applied only Security 0002 and 0003
using the existing application database owner. Backup digests, prior assessment
values, ownership/ACL boundaries, migration history, ingress and service health
passed. Runtime source is `4dec39c38d128a692be14f3bfedecc23753552dc`.

The authenticated browser and read-only API acceptance verified Administration
visibility, the scan request/status interface, empty findings and the existing
WSUS API. Six unused baselines were hidden and persisted through reload with six
matching audit records; Server 2025 and Windows 11 24H2 remain visible. Inventory
remains 25 servers and one client. All seven services are healthy.

The 11:10 UTC receipt verified all 26 Windows Agents still on 0.2.30 with fresh
heartbeats, Agent 0.2.31 offered for update, and the unchanged Linux 0.2.13
process/binary. No Agent upgrade job was created. A real browser scan request
returned zero queued and 25 unavailable because those Agents are too old.
There are no live assessment results; the displayed compliance remains unknown.
Actual SYSTEM/fleet scan acceptance requires an explicit Agent rollout and new
scan request. No live compliance claim is inferred from synthetic browser tests
or the local non-elevated native observation run.

No GitHub push, tag, release or external issue/comment publication was performed.
