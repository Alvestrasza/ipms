<!--
File Name: CENTRAL-GPO-APPROVAL-0253-VERIFICATION.md
Version: v0.3.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Evidence and acceptance boundaries for central GPO approval.
-->
# Central GPO approval: Portal 0.2.54 / Windows Agent 0.2.34

The owner-approved workflow is defined in
[ADR-0017](../architecture/ADR-0017-PORTAL-GPO-APPROVAL.md).
Approval is explicit, bound to an unchanged request, and restricted by tenant,
domain and tier. Four-eyes approval is optional per tenant and defaults to off.
The additive migration creates no grants and approves no existing requests.

## Local evidence

- Windows MSVC Release build completed. CTest: 21 tests, 19 passed, two
  privileged storage tests skipped, zero failures. The new schema-2 contract
  failed against the prior implementation before passing with the change.
- All 64 pinned GPO component bundles were decoded offline by the native
  implementation. Vendor content and the applied-GPO collector are unchanged.
- Backend combined local suite: 474 tests, 461 passed, 13 platform/PostgreSQL
  skips, zero failures. This local Python 3.12/SQLite run is supplemental;
  supported Python 3.14/PostgreSQL verification is recorded separately.
- A stale authenticated session after a concurrent password reset was shown
  to approve a request when the new guard was disabled. The fixed real-cookie
  tests reject approval, policy changes, authorization changes and request
  creation after authentication has changed.
- An additional initial-status regression reproduced `queued` before approval.
  The correction starts only new schema-2 jobs in `awaiting_approval`, changes
  them to `queued` on approval and preserves legacy behavior. The focused run
  passed 55 tests with two PostgreSQL skips and zero failures.

The immutable Windows package is 1,132,480 bytes with SHA-256
`b7e7e1d862dc5b3ca451b4ba622757c83766edd7b3f21e20856527ee4d0f7a4a`.
Its Agent executable is 1,919,488 bytes with SHA-256
`0c95a131102eda062e299a81f2d6209a975142b11b6c5bb3d306e2da9a932607`.

## Supported environment and DEV evidence

Source `7f4a262825dc962471f40afe0dd268134e3d80d5` passed all 609 backend tests
under Python 3.14.4 and PostgreSQL 18.6, with zero failures or skips. The test
cluster was isolated from the active database and stopped after verification.
The final combined browser run passed all 34 cases; production builds,
TypeScript and formatting checks passed.

Portal 0.2.53 was activated on DEV with the single additive migration. The
deployment verifier initially did not account for PostgreSQL 18 named NOT NULL
constraints and Django's two new content types/eight unassigned model permission
descriptors. It kept writers stopped. A corrected, independently checked
comparison proved that existing rows, schema objects and privileges were
unchanged, then completed activation. No database restore or reverse migration
was performed. The recovery material was retained.

All 26 existing Windows devices confirmed successful Agent 0.2.34 updates and
fresh inventory. The Linux Agent and its process remained unchanged. No domain
grants or four-eyes policy rows were created by deployment. Live UI verification
confirmed that four-eyes defaults to off and domain/tier grants start empty.

The owner explicitly requested deletion of two unclaimed legacy requests.
Their records were removed with a protected backup and retained audit history.
Acceptance then identified their prepared Agent journals repeatedly requesting
the now-missing jobs. Portal 0.2.54 addresses this with a separately audited,
strictly bound retirement receipt; it does not restore the jobs or clear an
ambiguous or claimed journal. Its final evidence is recorded separately below.

## Portal 0.2.54 retirement follow-up

Immutable source `1751c388050410dbfd29f87accf999e65ce28c89` passed all 616
backend tests under Python 3.14.4 and PostgreSQL 18.6. The isolated cluster
was stopped after testing and never contacted the active database. The
production web build and TypeScript checks passed. No migration, dependency,
native Agent or vendor policy content changed from the preceding candidate.

Code-only DEV activation verified unchanged existing rows, schema, privileges,
configuration and packages before reopening writers. Recovery material was
retained. Two retirement receipts were then appended under the tenant lock,
after checking the protected deletion backup, original immutable digests,
unclaimed status, enrollment identities and retained deletion audit events.
No job was restored, no local journal was reset, and no execution authority
was granted. Unknown, mismatched, duplicate and claimed requests remain fenced.

At 2026-09-15 11:19 UTC, both affected DCs had fresh Agent 0.2.34 reports;
all 12 writable DC executors reported ready for approval. All 26 Windows
updates were confirmed successful. No pending GPO request or staged import
existed; one earlier expired request remained as history. All eight checked
services were active, and the Linux Agent process remained unchanged.
The live Portal displayed 0.2.54, four-eyes off and no domain/tier grants.
Applied-GPO reports were present but incomplete on all 26 Windows systems;
this is not proof of baseline application.

## Acceptance boundaries

Local and supported-environment tests do not establish live directory acceptance.
No GPO approval, import, link, activation or policy refresh was performed as
part of implementation verification. The implemented operation remains a
disabled, unlinked pilot import. Linking and activation are separate future
actions, unavailable through this import operation.

Approval authenticity relies on the existing trusted gateway connection and
protected Agent state. It is not an independent signature by a separate tier
authority. Managing domain controllers places the Portal, its administration
and privileged update channel inside that management trust boundary.

Applied-GPO reporting remains a separate acceptance item. Partial or missing
RSoP evidence must not be presented as a confirmed applied baseline. Publishing
source, advertising a package, updating a device, and importing a real GPO are
separate evidence levels.
