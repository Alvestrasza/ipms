<!--
File Name: CENTRAL-GPO-APPROVAL-0253-VERIFICATION.md
Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Evidence and acceptance boundaries for central GPO approval.
-->
# Central GPO approval: Portal 0.2.53 / Windows Agent 0.2.34

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

## Acceptance boundaries

Browser, supported PostgreSQL and DEV deployment results are recorded after
their completion. Local tests do not establish live directory acceptance.
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
