# Managed GPO lifecycle verification

Version: 1.0.0 | Date: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Candidate: Portal 0.2.55 / Windows Agent 0.2.35

## Verified locally

The production Next.js build completes successfully. All 43 Security browser
tests pass, including nine managed GPO workflow scenarios. The fixtures use real
session authentication, Portal API, database, approval, claim and result handling.
Only the native directory observations are synthetic; these tests contact no AD.
After adding domain-root actions and active/prepared version distinction, the
production build and all 11 focused managed GPO browser scenarios pass again.
The earlier 43-test total is not a fresh combined 45-test run.

Coverage includes separate inspection/import/link/activation requests, the stable
GUID, explicit management and recovery access review, optional four-eyes approval,
permission withdrawal, tenant changes, expired and malformed observations,
lost-response reconciliation without duplicate creation, and Logs status filters
and CSV export. Existing schema-1/2 API and approval/document regressions remain.
Formatting checks pass for the affected frontend files.

Backend tests cover exact immutable assignments, all 64 component naming aliases,
adoption, update staging without active-content changes, operation postconditions,
backup requirements, typed snapshots, configured/observed OU identity casing,
nested OUs, active-revision application evidence and withdrawal/reconciliation.
Concurrency tests require PostgreSQL and are not claimed from SQLite execution.
The final domain-root backend run includes 36 tests: 34 pass and two PostgreSQL
concurrency cases are skipped on SQLite. It covers strict target confirmation,
Tier 0 authorization, root GUID binding, the separate lifecycle and preservation
of default-policy flags and relative order.
Malformed backup metadata is rejected on every operation except activation.
The integrated Security and Logs suite then runs 178 tests: 174 pass and four
PostgreSQL-only cases are skipped on SQLite; no failures occur.

The final MSVC Release Agent build includes forest-wide link checks and
domain-root support. Of 22 CTest cases, 20 pass and two privileged Windows cases
are skipped; none fail. All 64 compiled GPO artifacts decode successfully in the
offline census. The bounded journal test round-trips a 16,371-byte snapshot and
34,923-byte journal. These results do not establish live AD acceptance.

## Release gates

Before activation, execute the complete backend suite under Python 3.14 and
PostgreSQL 18 in an isolated cluster. Validate the migration preservation checker
against that disposable database, including the precise conditional legacy index,
new managed table, one model descriptor and four unassigned permissions.

Validate the packaged binary hashes against the final native build receipt.
Privileged Windows filesystem tests must be reported as skipped when the token
cannot execute them; a successful ordinary test run does not cover those cases.

The appliance rollout must pin source and artifact hashes, verify target identity
and quiescence, preserve service configuration and existing data, retain protected
recovery material and deploy the receiver before advertising the Agent update.
Migration 006 must not be reversed after managed requests are accepted.

## Acceptance still requiring a real directory

Browser fixtures and native contract tests do not demonstrate real GPMC import,
forest-wide visibility, replication, linking, activation or endpoint recovery.
Run a real read-only inspection first and let authorized administrators separately
review and approve any subsequent directory writes in the Portal. No release or
test automatically approves or activates a GPO.

A successful Agent update proves package/service delivery, not policy application.
Only separate Agent-confirmed Windows GPO processing evidence contributes to the
baseline assignment percentage. Firewall and administrator reachability must be
verified independently for each intended deployment scope.
