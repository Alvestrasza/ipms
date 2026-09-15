# Combined GPO request verification

Version: 1.0.0 | Date: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Candidate: Portal 0.2.56 / Windows Agent 0.2.36

## Behavior and boundaries

One Portal request automatically obtains a fresh read-only directory snapshot
and creates one approval-bound import-and-link operation. Approval remains manual
and scoped to the domain and tier, with the tenant's optional four-eyes policy.
The Agent imports and links the new GPO while leaving both policy halves and
its links disabled. Activation remains a separate approved action. Domain-root
operations retain the explicit Tier 0 confirmation. Neither default policy is
modified. Existing individual operations remain compatible with Agent 0.2.35.

The combined operation preserves the concrete GPO GUID after any partial write.
It rechecks the complete target state between import and linking and refuses
replay, target drift, expiry and unexpected links. A partial result requires
reconciliation rather than creating a replacement GPO.

## Fresh local evidence

The integrated Security and Logs backend suite runs 186 tests: 182 pass and four
PostgreSQL-only cases are skipped on SQLite. Django reports no model migration.
Tests cover a single compound approval, domain-root confirmation, exact legacy
adoption, existing disabled revisions, active-GPO rejection, artifact delivery,
result evidence and compatibility with previous operations.

The production Next.js build and frontend formatting checks pass. All eleven
focused managed-GPO browser scenarios pass against the real Portal API and
isolated database with synthetic directory observations. A stricter manual
network-retry case is included in the full Security/Logs release gate.

The final MSVC Release build runs 22 CTest cases: 20 pass, two privileged Windows
cases are skipped, and none fail. All 64 compiled GPO artifacts pass the offline
census. Compound contract cases cover partial linking, intervening target drift,
authority expiry, stable identity and no duplicate replay.

The managed worker previously attempted to launch an identity probe from inside
its one-process Job Object. The provider now receives the direct local identity
read performed inside that existing worker. Domain, forest, GUID, controller,
role and GPMC checks remain required. A regression check preserves the process
boundary and exercises rejection of each mismatched identity field.

## Release gates and acceptance

Before DEV activation, run the production frontend build and real API browser
fixtures, the complete backend suite under Python 3.14/PostgreSQL 18 in an
isolated cluster, and the twelve inert Linux contract tests. Verify immutable
source and package checksums and preserve configuration, data and recovery
material during the code-only cutover. This release introduces no migration.

Fixture and contract results do not establish real directory import, linking,
replication or policy application. Release delivery never approves an AD write.
The existing read-only inspection must succeed on the intended controller before
an authorized administrator approves the combined write in the Portal.
