<!--
File Name: SECURITY-GPO-0248-VERIFICATION.md
Version: v0.1.1 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Source and isolated-test evidence for domain planning and native GPO pilots.
-->
# Domain and GPO pilot verification

Date: 2026-09-14. Candidate **Portal 0.2.48 / Windows Agent 0.2.32**.
This records source implementation and isolated verification. It does not claim
a deployed release or actual Active Directory acceptance.

The later user-authorized software rollout is recorded separately in the
[DEV deployment evidence](SECURITY-GPO-0248-DEPLOYMENT.md). Candidate-only
statements below describe this earlier implementation step.

## Delivered behavior

- Tenant administrators can configure separate domains, multiple OU DNs for
  tiers 0/1/2, a bounded GPO naming template and baseline order. Save/reload,
  revision conflicts, tenant permissions, native drag and keyboard ordering
  are covered through the actual browser, session, API and database.
- Manual directory plans remain visibly unverified. Saving or reordering never
  creates a policy operation. Existing customer OU layouts are preserved.
- A separate explicit request prepares one immutable original Microsoft GPO
  component for an eligible writable DC Agent. The native provider requires
  independent exact-job local approval and creates only a new disabled,
  unlinked pilot. Durable receipts and domain reservations prevent blind replay.
- Tenant/identity/membership withdrawal and Agent update/deployment/removal
  reservations are integrated with the new operation. Scan findings retain
  their original meaning; staging a GPO cannot create compliance evidence.

See [ADR-0016](../architecture/ADR-0016-TIER-DOMAIN-GPO-PILOTS.md) and the
[operator workflow](SECURITY-GPO-PILOTS.md). Product work is tracked by
[epic #34](https://github.com/Alvestrasza/ipms/issues/34) and issues #35-42.

## Verification results

| Check | Result and boundary |
| --- | --- |
| Full local backend | 522 tests in 160.112 seconds: 511 passed, 11 PostgreSQL-only tests skipped. Local Python 3.12.14 / SQLite is supplementary evidence, not the supported runtime. |
| Supported backend | All 522 tests passed in 163.829 seconds with Python 3.14.4 / PostgreSQL 18.6, with no skips. The complete seven-application suite used a freshly owned isolated test database. |
| Migration | No model drift. PostgreSQL `security.0003 -> 0004 -> 0003 -> 0004` passed, preserving prior synthetic assessments/findings, visibility, scan and WSUS records. New constraints, nullable-requester row locking and the old-ORM/new-FK rollback boundary were verified. |
| Portal production build | Next.js 16.3.3 / Node 24.19.0 succeeded, including TypeScript and 54 route pages. Changed frontend files passed Biome. |
| Actual browser | All 15 tests passed in 56.4 seconds using installed Edge, real Django sessions/API and a disposable synthetic database. Native mouse drag, keyboard order, reload persistence, stale-edit preservation, tenant authorization, outages, pilot request state and existing baseline flows passed. Narrow German layout and accessibility checks passed. |
| Windows Agent | Full MSVC x64 build succeeded. CTest: 17 passed, 2 elevation-dependent checks skipped, no failures. The protected GPO storage test also verified rejection under the ordinary user token. |
| Package preparation | All 47 Security importer/package tests passed. Reproduction of 64 original components across 12 profiles had zero mismatches. No vendor payload was published. |
| Native artifact decoder | The built decoder accepted all 64 actual prepared artifacts offline with exit code 0, without AD calls. |
| Linux compatibility | GCC 15.2 Release build succeeded; all 10 CTests passed in 0.35 seconds. |

An initial local full-suite run exposed an intended audit-count expectation
change and an intermittent existing console-input ordering assertion. The audit
expectation was corrected; the console case passed focused and final full runs
without modifying console behavior. Browser verification found and corrected
duplicate component keys, German heading overflow and implicit textarea label
association after SSR. The drag test now starts the real native drag before
scrolling an initially offscreen destination; persistence assertions were kept.

## Content and build identity

- GPO descriptor catalog SHA256:
  `dafd8ee9ccfff15d077e9e8186680c2dccc834d71c150a98b5d5cb0c0c471c12`.
- Windows Agent executable SHA256:
  `4232cfcc55b22e7cf51f1efec37b4247a5fe902a1f15fc4c504f71f5916e4c07`.
- Private immutable backend/native test snapshot: 315 source/helper files,
  8,824,577 bytes; archive SHA256
  `406fc024c93f6a9f8a9e97bb63f7d113e4326702c3696e7e96f4334bf83f4b83`.

The snapshot contains source and synthetic test helpers, excluding runtime
environments, credentials, Git data and original vendor bundles. The selected
machine and immutable current release are checked before/after isolated tests.
Test databases were newly created and removed only after checking their
original OID, owner and absence of connections. Both were confirmed absent at
completion; source/helper hashes and the active release were unchanged. No
existing database was dropped. Reversing populated synthetic pilot tables is
not permission to discard live GPO identity or reconciliation evidence.

Private evidence is retained under `build/security-gpo-local-backend-final.log`,
`build/security-baseline-e2e/2026-09-14T16-02-43-179Z`,
`build/agent-msvc-security-ninja-20260914/Testing/Temporary/LastTest.log`,
`build/agent-msvc-security-ninja-20260914/gpo-artifact-decoder-64-verification.txt`
and `build/gpo-supported-tests/`. These operational artifacts are not published.

## Acceptance still required

No live GPMC import, elevated local approval/storage exercise, Agent installation,
DC delegation change or policy activation was performed for this candidate.
Actual domain acceptance must verify the service identity and GPMC dependency,
one independently approved import, returned GUID, disabled state, unchanged
default/customer policies and absence of domain/OU/site links. Recovery from an
ambiguous write must retain journals and reservations.

Production-GUID promotion, CIS content, conflict/effective-policy analysis,
verified directory object identities, Collections activation, IPMS firewall
recovery and complete Tier 0 management isolation remain later work. A source
build or staged receipt is not evidence for those capabilities.

GitHub requirements/issues were published. Candidate source has not been
committed, pushed, tagged or released in this implementation step. The existing
Portal and installed Agents remain unchanged; the separate test transfer is
not a deployment.
