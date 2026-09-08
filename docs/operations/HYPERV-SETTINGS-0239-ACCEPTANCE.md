# IPMS 0.2.39 VM settings dialog verification

Date: 2026-09-08. Status: **implemented and tested locally; not published or
activated**. The known DEV appliance was freshly checked: application 0.2.37
remains active. No installed Agent was upgraded and no live VM setting changed.

The [dialog lease contract](../architecture/HYPERV-SETTINGS-DIALOG-LEASE.md)
documents automatic Agent inspection, tooltip-only powered-on guidance, owner
display, server-side enforcement, expiry, and coordinated rollout requirements.
The existing [live-field matrix](../architecture/HYPERV-LIVE-SETTINGS-MATRIX.md)
remains unchanged. Windows Agent 0.2.28 is still required for supported live
fields; this change introduces no new native command or Agent binary.

## Fresh evidence

- Regression-first public API tests demonstrated the missing dialog endpoint
  and missing settings-dialog identity requirement before implementation.
- Final focused backend run against **PostgreSQL 18.6: 62 passed, no skips**.
  The run includes management policy/core regressions, same-user sibling dialogs,
  different sessions/users, tenant isolation, CSRF, owner-only submission,
  permission revocation, expiry, release ownership, accepted-job durability and
  token non-disclosure in public job history.
- The PostgreSQL concurrency case opened two dialogs simultaneously: exactly one
  lease owner and one shared inspection. Existing concurrent authority/job tests
  also ran. The tests applied migration 0023 to an explicitly separate disposable
  test database; it was removed by the test runner. The active application
  database and release were not changed. The final wrapper exited zero and
  independently verified that the test database no longer existed.
- Local SQLite regression runs passed; their three PostgreSQL-only checks were
  explicitly skipped rather than counted as concurrency evidence. Final Django
  system checks and `makemigrations --check --dry-run` exited zero with no drift.
- **22 isolated browser tests passed**. These cover waiting for the initial
  inspection before displaying fields, tooltip pointer/keyboard semantics,
  Escape dismissal without closing the dialog, red owner indication, disabled
  fields for other owners, explicit release, expiry, failed lease renewal without
  mutation replay, DE/EN, supported live fields, sparse state-bound submissions,
  old-Agent restrictions, and existing checkpoint/draft/recovery behavior.
  Dark/light desktop and 390px layouts passed scoped accessibility scans.
- **12 Node contract tests passed**. TypeScript, changed frontend Biome checks,
  and the final optimized Next.js production build passed. Local login-page
  smoke checks showed meaningful content and no browser errors. The red-lock
  and running-memory screenshots were visually inspected.

Browser authentication and SSR use disposable local fixture data; management
transport is intercepted and cannot reach a real host Agent. Backend tests use
real database/authorization/job collaborators but do not execute Hyper-V methods.
These tests do not establish live native-provider acceptance or a DEV deployment.

## Corrections found during verification

- The first browser run found that Escape on the tooltip also closed the native
  dialog. Preventing the native key default corrected it; the final run passed.
- A rebuild initially encountered the fixture's Windows file lock. Only the
  owned fixture was stopped before rebuilding; the final build passed.
- The first PostgreSQL wrapper completed its tests and cleanup but a trailing
  PowerShell CR caused an outer nonzero exit. The final script was transferred
  as a file and the complete repeated run exited zero.
- The local Black CLI formatted the selected Python files but hung afterward
  and was cancelled. No successful Black CLI check or unavailable Ruff run is
  claimed. Source review, imports, Django checks, and PostgreSQL tests passed.

Final browser outputs are retained locally under
`build/hyperv-settings-0239-final-browser`. The checksum-verified final backend
test source archive is `build/settings-0239-tests-final.tar.gz`, SHA-256:
`7fd8fec177e4f4452b5bf8c180f11ef85fe8ae53ff62916793dbc8568f51299b`.

## Approved activation procedure

This is not a UI-only release: migration 0023 and matching API/portal code must
be deployed together. Old portal settings writes fail closed after the API
upgrade. Publication and activation on the known DEV appliance were explicitly
approved on 2026-09-08. The version-specific
[`deploy-settings-dialog-dev.sh`](../../scripts/deploy-settings-dialog-dev.sh)
has separate `--preflight`, `--stage`, and `--activate` phases. Supply the verified
host name, machine ID, public host, previous immutable commit and new immutable
commit; never substitute a production or customer environment.

- Preflight requires the exact 0.2.37 baseline, migration 0022, no migration
  0023, protected paths, existing cutover fencing, usable tenant administrators,
  and no active/unresolved management, lifecycle, deployment or console work.
- Stage builds the pinned source without interrupting the runtime. Python
  dependencies are frozen from the current environment; frontend installation
  uses the unchanged lockfile. No dependency, identity, ingress, or native-console
  transport change is permitted by this cutover. The only pending migration
  must be the reviewed additive settings-lease table.
- Activation rechecks the candidate and quiescence, backs up configuration and
  the PostgreSQL database into a protected directory, fences and stops the
  coordinated application services/timers, applies migration 0023, checks table
  ownership and broker non-access, and atomically switches the release link.
  Previously active services/timers resume only after the schema checks pass.
- Verification checks version/readiness, EN/DE HTTPS login pages, anonymous
  authorization failures, disabled Django admin, Agent ingress, loopback-only
  console listeners, and unchanged environment/configuration digests and broker
  grants. No credential reset, installed Agent update, or VM action is included.
- A failure after fencing leaves application services fenced for explicit
  recovery. Keep the exact previous release and protected backup. For a reviewed
  rollback, first stop all application writers/timers and establish no accepted
  unresolved work or active settings dialog; select the verified previous
  immutable release and restart only the recorded previously active units.
  The additive lease table may remain, but the old backend no longer enforces
  leases. Do not automatically restore the database, erase jobs, or drop the
  table. Recheck the old version and health before ending recovery.

The script's Linux Bash syntax and exact-target read-only preflight passed.
At this checkpoint no publication, staging, migration, or activation has occurred.
A separately selected Windows Agent 0.2.28 canary remains necessary for live-field
provider acceptance; this approval does not include a fleet rollout.
