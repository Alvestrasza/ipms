# IPMS 0.2.38 state-aware VM settings verification

Date: 2026-09-08. Windows Agent source/build: **0.2.28**.

Status: implementation and local verification. **Not deployed, no installed
Agent upgraded, and no live VM setting changed during this work.** Application
0.2.37 remains the last previously verified DEV release; its live state was not
rechecked as part of these isolated tests. No production acceptance is claimed.

The [field matrix and protocol](../architecture/HYPERV-LIVE-SETTINGS-MATRIX.md)
document supported metadata and directional Dynamic Memory edits, remaining
static hot-memory/advanced-property restrictions, and the required canary order.

## Evidence

- Regression-first backend policy test initially failed because the new policy
  validator did not exist. After implementation, the policy, durable management
  and core suites ran 51 tests: **49 passed, 2 skipped**. The skipped tests require
  real PostgreSQL row locking; SQLite is not evidence for that boundary.
- MSVC 19.44 Release build produced the Windows Agent and native tests. CTest:
  **11 passed, 1 skipped**. Protected journal I/O requires an elevated
  administrator/LocalSystem token not provided by this execution context.
  Compilation and pure guards do not qualify actual Hyper-V live writes.
- Node contract tests: **12 passed**. Tests cover changed-field payloads,
  directions, power-state binding, unknown values, old contracts, and unrelated
  missing values without invented defaults.
- Portal TypeScript check and optimized Next.js build passed. Biome checks were
  applied to changed frontend files. Python Ruff was unavailable in the local
  environment; no Ruff success is claimed.
- Final isolated browser run: **17 passed**, including live-field enablement,
  sparse submission, rejected inverse memory direction, static-memory hints,
  DE hints, a running-to-paused transition, old-Agent restrictions and existing
  management behavior. Dark/light desktop and 390px layouts passed their scoped
  Axe scans. The active Apply button's insufficient contrast was corrected only
  inside this dialog. The fixture uses loopback only and a dedicated SQLite
  database; management calls are intercepted and cannot reach a host Agent.
- Django system checks and `makemigrations --check --dry-run` passed; no migration
  was generated. Existing runtime settings, TLS, firewall and service identities
  were not changed. No Linux Agent was built or deployed.

Local verification outputs are retained under `build/agent-msvc-0228` and
`build/hyperv-settings-0238-final-browser`; the latter contains the live-memory
fixture screenshot. Historical fixture helpers retain their earlier names.

## Local Agent artifact

`build/ipms-agent-windows-x64-0.2.28.zip` contains exactly the three executables
and three existing fixed installation/enrollment scripts. The installer default,
transport version/user agents and Hyper-V pack version are synchronized to
0.2.28. PowerShell parsing and the ZIP member allowlist passed. The package is
local only, not uploaded to the appliance or advertised for fleet updates.

SHA-256: `c7eb1a70330b058511dd36d8eba5daeec2ba1e0cfdd24e6ccc05fd75b31cfee1`.

## Explicit non-acceptance

Running-VM rename, notes writes and directional memory provider execution have
not yet been exercised on a live host with this binary. Static RAM hot-change,
live mode switching, CPU resource controls, automatic policies, devices, firmware,
security, production checkpoints, migration and cluster-role writers were not
added or certified. No VM was stopped to make a test pass.

Do not reuse the older exact-version cutover scripts for this release: the
0.2.37 script was UI-only, and the 0.2.36 script contains a migration already
applied on DEV. A coordinated control-plane/portal rollout followed by an
explicit canary Agent upgrade is required before the new live fields appear.
