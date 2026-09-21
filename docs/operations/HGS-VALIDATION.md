# HGS source candidate validation

Version: 1.0.1 | Date: 2026-09-21
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Status: Source validation evidence; release and runtime acceptance tracked separately

Candidates: Portal 0.2.76 and Windows Agent 0.2.49. This work extends source
baseline `1533464a4b5d35baaca41ce9d42c47e7070c9609`.

## Requirement coverage

| Requirement | Implementation | Evidence and limits |
| --- | --- | --- |
| Agent first on existing VMs | Existing enrollment plus typed HGS provider and local prerequisite helper | Native build and provider/transport contracts; no real forest promotion run |
| Dedicated HGS tenant and identities | Immutable tenant purpose, exclusive memberships, server-side permissions and device-bound jobs | Tenant/API/gateway regression suite; database concurrency checks skipped on SQLite |
| Simple vTPM and secure Shielded profiles | Distinct profile/attestation fields; shielded requires TPM | Backend/frontend validation and browser fixtures; does not configure a workload VM |
| One Appliance | HGS plans in the existing Control Plane/Gateway and Security workspace | Both profiles covered by one fixture/receiver; actual outage independence requires direct host-to-HGS acceptance |
| Fresh tenant Agent onboarding | Platform-only PKI/recovery ceremony, exact-SNI tenant Gateway material, all-tenant verification and package hash/version gate | 77 focused Agent-PKI/deployment/platform tests; no live Appliance or client-network acceptance |
| Air-gapped provisioning | Local feature source, embedded adapter, local certificate/secret custody, bounded offline feature installation | Source/provider checks; disconnected Windows installation and servicing still need lab acceptance |
| Reviewed changes and reboot recovery | Immutable digest, fresh inspection, claim/intent journal, durable receipts, fences and explicit resolution | Contract tests include interruption, expiry, authority withdrawal, duplicate receipts, preboot proof and next-step-only recovery |

## Executed checks

From `services/control-plane`, with `PYTHONPATH=src`:

```text
.venv/Scripts/python.exe manage.py test ipms.apps.core ipms.apps.hgs ipms.apps.tenancy ipms.apps.agent_pki --settings=ipms_control_plane.settings.test --noinput --verbosity 1
.venv/Scripts/python.exe manage.py makemigrations --check --dry-run --settings=ipms_control_plane.settings.test
```

The final integrated backend run completed 392 tests with zero failures and 11
skips. It also verifies that the Control Plane reports Portal 0.2.76 rather than
the 0.2.74 baseline version.
The final focused HGS run passed all 35 tests, including the input-schema fix
that rejects scoped IPv6 addresses unsupported by the native provider.
Migration drift check reported no changes. The local runner is Python 3.12.14
with Django 6.1; the repository requires Python 3.14. A supported Python 3.14
runner and PostgreSQL acceptance remain required before release.

The native MSVC x64 build completed. CTest in `build/agent-msvc-hgs-ninja-049`
registered 24 tests: 22 passed, two skipped. The skipped existing tests are
`gpo-protected-storage` and `hyperv-management-journal-io`, which require elevated
Windows access. HGS state-machine tests use controlled provider seams and do not
install roles, promote a domain controller or reboot this development computer.
The PowerShell adapter test parses both local scripts and exercises only the
pure dependency resolver with bounded fixtures; it does not prove real Windows
feature metadata mappings. After the final rebuild, the coordinator repeated all
24 CTest registrations: 22 passed, two skipped, zero failures (10.21 seconds).
The local `ipms-agent.exe` SHA-256 is
`831FDAC8082A64AE6F840FAA4C2E52E2D735A167D005739A14679171D3C656FB`.

From `apps/web-console`:

```text
node --experimental-strip-types --test tests/hgs-contract.test.mjs tests/portal-scope.test.mjs
node node_modules/typescript/bin/tsc --noEmit
node node_modules/next/dist/bin/next build
node node_modules/@playwright/test/cli.js test --config playwright.hgs.config.ts
```

Nine contract/scope tests passed, TypeScript passed, and the production build
completed. Targeted Biome validation passed on 20 files. Six isolated browser
tests passed, including exact review, expired evidence, lost response, separate
recovery confirmation, tenant isolation and the German plan view. A screenshot
was visually checked. Fixtures used loopback ports 3328/3329 and were stopped.
The build needed access to the project's existing public Google Fonts. Runtime
HGS operation does not download those fonts or Windows features from the Internet.

The `.next` tree was built with a fixture Control Plane URL and is a test artifact;
rebuild with the intended environment before packaging a release. These local
checks do not mutate a tenant, Agent, AD, HGS, Hyper-V, database or Appliance.

The final Agent-onboarding regression run completed 77 tests with zero failures
and two existing privileged skips. Django system checks and migration drift
checks passed. The Gateway tests cover two tenant SNI certificates over real TLS,
request-handler tenant selection, atomic multi-tenant material publication,
recovery download/digest/confirmation, DNS uniqueness, all-tenant verification
and HGS package version/hash readiness. TypeScript, targeted Biome, nine Web
contract tests and the 76-route production build passed. Bash syntax validation
was unavailable on this Windows host because neither Git Bash nor a WSL
distribution is installed.

A local lab package was assembled at
`build/ipms-agent-windows-x64-0.2.49.zip`. Its SHA-256 is
`1e1bac50c646c5c052c756aecc1a8a0fc650767f98569feea36973c2af182611`, and an
independent extraction matched all seven source files. The three local PE files
are not Authenticode-signed, so this is a hash-verified lab candidate rather than
a production distribution.

## Release and lab gates

This document does not by itself establish a commit, published release, signed
distribution package or infrastructure rollout. Verify immutable package and
signature provenance, and retain the deployment/backup evidence for activation.

Run an identified Windows lab through local media/certificate/secret preparation,
forest creation, additional-node join, planned reboot, process/network loss,
permission withdrawal and explicit recovery. Verify actual attestation and key
release, vTPM and shielded guest boot, certificate rotation/revocation, backup
restore, cold start, three-node failure tolerance and Appliance-offline operation.
Service metadata and private-key ACL checks alone do not prove those outcomes.
