<!--
File Name: SECURITY-BASELINES.md
Version: v0.1.1 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Baseline catalog scope, percentages, source evidence and rollout acceptance.
-->
# Security baselines

DEV release: IPMS **0.2.44**. Open **Security → Baseline** at
`/[locale]/security/baseline` as an authorized tenant reader or administrator.
The page supports English/German, server/client filters, matching-system
details, pagination, Microsoft source links, compliance and assessment coverage.

This is catalog and reporting preparation. The native baseline scanner, full
control import, policy editing and collection deployment are not enabled. The
existing Agent cannot yet provide full GPO-baseline evidence. An ordinary
installation therefore displays **Not assessed**, not invented percentages.
Screenshots/tests with measured values use an explicitly isolated fixture.

## Included packages

Verified against the [Microsoft Security Compliance Toolkit download](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
on **2026-09-14**:

| Product | Base build | Package |
| --- | --- | --- |
| Windows Server 2025 | 26100 | Windows Server 2025 Security Baseline - 2602.zip |
| Windows Server 2022 | 20348 | Windows Server 2022 Security Baseline.zip |
| Windows Server 2019 | 17763 | Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip |
| Windows Server 2016 | 14393 | Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip |
| Windows 11 25H2 | 26200 | Windows 11 v25H2 Security Baseline.zip |
| Windows 11 24H2 | 26100 | Windows 11 v24H2 Security Baseline.zip |
| Windows 11 23H2 | 22631 | Windows 11 v23H2 Security Baseline.zip |
| Windows 10 22H2 | 19045 | Windows 10 version 22H2 Security Baseline.zip |

Build mappings use Microsoft's [Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information),
[Windows 10 release information](https://learn.microsoft.com/en-us/windows/release-health/release-information)
and [Windows Server release information](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info).
Server profiles distinguish non-DC servers and domain controllers; full role
applicability will be resolved by the future evaluator. Client LTSC editions
sharing a listed build are candidates, not a claim of a separate LTSC package.
The combined legacy packages' Windows 10 1607/1809 client profiles and the 20H2
package are outside this initial eight-product selection.

Server 2025's package revision is **2602**. Older packages without an explicit
revision retain an empty revision; the catalog revision separately pins the
reviewed metadata set. SCT version 1.0 and the download page's publication date
do not identify each baseline version. Package availability does not establish
OS support lifecycle, ESU entitlement or CIS conformance.

Microsoft documents the [GPO toolkit and its contents](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10),
the separate [OSConfig mechanism](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines)
and the [Intune baseline boundary](https://learn.microsoft.com/en-us/intune/device-security/security-baselines/overview).

## Reading the results

The percentage is fully conforming systems divided by **all matching systems**.
Coverage is the percentage with a fresh, complete assessment. Unknown, partial,
stale and failed collection results stay in the denominator. An empty candidate
set is shown as no matching systems. No completed measurement means not assessed.
The details show each system's status, reason and original assessment time.
Assessments expire after 24 hours; heartbeats do not refresh them.

Scope is the selected tenant's Windows inventory, not a collection assignment.
Unclassified roles and releases outside the selected catalog are counted
separately. They must not be interpreted as compliant or silently mapped to the
nearest Windows version. Duplicate discovery rows, if present, remain inventory
rows; a future canonical-device reconciliation must precede merging identities.
Explicit Windows Home editions and clients without an identified
Pro/Enterprise/Education/SE edition remain unmatched. Microsoft's
[edition requirements](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines#windows-edition-and-licensing-requirements)
are separate from the presence of a Windows product/build in inventory.

## API and schema

- `GET /api/v1/security/baselines/?target=all|server|client`
- `GET /api/v1/security/baselines/{baseline_id}/systems/?page=1`

Both require the session and `X-IPMS-Tenant-ID` used by other tenant inventory
APIs. They enforce `inventory.view`, reject unsupported/repeated query parameters
and return no-store responses. System detail pages contain at most 25 rows.
No POST/import/scan/deploy endpoint exists. The additive `security.0001_initial`
migration creates the internal, initially empty `BaselineAssessment` table.

## Verification and rollout

Local verification commands:

```shell
python manage.py test ipms.apps.security ipms.apps.updates ipms.apps.core --settings=ipms_control_plane.settings.test
python manage.py makemigrations --check --dry-run --settings=ipms_control_plane.settings.test
```

From the Web Console, run the production build, TypeScript/Biome checks and
the security browser suite described in `tests/CONSOLE-TESTING.md`.
On 2026-09-14, the complete local backend suite ran 461 cases: 450 passed and
11 existing cases were skipped, including 18 passing Security cases. Six
browser cases passed against the actual standalone Web Console and an isolated
Django/SQLite fixture, including axe checks and EN/DE screenshots. Production
build, TypeScript, affected-file Biome and migration drift checks passed.
The initial local Python was 3.12.14 with Django 6.1. Subsequent supported-runtime
verification on the DEV appliance used Python 3.14.4 and PostgreSQL: all **461
backend tests passed**, zero skips, in 148.344 seconds. Forward migration,
reversal and reapplication passed in separate disposable databases while the
previous WSUS schema and migration history remained intact. Those test databases
were removed after acceptance. The appliance production build and TypeScript
checks also passed with the existing dependency versions.

See [ADR-0015](../architecture/ADR-0015-SECURITY-BASELINES.md) for the future
evaluator's full-scope evidence requirements and collection enforcement design.

On 2026-09-14 at 09:37 UTC, immutable local commit
`c15ebb765afc583490d3d32aa21db65d7e555ab5` was activated on the established DEV
appliance from a checksum-verified Git bundle. This deployment did not publish
the new source to GitHub. The single `security.0001_initial` migration was
applied as the existing application database owner after protected configuration
and database backups. Existing ownership, grants, service configuration,
Windows Agent package and WSUS integration were preserved.

Fresh live API and authenticated browser acceptance confirmed version 0.2.44,
eight catalog entries, server/client inventory and unknown assessment states.
The table remained empty. Both health endpoints, seven service states, WSUS API
access and all 26 Windows Agent heartbeats were verified after activation.
Windows Agents remain 0.2.30; the Linux appliance Agent remains 0.2.13 with its
process and executable unchanged. Backup digests and the active release link
were independently read back. Real baseline conformance was not measured.

For another rollout, verify supported Python 3.14/PostgreSQL behavior, migration
and tenant database permissions, exact release/target and rollback. Deploy the
Control Plane schema/API before the Web Console. An application rollback can
leave the unused additive table in place after confirming it is empty. If
assessment records exist, review their foreign keys before switching to the
older ORM, which does not know these relations. Reversing the migration deletes
assessment records and requires a backup/data decision.
Full baseline compliance acceptance requires native Windows/edition/role tests,
complete control coverage and a real enrolled Agent, not fixture records.

The dedicated `scripts/deploy-security-baselines-dev.sh` guard supports
preflight, staging and activation from 0.2.43. It binds the exact host, machine
identity, previous commit and candidate commit, preserves current Agent/WSUS
code and configuration, and accepts exactly the Security migration. A release
checkout can come from a checksum-verified local Git bundle when deployment is
authorized without public source publication. Stage with Python 3.14 and the
existing dependency set; run the PostgreSQL suite in disposable databases
before activation. Protected configuration/database backups precede the
cutover. Failure leaves application services fenced for reviewed recovery.
