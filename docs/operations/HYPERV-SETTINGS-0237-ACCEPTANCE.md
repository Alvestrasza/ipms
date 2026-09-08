# Hyper-V settings dialog: 0.2.37 acceptance

Date: 2026-09-08. Status: published and activated on the approved DEV appliance,
with live acceptance recorded below. No managed VM or Agent has been changed in this
UI work. The application version is prepared as 0.2.37; the Agent version and
management API contract remain unchanged.

## Requested behavior

Replace the long, duplicated settings display with an organized VM properties
dialog inspired by VMM's property-group workflow, not a pixel-identical copy or
a claim of VMM feature parity. The selected subsection must always be clear.
Microsoft documents configuration through the VM Properties / Configure Hardware
pages in its [VMM provisioning guidance](https://learn.microsoft.com/en-us/system-center/vmm/provision-vms?view=sc-vmm-2025).

- Identity: General.
- Hardware configuration: Processor, Memory and Devices.
- Management: Automatic actions and Checkpoint policy.

Only the selected subsection is visible. Editable values are shown once, in
their controls; the property list contains only additional read-only values.
The selected navigation entry has a distinct border, color and `aria-current`.
A sticky subsection heading preserves orientation while scrolling. Small screens
use one labeled, grouped section selector instead of displaying a second sidebar.

The footer stays visible and applies only the current editable section. Drafts
survive navigation between settings subsections; a new host configuration revision
still resets the bound form. Switching to another management action or closing
the dialog is not a draft persistence guarantee. Host identity is shown only in
the header. Successful inspection diagnostics no longer displace the settings;
other job details can be expanded, and active/failing/uncertain jobs remain clear.

## Preserved boundaries

The third header row places a yellow warning triangle and powered-on status to
the right of the host. Narrow screens wrap the status without horizontal overflow.
Unconfirmed/stale observations are explicitly described as last observed state.
The current Agent contract allows no hot edits in the three editable sections;
the running-state notice makes that IPMS limitation explicit rather than claiming
that Hyper-V itself cannot modify any setting online. State, capability, current
inspection and permission are independent gates. Reloading a running observation
locks an existing draft, even if its capability flag incorrectly remains true.
No supported hot-edit capability is being added or implicitly advertised here.

Tenant/CSRF authorization, fresh revision checks, stopped-VM requirements,
capability and unknown-value guards, single-section requests and uncertain-request
recovery are unchanged. Opening or switching a section submits no host work.
The native Agent, database schema, credentials, ports and console transport are
unchanged. These UI checks do not extend the previously bounded native acceptance
to new settings, checkpoints, migration or cluster actions.

## Verification

- The baseline regression reproduced missing subsection navigation. The first
  fixture attempt could not hydrate because its generated standalone assets were
  missing; that setup failure was not counted as evidence of the UI defect.
- Nine management contract tests and seven Core tests passed. The focused backend
  management suite passed 32 tests with two PostgreSQL-only cases skipped on the
  isolated SQLite test database. These are not a rerun of the full PostgreSQL
  backend or native suites.
- The production Next.js build/type check passed with network access for the
  existing font dependencies. The restricted build had failed only while fetching
  those unchanged fonts; no dependency or font policy was changed.
- The browser tests use real isolated login and SSR inventory, with all management
  operation requests intercepted. No real VM, host Agent or live database is used.
- All 14 final browser scenarios passed. Scope includes unduplicated fields, selected
  subsection and retained drafts, one-section writes, unknown and read-only states,
  German keyboard navigation, destructive confirmations and uncertain-request
  recovery. The first run exposed ambiguous accessible labels on the notes field
  and mobile section selector; explicit label associations fixed all four failures.
- The power-state extension initially exposed keyboard focus loss after disabling
  a reload control. Focus now returns to the current section heading if necessary;
  the final repeated browser suite passed without weakening its focus assertions.
- Dark/light desktop and 390px layouts passed scoped Axe scans, horizontal overflow
  and scroll-position heading checks. The run captured 32 screenshots, including
  settings, powered-on warnings, checkpoints and destructive confirmation states.
  Desktop dark and mobile light power-warning views were also visually reviewed.
- Final Biome checks passed for all 133 frontend files, and the standalone
  TypeScript check and all nine management contract tests passed again.

## DEV activation

The dedicated `scripts/deploy-vm-settings-dev.sh` is a schema-neutral 0.2.36 to
0.2.37 cutover, bound to the exact approved host, machine identity and commit IDs.
It verifies unchanged Agent, schema, authorization, dependency, service and ingress
contracts; retains the active dependency versions; builds a new immutable release;
and checks for active or unresolved jobs before interruption. Only the Control
Plane and Web Console are restarted. There is no migration execution, Agent
rollout, credential/environment edit, VM mutation or automatic power operation.

The script retains the exact previous release and restores it on activation
failure, provided the preserved configuration still matches. Failed recovery or
configuration drift leaves the portal fenced for explicit review. Bash syntax and
five isolated Linux rollback tests passed; these tests use inert command stubs,
not a forced failure of the running appliance.

Live activation completed on 2026-09-08 at 06:44 UTC using application commit
`a1e02948b50cab5f182bdbb2a6360f7e4ff430e2`. The Control Plane and Web Console were
both active/running with their process working directories resolved to that exact
immutable release. The TLS-verified API returned `application_version: 0.2.37`,
both localized login routes returned HTTP 200, configuration/ingress hashes were
preserved, the cutover fence was absent, and the Agent listener remained bound to
all IPv4 networks on TCP 9419. No failed systemd units were reported. Source was
clean; previous application commit `c4676e58e8ef2283dd44d2bf154c1155199528ca`
(0.2.36) remains intact. No rollback was needed.

The existing Django HSTS warning remained unchanged. Systemd requested a daemon
reload; the two on-disk unit files were first compared byte-for-byte with the
release, then reloaded without another service restart. Both reported
`NeedDaemonReload=no` afterward with unchanged PIDs and API version.

A newly isolated workstation browser profile rejected the internal portal
certificate with `ERR_CERT_AUTHORITY_INVALID`. Certificate checks were not
disabled and no trust-store change was made. Live HTTPS acceptance used the
explicit appliance certificate; authenticated production-like browser behavior
remains covered by the isolated fixture, not a new login to tenant infrastructure.

See [the management acceptance record](HYPERV-MANAGEMENT.md) for the separate
native settings evidence and remaining provider/recovery qualification gaps.
