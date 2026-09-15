# Agent-confirmed baseline application

<!-- File Name: BASELINE-APPLICATION-EVIDENCE.md | Version: v0.1.0
Created: 2026-09-15 | Last Modified: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation -->

Portal 0.2.52 and Windows Agent 0.2.33 distinguish **baseline application**
from assessment compliance. An applied baseline can legitimately have
noncompliant individual settings when another baseline overrides them.

## Configuration and workflow

Tenant Administration → Security → Domains contains the domain DNS name,
Tier 0/1/2 OU mappings, GPO naming template and baseline composition order.
They are saved together using the existing revision check. Customer-specific
OU paths and naming templates remain supported.

Security → Baseline contains the catalog and execution workflow. Details
appear only after selecting a baseline and can be collapsed or cleared.
The import panel selects a saved domain and retains the existing pilot-import
boundary. Configuration changes do not create, link or apply a GPO.

Square overview tiles show inventory counts and one application percentage
per active provider/platform/system-type family. Windows releases share a
family; different providers remain independent. Catalog target filters do not
change the overview population. Hiding a baseline removes that release from
the active family, without removing inventoried systems from its denominator.

## Read-only evidence

The optional `group_policy` object is carried by the existing schema-1
`windows-server-core` inventory. It reports computer scope only. The fixed
native child `--collect-windows-group-policy` has a 30-second deadline,
128-MiB process limit, single-process job and 64-KiB output bound.
No server-selected query, path, command, script or executable is accepted.

The collector correlates local RSoP GPO records with Windows' applied GPO
list for every reported client-side extension. A positive entry requires
matching domain, GPO GUID and version, enabled/access/filter checks, complete
error-free extension logging and a stable before/after snapshot. Disabled
RSoP logging, denied access, overflow, partial output and changes during
collection cannot produce a positive result. Observation and processing
times are retained; receiving queued data does not refresh their age.

Primary Windows API references:

- [GetAppliedGPOListW](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappliedgpolistw)
- [RSOP_GPO](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-gpo)
- [RSOP_ExtensionStatus](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/rsop-extensionstatus)

## Identity and counting

The receiver validates the bounded report before inventory persistence and
binds it to the authenticated enrollment and current inventory identity.
Missing evidence from an older Agent clears the previous report. Changed
domain, role, OS identity, revoked enrollment or stale evidence cannot retain
a previous confirmation.

A small server-owned watermark survives cleared reports. It retains the
highest observation time and an invalidation boundary bound to the enrollment.
Omission or identity changes block queued evidence through the receipt time
plus the allowed five-minute clock skew. Recovery requires a strictly newer
observation beyond that boundary. Identical retries are idempotent; conflicting
reports with the same observation time remain unknown. The native collector
also discards only its GPO evidence if the independently observed domain does
not match the domain captured by core inventory.

A successful, verified import receipt establishes the association between a
deployed domain/GPO GUID and its pinned baseline component. An import receipt
alone never proves application. Display names, matching individual settings
and intended assignments are not identity evidence. An externally managed
GPO without a known association remains unmapped.

Confirmation requires all computer-scope components of the applicable
baseline profile. Shared components may satisfy multiple profiles only when
their exact backup and artifact identities agree. User-only and domain-only
components are outside this computer-scope metric. The association identifies
the baseline; it does not attest that the GPO's contents remain unedited.

Each inventoried system contributes once to its family. The states are:

- **Applied:** all required components have current positive evidence.
- **Partly applied:** some components are confirmed, but the profile is incomplete.
- **Not applied:** complete known mapping and current conclusive negative evidence.
- **Unknown:** missing, stale, failed, ambiguous or unmapped evidence.

Both observation and processing evidence must be no older than 24 hours;
timestamps more than five minutes in the future are invalid. The percentage
is confirmed systems divided by all inventoried systems of that type. A
family with no conclusive results, or no systems, displays an unknown value
instead of presenting an unsupported zero percent.

Existing compliance results, history, local pilot approval, unlinked/disabled
pilot behavior, default policies and tier boundaries remain unchanged. This
release does not authorize or implement unattended AD policy activation.
