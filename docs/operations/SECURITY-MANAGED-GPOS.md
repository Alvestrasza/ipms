# Managed GPO operations

Version: 1.1.0 | Date: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Applies to: Portal 0.2.56 / Windows Agent 0.2.36

## Configuration

In **Administration → Security → Domains**, configure each domain's existing
tier OUs, naming template and baseline composition order. No OU layout is assumed
or created. A template such as `{tier}-{scope}-{target}-{purpose}_V{version}`
produces names such as `0-C-ALL-MS-WS2025-DC_V1.0.0`. Component aliases retain
distinctions such as VBS, Credential Guard, BitLocker and user policy. The GPO
GUID is the stable identity; its active name changes when a version is activated.

Grant the requesting and approving administrators explicit domain/tier access.
Four-eyes approval is optional per tenant. When enabled, the approver must be a
different authorized principal. The enrolled writable domain controller must
report the matching domain identity, GPMC prerequisites and Agent 0.2.36 or later.
The service identity needs the corresponding AD permissions. IPMS installs no
service account or directory permissions as part of these actions.

## Import and link with one request

In **Security → Baseline**, select the domain, managed GPO (or new GPO), baseline
component, tier and executor. Choose **Import and link** and create the request.
The Portal runs the read-only inspection in the background and prepares one
approval request covering both import and the exact target links. Review and
approve it in **Logs → Baselines**. No separate import or link request is needed.
Creating or viewing a request does not approve it. Activation remains separate.

| Action | Result |
| --- | --- |
| Import and link, new GPO | Final short name and stable GUID; GPO and target links disabled, links non-enforced |
| Import and link, existing disabled GPO | Pinned version prepared and disabled target links arranged; content applied during activation |
| Prepare a version | Pinned package prepared; active GPO unchanged |
| Link | Managed links placed on the approved OUs or domain root, disabled and non-enforced |
| Activate | Protected backup, prepared content applied to stable GUID, intended half and approved links enabled |
| Deactivate | Both GPO halves disabled; existing links retained |

The combined import and link uses one approval. Each action must have a fresh
successful inspection, which expires after 15 minutes. Changed configuration,
permissions, managed revision or directory state require a new inspection.
Changes to baseline order are applied only through another approved link action.
An active GPO must first be deactivated before its links can be changed.

Microsoft **Domain Security** components use the selected domain's root and
require Tier 0 authorization. Before requesting import and link, linking,
activation or deactivation, explicitly confirm this domain-wide target. The Portal derives the
root from the configured domain; the Agent verifies its domain object GUID.
Tier OU mappings are not required for this scope. Regular computer and user
components continue to use configured tier OUs. The target confirmation does
not approve a write: the combined request still needs explicit approval.
Neither Default Domain Policy nor Default Domain Controllers Policy is modified.
Managed links are inserted before default-policy links while preserving the
relative order and flags of unrelated links.

The read-only inspection checks links across every domain in the same forest
and the forest's site configuration. The executor needs complete read visibility,
including the rights required for the DirSync checks on those naming contexts.
IPMS does not grant these rights. Missing visibility, unreachable domains,
oversized results or links outside the approved scope stop the operation before
mutation. Validate these prerequisites using a read-only inspection first.

Before activation, explicitly review that IPMS connectivity and administrator
access remain permitted and an independent recovery path is available. This is
a required review, not an automatic firewall or lockout simulation. Validate
effective policies and endpoint access as part of domain acceptance.

## Existing imports and recovery

An existing successful IPMS import can be explicitly selected for adoption.
The Agent checks its previous job, GUID, artifact and ownership marker and
requires that it is still disabled and unlinked. IPMS does not rename all old
GPOs or adopt unrelated objects automatically. Historical records retain their
original protocol and names.

A timed-out, failed or uncertain directory write can require reconciliation.
Inspect the recorded job GUID, protected Agent receipt and actual directory
state before proceeding. Do not delete the journal, resubmit a replacement job
or restore a backup automatically. Activation stores a protected GPMC backup and
manifest before mutation; restoration remains an operator-led recovery action.
Endpoint settings can persist after deactivation and may need explicit recovery.
If import succeeds but linking cannot complete, the recorded GPO GUID is retained
for reconciliation. The Agent never creates a replacement GPO automatically.

Logs show the individual inspection and write outcomes and retain the existing
sort, filter and CSV export controls. A successful activation is not by itself
proof of application on clients: dashboard coverage uses the Agent-confirmed
Windows GPO processing evidence for the active managed identity.
When a later version is prepared, the Portal shows the confirmed active name
separately. Missing active-version evidence is displayed as unverified.

## Verification boundary

Native provider compilation, contract tests and Portal integration fixtures do
not establish successful execution against a real directory, AD replication,
firewall reachability or recovery on endpoints. Record these checks separately
for each domain and tier before broad policy activation.
