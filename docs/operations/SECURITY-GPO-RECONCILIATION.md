# GPO directory reconciliation

Version: 1.0.0 | Created: 2026-09-15 | Modified: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Candidate: Portal 0.2.57 / Windows Agent 0.2.37

## Operator workflow

Open the affected GPO request in **Logs > Baselines**. Select **Reconcile
directory** to ask the original domain controller Agent to read its protected
receipt, the known GPO and the complete forest link inventory. This action does
not need an interactive logon to the domain controller and grants no directory
write authority. The original request keeps the domain fence while the
observation is pending or being reviewed.

Review the observed identity, policy flags, directory/SYSVOL versions, target
links and reported limitations in that same log entry. Unknown or unreadable
information is not treated as an absent GPO or an empty link inventory.
The observation does not prove that the baseline settings were imported.

**Accept reconciliation** is available only to an authorized administrator for
that domain and tier and only when the observed state meets the recovery checks.
The optional four-eyes policy remains effective. Acceptance identifies the exact
observation digest; it does not submit another import or activate policy settings.

The Agent checks the directory again after acceptance. A changed observation
requires a new reconciliation. The Portal releases the domain fence only after
the Agent acknowledges the matching observation and protected resolution record.
An offline Agent therefore leaves acceptance pending.

## Accepted state and remaining work

The supported recovery state is an unambiguously identified IPMS-owned GPO with
both policy halves disabled, consistent readable metadata and a complete safe
link inventory for the authorized targets. Unknown identity, missing ownership,
foreign or enforced links, active policy, incomplete forest visibility and
directory/SYSVOL inconsistencies prevent acceptance.

The original request remains a historical failure with a separate reconciliation
record. It is never relabeled as a successful import, link or activation. The
managed identity retains the recovered GUID, but its prepared and active content
claims are cleared. A subsequent normal request reuses this identity and goes
through the existing inspection and approval workflow.

There is no manual checkbox that bypasses an unresolved observation. Repairs
that change directory objects require a separate authorized change. Neither
reconciliation action modifies a default policy, GPO content, link or ACL.

## Evidence and compatibility

Reconciliation diagnostics distinguish failure to connect to GPMC, open the
recorded GPO, read metadata, execute the isolated worker, and validate its result.
Failed Windows COM calls additionally report a bounded, numeric HRESULT; raw
exception text is never transported. Access denial is reported only when Windows
actually returns that error. The legacy `gpo_reconciliation_state_unavailable`
code alone does not establish an AD or SYSVOL permission problem.

These diagnostic codes remain blocking findings. Deploy a Portal supporting the
expanded diagnostic allowlist before deploying an Agent that emits them. Existing
reports remain readable; a fresh observation is required for additional detail.
Do not bypass reconciliation or broaden directory permissions based solely on
the legacy generic message.

Read requests, observations, acceptance and Agent acknowledgments are separate,
bound records. Original assignment, result and protected receipt bytes remain
unchanged. Idempotent retries cannot create replacement GPOs or replay the failed
write. A release sidecar is valid only for the original job, enrollment, journal
and accepted observation.

Older Agents cannot perform this workflow. Agent build/contract and synthetic
Portal tests do not establish live Active Directory recovery acceptance; that
requires observing the intended domain controller and an actual reconciliation.

An Agent-reported terminal failure can permit a forward, checksum-pinned update
to a reconciliation-capable Agent through the normal update workflow. This
exception does not permit uninstall, replacement enrollment, an unfinished
directory write or a server-only timeout with no terminal Agent receipt.
The updater preserves the protected GPO storage.

The application adds a reconciliation table and a `reconciled` historical job
status. Do not remove these records or downgrade to an application that cannot
interpret them after a reconciliation has completed. Recovery and rollout
procedures must preserve the original journal and every resolution sidecar.
