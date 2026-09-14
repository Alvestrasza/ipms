<!--
File Name: ADR-0015-SECURITY-BASELINES.md
Version: v0.1.1 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Modular security baseline catalog, evidence and future enforcement boundaries.
-->
# ADR-0015: Security baseline catalog and evidence

Status: accepted; the 0.2.44 catalog/reporting foundation is verified on DEV.
Native assessment, remediation and production acceptance remain future work.

## Context

IPMS needs a Security category that can grow from Windows security assessment
into configurable, collection-targeted security policies. Microsoft GPO
baselines are the first catalog family. CIS, other benchmark providers, Linux,
switches and firewalls must retain their own versioned definitions and adapters.
The current Agent reports inventory and update posture, but does not evaluate
complete Microsoft GPO baselines. Update currency is not GPO compliance.

## Decision

Separate four responsibilities:

1. **Catalog:** provider, platform, stable package identity, product release,
   published revision when available, source and verification date. Catalog
   metadata is shipped with the Control Plane. It contains no executable GPO,
   shell, PowerShell or remote-command payload.
2. **Assessment:** a future native, compiled-in evaluator measures effective
   configuration using a verified, complete control manifest and role profile.
   The Control Plane receives authenticated evidence bound to tenant, Agent,
   system, baseline revision, catalog revision, OS identity and observation time.
3. **Policy and targeting:** a future tenant-owned configuration overlay and
   collection assignment refer to immutable baseline revisions. Preview the
   resolved membership, applicability, conflicts and differences before rollout.
4. **Enforcement:** future explicitly authorized, typed operations need dedicated
   RBAC, audit, maintenance windows, staged deployment, rollback and verification.
   Domain GPO deployment and endpoint-local settings require separate executors
   and trust boundaries. A local Agent is not automatically a domain GPO writer.

Only catalog, applicability, the assessment storage/read model and percentage
calculation are implemented in 0.2.44. No assessment producer, control importer,
baseline editor, collection model, scan job or deployment operation is enabled.
API capability flags remain false for assessment, collections and deployment.
No new Agent binary or protocol command is introduced.

## Evidence and percentage semantics

The inventory denominator is all matching Windows inventory rows in the selected
tenant, including physical and virtual systems without usable Agent evidence.
Match product name, base OS build and client/server/DC role together. These are
**candidates** for the package, not proof that an edition, domain membership or
every component is applicable. Unknown roles and unmatched releases remain
visible. Windows 11 26H1 is not silently assigned the 25H2 baseline.

For each baseline:

`compliance = fully compliant systems / all matching systems * 100`

`coverage = systems with a current complete result / all matching systems * 100`

One pass, one failure, one unknown and one stale result means **25% compliance**
and **50% coverage**. No complete result means a null compliance percentage;
no matching systems means both percentages are null. Fully measured failures
produce 0%, not an unknown value. There is no average across unrelated baselines.

Select the newest observation, even when it is incomplete or unsuccessful.
Never fall back to an older pass. Assessments expire after 24 hours; heartbeat
traffic and fresh inventory do not extend that time. Changed baseline/catalog
revision, OS identity or role invalidates evidence. Revoked/removed Agents,
unverified scope, missing controls, collection errors and entirely inapplicable
control sets cannot produce a compliant result. Counts must match in the DB.

The internal `BaselineAssessment` model has **no external write endpoint**.
Its `scope_verified` field is an internal trust assertion, not a proof engine.
The future ingestion path must derive it from a pinned, fully imported control
manifest and verified native results; never accept this flag or aggregate counts
from a browser or treat unvalidated Agent totals as proof. Individual controls,
package/rule-set digests, receipts, duplicate handling and audit are required
before enabling the producer. The only records created in this change are
synthetic records in isolated tests.

Microsoft's packages include multiple GPOs (computer, user, domain security,
Defender, BitLocker, VBS/Credential Guard as appropriate). A few registry probes
or the primary member-server GPO alone cannot establish full-package compliance.
User/domain-scoped controls and workgroup applicability need explicit decisions
in the future evaluator. Existing `server` inventory means a non-DC server;
it does not itself prove domain membership.

## Isolation and compatibility

Reads require authenticated active tenant access and `inventory.view`. Platform
administration grants no tenant access. Assessment tenancy is inherited from
its system FK; enrollment must match tenant, source identity and platform.
Reads enforce both system and enrollment tenancy. API responses are no-store,
contain bounded projections and paginate system details in groups of 25.
No certificates, secrets, internal errors or raw policy payloads are exposed.

The additive migration creates one initially empty table. It does not alter
Agent enrollment, collection schedules, Windows Update sources, GPOs or managed
infrastructure. Future non-Windows evidence needs its own platform adapter and
device model, retaining these catalog/evaluation/assignment boundaries rather
than putting network devices into Windows inventory.

## Alternatives and consequences

Do not merge Microsoft, CIS, DISA STIG, Intune and OSConfig results into one
benchmark. They have distinct definitions, licenses and policy mechanisms.
Third-party package/license review and immutable hashes precede redistribution
or import. No third-party baseline files are redistributed by this preparation.
Catalog refresh must be reviewed and versioned; the SCT-wide version/date is
not an individual package revision.

See [Security baseline operation and sources](../operations/SECURITY-BASELINES.md).
