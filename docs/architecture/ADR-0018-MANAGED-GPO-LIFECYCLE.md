# ADR-0018: Approval-bound managed GPO lifecycle

Version: 1.1.0 | Date: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Status: Accepted design; live domain acceptance tracked separately

## Decision

Use stable managed GPO identities. Since Portal 0.2.56, import and linking form
one approved request; activation and deactivation remain separate. This replaces
the earlier requirement to request import and linking separately and supersedes the new-pilot-only product
flow in ADR-0016 while retaining the schema-1/2 wire contracts and history.
ADR-0017 domain/tier authorization and optional tenant four-eyes approval apply
to every write. No interactive domain-controller login is required for approval.

The combined operation creates a disabled GPO with its configured short name and
links it disabled and non-enforced to the approved targets. Subsequent imports validate and stage pinned content without writing the
existing GPO, including its active name. Activation backs up and updates that
same GUID. Updating an active GPO during an import would immediately change
effective policy and would violate the separation between import and activation.

Each write starts with an internal read-only inspection job. For import and link,
the Portal automatically proceeds from a successful inspection to one approval
request; the administrator does not manually create the intermediate jobs. The result contains
the actual GPO identity, versions, flags, security digest, WMI filter, links and
the target object GUIDs, USNs, inheritance and link order. A new immutable
write assignment binds that snapshot. Its maximum lifetime is the inspection's
15-minute expiry, not a renewed expiry. The Agent independently reads and
compares the full expected state immediately before a write. Drift fails closed.

Schema 3 extends the existing bounded exchange and protected journal. Snapshot
size is limited to 16 KiB and assignments to 24 KiB within the existing 64 KiB
transport. Oversized observations fail; they are never truncated. Inspection
uses a dedicated read-only provider path and cannot consume a write approval.

Link requests require both GPO halves disabled. They insert or reorder only the
managed GPO's disabled, non-enforced links within the approved scope, preserving
the relative order of unrelated links. Activation verifies the prepared version,
backs up the GPO, enables its intended C/U half and the approved links.
Deactivation disables both halves; it does not remove links. Reconfiguration
requires another inspected and approved request. Saving domain configuration
never deploys policy or creates/moves OUs.

Computer and user components target configured tier OUs. Compiled Domain Security
components instead target only the root derived from the selected domain and
require Tier 0 authority plus explicit domain-wide target confirmation. The root
object GUID must equal the approved domain GUID. The immutable assignment binds
that root and component; combined import/link and activation remain separate. Default
policies are excluded by GUID and their existing flags are preserved.

Before mutation, the native provider checks the complete forest domain inventory
and combines bounded signed/sealed LDAP DirSync link observations with GPMC
observations. Domain and site visibility must be complete; missing read rights,
unreachable domains or conflicting links fail closed. Only the originally
approved domain controller is used for mutation. No directory privileges are
automatically granted to satisfy these checks.

Legacy adoption is explicit and verifies the successful previous import job,
GUID, content identity and ownership marker. The existing GPO must remain
disabled and unlinked. Matching a display name is never authority to modify an
arbitrary customer GPO. Default policies are excluded by GUID.

## Recovery and authority

Each write retains the existing authenticated one-use claim and 15-second
monotonic grant. Approval, tenant policy, enrollment and domain/tier grants are
checked again at claim time. No independent signature or cross-tier trust
boundary is claimed: the Portal and enrolled executor remain security-sensitive
authorities. Native service permissions must already permit the intended action.

Protected durable write intent precedes mutation. Failure or uncertain completion
after that intent requires reconciliation; automatic replay, GPO deletion and
automatic restore are forbidden. A backup is recovery material, not proof that
every resulting endpoint setting is reversible. Activation requires explicit
management-access and independent recovery-access review. These reviews do not
replace testing the effective firewall, logon rights and connectivity on targets.

The combined executor retains the newly created GUID before proceeding to links.
It rereads the approved scope after import, allowing only the known creation or
adoption changes. Target drift or a partial failure stops execution and retains
the GUID for reconciliation. It does not renew the claim, replay creation or
activate the GPO. This is one approval, not a claim of transactional AD writes.

## Compatibility

The migration adds managed identities without changing existing job columns.
The legacy name uniqueness constraint applies to schema-1/2 assignments; managed
identities have their own domain/tenant uniqueness constraints. Deploy the receiver
before Agent 0.2.36. Existing assignments are immutable and are not upgraded.
The new combined operation uses the existing schema-3 fields and requires Agent
0.2.36; historical separate operations retain their existing interpretation.
Only a confirmed active managed revision can identify production baseline content;
endpoint application still requires the Agent's separate Windows processing
evidence. A prepared version or successful import does not count as application.
