<!--
File Name: ADR-0016-TIER-DOMAIN-GPO-PILOTS.md
Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Domain planning and independently approved native unlinked GPO pilots.
-->
# ADR-0016: Domain plans and native GPO pilots

Status: accepted design; implementation candidate in Portal 0.2.48 and Windows
Agent 0.2.32. This is not a declaration of deployed or live AD acceptance.
Tracking: [security and identity epic #34](https://github.com/Alvestrasza/ipms/issues/34).

The owner decision of 2026-09-15 supersedes the mandatory local approval
requirement for new requests with [central domain/tier approval](ADR-0017-PORTAL-GPO-APPROVAL.md).
The local workflow below remains the contract for persisted schema 1 jobs.

## Context and decisions

Customers have different forests, domains, OU layouts, tier boundaries and
naming conventions. A domain name, OU name or portal role is not a security
boundary. Domain controllers can store policies for member servers and clients;
the tier of a policy's intended targets is distinct from the authority needed
to administer its GPO in AD. A writer on a domain controller is privileged
infrastructure regardless of the eventual target tier.

Tenant administrators configure multiple existing OU DNs for each of tiers
0, 1 and 2. The API checks supported DN syntax, domain suffix, duplicates and
cross-tier containment. These are manually entered plans, marked **unverified**.
Saving a plan does not resolve, create, move or rename directory objects. A
later activation phase must resolve objectGUIDs, detect moved/replaced OUs and
inspect inheritance. Do not relocate the Domain Controllers OU to impose a
particular customer layout.

The naming template uses `{tier}`, `{scope}`, `{target}`, `{purpose}` and
`{version}` exactly once. The default is
`{tier}-{scope}-{target}-{purpose}_V{version}`. Computer/user scope becomes C/U;
the component manifest determines it. A is a shared logical template that
produces separate concrete tier GPOs. The accepted production lifecycle keeps
a stable GUID and updates its active version name, with separate pilots and
protected historical packages outside active AD. This first slice creates
pilots only; it does not adopt or update production GPOs.

The ordered baseline list records proposed composition from first to last.
Later entries are intended to override earlier entries where applicable. It
does not calculate effective policy, resolve conflicts or change AD link order.
Microsoft, CIS and corporate overlays remain distinct versioned content. Only
the eight actual Microsoft catalog entries are available in this candidate;
unknown or unlicensed providers cannot be inserted by sending a new ID.

## Native execution boundary

The single operation is `create_unlinked_pilot` for one original GPO backup
component. A Microsoft package contains several components; they are not
flattened into an invented combined GPO. The 64-component content census pins
original archive, artifact and file hashes. Raw vendor payloads are operator
provided and never tracked or redistributed in the product source archive.

An exact job binds tenant/enrollment, local writable DC FQDN, domain GUID/DNS,
forest DNS, settings ID/revision, concrete target tier, original baseline,
profile and backup ID, artifact hash, pilot name and expiry. Its digest is
SHA256 of compact sorted-key UTF-8 JSON excluding `input_digest`. No received
destination GUID, path, URL, command, script, OU link or ACL mutation is allowed.

Portal authorization can propose the job. A locally elevated administrator on
the selected DC must independently approve the full immutable job. Approval
and journal files are restricted to SYSTEM and local Administrators, including
checks against replacing their parent directories. Approval is consumed once
before creation. The approval command itself performs no AD operation. It is
not replaced by a portal checkbox or a shared cross-tier credential.

The bounded native GPMC child revalidates writable-DC identity and selects the
exact local DC. It checks for a name collision, creates a new GPO, records its
GUID, disables both halves, identifies the pilot, imports the pinned settings
and disables both halves again. Verification checks identity, disabled state,
ACL consistency, directory/SYSVOL version consistency, WMI association and
domain/OU/site links. The two default GPO GUIDs and all pre-existing customer
GPOs are outside the mutation interface. No restore, delete, link, enable or
ACL-setting operation exists in this provider.

GPMC [Import](https://learn.microsoft.com/en-us/windows/win32/api/gpmgmt/nf-gpmgmt-igpmgpo-import)
with flags 0 preserves destination identity/security and does not import links;
both its HRESULT and OverallStatus must succeed. Exact DC selection follows
[GetDomain](https://learn.microsoft.com/en-us/windows/win32/api/gpmgmt/nf-gpmgmt-igpm-getdomain).
Independent administrators can change AD concurrently; a staging receipt is an
observation at completion, not a permanent claim about all later changes.

## Authority, recovery and compatibility

Only one active or ambiguous import may occupy a tenant/domain GUID. The first
claim grants execution once; repeated claims never grant another write. Durable
intent precedes creation and the returned GUID is persisted immediately. A
lost create/import result retains the local journal and server domain fence.
There is no automatic retry, name-based adoption or deletion of a suspected
orphan. A definitive never-claimed cancellation can close the prepared journal;
an uncertain claim remains a reconciliation case. Exact result receipts replay
without another AD operation.

Tenant suspension, identity changes and membership authority changes withdraw
old requests durably. Re-enabling an account cannot revive them. Agent lifecycle,
remote installation and administrative removal respect GPO reservations in
both directions. An expired unclaimed offer does not block maintenance forever;
every claimed or ambiguous write continues to block it. Late authenticated
receipts can describe already granted work after its requester loses authority.
They cannot grant new work or manufacture assessment coverage.

Schema migration `security.0004_domain_gpo_pilots` is additive. Its foreign keys
and durable fences require a reviewed rollback plan; reverting application code
does not undo an AD write. Do not discard job tables or journals to clear an
ambiguous operation. Pilot staging does not change compliance or scan results.

## Deferred activation and tier isolation

Linking, enabling, production-GUID promotion, Collections, conflict analysis,
directory object verification and effective-policy assessment remain separate.
[Group Policy processing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
includes inheritance and enforcement; a list order alone cannot predict it.
Default policies keep their identities and contents, and their intended lowest
precedence must be assessed at each actual link location before later changes.

Firewall activation must preserve the configured IPMS endpoint and required
DNS, authentication, policy, PKI and recovery paths. Pilot acceptance needs a
new authenticated administrative session and an independently tested recovery
path. An existing heartbeat or local timer cannot guarantee recovery from a
domain policy that blocks management.

The same IPMS product can serve independent zones. Shared UI, SSO, package
publication or Agent update authority capable of controlling Tier 0 belongs
inside that trust boundary. This local approval mechanism does not implement
complete Tier 0 isolation: an unrestricted privileged Agent updater is itself
a control path. Zone-specific administration, update trust, credentials and
approval custody remain prerequisites for production use across tiers.

See [operator workflow](../operations/SECURITY-GPO-PILOTS.md) for the first slice
and the linked issues for the remaining implementation.
