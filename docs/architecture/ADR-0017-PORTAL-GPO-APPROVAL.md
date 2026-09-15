<!--
File Name: ADR-0017-PORTAL-GPO-APPROVAL.md
Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Tenant-configurable, domain- and tier-scoped central pilot approval.
-->
# ADR-0017: Central approval of exact GPO pilot requests

Status: accepted owner decision, 2026-09-15; implementation and execution
acceptance are recorded separately. Supersedes the mandatory local approval
requirement of [ADR-0016](ADR-0016-TIER-DOMAIN-GPO-PILOTS.md) for new Portal
requests. It does not authorize a directory mutation during development.

## User workflow

An administrator creates a request in Security Baseline. A permitted reviewer
opens its entry in Logs, inspects the exact domain, target tier, executor,
component, settings report, content hashes, proposed pilot name and expiry,
then explicitly approves that request in the Portal. Viewing or copying a
request never approves it. New requests require Windows Agent 0.2.34 or later.

The tenant administrator manages explicit domain/tier grants and the tenant's
four-eyes setting in Administration. There are no implicit all-domain grants.
An active tenant administrator with a matching grant may request and approve;
an active Approver with a matching grant may approve. Platform administrators
and unrelated tenant members gain no customer execution authority.

Four-eyes approval defaults to **off**. A customer with one administrator can
explicitly approve his own request if he holds its domain/tier grant. When
four-eyes approval is enabled, the approver must be a different user from the
requester and must independently hold the required scope. A tier with only one
administrator has no automatic exception. Saving a policy or grant change is
not approval of any request. Revision conflicts require reloading the settings.

Import, linking and activation remain separate actions. The implemented
operation creates only a new disabled, unlinked pilot GPO. No operation in
this release links a GPO, enables it, runs policy refresh, changes a default
policy, modifies OUs or grants AD permissions.

## Authority and immutable bindings

New assignment schema 2 includes `approval_mode: portal`; the existing input
digest includes this field and all other immutable job fields. Persisted
schema 1 jobs remain legacy local-approval jobs and cannot be converted or
centrally approved. A local approval file cannot authorize a schema 2 job.

The approval binds the job ID, input digest, enrolled device, domain GUID,
concrete tier, operation, requester, approver, approval time, exact job expiry,
tenant policy revision and four-eyes requirement. The API validates the
reviewed digest and policy revision. Current user memberships, scoped grants,
domain configuration, executor identity, artifact identity and expiry are
checked again before execution. Changes to approval policy or grants invalidate
prior authority. Identity withdrawal covers both requester and approver.

The Agent receives approval through the existing authenticated TLS exchange.
It independently checks all bindings, strict field types, time bounds and the
distinct-user requirement when enabled. The execution claim must carry the
same approval as the validated offer. A protected one-use receipt passes that
approval to the fixed native worker. Durable intent precedes the one-shot
claim; a short monotonic deadline bounds execution. Restart, lost replies or
ambiguous writes cannot turn an old claim into another write. Historical
receipts remain readable after expiry without restoring execution authority.

## Trust boundary

Authentication of approval comes from the existing trusted gateway connection
and protected local state. This is not an independently signed approval from
an external zone authority. The Control Plane, its administrators, database,
gateway and privileged Agent update path are part of the execution trust
boundary. Domain/tier grants constrain application users; they do not isolate
a compromised Control Plane from a domain it is trusted to manage.

An installation capable of managing domain controllers must be administered
within the corresponding privileged boundary. Independently secured zones
require independent administration and execution/update trust. This release
does not introduce cross-zone credentials or claim that a shared role table
provides complete tier isolation.

## Compatibility and recovery

Old Agents retain their existing read-only inventory and legacy pilot behavior.
The Portal does not offer a new central-approval job to an incompatible Agent.
The Agent rejects incomplete, mismatched or missing central authorization.

Only one active or ambiguous pilot occupies a domain. Policy, membership,
grant or tenant changes withdraw unclaimed authority; a potentially claimed
write remains fenced for reconciliation. A short execution grant already
issued to a worker may complete; revocation does not claim to undo an AD call
that has started. No automated GPO deletion, retry,
journal reset or database rollback clears that fence. Default policies and
existing customer GPOs remain outside the mutation interface.
