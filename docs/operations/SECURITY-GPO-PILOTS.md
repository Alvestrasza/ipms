<!--
File Name: SECURITY-GPO-PILOTS.md
Version: v0.2.0 | Created: 2026-09-14 | Last Modified: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Configure domain plans and prepare independently approved unlinked pilot GPOs.
-->
# Domain settings and GPO pilots

Candidate: Portal **0.2.53**, Windows Agent **0.2.34**. Source implementation,
automated verification and actual domain acceptance are separate. This guide
does not authorize a live import or claim the candidate is deployed.

## Configure the tenant domain

Open **Administration → Security → Domains & GPOs** as a tenant administrator.
This is tenant administration, separate from the platform-only tenant catalog.

1. Enter the DNS domain and existing OU DNs for each tier. Each tier accepts up
   to 32 OUs, including nested customer layouts. For example,
   `OU=Servers,OU=Operations,DC=example,DC=invalid`. Empty tiers are allowed.
   Cross-domain DNs, duplicates and overlapping cross-tier branches are rejected.
2. Enter a naming template, for example
   `{tier}-{scope}-{target}-{purpose}_V{version}`. The preview shows the three
   concrete tiers. Target aliases and policy versions are chosen with the pilot
   request. Pilot names contain a component-specific suffix; names are bounded
   to 240 ASCII characters and collisions are rejected.
3. Arrange the available baselines with drag and drop or the keyboard-accessible
   up/down buttons. The list expresses intended composition from first to last;
   it does not alter live GPO links. CIS content will appear only after a
   separately reviewed provider/package implementation.
4. Save. All manually entered OU plans remain **directory unverified**. Saving,
   changing order or hiding a baseline never creates an import job or applies
   a policy. Domain DNS identity is immutable after creation. Concurrent edits
   use an expected revision and preserve the unsaved draft on conflict.

The settings API is bounded to 100 domain plans per tenant. Catalog visibility
and composition order are separate: hiding a baseline does not silently remove
it from a saved plan. All current catalog IDs occur once in a saved order.

## Prepare content and an eligible executor

Use the exact Microsoft source archives pinned by
`scripts/import-security-baselines.py`. Acquire and retain them under the
operator's applicable content/license terms. The repository distributes only
metadata, hashes and native descriptors, not the raw GPO backup bytes or vendor
executables. The preparation script reads archives as data and runs no vendor
script, installer or executable.

Verify descriptors against the source archives, then prepare artifacts outside
the checkout and compare the review output with the committed descriptors:

```text
python scripts/import-security-gpo-packages.py --package-dir operator-content --check
python scripts/import-security-gpo-packages.py --package-dir operator-content --output-root content-review --prepare-artifacts --artifact-dir gpo-artifacts
```

The artifact format is `IPMSGPO1`, a fixed file count and length-prefixed file
bytes. Paths, directories, counts, sizes and hashes come from compiled
descriptors. Maximums are 16 files, 512 KiB per file and 1 MiB per component.
Each artifact is named by its full SHA256. The complete cache has 64 original
components covering twelve profiles and eight products. Components stay
separate; domain-specific SID/UNC remapping is not available in this slice.

For a reviewed deployment, configure `IPMS_SECURITY_GPO_ARTIFACT_DIR` in both
the Control Plane and Agent Gateway environments. The protected operator cache
must be readable by those service identities. Missing, changed, hardlinked or
unsafe artifact files are rejected. Without an available verified component the
Portal cannot queue its import. No runtime configuration is changed by building
or running the preparation tool.

For a new centrally approved request, the selected executor must report Windows
Agent 0.2.34 or later, active enrollment,
a heartbeat and native executor observation less than five minutes old, matching
domain/inventory identity, a writable local DC and available GPMC. RODCs, member
servers and clients cannot execute this provider. No GPMC feature installation
is triggered. **Ready for approval does not prove AD write permission.**
Validate the service identity and delegated GPO rights in the selected test
domain. Do not reuse the Hyper-V console account, grant broad rights automatically
or use one shared service credential across tiers.

## Configure central approval

In **Administration → Security → Domains & GPOs**, configure the tenant-wide
four-eyes requirement and explicitly assign permitted administrators to each
domain and tier. Tenant administrators may request and approve within their
granted scope; Approvers may approve within theirs. There are no implicit
domain/tier grants. Saving these settings neither creates nor approves a job.

Four-eyes approval is off by default. With it off, a single scoped administrator
can create a request and explicitly approve it afterward. With it on, another
scoped administrator must approve. There is no exception for tiers with only
one administrator. Changing approval policy or grants invalidates outstanding
authority, so review settings before creating requests.

## Request and centrally approve one pilot

1. In **Security → Baseline**, select a configured domain, its eligible DC,
   the baseline component, concrete target tier, target alias and version.
   Request the pilot import. This creates an immutable request, valid for at
   most one hour, without starting an import.
2. Open the request in **Logs → Baselines**. Review the domain, tier, DC,
   proposed name, baseline component, exact settings report, manifest and
   expiry. This operation creates a new disabled, unlinked pilot; it does not
   modify existing policies or apply settings to computers.
3. Explicitly approve the displayed request. If four eyes are required, use
   another administrator with the matching domain/tier grant. The server
   checks the reviewed digest and policy revision; stale reviews are rejected.
4. The Agent receives the bound approval over its existing authenticated
   connection and obtains a one-use execution grant. It validates the local
   controller and immutable content again, then imports only the pilot.

No interactive DC sign-in or local approval command is required for these
schema 2 requests. An expired or invalidated request needs a new request and
review. Linking and activation are separate future actions, not consequences
of this approval. See [ADR-0017](../architecture/ADR-0017-PORTAL-GPO-APPROVAL.md)
for the application authorization and deployment trust boundaries.

## Approve a legacy local pilot

The following procedure applies only to already persisted schema 1 jobs.
They cannot be converted into centrally approved jobs. New Portal requests
use the central workflow above.

1. Select the domain plan, DC Agent, baseline, original backup component,
   concrete tier, target alias and policy version. A configured OU list is
   required for that tier, but the pilot remains unlinked. Domain-wide and
   DC-only components require a Tier 0 plan. The DC stores the GPO even when
   its future intended targets are clients or member servers.
2. Select **Request unlinked pilot import**. This creates one immutable job
   valid for at most one hour. Its approval document is the exact full job JSON.
   Retrying the same request cannot create another job.
3. Independently review domain GUID/FQDN, component, version, content hash,
   settings revision and pilot name from a trusted administrative session in
   the selected zone. Save the approval document on that exact DC, for example
   `D:\IPMS\Approvals\pilot.json`.
4. From an elevated local administrative shell, invoke the installed Agent:

   ```powershell
   & '<installed-agent-directory>\ipms-agent.exe' --approve-gpo-pilot 'D:\IPMS\Approvals\pilot.json'
   ```

   The command validates and writes a one-time protected approval. It does not
   itself import the GPO, install tools or change the service identity. Never
   automate this independent approval using the same portal authority that
   proposed the job.
5. The Agent's separate worker validates the artifact and obtains a one-time
   grant. A fixed GPMC child has a 120-second limit and a 256 MiB memory limit.
   It creates only the new pilot, disables both computer and user settings,
   imports the original backup and verifies that it remains disabled/unlinked.

Default Domain Policy, Default Domain Controllers Policy and existing customer
GPOs are not mutation targets. No OU, domain or site link is created. No local
policy application, `gpupdate`, restart or firewall activation occurs.

## Interpret and recover jobs

| Portal state | Meaning |
| --- | --- |
| Queued / awaiting approval | No execution grant yet; approval or the Agent's claim is outstanding. The detail identifies central versus legacy local approval. |
| Running | One grant was issued; it cannot be issued again. |
| Staged | Agent observed the new GUID with both halves disabled and no domain/OU/site links. |
| Failed / expired | A terminal pre-execution failure or expiry; inspect the reported reason. |
| Reconciliation required | A write or claim may have happened; the domain remains fenced. |

Staged is not applied, replicated everywhere, or compliant. Continue using
independent scans; this workflow never writes baseline assessment results.
An Agent timeout, lost acknowledgement or service interruption cannot safely
prove that AD was unchanged. Preserve the per-job journal, approval receipt,
returned GUID and audit record. Inspect AD and the exact domain controller using
a trusted administrative path. Do not delete the journal, reuse the name,
retry the import or remove the Agent to bypass reconciliation. There is no
automatic cleanup or manual reconciliation API in this first slice.

Only one active/ambiguous import per domain is permitted. Agent update, uninstall,
remote deployment and removal cannot overlap its reservation. Expired unclaimed
offers release that maintenance restriction; claimed or ambiguous operations
retain it. Tenant suspension, account/password or membership changes invalidate
old authority. Re-enabling access requires a new job and a new approval.

## API, schema and later activation

- `GET/POST /api/v1/security/domain-settings/`
- `GET/PUT /api/v1/security/domain-settings/{id}/`
- `GET/POST /api/v1/security/domain-settings/{id}/gpo-imports/`
- Native mTLS: `POST /v1/security-gpo` and `POST /v1/security-gpo-artifact`

Portal requests use the authenticated session, selected tenant header and CSRF
protection. `security.domains.manage` and `security.gpo_imports.run` are granted
to tenant administrators; platform administrators have no tenant access.
Responses are no-store. Error/audit projections do not contain credentials or
raw provider diagnostics. Migration `security.0004_domain_gpo_pilots` adds
domain plans, executor observations and durable jobs.

Do not reverse that migration or discard its rows while work may have changed
AD. An old application version does not know all new FK/fence relationships.
Database rollback is not domain rollback. Retain evidence and prepare a separate
reviewed recovery plan before deployment.

Activation is tracked in [#42](https://github.com/Alvestrasza/ipms/issues/42),
IPMS connectivity/recovery in [#39](https://github.com/Alvestrasza/ipms/issues/39),
tier isolation in [#40](https://github.com/Alvestrasza/ipms/issues/40), and AD
identity management in [#41](https://github.com/Alvestrasza/ipms/issues/41).
These require further implementation and domain-specific acceptance; they are
not implied by a successful pilot import. See
[ADR-0016](../architecture/ADR-0016-TIER-DOMAIN-GPO-PILOTS.md) and the
[0.2.48 verification record](SECURITY-GPO-0248-VERIFICATION.md).
