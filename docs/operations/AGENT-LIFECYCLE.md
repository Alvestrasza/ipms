# Agent Lifecycle Administration

IPMS 0.1.52 provides the tenant-administrator Agent inventory at
**Administration > Infrastructure > Agents**. It displays FQDN, derived contact
state, operating system, installed Agent version, target version, compliance,
last contact, and any active lifecycle job.

## Contact state

- `Online`: last report was received within 45 seconds.
- `Stale`: last report is between 45 seconds and five minutes old.
- `Offline`: the last report is older than five minutes.
- `Not seen`: enrollment exists but inventory has never arrived.
- `Revoked`: the device enrollment was revoked.

These values are derived by the Control Plane when the list is requested. They
do not trust a browser-calculated state.

## Administrative removal

A tenant administrator may remove an Agent record only when its derived state
is `Offline`, `Not seen`, or `Revoked`. `Online` and `Stale` records fail
closed, which prevents a short network interruption from being mistaken for a
decommissioned system.

Removal is a security operation rather than an unaudited database deletion. An
active offline identity is revoked first, unused enrollment tokens are
destroyed, and any active fixed lifecycle jobs are cancelled. The enrollment
is then hidden from Agent administration. Historical Windows inventory,
terminal lifecycle and deployment records, certificate-revocation evidence,
and append-only audit events remain available for reconciliation. An active
Windows bootstrap deployment blocks removal until it reaches a terminal state.

## Bootstrap boundary

Agent 0.1.32 is the first version that can consume fixed lifecycle assignments.
For an older Agent, the row update or uninstall action opens a one-time secure
bootstrap dialog instead of remaining disabled. The administrator confirms the
Windows management endpoint and its certificate or explicit HTTP fallback,
then supplies transient administrative credentials. The worker must match the
remote device URI and installed certificate fingerprint to the selected active
enrollment before it copies or changes any Agent file. A nonstandard
development installation must additionally match its reported Agent version,
`LocalSystem` service identity, executable name, and registered installation
directory. The existing device identity and mTLS certificate are retained.

Bulk actions stop at the first older Agent because each endpoint certificate or
HTTP fallback requires an individual administrator decision. Once all selected
Agents report 0.1.32 or newer, the same bulk controls queue fixed lifecycle jobs
without Windows administrative credentials.

An older Agent is marked **One-time lifecycle bootstrap required**. Routine
later updates use the Agent-initiated mTLS channel and do not require Windows
administrator credentials.

## Update

Use the row update button, select multiple eligible rows and choose **Update
selected**, or choose **Update all outdated**. The API rejects already-current,
legacy, revoked, cross-tenant, unauthorized, duplicate, or malformed requests.

The Agent downloads only the binary assigned to its active job. Both the Agent
and the updater verify its SHA-256 digest. The updater retains a rollback copy
until the new service starts. ProgramData identity and configuration remain
unchanged.

Agent 0.1.34 closes the update race observed when the Service Control Manager
reported `Stopped` immediately before the service process released the Agent
image. The updater now waits for the process handle, retries only bounded
sharing and lock failures, accepts only a matching existing rollback binary,
restores the prior version and service on failure, and writes a terminal
failure result whenever the authenticated job is available. After the
transition from 0.1.33, each Agent stages the hardened runner from its own
current executable; subsequent updates no longer depend on an older installed
updater helper.

The Agent Gateway receives the same pinned package path, package digest, and
target version as the Control Plane. A deployment-time contract test protects
this shared configuration boundary. This prevents an accepted assignment from
remaining in `delivered` because the Gateway cannot resolve the approved
artifact. Existing `delivered` jobs are offered again and continue without
being recreated after the corrected Gateway restarts.

## Uninstall

The red uninstall button requires an explicit browser confirmation. The action
removes the IPMS Agent service and known installed program artifacts. Historical
inventory remains in the Control Plane. Certificate revocation and device
decommissioning are deliberately separate future actions so the Agent can
acknowledge the uninstall before losing its authenticated channel.

## Verification

For development acceptance:

1. confirm the job changes from queued to delivered or running;
2. confirm the Agent reports the target version after restart;
3. confirm the same device URI remains present after an update;
4. confirm failed replacement restores the previous executable and service;
5. confirm an uninstall removes the service while historical inventory remains;
6. review the tenant-scoped audit event and ensure no secret material appears.

Customer release remains blocked on signed manifests, Authenticode, MSI
packaging, anti-rollback enforcement, staged rollout rings, and clean-VM
acceptance as defined in ADR-0006.
