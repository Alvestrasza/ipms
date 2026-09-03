# Agent Lifecycle Administration

IPMS 0.1.41 introduces the tenant-administrator Agent inventory at
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

## Bootstrap boundary

Agent 0.1.32 is the first version that can consume fixed lifecycle assignments.
An older Agent is marked **One-time lifecycle bootstrap required**. Update that
system once through the existing **Add System > Windows system** workflow. The
existing managed identity, private key, certificate, configuration, and device
URI are retained. Routine later updates use the Agent-initiated mTLS channel and
do not require Windows administrator credentials.

## Update

Use the row update button, select multiple eligible rows and choose **Update
selected**, or choose **Update all outdated**. The API rejects already-current,
legacy, revoked, cross-tenant, unauthorized, duplicate, or malformed requests.

The Agent downloads only the binary assigned to its active job. Both the Agent
and the updater verify its SHA-256 digest. The updater retains a rollback copy
until the new service starts. ProgramData identity and configuration remain
unchanged.

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
