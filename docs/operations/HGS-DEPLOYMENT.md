# HGS deployment through IPMS

Version: 1.0.0 | Date: 2026-09-20
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Status: Source candidate runbook; no live deployment implied

## Topology and prerequisites

Use one IPMS Appliance with a dedicated HGS tenant and dedicated administrator
accounts. HGS itself runs on existing Windows Server VMs. Start with one lab
node; plan three independently placed HGS nodes for availability. The Appliance
count does not control HGS-node count. Avoid a dependency in which all HGS nodes
need keys from their own unavailable HGS service to start.

Upgrade the receiver/Portal to 0.2.76 with its migrations before using Agent
0.2.49. Follow the existing Appliance backup, immutable package, certificate
trust and rollback procedures. This document does not authorize a deployment.

Prepare Windows Server 2022 (build 20348) or 2025 (26100) workgroup VMs with stable
names, addressing, correct time and DNS. Existing domain members and adoption of
an existing HGS installation are not supported by the initial creation flow.
Verify edition/licensing, resource sizing and the current Microsoft prerequisites.
Ensure the intended HGS forest/service DNS names and required network paths work
without public DNS or Internet access. DNS/network preparation remains an
administrator responsibility, including additional-node access to the primary.

Before adding the first server, open **Administration > Tenants > Agent access**
for the active HGS tenant. Supply a unique Gateway DNS name that resolves to the
same Appliance, create the tenant Agent PKI, download its encrypted Root recovery
bundle, store the bundle and passphrase separately, and confirm the displayed
SHA-256. Wait for material reconciliation, then verify the selected endpoint and
all existing tenant endpoints. Enrollment remains blocked until the recovery,
Gateway and hash-pinned Agent-package checks are ready.

On every node:

1. Deploy and enroll Agent 0.2.49 in the HGS tenant using the existing Agent
   installer/enrollment flow. Confirm current inventory and heartbeat.
2. Stage matching Windows feature payloads in a local folder, for example
   `D:\sources\sxs`. UNC/HTTP sources, traversal, alternate data streams and
   shell metacharacters are rejected. The provider resolves the fixed required
   role/dependency set and installs it with DISM `LimitAccess`; missing mappings
   fail inspection and missing payloads fail installation rather than downloading.
   Promotion requires the complete feature set already installed. The readiness
   field `offline_source_policy_ready` describes this provider capability, not
   an obsolete Windows Update registry-policy check.
3. Import the chosen HGS signing and encryption certificates with private keys
   into Local Machine Personal. Use two distinct valid thumbprints and the same
   chosen HGS certificate identities on participating nodes. Prepare PKI chains,
   offline revocation access and protected recovery copies. IPMS does not generate,
   distribute, export or renew these keys. Supported local software RSA key
   containers are required; HSM custody needs a separate provider increment.
4. Run `prepare-hgs-secret.ps1` from the extracted Agent package (or reviewed
   `agent/scripts` source) locally as administrator in Windows
   PowerShell 5.1. Supply the actual HGS tenant UUID and a reference name, never a
   plaintext password argument. For example:

   ```powershell
   .\prepare-hgs-secret.ps1 -Reference hgs-dsrm -Purpose dsrm -TenantId <HGS-tenant-UUID>
   .\prepare-hgs-secret.ps1 -Reference hgs-join -Purpose join -TenantId <HGS-tenant-UUID>
   ```

   This helper remains a separate local operator tool. Agent 0.2.49 packages,
   updates and migrations place it in the installed service directory, but the
   service never invokes it automatically.
   The first command prompts securely for the DSRM password. The second prompts
   for the dedicated HGS forest join credential and is needed on additional nodes.
   References are local, device/tenant/purpose bound and cannot overwrite an
   existing reference. Each node needs its local copy under the same plan reference
   name. The primary must be available before additional-node join credentials can
   be exercised. Recovery secrets and backups remain under administrator custody.

Agent protocol state and DPAPI secrets use the existing protected ProgramData
Agent directory; do not relocate them by editing assignments. Offline media and
administrator evidence can remain on a separate data drive.

## Portal workflow

Create a tenant with purpose **Host Guardian Service** and a dedicated account.
Purpose cannot be changed later. Open **Security → Host Guardian Service** in
that tenant. Select **vTPM** for simple operation or **Shielded VMs** for the
secure profile. Set host-key or TPM attestation separately; shielded requires TPM.

Choose the nodes in execution order, the new forest DNS name, short HGS service
name, local feature-source folder, certificate thumbprints and local secret
reference names. For multiple nodes, supply the primary node's stable IP address.
Authorize planned reboots only when the node maintenance window permits them.
Save the plan, request inspection and resolve every reported prerequisite.

Review exact nodes, profile, attestation, stages and plan digest before confirming
execution. The Agent rechecks local prerequisites at the operation boundary.
The Portal shows receipts, current stage, blocked conditions and reboot waits.
Do not replace/re-enroll the Agent or clear its state during provisioning.

Verification checks the configured HGS domain/service/attestation/certificates,
local service health and service-key access. It does not register guarded hosts
or prove VM shielding. Configure guarded-host attestation evidence, direct HGS
URLs, VM key protectors and guest encryption through separately reviewed fabric
operations. Profile selection alone never converts a workload VM.

## Interrupted work

Cancellation stops future steps; it cannot undo an operation already claimed.
An uncertain result stays fenced. Use **Reconcile** to request a read-only
inspection. If the exact interrupted postcondition is proven, review and confirm
the separate recovery action. The confirmation is bound to the latest observation
digest. It releases that one fence and permits the next stage without replaying
the old write. A lost HTTP response should be followed by refresh/reconciliation,
not blind submission of another execution request.

Missing preboot proof, conflicting domain/service/certificates or unsupported key
storage cannot be accepted as success. Diagnose locally, preserve the journal and
audit history, then request fresh evidence. Recreating the plan or deleting Agent
state is not a recovery procedure. AD/forest rollback is manual and requires a
separate reviewed recovery plan; IPMS never automatically removes a domain.

## Disconnected acceptance

Test role installation, both attestation choices, reboot/service restart, lost
claim/result replies, authority withdrawal and an interrupted promotion. Then
test multi-node failover, backups/restore, full cold start, PKI/revocation access,
offline updates and a real guarded-host key release/VM boot with the Appliance
offline. Normal host-to-HGS traffic must use HGS directly. HGS offline key caching
is a separate Windows feature, not the definition of an air-gapped deployment.

Microsoft references: [HGS installation](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-hgs-default),
[additional nodes](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-configure-additional-hgs-nodes),
[fabric planning](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-planning-for-hosters).
