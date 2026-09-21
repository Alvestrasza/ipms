# ADR-0019: Agent-assisted HGS provisioning on one Appliance

Version: 1.0.0 | Date: 2026-09-20
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Status: Implemented source candidate; Windows fabric acceptance outstanding

## Decision

Portal 0.2.76 and Windows Agent 0.2.49 add a bounded HGS provisioning workflow.
One Linux IPMS Appliance orchestrates separately enrolled Windows HGS nodes.
The dedicated tenant has immutable purpose `hgs`. Its accounts cannot belong
to another tenant, including inactive memberships. Infrastructure accounts and
platform administrators cannot execute or read customer HGS plans. HGS managers
retain Agent enrollment/lifecycle administration but lose fabric and GPO writes.
The shared Appliance and its privileged administrators remain trusted.

Profiles and attestation are separate values. `vtpm` accepts `host_key` or `tpm`;
`shielded` requires `tpm`. One TPM-attested deployment can support both workload
profiles. Concurrent host-key and TPM modes require separate HGS deployments,
which can share the same Appliance. Selecting a profile does not configure a VM,
register a guarded host, replace a key protector or enable guest encryption.

## Fixed provider boundary

The Agent accepts only schema-1 HGS assignments over the enrolled mTLS channel
at `/v1/hgs`. Each assignment binds tenant, deployment, node enrollment, device
URI, reviewed plan digest, expiry, operation and an exact configuration schema.
Operations are `inspect`, `install_role`, `create_forest`, `join_node`,
`initialize`, `verify` and `reboot`. Unknown fields and executable/secret values
are rejected. A local drive feature-source folder is data, never script input.

Microsoft exposes the HGS administration surface through Windows PowerShell.
The native C++ provider embeds one reviewed adapter in the executable, extracts
it into protected storage and verifies its exact bytes before invocation with
trusted Windows PowerShell 5.1 and fixed modules. No supplied script, arbitrary
command, remote module, remote path or generic shell endpoint is supported.
This is a specific exception to the historical native-only implementation
preference, not an exception to the prohibition on generic execution.

Windows Server builds 20348 and 26100 are the initial allowed candidates. Feature
installation resolves a compiled feature list and its bounded OS-declared
dependency closure, then uses DISM with `LimitAccess`, local media and no implicit
reboot. Missing feature mappings fail inspection. All required features must be
installed before promotion; the provider does not rely on legacy update-policy
registry flags. `offline_source_policy_ready` reports availability of that fixed
offline provider path, not a claim about a Windows Update policy setting.
Secrets are prepared locally under protected ACLs and machine DPAPI, bound to
tenant, device and purpose. Only reference names cross the API. Existing local
signing/encryption certificates are identified by exact distinct thumbprints;
their private keys are not transported by IPMS. The adapter grants the observed
HGS KeyProtection service identity read access only to the two exact supported
local key containers. HSM providers fail closed in this increment.

## Approval, sequencing and recovery

An initial inspection must establish fresh workgroup Windows nodes, available
certificates, local media/policy and secret references. The reviewed immutable
plan expires after 24 hours; readiness must be no older than 30 minutes. Initial
selection also requires Agent 0.2.49 or later and a heartbeat within five minutes.
Each of at most eight nodes is processed in order: role installation, reboot,
forest creation or additional-node promotion, reboot, initialization, verification.
The first selected node creates the dedicated forest. Later nodes join it.

The Agent durably distinguishes claim preparation from mutation intent and
records receipts before reporting. A lost response cannot authorize replay.
Uncertain writes establish a persistent fence; read-only checks remain available.
Reboot proof compares boot identities, retaining the first preboot baseline
independently of subsequent receipts. Removing authority, cancelling a plan or
suspending a tenant stops subsequent writes. Restoring an account does not
revive a previous approval. Active plans and unresolved outcomes exclude Agent
replacement/lifecycle jobs through the supported APIs.

Recovery requires a fresh read-only observation, proof of the interrupted step's
postcondition and a separate current-manager confirmation bound to job, plan and
observation digest. It retains the original receipt and advances to the next
step; it never re-executes the interrupted write. A state that cannot be proven
remains fenced and requires local diagnosis. No automatic domain rollback,
certificate replacement or forest deletion is attempted.

## Acceptance boundary

Schema, authorization, persistence, UI and provider tests are source evidence.
Service metadata, exact certificate binding and key-file ACL evidence do not
prove a guarded host obtained a key or a shielded guest booted. Real promotion,
reboots, multi-node availability, cold start, recovery, disconnected servicing
and host-to-HGS key release require a Windows lab. The Linux Appliance must not
be in the normal Hyper-V attestation/key-release path. That topology is supported
by this architecture; its outage acceptance remains a separate lab test.

See [operations](../operations/HGS-DEPLOYMENT.md),
[validation evidence](../operations/HGS-VALIDATION.md) and the original
[proposal](HGS-DEPLOYMENT-PROPOSAL.md).
