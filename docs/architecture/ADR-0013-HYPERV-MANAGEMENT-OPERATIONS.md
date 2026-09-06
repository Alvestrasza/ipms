# ADR-0013: Durable Hyper-V Management Operations

- Status: DEV 0.2.36 deployed; inspection and bounded settings accepted;
  checkpoint/recovery acceptance pending
- Decision date: 2026-09-06
- Baseline application: 0.2.34; Windows Agent: 0.2.26

## Requested outcome

Provide checkpoint creation/deletion/application, VM configuration inspection and
editing, host and storage migration, and assignment/removal of a VM's existing
Failover Cluster high-availability role. Use accessible, localized dialogs with
the familiar Hyper-V settings tree and SCVMM-style staged migration workflow.
Adding or evicting cluster nodes, creating clusters, arbitrary remote scripts,
VM deletion, and implicit disk deletion are outside this request.

## Dependency order

1. Durable management channel, current-setting inspector and checkpoints.
2. Explicitly typed VM settings, with provider/state compatibility checks.
3. Source/target preflight, host/storage migration and inventory reconciliation.
4. Existing-cluster VM availability-role addition/removal and preservation tests.

Each integration slice must pass native, backend and portal checks before DEV
activation. Implementation or API acceptance is not proof that a provider action
completed. Native acceptance uses only an explicitly authorized test VM, never
another inventoried VM or an existing checkpoint selected by guesswork.

## Invariants

- Keep the native C++20 Agent, outbound certificate-authenticated TCP 9419,
  independent heartbeat/telemetry and fixed compiled-in API methods.
- Platform administrators never receive tenant VM control. New configuration,
  checkpoint, migration and cluster-role permissions are separate from existing
  power-operation permission; default grants are tenant-administrator only.
- Resolve VM/checkpoint/resource identities locally from validated immutable
  identifiers. Do not execute portal-supplied WMI paths, MOF/XML, queries, method
  names, PowerShell or arbitrary property dictionaries.
- Serialize conflicting work for a VM across old lifecycle and new management
  operations. An open console prevents disruptive restore/migration operations.
- Gate new operations by explicit Agent capability, fresh inventory and a
  configuration revision. The Hyper-V configuration-format version is not a
  configuration revision. Revalidate before provider execution.
- Never downgrade a production checkpoint silently, overwrite destination files,
  upgrade the VM configuration version, power off a VM as migration fallback,
  or alter AD delegation/host privileges without separate authority.

## Durable operation boundary

Use a separate management worker and mTLS route. A long checkpoint merge or
migration must not execute inside the inventory/telemetry loop. Browser request
IDs are idempotency keys bound to actor, tenant, VM and canonical inputs. Duplicate
IDs with changed inputs fail closed.

Persist an Agent journal before invocation, binding job, enrollment, VM,
operation and input digest. Persist provider job/result references immediately
after return. References remain local, not public API data. Replayed jobs resume
observation, never repeat the mutation. Result ingestion accepts identical
terminal-result retries without repeated audit events.

A crash between provider invocation and recording its returned reference is
ambiguous. Mark it as requiring reconciliation; do not fabricate failure or
automatically retry. Provider return 4096 is acceptance, not completion. Monitor
native state and confirm the final VM/checkpoint/storage observation. Missing
expired provider jobs and monitoring timeouts do not prove rollback. Closing a
popup stops observation only; it never cancels a remote operation.

Authorization withdrawal prevents new grants but cannot recall an already issued
execution grant (maximum 15 seconds) or accepted native work. The Agent rechecks
this monotonic start deadline and local identity after durably writing invocation
intent. Persist progress and bounded outcome codes, preserve audit history and
report partial or uncertain results truthfully. Agent maintenance and management
jobs reserve the same enrollment, including generic redeployment through known
historical endpoint aliases; neither path may bypass the other.

## Inspection and settings

Resolve `Msvm_SettingsDefineState` to the current realized VM configuration, then
read its associated resources. Host-wide settings collections contain checkpoint
settings and must not overwrite current CPU/RAM values.

The inspector reports collection status, observation time, revision, current
host, VM state, explicit operation capabilities, settings, devices, checkpoint
tree and current operation. Unknown and unsupported data are distinct from
empty values. Expose raw paths only as tenant-scoped inventory, never as an
unvalidated execution selector or public operational log.

Initial typed edits cover name/notes, processor allocation and static/dynamic
memory. Existing NIC switch bindings and automatic start/stop policy remain
future individually qualified sections. Require a stopped VM for changes that
have not passed hot-change qualification; do not stop it implicitly. Firmware,
security, device creation/removal and other advanced properties remain read-only
until individually supported. Apply one typed section at a time: a collection
of unrelated provider calls is not an atomic transaction.

## Checkpoints

Present a tree with name, type and creation time. Bind deletion/application to
the exact VM, checkpoint and fresh tree revision, displaying affected dependents
before confirmation. Never remove AVHDX files directly. A checkpoint is not a
backup. Production consistency must be established from the actual provider
contract and guest behavior, not inferred from numeric snapshot-type values.

## Migration and cluster boundaries

Only tenant-owned, explicitly inventoried and eligible target hosts are offered.
Plans bind both Agent identities, VM revision, storage/network mappings and an
expiry. Target storage roots must be explicitly approved and confirmed by the
target Agent; reject overwrite, device-path and reparse-point escapes. Use the
same native compatibility check immediately before execution.

LocalSystem presents the host computer account to remote systems. Agent mTLS and
the existing console account do not automatically authorize host-to-host
migration. Test the exact service identity first; missing host trust/delegation
requires a separately approved configuration or migration identity.

Host migration must preserve the portal's managed VM identity using an explicit
source/target reconciliation record. Do not globally merge matching GUIDs:
imported copies and conflicting observations are possible.

For a VM already managed by a cluster, use cluster-authorized movement rather
than bypassing its resource ownership. Cluster add/remove applies only to the
selected VM's high-availability role on an existing eligible cluster. Validate
all resources and verify VM registration, state and storage preservation after
role removal. Never evict hosts or request cleanup of VM disks.

## Sources

- [Snapshot creation](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/createsnapshot-msvm-virtualsystemsnapshotservice)
- [Snapshot settings and consistency](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/msvm-virtualsystemsnapshotsettingdata)
- [Settings modification](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/modifysystemsettings-msvm-virtualsystemmanagementservice)
- [Resource modification](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/modifyresourcesettings-msvm-virtualsystemmanagementservice)
- [Migration API](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/migratevirtualsystemtohost-msvm-virtualsystemmigrationservice)
- [Migration preflight](https://learn.microsoft.com/en-us/windows/win32/hyperv_v2/checkvirtualsystemismigratable-msvm-virtualsystemmigrationservice)
- [LocalSystem network identity](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [Cluster VM addition](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/cluswmi/mscluster-cluster-addvirtualmachine)
- [Cluster role removal](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/cluswmi/mscluster-resourcegroup-destroygroup)

## Acceptance status

The management channel, inspector, standard checkpoint execution and three
typed settings sections are implemented and covered by native contract/guard,
backend and isolated browser tests. Application 0.2.36 is deployed to the known
DEV appliance and the selected host runs Windows Agent 0.2.27. Two native
read-only inspections passed with the same configuration revision and exactly
one audit event per lifecycle stage. A graceful shutdown request was rejected;
testing paused until the user separately approved a hard stop of the same VM.
The second pass accepted six native settings jobs: notes, processor count and
startup memory were each changed and restored. All reported settings and the
empty checkpoint collection matched the baseline before restart; a fresh running
inspection confirmed the original configuration revision. Software remained
unchanged. This does not qualify VM rename, dynamic-memory mode or minimum/maximum
memory edits, checkpoint writes, guest-service health or recovery fault handling.
Production checkpoint creation, migration and cluster-role execution remain
unimplemented. Migration destination, storage and cluster test target are pending.
See the operations document for evidence and exact release/activation status.
