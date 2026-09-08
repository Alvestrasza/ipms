# Hyper-V settings by VM power state

Reviewed: 2026-09-08. Application: **0.2.38**. Windows Agent: **0.2.28**.
Scope: the ordinary Windows Hyper-V management interface; no assumption of
SCVMM orchestration, Azure-specific capabilities or a particular guest OS.

## Findings and implemented field policy

Hyper-V does not have one universal "running VM settings" switch. The answer
depends on the property, current configuration, change direction, host and guest
support. A paused or saved VM is not equivalent to a powered-off VM.

The following table is the **IPMS execution policy**, not a claim that every
Hyper-V property is implemented. "Allowed" still requires fresh configuration,
matching VM identity, tenant permission and positive native method capability.
Source/build tests are separate from live-provider acceptance (see below).

| Existing editor field | Running VM in IPMS 0.2.38 / Agent 0.2.28 | Stopped VM | Rationale / boundary |
| --- | --- | --- | --- |
| Name | Allowed | Allowed | Management-object identity metadata; does not rename the guest OS or its disk files. The resulting VM name is checked against the requested name. [Rename-VM](https://learn.microsoft.com/en-us/powershell/module/hyper-v/rename-vm?view=windowsserver2025-ps) |
| Notes | Allowed | Allowed | Bounded metadata update through the fixed native system-settings method. No guest operation. |
| vCPU count | Blocked | Allowed | IPMS does not implement or attest vCPU hot-plug. This must not be confused with CPU scheduling limits or weight. |
| Dynamic Memory startup RAM | Blocked | Allowed | Not a live min/max adjustment; the startup value is preserved during running changes. |
| Dynamic Memory minimum | Decrease only | Either direction within the complete memory tuple | Microsoft explicitly documents lowering the minimum while running. |
| Dynamic Memory maximum | Increase only | Either direction within the complete memory tuple | Microsoft explicitly documents raising the maximum while running. |
| Static RAM allocation | Blocked, with an explicit host/guest-support explanation | Allowed | Hyper-V supports conditional hot add/remove, but this inspector does not yet attest the necessary guest/host prerequisites. |
| Dynamic Memory mode | Blocked | Allowed | VMM documents a live static-to-dynamic workflow. That does not qualify arbitrary native mode toggles, especially the reverse direction. |

Dynamic Memory directions follow Microsoft's [Dynamic Memory documentation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/dynamic-memory).
For static hot-memory, **Generation 2 alone is not sufficient evidence**:
Microsoft lists hot add/removal for both generations with supported Windows
guests. See [feature compatibility](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-feature-compatibility-by-generation-and-guest)
and [Windows Server 2016 memory improvements](https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2016).
The broader orchestration behavior is documented under [VMM running-VM memory](https://learn.microsoft.com/en-us/system-center/vmm/vm-settings?view=sc-vmm-2025#manage-static-memory-on-a-running-vm).

The name/notes native live policy is an engineering inference from metadata
semantics and the system-settings interface, not a statement that the generic
method signature proves hot-change support on every host. Provider rejection
must remain a failed/uncertain operation, never an implicit shutdown.

## Other settings and workflows

These rows explain the broader platform behavior and remaining implementation
work. They do **not** open a write surface in this release.

| Area | Hyper-V behavior / prerequisite | IPMS boundary |
| --- | --- | --- |
| CPU reservation, cap and relative weight | Resource scheduling controls, not CPU hot-plug. Effect depends on the hypervisor scheduler; the root scheduler does not honor the ordinary per-VM resource controls. [Scheduler documentation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types) | Existing values remain read-only; live setters and scheduler attestation are not qualified. |
| Memory buffer and priority | Memory-management policy, distinct from changing startup RAM or enabling Dynamic Memory. | Collected read-only. Native property types, supported transitions and behavior need separate qualification. |
| CPU migration compatibility | VM must be powered off to enable or disable it. [Microsoft procedure](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/configure-processor-compatibility-mode) | Read-only; do not equate live migration with live compatibility-mode changes. |
| Virtual NUMA topology | Microsoft requires shutting down the VM before changing the topology. [NUMA procedure](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/configure-non-uniform-memory-access?tabs=hyper-v-manager) | No setter. Host-wide NUMA settings are a separate, wider-impact operation. |
| NIC hot add/remove | Supported for Generation 2 with supported guests. Existing switch/VLAN changes require exact adapter and network authorization; connectivity may be interrupted. [Feature compatibility](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/hyper-v-feature-compatibility-by-generation-and-guest#networking), [VMM adapter settings](https://learn.microsoft.com/en-us/system-center/vmm/vm-settings?view=sc-vmm-2025#add-a-virtual-adapter-to-a-vm) | Device editing is not implemented; no guessed adapter IDs or switch selectors. |
| VHDX online resizing | SCSI-attached VHDX can be expanded or shrunk online; IDE attachments cannot. Shrink is bounded by the image's minimum size and requires separate guest-volume preparation. [Resize-VHD](https://learn.microsoft.com/en-us/powershell/module/hyper-v/resize-vhd?view=windowsserver2025-ps), [online resizing prerequisites](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn282286%28v%3Dws.11%29) | No storage setter; never infer disk capacity changes from guest partition size or delete disk-chain files. |
| Automatic start/stop actions, checkpoint policy | These are policies for subsequent events, not instructions to power-cycle the current VM. Exact native live transitions have not been qualified here. | Collected read-only; do not label them universally impossible in Hyper-V. |
| Firmware, Secure Boot, vTPM, nested virtualization and advanced device changes | Property-, generation-, security- and host-dependent prerequisites need their own review; no blanket live allowance. | Not implemented. Security changes must not be bundled with ordinary memory/metadata edits. |
| Configuration-version upgrade | Offline upgrade; cannot downgrade afterward. [Microsoft upgrade procedure](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/deploy/upgrade-virtual-machine-version-in-hyper-v-on-windows-or-windows-server) | Read-only; never perform an implicit compatibility upgrade. |
| Live host/storage migration | Supported platform workflow with identity, storage, network and compatibility prerequisites, not a settings-field edit. [Live migration](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/use-live-migration-without-failover-clustering-to-move-a-virtual-machine) | Separate pending workflow under Issue #24. |
| Checkpoints and cluster membership | Independent operations with their own data-loss, consistency and ownership rules. | Existing checkpoint gates remain unchanged; migration/cluster execution is not enabled by this change. |

## Versioned protocol and independent enforcement

Snapshot schema **2** retains the bounded schema-1 shape but attests the new
state-aware patch contract. Agent 0.2.28 emits schema 2. The control plane accepts
both versions. A schema-1 Agent keeps its original complete-section, stopped-only
behavior. An old Agent cannot receive live edits merely because the UI changed.

New requests contain exactly `section`, `values` and `expected_state`. `values`
contains only changed, allowlisted fields in one section; it must not be empty.
Unchanged fields, unknown fields, provider paths and untyped extra properties
are rejected. For example:

```json
{
  "section": "memory",
  "expected_state": "running",
  "values": { "maximum_mib": 16384 }
}
```

The example is a shape, not authorization to assign that size to any VM.
The existing outer command also binds the VM GUID/name, revision, tenant,
enrollment, actor and durable job identifier.

- Portal: field-specific disabled states and directional bounds; only changed
  values are submitted. Stale, unauthorized, unsupported and busy views cannot
  apply changes. The powered-on warning remains in the host row. DE/EN hints
  explain offline-only and unqualified static hot-memory cases.
- Control plane: independently validates types, state, current values and
  direction during queueing, delivery and claim. Schema-2 patches require a host
  Agent version of at least 0.2.28. Unknown values are never defaulted.
- Native Agent: independently recomputes the same rules from the local provider
  observation. It reinspects after constructing the provider input and before
  durable invocation intent/lease validation. Exact local objects are cloned;
  only requested fixed properties are assigned. The API accepts no caller-
  supplied WMI classes, property names, paths, XML, commands or scripts.
- Success: requires exact requested values, VM identity and the original power
  state in the post-operation observation. Notes-only updates preserve the name;
  rename updates bind the new expected name. Ambiguous outcomes require existing
  reconciliation and are not replayed automatically.

Memory patches merge with the fresh observed configuration before validation:
`minimum <= startup <= maximum`, positive bounded integers and a known boolean
mode are required. Protocol limits are defensive serialization limits, **not**
a promise that every host supports that amount of memory or CPU. Hyper-V still
enforces its own host/configuration/guest resource limits.

There is no native compare-and-swap transaction with unrelated Hyper-V tools.
The second inspection narrows but does not eliminate an external-writer race.
No all-property atomicity, automatic rollback or unconditional host support is
claimed. A live minimum decrease or maximum increase **cannot simply be undone
live** under the directional rule; restoration needs a separately approved
stopped-VM window. Do not use such a change as a supposedly reversible smoke test.

## Qualification and rollout order

1. Validate the source and build both components. Run backend permission/state
   tests, native guards and browser negative cases independently.
2. Stage/deploy the schema-1/2-capable control plane and portal **before** upgrading
   any Windows Agent. No database migration is introduced by this contract.
3. Select an authorized canary host; verify its identity and Agent lifecycle
   state. Do not bulk-upgrade every Agent as part of a portal deployment.
4. After the canary Agent update, request a fresh inspection. Confirm schema 2,
   unchanged inventory and positive native method capabilities.
5. Qualify a bounded notes edit/restore on an explicitly authorized running test
   VM. Compare unrelated settings and the power state before/after. Qualify
   rename separately because it changes management identity visible to others.
6. Only test directional memory edits with an approved target, exact values and
   a restoration plan that acknowledges the required downtime. Never stop,
   start, enable Dynamic Memory or increase resource allocation implicitly.

For rollback, stop new management submissions and resolve in-flight/reconciliation
jobs first. Do not roll the server back to schema-1-only code while schema-2
Agents remain active; coordinate the canary rollback without deleting jobs,
journals or enrollment identities.

See the [0.2.38 verification record](../operations/HYPERV-SETTINGS-0238-ACCEPTANCE.md)
for the actual source, test and deployment boundary. This matrix does not itself
claim that any live VM or installed Agent was changed.
