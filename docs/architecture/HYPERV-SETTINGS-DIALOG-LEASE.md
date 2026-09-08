# Hyper-V settings dialog inspection and edit lease

Application: **0.2.39**. Windows Agent: **0.2.28** for supported live settings;
the Agent protocol and binary are unchanged from application 0.2.38.

## User-visible contract

Opening the management dialog requests a bounded, read-only Agent inspection.
The popup can show loading/progress immediately, but settings are not displayed
until that inspection succeeds. Existing stored settings do not unlock the form.
Simultaneous opens share an already active inspection for the same tenant/VM.
An active write blocks inspection; the dialog reports the conflict and retries
opening without replaying a write. Manual refresh remains available for an
additional inspection or a snapshot older than the existing 60-second limit.

The powered-on guidance appears only in the yellow triangle's tooltip, reachable
with pointer or keyboard. Escape dismisses the tooltip before the dialog.
Supported live fields retain the [field matrix](HYPERV-LIVE-SETTINGS-MATRIX.md):
name/notes, Dynamic Memory minimum decrease and maximum increase. Unsupported
fields and older Agents remain read-only; IPMS never changes VM power state to
make a settings operation possible.

An editor's management dialog obtains an exclusive IPMS settings lease. Another
dialog, including another tab of the same login, stays read-only and displays a
red triangle with `Settings locked by another Dialog (%USERNAME%)`. A reader
without VM configuration permission can inspect without acquiring a lease.
The lease covers settings while the combined management dialog is open; it does
not grant or change checkpoint permissions.

## Server boundary

`POST /api/v1/hyper-v/virtual-machines/{id}/management/dialog/` accepts only:

```json
{"action":"open","dialog_id":"<per-dialog UUID>","edit":true}
```

Actions are `open`, `renew`, and `release`. The response contains `edit_lock`
(`owned`, `owner_username`, `expires_at`) and an `inspection` job for `open`.
Authentication, CSRF, selected-tenant access, and inventory permission apply.
The server independently checks configuration permission before ownership is
granted. The public response never contains a lease token or session digest.
Inspection request IDs are deterministically derived, not the raw dialog UUID.

Migration `discovery.0023_hypervsettingslease` adds one lease row per VM. Ownership
binds the actor, per-dialog UUID, and a server-keyed digest of the login session.
No raw session key is stored in this model. Current tenant/membership/actor state
is rechecked; revoked owners cannot keep their lease. An expired or invalid lease
is removed when accessed. No background worker or browser-local mutex is needed.

The TTL is **90 seconds**, renewed approximately every **20 seconds**. Other
dialogs also poll lease status, but cannot renew, release, or revive another
owner's lease. The frontend disables editing on expiry or failed status/lease
requests. Close/X/Escape release ownership; page exit is best-effort. A crashed
tab or an unrelated component unmount is bounded by TTL. After ownership is lost,
close and reopen to acquire a new lease and collect a new snapshot; ownership is
not silently stolen and pending edits are never submitted automatically.

Settings operation requests must include a top-level `settings_dialog_id`.
The enqueue transaction checks ownership under the same tenant/VM lock order as
management operations. Direct API calls cannot bypass the lock. Other operation
types must omit this field. The lease identity/session binding participates in
settings-request idempotency, but never enters the native Agent parameters.

An accepted durable settings job outlives its dialog. Closing does not cancel it;
existing active-operation conflicts and fresh permission/state/revision checks
continue through Agent claim and execution. Idempotent observation of an already
accepted job does not need a new lease or enqueue another operation.

## Limits and rollout

This is an **IPMS editing lock**, not a Hyper-V Manager/SCVMM/provider lock. An
external administrator can still change the VM. The existing revision, state,
snapshot freshness, and native precondition/postcondition checks remain required.

Roll out migration 0023 and matching control-plane/portal together. Older portal
settings submissions lack the dialog identity and are rejected, not silently
accepted. Do not use the older UI-only cutover script. Keep the API/native worker
code coordinated and preserve the existing service environment and firewall.
The additive lease table can remain for a rollback, but rolling back the backend
also removes lease enforcement; quiesce settings writes and close dialogs first.

A separate, explicitly approved canary upgrade to Windows Agent 0.2.28 is needed
for live-field provider acceptance. No fleet update or VM power operation is part
of this dialog change.
