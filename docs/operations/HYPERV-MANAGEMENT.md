# Hyper-V management: prepared DEV rollout and acceptance

Status: prepared, not deployed or accepted by this document. Target application
version: **0.2.36**. Required Windows Agent package: **0.2.27**. The exact Git
commit and package SHA-256 must be recorded from the completed release build;
neither is inferred from a version string. See [VERSIONING.md](VERSIONING.md).

## Delivered source boundaries

The portal adds VM Settings, Checkpoints, Move virtual machine and Failover
cluster entries to the visible action menu, right-click menu and Shift+F10
navigation. Management uses a centered native browser dialog with English and
German text. Opening it reads the persisted snapshot and job state only.
**Refresh from host** explicitly requests a read-only Agent inspection.

The fixed native management contract supports inspection, standard checkpoint
creation under a supported configured policy, checkpoint subtree deletion,
checkpoint application, and bounded settings changes. Permission and native
capability checks remain authoritative on the server and Agent, not only in
the browser. No arbitrary command, script, WMI query, provider object path or
provider serialization is supplied by a portal request.

Settings changes are separate operations for exactly one section:

| Section | Admitted fields | Requirements |
| --- | --- | --- |
| General | Name and notes | Both values known; bounded valid text |
| Processor | Virtual processor count | Known positive integer |
| Memory | Startup, minimum, maximum MiB; dynamic-memory flag | All values known; minimum <= startup <= maximum |

The VM must be stopped. IPMS never stops it implicitly. Each section is applied
separately to avoid pretending a multi-object settings update is atomic.
Unreported values cannot be replaced with defaults. Other settings, including
device configuration, remain read-only or explicitly not collected.

Checkpoint creation never changes the configured checkpoint policy. Production
checkpoint creation is **not qualified in this slice**; IPMS must not silently
fall back to a standard checkpoint. Deletion requires acknowledgement of the
selected checkpoint and every descendant, including their exact IDs.
Application requires the exact current VM and checkpoint names and an explicit
data-loss warning. A checkpoint is not a backup or a rollback guarantee.

Host migration, storage migration and cluster-role add/remove are **not
executable** in this release. Their menu entries explain pending preflight.
No destination host, storage path or cluster action has been selected. These
features require separate native API qualification, credential/host prerequisites,
capacity and compatibility checks, exact resource identity, reconciliation and
explicit target selection before implementation can be accepted.

## Authority, durability and uncertain outcomes

- Snapshot and job records are tenant scoped. New mutation permissions are
  `virtual_machines.checkpoints.manage` and `virtual_machines.configure`.
  Inventory readers can inspect; these permissions are not implied by ordinary
  VM power-operation access or platform administration.
- A fresh snapshot/revision, matching enrollment and VM identity, current actor
  authorization, Agent contact and conflict checks are required. Authority is
  rechecked for execution, not merely at queue creation.
- A previously issued execution grant can remain valid for up to 15 seconds
  after authority withdrawal. The Agent checks the local monotonic start limit
  before and after persisting invocation intent; accepted provider work cannot
  be recalled. No instantaneous revocation or automatic rollback is promised.
- Agent lifecycle updates and generic Windows redeployment reserve the same
  enrollment as active management work. Checks precede credential access and
  are repeated before the remote update. Existing identity/endpoint aliases
  are resolved within the tenant without cross-tenant or guessed DNS matches.
- Browser polling observes an active durable job every three seconds without
  replaying its mutation. Closing the dialog does not cancel the job. Reopening
  retrieves active and latest operation status from the API.
- An ambiguous POST response triggers status-only recovery and requires a new
  successful explicit inspection before the browser permits another change.
- The native journal binds schema, job UUID, canonical input digest, enrollment,
  operation and VM UUID. It persists invocation intent before entering the
  provider. Recovery from an uncertain invocation requires reconciliation;
  observing resumes monitoring and terminal records report only.
- This is **not an exactly-once guarantee**. Missing/unconfirmed provider jobs,
  ambiguous acceptance or unverified postconditions must not be relabelled as
  success or retried automatically. `requires_reconciliation` intentionally
  remains an active blocker. Do not delete journals or database rows to clear it.
- JSON is bounded to 64 KiB, depth 8 and 4,096 nodes; snapshots use a 48 KiB
  ceiling. Duplicate keys, invalid UTF-8, malformed surrogate escapes, floats
  and unexpected typed fields are rejected. Journals contain only locally
  obtained relative provider-job references.

## Prepared deployment procedure

`scripts/deploy-hyperv-management-dev.sh` is an exact-target DEV cutover from
application **0.2.34** to **0.2.36**, not a general installer or automatic updater.
Do not run it against another environment or use it as production acceptance.

Before execution, independently verify the appliance hostname, current resolved
release and Git commit, service identities, absence of pending recovery state,
and the authorization for this specific maintenance window. Build/package and
publish the reviewed immutable source and Agent package separately. Stage the
ZIP under a dedicated `/tmp/ipms-hyperv-management-<identifier>/` directory with
the exact filename `ipms-agent-windows-x64-0.2.27.zip`.

The script takes six explicit arguments. Append `--preflight` to check current
runtime/ownership/quiescence prerequisites and the staged ZIP digest without
building a release, creating backups/fences or changing services. This preflight
does not replace immutable-source/build/ZIP-content checks during deployment.

```text
sudo bash scripts/deploy-hyperv-management-dev.sh \
  <verified-dev-hostname> <verified-public-hostname> \
  <new-40-character-commit> <previous-40-character-commit> \
  /tmp/ipms-hyperv-management-<identifier>/ipms-agent-windows-x64-0.2.27.zip \
  <verified-64-character-package-sha256>
```

The hash is a required operator-supplied release identity, not a placeholder the
script can generate for an untrusted upload. No uploaded file is executed. The
ZIP is copied into a protected location, then verified against its hash and
exact six-file allowlist. Script contents must match the selected release
(permitting CRLF/LF normalization only); Agent binaries must have PE signatures,
and the service binary must contain the expected version/capability markers.
These checks do not replace a trustworthy build/provenance record.

The script:

1. Acquires the existing protected process-lifetime cutover lock. It refuses
   mismatched immutable commits/versions, unsafe paths, existing release staging,
   a prior fence, active console/discovery/power/deployment/lifecycle work, or a
   previously initialized tenant without an active independent administrator.
2. Builds the new Python environment and standalone Web Console before stopping
   the running services. A staging failure leaves the old runtime untouched;
   staged source/artifacts are retained for explicit investigation.
3. Verifies the existing DEV database topology: Control Plane and Agent Gateway
   both use the existing `ipms` database role, while the console broker retains
   its isolated role. A different topology requires a reviewed deployment
   adaptation; the script never creates users or guesses new grants.
4. Creates a root-only backup directory under the separate root-controlled
   `/srv/ipms/shared/hyperv-management-backups` parent with a known-file configuration archive
   and a validated PostgreSQL custom-format dump. Environment files, the native
   credential key and nginx configuration are protected and never printed.
5. Checks existing systemd start-fence drop-ins, creates the persistent fence,
   stops the request/worker services and timers, and rechecks quiescence before
   migration. It applies `discovery.0022_hyperv_management` and verifies there are
   no other pending migrations, runs static collection and deployment checks.
6. Verifies ownership plus each required read/write privilege on the new job and
   snapshot tables for the existing CP/Gateway role. Broker ACL fingerprints
   must remain unchanged; the broker must not gain access to the new tables.
7. Updates only the three Agent package path/hash/version settings in the
   existing Control Plane/Gateway environment files, preserving ownership and
   modes. Native broker credentials, service accounts, keys, nginx and firewall
   policy remain unchanged. It selects the immutable forward release and checks
   application version, readiness, anonymous denial, existing console service
   health and listeners.

The Agent artifact is only made available for a later explicitly selected
rollout. This script creates no Agent lifecycle job, executes no VM operation,
changes no Windows account and opens no port. TCP 9419 must retain its existing
all-network listener; native relay listeners remain loopback-only.

## Failure and forward recovery

After fencing begins, a checked migration/cutover failure or handled interrupt
restores/retains the persistent start fence and stops the application services.
The script does **not** delete the backup, staged release, new Agent artifact,
journals or management records. It does not automatically restore the database
or point to older code. In particular, never discard a job whose provider outcome
is uncertain. Re-running the script against retained state is intentionally
refused.

Recovery is an explicit operator procedure: verify the applied migration and
table privileges; determine which immutable release is selected; inspect service
and job state; compare the protected environment backup; and choose a corrected
forward release or a separately approved offline database recovery. Remove a
fence only after that state is understood and compatible code is verified.
Review an unexpected reboot or unhandled process termination separately; an
ordinary shell error trap is not a distributed transaction or power-loss proof.

## Evidence and outstanding acceptance

The 0.2.35 source and Windows Agent artifact were published, but its initial DEV
rollout stopped at a read-only ownership precondition before creating a release,
backup or fence and before stopping services. The existing general backup parent
was owned by PostgreSQL rather than root. Version 0.2.36 uses a separate root-only
management-backup parent; existing backups and permissions remain untouched.
Collected static directories retain the previous 022 umask and are checked using
the existing Control Plane identity. No nginx group/traversal privilege is added;
the pre-existing private application-root boundary is preserved.
The corrected `--preflight` passed on the unchanged DEV baseline. Five inert
Bash recovery tests passed for direct failure, nested query failure, handled
termination, active-work rejection and quiescent continuation; these exercise
the extracted actual guard/recovery functions without touching services.

The final integrated MSVC Release build completed. **11 native CTest programs
passed; one protected Windows journal I/O test was skipped** because the test
process had no enabled administrator/LocalSystem token. The pure JSON/journal
executable passed **617 checks**; the earlier 615-check revision also ran under
AddressSanitizer. Provider/settings boundary tests used warnings-as-errors.
The full Linux Agent/core build and all **8 Linux CTests** also passed using
existing dependencies in an isolated temporary build; no Linux Agent was run
against the environment or deployed.

The full backend suite passed **381 tests** under **Python 3.14.4 and PostgreSQL**
with no skips, including row-lock concurrency and maintenance exclusion. Schema
drift and Django system checks were clean; the disposable database was removed.
The frontend helpers passed **9 Node tests**, Biome checked 133 files without
changes, and the production Next.js build/type check succeeded.

Ten isolated browser scenarios passed: six functional cases for centered/read-only access,
subtree acknowledgement and durable reopening, exact-name apply confirmation,
one-section settings, ambiguous-POST recovery and German keyboard navigation.
They used real fixture authentication/SSR and intercepted management transport;
none reached a real Agent. The login page also passed an initial browser visual
check without page errors. Four additional dark/light desktop/390px cases
verified settings, checkpoints and destructive confirmation, with sixteen
screenshots and scoped Axe WCAG A/AA scans. Dialog focus stayed contained and
document/dialog/content horizontal overflow was zero after correcting the
positioned table-scroll container. These layers do not prove live Hyper-V execution.

The Windows Agent 0.2.27 ZIP was built locally with exactly the three executables
and three fixed installation/enrollment scripts. Package SHA-256:
`e7deeb3794b34abf243e6f9a323e674f55781866ee0a62db3011c25eafc01814`.
The package digest identifies this build; publication and DEV activation must
be recorded independently. Full transport crash/response-loss/slow-flush fault
injection and protected journal I/O remain explicit acceptance gaps.

Before functional acceptance, record the final combined native/backend/browser
results, immutable package hash/version and DEV cutover evidence. Upgrade only
the explicitly selected test host Agent, verify unique test-VM GUID and host,
and perform one operation at a time. Check the actual Hyper-V result, persisted
job, expected postcondition, Agent journal behavior and unchanged tenant/console
boundaries. Settings tests must preserve/reinstate the agreed test configuration;
checkpoint apply/delete are destructive to VM state and require explicitly
agreed disposable checkpoint data. Agent restart, duplicate delivery, expired
authority, provider failure and reconciliation cases need their own evidence.

Successful deployment, browser rendering and a completed unit-test suite do not
establish migration, storage relocation, production checkpoint or cluster-role
acceptance. Those capabilities remain explicitly pending.
