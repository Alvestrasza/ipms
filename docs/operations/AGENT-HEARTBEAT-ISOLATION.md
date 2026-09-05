# Agent Heartbeat and Collection Isolation

- Application candidate: 0.2.30
- Windows Agent: 0.2.25
- Linux Agent: 0.2.13
- Date: 2026-09-05
- Live acceptance: pending the operator's console maintenance window

## Failure and required behavior

Previously an active Windows console suppressed inventory and telemetry in the
service loop. Administration derived presence from those unchanged timestamps,
so a communicating Agent appeared offline after five minutes and could expose
the removal action. A console frame timestamp alone did not update presence.

Presence must mean recent authenticated contact, not recent inventory. A fresh
heartbeat is not proof that every provider, metric or inventory capability is
healthy. Stored measurements retain their true observation times.

## Implementation

| Work | Scheduling and boundary |
| --- | --- |
| Heartbeat | Independent ten-second native worker; no inventory, software scan or command execution |
| Windows inventory and telemetry | Existing main worker; inventory normally five minutes and telemetry ten seconds, with collection time affecting actual delivery |
| Console frames | Separate activation-controlled worker; 150-ms target including work, minimum yield on busy hosts |
| Console input | Separate ordered worker and connection; immediate acknowledgement, existing receipt retry protections |
| Linux inventory | Existing five-minute collection loop; cannot block the heartbeat worker |

Agents use the fixed `POST /v1/heartbeat` route on the existing outbound mTLS
Gateway. Its envelope contains only `type`, certificate-bound `device_uri` and
optional bounded `correlation_id`. It accepts no client timestamp, inventory,
script, command or assignment. It returns only acknowledgement and closes the
request connection. The heartbeat never enrolls or changes credentials.

Windows uses request-owned transport and short two-second per-phase timeouts;
these are not a two-second end-to-end deadline. Linux uses request-owned curl
handles, two-second connection/three-second total bounds and cancellation.
Linux initializes global curl state once before workers start. Its DNS timeout
requires an asynchronous/threaded resolver; the checked DEV build has AsynchDNS.
Worker shutdown joins outstanding work. Existing synchronous WMI metadata
boundaries still depend on provider health; this is not a hard-stop guarantee
for an arbitrarily wedged provider.

The Gateway validates the client certificate and device binding on every
heartbeat. One additional single-thread database executor separates its small
authentication/write path from inventory and console database work. The update
uses transaction-local PostgreSQL lock (one second) and statement (two seconds)
timeouts; a busy row fails the heartbeat instead of indefinitely blocking the
lane. These settings are restored at transaction end. They are not a global
end-to-end deadline or admission-control guarantee. The update
rechecks active status, tenant/issuer binding, certificate fingerprint, validity
and revocation so a stale authenticated object cannot revive an invalid Agent.
Database/process/CPU resources remain shared; this is not complete scale-out or
denial-of-service isolation.

Migration `agent_pki.0008_agent_enrollment_heartbeat` adds nullable
`AgentEnrollment.last_heartbeat_at`, without backfilling invented contact.
Existing inventory/contact fields and telemetry `observed_at` are unchanged.
Administration exposes effective `last_seen_at` plus independent
`last_heartbeat_at`, `last_inventory_at` and `last_telemetry_at` fields.

Presence uses the latest valid contact, with existing online (45 seconds), stale
(five minutes), then offline thresholds. A valid active legacy console with
fresh Agent contact also counts. A live browser lease blocks removal even when
frames stop, but a lease alone does not claim the Agent is online. Tenant,
status, closure and lease bounds are checked without loading frame blobs.
Console creation and removal serialize through the enrollment row before
host/session locks; creation expiry is scoped to the selected tenant and VM.

## Port and security decision

No listener, port or firewall policy is changed. TCP 9419 remains the normal
Agent entry point, including its existing all-network appliance allowance;
customer perimeter policy remains a separate deployment responsibility.

A TCP connection is identified by its socket pair, so separate connections to
the same destination port already have independent TCP streams. Changing only
the port does not remove shared worker, CPU, database or WMI contention. This
performance conclusion follows from the transport model and the measured/code
bottlenecks, not from a benchmark of a second port. See
[RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293#section-3.4.1).

A dedicated optional console listener can enable separate firewall and QoS
rules. A useful next design would also isolate its process, resource budget,
queue and scale-out routing while preserving mTLS, tenant authorization and
short single-owner leases. A port number is not an authentication boundary;
TCP itself provides no cryptographic authentication. See
[RFC 9293 security considerations](https://datatracker.ietf.org/doc/html/rfc9293#section-7),
[nftables port matching](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers)
and [Microsoft QoS policy](https://learn.microsoft.com/en-us/windows-server/networking/technologies/qos/qos-policy-manage).
No separate listener is implemented or promised by this increment.

## Verification and rollout

Focused tests first reproduced the missing heartbeat route and false offline
state with a communicating legacy console. The integrated backend suite passes
225 tests; migration drift check passes. Worker tests cover blocked collection
and frames, independent heartbeat progress, failure recovery, cancellation and
late activation responses. Windows MSVC build and all five CTest targets pass;
the worker suite also passed 30 consecutive repetitions. Linux Release build
with GNU 15.2, libcurl 8.18 and OpenSSL 3.5.5 passes all three CTest targets and
strict warning checks. Web lint (98 files), TypeScript and production build pass.
A synthetic read-only PostgreSQL statement was cancelled at 2.002 seconds and
its prior connection setting was restored after rollback. This is not a live
concurrent Agent-removal/console-creation interleaving test.

The Windows archive contains only three final binaries and three installer
scripts. Extracted binaries match the MSVC outputs. Package SHA-256:
`910a1edc21a7bd1b482e8926145b31e4afd1148fc95daf108d7d2ba34e33b1c5`.
Linux source/build parity is verified; no Linux Agent service was installed or
enrolled during this increment.

Deploy the application and additive migration before updating Agents. Older
Agents remain compatible and gain the legacy-console presence/removal guard;
independent heartbeat and concurrent Windows collection require the new Agent.
Only the selected Hyper-V host is the initial canary, not every managed system.
Do not interrupt an operator-owned console for deployment or measurements.

The DEV Appliance was revalidated at the previous immutable application 0.2.28
release with Agent 0.2.23 on the selected host, and its console was still active.
This candidate has not been deployed or measured on that host. Do not infer
runtime version from repository HEAD or from the older runtime's stale root
VERSION file. Application API metadata is the version authority there.

Pending live acceptance: observe more than five minutes with a console open,
advancing heartbeat and telemetry timestamps, online/non-removable status,
and compare typed-input acknowledgement/frame timing on the same test VM.
Backend/worker tests do not establish glass-to-glass performance. The preceding
0.2.29 detached-browser end-to-end acceptance remains explicitly pending too.

For rollback, keep the additive database column and return to the prior
immutable application/Agent pair together. Rolling back only to application
0.2.28 while keeping Agents at or above 0.2.24 breaks the separate input
contract; removing this schema column discards heartbeat history unnecessarily.
