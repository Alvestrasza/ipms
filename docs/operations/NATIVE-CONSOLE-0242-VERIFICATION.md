# Native console event-driven relay and measurements: 0.2.42

Date: 2026-09-08. Related issue: #23.
Status: published; application **0.2.42** activated on DEV; Windows Agent
**0.2.29** successfully updated on one authorized Hyper-V canary host.
Source and both immutable release tags:
`cfb317e23966c88e33698cf363120860a7447579`.
Real-host rendering, input-latency and 15 FPS acceptance remain open.

## Changes

- Replace fixed 10 ms sleeps in the Windows native console handshake and relay
  with shared WinHTTP completion and Winsock readiness events.
- Drain ready reads/writes without an unconditional delay. Socket notification
  consumption is atomic, idle waits are bounded to 100 ms, and partial writes
  continue from their existing buffer offset.
- Preserve shared callback-buffer lifetime through HANDLE_CLOSING, single
  attachment ownership, fixed local port 2179, exact VM preconnection checks,
  mTLS, deadlines, message bounds, backpressure and session leases.
- Add localized display-update FPS and browser-to-broker RTT below the detached
  console toolbar. Update React state only once per second; no extra connection,
  probe endpoint, periodic screenshot or guest input is generated.
- Reuse the existing heartbeat for RTT, correlating bounded sequence identifiers
  with a monotonic local clock. Clear stale samples after three seconds and
  discard measurements on visibility changes, disconnects and failures.

## Metric semantics

Display FPS counts completed drawing batches to visible layers, using the
official pinned renderer's outgoing sync acknowledgment after its display-flush
callback. Receipt of a sync alone is not counted. Empty syncs, heartbeats, local
mouse movement, cursor-only updates and offscreen image-cache writes are excluded.
Copies from a cache onto a visible layer count when their batch completes.

This is not pixel-difference detection, monitor refresh rate, guest application
FPS, or a guarantee that every intermediate batch reached a physical monitor
refresh. An idle display can correctly show **0.0 FPS**. Measurement queues are
bounded; an overflowing or long-paused sample is unavailable rather than an
invented rate. Future codecs or nested display protocols need their own metric
coverage before these semantics can be extended.

Broker RTT measures only the existing browser-to-broker heartbeat round trip.
It excludes the Agent relay, host, guest scheduling, guest rendering and the
complete input-to-screen delay. It must not be presented as total console latency.

## Fresh local evidence

| Check | Result and boundary |
| --- | --- |
| MSVC 19.44, x64 Release full Agent build | Passed, including Agent, updater, configuration application and test targets. No Agent installation or real-host connection. |
| Native CTest suite | 12 passed; 1 existing protected-journal I/O test skipped because the process lacks an administrator/LocalSystem token. No blanket claim of 13 executed tests. |
| New real-Winsock event test | Passed, then 20 consecutive repeats passed: completion before wait, callback wakeup, auto-reset, bounded idle wait, receive re-arming, full send-buffer backpressure, writable wakeup and graceful EOF. Local ephemeral loopback fixture only. |
| JavaScript tests | 19 passed: five measurement tests plus channel, framing and pinned-renderer integrity tests. |
| Cursor/cache measurement regression | Initially failed (a cursor-buffer write incorrectly counted as one frame); passed after checking destination-layer indexes. |
| Biome and TypeScript | Targeted source/tests passed; production build type checking passed. |
| Next.js production build | Passed, including all 44 generated static pages. No dependency upgrade. |
| Browser integration | Five native-console scenarios passed against the production artifact and isolated SQLite fixture. Real renderer decoded PNG data; tests covered drawing FPS, idle zero, matched RTT, stale RTT, numeric keys, hover input, secure attention, configuration permissions, failures, 45 genuine heartbeat intervals and close cleanup. |
| Core backend tests | Seven passed using isolated in-memory SQLite. Application-version response included. |
| Migration drift | No changes detected. No deployed database migration. |
| Fixture cleanup | All three local helpers were stopped; both loopback web endpoints and the fixture API port were confirmed closed. |
| Browser-helper limitation | The separate agent-browser helper could not initialize its browser connection. Existing Playwright/Chromium integration and screenshot review completed without changing security settings. |

The missing event-helper/header and missing measurement module were first
observed as build/import failures. These are feature-gap checks, not a reproduction
or measurement of real-host console performance. The native tests validate the
event primitives and existing guard contracts; they do not exercise an entire
WinHTTP mTLS-to-VMConnect session, callback cancellation under real network loss,
or performance under an actual Hyper-V desktop workload.

## Activation and rollback gates

1. Publication, DEV activation and a single-host Agent canary were approved on
   2026-09-08. Future publication follows the [release policy](RELEASE-POLICY.md).
   Do not replace an Agent while its console is occupied. Use the exact-target
   `scripts/deploy-console-performance-dev.sh` for the schema-neutral DEV cutover.
2. Publish immutable, verified release artifacts. Retain the previous application
   release and installed Agent binaries; preserve service-account and gateway
   configuration. The Agent-only change is wire-compatible with application
   0.2.41, and the new measurement UI can run with the previous Agent.
3. Verify active application 0.2.42 and canary Agent 0.2.29 independently. A portal
   update alone does not remove polling in an older installed Agent.
4. Perform the synchronized real-host comparison described in the
   [vendor and implementation assessment](../architecture/HYPERV-CONSOLE-IMPLEMENTATION-COMPARISON.md).
   Confirm idle resource use, moving-window updates, input responsiveness, lease
   expiry, cancellation, reconnect cleanup and sustained session stability.
5. If regressions occur, end the canary session and use the retained previous
   Agent artifact with an explicitly reviewed recovery procedure. The ordinary
   portal update action rejects downgrades; do not claim it provides a manual
   version rollback. Application rollback remains independent; no schema rollback
   is required by this candidate.

No live FPS improvement, guest input-latency reduction or 15 FPS acceptance is
claimed yet. No firewall, authentication, certificate, port exposure, host
policy, guest configuration or external console session was changed.

## Publication and DEV activation evidence

- Published [application 0.2.42](https://github.com/Alvestrasza/ipms/releases/tag/v0.2.42)
  and [Windows Agent 0.2.29](https://github.com/Alvestrasza/ipms/releases/tag/windows-agent-v0.2.29)
  as development pre-releases. Both tags and `main` were read back at the exact
  feature commit before deployment; no existing tag or asset was overwritten.
- Uploaded the credential-free six-file Windows x64 ZIP and `SHA256SUMS`.
  GitHub's asset digest matched the locally verified ZIP:
  `a8633632e5a2717a0c32091bd37f786621525af9320fabd2f6a8dede3d56ad5f`.
  The embedded Agent executable matched:
  `ddb6d1573aa6d7de7052b16e621cca38b9835abd4ac49394d3fda95cc184be10`.
- Repeated five measurement tests and the native suite before publication:
  12 native passes, one explicitly reported protected-journal skip.
- Built the immutable published source on Linux, preserving the prior Python
  dependency versions and frozen web lockfile. Production build and TypeScript
  passed, with 44 generated static pages.
- All **73 focused PostgreSQL tests passed without skips** against the staged
  published source. The separate test database was removed; the operational
  database schema was not migrated.
- The coordinated portal cutover retained the previous immutable application
  and protected configuration/database backups. API version, English and German
  login routes, anonymous authorization rejection, six application services,
  all-interface Agent ingress and loopback-only console services were verified.
  The pre-existing DEV HSTS warning remains unchanged.
- The workstation PowerShell HTTPS probe rejected the existing internal CA
  chain as untrusted. No trust store or validation policy was changed. HTTPS
  API verification used the appliance's existing explicit certificate trust,
  and the existing authenticated browser session rendered the current version.

### Artifact activation interruption and recovery

The separate Agent-package activation initially stopped the Control Plane and
Gateway but omitted the Web Console from its restart list. The Web Console has
`Requires=ipms-control-plane.service`; stopping the dependency also stops the
web service. The final all-service check correctly failed and re-fenced the
affected application services. No Agent update had been queued at that point.

Read-only diagnosis confirmed successful service stop results, the exact active
release and the intended package-only configuration delta. Recovery explicitly
included the dependent Web Console and waited for both API readiness and the
Agent listener. All six services and the pinned-certificate HTTPS API then
passed. No database restore, privilege change or certificate-validation bypass
was used. The previous environments remain in protected recovery storage.

This dependency-aware restart requirement applies even to package-only
configuration changes; a single-service restart list is insufficient.

### Single-host canary boundary

With no occupied console or active management operation, exactly one existing
Hyper-V host was updated through the authorized tenant user's ordinary portal
lifecycle action. The durable job reached `succeeded` in approximately nine
seconds. Fresh inventory and subsequent authenticated heartbeats report Agent
**0.2.29**; the refreshed portal shows that host as **Current**. No other Agent
update was queued by this workflow, and no guest input or VM action was sent.

This proves package delivery, Agent restart and reconnect/version acceptance,
not the full console performance claim. A controlled real-host comparison and
sustained native console acceptance remain tracked in issue #23.
