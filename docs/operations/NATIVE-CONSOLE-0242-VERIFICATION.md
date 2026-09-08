# Native console event-driven relay and measurements: 0.2.42

Date: 2026-09-08. Related issue: #23.
Status: locally prepared and verified; not committed, published or activated.
Application candidate: **0.2.42**. Windows Agent candidate: **0.2.29**.
Last verified DEV application: **0.2.41**. No live activation was performed for
this candidate and no installed Agent was changed.

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
5. If regressions occur, end the canary session and restore the previous Agent
   via the existing verified lifecycle workflow. Application rollback remains
   independent; no schema rollback is required by this candidate.

No live FPS improvement, guest input-latency reduction or 15 FPS acceptance is
claimed yet. No firewall, authentication, certificate, port exposure, host
policy, guest configuration or external console session was changed.
