# Hyper-V Console Performance Acceptance

- Date: 2026-09-05
- Application: 0.2.28
- Windows Agent: 0.2.23
- Scope: authorized development Appliance and one explicitly selected test VM
- Code revision: `7f4c56ba7265f5c73a60e06670b0a8a179ecb96a`

## Delivered behavior

The console now opens in an independent, resizable browser window. It can be
moved outside the portal window, including onto another monitor. Reopening the
same VM focuses its existing window without creating a parallel session. The
main portal may navigate or close independently. Browsers that block popups
receive a localized explanation; allow popups for the trusted portal origin.

Mouse, keyboard, wheel and the explicit Ctrl+Alt+Delete toolbar action remain
available. Single-session ownership, tenant authorization, bounded leases and
outbound Agent mTLS remain unchanged. See
[ADR-0010](../architecture/ADR-0010-HYPERV-VM-CONSOLE.md).

## Diagnosis and changes

The initial loop added a fixed 750-ms wait after capture and exchange. Image
capture also copied RGB565 data through individual Automation array calls, and
input-device lookup scanned a host-wide collection. Active console requests
created repeated TLS connections. Browser status/image requests and individual
input submissions added further serial work.

The replacement uses validated bulk image reads, VM-filtered device lookup,
work-inclusive 150-ms target cycles, combined status/image polling, bounded
ordered input batches and a console-only authenticated connection pool. Actual
frame cadence is limited by the provider, encoding and network exchange; the
150-ms target is not an achieved-frame-rate guarantee.

## Live comparison

The same VM was sampled for approximately 12 seconds after its first frame.
The observer read frame sequence/contact timestamps every 100 ms and submitted
three neutral absolute mouse movements. No frame contents or keystrokes were
recorded. Sessions were explicitly closed after each sample.

| Windows Agent | Observed frames | Median frame interval | Maximum interval | Input acknowledgement samples |
| --- | ---: | ---: | ---: | --- |
| 0.2.21 baseline | 12 | 1,084 ms | 1,290 ms | 1,593 / 1,064 / 1,171 ms |
| 0.2.22 | 34 | 345 ms | 469 ms | 739 / 841 / 633 ms |
| 0.2.23 | 40 | 298 ms | 407 ms | 638 / 632 / 527 ms |

The final sample has approximately 3.6 times the frame cadence of the baseline.
A further 45-second active sample with Agent 0.2.23 delivered 145 observed
frames, a 305-ms median interval and a 405-ms maximum interval without a console
failure. Both final sessions were released successfully.

These are Control Plane observation/acknowledgement timings, not browser
glass-to-glass latency or a throughput guarantee. Input samples are small and
include the observer's polling granularity. First-frame arrival varied from
approximately 4.8 to 8.6 seconds across the runs: initial assignment still waits
for the Agent's normal update cycle. This is a bounded image console, not a
high-frame-rate video or RDP implementation.

## 0.2.30 follow-up

The same selected VM was measured after deploying application 0.2.30 and host
Agent 0.2.25. Its twelve-second window produced 51 observed frames, a 235-ms
median frame interval, a 318-ms maximum and 217 / 217 / 214 ms input
acknowledgements. First-frame arrival was 6,017 ms. Observer polling remained
100 ms; this is not browser glass-to-glass timing.

A 326.9-second session also verified independent heartbeat, telemetry and
scheduled inventory while the Agent remained online and not removable. The
production-build detached-browser regression passed. See the
[full acceptance record](AGENT-HEARTBEAT-ISOLATION.md#dev-runtime-acceptance).
Only the selected host was updated; both the authorized operator session and
the later test session were closed without stopping the VM.

## Verification layers

- 180 Django tests passed, including certificate revalidation on every pooled
  request, revoked identities, route/device changes, the 256-request connection
  bound, legacy one-shot compatibility and console ownership/input contracts.
- Native Windows build and all three CTests passed. The published Agent archive
  matched the verified package hash.
- Web lint, TypeScript and production build passed; three input-buffer tests
  passed.
- The isolated Chromium browser regression passed with real local
  authentication, tenant/session/input APIs and a synthetic image producer. It
  verified a separate resizable window, window reuse, independent portal
  navigation, occupancy warning, typed input and clean close. It did not
  substitute synthetic images for live performance measurements.
- The deployed DEV revision matched the code revision above. All eight checked
  application/support units were active, no failed units were reported, and the
  liveness endpoint returned `ok`. Existing global IPv4/IPv6 TCP 9419 firewall
  allow rules were preserved; this check does not assert external IPv6 routing.

Real guest frame color, keyboard layout, visual pointer mapping, mouse buttons,
wheel, secure attention, host failover and provider-timeout behavior remain
separate manual acceptance items. The user had already confirmed basic console
functionality before this optimization.

## Rollout and use

Reload the portal and close any old embedded console before opening a new one.
The optimized native path requires Windows Agent 0.2.23 on each Hyper-V host.
Only the explicitly selected test host was updated during this acceptance;
update other hosts through **Administration > Infrastructure > Agents**.
Older compatible Agents can still connect but retain their older capture and
transport performance. Do not update guest Agents solely to accelerate the
host-provided console.

## Rollback boundary

The DEV installer retains previous release directories. An application rollback
must use the documented deployment workflow and an exact reviewed release
revision. Agent rollback is a separate scoped lifecycle operation; reverting
the portal alone does not revert installed host binaries. These increments add
no database schema migration, and one-shot console transport remains supported.
