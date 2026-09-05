# Independent Hyper-V Console Input Channel

- Application: 0.2.29
- Windows Agent: 0.2.24
- Date: 2026-09-05
- Runtime acceptance: pending the authorized DEV test window

## Problem

The 0.2.28 optimization improved observed image cadence, but input still waited
behind capture, PNG encoding and upload. The Agent also withheld input
acknowledgements until it could post a new frame. The previous live sample
reported 527-638 ms input acknowledgement, which remained noticeable to the
operator. Those timings did not separate native input execution from image
processing.

## Changes

- An independent native input worker polls and applies one ordered typed batch
  at a time. It owns its COM and HTTP objects; the image loop cannot block it.
- The frame channel cannot deliver, execute or acknowledge inputs. The input
  channel cannot carry image data or change the frame scheduler's contact time.
- Input receipts are acknowledged immediately. If an acknowledgement response
  is lost, only the receipt is retried, not the local VM operation. A partially
  applied or uncertain provider result fails that exact session closed.
- The worker idles when no console is active. Empty polls have a one-second
  deadline with 25-ms queue checks, no transaction held while waiting and no
  repeated global expiry update. Queries do not fetch stored frame blobs.
- Keys, buttons, wheel and secure attention leave the browser immediately.
  Only adjacent mouse movements retain an eight-millisecond coalescing window.
- Native VM lookup is GUID-filtered and retains GUID/name/running-state checks.
  Input method completion uses semisynchronous WMI with two-second completion
  checks. Local provider connection/metadata calls still depend on WMI health.

Both channels use the existing fixed route and outbound TCP 9419 mTLS trust
boundary. No inbound Agent listener, new firewall port, generic command, guest
credentials or shared console session is introduced. Certificates are checked
per request and rechecked after a waiting input poll; validity-window checks
also prevent an established connection from outliving its certificate.

## Verification

The focused backend tests demonstrate delivery and acknowledgement without any
frame, frame-channel isolation, event ordering, bounded batches, exact-session
receipt retries, replacement-session isolation, expiry, malformed input and
certificate revocation/validity. The full suite passes 197 tests and reports no
pending schema migration.

The final MSVC build and four CTest targets pass. The dedicated native input
target includes eight checks, including blocked-frame independence, uncertain
ACK retry without execution replay, partial failure, stale identity, stop,
worker restart and idle/reactivation. The isolated browser queue suite passes
15 tests. Web lint, TypeScript and production build pass.

The complete detached-window browser regression remains unverified for this
increment: the local development run stopped at a login HTTP 403, and a
production-style local smoke check did not complete the browser session fetch.
Direct API checks succeeded. No login-code change or assumption of a confirmed
root cause was made; all temporary test servers were stopped. This is separate
from the passing deterministic browser input-queue tests.

These checks do not establish live input-to-screen latency. The authorized DEV
test VM was still occupied during preparation; its session was not joined,
renewed, controlled or closed by this work. Deployment and host Agent update
must precede the same-VM live comparison once the operator closes the console.

## Compatibility and rollout

Deploy application 0.2.29 before updating Hyper-V host Agents to 0.2.24. Old
Agents retain the combined protocol; the new Agent deliberately rejects input
on its frame lane and requires the separate-input response contract. Reverting
the Control Plane to 0.2.28 while keeping new Agents would disable console
input, so application and host Agent rollback must be coordinated.

Only the explicitly selected test Hyper-V host is in scope for the first live
update. Other hosts should use the existing Agent administration workflow after
acceptance. Updating guest Agents alone cannot accelerate the host console.
Reload the portal to obtain the browser input-queue change.

Receipt retention protects against transport failure and in-process worker
restart, not service/host crash durability or mathematically exactly-once guest
effects. Frame arrival and actual guest-visible response remain separate
measurement layers. The current PNG console is not a high-frame-rate video or
RDP stream.
