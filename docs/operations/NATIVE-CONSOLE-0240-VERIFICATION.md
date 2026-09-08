# Native console stream reliability: 0.2.40

Status: **implemented and verified on Windows and isolated Linux/PostgreSQL;
publication and DEV activation authorized, cutover pending**.

## Reproduced defect

The broker previously forwarded arbitrary renderer TCP reads directly to the
browser while independently writing transport keepalive replies into the same
protocol stream. A TCP read can end inside an image instruction. Inserting a
keepalive before the remaining image data changes the length-prefixed payload
and corrupts the browser decoder. The actual pinned browser decoder reproduced
the invalid-terminator failure with a split image payload.

A regression using the real broker, WebSocket and TCP transports reproduced this
interleaving deterministically. Only certificate observation and the external
renderer connection setup are test fixtures; authorization, parsing, relaying
and cleanup use production collaborators. The regression failed before the fix
and passes afterward.

The protocol explicitly defines messages as complete instructions with lengths
counted in Unicode characters, not TCP packets or UTF-8 bytes:
[Apache Guacamole protocol design](https://guacamole.apache.org/doc/gug/guacamole-protocol.html#design).

## Correction

- Frame decoded renderer output into complete instructions before allowing a
  keepalive reply into the shared browser stream. Preserve exact payload bytes
  and ordering; batch small instructions to avoid one WebSocket send per opcode.
- Bound an individual retained instruction to 8 MiB, including UTF-8 payload
  and framing. Reject invalid length prefixes, delimiters and truncated streams.
  Incremental UTF-8 decoding and code-point lengths preserve Unicode content.
- Relay a genuine browser heartbeat to the renderer as a harmless `nop` before
  echoing it. The heartbeat no longer stops at the outer broker. Do not invent
  rendering acknowledgments, mouse/key input, or an autonomous server heartbeat.
- Keep existing authorization/lease checks, explicit certificate trust, single
  session ownership, backpressure and cleanup. Browser pings cannot restore
  revoked access or keep a disconnected Agent authorized.

No Agent, renderer library, dependency, credential, firewall, authorization
policy, database schema or guest state change is required. Existing browser
protocol messages remain compatible; only the broker relay behavior changes.

## Verification completed

- **71 focused backend tests discovered: 70 passed, one PostgreSQL-only case
  skipped on SQLite.** Includes native protocol/authentication boundaries,
  legacy transport/input channels, revoked identity, settings-dialog and API
  regression checks.
- **All 71 focused backend tests passed on isolated Linux/Python 3.14 with
  PostgreSQL, with no skips.** The dedicated test database was removed after
  completion. The active application release remained unchanged.
- The split-image regression also keeps a real WebSocket/TCP relay open with an
  idle display for **45 seconds**, beyond the renderer input timeout and initial
  lease interval. Genuine heartbeats reach the renderer; the independently
  renewed session remains active. This is an isolated transport test, not a
  real Hyper-V guest connection.
- Every UTF-8 split point, multibyte characters, embedded delimiters, empty
  elements, byte-at-a-time input, large fragmented images, bounded batching,
  invalid/truncated data, and 200 ordered randomized image sequences pass.
- The existing permission-loss integration test now includes genuine
  keepalives before revocation and confirms that browser/renderer/Agent cleanup
  and input rejection still occur after revocation.
- **12 Node tests passed**, including the actual pinned browser parser and
  existing trust/timeout/backpressure channel tests. New frontend test formatting
  and lint checks passed. No vendor-library change is included.
- The local production portal build, its TypeScript check and targeted Biome
  checks passed. All seven core/API tests passed again after updating the version
  metadata; the migration drift check reported no changes.
- The version-specific deployment script passed Bash syntax validation and a
  non-mutating preflight against the verified DEV baseline. This does not claim
  that staging or activation has occurred.
- A local framing-only microbenchmark processed 20,000 instructions / 57.51 MiB
  in approximately 0.24 seconds. This bounds framing overhead on that workstation;
  it is not a remote-console FPS, end-to-end latency or host-resource benchmark.

## Deployment and remaining acceptance

Use the version-specific `deploy-console-stream-dev.sh` against the verified
0.2.39 DEV baseline. It stages/builds before cutover, asserts the actual API
version and absence of pending migrations, preserves configuration, refuses
active/unresolved work, retains backups and fails closed for reviewed recovery.
The previous immutable release is the rollback target; no schema reversal or
database restore is needed for this change. Do not interrupt an existing user
console session to run the cutover.

The initial publication attempt stopped before any staging, commit or push.
The owner subsequently explicitly authorized publishing 0.2.40 to the default
branch and activating it on DEV. Runtime cutover and real-host acceptance must
still be verified independently; authorization alone is not activation evidence.

Source publication, Linux release staging/build, DEV activation and real-host
operator acceptance remain pending and are separate from the completed tests
above. DEV remains on 0.2.39. The isolated transport regression does not prove
that a real Hyper-V console session is stable after deployment. Detailed
operational evidence stays local; public updates contain only sanitized
release/acceptance summaries.
