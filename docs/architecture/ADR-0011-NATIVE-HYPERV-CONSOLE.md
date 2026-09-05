# ADR-0011: Native Hyper-V Console Transport

- Status: Implemented and isolated verification passed; real-host acceptance pending
- Application target: 0.2.31
- Windows Agent target: 0.2.26

## Decision and acceptance boundary

Use the native Hyper-V VMConnect protocol on the enrolled host's fixed local
TCP endpoint `127.0.0.1:2179`. Preserve the independent browser window and an
Agent-initiated mTLS connection to the existing Gateway on TCP 9419. Do not
expose VMConnect, guacd, or a generic TCP proxy to customer networks.

The native path is an additional, explicitly selected transport. The existing
thumbnail implementation remains available for compatible older Agents; never
silently downgrade a native request after authentication or trust fails.

Host authentication is independent of Agent enrollment. The operator selected
a dedicated console account stored in encrypted form, scoped to the tenant and
enrolled Hyper-V host. Only an authorized administrator can configure or rotate
that account. Decrypted credentials are held in memory for the handshake,
never in URLs, plaintext database fields, audit events or operational logs.
Provisioning a new Windows account is a separate decision; this integration
must not silently create one or weaken host authentication policy.

## Component contract

1. The authenticated, CSRF-protected console creation API accepts
   `transport: "vmconnect"` and an explicit acknowledgement that externally
   opened VMConnect sessions cannot reliably be detected. The existing VM,
   tenant, permission, version, enrollment and occupancy checks remain. Bind
   native ownership to the immutable user identity as well as the display name.
2. Native sessions have a random stream generation and one fenced browser
   attachment. A session UUID is an identifier, not a bearer credential.
3. A separate loopback console broker serves the same-origin WebSocket route
   `/api/v1/hyper-v/console-sessions/<uuid>/native-stream/`, using subprotocol
   `guacamole`. It verifies the real Django session cookie, exact Origin,
   owner, permission and lease before accepting a connection, and periodically
   revalidates authorization. Query-string credentials and target parameters
   are forbidden.
4. Before rendering starts, bounded JSON WebSocket messages exchange
   `connect` (viewport size only), the
   observed `certificate` (SHA-256 and display metadata), and explicit `trust`
   approval of that exact fingerprint. The broker obtains the host credential
   from the tenant/enrollment-bound encrypted configuration, not the browser
   WebSocket. No guest authentication is attempted
   during certificate observation. The broker sends `ready` before switching
   to the Guacamole display/input protocol. An explicit `secure_attention`
   control message remains audited and becomes a fixed key sequence.
5. The broker owns the guacd handshake and fixes the destination, VM GUID,
   basic-console mode, certificate policy and disabled redirection features.
   The browser cannot supply guacd settings, join another session or select
   a different host, port or VM. RDP redirects are not allowed.
6. The enrolled Windows Agent receives an assignment with
   `transport: "vmconnect"`, `stream_generation`, the existing session ID,
   VM GUID and expected name. It opens a WebSocket GET on the fixed Gateway
   route `/v1/hyperv-console-native`, with `X-IPMS-Console-Session` and
   `X-IPMS-Console-Generation` headers and its enrolled client certificate.
   No caller-provided endpoint is accepted.
7. The Gateway validates the peer certificate and assignment before upgrade,
   then attaches to the broker through a protected Unix socket. Native bytes
   do not pass through the frame database. Only binary RDP data and bounded
   JSON lease controls (`type: "lease"`, `seconds: 15`, matching generation)
   are accepted. The Gateway refreshes the lease at most every five seconds
   only while all authorization checks pass. Cancellation closes both sides.
8. The Agent verifies the local VM identity and validates the complete initial
   RDP preconnection PDU against the assigned GUID and basic-console mode
   before forwarding any bytes to the fixed local endpoint. Its monotonic
   deadline expires without a valid lease refresh. Identity changes, timeout,
   stop, revocation or protocol errors close both transports.

The broker may make a certificate-observation connection followed by one
authenticated console connection. They must be sequential and bound to the
same exclusive session; overlapping Agent attachments and unexpected retries
are rejected. Buffers, connection counts, message sizes, handshake time and
write stalls are bounded. There is no frame history or keystroke recording.

## Reviewed dependency baseline and adaptations

The native renderer uses the signed Apache Guacamole 1.6.0 source release and
the exact Ubuntu-provided FreeRDP 3.31.0 API baseline. The build rejects a
different FreeRDP version until it has been reviewed. These are maintained IPMS
adaptations of upstream source, not a claim of upstream approval:

- Strict, single-leaf certificate verification and rejected redirects; TLS 1.2
  is the minimum for the host console leg. Agent-to-Gateway mTLS remains a
  separate trust boundary and is not weakened by this setting.
- GDI initialization and rendering hooks run after connection negotiation,
  matching the tested FreeRDP 3.31.0 initialization order.
- Nested sockets zero-initialize their state, initialize both mutexes before
  publishing handlers, and destroy initialized locks on cleanup. This fixes an
  initialization defect exposed by allocator-perturbed upstream tests.
- Per-session encoding uses at most two worker threads instead of scaling the
  worker count with every available host CPU. This bounds one source of load;
  it is not a measured total-CPU or frame-rate guarantee.
- Wake-on-LAN and unused redirection capabilities remain disabled. Current-libc
  compatibility fixes retain compiler hardening and visible ABI deprecations.

The certificate observation path uses explicit client-side TLS over the
Agent-initiated reverse stream. Its regression test uses an accepted-stream
topology; a client-created socket alone would not exercise that boundary.

## Isolated verification record — 2026-09-05

The final reviewed renderer build passed `make check` with 97 reported passing
checks (75 + 11 + 11), zero failures/errors and `MALLOC_PERTURB_=165`. Its nine
certificate-helper cases and six real loopback TLS cases passed. Both approved
TLS 1.3 and TLS 1.2 connections reached 93 synthetic application bytes. A
different self-signed leaf, a different CA-trusted leaf, an expired certificate
and a not-yet-valid certificate each reached zero application bytes. No real
host credentials were used in these fixtures.

The backend passed 246 tests, including 21 native-console tests, on Python
3.14.4. The Windows Agent passed six CTest targets. The frozen web source passed
27 deterministic Node tests, six isolated Playwright scenarios, and its
production build including 36/36 page-generation steps. The browser tests use
the official renderer and verify actual synthetic canvas pixels, but mock the
native broker/configuration collaborators; they do not establish real-host
authentication, transport performance or browser-visible FPS.

The scoped DEV application cutover to 0.2.31 completed with separate broker and
renderer services. The authorized canary host successfully updated to Agent
0.2.26 and resumed heartbeat and telemetry. The administrator must still enter
an existing dedicated host account through the portal.
Real-host authentication, boot-console display/input, close/reopen behavior,
heartbeat/telemetry under load, browser-visible FPS and resource measurements
remain required before acceptance. Isolated test success is not a production
readiness claim.

## Required evidence

- Wrong tenant, owner, user session, permission, Agent certificate, VM GUID,
  stream generation, lease or browser Origin is rejected.
- Duplicate attachments, replay, redirection and arbitrary tunnel targets fail
  closed; authorization loss closes an already established stream.
- The approved server certificate is accepted; another certificate is rejected
  even if it chains to a trusted CA or appears in a known-hosts file. A stock
  fingerprint option alone is not evidence of this property.
- Credentials and display/input bytes never enter persistent diagnostics.
- Native boot-console display, mouse, keyboard, secure attention, session
  cleanup and heartbeat/telemetry independence pass on the authorized test VM.
- Browser-displayed frame rate, input latency and resource usage are measured.
  Native protocol support alone is not a 15-FPS or low-CPU guarantee.
- Rollback preserves the previous release, Agent compatibility and port 9419.

## References

- [Microsoft VMConnect port configuration](https://learn.microsoft.com/en-us/powershell/module/virtualmachinemanager/set-scvmmserver?view=systemcenter-ps-2025)
- [Microsoft RDP session selection](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeps/b0c89d63-473a-445b-9945-4004c02ae3c6)
- [Microsoft browser VMConnect](https://learn.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines)
- [Apache Hyper-V support](https://guacamole.apache.org/doc/gug/configuring-guacamole.html#preconnection-pdu-hyper-v-vmconnect)
