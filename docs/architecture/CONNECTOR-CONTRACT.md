# Read-Only Connector Contract

## Purpose

IPMS connectors discover infrastructure through narrowly scoped, tenant-owned
integrations. A connector is not a remote shell and receives no implicit write
capability. The Control Plane owns endpoint enrollment, policy, durable job
state, normalized inventory, and audit attribution; a worker owns only the
bounded protocol exchange for one job.

## Required Declaration

Every connector declares:

- a stable connector type and implementation version;
- the protocol and supported device or platform generations;
- `read_inventory` as its only v0.1.0 capability;
- the allowed network schemes, HTTP methods, and request paths;
- required protected secret and trust references;
- timeout, response-size, collection-size, and concurrency limits; and
- normalized object types plus explicitly optional data.

No future write capability is enabled by registering or upgrading a read-only
connector. Write capabilities require separate policy declarations,
authorization, licensing, audit events, tests, and user approval.

## Lifecycle

1. An actor with `connectors.manage` enrolls an endpoint, trust policy, and
   protected credential reference.
2. The Control Plane validates tenant ownership and queues an attributable
   discovery job.
3. A connector worker resolves the secret only for the lifetime of that job.
4. The worker validates the endpoint and trust policy before sending a
   credential.
5. The worker performs only declared read operations, normalizes the result,
   and returns bounded observations.
6. The Control Plane persists inventory and connector health atomically and
   appends an audit event.
7. Ephemeral sessions and secret material are destroyed during cleanup,
   including failure and cancellation paths.

## Security Invariants

- Endpoint, connector, job, inventory, secret reference, and audit event carry
  the same tenant identity.
- Public APIs never return secret values or filesystem locations.
- Credentials do not appear in URLs, command lines, jobs, logs, exceptions, or
  normalized inventory.
- TLS verification uses an enrolled CA bundle or an explicitly approved SHA-256
  leaf-certificate pin. Trust on first use and an insecure deployed mode are
  forbidden.
- Redirects to another scheme, host, or port are rejected.
- Loopback, link-local, multicast, unspecified, and metadata-service addresses
  are rejected as connector targets. Private management networks are allowed
  only through an enrolled endpoint.
- A connector failure is isolated to its job and endpoint. It cannot expose
  another tenant, reuse another tenant's session, or return raw response bodies
  to the Web Console.

## Error and Health Model

Errors use stable non-secret codes such as `dns_failed`, `connection_timeout`,
`tls_untrusted`, `certificate_pin_mismatch`, `authentication_failed`,
`unsupported_service`, `response_limit_exceeded`, and `partial_inventory`.
Operator-facing details identify the stage and remediation without echoing
credentials, tokens, complete payloads, internal stack traces, or unrelated
network information.

Connector health is `unknown`, `healthy`, `warning`, or `critical`. Optional or
unsupported resources create explicit partial-data observations; they do not
invent values and do not automatically discard otherwise valid inventory.

## Test Contract

Each implementation includes deterministic sanitized fixtures and tests for:

- allowed methods and paths, including rejection of every write operation;
- authentication failure and guaranteed session cleanup;
- TLS failure and certificate-pin mismatch before credential submission;
- timeouts, malformed JSON, pagination, and bounded-response enforcement;
- idempotent inventory updates;
- secret redaction and error normalization;
- tenant isolation and audit attribution; and
- partial data from unsupported or inaccessible optional resources.

Real-device support claims additionally require a read-only acceptance record
for the exact generation and firmware family.
