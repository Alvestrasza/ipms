# BMC Connector Management

## Scope

Tenant and platform administrators manage Bare Metal Controller (BMC)
connectors through **Physical infrastructure > Bare Metal Controller**. The
initial implementation uses a read-only Redfish transport for HPE iLO 4,
modern HPE iLO generations, Dell iDRAC, and generic standards-compatible
Redfish services. A listed family is not a claim of hardware acceptance until
that family has passed its dedicated compatibility tests.

The connector does not change power, BIOS, firmware, virtual media, storage,
network, or account configuration.

## Enrollment Wizard

1. Select **Add BMC** and choose the BMC family.
2. Enter a display name, IP address or resolvable management DNS name, and the
   HTTPS port. Schemes, paths, and public or local destinations are rejected.
3. Enter a dedicated read-only username and password.
4. The Control Plane probes the TLS certificate before it submits credentials.
5. If the appliance trust store accepts the certificate, enrollment continues
   automatically. Otherwise a separate dialog displays its subject, issuer,
   validity period, DNS names, and SHA-256 fingerprint. Enrollment continues
   only after explicit administrator approval.

The short-lived certificate decision is signed, tenant-bound, and scoped to
the exact endpoint. The Control Plane probes the endpoint again immediately
before enrollment and rejects a certificate that changed between the two
checks. The approved leaf fingerprint remains pinned for connector traffic.

Credentials are encrypted with the appliance master key and are never returned
to the browser. Enrollment emits an audit event and queues the first read-only
discovery job.

## Credential Rotation and Removal

The key action replaces the encrypted credential and queues a new discovery.
It does not reveal the old username or password.

The minus action performs a soft removal: the endpoint disappears from active
views, queued work is stopped, and the encrypted credential is destroyed.
Audit events and sanitized communication history remain available for
accountability. Re-enrollment of the same endpoint is possible afterward.

## Communication Logs

**Physical infrastructure > Bare Metal Controller > Logs** provides
tenant-scoped filters for severity, time range, BMC, and text search, plus CSV
export. The interactive view returns at most 500 recent entries; CSV export is
bounded to 10,000 filtered entries and protects spreadsheet cells from formula
injection.

Logs record only safe exchange metadata such as time, severity, BMC name,
event type, HTTP method, Redfish resource path, status, duration, normalized
error code, bounded Redfish registry identifier, and correlation ID. They never
store credentials, session tokens, authorization or response headers, request
or response bodies, certificate bodies, Redfish message arguments, or raw
device logs. Observability failures cannot interrupt connector operations.

## Validation

- Active BMCs and their controls are isolated by the selected tenant.
- A queued discovery succeeds or exposes a stable, non-secret diagnostic.
- An untrusted certificate requires explicit approval of the displayed leaf.
- A changed certificate is rejected before credentials are submitted.
- Removal destroys the secret while preserving sanitized audit history.
- Logs and CSV export honor tenant and filter boundaries.

Never disable TLS validation, bypass private-target checks, broaden the device
account beyond read-only access, or publish endpoint details and operational
logs in public issue evidence.
