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

## System Overview

Select a BMC name to open its tenant-scoped, read-only system overview. The
page displays the last persisted discovery snapshot; changing a tab does not
open another session to the BMC. The overview contains subsystem health cards
and separate views for fans, temperatures, power, processors, memory, network,
device inventory, storage, firmware, and software.

For iLO 4, the Storage view groups Smart Array controllers, drive enclosures,
physical disks, and logical disks from HPE's advertised legacy Smart Storage
resources. Capacity, RAID, media and interface type, location, identity,
firmware, temperature, and health are shown only when the controller reports
them. The Web Console receives normalized snapshot data and never reads OEM
resources directly.

Legacy iLO 4 thermal and power documents provide fan speed, power history,
redundancy data, and detailed power-supply properties. IPMS prefers explicitly
reported redundancy. Where iLO 4 omits a fan-redundancy resource, the adapter
marks redundancy only when multiple installed fans all report a healthy state.

For iLO 4, the Memory view also uses advertised legacy HPE inventory to show
individual DIMM slots, capacity, speed, type, manufacturer, part number, and
reported state. Device Inventory includes the advertised PCI devices. Fibre
Channel adapters are additionally shown in Network with their slot identity.
The iLO 4 REST API does not expose WWPN or WWNN, so the console labels those
values as unavailable and explains that host or Management Agent inventory is
required. IPMS does not scrape the iLO web interface.

Unavailable optional data is shown as unknown or empty. IPMS does not infer a
healthy state merely because an older iLO generation, a firmware version, a
powered-off server, or a device license omits a resource. Run another discovery
to refresh the snapshot.

The connector request timeout is controlled by
`IPMS_BMC_CONNECT_TIMEOUT_SECONDS`. The standalone DEV profile defaults to 45
seconds and the Control Plane accepts bounded values from 5 through 60 seconds.
This timeout applies to certificate inspection and Redfish requests; it is not
an unbounded retry window.

The Web Console certificate check is executed by the dedicated
`ipms-certificate-probe` service. The Control Plane reaches this helper only on
localhost through an authenticated, bounded JSON request and retains
`IPAddressDeny=any` with only localhost allowed. The helper has no public
listener, runs as the unprivileged connector-worker account, and may reach
only localhost, RFC 1918 networks, and unique-local IPv6 networks. It applies
the private-target validation before opening a socket and returns only the
normalized certificate fields needed for the explicit trust decision.
Its dedicated environment file contains only the loopback port and the shared
probe-authentication token; database credentials and the connector encryption
key are not exposed to the helper process.

The standalone installer derives both service configurations from one token,
removes duplicate legacy token and port assignments, and then writes the
minimal helper environment. This normalization is required because systemd and
shell environment loaders select the last repeated assignment, while an
unbounded multi-line copy could make the helper select a different value.

## Enrollment Diagnostics

The enrollment API returns stable, non-secret error identifiers. Relevant
certificate-probe failures include:

- `certificate_probe_unavailable`: the localhost helper is unavailable or did
  not answer within the bounded timeout;
- `certificate_probe_forbidden`: the Control Plane and helper authentication
  configuration is inconsistent;
- `target_unresolved`: the supplied management name cannot be resolved;
- `target_not_private`: target validation rejected a non-private or otherwise
  forbidden destination;
- `connection_timeout`: the isolated helper could not complete the TLS
  connection before the configured timeout; and
- `connection_failed`: the target rejected the connection or TLS negotiation
  failed before a certificate could be observed.

Do not work around these errors by granting private-network egress to the
Control Plane. Validate the helper service, its localhost-only listener, the
single token assignment in each environment file, and the approved
private-network route instead. Public issue evidence must contain only the
stable error identifier, application version, immutable commit, and sanitized
service health.

## Credential Rotation and Removal

The key action replaces the encrypted credential and queues a new discovery.
It does not reveal the old username or password.

The refresh action between the key and minus actions queues a new read-only
discovery without changing connector configuration.

The minus action performs a soft removal: the endpoint disappears from active
views, queued work is stopped, and the encrypted credential is destroyed.
Audit events and sanitized communication history remain available for
accountability. Re-enrollment of the same endpoint is possible afterward.

## Communication Logs

**Physical infrastructure > Bare Metal Controller > Communication logs** provides
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

## Device Event Logs

**Physical infrastructure > Bare Metal Controller > Event logs** combines the
iLO Event Log and Integrated Management Log for every enrolled BMC within the
selected tenant. The view can filter by log type, severity, BMC, source time,
and text, and can export up to 10,000 filtered rows as formula-safe CSV.

These device event records are a separate data class from sanitized connector
communication metadata. IPMS persists the bounded message and the iLO record
identifiers required for an operator to diagnose hardware events; credentials,
session material, request bodies, and unrelated Redfish response bodies remain
excluded. Collection is read-only and refreshes during normal discovery.

## Validation

- Active BMCs and their controls are isolated by the selected tenant.
- A queued discovery succeeds or exposes a stable, non-secret diagnostic.
- A successful discovery persists a normalized detail snapshot without raw
  Redfish response bodies.
- An untrusted certificate requires explicit approval of the displayed leaf.
- The Control Plane can complete a probe through the localhost helper while its
  own systemd unit retains localhost-only network access.
- A changed certificate is rejected before credentials are submitted.
- Removal destroys the secret while preserving sanitized audit history.
- Logs and CSV export honor tenant and filter boundaries.
- Device event logs remain tenant-scoped and distinguish IEL from IML records.

Never disable TLS validation, bypass private-target checks, broaden the device
account beyond read-only access, or publish endpoint details and operational
logs in public issue evidence.
