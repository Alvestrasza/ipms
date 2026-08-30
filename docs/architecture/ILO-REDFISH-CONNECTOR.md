# iLO Redfish Connector Architecture

## Decision

The first physical-infrastructure integration is a read-only, out-of-band HPE
iLO connector built on the DMTF Redfish API. The v0.1.0 Appliance executes the
connector as a background worker with direct HTTPS reachability to an enrolled
iLO endpoint. A future customer Edge Gateway will execute the same connector
contract when the IPMS Control Plane is hosted outside the customer network.

The connector follows links returned by the Redfish service root and resource
collections. It must not assume that a system, chassis, or manager has the ID
`1`. Standard DMTF properties form the normalized inventory contract. HPE OEM
properties are optional inputs behind an HPE-specific adapter and must never be
required for the baseline inventory.

## Security Profile

- Use HTTPS only and require certificate verification. A customer CA bundle or
  explicitly approved certificate pin is enrolled before the first credentialed
  request. Automatic trust-on-first-use and an `insecure` runtime mode are not
  supported in deployed environments.
- Use a dedicated iLO local account with the HPE `ReadOnly` role. HPE maps that
  role to `LoginPriv` only; no power, console, media, BIOS, storage, network,
  user-management, or iLO-configuration privilege is granted.
- Store the password as a protected secret reference. Never return it through
  the API, serialize it into a job, place it in a command line, or write it to a
  log.
- Prefer Redfish session authentication. The password is submitted only to the
  session collection, the returned `X-Auth-Token` is held in worker memory, and
  the connector deletes its own session during cleanup.
- Permit `GET` and `HEAD` for discovery. Permit `POST` only for session creation
  and `DELETE` only for that connector-owned session. Reject `PATCH`, `PUT`, all
  action targets, and redirects to another authority.
- Validate endpoint scheme, resolved address, port, tenant ownership, and the
  enrolled trust material before connection. Apply bounded timeouts, response
  size limits, collection limits, and per-endpoint concurrency limits.

Session creation and deletion change only the authentication-session resource;
they do not change managed infrastructure. Tests must enforce this narrow
method-and-path allowlist instead of treating all `POST` or `DELETE` requests as
inventory operations.

## Discovery Sequence

1. Fetch `/redfish/v1/` and record Redfish version plus advertised service
   links.
2. Create a Redfish login session through the advertised session collection.
3. Enumerate the advertised `Systems`, `Chassis`, and `Managers` collections.
4. Follow resource links to processors, memory, storage, drives, volumes,
   network interfaces or adapters, thermal data, power data, log summaries, and
   firmware inventory when present.
5. Normalize stable identity, manufacturer, model, serial number, SKU, UUID,
   power state, health, CPU, memory, storage, network, BMC, and firmware fields.
6. Record unsupported and inaccessible optional resources as partial-data
   observations rather than inventing values or failing the entire endpoint.
7. Persist one tenant-scoped discovery result transaction, update connector
   health, emit an audit event, and delete the Redfish session.

Collection members and optional resources vary by iLO generation, firmware,
server power state, installed hardware, and license. Capability detection is
therefore based on advertised links and schemas rather than a fixed URI list.

## Compatibility Baseline

The design targets standards-conformant Redfish services in iLO 5, iLO 6, and
iLO 7. iLO 4 can be evaluated with a separate compatibility fixture, but its
older API behavior must not weaken the iLO 5+ security or data-model baseline.
The first physical acceptance device defines the initially tested generation
and firmware; support claims require a deterministic fixture and a real-device
read-only acceptance record for that version.

HPE documents that the legacy Smart Storage model used by iLO 4 is deprecated
with iLO 6 and later. The connector therefore prefers the DMTF Storage model and
isolates any legacy Smart Storage parsing in a version-specific adapter.

## Test Strategy

- Contract fixtures for service root, collections, partial resources,
  pagination, malformed responses, authentication failure, expired sessions,
  TLS failure, timeouts, and rate limits.
- Sanitized generation-specific fixtures without customer identifiers,
  credentials, certificates, addresses, or production payloads.
- An HTTP transport spy that rejects every method-and-path combination outside
  the explicit discovery and session allowlist.
- Idempotency tests proving that repeated discovery updates the same normalized
  objects instead of duplicating them.
- Tenant-isolation, secret-redaction, audit-attribution, cancellation, and
  interrupted-session cleanup tests.
- A real-device acceptance run that compares selected fields with the iLO UI
  while proving that no managed-infrastructure write request was sent.

## Implementation Stages

1. Finalize the generic read-only connector contract in Issue #4.
2. Add endpoint enrollment, protected credential references, and trust
   material without exposing secrets to the Web Console.
3. Implement the session-scoped Redfish transport and strict request allowlist.
4. Implement standard resource discovery and normalization with fixtures.
5. Add HPE adapters only for required data absent from the standard model.
6. Expose tenant-scoped inventory and connector health in the Control Plane and
   multilingual Web Console.
7. Complete the first real-device read-only acceptance and document the tested
   iLO generation and firmware.

## Primary References

- [DMTF Redfish Specification 1.23.1](https://www.dmtf.org/sites/default/files/standards/documents/DSP0266_1.23.1.pdf)
- [HPE Redfish concepts](https://servermanagementportal.ext.hpe.com/docs/concepts)
- [HPE Redfish getting started](https://servermanagementportal.ext.hpe.com/docs/concepts/gettingstarted)
- [HPE managing iLO users](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/managingusers)
- [HPE storage data models](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/storage)
- [HPE iLO 5 documentation](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/ilo5)
- [HPE iLO 7 documentation](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/ilo7)
