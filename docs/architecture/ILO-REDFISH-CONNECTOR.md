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
- Treat explicit leaf-certificate pin approval as the supported trust path for
  self-signed and private-CA endpoints. A different presented certificate is a
  hard failure until an administrator reviews and approves the new pin.
- Use a dedicated iLO local account with the HPE `ReadOnly` role. HPE maps that
  role to `LoginPriv` only; no power, console, media, BIOS, storage, network,
  user-management, or iLO-configuration privilege is granted.
- Enroll connectors only through the tenant-aware portal workflow. Encrypt the
  username and password with AES-256-GCM under a dedicated deployment master
  key and bind the ciphertext to its tenant and secret identifiers. Never
  return credentials, secret references, certificate pins, nonces, or
  ciphertext through the API.
- Prefer Redfish session authentication. The password is submitted only to the
  session collection, the returned `X-Auth-Token` is held in worker memory, and
  the connector deletes its own session during cleanup.
- Emit tenant-scoped communication metadata for TLS and Redfish operations.
  Store method, resource path, status, duration, normalized error identifiers,
  and correlation only; never store credentials, tokens, headers, message
  arguments, or payload bodies. Logging failures must not affect discovery.
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

1. A tenant or platform administrator completes the portal wizard; the Control
   Plane stores the encrypted credential and queues a durable discovery job.
2. The isolated connector worker claims the job and validates its private
   destination and trust material.
3. Fetch `/redfish/v1/` and record Redfish version plus advertised service
   links.
4. Create a Redfish login session through the advertised session collection.
5. Enumerate the advertised `Systems`, `Chassis`, and `Managers` collections.
6. Follow resource links to processors, memory, storage, drives, volumes,
   network interfaces or adapters, thermal data, power data, log summaries, and
   firmware inventory when present.
7. When an iLO 4 system advertises `Oem.Hp.Links.SmartStorage` or
   `Oem.Hpe.Links.SmartStorage`, invoke the isolated compatibility adapter. It
   follows only advertised array-controller, HBA, logical-drive,
   physical-drive, and enclosure links. Standard DMTF Storage remains
   preferred whenever it is available.
8. Normalize stable identity, manufacturer, model, serial number, SKU, UUID,
   power state, health, CPU, memory, storage, network, BMC, and firmware fields.
9. Record unsupported and inaccessible optional resources as partial-data
   observations rather than inventing values or failing the entire endpoint.
10. Persist one tenant-scoped discovery result transaction, update connector
   health, emit an audit event, and delete the Redfish session.
11. Return only normalized, secret-free failure diagnostics to the tenant
    console and allow an authorized administrator to queue a repeat discovery.

The normalized result includes a versioned detail snapshot for subsystem
health, fans, temperatures, power supplies and consumption, processors, memory,
network interfaces, device inventory, storage, firmware, and software. It
stores selected normalized fields only, never a raw Redfish document. The Web
Console renders this snapshot server-side and limits client-side behavior to
the accessible tab selector.

Each individual HTTPS exchange uses the deployment's bounded BMC connection
timeout. Increasing that value can accommodate slower legacy controllers, but
does not change the worker's method allowlist, certificate pinning, response
limits, or target validation.

Collection members and optional resources vary by iLO generation, firmware,
server power state, installed hardware, and license. Capability detection is
therefore based on advertised links and schemas rather than a fixed URI list.

## Compatibility Baseline

The design targets standards-conformant Redfish services in iLO 5, iLO 6, and
iLO 7. iLO 4 firmware 2.30 and later is eligible through a separate
compatibility adapter because HPE identifies 2.30 as its Redfish 1.0
conformance baseline. Its older API behavior must not weaken the iLO 5+
security or data-model baseline. The initially probed acceptance device
advertised Redfish 1.0.0, the standard Systems, Chassis, Managers, and
SessionService collections, and TLS 1.2. No private endpoint or certificate
identity is recorded in this public document.
The first physical acceptance device defines the initially tested generation
and firmware; support claims require a deterministic fixture and a real-device
read-only acceptance record for that version.

HPE documents that the legacy Smart Storage model used by iLO 4 is deprecated
with iLO 6 and later. The connector therefore prefers the DMTF Storage model and
isolates legacy Smart Storage parsing in a version-specific adapter. The
adapter normalizes controller and logical-drive rows into the Storage view and
physical drives plus enclosures into Device Inventory. It retains selected
capacity, RAID, media, interface, location, firmware, identity, and health
fields only; no OEM response body is persisted or exposed to the browser.

iLO 4 also advertises pre-Redfish HPE Memory and PCI Device resources. A
separate read-only inventory adapter follows only those advertised links and
accepts their legacy `href` member references. Normal Redfish requests retain
the `OData-Version: 4.0` header; only this compatibility fetch omits the header
because iLO 4 otherwise hides the pre-Redfish properties. The adapter
normalizes DIMM location, capacity, speed, type, identity, and state, plus PCI
device identity and location. Collection and response limits remain enforced.

HPE documents that the supported iLO 4 REST API cannot retrieve a Fibre
Channel HBA's WWPN. IPMS can therefore identify Fibre Channel adapters from
their PCI class and inventory but records WWPN and WWNN as unavailable rather
than inventing values or scraping the iLO web interface. A future host or
Management Agent inventory source will enrich these fields.

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
- Snapshot contract tests covering every overview section and persistence
  through the isolated discovery worker.
- iLO 4 Smart Storage fixtures proving advertised-link traversal, collection
  limits, standard-Storage precedence, health normalization, and a transport
  method set limited to discovery plus connector-owned session lifecycle.
- iLO 4 OEM inventory fixtures proving legacy `href` traversal, DIMM
  normalization, PCI-class Fibre Channel identification, explicit missing-WWN
  provenance, and omission of the OData header only on the compatibility path.

## Implementation Stages

1. Finalize the generic read-only connector contract in Issue #4.
2. Add portal-based endpoint enrollment, encrypted credentials, trust material,
   tenant-administrator authorization, and a separate execution worker.
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
- [HPE iLO 4 API reference](https://hewlettpackard.github.io/ilo-rest-api-docs/ilo4/)
- [HPE: iLO 4 cannot retrieve Fibre Channel WWPN through the RESTful API](https://support.hpe.com/hpesc/public/docDisplay?docId=sf000087648en_us&docLocale=en_US)
- [HPE iLO 5 documentation](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/ilo5)
- [HPE iLO 7 documentation](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/ilo7)
