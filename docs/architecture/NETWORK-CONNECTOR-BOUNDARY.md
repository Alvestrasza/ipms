# Network Connector Security Boundary

## Scope

IPMS 0.2.0 introduces read-only connector foundations for Sophos Firewall,
Loadbalancer.org ADC, and HPE 5130/5900AF switches running Comware 7.1. Each
connector contains a small fixed set of compiled discovery operations. IPMS
does not expose a generic API proxy, SNMP browser, SSH terminal, configuration
push, or operator-provided command facility.

## Common controls

- Connector records and discoveries are tenant-bound.
- Credentials and optional API/privacy keys are encrypted, write-only, and
  removed when a connector is archived.
- DNS names are resolved to private addresses and the validated literal target
  is used for the connection while retaining the original TLS server name.
- HTTPS redirects are disabled, response sizes and timeouts are bounded, TLS
  1.2 or newer is required, and the exact approved SHA-256 certificate pin is
  verified before credentials are sent.
- Certificate approval is short-lived, tenant-bound, endpoint-bound, and
  revalidated during enrollment.
- Discovery output is normalized before persistence; raw responses and
  credentials are not returned to the browser.

## Product boundaries

Sophos Firewall uses a fixed XML API request to the documented API controller.
DTD, entity, and external-reference XML constructs are rejected before parsing.
Loadbalancer.org uses a fixed read-only JSON API action with Basic
authentication and the documented encoded API-key header. Comware requires
SNMPv3 authPriv using SHA-1 authentication and AES-128 privacy, and permits only
fixed system and IF-MIB reads with a bounded interface count. SNMPv1, SNMPv2c,
SNMP SET, arbitrary OIDs, and SSH are rejected by design.

## Acceptance status

Fixture, negative, tenant-isolation, and payload-bound tests are mandatory for
the release. Live compatibility remains pending for each exact product and
firmware combination until an administrator enrolls a dedicated read-only
account and records the observed result. A successful fixture test is not a
claim of live vendor compatibility.
