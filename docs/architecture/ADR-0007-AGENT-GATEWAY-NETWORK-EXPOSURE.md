# ADR-0007: Agent Gateway Network Exposure

- Status: Accepted
- Application version: 0.1.51
- Date: 2026-09-03

## Context

IPMS must be bootstrap-ready in customer environments whose managed systems
may originate from initially unknown networks. Requiring the Appliance
installer to know every Agent subnet would delay discovery and make later
network additions an Appliance reconfiguration task.

The Agent Gateway accepts only Agent-initiated connections on TCP 9419. The
protocol requires mutual TLS, tenant-bound machine certificates, bounded
messages, and explicit enrollment. Managed systems do not expose an inbound
IPMS listener.

## Decision

The IPMS Appliance host firewall permits TCP 9419 from all IPv4 and IPv6
sources. This is the stable on-premises listener contract, not a temporary
development exception.

Customers are responsible for restricting which networks can reach TCP 9419
through a central firewall, security group, routed access policy, or equivalent
upstream control. IPMS documentation and deployment acceptance must state this
responsibility explicitly.

The open host-firewall rule does not relax application-layer controls. The
Gateway must continue to:

- require TLS 1.3 and mutual certificate authentication after enrollment;
- bind every certificate to one tenant and managed Agent identity;
- reject revoked, expired, unknown, or mismatched identities;
- accept only the versioned bounded Agent protocol;
- expose no shell, script runner, arbitrary command, or arbitrary artifact
  execution capability;
- retain throttling, audit, certificate rotation, and revocation controls.

## Consequences

- A newly routed customer network can connect without changing the Appliance
  firewall.
- Central network policy becomes part of the customer's deployment security
  boundary and must be covered by installation guidance and acceptance.
- Internet exposure remains strongly discouraged even though unauthenticated
  peers cannot complete mTLS. Upstream filtering and rate controls reduce
  denial-of-service and scanning exposure before traffic reaches the Gateway.
- Standalone and future scale-out installers must preserve the same listener
  contract unless a later ADR introduces an explicit deployment profile.
