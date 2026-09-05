# ADR-0009: Identity, Tenant RBAC, and OIDC Boundary

- Status: Accepted
- Date: 2026-09-04
- Decision owners: IPMS architecture and security
- Platform authority updated by [ADR-0012](ADR-0012-PLATFORM-AND-TENANT-ADMINISTRATION.md)

## Context

IPMS must support local bootstrap accounts, customer-managed identities, and a
future Keycloak integration without moving tenant authorization into the Web
Console or binding product policy to one identity provider.

Authentication answers who the actor is. Authorization remains an IPMS
Control Plane decision based on the selected tenant, effective membership,
permission, target object, license, and requested operation.

## Decision

The Django Control Plane owns the canonical tenant role assignments and derives
effective permission codes from a central role matrix. The Next.js console
receives effective permissions in the authenticated session and uses them only
to present available navigation and controls. Every API repeats the permission
check.

Initial tenant roles are:

| Role | Intended scope |
| --- | --- |
| Tenant administrator | User, connector, Agent, VM-operation, approval, and audit administration inside one tenant |
| Operator | Inventory, connector, Agent, and VM operations without user administration |
| Approver | Inventory, approval workflows, and audit visibility |
| Auditor | Read-only inventory, Agent, user-assignment, and audit visibility |
| Reader | Read-only inventory |

Platform administrators manage tenant metadata and one-time initial tenant
administration, not tenant data or operations. They have no tenant membership
and no implicit tenant recovery/impersonation authority. This separation,
including upgrade behavior, is defined by ADR-0012.

Tenant memberships can be disabled or given an expiry timestamp. Expired
memberships are excluded from tenant selection and permission resolution. A
tenant administrator cannot remove his own administrator role or remove the
last effective tenant administrator. Lost tenant access after initial setup
requires a separately authorized recovery procedure.

Local accounts use Django's password hashing and password validators. Initial
passwords are write-only request values and are never returned by the API,
written to audit details, or exposed to the Web Console after submission.
Membership removal is soft; identity and audit history are retained.

`ExternalIdentity` reserves the immutable OIDC `(issuer, subject)` tuple and
maps it to one internal user. It stores no token, client secret, private key, or
password. Display names, email addresses, and usernames are not external
identity keys.

## Future Keycloak integration

Keycloak and other conforming OIDC providers will use the same internal user,
membership, and permission model. The integration must:

1. use Authorization Code flow through the server-side Control Plane;
2. validate issuer, audience, signature, nonce, state, time claims, and the
   configured redirect URI;
3. map the validated `(iss, sub)` pair to `ExternalIdentity`;
4. create an IPMS browser session with the existing CSRF boundary;
5. map approved Keycloak groups or roles through explicit, tenant-scoped
   configuration instead of trusting arbitrary token role names;
6. keep break-glass local platform access available and separately audited;
7. apply provider and membership disablement immediately at the next request or
   session revalidation boundary.

OIDC tokens will not be forwarded to Agents, connectors, or browsers as an IPMS
authorization substitute. Agents retain their independent mTLS device identity.

## Permission codes

Permission codes are stable API contracts. The initial set covers inventory,
connectors, Agents, VM operations, approvals, audit visibility, and user
administration. New write capabilities require a new explicit permission and
must not inherit access from a visually hidden UI control.

## Consequences

- Keycloak can be added without redesigning tenant authorization.
- Operator, approver, auditor, and reader behavior is centrally testable.
- Tenant administrators can manage local users without access to platform
  identities or other tenants.
- Provider federation and custom role-mapping configuration remain future work;
  this decision establishes their storage and authorization boundary.
