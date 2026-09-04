# User Administration

IPMS 0.2.13 introduces tenant-scoped user administration under
**Administration > Users**.

## Available operations

An actor with `users.view` can list the selected tenant's memberships. An actor
with `users.manage` can:

- create a local user and assign one tenant role;
- change that tenant role;
- activate or deactivate the membership;
- set or remove a future access-expiry timestamp.

The API never returns the submitted initial password. Deactivation preserves
the user, membership, and append-only audit history. Platform administrator
accounts are visible but protected from tenant-scoped changes.

## Role model

- **Tenant administrator:** all current tenant permissions.
- **Operator:** inventory, connector, Agent, and virtual-machine operations.
- **Approver:** inventory, approvals, and audit visibility.
- **Auditor:** read-only inventory, Agent, user-assignment, and audit visibility.
- **Reader:** read-only inventory.

Every authorization decision is repeated by the Django API. Web Console
visibility is not a security boundary.

## Safety controls

- The selected tenant comes from the authenticated request and is checked for
  every list or update.
- Cross-tenant membership identifiers are not disclosed.
- Expired memberships cannot select or access their former tenant.
- Tenant administrators cannot remove their own administrator access or the
  last effective tenant administrator.
- Platform administrator membership is managed only at platform scope.
- User creation and membership changes write tenant-attributed audit events.

## OIDC readiness

The database can bind an internal user to a unique OIDC issuer and subject.
This is the stable identity bridge intended for Keycloak. It deliberately does
not store tokens or client secrets. Provider configuration, login redirects,
claim mapping, logout, and session revalidation must be implemented and
accepted separately before Keycloak authentication is enabled.

See [ADR-0009](../architecture/ADR-0009-IDENTITY-RBAC-AND-OIDC.md) for the full
boundary.
