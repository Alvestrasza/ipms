# ADR-0012: Separate Platform and Tenant Administration

- Status: Accepted; implementation acceptance tracked separately
- Date: 2026-09-05
- Application target: 0.2.33
- Supersedes: the platform-to-tenant authority exceptions in ADR-0009

## Decision

An IPMS platform administrator manages the product and tenant metadata, not
customer infrastructure. Platform authority is an explicit, separate principal
marker, not a tenant role and not Django staff or superuser status. Platform
principals must have no tenant membership. Authorization also rejects such
memberships if invalid historical data exists.

| Principal | Permitted scope | Explicitly excluded |
| --- | --- | --- |
| Platform administrator | Tenant creation, metadata, suspension/reactivation, one-time initial administrator provisioning | Tenant inventory, credentials, console sessions, Agent and VM operations |
| Tenant administrator | Assigned tenant's users, Service Accounts, inventory and permitted operations | Platform administration and other tenants |
| Other tenant roles | Explicit effective permissions in assigned active tenants | Implicit rights from UI navigation or Django flags |

The browser receives separate platform permissions and an empty tenant list for
a platform account. Its platform shell makes no operational inventory requests.
Direct operational URLs, tenant query strings and old selection cookies do not
restore tenant access. The API remains the authorization authority. The generic
Django administration route is not exposed.

## Tenant lifecycle and initial administration

The initial management surface creates tenants, edits display names and changes
active/suspended status. Slugs are immutable. No hard-delete or automatic data
purge is provided.

A new tenant has no implicit member. The platform administrator may explicitly
provision its first, separate local tenant-administrator principal by submitting
a new username and a validated initial password. This is bootstrap authority,
not ongoing credential-reset or impersonation authority. The API never returns
the password and does not authenticate the platform session as that new user.
Subsequent user administration belongs to the tenant.

One-time initialization is recorded durably. Disabling or expiring an existing
tenant administrator must not reopen the bootstrap path. Existing independent
administrator history counts as initialization during migration. Lost access
after initialization requires a separately authorized recovery procedure.

Last-administrator checks and membership changes are serialized on the tenant
row with PostgreSQL `NO KEY UPDATE`. Only active, unexpired, non-platform
principals count. The weaker row lock preserves foreign-key insertion paths
without reversing existing enrollment/session lock order.

## Services and credentials

Service Accounts remain owned by exactly one tenant and may be assigned only to
hosts in that same tenant. Tenant selection establishes ownership at creation;
accounts are not moved across customer boundaries and secrets are not shared
across tenants. The platform administrator does not read or manage these
credentials. Additional account purposes, service entitlements and per-service
write policies remain separate future features.

Creating tenant metadata does not provision Agent trust material. The current
managed-PKI and gateway export workflow remains a separate setup step; a tenant
row must never be described as a fully connected customer environment. Hosted
multi-tenant gateway trust registration still requires explicit design and
acceptance.

## Suspension and outstanding work

Suspension retains data but denies tenant sessions and new operational work.
Agent identity and message processing must recheck tenant status, including
messages on established connections. Workers and assignment delivery must
revalidate authorization before starting or offering work. Reactivation does
not replay work that was cancelled or denied.

An action already accepted by a remote system cannot be recalled merely by a
database status change. In-flight operations may finish, and reporting their
outcome is distinct from authorizing another operation. This limitation must be
visible to administrators; suspension is not an emergency network kill switch.
The Agent listener and permanent TCP 9419 firewall policy remain unchanged.

## Upgrade and rollback

Legacy platform principals are migrated to the explicit marker, their Django
staff/superuser flags cleared, and their memberships removed. Password hashes
are preserved. No default tenant credentials are generated or copied.

A tenant without prior independent administration is shown as needing its first
administrator. The existing platform login remains usable for that explicit
setup workflow. Customer operations require a separate tenant login afterward.

Reverting application code must not restore broad staff privileges or removed
memberships. The identity data migration is not reversed. A downlevel release
therefore cannot administer the platform with the migrated principal; forward
recovery is required. Stop old web, worker, Gateway and broker processes during
the security migration so old authorization code cannot serve mixed-state
traffic. Preserve protected backups, but do not restore an old application
database over newly collected inventory as routine rollback.

## Verification requirements

Required evidence includes API and browser scope separation, CSRF and secret
non-disclosure, one-time provisioning, last-admin protection, migration from a
legacy bootstrap account, downlevel fail-closed behavior, PostgreSQL locking,
suspension/queue/message fencing, and unchanged Agent versions/network exposure.
Application tests, DEV service health and real customer acceptance are distinct
evidence levels. See [Tenant administration](../operations/TENANT-ADMINISTRATION.md).

Framework references: [Django authentication and authorization](https://docs.djangoproject.com/en/6.1/topics/auth/default/)
and [row-lock semantics](https://docs.djangoproject.com/en/6.1/ref/models/querysets/#select-for-update).
