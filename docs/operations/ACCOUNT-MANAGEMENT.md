# Local Account Management

Application target: **0.2.34**. Agent packages and the permanent TCP 9419 policy
are unchanged. Verification and DEV deployment status are recorded separately.

## Portal workflows

Select your user identity in the top bar to open **My account**. This page is
available to authenticated platform and tenant users, including users without an
active tenant. It never grants access to tenant inventory.

- **Rename:** enter a new login name and your current password.
- **Change password:** enter your current password and confirm the new password.

Tenant administrators additionally use **Administration > Users** to rename or
reset another eligible local user's password. The confirmation password is the
administrator's own password, not the target user's password. Use **My account**
for your own password change rather than the administrative reset action.

New passwords must have at least 12 characters and pass the configured password
validators. No password or hash is returned in API responses, audit records or
browser persistence. An administrative reset does not activate a disabled user,
change tenant membership or create platform rights. A reset password is not
automatically single-use; forced first-login rotation is not part of this feature.

## Identity boundaries

Login identities are global, whereas memberships and administrative authority
are tenant-scoped. A tenant administrator cannot rename or reset an identity that
also has a membership in another tenant, including disabled or expired
memberships. That user can change his own credentials using **My account**.
Platform accounts cannot administer tenant credentials.

Accounts with an active external identity binding, including hybrid accounts,
are excluded from these local credential mutations. This avoids overriding a
future identity provider's authority; Keycloak integration is still separate.

Old normalized login names remain permanently reserved after renaming, including
against renaming back. Existing audit records retain the name used at the time.
Case-only changes of the current name are permitted. Name reservations prevent a
later account from inheriting historical username-based operational authority.

## Sessions and queued work

Changing or resetting a password invalidates all previous login sessions through
Django's session-authentication hash. Own password change also logs out the
current browser; sign in again with the new password. A reset does not log out the
administrator who performed it. See [Django session invalidation](https://docs.djangoproject.com/en/6.1/topics/auth/default/#session-invalidation-on-password-change).

Renaming retains the authenticated browser session because the internal user ID
does not change. Both renaming and password changes close that user's open VM
consoles and withdraw outstanding operational authority. Queued jobs are cancelled
or failed; already delivered/running Agent or VM jobs may report their result but
are not offered again. Completed jobs and historical audit records are preserved.
Already accepted remote work cannot be recalled or rolled back by a credential
change. A request already executing may finish; session invalidation applies to
subsequent authentication checks.

The standalone reverse proxy bounds credential-changing request bodies to 8 KiB
and rate-limits the fixed mutation routes per source address. A rate-limit
response is 429 with a safe error code and Retry-After. Other deployment
topologies must retain equivalent ingress controls. Do not automatically retry a
credential change after an ambiguous timeout.

## Upgrade and recovery

The additive migration reserves existing normalized usernames and rejects
collisions instead of silently choosing an owner. Stop old request handlers and
workers during cutover. Preserve a protected database/configuration backup and
use the exact-target `scripts/deploy-account-management-dev.sh` helper.

The existing persistent security-cutover fence and process-lifetime lock remain
in use. After migration starts, recover with a compatible forward release. Old
code does not enforce retired-name reservations; switching back to 0.2.33 after
renaming would reintroduce name-reuse risk. Do not discard name reservations or
restore old identities to work around this guard.

## Verification status

Verified against the candidate source with Python 3.14:

- PostgreSQL: all 331 backend tests pass, including real concurrent name claims,
  stale-session authority and membership races.
- SQLite: 331 tests complete successfully with seven PostgreSQL-only skips.
- Migration drift check and installed dependency check pass.
- Six inert cutover/recovery tests pass for each of the old and new helpers.
- The tracked nginx configuration passes an isolated loopback test: all four
  mutation routes share the limit, return safe JSON/Retry-After on 429, and leave
  account reads available. No live upstream or credential is used.
- Independent source review covers identity boundaries, permanent reservations,
  queued authority, session handling and the exact-target forward-only cutover.
- Frontend: 42 Node tests, TypeScript, Biome (128 files) and the 44-page
  production build pass. The integrated browser suite passes all 22 scenarios;
  a separate two-case run adds keyboard/scroll coverage for the long reset
  dialog (23 unique scenarios in total). German/English dialogs and screenshot
  layout were inspected. No real identity or remote system was mutated.

Initial verification caught an omitted API version bump and stale PostgreSQL
statistics in two new concurrency-test probes; both were corrected before the
successful full runs. A legacy password-hash regression additionally verifies
that confirmation alone does not rewrite the actor's hash or log him out.
One earlier browser run reported a completed platform edit followed by a failed
list refresh. The diagnostic rerun passed with all related GET responses 200 and
no backend exception; this remains an unreproduced transient, not a claimed
product fix.

The existing cutover helper readiness SQL does not cover
all historical/marker states, so the DEV preflight independently verifies every
historically initialized tenant has an effective non-platform administrator.

## DEV deployment evidence - 2026-09-06

Implementation commit `89ecd396e23f01a81b1499c2434b941bd9bd2fcc` is published and
running on the established DEV appliance as application **0.2.34**. This is not
customer or production acceptance.

- The exact-target helper built the candidate before the maintenance window,
  verified quiescence, created a protected database/configuration backup, applied
  migration `0005`, checked nginx, switched the release and restored services.
- Pre/post comparison confirmed unchanged usernames, password hashes, account
  flags, memberships and platform markers. Existing names have reservations.
- A real HTTPS/CSRF login verified the account API, German account page and
  tenant-user capability flags without any username/password mutation. Only the
  newly created smoke-test session was logged out.
- Actual broker process identity, secret-file isolation, Unix socket and its
  restricted PostgreSQL permission matrix passed. The synthetic permission
  probe's audit insert was rolled back and absence was confirmed.
- Anonymous account/administration APIs remain denied; Django admin remains
  unavailable. Services are healthy and the persistent cutover fence is clear.
- Agent packages, global IPv4/IPv6 firewall allowances for TCP 9419 and the
  loopback-only native console broker binding are unchanged. The isolated
  PostgreSQL test database was removed by the test runner.

The first transfer preflight rejected Windows archive line endings before any
live action; generating the archive with `git -c core.autocrlf=false archive`
resolved that packaging issue. The existing Django deployment check still emits
`security.W004` because HSTS is not configured; this account feature does not
change the appliance TLS/HSTS policy. Customer acceptance, PostgreSQL RLS,
Keycloak integration and forced first-login password rotation remain separate.
