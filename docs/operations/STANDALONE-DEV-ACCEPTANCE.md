# Standalone Development Acceptance

## Current Application Acceptance Update

- Date: 2026-08-31
- Application version: `0.1.12`
- Accepted release: `19442a75e321d97521343fe3ab8383dce2f3e736`
- Scope: BMC enrollment certificate path, visible application version, and
  immutable standalone deployment

The accepted release added a dedicated `ipms-certificate-probe` service. The
Control Plane retains localhost-only network access and reaches the helper
through an authenticated, bounded localhost request. The helper runs without
database credentials or the connector master key and permits only localhost
and private address ranges.

Deployment acceptance established:

- the active release link resolved to the exact accepted commit;
- the API information endpoint reported `application_version` `0.1.12`;
- PostgreSQL, the certificate helper, Control Plane, Web Console, connector
  timer, nginx, and Fail2ban were active with zero failed systemd units;
- API readiness and Web Console health succeeded;
- the Control Plane systemd network policy remained localhost-only;
- each probe environment contained exactly one token assignment after the
  installer normalized a legacy duplicate-entry condition; and
- a read-only live probe through the restricted Control Plane boundary reached
  an existing connector, returned a certificate fingerprint, and correctly
  reported that the development certificate was not trusted by the system.

The acceptance probe did not submit credentials, enroll another endpoint,
rotate a credential, remove a connector, or perform a state-changing BMC
operation. Interactive enrollment of another target remains an operator
acceptance step.

Verification for this update included 67 Django tests, installer Bash syntax,
the pinned Next.js production build, TypeScript validation inside that build,
API health, service health, systemd network-policy inspection, and the isolated
live certificate request. Public evidence excluded endpoints, credentials,
tokens, fingerprints, certificate contents, and raw device responses.

## Initial Appliance Acceptance Record

- Date: 2026-08-30
- Accepted release: `891b85826c4b2fddf6d734343cde55e749bb4810`
- Target class: hardened Ubuntu 26.04.1 LTS development appliance
- Deployment model: single-node, immutable application release with persistent
  state below `/srv/ipms`

This record intentionally omits hostnames, addresses, credentials, certificate
fingerprints, storage identifiers, and raw operational logs.

## Installed Runtime

- Node.js 24.20.0 and pnpm 11.24.0
- Next.js 16.3.3 and React 19.2.8
- Python 3.14.4, Django 6.1, and Gunicorn 26.2.0
- PostgreSQL 18.6
- nginx 1.28.3
- Fail2ban 1.1.0

The Node.js archive was verified against its official SHA-256 manifest before
installation. JavaScript and Python application dependencies are pinned by the
repository lockfile and Python project metadata.

## Verified Controls

- The active `/srv/ipms/current` link resolves to the accepted immutable
  release.
- PostgreSQL, the Control Plane, the Web Console, nginx, and Fail2ban are
  enabled and active.
- No failed systemd units or application restart loops were present.
- Only SSH and HTTPS listen on non-loopback addresses.
- PostgreSQL, Gunicorn, and Next.js listen on loopback only.
- UFW permits SSH and HTTPS only from the selected management source.
- PostgreSQL stores its data below `/srv/ipms/data/postgresql`.
- Runtime environment files, generated database credentials, the initial
  administrator credential, and the TLS private key have restrictive ownership
  and modes. Their contents were not included in acceptance evidence.
- Both the direct Control Plane readiness check and the nginx HTTPS readiness
  check returned `{"status":"ok"}`.
- An authenticated request to the Web Console root returned HTTP 200 and the
  expected tenant dashboard without redirects. Internal Next.js requests carry
  the trusted HTTPS forwarding signal required by Django production security.
- The login response includes a nonce-based script policy, explicit style
  attribute policy, frame denial, object denial, a same-origin referrer policy,
  a restrictive permissions policy, and content-type sniffing protection.
- Fail2ban's SSH jail is active.
- No operating-system package updates were pending after installation.
- No warning-or-higher application or nginx journal entries were present in the
  final post-deployment observation window.

## Verification Results

- Django test suite: 26 tests passed, including the internal HTTPS proxy
  regression test.
- Web Console lint: passed.
- Web Console TypeScript check: passed.
- Web Console production build: passed.
- Installed HTTPS Edge smoke test: passed, including anonymous redirect,
  rendered sign-in controls, CSRF bootstrap, missing-resource detection, and
  browser console/page error detection.
- Earlier isolated browser acceptance covered authenticated tenant selection,
  tenant-scoped dashboard rendering, dark/light themes, invalid-credential
  handling, and automated critical accessibility checks.

## Deliberate Development Exceptions

- The development certificate is self-signed and expires after 90 days.
- HSTS remains disabled while the self-signed certificate is in use. Customer
  and production deployments require a trusted certificate and the reviewed
  HSTS policy.
- The one-time administrator password was generated on the appliance and was
  never printed by the installer. Live authenticated acceptance requires an
  administrator to retrieve it through the verified SSH channel, sign in, set
  a new password, and remove the one-time credential file.
- The bootstrap application username defaults to `admin`; its password remains
  unique and randomly generated for every installation. A shared static
  password is not an accepted deployment mode.
- Full clean-VM reinstallation acceptance remains deferred until a separate
  disposable VM is available.

## Remaining v0.1.0 Scope

The initial deployment proved the Web Console, tenant-aware authentication
foundation, live Control Plane data path, and standalone runtime. The current
`0.1.12` deployment additionally proves the isolated BMC certificate path and
the existing read-only iLO connector path. It does not complete Hyper-V
discovery, customer certificate lifecycle, licensing, scale-out deployment, or
the deferred clean-VM installation acceptance. Their milestone issues remain
open.
