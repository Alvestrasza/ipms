# Standalone Development Acceptance

## Acceptance Record

- Date: 2026-08-30
- Accepted release: `aee04fc6a987412ee4fba2d4aeb721d04d14a66c`
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
- The login response includes a nonce-based script policy, explicit style
  attribute policy, frame denial, object denial, a same-origin referrer policy,
  a restrictive permissions policy, and content-type sniffing protection.
- Fail2ban's SSH jail is active.
- No operating-system package updates were pending after installation.
- No warning-or-higher application or nginx journal entries were present in the
  final post-deployment observation window.

## Verification Results

- Django test suite: 25 tests passed.
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
- Full clean-VM reinstallation acceptance remains deferred until a separate
  disposable VM is available.

## Remaining v0.1.0 Scope

This deployment proves the Web Console, tenant-aware authentication foundation,
live Control Plane data path, and standalone runtime. It does not complete the
inventory API, iLO discovery, Hyper-V discovery, customer certificate lifecycle,
licensing, or scale-out deployment. Their milestone issues remain open.
