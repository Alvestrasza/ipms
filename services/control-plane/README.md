# IPMS Control Plane

This service is the security and policy boundary for IPMS. It owns tenant
isolation, authorization, licensing, audit events, durable jobs, and the public
API. The web console, agents, and connectors must not bypass it.

## Current Scope

The initial scaffold provides:

- environment-specific, fail-closed Django settings;
- PostgreSQL-first configuration;
- versioned liveness, readiness, and API-information endpoints;
- a tenant domain model;
- audited session login/logout endpoints and explicit user-to-tenant membership;
- an append-only audit-event domain model; and
- tenant-scoped connector endpoints, physical-system inventory, and durable
  discovery jobs with read APIs;
- a certificate-pinned, session-scoped iLO Redfish connector that rejects
  managed-infrastructure write methods; and
- portal-only iLO enrollment with tenant-administrator authorization,
  AES-256-GCM credential storage, and a separately sandboxed queue worker; and
- request correlation and a common API error envelope; and
- tests for endpoint policy and model invariants.

External identity-provider and tenant-management APIs are not yet implemented.
The iLO enrollment endpoint creates read-only discovery jobs but no endpoint in
this scaffold changes managed infrastructure.

## Local Development

Python 3.14 is required. Create a virtual environment and install the project:

```shell
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
```

On Windows, use `.venv\\Scripts\\python.exe` instead.

Copy `.env.example` to a secret, untracked environment file or export the
variables through the process manager. Django does not load `.env` files by
itself. Never commit the secret key or database password.

Run the checks and tests:

```shell
python manage.py check --settings=ipms_control_plane.settings.test
python manage.py test ipms.apps.core ipms.apps.tenancy ipms.apps.audit \
  ipms.apps.discovery \
  --settings=ipms_control_plane.settings.test
```

Development runtime requires PostgreSQL. SQLite exists only in the explicit
test settings so that fast unit tests do not silently redefine the supported
deployment database.

## Public Endpoints

- `GET /api/v1/` returns non-sensitive API identity and version information.
- `GET /api/v1/health/live/` confirms that the application process can serve a
  request.
- `GET /api/v1/health/ready/` confirms database connectivity without exposing
  connection details.
- `GET /api/v1/auth/session/` bootstraps CSRF protection and returns the minimal
  authenticated user and authorized-tenant projection.
- `POST /api/v1/auth/login/` and `POST /api/v1/auth/logout/` use Django's
  server-side session framework, CSRF protection, generic failure responses,
  and append-only authentication audit events.
- `GET /api/v1/discovery-jobs/` and `GET /api/v1/discovery-jobs/{id}/` expose
  read-only status for the tenant selected through `X-IPMS-Tenant-ID`.
- `GET /api/v1/connectors/` exposes a redacted tenant-owned connector
  projection without credential references or certificate pins.
- `POST /api/v1/connectors/bmc/certificate/` probes the endpoint certificate
  and returns a short-lived, tenant-bound trust decision.
- `POST /api/v1/connectors/bmc/` enrolls a BMC and queues its first read-only
  discovery for tenant or platform administrators. Credential and trust-token
  fields are write-only.
- `POST /api/v1/connectors/{id}/credentials/` rotates an encrypted credential;
  `DELETE /api/v1/connectors/{id}/` destroys it and archives the endpoint.
- `GET /api/v1/bmc-logs/` and `/api/v1/bmc-logs/export/` expose bounded,
  tenant-scoped, sanitized communication metadata and CSV export.
- `GET /api/v1/physical-systems/` exposes normalized tenant-owned hardware
  inventory, including the versioned system-overview snapshot, without raw
  Redfish payloads.

`IPMS_BMC_CONNECT_TIMEOUT_SECONDS` sets the bounded timeout for certificate and
Redfish HTTPS exchanges. It defaults to `20` and accepts values from `5` to
`60`; invalid or out-of-range values prevent Control Plane startup.

Platform administrators must also select one tenant. Tenant members can select
only active tenants for which their membership is active. Inaccessible tenants
and cross-tenant object identifiers return `404` so the API does not confirm
their existence.

Every future API is authenticated by default. Public access must be declared
on the individual view and covered by a policy test.

The `ipms_control_plane.settings.e2e` module exists only for isolated browser
tests with a disposable SQLite database. It must never be selected in an IPMS
deployment; development and production remain PostgreSQL-only.

## Security Boundaries Still Required

The model layer is only one control. Production tenant isolation also requires
PostgreSQL Row-Level Security, tenant-scoped repository/query services,
authorization tests, restricted database roles, and negative cross-tenant
tests. The audit model blocks ordinary ORM updates and deletes, but database
permissions and append-only database controls remain required before release.

The appliance bootstrap uses `admin` as its default initial username and a
unique randomly generated one-time password. Static product passwords such as
`admin` are forbidden.
