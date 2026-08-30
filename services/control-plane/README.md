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
- an append-only audit-event domain model; and
- a durable discovery-job model with a platform-admin-only read API;
- request correlation and a common API error envelope; and
- tests for endpoint policy and model invariants.

Inventory, connector, identity-provider, and tenant-management APIs are not yet
implemented. Discovery-job creation is reserved for the future internal job
engine. No endpoint in this scaffold changes managed infrastructure.

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
- `GET /api/v1/discovery-jobs/` and `GET /api/v1/discovery-jobs/{id}/` expose
  read-only job status to authenticated platform administrators.

Every future API is authenticated by default. Public access must be declared
on the individual view and covered by a policy test.

## Security Boundaries Still Required

The model layer is only one control. Production tenant isolation also requires
PostgreSQL Row-Level Security, tenant-scoped repository/query services,
authorization tests, restricted database roles, and negative cross-tenant
tests. The audit model blocks ordinary ORM updates and deletes, but database
permissions and append-only database controls remain required before release.
