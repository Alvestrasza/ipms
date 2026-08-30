# IPMS Web Console

The IPMS Web Console is the tenant-aware presentation layer for the Django
Control Plane. It never connects directly to PostgreSQL, agents, connectors,
or managed infrastructure.

## Baseline

- Node.js 24
- Next.js 16 with the App Router
- React 19
- TypeScript
- A-Corp Dark as the default theme and semantic A-Corp Light tokens
- Playwright and axe-core browser checks
- Biome linting and formatting checks; ESLint is deferred because the current
  Next.js plugin chain does not yet accept the supported ESLint 10 line

Exact dependency versions are recorded in `package.json` and `pnpm-lock.yaml`.
The supported runtime range remains separate from the lock so patch updates can
be tested without redesigning the application.

## Development

```shell
pnpm install --frozen-lockfile
pnpm dev
```

Set `IPMS_CONTROL_PLANE_URL` to the private Django origin, then open
`http://127.0.0.1:3000`. Development rewrites keep browser traffic same-origin;
the deployed reverse proxy owns `/api/v1/` routing. The overview uses live
Control Plane readiness and tenant-scoped discovery jobs. Inventory remains an
honest empty state until the read-only connectors populate normalized data. No
current console action changes managed infrastructure.

## Validation

```shell
pnpm lint
pnpm typecheck
pnpm build
pnpm test:e2e
```

The production build uses Next.js standalone output for the Appliance and
future Scale-Out packaging.

## Security Boundary

Browser-visible environment variables, static assets, and API responses must
never contain connector credentials, certificate private keys, database
credentials, or privileged backend tokens. Authentication and tenant
authorization decisions remain authoritative in the Django Control Plane.

The console uses Django's HttpOnly session cookie and CSRF token bootstrap.
Tenant selection is stored in a separate HttpOnly preference cookie, but it is
never trusted for authorization: every tenant-scoped API call carries the
selected tenant ID and the Control Plane validates current access again.
