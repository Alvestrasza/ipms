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

Then open `http://127.0.0.1:3000`. The initial interface contains an explicit
preview dataset and does not accept credentials or execute infrastructure
actions.

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
