# Web Console Architecture

## Purpose

The IPMS Web Console is a self-hosted Next.js presentation layer. Django is the
authoritative Control Plane for identity, sessions, tenant access, audit, and
infrastructure data. The browser never receives database credentials,
connector credentials, certificate private keys, or a privileged service
token.

## Request Flow

1. The browser connects to one HTTPS origin exposed by the reverse proxy.
2. `/api/v1/` requests are routed to the Django Control Plane; all other
   application routes are routed to Next.js.
3. Django issues the HttpOnly session and CSRF cookies and returns a minimal
   session projection.
4. Next.js performs a server-side session check before rendering the console.
5. The selected tenant ID is carried as `X-IPMS-Tenant-ID` on every scoped API
   request.
6. Django validates the current user, membership, tenant status, and selected
   tenant before applying a tenant filter to the query.

The tenant preference cookie improves navigation only. It does not grant
access. Platform administrators must select a tenant too, so an unrestricted
query is never the default.

## Current Read-Only Data

The overview consumes live Control Plane readiness, tenant-scoped discovery
jobs, BMC-managed hardware, and Agent-reported physical and virtual Windows
inventory. Summary cards distinguish physical systems, virtual machines,
enrolled BMC endpoints, and restore points. The health distribution and
attention table combine all currently managed inventory records and link each
record to its appropriate detail view.

The product surface uses capability and vendor terminology such as BMC, iLO,
iDRAC, Hyper-V, and API. Connector transport protocols, internal model names,
resource identifiers, and compatibility-profile identifiers are implementation
details. They must not be rendered by the Web Console or returned by public API
and CSV projections. Internal identifiers may remain stable where changing them
would require a data migration, but serializers must translate and sanitize
them at the trust boundary.

The console does not substitute preview or cached numbers when the Control
Plane is unavailable.

Connector activity reflects only the latest discovery-job outcome. It is not
yet a full connector-health or managed-device-health signal.

## Browser Security

- A per-request nonce Content Security Policy limits scripts and styles.
- `frame-ancestors 'none'`, `object-src 'none'`, restrictive Referrer Policy,
  Permissions Policy, and MIME sniffing protection are applied by Next.js.
- Session, CSRF, and tenant-preference cookies are HttpOnly. Deployment cookies
  are Secure and SameSite=Lax.
- Login and logout are CSRF protected and authentication failures do not reveal
  whether an account exists.
- Authentication events are written to the append-only audit model.

The external reverse proxy still owns TLS policy, request-size limits, login
rate limiting, connection timeouts, and public exposure. Next.js and Django bind
only to loopback or a private application network.

## Localization

The console supports English and German from the first read-only release. All
console pages live below an explicit locale segment such as `/en/login`,
`/de/login`, `/en`, or `/de`. The localized URL is authoritative for rendering,
metadata, navigation, and links.

Unprefixed requests are redirected in this order:

1. A validated `ipms_locale` preference cookie.
2. The browser `Accept-Language` header, normalized to a supported base
   language.
3. English as the deterministic fallback.

The routing proxy synchronizes every explicit locale to a Secure, HttpOnly,
SameSite=Lax preference cookie. The language selector replaces only the locale
path segment and preserves the remaining route, query, and fragment. Locale
selection never participates in authentication, authorization, tenant
filtering, or licensing decisions.

Translation dictionaries live in source control and are type-checked against
the English key set. User-provided names and infrastructure values are never
translated. Locale-sensitive presentation such as timestamps uses the resolved
locale while operational timestamps remain stored and transferred in UTC.

## Scale-Out Considerations

All web instances must use one build artifact and deployment identifier. Any
Server Action encryption key must be shared. Django session storage and tenant
data remain in PostgreSQL. If Next.js caching is introduced, tag invalidation
and cache storage must be shared across instances; tenant-specific responses
must never use a public cache.
