# Windows Server Inventory Preparation

## Scope

IPMS `0.1.51` provides tenant-scoped read-only portal inventory and detail
views for physical and virtual Windows systems. Native Agent enrollment and
bounded inventory ingestion are available; Hyper-V provider discovery and all
state-changing Windows or virtualization operations remain outside this
release.

The Web Console routes are:

- `/{locale}/physical/servers` for physical Windows systems;
- `/{locale}/physical/servers/{id}` for one physical system;
- `/{locale}/virtual` for virtual Windows systems and their future Hyper-V
  placement; and
- `/{locale}/virtual/{id}` for one virtual system.

Both routes are server-rendered, require an authenticated tenant selection,
and use the same Control Plane inventory contract.

## Normalized inventory

`GET /api/v1/windows-servers/` returns only the selected tenant's records. The
optional `server_type=physical|virtual|unknown` and exact `role=<technical-name>`
query parameters support the separate portal and installed-role views.
`GET /api/v1/windows-server-roles/` returns bounded physical and virtual server
counts for every installed top-level role in the selected tenant.
`GET /api/v1/windows-servers/{id}/` returns one selected tenant record for the
detail page. None of these endpoints has a browser-facing create, update, or
delete method, and a cross-tenant identifier returns `404`.

The normalized record prepares these fields:

- stable source identity and source type (`agent` or `hyper-v`);
- physical, virtual, or not-yet-classified server type;
- hostname, FQDN, domain, operating-system version, build, and architecture;
- manufacturer, model, serial number, and system UUID;
- logical processor count and total memory;
- bounded Windows network-interface configuration;
- installed Windows Server roles, role services, and features, with explicit
  collected, unavailable, or not-yet-reported state;
- Hyper-V cluster and host placement;
- Agent version, connection state, management-pack state, and last-seen time;
  and
- normalized health and discovery timestamps.

Unnormalized provider data remains internal and is not returned by the list
API. Tenant identity is derived from the authenticated selected-tenant boundary,
never from a browser-supplied inventory document.

## Ingestion boundary

The native `windows-server-core` Management Pack populates bounded
operating-system and host inventory through Agent-initiated mTLS. Enrollment,
certificate-bound tenant identity, sequence validation, and durable Control
Plane ingestion remain mandatory. The `hyper-v-host` Management Pack will add
host, cluster, virtual-machine, and virtual-network observations after its
separate provider and fixture acceptance.

Agent and Hyper-V ingestion must use an internal authenticated service, validate
tenant and device identity, normalize bounded fields, reject stale sequences,
and write audit attribution. It must not reuse the public list endpoint or add
an arbitrary command, PowerShell, script, shell, or remote-execution channel.

The Agent reads installed roles and features directly from
`MSFT_ServerFeature` in `Root\Windows\ServerManager`, requesting only provider
state `1` (installed). It does not run `Get-WindowsFeature` or any other
PowerShell command. The Control Plane accepts no more than 512 unique entries,
validates their exact schema and type, stores them on the certificate-bound
tenant record, and projects top-level roles into an indexed read model. Role
services and features remain available on the tenant-scoped detail API but do
not create navigation entries.

Agent 0.1.36 allows the Server Manager provider up to one bounded minute to
complete a cold initialization. Five-second polling slices keep the operation
responsive without turning a slow provider into a false empty inventory. A
provider that still fails or exceeds the overall deadline remains explicitly
`unavailable`.

## Current acceptance boundary

If collection is unavailable, Agent 0.1.36 also reports one bounded reason code.
The portal translates this code into an operator-facing explanation without
publishing raw provider errors, host data, commands, or stack traces.

When that provider is absent, Agent 0.1.36 reads the installed server-feature
inventory from the local Windows system. Documented top-level server-role IDs
are classified as roles, their descendants as role services, and all remaining
entries as features. Generated technical identifiers remain stable across UI
languages while Windows supplies the localized display names.

The following are accepted through `0.1.51`:

- localized physical and virtual Windows Server navigation;
- live empty states that distinguish unavailable data from an empty inventory;
- summary and table layouts for Agent, health, CPU, memory, hardware, and
  Hyper-V placement;
- read-only system detail pages for identity, platform, resources, Agent state,
  inventory source, Management Packs, and timestamps;
- a read-only installed roles and features table that distinguishes successful
  empty collection, unavailable collection, and older Agent inventory;
- tenant-scoped, collapsible physical and virtual Windows role navigation with
  per-role server counts and exact server filtering;
- a current-sample-only telemetry surface for CPU, memory, and fixed-volume
  utilization, refreshed by the portal every ten seconds;
- a tenant-filtered read-only list and detail API and database migration; and
- negative API coverage for cross-tenant access and browser writes.

Native provider acceptance on a representative Windows Server 2025 system,
Hyper-V collection, search, lifecycle operations, and production support remain
future work.
