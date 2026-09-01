# Windows Server Inventory Preparation

## Scope

IPMS `0.1.24` provides tenant-scoped read-only portal inventory and detail
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
optional `server_type=physical|virtual|unknown` query parameter supports the
separate portal views. `GET /api/v1/windows-servers/{id}/` returns one selected
tenant record for the detail page. Neither endpoint has a browser-facing
create, update, or delete method, and a cross-tenant identifier returns `404`.

The normalized record prepares these fields:

- stable source identity and source type (`agent` or `hyper-v`);
- physical, virtual, or not-yet-classified server type;
- hostname, FQDN, domain, operating-system version, build, and architecture;
- manufacturer, model, serial number, and system UUID;
- logical processor count and total memory;
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

## Current acceptance boundary

The following are accepted through `0.1.24`:

- localized physical and virtual Windows Server navigation;
- live empty states that distinguish unavailable data from an empty inventory;
- summary and table layouts for Agent, health, CPU, memory, hardware, and
  Hyper-V placement;
- read-only system detail pages for identity, platform, resources, Agent state,
  inventory source, Management Packs, and timestamps;
- a tenant-filtered read-only list and detail API and database migration; and
- negative API coverage for cross-tenant access and browser writes.

Hyper-V collection, search, lifecycle operations, and production support remain
future work.
