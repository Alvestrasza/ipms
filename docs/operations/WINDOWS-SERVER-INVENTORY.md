# Windows Server Inventory Preparation

## Scope

IPMS `0.1.14` prepares tenant-scoped read-only portal views for physical and
virtual Windows servers. This foundation does not enroll an Agent, accept an
inventory upload, query Hyper-V, or perform a state-changing Windows or
virtualization operation.

The Web Console routes are:

- `/{locale}/physical/servers` for physical Windows servers; and
- `/{locale}/virtual` for virtual Windows servers and their future Hyper-V
  placement.

Both routes are server-rendered, require an authenticated tenant selection,
and use the same Control Plane inventory contract.

## Normalized inventory

`GET /api/v1/windows-servers/` returns only the selected tenant's records. The
optional `server_type=physical|virtual|unknown` query parameter supports the
separate portal views. The endpoint has no browser-facing create, update, or
delete method.

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

## Future ingestion boundary

The native `windows-server-core` Management Pack will populate operating-system
and host inventory only after Agent enrollment, outbound mTLS transport,
assignment verification, sequence handling, and durable Control Plane ingestion
are implemented. The `hyper-v-host` Management Pack will add host, cluster,
virtual-machine, and virtual-network observations after its separate provider
and fixture acceptance.

Agent and Hyper-V ingestion must use an internal authenticated service, validate
tenant and device identity, normalize bounded fields, reject stale sequences,
and write audit attribution. It must not reuse the public list endpoint or add
an arbitrary command, PowerShell, script, shell, or remote-execution channel.

## Current acceptance boundary

The following are prepared in `0.1.14`:

- localized physical and virtual Windows Server navigation;
- live empty states that distinguish unavailable data from an empty inventory;
- summary and table layouts for Agent, health, CPU, memory, hardware, and
  Hyper-V placement;
- a tenant-filtered read-only API and database migration; and
- negative API coverage for cross-tenant access and browser writes.

Agent enrollment, real inventory ingestion, Hyper-V collection, server detail
pages, search, lifecycle operations, and production support remain future work.
