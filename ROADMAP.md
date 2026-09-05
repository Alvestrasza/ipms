# IPMS Product Roadmap

## Purpose

IPMS (Independent Platform Management System) is a proprietary, multi-tenant
infrastructure management platform by Alvestrasza Corporation. It provides one
web console for physical infrastructure, virtual machines, monitoring,
networks, storage, and backup operations.

This roadmap defines the intended product direction. It is not a delivery
commitment, release schedule, or customer contract.

## Product Principles

- Build IPMS as a secure control plane, not as unrestricted remote shell access.
- Enforce tenant isolation in the API, data store, job queue, cache, telemetry,
  and audit trail.
- Separate read-only discovery from state-changing operations.
- Require explicit authorization, validation, durable jobs, idempotency, and
  audit records for every state-changing operation.
- Use mutual TLS and narrowly scoped service identities wherever supported.
- Keep customer workloads and backup data in customer environments; IPMS Cloud
  processes inventory, telemetry, backup metadata, and approved control jobs.
- Use a shared platform architecture for standalone and scale-out deployments.
  Standalone is the smallest supported scale-out topology, not a separate
  product.
- Keep proprietary product code closed. Publish only intentionally separated
  extension contracts, SDKs, or examples under their own licenses.

## Deployment Models

### IPMS Appliance

One virtual appliance for smaller customer environments. It hosts the web UI,
API, workers, message bus, transactional database, and initial telemetry
components on a single supported VM.

### IPMS Scale-Out

A customer-operated deployment with multiple management nodes, workers,
message-bus nodes, database nodes, and independently scalable telemetry
storage. It targets larger or highly available customer environments.

### IPMS Cloud

An A-Corp-hosted multi-tenant control plane for smaller customers. A customer
installs an IPMS Edge Agent or gateway in the customer environment. The Edge
Agent establishes an outbound mutually authenticated connection to IPMS Cloud;
the service does not require inbound Internet access to customer systems.

The initial Cloud scope focuses on Hyper-V virtual machine visibility and safe
operations, backup visibility and restore workflows, monitoring, and alerts.

## Target Architecture

```text
Web Console
    |
IPMS API, Identity, RBAC, Tenant Policy, Licensing, Audit, Job Engine
    |
    +-- Management Agents and Edge Gateways (mTLS)
    +-- Hyper-V and Cluster Connector
    +-- Redfish Connector for BMCs and server hardware
    +-- Network Connectors (API, SNMP, SSH)
    +-- Storage Connectors
    +-- Backup Connectors
```

## Technology Baseline and Update Policy

The first IPMS development appliance uses Ubuntu Server 26.04 LTS. As of the
initial architecture decision, the reference baseline is Ubuntu 26.04.1 LTS,
Python 3.14.7, Django 6.1, Next.js 16.3.3 Active LTS, PostgreSQL 18.6, Docker
Engine 29.7.2, and Go 1.27.0.

The baseline is a starting point, not a permanent version freeze. Before every
implementation or release, use the latest supported stable patch version within
the approved compatibility range and review security advisories. Preview,
beta, release-candidate, and end-of-life versions are not permitted in
production.

- Pin exact versions and image digests in reproducible build and deployment
  manifests.
- Maintain supported-version ranges separately from build locks.
- Test framework, database, container, and agent upgrades in CI and a staging
  appliance before customer deployment.
- Record upgrades, compatibility changes, and rollback instructions in release
  notes.
- Keep data migrations backward-compatible for at least one supported release
  transition whenever technically possible.

### Application Stack

- **Control Plane:** Python, Django, and Django REST Framework provide tenant
  policy, authorization, licensing, audit, durable jobs, and the public API.
- **Web Console:** Next.js and TypeScript provide the A-Corp-themed management
  interface. The console has no direct database, agent, or connector access.
- **Data Store:** PostgreSQL stores transactional data. Tenant-aware tables use
  application authorization and PostgreSQL Row-Level Security as complementary
  controls.
- **Agent and Edge Gateway:** C++20 provides native customer-deployed Windows
  and Linux binaries with outbound mTLS connections to the Control Plane.
- **Identity:** OIDC is the integration boundary. Keycloak is the initial
  reference identity provider, while customer OIDC providers remain supported.
  IPMS remains authoritative for tenant memberships and effective permissions;
  external subjects bind through the validated OIDC issuer and subject tuple.
- **Packaging:** Container images are used for Appliance and Scale-Out
  components. Rootless execution, minimal base images, signed images, and
  vulnerability scanning are required before production use.

All privileged write requests terminate at the Django Control Plane. Next.js
is a presentation layer and must not become an independent authorization or
licensing boundary.

## v0.1.0: Read-Only Foundation

Version 0.1.0 establishes a secure, single-appliance foundation and proves the
first two infrastructure connectors. It is deliberately read-only: it must not
change a customer VM, BMC, host, network device, storage system, backup job, or
restore point.

### v0.1.0 Goals

- Deploy IPMS on Ubuntu Server 26.04 LTS as a reproducible single-VM Appliance.
- Scaffold the Django Control Plane, Next.js Web Console, PostgreSQL database,
  container packaging, and CI quality gates.
- Establish tenant model, local platform administrator, audit-event model,
  baseline role model, and API versioning.
- Implement read-only inventory objects for sites, hosts, clusters, VMs, BMCs,
  CPU, memory, storage, network interfaces, and health status.
- Implement a read-only iLO connector using standard Redfish capabilities,
  with isolated iLO 4 Smart Storage and legacy inventory adapters that follow
  only advertised OEM links. Normalize DIMM and PCI/Fibre Channel adapter
  inventory; enrich WWPN and WWNN later through the Hyper-V or Management
  Agent source because the supported iLO 4 REST API does not expose them. All
  vendor-specific extensions remain behind the connector boundary.
- Provide a multilingual portal wizard for tenant-aware BMC enrollment with
  family selection, automatic TLS certificate inspection, explicit approval
  for untrusted certificates, encrypted write-only credentials, and automatic
  background discovery.
- Provide credential rotation, soft removal with credential destruction, and
  tenant-scoped BMC communication metadata with severity and time filters plus
  formula-safe CSV export. Credentials, tokens, headers, message arguments,
  and payload bodies are never retained in communication logs.
- Collect tenant-scoped iLO Event Log and Integrated Management Log records in
  a distinct bounded data model with log-type, severity, BMC, time, and text
  filters plus formula-safe CSV export.
- Provide a tenant-scoped BMC detail page backed by a persisted, versioned
  Redfish snapshot for subsystem health, fans, temperatures, power,
  processors, memory, network, device inventory, storage, firmware, and
  software. Optional resources remain explicitly unknown when not reported.
- Establish tenant-scoped read-only inventory views for physical and virtual
  Windows servers, backed by one normalized API contract for Agent and Hyper-V
  sources. Browser clients cannot create or modify inventory records.
- Separate Windows clients from Windows servers through native operating-system
  role classification while retaining physical or virtual placement as an
  independent dimension. Provide normalized client-family navigation, starting
  with Windows 11 LTSC.
- Establish the dedicated tenant-scoped Agent PKI and isolated TCP 9419 mTLS
  Gateway with one-time pinned enrollment, short-lived device certificates,
  immediate revocation, encrypted runtime issuer keys, offline Root recovery,
  dual-issuer rotation, rollback, and expiry monitoring. Native Agent transport
  integration remains required for end-to-end acceptance.
- Provide a tenant-administrator-only portal bootstrap for Windows systems. A
  dedicated worker may run only the compiled, version-pinned Agent installation
  workflow over administrator-approved HTTPS with certificate inspection and
  pinning. If HTTPS is unavailable, the portal may offer an explicitly approved
  TCP 5985 fallback with mandatory NTLM WS-Man message encryption and a clear
  residual-risk warning. Credentials are encrypted only until the first attempt
  and the path cannot execute operator-supplied scripts or commands.
- Provide a tenant-administrator Agent inventory under **Administration >
  Infrastructure > Agents** with FQDN, derived contact state, operating system,
  installed and target versions, compliance, last contact, and bounded update
  and uninstall actions. After a one-time Agent 0.1.32 bootstrap, routine
  lifecycle jobs use the Agent-initiated mTLS channel, preserve device identity,
  allow only compiled fixed actions, verify the artifact digest twice, roll back
  a failed update, and produce tenant-scoped audit events. Signed manifests,
  Authenticode, MSI packaging, and rollout rings remain customer-release gates.
- Implement a read-only Hyper-V connector for host, cluster, VM, and basic
  resource discovery through the C++20 Windows Agent and its signed,
  built-in `hyper-v-host` Management Pack.
- Present Hyper-V virtual machines with name, state, host, vCPU, RAM, uptime,
  configuration version, and integration-service-reported IP addresses.
- Present discovered inventory and connector health in the A-Corp Dark Web
  Console, with the A-Corp Light token set available from the beginning.
- Provide server-rendered English and German console localization, detect the
  browser language, persist an explicit user preference, and use English as the
  fallback for unsupported or missing language preferences.
- Provide test fixtures or simulators for Redfish and Hyper-V discovery; no
  shared production credentials are used in development or CI.
- Publish installation, bootstrap, security, update, and rollback guidance for
  the Appliance.
- Enforce the deployment-profile encryption, unlock, recovery, rotation, and
  migration policy defined in
  [ADR-0001](docs/architecture/ADR-0001-APPLIANCE-ENCRYPTION-AND-UNLOCK.md).

### v0.1.0 Acceptance Criteria

- A new Appliance can be bootstrapped with the minimum documented inputs.
- An administrator can create an isolated tenant and view only that tenant's
  inventory.
- The iLO connector discovers a supported Redfish endpoint without executing a
  state-changing Redfish request.
- A tenant administrator can enroll and manage the iLO BMC connector in the
  Web Console without console or SSH credential handling, and an untrusted or
  changed certificate cannot be used without an explicit current decision.
- BMC communication logs and exports remain tenant-scoped and contain no
  stored credential, token, header, message-argument, or payload content.
- iLO Event Log and Integrated Management Log views and exports remain
  tenant-scoped and are collected only through read requests.
- The BMC detail page presents the last normalized discovery snapshot without
  issuing live device requests during page or tab navigation.
- The Hyper-V connector discovers an authorized host or cluster and its VMs
  without executing a state-changing management action.
- Every discovery run is attributed to a tenant and produces auditable results.
- The Web Console renders in English or German without changing authentication
  or tenant authorization behavior, and unsupported browser languages fall
  back to English.
- The release build passes dependency, secret, static-analysis, and integration
  checks, and its deployment manifest uses pinned artifacts.

### v0.1.0 Non-Goals

- State-changing VM, iLO, network, storage, backup, or restore operations.
- Generic remote command, PowerShell, script, shell, or operator-provided Agent
  execution. The fixed IPMS Agent update and uninstall lifecycle is the only
  self-management exception.
- Scale-Out migration, customer Cloud tenancy, or a production Edge Gateway
  rollout.
- Full monitoring, backup, network, or storage management.

## v0.2.0: Cross-Platform Inventory and Infrastructure Connectors

Version 0.2.0 extends the tenant-safe read-only foundation without widening the
Agent into a remote administration channel.

### v0.2.0 Goals

- Deliver a native C++20 Linux Agent with the same Agent-initiated TCP 9419
  enrollment, TLS 1.3 mutual authentication, fixed capabilities, inventory,
  telemetry, lifecycle, and tenant-binding rules as the Windows Agent.
- Inventory installed Windows software from machine-wide uninstall
  registration without using `Win32_Product`, and inventory Linux packages
  from the native package database.
- Report bounded Windows and Linux operating-system update posture, including
  collection state, pending updates, pending security updates, last scan, and
  reboot requirement. Update installation is a separate state-changing scope.
- Add a read-only Sophos Firewall connector for appliance, interface, zone,
  route, HA, firmware, health, and supported operational inventory.
- Add a read-only Loadbalancer.org connector for appliance, HA, virtual
  service, real-server, health, version, and supported operational inventory.
- Add SNMPv3-first read-only HPE 5130 and HPE 5900AF Comware 7.1 discovery for
  chassis, firmware, IRF, ports, VLANs, LACP, LLDP, and health counters.
- Reuse encrypted write-only connector secrets, explicit TLS certificate trust,
  tenant-scoped logs, bounded collection, credential rotation, and removal.

### v0.2.0 Security and Acceptance Boundaries

- Agents and connectors expose no arbitrary command, PowerShell, SSH, shell,
  script, WMI-query, API-proxy, configuration-push, or OID-browser capability.
- SNMP switch discovery requires SNMPv3 authentication and privacy; SNMPv1 and
  SNMPv2c are not accepted.
- HTTPS connectors fail closed until the exact certificate is trusted and fail
  again when it changes.
- Fixture, negative, tenant-isolation, payload-bound, timeout, and native build
  tests are required before deployment.
- Live connector acceptance remains pending until a supported endpoint and a
  dedicated read-only credential are provided for each product family.

### v0.2.0 Implementation Checkpoint

Build 0.2.1 provides the native Linux Agent, cross-platform paged software
inventory, Linux package update posture, Windows update-history timestamps,
Windows client classification, Hyper-V VM inventory, and the first constrained
read-only operations for Sophos Firewall, Loadbalancer.org ADC, and HPE
Comware 7.1 devices. Connector credentials are encrypted and write-only; HTTPS
certificates require an explicit current trust decision and Comware requires
SNMPv3 authPriv.

The following compatibility work remains an acceptance requirement rather than
an implemented claim: live validation on every supported vendor/firmware
combination, Sophos route and HA normalization, Loadbalancer.org HA and virtual
service normalization, and Comware IRF, VLAN, LACP, LLDP, and health-counter
normalization. Windows software inventory deliberately reports update state as
unknown until a bounded, non-triggering Windows Update source is implemented;
it does not start an update scan merely to populate inventory.

Build 0.2.12 provides controlled Hyper-V workload mutations: tenant
administrators can start, pause, resume, gracefully shut down, or stop a
virtual machine from its context menu. The Control Plane creates a tenant-bound
durable job, the enrolled host Agent accepts only the five compiled-in actions
for a normalized VM GUID, resolves provider identity variations from local
object paths, requires the recorded VM name to agree, and audits every request,
delivery, and result.
Graceful shutdown uses the Hyper-V guest shutdown integration service
without forcing applications to close. Stop remains an immediate power-off
operation and therefore requires an explicit data-loss confirmation. Arbitrary
PowerShell, WMI queries, methods, scripts, and command arguments remain outside
the Agent contract.

## Licensing and Editions

- IPMS is proprietary software distributed under an A-Corp agreement or EULA.
- A signed license policy defines tenant, edition, expiry, capacity limits, and
  enabled modules.
- Every state-changing API, worker, and agent action enforces the license
  policy. The UI is not the licensing enforcement boundary.
- Without a valid license, IPMS provides a 30-day evaluation period in
  read-only mode.
- Read-only mode permits discovery, inventory, dashboards, monitoring, and
  export. It rejects state-changing management, network, backup, and restore
  jobs.
- IPMS Cloud uses subscription entitlements for modules, capacity, retention,
  and support level. The same policy model applies to on-premises deployments.

## Migration Principle

Migration from IPMS Appliance to IPMS Scale-Out must remain supported.

1. Export a versioned, encrypted configuration and data package.
2. Bootstrap the Scale-Out target with the desired topology.
3. Import tenants, identities, inventories, policies, certificates, connector
   configurations, and durable job state.
4. Re-enroll or redirect agents through a controlled dual-endpoint transition.
5. Validate the target, switch control-plane ownership, and retain a documented
   rollback path until acceptance.

## Phased Delivery

### Phase 0: Product Foundation

- Establish repository governance, proprietary licensing, contribution policy,
  security policy, supported-platform policy, and third-party notices.
- Define domain model, tenant boundaries, API conventions, error model, and
  audit-event schema.
- Define deployment contracts for Appliance, Scale-Out, and Cloud.
- Establish A-Corp Dark and A-Corp Light design tokens.

### Phase 1: Platform and Bootstrap

- Implement tenant management, identity integration, RBAC, platform roles, and
  customer support access with explicit, time-limited approval.
- The 0.2.13 foundation centralizes stable permission codes, tenant roles,
  expiring memberships, local user administration, and the future OIDC subject
  binding. Keycloak login, claim mapping, logout, and session revalidation
  remain a separately accepted integration step.
- Implement certificate authority integration, mTLS enrollment, certificate
  rotation, agent registration, and revocation.
- Provide web-wizard and unattended bootstrap workflows.
- Limit bootstrap input to organization name, deployment topology, FQDN,
  DNS/NTP, initial administrator, certificate mode, database target, and
  license or evaluation selection.
- Implement durable jobs, audit logging, secret references, and a license
  policy verifier.

### Phase 2: Inventory and Physical Infrastructure

- Provide read-only discovery and inventory for hosts, BMCs, hardware
  components, CPU, memory, storage, network interfaces, power, and health.
- Implement Redfish first, with vendor extensions isolated behind connectors.
- Define the CMDB relationship model for tenants, sites, racks, devices,
  clusters, VMs, networks, and services.

### Phase 3: Virtual Infrastructure MVP

- Implement Hyper-V host, cluster, and virtual machine inventory.
- Provide VM views grouped by cluster and host.
- Implement safe, audited VM operations such as start, shutdown, restart, and
  selected configuration workflows.
- Application 0.2.26 and Windows Agent 0.2.21 provide the first interactive
  Hyper-V console foundation. It enforces one database-backed, lease-bound
  session per VM, owner-only viewing and input, direct keyboard and mouse
  control, and an explicit secure-attention action over the existing outbound
  mTLS Agent channel. Clipboard, device redirection, recording, session
  takeover, and arbitrary remote execution remain excluded. The Agent resolves
  the currently active VM settings through `Msvm_SettingsDefineState` rather
  than scanning a host-wide collection.
- Application 0.2.27 and Windows Agent 0.2.22 add an independent, resizable
  browser console window, bulk frame-buffer reads, VM-filtered input-device
  queries, bounded 150-ms frame cycles, and ordered/coalesced input batches.
  Frame polling carries status and lease renewal in one response and skips
  unchanged images. Closing the browser window releases the session; abrupt
  disconnects retain the bounded lease-expiry fallback.
- Enforce validation, approval policy, maintenance awareness, idempotency, and
  rollback information for write operations.

### Phase 4: Monitoring

- Collect metrics, health signals, events, and operational logs.
- Provide tenant-safe dashboards, alert rules, notification routing, and
  maintenance windows.
- Keep transactional inventory data separate from scalable telemetry storage.

### Phase 5: Backup and Restore Integration

- Integrate backup platforms through supported APIs, starting with job status,
  restore points, failures, and alerting.
- Add controlled restore requests with validation, approval, audit, and status
  tracking.
- Do not reimplement backup data movement or repository engines in the initial
  product scope.

### Phase 6: Network and Storage Management

- Provide network and storage discovery, topology, and read-only configuration
  visibility.
- Add vendor-specific, validated port and storage changes only after read-only
  behavior and connector compatibility are proven.
- Preserve intended configuration, discovered state, change history, and
  exception handling separately.

### Phase 7: Scale-Out and Cloud Operations

- Deliver Appliance-to-Scale-Out migration and topology validation.
- Deliver IPMS Cloud tenancy, Edge Agent, outbound mTLS connectivity, customer
  onboarding, subscription entitlements, and controlled support access.
- Add capacity management, regional data-placement options, dedicated tenant
  offerings, and operational runbooks.

## UI Direction

IPMS uses an A-Corp-inspired enterprise console with an efficient management
layout: navigation, object lists, detail panes, contextual actions, job status,
and audit visibility.

Initial A-Corp Dark tokens:

| Token | Value |
| --- | --- |
| `color-deepspace` | `#071018` |
| `color-void` | `#04090e` |
| `color-panel-blue` | `#0b1721` |
| `color-text-primary` | `#f1f4f5` |
| `color-text-secondary` | `#c5cdd0` |
| `color-accent-crimson` | `#d4483e` |

A-Corp Light uses the same semantic tokens with light surfaces and accessible
contrast. Operational states must always use text, icons, and color; color
alone must not convey a system state.

## Explicit Non-Goals for the Initial Releases

- Replacing a full enterprise backup data plane or backup repository.
- Providing unrestricted PowerShell, SSH, or arbitrary command execution.
- Giving the cloud service unsolicited administrative access to customer
  environments.
- Treating discovery data as an authoritative overwrite of intended CMDB data.
