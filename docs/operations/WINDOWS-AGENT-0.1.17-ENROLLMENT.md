# Windows Agent Enrollment and Inventory

## Scope

IPMS 0.1.17 provides the first native Windows Agent connection to the dedicated
Agent Gateway. The path is read-only and agent initiated. It enrolls one Windows
device and publishes the bounded `windows-server-core` inventory to the
certificate-bound tenant.

This release does not add remote command execution, PowerShell, SSH, scripts,
an inbound listener, or executable Management Pack content.

## Security contract

- The Agent creates a non-exportable ECDSA P-256 key in the LocalMachine Windows
  key store through CertEnroll.
- A one-time bootstrap document contains the device URI, Gateway DNS name and
  port, the Gateway SHA-256 certificate pin, and a short-lived enrollment token.
- WinHTTP completes the TLS 1.3 handshake and validates the DNS identity. Only
  the unknown-CA error is temporarily ignored during bootstrap. The Agent
  verifies the pinned leaf certificate before it writes the request body.
- The dedicated Agent issuing chain is installed in the LocalMachine certificate
  stores. The returned client certificate is linked to the non-exportable key.
- Every inventory request after enrollment uses TLS 1.3, normal server chain and
  DNS validation, and the enrolled client certificate for mTLS.
- The Gateway derives the tenant and device URI exclusively from the validated
  client certificate. Client-supplied tenant identifiers are not accepted.
- Request headers, JSON documents, inventory fields, and response bodies are
  bounded. Redirects and proxy traversal are disabled.

## Operator flow

Create the one-time enrollment on the appliance without printing its secret:

```shell
python manage.py create_agent_enrollment \
  --tenant-slug <tenant> \
  --display-name <server-name> \
  --output /root/ipms-agent-enrollment.json \
  --actor <operator> \
  --lifetime-minutes 30
```

Transfer the file through an approved protected channel. On the Windows server,
run the importer from an elevated PowerShell session:

```powershell
& .\ipms-agent-import-enrollment.ps1 `
  -EnrollmentDocument .\ipms-agent-enrollment.json
```

Run one visible acceptance cycle before enabling periodic service operation:

```powershell
& .\ipms-agent.exe --run-once
```

The command reports only success or a sanitized failure reason. It never prints
the token, private key, certificate body, or complete bootstrap document. After
successful enrollment, the service repeats bounded live telemetry every ten
seconds and the full inventory cycle every five minutes.

## Local state

The installer protects `%ProgramData%\Alvestrasza\IPMS Agent` for `SYSTEM` and
local Administrators only. The directory contains:

| File | Content |
| --- | --- |
| `enrollment.json` | One-time secret; removed by the Agent after successful enrollment |
| `agent-state.json` | Device URI, public certificate SHA-256 fingerprint, Gateway DNS name, and port |
| `agent-settings.ini` | Locally editable Gateway endpoint and trust-mode selection |

The private key remains in the LocalMachine key store and is marked
non-exportable. No private key is written to these files.

## Operating system and machine classification

Starting with Agent `0.1.23`, the `windows-server-core` pack reads
`Win32_OperatingSystem.Caption` and the `Manufacturer` and `Model` properties
from `Win32_ComputerSystem` through the native WMI COM API. It does not invoke
PowerShell, a command shell, or an external inventory process.

The WMI operating-system caption is authoritative for the normalized portal
name. The legacy `ProductName` registry value remains in the bounded detail
snapshot for diagnostics because supported Windows 11 editions can report a
Windows 10 product name there. The Agent classifies known Hyper-V, VMware,
VirtualBox, KVM/QEMU, Xen, Parallels, bhyve, and public-cloud virtual hardware
models as `virtual`. A successfully read non-virtual model is `physical`; a
failed or empty model query is `unknown`. The Control Plane accepts only these
three classification values.

Starting with Agent `0.1.25`, the same native WMI session also reads
`Win32_ComputerSystem.Domain` and `Win32_OperatingSystem.Version`. The Agent
constructs the FQDN from the hostname and domain only when Windows reports that
the computer is domain joined. A Hyper-V guest reads
`PhysicalHostNameFullyQualified` from the documented guest parameters registry
location; the cluster remains unset until the Hyper-V host connector can
provide authoritative placement.

The five-minute inventory includes every bounded Windows adapter returned by
`GetAdaptersAddresses`, including operational state, MAC address, link speed,
DHCP state, DNS suffix, unicast addresses and prefixes, gateways, and DNS
servers. The Control Plane validates addresses and bounds adapter and address
counts before replacing the normalized configuration.

## Current live telemetry

Agent `0.1.25` sends a separate certificate-bound telemetry document every ten
seconds. It contains current CPU utilization, physical-memory utilization, and
capacity, free space, filesystem, label, and utilization for fixed Windows
volumes. CPU counters and storage APIs are read locally through native Windows
APIs; no PowerShell, shell, script, performance-counter command, or inbound
listener is introduced.

The Control Plane keeps only the newest telemetry sample for each tenant-owned
system in this release. The portal polls the read-only current-sample endpoint
every ten seconds while the system detail page is visible. Historical metric
retention, downsampling, alert evaluation, and a separately scalable
time-series store remain future monitoring work.

For a local, read-only diagnostic without contacting the Control Plane, an
administrator can run `ipms-agent.exe --telemetry-console`. The output is
limited to the current CPU, memory, and fixed-volume utilization payload.

## Portal result

An accepted inventory upserts one tenant-scoped `WindowsServer` record with
`inventory_source=agent`, `agent_state=online`, and the approved Management Pack
allow-list. The normalized machine classification places the system in the
physical or virtual inventory view. A later accepted report automatically moves
an existing record when its classification changes.

Starting with IPMS `0.1.24`, the system name links to a tenant-scoped read-only
detail page. It displays the normalized identity, operating system, hardware
model, logical processor and memory totals, Agent state and version, inventory
source, assigned Management Packs, and discovery timestamps. The detail API
does not expose the provider detail snapshot and does not accept browser writes.
IPMS `0.1.25` extends that page with the current utilization sample and the
normalized configuration of all reported network adapters.

## Current boundary

The Windows compatibility transport opens one short-lived HTTP/1.1 request per
TLS 1.3 cycle on the dedicated Gateway port. The existing native Gateway framing
with ALPN `ipms-agent/1` remains available. A later release will move the Windows
Agent to the persistent bidirectional stream required for signed assignments,
certificate rotation, and update manifests. This does not weaken the 0.1.17
identity or read-only inventory boundary.
