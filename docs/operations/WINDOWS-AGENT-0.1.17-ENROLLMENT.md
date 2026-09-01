# Windows Agent 0.1.17 Enrollment and Inventory

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
successful enrollment, the service repeats the bounded inventory cycle every
five minutes.

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

## Portal result

An accepted inventory upserts one tenant-scoped `WindowsServer` record with
`inventory_source=agent`, `agent_state=online`, and the approved Management Pack
allow-list. It appears in the existing physical Windows Server inventory view.

## Current boundary

The Windows compatibility transport opens one short-lived HTTP/1.1 request per
TLS 1.3 cycle on the dedicated Gateway port. The existing native Gateway framing
with ALPN `ipms-agent/1` remains available. A later release will move the Windows
Agent to the persistent bidirectional stream required for signed assignments,
certificate rotation, and update manifests. This does not weaken the 0.1.17
identity or read-only inventory boundary.
