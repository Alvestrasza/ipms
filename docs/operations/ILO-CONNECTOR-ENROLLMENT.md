# iLO Connector Enrollment

## Scope

This procedure enrolls one tenant-owned HPE iLO endpoint and runs one
read-only Redfish discovery. It does not perform power, BIOS, firmware,
virtual-media, storage, network, or account changes on the managed server.

## Prerequisites

- iLO 4 firmware 2.30 or later, or a supported iLO 5+ generation.
- HTTPS reachability from the IPMS connector execution environment.
- A dedicated iLO account with only login/read privileges.
- A separately verified SHA-256 fingerprint for the presented leaf
  certificate, or an approved CA trust path in a future profile.
- The IPMS SSH key and pinned server host key already validated.

Do not place an iLO password in a shell argument, command history, GitHub,
documentation, ticket, chat, or fixture.

## Enrollment

Run the PowerShell helper from the trusted management workstation. Use the
actual private values for the deployment; the values below are documentation
placeholders only.

```powershell
.\scripts\enroll-ilo-connector.ps1 `
  -HostName 'ipms-dev.example.invalid' `
  -TenantSlug 'development' `
  -DisplayName 'Example iLO' `
  -BaseUrl 'https://192.0.2.40/' `
  -CertificateSha256 '0000000000000000000000000000000000000000000000000000000000000000' `
  -IloUsername 'ipms_ro'
```

The helper prompts for the password as a SecureString. It then:

1. enrolls or updates the endpoint without a secret;
2. sends the credential JSON only over the pinned SSH connection;
3. installs it as a root-owned, group-readable `0640` file in the dedicated
   connector-secret directory;
4. executes one discovery as the unprivileged Control Plane runtime identity;
5. returns only endpoint, job, Redfish version, and object-count identifiers.

## Validation

- The endpoint appears under **Physical infrastructure**.
- The discovered system is tenant-scoped and shows model, serial number,
  power state, health, CPU, memory, BIOS, and iLO firmware when exposed.
- The discovery job is `succeeded` and has an append-only audit event.
- The connector transport used only `GET` requests plus session creation and
  deletion.
- No credential, token, certificate body, raw Redfish payload, or private
  endpoint is present in logs or public issue evidence.

If discovery fails, use the stable error code in the job and connector health
record. Do not enable insecure TLS or broaden iLO privileges as a workaround.
