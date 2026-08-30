# iLO Connector Enrollment

## Scope

Tenant and platform administrators enroll iLO connectors through the **Physical
infrastructure** portal wizard. No console command, SSH transfer, or manually
managed credential file is part of the product workflow.

The initial connector performs read-only Redfish inventory. It does not change
power, BIOS, firmware, virtual media, storage, network, or accounts.

## Prerequisites

- HTTPS reachability from the connector-worker network boundary.
- A dedicated iLO account restricted to login and read privileges.
- A SHA-256 fingerprint for the leaf certificate, verified through an
  independent trusted channel.
- Tenant-administrator or platform-administrator access in IPMS.

Never place an iLO password in a command line, shell history, GitHub issue,
documentation, chat, test fixture, or screenshot.

## Portal Workflow

1. Sign in and select the intended tenant.
2. Open **Physical infrastructure**.
3. Select **Add iLO connector**.
4. Enter the display name and HTTPS origin URL.
5. Enter the independently verified certificate SHA-256 fingerprint.
6. Enter the dedicated read-only account and confirm its read-only scope.
7. Select **Enroll and discover**.

The Control Plane revalidates tenant access and requires either the tenant
administrator role or platform-administrator status. It encrypts the credential
with AES-256-GCM using a dedicated appliance master key, stores no plaintext
credential, emits an enrollment audit event, and queues the first discovery.
The API response is redacted and never contains the credential reference,
username, password, certificate pin, nonce, or ciphertext.

The isolated connector worker polls the durable queue, validates that the
resolved destination is a private, non-local address, verifies the pinned TLS
certificate before authentication, and runs the read-only Redfish session.

## Validation

- The endpoint appears under **Physical infrastructure** for the selected
  tenant only.
- A queued job becomes `succeeded` or reports a stable, non-secret error code.
- A successful discovery populates normalized hardware inventory.
- Enrollment and discovery each produce an append-only audit event.
- No credential, token, certificate body, raw Redfish payload, or private
  endpoint appears in public issue evidence or application logs.

Do not enable insecure TLS, bypass private-target validation, or broaden iLO
privileges to work around a failed discovery.
