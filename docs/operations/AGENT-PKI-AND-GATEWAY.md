<!--
File Name: AGENT-PKI-AND-GATEWAY.md
Version: v0.2.76 | Last Modified: 2026-09-20
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Purpose: Operate tenant-isolated Agent PKI, recovery custody and the shared Gateway.
-->

# Agent PKI and mTLS Gateway Operations

## Scope

This runbook covers the dedicated IPMS Agent PKI and the isolated Agent
Gateway on TCP 9419. It applies to machine identities only. Browser, BMC,
database, connector, and code-signing trust must remain separate.

The Appliance supports explicit platform-operator onboarding for multiple
tenants on one listener. Each tenant receives its own managed hierarchy,
Gateway server identity and Agent trust chain. Exact DNS/SNI selection keeps
those identities separate while sharing the Appliance IP address and TCP 9419.
Production acceptance on representative customer networks and recovery media
remains a separate delivery gate.

## Managed hierarchy

The managed mode creates an offline Root, one runtime Issuing CA, a Gateway
server identity, and per-device Agent client identities. The Root private key
is not stored in the database or materialized for the Gateway. Bootstrap writes
it once as an encrypted PKCS#8 recovery bundle. The runtime Issuing CA and
Gateway private keys are encrypted independently with the dedicated
`IPMS_AGENT_PKI_MASTER_KEY` and tenant/object-specific authenticated data.

The recovery bundle and its passphrase are a two-part recovery secret. The
Portal never stores the passphrase. Until custody is confirmed, the encrypted
bundle is retained under an additional Appliance master-key envelope and Agent
enrollment is blocked. Download the bundle, verify its displayed SHA-256, place
bundle and passphrase in separate protected escrow locations, and confirm
custody. Confirmation removes the staged export from the database. Verify
recovery in an isolated exercise before production acceptance.

## Portal tenant onboarding

From **Administration > Tenants**, open **Agent access** after the independent
tenant administrator exists. Enter a DNS name dedicated to this tenant. It may
resolve to the same Appliance address as other tenants, but it must be unique
and clients must use the DNS name rather than an IP address so TLS SNI and
server identity validation remain available. Create the corresponding DNS
record before verification; the Appliance does not manage the surrounding DNS
service.

Create the PKI, download and separately secure the recovery material, confirm
custody, and run the Gateway verification. The verification connects to the
configured DNS endpoint once for every tenant with that tenant's SNI name and
Root trust. It compares the presented SHA-256 fingerprint with the database and
reports readiness only when the new endpoint and all existing endpoints still
match. `IPMS_AGENT_GATEWAY_PROBE_HOST` may override only the connection address
for constrained or load-balanced installations; setting it to loopback reduces
this check to local listener readiness. Agent-network firewall reachability is
still validated by an Agent connection during deployment acceptance. The
workflow also recomputes the Appliance Agent package SHA-256 and, for HGS
tenants, requires Agent 0.2.49 or later.

## Enrollment contract

An operator creates a short-lived one-time enrollment document. The command
writes the token, Gateway DNS name, TCP port, device URI, and pinned Gateway
SHA-256 fingerprint to a new mode-0600 file and never prints the token.

```bash
sudo -u ipms-control-plane \
  /srv/ipms/current/services/control-plane/.venv/bin/python \
  /srv/ipms/current/services/control-plane/manage.py \
  create_agent_enrollment \
  --tenant-slug example \
  --display-name example-server \
  --actor operator@example.invalid \
  --output /run/ipms-enrollment/example-server.json
```

The Agent must generate its own private key locally, pin the Gateway
fingerprint before sending the token and CSR, and retain the private key in the
operating-system certificate store. IPMS returns only the issued certificate
and public chain. The Agent then reconnects with mTLS and submits its first
bounded inventory message. Possession of a valid certificate does not bypass
tenant, device, enrollment, revocation, or message-policy checks.

The development acceptance client exercises this exact exchange with an
ephemeral device key and prints only the opaque device URI and pass/fail state:

```bash
python scripts/agent-gateway-acceptance.py /protected/enrollment.json
```

Revoke the synthetic identity immediately after the test and securely remove
all copies of the one-time enrollment document.

## Runtime separation

`ipms-agent-gateway-material.timer` reconciles all eligible tenants into an
immutable generation below `/run/ipms-agent-gateway` every 15 seconds. A
manifest is published only after every tenant's Gateway key, server chain and
accepted Agent issuer chain has been written. The listener reloads that
manifest on the next TLS handshake and selects a tenant context by exact SNI.
Unknown or duplicate names fail closed. Enrollment tokens and established
Agent certificates are additionally checked against the selected tenant.

The listener runs as the
unprivileged `ipms-agent-gateway` account with a minimal environment that does
not contain the Web, connector, or certificate-probe secrets. TLS 1.3 and ALPN
`ipms-agent/1` are mandatory. Unauthenticated TLS is accepted only for the
pinned, one-time enrollment message; every persistent Agent stream requires a
validated client certificate.

After a certificate or issuer change, request immediate reconciliation when a
15-second wait is unsuitable:

```bash
sudo systemctl restart ipms-agent-gateway-material.service
sudo systemctl is-active ipms-agent-gateway-material.timer
sudo systemctl is-active ipms-agent-gateway.service
```

## Revocation

Revocation changes the server-side enrollment state immediately. The existing
certificate is rejected even before its short lifetime ends.

```bash
sudo -u ipms-control-plane \
  /srv/ipms/current/services/control-plane/.venv/bin/python \
  /srv/ipms/current/services/control-plane/manage.py \
  revoke_agent \
  --tenant-slug example \
  --device-uri urn:ipms:agent:00000000-0000-4000-8000-000000000000 \
  --reason compromised \
  --actor operator@example.invalid
```

## Managed issuer rotation and rollback

Rotation requires the separately escrowed encrypted Root bundle and passphrase.
The new issuer becomes active, the old issuer enters overlap, and the Gateway
receives a new server identity. The old issuer remains trusted so existing
Agent certificates can renew onto the new issuer.

```bash
sudo -u ipms-control-plane \
  /srv/ipms/current/services/control-plane/.venv/bin/python \
  /srv/ipms/current/services/control-plane/manage.py \
  rotate_agent_issuer \
  --tenant-slug example \
  --root-recovery-bundle /protected/recovery/agent-root.pem \
  --root-recovery-passphrase-file /protected/secret/agent-root.passphrase \
  --actor operator@example.invalid
```

The command rejects links, non-regular inputs, oversized files, and files that
are accessible by group or others. It also verifies that the Root fingerprint,
certificate, and private key belong to the selected tenant.

During the overlap window, an operator can roll back by selecting the previous
issuer UUID. Retirement is refused while that issuer still has any unexpired
active Agent certificate.

```bash
sudo -u ipms-control-plane \
  /srv/ipms/current/services/control-plane/.venv/bin/python \
  /srv/ipms/current/services/control-plane/manage.py \
  manage_agent_issuer_overlap rollback \
  --tenant-slug example --issuer-id ISSUER_UUID \
  --actor operator@example.invalid

sudo -u ipms-control-plane \
  /srv/ipms/current/services/control-plane/.venv/bin/python \
  /srv/ipms/current/services/control-plane/manage.py \
  manage_agent_issuer_overlap retire \
  --tenant-slug example --issuer-id ISSUER_UUID \
  --actor operator@example.invalid
```

The material timer publishes rotations, rollbacks and retirements without
replacing another tenant's material or restarting established connections.

## External trust modes

`external_issuing_ca` imports a dedicated Agent intermediate certificate,
private key, and its direct parent chain from protected files. IPMS validates
CA constraints, signing usage, current validity, key matching, and direct
issuance before re-encrypting the intermediate key. The customer Root private
key is never imported.

`external_certificates` imports an externally issued Gateway certificate/key
and a dedicated Agent issuer certificate. IPMS verifies the Gateway DNS SAN,
server-only EKU, key usage, validity, key match, and direct chain. Agent
bootstrap and issuance are disabled; pre-issued client certificates must have
client-only EKU and exactly one valid IPMS device URI.

AD CS, EJBCA, Vault PKI, EST, and SCEP automation are not implemented by this
foundation and must not be presented as supported integrations.

## Expiry monitoring and safe evidence

`ipms-agent-pki-expiry.timer` runs a daily 14-day threshold check. The check
reports only aggregate counts and fails visibly when attention is required. It
does not emit certificates, tokens, subjects, device identities, or private
material.

Operational evidence may include tenant-safe object UUIDs, action names,
outcomes, certificate expiration timestamps, and public fingerprints. Never
copy enrollment documents, private keys, passphrases, raw certificates, raw
Gateway payloads, customer DNS names, or network addresses into GitHub issues,
commits, screenshots, or public logs.

## Acceptance gates

- Managed bootstrap produces one encrypted Root recovery export and no runtime
  Root key.
- Enrollment remains blocked until recovery download and separate custody are
  confirmed.
- Two tenant DNS names on the shared port present different expected server
  fingerprints and trust only their own Agent issuers; unknown SNI is rejected.
- Adding a tenant preserves every existing tenant identity during the Gateway
  self-check.
- The configured Agent package bytes match the pinned SHA-256 and the HGS
  minimum Agent version.
- A one-time token cannot be reused and a weak CSR key is rejected without
  consuming the token.
- The Gateway accepts the first inventory only after enrollment and mTLS
  identity validation.
- Revocation immediately rejects the enrolled identity.
- Rotation preserves dual-issuer overlap; rollback works before retirement;
  retirement waits for old Agent identities to expire or renew.
- External certificate/key, EKU, SAN, validity, and chain mismatches are
  rejected.
- Public API, UI, Git, and logs contain no bootstrap token, private key,
  passphrase, or raw certificate material.
