# Agent PKI and mTLS Gateway Operations

## Scope

This runbook covers the dedicated IPMS Agent PKI and the isolated Agent
Gateway on TCP 9419. It applies to machine identities only. Browser, BMC,
database, connector, and code-signing trust must remain separate.

The initial implementation provides the server-side enrollment and transport
foundation. Native Windows and Linux Agent integration, the portal enrollment
wizard, and production acceptance on representative customer PKIs remain
separate delivery gates.

## Managed hierarchy

The managed mode creates an offline Root, one runtime Issuing CA, a Gateway
server identity, and per-device Agent client identities. The Root private key
is not stored in the database or materialized for the Gateway. Bootstrap writes
it once as an encrypted PKCS#8 recovery bundle. The runtime Issuing CA and
Gateway private keys are encrypted independently with the dedicated
`IPMS_AGENT_PKI_MASTER_KEY` and tenant/object-specific authenticated data.

The recovery bundle and its passphrase are a two-part recovery secret. Retrieve
them through an approved, separate administrative channel, place them in
separate protected escrow locations, verify recovery in an isolated exercise,
and remove the bootstrap copies from the Appliance. Co-located bootstrap files
are suitable only for the current development ceremony and are a production
acceptance blocker.

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

`ipms-agent-gateway-material.service` decrypts only the current Gateway key and
accepted public chains into `/run/ipms-agent-gateway`. The listener runs as the
unprivileged `ipms-agent-gateway` account with a minimal environment that does
not contain the Web, connector, or certificate-probe secrets. TLS 1.3 and ALPN
`ipms-agent/1` are mandatory. Unauthenticated TLS is accepted only for the
pinned, one-time enrollment message; every persistent Agent stream requires a
validated client certificate.

After a certificate or issuer change, rematerialize the protected runtime files
and restart the listener:

```bash
sudo systemctl restart ipms-agent-gateway-material.service
sudo systemctl restart ipms-agent-gateway.service
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

Restart both Gateway services after rotation, rollback, or retirement.

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
