# ADR-0003: Agent PKI and Enrollment Trust Model

## Status

Accepted.

## Context

IPMS Agents establish persistent, bidirectional mTLS channels to the IPMS
Agent Gateway. Gateway messages can assign Management Packs, request bounded
inventory, rotate certificates, and offer signed update manifests. This
requires a dedicated and revocable machine-identity trust boundary that does
not depend on browser sessions, shared secrets, or a broad customer PKI trust
store.

## Decision

IPMS uses a dedicated Agent PKI. It is separate from Web Console, BMC,
database, code-signing, and unrelated customer certificate authorities.

The default Appliance profile creates this hierarchy during bootstrap:

```text
IPMS Agent Root CA (offline recovery material)
  └─ IPMS Agent Issuing CA (Appliance service)
       ├─ IPMS Agent Gateway server certificate
       └─ IPMS Agent client certificates
```

The Root CA signs the Issuing CA during bootstrap and is then removed from the
runtime path. Its encrypted recovery material is produced once and requires a
documented, operator-controlled recovery ceremony. The Appliance uses only the
Issuing CA for normal enrollment and renewal.

The bootstrap wizard supports these trust modes:

1. `ipms_managed`: IPMS creates the hierarchy above.
2. `external_issuing_ca`: the customer provides a dedicated IPMS Agent
   intermediate CA, issued by its existing PKI. IPMS receives the
   intermediate private key and certificate chain, never the customer root
   private key.
3. `external_certificates`: the customer supplies the Gateway certificate and
   Agent client certificates through a documented protected process. IPMS does
   not issue certificates in this mode.

Initial automation support for external issuing CAs is limited to protected
certificate-and-key import plus validation. Protocol-specific integrations for
AD CS, EJBCA, Vault PKI, EST, or SCEP require separate connector designs and
acceptance tests.

## Certificate profiles

| Profile | EKU | Subject alternative name | Lifetime |
| --- | --- | --- | --- |
| Agent Gateway | `serverAuth` | Gateway DNS name | 90 days |
| IPMS Agent | `clientAuth` | IPMS Agent device URI | 30 days |
| Agent Issuing CA | CA signing only | none | 3 years |

The Agent URI is a stable opaque identifier in the form
`urn:ipms:agent:<UUID>`. It is not a hostname, tenant name, user name, or
hardware serial number. The Gateway validates the certificate chain, EKU,
device URI, enrollment status, tenant binding, expiration, and revocation
state before accepting a stream.

## Renewal, revocation, and recovery

- Agents renew only through the authenticated TCP 9419 stream after the
  Gateway has revalidated their active enrollment.
- The Gateway maintains immediate server-side revocation state. Short-lived
  certificates complement, but do not replace, that check.
- Revocation, renewal, CA import, Root recovery, and Issuing CA replacement
  are durable, tenant-attributed, and audited operations.
- A recovered or replaced Issuing CA uses an overlap window, explicit Agent
  re-enrollment policy, and a rollback decision before the old issuer is
  retired.
- CA private keys, recovery material, and client private keys are never
  returned by public APIs, displayed in the Web Console, stored in Git, or
  emitted in logs.

## Non-goals

- Using the Agent PKI for browser, BMC, database, or code-signing trust.
- Auto-enrolling arbitrary customer machines based only on network reachability.
- Treating certificate possession as sufficient authorization.
- Automatically trusting an imported external root or bypassing certificate
  validation.

## Implementation handoff

1. Add tenant-scoped CA, issuer, enrollment, and revocation domain models with
   row-level policy and append-only audit events.
2. Implement protected, encrypted Issuing-CA key storage and one-time Root
   recovery export for the managed mode.
3. Build the guided enrollment ceremony: bootstrap token, pinned Gateway
   identity, device key generation, CSR, client certificate issuance, and
   post-enrollment inventory confirmation.
4. Implement the Agent Gateway TLS listener on TCP 9419, requiring client
   certificates and enforcing the profile checks above before creating a
   bidirectional stream.
5. Add certificate rotation, revocation, dual-issuer overlap, expiry alarms,
   negative tests, and an operator-tested rollback path.
6. Add external-CA import validation before protocol-specific CA integrations.

## Consequences

- IPMS is self-contained for Appliance deployments while preserving customer
  PKI ownership where it exists.
- A compromised Agent certificate affects one enrolled device and can be
  revoked independently.
- The Issuing CA remains sensitive runtime material and requires encrypted
  storage, controlled backup, and audited recovery.
