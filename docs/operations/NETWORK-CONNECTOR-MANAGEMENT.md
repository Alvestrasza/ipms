# Network Connector Management

## Supported foundation

The **Network** page can enroll Sophos Firewall, Loadbalancer.org ADC, and HPE
5130/5900AF Comware 7.1 endpoints. This release is read-only. Live support is
established only after the exact device and firmware pass acceptance.

## Enrollment

1. Create a dedicated read-only device account and enable only the vendor API
   or SNMP access required by the connector.
2. In **Network**, select **Add network device** and choose the product family.
3. Enter a DNS name or private address, management port, and the dedicated
   credential. Comware also requires an SNMPv3 privacy key; Loadbalancer.org
   requires its API key.
4. For HTTPS devices, independently verify the displayed subject, issuer, and
   SHA-256 fingerprint, then explicitly approve the current certificate.
5. Review status and normalized interface inventory after discovery.

The default ports shown by the portal are product defaults, not firewall
rules. Sophos API access must be enabled and restricted on the appliance.
Comware must use SNMPv3 authPriv; community-based SNMP is unsupported.

## Operations

The key action replaces the encrypted credential and queues discovery. The
refresh action queues the fixed read-only discovery. The remove action archives
the connector and destroys its stored credential. None of these actions send a
managed-device configuration change.

Record only sanitized error codes, product/firmware versions, and acceptance
results in public issues. Never paste endpoint addresses, topology, usernames,
passwords, API keys, privacy keys, certificates, fingerprints, or raw responses.

## Troubleshooting

- `certificate_changed`: repeat certificate inspection and investigate the
  change before trusting it.
- `authentication_failed`: verify the dedicated account and product API access.
- `connection_failed`: verify routing, product management port, and customer
  firewall policy.
- `invalid_response`: confirm the exact firmware and collect diagnostics in a
  private channel before creating a sanitized compatibility fixture.
