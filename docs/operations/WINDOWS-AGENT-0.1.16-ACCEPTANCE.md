# Windows Agent 0.1.16 Foundation Acceptance

- Date: 2026-09-01
- Evidence level: local Windows workstation foundation test
- Result: passed for the bounded scope below

## Accepted scope

- Native C++20 service executable compiled and completed its read-only console
  inventory diagnostic.
- Native configuration executable compiled with the A-Corp multi-resolution
  icon and an administrator UAC manifest.
- Configuration and Management Pack contract tests passed.
- The `IPMS Agent` service was installed with automatic start and the
  `LocalSystem` identity, then deliberately retained in the stopped state.
- Programs and Features exposed publisher, version `0.1.16`, A-Corp icon,
  `https://www.alvestrasza.com`, calculated installed size, Modify, and
  Uninstall metadata.
- All Control Panel Items exposed `IPMS Agent Configuration` with the A-Corp
  icon and the correct executable open command.
- The Agent configuration directory was created with inheritance removed and
  access restricted to `SYSTEM` and local Administrators.

All evidence is sanitized. No workstation hostname, network address,
certificate, fingerprint, credential, or raw inventory output is published.

## Not accepted

The following remain open and must not be inferred from this test:

- signed MSI/MSIX or equivalent release packaging;
- signed binary and installer verification;
- clean-VM installation and reboot acceptance;
- supported upgrade, repair, and rollback workflows;
- Agent enrollment and local device-key generation;
- persistent TCP 9419 mTLS connectivity and certificate rotation;
- server-side inventory ingestion and durable local queueing;
- real Windows Server 2025 and Hyper-V inventory acceptance; and
- Linux Agent parity.

The test service is not production-ready and was not connected to an IPMS
Management Server.
