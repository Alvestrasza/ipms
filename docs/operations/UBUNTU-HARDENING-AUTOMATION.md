# Ubuntu Appliance Hardening Automation

## Purpose

The IPMS hardening bootstrap converts the validated Ubuntu Appliance security
baseline into a versioned, idempotent, rollback-protected operation.

It consists of:

- `scripts/bootstrap-ubuntu-hardening.ps1`: trusted management-workstation
  orchestration, host-key verification, secure transfer, independent access
  tests, negative authentication tests, commit, and rollback exercise
- `scripts/ipms-ubuntu-hardening.sh`: root-only Ubuntu configuration, backup,
  automatic rollback, effective-state validation, and sanitized evidence

The implementation targets Ubuntu Server 26.04 LTS and the IPMS v0.1.0
development reference profile.

## Safety Boundary

The bootstrap requires an existing administrative identity with:

- a separately managed Ed25519 private key
- a console-verified Ed25519 server host-key fingerprint
- working key-only SSH access
- working non-interactive sudo

The bootstrap does not create the administrative identity. Use the separately
documented Alice SSH bootstrap first.

The following preconditions are mandatory:

- the persistent data filesystem is already mounted and present in `/etc/fstab`
- the data filesystem is ext4
- no inbound UFW allow rule exists outside the selected Appliance profile
- the management source is a host address or a deliberately scoped network
- console access remains available as the final break-glass path

IPv4 management networks broader than `/24` and IPv6 management networks
broader than `/64` are rejected. Unspecified and loopback sources are rejected.
No environment address is embedded in the scripts.

## Supported Profiles

Only the `development` profile is currently executable.

The `customer` and `production` values are recognized but deliberately
blocked until the encryption-at-rest, unattended unlock, recovery, and key
rotation policy tracked in Issue #10 is implemented. This prevents a
development exception from silently becoming a customer default.

## Standard Invocation

Use real values only at the command line or through a protected deployment
system. Do not commit them to source control.

```powershell
.\scripts\bootstrap-ubuntu-hardening.ps1 `
    -HostName '<appliance-fqdn>' `
    -ExpectedHostKeyFingerprint 'SHA256:<console-verified-fingerprint>' `
    -ManagementSource '<management-address-or-cidr>' `
    -AdminUser 'alice' `
    -Profile development `
    -DataMount '/srv/ipms' `
    -RollbackMinutes 20
```

Use `-WhatIf` to perform input, host-key, key-file, SSH, and sudo preflight
without staging or applying the hardening program.

`-SkipPackageUpdate` skips `apt-get update` but does not skip package-state or
effective-state validation. Use it only when package metadata was refreshed by
the same controlled maintenance operation.

## Transaction Sequence

The orchestrator performs this sequence:

1. validate every local input
2. verify the server Ed25519 host key against the console fingerprint
3. validate existing key-only SSH and non-interactive sudo
4. normalize and transfer the Bash program through the verified connection
5. validate Ubuntu, identity, mount, and firewall preconditions
6. install required security packages
7. create a root-only state directory and backup
8. arm a transient systemd rollback timer
9. install or reconcile managed configuration
10. reload SSH and activate the firewall policy
11. open a new independent SSH session
12. confirm password SSH and direct root SSH both fail
13. run the complete effective-state validator
14. cancel the rollback timer only after every validation passes

If any step after rollback arming fails, the timer remains active. The
management operator must not cancel it without first restoring and validating
independent access.

## Rollback Coverage

Each run stores root-only state below:

```text
/var/lib/ipms-bootstrap/hardening/<run-id>/
```

The backup includes:

- SSH, UFW, sudo, APT, Auditd, Journald, password-quality, shell, sysctl, and
  filesystem-table configuration
- pre-run hashes or absence markers for every exact managed file
- pre-run activation state for profile-managed services and sockets
- pre-run effective values for every managed sysctl
- pre-run ext4 error behavior
- pre-run UFW activation state

Required package installation occurs before access-policy changes and is not
automatically removed by rollback. Rollback is intentionally focused on
configuration, effective security state, services, storage behavior, and
continued administrative access.

Rollback removes newly introduced managed files before extracting the backup,
restores service activation, restores UFW, restores runtime sysctl values,
restores ext4 error behavior, remounts the data filesystem, validates SSH, and
reloads the affected services.

## Automated Rollback Exercise

Use `-ExerciseRollback` on an approved disposable or development reference
Appliance:

```powershell
.\scripts\bootstrap-ubuntu-hardening.ps1 `
    -HostName '<appliance-fqdn>' `
    -ExpectedHostKeyFingerprint 'SHA256:<console-verified-fingerprint>' `
    -ManagementSource '<management-address-or-cidr>' `
    -Profile development `
    -RollbackMinutes 20 `
    -ExerciseRollback
```

This mode applies and validates the baseline, explicitly invokes rollback
instead of commit, reconnects independently, and compares managed files,
services, sysctl values, ext4 behavior, and UFW activation with their pre-run
state. Successful evidence is sanitized JSON using the schema
`ipms.hardening.rollback.v1`.

## Effective-State Validation

The validator checks:

- effective SSH authentication and forwarding policy
- UFW activation, defaults, and management rule
- Auditd activation, required rule keys, and zero lost events
- AppArmor activation and enforced profiles
- unattended-upgrade service and APT timers
- persistent bounded Journal configuration
- sudoers syntax
- fstab validity and hardened ext4 mount behavior
- managed kernel and network values
- disabled profile services, including Apport
- externally listening sockets against the selected profile
- data-filesystem write, read, and delete behavior
- package integrity and unattended-upgrade dry run
- failed units, high-priority boot errors, pending updates, and pending reboot

Apport is disabled in the reference Appliance profile because it writes
`fs.suid_dumpable=2` after the normal systemd sysctl phase. The managed policy
requires the effective value to remain `0`.

Successful validation emits only a schema, script version, profile, and result.
It does not emit hostnames, addresses, fingerprints, disk identifiers,
credentials, backup content, or raw live configuration.

## Acceptance Evidence

The implementation was exercised on the development reference Appliance with:

- PowerShell parser validation
- Ubuntu Bash syntax validation
- an initial rollback-protected application
- an intentional failed transformation followed by successful automatic-state
  rollback and independent access validation
- a corrected successful application
- repeated `CHANGED=false` idempotency runs
- positive key-only SSH and non-interactive sudo tests
- negative password and direct-root SSH tests
- a full reboot and post-reboot validation
- the versioned `-ExerciseRollback` path with complete state comparison

This is strong reference-system evidence. It is not yet clean-install evidence.
Issue #11 remains open until the same versioned flow passes on a newly created
Ubuntu 26.04.1 LTS Appliance and is integrated into the unattended installer.
