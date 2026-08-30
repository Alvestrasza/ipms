# Ubuntu Appliance Hardening Baseline

## Purpose

This document defines the operating-system hardening baseline validated on the
initial IPMS Ubuntu 26.04.1 LTS development Appliance. It is a product design
contract for the future idempotent installer and bootstrap implementation. It
is not a record of customer-specific or environment-specific values.

The baseline follows a staged model:

1. capture the live state and preserve rollback data
2. protect administrative access with an automatic rollback
3. validate a second independent management session
4. apply host, audit, update, and filesystem controls
5. reboot and validate every persistent control

Never include real hostnames, addresses, stable disk identifiers, filesystem
identifiers, trust fingerprints, private keys, credentials, or raw production
output in this repository or in public issue comments.

## Deployment Profiles

### Development Reference

The initial development reference may use an unencrypted data volume when no
approved hardware-backed unlock path exists. This exception must be explicit
and must not be inherited by a customer or production profile.

### Customer and Production

Customer and production profiles require a separately approved
encryption-at-rest and recovery design. The design must cover the OS volume,
the persistent data volume, unattended restart, recovery material, key
rotation, hardware replacement, backup, and Appliance-to-Scale-Out migration.

An encryption key stored only on an unencrypted local OS volume is not
equivalent to TPM-backed or externally managed protection.

## Administrative Access

The reference administrative model uses a dedicated automation identity:

- its local password is locked
- authentication requires a separately managed Ed25519 key
- direct root SSH login is denied
- SSH password and keyboard-interactive authentication are denied
- only explicitly approved administrative identities may use SSH
- X11, agent, TCP, gateway, and tunnel forwarding are denied by default
- empty passwords, host-based authentication, and user-controlled environment
  injection are denied
- authentication attempts, concurrent sessions, and login grace time are
  bounded
- SSH logging uses a verbose authentication level

The private key is a root-equivalent credential when its identity has
unrestricted passwordless sudo. It must be excluded from Git, owned by the
interactive operator, and inaccessible to unrelated Windows identities.

### Safe SSH Change Sequence

Before committing an SSH policy change:

1. verify the host key through an independent console path
2. validate the existing key-only session and non-interactive sudo
3. back up the SSH and firewall configuration with root-only permissions
4. arm an automatic rollback timer
5. install the SSH drop-in and validate it with `sshd -t`
6. reload SSH without terminating the existing session
7. activate the firewall policy
8. open a second independent key-only session
9. validate the remote identity and non-interactive sudo
10. stop the rollback timer only after the second session succeeds

Ubuntu OpenSSH uses the first value obtained for a setting. The managed
hardening drop-in must therefore sort before a cloud-init file that defines a
conflicting value.

## Host Firewall

UFW is the reference host-firewall frontend.

- default incoming policy: deny
- default routed policy: deny
- default outgoing policy: allow
- firewall logging: enabled at a rate-safe level
- SSH access: only from an explicit bootstrap-supplied management source
- application ports: opened only by versioned IPMS service profiles

No real management source may be embedded in source code, examples, images,
or CI fixtures. A source-address change requires a controlled firewall update
through an already trusted session or the VM console.

Container networking must be tested explicitly because container runtimes can
introduce forwarding and packet-filtering behavior outside simple UFW rules.

## Security Updates

The Appliance uses the Ubuntu `unattended-upgrades` mechanism and systemd APT
timers.

- refresh package lists daily
- install eligible unattended security updates daily
- retain phased delivery for normal updates
- clean the package cache periodically
- remove unused kernel packages where supported
- do not automatically remove arbitrary dependencies
- do not automatically reboot until IPMS maintenance windows and durable job
  behavior are implemented
- send unattended-upgrade events to the system log

Custom policy belongs in a higher-priority APT drop-in. Do not edit the
package-owned `50unattended-upgrades` file. Every change requires an
`unattended-upgrade --dry-run` validation.

## AppArmor, Audit, and Logging

AppArmor remains Ubuntu's mandatory access-control system. Package-provided
enforced profiles remain enabled. Experimental profiles must not be forced
into enforcement without workload testing.

Auditd is enabled and watches changes to:

- local identity databases
- sudo policy
- SSH server policy
- firewall policy
- persistent mounts
- kernel parameter configuration
- systemd service configuration

Audit validation must confirm that the daemon is active, the intended rules
are loaded, and the lost-event counter is zero.

The system journal uses persistent storage, compression, sealing, bounded disk
usage, reserved free space, and bounded retention. Credentials, private keys,
license payloads, recovery secrets, and connector secrets must never be
written to operational logs.

## Kernel and Network Controls

The non-router Appliance baseline applies the following controls:

- restrict kernel-pointer exposure
- restrict unprivileged kernel-log access
- retain process-tracing restrictions
- disable privileged core dumps
- disable IPv4 forwarding
- reject IPv4 and IPv6 redirects
- disable sending IPv4 redirects
- reject IPv4 and IPv6 source routing
- enable TCP SYN cookies
- log martian IPv4 packets
- ignore broadcast echo requests and bogus ICMP error responses

Strict reverse-path filtering is appropriate for the current single-interface
reference profile. Multi-homed, asymmetric, overlay, container, and Scale-Out
topologies must re-evaluate that setting rather than inherit it blindly.

IPv6 remains available. The baseline hardens it instead of disabling it.

## Filesystem and Local Account Controls

The persistent IPMS data filesystem uses:

- ext4
- `noatime`
- `nosuid`
- `nodev`
- remount-read-only behavior after a filesystem error

The baseline intentionally does not use `noexec` because future container,
artifact, and controlled deployment workflows may require executable content.
Executable paths and service identities must be reviewed when those workloads
are introduced.

Application directories remain `root:root` with restrictive permissions until
dedicated service identities are created. Ownership must never be assigned to
an arbitrary container UID without a documented mapping.

Interactive shells use a restrictive umask. Local console passwords must meet
the configured length and complexity baseline. The console bootstrap identity
is retained as a break-glass path but is not automatically granted remote SSH
access.

## Sudo Compatibility and Validation

The Ubuntu 26.04 reference rejected the traditional sudoers option:

```text
Defaults logfile="/var/log/sudo.log"
```

The accepted baseline is:

```text
Defaults use_pty
Defaults timestamp_timeout=0
Defaults passwd_tries=3
```

Systemd Journal and Auditd provide the command and policy-change evidence.

Never install a generated sudoers file directly. Create a candidate, set mode
`0440`, validate it with `visudo -cf`, install it, run `visudo -c`, and verify a
new non-interactive sudo operation before continuing.

## Service Minimization

The reference profile disables services and sockets that are unnecessary for
the current Hyper-V Appliance role, including removable-device management,
modem management, unused iSCSI and multipath activation, the LXD installer
socket, and external MOTD news retrieval.

This is profile-based, not permanent removal. A future storage connector,
container runtime, or hardware integration may require a reviewed service to
be re-enabled. Every profile change requires a listener audit and reboot test.

## Validation Checklist

A hardening run is accepted only when all checks pass:

- new key-only SSH session succeeds
- non-interactive sudo succeeds
- password SSH attempt fails
- root SSH attempt fails
- SSH effective configuration matches policy
- UFW is active with only intended inbound rules
- externally listening sockets match the selected profile
- Auditd and AppArmor are active
- intended audit rules are loaded and lost events equal zero
- unattended-upgrade dry run succeeds
- package-integrity verification reports no unexpected changes
- journal persistence and limits are active
- kernel and network values match the managed configuration
- persistent mounts pass `findmnt --verify`
- filesystem mount options survive reboot
- privileged write, read, and delete test succeeds on the data volume
- expected service-disablement survives reboot
- no failed systemd units remain
- no high-priority boot errors remain
- no package update or reboot remains pending

## Rollback

Every hardening run creates a timestamped root-only backup before changing
configuration. The backup must include at least:

- SSH server configuration and drop-ins
- UFW configuration and prior status
- sudoers drop-ins
- APT policy drop-ins
- Auditd configuration and rules
- security and password-quality configuration
- filesystem table
- the enabled-unit baseline

Access-policy rollback removes the managed SSH drop-in, validates the restored
SSH configuration, reloads SSH, and restores or disables the firewall to its
known pre-change state. The automatic timer remains armed until an independent
new management session succeeds.

## Reference Evidence Boundary

The initial development reference passed this baseline on 2026-08-30,
including a full reboot, positive and negative authentication tests, package
integrity validation, unattended-update simulation, audit-loss validation,
listener inspection, mount persistence, and a post-reboot filesystem write
test.

This proves the live reference state only. It does not prove that a clean
Appliance can reproduce the state. Product acceptance requires the controls to
be implemented as versioned, idempotent bootstrap code with automated rollback
tests. That work is tracked in GitHub Issue #11.

## Intentional Development Exceptions

The current development reference retains these explicit exceptions:

- the OS and data volumes are unencrypted
- the automation private key has no passphrase
- the automation identity has unrestricted passwordless sudo
- centralized log collection is not yet available
- centralized secret storage and backup are not yet available
- IPMS application and container ports are not yet defined or opened

These exceptions are not approved defaults for customer or production
Appliances.

## References

- [Ubuntu Server firewall documentation](https://documentation.ubuntu.com/server/how-to/security/firewalls/index.html)
- [Ubuntu security updates documentation](https://documentation.ubuntu.com/security/security-updates/)
- [Ubuntu Server AppArmor documentation](https://documentation.ubuntu.com/server/how-to/security/apparmor/index.html)
- [IPMS encryption and unlock policy issue](https://github.com/Alvestrasza/ipms/issues/10)
- [IPMS hardening automation issue](https://github.com/Alvestrasza/ipms/issues/11)
