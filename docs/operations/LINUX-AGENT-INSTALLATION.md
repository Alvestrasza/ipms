# Linux Agent Installation

## Preconditions

- A supported x86-64 Linux system with systemd and dpkg/apt.
- DNS and outbound TCP 9419 connectivity to the IPMS Agent Gateway.
- Root access for installation.
- A current, unexpired one-time enrollment document downloaded from the IPMS
  portal.

The Agent opens no inbound listener. The appliance firewall keeps TCP 9419
available on IPv4 and IPv6; customer network policy must restrict which
networks may reach the Gateway.

## Installation

Verify the release signature and published SHA-256 digest, extract the archive,
then run:

```shell
sudo install -d -m 0700 /var/lib/ipms-agent
sudo install -m 0600 enrollment.json /var/lib/ipms-agent/enrollment.json
sudo ./install-linux-agent.sh ./ipms-agent
```

The installer places the binary under `/usr/lib/ipms-agent`, installs a
hardened systemd unit, and starts the service. Enrollment creates a local ECDSA
P-256 private key, validates the one-time Gateway certificate pin, receives the
device certificate and issuer chain, and deletes the enrollment document after
success.

## Verification

```shell
sudo systemctl status ipms-agent --no-pager
sudo journalctl -u ipms-agent --since today --no-pager
sudo stat -c '%a %U:%G %n' /var/lib/ipms-agent
```

The system should appear under the physical or virtual Linux navigation after
the first successful inventory cycle. Do not publish enrollment documents,
private keys, certificates, device identifiers, internal hostnames, or raw
service logs in an issue.

## Removal and rollback

Stop and disable `ipms-agent.service` before removing the package files. Retain
`/var/lib/ipms-agent` until the device identity is revoked or a rollback has
been completed; deleting it first prevents safe identity continuity.
