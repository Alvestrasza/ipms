# Alice SSH Bootstrap

## Purpose

This procedure creates a dedicated `alice` account on one IPMS Linux host,
installs a project-specific Ed25519 public key, locks password authentication
for the account, and grants passwordless sudo through a dedicated validated
sudoers file.

The private key is generated under the repository-local `.ssh` directory. That
directory is excluded from Git and must never be copied into source control,
build artifacts, tickets, or documentation.

## Security Boundary

The resulting private key grants full root-equivalent access to the target
host because `alice` receives `NOPASSWD: ALL`. Store and back up the private key
as a privileged credential. Use a separate key for other environments or
customers.

The bootstrap script deliberately requires an independently verified Ed25519
SSH host-key fingerprint. Obtain it from the server console, not from the same
network path used for SSH:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

## Prerequisites

- Windows OpenSSH client tools: `ssh`, `ssh-keygen`, and `ssh-keyscan`
- An existing bootstrap account on the target host
- The bootstrap account is either `root` or can run `sudo`
- The Ed25519 host-key fingerprint has been verified at the server console
- The project-specific key exists at `.ssh/alice_ipms_ed25519`

## Run the Bootstrap

From the repository root:

```powershell
.\scripts\bootstrap-alice-access.ps1 `
  -HostName 'ipms-appliance.example.invalid' `
  -BootstrapUser 'bootstrap-admin' `
  -ExpectedHostKeyFingerprint 'SHA256:REPLACE_WITH_CONSOLE_VERIFIED_VALUE'
```

The command requests confirmation before making remote changes. The existing
bootstrap account may prompt for its SSH and sudo passwords. Neither password
is stored by the script.

## Idempotent Behavior

- An existing safe `alice` account is retained.
- Existing entries in `authorized_keys` are retained.
- The project public key is added only when absent.
- The dedicated sudoers file is syntax-checked before installation.
- An existing `alice` account with UID 0 or a home directory other than
  `/home/alice` causes the bootstrap to stop.

## Verification

After provisioning, the script opens a new non-interactive SSH connection with
the dedicated private key and verifies:

- the remote user is `alice`
- login requires no account password
- `sudo -n` succeeds without a password
- the resulting sudo identity is UID 0

The script does not globally disable SSH password authentication. Make that
change only after every required administrative key has been tested and a
rollback path through the VM console is available.
