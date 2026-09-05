# Standalone Development Deployment

## Scope

This runbook installs the IPMS development stack on a dedicated Ubuntu 26.04
LTS VM. It is intentionally a single-node deployment, but application state,
database state, secrets, and release artifacts use separate paths so services
can move to scale-out nodes later.

The installer deploys:

- PostgreSQL 18 from the Ubuntu repository, with its data directory below
  `/srv/ipms/data/postgresql`;
- Python 3.14, Django 6.1, Django REST Framework 3.18, Psycopg 3.3.4, and
  Gunicorn 26.2.0;
- the official Node.js 24 LTS archive after SHA-256 verification, plus the
  repository-pinned pnpm version;
- the Next.js standalone Web Console;
- a localhost-only certificate-probe helper with narrowly scoped private
  network egress and no database or connector-master-key access;
- a separately sandboxed, private-network-only connector worker and timer;
- nginx as the only HTTPS listener; and
- systemd sandboxing, UFW source restriction, and Fail2ban for SSH.

The development certificate is self-signed and valid for 90 days. HSTS is set
to zero for this certificate so a temporary trust decision cannot lock a
browser to an untrusted development certificate. A customer or production
deployment must replace it with a trusted certificate and set the intended
HSTS policy.

## Prerequisites

- The target is a dedicated Ubuntu 26.04 LTS development VM.
- `/srv/ipms` is a dedicated persistent filesystem.
- DNS for the selected management name resolves from the administrator's
  workstation.
- The immutable release commit is already present in the public repository.
- SSH host-key verification and passwordless sudo have been validated.

## Install

Run the release's installer from a privileged SSH session:

```shell
sudo bash deploy/standalone/install-dev.sh \
  --public-host ipms-dev.example.invalid \
  --management-source 192.0.2.10 \
  --release-ref 0000000000000000000000000000000000000000 \
  --tenant-slug development \
  --tenant-name "Development"
```

The bootstrap username defaults to `admin`. A deployment may override it with
`--admin-username`, but it must never use a shared or predictable password.
Every installation generates its own random one-time password.

The management source controls SSH and HTTPS access. The Appliance listens for
Agent-initiated mTLS connections on TCP 9419 and permits that port from all IPv4
and IPv6 sources. Customer environments must restrict network reachability with
their central firewall or an equivalent upstream control. Network exposure does
not replace mutual certificate authentication, tenant-bound Agent identities,
revocation, throttling, or protocol validation at the Gateway.

## First Sign-In

The installer creates a random one-time password without printing it. Retrieve
it only over the already verified SSH channel:

```shell
sudo cat /srv/ipms/shared/initial-admin-password
```

After the first successful sign-in, rotate the password interactively:

```shell
sudo bash -c 'set -a; . /srv/ipms/shared/control-plane.env; set +a; \
  export PYTHONPATH=/srv/ipms/current/services/control-plane/src; \
  /srv/ipms/current/services/control-plane/.venv/bin/python \
  /srv/ipms/current/services/control-plane/manage.py changepassword admin'
```

Then remove the one-time password file through the approved privileged
operations process.

From 0.2.33 the bootstrap account is exclusively an IPMS platform administrator
and has no tenant membership. Open **Administration > Tenants** to provision a
different initial tenant administrator, then sign in with that separate account
for infrastructure and Service Accounts. See [Tenant administration](TENANT-ADMINISTRATION.md).

## Acceptance

```shell
sudo systemctl is-active postgresql ipms-certificate-probe ipms-control-plane ipms-web-console ipms-connector-worker.timer ipms-agent-deployment-worker.timer ipms-agent-gateway nginx fail2ban
sudo ss -lntp
sudo ufw status verbose
curl --fail --header "X-Forwarded-Proto: https" \
  http://127.0.0.1:8000/api/v1/health/ready/
curl --fail --insecure --resolve ipms-dev.example.invalid:443:127.0.0.1 \
  https://ipms-dev.example.invalid/api/v1/health/ready/
```

Only SSH, HTTPS and the authenticated Agent Gateway on TCP 9419 may listen on
non-loopback addresses. PostgreSQL, Gunicorn,
Next.js, and the certificate-probe helper must remain loopback-only. The
Control Plane systemd unit permits only localhost traffic. The certificate
helper and fixed Agent deployment worker permit localhost and private address
ranges, and the helper's dedicated
environment file contains only one probe token and one port assignment.

## Release and Rollback Model

Each deployment lives at `/srv/ipms/releases/<commit>`. The
`/srv/ipms/current` symlink selects the active immutable release. Persistent
database files, runtime cache, secrets, and the initial credential do not live
inside a release.

Application rollback consists of selecting the previous release symlink and
restarting the IPMS application services and connector timer. Database migrations require a separately
reviewed backward-compatibility or restore decision; switching application code
does not reverse a migration automatically.

The 0.2.33 platform/tenant identity migration is a forward-only security cutover.
Do not select an older authorization implementation after that migration. Follow
the fenced recovery procedure in [Tenant administration](TENANT-ADMINISTRATION.md).

## Scale-Out Migration

The Web Console and Control Plane already communicate through private HTTP and
environment-selected origins. For scale-out:

1. move PostgreSQL with a tested backup/restore or replication procedure;
2. update the Control Plane database environment without changing application
   code;
3. deploy the same immutable Web Console build to each web node;
4. share the Next.js deployment identifier and Server Action encryption key if
   Server Actions are introduced; and
5. replace local session/cache assumptions with shared services before adding
   more Control Plane or Web Console instances.
