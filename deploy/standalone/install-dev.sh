#!/usr/bin/env bash
set -euo pipefail

NODE_VERSION="24.20.0"
PNPM_VERSION="11.24.0"
REPOSITORY_URL="https://github.com/Alvestrasza/ipms.git"
AGENT_PACKAGE_NAME="ipms-agent-windows-x64-0.2.3.zip"
AGENT_PACKAGE_SHA256="57be8459b1c65720c15e0de2f6b3e5ec2b9e2bf3ea36db8e5145e42ffbef36a0"
AGENT_PACKAGE_URL="https://github.com/Alvestrasza/ipms/releases/download/v0.2.3/${AGENT_PACKAGE_NAME}"

usage() {
    echo "Usage: sudo install-dev.sh --public-host HOST --management-source IP_OR_CIDR --release-ref COMMIT --tenant-slug SLUG --tenant-name NAME [--admin-username USER]" >&2
    exit 2
}

PUBLIC_HOST=""
MANAGEMENT_SOURCE=""
AGENT_SOURCES=()
RELEASE_REF=""
TENANT_SLUG=""
TENANT_NAME=""
ADMIN_USERNAME="admin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --public-host) PUBLIC_HOST="${2:-}"; shift 2 ;;
        --management-source) MANAGEMENT_SOURCE="${2:-}"; shift 2 ;;
        --agent-source) AGENT_SOURCES+=("${2:-}"); shift 2 ;;
        --release-ref) RELEASE_REF="${2:-}"; shift 2 ;;
        --tenant-slug) TENANT_SLUG="${2:-}"; shift 2 ;;
        --tenant-name) TENANT_NAME="${2:-}"; shift 2 ;;
        --admin-username) ADMIN_USERNAME="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run this installer as root." >&2; exit 1; }
[[ $PUBLIC_HOST =~ ^[A-Za-z0-9.-]+$ ]] || usage
[[ $MANAGEMENT_SOURCE =~ ^[0-9A-Fa-f:./]+$ ]] || usage
for source in "${AGENT_SOURCES[@]}"; do
    [[ $source =~ ^[0-9A-Fa-f:./]+$ ]] || usage
done
[[ $RELEASE_REF =~ ^[0-9a-f]{40}$ ]] || usage
[[ $TENANT_SLUG =~ ^[a-z0-9-]+$ ]] || usage
[[ $ADMIN_USERNAME =~ ^[A-Za-z0-9@.+_-]+$ ]] || usage
[[ -n $TENANT_NAME ]] || usage

. /etc/os-release
[[ $ID == "ubuntu" && $VERSION_ID == "26.04" ]] || {
    echo "This development installer requires Ubuntu 26.04 LTS." >&2
    exit 1
}
mountpoint -q /srv/ipms || { echo "/srv/ipms must be a dedicated mount." >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /etc/postgresql-common
if ! dpkg-query -W postgresql >/dev/null 2>&1; then
    printf '%s\n' 'create_main_cluster = false' > /etc/postgresql-common/createcluster.conf
fi
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates curl fail2ban git nginx openssl postgresql postgresql-contrib \
    python3-venv xz-utils

install -d -m 0755 /opt/ipms
node_archive="node-v${NODE_VERSION}-linux-x64.tar.xz"
if [[ ! -x "/opt/ipms/node-v${NODE_VERSION}-linux-x64/bin/node" ]]; then
    temporary_directory=$(mktemp -d /tmp/ipms-install.XXXXXX)
    cleanup() {
        case "$temporary_directory" in
            /tmp/ipms-install.*) rm -rf -- "$temporary_directory" ;;
        esac
    }
    trap cleanup EXIT
    curl --fail --silent --show-error --location \
        "https://nodejs.org/dist/v${NODE_VERSION}/${node_archive}" \
        --output "${temporary_directory}/${node_archive}"
    curl --fail --silent --show-error --location \
        "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" \
        --output "${temporary_directory}/SHASUMS256.txt"
    (
        cd "$temporary_directory"
        grep " ${node_archive}$" SHASUMS256.txt | sha256sum --check --strict -
    )
    tar -xJf "${temporary_directory}/${node_archive}" -C /opt/ipms
fi
ln -sfn "/opt/ipms/node-v${NODE_VERSION}-linux-x64" /opt/ipms/node-current
export PATH="/opt/ipms/node-current/bin:${PATH}"
/opt/ipms/node-current/bin/corepack enable
/opt/ipms/node-current/bin/corepack prepare "pnpm@${PNPM_VERSION}" --activate

getent group ipms-control-plane >/dev/null || groupadd --system ipms-control-plane
id ipms-control-plane >/dev/null 2>&1 || useradd --system --gid ipms-control-plane --home-dir /nonexistent --shell /usr/sbin/nologin ipms-control-plane
getent group ipms-web >/dev/null || groupadd --system ipms-web
id ipms-web >/dev/null 2>&1 || useradd --system --gid ipms-web --home-dir /nonexistent --shell /usr/sbin/nologin ipms-web
getent group ipms-connector-worker >/dev/null || groupadd --system ipms-connector-worker
id ipms-connector-worker >/dev/null 2>&1 || useradd --system --gid ipms-connector-worker --home-dir /nonexistent --shell /usr/sbin/nologin ipms-connector-worker
getent group ipms-agent-gateway >/dev/null || groupadd --system ipms-agent-gateway
id ipms-agent-gateway >/dev/null 2>&1 || useradd --system --gid ipms-agent-gateway --home-dir /nonexistent --shell /usr/sbin/nologin ipms-agent-gateway
getent group ipms-agent-deployment-worker >/dev/null || groupadd --system ipms-agent-deployment-worker
id ipms-agent-deployment-worker >/dev/null 2>&1 || useradd --system --gid ipms-agent-deployment-worker --home-dir /nonexistent --shell /usr/sbin/nologin ipms-agent-deployment-worker
getent group ipms-runtime >/dev/null || groupadd --system ipms-runtime
for runtime_user in postgres ipms-control-plane ipms-web ipms-connector-worker ipms-agent-gateway ipms-agent-deployment-worker; do
    usermod --append --groups ipms-runtime "$runtime_user"
done

install -d -m 0755 /srv/ipms/releases /srv/ipms/shared /srv/ipms/data
chown root:ipms-runtime /srv/ipms
chmod 0710 /srv/ipms
install -d -o ipms-web -g ipms-web -m 0750 /srv/ipms/shared/web-cache
install -d -o root -g ipms-runtime -m 0750 /srv/ipms/shared/agent-artifacts
agent_package="/srv/ipms/shared/agent-artifacts/${AGENT_PACKAGE_NAME}"
if [[ ! -f $agent_package ]] || ! echo "${AGENT_PACKAGE_SHA256}  ${agent_package}" | sha256sum --check --status; then
    agent_package_download="${agent_package}.download"
    curl --fail --silent --show-error --location \
        "$AGENT_PACKAGE_URL" \
        --output "$agent_package_download"
    echo "${AGENT_PACKAGE_SHA256}  ${agent_package_download}" | sha256sum --check --strict -
    mv "$agent_package_download" "$agent_package"
fi
chown root:ipms-runtime "$agent_package"
chmod 0640 "$agent_package"
release_directory="/srv/ipms/releases/${RELEASE_REF}"
if [[ ! -d $release_directory ]]; then
    staging_directory="/srv/ipms/releases/.${RELEASE_REF}.staging"
    [[ ! -e $staging_directory ]] || { echo "Staging directory already exists." >&2; exit 1; }
    git clone --filter=blob:none --no-checkout "$REPOSITORY_URL" "$staging_directory"
    git -C "$staging_directory" checkout --detach "$RELEASE_REF"
    [[ $(git -C "$staging_directory" rev-parse HEAD) == "$RELEASE_REF" ]] || {
        echo "Checked-out commit does not match the requested release." >&2
        exit 1
    }
    mv "$staging_directory" "$release_directory"
fi

python3 -m venv "${release_directory}/services/control-plane/.venv"
"${release_directory}/services/control-plane/.venv/bin/python" -m pip install --upgrade pip
"${release_directory}/services/control-plane/.venv/bin/python" -m pip install \
    "${release_directory}/services/control-plane"

export NEXT_TELEMETRY_DISABLED=1
(
    cd "${release_directory}/apps/web-console"
    pnpm install --frozen-lockfile
    pnpm build
    cp -a public .next/standalone/public
    install -d .next/standalone/.next
    cp -a .next/static .next/standalone/.next/static
    rm -rf .next/standalone/.next/cache
    ln -s /srv/ipms/shared/web-cache .next/standalone/.next/cache
)
chown -R root:root "$release_directory"

postgresql_version=$(ls /usr/lib/postgresql | sort -V | tail -n 1)
postgresql_data="/srv/ipms/data/postgresql/${postgresql_version}/main"
if ! pg_lsclusters --no-header | awk '{print $1, $2}' | grep -qx "${postgresql_version} main"; then
    install -d -o postgres -g postgres -m 0700 \
        /srv/ipms/data/postgresql \
        "/srv/ipms/data/postgresql/${postgresql_version}" \
        "$postgresql_data"
    pg_createcluster "$postgresql_version" main --datadir="$postgresql_data" --start
fi
systemctl enable --now postgresql

database_password_file=/srv/ipms/shared/database-password
if [[ ! -f $database_password_file ]]; then
    openssl rand -hex 32 > "$database_password_file"
    chmod 0600 "$database_password_file"
fi
database_password=$(<"$database_password_file")
sudo -u postgres psql --set=ON_ERROR_STOP=1 --set=db_password="$database_password" <<'SQL'
SELECT format('CREATE ROLE ipms LOGIN PASSWORD %L', :'db_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ipms')\gexec
ALTER ROLE ipms PASSWORD :'db_password';
SELECT 'CREATE DATABASE ipms OWNER ipms'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ipms')\gexec
REVOKE ALL ON DATABASE ipms FROM PUBLIC;
SQL

control_plane_env=/srv/ipms/shared/control-plane.env
if [[ ! -f $control_plane_env ]]; then
    secret_key=$(openssl rand -hex 64)
    install -o root -g ipms-control-plane -m 0640 /dev/null "$control_plane_env"
    {
        echo "DJANGO_SETTINGS_MODULE=ipms_control_plane.settings.production"
        echo "IPMS_SECRET_KEY=${secret_key}"
        echo "IPMS_CONNECTOR_MASTER_KEY=$(openssl rand -base64 32 | tr -d '\n')"
        echo "IPMS_ALLOWED_HOSTS=${PUBLIC_HOST},127.0.0.1"
        echo "IPMS_CSRF_TRUSTED_ORIGINS=https://${PUBLIC_HOST}"
        echo "IPMS_DATABASE_NAME=ipms"
        echo "IPMS_DATABASE_USER=ipms"
        echo "IPMS_DATABASE_PASSWORD=${database_password}"
        echo "IPMS_DATABASE_HOST=127.0.0.1"
        echo "IPMS_DATABASE_PORT=5432"
        echo "IPMS_DATABASE_SSLMODE=prefer"
        echo "IPMS_HSTS_SECONDS=0"
    } > "$control_plane_env"
fi
if [[ -s $control_plane_env ]] && [[ $(tail -c 1 "$control_plane_env" | wc -l) -eq 0 ]]; then
    printf '\n' >> "$control_plane_env"
fi
if ! grep -q '^IPMS_CONNECTOR_MASTER_KEY=' "$control_plane_env"; then
    echo "IPMS_CONNECTOR_MASTER_KEY=$(openssl rand -base64 32 | tr -d '\n')" >> "$control_plane_env"
fi
if ! grep -q '^IPMS_AGENT_PKI_MASTER_KEY=' "$control_plane_env"; then
    echo "IPMS_AGENT_PKI_MASTER_KEY=$(openssl rand -base64 32 | tr -d '\n')" >> "$control_plane_env"
fi
if ! grep -q '^IPMS_AGENT_DEPLOYMENT_MASTER_KEY=' "$control_plane_env"; then
    echo "IPMS_AGENT_DEPLOYMENT_MASTER_KEY=$(openssl rand -base64 32 | tr -d '\n')" >> "$control_plane_env"
fi
sed -i \
    -e '/^IPMS_AGENT_WINDOWS_PACKAGE_PATH=/d' \
    -e '/^IPMS_AGENT_WINDOWS_PACKAGE_SHA256=/d' \
    -e '/^IPMS_AGENT_WINDOWS_VERSION=/d' \
    "$control_plane_env"
{
    echo "IPMS_AGENT_WINDOWS_PACKAGE_PATH=${agent_package}"
    echo "IPMS_AGENT_WINDOWS_PACKAGE_SHA256=${AGENT_PACKAGE_SHA256}"
    echo "IPMS_AGENT_WINDOWS_VERSION=0.2.3"
} >> "$control_plane_env"
if ! grep -q '^IPMS_CERTIFICATE_PROBE_TOKEN=' "$control_plane_env"; then
    generated_probe_token=$(openssl rand -hex 32)
    [[ $generated_probe_token =~ ^[0-9a-f]{64}$ ]] || {
        echo "Unable to generate the certificate probe token." >&2
        exit 1
    }
    printf '%s\n' "IPMS_CERTIFICATE_PROBE_TOKEN=${generated_probe_token}" >> "$control_plane_env"
fi
if ! grep -q '^IPMS_CERTIFICATE_PROBE_PORT=' "$control_plane_env"; then
    echo "IPMS_CERTIFICATE_PROBE_PORT=8010" >> "$control_plane_env"
fi
if ! grep -q '^IPMS_BMC_CONNECT_TIMEOUT_SECONDS=' "$control_plane_env"; then
    echo "IPMS_BMC_CONNECT_TIMEOUT_SECONDS=45" >> "$control_plane_env"
fi
if grep -q '^IPMS_ALLOWED_HOSTS=' "$control_plane_env"; then
    sed -i "s|^IPMS_ALLOWED_HOSTS=.*|IPMS_ALLOWED_HOSTS=${PUBLIC_HOST},127.0.0.1|" "$control_plane_env"
else
    echo "IPMS_ALLOWED_HOSTS=${PUBLIC_HOST},127.0.0.1" >> "$control_plane_env"
fi

certificate_probe_token=$(sed -n 's/^IPMS_CERTIFICATE_PROBE_TOKEN=//p' "$control_plane_env" | tail -n 1)
certificate_probe_port=$(sed -n 's/^IPMS_CERTIFICATE_PROBE_PORT=//p' "$control_plane_env" | tail -n 1)
[[ -n $certificate_probe_token && -n $certificate_probe_port ]] || {
    echo "Certificate probe configuration is incomplete." >&2
    exit 1
}
# EnvironmentFile and POSIX shell loading both use the last assignment. Collapse
# legacy duplicate entries so the control plane and isolated helper cannot select
# different probe credentials.
sed -i \
    -e '/^IPMS_CERTIFICATE_PROBE_TOKEN=/d' \
    -e '/^IPMS_CERTIFICATE_PROBE_PORT=/d' \
    "$control_plane_env"
{
    echo "IPMS_CERTIFICATE_PROBE_TOKEN=${certificate_probe_token}"
    echo "IPMS_CERTIFICATE_PROBE_PORT=${certificate_probe_port}"
} >> "$control_plane_env"
chown root:ipms-control-plane "$control_plane_env"
chmod 0640 "$control_plane_env"
certificate_probe_env=/srv/ipms/shared/certificate-probe.env
install -o root -g ipms-connector-worker -m 0640 /dev/null "$certificate_probe_env"
{
    echo "IPMS_CERTIFICATE_PROBE_TOKEN=${certificate_probe_token}"
    echo "IPMS_CERTIFICATE_PROBE_PORT=${certificate_probe_port}"
} > "$certificate_probe_env"

web_console_env=/srv/ipms/shared/web-console.env
install -o root -g ipms-web -m 0640 /dev/null "$web_console_env"
{
    echo "HOSTNAME=127.0.0.1"
    echo "PORT=3000"
    echo "IPMS_CONTROL_PLANE_URL=http://127.0.0.1:8000"
} > "$web_console_env"

agent_gateway_env=/srv/ipms/shared/agent-gateway.env
agent_gateway_secret_file=/srv/ipms/shared/agent-gateway-secret
if [[ ! -f $agent_gateway_secret_file ]]; then
    openssl rand -hex 64 > "$agent_gateway_secret_file"
    chmod 0600 "$agent_gateway_secret_file"
fi
agent_gateway_secret=$(<"$agent_gateway_secret_file")
agent_pki_master_key=$(sed -n 's/^IPMS_AGENT_PKI_MASTER_KEY=//p' "$control_plane_env" | tail -n 1)
install -o root -g ipms-agent-gateway -m 0640 /dev/null "$agent_gateway_env"
{
    echo "DJANGO_SETTINGS_MODULE=ipms_control_plane.settings.gateway"
    echo "IPMS_GATEWAY_SECRET_KEY=${agent_gateway_secret}"
    echo "IPMS_AGENT_PKI_MASTER_KEY=${agent_pki_master_key}"
    echo "IPMS_AGENT_WINDOWS_PACKAGE_PATH=${agent_package}"
    echo "IPMS_AGENT_WINDOWS_PACKAGE_SHA256=${AGENT_PACKAGE_SHA256}"
    echo "IPMS_AGENT_WINDOWS_VERSION=0.2.3"
    echo "IPMS_DATABASE_NAME=ipms"
    echo "IPMS_DATABASE_USER=ipms"
    echo "IPMS_DATABASE_PASSWORD=${database_password}"
    echo "IPMS_DATABASE_HOST=127.0.0.1"
    echo "IPMS_DATABASE_PORT=5432"
    echo "IPMS_DATABASE_SSLMODE=prefer"
    echo "IPMS_AGENT_GATEWAY_RUNTIME_DIRECTORY=/run/ipms-agent-gateway"
    echo "IPMS_AGENT_GATEWAY_BIND=0.0.0.0"
    echo "IPMS_AGENT_GATEWAY_PORT=9419"
    echo "IPMS_AGENT_GATEWAY_TENANT_SLUG=${TENANT_SLUG}"
} > "$agent_gateway_env"

initial_password_file=/srv/ipms/shared/initial-admin-password
if [[ ! -f $initial_password_file ]]; then
    openssl rand -base64 36 > "$initial_password_file"
    chmod 0600 "$initial_password_file"
fi

ln -sfn "$release_directory" /srv/ipms/current
set -a
. "$control_plane_env"
set +a
export PYTHONPATH=/srv/ipms/current/services/control-plane/src
control_python=/srv/ipms/current/services/control-plane/.venv/bin/python
control_manage=/srv/ipms/current/services/control-plane/manage.py
"$control_python" "$control_manage" migrate --noinput
"$control_python" "$control_manage" collectstatic --noinput
"$control_python" "$control_manage" bootstrap_instance \
    --tenant-slug "$TENANT_SLUG" \
    --tenant-name "$TENANT_NAME" \
    --admin-username "$ADMIN_USERNAME" \
    --admin-password-file "$initial_password_file"
root_recovery_passphrase_file=/srv/ipms/shared/agent-root-recovery.passphrase
root_recovery_bundle=/srv/ipms/shared/agent-root-recovery.pem
"$control_python" "$control_manage" bootstrap_agent_pki \
    --tenant-slug "$TENANT_SLUG" \
    --gateway-dns-name "$PUBLIC_HOST" \
    --root-recovery-output "$root_recovery_bundle" \
    --root-recovery-passphrase-file "$root_recovery_passphrase_file" \
    --generate-root-recovery-passphrase \
    --if-missing
if grep -q '^IPMS_AGENT_GATEWAY_TENANT_SLUG=' "$control_plane_env"; then
    sed -i "s|^IPMS_AGENT_GATEWAY_TENANT_SLUG=.*|IPMS_AGENT_GATEWAY_TENANT_SLUG=${TENANT_SLUG}|" "$control_plane_env"
else
    echo "IPMS_AGENT_GATEWAY_TENANT_SLUG=${TENANT_SLUG}" >> "$control_plane_env"
fi
"$control_python" "$control_manage" check --deploy

install -m 0644 "$release_directory/deploy/standalone/ipms-control-plane.service" /etc/systemd/system/ipms-control-plane.service
install -m 0644 "$release_directory/deploy/standalone/ipms-certificate-probe.service" /etc/systemd/system/ipms-certificate-probe.service
install -m 0644 "$release_directory/deploy/standalone/ipms-web-console.service" /etc/systemd/system/ipms-web-console.service
install -m 0644 "$release_directory/deploy/standalone/ipms-connector-worker.service" /etc/systemd/system/ipms-connector-worker.service
install -m 0644 "$release_directory/deploy/standalone/ipms-connector-worker.timer" /etc/systemd/system/ipms-connector-worker.timer
install -m 0644 "$release_directory/deploy/standalone/ipms-agent-deployment-worker.service" /etc/systemd/system/ipms-agent-deployment-worker.service
install -m 0644 "$release_directory/deploy/standalone/ipms-agent-deployment-worker.timer" /etc/systemd/system/ipms-agent-deployment-worker.timer
install -m 0644 "$release_directory/deploy/standalone/ipms-agent-gateway-material.service" /etc/systemd/system/ipms-agent-gateway-material.service
install -m 0644 "$release_directory/deploy/standalone/ipms-agent-gateway.service" /etc/systemd/system/ipms-agent-gateway.service
install -m 0644 "$release_directory/deploy/standalone/ipms-agent-pki-expiry.service" /etc/systemd/system/ipms-agent-pki-expiry.service
install -m 0644 "$release_directory/deploy/standalone/ipms-agent-pki-expiry.timer" /etc/systemd/system/ipms-agent-pki-expiry.timer

install -d -m 0700 /etc/ipms/tls
if [[ ! -f /etc/ipms/tls/server.key || ! -f /etc/ipms/tls/server.crt ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
        -days 90 -nodes -keyout /etc/ipms/tls/server.key \
        -out /etc/ipms/tls/server.crt -subj "/CN=${PUBLIC_HOST}" \
        -addext "subjectAltName=DNS:${PUBLIC_HOST}" \
        -addext "keyUsage=critical,digitalSignature" \
        -addext "extendedKeyUsage=serverAuth"
    chmod 0600 /etc/ipms/tls/server.key
    chmod 0644 /etc/ipms/tls/server.crt
fi

sed "s/@@PUBLIC_HOST@@/${PUBLIC_HOST}/g" \
    "$release_directory/deploy/standalone/nginx-ipms.conf.template" \
    > /etc/nginx/sites-available/ipms
ln -sfn /etc/nginx/sites-available/ipms /etc/nginx/sites-enabled/ipms
rm -f /etc/nginx/sites-enabled/default

install -d -m 0755 /etc/fail2ban/jail.d
{
    echo "[sshd]"
    echo "enabled = true"
    echo "backend = systemd"
    echo "banaction = ufw"
    echo "maxretry = 5"
    echo "findtime = 10m"
    echo "bantime = 1h"
} > /etc/fail2ban/jail.d/ipms-sshd.local

nginx -t
fail2ban-client -t
systemctl daemon-reload
systemctl enable fail2ban ipms-certificate-probe ipms-control-plane ipms-web-console ipms-connector-worker.timer ipms-agent-deployment-worker.timer ipms-agent-gateway-material ipms-agent-gateway ipms-agent-pki-expiry.timer nginx
systemctl restart fail2ban ipms-certificate-probe ipms-control-plane ipms-web-console ipms-connector-worker.timer ipms-agent-deployment-worker.timer ipms-agent-pki-expiry.timer nginx
systemctl restart ipms-agent-gateway-material ipms-agent-gateway
ufw allow from "$MANAGEMENT_SOURCE" to any port 443 proto tcp comment "IPMS HTTPS management"
ufw allow 9419/tcp comment "IPMS Agent Gateway"
ufw --force enable

systemctl is-active --quiet postgresql
systemctl is-active --quiet ipms-certificate-probe
systemctl is-active --quiet ipms-control-plane
systemctl is-active --quiet ipms-web-console
systemctl is-active --quiet ipms-connector-worker.timer
systemctl is-active --quiet ipms-agent-deployment-worker.timer
systemctl is-active --quiet ipms-agent-gateway-material
systemctl is-active --quiet ipms-agent-gateway
systemctl is-active --quiet ipms-agent-pki-expiry.timer
systemctl is-active --quiet nginx
ss -lntH 'sport = :9419' | grep -q ':9419'
curl --fail --silent --show-error \
    --header "Host: ${PUBLIC_HOST}" \
    --header "X-Forwarded-Proto: https" \
    http://127.0.0.1:8000/api/v1/health/ready/ >/dev/null
curl --fail --silent --show-error --insecure \
    --resolve "${PUBLIC_HOST}:443:127.0.0.1" \
    "https://${PUBLIC_HOST}/api/v1/health/ready/" >/dev/null

echo "IPMS standalone development deployment completed."
echo "Retrieve the one-time administrator password through a separate privileged SSH session."
