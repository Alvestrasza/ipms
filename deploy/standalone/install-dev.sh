#!/usr/bin/env bash
set -euo pipefail

NODE_VERSION="24.20.0"
PNPM_VERSION="11.24.0"
REPOSITORY_URL="https://github.com/Alvestrasza/ipms.git"

usage() {
    echo "Usage: sudo install-dev.sh --public-host HOST --management-source IP_OR_CIDR --release-ref COMMIT --tenant-slug SLUG --tenant-name NAME [--admin-username USER]" >&2
    exit 2
}

PUBLIC_HOST=""
MANAGEMENT_SOURCE=""
RELEASE_REF=""
TENANT_SLUG=""
TENANT_NAME=""
ADMIN_USERNAME="admin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --public-host) PUBLIC_HOST="${2:-}"; shift 2 ;;
        --management-source) MANAGEMENT_SOURCE="${2:-}"; shift 2 ;;
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
getent group ipms-runtime >/dev/null || groupadd --system ipms-runtime
for runtime_user in postgres ipms-control-plane ipms-web ipms-connector-worker; do
    usermod --append --groups ipms-runtime "$runtime_user"
done

install -d -m 0755 /srv/ipms/releases /srv/ipms/shared /srv/ipms/data
chown root:ipms-runtime /srv/ipms
chmod 0710 /srv/ipms
install -d -o ipms-web -g ipms-web -m 0750 /srv/ipms/shared/web-cache
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
if ! grep -q '^IPMS_CONNECTOR_MASTER_KEY=' "$control_plane_env"; then
    echo "IPMS_CONNECTOR_MASTER_KEY=$(openssl rand -base64 32 | tr -d '\n')" >> "$control_plane_env"
fi
if ! grep -q '^IPMS_BMC_CONNECT_TIMEOUT_SECONDS=' "$control_plane_env"; then
    echo "IPMS_BMC_CONNECT_TIMEOUT_SECONDS=45" >> "$control_plane_env"
fi
if grep -q '^IPMS_ALLOWED_HOSTS=' "$control_plane_env"; then
    sed -i "s|^IPMS_ALLOWED_HOSTS=.*|IPMS_ALLOWED_HOSTS=${PUBLIC_HOST},127.0.0.1|" "$control_plane_env"
else
    echo "IPMS_ALLOWED_HOSTS=${PUBLIC_HOST},127.0.0.1" >> "$control_plane_env"
fi

web_console_env=/srv/ipms/shared/web-console.env
install -o root -g ipms-web -m 0640 /dev/null "$web_console_env"
{
    echo "HOSTNAME=127.0.0.1"
    echo "PORT=3000"
    echo "IPMS_CONTROL_PLANE_URL=http://127.0.0.1:8000"
} > "$web_console_env"

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
"$control_python" "$control_manage" check --deploy

install -m 0644 "$release_directory/deploy/standalone/ipms-control-plane.service" /etc/systemd/system/ipms-control-plane.service
install -m 0644 "$release_directory/deploy/standalone/ipms-web-console.service" /etc/systemd/system/ipms-web-console.service
install -m 0644 "$release_directory/deploy/standalone/ipms-connector-worker.service" /etc/systemd/system/ipms-connector-worker.service
install -m 0644 "$release_directory/deploy/standalone/ipms-connector-worker.timer" /etc/systemd/system/ipms-connector-worker.timer

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
systemctl enable fail2ban ipms-control-plane ipms-web-console ipms-connector-worker.timer nginx
systemctl restart fail2ban ipms-control-plane ipms-web-console ipms-connector-worker.timer nginx
ufw allow from "$MANAGEMENT_SOURCE" to any port 443 proto tcp comment "IPMS HTTPS management"
ufw --force enable

systemctl is-active --quiet postgresql
systemctl is-active --quiet ipms-control-plane
systemctl is-active --quiet ipms-web-console
systemctl is-active --quiet ipms-connector-worker.timer
systemctl is-active --quiet nginx
curl --fail --silent --show-error \
    --header "Host: ${PUBLIC_HOST}" \
    --header "X-Forwarded-Proto: https" \
    http://127.0.0.1:8000/api/v1/health/ready/ >/dev/null
curl --fail --silent --show-error --insecure \
    --resolve "${PUBLIC_HOST}:443:127.0.0.1" \
    "https://${PUBLIC_HOST}/api/v1/health/ready/" >/dev/null

echo "IPMS standalone development deployment completed."
echo "Retrieve the one-time administrator password through a separate privileged SSH session."
