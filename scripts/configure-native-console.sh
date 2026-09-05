#!/usr/bin/env bash
# Provision only the Appliance-side service identities and encrypted key store.
# Never creates a Windows account or changes host/network firewall policy.
set -euo pipefail
umask 077
[[ $EUID -eq 0 && $# -eq 1 && $1 =~ ^[A-Za-z0-9.-]+$ ]] || exit 2
public_host=$1
prefix=/srv/ipms/dependencies/guacamole-1.6.0-ipms1
[[ -x $prefix/sbin/guacd && -f $prefix/SHA256SUMS.runtime ]] || {
    echo 'Install and verify the pinned native adapter before configuration.' >&2
    exit 2
}
sha256sum --check --strict "$prefix/SHA256SUMS.runtime" >/dev/null

for group in ipms-console-broker ipms-guacd ipms-console-transport ipms-native-console; do
    getent group "$group" >/dev/null || groupadd --system "$group"
done
for service_user in ipms-console-broker ipms-guacd; do
    id "$service_user" >/dev/null 2>&1 || useradd --system --gid "$service_user" \
        --home-dir /nonexistent --shell /usr/sbin/nologin "$service_user"
    usermod --append --groups ipms-runtime "$service_user"
done
usermod --append --groups ipms-native-console ipms-control-plane
usermod --append --groups ipms-native-console,ipms-console-transport ipms-console-broker
usermod --append --groups ipms-console-transport ipms-agent-gateway

install -d -o root -g ipms-native-console -m 0750 /srv/ipms/shared/native-console
key_file=/srv/ipms/shared/native-console/credential.key
if [[ ! -e $key_file && ! -L $key_file ]]; then
    openssl rand -out "$key_file" 32
fi
[[ -f $key_file && ! -L $key_file && $(stat -c %s "$key_file") == 32 ]] || exit 2
chown root:ipms-native-console "$key_file"
chmod 0640 "$key_file"
password_file=/srv/ipms/shared/native-console/broker-database-password
if [[ ! -e $password_file && ! -L $password_file ]]; then
    openssl rand -hex 32 > "$password_file"
fi
[[ -f $password_file && ! -L $password_file ]] || exit 2
chmod 0600 "$password_file"
broker_password=$(<"$password_file")
[[ $broker_password =~ ^[0-9a-f]{64}$ ]] || exit 2
# Send the random password over stdin, never as a command-line argument.
{
    printf "\\set broker_password '%s'\n" "$broker_password"
    cat <<'SQL'
SELECT 'CREATE ROLE ipms_console_broker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ipms_console_broker')\gexec
DO $ipms$
DECLARE broker oid;
BEGIN
    SELECT oid INTO STRICT broker FROM pg_roles WHERE rolname = 'ipms_console_broker';
    IF EXISTS (SELECT FROM pg_roles WHERE oid = broker AND
            (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit))
        OR EXISTS (SELECT FROM pg_auth_members WHERE member = broker)
        OR EXISTS (SELECT FROM pg_class WHERE relowner = broker)
        OR EXISTS (SELECT FROM pg_namespace WHERE nspowner = broker)
        OR EXISTS (SELECT FROM pg_database WHERE datdba = broker)
        OR has_schema_privilege(broker, 'public', 'CREATE')
        OR has_database_privilege(broker, 'ipms', 'CREATE,TEMP') THEN
        RAISE EXCEPTION 'Existing native broker role is not isolated; refusing to reuse it';
    END IF;
    IF EXISTS (
        SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND (
            (has_table_privilege(broker, c.oid, 'SELECT') AND c.relname NOT IN (
                'auth_user', 'django_session', 'tenancy_tenant', 'tenancy_tenantmembership',
                'tenancy_platformadministrator',
                'agent_pki_agentenrollment', 'agent_pki_agentrevocation', 'agent_pki_nativeconsolecredential',
                'agent_pki_serviceaccount',
                'discovery_windowsserver', 'discovery_hypervvirtualmachine', 'discovery_hypervconsolesession'))
            OR (has_table_privilege(broker, c.oid, 'UPDATE') AND c.relname <> 'discovery_hypervconsolesession')
            OR (has_table_privilege(broker, c.oid, 'INSERT') AND c.relname <> 'audit_auditevent')
            OR has_table_privilege(broker, c.oid, 'DELETE,TRUNCATE,REFERENCES,TRIGGER')
            OR EXISTS (SELECT FROM pg_attribute a, aclexplode(a.attacl) acl
                       WHERE a.attrelid = c.oid AND acl.grantee IN (broker, 0))
        )
    ) THEN
        RAISE EXCEPTION 'Existing native broker role has unexpected data privileges';
    END IF;
END
$ipms$;
ALTER ROLE ipms_console_broker PASSWORD :'broker_password';
GRANT CONNECT ON DATABASE ipms TO ipms_console_broker;
GRANT USAGE ON SCHEMA public TO ipms_console_broker;
GRANT SELECT ON auth_user, django_session, tenancy_tenant, tenancy_tenantmembership,
    tenancy_platformadministrator,
    agent_pki_agentenrollment, agent_pki_agentrevocation, agent_pki_nativeconsolecredential,
    agent_pki_serviceaccount,
    discovery_windowsserver, discovery_hypervvirtualmachine, discovery_hypervconsolesession
    TO ipms_console_broker;
GRANT UPDATE ON discovery_hypervconsolesession TO ipms_console_broker;
GRANT INSERT ON audit_auditevent TO ipms_console_broker;
SQL
} | sudo -n -u postgres psql --quiet --no-psqlrc --set=ON_ERROR_STOP=1 --dbname=ipms

control_env=/srv/ipms/shared/control-plane.env
set -a
. "$control_env"
set +a
[[ -n ${IPMS_SECRET_KEY:-} && ${IPMS_DATABASE_NAME:-} == ipms ]] || exit 2
broker_env=/srv/ipms/shared/console-broker.env
[[ ! -L $broker_env ]] || exit 2
install -o root -g ipms-console-broker -m 0640 /dev/null "$broker_env"
{
    printf 'DJANGO_SETTINGS_MODULE=ipms_control_plane.settings.console_broker\n'
    printf 'IPMS_SECRET_KEY=%s\n' "$IPMS_SECRET_KEY"
    printf 'IPMS_ALLOWED_HOSTS=%s,127.0.0.1\n' "$public_host"
    printf 'IPMS_CSRF_TRUSTED_ORIGINS=https://%s\n' "$public_host"
    printf 'IPMS_NATIVE_CONSOLE_ORIGIN=https://%s\n' "$public_host"
    printf 'IPMS_NATIVE_CONSOLE_KEY_FILE=%s\n' "$key_file"
    printf 'IPMS_DATABASE_NAME=ipms\nIPMS_DATABASE_USER=ipms_console_broker\n'
    printf 'IPMS_DATABASE_PASSWORD=%s\n' "$broker_password"
    printf 'IPMS_DATABASE_HOST=127.0.0.1\nIPMS_DATABASE_PORT=5432\nIPMS_DATABASE_SSLMODE=prefer\n'
} > "$broker_env"
sed -i '/^IPMS_NATIVE_CONSOLE_KEY_FILE=/d' "$control_env"
printf '\nIPMS_NATIVE_CONSOLE_KEY_FILE=%s\n' "$key_file" >> "$control_env"
echo 'Native console service configuration prepared; no services restarted.'
