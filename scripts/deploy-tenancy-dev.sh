#!/usr/bin/env bash
# Exact-target 0.2.32 -> 0.2.33 DEV cutover. No Agent or firewall changes.
set -Eeuo pipefail
umask 027
[[ $EUID -eq 0 && $# -eq 4 ]] || exit 2
# Hold one process-lifetime lock before reading or changing cutover state.
exec 9>/run/lock/ipms-tenant-cutover.lock
flock -n 9 || { echo 'Another tenant security cutover is already running.' >&2; exit 2; }
expected_host=$1
public_host=${2,,}
release_ref=$3
previous_ref=$4
[[ $(hostname -f) == "$expected_host" && $public_host =~ ^[A-Za-z0-9.-]+$ ]] || exit 2
[[ $release_ref =~ ^[0-9a-f]{40}$ && $previous_ref =~ ^[0-9a-f]{40}$ ]] || exit 2
previous=/srv/ipms/releases/$previous_ref
release=/srv/ipms/releases/$release_ref
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.32 ]] || exit 2
[[ ! -e $release && ! -L $release ]] || exit 2
[[ ! -e /srv/ipms/.current-tenancy-next && ! -L /srv/ipms/.current-tenancy-next ]] || exit 2
fence=/srv/ipms/shared/tenant-cutover.pending
[[ ! -e $fence && ! -L $fence ]] || {
    echo 'A prior security migration requires explicit forward recovery.' >&2; exit 2;
}

assert_quiescent() {
    local active_count
    active_count=$(sudo -n -u postgres psql --no-psqlrc --tuples-only --no-align --dbname=ipms -c \
        "SELECT (SELECT count(*) FROM discovery_hypervconsolesession WHERE status IN ('requested','active') AND lease_expires_at > now())
        + (SELECT count(*) FROM discovery_discoveryjob WHERE status IN ('queued','running'))
        + (SELECT count(*) FROM discovery_hypervvirtualmachineactionjob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM agent_pki_agentlifecyclejob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM agent_pki_windowsagentdeployment WHERE status IN ('queued','running'))")
    [[ $active_count == 0 ]] || { echo 'Active or queued operations prevent the security cutover.' >&2; return 1; }
}
assert_quiescent

assert_tenant_administrator_readiness() {
    local recovery_count
    recovery_count=$(sudo -n -u postgres psql --no-psqlrc --tuples-only --no-align --dbname=ipms -c \
        "SELECT count(*) FROM tenancy_tenant t WHERE t.status != 'decommissioned'
        AND EXISTS (SELECT 1 FROM tenancy_tenantmembership m JOIN auth_user u ON u.id=m.user_id
            WHERE m.tenant_id=t.id AND m.role='tenant_admin' AND NOT u.is_staff AND NOT u.is_superuser)
        AND NOT EXISTS (SELECT 1 FROM tenancy_tenantmembership m JOIN auth_user u ON u.id=m.user_id
            WHERE m.tenant_id=t.id AND m.role='tenant_admin' AND NOT u.is_staff AND NOT u.is_superuser
            AND m.is_active AND u.is_active AND (m.expires_at IS NULL OR m.expires_at > now()))")
    [[ $recovery_count == 0 ]] || {
        echo 'A previously initialized tenant has no active independent administrator. Resolve access recovery explicitly before cutover.' >&2
        return 1
    }
}
assert_tenant_administrator_readiness

# Build before the maintenance window. A failure here cannot affect the runtime.
umask 022
git clone --filter=blob:none --no-checkout https://github.com/Alvestrasza/ipms.git "$release"
git -C "$release" checkout --detach "$release_ref"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.33 ]]
/usr/bin/python3.14 -m venv "$release/services/control-plane/.venv"
"$release/services/control-plane/.venv/bin/python" -m pip install "$release/services/control-plane"
export PATH="/opt/ipms/node-current/bin:$PATH" NEXT_TELEMETRY_DISABLED=1
(
    cd "$release/apps/web-console"
    pnpm install --frozen-lockfile
    pnpm build
    cp -a public .next/standalone/public
    install -d .next/standalone/.next
    cp -a .next/static .next/standalone/.next/static
    if [[ -e .next/standalone/.next/cache ]]; then
        mv .next/standalone/.next/cache .next/standalone/.next/cache.build
    fi
    ln -s /srv/ipms/shared/web-cache .next/standalone/.next/cache
)
assert_quiescent
assert_tenant_administrator_readiness
[[ $(readlink -f /srv/ipms/current) == "$previous" ]]

backup=/srv/ipms/backups/tenancy-0233-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 -o root -g root "$backup"
for env_name in control-plane web-console agent-gateway console-broker; do
    cp -p "/srv/ipms/shared/$env_name.env" "$backup/$env_name.env"
done
install -m 0600 /srv/ipms/shared/native-console/credential.key "$backup/credential.key"
cp -p /etc/nginx/sites-available/ipms "$backup/nginx-ipms.conf"
units=(ipms-connector-worker.timer ipms-agent-deployment-worker.timer ipms-agent-pki-expiry.timer
    ipms-control-plane.service ipms-web-console.service ipms-agent-gateway.service ipms-console-broker.service
    ipms-connector-worker.service ipms-agent-deployment-worker.service ipms-agent-pki-expiry.service)
restart_units=()
for unit in "${units[@]}"; do
    if systemctl is-active --quiet "$unit"; then restart_units+=("$unit"); fi
done
schema_started=false
recover() {
    failure=$?
    # Propagate command-substitution failures; recover only in the parent shell.
    if (( BASH_SUBSHELL > 0 )); then exit "$failure"; fi
    trap - ERR
    set +e
    if [[ $schema_started == true ]]; then
        install -m 0600 /dev/null "$fence"
        systemctl stop "${units[@]}"
        echo 'Security migration started: services remain fenced, including after reboot. Use a corrected forward release.' >&2
        echo 'Do not restore old platform flags/memberships or restart old authorization code.' >&2
    else
        if [[ -f $fence && ! -L $fence ]]; then unlink "$fence"; fi
        systemctl start "${restart_units[@]}"
        echo 'No security migration started; prior runtime was restarted.' >&2
    fi
    echo "Protected recovery material: $backup; staged release: $release" >&2
    exit "${failure:-1}"
}
trap recover ERR
# Persist the guard before stopping services. A reboot cannot silently start
# old authorization code if migration or the symlink switch subsequently fails.
for unit in "${units[@]}"; do
    install -d -m 0755 "/etc/systemd/system/$unit.d"
    install -m 0644 "$release/deploy/standalone/ipms-tenant-cutover.conf" \
        "/etc/systemd/system/$unit.d/60-ipms-tenant-cutover.conf"
done
install -m 0600 /dev/null "$fence"
systemctl daemon-reload
systemctl stop "${units[@]}"
# Recheck after stopping request handlers and timers to close the staging race.
assert_quiescent
assert_tenant_administrator_readiness
sudo -n -u postgres pg_dump --format=custom --dbname=ipms > "$backup/ipms.dump"
[[ -s $backup/ipms.dump ]]
pg_restore --list "$backup/ipms.dump" >/dev/null
echo "Protected pre-migration backup created: $backup"

set -a
. /srv/ipms/shared/control-plane.env
set +a
export PYTHONPATH="$release/services/control-plane/src"
python="$release/services/control-plane/.venv/bin/python"
manage="$release/services/control-plane/manage.py"
schema_started=true
"$python" "$manage" migrate --noinput
"$python" "$manage" collectstatic --noinput
"$python" "$manage" check --deploy
sudo -n -u postgres psql --quiet --no-psqlrc --set=ON_ERROR_STOP=1 --dbname=ipms \
    -c 'GRANT SELECT ON tenancy_platformadministrator TO ipms_console_broker'
sed "s/@@PUBLIC_HOST@@/$public_host/g" "$release/deploy/standalone/nginx-ipms.conf.template" \
    > /etc/nginx/sites-available/ipms
nginx -t
ln -s "$release" /srv/ipms/.current-tenancy-next
mv -Tf /srv/ipms/.current-tenancy-next /srv/ipms/current
systemctl reload nginx
[[ $(readlink -f /srv/ipms/current) == "$release" ]]
unlink "$fence"
systemctl start "${restart_units[@]}"
ready=false
for attempt in {1..20}; do
    if curl --connect-timeout 2 --max-time 5 --fail --silent --header "Host: $public_host" --header 'X-Forwarded-Proto: https' \
        http://127.0.0.1:8000/api/v1/health/ready/ >/dev/null \
        && curl --connect-timeout 2 --max-time 5 --fail --silent http://127.0.0.1:3000/api/health >/dev/null; then ready=true; break; fi
    sleep 1
done
[[ $ready == true ]]
for unit in ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker ipms-guacd; do
    systemctl is-active --quiet "$unit"
done
curl --connect-timeout 2 --max-time 5 --fail --silent --show-error --header "Host: $public_host" \
    --header 'X-Forwarded-Proto: https' http://127.0.0.1:8000/api/v1/ \
    | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == "0.2.33"'
for route in api/v1/platform/tenants/ api/v1/service-accounts/ admin/ admin; do
    code=$(curl --connect-timeout 2 --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" "https://$public_host/$route")
    if [[ $route == admin* ]]; then [[ $code == 404 ]]; else [[ $code == 403 ]]; fi
done
ss -lntH 'sport = :9419' | grep -q '0.0.0.0:9419'
ss -lntH 'sport = :9420' | grep -q '127.0.0.1:9420'
test -S /run/ipms-console/agent.sock
trap - ERR
echo "IPMS 0.2.33 DEV security cutover completed. Use the portal to provision any missing separate tenant administrator. Backup: $backup"
