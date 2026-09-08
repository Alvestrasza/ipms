#!/usr/bin/env bash
# Exact-target, coordinated IPMS 0.2.37 -> 0.2.39 DEV cutover.
# Does not change Agent packages, service environments, ingress, or VM state.
set -Eeuo pipefail
shopt -s inherit_errexit
umask 027
trap 'echo "Deployment stopped at line $LINENO; inspect the reported phase before retrying." >&2' ERR

[[ $EUID == 0 && $# == 6 ]] || { echo 'Usage: deploy-settings-dialog-dev.sh HOST MACHINE_ID PUBLIC_HOST PREVIOUS_SHA RELEASE_SHA --preflight|--stage|--activate' >&2; exit 2; }
expected_host=$1
expected_machine=$2
public_host=$3
previous_ref=$4
release_ref=$5
mode=$6
[[ $expected_host =~ ^[a-z0-9-]+$ && $(hostname -s) == "$expected_host" ]]
[[ $expected_machine =~ ^[0-9a-f]{32}$ && $(</etc/machine-id) == "$expected_machine" ]]
[[ $public_host =~ ^[a-z0-9][a-z0-9.-]+$ && $public_host != *..* && $public_host != *. ]]
[[ $previous_ref =~ ^[0-9a-f]{40}$ && $release_ref =~ ^[0-9a-f]{40}$ && $previous_ref != "$release_ref" ]]
[[ $mode == --preflight || $mode == --stage || $mode == --activate ]]
previous=/srv/ipms/releases/$previous_ref
release=/srv/ipms/releases/$release_ref
fence=/srv/ipms/shared/tenant-cutover.pending
next_link=/srv/ipms/.current-settings-dialog-next
lock=/run/lock/ipms-tenant-cutover.lock
backup_root=/srv/ipms/shared/hyperv-management-backups

protected() {
    [[ -e $1 && ! -L $1 && $(realpath -e -- "$1") == "$1" && $(stat -c %u -- "$1") == 0 ]] || return 1
    local permissions
    permissions=$(stat -c %a -- "$1")
    (( (8#$permissions & 0022) == 0 ))
}
protected_file() { protected "$1" && [[ -f $1 && $(stat -c %h -- "$1") == 1 ]]; }
for path in /srv/ipms /srv/ipms/releases /srv/ipms/shared "$previous"; do protected "$path"; [[ -d $path ]]; done
protected_file "$lock"
exec 9>>"$lock"
flock -n 9 || { echo 'Another cutover is running.' >&2; exit 2; }
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.37 ]]
[[ $(git -C "$previous" rev-parse HEAD) == "$previous_ref" ]]
git -C "$previous" diff --exit-code HEAD -- >/dev/null
for path in "$fence" "$next_link"; do [[ ! -e $path && ! -L $path ]]; done
if [[ -e $backup_root || -L $backup_root ]]; then protected "$backup_root"; [[ -d $backup_root ]]; fi
for name in control-plane web-console agent-gateway console-broker; do protected_file "/srv/ipms/shared/$name.env"; done
protected_file /srv/ipms/shared/native-console/credential.key
protected_file /etc/nginx/sites-available/ipms
preserved_files=(/srv/ipms/shared/control-plane.env /srv/ipms/shared/web-console.env
    /srv/ipms/shared/agent-gateway.env /srv/ipms/shared/console-broker.env
    /srv/ipms/shared/native-console/credential.key /etc/nginx/sites-available/ipms)
preserved=$(sha256sum "${preserved_files[@]}")
units=(ipms-connector-worker.timer ipms-agent-deployment-worker.timer ipms-agent-pki-expiry.timer
    ipms-control-plane.service ipms-web-console.service ipms-agent-gateway.service ipms-console-broker.service
    ipms-connector-worker.service ipms-agent-deployment-worker.service ipms-agent-pki-expiry.service)
restart_units=()
for unit in "${units[@]}"; do
    if systemctl is-active --quiet "$unit"; then restart_units+=("$unit"); fi
    dropin=/etc/systemd/system/$unit.d/60-ipms-tenant-cutover.conf
    protected_file "$dropin"
    cmp "$previous/deploy/standalone/ipms-tenant-cutover.conf" "$dropin"
done
for unit in ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker ipms-guacd nginx; do systemctl is-active --quiet "$unit"; done
psql_read() { sudo -n -u postgres psql -XAt --set=ON_ERROR_STOP=1 --dbname=ipms -c "$1"; }
assert_quiescent() {
    local count
    count=$(psql_read "SELECT
        (SELECT count(*) FROM discovery_hypervmanagementjob WHERE status IN ('queued','delivered','running','requires_reconciliation'))
        + (SELECT count(*) FROM discovery_hypervvirtualmachineactionjob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM discovery_hypervconsolesession WHERE status IN ('requested','active') AND lease_expires_at > now())
        + (SELECT count(*) FROM agent_pki_agentlifecyclejob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM agent_pki_windowsagentdeployment WHERE status IN ('queued','running'))
        + (SELECT count(*) FROM discovery_discoveryjob WHERE status IN ('queued','running'))")
    [[ $count == 0 ]] || { echo 'Active or unresolved operations prevent this cutover.' >&2; return 1; }
}
assert_administrators() {
    local count
    count=$(psql_read "SELECT count(*) FROM tenancy_tenant t WHERE t.status != 'decommissioned'
        AND EXISTS (SELECT 1 FROM tenancy_tenantmembership m JOIN auth_user u ON u.id=m.user_id
            WHERE m.tenant_id=t.id AND m.role='tenant_admin' AND NOT u.is_staff AND NOT u.is_superuser)
        AND NOT EXISTS (SELECT 1 FROM tenancy_tenantmembership m JOIN auth_user u ON u.id=m.user_id
            WHERE m.tenant_id=t.id AND m.role='tenant_admin' AND NOT u.is_staff AND NOT u.is_superuser
            AND m.is_active AND u.is_active AND (m.expires_at IS NULL OR m.expires_at > now())
            AND NOT EXISTS (SELECT 1 FROM tenancy_platformadministrator p WHERE p.user_id=u.id))")
    [[ $count == 0 ]] || { echo 'Resolve tenant administrator access explicitly before cutover.' >&2; return 1; }
}
broker_acl() {
    psql_read "SELECT md5(coalesce(string_agg(c.relname || ':' || coalesce(c.relacl::text,''), E'\\n' ORDER BY c.relname),''))
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname IN ('auth_user','django_session','tenancy_tenant','tenancy_tenantmembership','tenancy_platformadministrator',
        'agent_pki_agentenrollment','agent_pki_agentrevocation','agent_pki_nativeconsolecredential','agent_pki_serviceaccount',
        'discovery_windowsserver','discovery_hypervvirtualmachine','discovery_hypervconsolesession','audit_auditevent',
        'discovery_hypervmanagementjob','discovery_hypervmanagementsnapshot')"
}
assert_quiescent
assert_administrators
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='discovery' AND name='0022_hyperv_management'") == 1 ]]
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='discovery' AND name='0023_hypervsettingslease'") == 0 ]]
[[ $(psql_read "SELECT count(*) FROM pg_roles r JOIN pg_database d ON d.datdba=r.oid WHERE r.rolname='ipms' AND d.datname='ipms' AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolbypassrls") == 1 ]]
before_broker_acl=$(broker_acl)
[[ $before_broker_acl =~ ^[0-9a-f]{32}$ ]]
if [[ $mode == --preflight ]]; then
    echo 'Exact-target runtime preflight passed. No release, database, environment, fence or service changed.'
    exit 0
fi

python=$release/services/control-plane/.venv/bin/python
manage=$release/services/control-plane/manage.py
receipt=$release/settings-0239-stage.sha256
if [[ $mode == --stage ]]; then
    [[ ! -e $release && ! -L $release ]]
    umask 022
    git clone --filter=blob:none --no-checkout https://github.com/Alvestrasza/ipms.git "$release"
    git -C "$release" checkout --detach "$release_ref"
fi
protected "$release"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.39 ]]
git -C "$release" diff --exit-code HEAD -- >/dev/null
# The dialog release is not a console transport, ingress, dependency or identity cutover.
git -C "$release" diff --exit-code "$previous_ref" "$release_ref" -- deploy services/console-broker \
    services/control-plane/src/ipms/apps/tenancy services/control-plane/src/ipms_control_plane \
    services/control-plane/src/ipms/apps/agent_pki/console_broker.py \
    services/control-plane/src/ipms/apps/agent_pki/native_console.py \
    services/control-plane/src/ipms/apps/agent_pki/native_gateway.py \
    services/control-plane/src/ipms/apps/agent_pki/native_protocol.py \
    apps/web-console/src/lib/guacamole-runtime.ts apps/web-console/pnpm-lock.yaml >/dev/null
"$previous/services/control-plane/.venv/bin/python" - "$previous" "$release" <<'PY'
import json, pathlib, sys, tomllib
previous, release = map(pathlib.Path, sys.argv[1:])
for relative, parse in [('services/control-plane/pyproject.toml', tomllib.loads), ('apps/web-console/package.json', json.loads)]:
    before, after = (parse((root / relative).read_text()) for root in (previous, release))
    if relative.endswith('.toml'):
        before['project']['version'] = after['project']['version']
    else:
        before['version'] = after['version']
    assert before == after, 'Dependency or build manifest changed'
PY
if [[ $mode == --stage ]]; then
    /usr/bin/python3.14 -m venv "$release/services/control-plane/.venv"
    "$previous/services/control-plane/.venv/bin/python" -m pip freeze --exclude ipms-control-plane > "$release/services/control-plane/runtime-requirements.txt"
    "$python" -m pip install -r "$release/services/control-plane/runtime-requirements.txt"
    "$python" -m pip install --no-deps "$release/services/control-plane"
    export PATH="/opt/ipms/node-current/bin:$PATH" NEXT_TELEMETRY_DISABLED=1
    (
        cd "$release/apps/web-console"
        pnpm install --frozen-lockfile
        pnpm build
        cp -a public .next/standalone/public
        install -d .next/standalone/.next
        cp -a .next/static .next/standalone/.next/static
        if [[ -e .next/standalone/.next/cache ]]; then mv .next/standalone/.next/cache .next/standalone/.next/cache.build; fi
        ln -s /srv/ipms/shared/web-cache .next/standalone/.next/cache
    )
fi
set -a
. /srv/ipms/shared/control-plane.env
set +a
export PYTHONPATH="$release/services/control-plane/src"
[[ $IPMS_DATABASE_NAME == ipms && $IPMS_DATABASE_USER == ipms && $IPMS_DATABASE_HOST == 127.0.0.1 && $IPMS_DATABASE_PORT == 5432 ]]
# Only the reviewed additive migration may be pending. This performs no DDL.
"$python" "$manage" shell -c "from django.db import connection; from django.db.migrations.executor import MigrationExecutor; e=MigrationExecutor(connection); p=e.migration_plan(e.loader.graph.leaf_nodes()); assert [(m.app_label,m.name,backwards) for m,backwards in p] == [('discovery','0023_hypervsettingslease',False)]"
"$python" "$manage" check --deploy
sudo -n -u ipms-control-plane test -x "$python"
sudo -n -u ipms-web test -r "$release/apps/web-console/.next/standalone/server.js"
[[ $(sha256sum "${preserved_files[@]}") == "$preserved" && $(broker_acl) == "$before_broker_acl" ]]
if [[ $mode == --stage ]]; then
    (umask 022; "$python" "$manage" collectstatic --noinput)
    sha256sum "$release/apps/web-console/.next/standalone/server.js" \
        "$release/apps/web-console/.next/BUILD_ID" "$release/VERSION" > "$receipt"
    protected_file "$receipt"
    [[ $(readlink -f /srv/ipms/current) == "$previous" ]]
    echo 'IPMS 0.2.39 immutable candidate staged and checked; runtime remains 0.2.37. No migration or Agent change.'
    exit 0
fi
protected_file "$receipt"
sha256sum --check --strict "$receipt" >/dev/null
sudo -n -u ipms-control-plane test -r "$release/services/control-plane/staticfiles/admin/css/base.css"
assert_quiescent
assert_administrators
[[ $(readlink -f /srv/ipms/current) == "$previous" ]]
umask 077
if [[ ! -e $backup_root ]]; then mkdir --mode=0700 -- "$backup_root"; fi
protected "$backup_root"
backup=$backup_root/0239-$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -e $backup && ! -L $backup ]]
mkdir --mode=0700 -- "$backup"
tar --create --file "$backup/configuration.tar" --directory / --no-recursion -- \
    srv/ipms/shared/control-plane.env srv/ipms/shared/web-console.env \
    srv/ipms/shared/agent-gateway.env srv/ipms/shared/console-broker.env \
    srv/ipms/shared/native-console/credential.key etc/nginx/sites-available/ipms
tar --list --file "$backup/configuration.tar" >/dev/null
printf 'Previous commit: %s\nForward commit: %s\n' "$previous_ref" "$release_ref" > "$backup/identity.txt"
printf '%s\n' "${restart_units[@]}" > "$backup/previous-active-units.txt"
recover() {
    local failure=$?
    if (( BASH_SUBSHELL > 0 )); then exit "$failure"; fi
    trap - ERR INT TERM
    set +e
    install -m 0600 /dev/null "$fence"
    systemctl stop "${units[@]}"
    echo "Cutover interrupted; application services remain fenced. Recovery material: $backup" >&2
    echo 'Review migration state, current release and accepted jobs before forward recovery or rollback; never restore a database or remove the fence by assumption.' >&2
    (( failure != 0 )) || failure=1
    exit "$failure"
}
trap recover ERR INT TERM
install -m 0600 /dev/null "$fence"
systemctl stop "${units[@]}"
assert_quiescent
assert_administrators
sudo -n -u postgres pg_dump --format=custom --dbname=ipms > "$backup/ipms.dump"
[[ -s $backup/ipms.dump ]]
pg_restore --list "$backup/ipms.dump" >/dev/null
"$python" "$manage" migrate discovery 0023_hypervsettingslease --noinput
"$python" "$manage" migrate --check
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='discovery' AND name='0023_hypervsettingslease'") == 1 ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname='discovery_hypervsettingslease' AND r.rolname='ipms'
    AND has_table_privilege('ipms',c.oid,'SELECT') AND has_table_privilege('ipms',c.oid,'INSERT')
    AND has_table_privilege('ipms',c.oid,'UPDATE') AND has_table_privilege('ipms',c.oid,'DELETE')") == 1 ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname='discovery_hypervsettingslease'
    AND has_table_privilege('ipms_console_broker',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')") == 0 ]]
[[ $(broker_acl) == "$before_broker_acl" && $(sha256sum "${preserved_files[@]}") == "$preserved" ]]
nginx -t
ln -s "$release" "$next_link"
mv -Tf "$next_link" /srv/ipms/current
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
for unit in ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker ipms-guacd nginx; do systemctl is-active --quiet "$unit"; done
curl --connect-timeout 2 --max-time 5 --fail --silent --header "Host: $public_host" --header 'X-Forwarded-Proto: https' \
    http://127.0.0.1:8000/api/v1/ | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == "0.2.39"'
for route in en/login de/login api/v1/hyper-v/virtual-machines/00000000-0000-4000-8000-000000000000/management/dialog/ api/v1/auth/account/ api/v1/platform/tenants/ api/v1/service-accounts/ admin/ admin; do
    code=$(curl --connect-timeout 2 --max-time 10 --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" "https://$public_host/$route")
    if [[ $route == */login ]]; then [[ $code == 200 ]]; elif [[ $route == admin* ]]; then [[ $code == 404 ]]; else [[ $code == 403 ]]; fi
done
ss -lntH 'sport = :9419' | grep -q '0.0.0.0:9419'
ss -lntH 'sport = :9420' | grep -q '127.0.0.1:9420'
ss -lntH 'sport = :4822' | grep -q '127.0.0.1:4822'
test -S /run/ipms-console/agent.sock
[[ $(broker_acl) == "$before_broker_acl" && $(sha256sum "${preserved_files[@]}") == "$preserved" ]]
git -C "$release" diff --exit-code HEAD -- >/dev/null
trap - ERR INT TERM
echo "IPMS 0.2.39 DEV activation verified; migration 0023 applied. Agent packages, installed Agents, VM state and environments unchanged. Backup: $backup"
