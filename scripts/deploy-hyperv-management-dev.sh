#!/usr/bin/env bash
# Prepared exact-target DEV cutover: IPMS 0.2.34 -> 0.2.36, Windows Agent 0.2.27.
# Stages an Agent package only; never rolls out Agents or invokes VM operations.
set -Eeuo pipefail
umask 027
trap 'echo "Deployment preflight failed at line $LINENO; existing privileges were not broadened." >&2' ERR
[[ $EUID -eq 0 && ( $# -eq 6 || ( $# -eq 7 && ${7:-} == --preflight ) ) ]] || {
    echo 'Usage: sudo deploy-hyperv-management-dev.sh EXPECTED_HOST PUBLIC_HOST NEW_COMMIT PREVIOUS_COMMIT STAGED_AGENT_ZIP SHA256 [--preflight]' >&2
    exit 2
}
expected_host=$1
public_host=${2,,}
release_ref=$3
previous_ref=$4
staged_artifact=$5
artifact_sha=$6
[[ $expected_host =~ ^[A-Za-z0-9][A-Za-z0-9.-]+$ && $(hostname -f) == "$expected_host" ]] || exit 2
[[ $public_host =~ ^[a-z0-9][a-z0-9.-]+$ && $public_host != *..* && $public_host != *. ]] || exit 2
[[ $release_ref =~ ^[0-9a-f]{40}$ && $previous_ref =~ ^[0-9a-f]{40}$ && $release_ref != "$previous_ref" ]] || exit 2
[[ $artifact_sha =~ ^[0-9a-f]{64}$ ]] || exit 2

protected_directory() {
    [[ -d $1 && ! -L $1 && $(realpath -e -- "$1") == "$1" && $(stat -c %u -- "$1") == 0 ]] || return 1
    local mode
    mode=$(stat -c %a -- "$1")
    (( (8#$mode & 0022) == 0 ))
}
protected_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u -- "$1") == 0 && $(stat -c %h -- "$1") == 1 ]] || return 1
    local mode
    mode=$(stat -c %a -- "$1")
    (( (8#$mode & 0022) == 0 ))
}
for directory in /srv/ipms /srv/ipms/releases /srv/ipms/shared /srv/ipms/shared/agent-artifacts; do
    protected_directory "$directory" || exit 2
done
# Reuse the root-owned lock established by the previous account-management cutover.
# Refuse a missing or untrusted lock instead of following a pre-planted symlink.
lock=/run/lock/ipms-tenant-cutover.lock
protected_file "$lock" || { echo 'The expected protected cutover lock is missing or unsafe.' >&2; exit 2; }
exec 9>>"$lock"
flock -n 9 || { echo 'Another IPMS security cutover is running.' >&2; exit 2; }
previous=/srv/ipms/releases/$previous_ref
release=/srv/ipms/releases/$release_ref
next_link=/srv/ipms/.current-hyperv-management-next
fence=/srv/ipms/shared/tenant-cutover.pending
backup_root=/srv/ipms/shared/hyperv-management-backups
if [[ -e $backup_root || -L $backup_root ]]; then protected_directory "$backup_root" || exit 2; fi
artifact=/srv/ipms/shared/agent-artifacts/ipms-agent-windows-x64-0.2.27.zip
artifact_next=/srv/ipms/shared/agent-artifacts/.ipms-agent-windows-x64-0.2.27.pending.zip
protected_directory "$previous" || exit 2
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.34 ]] || exit 2
[[ $(git -C "$previous" rev-parse HEAD) == "$previous_ref" ]] || exit 2
git -C "$previous" diff --exit-code HEAD -- >/dev/null
for absent in "$release" "$next_link" "$fence" "$artifact_next"; do
    [[ ! -e $absent && ! -L $absent ]] || { echo 'Existing staging or recovery state requires explicit review.' >&2; exit 2; }
done
[[ -f $staged_artifact && ! -L $staged_artifact ]] || exit 2
staged_artifact=$(realpath -e -- "$staged_artifact")
case "$staged_artifact" in
    /tmp/ipms-hyperv-management-*/ipms-agent-windows-x64-0.2.27.zip) ;;
    /srv/ipms/shared/agent-artifacts/ipms-agent-windows-x64-0.2.27.zip) ;;
    *) echo 'Stage the exact Agent ZIP in a dedicated /tmp/ipms-hyperv-management-* directory.' >&2; exit 2 ;;
esac
[[ $(stat -c %s -- "$staged_artifact") -gt 0 && $(stat -c %s -- "$staged_artifact") -le 134217728 ]] || exit 2

env_files=(control-plane web-console agent-gateway console-broker)
for name in "${env_files[@]}"; do protected_file "/srv/ipms/shared/$name.env" || exit 2; done
protected_file /srv/ipms/shared/native-console/credential.key || exit 2
protected_file /etc/nginx/sites-available/ipms || exit 2
[[ $(stat -c %s /srv/ipms/shared/native-console/credential.key) == 32 ]] || exit 2
env_value() {
    local count
    count=$(grep -c "^$2=" "$1")
    [[ $count == 1 ]] || return 1
    sed -n "s/^$2=//p" "$1"
}
# This DEV appliance uses one existing application DB role for CP and Gateway.
# Do not manufacture grants/accounts for an unreviewed alternate deployment.
for name in control-plane agent-gateway; do
    file=/srv/ipms/shared/$name.env
    [[ $(env_value "$file" IPMS_DATABASE_NAME) == ipms && $(env_value "$file" IPMS_DATABASE_USER) == ipms ]]
    [[ $(env_value "$file" IPMS_DATABASE_HOST) == 127.0.0.1 && $(env_value "$file" IPMS_DATABASE_PORT) == 5432 ]]
done
[[ $(env_value /srv/ipms/shared/console-broker.env IPMS_DATABASE_USER) == ipms_console_broker ]]
[[ $(env_value /srv/ipms/shared/agent-gateway.env IPMS_AGENT_GATEWAY_BIND) == 0.0.0.0 ]]
[[ $(env_value /srv/ipms/shared/agent-gateway.env IPMS_AGENT_GATEWAY_PORT) == 9419 ]]
psql_read() { sudo -n -u postgres psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname=ipms -c "$1"; }
assert_quiescent() {
    local count
    count=$(psql_read "SELECT (SELECT count(*) FROM discovery_hypervconsolesession WHERE status IN ('requested','active') AND lease_expires_at > now())
        + (SELECT count(*) FROM discovery_discoveryjob WHERE status IN ('queued','running'))
        + (SELECT count(*) FROM discovery_hypervvirtualmachineactionjob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM agent_pki_agentlifecyclejob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM agent_pki_windowsagentdeployment WHERE status IN ('queued','running'))")
    [[ $count == 0 ]] || { echo 'Active or queued operations prevent this cutover.' >&2; return 1; }
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
assert_quiescent
assert_administrators
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='discovery' AND name='0022_hyperv_management'") == 0 ]]
[[ $(psql_read "SELECT count(*) FROM pg_roles r JOIN pg_database d ON d.datdba=r.oid WHERE r.rolname='ipms' AND d.datname='ipms' AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolbypassrls") == 1 ]]
broker_acl() {
    psql_read "SELECT md5(coalesce(string_agg(c.relname || ':' || coalesce(c.relacl::text,''), E'\\n' ORDER BY c.relname),''))
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname IN ('auth_user','django_session','tenancy_tenant','tenancy_tenantmembership','tenancy_platformadministrator',
        'agent_pki_agentenrollment','agent_pki_agentrevocation','agent_pki_nativeconsolecredential','agent_pki_serviceaccount',
        'discovery_windowsserver','discovery_hypervvirtualmachine','discovery_hypervconsolesession','audit_auditevent')"
}
before_broker_acl=$(broker_acl)
[[ $before_broker_acl =~ ^[0-9a-f]{32}$ ]]
if [[ ${7:-} == --preflight ]]; then
    printf '%s  %s\n' "$artifact_sha" "$staged_artifact" | sha256sum --check --strict - >/dev/null
    echo 'Current-runtime preflight and staged ZIP digest passed. No release, backup, fence, environment or service changed; immutable release/build/ZIP-content validation remains a deployment step.'
    exit 0
fi

# Build the immutable forward release before any runtime interruption.
umask 022
git clone --filter=blob:none --no-checkout https://github.com/Alvestrasza/ipms.git "$release"
git -C "$release" checkout --detach "$release_ref"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.36 ]]
[[ -f $release/services/control-plane/src/ipms/apps/discovery/migrations/0022_hyperv_management.py ]]
grep -Fxq 'project(ipms_agent VERSION 0.2.27 LANGUAGES CXX)' "$release/agent/CMakeLists.txt"
cmp "$previous/deploy/standalone/ipms-tenant-cutover.conf" "$release/deploy/standalone/ipms-tenant-cutover.conf"
/usr/bin/python3.14 -m venv "$release/services/control-plane/.venv"
python="$release/services/control-plane/.venv/bin/python"
manage="$release/services/control-plane/manage.py"
"$python" -m pip install "$release/services/control-plane"
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

# Copy first into a protected destination; hash that immutable copy, not an
# uploader-writable path. Never extract ZIP entries or execute an uploaded file.
if [[ -e $artifact || -L $artifact ]]; then
    protected_file "$artifact"
    printf '%s  %s\n' "$artifact_sha" "$artifact" | sha256sum --check --strict - >/dev/null
else
    install -o root -g ipms-runtime -m 0640 -- "$staged_artifact" "$artifact_next"
    printf '%s  %s\n' "$artifact_sha" "$artifact_next" | sha256sum --check --strict - >/dev/null
    mv -T -- "$artifact_next" "$artifact"
fi
"$python" - "$artifact" "$release" <<'PY'
import pathlib, stat, sys, zipfile
artifact, release = map(pathlib.Path, sys.argv[1:])
expected = {'ipms-agent.exe', 'ipms-agent-config.exe', 'ipms-agent-updater.exe',
            'install-windows-agent.ps1', 'uninstall-windows-agent.ps1', 'import-windows-agent-enrollment.ps1'}
with zipfile.ZipFile(artifact) as archive:
    entries = archive.infolist()
    assert len(entries) == len(expected) and {item.filename for item in entries} == expected
    assert sum(item.file_size for item in entries) <= 128 * 1024 * 1024
    for item in entries:
        assert not item.is_dir() and not item.flag_bits & 1 and 0 < item.file_size <= 64 * 1024 * 1024
        assert not stat.S_ISLNK(item.external_attr >> 16)
        contents = archive.read(item)
        if item.filename.endswith('.ps1'):
            # Windows packaging may carry CRLF; only that newline convention
            # may differ from the immutable Git script contents.
            assert contents.replace(b'\r\n', b'\n') == (release / 'agent' / 'scripts' / item.filename).read_bytes().replace(b'\r\n', b'\n')
        else:
            assert contents[:2] == b'MZ'
            if item.filename == 'ipms-agent.exe':
                assert '0.2.27'.encode('utf-16le') in contents and b'hyperv.vm.management' in contents
print('Agent ZIP hash, exact file allowlist and release script identity verified; binaries were not executed.')
PY
for user in ipms-control-plane ipms-agent-gateway; do
    sudo -n -u "$user" sha256sum "$artifact" | cut -d ' ' -f 1 | grep -Fxq "$artifact_sha"
done
assert_quiescent
assert_administrators
[[ $(readlink -f /srv/ipms/current) == "$previous" ]]

umask 077
# Preserve the existing PostgreSQL-owned backup directory. Root-sensitive
# configuration backups use their own root-controlled parent instead.
if [[ ! -e $backup_root ]]; then mkdir --mode=0700 -- "$backup_root"; fi
protected_directory "$backup_root"
backup=$backup_root/0236-$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -e $backup && ! -L $backup ]]
mkdir --mode=0700 -- "$backup"
# Explicit known-file archive only: no traversal, wildcard or uploaded tar input.
tar --create --file "$backup/configuration.tar" --directory / --no-recursion -- \
    srv/ipms/shared/control-plane.env srv/ipms/shared/web-console.env \
    srv/ipms/shared/agent-gateway.env srv/ipms/shared/console-broker.env \
    srv/ipms/shared/native-console/credential.key etc/nginx/sites-available/ipms
chmod 0600 "$backup/configuration.tar"
tar --list --file "$backup/configuration.tar" >/dev/null
before_preserved=$(sha256sum /srv/ipms/shared/web-console.env /srv/ipms/shared/console-broker.env /srv/ipms/shared/native-console/credential.key /etc/nginx/sites-available/ipms)
units=(ipms-connector-worker.timer ipms-agent-deployment-worker.timer ipms-agent-pki-expiry.timer
    ipms-control-plane.service ipms-web-console.service ipms-agent-gateway.service ipms-console-broker.service
    ipms-connector-worker.service ipms-agent-deployment-worker.service ipms-agent-pki-expiry.service)
restart_units=()
for unit in "${units[@]}"; do
    if systemctl is-active --quiet "$unit"; then restart_units+=("$unit"); fi
    dropin=/etc/systemd/system/$unit.d/60-ipms-tenant-cutover.conf
    protected_file "$dropin"
    cmp "$release/deploy/standalone/ipms-tenant-cutover.conf" "$dropin"
done
for unit in ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker ipms-guacd nginx; do systemctl is-active --quiet "$unit"; done
recover() {
    failure=$?
    if (( BASH_SUBSHELL > 0 )); then exit "$failure"; fi
    trap - ERR INT TERM
    set +e
    install -m 0600 /dev/null "$fence"
    systemctl stop "${units[@]}"
    echo 'Cutover interrupted: application services remain fenced. Do not delete the fence or resume old code by assumption.' >&2
    echo "Protected recovery material: $backup; staged source: $release; Agent artifact: $artifact" >&2
    echo 'Inspect the applied migration, selected commit, jobs, environment and grants; use an explicitly reviewed forward recovery.' >&2
    (( failure != 0 )) || failure=1
    exit "$failure"
}
trap recover ERR INT TERM
install -m 0600 /dev/null "$fence"
systemctl daemon-reload
systemctl stop "${units[@]}"
assert_quiescent
assert_administrators
sudo -n -u postgres pg_dump --format=custom --dbname=ipms > "$backup/ipms.dump"
[[ -s $backup/ipms.dump ]]
pg_restore --list "$backup/ipms.dump" >/dev/null
printf 'Previous commit: %s\nForward commit: %s\nAgent ZIP SHA256: %s\n' "$previous_ref" "$release_ref" "$artifact_sha" > "$backup/identity.txt"

set -a
. /srv/ipms/shared/control-plane.env
set +a
export PYTHONPATH="$release/services/control-plane/src"
"$python" "$manage" migrate discovery 0022_hyperv_management --noinput
"$python" "$manage" migrate --check
(
    # Backup files remain private; preserve the previous release's static
    # directory modes without widening /srv/ipms or nginx group membership.
    umask 022
    "$python" "$manage" collectstatic --noinput
)
sudo -n -u ipms-control-plane test -r "$release/services/control-plane/staticfiles/admin/css/base.css"
"$python" "$manage" check --deploy
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='discovery' AND name='0022_hyperv_management'") == 1 ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname IN ('discovery_hypervmanagementjob','discovery_hypervmanagementsnapshot') AND r.rolname='ipms'
    AND has_table_privilege('ipms',c.oid,'SELECT') AND has_table_privilege('ipms',c.oid,'INSERT')
    AND has_table_privilege('ipms',c.oid,'UPDATE') AND has_table_privilege('ipms',c.oid,'DELETE')") == 2 ]]
[[ $(psql_read "SELECT count(*) FROM discovery_hypervmanagementjob WHERE status IN ('queued','delivered','running','requires_reconciliation')") == 0 ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname IN ('discovery_hypervmanagementjob','discovery_hypervmanagementsnapshot')
    AND has_table_privilege('ipms_console_broker',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')") == 0 ]]
[[ $(broker_acl) == "$before_broker_acl" ]]

# Change only the three versioned artifact settings in the existing protected
# files. Preserve file inode, owner, mode, all secrets and all unrelated settings.
for name in control-plane agent-gateway; do
    file=/srv/ipms/shared/$name.env
    before_metadata=$(stat -c '%u:%g:%a' "$file")
    "$python" - "$file" "$artifact" "$artifact_sha" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
updates = {'IPMS_AGENT_WINDOWS_PACKAGE_PATH': sys.argv[2], 'IPMS_AGENT_WINDOWS_PACKAGE_SHA256': sys.argv[3], 'IPMS_AGENT_WINDOWS_VERSION': '0.2.27'}
with path.open('r+', encoding='utf-8', newline='') as stream:
    lines = stream.read().splitlines()
    for key in updates:
        assert sum(line.startswith(key + '=') for line in lines) == 1
    replacement = '\n'.join(key + '=' + updates[key] if (key := line.partition('=')[0]) in updates else line for line in lines) + '\n'
    stream.seek(0)
    stream.write(replacement)
    stream.truncate()
    stream.flush()
    import os
    os.fsync(stream.fileno())
PY
    [[ $(stat -c '%u:%g:%a' "$file") == "$before_metadata" ]]
done
[[ $(sha256sum /srv/ipms/shared/web-console.env /srv/ipms/shared/console-broker.env /srv/ipms/shared/native-console/credential.key /etc/nginx/sites-available/ipms) == "$before_preserved" ]]
nginx -t
ln -s "$release" "$next_link"
mv -Tf "$next_link" /srv/ipms/current
[[ $(readlink -f /srv/ipms/current) == "$release" ]]
# Release the start fence only after the forward schema, artifact, grants and
# immutable target are verified. Any subsequent checked failure restores it.
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
curl --connect-timeout 2 --max-time 5 --fail --silent --show-error --header "Host: $public_host" --header 'X-Forwarded-Proto: https' \
    http://127.0.0.1:8000/api/v1/ | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == "0.2.36"'
for route in api/v1/hyper-v/virtual-machines/00000000-0000-4000-8000-000000000000/management/ api/v1/auth/account/ api/v1/platform/tenants/ api/v1/service-accounts/ admin/ admin; do
    code=$(curl --connect-timeout 2 --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" "https://$public_host/$route")
    if [[ $route == admin* ]]; then [[ $code == 404 ]]; else [[ $code == 403 ]]; fi
done
ss -lntH 'sport = :9419' | grep -q '0.0.0.0:9419'
ss -lntH 'sport = :9420' | grep -q '127.0.0.1:9420'
ss -lntH 'sport = :4822' | grep -q '127.0.0.1:4822'
test -S /run/ipms-console/agent.sock
[[ $(broker_acl) == "$before_broker_acl" ]]
trap - ERR INT TERM
echo "IPMS 0.2.36 DEV cutover completed; Windows Agent 0.2.27 is staged only. No VM operation or Agent rollout occurred. Protected backup: $backup"
