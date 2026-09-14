#!/usr/bin/env bash
# File Name: deploy-security-baselines-dev.sh
# Version: v0.1.0
# Created: 2026-09-14
# Last Modified: 2026-09-14
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Exact-target IPMS 0.2.43 -> 0.2.44 DEV staging and additive Security baseline cutover.
# The current Windows/Linux Agents and configured Windows package are preserved.
# Recovery is fenced and manual; this script never restores
# a database, rolls migrations back, or resumes a partially applied cutover.
set -Eeuo pipefail
shopt -s inherit_errexit
umask 027
trap 'echo "Deployment stopped at line $LINENO; inspect the reported phase before retrying." >&2' ERR

[[ $EUID == 0 && $# == 6 ]] || { echo 'Usage: deploy-security-baselines-dev.sh HOST MACHINE_ID PUBLIC_HOST PREVIOUS_SHA RELEASE_SHA --preflight|--stage|--activate' >&2; exit 2; }
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
next_link=/srv/ipms/.current-security-next
lock=/run/lock/ipms-tenant-cutover.lock
backup_root=/srv/ipms/shared/security-baseline-backups

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
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.43 ]]
[[ $(git -C "$previous" rev-parse HEAD) == "$previous_ref" ]]
git -C "$previous" diff --exit-code HEAD -- >/dev/null
for path in "$fence" "$next_link"; do [[ ! -e $path && ! -L $path ]]; done
if [[ -e $backup_root || -L $backup_root ]]; then protected "$backup_root"; [[ -d $backup_root ]]; fi
for name in control-plane web-console agent-gateway console-broker; do protected_file "/srv/ipms/shared/$name.env"; done
protected_file /srv/ipms/shared/native-console/credential.key
protected_file /etc/nginx/sites-available/ipms
preserved_files=(/srv/ipms/shared/control-plane.env /srv/ipms/shared/web-console.env
    /srv/ipms/shared/agent-gateway.env /srv/ipms/shared/console-broker.env
    /srv/ipms/shared/native-console/credential.key /etc/nginx/sites-available/ipms
    /etc/nginx/nginx.conf /etc/ipms/tls/server.crt)
# These are already trusted, root-owned shell environment files. Never print
# their content or credentials. Bind the original package as well as its config.
set -a
. /srv/ipms/shared/control-plane.env
set +a
[[ $IPMS_DATABASE_NAME == ipms && $IPMS_DATABASE_USER == ipms && $IPMS_DATABASE_HOST == 127.0.0.1 && $IPMS_DATABASE_PORT == 5432 ]]
[[ $IPMS_AGENT_WINDOWS_PACKAGE_PATH == /srv/ipms/shared/agent-artifacts/* && $IPMS_AGENT_WINDOWS_PACKAGE_SHA256 =~ ^[0-9a-f]{64}$ ]]
protected /srv/ipms/shared/agent-artifacts
protected_file "$IPMS_AGENT_WINDOWS_PACKAGE_PATH"
[[ $(sha256sum "$IPMS_AGENT_WINDOWS_PACKAGE_PATH" | cut -d ' ' -f 1) == "$IPMS_AGENT_WINDOWS_PACKAGE_SHA256" ]]
preserved_files+=("$IPMS_AGENT_WINDOWS_PACKAGE_PATH")
linux_agent_pid=$(systemctl show ipms-agent --property=MainPID --value)
[[ $linux_agent_pid =~ ^[1-9][0-9]*$ ]]
linux_agent_binary=$(readlink -f "/proc/$linux_agent_pid/exe")
protected_file "$linux_agent_binary"
preserved_files+=("$linux_agent_binary")
assert_linux_agent() {
    systemctl is-active --quiet ipms-agent
    [[ $(systemctl show ipms-agent --property=MainPID --value) == "$linux_agent_pid" ]]
    [[ $(sha256sum "/proc/$linux_agent_pid/exe" | cut -d ' ' -f 1) == $(sha256sum "$linux_agent_binary" | cut -d ' ' -f 1) ]]
}
assert_linux_agent
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
configuration_units=("${units[@]}" ipms-guacd.service nginx.service ipms-certificate-probe.service postgresql.service ipms-agent.service)
for unit in "${configuration_units[@]}"; do
    fragment=$(systemctl show "$unit" --property=FragmentPath --value)
    protected_file "$fragment"
    preserved_files+=("$fragment")
    read -r -a dropins <<< "$(systemctl show "$unit" --property=DropInPaths --value)"
    for dropin in "${dropins[@]}"; do protected_file "$dropin"; preserved_files+=("$dropin"); done
done
for path in "${preserved_files[@]}"; do protected_file "$path"; done
preserved_state() {
    # Capture contents, ownership/mode, extended ACLs, unit definitions and ingress
    # configuration without exposing the content of protected files in output.
    {
        sha256sum "${preserved_files[@]}"
        stat -c '%n:%u:%g:%a' -- "${preserved_files[@]}"
        "$previous/services/control-plane/.venv/bin/python" - "${preserved_files[@]}" <<'PYATTR'
import hashlib, os, sys
digest = hashlib.sha256()
for path in sys.argv[1:]:
    # POSIX ACLs are included as system.posix_acl_* extended attributes. Attribute
    # names and values remain inside this process; only their digest is emitted.
    value = os.fsencode(path)
    digest.update(len(value).to_bytes(8, 'big'))
    digest.update(value)
    for name in sorted(os.listxattr(path, follow_symlinks=False)):
        for value in (os.fsencode(name), os.getxattr(path, name, follow_symlinks=False)):
            digest.update(len(value).to_bytes(8, 'big'))
            digest.update(value)
print(digest.hexdigest())
PYATTR
        systemctl cat "${configuration_units[@]}"
        nginx -T 2>/dev/null
    } | sha256sum | cut -d ' ' -f 1
}
preserved=$(preserved_state)
for unit in ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker ipms-guacd nginx; do systemctl is-active --quiet "$unit"; done
psql_read() { sudo -n -u postgres env PGOPTIONS='-c default_transaction_read_only=on' psql -XAt --set=ON_ERROR_STOP=1 --dbname=ipms -c "$1"; }
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
    # Adding the Security table must not alter existing privileges or ownership.
    # The existing WSUS tables and all their ACLs remain in this fingerprint.
    psql_read "SELECT md5(coalesce(string_agg(value, E'\\n' ORDER BY value),'')) FROM (
        SELECT 'relation:' || c.relname || ':' || c.relowner || ':' || coalesce(c.relacl::text,'') value
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p','S','v','m','f') AND c.relname NOT LIKE 'security\\_%' ESCAPE '\\'
        UNION ALL SELECT 'column:' || c.relname || ':' || a.attname || ':' || a.attacl::text
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND a.attacl IS NOT NULL AND c.relname NOT LIKE 'security\\_%' ESCAPE '\\'
        UNION ALL SELECT 'schema:' || nspowner || ':' || coalesce(nspacl::text,'') FROM pg_namespace WHERE nspname='public'
        UNION ALL SELECT 'database:' || datdba || ':' || coalesce(datacl::text,'') FROM pg_database WHERE datname='ipms'
        UNION ALL SELECT 'default:' || defaclrole || ':' || defaclnamespace || ':' || defaclobjtype::text || ':' || defaclacl::text
        FROM pg_default_acl
        UNION ALL SELECT 'membership:' || roleid || ':' || member || ':' || admin_option FROM pg_auth_members
    ) permissions"
}
assert_database_owner() {
    [[ $(psql_read "SELECT count(*) FROM pg_roles r JOIN pg_database d ON d.datdba=r.oid
        WHERE r.rolname='ipms' AND d.datname='ipms' AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolbypassrls") == 1 ]]
    [[ $(psql_read "SELECT count(*) FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
        WHERE n.nspname='public' AND r.rolname IN ('ipms','pg_database_owner')
        AND has_schema_privilege('ipms',n.oid,'USAGE') AND has_schema_privilege('ipms',n.oid,'CREATE')") == 1 ]]
    [[ $(psql_read "SELECT count(*) FROM pg_roles WHERE rolname='ipms_console_broker'
        AND NOT rolsuper AND NOT rolcreaterole AND NOT rolbypassrls") == 1 ]]
    [[ $(psql_read "SELECT has_schema_privilege('ipms_console_broker','public','CREATE')") == f ]]
    [[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND r.rolname='ipms'
        AND c.relname IN ('django_migrations','discovery_softwareinventorysnapshot','discovery_hypervsettingslease')") == 3 ]]
}
assert_unmigrated() {
    [[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='security'") == 0 ]]
    [[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relname LIKE 'security\\_%' ESCAPE '\\'") == 0 ]]
    [[ $(psql_read "SELECT count(*) FROM django_migrations WHERE (app='discovery' AND name='0024_software_windows_update_evidence')
        OR (app='updates' AND name IN ('0001_initial','0002_wsus_server_settings'))") == 3 ]]
}
assert_quiescent
assert_administrators
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='discovery' AND name='0022_hyperv_management'") == 1 ]]
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='discovery' AND name='0023_hypervsettingslease'") == 1 ]]
assert_database_owner
assert_unmigrated
before_broker_acl=$(broker_acl)
[[ $before_broker_acl =~ ^[0-9a-f]{32}$ ]]
if [[ $mode == --preflight ]]; then
    echo 'Exact-target runtime preflight passed. No release, database, environment, fence or service changed.'
    exit 0
fi

python=$release/services/control-plane/.venv/bin/python
manage=$release/services/control-plane/manage.py
receipt=$release/security-0244-stage.sha256
stage_state=$release/security-0244-stage-state.txt
# The release checkout must already be created from a checksum-verified local
# Git bundle or a published commit. The immutable commit is checked below;
# deployment does not require or perform public source publication.
protected "$release"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.44 ]]
git -C "$release" diff --exit-code HEAD -- >/dev/null
# Existing ingress, service isolation, broker, dependencies and authentication
# contracts must remain unchanged. Only the Security app, registration and
# application version may differ; existing Agent/WSUS code cannot change.
git -C "$release" diff --exit-code "$previous_ref" "$release_ref" -- \
    agent deploy services/console-broker apps/web-console/pnpm-lock.yaml \
    services/control-plane/src/ipms/apps/agent_pki \
    services/control-plane/src/ipms/apps/discovery \
    services/control-plane/src/ipms/apps/updates \
    services/control-plane/src/ipms/apps/tenancy \
    services/control-plane/src/ipms/apps/audit >/dev/null
"$previous/services/control-plane/.venv/bin/python" - "$previous" "$release" <<'PY'
import json, pathlib, subprocess, sys, tomllib
previous, release = map(pathlib.Path, sys.argv[1:])
changed = set(subprocess.check_output([
    'git', '-C', str(release), 'diff', '--name-only', '-z',
    subprocess.check_output(['git', '-C', str(previous), 'rev-parse', 'HEAD'], text=True).strip(),
    'HEAD', '--', 'services/control-plane',
]).decode().rstrip('\0').split('\0'))
allowed = {
    'services/control-plane/pyproject.toml',
    'services/control-plane/src/ipms/apps/core/tests.py',
    'services/control-plane/src/ipms/apps/core/urls.py',
    'services/control-plane/src/ipms/apps/core/views.py',
    'services/control-plane/src/ipms_control_plane/settings/base.py',
}
assert all(name in allowed or name.startswith('services/control-plane/src/ipms/apps/security/') for name in changed), 'Unreviewed control-plane source change'
for relative, addition in {
    'services/control-plane/src/ipms_control_plane/settings/base.py': '    "ipms.apps.security",\n',
    'services/control-plane/src/ipms/apps/core/urls.py': '    path("security/", include("ipms.apps.security.urls")),\n',
}.items():
    before, after = ((root / relative).read_text() for root in (previous, release))
    assert after.count(addition) == 1 and after.replace(addition, '', 1) == before, 'Unexpected existing configuration/model change'
relative = 'services/control-plane/src/ipms/apps/core/views.py'
before, after = ((root / relative).read_text() for root in (previous, release))
assert after.replace('"application_version": "0.2.44"', '"application_version": "0.2.43"') == before, 'Unexpected core API view change'
for relative, parse in [('services/control-plane/pyproject.toml', tomllib.loads), ('apps/web-console/package.json', json.loads)]:
    before, after = (parse((root / relative).read_text()) for root in (previous, release))
    if relative.endswith('.toml'):
        before['project']['version'] = after['project']['version']
    else:
        before['version'] = after['version']
    assert before == after, 'Dependency or build manifest changed'
PY
if [[ $mode == --stage ]]; then
    umask 022
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
    umask 027
fi
set -a
. /srv/ipms/shared/control-plane.env
set +a
export PYTHONPATH="$release/services/control-plane/src"
[[ $IPMS_DATABASE_NAME == ipms && $IPMS_DATABASE_USER == ipms && $IPMS_DATABASE_HOST == 127.0.0.1 && $IPMS_DATABASE_PORT == 5432 ]]
django_read() { PGOPTIONS='-c default_transaction_read_only=on' "$python" "$manage" "$@"; }
assert_pending_migrations() {
    # The candidate loads its actual PostgreSQL connection using the existing
    # ipms credentials. PostgreSQL enforces read-only transactions during stage.
    django_read shell --no-imports -c "
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
assert connection.vendor == 'postgresql'
with connection.cursor() as cursor:
    cursor.execute(\"SELECT current_user, session_user, current_database(), current_schema(), current_setting('transaction_read_only')\")
    assert cursor.fetchone() == ('ipms', 'ipms', 'ipms', 'public', 'on')
executor = MigrationExecutor(connection)
executor.loader.check_consistent_history(connection)
plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
expected = {('security', '0001_initial', False)}
actual = [(migration.app_label, migration.name, backwards) for migration, backwards in plan]
assert len(actual) == 1 and set(actual) == expected, 'Unexpected pending migration plan'
"
}
assert_pending_migrations
# Exercise the real API view before any outage. Manifest/footer version checks
# alone do not detect an accidentally stale API information constant.
django_read shell --no-imports -c "from rest_framework.test import APIRequestFactory; from ipms.apps.core.views import api_information; r=api_information(APIRequestFactory().get('/api/v1/')); assert r.status_code == 200 and r.data['application_version'] == '0.2.44'"
django_read check --deploy
sudo -n -u ipms-control-plane test -x "$python"
sudo -n -u ipms-web test -r "$release/apps/web-console/.next/standalone/server.js"
[[ $(preserved_state) == "$preserved" && $(broker_acl) == "$before_broker_acl" ]]
if [[ $mode == --stage ]]; then
    (umask 022; django_read collectstatic --noinput)
    assert_pending_migrations
    assert_unmigrated
    assert_database_owner
    printf '%s\n' "$expected_host" "$expected_machine" "$public_host" "$previous_ref" "$release_ref" "$preserved" "$before_broker_acl" > "$stage_state"
    protected_file "$stage_state"
    sha256sum "$release/apps/web-console/.next/standalone/server.js" \
        "$release/apps/web-console/.next/BUILD_ID" "$release/VERSION" \
        "$stage_state" \
        "$release/services/control-plane/runtime-requirements.txt" \
        "$release/services/control-plane/src/ipms/apps/security/migrations/0001_initial.py" > "$receipt"
    protected_file "$receipt"
    [[ $(readlink -f /srv/ipms/current) == "$previous" && $(preserved_state) == "$preserved" && $(broker_acl) == "$before_broker_acl" ]]
    echo 'IPMS 0.2.44 candidate staged; exactly one additive migration pending. Runtime remains 0.2.43. No live database or Agent change.'
    exit 0
fi
protected_file "$receipt"
sha256sum --check --strict "$receipt" >/dev/null
protected_file "$stage_state"
[[ $(cat "$stage_state") == "$(printf '%s\n' "$expected_host" "$expected_machine" "$public_host" "$previous_ref" "$release_ref" "$preserved" "$before_broker_acl")" ]]
sudo -n -u ipms-control-plane test -r "$release/services/control-plane/staticfiles/admin/css/base.css"
assert_quiescent
assert_administrators
[[ $(readlink -f /srv/ipms/current) == "$previous" ]]
umask 077
if [[ ! -e $backup_root ]]; then mkdir --mode=0700 -- "$backup_root"; fi
protected "$backup_root"
backup=$backup_root/0244-$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -e $backup && ! -L $backup ]]
mkdir --mode=0700 -- "$backup"
tar --create --file "$backup/configuration.tar" --directory / --no-recursion --acls --xattrs -- "${preserved_files[@]#/}"
tar --list --file "$backup/configuration.tar" >/dev/null
printf 'Previous commit: %s\nForward commit: %s\n' "$previous_ref" "$release_ref" > "$backup/identity.txt"
printf '%s\n' "${restart_units[@]}" > "$backup/previous-active-units.txt"
cp -- "$receipt" "$stage_state" "$backup/"
printf '%s\n' "$preserved" "$before_broker_acl" > "$backup/preserved-state.txt"
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
for unit in "${units[@]}"; do
    state=$(systemctl show "$unit" --property=ActiveState --value)
    [[ $state == inactive || $state == failed ]]
done
assert_quiescent
assert_administrators
assert_database_owner
assert_unmigrated
assert_pending_migrations
sudo -n -u postgres pg_dump --format=custom --dbname=ipms > "$backup/ipms.dump"
[[ -s $backup/ipms.dump ]]
pg_restore --list "$backup/ipms.dump" >/dev/null
sha256sum "$backup/ipms.dump" "$backup/configuration.tar" > "$backup/backup.sha256"
# This is the only writable Django invocation. It uses the existing ipms
# database-owner credentials (not the postgres operating-system account).
# The pending set was revalidated after all writers stopped and before backup.
PGOPTIONS='-c default_transaction_read_only=off' "$python" "$manage" shell --no-imports -c "
from django.core.management import call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
with connection.cursor() as cursor:
    cursor.execute('SELECT current_user, session_user, current_database(), current_schema()')
    assert cursor.fetchone() == ('ipms', 'ipms', 'ipms', 'public')
executor = MigrationExecutor(connection)
plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
actual = [(migration.app_label, migration.name, backwards) for migration, backwards in plan]
assert len(actual) == 1 and set(actual) == {('security', '0001_initial', False)}
call_command('migrate', interactive=False)
"
django_read migrate --check
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE app='security' AND name='0001_initial'") == 1 ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind='r' AND r.rolname='ipms' AND c.relname='security_baselineassessment'
    AND has_table_privilege('ipms',c.oid,'SELECT') AND has_table_privilege('ipms',c.oid,'INSERT')
    AND has_table_privilege('ipms',c.oid,'UPDATE') AND has_table_privilege('ipms',c.oid,'DELETE')") == 1 ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname LIKE 'security\\_%' ESCAPE '\\'
    AND CASE WHEN c.relkind IN ('r','p') THEN
      (has_table_privilege('ipms_console_broker',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      OR has_any_column_privilege('ipms_console_broker',c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
      WHEN c.relkind='S' THEN has_sequence_privilege('ipms_console_broker',c.oid,'USAGE,SELECT,UPDATE')
      ELSE false END") == 0 ]]
[[ $(psql_read "SELECT count(*) FROM security_baselineassessment") == 0 ]]
# Existing schema-2 Update Agent evidence and WSUS configuration stay intact.
[[ $(psql_read "SELECT count(*) FROM django_migrations WHERE (app='discovery' AND name='0024_software_windows_update_evidence')
    OR (app='updates' AND name IN ('0001_initial','0002_wsus_server_settings'))") == 3 ]]
assert_database_owner
assert_administrators
[[ $(broker_acl) == "$before_broker_acl" && $(preserved_state) == "$preserved" ]]
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
    http://127.0.0.1:8000/api/v1/ | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == "0.2.44"'
for route in en/login de/login api/v1/security/baselines/ api/v1/security/baselines/microsoft-windows-server-2025/systems/ api/v1/hyper-v/virtual-machines/00000000-0000-4000-8000-000000000000/management/dialog/ api/v1/auth/account/ api/v1/platform/tenants/ api/v1/service-accounts/ api/v1/update-sources/ api/v1/update-sources/00000000-0000-4000-8000-000000000000/comparison/ api/v1/update-sources/00000000-0000-4000-8000-000000000000/servers/00000000-0000-4000-8000-000000000000/updates/ admin/ admin; do
    code=$(curl --connect-timeout 2 --max-time 10 --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" "https://$public_host/$route")
    if [[ $route == */login ]]; then [[ $code == 200 ]]; elif [[ $route == admin* ]]; then [[ $code == 404 ]]; else [[ $code == 403 ]]; fi
done
code=$(curl --connect-timeout 2 --max-time 10 --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" \
    --header 'Content-Type: application/json' --data '{}' \
    "https://$public_host/api/v1/update-sources/00000000-0000-4000-8000-000000000000/snapshots/")
[[ $code == 401 ]]
ss -lntH 'sport = :9419' | grep -q '0.0.0.0:9419'
ss -lntH 'sport = :9420' | grep -q '127.0.0.1:9420'
ss -lntH 'sport = :4822' | grep -q '127.0.0.1:4822'
test -S /run/ipms-console/agent.sock
[[ $(broker_acl) == "$before_broker_acl" && $(preserved_state) == "$preserved" ]]
assert_database_owner
assert_administrators
git -C "$release" diff --exit-code HEAD -- >/dev/null
assert_linux_agent
trap - ERR INT TERM
echo "IPMS 0.2.44 DEV Security activation verified; one additive migration applied as ipms. Current Agents, package, WSUS integration and environments preserved. Backup: $backup"
