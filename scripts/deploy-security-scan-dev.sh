#!/usr/bin/env bash
# File Name: deploy-security-scan-dev.sh
# Version: v0.1.0
# Created: 2026-09-14
# Last Modified: 2026-09-14
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Exact-target IPMS 0.2.44 -> 0.2.45 DEV Security visibility and native scan cutover.
# The configured Windows 0.2.30 package and running Linux Agent are preserved.
# Agent 0.2.31 artifacts are staged separately; this script never builds, installs,
# configures or deploys an Agent package and never queues a baseline scan.
# Recovery is fenced and manual; this script never restores
# a database, rolls migrations back, or resumes a partially applied cutover.
set -Eeuo pipefail
shopt -s inherit_errexit
umask 027
trap 'echo "Deployment stopped at line $LINENO; inspect the reported phase before retrying." >&2' ERR

[[ $EUID == 0 && $# == 6 ]] || { echo 'Usage: deploy-security-scan-dev.sh HOST MACHINE_ID PUBLIC_HOST PREVIOUS_SHA RELEASE_SHA --preflight|--stage|--activate' >&2; exit 2; }
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
next_link=/srv/ipms/.current-security-scan-next
lock=/run/lock/ipms-tenant-cutover.lock
backup_root=/srv/ipms/shared/security-scan-backups

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
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.44 ]]
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
[[ $IPMS_AGENT_WINDOWS_VERSION == 0.2.30 ]]
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
    if [[ $(psql_read "SELECT to_regclass('public.security_baselinescanjob') IS NOT NULL") == t ]]; then
        [[ $(psql_read "SELECT count(*) FROM security_baselinescanjob WHERE status IN ('queued','running')") == 0 ]] || {
            echo 'Active Security scans prevent this cutover.' >&2; return 1;
        }
    fi
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
    # New tables may be added; the existing assessment table, WSUS tables and
    # all pre-existing privileges and ownership stay in this fingerprint.
    psql_read "SELECT md5(coalesce(string_agg(value, E'\\n' ORDER BY value),'')) FROM (
        SELECT 'relation:' || c.relname || ':' || c.relowner || ':' || coalesce(c.relacl::text,'') value
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p','S','v','m','f')
        AND c.relname NOT IN ('security_baselinepreference','security_baselinescanjob')
        UNION ALL SELECT 'column:' || c.relname || ':' || a.attname || ':' || a.attacl::text
        FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND a.attacl IS NOT NULL
        AND c.relname NOT IN ('security_baselinepreference','security_baselinescanjob')
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
        AND c.relname IN ('django_migrations','discovery_softwareinventorysnapshot','discovery_hypervsettingslease','security_baselineassessment')") == 4 ]]
}
assert_unmigrated() {
    [[ $(psql_read "SELECT string_agg(name,',' ORDER BY name) FROM django_migrations WHERE app='security'") == 0001_initial ]]
    [[ $(psql_read "SELECT to_regclass('public.security_baselineassessment') IS NOT NULL
        AND to_regclass('public.security_baselinepreference') IS NULL AND to_regclass('public.security_baselinescanjob') IS NULL") == t ]]
    [[ $(psql_read "SELECT count(*) FROM information_schema.columns WHERE table_schema='public'
        AND table_name='security_baselineassessment' AND column_name IN ('content_sha256','findings')") == 0 ]]
    [[ $(psql_read "SELECT count(*) FROM django_migrations WHERE (app='discovery' AND name='0024_software_windows_update_evidence')
        OR (app='updates' AND name IN ('0001_initial','0002_wsus_server_settings'))") == 3 ]]
}
assessment_fingerprint() {
    # New 0003 fields are excluded on both sides; existing rows and every old
    # field must survive. Only a digest leaves PostgreSQL, never assessment data.
    psql_read "SELECT md5(coalesce(string_agg((to_jsonb(a) - 'content_sha256' - 'findings')::text,
        E'\\n' ORDER BY id),'')) FROM security_baselineassessment a"
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
receipt=$release/security-0245-stage.sha256
stage_state=$release/security-0245-stage-state.txt
# The release checkout must already be created from a checksum-verified local
# Git bundle or a published commit. The immutable commit is checked below;
# deployment does not require or perform public source publication.
protected "$release"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.45 ]]
git -C "$release" merge-base --is-ancestor "$previous_ref" "$release_ref"
git -C "$release" diff --exit-code HEAD -- >/dev/null
# Existing ingress, service isolation, broker, dependencies, WSUS and discovery
# contracts remain unchanged. Agent source may change only at the reviewed
# native scan seams below; the existing binaries/packages remain in service.
git -C "$release" diff --exit-code "$previous_ref" "$release_ref" -- \
    deploy services/console-broker apps/web-console/pnpm-lock.yaml \
    services/control-plane/src/ipms/apps/discovery \
    services/control-plane/src/ipms/apps/updates \
    services/control-plane/src/ipms/apps/audit >/dev/null
"$previous/services/control-plane/.venv/bin/python" - "$previous" "$release" <<'PY'
import json, pathlib, stat, subprocess, sys, tomllib
previous, release = map(pathlib.Path, sys.argv[1:])
changes = subprocess.check_output([
    'git', '-C', str(release), 'diff', '--name-status', '--no-renames', '-z',
    subprocess.check_output(['git', '-C', str(previous), 'rev-parse', 'HEAD'], text=True).strip(),
    'HEAD', '--',
]).decode().rstrip('\0').split('\0')
assert len(changes) % 2 == 0, 'Invalid source change list'
changed = {changes[index + 1] for index in range(0, len(changes), 2)}
assert all(changes[index] in ('A', 'M') for index in range(0, len(changes), 2)), 'Source deletions or renames require review'
allowed = {
    'README.md',
    'ROADMAP.md',
    'VERSION',
    'agent/CMakeLists.txt',
    'agent/README.md',
    'agent/include/ipms/agent/gateway_contract.hpp',
    'agent/include/ipms/agent/security_baseline.hpp',
    'agent/include/ipms/agent/security_baseline_content.hpp',
    'agent/include/ipms/agent/windows_core_pack.hpp',
    'agent/include/ipms/agent/windows_security_scan.hpp',
    'agent/include/ipms/agent/windows_transport.hpp',
    'agent/scripts/install-windows-agent.ps1',
    'agent/src/gateway_contract.cpp',
    'agent/src/main.cpp',
    'agent/src/security_baseline.cpp',
    'agent/src/windows/windows_core_pack.cpp',
    'agent/src/windows/windows_security_scan.cpp',
    'agent/src/windows/windows_service.cpp',
    'agent/src/windows/windows_transport.cpp',
    'agent/tests/management_pack_tests.cpp',
    'agent/tests/security_scan_contract_tests.cpp',
    'agent/tests/windows_security_scan_tests.cpp',
    'apps/web-console/package.json',
    'apps/web-console/src/app/[locale]/administration/security/baselines/page.tsx',
    'apps/web-console/src/app/[locale]/security/baseline/page.tsx',
    'apps/web-console/src/app/[locale]/security/baseline/[baselineId]/systems/[systemId]/findings/page.tsx',
    'apps/web-console/src/components/console-shell.tsx',
    'apps/web-console/src/components/sidebar.tsx',
    'apps/web-console/src/components/security-baseline-administration.tsx',
    'apps/web-console/src/components/security-baseline-administration.module.css',
    'apps/web-console/src/components/security-baseline-scans.tsx',
    'apps/web-console/src/components/security-baseline-scans.module.css',
    'apps/web-console/src/i18n/dictionaries/de.ts',
    'apps/web-console/src/i18n/dictionaries/en.ts',
    'apps/web-console/src/i18n/security-copy.ts',
    'apps/web-console/src/i18n/security-scan-copy.ts',
    'apps/web-console/src/lib/auth-types.ts',
    'apps/web-console/src/lib/security-types.ts',
    'apps/web-console/src/lib/security-scan-validation.ts',
    'apps/web-console/src/lib/server-security.ts',
    'apps/web-console/tests/fixtures/seed-security.py',
    'apps/web-console/tests/fixtures/complete-security-scan.py',
    'apps/web-console/tests/security-baselines.spec.ts',
    'docs/architecture/ADR-0015-SECURITY-BASELINES.md',
    'docs/operations/SECURITY-BASELINES.md',
    'docs/operations/SECURITY-SCAN-0245-VERIFICATION.md',
    'scripts/deploy-security-scan-dev.sh',
    'scripts/import-security-baselines.py',
    'scripts/tests/test_security_content.py',
    'services/control-plane/pyproject.toml',
    'services/control-plane/src/ipms/apps/agent_pki/gateway.py',
    'services/control-plane/src/ipms/apps/core/tests.py',
    'services/control-plane/src/ipms/apps/core/views.py',
    'services/control-plane/src/ipms/apps/tenancy/rbac.py',
    'services/control-plane/src/ipms/apps/security/administration.py',
    'services/control-plane/src/ipms/apps/security/catalog.py',
    'services/control-plane/src/ipms/apps/security/content.py',
    'services/control-plane/src/ipms/apps/security/evaluator.py',
    'services/control-plane/src/ipms/apps/security/models.py',
    'services/control-plane/src/ipms/apps/security/scan_views.py',
    'services/control-plane/src/ipms/apps/security/scans.py',
    'services/control-plane/src/ipms/apps/security/services.py',
    'services/control-plane/src/ipms/apps/security/test_administration.py',
    'services/control-plane/src/ipms/apps/security/test_scans.py',
    'services/control-plane/src/ipms/apps/security/tests.py',
    'services/control-plane/src/ipms/apps/security/urls.py',
    'services/control-plane/src/ipms/apps/security/views.py',
    'services/control-plane/src/ipms/apps/security/migrations/0002_baseline_visibility.py',
    'services/control-plane/src/ipms/apps/security/migrations/0003_native_baseline_scans.py',
}
assert changed <= allowed, 'Unreviewed source paths: ' + ', '.join(sorted(changed - allowed))
for relative in changed:
    entry = subprocess.check_output(['git', '--literal-pathspecs', '-C', str(release), 'ls-tree', '-z', 'HEAD', '--', relative]).decode().rstrip('\0')
    identity, name = entry.split('\t', 1)
    mode, kind, _ = identity.split()
    assert name == relative and mode in ('100644', '100755') and kind == 'blob', 'Source is not a regular tracked file'
    path = release / relative
    assert path.resolve(strict=True) == path and path.is_file(), 'Source path is redirected'
    assert path.stat().st_nlink == 1, 'Hard-linked source file'
    while path != release:
        metadata = path.stat()
        assert metadata.st_uid == 0 and not stat.S_IMODE(metadata.st_mode) & 0o022, 'Source path is writable by another identity'
        path = path.parent
relative = 'services/control-plane/src/ipms/apps/core/views.py'
before, after = ((root / relative).read_text() for root in (previous, release))
assert after.count('"application_version": "0.2.45"') == 1
assert after.replace('"application_version": "0.2.45"', '"application_version": "0.2.44"') == before, 'Unexpected core API view change'
for relative, parse in [('services/control-plane/pyproject.toml', tomllib.loads), ('apps/web-console/package.json', json.loads)]:
    before, after = (parse((root / relative).read_text()) for root in (previous, release))
    if relative.endswith('.toml'):
        assert before['project']['version'] == '0.2.44' and after['project']['version'] == '0.2.45'
        before['project']['version'] = after['project']['version']
    else:
        assert before['version'] == '0.2.44' and after['version'] == '0.2.45'
        before['version'] = after['version']
    assert before == after, 'Dependency or build manifest changed'
PY
if [[ $mode == --stage ]]; then
    # A failed stage is not resumed in place. Refuse pre-existing build targets
    # so a symlink or partial environment cannot redirect writes into runtime.
    for path in "$release/services/control-plane/.venv" \
        "$release/services/control-plane/runtime-requirements.txt" \
        "$release/services/control-plane/staticfiles" \
        "$release/apps/web-console/node_modules" "$release/apps/web-console/.next" \
        "$receipt" "$stage_state"; do
        [[ ! -e $path && ! -L $path ]]
    done
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
for path in "$release/services/control-plane/.venv" "$release/services/control-plane/.venv/bin" \
    "$release/apps/web-console/.next" "$release/apps/web-console/.next/standalone"; do
    protected "$path"; [[ -d $path ]]
done
for path in "$release/services/control-plane/runtime-requirements.txt" \
    "$release/apps/web-console/.next/standalone/server.js" "$release/apps/web-console/.next/BUILD_ID"; do
    protected_file "$path"
done
[[ $(readlink "$release/apps/web-console/.next/standalone/.next/cache") == /srv/ipms/shared/web-cache ]]
set -a
. /srv/ipms/shared/control-plane.env
set +a
export PYTHONPATH="$release/services/control-plane/src"
[[ $IPMS_DATABASE_NAME == ipms && $IPMS_DATABASE_USER == ipms && $IPMS_DATABASE_HOST == 127.0.0.1 && $IPMS_DATABASE_PORT == 5432 ]]
[[ $IPMS_AGENT_WINDOWS_VERSION == 0.2.30 ]]
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
expected = [('security', '0002_baseline_visibility', False), ('security', '0003_native_baseline_scans', False)]
actual = [(migration.app_label, migration.name, backwards) for migration, backwards in plan]
assert actual == expected, 'Unexpected pending migration plan'
"
}
assert_pending_migrations
# Exercise the real API view before any outage. Manifest/footer version checks
# alone do not detect an accidentally stale API information constant.
django_read shell --no-imports -c "from rest_framework.test import APIRequestFactory; from ipms.apps.core.views import api_information; r=api_information(APIRequestFactory().get('/api/v1/')); assert r.status_code == 200 and r.data['application_version'] == '0.2.45'"
django_read check --deploy
sudo -n -u ipms-control-plane test -x "$python"
sudo -n -u ipms-web test -r "$release/apps/web-console/.next/standalone/server.js"
[[ $(preserved_state) == "$preserved" && $(broker_acl) == "$before_broker_acl" ]]
if [[ $mode == --stage ]]; then
    (umask 022; django_read collectstatic --noinput)
    assert_pending_migrations
    assert_unmigrated
    assert_database_owner
    assert_linux_agent
    printf '%s\n' "$expected_host" "$expected_machine" "$public_host" "$previous_ref" "$release_ref" "$preserved" "$before_broker_acl" "$linux_agent_pid" > "$stage_state"
    protected_file "$stage_state"
    sha256sum "$release/apps/web-console/.next/standalone/server.js" \
        "$release/apps/web-console/.next/BUILD_ID" "$release/VERSION" \
        "$stage_state" \
        "$release/services/control-plane/runtime-requirements.txt" \
        "$release/services/control-plane/src/ipms/apps/security/migrations/0001_initial.py" \
        "$release/services/control-plane/src/ipms/apps/security/migrations/0002_baseline_visibility.py" \
        "$release/services/control-plane/src/ipms/apps/security/migrations/0003_native_baseline_scans.py" \
        "$release/services/control-plane/src/ipms/apps/security/content.py" \
        "$release/agent/include/ipms/agent/security_baseline_content.hpp" > "$receipt"
    protected_file "$receipt"
    [[ $(readlink -f /srv/ipms/current) == "$previous" && $(preserved_state) == "$preserved" && $(broker_acl) == "$before_broker_acl" ]]
    echo 'IPMS 0.2.45 candidate staged; exactly Security 0002 and 0003 pending. Runtime remains 0.2.44. Windows 0.2.30 package and running Linux Agent preserved.'
    exit 0
fi
protected_file "$receipt"
sha256sum --check --strict "$receipt" >/dev/null
protected_file "$stage_state"
[[ $(cat "$stage_state") == "$(printf '%s\n' "$expected_host" "$expected_machine" "$public_host" "$previous_ref" "$release_ref" "$preserved" "$before_broker_acl" "$linux_agent_pid")" ]]
sudo -n -u ipms-control-plane test -r "$release/services/control-plane/staticfiles/admin/css/base.css"
assert_quiescent
assert_administrators
[[ $(readlink -f /srv/ipms/current) == "$previous" ]]
umask 077
if [[ ! -e $backup_root ]]; then mkdir --mode=0700 -- "$backup_root"; fi
protected "$backup_root"
backup=$backup_root/0245-$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -e $backup && ! -L $backup ]]
mkdir --mode=0700 -- "$backup"
tar --create --file "$backup/configuration.tar" --directory / --no-recursion --acls --xattrs -- "${preserved_files[@]#/}"
tar --list --file "$backup/configuration.tar" >/dev/null
printf 'Previous commit: %s\nForward commit: %s\n' "$previous_ref" "$release_ref" > "$backup/identity.txt"
printf '%s\n' "${restart_units[@]}" > "$backup/previous-active-units.txt"
cp -- "$receipt" "$stage_state" "$backup/"
printf '%s\n' "$preserved" "$before_broker_acl" > "$backup/preserved-state.txt"
cat > "$backup/RECOVERY.md" <<'RECOVERY'
# Security 0.2.45 fenced recovery

Keep the cutover fence and application writers stopped while investigating.
This script neither reverses migrations nor restores the database. A missing
or failed backup check does not authorize a retry beyond the failed phase.

Verify the current release, migration history, archive checksums, captured
active units and any jobs or writes accepted after the snapshot. Prefer a
reviewed forward repair that retains the 0.2.45 schema and evidence.

Do not restart 0.2.44 against populated new preference/job tables. Its ORM does
not know their foreign keys to tenants, systems, enrollments, users and existing
assessments; cleanup or deletion can fail despite an otherwise additive schema.

Before an authorized return to 0.2.44, reconcile all post-snapshot operations.
Choose either an explicitly reviewed restore of the verified pre-cutover dump,
or an explicitly reviewed reverse of only Security 0003 and 0002 using the
candidate migration code. Reverse migration deletes preferences and scan jobs,
and drops content hashes and findings from every assessment. Archive required
evidence first; newly accepted assessments must not silently become trusted
legacy receipts after their content hashes are removed. A database restore also
discards every post-snapshot write, so it requires a separate reconciliation.

Verify that only Security 0001 remains, the new tables/columns are absent, the
retained assessment semantics and old runtime agree, and preserved configuration,
ACLs and WSUS state match. Only then switch the release and explicitly reopen
the fence and previously active units. The running Linux Agent and configured
Windows package were not replaced and require no automatic rollback.
RECOVERY
recover() {
    local failure=$?
    if (( BASH_SUBSHELL > 0 )); then exit "$failure"; fi
    trap - ERR INT TERM
    set +e
    install -m 0600 /dev/null "$fence"
    systemctl stop "${units[@]}"
    echo "Cutover interrupted; application services remain fenced. Recovery material: $backup" >&2
    echo 'Review migration state, current release and accepted jobs before forward recovery or rollback; never restore a database or remove the fence by assumption.' >&2
    echo "Read $backup/RECOVERY.md before starting 0.2.44: new foreign keys and removal of findings require explicit reconciliation." >&2
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
before_assessments=$(assessment_fingerprint)
[[ $before_assessments =~ ^[0-9a-f]{32}$ ]]
printf '%s\n' "$before_assessments" > "$backup/assessment-fingerprint.txt"
sudo -n -u postgres pg_dump --format=custom --dbname=ipms > "$backup/ipms.dump"
[[ -s $backup/ipms.dump ]]
protected_file "$backup/ipms.dump"
pg_restore --list "$backup/ipms.dump" >/dev/null
# Read and decompress the entire archive without executing its SQL. A later
# restore still needs separate authorization and post-snapshot reconciliation.
pg_restore --file /dev/null "$backup/ipms.dump"
sha256sum "$backup/ipms.dump" "$backup/configuration.tar" > "$backup/backup.sha256"
sha256sum --check --strict "$backup/backup.sha256" >/dev/null
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
assert actual == [('security', '0002_baseline_visibility', False), ('security', '0003_native_baseline_scans', False)]
call_command('migrate', 'security', '0003_native_baseline_scans', interactive=False)
"
django_read migrate --check
[[ $(psql_read "SELECT string_agg(name,',' ORDER BY name) FROM django_migrations WHERE app='security'") == 0001_initial,0002_baseline_visibility,0003_native_baseline_scans ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind='r' AND r.rolname='ipms'
    AND c.relname IN ('security_baselineassessment','security_baselinepreference','security_baselinescanjob')
    AND has_table_privilege('ipms',c.oid,'SELECT') AND has_table_privilege('ipms',c.oid,'INSERT')
    AND has_table_privilege('ipms',c.oid,'UPDATE') AND has_table_privilege('ipms',c.oid,'DELETE')") == 3 ]]
[[ $(psql_read "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname LIKE 'security\\_%' ESCAPE '\\'
    AND CASE WHEN c.relkind IN ('r','p') THEN
      (has_table_privilege('ipms_console_broker',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
      OR has_any_column_privilege('ipms_console_broker',c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))
      WHEN c.relkind='S' THEN has_sequence_privilege('ipms_console_broker',c.oid,'USAGE,SELECT,UPDATE')
      ELSE false END") == 0 ]]
[[ $(assessment_fingerprint) == "$before_assessments" ]]
[[ $(psql_read "SELECT (SELECT count(*) FROM security_baselinepreference)
    + (SELECT count(*) FROM security_baselinescanjob)
    + (SELECT count(*) FROM security_baselineassessment WHERE content_sha256 != '' OR findings != '[]'::jsonb)") == 0 ]]
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
    http://127.0.0.1:8000/api/v1/ | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == "0.2.45"'
for route in en/login de/login api/v1/security/baselines/ api/v1/security/baseline-settings/ api/v1/security/baselines/microsoft-windows-server-2025/scans/ api/v1/security/baselines/microsoft-windows-server-2025/systems/ api/v1/security/baselines/microsoft-windows-server-2025/systems/00000000-0000-4000-8000-000000000000/findings/ api/v1/hyper-v/virtual-machines/00000000-0000-4000-8000-000000000000/management/dialog/ api/v1/auth/account/ api/v1/platform/tenants/ api/v1/service-accounts/ api/v1/update-sources/ api/v1/update-sources/00000000-0000-4000-8000-000000000000/comparison/ api/v1/update-sources/00000000-0000-4000-8000-000000000000/servers/00000000-0000-4000-8000-000000000000/updates/ admin/ admin; do
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
echo "IPMS 0.2.45 DEV Security activation verified; only Security 0002 and 0003 applied as ipms. Existing assessments, Windows 0.2.30 package, running Linux Agent, WSUS integration and environments preserved. Backup: $backup"
