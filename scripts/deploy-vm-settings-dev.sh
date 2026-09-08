#!/usr/bin/env bash
# Exact-target, schema-neutral 0.2.36 -> 0.2.37 DEV portal cutover.
set -Eeuo pipefail
shopt -s inherit_errexit

[[ $EUID == 0 && $# == 5 ]] || { echo 'Usage: deploy-vm-settings-dev.sh HOST MACHINE_ID PUBLIC_HOST PREVIOUS_SHA RELEASE_SHA' >&2; exit 2; }
expected_host=$1
expected_machine=$2
public_host=$3
previous_ref=$4
release_ref=$5
[[ $expected_host =~ ^[a-z0-9-]+$ && $(hostname -s) == "$expected_host" ]]
[[ $expected_machine =~ ^[0-9a-f]{32}$ && $(</etc/machine-id) == "$expected_machine" ]]
[[ $public_host =~ ^[a-z0-9][a-z0-9.-]+$ && $public_host != *..* && $public_host != *. ]]
[[ $previous_ref =~ ^[0-9a-f]{40}$ && $release_ref =~ ^[0-9a-f]{40}$ && $previous_ref != "$release_ref" ]]
previous=/srv/ipms/releases/$previous_ref
release=/srv/ipms/releases/$release_ref
fence=/srv/ipms/shared/tenant-cutover.pending
next_link=/srv/ipms/.current-vm-settings-next
lock=/run/lock/ipms-tenant-cutover.lock

protected() {
    [[ -e $1 && ! -L $1 && $(stat -c %u -- "$1") == 0 ]] || return 1
    local mode
    mode=$(stat -c %a -- "$1")
    (( (8#$mode & 0022) == 0 ))
}
for path in /srv/ipms /srv/ipms/releases /srv/ipms/shared "$previous" "$lock"; do protected "$path"; done
[[ -f $lock && $(stat -c %h "$lock") == 1 ]]
exec 9>>"$lock"
flock -n 9 || { echo 'Another cutover is running.' >&2; exit 2; }
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.36 ]]
[[ $(git -C "$previous" rev-parse HEAD) == "$previous_ref" ]]
git -C "$previous" diff --exit-code HEAD -- >/dev/null
for path in "$release" "$fence" "$next_link"; do [[ ! -e $path && ! -L $path ]]; done
for name in control-plane web-console agent-gateway console-broker; do protected "/srv/ipms/shared/$name.env"; done
protected /etc/nginx/sites-available/ipms
preserved=$(sha256sum /srv/ipms/shared/{control-plane,web-console,agent-gateway,console-broker}.env /etc/nginx/sites-available/ipms)
units=(ipms-control-plane.service ipms-web-console.service)
for unit in "${units[@]}" ipms-agent-gateway ipms-console-broker ipms-guacd nginx; do systemctl is-active --quiet "$unit"; done
for unit in "${units[@]}"; do
    protected "/etc/systemd/system/$unit.d/60-ipms-tenant-cutover.conf"
    cmp "$previous/deploy/standalone/ipms-tenant-cutover.conf" "/etc/systemd/system/$unit.d/60-ipms-tenant-cutover.conf"
done

assert_quiescent() {
    local count
    count=$(sudo -n -u postgres psql --no-psqlrc --set=ON_ERROR_STOP=1 --tuples-only --no-align --dbname=ipms -c "SELECT
        (SELECT count(*) FROM discovery_hypervmanagementjob WHERE status IN ('queued','delivered','running','requires_reconciliation'))
        + (SELECT count(*) FROM discovery_hypervvirtualmachineactionjob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM discovery_hypervconsolesession WHERE status IN ('requested','active') AND lease_expires_at > now())
        + (SELECT count(*) FROM agent_pki_agentlifecyclejob WHERE status IN ('queued','delivered','running'))
        + (SELECT count(*) FROM agent_pki_windowsagentdeployment WHERE status IN ('queued','running'))
        + (SELECT count(*) FROM discovery_discoveryjob WHERE status IN ('queued','running'))")
    [[ $count == 0 ]] || { echo 'Active or unresolved operations prevent this cutover.' >&2; return 1; }
}
assert_quiescent

# No runtime interruption until the pinned, immutable candidate is built.
umask 022
git clone --filter=blob:none --no-checkout https://github.com/Alvestrasza/ipms.git "$release"
git -C "$release" checkout --detach "$release_ref"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.37 ]]
# This cutover must never introduce Agent, API-contract, schema, dependency,
# service-unit, environment, or ingress changes.
git -C "$release" diff --exit-code "$previous_ref" "$release_ref" -- agent deploy \
    services/control-plane/src/ipms/apps/agent_pki services/control-plane/src/ipms/apps/discovery \
    services/control-plane/src/ipms/apps/tenancy services/control-plane/src/ipms_control_plane \
    services/console-broker apps/web-console/pnpm-lock.yaml >/dev/null
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
/usr/bin/python3.14 -m venv "$release/services/control-plane/.venv"
python="$release/services/control-plane/.venv/bin/python"
manage="$release/services/control-plane/manage.py"
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
set -a
. /srv/ipms/shared/control-plane.env
set +a
export PYTHONPATH="$release/services/control-plane/src"
"$python" "$manage" migrate --check
"$python" "$manage" check --deploy
"$python" "$manage" collectstatic --noinput
sudo -n -u ipms-control-plane test -x "$python"
sudo -n -u ipms-web test -r "$release/apps/web-console/.next/standalone/server.js"
[[ $(sha256sum /srv/ipms/shared/{control-plane,web-console,agent-gateway,console-broker}.env /etc/nginx/sites-available/ipms) == "$preserved" ]]
git -C "$release" diff --exit-code HEAD -- >/dev/null
assert_quiescent
[[ $(readlink -f /srv/ipms/current) == "$previous" ]]

ready() {
    local version=$1
    curl --connect-timeout 2 --max-time 5 --fail --silent --header "Host: $public_host" --header 'X-Forwarded-Proto: https' \
        http://127.0.0.1:8000/api/v1/health/ready/ >/dev/null &&
    curl --connect-timeout 2 --max-time 5 --fail --silent --header "Host: $public_host" --header 'X-Forwarded-Proto: https' \
        http://127.0.0.1:8000/api/v1/ | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == sys.argv[1]' "$version" &&
    curl --connect-timeout 2 --max-time 5 --fail --silent http://127.0.0.1:3000/api/health >/dev/null
}
wait_ready() {
    local attempt
    for attempt in {1..20}; do if ready "$1"; then return 0; fi; sleep 1; done
    return 1
}
recover() {
    local failure=$?
    if (( BASH_SUBSHELL > 0 )); then exit "$failure"; fi
    trap - ERR INT TERM
    set +e
    install -m 0600 /dev/null "$fence"
    systemctl stop "${units[@]}"
    # Schema, environment and Agent contracts were deliberately unchanged.
    # Use only the exact previous immutable release, never an inferred target.
    if [[ -e $next_link || -L $next_link ]]; then unlink "$next_link"; fi
    if protected "$previous" && [[ $(git -C "$previous" rev-parse HEAD) == "$previous_ref" ]] &&
        [[ $(sha256sum /srv/ipms/shared/{control-plane,web-console,agent-gateway,console-broker}.env /etc/nginx/sites-available/ipms) == "$preserved" ]] &&
        ln -s "$previous" "$next_link" && mv -Tf "$next_link" /srv/ipms/current; then
        unlink "$fence"
        if systemctl start "${units[@]}" && wait_ready 0.2.36; then
            echo 'Cutover failed; the previous 0.2.36 portal is restored.' >&2
        else
            install -m 0600 /dev/null "$fence"
            systemctl stop "${units[@]}"
            echo 'Recovery requires review; portal services remain fenced.' >&2
        fi
    else
        echo 'Release restoration failed; portal services remain fenced.' >&2
    fi
    (( failure != 0 )) || failure=1
    exit "$failure"
}
trap recover ERR INT TERM
install -m 0600 /dev/null "$fence"
systemctl stop "${units[@]}"
assert_quiescent
ln -s "$release" "$next_link"
mv -Tf "$next_link" /srv/ipms/current
unlink "$fence"
systemctl start "${units[@]}"
wait_ready 0.2.37
for unit in "${units[@]}" ipms-agent-gateway ipms-console-broker ipms-guacd nginx; do systemctl is-active --quiet "$unit"; done
[[ $(sha256sum /srv/ipms/shared/{control-plane,web-console,agent-gateway,console-broker}.env /etc/nginx/sites-available/ipms) == "$preserved" ]]
for locale in en de; do
    code=$(curl --connect-timeout 2 --max-time 10 --fail --silent --output /dev/null --write-out '%{http_code}' \
        --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" "https://$public_host/$locale/login")
    [[ $code == 200 ]]
done
trap - ERR INT TERM
echo 'IPMS 0.2.37 DEV portal activated. No migration, environment change, Agent rollout or VM action. Previous immutable release retained.'
