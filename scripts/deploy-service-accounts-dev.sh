#!/usr/bin/env bash
# Exact-target DEV update from 0.2.31. Agent packages and firewall stay unchanged.
set -euo pipefail
umask 027
[[ $EUID -eq 0 && $# -eq 4 ]] || exit 2
expected_host=$1
public_host=${2,,}
release_ref=$3
previous_ref=$4
[[ $(hostname -f) == "$expected_host" && $public_host =~ ^[A-Za-z0-9.-]+$ ]] || exit 2
[[ $release_ref =~ ^[0-9a-f]{40}$ && $previous_ref =~ ^[0-9a-f]{40}$ ]] || exit 2
previous=/srv/ipms/releases/$previous_ref
release=/srv/ipms/releases/$release_ref
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.31 ]] || exit 2
[[ ! -e $release && ! -L $release ]] || exit 2
[[ ! -e /srv/ipms/.current-accounts-next && ! -L /srv/ipms/.current-accounts-next \
    && ! -e /srv/ipms/.current-accounts-rollback && ! -L /srv/ipms/.current-accounts-rollback ]] || exit 2
active_consoles=$(sudo -n -u postgres psql --no-psqlrc --tuples-only --no-align --dbname=ipms \
    -c "SELECT count(*) FROM discovery_hypervconsolesession WHERE status IN ('requested','active') AND lease_expires_at > now()")
[[ $active_consoles == 0 ]] || { echo 'Active console sessions prevent this DEV update.' >&2; exit 2; }
backup=/srv/ipms/backups/service-accounts-0232-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 -o root -g root "$backup"
for env_name in control-plane web-console agent-gateway console-broker; do
    cp -p "/srv/ipms/shared/$env_name.env" "$backup/$env_name.env"
done
# Never print or rotate the credential key. Keep its independent protected backup.
install -m 0600 /srv/ipms/shared/native-console/credential.key "$backup/credential.key"
sudo -n -u postgres pg_dump --format=custom --dbname=ipms > "$backup/ipms.dump"
[[ -s $backup/ipms.dump ]]
pg_restore --list "$backup/ipms.dump" >/dev/null
echo "Protected rollback backup created: $backup"

umask 022
git clone --filter=blob:none --no-checkout https://github.com/Alvestrasza/ipms.git "$release"
git -C "$release" checkout --detach "$release_ref"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.32 ]]
python3 -m venv "$release/services/control-plane/.venv"
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

rollback() {
    failure=$?
    trap - ERR
    set +e
    restore_failed=0
    echo 'Service Accounts cutover failed; restoring the previous application.' >&2
    cp -p "$backup/web-console.env" /srv/ipms/shared/web-console.env || restore_failed=1
    ln -s "$previous" /srv/ipms/.current-accounts-rollback && \
        mv -Tf /srv/ipms/.current-accounts-rollback /srv/ipms/current || restore_failed=1
    sudo -n -u postgres psql --quiet --no-psqlrc --set=ON_ERROR_STOP=1 --dbname=ipms \
        -c 'REVOKE SELECT ON agent_pki_serviceaccount FROM ipms_console_broker' || restore_failed=1
    systemctl restart ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker || restore_failed=1
    for unit in ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker; do
        systemctl is-active --quiet "$unit" || restore_failed=1
    done
    echo "Rollback restoration failure flag: $restore_failed. Backup: $backup" >&2
    echo 'Additive data and keys were retained. Central assignments fail closed in the old version.' >&2
    exit "${failure:-1}"
}
trap rollback ERR
set -a
. /srv/ipms/shared/control-plane.env
set +a
export PYTHONPATH="$release/services/control-plane/src"
python="$release/services/control-plane/.venv/bin/python"
manage="$release/services/control-plane/manage.py"
"$python" "$manage" migrate --noinput
"$python" "$manage" collectstatic --noinput
"$python" "$manage" check --deploy
sudo -n -u postgres psql --quiet --no-psqlrc --set=ON_ERROR_STOP=1 --dbname=ipms \
    -c 'GRANT SELECT ON agent_pki_serviceaccount TO ipms_console_broker'
# Recheck after the build, before restarting any running service.
active_consoles=$(sudo -n -u postgres psql --no-psqlrc --tuples-only --no-align --dbname=ipms \
    -c "SELECT count(*) FROM discovery_hypervconsolesession WHERE status IN ('requested','active') AND lease_expires_at > now()")
if [[ $active_consoles != 0 ]]; then
    trap - ERR
    echo 'Application remains unchanged: a console opened during staging.' >&2
    echo "Staged release retained: $release. Additive migration and broker SELECT grant are already applied." >&2
    echo 'Automatic rerun is not supported; follow the staged-cutover recovery procedure in SERVICE-ACCOUNTS.md.' >&2
    exit 2
fi
web_env=/srv/ipms/shared/web-console.env
if grep -q '^IPMS_PUBLIC_ORIGIN=' "$web_env"; then
    sed -i "s|^IPMS_PUBLIC_ORIGIN=.*|IPMS_PUBLIC_ORIGIN=https://$public_host|" "$web_env"
else
    printf '\nIPMS_PUBLIC_ORIGIN=https://%s\n' "$public_host" >> "$web_env"
fi
chown root:ipms-web "$web_env"
chmod 0640 "$web_env"
ln -s "$release" /srv/ipms/.current-accounts-next
mv -Tf /srv/ipms/.current-accounts-next /srv/ipms/current
systemctl restart ipms-control-plane ipms-web-console ipms-agent-gateway ipms-console-broker
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
    | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == "0.2.32"'
code=$(curl --connect-timeout 2 --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" "https://$public_host/api/v1/service-accounts/")
[[ $code == 403 ]]
# Invalid tenant values cannot set a selection cookie. Check the real TLS front door.
for origin in "https://$public_host" 'https://untrusted.example.invalid' ''; do
    origin_header=()
    [[ -z $origin ]] || origin_header=(--header "Origin: $origin")
    code=$(curl --connect-timeout 2 --max-time 5 --silent --show-error --output /dev/null --write-out '%{http_code}' \
        --cacert /etc/ipms/tls/server.crt --resolve "$public_host:443:127.0.0.1" \
        "${origin_header[@]}" --header 'Content-Type: application/json' \
        --data '{"tenantId":"invalid-test-value"}' "https://$public_host/api/tenant-selection")
    if [[ $origin == "https://$public_host" ]]; then [[ $code == 400 ]]; else [[ $code == 403 ]]; fi
done
ss -lntH 'sport = :9419' | grep -q '0.0.0.0:9419'
ss -lntH 'sport = :9420' | grep -q '127.0.0.1:9420'
test -S /run/ipms-console/agent.sock
trap - ERR
echo "IPMS 0.2.32 DEV update completed. Agent versions unchanged. Backup: $backup"
