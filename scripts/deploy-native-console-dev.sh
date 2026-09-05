#!/usr/bin/env bash
# Exact-target DEV cutover. No Windows account or firewall configuration.
set -euo pipefail
umask 027
[[ $EUID -eq 0 && $# -eq 5 ]] || exit 2
expected_host=$1
public_host=$2
release_ref=$3
previous_ref=$4
native_stage=$(realpath -e -- "$5")
[[ $(hostname -f) == "$expected_host" && $public_host =~ ^[A-Za-z0-9.-]+$ ]] || exit 2
[[ $release_ref =~ ^[0-9a-f]{40}$ && $previous_ref =~ ^[0-9a-f]{40}$ ]] || exit 2
previous=/srv/ipms/releases/$previous_ref
release=/srv/ipms/releases/$release_ref
prefix=/srv/ipms/dependencies/guacamole-1.6.0-ipms1
[[ $(readlink -f /srv/ipms/current) == "$previous" && $(<"$previous/VERSION") == 0.2.30 ]] || exit 2
[[ ! -e $release && ! -L $release && ! -e $prefix && ! -L $prefix ]] || exit 2
case "$native_stage" in /tmp/ipms-native-console-*/build*/dest/srv/ipms/dependencies/guacamole-1.6.0-ipms1) ;; *) exit 2 ;; esac
[[ -x $native_stage/sbin/guacd && -f $native_stage/lib/libguac-client-rdp.so ]] || exit 2
artifact=/srv/ipms/shared/agent-artifacts/ipms-agent-windows-x64-0.2.26.zip
artifact_sha=4ed700af429483973a24d72ecb5496bb87017313e1f1e2a36a89219c5c181700
[[ -f $artifact ]] || exit 2
echo "$artifact_sha  $artifact" | sha256sum --check --strict -
backup=/srv/ipms/backups/native-console-0231-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 -o root -g root "$backup"
cp -p /srv/ipms/shared/control-plane.env "$backup/control-plane.env"
cp -p /srv/ipms/shared/agent-gateway.env "$backup/agent-gateway.env"
cp -p /etc/nginx/sites-available/ipms "$backup/nginx-ipms"
sudo -n -u postgres pg_dump --format=custom --dbname=ipms > "$backup/ipms.dump"
[[ -s $backup/ipms.dump ]]
pg_restore --list "$backup/ipms.dump" >/dev/null
echo "Protected rollback backup created: $backup"

umask 022
git clone --filter=blob:none --no-checkout https://github.com/Alvestrasza/ipms.git "$release"
git -C "$release" checkout --detach "$release_ref"
[[ $(git -C "$release" rev-parse HEAD) == "$release_ref" && $(<"$release/VERSION") == 0.2.31 ]]
for adaptation in ipms-strict-certificate.h ipms-wol-disabled.c guacamole-1.6.0-strict-certificate.patch guacamole-1.6.0-nested-socket.patch; do
    cmp -- "$release/deploy/native-console/$adaptation" "$native_stage/$adaptation"
done
python3 -m venv "$release/services/control-plane/.venv"
"$release/services/control-plane/.venv/bin/python" -m pip install "$release/services/control-plane"
export PATH="/opt/ipms/node-current/bin:$PATH"
export NEXT_TELEMETRY_DISABLED=1
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
install -d -o root -g root -m 0755 /srv/ipms/dependencies
cp -a -- "$native_stage" "$prefix"
chown -R root:ipms-runtime -- "$prefix"
find "$prefix" -type d -exec chmod 0750 {} +
find "$prefix" -type f ! -perm /111 -exec chmod 0640 {} +
find "$prefix" -type f -perm /111 -exec chmod 0750 {} +
find "$prefix/lib" "$prefix/sbin" -type f -print0 | sort -z | xargs -0 sha256sum > "$prefix/SHA256SUMS.runtime"
chmod 0644 "$prefix/SHA256SUMS.runtime"
chown root:ipms-runtime "$artifact"
chmod 0640 "$artifact"

rollback() {
    failure=$?
    trap - ERR
    set +e
    restore_failed=0
    echo 'Native cutover failed; restoring the previous application configuration.' >&2
    systemctl stop ipms-console-broker ipms-guacd
    systemctl disable ipms-console-broker ipms-guacd
    cp -p "$backup/control-plane.env" /srv/ipms/shared/control-plane.env || restore_failed=1
    cp -p "$backup/agent-gateway.env" /srv/ipms/shared/agent-gateway.env || restore_failed=1
    cp -p "$backup/nginx-ipms" /etc/nginx/sites-available/ipms || restore_failed=1
    ln -s "$previous" /srv/ipms/.current-native-rollback && \
        mv -Tf /srv/ipms/.current-native-rollback /srv/ipms/current || restore_failed=1
    systemctl daemon-reload || restore_failed=1
    nginx -t && systemctl reload nginx || restore_failed=1
    systemctl restart ipms-control-plane ipms-web-console ipms-agent-gateway || restore_failed=1
    for unit in ipms-control-plane ipms-web-console ipms-agent-gateway nginx; do
        systemctl is-active --quiet "$unit" || restore_failed=1
    done
    echo "Rollback restoration failure flag: $restore_failed" >&2
    echo "Rollback backup retained: $backup. Additive data and keys were not deleted." >&2
    exit "${failure:-1}"
}
[[ ! -e /srv/ipms/.current-native-rollback && ! -L /srv/ipms/.current-native-rollback \
    && ! -e /srv/ipms/.current-native-next && ! -L /srv/ipms/.current-native-next ]]
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
bash "$release/scripts/configure-native-console.sh" "$public_host"
sudo -n -u ipms-guacd test -x "$prefix/sbin/guacd"
sudo -n -u ipms-guacd test -r "$prefix/lib/libguac-client-rdp.so"
sudo -n -u ipms-guacd sha256sum --check --strict "$prefix/SHA256SUMS.runtime" >/dev/null
for env_file in /srv/ipms/shared/control-plane.env /srv/ipms/shared/agent-gateway.env; do
    sed -i -e '/^IPMS_AGENT_WINDOWS_PACKAGE_PATH=/d' \
        -e '/^IPMS_AGENT_WINDOWS_PACKAGE_SHA256=/d' -e '/^IPMS_AGENT_WINDOWS_VERSION=/d' "$env_file"
    printf '\nIPMS_AGENT_WINDOWS_PACKAGE_PATH=%s\nIPMS_AGENT_WINDOWS_PACKAGE_SHA256=%s\nIPMS_AGENT_WINDOWS_VERSION=0.2.26\n' \
        "$artifact" "$artifact_sha" >> "$env_file"
done
install -m 0644 "$release/deploy/standalone/ipms-guacd.service" /etc/systemd/system/ipms-guacd.service
install -m 0644 "$release/deploy/standalone/ipms-console-broker.service" /etc/systemd/system/ipms-console-broker.service
sed "s/@@PUBLIC_HOST@@/${public_host}/g" "$release/deploy/standalone/nginx-ipms.conf.template" > /etc/nginx/sites-available/ipms
nginx -t
ln -s "$release" /srv/ipms/.current-native-next
mv -Tf /srv/ipms/.current-native-next /srv/ipms/current
systemctl daemon-reload
systemctl enable ipms-guacd ipms-console-broker
systemctl restart ipms-control-plane ipms-web-console ipms-guacd ipms-console-broker ipms-agent-gateway
systemctl reload nginx
ready=false
for attempt in {1..20}; do
    if curl --connect-timeout 2 --max-time 5 --fail --silent --header "Host: $public_host" --header 'X-Forwarded-Proto: https' \
        http://127.0.0.1:8000/api/v1/health/ready/ >/dev/null \
        && curl --connect-timeout 2 --max-time 5 --fail --silent http://127.0.0.1:3000/api/health >/dev/null; then ready=true; break; fi
    sleep 1
done
[[ $ready == true ]]
for unit in ipms-control-plane ipms-web-console ipms-agent-gateway ipms-guacd ipms-console-broker nginx; do
    systemctl is-active --quiet "$unit"
done
curl --connect-timeout 2 --max-time 5 --fail --silent --show-error --cacert /etc/ipms/tls/server.crt \
    --resolve "$public_host:443:127.0.0.1" "https://$public_host/api/health"
curl --connect-timeout 2 --max-time 5 --fail --silent --show-error --header "Host: $public_host" \
    --header 'X-Forwarded-Proto: https' http://127.0.0.1:8000/api/v1/ \
    | "$python" -c 'import json,sys; assert json.load(sys.stdin)["application_version"] == "0.2.31"'
ss -lntH 'sport = :9419' | grep -q '0.0.0.0:9419'
ss -lntH 'sport = :9420' | grep -q '127.0.0.1:9420'
ss -lntH 'sport = :4822' | grep -q '127.0.0.1:4822'
test -S /run/ipms-console/agent.sock
trap - ERR
echo "IPMS 0.2.31 DEV cutover completed; real-host native acceptance remains separate. Backup: $backup"
