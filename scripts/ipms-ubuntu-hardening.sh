#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly SCRIPT_VERSION="0.1.0"
readonly STATE_ROOT="/var/lib/ipms-bootstrap/hardening"
readonly MANAGED_COMMENT="IPMS management source"

action="${1:-}"
if [[ -n "$action" ]]; then
    shift
fi

management_source=""
admin_user="alice"
profile="development"
data_mount="/srv/ipms"
rollback_minutes="10"
run_id=""
skip_package_update="false"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf 'IPMS-HARDENING: %s\n' "$*" >&2
}

require_root() {
    [[ "$(id -u)" == "0" ]] || fail "This program must run as root."
}

parse_options() {
    while (($#)); do
        case "$1" in
            --management-source)
                (($# >= 2)) || fail "Missing value for --management-source."
                management_source="$2"
                shift 2
                ;;
            --admin-user)
                (($# >= 2)) || fail "Missing value for --admin-user."
                admin_user="$2"
                shift 2
                ;;
            --profile)
                (($# >= 2)) || fail "Missing value for --profile."
                profile="$2"
                shift 2
                ;;
            --data-mount)
                (($# >= 2)) || fail "Missing value for --data-mount."
                data_mount="$2"
                shift 2
                ;;
            --rollback-minutes)
                (($# >= 2)) || fail "Missing value for --rollback-minutes."
                rollback_minutes="$2"
                shift 2
                ;;
            --run-id)
                (($# >= 2)) || fail "Missing value for --run-id."
                run_id="$2"
                shift 2
                ;;
            --skip-package-update)
                skip_package_update="true"
                shift
                ;;
            *)
                fail "Unknown option: $1"
                ;;
        esac
    done
}

validate_inputs() {
    [[ "$management_source" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] ||
        fail "The management source must be an IPv4 or IPv6 address or CIDR."
    [[ "$management_source" != "0.0.0.0" && "$management_source" != "::" ]] ||
        fail "An unspecified address cannot be a management source."
    local prefix
    if [[ "$management_source" == *.* ]]; then
        prefix="${management_source#*/}"
        [[ "$prefix" != "$management_source" ]] || prefix="32"
        ((prefix >= 24 && prefix <= 32)) ||
            fail "An IPv4 management source must be a host or a /24-or-narrower CIDR."
    else
        prefix="${management_source#*/}"
        [[ "$prefix" != "$management_source" ]] || prefix="128"
        ((prefix >= 64 && prefix <= 128)) ||
            fail "An IPv6 management source must be a host or a /64-or-narrower CIDR."
    fi
    [[ "$admin_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] ||
        fail "The administrative user name is invalid."
    [[ "$data_mount" =~ ^/[A-Za-z0-9._/-]+$ ]] ||
        fail "The data mount path is invalid."
    [[ "$rollback_minutes" =~ ^[0-9]+$ ]] ||
        fail "The rollback timeout must be an integer."
    ((rollback_minutes >= 2 && rollback_minutes <= 60)) ||
        fail "The rollback timeout must be between 2 and 60 minutes."

    case "$profile" in
        development) ;;
        customer|production)
            fail "The $profile profile is blocked until the encryption and recovery policy is implemented."
            ;;
        *) fail "Unsupported Appliance profile: $profile" ;;
    esac
}

validate_platform() {
    [[ -r /etc/os-release ]] || fail "/etc/os-release is unavailable."
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || fail "Only Ubuntu is supported."
    [[ "${VERSION_ID:-}" == "26.04" ]] ||
        fail "This baseline requires Ubuntu 26.04 LTS."
    id "$admin_user" >/dev/null 2>&1 || fail "Administrative user does not exist."
    [[ "$(id -u "$admin_user")" != "0" ]] || fail "The administrative user must not be root."
}

validate_storage_preflight() {
    findmnt -n "$data_mount" >/dev/null || fail "The data mount is not mounted."
    [[ "$(findmnt -n -o FSTYPE "$data_mount")" == "ext4" ]] ||
        fail "The data filesystem must be ext4."
    findmnt --fstab -n "$data_mount" >/dev/null ||
        fail "The data mount is not present in /etc/fstab."
    local data_source
    data_source="$(findmnt -n -o SOURCE "$data_mount")"
    tune2fs -l "$data_source" >/dev/null 2>&1 ||
        fail "The ext4 data filesystem metadata is not readable."
}

install_managed_file() {
    local target="$1"
    local mode="$2"
    local validator="${3:-}"
    local candidate
    candidate="$(mktemp)"
    cat >"$candidate"
    chmod "$mode" "$candidate"

    if [[ -n "$validator" ]]; then
        $validator "$candidate"
    fi

    if [[ -f "$target" ]] && cmp -s "$candidate" "$target"; then
        rm -f "$candidate"
        return 0
    fi

    install -D -o root -g root -m "$mode" "$candidate" "$target"
    rm -f "$candidate"
    changed="true"
}

validate_sshd_candidate() {
    local candidate="$1"
    local test_root
    test_root="$(mktemp -d)"
    cp -a /etc/ssh/sshd_config "$test_root/sshd_config"
    mkdir -p "$test_root/sshd_config.d"
    cp -a /etc/ssh/sshd_config.d/. "$test_root/sshd_config.d/" 2>/dev/null || true
    cp "$candidate" "$test_root/sshd_config.d/00-ipms-hardening.conf"
    sed -i "s|^Include /etc/ssh/sshd_config.d/\*.conf|Include $test_root/sshd_config.d/*.conf|" \
        "$test_root/sshd_config"
    sshd -t -f "$test_root/sshd_config"
    rm -rf "$test_root"
}

validate_sudoers_candidate() {
    visudo -cf "$1" >/dev/null
}

record_service_state() {
    local output="$1"
    shift
    : >"$output"
    local unit enabled active
    for unit in "$@"; do
        enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        active="$(systemctl is-active "$unit" 2>/dev/null || true)"
        printf '%s\t%s\t%s\n' "$unit" "$enabled" "$active" >>"$output"
    done
}

record_managed_file_state() {
    local output="$1"
    local path digest
    : >"$output"
    for path in \
        /etc/ssh/sshd_config.d/00-ipms-hardening.conf \
        /etc/apt/apt.conf.d/60ipms-unattended-upgrades \
        /etc/systemd/journald.conf.d/60-ipms-hardening.conf \
        /etc/sysctl.d/60-ipms-hardening.conf \
        /etc/audit/rules.d/50-ipms-baseline.rules \
        /etc/sudoers.d/00-ipms-hardening \
        /etc/security/pwquality.conf.d/60-ipms-hardening.conf \
        /etc/profile.d/60-ipms-hardening.sh \
        /etc/fstab \
        /etc/default/ufw \
        /etc/ufw/user.rules \
        /etc/ufw/user6.rules; do
        if [[ -f "$path" ]]; then
            digest="$(sha256sum "$path" | awk '{ print $1 }')"
            printf '%s\t%s\n' "$path" "$digest" >>"$output"
        else
            printf '%s\tABSENT\n' "$path" >>"$output"
        fi
    done
}

record_ext4_state() {
    local output="$1"
    local data_source errors_behavior
    data_source="$(findmnt -n -o SOURCE "$data_mount")"
    errors_behavior="$(
        tune2fs -l "$data_source" |
            awk -F: '/Errors behavior/ { gsub(/^[[:space:]]+/, "", $2); print $2 }'
    )"
    printf '%s\t%s\n' "$data_source" "$errors_behavior" >"$output"
}

record_sysctl_state() {
    local output="$1"
    local key
    : >"$output"
    for key in \
        kernel.kptr_restrict \
        kernel.dmesg_restrict \
        kernel.yama.ptrace_scope \
        fs.suid_dumpable \
        net.ipv4.ip_forward \
        net.ipv4.conf.all.accept_redirects \
        net.ipv4.conf.default.accept_redirects \
        net.ipv4.conf.all.secure_redirects \
        net.ipv4.conf.default.secure_redirects \
        net.ipv4.conf.all.send_redirects \
        net.ipv4.conf.default.send_redirects \
        net.ipv4.conf.all.accept_source_route \
        net.ipv4.conf.default.accept_source_route \
        net.ipv4.conf.all.rp_filter \
        net.ipv4.conf.default.rp_filter \
        net.ipv4.conf.all.log_martians \
        net.ipv4.conf.default.log_martians \
        net.ipv4.icmp_echo_ignore_broadcasts \
        net.ipv4.icmp_ignore_bogus_error_responses \
        net.ipv4.tcp_syncookies \
        net.ipv6.conf.all.accept_redirects \
        net.ipv6.conf.default.accept_redirects \
        net.ipv6.conf.all.accept_source_route \
        net.ipv6.conf.default.accept_source_route; do
        printf '%s\t%s\n' "$key" "$(sysctl -n "$key")" >>"$output"
    done
}

create_backup() {
    local state_dir="$1"
    mkdir -p "$state_dir/backup"
    chmod 0700 "$state_dir" "$state_dir/backup"

    local paths=(
        /etc/ssh/sshd_config
        /etc/ssh/sshd_config.d
        /etc/ufw
        /etc/default/ufw
        /etc/sudoers.d
        /etc/apt/apt.conf.d
        /etc/audit/rules.d
        /etc/systemd/journald.conf.d
        /etc/security/pwquality.conf.d
        /etc/profile.d
        /etc/sysctl.d
        /etc/fstab
    )
    local existing=()
    local path
    for path in "${paths[@]}"; do
        [[ -e "$path" ]] && existing+=("${path#/}")
    done
    tar -C / -cpf "$state_dir/backup/configuration.tar" "${existing[@]}"

    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        printf 'active\n' >"$state_dir/backup/ufw-state"
    else
        printf 'inactive\n' >"$state_dir/backup/ufw-state"
    fi

    record_service_state "$state_dir/backup/services.tsv" \
        ModemManager.service \
        udisks2.service \
        open-iscsi.service \
        iscsid.socket \
        multipathd.service \
        multipathd.socket \
        lxd-installer.socket \
        motd-news.timer \
        apport.service
    record_managed_file_state "$state_dir/backup/managed-files.tsv"
    record_ext4_state "$state_dir/backup/ext4-errors-behavior.tsv"
    record_sysctl_state "$state_dir/backup/sysctl-values.tsv"
}

create_rollback_program() {
    local state_dir="$1"
    local rollback="$state_dir/rollback.sh"
    cat >"$rollback" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
state_dir=$(printf '%q' "$state_dir")
rm -f \
    /etc/ssh/sshd_config.d/00-ipms-hardening.conf \
    /etc/apt/apt.conf.d/60ipms-unattended-upgrades \
    /etc/systemd/journald.conf.d/60-ipms-hardening.conf \
    /etc/sysctl.d/60-ipms-hardening.conf \
    /etc/audit/rules.d/50-ipms-baseline.rules \
    /etc/sudoers.d/00-ipms-hardening \
    /etc/security/pwquality.conf.d/60-ipms-hardening.conf \
    /etc/profile.d/60-ipms-hardening.sh
tar -C / -xpf "\$state_dir/backup/configuration.tar"
while IFS=$'\t' read -r unit enabled active; do
    case "\$enabled" in
        enabled|enabled-runtime) systemctl unmask "\$unit" >/dev/null 2>&1 || true; systemctl enable "\$unit" >/dev/null 2>&1 || true ;;
        disabled) systemctl disable "\$unit" >/dev/null 2>&1 || true ;;
        masked|masked-runtime) systemctl mask "\$unit" >/dev/null 2>&1 || true ;;
    esac
    if [[ "\$active" == "active" ]]; then
        systemctl start "\$unit" >/dev/null 2>&1 || true
    else
        systemctl stop "\$unit" >/dev/null 2>&1 || true
    fi
done <"\$state_dir/backup/services.tsv"
sshd -t
systemctl reload ssh
if [[ "\$(cat "\$state_dir/backup/ufw-state")" == "active" ]]; then
    ufw --force enable >/dev/null
    ufw --force reload >/dev/null
else
    ufw --force disable >/dev/null
fi
systemctl daemon-reload
systemctl restart systemd-journald
sysctl --system >/dev/null
while IFS=$'\t' read -r key value; do
    sysctl -q -w "\$key=\$value"
done <"\$state_dir/backup/sysctl-values.tsv"
IFS=$'\t' read -r data_source errors_behavior <"\$state_dir/backup/ext4-errors-behavior.tsv"
case "\$errors_behavior" in
    Continue) tune2fs -e continue "\$data_source" >/dev/null ;;
    "Remount read-only") tune2fs -e remount-ro "\$data_source" >/dev/null ;;
    Panic) tune2fs -e panic "\$data_source" >/dev/null ;;
esac
mount -o remount $(printf '%q' "$data_mount")
printf 'rolled-back\n' >"\$state_dir/status"
EOF
    chmod 0700 "$rollback"
}

arm_rollback() {
    local state_dir="$1"
    local unit="ipms-hardening-rollback-$run_id"
    printf '%s\n' "$unit" >"$state_dir/rollback-unit"
    systemd-run \
        --unit "$unit" \
        --on-active "${rollback_minutes}m" \
        --property Type=oneshot \
        "$state_dir/rollback.sh" >/dev/null
    systemctl is-active --quiet "$unit.timer" || fail "Unable to arm the rollback timer."
}

update_fstab_options() {
    local target="$1"
    local candidate
    candidate="$(mktemp)"
    awk -v target="$target" '
        function hasopt(options, wanted, count, parts, item_number) {
            count = split(options, parts, ",")
            for (item_number = 1; item_number <= count; item_number++) {
                if (parts[item_number] == wanted) return 1
            }
            return 0
        }
        /^[[:space:]]*#/ || NF == 0 { print; next }
        $2 == target {
            if (!hasopt($4, "noatime")) $4 = $4 ",noatime"
            if (!hasopt($4, "nodev")) $4 = $4 ",nodev"
            if (!hasopt($4, "nosuid")) $4 = $4 ",nosuid"
            found = 1
        }
        { print }
        END { if (!found) exit 42 }
    ' /etc/fstab >"$candidate" || {
        rm -f "$candidate"
        fail "The data mount is not present in /etc/fstab."
    }
    findmnt --verify --tab-file "$candidate" >/dev/null
    if ! cmp -s "$candidate" /etc/fstab; then
        install -o root -g root -m 0644 "$candidate" /etc/fstab
        changed="true"
    fi
    rm -f "$candidate"
}

ensure_firewall_policy() {
    local status unexpected
    status="$(ufw status)"
    unexpected="$(
        while IFS= read -r rule; do
            if [[ "$rule" == *"22/tcp"* && "$rule" == *"$management_source"* ]]; then
                continue
            fi
            printf '%s\n' "$rule"
        done < <(printf '%s\n' "$status" | awk '/ALLOW IN/ { print }')
    )"
    [[ -z "$unexpected" ]] ||
        fail "Existing inbound UFW allow rules are outside the selected Appliance profile."

    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw default deny routed >/dev/null
    ufw logging low >/dev/null

    if ! printf '%s\n' "$status" | grep -F -- '22/tcp' | grep -Fq -- "$management_source"; then
        ufw allow from "$management_source" to any port 22 proto tcp comment "$MANAGED_COMMENT" >/dev/null
        changed="true"
    fi
    if ! printf '%s\n' "$status" | grep -q '^Status: active'; then
        ufw --force enable >/dev/null
        changed="true"
    else
        ufw --force reload >/dev/null
    fi
}

disable_reference_services() {
    local unit
    for unit in \
        ModemManager.service \
        udisks2.service \
        open-iscsi.service \
        iscsid.socket \
        multipathd.service \
        multipathd.socket \
        lxd-installer.socket \
        motd-news.timer \
        apport.service; do
        if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q .; then
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
        fi
    done
}

assert_sshd_value() {
    local effective="$1" key="$2" expected="$3"
    local actual
    actual="$(printf '%s\n' "$effective" | awk -v key="$key" '$1 == key { print $2; exit }')"
    [[ "$actual" == "$expected" ]] ||
        fail "Effective SSH setting $key does not match the baseline."
}

validate_effective_state() {
    require_root
    validate_inputs
    validate_platform
    validate_storage_preflight

    sshd -t
    local effective
    effective="$(sshd -T -C "user=$admin_user,host=localhost,addr=127.0.0.1")"
    assert_sshd_value "$effective" passwordauthentication no
    assert_sshd_value "$effective" kbdinteractiveauthentication no
    assert_sshd_value "$effective" permitrootlogin no
    assert_sshd_value "$effective" allowagentforwarding no
    assert_sshd_value "$effective" allowtcpforwarding no
    assert_sshd_value "$effective" x11forwarding no

    ufw status | grep -q '^Status: active' || fail "UFW is not active."
    ufw status | grep -F -- '22/tcp' | grep -Fq -- "$management_source" ||
        fail "The management SSH firewall rule is missing."
    local unexpected_firewall_rule
    while IFS= read -r unexpected_firewall_rule; do
        if [[ "$unexpected_firewall_rule" == *"22/tcp"* && "$unexpected_firewall_rule" == *"$management_source"* ]]; then
            continue
        fi
        fail "An inbound UFW allow rule exists outside the selected profile."
    done < <(ufw status | awk '/ALLOW IN/ { print }')
    grep -q '^DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw ||
        fail "The UFW inbound default policy is not deny."
    grep -q '^DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw ||
        fail "The UFW routed default policy is not deny."
    grep -q '^DEFAULT_OUTPUT_POLICY="ACCEPT"' /etc/default/ufw ||
        fail "The UFW outbound default policy is not allow."
    systemctl is-active --quiet auditd || fail "Auditd is not active."
    systemctl is-active --quiet apparmor || fail "AppArmor is not active."
    systemctl is-active --quiet unattended-upgrades ||
        fail "Unattended upgrades are not active."
    systemctl is-active --quiet apport.service &&
        fail "Apport is active and can override the privileged core-dump policy."
    aa-status --enabled >/dev/null || fail "AppArmor is not enabled."
    aa-status | grep -Eq '^[[:space:]]*[1-9][0-9]* profiles are in enforce mode\.$' ||
        fail "AppArmor has no enforced profiles."
    [[ "$(auditctl -s | awk '$1 == "lost" { print $2 }')" == "0" ]] ||
        fail "Auditd reports lost events."
    local loaded_audit_rules audit_key
    loaded_audit_rules="$(auditctl -l)"
    for audit_key in identity privilege ssh_configuration mounts firewall \
        kernel_configuration service_configuration; do
        printf '%s\n' "$loaded_audit_rules" | grep -Eq "(-k |key=)$audit_key([[:space:]]|$)" ||
            fail "Audit rule key $audit_key is not loaded."
    done

    for timer in apt-daily.timer apt-daily-upgrade.timer; do
        systemctl is-active --quiet "$timer" || fail "Update timer $timer is not active."
    done

    local journal_configuration journal_setting
    journal_configuration="$(systemd-analyze cat-config systemd/journald.conf)"
    for journal_setting in Storage=persistent Compress=yes Seal=yes \
        SystemMaxUse=1G SystemKeepFree=2G MaxRetentionSec=30day; do
        printf '%s\n' "$journal_configuration" | grep -Fxq "$journal_setting" ||
            fail "Effective Journal setting $journal_setting is missing."
    done

    visudo -c >/dev/null
    findmnt --verify >/dev/null
    local mount_options mount_type mount_source
    mount_options="$(findmnt -n -o OPTIONS "$data_mount")"
    mount_type="$(findmnt -n -o FSTYPE "$data_mount")"
    mount_source="$(findmnt -n -o SOURCE "$data_mount")"
    [[ "$mount_type" == "ext4" ]] || fail "The data mount is not ext4."
    for option in noatime nodev nosuid; do
        [[ ",$mount_options," == *",$option,"* ]] ||
            fail "The data mount is missing option $option."
    done
    [[ "$(tune2fs -l "$mount_source" 2>/dev/null | awk -F: '/Errors behavior/ { gsub(/^[[:space:]]+/, "", $2); print $2 }')" == "Remount read-only" ]] ||
        fail "The ext4 error behavior is not remount-read-only."

    [[ "$(sysctl -n kernel.kptr_restrict)" == "2" ]] || fail "kernel.kptr_restrict is incorrect."
    [[ "$(sysctl -n kernel.dmesg_restrict)" == "1" ]] || fail "kernel.dmesg_restrict is incorrect."
    [[ "$(sysctl -n fs.suid_dumpable)" == "0" ]] || fail "fs.suid_dumpable is incorrect."
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding is enabled."

    local disabled_unit unit_state
    for disabled_unit in ModemManager.service udisks2.service open-iscsi.service \
        iscsid.socket multipathd.service lxd-installer.socket motd-news.timer \
        apport.service; do
        unit_state="$(systemctl is-active "$disabled_unit" 2>/dev/null || true)"
        [[ "$unit_state" != "active" ]] || fail "Disabled profile unit $disabled_unit is active."
    done

    local listener protocol local_address
    while IFS= read -r listener; do
        protocol="$(awk '{print $1}' <<<"$listener")"
        local_address="$(awk '{print $5}' <<<"$listener")"
        if [[ "$local_address" == 127.* || "$local_address" == "[::1]:"* ]]; then
            continue
        fi
        if [[ "$protocol" == "tcp" && "$local_address" == *:22 ]]; then
            continue
        fi
        fail "An external listener exists outside the selected profile."
    done < <(ss -H -lntup)

    local write_test
    write_test="$(mktemp "$data_mount/.ipms-hardening-write.XXXXXX")"
    printf 'ipms-hardening-write-test\n' >"$write_test"
    if ! grep -Fxq 'ipms-hardening-write-test' "$write_test"; then
        rm -f "$write_test"
        fail "The data-mount write/read test failed."
    fi
    rm -f "$write_test"

    debsums -s >/dev/null || fail "Package-integrity validation failed."
    unattended-upgrade --dry-run >/dev/null || fail "Unattended-upgrade dry run failed."
    [[ "$(systemctl --failed --no-legend | wc -l)" == "0" ]] ||
        fail "Failed systemd units remain."
    [[ "$(journalctl -b -p 0..3 --no-pager --output=cat | sed '/^[[:space:]]*$/d' | wc -l)" == "0" ]] ||
        fail "High-priority boot errors remain."
    [[ "$(apt list --upgradable 2>/dev/null | sed '1d;/^[[:space:]]*$/d' | wc -l)" == "0" ]] ||
        fail "Package updates remain pending."
    [[ ! -e /var/run/reboot-required ]] || fail "A reboot remains pending."

    printf '{"schema":"ipms.hardening.validation.v1","version":"%s","profile":"%s","result":"pass"}\n' \
        "$SCRIPT_VERSION" "$profile"
}

apply_baseline() {
    require_root
    validate_inputs
    validate_platform
    validate_storage_preflight

    export DEBIAN_FRONTEND=noninteractive
    if [[ "$skip_package_update" != "true" ]]; then
        apt-get update
    fi
    apt-get install -y --no-install-recommends \
        apparmor-utils \
        auditd \
        audispd-plugins \
        debsums \
        libpam-pwquality \
        ufw \
        unattended-upgrades

    run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    local state_dir="$STATE_ROOT/$run_id"
    mkdir -p "$STATE_ROOT"
    chmod 0700 "$STATE_ROOT"
    create_backup "$state_dir"
    create_rollback_program "$state_dir"
    printf 'armed\n' >"$state_dir/status"
    arm_rollback "$state_dir"

    changed="false"

    install_managed_file /etc/ssh/sshd_config.d/00-ipms-hardening.conf 0644 validate_sshd_candidate <<EOF
# Managed by IPMS Appliance bootstrap v$SCRIPT_VERSION.
# OpenSSH uses the first obtained value, so this file sorts before cloud-init.
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
GSSAPIAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:30
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
AllowUsers $admin_user
EOF

    install_managed_file /etc/apt/apt.conf.d/60ipms-unattended-upgrades 0644 <<'EOF'
// Managed by IPMS Appliance bootstrap.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::SyslogEnable "true";
EOF

    install_managed_file /etc/systemd/journald.conf.d/60-ipms-hardening.conf 0644 <<'EOF'
# Managed by IPMS Appliance bootstrap.
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SystemMaxUse=1G
SystemKeepFree=2G
MaxRetentionSec=30day
EOF

    install_managed_file /etc/sysctl.d/60-ipms-hardening.conf 0644 <<'EOF'
# Managed by IPMS Appliance bootstrap.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

    install_managed_file /etc/audit/rules.d/50-ipms-baseline.rules 0640 <<'EOF'
## Managed by IPMS Appliance bootstrap.
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k ssh_configuration
-w /etc/ssh/sshd_config.d -p wa -k ssh_configuration
-w /etc/fstab -p wa -k mounts
-w /etc/ufw -p wa -k firewall
-w /etc/sysctl.conf -p wa -k kernel_configuration
-w /etc/sysctl.d -p wa -k kernel_configuration
-w /etc/systemd/system -p wa -k service_configuration
EOF

    install_managed_file /etc/sudoers.d/00-ipms-hardening 0440 validate_sudoers_candidate <<'EOF'
# Managed by IPMS Appliance bootstrap.
Defaults use_pty
Defaults timestamp_timeout=0
Defaults passwd_tries=3
EOF

    install_managed_file /etc/security/pwquality.conf.d/60-ipms-hardening.conf 0644 <<'EOF'
# Managed by IPMS Appliance bootstrap.
minlen = 14
minclass = 3
maxrepeat = 3
maxsequence = 3
difok = 4
retry = 3
enforce_for_root
EOF

    install_managed_file /etc/profile.d/60-ipms-hardening.sh 0644 <<'EOF'
# Managed by IPMS Appliance bootstrap.
umask 027
export HISTTIMEFORMAT='%Y-%m-%dT%H:%M:%S%z '
export HISTCONTROL='ignoreboth:erasedups'
EOF

    update_fstab_options "$data_mount"
    local data_source
    data_source="$(findmnt -n -o SOURCE "$data_mount")"
    [[ "$(findmnt -n -o FSTYPE "$data_mount")" == "ext4" ]] ||
        fail "The data filesystem must be ext4."
    tune2fs -e remount-ro "$data_source" >/dev/null
    mount -o remount "$data_mount"

    ensure_firewall_policy
    sshd -t
    systemctl reload ssh
    augenrules --load
    systemctl enable --now auditd apparmor unattended-upgrades >/dev/null
    systemctl restart systemd-journald
    disable_reference_services
    # Ubuntu Apport writes fs.suid_dumpable=2 when it starts. Apply the managed
    # sysctl policy only after the profile has stopped and disabled Apport.
    sysctl --system >/dev/null
    visudo -c >/dev/null
    findmnt --verify >/dev/null

    printf 'RUN_ID=%s\n' "$run_id"
    printf 'CHANGED=%s\n' "$changed"
    printf 'ROLLBACK_STATUS=armed\n'
}

commit_run() {
    require_root
    [[ "$run_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || fail "Invalid run identifier."
    local state_dir="$STATE_ROOT/$run_id"
    [[ -d "$state_dir" ]] || fail "Hardening run not found."
    [[ "$(cat "$state_dir/status")" == "armed" ]] ||
        fail "Hardening run is not awaiting commit."
    local unit
    unit="$(cat "$state_dir/rollback-unit")"
    systemctl stop "$unit.timer" "$unit.service" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
    printf 'committed\n' >"$state_dir/status"
    printf '{"schema":"ipms.hardening.commit.v1","version":"%s","result":"committed"}\n' \
        "$SCRIPT_VERSION"
}

verify_rollback() {
    require_root
    [[ "$run_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || fail "Invalid run identifier."
    local state_dir="$STATE_ROOT/$run_id"
    [[ -d "$state_dir" ]] || fail "Hardening run not found."
    [[ "$(cat "$state_dir/status")" == "rolled-back" ]] ||
        fail "The hardening run did not complete rollback."

    local unit current_state
    unit="$(cat "$state_dir/rollback-unit")"
    systemctl is-active --quiet "$unit.timer" && fail "The rollback timer is still active."

    current_state="$(mktemp)"
    record_managed_file_state "$current_state"
    cmp -s "$current_state" "$state_dir/backup/managed-files.tsv" || {
        rm -f "$current_state"
        fail "Managed files do not match their pre-run state after rollback."
    }
    record_service_state "$current_state" \
        ModemManager.service \
        udisks2.service \
        open-iscsi.service \
        iscsid.socket \
        multipathd.service \
        multipathd.socket \
        lxd-installer.socket \
        motd-news.timer \
        apport.service
    cmp -s "$current_state" "$state_dir/backup/services.tsv" || {
        rm -f "$current_state"
        fail "Service states do not match their pre-run state after rollback."
    }
    record_sysctl_state "$current_state"
    cmp -s "$current_state" "$state_dir/backup/sysctl-values.tsv" || {
        rm -f "$current_state"
        fail "Sysctl values do not match their pre-run state after rollback."
    }
    record_ext4_state "$current_state"
    cmp -s "$current_state" "$state_dir/backup/ext4-errors-behavior.tsv" || {
        rm -f "$current_state"
        fail "ext4 error behavior does not match its pre-run state after rollback."
    }
    rm -f "$current_state"

    local expected_ufw_state current_ufw_state
    expected_ufw_state="$(cat "$state_dir/backup/ufw-state")"
    if ufw status | grep -q '^Status: active'; then
        current_ufw_state="active"
    else
        current_ufw_state="inactive"
    fi
    [[ "$current_ufw_state" == "$expected_ufw_state" ]] ||
        fail "UFW activation state does not match its pre-run state after rollback."

    sshd -t
    visudo -c >/dev/null
    findmnt --verify >/dev/null
    printf '{"schema":"ipms.hardening.rollback.v1","version":"%s","result":"pass"}\n' \
        "$SCRIPT_VERSION"
}

parse_options "$@"

case "$action" in
    apply) apply_baseline ;;
    validate) validate_effective_state ;;
    commit) commit_run ;;
    verify-rollback) verify_rollback ;;
    version) printf '%s\n' "$SCRIPT_VERSION" ;;
    *) fail "Usage: $0 {apply|validate|commit|verify-rollback|version} [options]" ;;
esac
