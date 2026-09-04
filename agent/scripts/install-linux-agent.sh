#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: sudo %s --binary PATH --enrollment PATH\n' "$0" >&2
  exit 2
}

binary_path=''
enrollment_path=''
while (($#)); do
  case "$1" in
    --binary)
      (($# >= 2)) || usage
      binary_path=$2
      shift 2
      ;;
    --enrollment)
      (($# >= 2)) || usage
      enrollment_path=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { printf 'Run this installer as root.\n' >&2; exit 1; }
[[ -f ${binary_path} && -x ${binary_path} ]] || {
  printf 'The Agent binary is missing or is not executable.\n' >&2
  exit 1
}
[[ -f ${enrollment_path} ]] || {
  printf 'The one-time enrollment document is missing.\n' >&2
  exit 1
}

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
unit_source=${script_directory}/../packaging/linux/ipms-agent.service
[[ -f ${unit_source} ]] || {
  printf 'The systemd service definition is missing.\n' >&2
  exit 1
}

install -d -m 0755 -o root -g root /usr/lib/ipms-agent
install -d -m 0700 -o root -g root /var/lib/ipms-agent
install -m 0755 -o root -g root "${binary_path}" /usr/lib/ipms-agent/ipms-agent
install -m 0600 -o root -g root "${enrollment_path}" /var/lib/ipms-agent/enrollment.json
install -m 0644 -o root -g root "${unit_source}" /etc/systemd/system/ipms-agent.service

systemctl daemon-reload
systemctl enable --now ipms-agent.service
systemctl --no-pager --full status ipms-agent.service

printf 'The IPMS Agent was installed. Securely remove the original enrollment document after verifying enrollment.\n'
