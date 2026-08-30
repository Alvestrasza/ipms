#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: sudo install-connector-secret.sh --credential-reference UUID" >&2
    exit 2
}

[[ $EUID -eq 0 ]] || { echo "Run this helper as root." >&2; exit 1; }
[[ ${1:-} == "--credential-reference" && ${2:-} =~ ^[0-9a-f-]{36}$ && $# -eq 2 ]] || usage

secret_directory=/srv/ipms/shared/connector-secrets
target="${secret_directory}/${2}.json"
temporary=$(mktemp /tmp/ipms-connector-secret.XXXXXX)
cleanup() {
    rm -f -- "$temporary"
}
trap cleanup EXIT

umask 0077
cat > "$temporary"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert set(d)=={"username","password"}; assert all(isinstance(d[k],str) and d[k] for k in d)' "$temporary" \
    || { echo "Credential input is invalid." >&2; exit 1; }
install -d -o root -g ipms-control-plane -m 0750 "$secret_directory"
install -o root -g ipms-control-plane -m 0640 "$temporary" "$target"
echo "Connector credential installed without displaying its value."
