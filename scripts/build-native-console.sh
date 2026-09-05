#!/usr/bin/env bash
# Build the pinned, RDP-only adapter without installing or restarting services.
set -euo pipefail
umask 027

if [[ $# != 2 ]]; then
    echo 'Usage: build-native-console.sh <verified-source-directory> <new-build-directory>' >&2
    exit 2
fi
source_directory=$(realpath -e -- "$1")
build_directory=$(realpath -m -- "$2")
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
adaptation_directory=$(realpath -e -- "$script_directory/../deploy/native-console")
archive="$source_directory/guacamole-server-1.6.0.tar.gz"
command -v make >/dev/null
command -v gcc >/dev/null
expected_archive=8bc45675da96d7b6f39728160181e3d4ff3c08f460f6d26de5805b642bf13f2b
expected_signer=F467E54ACC52F1D2778826865B2977AEE5E4518F
prefix=/srv/ipms/dependencies/guacamole-1.6.0-ipms1

[[ ! -e "$build_directory" && ! -L "$build_directory" ]]
case "$build_directory" in /tmp/ipms-native-console-*/*|/srv/ipms/build/native-console-*) ;; *) exit 2 ;; esac
[[ "$(sha256sum -- "$archive" | cut -d ' ' -f 1)" == "$expected_archive" ]]
mkdir -m 0750 -- "$build_directory"
mkdir -m 0700 -- "$build_directory/gnupg"
gpg --homedir "$build_directory/gnupg" --batch --import "$source_directory/KEYS"
gpg --homedir "$build_directory/gnupg" --batch --status-fd 1 \
    --verify "$archive.asc" "$archive" > "$build_directory/signature.status"
grep -q "^\[GNUPG:\] VALIDSIG $expected_signer " "$build_directory/signature.status"
tar --extract --gzip --file "$archive" --directory "$build_directory"
cd -- "$build_directory/guacamole-server-1.6.0"
patch --batch --fuzz=0 -p1 < "$adaptation_directory/guacamole-1.6.0-strict-certificate.patch"
patch --batch --fuzz=0 -p1 < "$adaptation_directory/guacamole-1.6.0-nested-socket.patch"
install -m 0644 -- "$adaptation_directory/ipms-strict-certificate.h" src/protocols/rdp/
install -m 0644 -- "$adaptation_directory/ipms-wol-disabled.c" src/libguac/wol.c

# Exact reviewed API baseline. Upgrades require pin/redirect/rendering tests.
pkg-config --exact-version=3.31.0 freerdp3
# FreeRDP 3.31 headers retain deprecated ABI declarations, including aliases
# inside their own structs. Keep these visible as warnings; all other upstream
# warning-as-error checks remain enabled.
export CFLAGS='-std=gnu11 -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wno-error=deprecated-declarations'
export LDFLAGS='-Wl,-z,relro,-z,now'
./configure --prefix="$prefix" --with-rdp --without-vnc --without-ssh \
    --without-telnet --disable-kubernetes --disable-guacenc --disable-guaclog \
    --without-pulse --without-vorbis --without-pango > "$build_directory/configure.log" 2>&1
make -j2 > "$build_directory/make.log" 2>&1
MALLOC_PERTURB_=165 timeout --kill-after=10 120 make check -j2 > "$build_directory/check.log" 2>&1
make DESTDIR="$build_directory/dest" install > "$build_directory/install.log" 2>&1
install -m 0644 LICENSE NOTICE "$build_directory/dest$prefix/"
install -m 0644 -- "$adaptation_directory/ipms-strict-certificate.h" \
    "$adaptation_directory/ipms-wol-disabled.c" \
    "$adaptation_directory/guacamole-1.6.0-nested-socket.patch" \
    "$adaptation_directory/guacamole-1.6.0-strict-certificate.patch" "$build_directory/dest$prefix/"
sha256sum "$build_directory/dest$prefix/sbin/guacd" \
    "$build_directory/dest$prefix/lib/libguac-client-rdp.so" \
    "$build_directory/dest$prefix/ipms-strict-certificate.h"
printf 'Native console adapter staged at %s\n' "$build_directory/dest$prefix"
