#!/usr/bin/env bash
# Builds an isolated native runtime. Does not install system services or use sudo.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'This script requires macOS' >&2; exit 1; }
[[ $# == 2 && $1 == /* && $2 == /* ]] || { echo 'Usage: build-ipsec-macos.sh /absolute/source-dir /absolute/install-dir' >&2; exit 2; }
source_dir=$1
install_dir=$2
openssl_dir=${OPENSSL_PREFIX:-/opt/homebrew/opt/openssl@3}
[[ -f "$openssl_dir/include/openssl/ssl.h" ]] || { echo 'Set OPENSSL_PREFIX to an existing OpenSSL installation' >&2; exit 1; }
case "$install_dir" in
 *[!a-zA-Z0-9_./-]*) echo 'Use a runtime path containing only letters, digits, _, ., /, -' >&2; exit 2 ;;
esac
"$(dirname "$0")/patch-ipsec-macos.sh" "$source_dir"
cd "$source_dir"
CPPFLAGS="-I$openssl_dir/include" LDFLAGS="-L$openssl_dir/lib" ./configure \
 --prefix="$install_dir" --sysconfdir="$install_dir/etc" --with-piddir="$install_dir/run" \
 --disable-defaults --enable-charon --enable-ikev2 --enable-vici --enable-swanctl \
 --enable-kdf --enable-openssl --enable-random --enable-nonce --enable-pem --enable-pkcs1 \
 --enable-pubkey --enable-psk --enable-eap-identity --enable-eap-mschapv2 --enable-md4 \
 --enable-socket-default --enable-kernel-pfroute --enable-libipsec --enable-kernel-libipsec
make -j"$(sysctl -n hw.ncpu)"
make install
mkdir -p "$install_dir/run"

# Runtime configuration contains no credentials. The VICI socket is local.
cat > "$install_dir/etc/strongswan.conf" <<CONFIG
charon {
 load_modular = yes
 port = 15000
 port_nat_t = 4500
 keep_alive = 0
 plugins {
  include strongswan.d/charon/*.conf
  kernel-libipsec { load = 100 }
  socket-default { use_ipv6 = no }
  vici { socket = unix://$install_dir/run/charon.vici }
 }
 filelog {
  stderr {
   default = 1
   flush_line = yes
  }
 }
}
CONFIG
