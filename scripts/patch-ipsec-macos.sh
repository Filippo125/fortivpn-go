#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && $1 == /* ]] || { echo 'Usage: patch-ipsec-macos.sh /absolute/strongswan-5.9.14' >&2; exit 2; }
source_dir=$1
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
tun_target="$source_dir/src/libstrongswan/networking/tun_device.c"
tun_original=cd82777272ef39be9325423f1bb47308ffa180a87e38f9817402d1150d8deb6a
tun_ipv6_patched=6812c84cfa9352bc608c47f2c6c507ae30e77558e21688cb61cd541d3c3ab9e1
tun_patched=d828f13f2e799519df42c811afbe3a8d770a58632bf857cbda94a52de8992bd7
pfroute_target="$source_dir/src/libcharon/plugins/kernel_pfroute/kernel_pfroute_net.c"
pfroute_original=3a0b01f8df2e7f61d219b39e0cfbdaaf8d40ddd143df81146d78dfabdf77d578
pfroute_patched=ca3f610c7539623d9f23d1fd9715b34e24e5a1718d7e89e426d9a6ea0a56b0b8

tun_actual=$(shasum -a 256 "$tun_target" | awk '{print $1}')
case "$tun_actual" in
 "$tun_original")
 for patch_file in "$repo_dir"/patches/strongswan/000{1,2,3}-*.patch; do
   patch --batch --forward -p1 -d "$source_dir" < "$patch_file"
  done
  ;;
 "$tun_ipv6_patched"|"$tun_patched") echo 'Patch indirizzo utun IPv6 macOS già applicate.' ;;
 *) echo 'Sorgente tun_device.c inatteso: patch non applicate.' >&2; exit 1 ;;
esac

tun_actual=$(shasum -a 256 "$tun_target" | awk '{print $1}')
case "$tun_actual" in
 "$tun_ipv6_patched")
  patch --batch --forward -p1 -d "$source_dir" < "$repo_dir/patches/strongswan/0005-utun-ipv6-packet-protocol.patch"
  ;;
 "$tun_patched") echo 'Patch protocollo pacchetti utun IPv6 già applicata.' ;;
 *) echo 'Sorgente tun_device.c inatteso dopo le patch indirizzo.' >&2; exit 1 ;;
esac

pfroute_actual=$(shasum -a 256 "$pfroute_target" | awk '{print $1}')
case "$pfroute_actual" in
 "$pfroute_original")
  patch --batch --forward -p1 -d "$source_dir" < "$repo_dir/patches/strongswan/0004-pfroute-interface-gateway.patch"
  ;;
 "$pfroute_patched") echo 'Patch PF_ROUTE macOS già applicata.' ;;
 *) echo 'Sorgente kernel_pfroute_net.c inatteso: patch non applicata.' >&2; exit 1 ;;
esac

tun_actual=$(shasum -a 256 "$tun_target" | awk '{print $1}')
pfroute_actual=$(shasum -a 256 "$pfroute_target" | awk '{print $1}')
[[ $tun_actual == "$tun_patched" && $pfroute_actual == "$pfroute_patched" ]] || {
 echo 'Verifica dei sorgenti strongSwan modificati fallita.' >&2
 exit 1
}
