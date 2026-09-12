#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && $1 == /* ]] || { echo 'Usage: patch-ipsec-macos.sh /absolute/strongswan-5.9.14' >&2; exit 2; }
source_dir=$1
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
target="$source_dir/src/libstrongswan/networking/tun_device.c"
original=cd82777272ef39be9325423f1bb47308ffa180a87e38f9817402d1150d8deb6a
patched=6812c84cfa9352bc608c47f2c6c507ae30e77558e21688cb61cd541d3c3ab9e1
actual=$(shasum -a 256 "$target" | awk '{print $1}')
[[ $actual != "$patched" ]] || { echo 'Patch IPv6 macOS già applicate.'; exit 0; }
[[ $actual == "$original" ]] || { echo 'Sorgente tun_device.c inatteso: patch non applicate.' >&2; exit 1; }
for patch_file in "$repo_dir"/patches/strongswan/*.patch; do
 patch --batch --forward -p1 -d "$source_dir" < "$patch_file"
done
actual=$(shasum -a 256 "$target" | awk '{print $1}')
[[ $actual == "$patched" ]] || { echo 'Verifica del sorgente modificato fallita.' >&2; exit 1; }
