#!/usr/bin/env bash
# Opt-in live gateway test. All external UDP is blocked in the container.
set -euo pipefail
[[ $# == 5 && $1 == /* && -f $1 ]] || { echo 'Usage: run.sh /absolute/credentials.json ROUTE4 HOST4 ROUTE6 HOST6' >&2; exit 2; }
credentials=$1
route4=$2
host4=$3
route6=$4
host6=$5
repo_dir=$(cd "$(dirname "$0")/../../.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/fortivpn-tcp.XXXXXX")
lab_name="fortivpn-tcp-test-$$-$RANDOM"
created=false
cleanup() {
 if $created; then docker rm -f "$lab_name" >/dev/null; fi
 rm -rf "$work_dir"
}
trap cleanup EXIT
cd "$repo_dir"
docker build -t fortivpn-ipsec-tcp:local tests/integration/ipsec-tcp
machine=$(docker run --rm fortivpn-ipsec-tcp:local uname -m)
case "$machine" in aarch64) target_arch=arm64;; x86_64) target_arch=amd64;; *) exit 2;; esac
GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 go test -c -o "$work_dir/ipsec.test" ./internal/ipsec
docker create --name "$lab_name" --cap-add NET_ADMIN --device /dev/net/tun \
 --mount "type=bind,source=$credentials,target=/run/credentials.json,readonly" \
 --mount "type=bind,source=$work_dir/ipsec.test,target=/run/ipsec.test,readonly" \
 fortivpn-ipsec-tcp:local >/dev/null
created=true
docker start "$lab_name" >/dev/null
for _ in {1..50}; do
 if docker exec "$lab_name" test -S /var/run/charon.vici; then break; fi
 sleep 0.1
done
docker exec "$lab_name" test -S /var/run/charon.vici
docker exec "$lab_name" iptables -I OUTPUT '!' -o lo -p udp -j REJECT
docker exec -e FORTIVPN_IPSEC_CREDENTIALS=/run/credentials.json -e FORTIVPN_IPSEC_TRANSPORT=tcp \
 -e FORTIVPN_IPSEC_ROUTE4="$route4" -e FORTIVPN_IPSEC_HOST4="$host4" \
 -e FORTIVPN_IPSEC_ROUTE6="$route6" -e FORTIVPN_IPSEC_HOST6="$host6" \
 "$lab_name" /run/ipsec.test -test.run '^TestGatewayIntegration$' -test.v -test.timeout 180s
