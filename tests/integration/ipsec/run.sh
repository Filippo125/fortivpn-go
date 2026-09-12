#!/usr/bin/env bash
# Opt-in gateway-backed tests. Requires Go, Docker and the configured lab gateway.
set -euo pipefail
if [[ $# -ne 5 || "$1" != /* || ! -f "$1" ]]; then
    echo "Usage: $0 /absolute/credentials.json ROUTE4 HOST4 ROUTE6 HOST6" >&2
    exit 2
fi
credentials="$1"
route4="$2"
host4="$3"
route6="$4"
host6="$5"
repo_dir="$(cd "$(dirname "$0")/../../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/fortivpn-ipsec.XXXXXX")"
lab_name="fortivpn-ipsec-test-$$-$RANDOM"
network_created=false
container_created=false
cleanup() {
    if $container_created; then docker rm -f "$lab_name" >/dev/null; fi
    if $network_created; then docker network rm "$lab_name" >/dev/null; fi
    rm -rf "$work_dir"
}
trap cleanup EXIT
cd "$repo_dir"
docker build -t fortivpn-ipsec-lab:local tests/integration/ipsec
machine="$(docker run --rm fortivpn-ipsec-lab:local uname -m)"
case "$machine" in
    aarch64) target_arch=arm64 ;;
    x86_64) target_arch=amd64 ;;
    *) echo "Unsupported Docker architecture: $machine" >&2; exit 1 ;;
esac
GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 go test -c -o "$work_dir/ipsec.test" ./internal/ipsec
printf -v ipv6_subnet 'fd71:8e31:%x::/64' "$RANDOM"
docker network create --ipv6 --subnet "$ipv6_subnet" "$lab_name" >/dev/null
network_created=true
docker create --name "$lab_name" --network "$lab_name" --cap-add NET_ADMIN \
    --mount "type=bind,source=$credentials,target=/run/lab-secrets.json,readonly" \
    --mount "type=bind,source=$work_dir/ipsec.test,target=/run/ipsec.test,readonly" \
    fortivpn-ipsec-lab:local >/dev/null
container_created=true
docker start "$lab_name" >/dev/null
ready=false
for _ in {1..30}; do
    if docker exec "$lab_name" test -S /var/run/charon.vici; then ready=true; break; fi
    sleep 0.2
done
if ! $ready; then docker logs "$lab_name"; exit 1; fi
docker exec -e FORTIVPN_IPSEC_CREDENTIALS=/run/lab-secrets.json \
    -e FORTIVPN_IPSEC_ROUTE4="$route4" -e FORTIVPN_IPSEC_HOST4="$host4" \
    -e FORTIVPN_IPSEC_ROUTE6="$route6" -e FORTIVPN_IPSEC_HOST6="$host6" "$lab_name" \
    /run/ipsec.test -test.run '^TestGatewayIntegration$' -test.v -test.timeout 180s
