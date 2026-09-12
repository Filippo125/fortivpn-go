#!/usr/bin/env bash
# Foreground native lab session. Start from an interactive terminal with sudo.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'Questo script richiede macOS.' >&2; exit 1; }
[[ $# == 6 && $1 == /* && $2 == /* && $3 == /* ]] || {
 echo 'Usage: run-ipsec-macos.sh /runtime /fortivpn /credentials.json REMOTE_ID ROUTE4 ROUTE6' >&2
 exit 2
}
runtime_dir=$1
client_bin=$2
credentials=$3
remote_id=$4
route4=$5
route6=$6
missing=false
for binary in "$runtime_dir/libexec/ipsec/charon" "$client_bin"; do
 if [[ ! -x "$binary" ]]; then echo "Eseguibile mancante o non eseguibile: $binary" >&2; missing=true; fi
done
if [[ ! -f "$credentials" ]]; then echo "File credenziali mancante: $credentials" >&2; missing=true; fi
if $missing; then
 echo 'Ricreare i prerequisiti in una directory privata prima di riprovare.' >&2
 exit 2
fi
[[ $EUID == 0 ]] || { echo 'Avviare questo script con sudo per creare le interfacce e le route.' >&2; exit 1; }
pid_file="$runtime_dir/run/charon.pid"
socket_file="$runtime_dir/run/charon.vici"
if [[ -e "$pid_file" || -S "$socket_file" ]]; then
 old_pid=$(cat "$pid_file" 2>/dev/null || true)
 if [[ ! "$old_pid" =~ ^[1-9][0-9]*$ ]] || kill -0 "$old_pid" 2>/dev/null; then
  echo 'Runtime attivo o stato non verificabile: nessuna risorsa rimossa.' >&2
  exit 1
 fi
 if /usr/sbin/lsof -t "$socket_file" >/dev/null 2>&1; then
  echo 'Socket VICI ancora in uso: nessuna risorsa rimossa.' >&2
  exit 1
 fi
 echo 'Rimozione dei file PID/socket del daemon terminato.'
 rm -f -- "$pid_file" "$socket_file"
fi
daemon_pid=''
cleanup() {
 if [[ -n "$daemon_pid" ]]; then
  kill -TERM "$daemon_pid" 2>/dev/null || true
  wait "$daemon_pid" || true
  if [[ $(cat "$pid_file" 2>/dev/null || true) == "$daemon_pid" ]] && ! /usr/sbin/lsof -t "$socket_file" >/dev/null 2>&1; then
   rm -f -- "$pid_file" "$socket_file"
  fi
 fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
echo 'Avvio del daemon IPsec macOS...'
"$runtime_dir/libexec/ipsec/charon" &
daemon_pid=$!
for _ in {1..50}; do
 kill -0 "$daemon_pid" 2>/dev/null || { echo 'Daemon failed to start' >&2; exit 1; }
 [[ -S "$runtime_dir/run/charon.vici" ]] && break
 sleep 0.1
done
[[ -S "$runtime_dir/run/charon.vici" ]] || { echo "Timeout: socket VICI non creato in $runtime_dir/run/charon.vici" >&2; exit 1; }
chmod 600 "$runtime_dir/run/charon.vici"
echo 'Connessione TCP/4500 al laboratorio; disconnessione automatica dopo 60 secondi.'
"$client_bin" ipsec connect --socket "$runtime_dir/run/charon.vici" \
 --credentials "$credentials" --remote-id "$remote_id" --transport tcp --tcp-port 4500 \
 --ip-mode dual --route "$route4" --route "$route6" --duration 60s
