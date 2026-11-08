#!/usr/bin/env bash
# deploy/sandbox/verify_sandbox.sh
#
# Run on the server, as root, after the install steps in README.md. Prints PASS / FAIL / WARN
# for each check and the facts to write down for the paper (versions, image digest).
# It changes nothing. Exit code 1 if any check FAILED.
#
#   sudo ./verify_sandbox.sh [--client-ip PUBLIC_IP_YOU_CONNECTED_FROM] [--allow-private]
#
# Without --client-ip it still checks that Cowrie is not seeing Docker's own address.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$(cd "$HERE/../.." && pwd)"
LOG_DIR="$APP/honeypot_dataset/cowrie/logs"
CONTAINER="${COWRIE_CONTAINER:-cowrie-sandbox}"
PIPELINE_ENV="${PIPELINE_ENV:-/etc/honeypot/pipeline.env}"
GUARD_ENV="${GUARD_ENV:-/etc/honeypot-guard/guard.env}"
COWRIE_ENV="${COWRIE_ENV:-$HERE/cowrie.env}"
BLOCKLIST="${BLOCKLIST:-/var/lib/honeypot-guard/blocklist.json}"
KILL_FILE="${KILL_FILE:-/var/lib/honeypot-guard/MITIGATION_DISABLED}"

CLIENT_IP=""
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --client-ip) CLIENT_IP="${2:-}"; shift 2 ;;
    --allow-private) EXTRA+=(--allow-private); shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

fails=0; warns=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
warn() { printf '  WARN  %s\n' "$1"; warns=$((warns + 1)); }
info() { printf '  info  %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
# Value of KEY in an env file (last one wins), or nothing.
envval() { [ -r "$2" ] && grep -E "^$1=" "$2" | tail -n 1 | cut -d= -f2-; }

echo "== Who and where"
[ "$(id -u)" -eq 0 ] && pass "running as root" || { fail "run this as root (sudo)"; }
for tool in docker nft python3 ss; do have "$tool" || fail "$tool is not installed"; done

PORT="$(envval COWRIE_PUBLIC_PORT "$COWRIE_ENV")"; PORT="${PORT:-2222}"
info "Cowrie public port: $PORT   (from $COWRIE_ENV, default 2222)"

echo "== Services"
for unit in honeypot-egress.service honeypot-guard.timer honeypot-pipeline.service; do
  if systemctl is-active --quiet "$unit" 2>/dev/null; then pass "$unit is active"; else fail "$unit is not active (systemctl status $unit)"; fi
done

echo "== Cowrie container"
if have docker && docker inspect "$CONTAINER" >/dev/null 2>&1; then
  state="$(docker inspect -f '{{.State.Status}}' "$CONTAINER")"
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER")"
  [ "$state" = running ] && pass "container is running" || fail "container state is '$state'"
  [ "$health" = healthy ] && pass "container is healthy" || warn "container health is '$health' (give it 30 s after a start)"
  mapping="$(docker port "$CONTAINER" 2222/tcp 2>/dev/null)"
  info "published: $(echo "$mapping" | tr '\n' ' ')"
  if echo "$mapping" | grep -q '::'; then
    fail "the port is also published on IPv6; Docker would hide IPv6 attackers' real addresses"
  elif [ -n "$mapping" ]; then pass "the port is published on IPv4 only"; else fail "no published port"; fi
else
  fail "container '$CONTAINER' not found (docker compose --env-file ./cowrie.env up -d)"
fi

if [ "$PORT" = 22 ]; then
  if ss -ltnpH "sport = :22" 2>/dev/null | grep -q sshd; then
    fail "the host's own sshd is still listening on port 22 (move it first, README part B)"
  else pass "the host's sshd is not on port 22"; fi
fi

echo "== Firewall"
if have nft; then
  guard="$(nft list table inet honeypot_guard 2>/dev/null)"
  if echo "$guard" | grep -q 'priority raw' && echo "$guard" | grep -q 'ip saddr @blocked_v4 drop'; then
    pass "block table is loaded (drops at 'raw', before Docker's rules)"
  else fail "block table honeypot_guard is missing or wrong (is honeypot-guard.timer running? wait 20 s)"; fi

  egress="$(nft list table inet honeypot_egress 2>/dev/null)"
  if [ "$(echo "$egress" | grep -c 'br-honeypot')" -ge 2 ]; then pass "outbound block is loaded (forward + input)"
  else fail "outbound block honeypot_egress is missing (systemctl start honeypot-egress)"; fi

  # Does it really stop the container? Try to open a connection to TEST-NET-1 (never routed,
  # nothing is contacted). If our rule sees and drops it, its counter goes up.
  count() { nft list chain inet honeypot_egress forward_guard 2>/dev/null | sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | head -n 1; }
  if [ -n "$egress" ] && have docker && docker inspect "$CONTAINER" >/dev/null 2>&1; then
    before="$(count)"
    docker exec "$CONTAINER" /cowrie/cowrie-env/bin/python3 -c \
      'import socket; socket.create_connection(("192.0.2.1", 9), 3)' >/dev/null 2>&1
    after="$(count)"
    if [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ]; then
      pass "the honeypot cannot start outbound connections (the rule dropped our test)"
    else fail "the outbound rule did not see a test connection from the container (counter $before -> $after)"; fi
  fi

  if python3 /opt/honeypot-guard/apply_blocklist.py --blocklist "$BLOCKLIST" --kill-file "$KILL_FILE" --dry-run >/dev/null 2>&1; then
    pass "the block-list script runs (dry run)"
  else fail "the block-list script failed a dry run: sudo python3 /opt/honeypot-guard/apply_blocklist.py --blocklist $BLOCKLIST --dry-run"; fi
fi

echo "== Does Cowrie see the attackers' real addresses?"
if [ ! -f "$HERE/check_cowrie_ips.py" ]; then
  fail "check_cowrie_ips.py is missing next to this script"
elif have python3; then
  out="$(python3 "$HERE/check_cowrie_ips.py" "$LOG_DIR" ${CLIENT_IP:+--client-ip "$CLIENT_IP"} "${EXTRA[@]+"${EXTRA[@]}"}" 2>&1)"; code=$?
  while IFS= read -r line; do info "$line"; done <<<"$out"
  case "$code" in
    0) pass "real addresses are visible" ;;
    2) warn "no connections yet. From another machine run: ssh -p $PORT root@<this server>   then run this again with --client-ip" ;;
    3) fail "your test connection is not in the log" ;;
    *) fail "Cowrie is not seeing real addresses (see above)" ;;
  esac
fi

echo "== Settings"
mode="$(envval MITIGATION_MODE "$PIPELINE_ENV")"; fw="$(envval MITIGATION_FIREWALL "$PIPELINE_ENV")"
info "MITIGATION_MODE=${mode:-observe}  MITIGATION_FIREWALL=${fw:-0}"
if [ "${mode:-observe}" = enforce ] && [ "${fw:-0}" = 1 ]; then warn "real blocking is ON. Stage 0 should be observe + firewall 0."; fi
[ -n "$(envval MITIGATION_NEVER_BLOCK "$PIPELINE_ENV")" ] && pass "pipeline never-block list is set" || warn "MITIGATION_NEVER_BLOCK is empty in $PIPELINE_ENV (add your own IP)"
[ -n "$(envval HONEYPOT_GUARD_NEVER_BLOCK "$GUARD_ENV")" ] && pass "firewall script never-block list is set" || warn "HONEYPOT_GUARD_NEVER_BLOCK is empty in $GUARD_ENV (add your own IP)"
[ "$(envval HF_HUB_OFFLINE "$PIPELINE_ENV")" = 1 ] || info "HF_HUB_OFFLINE is not 1 yet; set it after the first successful start"
if [ -e "$KILL_FILE" ]; then warn "the kill switch is ON ($KILL_FILE exists): nothing is being blocked"; else info "kill switch is off"; fi

echo "== Model files (copied by hand; they are not in git)"
for f in ml_analytics/artifacts/mt3_full_d256/best.pt honeypot_dataset/data/final/feature_scaler.pkl; do
  [ -s "$APP/$f" ] && pass "$f ($(du -h "$APP/$f" | cut -f1))" || fail "$f is missing"
done
f=honeypot_dataset/data/processed/semantic_pca.pkl
[ -s "$APP/$f" ] && pass "$f" || warn "$f is missing: 30 of the 128 features will be zero and MT3 will be less confident"

echo "== Disk"
avail_kb="$(df -Pk /var/lib | awk 'NR==2 {print $4}')"
[ "${avail_kb:-0}" -ge 5242880 ] && pass "$((avail_kb / 1024 / 1024)) GB free under /var/lib" || warn "less than 5 GB free under /var/lib"

echo "== Facts to write down (provenance)"
info "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
info "repo commit: $(git -C "$APP" rev-parse --short HEAD 2>/dev/null || echo unknown)"
have docker && info "docker: $(docker version -f '{{.Server.Version}}' 2>/dev/null)"
have docker && info "cowrie image: $(docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null)  digest: $(docker image inspect -f '{{index .RepoDigests 0}}' "$(docker inspect -f '{{.Image}}' "$CONTAINER" 2>/dev/null)" 2>/dev/null || echo unknown)"
have nft && info "$(nft --version)"
info "kernel: $(uname -r)"
info "os: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"

echo
echo "Result: $fails failed, $warns warnings"
[ "$fails" -eq 0 ]
