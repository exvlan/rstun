#!/usr/bin/env bash
#
# `rstun` TURN（RFC 8656）验收：强制鉴权 / 中继回环 / 配额与端口 / 回收 / 指标 /
# 与 coturn 的对照。默认关闭的 STUN 路径不在这里重测（那是 `rstun-interop.sh` 与
# `rstun-abuse.sh` 的门禁）。
#
# 用法：
#   bash script/lab/rstun-turn.sh                  # 全部项（lean 构建：tls/dtls 标 SKIP）
#   bash script/lab/rstun-turn.sh --port 34980     # 端口基准（默认 34980）
#   bash script/lab/rstun-turn.sh --no-build       # 复用 target/debug/rstun（探测其 feature）
#   bash script/lab/rstun-turn.sh --tls --dtls     # 只跑 TLS/DTLS 项（自动 --features full 构建）
#   bash script/lab/rstun-turn.sh --only relay     # 只跑一项
#     （startup|relay|tcprelay|tcp-relay-passive|multi-instance-udp|multi-instance-tcp|
#       multi-instance-tcp-relay|multi-instance-tls|multi-instance-dtls|auth|lifecycle|
#       wrong-user|raf|df|ipv6relay|wildcard|permission-limit|quota|ports|tls|dtls|
#       cert-reload|cert-poll|rest|bandwidth|cleanup|frozen|coturn）
#   bash script/lab/rstun-turn.sh --keep           # 保留日志（默认只清进程）
#   FROZEN_BASE=<sha> bash script/lab/rstun-turn.sh --only frozen
#                                                  # 字节冻结对照的基线提交（默认 cad4fa2）
#
# 构建：默认 lean（`cargo build`，无 tls/dtls feature）。`--tls` / `--dtls` /
# `--only tls|dtls|cert-reload|cert-poll|coturn` 会自动用 `cargo build --features full` 构建；`--no-build`
# 时探测现有二进制是否带 feature。lean 下 tls/dtls 项记 SKIP（不是失败），
# coturn 项的 TLS/DTLS 对照行同样跳过。
#
# frozen 基线约定：`FROZEN_BASE` 是指「本次改动之前」的提交。基线二进制会用
# `RSTUN_BUILD_VERSION=<当前二进制的版本串>` 重新构建，因此**版本号 bump 不会让
# frozen 假红**，基线不需要随发版挪动；只有当你想换对照点（例如上次改动本身要当
# 新基线）时才改默认值。
#
# 依赖：cargo/rustc（本仓）、python3（探针，只用标准库）、`turnutils_uclient`
# （coturn 自带客户端）、`openssl`（TLS/DTLS 项自签证书 + 握手探针）。
# `turnserver` 缺失时 coturn 项记 SKIP 并说明；其余项用本仓探针 + uclient，
# 缺 uclient/openssl 的项同理 SKIP。
#
# 退出码：0 = 全部 ok；1 = 至少一项 FAIL；2 = 参数/环境错误。
# 日志：$RSTUN_TURN_DIR（默认 /tmp/opencode/rstun-turn），每项一个 .log。
#
# 判据提醒：本脚本用**真 socket + 真鉴权**，不用 mock。cleanup 项用
# `--allocation-lifetime 2` 让 allocation 自然过期，再断言 `ss -lun` + `ss -ltn`
# 在 relay 端口段内无监听 —— 这就是「回收彻底」的可执行定义。开始前先快照该段
# （UDP+TCP）：宿主的其它服务若占着段内端口，cleanup 记 SKIP（打印端口）而不是
# FAIL，tcprelay / tcp-relay-passive 则只把自己新增的端口算作残留。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/debug/rstun"
PROBE="$ROOT/script/lab/rstun-turn-probe.py"
WORK="${RSTUN_TURN_DIR:-/tmp/opencode/rstun-turn}"
LOG_DIR="$WORK/logs"

BASE=34980
RELAY_LO=49700
RELAY_HI=49799
BUILD=true
ONLY=""
T2_ONLY=()
# 空的 = lean 构建；需要 secure 传输的项会把它设成 `--features full`。
CARGO_FEATURES=()
# 当前二进制是否带 tls/dtls（building 时由 CARGO_FEATURES 决定，--no-build 时探测）。
HAVE_SECURE=false

USER_NAME="turnuser"
USER_PASS="turnpass"
REALM="example.org"
SECRET="turn-test-secret"

PIDS=()
FAILED=()
SKIPPED=()
PASSED=()

ALL_ITEMS=(startup relay tcprelay tcp-relay-passive multi-instance-udp multi-instance-tcp multi-instance-tcp-relay multi-instance-tls multi-instance-dtls auth lifecycle wrong-user raf df ipv6relay wildcard permission-limit quota ports tls dtls cert-reload cert-poll rest bandwidth cleanup frozen coturn)

usage() {
  # The doc block is the comment header above `set -uo pipefail`.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) BASE="${2:?--port 需要一个端口}"; shift ;;
    --port=*) BASE="${1#*=}" ;;
    --no-build) BUILD=false ;;
    --tls) T2_ONLY+=(tls multi-instance-tls) ;;
    --dtls) T2_ONLY+=(dtls multi-instance-dtls) ;;
    --only) ONLY="${2:?--only 需要一项名字}"; shift ;;
    --only=*) ONLY="${1#*=}" ;;
    --keep) : ;;
    -h | --help) usage; exit 0 ;;
    *) echo "未知参数: $1（--help 看用法）" >&2; exit 2 ;;
  esac
  shift
done

if ! [[ "$BASE" =~ ^[0-9]+$ ]]; then
  echo "--port 需要整数，收到: $BASE" >&2
  exit 2
fi
if [[ "$BASE" == "3478" || "$BASE" -le 1024 ]]; then
  echo "不要用 3478/特权端口（容易撞上本机服务）；给个高位端口" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "需要 python3（探针只用标准库）" >&2
  exit 2
fi
if [[ -n "$ONLY" ]]; then
  case "$ONLY" in
    startup | relay | tcprelay | tcp-relay-passive | multi-instance-udp | multi-instance-tcp | multi-instance-tcp-relay | multi-instance-tls | multi-instance-dtls | auth | lifecycle | wrong-user | raf | df | ipv6relay | wildcard | permission-limit | quota | ports | tls | dtls | cert-reload | cert-poll | rest | bandwidth | cleanup | frozen | coturn) : ;;
    *) echo "--only 未知项: $ONLY（可用：${ALL_ITEMS[*]}）" >&2; exit 2 ;;
  esac
fi

export PYTHONIOENCODING=utf-8
mkdir -p "$LOG_DIR"
: >"$LOG_DIR/summary.log"

log() { printf '%s\n' "$*" | tee -a "$LOG_DIR/summary.log"; }
ok() { PASSED+=("$1"); log "ok: $1${2:+ $2}"; }
fail() { FAILED+=("$1"); log "FAIL: $1${2:+ — $2}"; }
skip() { SKIPPED+=("$1"); log "SKIP: $1${2:+ — $2}"; }

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# ---------- process helpers ----------

start_server() { # name args...
  local name="$1"
  shift
  "$BIN" server "$@" >"$LOG_DIR/$name.log" 2>&1 &
  echo $! >>"$WORK/pids"
  PIDS+=("$!")
}

stop_server() { # name
  local name="$1"
  local pid
  pid="$(tail -n 1 "$WORK/pids" 2>/dev/null || true)"
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  sed '$d' "$WORK/pids" >"$WORK/pids.tmp" 2>/dev/null && mv "$WORK/pids.tmp" "$WORK/pids"
}

wait_health() { # port [tries]
  local port="$1"
  local tries="${2:-50}"
  local i=0
  while (( i < tries )); do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

metric() { # name
  curl -fsS "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null |
    awk -v name="$1" '$1 == name {print $2; found=1} END {if (!found) print ""}'
}

metric_at() { # ip name
  curl -fsS "http://$1:$HEALTH_PORT/metrics" 2>/dev/null |
    awk -v name="$2" '$1 == name {print $2; found=1} END {if (!found) print ""}'
}

metric_sum() { # name
  # Every instance reports its own view, so the cluster-wide count is the sum.
  local sum=0 value
  for ip in 127.0.0.1 127.0.0.2; do
    value="$(metric_at "$ip" "$1")"
    [[ -n "$value" ]] && sum=$((sum + value))
  done
  echo "$sum"
}

wait_ready_file() { # path [tries]
  local path="$1"
  local tries="${2:-50}"
  local i=0
  while (( i < tries )); do
    [[ -s "$path" ]] && return 0
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

udp_port_present() { # port
  ss -lunH 2>/dev/null | awk -v p="$1" '{ n = split($4, a, ":"); if (a[n] == p) found = 1 } END { exit !found }'
}

relay_sockets_owned() { # pid
  # Sockets in the relay range that belong to **our** process. The range can
  # overlap a host service (e.g. a proxy that binds a random port inside it);
  # the cleanup assertion must not blame that service on us.
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  {
    ss -lunpH 2>/dev/null | awk -v pid="$pid" 'index($0, "pid=" pid ",") {print $4}'
    ss -ltnpH 2>/dev/null | awk -v pid="$pid" 'index($0, "pid=" pid ",") {print $4}'
  } | awk -F: -v lo="$RELAY_LO" -v hi="$RELAY_HI" '
      { port = $NF + 0; if (port >= lo && port <= hi) print $NF }
    ' | sort -u
}

tcp_port_present() { # port
  ss -ltnH 2>/dev/null | awk -v p="$1" '{ n = split($4, a, ":"); if (a[n] == p) found = 1 } END { exit !found }'
}

wait_port_gone() { # proto port [tries]
  local proto="$1"
  local port="$2"
  local tries="${3:-50}"
  local i=0
  while (( i < tries )); do
    if [[ "$proto" == udp ]]; then
      udp_port_present "$port" || return 0
    else
      tcp_port_present "$port" || return 0
    fi
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

loopback_alias_ok() { # ip proto
  python3 -c '
import socket, sys
host, kind = sys.argv[1], sys.argv[2]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
try:
    sock.bind((host, 0))
except OSError:
    sys.exit(1)
finally:
    sock.close()
' "$1" "$2"
}

wait_health_at() { # ip [tries]
  local ip="$1"
  local tries="${2:-50}"
  local i=0
  while (( i < tries )); do
    if curl -fsS "http://$ip:$HEALTH_PORT/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

relay_listeners() {
  # Listening UDP sockets whose local port is inside the relay range.
  ss -lunH 2>/dev/null | awk '{print $4}' | awk -F: -v lo="$RELAY_LO" -v hi="$RELAY_HI" '
    { port = $NF + 0; if (port >= lo && port <= hi) print $NF }
  ' | sort -u
}

relay_tcp_listeners() {
  # RFC 6062 TCP relay listeners are LISTEN sockets, invisible to `ss -lun`.
  ss -ltnH 2>/dev/null | awk '{print $4}' | awk -F: -v lo="$RELAY_LO" -v hi="$RELAY_HI" '
    { port = $NF + 0; if (port >= lo && port <= hi) print $NF }
  ' | sort -u
}

relay_sockets() {
  # Every listening socket (UDP **and** TCP) whose local port is inside the
  # relay range. TCP has to be included since RFC 6062: its relay is a LISTEN
  # socket, invisible to `ss -lun`, so a UDP-only view reports false leftovers
  # (and a false "range is clean" before a run).
  { relay_listeners; relay_tcp_listeners; } | sort -u
}

relay_new_sockets() { # before-snapshot
  # Relay-range sockets that appeared **after** `$1` was taken. An unrelated
  # service squatting in the range must not be reported as this server's
  # leftover; only what our run added is an assertion failure.
  local before="$1"
  comm -13 <(printf '%s\n' "${before:-}" | sort -u) <(relay_sockets)
}

turn_args() { # extra args...
  printf '%s\0' "--listen" "127.0.0.1:$BASE" \
    "--turn" "--realm" "$REALM" "--auth-secret" "$SECRET" \
    "--auth-user" "$USER_NAME" "--auth-pass" "$USER_PASS" \
    "--relay-ports" "$RELAY_LO-$RELAY_HI" \
    "--health-listen" "127.0.0.1:$HEALTH_PORT" "$@"
}

start_turn() { # name extra args...
  local name="$1"
  shift
  local args=()
  while IFS= read -r -d '' arg; do args+=("$arg"); done < <(turn_args "$@")
  start_server "$name" "${args[@]}"
}

# Same server, two users: needed for the 441 (Wrong Credentials) cases.
start_turn_users() { # name extra args...
  local name="$1"
  shift
  start_server "$name" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-file "$USERS_FILE" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT" "$@"
}

uclient_ok() { # logfile
  grep -a -q "lost packets 0" "$1"
}

# ---------- TLS/DTLS 证书（TLS/DTLS 项与 coturn 对照共用）----------

CERT_DIR="$WORK/certs"
TLS_PORT=$((BASE + 3))
DTLS_PORT=$((BASE + 4))
REST_SECRET="rest-secret"
COTURN_CERT="$CERT_DIR/cert.pem"
COTURN_PKEY="$CERT_DIR/key.pem"

# 自签 ECDSA P-256 证书：ECDSA（不是 RSA）因为 webrtc-dtls 只接受 ECDSA/Ed25519；
# PKCS#8 因为它的 PEM 读取器读不了 SEC1/PKCS#1。
make_cert() {
  mkdir -p "$CERT_DIR"
  [[ -f "$CERT_DIR/cert.pem" && -f "$CERT_DIR/key.pem" ]] && return 0
  command -v openssl >/dev/null 2>&1 || return 1
  openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/sec1.pem" 2>/dev/null &&
    openssl pkcs8 -topk8 -nocrypt -in "$CERT_DIR/sec1.pem" -out "$CERT_DIR/key.pem" 2>/dev/null &&
    openssl req -new -x509 -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" -days 2 \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
}

# RSA-2048 自签证书（TLS 可以用；DTLS 只收 ECDSA/Ed25519）。用于两条反向用例：
#   · full + RSA + 只开 TLS → **必须能启动并中继**（B1：不能因为 DTLS 的密钥限制拒绝 TLS）；
#   · full + RSA + 开 DTLS → 必须拒绝启动。
make_rsa_cert() {
  mkdir -p "$CERT_DIR"
  [[ -f "$CERT_DIR/rsa-cert.pem" && -f "$CERT_DIR/rsa-key.pem" ]] && return 0
  command -v openssl >/dev/null 2>&1 || return 1
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$CERT_DIR/rsa-key.pem" 2>/dev/null &&
    openssl req -new -x509 -key "$CERT_DIR/rsa-key.pem" -out "$CERT_DIR/rsa-cert.pem" \
      -days 2 -subj "/CN=localhost" 2>/dev/null
}

# 二进制是否带 tls/dtls feature？用「启动 + 读错误信息」探测，不猜。
# 返回 0 = 带（能起 TLS 监听），1 = lean。
probe_secure_support() {
  make_cert || return 1
  local log="$LOG_DIR/feature-probe.log"
  timeout 3 "$BIN" server --listen "127.0.0.1:$((BASE + 45))" --turn \
    --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --turn-tls-listen "127.0.0.1:$((BASE + 46))" \
    --tls-cert "$CERT_DIR/cert.pem" --tls-key "$CERT_DIR/key.pem" \
    >"$log" 2>&1
  ! grep -qa 'build with the .tls. feature' "$log"
}

# 这些项需要 secure 传输 → BUILD=true 时自动加 `--features full`。
needs_secure_build() {
  [[ ${#T2_ONLY[@]} -gt 0 ]] && return 0
  case "$ONLY" in tls | dtls | multi-instance-tls | multi-instance-dtls | cert-reload | cert-poll | coturn) return 0 ;; esac
  return 1
}

# ---------- build ----------

rm -f "$WORK/pids"
if $BUILD && [[ ${#CARGO_FEATURES[@]} -eq 0 ]] && needs_secure_build; then
  CARGO_FEATURES=(--features full)
fi
if $BUILD; then
  log "building $BIN ${CARGO_FEATURES[*]:-（lean）}"
  if ! (cd "$ROOT" && cargo build "${CARGO_FEATURES[@]}" >"$LOG_DIR/build.log" 2>&1); then
    log "FAIL: build (see $LOG_DIR/build.log)"
    exit 1
  fi
  [[ " ${CARGO_FEATURES[*]:-} " == *" full "* ]] && HAVE_SECURE=true
elif probe_secure_support; then
  HAVE_SECURE=true
fi
log "secure transports (tls/dtls): $([ "$HAVE_SECURE" = true ] && echo available || echo lean-build)"
HEALTH_PORT=$((BASE + 1))
USERS_FILE="$WORK/users.txt"
cat >"$USERS_FILE" <<EOF
$USER_NAME:$USER_PASS
otheruser:otherpass
EOF

# ---------- 1. startup: TURN requires long-term credentials ----------

run_startup() {
  local name=startup
  "$BIN" server --turn --listen "127.0.0.1:$BASE" >"$LOG_DIR/$name-no-credentials.log" 2>&1
  local code=$?
  local short
  short="$("$BIN" server --turn --auth-user u --auth-pass p --listen "127.0.0.1:$BASE" 2>&1)"
  local short_code=$?
  if [[ $code -ne 0 ]] && grep -qa "long-term credentials" "$LOG_DIR/$name-no-credentials.log" &&
    [[ $short_code -ne 0 ]] && grep -qa "long-term credentials" <<<"$short"; then
    ok "$name" "exit=$code (no creds), exit=$short_code (short-term)"
  else
    fail "$name" "expected exit!=0 with an explicit long-term message (got $code/$short_code)"
  fi
}

# ---------- 2. relay: turnutils_uclient completes a UDP relay ----------

run_relay() {
  local name=relay
  start_turn "$name" "--max-allocations-per-user" "32"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 5 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local exit_code=$?
  local bytes_in bytes_out
  bytes_in="$(metric 'rstun_turn_bytes_total{direction="in"}')"
  bytes_out="$(metric 'rstun_turn_bytes_total{direction="out"}')"
  if [[ $exit_code -eq 0 ]] && uclient_ok "$LOG_DIR/$name-uclient.log" &&
    [[ -n "$bytes_in" && "$bytes_in" -gt 0 && -n "$bytes_out" && "$bytes_out" -gt 0 ]]; then
    ok "$name" "uclient exit=0, relay bytes in=$bytes_in out=$bytes_out"
  else
    fail "$name" "uclient exit=$exit_code bytes in=$bytes_in out=$bytes_out"
  fi
  # The probe adds the per-step view (permission/channel/indications).
  if python3 "$PROBE" relay --server "127.0.0.1:$BASE" >"$LOG_DIR/$name-probe.log" 2>&1; then
    ok "$name-probe" "$(grep -c '^ok:' "$LOG_DIR/$name-probe.log") assertions"
  else
    fail "$name-probe" "see $LOG_DIR/$name-probe.log"
  fi
  stop_server "$name"
}

# ---------- 2b. tcprelay: RFC 6062 outbound Connect + ConnectionBind ----------
#
# Outbound only: Allocate(TCP) → Connect → ConnectionBind → raw bytes. The
# `turnutils_uclient -T` shortcut is **not** used here: `-T` implies `-y`
# (client-to-client), so it also exercises the inbound half on the peer side;
# that belongs to the `tcp-relay-passive` item. The probe performs the standard
# client flow (and runs identically against coturn).
run_tcprelay() {
  local name=tcprelay
  # Snapshot the range first: `SO_REUSEPORT`-bound relay listeners are TCP
  # LISTEN sockets, so a foreign service in the range must be excluded from the
  # leftover assertion instead of turning into a false FAIL.
  local before
  before="$(relay_sockets)"
  start_turn "$name" --tcp --turn-tcp-relay
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if python3 "$PROBE" tcp-relay --server "127.0.0.1:$BASE" \
    --user "$USER_NAME" --password "$USER_PASS" --realm "$REALM" \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    local assertions
    assertions="$(grep -c '^ok:' "$LOG_DIR/$name-probe.log")"
    # The probe exits 0 only when every check passed, but a check that silently
    # stops running would still exit 0: pin the count so a dropped assertion is
    # a failure, not a smaller green.
    if (( assertions < 11 )); then
      fail "$name" "probe reported $assertions assertions (expected 11); see $LOG_DIR/$name-probe.log"
      stop_server "$name"
      return
    fi
  else
    fail "$name" "see $LOG_DIR/$name-probe.log"
    stop_server "$name"
    return
  fi
  # The TCP relay is a real listener while the allocation lives, and LIFETIME=0
  # (part of the probe) must take it away. Only ports *we* added count.
  local leftover
  leftover="$(relay_new_sockets "$before")"
  if [[ -n "$leftover" ]]; then
    fail "$name" "TCP relay listener left behind: $(echo "$leftover" | tr '\n' ' ')"
  else
    ok "$name" "$assertions assertions, no TCP relay listener left in $RELAY_LO-$RELAY_HI"
  fi
  if command -v turnutils_uclient >/dev/null 2>&1; then
    log "info: $name: uclient -T lives in the tcp-relay-passive item (it implies -y and needs ConnectionAttempt)"
  fi
  stop_server "$name"
}

# ---------- 2c. tcp-relay-passive: RFC 6062 §5.3 inbound (ConnectionAttempt) ----------
#
# A peer dials the TCP relay listener; the server accepts it, checks the
# permission table and announces it on the control connection with a
# `ConnectionAttempt` (CONNECTION-ID + XOR-PEER-ADDRESS), then the client binds a
# fresh connection. Two independent oracles:
#
#   · the probe, which walks the sequence step by step and also covers the
#     negative half (no permission → closed, no indication);
#   · `turnutils_uclient -P`, whose judge is **exit=0 plus bytes in both
#     directions** — not `lost packets 0`: coturn's own `-P` run loses 50% on
#     this path, so that counter is unusable as a criterion.
#
# `turnutils_uclient -T` (which implies -y) is the end-to-end regression that
# needs both halves: before the passive half it received nothing at all
# (tot_recv_msgs=0, hang to timeout), so `lost packets 0` is meaningful here.
run_tcp_relay_passive() {
  local name=tcp-relay-passive
  # Same snapshot as `tcprelay`: the leftover check must only look at the ports
  # this run created, not at whatever else listens inside the range.
  local before
  before="$(relay_sockets)"
  start_turn "$name" --tcp --turn-tcp-relay --max-allocations-per-user 32
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi

  # 1) The probe: ConnectionAttempt attributes + negative half + raw bytes.
  if ! python3 "$PROBE" tcp-relay-passive --server "127.0.0.1:$BASE" \
    --user "$USER_NAME" --password "$USER_PASS" --realm "$REALM" \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    fail "$name" "probe assertions failed (see $LOG_DIR/$name-probe.log)"
    stop_server "$name"
    return
  fi
  local assertions
  assertions="$(grep -c '^ok:' "$LOG_DIR/$name-probe.log")"
  # A check that silently stops running would still exit 0; pin the count.
  if (( assertions < 14 )); then
    fail "$name" "probe reported $assertions assertions (expected 14); see $LOG_DIR/$name-probe.log"
    stop_server "$name"
    return
  fi

  # 2) `uclient -P`: bytes must move both ways. The counters are cumulative, so
  #    compare against a snapshot taken right before the run.
  local before_in before_out after_in after_out
  before_in="$(metric 'rstun_turn_bytes_total{direction="in"}')"
  before_out="$(metric 'rstun_turn_bytes_total{direction="out"}')"
  before_in="${before_in:-0}"
  before_out="${before_out:-0}"
  turnutils_uclient -P -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 5 -m 2 -v 127.0.0.1 \
    >"$LOG_DIR/$name-uclient-P.log" 2>&1
  local passive_exit=$?
  after_in="$(metric 'rstun_turn_bytes_total{direction="in"}')"
  after_out="$(metric 'rstun_turn_bytes_total{direction="out"}')"
  after_in="${after_in:-0}"
  after_out="${after_out:-0}"
  local passive=ok
  if [[ $passive_exit -ne 0 ]] ||
    (( after_in <= before_in )) || (( after_out <= before_out )); then
    passive=failed
  fi

  # 3) `uclient -T` (implies -y): now completes with `lost packets 0`.
  turnutils_uclient -T -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 5 -m 2 -v 127.0.0.1 \
    >"$LOG_DIR/$name-uclient-T.log" 2>&1
  local active_exit=$?
  local active=ok
  if [[ $active_exit -ne 0 ]] || ! uclient_ok "$LOG_DIR/$name-uclient-T.log"; then
    active=failed
  fi

  # 4) The relay listeners are gone once both clients are done (only the ports
  #    this run created — see `relay_new_sockets`).
  local leftover
  leftover="$(relay_new_sockets "$before")"
  if [[ $passive == ok && $active == ok && -z "$leftover" ]]; then
    ok "$name" "$assertions probe assertions; uclient -P exit=0 bytes in=$((after_in - before_in)) out=$((after_out - before_out)); uclient -T lost packets 0"
  else
    fail "$name" "probe=$assertions passive=$passive(exit=$passive_exit in=$((after_in - before_in)) out=$((after_out - before_out))) active=$active(exit=$active_exit) leftover=[$(echo "$leftover" | tr '\n' ' ')]"
  fi
  stop_server "$name"
}

# ---------- 3. auth: 401 (missing/wrong) and 438 (expired nonce) ----------

run_auth() {
  local name=auth
  start_turn "$name" "--nonce-lifetime" "1"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if python3 "$PROBE" wrong-password --server "127.0.0.1:$BASE" >"$LOG_DIR/$name-401.log" 2>&1 &&
    python3 "$PROBE" auth --server "127.0.0.1:$BASE" --wait 1.3 >"$LOG_DIR/$name-438.log" 2>&1; then
    ok "$name" "401 on wrong password, 438 on expired nonce"
  else
    fail "$name" "see $LOG_DIR/$name-401.log / $LOG_DIR/$name-438.log"
  fi
  stop_server "$name"
}

# ---------- 4. lifecycle: Allocate / Refresh 600 / Refresh 0 / 437 ----------

run_lifecycle() {
  local name=lifecycle
  start_turn "$name"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if python3 "$PROBE" lifecycle --server "127.0.0.1:$BASE" >"$LOG_DIR/$name-probe.log" 2>&1; then
    ok "$name" "tid retransmit / new-tid 437, refresh no-lifetime=600, LIFETIME=0 → 437"
  else
    fail "$name" "see $LOG_DIR/$name-probe.log"
  fi
  stop_server "$name"
}

# ---------- 4b. wrong-user: same 5-tuple, other credentials → 441 ----------

run_wrong_user() {
  local name=wrong-user
  start_turn_users "$name"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if python3 "$PROBE" wrong-user --server "127.0.0.1:$BASE" \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    ok "$name" "Refresh/CreatePermission/LIFETIME=0 from another user all 441"
  else
    fail "$name" "see $LOG_DIR/$name-probe.log"
  fi
  stop_server "$name"
}

# ---------- 4c. RAF: REQUESTED-ADDRESS-FAMILY (0x0017) is understood ----------

# RFC 8656 §7.2 step 7: uclient's `-X` (IPv4 relay requested), `-x` (IPv6
# requested) and `-e` carry REQUESTED-ADDRESS-FAMILY. Plain UDP (no `-S`) on
# purpose: the attribute is handled before any transport dispatch, so the lean
# build covers it (the DTLS item repeats `-S -X` for the production shape that
# reported the 420). `-g` (DONT-FRAGMENT) moved to its own `df` item.
run_raf() {
  local name=raf
  start_turn "$name"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  # 1) Explicit IPv4 relay family → Allocate + relay (this used to be 420).
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 3 -m 2 -y -X 127.0.0.1 \
    >"$LOG_DIR/$name-ipv4.log" 2>&1
  # 2) IPv6 relay family from an IPv4 client → 440 (§7.2 step 7), not 420.
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 3 -m 2 -y -x 127.0.0.1 \
    >"$LOG_DIR/$name-ipv6.log" 2>&1
  local ipv4=ok ipv6=ok
  uclient_ok "$LOG_DIR/$name-ipv4.log" || ipv4=failed
  grep -qa "error 440" "$LOG_DIR/$name-ipv6.log" || ipv6=failed
  local family
  family="$(metric 'rstun_turn_rejected_total{reason="family"}')"
  if [[ $ipv4 == ok && $ipv6 == ok && -n "$family" && "$family" -gt 0 ]]; then
    ok "$name" "uclient -X relays (RAF IPv4), -x → error 440; rejected_family=$family"
  else
    # 失败时把 uclient 的尾部打进 CI 日志：只看 ipv4=failed 分不清「丢包」还是「硬错误」。
    echo "--- $name-ipv4.log (tail) ---"
    tail -n 8 "$LOG_DIR/$name-ipv4.log" 2>/dev/null || true
    echo "--- $name-ipv6.log (tail) ---"
    tail -n 5 "$LOG_DIR/$name-ipv6.log" 2>/dev/null || true
    fail "$name" "ipv4=$ipv4 ipv6=$ipv6 rejected_family=$family (see $LOG_DIR/$name-*.log)"
  fi
  stop_server "$name"
}

# ---------- 4c-bis. df: DONT-FRAGMENT (0x001A) relays instead of 420 ----------

# RFC 8656 §18.9 / §7.2 step 4 / §11.2: unix 上 `Allocate` 带 DONT-FRAGMENT
# 会真的给 relay socket 置 DF（Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DO`、macOS
# `IP_DONTFRAG`），所以 `uclient -g` 从「`error 420`」变成可中继。
#
# 证据口径（重要）：`tcpdump -i lo` 里的 `flags [DF]` **不是判别性证据** ——
# Linux 默认的 `IP_PMTUDISC_WANT` 对「不超过 MTU」的报文本来就置 DF，而 lo 的 MTU
# 是 65536、uclient 报文远小于它。判别性证据是单测里的 `getsockopt` 回读：
#   · `set_dont_fragment_round_trips`（DO/WANT↔DF on/off 往返）；
#   · `allocate_with_dont_fragment_sets_the_relay_socket`（活 allocation 的 relay
#     socket 真的处于 DO）。
# 本项因此断言三件可判别的事：`-g` 能中继（旧行为是 420）、线上报文带 DF（记录性）、
# 中继字节增长；tcpdump 不可用/无权限时退化为「uclient + 指标」并在输出里说明。
run_df() {
  local name=df
  start_turn "$name" "--max-allocations-per-user" "32"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi

  # 1) `-g` = DONT-FRAGMENT in Allocate. Before this change the server answered
  #    `error 420`; now the allocation is created and the relay carries bytes.
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 5 -m 2 -y -g 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local relayed=ok
  uclient_ok "$LOG_DIR/$name-uclient.log" || relayed=failed
  grep -qa "error 420" "$LOG_DIR/$name-uclient.log" && relayed=failed

  # 2) Observational wire evidence: relay→peer datagrams carry DF.
  local wire=skip wire_note="tcpdump unavailable"
  if command -v tcpdump >/dev/null 2>&1; then
    timeout 20 tcpdump -i lo -n -vv -c 3 'udp and portrange '"$RELAY_LO"'-'"$RELAY_HI" \
      >"$LOG_DIR/$name-tcpdump.log" 2>&1 &
    local capture_pid=$!
    sleep 0.5
    turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 10 -m 2 -y -g 127.0.0.1 \
      >"$LOG_DIR/$name-uclient-capture.log" 2>&1 || true
    wait "$capture_pid" 2>/dev/null
    if grep -qa "flags \[DF\]" "$LOG_DIR/$name-tcpdump.log"; then
      wire=ok
      wire_note="tcpdump: flags [DF] on relay→peer (recorded, not discriminating on lo)"
    elif grep -qa "permission denied\|Operation not permitted" "$LOG_DIR/$name-tcpdump.log"; then
      wire_note="tcpdump needs CAP_NET_RAW; getsockopt readback is the evidence"
    else
      wire=failed
      wire_note="no DF in $(grep -c . "$LOG_DIR/$name-tcpdump.log" 2>/dev/null || echo 0) tcpdump lines"
    fi
  fi

  local bytes_in bytes_out refused
  bytes_in="$(metric 'rstun_turn_bytes_total{direction="in"}')"
  bytes_out="$(metric 'rstun_turn_bytes_total{direction="out"}')"
  refused="$(metric 'rstun_turn_rejected_total{reason="df"}')"
  if [[ $relayed == ok && "$wire" != failed &&
    -n "$bytes_in" && "$bytes_in" -gt 0 && -n "$bytes_out" && "$bytes_out" -gt 0 ]]; then
    ok "$name" "uclient -g relays (was error 420), bytes in=$bytes_in out=$bytes_out, rejected_df=${refused:-0}; $wire_note"
  else
    fail "$name" "relayed=$relayed wire=$wire bytes in=$bytes_in out=$bytes_out ($wire_note; see $LOG_DIR/$name-*.log)"
  fi
  stop_server "$name"
}

# ---------- 4c-ter. ipv6relay: IPv6 listener + IPv6 client → IPv6 relay ----------

# The path that had no regression at all: `--listen [::1]`, an IPv6 client and
# an IPv6 peer. The relay follows the client, so the whole chain stays on ::1;
# the probe asserts the XOR-RELAYED-ADDRESS family and drives Send/Data/
# ChannelData both ways. Hosts without IPv6 loopback skip instead of failing.
run_ipv6relay() {
  local name=ipv6relay
  if ! python3 - <<'PY' >/dev/null 2>&1
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::1", 0))
s.close()
PY
  then
    skip "$name" "no IPv6 loopback on this host"
    return
  fi
  start_server "$name" --listen "[::1]:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy (see $LOG_DIR/$name.log)"
    stop_server "$name"
    return
  fi
  if python3 "$PROBE" relay --server "[::1]:$BASE" --family inet6 --show-relay \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    local relay_addr sent back family
    relay_addr="$(sed -n 's/^info: relay=//p' "$LOG_DIR/$name-probe.log")"
    family="$(sed -n 's/^ok: allocate-family relay-family=//p' "$LOG_DIR/$name-probe.log")"
    sent="$(sed -n 's/^ok: send-indication-bytes bytes=//p' "$LOG_DIR/$name-probe.log")"
    back="$(sed -n 's/^ok: peer-to-client-bytes kind=[^ ]* bytes=//p' "$LOG_DIR/$name-probe.log")"
    if [[ "$family" == "inet6" && -n "$relay_addr" &&
      "${sent:-0}" -gt 0 && "${back:-0}" -gt 0 ]]; then
      ok "$name" "relay=$relay_addr (IPv6), send→peer ${sent}B, peer→client ${back}B"
    else
      fail "$name" "relay=${relay_addr:-?} family=${family:-?} send=${sent:-0} back=${back:-0}"
    fi
  else
    fail "$name" "see $LOG_DIR/$name-probe.log"
  fi
  stop_server "$name"
}

# ---------- 4d. wildcard listener: loopback peers are refused ----------

run_wildcard() {
  local name=wildcard
  start_server "$name" --listen "0.0.0.0:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if python3 "$PROBE" loopback --server "127.0.0.1:$BASE" \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    ok "$name" "CreatePermission to 127.0.0.1:<listen> and another loopback port → 403"
  else
    fail "$name" "see $LOG_DIR/$name-probe.log"
  fi
  stop_server "$name"
}

# ---------- 4d. permission limit: one request cannot bypass the cap ----------

run_permission_limit() {
  local name=permission-limit
  start_turn "$name" "--permission-limit" "1"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if python3 "$PROBE" permission-limit --server "127.0.0.1:$BASE" \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    ok "$name" "combined request → 508 with zero effect; channel implicit permission → 508"
  else
    fail "$name" "see $LOG_DIR/$name-probe.log"
  fi
  stop_server "$name"
}

# ---------- 5. quota: per-user cap → 486 ----------

run_quota() {
  local name=quota
  start_turn "$name" "--max-allocations-per-user" "1"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 1 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local created
  created="$(metric 'rstun_turn_allocations_total{result="created"}')"
  if grep -qa "486 (Allocation Quota Reached)" "$LOG_DIR/$name-uclient.log" &&
    [[ -n "$created" && "$created" -ge 1 ]]; then
    ok "$name" "first allocation created, second refused with 486"
  else
    fail "$name" "no 486 in $LOG_DIR/$name-uclient.log"
  fi
  stop_server "$name"
}

# ---------- 6. ports: one-port relay range → 508 ----------

run_ports() {
  local name=ports
  local only_port
  only_port="$(python3 - <<'PY'
import socket
# uclient asks for EVEN-PORT (R=1), so a single-port range must be even to let
# the first client succeed; the second then runs out of ports (508).
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    if port % 2 == 0:
        print(port)
        break
PY
)"
  # Two ports: the first client takes the EVEN-PORT pair, the second is out.
  start_server "$name" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$only_port-$((only_port + 1))" \
    --health-listen "127.0.0.1:$HEALTH_PORT"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 1 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local created
  created="$(metric 'rstun_turn_allocations_total{result="created"}')"
  if grep -qa "508 (Insufficient Capacity)" "$LOG_DIR/$name-uclient.log" &&
    [[ -n "$created" && "$created" -ge 1 ]]; then
    ok "$name" "first allocation created, second refused with 508 (range=$only_port-$((only_port + 1)))"
  else
    fail "$name" "no 508 in $LOG_DIR/$name-uclient.log"
  fi
  stop_server "$name"
}

# ---------- 6b. TLS: turns: completes a relay (T2) ----------

run_tls() {
  local name=tls
  if [[ "$HAVE_SECURE" != true ]]; then
    skip "$name" "lean 构建没有 tls feature（用 --tls，或 cargo build --features full）"
    return
  fi
  make_cert || { skip "$name" "openssl unavailable"; return; }
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  start_server "$name" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT" \
    --turn-tls-listen "127.0.0.1:$TLS_PORT" \
    --tls-cert "$CERT_DIR/cert.pem" --tls-key "$CERT_DIR/key.pem"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy (see $LOG_DIR/$name.log)"
    stop_server "$name"
    return
  fi

  # 1) A real TLS handshake (independent of the TURN stack).
  timeout 10 openssl s_client -connect "127.0.0.1:$TLS_PORT" -servername localhost -brief \
    </dev/null >"$LOG_DIR/$name-sclient.log" 2>&1
  local handshake=ok
  grep -qa "CONNECTION ESTABLISHED" "$LOG_DIR/$name-sclient.log" || handshake=failed

  # 2) TURN over TLS: uclient's secure TCP mode (`-S -t`) completes the relay.
  turnutils_uclient -S -t -u "$USER_NAME" -w "$USER_PASS" -p "$TLS_PORT" -n 5 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local relay=ok
  uclient_ok "$LOG_DIR/$name-uclient.log" || relay=failed
  local bytes_in bytes_out
  bytes_in="$(metric 'rstun_turn_bytes_total{direction="in"}')"
  bytes_out="$(metric 'rstun_turn_bytes_total{direction="out"}')"

  # 3) Bad configuration: a listener without material must refuse to start.
  # A dedicated port: the running server already holds $BASE, and a bind error
  # would mask the configuration error this check is about.
  "$BIN" server --listen "127.0.0.1:$((BASE + 40))" --turn --realm "$REALM" \
    --auth-secret "$SECRET" --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --turn-tls-listen "127.0.0.1:$TLS_PORT" >"$LOG_DIR/$name-no-cert.log" 2>&1
  local no_cert=$?
  "$BIN" server --listen "127.0.0.1:$((BASE + 40))" --turn --realm "$REALM" \
    --auth-secret "$SECRET" --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --turn-tls-listen "127.0.0.1:$TLS_PORT" \
    --tls-cert "$WORK/no-such-cert.pem" --tls-key "$CERT_DIR/key.pem" \
    >"$LOG_DIR/$name-bad-path.log" 2>&1
  local bad_path=$?
  local bad_ok=ok
  { [[ $no_cert -ne 0 ]] && grep -qa "need --tls-cert and --tls-key" "$LOG_DIR/$name-no-cert.log"; } ||
    bad_ok=failed
  { [[ $bad_path -ne 0 ]] && grep -qa "cannot read --tls-cert" "$LOG_DIR/$name-bad-path.log"; } ||
    bad_ok=failed
  # A key that does not match the certificate is caught by rustls at startup
  # (`KeyMismatch`), so the listener never serves a pair clients cannot verify.
  if [[ ! -f "$CERT_DIR/other-key.pem" ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/other-sec1.pem" 2>/dev/null &&
      openssl pkcs8 -topk8 -nocrypt -in "$CERT_DIR/other-sec1.pem" -out "$CERT_DIR/other-key.pem" 2>/dev/null
  fi
  "$BIN" server --listen "127.0.0.1:$((BASE + 40))" --turn --realm "$REALM" \
    --auth-secret "$SECRET" --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --turn-tls-listen "127.0.0.1:$TLS_PORT" \
    --tls-cert "$CERT_DIR/cert.pem" --tls-key "$CERT_DIR/other-key.pem" \
    >"$LOG_DIR/$name-mismatch.log" 2>&1
  local mismatch=$?
  { [[ $mismatch -ne 0 ]] && grep -qa "do not form a usable pair" "$LOG_DIR/$name-mismatch.log"; } ||
    bad_ok=failed

  stop_server "$name"

  # 4) B1: a **full** build with an RSA certificate and **only** `--turn-tls-listen`
  #    must start and relay. DTLS's stricter key rules (PKCS#8 + ECDSA P-256/
  #    Ed25519) may not be applied when no DTLS listener was requested — RSA is
  #    what Let's Encrypt hands out, so this is the common `turns:` deployment.
  local rsa_relay=ok
  if make_rsa_cert; then
    start_server "$name-rsa" --listen "127.0.0.1:$BASE" \
      --turn --realm "$REALM" --auth-secret "$SECRET" \
      --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
      --relay-ports "$RELAY_LO-$RELAY_HI" \
      --health-listen "127.0.0.1:$HEALTH_PORT" \
      --turn-tls-listen "127.0.0.1:$TLS_PORT" \
      --tls-cert "$CERT_DIR/rsa-cert.pem" --tls-key "$CERT_DIR/rsa-key.pem"
    if wait_health "$HEALTH_PORT"; then
      turnutils_uclient -S -t -u "$USER_NAME" -w "$USER_PASS" -p "$TLS_PORT" -n 3 -m 2 -y 127.0.0.1 \
        >"$LOG_DIR/$name-rsa-uclient.log" 2>&1
      uclient_ok "$LOG_DIR/$name-rsa-uclient.log" || rsa_relay=failed
    else
      rsa_relay=failed
    fi
    stop_server "$name-rsa"
  else
    rsa_relay=skip
  fi

  if [[ $handshake == ok && $relay == ok && "$bad_ok" == ok && "$rsa_relay" == ok &&
    -n "$bytes_in" && "$bytes_in" -gt 0 && -n "$bytes_out" && "$bytes_out" -gt 0 ]]; then
    ok "$name" "s_client handshake ok, uclient -S -t relay in=$bytes_in out=$bytes_out, bad configs + key mismatch refused, RSA cert with TLS-only relays"
  else
    fail "$name" "handshake=$handshake relay=$relay bad_config=$bad_ok rsa_tls_only=$rsa_relay bytes in=$bytes_in out=$bytes_out"
  fi
}

# ---------- 6c. DTLS: openssl handshake + a real DTLS relay (T2) ----------

run_dtls() {
  local name=dtls
  if [[ "$HAVE_SECURE" != true ]]; then
    skip "$name" "lean 构建没有 dtls feature（用 --dtls，或 cargo build --features full）"
    return
  fi
  make_cert || { skip "$name" "openssl unavailable"; return; }
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  start_server "$name" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT" \
    --turn-dtls-listen "127.0.0.1:$DTLS_PORT" \
    --tls-cert "$CERT_DIR/cert.pem" --tls-key "$CERT_DIR/key.pem"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy (see $LOG_DIR/$name.log)"
    stop_server "$name"
    return
  fi

  # 1) DTLS 1.2 handshake with openssl (independent implementation).
  timeout 10 openssl s_client -dtls1_2 -connect "127.0.0.1:$DTLS_PORT" -brief \
    </dev/null >"$LOG_DIR/$name-sclient.log" 2>&1
  local handshake=ok
  grep -qa "CONNECTION ESTABLISHED" "$LOG_DIR/$name-sclient.log" || handshake=failed

  # 2) TURN over DTLS: uclient's secure UDP mode (`-S`) completes the relay,
  #    which exercises Allocate + permission + ChannelData inside DTLS records.
  turnutils_uclient -S -u "$USER_NAME" -w "$USER_PASS" -p "$DTLS_PORT" -n 5 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local relay=ok
  uclient_ok "$LOG_DIR/$name-uclient.log" || relay=failed
  # 2b) The production shape from 2026-11-21: Allocate over DTLS with an
  #     explicit REQUESTED-ADDRESS-FAMILY (`-X`) used to be answered 420.
  turnutils_uclient -S -X -u "$USER_NAME" -w "$USER_PASS" -p "$DTLS_PORT" -n 3 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-raf.log" 2>&1
  uclient_ok "$LOG_DIR/$name-raf.log" || relay=failed
  local bytes_in bytes_out
  bytes_in="$(metric 'rstun_turn_bytes_total{direction="in"}')"
  bytes_out="$(metric 'rstun_turn_bytes_total{direction="out"}')"

  # 3) A listener without material refuses to start.
  "$BIN" server --listen "127.0.0.1:$((BASE + 40))" --turn --realm "$REALM" \
    --auth-secret "$SECRET" --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --turn-dtls-listen "127.0.0.1:$DTLS_PORT" >"$LOG_DIR/$name-no-cert.log" 2>&1
  local no_cert=$?
  local bad_ok=ok
  { [[ $no_cert -ne 0 ]] && grep -qa "need --tls-cert and --tls-key" "$LOG_DIR/$name-no-cert.log"; } ||
    bad_ok=failed

  # 4) An RSA key is fine for TLS but unusable for DTLS: the start must fail
  #    loudly instead of serving a listener no client can handshake with.
  make_rsa_cert || true
  "$BIN" server --listen "127.0.0.1:$((BASE + 40))" --turn --realm "$REALM" \
    --auth-secret "$SECRET" --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --turn-dtls-listen "127.0.0.1:$DTLS_PORT" \
    --tls-cert "$CERT_DIR/rsa-cert.pem" --tls-key "$CERT_DIR/rsa-key.pem" \
    >"$LOG_DIR/$name-rsa.log" 2>&1
  local rsa=$?
  { [[ $rsa -ne 0 ]] && grep -qa "ECDSA P-256 or Ed25519" "$LOG_DIR/$name-rsa.log"; } ||
    bad_ok=failed

  if [[ $handshake == ok && $relay == ok && "$bad_ok" == ok &&
    -n "$bytes_in" && "$bytes_in" -gt 0 && -n "$bytes_out" && "$bytes_out" -gt 0 ]]; then
    ok "$name" "s_client -dtls1_2 handshake ok, uclient -S and -S -X relay in=$bytes_in out=$bytes_out, RSA key refused"
  else
    fail "$name" "handshake=$handshake relay=$relay bad_config=$bad_ok bytes in=$bytes_in out=$bytes_out"
  fi
  stop_server "$name"
}

# ---------- 6d. certificate hot reload: SIGHUP + polling (T2) ----------

RELOAD_DIR="$WORK/reload"

# 三套自签 ECDSA P-256 + PKCS#8（DTLS 的硬限制），写到独立目录：tls/dtls 项用的
# $CERT_DIR 保持不变，避免互相覆盖。
make_reload_certs() {
  mkdir -p "$RELOAD_DIR"
  command -v openssl >/dev/null 2>&1 || return 1
  local n
  for n in a b c; do
    [[ -f "$RELOAD_DIR/$n-cert.pem" && -f "$RELOAD_DIR/$n-key.pem" ]] && continue
    openssl ecparam -name prime256v1 -genkey -noout -out "$RELOAD_DIR/$n-sec1.pem" 2>/dev/null &&
      openssl pkcs8 -topk8 -nocrypt -in "$RELOAD_DIR/$n-sec1.pem" -out "$RELOAD_DIR/$n-key.pem" 2>/dev/null &&
      openssl req -new -x509 -key "$RELOAD_DIR/$n-key.pem" -out "$RELOAD_DIR/$n-cert.pem" -days 2 \
        -subj "/CN=reload-$n.example" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null || return 1
  done
}

# What the reloader actually armed, read from its startup line:
# `poll=None` = `--tls-cert-poll 0` (SIGHUP only), `poll=Some(2s)` = a 2 s timer.
# tracing inserts ANSI escapes between the field name and its value, so the
# pattern allows anything between `poll` and the expected rendering.
reloader_poll_matches() { # logfile regex
  grep -a "certificate reloader started" "$1" 2>/dev/null | head -n 1 |
    grep -qE "poll.*$2"
}

# The peer certificate's SHA-256 fingerprint, as `SHA256 Fingerprint=…`.
s_client_fingerprint() { # port [--dtls]
  local port="$1"
  shift
  timeout 10 openssl s_client "$@" -connect "127.0.0.1:$port" -servername localhost </dev/null 2>/dev/null |
    openssl x509 -noout -fingerprint -sha256 2>/dev/null
}

# One TLS session held open across the reload: Binding request → response
# before the SIGHUP, wait for the reload, then the **same** connection sends a
# second Binding request. Both must be the same STUN error response (0x0111:
# this server is started with --auth-user, so an unauthenticated Binding gets
# 401) and the same wire length — proving the established session survives.
write_session_probe() {
  cat >"$RELOAD_DIR/tls_session_probe.py" <<'PY'
import os, socket, ssl, sys, time

host, port = sys.argv[1], int(sys.argv[2])
first, go, second = sys.argv[3], sys.argv[4], sys.argv[5]
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
sock = context.wrap_socket(
    socket.create_connection((host, port), timeout=5), server_hostname="localhost"
)

def exact(n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise SystemExit("connection closed")
        data += chunk
    return data

def binding():
    # 20-byte Binding request (RFC 5389): type 0x0001, length 0, magic cookie,
    # fixed transaction id. No MESSAGE-INTEGRITY: the expected answer is 401.
    sock.sendall(b"\x00\x01\x00\x00\x21\x12\xa4\x42" + b"\xAA" * 12)
    head = exact(20)
    kind = int.from_bytes(head[0:2], "big")
    length = int.from_bytes(head[2:4], "big")
    exact(length)
    return kind, 20 + length

kind1, size1 = binding()
open(first, "w").write(f"{kind1} {size1}\n")
deadline = time.time() + 20
while not os.path.exists(go):
    time.sleep(0.1)
    if time.time() > deadline:
        raise SystemExit("timed out waiting for the reload")
kind2, size2 = binding()
open(second, "w").write(f"{kind2} {size2}\n")
sock.close()
PY
}

run_cert_reload() {
  local name=cert-reload
  if [[ "$HAVE_SECURE" != true ]]; then
    skip "$name" "lean 构建没有 tls/dtls feature（用 --tls --dtls，或 cargo build --features full）"
    return
  fi
  make_reload_certs || { skip "$name" "openssl unavailable"; return; }
  cp "$RELOAD_DIR/a-cert.pem" "$RELOAD_DIR/current-cert.pem"
  cp "$RELOAD_DIR/a-key.pem" "$RELOAD_DIR/current-key.pem"
  start_server "$name" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT" \
    --turn-tls-listen "127.0.0.1:$TLS_PORT" \
    --turn-dtls-listen "127.0.0.1:$DTLS_PORT" \
    --tls-cert "$RELOAD_DIR/current-cert.pem" --tls-key "$RELOAD_DIR/current-key.pem"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy (see $LOG_DIR/$name.log)"
    stop_server "$name"
    return
  fi
  local pid tls_a dtls_a expires ssl_left drift i
  pid="$(tail -n 1 "$WORK/pids")"
  tls_a="$(s_client_fingerprint "$TLS_PORT")"
  dtls_a="$(s_client_fingerprint "$DTLS_PORT" -dtls1_2)"
  expires="$(metric 'rstun_turn_tls_cert_expires_seconds')"
  ssl_left=$(( $(date -d "$(openssl x509 -in "$RELOAD_DIR/current-cert.pem" -noout -enddate | cut -d= -f2)" +%s) - $(date +%s) ))
  drift=$(( expires - ssl_left ))
  drift=${drift#-}

  # PRD acceptance: an **established** TLS session must not be disturbed by the
  # reload. It sends a Binding request now and another after the SIGHUP below,
  # over the same socket.
  write_session_probe
  rm -f "$RELOAD_DIR/session-1.txt" "$RELOAD_DIR/session-2.txt" "$RELOAD_DIR/session-go"
  python3 "$RELOAD_DIR/tls_session_probe.py" 127.0.0.1 "$TLS_PORT" \
    "$RELOAD_DIR/session-1.txt" "$RELOAD_DIR/session-go" "$RELOAD_DIR/session-2.txt" \
    >"$LOG_DIR/$name-session.log" 2>&1 &
  local session_pid=$!

  # 1) SIGHUP: both files replaced, new TLS **and** DTLS sessions see B.
  cp "$RELOAD_DIR/b-cert.pem" "$RELOAD_DIR/current-cert.pem"
  cp "$RELOAD_DIR/b-key.pem" "$RELOAD_DIR/current-key.pem"
  kill -HUP "$pid"
  local tls_b=""
  for i in $(seq 1 20); do
    sleep 0.2
    tls_b="$(s_client_fingerprint "$TLS_PORT")"
    [[ -n "$tls_b" && "$tls_b" != "$tls_a" ]] && break
  done
  local dtls_b
  dtls_b="$(s_client_fingerprint "$DTLS_PORT" -dtls1_2)"

  touch "$RELOAD_DIR/session-go"
  wait "$session_pid" 2>/dev/null
  local session1="" session2="" session_ok=failed
  if [[ -f "$RELOAD_DIR/session-1.txt" && -f "$RELOAD_DIR/session-2.txt" ]]; then
    session1="$(cat "$RELOAD_DIR/session-1.txt")"
    session2="$(cat "$RELOAD_DIR/session-2.txt")"
    # 273 == 0x0111 (Binding error: authentication required), same length both
    # times, and a body beyond the 20-byte header.
    [[ "$session1" == "273 "* && "$session1" == "$session2" ]] && session_ok=ok
  fi

  # 2) Polling: replace with C and send **no** signal; the 30 s poll must pick
  #    it up (worst case ~30 s + one handshake).
  cp "$RELOAD_DIR/c-cert.pem" "$RELOAD_DIR/current-cert.pem"
  cp "$RELOAD_DIR/c-key.pem" "$RELOAD_DIR/current-key.pem"
  local tls_c=""
  for i in $(seq 1 80); do
    sleep 0.5
    tls_c="$(s_client_fingerprint "$TLS_PORT")"
    [[ -n "$tls_c" && "$tls_c" != "$tls_b" ]] && break
  done

  # 3) Bad material (C cert + A key): rejected, C keeps serving, failure counted.
  local failed_before failed_after tls_bad
  failed_before="$(metric 'rstun_turn_tls_reload_total{result="failed"}')"
  cp "$RELOAD_DIR/a-key.pem" "$RELOAD_DIR/current-key.pem"
  kill -HUP "$pid"
  for i in $(seq 1 20); do
    sleep 0.5
    failed_after="$(metric 'rstun_turn_tls_reload_total{result="failed"}')"
    [[ -n "$failed_after" && "$failed_after" != "$failed_before" ]] && break
  done
  tls_bad="$(s_client_fingerprint "$TLS_PORT")"
  local alive=ok
  kill -0 "$pid" 2>/dev/null || alive=dead
  local ok_count
  ok_count="$(metric 'rstun_turn_tls_reload_total{result="ok"}')"
  stop_server "$name"

  if [[ -n "$tls_a" && -n "$tls_b" && "$tls_a" != "$tls_b" && "$tls_b" == "$dtls_b" &&
    "$session_ok" == ok &&
    -n "$tls_c" && "$tls_c" != "$tls_b" && "$tls_bad" == "$tls_c" &&
    -n "$failed_before" && -n "$failed_after" && "$failed_after" -gt "$failed_before" &&
    "$alive" == ok && -n "$expires" && "$expires" -gt 0 && -n "$drift" && "$drift" -le 60 ]]; then
    ok "$name" "SIGHUP → new cert (TLS+DTLS identical), established session still answers after reload ($session1), poll → third cert, bad pair kept the live one (failed ${failed_before}→${failed_after}, ok=$ok_count), expires=${expires}s (openssl drift ${drift}s)"
  else
    fail "$name" "sighup a=[$tls_a] b=[$tls_b] dtls-b=[$dtls_b]; session=[$session_ok $session1 / $session2] (see $LOG_DIR/$name-session.log); poll c=[$tls_c]; bad kept=[$tls_bad]; failed ${failed_before:-?}→${failed_after:-?}; alive=$alive; expires=${expires:-?} drift=${drift:-?}"
  fi
}

# ---------- 6e-0. --tls-cert-poll: 0 = SIGHUP only, N = that interval ----------

run_cert_poll() {
  local name=cert-poll
  if [[ "$HAVE_SECURE" != true ]]; then
    skip "$name" "lean 构建没有 tls/dtls feature（用 --tls --dtls，或 cargo build --features full）"
    return
  fi
  make_reload_certs || { skip "$name" "openssl unavailable"; return; }

  # A poll interval with no secure listener can never take effect: refused at
  # startup instead of silently ignored.
  local message code refused=ok
  message="$("$BIN" server --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --tls-cert-poll 0 2>&1)"
  code=$?
  if [[ $code -eq 0 ]] || ! grep -qa -- "--tls-cert-poll" <<<"$message"; then
    refused=failed
  fi

  # 0 = no polling task: overwriting both files with no signal must NOT reload;
  # SIGHUP must (the task stays alive for the signal alone).
  cp "$RELOAD_DIR/a-cert.pem" "$RELOAD_DIR/current-cert.pem"
  cp "$RELOAD_DIR/a-key.pem" "$RELOAD_DIR/current-key.pem"
  start_server "$name" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT" \
    --turn-tls-listen "127.0.0.1:$TLS_PORT" \
    --tls-cert "$RELOAD_DIR/current-cert.pem" --tls-key "$RELOAD_DIR/current-key.pem" \
    --tls-cert-poll 0
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy (see $LOG_DIR/$name.log)"
    stop_server "$name"
    return
  fi
  local pid a b unchanged silent=ok sighup=ok i
  pid="$(tail -n 1 "$WORK/pids")"
  a="$(s_client_fingerprint "$TLS_PORT")"
  cp "$RELOAD_DIR/b-cert.pem" "$RELOAD_DIR/current-cert.pem"
  cp "$RELOAD_DIR/b-key.pem" "$RELOAD_DIR/current-key.pem"
  # The files really changed and no signal was sent: the fingerprint must stay.
  # This window alone cannot catch a 30 s timer that was never disabled (the
  # default tick is 30 s and its first tick is consumed at spawn) — the
  # discriminating evidence is the startup-line assertion below (`poll=None`).
  sleep 4
  unchanged="$(s_client_fingerprint "$TLS_PORT")"
  [[ -n "$a" && "$unchanged" == "$a" ]] || silent=failed
  kill -HUP "$pid"
  b=""
  for i in $(seq 1 20); do
    sleep 0.2
    b="$(s_client_fingerprint "$TLS_PORT")"
    [[ -n "$b" && "$b" != "$a" ]] && break
  done
  [[ -n "$b" && "$b" != "$a" ]] || sighup=failed
  # `0` must really mean "no timer": the reloader's startup line says poll=None
  # (a mutant that keeps the 30 s interval logs Some(30s) and fails here).
  local trigger=ok
  reloader_poll_matches "$LOG_DIR/$name.log" "None" || trigger=failed
  stop_server "$name"

  # A positive value is the poll interval: overwrite the pair with **no** signal
  # and wait for the 2 s tick (the loop allows 8 s for the tick + handshake).
  cp "$RELOAD_DIR/a-cert.pem" "$RELOAD_DIR/current-cert.pem"
  cp "$RELOAD_DIR/a-key.pem" "$RELOAD_DIR/current-key.pem"
  start_server "$name-fast" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --health-listen "127.0.0.1:$HEALTH_PORT" \
    --turn-tls-listen "127.0.0.1:$TLS_PORT" \
    --tls-cert "$RELOAD_DIR/current-cert.pem" --tls-key "$RELOAD_DIR/current-key.pem" \
    --tls-cert-poll 2
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server with --tls-cert-poll 2 did not become healthy"
    stop_server "$name-fast"
    return
  fi
  local a2 c polled=ok waited=0
  a2="$(s_client_fingerprint "$TLS_PORT")"
  cp "$RELOAD_DIR/c-cert.pem" "$RELOAD_DIR/current-cert.pem"
  cp "$RELOAD_DIR/c-key.pem" "$RELOAD_DIR/current-key.pem"
  c=""
  for i in $(seq 1 16); do
    sleep 0.5
    c="$(s_client_fingerprint "$TLS_PORT")"
    if [[ -n "$c" && "$c" != "$a2" ]]; then
      waited=$((i / 2))
      break
    fi
  done
  [[ -n "$c" && "$c" != "$a2" ]] || polled=failed
  local armed=ok
  reloader_poll_matches "$LOG_DIR/$name-fast.log" 'Some\(2s\)' || armed=failed
  stop_server "$name-fast"

  if [[ $refused == ok && $silent == ok && $sighup == ok && $trigger == ok &&
    $polled == ok && $armed == ok ]]; then
    ok "$name" "no listener + flag → refused; 0 → reloader poll=None, file change ignored for 4s, SIGHUP reloads; 2s → poll=Some(2s), reloaded within ~${waited}s"
  else
    fail "$name" "refused=$refused silent=$silent sighup=$sighup trigger=$trigger polled=$polled armed=$armed (a=[$a] unchanged=[$unchanged] b=[$b] a2=[$a2] c=[$c])"
  fi
}

# ---------- 6e. REST credentials: valid / expired / wrong secret (T2) ----------

run_rest() {
  local name=rest
  start_turn "$name" "--rest-secret" "$REST_SECRET"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  # Independent python oracle: it computes the password from the coturn rule.
  if ! python3 "$PROBE" rest --server "127.0.0.1:$BASE" --rest-secret "$REST_SECRET" \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    fail "$name" "probe assertions failed (see $LOG_DIR/$name-probe.log)"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  # uclient's own `-W` computes the same username/password: a second independent
  # implementation of the coturn rule.
  turnutils_uclient -W "$REST_SECRET" -u alice -p "$BASE" -n 3 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-valid.log" 2>&1
  local valid=ok
  uclient_ok "$LOG_DIR/$name-valid.log" || valid=failed
  turnutils_uclient -W "wrong-secret" -u alice -p "$BASE" -n 3 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-wrong.log" 2>&1
  local wrong=ok
  grep -qa "Cannot complete Allocation" "$LOG_DIR/$name-wrong.log" || wrong=failed
  # Stored long-term credentials keep working next to the REST secret.
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 3 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-stored.log" 2>&1
  local stored=ok
  uclient_ok "$LOG_DIR/$name-stored.log" || stored=failed

  if [[ $valid == ok && $wrong == ok && $stored == ok ]]; then
    ok "$name" "probe: valid 200 / expired 401 / wrong secret 401 / ':' label 200; uclient -W valid+wrong; stored user ok"
  else
    fail "$name" "uclient valid=$valid wrong=$wrong stored=$stored (see $LOG_DIR/$name-*.log)"
  fi
  stop_server "$name"
}

# ---------- 6e. bandwidth: the cap drops payload but keeps the allocation ----------

run_bandwidth() {
  local name=bandwidth
  start_turn "$name" "--turn-bandwidth" "2000"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  # 100 messages of ~100 B every 10 ms (~10 KB/s) against a 2 KB/s cap.
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 100 -m 2 -y -z 10 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local lost dropped_in
  lost="$(grep -ao "Total lost packets [0-9]*" "$LOG_DIR/$name-uclient.log" | awk '{print $4}' | head -n 1)"
  dropped_in="$(metric 'rstun_turn_bytes_dropped_total{direction="in"}')"
  # The allocation must survive the throttling: a fresh small relay still works.
  # A `508` here can also mean "the host's ephemeral port range stole our relay
  # ports" (`ip_local_port_range` often covers the relay range; the server then
  # reports `rejected_ports` and answers 508). That is environmental, not a
  # regression, so retry a few times on 508 only — any other failure is final.
  local after=failed attempt
  for attempt in 1 2 3; do
    turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 2 -m 2 -y 127.0.0.1 \
      >"$LOG_DIR/$name-after.log" 2>&1
    if uclient_ok "$LOG_DIR/$name-after.log"; then
      after=ok
      break
    fi
    grep -qa "error 508" "$LOG_DIR/$name-after.log" || break
    sleep 1
  done
  local healthy=ok
  wait_health "$HEALTH_PORT" || healthy=failed

  if [[ -n "$lost" && "$lost" -gt 0 && -n "$dropped_in" && "$dropped_in" -gt 0 &&
    "$after" == ok && "$healthy" == ok ]]; then
    ok "$name" "lost=$lost dropped_in=${dropped_in}B, allocation survived (follow-up relay ok)"
  else
    fail "$name" "lost=$lost dropped_in=$dropped_in after=$after healthy=$healthy (see $LOG_DIR/$name-*.log)"
  fi
  stop_server "$name"
}

# ---------- 7. cleanup: TTL expiry releases the relay socket ----------

run_cleanup() {
  local name=cleanup
  local before
  # UDP **and** TCP: RFC 6062 relay listeners are TCP LISTEN sockets, so a
  # UDP-only pre-check misses them (and an unrelated TCP service inside the
  # range used to be reported as our leftover at the end → false FAIL).
  before="$(relay_sockets)"
  if [[ -n "$before" ]]; then
    skip "$name" "relay range $RELAY_LO-$RELAY_HI already has listeners (UDP/TCP): $(echo "$before" | tr '\n' ' ')"
    return
  fi
  start_turn "$name" "--allocation-lifetime" "2"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "server did not become healthy"
    stop_server "$name"
    return
  fi
  if ! command -v turnutils_uclient >/dev/null 2>&1; then
    stop_server "$name"
    skip "$name" "turnutils_uclient not installed"
    return
  fi
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 2 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-uclient.log" 2>&1
  local created active
  created="$(metric 'rstun_turn_allocations_total{result="created"}')"
  active="$(metric 'rstun_turn_allocations')"
  if [[ -z "$created" || "$created" -eq 0 ]]; then
    fail "$name" "no allocation was created (see $LOG_DIR/$name-uclient.log)"
    stop_server "$name"
    return
  fi
  local waited=0
  while (( waited < 60 )); do
    active="$(metric 'rstun_turn_allocations')"
    [[ "$active" == "0" ]] && break
    sleep 0.2
    waited=$((waited + 1))
  done
  # The pre-check proved the range was empty, so anything left now came from
  # this run (UDP relay sockets and RFC 6062 TCP listeners alike). Closing the
  # allocation and closing the sockets are separate steps (`Allocation::drop`
  # aborts the relay task), so poll the final `ss` state instead of racing it
  # (spec §5a: abort is asynchronous; assert the **final** state).
  local server_pid
  server_pid="$(tail -n 1 "$WORK/pids" 2>/dev/null || true)"
  local leftover=""
  local socket_polls=0
  while (( socket_polls < 20 )); do
    leftover="$(relay_sockets_owned "$server_pid")"
    [[ -z "$leftover" ]] && break
    sleep 0.1
    socket_polls=$((socket_polls + 1))
  done
  if [[ "$active" == "0" && -z "$leftover" ]]; then
    ok "$name" "created=$created, allocations=0 and no relay listener owned by pid $server_pid (socket poll ${socket_polls}×100ms)"
  else
    fail "$name" "created=$created allocations=$active leftover=[$(echo "$leftover" | tr '\n' ' ')] (pid $server_pid)"
  fi
  stop_server "$name"
}

# ---------- 7b. multi-instance-udp: two instances, one 5-tuple ----------
#
# Two instances on the same port of two loopback addresses (the deployment
# shape the normalized key assumes). The probe drives the same client socket
# through both: everything after the first Allocate must be forwarded to the
# owner and answered as if the client had never moved. A fake round-robin LB
# then puts a real turnutils_uclient through the same cluster.

run_multi_instance_udp() {
  local name=multi-instance-udp
  local cluster_port=$((BASE + 2))
  local lb_port=$((BASE + 5))
  local before
  before="$(relay_sockets)"

  if ! python3 -c '
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind(("127.0.0.2", 0))
except OSError:
    sys.exit(1)
finally:
    sock.close()
'; then
    skip "$name" "127.0.0.2 is not a usable loopback alias on this host"
    return
  fi

  start_server "$name-a" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.1:$cluster_port" --cluster-instance-id a \
    --health-listen "127.0.0.1:$HEALTH_PORT"
  start_server "$name-b" --listen "127.0.0.2:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.2:$cluster_port" --cluster-instance-id b \
    --health-listen "127.0.0.2:$HEALTH_PORT"
  if ! wait_health_at 127.0.0.1 || ! wait_health_at 127.0.0.2; then
    fail "$name" "instances did not become healthy (see $LOG_DIR/$name-*.log)"
    stop_server "$name-b"
    stop_server "$name-a"
    return
  fi

  # Start-up gate (M3): a clustered TCP allocation needs its own explicit
  # TCP relay range; without it the two instances would both LISTEN on the
  # same ports (SO_REUSEPORT) and accept each other's peers.
  local rejected rejected_code
  rejected="$("$BIN" server --listen "127.0.0.1:$((BASE + 6))" --turn --realm "$REALM" \
    --auth-secret "$SECRET" --auth-user u --auth-pass p --turn-tcp-relay \
    --cluster-listen "127.0.0.1:$((cluster_port + 10))" \
    --cluster-peer "a@127.0.0.1:$((cluster_port + 10))" \
    --cluster-instance-id a 2>&1)"
  rejected_code=$?
  if [[ $rejected_code -ne 0 ]] && grep -qa "tcp-relay-ports" <<<"$rejected"; then
    ok "$name-tcp-relay-gate" "cluster + --turn-tcp-relay without --tcp-relay-ports refused (exit=$rejected_code)"
  else
    fail "$name-tcp-relay-gate" "expected a refusal mentioning --tcp-relay-ports (exit=$rejected_code)"
  fi

  if python3 "$PROBE" multi-instance \
    --server "127.0.0.1:$BASE" --server-b "127.0.0.2:$BASE" \
    >"$LOG_DIR/$name-probe.log" 2>&1; then
    ok "$name" "$(grep -c '^ok:' "$LOG_DIR/$name-probe.log") cross-instance assertions"
  else
    fail "$name" "see $LOG_DIR/$name-probe.log"
  fi

  # The probe released its allocation through the **non-owner** at the end:
  # both instances must be back to zero and no relay socket may remain.
  local active=1 leftover
  local waited=0
  while (( waited < 30 )); do
    active="$(metric_sum 'rstun_turn_allocations')"
    active="${active:-1}"
    [[ "$active" == "0" ]] && break
    sleep 0.1
    waited=$((waited + 1))
  done
  leftover="$(relay_new_sockets "$before")"
  if [[ "$active" == "0" && -z "$leftover" ]]; then
    ok "$name-release" "LIFETIME=0 through the non-owner left no allocation or relay socket"
  else
    fail "$name-release" "allocations=$active leftover=[$(echo "$leftover" | tr '\n' ' ')]"
  fi

  # A real client through a round-robin LB: control and data both cross
  # instances, and the client only ever talks to the LB address (C1 as a NAT
  # LB provides it). Default lifetime: the run is long enough that an expiring
  # allocation would show up as lost packets.
  local ready="$WORK/$name-lb.ready"
  local lb_pid=""
  rm -f "$ready"
  python3 "$ROOT/script/lab/rstun-turn-lb.py" --listen "127.0.0.1:$lb_port" \
    --backend "127.0.0.1:$BASE" --backend "127.0.0.2:$BASE" \
    --ready-file "$ready" >"$LOG_DIR/$name-lb.log" 2>&1 &
  lb_pid=$!
  PIDS+=("$lb_pid")
  local waited=0
  while [[ ! -s "$ready" ]] && (( waited < 30 )); do
    sleep 0.1
    waited=$((waited + 1))
  done
  if [[ ! -s "$ready" ]]; then
    fail "$name-lb" "load balancer did not start (see $LOG_DIR/$name-lb.log)"
  elif ! command -v turnutils_uclient >/dev/null 2>&1; then
    skip "$name-lb" "turnutils_uclient not installed"
  else
    turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$lb_port" -n 8 -m 3 -y 127.0.0.1 \
      >"$LOG_DIR/$name-uclient.log" 2>&1
    local exit_code=$?
    local bytes_in bytes_out
    bytes_in="$(metric_sum 'rstun_turn_bytes_total{direction="in"}')"
    bytes_out="$(metric_sum 'rstun_turn_bytes_total{direction="out"}')"
    if [[ $exit_code -eq 0 ]] && uclient_ok "$LOG_DIR/$name-uclient.log" &&
      [[ -n "$bytes_in" && "$bytes_in" -gt 0 && -n "$bytes_out" && "$bytes_out" -gt 0 ]]; then
      ok "$name-lb" "uclient through the LB exit=0, relay bytes in=$bytes_in out=$bytes_out"
    else
      fail "$name-lb" "uclient exit=$exit_code bytes in=$bytes_in out=$bytes_out"
    fi
  fi
  if [[ -n "$lb_pid" ]]; then
    kill -TERM "$lb_pid" 2>/dev/null
    wait "$lb_pid" 2>/dev/null
  fi

  # The uclient allocations are left to the TTL; stopping the instances must
  # close their relay sockets with them (no residue in the shared range).
  stop_server "$name-b"
  stop_server "$name-a"
  leftover="$(relay_new_sockets "$before")"
  if [[ -z "$leftover" ]]; then
    ok "$name-cleanup" "no relay socket left in $RELAY_LO-$RELAY_HI after shutdown"
  else
    fail "$name-cleanup" "leftover=[$(echo "$leftover" | tr '\n' ' ')]"
  fi
}

# ---------- 7c. multi-instance-tcp: TCP control connection + PUSH_CLIENT ----------
#
# A TCP load balancer routes each connection to one instance. The TURN control
# connection lands on the entry, the allocation may live on the other instance:
# control requests are forwarded, and peer→client bytes come back through the
# entry's writer queue. Closing the connection must release the owner's relay
# socket immediately (CLIENT_CLOSED), not after the TTL.

start_mi_pair() { # name extra args... (the same extra args on both instances)
  local name="$1"
  shift
  local cluster_port=$((BASE + 2))
  start_server "$name-a" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.1:$cluster_port" --cluster-instance-id a \
    --health-listen "127.0.0.1:$HEALTH_PORT" "$@"
  start_server "$name-b" --listen "127.0.0.2:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.2:$cluster_port" --cluster-instance-id b \
    --health-listen "127.0.0.2:$HEALTH_PORT" "$@"
}

stop_mi_pair() { # name
  stop_server "$1-b"
  stop_server "$1-a"
}

run_multi_instance_tcp() {
  local name=multi-instance-tcp
  local lb_port=$((BASE + 6))
  local before
  before="$(relay_sockets)"

  if ! loopback_alias_ok 127.0.0.2 udp || ! loopback_alias_ok 127.0.0.2 tcp; then
    skip "$name" "127.0.0.2 is not a usable loopback alias on this host"
    return
  fi

  start_mi_pair "$name" --tcp
  if ! wait_health_at 127.0.0.1 || ! wait_health_at 127.0.0.2; then
    fail "$name" "instances did not become healthy (see $LOG_DIR/$name-*.log)"
    stop_mi_pair "$name"
    return
  fi

  local attempts=8 cross=0 all_ok=0 release_ok=1
  local attempt entry owner relay address lb_log lb_ready probe_log probe_pid code waited
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    lb_log="$LOG_DIR/$name-lb-$attempt.log"
    lb_ready="$WORK/$name-lb-$attempt.ready"
    rm -f "$lb_ready"
    if (( attempt % 2 )); then
      python3 "$ROOT/script/lab/rstun-turn-tcp-lb.py" --listen "127.0.0.1:$lb_port" \
        --backend "127.0.0.1:$BASE" --backend "127.0.0.2:$BASE" \
        --ready-file "$lb_ready" >"$lb_log" 2>&1 &
    else
      python3 "$ROOT/script/lab/rstun-turn-tcp-lb.py" --listen "127.0.0.1:$lb_port" \
        --backend "127.0.0.2:$BASE" --backend "127.0.0.1:$BASE" \
        --ready-file "$lb_ready" >"$lb_log" 2>&1 &
    fi
    local lb_pid=$!
    PIDS+=("$lb_pid")
    if ! wait_ready_file "$lb_ready" 30; then
      fail "$name-lb" "TCP load balancer did not start (see $lb_log)"
      kill -TERM "$lb_pid" 2>/dev/null
      wait "$lb_pid" 2>/dev/null
      break
    fi
    probe_log="$LOG_DIR/$name-probe-$attempt.log"
    python3 "$PROBE" tcp-control --server "127.0.0.1:$lb_port" --show-relay --hold 0.8 \
      >"$probe_log" 2>&1 &
    probe_pid=$!
    waited=0
    while ! grep -qa "info: holding" "$probe_log" 2>/dev/null && (( waited < 50 )); do
      sleep 0.1
      waited=$((waited + 1))
    done
    address="$(grep -aoE 'info: relay=[0-9.]+:[0-9]+' "$probe_log" | head -1 | sed 's/info: relay=//')"
    relay="${address##*:}"
    owner="${address%%:*}"
    entry="$(grep -a '^route ' "$lb_log" | head -1 | grep -oE '127\.0\.0\.[0-9]+' | tail -1)"
    if [[ -n "$relay" ]] && udp_port_present "$relay"; then
      :
    else
      fail "$name-relay" "attempt $attempt: relayed socket $address is not listening"
      release_ok=0
    fi
    if [[ -n "$owner" && -n "$entry" && "$owner" != "$entry" ]]; then
      cross=$((cross + 1))
    fi
    wait "$probe_pid"
    code=$?
    if [[ $code -eq 0 ]] && grep -qa "info: holding" "$probe_log"; then
      all_ok=$((all_ok + 1))
    else
      fail "$name" "attempt $attempt: probe exit=$code (see $probe_log)"
    fi
    if [[ -n "$relay" ]] && ! wait_port_gone udp "$relay" 50; then
      fail "$name-release" "attempt $attempt: relay port $relay still listening after the client closed"
      release_ok=0
    fi
    kill -TERM "$lb_pid" 2>/dev/null
    wait "$lb_pid" 2>/dev/null
  done

  if [[ $all_ok -eq $attempts ]]; then
    ok "$name" "$attempts TCP attempts through the LB, probe ok each time"
  fi
  if (( cross > 0 )); then
    ok "$name-cross" "$cross/$attempts attempts had the allocation on the other instance (forwarded control + PUSH_CLIENT)"
  else
    fail "$name-cross" "no attempt landed on a non-entry owner; the cross-instance path was not exercised"
  fi
  [[ $release_ok -eq 1 ]] && ok "$name-release" "every relayed socket disappeared when its control connection closed"

  stop_mi_pair "$name"
  local leftover
  leftover="$(relay_new_sockets "$before")"
  if [[ -z "$leftover" ]]; then
    ok "$name-cleanup" "no relay socket left after shutdown"
  else
    fail "$name-cleanup" "leftover=[$(echo "$leftover" | tr '\n' ' ')]"
  fi
}

# ---------- 7d. multi-instance-tcp-relay: RFC 6062 across instances ----------
#
# Control connection on the entry, `Allocate(TCP)`/`Connect` on the owner,
# `ConnectionBind` arriving on the other connection and routed by its
# CONNECTION-ID, then raw bytes over RAW_RELAY. Both instances own a disjoint
# TCP relay range (SO_REUSEPORT would otherwise let them listen on the same
# port).

run_multi_instance_tcp_relay() {
  local name=multi-instance-tcp-relay
  local lb_port=$((BASE + 6))
  local tcp_a_lo=49900 tcp_a_hi=49949 tcp_b_lo=49950 tcp_b_hi=49999
  local before
  before="$(relay_sockets)"
  local before_tcp
  before_tcp="$(ss -ltnH 2>/dev/null | awk '{print $4}' | awk -F: '$NF >= 49900 && $NF <= 49999 {print $NF}' | sort -u)"

  if ! loopback_alias_ok 127.0.0.2 udp || ! loopback_alias_ok 127.0.0.2 tcp; then
    skip "$name" "127.0.0.2 is not a usable loopback alias on this host"
    return
  fi

  local cluster_port=$((BASE + 2))
  start_server "$name-a" --listen "127.0.0.1:$BASE" --tcp \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" --turn-tcp-relay \
    --tcp-relay-ports "$tcp_a_lo-$tcp_a_hi" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.1:$cluster_port" --cluster-instance-id a \
    --health-listen "127.0.0.1:$HEALTH_PORT"
  start_server "$name-b" --listen "127.0.0.2:$BASE" --tcp \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" --turn-tcp-relay \
    --tcp-relay-ports "$tcp_b_lo-$tcp_b_hi" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.2:$cluster_port" --cluster-instance-id b \
    --health-listen "127.0.0.2:$HEALTH_PORT"
  if ! wait_health_at 127.0.0.1 || ! wait_health_at 127.0.0.2; then
    fail "$name" "instances did not become healthy (see $LOG_DIR/$name-*.log)"
    stop_server "$name-b"
    stop_server "$name-a"
    return
  fi

  # Overlapping TCP relay ranges must be refused before serving.
  local overlap
  overlap="$("$BIN" server --listen "127.0.0.1:$((BASE + 7))" --turn --realm "$REALM" \
    --auth-secret "$SECRET" --auth-user u --auth-pass p --turn-tcp-relay \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --tcp-relay-ports "$((RELAY_LO + 50))-$((RELAY_LO + 80))" \
    --cluster-listen "127.0.0.1:$((cluster_port + 10))" \
    --cluster-peer "a@127.0.0.1:$((cluster_port + 10))" 2>&1)"
  if [[ $? -ne 0 ]] && grep -qa "overlaps" <<<"$overlap"; then
    ok "$name-range" "a TCP relay range overlapping --relay-ports is refused"
  else
    fail "$name-range" "expected a refusal mentioning the overlap"
  fi

  local attempts=8 cross=0 all_ok=0 release_ok=1
  local attempt entry owner index relay lb_log lb_ready probe_log code waited
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    lb_log="$LOG_DIR/$name-lb-$attempt.log"
    lb_ready="$WORK/$name-lb-$attempt.ready"
    rm -f "$lb_ready"
    if (( attempt % 2 )); then
      python3 "$ROOT/script/lab/rstun-turn-tcp-lb.py" --listen "127.0.0.1:$lb_port" \
        --backend "127.0.0.1:$BASE" --backend "127.0.0.2:$BASE" \
        --ready-file "$lb_ready" >"$lb_log" 2>&1 &
    else
      python3 "$ROOT/script/lab/rstun-turn-tcp-lb.py" --listen "127.0.0.1:$lb_port" \
        --backend "127.0.0.2:$BASE" --backend "127.0.0.1:$BASE" \
        --ready-file "$lb_ready" >"$lb_log" 2>&1 &
    fi
    local lb_pid=$!
    PIDS+=("$lb_pid")
    if ! wait_ready_file "$lb_ready" 30; then
      fail "$name-lb" "TCP load balancer did not start (see $lb_log)"
      kill -TERM "$lb_pid" 2>/dev/null
      wait "$lb_pid" 2>/dev/null
      break
    fi
    probe_log="$LOG_DIR/$name-probe-$attempt.log"
    python3 "$PROBE" tcp-relay --server "127.0.0.1:$lb_port" --show-relay \
      >"$probe_log" 2>&1
    code=$?
    relay="$(grep -aoE 'info: relay=[0-9.]+:[0-9]+' "$probe_log" | head -1 | sed 's/info: relay=//')"
    entry="$(grep -a '^route ' "$lb_log" | head -1 | grep -oE '127\.0\.0\.[0-9]+' | tail -1)"
    local id
    id="$(grep -aoE 'info: connection-id=[0-9]+' "$probe_log" | head -1 | sed 's/.*=//')"
    owner=""
    if [[ -n "$id" ]]; then
      index=$((id >> 24))
      if (( index == 0 )); then owner=127.0.0.1; else owner=127.0.0.2; fi
    fi
    if [[ -n "$owner" && -n "$entry" && "$owner" != "$entry" ]]; then
      cross=$((cross + 1))
    fi
    if [[ $code -eq 0 ]]; then
      all_ok=$((all_ok + 1))
    else
      fail "$name" "attempt $attempt: probe exit=$code (see $probe_log)"
    fi
    if [[ -n "$relay" ]]; then
      local relay_port="${relay##*:}"
      if ! wait_port_gone tcp "$relay_port" 50; then
        fail "$name-release" "attempt $attempt: TCP relay listener $relay still open"
        release_ok=0
      fi
    fi
    kill -TERM "$lb_pid" 2>/dev/null
    wait "$lb_pid" 2>/dev/null
  done

  # Passive mode: the peer dials the owner's relay; the ConnectionAttempt is
  # pushed back to the entry's control connection.
  local lb_log="$LOG_DIR/$name-passive-lb.log"
  local lb_ready="$WORK/$name-passive-lb.ready"
  rm -f "$lb_ready"
  python3 "$ROOT/script/lab/rstun-turn-tcp-lb.py" --listen "127.0.0.1:$lb_port" \
    --backend "127.0.0.1:$BASE" --backend "127.0.0.2:$BASE" \
    --ready-file "$lb_ready" >"$lb_log" 2>&1 &
  local lb_pid=$!
  PIDS+=("$lb_pid")
  local passive_log="$LOG_DIR/$name-passive.log"
  local passive_ok=0
  if wait_ready_file "$lb_ready" 30; then
    python3 "$PROBE" tcp-relay-passive --server "127.0.0.1:$lb_port" --show-relay \
      >"$passive_log" 2>&1
    code=$?
    [[ $code -eq 0 ]] && passive_ok=1
    local passive_id passive_owner passive_entry
    passive_id="$(grep -aoE 'info: connection-id=[0-9]+' "$passive_log" | head -1 | sed 's/.*=//')"
    passive_entry="$(grep -a '^route ' "$lb_log" | head -1 | grep -oE '127\.0\.0\.[0-9]+' | tail -1)"
    passive_owner=""
    if [[ -n "$passive_id" ]]; then
      index=$((passive_id >> 24))
      if (( index == 0 )); then passive_owner=127.0.0.1; else passive_owner=127.0.0.2; fi
    fi
    if (( passive_ok == 1 )) && [[ -n "$passive_owner" && -n "$passive_entry" && "$passive_owner" != "$passive_entry" ]]; then
      cross=$((cross + 1))
    fi
  else
    fail "$name-passive" "TCP load balancer did not start"
  fi
  kill -TERM "$lb_pid" 2>/dev/null
  wait "$lb_pid" 2>/dev/null

  if [[ $all_ok -eq $attempts ]]; then
    ok "$name" "$attempts outbound RFC 6062 attempts through the LB"
  fi
  if (( passive_ok == 1 )); then
    ok "$name-passive" "$(grep -c '^ok:' "$passive_log") passive assertions"
  else
    fail "$name-passive" "see $passive_log"
  fi
  if (( cross > 0 )); then
    ok "$name-cross" "$cross cross-instance RFC 6062 runs (control and bind on different instances)"
  else
    fail "$name-cross" "no cross-instance bind/attempt was observed"
  fi
  [[ $release_ok -eq 1 ]] && ok "$name-release" "TCP relay listeners closed after LIFETIME=0"

  stop_server "$name-b"
  stop_server "$name-a"
  local leftover leftover_tcp
  leftover="$(relay_new_sockets "$before")"
  leftover_tcp="$(ss -ltnH 2>/dev/null | awk '{print $4}' | awk -F: '$NF >= 49900 && $NF <= 49999 {print $NF}' | sort -u | comm -13 <(printf '%s\n' "${before_tcp:-}") -)"
  if [[ -z "$leftover" && -z "$leftover_tcp" ]]; then
    ok "$name-cleanup" "no UDP relay socket and no TCP relay listener left"
  else
    fail "$name-cleanup" "udp=[$(echo "$leftover" | tr '\n' ' ')] tcp=[$(echo "$leftover_tcp" | tr '\n' ' ')]"
  fi
}

# ---------- 7e. multi-instance TLS / DTLS ----------
#
# Same cluster, but the client speaks `turns:` (TLS) or DTLS. The entry holds
# the encrypted connection and its writer queue; peer→client bytes must be
# pushed back to it (PUSH_CLIENT) exactly like plain TCP. The TLS proxy is a
# byte relay; DTLS needs a **sticky** UDP balancer (a session's datagrams must
# not be split across instances).

run_mi_secure() { # name proto(tls|dtls)
  local name="$1"
  local proto="$2"
  local cluster_port=$((BASE + 2))
  local lb_port=$((BASE + 6))
  local service_port
  if [[ "$proto" == tls ]]; then service_port="$TLS_PORT"; else service_port="$DTLS_PORT"; fi
  local transport_flag
  if [[ "$proto" == tls ]]; then transport_flag="--turn-tls-listen"; else transport_flag="--turn-dtls-listen"; fi
  local before
  before="$(relay_sockets)"

  start_server "$name-a" --listen "127.0.0.1:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    "$transport_flag" "127.0.0.1:$service_port" \
    --tls-cert "$CERT_DIR/cert.pem" --tls-key "$CERT_DIR/key.pem" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.1:$cluster_port" --cluster-instance-id a \
    --health-listen "127.0.0.1:$HEALTH_PORT"
  start_server "$name-b" --listen "127.0.0.2:$BASE" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    "$transport_flag" "127.0.0.2:$service_port" \
    --tls-cert "$CERT_DIR/cert.pem" --tls-key "$CERT_DIR/key.pem" \
    --cluster-peer "a@127.0.0.1:$cluster_port" \
    --cluster-peer "b@127.0.0.2:$cluster_port" \
    --cluster-secret "$SECRET" \
    --cluster-listen "127.0.0.2:$cluster_port" --cluster-instance-id b \
    --health-listen "127.0.0.2:$HEALTH_PORT"
  if ! wait_health_at 127.0.0.1 || ! wait_health_at 127.0.0.2; then
    fail "$name" "instances did not become healthy (see $LOG_DIR/$name-*.log)"
    stop_server "$name-b"
    stop_server "$name-a"
    return
  fi

  # The balancer pins the entry to A (one backend), so every allocation that
  # hashes to B exercises the cross-instance return path.
  local cross=0 relay_ok=0 attempt code bytes_in bytes_out owner_b
  # DTLS relay-address check needs to know whether **this** run had an owner-B
  # allocation; the byte counter is cumulative across attempts.
  local before_b after_b this_b dtls_relay_ok=0 dtls_relay_bad=0
  for attempt in 1 2 3; do
    local lb_log="$LOG_DIR/$name-lb.log"
    local lb_ready="$WORK/$name-lb.ready"
    rm -f "$lb_ready"
    if [[ "$proto" == tls ]]; then
      python3 "$ROOT/script/lab/rstun-turn-tcp-lb.py" --listen "127.0.0.1:$lb_port" \
        --backend "127.0.0.1:$service_port" --ready-file "$lb_ready" \
        >"$lb_log" 2>&1 &
    else
      python3 "$ROOT/script/lab/rstun-turn-lb.py" --listen "127.0.0.1:$lb_port" \
        --sticky --backend "127.0.0.1:$service_port" --ready-file "$lb_ready" \
        >"$lb_log" 2>&1 &
    fi
    local lb_pid=$!
    PIDS+=("$lb_pid")
    if ! wait_ready_file "$lb_ready" 30; then
      fail "$name-lb" "load balancer did not start (see $lb_log)"
      kill -TERM "$lb_pid" 2>/dev/null
      wait "$lb_pid" 2>/dev/null
      break
    fi
    before_b="$(metric_at 127.0.0.2 'rstun_turn_bytes_total{direction="out"}')"
    before_b="${before_b:-0}"
    if [[ "$proto" == tls ]]; then
      turnutils_uclient -S -t -u "$USER_NAME" -w "$USER_PASS" -p "$lb_port" \
        -n 5 -m 3 -y 127.0.0.1 >"$LOG_DIR/$name-uclient.log" 2>&1
    else
      # `-v` prints `Received relay addr: <ip>:<port>` per allocation, which is
      # the only client-side view of XOR-RELAYED-ADDRESS.
      turnutils_uclient -S -v -u "$USER_NAME" -w "$USER_PASS" -p "$lb_port" \
        -n 5 -m 3 -y 127.0.0.1 >"$LOG_DIR/$name-uclient.log" 2>&1
    fi
    code=$?
    bytes_in="$(metric_sum 'rstun_turn_bytes_total{direction="in"}')"
    bytes_out="$(metric_sum 'rstun_turn_bytes_total{direction="out"}')"
    # The owner is the only one that counts relay bytes; the entry holds A.
    # Only this run's delta proves that an allocation landed on B.
    after_b="$(metric_at 127.0.0.2 'rstun_turn_bytes_total{direction="out"}')"
    after_b="${after_b:-0}"
    this_b=$((after_b - before_b))
    if [[ $code -eq 0 ]] && uclient_ok "$LOG_DIR/$name-uclient.log" &&
      [[ -n "$bytes_in" && "$bytes_in" -gt 0 && -n "$bytes_out" && "$bytes_out" -gt 0 ]]; then
      relay_ok=1
    fi
    if (( this_b > 0 )); then
      cross=1
      # S1 for DTLS: an owner-B allocation must advertise 127.0.0.2, never the
      # host's primary 127.0.0.1.
      if [[ "$proto" == dtls ]]; then
        if grep -aq "Received relay addr: 127.0.0.2:" "$LOG_DIR/$name-uclient.log"; then
          dtls_relay_ok=1
        else
          dtls_relay_bad=1
        fi
      fi
    fi
    kill -TERM "$lb_pid" 2>/dev/null
    wait "$lb_pid" 2>/dev/null
    (( relay_ok == 1 && cross == 1 )) && break
  done

  if (( relay_ok == 1 )); then
    ok "$name" "uclient -S$([[ "$proto" == tls ]] && echo ' -t') through the LB: relay bytes in=$bytes_in out=$bytes_out"
  else
    fail "$name" "uclient did not complete (see $LOG_DIR/$name-uclient.log)"
  fi
  if (( cross == 1 )); then
    ok "$name-cross" "allocations on the non-entry instance used the $proto return path"
  else
    fail "$name-cross" "no allocation landed on the other instance"
  fi
  if [[ "$proto" == dtls ]] && (( cross == 1 )); then
    if (( dtls_relay_ok == 1 && dtls_relay_bad == 0 )); then
      ok "$name-relay-ip" "owner-B DTLS relay address is on 127.0.0.2 (uclient -S -v)"
    else
      fail "$name-relay-ip" "owner-B run advertised no 127.0.0.2 relay address (see $LOG_DIR/$name-uclient.log)"
    fi
  fi

  # S1: a forwarded TLS request must bind the relay on the **owner's own**
  # listener IP (127.0.0.2), not on whatever `egress_ip` guesses for the
  # wildcard fallback. The balancer's upstream source port decides the owner, so
  # pick one whose normalized key hashes to B using the same ring the server
  # uses (deterministic, no retry guessing).
  if [[ "$proto" == tls ]]; then
    local s1_port relay_ip relay_port owner_b
    s1_port="$(python3 - "$TLS_PORT" <<'RING_PY'
import struct, sys

service = int(sys.argv[1])


def fnv(bs):
    h = 0xCBF29CE484222325
    for b in bs:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def point(member, replica):
    return fnv(member.encode() + b"#" + struct.pack("!I", replica))


ring = sorted((point(m, r), m) for m in ("a", "b") for r in range(16))


def owner(port):
    key = bytes([4]) + bytes([127, 0, 0, 1]) + struct.pack("!H", port)
    key += bytes([1]) + struct.pack("!H", service)  # Tcp, TLS listen port
    h = fnv(key)
    for p, member in ring:
        if p >= h:
            return member
    return ring[0][1]


for port in range(45000, 45100):
    if owner(port) == "b":
        print(port)
        break
else:
    sys.exit(1)
RING_PY
)"
    if [[ -z "$s1_port" ]]; then
      fail "$name-relay-ip" "could not find a 5-tuple whose owner is B"
    else
      local lb_log="$LOG_DIR/$name-s1-lb.log"
      local lb_ready="$WORK/$name-s1-lb.ready"
      local probe_log="$LOG_DIR/$name-s1.log"
      rm -f "$lb_ready"
      python3 "$ROOT/script/lab/rstun-turn-tcp-lb.py" --listen "127.0.0.1:$lb_port" \
        --backend "127.0.0.1:$service_port" --source-port "$s1_port" \
        --ready-file "$lb_ready" >"$lb_log" 2>&1 &
      local lb_pid=$!
      PIDS+=("$lb_pid")
      if wait_ready_file "$lb_ready" 30; then
        python3 "$PROBE" tcp-control --tls --server "127.0.0.1:$lb_port" --show-relay --hold 0.8 \
          >"$probe_log" 2>&1 &
        local probe_pid=$!
        local waited=0
        while ! grep -qa "info: holding" "$probe_log" 2>/dev/null && (( waited < 50 )); do
          sleep 0.1
          waited=$((waited + 1))
        done
        relay_ip="$(grep -aoE 'info: relay=[0-9.]+:[0-9]+' "$probe_log" | head -1 | sed 's/.*=//; s/:[0-9]*$//')"
        relay_port="$(grep -aoE 'info: relay=[0-9.]+:[0-9]+' "$probe_log" | head -1 | sed 's/.*://')"
        owner_b="$(metric_at 127.0.0.2 'rstun_turn_allocations')"
        wait "$probe_pid" 2>/dev/null
        if [[ -n "$relay_port" ]] && ! wait_port_gone udp "$relay_port" 30; then
          fail "$name-relay-ip" "relay port $relay_port was not released"
        elif [[ -n "$owner_b" && "$owner_b" -gt 0 && "$relay_ip" == 127.0.0.2 ]]; then
          ok "$name-relay-ip" "XOR-RELAYED-ADDRESS IP is the owning instance's TLS listen IP (127.0.0.2)"
        else
          fail "$name-relay-ip" "owner-B allocation relay IP is ${relay_ip:-?} (owner_b=${owner_b:-?}); see $probe_log"
        fi
      else
        fail "$name-relay-ip" "load balancer did not start with --source-port $s1_port (see $lb_log)"
      fi
      kill -TERM "$lb_pid" 2>/dev/null
      wait "$lb_pid" 2>/dev/null
    fi
  fi

  stop_server "$name-b"
  stop_server "$name-a"
  local leftover
  leftover="$(relay_new_sockets "$before")"
  if [[ -z "$leftover" ]]; then
    ok "$name-cleanup" "no relay socket left after shutdown"
  else
    fail "$name-cleanup" "leftover=[$(echo "$leftover" | tr '\n' ' ')]"
  fi
}

run_multi_instance_tls() {
  local name=multi-instance-tls
  if [[ "$HAVE_SECURE" != true ]]; then
    skip "$name" "lean 构建没有 tls/dtls feature（用 --tls，或 cargo build --features full）"
    return
  fi
  make_cert || { skip "$name" "openssl 不可用，无法生成证书"; return; }
  run_mi_secure "$name" tls
}

run_multi_instance_dtls() {
  local name=multi-instance-dtls
  if [[ "$HAVE_SECURE" != true ]]; then
    skip "$name" "lean 构建没有 tls/dtls feature（用 --dtls，或 cargo build --features full）"
    return
  fi
  make_cert || { skip "$name" "openssl 不可用，无法生成证书"; return; }
  run_mi_secure "$name" dtls
}

# ---------- 8. frozen: no --turn is byte-identical to HEAD ----------

FROZEN_PY='
import socket, struct, sys, zlib

host, port = sys.argv[1], int(sys.argv[2])
MAGIC = 0x2112A442

def attr(t, v):
    pad = (4 - len(v) % 4) % 4
    return struct.pack("!HH", t, len(v)) + v + b"\0" * pad

def message(t, txn, body=b""):
    return struct.pack("!HH", t, len(body)) + struct.pack("!I", MAGIC) + txn + body

def fingerprint(frame):
    length = len(frame) - 20 + 8
    prefix = frame[:2] + struct.pack("!H", length) + frame[4:]
    crc = (zlib.crc32(prefix) & 0xFFFFFFFF) ^ 0x5354554E
    return prefix + attr(0x8028, struct.pack("!I", crc))

txn = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C"
binding = 0x0001
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.3)
requests = [
    message(binding, txn),
    message(binding, txn, attr(0x8022, b"probe")),
    message(binding, txn, attr(0x0002, b"")),
    message(0x0002, txn),
    message(binding, txn, attr(0x0026, b"12345678")),
    message(binding, txn, attr(0x0026, b"1234") + attr(0x0027, struct.pack("!H", 0))),
    message(binding, txn, attr(0x0003, struct.pack("!I", 0x06))),
    message(binding, txn, attr(0x0027, struct.pack("!H", port))),
    fingerprint(message(binding, txn)),
    message(binding, txn) + b"\0\0\0\0",           # trailing junk
    message(0x0011, txn),                           # indication
    message(0x0101, txn),                           # response
    message(0x0001, txn, attr(0x0024, struct.pack("!I", 1)) + attr(0x0025, b"")),
    message(0x0001, txn, attr(0x7777, b"")),
    b"\x00\x01",                                    # truncated
    b"\x00\x01\x00\x00\xde\xad\xbe\xef" + b"\0" * 12,  # bad magic cookie
    message(binding, txn, attr(0x8029, b"12345678")),
]
def normalise(reply):
    """Zero address payloads: the client source port differs between runs."""
    if len(reply) < 20:
        return reply
    length = struct.unpack("!H", reply[2:4])[0]
    body = bytearray(reply[20:20 + length])
    offset = 0
    address_types = {0x0001, 0x0020, 0x802B, 0x802C}
    while offset < len(body):
        attr_type, attr_length = struct.unpack("!HH", body[offset:offset + 4])
        if attr_type in address_types and attr_length >= 8:
            value = offset + 4
            body[value + 2:value + attr_length] = b"\0" * (attr_length - 2)
        offset += 4 + attr_length + ((4 - attr_length % 4) % 4)
    return reply[:20] + bytes(body) + reply[20 + length:]

for index, request in enumerate(requests):
    try:
        sock.sendto(request, (host, port))
        reply, _ = sock.recvfrom(65535)
        print(f"{index}: {normalise(reply).hex()}")
    except socket.timeout:
        print(f"{index}: NONE")
'
# The wrong-cookie frame above is malformed on purpose; send the rest anyway.

run_frozen() {
  local name=frozen
  local old_src="$WORK/old-src"
  local old_target="$WORK/old-target"
  # Baseline for the byte-freeze check: the commit *before* this change. HEAD is
  # correct before work is committed; after committing, pin the last pre-change
  # commit here (or pass FROZEN_BASE=<sha>).
  #
  # The baseline is rebuilt with `RSTUN_BUILD_VERSION` set to whatever version
  # string the *new* binary carries. `SOFTWARE` (and therefore every frame) embeds
  # that string, so without the override every version bump would show up as a
  # 17-frame diff and force a pointless re-pin. With it, `frozen` only reports
  # real behaviour changes.
  local base="${FROZEN_BASE:-cad4fa2}"
  if ! git -C "$ROOT" archive "$base" | tar -x -C "$old_src" 2>/dev/null; then
    mkdir -p "$old_src"
    if ! git -C "$ROOT" archive "$base" | tar -x -C "$old_src"; then
      skip "$name" "cannot export HEAD via git archive"
      return
    fi
  fi
  local pinned_version
  pinned_version="$("$BIN" --version 2>/dev/null | awk '{print $2}')"
  if [[ -z "$pinned_version" ]]; then
    skip "$name" "cannot read the version string from $BIN"
    return
  fi
  if ! RSTUN_BUILD_VERSION="$pinned_version" \
    cargo build --manifest-path "$old_src/Cargo.toml" --target-dir "$old_target" \
    >"$LOG_DIR/$name-build.log" 2>&1; then
    skip "$name" "old binary did not build (see $LOG_DIR/$name-build.log)"
    return
  fi
  local old_bin="$old_target/debug/rstun"
  local config_name config_args
  local mismatches=0
  for config_name in default verbose inflight; do
    case "$config_name" in
      default) config_args=() ;;
      verbose) config_args=(--verbose) ;;
      inflight) config_args=(--max-inflight 8) ;;
    esac
    local new_port=$((BASE + 20))
    local old_port=$((BASE + 21))
    "$BIN" server --listen "127.0.0.1:$new_port" "${config_args[@]}" \
      >"$LOG_DIR/$name-new-$config_name.log" 2>&1 &
    local new_pid=$!
    PIDS+=("$new_pid")
    "$old_bin" server --listen "127.0.0.1:$old_port" "${config_args[@]}" \
      >"$LOG_DIR/$name-old-$config_name.log" 2>&1 &
    local old_pid=$!
    PIDS+=("$old_pid")
    sleep 0.6
    python3 -c "$FROZEN_PY" 127.0.0.1 "$new_port" >"$LOG_DIR/$name-new-$config_name.txt"
    python3 -c "$FROZEN_PY" 127.0.0.1 "$old_port" >"$LOG_DIR/$name-old-$config_name.txt"
    kill -TERM "$new_pid" "$old_pid" 2>/dev/null
    wait "$new_pid" "$old_pid" 2>/dev/null
    if ! diff -q "$LOG_DIR/$name-old-$config_name.txt" "$LOG_DIR/$name-new-$config_name.txt" \
      >/dev/null; then
      mismatches=$((mismatches + 1))
      diff -u "$LOG_DIR/$name-old-$config_name.txt" "$LOG_DIR/$name-new-$config_name.txt" \
        >"$LOG_DIR/$name-diff-$config_name.txt"
    fi
  done
  if [[ $mismatches -eq 0 ]]; then
    ok "$name" "3 configurations × 17 requests byte-identical to ${base}"
  else
    fail "$name" "$mismatches configuration(s) differ (see $LOG_DIR/$name-diff-*.txt)"
  fi
}

# ---------- 9. coturn: same client, same steps, same outcomes ----------

run_coturn() {
  local name=coturn
  if ! command -v turnserver >/dev/null 2>&1 || ! command -v turnutils_uclient >/dev/null 2>&1; then
    skip "$name" "turnserver/turnutils_uclient not installed"
    return
  fi
  mkdir -p "$WORK/coturn"
  local coturn_port=$((BASE + 30))
  local coturn_lo=$((RELAY_HI + 1))
  local coturn_hi=$((RELAY_HI + 100))
  local coturn_tls=$((coturn_port + 2))
  # coturn's TLS/DTLS only make sense when our binary can serve them too: on a
  # lean build those comparison rows are skipped, the rest still runs.
  local cert_args=()
  if [[ "$HAVE_SECURE" == true ]] && make_cert; then
    cert_args=(--cert "$COTURN_CERT" --pkey "$COTURN_PKEY" --tls-listening-port="$coturn_tls")
  fi
  (cd "$WORK/coturn" && exec turnserver -n \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --listening-port="$coturn_port" \
    "${cert_args[@]}" \
    --min-port="$coturn_lo" --max-port="$coturn_hi" \
    --lt-cred-mech --realm="$REALM" --user="$USER_NAME:$USER_PASS" \
    --user=otheruser:otherpass \
    --allow-loopback-peers --no-multicast-peers --no-cli --log-file=stdout) \
    >"$LOG_DIR/$name-server.log" 2>&1 &
  local coturn_pid=$!
  PIDS+=("$coturn_pid")
  sleep 1.5
  if ! kill -0 "$coturn_pid" 2>/dev/null; then
    fail "$name" "turnserver did not start (see $LOG_DIR/$name-server.log)"
    return
  fi

  # Our server, same parameters (two users: the 441 comparison needs both).
  # `turns:` is enabled when a certificate could be made, so the TLS/DTLS rows
  # below compare the same client against both servers' secure transports.
  local rstun_tls_args=()
  if [[ ${#cert_args[@]} -gt 0 ]]; then
    rstun_tls_args=(--turn-tls-listen "127.0.0.1:$TLS_PORT" --turn-dtls-listen "127.0.0.1:$DTLS_PORT" \
      --tls-cert "$CERT_DIR/cert.pem" --tls-key "$CERT_DIR/key.pem")
  fi
  start_turn_users "$name-rstun" --tcp --turn-tcp-relay "${rstun_tls_args[@]}"
  if ! wait_health "$HEALTH_PORT"; then
    fail "$name" "rstun did not become healthy"
    stop_server "$name-rstun"
    kill -TERM "$coturn_pid" 2>/dev/null
    return
  fi

  local ok_all=true
  if ! python3 "$PROBE" relay --server "127.0.0.1:$coturn_port" \
    >"$LOG_DIR/$name-coturn-relay.log" 2>&1; then
    ok_all=false
  fi
  if ! python3 "$PROBE" relay --server "127.0.0.1:$BASE" \
    >"$LOG_DIR/$name-rstun-relay.log" 2>&1; then
    ok_all=false
  fi
  diff -u "$LOG_DIR/$name-coturn-relay.log" "$LOG_DIR/$name-rstun-relay.log" \
    >"$LOG_DIR/$name-relay-diff.log" 2>&1 || ok_all=false

  # RFC 6062 outbound: the same `tcp-relay` client flow (Allocate(TCP) →
  # Connect → ConnectionBind → raw bytes → LIFETIME=0) must produce the same
  # 11 lines on both servers. This is the PRD's "逐行一致" evidence; the
  # `tcprelay` item alone only proves rstun passes.
  python3 "$PROBE" tcp-relay --server "127.0.0.1:$coturn_port" \
    >"$LOG_DIR/$name-coturn-tcprelay.log" 2>&1 || ok_all=false
  python3 "$PROBE" tcp-relay --server "127.0.0.1:$BASE" \
    >"$LOG_DIR/$name-rstun-tcprelay.log" 2>&1 || ok_all=false
  diff -u "$LOG_DIR/$name-coturn-tcprelay.log" "$LOG_DIR/$name-rstun-tcprelay.log" \
    >"$LOG_DIR/$name-tcprelay-diff.log" 2>&1 || ok_all=false

  python3 "$PROBE" lifecycle --server "127.0.0.1:$coturn_port" --lenient-refresh \
    >"$LOG_DIR/$name-coturn-lifecycle.log" 2>&1 || ok_all=false
  python3 "$PROBE" lifecycle --server "127.0.0.1:$BASE" \
    >"$LOG_DIR/$name-rstun-lifecycle.log" 2>&1 || ok_all=false

  if ! python3 "$PROBE" wrong-user --server "127.0.0.1:$coturn_port" \
    >"$LOG_DIR/$name-coturn-wrong-user.log" 2>&1; then
    ok_all=false
  fi
  if ! python3 "$PROBE" wrong-user --server "127.0.0.1:$BASE" \
    >"$LOG_DIR/$name-rstun-wrong-user.log" 2>&1; then
    ok_all=false
  fi
  diff -u "$LOG_DIR/$name-coturn-wrong-user.log" "$LOG_DIR/$name-rstun-wrong-user.log" \
    >"$LOG_DIR/$name-wrong-user-diff.log" 2>&1 || ok_all=false

  # The same uclient run against both, relayed messages compared.
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$coturn_port" -n 5 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-coturn-uclient.log" 2>&1
  local coturn_exit=$?
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 5 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-rstun-uclient.log" 2>&1
  local rstun_exit=$?

  # TLS/DTLS: the same `turnutils_uclient` secure modes against both servers.
  local coturn_tls_result=SKIP rstun_tls_result=SKIP
  local coturn_dtls_result=SKIP rstun_dtls_result=SKIP
  if [[ ${#cert_args[@]} -gt 0 ]]; then
    if command -v turnutils_uclient >/dev/null 2>&1; then
      turnutils_uclient -S -t -u "$USER_NAME" -w "$USER_PASS" -p "$coturn_tls" -n 3 -m 2 -y 127.0.0.1 \
        >"$LOG_DIR/$name-coturn-tls.log" 2>&1
      uclient_ok "$LOG_DIR/$name-coturn-tls.log" && coturn_tls_result=ok || coturn_tls_result=failed
      turnutils_uclient -S -t -u "$USER_NAME" -w "$USER_PASS" -p "$TLS_PORT" -n 3 -m 2 -y 127.0.0.1 \
        >"$LOG_DIR/$name-rstun-tls.log" 2>&1
      uclient_ok "$LOG_DIR/$name-rstun-tls.log" && rstun_tls_result=ok || rstun_tls_result=failed
      turnutils_uclient -S -u "$USER_NAME" -w "$USER_PASS" -p "$coturn_tls" -n 3 -m 2 -y 127.0.0.1 \
        >"$LOG_DIR/$name-coturn-dtls.log" 2>&1
      uclient_ok "$LOG_DIR/$name-coturn-dtls.log" && coturn_dtls_result=ok || coturn_dtls_result=failed
      turnutils_uclient -S -u "$USER_NAME" -w "$USER_PASS" -p "$DTLS_PORT" -n 3 -m 2 -y 127.0.0.1 \
        >"$LOG_DIR/$name-rstun-dtls.log" 2>&1
      uclient_ok "$LOG_DIR/$name-rstun-dtls.log" && rstun_dtls_result=ok || rstun_dtls_result=failed
    fi
    [[ "$coturn_tls_result" == ok && "$rstun_tls_result" == ok && \
      "$coturn_dtls_result" == ok && "$rstun_dtls_result" == ok ]] || ok_all=false
  else
    log "  TLS/DTLS:       SKIP（lean 构建）"
  fi

  log "coturn comparison (same client, same steps):"
  log "  relay probe:    $(diff -q "$LOG_DIR/$name-coturn-relay.log" "$LOG_DIR/$name-rstun-relay.log" >/dev/null && echo identical || echo DIFFERENT)"
  log "  tcp-relay:      $(diff -q "$LOG_DIR/$name-coturn-tcprelay.log" "$LOG_DIR/$name-rstun-tcprelay.log" >/dev/null && echo identical || echo DIFFERENT)"
  log "  wrong-user:     $(diff -q "$LOG_DIR/$name-coturn-wrong-user.log" "$LOG_DIR/$name-rstun-wrong-user.log" >/dev/null && echo identical || echo DIFFERENT)"
  log "  uclient:        coturn exit=$coturn_exit  rstun exit=$rstun_exit"
  log "  TLS  (uclient -S -t): coturn=$coturn_tls_result  rstun=$rstun_tls_result"
  log "  DTLS (uclient -S):    coturn=$coturn_dtls_result  rstun=$rstun_dtls_result"
  log "  allocation:     $(grep -a '^ok: allocate ' "$LOG_DIR/$name-coturn-lifecycle.log" | sed 's/^ok: //')  (both servers)"
  log "  refresh:        $(grep -a '^ok: refresh-' "$LOG_DIR/$name-rstun-lifecycle.log" | sed 's/^ok: //' | tr '\n' ';')"
  local coturn_release rstun_release
  coturn_release="$(grep -a 'refresh-after-release' "$LOG_DIR/$name-coturn-lifecycle.log" | sed 's/.*code=//')"
  rstun_release="$(grep -a 'refresh-error-60' "$LOG_DIR/$name-rstun-lifecycle.log" | sed 's/.*code=//')"
  log "  after LIFETIME=0: coturn code=${coturn_release:-?}  rstun code=${rstun_release:-?}"
  log "  judgement:      rstun follows RFC 8656 §7.2 (437 for an unknown allocation);"
  log "                  coturn re-creates it (lenient, not RFC-mandated). All other steps identical."

  # REST credentials: coturn cannot mix `use-auth-secret` with `--user`, so the
  # comparison uses a second coturn instance and our server with --rest-secret.
  local rest_result=SKIP
  stop_server "$name-rstun"
  local coturn_rest=$((coturn_port + 4))
  (cd "$WORK/coturn" && exec turnserver -n \
    --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 \
    --listening-port="$coturn_rest" \
    --min-port="$((coturn_hi + 1))" --max-port="$((coturn_hi + 100))" \
    --use-auth-secret --static-auth-secret="$REST_SECRET" \
    --realm="$REALM" --allow-loopback-peers --no-multicast-peers --no-cli \
    --log-file=stdout) >"$LOG_DIR/$name-coturn-rest.log" 2>&1 &
  local coturn_rest_pid=$!
  PIDS+=("$coturn_rest_pid")
  start_turn "$name-rstun-rest" "--rest-secret" "$REST_SECRET"
  if wait_health "$HEALTH_PORT"; then
    sleep 1
    python3 "$PROBE" rest --server "127.0.0.1:$coturn_rest" --rest-secret "$REST_SECRET" \
      >"$LOG_DIR/$name-coturn-rest-probe.log" 2>&1
    local coturn_rest_probe=$?
    python3 "$PROBE" rest --server "127.0.0.1:$BASE" --rest-secret "$REST_SECRET" \
      >"$LOG_DIR/$name-rstun-rest-probe.log" 2>&1
    local rstun_rest_probe=$?
    if diff -u "$LOG_DIR/$name-coturn-rest-probe.log" "$LOG_DIR/$name-rstun-rest-probe.log" \
      >"$LOG_DIR/$name-rest-diff.log" 2>&1 &&
      [[ $coturn_rest_probe -eq 0 && $rstun_rest_probe -eq 0 ]]; then
      rest_result=identical
    else
      rest_result=DIFFERENT
    fi
  fi
  log "  REST probe:     $rest_result (valid / expired 401 / wrong secret 401 / ':' label)"
  [[ "$rest_result" == identical ]] || ok_all=false
  stop_server "$name-rstun-rest"

  local secure_note="TLS+DTLS relays ok on both"
  [[ "$coturn_tls_result" == SKIP ]] && secure_note="TLS/DTLS SKIP (lean build)"
  if $ok_all && [[ $coturn_exit -eq 0 && $rstun_exit -eq 0 ]]; then
    ok "$name" "relay/tcp-relay/lifecycle/441 identical; ${secure_note}; REST behaviour identical"
  else
    fail "$name" "see $LOG_DIR/$name-*.log"
  fi
  kill -TERM "$coturn_pid" "$coturn_rest_pid" 2>/dev/null
  wait "$coturn_pid" "$coturn_rest_pid" 2>/dev/null
}

# ---------- run ----------

run_item() {
  case "$1" in
    startup) run_startup ;;
    relay) run_relay ;;
    tcprelay) run_tcprelay ;;
    tcp-relay-passive) run_tcp_relay_passive ;;
    multi-instance-udp) run_multi_instance_udp ;;
    multi-instance-tcp) run_multi_instance_tcp ;;
    multi-instance-tcp-relay) run_multi_instance_tcp_relay ;;
    multi-instance-tls) run_multi_instance_tls ;;
    multi-instance-dtls) run_multi_instance_dtls ;;
    auth) run_auth ;;
    lifecycle) run_lifecycle ;;
    wrong-user) run_wrong_user ;;
    raf) run_raf ;;
    df) run_df ;;
    ipv6relay) run_ipv6relay ;;
    wildcard) run_wildcard ;;
    permission-limit) run_permission_limit ;;
    quota) run_quota ;;
    ports) run_ports ;;
    tls) run_tls ;;
    dtls) run_dtls ;;
    cert-reload) run_cert_reload ;;
    cert-poll) run_cert_poll ;;
    rest) run_rest ;;
    bandwidth) run_bandwidth ;;
    cleanup) run_cleanup ;;
    frozen) run_frozen ;;
    coturn) run_coturn ;;
  esac
}

if [[ ${#T2_ONLY[@]} -gt 0 ]]; then
  # `--tls` / `--dtls` are shortcuts for the T2 transports (both may be given).
  for item in "${T2_ONLY[@]}"; do
    run_item "$item"
  done
elif [[ -n "$ONLY" ]]; then
  run_item "$ONLY"
else
  for item in "${ALL_ITEMS[@]}"; do
    run_item "$item"
  done
fi

log ""
log "passed: ${#PASSED[@]}  failed: ${#FAILED[@]}  skipped: ${#SKIPPED[@]}"
if ((${#FAILED[@]} > 0)); then
  log "failed items: ${FAILED[*]}"
  exit 1
fi
exit 0
