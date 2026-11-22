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
#     （startup|relay|tcprelay|auth|lifecycle|wrong-user|raf|df|ipv6relay|wildcard|
#       permission-limit|quota|ports|tls|dtls|rest|bandwidth|cleanup|frozen|coturn）
#   bash script/lab/rstun-turn.sh --keep           # 保留日志（默认只清进程）
#   FROZEN_BASE=<sha> bash script/lab/rstun-turn.sh --only frozen
#                                                  # 字节冻结对照的基线提交（默认 cad4fa2）
#
# 构建：默认 lean（`cargo build`，无 tls/dtls feature）。`--tls` / `--dtls` /
# `--only tls|dtls|coturn` 会自动用 `cargo build --features full` 构建；`--no-build`
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
# `--allocation-lifetime 2` 让 allocation 自然过期，再断言 `ss -lun` 在 relay
# 端口段内无监听 —— 这就是「回收彻底」的可执行定义。

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

ALL_ITEMS=(startup relay tcprelay auth lifecycle wrong-user raf df ipv6relay wildcard permission-limit quota ports tls dtls rest bandwidth cleanup frozen coturn)

usage() {
  sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) BASE="${2:?--port 需要一个端口}"; shift ;;
    --port=*) BASE="${1#*=}" ;;
    --no-build) BUILD=false ;;
    --tls) T2_ONLY+=(tls) ;;
    --dtls) T2_ONLY+=(dtls) ;;
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
    startup | relay | tcprelay | auth | lifecycle | wrong-user | raf | df | ipv6relay | wildcard | permission-limit | quota | ports | tls | dtls | rest | bandwidth | cleanup | frozen | coturn) : ;;
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
  case "$ONLY" in tls | dtls | coturn) return 0 ;; esac
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
# `turnutils_uclient -T` shortcut is **not** usable as the assertion here:
# `-T` implies `-y` (client-to-client), and the second client's side needs a
# `ConnectionAttempt` indication — the passive mode this task leaves out. The
# probe performs the standard client flow (and runs identically against coturn).
run_tcprelay() {
  local name=tcprelay
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
  # (part of the probe) must take it away.
  local leftover
  leftover="$(relay_tcp_listeners)"
  if [[ -n "$leftover" ]]; then
    fail "$name" "TCP relay listener left behind: $(echo "$leftover" | tr '\n' ' ')"
  else
    ok "$name" "$assertions assertions, no TCP relay listener left in $RELAY_LO-$RELAY_HI"
  fi
  if command -v turnutils_uclient >/dev/null 2>&1; then
    log "info: $name: uclient -T not used (it implies -y; the peer side needs ConnectionAttempt, out of scope)"
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

# ---------- 6d. REST credentials: valid / expired / wrong secret (T2) ----------

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
  turnutils_uclient -u "$USER_NAME" -w "$USER_PASS" -p "$BASE" -n 2 -m 2 -y 127.0.0.1 \
    >"$LOG_DIR/$name-after.log" 2>&1
  local after=ok
  uclient_ok "$LOG_DIR/$name-after.log" || after=failed
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
  before="$(relay_listeners)"
  if [[ -n "$before" ]]; then
    skip "$name" "relay range $RELAY_LO-$RELAY_HI already has listeners: $(echo "$before" | tr '\n' ' ')"
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
  local leftover leftover_tcp
  leftover="$(relay_listeners)"
  leftover_tcp="$(relay_tcp_listeners)"
  if [[ "$active" == "0" && -z "$leftover" && -z "$leftover_tcp" ]]; then
    ok "$name" "created=$created, allocations=0 and no UDP/TCP relay listener in $RELAY_LO-$RELAY_HI"
  else
    fail "$name" "created=$created allocations=$active leftover=[$(echo "$leftover $leftover_tcp" | tr '\n' ' ')]"
  fi
  stop_server "$name"
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
