#!/usr/bin/env bash
#
# `rstun` 混沌用例（C1–C6）：`tc netem` 注入丢包 / 乱序 / 重复，外加 TCP 半包、
# 半开连接与 TURN 中继丢包 + 带宽配额。
#
# 为什么要单独一个脚本：单测能证明「某个函数对某个输入返回什么」，但证明不了
# 「内核丢包、包被乱序、连接发半个帧就沉默」时进程的行为。这些用例要 NET_ADMIN
# （`tc`），所以**不是 CI 门禁**：没有 root / 没有 `tc` 时对应项记 SKIP 并写明
# 原因，绝不伪装通过（设计见 `.trellis/tasks/11-19-rstun-qa/design.md` §4）。
#
# 用法：
#   bash script/lab/rstun-chaos.sh                # 全部 6 例
#   bash script/lab/rstun-chaos.sh --list         # 列用例名 + 说明
#   bash script/lab/rstun-chaos.sh --only loss    # 只跑一例
#   bash script/lab/rstun-chaos.sh --mtu 1500     # C3 额外把 lo MTU 降到 1500 以强制分片
#   bash script/lab/rstun-chaos.sh --no-build     # 复用 target/release/rstun
#   bash script/lab/rstun-chaos.sh --port 35380   # 从该端口起找一对可绑端口
#                                                 # （本机 ip_local_port_range 可能是 1024–65535，
#                                                 #  固定端口会被临时连接抢走 → 自动预检 + 换端口重试）
#
# 用例：
#   loss       C1  UDP 丢包 10%：服务不崩；客户端可见丢包，重传后全部成功
#   reorder    C2  延迟 20ms + 25% 乱序 + 5% 重复：每个请求至少一个应答，
#                  单请求应答 <= 4、总应答 <= 1.35×（>3σ）
#   mtu        C3  大 PADDING（1400 / 8000）：响应开销只有 0 或固定 32 字节（无额外放大）
#   half-frame C4  TCP 只发半个帧：服务端在 TCP_READ_TIMEOUT（30s）内回收，fd 回落
#   half-open  C5  TCP 建连不读不写：同上，fd 回落
#   turn-loss  C6  TURN 中继：5% 丢包 + `--turn-bandwidth` 配额，allocation 存活、
#                  `rstun_turn_bytes_dropped_total{direction="in"}` 增长
#
# 退出码：0 = 全部 ok 或 SKIP；1 = 至少一项 FAIL；2 = 参数/环境错误。
# 日志：$RSTUN_CHAOS_DIR（默认 /tmp/opencode/rstun-chaos），每例一个 .log。
#
# `--mtu 1500` 会临时改 lo 的 MTU 并在退出时恢复（默认不动：lo 的 MTU 是 65536，
# 默认路径下「分片」实际没有发生 —— 这一点在输出里如实标注，不冒充已验证）。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${RSTUN_CHAOS_DIR:-/tmp/opencode/rstun-chaos}"

PORT=35180
HEALTH_PORT=$((PORT + 1))
RELAY_LO=49750
RELAY_HI=49799
PROFILE="release"
BUILD=true
ONLY=""
FORCE_MTU=""

USER_NAME="turnuser"
USER_PASS="turnpass"
REALM="example.org"
SECRET="chaos-secret"

PIDS=()
SERVER_PID=""
FAILED=()
SKIPPED=()
PASSED=()
NETEM_REASON=""
NETEM_OWNED=false
MTU_SAVED=""

ALL_CASES=(loss reorder mtu half-frame half-open turn-loss)

usage() {
  sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="${2:?--port 需要一个端口}"; shift ;;
    --port=*) PORT="${1#*=}" ;;
    --only) ONLY="${2:?--only 需要一例}"; shift ;;
    --only=*) ONLY="${1#*=}" ;;
    --mtu) FORCE_MTU="${2:?--mtu 需要一个 MTU 值}"; shift ;;
    --mtu=*) FORCE_MTU="${1#*=}" ;;
    --debug) PROFILE="debug" ;;
    --no-build) BUILD=false ;;
    --list)
      printf '%s\n' "${ALL_CASES[@]}"
      exit 0
      ;;
    --keep) : ;;
    -h | --help) usage; exit 0 ;;
    *)
      echo "未知参数: $1（--help 看用法）" >&2
      exit 2
      ;;
  esac
  shift
done

HEALTH_PORT=$((PORT + 1))

case "$PROFILE" in
  release) BIN="$ROOT/target/release/rstun" ;;
  debug) BIN="$ROOT/target/debug/rstun" ;;
  *)
    echo "--profile 只能是 release 或 debug，收到: $PROFILE" >&2
    exit 2
    ;;
esac

if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  echo "--port 需要整数" >&2
  exit 2
fi
if [[ "$PORT" == "3478" || "$PORT" -le 1024 ]]; then
  echo "不要用 3478/特权端口；给个高位端口" >&2
  exit 2
fi
if [[ -n "$FORCE_MTU" ]] && ! [[ "$FORCE_MTU" =~ ^[0-9]+$ ]]; then
  echo "--mtu 需要整数" >&2
  exit 2
fi
if [[ -n "$ONLY" ]]; then
  found=false
  for known in "${ALL_CASES[@]}"; do
    [[ "$known" == "$ONLY" ]] && found=true
  done
  if [[ "$found" != true ]]; then
    echo "--only 未知用例: $ONLY（可用：${ALL_CASES[*]}）" >&2
    exit 2
  fi
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "需要 python3（探针只用标准库）" >&2
  exit 2
fi
export PYTHONIOENCODING=utf-8

RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
LOG_DIR="$WORK/$RUN_ID"
# 目录不可写时立刻失败（磁盘满是本机遇到过的真实场景），否则日志悄悄丢失。
mkdir -p "$WORK" || {
  echo "日志目录不可写: $WORK" >&2
  exit 2
}
mkdir -p "$LOG_DIR" || {
  echo "日志目录不可写: $LOG_DIR" >&2
  exit 2
}
ln -sfn "$RUN_ID" "$WORK/latest"

log() { printf '%s\n' "$*" | tee -a "$LOG_DIR/summary.log"; }
ok() { PASSED+=("$1"); log "ok: $1${2:+ — $2}"; }
fail() { FAILED+=("$1"); log "FAIL: $1${2:+ — $2}"; }
skip() { SKIPPED+=("$1"); log "SKIP: $1${2:+ — $2}"; }
info() { log "info: $*"; }

ADDR="127.0.0.1:$PORT"
HEALTH="127.0.0.1:$HEALTH_PORT"

# 端口可用性（1 个 python 进程检一种协议）。本机 `ip_local_port_range` 是
# `1024 65535` —— 整段非特权端口都会被内核当源端口用，固定端口随时可能被别的
# 进程的临时连接占住（实测 C4/C5 偶发 `Address already in use (os error 98)`）。
port_free() { # port proto
  python3 - "$1" "$2" <<'PY'
import socket, sys
port, proto = int(sys.argv[1]), sys.argv[2]
kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
sock = socket.socket(socket.AF_INET, kind)
try:
    sock.bind(("127.0.0.1", port))
except OSError:
    sys.exit(1)
finally:
    sock.close()
PY
}

set_ports() { # base
  PORT="$1"
  HEALTH_PORT=$((PORT + 1))
  ADDR="127.0.0.1:$PORT"
  HEALTH="127.0.0.1:$HEALTH_PORT"
}

# 从 base 往上挑一对「UDP + TCP + health TCP」都能绑的端口（最多 200 个候选）。
pick_ports() { # base
  local candidate="$1" tries=0
  while (( tries < 200 )); do
    if port_free "$candidate" udp && port_free "$candidate" tcp &&
      port_free "$((candidate + 1))" tcp; then
      set_ports "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
    tries=$((tries + 1))
  done
  return 1
}

healthz_ok() {
  python3 - "$HEALTH" <<'PY' >/dev/null 2>&1
import sys, urllib.request
urllib.request.urlopen(f"http://{sys.argv[1]}/healthz", timeout=2).read()
PY
}

metric() { # metric-key
  python3 - "$HEALTH" "$1" <<'PY' 2>/dev/null || echo ""
import sys, urllib.request
text = urllib.request.urlopen(f"http://{sys.argv[1]}/metrics", timeout=3).read().decode()
want = sys.argv[2]
value = ""
for line in text.splitlines():
    if line.startswith(want + " "):
        value = line.split(" ")[-1]
print(value)
PY
}

cleanup() {
  netem_clear
  restore_mtu
  local pid
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# ---------- 服务生命周期 ----------

# 端口是全局的（所有用例共用）。本机 `ip_local_port_range` 可能是 1024–65535，
# 固定端口会被别的进程的临时连接抢走：启动时先挑一对真正可绑的端口，遇到
# 运行期冲突再换端口重试（只对 `Address already in use` 重试，其它错误不掩盖）。
start_server() { # name args...
  local name="$1"
  shift
  local args=("$@") attempt=0 index old_addr old_health
  while :; do
    "$BIN" server "${args[@]}" >"$LOG_DIR/$name.log" 2>&1 &
    SERVER_PID=$!
    PIDS+=("$SERVER_PID")
    sleep 0.15
    kill -0 "$SERVER_PID" 2>/dev/null && return 0
    if ! grep -q "Address already in use" "$LOG_DIR/$name.log" 2>/dev/null; then
      # 别的启动错误：交给 wait_health 报，不在日志里重复刷错误信息。
      return 0
    fi
    attempt=$((attempt + 1))
    if (( attempt > 3 )); then
      log "WARN: $name 连续 $attempt 次绑定失败（见 $LOG_DIR/$name.log），交给 wait_health 判定"
      return 0
    fi
    old_addr="$ADDR"
    old_health="$HEALTH"
    if ! pick_ports "$((PORT + 2))"; then
      return 0
    fi
    log "WARN: $name 的端口被临时占用，换到 STUN $ADDR / health $HEALTH 重试（$attempt/3）"
    for index in "${!args[@]}"; do
      args[index]="${args[index]//$old_addr/$ADDR}"
      args[index]="${args[index]//$old_health/$HEALTH}"
    done
  done
}

stop_server() {
  [[ -n "$SERVER_PID" ]] || return 0
  kill -TERM "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
}

wait_health() { # tries
  local tries="${1:-60}" attempt=0
  while (( attempt < tries )); do
    healthz_ok && return 0
    sleep 0.1
    attempt=$((attempt + 1))
  done
  return 1
}

# ---------- netem / MTU ----------

qdisc_show() { tc qdisc show dev lo 2>/dev/null; }

netem_available() {
  if ! command -v tc >/dev/null 2>&1; then
    NETEM_REASON="缺少 tc（iproute2）"
    return 1
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    NETEM_REASON="需要 root（tc netem 改 lo 的 qdisc；当前 uid=$(id -u)）"
    return 1
  fi
  if ! qdisc_show | grep -q "noqueue"; then
    NETEM_REASON="lo 上已有自定义 qdisc，拒绝覆盖：$(qdisc_show | head -1)"
    return 1
  fi
  return 0
}

netem_set() { # netem args...
  if ! tc qdisc replace dev lo root netem "$@" >"$LOG_DIR/tc.log" 2>&1; then
    return 1
  fi
  # 只删自己加的 qdisc：并行跑两个混沌脚本时，后来的那个会因「已有自定义 qdisc」SKIP，
  # 它的 exit trap 绝不能把前一个脚正在用的 netem 删掉（否则 C1 的丢包断言会假通过）。
  NETEM_OWNED=true
  return 0
}

netem_clear() {
  [[ "$NETEM_OWNED" == true ]] || return 0
  command -v tc >/dev/null 2>&1 || return 0
  if qdisc_show | grep -q "netem"; then
    tc qdisc del dev lo root >>"$LOG_DIR/tc.log" 2>&1 || true
  fi
  NETEM_OWNED=false
}

mtu_available() {
  command -v ip >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]
}

set_mtu() { # mtu
  local current
  current="$(ip link show lo | sed -n 's/.* mtu \([0-9]*\).*/\1/p' | head -1)"
  [[ -n "$current" ]] || return 1
  MTU_SAVED="$current"
  ip link set dev lo mtu "$1" >/dev/null 2>&1 || return 1
  return 0
}

restore_mtu() {
  [[ -n "$MTU_SAVED" ]] || return 0
  ip link set dev lo mtu "$MTU_SAVED" >/dev/null 2>&1 || true
  MTU_SAVED=""
}

# ---------- 探针 ----------

run_probe() { # mode args...
  # 探针输出同时落盘（`probe.log`）：断言失败时 summary 只记「探针失败」，
  # 真正的 FAIL/info 行在 stdout 上 —— 不落盘就没法事后定位（复核后补）。
  local rc
  python3 - "$@" <<'PY' | tee -a "$LOG_DIR/probe.log"
"""混沌探针：只用标准库（TURN 部分复用 rstun-turn-probe.py 的客户端）。"""

import importlib.util
import os
import random
import socket
import struct
import sys
import time
import urllib.request

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_PADDING = 0x0026

failures = 0


def ok(message):
    print(f"ok: {message}")


def fail(message):
    global failures
    failures += 1
    print(f"FAIL: {message}")


def info(message):
    print(f"info: {message}")


def transaction_id(seq):
    return struct.pack("!QI", int(time.time() * 1000) & 0xFFFFFFFF, seq)[-12:]


def attribute(attr_type, value):
    return struct.pack("!HH", attr_type, len(value)) + value + b"\0" * ((-len(value)) % 4)


def binding_request(transaction, padding=0):
    body = attribute(ATTR_PADDING, b"\0" * padding) if padding else b""
    return struct.pack("!HHI12s", BINDING_REQUEST, len(body), MAGIC, transaction) + body


def is_success(data):
    return len(data) >= 20 and struct.unpack("!H", data[:2])[0] == BINDING_SUCCESS


def parse_addr(text):
    host, _, port = text.rpartition(":")
    return host, int(port)


def bind_udp(ip="127.0.0.1"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, 0))
    return sock


def health(health_addr, tries=5):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://{health_addr}/healthz", timeout=2).read()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def metric(health_addr, key, tries=5):
    for _ in range(tries):
        try:
            text = urllib.request.urlopen(f"http://{health_addr}/metrics", timeout=3).read().decode()
        except OSError:
            time.sleep(0.2)
            continue
        for line in text.splitlines():
            if line.startswith(key + " "):
                try:
                    return float(line.split(" ")[-1])
                except ValueError:
                    return None
        return 0.0
    return None


def fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


# ---------- C1：丢包 ----------


def mode_loss(server_addr, count, attempts):
    server = parse_addr(server_addr)
    sock = bind_udp()
    sock.settimeout(0.15)
    delivered = 0
    first_try = 0
    for index in range(count):
        transaction = transaction_id(index + 1)
        got = False
        for attempt in range(attempts):
            sock.sendto(binding_request(transaction), server)
            deadline = time.monotonic() + 0.15
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    break
                if is_success(data) and data[8:20] == transaction:
                    got = True
                    if attempt == 0:
                        first_try += 1
                    break
            if got:
                break
        if got:
            delivered += 1
    sock.close()
    info(f"loss：首轮应答 {first_try}/{count}，重传后 {delivered}/{count}")
    if delivered == count:
        ok(f"重传后 {count}/{count} 全部成功（丢包被应用层重传吸收）")
    else:
        fail(f"重传 {attempts} 次仍有 {count - delivered} 个请求没有应答")
    if first_try >= count:
        fail(f"注入 10% 丢包后首轮仍然 {first_try}/{count} 全达：netem 没有生效，这组结论无效")
    else:
        ok(f"首轮丢了 {count - first_try} 个（netem 生效），重传能补齐")


# ---------- C2：乱序 / 重复 ----------


def mode_reorder(server_addr, count, window, health_addr):
    server = parse_addr(server_addr)
    # 抓不到 /metrics（None）与「计数为 0」必须区分：前者是抓取失败，后者是合法初值。
    ok_before_raw = metric(health_addr, 'rstun_requests_total{transport="udp",result="ok"}')
    sock = bind_udp()
    # 发送缓冲放大到 1 MB：netem 的 `delay 20ms` 会把 200 个 datagram 攒在 qdisc 里，
    # 期间它们仍记在 socket 的 sk_wmem_alloc 上。默认 ~212 KB 在系统内存紧张时会让
    # `sendto` 抛 ENOBUFS（实测一次失败里服务端只收到 108/200，客户端随即 traceback
    # 退出 —— check() 把非 0 退出记成「断言失败」，看起来像 C2 假红）。
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
    transactions = [transaction_id(index + 1) for index in range(count)]
    # 再按 1ms 间隔发（约 1000/s）：既降低在途字节（不会一次占满发送缓冲），也让
    # 服务端不必在 netem 的 20ms 延迟后一次性吞下整批（默认 UDP 接收缓冲 ~104 个 skb）。
    send_interval = 0.001
    next_send = time.monotonic()
    sent = 0
    refusals = 0
    while sent < len(transactions):
        try:
            sock.sendto(binding_request(transactions[sent]), server)
        except OSError as exc:
            # 内核暂时发不出去（ENOBUFS/EAGAIN）：退避重试，连续失败才判失败。
            refusals += 1
            if refusals > 50:
                fail(f"reorder：sendto 连续失败 {refusals} 次（{type(exc).__name__}: {exc}），"
                     f"只发出 {sent}/{count}")
                sock.close()
                return
            info(f"reorder：sendto 失败（{type(exc).__name__}: {exc}），5ms 后重试 {refusals}/50")
            time.sleep(0.005)
            continue
        sent += 1
        next_send += send_interval
        remaining = next_send - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    answers = {transaction: 0 for transaction in transactions}
    sock.settimeout(0.2)
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if is_success(data) and data[8:20] in answers:
            answers[data[8:20]] += 1
    sock.close()
    ok_after_raw = metric(health_addr, 'rstun_requests_total{transport="udp",result="ok"}')
    missing = [transaction for transaction, hits in answers.items() if hits == 0]
    total = sum(answers.values())
    worst = max(answers.values()) if answers else 0
    counters_ok = ok_before_raw is not None and ok_after_raw is not None
    server_ok = (ok_after_raw - ok_before_raw) if counters_ok else None
    served = f"{server_ok:.0f}" if counters_ok else "unknown"
    info(
        f"reorder：发送 {sent} 个请求，客户端收到 {total} 个应答"
        f"（覆盖 {count - len(missing)}/{count} 个事务），服务端 ok={served}"
    )
    if missing:
        info(f"reorder：未应答的事务数 = {len(missing)}")
    if missing:
        fail(f"{len(missing)}/{count} 个请求没有任何应答（乱序把应答弄丢了）")
    else:
        ok(f"{count}/{count} 个请求都拿到了应答")

    # 每个请求最多 4 个应答：netem 可能把**请求**复制一次（服务端答两次），
    # 又把每个**应答**复制一次（客户端各收两次）。再多就说明服务端自己在放大。
    if worst > 4:
        fail(f"单个请求被应答 {worst} 次（> 4，服务端在放大）")
    else:
        ok(f"单请求最多 {worst} 个应答（<= 4：请求复制 x 应答复制）")
    # 上界用整数运算（`count * 135 // 100`）：`200 * 1.15` 在浮点下是 229.999…，
    # 会把恰好 230 的合法结果判红。1.35x 也有统计学依据：请求复制 5% ⇒ 服务端
    # 收到的量 ≈ 1.05x，应答复制 5% ⇒ 客户端看到的量 ≈ 1.10x，方差主要来自泊松
    # 抽样（σ ≈ √220 ≈ 15），1.35x（≈ +3σ）留足余量，同时仍能抓住「服务端自己放大」。
    limit = count * 135 // 100
    if total > limit:
        fail(f"总应答 {total} > {limit}（{count} x 1.35，越过 3σ 上界）")
    else:
        ok(f"总应答 {total} <= {limit}（{count} x 1.35）")
    # 服务端只应答「收到的请求」：收到的量受 5% 请求复制影响，上界同为 1.35x。
    if not counters_ok:
        fail("reorder：抓不到 /metrics（netem 下 TCP 抓取失败），计数自洽无法判定")
    elif count <= server_ok <= limit:
        ok(f"服务端 ok={server_ok:.0f} 落在 [{count}, {limit}]（一个请求一个应答）")
    else:
        fail(f"服务端 ok={server_ok:.0f} 不在 [{count}, {limit}]（计数不自洽）")


# ---------- C3：大 datagram / 分片 ----------


def mode_mtu(server_addr, sizes):
    server = parse_addr(server_addr)
    sock = bind_udp()
    sock.settimeout(2.0)
    for size in sizes:
        transaction = transaction_id(size)
        request = binding_request(transaction, padding=size)
        sock.sendto(request, server)
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            fail(f"PADDING {size}：2s 内没有应答")
            continue
        if not is_success(data) or data[8:20] != transaction:
            fail(f"PADDING {size}：应答类型/transaction 不匹配")
            continue
        overhead = len(data) - len(request)
        ratio = len(data) / len(request)
        info(f"mtu：PADDING {size} 请求 {len(request)} 字节 -> 应答 {len(data)} 字节"
             f"（固定开销 {overhead}，放大 {ratio:.3f}x）")
        # 只允许两种形态：0（服务端不回显 PADDING，大请求的应答反而更小）或
        # 32（回显时固定多出 XOR-MAPPED-ADDRESS 的 32 字节）。其它值 = 有额外属性
        # 在放大，必须红。
        if overhead not in (0, 32):
            fail(f"PADDING {size}：响应比请求大出 {overhead} 字节（只允许 0 或固定 32 字节开销）")
        else:
            ok(f"PADDING {size}：响应开销 {overhead} 字节（允许 0/32），放大 {ratio:.3f}x")
    sock.close()


# ---------- C4 / C5：TCP 半包 / 半开 ----------


def mode_tcp_half(server_addr, pid, kind, budget):
    server = parse_addr(server_addr)
    before = fd_count(pid)
    stream = socket.create_connection(server, timeout=5)
    if kind == "half-frame":
        stream.sendall(b"\x00" * 10)  # 20 字节头只发一半，然后沉默
    stream.settimeout(budget)
    time.sleep(0.5)
    during = fd_count(pid)
    started = time.monotonic()
    closed = False
    try:
        data = stream.recv(4096)
        if data == b"":
            closed = True
        else:
            fail(f"{kind}：服务端竟然回了一个 {len(data)} 字节的响应（半个帧不该被应答）")
    except socket.timeout:
        pass
    except OSError:
        closed = True
    elapsed = time.monotonic() - started
    stream.close()
    time.sleep(0.5)
    after = fd_count(pid)

    if not closed:
        fail(f"{kind}：{budget}s 内容连接没有被回收（TCP_READ_TIMEOUT 没有生效）")
        return
    ok(f"{kind}：连接在 {elapsed:.1f}s 后被服务端关闭")
    if before is not None and during is not None and during <= before:
        info(f"{kind}：fd 观测 before={before} during={during}（期间采样可能落在关闭之后）")
    if before is not None and after is not None:
        if after <= before + 1:
            ok(f"{kind}：fd 从 {before} 回到 {after}（没有泄漏连接）")
        else:
            fail(f"{kind}：fd 没有回落：before={before} after={after}")


# ---------- C6：TURN 中继丢包 + 带宽配额 ----------


def load_turn_probe(path):
    spec = importlib.util.spec_from_file_location("rstun_turn_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mode_turn_loss(turn_probe_path, server_addr, user, password, realm, health_addr, burst, payload):
    import argparse

    module = load_turn_probe(turn_probe_path)
    args = argparse.Namespace(
        host=parse_addr(server_addr)[0],
        port=parse_addr(server_addr)[1],
        user=user,
        password=password,
        realm=realm,
        default_lifetime=600,
        lenient_refresh=True,
        timeout=3.0,
    )
    probe = module.Probe(args)
    dropped_before = metric(health_addr, 'rstun_turn_bytes_dropped_total{direction="in"}') or 0.0

    # 控制面也要重试：本用例故意在 5% 丢包的路径上跑，challenge / Allocate /
    # CreatePermission / ChannelBind 的请求或响应都可能被 netem 丢掉。
    def retry(label, fn, *fn_args):
        for attempt in range(10):
            try:
                return fn(*fn_args)
            except (TimeoutError, OSError) as exc:
                info(f"turn-loss：{label} 超时（{type(exc).__name__}），重试 {attempt + 1}/10")
                time.sleep(0.2)
        fail(f"turn-loss：{label} 连续 10 次超时")
        return None

    retry("challenge", probe.challenge)
    failures_before_allocate = probe.failures
    relayed = retry("allocate", probe.allocate)
    if relayed is None and probe.failures == failures_before_allocate + 1:
        # 首轮 Allocate 的响应丢了，重试换了新 tid → 服务端按 RFC 8656 回 437
        # （同一个 5 元组已有 allocation）。这恰好证明 allocation 存在，把探针
        # 记的失败抹掉，正确性交给下面的数据面断言。
        probe.failures = failures_before_allocate
        info("turn-loss：Allocate 重试命中 437（首轮响应被丢）—— allocation 已存在，继续")
    elif relayed is None:
        fail("turn-loss：Allocate 失败（不是 437，见上面的探针输出）")
        return

    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(0.5)
    peer_address = peer.getsockname()
    retry("create-permission", probe.create_permission, peer_address)
    retry("channel-bind", probe.channel_bind, peer_address)
    if probe.failures > failures_before_allocate:
        fail("turn-loss：CreatePermission/ChannelBind 没有成功，后面的数据面断言不可信")
        peer.close()
        probe.close()
        return

    # 一次性打出远超 --turn-bandwidth（20 KB/s）的流量：超配额的部分必须被丢并计数。
    body = b"x" * payload
    for _ in range(burst):
        probe.send_channel_data(body)
    time.sleep(0.3)
    delivered = 0
    while True:
        try:
            peer.recvfrom(65535)
            delivered += 1
        except socket.timeout:
            break
    info(f"turn-loss：突发 {burst} x {payload} 字节，peer 收到 {delivered} 个包（5% netem 丢包 + 配额丢包）")

    dropped_after = metric(health_addr, 'rstun_turn_bytes_dropped_total{direction="in"}') or 0.0
    if dropped_after > dropped_before:
        ok(f"turn-loss：配额丢包计数增长 {dropped_before:.0f} -> {dropped_after:.0f}")
    else:
        fail(f"turn-loss：bytes_dropped 没有增长（{dropped_before:.0f} -> {dropped_after:.0f}）")

    # allocation 必须存活：等桶回填后，小流量仍能从 client 到 peer（重试吸收 netem 丢包）。
    time.sleep(1.5)
    alive = False
    for _ in range(10):
        probe.send_channel_data(b"after-burst")
        try:
            data, _ = peer.recvfrom(65535)
        except socket.timeout:
            continue
        if data == b"after-burst":
            alive = True
            break
    if alive:
        ok("turn-loss：突发后 allocation 仍存活，小流量仍能中继")
    else:
        fail("turn-loss：突发后小流量再也到不了 peer（allocation 被配额打死了）")

    if health(health_addr):
        ok("turn-loss：/healthz 仍是 200")
    else:
        fail("turn-loss：/healthz 不再 200")
    peer.close()
    probe.close()


def main():
    if len(sys.argv) < 3:
        print("usage: probe MODE HEALTH ADDR ARGS...", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    if mode == "loss":
        mode_loss(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif mode == "reorder":
        mode_reorder(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), sys.argv[5])
    elif mode == "mtu":
        mode_mtu(sys.argv[2], [int(value) for value in sys.argv[3:]])
    elif mode == "tcp-half":
        mode_tcp_half(sys.argv[2], int(sys.argv[3]), sys.argv[4], float(sys.argv[5]))
    elif mode == "turn-loss":
        mode_turn_loss(
            sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5],
            sys.argv[6], sys.argv[7], int(sys.argv[8]), int(sys.argv[9]),
        )
    else:
        print(f"unknown mode: {mode}", file=sys.stderr)
        return 2
    return 1 if failures else 0


sys.exit(main())
PY
  rc=${PIPESTATUS[0]}
  return "$rc"
}

check() { # case mode args...
  local name="$1"
  shift
  if run_probe "$@"; then
    PASSED+=("$name")
    log "ok: $name（断言明细见上方 info/ok 行）"
  else
    fail "$name" "$name: 探针断言失败（上面有 FAIL 行）"
  fi
}

# ---------- 用例 ----------

case_loss() {
  local name="C1-loss"
  if ! netem_available; then
    skip "$name" "$NETEM_REASON"
    return
  fi
  start_server "$name" --listen "$ADDR" --health-listen "$HEALTH"
  if ! wait_health; then
    fail "$name" "服务没起来（见 $LOG_DIR/$name.log）"
    stop_server
    return
  fi
  netem_set loss 10% || {
    fail "$name" "tc qdisc 注入失败（见 $LOG_DIR/tc.log）"
    stop_server
    return
  }
  check "$name" loss "$ADDR" 300 8
  netem_clear
  if healthz_ok; then
    ok "$name：服务存活（/healthz 200）"
  else
    fail "$name：丢包注入后 /healthz 不是 200"
  fi
  stop_server
}

case_reorder() {
  local name="C2-reorder"
  if ! netem_available; then
    skip "$name" "$NETEM_REASON"
    return
  fi
  start_server "$name" --listen "$ADDR" --health-listen "$HEALTH"
  if ! wait_health; then
    fail "$name" "服务没起来"
    stop_server
    return
  fi
  netem_set delay 20ms reorder 25% 50% duplicate 5% || {
    fail "$name" "tc qdisc 注入失败（见 $LOG_DIR/tc.log）"
    stop_server
    return
  }
  check "$name" reorder "$ADDR" 200 3.0 "$HEALTH"
  # 记 qdisc 统计（dropped/overlimits）：事后能判断丢包发生在队列还是 socket 缓冲。
  tc -s qdisc show dev lo >>"$LOG_DIR/tc.log" 2>&1 || true
  netem_clear
  # 解析层没有被打乱：服务端没有把乱序/重复算成 malformed。
  # 读不到计数就是「无法判定」——不能算通过（空断言正是复核要消掉的东西）。
  local dropped
  dropped="$(metric 'rstun_requests_total{transport="udp",result="dropped"}')"
  if [[ -z "$dropped" ]]; then
    fail "$name：读不到 /metrics 的 dropped 计数（/metrics 不可用或缺少该 counter），计数自洽无法判定"
  elif python3 -c "import sys; sys.exit(0 if float('${dropped}') == 0 else 1)"; then
    ok "$name：服务端 dropped=0（乱序/重复没有被算成 malformed）"
  else
    fail "$name：服务端 dropped=$dropped（乱序/重复产生了 malformed）"
  fi
  stop_server
}

case_mtu() {
  local name="C3-mtu"
  if ! netem_available; then
    skip "$name" "$NETEM_REASON"
    return
  fi
  if [[ -n "$FORCE_MTU" ]]; then
    if ! mtu_available; then
      skip "$name" "缺少 ip 命令或非 root，无法把 lo MTU 降到 $FORCE_MTU"
      return
    fi
    if ! set_mtu "$FORCE_MTU"; then
      skip "$name" "改 lo MTU 失败"
      return
    fi
    log "$name：lo MTU 临时改为 $FORCE_MTU（退出时恢复 $MTU_SAVED）"
  else
    info "$name：lo MTU=$(ip link show lo 2>/dev/null | sed -n 's/.* mtu \([0-9]*\).*/\1/p')，未强制分片（加 --mtu 1500 才真的走 IP 分片）"
  fi
  start_server "$name" --listen "$ADDR" --health-listen "$HEALTH"
  if ! wait_health; then
    fail "$name" "服务没起来"
    stop_server
    return
  fi
  netem_set delay 5ms || {
    fail "$name" "tc qdisc 注入失败（见 $LOG_DIR/tc.log）"
    stop_server
    return
  }
  check "$name" mtu "$ADDR" 1400 8000
  netem_clear
  # MTU 是全局状态：本用例结束就恢复，不要让后续用例跑在 1500 上。
  restore_mtu
  if healthz_ok; then
    ok "$name：8000 字节 datagram 后服务仍存活"
  else
    fail "$name：大 datagram 后 /healthz 不是 200"
  fi
  stop_server
}

case_half_frame() {
  local name="C4-half-frame"
  start_server "$name" --listen "$ADDR" --tcp --health-listen "$HEALTH"
  if ! wait_health; then
    fail "$name" "服务没起来"
    stop_server
    return
  fi
  check "$name" tcp-half "$ADDR" "$SERVER_PID" half-frame 45
  stop_server
}

case_half_open() {
  local name="C5-half-open"
  start_server "$name" --listen "$ADDR" --tcp --health-listen "$HEALTH"
  if ! wait_health; then
    fail "$name" "服务没起来"
    stop_server
    return
  fi
  check "$name" tcp-half "$ADDR" "$SERVER_PID" half-open 45
  stop_server
}

case_turn_loss() {
  local name="C6-turn-loss"
  if ! netem_available; then
    skip "$name" "$NETEM_REASON"
    return
  fi
  if [[ ! -f "$ROOT/script/lab/rstun-turn-probe.py" ]]; then
    skip "$name" "缺少 script/lab/rstun-turn-probe.py"
    return
  fi
  start_server "$name" --listen "$ADDR" \
    --turn --realm "$REALM" --auth-secret "$SECRET" \
    --auth-user "$USER_NAME" --auth-pass "$USER_PASS" \
    --relay-ports "$RELAY_LO-$RELAY_HI" \
    --turn-bandwidth 20000 \
    --health-listen "$HEALTH"
  if ! wait_health; then
    fail "$name" "服务没起来（见 $LOG_DIR/$name.log）"
    stop_server
    return
  fi
  netem_set delay 2ms loss 5% || {
    fail "$name" "tc qdisc 注入失败（见 $LOG_DIR/tc.log）"
    stop_server
    return
  }
  check "$name" turn-loss "$ROOT/script/lab/rstun-turn-probe.py" "$ADDR" \
    "$USER_NAME" "$USER_PASS" "$REALM" "$HEALTH" 200 512
  netem_clear
  stop_server
}

# ---------- main ----------

if [[ "$BUILD" == true ]]; then
  log "== 构建 rstun（$PROFILE）"
  build_args=()
  [[ "$PROFILE" == "release" ]] && build_args+=(--release)
  if ! (cd "$ROOT" && cargo build "${build_args[@]}" >"$LOG_DIR/build.log" 2>&1); then
    echo "cargo build 失败（见 $LOG_DIR/build.log）" >&2
    exit 2
  fi
fi
if [[ ! -x "$BIN" ]]; then
  echo "找不到 $BIN（去掉 --no-build，或先 cargo build --release）" >&2
  exit 2
fi

log "== 混沌用例（基准端口 $PORT，日志 $LOG_DIR）"
log "磁盘：$(df -h "$WORK" 2>/dev/null | tail -1)"
log "netem: $(command -v tc >/dev/null 2>&1 && echo 可用 || echo 缺失)；uid=$(id -u)"

# 启动前先挑一对可绑端口（见 start_server 上面的注释）。
if ! pick_ports "$PORT"; then
  echo "从 $PORT 起 200 个候选端口都不可绑（UDP+TCP），换个 --port" >&2
  exit 2
fi
log "端口：STUN $ADDR（UDP，TCP 用例另绑）/ health $HEALTH"

run_case() { # name function
  if [[ -n "$ONLY" && "$ONLY" != "$1" ]]; then
    return
  fi
  log ""
  log "-- $1"
  "$2"
}

run_case loss case_loss
run_case reorder case_reorder
run_case mtu case_mtu
run_case half-frame case_half_frame
run_case half-open case_half_open
run_case turn-loss case_turn_loss

log ""
log "passed: ${#PASSED[@]}  failed: ${#FAILED[@]}  skipped: ${#SKIPPED[@]}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  log "结果：${#FAILED[@]} 项失败（${FAILED[*]}）"
  exit 1
fi
log "结果：全部通过（或按原因 SKIP）"
exit 0
