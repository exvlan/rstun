#!/usr/bin/env bash
#
# `rstun` 抗滥用对照矩阵：限速 / 全局限速 / 反射防护 / 名单 / TCP 洪水。
#
# 为什么需要它：「默认关闭时逐字节不变」有单测锁着，但**打开之后到底拦住了什么**
# 只能靠真实 socket 的对照实验：同一个请求，关掉开关要答、打开要丢；某个源被限
# 不能误伤另一个源；伪造源的小包不能换来一个大响应。这里把这几组对照固化成可重跑
# 的脚本，任何一项从 ok 变 FAIL 就说明准入逻辑变了。
#
# 用法：
#   bash script/lab/rstun-abuse.sh                 # 全部对照（默认端口基准 34880）
#   bash script/lab/rstun-abuse.sh --port 34881    # 平移端口
#   bash script/lab/rstun-abuse.sh --no-build      # 复用 target/debug/rstun
#   bash script/lab/rstun-abuse.sh --only reflect  # 只跑一组
#     （off|rate|global|reflect|reflect-strict|reflect-reject|allow|deny|inflight|tcp）
#   bash script/lab/rstun-abuse.sh --keep          # 保留日志（默认就保留，只清进程）
#
# 不需要 root / NET_RAW：多源用 `127.0.0.0/8` 里的**不同源地址**模拟（Linux/macOS
# 整段都是本机），而不是伪造 IP。所以本脚本能证明「每 IP 桶按源地址分桶」，但
# **不能**证明真实公网伪造源下的行为 —— 那条只有反射防护（请求尺寸 + 放大比）能挡，
# 也正是它独立存在的原因。真实伪造源压测需要 raw socket / 专门工具，标注为可选。
#
# 退出码：0 = 全部 ok；1 = 至少一项 FAIL；2 = 参数/环境错误。
# 日志：$RSTUN_ABUSE_DIR（默认 /tmp/opencode/rstun-abuse），每组一个 .log。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/debug/rstun"
WORK="${RSTUN_ABUSE_DIR:-/tmp/opencode/rstun-abuse}"
LOG_DIR="$WORK/logs"

PORT=34880
BUILD=true
ONLY=""

PIDS=()
FAILED=()
SERVER_PID=""

usage() {
  sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="${2:?--port 需要一个端口}"; shift ;;
    --port=*) PORT="${1#*=}" ;;
    --no-build) BUILD=false ;;
    --only) ONLY="${2:?--only 需要一组名字}"; shift ;;
    --only=*) ONLY="${1#*=}" ;;
    --keep) : ;;
    -h | --help) usage; exit 0 ;;
    *)
      echo "未知参数: $1（--help 看用法）" >&2
      exit 2
      ;;
  esac
  shift
done

if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  echo "--port 需要整数，收到: $PORT" >&2
  exit 2
fi
if [[ "$PORT" == "3478" ]]; then
  echo "不要用 3478（STUN 标准端口，容易撞上本机正在跑的服务）；给个高位端口" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "需要 python3（只用标准库）" >&2
  exit 2
fi
# `--only` 必须是已知组名：打错名字时不能「跑了 0 组 + 全部通过」。
if [[ -n "$ONLY" ]]; then
  case "$ONLY" in
    off | rate | global | reflect | reflect-strict | reflect-reject | allow | deny | inflight | tcp) : ;;
    *)
      echo "--only 未知组: $ONLY（可用：off|rate|global|reflect|reflect-strict|reflect-reject|allow|deny|inflight|tcp）" >&2
      exit 2
      ;;
  esac
fi
export PYTHONIOENCODING=utf-8

mkdir -p "$LOG_DIR"

log() { printf '%s\n' "$*"; }
ok() { log "ok: $*"; }
fail() {
  FAILED+=("$1")
  log "FAIL: $2"
}

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# ---------- 服务生命周期 ----------

start_server() { # name args...
  local name="$1"
  shift
  "$BIN" server "$@" >"$LOG_DIR/$name.log" 2>&1 &
  SERVER_PID=$!
  PIDS+=("$SERVER_PID")
}

stop_server() {
  [[ -n "$SERVER_PID" ]] || return 0
  kill -TERM "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  SERVER_PID=""
}

server_addr() { echo "127.0.0.1:$PORT"; }

# 退出统计里的某个计数（没有该行时按 0 计）。
# 日志带 ANSI 颜色（tracing 默认开），字段之间夹着转义序列，先去掉再 grep。
counter() { # name field
  # 字段边界必须精确：`dropped` 不能命中 `inflight_dropped=`（两者都在统计行里）。
  local value
  value="$(
    sed -E 's/\x1B\[[0-9;]*m//g' "$LOG_DIR/$1.log" 2>/dev/null |
      grep -oE "(^|[[:space:]])$2=[0-9]*" | tail -1 | cut -d= -f2
  )"
  echo "${value:-0}"
}

assert_counter() { # name field min
  local value
  value="$(counter "$1" "$2")"
  if [[ "$value" -ge "$3" ]]; then
    ok "$1: $2=$value (>= $3)"
  else
    fail "$1" "$1: $2=$value (< $3)：准入没有生效或没有被计数"
  fi
}

# 每个探针内部都有自己的 socket 超时（collect 的窗口 / connect 的 timeout），
# 不依赖 coreutils 的 `timeout`（macOS 默认没有），所以这里直接跑 python。
run_probe() { # mode args...
  python3 - "$@" <<'PY'
"""只用标准库的 STUN 客户端：这脚本要的是「真实 socket 上的行为」，不是协议合规。"""

import random
import socket
import struct
import sys

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_CHANGE_REQUEST = 0x0003
ATTR_ERROR_CODE = 0x0009
ATTR_PADDING = 0x0026
ATTR_PRIORITY = 0x0024
ATTR_RESPONSE_PORT = 0x0027
ATTR_SOFTWARE = 0x8022

failures = 0


def ok(message):
    print(f"ok: {message}")


def fail(message):
    global failures
    failures += 1
    print(f"FAIL: {message}")


def info(message):
    print(f"info: {message}")


def transaction_id():
    return bytes(random.getrandbits(8) for _ in range(12))


def header(msg_type, body):
    return struct.pack("!HHI12s", msg_type, len(body), MAGIC, transaction_id()) + body


def attribute(attr_type, value):
    padding = (-len(value)) % 4
    return struct.pack("!HH", attr_type, len(value)) + value + b"\x00" * padding


def plain_request():
    return header(BINDING_REQUEST, b"")


def response_port_request(port, size=28):
    """28 字节 = 最小可携带 RESPONSE-PORT 的请求；40 字节 = 清过默认最小尺寸。"""
    body = attribute(ATTR_RESPONSE_PORT, struct.pack("!H", port))
    if size == 40:
        body += attribute(ATTR_PRIORITY, b"\x00" * 4) + attribute(ATTR_SOFTWARE, b"")
    assert len(body) == size - 20, (size, len(body))
    return header(BINDING_REQUEST, body)


def is_success(data):
    return len(data) >= 20 and struct.unpack("!H", data[:2])[0] == BINDING_SUCCESS


def parse_addr(text):
    host, port = text.rsplit(":", 1)
    return (host.strip("[]"), int(port))


def collect(sock, window):
    """收集 `window` 秒内到达的包：[(bytes, from)]。"""
    received = []
    sock.settimeout(window)
    while True:
        try:
            data, source = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            break
        received.append((data, source))
    return received


def successes(packets):
    return [data for data, _ in packets if is_success(data)]


def bind_source(source_ip):
    family = socket.AF_INET6 if ":" in source_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((source_ip, 0))
    return sock


def mode_basic(server, source, software="any"):
    sock = bind_source(source)
    sock.sendto(plain_request(), server)
    packets = collect(sock, 2.0)
    answered = successes(packets)
    if not answered:
        fail(f"basic：{source} 没有收到 Binding Success（收到 {len(packets)} 个包）")
        return
    response = answered[0]
    if software != "any" and has_software(response) != (software == "yes"):
        fail(
            f"basic：SOFTWARE 期望 {'有' if software == 'yes' else '无'}，"
            f"实际属性 {[hex(t) for t in attribute_types(response)]}"
        )
        return
    ok(
        f"basic：{source} 收到 Binding Success（{len(response)} 字节，"
        f"SOFTWARE {'有' if has_software(response) else '无'}）"
    )


def mode_flood(server, source, count, minimum, maximum):
    sock = bind_source(source)
    for _ in range(count):
        sock.sendto(plain_request(), server)
    answered = len(successes(collect(sock, 2.0)))
    info(f"flood：{source} 发 {count} 个请求，得到 {answered} 个响应")
    if answered < minimum:
        fail(f"flood：只回了 {answered} 个，少于下界 {minimum}")
    elif answered > maximum:
        fail(f"flood：回了 {answered} 个，超过上界 {maximum}（限速没生效）")
    else:
        ok(f"flood：{answered} 个响应落在 [{minimum}, {maximum}]")


def allowed_response_len(request_len, ratio):
    """与服务端同一条规则：max(len x ratio, len + 32)。

    32 = 每个重定向响应都要带的固定属性（XOR-MAPPED-ADDRESS 12，以及
    --alt-listen 下的 RESPONSE-ORIGIN + OTHER-ADDRESS 24）；SOFTWARE 是可选属性，
    小请求会被省略，所以不计入余量。
    """
    return max(request_len * ratio, request_len + 32)


def attribute_types(data):
    """响应里的属性类型列表（用于断言 SOFTWARE 在不在）。"""
    if len(data) < 20:
        return []
    body = data[20 : 20 + struct.unpack("!H", data[2:4])[0]]
    types = []
    offset = 0
    while offset + 4 <= len(body):
        attr_type, length = struct.unpack("!HH", body[offset : offset + 4])
        types.append(attr_type)
        offset += 4 + ((length + 3) // 4) * 4
    return types


def has_software(data):
    return ATTR_SOFTWARE in attribute_types(data)


def error_code(data):
    """ERROR-CODE 里的错误码（400 / 420 …），没有该属性时为 0。"""
    if len(data) < 20:
        return 0
    body = data[20 : 20 + struct.unpack("!H", data[2:4])[0]]
    offset = 0
    while offset + 4 <= len(body):
        attr_type, length = struct.unpack("!HH", body[offset : offset + 4])
        value = body[offset + 4 : offset + 4 + length]
        if attr_type == ATTR_ERROR_CODE and len(value) >= 4:
            return value[2] * 100 + value[3]
        offset += 4 + ((length + 3) // 4) * 4
    return 0


def mode_reflect(server, source, size, expect, ratio, software):
    """RESPONSE-PORT 反射：请求很小，响应去找「源 IP + 指定端口」。

    expect=success → 应当被放行：必须在**目标口**拿到 Binding Success，真实字节数
                     落在 `max(len x ratio, len + 32)` 之内，且 SOFTWARE 的有无与
                     `software`（yes/no）一致 —— 断言，不是打印；
    expect=none    → 应当被拒绝：两个口都拿不到 Binding Success，且目标口**0 个包**
                     （拒绝不能变成「把 400 发到受害者口上」）。
    """
    ratio = float(ratio)
    request_sock = bind_source(source)
    inbox = bind_source(source)  # RESPONSE-PORT 的落点：同源 IP、另一个端口
    port = inbox.getsockname()[1]
    request = response_port_request(port, size=size)
    limit = allowed_response_len(len(request), ratio)
    request_sock.sendto(request, server)
    at_request = collect(request_sock, 1.0)
    at_inbox = collect(inbox, 1.0)
    total = len(at_request) + len(at_inbox)
    info(
        f"reflect：请求 {len(request)} 字节（RESPONSE-PORT -> {port}），ratio={ratio}，"
        f"允许响应 <= {limit:.0f} 字节；请求口 {len(at_request)} 包、目标口 {len(at_inbox)} 包"
    )
    got_success = successes(at_inbox) + successes(at_request)
    if expect == "success":
        if not got_success:
            fail("reflect：应被处理的请求没有拿到响应（误伤）")
            return
        response = got_success[0]
        arrived_on_inbox = bool(successes(at_inbox))
        if not arrived_on_inbox:
            fail("reflect：Binding Success 没有落在 RESPONSE-PORT 指定的目标口上")
        if len(response) > limit:
            fail(
                f"reflect：响应 {len(response)} 字节超过允许的 {limit:.0f} 字节"
                f"（放大比 {len(response) / len(request):.2f}）"
            )
        elif has_software(response) != (software == "yes"):
            fail(
                f"reflect：SOFTWARE 期望 {'有' if software == 'yes' else '无'}，"
                f"实际属性 {[hex(t) for t in attribute_types(response)]}"
            )
        else:
            ok(
                f"reflect：{len(request)} 字节请求 -> {len(response)} 字节响应"
                f"（放大比 {len(response) / len(request):.2f}，允许 {limit:.0f}，"
                f"SOFTWARE {'有' if software == 'yes' else '无'}）"
            )
    else:
        if got_success:
            fail("reflect：伪造源形态的请求仍然拿到了 Binding Success")
        elif len(at_inbox) != 0:
            fail(f"reflect：拒绝时目标口仍收到 {len(at_inbox)} 个包（拒绝本身在放大）")
        elif total == 0:
            ok("reflect：请求被静默丢弃（连 400 都没有，目标口 0 包）")
        else:
            refusal = at_request[0][0]
            strict = len(request) * ratio
            if len(refusal) > strict:
                fail(
                    f"reflect：拒绝用了 {len(refusal)} 字节 > 请求 {len(request)} x {ratio}"
                    f"（拒绝本身在放大）"
                )
            else:
                info(f"reflect：收到 {len(refusal)} 字节的 400，目标口 0 包")
                ok("reflect：请求没有拿到 Binding Success，拒绝也没有放大")


def mode_reject(server, source, alt, ratio):
    """确实会被拒的用例：`CHANGE-REQUEST` + `PADDING`，让响应超过允许值。

    40 字节请求（`CHANGE-REQUEST` 8 + `PADDING 8` 12 + 头 20）在 --alt-listen 下
    本来会得到 `20 + 12 + SOFTWARE 20 + 12 + 12 + PADDING 12 = 88` 字节，而
    `max(40 x 2, 40 + 32) = 80`，所以必须被拒。

    expect: 拒绝报文（400）只能来自入口地址、长度 <= allowed；重定向目标地址
    （alt）**0 个包**；不能出现 Binding Success。
    """
    ratio = float(ratio)
    request_sock = bind_source(source)
    request = header(
        BINDING_REQUEST,
        attribute(ATTR_CHANGE_REQUEST, struct.pack("!I", 0x02))
        + attribute(ATTR_PADDING, b"\x00" * 8),
    )
    limit = allowed_response_len(len(request), ratio)
    info(f"reject：请求 {len(request)} 字节（CHANGE-REQUEST + PADDING 8），ratio={ratio}，允许 <= {limit:.0f}")
    request_sock.sendto(request, server)
    packets = collect(request_sock, 1.0)
    if successes(packets):
        fail("reject：应当被拒的请求拿到了 Binding Success")
        return
    if any(source_addr == alt for _, source_addr in packets):
        fail("reject：拒绝报文来自重定向目标地址（说明请求被当成合法探针处理了）")
        return
    if not packets:
        fail("reject：没有收到 400（静默丢弃也算拒绝，但这里期望可观测的 400）")
        return
    data, source_addr = packets[0]
    if source_addr != server:
        fail(f"reject：400 来自 {source_addr}，不是入口 {server}")
        return
    code = error_code(data)
    if len(data) > limit:
        fail(f"reject：400 用了 {len(data)} 字节，超过允许的 {limit:.0f}（拒绝本身在放大）")
    elif code != 400:
        fail(f"reject：期望 400，收到 {code}")
    else:
        ok(
            f"reject：{len(request)} 字节探针被拒（{len(data)} 字节的 400 <= {limit:.0f}），"
            f"重定向目标 {alt} 收到 0 个包"
        )


def mode_tcp_flood(server, count, concurrency):
    import threading

    results = {"ok": 0, "err": 0}
    lock = threading.Lock()

    def worker(rounds):
        for _ in range(rounds):
            try:
                with socket.create_connection(server, timeout=5) as stream:
                    stream.sendall(plain_request())
                    data = stream.recv(4096)
                with lock:
                    if is_success(data):
                        results["ok"] += 1
                    else:
                        results["err"] += 1
            except OSError:
                with lock:
                    results["err"] += 1

    rounds = count // concurrency + 1
    threads = [threading.Thread(target=worker, args=(rounds,)) for _ in range(concurrency)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    total = results["ok"] + results["err"]
    info(f"tcp-flood：{total} 次连接，成功 {results['ok']}，失败 {results['err']}")
    if results["ok"] >= total * 0.9:
        ok("tcp-flood：绝大多数连接被正常应答，进程没有被洪水打死")
    else:
        fail(f"tcp-flood：只有 {results['ok']}/{total} 成功，服务可能已经被拖垮")


def mode_tcp_sequential(server, count, maximum):
    """一条连接上连发 count 条请求；超限后服务端应直接关连接（不是回 486）。"""
    answered = 0
    closed = False
    try:
        with socket.create_connection(server, timeout=5) as stream:
            stream.settimeout(2.0)
            for _ in range(count):
                stream.sendall(plain_request())
                try:
                    data = stream.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    closed = True
                    break
                if is_success(data):
                    answered += 1
    except OSError:
        closed = True
    info(f"tcp-sequential：{answered} 条被应答，连接{'已' if closed else '未'}被关闭")
    if 1 <= answered <= maximum:
        ok(f"tcp-sequential：应答 {answered} 条（<= {maximum}），超限后不再服务")
    else:
        fail(f"tcp-sequential：应答 {answered} 条，超出 [1, {maximum}]")


def main():
    if len(sys.argv) < 4:
        print("usage: probe MODE SERVER ARGS...", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    server = parse_addr(sys.argv[2])
    arguments = sys.argv[3:]
    if mode == "basic":
        mode_basic(server, arguments[0], *arguments[1:2])
    elif mode == "flood":
        mode_flood(server, arguments[0], int(arguments[1]), int(arguments[2]), int(arguments[3]))
    elif mode == "reflect":
        mode_reflect(
            server, arguments[0], int(arguments[1]), arguments[2], arguments[3], arguments[4]
        )
    elif mode == "reject":
        mode_reject(server, arguments[0], parse_addr(arguments[1]), arguments[2])
    elif mode == "tcp-flood":
        mode_tcp_flood(server, int(arguments[0]), int(arguments[1]))
    elif mode == "tcp-sequential":
        mode_tcp_sequential(server, int(arguments[0]), int(arguments[1]))
    else:
        print(f"unknown mode: {mode}", file=sys.stderr)
        return 2
    return 1 if failures else 0


sys.exit(main())
PY
}

# 断言型探针：失败要在汇总里记一笔（`wait_ready` 用的是不带断言的 run_probe）。
check() { # case-name mode args...
  local name="$1"
  shift
  run_probe "$@" || fail "$name" "$name: 探针断言失败（上面有 FAIL 行）"
}

# 等服务真能应答。源地址用 127.0.0.9，避免消耗被测源（.1/.2）的令牌。
wait_ready() { # server-address
  local address="$1" attempt
  for attempt in $(seq 1 40); do
    if run_probe basic "$address" 127.0.0.9 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# ---------- 对照组 ----------

# A：关掉全部开关 —— 限速不生效、反射形态能成功（这就是「要防什么」的基线）。
case_off() {
  local name="00-off" addr
  addr="$(server_addr)"
  start_server "$name" --listen "$addr"
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来（见 $LOG_DIR/$name.log）"
    stop_server
    return
  fi
  check "$name" flood "$addr" 127.0.0.1 100 90 100
  check "$name" basic "$addr" 127.0.0.1 yes
  # 没有防护时 28 字节探针照旧带 SOFTWARE（52 字节，与 26.410.100 一致）。
  check "$name" reflect "$addr" 127.0.0.1 28 success 2 yes
  stop_server
  if [[ "$(counter "$name" rate_limited_ip)" != "0" ]]; then
    fail "$name" "$name: 没开限速却出现 rate_limited_ip 计数"
  else
    ok "$name: 退出统计里没有限速计数"
  fi
}

# B：每源 IP 限速 —— 一个源被限，另一个源照常。
case_rate() {
  local name="10-rate-limit" addr
  addr="$(server_addr)"
  start_server "$name" --listen "$addr" --rate-limit 5 --rate-burst 10
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" flood "$addr" 127.0.0.1 300 1 40
  check "$name" basic "$addr" 127.0.0.2
  stop_server
  assert_counter "$name" rate_limited_ip 1
}

# C：全局限速 —— 与源地址无关，总量封顶。
case_global() {
  local name="20-global-rate" addr source
  addr="$(server_addr)"
  start_server "$name" --listen "$addr" --global-rate 5
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  for source in 127.0.0.3 127.0.0.4 127.0.0.5; do
    check "$name" flood "$addr" "$source" 100 0 40
  done
  stop_server
  assert_counter "$name" rate_limited_global 1
}

# D：反射防护的默认值（min 20 / ratio 2.0）——
#   * 无 alt-listen：28 字节探针 -> 32 字节（1.14x，**无 SOFTWARE**）
#   * 有 alt-listen：28 字节探针 -> 56 字节（2.00x，仍**无 SOFTWARE**）
#   * 普通 20 字节 Binding 保持 SOFTWARE（不误伤、字节不变）
# 只给 `--reflect-ratio`，min 用默认值（20），所以这组同时锁住「默认 min 不会退回到 40」。
case_reflect() {
  local name="30-reflect-defaults" alt_name="31-reflect-alt" addr alt_addr
  addr="$(server_addr)"
  start_server "$name" --listen "$addr" --reflect-ratio 2
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" basic "$addr" 127.0.0.1 yes
  check "$name" reflect "$addr" 127.0.0.1 28 success 2 no
  stop_server
  assert_counter "$name" reflect_rejected 0

  alt_addr="127.0.0.2:$PORT"
  start_server "$alt_name" --listen "$addr" --alt-listen "$alt_addr" --alt-port "$((PORT + 1))" --reflect-ratio 2
  if ! wait_ready "$addr"; then
    fail "$alt_name" "$alt_name: 服务没起来"
    stop_server
    return
  fi
  # 56 字节 = 20 头 + XOR 12 + RESPONSE-ORIGIN 12 + OTHER-ADDRESS 12（无 SOFTWARE）。
  check "$alt_name" reflect "$addr" 127.0.0.1 28 success 2 no
  # 40 字节的合法探针 >= 门槛：仍带 SOFTWARE（76 字节，1.90x）。
  check "$alt_name" reflect "$addr" 127.0.0.1 40 success 2 yes
  stop_server
  assert_counter "$alt_name" reflect_rejected 0
}

# E：调高尺寸门槛（--reflect-min-request 40）—— 28 字节探针被拒且目标口 0 包，
# 40 字节合法探针仍然放行（拒绝不误伤合格请求）。
case_reflect_strict() {
  local name="31-reflect-strict" addr
  addr="$(server_addr)"
  start_server "$name" --listen "$addr" --reflect-min-request 40
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" reflect "$addr" 127.0.0.1 28 none 2 no
  check "$name" reflect "$addr" 127.0.0.1 40 success 2 yes
  stop_server
  assert_counter "$name" reflect_rejected 1
}

# E2：防护必须真的能拒 —— `CHANGE-REQUEST` + `PADDING 8`（40 字节）在
# --alt-listen 下本来会得到 88 字节（76 + 12），超过 max(80, 72) = 80，必须被拒：
# 只能收到入口地址发来的 400（<= allowed），重定向目标地址 0 个包。
case_reflect_reject() {
  local name="32-reflect-reject" addr alt_addr
  addr="$(server_addr)"
  alt_addr="127.0.0.2:$((PORT + 1))"
  start_server "$name" --listen "$addr" --alt-listen "127.0.0.2:$PORT" --alt-port "$((PORT + 1))" --reflect-ratio 2
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" reject "$addr" 127.0.0.1 "$alt_addr" 2
  check "$name" basic "$addr" 127.0.0.1 yes
  stop_server
  assert_counter "$name" reflect_rejected 1
  assert_counter "$name" dropped 1
}

# F：--max-inflight 必须在 UDP 上真的生效（曾因串行 receive 循环空转）。
case_inflight() {
  local name="35-inflight" addr
  addr="$(server_addr)"
  start_server "$name" --listen "$addr" --max-inflight 1
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" flood "$addr" 127.0.0.1 300 0 299
  check "$name" basic "$addr" 127.0.0.2
  stop_server
  assert_counter "$name" inflight_dropped 1
}

# F：--allow 跳过每源限速（NAT 后整段放行的场景）。
case_allow() {
  local name="40-allow" addr
  addr="$(server_addr)"
  start_server "$name" --listen "$addr" --rate-limit 1 --rate-burst 1 --allow 127.0.0.1/32
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" flood "$addr" 127.0.0.1 30 25 30
  check "$name" flood "$addr" 127.0.0.2 30 0 6
  stop_server
  assert_counter "$name" allowlisted 20
}

# G：--deny 直接拒绝（最长前缀；allow/deny 同时命中时 deny 赢）。
case_deny() {
  local name="50-deny" addr
  addr="$(server_addr)"
  start_server "$name" --listen "$addr" --deny 127.0.0.1/32
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" flood "$addr" 127.0.0.1 20 0 0
  check "$name" basic "$addr" 127.0.0.2
  stop_server
  assert_counter "$name" denied 1
}

# H：TCP 洪水 + 在途上限 + 请求级限速（超限直接关连接）。
case_tcp() {
  local name="60-tcp" addr limited="61-tcp-rate"
  addr="$(server_addr)"
  # 只开在途上限：这里验的是「洪水下进程存活、连接仍被应答」，限速另有专组。
  start_server "$name" --listen "$addr" --tcp --max-inflight 64
  if ! wait_ready "$addr"; then
    fail "$name" "$name: 服务没起来"
    stop_server
    return
  fi
  check "$name" tcp-flood "$addr" 200 32
  stop_server

  start_server "$limited" --listen "$addr" --tcp --rate-limit 5 --rate-burst 5
  if ! wait_ready "$addr"; then
    fail "$limited" "$limited: 服务没起来"
    stop_server
    return
  fi
  check "$limited" tcp-sequential "$addr" 20 8
  stop_server
  assert_counter "$limited" rate_limited_ip 1
}

# ---------- main ----------

if [[ "$BUILD" == true ]]; then
  log "== 构建 rstun（debug）"
  if ! (cd "$ROOT" && cargo build 2>&1 | tail -3); then
    echo "cargo build 失败" >&2
    exit 2
  fi
fi
if [[ ! -x "$BIN" ]]; then
  echo "找不到 $BIN（去掉 --no-build，或先 cargo build）" >&2
  exit 2
fi

log "== 抗滥用对照（基准端口 $PORT，日志 $LOG_DIR）"

run_case() { # name function
  if [[ -n "$ONLY" && "$ONLY" != "$1" ]]; then
    return
  fi
  log ""
  log "-- $1"
  "$2"
}

run_case off case_off
run_case rate case_rate
run_case global case_global
run_case reflect case_reflect
run_case reflect-strict case_reflect_strict
run_case reflect-reject case_reflect_reject
run_case allow case_allow
run_case deny case_deny
run_case inflight case_inflight
run_case tcp case_tcp

log ""
if [[ ${#FAILED[@]} -gt 0 ]]; then
  log "结果：${#FAILED[@]} 项失败（${FAILED[*]}）"
  exit 1
fi
log "结果：全部通过"
exit 0
