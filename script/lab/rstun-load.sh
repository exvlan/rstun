#!/usr/bin/env bash
#
# `rstun` 黑盒压测：UDP Binding 吞吐 / 延迟分位（单源与多源）、TCP 连接洪水与
# 首字节延迟、以及**限速开/关对照**。
#
# 为什么是黑盒：`rstun` 是 bin-only crate，函数级基准要先把 `src/lib.rs` 抽出来
# （结构性改动，会动 main.rs 与全部测试的可见性）。本脚本走真 socket，量的是
# 「真实进程收发包」的结果 —— 与 `rstun-abuse.sh` 的取舍一致。设计说明见
# `.trellis/tasks/11-19-rstun-qa/design.md` §2 与 `docs/perf.md`。
#
# 用法：
#   bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000
#   bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 2000 --rate-limit 1000
#   bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000 --sources 8
#   bash script/lab/rstun-load.sh --mode tcp --duration 5 --rate 200 --concurrency 32
#   bash script/lab/rstun-load.sh --mode udp --json > result.json
#
# 参数：
#   --mode udp|tcp        压测模式（默认 udp）
#   --rate N              udp = 请求/秒；tcp = 连接/秒（默认 5000 / 200）
#   --duration S          持续秒数（默认 10）
#   --sources S           UDP 源地址个数（127.0.0.1..127.0.0.S，默认 1）
#   --concurrency C       TCP 并发连接数（默认 32）
#   --rate-limit N        给服务端加 `--rate-limit N`（每源 IP 桶）；用来做开/关对照
#   --global-rate N       给服务端加 `--global-rate N`
#   --profile release|debug   被测二进制（默认 release：这是性能工具）
#   --debug               等价于 --profile debug
#   --port N              监听端口（默认 35080；health 用 N+1）
#   --no-build            复用已有二进制（默认会构建）
#   --json                只把 JSON 打到 stdout（人读表格进日志/ stderr）
#   --out FILE            另存 JSON 到文件
#   --server-arg ARG      追加一个服务端参数（可重复，如 --server-arg=--tcp）
#   --keep                保留日志（默认就保留，只清进程）
#
# 断言（不是打印）：
#   udp 无 --rate-limit：应答率 >= 95%，服务端 `dropped` 与 `rate_limited_ip` 均为 0；
#   udp 有 --rate-limit：`rate_limited_ip` 增长，应答率落在 [30%, 85%]（客户端 2x 桶速率时）；
#   tcp：成功连接率 >= 90%，洪水后 fd 回落到基线附近，进程仍存活。
# 任一断言失败 → exit 1；参数/环境错误 → exit 2。
#
# 依赖：cargo/rustc（本仓）、python3（只用标准库）。不需要 root。
# 日志：$RSTUN_LOAD_DIR（默认 /tmp/opencode/rstun-load），每次运行一个子目录。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${RSTUN_LOAD_DIR:-/tmp/opencode/rstun-load}"

MODE="udp"
RATE=""
DURATION=10
SOURCES=1
CONCURRENCY=32
RATE_LIMIT=""
GLOBAL_RATE=""
PROFILE="release"
PORT=35080
BUILD=true
JSON_ONLY=false
OUT=""
SERVER_ARGS=()

usage() {
  sed -n '2,43p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:?--mode 需要 udp 或 tcp}"; shift ;;
    --mode=*) MODE="${1#*=}" ;;
    --rate) RATE="${2:?--rate 需要一个整数}"; shift ;;
    --rate=*) RATE="${1#*=}" ;;
    --duration) DURATION="${2:?--duration 需要秒数}"; shift ;;
    --duration=*) DURATION="${1#*=}" ;;
    --sources) SOURCES="${2:?--sources 需要源个数}"; shift ;;
    --sources=*) SOURCES="${1#*=}" ;;
    --concurrency) CONCURRENCY="${2:?--concurrency 需要并发数}"; shift ;;
    --concurrency=*) CONCURRENCY="${1#*=}" ;;
    --rate-limit) RATE_LIMIT="${2:?--rate-limit 需要一个速率}"; shift ;;
    --rate-limit=*) RATE_LIMIT="${1#*=}" ;;
    --global-rate) GLOBAL_RATE="${2:?--global-rate 需要一个速率}"; shift ;;
    --global-rate=*) GLOBAL_RATE="${1#*=}" ;;
    --profile) PROFILE="${2:?--profile 需要 release 或 debug}"; shift ;;
    --profile=*) PROFILE="${1#*=}" ;;
    --debug) PROFILE="debug" ;;
    --port) PORT="${2:?--port 需要一个端口}"; shift ;;
    --port=*) PORT="${1#*=}" ;;
    --no-build) BUILD=false ;;
    --json) JSON_ONLY=true ;;
    --out) OUT="${2:?--out 需要文件路径}"; shift ;;
    --out=*) OUT="${1#*=}" ;;
    --server-arg) SERVER_ARGS+=("${2:?--server-arg 需要一个参数}"); shift ;;
    --server-arg=*) SERVER_ARGS+=("${1#*=}") ;;
    --keep) : ;;
    -h | --help) usage; exit 0 ;;
    *)
      echo "未知参数: $1（--help 看用法）" >&2
      exit 2
      ;;
  esac
  shift
done

case "$MODE" in
  udp) [[ -n "$RATE" ]] || RATE=5000 ;;
  tcp) [[ -n "$RATE" ]] || RATE=200 ;;
  *)
    echo "--mode 只能是 udp 或 tcp，收到: $MODE" >&2
    exit 2
    ;;
esac

case "$PROFILE" in
  release) BIN="$ROOT/target/release/rstun" ;;
  debug) BIN="$ROOT/target/debug/rstun" ;;
  *)
    echo "--profile 只能是 release 或 debug，收到: $PROFILE" >&2
    exit 2
    ;;
esac

for pair in "rate:$RATE" "duration:$DURATION" "sources:$SOURCES" "concurrency:$CONCURRENCY" "port:$PORT"; do
  name="${pair%%:*}"
  value="${pair#*:}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "--$name 需要非负整数，收到: $value" >&2
    exit 2
  fi
done
if [[ "$RATE" -le 0 || "$DURATION" -le 0 ]]; then
  echo "--rate 与 --duration 必须大于 0" >&2
  exit 2
fi
if [[ "$SOURCES" -lt 1 || "$SOURCES" -gt 250 ]]; then
  echo "--sources 必须在 1..250（127.0.0.0/8 里的源地址）" >&2
  exit 2
fi
if [[ "$PORT" == "3478" || "$PORT" -le 1024 ]]; then
  echo "不要用 3478/特权端口（容易撞上本机服务）；给个高位端口" >&2
  exit 2
fi
for value in "$RATE_LIMIT" "$GLOBAL_RATE"; do
  if [[ -n "$value" ]] && ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "限速参数需要整数，收到: $value" >&2
    exit 2
  fi
done
if ! command -v python3 >/dev/null 2>&1; then
  echo "需要 python3（探针只用标准库）" >&2
  exit 2
fi
export PYTHONIOENCODING=utf-8

RUN_ID="$(date +%Y%m%d-%H%M%S)-$MODE-$$"
LOG_DIR="$WORK/$RUN_ID"
# 目录不可写时要立刻失败：否则后面所有日志都写到 /dev/null（或直接报错退出），
# 排障时看不到真正原因。磁盘满（本机 `/` 曾 100%）是常见场景。
mkdir -p "$WORK" || {
  echo "日志目录不可写: $WORK" >&2
  exit 2
}
mkdir -p "$LOG_DIR" || {
  echo "日志目录不可写: $LOG_DIR" >&2
  exit 2
}
ln -sfn "$RUN_ID" "$WORK/latest"

HEALTH_PORT=$((PORT + 1))
ADDR="127.0.0.1:$PORT"
HEALTH="127.0.0.1:$HEALTH_PORT"

log() { printf '%s\n' "$*" >>"$LOG_DIR/summary.log"; printf '%s\n' "$*" >&2; }
say() { printf '%s\n' "$*" >>"$LOG_DIR/summary.log"; }

# 可用磁盘先打一行（本机 `/` 曾 100% 满，写测试产物失败时这一行就是第一条线索）。
log "== 磁盘：$(df -h "$WORK" 2>/dev/null | tail -1)"

SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  SERVER_PID=""
}
trap cleanup EXIT INT TERM

# ---------- 构建 ----------

if [[ "$BUILD" == true ]]; then
  say "== 构建 rstun（$PROFILE）"
  build_args=()
  [[ "$PROFILE" == "release" ]] && build_args+=(--release)
  if ! (cd "$ROOT" && cargo build "${build_args[@]}" >"$LOG_DIR/build.log" 2>&1); then
    echo "cargo build 失败（见 $LOG_DIR/build.log）" >&2
    exit 2
  fi
fi
if [[ ! -x "$BIN" ]]; then
  echo "找不到 $BIN（去掉 --no-build，或先 cargo build$([[ "$PROFILE" == release ]] && echo ' --release')）" >&2
  exit 2
fi

# ---------- 起服务 ----------

server_flags=(--listen "$ADDR" --health-listen "$HEALTH")
# TCP 模式必须给服务端 `--tcp`（不配时 TCP 端口根本不监听，表现为 ConnectionRefused）。
[[ "$MODE" == "tcp" ]] && server_flags+=(--tcp)
[[ -n "$RATE_LIMIT" ]] && server_flags+=(--rate-limit "$RATE_LIMIT")
[[ -n "$GLOBAL_RATE" ]] && server_flags+=(--global-rate "$GLOBAL_RATE")
[[ ${#SERVER_ARGS[@]} -gt 0 ]] && server_flags+=("${SERVER_ARGS[@]}")

"$BIN" server "${server_flags[@]}" >"$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!

ready=false
for _ in $(seq 1 60); do
  if python3 - "$HEALTH" <<'PY' >/dev/null 2>&1
import sys, urllib.request
urllib.request.urlopen(f"http://{sys.argv[1]}/healthz", timeout=0.5).read()
PY
  then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  log "FAIL: 服务没起来（见 $LOG_DIR/server.log）"
  tail -5 "$LOG_DIR/server.log" >&2 || true
  exit 1
fi

# 版本 / feature 从启动日志里读（`--version` 只给版本号，不含 feature）：
#   rstun: started, Ctrl-C to stop software=rstun/26.410.100 features="lean" listeners=1
strip_ansi() { sed -E 's/\x1B\[[0-9;]*m//g'; }
RSTUN_VERSION="$(strip_ansi <"$LOG_DIR/server.log" | grep -oE 'software=rstun/[^ ]+' | tail -1 | cut -d/ -f2)"
FEATURES="$(strip_ansi <"$LOG_DIR/server.log" | grep -oE 'features="[^"]*"' | tail -1 | cut -d'"' -f2)"
if [[ -z "$RSTUN_VERSION" ]]; then
  RSTUN_VERSION="$("$BIN" --version 2>/dev/null | awk '{print $2}')"
fi
RSTUN_VERSION="${RSTUN_VERSION:-unknown}"
FEATURES="${FEATURES:-unknown}"
log "== 被测二进制：rstun/$RSTUN_VERSION（features=$FEATURES，profile=$PROFILE）"

# ---------- 压测 ----------

LIMIT_ARG="-"
[[ -n "$RATE_LIMIT" ]] && LIMIT_ARG="$RATE_LIMIT"
JSON_PATH="$LOG_DIR/result.json"

probe_exit=0
python3 - \
  "$MODE" "$ADDR" "$HEALTH" "$SERVER_PID" "$RATE" "$DURATION" "$SOURCES" \
  "$CONCURRENCY" "$LIMIT_ARG" "$JSON_PATH" "$PROFILE" \
  "$RSTUN_VERSION" "$FEATURES" \
  >>"$LOG_DIR/probe.log" 2>&1 <<'PY' || probe_exit=$?
"""黑盒压测探针：只用标准库。

人读输出（ok/FAIL/info 行）进 probe.log；机器结果始终写 JSON（--json 由 shell
决定打不打到 stdout）。断言在这里做，shell 只做「进程还活着」这类环境断言。
"""

import json
import os
import select
import socket
import struct
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101

RESPONSE_MATCH_WINDOW = 1.0  # 发送结束后再收 1s，之后算丢包
TCP_TIMEOUT = 5.0
FD_SETTLE = 0.5


def ok(message):
    print(f"ok: {message}")


def fail(message):
    print(f"FAIL: {message}")
    return 1


def info(message):
    print(f"info: {message}")


def binding_request(transaction):
    return struct.pack("!HHI12s", BINDING_REQUEST, 0, MAGIC, transaction)


def transaction_id(seq):
    return struct.pack("!QI", int(time.time() * 1000) & 0xFFFFFFFF, seq)[-12:]


def is_success(data):
    return len(data) >= 20 and struct.unpack("!H", data[:2])[0] == BINDING_SUCCESS


def percentiles(samples):
    """毫秒分位（最近秩法）。空样本返回 None，避免把「没测到」写成 0。"""
    points = ((50, "p50"), (99, "p99"), (99.9, "p999"))
    if not samples:
        return {label: None for _, label in points} | {"max": None, "mean": None}
    ordered = sorted(samples)
    out = {}
    for point, label in points:
        rank = max(0, min(len(ordered) - 1, int(round(len(ordered) * point / 100.0)) - 1))
        out[label] = round(ordered[rank], 3)
    out["max"] = round(ordered[-1], 3)
    out["mean"] = round(sum(ordered) / len(ordered), 3)
    return out


def scrape(health):
    """抓一次 /metrics，返回 {`name{labels}`: float}。"""
    text = urllib.request.urlopen(f"http://{health}/metrics", timeout=5).read().decode()
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, _, value = line.rpartition(" ")
        try:
            values[key] = float(value)
        except ValueError:
            continue
    return values


def delta(before, after, key):
    """两次 scrape 的差值。

    **两侧都必须有该 counter**：缺 key 时返回 `None`，由调用方记成
    `counter missing: <key>` 并判失败。早期版本按 0 处理，会让「未限速组
    dropped=0」变成永远成立的空断言（复核 #5）。
    """
    if key not in before or key not in after:
        return None
    return after[key] - before[key]


def proc_metric(pid, field):
    """从 /proc/<pid>/status 读 VmRSS（kB）；不可用时返回 None。"""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as handle:
            for line in handle:
                if line.startswith(field + ":"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def parse_addr(text):
    host, _, port = text.rpartition(":")
    return host, int(port)


def bind_source(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, 0))
    sock.setblocking(False)
    return sock


# ---------- UDP ----------


def run_udp(server, rate, duration, sources):
    socks = [bind_source(f"127.0.0.{index + 1}") for index in range(sources)]
    total = int(rate * duration)
    interval = 1.0 / rate
    pending = {}  # transaction -> send timestamp
    rtts = []
    answered = 0
    sent = 0
    seq = 0
    started = time.monotonic()
    deadline = started + duration
    next_send = started
    end_grace = deadline + RESPONSE_MATCH_WINDOW

    while sent < total or pending:
        now = time.monotonic()
        if sent < total and now >= next_send:
            sock = socks[sent % len(socks)]
            seq += 1
            transaction = transaction_id(seq)
            sock.sendto(binding_request(transaction), server)
            pending[transaction] = now
            sent += 1
            next_send += interval
            continue

        if sent >= total and not pending:
            break
        if now > end_grace:
            break

        if sent < total:
            timeout = min(0.002, max(0.0, next_send - now))
        else:
            timeout = 0.002
        readable, _, _ = select.select(socks, [], [], timeout)
        for sock in readable:
            while True:
                try:
                    data, _ = sock.recvfrom(65536)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                if not is_success(data) or len(data) < 20:
                    continue
                transaction = data[8:20]
                sent_at = pending.pop(transaction, None)
                if sent_at is None:
                    continue
                answered += 1
                rtts.append((time.monotonic() - sent_at) * 1000.0)

    for sock in socks:
        sock.close()

    elapsed = max(time.monotonic() - started, 1e-9)
    return {
        "sent": sent,
        "answered": answered,
        "lost": sent - answered,
        "answer_ratio": round(answered / sent, 4) if sent else 0.0,
        # send_rate = 发送数 / 目标时长（不含收尾窗口）；achieved_rate 用实际耗时
        # （含 RESPONSE_MATCH_WINDOW），限速组会比 send_rate 低约 8–10%。两者不可混比。
        "send_rate": round(sent / duration, 1) if duration else 0.0,
        "achieved_rate": round(sent / elapsed, 1),
        "elapsed": round(elapsed, 3),
        "latency_ms": percentiles(rtts),
    }


# ---------- TCP ----------


def run_tcp(server, rate, duration, concurrency):
    import queue

    slots = queue.Queue(maxsize=concurrency * 4)
    results = []
    lock = threading.Lock()
    first_byte = []
    connect_ms = []
    errors = {}

    def worker():
        while True:
            item = slots.get()
            if item is None:
                return
            began = time.monotonic()
            connected = None
            error = None
            received = b""
            try:
                with socket.create_connection(server, timeout=TCP_TIMEOUT) as stream:
                    connected = time.monotonic()
                    stream.sendall(binding_request(transaction_id(1)))
                    stream.settimeout(TCP_TIMEOUT)
                    received = stream.recv(4096)
            except OSError as exc:
                error = type(exc).__name__
            finished = time.monotonic()
            with lock:
                good = error is None and is_success(received)
                results.append(good)
                if connected is not None:
                    connect_ms.append((connected - began) * 1000.0)
                    first_byte.append((finished - began) * 1000.0)
                if error is not None:
                    # 逐条打印在洪水下会淹掉真正的失败原因：只记类型计数，最后汇总一行。
                    errors[error] = errors.get(error, 0) + 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    for thread in threads:
        thread.start()

    total = int(rate * duration)
    interval = 1.0 / rate
    started = time.monotonic()
    next_send = started
    for _ in range(total):
        now = time.monotonic()
        if next_send > now:
            time.sleep(next_send - now)
        slots.put(time.monotonic())
        next_send += interval
    for _ in threads:
        slots.put(None)
    for thread in threads:
        thread.join()
    elapsed = max(time.monotonic() - started, 1e-9)

    good = sum(1 for result in results if result)
    if errors:
        detail = "，".join(f"{name}={count}" for name, count in sorted(errors.items()))
        info(f"tcp: 失败分类 {detail}")
    return {
        "attempted": total,
        "ok": good,
        "errors": len(results) - good,
        "error_kinds": errors,
        "ok_ratio": round(good / len(results), 4) if results else 0.0,
        # 见 run_udp 的注释：send_rate 用目标时长，achieved_rate 用实际耗时。
        "send_rate": round(total / duration, 1) if duration else 0.0,
        "achieved_rate": round(total / elapsed, 1),
        "elapsed": round(elapsed, 3),
        "connect_ms": percentiles(connect_ms),
        "first_byte_ms": percentiles(first_byte),
    }


# ---------- main ----------


def main():
    (
        mode,
        server_text,
        health,
        pid_text,
        rate_text,
        duration_text,
        sources_text,
        concurrency_text,
        rate_limit_text,
        json_path,
        profile,
        rstun_version,
        features,
    ) = sys.argv[1:14]
    server = parse_addr(server_text)
    pid = int(pid_text)
    rate = int(rate_text)
    duration = float(duration_text)
    sources = int(sources_text)
    concurrency = int(concurrency_text)
    rate_limit = None if rate_limit_text == "-" else int(rate_limit_text)

    before = scrape(health)
    fd_before = fd_count(pid)
    rss_before = proc_metric(pid, "VmRSS")

    if mode == "udp":
        result = run_udp(server, rate, duration, sources)
    else:
        result = run_tcp(server, rate, duration, concurrency)

    time.sleep(FD_SETTLE)
    after = scrape(health)
    fd_after = fd_count(pid)
    rss_after = proc_metric(pid, "VmRSS")

    transport = "udp" if mode == "udp" else "tcp"
    counter_keys = {
        "requests_ok": f'rstun_requests_total{{transport="{transport}",result="ok"}}',
        "requests_dropped": f'rstun_requests_total{{transport="{transport}",result="dropped"}}',
        "rate_limited_ip": 'rstun_rate_limited_total{scope="ip"}',
        "inflight_dropped": "rstun_inflight_dropped_total",
    }
    counters = {}
    missing_counters = []
    for name, key in counter_keys.items():
        value = delta(before, after, key)
        if value is None:
            missing_counters.append(key)
            counters[name] = None
        else:
            counters[name] = int(value)
    if fd_before is not None and fd_after is not None:
        counters["fd_before"] = fd_before
        counters["fd_after"] = fd_after
    if rss_before is not None and rss_after is not None:
        counters["rss_kb_before"] = rss_before
        counters["rss_kb_after"] = rss_after

    failures = []
    # 计数缺失不是「跳过断言」而是失败：没有 /metrics 计数，下面的「dropped=0」
    # 就成了空断言（复核 #5）。
    for key in missing_counters:
        failures.append(f"counter missing: {key}（/metrics 两侧都必须有这个 counter）")
    counters_complete = not missing_counters

    if mode == "udp":
        if result["sent"] != int(rate * duration):
            failures.append(f"只发出 {result['sent']} 个请求，目标是 {int(rate * duration)}")
        if counters_complete:
            # 服务端 ok 必须跟着发送量真实增长：计数读到了但没涨，说明抓错了 counter
            # 或服务端根本没在处理（空断言）。
            required_ok = (
                result["sent"] if rate_limit is None else result["answered"]
            )
            if counters["requests_ok"] < required_ok * 0.95:
                failures.append(
                    f"服务端 ok={counters['requests_ok']} < {required_ok} x 95%"
                    f"（{'发送数' if rate_limit is None else '客户端收到的应答数'}，"
                    f"计数没有真实增长）"
                )
        if counters_complete and rate_limit is None:
            if result["answer_ratio"] < 0.95:
                failures.append(
                    f"应答率 {result['answer_ratio']:.2%} < 95%（{result['answered']}/{result['sent']}）"
                )
            if counters["requests_dropped"] != 0:
                failures.append(f"未限速组服务端 dropped={counters['requests_dropped']}（应当为 0）")
            if counters["rate_limited_ip"] != 0:
                failures.append(f"未限速组 rate_limited_ip={counters['rate_limited_ip']}（应当为 0）")
        elif counters_complete:
            if counters["rate_limited_ip"] == 0:
                failures.append("限速组 rate_limited_ip=0：限速没有生效")
            # 区间断言建立在「客户端速率 ≈ 桶速率 2x」这个**假设**上：桶容量默认
            # 2x 速率，10s 内理论放行 ≈ rate_limit×duration + burst。假设不成立时
            # 把假设写进文案，避免把「客户端速率离桶太远」误判成「限速过度」。
            assumed_rate = rate_limit * 2
            burst = rate_limit * 2
            expected_answers = min(result["sent"], int(rate_limit * duration + burst))
            expected_ratio = expected_answers / result["sent"] if result["sent"] else 0.0
            if rate == assumed_rate:
                assumption = f"（假设客户端速率 = 2x 桶速率：{rate} = 2 x {rate_limit}）"
            else:
                assumption = (
                    f"（注意：客户端速率 {rate} 不是 2x 桶速率 {assumed_rate}，"
                    f"区间判断的假设不成立）"
                )
            if result["answer_ratio"] > 0.85:
                failures.append(
                    f"限速组应答率 {result['answer_ratio']:.2%} > 85%{assumption}；"
                    f"理论放行 ≈ {expected_answers}/{result['sent']}（{expected_ratio:.0%}）、"
                    f"rate_limited_ip={counters['rate_limited_ip']} —— 限速没有拦住多余流量"
                )
            if result["answer_ratio"] < 0.30:
                failures.append(
                    f"限速组应答率 {result['answer_ratio']:.2%} < 30%{assumption}；"
                    f"理论放行 ≈ {expected_answers}/{result['sent']}（{expected_ratio:.0%}），"
                    f"实际 {result['answered']} —— 若客户端速率低于桶速率，这个下界不适用"
                )
    else:
        if result["ok_ratio"] < 0.90:
            failures.append(
                f"TCP 成功连接率 {result['ok_ratio']:.2%} < 90%（{result['ok']}/{result['attempted']}）"
            )
        if counters_complete and counters["requests_ok"] < result["ok"] * 0.95:
            failures.append(
                f"服务端 ok={counters['requests_ok']} < 客户端成功数 {result['ok']} x 95%"
                f"（计数没有真实增长）"
            )
        if counters.get("fd_after") is not None:
            baseline = counters["fd_before"]
            if counters["fd_after"] > baseline + 8:
                failures.append(
                    f"洪水后 fd 没有回落：before={baseline} after={counters['fd_after']}"
                )

    if result.get("latency_ms", {}).get("p99") is None and mode == "udp" and result["answered"]:
        failures.append("没有采集到 RTT 样本，延迟分位不可信")

    for message in failures:
        fail(message)

    if not failures:
        if mode == "udp":
            latency = result["latency_ms"]
            ok(
                f"udp：{result['answered']}/{result['sent']} 应答"
                f"（{result['answer_ratio']:.2%}），p50={latency['p50']}ms p99={latency['p99']}ms "
                f"p999={latency['p999']}ms，send_rate={result['send_rate']}/s "
                f"achieved_rate={result['achieved_rate']}/s"
            )
            ok(
                f"udp：服务端 ok={counters['requests_ok']} dropped={counters['requests_dropped']} "
                f"rate_limited_ip={counters['rate_limited_ip']}"
            )
        else:
            first = result["first_byte_ms"]
            connect = result["connect_ms"]
            ok(
                f"tcp：{result['ok']}/{result['attempted']} 成功"
                f"（{result['ok_ratio']:.2%}），connect p50={connect['p50']}ms "
                f"p99={connect['p99']}ms，首字节 p50={first['p50']}ms p99={first['p99']}ms，"
                f"send_rate={result['send_rate']}/s achieved_rate={result['achieved_rate']}/s"
            )
            if counters.get("fd_after") is not None:
                ok(f"tcp：fd before={counters['fd_before']} after={counters['fd_after']}")

    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rstun_version": rstun_version,
        "features": features,
        "mode": mode,
        "profile": profile,
        "target_rate": rate,
        "duration": duration,
        "sources": sources if mode == "udp" else None,
        "concurrency": concurrency if mode == "tcp" else None,
        "rate_limit": rate_limit,
        "result": result,
        "server": counters,
        "missing_counters": missing_counters,
        "notes": [
            "send_rate = 发送数 / 目标时长（不含收尾窗口）；achieved_rate = 发送数 / 实际耗时"
            "（含 RESPONSE_MATCH_WINDOW 收尾，限速组会低约 8–10%），两者不可直接对比。",
            "latency 是客户端侧 RTT（lo 回环，不含网卡/qdisc/跨机 RTT）；",
            "target_rate 是要发送的速率的请求值，多源时是各源之和。",
        ],
        "failures": failures,
        "ok": not failures,
    }
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    return 1 if failures else 0


sys.exit(main())
PY

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  log "FAIL: 压测后服务进程已退出（见 $LOG_DIR/server.log）"
  probe_exit=1
fi

# 退出统计（SIGTERM 后打印）留档，便于人读复核。
cleanup

say ""
if [[ -f "$JSON_PATH" ]]; then
  say "== JSON（$JSON_PATH）"
  cat "$JSON_PATH" >>"$LOG_DIR/summary.log"
fi
if [[ -n "$OUT" ]]; then
  [[ -f "$JSON_PATH" ]] && cp "$JSON_PATH" "$OUT"
fi

if [[ "$JSON_ONLY" == true ]]; then
  if [[ -f "$JSON_PATH" ]]; then
    cat "$JSON_PATH"
  fi
fi

if [[ "$probe_exit" -ne 0 ]]; then
  # 断言失败的原因在 probe.log 的 FAIL 行里：直接回显到 stderr，别让人再去翻日志。
  if [[ -f "$LOG_DIR/probe.log" ]]; then
    grep -a '^FAIL' "$LOG_DIR/probe.log" >&2 || true
  fi
  log "结果：FAIL（见 $LOG_DIR/probe.log）"
  exit 1
fi
# 成功摘要（应答率 / 延迟分位 / counters）也回显到 stderr：`| tail` 与 CI 日志里
# 能直接看到关键数字，不用再 cat probe.log。`--json` 时 stdout 仍只有 JSON。
if [[ -f "$LOG_DIR/probe.log" ]]; then
  grep -a '^ok' "$LOG_DIR/probe.log" >&2 || true
fi
if [[ "$JSON_ONLY" != true ]]; then
  log "结果：全部通过（日志 $LOG_DIR）"
fi
exit 0
