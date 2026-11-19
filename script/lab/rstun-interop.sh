#!/usr/bin/env bash
#
# `rstun` 互操作矩阵（T1）单入口：能一次跑完，也能只跑某一项。
#
# 为什么需要它：协议合规的断言都在 `cargo test` 里（自己编、自己解）。
# 「敢说完整」还差一层：**第三方实现**能不能读我们的包、我们能不能读它们的包。
# 这一层依赖外部工具链（Go / 第三方 cargo 工程 / coturn / libFuzzer），
# 不适合塞进 `cargo test`，所以集中在这里，单项可跑、结果可摘录。
#
# 用法（本仓是**单 crate**：所有 cargo 命令都在仓库根跑，没有 `-p`）：
#   bash script/lab/rstun-interop.sh --list
#   bash script/lab/rstun-interop.sh probe
#   bash script/lab/rstun-interop.sh pion
#   bash script/lab/rstun-interop.sh webrtc-stun
#   bash script/lab/rstun-interop.sh coturn
#   bash script/lab/rstun-interop.sh stun-types
#   bash script/lab/rstun-interop.sh rfc5769
#   bash script/lab/rstun-interop.sh fuzz --fuzz-seconds 600
#   bash script/lab/rstun-interop.sh ci
#   bash script/lab/rstun-interop.sh all     # probe + pion + webrtc-stun + coturn + stun-types + rfc5769
#   bash script/lab/rstun-interop.sh full    # all + fuzz(600s) + ci
#
# 端口：默认 base 34780，**绝不使用 3478**（那是 STUN 的标准端口，容易被本机别的
#       服务占用，且「连到本机某个正在跑的服务」会让结论不可归因）；每个子项在自己的
#       偏移上跑，`--port N` 可整体平移。临时工程与日志都在 `$RSTUN_INTEROP_DIR`
#       （默认 /tmp/opencode/rstun-interop），不进仓库。
#
# 依赖：cargo/rustc（本仓）、python3（探针）；pion 项要 go、webrtc-stun 项要 cargo、
#       coturn 项要 turnserver + turnutils_stunclient、fuzz 项要 cargo-fuzz + nightly。
#       缺依赖时该项记 BLOCKED 并继续，其余项照跑。
#
# 退出码：0 = 跑的项全绿（BLOCKED 不算失败，但会在汇总里标出）；1 = 至少一项失败。
#
# 判据提醒：`CHANGE-REQUEST` 的回包来自**另一个源地址**，端口受限 NAT 后的客户端
#       会把它当陌生包丢掉 —— 「客户端收不到」≠「服务端没有换源」。判定要取本地回环、
#       服务端 `--verbose` 日志里的 `from=`、或 full-cone/DC 客户端。见 docs/interop-matrix.md §11。
#
# 证据：每项输出落 `$RSTUN_INTEROP_DIR/logs/`；「多少条断言」用
#       `grep -a -h '^ok:' $RSTUN_INTEROP_DIR/logs/*.log | wc -l`。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$ROOT/script/lab/rstun-interop-probe.py"
BIN="$ROOT/target/debug/rstun"
WORK="${RSTUN_INTEROP_DIR:-/tmp/opencode/rstun-interop}"
LOG_DIR="$WORK/logs"

PORT=34780
BUILD=true
FUZZ_SECONDS=600
ITEMS=()

PIDS=()
FAILED_ITEMS=()
BLOCKED_ITEMS=()
PASSED_ITEMS=()

ALL_ITEMS=(probe pion webrtc-stun coturn stun-types rfc5769)
# fuzz 与 ci 单独算：前者要 10 分钟，后者是「本地复现 CI 步骤」，都容易被误当成必跑项。
FULL_ITEMS=("${ALL_ITEMS[@]}" fuzz ci)

usage() {
  sed -n '2,39p' "$0" | sed 's/^# \{0,1\}//'
}

list_items() {
  cat <<'EOF'
可用项（--item 可重复，也可逗号分隔）：

  probe        rstun 自身的协议矩阵（19 项子用例 / 15 类 mode）：basic / mapped / ice /
               auth / unknown / padding(128,4000,8000) / response-port /
               padding-response-port / change(0x02,0x04,0x06) / rfc5780-attrs / tcp / ipv6 /
               fingerprint / fingerprint-drop / alternate。
               起 7 个实例（主、mapped、RFC 5780 双 IP、IPv6、--alternate-server、
               --check-fingerprint、--check-fingerprint --fingerprint-action drop）。
  pion         pion/stun（Go）作为第三方编解码 + 客户端：basic / ice / unknown /
               padding / response-port / tcp / rfc5780。
  webrtc-stun  webrtc-rs `stun` 0.17 同上，另加 ipv6（共 8 个 mode）。
  coturn       turnutils_stunclient 双向：他们 → 我们（含 RFC 5780 三响应）、
               我们（探针）→ coturn；coturn 自身基线也跑一遍用于归因。
  stun-types   `stun-types` 2.0.5 双向 + 300/500 错误响应（cargo test：tests_interop::stun_types，2 条）。
  rfc5769      RFC 5769 §2.1–§2.4 测试向量 + §2.1–§2.3 的 FINGERPRINT CRC
               （cargo test：tests_interop::rfc5769，5 条）。
  fuzz         `cargo +nightly fuzz run parse`，默认 600 秒，日志落 $RSTUN_INTEROP_DIR。
  ci           本地复现 CI 步骤：单测 + UDP/TCP/IPv6 冒烟 + workflow YAML 解析 +
               运行期零新增依赖（cargo tree 无 exvlan-*）。
  all          probe + pion + webrtc-stun + coturn + stun-types + rfc5769
  full         all + fuzz + ci

可选参数：
  --port N            端口基准（默认 34780；不要用 3478）
  --no-build          跳过 `cargo build`
  --fuzz-seconds N    fuzz 时长（默认 600）
  --keep              保留临时工程与日志目录（默认也保留日志，只清理进程）
EOF
}

log() { printf '%s\n' "$*"; }
ok_item() { PASSED_ITEMS+=("$1"); log "  ok   $1"; }
fail_item() {
  FAILED_ITEMS+=("$1")
  log "  FAIL $1${2:+ — $2}"
}
blocked_item() {
  BLOCKED_ITEMS+=("$1")
  log "  SKIP $1${2:+ — $2}"
}

cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# ---------- 服务生命周期 ----------

start_rstun() {
  local name="$1"
  shift
  "$BIN" server "$@" >"$LOG_DIR/$name.log" 2>&1 &
  PIDS+=("$!")
}

# 等服务真的能应答（bind 成功 ≠ 能回包：family 绑错、端口被占都可能「进程在跑」）。
wait_ready() {
  local address="$1" attempt
  for attempt in $(seq 1 40); do
    if python3 "$PROBE" basic --server "$address" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# 同 wait_ready，但用调用方给的 mode：`--alternate-server` 的实例对任何 Binding 都回
# 300，`basic` 会把它判成失败。其余参数原样传给探针。
wait_ready_mode() {
  local mode="$1" address="$2" attempt
  shift 2
  for attempt in $(seq 1 40); do
    if python3 "$PROBE" "$mode" --server "$address" "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# ---------- 探针 ----------

# `run_probe <label> <mode> [args…]`：label 进汇总与日志名（同一 mode 会用不同参数
# 跑多次，例如 padding 128/4000/8000，必须能分开），exit 77 视作环境不支持 → SKIP。
run_probe() {
  local label="$1"
  shift
  local mode="$1"
  shift
  local log_file="$LOG_DIR/probe-$label.log"
  echo "--- probe $label（mode=$mode $*）"
  python3 "$PROBE" "$mode" "$@" >"$log_file" 2>&1
  local status=$?
  cat "$log_file"
  if [[ $status -eq 0 ]]; then
    ok_item "probe/$label"
    return 0
  fi
  if [[ $status -eq 77 ]]; then
    blocked_item "probe/$label" "环境不支持（exit 77）"
    return 0
  fi
  fail_item "probe/$label" "见 $log_file"
  return 1
}

# ---------- 各项 ----------

item_probe() {
  log "== probe：rstun 协议矩阵（端口 base $PORT）"
  local main="127.0.0.1:$PORT"
  local alt="127.0.0.1:$((PORT + 2))"
  local alt_port=$((PORT + 3))
  local mapped="127.0.0.1:$((PORT + 4))"
  local v6="[::1]:$((PORT + 5))"
  local alternate="127.0.0.1:$((PORT + 8))"
  local fingerprint="127.0.0.1:$((PORT + 9))"
  local fingerprint_drop="127.0.0.1:$((PORT + 11))"

  start_rstun probe-main --listen "$main" --tcp
  start_rstun probe-mapped --listen "$mapped" --mapped-address
  start_rstun probe-alt --listen "$alt" --alt-listen "127.0.0.2:$((PORT + 2))" --alt-port "$alt_port"
  start_rstun probe-v6 --listen-v6 "$v6"
  start_rstun probe-alternate --listen "$alternate" --alternate-server 192.0.2.9:3478
  start_rstun probe-fingerprint --listen "$fingerprint" --check-fingerprint
  start_rstun probe-fingerprint-drop --listen "$fingerprint_drop" \
    --check-fingerprint --fingerprint-action drop

  # `--alternate-server` 对任何 Binding 都回 300，`basic` 会按 200 判定——就绪探测必须
  # 用它自己的 mode，否则 wait_ready 永远等不到「成功响应」。
  if ! wait_ready "$main" || ! wait_ready "$mapped" || ! wait_ready "$alt" \
    || ! wait_ready "$fingerprint" || ! wait_ready "$fingerprint_drop" \
    || ! wait_ready_mode alternate "$alternate" --alternate 192.0.2.9:3478; then
    fail_item "probe" "服务未就绪（看 $LOG_DIR/probe-*.log）"
    return
  fi

  run_probe basic basic --server "$main"
  run_probe mapped mapped --server "$mapped"
  run_probe ice ice --server "$main"
  run_probe auth auth --server "$main"
  run_probe unknown unknown --server "$main"
  # PADDING 三档（验收口径：128 / 4000 / 8000）：
  # 8000 字节是「超过常见 MTU 数倍」的一档，验证 64 KiB 读缓冲 + 不放大。
  run_probe padding-128 padding --server "$main" --size 128
  run_probe padding-4000 padding --server "$main" --size 4000
  run_probe padding-8000 padding --server "$main" --size 8000
  run_probe response-port response-port --server "$main"
  run_probe padding-response-port padding-response-port --server "$main"
  run_probe tcp tcp --server "$main"
  run_probe rfc5780-attrs rfc5780-attrs --server "$alt" --alt-ip 127.0.0.2 --alt-port "$alt_port"
  run_probe change-0x02 change --server "$alt" --alt-ip 127.0.0.2 --alt-port "$alt_port" --change 0x02
  run_probe change-0x04 change --server "$alt" --alt-ip 127.0.0.2 --alt-port "$alt_port" --change 0x04
  run_probe change-0x06 change --server "$alt" --alt-ip 127.0.0.2 --alt-port "$alt_port" --change 0x06
  run_probe fingerprint fingerprint --server "$fingerprint"
  run_probe fingerprint-drop fingerprint-drop --server "$fingerprint_drop"
  run_probe alternate alternate --server "$alternate" --alternate 192.0.2.9:3478

  # IPv6 不是所有环境都有（CI 容器 / 禁 v6 的内核）：绑不上就记 SKIP，不算失败。
  if wait_ready "$v6"; then
    run_probe ipv6 ipv6 --server "$v6"
  else
    blocked_item "probe/ipv6" "本机没有可用 IPv6 回环（$v6）"
  fi
}

item_pion() {
  log "== pion/stun（Go）"
  command -v go >/dev/null || { blocked_item "pion" "没有 go"; return; }
  local source="$ROOT/test/interop/pion"
  local dir="$WORK/pion"
  rm -rf "$dir"
  mkdir -p "$dir"
  cp "$source/main.go" "$dir/"
  # 第三方依赖在 /tmp 里解析：仓库里不留 go.sum/vendor。
  cat >"$dir/go.mod" <<'EOF'
module rstuninterop/pion

go 1.24

require github.com/pion/stun/v3 v3.1.7
EOF
  if ! (cd "$dir" && GOFLAGS=-mod=mod go mod tidy && go build -o pionprobe .) >"$LOG_DIR/pion-build.log" 2>&1; then
    fail_item "pion" "构建失败（$LOG_DIR/pion-build.log）"
    return
  fi
  local version
  version="$(cd "$dir" && go list -m github.com/pion/stun/v3 2>/dev/null)"
  log "   pinned: $version"

  local server="127.0.0.1:$PORT"
  start_rstun pion-server --listen "$server" --tcp --alt-listen "127.0.0.2:$PORT" --alt-port "$((PORT + 1))"
  wait_ready "$server" || { fail_item "pion" "服务未就绪"; return; }

  # 判定用**退出码**而不是 grep 输出：夹具 panic / 编译缓存损坏时也会非 0，
  # 只 grep "FAIL" 会把「崩了」误判成通过。
  local mode
  for mode in basic ice unknown padding response-port tcp; do
    if "$dir/pionprobe" -mode "$mode" -server "$server" >"$LOG_DIR/pion-$mode.log" 2>&1; then
      ok_item "pion/$mode"
    else
      fail_item "pion/$mode" "见 $LOG_DIR/pion-$mode.log"
    fi
  done
  if "$dir/pionprobe" -mode rfc5780 -server "$server" -alt-port "$((PORT + 1))" \
    >"$LOG_DIR/pion-rfc5780.log" 2>&1; then
    ok_item "pion/rfc5780"
  else
    fail_item "pion/rfc5780" "见 $LOG_DIR/pion-rfc5780.log"
  fi
}

item_webrtc_stun() {
  log "== webrtc-rs stun 0.17"
  command -v cargo >/dev/null || { blocked_item "webrtc-stun" "没有 cargo"; return; }
  local source="$ROOT/test/interop/webrtc-stun"
  local dir="$WORK/webrtc-stun"
  rm -rf "$dir"
  mkdir -p "$dir/src"
  cp "$source/Cargo.toml.in" "$dir/Cargo.toml"
  cp "$source/src/main.rs" "$dir/src/"
  if ! (cd "$dir" && cargo build --quiet) >"$LOG_DIR/webrtc-build.log" 2>&1; then
    fail_item "webrtc-stun" "构建失败（$LOG_DIR/webrtc-build.log）"
    return
  fi
  local binary="$dir/target/debug/rstun-interop-webrtc-stun"
  log "   pinned: $(cd "$dir" && grep -m1 '^stun =' Cargo.toml)"

  local server="127.0.0.1:$PORT"
  start_rstun webrtc-server --listen "$server" --tcp --alt-listen "127.0.0.2:$PORT" --alt-port "$((PORT + 1))"
  start_rstun webrtc-v6 --listen-v6 "[::1]:$((PORT + 6))"
  wait_ready "$server" || { fail_item "webrtc-stun" "服务未就绪"; return; }

  local mode
  for mode in basic ice unknown padding response-port tcp; do
    if "$binary" --mode "$mode" --server "$server" >"$LOG_DIR/webrtc-$mode.log" 2>&1; then
      ok_item "webrtc-stun/$mode"
    else
      fail_item "webrtc-stun/$mode" "见 $LOG_DIR/webrtc-$mode.log"
    fi
  done
  if "$binary" --mode rfc5780 --server "$server" --alt-port "$((PORT + 1))" \
    >"$LOG_DIR/webrtc-rfc5780.log" 2>&1; then
    ok_item "webrtc-stun/rfc5780"
  else
    fail_item "webrtc-stun/rfc5780" "见 $LOG_DIR/webrtc-rfc5780.log"
  fi
  if wait_ready "[::1]:$((PORT + 6))"; then
    if "$binary" --mode ipv6 --server "[::1]:$((PORT + 6))" >"$LOG_DIR/webrtc-ipv6.log" 2>&1; then
      ok_item "webrtc-stun/ipv6"
    else
      fail_item "webrtc-stun/ipv6" "见 $LOG_DIR/webrtc-ipv6.log"
    fi
  else
    blocked_item "webrtc-stun/ipv6" "本机没有可用 IPv6 回环"
  fi
}

item_coturn() {
  log "== coturn / turnutils_stunclient（双向）"
  command -v turnserver >/dev/null || { blocked_item "coturn" "没有 turnserver（apt-get install coturn）"; return; }
  command -v turnutils_stunclient >/dev/null || { blocked_item "coturn" "没有 turnutils_stunclient"; return; }

  local coturn_port=$((PORT + 10))
  # 用原生进程而不是容器：不触容器边界，也不依赖 docker/podman 可用。
  turnserver -n --log-file=stdout --listening-ip=127.0.0.1 --listening-port="$coturn_port" \
    --no-tls --no-dtls --no-cli >"$LOG_DIR/coturn.log" 2>&1 &
  PIDS+=("$!")

  # 我们（探针）→ coturn：证明我们的**编码**被 coturn 接受（方向 B）。
  if wait_ready "127.0.0.1:$coturn_port"; then
    # 方向 A′：我们的编码 → coturn 的服务端。单独命名，避免与 probe 项的同名断言混淆。
    if python3 "$PROBE" basic --server "127.0.0.1:$coturn_port" >"$LOG_DIR/coturn-probe-basic.log" 2>&1; then
      ok_item "coturn/probe→coturn（我们的编码）"
    else
      fail_item "coturn/probe→coturn（我们的编码）" "见 $LOG_DIR/coturn-probe-basic.log"
    fi
    # turnutils 基线：他们的 client → 他们的 server（工具本身可用，后续失败才可归因）
    if turnutils_stunclient -p "$coturn_port" 127.0.0.1 >"$LOG_DIR/coturn-baseline.log" 2>&1; then
      ok_item "coturn/baseline(stunclient→coturn)"
    else
      fail_item "coturn/baseline(stunclient→coturn)" "工具自身跑不通，后续结论不可用"
      return
    fi
  else
    fail_item "coturn" "turnserver 未就绪（$LOG_DIR/coturn.log）"
    return
  fi

  # 他们（turnutils_stunclient）→ 我们（方向 A）：必须给满 RFC 5780 的四 socket，
  # 否则客户端只会做基础 Binding，测不到 CHANGE-REQUEST / OTHER-ADDRESS。
  # `--verbose` 是这组证据的关键：coturn 客户端只从外部看得到「回包源」，
  # 而「它到底请求了哪些标志位 / 带了多长 PADDING」只有服务端 debug 行能证明。
  # 日志固定落 `logs/coturn-target-verbose.log`，报告直接引用这份真实产物。
  local server="127.0.0.1:$PORT"
  start_rstun coturn-target-verbose --listen "$server" \
    --alt-listen "127.0.0.2:$PORT" --alt-port "$((PORT + 1))" --verbose
  if ! wait_ready "$server"; then
    fail_item "coturn/stunclient→rstun" "服务未就绪"
    return
  fi
  local output="$LOG_DIR/coturn-stunclient-to-rstun.log"
  if ! turnutils_stunclient -p "$PORT" 127.0.0.1 >"$output" 2>&1; then
    fail_item "coturn/stunclient→rstun" "exit≠0（$output）"
    return
  fi
  ok_item "coturn/stunclient→rstun（exit=0）"
  # 更硬的判据：三条 RFC 5780 响应都要出来，且 RESPONSE-ORIGIN 与 change 语义一致。
  if grep -q "RFC 5780 response 1" "$output" \
    && grep -q "RFC 5780 response 2" "$output" \
    && grep -q "RFC 5780 response 3" "$output"; then
    ok_item "coturn/stunclient→rstun（RFC 5780 三次响应）"
  else
    fail_item "coturn/stunclient→rstun（RFC 5780 三次响应）" "客户端没有走完 5780 测试"
  fi
  # CHANGE-REQUEST 的**回包源**断言：response 2 必须是换 IP+换端口后的地址。
  if grep -q "Response origin: : 127.0.0.2:$((PORT + 1))" "$output"; then
    ok_item "coturn/stunclient→rstun（CHANGE-REQUEST 回包源）"
  else
    fail_item "coturn/stunclient→rstun（CHANGE-REQUEST 回包源）" "响应源地址不符合四 socket 计划（$output）"
  fi
}

# cargo 的测试名过滤器「0 匹配」也会 exit 0（还会打印 `0 passed`）——
# 只判退出码会把「测试被改名/删掉」误判成通过。这里必须同时断言 passed 数。
run_filtered_tests() {
  local label="$1" filter="$2" minimum="$3"
  local output status passed
  # label 里带 `/`（`stun-types/bidirectional`）：直接拼进路径会指向不存在的子目录，
  # 日志静默丢失。文件名一律把 `/` 换成 `-`，label 本身仍原样进汇总。
  local log_file="$LOG_DIR/cargo-${label//\//-}.log"
  output="$(cargo test --quiet -- "$filter" 2>&1)"
  status=$?
  printf '%s\n' "$output" >"$log_file"
  printf '%s\n' "$output" | tail -5
  passed="$(printf '%s\n' "$output" | sed -n 's/^test result: ok\. \([0-9]\+\) passed.*/\1/p' | head -1)"
  if [[ $status -eq 0 && ${passed:-0} -ge $minimum ]]; then
    ok_item "$label（${passed} passed ≥ ${minimum}）"
  else
    fail_item "$label" "exit=$status passed=${passed:-?}（要求 ≥${minimum}；过滤器 0 匹配也会 exit 0）"
  fi
}

item_stun_types() {
  log "== stun-types 2.0.5（双向 + 300/500 错误响应）"
  run_filtered_tests stun-types/codec tests_interop::stun_types 2
}

item_rfc5769() {
  log "== RFC 5769 测试向量（§2.1–§2.4 + FINGERPRINT CRC）"
  run_filtered_tests rfc5769/vectors tests_interop::rfc5769 5
}

item_fuzz() {
  log "== cargo-fuzz（解析路径 ${FUZZ_SECONDS}s）"
  command -v cargo-fuzz >/dev/null || { blocked_item "fuzz" "没有 cargo-fuzz（cargo install cargo-fuzz）"; return; }
  # 文件名带「时长 + 时间戳」：先跑 60 s 预热、再跑 600 s 验收时不会互相覆盖，
  # 报告引用的是**当次真实**产物（此前只有 fuzz-60.log，600 s 结论无据可查）。
  local log_file
  log_file="$LOG_DIR/fuzz-${FUZZ_SECONDS}s-$(date +%Y%m%d-%H%M%S).log"
  # cargo-fuzz 需要 nightly（libFuzzer + sanitizer）；没有就记 BLOCKED 而不是失败。
  if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    blocked_item "fuzz" "没有 nightly 工具链（rustup toolchain install nightly）"
    return
  fi
  if (cd "$ROOT/fuzz" && cargo +nightly fuzz run parse -- -max_total_time="$FUZZ_SECONDS" -rss_limit_mb=2048) \
    >"$log_file" 2>&1; then
    if grep -qE "panicked|ERROR: libFuzzer|deadly signal|timeout after" "$log_file"; then
      fail_item "fuzz" "日志里有崩溃/挂死（$log_file）"
    else
      ok_item "fuzz/${FUZZ_SECONDS}s（$(grep -oE 'Done [0-9]+ runs' "$log_file" | tail -1)；$log_file）"
    fi
  else
    fail_item "fuzz" "cargo fuzz 退出非 0（$log_file）"
  fi
}

item_ci() {
  log "== CI 的本地复现（Linux 部分）"
  local failures=0
  if cargo test --quiet >"$LOG_DIR/ci-tests.log" 2>&1; then
    ok_item "ci/cargo-test"
  else
    fail_item "ci/cargo-test"
    failures=$((failures + 1))
  fi

  # 单 crate 可独立构建：依赖树里不得出现 exvlan-*（本仓曾作为其 workspace 成员）。
  local upstream_deps
  upstream_deps="$(cargo tree -e all 2>/dev/null | grep -c 'exvlan-')"
  if [[ "$upstream_deps" == "0" ]]; then
    ok_item "ci/no-upstream-deps"
  else
    fail_item "ci/no-upstream-deps" "cargo tree 里出现 $upstream_deps 个 exvlan-*"
    failures=$((failures + 1))
  fi

  local server="127.0.0.1:$PORT"
  start_rstun ci-main --listen "$server" --tcp
  if wait_ready "$server" && bash "$ROOT/script/ci/rstun-smoke.sh" "$server" --tcp --retries 5 \
    >"$LOG_DIR/ci-smoke.log" 2>&1; then
    ok_item "ci/smoke-udp-tcp"
  else
    fail_item "ci/smoke-udp-tcp"
    failures=$((failures + 1))
  fi

  local v6="[::1]:$((PORT + 7))"
  start_rstun ci-v6 --listen-v6 "$v6"
  if wait_ready "$v6"; then
    if bash "$ROOT/script/ci/rstun-smoke.sh" "$v6" --retries 5 >"$LOG_DIR/ci-smoke-v6.log" 2>&1; then
      ok_item "ci/smoke-ipv6"
    else
      fail_item "ci/smoke-ipv6"
      failures=$((failures + 1))
    fi
  else
    blocked_item "ci/smoke-ipv6" "本机没有可用 IPv6 回环"
  fi

  # workflow 语法：改 `.github/workflows/ci.yml` 后，至少保证 YAML 可解析。
  # 先探测 PyYAML：缺模块是环境问题（SKIP），不能报成「workflow 语法错」。
  if ! python3 -c "import yaml" >/dev/null 2>&1; then
    blocked_item "ci/workflow-yaml" "没有 PyYAML（pip install pyyaml）"
  elif python3 -c "import yaml; yaml.safe_load(open('$ROOT/.github/workflows/ci.yml'))" 2>/dev/null; then
    ok_item "ci/workflow-yaml"
  else
    fail_item "ci/workflow-yaml"
    failures=$((failures + 1))
  fi

  # macOS / Windows 只能在 CI 上跑：这里明确告知，不冒充已验证。
  log "   注意：macOS / Windows 的矩阵项只能在 CI 上验证（本脚本只覆盖 Linux 本地）。"
  return 0
}

# ---------- 参数 ----------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) list_items; exit 0 ;;
    -h|--help|"") usage; exit 0 ;;
    --port) PORT="${2:?--port 需要端口}"; shift ;;
    --port=*) PORT="${1#*=}" ;;
    --no-build) BUILD=false ;;
    --fuzz-seconds) FUZZ_SECONDS="${2:?--fuzz-seconds 需要秒数}"; shift ;;
    --fuzz-seconds=*) FUZZ_SECONDS="${1#*=}" ;;
    --keep) : ;;
    # 顶层没有 `local`：用普通变量（每次覆盖，不会残留）。
    --item) IFS=',' read -r -a parts <<<"${2:?--item 需要名字}"; ITEMS+=("${parts[@]}"); shift ;;
    --item=*) IFS=',' read -r -a parts <<<"${1#*=}"; ITEMS+=("${parts[@]}") ;;
    all) ITEMS+=("${ALL_ITEMS[@]}") ;;
    full) ITEMS+=("${FULL_ITEMS[@]}") ;;
    probe|pion|webrtc-stun|coturn|stun-types|rfc5769|fuzz|ci) ITEMS+=("$1") ;;
    *) echo "未知参数: $1（--list 看可用项）" >&2; exit 2 ;;
  esac
  shift
done

[[ ${#ITEMS[@]} -gt 0 ]] || { usage; exit 0; }

mkdir -p "$WORK" "$LOG_DIR"

if [[ "$PORT" == "3478" ]]; then
  echo "--port 不能是 3478（STUN 标准端口，易被本机既有服务占用导致误判）：换一个高位端口，如 34780" >&2
  exit 2
fi

if [[ "$BUILD" == "true" ]]; then
  if ! cargo build --quiet; then
    echo "cargo build 失败" >&2
    exit 1
  fi
fi
if [[ ! -x "$BIN" ]]; then
  echo "找不到 $BIN（去掉 --no-build 或先 cargo build）" >&2
  exit 1
fi

log "rstun 互操作矩阵：端口 base=$PORT，工作目录 $WORK"
log ""

for item in "${ITEMS[@]}"; do
  case "$item" in
    probe) item_probe ;;
    pion) item_pion ;;
    webrtc-stun) item_webrtc_stun ;;
    coturn) item_coturn ;;
    stun-types) item_stun_types ;;
    rfc5769) item_rfc5769 ;;
    fuzz) item_fuzz ;;
    ci) item_ci ;;
    *) echo "未知项: $item" >&2; exit 2 ;;
  esac
  # 每项之间清理自己起的进程，避免端口串味（下一项会重新起服务）。
  cleanup
  PIDS=()
  log ""
done

log "================ 汇总 ================"
log "通过 ${#PASSED_ITEMS[@]} 项："
for item in "${PASSED_ITEMS[@]:-}"; do [[ -n "$item" ]] && log "  ok   $item"; done
if [[ ${#BLOCKED_ITEMS[@]} -gt 0 ]]; then
  log "跳过 ${#BLOCKED_ITEMS[@]} 项（环境缺依赖）："
  for item in "${BLOCKED_ITEMS[@]}"; do log "  SKIP $item"; done
fi
if [[ ${#FAILED_ITEMS[@]} -gt 0 ]]; then
  log "失败 ${#FAILED_ITEMS[@]} 项："
  for item in "${FAILED_ITEMS[@]}"; do log "  FAIL $item"; done
  log ""
  log "日志目录：$LOG_DIR"
  exit 1
fi
log ""
log "全绿（Linux 本地；macOS/Windows 见 CI 矩阵）。日志目录：$LOG_DIR"
exit 0
