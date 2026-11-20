# `script/lab/` —— 互操作 / 抗滥用 / 压测 / 混沌夹具

这里的脚本**默认不是 PR 门禁**：`ci.yml` 跑 `cargo test` + `script/ci/rstun-smoke.sh`
（三平台）+ 非阻塞覆盖率；`qa-scheduled.yml` 每周跑 fuzz / 互操作 / 压测冒烟
（只存数值，不设阈值）。本目录的价值是把「跑起来才知道」的结论固化成可重跑的夹具：

- 互操作：第三方实现能不能读我们的包、我们能不能读它们的包；
- 抗滥用：打开限速/反射防护之后**到底拦住了什么**（关/开对照、单源 vs 多源、28/40 字节反射）；
- 性能：吞吐 / 延迟分位 / 限速开-关对照（`rstun-load.sh`，基线见 `docs/perf.md`）；
- 混沌：丢包 / 乱序 / 大 datagram / 半开连接 / 中继丢包（`rstun-chaos.sh`）。

任何一项从 ok 变 FAIL 就说明行为变了。

| 文件 | 作用 |
| --- | --- |
| [`rstun-interop.sh`](./rstun-interop.sh) | 互操作矩阵单入口：8 个项，可单项跑也可一次跑完 |
| [`rstun-interop-probe.py`](./rstun-interop-probe.py) | 只用 python3 标准库的协议探针（逐条 `ok:` / `FAIL:` 断言） |
| [`rstun-abuse.sh`](./rstun-abuse.sh) | 抗滥用对照：关/开限速、单源洪水、28/40 字节反射尝试、allow/deny、TCP 洪水 |
| [`rstun-turn.sh`](./rstun-turn.sh) | TURN 验收（17 项）：中继 / 生命周期 / 441 / 508 / 486 / **TLS / DTLS** / **REST 凭据** / **带宽配额** / 回收 / 字节冻结 / coturn 对照。默认 lean 构建（tls/dtls 项 SKIP）；`--tls`/`--dtls` 自动 `--features full` 构建 |
| [`rstun-turn-probe.py`](./rstun-turn-probe.py) | 有状态 TURN 客户端（标准库）：`lifecycle` / `relay` / `auth` / `wrong-user` / `loopback` / `permission-limit` / `rest`，同一步骤可对 coturn 与 rstun 各跑一次再 diff |
| [`rstun-load.sh`](./rstun-load.sh) | 黑盒压测：UDP 吞吐/延迟分位（单源与 127.0.0.x 多源）、TCP 连接洪水与首字节、**限速开/关对照**、`--json`。数字见 [`docs/perf.md`](../../docs/perf.md) |
| [`rstun-chaos.sh`](./rstun-chaos.sh) | 混沌用例 C1–C6：`tc netem` 丢包 / 乱序重复 / 大 datagram（可选强制 MTU 分片）/ TCP 半包 / 半开连接 / TURN 中继丢包 + 配额。无 root 或 `tc` 时 SKIP 并说明 |

结论与原始证据摘录见 [`docs/interop-matrix.md`](../../docs/interop-matrix.md)。

## 用法

```bash
bash script/lab/rstun-interop.sh --list        # 列项 + 可选参数
bash script/lab/rstun-interop.sh probe         # 只跑 rstun 自身协议矩阵（19 项子用例）
bash script/lab/rstun-interop.sh --item pion,webrtc-stun   # 多选
bash script/lab/rstun-interop.sh all           # 除 fuzz/ci 外全部（42 项子用例）
bash script/lab/rstun-interop.sh full          # all + fuzz(600s) + ci
```

单项：`probe` / `pion` / `webrtc-stun` / `coturn` / `stun-types` / `rfc5769` / `fuzz` / `ci`。

TURN 验收（自起自停；TLS/DTLS 用 `openssl` 自签证书，REST 用探针 + `uclient -W`）：

```bash
bash script/lab/rstun-turn.sh              # 全部 17 项（lean 构建；tls/dtls 记 SKIP 并说明）
bash script/lab/rstun-turn.sh --tls        # 只跑 TLS（自动 --features full 构建；s_client + uclient -S -t）
bash script/lab/rstun-turn.sh --dtls       # 只跑 DTLS（自动 --features full；s_client -dtls1_2 + uclient -S）
bash script/lab/rstun-turn.sh --only rest  # REST：有效 / 过期 401 / 错 secret 401 / label 含 ':'
bash script/lab/rstun-turn.sh --only coturn # 与本地 turnserver 同参数对跑（含 TLS/DTLS/REST）
#   项名：startup|relay|auth|lifecycle|wrong-user|wildcard|permission-limit|quota|ports|
#         tls|dtls|rest|bandwidth|cleanup|frozen|coturn
```

抗滥用对照（自起自停、退出码可判定、每组一个日志）：

```bash
bash script/lab/rstun-abuse.sh               # 全部 10 组
bash script/lab/rstun-abuse.sh --only reflect # 只跑一组
#   组名：off | rate | global | reflect | reflect-strict | reflect-reject | allow | deny | inflight | tcp
#   未知组名直接 exit 2（不会「0 组运行 + 全部通过」）
bash script/lab/rstun-abuse.sh --port 34881 --no-build
```

它用 `127.0.0.0/8` 里的**不同源地址**模拟多源，**不需要 root / NET_RAW**，所以能验证
「每 IP 桶按源地址分桶 / allow 放行 / deny 拒绝 / `--max-inflight` 真的丢包」；真实公网
**伪造源**压测不在这里（那需要 raw socket），伪造源这条防线由 `--reflect-ratio` 的算术与
反射组的实测字节断言覆盖。反射组会断言**真实字节数**（28 → 32 / 56、40 → 76）、
与 `max(请求 × ratio, 请求 + 32)` 的关系、`SOFTWARE` 的有无，并检查拒绝时目标口收到 0 个包；
`reflect-reject` 组专门跑一个**确实会被拒**的用例（`CHANGE-REQUEST` + `PADDING 8` → 88 > 80）。
日志：`$RSTUN_ABUSE_DIR`（默认 `/tmp/opencode/rstun-abuse`）。

压测（自起自停；失败非 0；`--json` 供 CI artifact）：

```bash
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000 --sources 8
bash script/lab/rstun-load.sh --mode tcp --duration 5  --rate 200 --concurrency 32
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 2000 --rate-limit 1000  # 限速对照
bash script/lab/rstun-load.sh --mode udp --json > result.json
#   --profile debug / --no-build / --port N / --out FILE / --server-arg=--turn
```

断言不是打印：未限速组要求应答率 ≥ 95%、服务端 `dropped=0`，且 `requests_ok` ≥ 发送数 × 95%
（计数必须真实增长）；限速组要求 `rate_limited_ip` 增长、应答率落在 [30%, 85%]（假设客户端
≈ 2× 桶速率，文案会写明假设与理论放行量）；TCP 组要求成功率 ≥ 90%、洪水后 fd 回落。
`/metrics` 里缺任何一个 counter 都直接 FAIL（`counter missing: <key>`），不会退化成空断言。
默认 **release** 构建（这是性能工具）；基线数字与硬件见 [`docs/perf.md`](../../docs/perf.md)。
JSON 里 `send_rate` 是「发送数 / 目标时长」，`achieved_rate` 含 1s 收尾窗口（限速组低约 8–10%），
跨组比较用 `send_rate`；另有 `generated_at` / `rstun_version` / `features` 便于日后对比。
日志：`$RSTUN_LOAD_DIR`（默认 `/tmp/opencode/rstun-load`，每次一个子目录 + `latest` 软链）。

混沌（`tc netem` 需要 root；缺 `tc`/root 时对应项 SKIP 并写原因）：

```bash
bash script/lab/rstun-chaos.sh                # C1–C6
bash script/lab/rstun-chaos.sh --list         # loss|reorder|mtu|half-frame|half-open|turn-loss
bash script/lab/rstun-chaos.sh --only turn-loss
bash script/lab/rstun-chaos.sh --mtu 1500     # C3 额外把 lo MTU 降到 1500 以强制分片
```

`--mtu` 会临时改 `lo` 的 MTU 并在退出时恢复；默认不动（lo MTU 是 65536，默认路径下
「分片」其实没有发生，输出里会如实标注，不冒充已验证）。日志：
`$RSTUN_CHAOS_DIR`（默认 `/tmp/opencode/rstun-chaos`）。

断言口径（两处曾经假红，已修）：

- C2 的放大上界用**整数** `count * 135 // 100`（1.35×，>3σ）：`200 * 1.15` 在浮点下是
  229.999…，会把合法的 230 判红；`server_ok` 用同一上界。
- C3 只接受两种开销：**0**（不回显 `PADDING`）或 **32**（回显时固定多出 `XOR-MAPPED-ADDRESS`）；
  其它值判红。`lo` MTU=65536 时并没有真的分片，需 `--mtu 1500` 才验证分片路径。
- C2 的 `dropped` 计数读不到时判 **FAIL**（不是「跳过断言」）：没有计数就不算通过。

C2 的发送方式（flaky 的真实根因，不只是界）：

- 曾经一次性灌 200 个 datagram：netem 的 `delay 20ms` 会把它们攒在 qdisc/发送缓冲里，
  内存紧张时 `sendto` 抛 `ENOBUFS`，探针以 traceback 退出，`check()` 把非 0 退出记成
  「断言失败」——现象是一次失败里服务端只收到 **108/200**（≈ 212 KB 默认发送缓冲 / 每个
  loopback skb 的 truesize）。
- 现在：客户端 **SO_SNDBUF = 1 MB** + **1 ms 间隔**发送（≈1000/s），并对 `sendto` 的
  `OSError` 退避重试（连续 50 次才 FAIL，消息里带 errno 与实际发出数）。
- 探针输出现在落 `$RSTUN_CHAOS_DIR/<run>/probe.log`（以前只在 stdout，失败后无从定位）；
  C2 还会把 `tc -s qdisc` 记进 `tc.log`，用于区分「丢在队列」还是「丢在 socket 缓冲」；
  `/metrics` 抓取失败与计数为 0 也分开判定（前者直接 FAIL）。

端口（另一个 flaky 来源，已处理）：

- 本机 `ip_local_port_range` 可能是 **1024–65535**（整段非特权端口都能被内核当源端口），
  固定端口会被别的进程的临时连接抢走 → 偶发 `Address already in use (os error 98)`
  （实测 C4/C5 各一次）。
- 现在：启动时 `pick_ports` 用 UDP/TCP/health 三次 bind 预检挑一对真正可绑的端口（最多
  200 个候选，日志里打印实际使用的端口）；运行中若某个用例启动即报 `Address already in use`，
  `start_server` 会换端口重试（≤3 次）并打印 `WARN`。其它启动错误不重试（交给 `wait_health`
  如实报）。`--port` 仍是从该端口开始找。

常用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--port N` | `34780` | 端口基准，各子项在其上取偏移；**`3478` 会被直接拒跑（exit 2）** |
| `--no-build` | — | 跳过 `cargo build`（复用已有 `target/debug/rstun`） |
| `--fuzz-seconds N` | `600` | `fuzz` 项时长 |
| `--keep` | — | 保留临时工程与日志（日志默认就保留，只清进程） |

日志与临时工程：`$RSTUN_INTEROP_DIR`（默认 `/tmp/opencode/rstun-interop`）。
每次运行都把每项输出写进 `logs/`；「多少条断言」= `grep -a -h '^ok:' $RSTUN_INTEROP_DIR/logs/*.log | wc -l`。

## 依赖

| 项 | 需要 | 缺依赖时 |
| --- | --- | --- |
| `probe` / `stun-types` / `rfc5769` / `ci` | `cargo` + `python3` | — （`ci` 的 YAML 检查另需 PyYAML） |
| `rstun-abuse` | `cargo` + `python3`（只用标准库） | — |
| `pion` | `go`（夹具在 `test/interop/pion/`，`go mod tidy` 在临时目录跑） | SKIP |
| `webrtc-stun` | `cargo`（夹具在 `test/interop/webrtc-stun/`） | SKIP |
| `coturn` / `rstun-turn` | `turnserver` + `turnutils_stunclient` + `turnutils_uclient`（Debian: `apt-get install coturn`） | SKIP |
| `rstun-turn` 的 TLS/DTLS 项 | 另需 `openssl`（自签证书、`s_client` 握手探针） | TLS/DTLS 项 SKIP |
| `fuzz` | `cargo-fuzz` + `nightly` 工具链 | SKIP |
| `rstun-load` | `cargo` + `python3`（只用标准库；**不需要** root） | — |
| `rstun-chaos` 的 C1/C2/C3/C6 | `tc`（iproute2）+ **root**（NET_ADMIN，`lo` 的 qdisc） | SKIP + 原因（C4/C5 不需要，照跑） |
| `rstun-chaos --mtu` | `ip` + root（临时改 `lo` MTU，退出时恢复） | C3 强制分片段 SKIP |

容器（`docker`/`podman`）**不需要**：coturn 用原生进程起，不触容器边界。
IPv6 回环不可用时 `ipv6` 子项记 SKIP，不算失败。

## 判据提醒

`CHANGE-REQUEST`（RFC 5780）的回包来自**另一个源地址/端口**。端口受限 NAT 后的客户端会把
陌生源的包丢掉，于是表现为「超时」——**这不等于是服务端没有换源**。

判定换源是否真的发生，要看：

- 本地回环（`127.0.0.1` ↔ `127.0.0.2`）：本脚本的 `probe/change-*` 与 `pion|webrtc-stun/rfc5780`；
- 服务端 `--verbose` 日志里的 `from=` 字段（本脚本 coturn 项固定落 `logs/coturn-target-verbose.log`）；
- 或 full-cone / DC 一类的客户端。

同理，第三方工具**没有** STUN 服务端能力时（pion / webrtc-rs 都只有编解码 + 客户端），
方向 B 只到编解码层 —— 那是对手能力边界，不是我们的失败。
