# 性能基线（`script/lab/rstun-load.sh`）

> 任务：`.trellis/tasks/11-21-rstun-perf-refresh`（重测 `26.410.103`）
> 前次：`.trellis/tasks/11-19-rstun-qa`（2026-11-20 · `rstun 26.410.100`）
> 执行时间：2026-11-21 · 被测二进制：`rstun 26.410.103+4af885`
> （`cargo build --release` 与 `cargo build --release --features full` 各一组，均未 strip）·
> 环境见 §1，与前次的差异见 §8.1。
>
> 为什么是黑盒：`rstun` 是 bin-only crate，函数级基准（criterion 直接测 `decide()`）
> 需要先把 `src/lib.rs` 抽出来 —— 那是结构性改动，会动 `main.rs` 与全部测试的可见性。
> 本系列的边界是「度量与门禁，不改服务代码」，所以这里只量**真实进程收发包**的结果
> （设计见 `11-19-rstun-qa/design.md` §2 的取舍说明）。
>
> 这份文档是**参考基线**，不是门禁：CI 只上传数值（`qa-scheduled.yml`），阈值只在
> 本地发布前人工比对（§7）。
>
> **依赖面**：本次测量对应 unix 口径的 **10 个直接依赖（lean）/ 14 个（full）**
> （`cargo tree -e normal --depth 1`；Windows 仍是 9 / 13，`libc` 只在
> `[target.'cfg(unix)'.dependencies]` 里，用于 `DONT-FRAGMENT` 的 DF 位）。
> 前次（26.410.100）的记录是 9 / 13，`docs/perf.md` 的历史数字不回溯改写，
> 但**本文所有表格都来自 10 / 14 口径的这次测量**。

## 0. 结论（先说）

1. **5 000 req/s 对服务端仍是空闲负载**：UDP 单源与 8 源、lean 与 full 全部 100% 应答，
   服务端 `dropped=0`。p50 0.036–0.038 ms（与前次 4 次样本的 0.030–0.045 ms 一致），
   p99 中位数 lean 0.129 / 0.097 ms、full 0.103 / 0.120 ms（单源 / 8 源）。
   p99/p999 的散布比前次大，原因是**同机并行 agent 会话**（§8.1），不是代码。
2. **吞吐上限仍由压测客户端决定，不是服务端**：目标 100 000/s 时 9 次运行服务端
   `dropped=0` 且 `ok=500 000`（每个包都处理了），客户端呈两种稳态 ——
   跟得上（实际耗时 5 s、≈100 000/s、100% 应答）或跟不上（被拉到 6 s、≈83 300/s、
   应答 82.7–99.6%）。后者是单进程 python 探针读 socket 的速度（丢在客户端缓冲，
   不是服务端）。因此可以确定**服务端 ≥ 100 k/s**；要测真实上限需要多进程或
   C/Rust 压测器（后续增强项）。
3. **限速对照可分且完全可复现**：同一客户端速率 2 000/s，关限速 20 000/20 000 应答
   （`dropped=0`）；`--rate-limit 1000` 时 **11 999/20 000** 应答、`rate_limited_ip=8001`、
   `dropped=8001`（lean 与 full 各跑两次，四个数字完全相同）。理论值
   `1000×10 + burst 2000 = 12 000`，少 1 个包是边界。
4. **lean 与 full 的差异仍只在内存与体积**：RSS ≈5.3 MB vs ≈6.3 MB（+1.0 MB），
   未 strip 二进制 **3.77 MB vs 7.95 MB**；LTO+strip 后（`Dockerfile` 的 profile）
   **2.35 MB vs 4.83 MB**（与 `Dockerfile` 注释里的 2.35 / 4.8 MB 吻合，已复核）。
   延迟差在噪声内。
5. **TCP 200 连接/秒、32 并发**：1 000/1 000 成功，connect p99 0.187 ms（lean）/
   0.211 ms（full），首字节 p99 0.344 / 0.373 ms，洪水后 fd 12 → 12（无泄漏）。

## 1. 环境

| 项 | 值 |
| --- | --- |
| 机器 | 本机容器（Debian 13 / trixie），非 CI runner |
| CPU | Intel Core i9-14900T，32 线程（24 核，2 线程/核） |
| 内存 | 96 GB（测时 `available` ≈33 GB） |
| 内核 | Linux 6.12.111+deb13-amd64 x86_64 |
| 工具链 | rustc 1.95.0 (59807616e 2026-04-14)，cargo 1.95.0 (f2d3ce0bd 2026-03-21) |
| 网络 | 全部走 `lo`（回环），**不含**真实网卡/网桥开销 |
| 压测客户端 | `python3` 3.13（标准库）单进程探针，与服务器同机 |
| 服务端参数 | `--listen 127.0.0.1:35080 --health-listen 127.0.0.1:35081`（无 `--turn`、无认证、无关卡） |
| 背景负载 | **非独占**：同机另有并行 agent 会话（`node`/`opencode`/`windows` VM/`mysqld`/`valkey`），每次运行前后用 `/proc/stat` 采样，系统级 busy **6.5–33.4%**（53 次采样，中位 16.9%），逐次记录见 §8 |

> 回环上的绝对值不能当成生产容量：它把网卡、qdisc、跨机 RTT 都省掉了。它的价值是
> **可复现的回归基线**——同一台机器重跑，数字应在 ±10% 内（§8 的复现命令）。
> 本轮机器的「空闲度」与前次不同，所以本文额外记录背景 busy%；比较 p99/p999 时
> 必须先看这一列（§8.1 给了同二进制的相关性证据）。

## 2. 方法与命令

脚本自己起停服务、抓两次 `/metrics` 取增量的服务端计数，客户端侧按固定速率发
20 字节 Binding Request 并记录 RTT；`.json` 里同时存客户端结果与服务端计数
（`generated_at` / `rstun_version` / `features` 便于日后对比时确认是哪个二进制）：

```bash
# lean
cargo build --release
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000 --no-build
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000 --sources 8 --no-build
bash script/lab/rstun-load.sh --mode tcp --duration 5  --rate 200 --concurrency 32 --no-build

# full
cargo build --release --features full
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000 --no-build
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000 --sources 8 --no-build
bash script/lab/rstun-load.sh --mode tcp --duration 5  --rate 200 --concurrency 32 --no-build

# 限速开/关对照（两次的唯一差别是 --rate-limit）
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 2000 --no-build
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 2000 --rate-limit 1000 --no-build

# 容量探针（找客户端瓶颈在哪）
for r in 20000 50000 100000; do
  bash script/lab/rstun-load.sh --mode udp --duration 5 --rate "$r" --no-build
done
```

> **本次的执行细节（不改脚本，只为避开并行会话争用）**：二进制构建到独立的
> `CARGO_TARGET_DIR`（`cargo build --release`，版本串用
> `RSTUN_BUILD_VERSION=26.410.103+4af885` 注入，与 CI 的注入方式一致），再复制成
> `target/release/rstun` 供脚本使用；脚本用的是仓库里的
> `script/lab/rstun-load.sh` 原件（未改动）。除 `--out` 外没有额外参数。
> 每次运行前都用 `pgrep -af 'rstun|turnserver|cargo'` 确认没有自家残留进程；
> 期间同机还有其它会话的 `turnserver -c turnserver.conf`（0.9% CPU 的空闲驻留）和一个
> `rstun server --listen 127.0.0.1:34790 --turn`，端口与 35080/35081 不冲突，
> 所有运行都正常起停。

> **速率口径**：JSON 里有两个速率字段 —— `send_rate = 发送数 / 目标时长`（不含收尾），
> `achieved_rate = 发送数 / 实际耗时`（含 1s `RESPONSE_MATCH_WINDOW` 收尾）。
> 限速组实际耗时约 11s（10s 发送 + 1s 收尾），`achieved_rate` 会比 `send_rate` 低约 8–10%，
> 因此**跨组比较用 `send_rate`**；`achieved_rate` 只用于判断「客户端有没有跟上节奏」。

每次运行的完整 JSON 与服务器日志都在 `$RSTUN_LOAD_DIR/<run-id>/`
（默认 `/tmp/opencode/rstun-load`），`latest` 是指向最后一次的软链。
本轮原始数据：`/tmp/opencode/perf-run/logs/*.json`（每次运行的 `features` 字段
被逐一核对过，确认表里的行确实来自对应构建）。

## 3. lean 基线（`cargo build --release`，10 个直接依赖，3.77 MB）

本次 lean 组：单源 10 次、8 源 7 次、TCP 3 次。表里是**中位数**
（p99/p999 的逐次样本见 §8.1 —— 这台机器的尾巴受背景负载支配，单次值不可当基线）。

| 场景 | 目标速率 | 应答/发送 | 应答率 | p50 | p99 | p999 | 服务端 `dropped` | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| UDP 单源 | 5 000/s | 50 000/50 000 | 100% | 0.037 ms | 0.129 ms | 0.846 ms | 0 | 5 362 kB |
| UDP 8 源（127.0.0.1–.8） | 5 000/s | 50 000/50 000 | 100% | 0.038 ms | 0.097 ms | 0.171 ms | 0 | 5 304 kB |
| TCP 32 并发 | 200 连接/s | 1 000/1 000 | 100% | connect 0.116 ms / 首字节 0.200 ms | connect 0.187 ms / 首字节 0.344 ms | 0.432 / 0.607 ms | 0 | 5 252 kB |

低负载窗口（busy 6.5%）的一次运行原样摘录 —— 说明「尾巴」能回到前次的量级：

```json
{"mode":"udp","target_rate":5000,"sources":1,"rate_limit":null}
{"sent":50000,"answered":50000,"lost":0,"answer_ratio":1.0,"send_rate":5000.0,
 "latency_ms":{"p50":0.036,"p99":0.122,"p999":0.19,"max":1.038,"mean":0.042}}
{"requests_ok":50000,"requests_dropped":0,"rate_limited_ip":0,"fd_before":11,"fd_after":11,
 "rss_kb_before":5212,"rss_kb_after":5328}
```

```json
{"mode":"tcp","target_rate":200,"concurrency":32}
{"attempted":1000,"ok":1000,"errors":0,"ok_ratio":1.0,"achieved_rate":200.1,
 "connect_ms":{"p50":0.116,"p99":0.183,"p999":0.598},"first_byte_ms":{"p50":0.2,"p99":0.344,"p999":0.748}}
{"requests_ok":1000,"requests_dropped":0,"fd_before":12,"fd_after":12}
```

## 4. full 基线（`cargo build --release --features full`，14 个直接依赖，7.95 MB）

full 组：单源 4 次、8 源 4 次、TCP 3 次（同样取中位数）。启动日志里的
`features="tls,dtls"` 就是这一组。

| 场景 | 目标速率 | 应答/发送 | 应答率 | p50 | p99 | p999 | 服务端 `dropped` | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| UDP 单源 | 5 000/s | 50 000/50 000 | 100% | 0.036 ms | 0.103 ms | 0.285 ms | 0 | 6 348 kB |
| UDP 8 源 | 5 000/s | 50 000/50 000 | 100% | 0.037 ms | 0.120 ms | 1.360 ms | 0 | 6 260 kB |
| TCP 32 并发 | 200 连接/s | 1 000/1 000 | 100% | connect 0.132 ms / 首字节 0.224 ms | connect 0.211 ms / 首字节 0.373 ms | 0.337 / 1.062 ms | 0 | 6 284 kB |

（lean/full 的差异在回环噪声内；唯一稳定差异是 RSS ≈ +1 MB，因为 TLS/DTLS 代码与
rustls/webrtc-dtls 的静态数据进了进程。未 strip 二进制 3.77 MB → 7.95 MB；
按 `Dockerfile` 的 LTO+strip profile 另建一次是 2.35 MB → 4.83 MB。）

```json
{"mode":"udp","target_rate":5000,"sources":1,"rate_limit":null}
{"sent":50000,"answered":50000,"answer_ratio":1.0,"achieved_rate":5000.0,
 "latency_ms":{"p50":0.022,"p99":0.085,"p999":0.145,"max":3.645,"mean":0.027}}
{"requests_ok":50000,"requests_dropped":0,"fd_before":11,"fd_after":11,
 "rss_kb_before":6208,"rss_kb_after":6324}
```

> **表格里的 p50/p99/p999 是多次复跑的中位数**。发布前门禁不要拿单次值当基线：
> 本轮 p99 的重跑波动可达 2–3×（§8.1），按比例卡会假红。

## 5. 限速对照（防误伤 + 证明限速真的生效）

两次运行的**唯一差异**是服务端是否带 `--rate-limit 1000`（桶容量默认 2×速率）。
lean 与 full 各跑两次，结果**完全一致**：

| 组 | 发送 | 应答 | 应答率 | `rate_limited_ip` | `dropped` | p99（lean / full） |
| --- | --- | --- | --- | --- | --- | --- |
| 未限速 | 20 000 | 20 000 | 100% | 0 | 0 | 0.123 / 0.097 ms |
| `--rate-limit 1000` | 20 000 | 11 999 | 60.0% | 8 001 | 8 001 | 0.122 / 0.093 ms |

- 理论放行量 = `1000 × 10s + burst 2 000 = 12 000`，实测 11 999（1 个包的边界差异；
  2 次复跑都是 11 999）；
- **限速没有误伤到「能放行的部分」**：放行请求的 p99 仍是 0.08–0.16 ms，与未限速组同量级；
- 拒绝路径是「静默丢弃 + 计数」，客户端看到的是丢包（`lost=8001`），不是 400/500；
- 对照组（`qa-scheduled`）用同一脚本、同一断言，任何一边反转都会 FAIL。

```json
{"mode":"udp","target_rate":2000,"rate_limit":1000}
{"sent":20000,"answered":11999,"lost":8001,"answer_ratio":0.5999,"send_rate":2000.0,
 "achieved_rate":1818.1,"latency_ms":{"p50":0.034,"p99":0.083,"p999":0.141}}
{"requests_ok":11999,"requests_dropped":8001,"rate_limited_ip":8001,"fd_before":11,"fd_after":11}
```

> 本任务没有测「限速表 65 536 条目时的内存/P99」（`rstun-abuse-guard` 的未闭环观察项）：
> 那需要 65 536 个不同源（`--rate-limit-port` 的 ip:port 键），本机可以造，但与
> 「黑盒吞吐基线」是两件事，避免混在一起让基线不可复现。留作后续观察项。

## 6. 容量与延迟随负载（找瓶颈在哪）

lean 组，每个速率 2–5 次，取中位数（逐次样本见 §8.1）：

| 目标速率 | 实测速率 | 应答率 | p50 | p99 | p999 | 服务端 `dropped` |
| --- | --- | --- | --- | --- | --- | --- |
| 20 000/s | 19 999.9/s | 100% | 0.032 ms | 0.096 ms | 1.87 ms | 0 |
| 50 000/s | 49 999.0/s | 100% | 0.029 ms | 1.27 ms | 3.50 ms | 0 |
| 100 000/s | 83 318/s | 98.1% | 0.432 ms | 143 ms | 179 ms | 0 |

full 组同样速率（各 2–4 次）：20 000/s → p99 0.076 ms、100%；
50 000/s → p99 0.131 ms、100%；100 000/s → 实测 99 964/s、100%、p99 48 ms（中位）。

解读：

- 20 000/s 与 50 000/s **服务端轻松**：服务端计数与客户端发送量一致，`dropped=0`。
- 100 000/s 时 **服务端仍然一个包都没丢**（9 次运行 `requests_ok=500 000`、
  `dropped=0`），但客户端有**两种稳态**：
  - 跟得上 —— 实际耗时 5 s、≈100 000/s、100% 应答（本轮 full 4 次里 3 次）；
  - 跟不上 —— 被拉到 6 s、≈83 300/s、应答 82.7–99.6%（本轮 lean 5 次全部如此）。
  两种稳态由调度决定，不是服务端行为：`sent` 始终是 500 000，`requests_ok` 也是
  500 000，丢的是客户端来不及读走的应答（回环上客户端 socket 缓冲溢出）。这也意味着
  **不能**用这张表的「83 300/s」反推服务端上限 —— 只能说服务端 ≥ 100 000/s。
- 与脚本的关系：100 000/s 的 5 次 lean 运行里有 2 次触发脚本的 `应答率 < 95%` 断言
  （92.44% / 82.72%）。这是**客户端饱和**导致的，不是服务端丢包 ——
  同两次的 `requests_dropped` 都是 0。脚本没改；这条只作为 §8 的已知局限记录。

## 7. 本地发布前门禁（人工，不进 CI）

沿用 `11-19-rstun-qa/design.md` §3，**只用于同机、同硬件、同构建参数的发布前对比**：

- p99 ≤ 基线 × 1.3（基线 = §3/§4 表的**中位数**；亚毫秒量级的 p99 不能按比例复现，
  见 §8 —— 1.3× 是「同机对比」的容差，不是跨机器/跨内核的可移植阈值）；
- `send_rate` ≥ 基线 × 0.8（req/s 这一项可以按比例复现，同机重跑 ±10% 内）；
- 超出必须在发布说明里解释（换硬件、换内核、换了监听参数、**机器是否被别的任务占着**
  都要说明 —— 本轮就是这个变量在起作用）。

> 不要把这里的 1.3×/0.8× 与 §8 的「±10%」混用：±10% 只描述**同机重跑的 req/s 与应答率**
> 的可复现性；p99 在回环亚毫秒量级上重跑波动可达 2–3×（本轮实测），所以基线按
> 「中位数 + 最差值」记录，门禁用中位数。

CI（`qa-scheduled.yml` 的 `bench` job）**只上传数值 artifact**，不设阈值：公共 runner
的噪声比阈值大，设硬阈值只会制造假红。

## 8. 复现性与局限

| 项 | 状态 |
| --- | --- |
| 同机重跑（req/s 与应答率） | **±10% 只适用于这两项**。5 000/s 单源 10 次：`send_rate` 5 000.0–5 000.1/s，10 次全部 50 000/50 000 应答（100%） |
| 同机重跑（p50） | p50 稳定：10 次 0.023–0.040 ms，中位 0.037；与前次的 0.030–0.045 区间一致 |
| 同机重跑（p99 / p999） | **不稳定，本轮 2–3×**：10 次 p99 = 0.088–0.201 ms（中位 0.129），p999 = 0.189–3.285 ms。基线口径 = 中位数 + 最差值；对比时必须连同 §8.1 的背景负载一起看 |
| 背景负载（本轮新增观测） | 系统级 busy 6.5–33.4%。同一二进制、同一命令的 8 源组：busy 8.1% → p99 0.078/p999 0.142；busy 26.5% → p99 0.218/p999 2.028。**尾巴跟着背景负载走**，p50 不动 |
| 回环 vs 真实网络 | 未覆盖：真实网卡、跨机 RTT、丢包/重排见 `rstun-chaos.sh` |
| 客户端瓶颈 | 100 k/s 是 python 单进程的双稳态边界（跟得上 ≈100 k/s / 跟不上 ≈83.3 k/s），不代表服务端上限；92.44% / 82.72% 两次运行会让脚本的 ≥95% 断言 FAIL（服务端 `dropped=0`） |
| 内存 | 只记 RSS（`/proc/<pid>/status` 前后采样）；未做 65 536 条目限速表的内存曲线 |
| TURN 中继吞吐 | 不在本基线：`rstun-chaos.sh` 的 C6 只验证「配额丢包 + allocation 存活」，吞吐基线待单独补 |
| CI 平台 | 未验证：`qa-scheduled.yml` 的 bench job 只在 push 后第一次 schedule/dispatch 时才会产生数值 |
| 异常运行（作废） | 1 次 8 源运行在第 3 秒被**外部 SIGTERM** 终止（`server.log` 是 graceful stop、`received=15008`，不是崩溃也不是脚本的 cleanup；同机其它会话所致），该次作废后重跑；日志留在 `20261121-135410-udp-47948/` |

### 8.1 与前次（2026-11-20 / `26.410.100` / 9-13 依赖）的差异

| 项 | 前次 | 本次 | 差异 | 说明 |
| --- | --- | --- | --- | --- |
| 版本串 | `26.410.100` | `26.410.103+4af885` | — | git HEAD `4af885` |
| 直接依赖（lean / full） | 9 / 13 | **10 / 14** | +1 | `libc` 提升为 unix 直接依赖（DF 位要 `setsockopt`）；`cargo tree` 已复核 |
| 未 strip 二进制 | 3.5 MB / 7.9 MB | **3.77 MB / 7.95 MB** | +7.7% / +0.6% | digest 0.11 一代（hmac 0.13、sha1/sha2/md-5 0.11）、`clap 4.6.9`、`libc`、TURN（RAf/DF/IPv6 relay）代码 |
| LTO+strip 二进制 | 未记录 | 2.35 MB / 4.83 MB | — | 与 `Dockerfile` 注释的 2.35 / 4.8 MB 一致，已复核 |
| RSS | 5 244 / 6 176 kB | 5 362 / 6 348 kB | +2.3% / +2.8% | 量级不变；差异在噪声内 |
| p50（UDP 单源） | 0.033 ms | 0.037 ms | +12% | 落在前次 4 次样本区间（0.030–0.045）内 |
| p99（UDP 单源） | 0.083 ms | 0.129 ms（中位） | +55% | **环境**：机器不再独占（busy 6.5–33%）；低负载窗口（6.5%）实测 0.122，8 源组在 busy 8.1% 时 p99 0.078 —— 与前次同量级 |
| p999（UDP 单源） | 0.135 ms | 0.846 ms（中位） | 6× | 同上：繁忙窗口 3.285 ms，空闲窗口 0.19 ms |
| p99（TCP connect） | 0.177 / 0.215 ms | 0.187 / 0.211 ms | +6% / −2% | 噪声内 |
| 5 000/s 的应答率与 `send_rate` | 100% / 5 000.0 | 100% / 5 000.0 | 0 | 无变化 |
| 限速组放行量 | 11 999 | 11 999 | 0 | 无变化（4 次复跑全同） |
| 100 k/s 实测 | 83 306/s、98.65% | 83 318/s、98.1%（中位） | −1% | 客户端瓶颈未变；本轮另有「跟得上」稳态（≈100 k/s） |

结论：**没有证据表明本轮代码改动（DF/TURN/依赖升级）改变了热路径的吞吐或延迟** ——
p50、req/s、应答率、限速行为、RSS 全部与前次同量级，唯一显著变化的 p99/p999 与
同二进制的背景负载强相关。要点：**以后引用这些数字必须同时引用「背景 busy%」**，
否则 p99 的对比会得出错误结论。

逐次原始样本（lean 单源 10 次 / 8 源 7 次，`busy` 为该次运行期间的系统级占用）：

| 组 | 样本（p99 ms） | busy% |
| --- | --- | --- |
| lean 单源 | 0.104 / 0.178 / 0.152 / 0.201 / 0.135 / 0.109 / 0.118 / 0.136 / 0.122 / 0.088 | 前 4 次未采样；后 6 次 20.3 / 20.2 / 21.2 / 21.8 / 6.5 / 9.4 |
| lean 8 源 | 0.494 / 0.278 / 0.218 / 0.097 / 0.075 / 0.086 / 0.078 | 未采样 / 26.0 / 26.5 / 17.9 / 12.4 / 13.4 / 8.1 |
| lean 50 k/s | 21.074 / 1.266 / 0.246 | 24.5 / 22.1 / 14.1 |
| lean 100 k/s | 62.181 / 142.975 / 311.523 / 74.705 / 390.647 | 22.6 / 16.9 / 21.8 / 23.8 / 24.2（后两次应答率 99.4% / 82.7%） |
