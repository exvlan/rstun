# 性能基线（`script/lab/rstun-load.sh`）

> 任务：`.trellis/tasks/11-19-rstun-qa`（implement.md 第 1–3 步）
> 执行时间：2026-11-20 · 被测二进制：`rstun 26.410.100`（`cargo build --release`，
> lean 与 `--features full` 各一组）· 环境见 §1。
>
> 为什么是黑盒：`rstun` 是 bin-only crate，函数级基准（criterion 直接测 `decide()`）
> 需要先把 `src/lib.rs` 抽出来 —— 那是结构性改动，会动 `main.rs` 与全部测试的可见性。
> 本任务的边界是「度量与门禁，不改服务代码」，所以这里只量**真实进程收发包**的结果
> （设计见 `design.md` §2 的取舍说明）。
>
> 这份文档是**参考基线**，不是门禁：CI 只上传数值（`qa-scheduled.yml`），阈值只在
> 本地发布前人工比对（§6）。

## 0. 结论（先说）

1. **5 000 req/s 对服务端是空闲负载**：UDP 单源与 8 源都是 100% 应答，
   p50 ≈ 0.03–0.05 ms、p99 中位数 0.09 ms（4 次复跑 0.083–0.137 ms，亚毫秒噪声，见 §8），
   服务端 `dropped=0`。
2. **吞吐上限由压测客户端决定，不是服务端**：目标 100 000/s 时实测 83 306/s、
   p99 95.8 ms、`answer_ratio 98.65%`，而服务端 `dropped=0` —— 丢的是客户端来不及
   收的应答（单进程 python 探针读 socket 的速度）。服务端在 50 000/s 时 p99 仍是 0.45 ms。
3. **限速对照可分**：同一客户端速率 2 000/s，关限速 20 000/20 000 应答（`dropped=0`）；
   `--rate-limit 1000` 时 11 999/20 000 应答、`rate_limited_ip=8001`、`dropped=8001`
   （理论值 `1000×10 + burst 2000 = 12 000`，实测 11 999 —— 每分钟级误差在 1 个包内）。
4. **lean 与 full 的差异只在内存**（≈5.2 MB vs ≈6.2 MB RSS），延迟/吞吐在噪声内。
   二进制体积 3.5 MB vs 7.9 MB（`--features full` 把 rustls/webrtc-dtls 链进来）。
5. **TCP 200 连接/秒、32 并发**：1 000/1 000 成功，connect p99 0.18 ms、首字节 p99 0.31 ms，
   洪水后 fd 12 → 12（无泄漏）。

## 1. 环境

| 项 | 值 |
| --- | --- |
| 机器 | 本机容器（Debian 13 / trixie），非 CI runner |
| CPU | Intel Core i9-14900T，32 线程（24 核，2 线程/核） |
| 内存 | 96 GB（测时空闲 ~33 GB） |
| 内核 | Linux 6.12.111+deb13-amd64 x86_64 |
| 工具链 | rustc 1.95.0 (59807616e 2026-04-14)，cargo 1.95.0 |
| 网络 | 全部走 `lo`（回环），**不含**真实网卡/网桥开销 |
| 压测客户端 | `python3`（标准库）单进程探针，与服务器同机 |
| 服务端参数 | `--listen 127.0.0.1:35080 --health-listen 127.0.0.1:35081`（无 `--turn`、无认证、无关卡） |

> 回环上的绝对值不能当成生产容量：它把网卡、qdisc、跨机 RTT 都省掉了。它的价值是
> **可复现的回归基线**——同一台机器重跑，数字应在 ±10% 内（§5 的复现命令）。

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

> **速率口径**：JSON 里有两个速率字段 —— `send_rate = 发送数 / 目标时长`（不含收尾），
> `achieved_rate = 发送数 / 实际耗时`（含 1s `RESPONSE_MATCH_WINDOW` 收尾）。
> 限速组实际耗时约 11s（10s 发送 + 1s 收尾），`achieved_rate` 会比 `send_rate` 低约 8–10%，
> 因此**跨组比较用 `send_rate`**；`achieved_rate` 只用于判断「客户端有没有跟上节奏」。

每次运行的完整 JSON 与服务器日志都在 `$RSTUN_LOAD_DIR/<run-id>/`
（默认 `/tmp/opencode/rstun-load`），`latest` 是指向最后一次的软链。

## 3. lean 基线（`cargo build --release`，9 个直接依赖，3.5 MB）

| 场景 | 目标速率 | 应答/发送 | 应答率 | p50 | p99 | p999 | 服务端 `dropped` | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| UDP 单源 | 5 000/s | 50 000/50 000 | 100% | 0.033 ms | 0.083 ms | 0.135 ms | 0 | 5 244 kB |
| UDP 8 源（127.0.0.1–.8） | 5 000/s | 50 000/50 000 | 100% | 0.035 ms | 0.095 ms | 0.181 ms | 0 | 5 160 kB |
| TCP 32 并发 | 200 连接/s | 1 000/1 000 | 100% | connect 0.113 ms / 首字节 0.188 ms | connect 0.177 ms / 首字节 0.314 ms | 0.215 / 0.353 ms | 0 | 5 260 kB |

原始片段（`result.json` 摘录）：

```json
{"mode":"udp","target_rate":5000,"sources":1,"rate_limit":null}
{"sent":50000,"answered":50000,"lost":0,"answer_ratio":1.0,"achieved_rate":5000.0,
 "latency_ms":{"p50":0.033,"p99":0.083,"p999":0.135,"max":3.856,"mean":0.031}}
{"requests_ok":50000,"requests_dropped":0,"rate_limited_ip":0,"fd_before":11,"fd_after":11,
 "rss_kb_before":5244,"rss_kb_after":5244}
```

```json
{"mode":"tcp","target_rate":200,"concurrency":32}
{"attempted":1000,"ok":1000,"errors":0,"ok_ratio":1.0,"achieved_rate":200.1,
 "connect_ms":{"p50":0.113,"p99":0.177,"p999":0.215},"first_byte_ms":{"p50":0.188,"p99":0.314,"p999":0.353}}
{"requests_ok":1000,"requests_dropped":0,"fd_before":12,"fd_after":12}
```

## 4. full 基线（`cargo build --release --features full`，13 个直接依赖，7.9 MB）

| 场景 | 目标速率 | 应答/发送 | 应答率 | p50 | p99 | p999 | 服务端 `dropped` | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| UDP 单源 | 5 000/s | 50 000/50 000 | 100% | 0.030 ms | 0.088 ms | 0.186 ms | 0 | 6 176 kB |
| UDP 8 源 | 5 000/s | 50 000/50 000 | 100% | 0.041 ms | 0.110 ms | 0.242 ms | 0 | 6 144 kB |
| TCP 32 并发 | 200 连接/s | 1 000/1 000 | 100% | connect 0.128 ms / 首字节 0.214 ms | connect 0.215 ms / 首字节 0.391 ms | 0.727 / 1.338 ms | 0 | 6 224 kB |

（lean/full 的差异在回环噪声内；唯一稳定差异是 RSS ≈ +1 MB，因为 TLS/DTLS 代码与
rustls/webrtc-dtls 的静态数据进了进程。二进制 3.5 MB → 7.9 MB。）

> **表格里的 p50/p99 是「某一次运行」的原始值**（每行对应一次完整运行）。发布前门禁不要拿
> 单次值当基线：p99 的基线口径是 §8 的「4 次中位数 / 最差值」，回环亚毫秒量级的重跑波动
> 可达 ±25%，按比例卡会假红。

```json
{"mode":"udp","target_rate":5000,"sources":1,"rate_limit":null}
{"sent":50000,"answered":50000,"answer_ratio":1.0,"achieved_rate":5000.0,
 "latency_ms":{"p50":0.03,"p99":0.088,"p999":0.186,"max":9.434,"mean":0.031}}
{"requests_ok":50000,"requests_dropped":0,"fd_before":11,"fd_after":11,
 "rss_kb_before":6176,"rss_kb_after":6176}
```

## 5. 限速对照（防误伤 + 证明限速真的生效）

两次运行的**唯一差异**是服务端是否带 `--rate-limit 1000`（桶容量默认 2×速率）：

| 组 | 发送 | 应答 | 应答率 | `rate_limited_ip` | `dropped` | p99 |
| --- | --- | --- | --- | --- | --- | --- |
| 未限速 | 20 000 | 20 000 | 100% | 0 | 0 | 0.096 ms |
| `--rate-limit 1000` | 20 000 | 11 999 | 60.0% | 8 001 | 8 001 | 0.113 ms |

- 理论放行量 = `1000 × 10s + burst 2 000 = 12 000`，实测 11 999（1 个包的边界差异；
  复跑同样是 11 999，p99 0.123 ms）；
- **限速没有误伤到「能放行的部分」**：放行请求的 p99 仍是 0.113 ms，与未限速组同量级；
- 拒绝路径是「静默丢弃 + 计数」，客户端看到的是丢包（`lost=8001`），不是 400/500；
- 对照组（`qa-scheduled`）用同一脚本、同一断言，任何一边反转都会 FAIL。

> 本任务没有测「限速表 65 536 条目时的内存/P99」（`rstun-abuse-guard` 的未闭环观察项）：
> 那需要 65 536 个不同源（`--rate-limit-port` 的 ip:port 键），本机可以造，但与
> 「黑盒吞吐基线」是两件事，避免混在一起让基线不可复现。留作后续观察项。

## 6. 容量与延迟随负载（找瓶颈在哪）

| 目标速率 | 实测速率 | 应答率 | p50 | p99 | p999 | 服务端 `dropped` |
| --- | --- | --- | --- | --- | --- | --- |
| 20 000/s | 19 999.7/s | 100% | 0.034 ms | 0.129 ms | 1.20 ms | 0 |
| 50 000/s | 49 999.3/s | 100% | 0.026 ms | 0.451 ms | 3.00 ms | 0 |
| 100 000/s | 83 306/s | 98.65% | 0.022 ms | 95.8 ms | 128 ms | 0 |

解读：前两行说明服务端在 50 000/s 仍然轻松（服务端计数与客户端一致，`dropped=0`）。
第三行**实测速率掉到 83 306/s 且 p99 冲上 95 ms，但服务端一个包都没丢** —— 瓶颈是
单进程 python 客户端：它按 100 k/s 的节奏 `sendto`，却来不及把应答读走，客户端
socket 缓冲溢出（表现为 `answer_ratio < 1`、RTT 里混着排队时间）。所以这张表能说明
「服务端 ≥ 83 k/s」，**不能**说明服务端上限就是 83 k/s。要测真实上限需要多进程客户端
或 C/Rust 压测器，属后续增强项（见 `implement.md` 的观察项）。

## 7. 本地发布前门禁（人工，不进 CI）

沿用 `design.md` §3，**只用于同机、同硬件、同构建参数的发布前对比**：

- p99 ≤ 基线 × 1.3（基线 = §8 记录的历史**中位数**；亚毫秒量级的 p99 不能按比例复现，
  见 §8 —— 1.3× 是「同机对比」的容差，不是跨机器/跨内核的可移植阈值）；
- `send_rate` ≥ 基线 × 0.8（req/s 这一项可以按比例复现，同机重跑 ±10% 内）；
- 超出必须在发布说明里解释（换硬件、换内核、换了监听参数都要说明）。

> 不要把这里的 1.3×/0.8× 与 §8 的「±10%」混用：±10% 只描述**同机重跑的 req/s 与应答率**
> 的可复现性；p99 在回环亚毫秒量级上重跑波动可达 ±25%，所以基线按「中位数 + 最差值」记录，
> 门禁用中位数。

CI（`qa-scheduled.yml` 的 `bench` job）**只上传数值 artifact**，不设阈值：公共 runner
的噪声比阈值大，设硬阈值只会制造假红。

## 8. 复现性与局限

| 项 | 状态 |
| --- | --- |
| 同机重跑（req/s 与应答率） | **±10% 只适用于这两项**。5 000/s 组 4 次：`send_rate` 5 000.0–5 000.1/s（偏差 < 0.01%），应答率恒 100% |
| 同机重跑（p99 / p50） | **亚毫秒量级不能按比例复现**：4 次 p99 = 0.083 / 0.101 / 0.105 / 0.137 ms（中位数 0.103、最差 0.137，±25%），p50 = 0.030 / 0.031 / 0.037 / 0.045 ms。基线口径 = 中位数 + 最差值 |
| 回环 vs 真实网络 | 未覆盖：真实网卡、跨机 RTT、丢包/重排见 `rstun-chaos.sh` |
| 客户端瓶颈 | 100 k/s 以上是 python 单进程的极限，不代表服务端上限 |
| 内存 | 只记 RSS（`/proc/<pid>/status` 前后采样）；未做 65 536 条目限速表的内存曲线 |
| TURN 中继吞吐 | 不在本基线：`rstun-chaos.sh` 的 C6 只验证「配额丢包 + allocation 存活」，吞吐基线待 T2 发布后单独补 |
| CI 平台 | 未验证：`qa-scheduled.yml` 的 bench job 只在 push 后第一次 schedule/dispatch 时才会产生数值 |
