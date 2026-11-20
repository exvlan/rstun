# 执行计划：qa

> 前置：T1/T2 已完成并归档；`docs/browser-acceptance.md` 里的浏览器验收待办在本任务第 7 步。
> 本任务不改服务代码；只新增脚本/文档/workflow。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | `script/lab/rstun-load.sh`：UDP 吞吐/延迟（单源 + 多源 127.0.0.x）、`--json`、自起自停、限速开/关对照 | 本机跑出两张对照表；限速组丢弃 > 0、未限速组为 0 | 新增文件 |
| 2 | TCP 连接洪水与首字节延迟（复用脚本 `--mode tcp`） | fd 回落、进程存活 | 同上 |
| 3 | `docs/perf.md`：硬件/构建参数/命令/原始输出/结论 + **lean vs full** 两组基线 | 数字可复现（同机重跑 ±10%） | 文档 |
| 4 | 混沌脚本 `script/lab/rstun-chaos.sh`：C1–C6（netem；无 root 则 SKIP + 原因） | 每例断言明确；`--list` 可单跑 | 新增文件 |
| 5 | 覆盖率：CI 加 `cargo llvm-cov`（`--ignore-filename-regex` 排除测试模块），上传 artifact；本地 `--fail-under-lines 80` 可选 | CI 出现报告；无硬门禁（先观察一版） | workflow |
| 6 | `qa-scheduled.yml`：每周 cron + 手动；fuzz 10 分钟（崩溃→`gh issue create`）、`rstun-interop.sh all`（容器化依赖）、基准冒烟（存数值） | 手动 dispatch 跑通；schedule 语法正确 | 新增文件 |
| 7 | **浏览器 `turns:` 验收**（承接 T2 R4）：在合格环境（同主机/同网或可达地址 + 受信证书）执行 `docs/browser-acceptance.md` 步骤，归档截图/日志 | `typ relay` 候选 + 服务端 `bytes_total` 增长 | 文档 + 证据 |
| 8 | 观察两周：定时任务 flaky 记录；`docs/perf.md` 与 README 链接 | 两周内无未解释的红 | 文档 |

## 门禁

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all       # 42 项
bash script/lab/rstun-abuse.sh             # 10 组
bash script/lab/rstun-turn.sh              # lean 15 passed + 2 skipped
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000   # 新增
bash script/lab/rstun-chaos.sh             # 新增；无 root 时 SKIP 并说明
```

## 验收断言（必须）

- [ ] `rstun-load.sh` 的限速对照：开限速组 `dropped > 0` 且总吞吐受控；未限速组 `dropped = 0`
- [ ] `docs/perf.md` 含 lean/full 两组基线 + 硬件说明 + 复现命令
- [ ] 混沌 ≥5 例可用；每例有明确断言；无 root 时 SKIP 文案清楚
- [ ] CI 覆盖率报告可见（非阻塞）；`--ignore-filename-regex` 生效
- [ ] `qa-scheduled.yml` 手动 dispatch 跑通（fuzz + interop + 基准冒烟）
- [ ] 浏览器 `turns:` 验收在合格环境执行并归档证据（承接 T2 R4）
- [ ] 两周观察期结束，flaky 有记录

## 风险

| R | 缓解 |
| --- | --- |
| 基准噪声 | 本地阈值、CI 只存值 |
| `tc` 权限 | SKIP + 原因；文档写清本地命令 |
| 定时任务额度 | 每周一次；public 仓免费 |
| 浏览器验收仍无环境 | 保持为**未完成待办**并如实记录，不得勾选 |

## 执行记录（2026-11-20，第 1–6 步完成；7/8 为未完成待办）

| # | 事项 | 状态 | 证据 |
| --- | --- | --- | --- |
| 1 | `script/lab/rstun-load.sh`（UDP 吞吐/延迟、`--sources`、`--json`、自起自停、限速对照） | ✅ | 10 s × 5 000/s：50 000/50 000 应答、p99 0.083 ms；`--rate-limit 1000`：11 999/20 000 + `rate_limited_ip=8001`（见 `docs/perf.md` §5） |
| 2 | TCP 连接洪水 + 首字节（同一脚本 `--mode tcp`） | ✅ | 1 000/1 000 成功、connect p99 0.177 ms、fd 12 → 12 |
| 3 | `docs/perf.md`（硬件/命令/原始输出/结论 + lean/full 两组） | ✅ | `docs/perf.md`；lean p99 0.083–0.137 ms / full 0.085–0.110 ms，RSS 5.2 MB vs 6.2 MB |
| 4 | `script/lab/rstun-chaos.sh` C1–C6（netem；无 root SKIP） | ✅ | 6/6 通过；C1 首轮丢 66/300、重传后 300/300；C2 单请求 ≤2 应答、服务端 `dropped=0`；C4/C5 连接 29.5 s 后被回收；C6 `bytes_dropped` 0 → 78 336 且 allocation 存活 |
| 5 | `ci.yml` 加 `cargo llvm-cov`（非阻塞 + artifact） | ✅ | 本地 `--all-features --summary-only`：行 87.05%、区域 88.42%（排除 `tests_interop.rs`/`tests/`/`fuzz/`）；CI 里 `report` 也带同一 `--ignore-filename-regex` |
| 6 | `.github/workflows/qa-scheduled.yml`（cron + dispatch；fuzz/interop/bench） | ✅（YAML/命令层） | `yaml.safe_load` 通过；action 全部固定 SHA。**未在 GitHub 上真跑过**（本任务禁止 push），cron 与 dispatch 的实际执行留待首次 push 后确认 |
| 7 | 浏览器 `turns:` 验收（承接 T2 R4） | ⏳ 未完成 | 本机没有可达的 WebRTC 浏览器环境（in-app 浏览器只代理页面加载），与 `docs/browser-acceptance.md` 记录一致；**不得勾选**，证据要求不变 |
| 8 | 两周观察（定时任务 flaky / 数值趋势） | ⏳ 后续 | 从首次 push 起算，两周后回填 flaky 记录与数值趋势 |

### 与 design.md 的有意偏差（逐条）

1. **C3 的断言从「响应 ≤ 请求」改为「响应 = 请求 + 固定 32 字节」**：服务端会回显
   `PADDING`，实测 `PADDING 1400` → 1424/1456（+32）、`PADDING 8000` → 8024/8056（+32）。
   「响应 ≤ 请求」在回显语义下数学上做不到；可执行口径是「放大 ≤ 1.03×，且多出的就是固定
   32 字节头开销」。已写进脚本输出与 `script/lab/README.md`。
2. **C3 的分片是 opt-in（`--mtu 1500`）**：默认 `lo` MTU 是 65536，不强制就**没有**分片。
   默认路径如实打印「未强制分片」，`--mtu` 会在退出时恢复原值；不冒充「分片已验证」。
3. **设计的「基准冒烟（记录数值）」用 release 构建 + 3 条命令**（udp 5 000、限速对照、
   tcp 200），不是全矩阵：public runner 只适合存数值，铺开更多组只会增加噪声与时长。
4. **`docs/perf.md` 的容量结论标了「客户端瓶颈」**：100 000/s 目标下实测 83 306/s 而服务端
   `dropped=0`，说明上限在单进程 python 客户端。真实上限需要多进程/C 压测器，记为后续增强。
5. **未测「限速表 65 536 条目」的内存与 P99**（`rstun-abuse-guard` 的未闭环观察项）：与
   黑盒吞吐基线混在一起会让基线不可复现，留作后续观察项（`docs/perf.md` §5 已记）。
6. **覆盖率排除是文件级**：`main.rs` 内的 `#[cfg(test)] mod tests` 仍计入（llvm-cov 只能
   按文件排除，按模块排除要改源码结构，本任务不改服务代码）。CI 注释里写明了这一点。

### 后续观察项（需要时间或环境，不在本轮）

- 第 7 步：浏览器 `turns:` 验收（`typ relay` 候选 + 服务端 `bytes_total` 增长 + ≥1 方对称 NAT）。
- 第 8 步：`qa-scheduled.yml` 首次 push 后的实际运行结果；两周内 flaky 记录。
- 限速表 65 536 条目时的 RSS / P99（需要 65 536 个 `ip:port` 源）。
- 多进程或非 python 压测器，用于测服务端真实吞吐上限（当前只证明 ≥ 83 k/s）。
- TURN 中继吞吐基线（C6 只覆盖配额丢包 + allocation 存活）。
- **已知 flaky（环境）**：`rstun-turn.sh --only coturn` 的 coturn REST 探针在机器繁忙时会
  `probe aborted: timed out`（本机 `ip_local_port_range = 1024 65535`，coturn 的 relay 端口
  可能被临时连接占住）；同机空闲重跑为绿。修法应落在 `rstun-turn.sh`（给 coturn 的 relay
  端口段做占用预检 / 提高首次挑战超时），不在本任务范围。
- 混沌脚本的端口预检/重试是**环境适配**，如果上游换成 `ip_local_port_range` 正常的主机，
  这段逻辑仍然有效（只是很少触发 `WARN`）。

## 冷复核修复记录（2026-11-20，B1 + #2–#12）

| 项 | 状态 | 修法与证据 |
| --- | --- | --- |
| **B1** C2 放大断言假红 | ✅ | ① 上界改整数 `count * 135 // 100`（200 → **270**，>3σ），`server_ok` 用同界；② 修掉更深的根因：一次性灌 200 个 datagram 时，netem `delay 20ms` 把包攒在发送缓冲，内存紧张时 `sendto` 抛 `ENOBUFS` → 探针 traceback 退出 → `check()` 记成「断言失败」（实测一次失败里服务端只收到 **108/200**，与 ~212 KB 默认 `SO_SNDBUF` / 每个 loopback skb 的 truesize 吻合）。现改为 **`SO_SNDBUF=1 MB` + 1 ms 间隔发送 + `sendto` 退避重试**（连续 50 次才 FAIL，消息带 errno）。证据：最终版 `--only reorder` **8/8 exit 0**（其中一次客户端收到 **230** 个应答 —— 正是旧界 `200 × 1.15 = 229.999…` 会判红的值）；整盘混沌 **3/3 全绿**（gate-final2，run 2 因启动预检自动换到 35182/35183）；未 pacing 的对照版 20/20 也绿 ⇒ 该 flake 是环境/内存压力相关，不能只靠"重现"证明，故同时把失败模式改成可读的 FAIL |
| #2 perf.md 的 ±10% 口径 | ✅ | 「±10%」**只**描述同机重跑的 req/s 与应答率；p99 按「中位数 0.103 / 最差 0.137 ms」记录并注明亚毫秒不可按比例复现（±25%）；§7 的 1.3× 明确为**同机发布前对比**，不与 ±10% 混用 |
| #3 C3 界与文案不一致 | ✅ | `overhead > 64` → `overhead not in (0, 32)`，文案写明「允许 0（不回显 PADDING）/32（回显）」 |
| #4 C2 计数不可用算通过 | ✅ | `dropped` 读不到 → **FAIL**（「计数自洽无法判定」），不再 `info` 跳过 |
| #5 load 的空断言 | ✅ | `delta()` 两侧缺 key 返回 `None` → `counter missing: <key>` FAIL；新增 `requests_ok ≥ sent×95%`（限速组用 `answered×95%`）。桩 `/metrics` 实测：缺 3 个 counter → exit 1；ok 冻结 0 → `FAIL: 服务端 ok=0 < 1000 x 95%` |
| #6 achieved_rate 不可比 | ✅ | JSON 增 `result.send_rate = 发送数/目标时长`；`achieved_rate` 注明含 1s 收尾（限速组 -8~10%）；README + perf.md §2 写清跨组比较用 `send_rate` |
| #7 限速失败文案归因 | ✅ | 文案带「假设客户端 ≈ 2× 桶速率」+ 理论放行量/占比；假设不成立时显式写「假设不成立」（实测 `--rate 1000 --rate-limit 2000`） |
| #8 成功摘要不可见 | ✅ | 成功时把 `ok:` 摘要 grep 到 stderr（`| tail` 直接看到应答率/分位/counters）；`--json` 时 stdout 仍只有 JSON |
| #9 JSON 不自描述 | ✅ | 新增 `generated_at`（UTC ISO8601）、`rstun_version`、`features`（从启动日志 `software=rstun/<v>` / `features="…"` 读，缺失回落 `--version`/`unknown`）、`notes` |
| #10 interop SKIP 白名单 | ✅ | 只允许 `probe/ipv6`、`webrtc-stun/ipv6`（容器 IPv6 未验证）；其余 SKIP 红。用样例日志验证：只留 `coturn` 那条被判红、仅 ipv6 时为空 |
| #11 fuzz issue 去重 | ✅ | 改固定 label `fuzz`（`gh label create fuzz … \|\| true` + `gh issue list --label fuzz --state open`），弃用不可靠的标题 `--search` |
| #12 目录/磁盘排障 | ✅ | 两脚本 `mkdir -p` 失败 → `日志目录不可写` + exit 2；启动打印 `df -h` 一行（load 还打印 `rstun/<v>（features=…）`） |

> 约束核对：`src/**`、`Cargo.toml` 未改；netem 归属跟踪（`NETEM_OWNED`）与 `--mtu` 恢复逻辑未削弱（整盘跑完 `lo` 仍为 `qdisc noqueue` / MTU 65536）。

### B1 的诊断过程（记下来，避免下次重复踩）

1. 复现：整盘混沌第 1 次在 C2 失败，`summary.log` 只有「探针断言失败」——**探针输出没落盘**，
   无从定位。先补 `probe.log`（`run_probe` 用 `tee`），并在 C2 记录客户端发送数/覆盖数/服务端 ok。
2. 找到证据：失败那次的服务端日志是 `received=108 answered=108`（客户端声称发了 200）。
   108 ≈ 212 KB / ~2 KB（loopback skb truesize）——指向**发送侧缓冲**，不是服务端丢包。
3. 排除误判：单独做「服务端刚起 + netem delay 20ms + 200 个 unpaced sendto」6 次 → 6/6 正常；
   未 pacing 的完整 C2 对照版 20/20 也正常 ⇒ 触发条件是系统内存压力（本机 96 GB 用 62 GB、
   磁盘 99%），不是稳定可复现的时序问题。
4. 修法：`SO_SNDBUF=1 MB`（降低 wmem 耗尽概率）+ 1 ms 间隔（压低在途字节）+ `OSError` 退避
   重试（把"静默 traceback"变成可读 FAIL）。因为不能稳定复现，额外保留了可诊断性：
   `probe.log`、`tc -s qdisc`、`/metrics` 抓取失败与计数为 0 分开判定。

### 另一个 flaky 来源：本机临时端口范围覆盖全部非特权端口

- `cat /proc/sys/net/ipv4/ip_local_port_range` = **`1024 65535`**：任何固定端口都可能被
  内核分配给别的进程当**源端口**，于是 `bind` 偶发 `Address already in use (os error 98)`。
  实测：整盘混沌 run 1 的 C4/C5 各失败一次（服务端日志只有一行 bind 错误），随后 run 2/3 全绿。
- 混沌脚本已修：启动时 `pick_ports` 预检（UDP + TCP + health TCP 三次 bind，最多 200 个候选，
  打印实际端口），运行期 `start_server` 只针对 `Address already in use` 换端口重试 ≤3 次。
  验证：gate-final2 的 chaos run 2 自动选到 `35182/35183`（说明预检生效），run 1/3 用 `35180/35181`。
- 同一环境问题也解释了 `rstun-turn.sh --only coturn` 的偶发失败（coturn 的 REST 探针
  `FAIL: probe aborted: timed out`，同参数重跑即绿）：coturn 的 relay 端口落在临时端口范围内，
  可能被临时连接占住。**这是环境/夹具层面的已知 flaky，不是协议回归**，已记入观察项；
  本任务不改 `rstun-turn.sh`（不在复核范围）。

