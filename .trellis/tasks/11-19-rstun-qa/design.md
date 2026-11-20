# 设计：质量与性能（qa）

## 1. 边界

- 只做**度量与门禁**，不改协议/服务行为；所有产物落 `docs/perf.md`、`script/lab/`、CI workflow。
- 基准**不在 CI 设硬阈值**（公共 runner 噪声大）：CI 只保证「能跑、无崩溃、覆盖率不降」；
  硬阈值只在**本地发布前**人工对比。
- 混沌用例需要 `tc`/NET_ADMIN：本地脚本必跑；CI 里可选项（runner 有 sudo，`lo` 上 netem 可用），
  失败时以「SKIP + 原因」呈现，不伪装通过。

## 2. 度量口径

| 维度 | 测什么 | 工具 | 输出 |
| --- | --- | --- | --- |
| 吞吐 | UDP Binding req/s（单/多源）、TCP 连接建立速率 | 自写客户端（`script/lab/rstun-load.sh` + 内嵌 Rust/py 探针）| `docs/perf.md` 表格 |
| 延迟 | p50/p99/p999（UDP）、TCP 首字节 | 同上 | 同上 |
| 限速 | 开/关 `--rate-limit` 的吞吐与丢弃比（防误伤证据）| 同上 | 对照表 |
| 内存 | RSS 随连接/分配/限速表条目增长 | `/proc/<pid>/status` 采样 | 曲线摘要 |
| 覆盖率 | 行/分支（整体 + 协议模块） | `cargo llvm-cov` | CI artifact + 摘要 |
| fuzz | 解析路径 10 分钟无崩溃 | `cargo +nightly fuzz` | 定时 job + 崩溃即开 issue |

> **微基准（`decide()`）暂不做**：`rstun` 目前是 bin-only crate，criterion 需要 lib target。
> 抽 `src/lib.rs` 是结构性改动（会影响 main.rs 与所有测试的可见性），本任务**只做黑盒端到端**；
> 若将来需要函数级基准，单独立项并先评估 lib 化对冻结测试的影响。

## 3. 基准与阈值

- `docs/perf.md` 记录：硬件（CPU/内存/内核）、构建参数（`--release`、lean/full）、
  命令、原始输出片段、结论。
- **本地发布前门禁（人工）**：p99 ≤ 基线 × 1.3、req/s ≥ 基线 × 0.8；超出必须在发布说明里解释。
- CI 不设阈值，只上传数值 artifact 供趋势对比。

## 4. 混沌用例（≥5）

| # | 场景 | 注入 | 断言 |
| --- | --- | --- | --- |
| C1 | UDP 丢包 10% | `tc qdisc add dev lo root netem loss 10%` | 服务不崩；客户端可见丢包但能重传成功 |
| C2 | 乱序/重复 | `netem delay 20ms reorder 25% 50% duplicate 5%` | 响应不重复放大；统计计数自洽 |
| C3 | MTU/分片 | `netem` + 大 `PADDING`（1400/8000） | 响应 ≤ 请求（不放大）；无 panic |
| C4 | TCP 半包 | 客户端发半个帧后停止 | 服务端超时回收（`TCP_READ_TIMEOUT`），不泄漏连接 |
| C5 | 半开连接 | 建立后不读不写 | 受 `--max-inflight`/超时约束，fd 回落 |
| C6 | TURN 中继丢包 | netem 作用于 relay 端口 | allocation 存活；`bytes_dropped` 增长 |

## 5. CI 形态

| 工作流 | 触发 | 内容 |
| --- | --- | --- |
| `ci.yml`（已有）| push/PR | 单测（lean+full）、clippy、fmt、冒烟、`cargo audit`；**新增覆盖率上传**（非阻塞）|
| `qa-scheduled.yml`（新）| 每周 cron + 手动 | fuzz 10 分钟（失败即开 issue）、`rstun-interop.sh all`（容器化 coturn/go）、基准冒烟（记录数值，不设阈值）|
| 混沌 | 本地脚本 | CI 里可选 job（`sudo tc`），失败标 SKIP |

- 所有 action 用固定 SHA；`schedule` 只跑一份（避免矩阵浪费）。
- 额度：public 仓免费；每周一次可接受。

## 6. 数据流（基准脚本）

```
script/lab/rstun-load.sh --mode udp --rate N --duration D --sources S
  ├─ 起 rstun（指定监听/限速开关）
  ├─ 启动 S 个客户端（不同源端口/地址别名），按固定速率发 Binding
  ├─ 记录：发送数/应答数/丢弃数、p50/p99/p999（客户端侧）、服务端 counters
  └─ 输出 JSON + 人读表格；--json 供 CI artifact
```

## 7. 兼容与回滚

- 只新增脚本/文档/workflow；不改服务代码 → 回滚 = 删除新增文件。
- 覆盖率与定时任务均为**非阻塞**（除 fuzz 崩溃开 issue）；`ci.yml` 的既有门禁不变。

## 8. 风险

| R | 缓解 |
| --- | --- |
| 公共 runner 噪声导致假红 | 阈值只在本地；CI 只存数值 |
| `tc` 需要 root | 本地 sudo 脚本；CI 失败 SKIP 并写原因 |
| 定时任务 flaky 消耗注意力 | 先跑两周观察；flaky 用例标 `#[ignore]`/SKIP 并记账 |
| 覆盖率把大量测试代码算进去 | 用 `--ignore-filename-regex` 排除 `tests_interop`/`tests` 模块 |
