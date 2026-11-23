# 质量门禁契约（基准 / 压测 / 混沌 / 覆盖率 / 定时任务）

> 来源：2026-11-20 `rstun-qa`。冷复核曾发现混沌 C2 在边界值假红（`200×1.15 = 229.999…`，实测 1/5 失败），
> 以及 `sendto` ENOBUFS 被记成断言失败。任何改动 `script/lab/rstun-{load,chaos}.sh`、
> `docs/perf.md`、qa 相关 workflow 的提交都必须满足本文。

## 1. Scope / Trigger

- 修改压测/混沌脚本、性能基线、覆盖率作业、定时 workflow；
- 修改 `.github/workflows/schedule-guard.yml`（定时作业的 staleness 守卫，见 §5.2）；
- 新增任何「会失败」的断言（基准阈值、混沌判据）。

## 2. Signatures

| 项 | 契约 |
| --- | --- |
| `rstun-load.sh` | `--mode udp\|tcp`、`--rate`、`--duration`、`--sources`、`--rate-limit`、`--global-rate`、`--json/--out`、`--profile release\|debug` |
| 延迟分位 | **只统计成功应答**（超时/错误不入样本）；空样本返回 `None`，不得当 0 |
| `send_rate` | 发送数 / **目标时长**（不含 1s 收尾窗口）；`achieved_rate` 含收尾，**跨组比较只用 `send_rate`** |
| 计数器 | `delta()` 两侧必须都有该 key；缺失 → **FAIL**（`counter missing: <key>`），不得按 0 处理 |
| 限速期望 | 放行量 ≈ `burst(=2×rate) + rate × duration`；客户端速率应≈桶速率 2×，否则失败文案必须写明「假设不成立」 |
| `rstun-chaos.sh` | C1–C6；`--list/--only/--mtu`；需 `tc`，无 root → **SKIP + 原因** |
| 混沌上界 | **整数比较**且 ≥3σ（当前 1.35×）；禁止浮点边界（`count*1.15` 会因 `229.999…` 假红）|
| 覆盖率 | `--ignore-filename-regex` 必须**同时**作用于 lcov 与 `report --summary-only`；CI 非阻塞 + artifact |
| 定时任务 | 每周 cron + `workflow_dispatch`；action 固定 SHA；`permissions: {contents: read, issues: write}` |
| `schedule-guard.yml` | 触发 `schedule`（每日 06:00 UTC）+ **`push` 到 `main`** + `workflow_dispatch`（`max_age_days` 默认 8、`dry_run` 默认 false）；`permissions: {contents: read, issues: write, actions: read}`（`actions: read` 是 `gh run list` 必需，缺了会 403）|
| 守卫判据 | 只认 `event=schedule` 的运行；`age > max_age_days` 或 **0 次运行** → stale。手动 `workflow_dispatch` **不计入**（它产生的 run 不是 schedule）|

## 3. Contracts（数据与判据）

| 指标 | 口径 |
| --- | --- |
| `p50/p99/p999` | 客户端单调时钟，仅成功应答；**亚毫秒量级不可按 ±10% 复现**（实测 0.08–0.23，±25%）；基线记「中位数/最差」两值 |
| req/s、应答率 | 同机重跑 ±10% 可复现 |
| 发布前门禁 | **同机**对比：p99 ≤ 基线 × 1.3、req/s ≥ 基线 × 0.8；超限须在 release notes 解释。CI **不设硬阈值** |
| 混沌 C2 | 客户端总应答 ∈ `[count, count×1.35]`；服务端 `ok` 同界；`dropped` 必须为 0 且**计数可读**（读不到即 FAIL）|
| 混沌 C3 | 回显 `PADDING` 时响应 = 请求 + **32**（固定 XOR-MAPPED）；界用 `overhead not in (0, 32)` |
| 端口 | 启动前三次 bind 预检（UDP/TCP/health）；**只对 EADDRINUSE** 重试换端口 ≤3 次，其它启动错误不得重试 |
| netem | 只删自己加的 qdisc；退出恢复 MTU 与 qdisc；`--mtu` 才强制分片（默认如实标注「未强制」）|
| 客户端发送 | `SO_SNDBUF=1 MiB` + ≥1ms 间隔 + `sendto` 退避重试（ENOBUFS 属环境，不得记成断言失败）|
| JSON | 自描述：`generated_at`（UTC）、`rstun_version`、`features`（lean/full）、`missing_counters`、`notes` |

## 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| `/metrics` 缺 key | FAIL（不是 0、不是跳过）|
| 服务端 `ok` 冻结/为 0 | FAIL（`ok ≥ sent×95%` 守卫）|
| 无 root 跑混沌 | 每例 SKIP + 原因；整体 exit 0 但汇总打印 `skipped: N` |
| 日志目录不可写 | `exit 2` + 明确文案；启动打印 `df -h` 一行 |
| 定时任务里环境性 SKIP | 仅白名单（`probe/ipv6`、`webrtc-stun/ipv6`）；其它 SKIP 红 |
| fuzz 崩溃 | 用固定 label（`fuzz`）+ `gh issue list --label fuzz --state open` 去重；无则创建 |
| 守卫检测到 stale | 正常模式 **exit 0**（可见性靠 issue）；只在 `dry_run=true` 时 exit 1（演练断言）|
| 守卫的 issue 写入失败 | **exit 1**（守卫自己坏了必须可见，不能被当成 OK）|
| 守卫读不到 run 列表（workflow 名改了 / 403） | **exit 1** + `::error::`，不得把「查不到」当成「刚跑过」|
| 守卫读不到 open issue 列表（去重无法判定） | **exit 1** + `::error::`（search 分支可吞错，全量回退**不可**：吞掉会静默重复建 issue）|
| 守卫 `max_age_days` 非整数 / 负数 | `::error::` + `exit 2`（不猜、不夹取）|

## 5. Good / Base / Bad

- **Good**：整数界 ≥3σ、缺失计数硬失败、端口预检 + 仅 EADDRINUSE 重试、netem 归属跟踪。
- **Base**：`0.95`/`1.15` 这类浮点比例直接写进断言。
- **Bad**：`total > count * 1.15`（边界假红）；`after.get(key, 0)`（缺失当 0）；`info: 跳过断言`。

### 5.1 性能基线的测量契约（2026-11-21 重测时确立）

- **必须记录背景负载**：`docs/perf.md` 的每次运行样本要带同期的系统 busy%（本机并行 agent 会话可让
  p99 波动 2–3×）。引用 p99/p999 做前后对比时，**必须同时引用 busy%**，否则结论不可比。
- **`rstun-load.sh` 的 ≥95% 应答率断言在 100 k/s 会假红**：单进程 python 探针饱和时
  （实测 92.44% / 82.72%）服务端仍是 `ok=500000`、`dropped=0`。
  判定口径以**服务端** `dropped`/`ok` 为准；不要把该断言当成服务端容量门禁，
  也不要把 100 k/s 的客户端数字写成「服务端上限」。
- 二进制必须是**本次构建且版本串可核**（`RSTUN_BUILD_VERSION` 注入，与 CI 同法）；
  lean/full 两组要按 `features` 字段逐条核对，防止「lean 标签跑了 full 二进制」。

### 5.2 定时作业的 staleness 守卫（2026-11-23 确立）

- **事实**：2026-11-23 盘点发现本仓**从未有过任何 `event=schedule` 的运行**
  （`gh api "repos/exvlan/rstun/actions/runs?event=schedule" --jq .total_count` → `0`），
  而 `QA scheduled`（周一 04:00 UTC）与 `Verify platforms`（周四 06:00 UTC）状态都是 `active`、
  仓库非 fork、Actions 开启、`main` 持续有推送。周度回归可能一直静默未跑。
- **检查对象**：`QA scheduled`、`Verify platforms`（workflow 显示名；
  `gh run list --event schedule --workflow <name>` 解析，名字写错时 gh 非 0 退出 → 守卫红）。
- **阈值**：默认 **8 天** = 周度 1 个周期 + 1 天余量；**从未运行**同样算 stale
  （`age` 记 `-`，不是 0）。
- **为什么必须含 `push` 触发**：cron 整体失效时，只靠 cron 的守卫自己也不会跑 ——
  那时守卫与它守护的对象一起消失，等于没有守卫。`push` 到 `main` 是唯一的独立通道。
- **issue 语义**：标题固定 `[schedule-guard] <workflow> 的定时运行已停滞`；同标题只保留一条
  open issue（`--search` 后**精确比对标题**，search 未命中再回退全量 open 列表 —— 搜索索引会漏）；
  stale 时不每天刷评论；恢复（出现新的 schedule run 且年龄 ≤ 阈值）时评论「已恢复」并自动关闭。
- **手动补跑 ≠ 恢复**：`gh workflow run` 产生的是 `workflow_dispatch` run，不会清掉告警；
  它只补回归覆盖。
- **手动关闭 issue 无效**：守卫去重只看 `state=open` 的同标题 issue，stale 未解除时下一次
  `push` / 次日 cron 会**重建同标题 issue** —— 这是预期行为，不是守卫 bug。
  真正销账只有两条路：① 平台定时触发恢复（出现新鲜 `event=schedule` run → 自动评论 + 关闭）；
  ② 改守卫的目标列表 / 阈值并提交（书面承认不再按周监控该作业）。

## 6. Tests Required（断言点）

1. `rstun-load.sh`：未限速 100% 应答且 `dropped=0`；限速组放行 ≈ 理论值且 `rate_limited_ip>0`；放行请求 p99 与未限速同量级。
2. 反证：桩 `/metrics` 缺 counter → exit 1；`ok` 冻结 → exit 1。
3. `rstun-chaos.sh`：`--only reorder` 连跑 **8 次全绿**（含恰好 230 应答的一次）；整盘 3 次全绿；结束后 `qdisc noqueue`、`lo mtu 65536`。
4. 覆盖率：lcov 的 `SF:` 只含源文件（不含 `tests_interop.rs`）；summary 与 lcov 口径一致。
4a. interop 的 **Go 依赖下界**：`pion/stun v3` 的 `go.mod` 要求 **go 1.24.0**，
   而 Ubuntu 24.04 / `buildpack-deps:trixie` 的 `golang-go` 是 1.22.x —— 用 apt 版会触发
   `GOTOOLCHAIN=auto` 下载，CI 网络下失败（表现为 `FAIL pion`，细节只在
   `$RSTUN_INTEROP_DIR/logs/pion-build.log`）。因此 preflight/qa 必须用
   `actions/setup-go`（`go-version: 1.24.x`）并**从 apt 列表移除 `golang-go`**，
   同时保留 `go >= 1.24` 断言；interop 失败时必须打印 `*build*.log` 尾部。
5. workflow：`yaml.safe_load` 通过；`permissions` 含 `issues: write`；action 全为 40 位 SHA。
5a. `schedule-guard.yml`（判据与退出码逐条实测）：
    `max_age_days=8` 对 0 次 schedule 运行 → 两个目标都 `STALE`（`never`）、exit 0；
    `max_age_days=0` 重跑 → 同一标题**不重复建** issue（去重生效）；
    桩 `gh run list` 返回 2 小时前的 run → `OK`、无 issue、summary 显示 OK；
    桩「已存在同名 open issue」+ OK → 评论「已恢复」并 close；
    `dry_run=true` + stale → 不建 issue 且 **exit 1**；
    `max_age_days` = `abc` / `-1` / `1.5` → `::error::` + exit 2；
    桩 `gh run list` 非 0 → `::error::` + exit 1（不得当成 OK）。

## 7. Wrong vs Correct

#### Wrong
```python
if total > count * 1.15:            # 200*1.15 == 229.999… → 230 被误判
    fail(...)
after_value = after.get(key, 0.0)   # 缺失当 0 → 负 delta / 空断言
```

#### Correct
```python
limit = count * 135 // 100          # 整数、>3σ
if total > limit:
    fail(...)
if key not in after:
    fail(f"counter missing: {key}")
```
