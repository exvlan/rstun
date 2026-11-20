# 质量门禁契约（基准 / 压测 / 混沌 / 覆盖率 / 定时任务）

> 来源：2026-11-20 `rstun-qa`。冷复核曾发现混沌 C2 在边界值假红（`200×1.15 = 229.999…`，实测 1/5 失败），
> 以及 `sendto` ENOBUFS 被记成断言失败。任何改动 `script/lab/rstun-{load,chaos}.sh`、
> `docs/perf.md`、qa 相关 workflow 的提交都必须满足本文。

## 1. Scope / Trigger

- 修改压测/混沌脚本、性能基线、覆盖率作业、定时 workflow；
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

## 5. Good / Base / Bad

- **Good**：整数界 ≥3σ、缺失计数硬失败、端口预检 + 仅 EADDRINUSE 重试、netem 归属跟踪。
- **Base**：`0.95`/`1.15` 这类浮点比例直接写进断言。
- **Bad**：`total > count * 1.15`（边界假红）；`after.get(key, 0)`（缺失当 0）；`info: 跳过断言`。

## 6. Tests Required（断言点）

1. `rstun-load.sh`：未限速 100% 应答且 `dropped=0`；限速组放行 ≈ 理论值且 `rate_limited_ip>0`；放行请求 p99 与未限速同量级。
2. 反证：桩 `/metrics` 缺 counter → exit 1；`ok` 冻结 → exit 1。
3. `rstun-chaos.sh`：`--only reorder` 连跑 **8 次全绿**（含恰好 230 应答的一次）；整盘 3 次全绿；结束后 `qdisc noqueue`、`lo mtu 65536`。
4. 覆盖率：lcov 的 `SF:` 只含源文件（不含 `tests_interop.rs`）；summary 与 lcov 口径一致。
5. workflow：`yaml.safe_load` 通过；`permissions` 含 `issues: write`；action 全为 40 位 SHA。

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
