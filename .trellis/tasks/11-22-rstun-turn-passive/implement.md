# 执行计划：RFC 6062 被动模式

> 顺序：先「能收连接 + 能通知」，再「能 bind + 数据」，最后 lab 与文档。不 bump 版本（发版由主会话决定）。

## 阶段 0 · 结构与常量

| # | 事项 | 验证 |
| --- | --- | --- |
| 0.1 | `CONNECTION_ATTEMPT_METHOD = 0x00c`；**不**新增 `Allocation.sink` 字段：把 `ClientSink`/`state`/`key`/`username` 的 clone 交给 accept 任务（避免 `Arc<Allocation>` 循环）| 既有测试全绿（行为不变） |
| 0.2 | `Allocation.accept_task: Option<JoinHandle<()>>`；`Drop`/`remove` abort | 单测：移除 allocation 后任务结束 |

## 阶段 1 · accept 循环

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | TCP allocation 创建后 spawn accept 任务（`tcp_relay` 开着才 spawn）| 单测：连 relay listener 被接受 |
| 1.2 | permission 检查（`state.permissions` 含 peer IP 且未过期）→ 无则立刻关闭 | 单测 + lab 负例（无 indication） |
| 1.3 | 配额 16 / 预缓冲 64 KiB / pending 30s 复用既有逻辑 | 单测（第 17 条被关、缓冲溢出、30s sweep） |

## 阶段 2 · `ConnectionAttempt` indication

| # | 事项 | 验证 |
| --- | --- | --- |
| 2.1 | 编码：indication + `CONNECTION-ID (0x002a)` + `XOR-PEER-ADDRESS` [+ `SOFTWARE`] | 单测：解码断言属性与值 |
| 2.2 | 通过 `ClientSink` 发送（Udp → `send_to`；Queue → `try_send`）| 单测：UDP 控制面能收到；TCP 控制面 queue 收到 |
| 2.3 | 发送失败（控制连接已死）→ 丢弃该入站连接 + 计数 | 单测 |

## 阶段 3 · bind 与数据面

| # | 事项 | 验证 |
| --- | --- | --- |
| 3.1 | 入站 `TcpConnection` 直接 `Pending`；`ConnectionBind` 既有逻辑复用（不改）| 单测：bind 成功、错 id/过期失败 |
| 3.2 | 双向裸字节 + 预绑定缓冲先刷出 + 半关闭联动 | 单测（沿用出站用例的断言风格）|
| 3.3 | `LIFETIME=0`/过期 → 入站连接被关、accept 任务 abort、端口可重绑 | 单测 + `ss -ltnH` |

## 阶段 4 · lab 与文档

| # | 事项 | 验证 |
| --- | --- | --- |
| 4.1 | lab 新增 `tcp-relay-passive` 项：`uclient -P` 断言双向字节 > 0 且 exit=0（**不**用 `uclient_ok`）| `--only tcp-relay-passive` |
| 4.2 | `uclient -T` 回归（含 `-y`）| 同项或 `tcprelay` 扩展 |
| 4.3 | 无 permission 负例：控制连接 5s 内无 `ConnectionAttempt`、peer 连接被关 | lab 断言 |
| 4.4 | 控制面 UDP 与 TCP 各一次 indication 实测 | 探针 |
| 4.5 | 文档：`docs/book/src/turn.md` 行为表（被动模式：支持什么/不支持什么）、`spec/backend/turn.md`、`CHANGELOG ## Unreleased` | `check-docs` |

## 门禁（每阶段）

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-turn.sh
bash script/lab/rstun-turn.sh --tls --dtls
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/ci/check-docs.sh --no-build
cargo audit; echo "audit=$?"
cargo deny check
```

## 验收断言

- [ ] `uclient -P`：双向字节 > 0、exit=0（不用 `lost packets 0`）
- [ ] `uclient -T`（`-y`）：两端都能完成（此前 0 recv）
- [ ] 无 permission → 关闭且无 indication（lab + 单测）
- [ ] UDP 与 TCP 控制面各收到一次 `ConnectionAttempt`
- [ ] 30s 未 bind 关闭；`LIFETIME=0` 级联关闭；端口可重绑（`ss -ltnH`）
- [ ] 默认路径冻结不变（`FROZEN_BASE=cad4fa2` 3×17）
- [ ] 开关关闭时行为与 `.106` 完全一致

## 回滚

单 commit（或两个：accept+indication / bind+lab）；revert 即回到只剩出站。
