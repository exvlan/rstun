# 执行计划：TURN 多实例

> 三个里程碑各自独立可发布、独立可回滚。**M1 之前不改任何 TURN 行为**（新增字段全 `None`）。
> 每个里程碑结束都要跑全套门禁，并把结论写进本文件末尾的「进度」。

## 里程碑 0 · 骨架与配置（不改行为）

| # | 事项 | 位置 | 验证 |
| --- | --- | --- | --- |
| 0.1 | 新增 `src/cluster.rs`：帧编解码、HMAC、成员环（`ring`, `owner_for(key)`）、连接管理骨架 | 新文件 | 单测：帧往返、HMAC 错误拒绝、环稳定性（同 key 恒同 owner）|
| 0.2 | 归一化键 + 规范化 `Key.server`（D2/D3） | `turn.rs:476-480` 附近 | 单测：UDP 绑定地址 vs TCP 具体地址 → 同一归一化键 |
| 0.3 | 4 个 flag（`--cluster-listen/peer/secret/instance-id`）+ 校验（公网无 secret 拒绝、`--cluster-*` 与 `--turn-tcp-relay` 在 M3 前拒绝） | `main.rs:318-360` 风格 | `--help` 四构建一致；`check-docs.sh` 绿 |
| 0.4 | `Turn` 增字段 `cluster: Option<ClusterHandle>`；`Turn::new` 不传时为 `None` | `turn.rs:777-789` | `cargo test` 全绿（行为不变）|

**门禁**：`cargo test` / `--all-features`、clippy 两套、fmt、`frozen` 3×17、`check-docs --no-build`。
**回滚点**：单 commit revert 后回到 `.107` 行为。

## 里程碑 1 · UDP 控制面 + 数据面

| # | 事项 | 位置 | 验证 |
| --- | --- | --- | --- |
| 1.1 | 入口判定：`Turn::handle` 前插入 owner 判定（`owner != self` → 转发）；保证非 TURN 帧（`None`）原样返回 | `turn.rs:1159-1242` | 单测：非 TURN 帧不被转发 |
| 1.2 | `REQUEST`/`RESPONSE` 往返：入口发帧、owner 用规范化 key 执行、响应经入口回写 | `turn.rs` + `main.rs:2581-2643`（`respond_to_datagram`）| 单测：两 `Turn` + 假转发层，`Refresh` 从 B 到 A 得 `200` |
| 1.3 | `PUSH_DATA`（UDP 独立通道）：`Send`/`ChannelData` 转发 | `turn.rs:2738-2834`、`2881-2931` 前挂路由 | 单测：B 收 `ChannelData` → A 的 relay socket 发出字节 |
| 1.4 | 归属不可达 → `500` + 日志 `cluster=forward` | 新逻辑 | 单测：停掉 owner 后请求回 `500`（不是 437/静默） |
| 1.5 | 重复 `Allocate` 收敛：同一归一化键在 A、B 都收到 → 只有 A 建 | 复用 1.1 | 单测：`ss`/计数器断言只有一份 allocation |
| 1.6 | lab：假 LB（Python，UDP 逐包轮转）+ 两实例 | `script/lab/rstun-turn.sh`、新 `rstun-turn-lb.py` | `--only multi-instance-udp` |

**门禁**：全套 + `rstun-interop.sh all` + `rstun-abuse.sh`（限速在入口实例生效，实测确认）。
**回滚点**：M1 单 commit revert。

## 里程碑 2 · TCP/TLS/DTLS 控制面 + 回程

| # | 事项 | 位置 | 验证 |
| --- | --- | --- | --- |
| 2.1 | `ClientSink` 增远端变体（`PUSH_CLIENT` 定向回推） | `turn.rs:477-500` | 单测：owner 推字节 → 入口写队列收到 |
| 2.2 | `serve_turn_stream` / DTLS 循环接入 `session` 与 `CLIENT_CLOSED` | `main.rs:3009-3088`、`4002-4102` | 单测：断连即释放 owner allocation（不等 TTL）|
| 2.3 | `release_connection` 跨实例通知 | `turn.rs:941-953` | 单测 + lab `ss -lun` 无残留 |
| 2.4 | lab：TCP 假 LB（代理）+ TLS/DTLS 各一条 | lab | `--only multi-instance-tcp` |

**门禁**：全套 + `rstun-turn.sh --tls --dtls`。
**回滚点**：M2 单 commit revert（M1 仍可用）。

## 里程碑 3 · RFC 6062

| # | 事项 | 位置 | 验证 |
| --- | --- | --- | --- |
| 3.1 | 出站：`Connect` 在 owner，`ConnectionBind` 在入口 → 升级为 `RAW_RELAY` | `turn.rs:2237-2594`、`2600-2604` | lab `--only multi-instance-tcp-relay` |
| 3.2 | 被动：`ConnectionAttempt` 经 `PUSH_CLIENT` 回入口 | `turn.rs:3200-3268` | lab 复用 `tcp-relay-passive` 探针 |
| 3.3 | 启动校验：TCP relay 段不重叠（cluster 模式要求显式 `--tcp-relay-ports`） | `main.rs` 参数校验 | 负例：重叠 → 拒绝启动并说明 |
| 3.4 | 解除 M0.3 的「cluster + tcp-relay 拒绝启动」限制 | 同 0.3 | 单测断言不再拒绝 |
| 3.5 | 文档：`turn.md` 多实例章节、`cli.md`、`protocol.md`、`contrib/{k8s,helm,docker}` 示例 | docs | `check-docs.sh --no-build` |

## 每阶段门禁（原始输出贴回执）

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-turn.sh
bash script/lab/rstun-turn.sh --tls --dtls
bash script/lab/rstun-turn.sh --only frozen
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/ci/check-docs.sh --no-build
cargo audit; echo "audit=$?"
cargo deny check
cargo tree -e normal --depth 1 | tail -n +2 | wc -l          # lean 10
cargo tree -e normal --all-features --depth 1 | tail -n +2 | wc -l   # full 15
cargo check --all-targets --target x86_64-pc-windows-msvc
```

## 关键断言（可复制）

```bash
# M1：控制面跨实例
python3 script/lab/rstun-turn-probe.py --server 127.0.0.1:<lb> --mode relay ...
# 期望：Refresh/CreatePermission/ChannelBind = 200，relay 地址不变
# 现状（单实例语义）：437

# M1：重复 Allocate 收敛
# 同一 socket 先后打到两个实例 → 只应有一个 relay 地址

# M2：断连即释放
ss -lun | grep <relay 段>     # 期望：断开控制连接后立即无该端口

# M3：端口分片
ss -ltn | grep -E ':(5060[0-9]|5070[0-9])'   # 两实例段不重叠
```

## 已知前置（开工前必须成立）

1. **C1 源地址**：lab 用**真** `uclient` 验证客户端接受归属实例直发的 `Data`；不接受则 M1 的
   peer→client 也要经入口（设计里已留 `PUSH_CLIENT` 通道，M2 复用即可）。
2. **成员表静态**：所有人必须配置同一份 `--cluster-peer` 列表与同一 `--cluster-secret`。
3. **端口分片**：`--listen` 不同；TCP relay 段不同（M3 前不启用 TCP relay）。

## 进度

| 里程碑 | 状态 | 证据 |
| --- | --- | --- |
| M0 | 未开始 | — |
| M1 | 未开始 | — |
| M2 | 未开始 | — |
| M3 | 未开始 | — |
