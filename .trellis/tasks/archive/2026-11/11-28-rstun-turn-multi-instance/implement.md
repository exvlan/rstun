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
3. **端口一致 + IP 分片**：成员间 `--listen`/TLS/DTLS 端口**必须相同**（`HELLO` 校验），实例靠不同 IP/netns 区分；TCP relay 段每实例不同（`--tcp-relay-ports`，与 `--relay-ports` 不重叠）。

## 进度

| 里程碑 | 状态 | 证据 |
| --- | --- | --- |
| M0 | **完成**（2026-11-28） | `src/cluster.rs`（帧/HMAC/环/连接骨架）+ `src/cluster/tests.rs` 9 项；`Turn.key_for` 归一化单测；4 个 flag + `RSTUN_CLUSTER_*`；`--help` lean/full 逐字节一致；`cargo test` 287 / `--all-features` 296 |
| M1 | **完成**（2026-11-28） | 7 项跨实例单测（两 `serve_udp` + 两 cluster 节点）：Refresh/CreatePermission/ChannelBind=200、同 tid 同 relay、新 tid 437、Send/ChannelData 到达 peer、owner 不可达 500、非 TURN 不转发、secret 全链路；lab `multi-instance-udp` 5 项全绿；`frozen` 3×17 = `cad4fa2`；全量 lab 25 passed / 4 SKIP（lean TLS/DTLS）；interop/abuse/check-docs green |
| M2 | **完成**（2026-11-28） | `ClientSink::Remote` + `PUSH_CLIENT`；入口会话注册/`CLIENT_CLOSED` 即时释放；TCP/TLS/DTLS 全部接入；单测 `cluster_stream_control_forwards_and_pushes_bytes_back` / `cluster_stream_close_releases_the_owner_allocation`；lab `multi-instance-tcp` / `multi-instance-tls` / `multi-instance-dtls` |
| M3 | **完成**（2026-11-28） | id 携带归属下标、`ConnectionBind` 按 id 路由；`BOUND`/`RAW_RELAY`/`RAW_CLOSED`；`--tcp-relay-ports` + 段重叠拒绝；单测 `cluster_raw_relay_binds_and_carries_bytes_both_ways` / `cluster_passive_attempt_is_pushed_to_the_entry`；lab `multi-instance-tcp-relay` |
| 端口一致性 | **完成**（2026-11-28） | `HELLO` 交换（版本/id/端口/TCP 段）；端口或段不一致 → 拒绝启动；单测 `cluster_hello_rejects_a_different_listen_port` + `hello_requires_identical_ports_and_disjoint_tcp_ranges` |

## 实施记录（M0+M1，供 M2/M3 接手）

### 已落地的形状

- 新文件 `src/cluster.rs`（帧编解码、HMAC、成员环、TCP 控制长连、UDP `PUSH_DATA`、任务生命周期）。
- `Turn` 新增 `cluster: OnceLock<Arc<Cluster>>`；`key_for` 只在集群模式归一化 `Key.server`。
- `Turn::handle` 拆成 `dispatch(..., allow_forward)`：集群入口按归属转发，`handle_as_owner` 跳过归属判定
  （owner 侧执行，杜绝转发环）。`None`（非 TURN）路径原样返回。
- 新 flag：`--cluster-listen` / `--cluster-peer`（可重复，`ID@ADDR`）/ `--cluster-secret` /
  `--cluster-instance-id`；`ops::ENV_FLAGS` 同步 `RSTUN_CLUSTER_*`。
- 启动校验（`build_cluster`）：无 `--turn`、无 peer、公网监听/peer 无 secret、成员 >255、与
  `--turn-tcp-relay`（M3）或 `--tcp`/TLS/DTLS（M2）同时出现 → 拒绝启动。
- lab：`script/lab/rstun-turn-lb.py`（逐包轮转、每客户端一个上游 socket 的假 LB）+ 探针
  `multi-instance` 模式 + `--only multi-instance-udp`。

### 需要主会话确认的取舍（与 design 的偏差）

1. **帧头带 1 字节 reserved**（12 字节，按 design §4.1 的图）；任务文本里的 11 字节草图少了它。
2. **`PUSH_DATA` 载荷是完整原始 datagram**（含 `ChannelData` 4 字节头或整条 `Send` indication），
   不是「纯 relay 负载」：owner 因此复用 `handle_channel_data` / `send_indication`，permission/channel
   判定零改动。多 4 字节/包。
3. **`EVEN-PORT` 的 `RESERVATION-TOKEN` 跨实例语义**：token = `port(2)|issuer_index(1)|unique(5)`；
   issuer 走预留表；别的实例优先同端口、占用则用本实例空闲奇数端口。**不这样做**，coturn
   `turnutils_uclient` 在端口对跨实例时约 40% 的运行直接 `error 508` 退出（实测 5 次 2 次失败）。
   代价：跨实例的端口相邻性不保证（客户端从响应读地址），且 token 的「一次性」只在 issuer 上强制。
4. **M1 比任务最低要求更严**：除 `--turn-tcp-relay` 外，`--tcp` / `--turn-tls-listen` /
   `--turn-dtls-listen` 与 `--cluster-*` 同时出现也拒绝启动（否则 TURN-over-TCP 是半可用）。
5. **归属不可达的 `500` 不签名**：入口没有验证过的 key（RFC 5389 §10.2.3 允许省略 MI）。
6. **`--cluster-peer` 上限 255**：token 的一个字节存 issuer 环下标。

### C1 实测结论（决定 M2 不需要提前用 `PUSH_CLIENT`）

`turnutils_uclient` 的 UDP socket 是 **connected** 的（运行中 `ss -uanp` 显示
`ESTAB 127.0.0.1:<port> 127.0.0.1:<turn-port>`，4 条），因此内核只接受来自它发送目标的响应：
「客户端 → 共享 VIP、owner 用自己的地址直回」会被丢弃。部署前提按 PRD C1：每实例独立公网 IP、
DSR（源地址仍是 VIP）或 NAT 型 LB 转发回程。lab 的假 LB 是 NAT 形态（回程经 LB），真 `uclient`
因此 `exit=0`、`lost packets 0`、双向字节 > 0；探针（未 `connect`）覆盖 owner 直发路径。
**UDP 数据面不需要 `PUSH_CLIENT`**；M2 只在 TCP/TLS/DTLS 写队列不可重定向时才需要它。



## 实施记录（M2/M3 + 端口一致性，2026-11-28）

### 端口一致性（先修的设计缺陷）

- 新增 `HELLO` 帧（type `0x09`）：版本、instance-id、`--listen`/TLS/DTLS 端口、本实例 TCP relay 段。
  每条控制连接**首帧必须是 HELLO**；启动时对每个 peer 做一次短连接预检。
- 端口不一致 / TLS 或 DTLS 端口不一致 / TCP relay 段重叠 / **成员表不一致（`HELLO` 携带成员数与排序 id 摘要）** → **拒绝启动**；
  **peer 不可达只告警**（请求回 500，允许滚动上线）。
- 同实例的多个 `--listen`（含 `--listen-v6`）与 TLS/DTLS 监听必须各自共用**一个端口**，
  否则启动失败（否则同一客户端会在两个入口算出不同 owner）。
- 文档统一为：**成员间端口必须相同、IP 必须不同**（design C2 / PRD C2 / 本节「已知前置」已回写）。
- `Config::listen_port` 由 `build_cluster` 从 `--listen` 派生，测试里显式传入。

### M2（stream 控制面 + 回程）

- `Cluster::register_session(writer) -> u32`：入口每条 stream/DTLS 连接一个会话；
  `REQUEST`/`PUSH_DATA` 载荷前缀为 `stream_session(4)`；owner 用它构造 `ClientSink::Remote`。
- `PUSH_CLIENT{session}`：owner 的 relay reader 把 peer→client 字节 `try_send` 到入口写队列
  （有界，溢出与单实例同语义：丢包不涨内存）。
- `CLIENT_CLOSED{session}`：入口连接结束（EOF/错误/drain/reject）时发送；
  owner `take_allocation(session)` → `remove_allocation` → relay socket 立即回池。
- `serve_turn_stream`（TCP + TLS）与 DTLS 连接循环都注册会话、用 `handle_stream`、
  结束时 `release_connection(..., session)` + `unregister_session`。
- `handle_channel_data` 拆成「入口转发包装」+ 本地执行；`dispatch` 对完整 ChannelData 帧
  在任意 transport 上都可解析（owner 侧复用）。
- 解除了上一轮的 M2 启动限制（`--tcp` / TLS / DTLS + `--cluster-*` 允许）。

### M3（RFC 6062）

- `CONNECTION-ID` 最高字节 = 归属实例环下标（`fresh_connection_id` / 入站 accept 共用）；
  `ConnectionBind` **只按 id 路由**，绝不回退到 5 元组键（否则会被转发到不知道该 id 的实例，实测 400）。
- owner：`Decision::Bind` → 先写 `BOUND`（载荷前缀 = 入口会话），**再** `start_raw`
  把 pending 连接包装成 `DataConnection`（`ChannelReader` + 转发任务）；
  顺序保证 `RAW_RELAY` 不会越过 bind 响应。
- 入口：`BOUND` 由 cluster 调度器直接写进入口连接队列（先于任何 `RAW_RELAY`），
  然后 `stream_turn_loop` 返回 `BoundRemote`，连接切到 `raw_relay_loop`。
- `RAW_RELAY{session}` 双向裸字节；`RAW_CLOSED{0=client→peer EOF, 1=peer→client EOF, 2=abort}`
  传播半关闭/中止；owner 侧 `DataConnection.abort` 标志让 `LIFETIME=0`/错误关闭双向。
- 被动模式复用 `ClientSink::Remote`：`ConnectionAttempt` 经 `PUSH_CLIENT` 回入口。
- **`--tcp-relay-ports`（新 flag，不是 `--relay-ports` 的第二段）**：集群 + `--turn-tcp-relay`
  时必填；与 `--relay-ports` 及其它成员段不重叠（`SO_REUSEPORT` 会让重叠段双 LISTEN）。
  单实例不填时仍默认等于 `--relay-ports`（行为不变）。
- `--turn-tcp-relay` 与 `--cluster-*` 的启动拒绝已解除。

### 仍需拍板的取舍

1. `--tcp-relay-ports` 的形态：新增独立 flag（推荐，语义清晰），未复用 `--relay-ports` 的第二段。
2. `RAW_RELAY` 半关闭：按方向传播（客户端 EOF 只关 peer 写半边、peer EOF 只关客户端写半边）；
   错误/drain/allocation 删除发 `RAW_CLOSED(2)` 关双向。
3. 会话超时：**不设独立计时器**；正常由 `CLIENT_CLOSED` 立即回收，入口实例崩溃时随 allocation
   TTL 回收（与 PRD「实例崩溃 → allocation 随 TTL 消失」一致），裸中继状态在 `forget_allocation`
   一并清理。
4. `HELLO` 除 `listen_port` 外还带 TLS/DTLS 端口与 TCP relay 段（否则 M2/M3 的端口漂移无法 fail-fast）。


## 冷复核修复（2026-11-28）

| 项 | 改法 | 单测 / 证据 |
| --- | --- | --- |
| **B1** `--tcp-relay-ports` 缺省值 | `build_turn` 在 `config.relay_ports` 赋值后先 `config.tcp_relay_ports = config.relay_ports`，再由显式 flag 覆盖 | `tcp_relay_ports_default_to_the_udp_range`；进程证据：`--relay-ports 50000-50010 --turn-tcp-relay` 无 tcp flag → debug 日志 `relay=127.0.0.1:50000`（旧代码是 49152）|
| **B2** 同 5 元组并发 `Allocate` 双 200 | `Turn.creating` per-key 占位（RAII `Creating`）覆盖「查表 → 绑端口 → 插入」；落败者 `437`（同 tid 的后续重传由查表幂等 200）；`insert` 对存活条目再防御性拒绝并归还新端口 | `concurrent_allocate_for_one_five_tuple_yields_one_allocation`：两线程 + `Barrier`，120 轮，每轮恰好 1×200 + 1×437；输出 `B2 concurrency: 120 rounds, one 200 + one 437 each, double-200 = 0` |
| **B3** HELLO 不带成员表 | `Hello` 增加 `member_count` + 排序 id 的 `sha256[..8]`；`Cluster::hello()` 取**实时** membership（不是原始 config，`set_peers` 后仍正确）；`check_hello_members` 不一致 → 拒绝启动 | `hello_requires_the_same_member_set`、`cluster_hello_rejects_a_member_list_mismatch`；进程负例：A 列 [a,b]、B 列 [b] → A exit=1，错误含 `--cluster-peer must be identical` |
| **B4** 通配监听绕过 secret | `is_private` 把 `0.0.0.0`/`::` 视为非私有；错误文案写明「public or wildcard」；`PUSH_CLIENT`/`RAW_RELAY`/`RAW_CLOSED`/`BOUND` 校验发送实例 == session 记录的 owner，不匹配丢弃 + warn | `a_wildcard_cluster_listener_needs_a_secret`、`a_push_client_from_the_wrong_instance_is_dropped`；进程负例：`--cluster-listen 0.0.0.0:P` / `[::]:P` 无 secret → exit=1 |
| **S1** 转发的 TLS/DTLS 请求丢监听 IP | `ServerContext` 不改；`cluster::Config` 增 `tls_listen`/`dtls_listen`（`build_cluster` 从 args 填），`owner_local(config, context, transport, port)` 按传输类别解析（UDP/TCP = `--listen`，TLS/DTLS = 各自监听表）| `owner_local_resolves_each_transport_listener`；lab `multi-instance-tls-relay-ip`：用 LB `--source-port` + 同款环算法选一个 owner=B 的 5 元组，断言 `XOR-RELAYED-ADDRESS` IP == 127.0.0.2（反证：去掉 TLS 分支后该项报 `relay 127.0.0.1`）|
| **N2** RAW_RELAY 溢出静默截断 | 入口侧 `try_send` 失败 → `RAW_CLOSED(ABORT)` + close watch；owner 侧 `raw_in` 队列满 → 移除 inbound + `RAW_CLOSED(ABORT)`；`open_raw` 写任务把链路发送失败区分为 ABORT（只有干净 peer EOF 才是 `PEER_TO_CLIENT`）| `a_full_raw_relay_queue_aborts_the_session`、`a_full_owner_raw_queue_aborts_the_relay` |

顺带修复：`signal_session_close` 用 `send_replace`（原先 `send` 在尚无订阅者时失败，BOUND 后立刻到达的 `RAW_CLOSED` 会丢）；`raw_relay_loop` 启动时先读当前 close 值；入口 `RAW_RELAY` 溢出路径原先在持有 `sessions` 锁时再取同一把锁（死锁），已改为先释放再 signal。

### 最终门禁数字

- `cargo test` **303**；`cargo test --all-features` **312**；clippy 两套、fmt 全绿
- `rstun-turn.sh`：**35 passed / 0 failed / 6 SKIP**（lean；SKIP = tls/dtls/cert-reload/cert-poll/multi-instance-tls/dtls）
- `rstun-turn.sh --tls --dtls`：**9 passed / 0 failed**（含 `multi-instance-tls-relay-ip`）
- `--only multi-instance-{udp,tcp,tcp-relay}`：5/4/6 项全绿；`frozen` 3×17 与 `cad4fa2` 一致
- interop / abuse / check-docs 全绿；audit=0；deny ok；tree lean 10 / full 15；Windows check 通过

## 复验收口（2026-11-28，N-a..N-h）

| 项 | 改法 | 证据 |
| --- | --- | --- |
| **N-a** `cleanup` 同步检查 | 改成 **20×100ms（≤2s）轮询**；并新增 `relay_sockets_owned <pid>`：只用 `ss -p` 里属于本 server pid 的端口（根因：旧失败里 `leftover=[49706]` 的 owner 是宿主代理 `mihomo`，不是 rstun）| `cleanup` 连跑 10 次全绿，输出含 `owned by pid …` 与 `socket poll N×100ms`；手动复现：`ss -lunp` 显示 `mihomo` 持有 49706 |
| **N-b** 并发 437 计 `rejected_quota` | 去掉该计数（标签集固定，不新增 reason）| `concurrent_allocate_for_one_five_tuple_yields_one_allocation` 仍 120 轮 1×200+1×437 |
| **N-c** HELLO 版本 | `HELLO_VERSION: 1 → 2`；`check_hello_version` 报 `cluster HELLO version 1 is not supported (expected 2)` | `a_hello_from_another_protocol_version_is_refused` |
| **N-d** session 起点 | `session_start()`：时钟 + pid + 栈地址混合，奇数非 0，无 `rand` 依赖 | 代码审查（每进程起点不同；旧 allocation 未过期时不再从 1 撞号）|
| **N-e** 错来源日志 | `RAW_RELAY` 错来源改 `warn`，分三种：`from instance X … owner Y` / `unknown or expired session` / `without a HELLO identity` | 与 spec §5c「不匹配丢弃 + warn」一致 |
| **N-f** validate 一致性 | `tls_port.is_some() == tls_listen.is_empty()` 与 DTLS 同类断言 | `config_rejects_a_port_listener_mismatch` |
| **N-g** DTLS relay IP | `multi-instance-dtls` 用 `uclient -S -v` 的 `Received relay addr:` 断言 owner-B 的 relay 在 127.0.0.2；用**本次** byte 增量判断 owner-B（累计值会误判）| `ok: multi-instance-dtls-relay-ip …`；反证：去掉 `Dtls` 分支后该项 FAIL |
| **N-h** 文档 | `turn.md` + `design.md`：成员一致性只校验 id（地址漂移不 fail-fast，落到 500）；集群用具体 `--listen` IP（`0.0.0.0` 仍按路由反推）| 两处已写入 |

最终数字：`cargo test` **305**、`--all-features` **314**；clippy 两套 / fmt 全绿；`rstun-turn.sh` 35 passed / 0 failed / 6 SKIP；`--tls --dtls` 含 DTLS relay-ip 项。

## CI 修复：macOS 的 127.0.0.2（2026-11-28）

- 现象：`test (macos-latest)` 12 条集群单测 panic `no loopback port free on both 127.0.0.1 and 127.0.0.2`。
  根因是 macOS `lo0` 只有 `127.0.0.1`（Linux/Windows 整个 `127/8` 都是 loopback），而集群单测需要
  「同端口、两个不同 IP」。
- 测试侧：新增 `cluster_loopback_ready()`（`UdpSocket::bind("127.0.0.2:0")`）+ `require_cluster_loopback!` 宏，
  12 条集群单测开头显式 skip 并打印原因（**不用** `#[ignore]`，否则三个平台都零覆盖）。
  `RSTUN_TEST_NO_CLUSTER_LOOPBACK=1` 可强制走 skip 路径做自检。
- CI 侧：`test` job 增加 macOS-only `sudo ifconfig lo0 alias 127.0.0.2 up || true`（在 `cargo test` 之前），
  macOS 因此与 Linux/Windows 一样真跑这 12 条。
- 证据：Linux 上 `turn::tests::cluster` 12 passed（真跑）；强制 skip 时 12 条均打印
  `skip <test>: 127.0.0.2 is not configured …` 并 pass；`cargo test` 305、`--all-features` 314 不变。

## CI 修复：macOS 被动 ConnectionAttempt（2026-11-28）

- 现象：`eb78be1` 后 `test (macos-latest)` 只剩 `cluster_passive_attempt_is_pushed_to_the_entry` 失败
  （`no ConnectionAttempt`），Linux 稳定通过。
- 根因（推断，平台差异）：测试对 `127.0.0.1:9` 建 permission 后用**未绑定源地址**的 socket 连
  `127.0.0.2:<relay>`。Linux 上源地址选 `127.0.0.1`（本机实测），macOS 上 `127.0.0.2` 是 lo0 别名，
  路由可能把源地址选成 `127.0.0.2` → permission 只覆盖 `127.0.0.1` → accept 后静默关闭 → 永远等不到
  indication。**不是产品 bug**，是测试对源地址的隐含平台假设。
- 改法：① `TcpSocket::new_v4()` + `bind("127.0.0.1:0")` 显式钉源地址；② permission 同时建
  `127.0.0.1:9` 与 `127.0.0.2:9`（per-IP，两个合法）；③ `read_stun_within` 的 `None` 分支改为带
  `peer_local` / `owner_active` / `owner_pending` 的 panic，便于下次直接定位。
- 证据：本地连跑 20 次全绿（20/20）；`cargo test` 305 / `--all-features` 314 不变；
  强制 skip 仍 12 passed + 12 条 `skip` 打印。
