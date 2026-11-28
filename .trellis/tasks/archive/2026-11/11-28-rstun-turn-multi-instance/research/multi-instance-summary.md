# 摘要：多实例集成面（注入用；全文见 `multi-instance-integration.md`）

## 六条决定设计的事实

1. 数据面实例亲和：`XOR-RELAYED-ADDRESS` 是归属实例自己的 IP:port（`turn.rs:1495-1503`、`1679-1682`），
   peer 直连、不经 LB。只有「客户端 → `--listen`」会被分散。
2. `Key.server` 语义分裂：UDP/DTLS = 绑定地址（`main.rs:2404`，多实例相同）；
   TCP = 连接本地地址（`main.rs:2955`，逐主机不同；注释 `turn.rs:2680-2683`）。
   **不能直接拿 `Key` 当归属键**。
3. UDP relay 池可共用同段：`udp_socket` 无 REUSEPORT（`main.rs:4137-4145`），
   第二个进程 bind 失败 → `take_port` 跳过（`turn.rs:968-972`）。实测 50600 / 50602 自动分区。
4. TCP relay 池**必须分片**：`tcp_relay_listener` 设 REUSEPORT（`main.rs:4158-4175`），
   两实例同段会双 `LISTEN`（实测），入站 peer 按 4 元组分流（18/22），落到非归属实例即
   关连接且不发 `ConnectionAttempt`（`turn.rs:3200-3211`）。
5. 现有跨实例共享只有 nonce / REST 凭据（`auth.rs:734-783`）；allocation 表、端口池、`Instant`、
   令牌桶、`oneshot`/`watch` 全在进程内。
6. TCP/DTLS 回程必须回入口实例：写队列属于接受连接的实例（`main.rs:3009`、DTLS `4002`）；
   UDP 例外（owner 持有监听 socket，`turn.rs:1721-1734`）。

## 现状失败路径（可直接当 before 判据）

| 动作落到非归属实例 | 现状 |
| --- | --- |
| `Refresh` / `CreatePermission` / `ChannelBind` / `Connect` | `437`（鉴权已过；`turn.rs:1839-1847`、`1953-1961`、`2077-2085`、`2265-2273`）|
| `ConnectionBind` | `400`（`turn.rs:2551-2582`）|
| `Send` / `ChannelData` | 静默丢弃（`turn.rs:2752-2754`、`2896-2898`）|
| 重传 `Allocate` 换实例 | 第二份 allocation、两个 relay 地址（实测 50606 / 50608）|
| TCP 控制连接在 B 关闭、allocation 在 A | A 侧泄漏到 TTL（`main.rs:3036-3052`）|

## 关键接缝（必须改）

1. `Turn::handle`（`turn.rs:1159-1242`）—— 唯一分派点，插归属判定；`None` 必须原样返回。
2. `handle_channel_data`（`turn.rs:2881-2931`）—— 唯一绕过 `handle` 的入口（`main.rs:3137`）。
3. `respond_to_datagram`（`main.rs:2581-2643`）—— 响应可能来自 owner。
4. `serve_turn_stream` / `stream_turn_loop`（`main.rs:3009-3017`、`3182-3205`）+ DTLS（`4002-4052`）——
   需要「远端 sink」与连接结束通知。
5. `allocate` 里 `ClientSink` 构造（`turn.rs:1721-1748`）—— 增远端变体。
6. `release_connection`（`turn.rs:941-953`）—— 非 owner 要通知 owner。
7. `TcpConnection.bind: oneshot`（`turn.rs:722-739`、`2551-2582`、`main.rs:3057-3088`）—— M3 跨实例。
8. `quota_counts`（`turn.rs:2933-2946`）—— 若要做全局配额（本任务不做）。
9. `Turn` 结构（`turn.rs:777-789`）—— 新增可选字段。
10. `Key` / `local` 语义（`turn.rs:476-480`、`main.rs:2586-2588`）—— 归一化键。
11. 新配置面 —— 同步 `--help`、`check-docs.sh`、`turn.md`、`contrib/*`。

## 不要动

`AllocationState`/`TokenBucket` 每包语义、`protocol.rs` 线上格式、`--turn` 关闭时的全部路径、
`tcp_relay_listener` 的 REUSEPORT（它是出站前提）、`auth.rs` 的 nonce 格式。

## 已定取舍（本任务 design 的 D1–D10）

- 归属 = 静态成员一致性哈希（无共享表、无外部依赖）
- 归一化键 `(client_ip, client_port, transport_class, listen_port)`；集群模式 `Key.server` 规范化为 `0.0.0.0:<listen_port>`
- 内部：新 `--cluster-listen` TCP（请求/响应/回推）+ 同端口 UDP（`PUSH_DATA` 单向）
- 鉴权在 owner 做（原样转发）；`Send`/`ChannelData` fire-and-forget
- 归属不可达 → `500`（不回 437、不静默丢）
- UDP 池共用、TCP 池分片；`--listen` 不可共用
- 阶段化 M1 UDP → M2 TCP/TLS/DTLS → M3 RFC 6062；未完成阶段「多实例 + `--turn-tcp-relay`」启动拒绝

## 测试面

- `start_on`（`tests.rs:75-108`）同进程可起两个 `Turn`；`tcp_relay_config()`（`tests.rs:2226-2246`）
  已示范每测试独占 relay 段 —— 多实例用例给两个不同窗口。
- lab：`start_server` 通用（`script/lab/rstun-turn.sh:135-141`），但 `turn_args()` 写死单实例参数（`203-215`），
  需参数化；`relay_listeners()/relay_tcp_listeners()/relay_sockets()`（`172-199`）要按段各查一次。
- 探针 UDP 未 `connect`（`rstun-turn-probe.py:201-202`、`290-291`），能收非对端地址响应；
  TCP 探针 `connect()`（`536`），假 LB 需做 TCP 代理。
