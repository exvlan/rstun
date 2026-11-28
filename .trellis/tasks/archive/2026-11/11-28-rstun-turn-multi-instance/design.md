# 设计：TURN 多实例（归属 + 转发）

> 依据：`research/multi-instance-integration.md`（121 处 `file:line`，含两个真进程与内核 REUSEPORT 实测）。
> 本文只写取舍与契约；执行顺序见 `implement.md`。分 M1/M2/M3 三步，每步可独立发布。

## 1. 核心洞见（决定了架构形状）

1. **数据面天然实例亲和**：`XOR-RELAYED-ADDRESS` 是归属实例自己的 IP:port（`turn.rs:1495-1503`、`1679-1682`），
   peer 直连该地址、不经 LB。**只有「客户端 → `--listen`」这一侧会被 LB 分散**。
2. **不能靠共享端口做无状态**：UDP relay 绑不上就跳过（可共用段，实例自动分区）；
   TCP relay 有 `SO_REUSEPORT`，同段会双 LISTEN、入站 peer 被内核分流到错误实例（实测 18/22）。
3. **`Key` 不能当归属键**：`Key.server` 在 UDP/DTLS 是绑定地址（多实例相同），在 TCP 是连接本地地址
   （逐主机不同）。
4. **TCP/DTLS 的响应回程不是「返回字节」**：写队列属于接受连接的实例（`main.rs:3009`、`4002`），
   peer→client 必须反向推回入口实例；UDP 例外（归属实例自己持有监听 socket，`turn.rs:1721-1734`）。

## 2. 决策表

| # | 决策 | 理由 | 放弃的方案 |
| --- | --- | --- | --- |
| D1 | **确定性一致性哈希定归属**：`owner = ring[hash(normalized_key)]`，成员表静态配置 | 无共享存储、无 TTL、无脑裂；任何实例都能本地算出归属，不做成员注册表 | 共享归属表 + 心跳（多一套失效判定）；Redis（D8） |
| D2 | **归一化键** `(client_ip, client_port, transport_class, listen_port)`，`transport_class ∈ {udp, dtls, tcp}`（TLS 归 tcp） | 抹平 `Key.server` 两种语义；同一客户端在同一 listen 端口上跨实例一致 | 直接用 `Key`（同机不同端口时失效） |
| D3 | **集群模式下 `Key.server` 规范化**为 `0.0.0.0:<listen_port>` | 归属实例只做表键，不往该地址发包；让同一 5 元组在任意实例上得到同一个 `Key` | 用入口实例的真实地址（逐实例不同 → 键漂移） |
| D4 | **新开内部监听** `--cluster-listen <addr>` + 静态对端 `--cluster-peer <id>@<addr>`（可多次） | ops 端点的契约是「GET /healthz, GET /metrics，一连接一请求、拒绝请求体」（`ops.rs:1015`、`ops.md`），塞双向推送会破坏它 | 复用 `--health-listen` |
| D5 | **内部协议手写**：12 字节头 `u32 len ‖ u8 type ‖ u16 flags ‖ u8 reserved ‖ u32 session ‖ payload`，可选 `--cluster-secret`（HMAC-SHA256 over header+payload） | 与 `ops.rs` 极简 HTTP 同风格，不引依赖（R8）；有 secret 时拒绝未签名帧 | gRPC / protobuf / QUIC |
| D6 | **端口策略**：UDP 共用同段（依赖 bind 失败自动分区）；**TCP 必须分片** | 实测：UDP 第二个进程 bind 失败即跳过；TCP 因 REUSEPORT 一定绑上 | 全部共用（TCP 错投递）；全部分片（UDP 需人工规划，无收益） |
| D7 | **归属不可达 → `500`（Server Error）**，不猜、不回 `437` | `437` 会让客户端以为 allocation 没了而重建（制造第二份 allocation）；`500` 可重试 | 回 437；静默丢 |
| D8 | **不引入外部存储**；共享状态存储方案（C）整体放弃 | C 也消不掉转发（socket 不可迁移），却引入可用性单点、时钟偏差、权限缓存一致性风险 | Redis/etcd |
| D9 | **`Send`/`ChannelData` 走 fire-and-forget 单向帧**，不复用请求/响应 | 它们本来就没有响应（`turn.rs:2738-2834`、`2881-2931`）；复用会引入无谓的往返与超时耦合 | 请求/响应 |
| D10 | **阶段化**：M1 UDP → M2 TCP/TLS/DTLS → M3 RFC 6062；未完成的阶段**启动拒绝** | C5：M3 之前「多实例 + `--turn-tcp-relay`」= 半可用，比拒绝更糟 | 一次性全做 |

## 3. 数据流

### 3.1 M1（UDP）：控制面

```
client ──UDP──► E（入口，任意实例）
  E: Turn::handle(frame) → normalized_key
     ├─ owner(self)  → 现有路径，零改动
     └─ otherwise    → cluster REQUEST{session, key, client, transport, listen_port, frame}
                        └─► A（owner）：Turn::handle(frame) 用规范化 Key
                              └─ RESPONSE{session, signed bytes} ─► E ─► socket.send_to(client)
```

- 鉴权在 **owner** 做（D-Q3：原样转发）。配置相同 → 结果相同；失败凭据也付一次内部往返，可接受。
- 响应由 owner 用请求里验证通过的 key 重新 `seal`（`auth.rs:801-822`），E 不再解析，直接回写字节。

### 3.2 M1（UDP）：数据面

```
client ──Send/ChannelData──► E ──cluster PUSH_DATA{key, client, bytes}──► A
                                                   └─► 写 relay socket（permission 判定仍在 A）
peer ──► A.relay_socket ──► A.relay_reader ──► A 的 listen socket send_to(client)   ← 不经 E
```

- peer→client 由 A 直发是**有意**的：省一跳，且 UDP 的 `ClientSink::Udp` 本来就是 A 的监听 socket。
  前提是 C1（A 的源地址必须被客户端接受）。
- `PUSH_DATA` 无响应、无重传；A 侧 `permission` 不通过就丢（与本地路径同语义）。
- 每包一次内部跳转，上行带宽翻倍；`PUSH_DATA` 用**独立 UDP 通道**（见 §4.2）避免 TCP 头阻塞。

### 3.3 M2（TCP/TLS/DTLS）：控制面 + 回程

```
client ──TCP──► E（持有该连接与写队列 mpsc）
  E: 帧解析 → normalized_key → REQUEST ──► A
      A: handle → RESPONSE ──► E ──► 写队列
  数据面 peer→client：A 的 relay reader → PUSH_CLIENT{session, bytes} ──► E ──► 写队列
  连接结束：E → CLIENT_CLOSED{session} ──► A 立刻 remove(allocation)，不等 TTL
```

- `session` 由 E 生成，标识「E 上的这条客户端连接」；A 记住 `session → owner-side allocation`，
  用于 `PUSH_CLIENT` 的定向回推。
- 半关闭语义（`main.rs:3057-3088`）不变：`CLIENT_CLOSED` 只在连接真正结束时发。

### 3.4 M3（RFC 6062）

- 出站：`Connect` 在 A 执行，`CONNECTION-ID` 表仍在 A；`ConnectionBind` 落到 E → E 把该连接
  「升级」为 `RAW_RELAY{session}` 双向裸字节，A 侧包装成 `DataConnection.reader/writer`。
- 被动：peer 连 A 的 relay listener（**A 独占该端口段**），`ConnectionAttempt` 经 `PUSH_CLIENT` 回 E。
- 该阶段之前：`--cluster-*` 与 `--turn-tcp-relay` 同时出现 → 启动即报错退出。

## 4. 内部协议

### 4.1 帧格式

```
0               4      5      6      8            12
+---------------+------+------+------+-------------+-------------------
| payload len   | type | flags| rsvd | session id  | payload ...
+---------------+------+------+------+-------------+-------------------
                     (len 不含 12 字节头)
```

| type | 名称 | 方向 | payload |
| --- | --- | --- | --- |
| `0x01` | `REQUEST` | E→A | `client(10/22B) ‖ transport(1) ‖ listen_port(2) ‖ frame` |
| `0x02` | `RESPONSE` | A→E | 已签名的响应字节（或空 = 无响应） |
| `0x03` | `PUSH_DATA` | E→A | `client ‖ transport ‖ listen_port ‖ 原始 relay 负载` |
| `0x04` | `PUSH_CLIENT` | A→E | `client ‖ 原始字节`（写入该 session 的写队列） |
| `0x05` | `CLIENT_CLOSED` | E→A | 空（A 释放该 session 的全部状态） |
| `0x06` | `RAW_RELAY` | 双向 | 裸字节（M3） |
| `0x07` | `PING` / `0x08 PONG` | 双向 | 存活探测（仅用于日志与「对端不可达」判定） |

### 4.2 两条承载

- **控制通道**：每个对端一条长连 TCP（`--cluster-listen`），承载 `REQUEST/RESPONSE/PUSH_CLIENT/CLIENT_CLOSED/RAW_RELAY`。
  单条连接 + 帧序化即可；请求与响应用 `session` 关联（允许乱序完成）。
- **数据通道**：每个对端一条 **UDP** socket（同 `--cluster-listen` 端口号，UDP 侧），只承载 `PUSH_DATA`
  （丢包与客户端侧同语义，不必重传）。用 TCP 会让上行媒体受头阻塞。

### 4.3 安全

- `--cluster-secret` 存在时：每个帧带 truncated HMAC-SHA256（`flags & 0x01`），密钥错误 → 关闭连接并计数。
- 无 secret 时：只允许绑定到私网/回环（启动时若 `--cluster-listen` 是公网地址且无 secret → 拒绝启动）。
- 内部协议**不**承载用户凭据：`REQUEST` 只是原始 STUN 帧（已含 MESSAGE-INTEGRITY），owner 自己验。

## 5. 端口与配置

| 项 | 规则 |
| --- | --- |
| `--listen` | **成员间端口相同、IP（或 netns）不同**；启动 `HELLO` 校验，端口不一致拒绝启动（归属键含 listen_port，端口漂移会把一个客户端拆成两份 allocation）。TLS/DTLS 端口同理 |
| `--relay-ports`（UDP） | 可相同；实例靠 bind 失败自动分区 |
| TCP relay 段 | **必须**不同（`--turn-tcp-relay` 时启动校验：cluster 模式要求显式 `--tcp-relay-ports`，且与 `--relay-ports` 不重叠；HELLO 再校验成员间段不重叠） |
| `--cluster-listen` | 每实例一个；`--cluster-peer id@addr` 列全部成员（含自己可省略） |
| 成员稳定性 | 启动时按 `id` 排序成环；成员表变更 → 全部实例重启（C3） |

新增 flag（4 个 feature 构建的 `--help` 必须一致）：

```
--cluster-listen <addr>            启用多实例（不写 = 现行为）
--cluster-peer <id>@<addr>         对端，可重复；含自己
--cluster-secret <s>               内部帧 HMAC（公网地址时必需）
--cluster-instance-id <id>         本实例 id（缺省从 --cluster-listen 派生）
```

> `--cluster-peer` 的**地址**不参与 fail-fast：`HELLO` 只校验成员 **id** 集合（成员数 + 排序 id 摘要）。
> 地址漂移/写错会落到 §6 的「owner 不可达 → `500`」；换地址请同时重启所有成员并核对成员表。
> 集群内请用**具体**的 `--listen` IP：`0.0.0.0` 时 `egress_ip` 退回路由反推（与单实例通配一致），
> 同机多实例会算出同一主机 IP，relay 不再绑定在归属实例自己的地址上。

## 6. 错误与失效

| 场景 | 行为 |
| --- | --- |
| 归属实例不可达（连接失败 / 超时 200ms） | 回 `500 Server Error`（D7）。客户端重试要用**新的本地端口**：归属只由 5 元组决定，同一 5 元组重试仍会命中同一个死实例 |
| 内部帧超时（请求 500ms 未回） | 同上；同一 5 元组的重传仍命中同一 owner，需新本地端口才能换主 |
| 对端返回无法解析的字节 | 记 warn + `500`，不回垃圾给客户端 |
| 成员表缺某实例 | 该实例的键无归属 → `500`（不静默丢） |
| 边界：`session` 复用/串号 | 每次请求新 `session`，A 侧表按到达顺序消费；超时条目 1s 回收 |
| 入口实例在转发中途退出 | 客户端收不到响应 → 按客户端重传逻辑重新落到新实例；A 侧无状态残留（请求已完成或超时） |

## 7. 指标

不新增标签、不新增指标名（C6 / `ops.md` 标签集固定）。多实例可观测性靠：

- 日志字段：`cluster=owner|entry|forward`、`peer_instance=<id>`；
- 退出日志复用现有 `Counters`。

> 若将来要加指标，必须同时改 `ops.md` 标签契约与 `check-docs.sh`，属单独提案（不在本任务）。

## 8. 兼容与回滚

- 不写 `--cluster-*` → 所有路径与 `26.410.107` 完全一致（`Turn` 新增字段全为 `None`，`frozen` 3×17 必须逐字节相同）。
- 每个里程碑单独 commit，可单独 revert；M1/M2/M3 之间无强依赖（M2 复用 M1 的帧与归属键）。
- 回滚不影响已发布配置：删掉 `--cluster-*` 即回单实例。

## 9. 风险

| R | 缓解 |
| --- | --- |
| 归属键算错 → 转发环 / 落到自己 | 单测覆盖「A/B 双方对同一 key 得出同一 owner」；环成员排序固定；`owner == self` 走本地 |
| 内部链路放大延迟（控制面多一跳） | 请求超时 500ms 严于客户端预算；数据面走 UDP 独立通道 |
| 源地址不被客户端接受（C1 未满足） | lab 里用**真** `uclient` 验证；文档把 C1 写成部署硬前提，不满足时明确不建议多实例 |
| TCP relay 段配错（两实例重叠） | M3 启动校验 + lab `ss -ltn` 断言；文档写「每实例一段」 |
| 成员变更导致在途 allocation 失效 | 文档写明「改成员 = 排空重建」；不提供在线迁移 |
| 转发路径的安全边界（permission 判定） | permission 判定**只在 owner** 做（`turn.rs:2773-2779` 不变），入口实例不缓存、不放行 |
