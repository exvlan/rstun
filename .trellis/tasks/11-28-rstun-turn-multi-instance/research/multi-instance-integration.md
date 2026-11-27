# Research: TURN 多实例 —— 跨实例 allocation 归属与请求转发

- **Query**: 让 N 个 rstun 实例在**无 5 元组粘性的 L4 LB** 后正确服务 TURN（UDP/TCP 控制面 + RFC 6062），需要哪些共享状态、转发面落在哪、端口池能否共享
- **Scope**: mixed（内部代码为主，含内核 `SO_REUSEPORT` 行为实测）
- **Date**: 2026-11-28
- **只读**：未改 `src/`，未加依赖，未 commit。全部结论带 `file:line`，实测项在 §7 附录。

---

## 0. TL;DR（六条决定设计走向的事实）

**目录**：§0 TL;DR · §1 现状事实（1.1 状态项 / 1.2 入口 / 1.3 不可迁移资源 / 1.4 已可跨实例） ·
§2 为什么现在会坏（2.4 端口池） · §3 三种候选架构（A/B/C） · §4 代码接缝清单 · §5 开放问题 ·
§6 测试与验证面 · §7 证据附录 · §8 待验证

1. **数据面天生是「实例亲和」的**：`XOR-RELAYED-ADDRESS` 是**归属实例自己的 IP:port**（`turn.rs:1495-1503` `egress_ip` → `turn.rs:1679-1682` `socket.local_addr()`），peer 直接连该地址，**不经过 LB**。只有「客户端 → `--listen`」这一侧会被 LB 分散 → 需要跨实例处理的只是**控制面 + 客户端→peer 方向**。
2. **`Key.server` 在不同传输上语义不同**：UDP/DTLS 是 socket 的**绑定地址**（`main.rs:2404`，`--listen 0.0.0.0` 时就是 `0.0.0.0:3478`，多实例完全相同）；TCP 是**连接的本地地址**（`main.rs:2955`，恒为具体 IP，逐主机不同，注释见 `turn.rs:2680-2683`）。**共享归属表不能直接拿 `Key` 当键**，必须先定义归一化键。
3. **UDP relay 端口池不能共享也无需共享**：`udp_socket` **不设** `SO_REUSEPORT`（`main.rs:4137-4145`），第二个进程 bind 同端口失败 → `take_port` 跳过（`turn.rs:968-972`）。实测：两实例同段时自动分区 50600 / 50602。
4. **TCP relay 端口池必须按实例分片**：`tcp_relay_listener` **设了** `SO_REUSEPORT`（`main.rs:4158-4175`），两个实例会**绑到同一个端口**。实测：两个 `LISTEN` 同时在 `127.0.0.1:50600`。内核按 4 元组哈希分发入站连接（实测 18/22 分流）→ 被动模式（RFC 6062 §5.3）的 peer 会落到非归属实例 → 无 permission → **静默关闭**（`turn.rs:3200-3211`）。
5. **跨实例现在只有 nonce / REST 凭据是共享的**（`auth.rs:734-783`，注释明说「stateless … survives a load balancer」），allocation 表、端口池、`Instant` 计时器、令牌桶、`oneshot`/`watch` 句柄全部进程内。
6. **TCP/DTLS 的响应回程不是「返回一段字节」那么简单**：写回客户端的队列属于**接受连接的那个实例**（`main.rs:3009` 的 `mpsc`，DTLS 另有一份 `main.rs:4002`），所以 peer→client 方向必须**反向推回**接受实例；UDP 例外（归属实例自己持有 `ClientSink::Udp(监听 socket)`，`turn.rs:1721-1734`，可直接 `send_to`）。

---

## 1. 现状事实

### 1.1 状态项

| 状态项 | 归属 | 可复制？ | 代码位置 |
|---|---|---|---|
| `Key { client, transport, server }` | 纯值 | ✅ 可复制（但 §0-2 的语义差异必须处理） | `turn.rs:476-480` |
| `ClientTransport { Udp, Tcp, Dtls }` | 纯值 | ✅ | `turn.rs:452-462` |
| `Allocation.key / relay_addr / username / transaction_id / lifetime / client / dont_fragment` | 归属实例的 `allocationS: RwLock<HashMap<Key, Arc<Allocation>>>` | ✅ **元数据可复制** | `turn.rs:614-649`，表在 `turn.rs:777` |
| `Allocation.relay: Relay::{Udp(Arc<UdpSocket>), Tcp(TcpRelay{listener: Arc<TcpListener>})}` | 归属实例 | ❌ **socket / listener 不可迁移** | `turn.rs:565-587` |
| `Allocation.relay_task / accept_task`（`JoinHandle`） | 归属实例 | ❌ 任务句柄不可迁移 | `turn.rs:644-648`，`Drop` 在 `turn.rs:666-679` |
| `Allocation.df_lock: Mutex<()>` | 归属实例 | ❌ 无意义于他处 | `turn.rs:640` |
| `AllocationState { expires_at: Instant, permissions: HashMap<IpAddr, Instant>, channels: HashMap<u16, ChannelBinding>, inbound/outbound: TokenBucket }` | 每个 allocation 一份 `Arc<RwLock<…>>`，**读侧还有 relay reader 任务的高频只读** | ⚠️ 语义可复制，**但 `Instant` 与 `f64` 令牌桶不可序列化**，且是数据面热路径 | `turn.rs:511-519`、`524-532`；读侧 `turn.rs:3355-3376` |
| `Turn.used_ports / used_tcp_ports: Mutex<HashSet<u16>>` | 实例内 | ⚠️ 只能「分片」，不能共享（§2.4） | `turn.rs:778-782` |
| `Turn.reservations: Mutex<HashMap<[u8;8], Reservation{port, expires_at: Instant}>>`（`EVEN-PORT` R=1） | 实例内 | ⚠️ 同 `Instant` 问题；且 reservation 的奇数端口**也必须是归属实例的** | `turn.rs:784`、`791-796`、`1636-1659` |
| `Turn.connections: Arc<Mutex<HashMap<u32, TcpConnection>>>`（全局 `CONNECTION-ID` 表） | 实例内 | ⚠️ 元数据（`allocation/username/peer/state/expires_at`）可复制；`stop: watch::Sender` / `bind: oneshot::Sender<DataConnection>` / peer socket 不可 | `turn.rs:722-739`、`787` |
| `DataConnection { reader: Box<dyn AsyncRead>, sender: mpsc::Sender, writer_task, _permit }` | 接受客户端数据连接的实例 | ❌ 句柄不可迁移 | `turn.rs:706-719` |
| `Permit`（`--max-inflight` 名额） | 实例内 `Semaphore` | ❌ 语义为「本进程在途」 | `limit.rs:615-660`、`main.rs:750-766` |
| `Counters`（TURN） | 实例内 `AtomicU64`，`/metrics` 读同一份 | ❌ 不共享（标签集固定，见 §4.2） | `turn.rs:382-414`、`ops.rs:416-536` |
| `auth::Auth`（用户表 / `--auth-secret` / `--rest-secret`） | 每实例从 flag/文件构造，**读一次** | ✅ 只要配置相同即等价 | `auth.rs:239-254`、`main.rs:1054`、`auth.rs:1095` |
| `ServerContext.udp: Vec<(SocketAddr, Arc<UdpSocket>)>` | 实例内 | ❌ socket 句柄 | `main.rs:723-745`、`778-783` |

### 1.2 所有读写 allocation 的入口（含「需要回给客户端什么」）

| 入口 | 位置 | 读到什么 / 写什么 | 需要回给客户端 |
|---|---|---|---|
| `Turn::handle`（唯一分派点） | `turn.rs:1159-1242` | 解析 + 分流：`ChannelData`（1176-1202）、`Send` indication（1210-1213）、TURN 方法白名单（1220-1229） | `Option<Result<Decision, ParseError>>`：`None` = 不是 TURN（交给 STUN 路径） |
| `Turn::handle_request` | `turn.rs:1245-1310` | 鉴权（1268）→ 未知属性 420（1277-1288）→ 方法分派（1290-1309） | `Decision` |
| `allocate` | `turn.rs:1314-1820` | 读 `get()`（1435）；写 `insert()`（1802）、端口池、`reservations` | `200` + `XOR-RELAYED-ADDRESS`/`XOR-MAPPED-ADDRESS`/`LIFETIME`/`(RESERVATION-TOKEN)`/`SOFTWARE` |
| `refresh` | `turn.rs:1824-1933` | 读 `get()`（1839）；写 `expires_at`（1925）或 `remove()`（1912） | `200` + `LIFETIME`；无 allocation → **437**（1840-1846） |
| `create_permission` | `turn.rs:1937-2057` | 读 `get()`（1953）；写 `state.permissions`（2044-2048） | `200` 空体；`508`/`437`/`441`/`443`/`403` |
| `channel_bind` | `turn.rs:2061-2226` | 读 `get()`（2077）；写 `state.channels` + `permissions`（2208-2217） | `200` 空体；`400`/`508`/`437`/`441` |
| `connect`（RFC 6062，async） | `turn.rs:2237-2476` | 读 `get()`（2265）；写 `connections`（2320-2373、2427-2439）；dial 从 relay 地址出站（2377-2381） | `200` + `CONNECTION-ID`（**不带 SOFTWARE**）；`437`/`441`/`446`/`447`/`508`/`403` |
| `connection_bind` | `turn.rs:2481-2594` | 读「新连接 5 元组无 allocation」（2512）；写 `connections[id].state = Bound`（2551-2567） | `Decision::Bind{response, id}` 或 `400` |
| `take_bind` | `turn.rs:2600-2604` | 取出 `oneshot::Sender<DataConnection>` | 由 `main.rs:3057-3088` 完成交接 |
| `send_indication` | `turn.rs:2738-2834` | 读 `get()`（2752）+ `permissions`（2773-2776）；写 relay socket | **无响应**；无 allocation / 无 permission → **静默丢弃**（2752-2754、2777-2779） |
| `handle_channel_data` | `turn.rs:2881-2931` | 读 `get()`（2896）+ `channels`/`permissions`（2907-2923） | **无响应**；无 allocation → **静默丢弃**（2896-2898） |
| `sweep`（1s 常驻） | `turn.rs:1050-1112`，启动 `1115-1125` | 扫 `expires_at`、`permissions`、`channels`、`reservations`、`connections` | 无 |
| `release_connection` | `turn.rs:941-953` | `remove(&key)`（TCP/DTLS 连接关闭时） | 无 |
| `insert` / `remove` / `close_connections_for` / `release_port` | `turn.rs:885-937`、`900-906` | 表 + 端口池 + 数据连接 | 无 |
| `get` | `turn.rs:877-883` | 读表 + `remaining(now)` 过期判断 | — |
| `quota_counts` | `turn.rs:2933-2946` | 扫全表（per-user / per-IP） | — |
| `snapshot` / `active` | `turn.rs:827-865` | 读 `Counters` + `connections` 计数 | `/metrics`、退出日志 |
| 上游调用点（3 处） | `main.rs:2592-2605`（UDP）、`main.rs:3182-3196`（TCP/TLS 流）、`main.rs:4042-4052`（DTLS） | — | — |

### 1.3 天然只能属于归属实例的东西

| 资源 | 为什么不可迁移 | 代码 |
|---|---|---|
| UDP relay socket | 端口已在归属实例的 netns 绑定；rebind 会让 peer 侧所有已缓存路径失效 | `turn.rs:958-977` |
| TCP relay listener | 同上 + `SO_REUSEPORT` 使「同端口多 listener」看似可行，实则入站连接被内核分流到错误实例 | `turn.rs:984-1000`、`main.rs:4158-4175` |
| relay reader 任务 / accept 任务 | 持有 socket 的 `Arc` 与 `ClientSink`；`Drop` 靠 abort 释放端口 | `turn.rs:1760-1786`、`666-679` |
| RFC 6062 peer socket（`DataConnection.reader` / 出站 `TcpStream`） | 内核 socket + 读写半部 + 任务 | `turn.rs:706-719`、`2997-3005` |
| `--max-inflight` 名额 | 是「本进程并发」的定义 | `limit.rs:615-660` |
| 令牌桶（带宽） | 每包都要扣减；跨实例同步不可行 | `turn.rs:2841-2878`、`3376-3388` |

---

### 1.4 现有「跨实例已经能用」的部分（下一节的问题清单 §3）

| 能力 | 机制 | 边界 |
|---|---|---|
| nonce 互认 | `nonce = base64url(expiry(5B) ‖ HMAC-SHA256(secret, expiry‖client_ip)[..11])`（`auth.rs:734-783`，`NONCE_MASK` 在 `786-788`） | 只绑 `expiry + client_ip`；**不含实例/主机/端口**，也不含 server 标识（`docs/book/src/protocol.md:155-160` 明确记录了这个绑定范围）。所以任何同 `--auth-secret` 的实例都能签/验。作用**仅限**：`MESSAGE-INTEGRITY` 校验通过 → 走到方法分派。它**不证明** nonce 由同一实例签发，也**不携带**任何归属信息。 |
| 用户口令 / 长期密钥 | `--auth-user/--auth-pass`、`--auth-file`（启动时读一次，`main.rs:1054`、`auth.rs:1095`）；`Identity.keys` 由用户名+口令派生 | 靠**配置相同**而非共享存储；`--auth-file` 不支持热重载 |
| TURN REST 临时凭据 | `--rest-secret`，`password = base64(HMAC-SHA1(secret, "expiry:label"))`（`auth.rs:455`、`497`） | 无状态，同 secret 的任意实例都能验；同样只做鉴权，不做归属 |
| 响应签名 | `auth::seal`（`auth.rs:801-822`）用请求里验证通过的 key 重新签 | 因此**任何**持有同一份用户表/REST secret 的实例都能替归属实例签响应 —— 这是转发方案能成立的前提之一 |

**重要副作用**：`Send` indication 与 `ChannelData` 在 `handle` 里**先于鉴权**被分流（`turn.rs:1176-1213`），两条路径都**不做身份校验**。所以数据面的跨实例路由只能**按 5 元组**判定，不能依赖「已认证身份」。

---

## 2. 为什么现在会坏

### 2.1 失败路径一览（每条都有代码分支）

| 客户端动作 | 落到非归属实例的后果 | 代码分支 |
|---|---|---|
| `Refresh` | **437 Allocation Mismatch** | `turn.rs:1839-1847` |
| `CreatePermission` | **437** | `turn.rs:1953-1961` |
| `ChannelBind` | **437** | `turn.rs:2077-2085` |
| `Connect` | **437**（若该实例上恰好有 UDP allocation → 也是 437，`2285-2293`） | `turn.rs:2265-2273` |
| `ConnectionBind` | **400**（`connections` 表里没有该 `CONNECTION-ID`） | `turn.rs:2551-2582` |
| `Send` indication | **静默丢弃**（比 437 更糟：客户端会以为媒体在走） | `turn.rs:2752-2754` |
| `ChannelData`（UDP/DTLS/TCP 流） | **静默丢弃** | `turn.rs:2896-2898` |
| `Allocate`（重传/新建） | **创建第二个 allocation**，返回**另一个 relay 地址** | `turn.rs:1435`（表空）→ `1660-1678` → `1802` |

### 2.2 实测（两个真实进程，同段 `50600-50610`）

```
### 2. Refresh on the non-owner (allocation exists only on A) ###
   C relay: ('127.0.0.1', 50604)
   Refresh -> B (non-owner): error code = 437
```

注意这条链路能走到 437，说明**鉴权已经通过**：A 发的 nonce 被 B 接受（`--auth-secret` 相同，`auth.rs:734-783`），失败点纯粹是「B 的 allocation 表里没有」。

### 2.3 更隐蔽的两个后果

**(a) 重复 allocation（不是 437，是静默分裂）**

```
### 3. Duplicate Allocate on the other instance (same client socket) ###
   first relay: ('127.0.0.1', 50606)  second relay (other instance): ('127.0.0.1', 50608)
```

同一个客户端 socket 先向 A `Allocate`、再向 B 发同样的 `Allocate`：B 的表是空的 → 它**认为自己该建**，于是占第二个 relay 端口。此时同一 5 元组在两个实例上各有一份 allocation、两个不同 relay 地址，客户端每次重传可能拿到不同地址；旧的那份要等 TTL（默认 600 s，`turn.rs:1134-1143`）才回收，期间白占一个端口与一个 relay 实例。**该实例上的 `--max-allocations-per-user` 也是分开计的**（`quota_counts`，`turn.rs:2933-2946`），全局配额实际变成 N 倍。

**(b) TCP 控制连接关闭时的泄漏**

`serve_turn_stream` 在任何结束形态都调用 `turn.release_connection(peer, local, transport)`（`main.rs:3036`、`3044`、`3052`；DTLS 在 `4101`）。若该连接被 B 接受、allocation 却在 A 上，这个 `remove` 在 B 上是 no-op → **A 的 allocation 与其 relay socket 一直活到 TTL**。同理 `Connect` 建立的出站数据连接在 B 侧关闭时也不会去通知 A。

### 2.4 端口池 / `SO_REUSEPORT` 的结论（全文最关键的判定）

**代码现状**

- UDP relay：`udp_socket()` 只做 `only_v6` → `nonblocking` → `bind`（`main.rs:4137-4145`），**没有任何 reuse 选项**。
- TCP relay：`tcp_relay_listener()` → `tcp_listener_with(address, true)`，`unix` 下 `set_reuse_address(true)` + `set_reuse_port(true)`（`main.rs:4158-4175`）。用途写在注释里：让 `Connect` 能从 relay 端口**出站**（`turn.rs:2962-2986`，RFC 6062 §5.2）。
- `--listen` 的 UDP/TCP 监听器走 `udp_socket` / `tcp_listener`（后者 `reuse_port=false`，`main.rs:4148-4150`）→ 同机两实例**不能**共用 `--listen` 端口。

**内核行为（本机实测，见 §7）**

| 场景 | 结果 |
|---|---|
| 两个 UDP socket 同端口、**不**设 REUSEPORT | 第二个 `bind` → `EADDRINUSE(98)` |
| 两个 UDP socket 同端口、都设 REUSEPORT | 都成功；**同源 60 包全部落同一个 socket**，60 个不同源 → 34/26 分流（按 4 元组哈希） |
| 两个 TCP listener 同端口、都设 REUSEPORT | 都成功；40 条连接 → 18/22 分流 |

**因此在 rstun 里**

- **UDP relay 池：可以「共享同一段」，且不会重叠** —— 因为 bind 失败即跳过（`turn.rs:968-972`，注释明写「held by *someone else* … skip it」）。实测两实例同段 → `50600` / `50602`，`ss -lun` 各占一个。代价是每次 `Allocate` 都要从 `lo` 扫到 `hi`（默认 16384 个端口，`turn.rs:228`）并逐个尝试 bind，实例越多最坏情况越慢；这是性能问题，不是正确性问题。
- **TCP relay 池：必须按实例分片（不重叠段）** —— `take_tcp_port` 只查**自己**的 `used_tcp_ports`（`turn.rs:986-994`），而 bind 因 REUSEPORT **一定成功**，于是两个实例都拿到同段最低端口。实测：

```
### 4. TCP relay listener ports (SO_REUSEPORT) ###
   A tcp relay: (('127.0.0.1', 50600), None)  B tcp relay: (('127.0.0.1', 50600), None)
   ss -ltn:
      LISTEN 0 1024  127.0.0.1:50600  0.0.0.0:*
      LISTEN 0 1024  127.0.0.1:50600  0.0.0.0:*
```

  两个**不同 allocation** 的 listener 落在同一端口，内核按 4 元组把入站 peer 分给任意一方；分到非归属实例时，`spawn_tcp_accept_loop` 用自己的（空）permission 表判定 → 关连接、**不发 `ConnectionAttempt`**（`turn.rs:3200-3211`），客户端永远等不到那条 indication。spec 已经把这一点写进测试隔离条款：`.trellis/spec/backend/turn.md:152-153`（"共用默认段时内核会把并发测试的 peer 轮转投递给别的实例"）。
- **`--listen` 端口**：同机多实例也**不能**共享（没有 REUSEPORT），必须用不同端口 + LB 各自指向，或用容器/不同 netns 各自 `0.0.0.0:3478`。

**所以「靠端口共享做无状态」不成立**：

1. UDP relay 端口根本共享不了；
2. 真给 UDP 加上 REUSEPORT 也只会得到**单机内的按流哈希粘性**（实测同源恒定同一 socket），而不是无状态；且 relay 端口一旦被共享，peer 的数据报会被散到没有 permission 表的实例上（`turn.rs:3371-3373` 直接 `continue`）；
3. TCP relay 共享端口**会主动制造**被动模式的错误投递。

唯一有意义的推论：**同机多实例下，UDP 池可共用一段（系统自动分区），TCP 池必须显式分片（`--relay-ports` 各给一段）**；跨机多实例（各自独立 IP）时端口号重复无害，因为 relay 地址的 IP 不同（`egress_ip`，`turn.rs:1495-1503`）。

---

## 3. 三种候选架构

> 目标读者是 design.md 的取舍。三种都按「数据流 / 需要什么共享 / 对契约·依赖·测试的影响 / 失效模式」写。**不下结论**（除 §5 的开放问题里给推荐）。

### A. 粘性路由（不改代码，infra 层）—— 基准对照

**数据流**

```
client ──► LB（源地址哈希/一致性哈希） ──► 固定实例 A
                                          A: 全部 TURN 状态
peer  ──► 127.0.0.1? 否：relay_addr = A 的 IP:port（直达，不经 LB）
```

**需要的共享**：零。要求 LB 支持「按客户端源 IP（或 IP+port）着色」且 `externalTrafficPolicy: Local`（`contrib/k8s/service.yaml:16-17`、`contrib/helm/values.yaml:65` 已写）。

**影响**：`contrib/k8s/deployment.yaml:23-25` 与 `contrib/helm/values.yaml:6` 现在是 `replicas: 1` + `Recreate`（hostNetwork 抢端口）；开多副本要改成「每节点一个 + 不同 relay 段」或去掉 hostNetwork。文档已经把这个方案作为现状说明（`docs/book/src/turn.md:53`、`docs/book/src/protocol.md:151`）。

**失效模式**：客户端 NAT 重绑（源端口变化）→ 换实例 → 全部方法 437，直到 TTL；LB 节点故障 → 该实例上的 allocation 全部失效（无迁移）；同 NAT 后大量客户端共享一个源 IP → 哈希倾斜；`--max-inflight` 与配额按实例计，跨实例不均衡。

### B. 归属表 + 请求转发（owner 独占 socket）

**数据流（控制面）**

```
client ─► 入口实例 E：解析 + 鉴权（或原样转发）
            │  owner = map[归一化Key]         ← 归属表（共享）
            ├─ owner == self → 现有 Turn::handle 原样跑
            └─ owner != self → 内部连接 ──► owner A: Turn::handle(frame, peer, local, transport, sink=远端代理 sink)
                                              └─ 响应字节（已 seal）──► E ──► client
数据面（peer→client）：
  UDP  : A 的 relay reader 直接用 A 的监听 socket send_to(client)          —— 无需回 E
  TCP/TLS/DTLS: A 必须把 Data/ChannelData/ConnectionAttempt 推到 E，
               由 E 写入该连接的 writer 队列（main.rs:3009 / 4002）
```

**需要的共享**

- 归属表：归一化键 → 实例 id + lease/心跳 TTL（key 里不能直接用 `Key.server`，见 §0-2）。
- 实例注册表 + 存活探测（复用 `/healthz`？`ops.rs:1023-1037`）。
- 内部转发协议（新端口或新端点）：必须能承载 ①请求/响应（≤ ~64 KiB，`UDP_RECV_BUFFER=65535` main.rs:111 + 头；STUN 长度是 u16，`protocol.rs:294-313`）②**连接级反向推送**（TCP/DTLS 的 sink）③RFC 6062 bind 后的**裸字节双向中继**。
- 不共享：socket/listener/任务/令牌桶/`Permit`。

**对契约 / 依赖 / 测试的影响**

- 「默认关闭路径逐字节不变」的冻结契约不受影响（`--turn` 之外完全不碰），但 **TURN 侧所有断言点在「转发」形态下都要重跑**；`.trellis/spec/backend/turn.md` §5a/§5b 的方法学契约（437/441/446/447 的返回条件）在跨实例语义下要重新表述（例如「无 allocation → 437」变成「归属表无条目且本实例表无条目 → 437」）。
- 无新依赖（内部协议手写，和 `ops.rs` 的极简 HTTP 同风格）；`Cargo.toml` 依赖数契约（lean 10 / full 15，`turn.md:171-183` 第 7 条）不变。
- **单测可覆盖**：`src/turn/tests.rs` 的 `start_on` 已经是「一个进程一个 `Turn` + 一个 `serve_udp`」（`tests.rs:69-108`），同一进程起两个 harness 天然是两个实例（各用 `127.0.0.1:0` 拿到不同 `server` 分量），`tcp_relay_config()` 已示范每测试独占 relay 段（`tests.rs:2226-2246`）。跨实例用例可以直接在同进程内起两个 `Turn` + 一个「假转发层」。
- 新增配置面（实例 id、对端列表、内部端口）→ 必须同步 `--help`（四 feature 构建都要一致，`turn.md:169`）与 `script/ci/check-docs.sh`（它会把文档里出现的每个 `rstun_*` 与真跑实例的 `/metrics` 对照，`check-docs.sh:88-135`、`317`）。

**失效模式**

- 归属表与真实 owner 不一致（旧条目 / 脑裂）→ 请求被送到错的实例 → 与今天同样的 437，但客户端无法自愈（比 A 更隐蔽，因为「有时能成」）。
- owner 崩溃：归属条目靠 TTL 过期 → 该窗口内请求转发失败（要选一个明确的错误码语义，否则会退化成 500）。
- 每次控制面请求多一跳；**`Send`/`ChannelData` 是高频路径**，入口实例到 owner 的内部带宽 = 上行媒体带宽（2 倍内部流量）。
- 内部链路的超时/背压必须严于客户端预算：`TCP_READ_TIMEOUT = 30s`（`main.rs:115`、`2924-2937`）是每帧上限，转发若占满它，客户端侧就会超时。
- RFC 6062：`ConnectionBind` 之后本连接是**裸字节**（`turn.rs:2584-2593`、`main.rs:3057-3088`），而 peer socket 在 owner 上 → 这条连接退化成「E↔A 的内部裸字节中继」，是 B 方案里最重的一块。
- `--max-inflight` 语义变化：一次转发在两个进程各占一个名额（`limit.rs:615-660`）。

### C. 共享状态存储（Redis 等）+ 端口分片

**数据流**

```
client ─► 任意实例 ─► 读/写共享 KV（allocation 元数据、permissions、channels、expiry）
                     relay socket 仍在「第一次创建它的实例」上
peer   ─► relay_addr（该实例 IP:port，直达）
```

**必须先解决的硬问题（代码层面已确认）**

1. **没有任何 `Instant` 可跨进程**：`AllocationState.expires_at`、`permissions`/`channels` 的 deadline、`TcpConnection.expires_at`、`Reservation.expires_at` 全是 `std::time::Instant`（`turn.rs:513-518`、`732`、`791-796`）。共享存储只能用墙钟 → 需要把所有 TTL 改成「剩余时长」或 `SystemTime`，并接受跨机时钟偏差（这会改动 `sweep` 的全部比较与 `granted_lifetime` 的语义，`turn.rs:1050-1112`、`1134-1143`）。
2. **数据面热路径不能远程查**：relay reader 每收一个包都要查 `permissions`（`turn.rs:3355-3373`），`Send`/`ChannelData` 每包都查（`2773-2776`、`2907-2923`）。远程查 = 每包一次 RTT；只能做「本地缓存 + 变更推送」——而这**就是 B 的内部协议**，只是换成了 Redis pub/sub。
3. **relay socket 仍然不能共享** → 任何触及 socket 的操作（`Allocate` 取端口、`Send`、`ChannelData`、`Connect`、入站 accept）依然要么落到 owner，要么转发。C **不能**消除转发，只消除「元数据类方法」的 437（`Refresh`/`CreatePermission`/`ChannelBind` 可以就地改共享状态……但改完 owner 的 reader 靠的是本地缓存，仍然需要推送，见第 2 点）。
4. **权限判定是安全边界**（RFC 8656 §8；`turn.rs:2773-2779` 是「无 permission 就丢」的唯一实现点）。缓存不一致 = 要么放行不该放的，要么丢掉该放的。这是 C 最大的风险面。
5. 端口分片仍然必需（§2.4 的 TCP 结论不变）。

**影响**：新增外部依赖（与「单二进制、standalone、10 个直接依赖」的定位冲突，`Cargo.toml:20-33`），新增可用性单点；`/metrics` 与退出统计「同源」的契约（`ops.rs:1-10`）在共享存储下会分裂成「本进程计数」与「全局计数」两套。

**失效模式**：存储在但实例死 → 元数据指向已关闭的 socket；存储在但网络分区 → 两个实例都认为自己是 owner（写入无 fencing）；存储不可用 → 全部 TURN 请求失败（比现在的「单实例失败」放大到全集群）。

---

## 4. 代码接缝清单

### 5.1 必须改（若走 B；C 需要改的更多，见上）

| # | 位置 | 现状 | 要改什么 |
|---|---|---|---|
| 1 | `turn.rs:1159-1242` `Turn::handle` | 唯一 TURN 分派点，参数 `(datagram, peer, local, transport, context, sink)` | 在此前/此处插入归属判定与转发分支；必须保证 `None`（非 TURN）仍原样返回 |
| 2 | `turn.rs:2881-2931` `handle_channel_data` | **唯一绕过 `handle` 的入口**（`main.rs:3137` 直接调） | 同样需要归属判定（TCP/DTLS 流上的 `ChannelData`） |
| 3 | `main.rs:2581-2643` `respond_to_datagram` | `Decision::Respond` → `socket.send_to(&response, peer)`（2634） | 响应可能来自 owner（`Decision` 需要区分「本实例判定」与「远端字节」），发送仍在本实例完成 |
| 4 | `main.rs:3009-3017` + `3182-3205` `serve_turn_stream` / `stream_turn_loop` | `sender: mpsc::Sender<Vec<u8>>` 是本连接专属写队列 | `ClientSink` 需要一个「远端 sink」（把字节推回接受实例的这条连接）；`Decision::Bind` 之后还有裸字节半关闭语义（`3057-3088`） |
| 5 | `main.rs:4002-4052` DTLS 连接循环 | 同 4，另一份 writer 队列 | 同 4 |
| 6 | `turn.rs:1721-1748` `allocate` 里的 `ClientSink` 构造 | 只有 `Udp(Arc<UdpSocket>)` / `Queue(mpsc)` 两种 | 新增远端变体（owner 需要知道「回给哪个实例的哪条连接」） |
| 7 | `turn.rs:941-953` `release_connection` | 只 `remove` 本地表 | 非 owner 时必须通知 owner 释放 |
| 8 | `turn.rs:722-739` + `2551-2582` + `main.rs:3057-3088` | `TcpConnection.bind: oneshot::Sender<DataConnection>` 纯进程内 | 跨实例需要内部流（`DataConnection` 的远端变体）；`reader` 是 `Box<dyn AsyncRead>`（`turn.rs:707`），要能包一层内部连接 |
| 9 | `turn.rs:2933-2946` `quota_counts` | 扫本实例表 | 若要做**全局**配额，只能问归属表/注册表（需要决定是否值得） |
| 10 | `turn.rs:777-789` `Turn` 结构 | 只有表、端口池、reservations、connections、counters | 新增：本实例 id、对端注册表、转发客户端、归属表句柄（都是**可选 None** 才不破坏现状） |
| 11 | `main.rs:2586-2588` 的 `local` 语义 + `turn.rs:476-480` `Key` | UDP 用绑定地址、TCP 用连接本地地址 | **定义跨实例归一化键**（否则归属表永远查不中，见 §0-2） |
| 12 | 新配置面（实例 id / 对端 / 内部端口 / 端口分片） | — | 同步：`--help`（`main.rs:318-360` 同风格）、`script/ci/check-docs.sh`（`88-135`）、`.trellis/spec/backend/turn.md`、`docs/book/src/turn.md`、`contrib/{k8s,helm,docker}` |

### 5.2 可选（视设计取舍）

| 位置 | 说明 |
|---|---|
| `sweep`（`turn.rs:1050-1112`） | owner-only 即可；只有做「归属表 TTL 回收」时才需要扩展 |
| `Counters`（`turn.rs:382-414`）+ `ops.rs:416-536` | 要不要「全局指标」？注意**标签集固定**（`ops.md:40-60`、`turn.md:167`）：`instance=` 这类标签会让 `check-docs` 与标签契约同时变红 |
| `limit::Admission`（`limit.rs:622-660`） | 转发后每源限速在两个实例各算一次；要么接受，要么在入口实例统一限速 |
| `contrib/k8s|helm` 的 `replicas: 1` + `Recreate`（`deployment.yaml:23-25`、`values.yaml:6`） | 多副本的部署形态（hostNetwork 抢占 vs 每 pod 独立 IP） |

### 5.3 不要动

| 位置 | 原因 |
|---|---|
| `AllocationState` / `TokenBucket` 的每包语义（`turn.rs:511-563`、`2841-2878`） | 数据面零锁 / 单实例本地性是其性能前提；改成远程同步会毁掉中继性能 |
| `protocol.rs`（`294-313` `peek_frame_len`） | 线上格式，改动无收益 |
| `--turn` 关闭时的全部路径（`stats.turn() == None`） | 字节冻结契约：`turn.md:108-117`、`ops.md` 的「默认全关」 |
| `tcp_relay_listener` 的 REUSEPORT（`main.rs:4158-4175`） | 它是 `Connect` 从 relay 地址**出站**的前提（RFC 6062 §5.2），不能为了多实例去掉；正确做法是分片端口段 |
| `auth.rs` 的 nonce 格式（`734-783`） | 跨实例互认的既有契约，改格式会同时破坏单实例升级体验 |

---

## 5. 开放问题（各带推荐）

| # | 问题 | 选项 | 推荐 |
|---|---|---|---|
| Q1 | 数据面「客户端→peer」是否接受多一跳？ | (a) 全部转发（实现简单，内部流量翻倍）(b) 只转发控制面，数据面放弃（= 不满足 PRD） | (a)；但把 `Send`/`ChannelData` 做成**无响应、fire-and-forget** 的独立通道，别复用请求/响应协议 |
| Q2 | 回程地址的可接受性 | 归属实例直接 `send_to` 客户端（源地址 = 归属实例 IP，与客户端发往的 VIP 不同） | 先**实测**再定：用 lab 的假 LB 跑 `turnutils_uclient`，看客户端是否接受来自非 VIP 的 `Data`/`ChannelData`（**待验证**）。若不接受，回程也必须经入口实例 |
| Q3 | 谁做鉴权 | (a) 入口实例鉴权后把 `Identity`（含 HMAC key）带给 owner (b) 原样转发，owner 自己鉴权 | (b)：配置相同则结果相同，且避免把 key 交给内部协议；代价是坏凭据也会被转发一次 |
| Q4 | 归属键 | (a) 直接 `Key` (b) `(client, transport)` (c) `(client, transport, listen-port)` | (c)：`Key.server` 的两种语义（§0-2）使得 (a) 在同机不同端口时失效、(b) 在多 `--listen` 时冲突 |
| Q5 | 端口池策略 | (a) 全部共用同段 (b) UDP 共用 + TCP 分片 (c) 全部分片 | (b)：UDP 靠 bind 失败自动分区（实测），TCP **必须**分片（实测同端口双 LISTEN）。若追求可预测性（避免 O(range) 扫描）选 (c) |
| Q6 | 引用/`--max-inflight`/配额的全局性 | 接受按实例计 vs 引入全局计数 | 按实例计（现状，`limit.rs:615-660`、`turn.rs:2933-2946`），在文档里写明是 N 倍上限 |
| Q7 | 内部协议载体 | (a) 复用 `--health-listen`（`ops.rs:740-1050`：只认 GET/HEAD、**拒绝请求体** 1001/1005、一连接一请求） (b) 新开内部端口 (c) 新端点 + 自定义头 | (b)：现有 ops 端点的契约是「GET /healthz / GET /metrics，一连接一请求」（`ops.md:40-60`、`ops.rs:1015`），塞入双向推送会破坏它 |
| Q8 | 是否保持「单二进制、无外部依赖」 | (a) 是（→ 排除 C）(b) 否（→ C 才可行） | (a)：`Cargo.toml:20-33` 的依赖数契约 + standalone 定位；且 C 也消不掉转发（§3-C 第 3 点） |
| Q9 | RFC 6062 是否首期覆盖 | (a) 全做（含 bind 后裸字节的内部中继）(b) 首期只保证 UDP allocation，`--turn-tcp-relay` 在多实例下拒绝启动 | (b) 更省，但要与「PRD 说覆盖 RFC 6062」对齐；若 (a)，必须为 `StreamOutcome::Bound`（`main.rs:3057-3088`）设计内部裸字节通道 |

---

## 6. 测试与验证面

### 7.1 单测 harness 现状

- `start_on(bind, config, auth)`（`tests.rs:75-108`，`start`/`start_with` 在 `65`/`69`）：自建 `udp_socket` → `Turn::new` → `ServerStats::set_turn` → `ServerContext{ udp: vec![(bound, socket)] }` → `spawn(serve_udp)`。**同一进程起两个 harness 完全可行**，因为 `--listen` 用 `127.0.0.1:0` 让 `Key.server` 天然不同（这也说明单测里的「两个实例」不会碰到 §0-2 的键坍缩问题，需要**显式**构造同键场景）。
- `start_tcp` / `TcpHarness`（`tests.rs:2193-2225`）提供 TCP 侧；`TcpClient`（`tests.rs:868-935`）已能走 401→签名→帧解析。
- **每测试独占 relay 段的既有做法**：`tcp_relay_config()`（`tests.rs:2226-2246`）用 `AtomicU64` 窗口 + `% 400` 给出 `(lo, lo+99)`，理由注释就是 REUSEPORT 会让并发测试抢同端口。跨实例用例需要**两个不同窗口**（一个实例一段）。
- 可直接复用的断言点：437（`tests.rs:587-595`、`693-709`、`2353-2366`）、`used_ports` 回池（`tests.rs:796-807`）、`tcp_pending/bound` gauge。
- 尚缺：「同一 5 元组在两个 `Turn` 上分别建 allocation」的用例 —— 这正是 §2.3 的重复 allocation，建议新增。

### 7.2 lab 扩展可行性

- `start_server(name, args…)` 是**通用**的（`script/lab/rstun-turn.sh:135-141`），所以起两个进程只是多一次调用；但 `turn_args()` 把 `--listen $BASE` / `--relay-ports $RELAY_LO-$RELAY_HI` / `--health-listen $HEALTH_PORT` **写死**（`203-215`），需要改成「按实例传入」的参数化版本；同理 `relay_listeners()`/`relay_tcp_listeners()`/`relay_sockets()` 用全局 `$RELAY_LO/$RELAY_HI` 过滤（`172-199`），做双实例时要按段各查一次。
- 探针 `rstun-turn-probe.py` 的 `--server host:port` 是纯 socket 客户端：UDP 用 `sendto`+`recvfrom`（**未 connect**，`201-202`、`290-291`），所以「假 LB 转发回来的响应来自后端地址」也能收；TCP `TcpRelayProbe` 用 `connect()`（`536`），假 LB 需要做 TCP 代理。→ **「两个 server + 一个 Python 假 LB（轮转/UDP 逐包轮转、TCP 转发）」端到端可行**。
- 已有可复用的 lab 项：`relay`、`tcprelay`、`tcp-relay-passive`、`cleanup`（用 `ss` 断言段内无残留，`script/lab/rstun-turn.sh:172-199`）。双实例场景的判据建议：①A `Allocate`、B `Refresh`/`Send`/`ChannelData` 后字节计数增长；②`ss -lun`/`-ltn` 在两个段内各自无残留（`cleanup` 的既有语义）；③TCP 场景断言两个实例的 relay 段**不重叠**。

### 7.3 建议的验收证据（写进 design 前先确认）

1. 两进程 + 假 LB 的 `Refresh`/`CreatePermission`/`ChannelBind` → 期望 200（现状 437，已实测）。
2. 同一客户端 5 元组在两个实例上的 `Allocate` → 期望只有一份 allocation（现状两份，已实测）。
3. UDP `Send`/`ChannelData` 经非归属实例 → 期望对端收到字节（现状静默丢，代码 `turn.rs:2752-2754`）。
4. TCP 控制连接由 B 接受、allocation 在 A，客户端断开 → 期望 A 的 allocation 立刻回收（现状等 TTL，代码 `main.rs:3036-3052`）。
5. RFC 6062 出站 + 被动各一条（`turnutils_uclient -T` / `-P`）。

---

## 7. 证据附录

### 8.1 内核 `SO_REUSEPORT` 行为（python 现场验证）

```
UDP distinct  60 datagrams -> sock0=34 sock1=26      # 60 个不同源端口 → 按 4 元组哈希分流
UDP same-port 60 datagrams -> sock0=60 sock1=0       # 同一源端口 → 全部落同一 socket（按流粘性）
TCP REUSEPORT 40 conns -> listener0=18 listener1=22  # 入站连接被分流
UDP no-REUSEPORT second bind fails: 98 Address already in use
TCP no-REUSEPORT second bind fails: 98 Address already in use
```

### 8.2 `local_addr` 语义（决定 `Key.server` 的两种含义）

```
listener bound: ('0.0.0.0', 10767)
accepted sock local (getsockname): ('127.0.0.1', 10767)   # TCP：具体 IP
udp bound local: ('0.0.0.0', 37327)                       # UDP：仍是通配
```

与代码注释一致：`turn.rs:2680-2683`（"for TURN-over-TCP `stream.local_addr()` is concrete even when the listener is `0.0.0.0`"）、`main.rs:2404`（UDP 用 `socket.local_addr()`）、`main.rs:2955`（TCP 用 `stream.local_addr()`）。

### 8.3 两个真实 rstun 进程（`target/debug/rstun`，`--tcp --turn --turn-tcp-relay`，同段 `50600-50610`）

命令要点：

```
rstun server --listen 127.0.0.1:38180 --tcp --turn --realm example.org \
  --auth-secret mi-secret --auth-user turnuser --auth-pass turnpass \
  --relay-ports 50600-50610 --health-listen 127.0.0.1:39180 --turn-tcp-relay
（B 同，端口 38181/39181）
```

驱动脚本：复用 `script/lab/rstun-turn-probe.py` 的 `Probe` / `TcpRelayProbe`（`importlib` 加载），输出：

```
### 1. UDP relay pools when two instances share one range ###
   A relay: ('127.0.0.1', 50600)  B relay: ('127.0.0.1', 50602)
   ss -lun:
      UNCONN 0 0  127.0.0.1:50600  0.0.0.0:*
      UNCONN 0 0  127.0.0.1:50602  0.0.0.0:*

### 2. Refresh on the non-owner (allocation exists only on A) ###
   C relay: ('127.0.0.1', 50604)
   Refresh -> B (non-owner): error code = 437

### 3. Duplicate Allocate on the other instance (same client socket) ###
   first relay: ('127.0.0.1', 50606)  second relay (other instance): ('127.0.0.1', 50608)

### 4. TCP relay listener ports (SO_REUSEPORT) ###
   A tcp relay: (('127.0.0.1', 50600), None)  B tcp relay: (('127.0.0.1', 50600), None)
   ss -ltn:
      LISTEN 0 1024  127.0.0.1:50600  0.0.0.0:*
      LISTEN 0 1024  127.0.0.1:50600  0.0.0.0:*

### after SIGTERM ###
   ss -lun: []  ss -ltn: []        # 回收干净（与 cleanup 项的既有判据一致）
```

要点：①UDP 同段不冲突（50600 被 A 占用 → B 跳过后取 50602，且 A 的 `EVEN-PORT R=1` 还预留了 50601）；②非归属实例 `Refresh` = 437 且**鉴权已通过**；③同 5 元组在两个实例各建一份 allocation（50606 / 50608）；④两个实例的 TCP relay listener **同端口双 LISTEN**，回收后无残留。

### 8.4 部署面现状（grep 结果）

| 文件 | 现状 |
|---|---|
| `contrib/k8s/deployment.yaml:23-25` | `strategy: Recreate` + `replicas: 1`，注释「一个 Pod 独占一个节点的 3478/3479（hostNetwork）」 |
| `contrib/helm/values.yaml:6` | `replicaCount: 1` |
| `contrib/helm/templates/deployment.yaml:18` | `replicas: {{ .Values.replicaCount }}` |
| `contrib/k8s/service.yaml:16-17` | `type: LoadBalancer` + `externalTrafficPolicy: Local`（为 RFC 5780 保留源地址） |
| `contrib/docker/compose.yaml` | 单 service `rstun`，`network_mode: host` |
| `contrib/helm/values.yaml:69-70` | `hostNetwork: true`、`dnsPolicy: ClusterFirstWithHostNet` |

无 `affinity` 配置内容（`contrib/helm/values.yaml:82` 处 `affinity: {}`）。

### 8.5 关键常量与限制

| 项 | 值 / 位置 |
|---|---|
| 默认 relay 段 | `49152-65535`（16384 个端口），`turn.rs:228` |
| `--relay-ports` 解析/校验 | `LO-HI`，`lo != 0`、`lo <= hi`：`turn.rs:358-374`（解析）、`turn.rs:326-356`（`Config::validate`） |
| `--relay-ports` 契约 | `.trellis/spec/backend/turn.md:125`（TCP 池独立 + REUSEPORT）、`docs/book/src/turn.md:32`、`50-52`（与临时端口段重叠 → 偶发 508） |
| UDP 收包缓冲 | `UDP_RECV_BUFFER = 65535`，`main.rs:111` |
| STUN 帧上限 | `20 + u16`，`protocol.rs:294-313` |
| TCP 单帧超时 | `TCP_READ_TIMEOUT = 30s`，`main.rs:115`、`2924-2937` |
| `--max-inflight` | 每实例 `Semaphore`，`limit.rs:622-660`、`main.rs:750-766`；UDP 每 datagram、TCP 每连接 |
| ops 端点契约 | 只 `GET`/`HEAD`（`ops.rs:1015`）、**拒收请求体**（`1001`、`1005`）、一连接一请求（`serve_http_connection`）、`HTTP_CONNECTION_TIMEOUT = 2s`（`ops.rs:714`） |
| 指标标签集 | 固定、无高基数（`ops.md:40-60`）；TURN 族只在 `--turn` 输出（`ops.rs:416-536`）；`check-docs` 用真实例对照文档里的指标名（`script/ci/check-docs.sh:88-135`、`317`） |

---

## 8. 待验证 / 未覆盖

1. **客户端对「控制面来自 E、数据面来自 A」的容忍度**：未实测（需要 lab 假 LB + 真实客户端，见 Q2）。影响 B 方案是否必须做数据面回程。
2. **TCP 被动模式在同端口双 LISTEN 下的实际投递比例**：已实测内核层 18/22 分流 + 代码层「无 permission 即静默关」（`turn.rs:3200-3211`），但未做「两实例 + 假 LB 的完整 passive 场景」端到端复现。
3. **DTLS 的 `local` 是否为监听器绑定地址**：`main.rs:3891-3894` 用 `listener.addr()` → 与 UDP 同语义（通配时仍是 `0.0.0.0`）；未单独实测。
4. **`--max-allocations-per-user` 在多实例下的真实放大倍数**：取决于 LB 的分布，代码上确为按实例计（`turn.rs:2933-2946`），未压测。
5. **TLS 侧的 `Local` IP 与 LB VIP 关系**（`turns:` 端口同样被 LB 分发）；未在 k8s 环境验证 `externalTrafficPolicy` 与 `turn.tls` 的组合。
