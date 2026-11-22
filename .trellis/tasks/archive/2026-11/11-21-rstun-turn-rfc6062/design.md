# 设计：RFC 6062 TCP allocation（出站 + ConnectionBind）

> 依据：`.trellis/tasks/11-21-rstun-turn-rfc6062/research/rfc6062.md`（725 行，含 RFC 原文、
> 本仓 `file:line`、coturn 4.6.1 黑盒实测）。凡是「实测」结论本设计直接采用；「未验证」项在 §9 列出。

## 1. 三个已拍板的取舍

| # | 取舍 | 决定 | 理由 |
| --- | --- | --- | --- |
| D1 | 开关形态 | **新增 `--turn-tcp-relay`，默认关** | PRD 硬约束「未启用时 442 不变」只有默认关能满足；也避免把 `--turn` 的用户静默带进新语义 |
| D2 | 被动模式（`ConnectionAttempt`） | **本期不做**（留作子项） | 需要「allocation → 控制连接」反向通道（控制面有 UDP/TCP/TLS/DTLS 四种 sink，今天不存在该路径）；`uclient -P` 实测 50% 丢包，`uclient_ok` 的 `lost packets 0` 判据不可复用 |
| D3 | `CONNECTION-ID` 与数据连接状态 | **`Turn` 上全局 `connections: HashMap<u32, TcpConnection>`；每条数据连接独立 task；sweep 摘表 + abort** | 与现有 `Allocation::Drop → abort(relay_task)` 同构；避免塞进 `AllocationState` 与 relay reader 抢锁 |

## 2. 对外行为（开关打开时）

### 2.1 `Allocate`（`REQUESTED-TRANSPORT=6`）

| 条件 | 行为 |
| --- | --- |
| 控制连接是 **UDP 或 DTLS** | `400 Bad Request`（RFC 6062 §5.1 第 2 条；开关关闭时仍 `442`）|
| 带 `DONT-FRAGMENT` / `EVEN-PORT` / `RESERVATION-TOKEN` | `400`（§4.1）|
| 正常 | `200` + `XOR-RELAYED-ADDRESS`（TCP）+ `XOR-MAPPED-ADDRESS` + `LIFETIME` + `SOFTWARE`；**不带 `CONNECTION-ID`** |
| 端口池耗尽 | `508`（沿用）|
| 配额超限 | `486`（沿用）|

TCP 中继的「地址」= 该 allocation 独占的 **TCP listener**（`127.0.0.1:<port>` 或监听地址 IP）。

### 2.2 `Connect`（0x00a，控制连接上）

处理顺序照 RFC §5.2：

1. 该连接无 allocation → `437`
2. 同 allocation 正在连同一 peer → `446`
3. 同 allocation 已连过同一 peer（pending/bound）→ `446`
4. 缺/非法 `XOR-PEER-ADDRESS` → `400`
5. 本地策略禁止（loopback 规则等）→ `403`
6. 出站 TCP，**本地端点 = 该 allocation 的中继地址**；
   失败/超时 → `447`；超时常量 **`TCP_CONNECT_TIMEOUT = 30s`**（RFC MUST ≥30 s）
7. 成功 → peer data connection；**预绑定缓冲**（见 §2.6），响应带 `CONNECTION-ID`（u32，全局唯一）
8. 30 s 内无 `ConnectionBind` → 关闭该 peer data connection

**不做 permission 检查**（RFC 未要求；coturn 实测无 permission 也 200）。
`Connect` 成功响应**不带 `SOFTWARE`**（与 coturn 一致，避免「逐字节对照」分歧；文档注明为有意对齐）。

### 2.3 `ConnectionBind`（0x00b，新数据连接上）

1. 控制传输不是 TCP/TLS → `400`
2. 缺 `CONNECTION-ID` / 不指向 pending 连接 / 已绑定 / 超过 30 s → `400`
   （RFC 要求 400；coturn 线上是「400 后立即销毁连接 → 客户端看到 RST」，本仓**发 400 再关**，比 coturn 更规范，
   对照测试以「我方 400 / coturn RST」显式记录差异）
3. 成功 → 该连接成为 client data connection：**双向裸字节**，不再解析 STUN；预绑定的 peer 数据先刷出

### 2.4 `Refresh` / `LIFETIME` / 回收

- `Refresh` 语义与 UDP 相同（只在控制连接上）。
- **allocation 过期或 `LIFETIME=0`**：关闭该 allocation 的**全部数据连接**（RFC §5.5 MUST）。
  **控制连接保留**（本仓 UDP 现状一致；coturn 会连控制连接一起关——记为有意差异）。
- 数据连接任一侧 EOF/RST → 关闭另一侧（§5.5 三条 MUST）。
- 未 bind 的 pending 连接 30 s 后关闭（`sweep` 每秒扫描，按 `created_at` 判）。

### 2.5 TCP allocation 上的其它方法

| 方法 | 行为 | 理由 |
| --- | --- | --- |
| `CreatePermission` | **正常处理（200）** | `turnutils_uclient -T` 会先发它；RFC 未禁止；被动模式未来复用 |
| `ChannelBind` | `400` | TCP allocation 数据面是裸字节，没有 channel 概念（显式失败优于静默不转发）|
| `Send` indication | 静默丢弃 + 计 `rejected_total{reason="tcp_send"}` | indication 无错误响应；静默转发会误导 |
| `ChannelData` | 丢弃 + 同上计数 | 同上 |

### 2.6 预绑定缓冲

- 每连接上限 **`TCP_PREBIND_BUFFER = 64 KiB`**；超限 → 关闭该 peer data connection
  （RFC §5.2/§7 允许「缓冲将超本地上限时丢弃连接」）。计数 `rejected_total{reason="tcp_buffer"}`。
- 绑定后立即把缓冲区写入 client data connection，再进入双向转发。

## 3. 数据连接的状态机

```
Connect 成功 ──► Pending(buffered bytes) ──ConnectionBind ok──► Bound ──EOF/RST/超时──► Closed
                      └── 30s 未 bind ──► Closed
```

- 每连接一个 `TcpConnection { id, allocation_key, peer_addr, peer_stream, state, buffer, created_at }`；
- `Bound` 后：两个方向各一个 task（`copy`），任一结束 → `shutdown()` 另一方向 → 双方读完 → 摘表。

## 4. 端口与资源

- **独立 TCP 端口池** `used_tcp_ports: HashSet<u16>`（与 UDP 池分开：同一端口号在 UDP/TCP 语义不同，
  共池会造成「UDP allocation 占掉 TCP 想要的端口」这类不可解释的失败）。
- 端口范围仍用 `--relay-ports`。
- 每 allocation 数据连接上限（常量）**`TCP_MAX_CONNECTIONS_PER_ALLOCATION = 16`**，超限 `Connect` → `486`
  （RFC 8661? 不；用 `508 Insufficient Capacity` 更贴切 —— 决定：**`508`**，见 §10 待办）。
- 数据连接是 accepted TCP 连接 ⇒ 天然占用 `--max-inflight` 的 slot（现状），在文档里明写这个语义。

## 5. 指标（新增，固定标签集）

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `rstun_turn_tcp_connections{state="pending"\|"bound"}` | gauge | 当前数据连接数 |
| `rstun_turn_rejected_total{reason="tcp_connect"}` | counter | `447`（连接失败/超时）|
| `rstun_turn_rejected_total{reason="tcp_bind"}` | counter | `ConnectionBind` 的 `400` |
| `rstun_turn_rejected_total{reason="tcp_send"}` | counter | TCP allocation 上的 `Send`/`ChannelData` 丢弃 |
| `rstun_turn_rejected_total{reason="tcp_buffer"}` | counter | 预绑定缓冲超限 |
| `rstun_turn_rejected_total{reason="tcp_quota"}` | counter | 每 allocation 连接数超限 |

同步：`src/ops.rs` 的固定标签枚举、`docs/book` 指标表、`src/turn/tests.rs` 的逐行断言、
`--turn` 关闭时不得出现（既有测试会覆盖）。

## 6. 与现有代码的接线点（研究给出的 `file:line`）

| 位置 | 改动 |
| --- | --- |
| `src/turn.rs:976-996` | `REQUESTED_TRANSPORT` 分支：开关开 + TCP → 走 TCP allocation；UDP/DTLS 控制 → 400 |
| `src/turn.rs:802-876` `handle()` | 增加 `CONNECT_METHOD` / `CONNECTION_BIND_METHOD` 分派（后者由数据连接路径调用）|
| `src/turn.rs:453-484` `Allocation` | `relay` 从 `Arc<UdpSocket>` 抽象为 enum（`Udp(Arc<UdpSocket>)` / `Tcp(TcpRelay)`）|
| `src/turn.rs:653-675` `take_port` | TCP 版本：`tcp_listener()` + `used_tcp_ports` |
| `src/turn.rs:2435-2473` | 白名单加 `CONNECTION_ID (0x002a)`（否则 `Connect` 先 420）|
| `src/turn.rs:725-775` `sweep` | pending 超时、allocation 过期时联动关数据连接 |
| `src/turn.rs:2090-2161` `spawn_relay_reader` | TCP allocation 不走它；改为「每条数据连接两个 copy task」|
| `src/main.rs:2514-2578` / `2763` `serve_tcp*` | 数据连接的 accept 后识别：首帧是 `ConnectionBind` → 交给 TURN 绑定；绑定后切裸字节 |
| `src/main.rs:1028-1045` `build_turn` | 新开关的半配置校验（`--turn-tcp-relay` 需要 `--turn`）|
| `src/main.rs:317-371` | 新 CLI 字段 |

## 7. 兼容与默认路径

- 开关关闭：`Allocate`+TCP 仍 `442`，字节与现在一致（冻结对照不变）。
- 开关打开：只影响 `--turn-tcp-relay` 的用户；UDP 中继/STUN 路径字节不变。
- 文档：`docs/book/src/turn.md` 行为表、`README`「不做」清单、`CHANGELOG ## Unreleased`、spec。

## 8. 验收（与 PRD 对齐）

1. 标准流程探针（`rstun-turn-probe.py --mode tcp-relay`）对 rstun 与 coturn **逐行一致**；
   `turnutils_uclient -T` 因隐含 `-y`（需要被连侧的 `ConnectionAttempt`）**不在本期验收**，
   留到被动模式子任务（`11-22-rstun-turn-passive`）。
2. 无 permission 的 `Connect` → `200`；重复 `Connect` → `446`；连关闭端口 → `447`；
3. `ConnectionBind` 错 ID/二次 bind/超 30 s → `400` 且连接关闭；
4. `LIFETIME=0` / 过期 → 数据连接全部关闭（`ss -ltnH` 无残留）；
5. 半开：client 关写 → peer 读到 EOF；peer 关写 → client 读到 EOF；双向关完即摘表；
6. 开关关闭时 `uclient -T` 仍 `442`（回归）；
7. 默认路径冻结、interop/abuse/turn/audit/deny 全绿；
8. 与 coturn 对跑：探针 `tcp-relay` 在两侧结果一致（`Allocate` 无 `CONNECTION-ID`、`Connect` 无
   `SOFTWARE`、源端口=relay、双向字节）；差异（错 ID 时我方 `400` vs coturn RST、控制连接是否关闭）
   显式记录。（`uclient -T` 不在本期，见 §8.1。）

## 8.1 为什么不用 `turnutils_uclient -T` 验收（2026-11-21 复核确认）

- `uclient` 的 `-T`（TCP relay transport）**Implies options `-t, -y, -c`**；
- `-y` 是 client-to-client：`-T` 只做**一次** `Connect`（`i<j` 的循环），被连的一侧必须由服务器发
  `ConnectionAttempt` 才能 `ConnectionBind`；
- 实测（本仓，开关开）：`uclient -T` → `tot_recv_msgs=0`、进程挂到超时（`exit=124`）；
  开关关 → `error 442`、exit=255（回归正确）；
- 结论：`-T` 的通过前提是**被动模式**，与本期范围冲突。出站链路由探针 + 单测覆盖。

## 9. 未验证 / 待验证（研究声明）

- Windows/macOS 的半关闭语义、RST 映射；`SO_REUSEADDR` 在 Windows 的行为（本仓已有 `cfg(unix)` 门槛）。
- `Connect` 的真实超时下限（coturn 实测 19.4 s，低于 RFC 30 s）——本仓固定 30 s。
- `turns:` 上的 TCP allocation 端到端（控制面 TLS + 数据面 TLS 两条连接）。

## 10. 已拍板（用户 2026-11-21 决定）

1. 每 allocation 数据连接上限（16）超限 → **`508 Insufficient Capacity`**
   + `rstun_turn_rejected_total{reason="tcp_quota"}`（RFC 6062 未规定；508 与端口/权限耗尽口径一致）。
2. `Connect` 成功响应**不带 `SOFTWARE`**（对齐 coturn 32 字节响应）。
   文档注明「有意对齐 coturn」；`Connect` 之外的响应仍按既有规则带 SOFTWARE。

## 11. 回滚

- 开关默认关 ⇒ 上线即可回滚（不删代码也回到旧行为）；
- 如需整体回退：revert 该任务的提交（`src/turn.rs`、`src/main.rs`、`src/ops.rs`、tests、文档、lab）。
