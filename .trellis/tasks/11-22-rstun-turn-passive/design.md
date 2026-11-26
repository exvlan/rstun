# 设计：RFC 6062 被动模式（`ConnectionAttempt`）

> 依据：`archive/2026-11/11-21-rstun-turn-rfc6062/research/rfc6062.md` §5（coturn 实测：有 permission →
> `ConnectionAttempt`(cid+peer) → 新连接 `ConnectionBind`；无 permission → accept 后立即关闭、无 indication）。
> 出站路径已交付并在 `.104` 发布，本任务只加入站。

## 1. 复用与新增

| 组件 | 现状 | 本任务 |
| --- | --- | --- |
| `Allocation.relay` | `Relay::Tcp(TcpRelay { listener })` | 增加一个 **accept 任务**（随 allocation 生命周期）|
| `Allocation.sink` | **未保存**（只在 `allocate()` 局部构造给 relay reader）| 新增字段 `sink: ClientSink`（clone），供向控制连接推 `ConnectionAttempt` |
| `TcpConnection` / `connections: HashMap<u32, …>` | 出站：`Connecting → Pending → Bound` | 入站直接进 **`Pending`**（无 dial）；其余状态机不变 |
| `ConnectionBind` | 已实现（校验 id/username/pending/过期）| **不改**；入站 pending 自然可用 |
| `close_connections_for` | 已实现（allocation 移除级联）| 复用 |
| `TCP_MAX_CONNECTIONS_PER_ALLOCATION = 16` / `TCP_PREBIND_BUFFER = 64 KiB` / pending 30s | 已实现 | 复用；入站计入同一配额 |
| 指标 | `tcp_quota` / `tcp_buffer` 等 | 复用；入站不新增标签 |

新增常量：`CONNECTION_ATTEMPT_METHOD: u16 = 0x00c`（indication，class 0b001）。
`CONNECTION-ID (0x002a)` 已在 420 白名单与属性常量里。

## 2. 数据流（入站）

```
peer ──TCP──> allocation.relay.listener
   accept()
     ├─ 失败 → 记日志，continue（RFC：不通知客户端）
     ├─ permission 表无该 peer IP（5 分钟 TTL）→ 立即关闭，无 indication
     ├─ 该 allocation 的 pending+bound ≥ 16 → 关闭 + rejected{reason="tcp_quota"}
     └─ 分配 CONNECTION-ID（全局递增），插入 TcpConnection{state:Pending, expires_at:now+30s, stop, bind}
          ├─ 起 peer task：读入 → 预绑定缓冲（≤64 KiB，超限关连接 + tcp_buffer）
          └─ 向控制连接 sink 发 `ConnectionAttempt`（CONNECTION-ID + XOR-PEER-ADDRESS [+ SOFTWARE]）
                ↓
client 新连接 ConnectionBind(cid) ──> 既有逻辑：Pending→Bound，交接 stream 与预缓冲
```

`ConnectionAttempt` 是 **indication**：无 MESSAGE-INTEGRITY（RFC 5389），transaction id 随机；
`XOR-PEER-ADDRESS` 用与 Data indication 相同的编码函数；`SOFTWARE` 与 coturn 对齐带上（可选）。

## 3. 反向通道（本任务的核心新增）

`ClientSink` 已有两种形态，直接覆盖四种控制面：

| 控制面 | 构造 | 发送 |
| --- | --- | --- |
| UDP | `ClientSink::Udp(listen socket)` | `send_to(client)` |
| TCP / `turns:`(TLS) / DTLS | `ClientSink::Queue(mpsc::Sender<Vec<u8>>)` | 有界 `try_send`（溢出丢 indication，不阻塞 accept 循环）|

实现要点：
- 在 `allocate()` 里把已构造好的 `sink` **clone 进 `Allocation`**（不改变现有 relay reader 的用法）；
- accept 任务通过 `Arc<Allocation>`/克隆的 sink 发送，不依赖请求处理路径；
- `try_send` 失败只计数/日志（indication 可丢，客户端可重试；TCP 控制连接写队列满说明客户端不读，属自身问题）。

## 4. 生命周期与并发

- accept 任务在 **TCP allocation 创建成功后** spawn，句柄存 `Allocation.accept_task`；
  `Drop`/`remove` 时 abort（与 `relay_task` 同构）；
- 连接表插入在 accept 成功后、发 indication **之前**（客户端可能立刻 bind）；
- pending 30s 由既有 `sweep` 回收（`expires_at`）；
- `LIFETIME=0`/过期 → `close_connections_for`（已有）+ abort accept 任务（新增）；
- 端口归还仍由 `release_port`（既有）。

## 5. 错误与边界

| 场景 | 行为 |
| --- | --- |
| accept 返回错误 | 记 warn，continue（不退出任务；fatal 错误连续发生可计数）|
| 无 permission | 关闭，不 notification（coturn 实测）|
| 配额满（16）| 关闭 + `rejected_total{reason="tcp_quota"}`（RFC 未规定错误响应；入站无请求可回）|
| 预缓冲 > 64 KiB | 关闭 + `tcp_buffer` |
| 30s 未 bind | 关闭（sweep） |
| 客户端用错凭据 bind | 既有逻辑 `400`（不改）|
| 控制连接已死 | sink 发送失败 → 丢弃该入站连接（无人可 bind） |

## 6. 验收路径

- `turnutils_uclient -P`（蕴含 -T）：`Allocate(TCP)` → `CreatePermission` → 控制连接收
  `ConnectionAttempt` → 新连接 `ConnectionBind` → 裸字节。**判据**：双向字节数 > 0 + exit=0，
  不照搬 `lost packets 0`（coturn 实测 50% 丢包）。
- `turnutils_uclient -T`（隐含 `-y`）：两端都能通过（此前 0 recv）。
- 无 permission 负例：peer 直连 relay → 连接被拒（RST/立刻关闭），控制连接 5s 内无 indication。
- 控制面 UDP 与 TCP（TLS 复用 TCP sink；DTLS 复用 Queue）至少各验一次 indication。
- 默认路径冻结不变（`frozen` 3×17）。

## 7. 兼容与回滚

- 开关沿用 `--turn-tcp-relay`（默认关）；关闭时行为与现在完全一致（入站 accept 任务不 spawn）；
- 单 commit 可回滚（新增 accept 任务 + sink 字段 + indication 编码 + 测试）。

## 8. 风险

| R | 缓解 |
| --- | --- |
| accept 任务泄漏（allocation 移除未 abort）| `Drop` + `remove` 双路径 abort；lab 断言端口可重绑 |
| indication 洪泛（大量入站）| 受 permission + 配额约束；sink 有界 |
| UDP 控制面 sink 需要 listen socket | `allocate()` 已有的 `ClientSink::Udp` 直接复用 |
| `uclient -P` 判据不稳 | 用双向字节 + exit 组合判定（PRD 已写） |
