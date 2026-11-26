# 设计：RFC 6062 被动模式（`ConnectionAttempt`）

> 依据：`archive/2026-11/11-21-rstun-turn-rfc6062/research/rfc6062.md` §5（coturn 实测：有 permission →
> `ConnectionAttempt`(cid+peer) → 新连接 `ConnectionBind`；无 permission → accept 后立即关闭、无 indication）。
> 出站路径已交付并在 `.104` 发布，本任务只加入站。

## 1. 复用与新增

| 组件 | 现状 | 本任务 |
| --- | --- | --- |
| `Allocation.relay` | `Relay::Tcp(TcpRelay { listener })` | 增加一个 **accept 任务**（随 allocation 生命周期）|
| 反向通道 | **未保存**（`sink` 只在 `allocate()` 局部构造给 relay reader）| 把 `ClientSink`/`state`/`key`/`username` 的 **clone 直接交给 accept 任务**（**不**把 `Arc<Allocation>` 交给任务，避免循环引用导致 `Drop` 不触发）|
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

`ClientSink` 逻辑上仍只有**两种形态**，但**线上只有 `Queue` 可达**：TCP allocation 要求
stream 控制连接（RFC 6062 §5.1 步骤 2，UDP/DTLS 上 `Allocate(TCP)` 直接 `400`），
所以 `turns:`(TLS) 与明文 TCP 走同一条 `Queue(mpsc::Sender<Vec<u8>>)` 路径
（5 元组都记 `ClientTransport::Tcp`），`Udp` 分支在本功能里**不可达**，仅由 helper 级单测
（编码 + `send_to`）覆盖。

| 控制面 | 构造 | 发送 | 本功能是否可达 |
| --- | --- | --- | --- |
| TCP / `turns:`(TLS) | `ClientSink::Queue(mpsc::Sender<Vec<u8>>)`（`allocate()` 不区分两者）| 有界 `try_send`（溢出丢 indication，不阻塞 accept 循环）| **是**（唯一线上路径）|
| UDP | `ClientSink::Udp(listen socket)` | `send_to(client)` | **否**（UDP 上 `Allocate(TCP)` → `400`）；helper 级单测 |

实现要点：
- **不**把 `sink` 存进 `Allocation`（§1）：`allocate()` 里把已构造好的 `ClientSink`、`state`、
  `key`、`username` 的 **clone** 直接交给 accept 任务；
- 任务**不得**持有 `Arc<Allocation>`（会与表里的 `Arc` 构成循环，`Drop` 永不触发 ⇒ 端口永不释放），
  因此发送不依赖请求处理路径，也不依赖 allocation 表；
- `try_send` 失败（控制连接已死/队列满）→ 关闭该入站连接并计 `tcp_send`（indication 可丢，
  但没人能 bind 的连接不该继续占 30 s 窗口）。

## 4. 生命周期与并发

- accept 任务在 **TCP allocation 创建成功后** spawn，句柄存 `Allocation.accept_task`；
  `Drop`/`remove` 时 abort（与 `relay_task` 同构）。**abort 是异步的**：`release_port` 先回池、
  listener 在任务被调度取消时才关闭，因此断言按「**最终** 无残留 / 再连被拒」而不是同步关闭；
- 连接表插入在 accept 成功后、发 indication **之前**（客户端可能立刻 bind）；
- pending 30s 由既有 `sweep` 回收（`expires_at`）；
- `LIFETIME=0`/过期 → `close_connections_for`（已有）+ abort accept 任务（新增）；
- 端口归还仍由 `release_port`（既有）。
- 入站数据连接在 relay listener 上 accept，**不经过** `serve_tcp`，因此**不占** `--max-inflight`；
  只受「每 allocation 16 条 + 30s 回收」约束（文档已按事实写明）。

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
- 控制面：**TCP 端到端**实测 indication；TLS 复用同一 `ClientTransport::Tcp` + 同一 `Queue` sink
  （`allocate()` 不区分，`tls` 项的 `Data indication` 已端到端覆盖该队列）；UDP/DTLS 在协议上不可达
  （§5.1 步骤 2 → `400`），`ClientSink::Udp` 分支仅 helper 级单测。
- 默认路径冻结不变（`frozen` 3×17）。

## 7. 兼容与回滚

- 开关沿用 `--turn-tcp-relay`（默认关）；关闭时行为与现在完全一致（入站 accept 任务不 spawn）；
- 单 commit 可回滚（新增 accept 任务 + sink 字段 + indication 编码 + 测试）。

## 8. 风险

| R | 缓解 |
| --- | --- |
| accept 任务泄漏（allocation 移除未 abort）| `Drop` + `remove` 双路径 abort；断言「最终 `ss -ltn` 无残留」+ 单测「`LIFETIME=0` 后**再连被拒**」（`SO_REUSEPORT` 让端口重绑本来就成功，不能当判据）|
| indication 洪泛（大量入站）| 受 permission + 配额约束；sink 有界 |
| UDP 控制面 sink 需要 listen socket | 协议上不可达（§5.1 步骤 2 → `400`）；`ClientSink::Udp` 分支仅由 helper 级单测覆盖 |
| `uclient -P` 判据不稳 | 用双向字节 + exit 组合判定（PRD 已写） |
