# TURN RFC 6062：TCP allocation

## 背景

当前 `Allocate` 带 `REQUESTED-TRANSPORT=6`（TCP）一律回 **442 Unsupported Transport Protocol**
（`docs/book/src/turn.md`、`src/turn.rs` 头注释都明写「RFC 6062 不在范围」）。

coturn 与 `turnutils_uclient -T` 支持该模式；部分企业网络（阻断 UDP）依赖它。用户已确认二期
顺序为 **RFC 6062 → 证书热载 → 多实例**。

## Goal

实现 RFC 6062 的 TCP allocation：客户端与 peer 之间由服务器建立并维护 **TCP 中继**，
控制面仍走现有 TURN 连接（UDP / TCP / TLS / DTLS 均可），数据面是独立 TCP 连接。

## 范围（RFC 6062 关键语义，待 design 细化）

1. **`Allocate` + `REQUESTED-TRANSPORT=6`**：成功返回 `200` + `XOR-RELAYED-ADDRESS`
   （TCP 中继地址）+ `XOR-MAPPED-ADDRESS` + `LIFETIME`；**不含 `CONNECTION-ID`**
   （调研已证：RFC 6062 §5.1 无此要求，coturn 亦不带；`CONNECTION-ID` 由 `Connect` 响应产生）。
2. **`Connect`**（新方法）：客户端给 `XOR-PEER-ADDRESS`，服务器向 peer 建 TCP；
   成功回 `200`；失败按 RFC 给错误码（如 `447 Connection Timeout or Failure`、
   `403 Forbidden`、`446` 等——以 RFC 原文为准）。
3. **`ConnectionBind`**（新方法）：客户端在**新连接**上用 `CONNECTION-ID` 绑定，
   之后该连接上的字节裸转发到 peer（不再是 STUN 帧）。
4. **`ConnectionAttempt` indication**（**被动模式：本期不做**；调研结论见
   `research/rfc6062.md` §5.4 —— 需要「allocation → 控制连接」的反向通道，且 `uclient -P`
   实测 50% 丢包、验收判据不稳。留作二期内的后续子项）。
5. **生命周期**：`LIFETIME`/`Refresh` 对 TCP allocation 同样有效；连接半开、对端关闭、
   超时、配额超限都要有确定行为与计数。
6. **权限模型**：与 UDP 的 `CreatePermission` 关系（RFC 6062 对 TCP 的授权要求）；
   design 需给出与现有 permission 表/上限的复用方式。
7. **观测**：新增/复用指标（连接数、失败原因），不破坏既有标签面。

## 非目标

- 不做 `ADDITIONAL-ADDRESS-FAMILY` 双分配；
- 不改 UDP 中继与 STUN 行为（默认路径字节不变）；
- 不做跨实例状态共享（属后续「多实例」项）；
- 不发版（版本与 CHANGELOG 由主会话决定）。

## 约束（硬）

- 不新增运行时依赖（如必须新增，需单独立项说明体积/审计影响）；
- 现有配额（`--max-allocations-per-user/-ip`、`--relay-ports`、`--max-inflight`）对 TCP 中继同样生效；
- 默认关闭路径字节冻结不变（3 配置 × 17 请求）；
- 平台：Linux/macOS/Windows 都能编译（无 unix-only 依赖）；
- 现有 `442` 行为在**未启用**特征时保持不变：开关形态为**新增 CLI 开关**
  `--turn-tcp-relay`（默认关；只有显式打开才走 RFC 6062 路径）。

## 验收

- [ ] 标准客户端流程（仓库探针 `rstun-turn-probe.py` 的 tcp-relay 模式）对 rstun 与 coturn **逐行一致**：
      `Allocate(TCP)` → `Connect`（源地址 = relay 端口）→ `ConnectionBind` → 裸字节双向 → `LIFETIME=0` 关数据连接。
      **注**：`turnutils_uclient -T` **隐含 `-y`（client-to-client）**，被连侧需要服务器发 `ConnectionAttempt`
      （被动模式，本期不做）→ `-T` 留到被动模式子任务验收；本期不把它当验收条件。
- [ ] 与 coturn 同一套命令对跑，差异逐项判定（我方/对手/RFC 理解）
- [ ] `ConnectionBind` 的 5 元组与 `CONNECTION-ID` 校验收紧（错 ID/重放/并发绑定）
- [ ] 半开、对端 RST、超时、`LIFETIME=0`、配额超限各有确定行为与单测
- [ ] 默认路径字节冻结不变；`cargo test`/clippy/fmt/interop/abuse/turn/audit/deny 全绿
- [ ] 文档（行为表、部署注意）、spec、CHANGELOG(Unreleased) 同步

## 风险

| R | 缓解 |
| --- | --- |
| RFC 6062 复杂度高（连接生命周期/半开/超时） | 先「客户端 → peer 单向 + ConnectionBind」，再补被动模式与边界 |
| 新增 socket 类型影响资源上限 | 纳入现有配额与 1s 回收扫描 |
| 与现有 5 元组表耦合（控制连接 vs 数据连接） | 数据连接不占 allocation 5 元组；用 `CONNECTION-ID` 映射 |
| 平台差异（TCP 半关闭语义） | 统一按「读到 EOF 即单向关闭，双向关完即回收」实现并测试 |
