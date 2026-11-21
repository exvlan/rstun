# TURN RFC 6062 被动模式（ConnectionAttempt）

## 背景

`11-21-rstun-turn-rfc6062` 已实现**出站**路径（`Allocate(TCP)` + `Connect` + `ConnectionBind`），
验收用仓库探针（标准客户端流程）。被动模式被明确排除，原因见该任务 `design.md` §8.1：

- `turnutils_uclient -T` **隐含 `-y`（client-to-client）**，被连的一侧必须由服务器发
  `ConnectionAttempt` 才能 `ConnectionBind`；
- 实测：本仓开关开时 `uclient -T` → `tot_recv_msgs=0`、挂到超时（exit=124）；
- 因此「`-T` 全通」只能靠被动模式达成。

用户已确认：**另立本子任务**，排在证书热载之后（顺序 RFC 6062 出站 → 证书热载 → 被动模式/多实例）。

## Goal

实现 RFC 6062 §5.3 的入站路径：peer 主动连到 TCP 中继地址时，服务器 accept、按 permission 决定
是否通知客户端，并通过控制连接发 `ConnectionAttempt`（带 `CONNECTION-ID` + `XOR-PEER-ADDRESS`），
客户端再在新连接上 `ConnectionBind` 绑定。

## 范围（RFC 6062 §5.3 + §4.4，细节待 design）

1. **accept 循环**：每个 TCP allocation 一个 listener 任务；accept 失败 → 静默（不通知客户端）。
2. **permission 检查**：该 peer 无 permission → accept 后立即关闭（不发 indication）。
3. **`ConnectionAttempt` indication**：向**控制连接**推送（控制面可能是 UDP/TCP/TLS/DTLS 四种 sink ——
   这是本任务的主要新增能力：`allocation → 控制连接` 的反向通道）。
4. **`ConnectionAttempt` 属性**：`CONNECTION-ID` + `XOR-PEER-ADDRESS`（indication 无 MESSAGE-INTEGRITY；
   coturn 实测还带 `SOFTWARE`/`FINGERPRINT`，design 决定是否对齐）。
5. **`CONNECTION-ID` 表复用**：与出站共用同一张表与 bind 状态机；pending 30 s 未 bind 关闭。
6. **资源**：入站连接数量上限（与出站共用每 allocation 16 条）；预绑定缓冲 64 KiB；指标补齐。

## 非目标

- 不改出站路径的行为与错误码；
- 不做 `ADDITIONAL-ADDRESS-FAMILY`；
- 不发版（版本由主会话决定）。

## 验收

- [ ] `turnutils_uclient -T`（隐含 `-y`）在 rstun 上 `exit=0` 且 `lost packets 0`
- [ ] `turnutils_uclient -P`：能完成 `ConnectionAttempt` → `ConnectionBind` → 数据；
      **判据不能只用 `lost packets 0`**（coturn 实测 50% 丢包），需记录双向字节数与退出码
- [ ] 无 permission 的入站连接 → 立即关闭且**无** indication（coturn 实测行为）
- [ ] 控制面四种 transport（UDP/TCP/TLS/DTLS）都能收到 `ConnectionAttempt`（至少 UDP + TCP 实测）
- [ ] 30 s 未 bind 关闭、`LIFETIME=0` 级联关闭、指标同步
- [ ] 默认路径冻结不变；全量门禁绿

## 风险

| R | 缓解 |
| --- | --- |
| 反向通道（allocation → 控制连接）是新路径 | 先在 UDP + TCP 控制面实现并测试；TLS 复用 TCP sink；DTLS 沿用 session sender |
| `uclient -P` 判据不稳（50% 丢包） | 用字节数 + 双向连通 + 退出码组合判定，不照搬 `lost packets 0` |
| 与出站共享 `CONNECTION-ID` 表 | 复用同一状态机，避免两套 id 空间 |
