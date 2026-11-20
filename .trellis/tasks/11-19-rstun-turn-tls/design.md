# 设计：TURN T2（TLS + REST 凭据 + 配额完善）

## 1. 边界

- 建立在 T1（`rstun-turn-udp`）的 allocation/permission/channel 之上；**不重做 T1 的状态机**。
- 只做四件事：`turns:`（TLS over TCP）、TURN REST 临时凭据、每 allocation 带宽配额、验收工具链与文档。
- **DTLS 纳入**（用户决策）：`rustls` 不支持 DTLS，使用 `webrtc-dtls` 0.12（纯 Rust）。
  与 TLS 并列独立监听；两者共用证书解析逻辑。

## 2. 依赖取舍

| crate | 用途 | 说明 |
| --- | --- | --- |
| `tokio-rustls` | TLS 监听与握手 | 纯 Rust；`rustls` 由它带入 |
| `rustls-pemfile` | 读证书/私钥 PEM | 小 |
| `webrtc-dtls` | DTLS 1.2 监听与握手 | 纯 Rust（含 crypto 后端传递依赖）；与 `rustls` 并存，证书可复用 |

运行期依赖 9 → 11（与 auth 一样：**始终包含**，不做 feature gate——发布矩阵保持单一构建）。
二进制体积预计 +~1.2 MB；在 README 的「体积」处更新。

## 3. TLS 与 DTLS 监听

### 3.1 DTLS（`--turn-dtls-listen`）

- 每个 DTLS 连接 = 一个「客户端传输」，5 元组的 transport 记为 `Dtls`（与 `Udp`/`Tcp` 区分）。
- 一个 DTLS datagram 内是**恰好一个** STUN/TURN 消息或一个 `ChannelData`（与 UDP 同构，无长度前缀）。
- 握手失败：计数 + debug 日志（不打印证书内容）；超时 5s。
- 与 TLS 一样：证书缺失/不可读 → 拒绝启动；不配置则不监听。

### 3.2 TLS 监听

- `--turn-tls-listen <addr>`（可重复）：在 T1 的 TCP TURN 之上套 TLS。
- 证书：`--tls-cert <pem>` + `--tls-key <pem>`；启动时解析失败 → 拒绝启动（明确错误，不降级为明文）。
- 握手失败：计数 + debug 日志（**不打印证书内容**）；连接关闭。
- 明文 TCP 与 TLS 端口**不共用**（RFC 8656 允许 `turns:` 独立端口；共用需 ALPN/嗅探，本任务不做）。
- TLS 连接上的 STUN/TURN 分帧沿用 T1 的 TCP 逻辑（长度前缀 + `ChannelData` 4 字节头）。

## 4. TURN REST 临时凭据（与 coturn `use-auth-secret` 兼容）

```
username = "<expiry-unix>:<任意标签>"
password = base64( HMAC-SHA1( secret, username ) )
```

- 配置：`--rest-secret <s>`（与 `--auth-secret` 独立；同时配置时 **REST 优先**）。
- 校验：冒号前解析为过期时间；过期 → 401（不是 438，nonce 仍走 T1 的 438 逻辑）。
- 与长期凭据共存：REST 用户名含 `:` 且能解出时间戳 → 走 REST 校验；否则走普通长期凭据。
- 不引入 base64 依赖：`base64url` 实现已在 `auth` 模块（复用）。

## 5. 带宽配额

- 每 allocation 两个令牌桶（入/出），默认 `--turn-bandwidth 1M`（字节/秒，0 = 不限）。
- 超限：丢弃该方向的包并计数（不关闭 allocation）；与 T1 的端口/分配配额独立。
- 指标：`rstun_turn_bytes_dropped_total{direction}`（带宽丢包）与既有的
  `rstun_turn_bytes_total{direction}`（已中继字节）。

### 5b. PRD R3「每 peer 的中继连接数上限」→ `--permission-limit`

PRD 列了三条配额，其中「每 peer 的中继连接数」没有单独的计数器：RFC 8656 §9 的 permission
就是「这个 allocation 允许向这个 peer IP 发数据」的凭据，`Send` / `ChannelData` 只在该 peer
有 permission 时转发。因此**可同时中继的 peer 数 == 有效 permission 数**，`--permission-limit`
（默认 10）就是用户要的那个上限；`ChannelBind` 的隐式 permission 共用同一配额，超限 `508`
且整条请求零生效。再叠一个「每 peer 连接数」只会在同一维度上重复计数，故不做。

## 6. 端口与地址

- 复用 T1 的 `--relay-ports`；TLS 监听不占用 relay 端口范围。
- 客户端经 TLS 连接时，allocation 的 5 元组仍按「客户端地址 + TCP + 服务端地址」计（与 T1 一致）。

## 7. 验收工具链

- `script/lab/rstun-turn.sh` 扩展：`--tls` 生成自签证书（用 `openssl` 或 Rust 侧 `rcgen` 仅测试依赖），
  起 TLS 监听，跑 `turnutils_uclient` 的 TLS 模式。
- 浏览器验收：文档给出最小步骤（本地 demo + `turns:` + trickle ICE），并注明「至少一方在对称 NAT 后」。
- **coturn 对照**：本地 `turnserver` 配置 `use-auth-secret` + TLS，与本服务同参数对跑，比较 allocation 行为。

## 8. 兼容与回滚

- 未配置 `--turn-tls-listen` / `--rest-secret` / `--turn-bandwidth` 时，行为与 T1 完全一致。
- TLS 相关依赖始终编译，但**不配置即不监听**；出问题可只回滚 T2 的 commit。

## 9. 风险

| R | 缓解 |
| --- | --- |
| 依赖体积增加（rustls）| README 更新体积；发布前记录 `ls -l` 对比 |
| TLS/DTLS 握手被用于 DoS | 连接级限速（复用 abuse-guard 的 Semaphore/令牌桶）；握手超时 5s；DTLS 握手失败计入同一计数 |
| webrtc-dtls 依赖面扩大 | 记录依赖树与二进制体积变化；README 更新；发布前跑 `cargo audit` |
| REST secret 泄露 | 与 auth-secret 分离；日志不打印；文档建议独立轮换 |
| 证书路径/权限错误 | 启动即失败并给出明确错误（不静默降级到明文）|
