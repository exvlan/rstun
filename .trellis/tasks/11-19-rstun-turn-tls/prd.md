# TURN T2：TLS/DTLS + REST 凭据 + 配额完善与浏览器验收

> `11-19-rstun-turn` 的子任务；**依赖 T1（rstun-turn-udp）**。
> 目标：让 TURN 能被真实浏览器（`turns:`）使用，并补齐对外服务所需的凭据与配额能力。

## Goal

在 T1 的 UDP 中继之上，提供 `turns:`（TLS）与 DTLS 监听、TURN REST API 临时凭据、带宽配额，
并用 `turnutils_uclient` 与真实浏览器（trickle ICE）完成端到端验收。

## 需求

### R1 TLS / DTLS

- `--turn-tls-listen <addr>`：TLS 监听（证书/私钥从 CLI 或文件读取）；仅 TLS 特性启用时编译。
- `--turn-dtls-listen <addr>`（可选）：DTLS 监听。
- 证书热加载不做；重启生效。
- TLS 握手失败 / 证书不匹配必须记录可诊断日志（不含私钥内容）。

### R2 TURN REST API 凭据

- `--auth-secret` + `--rest-api`：临时凭据 `username = <expiry>:<user>`，
  `password = base64(hmac-sha1(secret, username))`（与 coturn 的 `use-auth-secret` 兼容）。
- 校验：过期拒绝（401/438），HMAC 不匹配拒绝。
- 与长期凭据可并存，优先级明确（REST 凭据优先）。

### R3 配额完善

- 每 allocation 的**带宽配额**（入/出，令牌桶；超限丢弃并计数）。
- 端口范围与分配上限的**运行时调优**参数（不改代码即可调整）。
- 每 peer 的中继连接数上限。

### R4 验收工具链

- `script/lab/rstun-turn.sh`：一键起 TURN（含 TLS 证书自签）+ `turnutils_uclient` 中继测试 + 清理。
- 浏览器验收步骤文档化（本地 WebRTC demo + `turns:` + trickle ICE；至少验证「一方在对称 NAT 后」）。

### R5 文档

- README 增补：`turns:` 用法、REST 凭据生成示例（shell/python 一行）、防火墙端口说明、常见失败原因。

## 非目标

- ACME/自动证书签发、OCSP stapling
- TURN-TCP 分配（RFC 6062）

## 验收

- [ ] `turnutils_uclient -t`（TCP/TLS）与 `-u/-w` 组合可完成中继
- [ ] 自签证书下浏览器（Chrome）通过 `turns:` 建立媒体；一方在对称 NAT 后仍成功
- [ ] REST 凭据：过期凭据被拒；错误 HMAC 被拒；正确凭据可用
- [ ] 带宽配额生效（超限丢包且计数增长）
- [ ] `--turn-tls-listen` 未给证书时拒绝启动（明确错误）
- [ ] 关闭 TLS 特性编译时：不引入 rustls 依赖（`cargo tree` 验证）

## 风险

| # | 风险 | 缓解 |
| --- | --- | --- |
| R1 | TLS 依赖膨胀 | feature flag，默认不编；发布矩阵固定两种构建（STUN-only / full）|
| R2 | 浏览器验收环境难复现 | 提供 docker-compose（coturn 对照 + 自签证书 + demo 页）|
| R3 | REST 凭据时钟偏移 | 允许 ±5 分钟；文档写明 NTP 前提 |
