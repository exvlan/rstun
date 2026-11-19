# TURN 中继（RFC 8656 + TLS/DTLS）

## Goal

实现 TURN 服务器，使 rstun 成为 **STUN + TURN** 的完整实现（coturn 的能力面，不含多租户/计费）。
这是本父任务中**工作量最大、风险最高**的子任务：中继意味着开环、配额、状态与鉴权四件事同时到位。

## 规范基线

- **RFC 8656**（TURN，obsoletes 5766）：`Allocate` / `Refresh` / `CreatePermission` / `ChannelBind`，
  `Send`/`Data` indication、`ChannelData` 封装、`XOR-RELAYED-ADDRESS` / `XOR-PEER-ADDRESS` /
  `LIFETIME` / `REQUESTED-TRANSPORT` / `DONT-FRAGMENT` / `RESERVATION-TOKEN`
- **RFC 8489**（STUN bis）：复用本仓已有的 STUN 编解码与鉴权
- **RFC 6156**：TURN IPv6（relay 地址族选择）
- **RFC 6062**（TURN-TCP 分配，`REQUESTED-TRANSPORT=TCP`）：**二期**，先不做
- **TLS/DTLS**：`turns:` 与 DTLS 监听（RFC 8656 §3.1）

## 需求

### R1 分配生命周期
- 5 元组 → allocation（client addr/proto × server addr × relay addr）
- `Allocate`：分配 relay socket（UDP），`LIFETIME` 默认 600s、上限可配；重复 `Allocate` 幂等（返回同一 relay）
- `Refresh`：续期；`LIFETIME=0` 立即释放
- `CreatePermission`：peer IP 白名单（TTL 5 分钟）
- `ChannelBind`：通道号 0x4000–0x7FFF 绑定 peer 地址（TTL 10 分钟）；`ChannelData` 直通
- 超时回收：分配、权限、通道三级定时器；回收必须释放 socket 与端口

### R2 鉴权（强制）
- **开放中继是绝对禁止的**：未配置凭据时 TURN 端口**拒绝启动**（与 STUN 允许多开相反）
- 长期凭据（复用 `rstun-auth` 的 realm/nonce/MI 实现）
- 可选 **TURN REST API**（临时凭据：`username = <expiry>:<user>`，`password = base64(hmac-sha1(secret, username))`）

### R3 配额与防滥用
- 每用户/每源 IP 的最大分配数、最大带宽（粗粒度令牌桶）
- relay 端口范围可配（`--relay-ports 49152-65535`），耗尽时 `486 Allocation Quota Reached` / `508 Insufficient Capacity`
- 每个 allocation 的 peer 白名单上限（默认 10）
- 中继流量不得回环到本服务自身监听

### R4 传输与部署
- UDP 监听（主）、TCP 监听（把 TURN 消息走 TCP 连接）、TLS（`turns:`）、DTLS（可选）
- 证书/私钥从 CLI/env 读取；不在本任务做 ACME
- `--realm`、`--auth-secret`、`--relay-ports`、`--max-allocations` 等配置

### R5 可观测
- 指标：活动分配数、中继字节数、创建/过期计数、配额拒绝数、每 allocation 的 peer 数

## 非目标（本子任务）

- 多租户/计费/数据库用户后端
- TURN-TCP 分配（RFC 6062）→ 二期
- Anycast/跨机 relay 调度

## 验收

- [ ] `turnutils_uclient -u <user> -w <pass> -p <port>` 能建立 allocation 并中继（UDP→UDP）
- [ ] 浏览器 WebRTC（trickle ICE）通过 `turns:` 建立媒体（至少一方位于对称 NAT 后）
- [ ] `Refresh` 续期与 `LIFETIME=0` 释放；权限/通道 TTL 到期后数据被丢弃
- [ ] 未配置凭据时拒绝启动（exit != 0 且日志明确）
- [ ] 配额：超限返回 `486`/`508`，不泄漏端口；端口耗尽后恢复
- [ ] 指标可观测（活动分配/字节数）
- [ ] 与 coturn 对跑：同一客户端分别连两者，行为一致（除实现细节）

## 风险

| # | 风险 | 缓解 |
| --- | --- | --- |
| R1 | 开放中继被滥用（反射/流量跳板） | 强制鉴权 + 配额 + 默认关闭 TURN（`--turn` 显式开启）|
| R2 | relay socket 泄漏 | 所有分配走 RAII 封装；回收测试断言 `ss -lun` 无残留 |
| R3 | TLS 引入大依赖（rustls/tokio-rustls） | 仅 TLS 特性启用时编译（feature flag），默认不编 |
| R4 | 与 STUN 路径相互污染 | TURN 方法在独立模块；STUN 冻结测试必须继续通过 |
| R5 | 复杂度导致进度失控 | 分两批交付：UDP 中继闭环 → TLS/DTLS + 配额完善 |

## 交付批次

1. **T1**：UDP `Allocate`/`Refresh`/`CreatePermission`/`ChannelBind` + `Send/Data`/`ChannelData` + 长期凭据 + 指标
2. **T2**：TLS/DTLS 监听、TURN REST API、配额与端口范围、`turnutils_uclient` + 浏览器验收
