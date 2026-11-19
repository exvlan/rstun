# TURN T1：UDP 中继闭环

> `11-19-rstun-turn` 的子任务；**T2 依赖本任务**。
> 目标：3–5 天内做出「可演示、不可被滥用」的 UDP 中继。

## Goal

实现 RFC 8656 的 UDP 中继最小闭环：客户端申请 allocation，获得 relay 地址，向白名单 peer 收发数据。
**强制长期凭据**，未配置凭据时拒绝启动。

## 需求

### R1 方法与生命周期

| 方法 | 行为 |
| --- | --- |
| `Allocate` | 按 5 元组查表；**同一 transaction id 的重传**幂等返回同一 relay，**新 transaction id → 437**，**同一 5 元组换用户 → 441**；`REQUESTED-TRANSPORT` 只接受 UDP；`LIFETIME` 默认 600s、上限可配 |
| `Refresh` | 续期；`LIFETIME=0` 立即释放（释放 socket + 端口）|
| `CreatePermission` | peer IP 白名单（TTL 5 分钟）；同 IP 重复请求幂等 |
| `ChannelBind` | 通道号 0x4000–0x7FFF ↔ peer 地址（TTL 10 分钟）；同通道重复绑定幂等 |
| `Send` / `Data` indication | 仅在 permission 覆盖的 peer 上转发 |
| `ChannelData` | 通道命中即转发，不解析 STUN |

### R2 鉴权（强制）

- 长期凭据（复用 `rstun-auth` 的 realm/nonce/MI 实现）；无凭据配置 → **启动失败**。
- `Allocate` 无 MI → `401` + `REALM` + `NONCE`；nonce 过期 → `438` + 新 `NONCE`；校验失败 → `401`。
- 401/438 也必须计入限速桶（防爆破）。

### R3 端口与配额（安全底线）

- `--relay-ports <lo>-<hi>`（默认 49152–65535）；耗尽 → `508 Insufficient Capacity`。
- `--max-allocations-per-user` / `--max-allocations-per-ip`（默认给保守值）；超限 → `486 Allocation Quota Reached`。
- 每 allocation 的 permission 上限（默认 10）；超限 → `508 Insufficient Capacity`（一条请求里的 peer 全量校验，不做部分生效）。
- 中继目标不得是本服务自身监听地址（防回环）。

### R4 观测与回收

- 指标：活动 allocation 数、创建/过期计数、配额拒绝数、中继字节数。
- 三级定时器（allocation/permission/channel）到期回收；**测试断言 `ss -lun` 无残留 relay socket**。

### R5 配置

`--turn`（显式开启）、`--realm`、`--auth-secret`、`--relay-ports`、`--max-allocations-*`、
`--permission-limit`、`--allocation-lifetime`。默认全部关闭/保守值。

## 非目标（T2 或更晚）

- TLS/DTLS 监听、REST 临时凭据、带宽配额
- TURN-TCP 分配（RFC 6062）

## 验收

- [ ] `turnutils_uclient -u <user> -w <pass> -p <turn-port>` 建立 allocation 并完成 UDP 中继
- [ ] 无 MI → 401；错口令 → 401；nonce 过期 → 438
- [ ] `Refresh` 续期与 `LIFETIME=0` 释放；permission/channel 到期后数据被丢弃
- [ ] 端口耗尽 → 508；分配数超限 → 486
- [ ] 到期后 `ss -lun` 无残留（回收彻底）
- [ ] 未配置凭据启动 → 非 0 退出且日志明确
- [ ] 关闭 `--turn` 时：与 `26.410.100` 字节级一致 + 互操作矩阵全绿

## 风险

| # | 风险 | 缓解 |
| --- | --- | --- |
| R1 | 开放中继 | 强制鉴权 + 默认关闭 + 配额 |
| R2 | relay socket 泄漏 | RAII 封装 + 回收断言 |
| R3 | 与 STUN 路径互相污染 | TURN 独立模块；冻结测试必须继续通过 |
| R4 | 端口范围与系统临时端口冲突 | 默认段避开 `net.ipv4.ip_local_port_range`，文档提示可配 |
