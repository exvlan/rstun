# TURN（父）：RFC 8656 中继能力

> 这是 `11-19-rstun-complete` 的子任务，同时是 T1/T2 的父任务。
> 用户定稿：**拆成两个可独立验收的子任务**，T1 先行、T2 依赖 T1。

## 为什么要拆

TURN 的工作量与风险都远大于 STUN 侧任何一项，且「能否先跑起来」与「能否安全对外」是两个不同问题：

- **T1** 解决「能不能中继」——最小闭环 + **强制鉴权**（杜绝开放中继）+ 端口范围与基本配额（防止端口耗尽）。
- **T2** 解决「能不能对外提供」——TLS/DTLS、REST 临时凭据、带宽配额、浏览器真机验收。

拆开的好处：T1 可以在 3–5 天内形成可演示的中继，T2 的 TLS/配额可以按需推迟，不必等一个大 PR 全部就绪。

## 子任务地图

| 子任务 | 范围 | 依赖 | 优先级 |
| --- | --- | --- | --- |
| `rstun-turn-udp`（T1） | Allocate/Refresh/CreatePermission/ChannelBind、Send/Data/ChannelData、强制长期凭据、relay 端口范围、每用户/IP 分配上限、基础指标 | `rstun-auth`、`rstun-abuse-guard`、`rstun-ops` | P1 |
| `rstun-turn-tls`（T2） | `turns:`（TLS）与 DTLS 监听、TURN REST API 临时凭据、带宽配额、`turnutils_uclient` + 浏览器 trickle ICE 验收 | T1 | P2 |

## 共享契约（两个子任务都必须遵守）

1. **禁止开放中继**：未配置凭据时 TURN 端口**拒绝启动**（与 STUN 的「可匿名」不同）。
2. **默认关闭**：`--turn`（或等价开关）显式开启；关闭时零监听、零行为变化。
3. **STUN 路径不回归**：冻结测试与互操作矩阵必须继续通过。
4. **回收必须彻底**：allocation/permission/channel 到期后，relay socket 与端口必须释放（测试断言无残留）。
5. **错误码语义**：`486 Allocation Quota Reached`、`508 Insufficient Capacity`、`401/438`（鉴权）不得混用。

## 非目标（整个 TURN 父任务）

- 多租户/计费/数据库用户后端
- TURN-TCP 分配（RFC 6062）与跨机 relay 调度
- ACME 证书签发（证书由外部提供）

## 验收（父任务级）

- [ ] T1 + T2 验收全部通过
- [ ] 关闭 TURN 时与 `26.410.100` 行为一致（字节级）
- [ ] 与 coturn 对跑：同一客户端（`turnutils_uclient`）分别连两者，中继行为一致
