# 设计：TURN T1（UDP 中继闭环）

## 1. 边界

- 只做 **UDP 中继**（`REQUESTED-TRANSPORT=17`）；`REQUESTED-TRANSPORT=6`（TCP 分配，RFC 6062）→ `442`。
- 默认可关闭：`--turn` 未开启时**零监听、零状态、零行为变化**（STUN 冻结测试必须继续通过）。
- **强制长期凭据**：缺少 `--realm`/`--auth-secret`（或等价配置）时，`--turn` 启动失败（exit != 0）。
- TURN 与 STUN 共用同一个 STUN 编解码与鉴权实现；TURN 的 method 常量与错误码在独立模块。

## 2. 数据结构

```
Key = (client: SocketAddr, transport: Udp|Tcp, server: SocketAddr)   // RFC 8656 §2「5 元组」
Allocation {
    key: Key,
    relay: Arc<UdpSocket>,          // 绑在 relay port range 内
    relay_addr: SocketAddr,
    username: String,               // 用于配额与日志
    expires_at: Instant,            // 默认 600s，可配上限
    permissions: HashMap<IpAddr, Instant>,   // TTL 5m
    channels: HashMap<u16, (SocketAddr, Instant)>, // TTL 10m，0x4000–0x7FFF
}
Tables {
    allocations: RwLock<HashMap<Key, Arc<Allocation>>>,
    used_ports: Mutex<HashSet<u16>>,     // relay 端口池
}
```

## 3. 关键流程

| 消息 | 处理 | 失败分支 |
| --- | --- | --- |
| `Allocate` | 鉴权（必须 MI）→ 配额检查 → 端口池取端口 → 绑 relay socket → 起转发任务 → 200 + `XOR-RELAYED-ADDRESS`/`LIFETIME`/`XOR-MAPPED-ADDRESS` + `SOFTWARE` | 401/438（鉴权）、**486**（超配额）、**508**（端口耗尽）、442（非 UDP）、440（地址族不支持）、500 |
| 重复 `Allocate` | **同一 transaction id** 的重传幂等返回现有 relay（RFC 8656 §6.2）；**新 transaction id → 437**；**同一 5 元组、不同用户 → 441**（不得暴露/改动他人 allocation） | 437（`ALLOCATION-MISMATCH`）、441（`WRONG CREDENTIALS`）|
| `Refresh` | 续期；**缺 `LIFETIME` → 服务端默认（600s）**；`LIFETIME=0` → 释放 | 437（未知 allocation）、**441（他人 allocation）**、401/438 |
| `CreatePermission` | 校验 peer 地址族与 relay 一致；**先校验整条请求的 quota，再一次性写入**（不做部分生效）| **441（他人 allocation）**、403（禁止的 peer）、443（族不匹配）、**508（permission 容量超限）**、401/438 |
| `ChannelBind` | 校验通道号范围/已占用/peer；写 channels | 400（越界/重复）、**441**、403、443、**508（隐式 permission 超限）** |
| `Send` indication | 仅当 permission 覆盖 peer IP 时转发；无权限静默丢弃 | — |
| `Data` indication | relay 收到 peer 数据 → 发给 client（带 `XOR-PEER-ADDRESS`）| — |
| `ChannelData` | 命中通道 → 直接转发；UDP 上 4 字节头，TCP 上 4 字节头 + 按 4 字节对齐 | 未命中通道静默丢弃 |

## 4. 定时回收

- 单一定时扫描任务（`interval(1s)`）遍历 `allocations`：
  过期 allocation → 从 `used_ports` 归还端口、drop `relay`（socket 关闭）、移除条目；
  过期 permissions/channels 就地删除。
- 选择「定时扫描」而非「每条目 sleep 任务」：条目数量级小（配额上限数百），避免任务爆炸。
- **回收断言**：测试在 allocation 过期后 `ss -lun` 无残留。

## 5. 鉴权复用

- 复用 `rstun-auth` 的长期凭据实现：`REALM`/`NONCE`/`MESSAGE-INTEGRITY`（HMAC-SHA1 先做，SHA256 归 T2 的 8489 可选）。
- nonce 无状态（HMAC(secret, expiry|client_ip)）；TURN 与 STUN 共用同一 secret 与过期策略。
- 401/438 分支必须与 STUN 一致（同一函数），避免两套语义。

## 6. 配额与端口

| 配置 | 默认 | 行为 |
| --- | --- | --- |
| `--relay-ports lo-hi` | 49152–65535 | 端口耗尽 → 508；与系统 `ip_local_port_range` 重叠时文档提示 |
| `--max-allocations-per-user` | 8 | 超限 → 486 |
| `--max-allocations-per-ip` | 16 | 超限 → 486 |
| `--permission-limit` | 10 | 超限 → **508**（RFC 8656 §10.2；整条请求原子校验）|
| `--allocation-lifetime` | 600s | 上限 3600s |

> 防回环：peer 为 unspecified / multicast / 本进程监听地址 / 该 allocation 自身 relay → 403。
> **loopback peer** 仅在请求到达的 socket 本身绑定在回环地址时允许（本地开发/测试）；
> `--listen 0.0.0.0` 或公网监听下一律拒绝（否则通配地址会让「peer=127.0.0.1:<监听端口>」漏检）。
> 同进程内**其它 allocation 的 relay 地址**允许（`turnutils_uclient -y` / 同 NAT WebRTC 的正常路径）。
> 已知盲区：宿主自身**公网 IP** 无法在不引入接口枚举依赖的情况下判定（文档登记）。

## 7. 传输细节

- **UDP**：`ChannelData` 与 STUN 消息共用监听 socket；按首字节 `0x40..0x7F` 区分（RFC 8656 §12.4）。
- **TCP**：TURN 消息按 STUN 分帧；`ChannelData` 有 4 字节头 + padding（§12.5）。TCP 上无 `Send/Data` indication 的必要（可直接 `ChannelData`），但**仍应支持**。
- 发送路径：client 侧从「收到请求的 server socket」发出（保持源地址正确）。

## 8. 兼容与回滚

- `--turn` 关闭：不解析 TURN method（非 Binding 仍回 400，与现状一致）。
- 单批 commit 可回滚；无持久化状态。
- 与 coturn 对跑：`turnutils_uclient` 同一组参数连两个服务，中继行为一致。

## 9. 观测（`/metrics` 已上线，必须接入）

`src/ops.rs` 的 `Counters` 已提供 `/metrics`（见 `.trellis/spec/backend/ops.md`）。T1 必须接入以下指标（与退出统计同源）：

| 指标 | 类型 | 标签 |
| --- | --- | --- |
| `rstun_turn_allocations` | gauge | —（当前活动分配数）|
| `rstun_turn_bytes_total` | counter | `direction=in\|out` |
| `rstun_turn_allocations_total` | counter | `result=created\|expired` |
| `rstun_turn_rejected_total` | counter | `reason=quota\|ports\|family\|loopback` |

- 退出统计仍需打印同一组数字（便于无 `/metrics` 的部署排查）；
- 未开启 `--turn` 时这些指标**不出现**（与 ops 的「TURN 指标省略」约定一致）。
