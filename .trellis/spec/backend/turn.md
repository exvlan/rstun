# TURN 契约（RFC 8656 UDP 中继 T1）

> 来源：2026-11-20 `rstun-turn-udp` 冷复核。三个阻塞项（441 / 通配监听防回环 / permission
> 容量绕过）与两项 RFC 对齐（Refresh 缺 LIFETIME、容量超限 508）已修复。任何改动
> `src/turn.rs`、TURN 请求分流、`--turn` 配置或 TURN 指标的提交都必须满足本文。

## 1. Scope / Trigger

- 修改 `src/turn.rs`、`main.rs` 的 TURN 分流（UDP/TCP）、`--turn` 相关 flag、`rstun_turn_*`；
- 新增 TURN 方法/属性/错误码、修改 allocation/permission/channel TTL 或配额语义；
- 任何会改变「`--turn` 关闭时字节」的改动。

## 2. Signatures（可执行契约）

| 项 | 契约 |
| --- | --- |
| 5 元组 | `(client SocketAddr, client transport, server SocketAddr)`；relay 恒为 UDP |
| `Allocate` 幂等 | **同一 transaction id** 的重传 → `200` + 原 `XOR-RELAYED-ADDRESS`/`LIFETIME`；**新 tid → `437`** |
| `Allocate` 换用户 | 5 元组命中但 `allocation.username != identity.username` → **`441`**；不得读/改他人 allocation |
| `Refresh` 生命周期 | 缺 `LIFETIME` → 服务端默认（600s，§8.2）；`LIFETIME=0` → 立即释放；未知 allocation → `437` |
| 他人 allocation | `Refresh` / `CreatePermission` / `ChannelBind` 命中他人 allocation → **`441`**；他人 `LIFETIME=0` 不删除 |
| permission 容量 | `--permission-limit`（默认 10）；一条请求里多个 `XOR-PEER-ADDRESS` **先全量校验再写入**，超限 → **`508`** 且零生效 |
| channel 容量 | `ChannelBind` 的隐式 permission 占用同一上限，超限 → **`508`** |
| 403 语义 | 只用于「地址本身被禁」：unspecified / multicast / **广播** / 本进程监听地址 / 自身 relay / loopback peer（见 §4） |
| 地址归一化 | 先做 `Ipv6Addr::to_ipv4_mapped()` 归一，再跑四类判定（否则 `::ffff:127.0.0.1` 会跳过全部检查）|
| `--allocation-lifetime` | **同时**是「缺省授予值」与「上限」：缺省 / `< 600` → 600；`> cap` → cap（`--allocation-lifetime 2` 用于回收测试）。help 与本节口径一致 |
| `ChannelData` | UDP 声明长度 > 实际报文 → 静默丢弃（不转发截断内容）；TCP 按 4 字节对齐；未命中通道静默丢弃 |
| 成功响应 | 均带 `SOFTWARE`（§14.10 SHOULD）并按请求算法签名；401/438 不带 SOFTWARE |
| TCP 写队列 | **有界**（`TCP_SINK_CAPACITY = 64`）+ `try_send`；溢出丢 relayed 数据，不无界增长 |
| TTL | permission 5 分钟、channel 10 分钟、allocation 600s（受 `--allocation-lifetime` 上限约束）；1s 扫描回收 |
| 指标 | `rstun_turn_allocations`、`rstun_turn_bytes_total{direction}`、`rstun_turn_allocations_total{result}`、`rstun_turn_rejected_total{reason}`；仅 `--turn` 输出 |

## 3. 判定顺序（四个 request 方法）

```
准入（限速/在途）→ 鉴权（401/438/400）→ 420（未知 comprehension-required）
→ 5 元组查表（无 → 437）
→ 用户名比对（不同 → 441）
→ 方法特定校验（400/442/440/443/508）
→ 写入 → 200（签名 + SOFTWARE）
```

`Allocate` 额外在「5 元组查表」命中后先比用户（441）、再比 tid（437）、最后才幂等 200。

> **有意偏离（SHOULD）**：RFC 8656 §6.1 建议失败响应也带 `SOFTWARE`；本实现只在成功响应带
> （401/438 复用 STUN 的共享函数，加进去会破坏「默认关闭字节冻结」）。要补时只能加在 `--turn` 分支。

## 4. 防回环（`is_own_endpoint`）

一律拒绝（先做 IPv4-mapped 归一）：`is_unspecified()`、`is_multicast()`、**`is_broadcast()`**、
与任一已绑定监听地址相等、与请求到达的 socket 相等、与该 allocation 自身 relay 相等；
以及**通配监听下的宿主自身地址**：若 peer 端口是本进程某个监听端口，且 `egress_ip(local, peer) == peer.ip()`
（内核去往该地址会从它自己发出），即判定为本机地址。

**loopback peer**：仅当请求到达的 socket `local.ip().is_loopback()` 时允许（本地开发/测试与
`turnutils_uclient -y` 矩阵）；通配 `0.0.0.0` 或公网监听下一律拒绝 —— 这是通配下
`peer = 127.0.0.1:<监听端口>` 的唯一拦截点。

**允许**其它 allocation 的 relay 地址（同进程 client-to-client 是标准路径）。

**已知盲区**：只拒绝「本进程监听端口」上的宿主地址。宿主在**其它端口**上的服务不在判定范围
（PRD 的范围是「本服务自身监听地址」）；枚举全部接口属另一件事（接口枚举=新依赖），不得悄悄引入。

## 5. Tests Required（断言点）

1. 同一 5 元组换用户：`Refresh` / `CreatePermission` / `LIFETIME=0` 三个都 `441`，allocation 仍在。
2. `--listen 0.0.0.0:0` 下对 `127.0.0.1:<listen-port>` 的 `CreatePermission` → `403`。
3. `--permission-limit 1` + 一条请求 2 个 peer → `508` 且**零生效**（随后单个 peer 成功）。
4. `Refresh` 不带 LIFETIME → 600（coturn 同）。
5. permission/channel 容量超限 → `508`（不是 403）。
6. 新 tid 重复 `Allocate` → `437`；同 tid 重传 → 200 且 relay 不变。
7. 长度撒谎的 UDP `ChannelData` → peer 收不到。
8. 成功响应含 `SOFTWARE`（Allocate/Refresh/CreatePermission/ChannelBind）。
9. 不配 `--turn`：3 组配置 × 17 请求与 HEAD 逐字节一致。

外部对照：`script/lab/rstun-turn.sh` 的 `wrong-user` / `lifecycle` / `relay` / `coturn` 项用同一
探针分别对 rstun 与本地 `turnserver` 跑，输出应逐行一致（唯一允许差异：coturn 在
`LIFETIME=0` 后会把 allocation「复活」，rstun 按 RFC 回 437）。

## 6. Wrong vs Correct

#### Wrong
```rust
// 命中他人 allocation 却继续执行：bob 能删 alice 的 relay
let Some(allocation) = self.get(&key, now) else { ... };
self.remove(&key); // LIFETIME=0
```

#### Correct
```rust
if allocation.username != identity.username {
    return Decision::Respond(signed_error(.., ERROR_WRONG_CREDENTIALS, ..));
}
```

#### Wrong
```rust
// 循环外算一次 live，循环内 insert 不递增：一条请求可越过上限
let live = state.permissions.len();
for address in &peers { if live >= limit { fail } insert(address); }
```

#### Correct
```rust
// 先统计「本次要新增的 IP」，超出就整条拒绝，再统一写入
if live + wanted.len() > limit { return 508; }
for address in &peers { state.permissions.insert(address.ip(), now + TTL); }
```
