# TURN 多实例：跨实例 allocation 归属与请求转发

## 背景（实测，见 `research/multi-instance-integration.md`）

今天只有 nonce / REST 凭据跨实例共享，allocation 表、端口池、`Instant` 计时器、socket 全在进程内。
两个真进程同段跑出来的现状：

| 客户端动作落到非归属实例 | 现状后果 |
| --- | --- |
| `Refresh` / `CreatePermission` / `ChannelBind` / `Connect` | `437 Allocation Mismatch`（鉴权已通过，纯归属失败）|
| `ConnectionBind` | `400`（该实例的 `CONNECTION-ID` 表里没有）|
| `Send` / `ChannelData` | **静默丢弃**（客户端以为媒体在走）|
| `Allocate`（重传/换实例）| **建第二份 allocation**，返回另一个 relay 地址，两份都活到 TTL |
| TCP 控制连接在 B 关闭、allocation 在 A | A 的 allocation 与 relay socket **泄漏到 TTL** |

另有端口池事实：UDP relay **不设** `SO_REUSEPORT`（bind 失败自动跳过 → 可共用同段）；
TCP relay listener **设了** `SO_REUSEPORT`（同机同段会绑同一端口，入站 peer 被内核按 4 元组分流到错误实例）。

## Goal

N 个实例、客户端可落到任意实例（无 5 元组粘性）时，TURN 语义仍正确：
同一 5 元组**只有一份** allocation，所有方法按归属处理，数据面双向可达，
allocation 生命周期跟随控制连接回收（不靠 TTL 兜底）。

## Requirements

- **R1 归属判定与转发（控制面）**：任一实例收到 TURN 请求，能判定该 5 元组的归属实例；
  非归属时转发给归属实例执行，响应经入口实例回客户端。
- **R2 数据面（客户端→peer）**：`Send` indication 与 `ChannelData` 在非归属入口同样生效。
- **R3 数据面（peer→client）**：由归属实例送达客户端；对「写队列属于接受连接的实例」的传输
  （TCP/TLS/DTLS）必须反向推回该入口实例，不能另起一条连接。
- **R4 生命周期联动**：控制连接结束或 `LIFETIME=0` 时，归属实例的 allocation 与 relay 资源被释放；
  TCP/DTLS 连接关闭必须通知归属实例，不等 TTL。
- **R5 端口策略**：UDP 池可共用同段（依赖 bind 失败自动分区）；TCP 池必须按实例分片；
  `--listen` 端口不可共用。配置与文档必须显式写明。
- **R6 成员与失效**：成员表静态配置；归属实例不可达时有**确定**的错误语义
  （不得静默丢包、不得退化成 `437`）。
- **R7 默认零变化**：未开启多实例配置时，行为与 `26.410.107` 逐字节一致（`frozen` 3×17 基线）。
- **R8 无外部依赖**：不引入 Redis / etcd / gRPC 等；内部协议手写（与 `ops.rs` 的极简 HTTP 同风格），
  lean 10 / full 15 的依赖数契约不变。

## 约束

- **C1 部署契约（源地址）**：客户端发往的地址必须在回程时保持稳定 —— 每实例独立公网 IP，
  或共享 VIP + DSR。否则任何实现都无法让客户端接受回程（这是部署前提，不是代码能补的）。
- **C2 单机多实例**：**成员间 `--listen`（以及 TLS/DTLS）端口必须相同、IP 必须不同**（同一 5 元组的归属键包含 listen_port，端口不同会让同一客户端在两个入口被算到两个 owner；同机不同端口不用于集群）。启动时用 `HELLO` 校验端口，不一致即拒绝启动。UDP relay 段可相同（bind 失败自动分区）；**TCP relay 段必须不同**（每实例一个 `--tcp-relay-ports`，与 `--relay-ports` 也不重叠）。
- **C3 成员变更 = 排空重建**：静态成员表决定归属，改成员会让部分键换主，在途 allocation 在
  LIFETIME 到期前不可服务；不做在线迁移/接管。
- **C4 配额按实例计**：`--max-inflight`、每用户/每 IP 配额、令牌桶仍是本进程视角（全局上限 = N 倍），
  文档必须写明。
- **C5 RFC 6062 分阶段**：跨实例裸字节中继是独立阶段；该阶段落地前，
  **多实例 + `--turn-tcp-relay` 启动即拒绝**（明确报错，不允许半可用）。
- **C6 指标标签集不变**：不新增 `instance=` 之类标签；每实例 `/metrics` 仍是本进程视角。

## 非目标

- allocation 跨实例迁移 / 故障接管（实例崩溃 → 其 allocation 随 TTL 消失）
- 全局配额、全局指标聚合、跨实例计费
- 动态成员发现（gossip / 注册中心）
- 共享状态存储（Redis / etcd）

## 验收（按阶段，各自可独立发布）

**M1 · UDP 控制面 + 数据面**

- [ ] 两实例 + 假 LB（逐包轮转）：A `Allocate` → B `Refresh`/`CreatePermission`/`ChannelBind` 均 `200`，
      `XOR-RELAYED-ADDRESS` 与 A 分配时一致
- [ ] 同一客户端 5 元组先后发到 A/B 的 `Allocate` → **只有一份** allocation、一个 relay 地址
      （现状两份，见调研 §2.3a）
- [ ] 经非归属实例 `Send`/`ChannelData` → peer 收到字节且 `bytes_total{direction=in/out}` 增长
      （现状静默丢，`turn.rs:2752-2754`、`2896-2898`）
- [ ] 归属实例不可达 → 明确错误（`500`），客户端可重试；**不**静默丢、**不**回 `437`
- [ ] 未配置多实例 → `frozen` 3×17 与基线逐字节一致

**M2 · TCP/TLS/DTLS 控制面 + 回程**

- [ ] TCP 控制连接落到 B、allocation 在 A：`Refresh` `200`；peer→client 字节经 **B 的写队列**到达客户端
- [ ] 客户端断开 B → A 的 allocation 立即释放（`ss -lun` 无残留，**不等 TTL**）
- [ ] TLS 与 DTLS 同路径（`turns:` 与 DTLS 各一条）

**M3 · RFC 6062（出站 + 被动）**

- [ ] 出站 `Connect` 在 A、`ConnectionBind` 落到 B → 绑定成功、裸字节双向
- [ ] 被动：peer 连入 A 的 relay、控制连接在 B → `ConnectionAttempt` 经 B 送达、bind 成功
- [ ] `ss -ltn` 断言两实例 TCP relay 段不重叠；M3 落地后才允许「多实例 + `--turn-tcp-relay`」启动

## 备注

- 判据全部可用 lab 复现：假 LB 用 Python（UDP 逐包轮转 + TCP 转发），探针不 `connect` UDP，能收非对端地址的响应。
- 各阶段未完成时保持「启动拒绝」而不是「部分方法可用」。
