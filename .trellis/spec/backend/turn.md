# TURN 契约（RFC 8656 中继：T1 UDP/TCP + T2 TLS/DTLS/REST/带宽）

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
| `REQUESTED-ADDRESS-FAMILY` (0x0017) | 4 字节 `family | reserved`；**reserved 24 位必须忽略**；`Allocate`：族与 `relay_ip` 一致 → `200`；不一致或族值非 `0x01`/`0x02` → **`440`**（计 `rejected_family`）；长度 ≠ 4 → **`400`**；`Refresh`：族与该 allocation 的 relay 族**不匹配 → `443`**（§8.2 MUST，计 `rejected_family`）、匹配 → 正常续期、长度 ≠ 4 → `400`；`RESERVATION-TOKEN` 与 `EVEN-PORT` **或 RAF** 互斥 → **`400`**，且**步骤 5 先于步骤 7**（异族 token 也是 400，coturn 同）；`ADDITIONAL-ADDRESS-FAMILY` (0x8000) 未实现（comprehension-optional，忽略）⇒ §7.2 **步骤 6**（RAF+AAF → 400）**不生效**，记账于 `docs/book/src/turn.md` |
| `DONT-FRAGMENT` (0x001A) | **平台**：`DONT_FRAGMENT_SUPPORTED = cfg!(any(target_os="linux","macos","ios"))` —— 只有 `set_dont_fragment` 真实现的三个平台为真；Windows 与其它 unix（FreeBSD 等）为假 ⇒ `0x001A` 保持未知 comprehension-required → **`420`** + `UNKNOWN-ATTRIBUTES=[0x001A]`（§7.2 步骤 4 允许）；编译期断言禁止该常量为真而实现缺失。**支持平台的行为**（§18.9）：`Allocate` 带它 → relay socket 置 DF（Linux `IPPROTO_IP/IP_MTU_DISCOVER`=`IP_PMTUDISC_DO`，IPv6 socket 用 `IPV6_MTU_DISCOVER`；macOS/iOS `IP_DONTFRAG`/`IPV6_DONTFRAG`），**整个 allocation 生命周期有效**；长度 ≠ 0 → **`400`**；`setsockopt` 失败 → **`500 Server Error`** + 计 `rejected_df` + 端口归还池。`Send` indication 带它 → **仅该报文**置位，发送后恢复 `IP_PMTUDISC_WANT`（Linux）/`0`（macOS），切换在同一 allocation 的互斥锁内（并发**带 DF 的** `Send` 不得看到彼此的临时状态；不带 DF 的 `Send`/`ChannelData` 不取锁，见下方「已知限制」）；**置位失败 → 丢弃该 indication**（§11.2 原文：视为未知 comprehension-required 属性，「and thus the Send indication is discarded」）+ 计 `rejected_df`，**不得**降级为「不置位但照常转发」；属性长度 ≠ 0 → 同样丢弃 + 计 `rejected_df`（indication 无错误响应）。`ChannelData` 无属性位 ⇒ 沿用 allocation 级设置。`cfg(unix)` 之外不得引用 `libc`。**已知限制（并发窗口）**：`df_lock` 只被**带 DF 的 `Send`** 持有 —— 不带 DF 的 `Send` 与 `ChannelData` 不取锁（数据面零锁开销），因此同一 allocation 上「DF-Send 置位窗口」与普通发包并发时，普通报文可能被短暂带上 DF；后果仅限「该报文超过路径 MTU 时被丢」，不跨 allocation、不改变协议语义。取锁范围**不得**说成「所有外包发互斥」 |
| 依赖 | `[target.'cfg(unix)'.dependencies] libc = "0.2"` 是 DF 的**唯一**新增直接依赖（不得引 `nix`/`rustix`）；直接依赖计数 unix 口径 **10（lean）/ 15（full）**，Windows 9/14；`script/ci/gen-sbom.sh` 的 `EXPECTED_DIRECT` 必须同步。`x509-parser 0.16`（optional，仅 `tls`）是证书到期 gauge 的唯一新增直接依赖（已在 lock，不得引 `notify`/`inotify`）|
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
| 指标 | `rstun_turn_allocations`、`rstun_turn_bytes_total{direction}`、`rstun_turn_allocations_total{result}`、`rstun_turn_rejected_total{reason=quota\|ports\|family\|loopback\|df\|tcp_connect\|tcp_bind\|tcp_send\|tcp_buffer\|tcp_quota}`、`rstun_turn_tcp_connections{state=pending\|bound}`；仅 `--turn` 输出 |
| RFC 6062 开关 | `--turn-tcp-relay` **默认关**；关时 `REQUESTED-TRANSPORT=6` 仍 `442`、`Connect`/`ConnectionBind` 不是 TURN 方法（仍 400），默认路径字节冻结不变 |

## 3. 判定顺序（四个 request 方法）

```
准入（限速/在途）→ 鉴权（401/438/400）→ 420（未知 comprehension-required）
→ 5 元组查表（无 → 437）
→ 用户名比对（不同 → 441）
→ 方法特定校验（400/442/440/443/508；其中 RAF 族比对在 `egress_ip` **与 §7.2 步骤 5（`EVEN-PORT`/`RESERVATION-TOKEN` 互斥）之后** —— 异族 token 也是 400）
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
9. 不配 `--turn`：3 组配置 × 17 请求与 `FROZEN_BASE`（默认 `cad4fa2`）逐字节一致。
10. `REQUESTED-ADDRESS-FAMILY` 四态：族匹配（+ reserved 非零）→ `200`；IPv4 客户端请求
    `0x02` → `440` 且 `active()==0`、`rejected_family` 增长；长度 3 → `400`；族值 `0x03`
    → `440`；`RESERVATION-TOKEN` + RAF **两种族（0x01/0x02）都** → `400`（步骤 5 先于
    步骤 7）；`Refresh`：RAF `0x02`（IPv4 分配）→ **`443`** 且 allocation 存活（含
    `LIFETIME=0` 的异族请求也不得释放）、RAF `0x01` → `200` + 正常 LIFETIME、RAF 长度 3
    → `400`；lab `raf` 项用真 uclient 断言 `-X` 中继、`-x` → `error 440`。
11. `DONT-FRAGMENT`（0x001A）：
    - 支持平台（Linux/macOS/iOS）：`Allocate` 带 DF → `200`、allocation 标记 DF，且
      **`getsockopt` 回读 relay socket 为 `IP_PMTUDISC_DO`/`IP_DONTFRAG=1`**
      （`allocate_with_dont_fragment_sets_the_relay_socket`）；DF 长度 ≠ 0 → `400` 且零分配；
      `set_dont_fragment` 往返（set→DO、clear→WANT、IPv4 与 IPv6 各一遍：
      `set_dont_fragment_round_trips`）；`Send` 带 DF（allocation 未开）→ 转发成功、回读恢复
      `WANT`；**置位失败 → peer 收不到（丢弃）且 `rejected_df` 增长**；畸形 DF 的 `Send` →
      同样丢弃且 `rejected_df` 增长（`send_indication_dont_fragment_is_per_datagram`，
      失败分支用 `df_failure` 注入；两条断言都做过「改成转发 → 测试红」的反证）；
    - 不支持平台（Windows / FreeBSD 等）：`turn_unknown_attributes([0x001A]) == [0x001A]`，
      `Allocate` → `420` + `UNKNOWN-ATTRIBUTES=[0x001A]`；`DONT_FRAGMENT_SUPPORTED` 必须等于
      `cfg!(any(linux, macos, ios))`（`dont_fragment_support_matches_the_platforms_that_can_set_the_bit`
      与编译期 `const _: () = assert!(!DONT_FRAGMENT_SUPPORTED)`）；
    - lab `df` 项：`uclient -g` 必须中继（旧行为 `error 420`）、中继字节 > 0、`rejected_df` 可读；
      `tcpdump -i lo` 的 `flags [DF]` **只是记录性证据**（Linux 默认 `IP_PMTUDISC_WANT` 本来就置
      DF），判别性证据是上面的 `getsockopt` 回读；
    - lab `ipv6relay` 项：`--listen [::1]` + IPv6 客户端 → `XOR-RELAYED-ADDRESS` 是 IPv6、
      `Send`/`Data`/`ChannelData` 双向字节 > 0；无 `::1` 时 SKIP（不算通过）。

外部对照：`script/lab/rstun-turn.sh` 的 `wrong-user` / `lifecycle` / `relay` / `coturn` 项用同一
探针分别对 rstun 与本地 `turnserver` 跑，输出应逐行一致（唯一允许差异：coturn 在
`LIFETIME=0` 后会把 allocation「复活」，rstun 按 RFC 回 437）。

**字节冻结口径**

- 默认关闭（无 `--turn`）由 lab `frozen` 项（3 配置 × 17 请求）对照 `FROZEN_BASE`。
  基线二进制用 `RSTUN_BUILD_VERSION=<当前二进制的版本串>` 重建，因此**版本号 bump 不会让
  frozen 假红**，基线不必随发版挪动；只有想换对照点时才改 `script/lab/rstun-turn.sh` 里的
  默认值（当前 `cad4fa2`，即 RAF 改动的基线）。
- TURN 侧**不设**「不带 RAF 的请求」的字节对照：RAF 缺失走 `Ok(None)` 分支，不进入任何族
  比较/拒绝路径；由 `requested_address_family_parsing` 的 `Ok(None)` 与
  `requested_address_family_selects_the_relay_family` 中「无/匹配 RAF → 200」隐含保证。
  将来若给 TURN 加字节冻结，应按 `--turn` + 固定 transaction id 增补一组。

## 5a. RFC 6062 契约（`--turn-tcp-relay`，出站）

| 项 | 契约 |
| --- | --- |
| 范围 | **只做出站**：`Allocate(TCP)` + `Connect` + `ConnectionBind`。被动模式（`ConnectionAttempt` / `uclient -P`）不在范围，`turnutils_uclient -T`（隐含 `-y`）因此不能作为验收判据 |
| `Allocate` TCP | 控制面必须 TCP/TLS（UDP/DTLS → `400`）；带 `DONT-FRAGMENT`/`EVEN-PORT`/`RESERVATION-TOKEN` → `400`（**与平台无关**：420 gate 对「`Allocate` + `REQUESTED-TRANSPORT=6`」把 `0x001A` 视为已知，Windows 也不得回 420；UDP Allocate + DF 在 Windows 仍按 §7.2 步骤 4 回 420）；成功 `200` + TCP `XOR-RELAYED-ADDRESS` + `XOR-MAPPED-ADDRESS` + `LIFETIME` + `SOFTWARE`，**无 `CONNECTION-ID`**；`Refresh`/`LIFETIME` 语义同 UDP |
| 端口池 | `used_tcp_ports` 独立于 UDP 池；listener 以 `SO_REUSEPORT` 绑定（`Connect` 从该地址出站）；「出站源端口 = relay 端口」只在 `RELAY_SOURCE_PORT_BOUND`（`cfg!(unix)`）成立，Windows 回退临时源端口 —— 实现与测试共用该常量，不得另写平台判断 |
| `Connect` | 无 allocation / 非 TCP allocation → `437`；他人 allocation → `441`；缺/非法 `XOR-PEER-ADDRESS` → `400`；禁用地址 → `403`（含 family `443`）；重复 peer（connecting/pending/bound）→ `446`；出站失败/超时（`TCP_CONNECT_TIMEOUT = 30s`）→ `447`；每 allocation 数据连接上限 16 → `508` + `tcp_quota`；成功 `200` + `CONNECTION-ID`，**不带 `SOFTWARE`**（对齐 coturn）|
| `ConnectionBind` | 必须 stream 传输、新连接（该 5 元组无 allocation）、`CONNECTION_ID` 4 字节且指向 pending、同用户名、未过期；否则 `400` 且**发完响应再关连接**（401/438 挑战保留，不关）；成功后该连接裸字节，不再解析 STUN |
| 生命周期 | pending 30s 未 bind → 关闭（`sweep`）；`LIFETIME=0`/allocation 过期 → 关闭全部数据连接（**控制连接保留**，与 coturn 的差异）；任一方向干净 EOF 只半关闭，错误/stop 信号关双向 |
| 缓冲 | 预绑定 peer→client 最多 `TCP_PREBIND_BUFFER = 64 KiB`，超限关连接 + `tcp_buffer`；绑定后先刷缓冲再双向 copy |
| 其它方法 | `CreatePermission` 正常 `200`；`ChannelBind` → `400`；`Send`/`ChannelData` 丢弃 + `tcp_send` |
| 资源 | 数据连接是 accepted TCP 连接，占一个 `--max-inflight` 名额（写进文档） |

## 5b. T2 契约（`turns:` / DTLS / REST / 带宽）

| 项 | 契约 |
| --- | --- |
| TLS | `--turn-tls-listen` + `--tls-cert`/`--tls-key`；材料在**启动时**解析，缺失/不可读/不配对 → exit 1（**不降级明文**）；TLS 与明文**不共用端口**；握手 **5s** 超时，失败计数（退出日志 `handshake_failed`），日志不含证书内容 |
| DTLS | `--turn-dtls-listen` + 同材料；DTLS **1.2**（`webrtc-dtls`）；**一个 datagram = 一个 STUN/TURN 消息或一个 `ChannelData`**（无 4 字节对齐）；5 元组 client transport = `ClientTransport::Dtls`；握手在每客户端任务里（5s），不阻塞 accept |
| DTLS 私钥 | 必须 PKCS#8 + **ECDSA P-256 / Ed25519**（`webrtc-dtls` 的硬限制）；启动时明确报错，不得静默跳过 DTLS |
| **证书热加载** | `SIGHUP`（`cfg(unix)`，独立任务，不塞进 `wait_for_shutdown`）+ **文件轮询**（`(mtime,len)` 去重；间隔由 `--tls-cert-poll <秒>` 决定：**默认 30s**、`0` = **不启动轮询**、只认 `SIGHUP`、其它正整数 = 该间隔；Windows 无 `SIGHUP` ⇒ 轮询是唯一触发，`0` **启动即拒绝**）共用同一个 `reload`，该 reload **必须**调用 `load_secure_material`（不得另写校验）；成功后**一次** `Arc` swap 整个 `SharedMaterial`（TLS `Arc<ServerConfig>` + DTLS `Config`），TLS/DTLS 同时生效；失败后 1s 重试一次，两次都失败才计 failed 并保留旧材料；SIGHUP 立即重试，轮询只在 `(mtime,len)` 变化时解析。`--tls-cert-poll` 属 secure-material 组：给了却没有 `--turn-tls-listen`/`--turn-dtls-listen` → 启动失败；lean 构建给出 → `` `tls` feature `` 错误。**启动时**打一行 `rstun: certificate reloader started poll=Some(30s)|None`（即 `?setup.poll` 的原值；SIGHUP 注册失败时按 `poll` 分支：`Some` → warn「falls back to polling」，`None` → error「不再自动轮换」），lab 用它断言 `0` 真的没装定时器（只等 4s 抓不到 30s 定时器的变异体：`setup.poll.or(Some(30s))` 必须让 `poll=None` 断言变红）。**生效范围**：新连接/新 DTLS 会话用新材料，已建立会话持旧材料（无重协商）；路径不可运行期修改。日志含路径与 mtime/notAfter，不含私钥 |
| **材料校验范围** | DTLS 的密钥规则**只在该次启动真的配了 `--turn-dtls-listen` 时**才应用。只开 `--turn-tls-listen` 时 RSA 证书必须被接受（Let's Encrypt 的默认形态）；`--features tls`（无 dtls）单独构建同理。反例：同时配 DTLS 监听 + RSA → 启动失败（热载沿用同一 `needs_dtls`）|
| TLS 5 元组 | 与明文 TCP 相同（`ClientTransport::Tcp`）；区分靠监听端口 |
| REST | `--rest-secret`；`username=<expiry>:<label>`（按**第一个** `:` 切分，label 可含 `:`）、`password=base64(HMAC-SHA1(secret, username))`（**标准 base64，带 padding**）；过期 → **401**（不是 438）；错 secret → 401；**REST 优先于用户表**（能解出时间戳即不查表）；`--rest-secret` 需要 `--realm` + `--auth-secret`，可以没有静态用户 |
| 带宽 | `--turn-bandwidth` 字节/秒，**每方向**一个令牌桶，容量 = 1 秒，默认 1 MiB/s，`0` = 不限；超限**丢该包 + 计数**，allocation 不销毁；与端口/分配配额独立 |
| 指标 | T2 新增 `rstun_turn_bytes_dropped_total{direction}`、`rstun_turn_tls_reload_total{result=ok\|failed}`、`rstun_turn_tls_cert_expires_seconds`（gauge，`notAfter − now`，`-1` = 不可解析；仅配了 TLS/DTLS 监听时出现）；握手失败**不进 `/metrics`**（保持标签集合），只进退出日志 |
| 默认关闭 | 不配任何 T2 开关时与 T1 逐字节一致（`frozen` 项 3 配置 × 17 请求）|
| **构建 feature** | `default = []`（lean）／`tls`／`dtls`（含 `tls`）／`full`。TLS/DTLS 的监听、材料解析、连接处理与单测全部 `#[cfg(feature = …)]`；**四个 flag 始终定义**（`--help` 不随构建变化），lean 下给出 → 启动失败且错误含 `` `tls` ``／`` `dtls` `` feature 名与 `--features tls,dtls`。`--rest-secret` / `--turn-bandwidth` **不 gate** |

### Tests Required（T2 断言点）

1. `turnutils_uclient -S -t`（TLS）与 `-S`（DTLS）两侧完成中继（对 rstun 与 coturn 同参数）。
2. `openssl s_client`（TLS）与 `-dtls1_2`（DTLS）握手成功。
3. 有监听无材料 / 证书路径不可读 → 启动失败并给出可操作错误。
4. REST：有效 200、过期 401、错 secret 401、label 含 `:` 200；静态用户仍可用；
   REST 与用户表同名时 REST 优先（同名用户的表口令必须被拒）。
5. 带宽：超过配额后 `rstun_turn_bytes_dropped_total{direction="in"}` 增长，
   allocation 存活（随后的小流量仍能中继），`/healthz` 仍 200。
6. `TokenBucket` 单测：满桶、恰好耗尽、空桶丢弃、连续补充、容量上限。
7. **两种构建**：`cargo test`（lean）与 `cargo test --all-features` 都必须全绿；
   `cargo tree -e normal --depth 1` 在 lean 下是 10、`--all-features` 下是 15（Windows 9/14）。
8. **RSA 证书 + 仅 TLS**：full 构建下 `--turn-tls-listen` + RSA 私钥必须能启动并完成 TLS 中继
   （lab `tls` 项第 4 步；单测 `full_build_accepts_an_rsa_certificate_when_dtls_is_off`）；
   同一份 RSA 材料再开 `--turn-dtls-listen` → 启动失败。
9. **lean 构建拒绝 secure flag**：`--turn-tls-listen` → 错误含 `` `tls` feature ``；
   `--turn-dtls-listen` → 错误含 `` `dtls` feature ``（`#[cfg(not(feature = …))]` 单测）。
10. **脚本**：`rstun-turn.sh` 默认用 lean 构建，`tls`/`dtls`/`cert-reload`/`cert-poll` 项记 SKIP 并说明；
   `--tls`/`--dtls`（或 `--only tls|dtls|cert-reload|cert-poll|coturn`）自动 `--features full` 构建；
   `--no-build` 时探测二进制是否带 feature（读启动错误里的 feature 名，不猜）。
11. **热载成功**：`reload_swaps_atomically_and_keeps_the_old_material_on_failure`
   （成功换 `Arc`、失败保持同一 `Arc` 且只计一次 failed）；
   `material_stamp_tracks_rewrites_and_missing_files`（`(mtime,len)` 去重、缺文件返回 None）；
   lab `cert-reload` 项：SIGHUP 后 TLS 与 DTLS 新连接指纹同时变化、轮询路径换第三张证书。
11a. **`--tls-cert-poll`**：`cert_poll_interval_defaults_to_30s_and_can_be_disabled`
   （不传 → `Some(30s)`；`0` → `None`，即不 spawn 轮询；`2` → `Some(2s)`）；
   `cert_poll_needs_a_secure_listener_and_a_signal_source`（无 secure 监听 → 错误；
   `has_sighup=false` + `0` → 错误且文案含 `SIGHUP`；Windows 下正整数值仍可用）；
   `tls_cert_poll_needs_a_secure_listener`（`build_turn` 两条负例 + 有监听时接受 0/2）；
   lab `cert-poll` 项：无监听 + flag → 启动失败、`0` 下改文件 4s 不重载而 `SIGHUP` 重载、
   `2s` 下改文件约 2s 内重载。
12. **坏材料**：不配对 / 截断 / 非 PKCS#8 / RSA（DTLS 监听下）→ 旧证书继续服务、
   `reload_total{result="failed"}` 增长、进程存活（单测两条 + lab 的坏密钥对一段）。
13. **到期 gauge**：`load_reads_the_leaf_not_after`、`secure_stats_expiry_follows_the_clock_and_marks_unknown_as_minus_one`；
   lab 断言 `rstun_turn_tls_cert_expires_seconds` 与 `openssl x509 -enddate` 差 ≤ 60s。
14. **门禁**：未配 `turns:`/DTLS 时两个证书指标**不出现**
   （`tls_reload_metrics_appear_only_with_secure_material`、`turn_metrics_appear_only_when_enabled`）；
   `cargo check --target x86_64-pc-windows-msvc`（`cfg(unix)` 隔离 SIGHUP）。

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
