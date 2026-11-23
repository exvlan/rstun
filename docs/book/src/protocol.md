# 协议行为

本页是协议的**唯一真源**：请求 → 响应表、RFC 覆盖子集、错误码矩阵、420 的「已知属性」表，
以及默认关闭的兼容开关（`--mapped-address` / `--check-fingerprint` / `--alternate-server`）。
README 只保留摘要与链接。改行为时先改这里，再跑 `bash script/ci/check-docs.sh`。

> 鉴权见 [鉴权](auth.md)，NAT 行为发现见 [RFC 5780](nat-discovery.md)，
> 限速与反射防护见 [抗滥用](rate-limit.md)，中继见 [TURN](turn.md)，
> 运维面（`/metrics` / 环境变量 / 优雅退出）见 [README](https://github.com/exvlan/rstun/blob/main/README.md#运维面readiness--metrics--env--优雅退出--部署清单)。

| 输入                                                                                                | 输出                                                                                                                                                                                        |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Binding Request`（method `0x001`，任意 transaction id）                                            | `Binding Success Response`（`0x0101`）+ `XOR-MAPPED-ADDRESS` + `SOFTWARE: rstun/<version>`                                                                                                  |
| 同上，且**启用了 `--mapped-address`**                                                               | 额外带 `MAPPED-ADDRESS`（`0x0001`，RFC 5389 §15.1 的**非 XOR** 形式），位置紧跟 `XOR-MAPPED-ADDRESS` 之后                                                                                   |
| 同上，且**启用了 RFC 5780** 并落在**四 socket** 之一                                                | 额外带 `RESPONSE-ORIGIN`（本响应发出的 `IP:端口`）+ `OTHER-ADDRESS`（另一个 IP + 另一个端口）。其余地址（多 `--listen`、所有 `--listen-v6`）**不带**这两个属性                              |
| `Binding Request` + `CHANGE-REQUEST`（仅 UDP，且落在四 socket 之一）                                | 从**被请求的那个 socket** 发出响应（换 IP / 换端口 / 两者），仍带 `XOR-MAPPED-ADDRESS` + `RESPONSE-ORIGIN` + `OTHER-ADDRESS`；落在普通地址上时按 §5 **忽略**该属性，仍从原 socket 回包      |
| `Binding Request` + `RESPONSE-PORT`（仅 UDP）                                                       | 响应**发往**「请求的源 IP + `RESPONSE-PORT` 端口」：只改**目的端口**，**源 IP/源端口不变**（仍从收到请求的 socket 发出，`RESPONSE-ORIGIN` 也仍是它）；端口无需已绑定，任意 `0–65535` 都照发 |
| 落在**普通监听地址**上的 `Binding Request`（多 `--listen` 里非 primary 的地址、全部 `--listen-v6`） | 普通 5389 响应（`XOR-MAPPED-ADDRESS` + `SOFTWARE`）：**不带** `RESPONSE-ORIGIN`/`OTHER-ADDRESS`；`CHANGE-REQUEST` 按 §5 忽略（回包源不变）                                                  |
| `Binding Request`（**配置了凭据**，无 `MESSAGE-INTEGRITY` / 口令错 / 用户未知 / realm 不符）          | `401 Unauthorized` + `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`（长期凭据；短期凭据只有 `ERROR-CODE`）                                                                                       |
| 同上，且 `NONCE` 是本服务签发但已过期                                                               | `438 Stale Nonce` + 新 `NONCE` + `REALM`（RFC 5389 §10.2.2）                                                                                                                               |
| 同上，且凭据有效                                                                                    | 普通 200，并带与请求同算法的 `MESSAGE-INTEGRITY` / `MESSAGE-INTEGRITY-SHA256`                                                                                                              |
| `Binding Request` + `PADDING`（RFC 5780 §7.6）                                                      | 响应**带同样长度**的 `PADDING`（永远不超过请求长度），用于 MTU / 分片探测；`PADDING` 恒为最后一个属性                                                                                       |
| `Binding Request` + `RESPONSE-PORT` + `PADDING`                                                     | `400 Bad Request`（RFC 5780 §6："the server MUST return an error response of type 400"；§7.5 `MUST NOT process` 与 §10 `are rejected` 同指这条）                                            |
| `Binding Request` + 未知的 **comprehension-required** 属性（如 `0x0033`）                           | `420 Unknown Attribute`（`0x0111`）+ `ERROR-CODE 420` + `UNKNOWN-ATTRIBUTES`（`0x000A`，每个类型 2 字节，值长度恰为 `2×N`；不足 4 字节的由通用 TLV padding 补齐且**不计入** Length，§15.9） |
| 其它 method 的 **request**（如 TURN `Allocate` `0x003`，且**未开** `--turn`）                                         | 该 method **自己的** `4xx` 错误响应 + `ERROR-CODE 400 Bad Request`（RFC 5389 §7.3.1）。开 `--turn` 时 TURN 方法由 TURN 状态机处理（见「[TURN](turn.md)」）                            |
| `Binding Request` + `FINGERPRINT`（**`--check-fingerprint` 开启**）                                  | 合法 → 普通 200；CRC 不符 → `400`（`--fingerprint-action drop` 时静默丢弃并计数）；**不在末位 → 一律 `400`**。默认关闭：不开开关时 `FINGERPRINT` 照旧被忽略，字节与 `26.410.100` 一致 |
| **任意** `Binding Request`（配置了 `--alternate-server <ip:port>`）                                  | `300 Try Alternate` + `ALTERNATE-SERVER`（`0x8023`，明文地址布局），从收到请求的 socket 回；**重定向优先于 RFC 5780**（带 `CHANGE-REQUEST`/`RESPONSE-PORT` 也回 300）；非 Binding 方法仍是 400 |
| 内部失败（`send_to` 失败，且错误不属于客户端地址问题）                                              | `500 Server Error`（固定文案、固定 **40 字节**），`io::Error` 细节只进日志                                                                                                                  |
| indication / response                                                                               | 静默丢弃（服务端不是客户端）                                                                                                                                                                |
| 畸形包（短于头部、magic cookie 错、长度不对齐、属性越界）                                            | 丢弃并计数，**不 panic、不打挂监听**                                                                                                                                                        |

- UDP 与 TCP 都是同一套编解码；TCP 按 RFC 5389 §7.2.2 用头部长度分帧，单连接可流水多条请求。
- **TCP 上 `CHANGE-REQUEST` 与 `RESPONSE-PORT` 都被忽略**（回包只能沿原连接返回），但 `RESPONSE-ORIGIN` /
  `OTHER-ADDRESS` 仍照常带上 —— 因此 `--tcp` 与 `--alt-listen` 可以同时开（TCP 只在两个 IP 的
  主端口上监听）。`PADDING` 在 TCP 上照常回声。
- IPv6 监听地址以 **v6-only** 绑定，可与 `--listen 0.0.0.0:3478` 并存（不会抢占端口）。
- **向后兼容**：不给 `--alt-listen` / `--mapped-address`，且请求不带 `PADDING` 时，响应字节被
  `protocol::tests::plain_response_bytes_are_frozen`（48 字节逐字节断言）冻结，升级不会悄悄改变
  客户端看到的内容。
- **抗滥用默认关闭**：不给 `--rate-limit` 族参数时不建表、不起后台任务、不改任何字节；
  开启后超限请求在 `decide()` **之前**被丢弃（UDP）或关连接（TCP），协议语义不变。
  参数、默认值推导与 NAT 误伤排查见「[抗滥用](rate-limit.md)」。
- 退出：Ctrl-C 与 Unix `SIGTERM`（systemd / `docker stop` 都走 SIGTERM）。SIGTERM 先**优雅
  drain**（停收新包 → 等在途，上限 `--drain-timeout`，默认 5s），再打印
  `received / answered / dropped` 统计并退出 0；开了抗滥用时前面还有一行
  `abuse guard counters`。第二个 SIGTERM 立即退出。详见「[运维面](https://github.com/exvlan/rstun/blob/main/README.md#运维面readiness--metrics--env--优雅退出--部署清单)」。
- 日志只走 stdout/stderr（`tracing`）：`RUST_LOG` 优先，否则 `--verbose` → `debug`，
  默认 `info`。**不写滚动文件**（容器/systemd 自己采集）。

## RFC 支持子集

| RFC | 覆盖 | 说明 |
| --- | --- | --- |
| **RFC 5389** | 服务端全行为 | Binding、`XOR-MAPPED-ADDRESS`、`SOFTWARE`、`MAPPED-ADDRESS`（可选）、`ERROR-CODE`（300/400/401/420/438/500）、`UNKNOWN-ATTRIBUTES`、`FINGERPRINT`（`--check-fingerprint` 校验）、`ALTERNATE-SERVER`（`--alternate-server`）、**鉴权 §10**（短期 / 长期凭据，`--auth-user` / `--realm`，默认关闭） |
| **RFC 5780** | 全量 | `CHANGE-REQUEST` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `RESPONSE-PORT` / `PADDING`（四条 change 路径，见 [RFC 5780](nat-discovery.md)） |
| **RFC 8489** | 鉴权扩展 | `MESSAGE-INTEGRITY-SHA256` / `PASSWORD-ALGORITHM(S)` 协商 / `USERHASH`（§14.4，32 字节，无 `USERNAME` 的长凭证）；`PASSWORD-ALGORITHM` 缺省按 MD5 派生（coturn 兼容）。**未实现** nonce cookie / security-feature 位（见「未实现（有意）」） |
| **RFC 8445（ICE）** | 属性容忍 | `PRIORITY` / `USE-CANDIDATE` / `ICE-CONTROLLING` / `ICE-CONTROLLED` 不触发 420；**开鉴权后**无凭据的 ICE 探测会收到 401（见「鉴权」） |

## 错误码矩阵

| 码 | 触发 | 备注 |
| --- | --- | --- |
| `300` | 配置了 `--alternate-server`（每个 Binding 请求） | 带 `ALTERNATE-SERVER`；**不带** `XOR-MAPPED-ADDRESS`；优先于鉴权、RFC 5780 与 420 |
| `400` | 非 Binding 方法；`PADDING` + `RESPONSE-PORT`；`FINGERPRINT` 不在末位 / 值不匹配（默认）；**凭据请求缺必需属性**（短期：`USERNAME`/`MESSAGE-INTEGRITY`；长期：`REALM`/`NONCE`/`USERNAME` 与 `USERHASH` 两者皆缺） | 不带 `UNKNOWN-ATTRIBUTES`；**只表示"消息不完整"**，值错一律 401 |
| `401` | 配置了凭据但请求未通过鉴权（无 `MESSAGE-INTEGRITY`、错口令、未知用户、`USERHASH` 长度≠32、realm 不符、nonce 不是本服务签发的、`--auth-require-sha256` 下用了 MD5） | 长期凭据时带 `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`；短期凭据只有 `ERROR-CODE` |
| `420` | 请求带未知 comprehension-required 属性 | 带 `2N` 字节的 `UNKNOWN-ATTRIBUTES`；**在鉴权之后**（未认证客户端探测不到这张表）；已认证请求的 420 **带 MI** |
| `438` | nonce 是本服务签发的但已过期（`--nonce-lifetime`） | 带新 `NONCE` + `REALM` + `PASSWORD-ALGORITHMS`（RFC 8489 §9.2.4 对 401/438 同样要求） |
| `500` | 响应编码不变量被破坏、`send_to` 失败、内部不可恢复错误 | 固定文案 `Server Error`，固定 **40 字节**，不泄露 `io::Error`；**不签名**（在 `decide` 之下、identity 已不可得，已登记） |

`--check-fingerprint` / `--alternate-server` 两个开关**默认关闭**：不给它们时，任何请求的响应字节与
`26.410.100` 完全一致（`plain_response_bytes_are_frozen` 与 68 组「旧二进制 vs 新二进制」逐字节对照：
17 个请求 × 默认 / `--mapped-address` / `--alt-listen` / `--check-fingerprint`）。

## 420 与「已知属性」表

RFC 5389 §7.3.1 要求：请求里出现**服务端没实现的 comprehension-required 属性**（类型 `< 0x8000`）时，
必须回 `420` 而不是硬着头皮应答。实现里这张「已知属性」表（`protocol::is_known_attribute`）是**判定的唯一依据**，
除了自己实现的属性，还显式收录了两类「理解但不用」的属性：

| 类别           | 属性                                                                                                                                                                           | 为什么不能算未知                                               |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| 鉴权（默认关） | `USERNAME` `0x0006`、`MESSAGE-INTEGRITY` `0x0008`、`MESSAGE-INTEGRITY-SHA256` `0x001C`、`REALM` `0x0014`、`NONCE` `0x0015`、`PASSWORD-ALGORITHM` `0x001D`、`USERHASH` `0x001E` | RFC 5389 §10.2.2 允许客户端主动带；不开鉴权时必须忽略而不是 420 |
| ICE 连通性检查 | `PRIORITY` `0x0024`、`USE-CANDIDATE` `0x0025`、`ICE-CONTROLLED` `0x8029`、`ICE-CONTROLLING` `0x802A`                                                                           | ICE 的 Binding 请求**标配**这些属性；回 420 等于打死打洞       |

把它们当作未知，会把正常客户端打成 420 —— 这比「少一条合规检查」危险得多。反过来，真的没实现的
（比如 `0x0033`）必须回 420，客户端才知道该换实现。

`UNKNOWN-ATTRIBUTES` 的值长度**恰为 `2×N`**，不足 4 字节的尾项由通用 TLV padding 补齐
（padding 不计入 Length，**不重复末项** —— RFC 5389 §15.9 没有 RFC 3489 的那条规则）。

## 兼容性开关：`--mapped-address`

`MAPPED-ADDRESS`（`0x0001`）是 `XOR-MAPPED-ADDRESS` 之前的旧形式（RFC 3489），只有很老的客户端读它。
**默认关闭**：开启会让每个响应多 12 字节，对现代客户端毫无意义。开启后属性顺序为
`XOR-MAPPED-ADDRESS` → `MAPPED-ADDRESS` → （RFC 5780 两个）→ `SOFTWARE` → （`PADDING`）。

## 协议闭环：`--check-fingerprint` / `--alternate-server`

两个开关都**默认关闭**；关闭时既不二次解析、也不改任何字节（68 组「旧二进制 vs 新二进制」逐字节
对照覆盖 17 个请求 × 默认 / `--mapped-address` / `--alt-listen` / `--check-fingerprint`：普通 Binding、
SOFTWARE、FINGERPRINT、ICE 簇、鉴权簇、420、`PADDING`、`RESPONSE-PORT`、`CHANGE-REQUEST`、
非 Binding 方法）。

**`--check-fingerprint`**（RFC 5389 §15.5）

- 只校验**请求**（indication / response 本来就不回）。`FINGERPRINT` 必须**是最后一个属性**、值恰好
  4 字节，且等于 `CRC32(消息中该属性之前的字节) XOR 0x5354554e`。
  CRC 的覆盖范围**包含**「Length 已计入 FINGERPRINT」的头部——这是 §15.5 的原意
  （"this value must be correct and include the CRC attribute as part of the message length"），
  与 RFC 5769 §2.1–§2.3 的标准字节一致。
- 不匹配 → `400`；`--fingerprint-action drop` 时静默丢弃并计入 `fingerprint_rejected`（同时 +1 `dropped`）。
- **结构错误**（`FINGERPRINT` 后面还有属性、或值不是 4 字节）永远 `400`：客户端连消息边界都算错了，
  静默丢弃只会让它以为路径不通。
- TCP 上同样校验；drop 模式下该帧不回包，连接保持（后续帧照常处理）。

**`--alternate-server <ip:port>`**（RFC 5389 §15.11）

- 可重复，**只取第一个**（其余在启动日志里告警）。配置后**所有** Binding 请求都得到
  `300 Try Alternate` + `ALTERNATE-SERVER`；`CHANGE-REQUEST` / `RESPONSE-PORT` **被忽略**（重定向优先），
  回包始终从收到请求的 socket 发往请求源。
- 响应大小：IPv4 **56 字节**（20 头 + 24 `ERROR-CODE` + 12 地址），IPv6 68 字节。
  它**不受**反射防护的比例规则约束：那条规则只管带 `RESPONSE-PORT` / `CHANGE-REQUEST` 的请求，
  而配置了 `--alternate-server` 时防护**估算的就是这个 300**（不会拿一个永远不发的成功响应去估）。
  但 20 字节普通 Binding → 56 字节 = 2.80×，与其它「非重定向应答」属同一类已知放大面，
  靠每源 IP 令牌桶兜底（见「反射防护」的边界与已知项）。

**`500 Server Error`**（RFC 5389 §15.6）

- 只在「请求已解析、原本要回包，但发送/编码失败」时出现：`server_error_for` 对
  `ConnectionRefused` / `NetworkUnreachable` / `AddrNotAvailable` **不映射**（那是客户端地址问题，
  回 500 既不准也没用），其余错误映射为 500。
- 固定 `Server Error` 文案、固定 **40 字节**（20 头 + 20 `ERROR-CODE`）；`io::Error` 只进 `warn` 日志。
  `RESPONSE-PORT 0` 触发 500 时最大 `40/28 ≈ 1.43×`，仍低于既有普通 Binding `2.60×` 基线。
- 发送 500 本身失败时只记 `debug`，不会重试成环。
- UDP 的 `send_to` 失败会回 500；TCP 上「写失败」意味着连接已不可用（没有可回包的信道），
  只有**编码不变量**失败才会在同一条连接上回 500。

## 未实现（有意）

TURN 侧能做的都已经做了（UDP/TCP/`turns:`/DTLS 中继、REST 临时凭据、带宽配额，见
「[TURN](turn.md)」）。真正缺的是下面这几项，且都是**刻意**不做：

- **TCP allocation（RFC 6062）**：**出站**部分已实现（`--turn-tcp-relay`：`Allocate(TCP)` +
  `Connect` + `ConnectionBind`，见「[TURN](turn.md)」）；**被动模式**（`ConnectionAttempt`，
  peer 主动连入 relay）仍未实现，`turnutils_uclient -T` 因此不能作为验收判据。
- **ACME / OCSP stapling**：签发与续期交给宿主的 certbot/acme.sh 等工具；本进程不做 ACME。
  证书本身可热加载：原地覆盖 `--tls-cert`/`--tls-key` 后 `kill -HUP`（unix）或等文件轮询
  （默认 30s，`--tls-cert-poll` 可调、`0` = 只认 `SIGHUP`），无需重启
  （详见「[TURN](turn.md)」的部署注意）。
- **多实例共享 allocation**：状态只在进程内存里（重启清零）。多实例部署靠 LB 源地址亲和；
  `--auth-secret` 与 `--rest-secret` 可以共享（nonce 与 REST 凭据都是无状态的），
  但 allocation 表不共享。
- 鉴权的**服务端状态**部分：没有用户数据库、没有按 realm 路由、没有 nonce 黑名单
  （nonce 无状态，靠 HMAC + 过期时间；要吊销就换 `--auth-secret`）。
- **nonce 的绑定范围**：只有 `HMAC(secret, expiry|client_ip)`，**不绑源端口**、不含
  nonce cookie，也不实现 RFC 8489 §9.2.3 的 `NONCE`/`SECURITY-FEATURE` 位
  （`0x80`/`0x40`）。影响：同一 NAT 出口后的两台客户端在同一 IP 上可互换 nonce；
  没有防重放的一次性 nonce（靠短 `--nonce-lifetime` 缩小窗口）。跨实例互认只需要
  共享 `--auth-secret`。
- 不实现 SASLprep：`--auth-pass` / `--auth-file` 里的口令按原样使用（ASCII 部署足够；
  非 ASCII 口令请先自行 SASLprep）。`--auth-file` **只去掉行尾 `CR/LF`**，口令里的
  首尾空格是数据、不会被 trim。
- 鉴权开启时 `500 Server Error` **不签名**：它在 `decide` 之下的编码/发送失败路径上产生，
  那里拿不到本次请求的 identity；客户端应按「内部错误」处理而不是验签。
- `FINGERPRINT` 默认**不校验**（保持字节兼容），需要显式 `--check-fingerprint`。
- `ALTERNATE-SERVER` 只接受 `ip:port` 形式，且只用一个目标（RFC 也允许 domain 形式）。
- `RESPONSE-PORT` 在 **TCP** 上忽略（回包只能沿原连接返回；§5 的这套机制只定义在 UDP 上）。
