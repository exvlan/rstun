# rstun

独立 STUN/TURN 服务器：RFC 5389 Binding，加可选的 RFC 5780 NAT 行为发现，以及
可选的 RFC 8656 UDP 中继（`--turn`，强制长期凭据）。
一个 crate、一个二进制、一个镜像，`cargo install` 就能跑，不依赖任何宿主项目。

**范围声明（先读）**：本服务只做**小规模、静态用户**的 STUN/TURN —— RFC 5389 Binding
（+ 可选的 RFC 5780 NAT 行为发现）+ **可选的**鉴权（RFC 5389 §10 短期/长期凭据 +
RFC 8489 §9.2 的 SHA256/USERHASH，**默认关闭**）+ **可选的 RFC 8656 UDP 中继**
（`--turn`，**默认关闭、缺长期凭据拒绝启动**）。TURN 的 T2 范围（TLS/DTLS、REST 临时凭据、
带宽配额、TCP allocation/RFC 6062）**不做**；需要这些能力时请用 coturn。没有租户、
配置文件或数据库。

**命名**：crate 与二进制都叫 `rstun`。**绝对不能改叫 `stun`** —— Debian 的 `stun-client`
包已经占用 `/usr/bin/stun`，同名会直接撞包/覆盖。

**许可**：整仓 **MPL-2.0**（`LICENSE`），边界见文末 [License](#license)。

CLI 分两级：`rstun server [flags]` 起服务（flag 语义自首个版本起未变），裸 `rstun` 打印帮助。

```
$ rstun --help
Standalone STUN/TURN server (RFC 5389 Binding; RFC 5780 with --alt-listen; RFC 8656 UDP relay with --turn)

Usage: rstun <COMMAND>

Commands:
  server  Serve STUN Binding over UDP (and TCP with --tcp); TURN UDP relay with --turn
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

$ rstun server --help
Serve STUN Binding over UDP (and TCP with --tcp); TURN UDP relay with --turn

Usage: rstun server [OPTIONS]

Options:
      --listen <ADDR>
          address to bind over UDP (and TCP with --tcp), repeatable; defaults to 0.0.0.0:3478. With
          --alt-listen the first IPv4 address here is the RFC 5780 primary; every other address (and
          all --listen-v6) only serves plain Binding

      --listen-v6 <ADDR>
          IPv6 address to bind, repeatable; bound v6-only so it can coexist with --listen. Never
          part of RFC 5780: these sockets only serve plain Binding

      --alt-listen <ADDR>
          second public IP (RFC 5780 "other address"); enables CHANGE-REQUEST, RESPONSE-ORIGIN and
          OTHER-ADDRESS. Only the IP is used: the port comes from --alt-port. Primary = the first
          IPv4 --listen address; other addresses (including --listen-v6) stay plain Binding

      --alt-port <PORT>
          RFC 5780 "other port"; defaults to the --listen port + 1. Used as the source port of a
          `CHANGE-REQUEST` answer and as half of `OTHER-ADDRESS`. (`RESPONSE-PORT` names a
          *destination* port and never refers to this.)

      --tcp
          also answer STUN Binding over TCP on every listen address

      --mapped-address
          also emit the legacy MAPPED-ADDRESS (0x0001) next to XOR-MAPPED-ADDRESS, for RFC 3489-era
          clients; off by default (response bytes stay unchanged)

      --check-fingerprint
          validate FINGERPRINT (RFC 5389 §15.5) when a request carries one: it must be the last
          attribute and its CRC must match. Off by default, so a request without FINGERPRINT is
          answered exactly as before

      --fingerprint-action <ACTION>
          what a FINGERPRINT with a wrong CRC gets: `answer` = 400 Bad Request (the default), `drop`
          = no response. `drop` needs --check-fingerprint

          Possible values:
          - answer: `400 Bad Request` (RFC 5389 §15.5 makes a bad fingerprint a bad message)
          - drop:   No response at all — for deployments that do not want to answer probes with a
            broken fingerprint (still counted, see `ServerStats`)

          [default: answer]

      --alternate-server <ADDR>
          answer every Binding request with `300 Try Alternate` + ALTERNATE-SERVER (RFC 5389
          §15.11), pointing at this instance; repeatable, only the first address is used. Redirect
          wins over RFC 5780

      --verbose
          log every Binding request with its source and mapped address

      --rate-limit [<REQ/S>]
          per-source-IP token bucket (req/s), UDP and TCP; bare flag = 200. Sources named by --allow
          skip this bucket; off by default

      --rate-burst <N>
          burst size of the --rate-limit bucket; defaults to 2x its rate

      --rate-limit-port [<REQ/S>]
          per source IP+port token bucket (req/s); bare flag = 20

      --global-rate <REQ/S>
          server-wide token bucket (req/s): the last line before the sockets

      --max-inflight <N>
          cap on work held at once: one slot per UDP datagram (until answered) and per TCP
          connection (until closed). Over the cap, datagrams are dropped and connections refused

      --reflect-min-request <BYTES>
          refuse RESPONSE-PORT / CHANGE-REQUEST requests shorter than BYTES (default 20 = the STUN
          header; a 28-byte RFC 5780 probe must pass). Raising it trades RFC 5780 compatibility for
          a stricter floor

      --reflect-ratio <RATIO>
          refuse RESPONSE-PORT / CHANGE-REQUEST requests whose answer would exceed `max(request x
          RATIO, request + 32)` (default 2.0; the 32 bytes are the fixed XOR + RFC 5780 address
          attributes, SOFTWARE is omitted for small probes). Enables the guard

      --allow <CIDR>
          CIDR whose sources bypass the per-source rate limits and the reflection guard, repeatable

      --deny <CIDR>
          CIDR whose sources are refused outright, repeatable; wins ties with --allow

      --auth-user <USER>
          short-term credential user name (RFC 5389 §10.1); needs --auth-pass. Short-term only
          applies without --realm: the key is the password itself

      --auth-pass <PASS>
          password of --auth-user (short-term) or of the single long-term user

      --auth-file <PATH>
          file with one `user:password` per line ('#' comments and blank lines ignored); repeatable
          users for long-term, or several short-term users

      --realm <REALM>
          long-term credential realm (RFC 5389 §10.2); turns on the 401/438 flow. Needs
          --auth-secret and at least one user

      --auth-secret <SECRET>
          secret that signs the stateless NONCE (any string; the same value on every instance makes
          nonces interchangeable). Required with --realm

      --nonce-lifetime <SECONDS>
          NONCE lifetime in seconds (default 3600); only meaningful with --realm

      --auth-require-sha256
          long-term only: refuse PASSWORD-ALGORITHM=MD5 (401 unless the client uses SHA256). Needs
          --realm

      --turn
          enable the TURN (RFC 8656) UDP relay on the STUN sockets. Requires long-term credentials:
          --realm, --auth-secret and at least one user

      --relay-ports <LO-HI>
          TURN relay port range, inclusive (default 49152-65535). Choose a range outside
          net.ipv4.ip_local_port_range

      --max-allocations-per-user <N>
          cap on concurrent TURN allocations per authenticated user (default 8)

      --max-allocations-per-ip <N>
          cap on concurrent TURN allocations per client IP (default 16)

      --permission-limit <N>
          cap on TURN permissions per allocation (default 10)

      --allocation-lifetime <SECONDS>
          TURN allocation lifetime in seconds (default 600, max 3600). Also caps whatever LIFETIME a
          client asks for

  -h, --help
          Print help (see a summary with '-h')
```

- 裸 `rstun`（无子命令）**打印帮助并以退出码 2 结束**：不给参数属于用法错误，
  不能悄悄起一个 `0.0.0.0:3478` 通配监听。
- `rstun --version` 打印 `rstun <version>`（版本串规则见下文「构建与运行」与 `RSTUN_BUILD_VERSION`）。
  `--version` 只在**二进制级**：`rstun server --version` 会报错（子命令不自带版本号，
  避免出现两个版本串；CI 与镜像自检一律用 `rstun --version`）。

## 行为

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
| 其它 method 的 **request**（如 TURN `Allocate` `0x003`，且**未开** `--turn`）                                         | 该 method **自己的** `4xx` 错误响应 + `ERROR-CODE 400 Bad Request`（RFC 5389 §7.3.1）。开 `--turn` 时 TURN 方法由 TURN 状态机处理（见「[TURN](#turnudp-中继turn)」）                            |
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
  参数、默认值推导与 NAT 误伤排查见「[抗滥用](#抗滥用限速--并发--反射防护)」。
- 退出：Ctrl-C 与 Unix `SIGTERM`（systemd / `docker stop` 都走 SIGTERM）。SIGTERM 先**优雅
  drain**（停收新包 → 等在途，上限 `--drain-timeout`，默认 5s），再打印
  `received / answered / dropped` 统计并退出 0；开了抗滥用时前面还有一行
  `abuse guard counters`。第二个 SIGTERM 立即退出。详见「[运维面](#运维面readiness--metrics--env--优雅退出--部署清单)」。
- 日志只走 stdout/stderr（`tracing`）：`RUST_LOG` 优先，否则 `--verbose` → `debug`，
  默认 `info`。**不写滚动文件**（容器/systemd 自己采集）。

### RFC 支持子集

| RFC | 覆盖 | 说明 |
| --- | --- | --- |
| **RFC 5389** | 服务端全行为 | Binding、`XOR-MAPPED-ADDRESS`、`SOFTWARE`、`MAPPED-ADDRESS`（可选）、`ERROR-CODE`（300/400/401/420/438/500）、`UNKNOWN-ATTRIBUTES`、`FINGERPRINT`（`--check-fingerprint` 校验）、`ALTERNATE-SERVER`（`--alternate-server`）、**鉴权 §10**（短期 / 长期凭据，`--auth-user` / `--realm`，默认关闭） |
| **RFC 5780** | 全量 | `CHANGE-REQUEST` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `RESPONSE-PORT` / `PADDING`（四条 change 路径，见下文） |
| **RFC 8489** | 鉴权扩展 | `MESSAGE-INTEGRITY-SHA256` / `PASSWORD-ALGORITHM(S)` 协商 / `USERHASH`（§14.4，32 字节，无 `USERNAME` 的长凭证）；`PASSWORD-ALGORITHM` 缺省按 MD5 派生（coturn 兼容）。**未实现** nonce cookie / security-feature 位（见「未实现（有意）」） |
| **RFC 8445（ICE）** | 属性容忍 | `PRIORITY` / `USE-CANDIDATE` / `ICE-CONTROLLING` / `ICE-CONTROLLED` 不触发 420；**开鉴权后**无凭据的 ICE 探测会收到 401（见「鉴权」） |

### 错误码矩阵

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

### 420 与「已知属性」表

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

### 兼容性开关：`--mapped-address`

`MAPPED-ADDRESS`（`0x0001`）是 `XOR-MAPPED-ADDRESS` 之前的旧形式（RFC 3489），只有很老的客户端读它。
**默认关闭**：开启会让每个响应多 12 字节，对现代客户端毫无意义。开启后属性顺序为
`XOR-MAPPED-ADDRESS` → `MAPPED-ADDRESS` → （RFC 5780 两个）→ `SOFTWARE` → （`PADDING`）。

### 协议闭环：`--check-fingerprint` / `--alternate-server`

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

### 鉴权：`--auth-user` / `--realm`（RFC 5389 §10 + RFC 8489 §9.2）

**默认完全关闭**：不配凭据时 `MESSAGE-INTEGRITY` 等属性照旧被忽略，响应字节与 `26.410.100`
逐字节一致（`plain_response_bytes_are_frozen` + 17 请求 × 3 配置的「旧二进制 vs 新二进制」对照）。
一旦配置凭据，**只有 Binding 请求**受保护（indication 仍忽略，非 Binding 方法仍 400）。

**短期凭据**（RFC 5389 §10.1，`--auth-user` + `--auth-pass`）

- key **就是口令**（§15.4），只校验 `MESSAGE-INTEGRITY`（HMAC-SHA1）。
- 缺 `USERNAME` 或 `MESSAGE-INTEGRITY`（§10.1.2 要求两者同时存在）→ **400 Bad Request**；
  未知用户 / 口令不符 → **401**（短期没有 realm/nonce 可提供）。
- `--auth-file` 也可用：一行一个 `user:password`，即多用户短期凭据。
  口令走命令行会在 `ps` 里可见，生产环境请用 `--auth-file`（`chmod 600`）。

**长期凭据**（RFC 5389 §10.2 + RFC 8489 §9.2，`--realm` + `--auth-secret`）

```
客户端                                rstun
  ── Binding（无凭据） ──▶            401 + REALM + NONCE + PASSWORD-ALGORITHMS
  ── USERNAME/REALM/NONCE + MI ──▶    200（响应同样带 MESSAGE-INTEGRITY）
  ── 同一条但 nonce 过期 ──▶          438 + 新 NONCE + REALM + PASSWORD-ALGORITHMS
```

- **缺失 ≠ 无效**：长凭据请求缺 `REALM` / `NONCE` / 身份属性（`USERNAME` 与 `USERHASH`
  都没有）→ **400**；属性齐全但值不对（realm 不符、用户不存在、`USERHASH` 不是 32 字节、
  MAC 不匹配）→ **401**。

- key 派生：`MD5(username:realm:password)`（`MESSAGE-INTEGRITY`）或
  `SHA256(username:realm:password)`（`MESSAGE-INTEGRITY-SHA256`）。口令本身**从不直接比较**
  —— 比的是 MAC，且用自写的**常量时间** `auth::ct_eq`（不引入 `subtle` 依赖）；
  `USERNAME` 与 `USERHASH` 的比对同样走它（避免用户名存在性时序探测）。
- `PASSWORD-ALGORITHM`（§14.12）缺省按 **MD5**（与 coturn 一致）；`PASSWORD-ALGORITHMS`
  （§14.11）在 401 里列出可接受集合。`--auth-require-sha256` 时只列 SHA256，
  用 MD5 的客户端回 401。
- `USERHASH`（§14.4）可替代 `USERNAME`，此时请求里**没有**明文用户名。值必须是**完整**的
  `SHA256(username:realm)`（**32 字节**）；16 字节的截断值不是 `USERHASH`，按值无效回 401。
- **nonce 无状态**：`base64url( expiry(5B) | HMAC-SHA256(secret, expiry|client_ip)[..11] )`
  （22 个字符）。校验只重算 HMAC 与过期时间，**没有服务端表**：同一 `--auth-secret` 的多个
  实例/重启后的进程都能互认对方的 nonce。有效期 `--nonce-lifetime`（默认 3600 秒）。
- **过期判定是严格的**（`now >= expiry` 即过期）：设计稿里的「±5 分钟时钟偏差容忍」没有
  实现成宽限期 —— 那会把每个配置的有效期都拉长 5 分钟（`--nonce-lifetime 1` 就不再是 1 秒）。
  需要容忍时钟偏差时把 `--nonce-lifetime` 调大即可。
- 判定顺序（最终实现）：**限速/反射防护（准入）→ FINGERPRINT → 300 → 鉴权 → 420 → 400 组合
  → 正常应答**。`300` 先于鉴权（重定向不需要认证），FINGERPRINT 先于鉴权（先证消息完整、
  再证凭据）；`401`/`438` 本身也先过了限速桶，所以 401 洪水不会绕过准入。

**放大面（必须配合限速）**

| 响应 | 字节（realm=`example.org`） | 对 20B 请求 | 对 28B 请求 |
| --- | --- | --- | --- |
| `401`（`ERROR-CODE` + `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`） | **96**（realm 每多 4 字节 +4） | 4.80× | 3.43× |
| `438`（`ERROR-CODE` + `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`） | **96** | 4.80× | 3.43× |
| `200` 成功（含 `MESSAGE-INTEGRITY`） | **76** | 3.80× | 2.71× |
| `200` 成功（含 `MESSAGE-INTEGRITY-SHA256`） | **88** | 4.40× | 3.14× |

结论：**开鉴权必须同时开限速**（`--rate-limit` 至少覆盖每源 IP，`--reflect-ratio` 覆盖重定向
探针）。启动时若配了凭据却没开任何抗滥用开关，会打一条 `warn` 明说这一点。

`401` / `438` 只回**请求源**、不响应 `RESPONSE-PORT`，因此不能被引到任意第三方端口（不构成
反射）；回包量仍受每源令牌桶约束。反射防护的比例规则只管带重定向属性的**成功**应答；开启鉴权
时它的估算取「签名后的成功响应」与「401 挑战」的**较大者**（未认证请求实发 96B 的 401，
不能按 76B 的成功响应去估）。这两类响应的放大面与 `300` 的已知放大面同属一类，
`docs/interop-matrix.md` 与本节都登记了实测字节数。

**对既有能力的影响**

- **ICE**：开鉴权后，无凭据的 ICE 连通性检查会收到 401（与 coturn 一致）。需要匿名 ICE 时
  不要开鉴权 —— 这也是它默认关闭的原因。
- **RFC 5780**：`CHANGE-REQUEST` / `RESPONSE-PORT` 与鉴权正交，带凭据即可正常使用；
  反射防护先于鉴权，所以小于门槛的重定向探针仍可能先被 400/静默丢弃。
- **`--alternate-server`**：300 先于鉴权，配置了重定向的实例不需要凭据。



### 未实现（有意）

- TURN 的 **T2 范围**：TLS/DTLS 监听、REST 临时凭据、带宽配额、TCP allocation（RFC 6062）。
  T1 已实现 UDP 中继（见「[TURN](#turnudp-中继turn)」）：`Allocate`/`Refresh`/
  `CreatePermission`/`ChannelBind`/`ChannelData`，强制长期凭据，默认关闭。
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

## RFC 5780（NAT 行为发现）

RFC 5780 让客户端判断自己处于**哪种 NAT**（映射行为 / 过滤行为），是 P2P 打洞策略的输入。
它需要服务器在**两个公网 IP × 两个端口 = 四个传输地址**上应答：

```
  ip1:port1   ← 客户端从这里开始（DNS / 发现链路里公布的那一个）
  ip1:port2   ┐
  ip2:port1   ├ CHANGE-REQUEST 会把响应改成从这三个之一发出
  ip2:port2   ┘（change-port / change-ip / 两者同时）
```

启用方式（示例用 RFC 5737 的 TEST-NET 地址，替换成你自己的两个公网 IP）：

```bash
rstun server \
  --listen 203.0.113.10:3478 \
  --alt-listen 198.51.100.20:3478 \
  --alt-port 3479
```

- **primary = 命令行顺序里第一个 IPv4 `--listen`**。它必须**写具体 IP**：`0.0.0.0` 与
  `--alt-listen` 同时出现会**直接报错退出**（不静默降级），因为「一个地址一个 socket」
  正是为了知道「这个包是发到哪个 IP 的」。
- `--alt-listen` 是第二个公网 IP（RFC 5780 的 "other address"）；**只取其中的 IP**，
  端口由 `--alt-port` 决定（默认 `--listen` 端口 + 1）。
- 两个 IP 必须同族（v4/v4 或 v6/v6）、互不相同；两个端口必须不同。校验失败一律启动即退出。
- **多地址共存**：`--listen` 可重复，`--listen-v6` 可重复；除 primary 与 alt 之外的所有地址
  （其余 v4 `--listen` + 全部 `--listen-v6`）**只做普通 Binding** —— 不带
  `RESPONSE-ORIGIN` / `OTHER-ADDRESS`，收到 `CHANGE-REQUEST` 也按 RFC 5780 §5 忽略
  （仍从原 socket 回包）。`--alt-listen` 存在时**必须至少有一个 IPv4 `--listen`**：
  `--listen-v6` 不计入 primary 选择（`change-ip` 是 v4 语义）。

> **为什么 wildcard 必须拒绝（不是「实现限制」而是「必然错答」）**：绑 `0.0.0.0` 时本机所有
> 地址共用一个 socket，回包源地址由内核按默认路由 / 策略路由**替我们挑**（通常是主 IP）。
> 客户端把请求发到第二个地址，回包却从第一个发出 —— 客户端侧 NAT / 防火墙按「请求的目标
> 地址」记账，会直接丢掉这个来自别的地址的回包。而 RFC 5780 的判据**正是回包源地址**，
> 所以这不是精度问题，而是**每个 change/advertise 路径都会给出错误结论**。一个地址一个
> socket，`send_to` 的源地址才等于「请求到达的那个地址」，也才谈得上 `RESPONSE-ORIGIN`
> 与 `OTHER-ADDRESS` 的语义。
>
> `RESPONSE-ORIGIN` 的值**故意保持**「发响应那个 socket 的本地地址」：云主机上 EIP 是
> 1:1 NAT，客户端拿到的回包源会被映射成公网地址；把属性改成公网地址反而会让
> 「属性值 ≠ 实际回包源」，破坏客户端用真实源地址做的校验。

常见形态是「两个 v4 入口 + 一个 v6 入口，只在其中一个上开 5780」：

```bash
rstun server \
  --listen 10.0.0.5:3478 --listen 10.0.0.8:3478 \
  --alt-listen 10.0.0.7:3478 --alt-port 3479 \
  --tcp --listen-v6 [::]:3478
# 10.0.0.5:3478（primary）与 10.0.0.7:* 四 socket 参与 5780；
# 10.0.0.8:3478 与 [::]:3478 只做普通 Binding。
```

### 实现要点：四个 socket，不要 `IP_PKTINFO`

常见做法是绑一个 `0.0.0.0` 的通配 socket，再用 `IP_PKTINFO` / `IPV6_RECVPKTINFO` 取出每个
datagram 的**目的地址**。那是平台相关代码（Linux/Windows/BSD 各一套，Rust 标准库不给）。

本服务反过来：**每个地址各绑一个 socket**（`ip1:p1`、`ip1:p2`、`ip2:p1`、`ip2:p2`），于是

| 问题                       | 答案                                                                          |
| -------------------------- | ----------------------------------------------------------------------------- |
| 这个包发到哪个 IP / 端口？ | 处理它的那个 socket 的 `local_addr()`                                         |
| 回包要从哪儿发出？         | 在**目标地址对应的那个 socket** 上 `send_to`（源地址就是它）                  |
| `RESPONSE-ORIGIN` 填什么？ | 应答 socket 的本地地址                                                        |
| `OTHER-ADDRESS` 填什么？   | 相对该 socket「换 IP + 换端口」的那一个（对称，从四个中的任一个进来都有意义） |

`CHANGE-REQUEST`（0x0003，4 字节：`0x04` 换 IP、`0x02` 换端口，可同时置位；未知位与保留位
忽略）只改**选哪个 socket 回包**，不改报文内容 —— 所以 `XOR-MAPPED-ADDRESS` 仍是客户端地址，
客户端用「回包源地址」就能验证。

`RESPONSE-PORT`（0x0027，2 字节端口 + 2 字节填充）按 §7.5 / §6 原文实现：响应**发往**
「请求的源 IP + `RESPONSE-PORT` 给的端口」—— 它只改**目的端口**，**源地址与源端口不变**，
仍从收到请求的那个 socket 发出，`RESPONSE-ORIGIN` 也仍然是它。因此该端口**不需要**是本进程
绑定的端口：§7.5 的 "Allowable values of RESPONSE-PORT are 0-65536" 就是说「任意端口都算合法
目的端口」，`0` 或没人监听的端口交给内核报 `send_to failed`，记一条 `warn` 后继续服务
（**不 panic、不回 400**）。
与 `CHANGE-REQUEST` **正交**：两者同时出现时，前者改**源** socket、后者改**目的**端口。

`PADDING`（0x0026）是**长度即语义**的填充串：请求带 N 字节，响应就回 N 字节（不超过 N，
且受 16 位 Message Length 上限约束），用来让一个 STUN 报文跨过路径 MTU、观察分片行为。
它不属于「地址发现」那部分，所以**不需要** `--alt-listen`。与 `RESPONSE-PORT` 同时出现时
按 §6（"the server MUST return an error response of type 400"）回 **`400 Bad Request`**；
§7.5 的 "MUST NOT process" 与 §10 的 "are rejected" 说的是同一件事，我们选最可见的那种拒绝
（静默丢弃会被客户端读成「链路被过滤」）。UDP 读缓冲是 **64 KiB**（最大 UDP 载荷），所以
1500 MTU 与 9000 jumbo 帧的探测都能被解析并原样回声 —— 缓冲更小会把要测的那些报文直接截断丢掉。

> **有意偏离：响应 `PADDING` 的长度**。RFC 5780 §6 对响应侧的 `PADDING` 用 SHOULD：
> 长度取「出接口 MTU 向上取整到 4 的倍数」（不足则补齐）。本服务**回显请求里 `PADDING`
> 的长度**（且永不放大）。理由：① 无放大风险（响应大小只由请求决定，不会被当成反射器）；
> ② 行为确定（不做 MTU 探测/缓存，不依赖平台接口，回环与容器里结果一致）；③ 易测
> （请求 N 字节 → 响应 N 字节，一条断言钉死）。代价是「按出接口 MTU 精确填充」的探测精度
> 略低，但该属性的用途是「看这个报文是否被路径分片」，客户端本来就要自己比对响应大小，
> 长度回显足够。

### 部署前先确认「回程可用」

协议正确 ≠ 网络可用。云主机上常见两种坑，都表现为「服务端看起来没问题，客户端什么都收不到」：

1. **EIP 是 1:1 NAT**：公网 IP 不在网卡上，`--listen <公网IP>` 会 `Address not available`
   直接退出。要绑**网卡上的地址**（私网 IP），云侧再把它映射成公网。
2. **某些 EIP 的 UDP 回程被云侧丢弃**：请求到达、回包已从网卡发出、客户端 0 入包，
   而同 IP 的 TCP/ICMP 正常。这种地址不能用于 `--listen` / `--alt-listen`，
   否则 `change-ip` 那一半测试永远超时，看起来像「服务器没实现」。
   上线前用 `script/ci/rstun-smoke.sh <ip>:3478 --tcp` 对每个地址各验一次；
   RFC 5780 的 `change-port` / `change-ip` / 两者同时三条路径见
   [`docs/interop-matrix.md`](docs/interop-matrix.md)（要点是看 `recvfrom` 的**真实源地址**）。

### 容器部署：必须 host 网络

`docker -p 13478:3478/udp` 这类端口映射会做源地址 NAT，`change-ip` / `change-port` 的回包
会被改写成「宿主机地址:发布端口」，RFC 5780 的判据就失效了（实测确认）。部署用
`--network host`，或给容器直连两个地址。

### 客户端侧

客户端只认 `RESPONSE-ORIGIN` / `OTHER-ADDRESS`（老客户端会忽略这两个属性），
不需要做任何适配；用 coturn 或本服务都能拿到同一组判据。

## 抗滥用（限速 / 并发 / 反射防护）

公网裸跑的 STUN 服务器同时面对两种**性质不同**的滥用，必须用不同防线：

| 威胁 | 特征 | 有效防线 |
| --- | --- | --- |
| 真实客户端 / 单机滥用 | 固定源 IP、高频 | 每源 IP、每源 IP+端口 令牌桶 |
| **伪造源反射** | 源 IP 每包都不同、请求小、响应大 | 每 IP 限速**无效**（每包都是新桶）；只能靠**反射防护**（最小请求尺寸 + 放大比）|
| 单点洪水 | 任意源、总量巨大 | 全局限速 + 在途上限（Semaphore）|
| 定向封禁 | 少量网段 | `--allow` / `--deny` CIDR |

**默认全部关闭**：不给任何 `--rate-limit` 族参数时，不建哈希表、不建信号量、不起后台清理任务，
`decide()` 与响应字节与 `26.410.100` 完全一致（`plain_response_bytes_are_frozen` 与
`enabled_guard_leaves_plain_answers_byte_identical` 两条测试锁住）。开启后只做**准入**：
超限的请求在 `decide()` **之前**被丢弃（UDP）或关闭连接（TCP），正常请求看到的内容一个字节都不变。

### 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--rate-limit [REQ/S]` | 关（裸写 = 200） | 每**源 IP** 令牌桶；UDP 与 TCP 共用同一张表 |
| `--rate-burst N` | `2 × rate`（200 → 400） | 上面的桶容量；要求 `--rate-limit` |
| `--rate-limit-port [REQ/S]` | 关（裸写 = 20，突发也是 2 × rate） | 每**源 IP + 源端口**令牌桶；防单端口刷。TCP 上「源端口」就是连接本身，所以等价于每条连接一个桶 |
| `--global-rate REQ/S` | 关（突发 2 × rate） | 全局限速（与源无关） |
| `--max-inflight N` | 关（文档值 4096） | 在途上限：UDP 一个 datagram 一个槽位（应答后释放），TCP 一条连接一个槽位（关闭前一直占着）；满时 UDP 静默丢、TCP 拒绝连接 |
| `--reflect-min-request BYTES` | 关（开启后 **20** = STUN 头长） | 含 `RESPONSE-PORT`/`CHANGE-REQUEST` 的请求小于此值才拒绝。20 只挡「不成帧」的输入：能携带该属性的最小请求是 28 字节，调高会先于比例规则挡掉真实探针 |
| `--reflect-ratio RATIO` | 关（开启后 **2.0**，另加固定 32 字节余量） | 响应上限 = `max(请求 × RATIO, 请求 + 32)`；小请求的应答还会省略可选的 `SOFTWARE`。见下文「反射防护」的实测表 |
| `--allow CIDR` | 空（可重复） | 命中者**跳过**每源 IP / 每源端口桶**与反射防护**（NAT 出口、可信探测网段） |
| `--deny CIDR` | 空（可重复） | 命中者直接拒绝；与 `--allow` 同前缀长度时 **deny 赢** |

默认值的推导（`design.md` §4）：家用 NAT 后 50 台设备做 ICE 连通性检查，每台每秒数十包，
所以每 IP 给到 200 req/s / 突发 400 不会误伤；全局限速取单核 pps 的 1/5 留余量；
`--max-inflight 4096` 对应 64 KiB 接收缓冲 × 4096 ≈ 256 MiB 的峰值上限。

开关的「值可选」写法让两个目标同时成立：`--rate-limit` 用文档默认值（200），
`--rate-limit 50` 显式覆盖，不给就是**关闭**。`0`、负数、`--rate-burst` 单独出现、
`--reflect-min-request < 20`、`--reflect-ratio <= 0`、非法 CIDR 一律**启动失败**（退出码 1/2），
不会静默降级成「看起来开了、其实没拦」。

### 判定顺序

```
recv → 名单（deny 优先 → 直接拒；allow 命中 → 跳过每源桶与反射防护）
     → 在途上限（Semaphore，满则丢）
     → 全局限速 → 每源 IP → 每源 IP+端口
     → FINGERPRINT 校验（--check-fingerprint：结构错误 400，不匹配 400 或丢弃）
     → 反射防护（仅 UDP；带 RESPONSE-PORT，或带 CHANGE-REQUEST 且启用了 --alt-listen）
       └ PADDING + RESPONSE-PORT 的 §6 400 也走这条「拒绝不许放大」的路径
     → decide()（300 / 420 / 400 / 200）→ 发送（send_to 失败按映射回 500）
```

顺序与代码一致（`Admission::admit` = 名单 → 在途 → 速率）：运维的 `--deny` 不该被报成
「在途已满」，而因为容量被拒的请求也不该白烧一个限速令牌。

「在途」按传输方式计不同的单位，因为占用的资源不同：**UDP 是「一个 datagram」**
（准入通过到 `send_to` 之后释放，限制同时占着 64 KiB 缓冲的请求数）；**TCP 是「一条连接」**
（`accept` 时取槽、连接关闭才释放，限制 fd 与任务数）。TCP 的请求级限速仍然每次查桶，
否则一条连接就能流水无限请求；把连接槽位也算进每次请求，会让 `--max-inflight N` 实际只能服务
`N/2` 条连接，所以两者是分开的。

注意 UDP 的实现形状：**只有设置了 `--max-inflight` 时**才「每个 datagram 一个任务」
（拿不到槽位就丢并计数）；未设置时仍是单任务串行循环，不额外 spawn —— 默认路径不变。
串行循环里一个 listener 最多只持有一个槽位，所以「串行 + 上限」等于没有上限，这正是
`--max-inflight` 之前对 UDP 空转的原因。

### 反射防护（核心）

`RESPONSE-PORT`（把响应发到任意**目的端口**）和 `CHANGE-REQUEST`（把响应从**另一个源地址**发出，
只有 `--alt-listen` 给了第二个地址时才成立）都能让一个很小的伪造源请求换来一个指向受害者的
较大响应。两条规则独立生效：

1. 请求长度 < `--reflect-min-request`（默认 **20**，即 STUN 头长）→ 拒绝。
   这是「是不是一个 STUN 帧」的门槛，**不是**「探针够不够大」的门槛：能携带
   `RESPONSE-PORT` 的最小请求是 28 字节，若把门槛取成 40，就会先于比例规则把 coturn
   `stunclient` 的全部 RFC 5780 探测挡掉（实测：3 个响应变成 0 个）。
2. 用**真实编码器**估算的响应长度 > `max(请求 × --reflect-ratio, 请求 + 32)`
   （默认 ratio **2.0**）→ 拒绝。

**32 字节余量的来历**：每个重定向响应必带 `XOR-MAPPED-ADDRESS`（12 字节），
带 `--alt-listen` 还要 `RESPONSE-ORIGIN` + `OTHER-ADDRESS`（24 字节）——正好 32。
`SOFTWARE`（20 字节）是**可选**属性（RFC 5389 §15.5.1），防护开启时**小请求的成功响应会省略它**，
所以它不该进余量。省略后响应就只剩「固有属性」，放大被压到协议下限：

| 场景 | 请求 | 响应 | 放大 | `allowed = max(len×2, len+32)` | SOFTWARE |
| --- | --- | --- | --- | --- | --- |
| `--alt-listen`，28 字节 `RESPONSE-PORT` 探针 | 28 | **56** | 2.00× | 60 ✓ | 无 |
| 无 `--alt-listen`，28 字节探针 | 28 | **32** | 1.14× | 60 ✓ | 无 |
| `--alt-listen`，40 字节探针 | 40 | **76** | 1.90× | 80 ✓ | 有 |
| 无 `--alt-listen`，20 字节普通 Binding | 20 | 52 | 2.60× | 不走本防护（无重定向属性） | 有 |

（以上为生产二进制实测字节数；`script/lab/rstun-abuse.sh` 的 `reflect` 组逐条断言这些值。）

这套规则的意义在于**它真的能拒**。例如 `--alt-listen` 下一个 40 字节的
「`CHANGE-REQUEST` + `PADDING 8`」请求本来会得到 `76 + 12 = 88` 字节，超过
`max(80, 72) = 80`，于是被拒（回 40 字节的 400，且重定向目标地址一个包都收不到）。
而同一探针把 `PADDING` 加到 16（请求 48 字节）后响应 92 ≤ `max(96, 80)`，又会被放行 ——
规则是「**答复不许比你发来的大**」，不是「禁止 PADDING」。

拒绝时优先回 `400 Bad Request`（**40 字节** = 20 头 + 20 的 `ERROR-CODE`）；如果这 40 字节
超过**严格**的 `请求 × ratio`（注意：**不含**上面那 32 字节余量，因为 400 不带那些固定属性），
就改为**静默丢弃**。于是「拒绝本身」永远不会放大。`PADDING` + `RESPONSE-PORT` 的 §6 400
也走同一条路径（同样计数、同样受这条规则约束）。

**省略 `SOFTWARE` 的边界**（这是可选属性的合规用法，不是协议改动）：

- 只在**开启防护**时生效：关掉防护后，28 字节探针的响应仍是 52 字节（含 `SOFTWARE`），
  与 26.410.100 逐字节一致（`plain_response_bytes_are_frozen` /
  `enabled_guard_leaves_plain_answers_byte_identical` 锁住）。
- 省略 `SOFTWARE` 的**域与防护的域完全相同**（`redirect_is_guarded`）：只有 **UDP**、且该请求
  **确实能重定向**（`RESPONSE-PORT` 总是；`CHANGE-REQUEST` 仅 `--alt-listen` 下）且**小于 40 字节**
  时才省略。所以 TCP 上的探针、无 `--alt-listen` 时的 `CHANGE-REQUEST`、普通 Binding、
  ≥ 40 字节的探针（如 PADDING 探针）都照旧带 `SOFTWARE`（实测：TCP + 28B `RESPONSE-PORT`
  → 76 字节含 `SOFTWARE`；UDP 无 alt + 28B `CHANGE-REQUEST` → 52 字节含 `SOFTWARE`）。

边界与已知项：

- **`--allow` 命中的源豁免反射防护**（整段可信探测网段 / 监控主机）。它们仍然受全局限速与
  在途上限约束，除非连每源桶也被 `--allow` 跳过。
- **放大比只约束带 `RESPONSE-PORT` / `CHANGE-REQUEST` 的请求**。其它响应不在本防护范围，
  而且这条面**确实还能放大**（26.410.100 就如此，`plain_response_bytes_are_frozen` 冻结）：
  20 字节普通 Binding 在 `--alt-listen` 下得到 **76 字节 = 3.80×**（无 alt-listen 52 字节 = 2.60×）；
  24 字节未知属性得到 `420` **56 字节 = 2.33×**（28 字节请求则是 2.00×）。
  这正是每源 IP 令牌桶存在的理由：无属性放大面靠限速兜底，不靠本条防护。
- **`--alternate-server` 的 300 也在这条规则之外**：20 字节普通 Binding → **56 字节（2.80×）**，
  与 `420`（2.33×）/ 普通 Binding（3.80×）同属「无重定向属性的应答」。带 `RESPONSE-PORT` /
  `CHANGE-REQUEST` 的请求仍受本防护管辖，且估算的是**实发的 300**（56 字节），不是成功响应。
- **`500 Server Error` 固定 40 字节**（`ERROR-CODE` 只有一句固定文案），且只在原本「回不了包」的
  路径出现；请求 < 20 字节根本不会被解析，所以它不构成新的放大面。
- 不带 `--alt-listen` 时 `CHANGE-REQUEST` 无法换源（我们没有第二个地址），因此**不触发**本防护；
  否则 28 字节的普通探针会被白拒。
- **兼容 coturn**：`turnutils_stunclient` 打 `--alt-listen` 且开启防护（不调参）时，
  3 个 RFC 5780 响应齐全、`exit 0`（`script/lab/rstun-abuse.sh` 的 `reflect` / `reflect-reject`
  组与判决实验都验这条）。

### 观测

不新增 HTTP / metrics 端点（镜像里没有 HTTP 栈，也没有就绪端点）。可见性有两处：

- 退出（Ctrl-C / `SIGTERM`）时多打印一行：
  `rstun: abuse guard counters rate_limited_ip=… rate_limited_port=… rate_limited_global=… inflight_dropped=… denied=… reflect_rejected=… allowlisted=…`；
  随后的 `rstun: stopped` 行里另有 `fingerprint_rejected=`（`--check-fingerprint` 的拒绝数，
  drop 模式下同样计数、并额外 +1 `dropped`）。
- `--verbose`（`debug`）下，每个被拒请求打印 `reason=`（`denied (CIDR)` / `in-flight cap` /
  `global rate` / `per-source-IP rate` / `per-source-port rate`）与对应 `counter=` 字段。
- 反射拒绝会**同时** +1 到 `reflect_rejected` 与 `dropped`；如果那条 400 真的发出去了，
  `answered` 也会 +1。所以 `received = answered + dropped` **不成立** —— 一个反射拒绝
  既是 dropped 也是 answered，看 `reflect_rejected` 才是准确口径。

`script/lab/rstun-abuse.sh` 把这些计数与真实 socket 行为做成对照实验（关/开限速、单源洪水、
反射防护默认值与严格门槛、allow/deny、`--max-inflight`、TCP 洪水），逐条断言真实字节数与放大比，
是本节的验收脚本。

### NAT 误伤排查

1. **先确认是限速**：`--verbose` 看到 `per-source-IP rate` 的拒绝行，或退出统计里
   `rate_limited_ip` 在涨，才是阈值问题（`dropped` 涨但 `rate_limited_*` 不涨 → 是畸形包）。
2. **整段放行**：出口 NAT / 监控探测网段加 `--allow 203.0.113.0/24`。注意 `--allow`
   只跳过**每源**桶，全局限速与在途上限仍然生效（那两个保护的是进程，不是公平性）。
3. **确认分桶口径**：桶按**归一化后的源 IP** 计（`::ffff:a.b.c.d` 折叠成 IPv4），
   所以同一个双栈客户端不会拿到两个桶；NAT 后所有设备共享出口 IP，也就是共享一个桶。
4. **别指望每 IP 限速挡伪造源**：源地址每包都变时，每包都拿到全新满桶。那种流量只能靠
   反射防护（它不依赖源地址）与全局/在途上限。
5. **反射防护误伤**：退出统计里 `reflect_rejected` 在涨、而 `rate_limited_*` 不动，
   就是放大规则在拒 —— 给探测网段加 `--allow`（完全豁免），或调 `--reflect-min-request` /
   `--reflect-ratio`。`--verbose` 下被拒请求带 `reason=` / `counter=`。

### 局限（明确不做）

- 状态只在**本进程内存**：不落盘、不跨实例共享，重启即清零；多实例部署时每个实例各自计数。
- 表有硬上限（65536 条约 4 MiB，64 分片，10 分钟不活跃即回收、每 60 秒清扫一次）：
  满了回收最久未用的条目，所以**不能**用它做长期审计。
- 不做内容 DPI，也不按协议模式封禁。

## TURN（UDP 中继，`--turn`）

> `--allocation-lifetime` 同时是**默认授予值**与**上限**：客户端不带 `LIFETIME`、或给的值小于 600 时得到 600，
> 超过上限时得到上限（`--allocation-lifetime 2` 正是回收测试用的形状）。
> TURN 的**成功**响应带 `SOFTWARE`，失败响应（401/437/441/486/508）不带——RFC 8656 §6.1 对失败响应是 SHOULD，
> 这里按「与 STUN 共享 401/438 编码、保持默认关闭字节冻结」取舍。

T1 范围：RFC 8656 的 **UDP 中继闭环**。TURN **默认关闭**；开启即强制长期凭据 —— 缺
`--realm` / `--auth-secret` / 用户时**启动失败（exit 1）**，不存在「匿名开放中继」形态。

```bash
rstun server \
  --listen 203.0.113.10:3478 \
  --turn --realm example.org --auth-secret "$SECRET" \
  --auth-file /etc/rstun/users.txt \
  --relay-ports 49152-65535 \
  --max-allocations-per-user 8 --max-allocations-per-ip 16 --permission-limit 10 \
  --health-listen 127.0.0.1:9100
```

| 项 | 行为 |
| --- | --- |
| 方法 | `Allocate` / `Refresh` / `CreatePermission` / `ChannelBind`；`Send`/`Data` indication；`ChannelData`（UDP 与 TCP 客户端传输，relay 本身恒为 UDP）|
| 鉴权 | 四个 request 方法都必须带 `MESSAGE-INTEGRITY`（长期凭据，复用 STUN 的 realm/nonce 实现）：无 MI → `401` + `REALM`/`NONCE`；nonce 过期 → `438` + 新 `NONCE`；错口令/未知用户 → `401`。**401/438 同样计入限速桶** |
| 生命周期 | `Allocate` 默认授予 **600s**（`LIFETIME=0`/缺省都按默认）；请求值低于默认时按 RFC 8656 §7.2 取默认，高于 `--allocation-lifetime` 上限被截断；`REFRESH LIFETIME=0` 立即释放；**`Refresh` 缺 `LIFETIME` 也按默认续期**（§8.2）；permission TTL **5 分钟**、channel TTL **10 分钟**；到期由 1s 扫描任务回收 |
| 5 元组 | `(client addr, client transport, server addr)`；**同一 transaction id** 的重传 `Allocate` 幂等返回同一 relay；**新 transaction id → `437`**；**同一 5 元组换用户 → `441 Wrong Credentials`**（不得暴露/改动他人 allocation，`LIFETIME=0` 也不删）；释放后再 `Refresh` → `437` |
| 端口与配额 | `--relay-ports` 耗尽 → `508`；每用户 `--max-allocations-per-user`（默认 8）/ 每 IP `--max-allocations-per-ip`（默认 16）超限 → `486`；每 allocation permission 超 `--permission-limit`（默认 10）→ **`508`**（RFC 8656 §10.2；一条请求带多个 peer 时**整条原子校验**，不做部分生效） |
| 响应属性 | 成功响应带 `SOFTWARE`（RFC 8656 §14.10 SHOULD），401/438 挑战不带；`ChannelBind` 隐式创建的 permission 与 `CreatePermission` 共用同一个上限 |
| 数据面 | `Send` 仅在 permission 覆盖 peer 时转发（否则静默丢弃）；relay 收到 peer 数据时，命中 channel → `ChannelData`，否则 → `Data` indication；`ChannelData` 不解析 STUN；**UDP 上声明长度大于实际报文的 `ChannelData` 静默丢弃**（不转发截断内容）；TCP 客户端写队列有界（64 帧，溢出丢 relayed 数据）|
| 其它 transport | `REQUESTED-TRANSPORT=6`（TCP allocation / RFC 6062）→ `442`；`EVEN-PORT`（含 R=1 reservation token）支持；`DONT-FRAGMENT` 等未实现的可理解属性 → `420` |
| 防回环 | 拒绝：`unspecified` / `multicast` / 本进程**监听地址** / 该 allocation 自己的 relay / **loopback peer**（仅当请求到达的 socket 本身绑定在回环地址时放行，供本地开发与 `-y` 矩阵）→ `403`。`--listen 0.0.0.0` 或公网监听下回环 peer 一律拒绝（否则「peer=127.0.0.1:<监听端口>」漏检）。同一进程内**其它 allocation 的 relay 地址允许** —— `turnutils_uclient -y` / 同 NAT WebRTC 的正常路径。**已知盲区**：宿主自身公网 IP 无法在不引入接口枚举依赖的情况下判定 |
| 回收 | allocation 过期 / `LIFETIME=0` → abort relay 读任务 → 关闭 socket → 端口归还池；测试断言过期后 `ss -lun` 在 relay 段内无监听 |
| 观测 | `/metrics`：`rstun_turn_allocations`（gauge）、`rstun_turn_bytes_total{direction=in\|out}`、`rstun_turn_allocations_total{result=created\|expired}`、`rstun_turn_rejected_total{reason=quota\|ports\|family\|loopback}`；退出日志打印同一组数字。**未开 `--turn` 时这些指标不出现** |

部署注意：

- **防火墙**：客户端 → `--listen` 的 UDP 要放行；relay 端口段也要放行 **UDP 双向**（与 coturn 同理），
  否则 `Allocate` 能成功但中继数据收不到。
- **临时端口冲突**：Linux 默认 `net.ipv4.ip_local_port_range`（常见 `32768 60999`）与默认
  relay 段 `49152-65535` 重叠。生产建议显式给一个不重叠的 `--relay-ports`（或调整内核范围），
  否则内核可能先占用 relay 段里的端口，表现为偶发 `508`。
- **多实例**：同一 `--auth-secret` 的实例互认 nonce；allocation 状态**不共享**（客户端会被
  `401` 后的重试带到同一实例，靠 LB 一致性哈希/源地址亲和）。T1 不做 REST 临时凭据。
- **通道号范围**：接受 `0x4000–0x7FFF`。RFC 8656 §12.1 定义到 `0x7FFE`；`0x7FFF` 是为 coturn
  兼容而放行（其解析器接受该值）。
- **指标口径**：`rstun_turn_bytes_total` 只计 relay payload（不含 STUN / ChannelData 头），
  `direction=in` 为 client→peer、`out` 为 peer→client；`rstun_requests_total` 也计 TURN 报文
  （同一 transport 循环），TURN 专用口径请看 `rstun_turn_*`。
- **配额抖动**：过期但尚未被 1s 扫描移除的 allocation 仍计入 per-user/per-IP 配额，
  高 churn 下可能多拒绝一次 `486`，下一次扫描恢复。
- **防回环已知盲区**：不枚举宿主接口，故「peer = 宿主自身公网 IP:端口」无法识别；
  需要该能力时应改用 coturn 或引入接口枚举（T2 评估，新增依赖需单独立项）。
- 不支持（T2 或更晚）：TLS/DTLS、REST 临时凭据、带宽配额、TCP allocation（RFC 6062）、
  `DONT-FRAGMENT`、`REQUESTED-ADDRESS-FAMILY`。

验收：

```bash
bash script/lab/rstun-turn.sh            # 12 项：启动失败/中继/401+438/生命周期/441/通配回环/permission 508/486/端口 508/回收/字节冻结/coturn 对照
```

## 与 coturn 的差异

|      | `rstun`                                                                                                                                                                                         | coturn                                        |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| 定位 | 只做 STUN/TURN 的**最小服务**：Binding + **NAT 行为发现** + TURN UDP 中继（`--turn`，强制长期凭据） | 完整 STUN/TURN（中继）+ 鉴权 + 多租户 |
| 协议 | RFC 5389 Binding + `SOFTWARE` + `MAPPED-ADDRESS`（可选）+ `UNKNOWN-ATTRIBUTES`/420 + `FINGERPRINT`/300/500（两个开关）+ 鉴权（短期/长期，默认关闭）；RFC 5780 的 `CHANGE-REQUEST` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `RESPONSE-PORT` / `PADDING`；RFC 8656 UDP 中继（T1：无 TLS/DTLS、无 REST 凭据、无 TCP allocation） | RFC 5389 / 5780 全量 / TURN（5766、turns 等） |
| 配置 | 纯命令行参数（无配置文件） | 上百行 `turnserver.conf`、数据库/鉴权后端 |
| 鉴权 | 短期 / 长期凭据 + RFC 8489 SHA256、USERHASH；用户来自 `--auth-user` 或 `--auth-file`，**无数据库**；TURN 复用同一套长期凭据 | 长期凭据 + 数据库/Redis/文件后端，TURN 也受保护 |
| 依赖 | 纯 Rust，无 OpenSSL/libevent | 依赖 libevent/OpenSSL + 系统配置 |
| 部署 | 单二进制 / 一个几十 MB 的镜像 | 发行版包 / 官方镜像 + 配置卷 |
| 用途 | 需要「公网 STUN 映射 + NAT 行为发现」，以及**小规模、静态用户**的 UDP 中继 | 需要完整 TURN（TLS/DTLS、REST 凭据、多租户）的基础设施 |

结论：**需要 TLS/DTLS、REST 临时凭据、带宽配额或 TCP allocation 时仍然用 coturn**。
本服务的 TURN 只覆盖 RFC 8656 的 UDP 中继最小闭环，用户清单是静态文件 / 单个 flag。

## 构建与运行

本地（需要 Rust 1.95，见 `rust-toolchain.toml`）：

```bash
cargo build --release
./target/release/rstun server --listen 0.0.0.0:3478 --tcp
```

安装：

```bash
cargo install --path .     # 从源码树装到 ~/.cargo/bin/rstun
cargo install rstun        # 在 crates.io 发布之后
```

容器（context = 仓库根）：

```bash
docker build -t rstun:dev .
docker run -d --name rstun \
  -p 3478:3478/udp -p 3478:3478/tcp \
  rstun:dev server --tcp
docker logs -f rstun        # 启动日志：listeners=N / UDP listener ready
docker stop rstun           # SIGTERM → 打印 received/answered/dropped 后退出
```

镜像细节：多阶段（`rust:1-slim` 构建 → `debian:stable-slim` 运行），非 root（uid 10001），
`ENTRYPOINT ["rstun"]`，`EXPOSE 3478/udp 3478/tcp`，`STOPSIGNAL SIGTERM`。

镜像内的 `--version` 由**构建期** `RSTUN_BUILD_VERSION` 决定（`src/main.rs` 的 `option_env!`）。
不传 `--build-arg` 时回落 crate 版本（`26.410.100`），所以本地 `docker build` 的行为不变：

```bash
docker build --build-arg RSTUN_BUILD_VERSION=26.410.100+abc123 -t rstun:dev .
docker run --rm rstun:dev --version     # 26.410.100+abc123
```

代码里 `RSTUN_BUILD_VERSION` 优先，`EXVLAN_BUILD_VERSION` 只是**旧构建链路的兼容回落**
（历史原因保留，新构建不要再用）：

```bash
RSTUN_BUILD_VERSION=26.410.100+local cargo build --release
./target/release/rstun --version        # rstun 26.410.100+local
```

多架构镜像由发布流水线用 `ubuntu-24.04` + `ubuntu-24.04-arm` 各自 build 后
`docker manifest create` 合成 `linux/amd64` + `linux/arm64`；本地要单架构可以直接
`docker build --platform linux/arm64 .`。

启用 RFC 5780 的容器必须用 **host 网络**（`-p` 的源地址 NAT 会破坏 `change-ip`/`change-port`
的判据，见上文）：

```bash
docker run -d --name rstun --network host rstun:dev server \
  --listen 10.0.0.5:3478 --alt-listen 10.0.0.7:3478 --alt-port 3479
```

### 发版：`.github/workflows/release.yml` 手动 dispatch

传 `version`（**不带 `v`**，如 `26.410.100`）即可，一次 dispatch 交付两样：

| 产出          | 内容                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Release       | tag **`rstun-v<version>`** + 四端资产 `rstun-<platform>-<version>.zip`（Linux x86_64/aarch64 musl、macOS x86_64、Windows x86_64）     |
| 镜像          | **`ghcr.io/<owner>/rstun:<version>`**（双架构 amd64+arm64；版本不含 `-` 的稳定版追加 `latest`）                                      |

- `prepare` 作业先校验 `version` 形如 `^\d+\.\d+\.\d+(-[...])?$`，且**必须等于 `Cargo.toml` 的
  `version`** —— 不一致直接失败，避免「tag 说 A、二进制说 B」。
- 版本串以 `<version>+<sha6>` 注入（`RSTUN_BUILD_VERSION`），二进制作业与镜像作业都会自检
  `--version` 里含这个串。
- musl 静态产物在 `ubuntu-24.04` / `ubuntu-24.04-arm` 上 native 构建并跑 UDP+TCP 冒烟；
  Windows 跑 `--version`；macOS runner 是 arm64，x86_64 产物**只编译不执行**（需 Rosetta）。
- 冒烟不可省：20 字节 Binding Request，断言 `0x0101` + `XOR-MAPPED-ADDRESS`
  （`script/ci/rstun-smoke.sh`），native 与容器各跑一次。
- 镜像推的就是**冒烟通过的那一份**：两个架构各自 build → 推 `:<version>-amd64` /
  `:<version>-arm64` → `docker manifest create/annotate/push` 合成 `:<version>`。

## 运维面（readiness / metrics / env / 优雅退出 / 部署清单）

运维只要回答两个问题：「它真的在服务吗？」「它现在怎么样？」。两者都由**一个可选的只读
HTTP 端点**回答 —— **不给 `--health-listen` 就没有任何 HTTP 监听、没有额外任务、字节行为
不变**（`interop all` 42 项、`abuse` 10 组、冻结测试都在这个前提下通过）。

```bash
rstun server --listen 0.0.0.0:3478 --tcp --health-listen 127.0.0.1:9100
```

### `/healthz`（readiness）

```bash
curl -si http://127.0.0.1:9100/healthz
# HTTP/1.1 200 OK
# {"status":"ok","listeners":1}
```

| 情形 | 响应 |
| --- | --- |
| 每个已配置的监听都还在服务 | `200 {"status":"ok","listeners":N}` |
| 任一监听任务意外结束（错误返回 / panic / abort） | `503 {"status":"degraded","listeners":N,"stale":["udp 1.2.3.4:3478"]}` |
| 正在 SIGTERM 之后 drain | `503 {"status":"draining","listeners":N,...}` —— LB 据此摘流 |
| 未知路径 | `404`；`POST` 等其它方法 `405` + `Allow: GET, HEAD` |
| 请求带**非零** `Content-Length`（或有 `Transfer-Encoding`） | `400` 并关闭连接（端点不读 body；`Content-Length: 0` 视为没有 body，照常按方法判定） |

判定来自 supervisor：每个 listener 任务持有一个 `AtomicBool`，任务**任何**结束方式（错误、
drain 后正常返回、被 abort）都会把它置 false。所以「进程还活着」不等于 `200`：**绑定失败不是
`503` 而是启动失败**（任何 socket 绑不上 → 进程直接退出 1，不会「起了一半还说健康」）；
起来之后某个监听任务意外结束（panic / abort）才是 `503` + `stale`。socket 读错误（瞬时 ICMP 等）
不会结束监听，按 `RECV_ERROR_BACKOFF` 重试 → 不产生 `stale`。

**资源上限**（都在 `--health-listen` 开启时才生效）：

- **整条连接 2 秒**：读头与写响应共用同一个截止时间。每读一次重置的超时挡不住「每 1.5s 发 1
  字节」的慢速客户端（旧行为可拖到分钟级），现在从 `accept` 起 2s 必然关闭。
- **并发上限 `--health-max-connections`（默认 64）**：`accept` 后 `try_acquire`，**超出上限不排队**
  —— 立刻回 `503 too many concurrent connections` 并关闭（排队会保留洪水想耗尽的那个 fd）。
  `/healthz`/`/metrics` 本身不受已占用连接拖累：只要还有空槽就能服务，超限计数见
  `rstun_ops_rejected_total`。
- 请求头（含终止空行）上限 **8192 字节**：恰好 8192 可服务，8193 起 `400 request head too large`。

### `/metrics`（Prometheus 文本）

```bash
curl -s http://127.0.0.1:9100/metrics | grep -E '^# TYPE|^rstun_requests_total'
```

| 指标 | 类型 | 标签 |
| --- | --- | --- |
| `rstun_requests_total` | counter | `transport=udp/tcp`、`result=ok/error/ignored/dropped` |
| `rstun_rate_limited_total` | counter | `scope=ip/ip_port/global` |
| `rstun_inflight_dropped_total` | counter | — |
| `rstun_reflect_rejected_total` | counter | — |
| `rstun_denied_total` / `rstun_allowlisted_total` | counter | —（`--deny` / `--allow` 命中）|
| `rstun_fingerprint_rejected_total` | counter | — |
| `rstun_socket_errors_total` | counter | `transport=udp/tcp`（`recv_from`/`accept` 失败）|
| `rstun_auth_total` | counter | `result=ok/unauthorized/stale_nonce/bad_request` |
| `rstun_turn_allocations` | gauge | —（仅 `--turn`；活动 allocation 数）|
| `rstun_turn_bytes_total` | counter | `direction=in`（client→peer）/ `out`（peer→client）；仅 `--turn` |
| `rstun_turn_allocations_total` | counter | `result=created/expired`；仅 `--turn` |
| `rstun_turn_rejected_total` | counter | `reason=quota/ports/family/loopback`；仅 `--turn` |
| `rstun_ops_rejected_total` | counter | —（运维端点因 `--health-max-connections` 拒绝的连接）|
| `rstun_build_info` | gauge = 1 | `version`（编译期常量）|
| `rstun_start_time_seconds` / `rstun_uptime_seconds` | gauge | — |
| `rstun_health` | gauge | —（1 = `/healthz` 会回 200）|

- **与退出统计同源**：`/metrics` 读的就是退出时打印的那组 `Counters`
  （`limit::Counters` + `auth::Counters` + `ServerStats`），没有第二份计数。
- **标签集合固定**：只有 `transport` / `result` / `scope` 三个枚举维度，没有按对端 IP 的标签 ——
  指标基数不会随流量爆炸。
- `result` 的归属：`ok` = 应答已发出；`dropped` = 策略拒绝（限速 / 在途 / 反射防护）；
  `error` = 读不懂或内部不变量失败；`ignored` = 有意不作答（indication、`--fingerprint-action drop`）。
  后两者与退出日志的 `dropped` 总量**有意重叠**（退出日志的 `received/answered/dropped` 语义
  未变，见 `.trellis/spec/backend/abuse-guard.md` §4）。
- **TURN 指标只在 `--turn` 时出现**：未开启时 `rstun_turn_*` 四条指标**不输出**
  （而不是恒为 0 —— 0 会被读成「TURN 开着但空闲」）；开启后与退出日志的
  `rstun: TURN counters` 同源（同一组原子计数）。
- 安全：端点只做 `GET`/`HEAD`、一个连接只答一个请求（无 keep-alive）、**整条连接 2 秒总时限**、
  请求头（含终止空行）上限 **8192 字节**、并发连接上限（`--health-max-connections`）、不读 body；
  响应里没有路径、配置值或证书信息。**默认示例都绑 127.0.0.1**，
  对外请用反代或内网地址。

### 配置：环境变量（`RSTUN_*`）

命令行的每个 flag 都有一个同名环境变量：`--health-listen` ⇔ `RSTUN_HEALTH_LISTEN`（大写、
`-` → `_`）。**命令行显式值优先**，环境变量只补「没写」的那些：

```bash
RSTUN_LISTEN=0.0.0.0:3478 RSTUN_TCP=1 RSTUN_REALM=example.org \
  rstun server --health-listen 127.0.0.1:9100
```

- 列表型用逗号：`RSTUN_LISTEN="10.0.0.5:3478,10.0.0.6:3478"`、`RSTUN_DENY="10.0.0.0/8,192.168.0.0/16"`。
  **列表不合并**：命令行给了 `--listen` 就以命令行为准，`RSTUN_LISTEN` 整条被忽略。
- 开关型：`1/true/yes/on` 为开，`0/false/no/off`（含空串）为关。
- **空字符串 = 未设置**：compose 里 `${RSTUN_REALM:-}` 这种写法会把变量留成空串，它不会被当成
  「显式空值」而启动失败（`--realm ""` 那种显式空值仍由 flag 校验拒绝）。
- 解析失败 → **启动失败并指明来源**（`RSTUN_ALT_PORT: invalid value …`），不会静默忽略。
- 启动日志会打印实际生效的变量名：`configuration defaults read from the environment variables=["RSTUN_LISTEN"]`。
- 未映射的 `RSTUN_*`（例如构建期的 `RSTUN_BUILD_VERSION`）被忽略。

### 优雅退出（drain）

```
SIGTERM → 停止收新包（UDP 停 recv、TCP 停 accept、已有连接不再读新帧）
        → 等在途请求与发送完成（上限 --drain-timeout，默认 5s，0 = 立即）
        → 打印统计 → 退出码 0
```

- 在途计数覆盖：UDP 的每个 datagram（含 `--max-inflight` 下 spawn 的任务）、每条 TCP 连接、
  每个正在处理的 TCP 帧。监听任务本身也在等：它的 `recv_from`/`accept` 在 drain 时不会打断
  手里那个请求。
- 超时后照样退出（退出码仍为 0），并 `warn` 记下卡住的 listener 数与在途数。
- **第二个 SIGTERM 立即退出**（运维兜底），所以 `TimeoutStopSec` 只需略大于 `--drain-timeout`。
- drain 期间 `/metrics` 仍可抓取；`/healthz` 变 `503 draining`。

### 部署清单（`contrib/`）

| 文件 | 用途 |
| --- | --- |
| `contrib/systemd/rstun.service` | systemd 单元（非 root、`ProtectSystem=strict`、`LimitNOFILE=65536`、`TimeoutStopSec=10`） |
| `contrib/docker/compose.yaml` | 单服务 Compose（**`network_mode: host`**：RFC 5780 必需）+ `/dev/tcp` 健康检查 |
| `contrib/k8s/deployment.yaml` | Deployment（`hostNetwork`、UDP+TCP 3478、`readinessProbe → /healthz`、只读根文件系统；RFC 5780 的 `--alt-port 3479` 以注释形式给出，开启时同时放开该端口） |
| `contrib/k8s/service.yaml` | `LoadBalancer` + `externalTrafficPolicy: Local`（Cluster 策略的 DNAT 会破坏 `CHANGE-REQUEST` 判据） |
| `contrib/helm/` | 最小 chart（`listen` / `rfc5780` / `health` / `abuse` 都在 values 里），**不引第三方 chart 依赖** |

清单里的参数与本文一致；校验方式见 `contrib/README.md`。

### 更深一层：外部 STUN 探测

`/healthz` 只说「监听还在」，不说「UDP 回程通」。要验回程：

```bash
# 任意一台有 python3 的机器：20 字节 Binding Request，期望 0x0101
python3 - <<'PY'
import socket, os
tid = os.urandom(12)
req = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + tid
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(req, ("<stun-host>", 3478))
data, src = s.recvfrom(2048)
assert data[0:2] == b'\x01\x01', data.hex()
print("ok", src, data.hex())
PY
```

`script/ci/rstun-smoke.sh` 就是这条探测（带断言）的固化版本，CI 里 native 与容器各跑一次。
镜像本身仍然**不带** `HEALTHCHECK`（镜像里没有 curl/python）；容器健康检查写在编排层
（见 `contrib/docker/compose.yaml`）。

## systemd 样例

**可直接安装的版本在 [`contrib/systemd/rstun.service`](contrib/systemd/rstun.service)**
（含安装步骤、`EnvironmentFile=-/etc/rstun/rstun.env`、`TimeoutStopSec=10` 与一组加固项）。
最小形态：

```ini
# /etc/systemd/system/rstun.service
[Unit]
Description=rstun (STUN Binding + RFC 5780 NAT behaviour discovery)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 单独的运行用户即可，不需要任何 capability（3478 > 1024）
User=rstun
Group=rstun
# 用 `RSTUN_*` 配参数（命令行 flag 仍然优先）：
EnvironmentFile=-/etc/rstun/rstun.env
# 只做 RFC 5389（单地址，可用通配）：
# ExecStart=/usr/local/bin/rstun server --listen 0.0.0.0:3478 --listen-v6 [::]:3478 --tcp
# 启用 RFC 5780：两个公网 IP 都要写具体地址（不能是 0.0.0.0）
ExecStart=/usr/local/bin/rstun server --listen 203.0.113.10:3478 --alt-listen 198.51.100.20:3478 --alt-port 3479 --tcp --health-listen 127.0.0.1:9100
Restart=on-failure
RestartSec=2
# 单实例、只读文件系统（本服务不写盘）
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_INET6
LimitNOFILE=65536
# SIGTERM 是缺省停止信号：先 drain（--drain-timeout 默认 5s）再打印统计退出。
# TimeoutStopSec 要留出 drain + 打印的余量；第二个 SIGTERM 会立即退出。
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
```

防火墙（Binding 只要 3478；开了 RFC 5780 就要**两个 IP 上的两个端口**）：

```bash
# nftables 例：RFC 5780 需要 3478 与 3479（--alt-port）两端口，且两个 IP 都要放行
nft add rule inet filter input udp dport 3478 accept
nft add rule inet filter input udp dport 3479 accept
nft add rule inet filter input tcp dport 3478 accept   # 仅 --tcp 时需要
```

> 云主机注意：安全组放行 ≠ 回程可用。UDP 回程被云侧丢弃的地址要先用冒烟脚本验过再用，
> 否则 `--alt-listen` 指到它会让 `change-ip` 永远超时（见上文「部署前先确认回程可用」）。

容器 / Kubernetes / Helm 的最小清单见 `contrib/`（compose 用 `network_mode: host`，k8s 用
`hostNetwork` + `readinessProbe → /healthz`），说明见 [`contrib/README.md`](contrib/README.md)。

## 依赖面

运行期依赖 **9** 个 crates.io 包，没有任何 path 依赖：

```
clap  socket2  tokio  tracing  tracing-subscriber
hmac  sha1  sha2  md-5            ← 鉴权（RFC 5389 §10 / RFC 8489 §9.2）
（dev-only: stun-types 2.0.5 —— 只用做编解码的参考实现 oracle，不进二进制）
```

`hmac` / `sha1` / `sha2` / `md-5` 都是 **RustCrypto**，纯 Rust、无 C 依赖（不需要
OpenSSL/libssl-dev）。引入它们的原因：鉴权要 HMAC-SHA1、HMAC-SHA256 与 MD5 三种算法，
而「不手写密码学」是硬约束 —— 自己实现 S 盒/压缩函数只会得到一堆难测的代码。
**底线是「不写算法」而不是「不加依赖」**：这四个 crate 加起来仍比 `ring`/`openssl` 小得多，
且 `cargo tree -e normal --depth 1` 一眼能看完。

`stun-types` 在 `[dev-dependencies]` 里，`cargo tree -e normal` 看不到它。编解码是手写的：
`stun-types` 缺全部 RFC 5780 属性，把运行时交给第三方库也换不来协议覆盖，只会多几层依赖。

## 测试

```bash
cargo test          # 198 个单测：3 crc32 + 30 protocol + 7 rfc5780 + 82 server + 27 limit + 13 auth + 8 interop + 28 ops
```

覆盖：

- **编解码**：XOR v4/v6 往返、与 `stun-types` 参考实现逐字节对齐（编码值字节与解码结果双向）、
  用参考解析器解我们的整条响应/错误响应；`CHANGE-REQUEST` 的两位标志（含未知位 / 保留位 /
  长度不对）、`RESPONSE-ORIGIN` / `OTHER-ADDRESS` 的 v4 与 v6（family `0x02` + 16 字节）
  编码与解码、坏 family / 截断值不 panic；`PADDING` / `RESPONSE-PORT` 的值解析（含截断容错）。
- **默认响应字节冻结**：固定 transaction id / peer / SOFTWARE 下，48 字节逐字节断言
  （`plain_response_bytes_are_frozen`），保证改动不悄悄改变客户端看到的内容。
- **合规包**：未知 comprehension-required 属性 → 420 + `UNKNOWN-ATTRIBUTES`（值长度恰为
  `2×N`：N=1/2/3 → 2/4/6 字节，wire 上 value+padding 分别 4/4/8；padding 不计入 Length，
  不重复末项）；400 不带 `UNKNOWN-ATTRIBUTES`；indication 仍静默；ICE / 鉴权
  属性（`USERNAME` / `MESSAGE-INTEGRITY` / `PRIORITY` / `USE-CANDIDATE` / `ICE-CONTROLLING` /
  `FINGERPRINT`）不触发 420；`--mapped-address` 开/关的字节差异与属性顺序；
  `PADDING` 回声长度（0 / 4 / 37 / 128 / 1400 / 2048 / `u16::MAX` 夹取）与「必须是最后一个属性」。
- **服务器**：畸形包（短包/坏 cookie/长度不对齐/属性越界）不打死监听、TCP 分帧与流水、
  非 Binding → 400（保留请求的 method）、indication 忽略、v6-only 不抢占 v4 端口、
  未启用 RFC 5780 时**不含**那两个属性、UDP 上 PADDING 回声（无 `--alt-listen` 也生效）。
- **RFC 5780（回环上真跑四个 socket）**：无 `CHANGE-REQUEST` → 响应源地址 == 目标地址、
  `RESPONSE-ORIGIN` == 它、`OTHER-ADDRESS` == `(127.0.0.2, alt_port)`；
  `change-port` → 响应的**源端口**是 alt 端口；`change-ip` → **源 IP** 是第二 IP；
  两者同时 → 对角线 socket；从「另一个地址」进来时四个地址仍互指；`RESPONSE-PORT=p`
  → 回包**发往** `(源 IP, p)`（客户端在另一个 socket 上收到）、**源地址/源端口不变**；
  未绑定端口乃至 `0` 也照样作为目的端口（不 panic、不回 400）；`RESPONSE-PORT` + `PADDING`
  → `400 Bad Request`；TCP 上 `RESPONSE-PORT` 被忽略。上述断言全部基于 `recv_from` 的
  源地址与收包 socket（也就是客户端能看到的东西），不只看报文里的属性。
- **CLI**：`0.0.0.0` / `[::]` 作为 `--listen` + `--alt-listen` 启动失败并给出明确提示、
  **primary = 命令行顺序里第一个 IPv4 `--listen`**（用第二个地址在前的顺序锁住「不能先排序再选」）、
  `--listen-v6` 不计入 primary 选择、只有 `--listen-v6` 时报「需要 IPv4 `--listen`」、
  alt 与 primary 同 IP 仍被拒、`--alt-port` 单独出现被拒、默认 alt 端口 = listen + 1。
- **多地址共存（生产形态：`.1` primary / `.2` alt / `.3` 普通 v4 / `[::]` 普通 v6）**：
  primary 上 `0x02` / `0x04` / `0x06` 三种 `CHANGE-REQUEST` 的回包源与
  `RESPONSE-ORIGIN`/`OTHER-ADDRESS` 全对；直接打 alt 地址得到计划内的应答（不主动换源）；
  普通 `.3` 上绑定与 `CHANGE-REQUEST` 都只得到 5389 响应（回包源不变、无那两个属性）；
  `[::]` 上 UDP/TCP 都只做普通 Binding 且**不会**出现 v4 的 `RESPONSE-ORIGIN`/`OTHER-ADDRESS`
  （显式断言地址族 `0x02`）；`--tcp` 在全部监听上生效，TCP 的 `CHANGE-REQUEST` 一律忽略；
  重复地址（alt socket 又写进 `--listen`）不会绑两次。
- **运维面（`ops`）**：`RSTUN_*` 映射的要点（命令行优先 / 列表用逗号不合并 / **空字符串视为
  未设置** / 非法值报错并指明变量名 / 连接上限可配）、开关型变量的 `1|true|yes|on` 与
  `0|false|no|off`、未映射的名字被忽略、以及「每个映射名都必须是真实 flag」的守卫测试；
  HTTP 解析（`GET`/`HEAD`/`405`+`Allow`/`404`/带 body 的 `400`/`Content-Length: 0` 放行/
  畸形请求行/查询串）；**资源维度**：每 1.5s 发 1 字节的慢速客户端必须在 ≈2s 被关闭（总时限，
  不是每次读重置）、`--health-max-connections 2` 时第 3 条连接立刻 503 且端点仍能服务、
  请求头 8192 字节可服务 / 8193 字节 400；`/healthz` 的 200 → 503（listener 租约被 drop、
  以及 drain 中）；`/metrics` 的 `# HELP`/`# TYPE`/固定标签集合与「随计数增长」；
  真实 socket 上的 200 → 503 与 `405`；drain 的 `wait_idle`（等在途、到点放弃并报剩余数）
  与 `Lifecycle` 订阅。
- **互操作（`tests_interop`）**：RFC 5769 §2.1–§2.4 的四段**标准字节**（请求、IPv4 响应、
  IPv6 响应、长凭证请求）全部能解析/解码，且 §2.2/§2.3 的 `XOR-MAPPED-ADDRESS`
  我们能**逐字节重建**；§2.1–§2.3 的 `FINGERPRINT` 被判为合法、改一位即不匹配；
  `stun-types` 2.0.5 双向（它编的请求我们解、我们编的响应它解，
  含 `MAPPED-ADDRESS` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `PADDING`），
  并能解出我们的 `300`（`ErrorCode 300` + `AlternateServer`）与 `500`（`ErrorCode 500`）。
- **协议闭环**：`crc32` 用 RFC 5769 §2.1 的 FINGERPRINT 常量锁死（`crc32(prefix)^0x5354554e
  == 0xe57a3bcf`）；`check_fingerprint` 覆盖 absent / 合法 / 错值 / 非末位 / 重复 / 长度非 4；
  UDP e2e 五态（合法 200、错值 400、非末位 400、drop 无响应且有计数、默认关闭时字节不变）；
  `300` 的IPv4/IPv6 编码与 `stun-types` 解码、重定向优先于 `CHANGE-REQUEST`、
  非 Binding 仍 400；`500` 的映射表（三种地址错误不映射、其余映射）与 40 字节响应，
  以及 Linux 上真实 `send_to` 失败（`RESPONSE-PORT 0`）触发 500 的 e2e。
- **抗滥用（`limit`）**：令牌桶速率/突发边界、空闲超 TTL 重置、**时钟回退不多发令牌**、
  条目上限与「回收到最久未用」、64 分片分散、CIDR 最长前缀 + deny 赢平局 + IPv6 +
  v4-mapped 归一化、`--allow` 只跳过每源桶（全局限速/在途上限不跳过）、
  `try_acquire` 满时拒绝且 permit 归还后可再生、TCP 的「连接持有槽位 + 请求查速率」两段式
  （不重复占槽、放开连接即归还）、反射防护的三种结局（静默丢弃 / 400 / 放行）、
  `max(len×ratio, len+32)` 的边界（比例项 vs 余量项）、小请求省略 `SOFTWARE`
  （28 字节无、40 字节有、普通 Binding 有、关闭防护时有）与「开/关准入的字节一致」。

## 运维验证

`script/ci/rstun-smoke.sh <host:port> [--tcp]` 是固化版探测（CI 对二进制与容器各跑一次，
线上也可直接拿来验部署）。RFC 5780 的四路验证要点是**打印 `recvfrom` 的源地址**再断言，
而不是相信报文里的 `RESPONSE-ORIGIN`。

## 互操作矩阵（第三方实现）

单测能证明「我们自己编、自己解」自洽；**第三方能不能读我们的包**另有独立验证。
完整报告（含原始输出摘录与判定）见 [`docs/interop-matrix.md`](docs/interop-matrix.md)：

| 对手                                | 覆盖                                                          |
| ----------------------------------- | ------------------------------------------------------------- |
| coturn `turnutils_stunclient` 4.6.1 | 生产同款客户端：完整 RFC 5780 三响应、`CHANGE-REQUEST` 回包源 |
| pion/stun v3（Go）                  | 主流 WebRTC 生态的编解码 + 客户端                             |
| webrtc-rs `stun` 0.17               | Rust 生态的编解码 + 客户端（含 IPv6）                         |
| `stun-types` 2.0.5                  | 编解码 oracle（`[dev-dependencies]`，不进运行时）；长凭证请求 → 我们的 200 可被它 `validate_integrity` 验签 |
| `rstun-interop-probe.py auth-long-term` | 独立实现（`hashlib`/`hmac`）的长期凭据客户端：self-computed key/MAC |

结论：四方**双向**全绿（42 项子用例 / 203 条断言，`probe` 新增 `fingerprint` /
`fingerprint-drop` / `alternate` 三项，`auth` 项覆盖长期凭据的完整 401 → MI → 200 流程），
RFC 5769 四段标准字节全通过，`cargo-fuzz` 解析路径 600 s 零 panic / 零挂死。

`test/interop/` 里是第三方客户端夹具（Go module 与 webrtc-stun 工程源码），
`fuzz/` 是独立 workspace（`cargo +nightly fuzz run parse` 只覆盖解析/编码纯函数）。
两者都不进发布包（`Cargo.toml` 的 `exclude`）。

## License

整仓（源码、Dockerfile、README、CI 描述）采用 **Mozilla Public License 2.0（MPL-2.0）**，
全文见 [`LICENSE`](LICENSE)（官方文本逐字未改）；`Cargo.toml` 的 `license = "MPL-2.0"`。

MPL-2.0 是**文件级** copyleft：改到本仓源文件必须以 MPL-2.0 公开，但**不要求**
「更大的作品」（链接/打包它的产品）整体换证。分发二进制（Release zip /
`ghcr.io/<owner>/rstun` 镜像）时按 MPL-2.0 §3.2 告知接收方源码位置：
`https://github.com/exvlan/rstun`。

维护约定（改这里前先看）：

1. **不要**给本 crate 加 path 依赖把外部代码缝进同一个可执行文件 —— 保持「单 crate、单许可」；
2. **不要**删除或替换 `LICENSE`（改证需要单独决策，并同步 `Cargo.toml` 的 `license`）。
