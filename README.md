# rstun

独立 STUN 服务器：RFC 5389 Binding，加可选的 RFC 5780 NAT 行为发现。
一个 crate、一个二进制、一个镜像，`cargo install` 就能跑，不依赖任何宿主项目。

**范围声明（先读）**：本服务**只做 STUN** —— RFC 5389 Binding（+ 可选的 RFC 5780 NAT 行为
发现）。**不做 TURN**（`Allocate` / `Refresh` / `Channel` 一律 `400`），**不做任何鉴权**，
没有租户、配置文件和数据库。需要 TURN 中继或按用户鉴权时请用 coturn，不要往这里加。

**命名**：crate 与二进制都叫 `rstun`。**绝对不能改叫 `stun`** —— Debian 的 `stun-client`
包已经占用 `/usr/bin/stun`，同名会直接撞包/覆盖。

**许可**：整仓 **MPL-2.0**（`LICENSE`），边界见文末 [License](#license)。

CLI 分两级：`rstun server [flags]` 起服务（flag 语义自首个版本起未变），裸 `rstun` 打印帮助。

```
$ rstun --help
Standalone STUN Binding server (RFC 5389; RFC 5780 with --alt-listen; TCP with --tcp)

Usage: rstun <COMMAND>

Commands:
  server  Serve STUN Binding over UDP (and TCP with --tcp)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

$ rstun server --help
Serve STUN Binding over UDP (and TCP with --tcp)

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
| `Binding Request` + `PADDING`（RFC 5780 §7.6）                                                      | 响应**带同样长度**的 `PADDING`（永远不超过请求长度），用于 MTU / 分片探测；`PADDING` 恒为最后一个属性                                                                                       |
| `Binding Request` + `RESPONSE-PORT` + `PADDING`                                                     | `400 Bad Request`（RFC 5780 §6："the server MUST return an error response of type 400"；§7.5 `MUST NOT process` 与 §10 `are rejected` 同指这条）                                            |
| `Binding Request` + 未知的 **comprehension-required** 属性（如 `0x0033`）                           | `420 Unknown Attribute`（`0x0111`）+ `ERROR-CODE 420` + `UNKNOWN-ATTRIBUTES`（`0x000A`，每个类型 2 字节，值长度恰为 `2×N`；不足 4 字节的由通用 TLV padding 补齐且**不计入** Length，§15.9） |
| 其它 method 的 **request**（如 TURN `Allocate` `0x003`）                                            | 该 method **自己的** `4xx` 错误响应 + `ERROR-CODE 400 Bad Request`（RFC 5389 §7.3.1）                                                                                                       |
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
- 退出：Ctrl-C 与 Unix `SIGTERM`（systemd / `docker stop` 都走 SIGTERM），退出前打印
  `received / answered / dropped` 统计；开了抗滥用时前面还有一行 `abuse guard counters`。
- 日志只走 stdout/stderr（`tracing`）：`RUST_LOG` 优先，否则 `--verbose` → `debug`，
  默认 `info`。**不写滚动文件**（容器/systemd 自己采集）。

### RFC 支持子集

| RFC | 覆盖 | 说明 |
| --- | --- | --- |
| **RFC 5389** | 服务端全行为 | Binding、`XOR-MAPPED-ADDRESS`、`SOFTWARE`、`MAPPED-ADDRESS`（可选）、`ERROR-CODE`（300/400/420/500）、`UNKNOWN-ATTRIBUTES`、`FINGERPRINT`（`--check-fingerprint` 校验）、`ALTERNATE-SERVER`（`--alternate-server`） |
| **RFC 5780** | 全量 | `CHANGE-REQUEST` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `RESPONSE-PORT` / `PADDING`（四条 change 路径，见下文） |
| **RFC 8489** | 属性处理 | `MESSAGE-INTEGRITY-SHA256` / `PASSWORD-ALGORITHM` / `USERHASH` 在「已知属性」表内（不触发 420）；`PASSWORD-ALGORITHMS`（`0x8002` 类）属 comprehension-optional，按 §7.3.1 直接忽略。鉴权本身属独立任务（`rstun-auth`），本服务**不发** 401/438 |
| **RFC 8445（ICE）** | 属性容忍 | `PRIORITY` / `USE-CANDIDATE` / `ICE-CONTROLLING` / `ICE-CONTROLLED` 不触发 420 |

### 错误码矩阵

| 码 | 触发 | 备注 |
| --- | --- | --- |
| `300` | 配置了 `--alternate-server`（每个 Binding 请求） | 带 `ALTERNATE-SERVER`；**不带** `XOR-MAPPED-ADDRESS`；优先于 RFC 5780 与 420 |
| `400` | 非 Binding 方法；`PADDING` + `RESPONSE-PORT`；`FINGERPRINT` 不在末位 / 值不匹配（默认） | 不带 `UNKNOWN-ATTRIBUTES` |
| `420` | 请求带未知 comprehension-required 属性 | 带 `2N` 字节的 `UNKNOWN-ATTRIBUTES` |
| `438` | nonce 过期 | **未实现**（属 `rstun-auth`）；本服务不会发出 |
| `500` | 响应编码不变量被破坏、`send_to` 失败、内部不可恢复错误 | 固定文案 `Server Error`，固定 **40 字节**，不泄露 `io::Error` |

`--check-fingerprint` / `--alternate-server` 两个开关**默认关闭**：不给它们时，任何请求的响应字节与
`26.410.100` 完全一致（`plain_response_bytes_are_frozen` 与 27 组「旧二进制 vs 新二进制」逐字节对照）。

### 420 与「已知属性」表

RFC 5389 §7.3.1 要求：请求里出现**服务端没实现的 comprehension-required 属性**（类型 `< 0x8000`）时，
必须回 `420` 而不是硬着头皮应答。实现里这张「已知属性」表（`protocol::is_known_attribute`）是**判定的唯一依据**，
除了自己实现的属性，还显式收录了两类「理解但不用」的属性：

| 类别           | 属性                                                                                                                                                                           | 为什么不能算未知                                               |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| 鉴权（未实现） | `USERNAME` `0x0006`、`MESSAGE-INTEGRITY` `0x0008`、`MESSAGE-INTEGRITY-SHA256` `0x001C`、`REALM` `0x0014`、`NONCE` `0x0015`、`PASSWORD-ALGORITHM` `0x001D`、`USERHASH` `0x001E` | RFC 5389 §10.2.2 允许客户端主动带；RFC 3489 时代客户端会顺手带 |
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

两个开关都**默认关闭**；关闭时既不二次解析、也不改任何字节（27 组「旧二进制 vs 新二进制」逐字节
对照覆盖普通 Binding / SOFTWARE / FINGERPRINT / 420 / PADDING / RESPONSE-PORT / CHANGE-REQUEST / 400
× 默认 / `--mapped-address` / `--alt-listen`）。

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

### 未实现（有意）

- TURN（`Allocate`/`Refresh`/`Channel`）、鉴权（401/438）。
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

## 与 coturn 的差异

|      | `rstun`                                                                                                                                                                                         | coturn                                        |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| 定位 | 只做 STUN，Binding + **NAT 行为发现**的**最小服务**                                                                                                                                             | 完整 STUN/TURN（中继）+ 鉴权 + 多租户         |
| 协议 | RFC 5389 Binding + `SOFTWARE` + `MAPPED-ADDRESS`（可选）+ `UNKNOWN-ATTRIBUTES`/420 + `FINGERPRINT`/300/500（两个开关）；RFC 5780 的 `CHANGE-REQUEST` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `RESPONSE-PORT` / `PADDING`（无 TURN） | RFC 5389 / 5780 全量 / TURN（5766、turns 等） |
| 配置 | 纯命令行参数（无配置文件）                                                                                                                                                                      | 上百行 `turnserver.conf`、数据库/鉴权后端     |
| 依赖 | 纯 Rust，无 OpenSSL/libevent                                                                                                                                                                    | 依赖 libevent/OpenSSL + 系统配置              |
| 部署 | 单二进制 / 一个几十 MB 的镜像                                                                                                                                                                   | 发行版包 / 官方镜像 + 配置卷                  |
| 用途 | 需要「公网 STUN 映射 + NAT 行为发现」、不需要中继的场景                                                                                                                                         | 需要 TURN 中继、按用户鉴权的通用基础设施      |

结论：**需要 TURN 中继时仍然用 coturn**。本服务负责「公网 STUN 映射 + NAT 行为发现」这一段，
把它部署到 UDP 回程可用的地址上即可。

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

## 健康检查

镜像**没有** `HEALTHCHECK`：镜像里没有 curl / python / STUN 客户端，也没有 HTTP 就绪端点，
容器内做假探针只会掩盖问题。建议在**外部**探测：

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

## systemd 样例

```ini
# /etc/systemd/system/rstun.service
[Unit]
Description=rstun (STUN Binding + RFC 5780 NAT behaviour discovery)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 单独的运行用户即可，不需要任何 capability
User=rstun
Group=rstun
# 只做 RFC 5389（单地址，可用通配）：
# ExecStart=/usr/local/bin/rstun server --listen 0.0.0.0:3478 --listen-v6 [::]:3478 --tcp
# 启用 RFC 5780：两个公网 IP 都要写具体地址（不能是 0.0.0.0）
ExecStart=/usr/local/bin/rstun server --listen 203.0.113.10:3478 --alt-listen 198.51.100.20:3478 --alt-port 3479 --tcp
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
# SIGTERM 是缺省停止信号；服务自己会打印统计后退出
KillSignal=SIGTERM
TimeoutStopSec=5

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

## 依赖面

运行期依赖只有 5 个 crates.io 包，没有任何 path 依赖：

```
clap  socket2  tokio  tracing  tracing-subscriber
（dev-only: stun-types 2.0.5 —— 只用做编解码的参考实现 oracle，不进二进制）
```

`stun-types` 在 `[dev-dependencies]` 里，`cargo tree -e normal` 看不到它。编解码是手写的：
`stun-types` 缺全部 RFC 5780 属性，把运行时交给第三方库也换不来协议覆盖，只会多几层依赖。

## 测试

```bash
cargo test          # 141 个单测：3 crc32 + 30 protocol + 7 rfc5780 + 67 server + 27 limit + 7 interop
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
| `stun-types` 2.0.5                  | 编解码 oracle（`[dev-dependencies]`，不进运行时）             |

结论：四方**双向**全绿（41 项子用例 / 191 条断言，`probe` 新增 `fingerprint` /
`fingerprint-drop` / `alternate` 三项），RFC 5769 四段标准字节全通过，
`cargo-fuzz` 解析路径 600 s 零 panic / 零挂死。

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
