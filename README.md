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
      --listen <ADDR>      address to bind over UDP (and TCP with --tcp), repeatable; defaults to
                           0.0.0.0:3478. With --alt-listen the first IPv4 address here is the RFC
                           5780 primary; every other address (and all --listen-v6) only serves plain
                           Binding
      --listen-v6 <ADDR>   IPv6 address to bind, repeatable; bound v6-only so it can coexist with
                           --listen. Never part of RFC 5780: these sockets only serve plain Binding
      --alt-listen <ADDR>  second public IP (RFC 5780 "other address"); enables CHANGE-REQUEST,
                           RESPONSE-ORIGIN and OTHER-ADDRESS. Only the IP is used: the port comes
                           from --alt-port. Primary = the first IPv4 --listen address; other
                           addresses (including --listen-v6) stay plain Binding
      --alt-port <PORT>    RFC 5780 "other port"; defaults to the --listen port + 1. Used as the
                           source port of a `CHANGE-REQUEST` answer and as half of `OTHER-ADDRESS`.
                           (`RESPONSE-PORT` names a *destination* port and never refers to this.)
      --tcp                also answer STUN Binding over TCP on every listen address
      --mapped-address     also emit the legacy MAPPED-ADDRESS (0x0001) next to XOR-MAPPED-ADDRESS,
                           for RFC 3489-era clients; off by default (response bytes stay unchanged)
      --verbose            log every Binding request with its source and mapped address
  -h, --help               Print help
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
- 退出：Ctrl-C 与 Unix `SIGTERM`（systemd / `docker stop` 都走 SIGTERM），退出前打印
  `received / answered / dropped` 统计。
- 日志只走 stdout/stderr（`tracing`）：`RUST_LOG` 优先，否则 `--verbose` → `debug`，
  默认 `info`。**不写滚动文件**（容器/systemd 自己采集）。

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

### 未实现（有意）

- TURN（`Allocate`/`Refresh`/`Channel`）、鉴权。
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

## 与 coturn 的差异

|      | `rstun`                                                                                                                                                                                         | coturn                                        |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| 定位 | 只做 STUN，Binding + **NAT 行为发现**的**最小服务**                                                                                                                                             | 完整 STUN/TURN（中继）+ 鉴权 + 多租户         |
| 协议 | RFC 5389 Binding + `SOFTWARE` + `MAPPED-ADDRESS`（可选）+ `UNKNOWN-ATTRIBUTES`/420；RFC 5780 的 `CHANGE-REQUEST` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `RESPONSE-PORT` / `PADDING`（无 TURN） | RFC 5389 / 5780 全量 / TURN（5766、turns 等） |
| 配置 | 7 个命令行参数，无配置文件                                                                                                                                                                      | 上百行 `turnserver.conf`、数据库/鉴权后端     |
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
cargo test          # 75 个单测：25 protocol + 7 rfc5780 + 38 server + 5 interop
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
  我们能**逐字节重建**；`stun-types` 2.0.5 双向（它编的请求我们解、我们编的响应它解，
  含 `MAPPED-ADDRESS` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `PADDING`）。

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

结论：四方**双向**全绿（38 项子用例 / 176 条断言），RFC 5769 四段标准字节全通过，
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
