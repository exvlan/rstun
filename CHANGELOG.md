# Changelog

版本线**独立于任何宿主项目**：`YY.QMM.Mmpp`（年.季度月.月日+序号），首发 `26.410.100`。
`rstun-v*` 的 Release tag / 镜像 tag / 资产名都用这里给出的版本号。

## Unreleased

### 抗滥用（默认全关）

- **每源限速**：`--rate-limit [REQ/S]`（裸写 200，突发 `2×rate`，`--rate-burst` 覆盖）、
  `--rate-limit-port [REQ/S]`（裸写 20）。64 分片 `Mutex<HashMap<…>>` 令牌桶，毫秒级
  `Instant` 精度，条目硬上限 65536（约 4 MiB），10 分钟不活跃回收 + 每 60 秒后台清扫。
- **在途上限**：`--max-inflight N`（`tokio::sync::Semaphore`）。UDP 一个 datagram 一个槽位
  （应答后释放；**只在设置了该参数时**才「每 datagram 一个任务」，否则保持串行），
  TCP 一条连接一个槽位（`accept` 取、关闭释放，挡「握手后不说话」的洪水）；
  满时 UDP 静默丢包并计数、TCP 直接关连接（不回 486 —— 与「不放大」一致）。TCP 的请求级
  限速仍每次查桶，一条连接不能流水绕过。
- **全局限速**：`--global-rate REQ/S`，与源地址无关的最后一道闸。
- **反射防护**（核心，独立成立）：含 `RESPONSE-PORT`（或带 `--alt-listen` 时的
  `CHANGE-REQUEST`）的请求，若小于 `--reflect-min-request`（默认 **20** = STUN 头长）
  或估算响应超过 `max(请求 × --reflect-ratio, 请求 + 32)`（默认 ratio **2.0**），则拒绝。
  32 = 重定向响应必带的固定属性（`XOR-MAPPED-ADDRESS` 12，`--alt-listen` 再加
  `RESPONSE-ORIGIN` + `OTHER-ADDRESS` 24）。**管辖范围内**（UDP 且确实能重定向）且
  < **40 字节**的请求，成功响应**省略可选的 `SOFTWARE`**（RFC 5389 §15.5.1）：
  28 字节探针于是得到 32 字节（无 alt，1.14×）或 56 字节（有 alt，2.00×），
  放大被压到固有下限，比例规则才真的能拒
  （例：`--alt-listen` 下 40 字节的 `CHANGE-REQUEST` + `PADDING 8` 会得到 88 > 80 → 400）。
  省略只发生在**开启防护时**：关闭防护仍是 52 字节（含 `SOFTWARE`），与 `26.410.100` 逐字节一致；
  普通 Binding、TCP 探针、无 `--alt-listen` 的 `CHANGE-REQUEST` 与 ≥ 40 字节的探针
  也照旧带 `SOFTWARE`。
  拒绝时回 `400`（40 字节），**若 400 本身也会放大（严格 `请求 × ratio`）则静默丢弃**；
  `--allow` 命中的源完全豁免反射防护。每源 IP 限速对伪造源无效，这条不依赖源地址。
- **名单**：`--allow CIDR` / `--deny CIDR`（可重复，最长前缀匹配，deny 赢平局，
  支持 IPv6 并把 `::ffff:a.b.c.d` 折叠成 IPv4）。`--allow` 只跳过每源桶**与反射防护**，
  全局限速与在途上限仍生效。判定顺序为 **名单 → 在途 → 速率**（deny 优先，运维直觉）。
- **可观测**：退出时打印 `rate_limited_ip` / `rate_limited_port` / `rate_limited_global` /
  `inflight_dropped` / `denied` / `reflect_rejected` / `allowlisted`；
  `--verbose` 下每个被拒请求带 `reason=` 与 `counter=`。**不新增 HTTP / metrics 端点**。
- **兼容性**：不给任何上述参数时**不建表、不建信号量、不起后台任务**，响应字节与
  `26.410.100` 完全一致（`plain_response_bytes_are_frozen` 与
  `enabled_guard_leaves_plain_answers_byte_identical` 锁住）；非法值（0、负数、
  `--rate-burst` 单独出现、`--reflect-min-request < 20`、`--reflect-ratio <= 0`、
  CIDR 解析失败）一律启动失败。
- 工程：tokio 只多开 `sync` feature（运行期依赖仍是那 5 个 crate）；新增
  `script/lab/rstun-abuse.sh`（关/开限速、单源洪水、反射防护默认值与严格门槛、
  allow/deny、`--max-inflight`、TCP 洪水的对照矩阵，逐条断言真实字节数与放大比，
  不需要 root/NET_RAW）。

## 26.410.100

首个独立发布（仓库 `github.com/exvlan/rstun`，整仓 MPL-2.0）。

### 协议合规（T0）

- **`420 Unknown Attribute`**（RFC 5389 §7.3.1/§15.9）：请求里出现未实现的
  comprehension-required 属性时返回 `0x0111` + `ERROR-CODE 420` +
  `UNKNOWN-ATTRIBUTES`（`0x000A`）。值长度恰为 `2×N`（N=1/2/3 → 2/4/6 字节），
  不足 4 字节由通用 TLV padding 补齐且**不计入** Length —— **不重复末项**
  （那是 RFC 3489 的写法，5389 已删除该规则）。
- **「已知属性」表**：显式收录鉴权簇（`USERNAME` / `MESSAGE-INTEGRITY` /
  `MESSAGE-INTEGRITY-SHA256` / `REALM` / `NONCE` / `PASSWORD-ALGORITHM` / `USERHASH`）
  与 ICE 簇（`PRIORITY` / `USE-CANDIDATE` / `ICE-CONTROLLED` / `ICE-CONTROLLING`），
  它们**不**触发 420 —— 否则正常 ICE 客户端会被打死。
- **`MAPPED-ADDRESS`**（RFC 5389 §15.1）新增 `--mapped-address` 开关，**默认关闭**；
  关闭时响应字节与拆分前**逐字节一致**（`plain_response_bytes_are_frozen` 冻结测试锁住）。
- **`RESPONSE-PORT`**（RFC 5780 §7.5）：按**目的端口**语义实现 —— 响应发往
  「请求的源 IP + 指定端口」，**源 IP / 源端口不变**；仅 UDP。
- **`PADDING`**（RFC 5780 §7.6）：回显且**永不放大**。
  有意偏离 §6 对响应侧 PADDING 的 SHOULD（「按出接口 MTU 补齐」）：我们回显请求长度，
  理由是「无放大风险 / 行为确定 / 易测」，详见 README「有意偏离」。
- **`PADDING` + `RESPONSE-PORT` 同时出现 → `400 Bad Request`**（RFC 5780 §10 MUST）。

### 多地址 / IPv6 共存

- `--alt-listen` **不再要求「恰好一个地址」**：`--listen` / `--listen-v6` 均可重复，
  **primary = 命令行顺序里第一个 IPv4 `--listen`**（不排序、不猜），其余 v4 地址与
  全部 `--listen-v6` 只做普通 Binding：不带 `RESPONSE-ORIGIN` / `OTHER-ADDRESS`，
  收到 `CHANGE-REQUEST` 按 §5 忽略（仍从原 socket 回包）。
- `--listen-v6` 以 **v6-only** 绑定，可与 `--listen` 同端口共存，且**不参与** primary 选择。
- `--tcp` 与 `--alt-listen` 可同时开启（TCP 上 `CHANGE-REQUEST` / `RESPONSE-PORT` 被忽略）。

### 互操作验证（T1）

- **四方矩阵全绿**：coturn `turnutils_stunclient` 4.6.1、pion/stun v3.1.7、
  webrtc-rs `stun` 0.17.3、`stun-types` 2.0.5，双向（他们发 → 我们答；我们发 → 他们答），
  共 38 项子用例 / 176 条断言。
- **RFC 5769 §2.1–§2.4** 四段标准字节全部通过（§2.2/§2.3 的 `XOR-MAPPED-ADDRESS`
  可逐字节重建）。
- **`cargo-fuzz` 解析路径 600 s**：`Done 84319569 runs in 601 second(s)`，零 panic、零挂死。
- 报告与原始输出摘录见 [`docs/interop-matrix.md`](docs/interop-matrix.md)。

### 工程

- 仓库独立：无 workspace、无 path 依赖，`cargo tree -e normal` 只有
  `clap` / `socket2` / `tokio` / `tracing` / `tracing-subscriber`（`stun-types` 仅测试用）。
- `Cargo.lock` 随源码提交；`rust-toolchain.toml` 固定 1.95（rustfmt + clippy）。
- 构建版本注入统一用 **`RSTUN_BUILD_VERSION`**（`<version>+<sha6>`）；
  `EXVLAN_BUILD_VERSION` 仅作为旧构建链路的兼容回落保留。
- CI：三平台单测 + fmt/clippy + UDP/TCP 冒烟 + IPv6 冒烟；
  发布：四平台 zip + `ghcr.io/<owner>/rstun` 双架构（amd64/arm64）镜像。
