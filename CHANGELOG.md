# Changelog

版本线**独立于任何宿主项目**：`YY.QMM.Mmpp`（年.季度月.月日+序号），首发 `26.410.100`。
`rstun-v*` 的 Release tag / 镜像 tag / 资产名都用这里给出的版本号。

## Unreleased

### 鉴权（RFC 5389 §10 短期/长期 + RFC 8489 §9.2，**默认关闭**）

- **短期凭据**（`--auth-user` + `--auth-pass`，或 `--auth-file` 多用户）：key = 口令
  （RFC 5389 §15.4），校验 `MESSAGE-INTEGRITY`（HMAC-SHA1）。缺 `USERNAME`/`MESSAGE-INTEGRITY`
  → `400`（§10.1.2）；未知用户/口令不符 → `401`。**没有任何凭据配置时行为与 `26.410.100`
  逐字节一致**（17 请求 × 3 配置对照 + 冻结测试）。
- **长期凭据**（`--realm` + `--auth-secret` + `--auth-file`/`--auth-user`）：无凭据 → `401`
  （`REALM` + `NONCE` + `PASSWORD-ALGORITHMS`）；nonce 过期 → `438` + 新 `NONCE` + `REALM` +
  `PASSWORD-ALGORITHMS`；口令/用户/realm 不符 → `401`。key = `MD5(username:realm:password)`。
  **缺失 ≠ 无效**：缺 `REALM` / `NONCE` / 身份属性（`USERNAME` 与 `USERHASH` 都缺）→ `400`，
  值不对 → `401`（RFC 8489 §9.2.4）。
- **RFC 8489 的 SHA256 / PASSWORD-ALGORITHM(S) / USERHASH**（**不是**「8489 全量」：
  nonce cookie 与 `SECURITY-FEATURE` 位未实现，见 README「未实现（有意）」）：
  `MESSAGE-INTEGRITY-SHA256`（key = `SHA256(user:realm:pass)`）、`PASSWORD-ALGORITHM`
  协商（缺省 MD5，coturn 兼容）、`PASSWORD-ALGORITHMS` 广告、`USERHASH`
  （**§14.4，完整 32 字节** `SHA256(user:realm)`；16 字节截断值按值无效回 401）。
  `--auth-require-sha256` 拒绝 MD5 凭据（401）。
- **无状态 nonce**：`base64url( expiry(5B) | HMAC-SHA256(secret, expiry|client_ip)[..11] )`，
  默认 1 小时（`--nonce-lifetime`）。同一 `--auth-secret` 的实例互认对方的 nonce，
  重启不失效，**没有服务端表**。过期判定严格（设计稿的 ±5 分钟宽限未实现，见 README 说明）。
- **响应也签**：通过鉴权的 **200 / 420 / 400** 都带与请求同算法的 `MESSAGE-INTEGRITY` /
  `MESSAGE-INTEGRITY-SHA256`（RFC 5389 §10.2.2），`stun-types` 的 `validate_integrity`
  可以验签。**`500` 不签名**（在 `decide` 之下的发送/编码失败路径上拿不到 identity）。
- **判定顺序**：准入（限速/反射防护）→ FINGERPRINT → 300 → **鉴权** → 420 → 400 组合 → 应答。
  `300` 先于鉴权（重定向不需凭据），FINGERPRINT 先于鉴权；`401`/`438` 同样先过限速桶。
- **放大面（已登记）**：`401` 与 `438` 都是 **96 字节**（realm `example.org`；对 20B 请求
  4.80×、对 28B 3.43×），带 MI 的 200 = 76 字节。**开鉴权必须同时开限速**；配了凭据但没开
  任何抗滥用开关时启动即 `warn`。开鉴权会打断匿名 ICE（README 明写）。反射防护在开启鉴权时
  按「签名后的成功响应」与「401 挑战」的较大者估算，避免把 96B 的 401 按 76B 估低。
- **依赖 5 → 9**：`hmac` / `sha1` / `sha2` / `md-5`（RustCrypto，纯 Rust、无 C）。
  常量时间比较自写（`auth::ct_eq`），没有引入 `subtle` 作为直接依赖；自写 base64url（22 字符
  nonce），没有引入 `base64`。
- **非法配置启动失败**：`--auth-user` 缺 `--auth-pass`（及反向）、`--realm` 缺 `--auth-secret`
  （及反向）、`--realm` 无用户、`--nonce-lifetime 0`、`--nonce-lifetime` 无 `--realm`、
  `--auth-require-sha256` 无 `--realm`、`--auth-file` 读不到/格式错/空文件。
- **互操作**：新增 `rstun-interop.sh auth` 项（独立 Python 客户端算 key/MAC：401 → MI → 200
  → 验签 → 错口令 401 → 32 字节 `USERHASH` 200 / 16 字节 401，15 条断言，矩阵 41→42 项 /
  191→203 条）；`tests_interop` 新增
  `stun-types` 长凭证请求双向（SHA1 + SHA256）；`auth` 模块用 RFC 5769 §2.4 原文向量
  （`MESSAGE-INTEGRITY = f6702465…`）锁死校验侧公式。

### 协议闭环（`500` / `FINGERPRINT` / `ALTERNATE-SERVER` / RFC 8489 语义）

- **`500 Server Error`**（RFC 5389 §15.6）：`send_to` 失败（除 `ConnectionRefused` /
  `NetworkUnreachable` / `AddrNotAvailable` 这类客户端地址问题）与内部不变量失败时回 `500`，
  不再是只写日志。响应固定 **40 字节**、固定文案 `Server Error`；`io::Error` 只进日志，
  不泄露路径/errno，也不构成放大面。
- **`FINGERPRINT` 校验**（RFC 5389 §15.5）：`--check-fingerprint`（默认关闭）。存在时必须
  **是最后一个属性**且值恰好 4 字节；值 = `CRC32(消息中该属性之前的字节) XOR 0x5354554e`，
  CRC 覆盖范围**包含「Length 已计入该属性」的头部**（§15.5 原文，与 RFC 5769 §2.1–§2.3 的
  标准字节一致）。不匹配 → `400`；`--fingerprint-action drop` 时静默丢弃并计数
  （`fingerprint_rejected`，同时 +1 `dropped`）；结构错误（非末位 / 长度非 4）永远 `400`。
  关闭时 `FINGERPRINT` 照旧被忽略，字节不变。
- **`ALTERNATE-SERVER` / `300 Try Alternate`**（RFC 5389 §15.11）：`--alternate-server <ip:port>`
  （可重复，只取第一个）。配置后**所有** Binding 请求回 `300` + `ALTERNATE-SERVER`
  （明文 `0|family|port|address` 布局），**重定向优先于 RFC 5780**（带 `CHANGE-REQUEST` /
  `RESPONSE-PORT` 也回 300，且从入口 socket 回）；非 Binding 方法仍是 400。
  IPv4 响应 56 字节 / IPv6 68 字节；**裸 Binding 的 300 不在反射防护域**，带 `RESPONSE-PORT` /
  `CHANGE-REQUEST` 的请求仍受防护管辖，且估算的是实发的 300（不是不会被发送的成功响应）。
- **RFC 8489 属性语义**：未开鉴权时 `MESSAGE-INTEGRITY-SHA256` / `PASSWORD-ALGORITHM` /
  `USERHASH` 按「理解但不用」忽略（不触发 420）；鉴权本身见上面「鉴权」一节。
- **CRC-32 自实现**：新增 `src/crc32.rs`（IEEE 查表，`const fn` 建表），本轮零新依赖
  （`cargo tree -e normal --depth 1` 当时仍是 5 个；鉴权带来的 4 个见上面「鉴权」一节）；
  RFC 5769 §2.1 的 `0xe57a3bcf` 作为向量锁死。
- **兼容性**：两个开关都不给时行为/字节与 `26.410.100` 完全一致
  （`plain_response_bytes_are_frozen` + 68 组「旧二进制 vs 新二进制」逐字节对照：
  17 个请求 × 默认 / `--mapped-address` / `--alt-listen` / `--check-fingerprint`）。
- **互操作**：`tests_interop` 新增 `300` / `500` 的 `stun-types` 解码与 RFC 5769 FINGERPRINT
  校验；互操作矩阵 `probe` 新增 `fingerprint` / `fingerprint-drop` / `alternate` 三项，
  共 **42 项子用例 / 203 条断言**。

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
- 工程：tokio 只多开 `sync` feature（本轮没有新增依赖；鉴权的 4 个 crate 见上面）；新增
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
