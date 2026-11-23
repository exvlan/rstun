# Changelog

版本线**独立于任何宿主项目**：`YY.QMM.Mmpp`（年.季度月.月日+序号），首发 `26.410.100`。
`rstun-v*` 的 Release tag / 镜像 tag / 资产名都用这里给出的版本号。

## 26.410.106-dev.0

### 发布产物 keyless 签名（cosign + OIDC）

- Release 资产新增 `SHA256SUMS`（覆盖 13 个核心产物的裸文件名哈希）与 3 个 cosign bundle
  （`SHA256SUMS` + lean/full 两份 SBOM），签名时共 **17** 个资产。签清单而不是逐个签二进制：
  签名数从 10 降到 1，而每个资产的字节仍被清单绑定。**发布产物不再「未签名」**。
- 容器镜像以**同一身份**对 **manifest list digest** 签名（存为 registry 的 OCI 附件，不增加 Release
  资产位）；不使用逐平台递归签名 —— 下游固定的就是 index。
- `release.yml` 新增 `sign` 输入（默认 `true`）与 `id-token: write`；`sign=false` 仅作应急逃生口
  （不产生清单/bundle，发布说明明示「本版未签名」）。签名失败 = 发布失败（不发「声称已签名」的资产）。
- **`sign=true` 只允许从 tag ref 触发**：`prepare` 新增 `Require tag ref when signing` 守卫 ——
  证书身份绑在触发 ref 上（`@refs/tags/rstun-v<version>`），从 `main` dispatch 会得到 `@refs/heads/main`
  并在说明里写出假身份。手工发版请用 `gh workflow run release.yml --ref rstun-v<version> -f version=…`；
  要从分支发版必须显式 `-f sign=false`。
- **预发布自动标 `--prerelease`**：版本号含 `-`（如 `26.410.106-dev.0`）时 `gh release create` 带
  `--prerelease`，已存在的 Release 用 `gh release edit --prerelease=<true|false>` 幂等校正，发布说明
  首行提示「不建议生产使用」。修的是 dev 演练暴露的真实缺陷：漏标让 `/releases/latest` 指向 dev，
  而 tap 的 `sync.yml` 读 latest → `brew install` 会被切到预发布。
- **预发布 deb 的文件名统一用 `-`**：`build-deb.sh` 在 nfpm 打包后把文件名里的 `~` 改成 `-`
  （`rstun_26.410.106-dev.0_amd64.deb`），**包内 Debian `Version:` 仍是 `~`**（`26.410.106~dev.0`）。
  原因：GitHub Release 会把资产名里的 `~` 改写成 `.`，导致 `SHA256SUMS`（按本地名算）与用户下载到的
  名字不一致、`sha256sum -c` 全红；`release.yml` 的暂存步骤另加「不得含 `~`」的断言，
  `post-release-verify` 的 deb 断言同时接受两种 `Version:` 形式。
- `post-release-verify` 新增 `require_signature`（默认 `true`）：逐个 `cosign verify-blob` 把证书身份
  绑定到**本仓 `release.yml` + 该 tag**（issuer = GitHub OIDC），再用 `SHA256SUMS` 校验每个资产的哈希，
  并 `cosign verify <digest>` 校验镜像签名。回看签名上线前的历史版本传 `false` 只告警。
- 新增文档页「验证发布产物（cosign keyless）」（`docs/book/src/verify.md`），README 给出可照抄的三条命令。

### 定时作业可见性（维护者可见）

- 新增 **`schedule-guard`**（每日 06:00 UTC + 每次 push 到 `main` + 手动可调）：检查
  `QA scheduled` / `Verify platforms` 最近一次 `event=schedule` 运行的年龄，超过 **8 天**或
  **从未运行** → 建一条固定标题的 issue（同标题去重，恢复后自动评论并关闭）。背景：本仓实测
  `event=schedule` 运行数为 **0**（两个 workflow 状态都还是 `active`），周度回归可能长期静默未跑。
  `push` 触发是刻意的：cron 整体失效时，只靠 cron 的守卫自己也跑不起来。
  手动 `workflow run` 补跑**不算** schedule 运行，不会清掉告警。

## 26.410.105

### TURN：证书轮询可关闭 / 可调（`--tls-cert-poll`）

- 新增 `--tls-cert-poll <SECONDS>`：默认 **30**（不传时与 .104 逐行为一致）；`0` = **不启动
  轮询任务**，只认 `SIGHUP`；其它正整数 = 轮询间隔（秒）。只用信号轮换的部署（例如侧车写完
  两张文件再发信号）不再在「先写 cert 后写 key」的窗口里收到一次
  `reload_total{result="failed"}` 噪音。
- **半配置仍拒绝启动**：给了该 flag 却没有 `--turn-tls-listen`/`--turn-dtls-listen` →
  启动失败（与 `--tls-cert`/`--tls-key` 同一条规则）；lean 构建给出它同样以
  `` `tls` feature `` 拒绝。Windows 没有 `SIGHUP`，轮询是唯一触发，因此 `0` 启动即被拒绝。
- `RSTUN_TLS_CERT_POLL` 同步映射；指标不变（`rstun_turn_tls_reload_total` /
  `rstun_turn_tls_cert_expires_seconds`）。
- lab 新增 `cert-poll` 项：无 secure 监听 + flag → 拒绝启动；`0` 下改文件 4s **不**重载而
  `SIGHUP` 重载；`2s` 下改文件约 2s 内重载。

### 依赖

- `x509-parser 0.16 → 0.18.1`（证书到期 gauge 的解析器，仅 `tls` 构建）。
  `cert-reload` lab 复验：`expires` 与 `openssl x509 -enddate` **drift 0s**，解析语义未变。

### 发布与回归自动化（维护者可见）

- **发版前预检 `release-preflight`**（只读）：版本钉死点、测试/clippy/fmt、interop 矩阵、
  TURN lean/full、SBOM、deb/brew 渲染、`cargo publish --dry-run` 一次跑完，结论写 step summary。
- **发布后验收 `post-release-verify`**（只读）：13 资产命名、四平台 zip 架构、`--version` 与 tag
  指向一致、两个 deb 的版本/架构、Homebrew formula 类体与 3 个 sha256、镜像 amd64+arm64 manifest。
- **CI 新增 `version-pins` 与 `packaging` 作业**：6 处版本钉死点必须等于 `Cargo.toml`；
  `cargo package` 的清单断言（不含夹具/密钥）与 `cargo publish --dry-run` 提前暴露打包问题。
- **crates.io 自动发布**（`publish-crates`，`release.yml` 内并行作业）：**幂等**（已发布即跳过，
  重跑不红）；版本必须等于检出树的 `Cargo.toml`。
- **`release-prep` 一键发版**：bump `Cargo.toml`/lock、收口 `## Unreleased`、同步 6 处钉死点、
  commit/push、打 tag、dispatch release；`dry_run` 默认 `true`（只出预演，不写远端）。
- **Homebrew tap 自动同步**：`exvlan/homebrew-rstun` 每日 05:30 UTC 反向拉取最新 Release 的
  formula（内容不变则不提交，零 PAT）。

## 26.410.104

### TURN：`turns:` / DTLS 证书热加载（`SIGHUP` + 30s 轮询，免重启）

- **不再重启轮换证书**：把 `--tls-cert`/`--tls-key` 指向的**同一路径**原地覆盖后，
  `kill -HUP <pid>`（Linux/macOS）立即重读；Windows 或不愿发信号时靠 **30s 文件轮询**
  （比对两条路径的 `(mtime,len)`，最坏 30s 生效）。两条触发路径共用同一个
  `load_secure_material`，热载规则与启动规则**逐字相同**。
- **整体原子替换**：一次成功重载重建并替换整个 `rustls::ServerConfig` + `webrtc_dtls::Config`，
  TLS 与 DTLS **同时**生效，不存在「一半新一半旧」。新连接/新 DTLS 会话用新证书；**已建立
  会话保持旧证书**（TLS 1.2/1.3 与 DTLS 均无重协商）。
- **会话恢复**：本实现**从未启用** TLS 会话恢复（`ServerConfig::builder()` 的 rustls 默认是
  `NoServerSessionStorage` + `NeverProducesTickets`），所以重载不影响恢复行为，也不存在
  「首批连接 vs 之后」的差异 —— 每条连接本来就是完整握手。若将来开启恢复，整体替换
  `ServerConfig` 才会清空 TLS 1.2 缓存与 TLS 1.3 ticket key。
- **失败保留旧材料**：不配对、RSA（DTLS 监听下）、非 PKCS#8、截断、空文件等一律拒绝本次重载
  并继续服务旧证书 —— **绝不降级明文、不关闭监听**。失败后 1s 重试一次以跨过「先写证书再写
  私钥」的半写窗口，两次都失败才计一次失败。
- **新指标（固定标签集，仅配了 `turns:`/DTLS 监听时出现）**：
  `rstun_turn_tls_reload_total{result=ok|failed}`、
  `rstun_turn_tls_cert_expires_seconds`（当前 leaf 的 `notAfter − now`，与
  `openssl x509 -enddate` 一致；负值=已过期，`-1`=无法解析）。退出日志同时打印
  `reload_ok`/`reload_failed`/`cert_expires_seconds`。
- **依赖**：新增直接依赖 `x509-parser 0.16`（**optional，仅 `tls` feature**）读证书有效期。
  它本来就在 `Cargo.lock`（`webrtc-dtls` 的传递依赖），**不新增 crate**；lean 构建不受影响。
  unix full 直接依赖 14 → **15**（Windows 13 → 14），`script/ci/gen-sbom.sh` 与 README 同步。
- lab 新增 `cert-reload` 项：SIGHUP 后 TLS/DTLS 新连接指纹同时变化、**已建立的 TLS 会话
  跨重载仍能应答**、轮询路径换第三张证书、坏密钥对保留当前证书且
  `reload_total{result="failed"}` 增长、到期 gauge 与 `openssl` 差 ≤60s。
- **默认路径不变**：全部代码在 `tls` feature 内；不带 `--turn-tls-listen`/`--turn-dtls-listen`
  时没有重载任务、没有新指标，字节冻结（3 配置 × 17 请求）照旧。

### TURN：RFC 6062 出站 TCP allocation（`--turn-tcp-relay`）

- **新开关 `--turn-tcp-relay`（默认关）**：打开后 `Allocate` 的 `REQUESTED-TRANSPORT=6`
  从 `442` 变为真正的 TCP allocation —— 返回一个 TCP relay 地址（无 `CONNECTION-ID`），
  `Connect` 从该地址出站连 `XOR-PEER-ADDRESS`（超时 ≥30s、失败 `447`、重复 `446`、禁用地址
  `403`、每 allocation 上限 16 条 → `508`），`ConnectionBind` 在**新连接**上绑定后该连接变成
  **裸字节**数据面（不再解析 STUN）。**开关关闭时行为逐字节不变**（`Allocate(TCP)` 仍 `442`）。
- **被动模式不做**：`ConnectionAttempt`（peer 主动连入 relay）不在本版范围，因此
  `turnutils_uclient -T`（隐含 `-y`）不能作为验收判据；lab 用自带探针的 `tcp-relay`
  模式跑标准客户端流程（与 coturn 同输出）。
- **语义细节**：UDP/DTLS 控制连接上申请 TCP allocation → `400`；带
  `DONT-FRAGMENT`/`EVEN-PORT`/`RESERVATION-TOKEN` → `400`；`CreatePermission` 正常 `200`
  （`turnutils_uclient -T` 会先发它）；`ChannelBind` → `400`；`Send`/`ChannelData` 丢弃并计
  `tcp_send`；预绑定缓冲上限 64 KiB（超限关连接 + `tcp_buffer`）、pending 30s 未 bind 关闭；
  `LIFETIME=0`/过期关闭全部数据连接而**保留控制连接**（与 coturn 的差异已记录）。
- **`Connect` 成功响应不带 `SOFTWARE`**（coturn 同为 32 字节响应），其余响应照旧。
- **指标**：新增 `rstun_turn_tcp_connections{state=pending|bound}` 与
  `rstun_turn_rejected_total{reason=tcp_connect|tcp_bind|tcp_send|tcp_buffer|tcp_quota}`；
  `--turn` 关闭时仍整体省略。
- **资源口径**：TCP 中继端口用独立端口池（与 UDP 同段但不共享槽位）；数据连接是 accepted
  TCP 连接，占一个 `--max-inflight` 名额；`Connect` 从 relay 地址出站依赖 `SO_REUSEPORT`
  （Windows 回退为临时源端口）。
- `--turn-bandwidth` 不作用于 TCP allocation 的裸字节流（逐包丢弃会破坏流），只统计
  `rstun_turn_bytes_total`；UDP 中继的带宽语义不变。
- lab 新增 `tcprelay` 项；`cleanup` 的残留断言同时检查 UDP（`ss -lun`）与 TCP（`ss -ltn`）。
- **Windows 修正（CI 抓到的两处平台假设）**：TCP Allocate 带 `DONT-FRAGMENT` 不再被 420 gate
  拦成 `420`（RFC 6062 §5.1 步骤 3 要求 `400`，UDP Allocate + DF 的 Windows `420` 不变）；
  「出站源端口 = relay 端口」的断言改由 `RELAY_SOURCE_PORT_BOUND` 控制（Windows 无
  `SO_REUSEPORT`，回退临时源端口），其余双向字节/预绑定/端口归属断言照旧。

### 修复：过期 allocation 被替换时的端口记账错误

- 同一 5 元组在「TTL 已过但 1s 扫描尚未回收」的窗口内重新 `Allocate` 时，旧端口没有归还
  （反而把**新**端口标成空闲）——UDP 与 TCP allocation 都受影响。短 TTL 反复重分配会逐步耗尽
  端口池；TCP 下因 `SO_REUSEPORT` 还可能让两个 allocation 绑到同一端口。
- 已改为归还**被替换项**的端口，并补回归测试 `reallocating_over_an_expired_entry_releases_the_old_port`。
  默认路径的响应字节不变。

## 26.410.103

### TURN：`DONT-FRAGMENT`（0x001A）真实现 + IPv6 relay 回归

- **行为变更**：在**能真的置 DF 的平台**（Linux、macOS/iOS）上，`Allocate` 携带
  `DONT-FRAGMENT` 不再回 `420`（RFC 8656 §7.2 步骤 4 允许的兼容路径），而是在 relay socket
  上**真置 DF**：Linux `IP_MTU_DISCOVER = IP_PMTUDISC_DO`（IPv6 socket 用
  `IPV6_MTU_DISCOVER`），macOS/iOS `IP_DONTFRAG` / `IPV6_DONTFRAG`。置位在 allocation 的
  整个生命周期内有效；`ChannelData` 没有属性位，沿用该设置。`setsockopt` 失败 →
  `500 Server Error` 并计 `rstun_turn_rejected_total{reason="df"}`。
  属性长度 ≠ 0（§18.9 规定无值部分）→ **`400`**。
- **`Send` indication 带 DF（§11.2）**：只对该报文置位、发送后恢复内核默认
  （`IP_PMTUDISC_WANT` / `0`），切换在同一 allocation 的互斥锁内串行化。
  **置位失败 → 丢弃该 indication**（§11.2：置不上 DF 时「按未知 comprehension-required
  属性处理，**因此丢弃该 Send indication**」）：不向 peer 转发、计 `rejected_df`、记日志。
  畸形（长度 ≠ 0）的 DF 属性同样按未知属性语义丢弃并计数。
- **平台口径**：`DONT_FRAGMENT_SUPPORTED = cfg!(any(target_os = "linux", "macos", "ios"))`。
  其它平台（Windows，以及 FreeBSD 等选项名未经验证的 unix）上 `0x001A` 仍是未知
  comprehension-required → `Allocate` 回 `420` + `UNKNOWN-ATTRIBUTES`（§7.2 步骤 4 明文允许），
  同平台的 `Send` 带 DF 走「未知属性 ⇒ 丢弃」的同一语义。
- **新增直接依赖 `libc`**（`[target.'cfg(unix)'.dependencies] libc = "0.2"`）：`socket2 0.6`
  没有 MTU-discover/DF 的 API。它本来就是 tokio/socket2 的传递依赖，**不新增任何 crate**；
  直接依赖计数 unix 口径 9→**10**（lean）/ 13→**14**（full），`gen-sbom.sh` 的断言与
  README「依赖面」已同步；依赖树行数 89→90 / 359→360，二进制体积不变。
- **IPv6 relay 回归**：lab 新增 `ipv6relay` 项（`--listen [::1]` + IPv6 客户端 + IPv6 peer），
  断言 `XOR-RELAYED-ADDRESS` 是 IPv6、`Send`/`Data`/`ChannelData` 双向都有字节 ——
  这条路径此前**完全没有仓内回归**。探针加 `--family inet|inet6`（XOR 编解码按族）。
- **lab 新增 `df` 项**：`turnutils_uclient -g` 从 `error 420` 变成可中继。证据口径：
  `tcpdump -i lo` 的 `flags [DF]` **不是**判别性的（Linux 默认 `IP_PMTUDISC_WANT` 对
  不超过 MTU 的报文本来就置 DF），判别性证据是单测的 `getsockopt` 回读；lab 认领的是
  「`-g` 能中继」+「线上带 DF」两件事，并在输出里说明证据来源。
- 影响面：只有**带** `DONT-FRAGMENT` 的请求字节改变（`uclient -g` 等）。不带它的请求
  与上一版逐字节一致（`plain_response_bytes_are_frozen`、3 配置 × 17 请求冻结对照未变）；
  `raf` 项不再断言 `-g` → `420`。

## 26.410.102

### TURN：`REQUESTED-ADDRESS-FAMILY`（0x0017）不再回 420

- **行为修正（RFC 8656 §7.2 步骤 7 / §18.6）**：`Allocate` 携带
  `REQUESTED-ADDRESS-FAMILY` 时按请求的地址族校验 relay：族一致（IPv4 客户端请求
  IPv4）→ 正常 `200`；请求的族本端提供不了（IPv4 客户端请求 `0x02`，或族值不是
  `0x01`/`0x02`）→ **`440 Address Family not Supported`**；长度 ≠ 4 → `400`；
  保留 24 位忽略。`RESERVATION-TOKEN` 与 `EVEN-PORT`/RAF 互斥 → **`400`**，且该判定
  （§7.2 步骤 5）**先于**族比对（步骤 7）—— 异族 token 也是 `400`（与 coturn 一致）。
- **`Refresh` 按 §8.2（MUST）**：`REQUESTED-ADDRESS-FAMILY` 与 allocation 的 relay 族
  不匹配 → **`443 Peer Address Family Mismatch`**（allocation 存活，含 `LIFETIME=0`
  的异族请求也不释放）；族匹配 → 正常续期；长度 ≠ 4 → `400`；不再回 `420`。
- `DONT-FRAGMENT`（0x001A）**不变**：仍按未知 comprehension-required 属性回 `420`
  —— RFC 8656 §7.2 步骤 4 明确允许「不设 DF 位的服务器」这样做，不是偏差。
- `ADDITIONAL-ADDRESS-FAMILY`（0x8000，comprehension-optional）仍未实现（忽略），
  因此 §7.2 步骤 6（RAF+AAF → `400`）不生效。
- 影响面：只有**带** `REQUESTED-ADDRESS-FAMILY` 的请求字节改变（`turnutils_uclient`
  的 `-e`/`-x`/`-X` 与 aioice 等客户端的显式族请求）；不带该属性的请求与
  `26.410.101` 逐字节一致（`plain_response_bytes_are_frozen`、3 配置 × 17 请求
  冻结对照均未变）。无新增依赖、无新增指标（`rejected_family` 复用）、无 CLI 变化。
- 验收：解析器单测 + 两条 e2e（`Allocate` 7 组断言：匹配 / 440 / 400 / 非法族 /
  保留位 / token 互斥（`0x01` 与 `0x02` 两种族）/ DF 仍 420；`Refresh` 5 组断言：
  异族 443 / 非法族 443 / 异族 `LIFETIME=0` 仍 443 且不释放 / 长度错 400 / 匹配 200）；
  lab 新增 `raf` 项（`uclient -X` 中继、`-x` → `error 440`、`-g` → `error 420`），
  `dtls` 项补 `-S -X`（生产复现形状）。

## 26.410.101

补丁版：依赖升到各自最新 + 上一版积累的功能（T1 TURN、T2 `turns:`/DTLS/REST/带宽、
运维面、鉴权、协议闭环、抗滥用）一并交付。

### TURN：`REQUESTED-ADDRESS-FAMILY`（RFC 8656 §18.6）

- `Allocate` 解析 `0x0017`：族与 relay 一致 → 正常分配；请求异族或族值非 `0x01`/`0x02`
  → `440 Address Family not Supported`；长度 ≠ 4 → `400`；保留 24 位忽略。
- `RESERVATION-TOKEN` 与 `EVEN-PORT`/RAF 互斥 → `400`（§7.2 步骤 5 先于步骤 7）。
- `Refresh` 上族不匹配 → `443 Peer Address Family Mismatch`（§8.2 MUST），且不释放分配。
- `DONT-FRAGMENT (0x001A)` **保持 `420`**：§7.2 步骤 4 明文允许（不是偏差）。
- 影响：`turnutils_uclient` 的 `-e`/`-X`（隐含 RAF）从 `420` 变为可中继；`-x` 得 `440`。
- 不带 RAF 的路径字节不变（`frozen` 3 配置 × 17 请求与上一版逐字节一致）。

### 依赖升级（无协议字节、无 CLI、无指标名变化）

- RustCrypto 栈升到 `digest 0.11` 一代：`hmac 0.12 → 0.13`、`md-5 0.10 → 0.11`、
  `sha1 0.10 → 0.11`、`sha2 0.10 → 0.11`。唯一代码改动是 `src/auth.rs` 里
  `<Hmac<_> as Mac>::new_from_slice` → `<Hmac<_> as KeyInit>::new_from_slice`
  （`digest 0.11` 把 `new_from_slice` 移到了 `KeyInit`）；算法、key 派生（`MD5`/`SHA256`
  长期凭据、`USERHASH` 32 字节、nonce HMAC）与全部 RFC 向量（2202 / 4231 / 1321 /
  5769 §2.4）**逐字节不变**。
- `clap 4.6.8 → 4.6.9`（锁文件里实际变化的唯一 patch）。
  `tokio` / `tokio-rustls` 只把 `Cargo.toml` 的约束文本收紧到 `1.54.1` / `0.26.6`
  （`Cargo.lock` 解析版本未变，运行时行为相同）。CI 门禁与 lab 全绿。
- **`webrtc-util` 保持 0.11**（Dependabot #5 不合并）：`webrtc-dtls` 最新版仍是 `0.12.0`，
  它钉死 `util ^0.11`；把直接依赖升到 `0.17.3` 会让树里出现两份 `webrtc-util`，
  `DTLSConn` 实现的是 0.11 的 `Conn`，`Arc<DTLSConn> → Arc<dyn Conn>` 转换编译失败
  （E0277/E0308）。等上游 `webrtc-dtls` 跟进后再升。
- 直接依赖数不变：`cargo tree -e normal --depth 1` = **9**（lean）/ **13**（full）。
  默认关闭路径的字节冻结（`plain_response_bytes_are_frozen` 与 3 配置 × 17 请求对照）不变。

### TURN（RFC 8656 UDP 中继，`--turn`，T1）

- **`--turn`（默认关闭）**：在现有 STUN socket 上启用 RFC 8656 的 UDP 中继。
  `Allocate` / `Refresh` / `CreatePermission` / `ChannelBind` + `Send`/`Data` indication +
  `ChannelData`（UDP 与 TCP 客户端传输；relay 恒为 UDP）。**强制长期凭据**：缺
  `--realm` / `--auth-secret` / 用户时**启动失败（exit 1）**，不会有匿名开放中继；
  短期凭据同样拒绝。
- **鉴权复用**：TURN 与 Binding 共用同一套 realm/nonce/MESSAGE-INTEGRITY 实现。无 MI → `401` +
  `REALM`/`NONCE`；nonce 过期 → `438` + 新 `NONCE`；错口令/未知用户 → `401`；`401/438` 计入
  同一限速桶。成功响应按请求所用算法签名。
- **生命周期**：默认 **600s**；低于默认的请求按 RFC 8656 §7.2 取默认，高于
  `--allocation-lifetime`（上限 3600s）被截断；`Allocate` 的 `LIFETIME=0` 按默认；**`Refresh`
  缺 `LIFETIME` 按默认续期（§8.2，不再 400）**；`REFRESH LIFETIME=0` 立即释放；permission 5 分钟、
  channel 10 分钟。**同一 transaction id** 的 `Allocate` 重传幂等（同一 relay），**新
  transaction id → 437**；释放后再 `Refresh` → `437`。
- **441 Wrong Credentials**：同一 5 元组、不同用户名 → `441`（RFC 8656 §5/§6.2），三个方法
  （`Refresh` / `CreatePermission` / `ChannelBind`）都拒绝；他人发来的 `LIFETIME=0` 不会删除
  allocation。
- **端口与配额**：`--relay-ports`（默认 49152–65535）耗尽 → `508`；每用户（默认 8）/每 IP
  （默认 16）超限 → `486`；permission 超 `--permission-limit`（默认 10）→ **`508`**（RFC 8656
  §10.2；一条请求带多个 peer 时先校验整条请求，**不做部分生效**）；`ChannelBind` 的隐式
  permission 同样计入；`REQUESTED-TRANSPORT=6` → `442`；族不匹配 → `440`/`443`。
- **`EVEN-PORT`（含 R=1 reservation token）**：coturn 的 `turnutils_uclient` 在每次 Allocate
  都带 `EVEN-PORT`，T1 实现「偶数端口 + 下一个端口保留（30s，`RESERVATION-TOKEN`）」，
  否则标准客户端第一步就 420。`DONT-FRAGMENT` 等未实现的可理解属性仍按 RFC 回 `420`。
- **数据面**：`Send` 只在 permission 覆盖 peer 时转发（否则静默丢弃）；relay 收到 peer 数据时
  命中 channel → `ChannelData`，否则 → `Data` indication；`ChannelData` 不解析 STUN；
  TCP 上的 `ChannelData` 按 4 字节对齐填充。**UDP `ChannelData` 声明长度大于报文 → 静默丢弃**
  （不转发截断内容）；TCP 客户端写队列改为**有界**（64 帧）+ `try_send`，溢出丢 relayed 数据，
  防止已认证客户端用不读连接撑大内存。
- **成功响应带 `SOFTWARE`**（RFC 8656 §14.10 SHOULD，coturn 同样有）；401/438 挑战不带。
- **防护**：拒绝 unspecified / multicast / 本进程监听地址 / 该 allocation 自身 relay /
  **loopback peer**（仅当请求到达的 socket 本身是回环地址时放行，供本地开发与 `-y` 矩阵）→
  `403`（`reason=loopback`）。`--listen 0.0.0.0` 下这条规则才真正堵住
  「peer = 127.0.0.1:<监听端口>」的漏检。同一进程内其它 allocation 的 relay 地址**允许** ——
  这是 `turnutils_uclient -y` 与同 NAT WebRTC 的正常路径。**已知盲区**：宿主自身公网 IP
  需接口枚举才能判定，T1 不引入该依赖，README 已登记。
- **回收**：单一定时扫描任务（1s）清理 allocation/permission/channel；allocation 移除时 abort
  relay 读任务、关闭 socket、端口归还池。验收断言过期后 `ss -lun` 在 relay 段内无监听。
- **观测**：`/metrics` 新增 `rstun_turn_allocations`（gauge）、
  `rstun_turn_bytes_total{direction=in|out}`、`rstun_turn_allocations_total{result=created|expired}`、
  `rstun_turn_rejected_total{reason=quota|ports|family|loopback}`；退出日志打印同一组数字。
  **未开 `--turn` 时这些指标不出现**（与既有的「不输出恒 0」约定一致）。
- **默认关闭零差异**：`--turn` 不在时 TURN 模块不解析、不建表、不生成指标；验收脚本用
  `git archive HEAD` 构建旧二进制，3 组配置 × 17 请求逐字节对照。
- **验收与对照**：新增 `script/lab/rstun-turn.sh`（12 项：启动失败 / uclient 中继 / 401+438 /
  生命周期 / 441 / 通配监听回环 / permission 508 / 486 / 端口 508 / 回收 / 字节冻结 /
  coturn 对照）与 `script/lab/rstun-turn-probe.py`
  （标准库最小 TURN 客户端，同一步骤可对 coturn 与 rstun 各跑一次再 diff）。
  与 coturn 的差异：`LIFETIME=0` 之后再 `Refresh`，本服务按 RFC 8656 §7.2 回 `437`，
  coturn 会「复活」该 allocation（宽松实现）；其余中继步骤逐行一致。
- **无新增运行期依赖**：`cargo tree -e normal --depth 1` 仍是 9 个。

### TURN T2（`turns:` / DTLS / REST 凭据 / 带宽配额）

- **两种构建（feature gate）**：`default = []` → **lean**（STUN + TURN UDP/TCP + REST + 带宽，
  9 个直接依赖、release ~3.6 MB）；`--features full`（=`tls` + `dtls`）→ 再加 `turns:`(TLS) 与
  DTLS（13 个直接依赖、未 strip 的 release 7.9 MB、201 个唯一 crate）。
  TLS/DTLS 的监听、材料解析、连接处理与
  单测全部 `#[cfg(feature = …)]`；四个 flag 仍出现在 `--help`（帮助不随构建变化），lean 下给出
  它们会**拒绝启动**并指明缺哪个 feature（`cargo build --features tls,dtls`）。`--rest-secret`
  与 `--turn-bandwidth` 不 gate：lean 的 UDP/TCP TURN 一样能用。
- **TLS 监听（`--turn-tls-listen` + `--tls-cert`/`--tls-key`，`tls` feature）**：在 T1 的 TCP 分帧之上套
  TLS 1.2/1.3（`tokio-rustls`，provider 固定 ring）。证书/私钥**启动时**解析：路径不可读、
  不配对、有监听没材料 → **启动失败**（不降级明文）；TLS 与明文不共用端口。握手 5s 超时、
  失败计数进退出日志（`handshake_failed`），日志不含证书内容。
- **DTLS 监听（`--turn-dtls-listen`，`dtls` feature）**：`webrtc-dtls` 0.12（纯 Rust）实现 DTLS 1.2；
  **一个 datagram = 一个 STUN/TURN 消息或一个 `ChannelData`**（与 UDP 同构，无 4 字节对齐），
  5 元组的客户端传输记为 `Dtls`。握手在每客户端任务里做（5s），**不阻塞 accept**；
  私钥须 PKCS#8 + ECDSA P-256/Ed25519（上游限制，启动时明确报错）。
- **REST 临时凭据（`--rest-secret`）**：coturn `use-auth-secret` 兼容，
  `username=<expiry>:<label>`、`password=base64(HMAC-SHA1(secret, username))`（标准 base64）。
  过期 → `401`（不是 438）；错 secret → `401`；**与长期凭据并存时 REST 优先**，label 可含 `:`。
  复用 `auth` 的 HMAC 与长期 key 推导，不新增依赖。
- **带宽配额（`--turn-bandwidth`，默认 1 MiB/s、0=不限）**：每 allocation 双向令牌桶，
  容量 1 秒；超限丢包并计数（`rstun_turn_bytes_dropped_total{direction=in|out}`），
  allocation 与通话不受影响。新增退出日志字段 `bytes_dropped_in/out`。
- **依赖与体积（实测）**：full 构建里直接依赖 9 → 13（`tokio-rustls`、`rustls-pemfile`、
  `webrtc-dtls`、`webrtc-util`；最后一个只是把上游同版本传递依赖提升为直接依赖，不新增 crate）、
  唯一 crate 65 → 201、未 strip 的 release 二进制 **3.5 MB → 7.9 MB**
  （LTO+strip 后的发布/镜像二进制：2.35 MB → 4.80 MB）。**默认 lean 构建不受影响**：
  仍是 9 个直接依赖、未 strip release **3.77 MB**（+0.25 MB 来自 REST 与带宽代码）。
  设计估计 +1.2 MB，实测更高 —— 这正是最终选择 feature gate 的原因。
- **`cargo audit`**：`RUSTSEC-2026-0387`（`crypto-bigint 0.5.5` 常量时间时序差异，修复版本与
  `elliptic-curve 0.13` 不兼容）进 `.cargo/audit.toml` 允许清单，附「仅 full 构建、仅
  `--turn-dtls-listen` 可达、每次发版前复查」的说明；`cargo audit` 退出码恢复 0。另有 3 条
  unmaintained 警告（`bincode`/`pin-utils`/`rustls-pemfile`，均在 `tls`/`dtls` 链上），不影响退出码。
- **验收**：`script/lab/rstun-turn.sh` 扩到 **17 项**，新增 `tls` / `dtls` / `rest` / `bandwidth`
  与 `--tls`/`--dtls` 快捷参数（会自动 `--features full` 构建；lean 二进制下 tls/dtls 记 SKIP
  并说明，不是失败）；`coturn` 项扩展为同参数对跑 TLS（`uclient -S -t`）、
  DTLS（`uclient -S`）与 REST（`use-auth-secret` 的独立实例 + 逐行 diff 探针）。
  探针新增 `rest` 模式（有效 / 过期 401 / 错 secret 401 / 含 `:` 的 label），每个用例用
  新的源端口（独立 5 元组），避免「已有 allocation」遮蔽凭据判定。
- **默认关闭零差异**：不配 T2 开关时 TURN 行为与 T1 一致；`frozen` 项仍是 3 配置 × 17 请求
  与 T1 基线逐字节相同（lean 与 full 两种构建都跑）。
- **B1 修复**：DTLS 的密钥规则（PKCS#8 + ECDSA P-256/Ed25519）此前在 full 构建里**无条件**
  应用，导致「只开 `--turn-tls-listen` + Let's Encrypt RSA 证书」被错误拒绝。现在只在该次启动
  真的配了 `--turn-dtls-listen` 时才解析/校验 DTLS 材料（`SecureMaterial.dtls: Option<_>`）；
  RSA 证书可以用于 `turns:`，同时开 DTLS 时仍然报错退出。lab `tls` 项新增该用例，单测
  `full_build_accepts_an_rsa_certificate_when_dtls_is_off` 覆盖两个方向。
- **CI 供应链审计**：Linux `test` 作业加 `cargo audit`（`rustsec/audit-check`，锁 commit SHA，
  ignore 列表与 `.cargo/audit.toml` 同步）。
- **发布/CI**：每个平台产出**两份**（lean `rstun-<platform>-<version>.zip`、full
  `rstun-full-<platform>-<version>.zip`，资产 4 → 8，release 作业断言恰好 8 个）；镜像改为
  `--features full` 构建（容器是 `turns:` 的主要用途）；CI 的 `test` 作业按
  `--no-default-features` / `--all-features` 各跑一次 `cargo test` + `clippy`。

### 运维面（readiness / metrics / `RSTUN_*` / 优雅 drain / 部署清单）

- **`--health-listen <addr>`（默认关闭）**：可选的最小 HTTP/1.1 端点（**手写，未引入
  hyper/axum**，运行期依赖仍是 9 个）。资源维度的两条硬上限：**整条连接 2 秒**（读头与写响应
  共用同一个截止时间 —— 每读重置的超时挡不住「每 1.5s 发 1 字节」的慢速客户端）与
  **并发连接上限 `--health-max-connections`（默认 64，可用 `RSTUN_HEALTH_MAX_CONNECTIONS` 配）**：
  超出上限**不排队**，立刻回 `503 too many concurrent connections` 并关闭（排队会保留洪水想
  耗尽的 fd），超限次数见新指标 `rstun_ops_rejected_total`。请求头（含终止空行）上限 **8192
  字节**：恰好 8192 可服务、8193 起 `400`。`GET /healthz` 只在**每个已配置监听都还在服务**时回
  `200 {"status":"ok","listeners":N}`；任一 listener 任务退出（错误返回 / 被 abort）→
  `503 {"status":"degraded",...,"stale":[...]}`；drain 期间 → `503 {"status":"draining"}`。
  其它方法 `405` + `Allow`，未知路径 `404`，带**非零** `Content-Length`（或 `Transfer-Encoding`）
  的请求 `400` 并关连接（`Content-Length: 0` 视为没有 body）；一个连接只答一个请求、读超时 2s、
  请求头（含终止空行）上限 8192 字节、整条连接 2s 总时限、并发连接上限，不读 body。
  **不给该参数时没有 HTTP 监听、没有额外任务、字节行为不变**。
- **`GET /metrics`（Prometheus 文本）**：`rstun_requests_total{transport,result}`、
  `rstun_rate_limited_total{scope}`、`rstun_inflight_dropped_total`、
  `rstun_reflect_rejected_total`、`rstun_denied_total`、`rstun_allowlisted_total`、
  `rstun_fingerprint_rejected_total`、`rstun_socket_errors_total{transport}`、
  `rstun_auth_total{result}`、`rstun_build_info{version}`、`rstun_start_time_seconds`、
  `rstun_uptime_seconds`、`rstun_health`。与退出统计**同一组 `Counters`**（不双份计数）；
  标签集合固定（三个枚举维度）。`rstun_turn_*` 只在 `--turn` 时输出（见上方 TURN 小节；
  未开启时不是恒 0）。
  为此 `ServerStats` 新增 transport × outcome 桶（`ok/error/ignored/dropped`），退出日志的
  `received/answered/dropped` 语义**未变**（含既有的「反射拒绝会同时记 answered 与 dropped」）。
- **`RSTUN_*` 环境变量映射**：每个 flag 一个同名变量（大写、`-` → `_`），列表用逗号分隔。
  **空字符串视为未设置**（compose 的 `${RSTUN_REALM:-}` 不会把启动打挂）；
  `RSTUN_VERBOSE=1` 与 `--verbose` 等价（环境变量现在在日志初始化**之前**应用）。
  **命令行显式值优先**（`--listen` 与 `RSTUN_LISTEN` 不合并），只补没写的那些；解析失败
  **启动失败并指明来源**（`RSTUN_ALT_PORT: invalid value …`）；启动日志列出实际生效的变量；
  未映射的 `RSTUN_*`（如 `RSTUN_BUILD_VERSION`）被忽略。
- **优雅退出（drain）**：`--drain-timeout`（默认 5s，0 = 立即）。SIGTERM 后 UDP 停 `recv_from`、
  TCP 停 `accept`、已建连接不再读新帧，等在途（datagram / TCP 连接 / 正在处理的帧）完成后
  打印统计并退出 0；超时则 `warn` 并照样退出（退出码仍 0）。**第二个 SIGTERM 立即退出**。
- **部署清单（`contrib/`）**：`systemd/rstun.service`、`docker/compose.yaml`
  （`network_mode: host` + `/dev/tcp` 健康检查）、`k8s/{deployment,service}.yaml`
  （`hostNetwork`、`readinessProbe → /healthz`、只读根文件系统、`externalTrafficPolicy: Local`；
  RFC 5780 的 alt 端口随 `rfc5780.altPort` 一起暴露）、
  `helm/`（最小 chart，values 覆盖 listen/rfc5780/health/abuse，无第三方 chart 依赖）。
- **测试 +28**：`RSTUN_*` 映射与优先级（含空值、连接上限）、HTTP 解析六种结局、
  **慢速客户端被 2s 总时限关闭**、**并发上限立刻 503 且端点仍服务**、**请求头 8192/8193 边界**、
  `/healthz` 200→503（真实 socket）、`/metrics` 固定标签集合与随计数增长、
  `wait_idle` 等在途/到点放弃、`Lifecycle` 订阅。
  回归：`interop all` 42 项、`abuse` 10 组、冻结测试全绿；`cargo tree -e normal --depth 1` 仍 9 个。


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

- 首次发布到 crates.io：`cargo install rstun`（lean）/ `cargo install rstun --features full`

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
