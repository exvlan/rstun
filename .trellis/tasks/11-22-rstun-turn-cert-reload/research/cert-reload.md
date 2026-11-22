# Research: TURN `turns:`(TLS) / DTLS 证书热加载

- **Query**: `--tls-cert` / `--tls-key` 的加载与校验现状、TLS/DTLS 监听的可替换点、信号/文件监视代价、跨平台、可观测、验收路径与风险
- **Scope**: mixed（本仓代码 + 上游 crate 源码 + 官方文档），含黑盒验证
- **Date**: 2026-11-22
- **基线**: 工作区 `/data/project/rstun`，`target/debug/rstun` 已用 `--features full` 构建（启动日志 `features="tls,dtls"`）
- **约束来源**: `.trellis/tasks/11-22-rstun-turn-cert-reload/prd.md:44`（「不新增运行时依赖……避免引入 `notify`/`inotify` 类库」）

标注约定：**[已验证]** = 本次跑过命令并贴了原始输出；**[读代码]** = 只走读源码（含上游 crate 源码），未运行；**[未验证]** = 无法确认。

---

## 0. 结论速览

| # | 问题 | 结论 | 证据等级 |
|---|---|---|---|
| 1 | 当前加载路径 | 启动期一次解析：`build_turn`（半配置/feature 门禁）→ `load_secure_material`（PEM→DER、`with_single_cert` 配对检查、DTLS 的 PKCS#8 + ECDSA P-256/Ed25519 检查）→ `SecureMaterial{acceptor, dtls}` | [读代码]+[已验证] |
| 2 | TLS 监听 | `TlsAcceptor` 就是 `Arc<ServerConfig>` 的薄包装；每个连接 `accept()` 再 `Arc::clone` 一次。当前 acceptor 按值传给 `serve_turn_tls`，**没有**共享可替换槽位；加一个 `Arc<RwLock<Arc<ServerConfig>>>`（或 `watch`）即可在 accept 点读到新配置，`ServerConnection::new(Arc<...>)` 本身接受 `Arc` | [读代码] |
| 3 | DTLS 监听 | `webrtc_dtls::config::Config`（`Clone`，内含 `Vec<Certificate>`）按值传入 `serve_turn_dtls`，**每客户端再 clone 一次**；`DTLSConn::new` 把 `config.certificates` clone 进 handshaker。所以「accept 前读新配置 ⇒ 新连接用新证书；已建立会话持有自己的副本 ⇒ 永远旧证书」。webrtc-dtls 0.12 **无 session ticket / 无 resumption 缓存**，不存在「旧会话缓存带旧证书」问题 | [读代码] |
| 4 | 信号/文件监视现状 | `tokio` 的 `signal` feature **已启用**（`Cargo.toml:50`），`signal-hook-registry` 已在 lean/full 依赖树里；现有信号处理只有 Ctrl-C + SIGTERM（`wait_for_shutdown`，`src/main.rs:3589`）。**没有** SIGHUP 处理、**没有** mtime 轮询、**没有** `notify`/`inotify`（`Cargo.lock` 无此包）。当前 SIGHUP = 进程被默认处置杀死 | [已验证] |
| 5 | 跨平台 | Windows 无 SIGHUP（tokio 只有 `ctrl_c`/`ctrl_break`…）；轮询 `mtime`+`len` 足够，建议 30–60 s（2 次 `stat`/分钟）；macOS 走 `notify` 才有 FSEvents（默认 feature），但本任务 PRD 禁新依赖 ⇒ 轮询在 macOS 上是最省事且行为一致的路径 | [读代码]+[文档] |
| 6 | 可观测 | `/metrics` 标签面固定为 `transport`/`result`/`scope` 三个枚举，且 TURN 指标族整体以 `rstun_turn_` 前缀**仅在 `--turn` 时输出**；`handshake_failed` 是「只进退出日志、不进 `/metrics`」的先例。建议新增 `rstun_turn_tls_reload_total{result="ok"\|"failed"}`（符合既有 `result=` 枚举写法）与 `rstun_turn_tls_cert_expires_seconds`（gauge，无标签）。**到期秒数需要解析 X.509 validity**，这是唯一有依赖代价的指标 | [读代码] |
| 7 | 验收路径 | `openssl` 两套 ECDSA P-256 + PKCS#8 证书、运行中 `cp` 覆盖同一路径 → `openssl s_client`（DTLS 加 `-dtls1_2`）取 `-serial/-dates/-fingerprint`；坏材料（不配对 / RSA+DTLS / SEC1 / 截断 / 空文件）在现基线下的报错文案已实测；lab 里 `make_cert`/`start_server`/`wait_health`/`metric` 可直接复用 | [已验证] |
| 8 | 风险 | 半写文件（先 cert 后 key）会有短暂不配对窗口 → 需要去抖/两次确认；链顺序（leaf 必须第一）无校验；私钥权限无检查；DTLS 无会话缓存；TLS 1.2 session-id 缓存随 `ServerConfig` 重建而清空（ticket 本来就没开）；「重载失败是否退出」与仓内「绝不静默降级」的既有口径存在张力 | [读代码]+[已验证] |

---

## 1. 当前加载路径（启动期，一次）

### 1.1 参数与半配置拒绝

| 位置 | 内容 |
|---|---|
| `src/main.rs:343-347` | `turn_tls_listen: Vec<SocketAddr>`（clap `--turn-tls-listen`） |
| `src/main.rs:349-353` | `turn_dtls_listen: Vec<SocketAddr>` |
| `src/main.rs:355-357` | `tls_cert: Option<PathBuf>`（文档写明 "PEM certificate chain"） |
| `src/main.rs:359-362` | `tls_key: Option<PathBuf>`（文档写明 "unencrypted PKCS#8, e.g. `openssl genpkey`"） |
| `src/main.rs:1039-1063` | `build_turn`：给了任一 TURN flag 却没 `--turn` → 拒绝启动；`--tls-cert`/`--tls-key` 也算 TURN flag（`1049-1050`） |
| `src/main.rs:1071-1075` | `#[cfg(not(feature = "tls"))]`：`--turn-tls-listen` / `--tls-cert` / `--tls-key` 任一出现 → "need a build with the `tls` feature" |
| `src/main.rs:1076-1081` | `#[cfg(not(feature = "dtls"))]`：`--turn-dtls-listen` → 同上 |
| `src/main.rs:1084-1098` | 「监听器必须成对拿到材料」：`(Some,Some)` 通过；`(None,None)`→"need --tls-cert and --tls-key"；`(Some,None)`→"--tls-cert needs --tls-key"；`(None,Some)`→"--tls-key needs --tls-cert" |
| `src/main.rs:1099-1107` | 给了材料却没有 TLS/DTLS 监听器 → "need --turn-tls-listen or --turn-dtls-listen" |
| `src/main.rs:1108-1120` | `--turn` 必须有长期凭据（`auth.mode() == LongTerm`） |
| `src/main.rs:1141-1142` | `config.validate()?`（TURN 表参数） |

### 1.2 `load_secure_material`（唯一解析点）

`src/main.rs:3132` 起（`SecureMaterial` 定义在 `3113-3119`）：

| 行 | 行为 |
|---|---|
| `3139-3140` | `std::fs::read(cert_path)`；失败 → `cannot read --tls-cert <path>: <err>` |
| `3141-3152` | `rustls_pemfile::certs()` 逐块解析；失败 → `--tls-cert <path> is not valid PEM: <err>` |
| `3153-3159` | 0 个 CERTIFICATE 块 → `--tls-cert <path> contains no CERTIFICATE block` |
| `3157-3166` | `rustls_pemfile::private_key()`（接受 PKCS#8 / PKCS#1 / SEC1）；无 key 块 → `contains no private key block` |
| `3168-3176` | `ServerConfig::builder().with_no_client_auth().with_single_cert(certs.clone(), key.clone_key())` —— 配对检查在这一步（rustls 报 `KeyMismatch`），失败 → `--tls-cert <p> / --tls-key <p> do not form a usable pair: <err>` |
| `3184-3207` | 仅当 `needs_dtls`（即真的配了 `--turn-dtls-listen`，`src/main.rs:1272`）才做 DTLS 校验：非 PKCS#8 → `must be an unencrypted PKCS#8 private key ... PKCS#1/SEC1` |
| `3200-3210` | `webrtc_dtls::crypto::Certificate::from_pem(&dtls_pem(&pkcs8, &certs))` —— 用 `dtls_pem`（`3241`）把已解析的 DER 重新包成 webrtc-dtls 要的 `PRIVATE_KEY` 首块格式 |
| `3211-3222` | `certificate.private_key.kind` 只接受 `Ecdsa256` / `Ed25519`，否则 `cannot be used for DTLS: webrtc-dtls signs with ECDSA P-256 or Ed25519 only` |
| `3224-3227` | `webrtc_dtls::config::Config { certificates: vec![certificate], ..Default::default() }` |
| `3229-3234` | `SecureMaterial { acceptor: TlsAcceptor::from(Arc::new(tls_config)), dtls }` |

配对检查的判定细节（上游）：rustls `CertifiedKey::keys_match` 只比对 **`cert_chain.first()`（leaf）** 的 SPKI 与私钥公钥（`rustls-0.23.46/src/crypto/signer.rs:190-200`，`end_entity_cert()` = `cert.first()`）。因此**证书链顺序（leaf 第一）不被显式校验**，顺序错了只会让对端验证失败。

DTLS 的算法白名单有两处同源判定：本仓 `src/main.rs:3211-3222` 主动检查一次（启动即报错），`webrtc-dtls` 的 `validate_config` 也会在 `DTLSConn::new` 时拒绝非 Ed25519/Ecdsa256（`webrtc-dtls-0.12.0/src/config.rs:175-181`）。

### 1.3 调用点（run 里，服务前）

| 行 | 内容 |
|---|---|
| `src/main.rs:1256-1260` | 注释：材料在**服务之前**读取，"bad path or unusable pair must never degrade into plaintext" |
| `src/main.rs:1262-1284` | 只有配了 TLS/DTLS 监听器才 `load_secure_material(cert, key, !turn_dtls_listen.is_empty())`；失败 → `tracing::error!("invalid TLS configuration")` + `ExitCode::FAILURE` |
| `src/main.rs:1311-1323` | 每个 `--turn-tls-listen` 地址 `tcp_listener()` 后把 `material.acceptor.clone()` 塞进 `tls_listeners` |
| `src/main.rs:1325-1335` | 逐个 `spawn_listener(serve_turn_tls(listener, acceptor, …))` |
| `src/main.rs:1339-1380` | DTLS：`material.dtls.clone()`（`1349`）拿到 `Config`，每个地址 `listen()`，再 `serve_turn_dtls(listener, dtls_config.clone(), …)`（`1372-1378`） |

### 1.4 黑盒验证（本次实测）

基线二进制 `target/debug/rstun`（`--features full`）。证书：`/tmp/opencode/certreload/{a,b}-cert.pem`，ECDSA P-256 + PKCS#8，`CN=a.example` / `CN=b.example`。

| 用例 | 命令 | 原始结果 |
|---|---|---|
| 不配对 | `... --turn-tls-listen 127.0.0.1:13544 --tls-cert a-cert.pem --tls-key b-key.pem` | `ERROR ... invalid TLS configuration --tls-cert a-cert.pem / --tls-key b-key.pem do not form a usable pair: keys may not be consistent: KeyMismatch`，`exit=1` |
| SEC1 私钥 + DTLS 监听 | `--turn-dtls-listen ... --tls-cert a-cert.pem --tls-key a-sec1.pem` | `--tls-key a-sec1.pem must be an unencrypted PKCS#8 private key (openssl genpkey -algorithm EC ...)`，`exit=1` |
| RSA 私钥 + DTLS 监听 | `--tls-cert rsa-cert.pem --tls-key rsa-key.pem` | `cannot be used for DTLS: webrtc-dtls signs with ECDSA P-256 or Ed25519 only (TLS itself accepts this key, DTLS does not)`，`exit=1` |
| RSA 私钥 + 仅 TLS 监听（B1 形状） | `--turn-tls-listen ... --tls-cert rsa-cert.pem --tls-key rsa-key.pem` | 启动成功；`openssl s_client` 拿到 `subject=CN=r`（与 `openssl x509 -in rsa-cert.pem -noout -subject` 一致） |
| 材料无监听器 | `--tls-cert a-cert.pem --tls-key a-key.pem`（无 tls/dtls 监听） | `exit=1` |
| 监听器无材料 | `--turn-tls-listen 127.0.0.1:13544` | `exit=1` |
| 截断 PEM（前 200 字节） | `--tls-cert trunc-cert.pem` | `--tls-cert trunc-cert.pem is not valid PEM: section end "CERTIFICATE" missing`，`exit=1` |
| 空文件 | `--tls-cert empty-cert.pem` | `--tls-cert empty-cert.pem contains no CERTIFICATE block`，`exit=1` |

> 注：上面「exit=1」是去掉管道后单独跑出来的；带 `| tail` 时 `$?` 是 `tail` 的。

**现状 = 重启才生效（实测）**：起服务时把 `live-cert.pem/live-key.pem` 指向 A 证书，`s_client` 得到指纹 `66:BA:…:F5:CC`（`CN=a.example`）；把同一路径覆盖成 B 证书（`36:E7:…:1A:F9`，`CN=b.example`）后等 2 s，新连接**仍然**是 A：

```
--- s_client after replacing files
subject=CN=a.example
sha256 Fingerprint=66:BA:02:…:F5:CC
--- dtls s_client
subject=CN=a.example
```

**SIGHUP 现状 = 直接死（实测）**：

```
$ kill -HUP $PID ; sleep 1
DEAD after SIGHUP
```

日志里没有任何 drain / 关闭行（最后一行仍是 `rstun: started, Ctrl-C to stop`）——即默认处置，不是我们自己的 handler。

---

## 2. TLS 监听：acceptor 在哪一层、能否换成可替换的 `Arc`

### 2.1 结构

- `tokio_rustls::TlsAcceptor` = `struct TlsAcceptor { inner: Arc<ServerConfig> }`（`tokio-rustls-0.26.6/src/server.rs:19-21`），`From<Arc<ServerConfig>>`（同文件 `23-27`）。
- `TlsAcceptor::accept()` 每次 `ServerConnection::new(self.inner.clone())`（`tokio-rustls-0.26.6/src/server.rs:61`），即**每个连接持有一个 `Arc<ServerConfig>` 快照**；rustls 的 `ServerConnection::new(config: Arc<ServerConfig>)`（`rustls-0.23.46/src/server/server_conn.rs:655`、`961`）把这个 `Arc` 存进连接。⇒ 已建立会话天然继续用旧配置；换 `Arc` 只影响之后的新连接。
- 本仓：`serve_turn_tls` 按值收 `acceptor`（`src/main.rs:3270-3276`），accept 循环里 `let acceptor = acceptor.clone();`（`3317`）再在 spawn 出的任务里 `acceptor.accept(stream)`（`3324`，5 s `SECURE_HANDSHAKE_TIMEOUT`，`3103`）。

### 2.2 现有共享方式能不能直接复用？

- **没有**现成的证书材料共享槽位：`ServerContext`（`src/main.rs:624-645`）放的是 plan/udp/admission/fingerprint/alternate_server/auth，不含监听材料；TLS acceptor 与 DTLS Config 是 `run()` 里的局部值，分别 clone 给每个监听任务（`1316`、`1374`）。
- 可复用的仓内惯例：`std::sync::RwLock` + `lock_read`/`lock_write` 帮助函数（`src/turn.rs:3564-3570`）。`tokio` 的 `sync` feature 也已启用（`Cargo.toml:52`），`watch` 同样可用、零新 crate。
- 替换粒度所需的上游 API 都在已用 crate 内：
  - **整体换 `ServerConfig`**：沿用现有 `ServerConfig::builder()...with_single_cert()` 重建（`src/main.rs:3168-3176`），只需把 `Arc<ServerConfig>` 放进 `RwLock`，accept 时 `TlsAcceptor::from(cfg.clone())`。
  - **只换证书**（不重建 `ServerConfig`）：`ServerConfig` 的证书来自 `cert_resolver: Arc<dyn ResolvesServerCert>`（`rustls-0.23.46/src/server/server_conn.rs:331-334`，`builder.rs:102 with_cert_resolver`），trait 定义在 `server_conn.rs:124-135`（`resolve() -> Option<Arc<sign::CertifiedKey>>`）。自建 resolver 需要 `rustls::crypto::ring::sign::any_supported_type()`（`rustls-0.23.46/src/crypto/ring/sign.rs:21`）+ `CertifiedKey::keys_match()`（`signer.rs:190`）——都在 rustls 内，无新依赖，但要多写一层解析代码。

### 2.3 「整体换 ServerConfig」的副作用（rustls 0.23 实测源码）

`ServerConfig::builder().with_cert_resolver()` 每次都给一份**新的** per-config 状态（`builder.rs:106-131`）：

- `session_storage: handy::ServerSessionMemoryCache::new(256)`（`builder.rs:113`）—— TLS 1.2 session-id 恢复缓存；新 config = 空缓存 ⇒ 重载后旧 session-id 恢复请求会退化成完整握手。
- `ticketer: Arc::new(handy::NeverProducesTickets {})`（`builder.rs:116`）—— **默认根本不发 TLS 1.3 ticket**，所以「ticket 密钥轮换导致恢复失败」在本仓不成立。
- rustls 自己也有专门章节提示两个 `ServerConfig` 共享 resumption 存储的问题：<https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#sharing-resumption-storage-between-serverconfigs>

---

## 3. DTLS 监听：Config / Certificate 的生命周期与会话语义

| 位置 | 内容 |
|---|---|
| `webrtc-dtls-0.12.0/src/config.rs:11-13` | `#[derive(Clone)] pub struct Config { pub certificates: Vec<Certificate>, … }`，注释：「After a Config is passed to a DTLS function it must not be modified」 |
| 同文件 `158-181` | `validate_config`：server 侧 `psk.is_none() && certificates.is_empty()` → `ErrServerMustHaveCertificate`；每个 cert 的 `private_key.kind` 只允许 `Ed25519`/`Ecdsa256` |
| `webrtc-dtls-0.12.0/src/crypto/mod.rs:30-35` | `Certificate { certificate: Vec<CertificateDer<'static>>, private_key: CryptoPrivateKey }`；`CryptoPrivateKey { kind, serialized_der: Vec<u8> }`（`151-156`）—— **clone 会复制 DER 字节**（几 KB 级） |
| `webrtc-dtls-0.12.0/src/crypto/mod.rs:69-102` | `Certificate::from_pem`：要求首块 tag 恰为 `PRIVATE_KEY`，后面全是 `CERTIFICATE`；链顺序按 PEM 顺序保留 |
| `webrtc-dtls-0.12.0/src/conn/mod.rs:152-158, 219` | `DTLSConn::new(conn, config: Config, is_client, initial_state)` → `local_certificates: config.certificates.clone()`（`219`） |
| `webrtc-dtls-0.12.0/src/handshaker.rs:90, 150-209` | 握手时从 `local_certificates[0]` 取证书链（`get_certificate()`），多证书链按序发出 |
| 本仓 `src/main.rs:3371-3378` | `serve_turn_dtls(listener, config: webrtc_dtls::config::Config, …)` —— 按值持有 |
| 本仓 `src/main.rs:3423` | accept 到新客户端后 `let config = config.clone();`（每客户端一次） |
| 本仓 `src/main.rs:3430-3432` | `timeout(SECURE_HANDSHAKE_TIMEOUT, DTLSConn::new(conn, config, false, None))` |

### 语义（[读代码]，结论明确）

1. **新连接拿到新证书的条件**：只要 accept 循环在 `config.clone()`（`3423`）之前读到「当前最新」的 `Config`（例如从一个 `Arc<RwLock<Arc<Config>>>` 里 clone），新握手就用新证书。
2. **已建立会话用旧证书**：`DTLSConn` 内部持有 `local_certificates` 的**副本**（`conn/mod.rs:219`），替换外层 `Config` 不影响它；DTLS 1.2 的重协商在本实现中没有实现（`webrtc-dtls` 只处理 `RenegotiationInfo` 扩展的编解码与 `NoRenegotiation` alert，见 `src/extension/renegotiation_info.rs`、`src/alert/mod.rs:64`），所以已建立会话**永久**用旧证书直到关闭。
3. **会话缓存**：webrtc-dtls 0.12 没有 session ticket / 会话缓存扩展（`src/extension/` 目录只有 server_name / elliptic_curves / point_formats / signature_algorithms / extended_master_secret / use_srtp / renegotiation_info），`grep -ri "ticket|resumption"` 无实现。⇒ 「旧缓存会话带旧证书」的隐患不存在。
4. **每客户端 clone 代价**：`Config::clone` 复制 `Vec<Certificate>`，其中每条证书复制 `Vec<CertificateDer>` + `serialized_der`（A 证书实测：`cert.pem` 615 B，`key.pem` 241 B；链更长时线性增长）。若改用 `Arc<Config>` 也只能省掉 listener→任务这一层的拷贝，`DTLSConn::new` 仍要求 owned `Config`。

---

## 4. 信号 / 文件监视现状与各自代价

### 4.1 现状（都已核对）

| 事实 | 证据 |
|---|---|
| `tokio` 已启用 `signal` feature | `Cargo.toml:45-54`（`"signal"` 在第 50 行） |
| `signal-hook-registry` 已在依赖树（lean 也有） | `cargo tree -e normal` 含 `signal-hook-registry`；`Cargo.lock:1369` |
| 已有信号处理只有 Ctrl-C + SIGTERM | `src/main.rs:3589-3608`（`SignalKind::terminate()` + `ctrl_c()`；`#[cfg(not(unix))]` 只有 `ctrl_c()`） |
| 优雅退出（drain）由第一次 shutdown 信号触发，第二次信号 `exit(0)` | `src/main.rs:1508-1524` |
| **无** SIGHUP | `grep -rn "SIGHUP\|SignalKind::hangup" src/` → 0 命中；实测 `kill -HUP` 进程直接消失、无日志（见 §1.4） |
| **无** 文件 mtime/轮询 | `grep -rn "metadata(\|mtime\|Modified" src/*.rs` → 0 命中 |
| **无** `notify`/`inotify` | `Cargo.lock` 无 `notify`、`notify-types`、`inotify`、`inotify-sys` |

### 4.2 代价对比

**A. 启用 `tokio` 的 SIGHUP（非新增 crate）**

- 代码：`tokio::signal::unix::signal(SignalKind::hangup())`（tokio 1.54.1 文档：<https://docs.rs/tokio/latest/tokio/signal/unix/struct.SignalKind.html#method.hangup>，「By default, the process is terminated by this signal」）。
- 依赖：**0 个新 crate**（feature 已开、`signal-hook-registry` 已在树里），仅 `#[cfg(unix)]`。
- 代价：Windows 上无此路径（需要另一条触发路径，否则 Windows 运维只能重启）；并且 `wait_for_shutdown` 目前 `select!` 在 `ctrl_c`/`terminate` 上，SIGHUP 必须**另起一个 task**（或改 `select!` 结构），否则会与 shutdown 语义纠缠。

**B. 引入 `notify`（新 crate，PRD 明确排除）**

- 版本现状：`notify 9.0.0`（2026-11-21，MSRV 1.91 ≤ 本仓 1.95），默认 feature `macos_fsevent`（+`objc2-core-foundation`/`objc2-core-services`）；Linux 走 `inotify`、Windows 走 `ReadDirectoryChangesW`（<https://docs.rs/crate/notify/latest>、<https://docs.rs/crate/notify/latest/features>）。
- 依赖增量：本仓 `Cargo.lock` 现有 `mio`/`bitflags`/`log`/`libc` 可复用，其余 `notify`、`notify-types`、`inotify`、`inotify-sys`、`walkdir`、`same-file`、`xxhash-rust`（`winapi-util` 仅 Windows）≈ **7–8 个新 crate 进 lock**（Linux 编译面 ≈ 7 个）。
- 额外成本：`script/ci/gen-sbom.sh:111` 的 `EXPECTED_DIRECT = {"lean": 10, "full": 14}` 断言、README「依赖面」表（`README.md:339-360`）、CHANGELOG 依赖说明都得同步；且直接依赖计数增加与仓内「每个依赖都写理由」的风格冲突。
- 行为成本：inotify 监听的是**inode**；证书轮换常见做法是「写临时文件 + `rename` 覆盖」，rename 后 watch 会指向旧 inode（需监听父目录 + 重新 watch）——这类平台差异要自己兜。

**C. `mtime`+`len` 轮询（无新 crate，跨平台一致）**

- 代码：一个 `tokio::time::interval` 任务 + 2 次 `std::fs::metadata`（或 `tokio::fs`）比较 `(mtime, len)`。
- 代价：2 次 `stat`/轮；60 s 间隔 = 2880 次/天，可忽略；但**轮询粒度决定平均生效延迟**（30 s 间隔 ≈ 平均 15 s）。
- 语义注意：`mtime` 精度与写入顺序无关——先写 cert 再写 key 的窗口内 `mtime` 也会变，所以**必须靠「解析成功」而不是「文件变了」**来做最终判定（见 §8）。

---

## 5. 跨平台

| 平台 | SIGHUP | 轮询 | 结论 |
|---|---|---|---|
| Linux | 有（`SignalKind::hangup()`） | 有 | 两条都可用 |
| macOS | 有（POSIX SIGHUP） | 有 | 两条都可用；**不需要**为 FSEvents 特判（只有用 `notify` 才涉及 FSEvents，且 notify 默认 feature 就带 `macos_fsevent`） |
| Windows | **无**（tokio 只有 `ctrl_c`、`ctrl_break`、`ctrl_close`、`ctrl_shutdown`；没有 hangup） | 有 | 轮询是唯一跨平台路径；本仓 CI 已构建 `x86_64-pc-windows-msvc`（`target/` 下有该目录） |

轮询间隔建议（[未验证]，属设计取值）：**30–60 s**，理由：证书轮换是人工/ACME 的低频操作；60 s 内 2 次 `stat`；比 inotify 差的只是「秒级生效」，而 `SIGHUP` 路径可以做到立即，二者互补。若要求「替换后 ≤5 s 生效」，轮询要压到 5 s（12 次 `stat`/分钟，仍可忽略 CPU，但日志/统计噪声与「半写窗口命中率」都会上升）。

`mtime` 的坑（[读代码]/[通用知识]，标注未在本仓验证）：某些文件系统 `mtime` 精度为 1 s（ext3、部分网络文件系统、某些容器 overlay），同秒内两次写入可能同值 → 因此判定条件建议是 `(mtime, len)` 二元组，且仍以「解析结果」为准，不能只看 `mtime` 变了就认为「一定可以重载」。

---

## 6. 可观测面

### 6.1 现有约束

- 标签面固定：`/metrics` 的 doc 注释（`src/ops.rs:242-251`）写明「Label sets are fixed (no per-peer labels)」，基数由 `transport × result`、`scope`、`direction` 枚举界定。
- TURN 指标族整体 gate 在 `if let Some(turn) = self.stats.turn()`（`src/ops.rs:418-528`）→ 未开 `--turn` 时**一条 `rstun_turn_*` 都不出现**（`src/ops.rs:249-252` 注释）。
- `handshake_failed` 先例：`turn::Counters.handshake_failed`（`src/turn.rs:372-377`，注释「Kept out of `/metrics` on purpose」），计数方法 `count_handshake_failure`（`src/turn.rs:818-823`，`#[cfg(feature = "tls")]`），只在退出日志打印（`src/main.rs:1604`）。
- 文档面同步点：`README.md:171-190`（指标表）、`docs/book/src/turn.md:36/40/43`（TLS 现状「启动时解析」、观测行）。

### 6.2 会因新增指标而受影响的既有测试

| 位置 | 断言 |
|---|---|
| `src/ops.rs:1526-1548`（`metrics_text_carries_help_type_and_fixed_label_sets`） | 断言各固定标签行存在，并且最后 `assert!(!text.contains("rstun_turn"))`（该 state 无 turn） |
| `src/ops.rs:1550-1560`（`metrics_follow_the_shared_counters`） | 只断言若干 `rstun_requests_total` 行 |
| `src/turn/tests.rs:1984-2026`（`turn_metrics_appear_only_when_enabled`） | 断言 turn 开启时各族存在；末尾 `assert!(!state.metrics().contains("rstun_turn"))`（turn 关闭） |

⇒ 只要新指标（a）用 `rstun_turn_` 前缀、（b）放在 `if let Some(turn)` 块内，这三处测试**不会**被破坏（它们靠子串 `rstun_turn` 做 gate 检查）。反之，若把指标命名为 `rstun_tls_*`（不带 `turn_`），`!text.contains("rstun_turn")` 检查**抓不到**，需要自己补 gate 测试。

### 6.3 建议新增（供 design 取舍，非实施）

| 指标 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `rstun_turn_tls_reload_total` | counter | `result="ok"\|"failed"` | 与既有 `rstun_turn_allocations_total{result=…}`/`rstun_turn_rejected_total{reason=…}` 的写法一致；枚举固定，不引入基数风险 |
| `rstun_turn_tls_cert_expires_seconds` | gauge | 无 | 当前 leaf 证书 `notAfter - now`（秒）；重载成功后更新；≤0 表示已过期 |

**到期秒数是唯一有依赖代价的指标**（现状/成本，实测）：

- rustls 不暴露 validity；`webrtc_dtls::crypto::Certificate` 也只有 DER + 私钥（`crypto/mod.rs:30-35`），无 notAfter。
- `x509-parser 0.16` 目前只是 **`webrtc-dtls` 的传递依赖**：`Cargo.lock:1699-1733` 的 webrtc-dtls 依赖列表含 `x509-parser`；`cargo tree --no-default-features --features tls`（111 行）里 **0 命中** `x509-parser`/`asn1-rs`/`oid-registry`/`nom`/`rusticata`。
- 若把它提升为直接依赖：full 构建 **0 个新 crate**（已在树中）；仅 `tls` 构建（`--features tls`，**CI 不测**这个组合，`ci.yml:74-94` 只测 lean 与 all-features）会新增 27 条 lock 条目（`x509-parser` 子树 32 项 − 已存在的 5 项），并让 `gen-sbom.sh:111` 的 full 直接依赖数 14→15（若计入 full 的 direct）。
- 与 PRD `prd.md:44`「不新增运行时依赖」冲突 ⇒ 若要 `expires_seconds`，现实选项只有：自写最小 DER 扫描（只读 `TBSCertificate.validity` 的两个 `Time`；RFC 5280 §4.1.2.5 的 UTCTime/GeneralizedTime 与 2050 世纪规则）；或**降低要求**（只在 full/dtls 构建里出该指标，或干脆只进日志）。**未验证**：自写扫描器在现实证书集上的正确性。

**失败/成功日志**（符合 PRD `prd.md:31`）：成功建议 `tracing::info!(not_after = …, fingerprint = …, "TURN TLS certificate reloaded")`；失败 `tracing::warn!(%error, "TURN TLS certificate reload rejected, keeping previous material")`——`error` 只可能是本仓 `String` 消息（`load_secure_material` 的错误全部是 `format!` 出来的、不含私钥）。

---

## 7. 验收路径（可复制）

### 7.1 造两套证书（与 lab `make_cert` 同形）

`script/lab/rstun-turn.sh:225-233` 的写法（ECDSA P-256 + PKCS#8，因为 DTLS 只收 ECDSA/Ed25519 且只读 PKCS#8）：

```bash
W=/tmp/opencode/certreload && mkdir -p "$W" && cd "$W"
for n in a b; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$n-sec1.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$n-sec1.pem" -out "live-$n-key.pem"     # PKCS#8
  openssl req -new -x509 -key "live-$n-key.pem" -out "live-$n-cert.pem" -days 2 \
    -subj "/CN=$n.example" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
done
```

### 7.2 起服务（TLS + DTLS 同时）

```bash
target/debug/rstun server --listen 127.0.0.1:13478 --turn --realm test --auth-secret s3cret \
  --auth-user u --auth-pass p \
  --turn-tls-listen 127.0.0.1:13534 --turn-dtls-listen 127.0.0.1:13535 \
  --tls-cert live-cert.pem --tls-key live-key.pem &
```

### 7.3 观测新连接用的是哪张证书（[已验证]）

```bash
# TLS
openssl s_client -connect 127.0.0.1:13534 -servername localhost </dev/null 2>/dev/null \
  | openssl x509 -noout -serial -subject -dates -fingerprint -sha256
# DTLS 1.2
openssl s_client -dtls1_2 -connect 127.0.0.1:13535 -servername localhost </dev/null 2>/dev/null \
  | openssl x509 -noout -serial -subject -dates -fingerprint -sha256
```

基线输出（A 证书）：

```
subject=CN=a.example
sha256 Fingerprint=66:BA:02:B0:14:D1:0A:F5:EF:4B:E7:40:E3:B6:A5:B3:3E:F7:06:84:9E:0E:3E:04:A7:FC:DA:5F:3B:98:F5:CC
```

TLS 与 DTLS 两条通道都拿到同一张 A 证书（DTLS 那次实测 `-dtls1_2` 输出同指纹）。

### 7.4 三条验收用例的具体做法

1. **正常运行中替换**：`cp live-b-cert.pem live-cert.pem && cp live-b-key.pem live-key.pem`（同一路径），触发 SIGHUP 或等轮询；再跑 7.3 应看到 `CN=b.example` 与新指纹；**已建立连接不受影响**：并发跑 `turnutils_uclient -S -t -u u -w p -p 13534 -n 200 -m 2 -y 127.0.0.1`（TLS）/ `-S`（DTLS），重载期间要求 `lost packets 0`（lab 的 `uclient_ok`，`script/lab/rstun-turn.sh:209-211`）。
2. **坏材料**：`cp live-b-key.pem live-key.pem`（不配对，cert 仍是 A）→ 期望 `do not form a usable pair ... KeyMismatch`（§1.4 实测文案），重载失败计数 +1，服务存活，7.3 仍是 A 证书；另外三种：`openssl genpkey -algorithm RSA`（DTLS 侧 `ECDSA P-256 or Ed25519`）、SEC1 私钥（`must be an unencrypted PKCS#8 private key`）、`head -c 200 cert.pem`（`is not valid PEM`）。
3. **DTLS 侧**：同 7.3 的 `-dtls1_2`；另外 `turnutils_uclient -S -p 13535`（lab `run_dtls` 的 `-S`/`-S -X` 两形状，`script/lab/rstun-turn.sh:860-877`）。

### 7.5 在现有 lab 里复用的写法

| lab 元素 | 位置 | 复用方式 |
|---|---|---|
| `BASE=34980`、`HEALTH_PORT=BASE+1`、`TLS_PORT=BASE+3`、`DTLS_PORT=BASE+4` | `script/lab/rstun-turn.sh:49`、`216-217`、`285` | 新增 `reload` 项不需要新端口，复用 tls/dtls 的项内端口即可（或 +5/+6 避开） |
| `make_cert` / `make_rsa_cert` | `225-244` | 生成第二套证书：复制 `make_cert` 写死 `cert.pem/key.pem` 的做法，改成 `make_cert_to DIR PREFIX` 或直接内联 openssl |
| `start_server` / `stop_server` | `131-147` | 起停（`stop_server` 用 SIGTERM，不干扰 SIGHUP 用例） |
| `wait_health` | `149-161` | 轮询 `/healthz` |
| `metric` | `163-167` | 读 `rstun_turn_tls_reload_total{result="failed"}` 等新指标 |
| `uclient_ok` | `209-211` | `grep -a -q "lost packets 0"` |
| `probe_secure_support` | `252-260` | lean 构建下 SKIP 的既有探测 |
| `run_frozen` | `1112+`（`--only frozen`） | 该改动全在 `tls`/`dtls` feature 与 `--turn` 内，**不影响** frozen 的 17 帧基线；保险起见 release 前跑一次 |

建议新项结构（不实施，仅给出可复用骨架）：

```
run_reload() {          # 依赖 make_cert / start_server / wait_health / metric / uclient_ok
  make_cert; make_cert_b   # 两套
  start_server reload ... --turn-tls-listen $TLS_PORT --turn-dtls-listen $DTLS_PORT
  wait_health $HEALTH_PORT
  fp_a=$(s_client_fp tls)          # openssl s_client | x509 -fingerprint
  cp cert-b cert.pem; cp key-b key.pem; kill -HUP $PID   # 或等轮询
  fp_b=$(s_client_fp tls); fp_dtls=$(s_client_fp dtls)
  [ "$fp_a" != "$fp_b" ] && [ "$fp_b" = "$fp_dtls" ]
  # 坏材料：cp key-c key.pem（不配对）→ 计数 +1、指纹仍 = fp_b、进程存活
}
```

---

## 8. 风险清单

| 风险 | 事实 / 证据 | 处理选项（供 design） |
|---|---|---|
| **半写文件（先 cert 后 key）** | 两个文件分两次写；中间态解析必失败（`KeyMismatch` 或 `no private key block`）。实测：A cert + B key → `do not form a usable pair ... KeyMismatch` | 轮询天然会重试下一轮；SIGHUP 只在收到信号时试一次。可选：失败后固定间隔（如 1 s）重试 N 次；或要求两次连续 `(mtime,len)` 一致才解析（去抖） |
| **`rename` 覆盖语义** | 用 `notify` 监听单文件时 rename 会让 watch 指向旧 inode（通用知识，未在本仓验证）；轮询不受影响 | 轮询方案天然规避；若将来上 `notify`，改为监听父目录 |
| **证书链顺序** | rustls 只校验 leaf（`cert_chain.first()`，`signer.rs:190-200`）与私钥配对，不校验链顺序/issuer；DTLS 侧按 PEM 顺序发出（`webrtc-dtls-0.12.0/src/handshaker.rs:150-209`） | 重载时链顺序错了**也能通过校验**但客户端会验证失败；是否加「链顺序/issuer 自检」需要新的 X.509 解析能力（见 §6.3 依赖问题） |
| **私钥权限** | 现状无任何权限检查：`std::fs::read` 直接读（`src/main.rs:3139/3157`），`grep -rn "metadata("` 无命中 | 重载时可 `std::fs::metadata` + `#[cfg(unix)] PermissionsExt::mode()` 检查是否 group/other 可读，只 warn 不拒绝（与仓内「warn 但不拦」的 `--alternate-server` 先例一致：`src/main.rs:1224-1230`） |
| **DTLS 会话缓存** | 无（见 §3 第 3 条）：不存在跨重载的会话恢复 | 无需处理；文档里写明「DTLS 会话不恢复」 |
| **TLS 1.2 session-id 恢复** | `ServerConfig` 重建 → 新的 `ServerSessionMemoryCache::new(256)`（`builder.rs:113`），旧 session-id 恢复失效；TLS 1.3 ticket 默认关闭（`builder.rs:116` `NeverProducesTickets`） | 若要保恢复能力，选「仅换证书（resolver）」粒度为可选项；否则文档写清 |
| **重载期间的并发** | 替换点若是 `RwLock<Arc<_>>`：读侧只在 accept 时 `read()+clone()`（纳秒级），写侧在重载时 `write()`；accept 循环不会阻塞在写锁上（除非写锁被长期持有） | 建议写侧「先在锁外完成 IO+解析，再短暂 write」——避免持锁做文件 IO |
| **重载失败是否该退出** | 仓内既有口径：「半配置拒绝启动」（`src/main.rs:1071-1107`、`load_secure_material` 全部 `Err`）。但轮换期失败通常意味着「文件正在写」，退出会打断所有连接——与 PRD `prd.md:47`「校验失败绝不降级明文、也不关闭监听器（只保留旧材料）」一致的是**不退出** | 见 §9 取舍 3 |
| **多监听器一致性** | 同一份 `SecureMaterial` 被 N 个 `--turn-tls-listen` / `--turn-dtls-listen` 共享（`1316`、`1374`） | 用**一个**共享槽位（而不是每监听器各一份），保证「一次重载全员生效」 |
| **lean 构建** | 全部代码在 `#[cfg(feature = "tls")]`/`#[cfg(feature = "dtls")]` 内；`--tls-cert` 等在 lean 下由 `build_turn` 拒绝（`1071-1075`） | reload 任务也必须 `#[cfg(feature = "tls")]` 且仅在 `secure.is_some()` 时 spawn，否则 lean 行为改变 |
| **`/metrics` gate** | 见 §6.2：必须沿用 `rstun_turn_` 前缀 + `--turn` gate，否则 gate 测试需要新写 | — |

---

## 9. 三个必须由 design 拍板的取舍

### D1. 触发方式：SIGHUP / 轮询 / 两者

| 选项 | 做法 | 代价 | 风险 |
|---|---|---|---|
| A. 仅 SIGHUP | `SignalKind::hangup()` + 独立 task | 0 新 crate；立即生效 | Windows 无此信号；「不想发信号」的容器场景（没有 `kill`）不可用 |
| B. 仅轮询 | `interval` + `(mtime,len)` 比较 | 0 新 crate；跨平台一致 | 生效有延迟（30–60 s 粒度）；每轮都要读 2 个 `stat`（可忽略）；半写窗口会被下一轮自然重试 |
| C. 两者（推荐，**与 PRD `prd.md:22-25` 一致**） | SIGHUP 立即触发 + 轮询兜底；共享同一个 `reload()` 函数 | 0 新 crate；代码量 ≈ C 的两倍于单一触发 | 需要去重（同一秒内 SIGHUP + 轮询同时来 → 用「解析结果与当前一致则不重复替换/不重复计数」） |
| D. `notify`/inotify | 见 §4.2 | +7–8 crate，违反 `prd.md:44` | 平台差异（rename/父目录）、SBOM 断言改动 |

**推荐 C**（SIGHUP 负责「立即」，轮询负责「跨平台 + 无信号场景」），常量间隔 30–60 s，SIGHUP 后若失败可选 1 s 级重试一次用于跨过写入窗口。

### D2. 替换粒度：整体 `ServerConfig` / 仅证书

| 选项 | 做法 | 代价 | 副作用 |
|---|---|---|---|
| A. 整体 `ServerConfig`（推荐） | 重建 `ServerConfig`（复用 `load_secure_material` 的 `3168-3176`），`RwLock<Arc<ServerConfig>>` 换 Arc；DTLS 侧换 `Arc<RwLock<Arc<Config>>>` | 最少的代码路径、与启动校验**完全同源**（PRD `prd.md:26`「同一套规则」）；TLS 与 DTLS 可以一次原子替换 | TLS 1.2 session-id 缓存被清空（本来 ticket 就没开）；`ServerConfig` 内的其他手工设置（本仓目前没有：`builder()` 默认 + `with_no_client_auth` + `with_single_cert`）会被重建重置——本仓无此问题 |
| B. 仅证书（`ResolvesServerCert` + `RwLock<Arc<CertifiedKey>>`） | `with_cert_resolver`（`builder.rs:102`）+ `any_supported_type` + `keys_match` | 保留 `ServerConfig`（含 resumption 状态），只需解析 cert/key；但**多一套**证书解析代码（不能直接复用 `with_single_cert`），且 DTLS 侧仍然只能整体换 `Config` ⇒ 两条替换路径 | 两套代码路径 = 两套失败语义（「TLS 换成功、DTLS 换失败」的半新半旧状态），与 PRD `prd.md:28`「替换窗口内不允许一半新一半旧」相冲突 |

**推荐 A**：单一「解析 + 校验」入口，TLS/DTLS 一次成型，天然满足 PRD 的原子性要求；代价只是 TLS 1.2 恢复缓存丢失（TURN 客户端几乎都用完整握手，且本仓默认不发 ticket）。

### D3. 失败策略：保留旧材料 / 退出

| 选项 | 做法 | 代价 | 与既有口径的关系 |
|---|---|---|---|
| A. 保留旧 + 计数 + warn（推荐） | 解析/校验任一失败：不替换、`reload_total{result="failed"}` +1、`tracing::warn!` | 运维必须看日志/指标才知道轮换没生效；坏证书可能一直用到过期 | 与 PRD `prd.md:47`（「校验失败绝不降级明文、也不关闭监听器」）一致；与启动期「拒绝启动」不矛盾（启动期没有「旧材料」可留） |
| B. 退出 | 失败即 `ExitCode::FAILURE`（与启动期同口径） | 一次「文件正在写」的竞态就会打掉所有 TURN 会话（PRD 背景要解决的就是这个）；轮询模式下会变成「反复重启」 | 违背 PRD 背景（`prd.md:5-7`） |
| C. 折中 | 失败不退出，但连续失败 N 次（如 5 次）或「证书已过期」时升级为 error / 可选退出 | 多一个计数器与阈值语义 | 可作为 A 的增强，不是本次必需 |

**推荐 A**，并把「证书即将过期」交给 `rstun_turn_tls_cert_expires_seconds` gauge 告警（这正是该指标的价值所在）。

---

## 10. 涉及文件清单（改前必读）

| 文件 | 行 | 说明 |
|---|---|---|
| `src/main.rs` | 343-362 | CLI 参数定义 |
| `src/main.rs` | 1039-1143 | `build_turn`：半配置 / feature / 材料成对校验 |
| `src/main.rs` | 1256-1284 | 启动期材料加载（唯一调用 `load_secure_material` 的地方） |
| `src/main.rs` | 1311-1335 | TLS 监听绑定 + `serve_turn_tls` 启动（acceptor clone 点） |
| `src/main.rs` | 1339-1380 | DTLS 监听绑定 + `serve_turn_dtls` 启动（Config clone 点） |
| `src/main.rs` | 3103 | `SECURE_HANDSHAKE_TIMEOUT = 5s` |
| `src/main.rs` | 3113-3237 | `SecureMaterial` + `load_secure_material`（校验规则唯一真源） |
| `src/main.rs` | 3241-3263 | `dtls_pem`（`PRIVATE_KEY` 首块重打包） |
| `src/main.rs` | 3270-3360 | `serve_turn_tls`（accept 循环，`3317` clone acceptor、`3324` accept） |
| `src/main.rs` | 3371-3460 | `serve_turn_dtls`（`3423` clone Config、`3431-3432` `DTLSConn::new`） |
| `src/main.rs` | 3473-3590 | `serve_turn_dtls_connection`（会话生命周期） |
| `src/main.rs` | 3589-3608 | `wait_for_shutdown`（Ctrl-C/SIGTERM；SIGHUP 若要加在这里附近） |
| `src/main.rs` | 1508-1524 | drain 与第二次信号 `exit(0)` |
| `src/main.rs` | 1590-1606 | 退出日志（TURN counters，含 `handshake_failed`） |
| `src/turn.rs` | 372-377, 403, 813, 818-823 | `handshake_failed` 计数（「不进 /metrics」先例） |
| `src/turn.rs` | 3564-3574 | `lock_read`/`lock_write`（可复用的锁惯例） |
| `src/ops.rs` | 242-252 | `/metrics` 标签面 & gate 约定 |
| `src/ops.rs` | 418-528 | TURN 指标块（新指标应放这里） |
| `src/ops.rs` | 1526-1560 | 受影响的指标测试 |
| `src/turn/tests.rs` | 1984-2026 | 受影响的 turn 指标测试 |
| `Cargo.toml` | 45-54 | `tokio` features（`signal` 已开） |
| `Cargo.lock` | 1369, 1596-1600, 1699-1733 | `signal-hook-registry`、`tokio-rustls`、`webrtc-dtls`（含 `x509-parser` 传递依赖） |
| `script/ci/gen-sbom.sh` | 111 | `EXPECTED_DIRECT = {"lean": 10, "full": 14}`（新增直接依赖必须同步） |
| `script/lab/rstun-turn.sh` | 49-63, 115-167, 209-244, 725-828, 834-913 | lab 常量 / 进程与指标 helper / 证书 helper / `tls`、`dtls` 项 |
| `README.md` | 171-190, 339-360 | 指标表 & 依赖面表 |
| `docs/book/src/turn.md` | 36, 40, 43 | TLS/DTLS 现状与观测说明 |
| `.github/workflows/ci.yml` | 74-94 | 只测 lean 与 all-features（**不测** `--features tls`） |

---

## 11. 未验证 / 未找到

1. **[未验证]** 自写 DER 扫描取 `notAfter` 的正确性与边界（UTCTime 2050 规则、链中有多张证书时只取 leaf）。没有实现也没有样例证书集去跑。
2. **[未验证]** 「已建立 TLS 连接在重载后继续工作」——当前没有重载机制，无法实测；结论来自 rustls `ServerConnection::new(Arc<ServerConfig>)`（`server_conn.rs:655`）与 tokio-rustls `accept` 里的 `self.inner.clone()`（`server.rs:61`）。
3. **[未验证]** 重载后 TLS 1.2 session-id 恢复确实退化：结论来自 `ServerConfig::builder().with_cert_resolver()` 里 `session_storage: ServerSessionMemoryCache::new(256)` 是**每 config 新建**（`builder.rs:113`）；没有构造「恢复」场景实测。
4. **[未验证]** 轮询在 Windows/macOS 上的 `mtime` 精度差异（只用 Linux 验证过 `stat` 行为）。
5. **未找到**：本仓/上游对 `--tls-cert` 的私钥文件权限检查（不存在）；`grep -rn "metadata("`、`grep -rn "mtime"` 均 0 命中。
6. **未找到**：`notify`/`inotify` 的任何现成依赖或代码（`Cargo.lock` 无）。
7. **未找到**：`webrtc-dtls 0.12` 的 session ticket / resumption 支持（`src/extension/` 无相关扩展，`grep -ri "ticket"` 无命中）。

## 参考链接（官方文档）

- tokio `SignalKind`（含 `hangup()` 默认处置说明）：<https://docs.rs/tokio/latest/tokio/signal/unix/struct.SignalKind.html>
- rustls `ServerConfig`（resumption 存储共享警告）：<https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html#sharing-resumption-storage-between-serverconfigs>
- rustls `ResolvesServerCert`：<https://docs.rs/rustls/latest/rustls/server/trait.ResolvesServerCert.html>
- tokio-rustls `TlsAcceptor`：<https://docs.rs/tokio-rustls/latest/tokio_rustls/struct.TlsAcceptor.html>
- webrtc-dtls `Config`：<https://docs.rs/webrtc-dtls/latest/webrtc_dtls/config/struct.Config.html>
- notify（平台后端 / feature flags）：<https://docs.rs/crate/notify/latest>、<https://docs.rs/crate/notify/latest/features>
- RFC 5280 §4.1.2.5（Validity / UTCTime / GeneralizedTime）：<https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5>
