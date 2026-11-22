# 设计：`turns:` / DTLS 证书热加载

> 依据：`research/cert-reload.md`（437 行；含 `file:line`、失败文案实测、依赖代价）。下列「已验证」项直接采用。

## 1. 四个取舍（D1–D3 研究推荐，D4 为实现必需）

| # | 取舍 | 决定 | 理由 |
| --- | --- | --- | --- |
| **D1** | 触发方式 | **SIGHUP（unix）+ 文件轮询（30s）共用同一个 `reload()`** | `tokio/signal` **已启用**、`signal-hook-registry` 已在依赖树 ⇒ SIGHUP **零新依赖**；轮询覆盖 Windows 与「不发信号」场景；`notify` 会新增 7–8 个 lock 条目并违反 PRD 的「不新增运行时依赖」 |
| **D2** | 替换粒度 | **整体替换 `Arc<ServerConfig>` + `Config`（不是只换证书）** | 与启动校验同源（`with_single_cert` / DTLS 算法约束），一次 swap 天然原子，不会出现 TLS/DTLS 半新半旧；代价：TLS1.2 session-id 缓存随 `ServerConfig` 重建清空（TLS1.3 ticket 默认本就不发）——写进文档 |
| **D3** | 失败策略 | **保留旧材料 + `reload_total{result="failed"}` + warn 日志** | 写入竞态（先写 cert 后写 key）不应打掉全部会话；到期风险交给运维告警（见 D4 的日志字段） |
| **D4** | 证书到期指标 | **本版不加 gauge**；重载成功日志里打印 `not_after`（ISO8601）与 `days_left` | 唯一的到期解析器 `x509-parser` 只是 `dtls` 的**传递**依赖，提升为直接依赖会让 tls-only 树多 27 条 lock、full 直接依赖 14→15，并破坏 `gen-sbom.sh` 的断言。自写 DER 扫描属未验证方向，不做。若将来需要 gauge，单独立项评估依赖 |

## 2. 共享材料槽位

现状（研究 §2/§3）：

- `build_turn` → `load_secure_material()` 产出 `SecureMaterial`（`src/main.rs:3132` 起），
  TLS 侧 `ServerConfig` 按值进 `serve_turn_tls`（`:3270`），每连接 clone（`:3317`）；
  DTLS 侧 `webrtc_dtls::Config`（Clone）按值进 `serve_turn_dtls`（`:3371`），每客户端 clone（`:3423`）。
- **没有共享槽位**，所以「一次重载全员生效」需要新增一个。

设计：

```rust
struct SharedMaterial {
    config: Arc<rustls::ServerConfig>,
    #[cfg(feature = "dtls")]
    dtls: webrtc_dtls::config::Config,
}

type MaterialSlot = Arc<std::sync::RwLock<Arc<SharedMaterial>>>;   // 仓内已有 lock_read/lock_write 惯例
```

- 启动时构造一次 `Arc<SharedMaterial>` 放进槽位；
- `serve_turn_tls`：每次 accept 时 `lock_read(&slot).config.clone()` 构造 `TlsAcceptor`（Arc clone，廉价）；
- `serve_turn_dtls`：每次新客户端时 `lock_read(&slot).dtls.clone()`；
- 重载：**先完整解析并校验新材料的 `SharedMaterial`**，成功后再一次性 `*lock_write(&slot) = Arc::new(new)`。
- 语义：新连接用新材料；已建立会话持有旧副本（TLS 1.3/1.2 与 DTLS 均无重协商）——文档写清。

## 3. 热载任务

```
spawn_cert_reloader(paths, needs_dtls, slot, counters)
  ├─ unix: tokio::signal::unix::signal(SIGHUP) ──┐
  └─ tokio::time::interval(30s) + (mtime,len) ───┴─► reload()
```

`reload()`：

1. 读 `(mtime, len)` 两文件；与「上次成功/上次尝试」相同 → 跳过（避免日志与解析空转）。
2. `load_secure_material(cert, key, needs_dtls)`（与启动**同一函数**）；
3. `Err` → 等 1s 重试一次（跨过「先写 cert 后写 key」的窗口）；仍失败 →
   `reload_failed += 1`、`warn!`（含原因，不含私钥）、保留旧材料、记录「已尝试的 mtime/len」；
4. `Ok` → 换槽位、`reload_ok += 1`、`info!(not_after, days_left)`（`not_after` 由 rustls 已解析的
   `CertificateDer` 里能拿到的信息？——**不能**：`ServerConfig` 不暴露 notAfter。见 §3.1）。

### 3.1 `not_after` 的来源（重要）

`rustls` 的 `ServerConfig` 不回读证书的 `notAfter`，本版又不引入 `x509-parser`。因此：

- 日志只打印**文件路径与 mtime**，以及「重载成功」；
- `days_left` **不在本版提供**（PRD 里「到期剩余秒数」改为「可选、后续任务」）。

> 决策修正：D4 从「日志打印 not_after」降级为「不提供到期信息」，避免为了日志字段引入解析器或手写 DER。
> 运维可用外部工具（`openssl x509 -enddate`）检查文件，或等后续单独立项。

## 4. 指标（固定标签集）

| 指标 | 类型 | 标签 |
| --- | --- | --- |
| `rstun_turn_tls_reload_total` | counter | `result="ok" \| "failed"` |

- 放在现有 `--turn` 指标块（`src/ops.rs:414-504`），沿用 `rstun_turn_` 前缀 ⇒ 不破坏
  `ops.rs:1526` 与 `turn/tests.rs:1984/2026` 的 gate 断言；
- 退出日志同时打印 ok/failed 计数（与既有 `handshake_failed` 先例一致）。

## 5. 触发与去抖细节

- 轮询间隔常量 `CERT_POLL_INTERVAL = 30s`（文档写明「最坏生效延迟 30s」）。
- SIGHUP 立即触发；与轮询共用同一 `reload()`，用「上次尝试的 (mtime,len)」去重。
- 失败后 1s 重试一次；两次都失败才计 failed（避免半写窗口噪音）。
- **rename 语义**：轮询只看路径的 `(mtime,len)`，`mv` 覆盖后 stat 会变 → 可感知；
  不依赖 inode 事件（避免 `notify`）。

## 6. 跨平台

| 平台 | SIGHUP | 轮询 |
| --- | --- | --- |
| Linux/macOS | ✅ `tokio::signal::unix` | ✅ |
| Windows | ❌（`cfg(unix)` 编译掉）| ✅ 唯一路径 |

Windows 上的行为写进文档：**最坏 30s 生效**，无信号触发。

## 7. 失败边界（研究 §8）

| 场景 | 行为 |
| --- | --- |
| 先写 cert 后写 key（半写） | 第一次解析失败 → 1s 重试 → 通常第二次成功；仍失败则保留旧材料 + failed |
| 证书/私钥不配对（`KeyMismatch`） | 拒绝、保留旧、failed+1 |
| RSA / 非 PKCS#8 / 截断 / 空文件 | 同上（复用启动校验的报错文本）|
| 链顺序错 / issuer 不匹配 | **不校验**（rustls 只比 leaf）——文档注明与启动一致 |
| 私钥权限 | 不检查（与启动一致）|
| 重载期间并发 accept | 读锁克隆旧值或新值，二者都自洽（整体替换）|

## 8. 验收（与 PRD 对齐）

1. 运行中覆盖同路径证书 → SIGHUP → `s_client` **新连接**指纹/序列号变化；旧连接不断；
2. 轮询路径（Windows 或临时把间隔调小）同样生效；
3. 坏材料四种（不配对 / RSA / 非 PKCS#8 / 截断）→ 旧证书继续、`reload_total{result="failed"}` 增长、进程存活；
4. DTLS：`s_client -dtls1_2` 新会话看到新证书；
5. 默认路径冻结与 `cad4fa2` 一致；lean 构建不受影响（代码在 `tls` feature 下）；
6. 全量门禁 + lab `tls`/`dtls` + 新增 `cert-reload` 项。

## 9. 回滚

单 commit；revert 即回到「启动时加载一次」。运行期无需开关（热载是纯增量能力）。

## 10. 待确认（主会话/评审）

1. 轮询间隔固定 30s 还是加 `--tls-cert-poll <secs>`（0=禁用）？**默认取固定常量**，除非评审要求可配。
2. 是否要在 Windows 上也提供「命令触发」（例如 `--tls-reload-request-file`）？本设计**不做**。
