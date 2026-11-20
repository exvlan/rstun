# 设计：依赖主版本升级（两阶段）

## 1. 边界

- **全部依赖升到各自最新**（用户定稿）：`clap`、`tokio`、crypto 栈（`sha1/sha2/md-5/hmac`）、
  `webrtc-util`，以及其间的 patch/minor；不借机重构鉴权/DTLS。
- 升级完成后**发补丁版**（用户定稿）：版本号 `26.410.101`（`YY.QMM.Mmpp` 的 patch+1），
  crates.io 重发 + Release 11 资产 + 双架构镜像，并告知生产新 digest。
- 分两阶段，各自独立可回滚：
  - **阶段 0**：semver 兼容的 patch/minor（`clap 4.6.9`、`tokio 1.54.1`、`tokio-rustls 0.26.6` 等）；
  - **阶段 1**：`sha1` / `sha2` / `md-5`（`digest 0.10 → 0.11`）→ 再 `hmac 0.12 → 0.13`；
  - **阶段 2**：`webrtc-util 0.11 → 0.17`（DTLS 链，可能连带 `webrtc-dtls`）；
  - **阶段 3**：版本号 `26.410.101` + `CHANGELOG`，进入发布（由主会话执行 publish/release）。
- 不改协议字节、不改 CLI、不改指标名。

## 2. 阶段 1：crypto 栈

### 2.1 影响面

| 位置 | 用法 | 迁移风险 |
| --- | --- | --- |
| `src/auth.rs` | `Hmac<Sha1>::new_from_slice(key)`、`mac.update(...)`、`mac.finalize().into_bytes()` | `hmac 0.13` + `digest 0.11`：`Mac` trait 路径与输出类型（`hybrid-array::Array`）可能变；`into_bytes()` 可能返回 `CtOutput`/数组 |
| `src/auth.rs` | `Md5::digest(...)`、`Sha256::digest(...)` | `digest 0.11` 的 `Digest` trait 基本保持，但 `Output` 大小类型变化可能影响 `[u8; 16]/[u8; 32]` 转换 |
| `src/turn.rs` / `src/main.rs` | 间接调用（key 派生） | 仅经 `auth` API，不改 |

### 2.2 策略

1. 先升 `sha1`/`sha2`/`md-5`（同一 `digest` 版本，必须一起升）；`hmac` 暂留 0.12 看是否还能编译（若 `digest` 0.11 不兼容 0.12 则同步升 0.13）。
2. 适配点集中在 `src/auth.rs`；**不改算法与向量**。
3. 用现有向量锁死行为：
   - RFC 2202（HMAC-SHA1）、RFC 4231（HMAC-SHA256）、RFC 1321（MD5）；
   - RFC 5769 §2.4 长凭据向量；
   - nonce 编解码与跨实例一致性。

### 2.3 验收

- `cargo test` / `--all-features` 全绿（向量不改）；
- 默认路径字节冻结（3 配置 × 17 请求）；
- `cargo audit` / `cargo deny` 不退化；
- PR #3/#4/#6/#7 合并（或由本任务提交取代）。

## 3. 阶段 2：webrtc-util 0.17

### 3.1 先决调查（写进 `implement.md`）

```bash
cargo tree -i webrtc-util
cargo tree -i webrtc-dtls
cargo info webrtc-dtls | head
```

判定三类：
- **A**：`webrtc-dtls 0.12` 允许 `webrtc-util 0.17` → 只升 `webrtc-util`；
- **B**：需要同时升 `webrtc-dtls`（如 0.12 → 0.13+）→ 连带评估 API（`DTLSConn::new`、`Config`、`Certificate`）；
- **C**：上游组合不可行（例如 `webrtc-dtls` 最新仍锁旧 `webrtc-util`）→ **关闭 PR #5** 并在 PR/任务里写明「等上游」，不硬升。

### 3.2 若走 A/B

- 适配 `src/main.rs` 的 DTLS 监听/握手（`ListenConfig`、`DTLSConn::new` 参数、`handshake` 超时）；
- 证书解析（PKCS#8/ECDSA）路径不变；RSA 拒绝逻辑保留；
- 验收：`rstun-turn.sh --tls --dtls` 全绿（真实 `uclient -S` 中继 + `openssl s_client -dtls1_2`）；
- 冻结：默认关闭字节不变。

## 4. 与发布的关系

- 升级不改变 `rstun-v26.410.100` 的 Release 资产；若在**下一个版本**发布前完成，则随下一版生效。
- 若阶段 1 改变二进制体积 >10%，记录到 `implement.md`，不阻塞。

## 5. 回滚

- 每个阶段一个（或两个）commit；回滚 = revert 对应 commit（只涉及 `Cargo.toml`/`Cargo.lock`/`src/auth.rs` 或 `src/main.rs`）。
- Dependabot PR 在阶段完成前保持 open；若选择「本任务提交取代」，合并后 PR 会自动关闭/可手工关闭。

## 6. 风险

| R | 缓解 |
| --- | --- |
| `digest 0.11` 破坏 `hmac 0.12` | 允许两者一起升；向量测试兜底 |
| `webrtc-util 0.17` 无兼容的 `webrtc-dtls` | 走 C：关闭 PR，写明原因，不硬升 |
| 升级引入新公告 | `cargo audit` 必须保持 0 vulnerability（新增 unmaintained 需登记） |
| 时序：Dependabot 继续 rebase PR | 以本任务提交为准，PR 合并/关闭后停止 |
