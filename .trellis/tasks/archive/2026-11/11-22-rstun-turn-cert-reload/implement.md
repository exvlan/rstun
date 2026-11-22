# 执行计划：证书热加载

> 顺序：先「共享槽位」（不改行为）→ 再「SIGHUP」→ 再「轮询/去抖」→ 最后 lab 与文档。
> 不 commit / 不 bump 版本（主会话执行）。

## 阶段 0a · 依赖与数字（`x509-parser`）

| # | 事项 | 验证 |
| --- | --- | --- |
| 0a.1 | `Cargo.toml`：`x509-parser = { version = "0.16", optional = true, default-features = false }`，`tls = [..., "dep:x509-parser"]` | `cargo tree -e normal --depth 1` lean 仍 10；`--all-features` 15 |
| 0a.2 | `script/ci/gen-sbom.sh`：`EXPECTED_DIRECT.full` 14 → 15 | `bash script/ci/gen-sbom.sh` 能跑通（或 --help 分支）|
| 0a.3 | `README` 依赖面表：full 15（lean 10、Windows full 14），注明 x509 用于到期指标 | 人工评审 |
| 0a.4 | `.trellis/spec/backend/{turn,ops,distribution}.md` 同步依赖数字与指标 | 人工评审 |

## 阶段 0b · 共享材料槽位（行为不变）

| # | 事项 | 验证 |
| --- | --- | --- |
| 0.1 | 引入 `SharedMaterial` + `MaterialSlot`（`Arc<RwLock<Arc<SharedMaterial>>>`）；启动时构造一次 | `cargo test --all-features` 现有 TLS/DTLS 用例全绿 |
| 0.2 | `serve_turn_tls` 改为每次 accept 从槽位取 `Arc<ServerConfig>` | lab `tls` 项绿 |
| 0.3 | `serve_turn_dtls` 改为每次新客户端从槽位 clone `Config` | lab `dtls` 项绿 |

## 阶段 1 · 重载核心

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | `reload_material(slot, paths, needs_dtls, counters) -> Result<(), Error>`：复用 `load_secure_material()`，成功后整槽替换 | 单测（用临时证书目录）|
| 1.2 | 失败保留旧材料 + `reload_failed` + warn（含原因，不含私钥）| 单测：坏材料后槽位内容不变 |
| 1.3 | 失败后 1s 重试一次；两次都失败才计 failed | 单测（半写模拟：先只写 cert）|
| 1.4 | `(mtime,len)` 去重：未变化不解析、不记日志 | 单测 |

## 阶段 2 · 触发

| # | 事项 | 验证 |
| --- | --- | --- |
| 2.1 | unix：`tokio::signal::unix::signal(SIGHUP)` → `reload_material`（`cfg(unix)`）| lab：`kill -HUP` 后新连接见新证书 |
| 2.2 | 全平台：`tokio::time::interval(30s)` + `(mtime,len)` 变化 → `reload_material` | lab：`--only cert-reload`（把间隔用测试钩子缩短或直接等待）|
| 2.3 | 重载任务在 shutdown 时退出（复用现有 shutdown 信号）| 退出无 panic/hang |

## 阶段 3 · 指标与日志

| # | 事项 | 验证 |
| --- | --- | --- |
| 3.1 | `rstun_turn_tls_reload_total{result}` + `rstun_turn_tls_cert_expires_seconds`（`ops.rs` 固定标签集 + 文档 + 逐行断言）| `turn_metrics_appear_only_when_enabled` 更新 |
| 3.1b | `x509-parser` 解析链首 DER 的 `notAfter`：启动一次 + 每次重载后重算；gauge = 缓存时间戳 − now | 单测：与 `openssl x509 -enddate` 比对（±60s）|
| 3.2 | 退出日志打印 ok/failed 计数 | 退出日志断言 |
| 3.3 | `--turn` 未开/TLS 未启用时不出现该指标 | 现有 gate 测试 |

## 阶段 4 · lab 与文档

| # | 事项 | 验证 |
| --- | --- | --- |
| 4.1 | lab 新增 `cert-reload` 项：起 TLS 服务 → `s_client` 取指纹 → 覆盖证书+私钥 → `SIGHUP` → 新指纹不同；再换坏材料 → 指纹不变 + `reload_total{result="failed"}` 增长 | `--only cert-reload` |
| 4.2 | DTLS 侧同样验一次（`s_client -dtls1_2`）| 同上 |
| 4.3 | 文档：`docs/book` 的 `turns:`/DTLS 章节写「SIGHUP / 30s 轮询 / 新连接生效 / 已有会话持有旧证书 / 失败保留旧材料 / Windows 无信号」 | `check-docs.sh` |
| 4.4 | `README` 摘要、`CHANGELOG ## Unreleased`、`.trellis/spec/backend/turn.md`、`src/turn.rs` 头注释 | 人工评审 |

## 门禁（每阶段）

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-turn.sh
bash script/lab/rstun-turn.sh --tls --dtls
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/ci/check-docs.sh --no-build
cargo audit; echo "audit=$?"
cargo deny check
cargo check --all-targets --target x86_64-pc-windows-msvc
```

## 验收断言

- [ ] SIGHUP 与 30s 轮询都能让**新连接**看到新证书；旧连接不断
- [ ] 四种坏材料（不配对 / RSA / 非 PKCS#8 / 截断）→ 保留旧证书、failed 计数 +1、进程存活
- [ ] 半写窗口（先写 cert）不会误判（1s 重试）
- [ ] DTLS 新会话见新证书
- [ ] 指标符合固定标签集；TLS 未启用时不出现
- [ ] 默认路径冻结不变；lean 构建不含该代码（feature gate）
- [ ] Windows target 编译通过（`cfg(unix)` 隔离信号）

## 回滚

单 commit；revert 回到「启动时加载一次」。

## 执行记录（2026-11-22）

| 项 | 结果 |
| --- | --- |
| 触发 | SIGHUP（unix，注册在 spawn 之前）+ 30s 轮询；同一 `reload()`；`(mtime,len)` 去重；失败 1s 重试一次 |
| 替换 | 整体替换 `Arc<ServerConfig>` + `webrtc_dtls::Config`（单槽位），TLS/DTLS 同步生效 |
| 校验 | 复用 `load_secure_material(…, setup.needs_dtls)`；DTLS 的 PKCS#8 / ECDSA-P256 / Ed25519 规则未放宽 |
| 失败 | 保留旧材料 + `reload_total{result="failed"}` + warn；进程存活 |
| 指标 | `rstun_turn_tls_reload_total{result}` + `rstun_turn_tls_cert_expires_seconds`（仅 secure 监听存在时输出；解析失败 -1）|
| 依赖 | `x509-parser 0.16`（optional，`tls` feature，default-features=false）；lean 10 / full 15（Windows 14）|
| 体积（实测，十进制 MB） | 未 strip **3.92 / 8.15**；LTO+strip **2.44 / 4.95**（README/release.yml/Dockerfile/docker.md 已同步）|
| lab | `cert-reload`：SIGHUP 后 TLS/DTLS 指纹同步变化、**已建立会话跨重载仍回 0x0111**、轮询换第三张、坏材料保留现役（failed+1）、expires 与 openssl drift 0s |
| 单测 | 新增 2 条并做变异反证：半写窗口重试成功（删 retry 逻辑即 FAIL）、`needs_dtls=true` 拒绝 RSA（写死 false 即 FAIL）|
| 复核 | 「可提交（技术正确性无阻塞）」；SIGHUP/SIGTERM 互不干扰、未放宽 DTLS 校验、`CONDITIONAL_METRICS` 反证可拦截漂移 |

### 复核修正（已落地）

1. **文档事实错误**：原文称「替换 ServerConfig 会清空 TLS1.2 会话缓存」——本实现 rustls 默认
   `NoServerSessionStorage` + `NeverProducesTickets`，**从未启用会话恢复**；已改为准确表述。
2. 补「半写 → 重试成功」单测与 `needs_dtls` 热载单测（各有变异证据）。
3. lab 增「已建立会话跨重载仍可收发」断言。
4. SIGHUP 注册前移、`recv()==None` 不空转、`(mtime,len)` 盲区写入运维注意。

### 已知限制（记录）

- 未配置 `turns:`/DTLS 监听时不注册 SIGHUP（该场景下 SIGHUP 仍是默认处置=终止进程）；
- `(mtime,len)` 都不变（`cp -p`/保留时间戳）时轮询不感知，需 `kill -HUP` 强制；
- 重载器任务 panic 会导致轮换静默停止（`/healthz` 仍 200）——未加活性观测。

## 发版执行记录（26.410.104，主会话）

与 RFC 6062（出站 TCP allocation）合并发布。

| 项 | 结果 |
| --- | --- |
| 版本提交 | `b53a8ed` |
| crates.io | ✅ `rstun 26.410.104`；干净安装通过，`--turn-tcp-relay` 在 `--help` 中出现 |
| Release | ✅ `rstun-v26.410.104`，**13 资产**（8 zip + 2 SBOM + rb + 2 deb）|
| 镜像 | `ghcr.io/exvlan/rstun:26.410.104`（amd64+arm64，full）|
| **manifest digest** | `sha256:549ba69ed3b1af2c90f92a1230b9a7e2db6c97629478dc1ea7a0ec993b7b79d6` |
| deb 抽检 | `Version: 26.410.104`，解包执行 `26.410.104+b53a8e` |
| Homebrew tap | 已同步 `.104`（类体与 Release `rstun.rb` 一致，3 个 sha256 逐条核对）|
| 版本钉死点 | README / docker.md / contrib{k8s,compose,helm×2} → `.104` |

### 首次发布失败（基础设施，不是代码）

run `44989059835` 的 `Build (macos-x86_64)` 失败于 macOS runner 的 **DNS 故障**：
`error sending request … dns error: failed to lookup address information`（拉 `channel-rust-1.95.toml.sha256`）。
`gh run rerun --failed` 后全绿；镜像未被重建，digest 保持首次成功值。
