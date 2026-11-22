# 执行计划：证书热加载

> 顺序：先「共享槽位」（不改行为）→ 再「SIGHUP」→ 再「轮询/去抖」→ 最后 lab 与文档。
> 不 commit / 不 bump 版本（主会话执行）。

## 阶段 0 · 共享材料槽位（行为不变）

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
| 3.1 | `rstun_turn_tls_reload_total{result}`（`ops.rs` 固定标签集 + 文档 + 逐行断言）| `turn_metrics_appear_only_when_enabled` 更新 |
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
