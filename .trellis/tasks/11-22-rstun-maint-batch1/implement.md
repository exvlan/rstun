# 执行记录：`--tls-cert-poll`（维护批一 A 项）

> 本轮只做 A；B（`docs/perf.md` → `.104`）下一轮。不 commit / 不 bump 版本 / 不动 `release.yml`。

## 1. 契约（flag 名 / 默认值 / 校验矩阵）

| 取值 | 行为 |
| --- | --- |
| 不传 | **30s 轮询 + SIGHUP**（与 `.104` 逐行为一致）|
| `0` | 不启动轮询；`SIGHUP` 仍生效（unix）|
| `>0` | 该间隔轮询（秒）|
| 无 `--turn-tls-listen`/`--turn-dtls-listen` 却给了（含 0）| 启动失败：`--tls-cert-poll needs --turn-tls-listen or --turn-dtls-listen: …` |
| Windows（无 SIGHUP）+ `0` | 启动失败：`--tls-cert-poll 0 is not allowed on this platform: there is no SIGHUP, …` |
| lean 构建给该 flag | 启动失败，错误含 `` `tls` feature `` 与 `--features tls,dtls` |
| 给了但没 `--turn` | `… --tls-cert-poll need --turn` |
| `RSTUN_TLS_CERT_POLL` | 与 CLI 同语义（CLI 优先；空值=未设置）|

## 2. 实现要点

| # | 事项 | 文件 |
| --- | --- | --- |
| 1 | `Args::tls_cert_poll: Option<u64>`（`--tls-cert-poll <SECONDS>`，紧跟 `--tls-key`）| `src/main.rs` |
| 2 | `cert_poll_interval(requested, has_secure_listener, has_sighup) -> Result<Option<Duration>, String>` —— 纯函数，两条负例都在这里；`has_sighup` 作参数，Windows 规则在任意平台可测 | `src/main.rs` |
| 3 | `build_turn` 调用它做校验（半配置、需 `--turn`、lean feature 门）；`run` 用同一个函数取值，两边不可能分歧 | `src/main.rs` |
| 4 | `SecureSetup.poll: Option<Duration>` 携带结果；`None` = 不 spawn 轮询 | `src/main.rs` |
| 5 | `spawn_cert_reloader`：`interval.map(...)` → `Option<Interval>`；`select!` 的轮询臂改为 `cert_poll_tick(&mut poll)`（`None` 时 `pending()`，永不到点），SIGHUP 臂抽成 `cert_hangup`（语义与原来逐字一致）| `src/main.rs` |
| 6 | `run` 里 `poll.is_none() && !cfg!(unix)` 时不 spawn（该组合启动已被拒，任务将无事可做）| `src/main.rs` |
| 7 | `RSTUN_TLS_CERT_POLL` 加入 `ENV_FLAGS` 与 `overlay!` 清单 | `src/ops.rs` |
| 8 | lab 新增 `cert-poll` 项（`--only cert-poll`，自动 `--features full`）| `script/lab/rstun-turn.sh` |

「0 不 spawn 轮询」的可断言形态：`cert_poll_interval(Some(0), true, true) == Ok(None)`，
reloader 持有 `SecureSetup.poll == None`，其轮询臂是 `pending()`，只有 SIGHUP/drain 能唤醒它。

## 3. 测试

单测（`src/main.rs` tests）：

- `cert_poll_interval_defaults_to_30s_and_can_be_disabled`：不传 → `Some(30s)`（含 `has_sighup=false`）；
  `0` → `None`；`2` → `Some(2s)`。
- `cert_poll_needs_a_secure_listener_and_a_signal_source`：无 secure 监听 × {0,2,30} → 错误含
  `--tls-cert-poll`/`--turn-tls-listen`；`has_sighup=false` + `0` → 错误含 `SIGHUP`；
  Windows 下正整数与默认值仍可用。
- `tls_cert_poll_needs_a_secure_listener`（`#[cfg(feature = "tls")]`）：`build_turn` 两条负例；
  有监听时接受 2 与 0（0 按平台 `cfg(unix)` 断言）；无 `--turn` → `need --turn`。
- `lean_build_refuses_tls_flags_with_the_feature_name` 增加 `tls_cert_poll: Some(0)` 一例。

lab：`cert-poll`（无监听拒绝启动 / `0` 下 reloader 启动行 `poll=None` 且 4s 内改文件不重载、SIGHUP 重载 /
`2s` 下启动行 `poll=Some(2s)` 且约 2s 重载）。

## 3a. 冷复核后的修正（4 条）

| # | 问题 | 修法 |
| --- | --- | --- |
| 1（必修）| lab `cert-poll` 的 `0` 分支**没有判别力**：只等 4s，而默认 tick 是 30s（且首个 tick 在 spawn 时吃掉），把 `setup.poll` 改成 `.or(Some(30s))` 后 3 个单测与 lab 全绿 | `spawn_cert_reloader` 启动时打 `tracing::info!(poll = ?interval, "rstun: certificate reloader started")`（`Some(30s)` / `None`）；lab 用 ANSI 安全的 `reloader_poll_matches()` 断言 `0` 分支日志含 `poll=None`、`2s` 分支含 `poll=Some(2s)`；4s「文件变了但指纹不变」断言保留。注释改为「4s 抓不到 30s 定时器变异体，判别性证据是启动行」 |
| 2（必修）| `README.md` 的 lean 启动错误示例缺 `/ --tls-cert-poll` | 同步为真实输出（与 `:424` 一致）|
| 3（建议）| `README.md` 摘要「`SIGHUP` 或 30s 文件轮询」过期 | 改为「默认 30s，`--tls-cert-poll` 可调、`0` = 只认 `SIGHUP`」|
| 4（建议）| SIGHUP 注册失败时固定 warn「falls back to polling」，`poll=None` 时与事实相反 | 按 `setup.poll` 分支：`Some` → 原 warn；`None` → `error!`「无 SIGHUP 且轮询已关闭 → 证书将不再自动轮换」|

**变异证据**（把 `let interval = setup.poll;` 改成 `setup.poll.or(Some(CERT_POLL_INTERVAL))`）：

```
FAIL: cert-poll — refused=ok silent=ok sighup=ok trigger=failed polled=ok armed=ok (…)
passed: 0  failed: 1  skipped: 0
failed items: cert-poll
```

`silent=ok` 而 `trigger=failed` —— 正是复核指出的「4s 窗口抓不到、只有启动行能抓到」。
改回后同一项 `ok: … reloader poll=None, file change ignored for 4s, SIGHUP reloads; 2s → poll=Some(2s) …`。

## 4. 门禁（本轮原始结论）

| 命令 | 结果 |
| --- | --- |
| `cargo test` | 263 passed |
| `cargo test --all-features` | 272 passed |
| `cargo clippy --all-targets --no-default-features -- -D warnings` | 通过 |
| `cargo clippy --all-targets --all-features -- -D warnings` | 通过 |
| `cargo fmt --all -- --check` | 通过 |
| `cargo check --target x86_64-pc-windows-msvc` | 通过 |
| `bash script/lab/rstun-turn.sh --only cert-poll` | ok |
| `bash script/lab/rstun-turn.sh --only cert-reload` | ok（SIGHUP + 30s 轮询 + 坏材料保留旧证书）|
| `bash script/lab/rstun-turn.sh --tls --dtls` | ok ×2 |
| `bash script/lab/rstun-turn.sh --only frozen` | ok（3 配置 × 17 请求与 `cad4fa2` 逐字节一致）|
| `bash script/ci/check-docs.sh --no-build` | ✓（46 flag / 20 指标 / 2 help 片段）|

## 5. 低风险决策（G2：实现细节，自行决策并记录）

- D1：早期实现里 `cargo build` 未重编（`target/` 指纹陈旧），用 `cargo clean -p rstun` 强制重编后
  复核了全部门禁；未改动任何构建配置。
- D2：不设 `--tls-cert-poll` 上限（任意正整数合法，一天一次也合理）；`u64` 极大值不会 panic
  （tokio 定时器把超长 deadline 饱和到 far future）。
- D3：`cert_poll_interval` 在「不传 + 无 secure 监听」返回 `Some(30s)`（值在 `build_turn` 里丢弃），
  保持「默认值」单一来源，避免为校验再写一个分支。

## B 项执行记录（性能快照，2026-11-23）

| 项 | 结果 |
| --- | --- |
| 被测二进制 | `26.410.104+a4c38a3`（HEAD，未发版；四个构建均 `--version` 核对）|
| 依赖面 | lean **10 / 90 行**、full **15 / 361 行** |
| 体积（未 strip） | **3.93 / 8.16 MB**；LTO+strip **2.44 / 4.95 MB** |
| 采样 | 56 次运行，busy 窗口 **6.1–12.4%（中位 ≈8%）**，逐次记录在 §8.3 |
| 关键结论 | UDP p50 0.034–0.035 ms；`TCP connect/首字节 p99` 比 `.103` 文档高 20–53%，**同机 A/B 证明是机器状态**（`.103` 今日重跑 connect p99=0.253，与 `.104` 0.255 一致），不是本轮代码 |
| 100 k/s | 服务端 `ok=500000`/`dropped=0`；客户端 6 次中 5 次跟得上（前次 0/5）——同属 busy 更低 |
| 同步 | README / `release.yml` 发布说明 / `docs/book/src/docker.md` 的体积数字改为实测 **3.93 / 8.16 MB** |
| 门禁 | `check-docs` ✓、`check-version-pins` ✓ |
