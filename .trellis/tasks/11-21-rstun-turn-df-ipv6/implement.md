# 执行计划：DF + IPv6 relay

> 两个可独立回滚的提交：① DF（依赖 + 代码 + 单测 + 文档）② IPv6 relay lab。
> 不 commit / 不 push / 不 bump 版本（由主会话执行）。

## 阶段 1 · DONT-FRAGMENT

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | `Cargo.toml`：`[target.'cfg(unix)'.dependencies] libc = "0.2"` | `cargo tree -e normal --depth 1 \| wc -l` = 11（含 root，即 10）/ full 15（14）|
| 1.2 | `DONT_FRAGMENT_SUPPORTED` + `parse_dont_fragment()` | 单测 |
| 1.3 | `turn_unknown_attributes`：unix 下 0x001A 已知 | 单测（含 `cfg!(not(unix))` 分支）|
| 1.4 | `set_dont_fragment()`（linux `IP_MTU_DISCOVER`，macOS `IP_DONTFRAG`，其它 unix 返回 Unsupported）| 单测回读 |
| 1.5 | Allocate：DF → 置位；失败 → 500 + 计数；length ≠ 0 → 400 | 单测 + lab |
| 1.6 | Send indication：DF → 临时置位/恢复 | 单测（回读恢复）|
| 1.7 | 指标（若新增 `reason="df"`）同步 ops/文档 | `check-docs.sh` |

## 阶段 2 · IPv6 relay 回归

| # | 事项 | 验证 |
| --- | --- | --- |
| 2.1 | 探针加 `--family inet6`（socket/bind/peer/XOR 解析）| `python3 script/lab/rstun-turn-probe.py --family inet6` 对起好的实例 |
| 2.2 | lab 新增 `ipv6relay` 项（`--listen-v6 [::1]` + 双向数据）| `bash script/lab/rstun-turn.sh --only ipv6relay` |
| 2.3 | lab 新增/扩展 `df` 项（`uclient -g` + tcpdump 或 getsockopt 证据）| `bash script/lab/rstun-turn.sh --only df` |

## 阶段 3 · 文档与 spec

| 文件 | 改动 |
| --- | --- |
| `docs/book/src/turn.md` | DF 行：unix 支持 / Windows 420；「不支持」列表移除 DF；验收项计数 |
| `README.md` | 依赖面 10/14；说明 libc 用途（DF 位）|
| `.trellis/spec/backend/turn.md` | DF 契约 + 测试项 |
| `CHANGELOG.md` | `## Unreleased` 一条 |
| `src/turn.rs` | 头注释「Deliberately absent」段更新 |

## 门禁（每阶段结束都跑）

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/lab/rstun-turn.sh                 # 含新增 df / ipv6relay
bash script/lab/rstun-turn.sh --tls --dtls
bash script/ci/check-docs.sh --no-build
cargo audit; echo "audit=$?"
cargo deny check licenses bans sources
cargo tree -e normal --depth 1 | wc -l
```

## 验收断言

- [ ] `uclient -g` 从 420 → 可中继；DF 位有**可复现证据**
- [ ] DF length ≠ 0 → 400（单测）
- [ ] Windows 仍 420（文档 + 编译通过）
- [ ] `ipv6relay` 项在支持 IPv6 的环境全绿；不支持时 skip 并说明
- [ ] 默认路径字节冻结不变（`FROZEN_BASE=cad4fa2`，版本串自动对齐）
- [ ] 依赖 10/14，audit/deny 不退化

## 回滚

- 阶段 1：revert 该 commit（`Cargo.toml`/`Cargo.lock`/`src/turn.rs`/tests/文档）。
- 阶段 2：revert lab commit（探针 + 脚本）。

## 执行记录（2026-11-21）

| 项 | 结果 |
| --- | --- |
| 依赖 | `[target.'cfg(unix)'.dependencies] libc = "0.2"`；无新 crate（lock 里只是提升为直接依赖）|
| 依赖面 | unix **10 / 14**，Windows target **9 / 13** |
| DF 支持平台 | `cfg!(any(linux, macos, ios))`；Windows/FreeBSD → 属性未知 → `420`（§7.2 步骤 4）|
| Allocate + DF | 置 DF（Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DO`；IPv6 `IPV6_MTU_DISCOVER`；macOS `IP_DONTFRAG`）；长度≠0 → 400；置位失败 → 500 + `rejected_df` + 端口归还 |
| Send + DF | 仅该报文置位、发送后恢复；**置位失败/畸形 → 丢弃**（§11.2，`rejected_df`）|
| IPv6 relay | lab `ipv6relay`：`relay=::1:49700`，send→peer 15B、peer→client 14B |
| 证据 | `getsockopt` 回读 WANT(1)→DO(2)；tcpdump 在 lo 上不判别，仅记录性 |
| 单测 | 新增 6 个 DF 用例（含 `Allocate` 500 + 端口归还）；变异测试 5 条均能变红 |
| 门禁 | `cargo test` 245 / `--all-features` 246；lab 18 passed；frozen 与 `cad4fa2` 一致；audit/deny ok |
| 复核 | 两轮，结论「可提交（无阻塞）」；4 处收尾（注释×2、锁范围收窄、500 分支补测）已落地 |
| 未做 | 版本号未动（仍 `26.410.102`）；发版由主会话另行决定 |

## 发版执行记录（26.410.103，主会话）

| 项 | 结果 |
| --- | --- |
| 代码提交 | `e5f38bf`（DF + IPv6 relay）→ 版本提交 `5d3e602` |
| crates.io | ✅ `rstun 26.410.103`；`cargo install` → `rstun 26.410.103` |
| Release | ✅ run `44864072983` 12/12 作业；**13 资产**（8 zip + 2 SBOM + rb + **2 deb**，deb 由 CI 首次产出）|
| 镜像 | `ghcr.io/exvlan/rstun:26.410.103`（amd64+arm64，full）|
| **manifest digest** | `sha256:d7c4f3872a545ee7a8b0cd57a1234c83e0ae0d9df37b7b341f2fd6aafd643874` |
| deb 抽检 | `rstun_26.410.103_amd64.deb` → `Version: 26.410.103`，解包执行 `26.410.103+bac375` |
| Homebrew tap | 已同步 `exvlan/homebrew-rstun`（formula 类体与 Release `rstun.rb` 一致，3 个 sha256 逐条核对）|
| 版本钉死点 | README / docker.md / contrib{k8s,compose,helm×2} → `.103` |

### 首次发布失败与修复（CI 缺陷）

第一次 dispatch（run `44863740893`）在 `Publish Release` 失败：
`::error::missing lean binary release_assets/rstun-linux-x86_64/rstun`。

根因：`download-artifact` **不保留权限位**（落盘 0644），deb 步骤用 `[ -x ]` 做存在性检查 → 误判缺文件。
修复：`[ -f ]` + `chmod +x`（`bac3757`），并把该契约写进 `spec/release-artifacts.md`
（作业间产物权限）。重跑即绿；tag 未被创建过，无半成品。
