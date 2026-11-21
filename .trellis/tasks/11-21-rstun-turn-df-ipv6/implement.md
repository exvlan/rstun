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
