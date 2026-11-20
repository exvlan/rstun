# 执行计划：maintenance（M1/M2/M3）

> 轻量任务：PRD 已在 `prd.md`。本文件只写**执行顺序与验证命令**。
> 用户口径：**crates.io（M1）最后**；先做 M2（arm64/macOS 实机验证），M3 长期运行。

## M2 · arm64 / macOS 实机验证（先做）

| # | 事项 | 验证 |
| --- | --- | --- |
| 2.1 | 新增 `.github/workflows/verify-platforms.yml`（`workflow_dispatch` + 每周一次）：<br>· `ubuntu-24.04-arm`：`cargo build --release --target aarch64-unknown-linux-musl` → `--version` + `rstun-smoke.sh` + 一次 `--turn` 的 UDP 中继（有 turnutils_uclient 则跑）<br>· `macos-latest`：下载/构建 `x86_64-apple-darwin` 产物 → `arch -x86_64 ./rstun --version`（Rosetta）+ 冒烟；Rosetta 不可用则 **SKIP + 原因**，不得伪装通过 | workflow 手动 dispatch 绿；日志含 `--version` 与冒烟输出 |
| 2.2 | 把 M2 的证据写进 `research/M2-platform-evidence.md`（run 链接、版本串、冒烟输出、平台/架构）| 文件存在且可复核 |
| 2.3 | 若 Rosetta 不可用：在 README/验收里如实标注「macOS x86_64 未实机」并保留 SKIP 证据 | 文档一致 |

**门禁**：workflow YAML 可解析、action 固定 SHA；不得改 `src/**`；默认路径字节不变。
**回滚**：删除 workflow 与 evidence 文件。

## M3 · 长期回归（M2 后持续）

- 每次发布前跑 `script/lab/rstun-interop.sh all` + `--item fuzz --fuzz-seconds 600`；
  结论写进 Release notes / `CHANGELOG`。
- 每周 `qa-scheduled.yml` 已在跑（fuzz/interop/bench），维护者只看红绿与 flaky。

## M1 · crates.io 首发（**最后**）

- 前置：`CARGO_REGISTRY_TOKEN`（或发布机 `cargo login`）；名称已验证可用（见 `research/name-availability.md`）。
- 步骤：`cargo package --list` 复核 → `cargo publish --dry-run` → `cargo publish` → 干净环境 `cargo install rstun`。
- 发布后：README 加 crates.io 徽章；`Cargo.toml` 的 `repository` 保持。
- **回滚**：`cargo yank --version <ver>`（crates.io 不支持删除）。
