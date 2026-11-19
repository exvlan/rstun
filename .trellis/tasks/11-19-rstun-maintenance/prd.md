# rstun 后续维护（crates.io 首发 / arm64 与 macOS 补验 / 长期回归）

> 承接 `11-19-rstun-standalone`（已归档）：拆仓、首发 `rstun-v26.410.100`、生产切换均已完成。
> 本任务是 `11-19-rstun-complete` 的子任务，只收**遗留与长期事项**，不重复已完成工作。
> **执行时序（用户定稿）**：本任务的 M2/M3 随「阶段 B · GitHub 分发」执行；
> **M1（crates.io）放在整个父任务最后**（阶段 C），不先发。

## Goal

把 `rstun` 从「可用已上线」推进到「可持续维护的独立开源项目」：可 `cargo install`、关键平台有实机背书、
回归与发布流程有固定节奏。

## Scope

### M1 · crates.io 首发（**阶段 C，最后执行**）

- 校验 crate 名 `rstun` 可用（`curl -s https://crates.io/api/v1/crates/rstun`，需可访问网络的机器）。
- `cargo package --list` 复核（应仍不含 `fuzz/`、`test/`、`.github/`）。
- `cargo publish --dry-run` → 正式 `cargo publish`。
- 发布后：干净容器里 `cargo install rstun` 成功，`rstun --version` 正确。
- **前置**：确认 `version` 与最新 tag `rstun-v26.410.100` 一致（或升到新版本再发）。

### M2 · arm64 / macOS 补验（阶段 B，与分发产物验证同批）

- `linux-aarch64`：在 arm64 机器（或 `ubuntu-24.04-arm` runner）实跑二进制 + `rstun-smoke.sh`。
- `macOS x86_64`：Intel Mac 或 Rosetta 上实跑 `--version` + UDP/TCP 冒烟（CI 只编译不执行）。
- Windows：已由 CI `--version` 覆盖；如条件允许补一次 UDP 冒烟。

### M3 · 长期回归（阶段 B 出口一并完成）

- 每次发布前跑 `bash script/lab/rstun-interop.sh all`（38 项 / 176 断言）。
- `cargo fuzz` 定期跑（≥10 分钟），corpus 可选持久化到独立分支/制品。
- 跟踪上游生态变动（`stun-types` 新版本、RFC 更新、coturn/pion 行为变化）。

## 非目标

- 不加 TURN / 鉴权 / TLS-DTLS / 限速（与 `11-19-rstun-standalone` 的非目标一致）。
- 不改协议行为；如需改动走新任务并先读 `research/T1-interop-matrix.md` 与 T0 条款。

## 验收标准

- [ ] M1：`cargo install rstun` 在干净环境成功；crates.io 页面可访问且版本正确
- [ ] M2：arm64 与 macOS x86_64 各有一份实跑证据（命令 + 输出）写入 `research/`
- [ ] M3：至少一次「发布前矩阵全绿 + fuzz 10 分钟无崩溃」的完整记录

## 风险

| # | 风险 | 缓解 |
| --- | --- | --- |
| R1 | crates.io 名称被占 | 先查；被占则改名（会连带改 README/镜像/tag），越早越好 |
| R2 | 无 arm64/macOS Intel 实机 | 用 `ubuntu-24.04-arm` runner 跑实机步骤；macOS 可用 Rosetta 代替 |
| R3 | 长期无回归导致协议倒退 | 发布前置矩阵 + fuzz；把结论写进 `CHANGELOG` |
