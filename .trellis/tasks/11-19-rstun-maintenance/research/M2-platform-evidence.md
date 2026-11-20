# M2 平台验证证据（arm64 / macOS x86_64）

> 2026-11-20 · workflow [`.github/workflows/verify-platforms.yml`](../../../../.github/workflows/verify-platforms.yml)
> run: https://github.com/exvlan/rstun/actions/runs/44736257405 （`workflow_dispatch`，两个作业均 success）

## 1. linux-aarch64（native arm64 runner，`ubuntu-24.04-arm`）

| 项 | 结果 |
| --- | --- |
| 构建 | `cargo build --release --target aarch64-unknown-linux-musl` |
| 产物 | `ELF 64-bit LSB executable, ARM aarch64, statically linked`，3,771,776 B |
| 版本 | `rstun 26.410.100`（与 `Cargo.toml` 一致）|
| 冒烟 | `[rstun-smoke] udp: ok 0x0101 attrs=['0x20','0x8022']`、`tcp: ok`、`127.0.0.1:34780 通过` |
| TURN 中继 | `turnutils_uclient`（arm64 coturn 4.6.1）→ `Total lost packets 0`；`rstun_turn_bytes_total{direction="in"} 2000` / `out 2000` |

结论：**arm64 musl 静态产物在 arm64 上真实可执行**，UDP/TCP Binding 与 TURN UDP 中继均通过。

## 2. macos-x86_64（`macos-latest` = arm64 runner，Rosetta 2）

| 项 | 结果 |
| --- | --- |
| 构建 | `cargo build --release --target x86_64-apple-darwin`（交叉编译成功）|
| Rosetta 2 | **可用**（`arch -x86_64 /usr/bin/true` 成功）|
| 实跑 | `arch -x86_64 …/rstun --version` → `rstun 26.410.100` |
| 冒烟 | `[rstun-smoke] 127.0.0.1:34780 通过`（x86_64 二进制经 Rosetta 运行）|

结论：**macOS x86_64 产物已在真机（arm64 + Rosetta）上执行验证**，不再是「只编译不执行」。

## 3. 复现

```bash
gh workflow run verify-platforms.yml -R exvlan/rstun
gh run list -R exvlan/rstun --workflow verify-platforms.yml --limit 1
```

定时：每周四 06:00 UTC（与 `qa-scheduled.yml` 的周一 04:00 错开）。

## 4. 未覆盖 / 后续

- TURN over **DTLS** 在 arm64/macOS 未跑（full 构建的 TLS/DTLS 已由 x86_64 Linux 的 `rstun-turn.sh --tls --dtls` 验证）。
- macOS **arm64** 原生二进制（`aarch64-apple-darwin`）未在发布矩阵中（当前只发 x86_64）；如需，另开任务。
- Windows 仅由 CI 的 `--version` + 冒烟覆盖（已有），无 arm64 Windows 产物。
