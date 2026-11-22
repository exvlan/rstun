# M3 长期回归：首份「发布前矩阵 + fuzz 10 分钟」完整记录

> 2026-11-22。维护任务 M3 的验收项：「至少一次『发布前矩阵全绿 + fuzz 10 分钟无崩溃』的完整记录」。

## 1. 发布前矩阵（`release-preflight`，只读）

run [45021336583](https://github.com/exvlan/rstun/actions/runs/45021336583) — **completed/success**：

| 段 | 结果 |
| --- | --- |
| 版本钉死点（6 处 = `Cargo.toml`）| success |
| 测试（lean/full）+ clippy（两种 feature）+ fmt | success |
| interop 矩阵（含 pion / coturn / webrtc-stun / rfc5769 / auth）| success |
| TURN lean（含 frozen 字节冻结）| success |
| TURN full（`--tls --dtls`）| success |
| SBOM lean/full | success |
| deb（amd64 元数据）| success |
| Homebrew formula 渲染 | success |
| `cargo publish --dry-run` | success |
| Summary | **PASS** |

## 2. 周度回归（`qa-scheduled` 手动预演，等同定时首跑）

run [45021337538](https://github.com/exvlan/rstun/actions/runs/45021337538) — **completed/success**：

| job | 结果 |
| --- | --- |
| interop matrix（容器 `buildpack-deps:trixie` + coturn + go 1.24）| success |
| fuzz（parse，**600s**）| success（无崩溃、无断言失败）|
| bench smoke（只记数值、不设阈值）| success |

## 3. 本记录同时验证的两条环境契约

1. **Go 版本**：`pion/stun v3` 要求 go 1.24；CI 的 `golang-go` 是 1.22 →
   改用 `actions/setup-go`（锁 SHA）并移除 apt 版；宿主 runner 与容器 job 都验证通过。
2. **interop 失败诊断**：失败时打印 `$LOG_DIR/*build*.log`，不再只有 `FAIL pion`。

## 4. 结论

M3 的「发布前矩阵全绿 + fuzz 10 分钟无崩溃」已有**可复现 run ID**，且两条由 workflow 自动执行
（无需人工跑）。维护任务继续保持 `in_progress` 到观察期结束（约 2026-12-05），期间观察：
周度 `qa-scheduled`（周一 04:00 UTC）与 `verify-platforms`（周四 06:00 UTC）的红绿与 flaky。
