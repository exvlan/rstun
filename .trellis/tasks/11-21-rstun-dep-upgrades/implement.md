# 执行计划：依赖主版本升级

> 两阶段独立验收；每阶段可单独回滚。开工前先做 1 的「现状核对」。

## 0. 现状核对（先做，只读）

```bash
grep -nE '^(sha1|sha2|md-5|hmac|webrtc-util|webrtc-dtls) *=' Cargo.toml
cargo tree -i webrtc-util
cargo tree -i webrtc-dtls
cargo test --all-features 2>&1 | tail -2
```

记录：当前版本、`webrtc-util` 的约束来源、基线测试数。

## 阶段 1 · crypto（sha1/sha2/md-5 → hmac）

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1.1 | `Cargo.toml`：`sha1 0.11`、`sha2 0.11`、`md-5 0.11`（同 `digest 0.11`）；先不动 `hmac` | `cargo tree -d` 看是否出现双 `digest` | 单 commit |
| 1.2 | 适配 `src/auth.rs`（`Digest` 输出类型、`finalize`） | `cargo test auth::` 向量全绿 | 同上 |
| 1.3 | `hmac 0.13` + 适配（`Mac`/`KeyInit` 路径） | `cargo test auth::` | 同上 |
| 1.4 | 全量门禁 | 见下 | 同上 |
| 1.5 | 合并/关闭 PR #3/#4/#6/#7 | `gh pr list` 状态 | — |

**门禁**：`cargo test`（lean/full）、clippy（两种 feature）、fmt、`interop all` 42、`abuse` 10、`turn` 15+2、`cargo audit` 0 vuln、`cargo deny` 四项 ok、冻结对照（3×17 与 `FROZEN_BASE` 一致）。

## 阶段 2 · webrtc-util 0.17

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 2.1 | 按 design §3.1 判定 A/B/C | `cargo tree` 证据 + `cargo info webrtc-dtls` | 只读 |
| 2.2 | 若 A/B：升 `webrtc-util`（必要时连 `webrtc-dtls`）并适配 `src/main.rs` 的 DTLS | `cargo test --all-features`；`rstun-turn.sh --tls --dtls` | 单 commit |
| 2.3 | 若 C：关闭 PR #5，写原因（上游组合不可行/需上游先动） | PR 评论 + 任务记录 | — |
| 2.4 | 门禁 + 冻结对照 + DTLS 真机握手 | 同阶段 1 | 同上 |

## 门禁（每阶段结束都跑）

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/lab/rstun-turn.sh          # lean：15 + 2 SKIP
bash script/lab/rstun-turn.sh --tls --dtls   # 仅阶段 2 涉及
cargo audit; echo "audit=$?"
cargo deny check
```

## 验收断言（必须）

- [ ] 向量测试全部保持通过（HMAC-SHA1/SHA256、MD5、RFC 5769 §2.4、nonce 跨实例）
- [ ] 默认路径字节冻结（3 配置 × 17 请求）与升级前一致
- [ ] `cargo tree -e normal --depth 1` 直接依赖数不变（9 / 13）
- [ ] `cargo audit` 0 vulnerability；新 unmaintained 需登记理由
- [ ] 5 个 PR：#3/#4/#6/#7 合并或取代；#5 合并或按 C 关闭并写明原因
- [ ] 二进制体积变化记录（>10% 说明）

## 风险

| R | 缓解 |
| --- | --- |
| `digest 0.11` 与 `hmac 0.12` 不兼容 | 一起升 `hmac 0.13`（阶段 1.3） |
| DTLS API 大改 | 先只升 `webrtc-util` 看编译；不行就评估 `webrtc-dtls` 连带升级 |
| Dependabot 在分支上持续 rebase | 以本任务提交为准，完成后关闭对应 PR |
