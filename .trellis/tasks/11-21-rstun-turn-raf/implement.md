# 执行计划：RAF 最小实现

> 顺序执行；每步可独立验证。**不 commit / 不 publish / 不改版本号**（版本与发版由主会话决定）。

## 0. 现状核对（只读）

```bash
grep -n "turn_unknown_attributes\|ATTR_EVEN_PORT\|egress_ip(local, peer)\|rejected_family" src/turn.rs | head
cargo test --features full turn:: 2>&1 | tail -3        # 基线
bash script/lab/rstun-turn.sh --only dtls 2>&1 | tail -3 # 基线（应绿）
```

记录：当前测试数、`turn` 相关用例清单。

## 1. 代码

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | 新增 `ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017` + 文档注释（RFC 8656 §18.6，4 字节，reserved 忽略）| `cargo check` |
| 1.2 | `turn_unknown_attributes()` 已知集合加入 RAF | 单测 0x0017 不再出现在 unknown |
| 1.3 | `parse_requested_address_family()`（缺失/长度/族值）| 单测 |
| 1.4 | Allocate：`egress_ip` 之后按族比对 → 200 / 440 / 400；440 计 `rejected_family` | 单测 |
| 1.5 | `RESERVATION-TOKEN` 与 RAF 互斥 → 400 | 单测 |
| 1.6 | Refresh：RAF 已已知 → 忽略（注释说明）| 单测 |

## 2. 测试

| # | 事项 |
| --- | --- |
| 2.1 | 单测 8 条（见 `design.md` §4），其中「未知属性」用例改为「0x001A 仍 420、0x0017 不再 420」|
| 2.2 | lab 新增 `raf` 项：`uclient -S -X` 成功 / `-S -x` → `440` / `-S -g` → `420` |
| 2.3 | 冻结对照：`RSTUN_BUILD_VERSION=<当前> FROZEN_BASE=<上一提交> --only frozen`（不带 RAF 的 3×17 必须一致）|

## 3. 文档

| # | 文件 | 改动 |
| --- | --- | --- |
| 3.1 | `docs/book/src/turn.md` | 行为表加 RAF 行；「不支持」列表移除 RAF、保留 DF 并注明「RFC 明文允许 420」|
| 3.2 | `src/turn.rs` 头注释 | 25-26 行改为「RAF 已解析（§18.6）；DF 故意按未知属性回 420（§7.2 步骤 4）」|
| 3.3 | `.trellis/spec/backend/turn.md` | 契约 + tests required 增补 RAF 四态 |
| 3.4 | `CHANGELOG.md` | `## Unreleased` 加一条（**不改版本号**）|

## 4. 门禁

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/lab/rstun-turn.sh
bash script/lab/rstun-turn.sh --tls --dtls
bash script/ci/check-docs.sh --no-build
cargo audit; echo "audit=$?"
cargo deny check licenses bans sources
```
