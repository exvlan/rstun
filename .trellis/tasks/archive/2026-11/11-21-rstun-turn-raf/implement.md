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
| 1.6 | Refresh：RAF 已已知 → 按 §8.2 校验（不匹配 443、长度 3 400、匹配续期）——**原稿「忽略」已由 design §2.5 取代** | 单测 |

## 2. 测试

| # | 事项 |
| --- | --- |
| 2.1 | 单测：解析器 + `family_matches` + 两条 e2e（Allocate 7 组 / Refresh 5 组断言），其中「未知属性」用例改为「0x001A 仍 420、0x0017 不再 420」|
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

## 复核与收尾（主会话）

- 冷复核两轮：第一轮判 2 项阻塞（B1 `RESERVATION-TOKEN + RAF(异族)` 应 400；B2 `Refresh` 族不匹配应 443，RFC §8.2 MUST），
  已修并第二轮确认「可提交（无阻塞）」；rstun 与 coturn 同参数探针逐条对照一致。
- 提交前落地的文档修正：spec 判定顺序（族比对在步骤 5 互斥之后）、spec 冻结口径写 `FROZEN_BASE`、
  `turn.md` 的 IPv6 覆盖表述（lab 实际**未**覆盖 IPv6 relay）。
- 记账未改：`CreatePermission/ChannelBind` 带 RAF 本仓 200（忽略）、coturn 420 —— RFC 8489 §7.3.1 两者皆可辩护；
  `RAF` 长度≠4 本仓 400、coturn 440/443 —— 本仓有意统一 400。
- 既有 flake（非本任务）：`script/lab/rstun-turn-probe.py` 的 peer `settimeout(0.5)` 在负载下偶发
  `send-indication-bytes` 差异；重跑即绿，未在本次修改。

## 发版执行记录（26.410.102，主会话）

| 项 | 结果 |
| --- | --- |
| 代码提交 | `28e51b3`（RAF 实现 + 测试 + lab + 文档/spec）|
| 冷复核 | 两轮，第二轮「可提交（无阻塞）」；rstun vs coturn 同参数探针逐条一致 |
| 版本/CHANGELOG | 提交 `e0a16cc`（`26.410.102`，Unreleased 定稿）|
| 附带修复 | frozen 基线构建改注入 `RSTUN_BUILD_VERSION=<当前版本串>`（版本 bump 不再假红）|
| 附带修复 | `rstun-turn-probe.py` peer 超时 0.5s → 1.0s（既有 flake）|
| crates.io | ✅ `rstun 26.410.102`；干净安装 `cargo install` → `rstun 26.410.102` |
| Release | ✅ run `44850731590` 11/11 作业；11 资产（lean+full 各 4 zip + 2 SBOM + `rstun.rb`）|
| 镜像 | `ghcr.io/exvlan/rstun:26.410.102`（amd64+arm64，full）|
| **新 manifest digest** | `sha256:62c766adb88d405a33134ac85f3d364122df72c79aaf9cf89e12502d25a6d66d` |
| 版本钉死点 | README / docker.md / contrib{k8s,compose,helm×2} 全部 → `26.410.102` |
