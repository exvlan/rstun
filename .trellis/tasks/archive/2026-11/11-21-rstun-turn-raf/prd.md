# TURN REQUESTED-ADDRESS-FAMILY 最小实现（420 偏差修正）

## 背景

对端在生产用 `turnutils_uclient -S` 验证 DTLS 时，Allocate 被 `420 Unknown Attribute` 拒绝，
怀疑是 `REQUESTED-ADDRESS-FAMILY` / `DONT-FRAGMENT`。已复现并定性
（`../11-19-turn-phase2/research/dtls-allocate-420-2026-11-21.md`）：

| 属性 | 码 | 触发方式 | 我方现状 | RFC 8656 要求 |
| --- | --- | --- | --- | --- |
| `REQUESTED-ADDRESS-FAMILY` | 0x0017 | `uclient -e` / `-x` / `-X` | `420` | §7.2 步骤 7：解析；不支持所请求族 → **440** |
| `DONT-FRAGMENT` | 0x001A | `uclient -g` | `420` | §7.2 步骤 4：**不支持 DF 时当作未知 comprehension-required → 420 合规** |

即：DF 的 420 合规，**RAF 的 420 是实现偏差**（少解析一步、错误码也不对）。
且与传输层无关（纯 UDP 同现象）。

## 目标

1. 解析 `REQUESTED-ADDRESS-FAMILY (0x0017)`，按 RFC 8656 §7.2 给出正确响应：
   - 族与本端可提供的 relay 地址族一致（IPv4 客户端 + 请求 IPv4）→ 正常 `200 Allocate`；
   - 请求 IPv6（或本端无法提供该族）→ `440 Address Family not Supported`；
   - 长度 ≠ 4 → `400 Bad Request`；族值非 0x01/0x02 → `440`。
2. `RESERVATION-TOKEN + REQUESTED-ADDRESS-FAMILY` → `400`（§7.2 步骤 5，与 `EVEN-PORT` 同款互斥）。
3. `Refresh` 里出现 RAF 不再回 420，且按 RFC 8656 §8.2 **MUST** 处理：
   与现有分配的 relay 地址族不匹配 → `443 Peer Address Family Mismatch`；匹配 → 正常续期；
   长度 ≠ 4 → `400`。（原设计写「接受并忽略」是遗漏 §8.2，已按复核修正。）
4. `DONT-FRAGMENT` 维持 `420`（合规，**不改**）。
5. 行为表、文档、spec 与 lab 验收同步；默认路径（不带 RAF）响应字节不变。

## 非目标

- 不做 IPv6 relay 的真正支持（只把「不支持」的**回答**改正确）；
- 不做 DONT-FRAGMENT（DF 位 / `IP_MTU_DISCOVER`）；
- 不做 `ADDITIONAL-ADDRESS-FAMILY (0x8000)` 双分配（comprehension-optional，继续忽略）；
- 不动 RFC 6062 TCP allocation、多实例、证书热载（留二期）；
- **不发版**（版本号与 CHANGELOG 版本见 `implement.md`；publish/release 由主会话另行决定）。

## 约束

- 默认路径字节冻结：`plain_response_bytes_are_frozen` 与 3 配置 × 17 请求对照必须不变；
- 直接依赖数不变（9 / 13）；不新增依赖；
- 错误码复用现有常量（`ERROR_BAD_REQUEST` / `ERROR_ADDRESS_FAMILY_NOT_SUPPORTED`），不新造；
- 指标名不新增（`rejected_family` 已有，可复用计数）。

## 验收

- [ ] `uclient -S -X`（显式 IPv4）：Allocate + 中继成功（此前 420）
- [ ] `uclient -S -x`（请求 IPv6，IPv4 客户端）：`error 440`
- [ ] `uclient -S -g`（DONT-FRAGMENT）：仍是 `error 420`
- [ ] `uclient -S -y`（不带两个属性）：行为不变
- [ ] 单测覆盖：匹配 / 不匹配 440 / 长度错 400 / 族值非法 440 / token+RAF 400 / Refresh 带 RAF 不 420
- [ ] `cargo test`（lean/full）、clippy、fmt、interop 42、abuse、turn（lean + `--tls --dtls`）、audit、deny 全绿
- [ ] 冻结对照：3 配置 × 17 请求逐字节一致（不带 RAF 的请求）
- [ ] `docs/book/src/turn.md`、`src/turn.rs` 头注释、`.trellis/spec/backend/turn.md` 同步
