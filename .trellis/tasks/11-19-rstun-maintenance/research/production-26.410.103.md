# 生产已切 26.410.103 + DF 端到端复验（对端回报，2026-11-21）

> 来源：EXVlan 会话（`ses_eda8…9mnS`）`[handoff] DONE`，线程 `t_mwpyerad_4owg`。

## 生产状态

| 项 | 值 |
| --- | --- |
| 版本 | `rstun 26.410.103+bac375` |
| 镜像 digest | `sha256:d7c4f3872a545ee7a8b0cd57a1234c83e0ae0d9df37b7b341f2fd6aafd643874` |
| 变更范围 | 仅重建 `exvlan` Pod；12 listeners（TLS + DTLS 就绪）|

## 复验（对端执行）

| 用例 | 26.410.102 | 26.410.103 | 备注 |
| --- | --- | --- | --- |
| `-S -y` | 20/20 | **20/20、0 丢包** | 不变 |
| `-S -g -y`（DONT-FRAGMENT） | 420 | **20/20、0 丢包** | ✅ DF 在 unix 真支持，端到端验证通过 |
| `-S -x`（请求 IPv6） | 440 | 440 | 不变 |

## 对端文档

- `docs/rules/workflow/upstream-debt.md` **P-014 已更新为 `.103` 版本化措辞**：
  unix DF 已实现；Windows 仍 `420`；IPv6 relay 不做生产承诺。

## 结论

- `DONT-FRAGMENT` 的实现从「lab 证据（getsockopt + uclient）」升级为**生产环境真机验证**
  （对端 `-S -g` 由 420 变可中继、0 丢包）。
- `.103` 的 13 资产（含 CI 自动产出的 2 个 deb）与 Homebrew tap 均已核对。
- 我方无遗留动作；下一步为 TURN 二期剩余项（RFC 6062 / 多实例 / 证书热加载）的规划。
