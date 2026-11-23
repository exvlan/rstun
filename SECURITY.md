# 安全策略

`rstun` 是一个**网络边界组件**：它直接面对公网 UDP/TCP，解析不可信报文，并在开启
`--turn` 后承担中继。所以「能打挂/能放大/能绕过鉴权」的问题都按安全漏洞处理，不当普通 bug。

## 报告渠道

**不要开公开 issue。** 任选其一（都只对维护者可见）：

1. GitHub 私密漏洞报告：<https://github.com/exvlan/rstun/security/advisories/new>
   （推荐：带复现、影响版本、建议修复）
2. 邮件：`exvlan@users.noreply.github.com`

报告里请包含（缺哪项我们会问，但先给全最省时间）：

- 受影响版本：`rstun --version` 的完整输出（含 `+<sha6>`），以及 Release tag / 镜像 tag；
- 构建形态：**lean** 还是 **full**（`--features full`），是否开了 `--turn` / `--realm` /
  `--turn-tls-listen` / `--turn-dtls-listen`；
- 部署形态：`--listen` 的实际形态（单地址 / 通配 / 多地址 + `--alt-listen`）、是否有反向代理；
- 最小复现：一条能重放的命令或脚本，**不要**包含生产地址与凭据；
- 影响：能造成什么（放大？绕过鉴权？信息泄露？拒绝服务？），以及你实测到的字节数/时序。

## 支持范围

| 版本线 | 支持 |
| --- | --- |
| 最新 Release（`rstun-v*` 里版本号最大的那个） | 修复 |
| 更早的版本 | 只做评估；需要时请先升级到最新版再复现 |

本仓**没有 LTS 分支**，也没有多版本并行维护的计划：修复进 `main`，随下一个 Release 发布。

## 响应时限（尽力而为，不是 SLA）

| 阶段 | 目标 |
| --- | --- |
| 确认收到 | 7 天内 |
| 初步判断（是否成立 / 严重度） | 14 天内 |
| 修复或缓解方案 | 30 天内（严重问题优先） |

修复发布时会发 GitHub Security Advisory，并在 Release notes 与 `CHANGELOG.md` 里注明。
如果你希望署名，请在报告里写明。

## 已知的、**不算**漏洞的行为

这些是设计取舍，已在文档里写明（[协议行为](docs/book/src/protocol.md)、[TURN](docs/book/src/turn.md)）：

- **默认不做 `FINGERPRINT` 校验**（需要显式 `--check-fingerprint`）：保持与旧版本字节一致。
- **`ALTERNATE-SERVER` / 420 / 普通 Binding 的放大面**（2.3×–3.8×）：靠每源 IP 令牌桶兜底，
  反射防护只约束带 `RESPONSE-PORT` / `CHANGE-REQUEST` 的请求。
- **TURN 失败响应不带 `SOFTWARE`**（RFC 8656 §6.1 是 SHOULD，不是 MUST）。
- **宿主自身公网 IP 的防回环盲区**：不引入接口枚举依赖，只拒绝本进程监听地址与 loopback peer。
- **多实例不共享 allocation 状态**：靠 LB 源地址亲和，REST 凭据与 nonce 是无状态的。

## 供应链

- `cargo audit`（`.cargo/audit.toml` 的豁免清单）与 `cargo deny`（`deny.toml`：licenses /
  bans / sources）在 CI 里是**必需作业**。
- Release 资产附 CycloneDX SBOM（`rstun-<version>-lean.cdx.json` / `-full.cdx.json`）。
- **发布产物已用 cosign keyless 签名**（GitHub OIDC + Sigstore Fulcio/Rekor，`26.410.106` 起）：
  `SHA256SUMS`（覆盖 13 个核心资产）+ 3 个 `.bundle`，容器镜像按 manifest list digest 签名。
  验证命令见 [验证发布产物](docs/book/src/verify.md)；**未签名的历史版本**（≤ `26.410.105`）
  只能自行计算 `sha256` 与 SBOM 对照，或在信任前自行构建。
