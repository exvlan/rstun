# 发布产物 keyless 签名（cosign + OIDC）

## 背景

Release 资产目前**完全未签名**（`docs/book/src/turn.md` 与发布说明都明写「发布产物未做签名」）。
供应链可验证性只能靠「自己下载后算 sha256 与 SBOM 对照」，无法证明「这些资产确实由本仓的
release workflow 构建」。

用户已定：**keyless（GitHub OIDC + Sigstore Fulcio/Rekor）**，不自管密钥。

## Goal

用 `cosign` 对发布产物做 keyless 签名，并在发布后**自动校验**：

1. 生成 `SHA256SUMS`（覆盖 13 个资产）并对它签名；
2. 对 2 份 SBOM 分别签名（它们是「资产里装了什么」的声明）；
3. 签名产物以 **cosign bundle**（`.bundle`，含签名 + 证书 + Rekor 证明）随 Release 上传；
4. `post-release-verify` 自动验证：证书身份绑定到**本仓 release workflow + 该 tag**、
   OIDC issuer 为 GitHub、且 sum 与资产哈希一致；
5. 文档给出用户可照抄的验证命令。

## 范围

### A. 签名（`release.yml`）

- 在 `release` 作业内、上传前生成 `SHA256SUMS` 并对以下三项签名：
  `SHA256SUMS`、`rstun-<ver>-lean.cdx.json`、`rstun-<ver>-full.cdx.json`；
- 采用 `cosign sign-blob --yes --bundle <file>.bundle <file>`（bundle 合并签名/证书/Rekor，
  资产数 +3，**13 → 16**）；
- 作业权限增加 **`id-token: write`**（OIDC）；cosign 通过
  `sigstore/cosign-installer`（**锁 40 位 SHA**）安装，版本固定；
- 输入 `sign`（boolean，默认 `true`）：紧急情况下可跳过签名（发布说明需注明「未签名」）。

### B. 校验（`post-release-verify.yml`）

- 资产数断言 13 → **16**；断言 3 个 `.bundle` 存在；
- 安装 cosign（同一 action/SHA），逐个 `cosign verify-blob`：
  - `--certificate-identity-regexp` 绑定 `https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>`
  - `--certificate-oidc-issuer https://token.actions.githubusercontent.com`
- 用 `SHA256SUMS` 校验 13 个资产的哈希（含 deb/zip/SBOM/rb）；
- `require_tap` 语义不变。

### C. 文档

- `README` 发版段 + `docs/book` 的「验证产物」小节：给出 3 条命令（验证 sums bundle、
  验证 SBOM bundle、用 sums 校验资产），说明「证书身份 = 本仓 release workflow + 该 tag」；
- `release.yml` 的发布说明去掉「未签名」，改成「已用 cosign keyless 签名，验证方式见 …」；
- `spec/backend/release-artifacts.md`：资产口径 16、签名契约、失败策略；
- `CHANGELOG.md` 的 `## Unreleased`。

## 非目标

- **不签容器镜像**（`cosign sign ghcr.io/...`）：需在 image 作业加 OIDC + 写 OCI artifact，
  属独立增量；本任务只覆盖 Release 文件资产（如需要，另立子任务）；
- 不签 crates.io（cargo 自带校验）；
- 不自管密钥/不做长期密钥轮换；
- 不改资产内容（只增加 `.bundle`）。

## 约束（硬）

- 签名失败 → **发布失败**（不发出「声称已签名但实际没有」的 Release）；`sign=false` 时跳过并在说明里明示；
- keyless 需要网络访问 Fulcio/Rekor；失败信息必须可读（不是超时无提示）；
- 不新增运行时依赖（cosign 只在 CI 用）；action 锁 SHA；
- 资产哈希必须基于**最终上传的字节**（`SHA256SUMS` 上传后再算会导致不一致）；
- `post-release-verify` 仍只读（`contents: read` + `packages: read`；验证签名不需要写权限）。

## 验收

- [ ] 发版后 Release 有 **16** 个资产（含 3 个 `.bundle`）
- [ ] `post-release-verify` 对 `.105`（回填演练）或下一个版本的签名全绿
- [ ] 手工按文档命令验证通过；**篡改任一资产**后验证失败（负例）
- [ ] `sign=false` 时：不产生 bundle、发布说明标注未签名、verify 对缺失 bundle 明确失败（或按输入跳过）
- [ ] 签名身份绑定正确：用错误的 `--certificate-identity-regexp` 验证会失败
- [ ] 默认路径/协议行为零变化；`check-docs` 通过
