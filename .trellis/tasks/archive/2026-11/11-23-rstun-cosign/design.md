# 设计：keyless 签名（cosign + OIDC）

> 用户已定：**keyless（GitHub OIDC + Sigstore Fulcio/Rekor）**，不自管密钥。
> 关键约束：`.105` 的镜像 digest 已被下游固定，**不能为重签而重跑该版本的 release**（会重建镜像）。

## 1. 签什么、怎么签

| 对象 | 方式 | 产物 |
| --- | --- | --- |
| `SHA256SUMS`（覆盖 13 个资产）| `cosign sign-blob --yes --bundle SHA256SUMS.bundle SHA256SUMS` | `SHA256SUMS` + `SHA256SUMS.bundle` |
| `rstun-<ver>-lean.cdx.json` | 同上 | `*.cdx.json.bundle` |
| `rstun-<ver>-full.cdx.json` | 同上 | `*.cdx.json.bundle` |

- **bundle** 内含签名 + 证书 + Rekor 证明（单文件，免去 `.sig`+`.pem` 两件套）；
- 资产数 **13 → 16**（+`SHA256SUMS` +3 个 `.bundle`；`SHA256SUMS` 本身也算资产）。

> 为什么签 sums 而不是逐个签 10 个二进制：签名数从 10 降到 1，同时保持「任一资产的字节都被绑定」
> （验证 = 先验 sums 的签名，再用 sums 校验每个文件哈希）。SBOM 单独签是因为它是「声明」而非哈希清单。

## 2. `release.yml` 改动

在 `release` 作业内、`gh release create/upload` **之前**：

1. `permissions` 增加 **`id-token: write`**（OIDC 换取 Fulcio 证书）；
2. 安装 cosign：`sigstore/cosign-installer`（**锁 40 位 SHA**，版本固定；实现时用 API 解析该 tag 的 commit SHA 并写死）；
3. 生成 `SHA256SUMS`：对 `zipped_assets/*.zip`、`sbom_assets/*.cdx.json`、`deb_assets/*.deb`、
   `dist/homebrew/*.rb` 共 13 个文件 `sha256sum`（**排序稳定**，按文件名）；
4. 逐个 `sign-blob --yes --bundle`；
5. 资产数组加入 `SHA256SUMS` 与 3 个 `.bundle`，断言 **16**；
6. 新增输入 `sign`（boolean，默认 `true`）：`false` 时跳过 2–5，并在发布说明标注「本版未签名」。

**顺序要求**：`SHA256SUMS` 必须在所有资产**最终字节**确定后生成（zip 由 `Package assets` 产出；
deb/brew/SBOM 各步已完成）。上传时不再改动这些文件。

## 3. 身份绑定（验证的关键）

keyless 证书的 SAN 形如：

```
https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v26.410.106
```

- 因此 **release 必须用 tag ref 触发**（`release-prep` 已经是 `gh workflow run release.yml --ref rstun-v<ver>`）；
- 手动 dispatch 在 `main` 上会产生 `@refs/heads/main` 的身份 —— **`post-release-verify` 只接受 tag 身份**，
  这样「用 main 的签名冒充某 tag 的产物」会失败；
- 验证命令：

```bash
cosign verify-blob --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp '^https://github\.com/exvlan/rstun/\.github/workflows/release\.yml@refs/tags/rstun-v[0-9.]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

## 3b. 容器镜像签名

- 新作业 `sign-image`（`needs: manifest`）：
  - 权限：`contents: read` + **`packages: write`** + **`id-token: write`**；
  - 登录 ghcr（`GITHUB_TOKEN`），取 manifest list digest（`docker buildx imagetools inspect`）；
  - `cosign sign --yes ghcr.io/<owner>/rstun@sha256:<digest>`（不 `--recursive`）；
- 签名声明存放在 registry 的 OCI artifact（**不增加 Release 资产**，所以 13→16 只算文件侧）；
- 验证：`cosign verify ghcr.io/<owner>/rstun@sha256:<digest>` + 同一 identity/issuer 约束
  （`post-release-verify` 已登录 ghcr，权限 `packages: read` 够用）。

## 4. `post-release-verify.yml` 改动

- 资产数 13 → **16**（并断言 3 个 `.bundle` + `SHA256SUMS` 存在）；
- 安装 cosign（同 action/SHA），对 3 个 bundle 执行 `verify-blob`（身份 regexp 与 issuer 如上）；
- 用 `SHA256SUMS` 校验 13 个资产（`sha256sum -c`），确保「签名覆盖的哈希 = 实际下载的字节」；
- 新增输入 `require_signature`（boolean，默认 `true`）：`false` 时缺 bundle 只 WARN
  （与 `require_tap` 同款语义，用于「签名上线前的旧版本」回看）；
- 权限不变（只读）。

## 5. 失败策略

| 场景 | 行为 |
| --- | --- |
| Fulcio/Rekor 不可达 / 签名失败 | **release 失败**，不产出 Release（宁缺勿假）|
| `sign=false` | 跳过签名；发布说明写明；`require_signature` 默认的 verify 会失败（**预期**，提醒不要宣称已签名）|
| 资产在签名后被改动 | 不可能（上传前生成 sums，上传不再改）；若有人手工替换 Release 资产，verify 的 `sha256sum -c` 会失败 |

## 6. 验证路线（不触碰 `.105`）

- 端到端验证用**下一个版本**（正常发版时自然验证），或用**预发布版本**（如 `26.410.106-dev.0`）
  跑一次完整 release：会产出 dev crate/Release/镜像，但**不影响 `.105` 的 digest**；
- `post-release-verify` 的负例：篡改任一 zip 后重跑 → `sha256sum -c` 失败；用错误 identity regexp → 验证失败。

## 7. 回滚

- 单 commit；revert 后回到「未签名」状态（资产数回到 13，verify 的 `require_signature` 相应调整或删除）；
- 已发布的签名资产无法撤回（与已发布产物同性质），但可直接发新版本。

## 8. 风险

| R | 缓解 |
| --- | --- |
| keyless 依赖 Fulcio/Rekor 可用性 | 失败即发布失败（可读错误）；`sign=false` 作为应急逃生口 |
| cosign 版本漂移导致验证口径变化 | 固定版本（installer 的 `cosign-release` 参数）并在 spec 记录版本 |
| 资产数从 13 变 16 影响下游脚本 | README/文档/spec/verify 全同步；发布说明列出新增资产 |
| 长 tag 导致 identity regexp 不匹配 | 用 `refs/tags/rstun-v[0-9.]+(-[a-z0-9.]+)?` 覆盖预发布 |
