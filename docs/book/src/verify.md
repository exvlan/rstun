# 验证发布产物（cosign keyless）

从 `26.410.106` 起，每个 Release 的产物都用 **cosign keyless** 签名：证书由 GitHub Actions 的
OIDC 身份向 Sigstore **Fulcio** 申请、签名与证明写入 **Rekor** 透明日志，**没有需要长期保管的私钥**。
签名不改变产物内容，只多出 `SHA256SUMS` 与几个 `.bundle`（签名 + 证书 + Rekor 证明的单文件）。

| 资产 | 是什么 |
| --- | --- |
| `SHA256SUMS` | 13 个核心产物（8 个 zip + 2 份 SBOM + `rstun.rb` + 2 个 deb）的 sha256，**裸文件名** |
| `SHA256SUMS.bundle` | 对 `SHA256SUMS` 的签名 |
| `rstun-<version>-lean.cdx.json.bundle` / `-full.cdx.json.bundle` | 两份 SBOM 各自的签名 |
| 容器镜像签名 | 对 **manifest list digest** 的签名，存为 registry 里的 OCI 附件（不占 Release 资产位）|

为什么签「哈希清单」而不是逐个签 10 个二进制：签名数从 10 降到 1，而「每个资产的字节」仍被绑定 ——
验证 = 先验清单的签名，再用清单核对每个文件的哈希。SBOM 单独签，因为它是**声明**（产物里装了什么）
而不是哈希清单。

## 1. 证书身份（验证的锚点）

keyless 的证书 SAN 就是「哪个仓库的、哪个 workflow 文件、在哪个 ref 上跑的」：

```
https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v26.410.106
```

所以验证必须同时给出两件事，缺一个都等于没验：

- `--certificate-identity`：**逐字**等于上面那串 URL（`https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>`）；
  这是**精确字符串**比较，不是正则 —— 把 `<version>` 换成你下载的那个版本号即可；
- `--certificate-oidc-issuer`：`https://token.actions.githubusercontent.com`（GitHub 的 OIDC）。

> 也别用 `--certificate-identity-regexp` 图「宽松一点」：`.*` 等于没验；手拼转义又极易写错 ——
> 源码写**四反斜杠** `${VERSION//./\\\\.}` 时产出 `\\.`（正则里是「字面反斜杠 + 任意字符」），
> 连正确身份都匹配不上；**两反斜杠** `\\.` 才产出 `\.`（regexp 不是不能用，是没必要冒这个错）。
> 逐字 `--certificate-identity` 没有转义面。

`release` 由 `release-prep` 用 `--ref rstun-v<version>` 触发，所以 ref 一定是 tag。
在 `main` 上手工 dispatch 产生的签名身份是 `@refs/heads/main` —— **这种签名不能冒充某个 tag 的产物**，
下面的命令会直接失败（这是有意的）。

## 2. 三条命令（在同一个下载目录里执行）

```bash
# 1) 验 SHA256SUMS 的签名（证书身份 = 本仓 release.yml + 该 tag，逐字相等）
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.bundle \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2) 用清单校验每个资产的哈希（清单里是裸文件名，所以必须在同一目录里跑）
sha256sum -c SHA256SUMS

# 3) 验两份 SBOM 的签名（同上；`full` 把 lean 换成 full 即可）
cosign verify-blob rstun-<version>-lean.cdx.json \
  --bundle rstun-<version>-lean.cdx.json.bundle \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

第 1 条过了，说明「这份哈希清单确实是本仓 release workflow 在这个 tag 上签的」；第 2 条过了，
说明「你手上的每个字节都与清单一致」。两条都过，才算验完（只验签名不校验哈希 = 只验了一张纸）。

## 3. 容器镜像

镜像签的是 **manifest list digest**（`amd64` + `arm64` 合成的 index），不是某个架构的 digest：

```bash
# 取 digest（报告给下游、写进部署清单的也是它）
docker buildx imagetools inspect ghcr.io/exvlan/rstun:<version>

# 验签名（用 digest，不要用 tag：tag 可能被重新指向；身份逐字相等）
cosign verify ghcr.io/exvlan/rstun@sha256:<digest> \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`ghcr.io/exvlan/rstun` 是 **private** 包：先 `docker login ghcr.io`（或用
`gh auth token | docker login ghcr.io -u <user> --password-stdin`），否则拉不到签名附件。

## 4. 未签名的版本

签名从 `26.410.106` 开始。更早的 Release（含 `26.410.105`）只有 13 个核心资产、没有 bundle，
只能自行计算 sha256 与 SBOM 对照，或在信任前从 tag 自行构建。

发布流程里 `release.yml` 有一个 `sign` 输入（默认 `true`）：`false` 是**应急逃生口**，
产物不签名且发布说明会明确写「本版未签名」。此时
`post-release-verify` 默认会判失败（`require_signature=true`）—— 这正是「不要宣称已签名」的守卫；
回看历史版本时传 `require_signature=false` 只告警。反向同样成立：`sign=true` 只能从 **tag ref**
触发（`gh workflow run release.yml --ref rstun-v<version>`）—— 从分支 dispatch 会让证书身份变成
`@refs/heads/<branch>`，`prepare` 会直接拒绝（不产出任何资产）。

## 5. 篡改会怎样（负例）

- 改任何一个资产 1 个字节 → `sha256sum -c SHA256SUMS` 报 `<文件>: 失败`（清单是签过名的，改不了）；
- 把别的 Release 的 bundle 拿来用 → 身份里的 tag 对不上，`cosign verify-blob` 失败；
- 用错误的 identity 或 issuer 验证 → 失败（没有「宽松模式」）。
