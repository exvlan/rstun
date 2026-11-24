# 26.410.106 发布：首个带 keyless 签名的正式版（2026-11-24）

## 版本与产物

| 项 | 值 |
| --- | --- |
| 版本 | `26.410.106`（正式版，`prerelease=false`）|
| Release | `rstun-v26.410.106`，**17 资产**（13 核心 + `SHA256SUMS` + 3 个 cosign bundle）|
| deb | `rstun_26.410.106_{amd64,arm64}.deb`（dash 命名，与清单一致）|
| 镜像 | `ghcr.io/exvlan/rstun:26.410.106`（amd64+arm64，full），digest `sha256:9cfc500ad56002f4ecd8c43d36a51991882df2b093db42e6a1542c2a75a9bf42` |
| crates.io | ✅ `26.410.106`（`publish-crates` 自动发布）|
| Homebrew tap | ✅ `version "26.410.106"`（反向同步 run 45294013996）|
| `/releases/latest` | `rstun-v26.410.106` |

## 发布链（全自动）

- `release-preflight`：首跑 `raf` 假红（负载丢包）→ 重跑 **PASS**（`verdict=PASS`，19 passed）；
  已给 `raf` 项补失败诊断（打印 uclient 尾部），提交 `2b8933a`；
- `release-prep`（dry_run 45293164479 → 真跑 45293232675）：bump → commit `0d4d89e` → tag → dispatch `--ref tag`；
- `release` run 45293289576：12/12 作业成功（含 `Sign container image`、`publish (26.410.106)`）；
- `post-release-verify` run **45294088487**：**13/13 步 success**：
  `Assert release assets (13 core + 4 signature)` / `Verify signatures and SHA256SUMS` /
  `Verify image signature (cosign keyless)` / `Verify tap formula` …

## 用户在 `.106` 起可用的验证方式

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.bundle \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v26.410.106' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c --strict SHA256SUMS
cosign verify 'ghcr.io/exvlan/rstun@sha256:9cfc500a…' \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v26.410.106' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

（身份是**逐字**字符串；`refs/heads/main`、别的 owner、别的版本都不匹配。）

## 演练产物保留（按用户决定）

- `rstun-v26.410.106-dev.0` / `-dev.1`：保留，均已标 `prerelease`；
- dev 镜像 `ghcr.io/exvlan/rstun:26.410.106-dev.{0,1}`：保留；
- 两个 dev crate 已 `cargo yank`。

## 对生产（EXVlan）的影响

默认行为与 `.105` 一致（新增的只是产物签名与验证方式）。他们当前 `.105`，
是否切换由他们决定；切换时按老规矩改 digest 并重建 exvlan 单 Pod。
