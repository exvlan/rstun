# 执行计划：keyless 签名

> 顺序：先「能签」（release 内生成 sums + 签名 + 上传），再「能验」（post-release-verify），
> 最后「能证明」（负例 + 文档命令）。不 bump 版本（发版时由 release-prep 决定）。

## 阶段 0 · 依赖与口径（一次性）

| # | 事项 | 验证 |
| --- | --- | --- |
| 0.1 | 解析 `sigstore/cosign-installer` 的 tag → 40 位 commit SHA，固定 `cosign-release` 版本（如 `v2.4.x`）| `gh api repos/sigstore/cosign-installer/git/ref/tags/<tag>` |
| 0.2 | 记录所选 cosign 版本到 spec（验证口径与版本绑定）| 人工评审 |
| 0.3 | 确认 keyless 所需权限只有 `id-token: write`（Release 作业已有 `contents: write`）| 文档 |

## 阶段 1 · `release.yml` 签名

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | 新增输入 `sign`（boolean，默认 `true`）| `yaml.safe_load` |
| 1.2 | `release` 作业 `permissions` 加 `id-token: write` | 同上 |
| 1.3 | 安装 cosign（锁 SHA + 固定版本）| 本地无法跑，CI 验 |
| 1.4 | 生成 `SHA256SUMS`：13 个文件、按文件名排序 | 本地对当前 Release 资产演练（下载后算，比对）|
| 1.5 | `sign-blob --yes --bundle` 签 sums + 2 SBOM | 同上（本地可用 `COSIGN_EXPERIMENTAL`? 不行，keyless 需 OIDC；本地只做 `yaml`/脚本审阅）|
| 1.6 | assets 数组加 `SHA256SUMS` + 3 bundle；断言 **16** | 人工核对数组与断言 |
| 1.7 | `sign=false`：跳过签名并在 release notes 标注「未签名」| 读代码 + 负例演练（dev 版本）|

## 阶段 2 · `post-release-verify.yml` 校验

| # | 事项 | 验证 |
| --- | --- | --- |
| 2.1 | 资产数 13 → 16；断言 3 个 `.bundle` + `SHA256SUMS` | `yaml` + 逻辑审阅 |
| 2.2 | 安装 cosign（同 SHA/版本），对 3 个 bundle `verify-blob` | 需真实签名产物（阶段 3）|
| 2.3 | `SHA256SUMS` 校验 13 个资产（`sha256sum -c`）| 同上 |
| 2.4 | 输入 `require_signature`（默认 true；false 时缺 bundle 仅 WARN）| 与 `require_tap` 同款 |
| 2.5 | Summary 增加「签名」一行 | 同上 |

## 阶段 2b · 镜像签名

| # | 事项 | 验证 |
| --- | --- | --- |
| 2b.1 | `release.yml` 新增 `sign-image`（needs manifest；`packages: write` + `id-token: write`）| `yaml` |
| 2b.2 | `cosign sign --yes ghcr.io/<owner>/rstun@<manifest digest>` | dev 版本演练（阶段 3）|
| 2b.3 | `post-release-verify` 增加 `cosign verify <digest>`（同一 identity/issuer）| 同上 |
| 2b.4 | `sign=false` 时镜像也不签；verify 的 `require_signature=false` 时只 WARN | 读代码 |

## 阶段 3 · 端到端验证（不触碰 `.105`）

| # | 事项 | 验证 |
| --- | --- | --- |
| 3.1 | 用**预发布版本** `26.410.106-dev.0` 跑完整 release（会产出 dev crate/Release/镜像）| release run 全绿、16 资产 |
| 3.2 | `post-release-verify`（`version=26.410.106-dev.0`，`require_signature=true`）| 全绿 |
| 3.3 | 负例 A：下载资产后篡改任一 zip 的字节再 `sha256sum -c` | 失败 |
| 3.4 | 负例 B：用错误 `--certificate-identity-regexp` 验证 | 失败 |
| 3.5 | 手工按 README 的三条命令验证 | 通过 |

> 若不想产生 dev 版本：可把 3.1–3.2 顺延到下一个正式版本，但那样本任务的「自动校验」在合入时未真跑过；
> 建议至少做一次 dev 演练（crate 可用 `cargo yank` 撤）。

## 阶段 4 · 文档与 spec

| 文件 | 改动 |
| --- | --- |
| `README.md` | 「验证产物」小节：3 条命令 + 身份含义 + 未签名版本如何识别 |
| `docs/book/src/turn.md`（或新页）| 同上（用户可照抄）|
| `release.yml` 发布说明 | 去掉「未签名」，改为「已 keyless 签名；验证见 …」；`sign=false` 时明确写未签名 |
| `spec/backend/release-artifacts.md` | 资产数 16、签名契约、cosign 版本、身份 regexp、失败策略 |
| `CHANGELOG.md` | `## Unreleased` 一条 |

## 门禁（仓库侧）

```bash
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')];print('yaml ok')"
bash script/ci/check-docs.sh --no-build
bash script/ci/check-version-pins.sh
git status --short; git diff --stat
```

（Rust 代码不变，`cargo test` 不受影响；仍建议提交前跑一次 `cargo test --all-features` 证明无副作用。）

## 验收映射

| PRD 验收 | 阶段 |
| --- | --- |
| 16 资产（3 bundle）| 3.1 |
| verify 全绿 | 3.2 |
| 手工验证 + 篡改负例 | 3.3–3.5 |
| `sign=false` | 1.7（dev 演练）|
| 错误 identity 失败 | 3.4 |
| 默认行为零变化 | 门禁 + 只改 CI |

## 回滚

单 commit；revert 后资产数回 13、verify 去掉签名步骤与 `require_signature`。

## dev 演练（26.410.106-dev.0）发现并修复的缺陷

### 已确认可用的部分（真实 keyless）

- release run `45189777328`：17 资产、`Sign container image` 成功、自动 publish 成功；
- 本地 cosign v3.1.4 对真实 bundle 验证：
  - 正确身份 `…release.yml@refs/tags/rstun-v26.410.106-dev.0` → **`Verified OK`**；
  - 错误身份 `refs/heads/main` → 失败并打印实际 SAN（身份绑定有效）；
  - 两份 SBOM bundle 同样 `Verified OK`。

### 缺陷 1：dev Release 未标 prerelease

`gh release create` 没有 `--prerelease` → `releases/latest` 指向 dev 版本，
tap 次日 05:30 会把 formula 同步成 dev。修：版本含 `-` 时 `--prerelease`（create 与已存在时的 edit 都加）。

### 缺陷 2：verify 的 deb 期望名未考虑 Debian 规范化

nfpm 把预发布版本写成 `rstun_26.410.106~dev.0_amd64.deb`；verify 期望 `-` 形式 → 「缺少资产」，
后续步骤被跳过（并因 cosign 未装出现 `exit 127`）。修：
- `build-deb.sh` 产出后把文件名 `~` → `-`（与版本串一致；稳定版无影响）；
- verify 的包内 `Version:` 允许 `$VERSION` 或 `${VERSION//-/\~}`；
- `Install cosign` 提前、镜像签名步骤依赖 cosign 安装成功；
- `signed_assets/` 断言文件名不含 `~`（GitHub 会把 `~` 改写为 `.`）。

### 缺陷 3：GitHub 改写资产名（`~` → `.`）

实测 Release 资产名 `rstun_26.410.106.dev.0_amd64.deb`，而 nfpm 本地名是 `~` 形式 →
`SHA256SUMS` 与实际下载名不一致，用户 `sha256sum -c` 必失败。与缺陷 2 同一修法（统一文件名）。

### 重新演练计划

修复合入后，用 `26.410.106-dev.1` 重新走 prep → release（新 tag 里包含修复后的 workflow）→ verify；
随后把 dev.0/dev.1 标 prerelease 并 `cargo yank`。

## dev.1 复验（修复后，全部通过）

run [45192444157](https://github.com/exvlan/rstun/actions/runs/45192444157)（release）与
[45193288345](https://github.com/exvlan/rstun/actions/runs/45193288345)（post-release-verify）：

| 检查 | 结果 |
| --- | --- |
| Release 标记 | `isPrerelease=true`；`/releases/latest` → `rstun-v26.410.105`（tap 不被污染）|
| 资产 | 17（13 核心 + `SHA256SUMS` + 3 bundle）|
| deb 名 | `rstun_26.410.106-dev.1_amd64.deb`（dash，与清单一致）|
| `sha256sum -c --strict`（本地下载 13 资产）| **13/13 成功** |
| `cosign verify-blob`（本地，正确身份）| **Verified OK** |
| `cosign verify-blob`（错误身份 `refs/heads/main`）| 失败并打印实际 SAN（绑定有效）|
| 镜像 | `Sign container image` success；verify 的 `Verify image signature (cosign keyless)` success |
| post-release-verify | **13/13 步 success**（含 deb、签名+清单、镜像签名、tap warn 路径）|

## 清理

- dev.0 已补标 `prerelease`（此前占用 `latest`）；
- `cargo yank 26.410.106-dev.0` 与 `26.410.106-dev.1` 已执行；
- dev 镜像 `ghcr.io/exvlan/rstun:26.410.106-dev.{0,1}` 保留（未删；如需清理另行执行）；
- 本地/远端 tags 均保留 `rstun-v26.410.106-dev.{0,1}` 作为演练证据。

## 演练共修复 4 个真实缺陷

1. dev Release 未标 `prerelease` → `latest` 被占用、tap 会同步 dev；
2. **`SHA256SUMS` 与 GitHub 改写后的资产名不一致**（nfpm 用 `~`，GitHub 改成 `.`）→ 用户 `sha256sum -c` 必败；
3. verify 期望 deb 名/包内 Version 未按 Debian 规则处理；
4. `Install cosign` 排在失败链之后 → `exit 127` 被 `continue-on-error` 洗成绿步骤。

## 未做（记录）

- 正式版发布（`26.410.106`）不在本任务范围；发版时按标准流程 `preflight → prep`。
- 镜像签名的 `--recursive`（逐平台签名）未启用，只签 manifest list digest。
