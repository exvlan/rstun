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
