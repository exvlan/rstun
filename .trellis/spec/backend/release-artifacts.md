# 发布物契约（Release artifacts）

> 来源：`rstun-v26.410.100` 首发时逐条踩到并实测修正；`11-22-rstun-release-automation` 补了自动路径
> （`release-prep` 一键 bump+tag+dispatch；`publish-crates` 幂等发布 crates.io）；
> `11-23-rstun-cosign` 补了 keyless 签名（文件资产 + 镜像）。
> 任何会产出 Release 资产、容器镜像或 crates.io 版本的改动都必须满足本文。

## 1. Scope / Trigger

满足任一条即适用（不是建议）：

- 修改 `.github/workflows/release.yml`（构建 / 打包 / 发布 / 镜像 / crates.io 发布 / **签名**）；
- 修改 `.github/workflows/{release-preflight,post-release-verify,release-prep,publish-crates}.yml`
  或 `script/ci/check-version-pins.sh`；
- 重发同一版本（`gh release upload --clobber`）或补发 crate（`publish-crates.yml` 的 dispatch）；
- **改动签名口径**（cosign 版本、签哪些对象、bundle 命名、身份 regexp、`sign` / `require_signature` 语义）；
- 修改版本注入（`RSTUN_BUILD_VERSION`）或 `Cargo.toml` 的 `version`。

## 2. Signatures（可执行入口）

| 动作 | 命令 |
| --- | --- |
| 标准发版顺序 | **preflight（只读）→ release-prep（bump+commit+tag+dispatch）→ release（资产/镜像/crate 并行）→ tap 同步（触发或等每日 05:30）→ post-release-verify（只读）** |
| 触发发布 | `gh workflow run release.yml -R exvlan/rstun --ref rstun-v<version> -f version=<x.y.z>`（**必须带 `--ref <tag>`**：`sign` 默认 `true`，`prepare` 有 ref 守卫 —— 从分支 dispatch 会让 keyless 身份绑成 `@refs/heads/main`；确实要从分支发版只能显式 `-f sign=false`，说明会写「本版未签名」）|
| 一键 bump + tag + 触发 | `gh workflow run release-prep.yml -R exvlan/rstun -f version=<x.y.z> -f dry_run=false`（**默认 `dry_run=true` 只预演**）|
| 发版前只读预检 | `gh workflow run release-preflight.yml -R exvlan/rstun -f version=<x.y.z>`（或 Actions → Release preflight）|
| 发布后只读验收 | `gh workflow run post-release-verify.yml -R exvlan/rstun -f version=<x.y.z>`（或 Actions → Post-release verify）。**tap 是跨仓异步派生**：刚发布后公式可能还没同步——默认 `require_tap=true` 会把不一致判失败（防漏同步）；只想先看 Release 资产时传 `-f require_tap=false`，tap 同步后**再跑一次**不带该参数。**签名**默认 `require_signature=true`（缺 bundle/镜像签名即红）；回看签名上线前的历史版本传 `-f require_signature=false` 只告警 |
| tap 同步触发 | `gh workflow run sync.yml -R exvlan/homebrew-rstun`（或等每日 05:30 UTC）。同步完成后公式版本应等于本次 release tag |
| tap 的 CDN 缓存 | `raw.githubusercontent.com` 有 CDN 缓存（实测同步后 2–5 分钟仍返回旧文件，且 `?t=` 查询串破不了）。因此 verify **轮询等待**：`require_tap=true` 时每 30s 重试、最多约 6 分钟；`false` 时只试一次 | 刚同步就验收会假红 |
| 补发 / 幂等演练 crate | `gh workflow run publish-crates.yml -R exvlan/rstun --ref <ref> -f version=<version>`（**必须 `--ref`**：workflow 断言「输入 == 检出树的 `Cargo.toml` version」；默认分支在下一版 bump 后已不等于历史版本。**ref 选择**：版本发布时该 tag 里必须有此 workflow 文件 → `rstun-v26.410.104` 及更早的 tag **没有**（本 workflow 于 2026-11-22 才落地），这类历史版本只能用 `--ref main` 且要求 main 的 `Cargo.toml` 仍等于该版本；下一个版本起的 tag 可用 `--ref rstun-v<version>`。**不要**为此重跑 `release.yml`：会重建镜像、改 digest）|
| 核对 crate | `curl -s -o /dev/null -w '%{http_code}\n' -A 'rstun-release/1.0' https://crates.io/api/v1/crates/rstun/<x.y.z>`（200=已发布，404=未发布）|
| 版本钉死点（6 处）| `bash script/ci/check-version-pins.sh [--version <x.y.z>]` |
| 核对资产 | `gh release view rstun-v<version> -R exvlan/rstun --json assets --jq '.assets[]\|{name,size}'` |
| 核对多架构 | `docker buildx imagetools inspect ghcr.io/exvlan/rstun:<version>` |
| 核对 tag 指向 | `gh api repos/exvlan/rstun/git/ref/tags/rstun-v<version> --jq .object.sha` |
| 撤回已发布的 crate | `cargo yank --version <x.y.z>`（crates.io **不可删除**，只能 yank）|
| 本地验证资产 | `gh release download … && unzip … && test -x ./rstun && ./rstun --version` |
| 验证文件签名 | `cosign verify-blob <file> --bundle <file>.bundle --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>' --certificate-oidc-issuer https://token.actions.githubusercontent.com`（`<file>` = `SHA256SUMS` / 两份 SBOM；身份**逐字**相等，非正则）|
| 验证哈希清单 | `sha256sum -c SHA256SUMS`（与 13 个资产同一目录；清单里是**裸文件名**）|
| 验证镜像签名 | `cosign verify ghcr.io/exvlan/rstun@sha256:<manifest-list-digest> --certificate-identity … --certificate-oidc-issuer …`（身份同上，逐字）|
| cosign 版本 | `sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532`（v4.1.3）+ `cosign-release: v3.1.4`（`release.yml` 与 `post-release-verify.yml` 必须同版本）|

## 3. Contracts

| 契约 | 规则 | 违反后的现象 |
| --- | --- | --- |
| 资产可执行位 | zip 内 `rstun` / `rstun.exe` 必须 `0755`（打包前 `chmod +x`）| 解压后 `./rstun` → `Permission denied` |
| 作业间产物权限 | `download-artifact` **不保留权限位**（落盘 0644）：任何直接使用下载产物的步骤（zip、deb、冒烟）必须先 `chmod +x`，不要用 `[ -x ]` 当存在性检查 | `::error::missing lean binary …` / `Permission denied` |
| tag ↔ 资产 ↔ 镜像 | 三者必须对应同一 commit；**不 force 移动已发布 tag**（消费者会拿到不同树）| `--version` 的 `+<sha6>` 与 tag 指向不符 |
| 下游 digest | 对外报 **manifest list digest**（amd64+arm64 index）| 下游按 digest 校验对不上 |
| 版本串 | `version` 输入 == `Cargo.toml` 的 `version`；二进制 `--version` = `<version>+<sha6>` | 包与报的版本不一致 |
| 镜像 | `ghcr.io/exvlan/rstun:<version>`，稳定版附 `:latest`；双架构必须由 manifest 合并 | 单架构冒充双架构 |
| Release 状态（prerelease / latest）| 版本号含 `-`（预发布）→ `gh release create --prerelease`；已存在的 Release 用 `gh release edit "$TAG" --prerelease=${PRERELEASE}` 幂等校正（正式版传 `--prerelease=false`）。**`/releases/latest` 只指向正式版**：预发布一旦漏标，latest 会被 dev 占用，而 tap 的 `sync.yml` 读的正是 latest → Homebrew formula 被切到预发布 | dev 演练实测：`26.410.106-dev.0` 漏 `--prerelease` → `releases/latest` 变 dev，tap 同步把 `brew install` 指到预发布 |
| deb 资产 | `rstun_<version>_{amd64,arm64}.deb` 各一份（lean、musl static-pie，包内二进制与 lean zip 同源）；缺任一即失败。**预发布**：文件名用版本串的 `-` 形式（`rstun_26.410.106-dev.0_amd64.deb`，`build-deb.sh` 把 nfpm 的 `~` 改掉 —— GitHub 会把资产名里的 `~` 改写成 `.`，不改则 `SHA256SUMS`/verify 与下载名不一致），而**包内 Debian `Version:` 保持 `~`**（`26.410.106~dev.0`，Debian 预发布规范：排在同版本正式版之前）| 用户装到旧版/异构二进制；或清单里的名字与下载到的名字不同（哈希校验全红）|
| Homebrew tap | `exvlan/homebrew-rstun` 的 formula 与该 Release 的 `rstun.rb` 类体一致 | `brew install` 拉到不存在的 sha256 |
| 包可见性 | 新包默认 private：有凭证可拉、匿名 401 | 「我这边能 pull」误判 |
| 动态链接 | linux 目标为 static-pie（musl）| 依赖宿主 glibc 版本 |
| full 构建的 C 工具链 | Linux musl 目标必须装 `musl-tools` 且设 `CC_<triple>=musl-gcc`（full 的 `ring` 含 C 代码）| `cc-rs: failed to find <triple>-musl-gcc`，构建 exit 101 |
| 发版前预检 | **发布前必须 `release-preflight.yml` 全绿**（pins / tests+clippy+fmt / interop all / TURN lean+full（含 frozen）/ SBOM / deb / brew 渲染 / `cargo publish --dry-run`）；只读、无 secret | 发版当天才发现打包或协议回归 |
| 发布后验收 | **发布后必须 `post-release-verify.yml` 全绿**（tap 同步之后）：资产命名与数量（13 核心 / 签名版 17）、四平台 zip 架构、`--version` 含 `<version>` 且 `+sha6` == tag 指向提交、两个 deb 的 Version/Architecture、tap formula 类体 + 3 个 sha256、镜像 amd64+arm64 manifest、**3 个 bundle 的身份 + `SHA256SUMS` 覆盖的 13 个哈希 + 镜像 digest 签名**；只读，`packages: read` 只为私有 ghcr 登录（验签不需要 `id-token`）| 「流水线绿了但用户下载到坏资产」 |
| 资产数量 | 13 个核心资产（8 zip + 2 SBOM + `rstun.rb` + 2 deb）恒存在；`sign=true`（默认）时再加 **`SHA256SUMS` + 3 个 `.bundle` = 17**，`sign=false` 时 13。断言按 `sign` 分支写，不写死一个数 | 下游脚本按固定数量断言 → 发版后红；或少了 bundle 还宣布「已签名」|
| 签名对象与覆盖 | 签 `SHA256SUMS` + 两份 SBOM（各一个 bundle）；`SHA256SUMS` 覆盖 **13 个核心资产的裸文件名哈希**（按文件名排序）。不逐个签二进制：签名数从 10 降到 1，字节由清单绑定 | 逐个签 → 验证成本高；只签二进制不签清单 → 「哪个文件属于这次发布」不可证 |
| bundle 命名 | `<被签文件名>.bundle`；验证时 `cosign verify-blob <file> --bundle <file>.bundle` | 命名漂移 → 文档命令与 verify 步骤同时失效 |
| 签名身份 | keyless：证书 SAN = `https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>`，issuer = `https://token.actions.githubusercontent.com`；`post-release-verify` 用 **`--certificate-identity` 逐字比较**（不是 regexp）+ 同一 issuer。**禁止在身份上拼 regexp**：当时实现写的是**四反斜杠** `${VERSION//./\\\\.}`，在双引号里产出 `\\.`（正则语义是「字面反斜杠 + 任意字符」），连正确身份都匹配不上（2026-11-23 阻塞缺陷）——**两反斜杠 `\\.` 才产出 `\.`**，即 regexp 本身可用、错在转义；逐字 `--certificate-identity` 没有转义面，所以选它；`'.*'` 等于没验 | 身份不绑 tag → `main` 上手工 dispatch 的签名可冒充某 tag 的产物；或用转义错误的正则 → **正确产物也验不过**（假红）|
| 签名触发 ref | `release` 必须从 tag ref dispatch（`release-prep` 的 `--ref rstun-v<version>`）；`@refs/heads/main` 的证书**不被 verify 接受**。`prepare` 有硬守卫：`sign=true` 且 `GITHUB_REF != refs/tags/<tag>` → `::error::` 失败（防止「证书 `@refs/heads/main` + 说明写 tag 身份」的事实性错误）；从分支发版只能显式 `-f sign=false` | tag 与签名身份不一致（verification 红），或说明里的身份是假的 |
| 哈希生成时机 | `SHA256SUMS` 在扁平暂存目录（`signed_assets/`）里对**最终上传的字节**生成，之后不再改动；上传的正是该目录 | 上传后再算 → 清单与实际文件不符 |
| 签名失败 | 文件侧（`cosign sign-blob` 在 `release` 作业内、上传之前）失败 → **不产出 Release**；镜像侧（`sign-image`）失败 → 整个 run 红、资产可能已上传，但 `post-release-verify` 会因缺镜像签名而红（必须重跑签名，不能宣称已签名）。`sign=false` 是**唯一**跳过路径（发布说明必须写「未签名」）| 发出「声称已签名其实没有」的 Release |
| 镜像签名 | 只签 **manifest list digest**（`ghcr.io/<owner>/rstun@sha256:<digest>`，签名存 OCI 附件，不占资产位），不加 `--recursive`；验证同样用 digest | 只验 tag → tag 被重指后仍然「验过」|
| 版本钉死点 | `Cargo.toml` 的 `version` 必须同时等于 6 处：README「已发布」、`docs/book/src/docker.md`、`contrib/k8s/deployment.yaml`、`contrib/docker/compose.yaml`、`contrib/helm/{Chart,values}.yaml`；`script/ci/check-version-pins.sh`（CI `version-pins` 作业）守 | 文档说 A、镜像示例说 B（拉镜像 404）|
| crate 打包预检 | CI `packaging` 作业：`cargo package --list` 断言不含 `fuzz/` `tests/` `.github/` `.trellis/` `.env`，版本与 `cargo metadata --locked` 一致，且 `cargo publish --dry-run` 通过 | 发版时才发现 crate 包混进夹具/密钥 |
| 发版流程顺序 | **先 `release-preflight` 全绿，再 `release-prep`（默认 `dry_run=true` 看 diff），最后 `release`**；跳过 preflight 直接 prep = 把「打包/协议回归」发现时间推到 crates.io 已发布之后（crate 不可删除）| crates.io 上留下一个坏版本（只能 yank）|
| crates.io 自动发布 | `release.yml` 的 `publish-crates` 作业调用可复用件 `publish-crates.yml`：与 `release` 作业**并行**（不 `needs: release`），`needs: [prepare, build]`；token 只经 `secrets.CARGO_REGISTRY_TOKEN` 注入并 `cargo publish --locked` | 资产发出去了但 crate 没发（或发了没人验证过的依赖组合）|
| crate 发布幂等 | 先查 `crates.io/api/v1/crates/rstun/<version>`：**200 → 跳过**（重跑不红）、**404 → 发布**、**其它状态（403/429/5xx/网络）→ 失败**（不盲发）。请求**必须带 `User-Agent`**（无 UA 实测 403）| 重跑同版本红；或把 403 当成「未发布」继续发 |
| crate 版本真源 | `publish-crates` 必须自己断言输入 `version` == 检出树的 `Cargo.toml` version（`cargo publish` 发的是清单里的版本，不是输入串）；因此补发/演练历史版本要 `--ref rstun-v<version>`（默认分支已 bump 到下一版） | 输入 105、清单 104 → 想着发 105 实际发 104 |
| crate 演练入口 | 验证幂等/补发只能 dispatch `publish-crates.yml`（`--ref` 规则见上一行：新版本用 tag，`26.410.104` 及更早只能用 `--ref main`）；**不要**重跑 `release.yml`（会重建镜像 → 同一版本 manifest digest 变化，下游按 digest 校验的记录失效）| 对端记录的 digest 对不上 |
| prep 版本单调 | `release-prep` 的新版本必须**严格大于** `Cargo.toml` 当前值（同版本 = 重复发版、更小 = 回退）；同 core 的正式版 > 预发布版；同 core 同通道（`dev.1`→`dev.2`）视为「不严格大于」 | 撞已发布的 tag / crates.io 上已存在的版本 |
| prep 的 tag | tag 已存在于 origin → 失败，**绝不 force**；tag 用 `git tag -a` 并先 `git ls-remote --tags` 检查 | 已发布 tag 被移动，消费者拿到不同树 |
| prep 的 dispatch | `gh workflow run release.yml --ref rstun-v<version>`：让 release 从 **tag 指向的树**构建（否则期间有人 push，资产 `+sha6` 与 tag 不符）| `post-release-verify` 的 sha6 检查红 |
| prep 的 dry_run | 默认 `true`：只改工作树 + 打印 `git diff` 与计划；写入步骤 `if: env.DRY_RUN == '0'` 正向开启，且脚本内再断言一次 | 演练变成真发版（push/tag/Release 不可撤）|
| prep 的 CHANGELOG | 必须有 `## Unreleased` 段；该版本已在 CHANGELOG 出现 → 失败（重复发版）| 发出去没有 changelog 的版本 |
| prep 的权限 | 作业需 `contents: write`（commit/push/tag）**+ `actions: write`**（`gh workflow run` 的 dispatch 事件）| dispatch 步骤 403 `Resource not accessible by integration` |
| 凭据不落库 | `CARGO_REGISTRY_TOKEN` 只作为仓库 secret；脚本/文档/日志不出现值；`.env.secret` 保持 gitignore | token 泄漏（crate 可被任意发布）|

### 3.1 发版流程（自动路径 + 逃生口）

```
release-preflight（只读：pins / tests / clippy / fmt / interop / TURN lean+full / SBOM / deb / brew / publish dry-run）
        ↓ 全绿
release-prep（dry_run=true 先看 diff；dry_run=false：bump + CHANGELOG 收口 + 6 处钉死点 + commit + push + tag + dispatch）
        ↓
release.yml ──┬── build（四平台 × lean/full）→ release（13 核心资产；签名时 +4 = 17）
              ├── image（amd64+arm64）→ manifest（<version> + latest）→ sign-image（cosign，digest 签名）
              └── publish-crates（crates.io，幂等：已存在即跳过）   ← 与 release / sign-image 并行、互不阻塞
        ↓
post-release-verify（只读：资产 13/17 / 四平台架构 / --version+sha6 / deb / tap formula sha256 /
                     镜像双架构 / 3 个 bundle 身份 + SHA256SUMS 哈希 / 镜像 digest 签名）
        ↓
tap 同步：`exvlan/homebrew-rstun` 的 `sync.yml`（每日 05:30 UTC cron + 手动 dispatch）
          反向拉取最新 Release 的 `rstun.rb` —— **已于 2026-11-22 合入并实测**（无变化时不提交、
          零 PAT、只用 tap 仓自己的 `GITHUB_TOKEN`）。`post-release-verify` 的 formula 段是
          「漏同步/同步错」的自动守卫（比较类体 + 3 个 sha256）。
```

- 任一步失败都**不自动回退**前面已完成的动作：资产坏了用 `--clobber` 重发；crate 错了只能 `cargo yank` +
  新版本修复；tag 一旦发布不移动（`release-prep` 会拒绝重打）。
- 手工逃生口始终可用：`bump` + `gh workflow run release.yml --ref rstun-v<version> -f version=…`
  （`--ref` 不能省：`sign` 默认 `true` 时 `prepare` 会拒绝非 tag ref）；补发 crate 用
  `publish-crates.yml` 的 dispatch。

## 4. Validation & Error Matrix

| 条件 | 必须的行为 |
| --- | --- |
| 输入 `version` ≠ `Cargo.toml` version | `::error::` 阻断发布（`release.yml`、`publish-crates.yml` 各查一次）|
| crates.io 上该版本已存在 | `publish-crates` **跳过**并写 summary（重跑不红）；不视为错误 |
| crates.io API 返回 200/404 之外 | 失败并打印状态码（不把 403/5xx 当「未发布」）|
| `CARGO_REGISTRY_TOKEN` 未设置且需要发布 | 明确报「secret 未设置」，不打印任何凭证 |
| 重跑同一版本的 `release.yml` | 资产 `--clobber`、镜像 `--amend`、crate 跳过（三段都幂等）。**注意**：`--clobber` 只覆盖资产、**不改发布说明** → 先 `sign=false` 再 `sign=true` 重跑会得到「17 个资产但说明仍写未签名」（反之亦然），必须手工 `gh release edit --notes-file …` 修正说明 | 说明与资产互相矛盾（用户以为没签名，或以为签了）|
| `release-prep` 的新版本 ≤ 当前 | 失败（同版本=重复发版；更小=回退）|
| `release-prep` 的 tag 已存在 | 失败并提示换版本号（不 force）|
| `release-prep` 找不到 `## Unreleased` / 版本已在 CHANGELOG | 失败并说明「先补 changelog / 重复发版」|
| `release-prep` 某一处钉死点替换命中数 ≠ 1 | 失败（钉死点漂移；先去跑 `check-version-pins.sh` 定位）|
| `release-prep` push 到受保护分支 | push 被拒 → 失败（有意的 fail-fast：走 PR 流程或临时放开保护）|
| Release 已存在 | 只 `--clobber` 覆盖资产，不移动 tag、不改说明 |
| zip 数为 0 | 失败（禁止空 Release）|
| 镜像缺 amd64 或 arm64 | 发布失败（manifest 不完整）|
| 是预发布（版本含 `-`）但 Release 未标 prerelease | `gh release create --prerelease`；已存在则 `gh release edit --prerelease=true`。漏标 → `/releases/latest` 指向 dev → tap 同步到预发布 |
| 版本含 `-` 却标成正式版 / 反之（历史上误标）| 重跑 `release.yml` 的同版本：`gh release edit --prerelease=${PRERELEASE}` 幂等校正（不改 tag、不动资产）|
| Fulcio/Rekor 不可达 / `cosign sign-blob` 失败（文件侧）| `release` 作业失败，**不产出 Release**；错误可读 |
| `cosign sign` 失败（`sign-image`，镜像侧）| 整个 run 红；资产可能已上传，但 verify 的镜像签名项会红 —— 修好后重跑签名，**不要**宣称已签名 |
| `sign=false` | 不产生 `SHA256SUMS`/bundle（13 资产）；发布说明写「本版未签名」；`post-release-verify` 默认（`require_signature=true`）判失败 |
| `sign=true` 但 `GITHUB_REF != refs/tags/<tag>`（如在 `main` 上手工 dispatch）| `prepare` 的 `Require tag ref when signing` 失败：三条 `::error::`，提示改用 `--ref <tag>` 或显式 `-f sign=false`；**不进入 build**（不产出任何资产）|
| 签名资产半套（有 `SHA256SUMS` 缺 bundle，或反之）| 发布侧：数量断言失败（≠13/17）；验证侧：**失败**（`require_signature=false` 也不例外）|
| 资产被替换 / 篡改 | `sha256sum -c SHA256SUMS` 失败（清单签过名，改不了）|
| bundle 的身份不是「本仓 release.yml @ 该 tag」 | `cosign verify-blob` / `cosign verify` 失败（含 `@refs/heads/main` 的签名）|
| `post-release-verify` 遇到无 bundle 的历史版本（≤ `26.410.105`）| 传 `require_signature=false` 只告警；默认 red（守卫「别宣称已签名」）|
| Windows 冒烟/脚本 | 必须 `PYTHONIOENCODING=utf-8`，缺 `python3` 时用 `python` shim |
| 精简 CI 作业 | 本仓无 `.cargo/config.toml` 的链接器强制项；若将来加入（如 mold），需在作业里自装 |
| TLS 握手探针 | 必须「先落盘再 `grep`」；`pipefail` 下 `openssl s_client \| grep -q` 会因 grep 命中即退出让 openssl 收 SIGPIPE，握手成功也判失败 |

## 5. Good / Base / Bad

- **Good**：打包前 `chmod +x`；发布后真下载执行；双架构 manifest；tag 指向发布提交且不再移动；
  发版前 `release-preflight` 全绿、发布后 `post-release-verify` 逐项 PASS；
  发版顺序 preflight → prep（先 `dry_run` 看 diff）→ release（crate 幂等自动发布）→ verify；
  签名覆盖「哈希清单 + SBOM + 镜像 digest」，身份绑死本仓 workflow 与该 tag。
- **Base**：CI 内 `--version` 自检 + 容器内 `--version` 自检（必要不充分）。
- **Bad**：只看到 `cargo build` 成功就认为资产可用；把单架构 digest 当双架构；`--clobber` 后不核对 tag；
  版本号只改 `Cargo.toml` 不改 6 处钉死点；跳过 preflight 直接自动发布 crate；
  为了重试 crate 而重跑 `release.yml`（重建镜像 → digest 变化）；`curl -f` 一把梭判幂等（分不清 403 与 404）；
  「签了名」但身份不是本仓/该 tag（`--certificate-identity-regexp '.*'` 等于没验）、或只验签名不校验哈希；
  用拼转义的正则做身份约束（四反斜杠 `\\\\.` 产出 `\\.` → 正确产物也验不过；**两反斜杠 `\\.` 才是对的**，
  但 regexp 的转义面本可避免 —— 用 `--certificate-identity` 逐字比较即无转义）。

## 6. Tests Required（断言点）

1. 下载 Release 资产 → `test -x ./rstun` → `./rstun --version` 含 `<version>+<sha6>`。
2. `docker buildx imagetools inspect` 输出含 `linux/amd64` 与 `linux/arm64`。
3. tag 指向的 commit 的 `sha6` 与资产 `--version` 一致。
4. 冒烟：`bash script/ci/rstun-smoke.sh <addr> --tcp` 返回 `0x0101`。
5. 本仓为 public：提交前扫描 `grep -rnE '(生产网段|内部路径)' --exclude-dir=.git .` 为空。
6. `check-version-pins.sh` 正例 exit 0；**反证**：把 README 的「已发布」版本改成旧值 → exit 1 并打印
   `README.md:<行>`；改回 exit 0。`--version` 与 `Cargo.toml` 不同 → exit 1。
7. `packaging` 预检反证：在 `Cargo.toml` 的 `exclude` 里去掉 `tests/**` → `cargo package --list` 出现
   `tests/...` → 作业失败。
8. `post-release-verify.yml` 对已发布版本全绿（签名基线：第一个带签名的版本，如 `26.410.106`；
   `26.410.105` 及更早必须带 `require_signature=false` 才绿）；传不存在的版本 → 资产步骤
   明确报 `Release rstun-v... 不存在` 并红。
9. 四个 workflow 必须 `yaml.safe_load` 通过、action 全 40 位 SHA、`permissions` 最小化：
   P0 两个（preflight / post-release-verify）只读（后者额外 `packages: read` 用于私有 ghcr 登录）；
   `publish-crates.yml` 只有 `contents: read`（发布用 secret，不用 GITHUB_TOKEN）；
   `release-prep.yml` 必须是 `contents: write` **+ `actions: write`**（后者供 `gh workflow run`）。
10. `publish-crates.yml` 幂等分支实测：对**已发布**版本 → HTTP 200 → summary 写「已发布即跳过」且**不**调
    cargo；对**未发布**版本 → 404 → 继续。反证：把 curl 桩成 403 → 步骤失败（不盲发）。
11. `publish-crates.yml` 版本门：输入与 `Cargo.toml` 不一致 → `::error::`（否则会发出清单里的旧版本）。
12. `release-prep.yml` 版本单调性：同版本 / 更小 / 同 core 的预发布 → 失败；`26.410.105-dev.0 → 26.410.105`
    → 通过。`dry_run=true` 时 `git status` 有改动但**无** commit / tag / dispatch。
13. `release-prep.yml` 全链路（测试分支演练）：bump 后 `check-version-pins.sh` exit 0、`Cargo.lock` 里
    `rstun` 版本已更新、`git tag -a` 打出的 tag 指向 bump commit、dispatch 带 `--ref rstun-v<version>`；
    同版本重跑在「严格大于」处失败，tag 已存在时在 `ls-remote` 处失败（不 force）。
14. 签名资产数量分支（实测脚本）：`sign=true` + 17 个文件 → 通过并上传；`sign=true` + 16 → `::error::`
    资产数不对；`sign=false` + 13 → 通过；`sign=false` + 14（残留 bundle）→ 失败。
15. `SHA256SUMS` 生成与校验（用已发布资产演练，不需要 keyless）：13 条、裸文件名、按文件名排序；
    **反证**：向任一资产追加 1 字节 → `sha256sum -c --strict SHA256SUMS` 非 0 并打印 `<文件>: 失败`；
    还原后 exit 0。
16. `post-release-verify.yml` 的资产分支：17 + `require_signature=true` → 通过；13 + `true` → 失败并提示
    「历史版本请传 require_signature=false」；13 + `false` → 通过但 `::warning::`；16（半套）+ 任一取值 → 失败。
17. 身份绑定反证（**逐字比较**，非正则）：`release.yml`/`post-release-verify.yml` 里传给 cosign 的
    `--certificate-identity` 必须**逐字**等于 `https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v<version>`；
    反证：`@refs/heads/main` 的签名 / 别的 owner / 别的版本 → `cosign verify-blob`、`cosign verify` 失败；
    镜像用 tag 而非 digest 验证不被接受（spec 要求 digest）。
    （附：`--certificate-identity-regexp` **并非不可用** —— 但转义极易写错：四反斜杠 `\\\\.` 产出 `\\.`
     会让正确身份也匹配不上，两反斜杠 `\\.` 才是 `\.`。逐字 `--certificate-identity` 无转义面，是本仓的选择。）
18. `release.yml` / `post-release-verify.yml` 的 cosign installer 必须同 action SHA 与同 `cosign-release`
    （`v3.1.4`）；`release` 作业有 `id-token: write`，`sign-image` 有 `packages: write` + `id-token: write`，
    `post-release-verify` **无** `id-token`（只读验签）。
19. `release.yml` 的 ref 守卫（把该步骤的 `run` 抽出来脚本级实测）：
    `GITHUB_REF=refs/heads/main` + `sign=true` → **exit 1**（三条 `::error::`）；
    `GITHUB_REF=refs/tags/<tag>` → exit 0；`refs/tags/<别的 tag>` → exit 1；
    `sign=false` 时该步骤被 `if: inputs.sign` 跳过（不执行、不失败）。
20. `release.yml` 的 prerelease 分支（把「Create or update release」的 `run` 抽出来，桩 `gh` 记录 argv）：
    `PRERELEASE=true` + Release 不存在 → `gh release create … --prerelease`；
    `PRERELEASE=false` + 不存在 → **不带** `--prerelease`；
    Release 已存在 → `gh release upload --clobber` 之后必定执行 `gh release edit "$TAG" --prerelease=<true|false>`；
    发布说明在预发布时含「**预发布版本** … 不建议生产使用」，正式版不含该行。
    真实验证：预发布发完后 `gh api repos/exvlan/rstun/releases/latest --jq .tag_name` **不得**是该 dev tag。
21. 预发布 deb 的命名/版本双形式（本地实测）：
    `build-deb.sh --version 26.410.106-dev.0` 产出的**文件名**是 `rstun_26.410.106-dev.0_<arch>.deb`
    （无 `~`），而 `dpkg-deb -I` 的 `Version:` 是 `26.410.106~dev.0`（Debian 预发布规范，**不改**）；
    `post-release-verify` 的 deb 断言对这两种 `Version:` 都接受，但文件名只认 `-` 形式
    （只有 GitHub 改写后的 `.` 形式 → `dpkg-deb` 打不开 → 失败）；
    `release.yml` 的暂存断言对含 `~` 的文件名 → `::error::` + 打印清单。

## 7. Wrong vs Correct

#### Wrong
```yaml
# upload-artifact → download-artifact 往返会丢权限位
( cd "$d" && zip -r "../../zipped_assets/${name}.zip" . )
```

#### Correct
```yaml
for f in "$d"/*; do [ -f "$f" ] && chmod +x "$f"; done
( cd "$d" && zip -r "../../zipped_assets/${name}.zip" . )
```

#### Wrong
```bash
# 无 UA → crates.io 回 403；`-f` 又把 403 与 404 混成「失败」
if curl -fsS "https://crates.io/api/v1/crates/rstun/${VERSION}" >/dev/null; then skip=1; fi
cargo publish                      # 发的是 Cargo.toml 的版本，不是 ${VERSION}
```

#### Correct
```bash
ua='rstun-release/1.0 (+https://github.com/exvlan/rstun)'
code="$(curl -sS -o /dev/null -w '%{http_code}' -A "$ua" "https://crates.io/api/v1/crates/rstun/${VERSION}")" || code=000
case "$code" in 200) skip=1 ;; 404) ;; *) exit 1 ;; esac   # 403/5xx 不盲发
[ "$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)" = "$VERSION" ] || exit 1
cargo publish --locked
```

#### Wrong
```yaml
# 用默认分支的头构建，tag 却是另一个提交 → 资产 `+sha6` 与 tag 不符
gh workflow run release.yml -f version="$VERSION"
```

#### Correct
```yaml
gh workflow run release.yml --ref "$TAG" -f version="$VERSION"   # 从 tag 指向的树构建
```

#### Wrong
```bash
# 1) 用 tag 验证镜像：tag 被重新指向后仍然「验过」；
# 2) 身份 regexp 写成 .*（任何人都能冒充），等于没验；
# 3) 拼转义身份：源码里**四反斜杠** `${VERSION//./\\\\.}` 在双引号里产出 `\\.`
#    （正则=「字面反斜杠+任意字符」），连正确身份都匹配不上（实测假红）；
#    **两反斜杠** `${VERSION//./\\.}` 才产出 `\.`（正确的字面点）
cosign verify "ghcr.io/exvlan/rstun:${VERSION}" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp "^https://github\\.com/${REPO//./\\\\.}/\\.github/workflows/release\\.yml@refs/tags/rstun-v${VERSION//./\\\\.}\$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

#### Correct
```bash
# digest 不可变（下游记录的也是它）；身份绑死本仓 release.yml + 该 tag，**逐字**比较（无正则/无转义）
digest="$(docker buildx imagetools inspect "ghcr.io/exvlan/rstun:${VERSION}" |
  sed -n 's/^Digest: *\(sha256:[0-9a-f]\{64\}\)$/\1/p' | head -n1)"
identity="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/rstun-v${VERSION}"
cosign verify "ghcr.io/exvlan/rstun@${digest}" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.bundle \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS   # 签名的哈希清单还要与实际字节对上
```
