# 发布物契约（Release artifacts）

> 来源：`rstun-v26.410.100` 首发时逐条踩到并实测修正。
> 任何会产出 Release 资产或容器镜像的改动都必须满足本文。

## 1. Scope / Trigger

满足任一条即适用（不是建议）：

- 修改 `.github/workflows/release.yml`（构建 / 打包 / 发布 / 镜像）；
- 修改 `.github/workflows/{release-preflight,post-release-verify}.yml` 或 `script/ci/check-version-pins.sh`；
- 重发同一版本（`gh release upload --clobber`）；
- 修改版本注入（`RSTUN_BUILD_VERSION`）或 `Cargo.toml` 的 `version`。

## 2. Signatures（可执行入口）

| 动作 | 命令 |
| --- | --- |
| 触发发布 | `gh workflow run release.yml -R exvlan/rstun -f version=<x.y.z>` |
| 发版前只读预检 | `gh workflow run release-preflight.yml -R exvlan/rstun -f version=<x.y.z>`（或 Actions → Release preflight）|
| 发布后只读验收 | `gh workflow run post-release-verify.yml -R exvlan/rstun -f version=<x.y.z>`（或 Actions → Post-release verify）|
| 版本钉死点（6 处）| `bash script/ci/check-version-pins.sh [--version <x.y.z>]` |
| 核对资产 | `gh release view rstun-v<version> -R exvlan/rstun --json assets --jq '.assets[]\|{name,size}'` |
| 核对多架构 | `docker buildx imagetools inspect ghcr.io/exvlan/rstun:<version>` |
| 核对 tag 指向 | `gh api repos/exvlan/rstun/git/ref/tags/rstun-v<version> --jq .object.sha` |
| 本地验证资产 | `gh release download … && unzip … && test -x ./rstun && ./rstun --version` |

## 3. Contracts

| 契约 | 规则 | 违反后的现象 |
| --- | --- | --- |
| 资产可执行位 | zip 内 `rstun` / `rstun.exe` 必须 `0755`（打包前 `chmod +x`）| 解压后 `./rstun` → `Permission denied` |
| 作业间产物权限 | `download-artifact` **不保留权限位**（落盘 0644）：任何直接使用下载产物的步骤（zip、deb、冒烟）必须先 `chmod +x`，不要用 `[ -x ]` 当存在性检查 | `::error::missing lean binary …` / `Permission denied` |
| tag ↔ 资产 ↔ 镜像 | 三者必须对应同一 commit；**不 force 移动已发布 tag**（消费者会拿到不同树）| `--version` 的 `+<sha6>` 与 tag 指向不符 |
| 下游 digest | 对外报 **manifest list digest**（amd64+arm64 index）| 下游按 digest 校验对不上 |
| 版本串 | `version` 输入 == `Cargo.toml` 的 `version`；二进制 `--version` = `<version>+<sha6>` | 包与报的版本不一致 |
| 镜像 | `ghcr.io/exvlan/rstun:<version>`，稳定版附 `:latest`；双架构必须由 manifest 合并 | 单架构冒充双架构 |
| deb 资产 | `rstun_<version>_{amd64,arm64}.deb` 各一份（lean、musl static-pie，包内二进制与 lean zip 同源）；缺任一即失败 | 用户装到旧版/异构二进制 |
| Homebrew tap | `exvlan/homebrew-rstun` 的 formula 与该 Release 的 `rstun.rb` 类体一致 | `brew install` 拉到不存在的 sha256 |
| 包可见性 | 新包默认 private：有凭证可拉、匿名 401 | 「我这边能 pull」误判 |
| 动态链接 | linux 目标为 static-pie（musl）| 依赖宿主 glibc 版本 |
| full 构建的 C 工具链 | Linux musl 目标必须装 `musl-tools` 且设 `CC_<triple>=musl-gcc`（full 的 `ring` 含 C 代码）| `cc-rs: failed to find <triple>-musl-gcc`，构建 exit 101 |
| 发版前预检 | **发布前必须 `release-preflight.yml` 全绿**（pins / tests+clippy+fmt / interop all / TURN lean+full（含 frozen）/ SBOM / deb / brew 渲染 / `cargo publish --dry-run`）；只读、无 secret | 发版当天才发现打包或协议回归 |
| 发布后验收 | **发布后必须 `post-release-verify.yml` 全绿**：13 资产命名、四平台 zip 架构、`--version` 含 `<version>` 且 `+sha6` == tag 指向提交、两个 deb 的 Version/Architecture、tap formula 类体 + 3 个 sha256、镜像 amd64+arm64 manifest；只读，`packages: read` 只为私有 ghcr 登录 | 「流水线绿了但用户下载到坏资产」 |
| 版本钉死点 | `Cargo.toml` 的 `version` 必须同时等于 6 处：README「已发布」、`docs/book/src/docker.md`、`contrib/k8s/deployment.yaml`、`contrib/docker/compose.yaml`、`contrib/helm/{Chart,values}.yaml`；`script/ci/check-version-pins.sh`（CI `version-pins` 作业）守 | 文档说 A、镜像示例说 B（拉镜像 404）|
| crate 打包预检 | CI `packaging` 作业：`cargo package --list` 断言不含 `fuzz/` `tests/` `.github/` `.trellis/` `.env`，版本与 `cargo metadata --locked` 一致，且 `cargo publish --dry-run` 通过 | 发版时才发现 crate 包混进夹具/密钥 |

## 4. Validation & Error Matrix

| 条件 | 必须的行为 |
| --- | --- |
| 输入 `version` ≠ `Cargo.toml` version | `::error::` 阻断发布 |
| Release 已存在 | 只 `--clobber` 覆盖资产，不移动 tag、不改说明 |
| zip 数为 0 | 失败（禁止空 Release）|
| 镜像缺 amd64 或 arm64 | 发布失败（manifest 不完整）|
| Windows 冒烟/脚本 | 必须 `PYTHONIOENCODING=utf-8`，缺 `python3` 时用 `python` shim |
| 精简 CI 作业 | 本仓无 `.cargo/config.toml` 的链接器强制项；若将来加入（如 mold），需在作业里自装 |
| TLS 握手探针 | 必须「先落盘再 `grep`」；`pipefail` 下 `openssl s_client \| grep -q` 会因 grep 命中即退出让 openssl 收 SIGPIPE，握手成功也判失败 |

## 5. Good / Base / Bad

- **Good**：打包前 `chmod +x`；发布后真下载执行；双架构 manifest；tag 指向发布提交且不再移动；
  发版前 `release-preflight` 全绿、发布后 `post-release-verify` 逐项 PASS。
- **Base**：CI 内 `--version` 自检 + 容器内 `--version` 自检（必要不充分）。
- **Bad**：只看到 `cargo build` 成功就认为资产可用；把单架构 digest 当双架构；`--clobber` 后不核对 tag；
  版本号只改 `Cargo.toml` 不改 6 处钉死点。

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
8. `post-release-verify.yml` 对已发布版本全绿（当前基线 `26.410.104`）；传不存在的版本 → 资产步骤
   明确报 `Release rstun-v... 不存在` 并红。
9. 两个新 workflow 必须 `yaml.safe_load` 通过、action 全 40 位 SHA、`permissions` 只有
   `contents: read`（post-release-verify 额外 `packages: read`，用于私有 ghcr 只读登录）。

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
