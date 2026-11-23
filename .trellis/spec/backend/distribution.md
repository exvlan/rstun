# 分发契约（文档站 / 打包 / 社区 / 供应链）

> 来源：2026-11-20 `rstun-dist`。冷复核修掉了 4 处（`rate-limit.md` 与实现矛盾、`build-deb.sh` 的 musl
> 架构 glob 永不命中、`docs.yml` 漏 `CHANGELOG.md` 路径、SBOM 依赖图不完整）。
> 任何改动文档站、打包脚本、`deny.toml`、`docs.yml`、SBOM 生成的提交都必须满足本文。

## 1. Scope / Trigger

- 修改 `docs/book/**`、`README.md` 的行为表、`script/ci/{check-docs,build-deb,gen-brew,gen-sbom}.sh`、
  `contrib/{deb,homebrew}/**`、`deny.toml`、`.github/workflows/docs.yml`、release 的 SBOM 步骤。

## 2. Signatures

| 入口 | 契约 |
| --- | --- |
| `check-docs.sh` | 扫描 `docs/book/src/**` + 仓库根 `*.md`；比对 ① `rstun --help` 片段（**逐 token**，避免 clap 折行假红）② `--flag` 名存在 ③ `rstun_*` 指标名存在 ④ 链接与跨章锚点 |
| `build-deb.sh` | 版本必须等于 `Cargo.toml`；架构映射 **amd64→`x86_64-unknown-linux-musl`**、arm64→`aarch64-…`；musl 缺失时回退 glibc **并警告**（动态链接需 libc6 约束）|
| `build-deb.sh --foreign-bin` | 跨架构打包时跳过「执行二进制做版本自检」（仅用于二进制来自可信发布物，如 Release 的 zip；调用方必须核对 sha256）|
| deb 产物位置 | Release 资产 `rstun_<version>_{amd64,arm64}.deb`，由 `release.yml` 的 Linux 构建作业产出（lean、musl static-pie）；补历史版本时可从已发布 zip 打包，**不重跑流水线**（避免镜像 digest 变化）|
| Homebrew tap | `exvlan/homebrew-rstun` 的 `Formula/rstun.rb` 必须与同版本 Release 的 `rstun.rb` 类体一致（sha256 对得上）；每版发版后人工同步（`gen-brew.sh` 产物覆盖）|
| `gen-brew.sh <version> <sha256...>` | 只取 3 个 lean zip（`rstun-<platform>-<version>.zip`）；full 前缀 `rstun-full-` 不得误匹配 |
| `gen-sbom.sh --features lean\|full --out <path>` | CycloneDX 1.5；组件含 `type/name/version/bom-ref/purl/licenses`；`dependencies` 为**全可达图**、无悬空 ref |
| `deny.toml` | `licenses` 显式允许清单；`bans.wildcards=deny`；`multiple-versions=warn`；advisories 交由 `cargo audit`（`unmaintained=none`）|

## 3. Contracts

| 主题 | 规则 |
| --- | --- |
| 行为表唯一真源 | `docs/book/src/protocol.md`；README 只留 3–6 行摘要 + 链接。**禁止两处维护**（相同表格行 = 0）|
| 文档站触发 | `docs.yml` 的 `paths` 必须含 `docs/book/**`、`README.md`、**`CHANGELOG.md`**（changelog 页 `{{#include}}`）、自身 |
| Pages 权限 | 工作流级 `contents: read`；deploy 作业 `pages: write` + `id-token: write`；action 固定 SHA |
| 包范围 | 只发 **lean** 的 brew/deb；full 走 Release `rstun-full-*` 与镜像（避免同版本两个包）|
| deb 安装路径 | 二进制 `/usr/local/bin/rstun`（**有意选择**：不覆盖发行版包管理器；代价是 lintian E 级，已在 `contrib/README.md` 说明）|
| deb 服务 | unit 在 `/lib/systemd/system/rstun.service`；postinst 幂等、不 `rm -rf`、无 systemd 时不起服务；preremove 只 `daemon-reload`（不 stop，升级由 systemd 处理）|
| SBOM | 随 Release 上传（lean/full 各一份）；**内容不含 hashes/签名**（签名以独立 `<file>.bundle` 随 Release 提供，`SHA256SUMS` 覆盖其哈希）；`components` 含 build/proc-macro 闭包，**不是运行期 crate 数** |
| 资产数量 | 13 个核心资产（8 zip + 2 cdx + 1 rb + 2 deb）必须齐全，缺 SBOM/deb 直接失败；keyless 签名（`11-23-rstun-cosign`）再加 `SHA256SUMS` + 3 个 `.bundle` = **17**（`sign=false` 时 13）|
| 供应链门禁 | `cargo audit` 与 `cargo deny` **都**是必需作业（`deny` 无 `continue-on-error`）；豁免清单两处同步：`.cargo/audit.toml` 与 `deny.toml`，只 ignore `RUSTSEC-2026-0387` |

## 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| 文档里 `--flag` 不存在 / help 片段与真实输出不一致 / 链接或锚点失效 | `check-docs.sh` exit 1 |
| 行为表**删一整行** | `check-docs.sh` **不报**（已知限制；真值由冻结测试 + 三套 lab 锁实现）。不得用行数断言替代 |
| 散文里的默认值写错（不在 help 块内） | 无自动守卫（人工核对；当前已逐项核对正确）|
| 版本与 `Cargo.toml` 不一致 | `build-deb.sh` / `gen-brew.sh` exit 1 |
| musl 产物缺失 | 回退 glibc 并打 3 行警告；**发布前必须确认走 musl** |
| SBOM 缺组件/悬空 ref | 生成脚本自检失败 |
| Release 资产 ≠ 13（未签名）/ 17（已签名）（或 deb ≠ 2）| release 作业 `::error::` |

## 5. Good / Base / Bad

- **Good**：行为表单一副本 + `check-docs` 守 help/参数/指标/链接；deb 走 musl 并校验；SBOM 全图。
- **Base**：只 `mdbook build` 成功就当文档没问题。
- **Bad**：`target/${ARCH}*-unknown-linux-musl` 这类 glob（`amd64*` 永不匹配，静默打出 glibc 包）；两处维护行为表。

## 6. Tests Required（断言点）

1. `check-docs.sh` 正例 exit 0；**反证**：改一个 `--flag`、改 help 默认值、改 README→docs 链接、改跨章锚点 → 各 exit 1。
2. `mdbook build docs/book` 成功；`book/` 在 `.gitignore`。
3. `cargo deny check` 四项 ok；`cargo audit` exit 0。
4. `build-deb.sh`：版本不符 exit 1；`dpkg -c` 权限正确；`systemd-analyze verify` ok。
5. `gen-brew.sh`：`ruby -c` 通过；版本/资产缺失负例 exit 1。
6. `gen-sbom.sh`：`--features lean|full --out …` 产物符合 CycloneDX 1.5，`dependencies` 无悬空。
7. workflow/template YAML 可解析；action SHA 全 40 位且与注释版本一致。

## 7. Wrong vs Correct

#### Wrong
```bash
# 架构变量直接拼进 target 三元组：amd64* 永不匹配
BIN="target/${ARCH}*-unknown-linux-musl/release/rstun"
```
```python
# SBOM 只写 root→direct 一条边：其余组件没有入边
dependencies = [{"ref": root, "dependsOn": [direct]}]
```

#### Correct
```bash
case "$ARCH" in
  amd64) TRIPLE=x86_64-unknown-linux-musl ;;
  arm64) TRIPLE=aarch64-unknown-linux-musl ;;
esac
BIN="target/${TRIPLE}/release/rstun"
```
```python
# BFS 全可达图，保留 normal 边，废弃悬空 ref
```
