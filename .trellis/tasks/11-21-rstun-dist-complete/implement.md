# 执行计划：tap + deb

> 顺序：先仓内（workflow + 文档）→ 本地验证 → 外部动作（建 tap、补 deb 资产）→ 记账。

## 1. 仓内改动

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | `release.yml`：build 作业加「Build Debian package (lean)」+「Upload deb artifact」（仅 linux 行）| `python3 -c "import yaml;..."` 解析通过 |
| 1.2 | `release.yml`：release 作业下载 `deb-*`、资产断言 8+2+1+2=13、`assets=(...)` 含 deb | 同上；人工核对数组 |
| 1.3 | release notes 增加 deb 两行（amd64/arm64 + `dpkg -i` 用法）| 人工评审 |
| 1.4 | `README.md` / `docs/book/src/quickstart.md`：brew/deb 改成可照抄命令 | `script/ci/check-docs.sh` |
| 1.5 | `.trellis/spec/backend/release-artifacts.md`：13 资产、deb 契约、tap 同步约定 | 人工评审 |

## 2. 本地验证（不依赖 CI）

```bash
# lean 二进制（已发布的 zip 内那份，直接取）
gh release download rstun-v26.410.102 -p 'rstun-linux-x86_64-*.zip' -p 'rstun-linux-aarch64-*.zip' -D /tmp/deb-src --clobber
# 解包 + 打包 amd64 / arm64
bash script/ci/build-deb.sh --download-nfpm --version 26.410.102 --arch amd64 --bin /tmp/deb-src/amd64/rstun --out /tmp/deb-out
bash script/ci/build-deb.sh --download-nfpm --version 26.410.102 --arch arm64 --bin /tmp/deb-src/arm64/rstun --out /tmp/deb-out
# 断言
dpkg-deb -I /tmp/deb-out/*amd64.deb | grep -E 'Package|Version|Architecture'
dpkg-deb -c /tmp/deb-out/*amd64.deb | grep -E '/usr/local/bin/rstun|systemd'
dpkg-deb -x /tmp/deb-out/*amd64.deb /tmp/deb-x && /tmp/deb-x/usr/local/bin/rstun --version
sha256sum /tmp/deb-out/*.deb
```

断言：包内 `--version` 与 Release 同串；amd64 包内二进制架构 x86_64、arm64 包内 aarch64。

## 3. 外部动作（已获用户批准）

| # | 动作 | 验证 |
| --- | --- | --- |
| 3.1 | `gh repo create exvlan/homebrew-rstun --public` | `gh repo view` 可见 |
| 3.2 | 推送 `Formula/rstun.rb`（= Release `rstun.rb`）+ `README.md` | `gh api .../contents/Formula/rstun.rb` 与 Release 资产逐字节一致 |
| 3.3 | formula sha256 与 Release zip 实测一致 | 三个平台逐条比对 |
| 3.4 | `gh release upload rstun-v26.410.102 <2 deb> --clobber` | `gh release view --json assets` → 13 个 |
| 3.5 | tag 未移动 | `gh api repos/.../git/ref/tags/rstun-v26.410.102 --jq .object.sha` 与发版提交一致 |

## 4. 收尾

- `implement.md` 追加执行记录（外部动作、资产清单、sha256）；
- 提交（只含仓内文件；tap 仓内容不复制进主仓）；
- 归档本任务；父任务 `11-19-rstun-complete` 进度 +1。

## 回滚点

- 1.1–1.3 一个 commit；revert 即恢复 11 资产口径。
- 3.1 tap 仓可删（需再次确认）；3.4 deb 资产可 `gh release delete-asset`。

## 执行记录（2026-11-21，主会话）

### 仓内改动

| 项 | 结果 |
| --- | --- |
| `release.yml` | release 作业统一打 2 个 deb（x86_64 runner 上用 nfpm 跨架构打包，arm64 传 `--foreign-bin`）；资产断言 8 zip + 2 SBOM + 1 rb + 2 deb = **13**；release notes 增加 brew/deb 用法 |
| `build-deb.sh` | 新增 `--foreign-bin`（跨架构打包时跳过执行二进制做版本自检，仅用于可信发布物）；用法注释同步 |
| `README.md` / `quickstart.md` | brew 指向 tap 仓；deb 指向 Releases（amd64/arm64），资产数 11 → 13 |
| specs | `distribution.md`（13 资产、deb 位置、`--foreign-bin`、tap 同步约定）、`release-artifacts.md`（deb/tap 契约）|

> 设计修正：原计划在 build 作业（arm64 runner）里打包，但 `build-deb.sh --download-nfpm` 的下载 URL
> 写死 `Linux_x86_64`，arm64 runner 会拿到 x86_64 的 nfpm。改为在 release 作业（x86_64）统一打包。

### 本地验证

```text
rstun_26.410.102_amd64.deb  sha256 f478d427097e4db0954f7f27c8ed0127b218930f8b56e0c87a85b28f0e7f44ca
rstun_26.410.102_arm64.deb  sha256 94a6183c0afaa64bc9b2945a70f6e6274b1156e915ccc5437b52f46543b5c5ed
dpkg-deb -I  → Package: rstun / Version: 26.410.102 / Architecture: amd64|arm64
dpkg-deb -c  → ./usr/local/bin/rstun、./lib/systemd/system/rstun.service
包内二进制 sha256 == 已发布 zip 内二进制（amd64 213a31f6… / arm64 5e738daa…）
解包执行 ./usr/local/bin/rstun --version → rstun 26.410.102+e0a16c
```

### 外部动作（已获用户批准）

| 动作 | 结果 |
| --- | --- |
| `gh release upload rstun-v26.410.102 <2 deb> --clobber` | Release 资产 **13** |
| `gh repo create exvlan/homebrew-rstun --public` | 已创建（PUBLIC，默认分支 `main`）|
| 推送 `Formula/rstun.rb` + `README.md` | 远端 Formula 与 Release `rstun.rb` 的类体 **逐字节一致** |
| formula sha256 | 与 Release 三个 lean zip 实测值逐条一致；`ruby -c` → `Syntax OK` |
| tag | 未移动（`rstun-v26.410.102` 仍指向发版提交）|

> 说明：本次 deb 由**已发布 lean zip** 内的二进制打包（不重跑流水线，避免镜像 digest 变化让对端手里的
> `62c766ad…` 失效）。下次发版由 `release.yml` 自动产出同样的两个 deb。
