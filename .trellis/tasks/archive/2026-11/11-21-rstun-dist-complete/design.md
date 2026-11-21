# 设计：tap + deb 落地

## 1. `.deb` 的两种产生方式

### 1.1 当前版本（26.410.102）补资产：不重跑发布流水线

重跑 `release.yml` 会重建镜像 → **digest 变化**，而对端刚拿到 `sha256:62c766ad…`，重发会使其失效。
因此本版本采用「从已发布 zip 取二进制」：

```bash
# 1) 取已发布的 lean 二进制（与 zip 完全同源）
gh release download rstun-v26.410.102 -p 'rstun-linux-x86_64-*.zip' -p 'rstun-linux-aarch64-*.zip' -D /tmp/deb-src
unzip -o .../rstun-linux-x86_64-26.410.102.zip -d /tmp/deb-src/amd64
unzip -o .../rstun-linux-aarch64-26.410.102.zip -d /tmp/deb-src/arm64

# 2) nfpm 打包（nfpm 与宿主架构无关，可交叉打包 aarch64 的 deb）
bash script/ci/build-deb.sh --download-nfpm --version 26.410.102 \
  --arch amd64 --bin /tmp/deb-src/amd64/rstun --out /tmp/deb-out
bash script/ci/build-deb.sh --download-nfpm --version 26.410.102 \
  --arch arm64 --bin /tmp/deb-src/arm64/rstun --out /tmp/deb-out

# 3) 只补资产，不动 tag/说明
gh release upload rstun-v26.410.102 /tmp/deb-out/*.deb --clobber
```

### 1.2 以后每次发布：`release.yml` 自动产出

在 `build` 作业的 Linux 行（`matrix.smoke == 'linux'`）里，`Stage lean artifact` 之后增加：

```yaml
- name: Build Debian package (lean)
  if: matrix.smoke == 'linux'
  run: |
    set -euo pipefail
    case "${{ matrix.name }}" in
      linux-x86_64) DEB_ARCH=amd64 ;;
      linux-aarch64) DEB_ARCH=arm64 ;;
      *) echo "::error::unexpected linux matrix entry"; exit 1 ;;
    esac
    bash script/ci/build-deb.sh --download-nfpm \
      --version "${{ needs.prepare.outputs.version }}" \
      --arch "$DEB_ARCH" --bin ./artifacts/lean/rstun --out ./artifacts/deb
    ls -l ./artifacts/deb

- name: Upload deb artifact
  if: matrix.smoke == 'linux'
  uses: actions/upload-artifact@...# v7
  with:
    name: deb-${{ matrix.name }}
    path: ./artifacts/deb
    if-no-files-found: error
    retention-days: 14
```

`release` 作业：

- `needs` 增加 deb 依赖（build 已在 needs 里）；
- 新增 `Download debs`（`pattern: deb-*`, `merge-multiple: true` → `deb_assets/`）；
- 资产断言：zip 8 + SBOM 2 + formula 1 + deb 2 = **13**；
- `assets=(...)` 增加 `deb_assets/*.deb`；
- release notes 增加一行 deb 资产名与 `dpkg -i` 用法。

> 注意：deb 在 build 作业里打包，`--bin ./artifacts/lean/rstun` 指向**未 strip 的 lean release 构建**
> （musl static-pie），与 zip 内二进制同源；nfpm 不需要目标架构工具链。

## 2. Homebrew tap

- 仓库名必须 `/^homebrew-/` 前缀，`exvlan/homebrew-rstun` → formula 引用路径 `exvlan/rstun/rstun`。
- 内容：
  - `Formula/rstun.rb`：**直接沿用** Release 资产 `rstun.rb`（`gen-brew.sh` 生成，sha256 已对齐 zip）。
  - `README.md`：三行（install / upgrade / uninstall）+ 指向主仓。
- 流程：`gh repo create exvlan/homebrew-rstun --public --description ...` → clone/init → commit → push。
- 后续版本同步：仍是人工（`gen-brew.sh` 产物覆盖 tap 的 formula）。在 spec 里写明。

## 3. 文档

| 文件 | 改动 |
| --- | --- |
| `README.md` | 安装表：brew = `brew install exvlan/rstun/rstun`；deb = `dpkg -i` + Release 链接 |
| `docs/book/src/quickstart.md` | 同上，两条路径改成可照抄命令 |
| `.trellis/spec/backend/release-artifacts.md` | 资产 13；deb 契约（lean、musl、dpkg 校验）；tap 同步约定 |

## 4. 回滚

- tap：`gh repo delete exvlan/homebrew-rstun`（需用户再次确认）或 revert 文件。
- deb 资产：`gh release delete-asset rstun-v26.410.102 <name>`。
- workflow 改动：单 commit revert。

## 5. 风险

| R | 缓解 |
| --- | --- |
| nfpm 下载失败（离线） | 本地已有 `target/ci-tools` 缓存；CI 用固定版本 + sha256 校验 |
| aarch64 deb 里混入 x86_64 二进制 | `build-deb.sh` 已有 `file` 架构一致性检查（`--arch arm64` vs 二进制）|
| tap 推送触发误以为改了主仓 | tap 是独立仓，主仓只加文档；不引用 git submodule |
| 资产数断言写死 13 | 与 workflow 的断言、spec、release notes 三处同步维护 |
