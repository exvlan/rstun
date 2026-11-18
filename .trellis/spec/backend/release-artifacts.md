# 发布物契约（Release artifacts）

> 来源：`rstun-v26.410.100` 首发时逐条踩到并实测修正。
> 任何会产出 Release 资产或容器镜像的改动都必须满足本文。

## 1. Scope / Trigger

满足任一条即适用（不是建议）：

- 修改 `.github/workflows/release.yml`（构建 / 打包 / 发布 / 镜像）；
- 重发同一版本（`gh release upload --clobber`）；
- 修改版本注入（`RSTUN_BUILD_VERSION`）或 `Cargo.toml` 的 `version`。

## 2. Signatures（可执行入口）

| 动作 | 命令 |
| --- | --- |
| 触发发布 | `gh workflow run release.yml -R exvlan/rstun -f version=<x.y.z>` |
| 核对资产 | `gh release view rstun-v<version> -R exvlan/rstun --json assets --jq '.assets[]\|{name,size}'` |
| 核对多架构 | `docker buildx imagetools inspect ghcr.io/exvlan/rstun:<version>` |
| 核对 tag 指向 | `gh api repos/exvlan/rstun/git/ref/tags/rstun-v<version> --jq .object.sha` |
| 本地验证资产 | `gh release download … && unzip … && test -x ./rstun && ./rstun --version` |

## 3. Contracts

| 契约 | 规则 | 违反后的现象 |
| --- | --- | --- |
| 资产可执行位 | zip 内 `rstun` / `rstun.exe` 必须 `0755`（打包前 `chmod +x`）| 解压后 `./rstun` → `Permission denied` |
| tag ↔ 资产 ↔ 镜像 | 三者必须对应同一 commit；**不 force 移动已发布 tag**（消费者会拿到不同树）| `--version` 的 `+<sha6>` 与 tag 指向不符 |
| 下游 digest | 对外报 **manifest list digest**（amd64+arm64 index）| 下游按 digest 校验对不上 |
| 版本串 | `version` 输入 == `Cargo.toml` 的 `version`；二进制 `--version` = `<version>+<sha6>` | 包与报的版本不一致 |
| 镜像 | `ghcr.io/exvlan/rstun:<version>`，稳定版附 `:latest`；双架构必须由 manifest 合并 | 单架构冒充双架构 |
| 包可见性 | 新包默认 private：有凭证可拉、匿名 401 | 「我这边能 pull」误判 |
| 动态链接 | linux 目标为 static-pie（musl）| 依赖宿主 glibc 版本 |

## 4. Validation & Error Matrix

| 条件 | 必须的行为 |
| --- | --- |
| 输入 `version` ≠ `Cargo.toml` version | `::error::` 阻断发布 |
| Release 已存在 | 只 `--clobber` 覆盖资产，不移动 tag、不改说明 |
| zip 数为 0 | 失败（禁止空 Release）|
| 镜像缺 amd64 或 arm64 | 发布失败（manifest 不完整）|
| Windows 冒烟/脚本 | 必须 `PYTHONIOENCODING=utf-8`，缺 `python3` 时用 `python` shim |
| 精简 CI 作业 | 本仓无 `.cargo/config.toml` 的链接器强制项；若将来加入（如 mold），需在作业里自装 |

## 5. Good / Base / Bad

- **Good**：打包前 `chmod +x`；发布后真下载执行；双架构 manifest；tag 指向发布提交且不再移动。
- **Base**：CI 内 `--version` 自检 + 容器内 `--version` 自检（必要不充分）。
- **Bad**：只看到 `cargo build` 成功就认为资产可用；把单架构 digest 当双架构；`--clobber` 后不核对 tag。

## 6. Tests Required（断言点）

1. 下载 Release 资产 → `test -x ./rstun` → `./rstun --version` 含 `<version>+<sha6>`。
2. `docker buildx imagetools inspect` 输出含 `linux/amd64` 与 `linux/arm64`。
3. tag 指向的 commit 的 `sha6` 与资产 `--version` 一致。
4. 冒烟：`bash script/ci/rstun-smoke.sh <addr> --tcp` 返回 `0x0101`。
5. 本仓为 public：提交前扫描 `grep -rnE '(生产网段|内部路径)' --exclude-dir=.git .` 为空。

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
