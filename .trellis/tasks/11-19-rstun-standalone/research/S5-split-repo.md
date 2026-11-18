# S3/S5 拆仓与首发（已完成）

> 2026-11-19 · `rstun` 从 monorepo 拆为独立公开仓并首发 `rstun-v26.410.100`

## 1. 结论

| 项 | 值 |
| --- | --- |
| 新仓 | https://github.com/exvlan/rstun （public，默认分支 `main`，MPL-2.0）|
| 首发 tag | `rstun-v26.410.100`（非 prerelease）|
| 镜像 | `ghcr.io/exvlan/rstun:26.410.100`（另 `:latest`）|
| manifest digest | `sha256:9d7382c619efe6b21d5b672c7811715b562bf6051b5d0f9ba4ee979f508df0bd`（amd64 + arm64，终版）|
| tag → commit | `rstun-v26.410.100` → `7ce862a6`（与实际构建资产的提交一致；`main` 另有 1 个纯 fmt 提交 `6f3f7905`）|
| 资产 | `rstun-{linux-x86_64,linux-aarch64,macos-x86_64,windows-x86_64}-26.410.100.zip` |
| Exvlan 侧 | `rstun/**`、`rstun.yml`、matrix 项、`script/ci/rstun-*` 由原会话**单提交**清理（本任务不删）|

## 2. 做法

1. `git subtree split --prefix=rstun -b rstun-split`（保留 1977 条历史）→ worktree `/tmp/opencode/rstun-repo`。
2. **安全审查后决定不公开抽取历史**：历史里含生产 EIP / 私网 IP / 内部文档引用；改为单一初始提交，
   并把工作树里的生产网段统一替换为 TEST-NET（`203.0.113.0/24`、`192.0.2.0/24`）。
3. 新仓工程化：`version = 26.410.100`、`exclude = fuzz/test/.github`、`Dockerfile` context 改根、
   版本注入改 `RSTUN_BUILD_VERSION`、`ci.yml`（三平台）/ `release.yml`（四目标 + 双架构 manifest）、
   `CHANGELOG.md`、`docs/interop-matrix.md`（T1 报告副本）。
4. `gh repo create exvlan/rstun --public` → push `main` → dispatch `release.yml version=26.410.100`。

## 3. 本轮发现并修复的缺陷

| # | 现象 | 根因 | 修复 |
| --- | --- | --- | --- |
| 1 | 解压后 `./rstun` 报「权限不够」 | `upload-artifact`/`download-artifact` 不保留权限位 | 打包前 `chmod +x`（`7ce862a6`）→ 实测 `-rwxr-xr-x` |
| 2 | 新仓 CI Ubuntu fmt 红 | IP 脱敏后行宽变化未重排 | `cargo fmt`（`6f3f7905`）|

## 4. 验证结果（2026-11-19）

| 项 | 结果 |
| --- | --- |
| 新仓 CI（run 44384621608，`main`@6f3f7905） | **9/9 全绿**：test ×3（ubuntu/macos/windows）+ smoke udp+tcp ×3 + smoke ipv6 ×3 |
| 原 monorepo CI（迁移前，run 44378708072） | `Test (rstun)` + `rstun matrix` ×3 **全绿**（alt-listen 多地址改动在旧仓 CI 上也通过）|
| 4 个 zip 可执行位 | 逐个解压实测：`-rwxr-xr-x`（linux x86_64 / aarch64、macOS、`rstun.exe`）|
| 资产自检 | `rstun 26.410.100+7ce862`，`static-pie linked`，UDP/TCP 冒烟绿 |
| 镜像 | manifest list 含 linux/amd64 + linux/arm64；`:latest` 同 |

## 5. 未完成 / 阻塞项

| # | 项 | 影响 | 处置 |
| --- | --- | --- | --- |
| ~~B1~~ | ~~ghcr 包默认 private~~ | **不阻塞**：发布机 sg 已有 ghcr 凭证（littlezo，2026-11-17），`podman pull` 实测成功（`sha256:9d7382c6…`）| 保持 private 即可；将来要匿名 pull 再改网页 |
| B2 | crates.io 未发布（本次范围外） | `cargo install rstun` 不可用 | 名称可用性需在可访问网络确认后再发 |
| B3 | macOS x86_64 只编译未执行 | 未在 Intel/Rosetta 上实跑 | 首发接受（同 Exvlan 旧约定），后续补 |
| B4 | Windows IPv6 冒烟只告警 | runner 能力差异 | 沿用；Linux/macOS 硬失败已覆盖 |

## 6. 复现命令

```bash
# 复现发布（新仓）
gh workflow run release.yml -R exvlan/rstun -f version=26.410.100

# 核验
gh release view rstun-v26.410.100 -R exvlan/rstun
docker buildx imagetools inspect ghcr.io/exvlan/rstun:26.410.100
gh release download rstun-v26.410.100 -R exvlan/rstun -p 'rstun-linux-x86_64-*.zip'
unzip -o rstun-linux-x86_64-26.410.100.zip && ./rstun --version
```

## 7. 本地收尾

- Exvlan 仓的临时分支 `rstun-split` 与 worktree `/tmp/opencode/rstun-repo` 在确认新仓稳定后清理：
  `git worktree remove /tmp/opencode/rstun-repo && git branch -D rstun-split`。
- 注意：worktree 的 `rstun` remote 指向新仓，清理前先确认 `main` 已推送（已推）。
