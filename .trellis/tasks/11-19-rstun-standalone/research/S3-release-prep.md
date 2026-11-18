# S3（独立发布）预检 — 现状与缺口

> 生成：2026-11-19 · 主会话只读预检（T1 收尾期间）
> 依据：`prd.md` S3、`implement.md` 3.1–3.5、`.github/workflows/rstun.yml`、`script/ci/rstun-publish.sh`、`rstun/Cargo.toml`

## 1. 现状（能用的部分）

| 能力 | 位置 | 状态 |
| --- | --- | --- |
| 手动发版入口（`workflow_dispatch`） | `.github/workflows/rstun.yml` | ✅ 不进 pipeline 依赖链 |
| 版本校验与 tag 派生（`rstun-v<version>`） | `rstun.yml` `prepare` | ✅ 正则接受 `YY.QMM.Mmpp[-channel.n]` |
| 四平台二进制（linux x86_64/aarch64 musl、win x86_64、mac x86_64） | `rstun.yml` `build` | ✅ 各平台带冒烟（mac 只编译） |
| Release 资产 `rstun-<platform>-<version>.zip` | `rstun.yml` `release` | ✅ 带 `rstun-` 前缀，避免与内核包撞名 |
| 镜像 `ghcr.io/<owner>/rstun:<version>`（稳定版加 `latest`） | `rstun.yml` + `script/ci/rstun-publish.sh` | ✅ 单架构（linux/amd64） |
| 冒烟门禁（native + 容器各发 20 字节 Binding） | `script/ci/rstun-smoke.sh` | ✅ |

## 2. 缺口（按 implement.md 3.x 对齐）

| # | 缺口 | 影响 | 建议动作 |
| --- | --- | --- | --- |
| **G1** | **crates.io 首发没有实现**（`rstun.yml` 无 `cargo publish`，脚本里也没有） | 3.4 无法验收 | 在 `rstun.yml` 加 `publish_crate` 作业（`workflow_dispatch` 输入 `push_crate`，`cargo publish --locked`，需 `CARGO_REGISTRY_TOKEN` secret 或 trusted publishing）；先 `cargo package --list` + `cargo publish --dry-run` |
| **G2** | **arm64 镜像缺失**（`rstun-publish.sh` 头注释明确「单架构；arm64 另开任务」） | 3.3 无法验收 | 两条路：① 复用 `ubuntu-24.04-arm` runner 构建 arm64 镜像并推 `:version-arm64`，再 `docker manifest create`；② buildx + QEMU 一次出双架构（慢）。推荐 ① |
| **G3** | `cargo package` 会带上 `test/interop/**`（3 文件：pion main.go、webrtc-stun 2 文件） | 包体噪音；不影响构建 | `rstun/Cargo.toml` 加 `exclude = ["fuzz/**", "test/**"]`（fuzz 目前已被 cargo 自动排除，仍显式写） |
| **G4** | **crates.io 名称可用性未验证** | 名称被占则首发要改名（连锁改 README/镜像/tag） | 本机网络把 `crates.io` 解析到 `198.18.4.255`（代理私有段），`fetch` 被拒；改在有公网访问的机器上 `curl -s https://crates.io/api/v1/crates/rstun` 确认。**这是 S3 的第一个门** |
| **G5** | crate 内 `version = "26.410.20715"`，首发要 `26.410.100` | 二进制 `--version` 与 crate 版本不一致（`rstun.yml` 用 `EXVLAN_BUILD_VERSION_OVERRIDE` 注入只改 `--version`，不改 crate 元数据） | 改 `rstun/Cargo.toml` `version` + 重生成 `Cargo.lock`；确认 `AGENTS.md`「版本对齐范围」里 rstun 的例外条款已写明（已有） |
| **G6** | `prepare` 只校验格式，不校验「输入版本 == crate 版本」 | 可能发出 `-v26.410.100` 的包但 crate 元数据是旧版 | `prepare` 增加一步：`cargo metadata -p rstun` 取 version，与输入不一致则 `::error::` 阻断（除非显式 `allow_mismatch`） |
| **G7** | 拆独立仓（3.5）没有任何脚手架 | 迁移成本后置会变大 | 先在任务内定「仓库名 / 是否保留 monorepo 兼容期 / 镜像与 Release 归属」；拆仓后消费方按镜像 digest 固定（prd R4） |
| **G8** | `rstun.yml` 的 `concurrency` 用 `rstun-${{ inputs.version }}` | 同版本重复 dispatch 排队而非取消（这是对的） | 无动作，记录以免后续误改 |

## 3. 建议执行顺序（S3）

1. **G4** 名称确认（外部网络）→ 不行就改名，越早越好。
2. **G5 + G6** 版本线与一致性门（纯仓库内改动，可本地全验）。
3. **G1** crates.io 作业 + `--dry-run` 本地验证；首发建议走 **D2 选项 A（prerelease/draft）**。
4. **G2** arm64 镜像（先单架构发布可用，再补双架构）。
5. **G3** 包体收敛（顺手）。
6. **G7** 拆仓（放最后，且需用户确认；S4 生产切换不依赖拆仓）。

## 4. 与 S4 的关系

S4 只依赖「镜像已发布 + `rstun server` 子命令」，**不依赖** crates.io、不依赖双架构、不依赖拆仓。
因此若 G1/G2/G7 拖长，可先发单架构镜像 + 四平台 zip 完成 S4，再补其余。
