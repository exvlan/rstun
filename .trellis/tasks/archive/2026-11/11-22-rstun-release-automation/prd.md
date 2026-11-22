# 发布与回归自动化（P0 预检/校验 + P1 全自动发布）

## 背景

`26.410.104` 的发布仍靠手工 10 步（bump → 门禁 → commit → dispatch → `cargo publish` → 核对资产/digest/deb
→ 同步 6 处版本钉死点 → 同步 tap → 通告 → 归档）。本会话实际踩到：

| 事件 | 次数 |
| --- | --- |
| 版本钉死点（README / docker.md / k8s / compose / helm×2）手工漂移 | 每次发版 |
| 发版前手工跑 interop/turn/frozen | 每次发版 |
| 资产/deb/tap sha 人肉核对 | 每次发版 |
| 发布流水线因环境/脚本缺陷失败后修（musl、pipefail、artifact 权限） | 3 次 |

用户已确认：**做 P0 + P1，且 crates.io 完全自动发布**（不逐次人工批准）。
凭据来源：工作区 `.env.secret`（cargo token，已在 `.gitignore`）；tap 同步**不需要 PAT**（改为 tap 仓反向拉取）。

## 范围

### P0 · 零密钥、零外部写

1. **版本钉死点检查**：`script/ci/check-version-pins.sh` + CI 作业。
   `Cargo.toml` 的 `version` 必须与 README「已发布」、`docs/book/src/docker.md` 镜像示例、
   `contrib/k8s/deployment.yaml`、`contrib/docker/compose.yaml`、`contrib/helm/{Chart,values}.yaml` 一致。
2. **打包预检**：CI 增加 `packaging` 作业：`cargo package --list`（断言不含 `fuzz/`、`tests/`、`.github/`、`.trellis/`）
   + `cargo publish --dry-run`。
3. **release-preflight**（`workflow_dispatch(version)`）：跑 interop/turn(lean+full)/frozen +
   `gen-sbom`/`gen-brew`/`build-deb`（本地，不上传）+ `cargo publish --dry-run`，输出清单与结论。
4. **post-release-verify**（`workflow_dispatch(version)`）：下载 Release 资产验 `--version`/架构、
   `dpkg-deb -I`、比对 tap formula 的 sha256、确认镜像 digest 存在；结果写 run summary。

### P1 · 全自动发布

5. **release 内自动 `cargo publish`**：新作业 `publish-crates`，读仓库 secret `CARGO_REGISTRY_TOKEN`；
   **幂等**：先查 `https://crates.io/api/v1/crates/rstun/<version>`，已存在则跳过（避免重跑失败）。
6. **tap 反向同步**（不需要 PAT）：在 `exvlan/homebrew-rstun` 加 `sync.yml`（每日 cron + 手动），
   用 tap 自己的 `GITHUB_TOKEN` 读 `exvlan/rstun` 最新 Release，下载 `rstun.rb`，内容变化则提交。
7. **release-prep**（`workflow_dispatch(version)`）：一次性完成 bump（`Cargo.toml`/`Cargo.lock`/CHANGELOG
   `## Unreleased` → 版本 + 6 处钉死点）→ commit → push → tag `rstun-v<version>` → dispatch `release.yml`。
   保留手工 dispatch 作为逃生口。

## 非目标

- 不做 Dependabot 主版本自动合并（本会话 5 个主版本跳变全失败）；
- 不做 cosign/sigstore 签名（后置项，需先定密钥/OIDC 策略）；
- 不做「自动对外通告」（对端消息仍由主会话起草、用户确认）；
- 不自动改动 `main` 之外的仓库（tap 仓的改动单独交付，不由主仓工作流写）。

## 约束（硬）

- **凭据不落库**：`CARGO_REGISTRY_TOKEN` 只作为仓库 secret；脚本/文档中不得出现 token 值；
  `.env.secret` 保持 gitignore。
- 自动 publish 必须**幂等**（重跑同一版本不红）；Release 重跑仍不移动 tag。
- P0 的一切作业只读（不 publish、不 push、不建 Release）。
- 所有新 workflow 的 action 必须锁 40 位 SHA（与现有约定一致）；
  YAML 必须 `yaml.safe_load` 通过；`permissions` 最小化。
- tap 仓的 `sync.yml` 只写它自己仓库。
- 不改变已验证的产物口径（13 资产、双架构 digest、deb 同源）。

## 验收

- [ ] 人为把 README 的「已发布」版本改成旧值 → `check-version-pins` 失败；改回即绿
- [ ] 打包预检：在 `Cargo.toml` 加一个 `[package] exclude` 破坏打包 → 作业失败
- [ ] preflight 对当前 `main` 全绿并输出清单
- [ ] post-release-verify 对 `26.410.104` 全绿（含 deb、tap sha、digest）
- [ ] release 重跑同一版本：`publish-crates` 跳过（不红），Release 资产 `--clobber`
- [ ] tap `sync.yml` 手动跑一次后 `Formula/rstun.rb` 与最新 Release 一致；无变化时不产生提交
- [ ] `release-prep` 在测试分支演练：bump + tag + dispatch 全链路走通，产物与手工发版一致
- [ ] 全量门禁不变（CI 绿），`cargo deny`/`audit` 不退化
