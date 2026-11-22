# 设计：发布与回归自动化

> 依赖事实：cargo token 在 `.env.secret`（35B，gitignore 已覆盖）；tap 仓与主仓同 owner，
> 但**不跨仓写**（改为 tap 反向拉取）；主仓内写操作只用工作流自带 `permissions`。

## 1. 凭据与权限模型

| 用途 | 机制 | 说明 |
| --- | --- | --- |
| crates.io 发布 | 仓库 secret `CARGO_REGISTRY_TOKEN`（由 `.env.secret` 一次性写入）| 用户已选「完全自动发布」，不做 environment 人工批准；发布**不可删除**，只能 yank → 由幂等检查 + preflight 降低误发风险 |
| Release/资产/提交 | 工作流 `permissions: contents: write` | 与现状一致 |
| tap 同步 | **tap 仓自己的 `GITHUB_TOKEN`** | tap 仓 `sync.yml` 读取公共 Release，不需要任何 PAT |
| 通告对端 | 手工 | 不自动化 |

写入 secret 的命令（一次，需用户在场确认）：

```bash
gh secret set CARGO_REGISTRY_TOKEN -R exvlan/rstun --body "$(tr -d '\n' < .env.secret)"
```

## 2. P0 组件

### 2.1 `script/ci/check-version-pins.sh`

- 真源：`Cargo.toml` 的 `version`；
- 检查点（只认「当前版本」语义，历史基线不改）：
  - `README.md`：`已发布 \`X\``
  - `docs/book/src/docker.md`：`ghcr.io/exvlan/rstun:X server`
  - `contrib/k8s/deployment.yaml`：`image: ghcr.io/exvlan/rstun:X`
  - `contrib/docker/compose.yaml`：同上
  - `contrib/helm/Chart.yaml`：`appVersion: "X"`
  - `contrib/helm/values.yaml`：`tag: "X"`
- 输出：缺一即 `exit 1` 并列出 `file:行`；CI 作业 `version-pins` 在 push/PR 跑。

### 2.2 CI `packaging` 作业

```bash
cargo package --list --allow-dirty | tee /tmp/pkg.txt
! grep -qE '^(fuzz/|tests/|\.github/|\.trellis/|\.env)' /tmp/pkg.txt
cargo publish --dry-run        # 验证能打包并构建
```

- 目的：把「发版时才发现打包坏」提前到每次 PR；
- 不加 token，不联网发布（dry-run 只上传到本地模拟）。

### 2.3 `release-preflight.yml`（dispatch: version）

顺序（任一失败即停）：

1. `check-version-pins.sh`（version 必须等于 `Cargo.toml`）
2. `cargo test` / `--all-features`；`clippy` 两种 feature；`fmt --check`
3. `rstun-interop.sh all`；`rstun-turn.sh`；`rstun-turn.sh --tls --dtls`
4. `gen-sbom.sh` lean/full；`build-deb.sh`（amd64）；`gen-brew.sh`（用占位 sha 不校验）
5. `cargo publish --dry-run`
6. Summary：输出「可以发版 / 卡在哪一步」

- 只读：不建 tag、不建 Release、不推任何东西。

### 2.4 `post-release-verify.yml`（dispatch: version）

1. `gh release view` 断言 13 资产（8 zip + 2 SBOM + rb + 2 deb）
2. 下载 lean/full（linux x86_64、aarch64、macos、windows）：`file` 验架构；
   x86_64 linux 直接 `--version`；其余只验 zip 完整性与可执行位
3. `dpkg-deb -I` 校验版本/架构；解包 x86_64 二进制执行 `--version`
4. 下载 tap 仓 `Formula/rstun.rb`，比对 3 个 sha256 与 Release zip 一致
5. `docker buildx imagetools inspect ghcr.io/exvlan/rstun:<version>` 存在且双架构
6. 结果写 `$GITHUB_STEP_SUMMARY`

## 3. P1 组件

### 3.1 `release.yml` 新增 `publish-crates` 作业

```yaml
publish-crates:
  needs: [prepare, build]
  runs-on: ubuntu-24.04
  steps:
    - checkout
    - uses: actions-rust-lang/setup-rust-toolchain (锁 SHA)
    - name: Skip if already published
      run: |
        if curl -fsS "https://crates.io/api/v1/crates/rstun/${{ needs.prepare.outputs.version }}" >/dev/null; then
          echo "already published; skipping" >> "$GITHUB_STEP_SUMMARY"; echo "skip=1" >> $GITHUB_ENV
        fi
    - name: cargo publish
      if: env.skip != '1'
      env:
        CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
      run: cargo publish
```

- 与 `release` 作业并行（互不阻塞）；失败只让工作流红，不撤 Release；
- 幂等：查 crates.io API 比 `cargo publish` 报错更清晰（也避免把 400 当失败）。

### 3.2 tap 反向同步（tap 仓）

`exvlan/homebrew-rstun/.github/workflows/sync.yml`：

```yaml
on:
  schedule: [{cron: "30 5 * * *"}]   # 每日，晚于主线发布窗口
  workflow_dispatch:
permissions:
  contents: write
jobs:
  sync:
    steps:
      - checkout
      - 取 exvlan/rstun 最新 release tag（API，无 token 亦可限速内）
      - gh release download <tag> -p rstun.rb -R exvlan/rstun
      - 替换 Formula/rstun.rb 的 class 体；`git diff --quiet` 则退出
      - commit + push（用 tap 自己的 GITHUB_TOKEN）
```

- 无 PAT；不需要主仓权限；
- 也可在 tap 仓加 `repository_dispatch` 由主仓发布后触发（需主仓 token 写 tap，故选轮询更简单）。

### 3.3 `release-prep.yml`（dispatch: version）

1. 校验 version 格式与 `> Cargo.toml` 当前值（防止重复/回退）；
2. `sed` 改 `Cargo.toml` 版本 + `cargo metadata` 刷新 lock；
3. `CHANGELOG.md`：`## Unreleased` → `## <version>`；
4. `check-version-pins` 的 6 处 → 新版本；
5. `git commit -m "chore(release): <version>"` + push；
6. `git tag rstun-v<version>` + push tag；
7. `gh workflow run release.yml -f version=<version>`；
8. Summary 输出后续观察点（release run 链接）。

- 失败点：第 6 步 tag 已存在 → 停止并提示（不 force）；
- 逃生口：仍可手工 bump + dispatch。

## 4. 误发防护（自动 publish 的代价）

| 风险 | 措施 |
| --- | --- |
| 版本号写错就永久发布 | `release-prep` 校验 version > 当前值；`release.yml` 校验 == `Cargo.toml`；`preflight` 必跑（建议流程：preflight → prep）|
| 同样版本重复发布 | `publish-crates` 先查 API，已存在即跳过 |
| 发布后才发现产物坏 | `post-release-verify` 独立可跑；坏了用 `cargo yank` + 新版本修复 |
| secret 泄漏 | 只在 workflow env 注入；不 echo；`.env.secret` 不入库（已有 gitignore + 一次 `git check-ignore` 验证）|

## 5. 兼容与回滚

- 全部为**增量**：现有手工路径保留（dispatch、手工 bump、手工 publish 都还能用）；
- 回滚：删除新增 workflow/脚本即可；secret 可 `gh secret delete`；
- tap 的 `sync.yml` 删除后回到手工同步。

## 6. 实施顺序

1. P0-1 version-pins + CI 作业（最小、立刻有价值）
2. P0-2 packaging 作业
3. P0-3 preflight（先只读跑通当前 main）
4. P0-4 post-release-verify（对 `26.410.104` 实测）
5. P1-1 publish-crates（先 dry-run 验证幂等分支）
6. P1-2 tap sync.yml（写进 tap 仓，手动跑一次）
7. P1-3 release-prep（最后做；先在分支演练 bump + tag 不进 main 的路径）

## 7. 待确认（开始前）

1. `gh secret set` 会把你 `.env.secret` 的 token 上传为仓库 secret —— 确认执行；
2. tap 仓新增 `sync.yml` 属外部仓写入 —— 确认执行（无 PAT，只用 tap 自己的 token）；
3. 自动 publish **不可撤回**（只能 yank），确认「完全自动」语义。
