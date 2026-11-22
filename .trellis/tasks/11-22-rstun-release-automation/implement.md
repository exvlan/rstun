# 执行计划：发布与回归自动化

> 顺序：P0（只读）→ P1（写外部）。每步独立可验证、可单独回滚。
> 不 bump 版本；本任务自身的改动按普通 PR 流程提交（不触发发布）。

## 阶段 0 · 前置确认（人工，一次）

| # | 事项 | 验证 |
| --- | --- | --- |
| 0.1 | 确认 `.env.secret` 仍被 gitignore 覆盖 | `git check-ignore -v .env.secret` |
| 0.2 | （用户确认后）`gh secret set CARGO_REGISTRY_TOKEN -R exvlan/rstun --body "$(tr -d '\n' < .env.secret)"` | `gh secret list -R exvlan/rstun` 出现该名字（不显示值）|
| 0.3 | 记录当前 Release `26.410.104` 的 13 资产与 digest，作为回归基线 | `gh release view … --json assets` |

## 阶段 1 · P0-1 版本钉死点检查

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | 新增 `script/ci/check-version-pins.sh`（6 处 + README，失败列 `file:行`）| 手动改 README 版本 → exit 1；改回 → exit 0 |
| 1.2 | `ci.yml` 增加 `version-pins` 作业（push/PR）| 本地 `bash script/ci/check-version-pins.sh` 绿 |
| 1.3 | README/CONTRIBUTING 的「发版步骤」提到该检查 | 人工评审 |

## 阶段 2 · P0-2 打包预检

| # | 事项 | 验证 |
| --- | --- | --- |
| 2.1 | `ci.yml` 增加 `packaging` 作业：`cargo package --list` 断言排除项 + `cargo publish --dry-run` | 本地跑同命令；故意加 `exclude` 破坏 → 失败 |
| 2.2 | 断言 `--version` 与 `Cargo.toml` 一致（dry-run 的 package 校验已覆盖，补显式检查）| 同上 |

## 阶段 3 · P0-3 release-preflight

| # | 事项 | 验证 |
| --- | --- | --- |
| 3.1 | 新增 `.github/workflows/release-preflight.yml`（dispatch: version；只读）| `yaml.safe_load`；dispatch 对 `26.410.104` 全绿 |
| 3.2 | 步骤：pins → tests/clippy/fmt → interop/turn(lean+full)/frozen → gen-sbom/deb/brew → publish --dry-run → summary | run 的 summary 含 6 段结论 |
| 3.3 | 文档：`spec/backend/release-artifacts.md` 写「发版前必须 preflight 绿」 | 人工评审 |

## 阶段 4 · P0-4 post-release-verify

| # | 事项 | 验证 |
| --- | --- | --- |
| 4.1 | 新增 `.github/workflows/post-release-verify.yml`（dispatch: version；只读）| 对 `26.410.104` 全绿 |
| 4.2 | 校验 13 资产、架构、`--version`、deb、tap sha、镜像双架构 | summary 逐项 PASS |
| 4.3 | 负例：传一个不存在的 version → 明确失败 | run 红且信息清晰 |

## 阶段 5 · P1-1 自动 cargo publish

| # | 事项 | 验证 |
| --- | --- | --- |
| 5.1 | `release.yml` 增加 `publish-crates`（needs prepare+build；查 API 幂等；secret 注入）| `yaml.safe_load` |
| 5.2 | 幂等演练：对已发布的 `26.410.104` 跑一次（应 skip 且不红）| summary 出现「already published」|
| 5.3 | 真发布演练：用**未发布**的版本（如 `26.410.105-dev.0`？）验证 publish 路径 | 需用户确认是否愿意产出一个 dev 版本；否则只 dry-run + 代码评审 |
| 5.4 | spec 更新：发布契约加「crates.io 自动发布 + 幂等」 | 人工评审 |

## 阶段 6 · P1-2 tap 反向同步（外部仓）

| # | 事项 | 验证 |
| --- | --- | --- |
| 6.1 | 在 `exvlan/homebrew-rstun` 加 `.github/workflows/sync.yml`（cron + dispatch）| `yaml.safe_load` |
| 6.2 | 手动跑一次：formula 与最新 Release `rstun.rb` 类体一致 | diff 为空 |
| 6.3 | 再跑一次：无变化 → 不产生提交 | run 显示「no change」|

## 阶段 7 · P1-3 release-prep

| # | 事项 | 验证 |
| --- | --- | --- |
| 7.1 | 新增 `.github/workflows/release-prep.yml`（dispatch: version；bump + commit + tag + dispatch release）| `yaml.safe_load` |
| 7.2 | 在**草稿分支/预发版本**演练：bump 后 pins 绿、tag 生成、release 触发 | 产物与手工发版一致（13 资产 + digest）|
| 7.3 | 失败语义：tag 已存在 → 停止且不 force；version ≤ 当前 → 停止 | 负例演练 |
| 7.4 | 文档：`CONTRIBUTING` 的发布流程改为「preflight → prep」，保留手工路径 | 人工评审 |

## 门禁（每阶段）

```bash
python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]; print('yaml ok')"
bash script/ci/check-docs.sh --no-build
bash script/ci/check-version-pins.sh
cargo test && cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo deny check
```

## 验收映射

| PRD 验收 | 对应阶段 |
| --- | --- |
| pins 漂移失败 | 1.1 |
| 打包破坏失败 | 2.1 |
| preflight 全绿 + 清单 | 3.2 |
| post-release-verify 全绿（含 deb/tap/digest）| 4.2 |
| 重跑同版本 publish 跳过 | 5.2 |
| tap 无变化不提交 | 6.3 |
| release-prep 全链路 | 7.2 |

## 回滚

| 改动 | 回滚 |
| --- | --- |
| 新增脚本/workflow | revert 对应 commit |
| repo secret | `gh secret delete CARGO_REGISTRY_TOKEN` |
| tap `sync.yml` | 在 tap 仓 revert（外部仓，单独提交）|
| 已自动发布的版本 | `cargo yank --version X`（不可删除）|
