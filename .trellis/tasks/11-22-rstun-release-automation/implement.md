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

## 阶段执行记录

### P0（2026-11-22，已完成待提交）

| 项 | 结果 |
| --- | --- |
| P0-1 版本钉死点 | `check-version-pins.sh`（真源 Cargo.toml，`--version` 必须一致，`EXPECTED_PINS=6` 断言）；CI `version-pins` 作业；负例：改 README/helm → exit 1 且定位 `file:行`；删行 → 报「找不到检查点」；`--version` 冲突 → exit 1；`v` 前缀 strip 与 release.yml 同语义 |
| P0-2 打包预检 | CI `packaging` 作业：`cargo package --list` 排除断言 + `cargo publish --dry-run`；负例（去掉 `exclude tests/**`）被捕获；已发布版本上 dry-run 不假红 |
| P0-3 preflight | 11 段只读（pins→tests→clippy→fmt→interop→TURN lean/full→SBOM→deb→brew→publish dry-run→summary）；`fetch-depth: 0`；装 coturn/golang；SKIP 判失败；日志落 `/tmp` 不脏树；`timeout 90min` |
| P0-4 post-release-verify | 对 `26.410.104` 逐段本机跑通：13 资产、四平台架构、deb 元数据、tap formula（**raw.githubusercontent.com**）+3 个 sha256、镜像 amd64+arm64、digest；负例版本 → 失败 |

### 复核（第二轮）

- 阻塞项 B1：`post-release-verify` 原用匿名 `gh api` 读 tap —— `gh` 无登录态直接拒绝（实测 exit=4），
  且 App token 不跨仓（404）。改为 `raw.githubusercontent.com`（匿名 200、无限流、无需 base64）；
- M2：去掉 workflow 级 `VERSION`，只由 Normalize 步骤写 `GITHUB_ENV`（输入 `v26.410.104` 实测归一化正确）；
- M3：preflight deb 段注明「只验 nfpm 元数据，不验 musl/static-pie」；
- M5：`EXPECTED_PINS=6` 断言（删掉一处 check_pin → exit 1，变异验证通过）；
- M6：`check-docs` 的 `--dry-run` 白名单为精确名；反证（改错 `--health-listen`）仍报错。

### P1 设计修正（复核连带）

- crates.io 幂等检查必须带 `User-Agent`（实测无 UA → 403，有 UA → 200/404）；
- `publish-crates` 拆成**可复用 workflow + dispatch 包装**，演练不触发 Release/镜像；
- `release-prep` 增加 `dry_run`（只输出 diff 预演）。

### P0-4 首次 Actions 真跑（2026-11-22）

`gh workflow run post-release-verify.yml -f version=26.410.104` → run
[45019486454](https://github.com/exvlan/rstun/actions/runs/45019486454) **completed/success**，逐步：

```
Normalize version                       success
Assert release assets (13)              success
Download assets                         success
Verify binary architectures (4 lean zips) success
Verify --version and tag commit         success
Verify Debian packages                  success
Verify tap formula (class body + sha256) success
Verify container image (multi-arch)     success
Summary                                 success
```

即 P0 的「发布后验收」不再依赖人肉核对：13 资产、四平台架构、`--version` 与 tag sha6 对齐、两个 deb、
tap formula 类体与 3 个 sha256、镜像 amd64+arm64 全部由 workflow 断言。

## P1 决策记录（主会话，2026-11-22）

| # | 取舍 | 决定 | 理由 |
| --- | --- | --- | --- |
| 1 | `publish-crates` 的前置 | **`needs: [prepare, build]`（保持）** | 构建矩阵坏了就不该发 crate：crate 只依赖源码，但「四平台编不出」是更基础的信号；30–50s 的等待可接受 |
| 2 | crate 与 Release 资产是否互相阻塞 | **不阻塞（保持并行）** | 两者失败面不同：资产坏可 `--clobber` 重发；crate 错只能 yank + 新版本。任一红都由人介入，不该互相拖死 |
| 3 | tap 同步状态 | **已合入并实测**（`exvlan/homebrew-rstun` 的 `sync.yml`，每日 05:30 UTC） | spec 里「属 P1-2、合入前人工」的旧表述已纠正；`post-release-verify` 的 formula 段是漏同步的自动守卫 |
| 4 | `## Unreleased` 缺失 | **保持 fail-fast，不预置空段** | `release-prep` 依赖该段；预置空段会发出「没有 changelog 的版本」。已在 `CONTRIBUTING.md` 写「合入功能时维护 Unreleased」 |
| 5 | `main` 分支保护 | **当前未保护**（`protected=false`），prep 直接 push | 若将来开启保护，prep 会 fail-fast；届时改用「测试分支演练 + merge」 |

## 下次发版的操作前提（写给未来的自己）

1. 合入功能/修复时在 `CHANGELOG.md` 顶部维护 `## Unreleased`（否则 prep 拒绝）；
2. 发版前跑 `release-preflight`（只读，30–50 分钟）；
3. `release-prep` 先 `dry_run=true` 看 diff，再 `dry_run=false`；
4. 发布后跑 `post-release-verify`，并确认 tap 同步（最迟次日 05:30 UTC，也可手动 dispatch）。

### P1-1 幂等 Actions 真跑（2026-11-22）

`gh workflow run publish-crates.yml --ref main -f version=26.410.104` → run
[45020473352](https://github.com/exvlan/rstun/actions/runs/45020473352) **completed/success**：

```
Normalize version                       success
Validate version against Cargo.toml     success
Skip if already published               success   ← 命中 200 → skip=1
Guard token                             skipped
cargo publish                           skipped
Summary                                 success
```

即：**已发布版本重跑不红、不需要 token、不会重复上传**。`--ref main` 的原因：
`rstun-v26.410.104` 的 tag 树里还没有本 workflow 文件（它 2026-11-22 才落地）。

### P1-2 tap 反向同步（2026-11-22 已合入）

- `exvlan/homebrew-rstun/.github/workflows/sync.yml`：每日 05:30 UTC + 手动 dispatch；
- 实测 run `45018325505`：`latest rstun release: rstun-v26.410.104` → 内容无变化 → **不产生提交**
  （tap HEAD 仍是 `739de12`）；零 PAT、只用 tap 自己的 `GITHUB_TOKEN`。

### 复核修正（P1）

- 幂等与 dry_run 的门控从 `env.*`（`GITHUB_ENV` 在 step-level `if:` 的可见性无文档保证）
  改为 `steps.<id>.outputs`；实测四态（200/404/403/000）与 dry_run 三层保证；
- 补发/演练的 `--ref` 规则写进 README/spec，并注明 `26.410.104` 及更早的 tag 无该文件（只能 `--ref main`）。

### P1-3 `release-prep` dry_run 演练（Actions，2026-11-22）

- 第一次 run `45020950315` **按设计失败**在 `Retitle CHANGELOG` —— 因为 `CHANGELOG.md` 当时没有
  `## Unreleased`（fail-fast 生效，且发生在任何写入之前）；
- 补上 `## Unreleased`（本次自动化条目）后重跑 run
  [45021188926](https://github.com/exvlan/rstun/actions/runs/45021188926) **completed/success**：

```
Preconditions (branch + clean tree + git identity) success
Normalize and validate version                     success
Bump Cargo.toml and refresh Cargo.lock             success
Retitle CHANGELOG                                  success
Bump version pins                                  success
Preview (dry_run)                                  success
Commit and push                                    skipped   ← 零远端写
Tag and push tag                                   skipped
Dispatch release workflow                          skipped
Summary                                            success
```

即：预演路径（默认 `dry_run=true`）在 Actions 上完整跑通，且**没有产生 commit/tag/dispatch**。
写入路径的证据来自本地裸仓演练（commit/tag 指向 bump commit、重打 tag 拒绝且不 force、dispatch 带 `--ref`）。

### preflight 首次真跑发现的环境缺陷（已修）

run `45020548183`：除 Summary 外全部 success，Summary 判 FAIL —— **判定正确**：
interop 真失败在 `pion`。根因：CI 的 `golang-go` 是 **1.22.2**，而 `pion/stun v3.1.7` 要求 **go 1.24.0**
→ `go mod tidy` 触发 toolchain 自动下载，CI 网络下失败（本地 Go 1.24.4，所以一直绿）。

修复：`release-preflight` 与 `qa-scheduled`（明天首跑会踩同一坑）都改用
`actions/setup-go`（锁 SHA `40f1582b…`，`go-version: 1.24.x`），并从 apt 列表移除 `golang-go`；
interop 失败时额外打印 `$LOG_DIR/*build*.log` 便于定位。

### P0-3 preflight 复验（2026-11-22，Go 修复后）

run [45021336583](https://github.com/exvlan/rstun/actions/runs/45021336583) **completed/success**：

```
Check version pins                                    success
Gates (tests + clippy + fmt)                          success
Install lab dependencies (coturn + python3 + iproute2) success
Interop matrix (all)                                  success   ← pion 在 go1.24 下通过
TURN acceptance (lean)                                success
TURN acceptance (full: --tls --dtls)                  success
SBOM (lean + full)                                    success
Build release binary (lean) and Debian package (amd64) success
Render Homebrew formula (placeholder sha256)          success
cargo publish --dry-run                               success
Summary                                               success   ← verdict=PASS
```

对照首跑 `45020548183`：除 Summary 外同样全绿，但 `INTEROP=failure`（pion）→ Summary 正确判 FAIL。
修复（`actions/setup-go` 1.24 + 移除 apt `golang-go` + 失败打印 build 日志）后全绿。

### qa-scheduled 首跑预演（2026-11-22）

run [45021337538](https://github.com/exvlan/rstun/actions/runs/45021337538) **completed/success**：

```
interop matrix (container: buildpack-deps:trixie + coturn + go 1.24)  success
fuzz (parse, 600s)                                                   success
bench smoke (numbers only)                                           success
```

- 容器内 interop 通过 → 证明 setup-go 修复在容器 job 同样有效（明天 04:00 UTC 定时首跑不会再因 pion 红）；
- fuzz 600s 无崩溃 → 同时作为维护任务 M3 的证据（见 `11-19-rstun-maintenance/research/M3-long-term-regression.md`）。
