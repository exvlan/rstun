# 贡献指南

`rstun` 是一个**单 crate、单二进制**的 STUN/TURN 服务。改动分两类，要求不同：

- **行为改动**（协议字节、状态码、默认值、配额语义）：需要先有文档/测试依据，且**默认路径的
  字节不能变**（`protocol::tests::plain_response_bytes_are_frozen` 会拦）。
- **非行为改动**（文档、CI、打包、脚本）：跑通对应门禁即可。

## 环境

- Rust **1.95**（`rust-toolchain.toml` 固定），`rustup` 装好 `rustfmt` / `clippy`。
- 两种 feature 组合都要能编：`--no-default-features`（lean，默认）与 `--all-features`（full）。
- 可选：`turnutils_uclient` / `turnutils_stunclient` / `openssl`（lab 脚本用）、
  `python3`（探针）、`docker`（镜像与 .deb 验证）、`mdbook`（文档站）。

## 提交前门禁

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --no-default-features
cargo test --all-features
cargo deny check licenses bans sources     # 供应链（licenses/bans/sources）
bash script/ci/check-docs.sh               # 文档里的 help 片段/参数名/指标名/链接
bash script/ci/check-version-pins.sh       # 版本号 6 处钉死点（README/docker.md/k8s/compose/helm×2）
mdbook build docs/book                     # 文档站能构建（改了 docs/book 才需要）
```

改了这些文件还要跑对应脚本：

| 改动 | 追加验证 |
| --- | --- |
| `src/**` 协议路径 | `bash script/lab/rstun-interop.sh all`（42 项） |
| 限速 / 反射防护 / 准入 | `bash script/lab/rstun-abuse.sh`（10 组） |
| TURN（`src/turn*`） | `bash script/lab/rstun-turn.sh`（lean；`--tls`/`--dtls` 自动 full 构建） |
| 压测 / 混沌 | `bash script/lab/rstun-load.sh`、`bash script/lab/rstun-chaos.sh`（需 root + `tc`） |
| 版本号 / 镜像示例 / 部署清单 | `bash script/ci/check-version-pins.sh`（6 处钉死点必须一致） |
| 打包 / 发布 | `bash script/ci/build-deb.sh`、`.github/workflows/release.yml` 的资产断言；发版顺序 **preflight（只读）→ release-prep（bump+tag+dispatch，`dry_run` 默认 true）→ release（自动 publish crates.io）→ post-release-verify（只读）**；详细契约见 `.trellis/spec/backend/release-artifacts.md` |
| CHANGELOG 维护 | 功能/修复合入 `main` 时在 `CHANGELOG.md` 顶部维护 `## Unreleased`：`release-prep` 依赖它（缺了会 fail-fast，不会发出没有 changelog 的版本）|

CI 里这些作业**都是必需的**（`continue-on-error` 只出现在覆盖率作业上）。

## 定时作业（周度回归）

两个作业**不靠 PR 触发**，只按周跑：

| 作业 | 时间（UTC） | 内容 |
| --- | --- | --- |
| `qa-scheduled.yml`（QA scheduled） | 每周一 04:00 | fuzz、互操作矩阵、基准冒烟（只存数值，不设阈值） |
| `verify-platforms.yml`（Verify platforms） | 每周四 06:00 | linux-aarch64 / macOS x86_64 真机实跑 |

**已知风险：定时触发可能整体失效，而且没有任何信号。** 2026-11-23 盘点发现本仓
`event=schedule` 的运行数是 **0**（`gh api "repos/exvlan/rstun/actions/runs?event=schedule"` →
`total_count=0`），两个 workflow 的状态却都是 `active`、仓库非 fork、Actions 开启、`main` 持续有推送。
也就是说这两项周度回归可能一直没跑。

因此在告警解除前，**每周二（UTC）把这两个周度作业各手动补跑一次**：

```bash
gh workflow run qa-scheduled.yml -R exvlan/rstun
gh workflow run verify-platforms.yml -R exvlan/rstun
gh run list -e schedule -w "QA scheduled" -L 1     # 核对是否真的出现了 schedule 运行
```

`schedule-guard.yml`（每日 06:00 UTC，**外加每次 push 到 `main`** —— 后者保证 cron 整体失效时
守卫自己仍会跑）检查这两个作业最近一次 `event=schedule` 运行的年龄：超过 **8 天**（或 0 次）就建一条
`[schedule-guard] <workflow> 的定时运行已停滞` 的 issue；同标题只保留一条 open issue（不刷屏）。
恢复后（出现新的 schedule run 且年龄 ≤ 阈值）自动评论并关闭。

**手动补跑不会清掉告警**：`gh workflow run` 产生的是 `workflow_dispatch`，不是 `event=schedule`。

**手动关闭 issue 也无效**：守卫只按「固定标题 + `state=open`」去重，stale 没解除时下一次 push
（或次日 cron）会立刻**重建同标题 issue** —— 那个重建是**预期行为，不是守卫 bug**。

真正销账只有两条路：

1. **等平台的定时触发恢复**（推荐，什么都不用做）：一旦出现新的 `event=schedule` 运行且年龄 ≤ 阈值，
   守卫会评论「已恢复」并自动关闭 issue；
2. **书面承认不再按周监控**：改 `schedule-guard.yml` 的目标列表或把阈值调大并提交，
   下次运行起不再对该作业告警。

演练（不写 issue）：Actions → **Schedule guard** → Run workflow，`max_age_days=0`、
`dry_run=true` —— 检测到停滞时该次运行以 exit 1 结束，summary 里列出目标与年龄。

## 提交规范

- 一个提交一件事。信息用 Conventional Commits 前缀（仓库历史即例子）：
  `feat(turn):` / `fix(server):` / `docs(book):` / `chore(ci):` / `test(abuse):`。
- 说明里写**为什么**，不只是改了什么。协议相关改动请附「字节/状态码/计数」的实测数字。
- 不提交：`target/`、`docs/book/book/`、`dist/`、`fuzz/artifacts/`、任何凭据或生产地址。
- **不 force-push 已发布 tag**：`rstun-v*` 的 tag 一旦发布就指向固定树。

## DCO / CLA

- 本项目**不要求 CLA**，也**不强制 DCO 签名**（`Signed-off-by`）。提交即表示你有权以
  **MPL-2.0** 授权该贡献。
- 新增文件若来自别处，必须在文件头或 `NOTICE` 里写明来源与许可证；与本仓 MPL-2.0 不兼容的
  许可证贡献不会被合并。
- 新增依赖会走 `cargo deny`（licenses 允许清单在 `deny.toml`）；引入新许可证需要单独说明理由。

## 文档约定

- **协议行为表只在文档站维护**（`docs/book/src/protocol.md`）。README 只放摘要 + 链接。
- 文档里写到的 `--<flag>` / `rstun_<metric>` 必须真实存在 —— `script/ci/check-docs.sh` 会比对
  `rstun server --help` 与 `/metrics`，所以**改 flag 必须同步文档**。
- `docs/book/src/cli.md` 的 help 片段由 `rstun --help` 输出生成：改了 clap 定义后重新贴一份。

## 报告问题

- 缺陷 / 功能请求：用 issue 模板（必填版本、features、平台、最小复现）。
- **安全漏洞**：见 [SECURITY.md](SECURITY.md)，不要开公开 issue。

## 行为准则

参与即表示同意：对人不对事、不人身攻击、不发布他人隐私信息。维护者可以关闭越界讨论。
（本仓暂不引入单独的 `CODE_OF_CONDUCT.md` 文件，此段即约定。）
