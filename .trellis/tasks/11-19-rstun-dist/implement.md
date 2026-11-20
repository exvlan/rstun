# 执行计划：dist

> 前置：阶段 A（T1/T2）与 qa 已完成；发布链（lean/full 产物、镜像）已可用。
> 本任务不发布任何东西：所有外部动作（建 tap、开 Pages、发 Release、传 SBOM）都在发布时执行，且需用户确认。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | `SECURITY.md`、`CONTRIBUTING.md`、issue/PR 模板 | `yaml.safe_load`（issue 模板）；人工评审 | 删除文件 |
| 2 | `deny.toml` + CI `deny` 作业 | 本地 `cargo deny check` 通过；CI 绿 | 单文件 |
| 3 | `.github/dependabot.yml`（cargo 周 / actions 月） | YAML 解析；GitHub 上生效需 push（首次 PR 观察） | 单文件 |
| 4 | `docs/book/`（mdBook：quickstart/docker/protocol/auth/rate-limit/turn/faq/changelog）+ `book.toml` + `SUMMARY.md` | 本地 `mdbook build` 成功；链接无死链（`mdbook test` 或脚本检查） | 新增目录 |
| 5 | README：行为表迁出到文档站、保留摘要+链接；加徽章 | `script/ci/check-docs.sh`（新增）通过 | 文档 commit |
| 6 | `script/ci/check-docs.sh`：`--help` 片段 diff + 参数名/指标名存在性 | 本地跑通；故意改坏一处 → 红 | 新增文件 |
| 7 | Pages workflow（`.github/workflows/docs.yml`）：`mdbook build` + `actions/deploy-pages`（固定 SHA，`pages: write`） | YAML 解析；本地构建产物可预览 | 新增文件 |
| 8 | Debian 包：`contrib/deb/nfpm.yaml` + `script/ci/build-deb.sh`（版本与 `Cargo.toml` 校验） | 干净容器 `dpkg -i` + `systemd-analyze verify` | 新增文件 |
| 9 | Homebrew：`contrib/homebrew/rstun.rb` 模板 + `script/ci/gen-brew.sh`（发布时填 url/sha256） | `brew install --build-from-source`（Linuxbrew/macOS） | 新增文件 |
| 10 | SBOM：Release 增加 `cargo cyclonedx`（lean/full 各一份）并上传 | 本地生成 `*.cdx.json`，结构合法 | workflow |
| 11 | 发布时外部动作清单（**需用户确认后执行**）：建 `exvlan/homebrew-rstun`、开 Pages、发 Release、上传 SBOM | 清单写入 `implement.md`，逐项勾选 | — |

## 门禁

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/lab/rstun-turn.sh
cargo deny check                     # 新增
mdbook build docs/book               # 新增
bash script/ci/check-docs.sh         # 新增
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')+glob.glob('.github/ISSUE_TEMPLATE/*.yml')];print('yaml ok')"
```

## 验收断言（必须）

- [ ] `cargo deny check` 在 CI 为**必需**作业（不是 `continue-on-error`）
- [ ] 文档站 `mdbook build` 成功；`check-docs.sh` 能抓住「`--help` 片段/参数名/指标名」漂移（给一次反证）
- [ ] README 的行为表已迁出且链接可达（无两处维护）
- [ ] issue 模板必填版本/features/平台；PR 模板含验证命令
- [ ] `.deb` 可安装且 unit 通过 `systemd-analyze verify`
- [ ] brew formula 可 `--build-from-source` 安装（Linuxbrew 或 macOS）
- [ ] Release 资产含 lean/full 的 SBOM（`.cdx.json`）
- [ ] 外部动作清单逐项列明，**均未擅自执行**

## 风险

| R | 缓解 |
| --- | --- |
| 文档站与 README 双维护 | 行为表只留文档站，README 摘要+链接 |
| nfpm/cyclonedx 引入不可控 | 版本固定、只在脚本/CI 用，不进 `Cargo.toml` |
| Pages/tap 需外部权限 | 清单化，发布时用户确认后执行 |
| brew 无法在 Linux CI 验证 | 用 Linuxbrew 容器或 macOS 本地；CI 不阻塞（记录为人工步骤） |
