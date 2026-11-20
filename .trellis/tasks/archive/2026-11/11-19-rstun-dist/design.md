# 设计：分发与文档（dist）

## 1. 边界

- 只做**分发、文档、社区与供应链**；不改服务行为（除 README 徽章等文档）。
- 外部动作（建 tap 仓、开 GitHub Pages、发布）需在**发布时**执行，并需用户确认；本任务先在仓内准备一切可验证的产物。
- 不做：nixpkgs（后置）、snap/flatpak、自动证书。

## 2. 包管理器

| 渠道 | 做法 | 验证 |
| --- | --- | --- |
| Homebrew | `contrib/homebrew/rstun.rb`（引用 Release 的 `rstun-<platform>-<ver>.zip` 与 sha256）+ 发布时建 `exvlan/homebrew-rstun` tap 并同步 formula | `brew install --build-from-source ./contrib/homebrew/rstun.rb`（Linux/macOS 本机或容器）|
| Debian `.deb` | `nfpm`（`contrib/deb/nfpm.yaml`）：二进制到 `/usr/local/bin`、systemd unit 到 `/lib/systemd/system`、LICENSE/README 到 `/usr/share/doc/rstun` | 干净容器 `dpkg -i` 后 `systemctl start`（容器里用 `systemd-analyze verify` 兜底）|
| apt 仓库 | 后置（需托管） | — |

- 版本串来自 tag（`rstun-v<ver>` → `<ver>`），打包脚本必须校验与 `Cargo.toml` 一致。
- 两种构建都出包？**只发 lean 的 deb/brew**；full 通过 Release 的 `rstun-full-*` 与镜像提供（避免包管理器里出现「同版本两个包」）。

## 3. 文档站（mdBook）

```
docs/book/
├── book.toml
└── src/
    ├── SUMMARY.md
    ├── quickstart.md        # cargo/brew/deb/docker 四条安装路径
    ├── docker.md
    ├── protocol.md          # 行为表（由 README 的核心表迁入，避免两处漂移）
    ├── auth.md              # 短期/长期/REST
    ├── rate-limit.md        # abuse guard
    ├── turn.md              # TURN(TLS/DTLS/REST/带宽)
    ├── faq.md
    └── changelog.md         # include CHANGELOG
```

- 行为表**只在文档站维护**，README 保留精简摘要 + 链接（避免两处不一致）。
- 构建：`mdbook build`；GitHub Pages 用 `actions/deploy-pages`（固定 SHA），只从 `main` 的 `docs/book` 构建。
- 文档与实现漂移检查：`script/ci/check-docs.sh` —— 抽取文档中的 `rstun --help` 片段与真实输出 diff；
  行文中引用的指标名/参数名必须在 `rstun --help` 或 `/metrics` 中存在。

## 4. 社区文件

| 文件 | 内容 |
| --- | --- |
| `SECURITY.md` | 漏洞报告渠道（私下邮箱/私密 advisory）、支持版本、响应时限；**不留内部信息** |
| `CONTRIBUTING.md` | 构建/测试/门禁（`cargo test`、两种 feature、`script/lab/*`）、提交规范、DCO/CLA 说明 |
| `.github/ISSUE_TEMPLATE/{bug,feature}.yml` | 必填：版本（`rstun --version`）、features（lean/full）、平台、最小复现 |
| `.github/pull_request_template.md` | 关联 issue、验证命令、是否改协议字节 |

## 5. 供应链

| 项 | 做法 |
| --- | --- |
| `cargo audit` | 已在 CI；保持 |
| `cargo deny` | 新增 `deny.toml`：licenses 允许清单（MPL-2.0 + 依赖常见 MIT/Apache/BSD/ISC/Unicode/Zlib）、bans（禁重复版本、禁 wildcard）、sources（只允许 crates.io）；CI 作业 `deny` |
| Dependabot | `.github/dependabot.yml`：cargo（周）、github-actions（月）；只开 PR 不自动合并 |
| SBOM | Release 时用 `cargo cyclonedx`（或 `syft`）生成 `rstun-<ver>.cdx.json` 并上传；从 lean 与 full 各生成一份 |
| 发布签名 | 后置（cosign/sigstore），在 Release notes 注明「未签名」 |

## 6. 可发现性

- README 徽章：CI、Release、license(MPL-2.0)、crates.io（发布后）、镜像大小。
- crates.io 元数据（keywords/categories）已有；`description` 已含 STUN/TURN。

## 7. 兼容与回滚

- 新增文件为主；`README` 只做「行为表迁出 + 链接」与徽章。
- Pages/tap 都是外部状态：失败不影响仓库；回滚 = 删除 workflow/文件或撤销 Pages 设置。

## 8. 风险

| R | 缓解 |
| --- | --- |
| 文档与实现漂移 | `check-docs.sh` 对 `--help` 片段与参数名做校验 |
| brew formula 需 Release 资产 sha256（发布前不存在） | formula 用 `url`+`sha256` 占位脚本在发布时生成；本地用 `--build-from-source` 验证 |
| Pages 部署权限 | 用 `permissions: {pages: write, id-token: write}` + `actions/deploy-pages` |
| 打包引入新工具（nfpm/cyclonedx） | 只在 CI/脚本里用，**不进 Cargo.toml**；版本固定 |
