# 分发与文档（包管理器 / 文档站 / 社区 / 供应链）

## Goal

让第三方能「一条命令装上、看懂、放心用」，并把供应链风险纳入 CI。

## 需求

1. **包管理器**：
   - Homebrew tap（`exvlan/homebrew-rstun`）或 formula PR；
   - Debian/Ubuntu：`.deb`（含 systemd unit）+ apt 仓库（可选）；
   - nixpkgs 提交（可选）。
2. **文档站**：mdBook（`docs/book/`），含：快速开始、Docker、RFC 行为表、鉴权配置、限速配置、FAQ、`CHANGELOG`。
3. **社区文件**：`SECURITY.md`（漏洞报告流程）、`CONTRIBUTING.md`、issue/PR 模板、`CODE_OF_CONDUCT.md`（可选）。
4. **供应链门禁**：CI 增加 `cargo audit`、`cargo deny`（licenses/bans）、dependabot、发布产物 SBOM（`syft` 或 `cargo cyclonedx`）。
5. **徽章/可发现性**：README 徽章、crates.io 元数据（keywords/categories 已有）。

## 验收

- [ ] `brew install exvlan/rstun/rstun`（或 formula 本地验证）可用
- [ ] `.deb` 在干净容器安装后 `systemctl start rstun` 成功
- [ ] 文档站可静态构建并在 GitHub Pages 预览
- [ ] CI 中 `cargo audit` / `cargo deny` 为必需作业；SBOM 随 Release 上传
- [ ] 仓库含 SECURITY/CONTRIBUTING/模板

## 风险

| R | 缓解 |
| --- | --- |
| 维护多套打包成本高 | 先做 brew + deb，nix 后置 |
| 文档与行为漂移 | 文档中的行为表由 `rstun --help` 与测试清单核对 |
