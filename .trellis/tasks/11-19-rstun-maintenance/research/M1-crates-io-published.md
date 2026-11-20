# M1 crates.io 首发（已完成）

> 2026-11-21 · `rstun v26.410.100` 已发布到 crates.io

| 项 | 结果 |
| --- | --- |
| 名称 | `rstun`（发布前确认未被占用）|
| 版本 | `26.410.100`（与 tag `rstun-v26.410.100`、`Cargo.toml` 一致）|
| 包内容 | 25 文件 / 890.8 KiB（压缩 234.4 KiB）；无 `fuzz/`、`test/`、`tests/`、`.github/`、`.trellis/`、`.opencode/` |
| `cargo publish` | ✅ `Uploaded rstun v26.410.100` → `Published rstun v26.410.100` |
| 干净环境安装 | ✅ `cargo install rstun --version 26.410.100 --root /tmp/…` → 二进制 3.77 MB，`rstun 26.410.100` |
| 文档 | README 加 crates.io 徽章；`cargo install rstun` 说明去掉「发布后」限制；quickstart 同步；CHANGELOG 记一行 |
| 门禁 | `script/ci/check-docs.sh` exit 0 |

## 备注

- 首次尝试曾因「账号邮箱未验证」被 crates.io 400 拒绝；账号完成邮箱验证后重试成功（token 始终有效）。
- 撤回方式：`cargo yank --version 26.410.100`（crates.io 不支持删除）。
- 本地 token 存放：工作区 `.env.secret`（35 字节裸 token，已 `.gitignore`）。
