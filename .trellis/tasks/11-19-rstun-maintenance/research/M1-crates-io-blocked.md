# M1 crates.io 首发（阻塞：账号邮箱未验证）

> 2026-11-21 · token 来自工作区 `.env.secret`（35 字节裸 token，已在 `.gitignore`）

## 已完成

| 步骤 | 结果 |
| --- | --- |
| 名称可用性 | ✅ `rstun` 未被占用（此前 sg 实测 404）|
| `cargo package --list` | 25 文件 / 890.8 KiB（压缩 234.4 KiB），无 `fuzz/`、`test/`、`tests/`、`.github/`、`.trellis/`、`.opencode/` |
| `cargo publish --dry-run` | ✅ 打包 → 验证构建（4.26 s）→ 上传被 dry-run 拦下 |
| `cargo publish`（真实） | ❌ **HTTP 400：A verified email address is required to publish crates to crates.io** |

## 阻塞项（需账号持有人操作）

crates.io 要求发布账号的**邮箱已验证**：

1. 打开 <https://crates.io/settings/profile>；
2. 设置并完成邮箱验证（点击邮件里的确认链接）；
3. 回到本仓重跑：

```bash
CARGO_REGISTRY_TOKEN="$(tr -d '\n' < .env.secret)" cargo publish
```

（token 有效，认证已通过；失败只发生在「账号资格检查」这一步。）

## 发布后待办

- `cargo install rstun --root <tmpdir> --version 26.410.100` 在干净环境验证（需要 crates.io 索引可用）；
- README 加 crates.io 徽章（`https://img.shields.io/crates/v/rstun.svg` + 链接）；
- `CHANGELOG` 记录首发版本；
- 若需要撤回：`cargo yank --version 26.410.100`（crates.io 不支持删除）。
