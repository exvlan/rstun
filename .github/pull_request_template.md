# 改动说明

## 关联

- Closes #
- 相关 issue / 讨论：

## 改了什么

<!-- 一段话：动机（为什么）＋结果（改完是什么样）。协议改动请附状态码/属性/字节数。 -->

## 验证（贴命令与关键输出）

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --no-default-features
cargo test --all-features
```

按改动面**追加**（见 [CONTRIBUTING.md](../CONTRIBUTING.md#提交前门禁)）：

- [ ] `bash script/lab/rstun-interop.sh all`（协议路径）
- [ ] `bash script/lab/rstun-abuse.sh`（限速 / 反射防护）
- [ ] `bash script/lab/rstun-turn.sh`（TURN；`--tls` / `--dtls` 需 full 构建）
- [ ] `cargo deny check licenses bans sources`（依赖变化）
- [ ] `bash script/ci/check-docs.sh` + `mdbook build docs/book`（文档 / flag 变化）

## 影响面

- [ ] **改了协议字节**（默认关闭路径的响应）：说明与哪个版本逐字节一致、靠哪条测试锁住
- [ ] **改了 flag / 默认值**：`docs/book/src/cli.md` 与相关章节已同步
- [ ] **改了依赖**：`cargo deny` 通过，必要时更新 `deny.toml` / `.cargo/audit.toml`
- [ ] **改了打包 / 发布**：`script/ci/build-deb.sh` 或 Release 资产断言已验
- [ ] 只改文档 / CI（无运行时影响）

## 回滚

<!-- 出问题时怎么退回：单文件 revert？还是需要同时回退 tag/镜像？ -->
