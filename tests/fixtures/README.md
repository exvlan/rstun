# `tests/fixtures/` — 测试夹具（不进发布物）

## `rsa-test-only.{crt,key}.pem`

- **一次性 throwaway 的 RSA-2048 自签密钥对**，`CN=rstun-test-invalid`，有效期到 2126 年
  （唯一目的是「永不过期」，免得测试在某天开始失败）。
- **只被一个测试使用**：`src/main.rs` 的
  `full_build_accepts_an_rsa_certificate_when_dtls_is_off`（`cfg(feature = "dtls")`）。
  该测试验证 B1：RSA 证书对 `turns:` 合法、对 DTLS 非法，所以「只开 TLS」必须能启动，
  「同时开 DTLS」必须拒绝。
- **不参与任何运行期路径**：不会被编进非测试构建（`include_str!` 在 `#[cfg(test)]` 的
  `mod tests` 里，且只在 `dtls` feature 下展开），不会被安装、不会被发布。
- **任何信任库都不应该接受它**：自签、私钥公开。不要把它加到系统/浏览器信任库，也不要
  在真实部署里引用这两个文件。
- **将来启用密钥扫描时请加入 allowlist**（例如 gitleaks 的 `.gitleaks.toml`、
  GitHub secret scanning 的自定义模式），并在白名单条目里引用本文件说明原因 ——
  它是一次性测试材料，不是泄露。

## 为什么放在这里

内嵌在源码里的字符串会让 `src/main.rs` 多出 ~2.8 KB 的 base64，且不好解释「这是测试材料」。
放到 `tests/fixtures/` 下、用 `include_str!` 引入，既保留了「跨平台、不依赖 CI 上的 openssl」
的好处，也让用途与风险一眼可见。

`tests/**` 在 `Cargo.toml` 的 `exclude` 里，所以 `cargo package` / crates.io 发布物**不含**
这两个文件；从 crates.io 解包后跑 `cargo test` 会因缺文件而失败，这是已知且可接受的取舍
（发布物只需要能 `cargo build`）。
