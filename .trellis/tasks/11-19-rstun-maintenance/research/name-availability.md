# crates.io 名称可用性（M1 前置）

> 2026-11-19 · 从发布机 `sg`（有公网）实测

## 结论

**`rstun` 在 crates.io 可用**（未被占用）。

## 证据

```
$ curl -sS -A "rstun-name-check/1.0 (github.com/exvlan/rstun)" \
       -H "Accept: application/json" \
       -o /tmp/rstun-crate.json -w "%{http_code}\n" \
       https://crates.io/api/v1/crates/rstun
404
{"errors":[{"detail":"crate `rstun` does not exist"}]}
```

补充：不带 `User-Agent` 时 crates.io 返回 `403`（Cloudflare 拦截默认 curl UA），
所以校验时必须带 UA（`cargo` 自身会带，无需特殊处理）。

## 后续（M1 剩余）

| 步骤 | 需要什么 | 在哪跑 |
| --- | --- | --- |
| `cargo package --list` / `--dry-run` | 仅 Rust 工具链 | 任意机器（本地即可）|
| `cargo publish` | `CARGO_REGISTRY_TOKEN`（或 `cargo login`） | **`sg`**（网络已验证）|
| `cargo install rstun` 验证 | 干净环境 + 网络 | `sg` 或容器 |

## 备注

- 本地（开发机）DNS 把 `crates.io` 解析到 `198.18.4.255`，`fetch`/`curl` 被拒 → 本地只能做 package/dry-run 以外的离线检查。
- 发布前确认 `Cargo.toml` 版本与 tag `rstun-v26.410.100` 一致（当前一致）。
