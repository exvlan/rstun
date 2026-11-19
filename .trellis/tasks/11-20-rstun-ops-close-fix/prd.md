# ops 端点跨平台优雅关闭（macOS RST 丢弃响应）

## Goal

修复 `/healthz` 与 `/metrics` 在 **macOS** 上「服务端已写 503/400，但客户端收到 `ConnectionReset`」的缺陷，
使同一响应在 Linux 与 macOS 都可被客户端读到。

## 背景（CI 证据）

`rstun-ops` 归档后的 CI（run `44563422358`）在 `test (macos-latest)` 失败，两例：

```
ops::tests::connections_over_the_cap_get_503_and_the_endpoint_keeps_serving
ops::tests::the_head_limit_is_exactly_the_documented_number_of_bytes
→ read: Os { code: 54, kind: ConnectionReset, message: "Connection reset by peer" }
```

根因：服务端 `write_reply` 写完响应后只做 `shutdown()`（关写方向），**不排空接收方向**。
macOS 在接收缓冲仍有未读数据时关闭 socket 会发 **RST**（Linux 发 FIN），RST 可能让客户端丢弃已到达的响应。
触发条件正是「请求头超过上限」与「并发超限拒绝」——两种都必然有未读的请求字节。

## Scope

- 只改 `src/ops.rs` 的关闭路径（`write_reply` 及其调用点）；不改端点契约、指标、STUN/TURN 路径。
- 不引入依赖、不改 `.github/**`。

## 需求

1. 写响应后：`shutdown(Write)` → **向读方向排空**（有界，≤200ms 或总 deadline）→ 再关闭。
2. 排空必须有界，且不得突破整条连接的 2s 总时限。
3. 保持「1 连接 1 请求」语义（不解析后续请求，只排空丢弃）。
4. 超限（`TooLarge`）与超并发（503）两条路径都要覆盖。

## 验收

- [ ] `cargo test` 在 Linux 全绿；两个原有失败用例在 macOS 逻辑下不再依赖「RST 不发生」
- [ ] 新增回归测试：客户端先发完整请求 + 额外垃圾字节，再读响应——必须读到 503/400（不是 ECONNRESET）
- [ ] 排空有界：慢速客户端仍能在 ≈2s 内被断开（不因排空无限等待）
- [ ] 不配 `--health-listen` 时行为与字节不变
- [ ] CI 三平台（ubuntu/macos/windows）全绿（以真实 CI 为准）

## 风险

| R | 缓解 |
| --- | --- |
| 排空引入新的慢速占用 | 排空截止 = `min(连接 deadline, now+200ms)`，且不计入新请求 |
| 排空读阻塞影响吞吐 | 端点默认关闭；并发上限仍生效 |
| 测试在 Linux 上无法复现 RST | 回归测试断言「读到响应」，Linux 同样通过；macOS 由 CI 验证 |
