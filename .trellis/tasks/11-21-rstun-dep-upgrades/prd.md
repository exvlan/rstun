# 依赖主版本升级（hmac / sha1 / sha2 / md-5 / webrtc-util）

## Goal

把 Dependabot 的 5 个**主版本跳变** PR 适配到代码上，使 CI 全绿后可以合并；避免长期挂着红 PR 掩盖真实失败。

## 背景（当前状态）

Dependabot 已开 7 个 PR：2 个 actions 小版本已合并（`32c477a`、`4c34ec2`），剩下 5 个 **CI 红**：

| PR | 变更 | 影响面 |
| --- | --- | --- |
| #3 | `sha1 0.10.7 → 0.11.0` | `digest` 0.11 家族；`auth.rs` 的 HMAC 调用 |
| #4 | `sha2 0.10.9 → 0.11.1` | 同上 |
| #6 | `md-5 0.10.6 → 0.11.0` | 长期凭据 key 派生 |
| #7 | `hmac 0.12.1 → 0.13.0` | HMAC 构造/`new_from_slice` API |
| #5 | `webrtc-util 0.11.0 → 0.17.3` | DTLS 依赖链（很可能牵连 `webrtc-dtls` 版本）|

## Scope

- 逐个升级并修复编译/行为差异（`src/auth.rs`、`src/main.rs` 的 TLS/DTLS 部分）；
- 全部门禁绿（lean/full 测试、clippy、fmt、interop/abuse/turn、`cargo audit`/`deny`）；
- 确认 **协议字节不变**（冻结测试 + 3 配置 × 17 请求对照）；
- 合并对应 PR（或关闭后由新提交取代）。

## 非目标

- 不借机重构鉴权/DTLS 逻辑；
- 不升级与这 5 个无关的依赖。

## 验收

- [ ] 5 个 PR 全部合并或关闭（取代），main 上 CI 绿
- [ ] `cargo tree -e normal --depth 1` 的直接依赖数不变（9 / 13）
- [ ] 冻结测试与 interop 42 项、abuse 10 组、turn 15+2 全绿
- [ ] `cargo audit` / `cargo deny` 结论不退化（新增公告必须登记理由）
- [ ] lean/full 二进制体积变化记录在 `implement.md`（如 >10% 需说明）

## 风险

| R | 缓解 |
| --- | --- |
| `digest 0.11` 破坏 `hmac` 用法（trait 变更） | 先单独升 sha1/sha2/md-5，再升 hmac；分步提交 |
| `webrtc-util 0.17` 与 `webrtc-dtls 0.12` 不兼容 | 先看 `cargo tree -i webrtc-util` 的约束；必要时同时升 `webrtc-dtls` 并复跑 DTLS 验收 |
| 升级改变握手/编码行为 | 冻结测试 + 与 coturn 对跑（`rstun-turn.sh --tls --dtls`）|
