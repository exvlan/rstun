# 鉴权（短期 / 长期凭据）

## Goal

对齐 coturn 的 STUN 鉴权能力：支持短期凭据与长期凭据（realm/nonce），使本服务可用于需要访问控制的场景。

## 需求

1. **短期凭据**（RFC 5389 §10.1）：`--auth-user`/`--auth-pass`（或 env），校验 `MESSAGE-INTEGRITY`（HMAC-SHA1）。
2. **长期凭据**（§10.2）：
   - 无 `MESSAGE-INTEGRITY` → `401` + `REALM` + `NONCE`；
   - nonce 过期 → `438` + 新 `NONCE`；
   - 校验失败 → `401`；
   - nonce **无状态**：`HMAC(secret, expiry|client_ip)`，默认 1h，可配置；
   - `--realm`、`--auth-secret`（或从文件读）。
3. **RFC 8489（全量，用户定稿）**：`MESSAGE-INTEGRITY-SHA256`、`PASSWORD-ALGORITHM(S)` 协商、`USERHASH`（长期凭据无 USERNAME）；
   key 派生按算法区分（MD5 → `MD5(user:realm:pass)`，SHA256 → `SHA256(user:realm:pass)`）。
4. **兼容**：未配置凭据时行为与现状一致（忽略 MI，不返回 401）；
   ICE 客户端的 `PRIORITY`/`USE-CANDIDATE` 仍不触发鉴权。
5. **错误响应体积受控并登记**：401 约 100–140 字节（含 REALM/NONCE/PASSWORD-ALGORITHMS），对 28B 请求是 4.3–5.0×；
   必须计入限速桶，并在 README 明写「开鉴权须配限速」。
6. **依赖变化**：新增 `hmac`/`sha1`/`sha2`/`md-5`（运行期 5 → 9），README/CHANGELOG 同步说明。

## 验收

- [ ] `turnutils_stunclient -u <user> -w <pass> -r <realm>` 成功
- [ ] 错误口令 → 401；过期 nonce → 438 且带新 NONCE；无凭据 → 401
- [ ] 无凭据配置时：字节级冻结测试通过
- [ ] 互操作：`turnutils_stunclient -u/-w/-r` 成功；`PASSWORD-ALGORITHM=SHA256` 与 `USERHASH` 各有一条通过用例
- [ ] `--auth-require-sha256` 下 MD5 凭据被拒（401）
- [ ] nonce 多实例一致（同一 secret 下两台机器签发的 nonce 可互认）

## 风险

| R | 缓解 |
| --- | --- |
| 引入 4 个 RustCrypto 依赖 | 纯 Rust、无 C；固定版本；README 明写 5→9；后续可 feature 化 |
| 401 放大被滥用 | 计入限速桶；文档要求同时开限速；`--realm` 长度可控 |
| 时钟偏移导致 438 频繁 | nonce 有效期可配 + 允许 ±5min 偏差 |
| 鉴权与限速互相影响 | 401/438 也计入限速桶 |
