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
3. **RFC 8489 的 SHA256 / PASSWORD-ALGORITHM(S) / USERHASH**（原稿写「全量」，复核后收窄）：
   `MESSAGE-INTEGRITY-SHA256`、`PASSWORD-ALGORITHM(S)` 协商、`USERHASH`
   （§14.4，**完整 32 字节** `SHA256(user:realm)`，长期凭据无 USERNAME）；
   key 派生按算法区分（MD5 → `MD5(user:realm:pass)`，SHA256 → `SHA256(user:realm:pass)`）。
   **未实现**：nonce cookie / `SECURITY-FEATURE` 位（RFC 8489 §9.2.3），即 nonce 只绑 client IP。
4. **兼容**：未配置凭据时行为与现状一致（忽略 MI，不返回 401）；
   ICE 客户端的 `PRIORITY`/`USE-CANDIDATE` 仍不触发鉴权。
5. **错误响应体积受控并登记**：**实测** 401 = 438 = 96 字节（realm `example.org`，含
   REALM/NONCE/PASSWORD-ALGORITHMS），对 20B 请求 4.80×、28B 3.43×（原稿估 100–140 字节 /
   4.3–5.0× 是更长 realm 的量级，按 realm 长度线性增长）；必须计入限速桶，并在 README 明写
   「开鉴权须配限速」。
6. **依赖变化**：新增 `hmac`/`sha1`/`sha2`/`md-5`（运行期 5 → 9），README/CHANGELOG 同步说明。

## 验收

- [ ] 长期凭据握手成功 —— **替代判据**（本机 coturn 4.6.1-2 的 `turnutils_stunclient`
      是**无鉴权选项**构建，`-u/-w/-r` 直接 `invalid option`；且 coturn 的 STUN Binding
      本身不要求鉴权，当不了服务端 oracle）：独立 `hashlib`/`hmac` 客户端完成
      401 → MI → 200 → 验签，且 `stun-types` 2.0.5 双向签/验各一条
- [ ] 错误口令 → 401；过期 nonce → 438 且带新 NONCE + REALM + PASSWORD-ALGORITHMS；无凭据 → 401
- [ ] 缺 REALM / NONCE / 身份属性 → **400**；值错（realm 不符等）→ 401
- [ ] `USERHASH` 用 **32 字节**（RFC 8489 §14.4）→ 200；16 字节截断值 → 401
- [ ] 无凭据配置时：字节级冻结测试通过
- [ ] 互操作：`turnutils_stunclient -u/-w/-r` 成功；`PASSWORD-ALGORITHM=SHA256` 与 `USERHASH` 各有一条通过用例
- [ ] `--auth-require-sha256` 下 MD5 凭据被拒（401）
- [ ] nonce 多实例一致（同一 secret 下两台机器签发的 nonce 可互认）

## 风险

| R | 缓解 |
| --- | --- |
| 引入 4 个 RustCrypto 依赖 | 纯 Rust、无 C；固定版本；README 明写 5→9；后续可 feature 化 |
| 401 放大被滥用 | 计入限速桶；文档要求同时开限速；`--realm` 长度可控 |
| 时钟偏移导致 438 频繁 | nonce 有效期可配（`--nonce-lifetime`）。**±5min 宽限未实现**：它会把每个配置的有效期都拉长 5 分钟，`--nonce-lifetime 1 → 438` 就无法成立 |
| 鉴权与限速互相影响 | 401/438 也计入限速桶 |
