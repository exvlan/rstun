# 鉴权契约（RFC 5389 短期/长期 + RFC 8489 SHA256/USERHASH）

> 来源：2026-11-19 `rstun-auth`。冷复核曾发现 `USERHASH` 被写成 16 字节（RFC 8489 §14.4 要求 **32**），
> 已修并加测。任何改动鉴权路径的提交都必须满足本文。

## 1. Scope / Trigger

- 修改 `src/auth.rs`、`decide` 的鉴权段、401/438 构造、响应签名；
- 新增凭据配置、nonce 参数、算法协商；
- 任何会改变「无凭据配置时的字节」的改动。

## 2. Signatures

| 项 | 契约 |
| --- | --- |
| 短期 key | `password`（原样，不做 SASLprep） |
| 长期 MD5 key | `MD5(username:realm:password)` |
| 长期 SHA256 key | `SHA256(username:realm:password)` |
| `USERHASH` | **32 字节** = `SHA256(username:realm)`（§14.4；16 字节必须被拒）|
| nonce | `base64url(expiry(5B) \| HMAC-SHA256(secret, expiry\|client_ip)[..11])`，默认 1h，严格 `now >= expiry` 即过期 |
| 401 | `ERROR-CODE 401` + `REALM` + `NONCE` + `PASSWORD-ALGORITHMS` |
| 438 | `ERROR-CODE 438` + `REALM` + `NONCE` + **`PASSWORD-ALGORITHMS`**（§9.2.4）|
| 签名范围 | `MESSAGE-INTEGRITY`：Length 已含 MI，HMAC 覆盖到 MI 之前；响应同样签名 |
| 插入位置 | 响应中 `MI`（及 `MI-SHA256`）在 `PADDING` **之前**，`PADDING` 仍为最后一个属性 |

## 3. Contracts（判定顺序与拒绝码）

```
准入（限速/反射） → FINGERPRINT → 300 → 鉴权 → 420 → PADDING+RESPONSE-PORT(400) → 应答
```

| 请求状态 | 响应 |
| --- | --- |
| 未配凭据 | 不做任何鉴权判定；带伪造 MI 的请求与裸请求**逐字节相同** |
| 长期：无 MI | 401（挑战）|
| 长期：有 MI 但缺 `USERNAME`/`USERHASH`（至少一个）、`REALM`、`NONCE` | **400** |
| 长期：realm 不符 / 未知用户 / MAC 不匹配 | 401 |
| 长期：nonce 过期 | **438** + 新 `NONCE`（+ REALM + PASSWORD-ALGORITHMS）|
| 短期：缺 `USERNAME` 或 `MESSAGE-INTEGRITY` | 400（RFC 5389 §10.1.2）|
| 认证通过后的 200 / 420 / PADDING+RESPONSE-PORT 400 | **均需签名**；500 不签名（拿不到 identity，已在 README 登记）|
| `--auth-require-sha256` + MD5 凭据 | 401（广告列表只有 SHA256）|

## 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| 算法声明与签名不一致（如声明 SHA256 用 MD5 签） | 401（不可降级）|
| 16 字节 USERHASH | 401（`find_user` 拒绝）|
| nonce 换 secret / 篡改 / 错 IP | 401 |
| 401/438 | **必须计入限速桶**；未开限速时启动打印告警 |
| 401 体积 | ~96B（realm `example.org`），对 28B 请求 **3.43×**；README 要求「开鉴权须配限速」|
| `--auth-file` | 每行 `user:password`；只去行尾 `\r`，**保留口令首尾空格**；`#` 注释 |

## 5. Good / Base / Bad

- **Good**：`USERHASH` 用完整 32 字节摘要；缺属性 400、值错 401；响应签名覆盖 200/420/400。
- **Base**：只测「自己客户端 + 自己服务端」的 USERHASH（共享错误约定会自证）。
- **Bad**：`USERHASH` 取 `digest[..16]` —— 对 RFC 合规客户端全部 401，且自家测试仍绿。

## 6. Tests Required（断言点）

1. HMAC-SHA1（RFC 2202）、HMAC-SHA256（RFC 4231）、MD5（RFC 1321）、RFC 5769 §2.4 长凭据向量。
2. USERHASH **32B → 200 / 16B → 401**（e2e，必须用独立实现算，不要用服务端自己的 helper）。
3. 缺 `NONCE`/`REALM`/`USERNAME(且无 USERHASH)` → 400；realm 值错 → 401。
4. 438 含 `PASSWORD-ALGORITHMS`；新 `NONCE` 与旧值不同。
5. 认证后 420 的 `MESSAGE-INTEGRITY` 可用同一 key 验签。
6. `--auth-require-sha256`：MD5 → 401、SHA256 → 200。
7. `PADDING` + 鉴权：MI 在 PADDING 之前、PADDING 仍最后。
8. 不配凭据：17 请求 × 4 配置与旧二进制逐字节一致（68 组）。

## 7. Wrong vs Correct

#### Wrong
```rust
const USERHASH_LEN: usize = 16;            // RFC 8489 §14.4 要求 32
let hash = sha256(user_realm)[..16];
```
```rust
// 有 MI 但缺 REALM → 401（会让客户端无限重试）
if realm.is_none() { return Rejection::Unauthorized; }
```

#### Correct
```rust
const USERHASH_LEN: usize = 32;
let hash: [u8; 32] = sha256(user_realm).into();
```
```rust
// 缺失 → 400；值错 → 401
if realm.is_none() { return Rejection::BadRequest; }
if realm != configured { return Rejection::Unauthorized; }
```
