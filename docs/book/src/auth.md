# 鉴权（`--auth-user` / `--realm` / `--auth-file`）

RFC 5389 §10（短期 / 长期凭据）与 RFC 8489 §9.2（SHA256 / USERHASH）。**默认完全关闭**；
TURN 复用同一套长期凭据，另有 `--rest-secret`（见 [TURN](turn.md)）。

**默认完全关闭**：不配凭据时 `MESSAGE-INTEGRITY` 等属性照旧被忽略，响应字节与 `26.410.100`
逐字节一致（`plain_response_bytes_are_frozen` + 17 请求 × 3 配置的「旧二进制 vs 新二进制」对照）。
一旦配置凭据，**只有 Binding 请求**受保护（indication 仍忽略，非 Binding 方法仍 400）。

**短期凭据**（RFC 5389 §10.1，`--auth-user` + `--auth-pass`）

- key **就是口令**（§15.4），只校验 `MESSAGE-INTEGRITY`（HMAC-SHA1）。
- 缺 `USERNAME` 或 `MESSAGE-INTEGRITY`（§10.1.2 要求两者同时存在）→ **400 Bad Request**；
  未知用户 / 口令不符 → **401**（短期没有 realm/nonce 可提供）。
- `--auth-file` 也可用：一行一个 `user:password`，即多用户短期凭据。
  口令走命令行会在 `ps` 里可见，生产环境请用 `--auth-file`（`chmod 600`）。

**长期凭据**（RFC 5389 §10.2 + RFC 8489 §9.2，`--realm` + `--auth-secret`）

```
客户端                                rstun
  ── Binding（无凭据） ──▶            401 + REALM + NONCE + PASSWORD-ALGORITHMS
  ── USERNAME/REALM/NONCE + MI ──▶    200（响应同样带 MESSAGE-INTEGRITY）
  ── 同一条但 nonce 过期 ──▶          438 + 新 NONCE + REALM + PASSWORD-ALGORITHMS
```

- **缺失 ≠ 无效**：长凭据请求缺 `REALM` / `NONCE` / 身份属性（`USERNAME` 与 `USERHASH`
  都没有）→ **400**；属性齐全但值不对（realm 不符、用户不存在、`USERHASH` 不是 32 字节、
  MAC 不匹配）→ **401**。

- key 派生：`MD5(username:realm:password)`（`MESSAGE-INTEGRITY`）或
  `SHA256(username:realm:password)`（`MESSAGE-INTEGRITY-SHA256`）。口令本身**从不直接比较**
  —— 比的是 MAC，且用自写的**常量时间** `auth::ct_eq`（不引入 `subtle` 依赖）；
  `USERNAME` 与 `USERHASH` 的比对同样走它（避免用户名存在性时序探测）。
- `PASSWORD-ALGORITHM`（§14.12）缺省按 **MD5**（与 coturn 一致）；`PASSWORD-ALGORITHMS`
  （§14.11）在 401 里列出可接受集合。`--auth-require-sha256` 时只列 SHA256，
  用 MD5 的客户端回 401。
- `USERHASH`（§14.4）可替代 `USERNAME`，此时请求里**没有**明文用户名。值必须是**完整**的
  `SHA256(username:realm)`（**32 字节**）；16 字节的截断值不是 `USERHASH`，按值无效回 401。
- **nonce 无状态**：`base64url( expiry(5B) | HMAC-SHA256(secret, expiry|client_ip)[..11] )`
  （22 个字符）。校验只重算 HMAC 与过期时间，**没有服务端表**：同一 `--auth-secret` 的多个
  实例/重启后的进程都能互认对方的 nonce。有效期 `--nonce-lifetime`（默认 3600 秒）。
- **过期判定是严格的**（`now >= expiry` 即过期）：设计稿里的「±5 分钟时钟偏差容忍」没有
  实现成宽限期 —— 那会把每个配置的有效期都拉长 5 分钟（`--nonce-lifetime 1` 就不再是 1 秒）。
  需要容忍时钟偏差时把 `--nonce-lifetime` 调大即可。
- 判定顺序（最终实现）：**限速/反射防护（准入）→ FINGERPRINT → 300 → 鉴权 → 420 → 400 组合
  → 正常应答**。`300` 先于鉴权（重定向不需要认证），FINGERPRINT 先于鉴权（先证消息完整、
  再证凭据）；`401`/`438` 本身也先过了限速桶，所以 401 洪水不会绕过准入。

**放大面（必须配合限速）**

| 响应 | 字节（realm=`example.org`） | 对 20B 请求 | 对 28B 请求 |
| --- | --- | --- | --- |
| `401`（`ERROR-CODE` + `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`） | **96**（realm 每多 4 字节 +4） | 4.80× | 3.43× |
| `438`（`ERROR-CODE` + `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`） | **96** | 4.80× | 3.43× |
| `200` 成功（含 `MESSAGE-INTEGRITY`） | **76** | 3.80× | 2.71× |
| `200` 成功（含 `MESSAGE-INTEGRITY-SHA256`） | **88** | 4.40× | 3.14× |

结论：**开鉴权必须同时开限速**（`--rate-limit` 至少覆盖每源 IP，`--reflect-ratio` 覆盖重定向
探针）。启动时若配了凭据却没开任何抗滥用开关，会打一条 `warn` 明说这一点。

`401` / `438` 只回**请求源**、不响应 `RESPONSE-PORT`，因此不能被引到任意第三方端口（不构成
反射）；回包量仍受每源令牌桶约束。反射防护的比例规则只管带重定向属性的**成功**应答；开启鉴权
时它的估算取「签名后的成功响应」与「401 挑战」的**较大者**（未认证请求实发 96B 的 401，
不能按 76B 的成功响应去估）。这两类响应的放大面与 `300` 的已知放大面同属一类，
`docs/interop-matrix.md` 与本节都登记了实测字节数。

**对既有能力的影响**

- **ICE**：开鉴权后，无凭据的 ICE 连通性检查会收到 401（与 coturn 一致）。需要匿名 ICE 时
  不要开鉴权 —— 这也是它默认关闭的原因。
- **RFC 5780**：`CHANGE-REQUEST` / `RESPONSE-PORT` 与鉴权正交，带凭据即可正常使用；
  反射防护先于鉴权，所以小于门槛的重定向探针仍可能先被 400/静默丢弃。
- **`--alternate-server`**：300 先于鉴权，配置了重定向的实例不需要凭据。

