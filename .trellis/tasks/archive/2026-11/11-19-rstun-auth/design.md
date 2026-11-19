# 设计：鉴权（RFC 5389 短期/长期 + RFC 8489 全量）

## 1. 边界

- 只在**配置了凭据**时启用；默认不配置 → 行为与 `26.410.100` 逐字节一致（忽略 `MESSAGE-INTEGRITY`，不返回 401）。
- 鉴权只保护 **Binding 请求**；indication 仍忽略；非 Binding 方法仍 400。
- **不做**多租户、数据库后端、按域（realm）路由；用户名来源为单用户配置或静态文件。
- 不实现 `SERVER`/`ALTERNATE` 相关的鉴权扩展。

## 2. 依赖取舍（重要）

RFC 8489 全量需要 `HMAC-SHA1`（5389 MI）、`HMAC-SHA256`（MI-SHA256）、`MD5`（长期凭据 key 派生）。
**不手写密码学**，引入 RustCrypto 四个小 crate：

| crate | 用途 | 备注 |
| --- | --- | --- |
| `hmac` | HMAC 通用层 | no_std、纯 Rust |
| `sha1` | 5389 `MESSAGE-INTEGRITY` | |
| `sha2` | 8489 `MESSAGE-INTEGRITY-SHA256` 与 nonce 派生 | |
| `md-5` | 长期凭据 key = `MD5(username:realm:password)` | |

**运行期依赖 5 → 9**（均为 RustCrypto，纯 Rust、无 C）。这会改变 README 的「5 个依赖」定位，
需要在 README/CHANGELOG 明写；若将来要回到精简，可用 `--features auth` 做可选编译（本任务不做，避免发布矩阵翻倍）。

## 3. 凭据与 key 派生

| 模式 | 配置 | key | 校验属性 |
| --- | --- | --- | --- |
| 短期 | `--auth-user` + `--auth-pass` | `password`（SASLprep 后） | `MESSAGE-INTEGRITY`（HMAC-SHA1） |
| 长期 · MD5 | `--realm` + `--auth-secret` + 用户口令（文件） | `MD5(username:realm:password)` | `MESSAGE-INTEGRITY` |
| 长期 · SHA256 | 同上 + `PASSWORD-ALGORITHM=0x0002` | `SHA256(username:realm:password)` | `MESSAGE-INTEGRITY-SHA256` |
| 长期 · USERHASH | 同上，无 `USERNAME` | 同上 | `USERHASH = SHA256(username:realm)`（**完整 32 字节**，§14.4）定位用户 |

- **用户名来源**：`--auth-file <path>`（每行 `user:password`，`#` 注释）；单用户模式用 `--auth-user/--auth-pass`。
- 口令比较一律**常量时间**（自写 `ct_eq`，不引入 `subtle`）。
- `PASSWORD-ALGORITHM` 缺省按 MD5（与 coturn 兼容）；`--auth-require-sha256` 可拒绝 MD5。

## 4. nonce（无状态）

```
nonce = base64url( expiry(5B) | HMAC-SHA256(secret, expiry | client_ip)[..11] )
```

- 默认有效期 `--nonce-lifetime 3600s`；
- 校验：解码 → 检查 `client_ip` 与过期 → 重算 HMAC（常量时间比较）；
- 多实例一致：只要共享 `--auth-secret`，任一实例签发的 nonce 都可用（无共享状态）；
- 过期 → **438 Stale Nonce** + 新 `NONCE` + `REALM` + `PASSWORD-ALGORITHMS`（RFC 8489 §9.2.4
  对 401/438 同样要求后两个）；缺失/错误 → **401 Unauthorized**；
- **已决偏差（复核 B4）**：nonce **只绑 `client_ip`**（不绑源端口），不含 nonce cookie，
  也不实现 §9.2.3 的 `SECURITY-FEATURE` 位；±5min 时钟宽限**不实现**（会把每个
  `--nonce-lifetime` 拉长 5 分钟，破坏「短 TTL → 438」的验收），需要容忍偏差就调大 lifetime。

## 5. 判定顺序（与现有错误路径的关系）

```
解析 → 方法/类 → [300 alternate-server] → [FINGERPRINT（若开启）]
  → 鉴权（若配置）：
      无凭据 → 401 + REALM + NONCE + PASSWORD-ALGORITHMS
      有凭据但 nonce 过期 → 438 + 新 NONCE
      凭据存在但不匹配 → 401
  → 420（未知 comprehension-required）
  → PADDING/RESPONSE-PORT 组合 → 400
  → 限速/反射防护（现有 abuse-guard）
  → 正常应答
```

> 鉴权先于 420：避免未认证客户端拿属性探测；但**限速在鉴权之后**会让 401 洪水绕过限速 ⇒ 实际实现顺序为
> **限速 → 鉴权 → 420**，401/438 也计入限速桶（与 abuse-guard 契约一致）。文档写最终顺序，不写中间稿。

## 6. 与既有能力的关系

| 能力 | 影响 |
| --- | --- |
| ICE（`PRIORITY`/`USE-CANDIDATE`）| 开鉴权后，无凭据的 ICE 探测会收到 401（与 coturn 一致）。**默认关闭**，README 明确「开鉴权会打断匿名 ICE」 |
| RFC 5780 | `CHANGE-REQUEST`/`RESPONSE-PORT` 与鉴权独立；带凭据即可正常使用 |
| 300 / FINGERPRINT | 300 先于鉴权（重定向不需要认证）；FINGERPRINT 先于鉴权（完整性优先） |
| abuse-guard | 401/438 计入所有限速桶；**放大面**：401（含 REALM/NONCE/PASSWORD-ALGORITHMS）约 100–140B，28B 请求 → 4–5×；必须在 README 登记，并要求开鉴权时同时开限速 |

## 7. 响应体积（放大面，写进 README）

| 响应 | 约字节 | 对 28B 请求的放大 |
| --- | --- | --- |
| 401（REALM + NONCE + PASSWORD-ALGORITHMS）| **96**（实测，realm `example.org`；原估 120–140 是更长 realm） | **3.43×** |
| 438（REALM + NONCE + PASSWORD-ALGORITHMS）| **96**（实测）| 3.43× |
| 200（成功，无 5780，带 MI）| 76 | 2.71× |

结论：**开鉴权必须配合限速**；这是安全换取的代价，文档不得省略。

## 8. 兼容性与回滚

| 配置 | 与当前行为的差异 |
| --- | --- |
| 不配凭据（默认）| 无差异（冻结测试 + 51 组字节对照）|
| 配短期凭据 | 无 `MESSAGE-INTEGRITY` 的 Binding → 401 |
| 配长期凭据 | 同上；多出 REALM/NONCE/438；缺必需属性 → 400、值错 → 401 |
| `--auth-require-sha256` | 拒绝 `PASSWORD-ALGORITHM=MD5` |

回滚：去掉凭据配置即恢复；代码单批 commit 可整体 revert。

## 9. 测试策略

- **单测**：HMAC-SHA1/SHA256 向量（RFC 2202 / RFC 4231）、`MD5` 向量、nonce 编解码与过期、`ct_eq`、key 派生。
- **e2e（Rust）**：无凭据 401、错口令 401、过期 438（短 TTL）、正确 200、USERHASH 路径。
- **互操作**：`turnutils_stunclient -u/-w/-r`（coturn 默认 MD5）成功；`--auth-require-sha256` 下需支持 SHA256 的客户端。
- **回归**：不配凭据时 `interop all` 41 项 + `rstun-abuse.sh` 10 组 + 冻结测试全绿。
