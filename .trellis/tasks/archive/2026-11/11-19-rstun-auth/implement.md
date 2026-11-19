# 执行计划：鉴权

> 前置：无（可独立实施）。后续：`rstun-turn-udp` 的强制凭据直接复用本任务的实现。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | 引入 `hmac`/`sha1`/`sha2`/`md-5`；`auth/` 模块骨架；`ct_eq` | `cargo tree` 列出 4 个新 crate；`ct_eq` 单测 | 单 commit |
| 2 | 向量单测：HMAC-SHA1（RFC 2202）、HMAC-SHA256（RFC 4231）、MD5 | 与标准向量逐字节 | 单文件 |
| 3 | 凭据解析：`--auth-user/--auth-pass`、`--auth-file`、`--realm`、`--auth-secret`；非法配置启动失败 | 启动失败用例 4 条 | 小 commit |
| 4 | key 派生（短/长/MD5/SHA256）+ `USERHASH` 计算 | 单测：同输入同 key；USERHASH 16B | 小 commit |
| 5 | nonce 签发/校验（无状态 + 过期 + 客户端 IP 绑定）| 单测：过期、错 IP、篡改、时钟偏差 | 小 commit |
| 6 | 401/438 响应构造（`REALM`/`NONCE`/`PASSWORD-ALGORITHMS`/`ERROR-CODE`）| 单测字节 + `stun-types` 解码 | 小 commit |
| 7 | 请求侧校验：`MESSAGE-INTEGRITY`、`MESSAGE-INTEGRITY-SHA256`、`PASSWORD-ALGORITHM`、`USERHASH` | e2e 五态（无凭据/错口令/过期/正确/USERHASH）| 小 commit |
| 8 | 接入判定顺序（限速 → 鉴权 → 420），401/438 计入限速桶 | e2e：洪水测 401 被限速 | 小 commit |
| 9 | `--auth-require-sha256`（拒绝 MD5） | e2e：MD5 客户端被 401 | 小 commit |
| 10 | 互操作：`turnutils_stunclient -u/-w/-r`；`rstun-interop.sh` 新增 `auth` 组（可选，计入 41→N 并同步文档）| 矩阵全绿 | 小 commit |
| 11 | 文档：README 鉴权节（配置/体积放大面/ICE 影响）、CHANGELOG、`docs/interop-matrix.md` | 人工评审 | 文档 commit |

## 复核修订（2026-11-19，冷复核后）

| # | 事项 | 处理 |
| --- | --- | --- |
| **B1** | `USERHASH` 必须是 **32 字节**（RFC 8489 §14.4） | `USERHASH_LEN = 32`、`userhash()` 返回完整摘要、`find_user` 接受 32 字节；16 字节截断值 → 401；单测钉 32 字节向量 + e2e（`cargo test` 与 interop probe 各一条）；文档 `[..16]` / `§14.13` 全改 |
| **B2** | `438` 必须带 `PASSWORD-ALGORITHMS`（RFC 8489 §9.2.4） | `stale_nonce` 追加该属性；实测 438 = 96 字节 |
| **B3** | 长凭据「有 MI 但缺必需属性」→ **400**（不是 401） | `verify_long_term` 先做缺失判定（`USERNAME`/`USERHASH` 至少一个 + `REALM` + `NONCE`）→ 400；值错仍 401 |
| **B5** | 认证后的 **420 / 400（PADDING+RESPONSE-PORT）** 也要签名 | `decide` 里三处（200/420/400）共用 `seal_answer`；`500` 在更低层拿不到 identity → README 登记「不签名」 |
| **B4** | nonce 只绑 client IP、无 cookie/security-feature | 记账：README「未实现（有意）」+ `design.md §4` + 本文件；PRD 的「8489 全量」改为「SHA256 / PASSWORD-ALGORITHM(S) / USERHASH」 |
| **M1** | 反射防护估算在未认证时低估（96B 401 vs 76B 成功） | 实现：开启鉴权时估算取 `max(签名成功响应, auth.challenge_len())` |
| **M2** | `turnutils_stunclient -u/-w/-r` 验收不成立（Debian 构建无该选项） | 改为「独立 hashlib/hmac 客户端 + `stun-types` 双向验签」，PRD 已改并注明工具版本 |
| 小 | Debug 脱敏、用户名 `ct_eq`、`--auth-file` 只 trim 行尾、probe 文案、注释/依赖数、README 反射措辞 | 全部改完 |

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all          # 默认配置：41 项
bash script/lab/rstun-abuse.sh                # 10 组
cargo tree -e normal --depth 1                # 新增 4 个（hmac/sha1/sha2/md-5）
```

外加：
- **默认路径字节对照**：不配凭据时，与 `HEAD` 旧二进制 17 请求 × 3 配置逐字节一致（沿用既有方法）。
- **鉴权开启的互操作**：`turnutils_stunclient -u test -w test -r example.org` → 成功（200）。

## 验收断言（必须）

- [ ] 不配凭据：冻结测试 + 41 项矩阵 + 10 组 abuse 全绿（零差异）
- [ ] 无 `MESSAGE-INTEGRITY` → 401，含 `REALM`/`NONCE`/`PASSWORD-ALGORITHMS`
- [ ] 错口令 → 401；nonce 过期（短 TTL）→ 438 + 新 `NONCE`
- [ ] `PASSWORD-ALGORITHM=SHA256` + `MESSAGE-INTEGRITY-SHA256` → 200
- [ ] `USERHASH`（无 `USERNAME`）→ 200
- [ ] `--auth-require-sha256`：MD5 凭据 → 401
- [ ] 401 洪水被限速桶拦截（计数可见）
- [ ] nonce 跨实例一致（同 secret）
- [ ] README 写明 401 的 4.3–5.0× 放大面与「开鉴权须配限速」

## 风险

| R | 缓解 |
| --- | --- |
| 密码学实现出错 | 用标准库 crate + RFC 向量；常量时间比较；不手写算法 |
| 依赖体积/定位变化 | README/CHANGELOG 明写 5→9；可选 feature 化留作后续 |
| 开启后打断匿名 ICE | 默认关闭 + README 醒目提示 |
| 401 放大被滥用 | 计入限速桶；文档要求同时开限速；`--realm` 长度可配以控制体积 |
