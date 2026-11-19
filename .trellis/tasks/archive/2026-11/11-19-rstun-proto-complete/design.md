# 设计：协议闭环（500 / FINGERPRINT / ALTERNATE-SERVER / RFC 8489）

## 1. 边界

- 只补**服务端错误路径与完整性校验**，不引入鉴权（属 `rstun-auth`）。
- 所有新行为由配置开关或「配置了该能力」触发；**默认路径字节不变**（冻结测试继续生效）。
- 不引入新依赖：CRC32 手写（查表法，~30 行），HMAC 留给 auth 子任务。

## 2. 500 Server Error（RFC 5389 §15.6）

**触发条件**（仅这三类，全部发生在「已经解析成功、需要回包」的路径）：

| 条件 | 现状 | 改为 |
| --- | --- | --- |
| 响应编码失败（`Vec` 分配失败/长度溢出这类不变量违反）| 记日志 | 500（能编码则发，不能则丢）|
| UDP `send_to` 失败（除 `ConnectionRefused` / `NetworkUnreachable` / `AddrNotAvailable` 这类客户端地址问题）| 记日志 | 500 |
| 监听任务内部不可恢复错误 | 记日志 + 任务结束 | 500（尽力），随后由 supervisor 记录 |

> 纠错（2026-11-19，实现期发现）：本节初稿把 `EINVAL`（以及 `ENETUNREACH`）也列为「客户端地址问题」。
> 实现按冷复核的显式清单只排除 `ConnectionRefused` / `NetworkUnreachable` / `AddrNotAvailable`，
> **`EINVAL` → 500**。`RESPONSE-PORT 0` 触发 `EINVAL → 500` 正是本任务的 e2e 手段：
> 目的端口 0 无法投递，回一个固定 40 字节的 500 比静默丢弃更可诊断，语义上可接受。

**不触发**：请求本身非法（400/420）、鉴权失败（401/438）、限速/反射拒绝（静默丢弃）。

- 文案固定 `Server Error`，**不把 io error / backtrace 写进响应**（只进日志）。
- 500 响应固定 40 字节（20 头 + 20 `ERROR-CODE`），不得成为放大器：请求 < 20 字节本就不会被解析。

## 3. FINGERPRINT 校验（§15.5）

- 开关：`--check-fingerprint`（默认关闭，保证默认字节不变）。
- 校验规则：
  1. 若存在，**必须是最后一个属性**；否则 → 400（`Bad Request`）。
  2. 值 = `CRC32(消息头部 + 属性区，直到 FINGERPRINT 之前) XOR 0x5354554e`；
     **头部 `Length` 已包含 FINGERPRINT（8 字节）**，不重算。
     > 纠错（2026-11-19，实现期发现）：本节初稿写「去掉该属性并重算 Length」，与 RFC 5389 §15.5 不符。
     > 用 RFC 5769 §2.1/§2.2/§2.3 的标准字节复算：只有「Length 含属性、CRC 覆盖到属性之前」才能得到
     > `e57a3bcf` / `c07d4c96` / `c8fb0b4c`；按初稿写法会把所有真实客户端判错。实现与测试按 RFC 执行。
  3. 不匹配 → 默认 400；`--fingerprint-action=drop` 时静默丢弃（给不希望回包的部署）。
- CRC32 用标准 IEEE 多项式（与 RFC 5769 §2.1 的常量一致），单测用 RFC 5769 向量锁死。
- 关闭时：FINGERPRINT 仍按「已知属性」忽略（现状）。

## 4. ALTERNATE-SERVER（§15.11）

- 配置：`--alternate-server <ip:port>`（可重复，最多 1 个生效；多个时取第一个并告警）。
- 行为：配置后，**所有** Binding 请求回 `300 Try Alternate` + `ALTERNATE-SERVER`（含地址属性：family/port/address，与 `MAPPED-ADDRESS` 同编码）。
- 不参与 RFC 5780：带 `CHANGE-REQUEST`/`RESPONSE-PORT` 时仍回 300（重定向优先），文档写明。
- 关闭（未配置）时零行为变化。

## 5. RFC 8489 属性语义

| 属性 | 未开鉴权 | 开鉴权（由 auth 子任务实现）|
| --- | --- | --- |
| `MESSAGE-INTEGRITY-SHA256` (0x001C) | 忽略（现状）| 按 `PASSWORD-ALGORITHM` 协商或默认 SHA256 |
| `PASSWORD-ALGORITHMS` (0x8002 类) | 忽略 | 回支持的算法列表 |
| `PASSWORD-ALGORITHM` (0x001D) | 忽略 | 校验时使用 |
| `USERHASH` (0x001E) | 忽略 | 长期凭据无 USERNAME 时使用 |

README 增加「支持的 RFC 子集」表：明确「5389 全服务端行为 + 5780 全量 + 8489 的属性处理（鉴权见 auth）」。

## 6. 错误码矩阵（写入 README）

| 码 | 触发 | 备注 |
| --- | --- | --- |
| 300 | 配置了 `--alternate-server` | 带 `ALTERNATE-SERVER` |
| 400 | 非 Binding 方法、结构非法、FINGERPRINT 非末位/不匹配 | 不带 `UNKNOWN-ATTRIBUTES` |
| 420 | 未知 comprehension-required 属性 | 带 2N 字节列表 |
| 438 | nonce 过期（auth 子任务） | 带新 `NONCE` |
| 500 | 编码/send/内部不可恢复错误 | 固定文案 |

## 7. 兼容性

| 配置 | 与 `26.410.100` 的差异 |
| --- | --- |
| 默认（全关）| 无差异（冻结测试 + 33 请求对照）|
| `--check-fingerprint` | 仅「带 FINGERPRINT 且不合法」的请求从「正常应答」变为 400/丢弃 |
| `--alternate-server` | 所有 Binding 从 200 变 300（显式选择的行为）|
| 500 | 只在原本「请求收到但回不了包」的路径出现；正常路径不可达 |

## 8. 测试策略

- **单测**：CRC32 向量（RFC 5769 §2.1）、FINGERPRINT 末位/非末位/错值、`ALTERNATE-SERVER` 编码、`error_response(500)` 字节。
- **e2e**：起服务 + 自建探针，三态（默认/开 fingerprint/开 alternate-server）。
- **互操作**：`stun-types` 能解 300 与 500；pion/webrtc 至少能解析消息（不断言类型化）。
- **不引入 failpoint**：500 的映射用纯函数 `server_error_for(&io::Error) -> Option<u16>` 单测，e2e 靠注入一个「必然失败的 send」（如发往 0.0.0.0 的非法目标）覆盖。

## 9. 回滚

- 两个开关独立；关闭即恢复。单批 commit 可整体 revert。
