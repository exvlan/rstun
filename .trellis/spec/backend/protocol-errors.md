# 协议错误路径契约（FINGERPRINT / 300 / 500 / 错误码矩阵）

> 来源：2026-11-19 `rstun-proto-complete`。设计初稿曾把 FINGERPRINT 的 Length 语义写错，
> 实现期用 RFC 5769 向量证伪并纠正 —— 本文记录**正确**语义与可执行断言。

## 1. Scope / Trigger

- 修改 `src/protocol.rs` 的属性编解码、`check_fingerprint`、任何错误响应构造；
- 新增/调整错误码、`--check-fingerprint` / `--fingerprint-action` / `--alternate-server`；
- 任何会改变「请求 → 响应类型」的判定顺序。

## 2. Signatures

| 项 | 契约 |
| --- | --- |
| `check_fingerprint(frame)` | `Absent / Valid / NotLast / Mismatch`；`NotLast` 与「值长度≠4」在**任何模式**下都 400 |
| FINGERPRINT 值 | `CRC32(头部 + 属性区，直到 FINGERPRINT 之前) XOR 0x5354554e`；**头部 Length 已包含该属性（8B），不重算** |
| `server_error_for(&io::Error)` | `ConnectionRefused / NetworkUnreachable / AddrNotAvailable → None`；其余（含 `InvalidInput`/EINVAL）→ `500` |
| `alternate_server_response` | `300 Try Alternate` + `ALTERNATE-SERVER`（`0 | family | port | address`）；IPv4 56B / IPv6 68B |
| 开关 | `--check-fingerprint`（默认关）、`--fingerprint-action answer|drop`（`drop` 需前者）、`--alternate-server <ip:port>` |

## 3. Contracts（判定顺序与响应）

| 输入 | 默认配置 | `--check-fingerprint` | `--alternate-server` |
| --- | --- | --- | --- |
| 合法指纹 Binding | 200 | 200 | **300** |
| 错误值指纹 | 200（不校验）| **400**（`drop` 则静默 + 计数）| 300（指纹优先判定 → 400/300 顺序：指纹先于 300）|
| 指纹非末位 / 长度≠4 | 200 | **400**（任何 action）| 400 |
| 未知 comprehension-required | 420 | 420 | **300**（300 先于 420）|
| `CHANGE-REQUEST` / `RESPONSE-PORT` | 正常 5780 行为 | 同左 | **300**（重定向优先）|
| 非 Binding 方法 | 400 | 400 | 400 |
| 内部失败（编码/send）| 500（若可编码）| 500 | 500 |

## 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| 默认（两个开关都关）| 与旧版本**逐字节一致**（51 组对照已验证）|
| FINGERPRINT 结构错误 | 400，不受 `--fingerprint-action drop` 影响 |
| FINGERPRINT 值不匹配 + `drop` | 无响应；`dropped` 与 `fingerprint_rejected` 各 +1 |
| 500 | 固定 40B、固定文案 `Server Error`，**不写 errno/路径/backtrace**（只进日志）|
| 300 放大面 | 20B 请求 → 56B（IPv4 2.80×）/ 68B（IPv6 3.40×）；**不在 abuse-guard 防护域**，靠每 IP 桶兜底，README 已登记 |
| 500 放大面 | 28B → 40B = 1.43×，低于普通 Binding 2.60× 基线 |

## 5. Good / Base / Bad

- **Good**：CRC 覆盖到 FINGERPRINT 之前、Length 不改写（与 RFC 5769 三个向量一致）。
- **Base**：只在单测里断言「值存在且长度 4」。
- **Bad**：为算 CRC 而把 Length 改成「去掉 FINGERPRINT」的值 —— 会让**所有真实客户端**的指纹失效。

## 6. Tests Required（断言点）

1. RFC 5769 §2.1/§2.2/§2.3 的 `crc32` 向量（`e57a3bcf` / `c07d4c96` / `c8fb0b4c`）。
2. FINGERPRINT 五态（缺席/合法/错值/非末位/drop），含 TCP 与 UDP。
3. 默认关闭：带错值指纹的请求与裸请求**逐字节相同**。
4. 300：IPv4 56B / IPv6 68B、`stun-types` 解出地址、带 `CHANGE-REQUEST` 仍 300。
5. 500：映射表单测 + 真实触发（`RESPONSE-PORT 0` → EINVAL）+ 固定 40B。
6. 新旧二进制字节对照（至少 17 请求 × 3 配置）全部一致。
7. `cargo +nightly fuzz build parse` 必须可编译（`#[path]` 引入的模块要一并声明，见 §7）。

## 7. Wrong vs Correct

#### Wrong
```rust
// 设计初稿的错误写法：去掉 FINGERPRINT 后重算 Length
let len = frame_len - 8;
let crc = crc32(&with_length(frame, len)) ^ 0x5354554e;
```
```rust
// fuzz target 只引入 protocol，不引入新模块 → 编译失败
#[path = "../../src/protocol.rs"] mod protocol;
```

#### Correct
```rust
// CRC 覆盖到属性之前；头部 Length 不改（已包含 FINGERPRINT）
let crc = crc32(&frame[..HEADER_LEN + offset]) ^ 0x5354554e;
```
```rust
#[path = "../../src/crc32.rs"] mod crc32;
#[path = "../../src/protocol.rs"] mod protocol;
```
