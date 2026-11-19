# 抗滥用契约（限速 / 在途 / 反射防护 / 名单）

> 来源：2026-11-19 `rstun-abuse-guard` 四轮实现与冷复核（含 240 组合差分测试）。
> 任何修改这些路径的改动都必须满足本文；默认关闭是硬前提。

## 1. Scope / Trigger

- 修改 `src/limit.rs`（令牌桶/名单/计数）、`src/main.rs` 的准入路径、`script/lab/rstun-abuse.sh`；
- 新增任何「会改变响应大小」的规则（属性省略、PADDING、错误响应）；
- 调整默认阈值或防护开关语义。

## 2. Signatures（可执行契约）

| 项 | 契约 |
| --- | --- |
| `REFLECT_ALLOWANCE` | `32`（`XOR-MAPPED 12 + ORIGIN 12 + OTHER 12 - 头 20` 的固定开销，`SOFTWARE` 不计入）|
| 允许值 | `allowed = max(len_request × ratio, len_request + 32)`；默认 `ratio = 2.0` |
| 最小请求 | `--reflect-min-request` 默认 `20`（STUN 帧最小长度；40 会误杀 28 字节真实探针）|
| 管辖谓词 | `redirect_is_guarded(transport, message, context)`：**UDP** 且（有 `RESPONSE-PORT` 或（有 `CHANGE-REQUEST` 且 `plan.is_some()`））|
| 省略 SOFTWARE | 仅当 `redirect_is_guarded` 且 `len_request < 40`；普通 Binding、TCP、无 plan 的 UDP 一律保留 |
| 在途上限 | `--max-inflight` 默认**不限**；设置时 UDP 每 datagram `try_acquire` + spawn，未设置走串行（零额外 spawn）|
| 判定顺序 | 名单（deny 优先）→ 在途 → 速率桶 |
| 指标/统计 | `rate_limited_ip/port/global`、`inflight_dropped`、`denied`、`reflect_rejected`、`allowlisted` |

## 3. Contracts（放大算术，必须逐项有测试）

| 场景 | 请求 | 响应 | 放大 | 备注 |
| --- | --- | --- | --- | --- |
| alt-listen，28B 探针 | 28 | **56** | **2.00×** | 省略 SOFTWARE（固有下限）|
| 无 alt-listen，28B 探针 | 28 | **32** | 1.14× | 省略 SOFTWARE |
| alt-listen，40B 探针 | 40 | **76** | 1.90× | 含 SOFTWARE，allowed 80 |
| 无 alt-listen，20B 普通 Binding | 20 | 52 | 2.60× | **不受防护管辖**（无重定向属性）|
| alt-listen，20B 普通 Binding | 20 | 76 | **3.80×** | 同上；已知无属性放大面，靠每 IP 限速兜底 |
| 24B 未知 comprehension-required | 24 | 56 | 2.33× | `420`，既有行为，不受防护管辖 |

> **不可兼得**：RFC 5780 与「放大 ≤1×」数学冲突。带 alt-listen 的固有下限就是 2.0×；
> 靠「省略可选 SOFTWARE」压到这里，禁止为了让数字好看而删除 `XOR-MAPPED`/`ORIGIN`/`OTHER`。

## 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| 未开任何开关 | 不建表、不建信号量、不 spawn sweeper；响应字节与 `26.410.100` 完全一致 |
| 请求携带重定向属性且 `len < min_request` | 静默丢弃（UDP）/ 关闭连接（TCP），计 `reflect_rejected` |
| 预估/实发响应 > `allowed` | 400（若 400 本身 ≤ `allowed`），否则静默丢弃 |
| 反射拒绝 | `reflect_rejected` 与 `dropped` 同时 +1；发出 400 时 `answered` 也 +1 ⇒ `received = answered + dropped` **不成立** |
| 名单 deny 命中 | 拒绝且记 `denied`（不被记成 `inflight_dropped`）|
| `--allow` 命中 | 跳过每源桶与反射防护；**仍计全局速率与在途** |

## 5. Good / Base / Bad

- **Good**：`answer_software`（实发）与 `reflect_guard`（预估）调用**同一个** `redirect_is_guarded`；
  省略域 == 防护域。
- **Base**：只在一处判断「是否省略 SOFTWARE」，另一处按最大值估算。
- **Bad**：预估按「省略」算、实发按「不省略」写（或反之）⇒ 每个 ratio 边界都能被 1 字节绕过。

## 6. Tests Required（断言点）

1. 四个算术行（28/40 × alt/no-alt）的响应字节数与 SOFTWARE 有无。
2. `allowed` 边界：`allowed(28)=60`、`allowed(32)=64`、`allowed(33)=66`、`allowed(1000)=2000`（余量项与比例项各一例）。
3. 「确实会拒」：40B `CHANGE-REQUEST+PADDING8` → 目标口 0 包、`reflect_rejected=1`；48B（PADDING16）→ 96 = allowed 压线放行。
4. 默认关闭：`plain_response_bytes_are_frozen`（48B 十六进制）+ 与旧二进制 33 请求 × 3 配置逐字节一致。
5. `--max-inflight 1` + 300 包 → 应答显著少于 300 且 `inflight_dropped > 0`。
6. 脚本反向验证：把 `allowed_response_len()` 改成恒 1 → 脚本必须 FAIL 且 exit 1；`--only <未知>` → exit 2。

## 7. Wrong vs Correct

#### Wrong
```rust
// 预估处省略，实发处不省略（或条件不一致）
let estimate = encode(response_without_software).len();
let actual   = encode(response_with_software).len();
```

#### Correct
```rust
let software = answer_software(len, &message, context, transport); // 两处共用
let estimate = encode(response { software }).len();
let actual   = encode(response { software }).len();
```
