# 设计：REQUESTED-ADDRESS-FAMILY（0x0017）

## 1. 属性语义（RFC 8656 §18.6）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Family     |                 Reserved                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `Family`：`0x01` IPv4、`0x02` IPv6（RFC 8489 §14.1）。
- `Reserved`：客户端置零，**服务端必须忽略**（不要因为非零回 400）。
- 出现在 `Allocate` 与 `Refresh`。

## 2. 处理流程（插在现有 Allocate 分支）

现状（`src/turn.rs`）：

```
turn_unknown_attributes(body)      // ~838：未知 comprehension-required → 420
... auth ...
egress_ip(local, peer)             // ~1018：决定 relay 地址族
if relay_ip.is_ipv4() != peer.is_ipv4() -> 440   // 现有：客户端与 relay 族不一致
EVEN-PORT / RESERVATION-TOKEN 互斥 // ~1042
```

改动：

1. `turn_unknown_attributes`：把 `ATTR_REQUESTED_ADDRESS_FAMILY` 加进「已知」集合
   （与 `ATTR_EVEN_PORT` 等并列），使其不再触发 420。
2. 新增解析 `parse_requested_address_family(body) -> Result<Option<u8>, ()>`：
   - 缺失 → `Ok(None)`；长度 ≠ 4 → `Err(())`；`value[0]` = family。
3. 在 `egress_ip` 判定之后（此时 `relay_ip` 已知）：
   - `Err(())` → `400 Bad Request`；
   - `Some(0x01)` 且 `relay_ip.is_ipv6()` → `440`；
   - `Some(0x02)` 且 `relay_ip.is_ipv4()` → `440`；
   - `Some(其他)` → `440`（语义是「该族不支持」）；
   - `Some(匹配)` / `None` → 照旧分配。
   - 440 复用 `ERROR_ADDRESS_FAMILY_NOT_SUPPORTED`，计入 `rejected_family` 计数。
4. 互斥（§7.2 步骤 5）：`RESERVATION-TOKEN` 与 `EVEN-PORT` **或 RAF** 同时出现 → `400`。
   现有代码只查 `wants_even`，补 `raf.is_some()`。
5. `Refresh`：属性已「已知」→ 不再 420；本实现**忽略其值**（分配已存在，族不可变）。
   在代码注释里写明这是有意为之。

## 3. 兼容性与字节冻结

- 不带 RAF 的请求：路径与字节完全不变（`plain_response_bytes_are_frozen`、3×17 对照）。
- 带 RAF 的请求：由 420 变成 200/440/400 —— **这是本次唯一的行为变化**，
  需要更新 `docs/book/src/turn.md` 行为表，并在 `CHANGELOG` 的 Unreleased 里记明。
- 对端 `uclient -e`（隐含 RAF）会从 420 变为成功（IPv4 场景），这正是修复目标。

## 4. 测试

单测（`src/turn/tests.rs`，沿用 `Client`/`request`/`attributes_of` 辅助）：

| 用例 | 断言 |
| --- | --- |
| RAF=IPv4 + IPv4 客户端 | `200`，有 XOR-RELAYED-ADDRESS |
| RAF=IPv6 + IPv4 客户端 | `440` |
| RAF 长度 3 | `400` |
| RAF family=0x03 | `440` |
| RAF reserved 非零 | 仍然 `200`（必须忽略）|
| RESERVATION-TOKEN + RAF | `400` |
| Refresh 带 RAF | 非 `420`（`200` 或既有 437/438 口径）|
| 未知属性 0x001A | 仍 `420` 且 UNKNOWN-ATTRIBUTES=[0x001A] |

lab（`script/lab/rstun-turn.sh`）：新增 `raf` 项，用真实 `turnutils_uclient` 跑
`-S -X`（期望成功）、`-S -x`（期望 `error 440`）、`-S -g`（期望 `error 420`）；
lean 下该项按 `turnutils` 可用性 SKIP（与现有项一致）。

## 5. 文档与 spec

- `docs/book/src/turn.md`：行为表加 RAF 行；「不支持」列表去掉 RAF（保留 DF）；
- `src/turn.rs` 头注释（25-26 行）：从「answered 420」改为「RAF 已解析；DF 故意 420」；
- `.trellis/spec/backend/turn.md`：契约 + tests required 增补；
- `README` 若提到这两个属性一并改。

## 6. 回滚

单 commit；回滚 = revert（只涉及 `src/turn.rs`、`src/turn/tests.rs`、lab 脚本、文档、spec）。
不发版，因此不涉及已发布产物。
