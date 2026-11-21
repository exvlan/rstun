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
   - **顺序要求**（复核 B1）：`RESERVATION-TOKEN` 互斥（步骤 5）必须先于族比对（步骤 7），
     否则「token + 异族 RAF」会错误地回 440 而不是 400。
   - 注意：relay 族**跟随客户端**，所以 IPv6 客户端会得到 IPv6 relay；本实现不支持的
     只是「与客户端族不同」的请求与双分配（AAF）——文档不得写成「IPv6 一律 440」。
4. 互斥（§7.2 步骤 5）：`RESERVATION-TOKEN` 与 `EVEN-PORT` **或 RAF** 同时出现 → `400`。
   现有代码只查 `wants_even`，补 `raf.is_some()`。
5. `Refresh`（§8.2 MUST）：属性已「已知」→ 不再 420；解析后与**现有分配**的 relay 族比对：
   - 匹配 → 正常续期（200）；
   - 不匹配 → `443 ERROR_PEER_ADDRESS_FAMILY_MISMATCH`，计 `rejected_family`；
   - 长度 ≠ 4 → `400`。
   （原稿「接受并忽略 → 200」偏离 §8.2，已废弃。）
6. `ADDITIONAL-ADDRESS-FAMILY (0x8000)` 继续忽略（comprehension-optional），
   因此 §7.2 步骤 6（RAF + AAF → 400）不生效 —— 需在 spec 显式记账。

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
| Refresh RAF 族匹配 | `200`，LIFETIME 正常续期 |
| Refresh RAF 族不匹配 | `443`（§8.2 MUST）|
| Refresh RAF 长度 3 | `400` |
| `RESERVATION-TOKEN + RAF(异族)` | `400`（步骤 5 先于步骤 7，复核 B1）|
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
