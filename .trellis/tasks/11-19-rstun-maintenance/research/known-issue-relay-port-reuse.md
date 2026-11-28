# 观察：UDP relay 端口池「不复用」（与多实例改动无关）

- 来源：2026-11-28 多实例冷复核的独立压测（`11-28-rstun-turn-multi-instance`），复核原文：
  「每轮 `Allocate` + `Refresh(0)` 后端口从 49500 → 49502 → 49504 前进；`used_ports` 释放了，
  但 `take_port` 只发偶数端口且不回到起点，100 端口段约 50 次分配后 508。」
- 代码：`src/turn.rs:1066-1085` `take_port` 每次从 `lo` 扫描，跳过 `used_ports` 命中项；
  bind 失败即跳过（注释写明「held by someone else … skip it」）。本次多实例改动**未触碰**该函数。
- **已验证（2026-11-28 复验实测，假设被否定）**：`Allocate → Refresh(LIFETIME=0)` 后 **500ms**，
  该端口在 `ss -lun` 中已不存在（`port_still_bound_after_500ms=False`），但下一次仍从 49500 跳到 49502：

  ```
  round 0: relay=('127.0.0.1', 49500) active=0.0 port_still_bound_after_500ms=False
  round 1: relay=('127.0.0.1', 49502) active=0.0 port_still_bound_after_500ms=False
  ```

  所以**不是异步释放延迟**，是端口池真的不回起点。原因待查：`take_port` 从 `lo` 扫描、`used_ports`
  应已删除该项；怀疑与 `even`（只发偶数）后 `lo` 的推进或 `used_ports` 未删除有关（`src/turn.rs:1066-1085`）。
- 影响面：lab/压测里会放大端口消耗（`bandwidth` 项曾因 508 假红，已加重试）；生产上若客户端轮换频繁，
  有效容量可能远低于配置段大小（100 段 ≈ 50 次分配）。
- 结论：**确认是缺陷**，但不属于 `11-28-rstun-turn-multi-instance` 的范围（该任务未触碰 `take_port`）。
  待单独立项修复 + 回归测试（`Allocate → Refresh(0) → Allocate` 必须拿回同一端口）。
