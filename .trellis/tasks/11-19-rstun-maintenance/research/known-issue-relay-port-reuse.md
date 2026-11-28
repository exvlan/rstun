# 观察（**已撤回**）：所谓「UDP relay 端口池不复用」其实是 `EVEN-PORT` 预留语义

> 2026-11-28 更正。前一版把「49500 → 49502 → 49504 递增、100 段约 50 次分配后 508」记成
> 「确认缺陷」——**该结论错误**，实测与代码都表明端口池本身正常。

## 实测结论

同一个 relay 段 `61000-61004`、同样的「分配 → `Refresh(0)` → 再分配」循环：

| 客户端请求 | 结果 |
| --- | --- |
| **带** `EVEN-PORT(R=1)`（lab 探针 `allocate_frame` 默认就带）| `61000 → 61002 → 61004`，第 3 次 `508` |
| **不带** `EVEN-PORT` | `61000 → 61000 → 61000 → 61000`，每次都回到同一端口 |

带临时日志的实测（已回滚）：

```
# 不带 EVEN-PORT
DBG take_port picked=61000 set={61000}
DBG release_port port=61000 tcp=false
DBG take_port picked=61000 set={61000}
...（4 轮完全一致）
```

## 为什么

`EVEN-PORT(R=1)`（RFC 8656 §7.2）要求服务端**预留下一个奇数端口**，等第二个 allocation 用
`RESERVATION-TOKEN` 来取。实现（`src/turn.rs` `take_even_port_with_reservation`）把
`port` 与 `port+1` **都**记进 `used_ports`；allocation 释放时只归还偶数口，奇数口作为
**预留**保留 30 秒（`RESERVATION_LIFETIME`），过期后由 `sweep` 归还。

所以一段 N 个端口，在 30 秒窗口内最多服务约 **N/2** 个带 `EVEN-PORT` 的分配 —— 这是规范行为，
不是泄漏。lab/压测之所以撞到 508，是因为 `turnutils_uclient` 与我们的探针**默认都带 EVEN-PORT**，
而且连续跑得多、间隔小于 30 秒。

## 影响与处置

- **代码无需修改**；`bandwidth` 项历史上那次 `508` 也就是这个原因（连续 uclient + 紧端口段），
  已有的「限速后仍能中继」508 重试仍是对症的。
- **文档已补**：`docs/book/src/turn.md` 的「端口与配额」行写明 EVEN-PORT 的 30 秒预留与容量减半。
- **lab 建议**（未改）：多轮分配类用例可以显式不带 EVEN-PORT（或把端口段放大一倍），
  避免把「规范预留」误判成容量不足；现有 `bandwidth` 重试保留即可。
- **教训**：验证端口池类问题必须控制「客户端是否请求 EVEN-PORT」这个变量；
  只看 `ss` 与分配到的端口号会把预留语义看成泄漏。
