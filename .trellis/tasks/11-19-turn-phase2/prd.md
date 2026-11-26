# TURN 二期（TCP allocation / DONT-FRAGMENT / 地址族选择）

> 前身是「TURN 父任务」：T1（UDP 中继）与 T2（TLS/DTLS/REST/带宽）均已完成并归档。
> 本任务承接**二期能力**，不重复已完成部分。

## Goal

补齐 RFC 8656 中**尚未实现**的中继能力，使 TURN 覆盖面接近 coturn 的常用集合。

## 需求

1. **TCP allocation（RFC 6062）**：`Allocate` 的 `REQUESTED-TRANSPORT=6` →
   为客户端建立到 peer 的 TCP 连接（`Connect` / `ConnectionBind` / `ConnectionAttempt` indication），
   当前回 442（Unsupported Transport Protocol）。
2. ~~**`DONT-FRAGMENT`**~~：**已完成**（子任务 `11-21-rstun-turn-df-ipv6`，未发布）——
   unix（Linux/macOS/iOS）真支持 DF；其它平台按 §7.2 步骤 4 保持 `420`。
3. ~~**`REQUESTED-ADDRESS-FAMILY`**~~：**已完成**（子任务 `11-21-rstun-turn-raf`，随 `26.410.102` 发布）——
   族匹配正常分配、异族 `440`、`Refresh` 不匹配 `443`；relay 族跟随客户端。
   双分配 `ADDITIONAL-ADDRESS-FAMILY` 仍未实现（comprehension-optional，忽略）。
4. **多实例共享 allocation 状态**：当前只共享 nonce secret；跨实例的 5 元组一致性无保证。
   （可选，取决于部署形态。）
5. **`turns:` 的证书热加载**：当前重启生效（T2 记录）。

## 非目标

- 多租户/计费/数据库用户后端
- 跨机 relay 调度（anycast）
- TURN over QUIC（不存在标准）

## 验收（每条都需要可复现证据）

- [x] RFC 6062：出站随 `26.410.104` 发布；**被动模式**（`ConnectionAttempt`）已完成并合并
      (`0ec6c41`，子任务 `11-22-rstun-turn-passive` 已归档)——`turnutils_uclient -T`/`-P` 均完成，
      探针 14 断言与 coturn 4.6.1 逐行一致
- [x] `DONT-FRAGMENT`：随 `26.410.103` 发布（unix 真置位；其它平台按 §7.2 步骤 4 保持 `420`）
- [x] `REQUESTED-ADDRESS-FAMILY`：随 `26.410.102` 发布（族匹配 200 / 异族 `440` / `Refresh` 不匹配 `443`）
- [x] 与 coturn 对跑：三类能力差异逐项判定（出站/被动/DF/RAF 均已录入 spec 与 lab）
- [x] 默认路径零差异：`frozen` 3 配置 × 17 请求与 `cad4fa2` 逐字节一致
- [x] 依赖不新增（`libc` 为 unix-only DF 所需，已在 `.103` 单独说明；lean 10 / full 15 未变）
- [ ] **多实例共享 allocation 状态**：仍未实现（可选，取决于部署形态；当前只共享 nonce secret）

## 风险

| R | 缓解 |
| --- | --- |
| RFC 6062 复杂度高（连接生命周期、半开、超时） | 先做「客户端 → peer」单向 + `ConnectionBind`，再补 `ConnectionAttempt` |
| 新增 socket 类型影响资源上限 | 纳入现有 `--max-inflight`/配额与回收扫描 |
| 平台差异（DF 位在 macOS/Windows） | 用 `socket2` 现有能力，不支持时按 RFC 返回 400/500 并记录 |

## 备注

- 本任务的前置（T1/T2）已归档，设计可参考：
  `.trellis/tasks/archive/2026-11/11-19-rstun-turn-udp/design.md` 与 `…/11-19-rstun-turn-tls/design.md`。
- 开工前需补 `design.md` + `implement.md`（复杂任务）。

## 状态（2026-11-26）

子任务全部完成并归档：

| 子任务 | 结果 | 发布 |
| --- | --- | --- |
| `11-21-rstun-turn-raf` | RFC 8656 RAF（440/443/400） | `26.410.102` |
| `11-21-rstun-turn-df-ipv6` | DF 真置位 + IPv6 relay 回归 | `26.410.103` |
| `11-21-rstun-turn-rfc6062` | RFC 6062 出站（`Connect`/`ConnectionBind`） | `26.410.104` |
| `11-22-rstun-turn-cert-reload` | `turns:` 证书热载（SIGHUP + 轮询） | `26.410.104` |
| `11-22-rstun-turn-passive` | RFC 6062 被动（`ConnectionAttempt`） | **未发布**（在 `main`） |

唯一未做项是需求 4「多实例共享 allocation 状态」——需求里明确标注「可选，取决于部署形态」，
且与协议合规无关。是否要做属产品决策，未擅自开工。
