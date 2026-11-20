# TURN 二期（TCP allocation / DONT-FRAGMENT / 地址族选择）

> 前身是「TURN 父任务」：T1（UDP 中继）与 T2（TLS/DTLS/REST/带宽）均已完成并归档。
> 本任务承接**二期能力**，不重复已完成部分。

## Goal

补齐 RFC 8656 中**尚未实现**的中继能力，使 TURN 覆盖面接近 coturn 的常用集合。

## 需求

1. **TCP allocation（RFC 6062）**：`Allocate` 的 `REQUESTED-TRANSPORT=6` →
   为客户端建立到 peer 的 TCP 连接（`Connect` / `ConnectionBind` / `ConnectionAttempt` indication），
   当前回 442（Unsupported Transport Protocol）。
2. **`DONT-FRAGMENT`**：目前作为未知 comprehension-required 回 **420**；应识别并按 §7.2 语义处理
   （设置 DF 位；平台不支持时按 RFC 返回错误）。
3. **`REQUESTED-ADDRESS-FAMILY`**：当前 420；应支持选择 relay 地址族（IPv4/IPv6），
   与 `--listen`/`--listen-v6` 的 relay 绑定配合。
4. **多实例共享 allocation 状态**：当前只共享 nonce secret；跨实例的 5 元组一致性无保证。
   （可选，取决于部署形态。）
5. **`turns:` 的证书热加载**：当前重启生效（T2 记录）。

## 非目标

- 多租户/计费/数据库用户后端
- 跨机 relay 调度（anycast）
- TURN over QUIC（不存在标准）

## 验收（每条都需要可复现证据）

- [ ] RFC 6062：`turnutils_uclient -T`（或 coturn 对照）完成 TCP allocation 与数据中继；
      `ConnectionAttempt` 指示格式正确；`ConnectionBind` 生命周期与 §5 一致
- [ ] `DONT-FRAGMENT`：识别且不再 420；DF 位可被 `tcpdump`/socket 选项验证；不支持平台返回文档化错误
- [ ] `REQUESTED-ADDRESS-FAMILY`：v4/v6 relay 均可按请求分配（`XOR-RELAYED-ADDRESS` 家族正确）
- [ ] 与 coturn 对跑：三类能力的差异逐项判定（我方/对手/RFC 理解）
- [ ] 默认路径零差异：不启用新能力时，与当前 `main` 逐字节一致
- [ ] 依赖不新增（或新增必须在 PR 里单独说明体积/审计影响）

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
