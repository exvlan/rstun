# 设计：抗滥用（限速 / 并发 / 反射防护）

## 1. 边界

- 只在前置路径（parse 之后、`decide()` 之前）做**准入判定**；不改协议语义。
- 状态只在本进程内存中，不落盘、不跨实例共享。
- **默认全部关闭**：关闭时 `decide()` 与响应字节与 `26.410.100` 完全一致（冻结测试继续生效）。

## 2. 威胁模型（决定算法）

| 威胁 | 特征 | 有效防线 |
| --- | --- | --- |
| 真实客户端滥用 | 固定源 IP、高频 | 每源 IP 令牌桶 |
| **伪造源反射** | 源 IP 随机、请求小、响应大 | **反射防护**：管辖范围内（UDP + 能重定向）的请求用 `max(请求 × ratio, 请求 + 32)` 判定，小请求省略 SOFTWARE 把放大压到固有下限（2.00× / 1.14×）|
| 单点洪水 | 任意源、总量巨大 | 全局速率上限 + 并发上限（Semaphore）|
| 定向封禁需求 | 少量网段 | CIDR allow/deny |

> 关键结论：**每 IP 限速对伪造源无效**（源 IP 每包都不同），
> 所以反射防护必须独立成立：任何会改变目的/来源地址的属性（`RESPONSE-PORT`、`CHANGE-REQUEST`），
> 只在「请求 ≥ `--reflect-min-request`（默认 20）」且「响应 ≤ `max(请求 × ratio, 请求 + 32)`」
> （默认 ratio 2.0）时处理；否则 400 或静默丢弃。

## 3. 关键取舍

| 主题 | 选择 | 理由 | 备选（弃） |
| --- | --- | --- | --- |
| 桶结构 | 分片 `Mutex<HashMap<IpAddr, Bucket>>`（64 片，按 IP hash） | 零新依赖；64 片足够降低争用 | `dashmap`（新增依赖）|
| 回收 | 惰性：取桶时若 `last_seen` 超过 10 分钟则重置；后台每 60s 扫一轮，条目上限 65536；表满时每 32 次回收做一次全扫描找最旧条目，其余按 HashMap 顺序丢一条（摊薄 O(1024)） | 无 LRU 依赖，内存有硬上限，且洪水下不出现 O(n²) | 定时全量重建（抖动）|
| 令牌精度 | 毫秒级 `Instant` 差值 + `f64` 令牌 | 简单、误差可忽略 | 整数时钟（累计误差）|
| 全局并发 | `tokio::sync::Semaphore`（默认 4096 在途）。**UDP：每 datagram `try_acquire` 后 `spawn` 处理**（仅在设置了 `--max-inflight` 时）；TCP：`accept` 取槽、连接关闭释放 | UDP 无连接但处理是异步的；串行循环只持 1 个 permit，上限永不触发（复核发现） | 不限（fd 耗尽）|
| 超限行为 | UDP：静默丢弃并计数；TCP：回复 500 后关闭？否 —— **直接关闭**（避免放大） | 与「不放大」一致 | 回 486（TURN 语义，不适用于 STUN）|
| allow/deny | 最长前缀匹配（`Vec<(IpNet, bool)>` 线性扫描，条目少） | 配置通常 < 20 条 | trie（过度设计）|

## 4. 默认参数（可配）

| 参数 | 默认 | 推导 |
| --- | --- | --- |
| 每源 IP 速率 | **200 req/s**，突发 400 | 家用 NAT 后 50 台设备、ICE 连通性检查突发（每设备数十包/秒）也不误伤 |
| 每源 IP+端口 | 20 req/s | 单客户端的正常上限；防单端口刷 |
| 全局速率 | 20000 req/s | 单核 ~5–10 万 pps 的 1/5，留余量 |
| 在途上限 | 4096 | 与 64KiB 缓冲 × 4096 ≈ 256 MiB 峰值可控 |
| 反射防护最小请求 | **20 字节**（= STUN 头长） | 只挡「不成帧」的输入。能携带 `RESPONSE-PORT` 的最小请求是 28 字节（20 + 8）；取 40 会先于比例规则挡掉 coturn `stunclient` 的全部 RFC 5780 探测（复核实测：3 响应 → 0） |
| 放大比上限 | **2.0**，加**固定 32 字节余量**：`allowed = max(请求 × ratio, 请求 + 32)` | 32 = 重定向响应必带的固定属性（`XOR-MAPPED-ADDRESS` 12，`--alt-listen` 再加 `RESPONSE-ORIGIN` + `OTHER-ADDRESS` 24）；`SOFTWARE` 是可选属性、小请求会省略，因此不计入余量。28 字节探针：无 alt 32B（1.14×）、有 alt 56B（2.00×），都在 60 以内 |
| 小请求省略 SOFTWARE | 请求带重定向属性（`RESPONSE-PORT` / `CHANGE-REQUEST`）且长度 < **40** 字节时，成功响应不带 `SOFTWARE`（RFC 5389 §15.5.1 可选属性）；≥40 字节与普通 Binding 保持现状 | 带 alt-listen 76→**56**、无 alt-listen 52→**32**：把响应压到「固有属性」的极限，比例规则才真的能拒（否则允许值恒大于任何合法响应，防护空转）。**仅开启防护时生效**，关闭时与 26.410.100 逐字节一致 | 在 codec 里加分支（拒绝：省略在 `SuccessResponse.software` 参数层完成）|
| 反射拒绝动作 | 400（40 字节）仅当 `40 ≤ 请求 × ratio`（**严格**，不含 32 字节余量）；否则静默丢弃 | 拒绝本身不许放大：400 不带固定属性，所以不吃余量 |
| 限速表条目上限 | 65536 | 约 4 MiB（每条约 64B）|

## 5. 数据流

```
recv → 长度 < MIN_FRAME(20) → 丢弃
     → 名单（deny 优先 → 拒绝；allow 命中 → 跳过每源桶与反射防护）
     → 在途上限（Semaphore，满则丢弃 + 计数）
     → 全局限速 → 每 IP → 每 IP+port 令牌桶（空则丢弃 + 计数）
     → parse → 方法/类判定（反射防护需要属性表）
     → 反射防护判定（仅 UDP；带 RESPONSE-PORT，或带 CHANGE-REQUEST 且 plan 存在时）：
          名单命中 allow → 豁免
          请求 < min_size → 拒绝（400 或丢弃）
          预估响应 > max(请求 × ratio, 请求 + 32) → 拒绝（400 或丢弃）
            （预估与 decide 用同一个 SOFTWARE 决策，见下）
          PADDING + RESPONSE-PORT 的 §6 400 也走这条拒绝路径
     → decide() → 发送
          带重定向属性且 < 40 字节 → 成功响应省略 SOFTWARE（固定开销只剩 12/36 字节）
```

顺序是**名单 → 在途 → 速率**：`--deny` 是运维决定，不该被报成「在途已满」；因为容量被拒的
请求也不该白烧一个限速令牌。`allow` 只跳过每源桶与反射防护，全局限速/在途上限照旧。

## 6. 兼容性

- 开关关闭：不创建桶表、不注册后台清理任务、不改变任何路径。
- 开关打开：`--rate-limit`、`--rate-burst`、`--global-rate`、`--max-inflight`、
  `--reflect-min-request`、`--reflect-ratio`、`--allow`、`--deny`（可重复）。
- 指标（若 ops 已上线）：`rstun_rate_limited_total{scope=ip|ip_port|global}`、`rstun_reflect_rejected_total`、
  `rstun_inflight_dropped_total`；未上线时先写退出统计（`rstun: abuse guard counters` 一行）。
- 反射拒绝与其它拒绝一致：除 `reflect_rejected` 外也计入 `dropped`。
- **`--max-inflight` 的 UDP 形状**：设置时才「每 datagram 一个任务」，未设置时保持串行 ——
  默认关闭路径零额外 spawn。

## 7. 回滚

运行时关闭配置即恢复原行为；代码回滚为单批 commit（新增模块 + 少量接线），无数据迁移。
