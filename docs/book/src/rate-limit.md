# 抗滥用（限速 / 并发 / 反射防护）

默认全部关闭；开启后只做准入，正常应答字节不变。含参数表、判定顺序、反射防护的实测放大表、
观测（退出统计与 `/metrics`）与 NAT 误伤排查。

公网裸跑的 STUN 服务器同时面对两种**性质不同**的滥用，必须用不同防线：

| 威胁 | 特征 | 有效防线 |
| --- | --- | --- |
| 真实客户端 / 单机滥用 | 固定源 IP、高频 | 每源 IP、每源 IP+端口 令牌桶 |
| **伪造源反射** | 源 IP 每包都不同、请求小、响应大 | 每 IP 限速**无效**（每包都是新桶）；只能靠**反射防护**（最小请求尺寸 + 放大比）|
| 单点洪水 | 任意源、总量巨大 | 全局限速 + 在途上限（Semaphore）|
| 定向封禁 | 少量网段 | `--allow` / `--deny` CIDR |

**默认全部关闭**：不给任何 `--rate-limit` 族参数时，不建哈希表、不建信号量、不起后台清理任务，
`decide()` 与响应字节与 `26.410.100` 完全一致（`plain_response_bytes_are_frozen` 与
`enabled_guard_leaves_plain_answers_byte_identical` 两条测试锁住）。开启后只做**准入**：
超限的请求在 `decide()` **之前**被丢弃（UDP）或关闭连接（TCP），正常请求看到的内容一个字节都不变。

## 参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--rate-limit [REQ/S]` | 关（裸写 = 200） | 每**源 IP** 令牌桶；UDP 与 TCP 共用同一张表 |
| `--rate-burst N` | `2 × rate`（200 → 400） | 上面的桶容量；要求 `--rate-limit` |
| `--rate-limit-port [REQ/S]` | 关（裸写 = 20，突发也是 2 × rate） | 每**源 IP + 源端口**令牌桶；防单端口刷。TCP 上「源端口」就是连接本身，所以等价于每条连接一个桶 |
| `--global-rate REQ/S` | 关（突发 2 × rate） | 全局限速（与源无关） |
| `--max-inflight N` | 关（文档值 4096） | 在途上限：UDP 一个 datagram 一个槽位（应答后释放），TCP 一条连接一个槽位（关闭前一直占着）；满时 UDP 静默丢、TCP 拒绝连接 |
| `--reflect-min-request BYTES` | 关（开启后 **20** = STUN 头长） | 含 `RESPONSE-PORT`/`CHANGE-REQUEST` 的请求小于此值才拒绝。20 只挡「不成帧」的输入：能携带该属性的最小请求是 28 字节，调高会先于比例规则挡掉真实探针 |
| `--reflect-ratio RATIO` | 关（开启后 **2.0**，另加固定 32 字节余量） | 响应上限 = `max(请求 × RATIO, 请求 + 32)`；小请求的应答还会省略可选的 `SOFTWARE`。见下文「反射防护」的实测表 |
| `--allow CIDR` | 空（可重复） | 命中者**跳过**每源 IP / 每源端口桶**与反射防护**（NAT 出口、可信探测网段） |
| `--deny CIDR` | 空（可重复） | 命中者直接拒绝；与 `--allow` 同前缀长度时 **deny 赢** |

默认值的推导（[设计稿](https://github.com/exvlan/rstun/blob/main/.trellis/tasks/11-19-rstun-dist/design.md) §4）：家用 NAT 后 50 台设备做 ICE 连通性检查，每台每秒数十包，
所以每 IP 给到 200 req/s / 突发 400 不会误伤；全局限速取单核 pps 的 1/5 留余量；
`--max-inflight 4096` 对应 64 KiB 接收缓冲 × 4096 ≈ 256 MiB 的峰值上限。

开关的「值可选」写法让两个目标同时成立：`--rate-limit` 用文档默认值（200），
`--rate-limit 50` 显式覆盖，不给就是**关闭**。`0`、负数、`--rate-burst` 单独出现、
`--reflect-min-request < 20`、`--reflect-ratio <= 0`、非法 CIDR 一律**启动失败**（退出码 1/2），
不会静默降级成「看起来开了、其实没拦」。

## 判定顺序

```
recv → 名单（deny 优先 → 直接拒；allow 命中 → 跳过每源桶与反射防护）
     → 在途上限（Semaphore，满则丢）
     → 全局限速 → 每源 IP → 每源 IP+端口
     → FINGERPRINT 校验（--check-fingerprint：结构错误 400，不匹配 400 或丢弃）
     → 反射防护（仅 UDP；带 RESPONSE-PORT，或带 CHANGE-REQUEST 且启用了 --alt-listen）
       └ PADDING + RESPONSE-PORT 的 §6 400 也走这条「拒绝不许放大」的路径
     → decide()（300 / 420 / 400 / 200）→ 发送（send_to 失败按映射回 500）
```

顺序与代码一致（`Admission::admit` = 名单 → 在途 → 速率）：运维的 `--deny` 不该被报成
「在途已满」，而因为容量被拒的请求也不该白烧一个限速令牌。

「在途」按传输方式计不同的单位，因为占用的资源不同：**UDP 是「一个 datagram」**
（准入通过到 `send_to` 之后释放，限制同时占着 64 KiB 缓冲的请求数）；**TCP 是「一条连接」**
（`accept` 时取槽、连接关闭才释放，限制 fd 与任务数）。TCP 的请求级限速仍然每次查桶，
否则一条连接就能流水无限请求；把连接槽位也算进每次请求，会让 `--max-inflight N` 实际只能服务
`N/2` 条连接，所以两者是分开的。

注意 UDP 的实现形状：**只有设置了 `--max-inflight` 时**才「每个 datagram 一个任务」
（拿不到槽位就丢并计数）；未设置时仍是单任务串行循环，不额外 spawn —— 默认路径不变。
串行循环里一个 listener 最多只持有一个槽位，所以「串行 + 上限」等于没有上限，这正是
`--max-inflight` 之前对 UDP 空转的原因。

## 反射防护（核心）

`RESPONSE-PORT`（把响应发到任意**目的端口**）和 `CHANGE-REQUEST`（把响应从**另一个源地址**发出，
只有 `--alt-listen` 给了第二个地址时才成立）都能让一个很小的伪造源请求换来一个指向受害者的
较大响应。两条规则独立生效：

1. 请求长度 < `--reflect-min-request`（默认 **20**，即 STUN 头长）→ 拒绝。
   这是「是不是一个 STUN 帧」的门槛，**不是**「探针够不够大」的门槛：能携带
   `RESPONSE-PORT` 的最小请求是 28 字节，若把门槛取成 40，就会先于比例规则把 coturn
   `stunclient` 的全部 RFC 5780 探测挡掉（实测：3 个响应变成 0 个）。
2. 用**真实编码器**估算的响应长度 > `max(请求 × --reflect-ratio, 请求 + 32)`
   （默认 ratio **2.0**）→ 拒绝。

**32 字节余量的来历**：每个重定向响应必带 `XOR-MAPPED-ADDRESS`（12 字节），
带 `--alt-listen` 还要 `RESPONSE-ORIGIN` + `OTHER-ADDRESS`（24 字节）——正好 32。
`SOFTWARE`（20 字节）是**可选**属性（RFC 5389 §15.5.1），防护开启时**小请求的成功响应会省略它**，
所以它不该进余量。省略后响应就只剩「固有属性」，放大被压到协议下限：

| 场景 | 请求 | 响应 | 放大 | `allowed = max(len×2, len+32)` | SOFTWARE |
| --- | --- | --- | --- | --- | --- |
| `--alt-listen`，28 字节 `RESPONSE-PORT` 探针 | 28 | **56** | 2.00× | 60 ✓ | 无 |
| 无 `--alt-listen`，28 字节探针 | 28 | **32** | 1.14× | 60 ✓ | 无 |
| `--alt-listen`，40 字节探针 | 40 | **76** | 1.90× | 80 ✓ | 有 |
| 无 `--alt-listen`，20 字节普通 Binding | 20 | 52 | 2.60× | 不走本防护（无重定向属性） | 有 |

（以上为生产二进制实测字节数；`script/lab/rstun-abuse.sh` 的 `reflect` 组逐条断言这些值。）

这套规则的意义在于**它真的能拒**。例如 `--alt-listen` 下一个 40 字节的
「`CHANGE-REQUEST` + `PADDING 8`」请求本来会得到 `76 + 12 = 88` 字节，超过
`max(80, 72) = 80`，于是被拒（回 40 字节的 400，且重定向目标地址一个包都收不到）。
而同一探针把 `PADDING` 加到 16（请求 48 字节）后响应 92 ≤ `max(96, 80)`，又会被放行 ——
规则是「**答复不许比你发来的大**」，不是「禁止 PADDING」。

拒绝时优先回 `400 Bad Request`（**40 字节** = 20 头 + 20 的 `ERROR-CODE`）；如果这 40 字节
超过**严格**的 `请求 × ratio`（注意：**不含**上面那 32 字节余量，因为 400 不带那些固定属性），
就改为**静默丢弃**。于是「拒绝本身」永远不会放大。`PADDING` + `RESPONSE-PORT` 的 §6 400
也走同一条路径（同样计数、同样受这条规则约束）。

**省略 `SOFTWARE` 的边界**（这是可选属性的合规用法，不是协议改动）：

- 只在**开启防护**时生效：关掉防护后，28 字节探针的响应仍是 52 字节（含 `SOFTWARE`），
  与 26.410.100 逐字节一致（`plain_response_bytes_are_frozen` /
  `enabled_guard_leaves_plain_answers_byte_identical` 锁住）。
- 省略 `SOFTWARE` 的**域与防护的域完全相同**（`redirect_is_guarded`）：只有 **UDP**、且该请求
  **确实能重定向**（`RESPONSE-PORT` 总是；`CHANGE-REQUEST` 仅 `--alt-listen` 下）且**小于 40 字节**
  时才省略。所以 TCP 上的探针、无 `--alt-listen` 时的 `CHANGE-REQUEST`、普通 Binding、
  ≥ 40 字节的探针（如 PADDING 探针）都照旧带 `SOFTWARE`（实测：TCP + 28B `RESPONSE-PORT`
  → 76 字节含 `SOFTWARE`；UDP 无 alt + 28B `CHANGE-REQUEST` → 52 字节含 `SOFTWARE`）。

边界与已知项：

- **`--allow` 命中的源豁免反射防护**（整段可信探测网段 / 监控主机）。它们仍然受全局限速与
  在途上限约束，除非连每源桶也被 `--allow` 跳过。
- **放大比只约束带 `RESPONSE-PORT` / `CHANGE-REQUEST` 的请求**。其它响应不在本防护范围，
  而且这条面**确实还能放大**（26.410.100 就如此，`plain_response_bytes_are_frozen` 冻结）：
  20 字节普通 Binding 在 `--alt-listen` 下得到 **76 字节 = 3.80×**（无 alt-listen 52 字节 = 2.60×）；
  24 字节未知属性得到 `420` **56 字节 = 2.33×**（28 字节请求则是 2.00×）。
  这正是每源 IP 令牌桶存在的理由：无属性放大面靠限速兜底，不靠本条防护。
- **`--alternate-server` 的 300 也在这条规则之外**：20 字节普通 Binding → **56 字节（2.80×）**，
  与 `420`（2.33×）/ 普通 Binding（3.80×）同属「无重定向属性的应答」。带 `RESPONSE-PORT` /
  `CHANGE-REQUEST` 的请求仍受本防护管辖，且估算的是**实发的 300**（56 字节），不是成功响应。
- **`500 Server Error` 固定 40 字节**（`ERROR-CODE` 只有一句固定文案），且只在原本「回不了包」的
  路径出现；请求 < 20 字节根本不会被解析，所以它不构成新的放大面。
- 不带 `--alt-listen` 时 `CHANGE-REQUEST` 无法换源（我们没有第二个地址），因此**不触发**本防护；
  否则 28 字节的普通探针会被白拒。
- **兼容 coturn**：`turnutils_stunclient` 打 `--alt-listen` 且开启防护（不调参）时，
  3 个 RFC 5780 响应齐全、`exit 0`（`script/lab/rstun-abuse.sh` 的 `reflect` / `reflect-reject`
  组与判决实验都验这条）。

## 观测

不新增**独立**端点：这组计数与 `/metrics` 同源 —— 开了 `--health-listen` 时从
`rstun_rate_limited_total{scope=ip|ip_port|global}`、`rstun_inflight_dropped_total`、
`rstun_reflect_rejected_total`、`rstun_denied_total`、`rstun_allowlisted_total`、
`rstun_fingerprint_rejected_total` 读；不开 `--health-listen` 时只有日志可见：

- 退出（Ctrl-C / `SIGTERM`）时多打印一行：
  `rstun: abuse guard counters rate_limited_ip=… rate_limited_port=… rate_limited_global=… inflight_dropped=… denied=… reflect_rejected=… allowlisted=…`；
  随后的 `rstun: stopped` 行里另有 `fingerprint_rejected=`（`--check-fingerprint` 的拒绝数，
  drop 模式下同样计数、并额外 +1 `dropped`）。
- `--verbose`（`debug`）下，每个被拒请求打印 `reason=`（`denied (CIDR)` / `in-flight cap` /
  `global rate` / `per-source-IP rate` / `per-source-port rate`）与对应 `counter=` 字段。
- 反射拒绝会**同时** +1 到 `reflect_rejected` 与 `dropped`；如果那条 400 真的发出去了，
  `answered` 也会 +1。所以 `received = answered + dropped` **不成立** —— 一个反射拒绝
  既是 dropped 也是 answered，看 `reflect_rejected` 才是准确口径。

`script/lab/rstun-abuse.sh` 把这些计数与真实 socket 行为做成对照实验（关/开限速、单源洪水、
反射防护默认值与严格门槛、allow/deny、`--max-inflight`、TCP 洪水），逐条断言真实字节数与放大比，
是本节的验收脚本。

## NAT 误伤排查

1. **先确认是限速**：`--verbose` 看到 `per-source-IP rate` 的拒绝行，或退出统计里
   `rate_limited_ip` 在涨，才是阈值问题（`dropped` 涨但 `rate_limited_*` 不涨 → 是畸形包）。
2. **整段放行**：出口 NAT / 监控探测网段加 `--allow 203.0.113.0/24`。注意 `--allow`
   只跳过**每源**桶，全局限速与在途上限仍然生效（那两个保护的是进程，不是公平性）。
3. **确认分桶口径**：桶按**归一化后的源 IP** 计（`::ffff:a.b.c.d` 折叠成 IPv4），
   所以同一个双栈客户端不会拿到两个桶；NAT 后所有设备共享出口 IP，也就是共享一个桶。
4. **别指望每 IP 限速挡伪造源**：源地址每包都变时，每包都拿到全新满桶。那种流量只能靠
   反射防护（它不依赖源地址）与全局/在途上限。
5. **反射防护误伤**：退出统计里 `reflect_rejected` 在涨、而 `rate_limited_*` 不动，
   就是放大规则在拒 —— 给探测网段加 `--allow`（完全豁免），或调 `--reflect-min-request` /
   `--reflect-ratio`。`--verbose` 下被拒请求带 `reason=` / `counter=`。

## 局限（明确不做）

- 状态只在**本进程内存**：不落盘、不跨实例共享，重启即清零；多实例部署时每个实例各自计数。
- 表有硬上限（65536 条约 4 MiB，64 分片，10 分钟不活跃即回收、每 60 秒清扫一次）：
  满了回收最久未用的条目，所以**不能**用它做长期审计。
- 不做内容 DPI，也不按协议模式封禁。
