# 执行计划：抗滥用

> 复述：默认全部关闭；打开后不得改变协议语义，只做准入。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | 新增配置项（`--rate-limit`/`--rate-burst`/`--global-rate`/`--max-inflight`/`--reflect-*`/`--allow`/`--deny`），全部有默认值且默认关闭 | `--help` 输出；非法值（0、负数、反序 CIDR）启动失败 | 单 commit |
| 2 | 令牌桶模块 `limit.rs`：分片哈希表 + 惰性回收 + 条目上限；纯函数单测（时间推进用注入的 `Instant`） | 单测：速率/突发边界、条目满时的行为、时钟回退 | 单文件 revert |
| 3 | 全局 Semaphore + 在途上限 | 单测：`try_acquire` 满时拒绝；压测下不泄漏 permit | 同上 |
| 4 | 接入 UDP 路径（`serve_udp`）与 TCP（accept 后/请求级） | e2e：超限丢包并计数；未超限正常 | 同上 |
| 5 | **反射防护**：`RESPONSE-PORT`/`CHANGE-REQUEST` 请求最小尺寸 + 放大比判定 | e2e：20 字节伪造源请求被拒；40 字节正常；`PADDING` 放大比 ≤ 1 | 同上 |
| 6 | allow/deny CIDR | 单测：最长前缀、deny 优先、IPv6 映射地址 | 同上 |
| 7 | 统计输出：退出时打印 `rate_limited_*` / `reflect_rejected` / `inflight_dropped`；若 ops 的 metrics 已在，接入指标 | 退出日志断言 | 同上 |
| 8 | 压测脚本 `script/lab/rstun-abuse.sh`（单源洪水 / 多源伪造 / 反射尝试） | 脚本跑出三张对照表（关/开限速） | 新增文件 |
| 9 | README/文档：参数语义、默认值推导、NAT 误伤排查 | 人工评审 | 文档 commit |

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all          # 38 项 / 176 断言（默认关闭时不得回归）
bash script/lab/rstun-abuse.sh                # 新增：限速与反射对照
```

## 验收断言（必须出现）

- [ ] 默认关闭：`plain_response_bytes_are_frozen` 等冻结测试通过，且无后台任务启动
- [ ] 单源超限：该源后续请求被丢弃且计数增长；另一源不受影响
- [ ] 伪造源 + `RESPONSE-PORT`：响应 ≤ `max(请求 × ratio, 请求 + 32)`（默认 2.0 / 32；
      带 `--alt-listen` 固有下限 **2.00×**（28→56）、无 alt-listen **1.14×**（28→32），
      实测表见 README），且 `reflect_rejected` / `dropped` 计数可见
- [ ] 40 字节以上的合法 `RESPONSE-PORT` 请求：仍正常（不误伤，响应 52→76 视 alt-listen）
- [ ] 防护真的能拒：`--alt-listen` 下 40 字节「`CHANGE-REQUEST` + `PADDING 8`」→ 400（40 字节），
      重定向目标地址 **0 个包**
- [ ] `PADDING` 场景：响应字节 ≤ 请求字节（PADDING 回声恒等于请求；固定属性由 32 字节余量支付）
- [ ] 并发上限：TCP 洪水下进程存活、fd 稳定、无 panic
- [ ] 关闭开关后：行为与 `26.410.100` 一致（逐字节）

## 观察项（不做成硬断言）

- 桶表在 65536 条目时的内存与 P99 延迟 —— **未闭环**，转 `.trellis/tasks/11-19-rstun-qa`
  的基准项（`prd.md` 需求 1 已引用），不在本任务里做。

## 复核修复（2026-11-19，冷复核后的第二轮）

> 触发：第一轮实现全绿，但复核发现「文档承诺 ≠ 实测」两处阻塞。用户已拍板新口径，
> 逐条修完并以 `cargo test` / `rstun-abuse.sh` / `turnutils_stunclient` 判决实验复核。

| # | 问题 | 修法 | 状态 |
| --- | --- | --- | --- |
| F1 | 反射防护默认 `min 40 / ratio 1.0` 会把 coturn `stunclient` 的 28 字节 RFC 5780 探针全挡掉（`--alt-listen` 下 28→76 = 2.71×），README 推荐的 `1.3`/`--allow` 实测无效 | 默认改为 `min 20`、`ratio 2.0` + 固定余量；`--allow` 命中者豁免反射防护；README 算术整段改写为实测值（**第三轮把余量 64→32 并加 SOFTWARE 省略，见下**）| ✅ |
| F2 | `--max-inflight` 对 UDP 空转（串行循环每 listener 最多 1 permit，`--max-inflight 1` 仍 300/300 全答） | 仅在设置了 `--max-inflight` 时改为「每 datagram `try_acquire` → `spawn` 处理」，未设置时保持串行；实测 `--max-inflight 1` + 300 包 = 3 应答 / 297 `inflight_dropped` | ✅ |
| F3 | `PADDING`+`RESPONSE-PORT` 的 §6 400 绕过「拒绝不许放大」 | 改走 `reflection_refusal`（含计数与严格比例判定），补单测 | ✅ |
| F4 | 放大比适用范围未写明 | README 明确「只约束带 `RESPONSE-PORT`/`CHANGE-REQUEST` 的请求」，普通 Binding 1.86–2.6× 与 420 的 ~2.3× 登记为已知既有行为 | ✅ |
| F5 | 注释写「400 is 28 bytes」 | 改为 40 字节（20 头 + 20 `ERROR-CODE`） | ✅ |
| F6 | 脚本只打印不断言；`--only` 未知组「0 组运行 + 全部通过」 | 探针传入 ratio 并断言「真实字节数 ≤ `max(len×ratio, len+64)`」；`expect=none` 断言目标口 0 包；`--only` 白名单校验（未知 → exit 2） | ✅ |
| F7 | 条目上限测试没有真的验证「最旧条目被驱逐」 | 改为「填满同分片 → 推进时间 → 插入新 key → 断言最旧 key 被回收、其余保留」；另加全局上限测试 | ✅ |
| F8 | 文档与代码顺序不一致；反射拒绝不计 `dropped` | 代码改为 **名单 → 在途 → 速率**（`check_nets` / `acquire_inflight` / `check_buckets`），并加顺序单测；`reflection_refusal` 同时 `count_dropped()` | ✅ |
| F9 | 突发倍率 / per-port 分桶口径未写 | README 补 `--rate-limit-port` / `--global-rate` 突发 = 2×，TCP 上 per-port 桶即「每条连接」 | ✅ |
| F10 | 表满时每次插入都 O(1024) 扫描 | 改为每 32 次回收做一次全扫描、其余按 HashMap 顺序丢一条（首 次仍扫描，行为可测），注释给出摊薄成本 | ✅ |
| F11 | 无 `--alt-listen` 时 `CHANGE-REQUEST` 也触发反射防护（不可能是反射向量） | 仅当 `context.plan.is_some()` 时才把 `CHANGE-REQUEST` 纳入判定；补「无 plan 放行 / 有 plan 拒绝」单测 | ✅ |

判决实验（F1 验收核心）：`turnutils_stunclient -p 34780 127.0.0.1` 打
`--alt-listen` + 开启防护（不调参）→ **3 个 RFC 5780 响应、EXIT=0、`reflect_rejected=0`**。

## 第三轮（2026-11-19，定稿口径：让防护真的能拒）

> 第二轮把余量取 64 后，`allowed` 恒大于任何合法响应（最大 76 字节），防护对合法流量等于空转。
> 用户定稿：余量 **32**，并在小请求上省略可选的 `SOFTWARE` 把响应压到固有下限。

| 项 | 定稿 | 实现 |
| --- | --- | --- |
| 允许值 | `allowed = max(len × ratio, len + 32)`，`REFLECT_ALLOWANCE = 32` | `src/limit.rs`（`Reflect::allows_response`） |
| 小请求省略 SOFTWARE | 带 `RESPONSE-PORT` / `CHANGE-REQUEST` 且 < 40 字节的成功响应不带 `SOFTWARE`；≥40 字节与普通 Binding 不变；**仅开启防护时生效** | `src/main.rs::answer_software`（`decide` 与反射预估共用同一个值） |
| 实测算术 | alt 28→56（2.00×）、non-alt 28→32（1.14×）、alt 40→76（1.90×）、non-alt 20→52（2.60×，不走防护） | `script/lab/rstun-abuse.sh` 的 `reflect` 组逐条断言（含 SOFTWARE 有无） |
| 真能拒 | `--alt-listen` + 40 字节 `CHANGE-REQUEST` + `PADDING 8` → 88 > 80 → 400（40 字节、重定向目标 0 包） | 单测 `the_guard_actually_rejects_a_padded_redirect_probe` + 脚本 `reflect-reject` 组 |

## 第四轮（2026-11-19，第三轮冷复核的记账项）

> 结论是「可提交」，这里只收 6 条记账，不加功能、不重构。

| # | 项 | 处理 | 位置 |
| --- | --- | --- | --- |
| **F-A** | 省略 SOFTWARE 的「域」比防护的「域」宽：TCP 探针、无 plan 的 `CHANGE-REQUEST` 也被省略 | 抽出共用谓词 `redirect_is_guarded(transport, message, context)`（UDP + 能重定向），`reflect_guard` 与 `answer_software` 都用它；补三条单测（TCP 含 SOFTWARE / 无 plan 含 / 有 alt 不含） | `src/main.rs`（`redirect_is_guarded` / `answer_software`） |
| **F-B** | README 残余放大数字不是实测 | 改为实测：`--alt-listen` 20B 普通 Binding → 76B = **3.80×**、24B 未知属性 → 56B = **2.33×**（28B → 2.00×、无 alt 20B → 52B = 2.60×），并说明「防护不约束普通 Binding，靠每 IP 限速兜底」 | `README.md`「边界与已知项」 |
| **F-C** | `limit.rs` 测试注释残留 `2.0 + 64 bytes` | 改为 `2.0 + 32 bytes`（全文复查无 64 残留） | `src/limit.rs` |
| **F-D** | prd/design/implement 口径仍是旧说法 | prd 需求 3 + 验收、design 威胁表/关键结论、implement 验收断言全部改成本轮定稿（20 / 2.0 / +32 / 省略 SOFTWARE 的域） | 三个任务文档 |
| **F-E** | `script/lab/README.md` 写「9 组」 | 改为「10 组」 | `script/lab/README.md` |
| **F-F** | `counter()` 的 `dropped` 会命中 `inflight_dropped=` | 改为字段边界匹配 `(^\|[[:space:]])FIELD=`，实测 `dropped=20` / `inflight_dropped=0` 不再混淆 | `script/lab/rstun-abuse.sh` |
| **F-G** | 退出统计口径缺失 | README 补「反射拒绝同时 +1 `reflect_rejected` 与 `dropped`，400 发出时 `answered` 也 +1，所以 `received = answered + dropped` 不成立」 | `README.md`「观测」 |
| **F-I** | 65536 条目的内存 / P99 未测 | 观察项标注「未闭环，转 `rstun-qa` 基准项」，并在该任务 prd 的基准条目里加一行引用 | `implement.md` + `.trellis/tasks/11-19-rstun-qa/prd.md` |

## 回滚

- 单批 commit；关闭配置即可运行时恢复；无持久化数据。
