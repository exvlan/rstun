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
- [ ] 伪造源 + `RESPONSE-PORT`（20 字节请求）：**不产生响应**（或 400），日志/计数可见
- [ ] 40 字节以上的合法 `RESPONSE-PORT` 请求：仍正常（不误伤）
- [ ] `PADDING` 场景：响应字节 ≤ 请求字节
- [ ] 并发上限：TCP 洪水下进程存活、fd 稳定、无 panic
- [ ] 关闭开关后：行为与 `26.410.100` 一致（逐字节）

## 观察项（不做成硬断言）

- 桶表在 65536 条目时的内存与 P99 延迟（记录到 `docs/perf.md` 或任务 research）

## 回滚

- 单批 commit；关闭配置即可运行时恢复；无持久化数据。
