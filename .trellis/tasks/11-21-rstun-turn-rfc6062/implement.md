# 执行计划：RFC 6062（出站 + ConnectionBind）

> 顺序设计：先「能通」（Allocate/Connect/Bind），再「正确」（错误码/超时/联动关闭），最后「可验收」（lab/coturn）。
> 每阶段结束都跑门禁；不 commit / 不 bump 版本（由主会话执行）。

## 阶段 0 · 接线与开关（不改行为）

| # | 事项 | 验证 |
| --- | --- | --- |
| 0.1 | `--turn-tcp-relay`（默认关）+ `build_turn` 半配置校验 | 开关关：`uclient -T` 仍 `442` |
| 0.2 | `Connect`/`ConnectionBind` 方法常量、`CONNECTION-ID=0x002a` 入白名单（否则 420）| 单测：带 0x002a 不再 420 |
| 0.3 | `Allocation.relay` 抽象（UDP/TCP 枚举）| `cargo test`（现有 UDP 用例全绿）|

## 阶段 1 · Allocate + 端口池

| # | 事项 | 验证 |
| --- | --- | --- |
| 1.1 | `used_tcp_ports` + `take_tcp_port()`（`tcp_listener()`）| 端口不重叠、释放可复用 |
| 1.2 | Allocate(TCP)：控制面 UDP/DTLS → `400`；TCP/TLS → 200 + TCP relay 地址（**无 CONNECTION-ID**）| 单测 + uclient 抓包 |
| 1.3 | 带 `DONT-FRAGMENT`/`EVEN-PORT`/`RESERVATION-TOKEN` → `400` | 单测 |
| 1.4 | 开关关闭仍是 442 | 回归单测 |

## 阶段 2 · Connect + 预绑定缓冲

| # | 事项 | 验证 |
| --- | --- | --- |
| 2.1 | `Connect` 处理顺序（437/446/400/403/447）、`TCP_CONNECT_TIMEOUT=30s` | 单测：重复 446、拒绝 447、非法 400 |
| 2.2 | 出站连接以 relay 地址为本地端点 | peer 侧 `getsockname`/日志断言 |
| 2.3 | 成功 → `CONNECTION-ID`（全局唯一）+ 预缓冲 64 KiB | 单测 |
| 2.4 | 30 s 未 bind → 关闭（sweep） | 单测（注入时间或短超时）|

## 阶段 3 · ConnectionBind + 数据面

| # | 事项 | 验证 |
| --- | --- | --- |
| 3.1 | 数据连接首帧 `ConnectionBind` → 绑定；之后裸字节 | `uclient -T` 端到端 |
| 3.2 | 错 ID/重复 bind/过期 → `400` + 关连接 | 单测 + 记录「本仓 400 vs coturn RST」 |
| 3.3 | 双向 copy + 半关闭联动；绑定时先刷预缓冲 | 单测（client 关写 → peer EOF）|
| 3.4 | `ChannelBind` → 400；`Send`/`ChannelData` → 丢弃 + 计数 | 单测 |

## 阶段 4 · 生命周期与资源

| # | 事项 | 验证 |
| --- | --- | --- |
| 4.1 | 过期/`LIFETIME=0` → 关全部数据连接（控制连接保留）| 单测 + `ss -ltnH` |
| 4.2 | 每 allocation 上限 16 → `508` + `{reason="tcp_quota"}` | 单测 |
| 4.3 | 指标 5 个新增项 + 固定标签集同步（ops/文档/测试）| `check-docs` + 逐行断言 |
| 4.4 | `--max-inflight` 语义（数据连接占 slot）写进文档 | 文档评审 |

## 阶段 5 · 验收与文档

| # | 事项 | 验证 |
| --- | --- | --- |
| 5.1 | lab 新增 `tcprelay` 项：探针标准流程（Allocate→Connect→Bind→裸字节→LIFETIME=0），rstun 与 coturn 逐行一致（`uclient -T` 见 design §8.1，留被动模式子任务）| `--only tcprelay` |
| 5.2 | lab cleanup 补 `ss -ltnH` 的 TCP 残留断言 | `--only cleanup` |
| 5.3 | coturn 对跑（同命令）：结果一致 + 差异清单 | 日志 |
| 5.4 | 文档：`turn.md` 行为表、`README` 不做清单、`CHANGELOG`、spec、`src/turn.rs` 头注释 | `check-docs.sh` |

## 门禁（每阶段）

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-turn.sh
bash script/lab/rstun-turn.sh --tls --dtls
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/ci/check-docs.sh --no-build
cargo audit; echo "audit=$?"
cargo deny check
```

## 验收断言（必须）

- [ ] 开关关：`-T` → `442`（回归）；默认路径冻结与 `cad4fa2` 一致
- [ ] 开关开：`-T` 全通（`lost packets 0`）；`-P` **不在本期**（不测、不承诺）
- [ ] 446/447/400/437/403 各有单测；`Connect` 无 permission 也 200
- [ ] `ConnectionBind` 错 ID/重复/过期 → 400 且连接关闭
- [ ] `LIFETIME=0` → 数据连接关闭、`ss -ltnH` 无残留
- [ ] 半关闭双向联动有单测
- [ ] 指标新增项被文档与测试同时覆盖

## 回滚

- 阶段内：开关默认关，可随时退回旧行为；
- 整体：revert 本任务提交。
