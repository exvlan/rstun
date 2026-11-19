# 执行计划：TURN T1（UDP 中继闭环）

> 前置依赖（**硬**）：`rstun-auth` 的长期凭据（401/438/nonce）与 `rstun-abuse-guard` 的配额/限速接口已落地。
> 若前置未完成：先做本计划的 1–4 步（纯数据结构与状态机，不接鉴权），但**不得**以「无鉴权可运行」的形态合并。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | `--turn` 与相关配置（realm/secret/relay-ports/配额/生命周期）；缺凭据时启动失败 | 启动失败用例 + `--help` | 单 commit |
| 2 | TURN method 常量与错误码（437/440/441/442/443/486/508） | 单测：错误码 → 线上编码 | 单文件 |
| 3 | `turn/mod.rs`：`Key`/`Allocation`/`Tables` + 端口池（取/还/耗尽） | 单测：并发取端口无重复、耗尽返回 508 条件 | 单文件 |
| 4 | 定时回收任务（1s 扫描）：allocation/permission/channel | 单测：时间注入验证 TTL；回收后端口可复用 | 单文件 |
| 5 | `Allocate` / `Refresh` 状态机（幂等、437、LIFETIME=0） | 单测（无网络）+ e2e | 同上 |
| 6 | `CreatePermission` / `ChannelBind`（TTL、上限、族校验、禁回环） | 单测 + e2e | 同上 |
| 7 | 数据面：relay→client（Data indication）、client→relay（Send indication）、`ChannelData`（UDP 头/TCP 头+padding） | e2e：双向中继、通道命中与未命中 | 同上 |
| 8 | 鉴权接入（401/438，复用 STUN 实现）；401 计入限速桶 | e2e：无 MI→401、错口令→401、过期→438 | 同上 |
| 9 | 配额（每用户/每 IP、permission 上限）→ 486/508 | e2e：超限用例；一条请求多 peer 必须零生效 | 同上 |
| 10 | 指标接入 `/metrics`（`rstun_turn_allocations`、`rstun_turn_bytes_total{direction}`、`rstun_turn_allocations_total{result}`、`rstun_turn_rejected_total{reason}`）+ 退出统计 | `curl /metrics` 断言数值随中继增长；未开 `--turn` 时指标不出现 | 同上 |
| 11 | `script/lab/rstun-turn.sh`：自签环境 + `turnutils_uclient` 中继 + 清理；无 `turnutils_uclient` 时 SKIP 并说明 | 脚本退出码 + 输出可 grep | 新增文件 |
| 12 | 文档：README TURN 小节（开启方式/端口/凭据/防火墙）、CHANGELOG | 人工评审 | 文档 commit |

## 测试策略（三层）

1. **单测**：状态机与端口池（时间注入，不碰网络）。
2. **e2e（Rust）**：本仓内起 TURN + 两个 UDP socket 作为 client/peer，跑
   `Allocate → CreatePermission → Send → Data → ChannelBind → ChannelData` 全链路（不依赖外部工具）。
3. **互操作（外部）**：`turnutils_uclient`（coturn 套件）对跑；**必须**另起本地 `turnserver` 作对照服务，
   同一客户端参数分别对两者跑，比较 allocation 生命周期/权限/通道行为；差异必须判定（我方/对手/RFC 理解）。

断言点（必须）：
- allocation 过期后 `ss -lun` 无残留 relay 端口
- 权限未覆盖时 `Send` 不产生任何发往 peer 的包
- 通道号重复绑定 → 400；权限超限 → 508（整条请求原子校验）
- `LIFETIME=0` 后再次使用该 relay → 437

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all       # STUN 侧不得回归（38 项）
bash script/lab/rstun-turn.sh              # 新增验收（含与本地 coturn 对跑）
cargo tree -e normal --depth 1             # 不得新增依赖（T1 阶段）
# 指标：起 `--health-listen` + `--turn`，中继后 `/metrics` 的 turn 指标必须增长
```

## 复核后遗留（记账，不阻塞）

| # | 项 | 说明 |
| --- | --- | --- |
| L1 | 防回环只覆盖「本进程监听端口」上的宿主地址 | 宿主其它端口的服务不在 PRD 范围内；枚举接口需新依赖，明确不引入 |
| L2 | `--allocation-lifetime` 同时是默认授予值与上限 | 已在 README/spec 写明双语义；若要拆成两个旋钮，属 API 变更 |
| L3 | 失败响应不带 `SOFTWARE` | RFC 8656 §6.1 为 SHOULD；401/438 与 STUN 共享编码，加了会破坏默认关闭字节冻结 |
| L4 | 端口池按端口而非 (IP,端口) 去重 | 单 relay IP 部署无影响；多 IP 部署时再评估 |
| L5 | 指标口径：`bytes_total` 只计 payload；配额含未扫描的过期条目（≤1s） | 已在 README 注明 |
| L6 | 通道号接受 0x4000–0x7FFF | RFC 到 0x4FFF；与 coturn 的 5766 兼容行为一致，已在 README 写明 |
| L7 | TCP 写队列有界（64）后溢出丢 relayed 数据 | 与 UDP 语义一致；如需「慢客户端不丢」应改背压，属 T2 |

## 回滚

- 单批 commit；`--turn` 默认关闭 → 关闭即回到 STUN-only 行为。
- 若鉴权前置未就绪：**不合并**半成品 TURN（可保留分支）。

## 复核后遗留（T2 记账）

- **宿主公网 IP 的防回环盲区**：`is_own_endpoint` 可判 loopback/unspecified/multicast 与所有已绑定
  地址，但无法枚举宿主自身公网 IP（需接口枚举，新一轮依赖，T1 不引入）。README/spec 已登记。
- **指标口径**：`rstun_turn_bytes_total` 只计 relay payload（不含 STUN/ChannelData 头）；
  `rstun_requests_total` 也计 TURN 报文（同一条 transport 循环），TURN 专用口径看 `rstun_turn_*`。
- **配额抖动**：已过期但尚未被 1s 扫描移除的 allocation 仍计入 per-user/per-IP 配额，
  短时间内可能多拒绝一次 486（下一次扫描后恢复）。
- **通道号 `0x7FFF`**：RFC 8656 §12.1 定义到 `0x7FFE`；本服务接受 `0x7FFF` 是 coturn 兼容，
  README 已写明。
- **TCP 写队列**：已改为有界（`TCP_SINK_CAPACITY=64`）+ `try_send`，溢出丢弃 relayed 数据帧；
  请求响应在队列满时关闭连接（不阻塞）。
- **多实例**：nonce 可共享（同一 `--auth-secret`），allocation 状态不共享。
- 仍未做：TLS/DTLS、REST 临时凭据、带宽配额、TCP allocation（RFC 6062）、`DONT-FRAGMENT`、
  `REQUESTED-ADDRESS-FAMILY`。

## 风险与观察

- 端口池与系统 ephemeral 端口冲突：文档提示 + `--relay-ports` 可配；
- 高并发 allocation 的锁竞争：`RwLock` 读多写少；压测确认 P99（在 qa 任务里补基准）。
