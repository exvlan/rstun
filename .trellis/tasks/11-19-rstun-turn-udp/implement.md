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
| 9 | 配额（每用户/每 IP、permission 上限）→ 486/403 | e2e：超限用例 | 同上 |
| 10 | 统计（退出时四项计数） | 日志断言 | 同上 |
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
- 通道号重复绑定 → 400；权限超限 → 403
- `LIFETIME=0` 后再次使用该 relay → 437

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all       # STUN 侧不得回归（38 项）
bash script/lab/rstun-turn.sh              # 新增验收（含与本地 coturn 对跑）
cargo tree -e normal --depth 1             # 不得新增依赖（T1 阶段）
```

## 回滚

- 单批 commit；`--turn` 默认关闭 → 关闭即回到 STUN-only 行为。
- 若鉴权前置未就绪：**不合并**半成品 TURN（可保留分支）。

## 风险与观察

- 端口池与系统 ephemeral 端口冲突：文档提示 + `--relay-ports` 可配；
- 高并发 allocation 的锁竞争：`RwLock` 读多写少；压测确认 P99（在 qa 任务里补基准）。
