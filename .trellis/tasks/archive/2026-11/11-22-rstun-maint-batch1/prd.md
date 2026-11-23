# 维护批一：`--tls-cert-poll` + `.104` 性能快照

## 背景

两处已知缺口，均小、可一起发一个补丁版：

1. **证书轮询不可关闭**：当前 30s 文件轮询是硬编码。只用 `SIGHUP` 的部署（例如对端侧车写文件后
   主动发信号）会在「先写 cert 后写 key」的窗口里看到一次 `reload_total{result="failed"}` 噪音；
   他们没有开关可以关掉轮询。
2. **性能基线陈旧**：`docs/perf.md` 是 `26.410.103` 快照（依赖 10/14、体积 3.77/7.95 MB）。
   `.104` 引入 RFC 6062、证书热载与 `x509-parser`（依赖变 **10/15**、体积 **3.92/8.15 MB**），
   README 已更新，但 perf 文档还停在旧版本。

## Goal

1. 新增 `--tls-cert-poll <secs>`：默认 `30`；`0` = 关闭轮询（只认 `SIGHUP`）；其它正整数 = 轮询间隔。
2. 把 `docs/perf.md` 更新为 `.104` 的实测数据（lean/full 两组，环境与命令不变）。

## 范围

### A. `--tls-cert-poll`

- CLI：仅 full 构建（`tls`）有意义；与 `--turn-tls-listen`/`--turn-dtls-listen` 的「半配置」校验一致：
  指定了该 flag 但**没有** secure 监听 → **启动失败**（避免「设了但从不生效」的静默配置）；
- `0`：不启动轮询任务；`SIGHUP` 仍生效（unix）；
- 非 unix（Windows）：无 `SIGHUP`，若 `0` → 启动时**拒绝**（否则证书永远无法轮换），错误文案说明；
- 文档：`turns:`/DTLS 章节、CLI 页、`README` 摘要、spec；
- 指标不变（`reload_total` / `expires_seconds` 照旧）。

### B. `docs/perf.md` → `.104`

- 被测版本 `26.410.104+<sha6>`；依赖面 **10 / 15**；体积未 strip **3.92 / 8.15 MB**、
  LTO+strip **2.44 / 4.95 MB**；
- §3/§4/§5/§6 数字来自本次实测（本机低负载窗口；记录 busy%）；
- §8 写清与 `.103` 的差异原因（RFC 6062 / 证书热载 / x509-parser / 体积增长），以及
  「数值随环境变化，只用于同机前后对比」。

## 非目标

- 不做 cosign 签名（下一项，独立任务）；
- 不做 RFC 6062 被动模式（后续任务）；
- 不改默认轮询间隔（仍 30s），只提供关闭/调节能力；
- 不发版（版本由主会话决定）。

## 约束（硬）

- 默认行为不变：不传新 flag 时轮询仍是 30s，`SIGHUP` 行为不变；
- 新增 flag 必须进 `check-docs`（help 片段）且 `docs/book/src/cli.md` 同步；
- 不新增依赖；Windows/macOS/Linux 编译通过；
- 性能测量需记录背景负载（按 `quality-gates.md` §5.1 的测量契约）。

## 验收

- [ ] `--tls-cert-poll 0` 后：文件变化**不触发**重载；`SIGHUP` 仍触发
- [ ] `--tls-cert-poll 2`：文件变化约 2s 内触发（lab 实测）
- [ ] 无 secure 监听 + 指定该 flag → 启动失败（明确文案）
- [ ] Windows + `0` → 启动失败（说明「无 SIGHUP」）
- [ ] 默认（不传）行为与现在一致（30s + SIGHUP），`frozen` 与全量门禁不变
- [ ] `docs/perf.md` 的版本/依赖/体积与实测一致，`check-docs` 通过
- [ ] 全量门禁绿（tests/clippy/fmt/labs/audit/deny）
