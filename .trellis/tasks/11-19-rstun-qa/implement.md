# 执行计划：qa

> 前置：T1/T2 已完成并归档；`docs/browser-acceptance.md` 里的浏览器验收待办在本任务第 7 步。
> 本任务不改服务代码；只新增脚本/文档/workflow。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | `script/lab/rstun-load.sh`：UDP 吞吐/延迟（单源 + 多源 127.0.0.x）、`--json`、自起自停、限速开/关对照 | 本机跑出两张对照表；限速组丢弃 > 0、未限速组为 0 | 新增文件 |
| 2 | TCP 连接洪水与首字节延迟（复用脚本 `--mode tcp`） | fd 回落、进程存活 | 同上 |
| 3 | `docs/perf.md`：硬件/构建参数/命令/原始输出/结论 + **lean vs full** 两组基线 | 数字可复现（同机重跑 ±10%） | 文档 |
| 4 | 混沌脚本 `script/lab/rstun-chaos.sh`：C1–C6（netem；无 root 则 SKIP + 原因） | 每例断言明确；`--list` 可单跑 | 新增文件 |
| 5 | 覆盖率：CI 加 `cargo llvm-cov`（`--ignore-filename-regex` 排除测试模块），上传 artifact；本地 `--fail-under-lines 80` 可选 | CI 出现报告；无硬门禁（先观察一版） | workflow |
| 6 | `qa-scheduled.yml`：每周 cron + 手动；fuzz 10 分钟（崩溃→`gh issue create`）、`rstun-interop.sh all`（容器化依赖）、基准冒烟（存数值） | 手动 dispatch 跑通；schedule 语法正确 | 新增文件 |
| 7 | **浏览器 `turns:` 验收**（承接 T2 R4）：在合格环境（同主机/同网或可达地址 + 受信证书）执行 `docs/browser-acceptance.md` 步骤，归档截图/日志 | `typ relay` 候选 + 服务端 `bytes_total` 增长 | 文档 + 证据 |
| 8 | 观察两周：定时任务 flaky 记录；`docs/perf.md` 与 README 链接 | 两周内无未解释的红 | 文档 |

## 门禁

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all       # 42 项
bash script/lab/rstun-abuse.sh             # 10 组
bash script/lab/rstun-turn.sh              # lean 15 passed + 2 skipped
bash script/lab/rstun-load.sh --mode udp --duration 10 --rate 5000   # 新增
bash script/lab/rstun-chaos.sh             # 新增；无 root 时 SKIP 并说明
```

## 验收断言（必须）

- [ ] `rstun-load.sh` 的限速对照：开限速组 `dropped > 0` 且总吞吐受控；未限速组 `dropped = 0`
- [ ] `docs/perf.md` 含 lean/full 两组基线 + 硬件说明 + 复现命令
- [ ] 混沌 ≥5 例可用；每例有明确断言；无 root 时 SKIP 文案清楚
- [ ] CI 覆盖率报告可见（非阻塞）；`--ignore-filename-regex` 生效
- [ ] `qa-scheduled.yml` 手动 dispatch 跑通（fuzz + interop + 基准冒烟）
- [ ] 浏览器 `turns:` 验收在合格环境执行并归档证据（承接 T2 R4）
- [ ] 两周观察期结束，flaky 有记录

## 风险

| R | 缓解 |
| --- | --- |
| 基准噪声 | 本地阈值、CI 只存值 |
| `tc` 权限 | SKIP + 原因；文档写清本地命令 |
| 定时任务额度 | 每周一次；public 仓免费 |
| 浏览器验收仍无环境 | 保持为**未完成待办**并如实记录，不得勾选 |
