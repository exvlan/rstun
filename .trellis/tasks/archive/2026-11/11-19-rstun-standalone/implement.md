# rstun 执行计划

> 状态：**in_progress**（`task.py start` 已过评审门）。
> 进度：T0 ✅ 已提交（`efab5664` + `c87fe5e8`）；T1 1.1–1.7 ✅、1.8 待真实 CI；
> T0.9（`--alt-listen` 与多地址/IPv6 共存，生产需求追加）实施中；S3 预检见 `research/S3-release-prep.md`。

## 阶段 T0 · 协议合规（✅ 已提交）

| 追加 | 内容 | 来源 |
| --- | --- | --- |
| 0.9 | `--alt-listen` 不再要求「恰好一个地址」：`--listen-v6` 不计入计数，多 v4 时**第一个**为 primary，其余只做普通 Binding；普通 socket 不带 `RESPONSE-ORIGIN`/`OTHER-ADDRESS`、忽略 `CHANGE-REQUEST` | 生产需求（2026-11-19）：5780 + IPv6 + 第三地址共存 |


| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 0.1 | `420 UNKNOWN-ATTRIBUTES`（`2N` value + 通用 padding，**不重复末项**） | 单测 N=1/2/3 → value 长度 2/4/6；e2e 断言 | 单文件 revert |
| 0.2 | 已知属性表（鉴权/ICE 簇必须收） | 单测：带 `MESSAGE-INTEGRITY`/`PRIORITY` 仍返回 success | 同上 |
| 0.3 | `MAPPED-ADDRESS` + `--mapped-address`（默认关） | 冻结测试（48B）+ e2e 开关对比 | 同上 |
| 0.4 | `PADDING` 回显、不放大 | e2e 128/4000/8000；断言响应 ≤ 请求 | 同上 |
| 0.5 | `RESPONSE-PORT` 目的端口语义（仅 UDP） | e2e：另起 socket 在目标端口收；源端口不变 | 同上 |
| 0.6 | `PADDING` + `RESPONSE-PORT` → 400 | e2e 断言 400 | 同上 |
| 0.7 | README 行为表 + 有意偏离说明 | 人工评审 | — |

**门禁**：`cargo test -p rstun`、`clippy -D warnings`、`fmt --check`、4 个 `script/ci` 脚本、`rstun-smoke.sh`。

## 阶段 T1 · 互操作矩阵（1.1–1.7 已完成；1.8 待 CI）

报告：`research/T1-interop-matrix.md`（每个对手一张表 + 原始输出摘录 + 判定）。
本地一次跑完：`bash script/lab/rstun-interop.sh all` → 38 项子用例全绿（176 条断言）。

| # | 事项 | 状态 | 证据 |
| --- | --- | --- | --- |
| 1.1 | 矩阵骨架（`script/lab/rstun-interop.sh` + `rstun-interop-probe.py`，可单项跑） | ✅ | `--list` / 单项；项间自清理 PID，端口 base 34780 |
| 1.2 | coturn/`turnutils_stunclient` 双向 | ✅ | `stunclient`→rstun exit=0 + 三条 RFC 5780 响应；探针→coturn |
| 1.3 | pion/stun（Go v3.1.7）双向 | ✅ | 7 个 mode 全绿（含 `response-port`、`rfc5780`） |
| 1.4 | webrtc-rs `stun` 0.17.3 双向 | ✅ | 8 个 mode 全绿（含 `ipv6`） |
| 1.5 | `stun-types` 2.0.5 双向 | ✅ | `tests_interop::stun_types_bidirectional` |
| 1.6 | RFC 5769 §2.1–§2.4 向量 | ✅ | `tests_interop::rfc5769_*`（4 条；§2.2/§2.3 可逐字节重建） |
| 1.7 | `cargo-fuzz` 解析路径 10 分钟 | ✅ | 600 s、零 panic/挂死（执行次数与覆盖见报告 §1.7） |
| 1.8 | CI 矩阵（Linux/macOS/Windows × UDP/TCP/IPv6） | ⏳ 阻塞 | 作业已写入 `test.yml` 的 `rstun_matrix`；Linux 步骤本地复现全绿；macOS/Windows 需 push 才能变绿，本任务禁止 push |

**门禁**：矩阵报告已写入 `research/`；本轮无对手失败项（三处差异的判定见报告 §9）；
1.8 的「workflow 绿」需主会话 push 后确认（建议 `script/ci/run-with-public.sh <branch>`）。

**口径对齐**：T0 0.4 写的「e2e 128 / 4000 / 8000」三档现在由
`probe/padding-128|4000|8000` 逐档覆盖（本轮补了 8000，每档都断言回显长度相等且不放大）。

## 阶段 S3 · 独立发布（✅ 已拆仓并首发）

- 新仓 https://github.com/exvlan/rstun（public，MPL-2.0），`rstun-v26.410.100` 已发布：
  4 平台 zip + `ghcr.io/exvlan/rstun:26.410.100`（amd64+arm64，digest `sha256:9d7382c6…`）。
- 详见 `research/S5-split-repo.md`（做法、修复、阻塞项 B1–B4）。
- 仍阻塞生产：ghcr 包默认 private，需改 Public 或 sg 登录拉取。

## 阶段 S3（原计划，保留作对照）

| # | 事项 | 验证 |
| --- | --- | --- |
| 3.1 | 首发 `rstun-v26.410.100`（prerelease） | Release 4 平台 zip + `ghcr.io/exvlan/rstun:26.410.100` |
| 3.2 | 镜像内 `rstun --version` 含 `+<sha6>` | `docker run --rm … --version` |
| 3.3 | arm64 镜像（buildx+QEMU） | 双架构 manifest |
| 3.4 | `crates.io` 首发（`cargo install rstun` 可用） | 干净容器里 `cargo install` 成功 |
| 3.5 | 拆独立仓库 + CI/发布链迁移 | 新仓 CI 绿、旧路径残留清零 |

**回滚**：都没发布过 → 直接撤回 tag/Release（`gh release delete`），镜像 tag 删除。

## 阶段 S4 · 生产切换

| # | 事项 | 验证 |
| --- | --- | --- |
| 4.1 | 部署清单：镜像 → `ghcr.io/exvlan/rstun:26.410.100`，命令 → `rstun server --listen …` | 容器 Running 且冒烟通过 |
| 4.2 | 外部 vantage（macOS）验 UDP/TCP/IPv6 | `SOFTWARE=rstun/<ver>`、tid 回显 |
| 4.3 | 回滚演练一次 | 还原备份 → 旧镜像 → 验通 |

**注意**：`server` 子命令是破坏性 CLI 变更，镜像与命令必须**同一批**改，否则容器重启循环。

## 交叉约束

- 每阶段结束后 `git status` 必须干净（除阶段产物），提交信息零「上游」字样。
- 生产侧改动（S4）只允许在 T0/T1 全绿、镜像已发布后执行。
- 任何阶段发现问题：先判定「我方 / 对手 / RFC 理解」三类，再决定修还是记账。
