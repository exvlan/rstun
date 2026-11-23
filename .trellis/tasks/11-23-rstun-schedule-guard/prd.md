# 定时作业 staleness 守卫（schedule 静默失效可见化）

## 背景（实测）

2026-11-23 盘点发现：本仓库**从未有过任何 `event=schedule` 的运行**。

```
$ gh api "repos/exvlan/rstun/actions/runs?event=schedule&per_page=5" --jq .total_count
0
```

- `qa-scheduled`（周一 04:00 UTC）与 `verify-platforms`（周四 06:00 UTC）都配了 `schedule`，
  状态 `active`；仓库非 fork、`actions.enabled=true`、`allowed_actions=all`、`main` 持续有推送；
- 但到今天（周一 10:41 UTC）`qa-scheduled` 的定时run 仍未出现（只有手动 dispatch 的历史）。

含义：**周度回归可能一直没跑，而没有任何人会发现**——这正好是「静默失效」。

## Goal

把「定时作业没跑」变成**可见**：

1. 每日（以及每次 push 到 `main` 时）检查两个周度 workflow 最近一次 `event=schedule` 的运行时间；
2. 超过阈值（默认 **8 天**，周度作业的 1 个周期 + 1 天余量）或**从未运行** → 建 **GitHub issue**
   （标题固定，已存在则跳过/评论，不刷屏）；
3. 守卫本身**不能只依赖 cron**（若 schedule 整体失效，守卫也不会跑）→ 必须同时有 `push` 触发器。

## 范围

- 新增 `.github/workflows/schedule-guard.yml`：
  - 触发：`schedule`（每日 06:00 UTC）+ `push`（`main`）+ `workflow_dispatch`
  - 输入（dispatch）：`max_age_days`（默认 8）、`dry_run`（默认 false）
  - 权限：`contents: read` + `issues: write` + `actions: read`（`gh run list` 走 Actions API，
    显式 `permissions:` 块会把未列出的 scope 置为 none，缺这一项会 403）
  - 检查对象：`QA scheduled`、`Verify platforms`（workflow 名从 `gh run list --event schedule -w …` 取）
  - 结论写 step summary；`dry_run=true` 只打印不建 issue
- 文档：`CONTRIBUTING.md` / `README` 增加「周度作业失效时如何手动补跑」；
  `.trellis/spec/backend/quality-gates.md` 记录该守卫与阈值。

## 非目标

- **不**在本任务里排查 GitHub 侧为何不调度（根因未知，可能平台侧）；守卫先把事实暴露出来；
- 不引入外部 cron/凭据；
- 不改 `qa-scheduled` / `verify-platforms` 的内容。

## 约束

- 守卫必须在「schedule 完全失效」的情况下仍能运行（`push` 触发）；
- issue 去重：同标题只保留一个 open issue；恢复后**自动关闭**（或至少在新 issue 里注明恢复方式）；
- 不新增依赖；workflow action 锁 40 位 SHA；`permissions` 最小化。

## 验收

- [ ] 对当前状态（0 次 schedule run）跑守卫 → 建 issue（或 dry-run 打印「never ran」）
- [ ] 手工把阈值设为 `0` 再跑 → 同样的 issue 不重复创建（去重生效）
- [ ] 存在一次新鲜 schedule run 时（可用 `max_age_days` 调大模拟）→ 不建 issue、summary 显示 OK
- [ ] `dry_run=true` 时不建 issue
- [ ] `push` 到 `main` 会触发守卫（证明不依赖 cron）
- [ ] 文档与 spec 同步；`check-docs` 通过
