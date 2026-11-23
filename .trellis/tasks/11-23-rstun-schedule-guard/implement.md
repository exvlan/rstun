# 执行记录：schedule 守卫

## 交付

- `.github/workflows/schedule-guard.yml`：0 个 action；触发 `cron 0 6 * * *` + `push: [main]` + `workflow_dispatch`
  （输入 `max_age_days` 默认 "8"、`dry_run` 默认 false）；权限 `contents: read` + `issues: write` + `actions: read`；
  3 个 step：Detect（0 次运行 → never/stale；`age > max` → stale；gh 失败 → exit 1；非法输入 → exit 2）→
  Reconcile（stale 且无同名 open issue → 建；OK 且有 → 评论+关闭）→ Fail-on-stale（仅 dry_run）；
- 去重两道保险：`gh issue list --search` 先精确比对标题，未命中再 `--state open --limit 200` 全量精确比对
  （复核用 `microsoft/vscode` 实测：搜索会把开头的 `[Bug]:` 当噪声，所以精确比对是必须的）；
- 文档：`CONTRIBUTING.md`（周度作业说明 + 手动补跑 + 守卫语义 + 「手动关闭无效」）、
  `quality-gates.md` §5.2、`CHANGELOG.md ## Unreleased`；PRD 权限行补 `actions: read`。

## 复核与修正

冷复核：**实现本体无缺陷**（YAML 抽取 + gh 桩逐条实测 10 个场景），1 条文档契约错误 + 3 条建议全部落地：

1. **B1**：原文写「手动关闭 issue」是恢复路径 → 实际关闭后下次 push/cron 会重建。已改为
   「手动关闭无效；真正销账 = 平台恢复 或 改目标列表/阈值」；
2. **S1**：全量回退分支不再 `|| true`（读不到 open 列表 → `::error::` + exit 1）。
   复核期间发现第一版把 `exit 1` 写在 `$( )` 子 shell 里（只退出子 shell、还把错误文案吃进 `num`），已改为
   函数返回码 + 调用方判定；
3. S2「每周二」歧义改写；S3 PRD 权限行补 `actions: read`。

## 已知语义（写进文档）

- 手动 `gh workflow run` **不会**消除告警（产生的是 `workflow_dispatch`，不是 `event=schedule`）；
- `release-prep` 用 `GITHUB_TOKEN` push，**不会再触发** workflow（避免 bot commit 自我循环）；
- 当前事实：`event=schedule` 全仓 0 次 → 守卫上线后会对两个周度作业各建一条 issue，属预期。
