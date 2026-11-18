# 待决策清单（rstun-standalone）

> 规则：编号连续 `D1`、`D2`…；每条给选项、代价、推荐项。决策后回写到本文件与对应产物（prd/design/implement）。

## D1 · `rstun_matrix` 在每次 push 都跑 macOS/Windows 是否可接受

**背景**（冷复核 C3）：`.github/workflows/test.yml` 新增 `rstun_matrix`（ubuntu/macos/windows）。
`should_skip` 只对 PR 生效，push 恒为 false → **每次 push 到 `feature`（哪怕只改文档）都会跑
macos-latest（计费约 10×）+ windows-latest**。AGENTS.md 已记过「私仓 Actions 额度耗尽」的痛点。

| 选项 | 做法 | 代价 / 风险 |
| --- | --- | --- |
| **A（推荐）** | 保持现状：push 也跑三平台 | 每月多花 macos 分钟；换来「任何提交都验跨平台」，T1 证据链最强 |
| B | macOS/Windows 收敛到 PR→develop/main、tag、nightly；push(feature) 只跑 ubuntu | 省额度；代价是 feature 上的 macOS/Windows 回归只能等 PR 才发现 |
| C | 加路径门控：只有 `rstun/**`、`script/{ci,lab}/rstun-*`、`test.yml` 变更才跑三平台 | 需要 dorny/paths-filter 的 per-job 输出或独立的 filter 作业，实现稍复杂；额度最省 |
| D | 只保留 ubuntu + windows（砍 macOS） | macOS 的 `set_only_v6`/回环别名差异正是要测的，不建议 |

**推荐 A**：当前 T1 只有一次跨平台验证机会，先让它跑；等 S3 拆仓后按独立仓的额度再收敛（届时 CI 不再与内核共用配额）。

## D2 · 首发 `rstun-v26.410.100` 是否先发 prerelease

**背景**：`implement.md` 3.1 写"首发（prerelease）"；AGENTS.md 的 `rstun.yml` 部分未规定 prerelease。
首发有四个变量同时变（workflow 名 / 资产前缀 / tag 前缀 / 镜像名），`prd.md` R3 的缓解是"首次 dispatch 只发 prerelease"。

| 选项 | 做法 | 代价 |
| --- | --- | --- |
| **A（推荐）** | 首次 `draft=true` 或 `prerelease=true`，人工核对 4 平台 zip + 镜像 digest 后再转正 | 多一步人工；避免假 Release 被下游当真 |
| B | 直接正式发布 | 一旦命名/资产错，需要删 Release 重发（可撤销但留痕） |

**待决策**：进入 S3 前由用户拍板。
