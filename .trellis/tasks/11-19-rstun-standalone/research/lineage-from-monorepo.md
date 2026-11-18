# 与 monorepo 的关系（迁入说明）

本仓由 monorepo 中的 `rstun` 子目录拆出（`git subtree split`），首次公开时**有意不携带抽取历史**：
原历史包含内部部署信息（生产网段、内部文档路径），不适合进入公开仓。

## 已迁入

- 代码与构建：`src/`、`test/interop/`、`fuzz/`、`Dockerfile`、`Cargo.toml`/`Cargo.lock`
- CI：`.github/workflows/{ci,release}.yml`、`script/ci/rstun-smoke.sh`
- 本任务：`prd.md` / `design.md` / `implement.md` / `research/`（互操作矩阵、发版预检、拆仓记录、证据）

## 留在 monorepo（不迁）

- workspace 成员声明、旧 workflow（`rstun.yml`）、旧脚本 `script/ci/rstun-{smoke,publish}.sh`
- 内部债务/决策记录、部署清单、会话交接件（`HANDOFF.md`）

## 脱敏

迁入文档里的生产网段统一替换为 TEST-NET（`203.0.113.0/24`、`192.0.2.0/24`），
并去掉具体主机/部署路径引用；协议与工程结论未改动。

## 版本线

本仓独立版本线（`YY.QMM.Mmpp`），首个发布 `rstun-v26.410.100`，不跟随任何下游产品的版本号。
