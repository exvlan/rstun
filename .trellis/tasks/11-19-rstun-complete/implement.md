# 执行顺序（父任务）

> 子任务各自有 PRD 与验收；本文件只定义顺序、门禁与集成点。

## 顺序（用户定稿：功能 → GitHub 分发 → crates.io）

### 阶段 A · 功能开发（先把服务做完整）

1. **abuse-guard（P0）**：先止血（伪造源 + RESPONSE-PORT 的反射放大是当前唯一可被利用的缺口）。
2. **proto-complete（P1）**：错误路径闭环，为鉴权提供 401/438/500 的基础。
3. **auth（P1）**：依赖 1（限速防爆破）与 2（错误码）。
4. **ops（P1）**：与 2/3 并行；readiness/metrics 用于验证 1–3。
5. **turn（P2，最大项）**：依赖 1（配额/防滥用）、3（长期凭据）、4（指标）；
   分两批：UDP 中继闭环 → TLS/DTLS + REST 凭据 + 配额完善。

> 阶段 A 出口：STUN + TURN 功能面齐全，`rstun-interop.sh all` 与浏览器/turnutils 验收全绿。

### 阶段 B · 产物与镜像的 GitHub 分发

6. **qa（P2）**：基准、混沌、覆盖率、fuzz/矩阵定时——为分发提供可回归的质量基线。
7. **dist（P2）**：Release 资产（4 平台 zip）、`ghcr.io/exvlan/rstun` 双架构镜像、
   包管理器（brew/deb）、文档站与社区文件、供应链门禁（audit/deny/SBOM）。
8. **maintenance 的 M2/M3**：`linux-aarch64` 与 macOS x86_64 实机补验（分发产物必须真跑过）、
   发布前长期回归记录。

> 阶段 B 出口：所有分发渠道（GitHub Release + 镜像 + brew/deb）产物可用且被实机验证。

### 阶段 C · crates.io 首发（最后）

9. **maintenance 的 M1**：`cargo publish` → 干净环境 `cargo install rstun` 验证。
   **必须在阶段 B 之后**：源码包是对外承诺的最后一道，要等二进制/镜像渠道稳定后再发。

## 门禁（每个子任务都必须）

- `cargo test`、`clippy -D warnings`、`fmt --check`
- `bash script/lab/rstun-interop.sh all`（38 项/176 断言）
- 现有冻结测试不得失败（无鉴权/无限速路径字节不变）
- 新增配置默认关闭，开启后必须有一份 e2e 证据

## 集成验收

- [ ] 无配置启动 = 与 26.410.100 行为一致（字节级）
- [ ] 开限速：伪造源 + RESPONSE-PORT 放大比 ≤ 1 且被限速
- [ ] 开鉴权：`turnutils_stunclient -u/-w/-r` 可成功；错误口令 401；过期 nonce 438
- [ ] 开 metrics：Prometheus 能抓取；readiness 反映端口可用
- [ ] 关闭全部新特性：性能与 p99 与基线相比无退化（基准记录）
- [ ] TURN 默认关闭；开启时未配凭据必须拒绝启动；relay 端口回收无残留

## 回滚点

每个子任务一个 commit 批次；默认关闭状态下可单独 revert；鉴权/限速的配置开关保留一版兼容。
