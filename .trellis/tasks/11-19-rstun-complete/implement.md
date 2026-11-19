# 执行顺序（父任务）

> 子任务各自有 PRD 与验收；本文件只定义顺序、门禁与集成点。

## 顺序

1. **abuse-guard（P0）**：先止血（伪造源 + RESPONSE-PORT 的反射放大是当前唯一可被利用的缺口）。
2. **proto-complete**：错误路径闭环，为鉴权提供 401/438/500 的基础。
3. **auth（P1）**：依赖 1（限速防爆破）与 2（错误码）。
4. **ops（P1）**：与 2/3 并行可行；readiness/metrics 用于验证 1–3。
5. **turn（P2，最大项）**：**依赖 1（配额/防滥用）、3（长期凭据）、4（指标）**；
   分两批：UDP 中继闭环 → TLS/DTLS + REST 凭据 + 配额完善。
6. **qa（P2）**：基准与混沌在 STUN 部分完成后固化；TURN 的中继压测单列。
7. **dist（P2）**：分发与文档，可与 qa 并行。
8. **maintenance**：crates.io 首发可随时进行（不依赖其它子任务），arm64 补验随发布。

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
