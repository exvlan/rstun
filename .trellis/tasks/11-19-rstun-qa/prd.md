# 质量与性能（基准 / 压测 / 混沌 / 覆盖率 / fuzz）

## Goal

把「能跑」变成「可量化、可回归」：性能有基线，异常有覆盖，长期有节奏。

## 需求

1. **基准**：Criterion（或自写 bench）测 `decide()` 与端到端 UDP 吞吐（req/s）与 p50/p99 延迟；
   基线写入 `docs/perf.md`，每次发布对比。抗滥用限速表在 65536 条目时的内存与 P99 也在此项
   （来自 `11-19-rstun-abuse-guard` 的未闭环观察项）。
2. **压测**：脚本 `script/lab/rstun-load.sh`（UDP 洪水 + 限速生效验证 + TCP 连接洪水），可指定并发/时长/源地址。
3. **混沌**：`tc netem` 丢包/延迟/MTU 分片下行为（UDP 截断、TCP 半包、超时回收）。
4. **覆盖率**：`cargo llvm-cov` 门禁（建议 ≥ 80%，协议模块单独阈值），CI 上传报告。
5. **fuzz 常态化**：每周定时跑 10 分钟（GitHub Actions scheduled），崩溃即开 issue；corpus 缓存到 artifact。
6. **互操作矩阵定时**：每周跑 `rstun-interop.sh all`（容器内 coturn/go），失败即通知。
7. **浏览器 `turns:` 验收（承接 T2 的 R4）**：`11-19-rstun-turn-tls` 的浏览器验收因环境阻断未执行
   （in-app 浏览器只代理页面加载，WebRTC 到不了 OpenCode 主机上的 TURN 监听；证据见
   `docs/browser-acceptance.md` 的「尝试记录」）。本任务负责在**满足条件的环境**里补跑并归档证据：
   - 浏览器与 TURN 服务同主机/同网络，或 TURN 绑到浏览器可达地址（同 LAN 私网 IP / 公网 IP）；
   - 证书可被该浏览器信任（受信 CA，或手动信任自签）；
   - 验收断言：`icecandidate` 出现 `typ relay`（`iceTransportPolicy:"relay"`），服务端对应 allocation
     的 `bytes_total` 增长；至少一方位于对称 NAT 后。

## 验收

- [ ] `docs/perf.md` 有可复现的基线数字与硬件说明
- [ ] 压测脚本能验证「限速生效」与「未限速对照」
- [ ] 混沌用例至少 5 条（丢包/乱序/截断/MTU/半开连接）且断言明确
- [ ] 覆盖率报告在 CI 可见，低于阈值红灯
- [ ] 定时任务运行两周无 flaky
- [ ] 浏览器 `turns:` 验收在合格环境执行，截图/日志归档（承接 T2 R4；不得只写文档就勾选）

## 风险

| R | 缓解 |
| --- | --- |
| 基准受 CI 机器噪声影响 | 只做趋势对比，不设硬阈值；硬阈值仅用于本地发布前 |
| 定时任务消耗额度 | public 仓免费；矩阵控制在每周一次 |
