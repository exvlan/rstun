# rstun 完整 STUN 服务端（对齐 coturn 的 STUN 能力）

## Goal

把 rstun 从「可用、已上线的 STUN-only 服务端」推进到**完整标准 STUN 服务端**：
协议错误路径闭环、可选鉴权、公网抗滥用、可运维、可分发、可持续验证。
**TURN 中继不在本父任务内**（如需要另立父任务，见「非目标」）。

## 判定「完整」的口径

以 coturn 的 **STUN 子集**为对照基准（不做 TURN）：

1. RFC 5389 §7-§15 的服务端行为全部可应答或可拒绝（含 400/420/500 与 FINGERPRINT 校验）；
2. RFC 5780 全套（CHANGE-REQUEST / RESPONSE-ORIGIN / OTHER-ADDRESS / RESPONSE-PORT / PADDING）— 已完成；
3. 支持短期与长期凭据鉴权（401/438、MESSAGE-INTEGRITY 校验；RFC 8489 的 SHA256/算法协商按需）；
4. 公网可裸跑：速率限制、并发上限、反射放大防护；
5. 可运维：readiness、指标、配置、优雅退出、部署清单；
6. 可分发与可验证：crates.io/包管理器、文档、基准与长期回归。

## 子任务地图

| 子任务 | 范围 | 优先级 |
| --- | --- | --- |
| `rstun-abuse-guard` | 限速、并发上限、反射防护、名单 | **P0** |
| `rstun-proto-complete` | 500、FINGERPRINT 校验、ALTERNATE-SERVER、RFC 8489 属性 | P1 |
| `rstun-auth` | 短期/长期凭据、401/438、MI/MI-SHA256 校验、realm/nonce | P1 |
| `rstun-ops` | readiness、metrics、配置文件、优雅 drain、systemd/k8s/Helm | P1 |
| `rstun-qa` | 基准、压测、混沌、覆盖率、fuzz 常态化 | P2 |
| `rstun-dist` | 包管理器、文档站、社区文件、供应链门禁 | P2 |
| `rstun-maintenance` | crates.io 首发、arm64/macOS 补验、长期回归 | 并行 |

## 跨子任务验收

- [ ] 对照表：coturn STUN 能力逐项 ✅/❌（不适用须写明理由）
- [ ] 互操作矩阵（coturn/pion/webrtc-rs/stun-types）在**开启鉴权**与**关闭鉴权**两种配置下均全绿
- [ ] 公网抗滥用：伪造源 + RESPONSE-PORT / CHANGE-REQUEST 的放大比 ≤ 1，且触发限速
- [ ] 运维：readiness 能反映「端口真的在服务」，指标可被 Prometheus 抓取
- [ ] 回归：`script/lab/rstun-interop.sh all` + fuzz ≥10 分钟 + 基准不退化

## 非目标

- **TURN**（Allocate/Refresh/Channel）与 turns/TLS 中继：另立父任务评估（工作量与 coturn 同级）
- 多租户/数据库后端
- 既有的「不放大」承诺不变：任何新增属性都不得让响应大于请求（鉴权错误响应除外，需说明）

## 风险

| # | 风险 | 缓解 |
| --- | --- | --- |
| R1 | 鉴权引入状态（nonce/realm），与「无状态、零依赖」定位冲突 | realm/nonce 从配置读，nonce 用无状态 HMAC（时间戳+密钥） |
| R2 | 限速在 NAT 后误伤（大量客户端共用出口 IP） | 默认宽松阈值 + 可配置；按「源 IP + 端口」与「源 IP」双维度 |
| R3 | 增加 HTTP 指标端点破坏「零 HTTP 面」 | 独立监听地址 + 默认关闭；或仅 systemd-notify + 日志统计 |
| R4 | 鉴权与现有 ICE 属性处理冲突 | 保留「无鉴权时忽略 MI」的兼容路径（现有 420 白名单不变） |
