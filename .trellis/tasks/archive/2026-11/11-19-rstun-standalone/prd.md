# rstun：独立 STUN 服务端（合规化 / 互操作 / 拆仓 / 首发）

## Goal

把自建 STUN 服务端从 Exvlan 内部件升格为**独立的 Rust STUN 服务端项目 `rstun`**：
协议合规（RFC 5389 + RFC 5780，可选 RFC 8489 子集）、有第三方互操作背书、可独立发布（crates.io + 多架构镜像），
同时继续作为 Exvlan 的公网 STUN 入口（dogfooding）。

## 背景（为什么做）

- Rust 生态**没有完整的 STUN 服务端**：纯 STUN 实现很多，但 RFC 5780（NAT 行为发现）几乎无人实现；
  唯一同时做 5780 的 `kruatech/turna` 只有 1★、且提交里 AI 参与占多数，可信度不足。
- 我们已有可用的自建实现（现名 `rstun`，原 `exvlan-stun`）：44→59 测试、1.7 MB、零运行时 STUN 依赖、
  UDP/TCP/IPv6 全支持、RFC 5780 四 socket 方案已在生产 3478 上验证。
- 生态缺口 = 我们的机会；自用即验证，不需要做无人使用的开源项目。

## 需求（Scope）

### S1 协议合规（T0）

- `420 UNKNOWN-ATTRIBUTES`（RFC 5389 §7.3.1 + §15.9，**注意：5389 无"重复末项"规则，用 2N value + 通用 padding**）
- `MAPPED-ADDRESS`（§15.1，默认关闭，`--mapped-address` 开启；关闭时响应字节**逐字节不变**）
- RFC 5780 `PADDING`（§7.6）：回显且**永不放大**（有意偏离"按 MTU 补齐"这条 SHOULD，需在 README 写明）
- RFC 5780 `RESPONSE-PORT`（§7.5）：**目的端口**语义（发往 `client_ip:resp_port`），仅 UDP
- `PADDING` + `RESPONSE-PORT` 同时出现 → **400**（§10 MUST）
- 「已知属性表」必须覆盖 ICE/鉴权常用属性（`MESSAGE-INTEGRITY`/`USERNAME`/`REALM`/`NONCE`/`PRIORITY`/`USE-CANDIDATE`…），
  避免把正常 ICE 客户端打成 420

### S2 互操作矩阵（T1，"敢说完整"的门槛）

四方矩阵，双向（他们发 → 我们答；我们发 → 他们答）：

| 对手 | 用途 |
| --- | --- |
| coturn / `turnutils_*` | 生产同款、最常用的实现 |
| pion/stun（Go） | 主流 WebRTC 生态 |
| webrtc-rs `stun` 0.17 | Rust 生态 |
| `stun-types` 2.0.5 | 编解码 oracle（仅测试） |

加：RFC 5769 测试向量、`cargo-fuzz` 解析健壮性、CI 矩阵（Linux/macOS/Windows × UDP/TCP/IPv6）。

### S3 独立发布与拆仓

- crate `rstun`，二进制 `rstun`，CLI `rstun server …`（**不能叫 `stun`**：Debian `stun-client` 占 `/usr/bin/stun`）
- **crate 级 MPL-2.0**（已落地），仓内其余保持 LGPL-3.0；README 写明边界
- **版本线独立**：首发 `rstun-v26.410.100`（遵循 `YY.QMM.Mmpp` 年号约定，但不跟随内核 `26.410.20715-dev.N`）
- 发布物：`rstun-v*` Release + `rstun-<platform>-<version>.zip` + `ghcr.io/<owner>/rstun:<version>`（amd64 + arm64）
- 拆独立仓库后，Exvlan 以依赖方式消费

### S4 生产切换

- `rstun-v*` 发布后可切部署：镜像换 `ghcr.io/exvlan/rstun:26.410.100`，
  命令改为 `rstun server --listen 192.0.2.5:3478 --tcp --listen-v6 [::]:3478`
- 切完立即验 UDP/TCP/IPv6 + 外部 vantage；回滚 = 还原上一版镜像或旧配置

## 非目标（明确不做）

- **TURN**（`Allocate`/`Channel`）：本服务不做中继，跨 NAT 由使用方自行兜底
- **STUN 鉴权**（`MESSAGE-INTEGRITY` 校验 / realm / nonce）：公开 STUN 无意义
- **限速/防放大**：参数需压测，且 NAT 后大量客户端共用出口 IP 易误伤（后续按需评估）
- **TLS/DTLS 传输**：与"1.7 MB、零依赖"卖点冲突，观察 3 个月采纳情况再定

## 关键约束

| 约束 | 说明 |
| --- | --- |
| 运行时零新增依赖 | `stun-types` 只能进 `[dev-dependencies]`；`cargo tree -p rstun` 不得出现 `exvlan-*` |
| 生产零回归 | 生产当前跑 `+27ec66`；`--mapped-address` 关闭路径必须逐字节一致（冻结测试锁住） |
| 公网能力现实 | 部署方可能只有一条可达 UDP 路径 → **生产不开 RFC 5780**，`change-ip` 只能在本地/内网验证 |
| 版本对齐规则 | `rstun` 是 `AGENTS.md`「版本对齐范围」的**例外**（独立版本线），拆仓时把这条写进规则 |

## 验收标准

- [ ] T0：`cargo test -p rstun` 全绿；420（N=1/2/3 的 value 长度 2/4/6）、PADDING 不放大、RESPONSE-PORT 目的端口、
      PADDING+RESPONSE-PORT→400、`--mapped-address` 关闭时字节冻结，均有自动化断言
- [ ] T1：四方互操作矩阵全绿；RFC 5769 向量通过；fuzz 跑 10 分钟无 panic/无挂死
- [ ] S3：`crates.io` 可 `cargo install rstun`；`docker run ghcr.io/<owner>/rstun:<ver> --version` 带 `+sha`；
              amd64 + arm64 双架构可用
- [ ] S4：生产 3478 切换后外部 vantage UDP/TCP/IPv6 全通，`SOFTWARE=rstun/<ver>`，回滚演练成功一次
- [ ] 文档：README 含范围声明（不做 TURN/鉴权）、License、RFC 条款引用；CHANGELOG 与本仓 AGENTS.md 同步

## 风险

| # | 风险 | 缓解 |
| --- | --- | --- |
| R1 | 420 误伤 ICE 客户端 | 「已知属性表」穷举 + 互操作矩阵里显式跑 ICE 属性组合 |
| R2 | RESPONSE-PORT 目的端口可被用于放大 | 只对客户端自身 IP 回包（RFC 语义），响应体积不放大 |
| R3 | 发布链路一次换四样（workflow 名/资产前缀/tag 前缀/镜像名） | 首发前 `gh release view rstun-v…` 预检；首次 dispatch 只发 prerelease |
| R4 | 拆仓后 Exvlan 侧版本漂移 | Exvlan 侧锁定具体版本 + 镜像 digest |
| R5 | 对外宣称"完整"但只有单一实现验证 | T1 矩阵是发布前置条件，不达标不发 |
