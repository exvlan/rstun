# rstun 技术设计

## 1. 边界

```
┌──────────────────────────── rstun (crate, MPL-2.0) ─────────────────────────┐
│  CLI: rstun server [--listen|--listen-v6|--alt-listen|--alt-port|--tcp|       │
│                      --mapped-address|--verbose]                              │
│  ── protocol.rs   消息编解码 + 属性（手写，541 行量级）                        │
│  ── rfc5780.rs    四 socket 地址算术（Plan）                                  │
│  ── main.rs       监听/分帧/决策（decide）/统计                               │
└──────────────────────────────────────────────────────────────────────────────┘
         ▲ 运行时依赖：tokio / clap / tracing / socket2（无 STUN 库）
         └ dev-dependencies：stun-types（互解 oracle）、tokio-test
```

- **不做的事**：TURN、鉴权、限速、TLS/DTLS（见 PRD 非目标）。
- **与 Exvlan 的关系**：Exvlan 只把它当二进制/镜像用；`cargo tree -p rstun` 必须零 `exvlan-*`。

## 2. 关键取舍

| 决策 | 选择 | 理由 |
| --- | --- | --- |
| 编解码 | **手写**，`stun-types` 仅作 dev oracle | `stun-types` 缺全部 RFC 5780 属性；`stun_codec` 停更且带 `md5 0.7` 等 7 个依赖；手写保住「零运行时依赖 + 1.7 MB」卖点，且已有交叉验证 |
| RFC 5780 地址发现 | **四 socket**（每地址每端口各绑一个） | 避免 `IP_PKTINFO` 平台差异；`local_addr()` 即"包从哪来"，选 socket 即"从哪回" |
| `MAPPED-ADDRESS` | 默认关闭，`--mapped-address` 开启 | 生产在跑，关闭路径必须逐字节冻结；RFC 5389 已废弃该属性，仅老客户端需要 |
| 响应 `PADDING` 长度 | **回显请求长度**（偏离 §10 的 "SHOULD 取 MTU"） | 无放大风险、行为确定可测；在 README 明示偏离 |
| `UNKNOWN-ATTRIBUTES` 对齐 | `2N` value + 通用 TLV padding | RFC 5389 §15.9 无"重复末项"（那是 RFC 3489）；§15 通用规则 |
| `RESPONSE-PORT` | **目的端口**（发往 `client_ip:port`） | RFC 5780 §7.5 原文；源端口保持不变 |
| 版本线 | 独立 `26.410.100` 起 | 已成独立项目，semver 语义属于自己；与内核解耦 |
| 许可 | crate 级 MPL-2.0 | 文件级 copyleft（改动需回流），比 LGPL 友好；拦不住 SaaS（如需只能 AGPL） |

## 3. 「已知属性」表（防止 420 误伤）

三类缺一不可：

1. **我们自己会发/实现的**：`MAPPED-ADDRESS` `XOR-MAPPED-ADDRESS` `ERROR-CODE` `UNKNOWN-ATTRIBUTES`
   `SOFTWARE` `CHANGE-REQUEST` `RESPONSE-PORT` `PADDING` `RESPONSE-ORIGIN` `OTHER-ADDRESS`
2. **理解但不实现的鉴权簇**：`USERNAME` `MESSAGE-INTEGRITY` `MESSAGE-INTEGRITY-SHA256` `REALM` `NONCE`
   `PASSWORD-ALGORITHM` `USERHASH`（回 420 = 锁死这些客户端）
3. **ICE 簇**：`PRIORITY` `USE-CANDIDATE` `ICE-CONTROLLED` `ICE-CONTROLLING`（ICE 连通性检查就是带这些的 Binding）

**故意不收**（会回 420，因我们确实不实现）：`REQUESTED-ADDRESS-FAMILY`(0x0017)、`DONT-FRAGMENT`(0x001A)、
RFC 3489 的 `RESPONSE-ADDRESS`(0x0002)。

## 4. 数据流（一次请求）

```
UDP/TCP → 读帧（TCP 按头长度分帧，1024+ 流水） → parse
  ├─ 非 request        → 丢弃计数
  ├─ 非 Binding        → 400（保持 method）
  ├─ 未知 comprehension-required → 420 + UNKNOWN-ATTRIBUTES(2N value)
  ├─ PADDING + RESPONSE-PORT      → 400（§10 MUST）
  └─ 正常 Binding
        ├─ 选 socket：CHANGE-REQUEST（需 --alt-listen）
        ├─ 目的端口：RESPONSE-PORT（仅 UDP）
        └─ 组装：XOR-MAPPED-ADDRESS [→ MAPPED-ADDRESS] [→ RESPONSE-ORIGIN, OTHER-ADDRESS] [→ SOFTWARE] [→ PADDING]
```

## 5. 兼容与回滚

- **wire 兼容**：`--mapped-address` 关闭、无 PADDING/RESPONSE-PORT/未知属性时，响应用**冻结测试**（48 字节）锁住。
- **部署回滚**：镜像按 digest 固定 + 保留上一版镜像；CLI 加 `server` 子命令是破坏性变更，换镜像必须同步改命令。
- **发布回滚**：`rstun-v*` 与旧 `stun-v*` 并存，互不覆盖。

## 6. 已知限制

- 部署环境可能只有一条可达 UDP 路径，此时**不要开 5780**；`change-ip` 在本地/内网 vantage 验证即可。
- 镜像仅 `linux/amd64`，arm64 需 buildx+QEMU（拆仓时补）。
