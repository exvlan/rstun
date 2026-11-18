# Changelog

版本线**独立于任何宿主项目**：`YY.QMM.Mmpp`（年.季度月.月日+序号），首发 `26.410.100`。
`rstun-v*` 的 Release tag / 镜像 tag / 资产名都用这里给出的版本号。

## 26.410.100

首个独立发布（仓库 `github.com/exvlan/rstun`，整仓 MPL-2.0）。

### 协议合规（T0）

- **`420 Unknown Attribute`**（RFC 5389 §7.3.1/§15.9）：请求里出现未实现的
  comprehension-required 属性时返回 `0x0111` + `ERROR-CODE 420` +
  `UNKNOWN-ATTRIBUTES`（`0x000A`）。值长度恰为 `2×N`（N=1/2/3 → 2/4/6 字节），
  不足 4 字节由通用 TLV padding 补齐且**不计入** Length —— **不重复末项**
  （那是 RFC 3489 的写法，5389 已删除该规则）。
- **「已知属性」表**：显式收录鉴权簇（`USERNAME` / `MESSAGE-INTEGRITY` /
  `MESSAGE-INTEGRITY-SHA256` / `REALM` / `NONCE` / `PASSWORD-ALGORITHM` / `USERHASH`）
  与 ICE 簇（`PRIORITY` / `USE-CANDIDATE` / `ICE-CONTROLLED` / `ICE-CONTROLLING`），
  它们**不**触发 420 —— 否则正常 ICE 客户端会被打死。
- **`MAPPED-ADDRESS`**（RFC 5389 §15.1）新增 `--mapped-address` 开关，**默认关闭**；
  关闭时响应字节与拆分前**逐字节一致**（`plain_response_bytes_are_frozen` 冻结测试锁住）。
- **`RESPONSE-PORT`**（RFC 5780 §7.5）：按**目的端口**语义实现 —— 响应发往
  「请求的源 IP + 指定端口」，**源 IP / 源端口不变**；仅 UDP。
- **`PADDING`**（RFC 5780 §7.6）：回显且**永不放大**。
  有意偏离 §6 对响应侧 PADDING 的 SHOULD（「按出接口 MTU 补齐」）：我们回显请求长度，
  理由是「无放大风险 / 行为确定 / 易测」，详见 README「有意偏离」。
- **`PADDING` + `RESPONSE-PORT` 同时出现 → `400 Bad Request`**（RFC 5780 §10 MUST）。

### 多地址 / IPv6 共存

- `--alt-listen` **不再要求「恰好一个地址」**：`--listen` / `--listen-v6` 均可重复，
  **primary = 命令行顺序里第一个 IPv4 `--listen`**（不排序、不猜），其余 v4 地址与
  全部 `--listen-v6` 只做普通 Binding：不带 `RESPONSE-ORIGIN` / `OTHER-ADDRESS`，
  收到 `CHANGE-REQUEST` 按 §5 忽略（仍从原 socket 回包）。
- `--listen-v6` 以 **v6-only** 绑定，可与 `--listen` 同端口共存，且**不参与** primary 选择。
- `--tcp` 与 `--alt-listen` 可同时开启（TCP 上 `CHANGE-REQUEST` / `RESPONSE-PORT` 被忽略）。

### 互操作验证（T1）

- **四方矩阵全绿**：coturn `turnutils_stunclient` 4.6.1、pion/stun v3.1.7、
  webrtc-rs `stun` 0.17.3、`stun-types` 2.0.5，双向（他们发 → 我们答；我们发 → 他们答），
  共 38 项子用例 / 176 条断言。
- **RFC 5769 §2.1–§2.4** 四段标准字节全部通过（§2.2/§2.3 的 `XOR-MAPPED-ADDRESS`
  可逐字节重建）。
- **`cargo-fuzz` 解析路径 600 s**：`Done 84319569 runs in 601 second(s)`，零 panic、零挂死。
- 报告与原始输出摘录见 [`docs/interop-matrix.md`](docs/interop-matrix.md)。

### 工程

- 仓库独立：无 workspace、无 path 依赖，`cargo tree -e normal` 只有
  `clap` / `socket2` / `tokio` / `tracing` / `tracing-subscriber`（`stun-types` 仅测试用）。
- `Cargo.lock` 随源码提交；`rust-toolchain.toml` 固定 1.95（rustfmt + clippy）。
- 构建版本注入统一用 **`RSTUN_BUILD_VERSION`**（`<version>+<sha6>`）；
  `EXVLAN_BUILD_VERSION` 仅作为旧构建链路的兼容回落保留。
- CI：三平台单测 + fmt/clippy + UDP/TCP 冒烟 + IPv6 冒烟；
  发布：四平台 zip + `ghcr.io/<owner>/rstun` 双架构（amd64/arm64）镜像。
