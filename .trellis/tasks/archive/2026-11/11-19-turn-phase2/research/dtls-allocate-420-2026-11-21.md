# DTLS 上 Allocate 被 420 拒绝 —— 复现与定性（2026-11-21）

> 来源：对端（EXVlan）在 sips 生产启用 `turns:`/DTLS 后的观察：
> TLS 链路全通（aioice 401→鉴权 Allocate→relay），DTLS 握手通过但 `turnutils_uclient -S`
> 的 Allocate 返回 `420 Unknown Attribute`。
> 对端证据：`.trellis/tasks/11-21-rstun-turns/research/implementation-2026-11-21.md`（对端仓）。

## 结论（一句话）

**与 DTLS 无关**：`turnutils_uclient` 在 `-e`（显式 peer）或 `-x/-X`（显式地址族）时会在 Allocate
里带 `REQUESTED-ADDRESS-FAMILY (0x0017)`；我方未实现该属性 → 按未知 comprehension-required
属性回 `420`。`-g` 则带 `DONT-FRAGMENT (0x001A)`，同样回 `420`。我方 lab 用 `-y`
（client-to-client）不带这两个属性，所以一直是绿的。

## 复现（26.410.101，Linux，本地 127.0.0.1）

```bash
# 证书 + 服务端
openssl ecparam -name prime256v1 -genkey -noout -out sec1.pem
openssl pkcs8 -topk8 -nocrypt -in sec1.pem -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 2 -subj "/CN=localhost"

RUST_LOG=debug rstun server --listen 127.0.0.1:3478 --turn --realm exvlan \
  --auth-secret s3cret --auth-user exvlan --auth-pass exvlan \
  --relay-ports 40000-40100 --turn-dtls-listen 127.0.0.1:5349 \
  --tls-cert cert.pem --tls-key key.pem
```

| # | uclient 调用 | 结果 | 服务端 `unknown` |
| --- | --- | --- | --- |
| A | `-S -y`（我方 lab 口径）| ✅ 中继通，`tot_send=2000 / tot_recv=2000`，lost 0 | — |
| B | `-S -e 127.0.0.1` | ❌ `error 420` | `[23]` = 0x0017 RAF |
| C | `-S -y -g` | ❌ `error 420` | `[26]` = 0x001A DONT-FRAGMENT |
| D | `-S -y -X`（显式 IPv4）| ❌ `error 420` | `[23]` RAF |
| E | `-S -y -x`（请求 IPv6）| ❌ `error 420` | `[23]` RAF |
| F | 纯 UDP `-e`（不带 `-S`）| ❌ `error 420` | `[23]` RAF |

服务端日志（DEBUG，`src/turn.rs:841-849`）：

```
DEBUG rstun::turn: rstun: TURN request with unknown comprehension-required attributes
      peer=127.0.0.1:16089 unknown=[23]
```

F 证明：**同一 420 在纯 UDP 上也出现**，传输层（DTLS/TLS/UDP/TCP）不是变量；
代码路径 `turn_unknown_attributes()` 在按传输分派之前执行。

## RFC 定性：两个属性待遇不同

| 属性 | 类型码 | RFC 8656 的要求 | 我方行为 | 判定 |
| --- | --- | --- | --- | --- |
| `DONT-FRAGMENT` | 0x001A | §7.2 步骤 4：**服务器不支持设置 DF 位时，把它当作未知的 comprehension-required 属性** | `420` + `UNKNOWN-ATTRIBUTES` | ✅ **合规**（RFC 明文允许）|
| `REQUESTED-ADDRESS-FAMILY` | 0x0017 | §7.2 步骤 7：不支持所请求地址族时回 **440**（Address Family not Supported）；缺失且支持 IPv4 则分配 IPv4 | `420` | ❌ **实现偏差**（少解析一步，码也不对）|

`ADDITIONAL-ADDRESS-FAMILY`（0x8001 一带，comprehension-optional）目前被忽略，属正确行为。

`420` 响应本身是规范的（RFC 5389 §7.3.1：未知 comprehension-required 属性 → 420 +
`UNKNOWN-ATTRIBUTES` 列出类型号）；对端从 pcap 里能直接看到 `0x0017`。

## 文档现状

`docs/book/src/turn.md` 已列「不支持 `DONT-FRAGMENT`、`REQUESTED-ADDRESS-FAMILY`」，
但把两者都写成「→ 420」，未区分 **DF 合规 / RAF 应为 440**——待随实现或文档修正。

## 选项（待决策）

1. **只改文档**：把 `turn.md` 写清楚「DF=420（RFC 明文）；RAF 目前 420，规范期望 440，未实现」，
   对端按「DTLS 可用、Allocate 仅 IPv4」写他们的文档。成本≈0。
2. **补 RAF 最小实现**（推荐作为二期子项）：解析 0x0017（len=4，family 0x01/0x02，reserved 忽略）：
   - family 与本端 relay 地址族一致 → 正常 Allocate；
   - 不一致（如请求 IPv6 而只支持 IPv4）→ `440`；
   - len≠4 或 family 非 0x01/0x02 → `400`。
   预计 20–30 行 + 4 个用例（匹配/不匹配/长度错/未知族），并补进 `turn.md` 行为表与冻结对照口径
   （注意：这**会改变**带 RAF 请求的响应字节，需更新 freeze 基线说明，但不影响默认路径）。
3. **整个二期一起做**（RFC 6062 TCP allocation、DF、多实例、证书热载），RAF 作为其中一项。

## 对端的即时解（无需我方改动）

他们的目的只是验证 DTLS 链路，不消费 TURN：

```bash
turnutils_uclient -S -u <user> -w <pass> -p 5349 -n 5 -m 2 -y <server>   # 不带 -e/-x/-X/-g
```

`-y` 走 client-to-client，不带 RAF/DONT-FRAGMENT，本仓全通（含 `ChannelData` 与 permissions）。
