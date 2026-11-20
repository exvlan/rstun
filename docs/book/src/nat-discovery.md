# RFC 5780（NAT 行为发现）

四 socket 布局、`CHANGE-REQUEST` / `RESPONSE-PORT` / `PADDING` 的语义，以及部署前必须确认的
回程可用性（EIP 1:1 NAT、丢 UDP 回程的地址）。

RFC 5780 让客户端判断自己处于**哪种 NAT**（映射行为 / 过滤行为），是 P2P 打洞策略的输入。
它需要服务器在**两个公网 IP × 两个端口 = 四个传输地址**上应答：

```
  ip1:port1   ← 客户端从这里开始（DNS / 发现链路里公布的那一个）
  ip1:port2   ┐
  ip2:port1   ├ CHANGE-REQUEST 会把响应改成从这三个之一发出
  ip2:port2   ┘（change-port / change-ip / 两者同时）
```

启用方式（示例用 RFC 5737 的 TEST-NET 地址，替换成你自己的两个公网 IP）：

```bash
rstun server \
  --listen 203.0.113.10:3478 \
  --alt-listen 198.51.100.20:3478 \
  --alt-port 3479
```

- **primary = 命令行顺序里第一个 IPv4 `--listen`**。它必须**写具体 IP**：`0.0.0.0` 与
  `--alt-listen` 同时出现会**直接报错退出**（不静默降级），因为「一个地址一个 socket」
  正是为了知道「这个包是发到哪个 IP 的」。
- `--alt-listen` 是第二个公网 IP（RFC 5780 的 "other address"）；**只取其中的 IP**，
  端口由 `--alt-port` 决定（默认 `--listen` 端口 + 1）。
- 两个 IP 必须同族（v4/v4 或 v6/v6）、互不相同；两个端口必须不同。校验失败一律启动即退出。
- **多地址共存**：`--listen` 可重复，`--listen-v6` 可重复；除 primary 与 alt 之外的所有地址
  （其余 v4 `--listen` + 全部 `--listen-v6`）**只做普通 Binding** —— 不带
  `RESPONSE-ORIGIN` / `OTHER-ADDRESS`，收到 `CHANGE-REQUEST` 也按 RFC 5780 §5 忽略
  （仍从原 socket 回包）。`--alt-listen` 存在时**必须至少有一个 IPv4 `--listen`**：
  `--listen-v6` 不计入 primary 选择（`change-ip` 是 v4 语义）。

> **为什么 wildcard 必须拒绝（不是「实现限制」而是「必然错答」）**：绑 `0.0.0.0` 时本机所有
> 地址共用一个 socket，回包源地址由内核按默认路由 / 策略路由**替我们挑**（通常是主 IP）。
> 客户端把请求发到第二个地址，回包却从第一个发出 —— 客户端侧 NAT / 防火墙按「请求的目标
> 地址」记账，会直接丢掉这个来自别的地址的回包。而 RFC 5780 的判据**正是回包源地址**，
> 所以这不是精度问题，而是**每个 change/advertise 路径都会给出错误结论**。一个地址一个
> socket，`send_to` 的源地址才等于「请求到达的那个地址」，也才谈得上 `RESPONSE-ORIGIN`
> 与 `OTHER-ADDRESS` 的语义。
>
> `RESPONSE-ORIGIN` 的值**故意保持**「发响应那个 socket 的本地地址」：云主机上 EIP 是
> 1:1 NAT，客户端拿到的回包源会被映射成公网地址；把属性改成公网地址反而会让
> 「属性值 ≠ 实际回包源」，破坏客户端用真实源地址做的校验。

常见形态是「两个 v4 入口 + 一个 v6 入口，只在其中一个上开 5780」：

```bash
rstun server \
  --listen 10.0.0.5:3478 --listen 10.0.0.8:3478 \
  --alt-listen 10.0.0.7:3478 --alt-port 3479 \
  --tcp --listen-v6 [::]:3478
# 10.0.0.5:3478（primary）与 10.0.0.7:* 四 socket 参与 5780；
# 10.0.0.8:3478 与 [::]:3478 只做普通 Binding。
```

## 实现要点：四个 socket，不要 `IP_PKTINFO`

常见做法是绑一个 `0.0.0.0` 的通配 socket，再用 `IP_PKTINFO` / `IPV6_RECVPKTINFO` 取出每个
datagram 的**目的地址**。那是平台相关代码（Linux/Windows/BSD 各一套，Rust 标准库不给）。

本服务反过来：**每个地址各绑一个 socket**（`ip1:p1`、`ip1:p2`、`ip2:p1`、`ip2:p2`），于是

| 问题                       | 答案                                                                          |
| -------------------------- | ----------------------------------------------------------------------------- |
| 这个包发到哪个 IP / 端口？ | 处理它的那个 socket 的 `local_addr()`                                         |
| 回包要从哪儿发出？         | 在**目标地址对应的那个 socket** 上 `send_to`（源地址就是它）                  |
| `RESPONSE-ORIGIN` 填什么？ | 应答 socket 的本地地址                                                        |
| `OTHER-ADDRESS` 填什么？   | 相对该 socket「换 IP + 换端口」的那一个（对称，从四个中的任一个进来都有意义） |

`CHANGE-REQUEST`（0x0003，4 字节：`0x04` 换 IP、`0x02` 换端口，可同时置位；未知位与保留位
忽略）只改**选哪个 socket 回包**，不改报文内容 —— 所以 `XOR-MAPPED-ADDRESS` 仍是客户端地址，
客户端用「回包源地址」就能验证。

`RESPONSE-PORT`（0x0027，2 字节端口 + 2 字节填充）按 §7.5 / §6 原文实现：响应**发往**
「请求的源 IP + `RESPONSE-PORT` 给的端口」—— 它只改**目的端口**，**源地址与源端口不变**，
仍从收到请求的那个 socket 发出，`RESPONSE-ORIGIN` 也仍然是它。因此该端口**不需要**是本进程
绑定的端口：§7.5 的 "Allowable values of RESPONSE-PORT are 0-65536" 就是说「任意端口都算合法
目的端口」，`0` 或没人监听的端口交给内核报 `send_to failed`，记一条 `warn` 后继续服务
（**不 panic、不回 400**）。
与 `CHANGE-REQUEST` **正交**：两者同时出现时，前者改**源** socket、后者改**目的**端口。

`PADDING`（0x0026）是**长度即语义**的填充串：请求带 N 字节，响应就回 N 字节（不超过 N，
且受 16 位 Message Length 上限约束），用来让一个 STUN 报文跨过路径 MTU、观察分片行为。
它不属于「地址发现」那部分，所以**不需要** `--alt-listen`。与 `RESPONSE-PORT` 同时出现时
按 §6（"the server MUST return an error response of type 400"）回 **`400 Bad Request`**；
§7.5 的 "MUST NOT process" 与 §10 的 "are rejected" 说的是同一件事，我们选最可见的那种拒绝
（静默丢弃会被客户端读成「链路被过滤」）。UDP 读缓冲是 **64 KiB**（最大 UDP 载荷），所以
1500 MTU 与 9000 jumbo 帧的探测都能被解析并原样回声 —— 缓冲更小会把要测的那些报文直接截断丢掉。

> **有意偏离：响应 `PADDING` 的长度**。RFC 5780 §6 对响应侧的 `PADDING` 用 SHOULD：
> 长度取「出接口 MTU 向上取整到 4 的倍数」（不足则补齐）。本服务**回显请求里 `PADDING`
> 的长度**（且永不放大）。理由：① 无放大风险（响应大小只由请求决定，不会被当成反射器）；
> ② 行为确定（不做 MTU 探测/缓存，不依赖平台接口，回环与容器里结果一致）；③ 易测
> （请求 N 字节 → 响应 N 字节，一条断言钉死）。代价是「按出接口 MTU 精确填充」的探测精度
> 略低，但该属性的用途是「看这个报文是否被路径分片」，客户端本来就要自己比对响应大小，
> 长度回显足够。

## 部署前先确认「回程可用」

协议正确 ≠ 网络可用。云主机上常见两种坑，都表现为「服务端看起来没问题，客户端什么都收不到」：

1. **EIP 是 1:1 NAT**：公网 IP 不在网卡上，`--listen <公网IP>` 会 `Address not available`
   直接退出。要绑**网卡上的地址**（私网 IP），云侧再把它映射成公网。
2. **某些 EIP 的 UDP 回程被云侧丢弃**：请求到达、回包已从网卡发出、客户端 0 入包，
   而同 IP 的 TCP/ICMP 正常。这种地址不能用于 `--listen` / `--alt-listen`，
   否则 `change-ip` 那一半测试永远超时，看起来像「服务器没实现」。
   上线前用 `script/ci/rstun-smoke.sh <ip>:3478 --tcp` 对每个地址各验一次；
   RFC 5780 的 `change-port` / `change-ip` / 两者同时三条路径见
   [`docs/interop-matrix.md`](https://github.com/exvlan/rstun/blob/main/docs/interop-matrix.md)（要点是看 `recvfrom` 的**真实源地址**）。

## 容器部署：必须 host 网络

`docker -p 13478:3478/udp` 这类端口映射会做源地址 NAT，`change-ip` / `change-port` 的回包
会被改写成「宿主机地址:发布端口」，RFC 5780 的判据就失效了（实测确认）。部署用
`--network host`，或给容器直连两个地址。

## 客户端侧

客户端只认 `RESPONSE-ORIGIN` / `OTHER-ADDRESS`（老客户端会忽略这两个属性），
不需要做任何适配；用 coturn 或本服务都能拿到同一组判据。
