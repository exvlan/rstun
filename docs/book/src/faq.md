# FAQ

## 装了却没反应，客户端拿不到映射地址？

先自检协议层，再怀疑网络：

```bash
bash script/ci/rstun-smoke.sh <ip>:3478 --tcp
```

返回 `0x0101` 说明服务端应答正常，问题在执行路径上：安全组 / 防火墙没放行 UDP、
云主机 EIP 是 1:1 NAT（要绑网卡上的私网地址）、或者该 EIP 的 UDP 回程被云侧丢弃
（见 [RFC 5780 的「回程可用」](nat-discovery.md#部署前先确认回程可用)）。

## 开了 `--realm` 之后 ICE 探测全挂了？

**预期行为**：开鉴权后无凭据的 ICE 连通性检查会收到 401（coturn 同）。需要匿名 ICE 就不要开鉴权
—— 这也是它默认关闭的原因。放大面（401 = 96 字节）要求**同时**开限速，见[鉴权](auth.md)。

## 限速是不是误伤了 NAT 后的用户？

桶按**归一化后的源 IP** 计，NAT 后所有设备共享出口 IP，也就共享一个桶。给出口网段加
`--allow 203.0.113.0/24`（只跳过每源桶，全局限速与在途上限仍生效）。排查步骤见
[抗滥用 · NAT 误伤排查](rate-limit.md#nat-误伤排查)。

## 为什么 README 里没有完整的协议表了？

行为表**只在文档站维护**（本页所在的书），README 只留摘要 + 链接，避免两处漂移。
`bash script/ci/check-docs.sh` 会检查 help 片段、参数名、指标名与链接。

## `rstun server --version` 报错？

`--version` 只在**二进制级**：版本串只有一个来源，避免「子命令报另一个版本」。
CI、镜像、包管理器自检一律用 `rstun --version`。

## lean 与 full 怎么选？

- **lean**（`cargo build`、`cargo install rstun`、brew、deb）：STUN + TURN(UDP/TCP) + REST + 带宽。
- **full**（`--features full`、Release 的 `rstun-full-*`、镜像）：再加 `turns:`(TLS) 与 DTLS 1.2。

同一版本的两种构建 `--version` 相同，区分看启动日志的 `features="lean"` / `features="tls,dtls"`。
lean 上给 `--turn-tls-listen` 会**明确拒绝启动**并提示 feature 名。

## TLS/DTLS 用哪种证书？

TLS（`--turn-tls-listen`）接受常规 RSA / ECDSA 证书；**DTLS 的私钥必须是 PKCS#8 且算法为
ECDSA P-256 或 Ed25519**（`webrtc-dtls` 的限制）。只开 TLS 时 RSA 证书必须被接受
（Let's Encrypt 的默认形态）。材料在**启动时**解析，坏证书/坏密钥对直接 exit 1，绝不降级明文。

## TURN 能通但中继数据收不到？

relay 端口段要放行 **UDP 双向**（与 coturn 同理），并避开 `net.ipv4.ip_local_port_range`
的重叠区间。TLS 要放行 TCP、DTLS 要放行 UDP —— 常见失败是「只放了 TCP 5349」。
见 [TURN 部署注意](turn.md)。

## `docker pull` 401？

新包默认 private：有凭证可拉、匿名 401。「我这边能 pull」是因为本机已登录。
见[容器 · 包可见性](docker.md#包可见性)。

## 能替代 coturn 吗？

需要 TCP allocation（RFC 6062）、ACME 自动证书、多租户数据库时**不能**，请继续用 coturn。
差异表见 [TURN · 与 coturn 的差异](turn.md#与-coturn-的差异)。
