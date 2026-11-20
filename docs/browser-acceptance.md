# `turns:` 浏览器验收（人工步骤）

> **状态：本仓库没有自动化浏览器验收。** 这是一份人工步骤清单，最近一次执行：**未执行（待办）**。
>
> 协议层已经有了可重跑的自动化：`script/lab/rstun-turn.sh --tls`（`openssl s_client` 握手 +
> `turnutils_uclient -S -t` 中继 + 与本地 coturn 同参数对跑 + 坏证书/坏密钥对拒绝启动），
> `--dtls` 同理。浏览器这一层能自动化的只有「TLS 握手能不能成」——**ICE 是否真的选中 relay
> candidate、对称 NAT 下能不能通，只能人工确认**，所以本文不声称「已验证」。

## 0. 前置

- **full 构建**：`cargo build --release --features full`（或直接用镜像，镜像就是 full）。
  lean 二进制给 `--turn-tls-listen` 会直接拒绝启动并提示缺 `tls` feature。
- 一张证书 + 私钥（PEM）。本地验收用自签即可：

  ```bash
  openssl ecparam -name prime256v1 -genkey -noout -out key-sec1.pem
  openssl pkcs8 -topk8 -nocrypt -in key-sec1.pem -out key.pem      # 只有要开 DTLS 才必须是 PKCS#8
  openssl req -new -x509 -key key.pem -out cert.pem -days 2 \
    -subj "/CN=turn.example.com" \
    -addext "subjectAltName=DNS:turn.example.com,IP:203.0.113.10"
  ```

  生产用 Let's Encrypt 即可：**RSA 证书可以用，只要不开 `--turn-dtls-listen`**
  （DTLS 只接受 ECDSA P-256/Ed25519，见 README「TURN」表）。
- 网络：客户端 → 服务器放行 **3478/udp**（STUN/ICE）、**5349/tcp**（`turns:`），
  以及 `--relay-ports` 段 **UDP 双向**。只放 TCP 是最常见的「握手成功但没声音」。

## 1. 起服务

```bash
rstun server \
  --listen 0.0.0.0:3478 \
  --turn --realm example.org --auth-secret "$SECRET" \
  --auth-file /etc/rstun/users.txt \
  --relay-ports 49152-65535 \
  --turn-tls-listen 0.0.0.0:5349 \
  --tls-cert /etc/rstun/cert.pem --tls-key /etc/rstun/key.pem \
  --health-listen 127.0.0.1:9100
```

期望启动日志（片段）：

```
INFO rstun: features="tls,dtls" listeners=2                 # lean 是 features="lean" 且上面会直接报错
INFO rstun: TURN TLS listener ready local=0.0.0.0:5349
INFO rstun: TURN over TLS enabled (turns:) listeners=[0.0.0.0:5349]
INFO rstun: started, Ctrl-C to stop
```

先用命令行确认 TLS 这一层是通的（不依赖浏览器）：

```bash
openssl s_client -connect turn.example.com:5349 -servername turn.example.com </dev/null | head -5
# 期望：Verify return code: 0 (ok) 或自签的 self signed certificate；CONNECTED
```

## 2. 让 Chrome 信任自签证书

`turns:` 的证书校验发生在 TLS 握手，**证书不受信时 ICE 直接失败**，页面上通常只有
`Failed to connect` / `ICE failed`，看不到「证书」字样。二选一：

1. **导入信任库**（推荐，接近生产行为）
   - Linux：`sudo cp cert.pem /usr/local/share/ca-certificates/rstun-test.crt && sudo update-ca-certificates`，重启 Chrome。
   - macOS：钥匙串访问 → 导入 `cert.pem` → 「始终信任」。
   - Windows：`certmgr.msc` → 受信任的根证书颁发机构 → 导入。
   - 证书的 SAN 必须包含你访问用的主机名（`turn.example.com`），否则即使受信也会主机名不匹配。
2. **临时跳过**（仅本地，别用于演示环境）：拿到证书 SPKI 的 base64 SHA-256 再启动 Chrome：

   ```bash
   openssl x509 -in cert.pem -pubkey -noout \
     | openssl pkey -pubin -outform der \
     | openssl dgst -sha256 -binary | base64
   # 然后： google-chrome --ignore-certificate-errors-spki-list=<上面那串>
   ```

## 3. 本地 WebRTC demo

任意 ICE demo 页都可以；关键是 `iceServers` 与 `iceTransportPolicy`。最小页面（可直接存成
`turn-demo.html`，用 `https://` 或 `http://localhost` 打开）：

```html
<script>
const pc = new RTCPeerConnection({
  iceServers: [{
    urls: "turns:turn.example.com:5349",
    username: "turnuser",              // 静态用户，或 REST 的 "<expiry>:<label>"
    credential: "turnpass",            // REST 时是 base64(HMAC-SHA1(secret, username))
  }],
  // 验收必须强制 relay：否则浏览器优先 host candidate，TURN 根本没被用到
  iceTransportPolicy: "relay",
});
pc.onicecandidate = (e) => console.log("candidate:", e.candidate && e.candidate.candidate);
pc.oniceconnectionstatechange = () => console.log("ice:", pc.iceConnectionState);
pc.ondatachannel = (e) => e.channel.onmessage = (m) => console.log("recv:", m.data);

const dc = pc.createDataChannel("probe");
dc.onopen = () => { console.log("channel open"); dc.send("hello over turns"); };
pc.createOffer().then((o) => pc.setLocalDescription(o));
</script>
```

用一个**另一个**页面/浏览器实例作为对端（同一页面也可以：两个 `RTCPeerConnection` 互连），
把 offer/answer 手工贴过去，或者直接用任何支持「填 TURN 参数」的 trickle ICE 测试页。

## 4. trickle ICE 观察点

- 控制台出现 **relay candidate**：`candidate:… typ relay raddr … rport …`；
  `iceTransportPolicy: "relay"` 下这是唯一合法的候选类型。
- SDP 里 `a=candidate:… typ relay`；`pc.getStats()` 的 `local-candidate` 项
  `candidateType === "relay"`、`relayProtocol === "tls"`。
- `oniceconnectionstatechange` 走到 `connected` / `completed`，`ondatachannel` 的 `onopen` 触发。
- 服务端侧（`--health-listen`）：
  - `rstun_turn_allocations` ≥ 1；
  - `rstun_turn_bytes_total{direction="in"}` 与 `{direction="out"}` 都增长；
  - `--verbose` 日志里 `rstun: TURN allocation created transport=Tcp`（`turns:` 走 TCP 分支；
    DTLS 才是 `Dtls`）。

## 5. 对称 NAT 拓扑（PRD 要求「至少一方在对称 NAT 后」）

| 拓扑 | 做法 | 期望 |
| --- | --- | --- |
| A：单侧对称 NAT | 客户端 A 接 **4G/5G 热点**（运营商级 NAT，通常是对称的），客户端 B 在另一条网络 | 两边都出现 `typ relay`，`connected`，数据通道互通 |
| B：双侧不同网络 | A 在家用 NAT 后、B 在办公室 NAT 后，服务端公网 | 同上；服务端 `rstun_turn_allocations` = 2 |

记录：两端 candidate 类型（必须都是 relay）、`iceConnectionState`、服务端 allocation 数与
`bytes_total` 前后差值。判定标准是**媒体/数据确实经 relay 双向通过**，不是「ICE 变绿」——
`iceTransportPolicy: "relay"` 已经排除了直连的可能。

## 6. 常见失败

| 现象 | 原因 | 排查 |
| --- | --- | --- |
| `ICE failed`，没有任何 relay candidate | 证书不受信 / 主机名不匹配 | Chrome DevTools → Security；按 §2 导入信任；确认 SAN |
| 有 relay candidate 但 `checking` 卡住 | relay 端口段没放行（UDP 双向） | `ss -lun` 看 relay socket；防火墙；`--relay-ports` 是否与 `ip_local_port_range` 冲突 |
| `401` / allocation 建不起来 | 用户/口令错，或 REST 凭据过期 | 静态用户查 `--auth-file`；REST 查 `<expiry>` 与 NTP |
| 启动就退出，提示 `tls` feature | 用了 lean 二进制 | `cargo build --features full` 或用镜像 |
| DTLS 监听起不来，提示 ECDSA | 证书是 RSA | 换 ECDSA P-256/Ed25519，或去掉 `--turn-dtls-listen` |
| 只有 host/srflx candidate | 忘了 `iceTransportPolicy: "relay"` | 加上重试；或看 SDP 里的 `typ` |
