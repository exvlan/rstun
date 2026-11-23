# TURN（RFC 8656：UDP / TCP / `turns:` / DTLS）

`--turn` 默认关闭；开启即强制长期凭据（或 `--rest-secret`），不存在匿名开放中继。
本页含方法/生命周期/配额/数据面/TLS/DTLS/REST/带宽的完整契约与 coturn 对照。

> `--allocation-lifetime` 同时是**默认授予值**与**上限**：客户端不带 `LIFETIME`、或给的值小于 600 时得到 600，
> 超过上限时得到上限（`--allocation-lifetime 2` 正是回收测试用的形状）。
> TURN 的**成功**响应带 `SOFTWARE`，失败响应（401/437/441/486/508）不带——RFC 8656 §6.1 对失败响应是 SHOULD，
> 这里按「与 STUN 共享 401/438 编码、保持默认关闭字节冻结」取舍。

RFC 8656 的中继闭环：UDP / TCP 客户端传输、`turns:`（TLS）、DTLS 1.2、TURN REST 临时凭据、
每 allocation 带宽配额。TURN **默认关闭**；开启即强制长期凭据（或 `--rest-secret`）—— 缺
`--realm` / `--auth-secret` / 用户/secret 时**启动失败（exit 1）**，不存在「匿名开放中继」形态。
**不配 T2 的任何开关时，行为与 T1 逐字节一致**（回归脚本 `frozen` 项：3 配置 × 17 请求）。

```bash
rstun server \
  --listen 203.0.113.10:3478 \
  --turn --realm example.org --auth-secret "$SECRET" \
  --auth-file /etc/rstun/users.txt \
  --relay-ports 49152-65535 \
  --max-allocations-per-user 8 --max-allocations-per-ip 16 --permission-limit 10 \
  --health-listen 127.0.0.1:9100
```

| 项 | 行为 |
| --- | --- |
| 方法 | `Allocate` / `Refresh` / `CreatePermission` / `ChannelBind`；`Send`/`Data` indication；`ChannelData`（UDP / TCP / TLS / DTLS 客户端传输，relay 本身恒为 UDP）|
| 鉴权 | 四个 request 方法都必须带 `MESSAGE-INTEGRITY`（长期凭据，复用 STUN 的 realm/nonce 实现）：无 MI → `401` + `REALM`/`NONCE`；nonce 过期 → `438` + 新 `NONCE`；错口令/未知用户 → `401`。**401/438 同样计入限速桶** |
| 生命周期 | `Allocate` 默认授予 **600s**（`LIFETIME=0`/缺省都按默认）；请求值低于默认时按 RFC 8656 §7.2 取默认，高于 `--allocation-lifetime` 上限被截断；`REFRESH LIFETIME=0` 立即释放；**`Refresh` 缺 `LIFETIME` 也按默认续期**（§8.2）；permission TTL **5 分钟**、channel TTL **10 分钟**；到期由 1s 扫描任务回收 |
| 5 元组 | `(client addr, client transport, server addr)`；**同一 transaction id** 的重传 `Allocate` 幂等返回同一 relay；**新 transaction id → `437`**；**同一 5 元组换用户 → `441 Wrong Credentials`**（不得暴露/改动他人 allocation，`LIFETIME=0` 也不删）；释放后再 `Refresh` → `437` |
| 端口与配额 | `--relay-ports` 耗尽 → `508`；每用户 `--max-allocations-per-user`（默认 8）/ 每 IP `--max-allocations-per-ip`（默认 16）超限 → `486`；每 allocation permission 超 `--permission-limit`（默认 10）→ **`508`**（RFC 8656 §10.2；一条请求带多个 peer 时**整条原子校验**，不做部分生效） |
| 响应属性 | 成功响应带 `SOFTWARE`（RFC 8656 §14.10 SHOULD），401/438 挑战不带；`ChannelBind` 隐式创建的 permission 与 `CreatePermission` 共用同一个上限 |
| 数据面 | `Send` 仅在 permission 覆盖 peer 时转发（否则静默丢弃）；relay 收到 peer 数据时，命中 channel → `ChannelData`，否则 → `Data` indication；`ChannelData` 不解析 STUN；**UDP 上声明长度大于实际报文的 `ChannelData` 静默丢弃**（不转发截断内容）；TCP 客户端写队列有界（64 帧，溢出丢 relayed 数据）|
| 其它 transport | `REQUESTED-TRANSPORT=6`（TCP allocation / RFC 6062）：**默认 `442`**；加 `--turn-tcp-relay` 后走下面的「RFC 6062」小节（仅出站 `Connect` + `ConnectionBind`）；`EVEN-PORT`（含 R=1 reservation token）支持；`REQUESTED-ADDRESS-FAMILY`（0x0017，§18.6）已解析：与 relay 地址族一致 → 正常分配（relay 族跟随客户端：IPv4 客户端 + IPv4、IPv6 客户端 + IPv6）；请求的族本端提供不了（如 IPv4 客户端请求 `0x02`）或族值非 `0x01`/`0x02` → **`440 Address Family not Supported`**；长度 ≠ 4 → `400`；**保留 24 位忽略**（非零不报错）；`Refresh` 上族不匹配 → **`443 Peer Address Family Mismatch`**（§8.2 MUST）、匹配 → 正常续期、长度 ≠ 4 → `400`；`RESERVATION-TOKEN` 与 `EVEN-PORT`/RAF 互斥 → **`400`**（§7.2 步骤 5 先于步骤 7，异族 token 也是 400）；`ADDITIONAL-ADDRESS-FAMILY`（0x8000，comprehension-optional）未实现 → 忽略（因此步骤 6 的「RAF+AAF → 400」不生效）；`DONT-FRAGMENT`（0x001A，§18.9）在 **Linux/macOS/iOS** 上真支持（`Allocate` 置 DF、长度 ≠ 0 → `400`、`setsockopt` 失败 → `500`；`Send` 带它而置不上 DF → **丢弃该 indication**，§11.2），其它平台（Windows/FreeBSD 等）仍按未知 comprehension-required → `420`（§7.2 步骤 4 允许）|
| TLS（`--turn-tls-listen`）| **仅 full 构建**（`tls` feature；lean 给出该 flag 会拒绝启动并说明）。在 TCP 分帧之上套 TLS 1.2/1.3（`tokio-rustls`，ring provider）。`--tls-cert`/`--tls-key` 在**启动时**解析：路径不可读、证书/私钥不配对、给了监听却没给材料 → **启动失败**（绝不降级明文）。**运行期可热加载**：`SIGHUP`（unix）或两条路径的 `(mtime,len)` 变化（`--tls-cert-poll` 轮询，默认 30s、`0` = 只认 `SIGHUP`，Windows 唯一路径）会用**同一套校验**重新解析，成功后整体替换 `ServerConfig` —— 新连接用新证书，**已建立会话持有旧证书**（TLS 无重协商）；失败保留旧材料、`reload_total{result="failed"}` +1、`warn` 日志。握手 5s 超时、失败计数（退出日志 `handshake_failed`），日志不含证书内容。TLS 与明文**不共用端口** |
| DTLS（`--turn-dtls-listen`）| **仅 full 构建**（`dtls` feature，含 `tls`）。DTLS 1.2（`webrtc-dtls`，纯 Rust）。**一个 datagram = 一个 STUN/TURN 消息或一个 `ChannelData`**（与 UDP 同构，无 4 字节对齐）；5 元组的 client transport 记为 `Dtls`；握手在每客户端独立任务里做（5s 超时），不阻塞 accept。私钥必须是 **PKCS#8** 且算法为 **ECDSA P-256 / Ed25519**（`webrtc-dtls` 的限制，启动时明确报错）。与 TLS 共用同一份材料与同一个替换槽位：热加载一次对两侧**同时**生效，新会话用新证书、已建立会话保持旧证书（DTLS 无重协商/会话恢复）|
| REST 临时凭据（`--rest-secret`）| coturn `use-auth-secret` 兼容：`username = <expiry-unix>:<label>`、`password = base64(HMAC-SHA1(secret, username))`（**标准 base64**，带 `=` 填充）。过期 → `401`（不是 438：nonce 仍有效，换凭据而不是换 nonce）；HMAC 不匹配 → `401`。**与长期凭据并存时 REST 优先**（用户名能解出时间戳即走 REST，不再查用户表）；`<expiry>:<label>` 的 label 可含 `:`（按**第一个** `:` 切分，coturn 同）|
| 带宽配额（`--turn-bandwidth`）| 每 allocation 两个令牌桶（client→peer / peer→client），容量 = 1 秒的字节数，默认 **1 MiB/s**、`0` = 不限。超限**丢该包并计数**，allocation 与通话不受影响；与端口/分配配额独立 |
| 观测（T2 增量）| `rstun_turn_bytes_dropped_total{direction=in\|out}`（带宽丢包字节）；退出日志另有 `handshake_failed`。T2 不新增其它指标，握手失败不进 `/metrics` 以免改变标签集合 |
| 防回环 | 拒绝：`unspecified` / `multicast` / 本进程**监听地址** / 该 allocation 自己的 relay / **loopback peer**（仅当请求到达的 socket 本身绑定在回环地址时放行，供本地开发与 `-y` 矩阵）→ `403`。`--listen 0.0.0.0` 或公网监听下回环 peer 一律拒绝（否则「peer=127.0.0.1:<监听端口>」漏检）。同一进程内**其它 allocation 的 relay 地址允许** —— `turnutils_uclient -y` / 同 NAT WebRTC 的正常路径。**已知盲区**：宿主自身公网 IP 无法在不引入接口枚举依赖的情况下判定 |
| 回收 | allocation 过期 / `LIFETIME=0` → abort relay 读任务 → 关闭 socket → 端口归还池；测试断言过期后 `ss -lun` 在 relay 段内无监听 |
| 观测 | `/metrics`：`rstun_turn_allocations`（gauge）、`rstun_turn_bytes_total{direction=in\|out}`、`rstun_turn_allocations_total{result=created\|expired}`、`rstun_turn_rejected_total{reason=quota\|ports\|family\|loopback\|df\|tcp_connect\|tcp_bind\|tcp_send\|tcp_buffer\|tcp_quota}`、`rstun_turn_tcp_connections{state=pending\|bound}`（gauge）；配了 `turns:`/DTLS 时另有 `rstun_turn_tls_reload_total{result=ok\|failed}` 与 `rstun_turn_tls_cert_expires_seconds`（当前 leaf 的 `notAfter − now`；负值 = 已过期，`-1` = 无法解析）。退出日志打印同一组数字。**未开 `--turn` 时这些指标不出现**；没配 TLS/DTLS 监听时两个证书指标也不出现；`tcp_*` 在没开 `--turn-tcp-relay` 时恒为 0 |
| **RFC 6062（`--turn-tcp-relay`，默认关）** | `Allocate(REQUESTED-TRANSPORT=6)` 只在 **TCP/TLS 控制连接**上成功（UDP/DTLS → `400`），带 `DONT-FRAGMENT`/`EVEN-PORT`/`RESERVATION-TOKEN` → `400`；成功响应带 TCP `XOR-RELAYED-ADDRESS` + `XOR-MAPPED-ADDRESS` + `LIFETIME` + `SOFTWARE`，**不带 `CONNECTION-ID`**。`Connect` 从 relay 地址出站连 peer（超时 ≥30s，失败 `447`），成功回 `200` + `CONNECTION-ID`，**不带 `SOFTWARE`**（对齐 coturn）；重复 peer `446`，无 allocation/非 TCP allocation `437`，无 peer 地址 `400`，禁用地址 `403`，每 allocation 超过 16 条数据连接 `508`。`ConnectionBind` 在**新连接**上（必须是首个未成功的 TURN 请求）用同一凭据绑定，之后该连接是**裸字节**（不再解析 STUN）；错/过期/重复 ID → `400` 后关闭（coturn 只发 RST，本实现更规范）。`ChannelBind` → `400`；`Send`/`ChannelData` 丢弃并计 `tcp_send`。预绑定 peer 数据最多缓冲 64 KiB（超限关连接 + `tcp_buffer`）；pending 连接 30s 未 bind 关闭；`LIFETIME=0`/过期关闭全部数据连接（**控制连接保留**，coturn 会一起关，记为有意差异）。**被动模式（`ConnectionAttempt`，peer 主动连入 relay）本期不做**。`--turn-bandwidth` 不作用于 TCP allocation 的裸字节流（逐包丢弃会破坏字节流），只计 `rstun_turn_bytes_total` |

部署注意：

- **防火墙**：客户端 → `--listen` 的 UDP 要放行；relay 端口段也要放行 **UDP 双向**（与 coturn 同理），
  否则 `Allocate` 能成功但中继数据收不到。
- **临时端口冲突**：Linux 默认 `net.ipv4.ip_local_port_range`（常见 `32768 60999`）与默认
  relay 段 `49152-65535` 重叠。生产建议显式给一个不重叠的 `--relay-ports`（或调整内核范围），
  否则内核可能先占用 relay 段里的端口，表现为偶发 `508`。
- **多实例**：同一 `--auth-secret` 的实例互认 nonce；allocation 状态**不共享**（客户端会被
  `401` 后的重试带到同一实例，靠 LB 一致性哈希/源地址亲和）。REST 临时凭据是**无状态**的：
  同一 `--rest-secret` 的实例都能校验，适合水平扩展。
- **`turns:`/DTLS 端口与证书**：TLS/DTLS 监听**不占** relay 端口段，也不与 `--listen` 共用端口
  （RFC 8656 允许独立端口；共用需 ALPN/嗅探，本实现不做）。防火墙要同时放行 TLS 的 **TCP** 与
  DTLS 的 **UDP**；常见失败是「只放了 TCP 5349，DTLS 握手超时」。
  **证书热加载**：保持 `--tls-cert`/`--tls-key` 路径不变，在原地覆盖文件后
  `kill -HUP <pid>`（Linux/macOS）即可，**不用重启**；不想发信号或 Windows 上则依赖
  **文件轮询**（比对 `(mtime,len)`，最坏一个轮询间隔 + 一次握手生效）。轮询间隔用
  `--tls-cert-poll <秒>` 调（默认 **30**）；`--tls-cert-poll 0` = **关掉轮询、只认 `SIGHUP`**
  —— 只用信号轮换的部署（例如侧车写完两张文件再发信号）可以借此避免「先写 cert 后写 key」
  窗口里的一次 `reload_total{result="failed"}` 噪音。Windows 没有 `SIGHUP`，轮询是唯一触发，
  所以在那里 `0` 会在启动时被**拒绝**。该 flag 与 `--tls-cert`/`--tls-key` 同组：给了它却
  没有 `--turn-tls-listen`/`--turn-dtls-listen` → 启动失败（避免「设了但从不生效」）。
  校验规则与启动时**完全相同**：
  不配对 / RSA 以外的 DTLS 限制 / 非 PKCS#8 / 截断 / 空文件都会被拒绝，**旧材料继续服务**，
  `rstun_turn_tls_reload_total{result="failed"}` +1 并打 `warn` 日志（不含私钥）。
  先写证书再写私钥的中间态会因 1s 重试被跳过。生效范围：**新连接/新 DTLS 会话**用新证书，
  已建立的会话保持旧证书（TLS 1.2/1.3 与 DTLS 均无重协商）。本实现**未启用** TLS 会话恢复
  （rustls 默认：无 `ServerSessionStorage`、不发 TLS 1.3 ticket），重载不改变这一点；若将来
  开启，整体替换 `ServerConfig` 才会清空 1.2 缓存与 1.3 ticket key。
  轮询只看 `(mtime,len)`：若覆盖时文件大小与 mtime 都没变（例如 `cp -p`/保留时间戳），轮询
  不会感知 —— 此时用 `kill -HUP <pid>` 强制重载。
  到期时间看 `rstun_turn_tls_cert_expires_seconds`（秒，`openssl x509 -enddate` 同值）。
  **`SIGHUP` 是稳定接口**：用 `--tls-cert-poll 0` 的部署（写文件 + 主动发信号）完全依赖它；
  任何移除/改名/语义变化都按**破坏性变更**处理（CHANGELOG + 发版前通知）。
  没有 `--health-listen` 时**没有任何 `/metrics`**（TURN 指标族同样不可见），轮换的唯一证据是
  日志行 `TURN TLS certificate reloaded cert=…` 加上「进程未重启」（`StartedAt`/`RestartCount`）；
  要用指标核对或告警，请配 `--health-listen`（内网地址）。
  DTLS 私钥必须是 PKCS#8（`openssl genpkey`），证书算法 ECDSA P-256 或 Ed25519；自签证书在浏览器
  里需要手动信任（`chrome://flags` 或导入系统信任库），否则 `turns:` 会在 ICE 阶段直接失败。
- **REST 时钟**：`username` 里的过期时间是**服务器本地时钟**（unix 秒）。过期判定严格
  （`now >= expiry` 即拒绝），部署前请确认 NTP：客户端与服务器的偏差会直接变成「凭据提前/延后失效」。
  生成示例：

  ```bash
  expiry=$(( $(date +%s) + 3600 )); user="$expiry:alice"
  pass=$(printf %s "$user" | openssl dgst -sha1 -hmac "$REST_SECRET" -binary | base64)
  # 或在 python 里：
  python3 -c 'import base64,hmac,hashlib,sys,time; u=f"{int(time.time())+3600}:alice"; print(u, base64.b64encode(hmac.new(sys.argv[1].encode(), u.encode(), hashlib.sha1).digest()).decode())' "$REST_SECRET"
  ```
- **带宽配额口径**：桶容量 = 1 秒的 `--turn-bandwidth`，所以首秒可以突发一整桶；持续速率超过
  配额的部分才会被丢弃。低于单个报文的配额（例如 `--turn-bandwidth 100` 配 1200 字节包）会让
  该方向**全丢** —— 需要更细的粒度请把值设到 ≥ 一个典型报文。
- **通道号范围**：接受 `0x4000–0x7FFF`。RFC 8656 §12.1 定义到 `0x7FFE`；`0x7FFF` 是为 coturn
  兼容而放行（其解析器接受该值）。
- **指标口径**：`rstun_turn_bytes_total` 只计 relay payload（不含 STUN / ChannelData 头），
  `direction=in` 为 client→peer、`out` 为 peer→client；`rstun_requests_total` 也计 TURN 报文
  （同一 transport 循环），TURN 专用口径请看 `rstun_turn_*`。
- **配额抖动**：过期但尚未被 1s 扫描移除的 allocation 仍计入 per-user/per-IP 配额，
  高 churn 下可能多拒绝一次 `486`，下一次扫描恢复。
- **防回环已知盲区**：不枚举宿主接口，故「peer = 宿主自身公网 IP:端口」无法识别；
  需要该能力时应改用 coturn 或引入接口枚举（T2 评估，新增依赖需单独立项）。
- 不支持：RFC 6062 的**被动模式**（`ConnectionAttempt`，peer 主动连入 relay）、ACME/OCSP、
  SNI 多证书、证书**自动续期**（热加载是「重读同一路径」，续期工具写好文件后发 `SIGHUP` 或等轮询即可）。
- **RFC 6062 部署注意**：TCP relay 端口需要放行 **TCP**（`--relay-ports` 同一段，UDP 与 TCP 各自独立占端口）；`Connect` 从 relay 地址出站依赖 `SO_REUSEPORT`（Linux/macOS），**Windows 上回退为临时源端口**（peer 看到的源端口不是 relay 端口，连接本身仍可用）。数据连接是 accepted TCP 连接，**占用一个 `--max-inflight` 名额**。
- **`DONT-FRAGMENT`（0x001A）**：在**能真的置 DF 的平台**上支持（Linux、macOS/iOS；
  上一节的 `df` 行）。五处细节值得记住：
  1. `Allocate` 带它 → relay socket 置 `IP_PMTUDISC_DO`（Linux）/ `IP_DONTFRAG=1`（macOS），
     整个 allocation 生命周期有效；`ChannelData` 没有属性位，因此**沿用**该设置。
  2. `Send` indication 带它 → 只对**该报文**置位，发送后恢复（恢复成 `IP_PMTUDISC_WANT`
     ——内核默认，不是「永不置位」）。**带 DF 的 `Send` 之间**用一把互斥锁串行化这次切换
     （见第 5 条的边界）。
  3. **置位失败 = 丢弃该 indication**（RFC 8656 §11.2 原文：服务器置不上 DF 时「把该属性当作
     未知 comprehension-required 属性处理，**因此丢弃该 Send indication**」）。本实现照此执行：
     不向 peer 转发、计 `rejected_df`、记日志。畸形（长度 ≠ 0，§18.9 规定无值部分）同理 ——
     按未知属性语义丢弃并计数（indication 没有错误响应）。
  4. **其它平台**（Windows，以及 FreeBSD 等选项名未经验证的 unix）：`DONT-FRAGMENT` 不在
     支持列表里，`0x001A` 保持未知 comprehension-required → `Allocate` 回 **`420`**
     （§7.2 步骤 4 允许）；同平台上的 `Send` 带 DF 走「未知属性 ⇒ 丢弃」的同一语义。
     判定常量是 `DONT_FRAGMENT_SUPPORTED`（`cfg!(any(linux, macos, ios))`），
     编译期断言禁止它在别的平台为真。
  5. **已知限制（并发窗口）**：只有**带 DF 的 `Send`** 之间互斥（`df_lock`）；不带 DF 的
     `Send` 与 `ChannelData` 不取锁（数据面零锁开销），所以极端并发下普通报文可能被短暂
     带上 DF —— 后果仅限「该报文超过路径 MTU 时被丢」，不跨 allocation、不改变协议语义。
- `DONT-FRAGMENT` 的 lab 证据口径：`tcpdump -i lo` 里的 `flags [DF]` **不能**证明 DF 是我们置的
  ——Linux 默认 `IP_PMTUDISC_WANT` 对「不超过 MTU」的报文本来就置 DF，而 lo 的 MTU 是 65536。
  判别性证据是单测的 `getsockopt` 回读（`set_dont_fragment_round_trips`、
  `allocate_with_dont_fragment_sets_the_relay_socket`），lab 的 `df` 项证明的是「`-g` 能中继了」
  与「线上带 DF」这两件事。
- `REQUESTED-ADDRESS-FAMILY`（0x0017）支持到「relay 地址族的请求与校验」：
  **relay 族跟随客户端**（IPv6 监听上 IPv6 客户端拿到 IPv6 relay），无法满足的只是
  「与客户端族不同」的请求（`440`）与双分配 `ADDITIONAL-ADDRESS-FAMILY`（未实现，忽略）。
  `Refresh` 上族不匹配 → **`443`**（RFC 8656 §8.2 MUST）。
  IPv6 relay（IPv6 监听 + IPv6 客户端 + IPv6 peer）由 lab 的 **`ipv6relay`** 项覆盖：
  断言 `XOR-RELAYED-ADDRESS` 是 IPv6、`Send`/`Data`/`ChannelData` 双向都有字节；
  宿主没有 IPv6 回环时该项 **SKIP 并说明**（不算通过）。
  `REQUESTED-ADDRESS-FAMILY` 的 420 曾是偏差，26.410.101 之后的版本已改为
  `200`/`440`/`443`/`400`。
- **DTLS 已知限制**（来自 `webrtc-util` 的监听实现）：每个远端地址的会话在监听器生命周期内
  只创建一次；一个 5s 内没完成握手的客户端，其后续重试会被丢弃到已关闭的会话里，直到进程重启。
  这是「握手超时」的代价，写在这里免得被当成随机故障。

验收：

```bash
bash script/lab/rstun-turn.sh            # 22 项（lean 构建：tls/dtls/cert-reload/cert-poll 标 SKIP）
                                         #   启动失败/中继/401+438/生命周期/441/RAF(-X 成功、
                                         #   -x 440)/DF(-g 中继 + tcpdump 记录 DF)/IPv6 relay/
                                         #   通配回环/permission 508/486/端口 508/
                                         #   TLS/DTLS/证书热载/REST/带宽/回收/字节冻结/coturn 对照
bash script/lab/rstun-turn.sh --tls      # 只跑 TLS（自动 --features full 构建；s_client 握手 + uclient -S -t 中继）
bash script/lab/rstun-turn.sh --dtls     # 只跑 DTLS（自动 --features full；s_client -dtls1_2 + uclient -S 中继）
bash script/lab/rstun-turn.sh --only cert-reload  # 证书热载（SIGHUP + 30s 轮询 + 坏材料保留旧证书）
bash script/lab/rstun-turn.sh --only cert-poll    # --tls-cert-poll（0 = 仅 SIGHUP / 2s 轮询 / 无监听拒绝启动）
bash script/lab/rstun-turn.sh --tls --dtls   # 两项都跑
bash script/lab/rstun-turn.sh --only df      # DONT-FRAGMENT 单项（需要 tcpdump 才有线上证据，否则退化）
bash script/lab/rstun-turn.sh --only ipv6relay  # IPv6 relay 单项（无 ::1 时 SKIP）
```

## 浏览器验收（`turns:`，人工）

`rstun-turn.sh --tls` 覆盖协议层：`openssl s_client` 握手、`turnutils_uclient -S -t` 中继、
与本地 coturn 同参数对跑、坏证书/坏密钥对拒绝启动。**浏览器这一层没有自动化** —— ICE 是否
真的选中 relay candidate、对称 NAT 下能不能通，只能人工确认（本仓库当前**未声称已验证**）。

步骤见 [`docs/browser-acceptance.md`](https://github.com/exvlan/rstun/blob/main/docs/browser-acceptance.md)：
自签证书如何让 Chrome 信任（或 `--ignore-certificate-errors-spki-list`）、最小 demo 页的
`iceServers` / `iceTransportPolicy: "relay"`、trickle ICE 的观察点（`typ relay`、
`candidateType === "relay"`、服务端 `bytes_total` 增长）、对称 NAT 拓扑建议与常见失败。
若动手跑过，请把日期与两端 candidate 类型补进该文档的「状态」行 —— 没跑就保持「未执行」。

## 与 coturn 的差异

|      | `rstun`                                                                                                                                                                                         | coturn                                        |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| 定位 | 只做 STUN/TURN 的**最小服务**：Binding + **NAT 行为发现** + TURN 中继（`--turn`，强制长期凭据/REST） | 完整 STUN/TURN（中继）+ 鉴权 + 多租户 |
| 协议 | RFC 5389 Binding + `SOFTWARE` + `MAPPED-ADDRESS`（可选）+ `UNKNOWN-ATTRIBUTES`/420 + `FINGERPRINT`/300/500（两个开关）+ 鉴权（短期/长期，默认关闭）；RFC 5780 的 `CHANGE-REQUEST` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `RESPONSE-PORT` / `PADDING`；RFC 8656 中继（UDP/TCP 客户端传输、`turns:` TLS、DTLS 1.2、REST 凭据、带宽配额）；RFC 6062 **出站** TCP allocation（`--turn-tcp-relay`，无被动模式） | RFC 5389 / 5780 全量 / TURN（含 TCP allocation 双向、ACME 等） |
| 配置 | 纯命令行参数（无配置文件） | 上百行 `turnserver.conf`、数据库/鉴权后端 |
| 鉴权 | 短期 / 长期凭据 + RFC 8489 SHA256、USERHASH；用户来自 `--auth-user` 或 `--auth-file`，**无数据库**；TURN 复用同一套长期凭据，或 `--rest-secret`（可并存，REST 优先）| 长期凭据 + 数据库/Redis/文件后端，TURN 也受保护；`use-auth-secret` 与静态用户**互斥** |
| 依赖 | 纯 Rust，无 OpenSSL/libevent | 依赖 libevent/OpenSSL + 系统配置 |
| 部署 | 单二进制 / 一个几十 MB 的镜像 | 发行版包 / 官方镜像 + 配置卷 |
| 用途 | 需要「公网 STUN 映射 + NAT 行为发现」，以及**小规模**的 TURN 中继（UDP 中继 + RFC 6062 出站 TCP 中继） | 需要完整 TURN（TCP allocation 双向、多租户、ACME）的基础设施 |

结论：**需要 RFC 6062 被动模式（`ConnectionAttempt`）、ACME 自动证书或多租户数据库时仍然用 coturn**。
本服务的 TURN 覆盖 UDP/TCP/`turns:`/DTLS 中继、RFC 6062 出站 TCP allocation（`--turn-tcp-relay`）、
REST 临时凭据与带宽配额，用户清单是静态文件 / 单个 flag / 一个共享 secret。

TLS/DTLS/REST 的行为已与本地 coturn **同参数对跑**（`rstun-turn.sh` 的 `coturn` 项）：
`turnutils_uclient` 的 `-S -t`（TLS）与 `-S`（DTLS）两侧都完成中继；REST 探针输出逐行一致
（有效 / 过期 401 / 错 secret 401 / 含 `:` 的 label）。唯一有意差异：coturn 的
`use-auth-secret` **不能**与静态用户共存，本服务允许并存且 REST 优先。
