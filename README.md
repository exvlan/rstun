# rstun

[![CI](https://github.com/exvlan/rstun/actions/workflows/ci.yml/badge.svg)](https://github.com/exvlan/rstun/actions/workflows/ci.yml)
[![Release](https://github.com/exvlan/rstun/actions/workflows/release.yml/badge.svg)](https://github.com/exvlan/rstun/actions/workflows/release.yml)
[![docs](https://github.com/exvlan/rstun/actions/workflows/docs.yml/badge.svg)](https://exvlan.github.io/rstun/)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![Image](https://img.shields.io/badge/ghcr.io-exvlan%2Frstun-2496ED?logo=docker&logoColor=white)](https://github.com/exvlan/rstun/pkgs/container/rstun)
[![crates.io](https://img.shields.io/crates/v/rstun.svg)](https://crates.io/crates/rstun)

文档站：<https://exvlan.github.io/rstun/>（源码 `docs/book/`，`mdbook build docs/book` 本地构建）

独立 STUN/TURN 服务器：RFC 5389 Binding，加可选的 RFC 5780 NAT 行为发现，以及
可选的 RFC 8656 中继（`--turn`，强制长期凭据；UDP / TCP / `turns:`(TLS) / DTLS）。
一个 crate、一个二进制、一个镜像，`cargo install` 就能跑，不依赖任何宿主项目。
两种构建：**lean**（默认，STUN + TURN UDP/TCP + REST + 带宽）与 **full**（再加 `turns:` 与 DTLS）。

**范围声明（先读）**：本服务只做**小规模**的 STUN/TURN —— RFC 5389 Binding
（+ 可选的 RFC 5780 NAT 行为发现）+ **可选的**鉴权（RFC 5389 §10 短期/长期凭据 +
RFC 8489 §9.2 的 SHA256/USERHASH，**默认关闭**）+ **可选的 RFC 8656 中继**
（`--turn`，**默认关闭、缺长期凭据拒绝启动**）：UDP / TCP 客户端传输、`turns:`（TLS）、
DTLS 1.2、TURN REST 临时凭据（coturn `use-auth-secret`）、每 allocation 带宽配额、
**证书热加载**（`SIGHUP` 或 30s 文件轮询，不重启、不中断监听）。
RFC 6062 的**出站** TCP allocation（`--turn-tcp-relay`，默认关）也支持：`Allocate` +
`Connect` + `ConnectionBind`，中继数据是裸 TCP 字节。**不做**：RFC 6062 的被动模式
（`ConnectionAttempt`）、ACME/OCSP、租户/数据库/配置文件。需要这些时请用 coturn。

**命名**：crate 与二进制都叫 `rstun`。**绝对不能改叫 `stun`** —— Debian 的 `stun-client`
包已经占用 `/usr/bin/stun`，同名会直接撞包/覆盖。

**许可**：整仓 **MPL-2.0**（`LICENSE`），边界见文末 [License](#license)。

CLI 分两级：`rstun server [flags]` 起服务（flag 语义自首个版本起未变），裸 `rstun` 打印帮助。

## 安装

四条主路径（都只需要一个二进制；包管理器只发 **lean**，`turns:`/DTLS 用 `--features full`、
Release 的 `rstun-full-*` 或镜像）：

| 渠道 | 命令 | 说明 |
| --- | --- | --- |
| Cargo | `cargo install rstun` | 已发布 `26.410.104`；从源码树用 `cargo install --path .` |
| Homebrew | `brew install exvlan/rstun/rstun` | tap [`exvlan/homebrew-rstun`](https://github.com/exvlan/homebrew-rstun)；模板见 [`contrib/homebrew/rstun.rb`](contrib/homebrew/rstun.rb)；**lean** |
| Debian / Ubuntu | `sudo dpkg -i rstun_<version>_amd64.deb` | 从 [Releases](https://github.com/exvlan/rstun/releases) 下载（`amd64` / `arm64`）；配置见 [`contrib/deb/nfpm.yaml`](contrib/deb/nfpm.yaml)，含 systemd unit；**lean** |
| Docker | `docker run -d -p 3478:3478/udp ghcr.io/exvlan/rstun:<version>` | **full** 构建，见 [Docker 页](docs/book/src/docker.md) |
| Release 二进制 | `rstun-<platform>-<version>.zip`（lean）/ `rstun-full-<platform>-<version>.zip` | [Releases](https://github.com/exvlan/rstun/releases) |

装完先自检：`rstun --version`（版本串规则见下文「构建与运行」），再
`rstun server --listen 0.0.0.0:3478`。

## 协议行为（摘要）

一句话：**每个 `Binding Request` 得到 `Binding Success Response`（`0x0101`）+
`XOR-MAPPED-ADDRESS` + `SOFTWARE: rstun/<version>`**；其余细节按主题分章，行为表**只在文档站维护**
（单一真源，README 不再重复）：

| 主题 | 内容 | 文档 |
| --- | --- | --- |
| 协议行为 | 请求 → 响应表、RFC 5389/5780/8489/8445 覆盖、错误码矩阵（300/400/401/420/438/500）、420 的已知属性表、`--mapped-address` / `--check-fingerprint` / `--alternate-server` | [`docs/book/src/protocol.md`](docs/book/src/protocol.md) |
| 鉴权 | 短期 / 长期凭据、`--auth-file`、SHA256 / USERHASH、nonce | [`docs/book/src/auth.md`](docs/book/src/auth.md) |
| RFC 5780 | 四 socket、`CHANGE-REQUEST` / `RESPONSE-PORT` / `PADDING` | [`docs/book/src/nat-discovery.md`](docs/book/src/nat-discovery.md) |
| 抗滥用 | 限速、在途上限、反射防护、allow/deny | [`docs/book/src/rate-limit.md`](docs/book/src/rate-limit.md) |
| TURN | `--turn`、`turns:`(TLS)、DTLS、REST、带宽、与 coturn 的差异 | [`docs/book/src/turn.md`](docs/book/src/turn.md) |
| 命令行 | `rstun --help` / `rstun server --help` 全量输出 | [`docs/book/src/cli.md`](docs/book/src/cli.md) |

默认关闭的三件事：鉴权、限速族、TURN —— 都不改变默认路径的响应字节
（`protocol::tests::plain_response_bytes_are_frozen` 锁住）。文档与实现是否漂移由
`bash script/ci/check-docs.sh` 检查（help 片段逐 token 比对、参数名/指标名存在性、README→docs 链接可达）。

## 构建与运行

本地（需要 Rust 1.95，见 `rust-toolchain.toml`）：

```bash
cargo build --release                    # lean（默认）：STUN + TURN(UDP/TCP) + REST + 带宽
cargo build --release --features full    # full：再加 turns:(TLS) 与 DTLS 1.2
./target/release/rstun server --listen 0.0.0.0:3478 --tcp
```

`--features tls` / `--features dtls` 是细分开关（`dtls` 会带上 `tls`，两者共用证书解析）。
两种构建的 `--version` 相同（一个 release 一个版本号），区分靠启动日志的
`features="lean"` / `features="tls,dtls"` 字段。
**不带 feature 时**给 `--turn-tls-listen` / `--turn-dtls-listen` 会明确拒绝启动：

```
ERROR rstun: invalid TURN configuration --turn-tls-listen / --tls-cert / --tls-key need a build
with the `tls` feature (cargo build --features tls,dtls)
```

证书轮换**不用重启**：把 `--tls-cert`/`--tls-key` 原地覆盖成新文件，然后
`kill -HUP <pid>`（Linux/macOS，新连接立即生效）。Windows 或不想发信号时，30 秒轮询会
自动发现 `(mtime,len)` 变化（最坏 30s 生效）。坏材料（不配对/RSA 非 DTLS/非 PKCS#8/截断）
会被拒绝并保留旧证书，计数见 `rstun_turn_tls_reload_total{result="failed"}`。

安装（`cargo install` 装的是 **lean**；要 `turns:`/DTLS 请 `--features full`）：
```bash
cargo install --path .                    # lean，从源码树
cargo install --path . --features full    # 完整版
cargo install rstun                       # crates.io（lean）
cargo install rstun --features full       # crates.io（完整版）
```

容器：多阶段构建、非 root（uid 10001）、**full** 构建（`Dockerfile` 里 `--features full`）、
`--version` 由 `RSTUN_BUILD_VERSION` 注入。完整说明（镜像细节、多架构、host 网络要求）见
[`docs/book/src/docker.md`](docs/book/src/docker.md)。

### 发版：`.github/workflows/release.yml` 手动 dispatch

传 `version`（**不带 `v`**，如 `26.410.100`）即可，一次 dispatch 交付两样：

| 产出          | 内容                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Release       | tag **`rstun-v<version>`** + **八**个 zip：四个平台（Linux x86_64/aarch64 musl、macOS x86_64、Windows x86_64）× 两种构建 —— lean `rstun-<platform>-<version>.zip`、full `rstun-full-<platform>-<version>.zip` |
| SBOM + formula | **两份** CycloneDX（`rstun-<version>-lean.cdx.json` / `-full.cdx.json`）+ Homebrew formula `rstun.rb`（lean，tap 同步是人工步骤） |
| 镜像          | **`ghcr.io/<owner>/rstun:<version>`**（双架构 amd64+arm64，**full** 构建；版本不含 `-` 的稳定版追加 `latest`）                        |

- `prepare` 作业先校验 `version` 形如 `^\d+\.\d+\.\d+(-[...])?$`，且**必须等于 `Cargo.toml` 的
  `version`** —— 不一致直接失败，避免「tag 说 A、二进制说 B」。
- 版本串以 `<version>+<sha6>` 注入（`RSTUN_BUILD_VERSION`），二进制作业与镜像作业都会自检
  `--version` 里含这个串。
- musl 静态产物在 `ubuntu-24.04` / `ubuntu-24.04-arm` 上 native 构建并跑 UDP+TCP 冒烟；
  Windows 跑 `--version`；macOS runner 是 arm64，x86_64 产物**只编译不执行**（需 Rosetta）。
- 冒烟不可省：20 字节 Binding Request，断言 `0x0101` + `XOR-MAPPED-ADDRESS`
  （`script/ci/rstun-smoke.sh`），native 与容器各跑一次。
- 镜像推的就是**冒烟通过的那一份**：两个架构各自 build → 推 `:<version>-amd64` /
  `:<version>-arm64` → `docker manifest create/annotate/push` 合成 `:<version>`。
- 每个平台**编译两次**（lean 先落盘、full 再覆盖 `target/release/rstun`），两次都自检
  `--version`；Linux 上 full 产物还多跑一次 TLS 冒烟（自签 ECDSA 证书起 `turns:` 监听 +
  `openssl s_client` 握手 + 另一实例的明文 Binding）。
- `sbom` 作业（与平台无关，只跑一次）用 `script/ci/gen-sbom.sh` 生成 lean / full 两份 SBOM；
  `release` 作业断言 **8 个 zip + 2 份 SBOM + 1 份 formula + 2 个 deb = 13 个资产**，少一个就拒绝发版
  （SBOM 的组件数还额外断言直接依赖 10 / 15）。

## 运维面（readiness / metrics / env / 优雅退出 / 部署清单）

运维只要回答两个问题：「它真的在服务吗？」「它现在怎么样？」。两者都由**一个可选的只读
HTTP 端点**回答 —— **不给 `--health-listen` 就没有任何 HTTP 监听、没有额外任务、字节行为
不变**（`interop all` 42 项、`abuse` 10 组、冻结测试都在这个前提下通过）。

```bash
rstun server --listen 0.0.0.0:3478 --tcp --health-listen 127.0.0.1:9100
```

### `/healthz`（readiness）

```bash
curl -si http://127.0.0.1:9100/healthz
# HTTP/1.1 200 OK
# {"status":"ok","listeners":1}
```

| 情形 | 响应 |
| --- | --- |
| 每个已配置的监听都还在服务 | `200 {"status":"ok","listeners":N}` |
| 任一监听任务意外结束（错误返回 / panic / abort） | `503 {"status":"degraded","listeners":N,"stale":["udp 1.2.3.4:3478"]}` |
| 正在 SIGTERM 之后 drain | `503 {"status":"draining","listeners":N,...}` —— LB 据此摘流 |
| 未知路径 | `404`；`POST` 等其它方法 `405` + `Allow: GET, HEAD` |
| 请求带**非零** `Content-Length`（或有 `Transfer-Encoding`） | `400` 并关闭连接（端点不读 body；`Content-Length: 0` 视为没有 body，照常按方法判定） |

判定来自 supervisor：每个 listener 任务持有一个 `AtomicBool`，任务**任何**结束方式（错误、
drain 后正常返回、被 abort）都会把它置 false。所以「进程还活着」不等于 `200`：**绑定失败不是
`503` 而是启动失败**（任何 socket 绑不上 → 进程直接退出 1，不会「起了一半还说健康」）；
起来之后某个监听任务意外结束（panic / abort）才是 `503` + `stale`。socket 读错误（瞬时 ICMP 等）
不会结束监听，按 `RECV_ERROR_BACKOFF` 重试 → 不产生 `stale`。

**资源上限**（都在 `--health-listen` 开启时才生效）：

- **整条连接 2 秒**：读头与写响应共用同一个截止时间。每读一次重置的超时挡不住「每 1.5s 发 1
  字节」的慢速客户端（旧行为可拖到分钟级），现在从 `accept` 起 2s 必然关闭。
- **并发上限 `--health-max-connections`（默认 64）**：`accept` 后 `try_acquire`，**超出上限不排队**
  —— 立刻回 `503 too many concurrent connections` 并关闭（排队会保留洪水想耗尽的那个 fd）。
  `/healthz`/`/metrics` 本身不受已占用连接拖累：只要还有空槽就能服务，超限计数见
  `rstun_ops_rejected_total`。
- 请求头（含终止空行）上限 **8192 字节**：恰好 8192 可服务，8193 起 `400 request head too large`。

### `/metrics`（Prometheus 文本）

```bash
curl -s http://127.0.0.1:9100/metrics | grep -E '^# TYPE|^rstun_requests_total'
```

| 指标 | 类型 | 标签 |
| --- | --- | --- |
| `rstun_requests_total` | counter | `transport=udp/tcp`、`result=ok/error/ignored/dropped` |
| `rstun_rate_limited_total` | counter | `scope=ip/ip_port/global` |
| `rstun_inflight_dropped_total` | counter | — |
| `rstun_reflect_rejected_total` | counter | — |
| `rstun_denied_total` / `rstun_allowlisted_total` | counter | —（`--deny` / `--allow` 命中）|
| `rstun_fingerprint_rejected_total` | counter | — |
| `rstun_socket_errors_total` | counter | `transport=udp/tcp`（`recv_from`/`accept` 失败）|
| `rstun_auth_total` | counter | `result=ok/unauthorized/stale_nonce/bad_request` |
| `rstun_turn_allocations` | gauge | —（仅 `--turn`；活动 allocation 数）|
| `rstun_turn_bytes_total` | counter | `direction=in`（client→peer）/ `out`（peer→client）；仅 `--turn` |
| `rstun_turn_allocations_total` | counter | `result=created/expired`；仅 `--turn` |
| `rstun_turn_rejected_total` | counter | `reason=quota/ports/family/loopback/df/tcp_connect/tcp_bind/tcp_send/tcp_buffer/tcp_quota`；仅 `--turn` |
| `rstun_turn_tcp_connections` | gauge | RFC 6062 数据连接数，`state=pending/bound`；仅 `--turn` |
| `rstun_turn_tls_reload_total` | counter | `result=ok/failed`；仅配了 `turns:`/DTLS 监听 |
| `rstun_turn_tls_cert_expires_seconds` | gauge | 当前 leaf 的 `notAfter − now`（秒；负=已过期，`-1`=不可解析）；仅配了 `turns:`/DTLS |
| `rstun_ops_rejected_total` | counter | —（运维端点因 `--health-max-connections` 拒绝的连接）|
| `rstun_build_info` | gauge = 1 | `version`（编译期常量）|
| `rstun_start_time_seconds` / `rstun_uptime_seconds` | gauge | — |
| `rstun_health` | gauge | —（1 = `/healthz` 会回 200）|

- **与退出统计同源**：`/metrics` 读的就是退出时打印的那组 `Counters`
  （`limit::Counters` + `auth::Counters` + `ServerStats`），没有第二份计数。
- **标签集合固定**：只有 `transport` / `result` / `scope` 三个枚举维度，没有按对端 IP 的标签 ——
  指标基数不会随流量爆炸。
- `result` 的归属：`ok` = 应答已发出；`dropped` = 策略拒绝（限速 / 在途 / 反射防护）；
  `error` = 读不懂或内部不变量失败；`ignored` = 有意不作答（indication、`--fingerprint-action drop`）。
  后两者与退出日志的 `dropped` 总量**有意重叠**（退出日志的 `received/answered/dropped` 语义
  未变，见 `.trellis/spec/backend/abuse-guard.md` §4）。
- **TURN 指标只在 `--turn` 时出现**：未开启时 `rstun_turn_*` 四条指标**不输出**
  （而不是恒为 0 —— 0 会被读成「TURN 开着但空闲」）；开启后与退出日志的
  `rstun: TURN counters` 同源（同一组原子计数）。
- 安全：端点只做 `GET`/`HEAD`、一个连接只答一个请求（无 keep-alive）、**整条连接 2 秒总时限**、
  请求头（含终止空行）上限 **8192 字节**、并发连接上限（`--health-max-connections`）、不读 body；
  响应里没有路径、配置值或证书信息。**默认示例都绑 127.0.0.1**，
  对外请用反代或内网地址。

### 配置：环境变量（`RSTUN_*`）

命令行的每个 flag 都有一个同名环境变量：`--health-listen` ⇔ `RSTUN_HEALTH_LISTEN`（大写、
`-` → `_`）。**命令行显式值优先**，环境变量只补「没写」的那些：

```bash
RSTUN_LISTEN=0.0.0.0:3478 RSTUN_TCP=1 RSTUN_REALM=example.org \
  rstun server --health-listen 127.0.0.1:9100
```

- 列表型用逗号：`RSTUN_LISTEN="10.0.0.5:3478,10.0.0.6:3478"`、`RSTUN_DENY="10.0.0.0/8,192.168.0.0/16"`。
  **列表不合并**：命令行给了 `--listen` 就以命令行为准，`RSTUN_LISTEN` 整条被忽略。
- 开关型：`1/true/yes/on` 为开，`0/false/no/off`（含空串）为关。
- **空字符串 = 未设置**：compose 里 `${RSTUN_REALM:-}` 这种写法会把变量留成空串，它不会被当成
  「显式空值」而启动失败（`--realm ""` 那种显式空值仍由 flag 校验拒绝）。
- 解析失败 → **启动失败并指明来源**（`RSTUN_ALT_PORT: invalid value …`），不会静默忽略。
- 启动日志会打印实际生效的变量名：`configuration defaults read from the environment variables=["RSTUN_LISTEN"]`。
- 未映射的 `RSTUN_*`（例如构建期的 `RSTUN_BUILD_VERSION`）被忽略。

### 优雅退出（drain）

```
SIGTERM → 停止收新包（UDP 停 recv、TCP 停 accept、已有连接不再读新帧）
        → 等在途请求与发送完成（上限 --drain-timeout，默认 5s，0 = 立即）
        → 打印统计 → 退出码 0
```

- 在途计数覆盖：UDP 的每个 datagram（含 `--max-inflight` 下 spawn 的任务）、每条 TCP 连接、
  每个正在处理的 TCP 帧。监听任务本身也在等：它的 `recv_from`/`accept` 在 drain 时不会打断
  手里那个请求。
- 超时后照样退出（退出码仍为 0），并 `warn` 记下卡住的 listener 数与在途数。
- **第二个 SIGTERM 立即退出**（运维兜底），所以 `TimeoutStopSec` 只需略大于 `--drain-timeout`。
- drain 期间 `/metrics` 仍可抓取；`/healthz` 变 `503 draining`。

### 部署清单（`contrib/`）

| 文件 | 用途 |
| --- | --- |
| `contrib/systemd/rstun.service` | systemd 单元（非 root、`ProtectSystem=strict`、`LimitNOFILE=65536`、`TimeoutStopSec=10`） |
| `contrib/docker/compose.yaml` | 单服务 Compose（**`network_mode: host`**：RFC 5780 必需）+ `/dev/tcp` 健康检查 |
| `contrib/k8s/deployment.yaml` | Deployment（`hostNetwork`、UDP+TCP 3478、`readinessProbe → /healthz`、只读根文件系统；RFC 5780 的 `--alt-port 3479` 以注释形式给出，开启时同时放开该端口） |
| `contrib/k8s/service.yaml` | `LoadBalancer` + `externalTrafficPolicy: Local`（Cluster 策略的 DNAT 会破坏 `CHANGE-REQUEST` 判据） |
| `contrib/helm/` | 最小 chart（`listen` / `rfc5780` / `health` / `abuse` 都在 values 里），**不引第三方 chart 依赖** |

清单里的参数与本文一致；校验方式见 `contrib/README.md`。

### 更深一层：外部 STUN 探测

`/healthz` 只说「监听还在」，不说「UDP 回程通」。要验回程：

```bash
# 任意一台有 python3 的机器：20 字节 Binding Request，期望 0x0101
python3 - <<'PY'
import socket, os
tid = os.urandom(12)
req = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + tid
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(req, ("<stun-host>", 3478))
data, src = s.recvfrom(2048)
assert data[0:2] == b'\x01\x01', data.hex()
print("ok", src, data.hex())
PY
```

`script/ci/rstun-smoke.sh` 就是这条探测（带断言）的固化版本，CI 里 native 与容器各跑一次。
镜像本身仍然**不带** `HEALTHCHECK`（镜像里没有 curl/python）；容器健康检查写在编排层
（见 `contrib/docker/compose.yaml`）。

## systemd 样例

**可直接安装的版本在 [`contrib/systemd/rstun.service`](contrib/systemd/rstun.service)**
（含安装步骤、`EnvironmentFile=-/etc/rstun/rstun.env`、`TimeoutStopSec=10` 与一组加固项）。
最小形态：

```ini
# /etc/systemd/system/rstun.service
[Unit]
Description=rstun (STUN Binding + RFC 5780 NAT behaviour discovery)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 单独的运行用户即可，不需要任何 capability（3478 > 1024）
User=rstun
Group=rstun
# 用 `RSTUN_*` 配参数（命令行 flag 仍然优先）：
EnvironmentFile=-/etc/rstun/rstun.env
# 只做 RFC 5389（单地址，可用通配）：
# ExecStart=/usr/local/bin/rstun server --listen 0.0.0.0:3478 --listen-v6 [::]:3478 --tcp
# 启用 RFC 5780：两个公网 IP 都要写具体地址（不能是 0.0.0.0）
ExecStart=/usr/local/bin/rstun server --listen 203.0.113.10:3478 --alt-listen 198.51.100.20:3478 --alt-port 3479 --tcp --health-listen 127.0.0.1:9100
Restart=on-failure
RestartSec=2
# 单实例、只读文件系统（本服务不写盘）
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_INET6
LimitNOFILE=65536
# SIGTERM 是缺省停止信号：先 drain（--drain-timeout 默认 5s）再打印统计退出。
# TimeoutStopSec 要留出 drain + 打印的余量；第二个 SIGTERM 会立即退出。
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
```

防火墙（Binding 只要 3478；开了 RFC 5780 就要**两个 IP 上的两个端口**）：

```bash
# nftables 例：RFC 5780 需要 3478 与 3479（--alt-port）两端口，且两个 IP 都要放行
nft add rule inet filter input udp dport 3478 accept
nft add rule inet filter input udp dport 3479 accept
nft add rule inet filter input tcp dport 3478 accept   # 仅 --tcp 时需要
```

> 云主机注意：安全组放行 ≠ 回程可用。UDP 回程被云侧丢弃的地址要先用冒烟脚本验过再用，
> 否则 `--alt-listen` 指到它会让 `change-ip` 永远超时（见
> [`docs/book/src/nat-discovery.md`](docs/book/src/nat-discovery.md#部署前先确认回程可用)）。

容器 / Kubernetes / Helm 的最小清单见 `contrib/`（compose 用 `network_mode: host`，k8s 用
`hostNetwork` + `readinessProbe → /healthz`），说明见 [`contrib/README.md`](contrib/README.md)。

## 依赖面

两种构建，依赖面不同。**下面的数字都可以用标注的命令复现**（2026-11-21，Linux x86_64，
Rust 1.95）：

| 指标 | lean（默认） | full（`--features full`） | 命令 |
| --- | --- | --- | --- |
| 直接依赖 | **10** | **15** | `cargo tree -e normal --depth 1 [--all-features] \| tail -n +2 \| wc -l` |
| 依赖树行数（含重复的 feature 合并） | 90 | 361 | `cargo tree -e normal [--all-features] \| wc -l` |
| 唯一 crate 数 | 66 | 213 | `cargo tree -e normal [--all-features] --format '{p}' \| sed 's/^[│├└─ \t]*//' \| sort -u \| wc -l` |
| release 二进制（未 strip） | **3.92 MB** | **8.15 MB** | `cargo build --release [--features full] && ls -l target/release/rstun` |
| 镜像/发布用的二进制（LTO + strip） | **2.44 MB** | **4.95 MB** | 见 Dockerfile 的 `CARGO_PROFILE_RELEASE_{LTO,CODEGEN_UNITS,STRIP}` |

> 直接依赖是 **unix 口径**：`libc` 在 `[target.'cfg(unix)'.dependencies]` 里（DF 位的
> `setsockopt`），Windows 构建没有它，lean/full 分别是 9/14 个。`cargo tree --depth 1`
> 按当前目标平台（本机 Linux）计数，所以表里是 10/15。

> `cargo metadata --format-version 1 | jq '.packages\|length'` 也能跑（本仓 77），但它数的是
> **Cargo.lock 里的全部包**——含 dev-dependencies 与未启用的 optional 依赖，不区 feature，
> 所以不适合回答「这份二进制带了多少依赖」。上表按 feature 分别计。
>
> full 比 lean 多出的 271 行（361 − 90）里，有一大块是 **两代 `digest` 各一份**：本仓的鉴权栈在
> `digest 0.11`，而 `webrtc-dtls 0.12`（上游最新版）仍钉 `digest 0.10`，两代都留在树里
> （`webrtc-dtls` 跟进后自动消失，届时删掉这段说明）。

```
lean：
clap  socket2  tokio  tracing  tracing-subscriber
hmac  sha1  sha2  md-5              ← 鉴权（RFC 5389 §10 / RFC 8489 §9.2）
libc (仅 unix)                      ← DONT-FRAGMENT 的 setsockopt（Windows 上没有）

full（= lean + 这 5 个）：
tokio-rustls  rustls-pemfile        ← turns:（TLS 监听；rustls 的 ring provider）
webrtc-dtls  webrtc-util            ← DTLS 1.2（纯 Rust；util 只用来调它的 Conn/Listener）
x509-parser                         ← 证书到期指标（只读 notAfter；已在 webrtc-dtls 的树里）
（dev-only: stun-types 2.0.5 —— 只用做编解码的参考实现 oracle，不进二进制）
```

feature 定义（`Cargo.toml`）：

```toml
default = []
tls  = ["dep:tokio-rustls", "dep:rustls-pemfile", "dep:x509-parser"]
dtls = ["tls", "dep:webrtc-dtls", "dep:webrtc-util"]   # DTLS 与 TLS 共用证书解析
full = ["tls", "dtls"]
```

- **lean 构建里没有 TLS/DTLS 代码**（`#[cfg(feature = ...)]`），也不链接那 5 个 crate 与
  它们带来的 ~136 个传递 crate（65 → 201）。`--turn-tls-listen` / `--turn-dtls-listen` /
  `--tls-cert` / `--tls-key` **仍然出现在 `--help`**（帮助文本不随构建变化），但给了就
  **拒绝启动**并说明缺哪个 feature。
- `--rest-secret` 与 `--turn-bandwidth` **不 gate**：它们与传输无关，lean 构建的
  UDP/TCP TURN 一样能用。
- `webrtc-util` 是 `webrtc-dtls` 已有的同版本依赖，只是从传递依赖提升为直接依赖
  （否则 `Conn`/`Listener` 的方法无法调用），**不新增任何 crate**。
- `libc` **只在 unix 上是直接依赖**（`[target.'cfg(unix)'.dependencies]`）：`DONT-FRAGMENT`
  （0x001A）要把 DF 位置到 relay socket 上，而 `socket2 0.6` 没有 MTU-discover / DF 的 API，
  只能直接 `setsockopt`（Linux `IP_MTU_DISCOVER`、macOS `IP_DONTFRAG`）。它本来就是
  tokio/socket2 的传递依赖，**不新增任何 crate**。DF 只在 **Linux / macOS / iOS** 上真的支持；
  其它平台（Windows，以及选项名未经验证的 FreeBSD 等 unix）上 `0x001A` 保持未知
  comprehension-required → `420`（RFC 8656 §7.2 步骤 4 允许），`Send` 带 DF 则按未知属性
  语义丢弃该 indication（§11.2）。
- `tokio-rustls` 显式关掉默认特性、只开 `ring`：`rustls` 同时编进两个 provider 时
  `CryptoProvider::get_default()` 会在运行期 panic，而 `webrtc-dtls` 固定用 ring。

### 供应链（`cargo audit` / `cargo deny` / SBOM）

`cargo audit` 对**两种构建**都是干净的（退出码 0，CI 的 Linux `test` 作业会跑）：唯一一条漏洞
公告已进 `.cargo/audit.toml` 的允许清单，另有 3 条 unmaintained 警告（不影响退出码）。

| 公告 | crate | 来源 | 处置 |
| --- | --- | --- | --- |
| `RUSTSEC-2026-0387`（常量时间实现存在时序差异）| `crypto-bigint 0.5.5` | `webrtc-dtls → p256/p384 → elliptic-curve 0.13` | **允许清单**（`.cargo/audit.toml`）：修复版本 `crypto-bigint >=0.7.6` 与 `elliptic-curve 0.13` 不兼容，只能等上游。默认 lean 构建**不含**该依赖；full 构建里只有显式启用 `--turn-dtls-listen` 才执行到该代码。每次发版前复查 |
| `RUSTSEC-2025-0141`（unmaintained）| `bincode 1.3.3` | `webrtc-dtls` | 只用于 DTLS 内部握手状态序列化（warning） |
| `RUSTSEC-2026-0441`（unmaintained）| `pin-utils 0.1.1` | `webrtc-dtls` 传递依赖 | 无运行期影响（warning） |
| `RUSTSEC-2025-0134`（unmaintained）| `rustls-pemfile 2.2.0` | 本仓直接依赖（仅 `tls` feature） | 只做 PEM 解析；替代品尚不稳定（warning） |

`hmac` / `sha1` / `sha2` / `md-5` 都是 **RustCrypto**，纯 Rust、无 C 依赖（不需要
OpenSSL/libssl-dev）。引入它们的原因：鉴权要 HMAC-SHA1、HMAC-SHA256 与 MD5 三种算法，
而「不手写密码学」是硬约束 —— 自己实现 S 盒/压缩函数只会得到一堆难测的代码。
**底线是「不写算法」而不是「不加依赖」**：这四个 crate 加起来仍比 `ring`/`openssl` 小得多。

`stun-types` 在 `[dev-dependencies]` 里，`cargo tree -e normal` 看不到它。编解码是手写的：
`stun-types` 缺全部 RFC 5780 属性，把运行时交给第三方库也换不来协议覆盖，只会多几层依赖。

**其它供应链门禁**（`deny.toml` / `.github/dependabot.yml` / Release）：

- `cargo deny check licenses bans sources` 是 CI 的**必需作业**（`deny`，不是 `continue-on-error`）：
  - licenses：允许清单按**实际依赖**写（`MPL-2.0` + `MIT` / `Apache-2.0` / `Apache-2.0 WITH LLVM-exception` /
    `BSD-1/2/3-Clause` / `ISC` / `Unicode-3.0` / `Unlicense`），新增许可证必须是一次显式决定；
  - bans：`wildcards = "deny"`（版本必须可复现）；重复版本只**警告** —— 树里有 16 处同名多版本，
    绝大多数来自 dev-only 的 `stun-types`，硬失败要写 16 条 skip 并随每次升级维护；
  - sources：只允许 crates.io（本仓没有 git / path 依赖）。
- Dependabot（`.github/dependabot.yml`）：cargo **每周**、GitHub Actions **每月**，**只开 PR 不自动合并**。
- Release 附 **CycloneDX 1.5 SBOM**：`rstun-<version>-lean.cdx.json` / `rstun-<version>-full.cdx.json`
  （`script/ci/gen-sbom.sh` 用 `cargo metadata` 生成，按 feature 分别算依赖闭包，并断言直接依赖数
  10 / 15）；另附 Homebrew formula `rstun.rb`。**发布产物未签名**（cosign/sigstore 后置）。

## 测试

```bash
cargo test                        # lean（默认）：235 个单测
cargo test --all-features         # full（TLS/DTLS 用例 + 证书材料校验）：235 个
# 3 crc32 + 30 protocol + 7 rfc5780 + 87 server + 27 limit + 19 auth + 8 interop + 33 ops + 20 TURN
```

覆盖：

- **编解码**：XOR v4/v6 往返、与 `stun-types` 参考实现逐字节对齐（编码值字节与解码结果双向）、
  用参考解析器解我们的整条响应/错误响应；`CHANGE-REQUEST` 的两位标志（含未知位 / 保留位 /
  长度不对）、`RESPONSE-ORIGIN` / `OTHER-ADDRESS` 的 v4 与 v6（family `0x02` + 16 字节）
  编码与解码、坏 family / 截断值不 panic；`PADDING` / `RESPONSE-PORT` 的值解析（含截断容错）。
- **默认响应字节冻结**：固定 transaction id / peer / SOFTWARE 下，48 字节逐字节断言
  （`plain_response_bytes_are_frozen`），保证改动不悄悄改变客户端看到的内容。
- **合规包**：未知 comprehension-required 属性 → 420 + `UNKNOWN-ATTRIBUTES`（值长度恰为
  `2×N`：N=1/2/3 → 2/4/6 字节，wire 上 value+padding 分别 4/4/8；padding 不计入 Length，
  不重复末项）；400 不带 `UNKNOWN-ATTRIBUTES`；indication 仍静默；ICE / 鉴权
  属性（`USERNAME` / `MESSAGE-INTEGRITY` / `PRIORITY` / `USE-CANDIDATE` / `ICE-CONTROLLING` /
  `FINGERPRINT`）不触发 420；`--mapped-address` 开/关的字节差异与属性顺序；
  `PADDING` 回声长度（0 / 4 / 37 / 128 / 1400 / 2048 / `u16::MAX` 夹取）与「必须是最后一个属性」。
- **服务器**：畸形包（短包/坏 cookie/长度不对齐/属性越界）不打死监听、TCP 分帧与流水、
  非 Binding → 400（保留请求的 method）、indication 忽略、v6-only 不抢占 v4 端口、
  未启用 RFC 5780 时**不含**那两个属性、UDP 上 PADDING 回声（无 `--alt-listen` 也生效）。
- **RFC 5780（回环上真跑四个 socket）**：无 `CHANGE-REQUEST` → 响应源地址 == 目标地址、
  `RESPONSE-ORIGIN` == 它、`OTHER-ADDRESS` == `(127.0.0.2, alt_port)`；
  `change-port` → 响应的**源端口**是 alt 端口；`change-ip` → **源 IP** 是第二 IP；
  两者同时 → 对角线 socket；从「另一个地址」进来时四个地址仍互指；`RESPONSE-PORT=p`
  → 回包**发往** `(源 IP, p)`（客户端在另一个 socket 上收到）、**源地址/源端口不变**；
  未绑定端口乃至 `0` 也照样作为目的端口（不 panic、不回 400）；`RESPONSE-PORT` + `PADDING`
  → `400 Bad Request`；TCP 上 `RESPONSE-PORT` 被忽略。上述断言全部基于 `recv_from` 的
  源地址与收包 socket（也就是客户端能看到的东西），不只看报文里的属性。
- **CLI**：`0.0.0.0` / `[::]` 作为 `--listen` + `--alt-listen` 启动失败并给出明确提示、
  **primary = 命令行顺序里第一个 IPv4 `--listen`**（用第二个地址在前的顺序锁住「不能先排序再选」）、
  `--listen-v6` 不计入 primary 选择、只有 `--listen-v6` 时报「需要 IPv4 `--listen`」、
  alt 与 primary 同 IP 仍被拒、`--alt-port` 单独出现被拒、默认 alt 端口 = listen + 1。
- **多地址共存（生产形态：`.1` primary / `.2` alt / `.3` 普通 v4 / `[::]` 普通 v6）**：
  primary 上 `0x02` / `0x04` / `0x06` 三种 `CHANGE-REQUEST` 的回包源与
  `RESPONSE-ORIGIN`/`OTHER-ADDRESS` 全对；直接打 alt 地址得到计划内的应答（不主动换源）；
  普通 `.3` 上绑定与 `CHANGE-REQUEST` 都只得到 5389 响应（回包源不变、无那两个属性）；
  `[::]` 上 UDP/TCP 都只做普通 Binding 且**不会**出现 v4 的 `RESPONSE-ORIGIN`/`OTHER-ADDRESS`
  （显式断言地址族 `0x02`）；`--tcp` 在全部监听上生效，TCP 的 `CHANGE-REQUEST` 一律忽略；
  重复地址（alt socket 又写进 `--listen`）不会绑两次。
- **运维面（`ops`）**：`RSTUN_*` 映射的要点（命令行优先 / 列表用逗号不合并 / **空字符串视为
  未设置** / 非法值报错并指明变量名 / 连接上限可配）、开关型变量的 `1|true|yes|on` 与
  `0|false|no|off`、未映射的名字被忽略、以及「每个映射名都必须是真实 flag」的守卫测试；
  HTTP 解析（`GET`/`HEAD`/`405`+`Allow`/`404`/带 body 的 `400`/`Content-Length: 0` 放行/
  畸形请求行/查询串）；**资源维度**：每 1.5s 发 1 字节的慢速客户端必须在 ≈2s 被关闭（总时限，
  不是每次读重置）、`--health-max-connections 2` 时第 3 条连接立刻 503 且端点仍能服务、
  请求头 8192 字节可服务 / 8193 字节 400；`/healthz` 的 200 → 503（listener 租约被 drop、
  以及 drain 中）；`/metrics` 的 `# HELP`/`# TYPE`/固定标签集合与「随计数增长」；
  真实 socket 上的 200 → 503 与 `405`；drain 的 `wait_idle`（等在途、到点放弃并报剩余数）
  与 `Lifecycle` 订阅。
- **互操作（`tests_interop`）**：RFC 5769 §2.1–§2.4 的四段**标准字节**（请求、IPv4 响应、
  IPv6 响应、长凭证请求）全部能解析/解码，且 §2.2/§2.3 的 `XOR-MAPPED-ADDRESS`
  我们能**逐字节重建**；§2.1–§2.3 的 `FINGERPRINT` 被判为合法、改一位即不匹配；
  `stun-types` 2.0.5 双向（它编的请求我们解、我们编的响应它解，
  含 `MAPPED-ADDRESS` / `RESPONSE-ORIGIN` / `OTHER-ADDRESS` / `PADDING`），
  并能解出我们的 `300`（`ErrorCode 300` + `AlternateServer`）与 `500`（`ErrorCode 500`）。
- **协议闭环**：`crc32` 用 RFC 5769 §2.1 的 FINGERPRINT 常量锁死（`crc32(prefix)^0x5354554e
  == 0xe57a3bcf`）；`check_fingerprint` 覆盖 absent / 合法 / 错值 / 非末位 / 重复 / 长度非 4；
  UDP e2e 五态（合法 200、错值 400、非末位 400、drop 无响应且有计数、默认关闭时字节不变）；
  `300` 的IPv4/IPv6 编码与 `stun-types` 解码、重定向优先于 `CHANGE-REQUEST`、
  非 Binding 仍 400；`500` 的映射表（三种地址错误不映射、其余映射）与 40 字节响应，
  以及 Linux 上真实 `send_to` 失败（`RESPONSE-PORT 0`）触发 500 的 e2e。
- **抗滥用（`limit`）**：令牌桶速率/突发边界、空闲超 TTL 重置、**时钟回退不多发令牌**、
  条目上限与「回收到最久未用」、64 分片分散、CIDR 最长前缀 + deny 赢平局 + IPv6 +
  v4-mapped 归一化、`--allow` 只跳过每源桶（全局限速/在途上限不跳过）、
  `try_acquire` 满时拒绝且 permit 归还后可再生、TCP 的「连接持有槽位 + 请求查速率」两段式
  （不重复占槽、放开连接即归还）、反射防护的三种结局（静默丢弃 / 400 / 放行）、
  `max(len×ratio, len+32)` 的边界（比例项 vs 余量项）、小请求省略 `SOFTWARE`
  （28 字节无、40 字节有、普通 Binding 有、关闭防护时有）与「开/关准入的字节一致」。

## 运维验证

`script/ci/rstun-smoke.sh <host:port> [--tcp]` 是固化版探测（CI 对二进制与容器各跑一次，
线上也可直接拿来验部署）。RFC 5780 的四路验证要点是**打印 `recvfrom` 的源地址**再断言，
而不是相信报文里的 `RESPONSE-ORIGIN`。

## 互操作矩阵（第三方实现）

单测能证明「我们自己编、自己解」自洽；**第三方能不能读我们的包**另有独立验证。
完整报告（含原始输出摘录与判定）见 [`docs/interop-matrix.md`](docs/interop-matrix.md)：

| 对手                                | 覆盖                                                          |
| ----------------------------------- | ------------------------------------------------------------- |
| coturn `turnutils_stunclient` 4.6.1 | 生产同款客户端：完整 RFC 5780 三响应、`CHANGE-REQUEST` 回包源 |
| pion/stun v3（Go）                  | 主流 WebRTC 生态的编解码 + 客户端                             |
| webrtc-rs `stun` 0.17               | Rust 生态的编解码 + 客户端（含 IPv6）                         |
| `stun-types` 2.0.5                  | 编解码 oracle（`[dev-dependencies]`，不进运行时）；长凭证请求 → 我们的 200 可被它 `validate_integrity` 验签 |
| `rstun-interop-probe.py auth-long-term` | 独立实现（`hashlib`/`hmac`）的长期凭据客户端：self-computed key/MAC |

结论：四方**双向**全绿（42 项子用例 / 203 条断言，`probe` 新增 `fingerprint` /
`fingerprint-drop` / `alternate` 三项，`auth` 项覆盖长期凭据的完整 401 → MI → 200 流程），
RFC 5769 四段标准字节全通过，`cargo-fuzz` 解析路径 600 s 零 panic / 零挂死。

`test/interop/` 里是第三方客户端夹具（Go module 与 webrtc-stun 工程源码），
`fuzz/` 是独立 workspace（`cargo +nightly fuzz run parse` 只覆盖解析/编码纯函数）。
两者都不进发布包（`Cargo.toml` 的 `exclude`）。

## License

整仓（源码、Dockerfile、README、CI 描述）采用 **Mozilla Public License 2.0（MPL-2.0）**，
全文见 [`LICENSE`](LICENSE)（官方文本逐字未改）；`Cargo.toml` 的 `license = "MPL-2.0"`。

MPL-2.0 是**文件级** copyleft：改到本仓源文件必须以 MPL-2.0 公开，但**不要求**
「更大的作品」（链接/打包它的产品）整体换证。分发二进制（Release zip /
`ghcr.io/<owner>/rstun` 镜像）时按 MPL-2.0 §3.2 告知接收方源码位置：
`https://github.com/exvlan/rstun`。

维护约定（改这里前先看）：

1. **不要**给本 crate 加 path 依赖把外部代码缝进同一个可执行文件 —— 保持「单 crate、单许可」；
2. **不要**删除或替换 `LICENSE`（改证需要单独决策，并同步 `Cargo.toml` 的 `license`）。
