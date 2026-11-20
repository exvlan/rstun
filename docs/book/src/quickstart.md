# 快速开始

## 1. 装

| 渠道 | 命令 | 构建 |
| --- | --- | --- |
| Cargo（crates.io，发布后） | `cargo install rstun` | lean |
| Cargo（源码树） | `cargo install --path .`（`--features full` 加 `turns:`/DTLS） | lean / full |
| Homebrew | `brew install exvlan/rstun/rstun` | lean |
| Debian / Ubuntu | `sudo dpkg -i rstun_<version>_amd64.deb` | lean |
| Docker | `docker run -d -p 3478:3478/udp ghcr.io/exvlan/rstun:<version>` | full |
| Release 资产 | `rstun-<platform>-<version>.zip` / `rstun-full-<platform>-<version>.zip` | lean / full |

**lean** = STUN + TURN(UDP/TCP) + REST + 带宽；**full** = 再加 `turns:`(TLS) 与 DTLS 1.2。
包管理器与 brew 只发 lean，full 走 Release 的 `rstun-full-*` 与镜像。

## 2. 起服务

```bash
# 最小形态：UDP + TCP 的 RFC 5389 Binding，监听所有地址
rstun server --listen 0.0.0.0:3478 --tcp

# 加上 IPv6（v6-only 绑定，可与 v4 同端口共存）
rstun server --listen 0.0.0.0:3478 --listen-v6 [::]:3478 --tcp

# 加上只读运维端点：/healthz 与 /metrics
rstun server --listen 0.0.0.0:3478 --tcp --health-listen 127.0.0.1:9100
```

不给参数时是**用法错误**（裸 `rstun` 打印帮助并退出 2），不会悄悄起一个通配监听。

## 3. 验证

```bash
rstun --version                       # rstun <version>（发行版资产带 +<sha6>）

# 20 字节 Binding Request，断言 0x0101 + XOR-MAPPED-ADDRESS
bash script/ci/rstun-smoke.sh 127.0.0.1:3478 --tcp

curl -s http://127.0.0.1:9100/healthz   # {"status":"ok","listeners":1}
curl -s http://127.0.0.1:9100/metrics | head
```

## 4. 按需加能力

- **鉴权**（默认关闭）→ [鉴权](auth.md)
- **NAT 行为发现**（RFC 5780）→ [RFC 5780](nat-discovery.md)
- **抗滥用**（限速 / 在途 / 反射防护，默认关闭）→ [抗滥用](rate-limit.md)
- **TURN 中继**（`--turn`，默认关闭、强制长期凭据）→ [TURN](turn.md)
- 生产部署清单、`RSTUN_*` 环境变量、systemd 样例、优雅退出 →
  [README](https://github.com/exvlan/rstun/blob/main/README.md#运维面readiness--metrics--env--优雅退出--部署清单)

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--listen <ADDR>` | `0.0.0.0:3478` | 可重复；UDP（加 `--tcp` 也答 TCP） |
| `--listen-v6 <ADDR>` | — | 可重复；v6-only 绑定 |
| `--tcp` | 关 | 每个监听地址同时答 TCP |
| `--health-listen <ADDR>` | 关 | 只读 HTTP：`/healthz` + `/metrics` |
| `--drain-timeout <SECONDS>` | `5` | SIGTERM 的 drain 上限（退出码仍为 0） |
