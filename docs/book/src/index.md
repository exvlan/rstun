# rstun

独立 **STUN/TURN** 服务器：RFC 5389 Binding（可选 RFC 5780 NAT 行为发现，可选 RFC 8656 中继）。
一个 crate、一个二进制、一个镜像，`cargo install` 就能跑，不依赖任何宿主项目。

- **默认最小**：不配鉴权 / 限速 / TURN 时只做 5389 Binding，响应字节被测试冻结。
- **默认安全**：鉴权、限速族、TURN 全部**默认关闭**；开启 TURN 即强制长期凭据，
  不存在匿名开放中继。
- **两种构建**：lean（STUN + TURN UDP/TCP + REST + 带宽）与 full（再加 `turns:`(TLS) 与 DTLS 1.2）。

```bash
rstun server --listen 0.0.0.0:3478 --tcp
```

## 从哪里开始

- [快速开始](quickstart.md) —— 四条安装路径 + 起服务 + 验证
- [命令行](cli.md) —— `rstun --help` / `rstun server --help` 全量输出
- [协议行为](protocol.md) —— 请求 → 响应表、RFC 覆盖、错误码矩阵
- [鉴权](auth.md) / [RFC 5780](nat-discovery.md) / [抗滥用](rate-limit.md) / [TURN](turn.md)
- [容器（Docker）](docker.md) / [FAQ](faq.md) / [Changelog](changelog.md)

仓库首页（构建、发版、运维面、systemd、依赖面、License）：
<https://github.com/exvlan/rstun>

> **范围**：本服务只做小规模 STUN/TURN。**不做** TCP allocation（RFC 6062）、ACME/OCSP、
> 租户/数据库/配置文件 —— 需要这些请用 coturn（差异表见 [TURN](turn.md#与-coturn-的差异)）。
