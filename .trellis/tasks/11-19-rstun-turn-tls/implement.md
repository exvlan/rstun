# 执行计划：TURN T2

> 前置：T1（`rstun-turn-udp`）已归档；`rstun-auth` 的长期凭据与 base64url 可复用。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | 依赖：`tokio-rustls`、`rustls-pemfile` | `cargo tree` 直接依赖 9 → 11；二进制体积记录 | 单 commit |
| 2 | CLI：`--turn-tls-listen`、`--tls-cert`、`--tls-key`、`--rest-secret`、`--turn-bandwidth` | 非法组合（有 cert 无 key、路径不存在）启动失败 | 小 commit |
| 3 | TLS 监听：在 T1 的 TCP 处理器外套 `TlsAcceptor`；握手超时 5s；失败计数 | e2e：`openssl s_client` 能握手；坏证书拒绝启动 | 小 commit |
| 4 | TLS 上的 TURN 分帧（长度前缀 + ChannelData 头） | e2e：TLS 连接完成 Allocate + ChannelData 中继 | 小 commit |
| 5 | REST 凭据：解析 `expiry:label`、HMAC-SHA1 校验、优先级（REST > 长期） | 单测：有效/过期/错 secret/无冒号；e2e | 小 commit |
| 6 | 带宽配额：每 allocation 双向令牌桶 | 单测：超限丢弃计数；e2e：压满后丢包但 allocation 存活 | 小 commit |
| 7 | 指标：`turn_bytes_relayed{direction}`、`turn_bytes_dropped{direction}` | 若 ops 已上线则接入 `/metrics`；否则退出统计 | 小 commit |
| 8 | `script/lab/rstun-turn.sh --tls`：自签证书生成 + TLS 中继 + 清理 | 脚本可重复跑、失败非 0 | 新增文件 |
| 9 | **coturn 对照**：本地 `turnserver` 开 `use-auth-secret` + TLS，同参数对跑 | 两侧 allocation 生命周期一致；差异必须判定 | 文档/脚本 |
| 10 | 浏览器验收步骤文档化（`turns:` + trickle ICE） | 人工按文档跑通一次（记录日志） | 文档 commit |
| 11 | README/CHANGELOG：TLS 用法、REST 凭据示例、防火墙端口、体积变化、DTLS 未实现 | 人工评审 | 文档 commit |

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all      # 42 项（TURN 不改 STUN 路径）
bash script/lab/rstun-abuse.sh            # 10 组
bash script/lab/rstun-turn.sh             # T1 的 UDP 中继
bash script/lab/rstun-turn.sh --tls       # 新增：TLS 中继
cargo tree -e normal --depth 1            # 11 个
```

## 验收断言（必须）

- [ ] `turnutils_uclient` 的 TLS/TCP 模式经 `turns:` 完成中继
- [ ] 证书缺失/不可读 → 启动失败（明确错误，不降级明文）
- [ ] REST 凭据：有效 → 200；过期 → 401；错 secret → 401；普通长期凭据仍可用
- [ ] 带宽配额：超过 `--turn-bandwidth` 后丢包且 `turn_bytes_dropped` 增长，allocation 不被销毁
- [ ] 与 coturn 对跑：同一客户端参数下 allocation 生命周期一致；差异写进报告
- [ ] 未配置 TLS/REST/带宽时：与 T1 行为一致（回归脚本全绿）
- [ ] 握手失败/坏证书不打印证书内容

## 风险

| R | 缓解 |
| --- | --- |
| rustls 体积 | 发布前记录体积；如需精简可改 feature gate（留作后续）|
| TLS 握手 DoS | 连接级 Semaphore + 5s 超时；纳入限速统计 |
| coturn 与本服务对 REST 用户名的边界差异（标签可否含 `:`） | 验收里显式测一条带 `:` 的标签，差异记文档 |
