# 设计：运维面（readiness / metrics / 配置 / 优雅退出 / 部署清单）

## 1. 边界

- **默认全关**：不配置 `--health-listen` 时不新增任何监听、不改变字节行为（冻结测试继续通过）。
- 只提供**只读**能力（健康 + 指标）；不做管理 API、不做热重载、不做远端配置下发。
- 手写最小 HTTP/1.1（**不引入 hyper/axum**）：只支持 `GET` 两个路径，不解析请求体。

## 2. readiness / health

```
--health-listen <addr>        # 例：127.0.0.1:9100；不配置 = 关闭
GET /healthz  → 200 {"status":"ok","listeners":N}   仅当所有已配置监听 socket 均处于服务状态
              → 503 {"status":"degraded","stale":[...]}  任一监听任务已退出（panic/abort）
              → 503 {"status":"draining","listeners":N}  SIGTERM 之后的 drain 窗口（LB 摘流）
```

- 「在服务」判定来自 supervisor：每个 listener 任务持有 `AtomicBool`，任务异常退出时置 false。
- **绑定失败不是 503**：任何 socket 绑不上都直接启动失败（退出码 1）——「起了一半」不会发生，
  所以没有「绑定失败 → 503」这条路径。
- 只回 `Content-Type: application/json`；`HEAD` 允许；其它方法 `405`；未知路径 `404`。
- 不暴露版本细节（版本只在 `/metrics` 的 info 指标里，方便运维但不算敏感）。

## 3. metrics（Prometheus 文本）

| 指标 | 类型 | 标签 |
| --- | --- | --- |
| `rstun_requests_total` | counter | `transport=udp|tcp`、`result=ok|error|ignored|dropped` |
| `rstun_rate_limited_total` | counter | `scope=ip|ip_port|global` |
| `rstun_inflight_dropped_total` | counter | — |
| `rstun_reflect_rejected_total` | counter | — |
| `rstun_fingerprint_rejected_total` | counter | — |
| `rstun_socket_errors_total` | counter | `transport=udp|tcp`（STUN socket 读/accept 失败；运维端点自身的 accept 失败只记日志）|
| `rstun_ops_rejected_total` | counter | —（运维端点因 `--health-max-connections` 拒绝的连接）|
| `rstun_auth_total` | counter | `result=ok|unauthorized|stale_nonce|bad_request` |
| `rstun_turn_allocations` | gauge | — |
| `rstun_turn_bytes_total` | counter | `direction=in|out` |
| `rstun_build_info` | gauge(=1) | `version`（编译期常量；**不加 `rustc` 标签** —— 取编译器版本需要 `build.rs`，本 crate 刻意保持无构建脚本）|

- 文本格式按 Prometheus exposition（`# HELP` / `# TYPE` / 样本行），一次写完可解析。
- 与退出统计共用同一组 `Counters`，不做双份计数。

## 4. 配置：CLI + 环境变量

- CLI 仍是唯一真源；`RSTUN_<FLAG>`（大写、`-` → `_`）作为默认值来源，**CLI 显式值优先**。
- 例：`RSTUN_LISTEN=0.0.0.0:3478`、`RSTUN_REALM=example.org`、`RSTUN_TURN_BANDWIDTH=1M`。
- 列表型（`--listen`）用逗号分隔；`--auth-file` 等路径类不做内容展开。
- **空字符串 = 未设置**：compose 的 `${VAR:-}` 会留下空变量，视同未设置（不报错、不生效）。
- 解析失败 → 启动失败并指明来源（env 名或 flag 名），不静默忽略。
- 环境变量在**日志初始化之前**应用：`RSTUN_VERBOSE=1` 与 `--verbose` 完全等价。
- 因为环境变量要在 `main` 里先合并，`run()` 只收到「已应用的变量名列表」用于启动日志；
  CLI 仍是唯一真源（`ArgMatches::value_source` 区分「显式给」与 clap 默认值）。

## 5. 优雅退出（drain）

```
SIGTERM → 标记 draining
        → UDP：停止读取新 datagram（保留 socket 绑定直到超时结束）
        → TCP：停止 accept；对已建立连接不再读取新帧
        → 等待在途请求与发送完成（上限 --drain-timeout，默认 5s）
        → 打印统计 → 退出 0
```

- 超时后强制退出，退出码仍为 0（已尽力），并在日志记录未完成的计数。
- 第二次 SIGTERM → 立即退出（运维兜底）。
- 运维端点在 drain 期间**继续服务**（`/healthz` 回 `503 draining`、`/metrics` 仍可抓），进程退出时才 abort。

## 6. 部署清单（contrib/）

| 文件 | 内容要点 |
| --- | --- |
| `contrib/systemd/rstun.service` | `ExecStart=/usr/local/bin/rstun server --listen ...`；`Restart=on-failure`；`LimitNOFILE=65536`；`AmbientCapabilities=CAP_NET_BIND_SERVICE`（仅当绑 3478）|
| `contrib/docker/compose.yaml` | 单服务、`network_mode: host`（RFC 5780 必需）、`healthcheck` 指向 `--health-listen` |
| `contrib/k8s/deployment.yaml` + `service.yaml` | UDP+TCP 3478；`readinessProbe` → `/healthz`；`securityContext.readOnlyRootFilesystem` |
| `contrib/helm/`（最小 chart） | values 里暴露 listen/health/turn 开关；不引第三方 chart 依赖 |

## 7. 兼容性

| 配置 | 差异 |
| --- | --- |
| 不配 `--health-listen` | 无新监听、无新线程、字节不变 |
| 配了 | 只多一个 HTTP 监听；不影响 STUN/TURN 路径 |
| 只配环境变量 | 与等价 CLI 相同；日志里打印「来自 env」的来源以便排查 |

## 8. 安全

- `/healthz` 与 `/metrics` **默认绑 `127.0.0.1`**（示例），文档建议反代或内网；
- 响应不含内部路径、配置值、证书信息；
- 仅 `GET/HEAD`；请求体不读（**非零** `Content-Length` 或 `Transfer-Encoding` → `400` 并关闭；
  `Content-Length: 0` 视为没有 body，照常按方法判定）；
- 单连接 1 请求后关闭（无 keep-alive），避免慢速攻击面；
- **整条连接 2s 总时限**（读头 + 写响应共用一个截止时间，不是每次读重置）；
- **并发上限 `--health-max-connections`（默认 64）**：超出不排队，立刻 `503` + 关闭；
- 请求头（含终止空行）上限 8192 字节，恰好 8192 可服务、8193 起 `400`。

## 9. 测试

- 单测：HTTP 解析（GET/HEAD/其它方法/未知路径/带 body）、指标文本格式（regex 校验 HELP/TYPE/样本）、env 映射优先级。
- e2e：起服务 + `--health-listen`，curl `/healthz`（200），杀掉一个 listener（测试钩子）→ 503；`/metrics` 随请求增长。
  **钩子只做在测试里**（`#[tokio::test]` 里 drop listener 的 `ListenerLease`，等价于任务被 abort）：
  生产上 listener 只有 panic/abort 才会结束 —— socket 读错误是 `RECV_ERROR_BACKOFF` 重试，
  不产生 `stale`。因此**不新增生产测试钩子**。
- 资源维度：慢速客户端（每 1.5s 发 1 字节）必须在 ≈2s 内被关闭；`--health-max-connections 2` +
  2 条空转连接 → 第 3 条立刻 `503`，且端点本身仍能服务；请求头 8192/8193 字节的边界。
- drain：SIGTERM 后在途请求完成、5s 内退出、统计完整。
- 回归：不配 `--health-listen` 时 `interop all` 42 项 + `abuse` 10 组 + 冻结测试全绿。

## 10. 回滚

- 单批 commit；不配 `--health-listen` 即回到现状；部署清单是新增文件，删除即回滚。
