# 运维面契约（health / metrics / env / drain / 部署）

> 来源：2026-11-19 `rstun-ops`。冷复核曾发现「2s 超时是每次 read 重置」（慢速连接可拖 51s）与
> `RSTUN_VERBOSE` 不生效；已修并加测。任何改动运维面的提交都必须满足本文。

## 1. Scope / Trigger

- 修改 `src/ops.rs`、`main.rs` 的启动/退出路径、`contrib/**`；
- 新增指标、端点、环境变量、drain 行为；
- 任何会改变「不配 `--health-listen` 时字节/监听」的改动。

## 2. Signatures

| 项 | 契约 |
| --- | --- |
| 端点 | `GET/HEAD /healthz`、`GET/HEAD /metrics`；其它方法 405（带 `Allow`）；未知路径 404 |
| 连接 | **1 连接 1 请求**；响应后关闭；管道化的第二个请求不执行 |
| 总时限 | **整条连接** 2s（`timeout_at(accept + 2s)`，读+写共用）；不是「每次 read 2s」 |
| 请求体 | `Content-Length: 0` 放行（`POST` → 405）；非 0 → 400 并关闭；`Transfer-Encoding` → 400 |
| 头限制 | 含终止空行共 **8192 字节**（8192 可服务、8193 → 400）|
| 并发 | `--health-max-connections`（默认 64，`RSTUN_HEALTH_MAX_CONNECTIONS`）；超限立即 **503** + 关闭（不排队）|
| 绑定失败 | **启动失败（exit 1）**；只有运行期 listener panic/abort 才让 `/healthz` 变 503 |
| env | 每个 flag 都有 `RSTUN_<FLAG>`；CLI 优先（按 `value_source`）；**空字符串视为未设置**；非法值启动失败并指明来源 |

## 3. Contracts

### health

| 状态 | `/healthz` |
| --- | --- |
| 全部 listener 存活 | `200 {"status":"ok","listeners":N}` |
| 任一 listener 任务结束（panic/abort）| `503 {"status":"degraded","stale":[...]}` |
| drain 中 | `503 {"status":"draining",...}`（供 LB 摘流）|

> `stale` 只覆盖「任务结束」；socket 读错误是退避重试，不会置 stale。

### metrics（标签集合固定，无高基数）

`rstun_requests_total{transport,result}`、`rstun_rate_limited_total{scope}`、`rstun_inflight_dropped_total`、
`rstun_reflect_rejected_total`、`rstun_fingerprint_rejected_total`、`rstun_auth_total{result}`、
`rstun_denied_total`、`rstun_allowlisted_total`、`rstun_socket_errors_total{transport}`、
`rstun_ops_rejected_total`（仅端点存在时）、`rstun_start_time_seconds`、`rstun_uptime_seconds`、
`rstun_health`、`rstun_build_info{version}`。

- 与退出统计**共用同一组 Counters**（不双份计数）；
- TURN 指标在 TURN 落地前**省略**（不输出恒 0，避免误读「开着但空闲」）。

### drain

```
SIGTERM → 标记 draining（/healthz 503 draining）
        → 停读 UDP、停 accept TCP、已建立连接停止读新帧
        → 等在途（--drain-timeout，默认 5s）
        → 打印统计 → exit 0（超时只 warn）
第二次 SIGTERM → 立即退出
```

- 常驻任务（rate-limit sweeper 等）**不参与** drain 等待；
- TCP 空闲连接不拖满超时（drain 即关闭）；
- `/metrics`、`/healthz` 在 drain 期间继续服务到进程退出。

## 4. Validation & Error Matrix

| 条件 | 行为 |
| --- | --- |
| 不配 `--health-listen` | **零新监听、零新任务、字节不变**（与旧二进制逐字节一致）|
| `RSTUN_LISTEN` + `--listen` | CLI 胜出（`value_source`）|
| `RSTUN_X=""` | 视为未设置，不报错 |
| `RSTUN_X` 非法 | 启动失败，错误信息含变量名 |
| 端点被绑定到 `0.0.0.0` | 必须在 `contrib/README.md` 提示限源（NetworkPolicy/nftables），端点无鉴权 |
| 并发超限 | 503 `too many concurrent connections`，`rstun_ops_rejected_total` +1 |
| ops accept 失败 | 只记日志，不计入 `rstun_socket_errors_total{transport="tcp"}` |

## 5. Good / Base / Bad

- **Good**：整条连接一个截止时间；并发用 `try_acquire`（不排队）；env 在日志初始化之前应用。
- **Base**：每次 read 设超时 + 连接数不限。
- **Bad**：`timeout(read)` 放在循环里 —— 慢速客户端每 1.5s 发 1 字节能占住连接数小时。

## 6. Tests Required（断言点）

1. 慢速客户端（每 1.5s 1 字节）在 ≈2s 内被关闭。
2. `--health-max-connections 4` + 10 条空转连接 → 多数 503，fd 不增长；`/healthz` 仍 200。
3. 头长 8192 → 200；8193 → 400。
4. `RSTUN_VERBOSE=1` 与 `--verbose` 的 DEBUG 行数一致（0 vs 1 对照）。
5. `RSTUN_LISTEN` 生效且被 `--listen` 覆盖；空值视为未设置；非法值失败并指明来源。
6. drain：在途完成、超时仍 exit 0、二次 SIGTERM 立即退出、sweeper 不拖慢退出。
7. 不配 `--health-listen`：与旧二进制逐字节一致（≥3 组）。
8. 清单：`docker compose config`、`helm lint`、k8s YAML 解析。

## 7. Wrong vs Correct

#### Wrong
```rust
loop {
    let n = timeout(READ_TIMEOUT, sock.read(&mut buf)).await??;  // 每次重置
    ...
}
```
```rust
// env 在日志初始化之后应用 → RSTUN_VERBOSE 静默失效
init_logging(args.verbose);
apply_env(&mut args)?;
```

#### Correct
```rust
let deadline = Instant::now() + HTTP_CONNECTION_TIMEOUT;        // 整条连接
let head = timeout_at(deadline, read_head(&mut sock, &mut buf)).await??;
```
```rust
apply_env(&mut args)?;          // 先应用
init_logging(args.verbose);     // 再初始化
```
