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
| 连接 | **1 连接 1 请求**；响应后关闭；管道化的第二个请求不执行（被**排空丢弃**，不解析）|
| 总时限 | **整条连接** 2s（`timeout_at(accept + 2s)`，读+写共用）；不是「每次 read 2s」 |
| 请求体 | `Content-Length: 0` 放行（`POST` → 405）；非 0 → 400 并关闭；`Transfer-Encoding` → 400 |
| 关闭 | 响应写完 → `shutdown(Write)` → **有界排空接收方向**（`min(总 deadline, now + 200ms)`）→ drop。带未读字节直接 close 在 macOS 上是 **RST**（客户端丢掉已到达的 503/400），Linux 上是 FIN（看不出问题）— 两条拒绝路径（超限、超并发）必然有未读字节 |
| 头限制 | 含终止空行共 **8192 字节**（8192 可服务、8193 → 400）|
| 并发 | `--health-max-connections`（默认 64，`RSTUN_HEALTH_MAX_CONNECTIONS`）；超限立即 **503** + 关闭（不排队）。
**名额在排空结束后才释放**：一条连接（无论 200 还是 503）都占用名额至多 `HTTP_DRAIN_TIMEOUT`（200ms）；
客户端读到响应即关时排空立刻 EOF、成本≈0。设很小的上限时，吞吐 ≈ `cap / 200ms`（默认 64 ≈ 290 次/秒）|
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
- TURN 指标只在 `--turn` 时输出（`rstun_turn_allocations`、`rstun_turn_bytes_total{direction}`、
  `rstun_turn_allocations_total{result}`、`rstun_turn_rejected_total{reason}`、
  `rstun_turn_bytes_dropped_total{direction}` —— 最后一项是 T2 带宽配额丢包）；未开启时
  **省略**（不输出恒 0，避免误读「开着但空闲」）。
- T2 的 TLS/DTLS 握手失败**只进退出日志**（`handshake_failed`），不新增指标：`/metrics` 的
  标签集合保持固定。TLS/DTLS 连接的请求计数沿用 `transport="tcp"`/`"udp"`。

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
| 总时限已耗尽（慢速客户端逼近 2s 才超限/被拒）| 排空被跳过（`min(deadline, now+200ms)` 已过期）→ 该形状**仍可能** RST，属已知边界；总时限优先 |
| ops accept 失败 | 只记日志，不计入 `rstun_socket_errors_total{transport="tcp"}` |

## 5. Good / Base / Bad

- **Good**：整条连接一个截止时间；并发用 `try_acquire`（不排队）；env 在日志初始化之前应用；
  写完响应先 `shutdown(Write)`，再在 `min(deadline, now+200ms)` 内排空读方向，然后才 drop。
- **Base**：每次 read 设超时 + 连接数不限。
- **Bad**：`timeout(read)` 放在循环里 —— 慢速客户端每 1.5s 发 1 字节能占住连接数小时。
- **Bad（本仓真实事故）**：写完响应直接 `drop` —— 带未读字节关闭在 macOS 上是 RST，
  客户端读不到 503/400（CI run `44563422358`）。修法是 `shutdown(Write)` 后有界排空。
- **Bad**：写完响应直接 drop —— 接收缓冲还有未读字节时，macOS 发 RST 让客户端丢掉已写出的 503/400
  （CI run `44563422358` 的 `test (macos-latest)` 两例失败即此）。排空只丢弃、不解析，
  仍是一次连接一个请求。

## 6. Tests Required（断言点）

1. 慢速客户端（每 1.5s 1 字节）在 ≈2s 内被关闭。
   **排空预算本身的断言**必须用 `HTTP_DRAIN_TIMEOUT + 150ms` 作上界（不是 2s）：
   用 2s 时，把 200ms 上限去掉的变异体也能通过。
2. `--health-max-connections 4` + 10 条空转连接 → 多数 503，fd 不增长；`/healthz` 仍 200。
3. 头长 8192 → 200；8193 → 400。
   3a. 两种拒绝路径后面再跟垃圾字节：客户端仍必须读到**完整**的 503 / 400（不是 `ECONNRESET`）。
   3b. 排空有界：客户端持续发字节或在排空期间保持静默（永不 EOF）时，服务端仍在 `HTTP_DRAIN_TIMEOUT` 内结束阅读；
   连接 deadline 更小时以 deadline 为准。
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
