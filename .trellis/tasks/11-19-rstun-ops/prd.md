# 运维面（readiness / metrics / 配置 / 优雅退出 / 部署清单）

## Goal

让运维能回答两个问题：「它真的在服务吗？」「它现在怎么样？」并让部署可复制。

## 需求

1. **readiness**：可选 `--health-listen <addr>`，GET `/healthz` 返回 200 仅当所有已配置监听 socket 成功绑定并在服务；
   默认关闭（保持「无 HTTP 面」）。
2. **metrics**：同一监听上的 `/metrics`（Prometheus 文本格式），指标至少：
   `rstun_requests_total{transport,result}`、`rstun_rate_limited_total{scope}`、
   `rstun_auth_total{result}`（原稿写作 `rstun_auth_failures_total`，实现按 result 分桶）、
   `rstun_socket_errors_total{transport}`（原稿写作 `rstun_udp_socket_errors_total`，实现同时覆盖 UDP/TCP）、
   `rstun_start_time_seconds` / `rstun_uptime_seconds`、`rstun_build_info{version}`。
   手写最小 HTTP/1.1 响应，**不引入 hyper/axum**。
3. **配置**：CLI 为唯一真源；新增 `RSTUN_*` 环境变量映射（等价于 CLI），便于容器/Helm。
4. **优雅退出**：SIGTERM 后停止接新包（UDP 关闭读、TCP 停止 accept），等在途请求与发送完成（有超时上限），再退出。
5. **部署清单**：仓库提供 `contrib/systemd/rstun.service`、`contrib/docker/compose.yaml`、
   `contrib/k8s/`（Deployment+Service，UDP/TCP，readinessProbe 指向 `/healthz`）、`contrib/helm/`（最小 chart）。

## 非目标

- 不做完整管理 API（只读健康与指标）。
- 不引入配置热重载（SIGHUP 只重新打开日志/不改绑定）。

## 验收

- [ ] 端口绑错时**启动失败**（进程退出 1，不是「进程活着就 200」）；运行期 listener 意外结束才 `/healthz` 503
- [ ] Prometheus 抓取 `/metrics` 成功，指标随请求增长
- [ ] SIGTERM 后 5s 内退出且统计完整；在途请求不被截断
- [ ] k8s manifest 在本地 kind/minikube 起得来（readiness 通过）
- [ ] 默认不开启时：无新增监听、字节级行为不变

## 风险

| R | 缓解 |
| --- | --- |
| 自写 HTTP 有安全风险 | 只支持 `GET /healthz`、`GET /metrics`，其余 400；不解析 body |
| 指标基数爆炸 | 标签只保留有限的 transport/result 枚举 |
