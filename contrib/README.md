# 部署清单（`contrib/`）

四份「能直接抄走」的部署描述，参数与 [`README.md`](../README.md) 的「运维面」一节一致。
共同前提：

- **`--health-listen` 是可选端点**：不配置就不会有任何 HTTP 监听（等价于旧版本的部署形态）；
  配了才有 `/healthz`（readiness）与 `/metrics`（Prometheus 文本）。
- **健康端点默认绑 `127.0.0.1`**：对外暴露要走反代/内网；只有 k8s 的 kubelet 需要从 Pod 外部
  连进来时，才写 `0.0.0.0:9100` —— **绑 0.0.0.0 时必须用网络策略/节点防火墙限源**（谁都能读
  `/metrics` 与 `/healthz`）。k8s 侧示例见「Kubernetes」一节末尾的 NetworkPolicy。
- **运维端点的资源上限**（只在配了 `--health-listen` 时生效）：整条连接 **2s** 总时限（读 + 写共用，
  慢速滴字节拖不住）、并发上限 `--health-max-connections`（默认 64，超出立刻 `503` + 关闭，
  不排队）、请求头（含终止空行）上限 **8192** 字节。并发要调大时用 `RSTUN_HEALTH_MAX_CONNECTIONS`
  或 helm 的 `extraArgs`。
- **RFC 5780 需要真实源地址**：`CHANGE-REQUEST` 的判据是「回包从哪个源地址/源端口发出」。
  Docker 必须 `network_mode: host`，k8s 必须 `hostNetwork`，Service 必须
  `externalTrafficPolicy: Local`（Cluster 策略的 DNAT 会换掉源地址）。
- **停止**：SIGTERM → 停收新包 → 等在途（`--drain-timeout`，默认 5s）→ 打印统计 → 退出 0。
  编排层的 `stop_grace_period` / `terminationGracePeriodSeconds` / `TimeoutStopSec`
  要比 `--drain-timeout` 略大（清单里都给 10–20s）。

## 文件

| 文件 | 用途 | 校验 |
| --- | --- | --- |
| `systemd/rstun.service` | systemd 单元（非 root、`ProtectSystem=strict`、`EnvironmentFile=-/etc/rstun/rstun.env`） | `systemd-analyze verify rstun.service` |
| `docker/compose.yaml` | 单服务 Compose，`network_mode: host`，健康检查用 bash `/dev/tcp`（镜像里没有 curl/python） | `docker compose -f contrib/docker/compose.yaml config` |
| `k8s/deployment.yaml` | `hostNetwork` + UDP/TCP 3478 + `readinessProbe → /healthz` + 只读根文件系统 | `kubectl apply --dry-run=client -f contrib/k8s/` |
| `k8s/service.yaml` | `LoadBalancer` + `externalTrafficPolicy: Local` | 同上 |
| `k8s/multi-instance.yaml` | 两实例（`hostNetwork`、同端口不同节点）+ 跨实例 TURN 归属（`--cluster-*`、每实例 TCP relay 段） | `kubectl apply --dry-run=client -f contrib/k8s/` |
| `helm/` | 最小 chart（`listen` / `rfc5780` / `health` / `abuse` / `drainTimeoutSeconds` 在 values 里），**无第三方 chart 依赖** | `helm lint contrib/helm` + `helm template contrib/helm` |
| `deb/nfpm.yaml` | `.deb` 打包配置（binary → `/usr/local/bin`、unit → `/lib/systemd/system`、文档 → `/usr/share/doc/rstun`），由 `script/ci/build-deb.sh` 渲染后调用 | `bash script/ci/build-deb.sh`（内含 `dpkg -c` + `systemd-analyze verify`） |
| `deb/rstun.service` | **装完就能起来**的默认 unit（通配 3478 + `--tcp`），与上面的运维样例不同 | `systemd-analyze verify` |
| `homebrew/rstun.rb` | Homebrew formula **模板**（发布时由 `script/ci/gen-brew.sh` 填版本 + sha256，推到 `exvlan/homebrew-rstun` tap） | `ruby -c` |

## 多实例（`--cluster-listen`）

多个实例分担同一批客户端时，TURN allocation 仍然只存在于创建它的进程里；`--cluster-*` 让任意
实例都能算出某个 5 元组的归属并转发（控制面走 TCP 长连，peer→client 字节按连接回推）。
部署约束（细节见 [`docs/book/src/turn.md`](../docs/book/src/turn.md) 的「多实例」）：

- **每个实例的 `--listen` / TLS / DTLS 端口必须相同**，实例靠 **IP（或 netns）** 区分；
  同一实例上的多个监听地址也必须共用端口（启动时 `HELLO` 校验，端口不一致直接拒绝启动）。
- `--cluster-peer` 在**每个实例**上写同一份完整成员表；`--cluster-secret` 相同。
- **UDP relay 段可共用**（第二个进程 bind 失败会自动跳过）；**TCP relay 段必须分片**：
  集群 + `--turn-tcp-relay` 时 `--tcp-relay-ports` 必填，且与 `--relay-ports` 及其它成员不重叠。
- 客户端发往的地址在回程必须保持稳定：**每实例独立公网 IP**、或 **共享 VIP + DSR**、
  或 NAT 型 LB（回程也经 LB）。否则真实客户端（`turnutils_uclient` 的 UDP socket 是 `connect` 的）
  会丢弃来自归属实例直发的 `Data`。
- 成员表变更 = 排空重建（在途 allocation 不会迁移）。

k8s 示例：[`k8s/multi-instance.yaml`](./k8s/multi-instance.yaml)。Docker 用两个容器、各自不同的
`--listen` IP（或 host 网络下的不同宿主 IP）加同一份 `--cluster-peer`；Helm 为每个实例单独
`helm install` 一份并覆盖 `listen`/`clusterPeer`/`argument` 段。

## 包管理器（只发 lean）

```bash
bash script/ci/build-deb.sh                  # dist/deb/rstun_<version>_<arch>.deb（含 systemd unit）
bash script/ci/gen-brew.sh --assets <dir>    # dist/homebrew/rstun.rb（发布时用真实 Release 资产）
```

包管理器里只出 **lean** 构建：`turns:`(TLS)/DTLS 走 Release 的 `rstun-full-*` 与
`ghcr.io/exvlan/rstun` 镜像，避免同一个版本出现两个包。两边的版本串都必须等于
`Cargo.toml` 的 `version`（脚本会硬校验）。

## systemd

```bash
install -m 0755 rstun /usr/local/bin/rstun
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin rstun
install -d -m 0750 -o root -g rstun /etc/rstun
install -m 0640 -o root -g rstun rstun.env /etc/rstun/rstun.env   # 可选：RSTUN_* 默认值
install -m 0644 contrib/systemd/rstun.service /etc/systemd/system/rstun.service
systemctl daemon-reload && systemctl enable --now rstun
systemctl status rstun
curl -s http://127.0.0.1:9100/healthz
```

`AmbientCapabilities=CAP_NET_BIND_SERVICE` 只在把监听改到 <1024 的特权端口时才需要（3478 不需要），
文件里以注释形式给出。

## Docker Compose

```bash
docker compose -f contrib/docker/compose.yaml config     # 只校验，不启动
docker compose -f contrib/docker/compose.yaml up -d
docker inspect --format '{{.State.Health.Status}}' rstun
```

镜像里没有 curl/python，健康检查用 bash 内建的 `/dev/tcp`：

```bash
bash -c 'exec 3<>/dev/tcp/127.0.0.1/9100 &&
         printf "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 &&
         head -n 1 <&3 | grep -q " 200 "'
```

## Kubernetes

```bash
kubectl apply --dry-run=client -f contrib/k8s/
kubectl apply -f contrib/k8s/
kubectl get pods -l app.kubernetes.io/name=rstun -w      # READY 0/1 → 1/1 表示 readiness 通过
```

- `strategy: Recreate`：`hostNetwork` 下同一节点只能有一个 Pod 占 3478，滚动更新会抢端口。
- `--health-listen=0.0.0.0:9100`：kubelet 从节点侧连 Pod，绑回环会 probe 失败。hostNetwork 下
  这也意味着**节点 IP 的 9100 对同网段开放**，所以必须配限源规则（下面两条）。
- 没有云 LB 时把 Service 的 `type` 改成 `NodePort`，**保留** `externalTrafficPolicy: Local`。
- RFC 5780 的 alt 端口（`--alt-port`，缺省 primary + 1）在清单里以注释形式给出：开启时同时放开
  deployment 的 `stun-alt-udp` 与 Service 的对应端口（helm 走 `rfc5780.altPort`，自动生成）。

`/healthz` 与 `/metrics` 只有 L3/L4 保护（端点自己不做鉴权），限源是必须的：

```yaml
# 只允许监控网段读 9100；STUN 的 3478 对公网开放。
# 注意：CNI 的 NetworkPolicy 对 hostNetwork Pod **不生效**，hostNetwork 部署请用
# 节点防火墙实现同一条规则（下面）。
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rstun-ops-allowlist
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: rstun
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.0.0/8        # 换成你的监控网段
      ports:
        - port: 9100
          protocol: TCP
    - ports:
        - port: 3478
          protocol: UDP
        - port: 3478
          protocol: TCP
```

节点防火墙等价规则（hostNetwork 用这条）：

```bash
nft add rule inet filter input tcp dport 9100 ip saddr != 10.0.0.0/8 drop
```

## Helm

```bash
helm lint contrib/helm
helm template rstun contrib/helm --set rfc5780.enabled=false | head -40
helm install rstun contrib/helm \
  --set listen.addresses[0]=203.0.113.10:3478 \
  --set rfc5780.enabled=true \
  --set rfc5780.altListen=198.51.100.20:3478
```

values 的语义：

| key | 说明 |
| --- | --- |
| `listen.addresses` | 一个或多个 `host:port`；启用 RFC 5780 时**第一个**是 primary |
| `listen.v6` | IPv6 监听（v6-only，永不参与 RFC 5780） |
| `listen.tcp` | 在同样的地址上再开 TCP |
| `rfc5780.enabled` / `altListen` / `altPort` | 第二个公网 IP 与 alt 端口（缺省 = primary + 1；写了 `altPort` 才生成 `stun-alt-udp` 端口） |
| `health.enabled` / `listen` / `path` | 运维端点；关掉就回到「无 HTTP 面」 |
| `abuse.*` | 限速 / 在途 / 反射防护 / CIDR 名单（默认全关） |
| `drainTimeoutSeconds` | `--drain-timeout`（默认 5） |
| `env` | 追加环境变量；`RSTUN_*` 只在没有同名 flag 时生效（模板里 flag 已写全，所以优先用 values） |
| `extraArgs` | 追加命令行参数（最高优先级） |

## 排障

| 现象 | 先看 |
| --- | --- |
| `/healthz` 一直 `503 degraded` | 响应里的 `stale` 列表：那个 listener 的任务已经退出（日志搜 `listener stopped`） |
| `/healthz` 连不上 | 端点绑在 `127.0.0.1`（容器/service 外部连不进来），或 `--health-listen` 没传 |
| `/metrics` 有 `dropped` 但没有 `ok` | 抗滥用把流量挡了：看 `rstun_rate_limited_total{scope=...}` |
| `CHANGE-REQUEST` 回包源地址不对 | 容器没走 host 网络 / Service 不是 `externalTrafficPolicy: Local` |
| `docker stop` 超时被杀 | 编排层的 grace 时间小于 `--drain-timeout`（给一倍余量） |
| `/healthz` 偶发 `503 too many concurrent connections` | 抓取端连接泄漏或并发过高：看 `rstun_ops_rejected_total`，调大 `--health-max-connections` |
| 抓取超时（2s 被断开） | 端点对**整条连接**限时 2s（读 + 写共用），不是每次读重置 |
