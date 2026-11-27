# rstun 升级说明：`26.410.105` → `26.410.107`

> 面向 EXVlan 运维。两版之间**默认行为零变化**：不改 `args`、不改端口、不改 relay 段，
> 只换镜像 digest 即可。下面给出差异、切换步骤、验证与回滚。
>
> 出具时间：2026-11-28 ｜ 上游仓库：`exvlan/rstun`

## 1. 一句话结论

| 项 | 说明 |
| --- | --- |
| 是否必须升 | 不必须。不升没有安全或协议缺陷。 |
| 升级收益 | ① 产物/镜像**可验签**（cosign keyless）；② `--turn-tcp-relay` 打开时支持 **RFC 6062 被动模式**（此前只能出站）。 |
| 风险 | 低：两版默认路径字节一致（`frozen` 3 配置 × 17 请求与基线逐字节相同）。 |
| 停机 | 有，短（`Recreate` 单 Pod，hostNetwork 占用 3478/3479，无法原地滚动）。建议维护窗口。 |

## 2. 版本差异

| 版本 | 变化 | 对默认部署的影响 |
| --- | --- | --- |
| `26.410.105` | 当前生产 | — |
| `26.410.106` | Release 产物开始 **cosign keyless 签名**（`SHA256SUMS` + 3 个 bundle + 镜像按 manifest digest 签名）；预发布版本标 `prerelease`；deb 文件名统一 `-` | 无（只是产物多了 `.bundle` 与验证方式） |
| `26.410.107` | **RFC 6062 被动模式**（`ConnectionAttempt`）：peer 主动连入 relay 时通知控制连接；`turnutils_uclient -T`/`-P` 均可完成 | 无（`--turn-tcp-relay` 仍**默认关闭**；关闭时行为与 `.105` 一致） |

镜像 digest：

```
26.410.105  ghcr.io/exvlan/rstun@sha256:8882b71cd08b0d1afede0010551ae358d7a0bdcbd78ec84d92023484b06f888c
26.410.106  ghcr.io/exvlan/rstun@sha256:9cfc500ad56002f4ecd8c43d36a51991882df2b093db42e6a1542c2a75a9bf42
26.410.107  ghcr.io/exvlan/rstun@sha256:c410cb68285accfb3e147ed2a905094828543a65476159d079ae855581faadef   ← 建议目标
```

> 生产请**钉 digest**而不是 tag：`latest` 会随新版本移动。

## 3. 升级前检查（只读，5 分钟）

```bash
# 1) 新镜像已发布且多架构可用（应看到 amd64/arm64 两个 manifest）
docker buildx imagetools inspect ghcr.io/exvlan/rstun@sha256:c410cb68285accfb3e147ed2a905094828543a65476159d079ae855581faadef

# 2) 二进制自报版本（可选，拉 lean 包即可）
gh release download rstun-v26.410.107 -R exvlan/rstun -p 'rstun-linux-x86_64-26.410.107.zip' -p 'SHA256SUMS'
sha256sum --ignore-missing -c SHA256SUMS && unzip -o rstun-linux-x86_64-26.410.107.zip
./rstun --version          # 期望：rstun 26.410.107+507a8c

# 3) 记录当前线上 digest（回滚用）
kubectl -n <ns> get pod -l app.kubernetes.io/name=rstun \
  -o jsonpath='{.items[0].status.containerStatuses[0].imageID}{"\n"}'
```

可选：验证产物签名（身份是**逐字**字符串，不是正则）：

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.bundle \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v26.410.107' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 4. 切换步骤（Kubernetes，`Recreate` 单 Pod + hostNetwork）

```bash
# 1) 改镜像（钉 digest）
kubectl -n <ns> set image deployment/rstun \
  rstun=ghcr.io/exvlan/rstun@sha256:c410cb68285accfb3e147ed2a905094828543a65476159d079ae855581faadef

# 2) 观察（Recreate：旧 Pod 先停，新 Pod 再起）
kubectl -n <ns> rollout status deployment/rstun --timeout=180s
kubectl -n <ns> get pods -l app.kubernetes.io/name=rstun -w
```

若你们用的是清单文件而不是 `set image`，改 `deployment.yaml` 的 `image:` 后 `kubectl apply -f`，效果相同。

**注意**：

- `Recreate` + `hostNetwork` 意味着**必然短暂断流**（旧 Pod 释放 3478/3479 后新 Pod 才能绑定）；
  `terminationGracePeriodSeconds: 20` 与 `--drain-timeout=5` 已是清单默认值，无需改。
- `imagePullPolicy` 若为 `IfNotPresent`，换 digest 会正常拉取（digest 变了）；不要改成 `Always`（无谓拉取）。
- 不要在同节点并行起第二个 Pod：hostNetwork 下会抢不到端口。

## 5. 切换后验证（逐项可复制）

```bash
# 1) 版本与健康
kubectl -n <ns> exec deploy/rstun -- /usr/local/bin/rstun --version   # 视镜像内路径调整
kubectl -n <ns> port-forward deploy/rstun 9100:9100 &
curl -fsS http://127.0.0.1:9100/healthz && echo OK
curl -fsS http://127.0.0.1:9100/metrics | head -20

# 2) 端口形态（应为 UDP 3478 + TCP 3478；开了 TURN 还有 relay 段内的监听）
ss -lunp | grep -E ':3478|:4915[2-9]|:491[6-9][0-9]' | head
ss -ltnp | grep ':3478'

# 3) STUN Binding（RFC 5389，最小验证）
#    任选其一：turnutils_stunclient / stunclient / 自备探针
turnutils_stunclient <公网IP> ; echo "exit=$?"

# 4) TURN 分配（若线上开了 TURN；用你们已有的测试凭据）
turnutils_uclient -u <user> -w <pass> -y <公网IP> | tail -5
```

判据：`/healthz` 返回成功、3478 UDP/TCP 在听、`stunclient` 能拿到 `XOR-MAPPED-ADDRESS`、
uclient 的 `tot_send_msgs`/`tot_recv_msgs` 均 > 0 且 `lost packets 0`。

## 6. 回滚（3 分钟）

```bash
kubectl -n <ns> set image deployment/rstun \
  rstun=ghcr.io/exvlan/rstun@sha256:8882b71cd08b0d1afede0010551ae358d7a0bdcbd78ec84d92023484b06f888c
kubectl -n <ns> rollout status deployment/rstun
```

回滚不需要改任何配置：两版 `args` 完全兼容，`.107` 新增的 flag（`--turn-tcp-relay`、
`--tls-cert-poll`）都可以不写。

## 7. 已知差异与注意点

| 项 | 说明 |
| --- | --- |
| `--turn-tcp-relay` | `.107` 仍默认**关**；打开后 UDP 池与 TCP 池是两套（TCP 端口段同 `--relay-ports`，listener 用 `SO_REUSEPORT`）。单实例部署无冲突；**将来上多副本时必须给每个实例分配不重叠的 relay 段** |
| 指标 | `.105 → .107` **未新增指标名**。既有：`rstun_turn_allocations`、`rstun_turn_bytes_total{direction=in\|out}`、`rstun_turn_allocations_total{result=…}`、`rstun_turn_rejected_total{reason=quota\|ports\|family\|loopback\|df\|tcp_connect\|tcp_bind\|tcp_send\|tcp_buffer\|tcp_quota}`、`rstun_turn_tcp_connections{state=pending\|bound}`。`tcp_*` 相关计数在**未开** `--turn-tcp-relay` 时恒为 0，不影响现有面板 |
| `crates.io` | `.107` 已发布（`cargo install rstun --version 26.410.107`），与容器同一份代码 |
| Homebrew | tap 已同步 `.107`（`brew install exvlan/rstun/rstun`）|
| 行为冻结 | 未启用新 flag 时，任何请求的响应字节与 `.105` 相同（我们的 `frozen` 测试以固定基线逐字节比对）|

## 8. 需要你们确认的两件事

1. 切换窗口（我们这边任何时间都可以配合；不需要我们改上游）。
2. 是否顺带启用 RFC 6062（`--turn-tcp-relay`）。**默认建议先不启**：它与你们当前业务无关，
   且一旦启用，relay 端口段要额外规划 TCP 侧（见 §7）。

升级过程若出现任何异常，把 `/metrics` 输出、`kubectl describe pod`、以及对应时间段的日志发我们，
我们按上游版本对比排查。
