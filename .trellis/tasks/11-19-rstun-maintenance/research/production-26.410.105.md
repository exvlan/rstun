# 生产已切 26.410.105 + `--tls-cert-poll 0` 落地（对端回报，2026-11-23）

> 来源：EXVlan 会话 `[handoff] DONE`，线程 `t_mwsr5k9b_is8o`；对端 P-014 已更新到 `.105`。

## 生产状态

| 项 | 值 |
| --- | --- |
| 版本（容器内） | `software=rstun/26.410.105+27bf65` |
| 镜像 digest | `sha256:8882b71cd08b0d1afede0010551ae358d7a0bdcbd78ec84d92023484b06f888c` |
| 变更范围 | 仅重建 `exvlan` Pod；`std-x` Created 未变 |
| 新增参数 | `--tls-cert-poll 0`（`podman inspect` 已确认生效）|
| `/healthz` | 200 |

## 为什么采纳 `0`

对端 `cert-watch` 的实现是「写文件 + `podman REST kill?signal=SIGHUP`」，因此：

- 关掉 30s 轮询后，**唯一**的重载入口就是他们的 SIGHUP，行为完全确定；
- 消除了「轮询恰好撞上『新 cert + 旧 key』半写窗口 → `reload_total{result="failed"}+1`」的不确定性；
- 「Windows 无 SIGHUP 时拒绝 `0`」与他们无关（Linux + `turns:`/DTLS 双监听）。

## 复验（对端实测）

| 项 | 结果 |
| --- | --- |
| `rstun_turn_tls_cert_expires_seconds` | **7587954** |
| `openssl x509 -enddate` 剩余秒 | **7587954**（**drift 0s**，x509-parser 0.18.1 的生产复现）|
| `-S -y` | 20/20、0% 丢包（67.6 ms）|
| `-S -g -y`（DONT-FRAGMENT）| 20/20、0% 丢包（66.2 ms）→ DF 在 `.105` 仍生效 |
| `-S -x -y` | `440 Address Family not Supported`（语义未变）|
| 触发一次 SIGHUP | `reload_total{result="ok"}` **0 → 1**，`failed` 保持 **0** |

## 对端提出的约束

> 他们后续会把「SIGHUP 可用」当作**硬依赖**；若我方移除/改名该信号语义，需要提前告知。

## 我方处置

1. 在 `docs/book/src/turn.md` 与 `.trellis/spec/backend/turn.md` 明确：`SIGHUP` 是**稳定接口**
   （`--tls-cert-poll 0` 的部署完全依赖它），移除/改名按破坏性变更走 CHANGELOG；
2. lab 的 `cert-poll` 项已覆盖 `0` 分支（文件变化不重载 + SIGHUP 重载），可作为回归护栏；
3. 无需对端动作；`.105` 为其生产最终版本。
