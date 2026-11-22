# 对端 cert-watch → 证书热载迁移计划（2026-11-22）

> 来源：EXVlan 会话 `[handoff] DONE`，线程 `t_mwrflw7i_k8n7`（P-014 已按其 commit `e8e8e23b` 补记）。

## 对端现状

| 项 | 值 |
| --- | --- |
| 生产版本 | 仍 `26.410.103`（digest `d7c4f387…`），默认行为与 `.104` 一致 |
| 现有轮换方式 | `cert-watch` 侧车：ZeroSSL 续期 → PKCS#8 转换 → **重启 stun 容器**（会断会话）|
| 升级动机 | **端口记账修复**（短 TTL 重复分配耗端口）+ **证书热载**（去掉重启断会话）|
| RFC 6062 | 暂时不需要；已知默认关、被动模式未实现 |
| 依赖面 14→15 | 无影响（镜像部署，不锁 crate）|
| 已记 digest | `.104` = `sha256:549ba69ed3b1af2c90f92a1230b9a7e2db6c97629478dc1ea7a0ec993b7b79d6`（最终值）|

## 我方给出的接入要点（已投递）

1. 触发二选一：侧车写**同路径**（30s 轮询自动生效，无需 exec）或 `kubectl exec … kill -HUP 1` 立即生效；
2. 写入顺序 **先 key 后 cert**（半写有 1s 重试，但可少一次 failed 计数）；
3. DTLS 开启时仍要求 **PKCS#8 + ECDSA P-256/Ed25519**；RSA/非 PKCS#8 会被拒并保留旧证书（fail-safe）；
4. 轮换后核对：`reload_total{result="ok"}` +1、`tls_cert_expires_seconds` 与 `openssl x509 -enddate` 一致、新连接指纹变化；
5. **已建立会话保持旧证书**（无重协商）→ 不要卡到期最后一刻轮换；
6. 避免 `cp -p`/保留 mtime（`(mtime,len)` 不变则轮询不触发），轮换后直接 `kill -HUP` 最稳；
7. 未配置 `turns:`/DTLS 监听时不注册 SIGHUP（该场景 SIGHUP 仍是终止）——对端有 5349，不涉及。

## 对端切换流程（其既有规矩）

改 `deploy.yaml` digest → 单文档 `play kube --replace`（仅 exvlan）→ 验
`-S -y` / `-S -g -y` / `-S -x` → 核对 `std-x` Pod `StartedAt` 不变 → 回执实测结果。

## 我方待办

- 等对端回执；若热载在其生产环境暴露问题（例如 Secret 挂载的 `..data` 符号链接导致路径变化），
  再评估是否需要「跟随符号链接」或在文档补一句。当前实现按固定路径 `stat`，**符号链接重指向到同长度**时轮询不感知（已知盲区，SIGHUP 兜底）。

## 对端实现细节（2026-11-22 第二轮对账）

| 项 | 对端做法 | 我方判断 |
| --- | --- | --- |
| 触发 | `podman … kill?signal=SIGHUP`（单节点 hostNetwork Pod，无 kubectl） | ✅ 等价于 `kill -HUP 1` |
| 写入顺序 | **无法 key-first**：cert 由 Caddy 写、key 由侧车转换；「cert → key → mv → SIGHUP」 | ⚠️ 可工作（SIGHUP 在两者就位后发）；中间态最多产生一两次 `failed` 噪音。**更好做法**：侧车自有两文件（copytree 到私有目录，先 key 后 cert），轮询也永远看到一致的一对 |
| 算法 | ZeroSSL ECDSA P-256 + `openssl pkcs8 -topk8 -nocrypt` | ✅ DTLS 硬要求 |
| 指标 | **未配 `--health-listen`** ⇒ 没有任何 `/metrics`（含 TURN 指标） | ❗ 真实缺口：只能用日志行 + 容器状态核对；建议加 `--health-listen`（hostNetwork 下绑 `127.0.0.1` 或私有 IP）|
| 会话 | 已建会话保持旧证书；侧车按 cert mtime 触发（6h 检查） | ✅ |
| 时间戳 | `openssl` 写 `.tmp` 再 `mv`（不保留源 mtime） | ✅ 不踩 `(mtime,len)` 盲区 |
| 监听 | 5349 上 TLS + DTLS 都开，SIGHUP 已注册 | ✅ |

### 衍生缺口（待对端决定）

- 轮询间隔**固定 30s、无法关闭**。对端只用 SIGHUP，若不想承担窗口噪音，可加
  `--tls-cert-poll <secs>`（`0` = 关闭轮询）。属小改动，等对端提出再立任务。
- 「无 `--health-listen` 时如何验证轮换」：日志行 `TURN TLS certificate reloaded` 是唯一证据；
  已在 `docs/book/src/turn.md` 补一句说明。
