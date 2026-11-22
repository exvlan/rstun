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
