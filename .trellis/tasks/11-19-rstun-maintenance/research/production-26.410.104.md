# 生产已切 26.410.104 + 证书热载首次生产验证（对端回报，2026-11-22）

> 来源：EXVlan 会话 `[handoff] DONE`，线程 `t_mwrmpsgf_je97`；对端 P-014 commit `8133d1c3`。

## 生产状态

| 项 | 值 |
| --- | --- |
| 版本（容器内） | `software=rstun/26.410.104+b53a8e` |
| 镜像 digest | `sha256:549ba69ed3b1af2c90f92a1230b9a7e2db6c97629478dc1ea7a0ec993b7b79d6` |
| 变更范围 | 仅重建 `exvlan` Pod；`std-x` 未动 |
| 监听 | 12 listeners，TURN/TLS/DTLS ready |

## TURN 复验（对端实测）

| 用例 | 结果 |
| --- | --- |
| 明文 `-y` | 0% 丢包（平均 RTT 73.3ms）|
| `-S -y` | 0% 丢包（73.0ms）|
| `-S -g -y`（DONT-FRAGMENT） | 0% 丢包（67.6ms）→ DF 在 `.104` 仍生效 |
| `-S -x -y`（请求 IPv6） | `440 Address Family not Supported`（与 `.103` 语义一致）|

**已知非问题**：

- 首次复验出现 `486 Allocation Quota Reached` —— 对端连跑多轮测试把
  `--max-allocations-per-user 8` 占满（600s TTL），非 `.104` 缺陷。
- `turnutils_uclient -S` 的 TLS-over-TCP 分支报工具侧 `SSL internal error`（对端旧文档已记）；
  实际走 DTLSv1.2，结论以丢包率为准。我方 lab 对 TLS 用 `-S -t`（stream 模式），
  裸 `-S` 对 TLS 端口本就是协议误用，与对端判断一致。

## 证书热载：首次生产验证通过

对端把 `cert-watch` 从「续期 → 重启容器」改成：

```
openssl pkcs8 转 key → POST /containers/exvlan-stun/kill?signal=SIGHUP
```

实测证据：

- 日志：`rstun: TURN TLS certificate reloaded cert=/caddy-certs/…`
- 容器 `StartedAt=2026-11-22 17:09:27`、`RestartCount=0` **未变** → 未重启、会话未断
- 保留 `RELOAD_MODE=restart` 作为对 `.104` 之前版本的应急回退

> 意义：证书热载从「lab + 我方探针」升级为**生产环境首次真实轮换**（无重启、无断流），
> 动机（去掉 cert-watch 的重启）已达成。

## 对端立场

- RFC 6062 **暂不启用**（不做 TURN TCP relay）；被动模式未实现的限制已记；
- 依赖面 full 14→15 无影响（镜像部署，不锁 crate）；
- P-014 已按版本补记热载语义（新连接新证书 / 老会话保持 / 坏材料保留旧证书）。

## 我方待办

- 无。维护任务 M3 观察期继续（约 12-05 归档）。
- 观察点：对端若改用 K8s Secret 挂载（`..data` 符号链接）替换侧车写文件，
  `(mtime,len)` 轮询可能不感知 → 需 `SIGHUP`（已知盲区，已写进 docs）。
