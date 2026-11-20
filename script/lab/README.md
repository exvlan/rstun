# `script/lab/` —— 互操作 / 抗滥用矩阵（可选夹具）

这里的脚本**不是 CI 门禁**：CI 只跑 `cargo test` + `script/ci/rstun-smoke.sh`（三平台）。
本目录的价值是把两类「跑起来才知道」的结论固化成可重跑的夹具：

- 互操作：第三方实现能不能读我们的包、我们能不能读它们的包；
- 抗滥用：打开限速/反射防护之后**到底拦住了什么**（关/开对照、单源 vs 多源、28/40 字节反射）。

任何一项从 ok 变 FAIL 就说明行为变了。

| 文件 | 作用 |
| --- | --- |
| [`rstun-interop.sh`](./rstun-interop.sh) | 互操作矩阵单入口：8 个项，可单项跑也可一次跑完 |
| [`rstun-interop-probe.py`](./rstun-interop-probe.py) | 只用 python3 标准库的协议探针（逐条 `ok:` / `FAIL:` 断言） |
| [`rstun-abuse.sh`](./rstun-abuse.sh) | 抗滥用对照：关/开限速、单源洪水、28/40 字节反射尝试、allow/deny、TCP 洪水 |
| [`rstun-turn.sh`](./rstun-turn.sh) | TURN 验收（17 项）：中继 / 生命周期 / 441 / 508 / 486 / **TLS / DTLS** / **REST 凭据** / **带宽配额** / 回收 / 字节冻结 / coturn 对照。默认 lean 构建（tls/dtls 项 SKIP）；`--tls`/`--dtls` 自动 `--features full` 构建 |
| [`rstun-turn-probe.py`](./rstun-turn-probe.py) | 有状态 TURN 客户端（标准库）：`lifecycle` / `relay` / `auth` / `wrong-user` / `loopback` / `permission-limit` / `rest`，同一步骤可对 coturn 与 rstun 各跑一次再 diff |

结论与原始证据摘录见 [`docs/interop-matrix.md`](../../docs/interop-matrix.md)。

## 用法

```bash
bash script/lab/rstun-interop.sh --list        # 列项 + 可选参数
bash script/lab/rstun-interop.sh probe         # 只跑 rstun 自身协议矩阵（19 项子用例）
bash script/lab/rstun-interop.sh --item pion,webrtc-stun   # 多选
bash script/lab/rstun-interop.sh all           # 除 fuzz/ci 外全部（42 项子用例）
bash script/lab/rstun-interop.sh full          # all + fuzz(600s) + ci
```

单项：`probe` / `pion` / `webrtc-stun` / `coturn` / `stun-types` / `rfc5769` / `fuzz` / `ci`。

TURN 验收（自起自停；TLS/DTLS 用 `openssl` 自签证书，REST 用探针 + `uclient -W`）：

```bash
bash script/lab/rstun-turn.sh              # 全部 17 项（lean 构建；tls/dtls 记 SKIP 并说明）
bash script/lab/rstun-turn.sh --tls        # 只跑 TLS（自动 --features full 构建；s_client + uclient -S -t）
bash script/lab/rstun-turn.sh --dtls       # 只跑 DTLS（自动 --features full；s_client -dtls1_2 + uclient -S）
bash script/lab/rstun-turn.sh --only rest  # REST：有效 / 过期 401 / 错 secret 401 / label 含 ':'
bash script/lab/rstun-turn.sh --only coturn # 与本地 turnserver 同参数对跑（含 TLS/DTLS/REST）
#   项名：startup|relay|auth|lifecycle|wrong-user|wildcard|permission-limit|quota|ports|
#         tls|dtls|rest|bandwidth|cleanup|frozen|coturn
```

抗滥用对照（自起自停、退出码可判定、每组一个日志）：

```bash
bash script/lab/rstun-abuse.sh               # 全部 10 组
bash script/lab/rstun-abuse.sh --only reflect # 只跑一组
#   组名：off | rate | global | reflect | reflect-strict | reflect-reject | allow | deny | inflight | tcp
#   未知组名直接 exit 2（不会「0 组运行 + 全部通过」）
bash script/lab/rstun-abuse.sh --port 34881 --no-build
```

它用 `127.0.0.0/8` 里的**不同源地址**模拟多源，**不需要 root / NET_RAW**，所以能验证
「每 IP 桶按源地址分桶 / allow 放行 / deny 拒绝 / `--max-inflight` 真的丢包」；真实公网
**伪造源**压测不在这里（那需要 raw socket），伪造源这条防线由 `--reflect-ratio` 的算术与
反射组的实测字节断言覆盖。反射组会断言**真实字节数**（28 → 32 / 56、40 → 76）、
与 `max(请求 × ratio, 请求 + 32)` 的关系、`SOFTWARE` 的有无，并检查拒绝时目标口收到 0 个包；
`reflect-reject` 组专门跑一个**确实会被拒**的用例（`CHANGE-REQUEST` + `PADDING 8` → 88 > 80）。
日志：`$RSTUN_ABUSE_DIR`（默认 `/tmp/opencode/rstun-abuse`）。

常用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--port N` | `34780` | 端口基准，各子项在其上取偏移；**`3478` 会被直接拒跑（exit 2）** |
| `--no-build` | — | 跳过 `cargo build`（复用已有 `target/debug/rstun`） |
| `--fuzz-seconds N` | `600` | `fuzz` 项时长 |
| `--keep` | — | 保留临时工程与日志（日志默认就保留，只清进程） |

日志与临时工程：`$RSTUN_INTEROP_DIR`（默认 `/tmp/opencode/rstun-interop`）。
每次运行都把每项输出写进 `logs/`；「多少条断言」= `grep -a -h '^ok:' $RSTUN_INTEROP_DIR/logs/*.log | wc -l`。

## 依赖

| 项 | 需要 | 缺依赖时 |
| --- | --- | --- |
| `probe` / `stun-types` / `rfc5769` / `ci` | `cargo` + `python3` | — （`ci` 的 YAML 检查另需 PyYAML） |
| `rstun-abuse` | `cargo` + `python3`（只用标准库） | — |
| `pion` | `go`（夹具在 `test/interop/pion/`，`go mod tidy` 在临时目录跑） | SKIP |
| `webrtc-stun` | `cargo`（夹具在 `test/interop/webrtc-stun/`） | SKIP |
| `coturn` / `rstun-turn` | `turnserver` + `turnutils_stunclient` + `turnutils_uclient`（Debian: `apt-get install coturn`） | SKIP |
| `rstun-turn` 的 TLS/DTLS 项 | 另需 `openssl`（自签证书、`s_client` 握手探针） | TLS/DTLS 项 SKIP |
| `fuzz` | `cargo-fuzz` + `nightly` 工具链 | SKIP |

容器（`docker`/`podman`）**不需要**：coturn 用原生进程起，不触容器边界。
IPv6 回环不可用时 `ipv6` 子项记 SKIP，不算失败。

## 判据提醒

`CHANGE-REQUEST`（RFC 5780）的回包来自**另一个源地址/端口**。端口受限 NAT 后的客户端会把
陌生源的包丢掉，于是表现为「超时」——**这不等于是服务端没有换源**。

判定换源是否真的发生，要看：

- 本地回环（`127.0.0.1` ↔ `127.0.0.2`）：本脚本的 `probe/change-*` 与 `pion|webrtc-stun/rfc5780`；
- 服务端 `--verbose` 日志里的 `from=` 字段（本脚本 coturn 项固定落 `logs/coturn-target-verbose.log`）；
- 或 full-cone / DC 一类的客户端。

同理，第三方工具**没有** STUN 服务端能力时（pion / webrtc-rs 都只有编解码 + 客户端），
方向 B 只到编解码层 —— 那是对手能力边界，不是我们的失败。
