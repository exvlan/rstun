# 执行计划：TURN T2

> 前置：T1（`rstun-turn-udp`）已归档；`rstun-auth` 的长期凭据与 base64url 可复用。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | 依赖：`tokio-rustls`、`rustls-pemfile`、`webrtc-dtls` | `cargo tree` 记录直接/传递依赖与体积变化；`cargo audit` 无新增高危 | 单 commit |
| 2 | CLI：`--turn-tls-listen`、`--tls-cert`、`--tls-key`、`--rest-secret`、`--turn-bandwidth` | 非法组合（有 cert 无 key、路径不存在）启动失败 | 小 commit |
| 3 | TLS 监听：在 T1 的 TCP 处理器外套 `TlsAcceptor`；握手超时 5s；失败计数 | e2e：`openssl s_client` 能握手；坏证书拒绝启动 | 小 commit |
| 3b | DTLS 监听：`webrtc-dtls` 握手 + 每连接一个 datagram 循环；transport=`Dtls` | e2e：`openssl s_client -dtls1_2` 或自写 DTLS 客户端握手；坏证书拒绝启动 | 小 commit |
| 3c | DTLS 数据面：STUN/TURN 消息与 `ChannelData` 直通；permission/channel 与 UDP 同规则 | e2e：DTLS 上完成 Allocate 与中继 | 小 commit |
| 4 | TLS 上的 TURN 分帧（长度前缀 + ChannelData 头） | e2e：TLS 连接完成 Allocate + ChannelData 中继 | 小 commit |
| 5 | REST 凭据：解析 `expiry:label`、HMAC-SHA1 校验、优先级（REST > 长期） | 单测：有效/过期/错 secret/无冒号；e2e | 小 commit |
| 6 | 带宽配额：每 allocation 双向令牌桶 | 单测：超限丢弃计数；e2e：压满后丢包但 allocation 存活 | 小 commit |
| 7 | 指标：`turn_bytes_relayed{direction}`、`turn_bytes_dropped{direction}` | 若 ops 已上线则接入 `/metrics`；否则退出统计 | 小 commit |
| 8 | `script/lab/rstun-turn.sh --tls`：自签证书生成 + TLS 中继 + 清理 | 脚本可重复跑、失败非 0 | 新增文件 |
| 9 | **coturn 对照**：本地 `turnserver` 开 `use-auth-secret` + TLS/DTLS，同参数对跑 | 两侧 allocation 生命周期一致；差异必须判定 | 文档/脚本 |
| 10 | 浏览器验收步骤文档化（`turns:` + trickle ICE） | 人工按文档跑通一次（记录日志） | 文档 commit |
| 11 | README/CHANGELOG：TLS 用法、REST 凭据示例、防火墙端口、体积变化、DTLS 未实现 | 人工评审 | 文档 commit |

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all      # 42 项（TURN 不改 STUN 路径）
bash script/lab/rstun-abuse.sh            # 10 组
bash script/lab/rstun-turn.sh             # T1 的 UDP 中继
bash script/lab/rstun-turn.sh --tls       # 新增：TLS 中继
bash script/lab/rstun-turn.sh --dtls      # 新增：DTLS 中继
cargo tree -e normal --depth 1            # 11 个
```

## 验收断言（必须）

- [ ] `turnutils_uclient` 的 TLS/TCP 模式经 `turns:` 完成中继
- [ ] 证书缺失/不可读 → 启动失败（明确错误，不降级明文）
- [ ] REST 凭据：有效 → 200；过期 → 401；错 secret → 401；普通长期凭据仍可用
- [ ] 带宽配额：超过 `--turn-bandwidth` 后丢包且 `turn_bytes_dropped` 增长，allocation 不被销毁
- [ ] 与 coturn 对跑：同一客户端参数下 allocation 生命周期一致；差异写进报告
- [ ] 未配置 TLS/REST/带宽时：与 T1 行为一致（回归脚本全绿）
- [ ] 握手失败/坏证书不打印证书内容

## 风险

| R | 缓解 |
| --- | --- |
| rustls 体积 | 发布前记录体积；如需精简可改 feature gate（留作后续）|
| TLS 握手 DoS | 连接级 Semaphore + 5s 超时；纳入限速统计 |
| coturn 与本服务对 REST 用户名的边界差异（标签可否含 `:`） | 验收里显式测一条带 `:` 的标签，差异记文档 |

---

## 实施记录（2026-11-20，T2 全部批次）

状态：批 1（依赖 + TLS）、批 2（DTLS）、批 3（REST + 带宽 + 指标 + 脚本/文档）均已落在工作区，
未提交。门禁全绿（见回执）。

### 与 design.md 的有意偏差

1. **多一个直接依赖 `webrtc-util`**（design 只列 3 个）：`webrtc-dtls` 的监听/连接 API 以
   `webrtc-util` 的 `Conn`/`Listener` trait 表达，`impl Listener`/`Arc<dyn Conn>` 的方法调用
   必须把 trait 带进作用域。它是 `webrtc-dtls` 已依赖的**同版本** crate，不新增任何传递依赖。
2. **DTLS 不用 `listener::listen()`，改用 `ListenConfig` + `DTLSConn::new`**：前者把握手放在
   `accept()` 里，一个静默/慢速客户端会阻塞整个 accept 循环（design §9 明确要防）。
   现在 accept 只建会话，握手在每客户端任务里 5s 超时。
3. **体积实测与估计不符**：design 估计 +1.2 MB，实测 release 3.5 MB → 7.9 MB（+4.4 MB），
   传递依赖 65 → 201。已在 README/CHANGELOG 记录；feature gate 留作后续。
4. **带宽默认 1 MiB/s（design §5）与「未配置即与 T1 完全一致」（design §8）张力**：按用户决定
   取 1 MiB/s。17 请求 × 3 配置的字节冻结不受影响；大流量下的行为与 T1 不同（受 1 MiB/s 约束），
   已在 README 写明。
5. **REST 过期严格判定，没有 ±5 分钟宽限**（risk R3 提到宽限）：design §4 要求「过期 → 401」，
   宽限会让「过期凭据被拒」的验收用例失效。改为在 README 写明 NTP 前提。
6. **`--rest-secret` 额外要求 `--auth-secret`**：nonce 仍需签名密钥；coturn 内部复用一个 secret，
   本实现把「nonce 签名」与「REST HMAC」分开（design §4 也要求两者独立）。缺 `--auth-secret`
   时启动失败并说明原因。
7. **DTLS 私钥受限**：`webrtc-dtls` 只接受 PKCS#8 + ECDSA P-256/Ed25519；RSA 在启动时被明确拒绝。
8. **握手失败计数只在退出日志**（`handshake_failed`），不进 `/metrics`：任务要求「只新增
   `rstun_turn_bytes_dropped_total`」，保持标签集合固定。TLS/DTLS 的请求计数沿用
   `transport=tcp`/`udp`。
9. **TLS 的 5 元组用 `ClientTransport::Tcp`**（design §6），DTLS 用新增的 `Dtls`。
10. **DTLS 已知限制**（上游 `webrtc-util`）：每个远端地址的会话只创建一次，握手超时后该地址的
    重试会被丢弃到已关闭会话，直到重启。已写进 README。

### 未做

- 证书热加载、ACME/OCSP、TCP allocation（RFC 6062）—— 与 prd 非目标一致。
- 浏览器人工验收（Chrome + trickle ICE）：步骤在 `docs/browser-acceptance.md`（README 已链接），
  但**没有自动化、也未执行过** —— 文档状态行明确写「未执行（待办）」，不假装已验证。
  协议层（TLS 握手、DTLS 中继、REST）由 `openssl` + `turnutils_uclient` + coturn 对跑自动覆盖。
11. **`cargo audit` 新增 1 条漏洞 + 3 条 unmaintained**（全部来自 DTLS/PEM 链，均无可用修复）：
    `crypto-bigint 0.5.5`（RUSTSEC-2026-0387，时序差异；修复版 0.7.6 与 `elliptic-curve 0.13`
    不兼容）、`bincode`/`pin-utils`（webrtc-dtls 传递依赖）、`rustls-pemfile`（本仓直接依赖，
    只做 PEM 解析）。已在 README「依赖面」逐条登记；DTLS 默认不监听，不启用则代码路径不执行。
    这与「不得新增高危」的门禁有张力，**需要主会话裁定**（接受并登记 / 改 feature gate /
    放弃 DTLS）。

---

## 实施记录（2026-11-20，第二轮：feature gate）

用户定稿：默认构建保持 lean，TLS/DTLS 走 `--features tls,dtls`（`full`）；发布两种产物；
`cargo audit` 对默认构建跑，完整版的公告进允许清单。

### 落地

1. `Cargo.toml`：`default = []`、`tls = ["dep:tokio-rustls", "dep:rustls-pemfile"]`、
   `dtls = ["tls", "dep:webrtc-dtls", "dep:webrtc-util"]`、`full = ["tls", "dtls"]`；
   四个 crate 改为 `optional = true`。`dtls` 含 `tls`：两者共用 `SecureMaterial` 的
   证书/私钥解析，单独一个 DTLS 构建没有意义。
2. 代码 gate：`SECURE_HANDSHAKE_TIMEOUT`、`SecureMaterial`、`load_secure_material`、
   `dtls_pem`、`serve_turn_tls`、`serve_turn_dtls*` 与 `run()` 里的材料加载/监听绑定/启动日志
   全部 cfg；`SecureMaterial.dtls` 字段只在 `dtls` 下存在（`tls`-only 构建不引用 webrtc-*）。
   `-Cfgdtls` 的四个 flag 保持定义，`build_turn` 里按 feature 给出
   `` need a build with the `tls`/`dtls` feature (cargo build --features tls,dtls) ``。
   `--rest-secret` / `--turn-bandwidth` 不 gate。启动日志加 `features="lean"|"tls,dtls"`。
3. 测试：新增 `lean_build_refuses_tls_flags_with_the_feature_name`（`cfg(not(tls))`）、
   `build_without_dtls_refuses_dtls_listeners_with_the_feature_name`（`cfg(not(dtls))`）；
   原 T2 flag 测试拆成 `turn_t2_flags_are_validated_before_serving`（feature 无关）、
   `tls_flags_need_certificate_material`（`cfg(tls)`）、`dtls_pem_...`（`cfg(dtls)`）。
   `turn.rs` 里 `ClientTransport::Dtls` 在 lean 下 `cfg_attr(allow(dead_code))`，
   `count_handshake_failure` 只在 `tls` 下存在。
4. CI：`test` 作业按 `--no-default-features` 与 `--all-features` 各跑一次
   `cargo test` + `clippy`；smoke 保持默认（lean）构建。
5. 发布：每个平台建两次（lean 先落盘，full 后编并覆盖 target），上传
   `rstun-<platform>` 与 `rstun-full-<platform>` 两个 artifact；`release` 作业断言资产数
   恰好 8（4 平台 × 2），Release notes 表格分 lean/full 两列；镜像 `--features full`。
6. Dockerfile：依赖层与真实构建都 `--features full`（否则依赖层白拉）；补 `EXPOSE 5349/tcp|udp`。
7. 供应链：新增 `.cargo/audit.toml`，只 ignore `RUSTSEC-2026-0387`，注释写明三条豁免前提
   （lean 不含该依赖 / full 只有 `--turn-dtls-listen` 可达 / 每次发版前复查）。
   `cargo audit` 退出码恢复 0（3 条 unmaintained 仍是 warning）。
8. 文档：README 依赖面改成 lean/full 双表 + 体积 + 审计表；构建/安装段两种命令；
   镜像说明 full；Release 表 8 资产；spec `turn.md` 增加「构建 feature」契约与 3 条测试要求；
   `script/lab/README.md` 说明 `--tls/--dtls` 自动 full、lean 记 SKIP。
9. 脚本：`rstun-turn.sh` 默认 lean；`--tls`/`--dtls`/`--only tls|dtls|coturn` 自动
   `--features full`；`--no-build` 时用「启动一次并读 feature 错误」探测（不猜）；
   lean 下 `tls`/`dtls` 项与 coturn 的 TLS/DTLS 对照行记 SKIP 并说明；证书工具上移，
   供探测与 coturn 共用。

### 实测

- lean：9 个直接依赖（`cargo tree -e normal --depth 1` = 10 行）、65 个传递 crate（与 T2 前相同）、
  release **3,767,184 B（~3.6 MB）**。
- full：13 个直接依赖（14 行）、201 个传递 crate、release **7,928,904 B（~7.9 MB）**。
- `cargo audit`：`0 vulnerabilities`，3 条 allowed warnings，exit 0。
- lean 下 `--turn-tls-listen` / `--turn-dtls-listen` 启动失败（exit 1）且错误含 feature 名；
  full 的 `frozen` 项（T2 全部关闭）仍与 T1 基线逐字节一致。


---

## 实施记录（2026-11-20，第三轮：冷复核 B1 + 文档缺口）

冷复核结论：功能面/门禁/A–E 全过，1 个代码缺陷 + 2 个文档缺口 + 8 项记账。

### B1（代码，已修）

`load_secure_material` 原先**无条件**构建并校验 DTLS 材料，于是 full 构建里「只开
`--turn-tls-listen` + RSA 证书」（Let's Encrypt 的默认形态）被 `--tls-key … cannot be used
for DTLS` 拒绝。修法：新增 `needs_dtls: bool` 参数，只在该次启动真的配了
`--turn-dtls-listen` 时解析/校验；`SecureMaterial.dtls` 变为 `Option<…>`，监听绑定处
显式 `let Some(...) else { 内部错误 }`。

- 保留：DTLS 监听 + RSA → 仍拒绝启动（错误文案不变）；
- 保留：TLS 监听的材料校验（不可读/不配对/KeyMismatch）；
- 单测：`full_build_accepts_an_rsa_certificate_when_dtls_is_off`（`cfg(dtls)`，内嵌
  **test-only** RSA-2048 自签证书/私钥 fixture，避免依赖 CI 上的 openssl），同时断言
  `needs_dtls = true` 时仍然报错；
- lab：`run_tls` 第 4 步用 RSA 证书 + 仅 `--turn-tls-listen` 起服务并跑 `uclient -S -t`，
  断言 0 丢包（`run_dtls` 的 RSA 拒绝用例改用共享的 `make_rsa_cert`）。

### 文档

- **M1**：新增 `docs/browser-acceptance.md`（自签证书信任 / `iceServers` +
  `iceTransportPolicy: "relay"` / trickle ICE 观察点 / 对称 NAT 拓扑 / 常见失败），README
  「TURN」下新增小节并链接；文档状态行与 prd/implement 均写明**无自动化浏览器验收、尚未执行**。
- **M2**：README「未实现（有意）」重写为「TCP allocation (RFC 6062) / ACME+证书热加载 /
  多实例共享 allocation」，删掉「T2 未实现」；给 TURN 标题加 `<a id="turn">`，两处失效锚点
  （`#turnudp-中继turn`）改为 `#turn`。
- **M6**：clap `about`、`server` 子命令说明、`--turn` help、`Cargo.toml` description 都提到
  `turns:`/DTLS；README 的 help 片段由真实输出重新生成，并与 `--help` 逐字节 diff 一致。
- **M7**：`turn.rs` 模块文档改为「RFC 8656 中继状态机」，说明四种客户端传输、REST、带宽桶，
  去掉「T1 scope / T2 or later」。
- **M8**：PRD R3「每 peer 中继连接数上限」映射到 `--permission-limit`（design §5b 说明为何
  不再叠一个同维度计数器）。

### 顺手

- **M3**：CI `test` 作业新增 `cargo audit`（`rustsec/audit-check@69366f3` = v2.0.0，锁 commit
  SHA），`ignore` 与 `.cargo/audit.toml` 同步；`audit.toml` 注释改成「本地自动读 + CI 用
  action 显式传 ignore，两处同步」。
- **M4**：README 依赖面改成「指标 × lean/full × 可复现命令」表（直接依赖 9/13、依赖树行数
  89/345、唯一 crate 65/201），并说明 `cargo metadata` 的口径为什么不适用（87 含 dev/optional）。
- **M5**：体积区分「未 strip 的本地 release（3.77 / 7.93 MB）」与「镜像用的 LTO+strip
  二进制（2.35 / 4.80 MB）」，README/Dockerfile/CHANGELOG/Release notes 同步。
- **M9**：release 的 full 产物在 Linux 上新增 TLS 冒烟（自签 ECDSA + `turns:` 监听 +
  `openssl s_client` 握手 + 另一实例的明文 Binding 走 `rstun-smoke.sh`）。
- **M10**：`.cargo/audit.toml` 保持 untracked，内容保留由主会话提交。

---

## 实施记录（2026-11-20，第四轮：RSA fixture 归位）

用户定稿：B1 的 RSA 回归测试保留内嵌材料，但挪到标准位置并标注用途。

- 常量从 `src/main.rs` 的 base64 字符串改为
  `include_str!("../tests/fixtures/rsa-test-only.{crt,key}.pem")`（仍只在 `cfg(dtls)` 的测试里）。
- 新增 `tests/fixtures/README.md`：一次性 throwaway RSA-2048 自签密钥、只服务
  `full_build_accepts_an_rsa_certificate_when_dtls_is_off`、不参与运行期、任何信任库都不应接受、
  将来密钥扫描需 allowlist；并写明「从 crates.io 解包后 `cargo test` 会因 `tests/**` 被
  `exclude` 而失败，发布物只需 `cargo build`」这一取舍。
- `Cargo.toml` 的 `exclude` 增加 `tests/**`（原只有 `test/**`）：`cargo package --list` 不再
  包含夹具；`cargo package`（verify）仍成功 —— `include_str!` 在 `#[cfg(test)]` 内，发布构建
  不会展开。

## 浏览器验收状态（R4，2026-11-20）

- 自动化尝试：**环境阻断**。in-app 浏览器只把页面加载代理到 OpenCode 主机；WebRTC 的 UDP/TCP 走浏览器自身网络，
  到不了绑在 OpenCode 主机 `127.0.0.1` 的 TURN 监听。
- 证据：页面内 `Image` 探测 `http://127.0.0.1:9001/healthz` → `unreachable`；UDP 中继候选 0 个；
  `turns:` 报 `onicecandidateerror code=701`；服务端 `/metrics` 的 `rstun_requests_total{transport="udp"} = 0`。
- 记录：`docs/browser-acceptance.md` 的「尝试记录」。
- 结论：需在「与 TURN 同主机/同网络」或「TURN 绑浏览器可达地址 + 受信证书」的环境人工执行；
  **不得视为已验证**，也不阻塞 T2 的其余验收（TLS/DTLS/REST/带宽的第三方工具与 coturn 对照均已通过）。
