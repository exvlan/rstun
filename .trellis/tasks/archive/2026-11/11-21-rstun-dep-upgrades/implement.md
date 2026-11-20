# 执行计划：依赖主版本升级

> 两阶段独立验收；每阶段可单独回滚。开工前先做 1 的「现状核对」。

## 0. 现状核对（先做，只读）

```bash
grep -nE '^(sha1|sha2|md-5|hmac|webrtc-util|webrtc-dtls) *=' Cargo.toml
cargo tree -i webrtc-util
cargo tree -i webrtc-dtls
cargo test --all-features 2>&1 | tail -2
```

记录：当前版本、`webrtc-util` 的约束来源、基线测试数。

## 阶段 0 · semver 兼容更新

```bash
cargo update                      # patch/minor 全量
# 显式：clap 4.6.9、tokio 1.54.1、tokio-rustls 0.26.6（若有）、其余按 `cargo search` 最新
```

验证：`cargo test`（lean/full）+ `cargo tree -d`（新增同名多版本需说明）。

## 阶段 1 · crypto（sha1/sha2/md-5 → hmac）

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1.1 | `Cargo.toml`：`sha1 0.11`、`sha2 0.11`、`md-5 0.11`（同 `digest 0.11`）；先不动 `hmac` | `cargo tree -d` 看是否出现双 `digest` | 单 commit |
| 1.2 | 适配 `src/auth.rs`（`Digest` 输出类型、`finalize`） | `cargo test auth::` 向量全绿 | 同上 |
| 1.3 | `hmac 0.13` + 适配（`Mac`/`KeyInit` 路径） | `cargo test auth::` | 同上 |
| 1.4 | 全量门禁 | 见下 | 同上 |
| 1.5 | 合并/关闭 PR #3/#4/#6/#7 | `gh pr list` 状态 | — |

**门禁**：`cargo test`（lean/full）、clippy（两种 feature）、fmt、`interop all` 42、`abuse` 10、`turn` 15+2、`cargo audit` 0 vuln、`cargo deny` 四项 ok、冻结对照（3×17 与 `FROZEN_BASE` 一致）。

## 阶段 2 · webrtc-util 0.17

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 2.1 | 按 design §3.1 判定 A/B/C | `cargo tree` 证据 + `cargo info webrtc-dtls` | 只读 |
| 2.2 | 若 A/B：升 `webrtc-util`（必要时连 `webrtc-dtls`）并适配 `src/main.rs` 的 DTLS | `cargo test --all-features`；`rstun-turn.sh --tls --dtls` | 单 commit |
| 2.3 | 若 C：关闭 PR #5，写原因（上游组合不可行/需上游先动） | PR 评论 + 任务记录 | — |
| 2.4 | 门禁 + 冻结对照 + DTLS 真机握手 | 同阶段 1 | 同上 |

## 阶段 3 · 版本与发版准备

| # | 事项 | 验证 |
| --- | --- | --- |
| 3.1 | `Cargo.toml` `version = "26.410.101"` + `cargo generate-lockfile`（或 `cargo update -p rstun`）| `cargo metadata` OK；`--version` = `26.410.101`（无 `RSTUN_BUILD_VERSION` 时）|
| 3.2 | `CHANGELOG.md` 加 `## 26.410.101`（依赖升级 + 上游修复）| 人工评审 |
| 3.3 | 全量门禁 + 冻结对照（与 `26.410.100` 的字节一致）| 见下 |
| 3.4 | 提交；**发布由主会话执行**（`release.yml` dispatch + `cargo publish`）| — |

## 门禁（每阶段结束都跑）

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/lab/rstun-turn.sh          # lean：15 + 2 SKIP
bash script/lab/rstun-turn.sh --tls --dtls   # 仅阶段 2 涉及
cargo audit; echo "audit=$?"
cargo deny check
```

## 验收断言（必须）

- [ ] 向量测试全部保持通过（HMAC-SHA1/SHA256、MD5、RFC 5769 §2.4、nonce 跨实例）
- [ ] 默认路径字节冻结（3 配置 × 17 请求）与升级前一致
- [ ] `cargo tree -e normal --depth 1` 直接依赖数不变（9 / 13）
- [ ] `cargo audit` 0 vulnerability；新 unmaintained 需登记理由
- [ ] 5 个 PR：#3/#4/#6/#7 合并或取代；#5 合并或按 C 关闭并写明原因
- [ ] 二进制体积变化记录（>10% 说明）

## 风险

| R | 缓解 |
| --- | --- |
| `digest 0.11` 与 `hmac 0.12` 不兼容 | 一起升 `hmac 0.13`（阶段 1.3） |
| DTLS API 大改 | 先只升 `webrtc-util` 看编译；不行就评估 `webrtc-dtls` 连带升级 |
| Dependabot 在分支上持续 rebase | 以本任务提交为准，完成后关闭对应 PR |

---

## 执行记录（2026-11-21，implement agent）

### 最终版本（`cargo tree -e normal --depth 1`）

| crate | 升级前 | 升级后 | 备注 |
| --- | --- | --- | --- |
| clap | 4.6.8（约束 4.6.7） | **4.6.9** | 约束同步为 4.6.9 |
| tokio | 1.54.1（约束 1.53） | **1.54.1** | 约束同步为 1.54.1 |
| tokio-rustls | 0.26.6（约束 0.26.5） | **0.26.6** | 约束同步为 0.26.6 |
| hmac | 0.12.1 | **0.13.0** | `digest 0.11` 家族 |
| md-5 | 0.10.6 | **0.11.0** | 同上 |
| sha1 | 0.10.7 | **0.11.0** | 同上 |
| sha2 | 0.10.9 | **0.11.1** | 同上 |
| webrtc-util | 0.11.0 | **0.11.0（不动）** | 阶段 2 判 C |
| webrtc-dtls | 0.12.0 | **0.12.0（不动）** | 上游最新即 0.12.0 |
| socket2 / tracing / tracing-subscriber / rustls-pemfile / stun-types | 0.6.5 / 0.1.44 / 0.3.23 / 2.2.0 / 2.0.5 | 不变 | 已是各自最新 |

`cargo update` 顺带：`cc 1.11.2 → 1.11.3`、`pin-project-lite 0.2.17 → 0.2.18`。

### 阶段 1 代码改动（唯一源码改动）

`src/auth.rs`：`<Hmac<_> as Mac>::new_from_slice` → `<Hmac<_> as KeyInit>::new_from_slice`
（`digest 0.11` 把 `new_from_slice` 从 `Mac` 移到了 `KeyInit`；`use hmac::{Hmac, KeyInit, Mac}`）。
算法、key 派生、nonce、USERHASH 一字未改。

`Cargo.toml`：四个 RustCrypto crate 加 `default-features = false`。0.11 一代的默认 feature 是
`alloc` + `oid`，而本仓只用「喂字节 → 取摘要」；关掉后 `const-oid` 不进运行期依赖树，
**lean 依赖树行数保持 89（与 0.10 一代完全一致）**，且没有新增同名多版本。

### 阶段 2 判定：**C（上游组合不可行）→ `webrtc-util` 保持 0.11，PR #5 应关闭**

```text
$ cargo tree -i webrtc-util --all-features          # 现状（0.11）
webrtc-util v0.11.0
├── rstun v26.410.101
└── webrtc-dtls v0.12.0
    └── rstun v26.410.101

$ cargo info webrtc-dtls@0.12.0 --verbose | grep webrtc-util
 +webrtc-util@0.11.0                                 # crates.io 索引里是 `util ^0.11.0`

$ cargo search webrtc-dtls --limit 1
webrtc-dtls = "0.12.0"                               # 上游最新，没有支持 util 0.17 的版本
```

实测（临时把直接依赖改成 `webrtc-util = "0.17"` 再 `cargo check --features dtls`）：

```text
error[E0308]: mismatched types
    webrtc_dtls::conn::DTLSConn::new(conn, config, false, None)
error[E0277]: the trait bound `DTLSConn: Conn` is not satisfied
    = note: required for the cast from `Arc<DTLSConn>` to `Arc<(dyn Conn + Send + Sync + 'static)>`
error: could not compile `rstun` (bin "rstun") due to 2 previous errors
```

树里出现两份 `webrtc-util`（0.11 + 0.17），`DTLSConn` 实现的是 0.11 的 `Conn`。
**结论：等到 `webrtc-dtls` 出跟进 `webrtc-util` 0.17 的版本再升；PR #5 关闭（或标 blocked-upstream）。**

由此带来的唯一副作用：full 构建里 `digest` 两代并存（本仓 0.11 + `webrtc-dtls` 的 0.10），
full 依赖树行数 345 → 359、唯一 crate 201 → 212；README「依赖面」已更新并附说明。

### 体积（Linux x86_64，Rust 1.95）

| 构建 | 升级前 | 升级后 | 变化 |
| --- | --- | --- | --- |
| release lean（未 strip） | 3,767,576 B | 3,765,504 B | −2,072 B（−0.05%）|
| release full（未 strip） | 7,930,176 B | 7,945,608 B | +15,432 B（+0.19%）|
| release lean（LTO + strip） | 2,345,616 B | 2,344,416 B | −1,200 B（−0.05%）|
| release full（LTO + strip） | 4,799,624 B | 4,817,208 B | +17,584 B（+0.37%）|

均远低于 10% 阈值。

### 同名多版本（`cargo tree -d --all-features` 前后对照）

基线 30 条 → 现在 28 条：**减少** `md-5 0.10/0.11` 两行（本仓升到 0.11 后与 dev-dep `stun-types` 共用同一份），
**没有新增**任何同名多版本。`bitflags` / `thiserror` / `syn` / `rand` / `getrandom` /
`block-buffer` / `crypto-common` / `cpufeatures` / `digest` / `hmac` / `sha1` / `sha2`
两代并存均为既有状态（`stun-types` dev-dep 与 `webrtc-dtls` 链）。

### 冻结对照的一个必要说明（重要）

`rstun-turn.sh` 的 `frozen` 项比较的是**线上字节**，其中 `SOFTWARE` = `rstun/<crate 版本>`。
版本号从 `26.410.100` → `26.410.101` 必然让这 17 个响应里的 SOFTWARE 串变化，
因此**直接跑会红**（diff 只有 SOFTWARE 一处）。正确做法是与旧二进制对齐版本串：

```bash
RSTUN_BUILD_VERSION=26.410.100 cargo build     # 新树，判「依赖升级有没有改字节」
FROZEN_BASE=8a0fe2d bash script/lab/rstun-turn.sh --no-build
# → ok: frozen 3 configurations × 17 requests byte-identical to HEAD
```

即：**依赖升级本身零字节变化**；唯一变化是版本号，属于阶段 3 的预期行为。

### 门禁结果（最终树）

| 门禁 | 结果 |
| --- | --- |
| `cargo test` | 235 passed |
| `cargo test --all-features` | 236 passed |
| clippy（lean / full，`-D warnings`） | clean |
| `cargo fmt --all -- --check` | clean |
| `bash script/lab/rstun-interop.sh all` | 全绿（42 项子用例） |
| `bash script/lab/rstun-abuse.sh` | 全部通过 |
| `bash script/lab/rstun-turn.sh --no-build`（版本串对齐） | 14 ok / 0 fail / 3 skip（`tls`、`dtls` lean 预期；`cleanup` 因 49700–49799 已被外部进程占用） |
| 同上 `cleanup`（端口段换 49900–49999） | ok：`created=5, allocations=0`，段内无监听 |
| `bash script/lab/rstun-turn.sh --tls --dtls` | 2/2 ok（TLS + DTLS 真机中继、RSA 仅 TLS 可启动 / DTLS 拒绝） |
| `cargo audit` | exit 0（3 条 unmaintained warning，与升级前同一组） |
| `cargo deny check licenses bans sources` | `bans ok, licenses ok, sources ok`（工具 0.22.0，与 CI 同版本） |
| `cargo tree -e normal --depth 1` | lean **9** / full **13**（不变） |
| `bash script/ci/check-docs.sh --no-build` | ✓（README 依赖面更新后仍一致） |

### 遗留（交给主会话）

1. PR #3 / #4 / #6 / #7：本任务提交已取代，合并后即可关闭。
2. PR #5：按上面 C 的证据关闭，并在 PR 留言「等 `webrtc-dtls` 支持 `webrtc-util` 0.17」。
3. 发版后把下列**钉死旧版本的可部署产物**改成 `26.410.101`（`release.yml` 不会自动改）：
   - `README.md` 安装表的「已发布 26.410.100」
   - `docs/book/src/docker.md` 的镜像示例 tag
   - `contrib/k8s/deployment.yaml`、`contrib/docker/compose.yaml`、
     `contrib/helm/Chart.yaml`（`appVersion`）、`contrib/helm/values.yaml`（`tag`）
   其余 `26.410.100` 出现点（协议/鉴权/限流文档里的「与 26.410.100 逐字节一致」、
   `docs/perf.md` 的被测版本、`script/**` 与源码注释）属历史基线与示例，保留不改。

## 发版执行记录（26.410.101，主会话）

| 项 | 结果 |
| --- | --- |
| 代码提交 | `9daa319`（依赖升级 + 版本号 + CHANGELOG + README 重测）|
| crates.io | ✅ `rstun v26.410.101` 已发布；`cargo install rstun --version 26.410.101` → `rstun 26.410.101` |
| Release 流水线 | ✅ run `44792798928` 11/11 作业成功 |
| Release 资产 | ✅ **11**（lean+full 各 4 zip + 2 SBOM + `rstun.rb`）；tag `rstun-v26.410.101` |
| 镜像 | `ghcr.io/exvlan/rstun:26.410.101`（amd64+arm64，full）|
| **新 manifest digest** | `sha256:78c0d07581a74c650dedb518347aa92079ed0063825d72c40e6fb52e0835ae17` |
| 上一版 digest（26.410.100）| `sha256:bafa4f17257b37d05e6d5615d9cbd4f46105ac610473607ca10329926657b663` |
| Dependabot | #3/#4/#6/#7 关闭（由 `9daa319` 取代）；#5 关闭（blocked upstream），**0 个 open** |

### 复核修正（冷复核发现，已改）

1. CHANGELOG 原写「tokio 1.54.0 → 1.54.1、tokio-rustls 0.26.5 → 0.26.6」与实际不符——
   `Cargo.lock` 里两者升级前后都是 1.54.1 / 0.26.6，本次只收紧约束文本；实际变化的 patch 只有
   `clap 4.6.8 → 4.6.9`。已按事实改写。
2. 同名多版本计数：30 → **28**（不是 29；减少的是 `md-5 0.10.6` 与 `md-5 0.11.0` 两行）。
3. 发版清单补 `contrib/{k8s,docker,helm}` 四个钉死旧 tag 的可部署产物（`release.yml` 不会自动改）。

### 发版后已同步的版本钉死点

`README.md`（安装表「已发布」）、`docs/book/src/docker.md`（镜像示例）、
`contrib/k8s/deployment.yaml`、`contrib/docker/compose.yaml`、
`contrib/helm/Chart.yaml`（`appVersion`）、`contrib/helm/values.yaml`（`tag`）。
