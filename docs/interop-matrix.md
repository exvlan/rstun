> 原始证据产生于 Exvlan monorepo 时期（日志路径为当时机器上的 /tmp）。

# T1 互操作矩阵（`rstun`）

> 任务：`.trellis/tasks/11-19-rstun-standalone` 阶段 T1（`implement.md` 1.1–1.8）
> 执行时间：2026-11-19 · 环境：Debian 13 (trixie) / x86_64，Rust 1.95.0 + nightly 1.102.0，
> Go 1.24.4，coturn 4.6.1-2
> 被测二进制：`rstun 26.410.20715`（`cargo build -p rstun`，debug）

## 0. 结论（先说）

1. **四方对手全绿**：coturn/`turnutils_stunclient`、pion/stun v3.1.7、webrtc-rs `stun` 0.17.3、
   `stun-types` 2.0.5 —— 共 **41 项子用例 / 191 条断言**
   （19 probe + 7 pion + 8 webrtc + 5 coturn + 1 stun-types + 1 rfc5769；
   断言数 = 各日志 `ok:` 行合计：probe 101 + pion 40 + webrtc 44 + coturn 6）。
   本轮 probe 新增 `fingerprint` / `fingerprint-drop` / `alternate` 三项（+15 条断言），
   见 §13；口径说明：冷复核给的「224」是**旧**口径（把解码里的结构性前置条件也当成 `ok:` 断言）；
   按 B2 把这类前置条件改成只在失败时输出后，可复核的 `ok:` 行是 191
   （`grep -a -h '^ok:' $RSTUN_INTEROP_DIR/logs/*.log | wc -l`）。
2. **RFC 5769 四段标准字节全部通过**（§2.1 请求 / §2.2 IPv4 响应 / §2.3 IPv6 响应 / §2.4 长凭证请求），
   并且 §2.2/§2.3 我们能**逐字节重建**同样的 `XOR-MAPPED-ADDRESS`。
3. **fuzz 10 分钟无 panic / 无挂死**：`Done 84319569 runs in 601 second(s)`，`cov: 302 ft: 687`，
   崩溃行 0、`artifacts/parse/` 空（日志 `logs/fuzz-600s-20261119-022639.log`，详见 §1.7）。
4. **未发现 rstun 的协议缺陷**：本轮唯一的实现缺陷在**探针脚本自身**（IPv6 用 v4 客户端），
   已修，见 §10。
5. **1.8 的「workflow 绿」未完成**：CI 矩阵作业已写好并在 Linux 本地复现全绿，
   但 macOS/Windows 需要真正推一次 CI 才能变绿，而本任务的硬约束是**禁止 push**。见 §1.8。

## 1. 方法

### 1.1 骨架（`script/lab/rstun-interop.sh`）

单入口、可单项跑、结果可摘录：

```bash
bash script/lab/rstun-interop.sh --list          # 列项
bash script/lab/rstun-interop.sh probe           # rstun 自身协议矩阵（19 项子用例）
bash script/lab/rstun-interop.sh pion            # Go 第三方
bash script/lab/rstun-interop.sh webrtc-stun     # Rust 第三方（webrtc-rs）
bash script/lab/rstun-interop.sh coturn          # coturn 双向
bash script/lab/rstun-interop.sh stun-types      # dev-dep 双向
bash script/lab/rstun-interop.sh rfc5769         # RFC 5769 向量
bash script/lab/rstun-interop.sh fuzz --fuzz-seconds 600
bash script/lab/rstun-interop.sh ci              # 本地复现 CI 矩阵步骤
bash script/lab/rstun-interop.sh all             # 除 fuzz/ci 外全部
```

设计要点：

- **端口不用 3478**：基准 `34780`，`--port N` 可平移；脚本对 `--port 3478` 直接拒跑。
- **临时工程不落仓库**：Go module、webrtc-stun cargo 工程都建在
  `$RSTUN_INTEROP_DIR`（默认 `/tmp/opencode/rstun-interop`），依赖解析与 `Cargo.lock`
  都在那里；仓库里只放**源码夹具**（`rstun/test/interop/{pion,webrtc-stun}/`）。
- **单项可跑**：每项自己起/停服务，项间 `cleanup` 清理自己的 PID，互不串端口。
- **缺依赖记 SKIP 不算失败**：没有 `turnserver` / `cargo-fuzz` / PyYAML / IPv6 回环时该项标
  `SKIP`，其余项照跑（避免「一个环境缺件就整盘红」）；探针的 exit 77 也映射成 SKIP。
- **证据就是日志**：每项把自己的输出写进 `$RSTUN_INTEROP_DIR/logs/`（probe 逐子用例、
  pion/webrtc 逐 mode、coturn 含服务端 `--verbose` 行）。本报告的「N 条断言」=
  `grep -a -h '^ok:' $RSTUN_INTEROP_DIR/logs/*.log | wc -l`。

探针 `script/lab/rstun-interop-probe.py` 只用 python3 标准库（与
`script/ci/rstun-smoke.sh` 同一依赖策略），逐条断言并输出 `ok:` / `FAIL:`，
便于报告直接摘录。

### 1.2 「双向」的定义（为什么第三方夹具不链接 rstun）

| 方向 | 含义 | 做法 |
| --- | --- | --- |
| A：他们发 → 我们答 | 对手的**编码器**产出请求，rstun 解析并应答 | 对手 SDK 组包 → 真实 UDP/TCP → rstun |
| B：我们发 → 他们答 | rstun 的响应被对手的**解码器**读出来 | 对手 SDK 解析我们返回的字节，逐个属性断言 |

两个夹具（Go / Rust）都**不 import/link `rstun`**，所以「他们能读我们的包」就是真正的第三方结论。

- 对手**有服务端**时（coturn），额外做真实网络方向 A′：我们的探针 → 对手服务端。
- pion/stun 与 webrtc-rs `stun` 只提供编解码 + 客户端（没有 STUN 服务端），
  因此它们的方向 B 只能到编解码层。这是**能力边界，不是失败**（见 §9 的 J2）。

## 2. 1.2 coturn / `turnutils_stunclient`（生产同款）

coturn 用**原生进程**（`turnserver -n …`），不用容器：不触容器边界，也不依赖 docker/podman。
端口：rstun 主入口 `34780`、alt 端口 `34781`；coturn 用 `34790`（= base+10，脚本变量
`coturn_port=$((PORT + 10))`，避免与 rstun 的四 socket 冲突）。

| # | 用例 | 请求属性 | 我方/对手响应属性 | 对手能否解析 | 结论 |
| --- | --- | --- | --- | --- | --- |
| C1 | coturn 基线：`stunclient` → coturn | 无 | `0x0101` + `XOR-MAPPED-ADDRESS` | 是（自家） | ✅ 工具可用，后续失败才可归因 |
| C2 | 我方探针 → coturn（方向 A′） | 无 | `0x0101` + XOR + `SOFTWARE=Coturn-4.6.1 'Gorst'` | 是 | ✅ 我们的请求编码被 coturn 接受 |
| C3 | `stunclient` → rstun（方向 A） | 无 / CHANGE-REQUEST / PADDING | 见下 | 是，exit=0 | ✅ |
| C4 | `stunclient` 的 RFC 5780 三响应 | 见下 | `RESPONSE-ORIGIN` + `OTHER-ADDRESS` 正确 | 是 | ✅ |
| C5 | `stunclient` 断言的**回包源** | CHANGE-REQUEST 0x06 | 来自 `127.0.0.2:34781` | 是 | ✅ |

`turnutils_stunclient -p 34780 127.0.0.1` 原始输出（完整见
`/tmp/opencode/rstun-interop/logs/coturn-stunclient-to-rstun.log`；下面只去掉了
`====` 分隔行与 turnutils 自己重复打印的同一行）：

```
RFC 5780 response 1
  Response origin: : 127.0.0.1:34780
  Other addr: : 127.0.0.2:34781
  UDP reflexive addr: 127.0.0.1:33805
RFC 5780 response 2
  Response origin: : 127.0.0.2:34781
  Other addr: : 127.0.0.1:34780
  UDP reflexive addr: 127.0.0.1:33805
RFC 5780 response 3
  Response origin: : 127.0.0.2:34781
  Other addr: : 127.0.0.1:34780
  UDP reflexive addr: 127.0.0.1:33806
EXIT=0
```

服务端侧 `--verbose` 日志（`coturn-target-verbose` 实例，日志文件
`$RSTUN_INTEROP_DIR/logs/coturn-target-verbose.log`）逐条对应 —— 这是
「回包源为什么是这个 / 客户端到底请求了什么」的直接证据。原文带 ANSI 颜色，
下面用 `sed -r 's/\x1B\[[0-9;]*m//g'` 去色后按时间顺序摘录（**未改动字段与数值**）：

```bash
$ sed -r 's/\x1B\[[0-9;]*m//g' logs/coturn-target-verbose.log \
    | grep -E 'RFC 5780 enabled|started|binding request'
2026-11-18T18:37:26.451503Z  INFO rstun: rstun: RFC 5780 enabled (CHANGE-REQUEST / RESPONSE-ORIGIN / OTHER-ADDRESS) primary=127.0.0.1:34780 other_ip=127.0.0.2 other_port=34781
2026-11-18T18:37:26.451577Z  INFO rstun: rstun: started, Ctrl-C to stop software=rstun/26.410.20715 listeners=4
# ① wait_ready 的探针（脚本启动等待，不是 coturn 的请求）
2026-11-18T18:37:26.484093Z DEBUG rstun: rstun: binding request source=127.0.0.1:33748 mapped=127.0.0.1:33748 local=127.0.0.1:34780 transaction_id=48f343a1b78fb9e3589d93f6 response_origin=Some(127.0.0.1:34780) padding=None from=127.0.0.1:34780 to=127.0.0.1:33748
# ② coturn response 1：无 CHANGE-REQUEST → 从入口 socket 回
2026-11-18T18:37:26.492113Z DEBUG rstun: rstun: binding request source=127.0.0.1:33805 mapped=127.0.0.1:33805 local=127.0.0.1:34780 transaction_id=05552a4c87dea6b1da11e117 response_origin=Some(127.0.0.1:34780) padding=None from=127.0.0.1:34780 to=127.0.0.1:33805
# ③ coturn response 2：CHANGE-REQUEST 0x06 → 从 127.0.0.2:34781 回，客户端已换到 33806
2026-11-18T18:37:26.492345Z DEBUG rstun: rstun: binding request source=127.0.0.1:33805 mapped=127.0.0.1:33805 local=127.0.0.1:34780 transaction_id=d273aec5c111f8d9b397995f response_origin=Some(127.0.0.2:34781) padding=None from=127.0.0.2:34781 to=127.0.0.1:33806
# ④ coturn response 3：同样 0x06，且带 PADDING 1500
2026-11-18T18:37:26.492541Z DEBUG rstun: rstun: binding request source=127.0.0.1:33806 mapped=127.0.0.1:33806 local=127.0.0.1:34780 transaction_id=bd7ce9e76896ac13ae128262 response_origin=Some(127.0.0.2:34781) padding=Some(1500) from=127.0.0.2:34781 to=127.0.0.1:33806
```

（`transaction_id` / 客户端端口每次运行都会变，`127.0.0.1:34780` 与
`127.0.0.2:34781` 是固定的——它们来自 `--listen` / `--alt-listen`。）

说明（重要，避免误读）：

- coturn 客户端**只**跑「change IP+port（0x06）」与「0x06 + PADDING 1500」两种组合，
  **不**单独发 0x02 / 0x04；单轴语义由我们自己的探针覆盖（`probe/change` 三条全绿）。
- coturn 客户端**不发** `RESPONSE-PORT`。该属性的第三方覆盖由 pion / webrtc-rs 夹具补上（§3/§4）。
- response 3 的源地址仍是 `127.0.0.2:34781`，因为它请求的也是 0x06（不是单换端口）；
  「从 .2 进入、只换端口」的对角场景由 `probe/rfc5780-attrs` 与单测
  `rfc5780_entering_on_the_other_address_still_reports_a_useful_pair` 覆盖。

## 3. 1.3 pion/stun（Go，v3.1.7）

夹具：`rstun/test/interop/pion/main.go`（运行时复制到 `/tmp/opencode/rstun-interop/pion`，
`go mod tidy` 在临时目录里跑，仓库不落 `go.sum`/vendor）。

| # | 用例 | 请求属性 | 我方响应属性 | pion 能否解析 | 结论 |
| --- | --- | --- | --- | --- | --- |
| P1 | basic | 无 | `0x0101`、`XOR-MAPPED-ADDRESS`、`SOFTWARE=rstun/26.410.20715` | 是 | ✅ |
| P2 | ice | `USERNAME` `MESSAGE-INTEGRITY` `PRIORITY` `USE-CANDIDATE` `ICE-CONTROLLING` `FINGERPRINT` | 仍是 `0x0101`（**未** 420） | 是 | ✅ 不误伤 ICE 客户端 |
| P3 | unknown | 原始 `0x0033` | `0x0111` + `ERROR-CODE 420` + `UNKNOWN-ATTRIBUTES` = `2` 字节 `0033` | 是 | ✅ |
| P4 | padding | `PADDING` 200 | 回显 200，`224 → 284` 字节（+60 = XOR 12 + SOFTWARE 24 + RESPONSE-ORIGIN 12 + OTHER-ADDRESS 12；PADDING 头在请求/响应各有一份、抵消。其中 24 字节来自本项实例的 `--alt-listen`，**不是** PADDING 放大：回显值仍是 200） | 是 | ✅ |
| P5 | response-port | `RESPONSE-PORT` = 第二 socket 端口 | 回包到该端口、源端口仍是 34780、请求源端口保持安静 | 是 | ✅ **目的端口**语义被第三方确认 |
| P6 | tcp | 无（RFC 5389 §7.2.2 分帧） | `0x0101` + XOR | 是 | ✅ |
| P7 | rfc5780 | `CHANGE-REQUEST` 0x02 | `RESPONSE-ORIGIN=127.0.0.1:34781`、`OTHER-ADDRESS=127.0.0.2:34780`；**并断言回包实际源端口/源 IP = alt**（不只比属性值） | 是 | ✅ |

关键输出（`logs/pion-rfc5780.log`、`logs/pion-response-port.log`）：

```
ok: pion 解码响应 type=Binding success response length=60 attrs=4
ok: pion 解出 RESPONSE-ORIGIN = 127.0.0.1:34781
ok: pion 解出 OTHER-ADDRESS = 127.0.0.2:34780
ok: RESPONSE-ORIGIN 是换端口后的源地址 127.0.0.1:34781

ok: 回包源端口仍是入口端口 34780（实际 34780）
ok: XOR-MAPPED-ADDRESS = 请求源地址 127.0.0.1:16562（实际 127.0.0.1:16562）
ok: 请求源端口没有收到第二份响应
```

## 4. 1.4 webrtc-rs `stun` 0.17（0.17.3）

夹具：`rstun/test/interop/webrtc-stun/`（`Cargo.toml.in` 复制为临时工程的 `Cargo.toml`，
避免在仓库里多出一个「非 workspace 成员」的 manifest）。

| # | 用例 | 请求属性 | 我方响应属性 | webrtc-rs 能否解析 | 结论 |
| --- | --- | --- | --- | --- | --- |
| W1 | basic | 无 | `0x0101` + XOR + `SOFTWARE` | 是（`XorMappedAddress::get_from`） | ✅ |
| W2 | ice | ICE/鉴权簇 | 仍是 `0x0101` | 是 | ✅ |
| W3 | unknown | `0x0033` | 420 + `UNKNOWN-ATTRIBUTES`（`length=2`） | 是（`attributes.get`） | ✅ |
| W4 | padding | `PADDING` 200 | 回显 200，无放大 | 是 | ✅ |
| W5 | response-port | `RESPONSE-PORT` | 目的端口投递、源端口不变 | 是 | ✅ |
| W6 | tcp | 无 | `0x0101` + XOR | 是 | ✅ |
| W7 | rfc5780 | `CHANGE-REQUEST` 0x02 | `RESPONSE-ORIGIN` / `OTHER-ADDRESS`（明文布局） | 是 | ✅ |
| W8 | ipv6 | 无（`[::1]`） | XOR 地址族 `0x02`，`[::1]:port` | 是 | ✅ |

`logs/webrtc-rfc5780.log`：

```
ok: webrtc-rs 解出 RESPONSE-ORIGIN = Some(127.0.0.1:34781)
ok: webrtc-rs 解出 OTHER-ADDRESS = Some(127.0.0.2:34780)
ok: RESPONSE-ORIGIN 是换端口后的源地址 127.0.0.1:34781（回包源 127.0.0.1:34781，alt-port 34781）
```

> 注：`RESPONSE-ORIGIN` / `OTHER-ADDRESS` 在 webrtc-rs 里没有类型化封装（只有 `ATTR_*` 常量），
> 所以用它自己的 `AttrType` 常量 + 我们按 RFC 5389 §15.1 的明文布局解码。
> 这一步仍是「它的消息结构读我们的字节」，但**地址布局**的最终判据是
> `stun-types` 的 `MappedSocketAddr`（§5）与 RFC 5769 向量（§6）。

## 5. 1.5 `stun-types` 2.0.5（`[dev-dependencies]`，双向）

测试：`rstun/src/tests_interop.rs::stun_types_bidirectional`（`cargo test -p rstun -- tests_interop::`）。

| 方向 | 内容 | 结论 |
| --- | --- | --- |
| A：他们编码 → 我们解析 | `stun-types` 的 `Message::builder_request` + `Software` / `Username` / `RawAttribute(CHANGE-REQUEST 0x02)` 组包；我们 `parse` 后：无未知属性、SOFTWARE 值一致、`change_request == {ip:false, port:true}` | ✅ |
| B：我们编码 → 他们解码 | 我们的成功响应（XOR + MAPPED + RESPONSE-ORIGIN + OTHER-ADDRESS + SOFTWARE + PADDING 32）被它解析：`XorMappedAddress` / `MappedSocketAddr`（三处地址）逐一对上、`PADDING` 原始长度为 32 | ✅ |
| B（错误响应） | 我们的 `300` 被它解出 `ErrorCode(300) + reason "Try Alternate"` 与 `AlternateServer(192.0.2.9:3478)`；`500` 被解出 `ErrorCode(500) + reason "Server Error"`，且响应固定 40 字节 | ✅ |

```
test tests_interop::stun_types_bidirectional ... ok
test tests_interop::stun_types_decodes_our_300_and_500_error_responses ... ok
```

## 6. 1.6 RFC 5769 测试向量

测试：`rstun/src/tests_interop.rs::rfc5769_*`。四段字节**全部来自 RFC 原文**（用脚本从
`rfc5769.txt` 抽取，避免手抄错误），基线长度与 Message Length 自检：

| 段落 | 内容 | 字节数 | 断言 |
| --- | --- | --- | --- |
| §2.1 | Sample Request | 108（Length 88） | 解析成功；SOFTWARE `STUN test client`；USERNAME `evtj:h6vY`；MI 20B；PRIORITY 4B；ICE-CONTROLLED 8B；FINGERPRINT 4B；**未知属性为空 → 不会被 420** |
| §2.2 | Sample IPv4 Response | 80（Length 60） | XOR 解出 `192.0.2.1:32853`；**我们重建的 XOR 值与其逐字节相同** |
| §2.3 | Sample IPv6 Response | 92（Length 72） | XOR 解出 `[2001:db8:1234:5678:11:2233:4455:6677]:32853`；重建逐字节相同 |
| §2.4 | Long-Term Auth Request | 116（Length 96） | USERNAME=18B `マトリックス`、NONCE 28B、REALM `example.org`、MI 20B；**不会 420** |

```
test tests_interop::rfc5769_2_1_sample_request_is_understood ... ok
test tests_interop::rfc5769_2_2_sample_ipv4_response_decodes_and_we_reencode_the_same_bytes ... ok
test tests_interop::rfc5769_2_3_sample_ipv6_response_decodes_and_we_reencode_the_same_bytes ... ok
test tests_interop::rfc5769_2_4_long_term_auth_request_is_not_turned_into_420 ... ok
test tests_interop::rfc5769_fingerprints_are_valid_and_our_crc32_agrees ... ok
```

FINGERPRINT 现在也被**校验**（`--check-fingerprint`）：§2.1–§2.3 的标准字节判为 `Valid`，
改一位后判为 `Mismatch`。CRC 的覆盖范围按 RFC 5389 §15.5 包含「Length 已计入该属性」的头部
（`crc32` 模块另用 §2.1 的 `0xe57a3bcf` 常量锁死）。

> 有意不做的：`MESSAGE-INTEGRITY` 只断言存在与长度。本服务器不做鉴权（PRD 非目标），
> 校验 HMAC 会给出「我们支持鉴权」的错误印象。

## 7. 1.7 `cargo-fuzz`（解析路径）

工程：`rstun/fuzz/`（独立 workspace，`libfuzzer-sys` 不进主 workspace 依赖图）。
目标 `parse`：`peek_frame_len` → `parse` → 属性迭代（`decode_xor_mapped_address` /
`decode_address_value` / 已知属性表）→ `unknown_attributes` / `padding_len` /
`response_port` / `change_request` → `binding_success_response` /
`unknown_attributes_response` / `error_response`，并断言**我们自己的响应能被自己解析**。

运行（**经由矩阵脚本**，与验收口径一致；日志名带时长 + 时间戳，短跑不会覆盖长跑）：

```bash
$ bash script/lab/rstun-interop.sh --item fuzz --fuzz-seconds 600
== cargo-fuzz（解析路径 600s）
  ok   fuzz/600s（Done 84319569 runs；/tmp/opencode/rstun-interop/logs/fuzz-600s-20261119-022639.log）
```

| 指标 | 值 |
| --- | --- |
| 时长 | **601 s**（`-max_total_time=600`，收尾多 1 s） |
| 执行次数 | **84,319,569 runs**（`Done 84319569 runs in 601 second(s)`） |
| 退出码 | 0（脚本汇总 `ok fuzz/600s`） |
| panic / 挂死 / OOM | **0**（`grep -cE "panicked\|ERROR: libFuzzer\|deadly signal\|timeout after"` = 0） |
| 覆盖 | 收尾行 `#84319569 DONE cov: 302 ft: 687 corp: 116/8562b lim: 4096 exec/s: 140298 rss: 529Mb` |
| 产物 | `fuzz/artifacts/parse/` 为空（无崩溃输入） |

> 600 s 内覆盖仍在增长（30 s 预热时 `cov: 281`，收尾 `cov: 302 ft: 687`），且没有一次崩溃 ——
> 说明解析器在「合法但奇怪」的输入上也稳定。

预热证据（不是验收依据，只用于说明 60 s 与 600 s 的差别）：
`Done 3465326 runs in 31 second(s)`（30 s 快速自检）。

## 8. 1.8 CI 矩阵（Linux / macOS / Windows × UDP / TCP / IPv6）

改动：`.github/workflows/test.yml`

- 新增作业 `rstun_matrix`：`os: [ubuntu-latest, macos-latest, windows-latest]`，
  步骤 = `cargo test -p rstun`（进程内真 bind 的 UDP/TCP/IPv6）→ `cargo build` →
  `rstun-smoke.sh`（UDP+TCP）→ IPv6 冒烟（仅 `[::1]`）。
- 路径门控补 `rstun/**`、`script/ci/rstun-*`、`script/lab/rstun-*`
  （此前 PR 只改 rstun 时会被 `pre_job` 判为「不相关」而跳过）。
- Windows 侧的两个坑写进注释并处理：`.exe` 后缀；`python3` 缺失时建临时 shim。
- 未碰 `pipeline.yml` / `docker.yml` / `release.yml`（另一会话在改）。

本地可验证部分（`bash script/lab/rstun-interop.sh ci`）：

```
ok   ci/cargo-test          cargo test（当时 64 passed；现 75）
ok   ci/no-upstream-deps    cargo tree -e all | grep -c '^exvlan-' == 0
ok   ci/smoke-udp-tcp       rstun-smoke.sh 127.0.0.1:34780 --tcp
ok   ci/smoke-ipv6          rstun-smoke.sh [::1]:34787
ok   ci/workflow-yaml       workflow 可被 YAML 解析
```

**状态：❌ 未完成（阻塞于「禁止 push」）。** 作业已写好、YAML 通过解析、Linux 步骤已本地复现全绿；
macOS / Windows 的 runner 结果只能由真实 CI 产生。本任务硬约束禁止 `git push`，
因此**不能**声称 workflow 已绿。下一步建议（需用户/主会话执行）：
`git push` 后等该 sha 的 `test` 运行结束，或用 `script/ci/run-with-public.sh <branch>`
（私有仓额度耗尽时的封装脚本）看 `rstun matrix (macos-latest)` / `(windows-latest)` 两项。

## 9. 失败项与判定

**本轮没有失败项**（41/41 项子用例 ok）。但有三处「看起来像差异」的点，判定如下：

| # | 观察 | 判定 | 依据 |
| --- | --- | --- | --- |
| J1 | coturn 客户端的 response 3 源地址与 response 2 相同（都是 `127.0.0.2:34781`） | **不是缺陷**：它请求的是 0x06 + PADDING，不是单换端口 | `logs/coturn-target-verbose.log` 第 ④ 条的 txn `bd7ce9…`：`response_origin=Some(127.0.0.2:34781) padding=Some(1500)`；对应 `turnutils` 输出里 response 3 的 `Response origin: : 127.0.0.2:34781` |
| J2 | pion / webrtc-rs 没有 STUN 服务端，方向 B 只到编解码层 | **对手能力边界**，非我方问题 | 两者 crate 只导出 codec/client/agent；真实网络方向由 coturn 覆盖 |
| J3 | `RESPONSE-ORIGIN` / `OTHER-ADDRESS` 在第三方库里没有类型化封装 | **事实，不是缺陷**：消息结构由它们读通，地址布局由 `stun-types::MappedSocketAddr` 与 RFC 5769 向量双重确认 | §5、§6 |

## 10. 本轮修的 bug（不在 rstun）

探针脚本初版用**固定 IPv4 客户端**（绑 `127.0.0.1`）去打 `[::1]` 的服务，
表现为「IPv6 超时」——其实是客户端把 `::1` 当 IPv4 解析。
修法：`client_for(server_addr)` 按被测服务地址族选回环绑定，地址文本用 `format_addr`
统一加方括号。修完 `probe/ipv6`、`webrtc-stun/ipv6` 全绿。

> 记这一条是因为它正是「IPv6 测试莫名超时」的典型误判来源：**先怀疑夹具**，
> 再怀疑实现。本轮据此没有改动 `rstun` 的任何协议行为。

## 11. 局限（不要过度引用）

1. **单机回环**：所有互操作都在本机（`127.0.0.1` / `127.0.0.2` / `[::1]`）。真实公网 NAT、
   丢包、MTU 分片不在本轮范围内（生产切换另有 S4 的外部 vantage 验证）。
2. **coturn 客户端覆盖面窄**：只发 0x06 + PADDING（见 J1），单轴 CHANGE-REQUEST 靠我们自己的探针。
3. **`RESPONSE-PORT` 的第三方只有 pion / webrtc-rs**；coturn 的 `stunclient` 不发该属性。
4. **macOS / Windows 的 CI 矩阵已由独立仓 CI 确认**（三平台 test + 冒烟 + IPv6 全绿）。
5. fuzz 只覆盖解析/编码纯函数，不含 `decide()` 与 socket 层（那部分由 e2e 单测覆盖）。
6. **公网「change 回包收不到」不等于服务端换源失败**：生产实测两个不同运营商的家宽客户端都收不到
   回包，而服务端抓包证明回包已从正确 socket 发出 —— 原因是客户端 NAT 非 full-cone，丢弃陌生源。
   验证 `CHANGE-REQUEST` 的判据必须取本地回环、服务端抓包（`from=`）或 DC/full-cone 客户端，
   详见任务 `research/S4-production-switch.md`。
7. **pion / webrtc-rs 夹具不解析错误响应类型（300/500）**：两者的公共 API 面向 Binding 成功响应与
   通用属性，没有 `ErrorCode` / `AlternateServer` 的类型化解码；因此这两类响应的第三方解码由
   `stun-types` 覆盖（§5、§13），探针只断言字节与错误码。不要据此认为「pion/webrtc 读不了 300」——
   它们能按通用 TLV 解析，只是本仓夹具没有断言这一点。

## 12. 复现命令（逐个可粘）

```bash
cd rstun            # 本仓根目录

# 0) 依赖（Debian 13）
sudo apt-get install -y coturn                 # turnserver + turnutils_stunclient
cargo install cargo-fuzz                       # + rustup toolchain install nightly

# 1) 全矩阵（除 fuzz/ci）
bash script/lab/rstun-interop.sh all

# 2) 单项
bash script/lab/rstun-interop.sh probe
bash script/lab/rstun-interop.sh pion
bash script/lab/rstun-interop.sh webrtc-stun
bash script/lab/rstun-interop.sh coturn
bash script/lab/rstun-interop.sh stun-types
bash script/lab/rstun-interop.sh rfc5769

# 3) fuzz 10 分钟
bash script/lab/rstun-interop.sh fuzz --fuzz-seconds 600
#   或直接：cd rstun/fuzz && cargo +nightly fuzz run parse -- -max_total_time=600

# 4) CI 本地等价
bash script/lab/rstun-interop.sh ci

# 5) 日志
ls /tmp/opencode/rstun-interop/logs
```

## 13. 协议闭环新增项（`fingerprint` / `fingerprint-drop` / `alternate`）

`item_probe` 起 7 个实例（主 / mapped / RFC 5780 双 IP / IPv6 / `--alternate-server` /
`--check-fingerprint` / `--check-fingerprint --fingerprint-action drop`），新增 3 项子用例。
判据都是**外部可观察行为**（响应字节、错误码、是否静默），不依赖服务端内部状态。

| 子用例 | 配置 | 断言 | 结论 |
| --- | --- | --- | --- |
| `probe/fingerprint` | `--check-fingerprint` | 合法 FINGERPRINT（CRC 由 python `zlib.crc32` 独立算出）→ 普通 200；错一位 → `400 Bad Request`；`FINGERPRINT` 后跟 `PADDING` → `400` | ✅ |
| `probe/fingerprint-drop` | `--check-fingerprint --fingerprint-action drop` | 错值 → 0 响应（0.3 s 静默）；随后合法请求仍得到 200（服务未被拖死） | ✅ |
| `probe/alternate` | `--alternate-server 192.0.2.9:3478` | 响应类型 `0x0111`、`ERROR-CODE 300 Try Alternate`、`ALTERNATE-SERVER = 192.0.2.9:3478`、**不带** `XOR-MAPPED-ADDRESS`；带 `CHANGE-REQUEST 0x02` 时仍从入口 socket 回（重定向优先） | ✅ |

原始输出（`$RSTUN_INTEROP_DIR/logs/probe-*.log`）：

```
# probe/fingerprint
ok: 响应类型 0x0101 = 0x0101
ok: transaction id 原样回显
ok: 合法 FINGERPRINT 得到普通 Binding 响应
ok: 错值 FINGERPRINT → 400 Bad Request
ok: FINGERPRINT 不在末位 → 400 Bad Request

# probe/fingerprint-drop
ok: drop 模式对错值 FINGERPRINT 静默（无响应）
ok: 响应类型 0x0101 = 0x0101
ok: transaction id 原样回显
ok: drop 模式之后合法 FINGERPRINT 仍得到 200

# probe/alternate
ok: 响应类型 = 0x0111（错误响应）
ok: ERROR-CODE = 300 Try Alternate
ok: 带 ALTERNATE-SERVER
ok: ALTERNATE-SERVER = 192.0.2.9:3478
ok: 300 不带 XOR-MAPPED-ADDRESS（它是指令，不是映射答案）
ok: 300 仍从入口 socket 回（重定向优先于 CHANGE-REQUEST）
```

> 500 不在探针里：它只在「发送失败」时出现，正常路径不可达。覆盖由
> `server_error_for` 的映射表 + Linux 上 `RESPONSE-PORT 0` 的真实 `send_to` 失败 e2e 提供
> （`cargo test`，见 README「协议闭环」）。
