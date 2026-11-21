# 设计：DONT-FRAGMENT + IPv6 relay 回归

## 1. 依赖

```toml
# DF 位需要在 relay socket 上调 setsockopt：socket2 0.6 没有 MTU-discover/DF API，
# 直接依赖 libc（unix-only）。Windows 没有 libc，DF 保持 420（RFC 8656 §7.2 步骤 4 允许）。
[target.'cfg(unix)'.dependencies]
libc = "0.2"
```

影响：`cargo tree -e normal --depth 1` 在 unix 上 9 → 10（lean）/ 13 → 14（full）；
`README`「依赖面」表与 `CHANGELOG` 都要改。`libc` 已是传递依赖，无新增 crate 风险。

## 2. 能力探测与解析

```rust
/// DF 是否真的可用：unix 上编译期确定；Windows 走 420 兼容路径。
const DONT_FRAGMENT_SUPPORTED: bool =
    cfg!(any(target_os = "linux", target_os = "macos", target_os = "ios"));
```

- `turn_unknown_attributes()`：仅当 `DONT_FRAGMENT_SUPPORTED` 时把 `0x001A` 视为已知，
  否则保持现状（Windows → 420）。
- `parse_dont_fragment(body) -> Result<bool, ()>`：缺失 → `Ok(false)`；存在且 length == 0 → `Ok(true)`；
  存在但 length ≠ 0 → `Err(())`。

## 3. 置位实现（`src/turn.rs`）

```rust
#[cfg(unix)]
fn set_dont_fragment(socket: &UdpSocket, on: bool) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    #[cfg(target_os = "linux")]
    let (level, name) = (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER);
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let (level, name) = (libc::IPPROTO_IP, libc::IP_DONTFRAG);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
    {
        let _ = (fd, on);
        return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
    }
    #[cfg(target_os = "linux")]
    let value: libc::c_int = if on { libc::IP_PMTUDISC_DO } else { libc::IP_PMTUDISC_WANT };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let value: libc::c_int = i32::from(on);
    // SAFETY: fd 由 socket 持有且存活；setsockopt 只读 value 的 4 字节。
    let rc = unsafe {
        libc::setsockopt(fd, level, name, &value as *const _ as *const libc::c_void,
                         std::mem::size_of_val(&value) as libc::socklen_t)
    };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}
```

要点：
- relay socket 是 tokio `UdpSocket`；`as_raw_fd` 在 unix 可用。
- **Allocate 带 DF**：在 relay socket 绑定后调用一次 `set_dont_fragment(&relay, true)`；
  失败 → 关闭 socket、`500 Server Error`、计入一个计数器（复用 `rejected_family`? 不合适 → 新增
  `rejected_df` 或复用 `rejected_ports`？建议新增最小计数并入 `/metrics` 的
  `rstun_turn_rejected_total{reason="df"}`，需同步 ops 与文档）。
- **Send indication 带 DF**：若 allocation 未开 DF，则 `set(true)` → 发送 → `set(false)`；
  **置位失败 → 丢弃该 indication**（RFC 8656 §11.2 要求「按未知 comprehension-required 处理」，
  即不转发），计 `rejected_df` 并记日志。若 allocation 已开 DF，无需切换。

## 4. IPv6 relay 回归

- 扩展 `script/lab/rstun-turn-probe.py`：加 `--family inet|inet6`（默认 inet），
  所有 `socket.socket(AF_INET…)` / `bind(("127.0.0.1",0))` 走参数化；`XOR-RELAYED-ADDRESS`
  解析已支持 v6（`src/turn.rs` 有 v6 编码）——探针需按 family 断言。
- `script/lab/rstun-turn.sh` 新增 `ipv6relay` 项：
  1. 起服务 `--listen-v6 "[::1]:$BASE"` + `--turn`（relay 跟随客户端 → IPv6）；
  2. 探针 IPv6：challenge → Allocate（断言 relay 是 `::1`）→ CreatePermission(::1 peer) →
     Send/Data 双向；
  3. 断言：`relay` 为 IPv6、`bytes in/out > 0`；
  4. 无 IPv6 的机器（`/proc/sys/net/ipv6` 缺失或 bind 失败）→ `skip` 并说明（不判失败）。
- CI 的 ubuntu runner 支持 `::1`；macOS/Windows 的 lean 作业不跑 lab，无影响。

## 5. 兼容与冻结

- 不带 DF 的请求：路径不变（`DONT_FRAGMENT_SUPPORTED` 只影响 0x001A 的 known 判定）。
- 带 DF 的请求：由 420 → 200（unix）+ socket 置位。
- `plain_response_bytes_are_frozen` 与 3×17 冻结对照不变。

## 6. 测试

单测（`src/turn/tests.rs`）：
| 用例 | 断言 |
| --- | --- |
| DF length 0 + unix | Allocate `200`；allocation 标记 DF |
| DF length ≠ 0 | `400` |
| `turn_unknown_attributes` | unix：0x001A 不再 unknown；`cfg!(not(unix))` 下仍 unknown |
| `set_dont_fragment` 回读（unix） | 创建 UDP socket → 置 true → `getsockopt` 回读为 DO；置 false → 回读为 WANT |
| Send indication 带 DF（allocation 未开） | 转发成功、DF 已恢复（回读 WANT）|

lab：`df`（`uclient -g` 中继 + `tcpdump` 断言 DF 位，缺 tcpdump/权限时 skip）、`ipv6relay`（上述）。

## 7. 文档 / spec / 度量

- `docs/book/src/turn.md`：行为表 DF 行改成「unix 支持、Windows 420」；「不支持」列表移除 DF（保留 TCP allocation）；
- `src/turn.rs` 头注释；
- `.trellis/spec/backend/turn.md`：DF 契约 + 测试项；
- `README` 依赖面 9/13 → 10/14（并说明 libc 用于 DF）；
- `CHANGELOG` `## Unreleased`；`/metrics` 若新增 `reason="df"` 需同步 `docs/book` 指标表与 `check-docs`。

## 8. 回滚

单 commit（或两个：DF / IPv6 lab）；revert 即回到 420 + 无 libc。不发版，无产物回滚。

## 9. 风险

| R | 缓解 |
| --- | --- |
| libc setsockopt 在非 Linux unix 上常量不同 | 按 `target_os` 分支；CI 的 macOS 作业编译 + 单测覆盖 |
| Send indication 逐包切换有并发竞争 | 同一 allocation 的 relay 发送在单一任务内串行；文档注明 |
| `lo` 上 tcpdump 需要权限 | lab 缺权限时 skip，并以 `getsockopt` 回读作为替代证据 |
| IPv6 在部分环境不可用 | `ipv6relay` 项 skip 而非 fail，但 `docs` 注明未覆盖时不算通过 |
