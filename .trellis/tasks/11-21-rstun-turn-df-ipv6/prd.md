# TURN：DONT-FRAGMENT（0x001A）真实现 + IPv6 relay 回归

## 背景

- `DONT-FRAGMENT` 目前按「未知 comprehension-required」回 `420`。RFC 8656 §7.2 步骤 4 允许
  「不支持 DF 位」的服务器这样做，所以不算偏差；但 coturn 支持它，MTU 发现类客户端会先带 DF 探测能力。
- IPv6 relay 路径（IPv6 监听 + IPv6 客户端 → IPv6 relay）**无任何自动化回归**：
  `docs/book/src/turn.md` 已注明，lab 的 `raf -x` 只验证「IPv4 客户端请求 IPv6 → 440」。

用户已确认：**新增 `libc` 直接依赖（unix-only）真支持 DF**；IPv6 relay 回归一并补上。

## RFC 依据（RFC 8656）

- §18.9：`DONT-FRAGMENT` 无值部分（length = 0）；用于**请求服务器在向 peer 转发数据时置 DF 位**，
  并在 Allocate 里用于**探测服务器能力**。
- §7.2 步骤 4：服务器不支持 DF 时，把该属性当作未知 comprehension-required（→ `420`）。
- §3.7：客户端可在 `Send indication` 里带 DF，表示**该报文**置 DF。
- §1306 附近：客户端若想后续在 Send indication 用 DF，应先在 Allocate 里带 DF 探测。

## 需求

1. **Allocate**：带 `DONT-FRAGMENT` → 不再 420；为该 allocation 的 relay socket 置 DF；
   该属性 length ≠ 0 → `400`；置位失败（setsockopt 报错）→ `500 Server Error` 并计数。
2. **Send indication**：带 DF → 仅该报文置 DF（发送后恢复原值）；length ≠ 0 → 忽略该属性并照常转发
   （indication 无错误响应；RFC 未定义错误路径），但计一次畸形计数（若已有计数可用）。
3. **平台**：`cfg(unix)` 支持（Linux `IP_MTU_DISCOVER = IP_PMTUDISC_DO`、macOS `IP_DONTFRAG`）；
   **Windows 保持 420**（无 libc；RFC 允许），文档注明。
4. **IPv6 relay 回归**：lab 新增一项——服务器监听 `[::1]`、客户端走 IPv6、peer 也走 IPv6，
   断言 Allocate 成功、`XOR-RELAYED-ADDRESS` 是 IPv6、`Send`/`Data` 双向都有字节。
5. 默认路径（不带 DF）字节不变；依赖面 9→**10**（lean）/ 13→**14**（full）并在 README 写明。

## 非目标

- 不做 IPv4↔IPv6 地址转换（RFC §3.7 里「跨族且无法读取 DF 位」的情形不适用）；
- 不改 RAF/EVEN-PORT/TOKEN 的既有行为；
- 不做 RFC 6062；
- 不发版（版本号与 CHANGELOG 版本由主会话另行决定）。

## 约束

- 新增依赖只能是 `[target.'cfg(unix)'.dependencies] libc = "0.2"`；不得引入 `nix`/`rustix`。
- `cargo audit` / `cargo deny` 不得退化；`libc` 的安全公告需逐条登记。
- 默认路径字节冻结（3 配置 × 17 请求，基线 `cad4fa2`）必须保持；
- Windows 构建必须仍能编译（`#[cfg(unix)]` 分支外不得引用 libc）。

## 验收

- [ ] `uclient -g`（DONT-FRAGMENT）从 `420` 变为**可中继**，且 lab 能证明 DF 位真的置上
      （`tcpdump -i lo -vv 'udp and port <relay>'` 显示 `flags [DF]`，或 `getsockopt` 回读）
- [ ] DF 属性 length ≠ 0 → `400`（单测）
- [ ] Windows 口径：仍 420（文档 + `cfg` 断言；CI 的 windows 作业编译通过）
- [ ] IPv6 relay：lab 新增 `ipv6relay` 项全绿（分配 + 双向数据）
- [ ] 默认路径冻结不变；`cargo test`（lean/full）、clippy、fmt、interop、abuse、turn、audit、deny 全绿
- [ ] 依赖面 10/14，README/spec/CHANGELOG(Unreleased) 同步
