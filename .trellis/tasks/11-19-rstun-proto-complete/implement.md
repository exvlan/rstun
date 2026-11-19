# 执行计划：协议闭环

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | `crc32.rs`（IEEE 查表，无依赖）+ RFC 5769 §2.1 向量单测 | 向量逐字节匹配 | 单文件 |
| 2 | FINGERPRINT 解析：末位判定 + 重算 Length + 校验；`--check-fingerprint` 与 `--fingerprint-action=answer|drop` | 单测：合法/非末位/错值；e2e 三态 | 小 commit |
| 3 | `ALTERNATE-SERVER` 编码（family/port/address）+ `--alternate-server`；300 响应 | 单测编码字节；e2e 300 + `stun-types` 解码 | 小 commit |
| 4 | `error_response(500)` + `server_error_for(&io::Error)` 映射；接入 UDP/TCP 的编码/发送失败路径 | 单测映射表；e2e 非法目标触发（或纯函数覆盖） | 小 commit |
| 5 | RFC 8489 属性语义明确化（未开鉴权：忽略）+ README「支持子集」表 | 文档评审；`is_known_attribute` 不变 | 文档 commit |
| 6 | 错误码矩阵写入 README（300/400/420/438/500） | 人工评审 + 与实现对照 | 同上 |
| 7 | 互操作：`tests_interop` 增加 300/500 解码用例；`rstun-interop.sh` 增加一组「alternate-server」探测（可选） | 矩阵仍 38 项全绿 + 新用例 | 小 commit |
| 8 | 全量门禁 + 默认路径字节对照（33 请求 × 3 配置）| 与 `26.410.100` 逐字节一致 | — |

## 门禁

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all          # 38 项
bash script/lab/rstun-abuse.sh                # 10 组（反射防护不受影响）
cargo tree -e normal --depth 1                # 仍 5 个
```

外加默认路径对照：用 `git archive HEAD` 旧二进制与新版各跑 33 请求 × 3 配置，逐字节比较（沿用 abuse-guard 的方法）。

## 验收断言（必须）

- [ ] `--check-fingerprint` + 合法指纹 → 正常 200；错值 → 400；非末位 → 400；`drop` 模式 → 无响应且计数
- [ ] 默认关闭时：带 FINGERPRINT 的请求仍被正常应答（字节与 `26.410.100` 一致）
- [ ] `--alternate-server` → 300 + `ALTERNATE-SERVER` 可被 `stun-types` 解出正确地址
- [ ] 未配置该开关时零监听变化、零字节变化
- [ ] 500：`server_error_for` 单测覆盖 `ConnectionRefused/NetworkUnreachable` 不映射、其余映射；响应 40 字节且不含内部信息
- [ ] 错误码矩阵与实现一致（文档评审）

## 风险

| R | 缓解 |
| --- | --- |
| FINGERPRINT 重算 Length 出错导致全部 400 | 用 RFC 5769 向量 + 三个 e2e 态锁死；默认关闭 |
| 500 泄露内部信息 | 固定文案；error 只进日志 |
| 300 与 RFC 5780 语义冲突 | 明确「重定向优先」，文档与本任务验收各写一条 |

## 回滚

- 单批 commit；两个开关关闭即恢复默认路径；无状态迁移。
