# 生产已切 26.410.102 + RAF 复验（对端回报，2026-11-21）

> 来源：EXVlan 会话（`ses_eda8…9mnS`）`[handoff] DONE`，线程 `t_mwprgj1z_gxno` / `t_mwprhq0f_w4b0`。

## 生产状态

| 项 | 值 |
| --- | --- |
| 版本 | `rstun 26.410.102+e0a16c` |
| 镜像 digest | `sha256:62c766adb88d405a33134ac85f3d364122df72c79aaf9cf89e12502d25a6d66d`（**最终值**，不做二次切换）|
| 变更范围 | 仅重建 `exvlan` Pod；12 listeners；TLS1.3 / DTLS1.2 就绪 |

## RAF 复验（对端执行）

| 用例 | 结果 |
| --- | --- |
| `-S -y` | 20/20、0 丢包（与 26.410.101 一致）|
| `-S -e` / `-S -X`（IPv4，隐含 RAF）| **不再 420**，Allocate 成功 |
| `-S -x`（请求 IPv6）| **440 Address Family not Supported** ✅ |
| `-S -g`（DONT-FRAGMENT）| 420（不变，合规）|
| aioice TLS Allocate | relay `10.254.66.5:40001` ✅ |

> 对端 `-e/-X` 的「数据面 100% 丢包」是**测试构造**问题（peer 指向服务器自身 3478、无回显），
> 不是 relay 缺陷：我方 lab 的 `raf` 项用真实 echo peer 跑同一命令为 **0 丢包**。

## 对端文档

- `docs/rules/workflow/upstream-debt.md` **P-014 已按版本表述定稿**：
  截至 `26.410.102`，`-g` 回 420；注明「后续补丁版拟在 unix 真支持 DF → 可中继，Windows 仍 420」，
  等新版本发布后按我方版本号与措辞更新；
- IPv6 relay 真实中继：双方一致**不做承诺**（我方只补自动化回归，见 `rstun-turn-df-ipv6`）。

## 我方待办

1. `rstun-turn-df-ipv6` 完成后：冷复核 → 提交 → 由用户决定发版（预计 `26.410.103`）。
2. 发版后把 **DF 的最终措辞 + 版本号 + 新 digest** 发给对端，供其更新 P-014。
