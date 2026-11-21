# 生产已切 26.410.101 + TURN TLS/DTLS 复验（对端回报，2026-11-21）

> 来源：EXVlan 会话（`ses_eda8…9mnS`）两条 `[handoff] DONE`，线程
> `t_mwpokpn5_h2oc` / `t_mwpolby4_wt4v`。我方只做记录，不代其对生产负责。

## 生产状态

| 项 | 值 |
| --- | --- |
| 版本 | `rstun 26.410.101+9daa31` |
| 镜像 digest | `sha256:78c0d07581a74c650dedb518347aa92079ed0063825d72c40e6fb52e0835ae17` |
| 变更范围 | 仅重建 `exvlan` Pod（参数未变）|

## 复验证据（对端执行）

- TLS 1.3 握手 `verify=0`
- `turnutils_uclient -S -y -n 5 -m 2`：Allocate 通，**20/20 包、0 丢包**
- DTLS 1.2 握手 `openssl s_client -dtls1_2` `verify=0`
- STUN：`43.98.203.136` / `8.219.211.50` 均返回 `0x0111`

## RAF / DF 立场（对端定稿）

- **不需要 IPv6 relay**（双栈分配）——只要错误码语义正确；
- 接受我方最小实现口径：RAF 解析后 IPv6 请求回 `440`；
- `DONT-FRAGMENT` 维持 `420` 符合 RFC（8656 §7.2 步骤 4），不需改；
- 对端已把「26.410.101 现状（RAF 回 420 = 已知偏差、DF = 合规）+ 验证口径 `-S -y`」写进
  其仓 `docs/rules/workflow/upstream-debt.md` **P-014**；
- **待我方 RAF 合入后**，对端会把 P-014 改成「DTLS 可用 / Allocate 仅 IPv4
  （RAF 已支持，IPv6 请求回 440）」，需要我方给**最终措辞 + 版本号**。

## 我方待办

1. `rstun-turn-raf` 合入 main（行为变化，默认路径字节不变）；
2. 发版时确认承载版本（预计 `26.410.102`）与 digest，连同措辞一起发给对端；
3. 发版后对端再复验 `-S -e`（隐含 RAF）应从 420 变为成功。
