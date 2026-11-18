# 发布前清单

> 详细契约见 [`../backend/release-artifacts.md`](../backend/release-artifacts.md)。本页只列「别忘了几件事」。

## 发版前

- [ ] `version` 输入与 `Cargo.toml` 的 `version` 一致
- [ ] 是**重发**吗？tag 不会自动移动 —— 确认 tag ↔ 资产 ↔ digest 指向同一 commit
- [ ] 报给下游的是 **manifest list digest**（amd64+arm64），不是单架构
- [ ] 拉镜像的机器有凭证吗（新包默认 private）

## 发布后

- [ ] 从 Release 实际下载 → `test -x ./rstun` → `./rstun --version` 与预期一致
- [ ] `docker buildx imagetools inspect` 含两个架构
- [ ] 冒烟：`bash script/ci/rstun-smoke.sh 127.0.0.1:<端口> --tcp`
- [ ] 结果（tag / digest / 已知局限）写进任务 `research/`

## 改协议或响应字节前

- [ ] 读 `implement.md` 的 T0 条款（420 的 2N value、RESPONSE-PORT 目的端口、PADDING 回显）
- [ ] 跑 `cargo test`（含 RFC 5769 向量与 stun-types 交叉解码）
- [ ] 跑互操作矩阵（coturn / pion / webrtc-rs），失败项必须判定「我方/对手/RFC 理解」
