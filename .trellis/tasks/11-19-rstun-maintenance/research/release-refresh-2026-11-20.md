# Release 重发与资产补齐（2026-11-21）

## 结论

`rstun-v26.410.100` 已按 dist/T2 的新构建矩阵**重发**（run [44784643952](https://github.com/exvlan/rstun/actions/runs/44784643952)），
11/11 作业全绿，Release 资产从 7 补到 **11**。

| 项 | 值 |
| --- | --- |
| tag | `rstun-v26.410.100`（未移动）|
| 资产 | 8 zip（`rstun-{linux-x86_64,linux-aarch64,macos-x86_64,windows-x86_64}` + `rstun-full-` 同四平台）+ 2 × `.cdx.json` + `rstun.rb` |
| 镜像 tag | `ghcr.io/exvlan/rstun:26.410.100`（amd64+arm64，full 构建）|
| **新 manifest digest** | `sha256:bafa4f17257b37d05e6d5615d9cbd4f46105ac610473607ca10329926657b663` |
| 旧 digest（生产现用）| `sha256:9d7382c619efe6b21d5b672c7811715b562bf6051b5d0f9ba4ee979f508df0bd` |

> 生产按 **digest 固定**，因此 tag 指向变化不影响生产；如需跟进新构建，按新 digest 切换。

## 重发过程中修掉的两个 CI 缺陷

1. **musl + ring**：full 构建的 `ring` 含 C 代码，musl 目标需要 `musl-gcc`；release 作业原先没有装 → `cc-rs: failed to find x86_64-linux-musl-gcc`。
   修复：Linux musl 作业 `apt-get install musl-tools` + `CC_<triple>=musl-gcc`（`02f1de2`）。
2. **pipefail + grep -q**：TLS 冒烟 `openssl s_client … | grep -q` 在 `pipefail` 下因 SIGPIPE 假红。
   修复：先落盘再 `grep -a`（`46c1ad5`）。

## 核对

- 资产数 = 11（`gh release view --json assets`）。
- `rstun.rb` 的三个 sha256 与重发后的 zip 一致（workflow 自动重生成）。
- full/lean 行为区分：full 下 `--turn-tls-listen` 进入证书解析；lean 下报 `need a build with the tls feature`。
- 版本串：两者均 `26.410.100+46c1ad`（同一提交）。
