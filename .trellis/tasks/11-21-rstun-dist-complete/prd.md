# 分发补全：Homebrew tap + `.deb` 产物

## 背景

`dist` 任务（已归档）把 brew formula 与 deb 打包**脚本**做完了，但两项外部落地一直标着「发布时人工执行」，
到今天仍未真正可用：

| 项 | 现状 | 后果 |
| --- | --- | --- |
| Homebrew tap | 仓 `exvlan/homebrew-rstun` **不存在**；`rstun.rb` 只在 Release 资产里 | `brew install exvlan/rstun/rstun` 不可用；用户只能 `brew install ./rstun.rb` 且无法随版本升级 |
| Debian `.deb` | Release **没有任何 `.deb`**；`script/ci/build-deb.sh` 可用但没人跑 | 文档写了 deb 安装路径却没有产物 |

用户已确认（本次会话）：**两项都补**。

## Goal

让 README/quickstart 里写的四条安装路径（cargo / brew / deb / docker）**每条都真的能用**，
并让后续版本自动产出 deb。

## 范围

### A. Homebrew tap

- 建 `exvlan/homebrew-rstun`（public），写入 `Formula/rstun.rb`（= 当前 Release 资产里的 `rstun.rb`）
  与最小 `README.md`（安装/升级/卸载三行）。
- formula 内容**不手工改**：用 Release 里 workflow 生成的 `rstun.rb`（sha256 已对齐已发布 zip）。
- 验证：`ruby -c` 语法；formula 里的 `url` 指向 `rstun-v26.410.102` 的三个 lean zip，
  sha256 与 Release 资产实际值一致（逐条比对）。

### B. `.deb` 产物

- 为 `26.410.102` 生成 **amd64 + arm64** 两个 lean `.deb` 并挂到现有 Release。
  二进制来源：**已发布 Release 里的 lean zip**（解包即用，保证包内二进制与 zip 完全一致，不重新编译）。
- `release.yml` 以后自动产出：在 Linux 构建作业里（已有 lean 二进制）增加 deb 打包 + artifact 上传；
  `Publish Release` 作业下载并一起上传。
- Release 资产数从 **11 → 13**，并更新断言、release notes、spec。

### C. 文档

- `README.md` 安装表 / `docs/book/src/quickstart.md`：brew 改成 `brew install exvlan/rstun/rstun`；
  deb 改成 `dpkg -i rstun_<version>_amd64.deb`（附下载地址）。
- `.trellis/spec/backend/release-artifacts.md`：资产数 13、deb 契约、tap 同步约定。

## 非目标

- 不做 full（tls/dtls）的 deb/brew —— 维持「包管理器只有 lean」的既有决定。
- 不做 cosign/sigstore 签名（仍是后置项）。
- 不改版本号、不发新 Release（只在现有 `rstun-v26.410.102` 上补 deb 资产）。
- 不重跑 release workflow（避免镜像 digest 再次变化、让对端手里的 digest 失效）。

## 约束（硬）

- **不移动 tag**、不改 release 标题/说明（补资产用 `--clobber`）。
- deb 内二进制必须与已发布 zip **同源**（sha256 比对）。
- tap 仓只能由本仓 owner 写；本次已获用户口头批准，执行时记录到 `implement.md`。
- 任何外部写操作失败 → 停止并报告，不重试、不换歪招。

## 验收

- [ ] `gh repo view exvlan/homebrew-rstun` 可见（public），`Formula/rstun.rb` 与 Release 的 `rstun.rb` 内容一致
- [ ] formula 三个 `sha256` 与 Release 对应 zip 的 `sha256sum` 一致
- [ ] `ruby -c` → `Syntax OK`
- [ ] Release `rstun-v26.410.102` 资产 **13**（8 zip + 2 SBOM + 1 rb + **2 deb**）
- [ ] `dpkg-deb -c` 显示 `/usr/local/bin/rstun` 与 unit 文件；`dpkg-deb -I` 架构/版本正确
- [ ] deb 内 `rstun --version` 与 Release 同串（解包执行验证）
- [ ] `release.yml` 语法通过，且下次发布能自动产出 2 个 deb（静态检查 + 本地跑通 build-deb.sh）
- [ ] 文档四条安装路径均可照抄执行
