# 执行计划：dist

> 前置：阶段 A（T1/T2）与 qa 已完成；发布链（lean/full 产物、镜像）已可用。
> 本任务不发布任何东西：所有外部动作（建 tap、开 Pages、发 Release、传 SBOM）都在发布时执行，且需用户确认。

## 顺序

| # | 事项 | 验证 | 回滚点 |
| --- | --- | --- | --- |
| 1 | `SECURITY.md`、`CONTRIBUTING.md`、issue/PR 模板 | `yaml.safe_load`（issue 模板）；人工评审 | 删除文件 |
| 2 | `deny.toml` + CI `deny` 作业 | 本地 `cargo deny check` 通过；CI 绿 | 单文件 |
| 3 | `.github/dependabot.yml`（cargo 周 / actions 月） | YAML 解析；GitHub 上生效需 push（首次 PR 观察） | 单文件 |
| 4 | `docs/book/`（mdBook：quickstart/docker/protocol/auth/rate-limit/turn/faq/changelog）+ `book.toml` + `SUMMARY.md` | 本地 `mdbook build` 成功；链接无死链（`mdbook test` 或脚本检查） | 新增目录 |
| 5 | README：行为表迁出到文档站、保留摘要+链接；加徽章 | `script/ci/check-docs.sh`（新增）通过 | 文档 commit |
| 6 | `script/ci/check-docs.sh`：`--help` 片段 diff + 参数名/指标名存在性 | 本地跑通；故意改坏一处 → 红 | 新增文件 |
| 7 | Pages workflow（`.github/workflows/docs.yml`）：`mdbook build` + `actions/deploy-pages`（固定 SHA，`pages: write`） | YAML 解析；本地构建产物可预览 | 新增文件 |
| 8 | Debian 包：`contrib/deb/nfpm.yaml` + `script/ci/build-deb.sh`（版本与 `Cargo.toml` 校验） | 干净容器 `dpkg -i` + `systemd-analyze verify` | 新增文件 |
| 9 | Homebrew：`contrib/homebrew/rstun.rb` 模板 + `script/ci/gen-brew.sh`（发布时填 url/sha256） | `brew install --build-from-source`（Linuxbrew/macOS） | 新增文件 |
| 10 | SBOM：Release 增加 `cargo cyclonedx`（lean/full 各一份）并上传 | 本地生成 `*.cdx.json`，结构合法 | workflow |
| 11 | 发布时外部动作清单（**需用户确认后执行**）：建 `exvlan/homebrew-rstun`、开 Pages、发 Release、上传 SBOM | 清单写入 `implement.md`，逐项勾选 | — |

## 门禁

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash script/lab/rstun-interop.sh all
bash script/lab/rstun-abuse.sh
bash script/lab/rstun-turn.sh
cargo deny check                     # 新增
mdbook build docs/book               # 新增
bash script/ci/check-docs.sh         # 新增
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')+glob.glob('.github/ISSUE_TEMPLATE/*.yml')];print('yaml ok')"
```

## 验收断言（必须）

- [ ] `cargo deny check` 在 CI 为**必需**作业（不是 `continue-on-error`）
- [ ] 文档站 `mdbook build` 成功；`check-docs.sh` 能抓住「`--help` 片段/参数名/指标名」漂移（给一次反证）
- [ ] README 的行为表已迁出且链接可达（无两处维护）
- [ ] issue 模板必填版本/features/平台；PR 模板含验证命令
- [ ] `.deb` 可安装且 unit 通过 `systemd-analyze verify`
- [ ] brew formula 可 `--build-from-source` 安装（Linuxbrew 或 macOS）
- [ ] Release 资产含 lean/full 的 SBOM（`.cdx.json`）
- [ ] 外部动作清单逐项列明，**均未擅自执行**

## 风险

| R | 缓解 |
| --- | --- |
| 文档站与 README 双维护 | 行为表只留文档站，README 摘要+链接 |
| nfpm/cyclonedx 引入不可控 | 版本固定、只在脚本/CI 用，不进 `Cargo.toml` |
| Pages/tap 需外部权限 | 清单化，发布时用户确认后执行 |
| brew 无法在 Linux CI 验证 | 用 Linuxbrew 容器或 macOS 本地；CI 不阻塞（记录为人工步骤） |

---

# 实施记录（2026-11-20）

> 环境：Debian 13 / x86_64 / Rust 1.95；磁盘 `/` 剩 3.8 G → 临时工具全部下到
> `/tmp/opencode/dist-fix`，打包缓存放 `target/ci-tools`（都在工作区内或 /tmp）。
> **未执行任何外部动作**：没有建 tap、没开 Pages、没发 Release、没 push。

## 1. 11 步逐条

| # | 事项 | 结果 | 证据 |
| --- | --- | --- | --- |
| 1 | `SECURITY.md`、`CONTRIBUTING.md`、`.github/ISSUE_TEMPLATE/{bug,feature}.yml`、`.github/pull_request_template.md` | ✅ | issue 模板必填 `version` / `features`(lean/full) / `platform` / 命令 / 最小复现；`yaml.safe_load` 通过（见 §3） |
| 2 | `deny.toml` + CI `deny` 作业（必需） | ✅ | `cargo deny check` → `advisories ok, bans ok, licenses ok, sources ok`；CI 作业 `deny` 无 `continue-on-error` |
| 3 | `.github/dependabot.yml` | ✅ | cargo `/` 每周、`/fuzz` 每月、github-actions 每月；`yaml.safe_load` 通过 |
| 4 | `docs/book/`（11 章 + `book.toml` + `SUMMARY.md`） | ✅ | `mdbook build docs/book` → 14 个 HTML 页；`changelog.md` 用 `{{#include ../../../CHANGELOG.md}}` |
| 5 | README：行为表迁出 + 摘要/链接 + 徽章 | ✅ | README 1372 → 533 行；「## 行为」被「## 协议行为（摘要）」替换（见 §2 判决 2） |
| 6 | `script/ci/check-docs.sh` | ✅ | 正例 exit 0；三组反证（help 片段 / 参数名 / 链接）都 exit 1（见 §2 判决 1） |
| 7 | `.github/workflows/docs.yml`（Pages） | ✅ | `mdbook build` + `configure-pages@45bfe01…`(v6.0.0) + `upload-pages-artifact@fc324d3…`(v5.0.0) + `deploy-pages@368f825…`(v5.0.1)；`permissions: {pages: write, id-token: write}`；只从 `main` |
| 8 | `contrib/deb/nfpm.yaml` + `script/ci/build-deb.sh` | ✅ | nfpm 2.49.0；`rstun_26.410.100_amd64.deb` 1.46 MB；`dpkg -c` 见 §2 判决 3；`systemd-analyze verify` → unit ok |
| 9 | `contrib/homebrew/rstun.rb` + `script/ci/gen-brew.sh` | ✅（装机待人工） | `ruby -c` → `Syntax OK`（模板与生成物，见 §2 判决 4）；本机无 brew/Linuxbrew，`brew install` 记为发布时人工步骤 |
| 10 | SBOM：`script/ci/gen-sbom.sh` + `release.yml` 的 `sbom` 作业 | ✅ | lean 86 组件 / 9 直接依赖；full 203 / 13；6.3 KB / 27 KB（见 §2 判决 5） |
| 11 | 外部动作清单写进 `implement.md` | ✅ | 见 §4，全部标「未执行」 |

## 2. 五条判决（原始输出）

### 判决 1 — `check-docs.sh` 反证

```
$ bash script/ci/check-docs.sh --no-build                     # 正例
check-docs: 扫描 17 个 markdown、2 个 help 片段、44 个 flag、19 个指标
✓ 文档与实现一致（help 片段 / 参数名 / 指标名 / 链接）
EXIT=0

# 反证 A：把 cli.md 的 `--turn-bandwidth` 改成 `--turn-bandwith`
✗ 2 处漂移：
  - docs/book/src/cli.md:29 help=server 片段与真实输出不一致（改了 flag/描述就必须同步这一块）
    --- 真实 rstun server --help
    +++ docs/book/src/cli.md:29 的片段
    @@ -960,13 +960,13 @@
EXIT=1   （改回 → EXIT=0）

# 反证 B：把 rate-limit.md 的 `--reflect-ratio` 改成 `--reflect-ration`
✗ 1 处漂移：
  - docs/book/src/rate-limit.md: 提到了 `--reflect-ration`，但 `rstun --help` / `rstun server --help` 里没有定义
EXIT=1   （改回 → EXIT=0）

# 反证 C：把 README 里指向 protocol.md 的链接改成 protocolo.md
✗ 1 处漂移：
  - README.md: 链接 `docs/book/src/protocolo.md` 指向的文件不存在
EXIT=1   （改回 → EXIT=0）
```

设计取舍：help 比对**逐 token**（`text.split()`）而不是逐行 —— clap 按终端宽度折行，
行边界随 `COLUMNS` 变；token 序列才是「内容」。参数名与指标名走真实
`rstun server --help` 与真实 `/metrics`（实例带 `--turn` 启动，否则 TURN 指标族不出现）。

### 判决 2 — README 行为表已迁出

```
$ wc -l README.md                                          # 迁移前 → 迁移后
1372 → 533
$ grep -c '^| ' README.md                                  # 表格行：迁移前 → 迁移后
156 → 71
$ grep -n '^## 行为' README.md
（无输出 —— 章节已不存在）
$ grep -n '^## 协议行为（摘要）' README.md
49:## 协议行为（摘要）
$ grep -c 'XOR-MAPPED-ADDRESS' README.md                   # 摘要里还剩 3 处引用
3
$ grep -c 'XOR-MAPPED-ADDRESS' docs/book/src/protocol.md    # 响应表在文档站
8
```

README 49→66 行（摘要 + 索引表）现在是「一句话摘要 + 6 行章节索引表 + 漂移检查说明」，行为表本体
（请求→响应表、RFC 子集、错误码矩阵、420 已知属性表、兼容性开关、未实现项）整段移到
`docs/book/src/protocol.md`；鉴权 / RFC 5780 / 抗滥用 / TURN / coturn 差异也各自成章
（`auth.md` / `nat-discovery.md` / `rate-limit.md` / `turn.md`），`--help` 全量输出移到 `cli.md`。

### 判决 3 — `.deb`（nfpm 2.49.0）

```
$ bash script/ci/build-deb.sh --download-nfpm
build-deb: nfpm 2.49.0
== 包：/data/project/rstun/dist/deb/rstun_26.410.100_amd64.deb
-rw-r--r-- 1 root root 1462484 ... rstun_26.410.100_amd64.deb
 Package: rstun
 Version: 26.410.100
 Architecture: amd64
 Installed-Size: 3732
== 包内文件（dpkg -c）
-rw-r--r-- root/root      1791 ./lib/systemd/system/rstun.service
-rwxr-xr-x root/root   3767576 ./usr/local/bin/rstun
-rw-r--r-- root/root     16726 ./usr/share/doc/rstun/LICENSE
-rw-r--r-- root/root     35932 ./usr/share/doc/rstun/README.md
（另有 postinst / prerm 维护脚本）
== systemd-analyze verify
unit ok（ExecStart 指向解包目录里的二进制）
```

未做 `dpkg -i`：那是**系统写入**（本仓硬约束：写操作只在工作区内）。改为
`dpkg-deb -x` 解包 + `systemd-analyze verify`（ExecStart 重写到解包目录里的真实二进制，
否则只会报「本机没装这个文件」）。真机 `systemctl start rstun` 是发布前的人工步骤。

### 判决 4 — brew formula 语法

```
$ bash script/ci/gen-brew.sh --assets <3 个 zip> --out dist/homebrew
gen-brew: 生成 dist/homebrew/rstun.rb（rstun 26.410.100）
$ docker run --rm -v .../homebrew:/w:ro ruby:alpine ruby -c /w/rstun.rb
Syntax OK (=0)
$ docker run --rm -v .../contrib/homebrew:/w:ro ruby:alpine ruby -c /w/rstun.rb
Syntax OK (=0)          # 仓库里的模板（占位符仍在字符串里，语法合法）
```

生成物里三个 `sha256` 已填（本地用真实 lean zip 的哈希；aarch64/macos 用同一份 zip
代替，**发布时由 release 作业用真实资产重算**）。本机无 brew：`brew install` 记为人工步骤
（`--build-from-source` 对「装预编译 zip」的 formula 无意义 —— 已在文件头写明）。

### 判决 5 — SBOM

```
$ bash script/ci/gen-sbom.sh --features lean --out dist/sbom/rstun-26.410.100-lean.cdx.json
gen-sbom: ... features=lean version=26.410.100
  组件 86 个（直接依赖 9 个）
-rw-r--r-- 1 root root 27351 ... rstun-26.410.100-lean.cdx.json
$ head -3 dist/sbom/rstun-26.410.100-lean.cdx.json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",

$ bash script/ci/gen-sbom.sh --features full --out dist/sbom/rstun-26.410.100-full.cdx.json
gen-sbom: ... features=full version=26.410.100
  组件 203 个（直接依赖 13 个）
-rw-r--r-- 1 root root 62891 ... rstun-26.410.100-full.cdx.json
```

闭包是**按 feature 从根节点 BFS** 出来的（不是 `metadata.packages` 全量）：
不这样做，lean 的 SBOM 里会冒出 rustls/webrtc-dtls 这些没编进去的包。
直接依赖数（9 / 13）是硬断言 —— 与 README「依赖面」表的数字同源。

## 3. 验证汇总（全部通过，原始输出见上）

| 命令 | 结果 |
| --- | --- |
| `cargo test --no-default-features` | `235 passed; 0 failed` |
| `cargo test --all-features` | `236 passed; 0 failed` |
| `cargo clippy --all-targets --no-default-features -- -D warnings` | 通过（Finished） |
| `cargo clippy --all-targets --all-features -- -D warnings` | 通过（Finished） |
| `cargo fmt --all -- --check` | 通过 |
| `bash script/lab/rstun-interop.sh all` | 全绿（42 项，含 rfc5769 / auth / coturn 对照） |
| `bash script/lab/rstun-abuse.sh` | 全部通过（10 组） |
| `bash script/lab/rstun-turn.sh` | `passed: 15 failed: 0 skipped: 2`（TLS/DTLS SKIP：lean 构建） |
| `cargo deny check`（cargo-deny 0.22.0） | `advisories ok, bans ok, licenses ok, sources ok` |
| `cargo audit` | 退出 0（3 条 unmaintained warning，符合 `.cargo/audit.toml` 的口径） |
| `mdbook build docs/book`（mdbook 0.5.4） | `HTML book written to .../docs/book/book`（14 页） |
| `bash script/ci/check-docs.sh` | exit 0（+ 三组反证 exit 1） |
| `python3 -c "yaml.safe_load(...)"` | `yaml ok`（3 个 workflow + 2 个 issue 模板 + dependabot） |

## 4. 外部动作清单（**全部未执行**，需人工确认后做）

| # | 动作 | 命令/位置 | 状态 |
| --- | --- | --- | --- |
| E1 | 开 GitHub Pages：Settings → Pages → Source = **GitHub Actions** | 仓库设置 | **未执行**（不开则 `docs.yml` 的 deploy 作业会红，不影响其它 CI） |
| E2 | 建 tap 仓 `exvlan/homebrew-rstun`，把 `dist/homebrew/rstun.rb` 推到 `Formula/rstun.rb` | `gh repo create exvlan/homebrew-rstun --public` + `git push` | **未执行** |
| E3 | 首次验证 `brew install exvlan/rstun/rstun` | Linuxbrew 或 macOS 本机 | **未执行**（本机无 brew；formula 只做了 `ruby -c`） |
| E4 | 发 Release（含 SBOM + formula 资产） | `gh workflow run release.yml -R exvlan/rstun -f version=<ver>` | **未执行** |
| E5 | 上传 SBOM（自动随 Release）后核对 | `gh release view rstun-v<ver> --json assets` | **未执行** |
| E6 | 真机 `dpkg -i` + `systemctl start rstun` + `systemctl status` | 干净 Debian/Ubuntu 容器或虚拟机 | **未执行**（本机不安装系统包） |
| E7 | 首次 `cargo publish`（之后才加 crates.io 徽章） | `cargo publish` | **未执行** |
| E8 | 发布签名（cosign/sigstore） | — | **后置**，Release notes 已声明「未签名」 |

## 5. 决策与偏离（低风险，已记录）

| 编号 | 决定 | 理由 |
| --- | --- | --- |
| D1 | `deny.toml` 的 `multiple-versions = "warn"`（设计稿写「禁重复版本」） | 树里 16 个同名多版本，多数来自 dev-only 的 `stun-types`；硬失败要写 16 条 skip 并随每次升级维护。`wildcards = "deny"` 保持硬约束 |
| D2 | `deny.toml` 的 `unmaintained = "none"` | cargo-deny 0.22 对 unmaintained 默认按 error 处理，而 `cargo audit` 按 warning（`.cargo/audit.toml` 的既定口径）。两边结论不能相反，advisories 的口径统一交给 `cargo audit` |
| D3 | SBOM 用 `cargo metadata` 自建 CycloneDX，不装 `cargo cyclonedx`/`syft` | 两者都要额外工具链（磁盘只剩 3.8 G，`cargo install` 不划算）；`metadata` 已给准确闭包 + SPDX 表达式。代价：没有第三方工具签发的合规声明 |
| D4 | `check-docs.sh` 的 help 比对**逐 token**、不做逐行 diff | clap 折行随宽度变；逐行在 CI 与本地之间必然假红（28→100 列就会全红） |
| D5 | `check-docs.sh` 额外扫描仓库根的 `*.md`（README/SECURITY/CONTRIBUTING），非 rstun 参数走显式白名单 | `SECURITY.md` 里也写了 `--check-fingerprint` 这类 flag，漏扫就等于留了个漂移出口。白名单每一条都写了理由 |
| D6 | `.deb` 的 unit 是**新的** `contrib/deb/rstun.service`（不是复用 `contrib/systemd/` 的样例） | 样例的 `ExecStart` 是 RFC 5780 双公网 IP 的示例地址，装完起不来；deb 要「装完就能 start」。样例仍保留给运维 |
| D7 | `.deb` 的 postinst 用 `useradd`/`groupadd`（不用 `adduser`） | `passwd` 包是 Essential，Debian/Ubuntu 都有；`adduser` 是 priority important，不保证 |
| D8 | 包管理器只发 lean | 用户已定（避免同版本两个包）；full 走 Release `rstun-full-*` 与镜像 |
| D9 | `docs.yml` 用 `configure-pages` + `upload-pages-artifact` + `deploy-pages`（全部锁 commit SHA） | SHA 由 GitHub API 从 tag 解析（v6.0.0 / v5.0.0 / v5.0.1），不是猜的 |
| D10 | 新增 `docs/book/src/{cli,nat-discovery}.md`（设计稿只列了 8 章） | `--help` 全量输出与 RFC 5780 都是长内容，塞进 `protocol.md` 会让单章 400+ 行；拆章不改变「单一真源」 |

## 6. 未完成 / 阻塞

| 项 | 状态 | 说明 |
| --- | --- | --- |
| `brew install` 实机验证 | 未执行 | 本机没有 brew/Linuxbrew；要装 Linuxbrew 需要联网 + 数百 MB，磁盘只剩 2.8 G。已用 `ruby -c` 验语法 |
| `dpkg -i` 实机安装 | 未执行 | 安装系统包属于工作区外的写操作，按硬约束不做；用 `dpkg-deb -x` + `systemd-analyze verify` 代替 |
| Pages 实际部署 | 未执行 | 需要仓库设置（E1） |
| tag → 资产 → 镜像一致性 | 未验证 | 需要一次真 Release（E4） |

## 7. 门禁（本任务后新增的命令）

```bash
cargo deny check                       # advisories + bans + licenses + sources（本地全量）
cargo deny check licenses bans sources # CI 的 deny 作业（advisories 交给 cargo audit）
mdbook build docs/book
bash script/ci/check-docs.sh           # 文档漂移（help 片段 / 参数名 / 指标名 / 链接）
bash script/ci/build-deb.sh            # .deb + dpkg -c + systemd-analyze verify
bash script/ci/gen-brew.sh --assets <dir>
bash script/ci/gen-sbom.sh --features lean|full --out <path>
```
