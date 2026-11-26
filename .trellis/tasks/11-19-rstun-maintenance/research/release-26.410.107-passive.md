# 26.410.107 发布：RFC 6062 被动模式（2026-11-26）

## 版本与产物

| 项 | 值 |
| --- | --- |
| 版本 | `26.410.107`（正式版，`prerelease=false`）|
| Release | `rstun-v26.410.107`，**17 资产**（13 核心 + `SHA256SUMS` + 3 个 cosign bundle）|
| deb | `rstun_26.410.107_{amd64,arm64}.deb` |
| 镜像 | `ghcr.io/exvlan/rstun:26.410.107`（amd64+arm64，full），digest `sha256:c410cb68285accfb3e147ed2a905094828543a65476159d079ae855581faadef`（`latest` 同步）|
| crates.io | ✅ `26.410.107`（`2026-11-26T14:23:50Z`，`yanked=false`，300 822 B）|
| Homebrew tap | ✅ `version "26.410.107"`（反向同步 run 45839768813）|
| `/releases/latest` | `rstun-v26.410.107` |

内容：RFC 6062 **被动模式**（`ConnectionAttempt`），首个两半都实现的版本 ——
`turnutils_uclient -T`（隐含 `-y`）首次全通、`-P` 双向 500B。

## 发布链（全自动）

| 阶段 | run | 结果 |
| --- | --- | --- |
| `release-prep` 预演 | 45837064463（`dry_run=true`）| success（11 处版本钉死点 diff 正确）|
| `release-prep` 实跑 | 45837177404 | success → commit `507a8c6` + tag `rstun-v26.410.107`（`c35412ac…`）|
| `release` | 45837249640 | **12/12 作业成功**（四平台构建、双架构镜像、`Sign container image`、`publish (26.410.107)`）|
| tap 同步 | 45839768813（`exvlan/homebrew-rstun`）| success |
| `post-release-verify` | **45839862533** | **13/13 步 success** |

### 一次假红（顺序问题，非缺陷）

首次 `post-release-verify`（45838651689）在 **Summary** 步失败：`FORMULA: failure` ——
12 次轮询（约 6 分钟）内 tap 的 formula 还是 `.106`。原因是我先跑 verify、后触发 tap 同步，
与 spec 的「标准发版顺序」（**tap 同步 → post-release-verify**）相反。
手动 `gh workflow run sync.yml -R exvlan/homebrew-rstun` 后重跑即 13/13。

> 结论：**不需要改代码或 spec**，spec §2 已写明顺序；下次按顺序执行即可省掉一轮重跑。

## 用户在 `.107` 起可用的验证方式

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.bundle \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v26.410.107' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c --strict SHA256SUMS
cosign verify 'ghcr.io/exvlan/rstun@sha256:c410cb68…' \
  --certificate-identity 'https://github.com/exvlan/rstun/.github/workflows/release.yml@refs/tags/rstun-v26.410.107' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

（身份是**逐字**字符串；`refs/heads/main`、别的 owner、别的版本都不匹配。）

## 对生产（EXVlan）的影响

默认行为与 `.106` 一致：`--turn-tcp-relay` 仍默认关闭，被动模式只在开关打开 + TCP allocation 时生效。
生产当前跑 `.105`（已通告 `.106`/`.107`），切换由他们决定。

## 遗留

- `#10`（Verify platforms 定时运行停滞）仍 open：`cron: "0 6 * * 4"`（周四 06:00 UTC），
  今天 14:35 UTC 仍未触发（GitHub schedule 已知延迟可达 ~10h，历史 3 次均为延迟触发）。
  守卫会在出现 `event=schedule` 运行后自动关闭。
