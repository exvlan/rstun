#!/usr/bin/env bash
#
# script/ci/build-deb.sh —— 打 Debian/Ubuntu 包（.deb，含 systemd unit）
#
# 只发 **lean** 构建：`turns:`(TLS)/DTLS 走 Release 的 `rstun-full-*` 与镜像，
# 避免包管理器里出现「同版本两个 rstun」。
#
# 版本只有一个真源：`Cargo.toml`。`--version`（或 `RSTUN_VERSION`）传进来时必须与它一致，
# 否则直接退出 —— 发布链上「tag 说 A、包说 B」是不可接受的。
#
# 用法：
#   bash script/ci/build-deb.sh                          # 版本取 Cargo.toml，架构取 uname -m
#   bash script/ci/build-deb.sh --version 26.410.100 --arch arm64 \
#        --bin target/aarch64-unknown-linux-musl/release/rstun
#   bash script/ci/build-deb.sh --download-nfpm          # 缺 nfpm 时下载固定版本（校验 sha256）
#   bash script/ci/build-deb.sh --foreign-bin            # 跨架构打包：跳过「执行二进制做版本自检」
#                                                        # （仅用于二进制来自可信发布物，如 Release 的 zip）
#
# 依赖：nfpm（>= 2.40，固定 2.49.0 验证过）、dpkg-deb（校验用，缺失时退化到 `ar t`）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION=""
ARCH=""
BIN=""
OUT="$ROOT/dist/deb"
DOWNLOAD_NFPM=0
VERIFY_TAG=0
FOREIGN_BIN=0

# nfpm 固定版本与校验值（只在 CI/脚本里用，**不进 Cargo.toml**）。
NFPM_VERSION="2.49.0"
NFPM_URL="https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
NFPM_SHA256="2afaa5ffb5e3493402e31e7c67a5a1fb42133e3f66fc315ca0051934125561c7"
CACHE_DIR="${RSTUN_CI_CACHE:-$ROOT/target/ci-tools}"

die() {
  echo "build-deb: $*" >&2
  exit 1
}

usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      shift
      VERSION="${1:-}"
      ;;
    --arch)
      shift
      ARCH="${1:-}"
      ;;
    --bin)
      shift
      BIN="${1:-}"
      ;;
    --out)
      shift
      OUT="${1:-}"
      ;;
    --download-nfpm) DOWNLOAD_NFPM=1 ;;
    --foreign-bin) FOREIGN_BIN=1 ;;
    --verify-tag) VERIFY_TAG=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "未知参数 $1"
      ;;
  esac
  shift
done

# ---- 版本：以 Cargo.toml 为准 -------------------------------------------------
manifest_version="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)"
[ -n "$manifest_version" ] || die "读不到 Cargo.toml 的 version"

VERSION="${VERSION:-${RSTUN_VERSION:-$manifest_version}}"
VERSION="${VERSION#v}"
if [ "$VERSION" != "$manifest_version" ]; then
  die "version=${VERSION} 与 Cargo.toml 的 ${manifest_version} 不一致（版本只有一个真源）"
fi

if [ "$VERIFY_TAG" -eq 1 ]; then
  tag="$(git describe --tags --exact-match 2>/dev/null || true)"
  [ "$tag" = "rstun-v${VERSION}" ] ||
    die "--verify-tag 要求 HEAD 正好在 rstun-v${VERSION} 上（当前：${tag:-无 tag}）"
fi

# ---- 架构：uname -m → Debian 架构名 ------------------------------------------
if [ -z "$ARCH" ]; then
  case "$(uname -m)" in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "不认识的架构 $(uname -m)：请用 --arch amd64|arm64" ;;
  esac
fi
case "$ARCH" in
  amd64 | arm64) ;;
  *) die "只支持 amd64 / arm64（当前：$ARCH）" ;;
esac

# ---- 二进制：默认 target/release/rstun（lean），缺失则构建 --------------------
# 优先 musl 产物（static-pie，装到任何发行版都不依赖宿主 glibc）；rust 的 target 三元组
# 与 Debian 架构名不同名（amd64→x86_64、arm64→aarch64），这里显式映射。
case "$ARCH" in
  amd64) musl_triple="x86_64-unknown-linux-musl" ;;
  arm64) musl_triple="aarch64-unknown-linux-musl" ;;
esac
if [ -z "$BIN" ]; then
  if [ -x "target/${musl_triple}/release/rstun" ]; then
    BIN="target/${musl_triple}/release/rstun"
  elif [ -x target/release/rstun ]; then
    BIN=target/release/rstun
    echo "build-deb: 警告：没有 musl 产物（target/${musl_triple}/release/rstun），用 target/release/rstun（动态链接 glibc）。" >&2
    echo "build-deb:       这样的包只能装在与构建机 glibc 同代或更新的发行版上；发布包请先" >&2
    echo "build-deb:       cargo build --release --target ${musl_triple}，或用 --bin 指定 musl 二进制。" >&2
  fi
fi
if [ -z "$BIN" ]; then
  echo "build-deb: 没有现成二进制，cargo build --release（lean）…"
  cargo build --release
  BIN=target/release/rstun
fi
[ -x "$BIN" ] || die "二进制不可执行：$BIN"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
file_arch="$(file -b "$BIN" | sed -n 's/.*, \(x86-64\|ARM aarch64\)[, ].*/\1/p' | head -n1)"
[ -n "$file_arch" ] ||
  die "认不出二进制架构（file 输出：$(file -b "$BIN" | head -c 120)）—— 只支持 x86-64 / ARM aarch64"
case "$ARCH:$file_arch" in
  amd64:x86-64 | arm64:ARM\ aarch64) ;;
  *)
    die "二进制架构（${file_arch}）与 --arch ${ARCH} 不一致"
    ;;
esac

# 版本串自检：发行版二进制是 `<version>+<sha6>`，所以用「包含」而不是「相等」。
#
# `--foreign-bin`：跨架构打包（例如在 x86_64 主机上给 Release 的 aarch64 zip 打 deb）时，
# 本机无法执行目标架构二进制，跳过这一步。调用方必须自己确认二进制来源（sha256 与发布物一致）。
if [ "$FOREIGN_BIN" -eq 1 ]; then
  echo "build-deb: --foreign-bin → 跳过版本自检（二进制来自外部发布物，请自行核对来源）" >&2
else
  bin_version="$("$BIN" --version)"
  case "$bin_version" in
    *"$VERSION"*) ;;
    *) die "--version 输出（${bin_version}）不含 ${VERSION}" ;;
  esac
fi

# ---- nfpm ------------------------------------------------------------------
find_nfpm() {
  if [ -n "${NFPM:-}" ]; then
    echo "$NFPM"
    return 0
  fi
  if command -v nfpm >/dev/null 2>&1; then
    command -v nfpm
    return 0
  fi
  if [ -x "$CACHE_DIR/nfpm_${NFPM_VERSION}/nfpm" ]; then
    echo "$CACHE_DIR/nfpm_${NFPM_VERSION}/nfpm"
    return 0
  fi
  return 1
}

if ! NFPM_BIN="$(find_nfpm)"; then
  [ "$DOWNLOAD_NFPM" -eq 1 ] || die "找不到 nfpm：装一个（固定版本 ${NFPM_VERSION}）或用 --download-nfpm"
  mkdir -p "$CACHE_DIR"
  tarball="$CACHE_DIR/nfpm_${NFPM_VERSION}.tar.gz"
  if [ ! -f "$tarball" ]; then
    echo "build-deb: 下载 nfpm ${NFPM_VERSION} …"
    curl -sSL --retry 3 -o "$tarball" "$NFPM_URL"
  fi
  echo "${NFPM_SHA256}  ${tarball}" | sha256sum -c --quiet - ||
    die "nfpm 校验失败（sha256 不匹配）：${tarball}"
  mkdir -p "$CACHE_DIR/nfpm_${NFPM_VERSION}"
  tar xzf "$tarball" -C "$CACHE_DIR/nfpm_${NFPM_VERSION}" nfpm
  NFPM_BIN="$CACHE_DIR/nfpm_${NFPM_VERSION}/nfpm"
fi
echo "build-deb: nfpm $("$NFPM_BIN" --version | sed -n 's/^GitVersion: *//p')"

# ---- 打包 ------------------------------------------------------------------
# nfpm 2.4x 不再对 `contents.src` 做 `${VAR}` 展开（试过：`Glob failed: ${RSTUN_BIN}`），
# 所以这里先渲染成临时配置再交给 nfpm —— `contrib/deb/nfpm.yaml` 是**模板**，
# 占位符只有这三个，值都来自上面的校验结果。
mkdir -p "$OUT"
rendered="$(mktemp -t rstun-nfpm.XXXXXX.yaml)"
case "$BIN$VERSION$ARCH" in
  *'&'* | *'|'*) die "路径/版本里出现 sed 分隔符，换一个（当前 $BIN / $VERSION / $ARCH）" ;;
esac
sed -e "s|\${RSTUN_BIN}|${BIN}|" \
  -e "s|\${NFPM_ARCH}|${ARCH}|" \
  -e "s|\${RSTUN_VERSION}|${VERSION}|" \
  contrib/deb/nfpm.yaml >"$rendered"

pkg="$(RSTUN_VERSION="$VERSION" NFPM_ARCH="$ARCH" RSTUN_BIN="$BIN" \
  "$NFPM_BIN" pkg --config "$rendered" --packager deb --target "$OUT" |
  tail -n1 | sed 's/^created package: *//')"
rm -f "$rendered"
[ -f "$pkg" ] || die "nfpm 没有产出 .deb（看上面的输出）"

# ---- 文件名规范化：`~` → `-`（只改文件名，不改包内 Version）--------------------
# nfpm 按 Debian 版本规则把预发布的 `-` 写成 `~`：`26.410.106-dev.0` →
# `rstun_26.410.106~dev.0_amd64.deb`（包内 `Version:` 也是 `~` 形式，这是**对的**）。
# 但 GitHub Release 会把**资产名**里的 `~` 改写成 `.`（实测 2026-11-23 dev 演练），
# 于是 `SHA256SUMS`（按本地文件名算）与用户下载到的文件名对不上，verify 也找不到资产。
# 所以文件名统一用版本串的 `-` 形式，与 zip/资产命名一致；**包内 `Version:` 保持 `~`**，
# 因为 `~` 让预发布版排在同版本正式版之前（改成 `-` 会变成 Debian 修订号，语义/排序都变）。
if [[ "$(basename "$pkg")" == *"~"* ]]; then
  pkg_name="$(basename "$pkg")"
  renamed="$(dirname "$pkg")/${pkg_name//\~/-}"
  mv "$pkg" "$renamed"
  echo "build-deb: 文件名 ${pkg_name} → $(basename "$renamed")（GitHub 会改写 ~；包内 Version 不变）"
  pkg="$renamed"
fi

# ---- 校验：包内文件 + unit -------------------------------------------------
echo
echo "== 包：$pkg"
ls -l "$pkg"
if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --info "$pkg" | sed -n '1,25p'
  echo "== 包内文件（dpkg -c）"
  dpkg -c "$pkg"
  if command -v systemd-analyze >/dev/null 2>&1; then
    verify_dir="$(mktemp -d)"
    dpkg-deb -x "$pkg" "$verify_dir"
    # 没安装到本机时 `ExecStart=/usr/local/bin/rstun` 必然报 "not executable"（那是环境，
    # 不是 unit 的错）。把 ExecStart 指到解包出来的二进制再 verify —— 这样校验的是
    # 真实的 unit 语法 + 依赖关系，而不是「我机器上没装这个文件」。
    sed "s|/usr/local/bin/rstun|${verify_dir}/usr/local/bin/rstun|" \
      "$verify_dir/lib/systemd/system/rstun.service" >"$verify_dir/verify.service"
    chmod +x "$verify_dir/usr/local/bin/rstun"
    echo "== systemd-analyze verify"
    if systemd-analyze verify "$verify_dir/verify.service"; then
      echo "unit ok（ExecStart 指向解包目录里的二进制）"
    else
      die "systemd-analyze verify 失败"
    fi
    rm -rf "$verify_dir"
  else
    echo "（无 systemd-analyze：unit 只做了静态评审，安装后再验）"
  fi
else
  echo "（无 dpkg-deb：只列出 ar 成员）"
  ar t "$pkg"
fi
