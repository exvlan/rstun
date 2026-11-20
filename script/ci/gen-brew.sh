#!/usr/bin/env bash
#
# script/ci/gen-brew.sh —— 发布时生成 Homebrew formula（填版本 + 三个平台的 sha256）
#
# 输入是**已经打好的 Release 资产**（lean 构建的三个 zip）：
#   rstun-linux-x86_64-<version>.zip
#   rstun-linux-aarch64-<version>.zip
#   rstun-macos-x86_64-<version>.zip
# 输出 `dist/homebrew/rstun.rb`（语法自检），发布时把它推到 `exvlan/homebrew-rstun`
# tap（**外部动作，需人工确认**；本脚本只生成本地文件，不 push 任何东西）。
#
# 用法：
#   bash script/ci/gen-brew.sh --assets zipped_assets
#   bash script/ci/gen-brew.sh --assets zipped_assets --version 26.410.100
#
# 版本真源仍是 `Cargo.toml`：`--version` 与它不一致直接失败。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

ASSETS=""
VERSION=""
OUT="$ROOT/dist/homebrew"

die() {
  echo "gen-brew: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --assets)
      shift
      ASSETS="${1:-}"
      ;;
    --version)
      shift
      VERSION="${1:-}"
      ;;
    --out)
      shift
      OUT="${1:-}"
      ;;
    -h | --help)
      sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die "未知参数 $1" ;;
  esac
  shift
done

manifest_version="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)"
[ -n "$manifest_version" ] || die "读不到 Cargo.toml 的 version"
VERSION="${VERSION:-${RSTUN_VERSION:-$manifest_version}}"
VERSION="${VERSION#v}"
[ "$VERSION" = "$manifest_version" ] ||
  die "version=${VERSION} 与 Cargo.toml 的 ${manifest_version} 不一致"

[ -n "$ASSETS" ] || die "需要 --assets <目录>（含三个 lean zip）"
[ -d "$ASSETS" ] || die "目录不存在：$ASSETS"

sha_of() {
  local zip="$ASSETS/rstun-$1-${VERSION}.zip"
  [ -f "$zip" ] || die "缺资产：$zip"
  sha256sum "$zip" | cut -d' ' -f1
}

linux_x86_64="$(sha_of linux-x86_64)"
linux_aarch64="$(sha_of linux-aarch64)"
macos_x86_64="$(sha_of macos-x86_64)"

mkdir -p "$OUT"
sed -e "s|__RSTUN_VERSION__|${VERSION}|g" \
  -e "s|__SHA256_LINUX_X86_64__|${linux_x86_64}|g" \
  -e "s|__SHA256_LINUX_AARCH64__|${linux_aarch64}|g" \
  -e "s|__SHA256_MACOS_X86_64__|${macos_x86_64}|g" \
  contrib/homebrew/rstun.rb >"$OUT/rstun.rb"

if grep -q '__[A-Z0-9_]*__' "$OUT/rstun.rb"; then
  die "formula 里还有未替换的占位符：$(grep -o '__[A-Z0-9_]*__' "$OUT/rstun.rb" | sort -u | tr '\n' ' ')"
fi

if command -v ruby >/dev/null 2>&1; then
  ruby -c "$OUT/rstun.rb"
else
  echo "（无 ruby：跳过语法检查，发布前请在 macOS/带 ruby 的机器上跑 ruby -c）"
fi

echo "gen-brew: 生成 $OUT/rstun.rb（rstun ${VERSION}）"
echo "  推送目标（发布时人工执行，本脚本不 push）：exvlan/homebrew-rstun/Formula/rstun.rb"
