#!/usr/bin/env bash
#
# script/ci/check-version-pins.sh —— 版本钉死点检查（版本只有一个真源）
#
# 为什么需要它：发版要把同一个版本号改 6 处（README / docs / k8s / compose / helm×2），
# 漏一处的后果是「README 说 A、镜像示例说 B」—— 用户照文档拉镜像直接 404。
# 手工核对每次发版都要重来一遍，这个脚本把它变成可执行断言（CI 每次 push/PR 都跑）。
#
# 检查点（真源 = Cargo.toml 的 version）：
#   README.md                      已发布 `<ver>`
#   docs/book/src/docker.md        ghcr.io/exvlan/rstun:<ver> server
#   contrib/k8s/deployment.yaml    image: ghcr.io/exvlan/rstun:<ver>
#   contrib/docker/compose.yaml    同上
#   contrib/helm/Chart.yaml        appVersion: "<ver>"
#   contrib/helm/values.yaml       tag: "<ver>"
#
# 只认「当前版本」语义：历史基线（性能表、旧版本说明）不在这里检查。
#
# 用法：
#   bash script/ci/check-version-pins.sh              # 版本取 Cargo.toml
#   bash script/ci/check-version-pins.sh --version X  # 供 preflight/prep 复用（必须等于 Cargo.toml）
#
# 失败时逐条打印 `file:行`，任一不一致 exit 1。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

WANT=""

die() {
  echo "check-version-pins: $*" >&2
  exit 1
}

usage() {
  sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      shift
      WANT="${1:-}"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "未知参数 $1（--help 看用法）" ;;
  esac
  shift
done

# ---- 版本：Cargo.toml 是唯一真源 ---------------------------------------------
# `--version` 只是「把 preflight/prep 的输入带进来做一致性校验」，**不能**用它绕过真源：
# 两个版本源不同就说明 tag/输入与清单已经分叉，必须停下。
manifest_version="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)"
[ -n "$manifest_version" ] || die "读不到 Cargo.toml 的 version"

WANT="${WANT:-${RSTUN_VERSION:-$manifest_version}}"
WANT="${WANT#v}"
[ "$WANT" = "$manifest_version" ] ||
  die "version=${WANT} 与 Cargo.toml 的 ${manifest_version} 不一致（版本只有一个真源，先 bump 再传参）"

pins=0
bad=()
# 检查点数量是契约的一部分（design/PRD 写死 6 处）。下面每条 `check_pin` 都会 +1，
# 末尾断言总数 —— 防止将来删掉某个检查点后剩下的仍然「全绿」。
EXPECTED_PINS=6

# check_pin <人类可读说明> <文件> <精确串> <「任意版本」正则>
# 精确串找不到时，用正则把**实际写的那一行**带出来（file:行），否则只知道「不对」而不知道在哪。
check_pin() {
  local label="$1" file="$2" needle="$3" any_re="$4" hit
  if [ ! -f "$file" ]; then
    bad+=("${file}: 文件不存在（检查点：${label}）")
    return
  fi
  if grep -qF -- "$needle" "$file"; then
    pins=$((pins + 1))
    return
  fi
  hit="$(grep -nE -- "$any_re" "$file" | head -n1 || true)"
  if [ -n "$hit" ]; then
    bad+=("${file}:${hit} —— 期望「${needle}」")
  else
    bad+=("${file}: 找不到检查点「${label}」（期望「${needle}」）")
  fi
}

# 反引号在双引号里要转义，否则会被当成命令替换。
check_pin "README 的已发布版本" \
  README.md \
  "已发布 \`${manifest_version}\`" \
  '已发布 `[^`]+`'

check_pin "docker.md 的镜像示例" \
  docs/book/src/docker.md \
  "ghcr.io/exvlan/rstun:${manifest_version} server" \
  'ghcr\.io/exvlan/rstun:[^ ]+ server'

check_pin "k8s 的镜像 tag" \
  contrib/k8s/deployment.yaml \
  "image: ghcr.io/exvlan/rstun:${manifest_version}" \
  'image: *ghcr\.io/exvlan/rstun:'

check_pin "compose 的镜像 tag" \
  contrib/docker/compose.yaml \
  "image: ghcr.io/exvlan/rstun:${manifest_version}" \
  'image: *ghcr\.io/exvlan/rstun:'

check_pin "Helm Chart 的 appVersion" \
  contrib/helm/Chart.yaml \
  "appVersion: \"${manifest_version}\"" \
  '^appVersion:'

check_pin "Helm values 的 image tag" \
  contrib/helm/values.yaml \
  "tag: \"${manifest_version}\"" \
  '^ *tag:'

if [ "${#bad[@]}" -gt 0 ]; then
  {
    echo "check-version-pins: ${#bad[@]} 处与 Cargo.toml（${manifest_version}）不一致："
    printf '  - %s\n' "${bad[@]}"
    echo "（发版前把这几处一起改成 ${manifest_version}，或确认是哪一边写错了）"
  } >&2
  exit 1
fi

[ "$pins" -eq "$EXPECTED_PINS" ] ||
  die "只检查了 ${pins} 处（期望 ${EXPECTED_PINS}）——有 check_pin 被删了？检查覆盖变少不能算绿"

echo "check-version-pins: ${pins} 处钉死点全部 = ${manifest_version}"
