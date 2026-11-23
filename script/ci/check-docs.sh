#!/usr/bin/env bash
#
# script/ci/check-docs.sh —— 文档与实现漂移检查（README + docs/book）
#
# 检查四件事，任一失败 → exit 1：
#   1. help 片段：`docs/**/*.md` 里标了 `<!-- check-docs: help=main|server -->` 的 fenced block
#      必须与真实二进制 `rstun --help` / `rstun server --help` **逐 token 一致**
#      （逐 token 而不是逐行：clap 按终端宽度折行，行边界随 COLUMNS 变，token 序列不变）；
#   2. 参数名：文档里出现的 `--flag` 必须在 `--help` 里有定义（cargo/docker/lab 脚本的 flag
#      走 `ALLOW_NON_RSTUN` 白名单，新增白名单必须写明理由）；
#   3. 指标名：文档里出现的 `rstun_*` 必须由真实 `/metrics` 输出（启动实例时带 `--turn`，
#      否则 TURN 指标族不出现）；只在 `turns:`/DTLS 部署里出现的证书指标走
#      `CONDITIONAL_METRICS`（本检查器的实例不带 secure 监听，门禁由单测覆盖）；
#   4. 链接：文档之间的相对链接与 `#锚点` 必须可达（README → docs 的摘要是由它守住的）。
#
# 用法：
#   bash script/ci/check-docs.sh            # 缺二进制时 cargo build（lean）
#   bash script/ci/check-docs.sh --no-build # 只用现成二进制（CI 里先 build 过）
#   bash script/ci/check-docs.sh --bin path/to/rstun
#
# 反证（必须能红）：把 docs/book/src/cli.md 里任一个 `--flag` 改名（或改 help 片段里的一个字），
# 脚本必须非 0 退出；改回来必须通过。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BUILD=1
BIN="${RSTUN_BIN:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --no-build) BUILD=0 ;;
    --bin)
      shift
      [ $# -gt 0 ] || { echo "check-docs: --bin 需要一个路径" >&2; exit 2; }
      BIN="$1"
      ;;
    -h | --help)
      sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "check-docs: 未知参数 $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [ -z "$BIN" ]; then
  for candidate in target/debug/rstun target/release/rstun; do
    if [ -x "$candidate" ]; then
      BIN="$candidate"
      break
    fi
  done
fi
if [ -z "$BIN" ]; then
  if [ "$BUILD" -eq 1 ]; then
    echo "check-docs: 没有现成二进制，cargo build（lean）…"
    cargo build --quiet
    BIN=target/debug/rstun
  else
    echo "check-docs: 没有二进制（--no-build）—— 先 cargo build 或用 --bin" >&2
    exit 2
  fi
fi
[ -x "$BIN" ] || { echo "check-docs: 二进制不可执行：$BIN" >&2; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

WORK="$(mktemp -d)"
PORT=""
SRV_PID=""
cleanup() {
  if [ -n "$SRV_PID" ] && kill -0 "$SRV_PID" 2>/dev/null; then
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- 1. help 片段 -----------------------------------------------------------
"$BIN" --help >"$WORK/help-main.txt"
"$BIN" server --help >"$WORK/help-server.txt"

# ---- 2. 指标名：起一个实例读真实 /metrics -------------------------------------
# 带 `--turn`：不开 TURN 时 `rstun_turn_*` 整族不出现，文档里提到它们就会被误判成漂移。
# 端口用「让内核挑一个」，避免和机器上别的东西撞（失败只重试 EADDRINUSE，和 lab 脚本同规矩）。
start_metrics_server() {
  local attempt
  for attempt in 1 2 3; do
    PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
    "$BIN" server --listen 127.0.0.1:0 --health-listen "127.0.0.1:${PORT}" \
      --turn --realm example.org --auth-secret check-docs \
      --auth-user docs --auth-pass docs >"$WORK/server.log" 2>&1 &
    SRV_PID=$!
    local i
    for i in $(seq 1 50); do
      if python3 - "$PORT" >"$WORK/metrics.txt" 2>/dev/null <<'PY'
import sys, urllib.request
port = sys.argv[1]
with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=1) as r:
    sys.stdout.write(r.read().decode())
PY
      then
        return 0
      fi
      if ! kill -0 "$SRV_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
    if grep -q 'Address already in use' "$WORK/server.log" 2>/dev/null; then
      continue
    fi
    break
  done
  echo "check-docs: 起不来一个带 /metrics 的实例（日志见下）" >&2
  cat "$WORK/server.log" >&2 || true
  return 1
}

if ! start_metrics_server; then
  exit 1
fi
kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true
SRV_PID=""

# ---- 3./4. help 比对 + 参数名 + 指标名 + 链接 --------------------------------
HELP_MAIN="$WORK/help-main.txt" \
  HELP_SERVER="$WORK/help-server.txt" \
  METRICS="$WORK/metrics.txt" \
  DOC_ROOT="$ROOT" \
  python3 - <<'PY'
import difflib
import os
import pathlib
import re
import sys
import urllib.parse

ROOT = pathlib.Path(os.environ["DOC_ROOT"])
DOC_SRC = ROOT / "docs/book/src"
HELP = {
    "main": (ROOT / os.environ["HELP_MAIN"]).read_text(encoding="utf-8"),
    "server": (ROOT / os.environ["HELP_SERVER"]).read_text(encoding="utf-8"),
}
METRICS = (ROOT / os.environ["METRICS"]).read_text(encoding="utf-8")

failures = []


def fail(msg):
    failures.append(msg)


def rel(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


# 非 rstun 的 flag：cargo / docker / lab 脚本。新增一条 = 一次「这不是 rstun 参数」的声明，
# 所以白名单写在代码里、带理由，不做通配。
ALLOW_NON_RSTUN = {
    "--all": "script/lab/rstun-interop.sh all",
    "--all-features": "cargo test/build",
    "--all-targets": "cargo clippy --all-targets",
    "--build-arg": "docker build",
    "--bundle": "cosign sign-blob/verify-blob（docs/book/src/verify.md 的产物验证）",
    "--certificate-identity": "cosign verify-blob/verify 的 keyless 身份约束（逐字比较；docs/book/src/verify.md）",
    "--certificate-identity-regexp": "cosign 的反例说明（spec 记录「禁用正则拼转义」的教训；docs/book/src/verify.md 未使用）",
    "--certificate-oidc-issuer": "cosign verify-blob/verify 的 OIDC issuer 约束（docs/book/src/verify.md）",
    "--check": "cargo fmt --all -- --check",
    "--depth": "cargo tree",
    "--dry-run": "cargo publish --dry-run（发版预检）",
    "--dtls": "script/lab/rstun-turn.sh --dtls",
    "--features": "cargo build/install",
    "--ignore-certificate-errors-spki-list": "Chrome（docs/browser-acceptance.md 的证书信任步骤）",
    "--format": "cargo tree --format '{p}'",
    "--format-version": "cargo metadata --format-version",
    "--name": "docker run --name",
    "--no-default-features": "cargo build/test（lean）",
    "--network": "docker run --network host",
    "--path": "cargo install --path",
    "--password-stdin": "docker login --password-stdin（docs/book/src/verify.md 的 ghcr 登录）",
    "--prerelease": "gh release create/edit（预发布标记；release.yml 与 CHANGELOG 的发布说明）",
    "--platform": "docker build --platform",
    "--ref": "gh workflow run --ref <tag>（发布演练/补发 crate、release-prep 从 tag 树构建）",
    "--release": "cargo build --release",
    "--rm": "docker run --rm",
    "--tls": "script/lab/rstun-turn.sh --tls",
    "--only": "script/lab/rstun-turn.sh --only <item>（lab 的单项选择）",
    "--family": "script/lab/rstun-turn-probe.py --family inet|inet6（探针的地址族）",
}

# ---- 收集 rstun 真正定义的 flag --------------------------------------------
help_text = HELP["main"] + "\n" + HELP["server"]
defined_flags = set(re.findall(r"(?<![\w-])(--[a-z0-9][a-z0-9-]*)", help_text))

# ---- 收集真实指标名 --------------------------------------------------------
metric_names = set()
for line in METRICS.splitlines():
    if line.startswith("#") or not line.strip():
        continue
    m = re.match(r"^([a-z_][a-z0-9_]*)", line)
    if m:
        metric_names.add(m.group(1))
if not metric_names:
    fail("没有从 /metrics 读到任何指标名（服务没起来？）")

# 只在一部分部署里出现的指标：本检查器起的实例是 `--turn` 但不带 `turns:`/DTLS，
# 所以证书相关指标永远读不到。它们是**条件输出**（`--turn` + secure 监听），
# 由单测 `tls_reload_metrics_appear_only_with_secure_material` 与
# `turn_metrics_appear_only_when_enabled` 覆盖门禁；这里只登记名字，不做真实抓取。
CONDITIONAL_METRICS = {
    "rstun_turn_tls_reload_total",
    "rstun_turn_tls_cert_expires_seconds",
}

# ---- 文档文件清单 ----------------------------------------------------------
# 扫描范围：文档站 + 仓库根的用户可见 markdown（README / SECURITY / CONTRIBUTING）。
# 仓库根的 `SECURITY.md` 里写着 `--check-fingerprint` 这类 flag，漂移了同样会骗用户。
md_files = sorted(DOC_SRC.rglob("*.md"))
md_files += [p for p in sorted(ROOT.glob("*.md")) if p.is_file()]
md_files = [p for p in md_files if p.is_file()]

MARKER = re.compile(r"<!--\s*check-docs:\s*help=(main|server)\s*-->")
FENCE = re.compile(r"^\s*```")
PROMPT = re.compile(r"^\s*\$ ")


def tokenize(text):
    return text.split()


def strip_comments(text):
    return re.sub(r"<!--.*?-->", "", text, flags=re.S)


# ---- 1. help 片段逐 token 比对 ---------------------------------------------
help_blocks = 0
for path in md_files:
    lines = path.read_text(encoding="utf-8").split("\n")
    i = 0
    while i < len(lines):
        m = MARKER.search(lines[i])
        if not m:
            i += 1
            continue
        which = m.group(1)
        j = i + 1
        while j < len(lines) and not FENCE.match(lines[j]):
            j += 1
        if j == len(lines):
            fail(f"{rel(path)}:{i + 1} 标记了 help={which} 但后面没有 fenced block")
            break
        k = j + 1
        body = []
        while k < len(lines) and not FENCE.match(lines[k]):
            body.append(lines[k])
            k += 1
        if k == len(lines):
            fail(f"{rel(path)}:{j + 1} fenced block 没有闭合")
            break
        documented = "\n".join(x for x in body if not PROMPT.match(x))
        expected = HELP[which]
        help_blocks += 1
        if tokenize(documented) != tokenize(expected):
            diff = list(
                difflib.unified_diff(
                    tokenize(expected),
                    tokenize(documented),
                    fromfile=f"真实 rstun{' server' if which == 'server' else ''} --help",
                    tofile=f"{rel(path)}:{j + 1} 的片段",
                    lineterm="",
                    n=6,
                )
            )
            fail(
                f"{rel(path)}:{j + 1} help={which} 片段与真实输出不一致"
                "（改了 flag/描述就必须同步这一块）\n    " + "\n    ".join(diff[:60])
            )
        i = k if k < len(lines) else i + 1

if help_blocks == 0:
    fail("没有任何 `<!-- check-docs: help=... -->` 片段 —— 检查器会空转，拒绝通过")

# ---- 2. 参数名 + 3. 指标名 -------------------------------------------------
for path in md_files:
    text = strip_comments(path.read_text(encoding="utf-8"))
    # 去掉 fenced code 里的 shell 提示行不影响判断：flag 在代码块里也算引用。
    for flag in sorted(set(re.findall(r"(?<![\w-])(--[a-z0-9][a-z0-9-]*)", text))):
        if flag in defined_flags or flag in ALLOW_NON_RSTUN:
            continue
        fail(
            f"{rel(path)}: 提到了 `{flag}`，但 `rstun --help` / `rstun server --help` 里没有定义"
            "（若是 cargo/docker/脚本的参数，请加进 check-docs.sh 的 ALLOW_NON_RSTUN 并写理由）"
        )
    for name in sorted(set(re.findall(r"\brstun_[a-z][a-z0-9_]*[a-z0-9]\b", text))):
        if name in metric_names or name in CONDITIONAL_METRICS:
            continue
        fail(f"{rel(path)}: 提到了指标 `{name}`，但 `--turn` 实例的 /metrics 里没有")


# ---- 4. 链接与锚点 ---------------------------------------------------------
def slug(heading):
    """GitHub / mdBook 风格锚点：小写、空格→'-'、其余标点丢弃（CJK 保留）。"""
    text = re.sub(r"`", "", heading)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.strip().lower()
    out = []
    for ch in text:
        if ch in " \t":
            out.append("-")
        elif ch.isalnum() or ch in "-_":
            out.append(ch)
    return "".join(out)


def anchors_of(path):
    result = set()
    for line in path.read_text(encoding="utf-8").split("\n"):
        m = re.match(r"^#{1,6}\s+(.*?)\s*$", line)
        if m:
            result.add(slug(m.group(1)))
        for explicit in re.findall(r'<a id="([^"]+)"></a>', line):
            result.add(explicit)
    return result


anchor_cache = {}
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
for path in md_files:
    text = strip_comments(path.read_text(encoding="utf-8"))
    # fenced code 里的括号不是链接：逐行剥掉
    kept = []
    in_fence = False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            kept.append(line)
    text = "\n".join(kept)
    for raw in LINK.findall(text):
        target = raw.strip()
        if target.startswith(("http://", "https://", "mailto:", "#", "<")):
            if target.startswith("#"):
                anchor = urllib.parse.unquote(target[1:])
                if anchor and anchor not in anchors_of(path):
                    fail(f"{rel(path)}: 锚点 `#{anchor}` 在本文件里不存在")
            continue
        path_part, _, anchor = target.partition("#")
        anchor = urllib.parse.unquote(anchor)
        resolved = (path.parent / path_part).resolve()
        if not resolved.exists():
            fail(f"{rel(path)}: 链接 `{target}` 指向的文件不存在（{rel(resolved)}）")
            continue
        if anchor and resolved.suffix == ".md":
            if resolved not in anchor_cache:
                anchor_cache[resolved] = anchors_of(resolved)
            if anchor not in anchor_cache[resolved]:
                fail(f"{rel(path)}: 链接 `{target}` 的锚点 `#{anchor}` 在 {rel(resolved)} 里不存在")
    # mdBook 的 include 指令同样必须可达（mdbook build 会失败，这里先给出可读的错）
    for inc in re.findall(r"\{\{#include\s+([^}\s]+)\s*\}\}", text):
        if not (path.parent / inc).resolve().exists():
            fail(f"{rel(path)}: {{{{#include {inc}}}}} 指向的文件不存在")

print(f"check-docs: 扫描 {len(md_files)} 个 markdown、{help_blocks} 个 help 片段、"
      f"{len(defined_flags)} 个 flag、{len(metric_names)} 个指标")
if failures:
    print(f"\n✗ {len(failures)} 处漂移：", file=sys.stderr)
    for item in failures:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)
print("✓ 文档与实现一致（help 片段 / 参数名 / 指标名 / 链接）")
PY
