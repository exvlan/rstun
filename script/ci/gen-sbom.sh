#!/usr/bin/env bash
#
# script/ci/gen-sbom.sh —— 生成 CycloneDX SBOM（lean / full 各一份）
#
# 为什么不用 `cargo cyclonedx` / `syft`：两者都要额外的工具链（cargo install 很重，
# 装进 CI 只为一件事不划算；镜像里也没有）。`cargo metadata` 已经给出**准确的**
# 依赖闭包 + 每个包的版本与 SPDX 许可证表达式，足够生成一份诚实的 SBOM。
#
# 用法：
#   bash script/ci/gen-sbom.sh --features lean --out dist/sbom/rstun-26.410.100-lean.cdx.json
#   bash script/ci/gen-sbom.sh --features full --out dist/sbom/rstun-26.410.100-full.cdx.json
#
# 输出是 CycloneDX 1.5 JSON（`bomFormat` / `specVersion` / `components` / `dependencies`）。
# 版本真源是 `Cargo.toml`。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

FEATURES=""
OUT=""

die() {
  echo "gen-sbom: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --features)
      shift
      FEATURES="${1:-}"
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

case "$FEATURES" in
  lean) CARGO_FLAGS=(--no-default-features) ;;
  full) CARGO_FLAGS=(--features full) ;;
  *) die "--features 必须是 lean 或 full（当前：'${FEATURES}'）" ;;
esac
[ -n "$OUT" ] || die "需要 --out <路径>（.cdx.json）"

manifest_version="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -n1)"
[ -n "$manifest_version" ] || die "读不到 Cargo.toml 的 version"

mkdir -p "$(dirname "$OUT")"

# `--locked`：SBOM 必须与 Cargo.lock 一致（依赖被改动却没提交锁文件时立刻失败）。
cargo metadata --format-version 1 --locked "${CARGO_FLAGS[@]}" >"$(dirname "$OUT")/.metadata-${FEATURES}.json"

RSTUN_FEATURES="$FEATURES" \
  RSTUN_EXPECTED_VERSION="$manifest_version" \
  RSTUN_METADATA="$(dirname "$OUT")/.metadata-${FEATURES}.json" \
  RSTUN_OUT="$OUT" \
  python3 - <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import uuid
from datetime import datetime, timezone

meta = json.loads(pathlib.Path(os.environ["RSTUN_METADATA"]).read_text())
features = os.environ["RSTUN_FEATURES"]
version = os.environ["RSTUN_EXPECTED_VERSION"]
out = pathlib.Path(os.environ["RSTUN_OUT"])

root_id = meta["resolve"]["root"]
packages = {p["id"]: p for p in meta["packages"]}
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
root_pkg = packages[root_id]

if root_pkg["version"] != version:
    sys.exit(f"gen-sbom: metadata 里的 {root_pkg['version']} 与 Cargo.toml 的 {version} 不一致")

# 可达闭包（从根节点 BFS）—— `packages` 里有本 feature 组合**没启用**的 optional 依赖，
# 直接全量输出会给出「装了 rustls」的假象。
reachable = set()
stack = [root_id]
while stack:
    pid = stack.pop()
    if pid in reachable:
        continue
    reachable.add(pid)
    for dep in nodes[pid].get("deps", []):
        stack.append(dep["pkg"])

# 直接依赖只算**正常**依赖（dev-dependencies 不进产物，`stun-types` 是测试 oracle）。
direct = []
for dep in nodes[root_id].get("deps", []):
    kinds = dep.get("dep_kinds") or [{}]
    if any(k.get("kind") is None for k in kinds):
        direct.append(packages[dep["pkg"]])
direct.sort(key=lambda p: p["name"])

EXPECTED_DIRECT = {"lean": 9, "full": 13}


def purl(pkg):
    return f"pkg:cargo/{pkg['name']}@{pkg['version']}"


def licenses_of(pkg):
    expr = pkg.get("license")
    if expr:
        return [{"expression": expr}]
    if pkg.get("license_file"):
        # 只有文件、没有 SPDX 表达式：宁可留空也不猜。
        return []
    return []


components = []
for pid in sorted(reachable - {root_id}, key=lambda i: (packages[i]["name"], packages[i]["version"])):
    pkg = packages[pid]
    entry = {
        "type": "library",
        "name": pkg["name"],
        "version": pkg["version"],
        "bom-ref": purl(pkg),
        "purl": purl(pkg),
        "scope": "required",
    }
    lic = licenses_of(pkg)
    if lic:
        entry["licenses"] = lic
    components.append(entry)

lock_hash = hashlib.sha256(pathlib.Path("Cargo.lock").read_bytes()).hexdigest()[:16]
serial = uuid.uuid5(uuid.NAMESPACE_URL, f"rstun/{version}/{features}/{lock_hash}")
timestamp = datetime.fromtimestamp(
    int(os.environ.get("SOURCE_DATE_EPOCH", datetime.now(timezone.utc).timestamp())), timezone.utc
).strftime("%Y-%m-%dT%H:%M:%SZ")

try:
    cargo_version = subprocess.run(
        ["cargo", "--version"], capture_output=True, text=True, check=True
    ).stdout.split()[1]
except Exception:  # pragma: no cover - cargo 必然存在（本脚本由它驱动）
    cargo_version = "unknown"

def normal_deps(pid):
    """该节点的 normal（运行期）依赖 id；dev/build 边不算产物的一部分。"""
    out = []
    for dep in nodes[pid].get("deps", []):
        kinds = dep.get("dep_kinds") or [{}]
        if any(k.get("kind") is None for k in kinds) and dep["pkg"] in reachable:
            if dep["pkg"] not in out:
                out.append(dep["pkg"])
    return out


graph = []
for pid in sorted(reachable, key=lambda i: (packages[i]["name"], packages[i]["version"])):
    graph.append(
        {"ref": purl(packages[pid]), "dependsOn": [purl(packages[d]) for d in normal_deps(pid)]}
    )

bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{serial}",
    "version": 1,
    "metadata": {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {"type": "application", "name": "cargo", "version": cargo_version},
                {"type": "application", "name": "gen-sbom.sh", "version": "1"},
            ]
        },
        "component": {
            "type": "application",
            "name": "rstun",
            "version": version,
            "bom-ref": purl(root_pkg),
            "purl": purl(root_pkg),
            "licenses": [{"license": {"id": "MPL-2.0"}}],
            "properties": [
                {"name": "rstun:features", "value": features},
                {"name": "rstun:direct-dependencies", "value": str(len(direct))},
            ],
        },
    },
    "components": components,
    # 完整的依赖图（不止 root → 直接依赖）：下游（Dependency-Track / Grype）靠它做传递影响分析。
    # 只输出 **normal** 依赖边（dev/build 边不是产物的一部分，和 components 的闭包口径一致）。
    "dependencies": graph,
}

out.write_text(json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=False) + "\n", encoding="utf-8")

missing_license = [c["name"] for c in components if "licenses" not in c]
print(f"gen-sbom: {out} —— features={features} version={version}")
print(f"  组件 {len(components)} 个（直接依赖 {len(direct)} 个）")
if missing_license:
    print(f"  ⚠ 无 SPDX 表达式的组件（licenses 字段留空）：{', '.join(missing_license[:8])}")

expected = EXPECTED_DIRECT[features]
if len(direct) != expected:
    sys.exit(
        f"gen-sbom: 直接依赖 {len(direct)} 个，与 spec 约定的 {expected} 个（{features}）不一致 —— "
        "改了 Cargo.toml 就要同步这里与 docs/book 的依赖面"
    )
PY

rm -f "$(dirname "$OUT")/.metadata-${FEATURES}.json"
ls -l "$OUT"
