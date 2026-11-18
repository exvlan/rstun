#!/usr/bin/env bash
#
# STUN Binding 冒烟：给一个**已在运行**的 `rstun` 发 20 字节 Binding Request，
# 断言返回 `0x0101`（Binding Success Response）且带 `XOR-MAPPED-ADDRESS`。
#
# 为什么需要它：`rstun` 没有 HTTP 就绪端点，镜像里也没有 curl/python，
# 「进程还活着」不等于协议正确（socket 绑错 family、编解码写错、容器端口没 publish
# 都表现为「进程在跑但客户端拿不到映射」）。所以 CI 对新编的二进制与容器镜像各跑一次，
# 线上也可以直接拿它验部署（UDP 回程是否通、NAT 映射对不对）。
#
# 用法：
#   bash script/ci/rstun-smoke.sh <host:port>                   # 只验 UDP
#   bash script/ci/rstun-smoke.sh <host:port> --tcp             # UDP + TCP（服务需 --tcp）
#   bash script/ci/rstun-smoke.sh 203.0.113.10:3478 --tcp --retries 10
#
# 退出码：0 = 通过；1 = 协议/网络失败；2 = 参数错误。
# 依赖：只用 python3 标准库（Linux/macOS runner 自带；镜像内不需要，因为探测从外部发起）。

set -euo pipefail

addr="${1:-}"
if [[ -z "$addr" || "$addr" == "-h" || "$addr" == "--help" ]]; then
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  [[ -n "$addr" ]] || exit 2
  exit 0
fi
shift

# 输出是中文；Windows 控制台默认 codepage（cp936/cp1252）会让 Python 直接在
# `print` 上抛 `UnicodeEncodeError`（协议连测都没测到）。CI 与本地都统一 UTF-8。
export PYTHONIOENCODING=utf-8

tcp=false
retries=10
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tcp) tcp=true ;;
    --retries) retries="${2:?--retries 需要一个数字}"; shift ;;
    --retries=*) retries="${1#*=}" ;;
    *)
      echo "未知参数: $1（可用：--tcp / --retries N）" >&2
      exit 2
      ;;
  esac
  shift
done

if ! [[ "$retries" =~ ^[0-9]+$ ]]; then
  echo "--retries 需要非负整数，收到: $retries" >&2
  exit 2
fi

STUN_ADDR="$addr" STUN_TCP="$tcp" STUN_RETRIES="$retries" python3 - <<'PY'
"""最小 STUN 客户端：够用来判断「服务真的回了正确的 Binding 响应」。"""

import os
import socket
import sys
import time

MAGIC_COOKIE = b"\x21\x12\xa4\x42"
BINDING_SUCCESS = 0x0101
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022

addr = os.environ["STUN_ADDR"]
want_tcp = os.environ["STUN_TCP"] == "true"
retries = int(os.environ["STUN_RETRIES"])

host, sep, port = addr.rpartition(":")
if not sep or not host or not port.isdigit():
    sys.exit(f"[rstun-smoke] 地址格式应为 host:port，收到 {addr!r}")
port = int(port)
host = host.strip("[]")  # 兼容 [::1]:3478
family = socket.AF_INET6 if ":" in host else socket.AF_INET


def build_request() -> bytes:
    """20 字节：8 字节头（type/len/magic）+ 12 字节随机 transaction id。"""
    return b"\x00\x01\x00\x00" + MAGIC_COOKIE + os.urandom(12)


def parse_response(data: bytes, what: str) -> None:
    """校验头部 + 必带属性；不满足就当作失败（不要只判断「收到东西」）。"""
    if len(data) < 20:
        raise SystemExit(f"[rstun-smoke] {what}: 响应过短（{len(data)} 字节 < 20）")
    mtype = int.from_bytes(data[0:2], "big")
    mlen = int.from_bytes(data[2:4], "big")
    if mtype != BINDING_SUCCESS:
        raise SystemExit(f"[rstun-smoke] {what}: 期望 0x0101，实际 0x{mtype:04x}")
    if data[4:8] != MAGIC_COOKIE:
        raise SystemExit(f"[rstun-smoke] {what}: magic cookie 不正确")
    if mlen % 4 != 0 or 20 + mlen > len(data):
        raise SystemExit(f"[rstun-smoke] {what}: 长度字段不自洽（{mlen}，收到 {len(data)} 字节）")

    body = data[20 : 20 + mlen]
    attrs: list[int] = []
    off = 0
    while off + 4 <= len(body):
        atype = int.from_bytes(body[off : off + 2], "big")
        alen = int.from_bytes(body[off + 2 : off + 4], "big")
        attrs.append(atype)
        off += 4 + ((alen + 3) // 4) * 4  # 4 字节对齐

    if ATTR_XOR_MAPPED_ADDRESS not in attrs:
        raise SystemExit(
            f"[rstun-smoke] {what}: 缺 XOR-MAPPED-ADDRESS（0x0020），属性={[hex(a) for a in attrs]}"
        )
    software = "有" if ATTR_SOFTWARE in attrs else "无"
    print(f"[rstun-smoke] {what}: ok 0x0101 attrs={[hex(a) for a in attrs]} SOFTWARE={software}")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SystemExit(f"[rstun-smoke] tcp: 连接提前关闭（期望 {n} 字节，收到 {len(buf)}）")
        buf += chunk
    return buf


def check_udp() -> None:
    last: object = "未发起请求"
    for attempt in range(1, retries + 1):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(build_request(), (host, port))
            data, _ = sock.recvfrom(2048)
            sock.close()
            parse_response(data, "udp")
            return
        except (SystemExit, OSError) as exc:
            last = exc
            print(f"[rstun-smoke] udp 第 {attempt}/{retries} 次未通过: {exc}", file=sys.stderr)
            if attempt < retries:
                time.sleep(1)
    raise SystemExit(f"[rstun-smoke] udp 连续 {retries} 次失败：{last}")


def check_tcp() -> None:
    last: object = "未发起请求"
    for attempt in range(1, retries + 1):
        try:
            sock = socket.create_connection((host, port), timeout=3)
            sock.settimeout(3)
            sock.sendall(build_request())
            header = recv_exact(sock, 20)
            body = recv_exact(sock, int.from_bytes(header[2:4], "big"))
            sock.close()
            parse_response(header + body, "tcp")
            return
        except (SystemExit, OSError) as exc:
            last = exc
            print(f"[rstun-smoke] tcp 第 {attempt}/{retries} 次未通过: {exc}", file=sys.stderr)
            if attempt < retries:
                time.sleep(1)
    raise SystemExit(f"[rstun-smoke] tcp 连续 {retries} 次失败：{last}")


print(f"[rstun-smoke] 目标 {addr}（udp{'+tcp' if want_tcp else ''}，重试上限 {retries}）")
check_udp()
if want_tcp:
    check_tcp()
print(f"[rstun-smoke] {addr} 通过")
PY
