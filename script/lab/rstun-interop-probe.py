#!/usr/bin/env python3
"""rstun 互操作探针：只用标准库，按 mode 发 STUN 请求并**断言**响应。

为什么单独一个探针而不用 `rstun-smoke.sh`：冒烟只验「20 字节 Binding → 0x0101」，
而互操作矩阵要逐项验证**属性级**行为（420 的 UNKNOWN-ATTRIBUTES、PADDING 回显不放大、
RESPONSE-PORT 的目的端口、RFC 5780 四条 change 路径的**回包源地址**、TCP 分帧、IPv6）。
每一项都必须能单独跑、单独判定，才能把「对手不通过」归因到「我方 / 对手 / RFC 理解」。

用法（mode 见 `MODES`）：

    python3 script/lab/rstun-interop-probe.py basic --server 127.0.0.1:34780
    python3 script/lab/rstun-interop-probe.py change --server 127.0.0.1:34780 \
        --alt-ip 127.0.0.2 --alt-port 34781 --change 0x02

退出码：0 = 通过；1 = 断言失败；2 = 参数错误；77 = 环境不支持（跳过，由
`rstun-interop.sh` 映射成 SKIP 而不是 FAIL）。
输出：每条**断言**一行 `ok: ...`；失败时一行 `FAIL: ...`。结构性前置条件
（长度/对齐/边界）用 `require()`：只在失败时输出，不会在通过时写出一句
读起来像失败的话（例：「响应不足 20 字节（80）」）。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import zlib

MAGIC_COOKIE = 0x2112A442
MSG_BINDING_REQUEST = 0x0001
MSG_BINDING_SUCCESS = 0x0101
MSG_BINDING_ERROR = 0x0111

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_CHANGE_REQUEST = 0x0003
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_UNKNOWN_ATTRIBUTES = 0x000A
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_MESSAGE_INTEGRITY_SHA256 = 0x001C
ATTR_PASSWORD_ALGORITHM = 0x001D
ATTR_USERHASH = 0x001E
ATTR_PASSWORD_ALGORITHMS = 0x8002
ATTR_PRIORITY = 0x0024
ATTR_USE_CANDIDATE = 0x0025
ATTR_PADDING = 0x0026
ATTR_RESPONSE_PORT = 0x0027
ATTR_SOFTWARE = 0x8022
ATTR_ALTERNATE_SERVER = 0x8023
ATTR_FINGERPRINT = 0x8028
ATTR_ICE_CONTROLLING = 0x802A
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C

# RFC 5389 §15.5: FINGERPRINT = CRC32(prefix) XOR this constant.
FINGERPRINT_XOR = 0x5354554E

CHANGE_IP = 0x04
CHANGE_PORT = 0x02

# 未实现但必须被 420 点名的「comprehension-required」属性（RFC 5389 §18.1）。
ATTR_UNKNOWN_FOR_TEST = 0x0033

SKIP = 77


class Fail(Exception):
    """一条断言失败：调用方打印后以退出码 1 结束。"""


def check(condition: bool, message: str) -> None:
    """一条**断言**：通过时打印 `ok:`（message 必须是陈述句，读起来就是结论）。"""
    if not condition:
        raise Fail(message)
    print(f"ok: {message}")


def require(condition: bool, message: str) -> None:
    """一条**前置条件**：只在失败时抛错，通过时不打印。

    解码/边界这类校验的 message 写成「不满足时的事实」（「响应不足 20 字节（80）」），
    用 `check()` 会在通过时打出 `ok: 响应不足 20 字节（80）` —— 日志里看着像失败。
    """
    if not condition:
        raise Fail(message)


def parse_addr(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise Fail(f"地址格式应为 host:port，收到 {text!r}")
    return host.strip("[]"), int(port)


def family_of(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def format_addr(host: str, port: int) -> str:
    """`host:port`；IPv6 必须带方括号（与 STUN 里地址属性的文本形式一致）。"""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def client_for(server_addr: tuple[str, int]) -> "Client":
    """绑到与被测服务**同一个地址族**的回环地址。

    只绑 `127.0.0.1` 的客户端根本发不到 `[::1]`（会被当 IPv4 地址解析），
    这正是「IPv6 测试莫名超时」的常见原因。
    """
    return Client("::1" if ":" in server_addr[0] else "127.0.0.1")


# ---------- 编码 ----------


def attribute(attr_type: int, value: bytes) -> bytes:
    """一条属性：type(2) | length(2) | value | 零 padding（不计入 length）。"""
    return (
        struct.pack("!HH", attr_type, len(value))
        + value
        + b"\x00" * ((-len(value)) % 4)
    )


def build_request(transaction_id: bytes, attributes: bytes = b"") -> bytes:
    return (
        struct.pack("!HH", MSG_BINDING_REQUEST, len(attributes))
        + struct.pack("!I", MAGIC_COOKIE)
        + transaction_id
        + attributes
    )


def address_value(host: str, port: int) -> bytes:
    """RESPONSE-ORIGIN / OTHER-ADDRESS / MAPPED-ADDRESS 的 0|family|port|addr 布局。"""
    info = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0]
    family = info[0]
    sockaddr = info[4]
    if family == socket.AF_INET:
        return b"\x00\x01" + struct.pack("!H", port) + socket.inet_aton(sockaddr[0])
    return b"\x00\x02" + struct.pack("!H", port) + socket.inet_pton(socket.AF_INET6, sockaddr[0])


def decode_address(value: bytes) -> str:
    """把 0|family|port|addr 解回 `host:port`（IPv6 带方括号）。"""
    require(len(value) >= 4, f"地址属性不足 4 字节（{len(value)}）")
    family = value[1]
    port = struct.unpack("!H", value[2:4])[0]
    if family == 0x01:
        return f"{socket.inet_ntoa(value[4:8])}:{port}"
    if family == 0x02:
        return f"[{socket.inet_ntop(socket.AF_INET6, value[4:20])}]:{port}"
    raise Fail(f"未知地址族 0x{family:02x}")


def decode_xor_mapped(value: bytes, transaction_id: bytes) -> str:
    require(len(value) >= 8, f"XOR-MAPPED-ADDRESS 不足 8 字节（{len(value)}）")
    port = struct.unpack("!H", value[2:4])[0] ^ (MAGIC_COOKIE >> 16)
    mask = struct.pack("!I", MAGIC_COOKIE) + transaction_id
    if value[1] == 0x01:
        octets = bytes(a ^ b for a, b in zip(value[4:8], mask))
        return f"{socket.inet_ntoa(octets)}:{port}"
    if value[1] == 0x02:
        octets = bytes(a ^ b for a, b in zip(value[4:20], mask))
        return f"[{socket.inet_ntop(socket.AF_INET6, octets)}]:{port}"
    raise Fail(f"XOR-MAPPED-ADDRESS 未知地址族 0x{value[1]:02x}")


# ---------- 解码 ----------


def decode(data: bytes) -> dict:
    """解析一条 STUN 消息：头字段 + 属性列表（value 已去掉 padding）。"""
    require(len(data) >= 20, f"响应不足 20 字节（{len(data)}）")
    msg_type, length = struct.unpack("!HH", data[0:4])
    cookie = struct.unpack("!I", data[4:8])[0]
    require(cookie == MAGIC_COOKIE, f"magic cookie 错误（0x{cookie:08x}）")
    require(length % 4 == 0, f"Message Length {length} 不是 4 的倍数")
    require(len(data) >= 20 + length, f"响应长度 {len(data)} 盖不住声明的 {length} 字节 body")

    attributes: list[tuple[int, bytes]] = []
    offset = 20
    end = 20 + length
    while offset < end:
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        value = data[offset + 4 : offset + 4 + attr_len]
        require(
            len(value) == attr_len,
            f"属性 0x{attr_type:04x} 的 {attr_len} 字节 value 越过了消息",
        )
        attributes.append((attr_type, value))
        offset += 4 + attr_len + ((-attr_len) % 4)
    require(offset == end, "属性列表没有用满 Message Length")

    return {
        "type": msg_type,
        "length": length,
        "transaction_id": data[8:20],
        "attributes": attributes,
        "types": [attr_type for attr_type, _ in attributes],
    }


def attr(message: dict, attr_type: int) -> bytes | None:
    for kind, value in message["attributes"]:
        if kind == attr_type:
            return value
    return None


def error_code(message: dict) -> int | None:
    value = attr(message, ATTR_ERROR_CODE)
    if value is None:
        return None
    return (value[2] & 0x07) * 100 + value[3]


def expect_success(message: dict, transaction_id: bytes) -> None:
    check(message["type"] == MSG_BINDING_SUCCESS, f"响应类型 0x{message['type']:04x} = 0x0101")
    check(message["transaction_id"] == transaction_id, "transaction id 原样回显")


# ---------- 传输 ----------


class Client:
    """一个绑定在指定地址（默认自动选端口）的 UDP/TCP 客户端。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, tcp: bool = False):
        # 默认绑到 127.0.0.1 而不是通配：服务端看到的就是 127.0.0.1，
        # 断言 XOR-MAPPED-ADDRESS 时才不用处理 0.0.0.0 这种「本地视角」地址。
        self.family = family_of(host)
        self.tcp = tcp
        kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
        self.socket = socket.socket(self.family, kind)
        self.socket.bind((host, port))
        self.socket.settimeout(3.0)
        # close() 之后 getsockname 会抛 OSError：本地地址在构造时就固定下来。
        local_host, local_port = self.socket.getsockname()[:2]
        self._local = (local_host, local_port)

    def local(self) -> tuple[str, int]:
        return self._local

    def udp_exchange(self, request: bytes, server: tuple[str, int]) -> tuple[bytes, tuple]:
        self.socket.sendto(request, server)
        data, source = self.socket.recvfrom(65535)
        return data, (source[0], source[1])

    def tcp_connect(self, server: tuple[str, int]) -> None:
        self.socket.connect(server)

    def tcp_send(self, request: bytes) -> None:
        self.socket.sendall(request)

    def tcp_read_frame(self) -> bytes:
        """按 RFC 5389 §7.2.2 的头长度读一整帧。"""
        header = self._read_exact(20)
        length = struct.unpack("!H", header[2:4])[0]
        return header + self._read_exact(length)

    def _read_exact(self, size: int) -> bytes:
        chunks = b""
        while len(chunks) < size:
            chunk = self.socket.recv(size - len(chunks))
            if not chunk:
                raise Fail(f"TCP 连接在读满 {size} 字节前关闭")
            chunks += chunk
        return chunks

    def close(self) -> None:
        self.socket.close()


# ---------- 各 mode ----------


# ---------- 鉴权（RFC 5389 §10 / RFC 8489 §9.2） ----------


def long_term_key(algorithm: str, user: str, realm: str, password: str) -> bytes:
    """key = MD5/SHA256(username:realm:password)（RFC 5389 §15.4 / RFC 8489 §9.2.2）。"""
    material = f"{user}:{realm}:{password}".encode()
    return hashlib.sha256(material).digest() if algorithm == "sha256" else hashlib.md5(material).digest()


def sign(frame: bytes, algorithm: str, key: bytes) -> bytes:
    """追加 MESSAGE-INTEGRITY(-SHA256)：HMAC 覆盖到该属性之前，Length 指向其末尾。"""
    size = 24 if algorithm == "md5" else 36
    body_len = len(frame) - 20
    prefix = bytearray(frame)
    prefix[2:4] = struct.pack("!H", body_len + size)
    if algorithm == "md5":
        mac = hmac.new(key, bytes(prefix), hashlib.sha1).digest()
        attr_type = ATTR_MESSAGE_INTEGRITY
    else:
        mac = hmac.new(key, bytes(prefix), hashlib.sha256).digest()
        attr_type = ATTR_MESSAGE_INTEGRITY_SHA256
    frame = bytearray(frame)
    frame[2:4] = struct.pack("!H", body_len + size)
    return bytes(frame) + struct.pack("!HH", attr_type, len(mac)) + mac


def verify_integrity(response: bytes, algorithm: str, key: bytes) -> bool:
    """独立验证响应里的 MESSAGE-INTEGRITY（同一个公式，反方向）。"""
    size = 24 if algorithm == "md5" else 36
    attr_type = ATTR_MESSAGE_INTEGRITY if algorithm == "md5" else ATTR_MESSAGE_INTEGRITY_SHA256
    message = decode(response)
    offset = 20
    for kind, value in message["attributes"]:
        if kind == attr_type:
            prefix = bytearray(response[:offset])
            prefix[2:4] = struct.pack("!H", offset - 20 + size)
            expected = (
                hmac.new(key, bytes(prefix), hashlib.sha1).digest()
                if algorithm == "md5"
                else hmac.new(key, bytes(prefix), hashlib.sha256).digest()
            )
            return hmac.compare_digest(expected, value)
        offset += 4 + len(value) + ((-len(value)) % 4)
    return False


def probe_auth_long_term(args) -> None:
    """长期凭据全流程：无凭据 → 401（REALM/NONCE/PASSWORD-ALGORITHMS），
    带 MESSAGE-INTEGRITY 重试 → 200 且响应可独立验签，错口令 → 401。

    这是探针**自己**算的 key 与 HMAC（hashlib/hmac），不是把服务端的结果再喂回去。
    """
    user, password, realm = args.auth_user, args.auth_password, args.auth_realm
    client = client_for(args.server_addr)
    try:
        transaction_id = os.urandom(12)
        response, _ = client.udp_exchange(build_request(transaction_id), args.server_addr)
        message = decode(response)
        check(message["type"] == MSG_BINDING_ERROR, f"无凭据 → 0x{message['type']:04x} = 0x0111")
        check(error_code(message) == 401, "ERROR-CODE = 401 Unauthorized")
        check(attr(message, ATTR_REALM) == realm.encode(), f"401 带 REALM = {realm}")
        nonce = attr(message, ATTR_NONCE)
        check(nonce is not None and len(nonce) == 22, "401 带 22 字符的无状态 NONCE")
        algorithms = attr(message, ATTR_PASSWORD_ALGORITHMS)
        check(
            algorithms is not None and b"\x00\x01" in algorithms and b"\x00\x02" in algorithms,
            "401 带 PASSWORD-ALGORITHMS（MD5 + SHA256）",
        )
        challenge_size = len(response)

        credentials = (
            attribute(ATTR_USERNAME, user.encode())
            + attribute(ATTR_REALM, realm.encode())
            + attribute(ATTR_NONCE, nonce)
        )
        key = long_term_key("md5", user, realm, password)
        transaction_id = os.urandom(12)
        request = sign(build_request(transaction_id, credentials), "md5", key)
        response, _ = client.udp_exchange(request, args.server_addr)
        message = decode(response)
        expect_success(message, transaction_id)
        check(attr(message, ATTR_MESSAGE_INTEGRITY) is not None, "200 带 MESSAGE-INTEGRITY（§10.2.2）")
        check(verify_integrity(response, "md5", key), "响应的 HMAC-SHA1 可被独立实现验证")

        transaction_id = os.urandom(12)
        wrong = sign(
            build_request(transaction_id, credentials),
            "md5",
            long_term_key("md5", user, realm, password + "-wrong"),
        )
        response, _ = client.udp_exchange(wrong, args.server_addr)
        check(error_code(decode(response)) == 401, "错口令 → 401")

        # USERHASH（RFC 8489 §14.4）：完整 SHA-256（32 字节），请求里没有 USERNAME。
        sha_key = long_term_key("sha256", user, realm, password)
        digest = hashlib.sha256(f"{user}:{realm}".encode()).digest()
        check(len(digest) == 32, "USERHASH = 完整 SHA-256（32 字节）")
        userhash_request = (
            attribute(ATTR_USERHASH, digest)
            + attribute(ATTR_REALM, realm.encode())
            + attribute(ATTR_NONCE, nonce)
            + attribute(ATTR_PASSWORD_ALGORITHM, struct.pack("!HH", 0x0002, 0))
        )
        transaction_id = os.urandom(12)
        request = sign(build_request(transaction_id, userhash_request), "sha256", sha_key)
        response, _ = client.udp_exchange(request, args.server_addr)
        expect_success(decode(response), transaction_id)
        check(
            verify_integrity(response, "sha256", sha_key),
            "USERHASH（32 字节）请求 → 200，且响应可被独立验签",
        )
        # 16 字节的截断值不是 USERHASH（RFC 8489 §14.4 定长 32）。
        truncated = (
            attribute(ATTR_USERHASH, digest[:16])
            + attribute(ATTR_REALM, realm.encode())
            + attribute(ATTR_NONCE, nonce)
            + attribute(ATTR_PASSWORD_ALGORITHM, struct.pack("!HH", 0x0002, 0))
        )
        transaction_id = os.urandom(12)
        request = sign(build_request(transaction_id, truncated), "sha256", sha_key)
        response, _ = client.udp_exchange(request, args.server_addr)
        check(error_code(decode(response)) == 401, "16 字节 USERHASH → 401（长度不是 32）")
        print(f"info: 401 挑战 = {challenge_size} 字节；错口令的重试得到 {len(response)} 字节的 401")
    finally:
        client.close()


def probe_basic(args) -> None:
    client = client_for(args.server_addr)
    local = client.local()
    transaction_id = os.urandom(12)
    try:
        response, source = client.udp_exchange(build_request(transaction_id), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    expect_success(message, transaction_id)
    check(source[1] == args.server_addr[1], f"回包源端口 = {args.server_addr[1]}")
    mapped = attr(message, ATTR_XOR_MAPPED_ADDRESS)
    check(mapped is not None, "带 XOR-MAPPED-ADDRESS")
    check(
        decode_xor_mapped(mapped, transaction_id) == format_addr(*local),
        "XOR-MAPPED-ADDRESS = 客户端真实地址",
    )
    software = attr(message, ATTR_SOFTWARE)
    check(software is not None, "带 SOFTWARE")
    print(f"info: SOFTWARE={software.decode('utf-8', 'replace')}")


def probe_mapped(args) -> None:
    """`--mapped-address` 打开时，MAPPED-ADDRESS 与 XOR 版必须同时出现且一致。"""
    client = client_for(args.server_addr)
    local = client.local()
    transaction_id = os.urandom(12)
    try:
        response, _ = client.udp_exchange(build_request(transaction_id), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    expect_success(message, transaction_id)
    mapped = attr(message, ATTR_MAPPED_ADDRESS)
    check(mapped is not None, "带 MAPPED-ADDRESS（--mapped-address）")
    expected = format_addr(*local)
    check(decode_address(mapped) == expected, f"MAPPED-ADDRESS = {expected}")
    check(
        decode_xor_mapped(attr(message, ATTR_XOR_MAPPED_ADDRESS), transaction_id) == expected,
        "XOR-MAPPED-ADDRESS 与 MAPPED-ADDRESS 一致",
    )


def probe_ice(args) -> None:
    """ICE 连通性检查的标配属性一个都不能触发 420（RFC 8445 §16）。"""
    client = client_for(args.server_addr)
    transaction_id = os.urandom(12)
    payload = b"".join(
        [
            attribute(ATTR_USERNAME, b"ufrag:pass"),
            attribute(ATTR_MESSAGE_INTEGRITY, b"\x00" * 20),
            attribute(ATTR_PRIORITY, struct.pack("!I", 0x6E0001FF)),
            attribute(ATTR_USE_CANDIDATE, b""),
            attribute(ATTR_ICE_CONTROLLING, b"\x11" * 8),
            attribute(ATTR_FINGERPRINT, b"\x00" * 4),
        ]
    )
    try:
        response, _ = client.udp_exchange(build_request(transaction_id, payload), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    expect_success(message, transaction_id)
    check(ATTR_XOR_MAPPED_ADDRESS in message["types"], "带 XOR-MAPPED-ADDRESS")
    check(ATTR_UNKNOWN_ATTRIBUTES not in message["types"], "没有 UNKNOWN-ATTRIBUTES（未被 420）")


def probe_auth(args) -> None:
    """RFC 3489 时代的鉴权簇（USERNAME/MI/REALM/NONCE）同样不能触发 420。"""
    client = client_for(args.server_addr)
    transaction_id = os.urandom(12)
    payload = b"".join(
        [
            attribute(ATTR_USERNAME, b"user"),
            attribute(ATTR_REALM, b"example.org"),
            attribute(ATTR_NONCE, b"f//499k954d6OL34oL9FSTvy64sA"),
            attribute(ATTR_MESSAGE_INTEGRITY, b"\xaa" * 20),
        ]
    )
    try:
        response, _ = client.udp_exchange(build_request(transaction_id, payload), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    expect_success(message, transaction_id)
    check(ATTR_UNKNOWN_ATTRIBUTES not in message["types"], "鉴权簇未被 420")


def probe_unknown(args) -> None:
    """RFC 5389 §7.3.1/§15.9：未知 comprehension-required → 420 + 恰好 2N 字节的列表。"""
    client = client_for(args.server_addr)
    transaction_id = os.urandom(12)
    payload = attribute(ATTR_UNKNOWN_FOR_TEST, b"\xde\xad\xbe\xef")
    try:
        response, _ = client.udp_exchange(build_request(transaction_id, payload), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    check(message["type"] == MSG_BINDING_ERROR, f"响应类型 0x{message['type']:04x} = 0x0111")
    check(message["transaction_id"] == transaction_id, "transaction id 原样回显")
    check(error_code(message) == 420, "ERROR-CODE = 420 Unknown Attribute")
    listed = attr(message, ATTR_UNKNOWN_ATTRIBUTES)
    check(listed is not None, "带 UNKNOWN-ATTRIBUTES")
    check(len(listed) == 2, f"UNKNOWN-ATTRIBUTES value 长度 = 2N = {len(listed)}")
    check(
        struct.unpack("!H", listed)[0] == ATTR_UNKNOWN_FOR_TEST,
        f"点名的属性 = 0x{ATTR_UNKNOWN_FOR_TEST:04x}",
    )


def probe_padding(args) -> None:
    """RFC 5780 §7.6：回显同样长度的 PADDING，且响应不因它放大。"""
    size = args.size
    client = client_for(args.server_addr)
    transaction_id = os.urandom(12)
    request = build_request(transaction_id, attribute(ATTR_PADDING, b"\x5a" * size))
    try:
        response, source = client.udp_exchange(request, args.server_addr)
    finally:
        client.close()

    check(source[1] == args.server_addr[1], "PADDING 请求仍由入口 socket 应答")
    message = decode(response)
    expect_success(message, transaction_id)
    echoed = attr(message, ATTR_PADDING)
    check(echoed is not None, "带 PADDING")
    check(len(echoed) == size, f"PADDING 回显长度 = 请求长度 = {size}")
    growth = len(response) - len(request)
    # 允许的增长只来自 XOR-MAPPED-ADDRESS(12) + SOFTWARE(4+name) + PADDING 头(4) − 请求头(4)：
    # 也就是说 PADDING 的**值**本身没有放大。
    check(growth <= 12 + 4 + 64 + 4, f"响应相对请求只增长 {growth} 字节（PADDING 未放大）")


def probe_response_port(args) -> None:
    """RFC 5780 §7.5：RESPONSE-PORT 是**目的端口**，源地址/端口不变。"""
    inbox = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inbox.bind(("127.0.0.1", 0))
    inbox.settimeout(3.0)
    inbox_port = inbox.getsockname()[1]
    client = Client("127.0.0.1")
    local = client.local()
    transaction_id = os.urandom(12)
    request = build_request(transaction_id, attribute(ATTR_RESPONSE_PORT, struct.pack("!H", inbox_port)))
    try:
        client.socket.sendto(request, args.server_addr)
        response, source = inbox.recvfrom(65535)
        check(source[1] == args.server_addr[1], f"回包源端口仍是入口端口 {args.server_addr[1]}")
        client.socket.settimeout(0.3)
        try:
            client.socket.recvfrom(4096)
            raise Fail("响应不应同时发给请求源端口")
        except socket.timeout:
            print("ok: 请求源端口没有收到第二份响应")
    finally:
        client.close()
        inbox.close()

    message = decode(response)
    expect_success(message, transaction_id)
    check(
        decode_xor_mapped(attr(message, ATTR_XOR_MAPPED_ADDRESS), transaction_id)
        == format_addr(*local),
        "XOR-MAPPED-ADDRESS 仍是请求源地址",
    )


def probe_padding_response_port(args) -> None:
    """RFC 5780 §6/§7.5/§10：PADDING + RESPONSE-PORT 同现 → 400。"""
    client = client_for(args.server_addr)
    transaction_id = os.urandom(12)
    payload = attribute(ATTR_RESPONSE_PORT, struct.pack("!H", 23480)) + attribute(
        ATTR_PADDING, b"\x00" * 32
    )
    try:
        response, _ = client.udp_exchange(build_request(transaction_id, payload), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    check(message["type"] == MSG_BINDING_ERROR, "响应类型 = 0x0111")
    check(error_code(message) == 400, "ERROR-CODE = 400 Bad Request（不是静默丢弃）")
    check(ATTR_UNKNOWN_ATTRIBUTES not in message["types"], "400 不带 UNKNOWN-ATTRIBUTES")


def probe_change(args) -> None:
    """RFC 5780 §7.2/§8：CHANGE-REQUEST 决定回包的**源**地址。"""
    require(args.alt_ip is not None, "change 需要 --alt-ip")
    require(args.alt_port is not None, "change 需要 --alt-port")
    client = Client("127.0.0.1")
    transaction_id = os.urandom(12)
    payload = attribute(ATTR_CHANGE_REQUEST, struct.pack("!I", args.change))
    try:
        response, source = client.udp_exchange(build_request(transaction_id, payload), args.server_addr)
    finally:
        client.close()

    expect_change = args.change
    expected_ip = args.alt_ip if expect_change & CHANGE_IP else args.server_addr[0]
    expected_port = args.alt_port if expect_change & CHANGE_PORT else args.server_addr[1]
    check(
        (source[0], source[1]) == (expected_ip, expected_port),
        f"回包源 = {expected_ip}:{expected_port}（change={expect_change:#04x}）",
    )

    message = decode(response)
    expect_success(message, transaction_id)
    # 一旦开了 RFC 5780，RESPONSE-ORIGIN 必须等于真实回包源，OTHER-ADDRESS 是「对角」地址。
    origin = attr(message, ATTR_RESPONSE_ORIGIN)
    other = attr(message, ATTR_OTHER_ADDRESS)
    check(origin is not None, "带 RESPONSE-ORIGIN")
    check(other is not None, "带 OTHER-ADDRESS")
    check(
        decode_address(origin) == format_addr(*source),
        f"RESPONSE-ORIGIN = 真实回包源 {format_addr(*source)}",
    )
    diagonal_ip = args.alt_ip if not expect_change & CHANGE_IP else args.server_addr[0]
    diagonal_port = args.alt_port if not expect_change & CHANGE_PORT else args.server_addr[1]
    check(
        decode_address(other) == format_addr(diagonal_ip, diagonal_port),
        f"OTHER-ADDRESS = 对角地址 {format_addr(diagonal_ip, diagonal_port)}",
    )


def probe_rfc5780_attrs(args) -> None:
    """不开 CHANGE-REQUEST，只验 RESPONSE-ORIGIN + OTHER-ADDRESS 的值。"""
    require(args.alt_ip is not None and args.alt_port is not None, "需要 --alt-ip/--alt-port")
    client = client_for(args.server_addr)
    transaction_id = os.urandom(12)
    try:
        response, source = client.udp_exchange(build_request(transaction_id), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    expect_success(message, transaction_id)
    check(
        decode_address(attr(message, ATTR_RESPONSE_ORIGIN)) == format_addr(*source),
        "RESPONSE-ORIGIN = 入口 socket",
    )
    check(
        decode_address(attr(message, ATTR_OTHER_ADDRESS))
        == format_addr(args.alt_ip, args.alt_port),
        f"OTHER-ADDRESS = {format_addr(args.alt_ip, args.alt_port)}",
    )


def probe_tcp(args) -> None:
    """RFC 5389 §7.2.2：TCP 按头部 Message Length 分帧，两条流水请求各回一条。"""
    client = Client("127.0.0.1", tcp=True)
    local = client.local()
    transaction_ids = [os.urandom(12), os.urandom(12)]
    # 两条请求**一次写入**：服务端必须按头部长度分帧，而不是把整个缓冲当一条。
    pipelined = b"".join(build_request(tid) for tid in transaction_ids)
    try:
        client.tcp_connect(args.server_addr)
        client.tcp_send(pipelined)
        responses = [client.tcp_read_frame(), client.tcp_read_frame()]
    finally:
        client.close()

    for index, (response, transaction_id) in enumerate(
        zip(responses, transaction_ids), start=1
    ):
        message = decode(response)
        expect_success(message, transaction_id)
        check(
            decode_xor_mapped(attr(message, ATTR_XOR_MAPPED_ADDRESS), transaction_id)
            == format_addr(*local),
            f"第 {index} 条响应映射到客户端地址",
        )


def probe_ipv6(args) -> None:
    """IPv6 监听：绑定 `[::1]` 时能收到请求并正确回映射地址。"""
    try:
        client = Client("::1")
    except OSError as error:
        raise SystemExit(SKIP) from error
    local = client.local()
    transaction_id = os.urandom(12)
    try:
        response, source = client.udp_exchange(build_request(transaction_id), args.server_addr)
    finally:
        client.close()

    message = decode(response)
    expect_success(message, transaction_id)
    mapped = attr(message, ATTR_XOR_MAPPED_ADDRESS)
    check(mapped is not None, "带 XOR-MAPPED-ADDRESS")
    check(mapped[1] == 0x02, "地址族 = IPv6 (0x02)")
    check(
        decode_xor_mapped(mapped, transaction_id) == f"[{local[0]}]:{local[1]}",
        "XOR-MAPPED-ADDRESS = 客户端 IPv6 地址",
    )


def add_fingerprint(transaction_id: bytes, attributes: bytes = b"") -> bytes:
    """按 RFC 5389 §15.5 追加 FINGERPRINT（CRC 覆盖到该属性之前，Length 已含它）。"""
    body = attributes + b"\x00" * 8  # 占位的 FINGERPRINT（之后填值）
    header = (
        struct.pack("!HH", MSG_BINDING_REQUEST, len(body))
        + struct.pack("!I", MAGIC_COOKIE)
        + transaction_id
    )
    value = (zlib.crc32(header + attributes) ^ FINGERPRINT_XOR).to_bytes(4, "big")
    return header + attributes + attribute(ATTR_FINGERPRINT, value)


def append_attribute(frame: bytes, attr_type: int, value: bytes) -> bytes:
    """在整帧之后追加一个属性，并把头部 Length 相应调大。"""
    extra = attribute(attr_type, value)
    header = bytearray(frame[:20])
    header[2:4] = struct.pack("!H", len(frame) - 20 + len(extra))
    return bytes(header) + frame[20:] + extra


def probe_fingerprint(args) -> None:
    """`--check-fingerprint`：合法 → 200；错值 / 非末位 → 400（RFC 5389 §15.5）。"""
    client = client_for(args.server_addr)
    try:
        transaction_id = os.urandom(12)
        valid = add_fingerprint(transaction_id)
        response, _ = client.udp_exchange(valid, args.server_addr)
        expect_success(decode(response), transaction_id)
        print("ok: 合法 FINGERPRINT 得到普通 Binding 响应")

        bad = bytearray(add_fingerprint(os.urandom(12)))
        bad[-1] ^= 0xFF
        response, _ = client.udp_exchange(bytes(bad), args.server_addr)
        check(error_code(decode(response)) == 400, "错值 FINGERPRINT → 400 Bad Request")

        misplaced = append_attribute(add_fingerprint(os.urandom(12)), ATTR_PADDING, b"\x00")
        response, _ = client.udp_exchange(misplaced, args.server_addr)
        check(error_code(decode(response)) == 400, "FINGERPRINT 不在末位 → 400 Bad Request")
    finally:
        client.close()


def probe_fingerprint_drop(args) -> None:
    """`--fingerprint-action drop`：错值不回应，但服务仍然活着。"""
    client = client_for(args.server_addr)
    try:
        bad = bytearray(add_fingerprint(os.urandom(12)))
        bad[-1] ^= 0xFF
        client.socket.sendto(bytes(bad), args.server_addr)
        client.socket.settimeout(0.3)
        try:
            client.socket.recvfrom(4096)
            raise Fail("drop 模式下错值 FINGERPRINT 不应有响应")
        except socket.timeout:
            print("ok: drop 模式对错值 FINGERPRINT 静默（无响应）")

        # 服务没有被拖死：合法请求仍然得到 200。
        client.socket.settimeout(3.0)
        transaction_id = os.urandom(12)
        response, _ = client.udp_exchange(add_fingerprint(transaction_id), args.server_addr)
        expect_success(decode(response), transaction_id)
        print("ok: drop 模式之后合法 FINGERPRINT 仍得到 200")
    finally:
        client.close()


def probe_alternate(args) -> None:
    """`--alternate-server`：Binding 回 300 + ALTERNATE-SERVER（RFC 5389 §15.11）。"""
    require(args.alternate is not None, "alternate 需要 --alternate")
    client = client_for(args.server_addr)
    transaction_id = os.urandom(12)
    # 带 CHANGE-REQUEST：重定向优先于 RFC 5780，仍回 300 且不换源。
    request = build_request(
        transaction_id, attribute(ATTR_CHANGE_REQUEST, struct.pack("!I", CHANGE_PORT))
    )
    try:
        response, source = client.udp_exchange(request, args.server_addr)
    finally:
        client.close()

    message = decode(response)
    check(message["type"] == MSG_BINDING_ERROR, "响应类型 = 0x0111（错误响应）")
    check(error_code(message) == 300, "ERROR-CODE = 300 Try Alternate")
    alternate = attr(message, ATTR_ALTERNATE_SERVER)
    check(alternate is not None, "带 ALTERNATE-SERVER")
    check(decode_address(alternate) == args.alternate, f"ALTERNATE-SERVER = {args.alternate}")
    check(
        ATTR_XOR_MAPPED_ADDRESS not in message["types"],
        "300 不带 XOR-MAPPED-ADDRESS（它是指令，不是映射答案）",
    )
    check(
        (source[0], source[1]) == (args.server_addr[0], args.server_addr[1]),
        "300 仍从入口 socket 回（重定向优先于 CHANGE-REQUEST）",
    )


MODES = {
    "basic": probe_basic,
    "mapped": probe_mapped,
    "ice": probe_ice,
    "auth": probe_auth,
    "auth-long-term": probe_auth_long_term,
    "unknown": probe_unknown,
    "padding": probe_padding,
    "response-port": probe_response_port,
    "padding-response-port": probe_padding_response_port,
    "change": probe_change,
    "rfc5780-attrs": probe_rfc5780_attrs,
    "tcp": probe_tcp,
    "ipv6": probe_ipv6,
    "fingerprint": probe_fingerprint,
    "fingerprint-drop": probe_fingerprint_drop,
    "alternate": probe_alternate,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="rstun 互操作探针")
    parser.add_argument("mode", choices=sorted(MODES), help="要验证的协议行为")
    parser.add_argument("--server", required=True, help="被测服务 host:port")
    parser.add_argument("--alt-ip", help="RFC 5780 第二地址（change / rfc5780-attrs）")
    parser.add_argument("--alt-port", type=int, help="RFC 5780 第二端口")
    parser.add_argument("--alternate", help="期望的 ALTERNATE-SERVER 地址（alternate 模式）")
    parser.add_argument("--change", type=lambda text: int(text, 0), default=0,
                        help="CHANGE-REQUEST 标志位（0x02 换端口 / 0x04 换 IP / 0x06 两者）")
    parser.add_argument("--size", type=int, default=128, help="padding 模式的 PADDING 长度")
    parser.add_argument("--auth-user", default="user", help="auth-long-term 模式的用户名")
    parser.add_argument("--auth-password", default="pass", help="auth-long-term 模式的口令")
    parser.add_argument("--auth-realm", default="example.org", help="auth-long-term 模式的 realm")
    args = parser.parse_args()

    args.server_addr = parse_addr(args.server)
    print(f"[probe] mode={args.mode} server={args.server_addr[0]}:{args.server_addr[1]}")
    try:
        MODES[args.mode](args)
    except Fail as error:
        print(f"FAIL: {error}")
        return 1
    except socket.timeout:
        print("FAIL: 超时（服务未响应）")
        return 1
    except OSError as error:
        print(f"FAIL: 网络错误 {error}")
        return 1
    print(f"[probe] {args.mode} 通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
