#!/usr/bin/env python3
"""Minimal TURN (RFC 8656) probe: standard library only.

Why a second probe next to `rstun-interop-probe.py`: the STUN probe asserts
Binding behaviour; TURN needs a *stateful* client (challenge → Allocate →
CreatePermission → Send/Data → ChannelBind → Refresh) before anything can be
said about relayed bytes. This one does exactly that and prints one canonical
line per step, so the same script can be run against this server and against
coturn and the two outputs diffed:

    python3 script/lab/rstun-turn-probe.py lifecycle --server 127.0.0.1:34980
    python3 script/lab/rstun-turn-probe.py relay     --server 127.0.0.1:34980
    python3 script/lab/rstun-turn-probe.py relay     --server '[::1]:34980' --family inet6
    python3 script/lab/rstun-turn-probe.py auth      --server 127.0.0.1:34980 \
        --nonce-lifetime 1

`--family inet6` moves the client and the peer to `::1` and asserts that
`XOR-RELAYED-ADDRESS` names an IPv6 address (the IPv6 relay path that used to
have no regression at all). The `loopback` / `permission-limit` modes keep
their hard-coded IPv4 peers and are only meaningful with the default family.

Exit code: 0 = every assertion passed; 1 = assertion failed; 2 = usage;
77 = environment/tool problem (the shell wrapper turns that into SKIP).

Output is deliberately stable: transaction ids, nonces and ports are never
printed, so `diff` between two servers is meaningful.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

MAGIC_COOKIE = 0x2112A442
HEADER_LEN = 20

METHOD_ALLOCATE = 0x003
METHOD_REFRESH = 0x004
METHOD_SEND = 0x006
METHOD_DATA = 0x007
METHOD_CREATE_PERMISSION = 0x008
METHOD_CHANNEL_BIND = 0x009

CLASS_REQUEST = 0
CLASS_INDICATION = 1
CLASS_SUCCESS = 2
CLASS_ERROR = 3

ATTR_CHANNEL_NUMBER = 0x000C
ATTR_LIFETIME = 0x000D
ATTR_XOR_PEER_ADDRESS = 0x0012
ATTR_DATA = 0x0013
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_EVEN_PORT = 0x0018
ATTR_REQUESTED_TRANSPORT = 0x0019
ATTR_DONT_FRAGMENT = 0x001A
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022

TRANSPORT_UDP = 17
CHANNEL = 0x4000


class Probe:
    def __init__(self, args: argparse.Namespace) -> None:
        self.server = (args.host, args.port)
        self.user = args.user
        self.password = args.password
        self.realm = args.realm
        self.default_lifetime = args.default_lifetime
        self.strict_refresh = not args.lenient_refresh
        self.key = hashlib.md5(
            f"{self.user}:{self.realm}:{self.password}".encode()
        ).digest()
        self.timeout = args.timeout
        # `--family inet6`: client, peer and the relay all live on ::1. The
        # XOR addresses have to be encoded/decoded per family, so this is a
        # probe-wide setting, not a per-call one.
        self.family = args.family
        self.af = socket.AF_INET6 if args.family == "inet6" else socket.AF_INET
        self.bind = ("::1", 0) if self.af == socket.AF_INET6 else ("127.0.0.1", 0)
        self.show_relay = args.show_relay
        self.socket = socket.socket(self.af, socket.SOCK_DGRAM)
        self.socket.settimeout(args.timeout)
        self.nonce = ""
        self.sequence = 0
        self.failures = 0

    # -- wire ------------------------------------------------------------

    def _transaction(self) -> bytes:
        self.sequence += 1
        return struct.pack("!QI", int(time.time() * 1000) & 0xFFFFFFFF, self.sequence)[-12:]

    @staticmethod
    def _message_type(method: int, klass: int) -> int:
        return (
            (method & 0x000F)
            | ((method & 0x0070) << 1)
            | ((method & 0x0F80) << 2)
            | ((klass & 0b10) << 7)
            | ((klass & 0b01) << 4)
        )

    @staticmethod
    def _attribute(attr_type: int, value: bytes) -> bytes:
        padded = value + b"\0" * ((4 - len(value) % 4) % 4)
        return struct.pack("!HH", attr_type, len(value)) + padded

    def _encode(
        self, method: int, klass: int, transaction: bytes, attributes: list[bytes]
    ) -> bytes:
        body = b"".join(attributes)
        return (
            struct.pack("!HH", self._message_type(method, klass), len(body))
            + struct.pack("!I", MAGIC_COOKIE)
            + transaction
            + body
        )

    def _seal(self, frame: bytes) -> bytes:
        adjusted = len(frame) - HEADER_LEN + 24
        prefix = frame[:2] + struct.pack("!H", adjusted) + frame[4:]
        mac = hmac.new(self.key, prefix, hashlib.sha1).digest()
        return prefix + struct.pack("!HH", ATTR_MESSAGE_INTEGRITY, 20) + mac

    def _xor_address(self, address: tuple[str, int], transaction: bytes) -> bytes:
        mask = struct.pack("!I", MAGIC_COOKIE) + transaction
        if self.af == socket.AF_INET6:
            ip = socket.inet_pton(socket.AF_INET6, address[0])
            return (
                b"\0\x02"
                + struct.pack("!H", address[1] ^ (MAGIC_COOKIE >> 16))
                + bytes(a ^ b for a, b in zip(ip, mask))
            )
        ip = socket.inet_aton(address[0])
        return (
            b"\0\x01"
            + struct.pack("!H", address[1] ^ (MAGIC_COOKIE >> 16))
            + bytes(a ^ b for a, b in zip(ip, mask))
        )

    @staticmethod
    def _decode_xor_address(value: bytes, transaction: bytes) -> tuple[str, int]:
        family = value[1]
        port = struct.unpack("!H", value[2:4])[0] ^ (MAGIC_COOKIE >> 16)
        mask = struct.pack("!I", MAGIC_COOKIE) + transaction
        if family == 0x01:
            ip = bytes(a ^ b for a, b in zip(value[4:8], mask))
            return socket.inet_ntoa(ip), port
        if family == 0x02:
            ip = bytes(a ^ b for a, b in zip(value[4:20], mask))
            return socket.inet_ntop(socket.AF_INET6, ip), port
        raise ValueError(f"unknown XOR address family {family:#04x}")

    def build_request(
        self,
        method: int,
        transaction: bytes,
        attributes: list[bytes],
        *,
        authenticate: bool,
    ) -> bytes:
        if authenticate:
            attributes = attributes + [
                self._attribute(ATTR_USERNAME, self.user.encode()),
                self._attribute(ATTR_REALM, self.realm.encode()),
                self._attribute(ATTR_NONCE, self.nonce.encode()),
            ]
        frame = self._encode(method, CLASS_REQUEST, transaction, attributes)
        return self._seal(frame) if authenticate else frame

    def exchange(self, frame: bytes) -> bytes:
        self.socket.sendto(frame, self.server)
        reply, _ = self.socket.recvfrom(65535)
        return reply

    def request(
        self,
        method: int,
        attributes: list[bytes],
        *,
        authenticate: bool,
    ) -> tuple[int, list[tuple[int, bytes]], bytes]:
        transaction = self._transaction()
        frame = self.build_request(method, transaction, attributes, authenticate=authenticate)
        reply = self.exchange(frame)
        return self._parse(reply, transaction)

    def reconnect(self) -> None:
        """New source port = new TURN 5-tuple (per-case isolation)."""
        self.socket.close()
        self.socket = socket.socket(self.af, socket.SOCK_DGRAM)
        self.socket.settimeout(self.timeout)
        self.nonce = ""

    def set_identity(self, user: str, password: str) -> None:
        """Switch credentials on the same socket (same 5-tuple)."""
        self.user = user
        self.password = password
        self.key = hashlib.md5(f"{user}:{self.realm}:{password}".encode()).digest()

    @staticmethod
    def _software(attributes: list[tuple[int, bytes]]) -> bool:
        return any(attr_type == ATTR_SOFTWARE for attr_type, _ in attributes)

    @staticmethod
    def _parse(reply: bytes, transaction: bytes) -> tuple[int, list[tuple[int, bytes]], bytes]:
        msg_type, length = struct.unpack("!HH", reply[:4])
        assert reply[8:20] == transaction, "transaction id mismatch"
        body = reply[HEADER_LEN : HEADER_LEN + length]
        attributes: list[tuple[int, bytes]] = []
        offset = 0
        while offset < len(body):
            attr_type, attr_length = struct.unpack("!HH", body[offset : offset + 4])
            value = body[offset + 4 : offset + 4 + attr_length]
            attributes.append((attr_type, value))
            offset += 4 + attr_length + ((4 - attr_length % 4) % 4)
        return msg_type, attributes, body

    @staticmethod
    def _error_code(attributes: list[tuple[int, bytes]]) -> int | None:
        for attr_type, value in attributes:
            if attr_type == ATTR_ERROR_CODE:
                return value[2] * 100 + value[3]
        return None

    @staticmethod
    def _lifetime(attributes: list[tuple[int, bytes]]) -> int | None:
        for attr_type, value in attributes:
            if attr_type == ATTR_LIFETIME:
                return struct.unpack("!I", value)[0]
        return None

    def _nonce(self, attributes: list[tuple[int, bytes]]) -> str:
        for attr_type, value in attributes:
            if attr_type == ATTR_NONCE:
                return value.decode()
        return ""

    # -- assertions ------------------------------------------------------

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"ok: {name}" + (f" {detail}" if detail else ""))
        else:
            self.failures += 1
            print(f"FAIL: {name}" + (f" {detail}" if detail else ""))

    # -- steps -----------------------------------------------------------

    def challenge(self) -> None:
        transaction = self._transaction()
        frame = self._encode(
            METHOD_ALLOCATE,
            CLASS_REQUEST,
            transaction,
            [
                self._attribute(ATTR_REQUESTED_TRANSPORT, bytes([TRANSPORT_UDP, 0, 0, 0])),
                self._attribute(ATTR_EVEN_PORT, b"\x80"),
            ],
        )
        self.socket.sendto(frame, self.server)
        reply, _ = self.socket.recvfrom(65535)
        msg_type, attributes, _ = self._parse(reply, transaction)
        code = self._error_code(attributes)
        self.nonce = self._nonce(attributes)
        self.check(
            "challenge",
            msg_type & 0x0110 == 0x0110 and code == 401 and bool(self.nonce),
            f"code={code}",
        )

    def allocate_frame(self, transaction: bytes) -> bytes:
        return self.build_request(
            METHOD_ALLOCATE,
            transaction,
            [
                self._attribute(ATTR_REQUESTED_TRANSPORT, bytes([TRANSPORT_UDP, 0, 0, 0])),
                self._attribute(ATTR_LIFETIME, struct.pack("!I", 300)),
                self._attribute(ATTR_EVEN_PORT, b"\x80"),
            ],
            authenticate=True,
        )

    def check_allocate(
        self,
        reply: bytes,
        transaction: bytes,
        label: str = "allocate",
        show_lifetime: bool = True,
    ) -> tuple[str, int] | None:
        msg_type, attributes, _ = self._parse(reply, transaction)
        code = self._error_code(attributes)
        lifetime = self._lifetime(attributes)
        relayed = None
        for attr_type, value in attributes:
            if attr_type == ATTR_XOR_RELAYED_ADDRESS:
                relayed = self._decode_xor_address(value, transaction)
        self.check(
            label,
            msg_type & 0x0110 == 0x0100 and code is None and relayed is not None,
            (
                f"code={code} lifetime={lifetime} software={self._software(attributes)}"
                if show_lifetime
                else f"code={code} software={self._software(attributes)}"
            ),
        )
        # A relay of the wrong family would make the client send to an address
        # that cannot carry its traffic (`requested_address_family` modes cover
        # the explicit requests). The port is never printed: it changes per run.
        if relayed is not None:
            relay_v6 = ":" in relayed[0]
            self.check(
                f"{label}-family",
                relay_v6 == (self.af == socket.AF_INET6),
                f"relay-family={'inet6' if relay_v6 else 'inet'}",
            )
            if self.show_relay:
                print(f"info: relay={relayed[0]}:{relayed[1]}")
        return relayed

    def allocate(self) -> tuple[str, int] | None:
        transaction = self._transaction()
        return self.check_allocate(self.exchange(self.allocate_frame(transaction)), transaction)

    def refresh(self, seconds: int) -> None:
        msg_type, attributes, _ = self.request(
            METHOD_REFRESH,
            [self._attribute(ATTR_LIFETIME, struct.pack("!I", seconds))],
            authenticate=True,
        )
        code = self._error_code(attributes)
        lifetime = self._lifetime(attributes)
        # RFC 8656 §7.2: the server default is the floor, so asking for less
        # than 600 s gets 600 s from both coturn and this server.
        if seconds == 0:
            expected = 0
        else:
            expected = seconds if seconds > self.default_lifetime else self.default_lifetime
        self.check(
            f"refresh-{seconds}",
            msg_type & 0x0110 == 0x0100 and code is None and lifetime == expected,
            f"code={code} lifetime={lifetime}",
        )

    def refresh_without_lifetime(self) -> None:
        # RFC 8656 §8.2: absent LIFETIME → server default.
        msg_type, attributes, _ = self.request(METHOD_REFRESH, [], authenticate=True)
        code = self._error_code(attributes)
        lifetime = self._lifetime(attributes)
        self.check(
            "refresh-no-lifetime",
            msg_type & 0x0110 == 0x0100 and code is None and lifetime == self.default_lifetime,
            f"code={code} lifetime={lifetime}",
        )

    def expect_error(
        self, label: str, method: int, attributes: list[bytes], expected: int
    ) -> None:
        _, attributes, _ = self.request(method, attributes, authenticate=True)
        code = self._error_code(attributes)
        self.check(label, code == expected, f"code={code}")

    def expect_error_with_tid(
        self,
        label: str,
        method: int,
        transaction: bytes,
        attributes: list[bytes],
        expected: int,
    ) -> None:
        reply = self.exchange(
            self.build_request(method, transaction, attributes, authenticate=True)
        )
        _, parsed, _ = self._parse(reply, transaction)
        code = self._error_code(parsed)
        self.check(label, code == expected, f"code={code}")

    def refresh_expect(self, seconds: int, expected: int) -> None:
        _, attributes, _ = self.request(
            METHOD_REFRESH,
            [self._attribute(ATTR_LIFETIME, struct.pack("!I", seconds))],
            authenticate=True,
        )
        code = self._error_code(attributes)
        if self.strict_refresh:
            self.check(f"refresh-error-{seconds}", code == expected, f"code={code}")
        else:
            # coturn is lenient here (it answers 200 and resurrects the
            # allocation); record the observation, do not judge it as a defect.
            print(f"info: refresh-after-release code={code}")

    def create_permission(self, peer: tuple[str, int]) -> None:
        # The XOR mask binds the peer address to the transaction id, so the id
        # has to exist before the attributes are built.
        transaction = self._transaction()
        frame = self._encode(
            METHOD_CREATE_PERMISSION,
            CLASS_REQUEST,
            transaction,
            [
                self._attribute(
                    ATTR_XOR_PEER_ADDRESS, self._xor_address(peer, transaction)
                ),
                self._attribute(ATTR_USERNAME, self.user.encode()),
                self._attribute(ATTR_REALM, self.realm.encode()),
                self._attribute(ATTR_NONCE, self.nonce.encode()),
            ],
        )
        self.socket.sendto(self._seal(frame), self.server)
        reply, received_transaction = self._recv()
        _, attributes, _ = self._parse(reply, received_transaction)
        self.check(
            "create-permission", self._error_code(attributes) is None,
            f"code={self._error_code(attributes)}",
        )

    def channel_bind(self, peer: tuple[str, int]) -> None:
        transaction = self._transaction()
        value = struct.pack("!H", CHANNEL) + b"\0\0"
        frame = self._encode(
            METHOD_CHANNEL_BIND,
            CLASS_REQUEST,
            transaction,
            [
                self._attribute(ATTR_CHANNEL_NUMBER, value),
                self._attribute(ATTR_XOR_PEER_ADDRESS, self._xor_address(peer, transaction)),
                self._attribute(ATTR_USERNAME, self.user.encode()),
                self._attribute(ATTR_REALM, self.realm.encode()),
                self._attribute(ATTR_NONCE, self.nonce.encode()),
            ],
        )
        self.socket.sendto(self._seal(frame), self.server)
        reply, received_transaction = self._recv()
        _, attributes, _ = self._parse(reply, received_transaction)
        self.check(
            "channel-bind", self._error_code(attributes) is None,
            f"code={self._error_code(attributes)}",
        )

    def _recv(self) -> tuple[bytes, bytes]:
        reply, _ = self.socket.recvfrom(65535)
        transaction = reply[8:20]
        return reply, transaction

    def send_to_peer(self, peer: tuple[str, int], payload: bytes) -> None:
        transaction = self._transaction()
        frame = self._encode(
            METHOD_SEND,
            CLASS_INDICATION,
            transaction,
            [
                self._attribute(ATTR_XOR_PEER_ADDRESS, self._xor_address(peer, transaction)),
                self._attribute(ATTR_DATA, payload),
            ],
        )
        self.socket.sendto(frame, self.server)

    def send_channel_data(self, payload: bytes) -> None:
        frame = struct.pack("!HH", CHANNEL, len(payload)) + payload
        self.socket.sendto(frame, self.server)

    def recv_indication(self) -> tuple[bytes | None, str | None]:
        """Return `(data, kind)` of the next Data indication or ChannelData."""
        try:
            reply, _ = self.socket.recvfrom(65535)
        except socket.timeout:
            return None, None
        first = reply[0]
        if first & 0xC0 == 0x40:  # ChannelData
            return reply[4:], "ChannelData"
        msg_type, length = struct.unpack("!HH", reply[:4])
        transaction = reply[8:20]
        body = reply[HEADER_LEN : HEADER_LEN + length]
        offset = 0
        data = None
        peer = None
        while offset < len(body):
            attr_type, attr_length = struct.unpack("!HH", body[offset : offset + 4])
            value = body[offset + 4 : offset + 4 + attr_length]
            if attr_type == ATTR_DATA:
                data = value
            elif attr_type == ATTR_XOR_PEER_ADDRESS:
                peer = self._decode_xor_address(value, transaction)[0].encode()
            offset += 4 + attr_length + ((4 - attr_length % 4) % 4)
        # An indication is (method 0x007 | class 01).
        if msg_type & 0x0110 != 0x0010:
            return None, None
        return data, "DataIndication"

    def close(self) -> None:
        self.socket.close()


def canonical_lifecycle(probe: Probe) -> None:
    probe.challenge()
    transaction = probe._transaction()
    frame = probe.allocate_frame(transaction)
    relayed = probe.check_allocate(probe.exchange(frame), transaction)
    if relayed is None:
        return

    # Same transaction id = retransmission: 200 and the same relay.
    retransmit = probe.check_allocate(
        probe.exchange(frame), transaction, "allocate-retransmit"
    )
    probe.check(
        "allocate-retransmit-same-relay",
        retransmit == relayed,
        f"same={retransmit == relayed}",
    )
    # A new transaction id on the same 5-tuple is an allocation mismatch.
    new_transaction = probe._transaction()
    reply = probe.exchange(probe.allocate_frame(new_transaction))
    _, attributes, _ = probe._parse(reply, new_transaction)
    probe.check(
        "allocate-new-tid-437",
        probe._error_code(attributes) == 437,
        f"code={probe._error_code(attributes)}",
    )

    probe.refresh(300)
    probe.refresh(60)
    probe.refresh_without_lifetime()
    probe.refresh(0)
    # After LIFETIME=0 the allocation is gone: Refresh is 437.
    probe.refresh_expect(60, 437)


def canonical_relay(probe: Probe) -> None:
    probe.challenge()
    relayed = probe.allocate()
    if relayed is None:
        return

    peer = socket.socket(probe.af, socket.SOCK_DGRAM)
    peer.bind(probe.bind)
    # 1s, not 0.5s: under a loaded host (full lab + coturn in parallel) the
    # relay round trip occasionally exceeds half a second, which surfaced as
    # `send-indication-bytes bytes=0` and a false diff against coturn.
    peer.settimeout(1.0)
    peer_address = peer.getsockname()

    probe.create_permission(peer_address)
    probe.channel_bind(peer_address)

    # Send indication (client → relay → peer).
    probe.send_to_peer(peer_address, b"send-indication")
    try:
        received = peer.recvfrom(65535)[0]
    except socket.timeout:
        received = None
    probe.check(
        "send-indication-bytes",
        received == b"send-indication",
        f"bytes={len(received) if received else 0}",
    )

    # Peer → relay → client: with a channel bound this must be ChannelData.
    peer.sendto(b"peer-to-client", relayed)
    data, kind = probe.recv_indication()
    probe.check(
        "peer-to-client-bytes",
        data == b"peer-to-client",
        f"kind={kind} bytes={len(data) if data else 0}",
    )

    # ChannelData (client → relay → peer).
    probe.send_channel_data(b"channel-data")
    try:
        received = peer.recvfrom(65535)[0]
    except socket.timeout:
        received = None
    probe.check(
        "channel-data-bytes",
        received == b"channel-data",
        f"bytes={len(received) if received else 0}",
    )

    # Declared length longer than the datagram → silently dropped.
    lying = struct.pack("!HH", CHANNEL, 20) + b"abc"
    probe.socket.sendto(lying, probe.server)
    try:
        received = peer.recvfrom(65535)[0]
    except socket.timeout:
        received = None
    probe.check(
        "lying-channel-data-dropped",
        received is None,
        f"received={received!r}",
    )
    peer.close()


def canonical_wrong_user(
    probe: Probe, other_user: str, other_password: str
) -> None:
    primary_user, primary_password = probe.user, probe.password
    probe.challenge()
    relayed = probe.allocate()
    if relayed is None:
        return

    peer = socket.socket(probe.af, socket.SOCK_DGRAM)
    peer.bind(probe.bind)
    peer_address = peer.getsockname()

    probe.set_identity(other_user, other_password)
    probe.expect_error(
        "wrong-user-refresh",
        METHOD_REFRESH,
        [probe._attribute(ATTR_LIFETIME, struct.pack("!I", 300))],
        441,
    )
    transaction = probe._transaction()
    probe.expect_error_with_tid(
        "wrong-user-create-permission",
        METHOD_CREATE_PERMISSION,
        transaction,
        [probe._attribute(ATTR_XOR_PEER_ADDRESS, probe._xor_address(peer_address, transaction))],
        441,
    )
    transaction = probe._transaction()
    probe.expect_error_with_tid(
        "wrong-user-release",
        METHOD_REFRESH,
        transaction,
        [probe._attribute(ATTR_LIFETIME, struct.pack("!I", 0))],
        441,
    )
    transaction = probe._transaction()
    probe.expect_error_with_tid(
        "wrong-user-channel-bind",
        METHOD_CHANNEL_BIND,
        transaction,
        [
            probe._attribute(ATTR_CHANNEL_NUMBER, struct.pack("!HH", 0x4000, 0)),
            probe._attribute(
                ATTR_XOR_PEER_ADDRESS, probe._xor_address(peer_address, transaction)
            ),
        ],
        441,
    )

    # The owner can still use the allocation: none of the 441 attempts may have
    # deleted or modified it.
    probe.set_identity(primary_user, primary_password)
    _, attributes, _ = probe.request(
        METHOD_REFRESH, [probe._attribute(ATTR_LIFETIME, struct.pack("!I", 300))],
        authenticate=True,
    )
    lifetime = [
        struct.unpack("!I", value)[0]
        for attr_type, value in attributes
        if attr_type == ATTR_LIFETIME
    ]
    probe.check(
        "wrong-user-owner-kept-allocation",
        bool(lifetime) and lifetime[0] >= 300,
        f"lifetime={lifetime}",
    )
    peer.close()


def canonical_permission_limit(probe: Probe) -> None:
    probe.challenge()
    if probe.allocate() is None:
        return
    first = ("127.0.0.1", 9)
    second = ("127.0.0.2", 9)
    third = ("127.0.0.3", 9)

    # One request with more peers than the remaining quota: 508, nothing added.
    transaction = probe._transaction()
    probe.expect_error_with_tid(
        "permission-limit-combined",
        METHOD_CREATE_PERMISSION,
        transaction,
        [
            probe._attribute(ATTR_XOR_PEER_ADDRESS, probe._xor_address(first, transaction)),
            probe._attribute(ATTR_XOR_PEER_ADDRESS, probe._xor_address(second, transaction)),
        ],
        508,
    )
    # The failed request installed nothing, so a single peer still succeeds.
    probe.create_permission(second)
    transaction = probe._transaction()
    probe.expect_error_with_tid(
        "permission-limit-single",
        METHOD_CREATE_PERMISSION,
        transaction,
        [probe._attribute(ATTR_XOR_PEER_ADDRESS, probe._xor_address(first, transaction))],
        508,
    )
    # ChannelBind installs an implicit permission and shares the same cap.
    transaction = probe._transaction()
    probe.expect_error_with_tid(
        "permission-limit-channel-bind",
        METHOD_CHANNEL_BIND,
        transaction,
        [
            probe._attribute(ATTR_CHANNEL_NUMBER, struct.pack("!H", CHANNEL) + b"\0\0"),
            probe._attribute(ATTR_XOR_PEER_ADDRESS, probe._xor_address(third, transaction)),
        ],
        508,
    )


def canonical_loopback(probe: Probe) -> None:
    probe.challenge()
    relayed = probe.allocate()
    if relayed is None:
        return
    # Only meaningful against a wildcard listener: the exact-address checks
    # cannot see 127.0.0.1:<listen-port>, the loopback rule must.
    targets = [probe.server, (probe.bind[0], 9)]
    for index, target in enumerate(targets):
        transaction = probe._transaction()
        probe.expect_error_with_tid(
            f"loopback-peer-{index}",
            METHOD_CREATE_PERMISSION,
            transaction,
            [probe._attribute(ATTR_XOR_PEER_ADDRESS, probe._xor_address(target, transaction))],
            403,
        )


def canonical_auth(probe: Probe, wait: float) -> None:
    probe.challenge()
    if wait > 0:
        time.sleep(wait)
    msg_type, attributes, transaction = probe.request(
        METHOD_ALLOCATE,
        [
            probe._attribute(ATTR_REQUESTED_TRANSPORT, bytes([TRANSPORT_UDP, 0, 0, 0])),
            probe._attribute(ATTR_LIFETIME, struct.pack("!I", 60)),
        ],
        authenticate=True,
    )
    code = probe._error_code(attributes)
    if wait > 0:
        # RFC 8656 §9.2: an expired nonce is 438 with a fresh NONCE.
        probe.check("expired-nonce-438", code == 438 and bool(probe._nonce(attributes)),
                    f"code={code}")
    else:
        success = msg_type & 0x0110 == 0x0100
        relayed = any(
            attr_type == ATTR_XOR_RELAYED_ADDRESS for attr_type, _ in attributes
        )
        probe.check("authenticated-allocate", success and code is None and relayed,
                    f"code={code}")
        if not success:
            return
        _, attributes, _ = probe.request(
            METHOD_REFRESH,
            [probe._attribute(ATTR_LIFETIME, struct.pack("!I", 0))],
            authenticate=True,
        )
        probe.check("release", code is None and probe._error_code(attributes) is None,
                    f"code={probe._error_code(attributes)}")


def rest_password(secret: str, username: str) -> str:
    """coturn `use-auth-secret`: base64(HMAC-SHA1(secret, username))."""
    digest = hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def canonical_rest(probe: Probe, secret: str, label: str) -> None:
    """TURN REST API credentials: valid / expired / wrong secret / `:` label.

    Independent of the server's own implementation: the password is computed
    here from the documented coturn rule, so a shared mistake cannot hide.
    """
    def case(name: str, expiry_offset: int, secret_used: str, *, expect_ok: bool = True) -> tuple[bool, int | None]:
        # Every case uses a **fresh 5-tuple**: an existing allocation must not
        # shadow the credential check (coturn answers 437 before 401 in that
        # shape, which would hide the thing this mode is about).
        probe.reconnect()
        probe.challenge()
        username = f"{int(time.time()) + expiry_offset}:{label}"
        probe.set_identity(username, rest_password(secret_used, username))
        transaction = probe._transaction()
        reply = probe.exchange(probe.allocate_frame(transaction))
        msg_type, attributes, _ = probe._parse(reply, transaction)
        code = probe._error_code(attributes)
        success = msg_type & 0x0110 == 0x0100
        if expect_ok:
            probe.check(name, success and code is None, f"code={code}")
        else:
            probe.check(name, code == 401 and not success, f"code={code}")
        return success, code

    def release() -> None:
        probe.request(
            METHOD_REFRESH,
            [probe._attribute(ATTR_LIFETIME, struct.pack("!I", 0))],
            authenticate=True,
        )

    valid, _ = case("rest-valid", 600, secret)
    if valid:
        release()

    # Expired: 401, never 438 — the nonce is fine, the username is not.
    probe.reconnect()
    probe.challenge()
    username = f"{int(time.time()) - 10}:{label}"
    probe.set_identity(username, rest_password(secret, username))
    transaction = probe._transaction()
    reply = probe.exchange(probe.allocate_frame(transaction))
    msg_type, attributes, _ = probe._parse(reply, transaction)
    code = probe._error_code(attributes)
    probe.check(
        "rest-expired-401",
        code == 401 and msg_type & 0x0110 != 0x0100,
        f"code={code}",
    )

    # Wrong secret: the derived password differs, so the MAC cannot match.
    case("rest-wrong-secret-401", 600, "not-the-secret", expect_ok=False)

    # The label is opaque and may itself contain the separator: coturn splits
    # on the **first** `:` only, and so must we (design §9 risk row).
    probe.reconnect()
    probe.challenge()
    colon_label = f"{label}:with:colons"
    username = f"{int(time.time()) + 600}:{colon_label}"
    probe.set_identity(username, rest_password(secret, username))
    transaction = probe._transaction()
    reply = probe.exchange(probe.allocate_frame(transaction))
    msg_type, attributes, _ = probe._parse(reply, transaction)
    code = probe._error_code(attributes)
    success = msg_type & 0x0110 == 0x0100
    probe.check("rest-label-with-colons", success and code is None, f"code={code}")
    if success:
        release()


def main() -> int:
    parser = argparse.ArgumentParser(description="minimal TURN client probe")
    parser.add_argument(
        "mode",
        choices=(
            "lifecycle",
            "relay",
            "auth",
            "wrong-password",
            "wrong-user",
            "loopback",
            "permission-limit",
            "rest",
        ),
    )
    parser.add_argument("--server", required=True, help="host:port of the TURN server")
    parser.add_argument("--user", default="turnuser")
    parser.add_argument("--password", default="turnpass")
    parser.add_argument("--realm", default="example.org")
    parser.add_argument("--other-user", default="otheruser")
    parser.add_argument("--other-password", default="otherpass")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument(
        "--default-lifetime", type=int, default=600,
        help="server default allocation lifetime (RFC 8656: values below it become it)",
    )
    parser.add_argument(
        "--lenient-refresh", action="store_true",
        help="record (do not fail) Refresh-after-release, for the coturn comparison",
    )
    parser.add_argument(
        "--rest-secret", default="", help="TURN REST API secret (rest mode)")
    parser.add_argument(
        "--rest-label", default="alice", help="REST username label (rest mode)")
    parser.add_argument(
        "--wait", type=float, default=0.0,
        help="seconds to hold the nonce before using it (auth mode)",
    )
    parser.add_argument(
        "--family", choices=("inet", "inet6"), default="inet",
        help="client/peer address family (inet6 binds ::1 and asserts an IPv6 relay)",
    )
    parser.add_argument(
        "--show-relay", action="store_true",
        help="print the relayed transport address (its port changes per run)",
    )
    args = parser.parse_args()

    # `[::1]:34980` for IPv6, `127.0.0.1:34980` for IPv4.
    server = args.server
    if server.startswith("["):
        host, _, rest = server[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = server.rpartition(":")
    if not host or not port.isdigit():
        print(f"invalid --server {args.server!r}", file=sys.stderr)
        return 2
    args.host = host
    args.port = int(port)

    probe = Probe(args)
    try:
        if args.mode == "lifecycle":
            canonical_lifecycle(probe)
        elif args.mode == "relay":
            canonical_relay(probe)
        elif args.mode == "auth":
            canonical_auth(probe, args.wait)
        elif args.mode == "wrong-user":
            canonical_wrong_user(probe, args.other_user, args.other_password)
        elif args.mode == "loopback":
            canonical_loopback(probe)
        elif args.mode == "permission-limit":
            canonical_permission_limit(probe)
        elif args.mode == "rest":
            if not args.rest_secret:
                print("FAIL: rest mode needs --rest-secret")
                return 1
            canonical_rest(probe, args.rest_secret, args.rest_label)
        else:
            probe.challenge()
            probe.key = b"definitely-not-the-password"
            msg_type, attributes, _ = probe.request(
                METHOD_ALLOCATE,
                [
                    probe._attribute(ATTR_REQUESTED_TRANSPORT, bytes([TRANSPORT_UDP, 0, 0, 0])),
                    probe._attribute(ATTR_LIFETIME, struct.pack("!I", 60)),
                ],
                authenticate=True,
            )
            code = probe._error_code(attributes)
            probe.check("wrong-password", code == 401, f"code={code}")
    finally:
        probe.close()
    return 1 if probe.failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, TimeoutError) as error:
        # Keep the output greppable: a dead port must read as a failed check,
        # not a Python traceback.
        print(f"FAIL: probe aborted: {error}")
        sys.exit(1)
