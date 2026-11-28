#!/usr/bin/env python3
"""Fake UDP load balancer for the TURN multi-instance lab.

Round-robins every client datagram to the configured backends and forwards each
reply back to the client that owns the upstream socket.

Why per-client upstream sockets: a backend behind a plain NAT-style LB must see
a *stable* client endpoint, otherwise the TURN 5-tuple changes on every packet
and no allocation can be found again. One upstream socket per client gives each
client a fixed `(LB address, upstream port)` pair on every instance while still
spreading its packets across backends. Replies come back from the LB address,
which is what a connected client (turnutils_uclient) will accept.

Usage:
    python3 rstun-turn-lb.py --listen 127.0.0.9:34990 \
        --backend 127.0.0.1:34980 --backend 127.0.0.2:34980 \
        --ready-file /tmp/lb.ready

The `--ready-file` is written (with the bound address) once the socket is up, so
the caller can wait for it instead of guessing a sleep.
"""

import argparse
import selectors
import socket
import sys


def split_address(text: str) -> tuple[str, int]:
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError(f"invalid address {text!r}")
    return host, int(port)


def main() -> int:
    parser = argparse.ArgumentParser(description="round-robin UDP load balancer")
    parser.add_argument("--listen", required=True, type=split_address)
    parser.add_argument("--backend", action="append", required=True, type=split_address)
    parser.add_argument("--ready-file", default="", help="write the bound address here")
    parser.add_argument(
        "--sticky", action="store_true",
        help="pin each client address to one backend (stateful transports such as DTLS)",
    )
    args = parser.parse_args()

    host, port = args.listen
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_DGRAM)
    listener.bind((host, port))
    listener.setblocking(False)
    bound = listener.getsockname()
    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as handle:
            handle.write(f"{bound[0]}:{bound[1]}\n")

    selector = selectors.DefaultSelector()
    selector.register(listener, selectors.EVENT_READ, ("listen", None))
    # one upstream socket per client, so the backends see a stable endpoint
    upstream_by_client: dict[tuple, socket.socket] = {}
    backend_by_client: dict[tuple, tuple[str, int]] = {}
    backends = args.backend
    turn = 0
    print(
        f"lb: listening on {bound[0]}:{bound[1]} -> "
        + ", ".join(f"{b[0]}:{b[1]}" for b in backends),
        flush=True,
    )
    try:
        while True:
            for key, _ in selector.select():
                kind, client = key.data
                sock = key.fileobj
                data, source = sock.recvfrom(65535)
                if kind == "listen":
                    client = source
                    upstream = upstream_by_client.get(client)
                    if upstream is None:
                        upstream = socket.socket(family, socket.SOCK_DGRAM)
                        upstream.bind((host, 0))
                        upstream.setblocking(False)
                        selector.register(upstream, selectors.EVENT_READ, ("upstream", client))
                        upstream_by_client[client] = upstream
                    if args.sticky:
                        target = backend_by_client.get(client)
                        if target is None:
                            target = backends[turn % len(backends)]
                            turn += 1
                            backend_by_client[client] = target
                    else:
                        target = backends[turn % len(backends)]
                        turn += 1
                    upstream.sendto(data, target)
                else:
                    listener.sendto(data, client)
    except KeyboardInterrupt:
        return 0
    finally:
        listener.close()
        for upstream in upstream_by_client.values():
            upstream.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        print(f"lb: {error}", file=sys.stderr)
        sys.exit(2)
