#!/usr/bin/env python3
"""Fake TCP load balancer for the TURN multi-instance lab.

Accepts a TCP connection, picks a backend **per connection** (round robin, so
consecutive client connections land on different instances) and relays bytes in
both directions. A TURN control connection therefore stays on one instance,
while the `ConnectionBind` connection of the same client can land on the other —
exactly the cross-instance shape M3 has to route.

Usage:
    python3 rstun-turn-tcp-lb.py --listen 127.0.0.1:34986 \
        --backend 127.0.0.1:34980 --backend 127.0.0.2:34980 \
        --ready-file /tmp/lb.ready

Each routed connection is logged as `route <client> -> <backend>` so the lab can
tell which instance served an entry.

TLS is byte-transparent, so the same proxy carries `turns:` connections; the
handshake is between the client and the backend.
"""

import argparse
import selectors
import socket
import sys
import threading


def split_address(text: str) -> tuple[str, int]:
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError(f"invalid address {text!r}")
    return host, int(port)


class Relay(threading.Thread):
    def __init__(
        self,
        client: socket.socket,
        backend: tuple[str, int],
        source: tuple[str, int] | None,
    ) -> None:
        super().__init__(daemon=True)
        self.client = client
        self.backend = backend
        self.source = source

    def run(self) -> None:
        try:
            if self.source is None:
                upstream = socket.create_connection(self.backend)
            else:
                # Fixed upstream source port: lets the multi-instance lab pick a
                # 5-tuple whose owner it computed in advance.
                upstream = socket.socket(
                    socket.AF_INET6 if ":" in self.source[0] else socket.AF_INET,
                    socket.SOCK_STREAM,
                )
                upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                upstream.bind(self.source)
                upstream.connect(self.backend)
        except OSError as error:
            print(f"lb: backend {self.backend} unreachable: {error}", flush=True)
            self.client.close()
            return
        print(f"route {self.client.getpeername()} -> {self.backend}", flush=True)
        selector = selectors.DefaultSelector()
        selector.register(self.client, selectors.EVENT_READ, upstream)
        selector.register(upstream, selectors.EVENT_READ, self.client)
        open_directions = 2
        try:
            while open_directions:
                for key, _ in selector.select():
                    source = key.fileobj
                    destination = key.data
                    data = source.recv(65536)
                    if not data:
                        open_directions -= 1
                        selector.unregister(source)
                        # Propagate the half-close instead of tearing the other
                        # direction down: RFC 6062 half-close tests rely on it.
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    destination.sendall(data)
        except OSError:
            pass
        finally:
            selector.close()
            self.client.close()
            upstream.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="round-robin TCP load balancer")
    parser.add_argument("--listen", required=True, type=split_address)
    parser.add_argument("--backend", action="append", required=True, type=split_address)
    parser.add_argument("--ready-file", default="")
    parser.add_argument(
        "--source-port", type=int, default=0,
        help="bind every upstream connection to this local port (lab determinism)",
    )
    args = parser.parse_args()

    host, port = args.listen
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    bound = listener.getsockname()
    if args.ready_file:
        with open(args.ready_file, "w", encoding="utf-8") as handle:
            handle.write(f"{bound[0]}:{bound[1]}\n")
    print(
        f"lb: listening on {bound[0]}:{bound[1]} -> "
        + ", ".join(f"{b[0]}:{b[1]}" for b in args.backend),
        flush=True,
    )
    turn = 0
    try:
        while True:
            client, _ = listener.accept()
            backend = args.backend[turn % len(args.backend)]
            turn += 1
            source = (host, args.source_port) if args.source_port else None
            Relay(client, backend, source).start()
    except KeyboardInterrupt:
        return 0
    finally:
        listener.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        print(f"lb: {error}", file=sys.stderr)
        sys.exit(2)
