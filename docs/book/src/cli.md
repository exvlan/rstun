# 命令行（CLI）

两级命令：`rstun server [flags]` 起服务，裸 `rstun` 打印帮助。本页两个 help 片段由
`bash script/ci/check-docs.sh` 与真实二进制逐 token 比对（忽略折行），改 flag 必须同步改这里。

## `rstun --help`

<!-- check-docs: help=main -->
```console
$ rstun --help
Standalone STUN/TURN server (RFC 5389 Binding; RFC 5780 with --alt-listen; RFC 8656 relay over
UDP/TCP, turns: (TLS) and DTLS with --turn)

Usage: rstun <COMMAND>

Commands:
  server  Serve STUN Binding over UDP (and TCP with --tcp); TURN relay with --turn (UDP/TCP, turns:
          with the `tls` feature, DTLS with the `dtls` feature)
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## `rstun server --help`

<!-- check-docs: help=server -->
```console
$ rstun server --help
Serve STUN Binding over UDP (and TCP with --tcp); TURN relay with --turn (UDP/TCP, turns: with the
`tls` feature, DTLS with the `dtls` feature)

Usage: rstun server [OPTIONS]

Options:
      --listen <ADDR>
          address to bind over UDP (and TCP with --tcp), repeatable; defaults to 0.0.0.0:3478. With
          --alt-listen the first IPv4 address here is the RFC 5780 primary; every other address (and
          all --listen-v6) only serves plain Binding

      --listen-v6 <ADDR>
          IPv6 address to bind, repeatable; bound v6-only so it can coexist with --listen. Never
          part of RFC 5780: these sockets only serve plain Binding

      --alt-listen <ADDR>
          second public IP (RFC 5780 "other address"); enables CHANGE-REQUEST, RESPONSE-ORIGIN and
          OTHER-ADDRESS. Only the IP is used: the port comes from --alt-port. Primary = the first
          IPv4 --listen address; other addresses (including --listen-v6) stay plain Binding

      --alt-port <PORT>
          RFC 5780 "other port"; defaults to the --listen port + 1. Used as the source port of a
          `CHANGE-REQUEST` answer and as half of `OTHER-ADDRESS`. (`RESPONSE-PORT` names a
          *destination* port and never refers to this.)

      --tcp
          also answer STUN Binding over TCP on every listen address

      --mapped-address
          also emit the legacy MAPPED-ADDRESS (0x0001) next to XOR-MAPPED-ADDRESS, for RFC 3489-era
          clients; off by default (response bytes stay unchanged)

      --check-fingerprint
          validate FINGERPRINT (RFC 5389 §15.5) when a request carries one: it must be the last
          attribute and its CRC must match. Off by default, so a request without FINGERPRINT is
          answered exactly as before

      --fingerprint-action <ACTION>
          what a FINGERPRINT with a wrong CRC gets: `answer` = 400 Bad Request (the default), `drop`
          = no response. `drop` needs --check-fingerprint

          Possible values:
          - answer: `400 Bad Request` (RFC 5389 §15.5 makes a bad fingerprint a bad message)
          - drop:   No response at all — for deployments that do not want to answer probes with a
            broken fingerprint (still counted, see `ServerStats`)
          
          [default: answer]

      --alternate-server <ADDR>
          answer every Binding request with `300 Try Alternate` + ALTERNATE-SERVER (RFC 5389
          §15.11), pointing at this instance; repeatable, only the first address is used. Redirect
          wins over RFC 5780

      --verbose
          log every Binding request with its source and mapped address

      --rate-limit [<REQ/S>]
          per-source-IP token bucket (req/s), UDP and TCP; bare flag = 200. Sources named by --allow
          skip this bucket; off by default

      --rate-burst <N>
          burst size of the --rate-limit bucket; defaults to 2x its rate

      --rate-limit-port [<REQ/S>]
          per source IP+port token bucket (req/s); bare flag = 20

      --global-rate <REQ/S>
          server-wide token bucket (req/s): the last line before the sockets

      --max-inflight <N>
          cap on work held at once: one slot per UDP datagram (until answered) and per TCP
          connection (until closed). Over the cap, datagrams are dropped and connections refused

      --reflect-min-request <BYTES>
          refuse RESPONSE-PORT / CHANGE-REQUEST requests shorter than BYTES (default 20 = the STUN
          header; a 28-byte RFC 5780 probe must pass). Raising it trades RFC 5780 compatibility for
          a stricter floor

      --reflect-ratio <RATIO>
          refuse RESPONSE-PORT / CHANGE-REQUEST requests whose answer would exceed `max(request x
          RATIO, request + 32)` (default 2.0; the 32 bytes are the fixed XOR + RFC 5780 address
          attributes, SOFTWARE is omitted for small probes). Enables the guard

      --allow <CIDR>
          CIDR whose sources bypass the per-source rate limits and the reflection guard, repeatable

      --deny <CIDR>
          CIDR whose sources are refused outright, repeatable; wins ties with --allow

      --auth-user <USER>
          short-term credential user name (RFC 5389 §10.1); needs --auth-pass. Short-term only
          applies without --realm: the key is the password itself

      --auth-pass <PASS>
          password of --auth-user (short-term) or of the single long-term user

      --auth-file <PATH>
          file with one `user:password` per line ('#' comments and blank lines ignored); repeatable
          users for long-term, or several short-term users

      --realm <REALM>
          long-term credential realm (RFC 5389 §10.2); turns on the 401/438 flow. Needs
          --auth-secret and at least one user

      --auth-secret <SECRET>
          secret that signs the stateless NONCE (any string; the same value on every instance makes
          nonces interchangeable). Required with --realm

      --nonce-lifetime <SECONDS>
          NONCE lifetime in seconds (default 3600); only meaningful with --realm

      --auth-require-sha256
          long-term only: refuse PASSWORD-ALGORITHM=MD5 (401 unless the client uses SHA256). Needs
          --realm

      --health-listen <ADDR>
          serve `GET /healthz` (readiness) and `GET /metrics` (Prometheus text) on this TCP address,
          e.g. 127.0.0.1:9100. Off by default: without it no HTTP listener, no extra task and no
          change to the STUN paths

      --health-max-connections <N>
          cap on concurrent connections to the ops endpoint (default 64). A connection over the cap
          gets an immediate 503 and is closed, never queued — queueing would keep the fd the flood
          is trying to exhaust. Only meaningful with --health-listen

      --drain-timeout <SECONDS>
          how long a SIGTERM may take to drain in-flight work before exiting anyway (seconds,
          default 5; 0 = stop immediately). The exit code stays 0

      --turn
          enable the TURN (RFC 8656) relay on the STUN sockets (UDP/TCP client transports;
          turns:/DTLS need the tls/dtls build features). Requires long-term credentials: --realm,
          --auth-secret and at least one user

      --relay-ports <LO-HI>
          TURN relay port range, inclusive (`LO-HI`, default 49152-65535). Choose a range outside
          `net.ipv4.ip_local_port_range`

      --max-allocations-per-user <N>
          TURN: cap on concurrent allocations per authenticated user (default 8)

      --max-allocations-per-ip <N>
          TURN: cap on concurrent allocations per client IP (default 16)

      --permission-limit <N>
          TURN: cap on permissions per allocation (default 10)

      --allocation-lifetime <SECONDS>
          TURN: allocation lifetime in seconds (default 600, max 3600). Also caps whatever LIFETIME
          a client asks for

      --turn-tls-listen <ADDR>
          TURN over TLS (`turns:`) listen address, repeatable. Needs --tls-cert, --tls-key and a
          build with the `tls` feature (cargo build --features tls,dtls); TLS and plaintext never
          share a port (no ALPN sniffing)

      --turn-dtls-listen <ADDR>
          TURN over DTLS (1.2) listen address, repeatable. Needs --tls-cert, --tls-key (ECDSA P-256
          or Ed25519: what webrtc-dtls supports) and a build with the `dtls` feature

      --tls-cert <PATH>
          PEM certificate chain for --turn-tls-listen / --turn-dtls-listen

      --tls-key <PATH>
          PEM private key for --turn-tls-listen / --turn-dtls-listen (unencrypted PKCS#8, e.g.
          `openssl genpkey`)

      --tls-cert-poll <SECONDS>
          Certificate rotation poll interval in seconds (default 30; 0 = no polling, SIGHUP only).
          Needs --turn-tls-listen or --turn-dtls-listen. Windows has no SIGHUP, so 0 is refused
          there

      --rest-secret <SECRET>
          TURN REST API shared secret (coturn `use-auth-secret`): username = `<expiry>:<label>`,
          password = base64(HMAC-SHA1(secret, username)). Needs --realm and --auth-secret; wins over
          stored users

      --turn-bandwidth <BYTES/S>
          TURN: per-allocation bandwidth cap in bytes/second, each direction (default 1 MiB/s; 0 =
          unlimited). Over the cap packets are dropped

      --turn-tcp-relay
          TURN: also serve RFC 6062 **TCP allocations** (`REQUESTED-TRANSPORT=6`, outbound `Connect`
          + `ConnectionBind`). Off by default: without it a TCP Allocate is still `442` and the
          byte-frozen path is untouched. The passive mode (`ConnectionAttempt`, `uclient -P`) is not
          implemented yet

  -h, --help
          Print help (see a summary with '-h')
```

- 裸 `rstun`（无子命令）**打印帮助并以退出码 2 结束**：不给参数属于用法错误，
  不能悄悄起一个 `0.0.0.0:3478` 通配监听。
- `rstun --version` 打印 `rstun <version>`（版本串规则见 [README · 构建与运行](https://github.com/exvlan/rstun/blob/main/README.md#构建与运行) 与 `RSTUN_BUILD_VERSION`）。
  `--version` 只在**二进制级**：`rstun server --version` 会报错（子命令不自带版本号，
  避免出现两个版本串；CI 与镜像自检一律用 `rstun --version`）。
