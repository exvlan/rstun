//! `rstun`: a standalone RFC 5389 Binding server, with optional RFC 5780
//! NAT behaviour discovery.
//!
//! Why this crate exists: full STUN/TURN servers (coturn et al.) are heavy and
//! need external TLS/libevent stacks plus multi-hundred-line config, while the
//! one thing most deployments actually need — mapping discovery and NAT
//! behaviour discovery — fits in a small dedicated binary. It can run on any
//! host, on whatever NIC that host already has.
//!
//! Naming: crate and binary are both `rstun` — **never** `stun`, because
//! Debian's `stun-client` package already owns `/usr/bin/stun`.
//!
//! License: this repository is MPL-2.0 (see `LICENSE`). MPL is file-level
//! copyleft: changes to these source files stay MPL-2.0, but linking the binary
//! into a larger product does not relicense that product.
//!
//! Scope: `Binding Request` → `Binding Success` with `XOR-MAPPED-ADDRESS`
//! (+ `SOFTWARE`, and the legacy `MAPPED-ADDRESS` with `--mapped-address`),
//! `420 Unknown Attribute` + `UNKNOWN-ATTRIBUTES` when the request carries an
//! attribute this server does not implement, `400 Bad Request` for any other
//! method (unless `--turn` handles it), ignore indications/responses, and (with
//! `--auth-user` / `--realm`) RFC 5389 §10 / RFC 8489 §9.2 authentication.
//! With `--turn` the RFC 8656 relay is enabled ([`turn`]): Allocate / Refresh /
//! CreatePermission / ChannelBind + Send/Data + ChannelData, always behind
//! long-term credentials or TURN REST credentials (startup fails without them).
//! The relay itself is always UDP; the **client** transport may be UDP, TCP,
//! `turns:` (TLS, `tls` feature) or DTLS (`dtls` feature). Without `--turn`
//! nothing TURN-related is parsed, allocated or emitted.
//!
//! With `--alt-listen` the server additionally speaks RFC 5780 (§5 behaviour
//! discovery): responses carry `RESPONSE-ORIGIN` + `OTHER-ADDRESS`, and a
//! `CHANGE-REQUEST` makes the answer leave from the other IP and/or the other
//! port. That needs two public IPs, so it is **opt-in**: without `--alt-listen`
//! the emitted bytes are exactly the pre-RFC-5780 ones.
//!
//! The primary is the **first IPv4 `--listen` in command line order**; every
//! other address (extra IPv4 `--listen`, all `--listen-v6`) is bound as a plain
//! RFC 5389 socket: no `RESPONSE-ORIGIN`/`OTHER-ADDRESS`, and `CHANGE-REQUEST`
//! is ignored there (RFC 5780 §5). See [`rfc5780`] for why the four sockets
//! exist and [`protocol`] for the wire format.
//!
//! Two RFC 5780 attributes work without `--alt-listen`, because they are not
//! part of address discovery: `PADDING` (§7.6) is echoed back at the same length
//! so an MTU probe sees an equally large answer, and `RESPONSE-PORT` (§7.5)
//! delivers the answer to a different **destination** port — the reply still
//! leaves from the socket the request arrived on.

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

#[cfg(feature = "tls")]
use std::sync::atomic::AtomicI64;
#[cfg(feature = "tls")]
use std::time::UNIX_EPOCH;

use clap::{CommandFactory as _, FromArgMatches as _, Parser, Subcommand};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
};

mod auth;
mod crc32;
pub mod limit;
/// 运维面：可选的 `/healthz` + `/metrics`、drain 信号、`RSTUN_*` 映射。
mod ops;
pub mod protocol;
pub mod rfc5780;
/// T1 互操作证据：RFC 5769 向量 + `stun-types` 双向（只在测试构建里编译）。
#[cfg(test)]
mod tests_interop;
/// TURN（RFC 8656）中继：`--turn` 显式开启，强制长期/REST 凭据。
/// 中继本身恒为 UDP；客户端传输可以是 UDP / TCP / `turns:`(TLS) / DTLS。
mod turn;

use protocol::MessageClass;

/// 构建版本串：`26.410.100`，CI 下是 `<标准版本>[-<channel>.<n>][+<sha6>]`。
///
/// 新仓（`github.com/exvlan/rstun`）用 **`RSTUN_BUILD_VERSION`** 注入：CI 与
/// `Dockerfile` 的 `--build-arg` 都写这一个名字；本地构建没有该变量时回落到
/// crate 版本（`Cargo.toml` 的 `version`）。
///
/// `EXVLAN_BUILD_VERSION` **保留为兼容旧构建链路**（记录历史：本 crate 曾作为
/// `exvlan` monorepo 的 workspace member，由 `script/ci/build-version.sh` 只写那一个
/// 变量）。新仓不依赖它，改动时也不要删——删掉会让仍在用旧变量的外部构建静默
/// 掉回 crate 版本。
const BUILD_VERSION: &str = match option_env!("RSTUN_BUILD_VERSION") {
    Some(version) => version,
    None => match option_env!("EXVLAN_BUILD_VERSION") {
        Some(version) => version,
        None => env!("CARGO_PKG_VERSION"),
    },
};

/// Port RFC 5389 assigns to STUN, also coturn's default.
const DEFAULT_PORT: u16 = 3478;
/// Binding requests are tiny — except when they carry RFC 5780 `PADDING` (§7.6),
/// whose whole purpose is to grow the datagram past the path MTU. The buffer is
/// therefore the largest UDP payload a datagram can have: anything smaller would
/// silently truncate (and so drop) exactly the MTU probes `PADDING` exists for.
const UDP_RECV_BUFFER: usize = 65535;
/// A datagram read that fails repeatedly must not spin the runtime.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);
/// How long a TCP peer may take to deliver one STUN frame.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_LISTEN_BACKLOG: i32 = 1024;
/// Default `--drain-timeout`: how long SIGTERM may take to finish in-flight
/// work before the process exits anyway (design §5).
const DEFAULT_DRAIN_TIMEOUT_SECONDS: u64 = 5;
/// `Binding` method, the only one this server implements.
const BINDING_METHOD: u16 = 0x0001;

/// Which optional transports this binary was compiled with. The startup log
/// prints it so an operator (or a bug report) can tell the lean artifact from
/// the full one without running `cargo tree` — the `--version` string is the same
/// in both builds on purpose (one release, one version).
const BUILD_FEATURES: &str = if cfg!(feature = "dtls") {
    "tls,dtls"
} else if cfg!(feature = "tls") {
    "tls"
} else {
    "lean"
};

/// Command line of `rstun`.
///
/// Two levels on purpose: `rstun server [flags]` leaves room for future
/// subcommands without renaming the binary, and keeps the flag surface
/// identical to the pre-rename CLI (only the subcommand word is new).
///
/// Bare `rstun` prints help and exits **2** (clap's
/// `arg_required_else_help` + `subcommand_required`): no arguments is a usage
/// error, not a request to start a wildcard listener.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "rstun",
    version = BUILD_VERSION,
    about = "Standalone STUN/TURN server (RFC 5389 Binding; RFC 5780 with --alt-listen; RFC 8656 relay over UDP/TCP, turns: (TLS) and DTLS with --turn)",
    long_about = None,
    arg_required_else_help = true,
    subcommand_required = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Serve STUN Binding over UDP (and TCP with --tcp); TURN relay with --turn
    /// (UDP/TCP, turns: with the `tls` feature, DTLS with the `dtls` feature)
    Server(Args),
}

/// Flags of `rstun server` (unchanged from the pre-rename CLI).
#[derive(clap::Args, Debug, Clone, Default)]
struct Args {
    /// address to bind over UDP (and TCP with --tcp), repeatable; defaults to 0.0.0.0:3478.
    /// With --alt-listen the first IPv4 address here is the RFC 5780 primary; every other
    /// address (and all --listen-v6) only serves plain Binding
    #[arg(long, value_name = "ADDR")]
    listen: Vec<SocketAddr>,

    /// IPv6 address to bind, repeatable; bound v6-only so it can coexist with --listen.
    /// Never part of RFC 5780: these sockets only serve plain Binding
    #[arg(long, value_name = "ADDR")]
    listen_v6: Vec<SocketAddr>,

    /// second public IP (RFC 5780 "other address"); enables CHANGE-REQUEST,
    /// RESPONSE-ORIGIN and OTHER-ADDRESS. Only the IP is used: the port comes
    /// from --alt-port. Primary = the first IPv4 --listen address; other addresses
    /// (including --listen-v6) stay plain Binding
    #[arg(long, value_name = "ADDR")]
    alt_listen: Option<SocketAddr>,

    /// RFC 5780 "other port"; defaults to the --listen port + 1. Used as the
    /// source port of a `CHANGE-REQUEST` answer and as half of `OTHER-ADDRESS`.
    /// (`RESPONSE-PORT` names a *destination* port and never refers to this.)
    #[arg(long, value_name = "PORT")]
    alt_port: Option<u16>,

    /// also answer STUN Binding over TCP on every listen address
    #[arg(long)]
    tcp: bool,

    /// also emit the legacy MAPPED-ADDRESS (0x0001) next to XOR-MAPPED-ADDRESS,
    /// for RFC 3489-era clients; off by default (response bytes stay unchanged)
    #[arg(long)]
    mapped_address: bool,

    /// validate FINGERPRINT (RFC 5389 §15.5) when a request carries one: it must
    /// be the last attribute and its CRC must match. Off by default, so a request
    /// without FINGERPRINT is answered exactly as before
    #[arg(long)]
    check_fingerprint: bool,

    /// what a FINGERPRINT with a wrong CRC gets: `answer` = 400 Bad Request (the
    /// default), `drop` = no response. `drop` needs --check-fingerprint
    #[arg(long, value_name = "ACTION", value_enum, default_value = "answer")]
    fingerprint_action: FingerprintAction,

    /// answer every Binding request with `300 Try Alternate` + ALTERNATE-SERVER
    /// (RFC 5389 §15.11), pointing at this instance; repeatable, only the first
    /// address is used. Redirect wins over RFC 5780
    #[arg(long, value_name = "ADDR")]
    alternate_server: Vec<SocketAddr>,

    /// log every Binding request with its source and mapped address
    #[arg(long)]
    verbose: bool,

    /// per-source-IP token bucket (req/s), UDP and TCP; bare flag = 200.
    /// Sources named by --allow skip this bucket; off by default
    #[arg(long, value_name = "REQ/S", num_args = 0..=1, default_missing_value = "200")]
    rate_limit: Option<u32>,

    /// burst size of the --rate-limit bucket; defaults to 2x its rate
    #[arg(long, value_name = "N")]
    rate_burst: Option<u32>,

    /// per source IP+port token bucket (req/s); bare flag = 20
    #[arg(long, value_name = "REQ/S", num_args = 0..=1, default_missing_value = "20")]
    rate_limit_port: Option<u32>,

    /// server-wide token bucket (req/s): the last line before the sockets
    #[arg(long, value_name = "REQ/S")]
    global_rate: Option<u32>,

    /// cap on work held at once: one slot per UDP datagram (until answered) and
    /// per TCP connection (until closed). Over the cap, datagrams are dropped
    /// and connections refused
    #[arg(long, value_name = "N")]
    max_inflight: Option<u32>,

    /// refuse RESPONSE-PORT / CHANGE-REQUEST requests shorter than BYTES
    /// (default 20 = the STUN header; a 28-byte RFC 5780 probe must pass).
    /// Raising it trades RFC 5780 compatibility for a stricter floor
    #[arg(long, value_name = "BYTES")]
    reflect_min_request: Option<usize>,

    /// refuse RESPONSE-PORT / CHANGE-REQUEST requests whose answer would exceed
    /// `max(request x RATIO, request + 32)` (default 2.0; the 32 bytes are the
    /// fixed XOR + RFC 5780 address attributes, SOFTWARE is omitted for small
    /// probes). Enables the guard
    #[arg(long, value_name = "RATIO")]
    reflect_ratio: Option<f64>,

    /// CIDR whose sources bypass the per-source rate limits and the reflection
    /// guard, repeatable
    #[arg(long = "allow", value_name = "CIDR")]
    allow: Vec<limit::IpNet>,

    /// CIDR whose sources are refused outright, repeatable; wins ties with --allow
    #[arg(long = "deny", value_name = "CIDR")]
    deny: Vec<limit::IpNet>,

    /// short-term credential user name (RFC 5389 §10.1); needs --auth-pass.
    /// Short-term only applies without --realm: the key is the password itself
    #[arg(long, value_name = "USER")]
    auth_user: Option<String>,

    /// password of --auth-user (short-term) or of the single long-term user
    #[arg(long, value_name = "PASS")]
    auth_pass: Option<String>,

    /// file with one `user:password` per line ('#' comments and blank lines
    /// ignored); repeatable users for long-term, or several short-term users
    #[arg(long, value_name = "PATH")]
    auth_file: Option<PathBuf>,

    /// long-term credential realm (RFC 5389 §10.2); turns on the 401/438 flow.
    /// Needs --auth-secret and at least one user
    #[arg(long, value_name = "REALM")]
    realm: Option<String>,

    /// secret that signs the stateless NONCE (any string; the same value on
    /// every instance makes nonces interchangeable). Required with --realm
    #[arg(long, value_name = "SECRET")]
    auth_secret: Option<String>,

    /// NONCE lifetime in seconds (default 3600); only meaningful with --realm
    #[arg(long, value_name = "SECONDS")]
    nonce_lifetime: Option<u64>,

    /// long-term only: refuse PASSWORD-ALGORITHM=MD5 (401 unless the client
    /// uses SHA256). Needs --realm
    #[arg(long)]
    auth_require_sha256: bool,

    /// serve `GET /healthz` (readiness) and `GET /metrics` (Prometheus text) on
    /// this TCP address, e.g. 127.0.0.1:9100. Off by default: without it no
    /// HTTP listener, no extra task and no change to the STUN paths
    #[arg(long, value_name = "ADDR")]
    health_listen: Option<SocketAddr>,

    /// cap on concurrent connections to the ops endpoint (default 64). A
    /// connection over the cap gets an immediate 503 and is closed, never
    /// queued — queueing would keep the fd the flood is trying to exhaust.
    /// Only meaningful with --health-listen
    #[arg(long, value_name = "N")]
    health_max_connections: Option<usize>,

    /// how long a SIGTERM may take to drain in-flight work before exiting
    /// anyway (seconds, default 5; 0 = stop immediately). The exit code stays 0
    #[arg(long, value_name = "SECONDS")]
    drain_timeout: Option<u64>,

    /// enable the TURN (RFC 8656) relay on the STUN sockets (UDP/TCP client
    /// transports; turns:/DTLS need the tls/dtls build features). Requires
    /// long-term credentials: --realm, --auth-secret and at least one user
    #[arg(long)]
    turn: bool,

    /// TURN relay port range, inclusive (`LO-HI`, default 49152-65535).
    /// Choose a range outside `net.ipv4.ip_local_port_range`
    #[arg(long, value_name = "LO-HI")]
    relay_ports: Option<String>,

    /// TURN: cap on concurrent allocations per authenticated user (default 8)
    #[arg(long, value_name = "N")]
    max_allocations_per_user: Option<usize>,

    /// TURN: cap on concurrent allocations per client IP (default 16)
    #[arg(long, value_name = "N")]
    max_allocations_per_ip: Option<usize>,

    /// TURN: cap on permissions per allocation (default 10)
    #[arg(long, value_name = "N")]
    permission_limit: Option<usize>,

    /// TURN: allocation lifetime in seconds (default 600, max 3600). Also caps
    /// whatever LIFETIME a client asks for
    #[arg(long, value_name = "SECONDS")]
    allocation_lifetime: Option<u64>,

    /// TURN over TLS (`turns:`) listen address, repeatable. Needs --tls-cert,
    /// --tls-key and a build with the `tls` feature (cargo build --features
    /// tls,dtls); TLS and plaintext never share a port (no ALPN sniffing)
    #[arg(long, value_name = "ADDR")]
    turn_tls_listen: Vec<SocketAddr>,

    /// TURN over DTLS (1.2) listen address, repeatable. Needs --tls-cert,
    /// --tls-key (ECDSA P-256 or Ed25519: what webrtc-dtls supports) and a
    /// build with the `dtls` feature
    #[arg(long, value_name = "ADDR")]
    turn_dtls_listen: Vec<SocketAddr>,

    /// PEM certificate chain for --turn-tls-listen / --turn-dtls-listen
    #[arg(long, value_name = "PATH")]
    tls_cert: Option<PathBuf>,

    /// PEM private key for --turn-tls-listen / --turn-dtls-listen
    /// (unencrypted PKCS#8, e.g. `openssl genpkey`)
    #[arg(long, value_name = "PATH")]
    tls_key: Option<PathBuf>,

    /// Certificate rotation poll interval in seconds (default 30; 0 = no
    /// polling, SIGHUP only). Needs --turn-tls-listen or --turn-dtls-listen.
    /// Windows has no SIGHUP, so 0 is refused there
    #[arg(long, value_name = "SECONDS")]
    tls_cert_poll: Option<u64>,

    /// TURN REST API shared secret (coturn `use-auth-secret`):
    /// username = `<expiry>:<label>`, password = base64(HMAC-SHA1(secret,
    /// username)). Needs --realm and --auth-secret; wins over stored users
    #[arg(long, value_name = "SECRET")]
    rest_secret: Option<String>,

    /// TURN: per-allocation bandwidth cap in bytes/second, each direction
    /// (default 1 MiB/s; 0 = unlimited). Over the cap packets are dropped
    #[arg(long, value_name = "BYTES/S")]
    turn_bandwidth: Option<u64>,

    /// TURN: also serve RFC 6062 **TCP allocations** (`REQUESTED-TRANSPORT=6`):
    /// outbound `Connect` + `ConnectionBind`, plus the inbound half — a peer
    /// dialling the relay address is accepted, checked against the permission
    /// table and announced with a `ConnectionAttempt` on the control connection.
    /// Off by default: without it a TCP Allocate is still `442` and the
    /// byte-frozen path is untouched
    #[arg(long)]
    turn_tcp_relay: bool,
}

/// What an invalid `FINGERPRINT` gets (`--fingerprint-action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
enum FingerprintAction {
    /// `400 Bad Request` (RFC 5389 §15.5 makes a bad fingerprint a bad message).
    #[default]
    Answer,
    /// No response at all — for deployments that do not want to answer probes
    /// with a broken fingerprint (still counted, see `ServerStats`).
    Drop,
}

/// Counters reported when the server stops; also what `--verbose` helps debug.
///
/// It also carries the [`ops::Lifecycle`] (drain signal + in-flight count). That
/// is deliberate: every listener already holds `Arc<ServerStats>`, so putting it
/// here keeps `serve_udp` / `serve_tcp` signatures — and therefore the default,
/// byte-frozen path — untouched.
#[derive(Debug, Default)]
pub struct ServerStats {
    received: AtomicU64,
    answered: AtomicU64,
    dropped: AtomicU64,
    /// Requests rejected because of a bad `FINGERPRINT` (`--check-fingerprint`).
    fingerprint_rejected: AtomicU64,
    /// `recv_from` / `accept` failures (one listener read, one metric label).
    udp: TransportCounts,
    tcp: TransportCounts,
    /// Connections refused by the ops endpoint's `--health-max-connections`.
    /// Kept apart from the STUN counters on purpose: it says nothing about STUN
    /// traffic (and never fires without `--health-listen`).
    ops_rejected: AtomicU64,
    lifecycle: ops::Lifecycle,
    /// TURN table, set once at startup when `--turn` is on. `None` (the
    /// default) means the whole TURN path is skipped: no parse, no table, no
    /// `/metrics` lines — the pre-TURN bytes stay frozen.
    turn: std::sync::OnceLock<Arc<turn::Turn>>,
    /// TLS/DTLS certificate material bookkeeping, set once at startup when a
    /// secure listener is configured. Absent in a lean build, and `None` for a
    /// `--turn` server without `turns:`/DTLS, so the non-TLS label set keeps
    /// exactly the T1 rows.
    #[cfg(feature = "tls")]
    secure: std::sync::OnceLock<Arc<SecureStats>>,
}

/// Per-transport outcome buckets for `rstun_requests_total`.
///
/// Every message is counted **once** per bucket, so `ok + error + ignored +
/// dropped` is the number of messages the transport saw — except that a
/// `--fingerprint-action drop` request is counted in `dropped` (the guard's
/// bucket) *and* in `ignored` (the decision). The rows are independent
/// counters; the exit log's `received/answered/dropped` triple keeps its
/// existing meaning, including the documented `received != answered + dropped`
/// cases (`.trellis/spec/backend/abuse-guard.md` §4).
#[derive(Debug, Default)]
struct TransportCounts {
    ok: AtomicU64,
    error: AtomicU64,
    ignored: AtomicU64,
    dropped: AtomicU64,
    socket_errors: AtomicU64,
}

/// A snapshot of one transport's buckets (`/metrics`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Buckets {
    pub ok: u64,
    pub error: u64,
    pub ignored: u64,
    pub dropped: u64,
    pub socket_errors: u64,
}

impl TransportCounts {
    fn bump(&self, counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn snapshot(&self) -> Buckets {
        Buckets {
            ok: self.ok.load(Ordering::Relaxed),
            error: self.error.load(Ordering::Relaxed),
            ignored: self.ignored.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            socket_errors: self.socket_errors.load(Ordering::Relaxed),
        }
    }
}

impl ServerStats {
    /// `(received, answered, dropped)`.
    pub fn counters(&self) -> (u64, u64, u64) {
        (
            self.received.load(Ordering::Relaxed),
            self.answered.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// Requests whose `FINGERPRINT` was absent-but-invalid, misplaced or wrong.
    pub fn fingerprint_rejected(&self) -> u64 {
        self.fingerprint_rejected.load(Ordering::Relaxed)
    }

    /// `ok/error/ignored/dropped` (+ socket errors) for one transport.
    pub(crate) fn buckets(&self, transport: Transport) -> Buckets {
        self.buckets_of(transport).snapshot()
    }

    fn buckets_of(&self, transport: Transport) -> &TransportCounts {
        match transport {
            Transport::Udp => &self.udp,
            Transport::Tcp => &self.tcp,
        }
    }

    /// The drain signal every listener selects on.
    pub fn lifecycle(&self) -> &ops::Lifecycle {
        &self.lifecycle
    }

    pub fn is_draining(&self) -> bool {
        self.lifecycle.is_draining()
    }

    pub fn begin_drain(&self) {
        self.lifecycle.begin();
    }

    pub fn subscribe_drain(&self) -> tokio::sync::watch::Receiver<bool> {
        self.lifecycle.subscribe()
    }

    /// One unit of in-flight work; see [`ops::Lifecycle::enter`].
    pub fn enter(&self) -> ops::InFlight {
        self.lifecycle.enter()
    }

    pub async fn wait_idle(&self, deadline: tokio::time::Instant) -> u64 {
        self.lifecycle.wait_idle(deadline).await
    }

    fn transport(&self, transport: Transport) -> &TransportCounts {
        self.buckets_of(transport)
    }

    fn count_received(&self, _transport: Transport) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    /// A response was sent.
    fn count_answered(&self, transport: Transport) {
        self.answered.fetch_add(1, Ordering::Relaxed);
        let counts = self.transport(transport);
        counts.bump(&counts.ok);
    }

    /// Refused by policy (rate limit, in-flight cap, reflection guard, unframable
    /// payload). Part of the legacy `dropped` total.
    fn count_dropped(&self, transport: Transport) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        let counts = self.transport(transport);
        counts.bump(&counts.dropped);
    }

    /// malformed / internal failure: also a `dropped` in the legacy total, but
    /// its own bucket so `/metrics` can tell "we refused it" from "we could not
    /// read it".
    fn count_error(&self, transport: Transport) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
        let counts = self.transport(transport);
        counts.bump(&counts.error);
    }

    /// Well-formed message we deliberately stay silent about.
    fn count_ignored(&self, transport: Transport) {
        let counts = self.transport(transport);
        counts.bump(&counts.ignored);
    }

    /// A socket read/accept failure (not a message: no request is counted).
    fn count_socket_error(&self, transport: Transport) {
        let counts = self.transport(transport);
        counts.bump(&counts.socket_errors);
    }

    fn count_fingerprint_rejected(&self) {
        self.fingerprint_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// `/metrics`: connections the ops endpoint refused over its cap.
    pub fn ops_rejected(&self) -> u64 {
        self.ops_rejected.load(Ordering::Relaxed)
    }

    pub(crate) fn count_ops_rejected(&self) {
        self.ops_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// The TURN table, when `--turn` was given. `None` keeps every TURN path —
    /// request dispatch, relay tasks and `/metrics` — out of the process.
    pub(crate) fn turn(&self) -> Option<&Arc<turn::Turn>> {
        self.turn.get()
    }

    /// Install the TURN table once, at startup.
    pub(crate) fn set_turn(&self, turn: Arc<turn::Turn>) {
        let _ = self.turn.set(turn);
    }

    /// Certificate reload bookkeeping, when a secure listener is configured.
    #[cfg(feature = "tls")]
    pub(crate) fn secure(&self) -> Option<&Arc<SecureStats>> {
        self.secure.get()
    }

    /// Install the certificate bookkeeping once, at startup.
    #[cfg(feature = "tls")]
    pub(crate) fn set_secure(&self, secure: Arc<SecureStats>) {
        let _ = self.secure.set(secure);
    }
}

/// Certificate reload bookkeeping for `turns:` / DTLS.
///
/// Deliberately separate from [`turn::Counters`]: a `--turn` server without a
/// secure listener must not grow these two metric families, and a lean build
/// does not compile this type at all.
#[cfg(feature = "tls")]
#[derive(Debug, Default)]
pub struct SecureStats {
    reload_ok: AtomicU64,
    reload_failed: AtomicU64,
    /// Unix seconds of the current leaf certificate's `notAfter`; `0` means
    /// "could not parse", which the gauge reports as `-1` (design §3.1).
    not_after: AtomicI64,
}

/// One consistent read of [`SecureStats`] (`/metrics` and the exit log).
#[cfg(feature = "tls")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecureSnapshot {
    pub reload_ok: u64,
    pub reload_failed: u64,
    /// `notAfter - now` in seconds; negative means already expired, `-1` means
    /// the validity could not be parsed.
    pub cert_expires_seconds: i64,
}

#[cfg(feature = "tls")]
impl SecureStats {
    /// A reload parsed and swapped in a complete new material set.
    pub fn count_reload_ok(&self) {
        self.reload_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// A reload was rejected after its retry: old material stays in service.
    pub fn count_reload_failure(&self) {
        self.reload_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the current leaf's `notAfter`; `None` marks it unparseable.
    pub fn set_not_after(&self, not_after: Option<i64>) {
        self.not_after
            .store(not_after.unwrap_or(0), Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> SecureSnapshot {
        let not_after = self.not_after.load(Ordering::Relaxed);
        let cert_expires_seconds = if not_after == 0 {
            -1
        } else {
            not_after - unix_seconds_now()
        };
        SecureSnapshot {
            reload_ok: self.reload_ok.load(Ordering::Relaxed),
            reload_failed: self.reload_failed.load(Ordering::Relaxed),
            cert_expires_seconds,
        }
    }
}

/// Current Unix time in whole seconds (saturating on a pre-1970 clock).
#[cfg(feature = "tls")]
fn unix_seconds_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// What to do with one inbound message.
#[derive(Debug)]
enum Decision {
    /// Send these bytes back to the peer from the socket that received them.
    Respond(Vec<u8>),
    /// RFC 5780: the answer must leave from *another* socket — `CHANGE-REQUEST`
    /// (§7.2), because the client asserts on that socket's source address —
    /// and/or be delivered to *another destination port* — `RESPONSE-PORT`
    /// (§7.5), which never changes the source address.
    RespondFrom {
        from: SocketAddr,
        to: SocketAddr,
        bytes: Vec<u8>,
    },
    /// Well-formed STUN that a Binding-only server must stay silent about.
    Ignore(&'static str),
    /// RFC 6062 §5.4: a `ConnectionBind` succeeded. Write `response` on this
    /// stream, then stop parsing STUN frames: the connection is now the raw-byte
    /// **client data connection** identified by `id`. Only reachable on a
    /// TCP/TLS TURN connection with `--turn-tcp-relay`.
    Bind { response: Vec<u8>, id: u32 },
}

/// Which transport a message arrived on; RFC 5780 `CHANGE-REQUEST` is UDP-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// Everything a listener needs besides its own socket: which addresses this
/// process serves, and which optional response shapes are enabled.
///
/// The `udp` table answers "where did this datagram arrive?" and "which socket
/// may answer it?": RFC 5780 `CHANGE-REQUEST` (§7.2) can only pick a socket we
/// actually hold, so a requested address that is not in this table is ignored
/// rather than faked. `RESPONSE-PORT` (§7.5) needs no table at all — it names a
/// *destination* port, which this process does not have to hold.
#[derive(Debug, Default)]
struct ServerContext {
    /// `Some` iff `--alt-listen`: enables `RESPONSE-ORIGIN`, `OTHER-ADDRESS` and
    /// `CHANGE-REQUEST` (the "other address" pair that needs a second IP).
    plan: Option<rfc5780::Plan>,
    /// Every bound UDP socket, keyed by its bound local address.
    udp: Vec<(SocketAddr, Arc<UdpSocket>)>,
    /// `--mapped-address`: also emit the pre-XOR `MAPPED-ADDRESS`.
    mapped_address: bool,
    /// Abuse guard; `None` unless at least one `--rate-limit`-family flag was
    /// given, so the default path allocates nothing and checks nothing.
    admission: Option<Arc<limit::Admission>>,
    /// `--check-fingerprint`: validate `FINGERPRINT` and pick what an invalid one
    /// gets. `None` = off (the attribute is ignored, as before).
    fingerprint: Option<FingerprintAction>,
    /// `--alternate-server`: answer every Binding request with `300 Try
    /// Alternate` + `ALTERNATE-SERVER` pointing here.
    alternate_server: Option<SocketAddr>,
    /// Configured credentials; `None` (the default) means the authentication
    /// attributes are ignored exactly as before (RFC 5389 §10.2.2 allows a
    /// client to send them unprompted).
    auth: Option<auth::Auth>,
}

impl ServerContext {
    /// UDP: one datagram = one unit of work, so in-flight slot + rate checks
    /// happen together.
    ///
    /// `None` = guard off (the caller keeps the plain path). `Some(Err)` = do
    /// not process the datagram. `Some(Ok(permit))` = the caller must keep the
    /// permit alive until the answer has been sent (that is what the in-flight
    /// cap counts).
    fn admit(&self, peer: SocketAddr) -> Option<Result<limit::Permit, limit::Refusal>> {
        self.admission
            .as_ref()
            .map(|admission| admission.admit(peer, std::time::Instant::now()))
    }

    /// TCP `accept`: take an in-flight slot for the connection's lifetime.
    /// One idle connection holds no request, but it does hold an fd and a task.
    fn acquire_inflight(&self) -> Option<Result<limit::Permit, limit::Refusal>> {
        self.admission
            .as_ref()
            .map(|admission| admission.acquire_inflight())
    }

    /// TCP per request: the rate buckets only (the slot is already held by the
    /// connection, and re-counting it would halve `--max-inflight`).
    fn check_rates(&self, peer: SocketAddr) -> Option<Result<(), limit::Refusal>> {
        self.admission
            .as_ref()
            .map(|admission| admission.check_rates(peer, std::time::Instant::now()))
    }
}

impl ServerContext {
    fn socket_for(&self, address: SocketAddr) -> Option<&Arc<UdpSocket>> {
        self.udp
            .iter()
            .find(|(local, _)| *local == address)
            .map(|(_, socket)| socket)
    }

    /// RFC 5780 attributes for a request answered from `local`.
    ///
    /// Only the four sockets [`rfc5780::Plan`] owns get them. Extra `--listen`
    /// addresses and every `--listen-v6` socket answer as plain RFC 5389: they
    /// have no defined "other address", and pairing a v6 `local` with the plan's
    /// v4 `OTHER-ADDRESS` would be a protocol error a client cannot interpret.
    fn addresses(&self, local: SocketAddr) -> Option<protocol::ResponseAddresses> {
        let plan = self.plan?;
        if !plan.is_plan_socket(local) {
            return None;
        }
        Some(protocol::ResponseAddresses {
            origin: local,
            other: plan.other_of(local),
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    // Two-phase parse: the `ArgMatches` are what tell [`ops::apply_env`] which
    // flags the operator actually wrote (as opposed to clap's defaults), so the
    // command line can win over `RSTUN_*` without a second, divergent parser.
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    let server_matches = matches
        .subcommand_matches("server")
        .cloned()
        .unwrap_or_else(|| unreachable!("clap requires a subcommand"));

    match cli.command {
        Command::Server(mut args) => {
            // `RSTUN_*` 必须在日志初始化**之前**应用：`RSTUN_VERBOSE=1` 要和
            // `--verbose` 一样把过滤器调到 debug，晚一步就只影响服务而不影响日志。
            // （`apply_env` 只在成功时才改 `args`，所以失败路径仍能用命令行值初始化日志。）
            let applied =
                ops::apply_env(&mut args, &server_matches, &|name| std::env::var(name).ok());

            // 日志初始化失败不阻断服务：与内核主路径一致，没有日志也好过起不来。
            if let Err(error) = init_logging(args.verbose) {
                eprintln!("[rstun] failed to initialize logging: {error:#}");
            }

            let applied = match applied {
                Ok(applied) => applied,
                Err(message) => {
                    tracing::error!(%message, "rstun: invalid environment configuration");
                    return ExitCode::FAILURE;
                }
            };

            run(args, applied).await
        }
    }
}

/// 控制台日志：`RUST_LOG` 优先，否则 `--verbose` 决定 info/debug。
///
/// 不再写滚动文件（内核那套 `exvlan_rpc::log` 会把文件日志的路径/轮转一起
/// 拖进来）：容器与 systemd 都直接采 stdout/stderr。
fn init_logging(verbose: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let default_level = if verbose { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()?;
    Ok(())
}

/// Work out which addresses to bind, and whether RFC 5780 is on.
///
/// Split from [`run`] so the CLI contract is unit-testable without binding
/// anything or touching the process exit path. Three rules matter:
///
/// * the returned list is **every** `--listen` / `--listen-v6` address (sorted,
///   deduped) — [`bind`] adds the RFC 5780 four-socket set on top;
/// * with `--alt-listen`, the primary is the **first IPv4 `--listen` in command
///   line order** — sorting is for binding only, never for choosing it;
/// * `--listen-v6` never participates in RFC 5780 (change-ip is IPv4): those
///   addresses only serve plain Binding.
fn resolve_listen(args: &Args) -> Result<(Vec<SocketAddr>, Option<rfc5780::Plan>), String> {
    let mut addresses = args.listen.clone();
    addresses.extend(args.listen_v6.iter().copied());
    if addresses.is_empty() {
        addresses.push(SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)));
    }
    // 排序/去重只服务「绑定」这一步。primary 必须在排序**之前**按 CLI 顺序取，
    // 否则 `--listen .8 --listen .5` 会静默把 primary 变成 .5。
    addresses.sort_unstable();
    addresses.dedup();

    let Some(other) = args.alt_listen else {
        if args.alt_port.is_some() {
            return Err(
                "--alt-port only makes sense together with --alt-listen (RFC 5780)".to_string(),
            );
        }
        return Ok((addresses, None));
    };

    // primary = 命令行顺序里第一个 IPv4 `--listen`。
    let primary = match args.listen.iter().copied().find(SocketAddr::is_ipv4) {
        Some(primary) => primary,
        // `--listen` 里只有 v6（含 v6 通配）：交给 `Plan::from_cli`，它给出的
        // 「concrete --listen」/ 同族错误与改造前一致，比「缺 v4」更准确。
        None => match args.listen.first().copied() {
            Some(first) => first,
            // 完全没给地址：沿用默认通配，仍由 `Plan::from_cli` 报 wildcard。
            None if args.listen_v6.is_empty() => addresses[0],
            None => {
                return Err(format!(
                    "--alt-listen needs an IPv4 --listen address: RFC 5780 CHANGE-REQUEST flips \
                     between two IPv4 addresses, and --listen-v6 ({}) only serves plain Binding",
                    args.listen_v6
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        },
    };
    let plan = rfc5780::Plan::from_cli(primary, other, args.alt_port)?;
    Ok((addresses, Some(plan)))
}

/// Sockets bound before any task is spawned.
struct Bound {
    udp: Vec<(SocketAddr, Arc<UdpSocket>)>,
    tcp: Vec<(SocketAddr, TcpListener)>,
}

/// Bind every UDP socket (and TCP listener with `tcp`) the server needs.
///
/// The set is `plan`'s four sockets (if RFC 5780 is on) **plus** every address
/// from [`resolve_listen`] that is not already one of them: extra `--listen`
/// addresses and all `--listen-v6` serve plain Binding. Membership checks are
/// what keep a repeated address from being bound twice (`Address in use`) —
/// e.g. `--listen <alt-ip>:3478 --alt-listen <alt-ip>:3478`, or a `--listen`
/// that names a primary-port/alt-port socket explicitly.
///
/// Binding happens up front so a half-started server never announces itself:
/// if any socket fails, nothing is served at all.
fn bind(
    addresses: &[SocketAddr],
    plan: Option<rfc5780::Plan>,
    tcp: bool,
) -> std::io::Result<Bound> {
    let mut udp_addresses: Vec<SocketAddr> = Vec::with_capacity(addresses.len() + 4);
    let mut tcp_addresses: Vec<SocketAddr> = Vec::with_capacity(addresses.len() + 2);
    if let Some(plan) = plan {
        udp_addresses.extend(plan.sockets());
        tcp_addresses.extend(plan.tcp_listeners());
    }
    // 普通 Binding 的地址（多 v4 / 全部 v6）：已在计划的 socket 集合里就跳过。
    for address in addresses {
        if !udp_addresses.contains(address) {
            udp_addresses.push(*address);
        }
    }
    if tcp {
        for address in addresses {
            if !tcp_addresses.contains(address) {
                tcp_addresses.push(*address);
            }
        }
    }

    let mut bound = Bound {
        udp: Vec::with_capacity(udp_addresses.len()),
        tcp: Vec::with_capacity(tcp_addresses.len()),
    };
    for address in udp_addresses {
        let socket = Arc::new(udp_socket(address)?);
        // The bound address is what identifies the socket in
        // `ServerContext::socket_for`, so keep the kernel's answer.
        bound.udp.push((socket.local_addr()?, socket));
    }
    for address in tcp_addresses {
        bound.tcp.push((address, tcp_listener(address)?));
    }
    Ok(bound)
}

/// Turn the abuse-guard flags into a policy, or explain why they are unusable.
///
/// `Ok(None)` means "no flag given": the caller then never builds an
/// [`limit::Admission`], so nothing is allocated and no task is spawned.
/// Values that parse but cannot work (`0` tokens, a burst below one, a
/// `--reflect-min-request` under the 20-byte header) are startup errors — a
/// silent no-op guard is worse than a refused start.
fn build_policy(args: &Args) -> Result<Option<limit::Policy>, String> {
    if args.rate_limit.is_none() && args.rate_burst.is_some() {
        return Err("--rate-burst needs --rate-limit".to_string());
    }
    let per_ip = args.rate_limit.map(|rate| {
        // The design's default is 200 req/s with a burst of 400: a household
        // NAT with tens of devices (ICE connectivity checks) must not trip it.
        limit::Rate::new(
            f64::from(rate),
            f64::from(args.rate_burst.unwrap_or_else(|| rate.saturating_mul(2))),
        )
    });
    let per_port = args
        .rate_limit_port
        .map(|rate| limit::Rate::new(f64::from(rate), f64::from(rate.saturating_mul(2))));
    let global = args
        .global_rate
        .map(|rate| limit::Rate::new(f64::from(rate), f64::from(rate.saturating_mul(2))));
    let reflect = match (args.reflect_min_request, args.reflect_ratio) {
        (None, None) => None,
        (min_request, ratio) => Some(limit::Reflect {
            min_request: min_request.unwrap_or(limit::DEFAULT_REFLECT_MIN_REQUEST),
            ratio: ratio.unwrap_or(limit::DEFAULT_REFLECT_RATIO),
        }),
    };
    let policy = limit::Policy {
        per_ip,
        per_port,
        global,
        max_inflight: args.max_inflight.map(|slots| slots as usize),
        reflect,
        allow: args.allow.clone(),
        deny: args.deny.clone(),
    };
    if policy.is_off() {
        return Ok(None);
    }
    policy.validate()?;
    Ok(Some(policy))
}

/// Turn the protocol flags into the two optional behaviours, or explain why they
/// are unusable.
///
/// `Ok(None)` means "no flag given": the caller then never parses twice, never
/// checks a fingerprint and never answers `300` — the default path stays
/// byte-for-byte the pre-flag one. `--fingerprint-action` alone is refused
/// because a silent no-op guard is worse than a refused start (same rule the
/// abuse-guard flags follow).
fn fingerprint_policy(args: &Args) -> Result<Option<FingerprintAction>, String> {
    if args.check_fingerprint {
        return Ok(Some(args.fingerprint_action));
    }
    if args.fingerprint_action != FingerprintAction::Answer {
        return Err("--fingerprint-action needs --check-fingerprint".to_string());
    }
    Ok(None)
}

/// `--alternate-server` is repeatable but only one redirect target makes sense:
/// the first entry wins, the caller warns about the rest (no silent merge).
fn alternate_server(args: &Args) -> Option<SocketAddr> {
    args.alternate_server.first().copied()
}

/// Turn the credential flags into an [`auth::Auth`], or explain why they are
/// unusable.
///
/// `Ok(None)` means "no credential configured": the caller then never builds an
/// `Auth`, never parses an integrity attribute and never answers 401/438 — the
/// default path stays byte-for-byte the pre-auth one. Every half-configured
/// combination is a startup error: a server that *silently* ignores the
/// credentials an operator wrote down is worse than one that refuses to start.
fn build_auth(args: &Args) -> Result<Option<auth::Auth>, String> {
    let mut users = match &args.auth_file {
        Some(path) => auth::read_users(path)?,
        None => Vec::new(),
    };
    match (&args.auth_user, &args.auth_pass) {
        (Some(username), Some(password)) => users.push(auth::User {
            username: username.clone(),
            password: password.clone(),
        }),
        (Some(_), None) => return Err("--auth-user needs --auth-pass".to_string()),
        (None, Some(_)) => return Err("--auth-pass needs --auth-user".to_string()),
        (None, None) => {}
    }
    let nonce_lifetime = match args.nonce_lifetime {
        Some(0) => return Err("--nonce-lifetime must be at least 1 second".to_string()),
        Some(seconds) => Duration::from_secs(seconds),
        None => Duration::from_secs(auth::DEFAULT_NONCE_LIFETIME),
    };

    // `--rest-secret` is a long-term credential source of its own: it still
    // needs a realm (it is part of the key derivation) and a nonce signing
    // secret, but no stored user.
    match (&args.realm, &args.auth_secret) {
        (Some(realm), Some(secret)) => {
            if realm.is_empty() {
                return Err("--realm must not be empty".to_string());
            }
            if secret.is_empty() {
                return Err("--auth-secret must not be empty".to_string());
            }
            if users.is_empty() && args.rest_secret.is_none() {
                return Err(
                    "--realm needs at least one user (--auth-user/--auth-pass or --auth-file) \
                     or --rest-secret"
                        .to_string(),
                );
            }
            let mut auth = auth::Auth::long_term(
                realm.clone(),
                secret.as_bytes().to_vec(),
                users,
                nonce_lifetime,
                args.auth_require_sha256,
            );
            if let Some(rest) = &args.rest_secret {
                if rest.is_empty() {
                    return Err("--rest-secret must not be empty".to_string());
                }
                auth = auth.with_rest_secret(rest.as_bytes().to_vec());
            }
            Ok(Some(auth))
        }
        (Some(_), None) => Err(
            "--realm needs --auth-secret (it signs the NONCE, including the 401 that a REST \
             client receives)"
                .to_string(),
        ),
        (None, Some(_)) => Err("--auth-secret only makes sense together with --realm".to_string()),
        (None, None) => {
            if args.rest_secret.is_some() {
                return Err("--rest-secret needs --realm and --auth-secret".to_string());
            }
            if args.auth_require_sha256 {
                return Err(
                    "--auth-require-sha256 needs --realm (it is a long-term concept)".to_string(),
                );
            }
            if args.nonce_lifetime.is_some() {
                return Err("--nonce-lifetime needs --realm".to_string());
            }
            if users.is_empty() {
                return Ok(None);
            }
            Ok(Some(auth::Auth::short_term(users)))
        }
    }
}

/// Turn the TURN flags into a validated configuration, or explain why they are
/// unusable.
///
/// TURN is **not** a STUN feature that can run anonymously: `--turn` without
/// long-term credentials (`--realm` + `--auth-secret` + a user) is a startup
/// error, not a warning. That is the whole anti-open-relay baseline (prd R2).
fn build_turn(args: &Args, auth: Option<&auth::Auth>) -> Result<Option<turn::Config>, String> {
    let any_turn_flag = args.relay_ports.is_some()
        || args.max_allocations_per_user.is_some()
        || args.max_allocations_per_ip.is_some()
        || args.permission_limit.is_some()
        || args.allocation_lifetime.is_some()
        || args.turn_bandwidth.is_some()
        || args.turn_tcp_relay
        || !args.turn_tls_listen.is_empty()
        || !args.turn_dtls_listen.is_empty()
        || args.tls_cert.is_some()
        || args.tls_key.is_some()
        || args.tls_cert_poll.is_some();
    if !args.turn {
        if any_turn_flag {
            return Err(
                "--relay-ports / --max-allocations-* / --permission-limit / \
                 --allocation-lifetime / --turn-bandwidth / --turn-tcp-relay / \
                 --turn-tls-listen / --turn-dtls-listen / --tls-cert / --tls-key / \
                 --tls-cert-poll \
                 need --turn"
                    .to_string(),
            );
        }
        if args.rest_secret.is_some() {
            return Err("--rest-secret needs --turn (TURN REST API credentials)".to_string());
        }
        return Ok(None);
    }
    // Feature gate first: with `default = []` the flags still exist (help text
    // never changes with the build), but a lean build cannot serve them. Saying
    // so is more useful than "missing certificate" — the operator needs to know
    // they are running the wrong artifact.
    #[cfg(not(feature = "tls"))]
    if !args.turn_tls_listen.is_empty()
        || args.tls_cert.is_some()
        || args.tls_key.is_some()
        || args.tls_cert_poll.is_some()
    {
        return Err(
            "--turn-tls-listen / --tls-cert / --tls-key / --tls-cert-poll need a build with the \
             `tls` feature (cargo build --features tls,dtls)"
                .to_string(),
        );
    }
    #[cfg(not(feature = "dtls"))]
    if !args.turn_dtls_listen.is_empty() {
        return Err("--turn-dtls-listen needs a build with the `dtls` feature \
             (cargo build --features tls,dtls)"
            .to_string());
    }
    // TLS/DTLS are a pair of flags each: a listener without material would
    // silently serve plaintext, which is exactly what design §3.2 forbids.
    if !args.turn_tls_listen.is_empty() || !args.turn_dtls_listen.is_empty() {
        match (&args.tls_cert, &args.tls_key) {
            (Some(_), Some(_)) => {}
            (None, None) => {
                return Err(
                    "--turn-tls-listen / --turn-dtls-listen need --tls-cert and --tls-key"
                        .to_string(),
                );
            }
            (Some(_), None) => return Err("--tls-cert needs --tls-key".to_string()),
            (None, Some(_)) => return Err("--tls-key needs --tls-cert".to_string()),
        }
    }
    if args.tls_cert.is_some()
        && args.turn_tls_listen.is_empty()
        && args.turn_dtls_listen.is_empty()
    {
        return Err(
            "--tls-cert / --tls-key need --turn-tls-listen or --turn-dtls-listen".to_string(),
        );
    }
    // `--tls-cert-poll` belongs to the same secure-material group: a value with
    // no secure listener would never take effect, and `0` without SIGHUP would
    // leave a certificate that can never rotate. `run` calls this same helper
    // for the interval it hands to the reloader, so the two cannot disagree.
    cert_poll_interval(
        args.tls_cert_poll,
        !args.turn_tls_listen.is_empty() || !args.turn_dtls_listen.is_empty(),
        cfg!(unix),
    )?;
    let Some(auth) = auth else {
        return Err(
            "--turn needs long-term credentials: --realm, --auth-secret and at least one user \
             (--auth-user/--auth-pass or --auth-file)"
                .to_string(),
        );
    };
    if auth.mode() != auth::Mode::LongTerm {
        return Err(
            "--turn needs long-term credentials (--realm + --auth-secret); short-term \
             --auth-user/--auth-pass is not enough"
                .to_string(),
        );
    }
    let mut config = turn::Config::default();
    if let Some(text) = &args.relay_ports {
        config.relay_ports = turn::parse_port_range(text)?;
    }
    if let Some(count) = args.max_allocations_per_user {
        config.max_allocations_per_user = count;
    }
    if let Some(count) = args.max_allocations_per_ip {
        config.max_allocations_per_ip = count;
    }
    if let Some(count) = args.permission_limit {
        config.permission_limit = count;
    }
    if let Some(seconds) = args.allocation_lifetime {
        config.lifetime = Duration::from_secs(seconds);
    }
    if let Some(bandwidth) = args.turn_bandwidth {
        config.bandwidth = bandwidth;
    }
    config.tcp_relay = args.turn_tcp_relay;
    config.validate()?;
    Ok(Some(config))
}

/// Run the STUN Binding server until Ctrl-C (Unix: also SIGTERM).
///
/// `applied_env` is what `main` already merged from `RSTUN_*` (it has to happen
/// there, before logging is initialized — see `main`), and is only used for the
/// startup log.
async fn run(args: Args, applied_env: Vec<String>) -> ExitCode {
    if !applied_env.is_empty() {
        tracing::info!(
            variables = ?applied_env,
            "rstun: configuration defaults read from the environment"
        );
    }
    // 运维端点的两个参数都要在起任何 socket 之前校验完：
    // 「给了 `--health-max-connections` 却没给 `--health-listen`」是半配置，
    // 静默忽略会让运维以为上限生效了（本项目一贯：宁可拒绝启动）。
    if args.health_max_connections.is_some() && args.health_listen.is_none() {
        tracing::error!("rstun: --health-max-connections needs --health-listen");
        return ExitCode::FAILURE;
    }
    let health_max_connections = match args.health_max_connections {
        Some(0) => {
            tracing::error!("rstun: --health-max-connections must be at least 1");
            return ExitCode::FAILURE;
        }
        Some(connections) => connections,
        None => ops::DEFAULT_MAX_CONNECTIONS,
    };
    let drain_timeout = match args.drain_timeout {
        // 0 = 立即停（不等在途），显式允许；上限防手滑写出「一天」。
        Some(seconds) if seconds <= 3600 => Duration::from_secs(seconds),
        Some(seconds) => {
            tracing::error!(
                seconds,
                "rstun: --drain-timeout must be between 0 and 3600 seconds"
            );
            return ExitCode::FAILURE;
        }
        None => Duration::from_secs(DEFAULT_DRAIN_TIMEOUT_SECONDS),
    };

    let (addresses, plan) = match resolve_listen(&args) {
        Ok(resolved) => resolved,
        Err(message) => {
            // 配置错误必须让人看见：不要静默降级成「单 IP、无 RFC 5780」的服务器。
            tracing::error!(%message, "rstun: invalid command line");
            return ExitCode::FAILURE;
        }
    };

    // 抗滥用：仅当给了开关才建表/建信号量；`None` 时下面所有路径与 26.410.100 一致。
    let admission = match build_policy(&args).and_then(|policy| match policy {
        None => Ok(None),
        Some(policy) => limit::Admission::new(policy).map(Some),
    }) {
        Ok(admission) => admission,
        Err(message) => {
            tracing::error!(%message, "rstun: invalid abuse-guard configuration");
            return ExitCode::FAILURE;
        }
    };

    let Bound { udp, tcp } = match bind(&addresses, plan, args.tcp) {
        Ok(bound) => bound,
        Err(error) => {
            tracing::error!(%error, "rstun: failed to bind");
            return ExitCode::FAILURE;
        }
    };

    let software: Arc<str> = Arc::from(format!("rstun/{BUILD_VERSION}"));
    let stats = Arc::new(ServerStats::default());
    // 协议闭环的两个开关同样「不给就不改任何字节」：`None` 时下面的路径与 26.410.100 一致。
    let fingerprint = match fingerprint_policy(&args) {
        Ok(policy) => policy,
        Err(message) => {
            tracing::error!(%message, "rstun: invalid protocol configuration");
            return ExitCode::FAILURE;
        }
    };
    let alternate_server = alternate_server(&args);
    if args.alternate_server.len() > 1 {
        tracing::warn!(
            ignored = ?&args.alternate_server[1..],
            used = %args.alternate_server[0],
            "rstun: only the first --alternate-server is used"
        );
    }
    // 鉴权同样「不给凭据就不改任何字节」：`None` 时下面的路径与 26.410.100 一致。
    let auth = match build_auth(&args) {
        Ok(auth) => auth,
        Err(message) => {
            tracing::error!(%message, "rstun: invalid authentication configuration");
            return ExitCode::FAILURE;
        }
    };
    // TURN：`--turn` 显式开启，且**必须**有长期凭据（prd R2）。关闭时零表、零任务、
    // 零指标行，STUN 路径与 26.410.100 一致。
    let turn = match build_turn(&args, auth.as_ref()) {
        Ok(Some(config)) => Some(Arc::new(turn::Turn::new(
            config,
            format!("rstun/{BUILD_VERSION}"),
        ))),
        Ok(None) => None,
        Err(message) => {
            tracing::error!(%message, "rstun: invalid TURN configuration");
            return ExitCode::FAILURE;
        }
    };
    if let Some(turn) = &turn {
        // `OnceLock` only accepts the first value; startup is the only writer.
        stats.set_turn(turn.clone());
    }
    // TLS/DTLS material is read **before** anything is served: a bad path or an
    // unusable pair must never degrade into "plaintext on the turns port".
    // Absent in a lean build (`default = []`): `build_turn` already refused the
    // flags there, so there is nothing to read.
    #[cfg(feature = "tls")]
    let secure = if args.turn_tls_listen.is_empty() && args.turn_dtls_listen.is_empty() {
        None
    } else {
        let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
            // `build_turn` already refused this; keep the invariant local.
            tracing::error!(
                "rstun: --turn-tls-listen / --turn-dtls-listen need --tls-cert and --tls-key"
            );
            return ExitCode::FAILURE;
        };
        let needs_dtls = !args.turn_dtls_listen.is_empty();
        // The listeners are non-empty here (`secure` is `None` otherwise), and
        // `build_turn` already validated the value — same helper, same rule.
        let poll = match cert_poll_interval(args.tls_cert_poll, true, cfg!(unix)) {
            Ok(poll) => poll,
            Err(message) => {
                tracing::error!(%message, "rstun: invalid TLS configuration");
                return ExitCode::FAILURE;
            }
        };
        match load_secure_material(cert, key, needs_dtls) {
            Ok(loaded) => {
                let secure_stats = Arc::new(SecureStats::default());
                secure_stats.set_not_after(loaded.not_after);
                stats.set_secure(secure_stats.clone());
                Some(SecureSetup {
                    slot: Arc::new(std::sync::RwLock::new(loaded.material)),
                    cert: cert.clone(),
                    key: key.clone(),
                    needs_dtls,
                    poll,
                    stats: secure_stats,
                })
            }
            Err(message) => {
                tracing::error!(%message, "rstun: invalid TLS configuration");
                return ExitCode::FAILURE;
            }
        }
    };
    // Every listener shares one view of the bound sockets: that is what makes
    // `CHANGE-REQUEST` able to answer from a different one.
    let context = Arc::new(ServerContext {
        plan,
        udp: udp.clone(),
        mapped_address: args.mapped_address,
        admission: admission.clone(),
        fingerprint,
        alternate_server,
        auth,
    });
    let mut tasks = Vec::new();
    let mut listeners = Vec::new();

    // 运维端点：只有给了 `--health-listen` 才绑定（默认零新增）。先绑再起任何任务：
    // 与 STUN socket 同样的「要么全起、要么全不起」，不要起了一半还说自己健康。
    let ops_listener = match args.health_listen {
        None => None,
        Some(address) => match tcp_listener(address) {
            Ok(listener) => Some(listener),
            Err(error) => {
                tracing::error!(%address, %error, "rstun: failed to bind --health-listen");
                return ExitCode::FAILURE;
            }
        },
    };

    // `turns:` listeners are bound up front with the same "all or nothing" rule
    // as the STUN sockets: a port already taken is a refused start, not a
    // server that silently has one transport less than announced.
    #[cfg(feature = "tls")]
    let mut tls_listeners = Vec::new();
    #[cfg(feature = "tls")]
    if let Some(material) = &secure {
        for address in &args.turn_tls_listen {
            match tcp_listener(*address) {
                Ok(listener) => tls_listeners.push((*address, listener, material.slot.clone())),
                Err(error) => {
                    tracing::error!(%address, %error, "rstun: failed to bind --turn-tls-listen");
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    #[cfg(feature = "tls")]
    for (local, listener, material) in tls_listeners {
        let (task, health) = spawn_listener(
            format!("tls {local}"),
            serve_turn_tls(
                listener,
                material,
                context.clone(),
                software.clone(),
                stats.clone(),
            ),
        );
        tasks.push(task);
        listeners.push(health);
    }
    // DTLS: the parent UDP listener is bound here; the handshake happens per
    // client in its own task (see `serve_turn_dtls`). The accept filter keeps a
    // non-DTLS datagram from allocating a session at all.
    #[cfg(feature = "dtls")]
    if !args.turn_dtls_listen.is_empty()
        && let Some(material) = &secure
    {
        // `load_secure_material(…, needs_dtls = !turn_dtls_listen.is_empty())`
        // guarantees this; failing loudly beats serving a listener every client
        // would fail to handshake with.
        if current_material(&material.slot).dtls.is_none() {
            tracing::error!("rstun: DTLS listener without DTLS material (internal bug)");
            return ExitCode::FAILURE;
        }
        for address in &args.turn_dtls_listen {
            let mut config = webrtc_util::conn::conn_udp_listener::ListenConfig {
                accept_filter: Some(Box::new(|packet: &[u8]| {
                    // ContentType::Handshake == 22 (RFC 6347 §4.1); a record
                    // header is 13 bytes. Anything else is not a handshake.
                    let looks_like_handshake = packet.len() >= 13 && packet[0] == 22;
                    Box::pin(async move { looks_like_handshake })
                })),
                ..Default::default()
            };
            let listener = match config.listen(*address).await {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::error!(%address, %error, "rstun: failed to bind --turn-dtls-listen");
                    return ExitCode::FAILURE;
                }
            };
            let (task, health) = spawn_listener(
                format!("dtls {address}"),
                serve_turn_dtls(
                    listener,
                    material.slot.clone(),
                    context.clone(),
                    software.clone(),
                    stats.clone(),
                ),
            );
            tasks.push(task);
            listeners.push(health);
        }
    }
    for (local, socket) in udp {
        let (task, health) = spawn_listener(
            format!("udp {local}"),
            serve_udp(socket, context.clone(), software.clone(), stats.clone()),
        );
        tasks.push(task);
        listeners.push(health);
    }
    for (local, listener) in tcp {
        let (task, health) = spawn_listener(
            format!("tcp {local}"),
            serve_tcp(listener, context.clone(), software.clone(), stats.clone()),
        );
        tasks.push(task);
        listeners.push(health);
    }
    // Only a per-key table needs sweeping; a guard that is only a Semaphore or
    // a CIDR list must not start a task it never uses. Kept **out of `tasks`**:
    // the sweeper lives until the process ends, so waiting for it would make
    // every SIGTERM block until `--drain-timeout`.
    let sweeper = admission.as_ref().and_then(limit::start_sweeper);
    // TURN 的 1s 扫描任务同样常驻、不参与 drain（与限速 sweeper 同一条规则）。
    let turn_sweeper = turn.as_ref().map(turn::Turn::start_sweeper);
    // Certificate rotation: SIGHUP (Unix) + the `--tls-cert-poll` timer (30 s
    // by default, off with `0`), both driving the same
    // `reload_secure_material`. Only exists when a secure listener does, and it
    // leaves on drain (it is not tracked as in-flight work).
    #[cfg(feature = "tls")]
    let cert_reloader = secure.as_ref().and_then(|setup| {
        // `--tls-cert-poll 0` keeps the task for SIGHUP on Unix. Where there is
        // no SIGHUP (Windows) that combination is refused at startup, so a task
        // with neither trigger would never run: don't spawn one.
        if setup.poll.is_none() && !cfg!(unix) {
            return None;
        }
        Some(spawn_cert_reloader(setup.clone(), stats.clone()))
    });
    let listener_count = listeners.len();
    let ops_task = ops_listener.map(|listener| {
        let state = Arc::new(ops::OpsState::new(
            listeners.clone(),
            stats.clone(),
            context.clone(),
        ));
        tokio::spawn(ops::serve_http(listener, state, health_max_connections))
    });

    if let Some(admission) = &admission {
        let policy = admission.policy();
        tracing::info!(
            per_ip = ?policy.per_ip,
            per_port = ?policy.per_port,
            global = ?policy.global,
            max_inflight = ?policy.max_inflight,
            reflect = ?policy.reflect,
            allow = policy.allow.len(),
            deny = policy.deny.len(),
            "rstun: abuse guard enabled"
        );
    }

    if let Some(plan) = plan {
        tracing::info!(
            primary = %plan.primary,
            other_ip = %plan.other_ip,
            other_port = plan.other_port,
            "rstun: RFC 5780 enabled (CHANGE-REQUEST / RESPONSE-ORIGIN / OTHER-ADDRESS)"
        );
    }
    if args.mapped_address {
        tracing::info!("rstun: legacy MAPPED-ADDRESS enabled (--mapped-address)");
    }
    if let Some(action) = fingerprint {
        tracing::info!(
            ?action,
            "rstun: FINGERPRINT validation enabled (--check-fingerprint)"
        );
    }
    if let Some(server) = alternate_server {
        tracing::info!(%server, "rstun: answering with 300 Try Alternate (--alternate-server)");
    }
    if let Some(auth) = &context.auth {
        tracing::info!(
            mode = ?auth.mode(),
            realm = auth.realm(),
            users = auth.user_count(),
            require_sha256 = auth.require_sha256(),
            "rstun: authentication enabled"
        );
        // A 401 is the biggest answer this server emits per request: for a
        // 28-byte probe it is ~3.4-5.0x. Rate limiting is the documented
        // mitigation, so say it out loud when it is missing.
        if admission.is_none() {
            tracing::warn!(
                "rstun: authentication without --rate-limit/--reflect-ratio: a 401 can amplify a \
                 small request by 3-5x; enable the abuse guard in production"
            );
        }
    }
    if let Some(turn) = &turn {
        let config = turn.config();
        tracing::info!(
            relay_ports = ?config.relay_ports,
            max_allocations_per_user = config.max_allocations_per_user,
            max_allocations_per_ip = config.max_allocations_per_ip,
            permission_limit = config.permission_limit,
            lifetime_seconds = config.lifetime.as_secs(),
            bandwidth = config.bandwidth,
            "rstun: TURN relay enabled (long-term credentials required)"
        );
        #[cfg(feature = "tls")]
        if !args.turn_tls_listen.is_empty() {
            tracing::info!(
                listeners = ?args.turn_tls_listen,
                "rstun: TURN over TLS enabled (turns:)"
            );
        }
        #[cfg(feature = "dtls")]
        if !args.turn_dtls_listen.is_empty() {
            tracing::info!(
                listeners = ?args.turn_dtls_listen,
                "rstun: TURN over DTLS enabled"
            );
        }
        if let Some(auth) = &context.auth
            && auth.has_rest_secret()
        {
            tracing::info!("rstun: TURN REST API credentials enabled (--rest-secret)");
        }
    }
    tracing::info!(
        software = %software,
        features = BUILD_FEATURES,
        listeners = listener_count,
        "rstun: started, Ctrl-C to stop"
    );

    let exit_code = match wait_for_shutdown().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "rstun: failed while waiting for a shutdown signal");
            ExitCode::FAILURE
        }
    };

    // 优雅退出（design §5）：先停「收新活」，再等在途，最后才 abort。
    // 第二次信号立刻退出（运维兜底：drain 卡住时不必等超时）。
    stats.begin_drain();
    tokio::spawn(async move {
        if wait_for_shutdown().await.is_ok() {
            tracing::warn!("rstun: second shutdown signal, exiting without draining");
            std::process::exit(0);
        }
    });
    let deadline = tokio::time::Instant::now() + drain_timeout;
    let mut unfinished = 0_u32;
    for task in &mut tasks {
        // `timeout_at` 用同一个截止时间：一个 listener 卡住不会把后面的等待翻倍。
        if tokio::time::timeout_at(deadline, &mut *task).await.is_err() {
            unfinished += 1;
        }
    }
    let in_flight = stats.wait_idle(deadline).await;
    if unfinished > 0 || in_flight > 0 {
        tracing::warn!(
            drain_timeout_ms = drain_timeout.as_millis() as u64,
            unfinished_listeners = unfinished,
            in_flight,
            "rstun: drain timed out, exiting with work still pending"
        );
    } else {
        tracing::info!("rstun: drained, no work in flight");
    }
    for task in tasks {
        task.abort();
    }
    if let Some(task) = sweeper {
        task.abort();
    }
    if let Some(task) = turn_sweeper {
        task.abort();
    }
    #[cfg(feature = "tls")]
    if let Some(task) = cert_reloader {
        task.abort();
    }
    if let Some(task) = ops_task {
        // 健康端点留到最后一刻：drain 期间仍可抓取最终指标。
        task.abort();
    }
    // 被拒的请求数与协议统计分开报：前者只有开了抗滥用才非零。
    if let Some(admission) = &admission {
        let counts = admission.counters();
        tracing::info!(
            rate_limited_ip = counts.rate_limited_ip,
            rate_limited_port = counts.rate_limited_port,
            rate_limited_global = counts.rate_limited_global,
            inflight_dropped = counts.inflight_dropped,
            denied = counts.denied,
            reflect_rejected = counts.reflect_rejected,
            allowlisted = counts.allowlisted,
            "rstun: abuse guard counters"
        );
    }
    let (received, answered, dropped) = stats.counters();
    tracing::info!(
        received,
        answered,
        dropped,
        fingerprint_rejected = stats.fingerprint_rejected(),
        "rstun: stopped"
    );
    if let Some(auth) = &context.auth {
        let (authenticated, unauthorized, stale_nonce, bad_request) = auth.counters().snapshot();
        tracing::info!(
            authenticated,
            unauthorized,
            stale_nonce,
            bad_request,
            "rstun: authentication counters"
        );
    }
    if let Some(turn) = &turn {
        let counts = turn.snapshot();
        tracing::info!(
            active_allocations = counts.active,
            created = counts.created,
            expired = counts.expired,
            bytes_in = counts.bytes_in,
            bytes_out = counts.bytes_out,
            rejected_quota = counts.rejected_quota,
            rejected_ports = counts.rejected_ports,
            rejected_family = counts.rejected_family,
            rejected_loopback = counts.rejected_loopback,
            rejected_df = counts.rejected_df,
            bytes_dropped_in = counts.bytes_dropped_in,
            bytes_dropped_out = counts.bytes_dropped_out,
            handshake_failed = counts.handshake_failed,
            "rstun: TURN counters"
        );
    }
    // Same precedent as `handshake_failed`: the reload outcome is an exit-log
    // line as well as the two `/metrics` families.
    #[cfg(feature = "tls")]
    if let Some(secure) = stats.secure() {
        let counts = secure.snapshot();
        tracing::info!(
            reload_ok = counts.reload_ok,
            reload_failed = counts.reload_failed,
            cert_expires_seconds = counts.cert_expires_seconds,
            "rstun: TURN TLS certificate counters"
        );
    }
    exit_code
}

/// Spawn one listener task, logging if it ever stops (a dead listener must not
/// leave the process quietly serving with fewer sockets than it announced).
///
/// The returned [`ops::ListenerHealth`] is what `/healthz` reads: the task holds
/// the lease for its whole life, so *any* way of ending (error return, normal
/// return while draining, abort) marks that listener stale.
fn spawn_listener<F>(
    name: String,
    listener: F,
) -> (tokio::task::JoinHandle<()>, ops::ListenerHealth)
where
    F: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    let health = ops::ListenerHealth::new(name.clone());
    let lease = health.lease();
    let task = tokio::spawn(async move {
        let _lease = lease;
        if let Err(error) = listener.await {
            tracing::error!(listener = %name, %error, "rstun: listener stopped");
        }
    });
    (task, health)
}

/// Requests below this size get an answer without the optional `SOFTWARE`
/// attribute when they carry a redirect attribute (see [`answer_software`]).
const SMALL_REDIRECT_REQUEST: usize = 40;

/// Is this message one the reflection guard has jurisdiction over?
///
/// The guard only applies to **UDP** (a TCP answer can only reach the peer that
/// opened the connection) and only to a redirect this server can actually
/// honour: `RESPONSE-PORT` always can, `CHANGE-REQUEST` only when
/// `--alt-listen` gave us a second address.
///
/// [`answer_software`] uses the same predicate on purpose: the SOFTWARE rule
/// must not be wider than the guard, otherwise a TCP probe or a
/// `CHANGE-REQUEST` without a plan would lose its `SOFTWARE` for no reason.
fn redirect_is_guarded(
    transport: Transport,
    message: &protocol::Message<'_>,
    context: &ServerContext,
) -> bool {
    if transport != Transport::Udp {
        return false;
    }
    protocol::response_port(message.body).is_some()
        || (context.plan.is_some()
            && protocol::change_request(message.body)
                .filter(protocol::ChangeRequest::any)
                .is_some())
}

/// The `SOFTWARE` value to put into a Binding success answer.
///
/// `SOFTWARE` is optional (RFC 5389 §15.5.1) and costs 20 bytes on the wire.
/// With the abuse guard on, a *small* probe **inside the guard's domain** (see
/// [`redirect_is_guarded`]) gets an answer without it: the fixed part is then
/// just `XOR-MAPPED-ADDRESS` (12) and, with `--alt-listen`, the RFC 5780 pair
/// (24) — the 32 bytes [`limit::REFLECT_ALLOWANCE`] pays for. A 28-byte probe
/// therefore gets 32 bytes instead of 52 (1.14x instead of 1.86x) and 56
/// instead of 76 with `--alt-listen` (2.00x instead of 2.71x): the answer is at
/// its irreducible size, which is what lets the ratio rule reject real growth.
///
/// Everything else keeps the full `SOFTWARE`: plain Binding (byte-frozen), any
/// request of [`SMALL_REDIRECT_REQUEST`] bytes or more, a TCP probe, and a
/// `CHANGE-REQUEST` that cannot redirect because there is no plan. With the
/// guard off the full value is always used, so the default path stays
/// byte-for-byte the pre-guard one.
fn answer_software<'a>(
    request_len: usize,
    message: &protocol::Message<'_>,
    transport: Transport,
    context: &ServerContext,
    software: &'a str,
) -> &'a str {
    let guard_on = context
        .admission
        .as_ref()
        .is_some_and(|admission| admission.policy().reflect.is_some());
    if !guard_on
        || request_len >= SMALL_REDIRECT_REQUEST
        || !redirect_is_guarded(transport, message, context)
    {
        return software;
    }
    ""
}

/// Seal an answer with the request's integrity key(s), if the request was
/// authenticated (RFC 5389 §10.2.2: "the response MUST contain a
/// MESSAGE-INTEGRITY attribute").
///
/// `None` is the unauthenticated path — and the byte-frozen default — so the
/// helper is a no-op there. The one answer this cannot cover is `500`: it is
/// built where the failure happens (`respond_to_datagram`), below `decide`, so
/// no identity is available (README documents that).
fn seal_answer(bytes: Vec<u8>, identity: Option<&auth::Identity>) -> Vec<u8> {
    match identity {
        Some(identity) => auth::seal(bytes, identity),
        None => bytes,
    }
}

/// Resolve one message into a response, or explain why it is ignored.
///
/// `local` is the address of the socket / connection the message arrived on.
/// Without RFC 5780 it is only bookkeeping; with `--alt-listen` it also becomes
/// `RESPONSE-ORIGIN` and the basis for `CHANGE-REQUEST`.
fn decide(
    datagram: &[u8],
    peer: SocketAddr,
    local: SocketAddr,
    transport: Transport,
    context: &ServerContext,
    software: &str,
) -> Result<Decision, protocol::ParseError> {
    let message = protocol::parse(datagram)?;
    if protocol::message_class(message.msg_type) != MessageClass::Request {
        return Ok(Decision::Ignore("not a request"));
    }
    if protocol::message_method(message.msg_type) != BINDING_METHOD {
        // RFC 5389 §7.3.1: a server that only implements Binding answers other
        // methods with 400 rather than leaving the client to time out.
        tracing::debug!(
            %peer,
            transaction_id = %message.transaction_id,
            method = protocol::message_method(message.msg_type),
            "rstun: unsupported method"
        );
        return Ok(Decision::Respond(protocol::error_response(
            &message.transaction_id,
            protocol::message_method(message.msg_type),
            protocol::ERROR_BAD_REQUEST,
            "Bad Request",
        )));
    }

    // `--alternate-server`: this instance only redirects. It deliberately comes
    // before the extension checks below (design §4: *every* Binding request gets
    // 300), including RFC 5780's redirect attributes — the point is to move the
    // client to the real server, not to answer the probe ourselves.
    if let Some(server) = context.alternate_server {
        tracing::debug!(
            %peer,
            transaction_id = %message.transaction_id,
            %server,
            "rstun: answering 300 Try Alternate"
        );
        return Ok(Decision::Respond(protocol::alternate_server_response(
            &message.transaction_id,
            BINDING_METHOD,
            server,
        )));
    }

    // RFC 5389 §10: authentication, when configured, comes here — after the
    // redirect (a client that must move to another server does not need
    // credentials for this one) and after FINGERPRINT (checked in
    // [`decide_guarded`]: message integrity before credential integrity), but
    // before every other attribute check, so an unauthenticated client cannot
    // probe the 420/400 branches.
    //
    // The rate-limit buckets have already run in the caller (`admit` /
    // `check_rates`), which is what keeps a 401 flood inside the guard: the
    // answer may be bigger than the request, but not more frequent.
    let identity = match &context.auth {
        None => None,
        Some(auth) => {
            // One clock read per request: the challenge/438 nonce must be issued
            // against the same instant that judged the request's own nonce.
            let now = SystemTime::now();
            // `HEADER_LEN + body.len()` is the declared frame: a UDP datagram
            // may carry trailing junk, and the MAC covers only the frame.
            let frame = &datagram[..protocol::HEADER_LEN + message.body.len()];
            let outcome = auth.verify(frame, &message, peer.ip(), now);
            auth.count(&outcome);
            match outcome {
                Ok(identity) => {
                    tracing::debug!(
                        %peer,
                        transaction_id = %message.transaction_id,
                        username = %identity.username,
                        "rstun: authenticated"
                    );
                    Some(identity)
                }
                Err(rejection) => {
                    tracing::debug!(
                        %peer,
                        transaction_id = %message.transaction_id,
                        ?rejection,
                        "rstun: authentication rejected"
                    );
                    return Ok(Decision::Respond(auth.rejection_response(
                        rejection,
                        &message.transaction_id,
                        BINDING_METHOD,
                        peer.ip(),
                        now,
                    )));
                }
            }
        }
    };

    // RFC 5389 §7.3.1: a request carrying an attribute we do not implement must
    // be *rejected* with 420, not answered partially — a client that sends an
    // extension we ignore cannot tell "unsupported" from "malformed answer".
    // The list in the response says which attribute to stop sending.
    let unknown = protocol::unknown_attributes(message.body);
    if !unknown.is_empty() {
        tracing::debug!(
            %peer,
            transaction_id = %message.transaction_id,
            ?unknown,
            "rstun: unknown comprehension-required attributes"
        );
        return Ok(Decision::Respond(seal_answer(
            protocol::unknown_attributes_response(
                &message.transaction_id,
                BINDING_METHOD,
                &unknown,
            ),
            identity.as_ref(),
        )));
    }

    // RFC 5780 §7.6 PADDING: echo the same amount of filler back, so an MTU /
    // fragmentation probe sees an equally large answer. Length only — the value
    // is meaningless by definition.
    let padding = protocol::padding_len(message.body);
    // RFC 5780 §6 (response processing): "If the Request also contains the
    // RESPONSE-PORT attribute the server MUST return an error response of type
    // 400"; §7.5 restates it as "The server MUST NOT process a request
    // containing a RESPONSE-PORT and a PADDING attribute", and §10 as "Requests
    // containing both RESPONSE-PORT and PADDING are rejected by the server".
    // The two attributes probe different things (datagram size vs. alternate
    // return port), so the combination is *refused* with a visible 400 rather
    // than silently dropped — a dropped datagram only looks like a filtered path.
    let response_port = protocol::response_port(message.body);
    if padding.is_some() && response_port.is_some() {
        tracing::debug!(
            %peer,
            transaction_id = %message.transaction_id,
            "rstun: PADDING together with RESPONSE-PORT (RFC 5780 §6)"
        );
        return Ok(Decision::Respond(seal_answer(
            protocol::error_response(
                &message.transaction_id,
                BINDING_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
            ),
            identity.as_ref(),
        )));
    }

    // Where the answer goes and which socket sends it. Only UDP can do anything
    // unusual: over TCP the reply can only travel back on the connection it
    // arrived on, so both `RESPONSE-PORT` and `CHANGE-REQUEST` are ignored there
    // (RFC 5780 §5 is defined for UDP).
    let (from, to, addresses) = response_route(&message, peer, local, transport, context);

    tracing::debug!(
        source = %peer,
        mapped = %peer,
        %local,
        transaction_id = %message.transaction_id,
        response_origin = ?addresses.map(|addresses| addresses.origin),
        padding = ?padding,
        %from,
        %to,
        "rstun: binding request"
    );

    let bytes = protocol::binding_success_response(&protocol::SuccessResponse {
        transaction_id: &message.transaction_id,
        peer,
        software: answer_software(datagram.len(), &message, transport, context, software),
        addresses,
        mapped_address: context.mapped_address,
        padding,
    });
    // RFC 5389 §10.2.2 / RFC 8489 §9.2.4: *every* answer to an authenticated
    // request (200 / 420 / 400) carries the integrity attribute(s) the request
    // used. Added *after* the frozen default shape, so an unauthenticated
    // deployment emits exactly the pre-auth bytes.
    let bytes = seal_answer(bytes, identity.as_ref());
    if from == local && to == peer {
        Ok(Decision::Respond(bytes))
    } else {
        Ok(Decision::RespondFrom { from, to, bytes })
    }
}

/// Where an answer goes and which socket sends it.
///
/// Split out of [`decide`] because the reflection guard has to *estimate* the
/// very same answer before `decide` builds it: one implementation of the RFC
/// 5780 routing rules, two callers.
///
/// The two attributes are orthogonal and may both apply:
/// * §7.2 `CHANGE-REQUEST` picks the *source* socket;
/// * §7.5 `RESPONSE-PORT` picks the *destination* port, keeping both the
///   source IP and the source port ("the Binding Response MUST be transmitted
///   to the source IP address of the Binding Request and the port contained in
///   RESPONSE-PORT").
fn response_route(
    message: &protocol::Message<'_>,
    peer: SocketAddr,
    local: SocketAddr,
    transport: Transport,
    context: &ServerContext,
) -> (SocketAddr, SocketAddr, Option<protocol::ResponseAddresses>) {
    let (from, to) = match transport {
        Transport::Tcp => (local, peer),
        Transport::Udp => {
            // RFC 5780 §5: a server that cannot honour CHANGE-REQUEST simply
            // answers from the socket the request arrived on. Only the plan's
            // four sockets can honour it — `Plan::flipped` treats any other
            // address as "primary", which would silently move the answer of a
            // plain `--listen`/`--listen-v6` socket to a foreign address.
            let from = context
                .plan
                .filter(|plan| plan.is_plan_socket(local))
                .and_then(|plan| {
                    protocol::change_request(message.body)
                        .filter(protocol::ChangeRequest::any)
                        .map(|request| plan.changed(local, request))
                })
                .unwrap_or(local);
            let to = match protocol::response_port(message.body) {
                // Any 16-bit port is a legal destination; whether anything
                // listens there is the client's problem (`0` included — the
                // kernel refuses the send, we log it and keep serving).
                Some(port) => SocketAddr::new(peer.ip(), port),
                None => peer,
            };
            (from, to)
        }
    };
    (from, to, context.addresses(from))
}

/// [`decide`], with the abuse guard's reflection check and the optional
/// `FINGERPRINT` validation in front of it.
///
/// Both are off by default, so without flags this is `decide` plus one `Option`
/// test; only when one of them is enabled is the message parsed a second time
/// (the pre-existing shape for the reflection guard, kept because `decide` must
/// stay byte-for-byte the function it was).
fn decide_guarded(
    datagram: &[u8],
    peer: SocketAddr,
    local: SocketAddr,
    transport: Transport,
    context: &ServerContext,
    software: &str,
    stats: &ServerStats,
) -> Result<Decision, protocol::ParseError> {
    let reflect = context
        .admission
        .as_ref()
        .and_then(|admission| admission.policy().reflect);
    if context.fingerprint.is_none() && reflect.is_none() && context.auth.is_none() {
        return decide(datagram, peer, local, transport, context, software);
    }
    let message = protocol::parse(datagram)?;
    if let Some(action) = context.fingerprint
        && let Some(decision) = fingerprint_guard(datagram, &message, action, transport, stats)
    {
        return Ok(decision);
    }
    if let Some(admission) = &context.admission
        && let Some(policy) = reflect
    {
        let inbound = Inbound {
            datagram,
            peer,
            local,
            transport,
            context,
            software,
        };
        if let Some(decision) = reflect_guard(&inbound, &message, admission, policy, stats) {
            return Ok(decision);
        }
    }
    decide(datagram, peer, local, transport, context, software)
}

/// Validate `FINGERPRINT` when `--check-fingerprint` is on (RFC 5389 §15.5).
///
/// Only **requests** are validated: a server must not answer an indication or a
/// response at all, so a bad fingerprint there stays silence (`decide` ignores
/// the message for its own reasons). A structural error (another attribute after
/// `FINGERPRINT`) is always answered with `400`; only a CRC mismatch honours
/// `--fingerprint-action=drop`, because a misplaced attribute means the client
/// cannot interpret the message boundary either way.
fn fingerprint_guard(
    datagram: &[u8],
    message: &protocol::Message<'_>,
    action: FingerprintAction,
    transport: Transport,
    stats: &ServerStats,
) -> Option<Decision> {
    if protocol::message_class(message.msg_type) != MessageClass::Request {
        return None;
    }
    let frame = &datagram[..protocol::HEADER_LEN + message.body.len()];
    let verdict = protocol::check_fingerprint(frame);
    if matches!(
        verdict,
        protocol::FingerprintVerdict::Absent | protocol::FingerprintVerdict::Valid
    ) {
        return None;
    }
    stats.count_fingerprint_rejected();
    tracing::debug!(
        transaction_id = %message.transaction_id,
        ?verdict,
        ?action,
        "rstun: FINGERPRINT rejected"
    );
    match (verdict, action) {
        (protocol::FingerprintVerdict::NotLast, _) | (_, FingerprintAction::Answer) => {
            Some(Decision::Respond(protocol::error_response(
                &message.transaction_id,
                protocol::message_method(message.msg_type),
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
            )))
        }
        (_, FingerprintAction::Drop) => {
            // Counted twice on purpose: `dropped` keeps `received = answered +
            // dropped` readable for this path, `fingerprint_rejected` says *why*.
            stats.count_dropped(transport);
            Some(Decision::Ignore("fingerprint mismatch"))
        }
    }
}

/// The request path's fixed context, bundled so the guard stays readable.
struct Inbound<'a> {
    datagram: &'a [u8],
    peer: SocketAddr,
    local: SocketAddr,
    transport: Transport,
    context: &'a ServerContext,
    software: &'a str,
}

/// Anti-reflection: refuse the attributes that let one small datagram make us
/// send a large answer somewhere else (design §2/§4).
///
/// Only `RESPONSE-PORT` (moves the answer to an arbitrary **destination** port —
/// the classic spoofed-source reflector) and `CHANGE-REQUEST` (moves the
/// **source**) are gated; plain Binding is untouched, otherwise every probe
/// would need to be as large as its answer.
///
/// The comparison uses the real encoder, not a guess: the same
/// [`protocol::SuccessResponse`] `decide` will build is serialised and measured.
fn reflect_guard(
    inbound: &Inbound<'_>,
    message: &protocol::Message<'_>,
    admission: &limit::Admission,
    policy: limit::Reflect,
    stats: &ServerStats,
) -> Option<Decision> {
    // A TCP answer can only travel back on the connection the request came in
    // on, so it cannot reflect onto a third party: the guard is UDP-only.
    if inbound.transport != Transport::Udp {
        return None;
    }
    // `--allow` is the operator saying "these sources are mine": an allowlisted
    // source is exempt from the amplification rules (NAT'd probe networks, the
    // monitoring host, …). Rate limits still apply unless `--allow` skipped
    // them too, and the global/in-flight caps are never bypassed.
    if admission.is_allowlisted(inbound.peer.ip()) {
        return None;
    }
    // Everything else is either answered with a small 400/420 or ignored by
    // `decide`; there is no large answer to prevent.
    //
    // `--alternate-server` changes that: every Binding request (even one with an
    // unknown comprehension-required attribute, which `decide` never reaches)
    // gets the fixed 300. The guard therefore estimates *that* answer below.
    let alternate = inbound.context.alternate_server.is_some();
    if protocol::message_class(message.msg_type) != MessageClass::Request
        || protocol::message_method(message.msg_type) != BINDING_METHOD
        || (!alternate && !protocol::unknown_attributes(message.body).is_empty())
    {
        return None;
    }
    let padding = protocol::padding_len(message.body);
    let response_port = protocol::response_port(message.body);
    // RESPONSE-PORT + PADDING is a 400 (RFC 5780 §6) — a *refusal*, so it goes
    // through the same "a refusal must not amplify" rule as everything else on
    // this path (and is counted in `reflect_rejected`). Without the guard,
    // `decide` still answers the 400 itself. With `--alternate-server` the
    // answer is a 300 (redirect wins), so this early refusal does not apply.
    if !alternate && padding.is_some() && response_port.is_some() {
        return Some(reflection_refusal(
            inbound, message, policy, admission, stats,
        ));
    }
    // The guard's domain: UDP, and a redirect we can actually honour
    // (`RESPONSE-PORT` always, `CHANGE-REQUEST` only with a plan). A
    // `CHANGE-REQUEST` without a plan moves nothing, so it is not a reflection
    // vector and must not be gated — 28-byte RFC 5780 probes would otherwise be
    // refused for no reason. `answer_software` shares this predicate.
    if !redirect_is_guarded(inbound.transport, message, inbound.context) {
        return None;
    }

    if inbound.datagram.len() < policy.min_request {
        return Some(reflection_refusal(
            inbound, message, policy, admission, stats,
        ));
    }

    let context = inbound.context;
    // Estimate with the very bytes `decide` will emit, otherwise the ratio would
    // be measured on a different message than the one we send: a 300 is fixed
    // size and carries no redirect attributes, a success answer depends on
    // SOFTWARE / RFC 5780 / PADDING.
    let estimated = if let Some(server) = context.alternate_server {
        protocol::alternate_server_response(&message.transaction_id, BINDING_METHOD, server).len()
    } else {
        let (_from, _to, addresses) = response_route(
            message,
            inbound.peer,
            inbound.local,
            inbound.transport,
            context,
        );
        let sealed = protocol::binding_success_response(&protocol::SuccessResponse {
            transaction_id: &message.transaction_id,
            peer: inbound.peer,
            software: answer_software(
                inbound.datagram.len(),
                message,
                inbound.transport,
                context,
                inbound.software,
            ),
            addresses,
            mapped_address: context.mapped_address,
            padding,
        });
        // With authentication on, this request's answer is *not* necessarily the
        // success response: an unauthenticated one gets a 401 (or a 438),
        // which is much bigger than a 50-byte success. The guard cannot know
        // whether the credentials verify without doing the whole check twice, so
        // it takes the **largest** of the two candidates — an upper bound, never
        // an underestimate (abuse-guard spec §5: estimate and actual must be the
        // same message, or every ratio boundary can be walked past).
        let success = sealed.len()
            + if context.auth.is_some() {
                auth::integrity_overhead(message)
            } else {
                0
            };
        match &context.auth {
            Some(auth) => success.max(auth.challenge_len()),
            None => success,
        }
    };
    if !policy.allows_response(inbound.datagram.len(), estimated) {
        return Some(reflection_refusal(
            inbound, message, policy, admission, stats,
        ));
    }
    None
}

/// Answer a refused reflection probe — without becoming a reflector ourselves.
///
/// A `400 Bad Request` is **40 bytes** (20-byte header + 20-byte `ERROR-CODE`
/// with the "Bad Request" reason). The refusal is only sent while it fits the
/// *strict* ratio — deliberately without the [`limit::REFLECT_ALLOWANCE`] the
/// success path gets, because that allowance pays for attributes (XOR / SOFTWARE
/// / RFC 5780 pair) a 400 does not carry. If the 400 would be bigger than the
/// request allows, the datagram is dropped silently. Either way it is counted:
/// `reflect_rejected` plus the ordinary `dropped`, like every other refusal.
fn reflection_refusal(
    inbound: &Inbound<'_>,
    message: &protocol::Message<'_>,
    policy: limit::Reflect,
    admission: &limit::Admission,
    stats: &ServerStats,
) -> Decision {
    admission.count_reflect_rejected();
    stats.count_dropped(inbound.transport);
    let bad_request = protocol::error_response(
        &message.transaction_id,
        BINDING_METHOD,
        protocol::ERROR_BAD_REQUEST,
        "Bad Request",
    );
    if bad_request.len() as f64 <= inbound.datagram.len() as f64 * policy.ratio {
        Decision::Respond(bad_request)
    } else {
        Decision::Ignore("reflection guard: too small to answer without amplifying")
    }
}

/// Serve one UDP socket until draining starts (or the task is aborted).
///
/// Two shapes, chosen once at startup:
///
/// * **serial** (no `--max-inflight`): one datagram at a time in this task —
///   the default path, unchanged, no extra tasks;
/// * **concurrent** (`--max-inflight` set): each datagram gets its own task so
///   the in-flight cap can actually be reached. In the serial loop one listener
///   holds at most one permit, so a cap above 1 could never trigger and
///   `--max-inflight 1` would silently do nothing.
///
/// Draining only stops the *read*: the datagram in this task's hands finishes
/// (including its send) before the loop exits, and the spawned shape is counted
/// by [`ServerStats::enter`] so the shutdown path can wait for it.
async fn serve_udp(
    socket: Arc<UdpSocket>,
    context: Arc<ServerContext>,
    software: Arc<str>,
    stats: Arc<ServerStats>,
) -> std::io::Result<()> {
    let local = socket.local_addr()?;
    tracing::info!(%local, "rstun: UDP listener ready");
    let concurrent = context
        .admission
        .as_ref()
        .is_some_and(|admission| admission.policy().max_inflight.is_some());
    let mut drain = stats.subscribe_drain();
    if stats.is_draining() {
        return Ok(());
    }
    let mut buffer = vec![0_u8; UDP_RECV_BUFFER];
    loop {
        let received = tokio::select! {
            biased;
            // SIGTERM: stop taking new datagrams; the socket stays bound.
            _ = drain.changed() => break,
            received = socket.recv_from(&mut buffer) => received,
        };
        let (len, peer) = match received {
            Ok(received) => received,
            Err(error) => {
                // 单个 datagram 的读错误（瞬时 ICMP 等）不该打死监听。
                stats.count_socket_error(Transport::Udp);
                tracing::warn!(%local, %error, "rstun: UDP recv_from failed");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        stats.count_received(Transport::Udp);
        // 抗滥用准入：在解析/判定之前只做「能不能处理」的判定，不改协议语义。
        // permit 必须活到响应发出之后 —— 在途上限统计的就是「正在处理的请求」。
        let permit = match context.admit(peer) {
            None => None,
            Some(Ok(permit)) => Some(permit),
            Some(Err(refusal)) => {
                stats.count_dropped(Transport::Udp);
                tracing::debug!(
                    %local,
                    %peer,
                    reason = refusal.reason(),
                    counter = refusal.counter(),
                    "rstun: UDP datagram refused by abuse guard"
                );
                continue;
            }
        };
        if concurrent {
            let socket = socket.clone();
            let context = context.clone();
            let software = software.clone();
            let stats = stats.clone();
            let datagram = buffer[..len].to_vec();
            // Counted *before* the spawn: otherwise a SIGTERM landing in the gap
            // could see an empty in-flight set and abort this datagram.
            let in_flight = stats.enter();
            tokio::spawn(async move {
                respond_to_datagram(&socket, &context, &software, &stats, local, peer, &datagram)
                    .await;
                drop(in_flight);
                // Releasing the permit last is what the cap counts.
                drop(permit);
            });
        } else {
            let in_flight = stats.enter();
            respond_to_datagram(
                &socket,
                &context,
                &software,
                &stats,
                local,
                peer,
                &buffer[..len],
            )
            .await;
            drop(in_flight);
            drop(permit);
        }
    }
    tracing::info!(%local, "rstun: UDP listener stopped (draining)");
    Ok(())
}

/// Map a failed `send_to` to a STUN error code, or `None` when the failure is the
/// **client's** address problem rather than an internal one (design §2).
///
/// `ConnectionRefused` / `NetworkUnreachable` / `AddrNotAvailable` describe where
/// the datagram was going, not what this server did: answering them with `500`
/// would claim an internal fault and add traffic to a path that is already
/// broken. Everything else means the send failed for a reason we cannot express
/// in the original answer, so the client gets an explicit `500 Server Error`.
fn server_error_for(error: &std::io::Error) -> Option<u16> {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::NetworkUnreachable
        | std::io::ErrorKind::AddrNotAvailable => None,
        _ => Some(protocol::ERROR_SERVER_ERROR),
    }
}

/// Wire invariants every response must satisfy before it is sent (design §2's
/// "encoding failure" path): a STUN header, and a `Message Length` that matches
/// the bytes about to be written.
///
/// The encoders cannot produce anything else — bodies are padded and the echoed
/// `PADDING` is clamped — so a violation means an internal bug. Answering `500`
/// (instead of writing a malformed frame) is what keeps the failure visible to
/// the client without leaking the bug.
fn response_is_encodable(response: &[u8]) -> bool {
    response.len() >= protocol::HEADER_LEN
        && usize::from(u16::from_be_bytes([response[2], response[3]])) + protocol::HEADER_LEN
            == response.len()
}

/// The `ERROR-CODE` value of a STUN error response, if it has one.
///
/// Used by the RFC 6062 data-connection path to tell "retry with credentials"
/// (`401` / `438`, which must not close the connection) from a final refusal.
fn response_error_code(response: &[u8]) -> Option<u16> {
    let message = protocol::parse(response).ok()?;
    let value = protocol::attributes(message.body)
        .find(|attribute| attribute.attr_type == protocol::ATTR_ERROR_CODE)?
        .value;
    if value.len() < 4 {
        return None;
    }
    Some(u16::from(value[2]) * 100 + u16::from(value[3]))
}

/// The fixed `500 Server Error` for `frame`, or `None` when the frame cannot be
/// parsed (no transaction id to answer to).
///
/// `code` is what `server_error_for` decided; only the fixed reason text is ever
/// used, so no `io::Error` detail ends up on the wire.
fn server_error_bytes(frame: &[u8], code: u16) -> Option<Vec<u8>> {
    let message = protocol::parse(frame).ok()?;
    Some(protocol::error_response(
        &message.transaction_id,
        protocol::message_method(message.msg_type),
        code,
        "Server Error",
    ))
}

/// Best-effort `500 Server Error` for an internal failure (design §2).
///
/// UDP-only by construction (it writes through the receiving socket); the TCP
/// path writes its 500 in-band in `serve_tcp_connection`.
///
/// The reason text is fixed and the `io::Error` only goes to the log, so the
/// response can neither leak internal detail nor grow: it is always 40 bytes
/// (20 header + 20 `ERROR-CODE`), which also means it cannot become an
/// amplifier. A failure to deliver it is logged at `debug` and otherwise
/// ignored — there is nothing left to answer on.
async fn send_server_error(
    socket: &UdpSocket,
    local: SocketAddr,
    peer: SocketAddr,
    datagram: &[u8],
    stats: &ServerStats,
    code: u16,
) {
    let Some(response) = server_error_bytes(datagram, code) else {
        return;
    };
    match socket.send_to(&response, peer).await {
        Ok(_) => stats.count_answered(Transport::Udp),
        Err(error) => {
            tracing::debug!(%local, %peer, %error, "rstun: 500 Server Error could not be sent")
        }
    }
}

/// Resolve one datagram into a response and send it.
///
/// Split from [`serve_udp`] so the serial and the `--max-inflight` (spawned)
/// shapes share one implementation — and so the permit the caller holds really
/// outlives the send.
async fn respond_to_datagram(
    socket: &UdpSocket,
    context: &ServerContext,
    software: &str,
    stats: &ServerStats,
    local: SocketAddr,
    peer: SocketAddr,
    datagram: &[u8],
) {
    // TURN 先于 STUN：`--turn` 关闭时 `handle` 不会被调用（`None`），字节与
    // 26.410.100 一致。开启后 ChannelData / TURN method 在此分流，Binding 仍走原路。
    let turn_decision = match stats.turn() {
        Some(turn) => {
            turn.handle(
                datagram,
                peer,
                local,
                turn::ClientTransport::Udp,
                context,
                None,
            )
            .await
        }
        None => None,
    };
    let decision = match turn_decision {
        Some(decision) => decision,
        None => decide_guarded(
            datagram,
            peer,
            local,
            Transport::Udp,
            context,
            software,
            stats,
        ),
    };
    match decision {
        Ok(Decision::Respond(response)) => {
            if !response_is_encodable(&response) {
                stats.count_dropped(Transport::Udp);
                tracing::error!(%local, %peer, "rstun: response violates STUN wire invariants");
                send_server_error(
                    socket,
                    local,
                    peer,
                    datagram,
                    stats,
                    protocol::ERROR_SERVER_ERROR,
                )
                .await;
                return;
            }
            match socket.send_to(&response, peer).await {
                Ok(_) => stats.count_answered(Transport::Udp),
                Err(error) => {
                    tracing::warn!(%local, %peer, %error, "rstun: UDP send_to failed");
                    if let Some(code) = server_error_for(&error) {
                        send_server_error(socket, local, peer, datagram, stats, code).await;
                    }
                }
            }
        }
        Ok(Decision::RespondFrom { from, to, bytes }) => {
            if !response_is_encodable(&bytes) {
                stats.count_dropped(Transport::Udp);
                tracing::error!(%local, %peer, %from, "rstun: response violates STUN wire invariants");
                send_server_error(
                    socket,
                    local,
                    peer,
                    datagram,
                    stats,
                    protocol::ERROR_SERVER_ERROR,
                )
                .await;
                return;
            }
            // `from` is the *source* address (CHANGE-REQUEST picks another
            // socket we hold); `to` is the *destination* (RESPONSE-PORT moves
            // only the port — the IP stays the one the request came from).
            let target = context.socket_for(from);
            let Some(target) = target else {
                // Internal invariant violation: the plan only ever names sockets
                // this process bound, so this is a bug, not a client error.
                // Answer 500 (best effort) rather than leave the client waiting.
                stats.count_dropped(Transport::Udp);
                tracing::error!(
                    %local,
                    %peer,
                    %from,
                    "rstun: no socket bound for the requested response address"
                );
                send_server_error(
                    socket,
                    local,
                    peer,
                    datagram,
                    stats,
                    protocol::ERROR_SERVER_ERROR,
                )
                .await;
                return;
            };
            match target.send_to(&bytes, to).await {
                Ok(_) => stats.count_answered(Transport::Udp),
                Err(error) => {
                    tracing::warn!(
                        %local,
                        %from,
                        %to,
                        %error,
                        "rstun: UDP send_to failed (RFC 5780)"
                    );
                    if let Some(code) = server_error_for(&error) {
                        send_server_error(socket, local, peer, datagram, stats, code).await;
                    }
                }
            }
        }
        Ok(Decision::Ignore(reason)) => {
            stats.count_ignored(Transport::Udp);
            tracing::debug!(%local, %peer, reason, "rstun: ignored message")
        }
        // A data connection only exists on a TCP/TLS TURN connection; a
        // datagram never reaches `ConnectionBind`.
        Ok(Decision::Bind { .. }) => {
            stats.count_error(Transport::Udp);
            tracing::error!(%local, %peer, "rstun: ConnectionBind on a datagram transport");
        }
        Err(error) => {
            stats.count_error(Transport::Udp);
            tracing::debug!(%local, %peer, %error, "rstun: dropped malformed datagram")
        }
    }
}

/// Accept STUN-over-TCP connections until draining starts (or the task is
/// aborted by the shutdown timeout).
async fn serve_tcp(
    listener: TcpListener,
    context: Arc<ServerContext>,
    software: Arc<str>,
    stats: Arc<ServerStats>,
) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    tracing::info!(%local, "rstun: TCP listener ready");
    let mut drain = stats.subscribe_drain();
    if stats.is_draining() {
        return Ok(());
    }
    loop {
        let accepted = tokio::select! {
            biased;
            // SIGTERM: stop accepting; established connections keep draining.
            _ = drain.changed() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                stats.count_socket_error(Transport::Tcp);
                tracing::warn!(%local, %error, "rstun: TCP accept failed");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        // 抗滥用（连接级）：在途上限按**连接**计数 —— 空闲连接也占 fd 与一个任务，
        // 只按请求计数挡不住「握手后不说话」的洪水。请求级限速见下方。
        let permit = match context.acquire_inflight() {
            None => None,
            Some(Ok(permit)) => Some(permit),
            Some(Err(refusal)) => {
                stats.count_dropped(Transport::Tcp);
                tracing::debug!(
                    %local,
                    %peer,
                    reason = refusal.reason(),
                    counter = refusal.counter(),
                    "rstun: TCP connection refused by abuse guard"
                );
                drop(stream);
                continue;
            }
        };
        let software = software.clone();
        let stats = stats.clone();
        let context = context.clone();
        // A connection counts as in-flight work: it holds an fd and may be
        // mid-answer when SIGTERM arrives. Counted before the spawn so the
        // shutdown path cannot miss it.
        let in_flight = stats.enter();
        tokio::spawn(async move {
            if let Err(error) =
                serve_tcp_connection(stream, peer, context, &software, &stats, permit).await
            {
                tracing::debug!(%local, %peer, %error, "rstun: TCP connection closed")
            }
            drop(in_flight);
        });
    }
    tracing::info!(%local, "rstun: TCP listener stopped (draining)");
    Ok(())
}

/// One TCP connection; RFC 5389 §7.2.2 frames messages by the header length.
async fn serve_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    context: Arc<ServerContext>,
    software: &str,
    stats: &ServerStats,
    // Held for the whole connection: releasing it is what frees the slot.
    _inflight: Option<limit::Permit>,
) -> std::io::Result<()> {
    // TURN over TCP is a distinct framing (ChannelData first byte), so it gets
    // its own loop. Without `--turn` this is the unchanged pre-TURN path.
    if let Some(turn) = stats.turn().cloned() {
        return serve_tcp_turn(stream, peer, context, turn, software, stats, _inflight).await;
    }
    let local = stream.local_addr()?;
    let mut drain = stats.subscribe_drain();
    if stats.is_draining() {
        return Ok(());
    }
    loop {
        let mut header = [0_u8; protocol::HEADER_LEN];
        // Draining stops *reading new frames*; the frame in hand is finished
        // below. `read_exact_with_timeout` is cancel-safe enough here: we are
        // closing the connection, so a half-read frame is discarded.
        let header_read = tokio::select! {
            biased;
            _ = drain.changed() => return Ok(()),
            read = read_exact_with_timeout(&mut stream, &mut header) => read,
        };
        if !header_read? {
            // 对端正常关闭。
            return Ok(());
        }
        let frame_len = match protocol::peek_frame_len(&header) {
            Ok(frame_len) => frame_len,
            Err(error) => {
                // Header gives us no frame boundary any more: the stream is unusable.
                stats.count_error(Transport::Tcp);
                tracing::debug!(%peer, %error, "rstun: malformed TCP STUN header");
                return Ok(());
            }
        };
        stats.count_received(Transport::Tcp);

        let mut frame = vec![0_u8; frame_len];
        frame[..protocol::HEADER_LEN].copy_from_slice(&header);
        if !read_exact_with_timeout(&mut stream, &mut frame[protocol::HEADER_LEN..]).await? {
            stats.count_error(Transport::Tcp);
            tracing::debug!(%peer, "rstun: truncated TCP STUN message");
            return Ok(());
        }

        // 抗滥用准入（请求级）：TCP 没有「丢一个 datagram」这回事，超限就直接关连接
        // —— 与「不放大 / 不回 486」的设计一致（design §3）。在途槽位由连接持有，
        // 这里只查名单与速率桶。
        if let Some(Err(refusal)) = context.check_rates(peer) {
            stats.count_dropped(Transport::Tcp);
            tracing::debug!(
                %peer,
                reason = refusal.reason(),
                counter = refusal.counter(),
                "rstun: TCP request refused by abuse guard, closing connection"
            );
            return Ok(());
        }

        // One frame in hand is the unit of work the drain waits for.
        let in_flight = stats.enter();
        match decide_guarded(
            &frame,
            peer,
            local,
            Transport::Tcp,
            &context,
            software,
            stats,
        ) {
            Ok(Decision::Respond(response)) => {
                if !response_is_encodable(&response) {
                    // Same internal-invariant path as UDP: answer 500 in-band
                    // instead of writing a malformed frame.
                    stats.count_error(Transport::Tcp);
                    tracing::error!(%peer, "rstun: response violates STUN wire invariants");
                    if let Some(error) = server_error_bytes(&frame, protocol::ERROR_SERVER_ERROR) {
                        stream.write_all(&error).await?;
                        stats.count_answered(Transport::Tcp);
                    }
                    drop(in_flight);
                    continue;
                }
                stream.write_all(&response).await?;
                stats.count_answered(Transport::Tcp);
            }
            Ok(Decision::RespondFrom { from, to, bytes }) => {
                // Cannot happen: `decide` never asks for another socket or
                // destination over TCP (CHANGE-REQUEST and RESPONSE-PORT are
                // UDP-only). Answer in-band rather than drop, so a future
                // regression shows up as a normal response, not dead air.
                tracing::warn!(
                    %peer,
                    %from,
                    %to,
                    "rstun: CHANGE-REQUEST / RESPONSE-PORT are UDP-only, answering on the same connection"
                );
                if !response_is_encodable(&bytes) {
                    stats.count_error(Transport::Tcp);
                    tracing::error!(%peer, "rstun: response violates STUN wire invariants");
                    if let Some(error) = server_error_bytes(&frame, protocol::ERROR_SERVER_ERROR) {
                        stream.write_all(&error).await?;
                        stats.count_answered(Transport::Tcp);
                    }
                    drop(in_flight);
                    continue;
                }
                stream.write_all(&bytes).await?;
                stats.count_answered(Transport::Tcp);
            }
            Ok(Decision::Ignore(reason)) => {
                stats.count_ignored(Transport::Tcp);
                tracing::debug!(%peer, reason, "rstun: ignored message")
            }
            // Not reachable without `--turn` (this is the pre-TURN loop).
            Ok(Decision::Bind { .. }) => {
                stats.count_error(Transport::Tcp);
                tracing::error!(%peer, "rstun: ConnectionBind without TURN");
            }
            Err(error) => {
                stats.count_error(Transport::Tcp);
                tracing::debug!(%peer, %error, "rstun: malformed TCP STUN message");
                return Ok(());
            }
        }
        drop(in_flight);
    }
}

/// Read exactly `buffer.len()` bytes; `false` means the peer closed cleanly.
async fn read_exact_with_timeout<R>(stream: &mut R, buffer: &mut [u8]) -> std::io::Result<bool>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    match tokio::time::timeout(TCP_READ_TIMEOUT, stream.read_exact(buffer)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Ok(Err(error)) => Err(error),
        Err(elapsed) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("STUN frame read timed out after {elapsed}"),
        )),
    }
}

/// One TURN-capable TCP connection: STUN frames and `ChannelData` share the
/// stream, distinguished by the first byte (RFC 8656 §12.5).
///
/// Only reached with `--turn`; the connection's writer lives in one task so a
/// relay reader can push `Data`/`ChannelData` without borrowing the request
/// loop. Closing the connection releases its allocations immediately instead of
/// leaving relay sockets bound until the TTL.
async fn serve_tcp_turn(
    stream: TcpStream,
    peer: SocketAddr,
    context: Arc<ServerContext>,
    turn: Arc<turn::Turn>,
    software: &str,
    stats: &ServerStats,
    _inflight: Option<limit::Permit>,
) -> std::io::Result<()> {
    let local = stream.local_addr()?;
    serve_turn_stream(
        stream,
        peer,
        local,
        turn::ClientTransport::Tcp,
        context,
        turn,
        software,
        stats,
        _inflight,
    )
    .await
}

/// How a TURN-over-stream loop ended.
enum StreamOutcome {
    /// Control connection finished (EOF, drain, malformed frame, error): the
    /// caller releases the allocation and aborts the writer.
    ControlClosed,
    /// `ConnectionBind` succeeded: answer first, then hand the stream over as
    /// the client data connection `id` (RFC 6062 §5.4).
    Bound { response: Vec<u8>, id: u32 },
    /// A `ConnectionBind` was refused: flush the error response, then close
    /// (coturn closes so hard the client only sees a RST; answering the `400`
    /// is strictly better and is an explicit, documented difference).
    RejectAfterResponse,
}

/// One TURN-capable connection over **any byte stream**: plain TCP or TLS
/// (`turns:`, design §3.2/§4). The framing is identical, so the only thing the
/// caller chooses is the 5-tuple's client transport.
#[allow(clippy::too_many_arguments)]
async fn serve_turn_stream<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    transport: turn::ClientTransport,
    context: Arc<ServerContext>,
    turn: Arc<turn::Turn>,
    software: &str,
    stats: &ServerStats,
    inflight: Option<limit::Permit>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let mut drain = stats.subscribe_drain();
    if stats.is_draining() {
        return Ok(());
    }
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Bounded on purpose (see `turn::TCP_SINK_CAPACITY`): an authenticated
    // client that stops reading must not grow an unbounded server-side queue.
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(turn::TCP_SINK_CAPACITY);
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = receiver.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    let outcome = match stream_turn_loop(
        &mut reader,
        peer,
        local,
        transport,
        &context,
        &turn,
        software,
        stats,
        &sender,
        &mut drain,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            // Same cleanup as a closed control connection: without the writer
            // task the allocation could only leak its relay socket until TTL.
            turn.release_connection(peer, local, transport);
            drop(sender);
            writer_task.abort();
            return Err(error);
        }
    };
    match outcome {
        StreamOutcome::ControlClosed => {
            turn.release_connection(peer, local, transport);
            drop(sender);
            writer_task.abort();
            Ok(())
        }
        StreamOutcome::RejectAfterResponse => {
            // Flush the queued 400 before closing: dropping the last sender
            // ends the writer task after it has written everything.
            turn.release_connection(peer, local, transport);
            drop(sender);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), writer_task).await;
            Ok(())
        }
        StreamOutcome::Bound { response, id } => {
            // The bind response is queued first, so it precedes any buffered
            // peer bytes in the same FIFO writer queue.
            if sender.try_send(response).is_err() {
                // The queue is unusable (it cannot be full on a fresh data
                // connection). Drop the pending hand-over so the peer task
                // tears both halves down instead of staying "bound" with a
                // client half nobody will ever write to.
                drop(turn.take_bind(id));
                return Ok(());
            }
            stats.count_answered(Transport::Tcp);
            let data = turn::DataConnection {
                reader: Box::new(reader),
                sender,
                writer_task,
                // A data connection is an accepted TCP connection: it keeps
                // holding its `--max-inflight` slot for its whole life.
                _permit: inflight,
            };
            match turn.take_bind(id) {
                Some(bind) => {
                    // If the peer task is already gone the send fails and both
                    // halves are dropped, which closes the connection.
                    let _ = bind.send(data);
                }
                None => {
                    tracing::debug!(id, "rstun: TURN data connection vanished before bind");
                }
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn stream_turn_loop<R>(
    reader: &mut R,
    peer: SocketAddr,
    local: SocketAddr,
    transport: turn::ClientTransport,
    context: &ServerContext,
    turn: &turn::Turn,
    software: &str,
    stats: &ServerStats,
    sender: &tokio::sync::mpsc::Sender<Vec<u8>>,
    drain: &mut tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<StreamOutcome>
where
    R: tokio::io::AsyncRead + Unpin + ?Sized,
{
    loop {
        let mut prefix = [0_u8; 4];
        let read = tokio::select! {
            biased;
            _ = drain.changed() => return Ok(StreamOutcome::ControlClosed),
            read = read_exact_with_timeout(reader, &mut prefix) => read,
        };
        if !read? {
            return Ok(StreamOutcome::ControlClosed);
        }
        stats.count_received(Transport::Tcp);

        // ChannelData: 4-byte header + payload + 4-byte padding (§12.5).
        if turn::is_channel_data_prefix(prefix[0]) {
            let channel = u16::from_be_bytes([prefix[0], prefix[1]]);
            let length = usize::from(u16::from_be_bytes([prefix[2], prefix[3]]));
            let mut data = vec![0_u8; length];
            if !read_exact_with_timeout(reader, &mut data).await? {
                stats.count_error(Transport::Tcp);
                return Ok(StreamOutcome::ControlClosed);
            }
            let padding = (4 - length % 4) % 4;
            if padding > 0 {
                let mut skip = [0_u8; 3];
                if !read_exact_with_timeout(reader, &mut skip[..padding]).await? {
                    stats.count_error(Transport::Tcp);
                    return Ok(StreamOutcome::ControlClosed);
                }
            }
            turn.handle_channel_data(channel, &data, peer, local, transport, context);
            stats.count_ignored(Transport::Tcp);
            continue;
        }

        let mut header = [0_u8; protocol::HEADER_LEN];
        header[..4].copy_from_slice(&prefix);
        if !read_exact_with_timeout(reader, &mut header[4..]).await? {
            stats.count_error(Transport::Tcp);
            return Ok(StreamOutcome::ControlClosed);
        }
        let frame_len = match protocol::peek_frame_len(&header) {
            Ok(frame_len) => frame_len,
            Err(error) => {
                stats.count_error(Transport::Tcp);
                tracing::debug!(%peer, %error, "rstun: malformed TCP STUN header");
                return Ok(StreamOutcome::ControlClosed);
            }
        };
        let mut frame = vec![0_u8; frame_len];
        frame[..protocol::HEADER_LEN].copy_from_slice(&header);
        if !read_exact_with_timeout(reader, &mut frame[protocol::HEADER_LEN..]).await? {
            stats.count_error(Transport::Tcp);
            tracing::debug!(%peer, "rstun: truncated TCP STUN message");
            return Ok(StreamOutcome::ControlClosed);
        }
        if let Some(Err(refusal)) = context.check_rates(peer) {
            stats.count_dropped(Transport::Tcp);
            tracing::debug!(
                %peer,
                reason = refusal.reason(),
                counter = refusal.counter(),
                "rstun: TCP request refused by abuse guard, closing connection"
            );
            return Ok(StreamOutcome::ControlClosed);
        }
        // Only with `--turn-tcp-relay` is a refused `ConnectionBind` a reason to
        // close; with the switch off the frame keeps the old "400, stay open"
        // behaviour of a server that does not implement the method.
        let connection_bind = turn.config().tcp_relay
            && protocol::parse(&frame).is_ok_and(|message| {
                protocol::message_method(message.msg_type) == turn::CONNECTION_BIND_METHOD
            });

        let in_flight = stats.enter();
        let decision = match turn
            .handle(&frame, peer, local, transport, context, Some(sender))
            .await
        {
            Some(decision) => decision,
            None => decide_guarded(
                &frame,
                peer,
                local,
                Transport::Tcp,
                context,
                software,
                stats,
            ),
        };
        match decision {
            Ok(Decision::Bind { response, id }) => {
                if !response_is_encodable(&response) {
                    stats.count_error(Transport::Tcp);
                    tracing::error!(%peer, "rstun: response violates STUN wire invariants");
                    return Ok(StreamOutcome::ControlClosed);
                }
                return Ok(StreamOutcome::Bound { response, id });
            }
            Ok(Decision::Respond(response)) => {
                // Keep the ordinary long-term challenge dance alive: an
                // unsigned first attempt gets 401/438 and is retried with
                // credentials. Any other refusal ends the connection (coturn
                // closes it too, just without letting the client read the 400).
                let retryable =
                    connection_bind && matches!(response_error_code(&response), Some(401 | 438));
                if !response_is_encodable(&response) {
                    stats.count_error(Transport::Tcp);
                    tracing::error!(%peer, "rstun: response violates STUN wire invariants");
                    if let Some(error) = server_error_bytes(&frame, protocol::ERROR_SERVER_ERROR) {
                        let _ = sender.try_send(error);
                        stats.count_answered(Transport::Tcp);
                    }
                } else if sender.try_send(response).is_err() {
                    // Queue full or writer gone: the connection is backed up
                    // beyond recovery, close it instead of buffering forever.
                    return Ok(StreamOutcome::ControlClosed);
                } else {
                    stats.count_answered(Transport::Tcp);
                }
                if connection_bind && !retryable {
                    return Ok(StreamOutcome::RejectAfterResponse);
                }
            }
            Ok(Decision::RespondFrom { bytes, .. }) => {
                // Not produced for TURN; the STUN path cannot reach here over
                // TCP either (CHANGE-REQUEST/RESPONSE-PORT are UDP-only).
                if sender.try_send(bytes).is_err() {
                    return Ok(StreamOutcome::ControlClosed);
                }
                stats.count_answered(Transport::Tcp);
            }
            Ok(Decision::Ignore(reason)) => {
                stats.count_ignored(Transport::Tcp);
                tracing::debug!(%peer, reason, "rstun: ignored message");
            }
            Err(error) => {
                stats.count_error(Transport::Tcp);
                tracing::debug!(%peer, %error, "rstun: malformed TCP STUN message");
                return Ok(StreamOutcome::ControlClosed);
            }
        }
        drop(in_flight);
    }
}

// ---------------------------------------------------------------------------
// TURN over TLS / DTLS (T2; behind the `tls` / `dtls` features)
// ---------------------------------------------------------------------------
//
// `default = []`: the lean build has none of the code below, none of the four
// crates and none of their transitive dependencies. `--features full` (or
// `tls` / `dtls`) compiles it in; the flags themselves are defined either way
// so `--help` never changes with the build.

/// One TLS/DTLS handshake budget. Without a bound a silent peer could hold a
/// connection slot (and, for DTLS, a session in the listener's table) forever.
/// TLS: rustls has no handshake deadline of its own; DTLS: `DTLSConn::new` is
/// wrapped in this timeout inside a per-client task, so a stuck handshake can
/// never block `accept()`.
#[cfg(feature = "tls")]
const SECURE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// One complete set of server-side TLS + DTLS material.
///
/// Replaced **whole** on a reload (design §2 / D2): a single `Arc` swap means a
/// new `turns:` connection and a new DTLS session can never observe a mix of two
/// certificate generations. Established sessions keep the copy they handshook
/// with — neither TLS 1.3/1.2 nor `webrtc-dtls` renegotiates certificates.
///
/// `dtls` is `Some` only when the `dtls` feature is on **and** a
/// `--turn-dtls-listen` address was given. The DTLS side has stricter rules
/// (PKCS#8, ECDSA P-256/Ed25519) than TLS, so validating it unconditionally
/// would refuse a perfectly good `turns:`-only deployment that happens to use an
/// RSA certificate — which is the normal Let's Encrypt shape.
#[cfg(feature = "tls")]
struct SharedMaterial {
    tls: Arc<tokio_rustls::rustls::ServerConfig>,
    #[cfg(feature = "dtls")]
    dtls: Option<webrtc_dtls::config::Config>,
}

/// The live material every secure listener reads from.
///
/// Read-locked once per accepted connection for a cheap `Arc` clone; written
/// once per successful reload. The write never holds the lock across file I/O:
/// the new material is parsed and validated first, then swapped in.
#[cfg(feature = "tls")]
type MaterialSlot = Arc<std::sync::RwLock<Arc<SharedMaterial>>>;

/// What a successful [`load_secure_material`] produced.
#[cfg(feature = "tls")]
struct LoadedMaterial {
    material: Arc<SharedMaterial>,
    /// The leaf certificate's `notAfter` (present unless X.509 parsing, which
    /// the same DER already survived through rustls, somehow fails).
    not_after: Option<i64>,
}

/// Everything a running secure deployment needs to reload its own material:
/// the live slot, the (unchangeable) source paths, whether DTLS material is
/// required, how often to poll for a rewrite (`None` = `--tls-cert-poll 0`,
/// SIGHUP only), and where to count.
#[cfg(feature = "tls")]
#[derive(Clone)]
struct SecureSetup {
    slot: MaterialSlot,
    cert: PathBuf,
    key: PathBuf,
    needs_dtls: bool,
    poll: Option<Duration>,
    stats: Arc<SecureStats>,
}

/// One cheap, poison-tolerant read of the live material.
#[cfg(feature = "tls")]
fn current_material(slot: &MaterialSlot) -> Arc<SharedMaterial> {
    let guard = slot.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

/// Load `--tls-cert` / `--tls-key` into the stacks this start actually serves.
///
/// `needs_dtls` must be `true` only when a `--turn-dtls-listen` address was
/// given: the DTLS side has two extra constraints that `webrtc-dtls` enforces
/// (the private key must be unencrypted **PKCS#8**, and its algorithm must be
/// ECDSA P-256 or Ed25519), and applying them to a TLS-only start would reject
/// every RSA certificate for nothing.
#[cfg(feature = "tls")]
fn load_secure_material(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    needs_dtls: bool,
) -> Result<LoadedMaterial, String> {
    // A `tls`-only build has no DTLS path at all; `build_turn` already refused
    // `--turn-dtls-listen` there, so the flag is simply not consulted.
    #[cfg(not(feature = "dtls"))]
    let _ = needs_dtls;

    let cert_pem = std::fs::read(cert_path)
        .map_err(|error| format!("cannot read --tls-cert {}: {error}", cert_path.display()))?;
    let certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<_, _>>()
            .map_err(|error| {
                format!(
                    "--tls-cert {} is not valid PEM: {error}",
                    cert_path.display()
                )
            })?;
    if certs.is_empty() {
        return Err(format!(
            "--tls-cert {} contains no CERTIFICATE block",
            cert_path.display()
        ));
    }

    let key_pem = std::fs::read(key_path)
        .map_err(|error| format!("cannot read --tls-key {}: {error}", key_path.display()))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|error| format!("--tls-key {} is not valid PEM: {error}", key_path.display()))?
        .ok_or_else(|| {
            format!(
                "--tls-key {} contains no private key block",
                key_path.display()
            )
        })?;

    let tls_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key.clone_key())
        .map_err(|error| {
            format!(
                "--tls-cert {} / --tls-key {} do not form a usable pair: {error}",
                cert_path.display(),
                key_path.display()
            )
        })?;

    // DTLS needs the private key as PKCS#8 DER and only signs with ECDSA P-256
    // or Ed25519. Both are `webrtc-dtls` limits, so they are checked here —
    // at startup, where the operator can fix them (design §9). Skipped entirely
    // when no DTLS listener was requested: TLS itself accepts RSA.
    #[cfg(feature = "dtls")]
    let dtls = if !needs_dtls {
        None
    } else {
        use tokio_rustls::rustls::pki_types::PrivateKeyDer;

        let pkcs8 = match &key {
            PrivateKeyDer::Pkcs8(pkcs8) => pkcs8.secret_pkcs8_der().to_vec(),
            _ => {
                return Err(format!(
                    "--tls-key {} must be an unencrypted PKCS#8 private key \
                     (openssl genpkey -algorithm EC ...): the DTLS stack cannot read \
                     PKCS#1/SEC1 keys",
                    key_path.display()
                ));
            }
        };
        let certificate = webrtc_dtls::crypto::Certificate::from_pem(&dtls_pem(&pkcs8, &certs))
            .map_err(|error| {
                format!(
                    "--tls-cert {} / --tls-key {} are not usable for DTLS: {error} \
                     (DTLS needs an ECDSA P-256 or Ed25519 key)",
                    cert_path.display(),
                    key_path.display()
                )
            })?;
        // `webrtc-dtls` validates the key algorithm when a *client* arrives, not
        // when the listener is built: an RSA key would look like "DTLS never
        // connects". Refuse the start instead (design §9: no silent degradation).
        match certificate.private_key.kind {
            webrtc_dtls::crypto::CryptoPrivateKeyKind::Ecdsa256(_)
            | webrtc_dtls::crypto::CryptoPrivateKeyKind::Ed25519(_) => {}
            _ => {
                return Err(format!(
                    "--tls-key {} cannot be used for DTLS: webrtc-dtls signs with ECDSA P-256 \
                     or Ed25519 only (TLS itself accepts this key, DTLS does not)",
                    key_path.display()
                ));
            }
        }
        Some(webrtc_dtls::config::Config {
            certificates: vec![certificate],
            ..Default::default()
        })
    };

    // The leaf's validity, for `rstun_turn_tls_cert_expires_seconds`. rustls
    // does not expose it, and re-parsing here is the only way to keep the
    // gauge without a second validation path: this is read-only, the DER has
    // already passed `with_single_cert` above.
    let not_after = certificate_not_after(certs[0].as_ref());

    Ok(LoadedMaterial {
        material: Arc::new(SharedMaterial {
            tls: Arc::new(tls_config),
            #[cfg(feature = "dtls")]
            dtls,
        }),
        not_after,
    })
}

/// The leaf certificate's `notAfter` as Unix seconds.
///
/// Only the validity is read: no chain building, no signature check — the same
/// DER was just accepted by `with_single_cert`, so this can only fail on a
/// parser/rustls disagreement (reported as `None` → gauge `-1`).
#[cfg(feature = "tls")]
fn certificate_not_after(der: &[u8]) -> Option<i64> {
    use x509_parser::prelude::FromDer as _;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    Some(certificate.validity().not_after.timestamp())
}

/// Default interval of the certificate-file poll (design §5).
///
/// SIGHUP is the immediate path; polling is what makes rotation work on
/// Windows (no `SIGHUP`) and in deployments that would rather not signal.
/// `--tls-cert-poll 0` turns the timer off; a positive value replaces this.
const CERT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The interval `--tls-cert-poll` asks for, validated against what this start
/// actually serves.
///
/// `Ok(None)` means "no polling task at all: SIGHUP only" — a deployment that
/// rotates by signalling writes cert and key one file at a time, and a poll
/// landing in that window would log a rotation failure nobody asked for.
///
/// `has_sighup` is a parameter rather than a `cfg!(unix)` read inside, so the
/// Windows rule is testable on every platform: polling is the **only** trigger
/// there, so disabling it would freeze the certificate until the next restart.
fn cert_poll_interval(
    requested: Option<u64>,
    has_secure_listener: bool,
    has_sighup: bool,
) -> Result<Option<Duration>, String> {
    let Some(seconds) = requested else {
        return Ok(Some(CERT_POLL_INTERVAL));
    };
    if !has_secure_listener {
        return Err(
            "--tls-cert-poll needs --turn-tls-listen or --turn-dtls-listen: \
             without a secure listener there is nothing to rotate"
                .to_string(),
        );
    }
    if seconds == 0 {
        if !has_sighup {
            return Err(
                "--tls-cert-poll 0 is not allowed on this platform: there is no SIGHUP, \
                 so the certificate could never rotate (use a positive interval, \
                 e.g. --tls-cert-poll 30)"
                    .to_string(),
            );
        }
        return Ok(None);
    }
    Ok(Some(Duration::from_secs(seconds)))
}

/// One retry after this delay, to step over the "cert already written, key
/// still being written" window (design §5 / D3).
#[cfg(feature = "tls")]
const CERT_RELOAD_RETRY: Duration = Duration::from_secs(1);

/// `(mtime, len)` for one file. `mtime` can be unavailable on exotic
/// filesystems; the length alone still detects most rewrites, and the parse
/// result is the real gate either way.
#[cfg(feature = "tls")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
}

#[cfg(feature = "tls")]
fn file_stamp(path: &std::path::Path) -> Option<FileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileStamp {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

/// Both paths' stamps, or `None` while a `rename` has one of them missing.
#[cfg(feature = "tls")]
fn material_stamp(setup: &SecureSetup) -> Option<(FileStamp, FileStamp)> {
    Some((file_stamp(&setup.cert)?, file_stamp(&setup.key)?))
}

/// Parse + validate the material at the configured paths and swap it in.
///
/// The validation is literally [`load_secure_material`] — the startup rules
/// (pairing, PKCS#8, DTLS algorithms) are the reload rules, so a rotation
/// cannot be accepted here and refused on the next restart.
///
/// Any failure keeps the previous material in service (D3): a rotation that
/// lands in a half-written window must not take down every established
/// session. Returns whether the live material changed.
#[cfg(feature = "tls")]
async fn reload_secure_material(setup: &SecureSetup) -> bool {
    match load_secure_material(&setup.cert, &setup.key, setup.needs_dtls) {
        Ok(loaded) => {
            swap_material(setup, loaded);
            true
        }
        Err(first_error) => {
            // The usual cause is an in-progress rotation: cert and key are two
            // files, so one of them is momentarily new and the other old.
            tokio::time::sleep(CERT_RELOAD_RETRY).await;
            match load_secure_material(&setup.cert, &setup.key, setup.needs_dtls) {
                Ok(loaded) => {
                    swap_material(setup, loaded);
                    true
                }
                Err(second_error) => {
                    setup.stats.count_reload_failure();
                    // Both messages are our own `format!` strings (paths and
                    // parser text only) — never the private key.
                    tracing::warn!(
                        cert = %setup.cert.display(),
                        key = %setup.key.display(),
                        error = %second_error,
                        first_error = %first_error,
                        "rstun: TURN TLS certificate reload rejected, keeping the previous material"
                    );
                    false
                }
            }
        }
    }
}

/// One complete swap: the slot write is the only mutation, and it happens
/// after all parsing/validation succeeded.
#[cfg(feature = "tls")]
fn swap_material(setup: &SecureSetup, loaded: LoadedMaterial) {
    {
        let mut slot = setup
            .slot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = loaded.material;
    }
    setup.stats.count_reload_ok();
    setup.stats.set_not_after(loaded.not_after);

    // Once-only warning if the (already rustls-validated) DER somehow does not
    // parse for the validity meter: the gauge then reports `-1`.
    if loaded.not_after.is_none() {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            tracing::warn!(
                cert = %setup.cert.display(),
                "rstun: cannot read the certificate validity; \
                 rstun_turn_tls_cert_expires_seconds will report -1"
            );
        });
    }
    let cert_modified = file_stamp(&setup.cert)
        .and_then(|stamp| stamp.modified)
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs());
    let days_left = loaded
        .not_after
        .map(|not_after| (not_after - unix_seconds_now()) as f64 / SECONDS_PER_DAY as f64);
    tracing::info!(
        cert = %setup.cert.display(),
        key = %setup.key.display(),
        cert_mtime_unix = cert_modified,
        not_after_unix = loaded.not_after,
        days_left,
        "rstun: TURN TLS certificate reloaded"
    );
}

#[cfg(feature = "tls")]
const SECONDS_PER_DAY: u64 = 86_400;

/// Reload on `SIGHUP` (Unix) and, when `--tls-cert-poll` is not `0`, whenever
/// either file's `(mtime, len)` changes on that interval. Both paths share
/// [`reload_secure_material`], so they cannot diverge.
#[cfg(feature = "tls")]
fn spawn_cert_reloader(setup: SecureSetup, stats: Arc<ServerStats>) -> tokio::task::JoinHandle<()> {
    // Register SIGHUP **before** spawning: between `spawn` and the task's first
    // poll the signal would still have its default disposition (terminate the
    // process), leaving a window where `kill -HUP` kills the server.
    #[cfg(unix)]
    let hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(signal) => Some(signal),
        Err(error) => {
            if setup.poll.is_some() {
                tracing::warn!(
                    %error,
                    "rstun: cannot listen for SIGHUP; certificate reload falls back to polling"
                );
            } else {
                // Neither trigger left: `--tls-cert-poll 0` already removed the
                // timer, so pointing at "polling" here would be a lie.
                tracing::error!(
                    %error,
                    "rstun: cannot listen for SIGHUP and --tls-cert-poll 0 disabled polling: \
                     the certificate will no longer be rotated (restart with a positive \
                     --tls-cert-poll once the signal handler works)"
                );
            }
            None
        }
    };
    // `None` = `--tls-cert-poll 0`: the deployment rotates by signalling, so the
    // timer stays out of the way (a poll landing between the cert write and the
    // key write would log a failure nobody asked for).
    let interval = setup.poll;
    tokio::spawn(async move {
        // One line that makes the effective trigger set observable from outside
        // (and assertable by the lab): `poll=None` really means "SIGHUP only",
        // anything else is the interval that will re-stat the two files.
        tracing::info!(poll = ?interval, "rstun: certificate reloader started");
        let mut drain = stats.subscribe_drain();
        #[cfg(unix)]
        let mut hangup = hangup;
        let mut poll = interval.map(|interval| {
            let mut poll = tokio::time::interval(interval);
            poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            poll
        });
        // `interval` fires once immediately; that would be a redundant parse of
        // material that was loaded seconds ago at startup.
        if let Some(poll) = poll.as_mut() {
            poll.tick().await;
        }
        let mut last_attempt = material_stamp(&setup);
        loop {
            // `true` = an operator asked explicitly (SIGHUP), `false` = poll.
            #[cfg(unix)]
            let signalled = tokio::select! {
                biased;
                _ = drain.changed() => break,
                _ = cert_hangup(&mut hangup) => true,
                _ = cert_poll_tick(&mut poll) => false,
            };
            #[cfg(not(unix))]
            let signalled = tokio::select! {
                biased;
                _ = drain.changed() => break,
                _ = cert_poll_tick(&mut poll) => false,
            };

            let stamp = material_stamp(&setup);
            if !signalled {
                // Poll: nothing changed means nothing to parse (and no log).
                // `None` means a file is momentarily missing (a `rename` in
                // progress) — try again on the next tick.
                match (stamp, last_attempt) {
                    (Some(current), Some(previous)) if current == previous => continue,
                    (None, _) => continue,
                    _ => {}
                }
            }
            last_attempt = stamp;
            let _ = reload_secure_material(&setup).await;
        }
        tracing::debug!("rstun: TURN TLS certificate reloader stopped (draining)");
    })
}

/// The poll arm of the reloader's `select!`.
///
/// With `--tls-cert-poll 0` the interval is `None` and this never resolves:
/// that is how the SIGHUP path keeps working with no timer at all.
#[cfg(feature = "tls")]
async fn cert_poll_tick(poll: &mut Option<tokio::time::Interval>) {
    match poll {
        Some(poll) => {
            poll.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// The `SIGHUP` arm of the reloader's `select!` (Unix only).
#[cfg(all(feature = "tls", unix))]
async fn cert_hangup(hangup: &mut Option<tokio::signal::unix::Signal>) {
    match hangup {
        Some(signal) => {
            // `None` means the signal stream ended (never in practice). Park
            // instead of spinning the select.
            if signal.recv().await.is_none() {
                std::future::pending::<()>().await;
            }
        }
        None => std::future::pending::<()>().await,
    }
}

/// `webrtc-dtls` reads a PEM bundle whose **first** block is tagged
/// `PRIVATE_KEY`, followed by `CERTIFICATE` blocks. Standard PEM tools write
/// `PRIVATE KEY`, so the DER we already parsed is re-wrapped here instead of
/// asking operators for a second, non-standard file.
#[cfg(feature = "dtls")]
fn dtls_pem(
    private_key: &[u8],
    certs: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
) -> String {
    fn block(out: &mut String, tag: &str, der: &[u8]) {
        out.push_str("-----BEGIN ");
        out.push_str(tag);
        out.push_str("-----\n");
        let encoded = auth::base64_encode(der);
        for line in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END ");
        out.push_str(tag);
        out.push_str("-----\n");
    }

    let mut pem = String::new();
    block(&mut pem, "PRIVATE_KEY", private_key);
    for cert in certs {
        block(&mut pem, "CERTIFICATE", cert.as_ref());
    }
    pem
}

/// Accept `turns:` connections: TLS handshake (5 s budget), then the same
/// TURN-over-stream framing as plaintext TCP.
#[cfg(feature = "tls")]
async fn serve_turn_tls(
    listener: TcpListener,
    material: MaterialSlot,
    context: Arc<ServerContext>,
    software: Arc<str>,
    stats: Arc<ServerStats>,
) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    let Some(turn) = stats.turn().cloned() else {
        return Ok(());
    };
    tracing::info!(%local, "rstun: TURN TLS listener ready");
    let mut drain = stats.subscribe_drain();
    if stats.is_draining() {
        return Ok(());
    }
    loop {
        let accepted = tokio::select! {
            biased;
            _ = drain.changed() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                stats.count_socket_error(Transport::Tcp);
                tracing::warn!(%local, %error, "rstun: TURN TLS accept failed");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        let permit = match context.acquire_inflight() {
            None => None,
            Some(Ok(permit)) => Some(permit),
            Some(Err(refusal)) => {
                stats.count_dropped(Transport::Tcp);
                tracing::debug!(
                    %local,
                    %peer,
                    reason = refusal.reason(),
                    counter = refusal.counter(),
                    "rstun: TURN TLS connection refused by abuse guard"
                );
                drop(stream);
                continue;
            }
        };
        // Read the live material **after** accepting: this is where a reload
        // takes effect. Established connections keep the `Arc<ServerConfig>`
        // their handshake cloned, so they are unaffected.
        let acceptor = tokio_rustls::TlsAcceptor::from(current_material(&material).tls.clone());
        let context = context.clone();
        let software = software.clone();
        let stats = stats.clone();
        let turn = turn.clone();
        let in_flight = stats.enter();
        tokio::spawn(async move {
            match tokio::time::timeout(SECURE_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    if let Err(error) = serve_turn_stream(
                        tls,
                        peer,
                        local,
                        turn::ClientTransport::Tcp,
                        context,
                        turn,
                        &software,
                        &stats,
                        permit,
                    )
                    .await
                    {
                        tracing::debug!(%peer, %error, "rstun: TURN TLS connection closed");
                    }
                }
                Ok(Err(error)) => {
                    // Never log key material — the error is rustls' own text.
                    if let Some(turn) = stats.turn() {
                        turn.count_handshake_failure();
                    }
                    tracing::debug!(%peer, %error, "rstun: TURN TLS handshake failed");
                }
                Err(_elapsed) => {
                    if let Some(turn) = stats.turn() {
                        turn.count_handshake_failure();
                    }
                    tracing::debug!(%peer, "rstun: TURN TLS handshake timed out");
                }
            }
            drop(in_flight);
        });
    }
    tracing::info!(%local, "rstun: TURN TLS listener stopped (draining)");
    Ok(())
}

/// Accept DTLS clients on one UDP socket.
///
/// The handshake happens **here**, in a per-client task with its own 5 s
/// budget: `webrtc-dtls`'s own `listen()` performs it inside `accept()`, which
/// would let one silent peer block every other client (design §9). The parent
/// listener only creates a session per remote that sends a DTLS handshake
/// record, so a stray datagram does not allocate anything.
#[cfg(feature = "dtls")]
async fn serve_turn_dtls<L>(
    listener: L,
    material: MaterialSlot,
    context: Arc<ServerContext>,
    software: Arc<str>,
    stats: Arc<ServerStats>,
) -> std::io::Result<()>
where
    L: webrtc_util::conn::Listener + Send + Sync + 'static,
{
    let local = listener
        .addr()
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let Some(turn) = stats.turn().cloned() else {
        return Ok(());
    };
    tracing::info!(%local, "rstun: TURN DTLS listener ready");
    let mut drain = stats.subscribe_drain();
    if stats.is_draining() {
        return Ok(());
    }
    loop {
        let accepted = tokio::select! {
            biased;
            _ = drain.changed() => break,
            accepted = listener.accept() => accepted,
        };
        let (conn, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%local, %error, "rstun: TURN DTLS accept failed");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        let permit = match context.acquire_inflight() {
            None => None,
            Some(Ok(permit)) => Some(permit),
            Some(Err(refusal)) => {
                stats.count_dropped(Transport::Udp);
                tracing::debug!(
                    %local,
                    %peer,
                    reason = refusal.reason(),
                    counter = refusal.counter(),
                    "rstun: TURN DTLS connection refused by abuse guard"
                );
                let _ = conn.close().await;
                continue;
            }
        };
        // A reload swaps the whole config; cloning it here is what makes the
        // new certificate apply to this client while older sessions keep the
        // copy `DTLSConn` took at their own handshake.
        let Some(config) = current_material(&material).dtls.clone() else {
            tracing::error!(%local, %peer, "rstun: TURN DTLS listener without material");
            let _ = conn.close().await;
            continue;
        };
        let context = context.clone();
        let software = software.clone();
        let stats = stats.clone();
        let turn = turn.clone();
        let in_flight = stats.enter();
        tokio::spawn(async move {
            match tokio::time::timeout(
                SECURE_HANDSHAKE_TIMEOUT,
                webrtc_dtls::conn::DTLSConn::new(conn, config, false, None),
            )
            .await
            {
                Ok(Ok(dtls)) => {
                    serve_turn_dtls_connection(
                        Arc::new(dtls),
                        peer,
                        local,
                        context,
                        turn,
                        software,
                        stats,
                        permit,
                    )
                    .await;
                }
                Ok(Err(error)) => {
                    turn.count_handshake_failure();
                    tracing::debug!(%peer, %error, "rstun: TURN DTLS handshake failed");
                }
                Err(_elapsed) => {
                    turn.count_handshake_failure();
                    tracing::debug!(%peer, "rstun: TURN DTLS handshake timed out");
                }
            }
            drop(in_flight);
        });
    }
    tracing::info!(%local, "rstun: TURN DTLS listener stopped (draining)");
    Ok(())
}

/// One DTLS "connection": a per-5-tuple transport whose datagrams each carry
/// exactly one STUN/TURN message or one `ChannelData` (design §3.1).
///
/// The read side and the write side share the `webrtc-util` `Conn`; the writer
/// runs in its own task because the relay reader must not borrow the request
/// loop.
#[cfg(feature = "dtls")]
#[allow(clippy::too_many_arguments)]
async fn serve_turn_dtls_connection(
    conn: Arc<dyn webrtc_util::conn::Conn + Send + Sync>,
    peer: SocketAddr,
    local: SocketAddr,
    context: Arc<ServerContext>,
    turn: Arc<turn::Turn>,
    software: Arc<str>,
    stats: Arc<ServerStats>,
    _inflight: Option<limit::Permit>,
) {
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(turn::TCP_SINK_CAPACITY);
    let writer_conn = conn.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = receiver.recv().await {
            // One `send` = one DTLS application-data record (a datagram on the
            // wire); relayed payload keeps its message boundary.
            if writer_conn.send(&bytes).await.is_err() {
                break;
            }
        }
    });

    let mut drain = stats.subscribe_drain();
    let mut buffer = vec![0_u8; UDP_RECV_BUFFER];
    loop {
        let received = tokio::select! {
            biased;
            _ = drain.changed() => break,
            received = conn.recv(&mut buffer) => received,
        };
        let length = match received {
            Ok(0) => break,
            Ok(length) => length,
            Err(error) => {
                tracing::debug!(%peer, %error, "rstun: TURN DTLS recv failed");
                break;
            }
        };
        if let Some(Err(refusal)) = context.check_rates(peer) {
            stats.count_dropped(Transport::Udp);
            tracing::debug!(
                %peer,
                reason = refusal.reason(),
                counter = refusal.counter(),
                "rstun: TURN DTLS datagram refused by abuse guard"
            );
            continue;
        }
        stats.count_received(Transport::Udp);
        let datagram = &buffer[..length];
        let decision = match turn
            .handle(
                datagram,
                peer,
                local,
                turn::ClientTransport::Dtls,
                &context,
                Some(&sender),
            )
            .await
        {
            Some(decision) => decision,
            None => decide_guarded(
                datagram,
                peer,
                local,
                Transport::Udp,
                &context,
                &software,
                &stats,
            ),
        };
        match decision {
            Ok(Decision::Respond(response)) => {
                if !response_is_encodable(&response) {
                    stats.count_error(Transport::Udp);
                    tracing::error!(%peer, "rstun: response violates STUN wire invariants");
                } else if sender.try_send(response).is_err() {
                    // Writer backlog: drop the answer like a lost datagram.
                    stats.count_dropped(Transport::Udp);
                } else {
                    stats.count_answered(Transport::Udp);
                }
            }
            Ok(Decision::RespondFrom { bytes, .. }) => {
                // UDP-only routing (RFC 5780): never reachable on DTLS.
                if sender.try_send(bytes).is_err() {
                    stats.count_dropped(Transport::Udp);
                } else {
                    stats.count_answered(Transport::Udp);
                }
            }
            Ok(Decision::Ignore(reason)) => {
                stats.count_ignored(Transport::Udp);
                tracing::debug!(%peer, reason, "rstun: ignored message")
            }
            Ok(Decision::Bind { .. }) => {
                // A DTLS session is not a stream: `ConnectionBind` is refused
                // with 400 before it could ever get here.
                stats.count_error(Transport::Udp);
                tracing::error!(%peer, "rstun: ConnectionBind on DTLS");
            }
            Err(error) => {
                stats.count_error(Transport::Udp);
                tracing::debug!(%peer, %error, "rstun: malformed DTLS STUN message");
            }
        }
    }

    turn.release_connection(peer, local, turn::ClientTransport::Dtls);
    drop(sender);
    writer_task.abort();
    let _ = conn.close().await;
}

/// Wait for Ctrl-C, and on Unix for SIGTERM as well (systemd stops us that way).
async fn wait_for_shutdown() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => result,
                    _ = terminate.recv() => Ok(()),
                }
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "rstun: SIGTERM handler unavailable, only Ctrl-C will stop the server"
                );
                tokio::signal::ctrl_c().await
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

/// UDP socket bound to `address`, v6-only when it is an IPv6 address.
///
/// The v6-only flag matters: a dual-stack `[::]:3478` would take the port from
/// `--listen 0.0.0.0:3478`, so the two could not coexist.
fn udp_socket(address: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(domain_of(address), Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(address))?;
    UdpSocket::from_std(socket.into())
}

/// TCP listener bound to `address`, v6-only when it is an IPv6 address.
fn tcp_listener(address: SocketAddr) -> std::io::Result<TcpListener> {
    tcp_listener_with(address, false)
}

/// TCP listener for an RFC 6062 relay port.
///
/// `SO_REUSEPORT` is what lets `Connect` bind a **second** socket to the same
/// address and dial the peer from it (RFC 6062 §5.2: the peer data connection
/// must come from the relayed transport address). On Windows that option does
/// not exist; the dial then uses an ephemeral source port (documented).
pub(crate) fn tcp_relay_listener(address: SocketAddr) -> std::io::Result<TcpListener> {
    tcp_listener_with(address, true)
}

fn tcp_listener_with(address: SocketAddr, reuse_port: bool) -> std::io::Result<TcpListener> {
    let socket = Socket::new(domain_of(address), Type::STREAM, Some(Protocol::TCP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // Windows maps SO_REUSEADDR to "steal the port"; a server does not want that.
    #[cfg(unix)]
    {
        socket.set_reuse_address(true)?;
        if reuse_port {
            // Unix only: Windows has no SO_REUSEPORT at all.
            socket.set_reuse_port(true)?;
        }
    }
    #[cfg(not(unix))]
    let _ = reuse_port;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(TCP_LISTEN_BACKLOG)?;
    TcpListener::from_std(socket.into())
}

fn domain_of(address: SocketAddr) -> Domain {
    if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use protocol::{ATTR_XOR_MAPPED_ADDRESS, BINDING_SUCCESS_RESPONSE, HEADER_LEN, MAGIC_COOKIE};

    const TEST_SOFTWARE: &str = "rstun/test";
    /// Transaction id every helper in this module uses; tests only check that
    /// the response echoes it.
    const TEST_TRANSACTION: [u8; 12] = [0x9a; 12];

    /// The minimal 20-byte `Binding Request` an operator would send by hand.
    fn binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        bytes.extend_from_slice(&0x0001_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction_id);
        bytes
    }

    /// `binding_request` plus a 4-byte `CHANGE-REQUEST` (RFC 5780 §7.2).
    fn change_request(transaction_id: [u8; 12], flags: u32) -> Vec<u8> {
        let mut bytes = binding_request(transaction_id);
        bytes[2..4].copy_from_slice(&8_u16.to_be_bytes());
        bytes.extend_from_slice(&protocol::ATTR_CHANGE_REQUEST.to_be_bytes());
        bytes.extend_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes
    }

    /// `(RESPONSE-ORIGIN, OTHER-ADDRESS)` of a response, `None` when absent.
    fn response_addresses(
        message: &protocol::Message<'_>,
    ) -> (Option<SocketAddr>, Option<SocketAddr>) {
        let mut origin = None;
        let mut other = None;
        for attribute in protocol::attributes(message.body) {
            match attribute.attr_type {
                protocol::ATTR_RESPONSE_ORIGIN => {
                    origin = protocol::decode_address_value(attribute.value)
                }
                protocol::ATTR_OTHER_ADDRESS => {
                    other = protocol::decode_address_value(attribute.value)
                }
                _ => {}
            }
        }
        (origin, other)
    }

    fn assert_binding_success(response: &[u8], transaction_id: [u8; 12], expected: SocketAddr) {
        assert!(
            response.len() >= HEADER_LEN,
            "response shorter than a STUN header"
        );
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            BINDING_SUCCESS_RESPONSE
        );
        let length = usize::from(u16::from_be_bytes([response[2], response[3]]));
        assert_eq!(response.len(), HEADER_LEN + length);
        assert_eq!(&response[8..20], &transaction_id);

        let message = protocol::parse(response).expect("response must parse");
        let mapped = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_XOR_MAPPED_ADDRESS)
            .expect("XOR-MAPPED-ADDRESS");
        assert_eq!(
            protocol::decode_xor_mapped_address(mapped.value, &message.transaction_id),
            Some(expected)
        );
    }

    async fn udp_server() -> (Arc<UdpSocket>, SocketAddr, Arc<ServerStats>) {
        let socket = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = socket.local_addr().unwrap();
        let stats = Arc::new(ServerStats::default());
        // Only the socket we serve on: the "single address" deployment shape.
        // `CHANGE-REQUEST` can only pick from this table (nothing else to pick),
        // while `RESPONSE-PORT` needs no table at all — it names a destination.
        let context = Arc::new(ServerContext {
            plan: None,
            udp: vec![(address, socket.clone())],
            mapped_address: false,
            admission: None,
            fingerprint: None,
            alternate_server: None,
            auth: None,
        });
        tokio::spawn(serve_udp(
            socket.clone(),
            context,
            Arc::from(TEST_SOFTWARE),
            stats.clone(),
        ));
        (socket, address, stats)
    }

    /// An RFC 5780 context for `decide`-level tests.
    ///
    /// The plan is what drives `CHANGE-REQUEST`; `udp` lists two ports of the
    /// same IP so the changed socket is one we actually hold.
    fn rfc5780_context() -> ServerContext {
        ServerContext {
            admission: None,
            fingerprint: None,
            alternate_server: None,
            plan: Some(rfc5780::Plan::new(
                "127.0.0.1:3478".parse().unwrap(),
                "127.0.0.2".parse().unwrap(),
                3479,
            )),
            udp: [
                "127.0.0.1:3478",
                "127.0.0.1:3479",
                "127.0.0.2:3478",
                "127.0.0.2:3479",
            ]
            .iter()
            .map(|address| {
                (
                    address.parse().unwrap(),
                    Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap()),
                )
            })
            .collect(),
            mapped_address: false,
            auth: None,
        }
    }

    /// Four real UDP sockets on the two loopback addresses RFC 5780 needs.
    ///
    /// `127.0.0.0/8` is all local on Linux and macOS, but a hardened sandbox can
    /// still refuse a bind — then the test is skipped instead of failing on an
    /// environment the server cannot control.
    struct Rig {
        plan: rfc5780::Plan,
        client: UdpSocket,
    }

    impl Rig {
        async fn start() -> Option<Self> {
            let first = udp_socket("127.0.0.1:0".parse().unwrap()).ok()?;
            let second = udp_socket("127.0.0.1:0".parse().unwrap()).ok()?;
            let primary = first.local_addr().ok()?;
            let other_port = second.local_addr().ok()?.port();
            let other_ip: IpAddr = "127.0.0.2".parse().unwrap();
            let plan = rfc5780::Plan::new(primary, other_ip, other_port);

            // The two 127.0.0.1 sockets are already bound (with kernel-chosen
            // ports); only the 127.0.0.2 ones still need binding.
            let mut sockets = vec![
                (primary, Arc::new(first)),
                (SocketAddr::new(primary.ip(), other_port), Arc::new(second)),
            ];
            for address in plan.sockets() {
                if sockets.iter().any(|(local, _)| *local == address) {
                    continue;
                }
                let socket = match udp_socket(address) {
                    Ok(socket) => socket,
                    Err(error) => {
                        eprintln!("skipping RFC 5780 test: cannot bind {address}: {error}");
                        return None;
                    }
                };
                sockets.push((address, Arc::new(socket)));
            }

            // Keep the context alive: the listener tasks hold their own `Arc`s.
            let context = Arc::new(ServerContext {
                plan: Some(plan),
                udp: sockets.clone(),
                mapped_address: false,
                admission: None,
                fingerprint: None,
                alternate_server: None,
                auth: None,
            });
            let stats = Arc::new(ServerStats::default());
            for (local, socket) in sockets {
                tokio::spawn(serve_udp(
                    socket,
                    context.clone(),
                    Arc::from(TEST_SOFTWARE),
                    stats.clone(),
                ));
                tracing::debug!(%local, "test: RFC 5780 socket ready");
            }

            let client = UdpSocket::bind("127.0.0.1:0").await.ok()?;
            Some(Self { plan, client })
        }

        /// Send one request and return the response bytes plus the **source
        /// address of the reply** — the whole point of RFC 5780.
        async fn exchange(&self, target: SocketAddr, flags: Option<u32>) -> (Vec<u8>, SocketAddr) {
            let request = match flags {
                Some(flags) => change_request(TEST_TRANSACTION, flags),
                None => binding_request(TEST_TRANSACTION),
            };
            self.exchange_with(request, target).await
        }

        /// Same as [`Rig::exchange`], with the request bytes supplied by the
        /// caller (for `RESPONSE-PORT` / `PADDING` probes).
        async fn exchange_with(
            &self,
            request: Vec<u8>,
            target: SocketAddr,
        ) -> (Vec<u8>, SocketAddr) {
            self.client.send_to(&request, target).await.unwrap();

            let mut buffer = [0_u8; 2048];
            let (len, from) =
                tokio::time::timeout(Duration::from_secs(5), self.client.recv_from(&mut buffer))
                    .await
                    .expect("RFC 5780 response timed out")
                    .unwrap();
            assert_eq!(&buffer[8..20], &TEST_TRANSACTION);
            (buffer[..len].to_vec(), from)
        }

        fn client_address(&self) -> SocketAddr {
            self.client.local_addr().unwrap()
        }
    }

    #[tokio::test]
    async fn udp_binding_request_gets_its_own_address_back() {
        let (_server, server_address, stats) = udp_server().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = client.local_addr().unwrap();
        let transaction_id = [0x11; 12];

        client
            .send_to(&binding_request(transaction_id), server_address)
            .await
            .unwrap();

        let mut buffer = [0_u8; 256];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                .await
                .expect("binding response timed out")
                .unwrap();
        assert_eq!(from, server_address);
        assert_binding_success(&buffer[..len], transaction_id, client_address);
        // 向后兼容：没有 --alt-listen 时不得出现 RFC 5780 的两个属性。
        let message = protocol::parse(&buffer[..len]).unwrap();
        assert_eq!(response_addresses(&message), (None, None));
        assert_eq!(stats.counters(), (1, 1, 0));
    }

    #[tokio::test]
    async fn udp_malformed_datagram_is_dropped_and_the_listener_survives() {
        let (_server, server_address, stats) = udp_server().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = client.local_addr().unwrap();

        // 15 bytes: shorter than a STUN header, so it must not panic or answer.
        client
            .send_to(b"not stun at all", server_address)
            .await
            .unwrap();
        // A wrong magic cookie must be dropped too.
        let mut bad_cookie = binding_request([0x22; 12]);
        bad_cookie[4..8].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        client.send_to(&bad_cookie, server_address).await.unwrap();

        let transaction_id = [0x33; 12];
        client
            .send_to(&binding_request(transaction_id), server_address)
            .await
            .unwrap();

        let mut buffer = [0_u8; 256];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
            .await
            .expect("listener died after a malformed datagram")
            .unwrap();
        assert_binding_success(&buffer[..len], transaction_id, client_address);
        assert_eq!(stats.counters(), (3, 1, 2));
    }

    #[tokio::test]
    async fn tcp_binding_request_gets_its_own_address_back() {
        let listener = tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_address = listener.local_addr().unwrap();
        let stats = Arc::new(ServerStats::default());
        let context = Arc::new(ServerContext {
            plan: None,
            udp: Vec::new(),
            mapped_address: false,
            admission: None,
            fingerprint: None,
            alternate_server: None,
            auth: None,
        });
        tokio::spawn(serve_tcp(
            listener,
            context,
            Arc::from(TEST_SOFTWARE),
            stats.clone(),
        ));

        let mut stream = TcpStream::connect(server_address).await.unwrap();
        let client_address = stream.local_addr().unwrap();
        // Two requests in one write: the server must frame them by header length.
        let transaction_ids = [[0x44; 12], [0x55; 12]];
        let mut pipelined = Vec::new();
        for transaction_id in transaction_ids {
            pipelined.extend_from_slice(&binding_request(transaction_id));
        }
        stream.write_all(&pipelined).await.unwrap();

        for transaction_id in transaction_ids {
            let mut header = [0_u8; HEADER_LEN];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
                .await
                .expect("TCP binding response timed out")
                .unwrap();
            let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let mut response = vec![0_u8; HEADER_LEN + length];
            response[..HEADER_LEN].copy_from_slice(&header);
            stream
                .read_exact(&mut response[HEADER_LEN..])
                .await
                .unwrap();
            assert_binding_success(&response, transaction_id, client_address);
        }
        assert_eq!(stats.counters(), (2, 2, 0));
    }

    #[test]
    fn non_binding_request_gets_bad_request() {
        let mut request = binding_request([0x66; 12]);
        // Allocate (TURN method 0x003) is a request too, but not Binding.
        request[0..2].copy_from_slice(&0x0003_u16.to_be_bytes());

        let decision = decide(
            &request,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                let msg_type = u16::from_be_bytes([response[0], response[1]]);
                // 0x0113 = Allocate Error Response, not a Binding error.
                assert_eq!(msg_type, 0x0113);
                assert_eq!(
                    protocol::message_method(msg_type),
                    protocol::message_method(0x0003)
                );
            }
            Decision::Ignore(reason) => panic!("expected an error response, got ignore: {reason}"),
            Decision::RespondFrom { .. } => panic!("error responses never change socket"),
            Decision::Bind { .. } => panic!("plain Binding never binds a data connection"),
        }
    }

    #[test]
    fn indication_is_ignored() {
        // Binding Indication: class 0b01 on method 0x001 → type 0x0011.
        let mut request = binding_request([0x77; 12]);
        request[0..2].copy_from_slice(&0x0011_u16.to_be_bytes());

        let decision = decide(
            &request,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap();
        assert!(matches!(decision, Decision::Ignore(_)));
    }

    #[tokio::test]
    async fn ipv6_listener_does_not_steal_the_ipv4_port() {
        let Ok(_probe) = udp_socket("[::]:0".parse().unwrap()) else {
            // IPv6 不可用的环境（部分 CI 容器）跳过。
            return;
        };
        let ipv4 = udp_socket("0.0.0.0:0".parse().unwrap()).unwrap();
        let port = ipv4.local_addr().unwrap().port();
        let ipv6 = udp_socket(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)));
        assert!(
            ipv6.is_ok(),
            "v6-only bind must coexist with the IPv4 wildcard: {:?}",
            ipv6.err()
        );
    }

    // ---------- RFC 5780 ----------

    #[tokio::test]
    async fn rfc5780_answers_with_origin_and_other_address() {
        let Some(rig) = Rig::start().await else {
            return;
        };
        let (response, from) = rig.exchange(rig.plan.primary, None).await;

        // No CHANGE-REQUEST: the reply leaves from the socket it arrived on...
        assert_eq!(from, rig.plan.primary);
        let message = protocol::parse(&response).unwrap();
        // ...RESPONSE-ORIGIN says so, OTHER-ADDRESS is the other IP + other port,
        // and XOR-MAPPED-ADDRESS is still the client.
        assert_eq!(
            response_addresses(&message),
            (
                Some(rig.plan.primary),
                Some(SocketAddr::new(rig.plan.other_ip, rig.plan.other_port))
            )
        );
        assert_binding_success(&response, TEST_TRANSACTION, rig.client_address());
    }

    #[tokio::test]
    async fn rfc5780_change_port_answers_from_the_other_port() {
        let Some(rig) = Rig::start().await else {
            return;
        };
        let (response, from) = rig
            .exchange(rig.plan.primary, Some(protocol::CHANGE_PORT))
            .await;

        // RFC 5780 Test II: same IP, other port — asserted on the datagram's
        // *source* address, not on anything inside the message.
        assert_eq!(from.ip(), rig.plan.primary.ip());
        assert_eq!(from.port(), rig.plan.other_port);

        let message = protocol::parse(&response).unwrap();
        assert_eq!(
            response_addresses(&message),
            (
                Some(from),
                Some(SocketAddr::new(rig.plan.other_ip, rig.plan.primary.port()))
            ),
            "RESPONSE-ORIGIN names the socket that answered, OTHER-ADDRESS the diagonal"
        );
        assert_binding_success(&response, TEST_TRANSACTION, rig.client_address());
    }

    #[tokio::test]
    async fn rfc5780_change_ip_answers_from_the_other_ip() {
        let Some(rig) = Rig::start().await else {
            return;
        };
        let (response, from) = rig
            .exchange(rig.plan.primary, Some(protocol::CHANGE_IP))
            .await;

        // RFC 5780 Test III: other IP, same port.
        assert_eq!(
            from,
            SocketAddr::new(rig.plan.other_ip, rig.plan.primary.port())
        );
        let message = protocol::parse(&response).unwrap();
        assert_eq!(
            response_addresses(&message),
            (
                Some(from),
                Some(SocketAddr::new(rig.plan.primary.ip(), rig.plan.other_port))
            )
        );
        assert_binding_success(&response, TEST_TRANSACTION, rig.client_address());
    }

    #[tokio::test]
    async fn rfc5780_change_both_answers_from_the_diagonal_socket() {
        let Some(rig) = Rig::start().await else {
            return;
        };
        let (response, from) = rig
            .exchange(
                rig.plan.primary,
                Some(protocol::CHANGE_IP | protocol::CHANGE_PORT),
            )
            .await;

        // RFC 5780 Test IV: other IP *and* other port.
        assert_eq!(
            from,
            SocketAddr::new(rig.plan.other_ip, rig.plan.other_port)
        );
        let message = protocol::parse(&response).unwrap();
        assert_eq!(
            response_addresses(&message),
            (Some(from), Some(rig.plan.primary))
        );
        assert_binding_success(&response, TEST_TRANSACTION, rig.client_address());
    }

    #[tokio::test]
    async fn rfc5780_entering_on_the_other_address_still_reports_a_useful_pair() {
        let Some(rig) = Rig::start().await else {
            return;
        };
        let entry = SocketAddr::new(rig.plan.other_ip, rig.plan.other_port);
        let (response, from) = rig.exchange(entry, None).await;

        // A client that probed the "other" address must not be told "the other
        // address is the one you just used"; the pair flips back to primary.
        assert_eq!(from, entry);
        let message = protocol::parse(&response).unwrap();
        assert_eq!(
            response_addresses(&message),
            (Some(entry), Some(rig.plan.primary))
        );
    }

    #[tokio::test]
    async fn udp_change_request_moves_the_answer_to_the_addressed_socket() {
        let context = rfc5780_context();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let cases = [
            (0, local),
            (protocol::CHANGE_PORT, "127.0.0.1:3479".parse().unwrap()),
            (protocol::CHANGE_IP, "127.0.0.2:3478".parse().unwrap()),
            (
                protocol::CHANGE_IP | protocol::CHANGE_PORT,
                "127.0.0.2:3479".parse().unwrap(),
            ),
        ];
        for (flags, expected) in cases {
            let request = change_request([0x43; 12], flags);
            let decision = decide(
                &request,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap();
            match decision {
                Decision::Respond(_) if flags == 0 => {}
                Decision::RespondFrom { from, .. } => {
                    assert_eq!(from, expected, "flags {flags:#x}")
                }
                other => panic!("flags {flags:#x}: expected a response, got {other:?}"),
            }
        }
    }

    // ---------- 多地址 + RFC 5780（生产用例：primary / alt / 普通 v4 / 通配 v6） ----------

    /// 生产形态的回环映射（测试里不碰 `10.254.x`）：
    ///
    /// | 生产地址 | 测试地址 | 角色 |
    /// | --- | --- | --- |
    /// | `192.0.2.5` | `127.0.0.1` | 5780 primary：**唯一**处理 `CHANGE-REQUEST` |
    /// | `192.0.2.7` | `127.0.0.2` | alt：只在四 socket 计划内被选中回包，不主动做 discovery |
    /// | `192.0.2.8` | `127.0.0.3` | 普通 v4 `--listen`：只做 RFC 5389 |
    /// | `[::]` | `[::]`（客户端打 `[::1]`） | 普通 v6 `--listen-v6`：只做 RFC 5389 |
    ///
    /// 127.0.0.0/8 在 Linux 上整段可用；沙箱/CI 容器里绑不上 `.2`/`.3`/`[::]` 时按现有
    /// `Rig` 的做法跳过（环境能力问题，不是被测代码的错误）。
    fn loopback_plan(port: u16) -> Option<rfc5780::Plan> {
        Some(rfc5780::Plan::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
            "127.0.0.2".parse().ok()?,
            port.checked_add(1)?,
        ))
    }

    async fn free_udp_port() -> Option<u16> {
        let probe = udp_socket("127.0.0.1:0".parse().ok()?).ok()?;
        let port = probe.local_addr().ok()?.port();
        drop(probe);
        Some(port)
    }

    /// 绑一套「多地址 + RFC 5780」的服务（UDP + TCP）并 spawn 监听任务。
    ///
    /// 返回 `None` = 环境绑不了这些地址（没有 127.0.0.3 别名 / 没有 IPv6 回环），
    /// 调用方直接跳过。任务持有 socket，函数返回后服务仍在跑。
    async fn spawn_multi_address_server(
        addresses: &[SocketAddr],
        plan: rfc5780::Plan,
    ) -> Option<()> {
        let bound = match bind(addresses, Some(plan), true) {
            Ok(bound) => bound,
            Err(error) => {
                eprintln!("skipping multi-address test: cannot bind: {error}");
                return None;
            }
        };
        let context = Arc::new(ServerContext {
            plan: Some(plan),
            udp: bound.udp.clone(),
            mapped_address: false,
            admission: None,
            fingerprint: None,
            alternate_server: None,
            auth: None,
        });
        let stats = Arc::new(ServerStats::default());
        for (_, socket) in bound.udp {
            tokio::spawn(serve_udp(
                socket,
                context.clone(),
                Arc::from(TEST_SOFTWARE),
                stats.clone(),
            ));
        }
        for (_, listener) in bound.tcp {
            tokio::spawn(serve_tcp(
                listener,
                context.clone(),
                Arc::from(TEST_SOFTWARE),
                stats.clone(),
            ));
        }
        Some(())
    }

    /// 未 connect 的 v4 UDP 客户端：能从任意回环源地址收包（CHANGE-REQUEST 会换源）。
    async fn udp_client() -> Option<UdpSocket> {
        UdpSocket::bind("127.0.0.1:0").await.ok()
    }

    async fn udp_exchange(
        client: &UdpSocket,
        target: SocketAddr,
        request: &[u8],
    ) -> (Vec<u8>, SocketAddr) {
        client.send_to(request, target).await.unwrap();
        let mut buffer = [0_u8; 2048];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                .await
                .expect("multi-address response timed out")
                .unwrap();
        (buffer[..len].to_vec(), from)
    }

    /// 在一条 TCP 连接上发一条 STUN 请求并读回一整帧（RFC 5389 §7.2.2 分帧）。
    async fn tcp_round_trip(stream: &mut TcpStream, request: &[u8]) -> Vec<u8> {
        stream.write_all(request).await.unwrap();
        let mut header = [0_u8; HEADER_LEN];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
            .await
            .expect("TCP response timed out")
            .unwrap();
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut response = vec![0_u8; HEADER_LEN + length];
        response[..HEADER_LEN].copy_from_slice(&header);
        stream
            .read_exact(&mut response[HEADER_LEN..])
            .await
            .unwrap();
        response
    }

    /// 生产用例 1：primary 是唯一处理 CHANGE-REQUEST 的地址，三种组合都换对源，
    /// 且响应带 `RESPONSE-ORIGIN`（= 真实回包源，生产上是私网地址）+ `OTHER-ADDRESS`。
    #[tokio::test]
    async fn primary_socket_serves_all_three_change_request_combinations() {
        let Some(port) = free_udp_port().await else {
            return;
        };
        let Some(plan) = loopback_plan(port) else {
            return;
        };
        let plain = SocketAddr::from(([127, 0, 0, 3], port));
        if spawn_multi_address_server(&[plan.primary, plain], plan)
            .await
            .is_none()
        {
            return;
        }
        let Some(client) = udp_client().await else {
            return;
        };

        // 0x02 = 换端口、0x04 = 换 IP、0x06 = 两者（RFC 5780 §7.2 的 A/B 位）。
        for (flags, from_expected, other_expected) in [
            (
                protocol::CHANGE_PORT,
                SocketAddr::new(plan.primary.ip(), plan.other_port),
                SocketAddr::new(plan.other_ip, plan.primary.port()),
            ),
            (
                protocol::CHANGE_IP,
                SocketAddr::new(plan.other_ip, plan.primary.port()),
                SocketAddr::new(plan.primary.ip(), plan.other_port),
            ),
            (
                protocol::CHANGE_IP | protocol::CHANGE_PORT,
                SocketAddr::new(plan.other_ip, plan.other_port),
                plan.primary,
            ),
        ] {
            let (response, from) = udp_exchange(
                &client,
                plan.primary,
                &change_request(TEST_TRANSACTION, flags),
            )
            .await;
            assert_eq!(from, from_expected, "flags {flags:#04x}: 回包源");
            let message = protocol::parse(&response).unwrap();
            assert_eq!(
                response_addresses(&message),
                (Some(from), Some(other_expected)),
                "flags {flags:#04x}: RESPONSE-ORIGIN / OTHER-ADDRESS"
            );
            // RESPONSE-ORIGIN 语义：**发响应那个 socket 的地址**（生产上是私网地址，
            // 客户端侧做 1:1 NAT 映射），不是 EIP/公网地址。
            assert_eq!(
                response_addresses(&message).0,
                Some(from),
                "flags {flags:#04x}: RESPONSE-ORIGIN 必须等于真实回包源"
            );
        }
    }

    /// 生产用例 2：alt 地址本身也是四 socket 之一 —— 直接打它会得到 5780 应答
    /// （`RESPONSE-ORIGIN` = alt，`OTHER-ADDRESS` = 对角地址），但它不会「主动」改变源：
    /// 不带 CHANGE-REQUEST 时仍从 alt 回。
    #[tokio::test]
    async fn alt_socket_answers_inside_the_plan_without_being_a_discovery_entry() {
        let Some(port) = free_udp_port().await else {
            return;
        };
        let Some(plan) = loopback_plan(port) else {
            return;
        };
        let plain = SocketAddr::from(([127, 0, 0, 3], port));
        if spawn_multi_address_server(&[plan.primary, plain], plan)
            .await
            .is_none()
        {
            return;
        }
        let Some(client) = udp_client().await else {
            return;
        };

        let alt = SocketAddr::new(plan.other_ip, plan.primary.port());
        let (response, from) = udp_exchange(&client, alt, &binding_request(TEST_TRANSACTION)).await;
        assert_eq!(from, alt, "没有 CHANGE-REQUEST 时不能换源");
        let message = protocol::parse(&response).unwrap();
        assert_eq!(
            response_addresses(&message),
            (
                Some(alt),
                Some(SocketAddr::new(plan.primary.ip(), plan.other_port))
            ),
            "从 alt 进来时 OTHER-ADDRESS 应是 primary 的换端口地址"
        );

        // alt 也只在计划内换：0x06 → 对角 socket（primary.ip + other_port）。
        let (response, from) = udp_exchange(
            &client,
            alt,
            &change_request(
                TEST_TRANSACTION,
                protocol::CHANGE_IP | protocol::CHANGE_PORT,
            ),
        )
        .await;
        assert_eq!(
            from,
            SocketAddr::new(plan.primary.ip(), plan.other_port),
            "alt 上的 CHANGE-REQUEST 也必须留在四 socket 计划内"
        );
        let message = protocol::parse(&response).unwrap();
        assert_eq!(response_addresses(&message), (Some(from), Some(alt)));
    }

    /// 生产用例 3：普通 v4 `--listen`（`.8` / 测试 `.3`）只做 5389 ——
    /// `CHANGE-REQUEST` 被忽略（回包源不变），且**绝不**带 `RESPONSE-ORIGIN`/`OTHER-ADDRESS`。
    #[tokio::test]
    async fn plain_v4_listen_answers_plain_binding_only() {
        let Some(port) = free_udp_port().await else {
            return;
        };
        let Some(plan) = loopback_plan(port) else {
            return;
        };
        let plain = SocketAddr::from(([127, 0, 0, 3], port));
        if spawn_multi_address_server(&[plan.primary, plain], plan)
            .await
            .is_none()
        {
            return;
        }
        let Some(client) = udp_client().await else {
            return;
        };

        for flags in [
            None,
            Some(protocol::CHANGE_PORT),
            Some(protocol::CHANGE_IP),
            Some(protocol::CHANGE_IP | protocol::CHANGE_PORT),
        ] {
            let request = match flags {
                Some(flags) => change_request(TEST_TRANSACTION, flags),
                None => binding_request(TEST_TRANSACTION),
            };
            let (response, from) = udp_exchange(&client, plain, &request).await;
            assert_eq!(
                from, plain,
                "普通 socket 必须从原 socket 回包（flags {flags:?}）"
            );
            let message = protocol::parse(&response).unwrap();
            assert_eq!(
                response_addresses(&message),
                (None, None),
                "普通 socket 不得带 RESPONSE-ORIGIN/OTHER-ADDRESS（flags {flags:?}）"
            );
            assert_binding_success(&response, TEST_TRANSACTION, client.local_addr().unwrap());
        }
    }

    /// 生产用例 4 + 5（v6 部分）：`--listen-v6 [::]` 是普通 v6 监听 ——
    /// UDP/TCP 都只回普通 Binding，且**绝不能**出现 v4 的 `RESPONSE-ORIGIN`/`OTHER-ADDRESS`
    /// （把 v4 计划算到 v6 local 上就是协议错误）。TCP 上的 `CHANGE-REQUEST` 一并忽略。
    #[tokio::test]
    async fn wildcard_v6_listen_stays_plain_when_rfc5780_is_on() {
        let Some(port) = free_udp_port().await else {
            return;
        };
        let Some(plan) = loopback_plan(port) else {
            return;
        };
        let v6_wildcard = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        let v6_target = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
        if spawn_multi_address_server(&[plan.primary, v6_wildcard], plan)
            .await
            .is_none()
        {
            return;
        }

        // --- UDP：socket 绑的是 `[::]`，客户端打 `[::1]:P`，回包源就是 `[::1]:P`。
        let client = match UdpSocket::bind("[::1]:0").await {
            Ok(client) => client,
            Err(error) => {
                eprintln!("skipping wildcard-v6 UDP half: no IPv6 client socket: {error}");
                return;
            }
        };
        let transaction_id = [0x6b; 12];
        let (response, from) =
            udp_exchange(&client, v6_target, &binding_request(transaction_id)).await;
        assert_eq!(from, v6_target);
        let message = protocol::parse(&response).unwrap();
        assert_eq!(
            response_addresses(&message),
            (None, None),
            "v6 socket 不得带 5780 属性（尤其不能出现 v4 的 RESPONSE-ORIGIN/OTHER-ADDRESS）"
        );
        assert_binding_success(&response, transaction_id, client.local_addr().unwrap());
        let xor = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_XOR_MAPPED_ADDRESS)
            .expect("XOR-MAPPED-ADDRESS");
        assert_eq!(
            xor.value[1], 0x02,
            "地址族必须是 IPv6：证明请求真的落在 [::] 这个 v6 socket 上"
        );

        // --- TCP：同一条连接上普通 Binding 与 CHANGE-REQUEST 都只得到普通响应。
        let mut stream = match TcpStream::connect(v6_target).await {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("skipping wildcard-v6 TCP half: {error}");
                return;
            }
        };
        let response = tcp_round_trip(&mut stream, &binding_request([0x6c; 12])).await;
        assert_binding_success(&response, [0x6c; 12], stream.local_addr().unwrap());
        assert_eq!(
            response_addresses(&protocol::parse(&response).unwrap()),
            (None, None),
            "v6 TCP 的普通 Binding 不得带 5780 属性"
        );
        let response = tcp_round_trip(
            &mut stream,
            &change_request([0x6d; 12], protocol::CHANGE_IP | protocol::CHANGE_PORT),
        )
        .await;
        assert_binding_success(&response, [0x6d; 12], stream.local_addr().unwrap());
        assert_eq!(
            response_addresses(&protocol::parse(&response).unwrap()),
            (None, None),
            "TCP 上的 CHANGE-REQUEST 必须忽略（状态不变，别退化）"
        );
    }

    /// 生产用例 5（v4 部分）：`--tcp` 在**全部**监听上生效（含普通 `.8`）。
    /// TCP 上 `CHANGE-REQUEST` 一律忽略，仍在原连接上应答；plan socket 的 TCP
    /// 响应仍带 5780 属性（`RESPONSE-ORIGIN` = 该 listener 的地址）。
    #[tokio::test]
    async fn tcp_plain_sockets_answer_bindings_and_ignore_change_request() {
        let Some(port) = free_udp_port().await else {
            return;
        };
        let Some(plan) = loopback_plan(port) else {
            return;
        };
        let plain = SocketAddr::from(([127, 0, 0, 3], port));
        if spawn_multi_address_server(&[plan.primary, plain], plan)
            .await
            .is_none()
        {
            return;
        }

        // 普通地址上的 TCP：binding 与 CHANGE-REQUEST 都只得到普通响应。
        let mut stream = TcpStream::connect(plain)
            .await
            .expect("--tcp 必须在普通 --listen 地址上也监听");
        let response = tcp_round_trip(&mut stream, &binding_request([0x71; 12])).await;
        assert_binding_success(&response, [0x71; 12], stream.local_addr().unwrap());
        assert_eq!(
            response_addresses(&protocol::parse(&response).unwrap()),
            (None, None)
        );
        let response = tcp_round_trip(
            &mut stream,
            &change_request([0x72; 12], protocol::CHANGE_IP | protocol::CHANGE_PORT),
        )
        .await;
        assert_binding_success(&response, [0x72; 12], stream.local_addr().unwrap());
        assert_eq!(
            response_addresses(&protocol::parse(&response).unwrap()),
            (None, None),
            "TCP 普通 socket 上的 CHANGE-REQUEST 必须忽略"
        );

        // plan socket 上的 TCP：仍带 5780 属性，但 ROT 不会换连接（respond in-band）。
        let mut stream = TcpStream::connect(plan.primary)
            .await
            .expect("primary 上也必须有 TCP listener");
        let response = tcp_round_trip(
            &mut stream,
            &change_request([0x73; 12], protocol::CHANGE_IP | protocol::CHANGE_PORT),
        )
        .await;
        assert_binding_success(&response, [0x73; 12], stream.local_addr().unwrap());
        assert_eq!(
            response_addresses(&protocol::parse(&response).unwrap()),
            (
                Some(plan.primary),
                Some(SocketAddr::new(plan.other_ip, plan.other_port))
            ),
            "TCP 上 5780 属性仍是这套 listener 的地址对"
        );
    }

    #[tokio::test]
    async fn bind_dedupes_plan_sockets_listed_again_as_listen_addresses() {
        let probe = match udp_socket("127.0.0.1:0".parse().unwrap()) {
            Ok(probe) => probe,
            Err(_) => return,
        };
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let primary = SocketAddr::from(([127, 0, 0, 1], port));
        let alt_ip: IpAddr = "127.0.0.2".parse().unwrap();
        let other_port = match port.checked_add(1) {
            Some(other_port) => other_port,
            None => return,
        };
        let plan = rfc5780::Plan::new(primary, alt_ip, other_port);
        // 把 alt socket（`.2:P`，同时是 TCP listener）再写进 --listen：它已在
        // plan 里，bind() 必须跳过，否则第二次 bind 会 `Address in use`。
        let addresses = [primary, SocketAddr::new(alt_ip, port)];
        let bound = match bind(&addresses, Some(plan), true) {
            Ok(bound) => bound,
            Err(error) => {
                eprintln!("skipping bind-dedupe test: cannot bind: {error}");
                return;
            }
        };
        assert_eq!(bound.udp.len(), 4, "四 socket，多余地址全部去重");
        assert_eq!(
            bound.tcp.len(),
            2,
            "TCP = plan.tcp_listeners()，去重后仍是 2"
        );
        let mut udp: Vec<SocketAddr> = bound.udp.iter().map(|(local, _)| *local).collect();
        udp.sort_unstable();
        udp.dedup();
        assert_eq!(udp.len(), 4, "没有地址被绑两次");
    }

    #[tokio::test]
    async fn tcp_ignores_change_request_and_answers_on_the_same_connection() {
        let context = rfc5780_context();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let request = change_request([0x42; 12], protocol::CHANGE_IP | protocol::CHANGE_PORT);

        let decision = decide(
            &request,
            "127.0.0.1:5000".parse().unwrap(),
            local,
            Transport::Tcp,
            &context,
            TEST_SOFTWARE,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                let message = protocol::parse(&response).unwrap();
                assert_eq!(
                    response_addresses(&message),
                    (Some(local), Some("127.0.0.2:3479".parse().unwrap()))
                );
            }
            other => panic!("TCP must answer in-band, got {other:?}"),
        }
    }

    #[test]
    fn udp_without_rfc5780_adds_no_attributes() {
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let decision = decide(
            &binding_request([0x45; 12]),
            peer,
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                let message = protocol::parse(&response).unwrap();
                assert_eq!(response_addresses(&message), (None, None));
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    // ---------- 合规包（420 / MAPPED-ADDRESS / PADDING / RESPONSE-PORT） ----------

    /// `binding_request` plus the given `(type, value)` attributes.
    fn request_with_attributes(transaction_id: [u8; 12], attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut bytes = binding_request(transaction_id);
        let mut body = Vec::new();
        for (attr_type, value) in attributes {
            body.extend_from_slice(&attr_type.to_be_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value);
            body.resize(body.len().div_ceil(4) * 4, 0);
        }
        bytes[2..4].copy_from_slice(&(body.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    /// `binding_request` plus one attribute carrying `value`.
    fn request_with_attribute(transaction_id: [u8; 12], attr_type: u16, value: &[u8]) -> Vec<u8> {
        request_with_attributes(transaction_id, &[(attr_type, value)])
    }

    /// Attribute types of a response, in wire order.
    fn attribute_types(response: &[u8]) -> Vec<u16> {
        let message = protocol::parse(response).expect("response must parse");
        protocol::attributes(message.body)
            .map(|attribute| attribute.attr_type)
            .collect()
    }

    /// `(error code, UNKNOWN-ATTRIBUTES value)` of an error response.
    fn error_details(response: &[u8]) -> (u16, Vec<u8>) {
        let message = protocol::parse(response).expect("error response must parse");
        assert_eq!(
            protocol::message_class(message.msg_type),
            MessageClass::ErrorResponse
        );
        let error = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_ERROR_CODE)
            .expect("ERROR-CODE");
        let code = u16::from(error.value[2]) * 100 + u16::from(error.value[3]);
        let unknown = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_UNKNOWN_ATTRIBUTES)
            .map(|attribute| attribute.value.to_vec())
            .unwrap_or_default();
        (code, unknown)
    }

    #[test]
    fn unknown_comprehension_required_attribute_gets_a_420() {
        // RFC 5389 §7.3.1: an attribute we do not implement must be refused, and
        // RFC 5389 §15.9 says the response carries the offending type.
        let request = request_with_attribute([0x71; 12], 0x0033, &[0xde, 0xad, 0xbe, 0xef]);
        let decision = decide(
            &request,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                assert_eq!(
                    u16::from_be_bytes([response[0], response[1]]),
                    protocol::BINDING_ERROR_RESPONSE
                );
                let (code, list) = error_details(&response);
                assert_eq!(code, 420);
                // RFC 5389 §15.9: one 16-bit type per unknown attribute, no
                // repeated entry (the alignment padding lives outside the value).
                assert_eq!(list, vec![0x00, 0x33]);
            }
            other => panic!("expected a 420, got {other:?}"),
        }
    }

    #[test]
    fn unknown_attributes_only_apply_to_binding_requests() {
        // An indication is never answered, even carrying an unknown attribute.
        let mut indication = request_with_attribute([0x74; 12], 0x0033, &[0; 4]);
        indication[0..2].copy_from_slice(&0x0011_u16.to_be_bytes());
        let decision = decide(
            &indication,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap();
        assert!(matches!(decision, Decision::Ignore(_)));

        // An unimplemented method keeps its 400 — the 420 check runs only after
        // the method is known to be Binding, so existing behaviour is unchanged.
        let mut allocate = request_with_attribute([0x75; 12], 0x0033, &[0; 4]);
        allocate[0..2].copy_from_slice(&0x0003_u16.to_be_bytes());
        let decision = decide(
            &allocate,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                let (code, list) = error_details(&response);
                assert_eq!(code, 400);
                assert!(list.is_empty(), "a 400 must not carry UNKNOWN-ATTRIBUTES");
            }
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    #[test]
    fn ice_and_auth_attributes_still_get_a_binding_response() {
        // 这些属性一个都不能触发 420：USERNAME / MESSAGE-INTEGRITY 是 RFC 3489 时代
        // 客户端会顺手带的，PRIORITY / USE-CANDIDATE / ICE-CONTROLLING 是 ICE 连通性
        // 检查的标配。把它们当成「未知」会把正常客户端打成 420。
        let request = request_with_attributes(
            [0x76; 12],
            &[
                (protocol::ATTR_USERNAME, b"user:pass"),
                (protocol::ATTR_MESSAGE_INTEGRITY, &[0_u8; 20]),
                (protocol::ATTR_PRIORITY, &[0x6e, 0x00, 0x01, 0xff]),
                (protocol::ATTR_USE_CANDIDATE, &[]),
                (protocol::ATTR_ICE_CONTROLLING, &[0_u8; 8]),
                (protocol::ATTR_FINGERPRINT, &[0_u8; 4]),
            ],
        );

        let decision = decide(
            &request,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                assert_eq!(
                    attribute_types(&response),
                    vec![protocol::ATTR_XOR_MAPPED_ADDRESS, protocol::ATTR_SOFTWARE]
                );
            }
            other => panic!("expected a Binding success, got {other:?}"),
        }
    }

    #[test]
    fn mapped_address_is_off_by_default_and_wired_through_the_flag() {
        let request = binding_request([0x77; 12]);
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let decide_with = |mapped_address: bool| {
            let context = ServerContext {
                plan: None,
                udp: Vec::new(),
                mapped_address,
                admission: None,
                fingerprint: None,
                alternate_server: None,
                auth: None,
            };
            match decide(
                &request,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap()
            {
                Decision::Respond(response) => response,
                other => panic!("expected a response, got {other:?}"),
            }
        };

        // 默认关闭：与改造前完全一致（只有 XOR-MAPPED-ADDRESS + SOFTWARE）。
        let plain = decide_with(false);
        assert_eq!(
            attribute_types(&plain),
            vec![protocol::ATTR_XOR_MAPPED_ADDRESS, protocol::ATTR_SOFTWARE]
        );

        // 打开：多一个 MAPPED-ADDRESS，紧跟在 XOR 后面，值就是客户端地址。
        let mapped = decide_with(true);
        assert_eq!(
            attribute_types(&mapped),
            vec![
                protocol::ATTR_XOR_MAPPED_ADDRESS,
                protocol::ATTR_MAPPED_ADDRESS,
                protocol::ATTR_SOFTWARE
            ]
        );
        let message = protocol::parse(&mapped).unwrap();
        let raw = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_MAPPED_ADDRESS)
            .expect("MAPPED-ADDRESS");
        assert_eq!(protocol::decode_address_value(raw.value), Some(peer));
        // 除了插入的这个属性，其余字节不变（Message Length 除外）。
        assert_eq!(&mapped[8..HEADER_LEN + 12], &plain[8..HEADER_LEN + 12]);
        assert_eq!(&mapped[HEADER_LEN + 24..], &plain[HEADER_LEN + 12..]);
    }

    #[tokio::test]
    async fn udp_padding_is_echoed_back_with_the_same_length() {
        let (_server, server_address, stats) = udp_server().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = request_with_attribute([0x78; 12], protocol::ATTR_PADDING, &[0x5a; 128]);
        client.send_to(&request, server_address).await.unwrap();

        let mut buffer = [0_u8; 2048];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
            .await
            .expect("padded response timed out")
            .unwrap();
        let response = &buffer[..len];
        assert_binding_success(response, [0x78; 12], client.local_addr().unwrap());
        let message = protocol::parse(response).unwrap();
        // RFC 5780 §7.6: same length as the request asked for, so an MTU probe
        // measures the path and not our answer's size.
        assert_eq!(protocol::padding_len(message.body), Some(128));
        // 不放大：响应里的 PADDING 不超过请求里的。
        let request_padding = protocol::parse(&request).unwrap();
        assert!(protocol::padding_len(message.body) <= protocol::padding_len(request_padding.body));
        assert_eq!(stats.counters(), (1, 1, 0));
    }

    #[tokio::test]
    async fn udp_response_port_delivers_to_the_named_port() {
        let (_server, server_address, stats) = udp_server().await;
        // RFC 5780 §7.5: "the Binding Response MUST be transmitted to the source
        // IP address of the Binding Request and the port contained in
        // RESPONSE-PORT". The client therefore keeps a *second* socket on the
        // named port — the answer must arrive there, not on the socket that sent
        // the request.
        let inbox = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let inbox_address = inbox.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transaction_id = [0x7a; 12];

        let request = request_with_attribute(
            transaction_id,
            protocol::ATTR_RESPONSE_PORT,
            &inbox_address.port().to_be_bytes(),
        );
        client.send_to(&request, server_address).await.unwrap();

        let mut buffer = [0_u8; 512];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), inbox.recv_from(&mut buffer))
                .await
                .expect("response did not reach the port named in RESPONSE-PORT")
                .unwrap();
        // Source address/port are unchanged: RESPONSE-PORT is a destination.
        assert_eq!(from, server_address);
        assert_binding_success(&buffer[..len], transaction_id, client.local_addr().unwrap());

        // ...and the request source port must stay quiet: the answer went to the
        // named port instead of back to where the request came from.
        let mut stray = [0_u8; 64];
        let quiet =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut stray)).await;
        assert!(
            quiet.is_err(),
            "the answer must not also be sent to the request source port"
        );
        assert_eq!(stats.counters(), (1, 1, 0));
    }

    #[test]
    fn response_port_is_a_destination_port_even_when_nothing_listens() {
        // No socket table at all: the port does not have to be one we hold, and
        // `0` must be passed through rather than rejected or panicking (the
        // kernel reports the send error; see `serve_udp`).
        let context = ServerContext::default();
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        for port in [1_u16, 0, 23480, u16::MAX] {
            let request = request_with_attribute(
                [0x7b; 12],
                protocol::ATTR_RESPONSE_PORT,
                &port.to_be_bytes(),
            );
            let decision = decide(
                &request,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap();
            match decision {
                Decision::RespondFrom { from, to, .. } => {
                    assert_eq!(from, local, "source address must not change");
                    assert_eq!(
                        to,
                        SocketAddr::new(peer.ip(), port),
                        "destination must keep the source IP and use RESPONSE-PORT"
                    );
                }
                other => panic!("expected a redirected response, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn udp_response_port_with_padding_gets_a_400() {
        let (_server, server_address, stats) = udp_server().await;
        // RFC 5780 §6: "If the Request also contains the RESPONSE-PORT attribute
        // the server MUST return an error response of type 400" (§7.5 says the
        // server "MUST NOT process" the combination). Dropping the datagram
        // would look like a filtered path to the client.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = request_with_attributes(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_RESPONSE_PORT, &23480_u16.to_be_bytes()),
                (protocol::ATTR_PADDING, &[0_u8; 32]),
            ],
        );
        client.send_to(&request, server_address).await.unwrap();

        let mut buffer = [0_u8; 512];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                .await
                .expect("RESPONSE-PORT + PADDING must be answered with 400")
                .unwrap();
        assert_eq!(from, server_address, "the 400 comes from the entry socket");
        let (code, list) = error_details(&buffer[..len]);
        assert_eq!(code, 400);
        assert!(list.is_empty(), "a 400 must not carry UNKNOWN-ATTRIBUTES");
        assert_eq!(stats.counters(), (1, 1, 0));
    }

    #[test]
    fn response_port_is_udp_only() {
        // Over TCP the answer can only come back on the connection it arrived
        // on, so RESPONSE-PORT (like CHANGE-REQUEST) is ignored there.
        let context = ServerContext::default();
        let request = request_with_attribute(
            [0x79; 12],
            protocol::ATTR_RESPONSE_PORT,
            &3479_u16.to_be_bytes(),
        );
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();

        // TCP: in-band, destination unchanged (still the request source).
        let decision = decide(
            &request,
            peer,
            local,
            Transport::Tcp,
            &context,
            TEST_SOFTWARE,
        )
        .unwrap();
        assert!(
            matches!(decision, Decision::Respond(_)),
            "TCP must answer in-band"
        );

        // ...while UDP moves the destination port, keeping the source socket.
        let decision = decide(
            &request,
            peer,
            local,
            Transport::Udp,
            &context,
            TEST_SOFTWARE,
        )
        .unwrap();
        match decision {
            Decision::RespondFrom { from, to, .. } => {
                assert_eq!(from, local);
                assert_eq!(to, SocketAddr::new(peer.ip(), 3479));
            }
            other => panic!("expected a response to port 3479, got {other:?}"),
        }
    }

    // ---------- 抗滥用（限速 / 在途 / 反射防护 / 名单） ----------

    /// A context whose only configuration is the abuse guard under test.
    fn guarded_context(policy: limit::Policy) -> ServerContext {
        ServerContext {
            admission: Some(limit::Admission::new(policy).expect("policy must build")),
            ..ServerContext::default()
        }
    }

    fn admission_of(context: &ServerContext) -> &Arc<limit::Admission> {
        context
            .admission
            .as_ref()
            .expect("guard must be configured")
    }

    /// A 40-byte `Binding Request` carrying `RESPONSE-PORT` (8 bytes) plus two
    /// inert attributes: the probe used by the "raised `--reflect-min-request`"
    /// tests (`20` is the default, so 28 bytes already clears it).
    fn forty_byte_response_port_request(transaction_id: [u8; 12], port: u16) -> Vec<u8> {
        let request = request_with_attributes(
            transaction_id,
            &[
                (protocol::ATTR_RESPONSE_PORT, &port.to_be_bytes()),
                (protocol::ATTR_PRIORITY, &[0_u8; 4]),
                (protocol::ATTR_SOFTWARE, b""),
            ],
        );
        assert_eq!(request.len(), 40, "helper must produce a 40-byte request");
        request
    }

    /// The smallest datagram that can carry a redirect attribute: 20-byte header
    /// + one 8-byte `RESPONSE-PORT` (4-byte TLV header, 2-byte value, 2-byte pad).
    fn minimal_response_port_request(transaction_id: [u8; 12], port: u16) -> Vec<u8> {
        let request = request_with_attribute(
            transaction_id,
            protocol::ATTR_RESPONSE_PORT,
            &port.to_be_bytes(),
        );
        assert_eq!(
            request.len(),
            28,
            "28 bytes is the smallest RESPONSE-PORT probe"
        );
        request
    }

    #[test]
    fn abuse_guard_is_off_until_a_flag_is_given() {
        assert!(build_policy(&Args::default()).unwrap().is_none());
        // `--allow`/`--deny` alone are a guard too (they change admission).
        let deny_only = build_policy(&Args {
            deny: vec!["127.0.0.1/32".parse().unwrap()],
            ..Args::default()
        })
        .unwrap()
        .expect("a deny list is a guard");
        assert!(deny_only.deny.len() == 1);
        assert!(deny_only.per_ip.is_none());
    }

    #[test]
    fn bare_rate_limit_flags_use_the_documented_defaults() {
        let cli = Cli::try_parse_from(["rstun", "server", "--rate-limit", "--rate-limit-port"])
            .expect("the value of these flags is optional");
        let Command::Server(args) = cli.command;
        let policy = build_policy(&args).unwrap().expect("guard enabled");
        // Design §4: 200 req/s with a burst of 400 per source IP, 20 req/s per
        // source port.
        assert_eq!(policy.per_ip, Some(limit::Rate::new(200.0, 400.0)));
        assert_eq!(policy.per_port, Some(limit::Rate::new(20.0, 40.0)));
    }

    #[test]
    fn one_reflect_flag_enables_the_guard_with_the_documented_defaults() {
        // Either numeric flag turns the guard on; the other value comes from the
        // documented default (min = the 20-byte header, ratio 2.0).
        for args in [
            Args {
                reflect_min_request: Some(20),
                ..Args::default()
            },
            Args {
                reflect_ratio: Some(2.0),
                ..Args::default()
            },
        ] {
            let policy = build_policy(&args).unwrap().expect("guard enabled");
            assert_eq!(
                policy.reflect,
                Some(limit::Reflect {
                    min_request: limit::DEFAULT_REFLECT_MIN_REQUEST,
                    ratio: limit::DEFAULT_REFLECT_RATIO,
                }),
                "{args:?}"
            );
        }
        assert_eq!(limit::DEFAULT_REFLECT_MIN_REQUEST, 20);
        assert_eq!(limit::DEFAULT_REFLECT_RATIO, 2.0);
    }

    #[test]
    fn explicit_rate_limit_values_win() {
        let cli = Cli::try_parse_from([
            "rstun",
            "server",
            "--rate-limit",
            "50",
            "--rate-burst",
            "7",
            "--global-rate",
            "1000",
            "--max-inflight",
            "8",
        ])
        .unwrap();
        let Command::Server(args) = cli.command;
        let policy = build_policy(&args).unwrap().expect("guard enabled");
        assert_eq!(policy.per_ip, Some(limit::Rate::new(50.0, 7.0)));
        assert_eq!(policy.global, Some(limit::Rate::new(1000.0, 2000.0)));
        assert_eq!(policy.max_inflight, Some(8));
    }

    #[test]
    fn unusable_abuse_guard_values_fail_startup() {
        // clap rejects what it cannot parse (negative numbers, bad CIDRs)...
        assert!(Cli::try_parse_from(["rstun", "server", "--rate-limit", "-1"]).is_err());
        assert!(Cli::try_parse_from(["rstun", "server", "--deny", "10.0.0.0/33"]).is_err());
        assert!(Cli::try_parse_from(["rstun", "server", "--allow", "not-a-cidr"]).is_err());
        // ...and `build_policy` rejects values that parse but cannot work.
        for args in [
            Args {
                rate_limit: Some(0),
                ..Args::default()
            },
            Args {
                rate_burst: Some(10),
                ..Args::default()
            },
            Args {
                rate_limit: Some(10),
                rate_burst: Some(0),
                ..Args::default()
            },
            Args {
                rate_limit_port: Some(0),
                ..Args::default()
            },
            Args {
                global_rate: Some(0),
                ..Args::default()
            },
            Args {
                max_inflight: Some(0),
                ..Args::default()
            },
            Args {
                reflect_min_request: Some(19),
                ..Args::default()
            },
            Args {
                reflect_ratio: Some(0.0),
                ..Args::default()
            },
            Args {
                reflect_ratio: Some(-1.0),
                ..Args::default()
            },
        ] {
            assert!(build_policy(&args).is_err(), "{args:?} should be refused");
        }
    }

    /// A policy with only the reflection guard configured.
    fn reflect_policy(min_request: usize, ratio: f64) -> limit::Policy {
        limit::Policy {
            reflect: Some(limit::Reflect { min_request, ratio }),
            ..limit::Policy::default()
        }
    }

    /// `decide_guarded` with a throwaway stats object: these tests assert the
    /// *decision*, and the counters through the context's admission.
    fn guarded(
        datagram: &[u8],
        peer: &str,
        local: &str,
        transport: Transport,
        context: &ServerContext,
    ) -> Decision {
        decide_guarded(
            datagram,
            peer.parse().unwrap(),
            local.parse().unwrap(),
            transport,
            context,
            TEST_SOFTWARE,
            &ServerStats::default(),
        )
        .unwrap()
    }

    /// `--alt-listen` shape: a plan exists, so answers carry the RFC 5780 pair.
    fn alt_listen_context(policy: limit::Policy) -> ServerContext {
        ServerContext {
            plan: Some(rfc5780::Plan::new(
                "127.0.0.1:3478".parse().unwrap(),
                "127.0.0.2".parse().unwrap(),
                3479,
            )),
            udp: Vec::new(),
            mapped_address: false,
            admission: Some(limit::Admission::new(policy).expect("policy must build")),
            fingerprint: None,
            alternate_server: None,
            auth: None,
        }
    }

    fn success_bytes(decision: Decision) -> Vec<u8> {
        match decision {
            Decision::Respond(bytes) | Decision::RespondFrom { bytes, .. } => bytes,
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn reflect_defaults_let_a_real_rfc5780_probe_through() {
        // The real probe coturn's `stunclient` sends: 28-byte RESPONSE-PORT.
        // With the guard on the answer omits the optional SOFTWARE, so the
        // 28-byte probe gets 32 bytes (TEST_SOFTWARE adds 16 here, and 20 with
        // the production string — omitted either way) = 1.14x.
        let context = guarded_context(reflect_policy(
            limit::DEFAULT_REFLECT_MIN_REQUEST,
            limit::DEFAULT_REFLECT_RATIO,
        ));
        let request = minimal_response_port_request(TEST_TRANSACTION, 23480);
        assert_eq!(request.len(), 28);

        match guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &context,
        ) {
            Decision::RespondFrom { to, bytes, .. } => {
                assert_eq!(to.port(), 23480, "RESPONSE-PORT must still be honoured");
                assert_eq!(
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    protocol::BINDING_SUCCESS_RESPONSE
                );
                assert_eq!(
                    attribute_types(&bytes),
                    vec![protocol::ATTR_XOR_MAPPED_ADDRESS],
                    "a small redirect answer carries no SOFTWARE"
                );
                assert_eq!(bytes.len(), 32, "20-byte header + XOR-MAPPED-ADDRESS");
                let policy = limit::Reflect {
                    min_request: limit::DEFAULT_REFLECT_MIN_REQUEST,
                    ratio: limit::DEFAULT_REFLECT_RATIO,
                };
                assert!(
                    policy.allows_response(request.len(), bytes.len()),
                    "{} bytes for a {} byte probe must be inside the policy",
                    bytes.len(),
                    request.len()
                );
            }
            other => panic!("a 28-byte RFC 5780 probe must be answered, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 0);
    }

    #[test]
    fn reflect_defaults_cover_the_alt_listen_answer() {
        // The acceptance case: with --alt-listen the answer also carries
        // RESPONSE-ORIGIN + OTHER-ADDRESS (24 bytes). Without SOFTWARE that is
        // 56 bytes for a 28-byte probe = 2.00x, inside
        // max(28 x 2.0, 28 + 32) = 60. (With SOFTWARE it would be 76 = 2.71x
        // and the guard would refuse it — which is why the omission exists.)
        let context = alt_listen_context(reflect_policy(
            limit::DEFAULT_REFLECT_MIN_REQUEST,
            limit::DEFAULT_REFLECT_RATIO,
        ));
        let request = minimal_response_port_request(TEST_TRANSACTION, 23480);
        let bytes = success_bytes(guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &context,
        ));
        assert_eq!(bytes.len(), 56, "20 header + XOR 12 + the RFC 5780 pair");
        assert_eq!(
            attribute_types(&bytes),
            vec![
                protocol::ATTR_XOR_MAPPED_ADDRESS,
                protocol::ATTR_RESPONSE_ORIGIN,
                protocol::ATTR_OTHER_ADDRESS
            ],
            "no SOFTWARE on a small redirect answer"
        );
        assert!(
            limit::Reflect {
                min_request: 20,
                ratio: limit::DEFAULT_REFLECT_RATIO
            }
            .allows_response(request.len(), bytes.len())
        );
        assert_eq!(admission_of(&context).counters().reflect_rejected, 0);
    }

    #[test]
    fn software_is_dropped_only_for_small_redirect_probes() {
        // The whole matrix of the SOFTWARE rule, in one place. The rule is
        // exactly as wide as the guard's domain (`redirect_is_guarded`):
        //   guard on + UDP + redirect that can be honoured + < 40 bytes -> no SOFTWARE
        //   guard on + UDP + redirect + >= 40                            -> SOFTWARE
        //   guard on + UDP + plain Binding                               -> SOFTWARE (byte-frozen)
        //   guard on + UDP + CHANGE-REQUEST without a plan               -> SOFTWARE
        //   guard on + TCP + redirect                                    -> SOFTWARE
        //   guard off + anything                                         -> SOFTWARE (26.410.100 bytes)
        let small = minimal_response_port_request(TEST_TRANSACTION, 23480);
        let big = forty_byte_response_port_request(TEST_TRANSACTION, 23480);
        let plain = binding_request(TEST_TRANSACTION);
        let change = change_request(TEST_TRANSACTION, protocol::CHANGE_IP);
        assert_eq!(change.len(), 28);
        let guarded_ctx = guarded_context(reflect_policy(20, 2.0));
        let alt_ctx = alt_listen_context(reflect_policy(20, 2.0));
        let plain_ctx = ServerContext::default();

        let has_software = |decision: Decision| {
            attribute_types(&success_bytes(decision)).contains(&protocol::ATTR_SOFTWARE)
        };

        assert!(!has_software(guarded(
            &small,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &guarded_ctx
        )));
        assert!(has_software(guarded(
            &big,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &guarded_ctx
        )));
        assert!(has_software(guarded(
            &plain,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &guarded_ctx
        )));
        // F-A: the rule must not be wider than the guard.
        // 1. TCP: the guard never applies, so the probe keeps its SOFTWARE.
        assert!(has_software(guarded(
            &small,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Tcp,
            &guarded_ctx
        )));
        // 2. UDP without `--alt-listen`: CHANGE-REQUEST cannot redirect, so the
        //    request is not guarded and keeps its SOFTWARE.
        assert!(has_software(guarded(
            &change,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &guarded_ctx
        )));
        // 3. UDP with `--alt-listen`: the same probe *is* guarded, so no SOFTWARE.
        assert!(!has_software(guarded(
            &change,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &alt_ctx
        )));

        // Guard off: the 28-byte redirect probe keeps its SOFTWARE (48 bytes
        // with TEST_SOFTWARE, 52 with the production string), exactly as
        // 26.410.100 answered it.
        let unguarded = success_bytes(guarded(
            &small,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &plain_ctx,
        ));
        assert_eq!(unguarded.len(), 48);
        assert!(attribute_types(&unguarded).contains(&protocol::ATTR_SOFTWARE));
    }

    #[test]
    fn the_guard_actually_rejects_a_padded_redirect_probe() {
        // The case that proves the ratio rule is not a formality: a 40-byte
        // request made of CHANGE-REQUEST (8) + PADDING 8 (12) with
        // --alt-listen would get 76 + 12 = 88 bytes (84 with TEST_SOFTWARE),
        // which is above max(40 x 2.0, 40 + 32) = 80.
        let context = alt_listen_context(reflect_policy(
            limit::DEFAULT_REFLECT_MIN_REQUEST,
            limit::DEFAULT_REFLECT_RATIO,
        ));
        let request = request_with_attributes(
            TEST_TRANSACTION,
            &[
                (
                    protocol::ATTR_CHANGE_REQUEST,
                    &protocol::CHANGE_PORT.to_be_bytes(),
                ),
                (protocol::ATTR_PADDING, &[0_u8; 8]),
            ],
        );
        assert_eq!(request.len(), 40);
        let stats = ServerStats::default();
        let decision = decide_guarded(
            &request,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &context,
            TEST_SOFTWARE,
            &stats,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                assert_eq!(error_details(&response).0, 400);
                assert!(
                    (response.len() as f64)
                        <= limit::Reflect {
                            min_request: 20,
                            ratio: 2.0
                        }
                        .allowed_response_len(request.len()),
                    "the refusal itself must stay inside the allowance"
                );
            }
            other => panic!("a padded redirect probe must be refused, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 1);
        assert_eq!(stats.counters(), (0, 0, 1));

        // More padding makes the request pay for the growth: PADDING 16 gives a
        // 48-byte request, 92-byte answer and max(96, 80) = 96, so it passes —
        // the rule is "answer no bigger than what you sent", not "no PADDING".
        let padded = request_with_attributes(
            TEST_TRANSACTION,
            &[
                (
                    protocol::ATTR_CHANGE_REQUEST,
                    &protocol::CHANGE_PORT.to_be_bytes(),
                ),
                (protocol::ATTR_PADDING, &[0_u8; 16]),
            ],
        );
        assert_eq!(padded.len(), 48);
        assert!(matches!(
            guarded(
                &padded,
                "198.51.100.9:5000",
                "127.0.0.1:3478",
                Transport::Udp,
                &context
            ),
            Decision::RespondFrom { .. }
        ));
    }

    #[test]
    fn reflect_min_request_still_gates_when_raised() {
        // Raising the size floor is the operator's choice; it must still work
        // and must still answer with a 400 when that 400 does not amplify.
        let context = guarded_context(reflect_policy(40, limit::DEFAULT_REFLECT_RATIO));
        let small = minimal_response_port_request(TEST_TRANSACTION, 23480);
        let stats = ServerStats::default();
        let decision = decide_guarded(
            &small,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &context,
            TEST_SOFTWARE,
            &stats,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => {
                assert_eq!(error_details(&response).0, 400);
                assert!(
                    response.len() <= 40,
                    "the 400 is 40 bytes; it must not amplify either"
                );
            }
            other => panic!("expected a 400, got {other:?}"),
        }
        // A refusal counts both as a reflection rejection and as a dropped
        // request, like every other refusal path.
        assert_eq!(admission_of(&context).counters().reflect_rejected, 1);
        assert_eq!(stats.counters(), (0, 0, 1));

        // 40 bytes clears the raised floor; the 48-byte answer is still inside
        // max(80, 104).
        let big = forty_byte_response_port_request(TEST_TRANSACTION, 23480);
        assert_eq!(
            u16::from_be_bytes({
                let bytes = success_bytes(guarded(
                    &big,
                    "198.51.100.9:5000",
                    "127.0.0.1:3478",
                    Transport::Udp,
                    &context,
                ));
                [bytes[0], bytes[1]]
            }),
            protocol::BINDING_SUCCESS_RESPONSE
        );
    }

    #[test]
    fn reflection_guard_drops_when_even_a_400_would_amplify() {
        // A strict ratio (no allowance on the refusal path): the 40-byte 400 is
        // bigger than 28 x 0.5, so nothing is sent at all.
        let context = guarded_context(reflect_policy(40, 0.5));
        let stats = ServerStats::default();
        let decision = decide_guarded(
            &minimal_response_port_request(TEST_TRANSACTION, 23480),
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &context,
            TEST_SOFTWARE,
            &stats,
        )
        .unwrap();
        assert!(
            matches!(decision, Decision::Ignore(_)),
            "a refusal that would amplify must be silent, got {decision:?}"
        );
        assert_eq!(admission_of(&context).counters().reflect_rejected, 1);
        assert_eq!(stats.counters(), (0, 0, 1));
    }

    #[test]
    fn padding_plus_response_port_refusal_goes_through_the_guard() {
        // RFC 5780 §6 already refuses PADDING + RESPONSE-PORT with a 400. With
        // the guard on that refusal is produced by `reflection_refusal` — so it
        // is counted, and it is subject to the same "a refusal must not
        // amplify" rule.
        let port = 23480_u16;
        let request = request_with_attributes(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_RESPONSE_PORT, &port.to_be_bytes()),
                (protocol::ATTR_PADDING, &[0_u8; 4]),
            ],
        );
        assert_eq!(request.len(), 36);

        let context = guarded_context(reflect_policy(20, limit::DEFAULT_REFLECT_RATIO));
        let stats = ServerStats::default();
        let decision = decide_guarded(
            &request,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &context,
            TEST_SOFTWARE,
            &stats,
        )
        .unwrap();
        match decision {
            Decision::Respond(response) => assert_eq!(error_details(&response).0, 400),
            other => panic!("expected the §6 400, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 1);
        assert_eq!(stats.counters(), (0, 0, 1));

        // With a ratio that cannot afford the 400 the combination is dropped.
        let strict = guarded_context(reflect_policy(20, 0.5));
        assert!(matches!(
            guarded(
                &request,
                "198.51.100.9:5000",
                "127.0.0.1:3478",
                Transport::Udp,
                &strict
            ),
            Decision::Ignore(_)
        ));
    }

    #[test]
    fn change_request_is_only_gated_when_a_plan_exists() {
        // Without --alt-listen a CHANGE-REQUEST cannot move the answer to
        // another address (we hold none), so it is not a reflection vector and
        // must not be refused for its size.
        let request = change_request(TEST_TRANSACTION, protocol::CHANGE_IP);
        assert_eq!(request.len(), 28);
        let without_plan = guarded_context(reflect_policy(40, limit::DEFAULT_REFLECT_RATIO));
        match guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &without_plan,
        ) {
            Decision::Respond(response) => assert_binding_success(
                &response,
                TEST_TRANSACTION,
                "198.51.100.9:5000".parse().unwrap(),
            ),
            other => panic!("CHANGE-REQUEST without a plan must be answered, got {other:?}"),
        }
        assert_eq!(admission_of(&without_plan).counters().reflect_rejected, 0);

        // With a plan the same probe can move the source, so the size floor
        // applies.
        let with_plan = alt_listen_context(reflect_policy(40, limit::DEFAULT_REFLECT_RATIO));
        match guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &with_plan,
        ) {
            Decision::Respond(response) => assert_eq!(error_details(&response).0, 400),
            other => panic!("a 28-byte CHANGE-REQUEST with a plan must be refused, got {other:?}"),
        }
        assert_eq!(admission_of(&with_plan).counters().reflect_rejected, 1);
    }

    #[test]
    fn reflection_guard_exempts_allowlisted_sources() {
        // `--allow` says "these sources are mine": they are exempt from the
        // amplification rules, which is the documented way to keep a probing
        // network (or the monitoring host) working with a strict guard.
        let context = guarded_context(limit::Policy {
            reflect: Some(limit::Reflect {
                min_request: 40,
                ratio: 0.1,
            }),
            allow: vec!["198.51.100.0/24".parse().unwrap()],
            ..limit::Policy::default()
        });
        let request = minimal_response_port_request(TEST_TRANSACTION, 23480);
        match guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &context,
        ) {
            Decision::RespondFrom { to, .. } => assert_eq!(to.port(), 23480),
            other => panic!("an allowlisted source must not be gated, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 0);

        // A source outside the block is still gated by the same policy; at ratio
        // 0.1 even the 40-byte 400 would amplify, so the datagram is dropped.
        match guarded(
            &request,
            "203.0.113.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &context,
        ) {
            Decision::Ignore(reason) => assert!(reason.contains("reflection guard")),
            other => panic!("a non-allowlisted source must be gated, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 1);
    }

    #[test]
    fn reflection_guard_ignores_plain_binding_and_the_tcp_path() {
        let context = guarded_context(reflect_policy(40, 0.1));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();

        // A 20-byte plain Binding request has no redirect attribute: it must not
        // be caught by the size rule (that would break every normal client).
        let plain = binding_request(TEST_TRANSACTION);
        assert_eq!(plain.len(), 20);
        match guarded(
            &plain,
            &peer.to_string(),
            &local.to_string(),
            Transport::Udp,
            &context,
        ) {
            Decision::Respond(response) => {
                assert_binding_success(&response, TEST_TRANSACTION, peer)
            }
            other => panic!("plain Binding must still be answered, got {other:?}"),
        }

        // Over TCP a redirect attribute cannot reflect onto a third party (the
        // answer stays on the connection), so the probe is answered in-band.
        let tcp_probe = minimal_response_port_request(TEST_TRANSACTION, 23480);
        match guarded(
            &tcp_probe,
            &peer.to_string(),
            &local.to_string(),
            Transport::Tcp,
            &context,
        ) {
            Decision::Respond(response) => {
                assert_binding_success(&response, TEST_TRANSACTION, peer)
            }
            other => panic!("TCP must answer in-band, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 0);
    }

    #[test]
    fn enabled_guard_leaves_plain_answers_byte_identical() {
        // 「开启准入 ≠ 改协议」：同一请求，开了限速得到的字节必须与关闭时一致。
        let request = binding_request([0x92; 12]);
        let peer: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let plain = match decide(
            &request,
            peer,
            local,
            Transport::Udp,
            &ServerContext::default(),
            TEST_SOFTWARE,
        )
        .unwrap()
        {
            Decision::Respond(bytes) => bytes,
            other => panic!("expected a response, got {other:?}"),
        };
        let guarded_context = guarded_context(limit::Policy {
            per_ip: Some(limit::Rate::new(100.0, 100.0)),
            ..limit::Policy::default()
        });
        let guarded_bytes = match guarded(
            &request,
            &peer.to_string(),
            &local.to_string(),
            Transport::Udp,
            &guarded_context,
        ) {
            Decision::Respond(bytes) => bytes,
            other => panic!("expected a response, got {other:?}"),
        };
        assert_eq!(guarded_bytes, plain);
    }

    /// Drain whatever a socket has received within `window`.
    async fn drain(socket: &UdpSocket, window: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + window;
        let mut buffer = [0_u8; 512];
        let mut received = 0;
        while let Ok(Ok(_)) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
        {
            received += 1;
        }
        received
    }

    #[tokio::test]
    async fn rate_limit_drops_the_flooding_source_and_spares_another() {
        let socket = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = socket.local_addr().unwrap();
        let admission = limit::Admission::new(limit::Policy {
            per_ip: Some(limit::Rate::new(1.0, 3.0)),
            ..limit::Policy::default()
        })
        .unwrap();
        let context = Arc::new(ServerContext {
            plan: None,
            udp: vec![(address, socket.clone())],
            mapped_address: false,
            admission: Some(admission.clone()),
            fingerprint: None,
            alternate_server: None,
            auth: None,
        });
        let stats = Arc::new(ServerStats::default());
        tokio::spawn(serve_udp(
            socket,
            context,
            Arc::from(TEST_SOFTWARE),
            stats.clone(),
        ));

        let flooder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A second loopback source: 127.0.0.0/8 is local on Linux/macOS. If the
        // sandbox refuses it, skip instead of failing on the environment.
        let Ok(neighbour) = UdpSocket::bind("127.0.0.2:0").await else {
            eprintln!("skipping rate-limit e2e: cannot bind 127.0.0.2");
            return;
        };

        for _ in 0..20 {
            flooder
                .send_to(&binding_request([0x90; 12]), address)
                .await
                .unwrap();
        }
        let answered = drain(&flooder, Duration::from_millis(300)).await;
        assert!(
            (1..=6).contains(&answered),
            "a 3-token burst should answer a handful of 20 requests, got {answered}"
        );
        assert!(
            admission.counters().rate_limited_ip >= 14,
            "the rest must be counted as rate limited: {:?}",
            admission.counters()
        );

        // The other source has its own bucket and is not collateral damage.
        neighbour
            .send_to(&binding_request([0x91; 12]), address)
            .await
            .unwrap();
        let mut buffer = [0_u8; 512];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), neighbour.recv_from(&mut buffer))
                .await
                .expect("another source must still be answered")
                .unwrap();
        assert_eq!(from, address);
        assert_binding_success(&buffer[..len], [0x91; 12], neighbour.local_addr().unwrap());
        assert_eq!(stats.counters().1, answered as u64 + 1);
    }

    #[tokio::test]
    async fn max_inflight_actually_drops_udp_datagrams() {
        // Regression: the serial receive loop holds at most one permit, so a cap
        // above 1 could never trigger and `--max-inflight` was a no-op over UDP.
        // With the cap set, each datagram is handed to its own task while it
        // holds a permit — so the cap is reachable and the excess is counted.
        let socket = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = socket.local_addr().unwrap();
        let admission = limit::Admission::new(limit::Policy {
            max_inflight: Some(1),
            ..limit::Policy::default()
        })
        .unwrap();
        let context = Arc::new(ServerContext {
            plan: None,
            udp: vec![(address, socket.clone())],
            mapped_address: false,
            admission: Some(admission.clone()),
            fingerprint: None,
            alternate_server: None,
            auth: None,
        });
        let stats = Arc::new(ServerStats::default());
        tokio::spawn(serve_udp(
            socket,
            context,
            Arc::from(TEST_SOFTWARE),
            stats.clone(),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..300 {
            client
                .send_to(&binding_request([0x96; 12]), address)
                .await
                .unwrap();
        }
        let answered = drain(&client, Duration::from_millis(500)).await;
        // `#[tokio::test]` runs on a current-thread runtime: the spawned
        // handlers only get polled when the receive loop yields, so the single
        // slot is still held for the following datagrams — the excess must be
        // refused *and counted*, not silently serialised.
        assert!(
            answered < 300,
            "a one-slot cap must refuse some of the 300 datagrams (answered {answered})"
        );
        assert!(
            admission.counters().inflight_dropped > 0,
            "the cap must show up in the counters: {:?}",
            admission.counters()
        );

        // The cap is not a latch: once the queue settles a new request is served.
        let _ = drain(&client, Duration::from_millis(200)).await;
        client
            .send_to(&binding_request([0x97; 12]), address)
            .await
            .unwrap();
        let mut buffer = [0_u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
            .await
            .expect("the server must recover once permits are released")
            .unwrap();
        assert_binding_success(&buffer[..len], [0x97; 12], client.local_addr().unwrap());
    }

    #[tokio::test]
    async fn deny_list_refuses_one_source_without_touching_the_other() {
        let socket = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = socket.local_addr().unwrap();
        let context = Arc::new(ServerContext {
            plan: None,
            udp: vec![(address, socket.clone())],
            mapped_address: false,
            admission: Some(
                limit::Admission::new(limit::Policy {
                    deny: vec!["127.0.0.1/32".parse().unwrap()],
                    ..limit::Policy::default()
                })
                .unwrap(),
            ),
            fingerprint: None,
            alternate_server: None,
            auth: None,
        });
        let stats = Arc::new(ServerStats::default());
        tokio::spawn(serve_udp(
            socket,
            context.clone(),
            Arc::from(TEST_SOFTWARE),
            stats.clone(),
        ));

        let Ok(denied) = UdpSocket::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(allowed) = UdpSocket::bind("127.0.0.2:0").await else {
            eprintln!("skipping deny-list e2e: cannot bind 127.0.0.2");
            return;
        };
        denied
            .send_to(&binding_request([0x92; 12]), address)
            .await
            .unwrap();
        assert_eq!(
            drain(&denied, Duration::from_millis(300)).await,
            0,
            "--deny 127.0.0.1/32 must drop the request outright"
        );

        allowed
            .send_to(&binding_request([0x93; 12]), address)
            .await
            .unwrap();
        let mut buffer = [0_u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), allowed.recv_from(&mut buffer))
            .await
            .expect("a source outside --deny must be answered")
            .unwrap();
        assert_binding_success(&buffer[..len], [0x93; 12], allowed.local_addr().unwrap());
        assert_eq!(stats.counters(), (2, 1, 1));
    }

    // ---------- 协议闭环（FINGERPRINT / 300 / 500） ----------

    /// A request whose `FINGERPRINT` (RFC 5389 §15.5) is the last attribute.
    fn request_with_fingerprint(transaction_id: [u8; 12], attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut bytes = request_with_attributes(transaction_id, attributes);
        // The header Length must already include the 8-byte attribute before the
        // CRC is computed (RFC 5389 §15.5), so set it first, then checksum.
        let body_len = (bytes.len() - HEADER_LEN + 8) as u16;
        bytes[2..4].copy_from_slice(&body_len.to_be_bytes());
        let value = protocol::fingerprint_value(&bytes);
        bytes.extend_from_slice(&protocol::ATTR_FINGERPRINT.to_be_bytes());
        bytes.extend_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(&value.to_be_bytes());
        bytes
    }

    /// Append one zero-valued attribute *after* an existing FINGERPRINT.
    fn append_attribute(mut request: Vec<u8>, attr_type: u16) -> Vec<u8> {
        let grown = u16::from_be_bytes([request[2], request[3]]) + 4;
        request[2..4].copy_from_slice(&grown.to_be_bytes());
        request.extend_from_slice(&attr_type.to_be_bytes());
        request.extend_from_slice(&0_u16.to_be_bytes());
        request
    }

    fn protocol_context(
        fingerprint: Option<FingerprintAction>,
        alternate_server: Option<SocketAddr>,
    ) -> ServerContext {
        ServerContext {
            fingerprint,
            alternate_server,
            ..ServerContext::default()
        }
    }

    /// A UDP server whose only configuration is the protocol-closure feature
    /// under test (no plan, no guard): the bytes are the frozen default ones.
    async fn udp_server_with_protocol(
        fingerprint: Option<FingerprintAction>,
        alternate_server: Option<SocketAddr>,
    ) -> (SocketAddr, Arc<ServerStats>) {
        let socket = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = socket.local_addr().unwrap();
        let context = Arc::new(ServerContext {
            udp: vec![(address, socket.clone())],
            ..protocol_context(fingerprint, alternate_server)
        });
        let stats = Arc::new(ServerStats::default());
        tokio::spawn(serve_udp(
            socket,
            context,
            Arc::from(TEST_SOFTWARE),
            stats.clone(),
        ));
        (address, stats)
    }

    #[test]
    fn fingerprint_check_is_off_and_the_action_needs_it() {
        assert_eq!(fingerprint_policy(&Args::default()), Ok(None));

        let cli = Cli::try_parse_from(["rstun", "server", "--check-fingerprint"]).unwrap();
        let Command::Server(args) = cli.command;
        assert_eq!(
            fingerprint_policy(&args),
            Ok(Some(FingerprintAction::Answer))
        );

        let cli = Cli::try_parse_from([
            "rstun",
            "server",
            "--check-fingerprint",
            "--fingerprint-action",
            "drop",
        ])
        .unwrap();
        let Command::Server(args) = cli.command;
        assert_eq!(fingerprint_policy(&args), Ok(Some(FingerprintAction::Drop)));

        // A `drop` action without the switch would be a silent no-op: refused.
        let cli = Cli::try_parse_from(["rstun", "server", "--fingerprint-action", "drop"]).unwrap();
        let Command::Server(args) = cli.command;
        let error = fingerprint_policy(&args).unwrap_err();
        assert!(error.contains("--check-fingerprint"), "{error}");
        // An unknown action is a clap usage error, not a silent default.
        assert!(
            Cli::try_parse_from(["rstun", "server", "--fingerprint-action", "explode"]).is_err()
        );
    }

    #[tokio::test]
    async fn fingerprint_five_states_over_udp() {
        let (address, stats) =
            udp_server_with_protocol(Some(FingerprintAction::Answer), None).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transaction_id = [0xa1; 12];
        let valid = request_with_fingerprint(transaction_id, &[]);
        assert_eq!(valid.len(), HEADER_LEN + 8);

        // 1) Correct fingerprint -> the ordinary Binding success.
        let (response, _) = udp_exchange(&client, address, &valid).await;
        assert_binding_success(&response, transaction_id, client.local_addr().unwrap());
        assert_eq!(stats.fingerprint_rejected(), 0);

        // 2) Wrong CRC -> 400 Bad Request (not a success, not silence).
        let mut mismatch = valid.clone();
        let last = mismatch.len() - 1;
        mismatch[last] ^= 0xff;
        let (response, _) = udp_exchange(&client, address, &mismatch).await;
        assert_eq!(error_details(&response).0, 400);
        assert_eq!(stats.fingerprint_rejected(), 1);
        assert_eq!(stats.counters(), (2, 2, 0));

        // 3) FINGERPRINT followed by another attribute -> 400, even though the
        //    CRC bytes themselves would still be right for that prefix.
        let misplaced = append_attribute(valid.clone(), protocol::ATTR_PADDING);
        let (response, _) = udp_exchange(&client, address, &misplaced).await;
        assert_eq!(error_details(&response).0, 400);
        assert_eq!(stats.fingerprint_rejected(), 2);

        // 4) `--fingerprint-action drop`: the same wrong CRC gets no answer,
        //    but is counted (both as a drop and as a fingerprint rejection).
        let (drop_address, drop_stats) =
            udp_server_with_protocol(Some(FingerprintAction::Drop), None).await;
        client.send_to(&mismatch, drop_address).await.unwrap();
        let mut buffer = [0_u8; 256];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer))
                .await
                .is_err(),
            "drop mode must stay silent"
        );
        assert_eq!(drop_stats.counters(), (1, 0, 1));
        assert_eq!(drop_stats.fingerprint_rejected(), 1);

        // 5) Default (switch off): a broken FINGERPRINT is ignored and the
        //    response is byte-identical to the one for a bare request.
        let (plain_address, plain_stats) = udp_server_with_protocol(None, None).await;
        let (response, _) = udp_exchange(&client, plain_address, &mismatch).await;
        assert_binding_success(&response, transaction_id, client.local_addr().unwrap());
        let (bare, _) =
            udp_exchange(&client, plain_address, &binding_request(transaction_id)).await;
        assert_eq!(response, bare, "the attribute must not change any byte");
        assert_eq!(plain_stats.fingerprint_rejected(), 0);
    }

    #[test]
    fn fingerprint_guard_uses_the_request_method_in_the_400() {
        // A non-Binding request with a broken FINGERPRINT keeps its own method in
        // the error response (RFC 5389 §7.3.1), like every other 400.
        let mut request = request_with_fingerprint([0xa2; 12], &[]);
        request[0..2].copy_from_slice(&0x0003_u16.to_be_bytes());
        let context = protocol_context(Some(FingerprintAction::Answer), None);
        match guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &context,
        ) {
            Decision::Respond(response) => {
                let msg_type = u16::from_be_bytes([response[0], response[1]]);
                assert_eq!(msg_type, 0x0113, "Allocate error response");
                assert_eq!(error_details(&response).0, 400);
            }
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn alternate_server_answers_every_binding_with_300() {
        let server: SocketAddr = "192.0.2.9:3478".parse().unwrap();
        let (address, stats) = udp_server_with_protocol(None, Some(server)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Plain Binding *and* a redirect probe: the 300 wins over RFC 5780 and
        // always leaves from the socket that received the request.
        for request in [
            binding_request([0xb1; 12]),
            change_request([0xb2; 12], protocol::CHANGE_PORT),
        ] {
            let (response, from) = udp_exchange(&client, address, &request).await;
            assert_eq!(from, address, "redirect must not move the source");
            assert_eq!(
                u16::from_be_bytes([response[0], response[1]]),
                protocol::BINDING_ERROR_RESPONSE
            );
            let (code, unknown) = error_details(&response);
            assert_eq!(code, 300);
            assert!(unknown.is_empty());
            let message = protocol::parse(&response).unwrap();
            let alternate = protocol::attributes(message.body)
                .find(|attribute| attribute.attr_type == protocol::ATTR_ALTERNATE_SERVER)
                .expect("ALTERNATE-SERVER");
            assert_eq!(
                protocol::decode_address_value(alternate.value),
                Some(server)
            );
            // A redirect answer carries no mapped address: it is not an answer
            // *about* the peer, it is an instruction.
            assert!(
                protocol::attributes(message.body)
                    .all(|attribute| attribute.attr_type != ATTR_XOR_MAPPED_ADDRESS)
            );
        }
        assert_eq!(stats.counters(), (2, 2, 0));
    }

    #[test]
    fn alternate_server_keeps_400_for_other_methods_and_takes_the_first_address() {
        let server: SocketAddr = "192.0.2.9:3478".parse().unwrap();
        let context = protocol_context(None, Some(server));

        // Non-Binding methods keep their 400 (a redirect would not be an answer).
        let mut allocate = binding_request([0xb3; 12]);
        allocate[0..2].copy_from_slice(&0x0003_u16.to_be_bytes());
        match decide(
            &allocate,
            "198.51.100.9:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
            Transport::Udp,
            &context,
            TEST_SOFTWARE,
        )
        .unwrap()
        {
            Decision::Respond(response) => assert_eq!(error_details(&response).0, 400),
            other => panic!("expected a 400, got {other:?}"),
        }

        // Repeated flag: the first address wins (the rest are warned about).
        let cli = Cli::try_parse_from([
            "rstun",
            "server",
            "--alternate-server",
            "192.0.2.9:3478",
            "--alternate-server",
            "192.0.2.10:3478",
        ])
        .unwrap();
        let Command::Server(args) = cli.command;
        assert_eq!(
            alternate_server(&args),
            Some("192.0.2.9:3478".parse().unwrap())
        );
    }

    #[test]
    fn alternate_server_answer_is_what_the_reflection_guard_estimates() {
        // The guard must measure the answer it will actually send: with
        // `--alternate-server` that is the fixed 56-byte 300, not a success
        // response (which would be 76 bytes with --alt-listen and 52 plain).
        let context = ServerContext {
            alternate_server: Some("192.0.2.9:3478".parse().unwrap()),
            ..guarded_context(reflect_policy(20, limit::DEFAULT_REFLECT_RATIO))
        };
        let request = minimal_response_port_request(TEST_TRANSACTION, 23480);
        match guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &context,
        ) {
            Decision::Respond(bytes) => {
                assert_eq!(error_details(&bytes).0, 300);
                assert_eq!(bytes.len(), 56);
                assert!(
                    limit::Reflect {
                        min_request: 20,
                        ratio: limit::DEFAULT_REFLECT_RATIO,
                    }
                    .allows_response(request.len(), bytes.len())
                );
            }
            other => panic!("a 28-byte probe must still get the 300, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 0);
    }

    #[test]
    fn server_error_mapping_only_covers_internal_failures() {
        use std::io::ErrorKind;

        // The client's address problem: the datagram never left (or can never
        // arrive), so claiming "server error" would be wrong and noisy.
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::NetworkUnreachable,
            ErrorKind::AddrNotAvailable,
        ] {
            assert_eq!(
                server_error_for(&std::io::Error::from(kind)),
                None,
                "{kind:?} must not map to 500"
            );
        }
        // Everything else is a failure on our side of the send.
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::PermissionDenied,
            ErrorKind::BrokenPipe,
            ErrorKind::TimedOut,
            ErrorKind::WouldBlock,
            ErrorKind::Other,
        ] {
            assert_eq!(
                server_error_for(&std::io::Error::from(kind)),
                Some(protocol::ERROR_SERVER_ERROR),
                "{kind:?} must map to 500"
            );
        }
    }

    #[tokio::test]
    async fn server_error_answer_is_forty_bytes_with_the_transaction_id() {
        let server = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let local = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client.local_addr().unwrap();
        let request = binding_request([0xc1; 12]);
        let stats = ServerStats::default();

        send_server_error(
            &server,
            local,
            peer,
            &request,
            &stats,
            protocol::ERROR_SERVER_ERROR,
        )
        .await;

        let mut buffer = [0_u8; 256];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                .await
                .expect("500 was not delivered")
                .unwrap();
        assert_eq!(from, local);
        let response = &buffer[..len];
        assert_eq!(response.len(), 40, "500 must stay a fixed 40 bytes");
        assert_eq!(&response[8..20], &[0xc1; 12]);
        let (code, unknown) = error_details(response);
        assert_eq!(code, 500);
        assert!(unknown.is_empty());
        assert_eq!(stats.counters(), (0, 1, 0));
    }

    #[test]
    fn wire_invariants_and_the_server_error_builder() {
        let transaction_id = protocol::TransactionId([0xd1; 12]);
        let good = protocol::server_error_response(&transaction_id, protocol::BINDING_REQUEST);
        assert!(response_is_encodable(&good));

        // Anything that is not a complete STUN frame is refused before sending.
        assert!(!response_is_encodable(&[]));
        assert!(!response_is_encodable(&[0_u8; protocol::HEADER_LEN - 1]));
        let mut wrong_length = good.clone();
        wrong_length[2..4].copy_from_slice(&0_u16.to_be_bytes());
        assert!(!response_is_encodable(&wrong_length));
        let mut truncated = good.clone();
        truncated.pop();
        assert!(!response_is_encodable(&truncated));

        // The 500 builder needs only a parseable frame, and its bytes are the
        // fixed `Server Error` response (no internal detail can ride along).
        let request = binding_request([0xd2; 12]);
        assert_eq!(
            server_error_bytes(&request, protocol::ERROR_SERVER_ERROR),
            Some(protocol::server_error_response(
                &protocol::TransactionId([0xd2; 12]),
                protocol::BINDING_REQUEST
            ))
        );
        assert_eq!(
            server_error_bytes(b"not stun", protocol::ERROR_SERVER_ERROR),
            None
        );
    }

    /// A real failed `send_to`: the kernel refuses destination port 0 (EINVAL),
    /// so `server_error_for` maps it to 500 and the client sees the error answer
    /// instead of dead air. Linux-only because the errno is what makes it
    /// deterministic; elsewhere the mapping is covered by the table test.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn udp_send_failure_answers_500_server_error() {
        let (_server, address, stats) = udp_server().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transaction_id = [0xc2; 12];
        let request = request_with_attribute(
            transaction_id,
            protocol::ATTR_RESPONSE_PORT,
            &0_u16.to_be_bytes(),
        );
        client.send_to(&request, address).await.unwrap();

        let mut buffer = [0_u8; 512];
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
                .await
                .expect("a failed send_to must be answered with 500")
                .unwrap();
        assert_eq!(from, address);
        let (code, unknown) = error_details(&buffer[..len]);
        assert_eq!(code, 500);
        assert!(unknown.is_empty());
        assert_eq!(stats.counters(), (1, 1, 0));
    }

    // ---------- CLI ----------

    #[test]
    fn legacy_mode_defaults_to_the_wildcard_and_no_plan() {
        let (addresses, plan) = resolve_listen(&Args::default()).unwrap();
        assert_eq!(
            addresses,
            vec![SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT))]
        );
        assert_eq!(plan, None);
    }

    #[test]
    fn alt_listen_builds_the_four_socket_plan() {
        let args = Args {
            listen: vec!["203.0.113.5:3478".parse().unwrap()],
            alt_listen: Some("203.0.113.50:3478".parse().unwrap()),
            alt_port: Some(3479),
            ..Args::default()
        };
        let (addresses, plan) = resolve_listen(&args).unwrap();
        assert_eq!(
            addresses,
            vec!["203.0.113.5:3478".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            plan.unwrap().sockets(),
            [
                "203.0.113.5:3478".parse().unwrap(),
                "203.0.113.50:3478".parse().unwrap(),
                "203.0.113.5:3479".parse().unwrap(),
                "203.0.113.50:3479".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn wildcard_listen_is_refused_when_rfc5780_is_enabled() {
        // 0.0.0.0 cannot answer "which address did this arrive on?" when every
        // address is its own socket: the fix is to write the concrete IP, and the
        // error has to say so (no silent downgrade to plain RFC 5389).
        for wildcard in ["0.0.0.0:3478", "[::]:3478"] {
            let args = Args {
                listen: vec![wildcard.parse().unwrap()],
                alt_listen: Some("203.0.113.50:3478".parse().unwrap()),
                ..Args::default()
            };
            let error = resolve_listen(&args).unwrap_err();
            assert!(error.contains("concrete --listen"), "{wildcard}: {error}");
        }
    }

    #[test]
    fn alt_listen_takes_the_first_ipv4_listen_in_cli_order() {
        // CLI 顺序是 `.8` 在前、`.5` 在后；绑定用的列表会排成 `.5, .8`。
        // 所以「primary == .8」只有在**取原始顺序**时才成立 —— 这条正好锁住
        // resolve_listen 不能先 sort 再选 primary。
        let args = Args {
            listen: vec![
                "192.0.2.8:3478".parse().unwrap(),
                "192.0.2.5:3478".parse().unwrap(),
            ],
            alt_listen: Some("192.0.2.7:3478".parse().unwrap()),
            alt_port: Some(3479),
            ..Args::default()
        };
        let (addresses, plan) = resolve_listen(&args).unwrap();
        let plan = plan.expect("--alt-listen 应当启用 RFC 5780");
        assert_eq!(
            plan.primary,
            "192.0.2.8:3478".parse::<SocketAddr>().unwrap()
        );
        // 所有 --listen 都留在绑定列表里（排序去重），但只有四 socket 参与 5780。
        assert_eq!(
            addresses,
            vec![
                "192.0.2.5:3478".parse::<SocketAddr>().unwrap(),
                "192.0.2.8:3478".parse::<SocketAddr>().unwrap(),
            ]
        );
        assert_eq!(
            plan.sockets(),
            [
                "192.0.2.8:3478".parse().unwrap(),
                "192.0.2.7:3478".parse().unwrap(),
                "192.0.2.8:3479".parse().unwrap(),
                "192.0.2.7:3479".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn alt_listen_ignores_listen_v6_when_picking_the_primary() {
        let args = Args {
            listen: vec!["192.0.2.5:3478".parse().unwrap()],
            listen_v6: vec!["[::]:3478".parse().unwrap()],
            alt_listen: Some("192.0.2.7:3478".parse().unwrap()),
            alt_port: Some(3479),
            ..Args::default()
        };
        let (addresses, plan) = resolve_listen(&args).unwrap();
        assert_eq!(
            plan.unwrap().primary,
            "192.0.2.5:3478".parse::<SocketAddr>().unwrap()
        );
        // v6 仍在绑定列表里（只做普通 Binding），没有被 5780 吃掉。
        assert!(
            addresses.contains(&"[::]:3478".parse::<SocketAddr>().unwrap()),
            "{addresses:?}"
        );
    }

    #[test]
    fn alt_listen_without_any_ipv4_listen_is_refused() {
        let args = Args {
            listen_v6: vec!["[::]:3478".parse().unwrap()],
            alt_listen: Some("192.0.2.7:3478".parse().unwrap()),
            ..Args::default()
        };
        let error = resolve_listen(&args).unwrap_err();
        assert!(error.contains("IPv4"), "{error}");
        assert!(error.contains("--listen-v6"), "{error}");
    }

    #[test]
    fn alt_listen_with_only_the_default_wildcard_still_says_concrete() {
        // 完全没给 --listen/--listen-v6 → 默认补 `0.0.0.0:3478`：错误必须仍是
        // 「wildcard 不能配 5780」，不能退化成「缺地址」之类的另一条消息。
        let args = Args {
            alt_listen: Some("192.0.2.7:3478".parse().unwrap()),
            ..Args::default()
        };
        let error = resolve_listen(&args).unwrap_err();
        assert!(error.contains("concrete --listen"), "{error}");
    }

    #[test]
    fn alt_listen_on_the_same_ip_is_still_refused() {
        let args = Args {
            listen: vec!["192.0.2.5:3478".parse().unwrap()],
            alt_listen: Some("192.0.2.5:3478".parse().unwrap()),
            ..Args::default()
        };
        let error = resolve_listen(&args).unwrap_err();
        assert!(error.contains("second IP"), "{error}");
    }

    #[test]
    fn alt_port_without_alt_listen_is_refused() {
        let args = Args {
            alt_port: Some(3479),
            ..Args::default()
        };
        let error = resolve_listen(&args).unwrap_err();
        assert!(error.contains("--alt-listen"), "{error}");
    }

    // ----- authentication (RFC 5389 §10 / RFC 8489 §9.2) -----

    /// A long-term context with one user `user:pass` in realm `example.org`.
    fn long_term_auth(require_sha256: bool) -> auth::Auth {
        auth::Auth::long_term(
            "example.org".to_string(),
            b"nonce-secret".to_vec(),
            vec![auth::User {
                username: "user".to_string(),
                password: "pass".to_string(),
            }],
            Duration::from_secs(auth::DEFAULT_NONCE_LIFETIME),
            require_sha256,
        )
    }

    fn with_auth(auth: auth::Auth) -> ServerContext {
        ServerContext {
            auth: Some(auth),
            ..ServerContext::default()
        }
    }

    // ----- TURN configuration (prd R2 / R5) -----

    #[test]
    fn turn_requires_long_term_credentials() {
        // No credentials at all.
        let args = Args {
            turn: true,
            ..Args::default()
        };
        assert!(build_turn(&args, None).is_err());

        // Short-term credentials are not enough.
        let short = auth::Auth::short_term(vec![auth::User {
            username: "user".to_string(),
            password: "pass".to_string(),
        }]);
        assert!(build_turn(&args, Some(&short)).is_err());

        // Long-term credentials enable the defaults.
        let long = long_term_auth(false);
        let config = build_turn(&args, Some(&long)).unwrap().expect("enabled");
        assert_eq!(config.relay_ports, turn::DEFAULT_RELAY_PORTS);
        assert_eq!(
            config.max_allocations_per_user,
            turn::DEFAULT_MAX_ALLOCATIONS_PER_USER
        );
    }

    #[test]
    fn turn_flags_need_turn_and_config_is_validated() {
        let long = long_term_auth(false);
        // TURN-only flags without --turn are a startup error, not a no-op.
        let args = Args {
            relay_ports: Some("5000-5001".to_string()),
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_err());

        // RFC 6062's switch is a TURN flag too.
        let args = Args {
            turn_tcp_relay: true,
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_err());

        let args = Args {
            turn: true,
            turn_tcp_relay: true,
            ..Args::default()
        };
        let config = build_turn(&args, Some(&long)).unwrap().expect("enabled");
        assert!(config.tcp_relay);

        let args = Args {
            turn: true,
            relay_ports: Some("6000-5000".to_string()),
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_err());

        let args = Args {
            turn: true,
            max_allocations_per_user: Some(0),
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_err());

        let args = Args {
            turn: true,
            allocation_lifetime: Some(u64::MAX),
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_err());
    }

    #[test]
    fn turn_t2_flags_are_validated_before_serving() {
        let long = long_term_auth(false);
        // T2-only flags without --turn: refused (same rule as the T1 flags).
        for args in [
            Args {
                turn_bandwidth: Some(0),
                ..Args::default()
            },
            Args {
                turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
                ..Args::default()
            },
            Args {
                turn_dtls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
                ..Args::default()
            },
            Args {
                tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
                tls_key: Some(PathBuf::from("/tmp/key.pem")),
                ..Args::default()
            },
            Args {
                rest_secret: Some("secret".to_string()),
                ..Args::default()
            },
        ] {
            assert!(build_turn(&args, Some(&long)).is_err());
        }

        // Bandwidth is a transport-independent knob: the lean build accepts it.
        let args = Args {
            turn: true,
            turn_bandwidth: Some(4096),
            ..Args::default()
        };
        let config = build_turn(&args, Some(&long)).unwrap().expect("enabled");
        assert_eq!(config.bandwidth, 4096);
    }

    /// Material handling only exists when the transport was compiled in; the
    /// lean build's answer to these flags is the feature error (next test).
    #[cfg(feature = "tls")]
    #[test]
    fn tls_flags_need_certificate_material() {
        let long = long_term_auth(false);
        // A listener without material is a refused start, never a silent
        // plaintext fallback (design §3.2).
        let args = Args {
            turn: true,
            turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
            ..Args::default()
        };
        let message = build_turn(&args, Some(&long)).unwrap_err();
        assert!(message.contains("--tls-cert"), "{message}");
        let args = Args {
            turn: true,
            turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
            tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_err(), "--tls-cert alone");
        let args = Args {
            turn: true,
            tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            tls_key: Some(PathBuf::from("/tmp/key.pem")),
            ..Args::default()
        };
        assert!(
            build_turn(&args, Some(&long)).is_err(),
            "material without a listener is a half configuration"
        );
        // With --turn, each half of a TLS pair alone is still an error.
        let args = Args {
            turn: true,
            turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
            tls_key: Some(PathBuf::from("/tmp/key.pem")),
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_err(), "--tls-key alone");

        // The complete pair is accepted and reaches the TURN config.
        #[cfg(feature = "dtls")]
        let turn_dtls_listen = vec!["127.0.0.1:5350".parse().unwrap()];
        #[cfg(not(feature = "dtls"))]
        let turn_dtls_listen = Vec::new();
        let args = Args {
            turn: true,
            turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
            turn_dtls_listen,
            tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            tls_key: Some(PathBuf::from("/tmp/key.pem")),
            turn_bandwidth: Some(4096),
            ..Args::default()
        };
        let config = build_turn(&args, Some(&long)).unwrap().expect("enabled");
        assert_eq!(config.bandwidth, 4096);
    }

    /// `--tls-cert-poll`: default 30 s, `0` = SIGHUP only (no poll interval at
    /// all), any positive value is taken verbatim. `0` is the "no polling task"
    /// contract: the reloader gets `None` and its timer arm never fires.
    #[test]
    fn cert_poll_interval_defaults_to_30s_and_can_be_disabled() {
        assert_eq!(
            cert_poll_interval(None, true, true).unwrap(),
            Some(Duration::from_secs(30)),
            "not passed → the documented 30 s default"
        );
        assert_eq!(
            cert_poll_interval(None, true, false).unwrap(),
            Some(CERT_POLL_INTERVAL),
            "the default is build- and platform-independent"
        );
        assert_eq!(
            cert_poll_interval(Some(0), true, true).unwrap(),
            None,
            "0 = no polling task; SIGHUP is the only trigger"
        );
        assert_eq!(
            cert_poll_interval(Some(2), true, true).unwrap(),
            Some(Duration::from_secs(2)),
            "a positive value is the interval, in seconds"
        );
    }

    /// The two half configurations: a poll interval with no `turns:`/DTLS
    /// listener would never take effect, and `0` where there is no `SIGHUP`
    /// (Windows) would leave a certificate that can never rotate.
    #[test]
    fn cert_poll_needs_a_secure_listener_and_a_signal_source() {
        for seconds in [Some(0), Some(2), Some(30)] {
            let error = cert_poll_interval(seconds, false, true).unwrap_err();
            assert!(
                error.contains("--tls-cert-poll") && error.contains("--turn-tls-listen"),
                "{error}"
            );
        }

        let error = cert_poll_interval(Some(0), true, false).unwrap_err();
        assert!(
            error.contains("--tls-cert-poll") && error.contains("SIGHUP"),
            "the error must say why 0 is refused there: {error}"
        );
        // Windows keeps rotating: a positive interval (and the default) works.
        assert_eq!(
            cert_poll_interval(Some(2), true, false).unwrap(),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            cert_poll_interval(None, true, false).unwrap(),
            Some(CERT_POLL_INTERVAL)
        );
    }

    /// `build_turn` is where the flag's half configurations are refused: a
    /// value with no secure listener, and any value without `--turn`.
    #[cfg(feature = "tls")]
    #[test]
    fn tls_cert_poll_needs_a_secure_listener() {
        let long = long_term_auth(false);
        for seconds in [0, 2] {
            let args = Args {
                turn: true,
                tls_cert_poll: Some(seconds),
                ..Args::default()
            };
            let message = build_turn(&args, Some(&long)).unwrap_err();
            assert!(
                message.contains("--tls-cert-poll") && message.contains("--turn-tls-listen"),
                "poll {seconds}: {message}"
            );
        }

        // With a secure listener the value is accepted (the paths themselves
        // are only read at startup, so a placeholder pair is enough here).
        let args = Args {
            turn: true,
            turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
            tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            tls_key: Some(PathBuf::from("/tmp/key.pem")),
            tls_cert_poll: Some(2),
            ..Args::default()
        };
        assert!(build_turn(&args, Some(&long)).is_ok());
        let zero = Args {
            turn: true,
            turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
            tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
            tls_key: Some(PathBuf::from("/tmp/key.pem")),
            tls_cert_poll: Some(0),
            ..Args::default()
        };
        // `0` means "SIGHUP only", so it needs a platform that has SIGHUP.
        #[cfg(unix)]
        assert!(build_turn(&zero, Some(&long)).is_ok(), "0 on unix is legal");
        #[cfg(not(unix))]
        assert!(
            build_turn(&zero, Some(&long)).is_err(),
            "0 without SIGHUP would freeze the certificate"
        );

        // Without `--turn` it is one more TURN-only flag.
        let args = Args {
            tls_cert_poll: Some(30),
            ..Args::default()
        };
        let message = build_turn(&args, Some(&long)).unwrap_err();
        assert!(message.contains("--turn"), "{message}");
    }

    /// The lean build must not pretend: the flag exists (help is build-independent)
    /// but the start is refused with the feature name the operator has to build.
    #[cfg(not(feature = "tls"))]
    #[test]
    fn lean_build_refuses_tls_flags_with_the_feature_name() {
        let long = long_term_auth(false);
        for args in [
            Args {
                turn: true,
                turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
                ..Args::default()
            },
            Args {
                turn: true,
                tls_cert: Some(PathBuf::from("/tmp/cert.pem")),
                tls_key: Some(PathBuf::from("/tmp/key.pem")),
                turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
                ..Args::default()
            },
            Args {
                turn: true,
                tls_cert_poll: Some(0),
                turn_tls_listen: vec!["127.0.0.1:5349".parse().unwrap()],
                ..Args::default()
            },
        ] {
            let message = build_turn(&args, Some(&long)).unwrap_err();
            assert!(message.contains("`tls` feature"), "{message}");
            assert!(
                message.contains("--features tls,dtls"),
                "the error must say how to fix it: {message}"
            );
        }
    }

    #[cfg(not(feature = "dtls"))]
    #[test]
    fn build_without_dtls_refuses_dtls_listeners_with_the_feature_name() {
        let long = long_term_auth(false);
        let args = Args {
            turn: true,
            turn_dtls_listen: vec!["127.0.0.1:5350".parse().unwrap()],
            ..Args::default()
        };
        let message = build_turn(&args, Some(&long)).unwrap_err();
        assert!(message.contains("`dtls` feature"), "{message}");
        assert!(
            message.contains("--features tls,dtls"),
            "the error must say how to fix it: {message}"
        );
    }

    #[test]
    fn rest_credentials_need_realm_and_nonce_secret_but_no_stored_user() {
        // `--rest-secret` without `--realm` / `--auth-secret`: refused.
        let args = Args {
            rest_secret: Some("secret".to_string()),
            ..Args::default()
        };
        assert!(build_auth(&args).is_err());

        let args = Args {
            rest_secret: Some("secret".to_string()),
            realm: Some("example.org".to_string()),
            ..Args::default()
        };
        assert!(
            build_auth(&args).is_err(),
            "--rest-secret needs --auth-secret"
        );

        // Realm + nonce secret + REST secret: no stored user is needed.
        let args = Args {
            rest_secret: Some("secret".to_string()),
            realm: Some("example.org".to_string()),
            auth_secret: Some("nonce-secret".to_string()),
            ..Args::default()
        };
        let auth = build_auth(&args).unwrap().expect("long-term mode");
        assert!(auth.has_rest_secret());
        assert_eq!(auth.user_count(), 0);

        // An empty REST secret is a half configuration.
        let args = Args {
            rest_secret: Some(String::new()),
            realm: Some("example.org".to_string()),
            auth_secret: Some("nonce-secret".to_string()),
            ..Args::default()
        };
        assert!(build_auth(&args).is_err());

        // And `--turn` accepts REST-only credentials (mode is long-term).
        let args = Args {
            turn: true,
            rest_secret: Some("secret".to_string()),
            realm: Some("example.org".to_string()),
            auth_secret: Some("nonce-secret".to_string()),
            tls_cert: None,
            ..Args::default()
        };
        let auth = build_auth(&args).unwrap().expect("long-term mode");
        assert!(build_turn(&args, Some(&auth)).unwrap().is_some());
    }

    #[cfg(feature = "dtls")]
    #[test]
    fn dtls_pem_uses_the_private_key_tag_webrtc_dtls_expects() {
        // `webrtc-dtls` requires `PRIVATE_KEY` first, then `CERTIFICATE`
        // blocks; standard tools write `PRIVATE KEY`, so the DER is re-wrapped.
        let certs = vec![tokio_rustls::rustls::pki_types::CertificateDer::from(vec![
            0x30, 0x01, 0x02,
        ])];
        let pem = dtls_pem(&[0x30, 0x02, 0x01, 0x03], &certs);
        assert!(pem.starts_with("-----BEGIN PRIVATE_KEY-----\n"), "{pem}");
        assert!(pem.contains("-----BEGIN CERTIFICATE-----\n"), "{pem}");
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"), "{pem}");
        assert!(
            !pem.contains("BEGIN PRIVATE KEY"),
            "tag must be PRIVATE_KEY"
        );
    }

    /// **Test-only** self-signed RSA-2048 pair (`CN=rstun-test-invalid`),
    /// generated for this test: never trusted, never used at runtime. It exists
    /// so the B1 regression (an RSA certificate is valid for `turns:` but not for
    /// DTLS) is covered without shelling out to `openssl`, which the Windows and
    /// macOS CI runners do not have.
    #[cfg(feature = "tls")]
    const TEST_RSA_CERT_PEM: &str = include_str!("../tests/fixtures/rsa-test-only.crt.pem");
    #[cfg(feature = "tls")]
    const TEST_RSA_KEY_PEM: &str = include_str!("../tests/fixtures/rsa-test-only.key.pem");

    /// Write the embedded PEM pair to a private temp dir; returns `(dir, cert, key)`.
    #[cfg(feature = "tls")]
    fn rsa_test_pair() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "rstun-rsa-pair-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, TEST_RSA_CERT_PEM).unwrap();
        std::fs::write(&key, TEST_RSA_KEY_PEM).unwrap();
        (dir, cert, key)
    }

    /// B1: with no `--turn-dtls-listen`, the DTLS-only key rules (PKCS#8 +
    /// ECDSA P-256/Ed25519) must not be applied. A Let's Encrypt RSA pair must
    /// start a `turns:`-only server. With DTLS requested the same pair is still
    /// refused, at startup, with an actionable message.
    #[cfg(feature = "dtls")]
    #[test]
    fn full_build_accepts_an_rsa_certificate_when_dtls_is_off() {
        let (dir, cert, key) = rsa_test_pair();
        let material = load_secure_material(&cert, &key, false)
            .expect("an RSA pair is fine for turns: when DTLS is not requested");
        assert!(
            material.material.dtls.is_none(),
            "no DTLS listener → no DTLS material to build"
        );

        let Err(error) = load_secure_material(&cert, &key, true) else {
            panic!("DTLS still cannot sign with RSA: the start must be refused");
        };
        assert!(
            error.contains("ECDSA P-256") && error.contains("DTLS"),
            "the error must name the DTLS restriction: {error}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A fresh, unique temp directory for the reload tests.
    #[cfg(feature = "tls")]
    fn material_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rstun-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A [`SecureSetup`] plus its two live paths, seeded with the RSA fixture.
    /// RSA is fine here because these tests never request DTLS material.
    #[cfg(feature = "tls")]
    fn seeded_setup(
        tag: &str,
    ) -> (
        std::path::PathBuf,
        SecureSetup,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let dir = material_dir(tag);
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, TEST_RSA_CERT_PEM).unwrap();
        std::fs::write(&key, TEST_RSA_KEY_PEM).unwrap();
        let loaded = load_secure_material(&cert, &key, false).expect("seed material");
        let stats = Arc::new(SecureStats::default());
        stats.set_not_after(loaded.not_after);
        (
            dir.clone(),
            SecureSetup {
                slot: Arc::new(std::sync::RwLock::new(loaded.material)),
                cert: cert.clone(),
                key: key.clone(),
                needs_dtls: false,
                poll: Some(CERT_POLL_INTERVAL),
                stats,
            },
            cert,
            key,
        )
    }

    /// D2 + D3: a successful reload swaps the whole `SharedMaterial`; a rejected
    /// one leaves the old `Arc` live (established sessions and new handshakes
    /// keep the same config) and counts exactly one failure after its retry.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn reload_swaps_atomically_and_keeps_the_old_material_on_failure() {
        let (dir, setup, cert, key) = seeded_setup("reload");
        let original = current_material(&setup.slot);

        assert!(
            reload_secure_material(&setup).await,
            "same bytes still parse"
        );
        let after_ok = current_material(&setup.slot);
        assert!(
            !Arc::ptr_eq(&original, &after_ok),
            "a reload rebuilds the whole ServerConfig on purpose"
        );
        assert_eq!(setup.stats.snapshot().reload_ok, 1);
        assert_eq!(setup.stats.snapshot().reload_failed, 0);

        // A key that is not a key: rejected after the 1 s retry.
        std::fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\nnot base64 at all\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(!reload_secure_material(&setup).await);
        let after_failure = current_material(&setup.slot);
        assert!(
            Arc::ptr_eq(&after_ok, &after_failure),
            "a rejected reload must not touch the live material"
        );
        let counts = setup.stats.snapshot();
        assert_eq!(counts.reload_failed, 1, "one failure, not one per attempt");
        assert_eq!(counts.reload_ok, 1);

        // A truncated certificate is the same class of rejection, with the
        // startup text (the reload rules *are* the startup rules).
        std::fs::write(&key, TEST_RSA_KEY_PEM).unwrap();
        std::fs::write(&cert, &TEST_RSA_CERT_PEM.as_bytes()[..200]).unwrap();
        assert!(!reload_secure_material(&setup).await);
        assert!(Arc::ptr_eq(&after_ok, &current_material(&setup.slot)));
        assert_eq!(setup.stats.snapshot().reload_failed, 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// D3 / implement.md 1.3: cert and key are two files, so the first parse
    /// can legitimately fail while the key is still the old one. The 1 s retry
    /// must then succeed **without counting a failure**.
    ///
    /// Real time, not `tokio::time::pause`: the helper has to actually write the
    /// file, and 300 ms sits well inside the 1 s retry window. Pausing would
    /// need tokio's `test-util` feature and would make the helper's file write
    /// race the manual `advance`.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn reload_retries_once_across_the_half_written_window() {
        let (dir, setup, _cert, key) = seeded_setup("half-write");
        let before = current_material(&setup.slot);

        // "cert written, key not yet": the pair does not match.
        std::fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\nnot base64 at all\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let key_path = key.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            std::fs::write(&key_path, TEST_RSA_KEY_PEM).unwrap();
        });

        assert!(
            reload_secure_material(&setup).await,
            "the retry must pick up the completed pair"
        );
        writer.await.unwrap();
        let counts = setup.stats.snapshot();
        assert_eq!(counts.reload_ok, 1);
        assert_eq!(
            counts.reload_failed, 0,
            "a recovered retry is not a failure"
        );
        assert!(
            !Arc::ptr_eq(&before, &current_material(&setup.slot)),
            "the successful retry must swap the slot"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The reload must use the **same** `needs_dtls` as startup: a pair that is
    /// fine for `turns:` is refused when the deployment also has a DTLS
    /// listener. Same files, same entry point — only the flag differs.
    #[cfg(all(feature = "tls", feature = "dtls"))]
    #[tokio::test]
    async fn reload_threads_needs_dtls_into_the_startup_rules() {
        let (dir, mut setup, _cert, _key) = seeded_setup("needs-dtls");
        let before = current_material(&setup.slot);

        // RSA is accepted for TLS and refused for DTLS (webrtc-dtls signs with
        // ECDSA P-256 / Ed25519 only); `seeded_setup` loads needs_dtls = false.
        setup.needs_dtls = true;
        assert!(
            !reload_secure_material(&setup).await,
            "an RSA pair must be rejected for a DTLS deployment"
        );
        assert!(Arc::ptr_eq(&before, &current_material(&setup.slot)));
        assert_eq!(setup.stats.snapshot().reload_failed, 1);

        // Same bytes with the DTLS rules off → accepted. If the reload dropped
        // the flag (always `false`), the assert above would fail instead.
        setup.needs_dtls = false;
        assert!(reload_secure_material(&setup).await);
        assert_eq!(setup.stats.snapshot().reload_ok, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The `(mtime, len)` gate: unchanged files compare equal, a rewrite is
    /// detected, and a file that is momentarily missing (a `rename` in
    /// progress) reports `None` instead of a false "changed".
    #[cfg(feature = "tls")]
    #[test]
    fn material_stamp_tracks_rewrites_and_missing_files() {
        let (dir, setup, cert, key) = seeded_setup("stamp");
        let first = material_stamp(&setup).expect("both files exist");
        assert_eq!(material_stamp(&setup), Some(first));

        std::fs::write(&cert, format!("{TEST_RSA_CERT_PEM}\n")).unwrap();
        let rewritten = material_stamp(&setup).expect("still both files");
        assert_ne!(first, rewritten, "(mtime, len) must notice the rewrite");

        std::fs::remove_file(&key).unwrap();
        assert_eq!(material_stamp(&setup), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The expiry gauge is computed against the wall clock when scraped, so a
    /// long-lived process does not report a stale "time left".
    #[cfg(feature = "tls")]
    #[test]
    fn secure_stats_expiry_follows_the_clock_and_marks_unknown_as_minus_one() {
        let stats = SecureStats::default();
        assert_eq!(stats.snapshot().cert_expires_seconds, -1);

        stats.set_not_after(Some(unix_seconds_now() + 600));
        let left = stats.snapshot().cert_expires_seconds;
        assert!((595..=600).contains(&left), "expected ~600, got {left}");

        stats.set_not_after(Some(unix_seconds_now() - 60));
        assert!(stats.snapshot().cert_expires_seconds < 0);

        stats.set_not_after(None);
        assert_eq!(stats.snapshot().cert_expires_seconds, -1);
    }

    /// `x509-parser` reads the leaf's validity (the only reason it is a direct
    /// dependency); the fixture expires in 2126.
    #[cfg(feature = "tls")]
    #[test]
    fn load_reads_the_leaf_not_after() {
        let (dir, cert, key) = rsa_test_pair();
        let loaded = load_secure_material(&cert, &key, false).expect("RSA is fine for TLS");
        let not_after = loaded.not_after.expect("the fixture DER must parse");
        assert!(
            not_after > 1_700_000_000,
            "sanity: post-2023, got {not_after}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `(code, attributes)` of an error response, decoded once.
    fn error_attribute_types(response: &[u8]) -> (u16, Vec<u16>) {
        let message = protocol::parse(response).expect("error response must parse");
        let code = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_ERROR_CODE)
            .map(|attribute| u16::from(attribute.value[2]) * 100 + u16::from(attribute.value[3]))
            .expect("ERROR-CODE");
        let types = protocol::attributes(message.body)
            .map(|attribute| attribute.attr_type)
            .collect();
        (code, types)
    }

    fn nonce_of(response: &[u8]) -> String {
        let message = protocol::parse(response).expect("error response must parse");
        let nonce = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_NONCE)
            .expect("NONCE")
            .value;
        std::str::from_utf8(nonce).unwrap().to_string()
    }

    /// A Binding request carrying `attributes`, sealed with `algorithm` — the
    /// same construction a real client performs (body → header length that
    /// includes the integrity attribute → MAC).
    fn authenticated_request(
        transaction_id: [u8; 12],
        attributes: &[(u16, &[u8])],
        identity: &auth::Identity,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        for (attr_type, value) in attributes {
            let padding = (4 - value.len() % 4) % 4;
            body.extend_from_slice(&attr_type.to_be_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value);
            body.extend(std::iter::repeat_n(0_u8, padding));
        }
        let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
        frame.extend_from_slice(&protocol::BINDING_REQUEST.to_be_bytes());
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        frame.extend_from_slice(&transaction_id);
        frame.extend_from_slice(&body);
        auth::seal(frame, identity)
    }

    fn long_term_identity(
        username: &str,
        password: &str,
        algorithm: auth::KeyAlgorithm,
    ) -> auth::Identity {
        auth::Identity {
            username: username.to_string(),
            keys: vec![(
                algorithm,
                auth::long_term_key(algorithm, username, "example.org", password),
            )],
        }
    }

    #[test]
    fn auth_off_keeps_the_integrity_cluster_ignored() {
        // RFC 5389 §10.2.2: a client may send the authentication attributes
        // unprompted. Without configured credentials they must change nothing.
        let mut request = binding_request(TEST_TRANSACTION);
        let attributes: &[(u16, &[u8])] = &[
            (protocol::ATTR_USERNAME, b"user"),
            (protocol::ATTR_REALM, b"example.org"),
            (protocol::ATTR_NONCE, b"not a nonce"),
            (protocol::ATTR_MESSAGE_INTEGRITY, &[0xaa; 20]),
        ];
        let mut body = Vec::new();
        for (attr_type, value) in attributes {
            body.extend_from_slice(&attr_type.to_be_bytes());
            body.extend_from_slice(&(value.len() as u16).to_be_bytes());
            body.extend_from_slice(value);
            body.extend(std::iter::repeat_n(0_u8, (4 - value.len() % 4) % 4));
        }
        request[2..4].copy_from_slice(&(body.len() as u16).to_be_bytes());
        request.extend_from_slice(&body);

        let response = success_bytes(
            decide(
                &request,
                "198.51.100.9:5000".parse().unwrap(),
                "127.0.0.1:3478".parse().unwrap(),
                Transport::Udp,
                &ServerContext::default(),
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_binding_success(
            &response,
            TEST_TRANSACTION,
            "198.51.100.9:5000".parse().unwrap(),
        );
    }

    #[test]
    fn long_term_401_carries_realm_nonce_and_algorithms_then_the_answer_is_signed() {
        let context = with_auth(long_term_auth(false));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let request = binding_request(TEST_TRANSACTION);

        let challenge = success_bytes(
            decide(
                &request,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        let (code, types) = error_attribute_types(&challenge);
        assert_eq!(code, 401);
        for expected in [
            protocol::ATTR_REALM,
            protocol::ATTR_NONCE,
            auth::ATTR_PASSWORD_ALGORITHMS,
        ] {
            assert!(types.contains(&expected), "401 must carry 0x{expected:04x}");
        }
        // Not an answer about the peer: a challenge carries no mapped address.
        assert!(!types.contains(&ATTR_XOR_MAPPED_ADDRESS));

        // The client retries with USERNAME / REALM / the nonce we just issued
        // and a MAC; the answer is a success sealed with the same key.
        let nonce = nonce_of(&challenge);
        let identity = long_term_identity("user", "pass", auth::KeyAlgorithm::Md5);
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_binding_success(&response, TEST_TRANSACTION, peer);
        let message = protocol::parse(&response).unwrap();
        let mac = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_MESSAGE_INTEGRITY)
            .expect("a success answer to a signed request is signed");
        assert!(auth::verify_integrity(
            &response,
            &identity.keys[0].1,
            auth::KeyAlgorithm::Md5
        ));
        assert_eq!(mac.value.len(), 20);
        // The signature is the only difference from the unsigned answer.
        let plain = success_bytes(
            decide(
                &binding_request(TEST_TRANSACTION),
                peer,
                local,
                Transport::Udp,
                &ServerContext::default(),
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(response.len(), plain.len() + 24);
    }

    #[test]
    fn wrong_password_gets_401() {
        let context = with_auth(long_term_auth(false));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let challenge = success_bytes(
            decide(
                &binding_request(TEST_TRANSACTION),
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        let nonce = nonce_of(&challenge);
        let identity = long_term_identity("user", "wrong", auth::KeyAlgorithm::Md5);
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 401);
        // Unknown user and a mismatching realm are 401 too, never a 420/400.
        let unknown = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"nobody"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &long_term_identity("nobody", "pass", auth::KeyAlgorithm::Md5),
        );
        let response = success_bytes(
            decide(
                &unknown,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 401);
        let other_realm = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"other.example"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &long_term_identity("user", "pass", auth::KeyAlgorithm::Md5),
        );
        let response = success_bytes(
            decide(
                &other_realm,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 401);
    }

    #[test]
    fn expired_nonce_gets_438_with_a_fresh_nonce() {
        // A lifetime of 0 seconds is rejected by `build_auth`, but the `Auth`
        // itself accepts it: the nonce is then already expired on arrival.
        let context = with_auth(auth::Auth::long_term(
            "example.org".to_string(),
            b"nonce-secret".to_vec(),
            vec![auth::User {
                username: "user".to_string(),
                password: "pass".to_string(),
            }],
            Duration::from_secs(0),
            false,
        ));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let nonce = context
            .auth
            .as_ref()
            .unwrap()
            .issue_nonce(peer.ip(), SystemTime::now());
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &long_term_identity("user", "pass", auth::KeyAlgorithm::Md5),
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        let (code, types) = error_attribute_types(&response);
        assert_eq!(code, 438);
        assert!(types.contains(&protocol::ATTR_NONCE));
        assert!(types.contains(&protocol::ATTR_REALM));
        // RFC 8489 §9.2.4: 438 carries PASSWORD-ALGORITHMS too.
        assert!(types.contains(&auth::ATTR_PASSWORD_ALGORITHMS));
        // A forged (not ours) nonce is a 401: 438 would tell the client to
        // refresh, which is only true for a nonce we signed.
        let forged = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, b"f//499k954d6OL34oL9FSTvy64sA"),
            ],
            &long_term_identity("user", "pass", auth::KeyAlgorithm::Md5),
        );
        let response = success_bytes(
            decide(
                &forged,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 401);
    }

    #[test]
    fn missing_long_term_attributes_are_400_while_wrong_values_are_401() {
        // RFC 5389 §10.2.2 / RFC 8489 §9.2.4 split: an *incomplete* message is a
        // bad request; only a present-but-wrong value is a failed authentication.
        let context = with_auth(long_term_auth(false));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let nonce = context
            .auth
            .as_ref()
            .unwrap()
            .issue_nonce(peer.ip(), SystemTime::now());
        let identity = long_term_identity("user", "pass", auth::KeyAlgorithm::Md5);
        let code_of = |attributes: &[(u16, &[u8])]| {
            let request = authenticated_request(TEST_TRANSACTION, attributes, &identity);
            let response = success_bytes(
                decide(
                    &request,
                    peer,
                    local,
                    Transport::Udp,
                    &context,
                    TEST_SOFTWARE,
                )
                .unwrap(),
            );
            error_attribute_types(&response).0
        };

        // Missing NONCE: the pair USERNAME + REALM is not enough.
        assert_eq!(
            code_of(&[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
            ]),
            400
        );
        // Missing REALM.
        assert_eq!(
            code_of(&[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ]),
            400
        );
        // Missing both USERNAME and USERHASH (an empty identity is not a user).
        assert_eq!(
            code_of(&[
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ]),
            400
        );
        // Wrong *value* of the realm: 401, not 400 — every attribute is there.
        assert_eq!(
            code_of(&[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"other.example"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ]),
            401
        );
        // Sanity: the complete message authenticates.
        assert_binding_success(
            &success_bytes(
                decide(
                    &authenticated_request(
                        TEST_TRANSACTION,
                        &[
                            (protocol::ATTR_USERNAME, b"user"),
                            (protocol::ATTR_REALM, b"example.org"),
                            (protocol::ATTR_NONCE, nonce.as_bytes()),
                        ],
                        &identity,
                    ),
                    peer,
                    local,
                    Transport::Udp,
                    &context,
                    TEST_SOFTWARE,
                )
                .unwrap(),
            ),
            TEST_TRANSACTION,
            peer,
        );
    }

    #[test]
    fn auth_makes_the_reflection_estimate_cover_the_401() {
        // M1: a 28-byte RESPONSE-PORT probe under ratio 2.0 allows 60 bytes.
        // Without `--realm` the guard predicts the 56-byte success (SOFTWARE
        // omitted, MI added) and would answer; with authentication on the
        // actual answer to *this* (credential-less) request is the 96-byte 401,
        // so the estimate must be the challenge, not the success.
        let context = ServerContext {
            auth: Some(long_term_auth(false)),
            ..guarded_context(reflect_policy(20, limit::DEFAULT_REFLECT_RATIO))
        };
        let request = minimal_response_port_request(TEST_TRANSACTION, 23480);
        match guarded(
            &request,
            "198.51.100.9:5000",
            "127.0.0.1:3478",
            Transport::Udp,
            &context,
        ) {
            Decision::Respond(bytes) => {
                assert_eq!(
                    error_details(&bytes).0,
                    400,
                    "96 > allowed(28) = 60 → refuse with a 40-byte 400"
                );
                assert_eq!(bytes.len(), 40);
            }
            other => panic!("expected a 400 refusal, got {other:?}"),
        }
        assert_eq!(admission_of(&context).counters().reflect_rejected, 1);
    }

    #[test]
    fn authenticated_420_and_400_are_signed() {
        // RFC 5389 §10.2.2: an authenticated request gets a signed answer even
        // when the answer is an error (420 / 400); only 500 is out of reach.
        let context = with_auth(long_term_auth(false));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let nonce = context
            .auth
            .as_ref()
            .unwrap()
            .issue_nonce(peer.ip(), SystemTime::now());
        let identity = long_term_identity("user", "pass", auth::KeyAlgorithm::Md5);
        let key = identity.keys[0].1.clone();

        let answer = |extra: &[(u16, &[u8])]| {
            let mut attributes = vec![
                (protocol::ATTR_USERNAME, b"user".as_slice()),
                (protocol::ATTR_REALM, b"example.org".as_slice()),
                (protocol::ATTR_NONCE, nonce.as_bytes() as &[u8]),
            ];
            attributes.extend_from_slice(extra);
            let request = authenticated_request(TEST_TRANSACTION, &attributes, &identity);
            success_bytes(
                decide(
                    &request,
                    peer,
                    local,
                    Transport::Udp,
                    &context,
                    TEST_SOFTWARE,
                )
                .unwrap(),
            )
        };

        // 420: an unknown comprehension-required attribute, authenticated.
        let response = answer(&[(0x7f01, b"\xde\xad")]);
        assert_eq!(error_attribute_types(&response).0, 420);
        assert!(
            auth::verify_integrity(&response, &key, auth::KeyAlgorithm::Md5),
            "the 420 must be signed with the request's key"
        );

        // 400: PADDING together with RESPONSE-PORT, authenticated.
        let response = answer(&[
            (protocol::ATTR_PADDING, b"\x00\x00\x00\x00"),
            (protocol::ATTR_RESPONSE_PORT, b"\x00\x50"),
        ]);
        assert_eq!(error_attribute_types(&response).0, 400);
        assert!(
            auth::verify_integrity(&response, &key, auth::KeyAlgorithm::Md5),
            "the 400 must be signed with the request's key"
        );
    }

    #[test]
    fn sha256_algorithm_and_userhash_authenticate() {
        let context = with_auth(long_term_auth(false));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let nonce = context
            .auth
            .as_ref()
            .unwrap()
            .issue_nonce(peer.ip(), SystemTime::now());

        // 1) PASSWORD-ALGORITHM=SHA256 + MESSAGE-INTEGRITY-SHA256.
        let identity = long_term_identity("user", "pass", auth::KeyAlgorithm::Sha256);
        let mut algorithm = Vec::new();
        algorithm.extend_from_slice(&auth::PASSWORD_ALGORITHM_SHA256.to_be_bytes());
        algorithm.extend_from_slice(&0_u16.to_be_bytes());
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
                (protocol::ATTR_PASSWORD_ALGORITHM, &algorithm),
            ],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_binding_success(&response, TEST_TRANSACTION, peer);
        assert!(auth::verify_integrity(
            &response,
            &identity.keys[0].1,
            auth::KeyAlgorithm::Sha256
        ));

        // 2) USERHASH instead of USERNAME (RFC 8489 §14.4) — same key, no
        //    USERNAME on the wire at all. The value is the **whole** 32-byte
        //    digest; this is the case a 16-byte prefix used to get wrong.
        let hash = auth::userhash("user", "example.org");
        assert_eq!(hash.len(), 32);
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERHASH, &hash),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
                (protocol::ATTR_PASSWORD_ALGORITHM, &algorithm),
            ],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_binding_success(&response, TEST_TRANSACTION, peer);

        // 3) A 16-byte USERHASH is *not* USERHASH (RFC 8489 §14.4 fixes it at
        //    32 bytes): 401, and never a truncated-prefix match.
        let short_hash: [u8; 16] = hash[..16].try_into().expect("first 16 bytes");
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERHASH, &short_hash),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
                (protocol::ATTR_PASSWORD_ALGORITHM, &algorithm),
            ],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 401);

        // 4) An unknown (but correctly sized) USERHASH is a 401, not a panic
        //    and not a 420.
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERHASH, &[0_u8; 32]),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
                (protocol::ATTR_PASSWORD_ALGORITHM, &algorithm),
            ],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 401);
    }

    #[test]
    fn require_sha256_rejects_md5_credentials() {
        let context = with_auth(long_term_auth(true));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let nonce = context
            .auth
            .as_ref()
            .unwrap()
            .issue_nonce(peer.ip(), SystemTime::now());

        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &long_term_identity("user", "pass", auth::KeyAlgorithm::Md5),
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        let (code, _) = error_attribute_types(&response);
        assert_eq!(code, 401);

        // The 401 advertises SHA256 only, so a client can renegotiate.
        let challenge = success_bytes(
            decide(
                &binding_request(TEST_TRANSACTION),
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        let message = protocol::parse(&challenge).unwrap();
        let algorithms = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == auth::ATTR_PASSWORD_ALGORITHMS)
            .expect("PASSWORD-ALGORITHMS")
            .value
            .to_vec();
        assert_eq!(algorithms, vec![0, 2, 0, 0]);

        // SHA256 still authenticates under the same switch.
        let identity = long_term_identity("user", "pass", auth::KeyAlgorithm::Sha256);
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_binding_success(&response, TEST_TRANSACTION, peer);
    }

    #[test]
    fn short_term_answers_400_without_credentials_and_401_for_a_bad_password() {
        let context = with_auth(auth::Auth::short_term(vec![auth::User {
            username: "user".to_string(),
            password: "pass".to_string(),
        }]));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();

        // RFC 5389 §10.1.2: a short-term request without both USERNAME and
        // MESSAGE-INTEGRITY is a *bad request*.
        let response = success_bytes(
            decide(
                &binding_request(TEST_TRANSACTION),
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 400);
        // A bare `--auth-user`-style 401 has no realm/nonce to offer.
        let identity = auth::Identity {
            username: "user".to_string(),
            keys: vec![(auth::KeyAlgorithm::Md5, b"wrong".to_vec())],
        };
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[(protocol::ATTR_USERNAME, b"user")],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        let (code, types) = error_attribute_types(&response);
        assert_eq!(code, 401);
        assert!(!types.contains(&protocol::ATTR_NONCE));

        // The short-term key is the password itself (RFC 5389 §15.4).
        let identity = auth::Identity {
            username: "user".to_string(),
            keys: vec![(auth::KeyAlgorithm::Md5, b"pass".to_vec())],
        };
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[(protocol::ATTR_USERNAME, b"user")],
            &identity,
        );
        let response = success_bytes(
            decide(
                &signed,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_binding_success(&response, TEST_TRANSACTION, peer);
    }

    #[test]
    fn redirect_wins_over_authentication() {
        // Design §5: 300 comes before credentials — a redirect needs none.
        let context = ServerContext {
            alternate_server: Some("192.0.2.9:3478".parse().unwrap()),
            ..with_auth(long_term_auth(false))
        };
        let response = success_bytes(
            decide(
                &binding_request(TEST_TRANSACTION),
                "198.51.100.9:5000".parse().unwrap(),
                "127.0.0.1:3478".parse().unwrap(),
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 300);
    }

    #[test]
    fn authentication_comes_before_the_420_branch() {
        // An unauthenticated request must not learn which attributes this server
        // knows: the 401 wins over the 420, the 420 still wins once signed.
        let context = with_auth(long_term_auth(false));
        let peer: SocketAddr = "198.51.100.9:5000".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let mut request = binding_request(TEST_TRANSACTION);
        request[2..4].copy_from_slice(&4_u16.to_be_bytes());
        request.extend_from_slice(&0x7f01_u16.to_be_bytes());
        request.extend_from_slice(&0_u16.to_be_bytes());
        let response = success_bytes(
            decide(
                &request,
                peer,
                local,
                Transport::Udp,
                &context,
                TEST_SOFTWARE,
            )
            .unwrap(),
        );
        assert_eq!(error_attribute_types(&response).0, 401);
    }

    #[test]
    fn invalid_authentication_configurations_fail_startup() {
        // Each of these would otherwise be a silent no-op: refuse to start.
        let cases: [(&str, Args); 8] = [
            (
                "--auth-user needs --auth-pass",
                Args {
                    auth_user: Some("user".to_string()),
                    ..Args::default()
                },
            ),
            (
                "--auth-pass needs --auth-user",
                Args {
                    auth_pass: Some("pass".to_string()),
                    ..Args::default()
                },
            ),
            (
                "--realm needs --auth-secret",
                Args {
                    realm: Some("example.org".to_string()),
                    auth_user: Some("user".to_string()),
                    auth_pass: Some("pass".to_string()),
                    ..Args::default()
                },
            ),
            (
                "--auth-secret only makes sense",
                Args {
                    auth_secret: Some("secret".to_string()),
                    auth_user: Some("user".to_string()),
                    auth_pass: Some("pass".to_string()),
                    ..Args::default()
                },
            ),
            (
                "--realm needs at least one user",
                Args {
                    realm: Some("example.org".to_string()),
                    auth_secret: Some("secret".to_string()),
                    ..Args::default()
                },
            ),
            (
                "--nonce-lifetime must be at least 1 second",
                Args {
                    realm: Some("example.org".to_string()),
                    auth_secret: Some("secret".to_string()),
                    auth_user: Some("user".to_string()),
                    auth_pass: Some("pass".to_string()),
                    nonce_lifetime: Some(0),
                    ..Args::default()
                },
            ),
            (
                "--nonce-lifetime needs --realm",
                Args {
                    auth_user: Some("user".to_string()),
                    auth_pass: Some("pass".to_string()),
                    nonce_lifetime: Some(60),
                    ..Args::default()
                },
            ),
            (
                "--auth-require-sha256 needs --realm",
                Args {
                    auth_user: Some("user".to_string()),
                    auth_pass: Some("pass".to_string()),
                    auth_require_sha256: true,
                    ..Args::default()
                },
            ),
        ];
        for (expected, args) in cases {
            let error = build_auth(&args).unwrap_err();
            assert!(error.contains(expected), "{error} != {expected}");
        }
        // And the good configurations build the mechanism they name.
        assert!(build_auth(&Args::default()).unwrap().is_none());
        let short = build_auth(&Args {
            auth_user: Some("user".to_string()),
            auth_pass: Some("pass".to_string()),
            ..Args::default()
        })
        .unwrap()
        .expect("short-term");
        assert_eq!(short.mode(), auth::Mode::ShortTerm);
        let long = build_auth(&Args {
            realm: Some("example.org".to_string()),
            auth_secret: Some("secret".to_string()),
            auth_user: Some("user".to_string()),
            auth_pass: Some("pass".to_string()),
            nonce_lifetime: Some(60),
            auth_require_sha256: true,
            ..Args::default()
        })
        .unwrap()
        .expect("long-term");
        assert_eq!(long.mode(), auth::Mode::LongTerm);
        assert!(long.require_sha256());
    }

    #[tokio::test]
    async fn a_401_flood_is_still_rate_limited() {
        // 401 is the largest answer this server emits for a small request, so it
        // must be the *admission* that bounds it, not the answer's shape: the
        // permit is taken before `decide` ever looks at the credentials.
        let admission = limit::Admission::new(limit::Policy {
            per_ip: Some(limit::Rate::new(1.0, 3.0)),
            ..limit::Policy::default()
        })
        .unwrap();
        let socket = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = socket.local_addr().unwrap();
        let context = Arc::new(ServerContext {
            udp: vec![(address, socket.clone())],
            admission: Some(admission.clone()),
            ..with_auth(long_term_auth(false))
        });
        tokio::spawn(serve_udp(
            socket,
            context,
            Arc::from(TEST_SOFTWARE),
            Arc::new(ServerStats::default()),
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..20 {
            client
                .send_to(&binding_request([0x91; 12]), address)
                .await
                .unwrap();
        }
        let answered = drain(&client, Duration::from_millis(300)).await;
        assert!(
            (1..=6).contains(&answered),
            "a 401 flood must be cut down to the burst size, got {answered}"
        );
        assert!(admission.counters().rate_limited_ip > 0);
    }

    #[tokio::test]
    async fn auth_probe_over_udp_gets_401_then_200() {
        // Same path as production: a real datagram through `serve_udp`.
        let socket = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let address = socket.local_addr().unwrap();
        let transport = Arc::new(ServerContext {
            udp: vec![(address, socket.clone())],
            ..with_auth(long_term_auth(false))
        });
        let stats = Arc::new(ServerStats::default());
        tokio::spawn(serve_udp(
            socket.clone(),
            transport,
            Arc::from(TEST_SOFTWARE),
            stats.clone(),
        ));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (challenge, from) =
            udp_exchange(&client, address, &binding_request(TEST_TRANSACTION)).await;
        assert_eq!(from, address);
        let (code, types) = error_attribute_types(&challenge);
        assert_eq!(code, 401);
        assert!(types.contains(&auth::ATTR_PASSWORD_ALGORITHMS));

        let nonce = nonce_of(&challenge);
        let signed = authenticated_request(
            TEST_TRANSACTION,
            &[
                (protocol::ATTR_USERNAME, b"user"),
                (protocol::ATTR_REALM, b"example.org"),
                (protocol::ATTR_NONCE, nonce.as_bytes()),
            ],
            &long_term_identity("user", "pass", auth::KeyAlgorithm::Md5),
        );
        let (response, _) = udp_exchange(&client, address, &signed).await;
        assert_binding_success(&response, TEST_TRANSACTION, client.local_addr().unwrap());
        assert_eq!(stats.counters(), (2, 2, 0));
    }
}
