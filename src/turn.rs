//! TURN (RFC 8656) relay state machine: allocations, permissions, channels,
//! indications and the per-allocation bandwidth buckets.
//!
//! What this module owns (the transports themselves live in `main.rs`):
//!
//! * `Allocate` / `Refresh` / `CreatePermission` / `ChannelBind` over **UDP,
//!   TCP, TLS (`turns:`) and DTLS** client transports — see
//!   [`ClientTransport`]. TLS and DTLS are compiled in only with the `tls` /
//!   `dtls` features and never change the UDP/TCP code paths.
//! * Authentication is **long-term credentials** (`--realm` + `--auth-secret` +
//!   a stored user) or the TURN REST ephemeral credentials (`--rest-secret`,
//!   coturn's `use-auth-secret`). There is no unauthenticated operation: the
//!   startup path refuses to enable `--turn` without one of them.
//! * A **UDP** relay allocation (`REQUESTED-TRANSPORT = 17`) regardless of the
//!   client transport. With `--turn-tcp-relay` a **TCP** allocation (RFC 6062,
//!   `REQUESTED-TRANSPORT = 6`) is also served: `Allocate` returns a TCP relay
//!   listener, `Connect` dials a peer from that address and `ConnectionBind`
//!   turns a second connection into the raw-byte client data connection.
//!   Without the switch the RFC 6062 methods are not TURN at all (the old
//!   `442` / `400` answers are byte-identical).
//! * `Send` / `Data` indications and `ChannelData` (4-byte header; padded only on
//!   a stream transport). A TCP allocation has none of these: `Send` and
//!   `ChannelData` are discarded, `ChannelBind` is `400`.
//! * `EVEN-PORT` (including the R=1 reservation token), because coturn's
//!   `turnutils_uclient` sends it on every Allocate.
//! * `--turn-bandwidth`: two token buckets per allocation (client→peer,
//!   peer→client); over the cap the packet is dropped and counted, the
//!   allocation survives.
//!
//! `REQUESTED-ADDRESS-FAMILY` (0x0017, §18.6) is parsed: a family the relay
//! cannot serve is answered `440 Address Family not Supported` (§7.2 step 7)
//! *after* the step-5 `RESERVATION-TOKEN` mutual exclusion (`400`), a malformed
//! value `400`, and the reserved 24 bits are ignored. `Refresh` compares it with
//! the allocation's relay family: a mismatch is `443 Peer Address Family
//! Mismatch` (§8.2 MUST), a match refreshes normally.
//!
//! Deliberately absent: the **inbound** half of RFC 6062 (`ConnectionAttempt`,
//! i.e. a peer dialling the relay listener). Outbound `Connect` +
//! `ConnectionBind` is what `turnutils_uclient -T` exercises; the passive mode
//! needs an "allocation → control connection" reverse channel and is a later
//! sub-item.
//!
//! `DONT-FRAGMENT` (0x001A, §18.9) is supported where the DF bit can really be
//! set — Linux and macOS/iOS, see [`DONT_FRAGMENT_SUPPORTED`]. `Allocate` with
//! the attribute arms the relay socket (`IP_MTU_DISCOVER` / `IP_DONTFRAG`; a
//! `setsockopt` failure there is a `500`), a `Send` indication carrying it sets
//! the bit for that datagram only (§11.2 — if the bit cannot be applied the
//! indication is **discarded**, as §11.2 requires), and `ChannelData` inherits
//! the allocation's setting because it has no attribute part. Everywhere else
//! (Windows, and unix targets without a verified option) `0x001A` stays unknown
//! comprehension-required → `420`, which §7.2 step 4 explicitly allows for a
//! server that does not set the bit.
//!
//! ## Certificate reload
//!
//! The TLS/DTLS material itself is owned by `main.rs` (it is the same
//! `SharedMaterial` slot both listeners read), but the observability contract
//! lives here: `rstun_turn_tls_reload_total{result}` and
//! `rstun_turn_tls_cert_expires_seconds` are part of the TURN metric block and
//! are gated exactly like `handshake_failed`-adjacent counters — absent unless
//! the relay **and** a secure listener are configured. A reload swaps the whole
//! `ServerConfig`/DTLS `Config` atomically; new connections use it, established
//! sessions keep the material they handshook with, and a rejected reload leaves
//! the old material serving. See `.trellis/spec/backend/turn.md` §5b.
//!
//! ## Accounting model
//!
//! Everything short-lived is time-stamped with a monotonic [`Instant`] and
//! reclaimed by one 1-second sweeper ([`Turn::sweep`], started by
//! [`start_sweeper`]). A removal drops the [`Allocation`], whose `Drop` aborts
//! the relay reader task and lets the relay socket fall out of scope — the port
//! goes back to the pool at the same moment, which is what makes the acceptance
//! check "`ss -lun` has no leftover relay socket" meaningful.
//!
//! TCP data connections (RFC 6062) live in a **global** `CONNECTION-ID` table
//! ([`Turn::connections`]) rather than in an allocation: they are their own
//! accepted TCP connection and must not share the control connection's
//! 5-tuple. Each one is a task that owns the peer socket; `sweep` closes the
//! ones that never bound within 30 s, and removing an allocation signals every
//! connection it owns to stop (§5.5 MUST).
//!
//! Counters are atomics shared by every task, read by `/metrics` and by the exit
//! log — one source, no double bookkeeping. When `--turn` is off the whole
//! module is inert: no table, no task, no metric line.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::auth::{self, Identity};
use crate::protocol::{self, MessageClass, TransactionId};
use crate::{Decision, ServerContext};

// ---------------------------------------------------------------------------
// Wire constants (RFC 8656 §14)
// ---------------------------------------------------------------------------

/// `Allocate` (RFC 8656 §7.2).
pub const ALLOCATE_METHOD: u16 = 0x003;
/// `Refresh` (§7.2).
pub const REFRESH_METHOD: u16 = 0x004;
/// `Send` indication (§7.3).
pub const SEND_METHOD: u16 = 0x006;
/// `Data` indication (§7.3).
pub const DATA_METHOD: u16 = 0x007;
/// `CreatePermission` (§9).
pub const CREATE_PERMISSION_METHOD: u16 = 0x008;
/// `ChannelBind` (§11).
pub const CHANNEL_BIND_METHOD: u16 = 0x009;
/// `Connect` (RFC 6062 §6.1): on the **control** connection, asks the server to
/// dial an `XOR-PEER-ADDRESS` from the TCP allocation's relay address.
pub const CONNECT_METHOD: u16 = 0x00a;
/// `ConnectionBind` (RFC 6062 §6.1): on a **new** connection, binds it to a
/// pending peer data connection named by `CONNECTION-ID`; afterwards that
/// connection carries raw application bytes only.
pub const CONNECTION_BIND_METHOD: u16 = 0x00b;

/// `CHANNEL-NUMBER` (§14.1): channel (u16) + RFFU.
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
/// `LIFETIME` (§14.2): u32 seconds.
pub const ATTR_LIFETIME: u16 = 0x000D;
/// `XOR-PEER-ADDRESS` (§14.3).
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
/// `DATA` (§14.4).
pub const ATTR_DATA: u16 = 0x0013;
/// `XOR-RELAYED-ADDRESS` (§14.5).
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
/// `REQUESTED-ADDRESS-FAMILY` (§18.6): `Family (1 byte) | Reserved (3 bytes)`.
///
/// `0x01` = IPv4, `0x02` = IPv6. The reserved bits are ignored, as §18.6
/// requires. Legal on `Allocate` and `Refresh`; `Allocate` answers `440` when
/// the requested family is not the one the relay can offer (§7.2 step 7), and
/// `Refresh` answers `443` when it does not match the existing allocation
/// (§8.2).
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
/// `REQUESTED-TRANSPORT` (§14.7): protocol (1 byte) + RFFU.
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
/// `DONT-FRAGMENT` (§18.9): **no value part** (length 0). In `Allocate` it asks
/// the server to set the DF bit on every datagram the relay sends, and doubles
/// as a capability probe; in a `Send` indication it asks for the bit on that
/// one datagram (§11.2).
pub const ATTR_DONT_FRAGMENT: u16 = 0x001A;
/// `EVEN-PORT` (§14.6): R bit + reserved. coturn's `turnutils_uclient` sends
/// it on every Allocate, so T1 accepts the "even port" half of it.
pub const ATTR_EVEN_PORT: u16 = 0x0018;
/// `RESERVATION-TOKEN` (§14.9): 8 opaque bytes naming an EVEN-PORT reservation.
pub const ATTR_RESERVATION_TOKEN: u16 = 0x0022;
/// `CONNECTION-ID` (RFC 6062 §6.2.1): 32-bit unsigned, names one peer data
/// connection. Appears in a `Connect` success response and in the
/// `ConnectionBind` request that claims it.
pub const ATTR_CONNECTION_ID: u16 = 0x002a;

/// IANA protocol number of UDP.
pub const TRANSPORT_UDP: u8 = 17;
/// IANA protocol number of TCP (`REQUESTED-TRANSPORT = 6`, RFC 6062). Only
/// honoured when `--turn-tcp-relay` is on; otherwise `442` as before.
pub const TRANSPORT_TCP: u8 = 6;

/// Whether `DONT-FRAGMENT` can really be honoured (RFC 8656 §7.2 step 4).
///
/// True only on the platforms [`set_dont_fragment`] implements: Linux
/// (`IP_MTU_DISCOVER`), macOS/iOS (`IP_DONTFRAG`). Everywhere else — Windows,
/// and unix targets whose option names nobody has verified (FreeBSD & co.) —
/// `0x001A` stays unknown comprehension-required and is answered `420`, which
/// §7.2 step 4 permits for a server that does not set the bit.
pub const DONT_FRAGMENT_SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios"
));

// Compile-time guard: the flag must never be true where there is no
// `setsockopt` path, otherwise `Allocate` would answer `500` where §7.2 step 4
// sanctions the `420`. Checked by `cargo check --target
// x86_64-pc-windows-msvc` (and by any non-Linux/macOS unix build).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
const _: () = assert!(!DONT_FRAGMENT_SUPPORTED);

/// RFC 8656 §14 error codes.
pub const ERROR_FORBIDDEN: u16 = 403;
/// `441 Wrong Credentials`: the 5-tuple is in use by another username
/// (RFC 8656 §5 / §6.2). The allocation must not be touched.
pub const ERROR_WRONG_CREDENTIALS: u16 = 441;
pub const ERROR_ALLOCATION_MISMATCH: u16 = 437;
pub const ERROR_ADDRESS_FAMILY_NOT_SUPPORTED: u16 = 440;
pub const ERROR_UNSUPPORTED_TRANSPORT: u16 = 442;
pub const ERROR_PEER_ADDRESS_FAMILY_MISMATCH: u16 = 443;
pub const ERROR_ALLOCATION_QUOTA_REACHED: u16 = 486;
pub const ERROR_INSUFFICIENT_CAPACITY: u16 = 508;
/// RFC 6062 §6.3: the same `XOR-PEER-ADDRESS` already has a peer data
/// connection (pending or bound) on this allocation.
pub const ERROR_CONNECTION_ALREADY_EXISTS: u16 = 446;
/// RFC 6062 §6.3: the outbound TCP connection failed or timed out.
pub const ERROR_CONNECTION_TIMEOUT_OR_FAILURE: u16 = 447;

/// First/last channel number of the `ChannelData` range (§12).
///
/// RFC 8656 §12.1 defines `0x4000-0x7FFE`; the last value is accepted as
/// coturn compatibility (its parser allows `0x7FFF`), documented in README.
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x7FFF;

/// Capacity of the per-connection writer queue for TURN-over-TCP.
///
/// Bounded on purpose: an authenticated client that stops reading must not be
/// able to grow an unbounded `Vec` queue in the server. Overflow drops the
/// datagram (relayed data is best-effort, like UDP itself).
pub(crate) const TCP_SINK_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// Defaults (conservative by contract; see prd.md R3/R5)
// ---------------------------------------------------------------------------

pub const DEFAULT_RELAY_PORTS: (u16, u16) = (49152, 65535);
pub const DEFAULT_MAX_ALLOCATIONS_PER_USER: usize = 8;
pub const DEFAULT_MAX_ALLOCATIONS_PER_IP: usize = 16;
pub const DEFAULT_PERMISSION_LIMIT: usize = 10;
pub const DEFAULT_ALLOCATION_LIFETIME_SECONDS: u64 = 600;
/// Default `--turn-bandwidth`: 1 MiB/s per direction per allocation. Large
/// enough that control traffic and a few media streams are untouched, small
/// enough that one allocation cannot flatten a shared uplink.
pub const DEFAULT_BANDWIDTH: u64 = 1024 * 1024;
pub const MAX_ALLOCATION_LIFETIME_SECONDS: u64 = 3600;
/// Permission lifetime, fixed by RFC 8656 §8 (5 minutes).
pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
/// Channel lifetime, fixed by RFC 8656 §11 (10 minutes).
pub const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
/// Sweeper cadence; also the worst-case overshoot of an expired TTL.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// How long an `EVEN-PORT` reservation token stays usable (RFC 8656 §7.2).
pub const RESERVATION_LIFETIME: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// RFC 6062 (TCP allocations) tunables
// ---------------------------------------------------------------------------

/// `Connect` budget. RFC 6062 §5.2 says the timeout **MUST be at least 30
/// seconds**; this is deliberately its own constant (not `TCP_READ_TIMEOUT`,
/// which is a per-frame control-plane budget and must stay free to change).
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a **pending** peer data connection may wait for its
/// `ConnectionBind` before the server closes it (RFC 6062 §5.2/§5.4 MUST).
pub const TCP_BIND_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on bytes buffered from the peer before the client data connection is
/// bound (RFC 6062 §5.2/§7 allows closing the connection instead of growing
/// memory without bound). Purely the application copy; the kernel receive
/// window provides the first line of backpressure.
pub const TCP_PREBIND_BUFFER: usize = 64 * 1024;
/// Per-allocation cap on simultaneous peer data connections (pending + bound).
/// RFC 6062 does not cap this; exceeding it is `508 Insufficient Capacity`
/// (same shape as the relay-port and permission limits).
pub const TCP_MAX_CONNECTIONS_PER_ALLOCATION: usize = 16;

/// Can an outbound `Connect` dial **from the relayed transport address** (RFC
/// 6062 §5.2)?
///
/// Yes where the platform has `SO_REUSEPORT` — both the relay listener and the
/// dialling socket are bound to the same port. Windows has no such option, so
/// [`dial_from_relay`] falls back to an ephemeral source port there; the peer
/// data connection still works, only the peer's view of the source port differs.
///
/// The implementation gates the option with `#[cfg(unix)]`; this constant is the
/// same predicate for tests (so a Windows run knows not to assert the source
/// port) and is guarded by the compile-time check below.
pub(crate) const RELAY_SOURCE_PORT_BOUND: bool = cfg!(unix);

// The dial only sets `SO_REUSEPORT` under `cfg(unix)`; the predicate tests read
// must never drift from that gate.
const _: () = assert!(RELAY_SOURCE_PORT_BOUND == cfg!(unix));

/// Parsed `--turn` configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Inclusive relay port range (`--relay-ports LO-HI`).
    pub relay_ports: (u16, u16),
    pub max_allocations_per_user: usize,
    pub max_allocations_per_ip: usize,
    pub permission_limit: usize,
    /// Default `LIFETIME` granted when a client requests none, and the cap
    /// applied to whatever it does request. `--allocation-lifetime`.
    pub lifetime: Duration,
    /// Per-allocation bandwidth cap in bytes/second, applied **per direction**
    /// (`--turn-bandwidth`). `0` = unlimited.
    ///
    /// Enforced with two token buckets (one for client→peer, one for
    /// peer→client) whose capacity is one second of tokens. Over the cap the
    /// offending packet is dropped and counted; the allocation lives on.
    pub bandwidth: u64,
    /// `--turn-tcp-relay`: serve RFC 6062 TCP allocations (`Allocate` with
    /// `REQUESTED-TRANSPORT = 6`, plus `Connect` / `ConnectionBind`). Off by
    /// default so a request that used to get `442` still does, byte for byte.
    pub tcp_relay: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            relay_ports: DEFAULT_RELAY_PORTS,
            max_allocations_per_user: DEFAULT_MAX_ALLOCATIONS_PER_USER,
            max_allocations_per_ip: DEFAULT_MAX_ALLOCATIONS_PER_IP,
            permission_limit: DEFAULT_PERMISSION_LIMIT,
            lifetime: Duration::from_secs(DEFAULT_ALLOCATION_LIFETIME_SECONDS),
            bandwidth: DEFAULT_BANDWIDTH,
            tcp_relay: false,
        }
    }
}

impl Config {
    /// Reject configurations that would silently disable a limit (the project
    /// rule: a half-configured guard is worse than a refused start).
    pub fn validate(&self) -> Result<(), String> {
        let (lo, hi) = self.relay_ports;
        if lo == 0 {
            return Err("--relay-ports must not start at 0".to_string());
        }
        if lo > hi {
            return Err(format!(
                "--relay-ports LO-HI needs LO <= HI (got {lo}-{hi})"
            ));
        }
        if self.max_allocations_per_user == 0 {
            return Err("--max-allocations-per-user must be at least 1".to_string());
        }
        if self.max_allocations_per_ip == 0 {
            return Err("--max-allocations-per-ip must be at least 1".to_string());
        }
        if self.permission_limit == 0 {
            return Err("--permission-limit must be at least 1".to_string());
        }
        if self.lifetime.is_zero() {
            return Err("--allocation-lifetime must be at least 1 second".to_string());
        }
        if self.lifetime > Duration::from_secs(MAX_ALLOCATION_LIFETIME_SECONDS) {
            return Err(format!(
                "--allocation-lifetime must be at most {MAX_ALLOCATION_LIFETIME_SECONDS} seconds"
            ));
        }
        Ok(())
    }
}

/// Parse the `LO-HI` spelling of `--relay-ports`.
pub fn parse_port_range(text: &str) -> Result<(u16, u16), String> {
    let (lo, hi) = text
        .split_once('-')
        .ok_or_else(|| format!("--relay-ports expects LO-HI (got {text:?})"))?;
    let lo: u16 = lo
        .trim()
        .parse()
        .map_err(|_| format!("--relay-ports: invalid low port {lo:?}"))?;
    let hi: u16 = hi
        .trim()
        .parse()
        .map_err(|_| format!("--relay-ports: invalid high port {hi:?}"))?;
    if lo == 0 {
        return Err("--relay-ports must not start at 0".to_string());
    }
    Ok((lo, hi))
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Everything `/metrics` and the exit log report about TURN.
#[derive(Debug, Default)]
pub struct Counters {
    /// Client → peer payload bytes accepted for relaying.
    pub bytes_in: AtomicU64,
    /// Peer → client payload bytes relayed to the client.
    pub bytes_out: AtomicU64,
    pub created: AtomicU64,
    pub expired: AtomicU64,
    pub rejected_quota: AtomicU64,
    pub rejected_ports: AtomicU64,
    pub rejected_family: AtomicU64,
    pub rejected_loopback: AtomicU64,
    /// `DONT-FRAGMENT` handling failures: a relay socket that refused the DF
    /// option on `Allocate` (→ `500`), or a `Send` indication that had to be
    /// discarded because the bit could not be applied (§11.2) or because the
    /// attribute carried a value part (§18.9).
    pub rejected_df: AtomicU64,
    /// Bytes dropped by the per-allocation bandwidth buckets (`--turn-bandwidth`).
    pub bytes_dropped_in: AtomicU64,
    pub bytes_dropped_out: AtomicU64,
    /// RFC 6062 rejections, one bucket per reason (design §5):
    /// `Connect` failed/timed out (`447`), `ConnectionBind` was refused
    /// (`400`), a `Send`/`ChannelData` hit a TCP allocation, the pre-bind
    /// buffer overflowed, or the per-allocation connection cap was hit.
    pub rejected_tcp_connect: AtomicU64,
    pub rejected_tcp_bind: AtomicU64,
    pub rejected_tcp_send: AtomicU64,
    pub rejected_tcp_buffer: AtomicU64,
    pub rejected_tcp_quota: AtomicU64,
    /// TLS/DTLS handshakes that failed or timed out (`--turn-tls-listen` /
    /// `--turn-dtls-listen`). Kept out of `/metrics` on purpose: the label
    /// space stays exactly the T1 one plus `rstun_turn_bytes_dropped_total`.
    pub handshake_failed: AtomicU64,
}

/// One consistent read of [`Counters`] plus the live allocation count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub active: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub created: u64,
    pub expired: u64,
    pub rejected_quota: u64,
    pub rejected_ports: u64,
    pub rejected_family: u64,
    pub rejected_loopback: u64,
    pub rejected_df: u64,
    pub bytes_dropped_in: u64,
    pub bytes_dropped_out: u64,
    pub rejected_tcp_connect: u64,
    pub rejected_tcp_bind: u64,
    pub rejected_tcp_send: u64,
    pub rejected_tcp_buffer: u64,
    pub rejected_tcp_quota: u64,
    /// Live RFC 6062 data connections, by state (gauges).
    pub tcp_pending: u64,
    pub tcp_bound: u64,
    pub handshake_failed: u64,
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Which transport the *client* speaks to us (the relay itself is always UDP).
///
/// `Tcp` is also what a `turns:` (TLS) connection records: design §6 keeps the
/// 5-tuple identical to plain TCP — the listener port already distinguishes
/// the two, and TLS and plaintext are never served on the same port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientTransport {
    Udp,
    Tcp,
    /// DTLS: one datagram = one STUN/TURN message or one `ChannelData` (§12),
    /// exactly like UDP, but a distinct 5-tuple from a plaintext UDP client.
    ///
    /// Constructed only by the `dtls` feature (and by the framing unit test), so
    /// a lean build would otherwise report it as dead code.
    #[cfg_attr(not(any(feature = "dtls", test)), allow(dead_code))]
    Dtls,
}

impl ClientTransport {
    /// Datagram framing: `ChannelData` is `header + payload` with no padding
    /// (RFC 8656 §12.4); only a *stream* transport pads (§12.5).
    fn is_datagram(self) -> bool {
        matches!(self, Self::Udp | Self::Dtls)
    }
}

/// RFC 8656 §2 "5-tuple": client address, transport, server address.
///
/// The relayed transport is always UDP in T1, so it is not part of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub client: SocketAddr,
    pub transport: ClientTransport,
    pub server: SocketAddr,
}

/// Where relayed payload goes on the client side.
#[derive(Clone)]
enum ClientSink {
    /// The listening socket that received the request (source address must be
    /// the server's own, RFC 8656 §7.3).
    Udp(Arc<UdpSocket>),
    /// A connection's writer task: TCP, TLS and DTLS all hand back a bounded
    /// queue (ChannelData / Data indication already framed for the transport).
    /// Bounded: `try_send` drops on overflow instead of growing memory.
    Queue(mpsc::Sender<Vec<u8>>),
}

impl std::fmt::Debug for ClientSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(_) => f.write_str("Udp"),
            Self::Queue(_) => f.write_str("Queue"),
        }
    }
}

/// One channel binding (RFC 8656 §11).
#[derive(Debug, Clone, Copy)]
struct ChannelBinding {
    peer: SocketAddr,
    expires_at: Instant,
}

/// The mutable part of an allocation; shared with its relay reader task.
#[derive(Debug)]
struct AllocationState {
    expires_at: Instant,
    permissions: HashMap<IpAddr, Instant>,
    channels: HashMap<u16, ChannelBinding>,
    /// `--turn-bandwidth` enforcement, one bucket per direction.
    inbound: TokenBucket,
    outbound: TokenBucket,
}

/// One direction's bandwidth bucket (bytes, refilled continuously).
///
/// Capacity is one second of tokens, so a burst of up to `--turn-bandwidth`
/// bytes passes immediately and a sustained rate above it is what gets
/// dropped. `rate == 0` disables the bucket entirely.
#[derive(Debug)]
struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(bandwidth: u64, now: Instant) -> Self {
        let rate = bandwidth as f64;
        Self {
            rate,
            capacity: rate,
            tokens: rate,
            last: now,
        }
    }

    /// Take `bytes` tokens if the bucket has them; `false` means "drop it".
    fn try_take(&mut self, now: Instant, bytes: usize) -> bool {
        if self.rate <= 0.0 {
            return true;
        }
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            self.last = now;
        }
        let wanted = bytes as f64;
        if self.tokens >= wanted {
            self.tokens -= wanted;
            true
        } else {
            false
        }
    }
}

/// What an allocation relays through.
///
/// RFC 8656 allocations have one UDP socket; RFC 6062 allocations have one TCP
/// listener whose address is the relayed transport address.
enum Relay {
    Udp(Arc<UdpSocket>),
    Tcp(TcpRelay),
}

/// The listening half of a TCP relay allocation.
///
/// Outbound `Connect` dials from this address (see [`dial_from_relay`]); that is
/// why the listener sets `SO_REUSEPORT` — without it the kernel refuses to bind
/// a second socket to a port that is already listening (see
/// [`crate::tcp_relay_listener`]).
struct TcpRelay {
    listener: TcpListener,
}

impl Relay {
    fn udp(&self) -> Option<&Arc<UdpSocket>> {
        match self {
            Self::Udp(socket) => Some(socket),
            Self::Tcp(_) => None,
        }
    }

    fn port(&self) -> Option<u16> {
        match self {
            Self::Udp(socket) => socket.local_addr().ok().map(|address| address.port()),
            Self::Tcp(relay) => relay
                .listener
                .local_addr()
                .ok()
                .map(|address| address.port()),
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }
}

/// One live allocation.
pub struct Allocation {
    key: Key,
    relay: Relay,
    relay_addr: SocketAddr,
    /// Credentials that created the allocation: a different user on the same
    /// 5-tuple gets `441` and cannot touch it (RFC 8656 §5).
    username: String,
    /// Transaction id of the creating `Allocate`: only a retransmission with
    /// the **same** id is idempotent; a new id is `437` (RFC 8656 §6.2).
    transaction_id: TransactionId,
    /// Lifetime granted by the creating response; a retransmission must return
    /// the same value, not the remaining one (§6.2).
    lifetime: u32,
    client: SocketAddr,
    /// The creating `Allocate` carried `DONT-FRAGMENT` (§18.9), so the relay
    /// socket has the DF bit on for its whole life. A `Send` indication then
    /// needs no per-datagram toggle.
    dont_fragment: bool,
    /// Serialises the per-datagram DF toggle **between `Send` indications that
    /// ask for DF** (§11.2). Only touched when `dont_fragment` is false (an
    /// allocation created with DF never toggles) and only by DF-carrying
    /// `Send`s: two of them may be handled concurrently (`--max-inflight`), and
    /// neither may observe the other's temporary setting. Plain `Send`s and
    /// `ChannelData` deliberately stay lock-free — the known limitation is
    /// recorded in `.trellis/spec/backend/turn.md`. The toggle is synchronous
    /// (`setsockopt` + `try_send_to`), so a plain mutex is enough.
    df_lock: Mutex<()>,
    state: Arc<RwLock<AllocationState>>,
    /// Aborts the relay reader when the allocation goes away. `None` for a TCP
    /// allocation: its data plane is one task per `CONNECTION-ID`, not a reader.
    relay_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Allocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Allocation")
            .field("key", &self.key)
            .field("relay_addr", &self.relay_addr)
            .field("username", &self.username)
            .field("transaction_id", &self.transaction_id)
            .field("lifetime", &self.lifetime)
            .field("client", &self.client)
            .field("dont_fragment", &self.dont_fragment)
            .field("tcp", &self.relay.is_tcp())
            .finish_non_exhaustive()
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        // Stopping the reader is what lets the socket (and its port) go. A TCP
        // relay has no reader task; dropping `relay` closes its listener.
        if let Some(task) = &self.relay_task {
            task.abort();
        }
    }
}

impl Allocation {
    fn remaining(&self, now: Instant) -> Duration {
        lock_read(&self.state)
            .expires_at
            .saturating_duration_since(now)
    }

    fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    fn is_tcp(&self) -> bool {
        self.relay.is_tcp()
    }
}

// ---------------------------------------------------------------------------
// RFC 6062 connection table
// ---------------------------------------------------------------------------

/// The client half of a bound data connection, handed from the accepted
/// connection's task to the peer connection's task.
///
/// Type-erased on purpose: the reader is either a plain-TCP or a TLS half, and
/// the connection table must not be generic over that.
pub(crate) struct DataConnection {
    pub(crate) reader: Box<dyn AsyncRead + Send + Unpin>,
    /// The control-style bounded writer queue of that connection. Raw peer→
    /// client bytes go through it, so ordering with the `ConnectionBind`
    /// success response is preserved and a client that stops reading applies
    /// backpressure instead of growing memory.
    pub(crate) sender: mpsc::Sender<Vec<u8>>,
    /// The writer task that owns the write half; awaiting it after the queue is
    /// closed is what makes the half-close visible to the client.
    pub(crate) writer_task: JoinHandle<()>,
    /// Keeps the accepted-connection slot (`--max-inflight`) alive for the life
    /// of the data connection. Dropped when the relay task ends.
    pub(crate) _permit: Option<crate::limit::Permit>,
}

/// One RFC 6062 peer data connection, keyed by `CONNECTION-ID`.
struct TcpConnection {
    /// The allocation (control connection's 5-tuple) that owns it.
    allocation: Key,
    /// Username that created the allocation; `ConnectionBind` must use the same
    /// credentials (RFC 6062 §4.3).
    username: String,
    peer: SocketAddr,
    state: ConnState,
    /// When the pending connection must be closed (sweep). `None` once bound:
    /// a bound connection is owned by its task.
    expires_at: Option<Instant>,
    /// Wakes the peer task on any forced close (allocation removal, sweep
    /// timeout, pre-bind buffer overflow). Unused (`Err`) once the task ended.
    stop: watch::Sender<bool>,
    /// Given to the peer task on a successful `ConnectionBind`; `None` in every
    /// other state.
    bind: Option<oneshot::Sender<DataConnection>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    /// The outbound TCP connect is still in progress.
    Connecting,
    /// Connected to the peer, waiting for `ConnectionBind`.
    Pending,
    /// `ConnectionBind` succeeded; the data path is live.
    Bound,
}

impl TcpConnection {
    fn pending(&self) -> bool {
        matches!(self.state, ConnState::Connecting | ConnState::Pending)
    }
}

/// A client transport is a *stream* when `ConnectionBind` (and thus a data
/// connection) can exist on it: RFC 6062 §5.4 step 1 refuses the rest with 400.
fn is_stream_transport(transport: ClientTransport) -> bool {
    matches!(transport, ClientTransport::Tcp)
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// The TURN table: allocations, relay port pools and counters.
///
/// `Turn` is immutable except for the two locks; it is stored in an `Arc` and
/// reached from the request paths through [`ServerStats`](crate::ServerStats)
/// so the STUN payload functions keep their signatures.
pub struct Turn {
    config: Config,
    /// `SOFTWARE` value emitted on every success response (RFC 8656 §14.10
    /// SHOULD). Fixed per process, so it lives next to the table.
    software: String,
    allocations: RwLock<HashMap<Key, Arc<Allocation>>>,
    used_ports: Mutex<HashSet<u16>>,
    /// TCP relay ports, kept **separate** from `used_ports`: the same port
    /// number means different things to UDP and TCP, and sharing the pool would
    /// make one allocation of either kind block the other for no reason.
    used_tcp_ports: Mutex<HashSet<u16>>,
    /// `EVEN-PORT` (R=1) reservations: token → (odd port, deadline).
    reservations: Mutex<HashMap<[u8; 8], Reservation>>,
    /// RFC 6062 data connections by `CONNECTION-ID`. `Arc<Mutex<…>>` because the
    /// per-connection task also removes its own entry when it ends.
    connections: Arc<Mutex<HashMap<u32, TcpConnection>>>,
    counters: Arc<Counters>,
}

/// One pending `EVEN-PORT` reservation (the odd half of the requested pair).
#[derive(Debug, Clone, Copy)]
struct Reservation {
    port: u16,
    expires_at: Instant,
}

impl std::fmt::Debug for Turn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Turn")
            .field("config", &self.config)
            .field("software", &self.software)
            .field("allocations", &lock_read(&self.allocations).len())
            .field("used_ports", &lock_lock(&self.used_ports).len())
            .finish_non_exhaustive()
    }
}

impl Turn {
    pub fn new(config: Config, software: impl Into<String>) -> Self {
        Self {
            config,
            software: software.into(),
            allocations: RwLock::new(HashMap::new()),
            used_ports: Mutex::new(HashSet::new()),
            used_tcp_ports: Mutex::new(HashSet::new()),
            reservations: Mutex::new(HashMap::new()),
            connections: Arc::new(Mutex::new(HashMap::new())),
            counters: Arc::new(Counters::default()),
        }
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn active(&self) -> u64 {
        lock_read(&self.allocations).len() as u64
    }

    /// One consistent snapshot for `/metrics` and the exit log.
    pub fn snapshot(&self) -> Snapshot {
        let counters = &self.counters;
        let (tcp_pending, tcp_bound) = {
            let connections = lock_lock(&self.connections);
            let pending = connections
                .values()
                .filter(|connection| connection.pending())
                .count() as u64;
            let bound = connections.len() as u64 - pending;
            (pending, bound)
        };
        Snapshot {
            active: self.active(),
            bytes_in: counters.bytes_in.load(Ordering::Relaxed),
            bytes_out: counters.bytes_out.load(Ordering::Relaxed),
            created: counters.created.load(Ordering::Relaxed),
            expired: counters.expired.load(Ordering::Relaxed),
            rejected_quota: counters.rejected_quota.load(Ordering::Relaxed),
            rejected_ports: counters.rejected_ports.load(Ordering::Relaxed),
            rejected_family: counters.rejected_family.load(Ordering::Relaxed),
            rejected_loopback: counters.rejected_loopback.load(Ordering::Relaxed),
            rejected_df: counters.rejected_df.load(Ordering::Relaxed),
            bytes_dropped_in: counters.bytes_dropped_in.load(Ordering::Relaxed),
            bytes_dropped_out: counters.bytes_dropped_out.load(Ordering::Relaxed),
            rejected_tcp_connect: counters.rejected_tcp_connect.load(Ordering::Relaxed),
            rejected_tcp_bind: counters.rejected_tcp_bind.load(Ordering::Relaxed),
            rejected_tcp_send: counters.rejected_tcp_send.load(Ordering::Relaxed),
            rejected_tcp_buffer: counters.rejected_tcp_buffer.load(Ordering::Relaxed),
            rejected_tcp_quota: counters.rejected_tcp_quota.load(Ordering::Relaxed),
            tcp_pending,
            tcp_bound,
            handshake_failed: counters.handshake_failed.load(Ordering::Relaxed),
        }
    }

    /// Count one failed/timed-out TLS/DTLS handshake (exit log only).
    #[cfg(feature = "tls")]
    pub fn count_handshake_failure(&self) {
        self.counters
            .handshake_failed
            .fetch_add(1, Ordering::Relaxed);
    }

    // -- lookup ------------------------------------------------------------

    fn get(&self, key: &Key, now: Instant) -> Option<Arc<Allocation>> {
        let allocation = lock_read(&self.allocations).get(key).cloned()?;
        if allocation.remaining(now).is_zero() {
            return None;
        }
        Some(allocation)
    }

    fn insert(&self, allocation: Allocation) {
        let key = allocation.key;
        let replaced = lock_write(&self.allocations).insert(key, Arc::new(allocation));
        // Replacing an expired-but-not-yet-swept entry must not leak its port;
        // the old socket dies with the last `Arc` right after this. Its data
        // connections go too (§5.5). Note it is the **previous** entry's port
        // that goes back to its pool — the new allocation's port is in use.
        if let Some(previous) = replaced {
            self.release_port(previous.relay_addr.port(), previous.is_tcp());
            self.close_connections_for(&key);
            drop(previous);
        }
    }

    /// Return one relay port to the pool it came from (idempotent).
    fn release_port(&self, port: u16, tcp: bool) {
        if tcp {
            lock_lock(&self.used_tcp_ports).remove(&port);
        } else {
            lock_lock(&self.used_ports).remove(&port);
        }
    }

    /// Remove one allocation, returning its relay port to the pool and closing
    /// every data connection it owns (RFC 6062 §5.5).
    fn remove(&self, key: &Key) -> Option<Arc<Allocation>> {
        let allocation = lock_write(&self.allocations).remove(key)?;
        self.release_port(allocation.relay_addr.port(), allocation.is_tcp());
        self.close_connections_for(key);
        Some(allocation)
    }

    /// Signal every RFC 6062 data connection of `key` to stop. Pending ones are
    /// dropped with their peer socket; bound ones are closed by their task.
    fn close_connections_for(&self, key: &Key) {
        let ids: Vec<u32> = {
            let connections = lock_lock(&self.connections);
            connections
                .iter()
                .filter(|(_, connection)| connection.allocation == *key)
                .map(|(id, _)| *id)
                .collect()
        };
        for id in ids {
            if let Some(connection) = lock_lock(&self.connections).remove(&id) {
                // The peer task wakes up and tears both halves down; a task that
                // is not running yet (still connecting) simply finds its entry
                // gone when the connect returns.
                let _ = connection.stop.send(true);
                tracing::debug!(id, "rstun: TURN TCP connection closed with its allocation");
            }
        }
    }

    /// Allocations belonging to one closed TCP connection: their writer task
    /// is gone, so keeping them would only leak relay sockets until the TTL.
    pub fn release_connection(
        &self,
        client: SocketAddr,
        server: SocketAddr,
        transport: ClientTransport,
    ) {
        let key = Key {
            client,
            transport,
            server,
        };
        self.remove(&key);
    }

    // -- port pool ---------------------------------------------------------

    /// Take the lowest free port of the range and bind a relay socket on `ip`.
    fn take_port(&self, ip: IpAddr, even: bool) -> Option<Arc<UdpSocket>> {
        let (lo, hi) = self.config.relay_ports;
        let mut used = lock_lock(&self.used_ports);
        for port in lo..=hi {
            if used.contains(&port) {
                continue;
            }
            if even && !port.is_multiple_of(2) {
                continue;
            }
            // A bind failure means the port is held by *someone else* (or the
            // OS ephemeral range): skip it, it is not ours to claim.
            let Ok(socket) = crate::udp_socket(SocketAddr::new(ip, port)) else {
                continue;
            };
            used.insert(port);
            return Some(Arc::new(socket));
        }
        None
    }

    /// Take the lowest free **TCP** relay port and listen on it.
    ///
    /// The listener binds with `SO_REUSEPORT` (see [`crate::tcp_relay_listener`])
    /// so `Connect` can dial out from the same address — RFC 6062 §5.2 requires
    /// the peer data connection to originate from the relayed transport address.
    fn take_tcp_port(&self, ip: IpAddr) -> Option<TcpRelay> {
        let (lo, hi) = self.config.relay_ports;
        let mut used = lock_lock(&self.used_tcp_ports);
        for port in lo..=hi {
            if used.contains(&port) {
                continue;
            }
            let Ok(listener) = crate::tcp_relay_listener(SocketAddr::new(ip, port)) else {
                continue;
            };
            used.insert(port);
            return Some(TcpRelay { listener });
        }
        None
    }

    /// Bind an even relay port and keep the next (odd) port reserved for the
    /// `EVEN-PORT` (R=1) token (RFC 8656 §7.2).
    fn take_even_port_with_reservation(&self, ip: IpAddr) -> Option<(Arc<UdpSocket>, u16)> {
        let (lo, hi) = self.config.relay_ports;
        let mut used = lock_lock(&self.used_ports);
        for port in lo..=hi {
            if !port.is_multiple_of(2) || port == u16::MAX {
                continue;
            }
            let next = port + 1;
            if next > hi || used.contains(&port) || used.contains(&next) {
                continue;
            }
            let Ok(socket) = crate::udp_socket(SocketAddr::new(ip, port)) else {
                continue;
            };
            used.insert(port);
            used.insert(next);
            return Some((Arc::new(socket), next));
        }
        None
    }

    /// Bind the port named by a reservation token, if it is still valid.
    fn take_reserved_port(&self, ip: IpAddr, token: [u8; 8]) -> Option<Arc<UdpSocket>> {
        let now = Instant::now();
        let reservation = lock_lock(&self.reservations).remove(&token)?;
        if reservation.expires_at <= now {
            self.release_port(reservation.port, false);
            return None;
        }
        match crate::udp_socket(SocketAddr::new(ip, reservation.port)) {
            Ok(socket) => Some(Arc::new(socket)),
            Err(_) => {
                // Give the port back rather than leave it reserved forever.
                self.release_port(reservation.port, false);
                None
            }
        }
    }

    // -- sweeper -----------------------------------------------------------

    /// Expire allocations, permissions and channels.
    ///
    /// One scan instead of one sleeping task per entry: the table is bounded by
    /// the quota (hundreds at most), and a single task cannot be starved by
    /// timer pile-up.
    pub fn sweep(&self, now: Instant) -> usize {
        let mut expired: Vec<Key> = Vec::new();
        {
            let allocations = lock_read(&self.allocations);
            for (key, allocation) in allocations.iter() {
                let mut state = lock_write(&allocation.state);
                state.permissions.retain(|_, deadline| *deadline > now);
                state.channels.retain(|_, binding| binding.expires_at > now);
                if state.expires_at <= now {
                    expired.push(*key);
                }
            }
        }
        let mut removed = 0;
        for key in expired {
            if self.remove(&key).is_some() {
                self.counters.expired.fetch_add(1, Ordering::Relaxed);
                removed += 1;
            }
        }

        // Unused EVEN-PORT reservations expire after 30 seconds; the odd port
        // they held goes back to the pool with them.
        let stale: Vec<[u8; 8]> = {
            let reservations = lock_lock(&self.reservations);
            reservations
                .iter()
                .filter(|(_, reservation)| reservation.expires_at <= now)
                .map(|(token, _)| *token)
                .collect()
        };
        for token in stale {
            if let Some(reservation) = lock_lock(&self.reservations).remove(&token) {
                self.release_port(reservation.port, false);
            }
        }

        // RFC 6062 §5.2/§5.4: a peer data connection that never got its
        // `ConnectionBind` MUST be closed after 30 s. Connecting entries are
        // included — a dial that hangs is bounded by `TCP_CONNECT_TIMEOUT`.
        let stale_connections: Vec<u32> = {
            let connections = lock_lock(&self.connections);
            connections
                .iter()
                .filter(|(_, connection)| {
                    connection
                        .expires_at
                        .is_some_and(|deadline| deadline <= now)
                })
                .map(|(id, _)| *id)
                .collect()
        };
        for id in stale_connections {
            if let Some(connection) = lock_lock(&self.connections).remove(&id) {
                let _ = connection.stop.send(true);
                tracing::debug!(
                    id,
                    "rstun: TURN TCP connection expired before ConnectionBind"
                );
            }
        }
        removed
    }

    /// Start the 1-second sweeper; abort the handle at shutdown.
    pub fn start_sweeper(self: &Arc<Self>) -> JoinHandle<()> {
        let turn = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                turn.sweep(Instant::now());
            }
        })
    }

    /// RFC 8656 §7.2 lifetime arithmetic: the server's **default** is the floor;
    /// a request above it is clamped to the configured maximum.
    ///
    /// `config.lifetime` is both knobs in T1: it is the maximum granted and,
    /// capped at the RFC default (600 s), the value used when a client asks for
    /// less. An operator setting `--allocation-lifetime 2` therefore gets 2 s,
    /// while the default 600 keeps coturn's observable behaviour.
    fn granted_lifetime(&self, requested: u32) -> u32 {
        let cap = self.config.lifetime.as_secs() as u32;
        let default = cap.min(DEFAULT_ALLOCATION_LIFETIME_SECONDS as u32);
        let computed = requested.min(cap);
        if computed > default {
            computed
        } else {
            default
        }
    }

    // -- request entry points ---------------------------------------------

    /// Handle a datagram/frame that may be TURN.
    ///
    /// `None` means "not ours": the STUN path keeps deciding (a Binding request,
    /// a malformed frame, an indication we do not answer). `Some(Ok(decision))`
    /// is a fully handled TURN message.
    ///
    /// Async only for RFC 6062 `Connect`, which dials the peer from the relay
    /// address. Every other request completes without awaiting anything, so the
    /// datagram path keeps its old serial behaviour (a TCP allocation cannot
    /// exist on a datagram transport, hence `Connect` is rejected before the
    /// dial on UDP/DTLS).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle(
        &self,
        datagram: &[u8],
        peer: SocketAddr,
        local: SocketAddr,
        client_transport: ClientTransport,
        context: &ServerContext,
        // Writer queue for a connection-oriented transport (TCP/TLS) and for
        // DTLS, whose relayed payload must go back through the same
        // encryption context. `None` on the UDP path, which answers from the
        // listening socket itself.
        sink: Option<&mpsc::Sender<Vec<u8>>>,
    ) -> Option<Result<Decision, protocol::ParseError>> {
        // ChannelData is not STUN: first byte 0x40–0x7F (RFC 8656 §12.4).
        // Over a datagram (UDP/DTLS) the frame is exactly header + payload;
        // over a stream the caller has already de-framed it and calls
        // `handle_channel_data`.
        if client_transport.is_datagram() && is_channel_data(datagram) {
            if datagram.len() < 4 {
                // A truncated header is not a STUN frame either; ignore it
                // rather than index past the datagram.
                return Some(Ok(Decision::Ignore("short TURN ChannelData")));
            }
            let channel = u16::from_be_bytes([datagram[0], datagram[1]]);
            let length = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
            let Some(end) = 4usize.checked_add(length) else {
                return Some(Ok(Decision::Ignore("TURN ChannelData length overflow")));
            };
            if end > datagram.len() {
                // The declared length is longer than the datagram: dropping is
                // mandatory (§12.4) — forwarding a truncated payload would
                // deliver bytes the peer never received.
                return Some(Ok(Decision::Ignore("truncated TURN ChannelData")));
            }
            self.handle_channel_data(
                channel,
                &datagram[4..end],
                peer,
                local,
                client_transport,
                context,
            );
            return Some(Ok(Decision::Ignore("TURN ChannelData")));
        }

        // A malformed frame is the STUN path's error to report: return `None`
        // so `decide` produces the same drop it always did.
        let message = protocol::parse(datagram).ok()?;
        let method = protocol::message_method(message.msg_type);
        let class = protocol::message_class(message.msg_type);

        if class == MessageClass::Indication && method == SEND_METHOD {
            self.send_indication(&message, peer, local, client_transport, context);
            return Some(Ok(Decision::Ignore("TURN Send indication")));
        }
        if class != MessageClass::Request {
            return None;
        }
        // RFC 6062 methods only exist as TURN when the switch is on. Off, they
        // fall through to the STUN path exactly as before (`400`), keeping the
        // classic answers byte-identical.
        let rfc6062 =
            self.config.tcp_relay && matches!(method, CONNECT_METHOD | CONNECTION_BIND_METHOD);
        if !(rfc6062
            || matches!(
                method,
                ALLOCATE_METHOD | REFRESH_METHOD | CREATE_PERMISSION_METHOD | CHANNEL_BIND_METHOD
            ))
        {
            return None;
        }
        Some(Ok(self
            .handle_request(
                datagram,
                &message,
                method,
                peer,
                local,
                client_transport,
                context,
                sink,
            )
            .await))
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_request(
        &self,
        datagram: &[u8],
        message: &protocol::Message<'_>,
        method: u16,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        context: &ServerContext,
        sink: Option<&mpsc::Sender<Vec<u8>>>,
    ) -> Decision {
        let transaction_id = &message.transaction_id;

        // 1. Long-term credentials. `--turn` is refused at startup without
        //    them, so the `None` arm is a defensive 500 rather than a policy.
        let Some(auth) = context.auth.as_ref() else {
            return Decision::Respond(protocol::error_response(
                transaction_id,
                method,
                protocol::ERROR_SERVER_ERROR,
                "Server Error",
            ));
        };
        let identity = match authenticate(auth, datagram, message, peer, method) {
            Ok(identity) => identity,
            // 401 / 438 / 400 — always unsigned (the client has no key yet).
            Err(response) => return Decision::Respond(response),
        };

        // 2. Unknown comprehension-required attributes (RFC 5389 §7.3.1). The
        //    TURN-only set is understood here even though plain Binding does not
        //    know it (and must keep answering 400 for other methods).
        let unknown = turn_unknown_attributes(message.body);
        if !unknown.is_empty() {
            tracing::debug!(
                %peer,
                ?unknown,
                "rstun: TURN request with unknown comprehension-required attributes"
            );
            return Decision::Respond(auth::seal(
                protocol::unknown_attributes_response(transaction_id, method, &unknown),
                &identity,
            ));
        }

        match method {
            ALLOCATE_METHOD => {
                self.allocate(message, peer, local, transport, context, sink, &identity)
            }
            REFRESH_METHOD => self.refresh(message, peer, local, transport, &identity),
            CREATE_PERMISSION_METHOD => {
                self.create_permission(message, peer, local, transport, context, &identity)
            }
            CHANNEL_BIND_METHOD => {
                self.channel_bind(message, peer, local, transport, context, &identity)
            }
            CONNECT_METHOD => {
                self.connect(message, peer, local, transport, context, &identity)
                    .await
            }
            CONNECTION_BIND_METHOD => {
                self.connection_bind(message, peer, local, transport, &identity)
            }
            _ => unreachable!("handle_request is only called for TURN methods"),
        }
    }

    // -- Allocate ----------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn allocate(
        &self,
        message: &protocol::Message<'_>,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        context: &ServerContext,
        sink: Option<&mpsc::Sender<Vec<u8>>>,
        identity: &Identity,
    ) -> Decision {
        let transaction_id = &message.transaction_id;
        let body = message.body;
        let now = Instant::now();

        // REQUESTED-TRANSPORT is mandatory (RFC 8656 §7.2).
        let Some(requested) = attribute(body, ATTR_REQUESTED_TRANSPORT) else {
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        };
        if requested.len() != 4 {
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        // The wire value is `protocol (1 byte) | RFFU (3 bytes)`.
        let tcp_relay = match requested[0] {
            TRANSPORT_UDP => false,
            // RFC 6062: only with the explicit switch, and only on a TCP/TLS
            // control connection (§5.1 step 2). Off, this is the old `442`.
            TRANSPORT_TCP if self.config.tcp_relay => true,
            _ => {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    ERROR_UNSUPPORTED_TRANSPORT,
                    "Unsupported Transport Protocol",
                    identity,
                ));
            }
        };
        if tcp_relay {
            // RFC 6062 §5.1 step 2 / §4.1: a TCP allocation needs a stream
            // control connection, and it MUST NOT carry DONT-FRAGMENT,
            // EVEN-PORT or RESERVATION-TOKEN (there is no datagram to fragment
            // and no port pair to reserve).
            if !is_stream_transport(transport) {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
            if attribute(body, ATTR_DONT_FRAGMENT).is_some()
                || attribute(body, ATTR_EVEN_PORT).is_some()
                || attribute(body, ATTR_RESERVATION_TOKEN).is_some()
            {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
        }

        // `DONT-FRAGMENT` (§18.9, §7.2 step 4): no value part, so a non-zero
        // length is malformed → 400. Whether the bit can actually be set is only
        // knowable once the relay socket exists; that happens below.
        let dont_fragment = match parse_dont_fragment(body) {
            Ok(requested) => requested,
            Err(()) => {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
        };

        let requested_lifetime = match parse_lifetime(body) {
            // RFC 8656 §6.2: an absent (or zero) LIFETIME means "server
            // default"; zero is only an explicit release on Refresh.
            Ok(Some(0)) | Ok(None) => self.config.lifetime.as_secs() as u32,
            Ok(Some(seconds)) => seconds,
            Err(()) => {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
        };
        let granted = self.granted_lifetime(requested_lifetime);

        let key = Key {
            client: peer,
            transport,
            server: local,
        };

        // An existing allocation on this 5-tuple (§6.2): another user must not
        // learn or touch it (441), a *new* transaction is an allocation
        // mismatch (437), and only a retransmission of the creating request is
        // answered idempotently.
        if let Some(existing) = self.get(&key, now) {
            if existing.username != identity.username {
                tracing::debug!(
                    %peer,
                    username = %identity.username,
                    owner = %existing.username,
                    "rstun: TURN Allocate with another user's 5-tuple"
                );
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    ERROR_WRONG_CREDENTIALS,
                    "Wrong Credentials",
                    identity,
                ));
            }
            if existing.transaction_id != *transaction_id {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    ERROR_ALLOCATION_MISMATCH,
                    "Allocation Mismatch",
                    identity,
                ));
            }
            let attributes =
                relay_attributes(&existing, peer, transaction_id, existing.lifetime, None);
            return Decision::Respond(success(
                transaction_id,
                ALLOCATE_METHOD,
                &attributes,
                identity,
                &self.software,
            ));
        }

        // Quotas (§6.2 / §7.2): per authenticated user and per client IP.
        let (per_user, per_ip) = self.quota_counts(&identity.username, peer.ip());
        if per_user >= self.config.max_allocations_per_user
            || per_ip >= self.config.max_allocations_per_ip
        {
            self.counters.rejected_quota.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                %peer,
                username = %identity.username,
                per_user,
                per_ip,
                "rstun: TURN allocation refused by quota"
            );
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                ERROR_ALLOCATION_QUOTA_REACHED,
                "Allocation Quota Reached",
                identity,
            ));
        }

        // The relay address must be reachable by the client: bind the relay
        // socket on the address the client sees, not blindly on `0.0.0.0`.
        let Some(relay_ip) = egress_ip(local, peer) else {
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                protocol::ERROR_SERVER_ERROR,
                "Server Error",
                identity,
            ));
        };
        if relay_ip.is_ipv4() != peer.is_ipv4() {
            self.counters
                .rejected_family
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                ERROR_ADDRESS_FAMILY_NOT_SUPPORTED,
                "Address Family not Supported",
                identity,
            ));
        }
        // `REQUESTED-ADDRESS-FAMILY` (§18.6). Parsing only; the family
        // comparison happens **after** the §7.2 step-5 mutual exclusion below,
        // so `RESERVATION-TOKEN + RAF(<other family>)` is 400 (coturn's
        // answer), not 440 — step 5 precedes step 7.
        let requested_family = match parse_requested_address_family(body) {
            Ok(family) => family,
            Err(()) => {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
        };

        // `EVEN-PORT` (§14.6): an even relay port; with the R bit, the next
        // (odd) port is reserved and its token returned. coturn's
        // `turnutils_uclient` asks for R=1 on every Allocate, so this is the
        // difference between "interoperates" and "420 on the first request".
        // Understanding the attribute keeps the 420 branch for genuinely
        // unknown extensions.
        let even_port_attribute = attribute(body, ATTR_EVEN_PORT);
        let reserve_next = match even_port_attribute {
            None => false,
            Some(value) if value.len() == 1 => value[0] & 0x80 != 0,
            Some(_) => {
                return Decision::Respond(signed_error(
                    transaction_id,
                    ALLOCATE_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
        };
        let wants_even = even_port_attribute.is_some();
        let reservation_token = match attribute(body, ATTR_RESERVATION_TOKEN) {
            None => None,
            Some(value) => match <[u8; 8]>::try_from(value) {
                Ok(token) => Some(token),
                Err(_) => {
                    return Decision::Respond(signed_error(
                        transaction_id,
                        ALLOCATE_METHOD,
                        protocol::ERROR_BAD_REQUEST,
                        "Bad Request",
                        identity,
                    ));
                }
            },
        };
        if reservation_token.is_some() && (wants_even || requested_family.is_some()) {
            // §7.2 step 5, checked **before** the step-7 family comparison:
            // `RESERVATION-TOKEN` is mutually exclusive with `EVEN-PORT` and
            // `REQUESTED-ADDRESS-FAMILY`, and the answer is 400 for any family.
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }

        // §7.2 step 7: the relay address family is already decided by
        // `egress_ip` (it follows the client), so this only has to answer "yes"
        // or `440` — never `420`, which is what `turnutils_uclient -x/-X/-e`
        // used to hit.
        if let Some(family) = requested_family
            && !family_matches(family, relay_ip)
        {
            self.counters
                .rejected_family
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                ERROR_ADDRESS_FAMILY_NOT_SUPPORTED,
                "Address Family not Supported",
                identity,
            ));
        }

        let (relay, new_token) = if tcp_relay {
            // RFC 6062: a dedicated TCP relay port (separate pool, §4 `Connect`
            // dials from it) and no `EVEN-PORT` / `RESERVATION-TOKEN`, which
            // were rejected above.
            match self.take_tcp_port(relay_ip) {
                Some(relay) => (Relay::Tcp(relay), None),
                None => {
                    self.counters.rejected_ports.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        ports = ?self.config.relay_ports,
                        "rstun: TURN TCP relay port range exhausted"
                    );
                    return Decision::Respond(signed_error(
                        transaction_id,
                        ALLOCATE_METHOD,
                        ERROR_INSUFFICIENT_CAPACITY,
                        "Insufficient Capacity",
                        identity,
                    ));
                }
            }
        } else if let Some(token) = reservation_token {
            match self.take_reserved_port(relay_ip, token) {
                Some(relay) => (Relay::Udp(relay), None),
                None => {
                    self.counters.rejected_ports.fetch_add(1, Ordering::Relaxed);
                    return Decision::Respond(signed_error(
                        transaction_id,
                        ALLOCATE_METHOD,
                        ERROR_INSUFFICIENT_CAPACITY,
                        "Insufficient Capacity",
                        identity,
                    ));
                }
            }
        } else if reserve_next {
            match self.take_even_port_with_reservation(relay_ip) {
                Some((relay, next)) => {
                    let token = fresh_reservation_token();
                    lock_lock(&self.reservations).insert(
                        token,
                        Reservation {
                            port: next,
                            expires_at: now + RESERVATION_LIFETIME,
                        },
                    );
                    (Relay::Udp(relay), Some(token))
                }
                None => {
                    self.counters.rejected_ports.fetch_add(1, Ordering::Relaxed);
                    return Decision::Respond(signed_error(
                        transaction_id,
                        ALLOCATE_METHOD,
                        ERROR_INSUFFICIENT_CAPACITY,
                        "Insufficient Capacity",
                        identity,
                    ));
                }
            }
        } else {
            match self.take_port(relay_ip, wants_even) {
                Some(relay) => (Relay::Udp(relay), None),
                None => {
                    self.counters.rejected_ports.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        ports = ?self.config.relay_ports,
                        "rstun: TURN relay port range exhausted"
                    );
                    return Decision::Respond(signed_error(
                        transaction_id,
                        ALLOCATE_METHOD,
                        ERROR_INSUFFICIENT_CAPACITY,
                        "Insufficient Capacity",
                        identity,
                    ));
                }
            }
        };
        let relay_addr = match &relay {
            Relay::Udp(socket) => socket.local_addr(),
            Relay::Tcp(relay) => relay.listener.local_addr(),
        };
        let Ok(relay_addr) = relay_addr else {
            // Unreachable on a bound socket; still return the port to its pool
            // rather than leak a slot in the range.
            if let Some(port) = relay.port() {
                self.release_port(port, tcp_relay);
            }
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                protocol::ERROR_SERVER_ERROR,
                "Server Error",
                identity,
            ));
        };

        // §7.2 step 4 / §18.9: the client asked for every datagram from this
        // relay to carry DF. A socket that refuses the option is an internal
        // failure (`500`), not a protocol one — the capability probe already
        // succeeded, so answering `420` would be a lie. TCP allocations never
        // carry DF (the attribute was rejected above).
        if dont_fragment
            && let Some(socket) = relay.udp()
            && let Err(error) = set_dont_fragment(socket, true)
        {
            self.counters.rejected_df.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, %error, "rstun: TURN relay socket refused DONT-FRAGMENT");
            // Dropping the last `Arc` closes the socket; the port must go back
            // to the pool explicitly (nothing references it yet).
            self.release_port(relay_addr.port(), false);
            return Decision::Respond(signed_error(
                transaction_id,
                ALLOCATE_METHOD,
                protocol::ERROR_SERVER_ERROR,
                "Server Error",
                identity,
            ));
        }

        let sink = match transport {
            ClientTransport::Udp => match context.socket_for(local) {
                Some(socket) => ClientSink::Udp(socket.clone()),
                None => {
                    self.release_port(relay_addr.port(), tcp_relay);
                    return Decision::Respond(signed_error(
                        transaction_id,
                        ALLOCATE_METHOD,
                        protocol::ERROR_SERVER_ERROR,
                        "Server Error",
                        identity,
                    ));
                }
            },
            ClientTransport::Tcp | ClientTransport::Dtls => match sink {
                Some(sink) => ClientSink::Queue(sink.clone()),
                None => {
                    self.release_port(relay_addr.port(), tcp_relay);
                    return Decision::Respond(signed_error(
                        transaction_id,
                        ALLOCATE_METHOD,
                        protocol::ERROR_SERVER_ERROR,
                        "Server Error",
                        identity,
                    ));
                }
            },
        };

        let state = Arc::new(RwLock::new(AllocationState {
            expires_at: now + Duration::from_secs(u64::from(granted)),
            permissions: HashMap::new(),
            channels: HashMap::new(),
            inbound: TokenBucket::new(self.config.bandwidth, now),
            outbound: TokenBucket::new(self.config.bandwidth, now),
        }));
        // A TCP allocation has no relay reader: its data plane is one task per
        // peer data connection (RFC 6062), started by `Connect`.
        let relay_task = match &relay {
            Relay::Udp(relay) => Some(spawn_relay_reader(
                relay.clone(),
                state.clone(),
                sink.clone(),
                peer,
                transport,
                self.counters.clone(),
            )),
            Relay::Tcp(_) => None,
        };
        let allocation = Allocation {
            key,
            relay,
            relay_addr,
            username: identity.username.clone(),
            transaction_id: *transaction_id,
            lifetime: granted,
            client: peer,
            dont_fragment,
            df_lock: Mutex::new(()),
            state,
            relay_task,
        };
        let attributes = relay_attributes(&allocation, peer, transaction_id, granted, new_token);
        self.insert(allocation);
        self.counters.created.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            %peer,
            relay = %relay_addr,
            transport = ?transport,
            lifetime = granted,
            username = %identity.username,
            "rstun: TURN allocation created"
        );
        Decision::Respond(success(
            transaction_id,
            ALLOCATE_METHOD,
            &attributes,
            identity,
            &self.software,
        ))
    }

    // -- Refresh -----------------------------------------------------------

    fn refresh(
        &self,
        message: &protocol::Message<'_>,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        identity: &Identity,
    ) -> Decision {
        let transaction_id = &message.transaction_id;
        let key = Key {
            client: peer,
            transport,
            server: local,
        };
        let now = Instant::now();
        let Some(allocation) = self.get(&key, now) else {
            return Decision::Respond(signed_error(
                transaction_id,
                REFRESH_METHOD,
                ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                identity,
            ));
        };
        // Another user owns this 5-tuple: 441, and the allocation is untouched
        // (a `LIFETIME=0` from that user must not delete it).
        if allocation.username != identity.username {
            return Decision::Respond(signed_error(
                transaction_id,
                REFRESH_METHOD,
                ERROR_WRONG_CREDENTIALS,
                "Wrong Credentials",
                identity,
            ));
        }

        // RFC 8656 §8.2 (MUST): a Refresh carrying `REQUESTED-ADDRESS-FAMILY`
        // whose value does not match the allocation's relay family is a
        // `443 Peer Address Family Mismatch` — not a 200, so a client never
        // believes it switched families. Checked before LIFETIME handling so a
        // mismatched `LIFETIME=0` cannot release the allocation either. A
        // malformed value is 400; a matching one is accepted (the family cannot
        // change, so the value itself has no further effect).
        match parse_requested_address_family(message.body) {
            Ok(None) => {}
            Ok(Some(family)) => {
                if !family_matches(family, allocation.relay_addr().ip()) {
                    self.counters
                        .rejected_family
                        .fetch_add(1, Ordering::Relaxed);
                    return Decision::Respond(signed_error(
                        transaction_id,
                        REFRESH_METHOD,
                        ERROR_PEER_ADDRESS_FAMILY_MISMATCH,
                        "Peer Address Family Mismatch",
                        identity,
                    ));
                }
            }
            Err(()) => {
                return Decision::Respond(signed_error(
                    transaction_id,
                    REFRESH_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
        }

        // RFC 8656 §8.2: an absent LIFETIME means "server default", not 400.
        let lifetime = match parse_lifetime(message.body) {
            Ok(Some(seconds)) => seconds,
            Ok(None) => self.config.lifetime.as_secs() as u32,
            Err(()) => {
                return Decision::Respond(signed_error(
                    transaction_id,
                    REFRESH_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            }
        };

        if lifetime == 0 {
            // `LIFETIME=0` releases immediately: port back to the pool, relay
            // socket dropped, subsequent requests on the key get 437.
            self.remove(&key);
            self.counters.expired.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, "rstun: TURN allocation released (lifetime=0)");
            return Decision::Respond(success(
                transaction_id,
                REFRESH_METHOD,
                &[(ATTR_LIFETIME, 0_u32.to_be_bytes().to_vec())],
                identity,
                &self.software,
            ));
        }

        let granted = self.granted_lifetime(lifetime);
        lock_write(&allocation.state).expires_at = now + Duration::from_secs(u64::from(granted));
        Decision::Respond(success(
            transaction_id,
            REFRESH_METHOD,
            &[(ATTR_LIFETIME, granted.to_be_bytes().to_vec())],
            identity,
            &self.software,
        ))
    }

    // -- CreatePermission --------------------------------------------------

    fn create_permission(
        &self,
        message: &protocol::Message<'_>,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        context: &ServerContext,
        identity: &Identity,
    ) -> Decision {
        let transaction_id = &message.transaction_id;
        let key = Key {
            client: peer,
            transport,
            server: local,
        };
        let now = Instant::now();
        let Some(allocation) = self.get(&key, now) else {
            return Decision::Respond(signed_error(
                transaction_id,
                CREATE_PERMISSION_METHOD,
                ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                identity,
            ));
        };
        if allocation.username != identity.username {
            return Decision::Respond(signed_error(
                transaction_id,
                CREATE_PERMISSION_METHOD,
                ERROR_WRONG_CREDENTIALS,
                "Wrong Credentials",
                identity,
            ));
        }

        let mut peers = Vec::new();
        for attribute in protocol::attributes(message.body)
            .filter(|attribute| attribute.attr_type == ATTR_XOR_PEER_ADDRESS)
        {
            let Some(address) =
                protocol::decode_xor_mapped_address(attribute.value, &message.transaction_id)
            else {
                return Decision::Respond(signed_error(
                    transaction_id,
                    CREATE_PERMISSION_METHOD,
                    protocol::ERROR_BAD_REQUEST,
                    "Bad Request",
                    identity,
                ));
            };
            peers.push(address);
        }
        // At least one XOR-PEER-ADDRESS is required (RFC 8656 §9.1).
        if peers.is_empty() {
            return Decision::Respond(signed_error(
                transaction_id,
                CREATE_PERMISSION_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        if let Some(response) = self.check_peers(
            &allocation,
            &peers,
            local,
            context,
            CREATE_PERMISSION_METHOD,
            transaction_id,
            identity,
        ) {
            return Decision::Respond(response);
        }
        // Validate the **whole** request before touching the table: a single
        // request carrying more peers than the remaining quota must install
        // nothing (RFC 8656 §10.2, 508 Insufficient Capacity).
        let mut state = lock_write(&allocation.state);
        let live = state
            .permissions
            .iter()
            .filter(|(_, deadline)| **deadline > now)
            .count();
        let is_live = |state: &AllocationState, ip: IpAddr| {
            state
                .permissions
                .get(&ip)
                .is_some_and(|deadline| *deadline > now)
        };
        let mut wanted: Vec<IpAddr> = Vec::with_capacity(peers.len());
        for address in &peers {
            let ip = address.ip();
            if !wanted.contains(&ip) && !is_live(&state, ip) {
                wanted.push(ip);
            }
        }
        if live + wanted.len() > self.config.permission_limit {
            drop(state);
            self.counters.rejected_quota.fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CREATE_PERMISSION_METHOD,
                ERROR_INSUFFICIENT_CAPACITY,
                "Insufficient Capacity",
                identity,
            ));
        }
        // Refresh every listed permission (idempotent repeats included).
        for address in &peers {
            state
                .permissions
                .insert(address.ip(), now + PERMISSION_LIFETIME);
        }
        drop(state);
        Decision::Respond(success(
            transaction_id,
            CREATE_PERMISSION_METHOD,
            &[],
            identity,
            &self.software,
        ))
    }

    // -- ChannelBind -------------------------------------------------------

    fn channel_bind(
        &self,
        message: &protocol::Message<'_>,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        context: &ServerContext,
        identity: &Identity,
    ) -> Decision {
        let transaction_id = &message.transaction_id;
        let key = Key {
            client: peer,
            transport,
            server: local,
        };
        let now = Instant::now();
        let Some(allocation) = self.get(&key, now) else {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                identity,
            ));
        };
        if allocation.username != identity.username {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                ERROR_WRONG_CREDENTIALS,
                "Wrong Credentials",
                identity,
            ));
        }
        // RFC 6062 §3: a TCP allocation's data plane is raw bytes keyed by
        // `CONNECTION-ID`; there is no channel to bind. Failing loudly beats a
        // 200 that would never relay.
        if allocation.is_tcp() {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }

        let Some(channel) = attribute(message.body, ATTR_CHANNEL_NUMBER) else {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        };
        if channel.len() != 4 {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        let channel_number = u16::from_be_bytes([channel[0], channel[1]]);
        if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel_number) {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        let Some(peer_address) = attribute(message.body, ATTR_XOR_PEER_ADDRESS)
            .and_then(|value| protocol::decode_xor_mapped_address(value, &message.transaction_id))
        else {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        };
        if let Some(response) = self.check_peers(
            &allocation,
            &[peer_address],
            local,
            context,
            CHANNEL_BIND_METHOD,
            transaction_id,
            identity,
        ) {
            return Decision::Respond(response);
        }

        let mut state = lock_write(&allocation.state);
        // Same channel to a different peer, or the same peer on a different
        // channel: 400 (RFC 8656 §11).
        if state
            .channels
            .get(&channel_number)
            .is_some_and(|binding| binding.expires_at > now && binding.peer != peer_address)
        {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        if state.channels.iter().any(|(number, binding)| {
            *number != channel_number && binding.expires_at > now && binding.peer == peer_address
        }) {
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        // ChannelBind installs/refreshes the permission for the peer's IP
        // (§9.1); it counts against the same limit.
        let live = state
            .permissions
            .iter()
            .filter(|(_, deadline)| **deadline > now)
            .count();
        let permitted = state
            .permissions
            .get(&peer_address.ip())
            .is_some_and(|deadline| *deadline > now);
        if !permitted && live >= self.config.permission_limit {
            drop(state);
            self.counters.rejected_quota.fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CHANNEL_BIND_METHOD,
                ERROR_INSUFFICIENT_CAPACITY,
                "Insufficient Capacity",
                identity,
            ));
        }
        state
            .permissions
            .insert(peer_address.ip(), now + PERMISSION_LIFETIME);
        state.channels.insert(
            channel_number,
            ChannelBinding {
                peer: peer_address,
                expires_at: now + CHANNEL_LIFETIME,
            },
        );
        drop(state);
        Decision::Respond(success(
            transaction_id,
            CHANNEL_BIND_METHOD,
            &[],
            identity,
            &self.software,
        ))
    }

    // -- RFC 6062: Connect / ConnectionBind --------------------------------

    /// `Connect` (RFC 6062 §5.2): dial `XOR-PEER-ADDRESS` from the allocation's
    /// relay address, buffer what the peer says, and hand back a
    /// `CONNECTION-ID` for the pending peer data connection.
    ///
    /// `SOFTWARE` is deliberately **absent** from the success response, which is
    /// what coturn does too (`Connect ok` is 32 bytes there); every other TURN
    /// response keeps it. Recorded in `docs/book/src/turn.md`.
    async fn connect(
        &self,
        message: &protocol::Message<'_>,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        context: &ServerContext,
        identity: &Identity,
    ) -> Decision {
        let transaction_id = &message.transaction_id;
        // §4.1 / §5.2: peer data connections exist only on a TCP/TLS control
        // connection. (A TCP allocation cannot be created anywhere else either,
        // but be explicit rather than answering 437 for a shape we never serve.)
        if !is_stream_transport(transport) {
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECT_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        let key = Key {
            client: peer,
            transport,
            server: local,
        };
        let now = Instant::now();
        let Some(allocation) = self.get(&key, now) else {
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECT_METHOD,
                ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                identity,
            ));
        };
        if allocation.username != identity.username {
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECT_METHOD,
                ERROR_WRONG_CREDENTIALS,
                "Wrong Credentials",
                identity,
            ));
        }
        // Only TCP allocations have peer data connections; anything else on
        // this 5-tuple is an allocation mismatch for this method.
        if !allocation.is_tcp() {
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECT_METHOD,
                ERROR_ALLOCATION_MISMATCH,
                "Allocation Mismatch",
                identity,
            ));
        }
        // §5.2 step 4: `XOR-PEER-ADDRESS` is mandatory and must decode.
        let Some(peer_address) = attribute(message.body, ATTR_XOR_PEER_ADDRESS)
            .and_then(|value| protocol::decode_xor_mapped_address(value, transaction_id))
        else {
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECT_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        };
        // §5.2 step 5 (local policy): the same four address classes and
        // loopback rules as permissions. `check_peers` answers 443 for a family
        // mismatch and 403 for a forbidden address.
        if let Some(response) = self.check_peers(
            &allocation,
            &[peer_address],
            local,
            context,
            CONNECT_METHOD,
            transaction_id,
            identity,
        ) {
            return Decision::Respond(response);
        }
        let (id, stop_rx) = {
            let mut connections = lock_lock(&self.connections);
            // §5.2 steps 2/3: one peer data connection per peer address.
            if connections
                .values()
                .any(|connection| connection.allocation == key && connection.peer == peer_address)
            {
                return Decision::Respond(signed_error(
                    transaction_id,
                    CONNECT_METHOD,
                    ERROR_CONNECTION_ALREADY_EXISTS,
                    "Connection Already Exists",
                    identity,
                ));
            }
            let live = connections
                .values()
                .filter(|connection| connection.allocation == key)
                .count();
            if live >= TCP_MAX_CONNECTIONS_PER_ALLOCATION {
                self.counters
                    .rejected_tcp_quota
                    .fetch_add(1, Ordering::Relaxed);
                return Decision::Respond(signed_error(
                    transaction_id,
                    CONNECT_METHOD,
                    ERROR_INSUFFICIENT_CAPACITY,
                    "Insufficient Capacity",
                    identity,
                ));
            }
            let id = loop {
                let candidate = fresh_connection_id();
                if !connections.contains_key(&candidate) {
                    break candidate;
                }
            };
            let (stop_tx, stop_rx) = watch::channel(false);
            connections.insert(
                id,
                TcpConnection {
                    allocation: key,
                    username: identity.username.clone(),
                    peer: peer_address,
                    state: ConnState::Connecting,
                    // Leave room for the dial's own budget: the sweep must not
                    // reap a connect that is still running.
                    expires_at: Some(now + TCP_CONNECT_TIMEOUT + SWEEP_INTERVAL),
                    stop: stop_tx,
                    bind: None,
                },
            );
            (id, stop_rx)
        };

        // §5.2 step 6: dial from the relayed transport address, bounded by the
        // RFC's ≥30 s budget.
        let dialed = tokio::time::timeout(
            TCP_CONNECT_TIMEOUT,
            dial_from_relay(allocation.relay_addr(), peer_address),
        )
        .await;
        let stream = match dialed {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                lock_lock(&self.connections).remove(&id);
                self.counters
                    .rejected_tcp_connect
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    %peer,
                    %peer_address,
                    relay = %allocation.relay_addr(),
                    %error,
                    "rstun: TURN Connect failed"
                );
                return Decision::Respond(signed_error(
                    transaction_id,
                    CONNECT_METHOD,
                    ERROR_CONNECTION_TIMEOUT_OR_FAILURE,
                    "Connection Timeout or Failure",
                    identity,
                ));
            }
            Err(_elapsed) => {
                lock_lock(&self.connections).remove(&id);
                self.counters
                    .rejected_tcp_connect
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    %peer,
                    %peer_address,
                    "rstun: TURN Connect timed out"
                );
                return Decision::Respond(signed_error(
                    transaction_id,
                    CONNECT_METHOD,
                    ERROR_CONNECTION_TIMEOUT_OR_FAILURE,
                    "Connection Timeout or Failure",
                    identity,
                ));
            }
        };

        // Publish the pending connection and start its task. The task buffers
        // peer→client bytes until `ConnectionBind` hands it the client halves.
        let (bind_tx, bind_rx) = oneshot::channel();
        let installed = {
            let mut connections = lock_lock(&self.connections);
            match connections.get_mut(&id) {
                Some(connection) => {
                    connection.state = ConnState::Pending;
                    connection.expires_at = Some(Instant::now() + TCP_BIND_TIMEOUT);
                    connection.bind = Some(bind_tx);
                    true
                }
                // Swept or its allocation removed while we were dialling.
                None => false,
            }
        };
        if !installed {
            self.counters
                .rejected_tcp_connect
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECT_METHOD,
                ERROR_CONNECTION_TIMEOUT_OR_FAILURE,
                "Connection Timeout or Failure",
                identity,
            ));
        }
        let (peer_reader, peer_writer) = tokio::io::split(stream);
        tokio::spawn(run_tcp_connection(
            id,
            self.connections.clone(),
            self.counters.clone(),
            peer_reader,
            peer_writer,
            stop_rx,
            bind_rx,
        ));

        tracing::debug!(
            %peer,
            %peer_address,
            relay = %allocation.relay_addr(),
            connection_id = id,
            "rstun: TURN Connect established a peer data connection"
        );
        Decision::Respond(success_without_software(
            transaction_id,
            CONNECT_METHOD,
            &[(ATTR_CONNECTION_ID, id.to_be_bytes().to_vec())],
            identity,
        ))
    }

    /// `ConnectionBind` (RFC 6062 §5.4): claim a pending peer data connection
    /// from a **new** connection. The caller turns the stream into a raw-byte
    /// data connection when this returns [`Decision::Bind`].
    fn connection_bind(
        &self,
        message: &protocol::Message<'_>,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        identity: &Identity,
    ) -> Decision {
        let transaction_id = &message.transaction_id;
        // §5.4 step 1: only a stream transport can carry a data connection.
        if !is_stream_transport(transport) {
            self.counters
                .rejected_tcp_bind
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECTION_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        // A control connection that already owns an allocation is not a data
        // connection (RFC 6062 §3: the client data connection is a *new*
        // connection). This also leaves room for the ordinary 401 challenge
        // dance on a fresh connection.
        let key = Key {
            client: peer,
            transport,
            server: local,
        };
        if self.get(&key, Instant::now()).is_some() {
            self.counters
                .rejected_tcp_bind
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECTION_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        // §5.4 step 2: the id must be present, well-formed and pending.
        let Some(value) = attribute(message.body, ATTR_CONNECTION_ID) else {
            self.counters
                .rejected_tcp_bind
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECTION_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        };
        let Ok(bytes) = <[u8; 4]>::try_from(value) else {
            self.counters
                .rejected_tcp_bind
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECTION_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        };
        let id = u32::from_be_bytes(bytes);
        let now = Instant::now();
        let bound = {
            let mut connections = lock_lock(&self.connections);
            match connections.get_mut(&id) {
                Some(connection)
                    if connection.state == ConnState::Pending
                        && connection.username == identity.username
                        && connection.expires_at.is_some_and(|deadline| deadline > now)
                        && self
                            .get(&connection.allocation, now)
                            .is_some_and(|allocation| allocation.is_tcp()) =>
                {
                    // §5.4 step 3: from now on this connection carries raw
                    // application bytes; `ConnectionBind` cannot be repeated.
                    connection.state = ConnState::Bound;
                    connection.expires_at = None;
                    true
                }
                _ => false,
            }
        };
        if !bound {
            self.counters
                .rejected_tcp_bind
                .fetch_add(1, Ordering::Relaxed);
            return Decision::Respond(signed_error(
                transaction_id,
                CONNECTION_BIND_METHOD,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
                identity,
            ));
        }
        tracing::debug!(%id, "rstun: TURN ConnectionBind bound a client data connection");
        Decision::Bind {
            response: success(
                transaction_id,
                CONNECTION_BIND_METHOD,
                &[],
                identity,
                &self.software,
            ),
            id,
        }
    }

    /// Hand the client halves of a bound data connection to its peer task.
    ///
    /// `None` means the connection vanished (allocation removed) between the
    /// bind and this call; the caller just closes the connection.
    pub(crate) fn take_bind(&self, id: u32) -> Option<oneshot::Sender<DataConnection>> {
        lock_lock(&self.connections)
            .get_mut(&id)
            .and_then(|connection| connection.bind.take())
    }

    /// Shared peer validation: family, loopback, permission upper bound.
    ///
    /// Returns the response to send when a peer is not acceptable.
    #[allow(clippy::too_many_arguments)]
    fn check_peers(
        &self,
        allocation: &Allocation,
        peers: &[SocketAddr],
        local: SocketAddr,
        context: &ServerContext,
        method: u16,
        transaction_id: &TransactionId,
        identity: &Identity,
    ) -> Option<Vec<u8>> {
        for peer in peers {
            let same_family = peer.is_ipv4() == allocation.relay_addr().is_ipv4();
            if !same_family {
                self.counters
                    .rejected_family
                    .fetch_add(1, Ordering::Relaxed);
                return Some(signed_error(
                    transaction_id,
                    method,
                    ERROR_PEER_ADDRESS_FAMILY_MISMATCH,
                    "Peer Address Family Mismatch",
                    identity,
                ));
            }
            if *peer == allocation.relay_addr() || self.is_own_endpoint(*peer, local, context) {
                self.counters
                    .rejected_loopback
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    peer = %peer,
                    "rstun: TURN peer points at this server, refusing (loopback)"
                );
                return Some(signed_error(
                    transaction_id,
                    method,
                    ERROR_FORBIDDEN,
                    "Forbidden",
                    identity,
                ));
            }
        }
        None
    }

    /// Would relaying to `address` point back at this host's own protocol
    /// surface, or at a destination class that must never be relayed to?
    ///
    /// Rejected unconditionally:
    /// * unspecified (`0.0.0.0` / `::`) and multicast destinations — never a
    ///   legitimate peer and a known amplification vector;
    /// * any address equal to a bound listener socket (the request path itself)
    ///   or to the socket the request arrived on.
    ///
    /// Rejected **unless** the request arrived on a loopback socket:
    /// * loopback peers. With `--listen 0.0.0.0:3478` the exact-address checks
    ///   all miss `127.0.0.1:3478` (the bound address is `0.0.0.0:3478`), so the
    ///   wildcard case is the one that matters: a public TURN server must not be
    ///   usable as a bridge to localhost-only services. Deliberately allowing
    ///   loopback when the listener itself is loopback keeps local development
    ///   and the `turnutils_uclient -y` matrix working.
    ///
    /// Other allocations' *relay* addresses stay allowed: client-to-client
    /// relaying through one TURN server is the standard `-y` / same-NAT WebRTC
    /// case, and a relay socket only talks to peers that already hold a
    /// permission (the caller checks the allocation's own relay separately).
    ///
    /// Known limitation: the host's own **public** IP cannot be enumerated
    /// without interface discovery (a new dependency, out of scope for T1), so
    /// `peer = <this host's public IP>:<port>` is not detectable. See README.
    ///
    /// The loopback decision is made from the **bound** listener set, not from
    /// `local`: for TURN-over-TCP `stream.local_addr()` is concrete even when
    /// the listener is `0.0.0.0`, so using it would let a wildcard deployment
    /// reach localhost over TCP.
    fn loopback_peers_allowed(context: &ServerContext, local: SocketAddr) -> bool {
        if context.udp.is_empty() {
            // Tests / exotic embeddings: fall back to the socket that received
            // the request (the production path always has the UDP listeners).
            return local.ip().is_loopback();
        }
        context
            .udp
            .iter()
            .all(|(bound, _)| bound.ip().is_loopback())
    }

    fn is_own_endpoint(
        &self,
        address: SocketAddr,
        local: SocketAddr,
        context: &ServerContext,
    ) -> bool {
        // Normalise IPv4-mapped IPv6 first: `is_loopback()` / `is_unspecified()` /
        // `is_multicast()` all return false for `::ffff:127.0.0.1`, which would
        // otherwise skip every address-class check below.
        let ip = match address.ip() {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            ip => ip,
        };
        if ip.is_unspecified() || ip.is_multicast() {
            return true;
        }
        if matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()) {
            return true;
        }
        if ip.is_loopback() && !Self::loopback_peers_allowed(context, local) {
            return true;
        }
        // A wildcard listener cannot be matched by address, so ask the kernel
        // which source it would use to reach the peer: if that is the peer's own
        // address, the peer is on this host and the port is one of ours.
        if context
            .udp
            .iter()
            .any(|(bound, _)| bound.port() == address.port())
            && egress_ip(local, address) == Some(ip)
        {
            return true;
        }
        address == local || context.udp.iter().any(|(bound, _)| *bound == address)
    }

    // -- data plane --------------------------------------------------------

    /// `Send` indication: client → peer, only through a live permission.
    fn send_indication(
        &self,
        message: &protocol::Message<'_>,
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        context: &ServerContext,
    ) {
        let key = Key {
            client: peer,
            transport,
            server: local,
        };
        let now = Instant::now();
        let Some(allocation) = self.get(&key, now) else {
            return;
        };
        // RFC 6062: a TCP allocation relays raw bytes over its bound data
        // connections; a `Send` indication has no meaning and silently
        // forwarding it would be a lie. Counted, not answered (§7.3).
        if allocation.is_tcp() {
            self.counters
                .rejected_tcp_send
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(peer_address) = attribute(message.body, ATTR_XOR_PEER_ADDRESS)
            .and_then(|value| protocol::decode_xor_mapped_address(value, &message.transaction_id))
        else {
            return;
        };
        let Some(data) = attribute(message.body, ATTR_DATA) else {
            return;
        };
        // No permission → silent discard (§7.3); never answer an indication.
        let permitted = lock_read(&allocation.state)
            .permissions
            .get(&peer_address.ip())
            .is_some_and(|deadline| *deadline > now);
        if !permitted {
            return;
        }
        if self.is_own_endpoint(peer_address, local, context) {
            self.counters
                .rejected_loopback
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        // `DONT-FRAGMENT` in a `Send` indication (§11.2). Two shapes make the
        // indication **undeliverable**, and both are silent discards (an
        // indication has no error response, §7.3):
        //   * a value part — §18.9 gives this attribute no value at all;
        //   * a `setsockopt` failure — §11.2: the server then "acts as if the
        //     DONT-FRAGMENT attribute is an unknown comprehension-required
        //     attribute (and thus the Send indication is discarded)".
        let per_datagram_df = match parse_dont_fragment(message.body) {
            Ok(requested) => requested,
            Err(()) => {
                self.counters.rejected_df.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%peer, "rstun: TURN Send dropped: malformed DONT-FRAGMENT");
                return;
            }
        };
        if per_datagram_df && !allocation.dont_fragment {
            // Only DF-carrying `Send`s take this lock: two of them may be
            // handled concurrently (`--max-inflight`) and the second must not
            // observe the first's temporary setting. Plain `Send`s and
            // `ChannelData` stay lock-free (known limitation, documented in
            // `.trellis/spec/backend/turn.md`).
            let _guard = lock_lock(&allocation.df_lock);
            let Some(relay) = allocation.relay.udp() else {
                return;
            };
            if let Err(error) = set_dont_fragment(relay, true) {
                self.counters.rejected_df.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    relay = %allocation.relay_addr,
                    %error,
                    "rstun: TURN Send dropped: DONT-FRAGMENT could not be applied"
                );
                return;
            }
            self.relay_to_peer(&allocation, data, peer_address);
            if let Err(error) = set_dont_fragment(relay, false) {
                // The bit stays on for this allocation: a later datagram may be
                // sent with DF it did not ask for, which is harmless, so only
                // log it.
                tracing::warn!(
                    relay = %allocation.relay_addr,
                    %error,
                    "rstun: TURN relay socket kept DONT-FRAGMENT"
                );
            }
            return;
        }
        self.relay_to_peer(&allocation, data, peer_address);
    }

    /// Client → peer relay of one payload, gated by the allocation's inbound
    /// bandwidth bucket (`--turn-bandwidth`).
    ///
    /// Over the cap the payload is dropped and counted; the allocation stays
    /// alive (a bandwidth spike must not tear down a call).
    fn relay_to_peer(
        &self,
        allocation: &Allocation,
        data: &[u8],
        peer_address: SocketAddr,
    ) -> bool {
        // A TCP allocation has no datagram relay path: the data plane is the
        // bound connection's raw-byte copy, not `Send`/`ChannelData`.
        let Some(relay) = allocation.relay.udp() else {
            self.counters
                .rejected_tcp_send
                .fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let now = Instant::now();
        let allowed = lock_write(&allocation.state)
            .inbound
            .try_take(now, data.len());
        if !allowed {
            self.counters
                .bytes_dropped_in
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            tracing::debug!(
                relay = %allocation.relay_addr,
                bytes = data.len(),
                "rstun: TURN inbound bandwidth cap, payload dropped"
            );
            return false;
        }
        if relay.try_send_to(data, peer_address).is_ok() {
            self.counters
                .bytes_in
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// `ChannelData` from the client: channel hit → relay, no STUN parsing.
    pub(crate) fn handle_channel_data(
        &self,
        channel: u16,
        data: &[u8],
        peer: SocketAddr,
        local: SocketAddr,
        transport: ClientTransport,
        context: &ServerContext,
    ) {
        let key = Key {
            client: peer,
            transport,
            server: local,
        };
        let now = Instant::now();
        let Some(allocation) = self.get(&key, now) else {
            return;
        };
        // A TCP allocation has no channels (`ChannelBind` is 400), but a client
        // could still send a ChannelData frame: discard and count it.
        if allocation.is_tcp() {
            self.counters
                .rejected_tcp_send
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let peer_address = {
            let state = lock_read(&allocation.state);
            let Some(binding) = state.channels.get(&channel) else {
                return;
            };
            if binding.expires_at <= now {
                return;
            }
            let permitted = state
                .permissions
                .get(&binding.peer.ip())
                .is_some_and(|deadline| *deadline > now);
            if !permitted {
                return;
            }
            binding.peer
        };
        if self.is_own_endpoint(peer_address, local, context) {
            self.counters
                .rejected_loopback
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.relay_to_peer(&allocation, data, peer_address);
    }

    fn quota_counts(&self, username: &str, ip: IpAddr) -> (usize, usize) {
        let allocations = lock_read(&self.allocations);
        let mut per_user = 0;
        let mut per_ip = 0;
        for allocation in allocations.values() {
            if allocation.username == username {
                per_user += 1;
            }
            if allocation.client.ip() == ip {
                per_ip += 1;
            }
        }
        (per_user, per_ip)
    }
}

// ---------------------------------------------------------------------------
// RFC 6062 data plane
// ---------------------------------------------------------------------------

/// Dial `peer` with `local` as the source address.
///
/// RFC 6062 §5.2: the peer data connection must originate from the relayed
/// transport address. That means binding a second socket to the port the relay
/// **listener** already holds, which the kernel only allows when both sockets
/// set `SO_REUSEPORT` (`crate::tcp_relay_listener` does the same for the
/// listener). Platforms without it — Windows — fall back to an ephemeral source
/// port; the connection itself still works, only the peer's view of the source
/// address differs. Recorded in `docs/book/src/turn.md`.
async fn dial_from_relay(local: SocketAddr, peer: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = if peer.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Share the relay listener's port so the peer sees the relayed transport
    // address as the source (RFC 6062 §5.2). `RELAY_SOURCE_PORT_BOUND` is the
    // predicate tests read; on Windows it is false (no `SO_REUSEPORT`) and the
    // dial below keeps an ephemeral source port.
    if RELAY_SOURCE_PORT_BOUND {
        let _ = socket.set_reuseaddr(true);
        #[cfg(unix)]
        let _ = socket.set_reuseport(true);
    }
    if let Err(error) = socket.bind(local) {
        tracing::debug!(
            %local,
            %peer,
            %error,
            "rstun: TURN Connect cannot bind the relay address; using an ephemeral source port"
        );
    }
    socket.connect(peer).await
}

/// One peer data connection's task: buffer until bound, then copy both ways.
///
/// Lifecycle (RFC 6062 §5.5):
/// * either side finishing its write half (`EOF`) shuts down the other side's
///   write half, and the copy continues in the other direction;
/// * an error on either side, the `stop` signal (allocation removed) or the
///   bind deadline ending closes both;
/// * the table entry is removed when the task ends.
#[allow(clippy::too_many_arguments)]
async fn run_tcp_connection(
    id: u32,
    connections: Arc<Mutex<HashMap<u32, TcpConnection>>>,
    counters: Arc<Counters>,
    mut peer_reader: tokio::io::ReadHalf<TcpStream>,
    mut peer_writer: tokio::io::WriteHalf<TcpStream>,
    mut stop: watch::Receiver<bool>,
    mut halves: oneshot::Receiver<DataConnection>,
) {
    // Phase 1: `Connect` has succeeded but the client has not bound yet. RFC
    // 6062 §5.2 requires buffering what the peer sends, with a local cap (§7).
    let mut prebuffer: Vec<u8> = Vec::new();
    let mut chunk = vec![0_u8; 8192];
    let data = loop {
        tokio::select! {
            biased;
            _ = stop.changed() => return finish_tcp_connection(&connections, id),
            received = &mut halves => match received {
                Ok(data) => break data,
                Err(_) => return finish_tcp_connection(&connections, id),
            },
            read = peer_reader.read(&mut chunk) => match read {
                Ok(0) => return finish_tcp_connection(&connections, id),
                Ok(length) => {
                    if prebuffer.len() + length > TCP_PREBIND_BUFFER {
                        counters.rejected_tcp_buffer.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(id, "rstun: TURN pre-bind buffer overflow, closing");
                        return finish_tcp_connection(&connections, id);
                    }
                    prebuffer.extend_from_slice(&chunk[..length]);
                }
                Err(_) => return finish_tcp_connection(&connections, id),
            },
        }
    };
    let DataConnection {
        mut reader,
        sender,
        writer_task,
        _permit: _inflight,
    } = data;

    // Phase 2: drain the pre-bind buffer through the same queue the client's
    // write half consumes, so ordering with the bind response is preserved.
    if !prebuffer.is_empty() {
        let buffered = prebuffer.len();
        if sender.send(prebuffer).await.is_err() {
            return finish_tcp_connection(&connections, id);
        }
        counters
            .bytes_out
            .fetch_add(buffered as u64, Ordering::Relaxed);
    }

    // Phase 3: bidirectional copy. Each direction is `Ok(())` on a clean EOF —
    // a clean EOF only half-closes the connection (RFC 6062 §5.5) — and `Err`
    // on a socket error, which closes both.
    let mut client_to_peer = {
        let counters = counters.clone();
        Box::pin(async move {
            let mut chunk = vec![0_u8; 16384];
            loop {
                let length = match reader.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(length) => length,
                    Err(_) => return Err(()),
                };
                if peer_writer.write_all(&chunk[..length]).await.is_err() {
                    return Err(());
                }
                counters
                    .bytes_in
                    .fetch_add(length as u64, Ordering::Relaxed);
            }
            // Client half-closed its write side: pass the EOF on to the peer.
            let _ = peer_writer.shutdown().await;
            Ok(())
        })
    };
    let mut peer_to_client = {
        let counters = counters.clone();
        Box::pin(async move {
            let mut chunk = vec![0_u8; 16384];
            loop {
                let length = match peer_reader.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(length) => length,
                    Err(_) => return Err(()),
                };
                if sender.send(chunk[..length].to_vec()).await.is_err() {
                    return Err(());
                }
                counters
                    .bytes_out
                    .fetch_add(length as u64, Ordering::Relaxed);
            }
            // Peer half-closed: dropping the last sender makes the writer task
            // shut the client's write half down (the half-close the client sees).
            drop(sender);
            let _ = writer_task.await;
            Ok(())
        })
    };

    let mut client_to_peer_done = false;
    let mut peer_to_client_done = false;
    while !(client_to_peer_done && peer_to_client_done) {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            result = &mut client_to_peer, if !client_to_peer_done => {
                client_to_peer_done = true;
                if result.is_err() {
                    break;
                }
            }
            result = &mut peer_to_client, if !peer_to_client_done => {
                peer_to_client_done = true;
                if result.is_err() {
                    break;
                }
            }
        }
    }
    finish_tcp_connection(&connections, id);
}

/// Remove a data connection's entry; the caller's task is about to end.
fn finish_tcp_connection(connections: &Mutex<HashMap<u32, TcpConnection>>, id: u32) {
    lock_lock(connections).remove(&id);
}

/// A `CONNECTION-ID` no live connection uses (checked by the caller) and that
/// is never `0`, which clients treat as "unset".
fn fresh_connection_id() -> u32 {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let id = (nanos ^ sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15)) as u32;
    if id == 0 { 1 } else { id }
}

// ---------------------------------------------------------------------------
// Relay reader (peer → client)
// ---------------------------------------------------------------------------

/// Forward datagrams arriving on the relay socket to the client.
///
/// * permission for the peer's IP is mandatory — a stranger that learned the
///   relayed address cannot make us talk to the client (§8);
/// * a live channel binding picks `ChannelData`, otherwise a `Data` indication;
/// * the task ends when the allocation expires or its `Arc`/socket goes away.
fn spawn_relay_reader(
    relay: Arc<UdpSocket>,
    state: Arc<RwLock<AllocationState>>,
    sink: ClientSink,
    client: SocketAddr,
    transport: ClientTransport,
    counters: Arc<Counters>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65535];
        loop {
            let (length, source) = match relay.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(error) => {
                    tracing::debug!(%client, %error, "rstun: TURN relay recv_from failed");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
            };
            let now = Instant::now();
            let (permitted, channel) = {
                let state = lock_read(&state);
                if state.expires_at <= now {
                    break;
                }
                let permitted = state
                    .permissions
                    .get(&source.ip())
                    .is_some_and(|deadline| *deadline > now);
                let channel = state
                    .channels
                    .iter()
                    .find(|(_, binding)| binding.expires_at > now && binding.peer == source)
                    .map(|(number, _)| *number);
                (permitted, channel)
            };
            if !permitted {
                continue;
            }
            // Peer → client bandwidth bucket. Over the cap: drop and count,
            // keep the allocation (and the call) alive.
            let allowed = lock_write(&state).outbound.try_take(now, length);
            if !allowed {
                counters
                    .bytes_dropped_out
                    .fetch_add(length as u64, Ordering::Relaxed);
                tracing::debug!(
                    %client,
                    %source,
                    bytes = length,
                    "rstun: TURN outbound bandwidth cap, payload dropped"
                );
                continue;
            }
            let payload = match channel {
                Some(channel) => channel_data_frame(channel, &buffer[..length], transport),
                None => data_indication(source, &buffer[..length]),
            };
            let sent = match &sink {
                ClientSink::Udp(socket) => socket.send_to(&payload, client).await.is_ok(),
                // Bounded queue: a client that stops reading loses datagrams
                // (relayed data is best-effort) but cannot grow memory.
                ClientSink::Queue(writer) => writer.try_send(payload).is_ok(),
            };
            if sent {
                counters
                    .bytes_out
                    .fetch_add(length as u64, Ordering::Relaxed);
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// First byte of a `ChannelData` frame is in `0x40..=0x7F` (RFC 8656 §12.4).
pub fn is_channel_data(frame: &[u8]) -> bool {
    frame.first().is_some_and(|byte| byte & 0xC0 == 0x40)
}

/// True when the *first* byte says ChannelData (TCP framing reads it alone).
pub fn is_channel_data_prefix(byte: u8) -> bool {
    byte & 0xC0 == 0x40
}

/// `ChannelData` framing: 4-byte header + payload; TCP pads to 4 bytes (§12.5).
fn channel_data_frame(channel: u16, data: &[u8], transport: ClientTransport) -> Vec<u8> {
    // A datagram transport carries header + payload (RFC 8656 §12.4); only a
    // stream transport pads to a 4-byte boundary (§12.5).
    let padding = if transport.is_datagram() {
        0
    } else {
        (4 - data.len() % 4) % 4
    };
    let mut frame = Vec::with_capacity(4 + data.len() + padding);
    frame.extend_from_slice(&channel.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame.resize(frame.len() + padding, 0);
    frame
}

/// `Data` indication: `XOR-PEER-ADDRESS` + `DATA` (RFC 8656 §7.3).
fn data_indication(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
    let transaction_id = fresh_transaction_id();
    let mut body = Vec::with_capacity(32 + data.len());
    protocol::push_attribute(
        &mut body,
        ATTR_XOR_PEER_ADDRESS,
        &protocol::xor_mapped_address_value(peer, &transaction_id),
    );
    protocol::push_attribute(&mut body, ATTR_DATA, data);
    protocol::encode_message(
        protocol::message_type(DATA_METHOD, MessageClass::Indication),
        &transaction_id,
        &body,
    )
}

/// Reply attributes of a successful `Allocate` (RFC 8656 §7.2).
fn relay_attributes(
    allocation: &Allocation,
    peer: SocketAddr,
    transaction_id: &TransactionId,
    lifetime: u32,
    reservation_token: Option<[u8; 8]>,
) -> Vec<(u16, Vec<u8>)> {
    let mut attributes = vec![
        (
            ATTR_XOR_RELAYED_ADDRESS,
            protocol::xor_mapped_address_value(allocation.relay_addr(), transaction_id),
        ),
        (
            protocol::ATTR_XOR_MAPPED_ADDRESS,
            protocol::xor_mapped_address_value(peer, transaction_id),
        ),
        (ATTR_LIFETIME, lifetime.to_be_bytes().to_vec()),
    ];
    if let Some(token) = reservation_token {
        attributes.push((ATTR_RESERVATION_TOKEN, token.to_vec()));
    }
    attributes
}

fn success(
    transaction_id: &TransactionId,
    method: u16,
    attributes: &[(u16, Vec<u8>)],
    identity: &Identity,
    software: &str,
) -> Vec<u8> {
    let mut body = Vec::new();
    for (attr_type, value) in attributes {
        protocol::push_attribute(&mut body, *attr_type, value);
    }
    // RFC 8656 §14.10: SHOULD on every success response. Placed last (before
    // the integrity attribute `seal` appends), like the STUN path.
    protocol::push_attribute(&mut body, protocol::ATTR_SOFTWARE, software.as_bytes());
    let frame = protocol::encode_message(
        protocol::message_type(method, MessageClass::SuccessResponse),
        transaction_id,
        &body,
    );
    auth::seal(frame, identity)
}

/// A success response **without** `SOFTWARE`.
///
/// Only RFC 6062 `Connect` uses it: coturn's own `Connect ok` is exactly
/// `CONNECTION-ID + MESSAGE-INTEGRITY` (32 bytes), and matching that keeps the
/// interop comparison meaningful. Every other response still appends
/// `SOFTWARE` (§14.10 SHOULD); the deviation is recorded in
/// `docs/book/src/turn.md`.
fn success_without_software(
    transaction_id: &TransactionId,
    method: u16,
    attributes: &[(u16, Vec<u8>)],
    identity: &Identity,
) -> Vec<u8> {
    let mut body = Vec::new();
    for (attr_type, value) in attributes {
        protocol::push_attribute(&mut body, *attr_type, value);
    }
    auth::seal(
        protocol::encode_message(
            protocol::message_type(method, MessageClass::SuccessResponse),
            transaction_id,
            &body,
        ),
        identity,
    )
}

fn signed_error(
    transaction_id: &TransactionId,
    method: u16,
    code: u16,
    reason: &str,
    identity: &Identity,
) -> Vec<u8> {
    auth::seal(
        protocol::error_response(transaction_id, method, code, reason),
        identity,
    )
}

/// First value of `attr_type` in `body`, if any.
fn attribute(body: &[u8], attr_type: u16) -> Option<&[u8]> {
    protocol::attributes(body)
        .find(|attribute| attribute.attr_type == attr_type)
        .map(|attribute| attribute.value)
}

/// `Ok(None)` = absent; `Ok(Some(seconds))` = present and well formed;
/// `Err(())` = present with the wrong length.
fn parse_lifetime(body: &[u8]) -> Result<Option<u32>, ()> {
    match attribute(body, ATTR_LIFETIME) {
        None => Ok(None),
        Some(value) if value.len() == 4 => Ok(Some(u32::from_be_bytes([
            value[0], value[1], value[2], value[3],
        ]))),
        Some(_) => Err(()),
    }
}

/// `REQUESTED-ADDRESS-FAMILY` (§18.6): `Family (1 byte) | Reserved (3 bytes)`.
///
/// `Ok(None)` = absent; `Ok(Some(family))` = present and well formed — the
/// reserved bits are ignored, as §18.6 requires; `Err(())` = present with the
/// wrong length.
fn parse_requested_address_family(body: &[u8]) -> Result<Option<u8>, ()> {
    match attribute(body, ATTR_REQUESTED_ADDRESS_FAMILY) {
        None => Ok(None),
        Some(value) if value.len() == 4 => Ok(Some(value[0])),
        Some(_) => Err(()),
    }
}

/// `DONT-FRAGMENT` (§18.9) has **no value part**.
///
/// `Ok(false)` = absent, `Ok(true)` = present and well formed, `Err(())` =
/// present with a value (the attribute carries no bytes, so any length but 0
/// is malformed).
fn parse_dont_fragment(body: &[u8]) -> Result<bool, ()> {
    match attribute(body, ATTR_DONT_FRAGMENT) {
        None => Ok(false),
        Some([]) => Ok(true),
        Some(_) => Err(()),
    }
}

/// Set (or clear) the IPv4/IPv6 **Don't Fragment** bit on a relay socket.
///
/// `socket2` has no MTU-discover setter, so this is the raw `setsockopt`:
///
/// * Linux — `IP_MTU_DISCOVER = IP_PMTUDISC_DO` (DF set, PMTU enforced) and
///   back to `IP_PMTUDISC_WANT` (the kernel default) to clear it; IPv6 sockets
///   use the same values under `IPV6_MTU_DISCOVER`.
/// * macOS/iOS — `IP_DONTFRAG` / `IPV6_DONTFRAG`, an `int` of 1 or 0.
/// * Everything else (Windows, FreeBSD & co.) — `Unsupported`. Those targets
///   never get here for `Allocate` (`DONT_FRAGMENT_SUPPORTED` is false, so the
///   attribute is answered `420` first); a `Send` indication carrying it is
///   discarded, which is exactly §11.2's "treat it as unknown".
fn set_dont_fragment(socket: &UdpSocket, on: bool) -> std::io::Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
    {
        let _ = (socket, on);
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    {
        use std::os::fd::AsRawFd;

        // A real `setsockopt` failure cannot be provoked from a test on a
        // healthy socket, and §11.2's "cannot set DF ⇒ discard the indication"
        // branch has to stay covered. Production builds compile the hook out.
        #[cfg(test)]
        if df_failure::failing() {
            return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        }

        // The IPv4 and IPv6 options are distinct on both platforms; an
        // `AF_INET6` relay socket needs the v6 spelling (macOS rejects the v4
        // one there).
        let ipv6 = socket.local_addr().is_ok_and(|address| address.is_ipv6());

        #[cfg(target_os = "linux")]
        let (level, name, value) = {
            let (level, name) = if ipv6 {
                (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
            } else {
                (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
            };
            let value = if on {
                libc::IP_PMTUDISC_DO
            } else {
                libc::IP_PMTUDISC_WANT
            };
            (level, name, value)
        };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let (level, name, value) = {
            let (level, name) = if ipv6 {
                (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
            } else {
                (libc::IPPROTO_IP, libc::IP_DONTFRAG)
            };
            (level, name, i32::from(on))
        };

        // SAFETY: the fd is owned by `socket` for the whole call (the borrow
        // keeps it alive) and the option value is a live, correctly sized
        // `c_int`, read by the kernel for exactly `size_of_val` bytes.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                std::ptr::from_ref(&value).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

/// Test-only switch that makes [`set_dont_fragment`] fail, so the §11.2
/// "cannot set DF ⇒ discard the `Send` indication" path is exercised instead of
/// only read. Thread-local: `#[tokio::test]` runs a current-thread runtime, so
/// the server task sees the same flag, and parallel tests cannot interfere.
///
/// Same platform gate as the callers: on a target without a `setsockopt` path
/// nothing would ever call it.
#[cfg(all(test, any(target_os = "linux", target_os = "macos", target_os = "ios")))]
pub(crate) mod df_failure {
    use std::cell::Cell;

    thread_local! {
        static FAILING: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn set(failing: bool) {
        FAILING.with(|flag| flag.set(failing));
    }

    pub(crate) fn failing() -> bool {
        FAILING.with(Cell::get)
    }
}

/// Does `family` (0x01 IPv4 / 0x02 IPv6) name the address family of `relay`?
///
/// Anything else (including `0x00` and `0x03`) is "not supported", which is
/// what drives both the `Allocate` `440` (§7.2 step 7) and the `Refresh` `443`
/// (§8.2). The relay family itself follows the client (§5), so an IPv6 client
/// on an IPv6 listener matches `0x02`.
fn family_matches(family: u8, relay: IpAddr) -> bool {
    match family {
        0x01 => relay.is_ipv4(),
        0x02 => relay.is_ipv6(),
        _ => false,
    }
}

/// Unknown comprehension-required attributes *in the TURN dialect*.
fn turn_unknown_attributes(body: &[u8]) -> Vec<u16> {
    turn_unknown_attributes_with(body, DONT_FRAGMENT_SUPPORTED, is_tcp_allocate(body))
}

/// Is this body a `TCP` `Allocate` (`REQUESTED-TRANSPORT = 6`, RFC 6062)?
///
/// Used by the `420` gate only: RFC 6062 §5.1 step 3 makes `DONT-FRAGMENT` on a
/// TCP `Allocate` a `400 Bad Request` **on every platform**, so the gate must
/// not turn it into a `420` first — even where the platform cannot set the DF
/// bit (Windows, FreeBSD & co.). The `400` itself comes from [`Turn::allocate`],
/// which rejects the attribute before any port or platform logic runs. With the
/// `--turn-tcp-relay` switch off the same shape reaches the old `442` answer on
/// every platform (Windows used to say `420` only because of the gate).
/// A malformed `REQUESTED-TRANSPORT` is deliberately *not* treated as TCP here:
/// it is answered `400` by the allocation path anyway, and the classic UDP
/// column must stay byte-identical.
fn is_tcp_allocate(body: &[u8]) -> bool {
    attribute(body, ATTR_REQUESTED_TRANSPORT)
        .is_some_and(|value| value.len() == 4 && value[0] == TRANSPORT_TCP)
}

/// The same decision table with the platform capability **injected**, so both
/// columns are reachable from a test on any host: the `false` column is exactly
/// what a Windows or FreeBSD build does (there DF stays unknown → `420`).
///
/// `tcp_allocate` says the request is `Allocate` with `REQUESTED-TRANSPORT = 6`;
/// on that shape `DONT-FRAGMENT` is **understood** even when
/// `dont_fragment_supported` is false, because RFC 6062 §5.1 step 3 answers it
/// `400` (attribute not allowed on a TCP allocation) instead of `420`.
fn turn_unknown_attributes_with(
    body: &[u8],
    dont_fragment_supported: bool,
    tcp_allocate: bool,
) -> Vec<u16> {
    let mut unknown: Vec<u16> = Vec::new();
    for attribute in protocol::attributes(body) {
        let attr_type = attribute.attr_type;
        if !protocol::is_comprehension_required(attr_type) {
            continue;
        }
        if protocol::is_known_attribute(attr_type)
            // `DONT-FRAGMENT` is understood only where the DF bit can actually
            // be set (§7.2 step 4): elsewhere it must stay unknown → 420.
            || (dont_fragment_supported && attr_type == ATTR_DONT_FRAGMENT)
            // RFC 6062 §5.1 step 3: a TCP `Allocate` carrying it is `400` on
            // every platform, so it must not become `420` on the platforms that
            // cannot set the bit (Windows).
            || (tcp_allocate && attr_type == ATTR_DONT_FRAGMENT)
            || matches!(
                attr_type,
                ATTR_CHANNEL_NUMBER
                    | ATTR_LIFETIME
                    | ATTR_XOR_PEER_ADDRESS
                    | ATTR_DATA
                    | ATTR_XOR_RELAYED_ADDRESS
                    | ATTR_REQUESTED_TRANSPORT
                    | ATTR_EVEN_PORT
                    | ATTR_RESERVATION_TOKEN
                    | ATTR_REQUESTED_ADDRESS_FAMILY
                    // RFC 6062 §6.2.1: understood by this server (the `Connect`
                    // / `ConnectionBind` paths), so a request carrying it must
                    // not be answered `420` before those methods run.
                    | ATTR_CONNECTION_ID
            )
        {
            continue;
        }
        if !unknown.contains(&attr_type) {
            unknown.push(attr_type);
        }
    }
    unknown
}

/// Authenticate one TURN request with the shared long-term implementation.
///
/// `Err(response)` is the wire answer (401 / 438 / 400), counted exactly like
/// the STUN path (`Auth::count`), which is what keeps a 401 flood inside the
/// abuse guard's buckets.
fn authenticate(
    auth: &auth::Auth,
    datagram: &[u8],
    message: &protocol::Message<'_>,
    peer: SocketAddr,
    method: u16,
) -> Result<Identity, Vec<u8>> {
    let now = SystemTime::now();
    // A UDP datagram may carry trailing junk; the MAC covers only the frame.
    let end = (protocol::HEADER_LEN + message.body.len()).min(datagram.len());
    let frame = &datagram[..end];
    let outcome = auth.verify(frame, message, peer.ip(), now);
    auth.count(&outcome);
    match outcome {
        Ok(identity) => Ok(identity),
        Err(rejection) => {
            Err(auth.rejection_response(rejection, &message.transaction_id, method, peer.ip(), now))
        }
    }
}

/// The address a client would see as the relay: the socket's own address when
/// it is concrete, otherwise the egress address the kernel picks for `peer`.
fn egress_ip(local: SocketAddr, peer: SocketAddr) -> Option<IpAddr> {
    if !local.ip().is_unspecified() {
        return Some(local.ip());
    }
    let bind: SocketAddr = if peer.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0_u16; 8], 0))
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(peer).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// A transaction id for server-originated indications: no matching semantics,
/// only uniqueness (time counter mixed with a process-local sequence).
fn fresh_transaction_id() -> TransactionId {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let mixed = nanos ^ sequence.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut id = [0_u8; 12];
    id[..8].copy_from_slice(&mixed.to_be_bytes());
    id[8..].copy_from_slice(&((nanos >> 32) as u32 ^ sequence as u32).to_be_bytes());
    TransactionId(id)
}

/// Opaque 8-byte token for an `EVEN-PORT` reservation.
fn fresh_reservation_token() -> [u8; 8] {
    let id = fresh_transaction_id();
    let mut token = [0_u8; 8];
    token.copy_from_slice(&id.as_bytes()[..8]);
    token
}

// Lock helpers: a poisoned lock still carries a consistent (if possibly
// half-updated) table, and the process keeps serving rather than panicking.

fn lock_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|error| error.into_inner())
}

fn lock_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|error| error.into_inner())
}

fn lock_lock<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests;
