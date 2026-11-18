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
//! Scope is Binding-only: `Binding Request` → `Binding Success` with
//! `XOR-MAPPED-ADDRESS` (+ `SOFTWARE`, and the legacy `MAPPED-ADDRESS` with
//! `--mapped-address`), `420 Unknown Attribute` + `UNKNOWN-ATTRIBUTES` when the
//! request carries an attribute this server does not implement, `400 Bad
//! Request` for any other method, ignore indications/responses. No TURN
//! allocate/refresh/channel, no authentication.
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
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use clap::{Parser, Subcommand};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
};

pub mod protocol;
pub mod rfc5780;
/// T1 互操作证据：RFC 5769 向量 + `stun-types` 双向（只在测试构建里编译）。
#[cfg(test)]
mod tests_interop;

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
/// `Binding` method, the only one this server implements.
const BINDING_METHOD: u16 = 0x0001;

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
    about = "Standalone STUN Binding server (RFC 5389; RFC 5780 with --alt-listen; TCP with --tcp)",
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
    /// Serve STUN Binding over UDP (and TCP with --tcp)
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

    /// log every Binding request with its source and mapped address
    #[arg(long)]
    verbose: bool,
}

/// Counters reported when the server stops; also what `--verbose` helps debug.
#[derive(Debug, Default)]
pub struct ServerStats {
    received: AtomicU64,
    answered: AtomicU64,
    dropped: AtomicU64,
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

    fn count_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    fn count_answered(&self) {
        self.answered.fetch_add(1, Ordering::Relaxed);
    }

    fn count_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
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
    let cli = Cli::parse();

    match cli.command {
        Command::Server(args) => {
            // 日志初始化失败不阻断服务：与内核主路径一致，没有日志也好过起不来。
            if let Err(error) = init_logging(args.verbose) {
                eprintln!("[rstun] failed to initialize logging: {error:#}");
            }

            run(args).await
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

/// Run the STUN Binding server until Ctrl-C (Unix: also SIGTERM).
async fn run(args: Args) -> ExitCode {
    let (addresses, plan) = match resolve_listen(&args) {
        Ok(resolved) => resolved,
        Err(message) => {
            // 配置错误必须让人看见：不要静默降级成「单 IP、无 RFC 5780」的服务器。
            tracing::error!(%message, "rstun: invalid command line");
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
    // Every listener shares one view of the bound sockets: that is what makes
    // `CHANGE-REQUEST` able to answer from a different one.
    let context = Arc::new(ServerContext {
        plan,
        udp: udp.clone(),
        mapped_address: args.mapped_address,
    });
    let mut tasks = Vec::new();

    for (local, socket) in udp {
        tasks.push(spawn_listener(
            format!("udp {local}"),
            serve_udp(socket, context.clone(), software.clone(), stats.clone()),
        ));
    }
    for (local, listener) in tcp {
        tasks.push(spawn_listener(
            format!("tcp {local}"),
            serve_tcp(listener, context.clone(), software.clone(), stats.clone()),
        ));
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
    tracing::info!(
        software = %software,
        listeners = tasks.len(),
        "rstun: started, Ctrl-C to stop"
    );

    let exit_code = match wait_for_shutdown().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "rstun: failed while waiting for a shutdown signal");
            ExitCode::FAILURE
        }
    };

    for task in tasks {
        task.abort();
    }
    let (received, answered, dropped) = stats.counters();
    tracing::info!(received, answered, dropped, "rstun: stopped");
    exit_code
}

/// Spawn one listener task, logging if it ever stops (a dead listener must not
/// leave the process quietly serving with fewer sockets than it announced).
fn spawn_listener<F>(name: String, listener: F) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = listener.await {
            tracing::error!(listener = %name, %error, "rstun: listener stopped");
        }
    })
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
        return Ok(Decision::Respond(protocol::unknown_attributes_response(
            &message.transaction_id,
            BINDING_METHOD,
            &unknown,
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
        return Ok(Decision::Respond(protocol::error_response(
            &message.transaction_id,
            BINDING_METHOD,
            protocol::ERROR_BAD_REQUEST,
            "Bad Request",
        )));
    }

    // Where the answer goes and which socket sends it. Only UDP can do anything
    // unusual: over TCP the reply can only travel back on the connection it
    // arrived on, so both `RESPONSE-PORT` and `CHANGE-REQUEST` are ignored there
    // (RFC 5780 §5 is defined for UDP).
    //
    // The two attributes are orthogonal and may both apply:
    // * §7.2 `CHANGE-REQUEST` picks the *source* socket;
    // * §7.5 `RESPONSE-PORT` picks the *destination* port, keeping both the
    //   source IP and the source port ("the Binding Response MUST be transmitted
    //   to the source IP address of the Binding Request and the port contained in
    //   RESPONSE-PORT").
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
            let to = match response_port {
                // Any 16-bit port is a legal destination; whether anything
                // listens there is the client's problem (`0` included — the
                // kernel refuses the send, we log it and keep serving).
                Some(port) => SocketAddr::new(peer.ip(), port),
                None => peer,
            };
            (from, to)
        }
    };

    let addresses = context.addresses(from);

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
        software,
        addresses,
        mapped_address: context.mapped_address,
        padding,
    });
    if from == local && to == peer {
        Ok(Decision::Respond(bytes))
    } else {
        Ok(Decision::RespondFrom { from, to, bytes })
    }
}

/// Serve one UDP socket until the task is aborted.
async fn serve_udp(
    socket: Arc<UdpSocket>,
    context: Arc<ServerContext>,
    software: Arc<str>,
    stats: Arc<ServerStats>,
) -> std::io::Result<()> {
    let local = socket.local_addr()?;
    tracing::info!(%local, "rstun: UDP listener ready");
    let mut buffer = vec![0_u8; UDP_RECV_BUFFER];
    loop {
        let (len, peer) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                // 单个 datagram 的读错误（瞬时 ICMP 等）不该打死监听。
                tracing::warn!(%local, %error, "rstun: UDP recv_from failed");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        stats.count_received();
        let decision = decide(
            &buffer[..len],
            peer,
            local,
            Transport::Udp,
            &context,
            &software,
        );
        match decision {
            Ok(Decision::Respond(response)) => match socket.send_to(&response, peer).await {
                Ok(_) => stats.count_answered(),
                Err(error) => {
                    tracing::warn!(%local, %peer, %error, "rstun: UDP send_to failed")
                }
            },
            Ok(Decision::RespondFrom { from, to, bytes }) => {
                // `from` is the *source* address (CHANGE-REQUEST picks another
                // socket we hold); `to` is the *destination* (RESPONSE-PORT moves
                // only the port — the IP stays the one the request came from).
                let target = context.socket_for(from);
                let Some(target) = target else {
                    stats.count_dropped();
                    tracing::error!(
                        %local,
                        %peer,
                        %from,
                        "rstun: no socket bound for the requested response address"
                    );
                    continue;
                };
                match target.send_to(&bytes, to).await {
                    Ok(_) => stats.count_answered(),
                    Err(error) => tracing::warn!(
                        %local,
                        %from,
                        %to,
                        %error,
                        "rstun: UDP send_to failed (RFC 5780)"
                    ),
                }
            }
            Ok(Decision::Ignore(reason)) => {
                tracing::debug!(%local, %peer, reason, "rstun: ignored message")
            }
            Err(error) => {
                stats.count_dropped();
                tracing::debug!(%local, %peer, %error, "rstun: dropped malformed datagram")
            }
        }
    }
}

/// Accept STUN-over-TCP connections until the task is aborted.
async fn serve_tcp(
    listener: TcpListener,
    context: Arc<ServerContext>,
    software: Arc<str>,
    stats: Arc<ServerStats>,
) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    tracing::info!(%local, "rstun: TCP listener ready");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%local, %error, "rstun: TCP accept failed");
                tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                continue;
            }
        };
        let software = software.clone();
        let stats = stats.clone();
        let context = context.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_tcp_connection(stream, peer, context, &software, &stats).await
            {
                tracing::debug!(%local, %peer, %error, "rstun: TCP connection closed")
            }
        });
    }
}

/// One TCP connection; RFC 5389 §7.2.2 frames messages by the header length.
async fn serve_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    context: Arc<ServerContext>,
    software: &str,
    stats: &ServerStats,
) -> std::io::Result<()> {
    let local = stream.local_addr()?;
    loop {
        let mut header = [0_u8; protocol::HEADER_LEN];
        if !read_exact_with_timeout(&mut stream, &mut header).await? {
            // 对端正常关闭。
            return Ok(());
        }
        let frame_len = match protocol::peek_frame_len(&header) {
            Ok(frame_len) => frame_len,
            Err(error) => {
                // Header gives us no frame boundary any more: the stream is unusable.
                stats.count_dropped();
                tracing::debug!(%peer, %error, "rstun: malformed TCP STUN header");
                return Ok(());
            }
        };
        stats.count_received();

        let mut frame = vec![0_u8; frame_len];
        frame[..protocol::HEADER_LEN].copy_from_slice(&header);
        if !read_exact_with_timeout(&mut stream, &mut frame[protocol::HEADER_LEN..]).await? {
            stats.count_dropped();
            tracing::debug!(%peer, "rstun: truncated TCP STUN message");
            return Ok(());
        }

        match decide(&frame, peer, local, Transport::Tcp, &context, software) {
            Ok(Decision::Respond(response)) => {
                stream.write_all(&response).await?;
                stats.count_answered();
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
                stream.write_all(&bytes).await?;
                stats.count_answered();
            }
            Ok(Decision::Ignore(reason)) => {
                tracing::debug!(%peer, reason, "rstun: ignored message")
            }
            Err(error) => {
                stats.count_dropped();
                tracing::debug!(%peer, %error, "rstun: malformed TCP STUN message");
                return Ok(());
            }
        }
    }
}

/// Read exactly `buffer.len()` bytes; `false` means the peer closed cleanly.
async fn read_exact_with_timeout(
    stream: &mut TcpStream,
    buffer: &mut [u8],
) -> std::io::Result<bool> {
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
    let socket = Socket::new(domain_of(address), Type::STREAM, Some(Protocol::TCP))?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // Windows maps SO_REUSEADDR to "steal the port"; a server does not want that.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
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
}
