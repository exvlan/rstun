//! 运维面：可选的 `/healthz` + `/metrics` HTTP 端点、优雅 drain 信号，以及
//! `RSTUN_*` 环境变量映射。
//!
//! 三条硬约束（`11-19-rstun-ops` 的 prd/design 与 `.trellis/spec/backend/*`）：
//!
//! 1. **默认全关**：不给 `--health-listen` 就不建监听、不 spawn 任务、不改一个
//!    字节 —— 冻结测试与 `26.410.100` 的响应字节必须继续成立；
//! 2. **不引第三方 HTTP 栈**（hyper/axum）：手写最小 HTTP/1.1 —— 只认 `GET`/`HEAD`
//!    的 `/healthz` 与 `/metrics`，不读请求体，一个连接只答一个请求；
//! 3. **指标与退出统计同源**：`/metrics` 读的就是退出时打印的那组 `Counters`，
//!    另外加一层按 transport × outcome 的桶（退出日志的 `received/answered/
//!    dropped` 三元组语义不变）。
//!
//! drain 信号放在 [`crate::ServerStats`] 里，而不是新建一个全局：每个 listener
//! 已经持有 `Arc<ServerStats>`，这样 `serve_udp` / `serve_tcp` 的签名（以及默认
//! 路径的行为）都不用改。

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{ArgMatches, Parser as _, parser::ValueSource};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};

use crate::{Args, BUILD_VERSION, Cli, Command, ServerContext, ServerStats, Transport, auth::Auth};

// ---------------------------------------------------------------------------
// Lifecycle: drain signal + in-flight accounting
// ---------------------------------------------------------------------------

/// The two things a graceful shutdown needs: "stop taking new work" (a `watch`
/// the listeners select on) and "is any work still running" (a counter).
///
/// Lives inside [`crate::ServerStats`] so that every listener already has it
/// without a new parameter; see the module docs.
#[derive(Debug)]
pub struct Lifecycle {
    draining: watch::Sender<bool>,
    /// `Arc` so a guard can be moved into a spawned task: the listener counts
    /// the work *before* spawning, which is what closes the race between
    /// "SIGTERM arrives" and "the task has not started yet".
    in_flight: Arc<AtomicU64>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            draining: watch::Sender::new(false),
            in_flight: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl Lifecycle {
    /// A receiver that resolves as soon as draining starts.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.draining.subscribe()
    }

    /// SIGTERM has been received: stop reading datagrams / accepting.
    pub fn begin(&self) {
        self.draining.send_replace(true);
    }

    pub fn is_draining(&self) -> bool {
        *self.draining.borrow()
    }

    /// Mark one unit of work (a datagram, a TCP connection or one TCP frame) as
    /// in flight until the guard is dropped.
    pub fn enter(&self) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        InFlight(self.in_flight.clone())
    }

    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Wait until nothing is in flight, or until `deadline` passes.
    ///
    /// Returns the number of units still running (0 = drained cleanly). Polling
    /// instead of a semaphore keeps the hot path to one relaxed atomic add and
    /// costs nothing when no shutdown is happening.
    pub async fn wait_idle(&self, deadline: tokio::time::Instant) -> u64 {
        loop {
            let remaining = self.in_flight();
            if remaining == 0 {
                return 0;
            }
            if tokio::time::Instant::now() >= deadline {
                return remaining;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// One unit of in-flight work; dropping it is what releases the slot.
#[derive(Debug)]
pub struct InFlight(Arc<AtomicU64>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Listener supervision
// ---------------------------------------------------------------------------

/// One listener task's liveness flag, shared between the task and `/healthz`.
///
/// The task holds a [`ListenerLease`] for its whole life; the lease clears the
/// flag on drop, which covers *both* an early return with an error and the task
/// being aborted (aborting a task drops its future, so the lease runs).
#[derive(Debug, Clone)]
pub struct ListenerHealth {
    name: String,
    alive: Arc<AtomicBool>,
}

impl ListenerHealth {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// The guard the listener task itself holds.
    pub fn lease(&self) -> ListenerLease {
        ListenerLease(self.alive.clone())
    }
}

/// Held by the listener task; dropping it marks the listener stale.
#[derive(Debug)]
pub struct ListenerLease(Arc<AtomicBool>);

impl Drop for ListenerLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// State behind the HTTP endpoint
// ---------------------------------------------------------------------------

/// Everything `/healthz` and `/metrics` report on: who should be listening,
/// whether the process is draining, and where the live counters are.
pub struct OpsState {
    listeners: Vec<ListenerHealth>,
    stats: Arc<ServerStats>,
    context: Arc<ServerContext>,
    started_unix: u64,
}

impl std::fmt::Debug for OpsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpsState")
            .field("listeners", &self.listeners.len())
            .field("draining", &self.stats.is_draining())
            .finish_non_exhaustive()
    }
}

impl OpsState {
    pub fn new(
        listeners: Vec<ListenerHealth>,
        stats: Arc<ServerStats>,
        context: Arc<ServerContext>,
    ) -> Self {
        let started_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        Self {
            listeners,
            stats,
            context,
            started_unix,
        }
    }

    /// `(status, body)` for `GET /healthz`.
    ///
    /// `200` only when every configured listener is still running *and* the
    /// process is not draining: "the process is alive" is not readiness — a
    /// server that lost a listener is still up but no longer serving the
    /// address it announced.
    pub fn health(&self) -> (u16, String) {
        let stale: Vec<&str> = self
            .listeners
            .iter()
            .filter(|listener| !listener.is_alive())
            .map(ListenerHealth::name)
            .collect();
        let listeners = self.listeners.len();
        if self.stats.is_draining() {
            return (
                503,
                format!(
                    "{{\"status\":\"draining\",\"listeners\":{listeners},\"stale\":{}}}",
                    json_strings(&stale)
                ),
            );
        }
        if stale.is_empty() {
            (
                200,
                format!("{{\"status\":\"ok\",\"listeners\":{listeners}}}"),
            )
        } else {
            (
                503,
                format!(
                    "{{\"status\":\"degraded\",\"listeners\":{listeners},\"stale\":{}}}",
                    json_strings(&stale)
                ),
            )
        }
    }

    /// The Prometheus text exposition of everything this process counts.
    ///
    /// Label sets are fixed (no per-peer labels): the cardinality is bounded by
    /// the enums `transport × result`, `scope` and `direction`, which is the
    /// design's mitigation for metric blow-up.
    ///
    /// TURN is not implemented yet, so `rstun_turn_allocations` and
    /// `rstun_turn_bytes_total` are **omitted** rather than reported as a
    /// permanent zero (a zero would look like "TURN is on and idle"); README's
    /// ops section says so explicitly.
    pub fn metrics(&self) -> String {
        let mut out = String::with_capacity(2048);
        let admission = self.context.admission.as_ref();
        let counts = admission
            .map(|admission| admission.counters())
            .unwrap_or_default();

        header(
            &mut out,
            "rstun_requests_total",
            "STUN messages handled, by transport and outcome.",
            "counter",
        );
        for transport in ["udp", "tcp"] {
            let buckets = self.stats.buckets(match transport {
                "udp" => Transport::Udp,
                _ => Transport::Tcp,
            });
            for (result, value) in [
                ("ok", buckets.ok),
                ("error", buckets.error),
                ("ignored", buckets.ignored),
                ("dropped", buckets.dropped),
            ] {
                sample(
                    &mut out,
                    "rstun_requests_total",
                    &[("transport", transport), ("result", result)],
                    value,
                );
            }
        }

        header(
            &mut out,
            "rstun_rate_limited_total",
            "Requests refused by the abuse guard's token buckets.",
            "counter",
        );
        for (scope, value) in [
            ("ip", counts.rate_limited_ip),
            ("ip_port", counts.rate_limited_port),
            ("global", counts.rate_limited_global),
        ] {
            sample(
                &mut out,
                "rstun_rate_limited_total",
                &[("scope", scope)],
                value,
            );
        }

        header(
            &mut out,
            "rstun_inflight_dropped_total",
            "Requests refused because the in-flight cap was full.",
            "counter",
        );
        sample(
            &mut out,
            "rstun_inflight_dropped_total",
            &[],
            counts.inflight_dropped,
        );

        header(
            &mut out,
            "rstun_reflect_rejected_total",
            "Redirect requests refused by the reflection guard.",
            "counter",
        );
        sample(
            &mut out,
            "rstun_reflect_rejected_total",
            &[],
            counts.reflect_rejected,
        );

        header(
            &mut out,
            "rstun_denied_total",
            "Requests refused by --deny (CIDR).",
            "counter",
        );
        sample(&mut out, "rstun_denied_total", &[], counts.denied);

        header(
            &mut out,
            "rstun_allowlisted_total",
            "Requests whose source matched --allow.",
            "counter",
        );
        sample(&mut out, "rstun_allowlisted_total", &[], counts.allowlisted);

        header(
            &mut out,
            "rstun_fingerprint_rejected_total",
            "Requests whose FINGERPRINT was invalid (--check-fingerprint).",
            "counter",
        );
        sample(
            &mut out,
            "rstun_fingerprint_rejected_total",
            &[],
            self.stats.fingerprint_rejected(),
        );

        header(
            &mut out,
            "rstun_socket_errors_total",
            "Socket read/accept failures, by transport.",
            "counter",
        );
        for transport in ["udp", "tcp"] {
            let buckets = self.stats.buckets(match transport {
                "udp" => Transport::Udp,
                _ => Transport::Tcp,
            });
            sample(
                &mut out,
                "rstun_socket_errors_total",
                &[("transport", transport)],
                buckets.socket_errors,
            );
        }

        header(
            &mut out,
            "rstun_ops_rejected_total",
            "Ops endpoint connections refused over --health-max-connections.",
            "counter",
        );
        sample(
            &mut out,
            "rstun_ops_rejected_total",
            &[],
            self.stats.ops_rejected(),
        );

        header(
            &mut out,
            "rstun_auth_total",
            "Authentication outcomes (all zero when no credential is configured).",
            "counter",
        );
        let (authenticated, unauthorized, stale_nonce, bad_request) = self
            .context
            .auth
            .as_ref()
            .map(Auth::counters)
            .map(auth_counts)
            .unwrap_or_default();
        for (result, value) in [
            ("ok", authenticated),
            ("unauthorized", unauthorized),
            ("stale_nonce", stale_nonce),
            ("bad_request", bad_request),
        ] {
            sample(&mut out, "rstun_auth_total", &[("result", result)], value);
        }

        header(
            &mut out,
            "rstun_build_info",
            "Build identity; the value is always 1 and the labels carry the details.",
            "gauge",
        );
        sample(
            &mut out,
            "rstun_build_info",
            &[("version", BUILD_VERSION)],
            1,
        );

        header(
            &mut out,
            "rstun_start_time_seconds",
            "Unix time at which this process finished starting.",
            "gauge",
        );
        sample(&mut out, "rstun_start_time_seconds", &[], self.started_unix);

        header(
            &mut out,
            "rstun_uptime_seconds",
            "Seconds since this process finished starting.",
            "gauge",
        );
        sample(&mut out, "rstun_uptime_seconds", &[], self.uptime_seconds());

        header(
            &mut out,
            "rstun_health",
            "1 when /healthz would answer 200, 0 when it would answer 503.",
            "gauge",
        );
        sample(
            &mut out,
            "rstun_health",
            &[],
            u64::from(self.health().0 == 200),
        );

        out
    }

    fn uptime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs().saturating_sub(self.started_unix))
            .unwrap_or(0)
    }
}

fn auth_counts(counters: &crate::auth::Counters) -> (u64, u64, u64, u64) {
    counters.snapshot()
}

/// `# HELP` + `# TYPE` for one metric family.
fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(kind);
    out.push('\n');
}

/// One sample line; labels are emitted in the given order.
fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (index, (key, raw)) in labels.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push_str("=\"");
            push_escaped(out, raw);
            out.push('"');
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Prometheus label values escape `\`, `"` and newlines.
fn push_escaped(out: &mut String, raw: &str) {
    for character in raw.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
}

/// `["a","b"]`, with the names escaped like any other JSON string.
fn json_strings(values: &[&str]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        for character in value.chars() {
            match character {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                other => out.push(other),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1
// ---------------------------------------------------------------------------

/// Total budget for **one connection**: reading the request head and writing the
/// answer share this single deadline.
///
/// Per-read timeouts are not enough: a client that sends one byte every 1.5 s
/// would reset a per-read timer forever and hold the slot for minutes. One
/// deadline from `accept` bounds the whole exchange at 2 s.
pub const HTTP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
/// Largest request head accepted, **terminator included**: a head of exactly
/// this many bytes is served, one byte more is a `400`.
pub const HTTP_MAX_HEAD: usize = 8 * 1024;
/// Default for `--health-max-connections`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const JSON_CONTENT_TYPE: &str = "application/json";
const TEXT_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

/// Accept `/healthz` + `/metrics` requests until the process aborts this task.
///
/// It deliberately keeps serving while draining: `/healthz` then answers `503`
/// (`"status":"draining"`) so a load balancer removes the instance, and
/// `/metrics` stays scrapeable until the very end. One request per connection,
/// no keep-alive: that removes the slow-loris shape (a client holding a
/// connection open between requests) from a surface that exists to answer
/// probes.
///
/// `max_connections` bounds how many exchanges may be in flight at once. A
/// connection over the cap is **not queued**: it gets an immediate `503` and is
/// closed, because queueing would keep the fd the attack is trying to exhaust.
pub async fn serve_http(
    listener: TcpListener,
    ops: Arc<OpsState>,
    max_connections: usize,
) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    tracing::info!(
        %local,
        max_connections,
        "rstun: ops endpoint ready (GET /healthz, GET /metrics)"
    );
    let permits = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // STUN socket errors have their own counter; an ops accept
                // failure is a different thing (and only ever happens here).
                tracing::warn!(%local, %error, "rstun: ops endpoint accept failed");
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        match permits.clone().try_acquire_owned() {
            Ok(permit) => {
                let ops = ops.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_http_connection(stream, &ops, permit).await {
                        tracing::debug!(%peer, %error, "rstun: ops request ended");
                    }
                });
            }
            Err(_full) => {
                ops.stats.count_ops_rejected();
                tracing::debug!(
                    %peer,
                    max_connections,
                    "rstun: ops endpoint over capacity, answering 503"
                );
                // The refusal is a small fixed write under the same 2 s budget:
                // a client cannot turn it into more work than the request it was
                // already making.
                let reply = Reply::error(
                    503,
                    "Service Unavailable",
                    "too many concurrent connections",
                );
                tokio::spawn(async move {
                    let mut stream = stream;
                    let deadline = tokio::time::Instant::now() + HTTP_CONNECTION_TIMEOUT;
                    let _ = write_reply(&mut stream, &reply, true, deadline).await;
                });
            }
        }
    }
}

/// One request, one answer, then close; `_permit` is held for the whole exchange
/// (dropping it is what frees the concurrency slot).
async fn serve_http_connection(
    mut stream: TcpStream,
    ops: &OpsState,
    _permit: OwnedSemaphorePermit,
) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + HTTP_CONNECTION_TIMEOUT;
    let head = match read_head(&mut stream, deadline).await? {
        HeadOutcome::Head(head) => String::from_utf8_lossy(&head).into_owned(),
        // No request head: nothing to answer, just close.
        HeadOutcome::Closed | HeadOutcome::Timeout => return Ok(()),
        HeadOutcome::TooLarge => {
            // Still worth answering: an operator hitting the endpoint with a
            // broken client should see *why* it was refused.
            let reply = Reply::error(400, "Bad Request", "request head too large");
            let with_body = reply.with_body;
            return write_reply(&mut stream, &reply, with_body, deadline).await;
        }
    };
    let reply = handle(&head, ops);
    write_reply(&mut stream, &reply, reply.with_body, deadline).await
}

async fn write_reply(
    stream: &mut TcpStream,
    reply: &Reply,
    with_body: bool,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    let bytes = reply.render(with_body);
    match tokio::time::timeout_at(deadline, stream.write_all(&bytes)).await {
        Ok(Err(error)) => return Err(error),
        // Budget already spent on the read: close without a farewell.
        Err(_elapsed) => return Ok(()),
        Ok(Ok(())) => {}
    }
    let _ = tokio::time::timeout_at(deadline, stream.shutdown()).await;
    Ok(())
}

/// What was read off the socket before parsing.
enum HeadOutcome {
    /// Request line + headers, exactly as received (terminator excluded).
    Head(Vec<u8>),
    /// The peer stopped sending without finishing the head.
    Closed,
    /// The head was not finished within [`HTTP_CONNECTION_TIMEOUT`].
    Timeout,
    /// More than [`HTTP_MAX_HEAD`] bytes before the blank line.
    TooLarge,
}

async fn read_head(
    stream: &mut TcpStream,
    deadline: tokio::time::Instant,
) -> std::io::Result<HeadOutcome> {
    let mut buffer: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0_u8; 1024];
    loop {
        if let Some(end) = head_end(&buffer) {
            buffer.truncate(end);
            return Ok(HeadOutcome::Head(buffer));
        }
        // Never read past the limit: the buffer then holds exactly
        // `HTTP_MAX_HEAD` bytes at most, so "the terminator fits" and "the head
        // is within the documented size" are the same statement.
        if buffer.len() >= HTTP_MAX_HEAD {
            return Ok(HeadOutcome::TooLarge);
        }
        let room = (HTTP_MAX_HEAD - buffer.len()).min(chunk.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..room])).await {
            Err(_elapsed) => return Ok(HeadOutcome::Timeout),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(0)) => return Ok(HeadOutcome::Closed),
            Ok(Ok(read)) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
}

/// Index just past the blank line that ends the head (`\r\n\r\n`, tolerating
/// the bare-`\n` spelling some hand-written clients use).
fn head_end(buffer: &[u8]) -> Option<usize> {
    for (index, window) in buffer.windows(4).enumerate() {
        if window == b"\r\n\r\n" {
            return Some(index + 4);
        }
    }
    for (index, window) in buffer.windows(2).enumerate() {
        if window == b"\n\n" {
            return Some(index + 2);
        }
    }
    None
}

/// One HTTP answer, before framing.
#[derive(Debug)]
struct Reply {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: String,
    /// `Allow:` header, present on `405`.
    allow: Option<&'static str>,
    /// `false` for `HEAD`: headers only, `Content-Length` still advertised.
    with_body: bool,
}

impl Reply {
    fn error(status: u16, reason: &'static str, detail: &str) -> Self {
        Self {
            status,
            reason,
            content_type: TEXT_CONTENT_TYPE,
            body: format!("{detail}\n"),
            allow: None,
            with_body: true,
        }
    }

    fn render(&self, with_body: bool) -> Vec<u8> {
        let mut text = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        if let Some(allow) = self.allow {
            text.push_str("Allow: ");
            text.push_str(allow);
            text.push_str("\r\n");
        }
        text.push_str("\r\n");
        let mut bytes = text.into_bytes();
        if with_body {
            bytes.extend_from_slice(self.body.as_bytes());
        }
        bytes
    }
}

/// Resolve one request head into an answer.
///
/// Order matters and is the design's: a malformed head or a body is `400`
/// before anything else (we cannot trust the rest of the message), then the
/// method (`405`), then the path (`404`).
fn handle(head: &str, ops: &OpsState) -> Reply {
    let mut lines = head.split("\r\n").flat_map(str::lines);
    let Some(request_line) = lines.next() else {
        return Reply::error(400, "Bad Request", "empty request");
    };
    let fields: Vec<&str> = request_line.split(' ').collect();
    if fields.len() != 3 {
        return Reply::error(400, "Bad Request", "malformed request line");
    }
    let (method, target, version) = (fields[0], fields[1], fields[2]);
    if !version.starts_with("HTTP/1.") {
        return Reply::error(400, "Bad Request", "only HTTP/1.x is supported");
    }

    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Reply::error(400, "Bad Request", "malformed header");
        };
        // The endpoint never reads a body: a declared one means the client is
        // talking to the wrong kind of server, so refuse instead of guessing
        // where the body ends (design §8). `Content-Length: 0` declares *no*
        // body, so it is allowed — otherwise a `POST` would be reported as 400
        // instead of the 405 it is.
        if name.eq_ignore_ascii_case("content-length") {
            match value.trim().parse::<u64>() {
                Ok(0) => {}
                _ => return Reply::error(400, "Bad Request", "request bodies are not accepted"),
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Reply::error(400, "Bad Request", "request bodies are not accepted");
        }
    }

    let with_body = match method {
        "GET" => true,
        // `HEAD` answers with the same headers so a probe can be cheap.
        "HEAD" => false,
        _ => {
            let mut reply =
                Reply::error(405, "Method Not Allowed", "only GET and HEAD are allowed");
            reply.allow = Some("GET, HEAD");
            return reply;
        }
    };

    let path = target.split(['?', '#']).next().unwrap_or(target);
    let mut reply = match path {
        "/healthz" => {
            let (status, body) = ops.health();
            Reply {
                status,
                reason: if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                },
                content_type: JSON_CONTENT_TYPE,
                body,
                allow: None,
                with_body: true,
            }
        }
        "/metrics" => Reply {
            status: 200,
            reason: "OK",
            content_type: METRICS_CONTENT_TYPE,
            body: ops.metrics(),
            allow: None,
            with_body: true,
        },
        _ => Reply::error(404, "Not Found", "unknown path"),
    };
    reply.with_body = with_body;
    reply
}

// ---------------------------------------------------------------------------
// RSTUN_* environment mapping
// ---------------------------------------------------------------------------

/// Prefix of every mapped variable: `--health-listen` ⇔ `RSTUN_HEALTH_LISTEN`.
pub const ENV_PREFIX: &str = "RSTUN_";

/// How a variable's value becomes command line tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvKind {
    /// `--tcp` / `RSTUN_TCP=1|true|yes|on` (falsy values mean "not given").
    Switch,
    /// `--realm example.org` / `RSTUN_REALM=example.org`.
    Value,
    /// Repeatable flag: `RSTUN_LISTEN=a:3478,b:3478` → `--listen a:3478 --listen b:3478`.
    List,
}

/// Every flag that accepts an `RSTUN_*` default, in `Args` field order.
///
/// The names are the clap arg ids, which are the struct field names — the same
/// string is used to ask clap "was this given on the command line?".
const ENV_FLAGS: &[(&str, EnvKind)] = &[
    ("listen", EnvKind::List),
    ("listen_v6", EnvKind::List),
    ("alt_listen", EnvKind::Value),
    ("alt_port", EnvKind::Value),
    ("tcp", EnvKind::Switch),
    ("mapped_address", EnvKind::Switch),
    ("check_fingerprint", EnvKind::Switch),
    ("fingerprint_action", EnvKind::Value),
    ("alternate_server", EnvKind::List),
    ("verbose", EnvKind::Switch),
    ("rate_limit", EnvKind::Value),
    ("rate_burst", EnvKind::Value),
    ("rate_limit_port", EnvKind::Value),
    ("global_rate", EnvKind::Value),
    ("max_inflight", EnvKind::Value),
    ("reflect_min_request", EnvKind::Value),
    ("reflect_ratio", EnvKind::Value),
    ("allow", EnvKind::List),
    ("deny", EnvKind::List),
    ("auth_user", EnvKind::Value),
    ("auth_pass", EnvKind::Value),
    ("auth_file", EnvKind::Value),
    ("realm", EnvKind::Value),
    ("auth_secret", EnvKind::Value),
    ("nonce_lifetime", EnvKind::Value),
    ("auth_require_sha256", EnvKind::Switch),
    ("health_listen", EnvKind::Value),
    ("health_max_connections", EnvKind::Value),
    ("drain_timeout", EnvKind::Value),
];

/// `RSTUN_<FLAG>`: uppercase, `-` → `_`.
fn env_name(flag: &str) -> String {
    format!("{ENV_PREFIX}{}", flag.to_ascii_uppercase())
}

/// Fill every flag the operator did *not* give on the command line from its
/// `RSTUN_*` variable. The CLI is the single source of truth: an explicitly
/// passed flag always wins, including "explicitly repeated `--listen` beats
/// `RSTUN_LISTEN`" (the two are never merged).
///
/// Returns the variables that were applied (for the startup log). Unset
/// variables are skipped; a variable that is set but unparseable is a startup
/// error naming the variable — silently ignoring it would mean the operator's
/// written-down configuration is not the one running.
pub fn apply_env(
    args: &mut Args,
    matches: &ArgMatches,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<String>, String> {
    let mut argv: Vec<String> = vec!["rstun".into(), "server".into()];
    let mut applied: Vec<(String, &'static str)> = Vec::new();
    for (flag, kind) in ENV_FLAGS {
        if is_from_command_line(matches, flag) {
            continue;
        }
        let name = env_name(flag);
        let Some(raw) = lookup(&name) else {
            continue;
        };
        // An empty value means "not set": compose interpolation such as
        // `${RSTUN_REALM:-}` left in the environment must not turn into
        // "explicitly empty" and fail the start.
        if raw.is_empty() {
            continue;
        }
        let Some(tokens) = env_tokens(flag, *kind, &raw) else {
            continue;
        };
        argv.extend(tokens);
        applied.push((name, flag));
    }
    if applied.is_empty() {
        return Ok(Vec::new());
    }

    let parsed = Cli::try_parse_from(&argv).map_err(|error| env_error(&error, &applied))?;
    let Command::Server(mut from_env) = parsed.command;
    overlay(args, &mut from_env, matches);
    Ok(applied.into_iter().map(|(name, _)| name).collect())
}

/// `true` when the flag was literally written on the command line (as opposed
/// to clap's own default value for it).
fn is_from_command_line(matches: &ArgMatches, flag: &str) -> bool {
    matches.value_source(flag) == Some(ValueSource::CommandLine)
}

/// The command line spelling of a field (`health_listen` → `--health-listen`).
fn long_flag(flag: &str) -> String {
    format!("--{}", flag.replace('_', "-"))
}

/// The command line tokens a variable stands for; `None` means "behaves as if
/// unset" (a switch spelled with a falsy value).
fn env_tokens(flag: &str, kind: EnvKind, raw: &str) -> Option<Vec<String>> {
    let long = long_flag(flag);
    match kind {
        EnvKind::Switch => env_switch(raw).then(|| vec![long]),
        EnvKind::Value => Some(vec![long, raw.to_string()]),
        EnvKind::List => Some(
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .flat_map(|item| [long.clone(), item.to_string()])
                .collect(),
        ),
    }
}

/// `1/true/yes/on` and `0/false/no/off` (any case, surrounding blanks ignored);
/// an empty value is "off". Anything else is silently falsy — the *parse* of a
/// mistyped switch has no error path worth failing the start over, and the
/// startup log lists exactly which variables were applied.
fn env_switch(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Point a clap parse error at the environment variable that caused it.
fn env_error(error: &clap::Error, applied: &[(String, &'static str)]) -> String {
    let rendered = error.to_string();
    let source = applied
        .iter()
        .find(|(_, flag)| rendered.contains(&long_flag(flag)))
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| "RSTUN_*".to_string());
    let detail = rendered
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("invalid value")
        .trim_start_matches("error: ")
        .to_string();
    format!("{source}: {detail}")
}

/// Copy every env-derived field into `args`, except the ones the operator set
/// explicitly on the command line (`value_source` is what tells them apart from
/// clap's defaults).
fn overlay(args: &mut Args, from_env: &mut Args, matches: &ArgMatches) {
    macro_rules! overlay {
        ($($field:ident),+ $(,)?) => {
            $(
                if !is_from_command_line(matches, stringify!($field)) {
                    args.$field.fill_if_unset(&mut from_env.$field);
                }
            )+
        };
    }
    overlay!(
        listen,
        listen_v6,
        alt_listen,
        alt_port,
        tcp,
        mapped_address,
        check_fingerprint,
        fingerprint_action,
        alternate_server,
        verbose,
        rate_limit,
        rate_burst,
        rate_limit_port,
        global_rate,
        max_inflight,
        reflect_min_request,
        reflect_ratio,
        allow,
        deny,
        auth_user,
        auth_pass,
        auth_file,
        realm,
        auth_secret,
        nonce_lifetime,
        auth_require_sha256,
        health_listen,
        health_max_connections,
        drain_timeout,
    );
}

/// "Take the other value when I have none" — the three shapes `Args` has.
trait Fill {
    fn fill_if_unset(&mut self, other: &mut Self);
}

impl<T> Fill for Option<T> {
    fn fill_if_unset(&mut self, other: &mut Self) {
        if self.is_none() {
            *self = other.take();
        }
    }
}

impl<T> Fill for Vec<T> {
    fn fill_if_unset(&mut self, other: &mut Self) {
        if self.is_empty() {
            std::mem::swap(self, other);
        }
    }
}

impl Fill for bool {
    fn fill_if_unset(&mut self, other: &mut Self) {
        *self |= *other;
    }
}

impl Fill for crate::FingerprintAction {
    fn fill_if_unset(&mut self, other: &mut Self) {
        if *other != Self::default() {
            *self = *other;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, net::SocketAddr};

    use clap::{CommandFactory as _, FromArgMatches as _};

    use crate::limit;

    /// `value_source` panics on an id the command does not know, so every mapped
    /// name must be a real flag: this test is what keeps that true.
    #[test]
    fn every_mapped_variable_names_a_real_flag() {
        let command = Cli::command();
        let server = command
            .find_subcommand("server")
            .expect("server subcommand");
        let ids: Vec<&str> = server
            .get_arguments()
            .map(|argument| argument.get_id().as_str())
            .collect();
        for (flag, _) in ENV_FLAGS {
            assert!(
                ids.contains(flag),
                "RSTUN mapping for unknown flag {flag:?}"
            );
        }
    }

    /// Parse `rstun server <extra>` exactly like `main` does, then apply the
    /// `RSTUN_*` pairs on top — the same two-phase shape `run` uses.
    fn with_env(extra: &[&str], pairs: &[(&str, &str)]) -> (Args, Result<Vec<String>, String>) {
        let mut argv = vec!["rstun", "server"];
        argv.extend_from_slice(extra);
        let command = Cli::command()
            .try_get_matches_from(argv)
            .expect("test command line");
        let matches = command
            .subcommand_matches("server")
            .expect("server subcommand")
            .clone();
        let Cli {
            command: Command::Server(mut args),
        } = Cli::from_arg_matches(&command).expect("test command line");
        let values: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        let applied = apply_env(&mut args, &matches, &|name| values.get(name).cloned());
        (args, applied)
    }

    /// A state whose single listener can be flipped by the test — the in-process
    /// stand-in for "a listener task died" (design §9 e2e hook).
    fn ops_state() -> (Arc<OpsState>, ListenerHealth) {
        let stats = Arc::new(ServerStats::default());
        let listener = ListenerHealth::new("udp 127.0.0.1:3478");
        let context = Arc::new(ServerContext::default());
        let state = Arc::new(OpsState::new(vec![listener.clone()], stats, context));
        (state, listener)
    }

    // -- lifecycle ---------------------------------------------------------

    #[tokio::test]
    async fn drain_waits_for_in_flight_work() {
        let stats = Arc::new(ServerStats::default());
        let guard = stats.enter();
        assert_eq!(stats.lifecycle().in_flight(), 1);
        stats.begin_drain();
        assert!(stats.is_draining());

        // The work finishes 100 ms after the drain started.
        let finisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(guard);
        });
        let started = tokio::time::Instant::now();
        let remaining = stats
            .wait_idle(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert_eq!(remaining, 0);
        assert!(
            started.elapsed() >= Duration::from_millis(90),
            "drain returned too early: {:?}",
            started.elapsed()
        );
        finisher.await.expect("finisher");
        assert_eq!(stats.lifecycle().in_flight(), 0);
    }

    #[tokio::test]
    async fn drain_gives_up_at_the_deadline_and_reports_the_remainder() {
        let stats = Arc::new(ServerStats::default());
        let _guard = stats.enter();
        stats.begin_drain();
        let started = tokio::time::Instant::now();
        let remaining = stats
            .wait_idle(tokio::time::Instant::now() + Duration::from_millis(50))
            .await;
        assert_eq!(remaining, 1, "the stuck unit must be reported");
        assert!(started.elapsed() >= Duration::from_millis(45));
    }

    #[test]
    fn drain_is_observable_through_the_subscription() {
        let stats = ServerStats::default();
        let mut receiver = stats.subscribe_drain();
        assert!(!*receiver.borrow());
        stats.begin_drain();
        assert!(*receiver.borrow_and_update());
    }

    // -- env ---------------------------------------------------------------

    #[test]
    fn cli_wins_over_env_and_env_fills_the_rest() {
        let (args, applied) = with_env(
            &["--listen", "127.0.0.1:4000"],
            &[
                ("RSTUN_LISTEN", "127.0.0.1:9999"),
                ("RSTUN_REALM", "example.org"),
                ("RSTUN_HEALTH_LISTEN", "127.0.0.1:9100"),
                ("RSTUN_DRAIN_TIMEOUT", "2"),
            ],
        );
        let applied = applied.expect("env must parse");
        // Explicit --listen beats RSTUN_LISTEN: the two are never merged.
        assert_eq!(args.listen, vec!["127.0.0.1:4000".parse().unwrap()]);
        assert_eq!(args.realm.as_deref(), Some("example.org"));
        assert_eq!(args.health_listen, Some("127.0.0.1:9100".parse().unwrap()));
        assert_eq!(args.drain_timeout, Some(2));
        assert_eq!(
            applied,
            vec![
                "RSTUN_REALM".to_string(),
                "RSTUN_HEALTH_LISTEN".to_string(),
                "RSTUN_DRAIN_TIMEOUT".to_string(),
            ]
        );
    }

    #[test]
    fn list_variables_are_comma_separated_and_replace_the_empty_cli_list() {
        let (args, applied) = with_env(
            &[],
            &[
                ("RSTUN_LISTEN", "127.0.0.1:4000, 127.0.0.1:4001"),
                ("RSTUN_DENY", "10.0.0.0/8"),
            ],
        );
        applied.expect("env must parse");
        assert_eq!(
            args.listen,
            vec![
                "127.0.0.1:4000".parse().unwrap(),
                "127.0.0.1:4001".parse().unwrap()
            ]
        );
        assert_eq!(
            args.deny,
            vec!["10.0.0.0/8".parse::<limit::IpNet>().unwrap()]
        );
        assert!(args.allow.is_empty());
    }

    #[test]
    fn an_invalid_variable_fails_and_names_itself() {
        let (_args, applied) = with_env(&[], &[("RSTUN_ALT_PORT", "not-a-port")]);
        let error = applied.expect_err("invalid value must fail the start");
        assert!(error.starts_with("RSTUN_ALT_PORT:"), "{error}");
    }

    #[test]
    fn switches_accept_the_usual_spellings_and_falsy_means_absent() {
        for (raw, expected) in [("1", true), ("true", true), ("yes", true), ("on", true)] {
            let (args, _) = with_env(&[], &[("RSTUN_TCP", raw)]);
            assert_eq!(args.tcp, expected, "RSTUN_TCP={raw}");
        }
        for raw in ["0", "false", "no", "off", ""] {
            let (args, _) = with_env(&[], &[("RSTUN_TCP", raw)]);
            assert!(!args.tcp, "RSTUN_TCP={raw}");
        }
    }

    #[test]
    fn an_empty_variable_is_treated_as_unset() {
        // `${RSTUN_REALM:-}` in a compose file leaves an empty variable behind;
        // that must not become "explicitly empty realm" and fail the start.
        let (args, applied) = with_env(
            &[],
            &[("RSTUN_REALM", ""), ("RSTUN_LISTEN", ""), ("RSTUN_TCP", "")],
        );
        assert!(applied.expect("empty values are ignored").is_empty());
        assert_eq!(args.realm, None);
        assert!(args.listen.is_empty());
        assert!(!args.tcp);
    }

    #[test]
    fn the_connection_cap_is_configurable_from_the_environment() {
        let (args, applied) = with_env(&[], &[("RSTUN_HEALTH_MAX_CONNECTIONS", "8")]);
        assert_eq!(
            applied.expect("env must parse"),
            vec!["RSTUN_HEALTH_MAX_CONNECTIONS"]
        );
        assert_eq!(args.health_max_connections, Some(8));
    }

    #[test]
    fn unknown_rstun_names_are_not_mapped() {
        let (args, applied) = with_env(
            &[],
            &[("RSTUN_NOT_A_FLAG", "x"), ("RSTUN_BUILD_VERSION", "1.2.3")],
        );
        assert!(applied.expect("unknown names are ignored").is_empty());
        assert_eq!(args.realm, None);
        assert!(args.listen.is_empty());
        assert!(!args.tcp);
    }

    // -- health / metrics --------------------------------------------------

    #[test]
    fn health_is_ok_while_every_listener_runs() {
        let (state, _listener) = ops_state();
        let (status, body) = state.health();
        assert_eq!(status, 200);
        assert_eq!(body, "{\"status\":\"ok\",\"listeners\":1}");
    }

    #[test]
    fn a_dead_listener_turns_health_into_503_and_is_listed() {
        let (state, listener) = ops_state();
        drop(listener.lease());
        let (status, body) = state.health();
        assert_eq!(status, 503);
        assert_eq!(
            body,
            "{\"status\":\"degraded\",\"listeners\":1,\"stale\":[\"udp 127.0.0.1:3478\"]}"
        );
    }

    #[test]
    fn draining_reports_503_even_with_healthy_listeners() {
        let (state, _listener) = ops_state();
        state.stats.begin_drain();
        let (status, body) = state.health();
        assert_eq!(status, 503);
        assert!(body.contains("\"status\":\"draining\""), "{body}");
    }

    #[test]
    fn metrics_text_carries_help_type_and_fixed_label_sets() {
        let (state, _listener) = ops_state();
        let text = state.metrics();
        assert!(text.contains("# TYPE rstun_requests_total counter"));
        assert!(text.contains("# HELP rstun_requests_total "));
        // 2 transports x 4 outcomes, always present (fixed label sets).
        for transport in ["udp", "tcp"] {
            for result in ["ok", "error", "ignored", "dropped"] {
                let line = format!(
                    "rstun_requests_total{{transport=\"{transport}\",result=\"{result}\"}} "
                );
                assert!(text.contains(&line), "missing {line}");
            }
        }
        assert!(text.contains("rstun_rate_limited_total{scope=\"ip\"} 0"));
        assert!(text.contains("rstun_rate_limited_total{scope=\"global\"} 0"));
        assert!(text.contains("rstun_build_info{version=\""));
        assert!(text.contains("rstun_auth_total{result=\"stale_nonce\"} 0"));
        // TURN is not implemented: no metric rows for it at all.
        assert!(!text.contains("rstun_turn"));
    }

    #[test]
    fn metrics_follow_the_shared_counters() {
        let stats = Arc::new(ServerStats::default());
        let context = Arc::new(ServerContext::default());
        let state = OpsState::new(Vec::new(), stats.clone(), context);
        stats.count_answered(Transport::Udp);
        stats.count_dropped(Transport::Tcp);
        let text = state.metrics();
        assert!(text.contains("rstun_requests_total{transport=\"udp\",result=\"ok\"} 1"));
        assert!(text.contains("rstun_requests_total{transport=\"tcp\",result=\"dropped\"} 1"));
    }

    // -- HTTP --------------------------------------------------------------

    fn get(path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    #[test]
    fn get_healthz_is_200_json() {
        let (state, _listener) = ops_state();
        let reply = handle(&get("/healthz"), &state);
        assert_eq!(reply.status, 200);
        assert_eq!(reply.content_type, JSON_CONTENT_TYPE);
        assert!(reply.body.contains("\"status\":\"ok\""));
    }

    #[test]
    fn head_answers_without_a_body_but_with_the_length() {
        let (state, _listener) = ops_state();
        let head = "HEAD /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let reply = handle(head, &state);
        assert_eq!(reply.status, 200);
        let bytes = reply.render(reply.with_body);
        let text = String::from_utf8_lossy(&bytes);
        let (headers, body) = text.split_once("\r\n\r\n").expect("head terminator");
        assert!(headers.contains("Content-Length: "));
        assert!(body.is_empty(), "HEAD must not carry a body");
    }

    #[test]
    fn other_methods_are_405_with_allow() {
        let (state, _listener) = ops_state();
        let reply = handle("POST /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n", &state);
        assert_eq!(reply.status, 405);
        assert_eq!(reply.allow, Some("GET, HEAD"));
    }

    #[test]
    fn unknown_paths_are_404() {
        let (state, _listener) = ops_state();
        assert_eq!(handle(&get("/nope"), &state).status, 404);
        assert_eq!(handle(&get("/"), &state).status, 404);
    }

    #[test]
    fn a_body_is_refused_with_400() {
        let (state, _listener) = ops_state();
        let head = "GET /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n";
        assert_eq!(handle(head, &state).status, 400);
        let head = "GET /metrics HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(handle(head, &state).status, 400);
        // A declared *zero* length means no body: that must not mask the method.
        let head = "POST /metrics HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(handle(head, &state).status, 405);
        let head = "GET /healthz HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(handle(head, &state).status, 200);
    }

    #[test]
    fn malformed_request_lines_are_400() {
        let (state, _listener) = ops_state();
        assert_eq!(handle("", &state).status, 400);
        assert_eq!(handle("GET /healthz\r\n\r\n", &state).status, 400);
        assert_eq!(handle("GET /healthz HTTP/2.0\r\n\r\n", &state).status, 400);
    }

    #[test]
    fn the_query_string_is_not_part_of_the_path() {
        let (state, _listener) = ops_state();
        assert_eq!(handle(&get("/healthz?probe=1"), &state).status, 200);
    }

    /// The real socket path: one request, one answer, connection closed.
    #[tokio::test]
    async fn serves_healthz_and_metrics_over_tcp() {
        let (state, _listener) = ops_state();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(serve_http(listener, state.clone(), 8));

        let response = request(address, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("application/json"));

        let response = request(address, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(response.contains("# TYPE rstun_requests_total counter"));

        let response = request(address, "POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 405"), "{response}");
        assert!(response.contains("Allow: GET, HEAD"));

        let response = request(address, &get("/healthz")).await;
        assert!(response.starts_with("HTTP/1.1 200"));

        server.abort();
    }

    /// The readiness judgement end-to-end: a listener that stopped serving
    /// flips `/healthz` from 200 to 503 over a real socket.
    #[tokio::test]
    async fn a_stale_listener_turns_the_endpoint_into_503() {
        let (state, listener) = ops_state();
        let net = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = net.local_addr().expect("local address");
        let server = tokio::spawn(serve_http(net, state.clone(), 8));

        let response = request(address, &get("/healthz")).await;
        assert!(response.starts_with("HTTP/1.1 200"));

        // What a listener task does when it returns / is aborted.
        drop(listener.lease());

        let response = request(address, &get("/healthz")).await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("\"stale\":[\"udp 127.0.0.1:3478\"]"));

        server.abort();
    }

    /// A slow client cannot renew the budget by dripping bytes: the 2 s covers
    /// the whole head, not each read.
    ///
    /// The drip (one byte every 300 ms) is what separates the two rules: a
    /// per-read timeout would never fire, the total deadline must fire at ≈2 s.
    #[tokio::test]
    async fn a_dripping_client_is_cut_off_by_the_total_deadline() {
        let (state, _listener) = ops_state();
        let net = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = net.local_addr().expect("local address");
        let server = tokio::spawn(serve_http(net, state.clone(), 8));

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let (mut reader, mut writer) = stream.into_split();
        writer.write_all(b"G").await.expect("first byte");

        let dripper = tokio::spawn(async move {
            loop {
                if writer.write_all(b"E").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });

        let started = std::time::Instant::now();
        let mut buffer = [0_u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buffer))
            .await
            .expect("the server must close the connection at the total deadline");
        // Nothing is answered to an unfinished head: the close shows up as EOF
        // (or as an error) rather than as a response.
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "the deadline must be the total, not per read: {elapsed:?}"
        );
        dripper.abort();
        server.abort();
    }

    /// Over the cap: the extra connection gets an immediate 503 instead of a
    /// queue slot (and the healthy path keeps working once slots free up).
    #[tokio::test]
    async fn connections_over_the_cap_get_503_and_the_endpoint_keeps_serving() {
        let (state, _listener) = ops_state();
        let net = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = net.local_addr().expect("local address");
        let server = tokio::spawn(serve_http(net, state.clone(), 2));

        // Two idle connections fill the cap without sending a byte.
        let idle_a = tokio::net::TcpStream::connect(address).await.expect("a");
        let idle_b = tokio::net::TcpStream::connect(address).await.expect("b");
        // Give the accept loop a moment to take both permits.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let response = request(address, &get("/healthz")).await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("too many concurrent connections"));
        assert_eq!(state.stats.ops_rejected(), 1);

        // The endpoint itself is still alive (draining the rejected connection
        // is what the 503 above proves) — free a slot and ask again.
        drop(idle_a);
        drop(idle_b);
        let mut response = String::new();
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            response = request(address, &get("/healthz")).await;
            if response.starts_with("HTTP/1.1 200") {
                break;
            }
        }
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        server.abort();
    }

    /// The documented head limit is exact: `HTTP_MAX_HEAD` bytes of head are
    /// served, one byte more is a 400.
    #[tokio::test]
    async fn the_head_limit_is_exactly_the_documented_number_of_bytes() {
        let (state, _listener) = ops_state();
        let net = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = net.local_addr().expect("local address");
        let server = tokio::spawn(serve_http(net, state.clone(), 8));

        let head = |total: usize| {
            let prefix = "GET /healthz HTTP/1.1\r\nHost: probe\r\nX-Filler: ";
            let suffix = "\r\n\r\n";
            let filler = total - prefix.len() - suffix.len();
            format!("{prefix}{}{suffix}", "a".repeat(filler))
        };
        let exact = head(HTTP_MAX_HEAD);
        assert_eq!(exact.len(), HTTP_MAX_HEAD);
        let response = request(address, &exact).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");

        let over = head(HTTP_MAX_HEAD + 1);
        assert_eq!(over.len(), HTTP_MAX_HEAD + 1);
        let response = request(address, &over).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert!(response.contains("request head too large"));

        server.abort();
    }

    async fn request(address: SocketAddr, head: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        stream.write_all(head.as_bytes()).await.expect("write");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .expect("response within 2s")
            .expect("read");
        String::from_utf8_lossy(&response).into_owned()
    }
}
