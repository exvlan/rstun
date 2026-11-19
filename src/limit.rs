//! Admission control in front of `decide()`: per-source token buckets, a
//! global rate cap, an in-flight cap, CIDR allow/deny lists, and the
//! configuration of the reflection guard.
//!
//! Everything here is **opt-in**. `main` builds an [`Admission`] only when at
//! least one abuse-guard flag was given; with no flag no table is allocated,
//! no sweeper is spawned and the request path is byte-for-byte the pre-guard
//! one (`protocol::tests::plain_response_bytes_are_frozen` keeps that honest).
//!
//! Threat model (see `.trellis/tasks/11-19-rstun-abuse-guard/design.md` §2):
//!
//! | 威胁 | 特征 | 防线 |
//! | --- | --- | --- |
//! | 真实客户端滥用 | 固定源 IP、高频 | 每源 IP 令牌桶（[`RateLimiter`]）|
//! | **伪造源反射** | 源 IP 随机、请求小、响应大 | 每 IP 限速**无效**；靠 `main` 的反射防护（最小请求尺寸 + 放大比）|
//! | 单点洪水 | 任意源、总量巨大 | 全局速率 + 在途上限（[`Semaphore`]）|
//! | 定向封禁 | 少量网段 | `--allow` / `--deny`（[`NetPolicy`]）|
//!
//! Design notes worth keeping:
//!
//! * the table is sharded 64 ways with a plain `std::sync::Mutex` per shard —
//!   no new dependency, and 64 shards keep contention away from the hot path;
//! * entries are recycled lazily (an entry untouched for [`ENTRY_TTL`] starts
//!   over) **and** capped ([`MAX_ENTRIES`]), so memory has a hard upper bound
//!   even under a spoofed-source flood;
//! * time is a parameter (`Instant`) everywhere, so rate/burst/clock-rollback
//!   behaviour is unit-tested without sleeping.

use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How many shards the per-key tables are split into.
pub const SHARDS: usize = 64;
/// Hard cap on the number of tracked keys (all shards together).
pub const MAX_ENTRIES: usize = 65_536;
/// An entry that has not been touched for this long starts from a full bucket
/// again (and is dropped by the background sweep).
pub const ENTRY_TTL: Duration = Duration::from_secs(600);
/// How often the background sweep walks the tables.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Smallest frame the reflection guard will look at: a STUN header
/// (`protocol::HEADER_LEN`). It is deliberately **not** the size of a redirect
/// probe — the smallest datagram that can carry `RESPONSE-PORT` is 28 bytes,
/// and refusing those by size would disable RFC 5780 for every real client
/// (coturn's `stunclient` sends exactly 28-byte `CHANGE-REQUEST` probes).
pub const DEFAULT_REFLECT_MIN_REQUEST: usize = crate::protocol::HEADER_LEN;
/// How much larger than the request a **redirect** answer may be before
/// [`REFLECT_ALLOWANCE`] is added.
pub const DEFAULT_REFLECT_RATIO: f64 = 2.0;
/// Fixed growth a redirect answer is allowed on top of the ratio.
///
/// A redirect answer always carries `XOR-MAPPED-ADDRESS` (12 bytes) and, with
/// `--alt-listen`, `RESPONSE-ORIGIN` + `OTHER-ADDRESS` (24 bytes) = **32 bytes**
/// that the request does not pay for; `SOFTWARE` (20) is *optional* and is left
/// out of small redirect answers on purpose (see `main::answer_software`), so it
/// is not part of the allowance.
///
/// 32 is therefore the irreducible overhead of a redirect answer: a 28-byte
/// RFC 5780 probe gets a 32-byte answer without `--alt-listen` and 56 bytes with
/// it (2.0x), and the ratio still bounds anything the client can scale. The
/// guard thus accepts the fixed attributes and rejects real growth
/// (`> max(len × ratio, len + 32)`), which is what makes it a guard rather than
/// a formality.
pub const REFLECT_ALLOWANCE: usize = 32;

const SHARD_CAPACITY: usize = MAX_ENTRIES / SHARDS;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// One token bucket's shape: `per_second` tokens added per second, never more
/// than `burst` stored.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    pub per_second: f64,
    pub burst: f64,
}

impl Rate {
    pub fn new(per_second: f64, burst: f64) -> Self {
        Self { per_second, burst }
    }
}

/// The reflection guard's numbers (RFC 5780 `RESPONSE-PORT` /
/// `CHANGE-REQUEST`, see `main::reflect_guard`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reflect {
    /// Requests shorter than this are refused outright.
    pub min_request: usize,
    /// The answer may not exceed `request_len × ratio` (see
    /// [`Reflect::allows_response`] for the fixed allowance that is added on
    /// top of it).
    pub ratio: f64,
}

impl Reflect {
    /// Largest answer this policy accepts for a request of `request_len` bytes.
    ///
    /// `max(len × ratio, len + REFLECT_ALLOWANCE)`: the ratio bounds what an
    /// attacker can *scale*, the allowance pays for the constant attributes
    /// every redirect answer carries (see [`REFLECT_ALLOWANCE`]).
    pub fn allowed_response_len(&self, request_len: usize) -> f64 {
        (request_len as f64 * self.ratio).max((request_len + REFLECT_ALLOWANCE) as f64)
    }

    /// `true` when an answer of `response_len` bytes stays within the policy.
    pub fn allows_response(&self, request_len: usize, response_len: usize) -> bool {
        response_len as f64 <= self.allowed_response_len(request_len)
    }
}

/// Everything the abuse-guard flags configure. Built once at startup; an
/// `Admission` is only created when at least one field is set.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Policy {
    pub per_ip: Option<Rate>,
    pub per_port: Option<Rate>,
    pub global: Option<Rate>,
    pub max_inflight: Option<usize>,
    pub reflect: Option<Reflect>,
    pub allow: Vec<IpNet>,
    pub deny: Vec<IpNet>,
}

impl Policy {
    /// `true` when nothing was configured: the caller then keeps the old path.
    pub fn is_off(&self) -> bool {
        self.per_ip.is_none()
            && self.per_port.is_none()
            && self.global.is_none()
            && self.max_inflight.is_none()
            && self.reflect.is_none()
            && self.allow.is_empty()
            && self.deny.is_empty()
    }

    /// Reject values the buckets cannot honour. Called after CLI parsing, so a
    /// typo (`--rate-limit 0`) fails startup instead of silently disabling or
    /// wedging the limiter.
    pub fn validate(&self) -> Result<(), String> {
        let rates = [
            ("--rate-limit", self.per_ip),
            ("--rate-limit-port", self.per_port),
            ("--global-rate", self.global),
        ];
        for (flag, rate) in rates {
            let Some(rate) = rate else { continue };
            if rate.per_second <= 0.0 || !rate.per_second.is_finite() {
                return Err(format!("{flag} must be greater than 0"));
            }
            if rate.burst < 1.0 || !rate.burst.is_finite() {
                return Err(format!("the burst for {flag} must be at least 1"));
            }
        }
        if let Some(max_inflight) = self.max_inflight
            && max_inflight == 0
        {
            return Err("--max-inflight must be at least 1".to_string());
        }
        if let Some(reflect) = self.reflect {
            if reflect.min_request < crate::protocol::HEADER_LEN {
                return Err(format!(
                    "--reflect-min-request must be at least {} (a STUN header)",
                    crate::protocol::HEADER_LEN
                ));
            }
            if reflect.ratio <= 0.0 || !reflect.ratio.is_finite() {
                return Err("--reflect-ratio must be greater than 0".to_string());
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CIDR matching
// ---------------------------------------------------------------------------

/// A CIDR block, parsed without a new dependency (`ipnet` would be one for a
/// job that is a mask and a compare).
///
/// A bare address (`127.0.0.1`) is accepted and means the single-host prefix.
/// Host bits are masked (`10.1.2.3/8` == `10.0.0.0/8`) so two spellings of the
/// same block compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    network: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn new(address: IpAddr, prefix: u8) -> Result<Self, String> {
        let width = if address.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return Err(format!(
                "prefix /{prefix} is out of range for {address} (max /{width})"
            ));
        }
        Ok(Self {
            network: mask(address, prefix),
            prefix,
        })
    }

    /// Longest-prefix matching needs this to break ties.
    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        // A v6 rule never matches a v4 address and vice versa; `mask` would
        // otherwise compare unrelated bit patterns.
        if address.is_ipv4() != self.network.is_ipv4() {
            return false;
        }
        mask(address, self.prefix) == self.network
    }
}

impl FromStr for IpNet {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("{text:?} is not an IP address or CIDR block"))?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|_| format!("{text:?}: the prefix length must be 0-{width}"))?,
            None => width,
        };
        Self::new(address, prefix)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

fn mask(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & prefix_mask32(prefix))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & prefix_mask128(prefix))),
    }
}

fn prefix_mask32(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        prefix => u32::MAX << (32 - prefix),
    }
}

fn prefix_mask128(prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        prefix => u128::MAX << (128 - prefix),
    }
}

/// `::ffff:a.b.c.d` (IPv4-mapped IPv6) is a v4 address on the wire; folding it
/// keeps one bucket per real peer and lets `--deny 10.0.0.0/8` match a
/// connection that arrived on a dual-stack v6 socket.
///
/// Only the mapped form is folded: the deprecated `::a.b.c.d` compatibility
/// form is treated as plain IPv6, which is what modern stacks do too.
pub fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => address,
    }
}

/// Longest-prefix match over `--allow` / `--deny`, deny winning ties.
///
/// The rule list is small (a handful of operator-written CIDRs), so a linear
/// scan is cheaper than building a trie and much easier to reason about.
#[derive(Debug, Clone, Default)]
pub struct NetPolicy {
    rules: Vec<(IpNet, bool /* allow */)>,
}

impl NetPolicy {
    pub fn new(allow: &[IpNet], deny: &[IpNet]) -> Self {
        let mut rules = Vec::with_capacity(allow.len() + deny.len());
        rules.extend(allow.iter().map(|net| (*net, true)));
        rules.extend(deny.iter().map(|net| (*net, false)));
        Self { rules }
    }

    /// `Some(true)` = allowlisted (rate limits bypassed), `Some(false)` =
    /// denied, `None` = no rule matches.
    pub fn classify(&self, address: IpAddr) -> Option<bool> {
        let mut best: Option<(u8, bool)> = None;
        for (net, allow) in &self.rules {
            if !net.contains(address) {
                continue;
            }
            let prefix = net.prefix_len();
            best = match best {
                // Longer prefix wins...
                Some((length, allowed)) if length > prefix => Some((length, allowed)),
                // ...and on a tie deny wins (`allow && <deny>` is false).
                Some((length, allowed)) if length == prefix => Some((length, allowed && *allow)),
                _ => Some((prefix, *allow)),
            };
        }
        best.map(|(_, allow)| allow)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Token buckets
// ---------------------------------------------------------------------------

/// One key's bucket: how many tokens are left, and when we last touched it.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    /// Add the tokens earned since `last`, capped at `burst`.
    ///
    /// A clock that goes backwards (monotonic clocks do not, but tests inject
    /// `Instant`s) grants nothing and re-anchors at the new "now", so a caller
    /// cannot bank time by moving the clock back and forth.
    fn refill(&mut self, now: Instant, rate: f64, burst: f64) {
        match now.checked_duration_since(self.last) {
            Some(elapsed) => {
                self.tokens = (self.tokens + elapsed.as_secs_f64() * rate).min(burst);
                self.last = now;
            }
            None => self.last = now,
        }
    }

    fn try_take(&mut self, now: Instant, rate: f64, burst: f64, ttl: Duration) -> bool {
        // Idle longer than the TTL: start over, so a peer that comes back after
        // a long pause is not still "punished" and the entry looks fresh.
        if now.saturating_duration_since(self.last) > ttl {
            *self = Self::full(burst, now);
        }
        self.refill(now, rate, burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Sharded `key → Bucket` table.
///
/// `K` is an `IpAddr` in production and a `SocketAddr` for the per-port bucket.
#[derive(Debug)]
pub struct RateLimiter<K> {
    shards: Vec<Mutex<HashMap<K, Bucket>>>,
    rate: f64,
    burst: f64,
    ttl: Duration,
    /// How many entries have been recycled out of a full shard; drives the
    /// sampling in [`recycle`].
    evictions: AtomicU64,
}

/// One in [`EVICTION_SCAN_EVERY`] recycles does the full "find the stalest"
/// scan; the rest drop an arbitrary entry (see [`recycle`]).
const EVICTION_SCAN_EVERY: u64 = 32;

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    pub fn new(rate: f64, burst: f64) -> Self {
        debug_assert!(rate > 0.0, "a limiter without a rate must not be built");
        debug_assert!(burst >= 1.0, "a burst below one token rejects everything");
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            rate,
            burst,
            ttl: ENTRY_TTL,
            evictions: AtomicU64::new(0),
        }
    }

    /// Take one token for `key`; `false` means "over the limit right now".
    pub fn try_take(&self, key: &K, now: Instant) -> bool {
        let mut table = lock(&self.shards[shard_of(key)]);
        if !table.contains_key(key) && table.len() >= SHARD_CAPACITY {
            // Bounded memory: recycle one entry so the new key still gets its
            // bucket (a spoofed-source flood cannot lock everyone else out).
            let evictions = self.evictions.fetch_add(1, Ordering::Relaxed);
            recycle(&mut table, evictions.is_multiple_of(EVICTION_SCAN_EVERY));
        }
        let bucket = table
            .entry(key.clone())
            .or_insert_with(|| Bucket::full(self.burst, now));
        bucket.try_take(now, self.rate, self.burst, self.ttl)
    }

    /// Drop entries idle longer than the TTL; returns how many went away.
    pub fn sweep(&self, now: Instant) -> usize {
        let mut removed = 0;
        for shard in &self.shards {
            let mut table = lock(shard);
            let before = table.len();
            table.retain(|_, bucket| now.saturating_duration_since(bucket.last) <= self.ttl);
            removed += before - table.len();
        }
        removed
    }

    /// Test-only: is this key currently tracked?
    #[cfg(test)]
    pub fn contains(&self, key: &K) -> bool {
        lock(&self.shards[shard_of(key)]).contains_key(key)
    }

    /// Tracked keys, all shards together (tests + exit diagnostics).
    pub fn entries(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| lock(shard).len())
            .sum::<usize>()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while a bucket was locked must not take the limiter down with it:
    // the table is only ever left consistent enough to keep using.
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn shard_of<K: Hash>(key: &K) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % SHARDS
}

/// Make room in a full shard.
///
/// A full scan finds the truly stalest entry but costs O(shard capacity); doing
/// that on *every* insert into a full shard would make a spoofed-source flood
/// quadratic (`1024` comparisons per packet). The scan therefore runs only on
/// every [`EVICTION_SCAN_EVERY`]-th recycle (~32 comparisons/packet amortised);
/// the other times one arbitrary entry (HashMap iteration order) is dropped,
/// which keeps the table bounded in O(1) and still recycles idle entries within
/// a few inserts. The very first recycle always scans, so the "stalest goes
/// first" behaviour is what a short burst sees.
fn recycle<K: Clone + Eq + Hash>(table: &mut HashMap<K, Bucket>, scan: bool) {
    let victim = if scan {
        table
            .iter()
            .min_by_key(|(_, bucket)| bucket.last)
            .map(|(key, _)| key.clone())
    } else {
        table.keys().next().cloned()
    };
    if let Some(victim) = victim {
        table.remove(&victim);
    }
}

/// The `--global-rate` bucket: one mutex, because there is exactly one.
#[derive(Debug)]
struct GlobalBucket {
    bucket: Mutex<Bucket>,
    rate: f64,
    burst: f64,
}

impl GlobalBucket {
    fn new(rate: f64, burst: f64, now: Instant) -> Self {
        Self {
            bucket: Mutex::new(Bucket::full(burst, now)),
            rate,
            burst,
        }
    }

    fn try_take(&self, now: Instant) -> bool {
        lock(&self.bucket).try_take(now, self.rate, self.burst, ENTRY_TTL)
    }
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Atomic refusal counters. Reported at exit (`rstun: abuse guard counters`)
/// and cheap enough (one `Relaxed` add) to keep on the hot path.
#[derive(Debug, Default)]
pub struct Counters {
    rate_limited_ip: AtomicU64,
    rate_limited_port: AtomicU64,
    rate_limited_global: AtomicU64,
    inflight_dropped: AtomicU64,
    denied: AtomicU64,
    reflect_rejected: AtomicU64,
    allowlisted: AtomicU64,
}

/// A consistent-enough snapshot of [`Counters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub rate_limited_ip: u64,
    pub rate_limited_port: u64,
    pub rate_limited_global: u64,
    pub inflight_dropped: u64,
    pub denied: u64,
    pub reflect_rejected: u64,
    pub allowlisted: u64,
}

impl Counters {
    fn bump(counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn snapshot(&self) -> Counts {
        Counts {
            rate_limited_ip: self.rate_limited_ip.load(Ordering::Relaxed),
            rate_limited_port: self.rate_limited_port.load(Ordering::Relaxed),
            rate_limited_global: self.rate_limited_global.load(Ordering::Relaxed),
            inflight_dropped: self.inflight_dropped.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            reflect_rejected: self.reflect_rejected.load(Ordering::Relaxed),
            allowlisted: self.allowlisted.load(Ordering::Relaxed),
        }
    }
}

/// Why a request was refused before `decide()` ever saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Matched `--deny` (longest prefix, deny winning ties).
    Denied,
    /// The in-flight cap (`--max-inflight`) is full.
    Inflight,
    /// The `--global-rate` bucket is empty.
    Global,
    /// The source-IP bucket is empty.
    PerIp,
    /// The source IP+port bucket is empty.
    PerPort,
}

impl Refusal {
    /// Short label for logs.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Denied => "denied (CIDR)",
            Self::Inflight => "in-flight cap",
            Self::Global => "global rate",
            Self::PerIp => "per-source-IP rate",
            Self::PerPort => "per-source-port rate",
        }
    }

    /// Counter name, matching the exit-stats fields.
    pub const fn counter(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Inflight => "inflight_dropped",
            Self::Global => "rate_limited_global",
            Self::PerIp => "rate_limited_ip",
            Self::PerPort => "rate_limited_port",
        }
    }
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// The in-flight slot a request holds until its answer has been sent. Dropping
/// it is what releases the slot, so an early return can never leak a permit.
#[derive(Debug)]
pub struct Permit {
    _inflight: Option<OwnedSemaphorePermit>,
}

/// The abuse guard itself: buckets, the in-flight cap, the CIDR lists and their
/// counters. Shared (`Arc`) by every listener task.
#[derive(Debug)]
pub struct Admission {
    policy: Policy,
    nets: NetPolicy,
    per_ip: Option<RateLimiter<IpAddr>>,
    per_port: Option<RateLimiter<SocketAddr>>,
    global: Option<GlobalBucket>,
    inflight: Option<Arc<Semaphore>>,
    counters: Counters,
}

impl Admission {
    /// Build the guard from a validated policy (`--rate-limit 0`, a burst of 0,
    /// `/129` … are startup errors, not silent no-ops).
    pub fn new(policy: Policy) -> Result<Arc<Self>, String> {
        policy.validate()?;
        let now = Instant::now();
        let global = policy
            .global
            .map(|rate| GlobalBucket::new(rate.per_second, rate.burst, now));
        Ok(Arc::new(Self {
            nets: NetPolicy::new(&policy.allow, &policy.deny),
            per_ip: policy
                .per_ip
                .map(|rate| RateLimiter::new(rate.per_second, rate.burst)),
            per_port: policy
                .per_port
                .map(|rate| RateLimiter::new(rate.per_second, rate.burst)),
            global,
            inflight: policy
                .max_inflight
                .map(|slots| Arc::new(Semaphore::new(slots))),
            counters: Counters::default(),
            policy,
        }))
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn counters(&self) -> Counts {
        self.counters.snapshot()
    }

    /// One `reflect_rejected`: the reflection guard lives in `main` (it needs
    /// the parsed message), but the counter belongs with the rest.
    pub fn count_reflect_rejected(&self) -> u64 {
        Counters::bump(&self.counters.reflect_rejected)
    }

    /// Decide whether one datagram may be processed: CIDR lists, then the
    /// in-flight slot, then the rate buckets. That is the UDP shape, where
    /// "one message" and "one unit of work" are the same thing.
    ///
    /// The order is the design's: `--deny` is an operator decision and should
    /// win over any capacity accounting, and the in-flight cap is checked before
    /// the buckets so a full server does not burn rate-limit tokens on requests
    /// it will refuse anyway.
    pub fn admit(&self, peer: SocketAddr, now: Instant) -> Result<Permit, Refusal> {
        let allowlisted = self.check_nets(peer.ip())?;
        let permit = self.acquire_inflight()?;
        self.check_buckets(peer, now, allowlisted)?;
        Ok(permit)
    }

    /// `true` when `--allow` names this address.
    ///
    /// Used where the CIDR list is not consulted by [`Self::check_rates`] (the
    /// reflection guard): an allowlisted source is trusted enough to ask for
    /// `RESPONSE-PORT`/`CHANGE-REQUEST` without the amplification rules.
    pub fn is_allowlisted(&self, address: IpAddr) -> bool {
        self.nets.classify(normalize_ip(address)) == Some(true)
    }

    /// Take one in-flight slot, or refuse.
    ///
    /// Split from [`Self::check_rates`] because TCP counts different things on
    /// purpose: a *connection* occupies an fd and a task for as long as it
    /// lives (30 s read timeout), so the slot is taken at `accept` time and
    /// held for the connection; the rate buckets are then checked per request
    /// (otherwise one connection could pipeline unlimited requests).
    pub fn acquire_inflight(&self) -> Result<Permit, Refusal> {
        let inflight = match &self.inflight {
            Some(semaphore) => match Arc::clone(semaphore).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    Counters::bump(&self.counters.inflight_dropped);
                    return Err(Refusal::Inflight);
                }
            },
            None => None,
        };
        Ok(Permit {
            _inflight: inflight,
        })
    }

    /// CIDR lists plus the rate buckets (no in-flight; used per TCP request,
    /// where the slot is already held by the connection).
    pub fn check_rates(&self, peer: SocketAddr, now: Instant) -> Result<(), Refusal> {
        let allowlisted = self.check_nets(peer.ip())?;
        self.check_buckets(peer, now, allowlisted)
    }

    /// `--deny` / `--allow`, longest prefix, deny winning ties.
    ///
    /// Returns "is this source allowlisted": such a source skips the
    /// *per-source* buckets and the reflection guard, but still counts against
    /// the global rate and the in-flight cap — those protect the process, not
    /// fairness between sources.
    pub fn check_nets(&self, address: IpAddr) -> Result<bool, Refusal> {
        match self.nets.classify(normalize_ip(address)) {
            Some(false) => {
                Counters::bump(&self.counters.denied);
                Err(Refusal::Denied)
            }
            Some(true) => {
                Counters::bump(&self.counters.allowlisted);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Global rate, then per-IP, then per IP+port.
    fn check_buckets(
        &self,
        peer: SocketAddr,
        now: Instant,
        allowlisted: bool,
    ) -> Result<(), Refusal> {
        let ip = normalize_ip(peer.ip());

        if let Some(global) = &self.global
            && !global.try_take(now)
        {
            Counters::bump(&self.counters.rate_limited_global);
            return Err(Refusal::Global);
        }

        if !allowlisted {
            if let Some(limiter) = &self.per_ip
                && !limiter.try_take(&ip, now)
            {
                Counters::bump(&self.counters.rate_limited_ip);
                return Err(Refusal::PerIp);
            }
            if let Some(limiter) = &self.per_port
                && !limiter.try_take(&SocketAddr::new(ip, peer.port()), now)
            {
                Counters::bump(&self.counters.rate_limited_port);
                return Err(Refusal::PerPort);
            }
        }

        Ok(())
    }

    /// Drop idle entries from both per-key tables.
    pub fn sweep(&self, now: Instant) -> usize {
        let mut removed = 0;
        if let Some(limiter) = &self.per_ip {
            removed += limiter.sweep(now);
        }
        if let Some(limiter) = &self.per_port {
            removed += limiter.sweep(now);
        }
        removed
    }

    /// Tracked keys in the per-key tables (tests).
    pub fn entries(&self) -> usize {
        let mut entries = 0;
        if let Some(limiter) = &self.per_ip {
            entries += limiter.entries();
        }
        if let Some(limiter) = &self.per_port {
            entries += limiter.entries();
        }
        entries
    }
}

/// Spawn the 60 s sweeper. `None` when there is no per-key table to sweep, so
/// a process that only uses `--max-inflight`/`--allow` starts no task at all.
pub fn start_sweeper(admission: &Arc<Admission>) -> Option<tokio::task::JoinHandle<()>> {
    if admission.per_ip.is_none() && admission.per_port.is_none() {
        return None;
    }
    let admission = Arc::downgrade(admission);
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(admission) = admission.upgrade() else {
                return;
            };
            let removed = admission.sweep(Instant::now());
            if removed > 0 {
                tracing::debug!(removed, "rstun: rate-limit table swept");
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn at(base: Instant, millis: u64) -> Instant {
        base + Duration::from_millis(millis)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn net(text: &str) -> IpNet {
        text.parse().unwrap()
    }

    // ---------- CIDR ----------

    #[test]
    fn cidr_parses_v4_v6_and_bare_addresses() {
        assert_eq!(net("10.0.0.0/8").prefix_len(), 8);
        assert!(net("10.1.2.3").contains(Ipv4Addr::new(10, 1, 2, 3).into()));
        assert!(!net("10.1.2.3").contains(Ipv4Addr::new(10, 1, 2, 4).into()));
        assert!(net("2001:db8::/32").contains(ip("2001:db8:1234::1")));
        assert!(!net("2001:db8::/32").contains(ip("2001:db9::1")));
        // Host bits are masked, so two spellings of one block are equal.
        assert_eq!(net("10.1.2.3/8"), net("10.0.0.0/8"));
        assert!(net("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(net("::/0").contains(ip("2001:db8::1")));
        // A v6 rule never matches a v4 address (or the other way round).
        assert!(!net("::/0").contains(ip("10.0.0.1")));
        assert!(!net("0.0.0.0/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn cidr_rejects_bad_input() {
        for text in [
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "2001:db8::/129",
            "not-an-address/8",
            "10.0.0.0/8/8",
        ] {
            assert!(text.parse::<IpNet>().is_err(), "{text} should not parse");
        }
    }

    #[test]
    fn net_policy_uses_the_longest_prefix_and_deny_wins_ties() {
        // allow 10.0.0.0/8, deny 10.1.0.0/16: the longer deny wins inside .1/16.
        let policy = NetPolicy::new(&[net("10.0.0.0/8")], &[net("10.1.0.0/16")]);
        assert_eq!(policy.classify(ip("10.9.0.1")), Some(true));
        assert_eq!(policy.classify(ip("10.1.2.3")), Some(false));
        assert_eq!(policy.classify(ip("192.0.2.1")), None);

        // Same prefix length on both sides: deny wins.
        let tie = NetPolicy::new(&[net("192.0.2.0/24")], &[net("192.0.2.0/24")]);
        assert_eq!(tie.classify(ip("192.0.2.7")), Some(false));

        // An allow inside a broad deny still saves that block (longest prefix).
        let hole = NetPolicy::new(&[net("127.0.0.2/32")], &[net("127.0.0.0/8")]);
        assert_eq!(hole.classify(ip("127.0.0.2")), Some(true));
        assert_eq!(hole.classify(ip("127.0.0.1")), Some(false));
    }

    #[test]
    fn v4_mapped_v6_is_normalized_to_v4() {
        assert_eq!(normalize_ip(ip("::ffff:10.0.0.1")), ip("10.0.0.1"));
        assert_eq!(normalize_ip(ip("10.0.0.1")), ip("10.0.0.1"));
        assert_eq!(normalize_ip(ip("2001:db8::1")), ip("2001:db8::1"));
    }

    // ---------- reflection policy ----------

    #[test]
    fn reflect_defaults_are_the_documented_ones() {
        // `--reflect-min-request` is only the "is this a STUN frame" floor; a
        // 28-byte RFC 5780 probe must pass it. The ratio alone would reject
        // every real probe (see the allowance test), hence 2.0 + 32 bytes.
        assert_eq!(DEFAULT_REFLECT_MIN_REQUEST, 20);
        assert_eq!(DEFAULT_REFLECT_MIN_REQUEST, crate::protocol::HEADER_LEN);
        assert_eq!(DEFAULT_REFLECT_RATIO, 2.0);
        assert_eq!(REFLECT_ALLOWANCE, 32);
    }

    #[test]
    fn reflect_allowance_is_the_irreducible_overhead() {
        let policy = Reflect {
            min_request: DEFAULT_REFLECT_MIN_REQUEST,
            ratio: DEFAULT_REFLECT_RATIO,
        };

        // 28-byte RFC 5780 probe: 28 x 2 = 56, 28 + 32 = 60 -> the allowance
        // dominates. A 32-byte answer (no `--alt-listen`, no SOFTWARE) and the
        // 56-byte one with the RFC 5780 pair both fit; one byte more than the
        // allowance does not.
        assert_eq!(policy.allowed_response_len(28), 60.0);
        assert!(policy.allows_response(28, 32));
        assert!(policy.allows_response(28, 56));
        assert!(!policy.allows_response(28, 61));

        // For large requests the ratio term takes over: 1000 x 2 = 2000, not 1032.
        assert_eq!(policy.allowed_response_len(1000), 2000.0);
        assert!(policy.allows_response(1000, 2000));
        assert!(!policy.allows_response(1000, 2001));

        // The crossover is len = allowance / (ratio - 1) = 32; below it the
        // allowance wins, above it the ratio does.
        assert_eq!(policy.allowed_response_len(32), 64.0);
        assert_eq!(policy.allowed_response_len(33), 66.0);
    }

    // ---------- token buckets ----------

    #[test]
    fn bucket_allows_the_burst_then_refills_at_the_rate() {
        let mut bucket = Bucket::full(4.0, Instant::now());
        let start = Instant::now();
        // Burst of 4: the first four go through, the fifth does not.
        for take in 0..4 {
            assert!(bucket.try_take(start, 1.0, 4.0, ENTRY_TTL), "take {take}");
        }
        assert!(!bucket.try_take(start, 1.0, 4.0, ENTRY_TTL));
        // 1 req/s: 999 ms is not enough for a token, 1001 ms is.
        assert!(!bucket.try_take(at(start, 999), 1.0, 4.0, ENTRY_TTL));
        assert!(bucket.try_take(at(start, 1_001), 1.0, 4.0, ENTRY_TTL));
    }

    #[test]
    fn bucket_never_exceeds_the_burst_when_idle() {
        let mut bucket = Bucket::full(2.0, Instant::now());
        let start = Instant::now();
        for take in 0..2 {
            assert!(bucket.try_take(start, 10.0, 2.0, ENTRY_TTL), "take {take}");
        }
        // Ten seconds of idling at 10/s would be 100 tokens; the burst caps it.
        assert!(bucket.try_take(at(start, 10_000), 10.0, 2.0, ENTRY_TTL));
        assert!(bucket.try_take(at(start, 10_000), 10.0, 2.0, ENTRY_TTL));
        assert!(!bucket.try_take(at(start, 10_000), 10.0, 2.0, ENTRY_TTL));
    }

    #[test]
    fn a_backwards_clock_grants_no_tokens() {
        let start = Instant::now();
        let mut bucket = Bucket::full(1.0, start);
        assert!(bucket.try_take(start, 1.0, 1.0, ENTRY_TTL));
        // Move "now" behind `last`: no refill, and the bucket does not refill
        // twice by bouncing between the two instants.
        let earlier = start - Duration::from_secs(5);
        assert!(!bucket.try_take(earlier, 1.0, 1.0, ENTRY_TTL));
        // From the new anchor the bucket refills normally — and never above the
        // burst, so bouncing the clock cannot mint an unbounded allowance.
        assert!(bucket.try_take(start + Duration::from_secs(5), 1.0, 1.0, ENTRY_TTL));
        assert!(!bucket.try_take(start + Duration::from_secs(5), 1.0, 1.0, ENTRY_TTL));
    }

    #[test]
    fn an_idle_entry_starts_over_after_the_ttl() {
        let start = Instant::now();
        let mut bucket = Bucket::full(1.0, start);
        assert!(bucket.try_take(start, 0.001, 1.0, ENTRY_TTL));
        assert!(!bucket.try_take(start, 0.001, 1.0, ENTRY_TTL));
        // Past the TTL the history is forgotten: a full bucket again.
        assert!(bucket.try_take(at(start, 600_001), 0.001, 1.0, ENTRY_TTL));
    }

    #[test]
    fn limiter_limits_per_key_only() {
        let limiter: RateLimiter<IpAddr> = RateLimiter::new(1.0, 2.0);
        let start = Instant::now();
        let first = ip("203.0.113.1");
        let second = ip("203.0.113.2");
        assert!(limiter.try_take(&first, start));
        assert!(limiter.try_take(&first, start));
        assert!(!limiter.try_take(&first, start));
        // Another key has its own bucket and is untouched by the first one.
        assert!(limiter.try_take(&second, start));
        assert_eq!(limiter.entries(), 2);
    }

    /// `SHARD_CAPACITY` keys that all hash into the same shard.
    fn keys_in_one_shard(from: usize, count: usize) -> Vec<usize> {
        let target = shard_of(&from);
        (from..)
            .filter(|key| shard_of(key) == target)
            .take(count)
            .collect()
    }

    #[test]
    fn a_full_shard_recycles_the_stalest_entry() {
        let limiter: RateLimiter<usize> = RateLimiter::new(1.0, 1.0);
        let keys = keys_in_one_shard(0, SHARD_CAPACITY);
        assert_eq!(keys.len(), SHARD_CAPACITY);

        // Insert with a rising clock, so `keys[0]` is the oldest entry.
        let start = Instant::now();
        for (index, key) in keys.iter().enumerate() {
            assert!(limiter.try_take(key, start + Duration::from_millis(index as u64)));
        }
        assert_eq!(limiter.entries(), SHARD_CAPACITY, "the shard is full");

        // A new key in the same shard has to make room; the first recycle does
        // the full scan (see `recycle`), so the oldest entry goes.
        let target = shard_of(&keys[0]);
        let fresh = (keys[SHARD_CAPACITY - 1] + 1..)
            .find(|key| shard_of(key) == target)
            .expect("another key in the same shard");
        limiter.try_take(&fresh, start + Duration::from_secs(10));

        assert_eq!(limiter.entries(), SHARD_CAPACITY, "the cap still holds");
        assert!(
            !limiter.contains(&keys[0]),
            "the stalest entry was recycled"
        );
        assert!(limiter.contains(&keys[1]), "only one entry went away");
        assert!(limiter.contains(&fresh), "the new key got its bucket");
    }

    #[test]
    fn a_flood_keeps_the_whole_table_bounded() {
        // The global bound has to survive more keys than `MAX_ENTRIES`, including
        // the sampling path (only every 32nd recycle does the full scan).
        let limiter: RateLimiter<usize> = RateLimiter::new(1.0, 1.0);
        let start = Instant::now();
        for key in 0..(MAX_ENTRIES + SHARDS * 8) {
            limiter.try_take(&key, start);
        }
        assert!(
            limiter.entries() <= MAX_ENTRIES,
            "entries {} exceeded the cap {}",
            limiter.entries(),
            MAX_ENTRIES
        );
        assert!(limiter.entries() > 0);
    }

    #[test]
    fn sweep_drops_idle_entries_only() {
        let limiter: RateLimiter<IpAddr> = RateLimiter::new(1.0, 1.0);
        let start = Instant::now();
        limiter.try_take(&ip("198.51.100.1"), start);
        limiter.try_take(&ip("198.51.100.2"), at(start, 300_000));
        assert_eq!(limiter.sweep(at(start, 600_001)), 1);
        assert_eq!(limiter.entries(), 1);
        assert_eq!(limiter.sweep(at(start, 900_001)), 1);
        assert_eq!(limiter.entries(), 0);
    }

    // ---------- admission ----------

    #[test]
    fn deny_is_checked_before_capacity_and_buckets() {
        // Order is 名单 -> 在途 -> 速率: an operator ban must not be reported as
        // "in-flight full", and a request refused for capacity must not burn a
        // rate-limit token.
        let admission = admission(Policy {
            max_inflight: Some(1),
            per_ip: Some(Rate::new(0.001, 1.0)),
            deny: vec![net("10.0.0.0/8")],
            ..Policy::default()
        });
        let now = Instant::now();
        let held = admission.admit(peer("198.51.100.1:5000"), now).unwrap();
        assert_eq!(
            admission.admit(peer("10.1.2.3:5000"), now).unwrap_err(),
            Refusal::Denied
        );
        // Another source hits the cap, not its empty bucket...
        assert_eq!(
            admission.admit(peer("198.51.100.2:5000"), now).unwrap_err(),
            Refusal::Inflight
        );
        // ...so its token is still there once the slot is free.
        drop(held);
        assert!(admission.admit(peer("198.51.100.2:5000"), now).is_ok());
    }

    #[test]
    fn allowlisted_sources_are_known_to_the_reflection_guard() {
        let admission = admission(Policy {
            allow: vec![net("127.0.0.2/32")],
            deny: vec![net("127.0.0.3/32")],
            ..Policy::default()
        });
        assert!(admission.is_allowlisted(ip("127.0.0.2")));
        // v4-mapped spelling of an allowlisted v4 address still matches.
        assert!(admission.is_allowlisted(ip("::ffff:127.0.0.2")));
        assert!(
            !admission.is_allowlisted(ip("127.0.0.3")),
            "deny is not allow"
        );
        assert!(!admission.is_allowlisted(ip("127.0.0.4")));
    }

    // ---------- admission ----------

    fn admission(policy: Policy) -> Arc<Admission> {
        Admission::new(policy).expect("policy must build")
    }

    fn peer(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn zero_and_negative_values_are_rejected() {
        for policy in [
            Policy {
                per_ip: Some(Rate::new(0.0, 1.0)),
                ..Policy::default()
            },
            Policy {
                per_ip: Some(Rate::new(1.0, 0.0)),
                ..Policy::default()
            },
            Policy {
                global: Some(Rate::new(-1.0, 1.0)),
                ..Policy::default()
            },
            Policy {
                max_inflight: Some(0),
                ..Policy::default()
            },
            Policy {
                reflect: Some(Reflect {
                    min_request: 19,
                    ratio: 1.0,
                }),
                ..Policy::default()
            },
            Policy {
                reflect: Some(Reflect {
                    min_request: 40,
                    ratio: 0.0,
                }),
                ..Policy::default()
            },
        ] {
            assert!(Admission::new(policy.clone()).is_err(), "{policy:?}");
        }
    }

    #[test]
    fn an_empty_policy_is_off() {
        assert!(Policy::default().is_off());
        assert!(
            !Policy {
                deny: vec![net("10.0.0.0/8")],
                ..Policy::default()
            }
            .is_off()
        );
    }

    #[test]
    fn deny_refuses_even_when_nothing_else_is_configured() {
        let admission = admission(Policy {
            deny: vec![net("127.0.0.1/32")],
            ..Policy::default()
        });
        let now = Instant::now();
        assert_eq!(
            admission.admit(peer("127.0.0.1:5000"), now).unwrap_err(),
            Refusal::Denied
        );
        assert!(admission.admit(peer("127.0.0.2:5000"), now).is_ok());
        assert_eq!(admission.counters().denied, 1);
    }

    #[test]
    fn allow_bypasses_the_per_source_buckets() {
        let admission = admission(Policy {
            per_ip: Some(Rate::new(0.001, 1.0)),
            allow: vec![net("127.0.0.2/32")],
            ..Policy::default()
        });
        let now = Instant::now();
        // The allowlisted source can spend far more than its single token...
        for _ in 0..5 {
            assert!(admission.admit(peer("127.0.0.2:4010"), now).is_ok());
        }
        assert_eq!(admission.counters().allowlisted, 5);
        // ...while everyone else is held to one token per second.
        assert!(admission.admit(peer("198.51.100.7:5000"), now).is_ok());
        assert_eq!(
            admission.admit(peer("198.51.100.7:5000"), now).unwrap_err(),
            Refusal::PerIp
        );
    }

    #[test]
    fn an_allowlisted_source_still_counts_against_the_global_rate() {
        // `--allow` is about fairness between sources; the global bucket and the
        // in-flight cap protect the process and are never bypassed.
        let admission = admission(Policy {
            global: Some(Rate::new(0.001, 2.0)),
            allow: vec![net("127.0.0.2/32")],
            ..Policy::default()
        });
        let now = Instant::now();
        assert!(admission.admit(peer("127.0.0.2:4010"), now).is_ok());
        assert!(admission.admit(peer("127.0.0.2:4010"), now).is_ok());
        assert_eq!(
            admission.admit(peer("127.0.0.2:4010"), now).unwrap_err(),
            Refusal::Global
        );
    }

    #[test]
    fn per_port_bucket_is_separate_from_the_per_ip_bucket() {
        let admission = admission(Policy {
            per_ip: Some(Rate::new(0.001, 10.0)),
            per_port: Some(Rate::new(0.001, 1.0)),
            ..Policy::default()
        });
        let now = Instant::now();
        assert!(admission.admit(peer("198.51.100.7:5000"), now).is_ok());
        assert_eq!(
            admission.admit(peer("198.51.100.7:5000"), now).unwrap_err(),
            Refusal::PerPort
        );
        // Same IP, another source port: a fresh per-port bucket.
        assert!(admission.admit(peer("198.51.100.7:5001"), now).is_ok());
    }

    #[test]
    fn inflight_slots_are_released_when_the_permit_is_dropped() {
        let admission = admission(Policy {
            max_inflight: Some(2),
            ..Policy::default()
        });
        let now = Instant::now();
        let first = admission.admit(peer("198.51.100.7:5000"), now).unwrap();
        let second = admission.admit(peer("198.51.100.8:5000"), now).unwrap();
        assert_eq!(
            admission.admit(peer("198.51.100.9:5000"), now).unwrap_err(),
            Refusal::Inflight
        );
        drop(first);
        assert!(admission.admit(peer("198.51.100.9:5000"), now).is_ok());
        drop(second);
        assert_eq!(admission.counters().inflight_dropped, 1);
    }

    #[test]
    fn a_connection_holds_one_slot_and_makes_many_rate_checked_requests() {
        // TCP 的形状：槽位按连接持有，速率按请求检查 —— 两者不能互相顶替，
        // 否则一条连接可以流水无限请求，或者一个请求吃掉两个槽位。
        let admission = admission(Policy {
            max_inflight: Some(2),
            per_ip: Some(Rate::new(0.001, 3.0)),
            ..Policy::default()
        });
        let now = Instant::now();
        let connection = admission.acquire_inflight().unwrap();
        let other = admission.acquire_inflight().unwrap();
        assert_eq!(admission.acquire_inflight().unwrap_err(), Refusal::Inflight);

        // Per-request checks do not consume a second slot...
        for take in 0..3 {
            assert!(
                admission.check_rates(peer("127.0.0.1:5000"), now).is_ok(),
                "request {take}"
            );
        }
        assert_eq!(
            admission
                .check_rates(peer("127.0.0.1:5000"), now)
                .unwrap_err(),
            Refusal::PerIp
        );

        // ...and closing a connection returns its slot.
        drop(connection);
        assert!(admission.acquire_inflight().is_ok());
        drop(other);
        assert_eq!(admission.counters().inflight_dropped, 1);
    }

    #[test]
    fn global_rate_caps_the_total_across_sources() {
        let admission = admission(Policy {
            global: Some(Rate::new(0.001, 2.0)),
            ..Policy::default()
        });
        let now = Instant::now();
        assert!(admission.admit(peer("198.51.100.1:5000"), now).is_ok());
        assert!(admission.admit(peer("198.51.100.2:5000"), now).is_ok());
        assert_eq!(
            admission.admit(peer("198.51.100.3:5000"), now).unwrap_err(),
            Refusal::Global
        );
        assert_eq!(admission.counters().rate_limited_global, 1);
    }

    #[tokio::test]
    async fn sweeper_is_only_spawned_when_a_table_exists() {
        let no_table = admission(Policy {
            max_inflight: Some(4),
            ..Policy::default()
        });
        assert!(start_sweeper(&no_table).is_none());

        let table = admission(Policy {
            per_ip: Some(Rate::new(1.0, 1.0)),
            ..Policy::default()
        });
        let sweeper = start_sweeper(&table).expect("a rate table needs a sweeper");
        sweeper.abort();
    }

    #[test]
    fn counters_snapshot_is_additive() {
        let admission = admission(Policy {
            deny: vec![net("127.0.0.1/32")],
            ..Policy::default()
        });
        admission.admit(peer("127.0.0.1:1"), Instant::now()).ok();
        admission.count_reflect_rejected();
        let counts = admission.counters();
        assert_eq!(counts.denied, 1);
        assert_eq!(counts.reflect_rejected, 1);
    }
}
