//! STUN authentication: RFC 5389 §10 credentials, with the RFC 8489 §9.2
//! extension the task asked for (`MESSAGE-INTEGRITY-SHA256`,
//! `PASSWORD-ALGORITHM(S)`, `USERHASH`).
//!
//! Two mechanisms, selected by configuration (never by the request):
//!
//! * **short-term** (`--auth-user` / `--auth-pass`): the key *is* the password
//!   (RFC 5389 §15.4), the only integrity attribute is `MESSAGE-INTEGRITY`
//!   (HMAC-SHA1), and there is no realm / nonce.
//! * **long-term** (`--realm` + `--auth-secret` + a user source): the key is
//!   derived from `username:realm:password` — MD5 for `MESSAGE-INTEGRITY`,
//!   SHA-256 for `MESSAGE-INTEGRITY-SHA256`. A stateless `NONCE` makes the
//!   challenge replayable across instances that share `--auth-secret`.
//!
//! Nothing here is enabled unless credentials were configured: the caller holds
//! `Option<Auth>`, so the default path never even looks at these attributes
//! (bit-for-bit compatibility with the pre-auth binary).
//!
//! Deliberate scope limits (documented in the README):
//! * no database / multi-tenant back end — users come from a file or one flag;
//! * no SASLprep: a configured password is used as-is (ASCII deployments);
//! * `PASSWORD-ALGORITHM` parameters are accepted but not interpreted (RFC 8489
//!   defines none for MD5 / SHA256).
//!
//! No hand-written cryptography: HMAC-SHA1, HMAC-SHA256, SHA-256, MD5 come from
//! the RustCrypto crates; only the (non-cryptographic) base64url codec, the
//! constant-time comparison and the nonce framing live here.

use std::{
    net::IpAddr,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::protocol::{
    self, ATTR_MESSAGE_INTEGRITY, ATTR_MESSAGE_INTEGRITY_SHA256, ATTR_NONCE,
    ATTR_PASSWORD_ALGORITHM, ATTR_REALM, ATTR_USERHASH, ATTR_USERNAME, HEADER_LEN, Message,
    TransactionId,
};

/// `PASSWORD-ALGORITHMS` (RFC 8489 §14.11): the algorithms a server accepts,
/// carried by a `401`. Comprehension-optional (`0x8002`), so a client that does
/// not know it simply ignores it (RFC 5389 §7.3.1).
pub const ATTR_PASSWORD_ALGORITHMS: u16 = 0x8002;
/// `PASSWORD-ALGORITHM` value: key = `MD5(username:realm:password)` (RFC 8489
/// §14.12, the coturn default).
pub const PASSWORD_ALGORITHM_MD5: u16 = 0x0001;
/// `PASSWORD-ALGORITHM` value: key = `SHA256(username:realm:password)`.
pub const PASSWORD_ALGORITHM_SHA256: u16 = 0x0002;
/// `401 Unauthorized` (RFC 5389 §15.6).
pub const ERROR_UNAUTHORIZED: u16 = 401;
/// `438 Stale Nonce` (RFC 5389 §15.6).
pub const ERROR_STALE_NONCE: u16 = 438;
/// Default `--nonce-lifetime`: RFC 5389 §10.2 leaves it to the server.
pub const DEFAULT_NONCE_LIFETIME: u64 = 3600;

/// `--rest-secret` username shape (coturn `use-auth-secret`): the expiry is the
/// unix timestamp before the first `:`, the rest is an arbitrary label (it may
/// itself contain `:`, which is why the split is on the **first** separator).
/// `1700000000:alice` → `Some(1700000000)`; `alice` → `None` (a stored user).
pub fn rest_username_expiry(username: &str) -> Option<u64> {
    let (expiry, _label) = username.split_once(':')?;
    if expiry.is_empty() || !expiry.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    expiry.parse().ok()
}

/// `password = base64(HMAC-SHA1(secret, username))` — the coturn
/// `use-auth-secret` rule (standard base64 alphabet, padded; the TURN REST API
/// is not the URL-safe variant used by the nonce).
pub fn rest_password(secret: &[u8], username: &str) -> String {
    base64_encode(&hmac_sha1(secret, username.as_bytes()))
}

/// `MESSAGE-INTEGRITY` value length (HMAC-SHA1, RFC 5389 §15.4).
const MI_LEN: usize = 20;
/// `MESSAGE-INTEGRITY-SHA256` value length (RFC 8489 §14.6).
const MI_SHA256_LEN: usize = 32;
/// `USERHASH` value length: the **whole** SHA-256 digest (RFC 8489 §14.4),
/// 32 bytes — not a truncated prefix.
const USERHASH_LEN: usize = 32;
/// Nonce layout: 5-byte expiry + 11-byte HMAC tag = 16 bytes → 22 base64url chars.
const NONCE_LEN: usize = 16;
const NONCE_EXPIRY_LEN: usize = 5;
const NONCE_TAG_LEN: usize = NONCE_LEN - NONCE_EXPIRY_LEN;

/// Which key derivation a message uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// `MD5(username:realm:password)` + `MESSAGE-INTEGRITY` (RFC 5389 §15.4).
    Md5,
    /// `SHA256(username:realm:password)` + `MESSAGE-INTEGRITY-SHA256`
    /// (RFC 8489 §9.2.2 / §14.6).
    Sha256,
}

impl KeyAlgorithm {
    /// The `PASSWORD-ALGORITHM` identifier (RFC 8489 §14.12).
    pub const fn id(self) -> u16 {
        match self {
            Self::Md5 => PASSWORD_ALGORITHM_MD5,
            Self::Sha256 => PASSWORD_ALGORITHM_SHA256,
        }
    }

    /// Inverse of [`KeyAlgorithm::id`]; `None` is "an algorithm we do not
    /// implement", which is a 401, never a silent fallback.
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            PASSWORD_ALGORITHM_MD5 => Some(Self::Md5),
            PASSWORD_ALGORITHM_SHA256 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// The integrity attribute that carries this algorithm's MAC.
    pub const fn attribute(self) -> u16 {
        match self {
            Self::Md5 => ATTR_MESSAGE_INTEGRITY,
            Self::Sha256 => ATTR_MESSAGE_INTEGRITY_SHA256,
        }
    }

    /// MAC length, also the attribute's value length.
    pub const fn mac_len(self) -> usize {
        match self {
            Self::Md5 => MI_LEN,
            Self::Sha256 => MI_SHA256_LEN,
        }
    }

    /// Attribute size on the wire: 4-byte TLV header + MAC (both lengths are
    /// multiples of 4, so no padding).
    pub const fn attribute_size(self) -> usize {
        4 + self.mac_len()
    }
}

/// One configured credential. `password` is the *cleartext* password; the key
/// derivation happens per request so that one store can serve both algorithms.
#[derive(Clone, PartialEq, Eq)]
pub struct User {
    pub username: String,
    pub password: String,
}

/// Never print the password: `Debug` output ends up in logs, panics and test
/// failures, none of which should become a credential leak. The length is
/// enough to debug "did the file get parsed".
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("username", &self.username)
            .field("password_len", &self.password.len())
            .finish()
    }
}

/// Which RFC 5389 §10 mechanism is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// §10.1: key = password, `MESSAGE-INTEGRITY` only, no realm / nonce.
    ShortTerm,
    /// §10.2: realm + nonce, key derived from `username:realm:password`.
    LongTerm,
}

/// Why a request was not authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// `401 Unauthorized`: missing / unusable credentials, unknown user, wrong
    /// password, nonce that is not one of ours, or an algorithm we refuse.
    Unauthorized,
    /// `438 Stale Nonce`: a nonce this server signed, but past its lifetime.
    /// Only reachable in long-term mode (short-term has no nonce at all).
    StaleNonce,
    /// `400 Bad Request`: the request is *incomplete*, not unauthenticated —
    /// a short-term request without both `USERNAME` and `MESSAGE-INTEGRITY`
    /// (RFC 5389 §10.1.2), or a long-term request missing `REALM` / `NONCE` /
    /// both `USERNAME` and `USERHASH` (RFC 8489 §9.2.4).
    BadRequest,
}

/// What a nonce says about the request that carried it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceState {
    Valid,
    Expired,
    /// Not produced by this `--auth-secret` (or produced for another client IP),
    /// or not even a nonce. A forged nonce is a 401, never a 438: 438 tells a
    /// client "refresh and retry", which is only true for our own nonce.
    Invalid,
}

/// The authenticated identity of one request: enough to *answer* it.
///
/// `keys` pairs each verified integrity attribute with the key that verified it,
/// in wire order, so the response can be sealed exactly like the request was
/// (RFC 5389 §10.2.2 / RFC 8489 §9.2.4: a response to an authenticated request
/// must carry `MESSAGE-INTEGRITY`, and `MESSAGE-INTEGRITY-SHA256` when that is
/// what the client used).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub username: String,
    pub keys: Vec<(KeyAlgorithm, Vec<u8>)>,
}

/// Counters reported at shutdown (`rstun: authentication counters`). They are
/// only interesting when auth is on, so they live here instead of in the
/// protocol-wide `ServerStats`.
#[derive(Debug, Default)]
pub struct Counters {
    authenticated: AtomicU64,
    unauthorized: AtomicU64,
    stale_nonce: AtomicU64,
    bad_request: AtomicU64,
}

impl Counters {
    /// `(authenticated, 401, 438, 400)`.
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.authenticated.load(Ordering::Relaxed),
            self.unauthorized.load(Ordering::Relaxed),
            self.stale_nonce.load(Ordering::Relaxed),
            self.bad_request.load(Ordering::Relaxed),
        )
    }
}

/// The configured mechanism plus its (immutable) credential store.
pub struct Auth {
    mode: Mode,
    users: Vec<User>,
    /// Long-term only; empty in short-term mode (no `REALM` is emitted).
    realm: String,
    /// Long-term only: the HMAC key of the stateless nonce. Never logged.
    secret: Vec<u8>,
    nonce_lifetime: Duration,
    /// `--auth-require-sha256`: refuse MD5 credentials with a 401.
    require_sha256: bool,
    /// `--rest-secret`: TURN REST API ephemeral credentials (coturn's
    /// `use-auth-secret`). `None` = the feature is off and a username is always
    /// looked up in `users`.
    rest_secret: Option<Vec<u8>>,
    counters: Counters,
}

/// Redacted on purpose: `--auth-secret` is the nonce signing key, and the user
/// list holds cleartext passwords. Neither may reach a log line or a panic
/// message; lengths are enough to debug a misconfiguration.
impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("mode", &self.mode)
            .field("users", &self.users)
            .field("realm", &self.realm)
            .field("secret_len", &self.secret.len())
            .field("nonce_lifetime", &self.nonce_lifetime)
            .field("require_sha256", &self.require_sha256)
            .field("rest_secret_len", &self.rest_secret.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl Auth {
    /// RFC 5389 §10.1 credentials: the password *is* the key.
    pub fn short_term(users: Vec<User>) -> Self {
        Self {
            mode: Mode::ShortTerm,
            users,
            realm: String::new(),
            secret: Vec::new(),
            nonce_lifetime: Duration::from_secs(DEFAULT_NONCE_LIFETIME),
            require_sha256: false,
            rest_secret: None,
            counters: Counters::default(),
        }
    }

    /// RFC 5389 §10.2 credentials. `secret` signs the stateless nonce: every
    /// instance behind the same `--auth-secret` accepts the others' nonces.
    pub fn long_term(
        realm: String,
        secret: Vec<u8>,
        users: Vec<User>,
        nonce_lifetime: Duration,
        require_sha256: bool,
    ) -> Self {
        Self {
            mode: Mode::LongTerm,
            users,
            realm,
            secret,
            nonce_lifetime,
            require_sha256,
            rest_secret: None,
            counters: Counters::default(),
        }
    }

    /// Enable TURN REST API ephemeral credentials (`--rest-secret`).
    ///
    /// Long-term only: the ephemeral password is fed into the same
    /// `MD5(username:realm:password)` key derivation every other long-term
    /// request uses, so a REST client and a stored user differ only in *where*
    /// the password comes from.
    pub fn with_rest_secret(mut self, secret: Vec<u8>) -> Self {
        self.rest_secret = Some(secret);
        self
    }

    /// Is the TURN REST API credential path enabled?
    pub fn has_rest_secret(&self) -> bool {
        self.rest_secret.is_some()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The realm this server challenges with (`""` in short-term mode).
    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    pub fn require_sha256(&self) -> bool {
        self.require_sha256
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Algorithms advertised in `PASSWORD-ALGORITHMS` and accepted in a request,
    /// in preference order.
    fn supported_algorithms(&self) -> &'static [KeyAlgorithm] {
        if self.require_sha256 {
            &[KeyAlgorithm::Sha256]
        } else {
            &[KeyAlgorithm::Md5, KeyAlgorithm::Sha256]
        }
    }

    /// Authenticate one request.
    ///
    /// `frame` is the whole message (`HEADER_LEN + Message Length` bytes; the
    /// MAC covers the header, so trailing datagram junk must be trimmed by the
    /// caller), `client` is the source IP the nonce is bound to.
    pub fn verify(
        &self,
        frame: &[u8],
        message: &Message<'_>,
        client: IpAddr,
        now: SystemTime,
    ) -> Result<Identity, Rejection> {
        let body = message.body;
        let has_mi = attribute(body, ATTR_MESSAGE_INTEGRITY).is_some();
        let has_sha256 = attribute(body, ATTR_MESSAGE_INTEGRITY_SHA256).is_some();
        if !has_mi && !has_sha256 {
            // RFC 5389 §10.1.2: a short-term request without both USERNAME and
            // MESSAGE-INTEGRITY is a *bad request*; §10.2.2 makes the missing
            // integrity of a long-term request a plain 401 (the challenge that
            // teaches the client the realm/nonce is the point).
            return Err(match self.mode {
                Mode::ShortTerm => Rejection::BadRequest,
                Mode::LongTerm => Rejection::Unauthorized,
            });
        }
        match self.mode {
            Mode::ShortTerm => self.verify_short_term(frame, body),
            Mode::LongTerm => self.verify_long_term(frame, body, has_mi, has_sha256, client, now),
        }
    }

    fn verify_short_term(&self, frame: &[u8], body: &[u8]) -> Result<Identity, Rejection> {
        let Some(username) = attribute(body, ATTR_USERNAME) else {
            // Same §10.1.2 rule: the pair is mandatory.
            return Err(Rejection::BadRequest);
        };
        let Ok(username) = std::str::from_utf8(username) else {
            return Err(Rejection::Unauthorized);
        };
        let Some(user) = self.users.iter().find(|user| user.username == username) else {
            return Err(Rejection::Unauthorized);
        };
        // RFC 5389 §15.4: for short-term credentials the key is the password
        // itself (SASLprep'd by the operator; see the module docs).
        let key = user.password.as_bytes().to_vec();
        if !verify_integrity(frame, &key, KeyAlgorithm::Md5) {
            return Err(Rejection::Unauthorized);
        }
        Ok(Identity {
            username: user.username.clone(),
            keys: vec![(KeyAlgorithm::Md5, key)],
        })
    }

    fn verify_long_term(
        &self,
        frame: &[u8],
        body: &[u8],
        has_mi: bool,
        has_sha256: bool,
        client: IpAddr,
        now: SystemTime,
    ) -> Result<Identity, Rejection> {
        // RFC 5389 §10.2.2 / RFC 8489 §9.2.4: a long-term request *missing* one
        // of the mandatory attributes is malformed — **400**, not a failed
        // authentication. 401 is reserved for "present but wrong" values
        // (realm mismatch, unknown user, bad MAC, foreign nonce).
        //
        // The client identifies itself with `USERNAME` *or* `USERHASH`
        // (RFC 8489 §14.4): only when both are absent is the message incomplete.
        let identified =
            attribute(body, ATTR_USERNAME).is_some() || attribute(body, ATTR_USERHASH).is_some();
        if !identified
            || attribute(body, ATTR_REALM).is_none()
            || attribute(body, ATTR_NONCE).is_none()
        {
            return Err(Rejection::BadRequest);
        }

        // From here on every check is about *values*.
        //
        // A client challenged by another realm would derive a different key, so
        // a mismatching REALM can never authenticate (RFC 5389 §10.2.2).
        if attribute(body, ATTR_REALM) != Some(self.realm.as_bytes()) {
            return Err(Rejection::Unauthorized);
        }
        let requested = match password_algorithm(body) {
            Ok(algorithm) => algorithm,
            // An algorithm identifier we do not implement is a 401: answering
            // with a different one would be silently downgrading the client.
            Err(()) => return Err(Rejection::Unauthorized),
        };
        // TURN REST API ephemeral credentials (coturn `use-auth-secret`): a
        // `USERNAME` of the form `<expiry>:<label>` carries its own password
        // source, so it is **never** looked up in the user table — REST wins
        // over a stored user with the same name (design §4). A name without a
        // numeric prefix falls through to the stored credentials, and the
        // non-REST path keeps its original evaluation order (unknown user →
        // 401 even when the nonce is stale).
        let rest_username = if self.rest_secret.is_some() {
            attribute(body, ATTR_USERNAME)
                .and_then(|value| std::str::from_utf8(value).ok())
                .filter(|username| rest_username_expiry(username).is_some())
        } else {
            None
        };
        let user = match rest_username {
            Some(_) => None,
            None => Some(self.find_user(body)?),
        };
        if attribute(body, ATTR_USERHASH).is_some() {
            // RFC 8489 §9.2.2: USERHASH is defined together with the SHA-256
            // key derivation; pairing it with MD5 would be a client bug.
            if requested == Some(KeyAlgorithm::Md5) {
                return Err(Rejection::Unauthorized);
            }
        }
        // Present (checked above), so this cannot be `None`; the `else` keeps the
        // function total instead of unwrapping.
        let Some(nonce) = attribute(body, ATTR_NONCE) else {
            return Err(Rejection::BadRequest);
        };
        let Ok(nonce) = std::str::from_utf8(nonce) else {
            return Err(Rejection::Unauthorized);
        };
        match self.check_nonce(nonce, client, now) {
            NonceState::Valid => {}
            NonceState::Expired => return Err(Rejection::StaleNonce),
            NonceState::Invalid => return Err(Rejection::Unauthorized),
        }

        // PASSWORD-ALGORITHM wins when present (explicit negotiation); without
        // it, the integrity attributes present say which algorithms to check —
        // a client that sends only MESSAGE-INTEGRITY-SHA256 means SHA-256.
        let algorithms = self.select_algorithms(requested, has_mi, has_sha256);
        if self.require_sha256 && algorithms.contains(&KeyAlgorithm::Md5) {
            return Err(Rejection::Unauthorized);
        }

        if let Some(username) = rest_username {
            let secret = self
                .rest_secret
                .as_ref()
                .expect("rest_username is only set when --rest-secret is configured");
            return self.verify_rest(frame, username, secret, &algorithms, now);
        }
        let user = user.expect("the non-REST path resolved a stored user");
        let mut keys = Vec::with_capacity(algorithms.len());
        for algorithm in algorithms {
            let key = long_term_key(algorithm, &user.username, &self.realm, &user.password);
            if !verify_integrity(frame, &key, algorithm) {
                return Err(Rejection::Unauthorized);
            }
            keys.push((algorithm, key));
        }
        Ok(Identity {
            username: user.username.clone(),
            keys,
        })
    }

    /// Which key derivations to try for this request: an explicit
    /// `PASSWORD-ALGORITHM` wins, otherwise the integrity attributes present
    /// say it (a client that sends only `MESSAGE-INTEGRITY-SHA256` means SHA-256).
    fn select_algorithms(
        &self,
        requested: Option<KeyAlgorithm>,
        has_mi: bool,
        has_sha256: bool,
    ) -> Vec<KeyAlgorithm> {
        match requested {
            Some(algorithm) => vec![algorithm],
            None => {
                let mut algorithms = Vec::with_capacity(2);
                if has_mi {
                    algorithms.push(KeyAlgorithm::Md5);
                }
                if has_sha256 {
                    algorithms.push(KeyAlgorithm::Sha256);
                }
                algorithms
            }
        }
    }

    /// Verify one TURN REST API credential: `password =
    /// base64(HMAC-SHA1(secret, username))`, then the ordinary long-term key
    /// derivation on top of it.
    ///
    /// Expiry is strict (`now >= expiry` → 401, design §4). The reply for an
    /// expired credential is a plain 401 and **not** a 438: the nonce is still
    /// valid, so a new nonce would not help — the client has to mint a new
    /// username.
    fn verify_rest(
        &self,
        frame: &[u8],
        username: &str,
        secret: &[u8],
        algorithms: &[KeyAlgorithm],
        now: SystemTime,
    ) -> Result<Identity, Rejection> {
        let Some(expiry) = rest_username_expiry(username) else {
            return Err(Rejection::Unauthorized);
        };
        if unix_seconds(now) >= expiry {
            return Err(Rejection::Unauthorized);
        }
        let password = rest_password(secret, username);
        let mut keys = Vec::with_capacity(algorithms.len());
        for algorithm in algorithms {
            let key = long_term_key(*algorithm, username, &self.realm, &password);
            if !verify_integrity(frame, &key, *algorithm) {
                return Err(Rejection::Unauthorized);
            }
            keys.push((*algorithm, key));
        }
        Ok(Identity {
            username: username.to_string(),
            keys,
        })
    }

    /// Resolve the request's user: `USERHASH` first (RFC 8489 §14.4, no
    /// `USERNAME` on the wire), then `USERNAME`.
    ///
    /// A hash of the wrong length is a *value* error (401), not a missing
    /// attribute: the client did send one, it just cannot be ours.
    fn find_user(&self, body: &[u8]) -> Result<&User, Rejection> {
        if let Some(hash) = attribute(body, ATTR_USERHASH) {
            if hash.len() != USERHASH_LEN {
                return Err(Rejection::Unauthorized);
            }
            return self
                .users
                .iter()
                .find(|user| ct_eq(&userhash(&user.username, &self.realm), hash))
                .ok_or(Rejection::Unauthorized);
        }
        let Some(username) = attribute(body, ATTR_USERNAME) else {
            return Err(Rejection::Unauthorized);
        };
        // Constant-time comparison: a plain `==` stops at the first differing
        // byte, which leaks how much of a guessed user name was right.
        self.users
            .iter()
            .find(|user| ct_eq(user.username.as_bytes(), username))
            .ok_or(Rejection::Unauthorized)
    }

    /// Record the authentication outcome.
    ///
    /// This only updates the auth counters (`rstun_auth_total` / the exit log);
    /// it does **not** rate limit. The admission buckets (`limit::Admission`)
    /// run in the transport loop *before* verification, which is what keeps a
    /// 401/438 flood inside the guard — counting here would be too late.
    pub fn count(&self, outcome: &Result<Identity, Rejection>) {
        match outcome {
            Ok(_) => self.counters.authenticated.fetch_add(1, Ordering::Relaxed),
            Err(Rejection::Unauthorized) => {
                self.counters.unauthorized.fetch_add(1, Ordering::Relaxed)
            }
            Err(Rejection::StaleNonce) => self.counters.stale_nonce.fetch_add(1, Ordering::Relaxed),
            Err(Rejection::BadRequest) => self.counters.bad_request.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// The response to a rejected request.
    pub fn rejection_response(
        &self,
        rejection: Rejection,
        transaction_id: &TransactionId,
        method: u16,
        client: IpAddr,
        now: SystemTime,
    ) -> Vec<u8> {
        match rejection {
            Rejection::BadRequest => protocol::error_response(
                transaction_id,
                method,
                protocol::ERROR_BAD_REQUEST,
                "Bad Request",
            ),
            Rejection::Unauthorized => self.unauthorized(transaction_id, method, client, now),
            Rejection::StaleNonce => self.stale_nonce(transaction_id, method, client, now),
        }
    }

    /// The wire size of the challenge this server would send. `401` is the
    /// largest: `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`. The reflection guard
    /// needs it to estimate an *unauthenticated* answer, which is bigger than
    /// the success answer it would otherwise predict (abuse-guard spec §5:
    /// estimate and actual must be the same message).
    pub fn challenge_len(&self) -> usize {
        self.unauthorized(
            &TransactionId([0; 12]),
            protocol::BINDING_REQUEST,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            UNIX_EPOCH,
        )
        .len()
    }

    /// `401 Unauthorized` + `REALM` + `NONCE` + `PASSWORD-ALGORITHMS`
    /// (RFC 5389 §10.2.2, RFC 8489 §9.2.4). Short-term mode has neither realm
    /// nor nonce, so it answers with the bare `ERROR-CODE`.
    pub fn unauthorized(
        &self,
        transaction_id: &TransactionId,
        method: u16,
        client: IpAddr,
        now: SystemTime,
    ) -> Vec<u8> {
        let mut extra: Vec<(u16, Vec<u8>)> = Vec::with_capacity(3);
        if self.mode == Mode::LongTerm {
            extra.push((ATTR_REALM, self.realm.as_bytes().to_vec()));
            extra.push((ATTR_NONCE, self.issue_nonce(client, now).into_bytes()));
            extra.push((ATTR_PASSWORD_ALGORITHMS, self.password_algorithms_value()));
        }
        self.error_with(
            transaction_id,
            method,
            ERROR_UNAUTHORIZED,
            "Unauthorized",
            &extra,
        )
    }

    /// `438 Stale Nonce` + a fresh `NONCE`, plus `REALM` and
    /// `PASSWORD-ALGORITHMS`, which RFC 8489 §9.2.4 makes mandatory on every
    /// 401 *and* 438 (the client needs them to compute the new MAC).
    pub fn stale_nonce(
        &self,
        transaction_id: &TransactionId,
        method: u16,
        client: IpAddr,
        now: SystemTime,
    ) -> Vec<u8> {
        let extra = [
            (ATTR_REALM, self.realm.as_bytes().to_vec()),
            (ATTR_NONCE, self.issue_nonce(client, now).into_bytes()),
            (ATTR_PASSWORD_ALGORITHMS, self.password_algorithms_value()),
        ];
        self.error_with(
            transaction_id,
            method,
            ERROR_STALE_NONCE,
            "Stale Nonce",
            &extra,
        )
    }

    fn error_with(
        &self,
        transaction_id: &TransactionId,
        method: u16,
        code: u16,
        reason: &str,
        extra: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let borrowed: Vec<(u16, &[u8])> = extra
            .iter()
            .map(|(attr_type, value)| (*attr_type, value.as_slice()))
            .collect();
        protocol::error_response_with(transaction_id, method, code, reason, &borrowed)
    }

    /// `PASSWORD-ALGORITHMS` value: `{algorithm, parameter length = 0}` pairs
    /// (RFC 8489 §14.11).
    fn password_algorithms_value(&self) -> Vec<u8> {
        let algorithms = self.supported_algorithms();
        let mut value = Vec::with_capacity(algorithms.len() * 4);
        for algorithm in algorithms {
            value.extend_from_slice(&algorithm.id().to_be_bytes());
            value.extend_from_slice(&0_u16.to_be_bytes());
        }
        value
    }

    /// Mint a nonce for `client`: `base64url( expiry(5) | tag(11) )` where
    /// `tag = HMAC-SHA256(secret, expiry | client_ip)[..11]`.
    ///
    /// No server-side state: any instance with the same `--auth-secret`
    /// recomputes the tag and accepts the nonce (that is what makes the
    /// challenge survive a restart or a load balancer).
    pub fn issue_nonce(&self, client: IpAddr, now: SystemTime) -> String {
        let expiry = unix_seconds(now).saturating_add(self.nonce_lifetime.as_secs()) & NONCE_MASK;
        base64url_encode(&self.nonce_bytes(expiry, client))
    }

    /// Classify a nonce without trusting anything in it before the tag matches.
    pub fn check_nonce(&self, nonce: &str, client: IpAddr, now: SystemTime) -> NonceState {
        let Some(raw) = base64url_decode(nonce) else {
            return NonceState::Invalid;
        };
        let Ok(raw): Result<[u8; NONCE_LEN], _> = raw.try_into() else {
            return NonceState::Invalid;
        };
        let expiry = raw[..NONCE_EXPIRY_LEN]
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        if !ct_eq(&self.nonce_bytes(expiry, client), &raw) {
            return NonceState::Invalid;
        }
        // Strict expiry: `--nonce-lifetime 1` must really mean one second. The
        // design's ±5 min clock-skew tolerance is *not* applied here — a grace
        // window would stretch every configured lifetime by the same amount;
        // operators that need tolerance raise `--nonce-lifetime` instead.
        if unix_seconds(now) >= expiry {
            return NonceState::Expired;
        }
        NonceState::Valid
    }

    fn nonce_bytes(&self, expiry: u64, client: IpAddr) -> [u8; NONCE_LEN] {
        let expiry_bytes = expiry.to_be_bytes();
        let mut nonce = [0_u8; NONCE_LEN];
        nonce[..NONCE_EXPIRY_LEN].copy_from_slice(&expiry_bytes[8 - NONCE_EXPIRY_LEN..]);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .expect("HMAC accepts a key of any length");
        mac.update(&expiry_bytes[8 - NONCE_EXPIRY_LEN..]);
        match client {
            IpAddr::V4(ip) => mac.update(&ip.octets()),
            IpAddr::V6(ip) => mac.update(&ip.octets()),
        }
        let tag = mac.finalize().into_bytes();
        nonce[NONCE_EXPIRY_LEN..].copy_from_slice(&tag[..NONCE_TAG_LEN]);
        nonce
    }
}

/// 40 bits of unix time: enough until the year 36812, and exactly what fits in
/// the nonce's 5-byte expiry field.
const NONCE_MASK: u64 = (1 << (8 * NONCE_EXPIRY_LEN)) - 1;

/// Seal an already encoded response with the integrity attributes the request
/// was authenticated with (RFC 5389 §10.2.2, RFC 8489 §9.2.4).
///
/// Each MAC covers the frame *up to its own attribute*, with the header
/// `Message Length` adjusted to point at the end of that attribute — the same
/// rule [`verify_integrity`] applies in reverse, so a client that can verify its
/// own request can verify our answer.
///
/// A trailing RFC 5780 `PADDING` stays the **last** attribute (§7.6): the
/// integrity attribute is inserted in front of it, so both rules hold at once
/// and the echoed padding length is unchanged.
pub fn seal(frame: Vec<u8>, identity: &Identity) -> Vec<u8> {
    let (mut frame, padding) = split_trailing_padding(frame);
    let mut body_len = frame.len() - HEADER_LEN;
    for (algorithm, key) in &identity.keys {
        let size = algorithm.attribute_size();
        let adjusted = (body_len + size) as u16;
        let mut prefix = frame.clone();
        prefix[2..4].copy_from_slice(&adjusted.to_be_bytes());
        let mac = match algorithm {
            KeyAlgorithm::Md5 => hmac_sha1(key, &prefix),
            KeyAlgorithm::Sha256 => hmac_sha256(key, &prefix),
        };
        frame[2..4].copy_from_slice(&adjusted.to_be_bytes());
        frame.extend_from_slice(&algorithm.attribute().to_be_bytes());
        frame.extend_from_slice(&(mac.len() as u16).to_be_bytes());
        frame.extend_from_slice(&mac);
        body_len += size;
    }
    frame.extend_from_slice(&padding);
    frame[2..4].copy_from_slice(&((body_len + padding.len()) as u16).to_be_bytes());
    frame
}

/// Split an encoded frame into `(everything before a trailing PADDING, the
/// PADDING attribute)`. No trailing `PADDING` → `(frame, empty)`.
fn split_trailing_padding(frame: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    if frame.len() < HEADER_LEN {
        return (frame, Vec::new());
    }
    let body = &frame[HEADER_LEN..];
    let mut offset = 0;
    let mut padding_at = None;
    while offset + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        if attr_type == protocol::ATTR_PADDING {
            padding_at = Some(offset);
        }
        offset += 4 + length.div_ceil(4) * 4;
    }
    let Some(offset) = padding_at else {
        return (frame, Vec::new());
    };
    let split = HEADER_LEN + offset;
    if split >= frame.len() {
        return (frame, Vec::new());
    }
    let padding = frame[split..].to_vec();
    let mut head = frame;
    head.truncate(split);
    (head, padding)
}

/// How many bytes [`seal`] will add to an answer for this request: 0 when auth
/// is off or the request carries no integrity attribute, 24 for
/// `MESSAGE-INTEGRITY`, 36 for `MESSAGE-INTEGRITY-SHA256`, 60 for both.
///
/// The reflection guard needs this to keep its estimate equal to the answer
/// `decide` will actually send (abuse-guard spec §5: one predicate, two callers).
pub fn integrity_overhead(message: &Message<'_>) -> usize {
    let mut overhead = 0;
    if attribute(message.body, ATTR_MESSAGE_INTEGRITY).is_some() {
        overhead += KeyAlgorithm::Md5.attribute_size();
    }
    if attribute(message.body, ATTR_MESSAGE_INTEGRITY_SHA256).is_some() {
        overhead += KeyAlgorithm::Sha256.attribute_size();
    }
    overhead
}

/// `MD5(username:realm:password)` (RFC 5389 §15.4) or
/// `SHA256(username:realm:password)` (RFC 8489 §9.2.2).
pub fn long_term_key(
    algorithm: KeyAlgorithm,
    username: &str,
    realm: &str,
    password: &str,
) -> Vec<u8> {
    let material = format!("{username}:{realm}:{password}");
    match algorithm {
        KeyAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(material.as_bytes());
            hasher.finalize().to_vec()
        }
        KeyAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(material.as_bytes());
            hasher.finalize().to_vec()
        }
    }
}

/// `USERHASH = SHA256(username ":" realm)` (RFC 8489 §14.4).
///
/// The attribute carries the **entire** 32-byte digest; a 16-byte "prefix"
/// (what some early drafts of this code did) is not USERHASH and is rejected.
pub fn userhash(username: &str, realm: &str) -> [u8; USERHASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{username}:{realm}").as_bytes());
    let digest = hasher.finalize();
    let mut hash = [0_u8; USERHASH_LEN];
    hash.copy_from_slice(&digest);
    hash
}

/// Constant-time byte comparison (no `subtle` dependency: one XOR-OR loop).
///
/// Only the *content* comparison is constant time; the early return on a length
/// mismatch leaks the length, which is public on the wire anyway (attribute
/// `Length` fields and MAC sizes are fixed).
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Does `frame` carry a valid MAC for `algorithm` under `key`?
///
/// Walks the attributes to find the (first) integrity attribute, then recomputes
/// the MAC over everything before it with the header length adjusted to point at
/// the end of that attribute (RFC 5389 §15.4, RFC 8489 §14.6). A missing
/// attribute, a wrong value length or a mismatch all answer `false`.
pub fn verify_integrity(frame: &[u8], key: &[u8], algorithm: KeyAlgorithm) -> bool {
    if frame.len() < HEADER_LEN {
        return false;
    }
    let body = &frame[HEADER_LEN..];
    let mut offset = 0_usize;
    while offset + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        if attr_type == algorithm.attribute() {
            if length != algorithm.mac_len() {
                return false;
            }
            let Some(expected) = body.get(offset + 4..offset + 4 + length) else {
                return false;
            };
            let adjusted = (offset + algorithm.attribute_size()) as u16;
            let mut prefix = frame[..HEADER_LEN + offset].to_vec();
            prefix[2..4].copy_from_slice(&adjusted.to_be_bytes());
            let mac = match algorithm {
                KeyAlgorithm::Md5 => hmac_sha1(key, &prefix),
                KeyAlgorithm::Sha256 => hmac_sha256(key, &prefix),
            };
            return ct_eq(&mac, expected);
        }
        offset += 4 + length.div_ceil(4) * 4;
    }
    false
}

/// The `PASSWORD-ALGORITHM` attribute (RFC 8489 §14.12), if any.
///
/// `Err(())` = the attribute is present but unusable (truncated, inconsistent
/// parameter length, or an algorithm identifier this server does not implement).
fn password_algorithm(body: &[u8]) -> Result<Option<KeyAlgorithm>, ()> {
    let Some(value) = attribute(body, ATTR_PASSWORD_ALGORITHM) else {
        return Ok(None);
    };
    let Some(header) = value.get(..4) else {
        return Err(());
    };
    let id = u16::from_be_bytes([header[0], header[1]]);
    let parameters = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if value.len() != 4 + parameters {
        return Err(());
    }
    KeyAlgorithm::from_id(id).map(Some).ok_or(())
}

/// First value of `attr_type` in `body` (attribute order is preserved by the
/// encoder, so "first" is the meaningful one for every attribute we read).
fn attribute(body: &[u8], attr_type: u16) -> Option<&[u8]> {
    protocol::attributes(body)
        .find(|attribute| attribute.attr_type == attr_type)
        .map(|attribute| attribute.value)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn unix_seconds(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Standard base64 (RFC 4648 §4: `+/` alphabet, `=` padded) — what the TURN
/// REST API specifies for the ephemeral password, and what coturn emits. Kept
/// next to [`base64url_encode`] instead of pulling a `base64` dependency: two
/// alphabets, one loop.
pub fn base64_encode(bytes: &[u8]) -> String {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let bits = (u32::from(chunk[0]) << 16) | (u32::from(second) << 8) | u32::from(third);
        out.push(BASE64[(bits >> 18) as usize & 0x3f] as char);
        out.push(BASE64[(bits >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(BASE64[(bits >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64[bits as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// URL-safe base64 without padding (RFC 4648 §5) — the nonce alphabet.
///
/// Written out instead of pulling a `base64` dependency: it encodes a 16-byte
/// value in 22 characters and never needs the `=` forms.
pub fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let bits = (u32::from(chunk[0]) << 16) | (u32::from(second) << 8) | u32::from(third);
        out.push(BASE64URL[(bits >> 18) as usize & 0x3f] as char);
        out.push(BASE64URL[(bits >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL[(bits >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL[bits as usize & 0x3f] as char);
        }
    }
    out
}

/// Inverse of [`base64url_encode`]; rejects padding, foreign characters and
/// lengths a base64 block cannot have (`n % 4 == 1`).
pub fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for byte in text.bytes() {
        accumulator = (accumulator << 6) | u32::from(base64url_value(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero, and 6 leftover bits is the impossible
    // `n % 4 == 1` case (a lone character cannot carry a whole byte).
    if bits >= 6 || accumulator != 0 {
        return None;
    }
    Some(out)
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Read `user:password` lines (`#` comments and blank lines ignored).
///
/// Parsed at startup so a typo is a failed start, not a 401 for every client.
pub fn read_users(path: &Path) -> Result<Vec<User>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read --auth-file {}: {error}", path.display()))?;
    let mut users = Vec::new();
    // `text.lines()` already drops the line terminator; only a stray `\r`
    // (CRLF file) is trimmed. Leading/trailing blanks inside a field are **data**:
    // a password may legitimately start or end with a space, and silently
    // trimming it would produce a 401 that no one can explain.
    for (index, line) in text.lines().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((username, password)) = line.split_once(':') else {
            return Err(format!(
                "{}:{}: expected `user:password`, found no `:`",
                path.display(),
                index + 1
            ));
        };
        if username.is_empty() {
            return Err(format!("{}:{}: empty user name", path.display(), index + 1));
        }
        users.push(User {
            username: username.to_string(),
            password: password.to_string(),
        });
    }
    if users.is_empty() {
        return Err(format!(
            "{}: no credentials (expected at least one `user:password` line)",
            path.display()
        ));
    }
    Ok(users)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    fn user() -> User {
        User {
            username: "user".to_string(),
            password: "pass".to_string(),
        }
    }

    fn auth() -> Auth {
        Auth::long_term(
            "example.org".to_string(),
            b"nonce-secret".to_vec(),
            vec![user()],
            Duration::from_secs(DEFAULT_NONCE_LIFETIME),
            false,
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"same bytes", b"same bytes"));
        assert!(!ct_eq(b"same bytes", b"same byteS"));
        assert!(!ct_eq(b"short", b"longer"));
    }

    #[test]
    fn hmac_sha1_matches_rfc2202() {
        // RFC 2202 §2, test case 1 and 2.
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231() {
        // RFC 4231 §4.2/§4.3, test cases 1 and 2.
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn md5_key_derivation_matches_rfc1321() {
        // RFC 1321 §A.5 test suite (independent of our own hasher).
        let mut hasher = Md5::new();
        hasher.update(b"");
        assert_eq!(hex(&hasher.finalize()), "d41d8cd98f00b204e9800998ecf8427e");
        let mut hasher = Md5::new();
        hasher.update(b"abc");
        assert_eq!(hex(&hasher.finalize()), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn long_term_keys_and_userhash_follow_the_rfc_definition() {
        // md5/sha256 of `user:realm:pass`, computed with python's hashlib.
        assert_eq!(
            hex(&long_term_key(KeyAlgorithm::Md5, "user", "realm", "pass")),
            "8493fbc53ba582fb4c044c456bdc40eb"
        );
        assert_eq!(
            hex(&long_term_key(
                KeyAlgorithm::Sha256,
                "user",
                "realm",
                "pass"
            )),
            "07e934117abd40836e7c6329b54731b2b2d2a5f9a71f544922d75e0730d8251b"
        );
        // RFC 8489 §14.4: USERHASH is the **whole** SHA-256 digest (32 bytes),
        // not a 16-byte prefix. Both values are python's
        // `hashlib.sha256(b"<user>:<realm>").hexdigest()`.
        assert_eq!(
            hex(&userhash("user", "realm")),
            "6a3029116b47aa98bcaa325399733dc1a23cd57e26b81bef3ff6531ce624e2da"
        );
        assert_eq!(
            hex(&userhash("test", "example.org")),
            "3e170a99c121983e12c4c431ea2ab67306fd00167d69f19a68934d6d2e4e6127"
        );
        assert_eq!(userhash("user", "realm").len(), 32);
    }
    /// RFC 5769 §2.4: the long-term sample request, byte for byte. The password
    /// is `TheMatrIX` (after SASLprep), the realm `example.org`, the username
    /// the Japanese word for "matrix". Its `MESSAGE-INTEGRITY` value is the
    /// vector — so this pins the *verification* side of the HMAC-SHA1 rule,
    /// including the "length field includes the MI attribute" subtlety.
    const RFC5769_LONG_TERM: &str = concat!(
        "000100602112a44278ad3433c6ad72c029da412e",
        "00060012e3839ee38388e383aae38383e382afe382b90000",
        "0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341",
        "0014000b6578616d706c652e6f726700",
        "00080014f67024656dd64a3e02b8e0712e85c9a28ca89666",
    );

    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc5769_long_term_vector_verifies() {
        let frame = unhex(RFC5769_LONG_TERM);
        assert_eq!(frame.len(), 116);
        let key = long_term_key(
            KeyAlgorithm::Md5,
            "マトリックス",
            "example.org",
            "TheMatrIX",
        );
        assert!(verify_integrity(&frame, &key, KeyAlgorithm::Md5));

        // A wrong password, a flipped MAC byte and a truncated value all fail.
        let wrong = long_term_key(KeyAlgorithm::Md5, "マトリックス", "example.org", "wrong");
        assert!(!verify_integrity(&frame, &wrong, KeyAlgorithm::Md5));
        let mut flipped = frame.clone();
        flipped[108] ^= 0x01;
        assert!(!verify_integrity(&flipped, &key, KeyAlgorithm::Md5));
        // The same key must not verify a *SHA-256* claim.
        assert!(!verify_integrity(&frame, &key, KeyAlgorithm::Sha256));
    }

    #[test]
    fn nonce_round_trip_is_bound_to_expiry_and_client() {
        let auth = auth();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let nonce = auth.issue_nonce(CLIENT, now);
        assert_eq!(nonce.len(), 22, "16 bytes → 22 base64url characters");
        assert_eq!(auth.check_nonce(&nonce, CLIENT, now), NonceState::Valid);
        // Same secret, another instance: the nonce still verifies — that is what
        // "stateless" buys (no shared state, just a shared secret).
        let peer_instance = Auth::long_term(
            "example.org".to_string(),
            b"nonce-secret".to_vec(),
            vec![user()],
            Duration::from_secs(DEFAULT_NONCE_LIFETIME),
            false,
        );
        assert_eq!(
            peer_instance.check_nonce(&nonce, CLIENT, now),
            NonceState::Valid
        );
        // 1h later (plus a second) it is stale, not invalid.
        let later = now + Duration::from_secs(DEFAULT_NONCE_LIFETIME + 1);
        assert_eq!(auth.check_nonce(&nonce, CLIENT, later), NonceState::Expired);
        // Another client IP: the tag no longer matches → 401, never 438.
        let other: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        assert_eq!(auth.check_nonce(&nonce, other, now), NonceState::Invalid);
        // A different secret does not accept it either.
        let other_secret = Auth::long_term(
            "example.org".to_string(),
            b"other-secret".to_vec(),
            vec![user()],
            Duration::from_secs(DEFAULT_NONCE_LIFETIME),
            false,
        );
        assert_eq!(
            other_secret.check_nonce(&nonce, CLIENT, now),
            NonceState::Invalid
        );
    }

    #[test]
    fn nonce_rejects_tampering_and_garbage() {
        let auth = auth();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let nonce = auth.issue_nonce(CLIENT, now);
        let mut bytes = base64url_decode(&nonce).unwrap();
        bytes[3] ^= 0x40;
        let tampered = base64url_encode(&bytes);
        assert_eq!(
            auth.check_nonce(&tampered, CLIENT, now),
            NonceState::Invalid
        );
        for garbage in ["", "not a nonce", "AAAA", "f//499k954d6OL34oL9FSTvy64sA"] {
            assert_eq!(
                auth.check_nonce(garbage, CLIENT, now),
                NonceState::Invalid,
                "{garbage:?} must not be accepted"
            );
        }
        // A short lifetime really expires immediately at its own second.
        let short = Auth::long_term(
            "example.org".to_string(),
            b"nonce-secret".to_vec(),
            vec![user()],
            Duration::from_secs(1),
            false,
        );
        let nonce = short.issue_nonce(CLIENT, now);
        assert_eq!(short.check_nonce(&nonce, CLIENT, now), NonceState::Valid);
        assert_eq!(
            short.check_nonce(&nonce, CLIENT, now + Duration::from_secs(1)),
            NonceState::Expired
        );
    }

    #[test]
    fn base64_matches_rfc4648_padding_rules() {
        // The standard alphabet (not the nonce's URL-safe one): the TURN REST
        // API password is consumed by coturn and by `turnutils_uclient -W`.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64_encode(&[0x00, 0x01, 0x02, 0x03, 0x04]), "AAECAwQ=");
    }

    #[test]
    fn rest_password_matches_coturn_use_auth_secret() {
        // python: base64.b64encode(hmac.new(secret, username, sha1).digest())
        assert_eq!(
            rest_password(b"turn-test-secret", "1700000000:alice"),
            "AHuE7M4O2lyk3ebHJ95FoVRfR5A="
        );
        // The label after the first `:` is opaque: it may contain separators.
        assert_eq!(
            rest_password(b"turn-test-secret", "1700000000:label:with:colons"),
            "e4LMlhg2jmZG/q3ikBP/if84ybs="
        );
        // Only the first `:` splits: `<expiry>:<label>` with an empty label is
        // still a REST name, a leading `:` is not.
        assert_eq!(
            rest_username_expiry("1700000000:alice"),
            Some(1_700_000_000)
        );
        assert_eq!(rest_username_expiry("1700000000:"), Some(1_700_000_000));
        assert_eq!(rest_username_expiry("1700000000:a:b"), Some(1_700_000_000));
        assert_eq!(rest_username_expiry("1700000000"), None);
        assert_eq!(rest_username_expiry(":alice"), None);
        assert_eq!(rest_username_expiry("alice:1700000000"), None);
        assert_eq!(rest_username_expiry("-1:alice"), None);
        assert_eq!(rest_username_expiry("1_700:alice"), None);
        assert_eq!(rest_username_expiry("99999999999999999999999:x"), None);
    }

    /// Long-term request carrying `USERNAME`/`REALM`/`NONCE` and a MAC made
    /// with `key` — the shape both the stored-user and REST paths verify.
    fn long_term_request(
        username: &str,
        nonce: &str,
        key: Vec<u8>,
        algorithm: KeyAlgorithm,
    ) -> Vec<u8> {
        let transaction_id = TransactionId([0x5a; 12]);
        let mut body = Vec::new();
        protocol::push_attribute(&mut body, ATTR_USERNAME, username.as_bytes());
        protocol::push_attribute(&mut body, ATTR_REALM, b"example.org");
        protocol::push_attribute(&mut body, ATTR_NONCE, nonce.as_bytes());
        protocol::push_attribute(&mut body, 0x0019, &[17, 0, 0, 0]);
        let frame = protocol::encode_message(
            protocol::message_type(0x0003, protocol::MessageClass::Request),
            &transaction_id,
            &body,
        );
        seal(
            frame,
            &Identity {
                username: username.to_string(),
                keys: vec![(algorithm, key)],
            },
        )
    }

    fn rest_auth() -> Auth {
        auth().with_rest_secret(b"turn-test-secret".to_vec())
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn rest_credentials_verify_expire_and_do_not_need_a_stored_user() {
        let auth = rest_auth();
        let now = at(1_700_000_000);
        let nonce = auth.issue_nonce(CLIENT, now);
        let username = "1700000600:alice";
        let password = rest_password(b"turn-test-secret", username);
        let key = long_term_key(KeyAlgorithm::Md5, username, "example.org", &password);
        let frame = long_term_request(username, &nonce, key, KeyAlgorithm::Md5);
        let message = protocol::parse(&frame).unwrap();
        assert_eq!(
            auth.verify(&frame, &message, CLIENT, now),
            Ok(Identity {
                username: username.to_string(),
                keys: vec![(
                    KeyAlgorithm::Md5,
                    long_term_key(KeyAlgorithm::Md5, username, "example.org", &password)
                )],
            })
        );

        // Expired: 401, even with a perfectly valid MAC.
        let later = at(1_700_000_600);
        let nonce = auth.issue_nonce(CLIENT, later);
        let frame = long_term_request(
            username,
            &nonce,
            long_term_key(KeyAlgorithm::Md5, username, "example.org", &password),
            KeyAlgorithm::Md5,
        );
        let message = protocol::parse(&frame).unwrap();
        assert_eq!(
            auth.verify(&frame, &message, CLIENT, later),
            Err(Rejection::Unauthorized)
        );

        // Wrong secret: the derived password (and therefore the key) differs.
        let wrong = rest_password(b"other-secret", username);
        let key = long_term_key(KeyAlgorithm::Md5, username, "example.org", &wrong);
        let frame = long_term_request(username, &nonce, key, KeyAlgorithm::Md5);
        let message = protocol::parse(&frame).unwrap();
        assert_eq!(
            auth.verify(&frame, &message, CLIENT, now),
            Err(Rejection::Unauthorized)
        );
    }

    #[test]
    fn rest_credentials_take_priority_over_a_stored_user_with_the_same_name() {
        // A stored user literally named `1700000600:rest` with a different
        // password: if the table won, the REST MAC below would not verify.
        let stored = User {
            username: "1700000600:rest".to_string(),
            password: "table-password".to_string(),
        };
        let auth = Auth::long_term(
            "example.org".to_string(),
            b"nonce-secret".to_vec(),
            vec![stored],
            Duration::from_secs(DEFAULT_NONCE_LIFETIME),
            false,
        )
        .with_rest_secret(b"turn-test-secret".to_vec());
        let now = at(1_700_000_000);
        let nonce = auth.issue_nonce(CLIENT, now);
        let password = rest_password(b"turn-test-secret", "1700000600:rest");
        let key = long_term_key(
            KeyAlgorithm::Md5,
            "1700000600:rest",
            "example.org",
            &password,
        );
        let frame = long_term_request("1700000600:rest", &nonce, key, KeyAlgorithm::Md5);
        let message = protocol::parse(&frame).unwrap();
        assert!(auth.verify(&frame, &message, CLIENT, now).is_ok());
        // And the table password is *not* accepted for that name any more.
        let table = long_term_key(
            KeyAlgorithm::Md5,
            "1700000600:rest",
            "example.org",
            "table-password",
        );
        let frame = long_term_request("1700000600:rest", &nonce, table, KeyAlgorithm::Md5);
        let message = protocol::parse(&frame).unwrap();
        assert_eq!(
            auth.verify(&frame, &message, CLIENT, now),
            Err(Rejection::Unauthorized)
        );
    }

    #[test]
    fn rest_secret_stays_off_the_stored_user_path() {
        // With `--rest-secret` configured, a name that does not parse as
        // `<expiry>:<label>` must still authenticate against the user table.
        let auth = rest_auth();
        let now = at(1_700_000_000);
        let nonce = auth.issue_nonce(CLIENT, now);
        let key = long_term_key(KeyAlgorithm::Md5, "user", "example.org", "pass");
        let frame = long_term_request("user", &nonce, key, KeyAlgorithm::Md5);
        let message = protocol::parse(&frame).unwrap();
        assert!(auth.verify(&frame, &message, CLIENT, now).is_ok());
    }

    #[test]
    fn rest_missing_nonce_is_still_a_bad_request() {
        let auth = rest_auth();
        let transaction_id = TransactionId([0x11; 12]);
        let mut body = Vec::new();
        protocol::push_attribute(&mut body, ATTR_USERNAME, b"1700000600:alice");
        protocol::push_attribute(&mut body, ATTR_REALM, b"example.org");
        let frame = protocol::encode_message(
            protocol::message_type(0x0003, protocol::MessageClass::Request),
            &transaction_id,
            &body,
        );
        // MI present (so this is not the "no credentials at all" 401), NONCE
        // absent: a malformed long-term request is a 400.
        let frame = seal(
            frame,
            &Identity {
                username: "1700000600:alice".to_string(),
                keys: vec![(KeyAlgorithm::Md5, vec![0x11; 16])],
            },
        );
        let message = protocol::parse(&frame).unwrap();
        assert_eq!(
            auth.verify(&frame, &message, CLIENT, at(1_700_000_000)),
            Err(Rejection::BadRequest)
        );
    }

    #[test]
    fn base64url_matches_rfc4648() {
        // RFC 4648 §10, with `+/` replaced by `-_` and no padding.
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        for text in [
            b"".as_slice(),
            b"f",
            b"fo",
            b"foo",
            b"foobar",
            &[0xfb, 0xff, 0x00],
        ] {
            assert_eq!(base64url_decode(&base64url_encode(text)).unwrap(), text);
        }
        // Padding, foreign characters and `n % 4 == 1` are rejected.
        for bad in ["Zg==", "Zm9v+", "Zm9v/", "AAAAA"] {
            assert!(base64url_decode(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn password_algorithms_value_lists_the_supported_set() {
        let auth = auth();
        assert_eq!(
            auth.password_algorithms_value(),
            vec![0, 1, 0, 0, 0, 2, 0, 0]
        );
        let sha_only = Auth::long_term(
            "example.org".to_string(),
            b"nonce-secret".to_vec(),
            vec![user()],
            Duration::from_secs(DEFAULT_NONCE_LIFETIME),
            true,
        );
        assert_eq!(sha_only.password_algorithms_value(), vec![0, 2, 0, 0]);
    }

    #[test]
    fn sealing_keeps_padding_last_and_stays_verifiable() {
        // RFC 5780 §7.6 says PADDING is the last attribute; RFC 5389 §10.2.2
        // wants an integrity attribute on the answer. Both must hold at once.
        let identity = Identity {
            username: "user".to_string(),
            keys: vec![(
                KeyAlgorithm::Md5,
                long_term_key(KeyAlgorithm::Md5, "user", "example.org", "pass"),
            )],
        };
        let transaction_id = TransactionId([0x33; 12]);
        let peer: std::net::SocketAddr = "198.51.100.7:5000".parse().unwrap();
        let plain = protocol::binding_success_response(&protocol::SuccessResponse {
            transaction_id: &transaction_id,
            peer,
            software: "rstun/test",
            addresses: None,
            mapped_address: false,
            padding: Some(8),
        });
        let sealed = seal(plain.clone(), &identity);
        let message = protocol::parse(&sealed).expect("sealed response must parse");
        let types: Vec<u16> = protocol::attributes(message.body)
            .map(|attribute| attribute.attr_type)
            .collect();
        assert_eq!(types.last(), Some(&protocol::ATTR_PADDING));
        assert!(types.contains(&ATTR_MESSAGE_INTEGRITY));
        assert!(verify_integrity(
            &sealed,
            &identity.keys[0].1,
            KeyAlgorithm::Md5
        ));
        let padding = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_PADDING)
            .expect("PADDING");
        assert_eq!(padding.value.len(), 8, "the echoed length must not change");
        assert_eq!(sealed.len(), plain.len() + 24);
        assert_eq!(
            usize::from(u16::from_be_bytes([sealed[2], sealed[3]])),
            sealed.len() - HEADER_LEN
        );
    }

    #[test]
    fn error_responses_carry_the_documented_attributes() {
        let auth = auth();
        let transaction_id = TransactionId([0x5a; 12]);
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let response = auth.unauthorized(&transaction_id, 0x0001, CLIENT, now);
        let message = protocol::parse(&response).unwrap();
        assert_eq!(
            protocol::message_class(message.msg_type),
            protocol::MessageClass::ErrorResponse
        );
        let mut types: Vec<u16> = protocol::attributes(message.body)
            .map(|attribute| attribute.attr_type)
            .collect();
        types.sort_unstable();
        assert_eq!(
            types,
            vec![
                protocol::ATTR_ERROR_CODE,
                ATTR_REALM,
                ATTR_NONCE,
                ATTR_PASSWORD_ALGORITHMS
            ]
        );
        let code = protocol::attributes(message.body)
            .find(|attribute| attribute.attr_type == protocol::ATTR_ERROR_CODE)
            .map(|attribute| u16::from(attribute.value[2]) * 100 + u16::from(attribute.value[3]))
            .unwrap();
        assert_eq!(code, ERROR_UNAUTHORIZED);
        // 438 carries a *fresh* nonce next to the realm (RFC 5389 §10.2.2).
        let stale = auth.stale_nonce(&transaction_id, 0x0001, CLIENT, now);
        let message = protocol::parse(&stale).unwrap();
        let nonce = attribute(message.body, ATTR_NONCE).expect("NONCE");
        assert_eq!(
            auth.check_nonce(std::str::from_utf8(nonce).unwrap(), CLIENT, now),
            NonceState::Valid
        );
        assert!(attribute(message.body, ATTR_REALM).is_some());
        // RFC 8489 §9.2.4: a 438 carries PASSWORD-ALGORITHMS too, so the client
        // can rebuild the MAC with the algorithm the server will accept.
        let algorithms = attribute(message.body, ATTR_PASSWORD_ALGORITHMS);
        assert_eq!(algorithms, Some([0, 1, 0, 0, 0, 2, 0, 0].as_slice()));
        // Short-term 401 has no realm / nonce to offer.
        let short = Auth::short_term(vec![user()]);
        let response = short.unauthorized(&transaction_id, 0x0001, CLIENT, now);
        let message = protocol::parse(&response).unwrap();
        assert!(
            protocol::attributes(message.body)
                .all(|attribute| attribute.attr_type != ATTR_NONCE
                    && attribute.attr_type != ATTR_REALM)
        );
    }

    #[test]
    fn read_users_parses_comments_and_rejects_garbage() {
        let directory = std::env::temp_dir().join(format!("rstun-auth-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let valid = directory.join("users");
        // CRLF file, a comment, a blank line, and a password with a trailing
        // space: only the line ending is stripped, the space is data.
        std::fs::write(
            &valid,
            "# comment\r\n\r\nalice:s3cret \r\nbob:pw:with:colons\r\n",
        )
        .unwrap();
        let users = read_users(&valid).unwrap();
        assert_eq!(
            users,
            vec![
                User {
                    username: "alice".to_string(),
                    password: "s3cret ".to_string()
                },
                User {
                    username: "bob".to_string(),
                    password: "pw:with:colons".to_string()
                },
            ]
        );
        let invalid = directory.join("bad");
        std::fs::write(&invalid, "alice\n").unwrap();
        assert!(read_users(&invalid).unwrap_err().contains("user:password"));
        std::fs::write(&invalid, "# only comments\n").unwrap();
        assert!(read_users(&invalid).unwrap_err().contains("no credentials"));
        assert!(read_users(&directory.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
