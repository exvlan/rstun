//! Cross-instance TURN ownership (multi-instance, M1: UDP clients).
//!
//! A TURN allocation lives in the process that created it: the relay socket,
//! the permission/channel tables and the client-side sink all belong to that
//! process. When several instances sit behind a load balancer, a client's
//! requests can land on any of them, so every instance has to be able to name
//! the **owner** of a client's 5-tuple and forward the work there.
//!
//! Ownership is a pure function of the normalized 5-tuple and a static member
//! list (consistent hashing, design D1): no shared table, no heartbeats, no
//! external store. Changing the member list moves some keys, so a membership
//! change is a drain-and-rebuild, not an online migration (design C3).
//!
//! Two channels connect a pair of instances, both bound by `--cluster-listen`:
//!
//! * **control**: one long-lived TCP connection per peer. Carries `REQUEST`
//!   (entry → owner, the raw STUN frame plus the client endpoint) and the
//!   owner's signed `RESPONSE` back over the same connection.
//! * **data**: a UDP socket on the same port number. Carries `PUSH_DATA`
//!   (entry → owner) for `Send` / `ChannelData`; it is fire-and-forget because
//!   relayed media is best-effort exactly like the client-side UDP path, and a
//!   TCP hop would let one lost segment stall every media stream of a client.
//!
//! Authentication stays on the owner: a `REQUEST` is just the original STUN
//! frame, so the owner verifies `MESSAGE-INTEGRITY` exactly as it would for a
//! locally received request. Permission checks for pushed data stay there too.
//!
//! Frames are hand-written (design D5, no new dependency):
//!
//! ```text
//! 0               4      5      6      7      8            12
//! +---------------+------+------+------+------+-------------+-----------
//! | payload len   | type | flags| rsvd |      session id     | payload …
//! +---------------+------+------+------+------+-------------+-----------
//!                      (len 不含 12 字节头；含 HMAC 尾)
//! ```
//!
//! With `--cluster-secret` every frame carries a truncated HMAC-SHA256 over the
//! header and the untagged payload (`flags & 0x01`), and an unsigned frame is
//! refused. Without a secret the listener may only bind to a private/loopback
//! address (`Config::validate`).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::turn::{ClientTransport, Key as TurnKey, Turn};
use crate::{Decision, ServerContext};

/// Header length of every internal frame: `len(4) | type(1) | flags(2) |
/// reserved(1) | session(4)`.
pub const HEADER_LEN: usize = 12;

/// `flags & 0x01`: a truncated HMAC-SHA256 tag closes the payload.
pub const FLAG_HMAC: u16 = 0x0001;
/// Bytes of the HMAC-SHA256 tag that are kept (the first 16).
pub const HMAC_TAG_LEN: usize = 16;
/// Upper bound for one frame's payload. A STUN frame is at most 64 KiB; the
/// bound keeps a corrupt length field from making us allocate megabytes.
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Control-channel request budget (design §6: 500 ms, well inside a client's
/// retransmission window). A request that is not answered in time becomes an
/// explicit `500`, never a silent drop.
pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(500);
/// Outbound control link connect budget.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
/// Startup `HELLO` exchange budget (per peer).
const HELLO_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounded queue behind one raw RFC 6062 relay direction (M3).
const RAW_CAPACITY: usize = 64;
/// `RAW_CLOSED` kinds: the client's write half ended, the peer's write half
/// ended, or the whole connection must go away.
pub const RAW_CLOSE_CLIENT_TO_PEER: u8 = 0;
pub const RAW_CLOSE_PEER_TO_CLIENT: u8 = 1;
pub const RAW_CLOSE_ABORT: u8 = 2;
/// Delay before re-dialling a peer whose control connection ended.
const RETRY_DELAY: Duration = Duration::from_millis(200);
/// Bounded write queue of one control link; a peer that stops reading must not
/// let the queue grow without bound.
const LINK_CAPACITY: usize = 256;
/// Read chunk for the buffered frame reader.
const READ_CHUNK: usize = 16 * 1024;
/// Virtual ring points per member. One point per member is a mathematically
/// valid consistent hash but can leave a two-member ring lopsided; 16 points
/// keeps the split close to even and changes nothing else.
const VIRTUAL_NODES: u32 = 16;

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// Frame kinds (design §4.1). Only `Request`, `Response` and `PushData` are
/// used by M1; the rest are defined here so M2/M3 add no wire churn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Entry → owner: the original STUN frame, execute it.
    Request = 0x01,
    /// Owner → entry: the signed response bytes (empty = no response).
    Response = 0x02,
    /// Entry → owner: `Send` / `ChannelData` bytes to relay.
    PushData = 0x03,
    /// Owner → entry: bytes for a stream client's write queue (M2).
    PushClient = 0x04,
    /// Entry → owner: the client connection is gone (M2).
    ClientClosed = 0x05,
    /// Raw bytes of a bound RFC 6062 data connection (M3).
    RawRelay = 0x06,
    Ping = 0x07,
    Pong = 0x08,
    /// Identify the peer before anything else on a control connection: protocol
    /// version, instance id and the service ports the member serves.
    Hello = 0x09,
    /// Owner → entry: `ConnectionBind` succeeded; the payload is the signed
    /// response and the session's connection continues as raw bytes (M3).
    Bound = 0x0A,
    /// Either side: one direction of a raw relay ended. Payload is one byte.
    RawClosed = 0x0B,
}

impl FrameType {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0x01 => Self::Request,
            0x02 => Self::Response,
            0x03 => Self::PushData,
            0x04 => Self::PushClient,
            0x05 => Self::ClientClosed,
            0x06 => Self::RawRelay,
            0x07 => Self::Ping,
            0x08 => Self::Pong,
            0x09 => Self::Hello,
            0x0A => Self::Bound,
            0x0B => Self::RawClosed,
            _ => return None,
        })
    }

    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Wire version of [`Hello`]. A member speaking another version is refused
/// instead of being served with mismatched semantics.
pub const HELLO_VERSION: u8 = 2;

/// Payload of a [`FrameType::Hello`] frame.
///
/// Every member must serve the **same** ports: the ownership key contains the
/// port the request arrived on, so a client that reaches `--listen 3478` on one
/// instance and `--listen 3479` on another would hash to two owners. Instances
/// are told apart by IP (or netns), not by port (design C2 / PRD C2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub instance_id: String,
    /// Plain UDP/TCP `--listen` port (the one TURN clients reach).
    pub listen_port: u16,
    /// `--turn-tls-listen` port, `0` when that transport is off.
    pub tls_port: u16,
    /// `--turn-dtls-listen` port, `0` when that transport is off.
    pub dtls_port: u16,
    /// This instance's **own** TCP relay range, `(0, 0)` when RFC 6062 is off.
    /// Ranges must be disjoint across members (`SO_REUSEPORT` would otherwise
    /// let two instances listen on the same TCP port).
    pub tcp_relay_ports: (u16, u16),
    /// Number of members in this instance's `--cluster-peer` set (self added
    /// when omitted) and a digest of their sorted ids. A member list that is
    /// missing an entry would silently move some keys to another owner, so the
    /// sets must match exactly (B3).
    pub member_count: u16,
    pub member_digest: [u8; 8],
}

impl Hello {
    fn encode(&self) -> Vec<u8> {
        let id = self.instance_id.as_bytes();
        let mut out = Vec::with_capacity(22 + id.len());
        out.push(self.version);
        out.extend_from_slice(&self.listen_port.to_be_bytes());
        out.extend_from_slice(&self.tls_port.to_be_bytes());
        out.extend_from_slice(&self.dtls_port.to_be_bytes());
        out.extend_from_slice(&self.tcp_relay_ports.0.to_be_bytes());
        out.extend_from_slice(&self.tcp_relay_ports.1.to_be_bytes());
        out.extend_from_slice(&self.member_count.to_be_bytes());
        out.extend_from_slice(&self.member_digest);
        out.push(id.len().min(u8::MAX as usize) as u8);
        out.extend_from_slice(&id[..id.len().min(u8::MAX as usize)]);
        out
    }

    fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < 22 {
            return None;
        }
        let version = payload[0];
        let listen_port = u16::from_be_bytes([payload[1], payload[2]]);
        let tls_port = u16::from_be_bytes([payload[3], payload[4]]);
        let dtls_port = u16::from_be_bytes([payload[5], payload[6]]);
        let tcp_lo = u16::from_be_bytes([payload[7], payload[8]]);
        let tcp_hi = u16::from_be_bytes([payload[9], payload[10]]);
        let member_count = u16::from_be_bytes([payload[11], payload[12]]);
        let mut member_digest = [0_u8; 8];
        member_digest.copy_from_slice(payload.get(13..21)?);
        let id_len = usize::from(*payload.get(21)?);
        let id = std::str::from_utf8(payload.get(22..22 + id_len)?).ok()?;
        Some(Self {
            version,
            instance_id: id.to_string(),
            listen_port,
            tls_port,
            dtls_port,
            tcp_relay_ports: (tcp_lo, tcp_hi),
            member_count,
            member_digest,
        })
    }
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameType,
    pub session: u32,
    pub payload: Vec<u8>,
}

/// Why a frame was refused. Every variant closes the connection: a stream that
/// carried one cannot be trusted to stay aligned.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Header or payload shorter than claimed.
    Short,
    /// `type` byte is not a known frame kind.
    UnknownType(u8),
    /// `flags` carries bits this version does not define.
    UnknownFlags(u16),
    /// Claimed payload length above [`MAX_PAYLOAD`].
    TooLarge,
    /// HMAC missing, malformed or wrong.
    BadHmac,
}

/// Header fields of one frame (payload not yet read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameHead {
    kind: FrameType,
    flags: u16,
    session: u32,
    payload_len: usize,
}

impl FrameHead {
    fn parse(header: &[u8]) -> Result<Self, FrameError> {
        if header.len() < HEADER_LEN {
            return Err(FrameError::Short);
        }
        let kind = FrameType::from_byte(header[4]).ok_or(FrameError::UnknownType(header[4]))?;
        let flags = u16::from_be_bytes([header[5], header[6]]);
        if flags & !FLAG_HMAC != 0 {
            return Err(FrameError::UnknownFlags(flags));
        }
        let payload_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if payload_len > MAX_PAYLOAD {
            return Err(FrameError::TooLarge);
        }
        let session = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        Ok(Self {
            kind,
            flags,
            session,
            payload_len,
        })
    }
}

fn hmac_tag(secret: &[u8], header: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(header);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

/// Constant-time comparison for the truncated tag.
fn tag_matches(expected: &[u8], supplied: &[u8]) -> bool {
    if expected.len() != supplied.len() {
        return false;
    }
    expected
        .iter()
        .zip(supplied)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn encode_with_flags(
    kind: FrameType,
    flags: u16,
    session: u32,
    payload: &[u8],
    secret: Option<&[u8]>,
) -> Vec<u8> {
    let tagged = secret.is_some();
    let body_len = payload.len() + if tagged { HMAC_TAG_LEN } else { 0 };
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&(body_len as u32).to_be_bytes());
    header.push(kind.as_byte());
    header.extend_from_slice(&flags.to_be_bytes());
    header.push(0);
    header.extend_from_slice(&session.to_be_bytes());
    let mut out = Vec::with_capacity(HEADER_LEN + body_len);
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    if let Some(secret) = secret {
        // The tag covers the header (length field included) and the payload,
        // and is appended after it.
        let tag = hmac_tag(secret, &header, payload);
        out.extend_from_slice(&tag[..HMAC_TAG_LEN]);
    }
    out
}

/// Encode one frame; `secret` selects (and signs with) the HMAC flag.
pub fn encode_frame(
    kind: FrameType,
    session: u32,
    payload: &[u8],
    secret: Option<&[u8]>,
) -> Vec<u8> {
    let flags = if secret.is_some() { FLAG_HMAC } else { 0 };
    encode_with_flags(kind, flags, session, payload, secret)
}

fn decode_frame(header: &[u8], body: &[u8], secret: Option<&[u8]>) -> Result<Frame, FrameError> {
    let head = FrameHead::parse(header)?;
    if body.len() < head.payload_len {
        return Err(FrameError::Short);
    }
    let tagged = head.flags & FLAG_HMAC != 0;
    let (payload, tag) = if tagged {
        let split = head
            .payload_len
            .checked_sub(HMAC_TAG_LEN)
            .ok_or(FrameError::BadHmac)?;
        (&body[..split], Some(&body[split..head.payload_len]))
    } else {
        (&body[..head.payload_len], None)
    };
    match (tagged, secret, tag) {
        (true, Some(secret), Some(tag)) => {
            let expected = hmac_tag(secret, header, payload);
            if !tag_matches(&expected[..HMAC_TAG_LEN], tag) {
                return Err(FrameError::BadHmac);
            }
        }
        // A secret is configured but the frame is unsigned, or the reverse:
        // both are refusals, never "verify what we can".
        (true, None, _) | (false, Some(_), _) => return Err(FrameError::BadHmac),
        (false, None, _) => {}
        (true, Some(_), None) => unreachable!("tagged frame always splits a tag"),
    }
    Ok(Frame {
        kind: head.kind,
        session: head.session,
        payload: payload.to_vec(),
    })
}

/// Decode one datagram that must hold exactly one frame.
fn decode_datagram(datagram: &[u8], secret: Option<&[u8]>) -> Result<Frame, FrameError> {
    let head = FrameHead::parse(datagram)?;
    if datagram.len() < HEADER_LEN + head.payload_len {
        return Err(FrameError::Short);
    }
    if datagram.len() != HEADER_LEN + head.payload_len {
        return Err(FrameError::Short);
    }
    decode_frame(&datagram[..HEADER_LEN], &datagram[HEADER_LEN..], secret)
}

/// Buffered, cancel-safe frame reader for a byte stream.
///
/// `AsyncReadExt::read` either transfers bytes or is cancelled without losing
/// them, so this is safe inside a `select!` next to a write branch, which is
/// what a bidirectional control link needs.
struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Pull more bytes into the buffer. `Ok(false)` is a clean EOF.
    async fn read_more<R>(&mut self, reader: &mut R, chunk: &mut [u8]) -> io::Result<bool>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        let length = reader.read(chunk).await?;
        if length == 0 {
            return Ok(false);
        }
        self.buffer.extend_from_slice(&chunk[..length]);
        Ok(true)
    }

    /// Take the next complete frame, if the buffer holds one.
    fn next(&mut self, secret: Option<&[u8]>) -> Result<Option<Frame>, FrameError> {
        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }
        let head = FrameHead::parse(&self.buffer[..HEADER_LEN])?;
        let total = HEADER_LEN + head.payload_len;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let frame = decode_frame(
            &self.buffer[..HEADER_LEN],
            &self.buffer[HEADER_LEN..total],
            secret,
        )?;
        self.buffer.drain(..total);
        Ok(Some(frame))
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// Which client transport the request arrived on, for the normalized key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportClass {
    Udp,
    Tcp,
    Dtls,
}

impl TransportClass {
    fn as_byte(self) -> u8 {
        match self {
            Self::Udp => 0,
            Self::Tcp => 1,
            Self::Dtls => 2,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Udp,
            1 => Self::Tcp,
            2 => Self::Dtls,
            _ => return None,
        })
    }
}

impl From<ClientTransport> for TransportClass {
    fn from(transport: ClientTransport) -> Self {
        match transport {
            ClientTransport::Udp => Self::Udp,
            ClientTransport::Tcp => Self::Tcp,
            ClientTransport::Dtls => Self::Dtls,
        }
    }
}

impl From<TransportClass> for ClientTransport {
    fn from(transport: TransportClass) -> Self {
        match transport {
            TransportClass::Udp => Self::Udp,
            TransportClass::Tcp => Self::Tcp,
            TransportClass::Dtls => Self::Dtls,
        }
    }
}

/// IPv4-mapped IPv6 is the same endpoint as the IPv4 address (`::ffff:127.0.0.1`
/// and `127.0.0.1` must not be two different clients).
fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        ip => ip,
    }
}

/// The canonical `Key.server` value in cluster mode (design D3).
///
/// `Key.server` means two different things today: the *bound* address on
/// UDP/DTLS (the same on every instance) and the *connection's local* address
/// on TCP (different per host). Since ownership must be identical on every
/// instance, the key only keeps the listen **port**; the address becomes the
/// wildcard. Nothing ever sends to this value — it is a table key.
pub fn normalized_server(listen_port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port)
}

/// The normalized 5-tuple ownership is computed from (design D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub transport: TransportClass,
    pub listen_port: u16,
}

impl NodeKey {
    /// Build from the client endpoint, the client transport and the address
    /// the request arrived on (or its normalized form; only the port is read).
    pub fn new(client: SocketAddr, transport: TransportClass, server: SocketAddr) -> Self {
        Self {
            client_ip: normalized_ip(client.ip()),
            client_port: client.port(),
            transport,
            listen_port: server.port(),
        }
    }

    fn hash(&self) -> u64 {
        let mut bytes = Vec::with_capacity(24);
        match self.client_ip {
            IpAddr::V4(v4) => {
                bytes.push(4);
                bytes.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                bytes.push(6);
                bytes.extend_from_slice(&v6.octets());
            }
        }
        bytes.extend_from_slice(&self.client_port.to_be_bytes());
        bytes.push(self.transport.as_byte());
        bytes.extend_from_slice(&self.listen_port.to_be_bytes());
        fnv1a(&bytes)
    }
}

/// Wire form of one client endpoint: `family(1) | reserved(3) | port(2) |
/// address(4|16)` (10 or 22 bytes). Used by `PUSH_CLIENT` and as the middle of
/// a `REQUEST` / `PUSH_DATA` payload.
fn encode_endpoint(client: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    match client.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&[0, 0, 0]);
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x02);
            out.extend_from_slice(&[0, 0, 0]);
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&v6.octets());
        }
    }
    out
}

fn decode_endpoint(payload: &[u8]) -> Option<(SocketAddr, &[u8])> {
    let family = *payload.first()?;
    let (ip, used) = match family {
        0x01 => {
            let bytes: [u8; 4] = payload.get(6..10)?.try_into().ok()?;
            (IpAddr::V4(bytes.into()), 10)
        }
        0x02 => {
            let bytes: [u8; 16] = payload.get(6..22)?.try_into().ok()?;
            (IpAddr::V6(bytes.into()), 22)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([payload[4], payload[5]]);
    Some((SocketAddr::new(ip, port), payload.get(used..)?))
}

/// Wire form of one `REQUEST` / `PUSH_DATA` payload:
/// `stream_session(4) | endpoint(10|22) | transport(1) | listen_port(2) |
/// datagram`.
///
/// `stream_session` is the entry-side client connection (0 for UDP): the owner
/// uses it to push peer→client bytes back through `PUSH_CLIENT` and to release
/// the allocation on `CLIENT_CLOSED`.
pub(crate) fn encode_payload(
    stream_session: u32,
    client: SocketAddr,
    transport: TransportClass,
    listen_port: u16,
    datagram: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + datagram.len());
    out.extend_from_slice(&stream_session.to_be_bytes());
    out.extend_from_slice(&encode_endpoint(client));
    out.push(transport.as_byte());
    out.extend_from_slice(&listen_port.to_be_bytes());
    out.extend_from_slice(datagram);
    out
}

fn decode_payload(payload: &[u8]) -> Option<(u32, SocketAddr, TransportClass, u16, &[u8])> {
    let stream_session = u32::from_be_bytes(payload.get(..4)?.try_into().ok()?);
    let (client, rest) = decode_endpoint(payload.get(4..)?)?;
    let transport = TransportClass::from_byte(*rest.first()?)?;
    let listen_port = u16::from_be_bytes([*rest.get(1)?, *rest.get(2)?]);
    Some((
        stream_session,
        client,
        transport,
        listen_port,
        rest.get(3..)?,
    ))
}

fn decode_push_client(payload: &[u8]) -> Option<Vec<u8>> {
    let (_client, bytes) = decode_endpoint(payload)?;
    Some(bytes.to_vec())
}

/// `AsyncRead` over the owner-side inbound half of a raw relay: each
/// `RAW_RELAY` payload is one chunk, and the channel closing is EOF.
struct ChannelReader {
    receiver: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
}

impl ChannelReader {
    fn new(receiver: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            receiver,
            current: Vec::new(),
            offset: 0,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.offset < this.current.len() {
                let length = buffer.remaining().min(this.current.len() - this.offset);
                buffer.put_slice(&this.current[this.offset..this.offset + length]);
                this.offset += length;
                return Poll::Ready(Ok(()));
            }
            match this.receiver.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.current = chunk;
                    this.offset = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Member ring
// ---------------------------------------------------------------------------

/// One configured instance: an id and the address its control/data channels
/// are bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: String,
    pub addr: SocketAddr,
}

/// Static member list plus its consistent-hash ring.
#[derive(Debug)]
pub struct Membership {
    members: Vec<Member>,
    /// `(ring point, member index)`, sorted by point.
    ring: Vec<(u64, usize)>,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn ring_point(id: &str, replica: u32) -> u64 {
    let mut bytes = id.as_bytes().to_vec();
    bytes.push(b'#');
    bytes.extend_from_slice(&replica.to_be_bytes());
    fnv1a(&bytes)
}

impl Membership {
    /// Sort members by id and lay out their virtual points. Duplicate ids are a
    /// configuration error: they would make the ring ambiguous.
    pub fn new(mut members: Vec<Member>) -> Result<Self, String> {
        members.sort_by(|a, b| a.id.cmp(&b.id));
        if members.is_empty() {
            return Err("cluster member list must not be empty".to_string());
        }
        if let Some(pair) = members.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(format!("duplicate --cluster-peer id {:?}", pair[0].id));
        }
        let mut ring = Vec::with_capacity(members.len() * VIRTUAL_NODES as usize);
        for (index, member) in members.iter().enumerate() {
            for replica in 0..VIRTUAL_NODES {
                ring.push((ring_point(&member.id, replica), index));
            }
        }
        ring.sort_unstable();
        Ok(Self { members, ring })
    }

    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The member that owns `key`. Deterministic on every instance because the
    /// ring is built only from the (sorted) ids and the hash is fixed (FNV-1a,
    /// not `RandomState`).
    pub fn owner(&self, key: &NodeKey) -> &Member {
        let hash = key.hash();
        let index = match self.ring.binary_search_by(|(point, _)| point.cmp(&hash)) {
            Ok(index) => index,
            // Past the last point wraps to the first, which is what makes it a
            // ring rather than a range.
            Err(index) if index >= self.ring.len() => 0,
            Err(index) => index,
        };
        &self.members[self.ring[index].1]
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Parsed `--cluster-*` configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub instance_id: String,
    /// The internal `--cluster-listen` address (TCP + UDP on one port).
    pub listen: SocketAddr,
    pub peers: Vec<Member>,
    pub secret: Option<Vec<u8>>,
    /// TURN plain `--listen` port; identical on every member.
    pub listen_port: u16,
    /// `--turn-tls-listen` port, `None` when off; identical on every member.
    pub tls_port: Option<u16>,
    /// `--turn-dtls-listen` port, `None` when off; identical on every member.
    pub dtls_port: Option<u16>,
    /// This instance's TCP relay range (`--tcp-relay-ports`), `None` when RFC
    /// 6062 is off. Members' ranges must be **disjoint**.
    pub tcp_relay_ports: Option<(u16, u16)>,
    /// Concrete `--turn-tls-listen` addresses. The owner binds its relay on the
    /// address of the listener the request arrived on; a TLS request's port is
    /// not in `ServerContext::udp`, so it must be resolved from here (S1).
    pub tls_listen: Vec<SocketAddr>,
    /// Concrete `--turn-dtls-listen` addresses, same reason.
    pub dtls_listen: Vec<SocketAddr>,
}

impl Config {
    /// Refuse configurations that cannot work or would expose the control
    /// channel: an empty member list, duplicate ids, a self entry that does not
    /// match `--cluster-listen`, or a public listener without a secret.
    pub fn validate(&self) -> Result<(), String> {
        if self.instance_id.is_empty() {
            return Err("--cluster-instance-id must not be empty".to_string());
        }
        if self.peers.is_empty() {
            return Err(
                "--cluster-listen needs at least one --cluster-peer <id>@<addr> (the full member list, self included)"
                    .to_string(),
            );
        }
        // The EVEN-PORT token encodes a member index in one byte.
        if self.peers.len() > 255 {
            return Err("--cluster-peer supports at most 255 members".to_string());
        }
        let mut ids = std::collections::HashSet::new();
        for peer in &self.peers {
            if peer.id.is_empty() {
                return Err("--cluster-peer needs a non-empty id (id@addr)".to_string());
            }
            if !ids.insert(peer.id.as_str()) {
                return Err(format!("duplicate --cluster-peer id {:?}", peer.id));
            }
            if peer.id == self.instance_id && peer.addr != self.listen {
                return Err(format!(
                    "--cluster-peer {:?} names this instance but {} does not match --cluster-listen {}",
                    peer.id, peer.addr, self.listen
                ));
            }
        }
        if self.listen_port == 0 {
            return Err("multi-instance TURN needs a non-zero --listen port".to_string());
        }
        if let Some((lo, hi)) = self.tcp_relay_ports
            && (lo == 0 || lo > hi)
        {
            return Err(format!(
                "--tcp-relay-ports needs a valid LO-HI range (got {lo}-{hi})"
            ));
        }
        if let Some(port) = self.tls_port
            && port == 0
        {
            return Err("--turn-tls-listen must not use port 0 in a cluster".to_string());
        }
        if let Some(port) = self.dtls_port
            && port == 0
        {
            return Err("--turn-dtls-listen must not use port 0 in a cluster".to_string());
        }
        if self.tls_port.is_some() == self.tls_listen.is_empty() {
            return Err(
                "cluster TLS port and --turn-tls-listen addresses disagree (internal)".to_string(),
            );
        }
        if self.dtls_port.is_some() == self.dtls_listen.is_empty() {
            return Err(
                "cluster DTLS port and --turn-dtls-listen addresses disagree (internal)"
                    .to_string(),
            );
        }
        if self.secret.as_ref().is_none_or(Vec::is_empty) {
            for address in std::iter::once(self.listen).chain(self.peers.iter().map(|p| p.addr)) {
                if !is_private(address) {
                    return Err(format!(
                        "--cluster-listen / --cluster-peer on a public or wildcard address ({address}) needs --cluster-secret; \
                         bind a concrete private address if you really want no secret"
                    ));
                }
            }
        }
        Ok(())
    }

    /// `--cluster-peer` plus self when the operator omitted it (the same set
    /// [`Membership`] is built from).
    fn members_with_self(&self) -> Vec<Member> {
        let mut members = self.peers.clone();
        if !members.iter().any(|member| member.id == self.instance_id) {
            members.push(Member {
                id: self.instance_id.clone(),
                addr: self.listen,
            });
        }
        members
    }

    fn membership(&self) -> Result<Membership, String> {
        Membership::new(self.members_with_self())
    }
}

/// A peer speaking another HELLO layout must be refused before its payload is
/// interpreted (the member digest extended it from 12 to 22 bytes).
fn check_hello_version(peer: &Hello) -> Result<(), String> {
    if peer.version != HELLO_VERSION {
        return Err(format!(
            "cluster HELLO version {} is not supported (expected {HELLO_VERSION}); \
             every instance must run the same rstun build",
            peer.version
        ));
    }
    Ok(())
}

/// Sorted-id digest of the member set: a member list missing one entry would
/// move some keys to another owner, so peers must agree on the whole set.
fn member_digest(members: &[Member]) -> (u16, [u8; 8]) {
    let mut ids: Vec<&str> = members.iter().map(|member| member.id.as_str()).collect();
    ids.sort_unstable();
    let mut hasher = Sha256::new();
    for id in &ids {
        hasher.update(id.as_bytes());
        hasher.update([0]);
    }
    let mut digest = [0_u8; 8];
    digest.copy_from_slice(&hasher.finalize()[..8]);
    (u16::try_from(ids.len()).unwrap_or(u16::MAX), digest)
}

/// Both instances must list exactly the same `--cluster-peer` ids.
fn check_hello_members(own: &Hello, peer: &Hello) -> Result<(), String> {
    if peer.member_count != own.member_count || peer.member_digest != own.member_digest {
        return Err(format!(
            "--cluster-peer must be identical on every instance: this instance lists {} member(s), \
             {:?} lists {}; copy the same ids to every member",
            own.member_count, peer.instance_id, peer.member_count
        ));
    }
    Ok(())
}

/// Every member must serve the same ports (ownership keys contain the listen
/// port) while owning a **disjoint** TCP relay range (`SO_REUSEPORT`).
fn check_hello_ports(own: &Hello, peer: &Hello) -> Result<(), String> {
    if peer.listen_port != own.listen_port {
        return Err(format!(
            "cluster members must use the same --listen port: this instance serves {}, {:?} serves {}; \
             distinguish instances by IP/netns, not by port",
            own.listen_port, peer.instance_id, peer.listen_port
        ));
    }
    if peer.tls_port != own.tls_port || peer.dtls_port != own.dtls_port {
        return Err(format!(
            "cluster members must serve the same TLS/DTLS ports (this instance: tls={}, dtls={}; {:?}: tls={}, dtls={})",
            own.tls_port, own.dtls_port, peer.instance_id, peer.tls_port, peer.dtls_port
        ));
    }
    match (own.tcp_relay_ports, peer.tcp_relay_ports) {
        ((0, 0), (0, 0)) => Ok(()),
        ((0, 0), _) | (_, (0, 0)) => Err(format!(
            "cluster members must all enable or all disable --turn-tcp-relay ({:?} disagrees)",
            peer.instance_id
        )),
        (mine, theirs) if ranges_overlap(mine, theirs) => Err(format!(
            "TCP relay ranges must be disjoint per instance: this instance {}-{}, {:?} {}-{}; \
             give each member its own --tcp-relay-ports",
            mine.0, mine.1, peer.instance_id, theirs.0, theirs.1
        )),
        _ => Ok(()),
    }
}

/// Do two inclusive port ranges share a port?
fn ranges_overlap(a: (u16, u16), b: (u16, u16)) -> bool {
    a.0 != 0 && b.0 != 0 && a.0 <= b.1 && b.0 <= a.1
}

/// Is `address` a **concrete** private/loopback address? A wildcard
/// (`0.0.0.0` / `::`) is not: it is reachable from every interface, so it needs
/// a `--cluster-secret` just like a public address (B4). Operators who really
/// want an unauthenticated private control channel must name the private IP.
fn is_private(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && (v4.is_private() || v4.is_loopback() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && (v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local())
        }
    }
}

// ---------------------------------------------------------------------------
// The cluster node
// ---------------------------------------------------------------------------

/// Answer to a forwarded `REQUEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Ordinary signed response bytes (empty = no response).
    Response(Vec<u8>),
    /// The request was a successful `ConnectionBind`. The entry writes these
    /// bytes **first**; only then does the owner hand the pending peer data
    /// connection its raw halves, so no `RAW_RELAY` can precede the response.
    /// `session` is the entry-side client connection the response belongs to.
    Bound {
        response: Vec<u8>,
        id: u32,
        session: u32,
    },
}

/// One entry-side connection: the instance that accepted it plus its session
/// number. Ownership-side tables are keyed by this so two entries cannot collide.
type SessionKey = (String, u32);

/// First entry-side session id: drift it with the wall clock, the pid and a
/// stack address. Not cryptographic — the goal is only that a restarted entry
/// does not immediately replay ids an owner still has allocations for (N-d).
fn session_start() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let stack = &nanos as *const u64 as usize as u64;
    let pid = u64::from(std::process::id());
    let mixed = nanos ^ stack.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ pid.rotate_left(17);
    (mixed as u32) | 1
}

/// One entry-side client connection registered for `PUSH_CLIENT` / raw relay.
struct SessionEntry {
    /// The connection's bounded writer queue.
    writer: mpsc::Sender<Vec<u8>>,
    /// Raw-relay close signal (M3): 0 = open, 1 = peer→client EOF, 2 = abort.
    close: watch::Sender<u8>,
}

/// The owner half of a raw RFC 6062 data connection that lives on another
/// instance: `reader` yields the client's bytes (from `RAW_RELAY`), `sender`
/// feeds the writer task that emits `RAW_RELAY` back.
pub(crate) struct RawConnection {
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    pub sender: mpsc::Sender<Vec<u8>>,
    pub writer_task: JoinHandle<()>,
    pub abort: Arc<std::sync::atomic::AtomicBool>,
}

/// What the cluster needs to execute work locally once it is running: the TURN
/// table and the server context (auth, bound sockets).
struct Runtime {
    turn: Weak<Turn>,
    context: Arc<ServerContext>,
}

/// One instance's view of the other members.
pub struct Cluster {
    config: Config,
    membership: RwLock<Option<Membership>>,
    /// Peer id → writer queue of the outbound control link.
    links: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    /// In-flight control requests, keyed by session id.
    pending: Mutex<HashMap<u32, oneshot::Sender<Reply>>>,
    next_session: AtomicU32,
    push: Arc<UdpSocket>,
    runtime: OnceLock<Runtime>,
    shutdown: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Entry role: session id → the stream connection's writer queue. Both
    /// `PUSH_CLIENT` (M2) and `RAW_RELAY` (M3) write through it.
    sessions: Mutex<HashMap<u32, SessionEntry>>,
    /// Entry role: session id → the instance that owns the allocation. Frames
    /// that write into a client connection must come from that instance (B4).
    session_owners: Mutex<HashMap<u32, String>>,
    /// Owner role: `(entry instance, entry session)` → the allocation the
    /// session created. The entry id is part of the key because two entries
    /// both number their connections from 1.
    session_keys: Mutex<HashMap<SessionKey, TurnKey>>,
    /// Owner role: `(entry, session)` → the inbound end of a raw relay (M3).
    raw_in: Mutex<HashMap<SessionKey, mpsc::Sender<Vec<u8>>>>,
    /// Owner role: `(entry, session)` → the `CONNECTION-ID` it bound (M3).
    raw_connections: Mutex<HashMap<SessionKey, u32>>,
    next_client_session: AtomicU32,
}

impl std::fmt::Debug for Cluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cluster")
            .field("instance", &self.config.instance_id)
            .field("listen", &self.config.listen)
            .field(
                "members",
                &self
                    .membership
                    .read()
                    .ok()
                    .and_then(|membership| membership.as_ref().map(|m| m.members().to_vec())),
            )
            .finish_non_exhaustive()
    }
}

impl Cluster {
    /// Bind the TCP control listener and the UDP data socket on the same
    /// address. The listener is returned so [`Cluster::start`] can spawn its
    /// accept loop; binding happens before anything is served.
    pub async fn bind(config: Config) -> io::Result<(Arc<Self>, TcpListener)> {
        config.validate().map_err(io::Error::other)?;
        let membership = config.membership().map_err(io::Error::other)?;
        let listener = TcpListener::bind(config.listen).await?;
        let bound = listener.local_addr()?;
        // The UDP side must use the port the TCP listener actually got (a
        // `--cluster-listen port 0` is for tests).
        let push = Arc::new(crate::udp_socket(bound)?);
        let mut effective = config;
        effective.listen = bound;
        let (shutdown, _) = watch::channel(false);
        Ok((
            Arc::new(Self {
                config: effective,
                membership: RwLock::new(Some(membership)),
                links: Mutex::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
                next_session: AtomicU32::new(1),
                push,
                runtime: OnceLock::new(),
                shutdown,
                tasks: Mutex::new(Vec::new()),
                sessions: Mutex::new(HashMap::new()),
                session_owners: Mutex::new(HashMap::new()),
                session_keys: Mutex::new(HashMap::new()),
                raw_in: Mutex::new(HashMap::new()),
                raw_connections: Mutex::new(HashMap::new()),
                next_client_session: AtomicU32::new(session_start()),
            }),
            listener,
        ))
    }

    pub fn instance_id(&self) -> &str {
        &self.config.instance_id
    }

    pub fn listen(&self) -> SocketAddr {
        self.config.listen
    }

    /// The `HELLO` this instance advertises: ports and TCP range from the
    /// configuration, member set from the **live** membership (tests replace it
    /// after binding on port 0).
    fn hello(&self) -> Hello {
        let members = self.members();
        let (member_count, member_digest) = member_digest(&members);
        Hello {
            version: HELLO_VERSION,
            instance_id: self.config.instance_id.clone(),
            listen_port: self.config.listen_port,
            tls_port: self.config.tls_port.unwrap_or(0),
            dtls_port: self.config.dtls_port.unwrap_or(0),
            tcp_relay_ports: self.config.tcp_relay_ports.unwrap_or((0, 0)),
            member_count,
            member_digest,
        }
    }

    pub fn members(&self) -> Vec<Member> {
        lock_read(&self.membership)
            .as_ref()
            .map(|membership| membership.members().to_vec())
            .unwrap_or_default()
    }

    /// Replace the member list. Tests bind on port 0 and only then know each
    /// instance's address, so they need this second step; production passes the
    /// static list to [`Cluster::bind`] (membership changes are a
    /// drain-and-rebuild, design C3). Self is added when the list omits it.
    #[cfg(test)]
    pub fn set_peers(self: &Arc<Self>, peers: Vec<Member>) -> Result<(), String> {
        let mut members = peers;
        if !members
            .iter()
            .any(|member| member.id == self.config.instance_id)
        {
            members.push(Member {
                id: self.config.instance_id.clone(),
                addr: self.config.listen,
            });
        }
        let membership = Membership::new(members)?;
        *lock_write(&self.membership) = Some(membership);
        Ok(())
    }

    /// The owner of `key`, or `None` before the member list is known (the
    /// caller then keeps the request local rather than dropping it).
    pub fn owner_for(&self, key: &NodeKey) -> Option<Member> {
        lock_read(&self.membership)
            .as_ref()
            .map(|membership| membership.owner(key).clone())
    }

    /// Fail-fast startup check: exchange `HELLO` with every reachable peer and
    /// refuse the configuration when a member serves a different port set (the
    /// ownership key contains the listen port, so mismatched ports split one
    /// client into two allocations). An unreachable peer is only a warning:
    /// requests to it already answer `500`, and it may come up later.
    pub async fn handshake(self: &Arc<Self>) -> Result<(), String> {
        let own = self.hello();
        for member in self.members() {
            if member.id == self.config.instance_id {
                continue;
            }
            let exchange = tokio::time::timeout(
                HELLO_TIMEOUT,
                exchange_hello(&member.addr, &own, self.config.secret.as_deref(), self),
            )
            .await;
            match exchange {
                Ok(Ok(_)) => {}
                // A definite configuration mismatch: refuse to start.
                Ok(Err(HelloError::Invalid(message))) => return Err(message),
                Ok(Err(HelloError::Unreachable(message))) => {
                    tracing::warn!(
                        peer_instance = %member.id,
                        address = %member.addr,
                        %message,
                        "rstun: TURN cluster peer is not reachable yet, starting anyway"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        peer_instance = %member.id,
                        address = %member.addr,
                        "rstun: TURN cluster peer did not answer HELLO, starting anyway"
                    );
                }
            }
        }
        Ok(())
    }

    /// Validate a peer's `HELLO` against this instance's configuration.
    fn verify_hello(&self, hello: &Hello, expected_id: Option<&str>) -> Result<(), String> {
        check_hello_version(hello)?;
        if hello.instance_id == self.config.instance_id {
            return Err(format!(
                "cluster member {:?} uses this instance's id; give every instance a unique --cluster-instance-id",
                hello.instance_id
            ));
        }
        if let Some(expected) = expected_id
            && hello.instance_id != expected
        {
            return Err(format!(
                "cluster address was configured as {expected:?} but the peer identified itself as {:?}",
                hello.instance_id
            ));
        }
        if self
            .members()
            .iter()
            .all(|member| member.id != hello.instance_id)
        {
            return Err(format!(
                "cluster member {:?} is not in --cluster-peer",
                hello.instance_id
            ));
        }
        let own = self.hello();
        check_hello_ports(&own, hello)?;
        check_hello_members(&own, hello)
    }

    /// Spawn the accept loop, the UDP push loop and one control link per peer.
    /// Call after the member list and the TURN table exist.
    pub fn start(
        self: &Arc<Self>,
        turn: Weak<Turn>,
        context: Arc<ServerContext>,
        listener: TcpListener,
    ) {
        let _ = self.runtime.set(Runtime { turn, context });
        let cluster = self.clone();
        let accept = tokio::spawn(async move { cluster.accept_loop(listener).await });
        let cluster = self.clone();
        let push = tokio::spawn(async move { cluster.push_loop().await });
        lock_lock(&self.tasks).push(accept);
        lock_lock(&self.tasks).push(push);
        for member in self.members() {
            if member.id != self.config.instance_id {
                let _ = self.ensure_link(&member);
            }
        }
    }

    /// Stop every task (accept loop, links, UDP reader) and drop the listener.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        for task in lock_lock(&self.tasks).drain(..) {
            task.abort();
        }
    }

    // -- entry-side session registry -------------------------------------

    /// Register one accepted client connection and return its session id.
    pub fn register_session(self: &Arc<Self>, writer: mpsc::Sender<Vec<u8>>) -> u32 {
        let session = self.next_client_session.fetch_add(1, Ordering::Relaxed);
        let (close, _) = watch::channel(0_u8);
        lock_lock(&self.sessions).insert(session, SessionEntry { writer, close });
        session
    }

    pub fn unregister_session(&self, session: u32) {
        lock_lock(&self.sessions).remove(&session);
        lock_lock(&self.session_owners).remove(&session);
    }

    /// Remember which instance owns this session's allocation. Called when the
    /// entry forwards the request, i.e. before any `PUSH_CLIENT` can arrive.
    pub fn claim_session_owner(&self, session: u32, owner: &str) {
        let mut owners = lock_lock(&self.session_owners);
        match owners.get(&session) {
            Some(existing) if existing != owner => {
                tracing::warn!(
                    session,
                    existing = %existing,
                    claimed = %owner,
                    "rstun: TURN session claimed by a second owner"
                );
            }
            Some(_) => {}
            None => {
                owners.insert(session, owner.to_string());
            }
        }
    }

    /// Does `peer` own the allocation behind this entry-side session?
    fn session_owner_matches(&self, session: u32, peer: &str) -> bool {
        lock_lock(&self.session_owners)
            .get(&session)
            .is_some_and(|owner| owner == peer)
    }

    pub fn session_close(&self, session: u32) -> Option<watch::Receiver<u8>> {
        lock_lock(&self.sessions)
            .get(&session)
            .map(|entry| entry.close.subscribe())
    }

    /// Owner side: remember which allocation an entry's session created.
    pub fn remember_allocation(&self, entry: &str, session: u32, key: TurnKey) {
        lock_lock(&self.session_keys).insert((entry.to_string(), session), key);
    }

    pub fn take_allocation(&self, entry: &str, session: u32) -> Option<TurnKey> {
        lock_lock(&self.session_keys).remove(&(entry.to_string(), session))
    }

    /// Drop every piece of owner-side session state (allocation gone).
    pub fn forget_allocation(&self, entry: &str, session: u32) {
        let key = (entry.to_string(), session);
        lock_lock(&self.session_keys).remove(&key);
        lock_lock(&self.raw_in).remove(&key);
        lock_lock(&self.raw_connections).remove(&key);
    }

    pub fn member_by_id(&self, id: &str) -> Option<Member> {
        self.members().into_iter().find(|member| member.id == id)
    }

    // -- routing ---------------------------------------------------------

    fn ensure_link(self: &Arc<Self>, member: &Member) -> Option<mpsc::Sender<Vec<u8>>> {
        let mut links = lock_lock(&self.links);
        if let Some(sender) = links.get(&member.id) {
            return Some(sender.clone());
        }
        let (sender, receiver) = mpsc::channel(LINK_CAPACITY);
        let cluster = self.clone();
        let peer = member.clone();
        let id = member.id.clone();
        let task = tokio::spawn(async move { cluster.link_loop(peer, receiver).await });
        lock_lock(&self.tasks).push(task);
        links.insert(id, sender.clone());
        Some(sender)
    }

    /// Send one control `REQUEST` to `owner` and wait for its `RESPONSE`.
    /// `None` = the owner is unreachable or too slow; the caller answers `500`.
    pub async fn request(self: &Arc<Self>, owner: &Member, payload: Vec<u8>) -> Option<Reply> {
        let sender = self.ensure_link(owner)?;
        let session = self.next_session.fetch_add(1, Ordering::Relaxed);
        let (response_tx, response_rx) = oneshot::channel::<Reply>();
        lock_lock(&self.pending).insert(session, response_tx);
        let frame = encode_frame(
            FrameType::Request,
            session,
            &payload,
            self.config.secret.as_deref(),
        );
        if sender.send(frame).await.is_err() {
            lock_lock(&self.pending).remove(&session);
            return None;
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, response_rx).await {
            Ok(Ok(reply)) => Some(reply),
            _ => {
                lock_lock(&self.pending).remove(&session);
                None
            }
        }
    }

    /// Fire-and-forget data-plane push to the owner.
    pub async fn push_data(self: &Arc<Self>, owner: &Member, payload: &[u8]) {
        let frame = encode_frame(
            FrameType::PushData,
            0,
            payload,
            self.config.secret.as_deref(),
        );
        if let Err(error) = self.push.send_to(&frame, owner.addr).await {
            tracing::debug!(
                peer_instance = %owner.id,
                %error,
                "rstun: TURN cluster push could not be sent"
            );
        }
    }

    /// Owner → entry: bytes for one client connection's writer queue (M2).
    /// Bounded `try_send`, like the single-instance sink: overflow drops the
    /// datagram rather than growing memory.
    pub fn push_client(
        self: &Arc<Self>,
        owner_entry: &Member,
        session: u32,
        client: SocketAddr,
        payload: Vec<u8>,
    ) -> bool {
        let mut body = encode_endpoint(client);
        body.extend_from_slice(&payload);
        self.send_sync(owner_entry, FrameType::PushClient, session, &body)
    }

    /// Entry → owner: this client connection is gone; release its allocation.
    pub fn client_closed(self: &Arc<Self>, owner: &Member, session: u32) {
        self.send_sync(owner, FrameType::ClientClosed, session, &[]);
    }

    /// Either side: one raw relay direction ended (`kind` 0/1/2).
    pub fn raw_closed(self: &Arc<Self>, owner: &Member, session: u32, kind: u8) {
        self.send_sync(owner, FrameType::RawClosed, session, &[kind]);
    }

    /// Entry → owner: raw bytes for a bound RFC 6062 data connection.
    pub async fn send_raw(self: &Arc<Self>, owner: &Member, session: u32, bytes: &[u8]) -> bool {
        let Some(sender) = self.ensure_link(owner) else {
            return false;
        };
        sender
            .send(encode_frame(
                FrameType::RawRelay,
                session,
                bytes,
                self.config.secret.as_deref(),
            ))
            .await
            .is_ok()
    }

    /// Owner side: build the data-connection halves that speak `RAW_RELAY` to
    /// the entry instead of a local socket.
    pub fn open_raw(self: &Arc<Self>, entry: &Member, session: u32) -> RawConnection {
        let (in_tx, in_rx) = mpsc::channel(RAW_CAPACITY);
        let key: SessionKey = (entry.id.clone(), session);
        lock_lock(&self.raw_in).insert(key.clone(), in_tx);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(RAW_CAPACITY);
        let abort = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_abort = abort.clone();
        let cluster = self.clone();
        let entry = entry.clone();
        let writer_task = tokio::spawn(async move {
            let mut aborted = false;
            while let Some(bytes) = out_rx.recv().await {
                if !cluster.send_sync(&entry, FrameType::RawRelay, session, &bytes) {
                    // The control link could not take the bytes: the stream is
                    // no longer intact, so close instead of pretending EOF.
                    aborted = true;
                    break;
                }
            }
            // A clean peer EOF half-closes the client; a forced teardown
            // (allocation removed, error, overflow) closes it.
            let kind = if aborted || writer_abort.load(std::sync::atomic::Ordering::Relaxed) {
                RAW_CLOSE_ABORT
            } else {
                RAW_CLOSE_PEER_TO_CLIENT
            };
            cluster.raw_closed(&entry, session, kind);
            lock_lock(&cluster.raw_in).remove(&key);
        });
        RawConnection {
            reader: Box::new(ChannelReader::new(in_rx)),
            sender: out_tx,
            writer_task,
            abort,
        }
    }

    /// Remember which `CONNECTION-ID` a raw session bound (abort path).
    pub fn remember_raw_connection(&self, entry: &str, session: u32, id: u32) {
        lock_lock(&self.raw_connections).insert((entry.to_string(), session), id);
    }

    pub fn take_raw_connection(&self, entry: &str, session: u32) -> Option<u32> {
        lock_lock(&self.raw_connections).remove(&(entry.to_string(), session))
    }

    /// Enqueue one frame on the peer's control link without waiting. Used where
    /// the caller is synchronous (connection teardown) and best-effort is the
    /// same semantics as the single-instance bounded queue.
    fn send_sync(
        self: &Arc<Self>,
        member: &Member,
        kind: FrameType,
        session: u32,
        payload: &[u8],
    ) -> bool {
        let Some(sender) = self.ensure_link(member) else {
            return false;
        };
        sender
            .try_send(encode_frame(
                kind,
                session,
                payload,
                self.config.secret.as_deref(),
            ))
            .is_ok()
    }

    fn deliver_response(&self, session: u32, reply: Reply) {
        if let Some(sender) = lock_lock(&self.pending).remove(&session) {
            let _ = sender.send(reply);
        } else {
            tracing::debug!(
                session,
                "rstun: TURN cluster response for an unknown session"
            );
        }
    }

    // -- task bodies -----------------------------------------------------

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        let mut shutdown = self.shutdown.subscribe();
        loop {
            let accepted = tokio::select! {
                biased;
                _ = shutdown.changed() => return,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::debug!(%error, "rstun: TURN cluster accept failed");
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
            };
            let cluster = self.clone();
            // Connection tasks end with the shutdown signal; they are not
            // tracked individually (one per peer, plus reconnects).
            tokio::spawn(async move {
                if let Err(error) = cluster.serve_control(stream, peer).await {
                    tracing::debug!(%peer, %error, "rstun: TURN cluster connection closed");
                }
            });
        }
    }

    /// One accepted control connection: HELLO, then requests and responses.
    async fn serve_control(
        self: &Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> io::Result<()> {
        let _ = stream.set_nodelay(true);
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut frames = FrameReader::new();
        let mut chunk = vec![0_u8; READ_CHUNK];
        let mut shutdown = self.shutdown.subscribe();
        let mut peer_id: Option<String> = None;
        loop {
            let read = tokio::select! {
                biased;
                _ = shutdown.changed() => return Ok(()),
                read = frames.read_more(&mut reader, &mut chunk) => read,
            };
            if !read? {
                return Ok(());
            }
            loop {
                match frames.next(self.config.secret.as_deref()) {
                    Ok(Some(frame)) => {
                        if peer_id.is_none() {
                            // The first frame on a control connection must name
                            // the peer, and its ports must match ours.
                            if frame.kind != FrameType::Hello {
                                return Err(io::Error::other(
                                    "cluster control connection did not start with HELLO",
                                ));
                            }
                            let hello = Hello::decode(&frame.payload)
                                .ok_or_else(|| io::Error::other("malformed cluster HELLO"))?;
                            // Answer first: the dialer then diagnoses a port
                            // mismatch itself instead of just seeing EOF.
                            let reply = encode_frame(
                                FrameType::Hello,
                                frame.session,
                                &self.hello().encode(),
                                self.config.secret.as_deref(),
                            );
                            writer.write_all(&reply).await?;
                            self.verify_hello(&hello, None).map_err(io::Error::other)?;
                            peer_id = Some(hello.instance_id);
                            continue;
                        }
                        self.serve_inbound_frame(frame, &mut writer, peer_id.as_deref())
                            .await?;
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(%peer, ?error, "rstun: TURN cluster frame refused");
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn serve_inbound_frame<W>(
        self: &Arc<Self>,
        frame: Frame,
        writer: &mut W,
        peer_id: Option<&str>,
    ) -> io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        match frame.kind {
            FrameType::Request => {
                let reply = self.execute_request(&frame.payload, peer_id).await;
                match reply {
                    Reply::Response(bytes) => {
                        let frame = encode_frame(
                            FrameType::Response,
                            frame.session,
                            &bytes,
                            self.config.secret.as_deref(),
                        );
                        writer.write_all(&frame).await?;
                    }
                    Reply::Bound {
                        response,
                        id,
                        session,
                    } => {
                        // Header session = request correlation; payload prefix =
                        // the client connection the response is written to.
                        let mut body = Vec::with_capacity(4 + response.len());
                        body.extend_from_slice(&session.to_be_bytes());
                        body.extend_from_slice(&response);
                        let bound = encode_frame(
                            FrameType::Bound,
                            frame.session,
                            &body,
                            self.config.secret.as_deref(),
                        );
                        writer.write_all(&bound).await?;
                        // The response is on the wire: now the peer's bytes may
                        // flow without overtaking it.
                        self.start_raw(id, session, peer_id);
                    }
                }
            }
            FrameType::PushData => self.execute_push(&frame.payload).await,
            FrameType::Response => {
                self.deliver_response(frame.session, Reply::Response(frame.payload));
            }
            FrameType::Bound => self.deliver_bound(peer_id, frame.session, frame.payload),
            FrameType::PushClient => {
                self.deliver_push_client(peer_id, frame.session, &frame.payload)
            }
            FrameType::ClientClosed => {
                if let Some(peer) = peer_id {
                    self.execute_client_closed(peer, frame.session);
                }
            }
            FrameType::RawRelay => {
                let owner_key = peer_id.map(|peer| (peer.to_string(), frame.session));
                if owner_key
                    .as_ref()
                    .is_some_and(|key| lock_lock(&self.raw_in).contains_key(key))
                {
                    if let Some(key) = owner_key {
                        self.deliver_raw(key, frame.payload);
                    }
                } else if let Some(peer) = peer_id
                    && self.session_owner_matches(frame.session, peer)
                {
                    // This instance is the entry: the raw bytes belong to the
                    // client connection's writer queue (ordered after BOUND).
                    // A full queue would silently truncate a byte stream, so
                    // abort the relay instead (N2). Drop the sessions lock
                    // before signalling: both take it.
                    let overflow = {
                        let sessions = lock_lock(&self.sessions);
                        match sessions.get(&frame.session) {
                            Some(entry) => entry.writer.try_send(frame.payload).is_err(),
                            None => false,
                        }
                    };
                    if overflow {
                        tracing::warn!(
                            session = frame.session,
                            "rstun: TURN RAW_RELAY queue full, aborting the data connection"
                        );
                        self.signal_session_close(frame.session, RAW_CLOSE_ABORT);
                    }
                } else {
                    let owner = lock_lock(&self.session_owners).get(&frame.session).cloned();
                    match (peer_id, owner) {
                        (Some(peer), Some(owner)) => tracing::warn!(
                            session = frame.session,
                            from = %peer,
                            owner = %owner,
                            "rstun: TURN RAW_RELAY from an instance that does not own the session"
                        ),
                        (Some(peer), None) => tracing::warn!(
                            session = frame.session,
                            from = %peer,
                            "rstun: TURN RAW_RELAY for an unknown or expired session"
                        ),
                        (None, _) => tracing::warn!(
                            session = frame.session,
                            "rstun: TURN RAW_RELAY without a HELLO identity"
                        ),
                    }
                }
            }
            FrameType::RawClosed => {
                let kind = frame.payload.first().copied().unwrap_or(RAW_CLOSE_ABORT);
                let owner_key = peer_id.map(|peer| (peer.to_string(), frame.session));
                if owner_key
                    .as_ref()
                    .is_some_and(|key| lock_lock(&self.raw_in).contains_key(key))
                {
                    if let Some(key) = owner_key {
                        self.execute_raw_closed(key, kind);
                    }
                } else if let Some(peer) = peer_id
                    && self.session_owner_matches(frame.session, peer)
                {
                    // This instance is the entry for this session.
                    self.signal_session_close(frame.session, kind);
                } else {
                    tracing::warn!(
                        session = frame.session,
                        "rstun: TURN RAW_CLOSED from an instance that does not own the session"
                    );
                }
            }
            FrameType::Hello => {
                // A repeated HELLO after the handshake: answer it, it is inert.
                let reply = encode_frame(
                    FrameType::Hello,
                    frame.session,
                    &self.hello().encode(),
                    self.config.secret.as_deref(),
                );
                writer.write_all(&reply).await?;
            }
            FrameType::Ping => {
                let bytes = encode_frame(
                    FrameType::Pong,
                    frame.session,
                    &[],
                    self.config.secret.as_deref(),
                );
                writer.write_all(&bytes).await?;
            }
            FrameType::Pong => {}
        }
        Ok(())
    }

    async fn push_loop(self: Arc<Self>) {
        let mut buffer = vec![0_u8; 65535];
        let mut shutdown = self.shutdown.subscribe();
        loop {
            let received = tokio::select! {
                biased;
                _ = shutdown.changed() => return,
                received = self.push.recv_from(&mut buffer) => received,
            };
            let length = match received {
                Ok((length, _source)) => length,
                Err(error) => {
                    tracing::debug!(%error, "rstun: TURN cluster push recv failed");
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
            };
            match decode_datagram(&buffer[..length], self.config.secret.as_deref()) {
                Ok(frame) if frame.kind == FrameType::PushData => {
                    self.execute_push(&frame.payload).await;
                }
                Ok(frame) => {
                    tracing::debug!(kind = ?frame.kind, "rstun: TURN cluster unexpected datagram");
                }
                Err(error) => {
                    tracing::debug!(?error, "rstun: TURN cluster datagram refused");
                }
            }
        }
    }

    /// Outbound control link: dial, write queued frames, read responses,
    /// reconnect on failure. The queue survives reconnects; a frame that is
    /// lost mid-connection is detected by the request timeout.
    async fn link_loop(self: Arc<Self>, owner: Member, mut outgoing: mpsc::Receiver<Vec<u8>>) {
        let mut shutdown = self.shutdown.subscribe();
        loop {
            if *shutdown.borrow() {
                return;
            }
            let stream = match connect(&owner.addr).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(
                        peer_instance = %owner.id,
                        %error,
                        "rstun: TURN cluster link could not connect"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(RETRY_DELAY) => {}
                        _ = shutdown.changed() => return,
                    }
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let (mut reader, mut writer) = tokio::io::split(stream);
            let hello = encode_frame(
                FrameType::Hello,
                0,
                &self.hello().encode(),
                self.config.secret.as_deref(),
            );
            if writer.write_all(&hello).await.is_err() {
                break;
            }
            let mut hello_done = false;
            let mut frames = FrameReader::new();
            let mut chunk = vec![0_u8; READ_CHUNK];
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => return,
                    outgoing = outgoing.recv() => {
                        let Some(bytes) = outgoing else { return };
                        if writer.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    read = frames.read_more(&mut reader, &mut chunk) => {
                        match read {
                            Ok(true) => {}
                            Ok(false) | Err(_) => break,
                        }
                        loop {
                            match frames.next(self.config.secret.as_deref()) {
                                Ok(Some(frame)) => {
                                    if !hello_done {
                                        let hello = (frame.kind == FrameType::Hello)
                                            .then(|| Hello::decode(&frame.payload))
                                            .flatten();
                                        let Some(hello) = hello else {
                                            tracing::error!(peer_instance = %owner.id, "rstun: TURN cluster link did not start with HELLO");
                                            break;
                                        };
                                        if let Err(message) =
                                            self.verify_hello(&hello, Some(&owner.id))
                                        {
                                            tracing::error!(peer_instance = %owner.id, %message, "rstun: TURN cluster peer refused");
                                            break;
                                        }
                                        hello_done = true;
                                        continue;
                                    }
                                    if self
                                        .serve_inbound_frame(frame, &mut writer, Some(&owner.id))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(error) => {
                                    tracing::debug!(peer_instance = %owner.id, ?error, "rstun: TURN cluster frame refused");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            tracing::debug!(peer_instance = %owner.id, "rstun: TURN cluster link lost, reconnecting");
            tokio::select! {
                _ = tokio::time::sleep(RETRY_DELAY) => {}
                _ = shutdown.changed() => return,
            }
        }
    }

    // -- owner-side execution --------------------------------------------

    async fn execute_request(self: &Arc<Self>, payload: &[u8], peer_id: Option<&str>) -> Reply {
        let Some((session, client, transport, listen_port, datagram)) = decode_payload(payload)
        else {
            return Reply::Response(Vec::new());
        };
        let Some((turn, context)) = self.run_time() else {
            return Reply::Response(Vec::new());
        };
        let Some(peer_id) = (session == 0).then_some("").or(peer_id) else {
            return Reply::Response(Vec::new());
        };
        let remote = (session != 0).then(|| crate::turn::RemoteSink {
            peer: peer_id.to_string(),
            session,
        });
        let local = owner_local(&self.config, &context, transport.into(), listen_port);
        match turn
            .handle_as_owner(
                datagram,
                client,
                local,
                transport.into(),
                &context,
                None,
                remote.as_ref(),
            )
            .await
        {
            Some(Ok(Decision::Respond(bytes))) => Reply::Response(bytes),
            Some(Ok(Decision::Bind { response, id })) => {
                // The client connection lives on the entry. `serve_inbound_frame`
                // writes the BOUND frame first and then calls `start_raw`.
                if session == 0 || peer_id.is_empty() {
                    Reply::Response(response)
                } else {
                    Reply::Bound {
                        response,
                        id,
                        session,
                    }
                }
            }
            _ => Reply::Response(Vec::new()),
        }
    }

    async fn execute_push(&self, payload: &[u8]) {
        let Some((session, client, transport, listen_port, datagram)) = decode_payload(payload)
        else {
            return;
        };
        let Some((turn, context)) = self.run_time() else {
            return;
        };
        let local = owner_local(&self.config, &context, transport.into(), listen_port);
        let _ = turn
            .handle_as_owner(
                datagram,
                client,
                local,
                transport.into(),
                &context,
                None,
                None,
            )
            .await;
        let _ = session;
    }

    /// Entry side: queue the bind response into the connection's writer queue
    /// *before* any `RAW_RELAY` for the session is delivered, then tell the
    /// stream loop to switch to raw mode.
    fn deliver_bound(&self, peer: Option<&str>, correlation: u32, payload: Vec<u8>) {
        if payload.len() < 4 {
            return;
        }
        let session = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if let Some(peer) = peer
            && !self.session_owner_matches(session, peer)
        {
            tracing::warn!(
                session,
                from = %peer,
                "rstun: TURN BOUND from an instance that does not own the session"
            );
            return;
        }
        let response = payload[4..].to_vec();
        if let Some(entry) = lock_lock(&self.sessions).get(&session)
            && entry.writer.try_send(response).is_ok()
        {
            self.deliver_response(
                correlation,
                Reply::Bound {
                    response: Vec::new(),
                    id: 0,
                    session,
                },
            );
            return;
        }
        tracing::warn!(
            session,
            "rstun: TURN bound response could not be queued on the entry"
        );
        self.deliver_response(correlation, Reply::Response(Vec::new()));
    }

    /// Owner side, after the BOUND frame is written: hand the pending peer data
    /// connection raw halves that speak `RAW_RELAY` to the entry.
    fn start_raw(self: &Arc<Self>, id: u32, session: u32, peer_id: Option<&str>) {
        let Some((turn, _)) = self.run_time() else {
            return;
        };
        let Some(entry) = peer_id.and_then(|id| self.member_by_id(id)) else {
            return;
        };
        let Some(bind) = turn.take_bind(id) else {
            return;
        };
        let raw = self.open_raw(&entry, session);
        self.remember_raw_connection(&entry.id, session, id);
        let _ = bind.send(crate::turn::DataConnection {
            reader: raw.reader,
            sender: raw.sender,
            writer_task: raw.writer_task,
            _permit: None,
            abort: Some(raw.abort),
        });
    }

    fn deliver_push_client(&self, peer: Option<&str>, session: u32, payload: &[u8]) {
        let Some(peer) = peer else {
            return;
        };
        if !self.session_owner_matches(session, peer) {
            tracing::warn!(
                session,
                from = %peer,
                "rstun: TURN PUSH_CLIENT from an instance that does not own the session"
            );
            return;
        }
        let Some(bytes) = decode_push_client(payload) else {
            return;
        };
        if let Some(entry) = lock_lock(&self.sessions).get(&session) {
            let _ = entry.writer.try_send(bytes);
        } else {
            tracing::debug!(session, "rstun: TURN PUSH_CLIENT for an unknown session");
        }
    }

    fn execute_client_closed(&self, entry: &str, session: u32) {
        let Some(key) = self.take_allocation(entry, session) else {
            return;
        };
        if let Some((turn, _)) = self.run_time() {
            turn.remove_allocation(&key);
        }
        self.forget_allocation(entry, session);
        tracing::debug!(
            entry,
            session,
            "rstun: TURN client connection closed on its entry"
        );
    }

    fn deliver_raw(self: &Arc<Self>, key: SessionKey, payload: Vec<u8>) {
        // A raw byte stream cannot skip a chunk: a full inbound queue means the
        // data connection is not keeping up, so abort it instead of silently
        // truncating (N2).
        let overflow = {
            let raw_in = lock_lock(&self.raw_in);
            match raw_in.get(&key) {
                Some(sender) => sender.try_send(payload).is_err(),
                None => false,
            }
        };
        if overflow {
            tracing::warn!(
                session = key.1,
                "rstun: TURN inbound RAW_RELAY queue full, aborting the data connection"
            );
            self.execute_raw_closed(key.clone(), RAW_CLOSE_ABORT);
            if let Some(entry) = self.member_by_id(&key.0) {
                self.raw_closed(&entry, key.1, RAW_CLOSE_ABORT);
            }
        }
    }

    fn execute_raw_closed(&self, key: SessionKey, kind: u8) {
        match kind {
            RAW_CLOSE_CLIENT_TO_PEER => {
                lock_lock(&self.raw_in).remove(&key);
            }
            RAW_CLOSE_ABORT => {
                lock_lock(&self.raw_in).remove(&key);
                if let Some(id) = self.take_raw_connection(&key.0, key.1)
                    && let Some((turn, _)) = self.run_time()
                {
                    turn.stop_connection(id);
                }
            }
            _ => {}
        }
    }

    fn signal_session_close(&self, session: u32, kind: u8) {
        if let Some(entry) = lock_lock(&self.sessions).get(&session) {
            // `send` fails when nobody subscribed yet (the raw loop may not have
            // started); the value must still be recorded so a later subscriber
            // sees it.
            entry.close.send_replace(kind);
        }
    }

    fn run_time(&self) -> Option<(Arc<Turn>, Arc<ServerContext>)> {
        let runtime = self.runtime.get()?;
        let turn = runtime.turn.upgrade()?;
        Some((turn, runtime.context.clone()))
    }
}

/// The local address a forwarded request arrived "on": the owner's own bound
/// socket with the same port (the key only keeps the port). A request whose
/// port this instance does not serve falls back to the wildcard, which makes
/// `socket_for` fail loudly instead of binding a relay on the wrong address.
/// The local address a forwarded request arrived "on", resolved **per
/// transport** (S1): plain TCP shares the UDP bind table, TLS and DTLS have
/// their own listener lists. Falling back to `0.0.0.0:<port>` would make
/// `egress_ip` guess the host's primary address, so two instances on the same
/// host (C2) could both bind the relay on the same IP.
fn owner_local(
    config: &Config,
    context: &ServerContext,
    transport: ClientTransport,
    listen_port: u16,
) -> SocketAddr {
    let candidates = |addresses: &[SocketAddr]| {
        addresses
            .iter()
            .find(|address| address.port() == listen_port)
            .copied()
    };
    let found = match transport {
        ClientTransport::Udp => context
            .udp
            .iter()
            .find(|(bound, _)| bound.port() == listen_port)
            .map(|(bound, _)| *bound),
        ClientTransport::Tcp => context
            .udp
            .iter()
            .find(|(bound, _)| bound.port() == listen_port)
            .map(|(bound, _)| *bound)
            .or_else(|| candidates(&config.tls_listen)),
        ClientTransport::Dtls => candidates(&config.dtls_listen),
    };
    found.unwrap_or_else(|| normalized_server(listen_port))
}

/// Why a startup `HELLO` exchange did not complete.
enum HelloError {
    /// The peer could not be reached / did not answer: a warning, not a
    /// configuration error (requests to it will answer `500`).
    Unreachable(String),
    /// The peer answered with a mismatched configuration: refuse to start.
    Invalid(String),
}

/// Send our `HELLO` on a freshly dialled connection and validate the reply.
/// Used by the startup preflight; the long-lived link repeats the exchange.
async fn exchange_hello(
    address: &SocketAddr,
    own: &Hello,
    secret: Option<&[u8]>,
    cluster: &Cluster,
) -> Result<Hello, HelloError> {
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| HelloError::Unreachable(format!("{address}: {error}")))?;
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = tokio::io::split(stream);
    writer
        .write_all(&encode_frame(FrameType::Hello, 0, &own.encode(), secret))
        .await
        .map_err(|error| HelloError::Unreachable(format!("HELLO write failed: {error}")))?;
    let mut frames = FrameReader::new();
    let mut chunk = vec![0_u8; READ_CHUNK];
    loop {
        if !frames
            .read_more(&mut reader, &mut chunk)
            .await
            .map_err(|error| HelloError::Unreachable(format!("HELLO read failed: {error}")))?
        {
            return Err(HelloError::Unreachable(
                "peer closed the connection before answering HELLO".to_string(),
            ));
        }
        match frames.next(secret) {
            Ok(Some(frame)) => {
                if frame.kind != FrameType::Hello {
                    return Err(HelloError::Invalid(
                        "peer answered the HELLO with a non-HELLO frame".to_string(),
                    ));
                }
                let hello = Hello::decode(&frame.payload).ok_or_else(|| {
                    HelloError::Invalid("peer sent a malformed HELLO".to_string())
                })?;
                cluster
                    .verify_hello(&hello, None)
                    .map_err(HelloError::Invalid)?;
                return Ok(hello);
            }
            Ok(None) => continue,
            Err(error) => {
                return Err(HelloError::Invalid(format!(
                    "HELLO frame refused: {error:?}"
                )));
            }
        }
    }
}

async fn connect(address: &SocketAddr) -> io::Result<TcpStream> {
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "cluster connect timed out"))?
}

fn lock_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
fn lock_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|error| error.into_inner())
}

fn lock_lock<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
mod tests;
