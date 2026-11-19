//! Minimal RFC 5389 wire codec for a Binding-only STUN server.
//!
//! The upstream project this crate was extracted from already owns a STUN
//! attribute codec for its own NAT probing, but its responder only answers the
//! fork-internal transaction-id convention (`0xdeadbeef…`) and is built on
//! `stun_codec`/`bytecodec`. A public-facing Binding server has to answer *any*
//! transaction id and needs byte-exact control over what it emits, so this
//! module parses and builds the few messages it needs by hand — which also
//! keeps this crate free of any kernel dependency (see `Cargo.toml`).
//!
//! Every STUN message starts with a 20-byte header:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0|     Message Type          |         Message Length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Magic Cookie                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Transaction ID (96 bits)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `Message Length` counts the attributes only (never the header) and must be
//! a multiple of 4. Each attribute is `type (2) | length (2) | value`, with the
//! value zero-padded up to a 4-byte boundary while `length` keeps the *unpadded*
//! size. `XOR-MAPPED-ADDRESS` (RFC 5389 §15.2) then XORs the port with the top
//! half of the magic cookie and the address with the cookie (IPv4) or with
//! `cookie || transaction id` (IPv6).
//!
//! RFC 5780 (NAT behaviour discovery) adds four attributes here, none of them
//! XOR-obfuscated: `CHANGE-REQUEST` (§7.2, request side), `RESPONSE-PORT`
//! (§7.5, request side) plus `RESPONSE-ORIGIN` (§7.3) and `OTHER-ADDRESS`
//! (§7.4) on the response side. The address pair uses the plain RFC 5389 §15.1
//! layout — `0 | family | port | address` — which is also what the kernel's own
//! STUN codec (`stun_codec::net::SocketAddrEncoder`) emits, so a client reading
//! our response with the kernel's codec sees exactly the same bytes. `PADDING`
//! (§7.6) is echoed back at the same length, so an MTU / fragmentation probe gets
//! an equally large answer; §6's "pad the answer up to the egress MTU" SHOULD is
//! deliberately not implemented (see `rstun/README.md`, "有意偏离").
//!
//! Two attributes exist purely for compliance and compatibility:
//!
//! * `MAPPED-ADDRESS` (RFC 5389 §15.1) — the pre-XOR form of the client address,
//!   still read by RFC 3489-era clients. Off by default (`--mapped-address`),
//!   because it only duplicates `XOR-MAPPED-ADDRESS` for anything modern.
//! * `UNKNOWN-ATTRIBUTES` (RFC 5389 §15.9) — the list that accompanies a
//!   `420 Unknown Attribute` response. Without it, a request carrying an
//!   attribute this server does not implement (RFC 5389 §7.3.1 says it must be
//!   rejected, not partially answered) produces a response the client cannot
//!   act on. §15.9 keeps the list strictly `2 × N` bytes and defers alignment to
//!   the generic TLV padding ("In this version of the specification, the normal
//!   padding rules for attributes are used instead" of RFC 3489's duplication).
//!
//! Two more error paths complete the server side of RFC 5389:
//!
//! * `300 Try Alternate` + `ALTERNATE-SERVER` (RFC 5389 §15.11) — only when
//!   `--alternate-server` names another instance. The address attribute uses the
//!   same plain `0 | family | port | address` layout as `MAPPED-ADDRESS`.
//! * `500 Server Error` (§15.6) — for failures that are *ours* (a send that
//!   cannot be retried, an internal invariant), never for a bad request. The
//!   reason text is a fixed `Server Error`, so no `io::Error` detail leaks and
//!   the message stays 40 bytes (it cannot become an amplifier).
//!
//! `FINGERPRINT` (§15.5) is validated on request with [`check_fingerprint`]:
//! the attribute must be *last* and its value must be `CRC32(prefix) XOR
//! 0x5354554e`, where the prefix is the message **as sent** minus the attribute —
//! the header `Length` already counts the attribute, as §15.5 requires. The
//! `crate::crc32` module provides the IEEE CRC-32 (RFC 5769's vectors lock it).

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::crc32::crc32;

/// `0x2112A442`, fixed by RFC 5389 §6.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Size of the fixed STUN header in bytes.
pub const HEADER_LEN: usize = 20;
/// Message type of a Binding request.
pub const BINDING_REQUEST: u16 = 0x0001;
/// Message type of a Binding success response.
pub const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
/// Message type of a Binding error response.
pub const BINDING_ERROR_RESPONSE: u16 = 0x0111;
/// `XOR-MAPPED-ADDRESS` (RFC 5389 §15.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// `MAPPED-ADDRESS` (RFC 5389 §15.1): the pre-XOR form, `--mapped-address` only.
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// `ERROR-CODE` (RFC 5389 §15.6).
pub const ATTR_ERROR_CODE: u16 = 0x0009;
/// `UNKNOWN-ATTRIBUTES` (RFC 5389 §15.9): only ever next to a `420`.
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000a;
/// `CHANGE-REQUEST` (RFC 5780 §7.2), only meaningful on a Binding *request*.
pub const ATTR_CHANGE_REQUEST: u16 = 0x0003;
/// `PADDING` (RFC 5780 §7.6): free-form filler used to probe MTU / fragmentation.
pub const ATTR_PADDING: u16 = 0x0026;
/// `RESPONSE-PORT` (RFC 5780 §7.5): the **destination** port of the answer.
///
/// §7.5: "the Binding Response MUST be transmitted to the source IP address of
/// the Binding Request and the port contained in RESPONSE-PORT". It is a
/// destination, never a source: the reply still leaves from the socket the
/// request arrived on, so any 16-bit port is acceptable here and the port does
/// not have to be bound by this process.
pub const ATTR_RESPONSE_PORT: u16 = 0x0027;
/// `USERNAME` (RFC 5389 §15.3): authentication attribute, not implemented here.
pub const ATTR_USERNAME: u16 = 0x0006;
/// `MESSAGE-INTEGRITY` (RFC 5389 §15.4): authentication attribute.
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
/// `MESSAGE-INTEGRITY-SHA256` (RFC 8489 §14.6): authentication attribute.
pub const ATTR_MESSAGE_INTEGRITY_SHA256: u16 = 0x001c;
/// `REALM` (RFC 5389 §15.7): authentication attribute.
pub const ATTR_REALM: u16 = 0x0014;
/// `NONCE` (RFC 5389 §15.8): authentication attribute.
pub const ATTR_NONCE: u16 = 0x0015;
/// `PASSWORD-ALGORITHM` (RFC 8489 §14.12): authentication attribute.
pub const ATTR_PASSWORD_ALGORITHM: u16 = 0x001d;
/// `USERHASH` (RFC 8489 §14.13): authentication attribute.
pub const ATTR_USERHASH: u16 = 0x001e;
/// `PRIORITY` (RFC 8445 §16.1): carried by every ICE connectivity check.
pub const ATTR_PRIORITY: u16 = 0x0024;
/// `USE-CANDIDATE` (RFC 8445 §16.2): ICE nomination flag.
pub const ATTR_USE_CANDIDATE: u16 = 0x0025;
/// `SOFTWARE` (RFC 5389 §15.10).
pub const ATTR_SOFTWARE: u16 = 0x8022;
/// `ALTERNATE-SERVER` (RFC 5389 §15.11).
pub const ATTR_ALTERNATE_SERVER: u16 = 0x8023;
/// `FINGERPRINT` (RFC 5389 §15.5).
pub const ATTR_FINGERPRINT: u16 = 0x8028;
/// `ICE-CONTROLLED` (RFC 8445 §16.3).
pub const ATTR_ICE_CONTROLLED: u16 = 0x8029;
/// `ICE-CONTROLLING` (RFC 8445 §16.4).
pub const ATTR_ICE_CONTROLLING: u16 = 0x802a;
/// `RESPONSE-ORIGIN` (RFC 5780 §7.3): the address this response leaves from.
pub const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;
/// `OTHER-ADDRESS` (RFC 5780 §7.4): the other IP *and* other port to probe next.
pub const ATTR_OTHER_ADDRESS: u16 = 0x802c;
/// `400 Bad Request`, for a request whose method this server does not implement.
pub const ERROR_BAD_REQUEST: u16 = 400;
/// `300 Try Alternate` (RFC 5389 §15.6, used with `ALTERNATE-SERVER` §15.11):
/// "use the server in this attribute instead".
pub const ERROR_TRY_ALTERNATE: u16 = 300;
/// `420 Unknown Attribute` (RFC 5389 §7.3.1 / §15.9): a request carried at least
/// one comprehension-required attribute this server does not implement.
pub const ERROR_UNKNOWN_ATTRIBUTE: u16 = 420;
/// `500 Server Error` (RFC 5389 §15.6): a failure on our side, never a client
/// error. The reason text is always the fixed `Server Error`.
pub const ERROR_SERVER_ERROR: u16 = 500;
/// XOR applied to the CRC-32 of a message to form `FINGERPRINT` (RFC 5389 §15.5).
pub const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// `CHANGE-REQUEST` bit: answer from the other IP (RFC 5780 §7.2, bit `A`).
///
/// Use `0x04`/`0x02`, not the `0x02`/`0x01` some older codecs decoded (RFC 3489
/// minus one bit position): coturn, pion/stun and RFC 5780 §7.2 all agree on
/// `0x04`/`0x02`, and that is what a real client asserts on — a reference
/// library that disagrees is the one that is wrong.
pub const CHANGE_IP: u32 = 0x04;
/// `CHANGE-REQUEST` bit: answer from the other port (RFC 5780 §7.2, bit `B`).
pub const CHANGE_PORT: u32 = 0x02;

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
/// Size of the `CHANGE-REQUEST` value: 32 flag bits, nothing else.
const CHANGE_REQUEST_LEN: usize = 4;

/// STUN message classes (RFC 5389 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

/// Class encoded in the message type's C1/C0 bits.
pub const fn message_class(msg_type: u16) -> MessageClass {
    let class = ((msg_type >> 7) & 0x0002) | ((msg_type >> 4) & 0x0001);
    match class {
        0 => MessageClass::Request,
        1 => MessageClass::Indication,
        2 => MessageClass::SuccessResponse,
        _ => MessageClass::ErrorResponse,
    }
}

/// Method encoded in the message type's M11..M0 bits.
pub const fn message_method(msg_type: u16) -> u16 {
    (msg_type & 0x000F) | ((msg_type >> 1) & 0x0070) | ((msg_type >> 2) & 0x0F80)
}

/// Inverse of [`message_class`] / [`message_method`]: assemble a message type.
pub const fn message_type(method: u16, class: MessageClass) -> u16 {
    let class_bits: u16 = match class {
        MessageClass::Request => 0b00,
        MessageClass::Indication => 0b01,
        MessageClass::SuccessResponse => 0b10,
        MessageClass::ErrorResponse => 0b11,
    };
    (method & 0x000F)
        | ((method & 0x0070) << 1)
        | ((method & 0x0F80) << 2)
        | ((class_bits & 0b10) << 7)
        | ((class_bits & 0b01) << 4)
}

/// The 96-bit transaction id that ties a response to its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId(pub [u8; 12]);

impl TransactionId {
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Why a datagram / stream frame is not a usable STUN message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer bytes than the header (or than the header promises).
    Truncated { have: usize, need: usize },
    /// The leading two bits are not zero, so this is not STUN at all.
    NotStun,
    /// The magic cookie is missing (or this is a pre-RFC 5389 message).
    BadCookie,
    /// `Message Length` is not a multiple of 4.
    UnalignedLength(usize),
    /// An attribute header or value runs past the end of the message body.
    AttributeOverrun {
        offset: usize,
        length: usize,
        body_len: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { have, need } => {
                write!(f, "truncated STUN message: {have} of {need} bytes")
            }
            Self::NotStun => f.write_str("not STUN: the leading two bits are set"),
            Self::BadCookie => f.write_str("bad STUN magic cookie"),
            Self::UnalignedLength(length) => {
                write!(f, "STUN message length {length} is not a multiple of 4")
            }
            Self::AttributeOverrun {
                offset,
                length,
                body_len,
            } => write!(
                f,
                "STUN attribute at offset {offset} (length {length}) overruns the {body_len}-byte body"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// A structurally validated STUN message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub msg_type: u16,
    pub transaction_id: TransactionId,
    /// Attributes, already validated: walking them cannot run past the end.
    pub body: &'a [u8],
}

/// One parsed attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub attr_type: u16,
    /// Value without the zero padding that follows it.
    pub value: &'a [u8],
}

/// Learn how many bytes one frame occupies, from its header alone.
///
/// Needed to frame STUN over TCP (RFC 5389 §7.2.2): the header carries the
/// attribute length, so the next frame starts at `20 + length`.
pub fn peek_frame_len(bytes: &[u8]) -> Result<usize, ParseError> {
    if bytes.len() < HEADER_LEN {
        return Err(ParseError::Truncated {
            have: bytes.len(),
            need: HEADER_LEN,
        });
    }
    if bytes[0] & 0xC0 != 0 {
        return Err(ParseError::NotStun);
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(ParseError::BadCookie);
    }
    let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if !length.is_multiple_of(4) {
        return Err(ParseError::UnalignedLength(length));
    }
    Ok(HEADER_LEN + length)
}

/// Validate and split off one STUN message.
///
/// Trailing bytes after the declared frame are ignored (a caller carrying the
/// frame length from [`peek_frame_len`] is expected to pass exactly one frame).
pub fn parse(bytes: &[u8]) -> Result<Message<'_>, ParseError> {
    let frame_len = peek_frame_len(bytes)?;
    if bytes.len() < frame_len {
        return Err(ParseError::Truncated {
            have: bytes.len(),
            need: frame_len,
        });
    }

    let mut transaction_id = [0_u8; 12];
    transaction_id.copy_from_slice(&bytes[8..HEADER_LEN]);
    let body = &bytes[HEADER_LEN..frame_len];
    validate_attributes(body)?;

    Ok(Message {
        msg_type: u16::from_be_bytes([bytes[0], bytes[1]]),
        transaction_id: TransactionId(transaction_id),
        body,
    })
}

/// Walk the attribute list of a message body, rejecting any overrun.
fn validate_attributes(body: &[u8]) -> Result<(), ParseError> {
    let mut offset = 0;
    while offset < body.len() {
        if body.len() - offset < 4 {
            return Err(ParseError::AttributeOverrun {
                offset,
                length: 0,
                body_len: body.len(),
            });
        }
        let length = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        // The value itself and its zero padding both have to stay inside the body.
        let value_end = offset + 4 + length;
        let padded_end = offset + 4 + length.div_ceil(4) * 4;
        if value_end > body.len() || padded_end > body.len() {
            return Err(ParseError::AttributeOverrun {
                offset,
                length,
                body_len: body.len(),
            });
        }
        offset = padded_end;
    }
    Ok(())
}

/// Iterate the attributes of a body that [`parse`] already validated.
///
/// Stops at the first attribute that would overrun the body, so this is safe on
/// arbitrary input even though strict callers should prefer [`parse`].
pub fn attributes(body: &[u8]) -> Attributes<'_> {
    Attributes { body, offset: 0 }
}

/// Iterator returned by [`attributes`].
#[derive(Debug, Clone)]
pub struct Attributes<'a> {
    body: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Attribute<'a>;

    fn next(&mut self) -> Option<Attribute<'a>> {
        let remaining = self.body.len().checked_sub(self.offset)?;
        if remaining < 4 {
            return None;
        }
        let header = &self.body[self.offset..self.offset + 4];
        let attr_type = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let value_start = self.offset + 4;
        let value_end = value_start.checked_add(length)?;
        let value = self.body.get(value_start..value_end)?;
        self.offset = value_start + length.div_ceil(4) * 4;
        Some(Attribute { attr_type, value })
    }
}

/// Is `attr_type` in the comprehension-required range (RFC 5389 §18.1)?
///
/// The bit is the top one of the 16-bit type: `0x0000-0x7FFF` means "a server
/// that does not understand this attribute MUST reject the request" (`420`),
/// `0x8000-0xFFFF` means "ignore it and carry on".
pub const fn is_comprehension_required(attr_type: u16) -> bool {
    attr_type < 0x8000
}

/// Every attribute this server either implements or deliberately tolerates.
///
/// This table is the **only** input to the 420 decision ([`unknown_attributes`]),
/// so it is an exhaustive `match` with one line per type instead of a range
/// heuristic: a missing entry turns into a `420`, and a spurious `420` is
/// indistinguishable from "the server is broken" to a real client.
///
/// Three groups:
///
/// * **Implemented / emitted**: `XOR-MAPPED-ADDRESS`, `MAPPED-ADDRESS`,
///   `ERROR-CODE`, `UNKNOWN-ATTRIBUTES`, `SOFTWARE`, plus the RFC 5780 set
///   `CHANGE-REQUEST` / `RESPONSE-PORT` / `PADDING` / `RESPONSE-ORIGIN` /
///   `OTHER-ADDRESS`.
/// * **Understood, intentionally unused — authentication**: a server without
///   authentication must still *ignore* `USERNAME` / `MESSAGE-INTEGRITY` /
///   `MESSAGE-INTEGRITY-SHA256` / `REALM` / `NONCE` / `PASSWORD-ALGORITHM` /
///   `USERHASH`. RFC 5389 §10.2.2 lets a client send them unprompted (and
///   RFC 3489-era clients do), so rejecting them would lock those clients out.
/// * **Understood, intentionally unused — ICE**: ICE connectivity checks are
///   Binding requests carrying `PRIORITY` and `USE-CANDIDATE` (RFC 8445
///   §16.1/§16.2) and often `ICE-CONTROLLING` / `ICE-CONTROLLED`. A `420` here
///   would break hole punching on every ICE client that probes us.
///
/// The `0x8000`+ entries can never trigger a `420` (see
/// [`is_comprehension_required`]); they are listed anyway so this stays the
/// single source of truth for "what this server recognizes".
pub const fn is_known_attribute(attr_type: u16) -> bool {
    matches!(
        attr_type,
        ATTR_MAPPED_ADDRESS
            | ATTR_CHANGE_REQUEST
            | ATTR_USERNAME
            | ATTR_MESSAGE_INTEGRITY
            | ATTR_ERROR_CODE
            | ATTR_UNKNOWN_ATTRIBUTES
            | ATTR_REALM
            | ATTR_NONCE
            | ATTR_MESSAGE_INTEGRITY_SHA256
            | ATTR_PASSWORD_ALGORITHM
            | ATTR_USERHASH
            | ATTR_XOR_MAPPED_ADDRESS
            | ATTR_PRIORITY
            | ATTR_USE_CANDIDATE
            | ATTR_PADDING
            | ATTR_RESPONSE_PORT
            | ATTR_SOFTWARE
            | ATTR_ALTERNATE_SERVER
            | ATTR_FINGERPRINT
            | ATTR_ICE_CONTROLLED
            | ATTR_ICE_CONTROLLING
            | ATTR_RESPONSE_ORIGIN
            | ATTR_OTHER_ADDRESS
    )
}

/// The unknown comprehension-required attribute types of a request, in
/// first-seen order and without repeats (RFC 5389 §7.3.1).
///
/// An empty result means "process this request normally". Anything else must be
/// answered with [`unknown_attributes_response`]; the list in the response is
/// exactly this vector (RFC 5389 §15.9), so a client learns which attribute to
/// stop sending.
pub fn unknown_attributes(body: &[u8]) -> Vec<u16> {
    let mut unknown: Vec<u16> = Vec::new();
    for attribute in attributes(body) {
        if is_comprehension_required(attribute.attr_type)
            && !is_known_attribute(attribute.attr_type)
            && !unknown.contains(&attribute.attr_type)
        {
            unknown.push(attribute.attr_type);
        }
    }
    unknown
}

/// How many value bytes of `PADDING` a request carries (RFC 5780 §7.6).
///
/// The bytes themselves are free-form filler: only the *length* matters, because
/// the attribute exists to push a datagram past the path MTU and the answer has
/// to be equally large for the probe to mean anything.
pub fn padding_len(body: &[u8]) -> Option<u16> {
    attributes(body)
        .find(|attribute| attribute.attr_type == ATTR_PADDING)
        // The wire length is a u16, so this cannot truncate.
        .map(|attribute| attribute.value.len() as u16)
}

/// The **destination** port a client asked the answer to be delivered to
/// (RFC 5780 §7.5).
///
/// The attribute is a 16-bit port followed by two padding bytes; we accept any
/// value of at least two bytes and ignore a shorter one — a malformed
/// `RESPONSE-PORT` must not turn a good Binding request into an error, the same
/// rule [`change_request`] follows.
///
/// No validation of the port is done here or by the caller: §7.5 makes the
/// attribute a destination, so `0` (and any other unbound port) is passed
/// through and left for the kernel to reject. This function only decodes.
pub fn response_port(body: &[u8]) -> Option<u16> {
    let value = attributes(body)
        .find(|attribute| attribute.attr_type == ATTR_RESPONSE_PORT)?
        .value;
    let port: [u8; 2] = value.get(..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(port))
}

/// A parsed `CHANGE-REQUEST`: which of the two axes the client wants flipped.
///
/// `CHANGE-REQUEST` is a *request* attribute; a server ignores it on indications
/// and responses, and over TCP (a response can only come back on the connection
/// it arrived on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChangeRequest {
    /// Answer from the other IP.
    pub change_ip: bool,
    /// Answer from the other port.
    pub change_port: bool,
}

impl ChangeRequest {
    /// `true` when at least one axis was requested.
    pub const fn any(&self) -> bool {
        self.change_ip || self.change_port
    }
}

/// Find and parse the `CHANGE-REQUEST` attribute of a request body.
///
/// Returns `None` when the attribute is absent, or when its value is not the
/// 4 bytes RFC 5780 §7.2 mandates — an unparseable `CHANGE-REQUEST` must not
/// turn a perfectly good Binding request into an error, so it simply means "the
/// client asked for nothing unusual". Unknown flag bits (including the reserved
/// low half) are ignored for the same reason: only `A` (`0x04`) and `B` (`0x02`)
/// are meaningful, and a future extension must not break a Binding probe.
pub fn change_request(body: &[u8]) -> Option<ChangeRequest> {
    let value = attributes(body)
        .find(|attribute| attribute.attr_type == ATTR_CHANGE_REQUEST)?
        .value;
    let flags: [u8; CHANGE_REQUEST_LEN] = value.get(..CHANGE_REQUEST_LEN)?.try_into().ok()?;
    let flags = u32::from_be_bytes(flags);
    Some(ChangeRequest {
        change_ip: flags & CHANGE_IP != 0,
        change_port: flags & CHANGE_PORT != 0,
    })
}

/// The two RFC 5780 address attributes carried by a Binding response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseAddresses {
    /// Where this response is sent from: the socket that answers.
    pub origin: SocketAddr,
    /// The other IP *and* other port the client may probe next.
    pub other: SocketAddr,
}

/// Everything a `Binding Success Response` is built from.
///
/// A struct instead of a growing argument list because the two optional
/// additions (`--mapped-address`, echoed `PADDING`) are easy to swap by
/// accident — and both must default to *no change at all* in the emitted bytes,
/// which a test locks down byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuccessResponse<'a> {
    pub transaction_id: &'a TransactionId,
    /// The client's address, as this server sees it.
    pub peer: SocketAddr,
    /// Emitted as `SOFTWARE` when non-empty.
    pub software: &'a str,
    /// The RFC 5780 §7.3 / §7.4 pair; present only with `--alt-listen`.
    pub addresses: Option<ResponseAddresses>,
    /// Also emit `MAPPED-ADDRESS` (RFC 5389 §15.1) next to `XOR-MAPPED-ADDRESS`.
    pub mapped_address: bool,
    /// Echo `PADDING` (RFC 5780 §7.6) with this many value bytes.
    pub padding: Option<u16>,
}

/// Serialize a `Binding Success Response` carrying `XOR-MAPPED-ADDRESS`,
/// optionally `MAPPED-ADDRESS`, the RFC 5780 `RESPONSE-ORIGIN` +
/// `OTHER-ADDRESS` pair, echoed `PADDING`, and `SOFTWARE` when a non-empty name
/// is given.
///
/// Attribute order: `XOR-MAPPED-ADDRESS` is always first (every client reads
/// it), `PADDING` is always last (RFC 5780 §7.6 filler, so nothing can be
/// mistaken for a payload), and `SOFTWARE` sits before it.
pub fn binding_success_response(response: &SuccessResponse<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(if response.addresses.is_some() { 64 } else { 32 });
    push_attribute(
        &mut body,
        ATTR_XOR_MAPPED_ADDRESS,
        &xor_mapped_address_value(response.peer, response.transaction_id),
    );
    if response.mapped_address {
        // RFC 5389 §15.1: same `0 | family | port | address` layout as
        // RESPONSE-ORIGIN, just for the client instead of for us — and
        // deliberately **not** XOR-obfuscated.
        push_attribute(
            &mut body,
            ATTR_MAPPED_ADDRESS,
            &address_value(response.peer),
        );
    }
    if let Some(addresses) = response.addresses {
        // Not XOR-obfuscated: RFC 5780 §7.3/§7.4 reuse the plain RFC 5389
        // §15.1 address layout (the same one `ALTERNATE-SERVER` uses).
        push_attribute(
            &mut body,
            ATTR_RESPONSE_ORIGIN,
            &address_value(addresses.origin),
        );
        push_attribute(
            &mut body,
            ATTR_OTHER_ADDRESS,
            &address_value(addresses.other),
        );
    }
    if !response.software.is_empty() {
        push_attribute(&mut body, ATTR_SOFTWARE, response.software.as_bytes());
    }
    if let Some(padding) = response.padding {
        // RFC 5780 §7.6: PADDING is "entirely a free-form string, the value of
        // which does not matter" — zeros are as good as anything, and they keep
        // the padding visibly distinct from a payload.
        //
        // Two hard limits on the echo, both about not becoming a reflector:
        // never longer than the client asked for, and never so long that the
        // 16-bit Message Length would overflow.
        // Keep the 4-byte attribute alignment in mind: rounding the room *down*
        // to a multiple of 4 means the padded attribute still fits.
        let room = usize::from(u16::MAX).saturating_sub(body.len() + 4) & !3;
        let length = usize::from(padding).min(room);
        push_attribute(&mut body, ATTR_PADDING, &vec![0_u8; length]);
    }
    encode_message(BINDING_SUCCESS_RESPONSE, response.transaction_id, &body)
}

/// Serialize an error response for `method` with an `ERROR-CODE` attribute.
///
/// The response type keeps the request's method (RFC 5389 §7.3.1), so an
/// unsupported method gets *its own* error response rather than a Binding one.
pub fn error_response(
    transaction_id: &TransactionId,
    method: u16,
    code: u16,
    reason: &str,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + reason.len() + 3);
    push_attribute(&mut body, ATTR_ERROR_CODE, &error_code_value(code, reason));
    encode_message(
        message_type(method, MessageClass::ErrorResponse),
        transaction_id,
        &body,
    )
}

/// `<ERROR-CODE>` value: 2 reserved bytes, class digit, number digit, reason.
///
/// RFC 5389 §15.6 keeps the class/number split so a client can match on the
/// class alone; the class digit is `code / 100` for every code we emit
/// (`300` / `400` / `420` / `500`).
fn error_code_value(code: u16, reason: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + reason.len());
    value.extend_from_slice(&[0, 0, (code / 100) as u8, (code % 100) as u8]);
    value.extend_from_slice(reason.as_bytes());
    value
}

/// `300 Try Alternate` carrying `ALTERNATE-SERVER` (RFC 5389 §15.11).
///
/// The address attribute is the plain RFC 5389 §15.1 layout
/// (`0 | family | port | address`) — **not** XOR-obfuscated: §15.11 says
/// "the format of the ALTERNATE-SERVER attribute is identical to the
/// MAPPED-ADDRESS attribute" and only §15.2's XOR form is obfuscated.
///
/// Emitted by an instance configured with `--alternate-server`; the redirect
/// deliberately wins over RFC 5780 (a `CHANGE-REQUEST`/`RESPONSE-PORT` request
/// still gets this answer, from the socket that received it).
pub fn alternate_server_response(
    transaction_id: &TransactionId,
    method: u16,
    server: SocketAddr,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    push_attribute(
        &mut body,
        ATTR_ERROR_CODE,
        &error_code_value(ERROR_TRY_ALTERNATE, "Try Alternate"),
    );
    push_attribute(&mut body, ATTR_ALTERNATE_SERVER, &address_value(server));
    encode_message(
        message_type(method, MessageClass::ErrorResponse),
        transaction_id,
        &body,
    )
}

/// `500 Server Error` with the fixed `Server Error` reason (RFC 5389 §15.6).
///
/// The response is exactly **40 bytes** (20-byte header + 20-byte `ERROR-CODE`:
/// 4 value bytes + the 11-byte reason + 1 byte of TLV padding). A fixed reason
/// is the point: internal details (`io::Error`, paths, hostnames) go to the log
/// only, and the size cannot grow with them.
pub fn server_error_response(transaction_id: &TransactionId, method: u16) -> Vec<u8> {
    error_response(transaction_id, method, ERROR_SERVER_ERROR, "Server Error")
}

/// The value a `FINGERPRINT` attribute carries (RFC 5389 §15.5).
///
/// `frame_without_fingerprint` is the message **as sent**, minus the 8-byte
/// attribute: the header `Length` still counts the attribute (RFC 5389 §15.5:
/// "this value must be correct and include the CRC attribute as part of the
/// message length, prior to computation of the CRC"). That is what the RFC 5769
/// §2.1–§2.3 vectors encode, and what real clients compute — see
/// `crc32::tests::rfc5769_section_2_1_fingerprint_vector`.
///
/// Kept public for tests and the interop probe: an independent implementation
/// (python's `zlib.crc32`) can then be compared byte for byte instead of
/// trusting our own round trip.
pub fn fingerprint_value(frame_without_fingerprint: &[u8]) -> u32 {
    crc32(frame_without_fingerprint) ^ FINGERPRINT_XOR
}

/// What a message's `FINGERPRINT` attribute (if any) says about the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintVerdict {
    /// No `FINGERPRINT` attribute: nothing to check (the default path).
    Absent,
    /// Present as the last attribute, four bytes, CRC matches.
    Valid,
    /// Present, but at least one attribute follows it (or it is not 4 bytes).
    NotLast,
    /// Last and four bytes, but the CRC does not match.
    Mismatch,
}

/// Validate the `FINGERPRINT` attribute of one STUN frame (RFC 5389 §15.5).
///
/// The rule is deliberately *structural first*: the attribute has to be the last
/// one, and only then is the CRC compared. RFC 5389 §15.5 makes the position
/// part of the definition ("it MUST be the last attribute in the message"), so a
/// misplaced `FINGERPRINT` is [`FingerprintVerdict::NotLast`] even when the
/// four bytes would otherwise check out.
///
/// `frame` is one whole message (`HEADER_LEN + Message Length` bytes). Trailing
/// bytes are ignored, so a UDP datagram carrying extra junk is judged on its
/// declared frame — the same boundary [`parse`] uses.
pub fn check_fingerprint(frame: &[u8]) -> FingerprintVerdict {
    let Ok(frame_len) = peek_frame_len(frame) else {
        return FingerprintVerdict::Absent;
    };
    // `peek_frame_len` trusts the header's declared length; a truncated datagram
    // has no attributes to judge (and `parse` will reject it first), so do not
    // slice past the buffer here.
    let Some(frame) = frame.get(..frame_len) else {
        return FingerprintVerdict::Absent;
    };
    let body = &frame[HEADER_LEN..];

    let mut offset = 0;
    let mut fingerprint: Option<usize> = None;
    while offset + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
        if attr_type == ATTR_FINGERPRINT {
            if fingerprint.replace(offset).is_some() {
                // A second FINGERPRINT means the first one was not last.
                return FingerprintVerdict::NotLast;
            }
        } else if fingerprint.is_some() {
            return FingerprintVerdict::NotLast;
        }
        offset += 4 + length.div_ceil(4) * 4;
    }

    let Some(offset) = fingerprint else {
        return FingerprintVerdict::Absent;
    };
    let length = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
    let Some(value) = body.get(offset + 4..offset + 4 + length) else {
        return FingerprintVerdict::Mismatch;
    };
    // "MUST be the last attribute" also fixes the on-wire size at 8 bytes:
    // a FINGERPRINT of another length cannot be the one the sender computed.
    if offset + 8 != body.len() || value.len() != 4 {
        return FingerprintVerdict::NotLast;
    }

    // RFC 5389 §15.5: "the CRC used in the FINGERPRINT attribute covers the
    // length field from the STUN message header. Therefore, this value must be
    // correct and include the CRC attribute as part of the message length,
    // prior to computation of the CRC." So the prefix is the frame as sent, with
    // the header Length left alone — no rewriting (RFC 5769's vectors agree).
    let expected = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
    if fingerprint_value(&frame[..HEADER_LEN + offset]) == expected {
        FingerprintVerdict::Valid
    } else {
        FingerprintVerdict::Mismatch
    }
}

/// `420 Unknown Attribute` with the `UNKNOWN-ATTRIBUTES` list (RFC 5389 §7.3.1,
/// §15.9) — the answer to a Binding request carrying a comprehension-required
/// attribute this server does not implement.
///
/// The attribute value is exactly `2 × N` bytes, one 16-bit type per unknown
/// attribute. RFC 5389 §15.9 says so explicitly:
///
/// > Note: In [RFC3489], this field was padded to 32 by duplicating the last
/// > attribute.  In this version of the specification, the normal padding rules
/// > for attributes are used instead.
///
/// So when `2 × N` is not a multiple of 4 the generic TLV padding of §15 fills
/// the gap *outside* the value: it is not counted in the attribute `Length`
/// field and a decoder never sees it. The RFC 3489-era "repeat the last entry"
/// trick would make the list claim an attribute the client never sent, so it is
/// not used here — `stun-types` writes the same shape.
///
/// # Panics
///
/// In debug builds only, when `unknown` is empty: a 420 without an offending
/// attribute is a bug in the caller, and RFC 5389 §15.9 says the attribute is
/// "present only in an ERROR response when the response code in the ERROR-CODE
/// attribute is 420".
pub fn unknown_attributes_response(
    transaction_id: &TransactionId,
    method: u16,
    unknown: &[u16],
) -> Vec<u8> {
    debug_assert!(
        !unknown.is_empty(),
        "a 420 must name at least one unknown attribute"
    );
    let mut value = Vec::with_capacity(unknown.len() * 2);
    for attr_type in unknown {
        value.extend_from_slice(&attr_type.to_be_bytes());
    }

    let mut body = Vec::with_capacity(12 + value.len() + 3);
    push_attribute(
        &mut body,
        ATTR_ERROR_CODE,
        &error_code_value(ERROR_UNKNOWN_ATTRIBUTE, "Unknown Attribute"),
    );
    // `push_attribute` adds the 4-byte alignment padding itself; the `Length`
    // field it writes is `value.len()`, i.e. `2 × N` (RFC 5389 §15).
    push_attribute(&mut body, ATTR_UNKNOWN_ATTRIBUTES, &value);
    encode_message(
        message_type(method, MessageClass::ErrorResponse),
        transaction_id,
        &body,
    )
}

fn encode_message(msg_type: u16, transaction_id: &TransactionId, body: &[u8]) -> Vec<u8> {
    debug_assert!(body.len().is_multiple_of(4), "body must be padded");
    let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
    bytes.extend_from_slice(&msg_type.to_be_bytes());
    bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    bytes.extend_from_slice(transaction_id.as_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn push_attribute(out: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    debug_assert!(value.len() <= u16::MAX as usize);
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    // Zero-pad to the next 4-byte boundary; `length` above stays unpadded.
    out.resize(out.len() + (4 - value.len() % 4) % 4, 0);
}

/// Value of an `XOR-MAPPED-ADDRESS` attribute for `peer`.
fn xor_mapped_address_value(peer: SocketAddr, transaction_id: &TransactionId) -> Vec<u8> {
    let is_v4 = peer.is_ipv4();
    let mut value = Vec::with_capacity(if is_v4 { 8 } else { 20 });
    value.push(0);
    value.push(if is_v4 { FAMILY_IPV4 } else { FAMILY_IPV6 });
    value.extend_from_slice(&(peer.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());

    let mut mask = [0_u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(transaction_id.as_bytes());

    match peer.ip() {
        IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            for (byte, mask) in octets.iter_mut().zip(&mask) {
                *byte ^= *mask;
            }
            value.extend_from_slice(&octets);
        }
        IpAddr::V6(ip) => {
            let mut octets = ip.octets();
            for (byte, mask) in octets.iter_mut().zip(&mask) {
                *byte ^= *mask;
            }
            value.extend_from_slice(&octets);
        }
    }
    value
}

/// Inverse of the `XOR-MAPPED-ADDRESS` encoding: recover the peer address.
///
/// XOR is its own inverse, so this doubles as the encoder's reference check.
pub fn decode_xor_mapped_address(
    value: &[u8],
    transaction_id: &TransactionId,
) -> Option<SocketAddr> {
    let family = *value.get(1)?;
    let mut port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]);
    port ^= (MAGIC_COOKIE >> 16) as u16;

    let mut mask = [0_u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(transaction_id.as_bytes());

    let ip = match family {
        FAMILY_IPV4 => {
            let mut octets: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            for (byte, mask) in octets.iter_mut().zip(&mask) {
                *byte ^= *mask;
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        FAMILY_IPV6 => {
            let mut octets: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            for (byte, mask) in octets.iter_mut().zip(&mask) {
                *byte ^= *mask;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Value of a plain (non-XOR) address attribute: `0 | family | port | address`.
///
/// Used by `RESPONSE-ORIGIN` / `OTHER-ADDRESS` (RFC 5780 §7.3/§7.4), which both
/// say "the format is identical to `MAPPED-ADDRESS`" — i.e. RFC 5389 §15.1, *not*
/// the XOR form.
fn address_value(address: SocketAddr) -> Vec<u8> {
    let is_v4 = address.is_ipv4();
    let mut value = Vec::with_capacity(if is_v4 { 8 } else { 20 });
    value.push(0);
    value.push(if is_v4 { FAMILY_IPV4 } else { FAMILY_IPV6 });
    value.extend_from_slice(&address.port().to_be_bytes());
    match address.ip() {
        IpAddr::V4(ip) => value.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => value.extend_from_slice(&ip.octets()),
    }
    value
}

/// Inverse of [`address_value`]: recover a plain address attribute's address.
///
/// Returns `None` for an unknown address family or a value that is too short,
/// so a hostile / truncated `OTHER-ADDRESS` can never panic a client.
pub fn decode_address_value(value: &[u8]) -> Option<SocketAddr> {
    let family = *value.get(1)?;
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]);
    let ip = match family {
        FAMILY_IPV4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(value.get(4..8)?).ok()?)),
        FAMILY_IPV6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(value.get(4..20)?).ok()?,
        )),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_request(transaction_id: [u8; 12], attributes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_LEN + attributes.len());
        bytes.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        bytes.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction_id);
        bytes.extend_from_slice(attributes);
        bytes
    }

    /// The exact 20-byte request an operator can paste into `nc`/python.
    fn bare_binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
        binding_request(transaction_id, &[])
    }

    fn xor_mapped_address<'a>(message: &'a Message<'a>) -> Attribute<'a> {
        attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_XOR_MAPPED_ADDRESS)
            .expect("response must carry XOR-MAPPED-ADDRESS")
    }

    /// [`SuccessResponse`] with both optional extras off — the shape every
    /// pre-`--mapped-address` / pre-`PADDING` test and deployment uses.
    fn success<'a>(
        transaction_id: &'a TransactionId,
        peer: SocketAddr,
        software: &'a str,
        addresses: Option<ResponseAddresses>,
    ) -> SuccessResponse<'a> {
        SuccessResponse {
            transaction_id,
            peer,
            software,
            addresses,
            mapped_address: false,
            padding: None,
        }
    }

    /// `hex` without separators → bytes, so a frozen wire image stays readable.
    fn hex_bytes(hex: &str) -> Vec<u8> {
        let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(hex.len().is_multiple_of(2), "odd hex length");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn bare_binding_request_is_twenty_bytes_of_header_only() {
        let request = bare_binding_request([0xaa; 12]);
        assert_eq!(request.len(), HEADER_LEN);
        assert_eq!(peek_frame_len(&request), Ok(HEADER_LEN));

        let message = parse(&request).unwrap();
        assert_eq!(message.msg_type, BINDING_REQUEST);
        assert_eq!(message_class(message.msg_type), MessageClass::Request);
        assert_eq!(message_method(message.msg_type), 0x0001);
        assert_eq!(message.transaction_id.as_bytes(), &[0xaa; 12]);
        assert!(message.body.is_empty());
    }

    #[test]
    fn ipv4_binding_response_round_trips_the_xor_mapped_address() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = bare_binding_request(transaction_id);
        let parsed = parse(&request).unwrap();

        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let response =
            binding_success_response(&success(&parsed.transaction_id, peer, "exvlan/test", None));

        // Header fields the client will check.
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            BINDING_SUCCESS_RESPONSE
        );
        assert_eq!(
            message_class(u16::from_be_bytes([response[0], response[1]])),
            MessageClass::SuccessResponse
        );
        let length = usize::from(u16::from_be_bytes([response[2], response[3]]));
        assert!(length.is_multiple_of(4), "attribute length must be padded");
        assert_eq!(response.len(), HEADER_LEN + length);
        assert_eq!(response[4..8], MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&response[8..20], &transaction_id);

        let message = parse(&response).unwrap();
        assert_eq!(message.transaction_id.as_bytes(), &transaction_id);
        let mapped = xor_mapped_address(&message);
        assert_eq!(mapped.value[1], FAMILY_IPV4);
        assert_eq!(
            decode_xor_mapped_address(mapped.value, &message.transaction_id),
            Some(peer)
        );

        let software = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_SOFTWARE)
            .expect("SOFTWARE attribute");
        assert_eq!(software.value, b"exvlan/test");
    }

    #[test]
    fn ipv6_binding_response_round_trips_the_xor_mapped_address() {
        let transaction_id = TransactionId([0x5a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let request = bare_binding_request(transaction_id.0);
        let parsed = parse(&request).unwrap();

        let peer: SocketAddr = "[2001:db8::dead:beef]:9".parse().unwrap();
        let response = binding_success_response(&success(&parsed.transaction_id, peer, "", None));
        let message = parse(&response).unwrap();

        let mapped = xor_mapped_address(&message);
        assert_eq!(mapped.value[1], FAMILY_IPV6);
        assert_eq!(mapped.value.len(), 20);
        assert_eq!(
            decode_xor_mapped_address(mapped.value, &message.transaction_id),
            Some(peer)
        );
        // No SOFTWARE attribute when the name is empty.
        assert!(attributes(message.body).all(|attribute| attribute.attr_type != ATTR_SOFTWARE));
    }

    #[test]
    fn xor_encoding_matches_the_reference_codec() {
        // `stun-types` is the actively maintained reference stack (used by the
        // TURN / WebRTC side of the ecosystem); agreeing with its XOR transform
        // is what makes our response readable by any RFC 5389 client, not just
        // ours.
        let transaction_id = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8];
        let reference_id = reference_transaction_id(transaction_id);
        for peer in [
            "192.0.2.33:41234".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:3478".parse::<SocketAddr>().unwrap(),
        ] {
            let value = xor_mapped_address_value(peer, &TransactionId(transaction_id));
            let reference = stun_types::attribute::XorMappedAddress::new(peer, reference_id);
            // `RawAttribute::from` writes the reference encoder's value bytes
            // behind the 4-byte attribute header; our hand-rolled encoding must
            // match those bytes exactly.
            let reference_bytes = stun_types::attribute::RawAttribute::from(&reference).to_bytes();
            assert_eq!(reference_bytes.len(), 4 + value.len(), "{peer}");
            assert_eq!(&reference_bytes[4..], value.as_slice(), "{peer}");

            // ...and the reference decoder must give the original address back.
            let raw =
                stun_types::attribute::RawAttribute::new(ATTR_XOR_MAPPED_ADDRESS.into(), &value);
            let decoded = stun_types::attribute::XorMappedAddress::try_from(&raw)
                .expect("reference decoder must accept our XOR-MAPPED-ADDRESS");
            assert_eq!(decoded.addr(reference_id), peer);
            // Sanity: our own decoder agrees.
            assert_eq!(
                decode_xor_mapped_address(&value, &TransactionId(transaction_id)),
                Some(peer)
            );
        }
    }

    /// Our 12-byte transaction id as the reference crate models it (its 128-bit
    /// value keeps the id in the low 96 bits).
    fn reference_transaction_id(id: [u8; 12]) -> stun_types::message::TransactionId {
        let mut wide = [0_u8; 16];
        wide[4..].copy_from_slice(&id);
        stun_types::message::TransactionId::from(u128::from_be_bytes(wide))
    }

    #[test]
    fn binding_response_decodes_with_the_reference_decoder() {
        // If the reference implementation cannot read our Binding response, no
        // third-party client can either.
        use stun_types::attribute::{Software, XorMappedAddress};
        use stun_types::message::{BINDING, Message, MessageClass};

        let transaction_id = TransactionId([0xab; 12]);
        let peer: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let response =
            binding_success_response(&success(&transaction_id, peer, "rstun/test", None));

        let message =
            Message::from_bytes(&response).expect("reference parser rejected our response");
        assert!(message.has_class(MessageClass::Success));
        assert!(message.has_method(BINDING));
        assert_eq!(
            message.transaction_id(),
            reference_transaction_id(transaction_id.0)
        );
        let mapped = message
            .attribute::<XorMappedAddress>()
            .expect("XOR-MAPPED-ADDRESS");
        assert_eq!(mapped.addr(message.transaction_id()), peer);
        assert_eq!(
            message
                .attribute::<Software>()
                .expect("SOFTWARE")
                .software(),
            "rstun/test"
        );
    }

    #[test]
    fn plain_response_bytes_are_frozen() {
        // 生产上这个二进制正在服务公网客户端：**不开任何可选开关**时，响应字节
        // 必须与改造前逐字节一致。固定 transaction id / peer / SOFTWARE，把这
        // 48 字节钉死；任何人改动默认路径（属性顺序、新增默认属性）都会在这里红灯。
        let transaction_id = TransactionId([0x11; 12]);
        let peer: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let response =
            binding_success_response(&success(&transaction_id, peer, "rstun/test", None));
        assert_eq!(
            response,
            hex_bytes(
                "0101001c2112a442111111111111111111111111\
                 0020000800013180e721c04b\
                 8022 000a 727374756e2f746573740000"
            ),
            "默认响应字节变了：线上客户端看到的内容会跟着变"
        );
        assert_eq!(response.len(), 48);
    }

    #[test]
    fn mapped_address_is_opt_in_and_appended_after_xor() {
        let transaction_id = TransactionId([0x11; 12]);
        let peer: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let mut with_mapped = success(&transaction_id, peer, "rstun/test", None);
        with_mapped.mapped_address = true;
        let plain = binding_success_response(&success(&transaction_id, peer, "rstun/test", None));
        let mapped = binding_success_response(&with_mapped);

        // RFC 5389 §15.1 layout: 0 | family | port | address, **not** XOR-ed.
        // 198.51.100.9:4242 = 0x1092 → bytes 0x10 0x92.
        let expected_attribute = hex_bytes("0001000800011092c6336409");
        assert_eq!(mapped.len(), plain.len() + expected_attribute.len());
        // XOR-MAPPED-ADDRESS stays first, MAPPED-ADDRESS follows it, SOFTWARE is
        // untouched — the extra attribute is inserted, nothing is reordered.
        // (The Message Length in bytes 2..4 necessarily grows; everything else
        // up to the new attribute is identical.)
        assert_eq!(mapped[0..2], plain[0..2], "message type must not change");
        assert_eq!(&mapped[8..HEADER_LEN + 12], &plain[8..HEADER_LEN + 12]);
        assert_eq!(
            &mapped[HEADER_LEN + 12..HEADER_LEN + 12 + 12],
            expected_attribute
        );
        assert_eq!(&mapped[HEADER_LEN + 24..], &plain[HEADER_LEN + 12..]);

        let message = parse(&mapped).unwrap();
        let raw = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_MAPPED_ADDRESS)
            .expect("MAPPED-ADDRESS");
        assert_eq!(decode_address_value(raw.value), Some(peer));
        // The reference decoder reads it as a plain mapped address too.
        let reference = stun_types::attribute::MappedSocketAddr::from_raw(
            &stun_types::attribute::RawAttribute::new(ATTR_MAPPED_ADDRESS.into(), raw.value),
        )
        .expect("reference decoder must accept MAPPED-ADDRESS");
        assert_eq!(reference.addr(), peer);
    }

    #[test]
    fn padding_is_echoed_without_amplifying() {
        let transaction_id = TransactionId([0x22; 12]);
        let peer: SocketAddr = "203.0.113.7:9".parse().unwrap();

        // RFC 5780 §7.6: PADDING is filler whose length is the point. The echo
        // must be exactly as long as the request asked for, never longer.
        for requested in [0_u16, 4, 37, 128, 1400, 2048] {
            let mut params = success(&transaction_id, peer, "rstun/test", None);
            params.padding = Some(requested);
            let response = binding_success_response(&params);
            let message = parse(&response).unwrap();
            let pads: Vec<usize> = attributes(message.body)
                .filter(|attribute| attribute.attr_type == ATTR_PADDING)
                .map(|attribute| attribute.value.len())
                .collect();
            assert_eq!(pads, vec![usize::from(requested)], "PADDING {requested}");
            // PADDING goes last, so nothing else moves and SOFTWARE stays put.
            let kinds: Vec<u16> = attributes(message.body).map(|a| a.attr_type).collect();
            assert_eq!(
                kinds.last(),
                Some(&ATTR_PADDING),
                "PADDING must be the last attribute"
            );
        }

        // A padding request bigger than a STUN body can express is clamped, not
        // silently wrapped (the Message Length field is a u16).
        let mut huge = success(&transaction_id, peer, "rstun/test", None);
        huge.padding = Some(u16::MAX);
        let response = binding_success_response(&huge);
        assert!(response.len() <= HEADER_LEN + usize::from(u16::MAX));
        let message = parse(&response).unwrap();
        let echoed = padding_len(message.body).expect("PADDING");
        assert!(
            echoed < u16::MAX,
            "the clamp must leave room for the header and the other attributes"
        );
    }

    #[test]
    fn unknown_comprehension_required_attributes_are_collected() {
        fn body_with(types: &[u16]) -> Vec<u8> {
            let mut body = Vec::new();
            for attr_type in types {
                push_attribute(&mut body, *attr_type, &[0xaa, 0xbb, 0xcc, 0xdd]);
            }
            body
        }

        // Nothing unknown in a bare request.
        assert_eq!(unknown_attributes(&[]), Vec::<u16>::new());
        // 0x0033 is comprehension-required and not in our table.
        assert_eq!(unknown_attributes(&body_with(&[0x0033])), vec![0x0033]);
        // ...0x7fff is the top of the comprehension-required range.
        assert_eq!(unknown_attributes(&body_with(&[0x7fff])), vec![0x7fff]);
        // Comprehension-optional attributes are ignored by definition (<0x8000
        // is the filter), so an unknown one never triggers 420.
        assert!(unknown_attributes(&body_with(&[0x8fff])).is_empty());
        // Repeats collapse: one entry per distinct type, in first-seen order.
        assert_eq!(
            unknown_attributes(&body_with(&[0x0033, 0x1234, 0x0033, 0x0034, 0x1234])),
            vec![0x0033, 0x1234, 0x0034]
        );
        // Known attributes never show up, even mixed with unknown ones.
        assert_eq!(
            unknown_attributes(&body_with(&[
                ATTR_USERNAME,
                ATTR_MESSAGE_INTEGRITY,
                ATTR_PRIORITY,
                ATTR_USE_CANDIDATE,
                ATTR_FINGERPRINT,
                ATTR_ICE_CONTROLLING,
                ATTR_CHANGE_REQUEST,
                ATTR_PADDING,
                ATTR_RESPONSE_PORT,
                ATTR_XOR_MAPPED_ADDRESS,
                0x0042,
            ])),
            vec![0x0042]
        );
        // The table itself: everything a real client is known to send.
        for known in [
            ATTR_MAPPED_ADDRESS,
            ATTR_CHANGE_REQUEST,
            ATTR_USERNAME,
            ATTR_MESSAGE_INTEGRITY,
            ATTR_ERROR_CODE,
            ATTR_UNKNOWN_ATTRIBUTES,
            ATTR_REALM,
            ATTR_NONCE,
            ATTR_MESSAGE_INTEGRITY_SHA256,
            ATTR_PASSWORD_ALGORITHM,
            ATTR_USERHASH,
            ATTR_XOR_MAPPED_ADDRESS,
            ATTR_PRIORITY,
            ATTR_USE_CANDIDATE,
            ATTR_PADDING,
            ATTR_RESPONSE_PORT,
            ATTR_SOFTWARE,
            ATTR_ALTERNATE_SERVER,
            ATTR_FINGERPRINT,
            ATTR_ICE_CONTROLLED,
            ATTR_ICE_CONTROLLING,
            ATTR_RESPONSE_ORIGIN,
            ATTR_OTHER_ADDRESS,
        ] {
            assert!(is_known_attribute(known), "{known:#06x} must be known");
            assert!(
                !is_comprehension_required(known)
                    || unknown_attributes(&body_with(&[known])).is_empty(),
                "{known:#06x} must not trigger 420"
            );
        }
        assert!(!is_known_attribute(0x0033));
        assert!(!is_known_attribute(0x0000));
        assert!(!is_known_attribute(0x0002));
    }

    #[test]
    fn unknown_attribute_response_is_a_420_with_a_two_byte_per_type_list() {
        let transaction_id = TransactionId([0x33; 12]);

        // RFC 5389 §15.9 (Note): the normal attribute padding rules apply —
        // "In [RFC3489], this field was padded to 32 by duplicating the last
        // attribute. In this version of the specification, the normal padding
        // rules for attributes are used instead." So the value is exactly `2 × N`
        // bytes and the 4-byte alignment padding lives outside it (and is not
        // counted in the attribute `Length`). RFC 3489's repeat-the-last-entry
        // trick would make the list claim an attribute the client never sent.
        //
        // (value length, value + padding length) per case: N=1 → 2/4,
        // N=2 → 4/4, N=3 → 6/8.
        for (unknown, value_len, wire_len) in [
            (&[0x0033_u16][..], 2_usize, 4_usize),
            (&[0x0033, 0x1234][..], 4, 4),
            (&[0x0033, 0x1234, 0x0035][..], 6, 8),
        ] {
            let response = unknown_attributes_response(&transaction_id, BINDING_REQUEST, unknown);
            assert_eq!(
                u16::from_be_bytes([response[0], response[1]]),
                BINDING_ERROR_RESPONSE
            );
            let message = parse(&response).unwrap();
            assert_eq!(message_class(message.msg_type), MessageClass::ErrorResponse);
            let error = attributes(message.body)
                .find(|attribute| attribute.attr_type == ATTR_ERROR_CODE)
                .expect("ERROR-CODE");
            assert_eq!((error.value[2], error.value[3]), (4, 20), "420");

            // Read the raw attribute so the `Length` field itself is asserted:
            // `attributes()` would hide the difference between "2 bytes of value
            // + 2 bytes of padding" and "4 bytes of value".
            let (offset, length) = raw_attribute(message.body, ATTR_UNKNOWN_ATTRIBUTES);
            assert_eq!(length, value_len, "Length field for N={}", unknown.len());
            let padded = length.div_ceil(4) * 4;
            assert_eq!(padded, wire_len, "value + padding for N={}", unknown.len());
            let expected: Vec<u8> = unknown
                .iter()
                .flat_map(|attr_type| attr_type.to_be_bytes())
                .collect();
            assert_eq!(
                &message.body[offset + 4..offset + 4 + length],
                expected.as_slice()
            );
            // The alignment bytes are zero padding outside the value.
            assert!(
                message.body[offset + 4 + length..offset + 4 + padded]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            // Message Length still counts the padded body: STUN bodies are
            // always a multiple of 4 (RFC 5389 §6).
            assert_eq!(
                usize::from(u16::from_be_bytes([response[2], response[3]])),
                message.body.len()
            );
            assert!(message.body.len().is_multiple_of(4));

            // The reference implementation reads the same code and the same list.
            use stun_types::attribute::{Attribute as _, ErrorCode, UnknownAttributes};
            use stun_types::message::{Message, MessageClass as ReferenceClass};
            let reference = Message::from_bytes(&response).unwrap();
            assert!(reference.has_class(ReferenceClass::Error));
            assert_eq!(
                reference
                    .attribute::<ErrorCode>()
                    .expect("ERROR-CODE")
                    .code(),
                ERROR_UNKNOWN_ATTRIBUTE
            );
            let listed = reference
                .attribute::<UnknownAttributes>()
                .expect("UNKNOWN-ATTRIBUTES");
            // The reference decoder's own `length()` is `2 × N`, so it read
            // exactly the bytes we wrote — no repeated trailing entry.
            assert_eq!(
                usize::from(listed.length()),
                value_len,
                "the reference decoder must see exactly {value_len} bytes of value"
            );
            for attr_type in unknown {
                assert!(
                    listed.has_attribute((*attr_type).into()),
                    "{attr_type:#06x}"
                );
            }
        }
    }

    /// `(offset, Length)` of the first attribute of `attr_type` in a body.
    fn raw_attribute(body: &[u8], attr_type: u16) -> (usize, usize) {
        let mut offset = 0;
        while offset + 4 <= body.len() {
            let kind = u16::from_be_bytes([body[offset], body[offset + 1]]);
            let length = usize::from(u16::from_be_bytes([body[offset + 2], body[offset + 3]]));
            if kind == attr_type {
                return (offset, length);
            }
            offset += 4 + length.div_ceil(4) * 4;
        }
        panic!("attribute {attr_type:#06x} not found");
    }

    #[test]
    fn malformed_messages_are_rejected() {
        let transaction_id = [0_u8; 12];

        // Shorter than a header.
        assert_eq!(
            parse(&[0_u8; HEADER_LEN - 1]),
            Err(ParseError::Truncated {
                have: HEADER_LEN - 1,
                need: HEADER_LEN
            })
        );

        // Leading two bits set: not STUN.
        let mut not_stun = bare_binding_request(transaction_id);
        not_stun[0] = 0x80;
        assert_eq!(parse(&not_stun), Err(ParseError::NotStun));

        // Wrong magic cookie.
        let mut bad_cookie = bare_binding_request(transaction_id);
        bad_cookie[4..8].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        assert_eq!(parse(&bad_cookie), Err(ParseError::BadCookie));

        // Declared length is not a multiple of 4.
        let mut unaligned = bare_binding_request(transaction_id);
        unaligned[2..4].copy_from_slice(&6_u16.to_be_bytes());
        assert_eq!(parse(&unaligned), Err(ParseError::UnalignedLength(6)));

        // Declared length overruns the datagram.
        let mut overrun = bare_binding_request(transaction_id);
        overrun[2..4].copy_from_slice(&8_u16.to_be_bytes());
        assert_eq!(
            parse(&overrun),
            Err(ParseError::Truncated {
                have: HEADER_LEN,
                need: HEADER_LEN + 8
            })
        );

        // Attribute value + padding runs past the body.
        let mut body = Vec::new();
        body.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        body.extend_from_slice(&6_u16.to_be_bytes());
        body.extend_from_slice(b"four");
        assert_eq!(body.len(), 8);
        let attribute_overrun = binding_request(transaction_id, &body);
        assert_eq!(
            parse(&attribute_overrun),
            Err(ParseError::AttributeOverrun {
                offset: 0,
                length: 6,
                body_len: 8
            })
        );
    }

    #[test]
    fn attributes_are_padded_to_four_byte_boundaries() {
        // `hello` is 5 bytes: header + 5 value bytes + 3 padding bytes = 12.
        let mut body = Vec::new();
        body.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        body.extend_from_slice(&5_u16.to_be_bytes());
        body.extend_from_slice(b"hello");
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        body.extend_from_slice(&8_u16.to_be_bytes());
        body.extend_from_slice(&[0_u8; 8]);
        assert_eq!(body.len(), 12 + 12);

        let request = binding_request([7; 12], &body);
        let message = parse(&request).unwrap();
        let collected: Vec<(u16, usize)> = attributes(message.body)
            .map(|attribute| (attribute.attr_type, attribute.value.len()))
            .collect();
        assert_eq!(
            collected,
            vec![(ATTR_SOFTWARE, 5), (ATTR_XOR_MAPPED_ADDRESS, 8)]
        );
    }

    #[test]
    fn attributes_iterator_stops_at_an_overrun() {
        let mut body = Vec::new();
        body.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        body.extend_from_slice(&100_u16.to_be_bytes());
        // Only 4 bytes of "value" follow, far short of the claimed 100.
        assert!(attributes(&body).next().is_none());
    }

    #[test]
    fn error_response_carries_the_error_code() {
        let transaction_id = TransactionId([9; 12]);
        let response = error_response(
            &transaction_id,
            BINDING_REQUEST,
            ERROR_BAD_REQUEST,
            "Bad Request",
        );
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            BINDING_ERROR_RESPONSE
        );
        let message = parse(&response).unwrap();
        assert_eq!(message_class(message.msg_type), MessageClass::ErrorResponse);
        let error = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_ERROR_CODE)
            .expect("ERROR-CODE attribute");
        assert_eq!(error.value[2], 4, "class digit of 400");
        assert_eq!(error.value[3], 0, "number digit of 400");
        assert_eq!(&error.value[4..], b"Bad Request");
    }

    #[test]
    fn error_response_keeps_the_request_method() {
        // TURN Allocate (0x003) must not be answered with a *Binding* error.
        let response = error_response(
            &TransactionId([1; 12]),
            0x0003,
            ERROR_BAD_REQUEST,
            "Bad Request",
        );
        let msg_type = u16::from_be_bytes([response[0], response[1]]);
        assert_eq!(msg_type, 0x0113);
        assert_eq!(message_method(msg_type), 0x0003);
        assert_eq!(message_class(msg_type), MessageClass::ErrorResponse);
    }

    /// Append a `FINGERPRINT` (RFC 5389 §15.5) to a request whose body is
    /// `attributes`, computing the CRC over the message **without** it but with
    /// the header `Length` already counting the attribute.
    fn with_fingerprint(transaction_id: [u8; 12], attributes: &[u8]) -> Vec<u8> {
        let mut bytes = binding_request(transaction_id, attributes);
        let body_len = (attributes.len() + 8) as u16;
        bytes[2..4].copy_from_slice(&body_len.to_be_bytes());
        let value = fingerprint_value(&bytes);
        bytes.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        bytes.extend_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(&value.to_be_bytes());
        bytes
    }

    #[test]
    fn fingerprint_verdict_covers_absent_valid_mismatch_and_position() {
        let transaction_id = [0x61; 12];

        // No attribute: nothing to check (the default path).
        assert_eq!(
            check_fingerprint(&bare_binding_request(transaction_id)),
            FingerprintVerdict::Absent
        );

        // Valid, as the only attribute.
        let only = with_fingerprint(transaction_id, &[]);
        assert_eq!(only.len(), HEADER_LEN + 8);
        assert_eq!(check_fingerprint(&only), FingerprintVerdict::Valid);

        // Valid with attributes in front of it (the CRC covers them too).
        let mut body = Vec::new();
        push_attribute(&mut body, ATTR_SOFTWARE, b"rstun/test");
        push_attribute(&mut body, ATTR_PADDING, &[0x5a; 8]);
        let with_extras = with_fingerprint(transaction_id, &body);
        assert_eq!(check_fingerprint(&with_extras), FingerprintVerdict::Valid);

        // One flipped byte in the value -> Mismatch.
        let mut mismatch = with_extras.clone();
        let last = mismatch.len() - 1;
        mismatch[last] ^= 0xff;
        assert_eq!(check_fingerprint(&mismatch), FingerprintVerdict::Mismatch);

        // A CRC that matches the prefix but the attribute is not last: the
        // position check wins (RFC 5389 §15.5: "MUST be the last attribute").
        let mut misplaced = with_extras.clone();
        let grown = u16::from_be_bytes([misplaced[2], misplaced[3]]) + 4;
        misplaced[2..4].copy_from_slice(&grown.to_be_bytes());
        push_attribute(&mut misplaced, ATTR_PADDING, &[]);
        assert_eq!(check_fingerprint(&misplaced), FingerprintVerdict::NotLast);

        // Two FINGERPRINTs: the first one was not last.
        let mut twice = with_extras.clone();
        let doubled = u16::from_be_bytes([twice[2], twice[3]]) + 8;
        twice[2..4].copy_from_slice(&doubled.to_be_bytes());
        twice.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        twice.extend_from_slice(&4_u16.to_be_bytes());
        twice.extend_from_slice(&[0_u8; 4]);
        assert_eq!(check_fingerprint(&twice), FingerprintVerdict::NotLast);

        // A FINGERPRINT whose value is not 4 bytes cannot be the one the sender
        // computed -> treated as a structural error, never as "valid".
        let mut wrong_length = binding_request(transaction_id, &[]);
        wrong_length[2..4].copy_from_slice(&12_u16.to_be_bytes());
        wrong_length.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        wrong_length.extend_from_slice(&8_u16.to_be_bytes());
        wrong_length.extend_from_slice(&[0_u8; 8]);
        assert_eq!(
            check_fingerprint(&wrong_length),
            FingerprintVerdict::NotLast
        );

        // A datagram shorter than its header claims is not our business here:
        // `parse` reports `Truncated` and the caller drops it, so the fingerprint
        // check must not slice past the buffer (and must not panic).
        let mut truncated = with_fingerprint(transaction_id, &[]);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(check_fingerprint(&truncated), FingerprintVerdict::Absent);
    }

    #[test]
    fn fingerprint_value_is_the_rfc_xor_of_the_crc() {
        // The attribute is `CRC32(message) ^ 0x5354554e`; spelling the constant
        // out here keeps a refactor from quietly dropping the XOR.
        let transaction_id = [0x62; 12];
        let request = with_fingerprint(transaction_id, &[]);
        let message = parse(&request).unwrap();
        let fingerprint = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_FINGERPRINT)
            .expect("FINGERPRINT");
        let value = u32::from_be_bytes(fingerprint.value.try_into().unwrap());

        // The CRC covers the message as sent minus the attribute; the header
        // Length already counts the attribute (RFC 5389 §15.5).
        let prefix = &request[..request.len() - 8];
        assert_eq!(value, crate::crc32::crc32(prefix) ^ FINGERPRINT_XOR);
        assert_eq!(value, fingerprint_value(prefix));
    }

    #[test]
    fn rfc8489_attributes_are_ignored_without_authentication() {
        // The RFC 8489 auth cluster must not turn a probe into a 420: the three
        // comprehension-required types are in the known-attribute table, and
        // PASSWORD-ALGORITHMS (0x8002) is comprehension-optional, so §7.3.1
        // ignores it whether or not the table names it.
        let mut body = Vec::new();
        push_attribute(&mut body, ATTR_MESSAGE_INTEGRITY_SHA256, &[0_u8; 32]);
        push_attribute(&mut body, ATTR_PASSWORD_ALGORITHM, &[0_u8; 4]);
        push_attribute(&mut body, ATTR_USERHASH, &[0_u8; 32]);
        push_attribute(&mut body, 0x8002, &[0_u8; 8]);
        assert_eq!(unknown_attributes(&body), Vec::<u16>::new());
        for attr_type in [
            ATTR_MESSAGE_INTEGRITY_SHA256,
            ATTR_PASSWORD_ALGORITHM,
            ATTR_USERHASH,
        ] {
            assert!(is_known_attribute(attr_type), "{attr_type:#06x}");
        }
    }

    #[test]
    fn alternate_server_response_is_a_300_with_the_plain_address_layout() {
        let transaction_id = TransactionId([0x63; 12]);
        // IPv4: 20 header + 24 ERROR-CODE + 12 ALTERNATE-SERVER.
        let server: SocketAddr = "192.0.2.9:3478".parse().unwrap();
        let response = alternate_server_response(&transaction_id, BINDING_REQUEST, server);
        assert_eq!(response.len(), 56);
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            BINDING_ERROR_RESPONSE
        );
        let message = parse(&response).unwrap();
        assert_eq!(message_class(message.msg_type), MessageClass::ErrorResponse);
        let error = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_ERROR_CODE)
            .expect("ERROR-CODE");
        assert_eq!(
            (error.value[2], error.value[3]),
            (3, 0),
            "class/number of 300"
        );
        assert_eq!(&error.value[4..], b"Try Alternate");
        let alternate = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_ALTERNATE_SERVER)
            .expect("ALTERNATE-SERVER");
        // Same layout as MAPPED-ADDRESS: 0 | family | port | address, not XORed.
        assert_eq!(alternate.value[0], 0);
        assert_eq!(alternate.value[1], FAMILY_IPV4);
        assert_eq!(
            &alternate.value[2..],
            hex_bytes("0d96 c000 0209").as_slice()
        );
        assert_eq!(decode_address_value(alternate.value), Some(server));

        // IPv6: family 0x02 and the full 16-byte address.
        let server: SocketAddr = "[2001:db8::9]:3478".parse().unwrap();
        let response = alternate_server_response(&transaction_id, BINDING_REQUEST, server);
        let message = parse(&response).unwrap();
        let alternate = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_ALTERNATE_SERVER)
            .expect("ALTERNATE-SERVER");
        assert_eq!(alternate.value[1], FAMILY_IPV6);
        assert_eq!(decode_address_value(alternate.value), Some(server));

        // The request method is kept, like every other error response.
        let response = alternate_server_response(&transaction_id, 0x0003, server);
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0x0113);
    }

    #[test]
    fn server_error_response_is_forty_bytes_and_says_nothing_internal() {
        let transaction_id = TransactionId([0x64; 12]);
        let response = server_error_response(&transaction_id, BINDING_REQUEST);
        // 20 header + 20 ERROR-CODE (4 value bytes + 11-byte reason + 1 pad).
        assert_eq!(response.len(), 40);
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            BINDING_ERROR_RESPONSE
        );
        let message = parse(&response).unwrap();
        assert_eq!(message_class(message.msg_type), MessageClass::ErrorResponse);
        let error = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_ERROR_CODE)
            .expect("ERROR-CODE");
        assert_eq!((error.value[2], error.value[3]), (5, 0));
        assert_eq!(&error.value[4..], b"Server Error");
        // Only the fixed reason text: no paths, no errno, no backtrace.
        assert_eq!(
            response,
            error_response(
                &transaction_id,
                BINDING_REQUEST,
                ERROR_SERVER_ERROR,
                "Server Error"
            )
        );
    }

    #[test]
    fn message_class_and_method_decode_rfc_examples() {
        assert_eq!(message_class(0x0001), MessageClass::Request);
        assert_eq!(message_method(0x0001), 0x0001);
        assert_eq!(message_class(0x0011), MessageClass::Indication);
        assert_eq!(message_method(0x0011), 0x0001);
        assert_eq!(message_class(0x0101), MessageClass::SuccessResponse);
        assert_eq!(message_method(0x0101), 0x0001);
        assert_eq!(message_class(0x0111), MessageClass::ErrorResponse);
        assert_eq!(message_method(0x0111), 0x0001);
        // Allocate request (TURN method 0x003) must not decode as Binding.
        assert_eq!(message_class(0x0003), MessageClass::Request);
        assert_eq!(message_method(0x0003), 0x0003);
        // Encoding is the exact inverse for every method/class pair we produce.
        for (method, class) in [
            (0x0001, MessageClass::Request),
            (0x0001, MessageClass::Indication),
            (0x0001, MessageClass::SuccessResponse),
            (0x0001, MessageClass::ErrorResponse),
            (0x0003, MessageClass::ErrorResponse),
        ] {
            let msg_type = message_type(method, class);
            assert_eq!(message_method(msg_type), method);
            assert_eq!(message_class(msg_type), class);
        }
    }

    #[test]
    fn transaction_id_displays_as_hex() {
        assert_eq!(
            TransactionId([0x0a, 0xbc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_string(),
            "0abc00000000000000000000"
        );
    }

    /// One `CHANGE-REQUEST` attribute with a raw value (so malformed lengths can
    /// be exercised too).
    fn change_request_attribute(value: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
        body.resize(body.len() + (4 - value.len() % 4) % 4, 0);
        body
    }

    fn parsed_change_request(flags: u32) -> Option<ChangeRequest> {
        let request = binding_request([0x2b; 12], &change_request_attribute(&flags.to_be_bytes()));
        let message = parse(&request).expect("request must parse");
        change_request(message.body)
    }

    #[test]
    fn change_request_decodes_the_two_flag_bits() {
        // RFC 5780 §7.2: A = 0x04 (change IP), B = 0x02 (change port).
        assert_eq!(
            parsed_change_request(0x0000),
            Some(ChangeRequest {
                change_ip: false,
                change_port: false
            })
        );
        assert_eq!(
            parsed_change_request(CHANGE_IP),
            Some(ChangeRequest {
                change_ip: true,
                change_port: false
            })
        );
        assert_eq!(
            parsed_change_request(CHANGE_PORT),
            Some(ChangeRequest {
                change_ip: false,
                change_port: true
            })
        );
        assert_eq!(
            parsed_change_request(CHANGE_IP | CHANGE_PORT),
            Some(ChangeRequest {
                change_ip: true,
                change_port: true
            })
        );
        assert!(parsed_change_request(CHANGE_IP).unwrap().any());
        assert!(!parsed_change_request(0).unwrap().any());
    }

    #[test]
    fn change_request_ignores_unknown_bits_and_wrong_lengths() {
        // Unknown high bits and a non-zero reserved half must not flip anything.
        assert_eq!(
            parsed_change_request(0x8000_0000),
            Some(ChangeRequest {
                change_ip: false,
                change_port: false
            })
        );
        assert_eq!(
            parsed_change_request(0x0000_0001),
            Some(ChangeRequest {
                change_ip: false,
                change_port: false
            })
        );
        // Still readable when the ignored bits ride along with a real request.
        assert_eq!(
            parsed_change_request(0xffff_fffe),
            Some(ChangeRequest {
                change_ip: true,
                change_port: true
            })
        );

        // A value shorter than 4 bytes is not a CHANGE-REQUEST: Binding still works.
        let short = [0xff_u8; CHANGE_REQUEST_LEN];
        for length in 0..CHANGE_REQUEST_LEN {
            let request = binding_request([0x2c; 12], &change_request_attribute(&short[..length]));
            let message = parse(&request).expect("request must parse");
            assert_eq!(change_request(message.body), None, "length {length}");
        }

        // No attribute at all.
        let bare = bare_binding_request([0x2d; 12]);
        let message = parse(&bare).unwrap();
        assert_eq!(change_request(message.body), None);
    }

    #[test]
    fn change_request_ignores_a_nonzero_reserved_half() {
        // First half = flags, second half reserved (RFC 5780 asks for zero); a
        // client that fills the reserved half must still be understood.
        let mut value = Vec::new();
        value.extend_from_slice(&CHANGE_PORT.to_be_bytes());
        value.extend_from_slice(&[0xde, 0xad]);
        let request = binding_request([0x2e; 12], &change_request_attribute(&value));
        let message = parse(&request).unwrap();
        assert_eq!(
            change_request(message.body),
            Some(ChangeRequest {
                change_ip: false,
                change_port: true
            })
        );
    }

    #[test]
    fn plain_address_attributes_round_trip_ipv4() {
        let transaction_id = TransactionId([0x31; 12]);
        let peer: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let origin: SocketAddr = "203.0.113.7:3478".parse().unwrap();
        let other: SocketAddr = "203.0.113.8:3479".parse().unwrap();

        let response = binding_success_response(&success(
            &transaction_id,
            peer,
            "",
            Some(ResponseAddresses { origin, other }),
        ));
        let message = parse(&response).unwrap();

        let collected: Vec<(u16, Vec<u8>)> = attributes(message.body)
            .map(|attribute| (attribute.attr_type, attribute.value.to_vec()))
            .collect();
        assert_eq!(
            collected.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![
                ATTR_XOR_MAPPED_ADDRESS,
                ATTR_RESPONSE_ORIGIN,
                ATTR_OTHER_ADDRESS
            ]
        );

        // 0 | family 0x01 | port | 4 address bytes, **not** XOR-obfuscated.
        let (_, origin_value) = &collected[1];
        assert_eq!(
            origin_value,
            &vec![0, FAMILY_IPV4, 0x0d, 0x96, 203, 0, 113, 7]
        );
        let (_, other_value) = &collected[2];
        assert_eq!(
            other_value,
            &vec![0, FAMILY_IPV4, 0x0d, 0x97, 203, 0, 113, 8]
        );

        assert_eq!(decode_address_value(origin_value), Some(origin));
        assert_eq!(decode_address_value(other_value), Some(other));
        // The mapped address is untouched by the RFC 5780 additions.
        assert_eq!(
            decode_xor_mapped_address(xor_mapped_address(&message).value, &transaction_id),
            Some(peer)
        );
    }

    #[test]
    fn plain_address_attributes_round_trip_ipv6() {
        let transaction_id = TransactionId([0x32; 12]);
        let origin: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        let other: SocketAddr = "[2001:db8::2]:3479".parse().unwrap();
        let response = binding_success_response(&success(
            &transaction_id,
            "127.0.0.1:9".parse().unwrap(),
            "",
            Some(ResponseAddresses { origin, other }),
        ));
        let message = parse(&response).unwrap();

        let other_value = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_OTHER_ADDRESS)
            .expect("OTHER-ADDRESS")
            .value;
        // RFC 5780 §7.4 for IPv6: family 0x02 and the full 16-byte address.
        assert_eq!(other_value.len(), 20);
        assert_eq!(other_value[1], FAMILY_IPV6);
        assert_eq!(decode_address_value(other_value), Some(other));

        let origin_value = attributes(message.body)
            .find(|attribute| attribute.attr_type == ATTR_RESPONSE_ORIGIN)
            .expect("RESPONSE-ORIGIN")
            .value;
        assert_eq!(origin_value.len(), 20);
        assert_eq!(decode_address_value(origin_value), Some(origin));
    }

    #[test]
    fn plain_address_attributes_reject_short_or_unknown_values() {
        // Unknown family.
        assert_eq!(
            decode_address_value(&[0, 0x03, 0x0d, 0x96, 1, 2, 3, 4]),
            None
        );
        // Truncated IPv4 / IPv6 values.
        assert_eq!(
            decode_address_value(&[0, FAMILY_IPV4, 0x0d, 0x96, 1, 2, 3]),
            None
        );
        assert_eq!(
            decode_address_value(&[0, FAMILY_IPV6, 0x0d, 0x96, 0x20, 0x01, 0x0d, 0xb8]),
            None
        );
        assert_eq!(decode_address_value(&[]), None);
    }

    #[test]
    fn rfc5780_attributes_decode_with_the_reference_codec() {
        // `stun-types` 2.x has no RFC 5780 attribute types of its own, so the
        // oracle here is its *generic* parser: the message must parse, and the
        // two address attributes must be byte-identical to the layout
        // `MappedSocketAddr` prescribes for "same format as MAPPED-ADDRESS"
        // (RFC 5780 §7.1) — which is the shared contract, not our own decoder.
        use stun_types::attribute::{MappedSocketAddr, RawAttribute, XorMappedAddress};
        use stun_types::message::{Message, MessageClass};

        let transaction_id = TransactionId([0x33; 12]);
        let peer: SocketAddr = "198.51.100.9:4242".parse().unwrap();
        let origin: SocketAddr = "203.0.113.7:3478".parse().unwrap();
        let other: SocketAddr = "203.0.113.8:3479".parse().unwrap();
        let response = binding_success_response(&success(
            &transaction_id,
            peer,
            "rstun/test",
            Some(ResponseAddresses { origin, other }),
        ));

        let message =
            Message::from_bytes(&response).expect("reference parser rejected RFC 5780 response");
        assert!(message.has_class(MessageClass::Success));
        let (_, raw_origin) = message
            .iter_attributes()
            .find(|(_, attribute)| attribute.header.get_type().value() == ATTR_RESPONSE_ORIGIN)
            .expect("RESPONSE-ORIGIN");
        let (_, raw_other) = message
            .iter_attributes()
            .find(|(_, attribute)| attribute.header.get_type().value() == ATTR_OTHER_ADDRESS)
            .expect("OTHER-ADDRESS");

        // `MappedSocketAddr` is the reference's plain (non-XOR) address codec:
        // our value bytes must be exactly what it writes for the same address.
        for (raw, address) in [(&raw_origin, origin), (&raw_other, other)] {
            let reference = MappedSocketAddr::new(address);
            let reference = reference.to_raw(raw.header.get_type());
            assert_eq!(&*raw.value, &*reference.value, "{address}");
            let decoded = MappedSocketAddr::from_raw(raw).expect("plain address layout");
            assert_eq!(decoded.addr(), address);
            // ...and our own decoder agrees.
            assert_eq!(decode_address_value(&raw.value), Some(address));
        }

        let mapped = message
            .attribute::<XorMappedAddress>()
            .expect("XOR-MAPPED-ADDRESS");
        assert_eq!(mapped.addr(message.transaction_id()), peer);
        assert_eq!(
            RawAttribute::new(ATTR_RESPONSE_ORIGIN.into(), &raw_origin.value)
                .header
                .length(),
            8
        );
    }

    #[test]
    fn padding_and_response_port_parsing_is_tolerant() {
        let padding_attribute = |len: usize| {
            let mut body = Vec::new();
            push_attribute(&mut body, ATTR_PADDING, &vec![0x5a; len]);
            body
        };
        assert_eq!(padding_len(&padding_attribute(0)), Some(0));
        assert_eq!(padding_len(&padding_attribute(37)), Some(37));
        assert_eq!(padding_len(&[]), None);

        // RESPONSE-PORT is "16-bit port + 2 padding bytes"; a client that only
        // writes the port is still understood, and a truncated value is ignored
        // rather than turned into a 400.
        let response_port_attribute = |value: &[u8]| {
            let mut body = Vec::new();
            push_attribute(&mut body, ATTR_RESPONSE_PORT, value);
            body
        };
        assert_eq!(
            response_port(&response_port_attribute(&[0x0d, 0x96, 0, 0])),
            Some(3478)
        );
        assert_eq!(
            response_port(&response_port_attribute(&[0x0d, 0x96])),
            Some(3478)
        );
        assert_eq!(response_port(&response_port_attribute(&[0x0d])), None);
        assert_eq!(response_port(&response_port_attribute(&[])), None);
        assert_eq!(response_port(&[]), None);
    }
}
