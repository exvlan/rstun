//! TURN unit + end-to-end tests (no external tools).
//!
//! The e2e cases run a real `serve_udp` loop and two UDP sockets (client and
//! peer) on loopback: the wire path is exactly the one `turnutils_uclient`
//! exercises, only the client is ours. Authentication is real too (401
//! challenge, MD5 long-term key, `MESSAGE-INTEGRITY`), so a regression in the
//! shared `auth` implementation shows up here.

use std::net::SocketAddr;
use std::time::Duration;

use super::*;
use crate::auth::{self, Identity, KeyAlgorithm, User};
use crate::protocol;
use crate::{ServerContext, ServerStats, udp_socket};

const USER: &str = "turnuser";
const PASS: &str = "turnpass";
const REALM: &str = "example.org";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn long_term_auth() -> auth::Auth {
    auth::Auth::long_term(
        REALM.to_string(),
        b"nonce-secret".to_vec(),
        vec![User {
            username: USER.to_string(),
            password: PASS.to_string(),
        }],
        Duration::from_secs(auth::DEFAULT_NONCE_LIFETIME),
        false,
    )
}

fn long_term_auth_two_users() -> auth::Auth {
    auth::Auth::long_term(
        REALM.to_string(),
        b"nonce-secret".to_vec(),
        vec![
            User {
                username: USER.to_string(),
                password: PASS.to_string(),
            },
            User {
                username: "otheruser".to_string(),
                password: "otherpass".to_string(),
            },
        ],
        Duration::from_secs(auth::DEFAULT_NONCE_LIFETIME),
        false,
    )
}

struct Harness {
    server: SocketAddr,
    turn: Arc<Turn>,
    stats: Arc<ServerStats>,
    context: Arc<ServerContext>,
}

/// Start `serve_udp` with TURN enabled on an ephemeral loopback port.
async fn start(config: Config) -> Harness {
    start_with(config, long_term_auth()).await
}

async fn start_with(config: Config, auth: auth::Auth) -> Harness {
    start_on("127.0.0.1:0", config, auth).await
}

/// Start on an explicit bind address; `server` is always the loopback address a
/// client can reach (a wildcard bind still receives on 127.0.0.1 in tests).
async fn start_on(bind: &str, config: Config, auth: auth::Auth) -> Harness {
    let socket = Arc::new(udp_socket(bind.parse().unwrap()).unwrap());
    let bound = socket.local_addr().unwrap();
    // A wildcard bind is probed over loopback; concrete binds (including IPv6)
    // keep their own address so family-specific tests can reach them.
    let server = if bound.ip().is_unspecified() {
        SocketAddr::new("127.0.0.1".parse().unwrap(), bound.port())
    } else {
        bound
    };
    let turn = Arc::new(Turn::new(config, "rstun/test"));
    let stats = Arc::new(ServerStats::default());
    stats.set_turn(turn.clone());
    let context = Arc::new(ServerContext {
        plan: None,
        udp: vec![(bound, socket.clone())],
        mapped_address: false,
        admission: None,
        fingerprint: None,
        alternate_server: None,
        auth: Some(auth),
    });
    tokio::spawn(crate::serve_udp(
        socket,
        context.clone(),
        Arc::from("rstun/test"),
        stats.clone(),
    ));
    Harness {
        server,
        turn,
        stats,
        context,
    }
}

fn transaction_id(sequence: u8) -> TransactionId {
    let mut bytes = [0_u8; 12];
    bytes[11] = sequence;
    bytes[0] = 0x5a;
    TransactionId(bytes)
}

fn request(method: u16, transaction_id: &TransactionId, attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (attr_type, value) in attributes {
        protocol::push_attribute(&mut body, *attr_type, value);
    }
    protocol::encode_message(
        protocol::message_type(method, MessageClass::Request),
        transaction_id,
        &body,
    )
}

fn attributes_of(response: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let message = protocol::parse(response).expect("response must parse");
    protocol::attributes(message.body)
        .map(|attribute| (attribute.attr_type, attribute.value.to_vec()))
        .collect()
}

fn error_code(response: &[u8]) -> Option<u16> {
    let message = protocol::parse(response).ok()?;
    if protocol::message_class(message.msg_type) != MessageClass::ErrorResponse {
        return None;
    }
    let value = protocol::attributes(message.body)
        .find(|attribute| attribute.attr_type == protocol::ATTR_ERROR_CODE)?
        .value;
    Some(u16::from(value[2]) * 100 + u16::from(value[3]))
}

async fn recv(socket: &UdpSocket, millis: u64) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; 65535];
    match tokio::time::timeout(Duration::from_millis(millis), socket.recv_from(&mut buffer)).await {
        Ok(Ok((length, _))) => Some(buffer[..length].to_vec()),
        _ => None,
    }
}

async fn send(socket: &UdpSocket, bytes: &[u8], to: SocketAddr) {
    socket.send_to(bytes, to).await.expect("send");
}

/// A client that walks the real long-term challenge flow.
struct Client {
    socket: UdpSocket,
    server: SocketAddr,
    nonce: String,
    user: String,
    key: Vec<u8>,
    sequence: u8,
}

impl Client {
    async fn connect(server: SocketAddr) -> Self {
        // Bind in the server's family so IPv6 relays are reachable too.
        let local = if server.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        };
        let socket = UdpSocket::bind(local).await.unwrap();
        Self {
            socket,
            server,
            nonce: String::new(),
            user: USER.to_string(),
            key: auth::long_term_key(KeyAlgorithm::Md5, USER, REALM, PASS),
            sequence: 0,
        }
    }

    /// Switch credentials without changing the 5-tuple (same socket). Used to
    /// prove another user cannot touch this allocation (441).
    fn set_identity(&mut self, user: &str, password: &str) {
        self.user = user.to_string();
        self.key = auth::long_term_key(KeyAlgorithm::Md5, user, REALM, password);
    }

    fn next_id(&mut self) -> TransactionId {
        self.sequence = self.sequence.wrapping_add(1);
        transaction_id(self.sequence)
    }

    /// The TURN 5-tuple this client occupies (the harness binds a concrete
    /// loopback address, so the server half is exactly `self.server`).
    ///
    /// Only the DONT-FRAGMENT tests reach into the allocation table, and those
    /// are platform-gated; without the same gate a Windows test build warns
    /// about a dead helper.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    fn key(&self) -> Key {
        Key {
            client: self.socket.local_addr().expect("local address"),
            transport: ClientTransport::Udp,
            server: self.server,
        }
    }

    fn alloc_attributes(&self) -> Vec<(u16, Vec<u8>)> {
        vec![
            (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
            (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
        ]
    }

    fn sign(&self, frame: Vec<u8>) -> Vec<u8> {
        auth::seal(
            frame,
            &Identity {
                username: self.user.clone(),
                keys: vec![(KeyAlgorithm::Md5, self.key.clone())],
            },
        )
    }

    /// Unauthenticated Allocate: 401 + NONCE, which the client stores.
    async fn challenge(&mut self) -> Vec<u8> {
        let transaction_id = self.next_id();
        let frame = request(ALLOCATE_METHOD, &transaction_id, &self.alloc_attributes());
        send(&self.socket, &frame, self.server).await;
        let response = recv(&self.socket, 1000).await.expect("401 challenge");
        for (attr_type, value) in attributes_of(&response) {
            if attr_type == protocol::ATTR_NONCE {
                self.nonce = String::from_utf8(value).expect("nonce is text");
            }
        }
        response
    }

    async fn request(&mut self, method: u16, extra: Vec<(u16, Vec<u8>)>) -> Vec<u8> {
        let transaction_id = self.next_id();
        self.signed_request(method, &transaction_id, extra).await
    }

    /// Send one signed request with a caller-chosen transaction id (so a
    /// retransmission can be byte-identical).
    async fn signed_request(
        &mut self,
        method: u16,
        transaction_id: &TransactionId,
        extra: Vec<(u16, Vec<u8>)>,
    ) -> Vec<u8> {
        let mut attributes = extra;
        attributes.push((protocol::ATTR_USERNAME, self.user.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_REALM, REALM.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_NONCE, self.nonce.as_bytes().to_vec()));
        let frame = self.sign(request(method, transaction_id, &attributes));
        send(&self.socket, &frame, self.server).await;
        recv(&self.socket, 1000).await.expect("TURN response")
    }

    async fn allocate(&mut self) -> Vec<u8> {
        self.allocate_with(300).await
    }

    async fn allocate_with(&mut self, seconds: u32) -> Vec<u8> {
        let transaction_id = self.next_id();
        self.allocate_with_tid(&transaction_id, seconds).await
    }

    async fn allocate_with_tid(&mut self, transaction_id: &TransactionId, seconds: u32) -> Vec<u8> {
        self.signed_request(
            ALLOCATE_METHOD,
            transaction_id,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_LIFETIME, seconds.to_be_bytes().to_vec()),
            ],
        )
        .await
    }

    async fn create_permission(&mut self, peers: &[SocketAddr]) -> Vec<u8> {
        let transaction_id = self.next_id();
        let mut attributes: Vec<(u16, Vec<u8>)> = peers
            .iter()
            .map(|peer| {
                (
                    ATTR_XOR_PEER_ADDRESS,
                    protocol::xor_mapped_address_value(*peer, &transaction_id),
                )
            })
            .collect();
        attributes.push((protocol::ATTR_USERNAME, self.user.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_REALM, REALM.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_NONCE, self.nonce.as_bytes().to_vec()));
        let frame = self.sign(request(
            CREATE_PERMISSION_METHOD,
            &transaction_id,
            &attributes,
        ));
        send(&self.socket, &frame, self.server).await;
        recv(&self.socket, 1000).await.expect("CreatePermission")
    }
}

fn relayed_address(response: &[u8]) -> SocketAddr {
    let message = protocol::parse(response).expect("parse");
    let value = protocol::attributes(message.body)
        .find(|attribute| attribute.attr_type == ATTR_XOR_RELAYED_ADDRESS)
        .expect("XOR-RELAYED-ADDRESS")
        .value;
    protocol::decode_xor_mapped_address(value, &message.transaction_id).expect("relay address")
}

fn lifetime_of(response: &[u8]) -> u32 {
    let message = protocol::parse(response).expect("parse");
    let value = protocol::attributes(message.body)
        .find(|attribute| attribute.attr_type == ATTR_LIFETIME)
        .expect("LIFETIME")
        .value;
    u32::from_be_bytes([value[0], value[1], value[2], value[3]])
}

/// Build a `Send` indication (unauthenticated by design, RFC 8656 §7.3).
fn send_indication(transaction_id: &TransactionId, peer: SocketAddr, data: &[u8]) -> Vec<u8> {
    send_indication_with(transaction_id, peer, data, &[])
}

/// Same, plus extra attributes (`DONT-FRAGMENT`, malformed variants, ...).
fn send_indication_with(
    transaction_id: &TransactionId,
    peer: SocketAddr,
    data: &[u8],
    extra: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut body = Vec::new();
    protocol::push_attribute(
        &mut body,
        ATTR_XOR_PEER_ADDRESS,
        &protocol::xor_mapped_address_value(peer, transaction_id),
    );
    protocol::push_attribute(&mut body, ATTR_DATA, data);
    for (attr_type, value) in extra {
        protocol::push_attribute(&mut body, *attr_type, value);
    }
    protocol::encode_message(
        protocol::message_type(SEND_METHOD, MessageClass::Indication),
        transaction_id,
        &body,
    )
}

fn channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&channel.to_be_bytes());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

#[test]
fn port_range_parsing_and_config_validation() {
    assert_eq!(parse_port_range("49152-65535"), Ok((49152, 65535)));
    assert!(parse_port_range("5000").is_err());
    assert!(parse_port_range("x-1").is_err());
    assert!(parse_port_range("0-10").is_err());

    assert!(Config::default().validate().is_ok());
    assert!(
        Config {
            max_allocations_per_user: 0,
            ..Config::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Config {
            relay_ports: (6000, 5000),
            ..Config::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Config {
            lifetime: Duration::from_secs(MAX_ALLOCATION_LIFETIME_SECONDS + 1),
            ..Config::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn channel_data_framing_and_detection() {
    assert!(is_channel_data(&channel_data(CHANNEL_MIN, b"x")));
    assert!(!is_channel_data(&[0x00, 0x03, 0x00, 0x00]));
    assert!(is_channel_data_prefix(0x40));
    assert!(is_channel_data_prefix(0x7f));
    assert!(!is_channel_data_prefix(0x3f));
    assert!(!is_channel_data_prefix(0x80));

    // UDP: no padding. TCP: 4-byte alignment (§12.5).
    let udp = channel_data_frame(0x4001, b"abc", ClientTransport::Udp);
    assert_eq!(udp, vec![0x40, 0x01, 0x00, 0x03, b'a', b'b', b'c']);
    let tcp = channel_data_frame(0x4001, b"abc", ClientTransport::Tcp);
    assert_eq!(tcp.len(), 8);
    assert_eq!(&tcp[4..], b"abc\0");
    // DTLS is a datagram transport: same framing as UDP, no stream padding.
    let dtls = channel_data_frame(0x4001, b"abc", ClientTransport::Dtls);
    assert_eq!(dtls, udp);
}

#[test]
fn bandwidth_bucket_drops_after_the_one_second_budget() {
    let start = Instant::now();
    let mut unlimited = TokenBucket::new(0, start);
    for _ in 0..1000 {
        assert!(unlimited.try_take(start, 65_535));
    }

    // 1000 B/s: one second of tokens, starting full.
    let mut bucket = TokenBucket::new(1000, start);
    assert!(bucket.try_take(start, 600), "the bucket starts full");
    assert!(!bucket.try_take(start, 600), "only 400 tokens left");
    assert!(bucket.try_take(start, 400), "exactly draining is allowed");
    assert!(!bucket.try_take(start, 1), "empty bucket drops the payload");
    // Refills continuously: 500 ms later there are ~500 tokens again.
    assert!(bucket.try_take(start + Duration::from_millis(500), 400));
    // Never above one second's worth, no matter how long the idle period was.
    assert!(bucket.try_take(start + Duration::from_secs(3600), 1000));
    assert!(!bucket.try_take(start + Duration::from_secs(3600), 1));
}

#[test]
fn error_codes_have_expected_values() {
    assert_eq!(ERROR_FORBIDDEN, 403);
    assert_eq!(ERROR_ALLOCATION_MISMATCH, 437);
    assert_eq!(ERROR_WRONG_CREDENTIALS, 441);
    assert_eq!(ERROR_ADDRESS_FAMILY_NOT_SUPPORTED, 440);
    assert_eq!(ERROR_UNSUPPORTED_TRANSPORT, 442);
    assert_eq!(ERROR_PEER_ADDRESS_FAMILY_MISMATCH, 443);
    assert_eq!(ERROR_ALLOCATION_QUOTA_REACHED, 486);
    assert_eq!(ERROR_INSUFFICIENT_CAPACITY, 508);
    // RFC 6062 §6.3
    assert_eq!(ERROR_CONNECTION_ALREADY_EXISTS, 446);
    assert_eq!(ERROR_CONNECTION_TIMEOUT_OR_FAILURE, 447);
    assert_eq!(CONNECT_METHOD, 0x00a);
    assert_eq!(CONNECTION_BIND_METHOD, 0x00b);
    assert_eq!(ATTR_CONNECTION_ID, 0x002a);
}

#[test]
fn unknown_comprehension_required_attributes_are_reported() {
    let mut body = Vec::new();
    protocol::push_attribute(&mut body, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    protocol::push_attribute(&mut body, 0x7777, &[]); // genuinely unknown
    assert_eq!(turn_unknown_attributes(&body), vec![0x7777]);

    // DONT-FRAGMENT is understood where the DF bit can be set (§18.9); on a
    // build without that path it must stay unknown → 420 (§7.2 step 4).
    let mut df = Vec::new();
    protocol::push_attribute(&mut df, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    protocol::push_attribute(&mut df, ATTR_DONT_FRAGMENT, &[]);
    if DONT_FRAGMENT_SUPPORTED {
        assert!(turn_unknown_attributes(&df).is_empty());
    } else {
        assert_eq!(turn_unknown_attributes(&df), vec![ATTR_DONT_FRAGMENT]);
    }

    // REQUESTED-ADDRESS-FAMILY is understood now (answered 200/440/400), so a
    // request carrying it is no longer a 420 (RFC 8656 §7.2 step 7).
    let mut raf = Vec::new();
    protocol::push_attribute(&mut raf, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    protocol::push_attribute(&mut raf, ATTR_REQUESTED_ADDRESS_FAMILY, &[0x01, 0, 0, 0]);
    assert!(turn_unknown_attributes(&raf).is_empty());

    let mut known = Vec::new();
    protocol::push_attribute(&mut known, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    protocol::push_attribute(&mut known, ATTR_LIFETIME, &300_u32.to_be_bytes());
    assert!(turn_unknown_attributes(&known).is_empty());

    // RFC 6062 §6.2.1: CONNECTION-ID must not be answered 420 before
    // `Connect` / `ConnectionBind` get to run.
    let mut connection_id = Vec::new();
    protocol::push_attribute(&mut connection_id, ATTR_CONNECTION_ID, &[0, 0, 0, 1]);
    assert!(turn_unknown_attributes(&connection_id).is_empty());
}

#[test]
fn dont_fragment_parsing() {
    // Absent → nothing requested.
    assert_eq!(parse_dont_fragment(&[]), Ok(false));
    // §18.9: no value part, so length 0 is the well-formed shape.
    let mut present = Vec::new();
    protocol::push_attribute(&mut present, ATTR_DONT_FRAGMENT, &[]);
    assert_eq!(parse_dont_fragment(&present), Ok(true));
    // Any value part is malformed: `Allocate` answers 400, and a `Send`
    // indication carrying it is discarded and counted (§11.2 treats an
    // unusable DONT-FRAGMENT as an unknown comprehension-required attribute).
    let mut malformed = Vec::new();
    protocol::push_attribute(&mut malformed, ATTR_DONT_FRAGMENT, &[1]);
    assert_eq!(parse_dont_fragment(&malformed), Err(()));
}

#[test]
fn requested_address_family_parsing() {
    assert_eq!(parse_requested_address_family(&[]), Ok(None));

    let mut ipv4 = Vec::new();
    protocol::push_attribute(&mut ipv4, ATTR_REQUESTED_ADDRESS_FAMILY, &[0x01, 0, 0, 0]);
    assert_eq!(parse_requested_address_family(&ipv4), Ok(Some(0x01)));

    // §18.6: the reserved 24 bits are ignored, never validated.
    let mut reserved = Vec::new();
    protocol::push_attribute(
        &mut reserved,
        ATTR_REQUESTED_ADDRESS_FAMILY,
        &[0x02, 0xff, 0xff, 0xff],
    );
    assert_eq!(parse_requested_address_family(&reserved), Ok(Some(0x02)));

    let mut short = Vec::new();
    protocol::push_attribute(&mut short, ATTR_REQUESTED_ADDRESS_FAMILY, &[0x01, 0, 0]);
    assert_eq!(parse_requested_address_family(&short), Err(()));
}

#[test]
fn requested_address_family_matches_the_relay_family() {
    let v4: IpAddr = "192.0.2.1".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(family_matches(0x01, v4));
    assert!(!family_matches(0x01, v6));
    assert!(family_matches(0x02, v6));
    assert!(!family_matches(0x02, v4));
    // Values outside 0x01/0x02 never match: "family not supported".
    assert!(!family_matches(0x00, v4));
    assert!(!family_matches(0x03, v6));
}

// ---------------------------------------------------------------------------
// End-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn udp_relay_full_flow() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;

    // 1. No MESSAGE-INTEGRITY → 401 with REALM + NONCE.
    let challenge = client.challenge().await;
    assert_eq!(error_code(&challenge), Some(401));
    assert!(
        !client.nonce.is_empty(),
        "401 must teach the client a nonce"
    );

    // 2. Authenticated Allocate → 200 with relay address + lifetime.
    let allocate_tid = client.next_id();
    let response = client.allocate_with_tid(&allocate_tid, 300).await;
    assert_eq!(error_code(&response), None, "Allocate must succeed");
    let relay = relayed_address(&response);
    assert_ne!(relay.port(), 0);
    assert!(lifetime_of(&response) > 0);
    // RFC 8656 §14.10 SHOULD: success responses carry SOFTWARE.
    let software = attributes_of(&response)
        .into_iter()
        .find(|(attr_type, _)| *attr_type == protocol::ATTR_SOFTWARE)
        .expect("SOFTWARE")
        .1;
    assert!(software.starts_with(b"rstun/"));

    // 3. Same transaction id = retransmission: 200 and the same relay. A new
    //    transaction id on the same 5-tuple is an allocation mismatch (437).
    let retransmit = client.allocate_with_tid(&allocate_tid, 300).await;
    assert_eq!(error_code(&retransmit), None);
    assert_eq!(relayed_address(&retransmit), relay);
    // §6.2: the retransmission carries the *granted* lifetime, not the rest.
    assert_eq!(lifetime_of(&retransmit), lifetime_of(&response));
    let new_tid = client.next_id();
    let mismatched = client.allocate_with_tid(&new_tid, 300).await;
    assert_eq!(error_code(&mismatched), Some(437));
    assert_eq!(harness.turn.active(), 1);

    // 4. A peer that the client never permitted gets nothing.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let transaction_id = client.next_id();
    let indication = send_indication(&transaction_id, peer_addr, b"no-permission");
    send(&client.socket, &indication, harness.server).await;
    assert!(
        recv(&peer, 250).await.is_none(),
        "Send without permission must not reach the peer"
    );

    // 5. CreatePermission → 200.
    let response = client.create_permission(&[peer_addr]).await;
    assert_eq!(error_code(&response), None);

    // 6. Peer → relay → client, as a Data indication.
    send(&peer, b"hello-client", relay).await;
    let indication = recv(&client.socket, 1000).await.expect("Data indication");
    let message = protocol::parse(&indication).expect("parse indication");
    assert_eq!(
        protocol::message_class(message.msg_type),
        MessageClass::Indication
    );
    assert_eq!(protocol::message_method(message.msg_type), DATA_METHOD);
    let attributes = attributes_of(&indication);
    let data = attributes
        .iter()
        .find(|(attr_type, _)| *attr_type == ATTR_DATA)
        .expect("DATA")
        .1
        .clone();
    assert_eq!(data, b"hello-client");
    let peer_attribute = attributes
        .iter()
        .find(|(attr_type, _)| *attr_type == ATTR_XOR_PEER_ADDRESS)
        .expect("XOR-PEER-ADDRESS");
    assert_eq!(
        protocol::decode_xor_mapped_address(&peer_attribute.1, &message.transaction_id),
        Some(peer_addr)
    );

    // 7. Client → relay → peer, as a Send indication.
    let transaction_id = client.next_id();
    let indication = send_indication(&transaction_id, peer_addr, b"hello-peer");
    send(&client.socket, &indication, harness.server).await;
    let received = recv(&peer, 1000).await.expect("peer receives relay data");
    assert_eq!(received, b"hello-peer");

    // 8. ChannelBind + ChannelData both directions.
    let channel = CHANNEL_MIN + 1;
    let transaction_id = client.next_id();
    let mut attributes = vec![(ATTR_CHANNEL_NUMBER, {
        let mut value = channel.to_be_bytes().to_vec();
        value.extend_from_slice(&[0, 0]);
        value
    })];
    attributes.push((
        ATTR_XOR_PEER_ADDRESS,
        protocol::xor_mapped_address_value(peer_addr, &transaction_id),
    ));
    attributes.push((protocol::ATTR_USERNAME, USER.as_bytes().to_vec()));
    attributes.push((protocol::ATTR_REALM, REALM.as_bytes().to_vec()));
    attributes.push((protocol::ATTR_NONCE, client.nonce.as_bytes().to_vec()));
    let frame = client.sign(request(CHANNEL_BIND_METHOD, &transaction_id, &attributes));
    send(&client.socket, &frame, harness.server).await;
    let response = recv(&client.socket, 1000).await.expect("ChannelBind");
    assert_eq!(error_code(&response), None);

    send(&peer, b"via-channel", relay).await;
    let frame = recv(&client.socket, 1000)
        .await
        .expect("ChannelData from server");
    assert!(is_channel_data(&frame));
    assert_eq!(u16::from_be_bytes([frame[0], frame[1]]), channel);
    assert_eq!(&frame[4..], b"via-channel");

    send(
        &client.socket,
        &channel_data(channel, b"to-peer"),
        harness.server,
    )
    .await;
    let received = recv(&peer, 1000).await.expect("peer receives ChannelData");
    assert_eq!(received, b"to-peer");

    // 8b. A ChannelData frame whose declared length is longer than the
    //     datagram must be dropped, not forwarded truncated.
    let mut lying = channel_data(channel, b"abc");
    lying[2..4].copy_from_slice(&20_u16.to_be_bytes());
    send(&client.socket, &lying, harness.server).await;
    assert!(
        recv(&peer, 300).await.is_none(),
        "a lying ChannelData length must not reach the peer"
    );

    // 9. Refresh releases immediately; a second Refresh is 437.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![(ATTR_LIFETIME, 0_u32.to_be_bytes().to_vec())],
        )
        .await;
    assert_eq!(error_code(&response), None);
    assert_eq!(lifetime_of(&response), 0);
    assert_eq!(harness.turn.active(), 0);
    let response = client
        .request(
            REFRESH_METHOD,
            vec![(ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec())],
        )
        .await;
    assert_eq!(error_code(&response), Some(437));

    // 10. The relay port really went back to the OS.
    let mut rebound = false;
    for _ in 0..100 {
        if std::net::UdpSocket::bind(relay).is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(rebound, "relay socket {relay} must be released");

    // 11. Metrics grew with the relay.
    let counts = harness.turn.snapshot();
    assert_eq!(counts.created, 1);
    assert_eq!(counts.expired, 1);
    assert!(counts.bytes_in >= b"hello-peer".len() as u64);
    assert!(counts.bytes_out >= b"hello-client".len() as u64);
}

#[tokio::test]
async fn permissions_and_channels_expire() {
    let harness = start(Config {
        lifetime: Duration::from_secs(3600),
        ..Config::default()
    })
    .await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client.allocate_with(3600).await;
    assert_eq!(lifetime_of(&response), 3600);
    let relay = relayed_address(&response);

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let response = client.create_permission(&[peer_addr]).await;
    assert_eq!(error_code(&response), None);
    send(&peer, b"before", relay).await;
    assert!(recv(&client.socket, 1000).await.is_some());

    // Past both the 5-minute permission and the 10-minute channel TTL.
    harness
        .turn
        .sweep(Instant::now() + Duration::from_secs(601));
    send(&peer, b"after", relay).await;
    assert!(
        recv(&client.socket, 300).await.is_none(),
        "expired permission must drop peer data"
    );

    // Send after the permission expired: nothing reaches the peer.
    let transaction_id = client.next_id();
    let indication = send_indication(&transaction_id, peer_addr, b"stale");
    send(&client.socket, &indication, harness.server).await;
    assert!(recv(&peer, 300).await.is_none());
}

/// An expired-but-not-swept allocation is *replaced* by the next `Allocate` on
/// the same 5-tuple. The port that goes back to the pool must be the replaced
/// entry's, not the new one's: releasing the live port would let a second
/// allocation claim it (and `SO_REUSEPORT` would even let two TCP relays share
/// it), while the old port would stay marked used forever.
#[tokio::test]
async fn reallocating_over_an_expired_entry_releases_the_old_port() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let first_reply = client.allocate().await;
    assert_eq!(error_code(&first_reply), None);
    let first_relay = relayed_address(&first_reply);

    let key = Key {
        client: client.socket.local_addr().expect("client address"),
        transport: ClientTransport::Udp,
        server: harness.server,
    };
    let allocation = harness.turn.get(&key, Instant::now()).expect("allocation");
    // TTL elapsed, but the 1 s sweep has not run yet: the entry is still in the
    // table, so the next Allocate inserts a *new* one over it.
    lock_write(&allocation.state).expires_at = Instant::now() - Duration::from_secs(1);
    drop(allocation);

    let second_reply = client.allocate().await;
    assert_eq!(error_code(&second_reply), None);
    let second_relay = relayed_address(&second_reply);
    assert_ne!(
        second_relay.port(),
        first_relay.port(),
        "the expired entry's port is still marked used when the new one is picked"
    );
    let used = lock_lock(&harness.turn.used_ports);
    assert!(
        !used.contains(&first_relay.port()),
        "the replaced entry's port must go back to the pool"
    );
    assert!(
        used.contains(&second_relay.port()),
        "the live allocation's port must stay taken"
    );
}

#[tokio::test]
async fn quota_and_port_exhaustion() {
    // Quota: one allocation per user.
    let harness = start(Config {
        max_allocations_per_user: 1,
        ..Config::default()
    })
    .await;
    let mut first = Client::connect(harness.server).await;
    first.challenge().await;
    assert_eq!(error_code(&first.allocate().await), None);
    let mut second = Client::connect(harness.server).await;
    second.challenge().await;
    assert_eq!(error_code(&second.allocate().await), Some(486));

    // Ports: a one-port relay range.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let only_port = probe.local_addr().unwrap().port();
    drop(probe);
    let harness = start(Config {
        relay_ports: (only_port, only_port),
        ..Config::default()
    })
    .await;
    let mut first = Client::connect(harness.server).await;
    first.challenge().await;
    assert_eq!(error_code(&first.allocate().await), None);
    let mut second = Client::connect(harness.server).await;
    second.challenge().await;
    assert_eq!(error_code(&second.allocate().await), Some(508));
}

#[tokio::test]
async fn family_and_loopback_peers_are_refused() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let relay = relayed_address(&client.allocate().await);
    assert!(relay.is_ipv4());

    // Wrong family: an IPv6 peer against an IPv4 relay → 443.
    let ipv6_peer: SocketAddr = "[::1]:9000".parse().unwrap();
    assert_eq!(
        error_code(&client.create_permission(&[ipv6_peer]).await),
        Some(443)
    );
    assert_eq!(harness.turn.snapshot().rejected_family, 1);

    // Loopback: the server's own socket as the peer → 403.
    assert_eq!(
        error_code(&client.create_permission(&[harness.server]).await),
        Some(403)
    );
    assert_eq!(harness.turn.snapshot().rejected_loopback, 1);
}

/// Minimal TURN-over-TCP client: STUN frames and `ChannelData` on one stream.
struct TcpClient {
    stream: tokio::net::TcpStream,
    nonce: String,
    key: Vec<u8>,
    sequence: u8,
}

impl TcpClient {
    async fn connect(server: SocketAddr) -> Self {
        let stream = tokio::net::TcpStream::connect(server).await.unwrap();
        Self {
            stream,
            nonce: String::new(),
            key: auth::long_term_key(KeyAlgorithm::Md5, USER, REALM, PASS),
            sequence: 0,
        }
    }

    fn next_id(&mut self) -> TransactionId {
        self.sequence = self.sequence.wrapping_add(1);
        transaction_id(self.sequence)
    }

    fn sign(&self, frame: Vec<u8>) -> Vec<u8> {
        auth::seal(
            frame,
            &Identity {
                username: USER.to_string(),
                keys: vec![(KeyAlgorithm::Md5, self.key.clone())],
            },
        )
    }

    async fn write(&mut self, bytes: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        self.stream.write_all(bytes).await.expect("tcp write");
    }

    async fn read_exact(&mut self, buffer: &mut [u8]) {
        use tokio::io::AsyncReadExt as _;
        self.stream.read_exact(buffer).await.expect("tcp read");
    }

    async fn read_stun(&mut self) -> Vec<u8> {
        let mut header = [0_u8; protocol::HEADER_LEN];
        self.read_exact(&mut header).await;
        let length =
            protocol::peek_frame_len(&header).expect("frame header") - protocol::HEADER_LEN;
        let mut frame = vec![0_u8; protocol::HEADER_LEN + length];
        frame[..protocol::HEADER_LEN].copy_from_slice(&header);
        self.read_exact(&mut frame[protocol::HEADER_LEN..]).await;
        frame
    }

    async fn challenge(&mut self) -> Vec<u8> {
        let frame = request(
            ALLOCATE_METHOD,
            &transaction_id(0),
            &[
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
            ],
        );
        self.sequence = 0;
        self.write(&frame).await;
        let response = self.read_stun().await;
        for (attr_type, value) in attributes_of(&response) {
            if attr_type == protocol::ATTR_NONCE {
                self.nonce = String::from_utf8(value).expect("nonce is text");
            }
        }
        response
    }

    async fn request(&mut self, method: u16, extra: Vec<(u16, Vec<u8>)>) -> Vec<u8> {
        let transaction_id = self.next_id();
        let mut attributes = extra;
        attributes.push((protocol::ATTR_USERNAME, USER.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_REALM, REALM.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_NONCE, self.nonce.as_bytes().to_vec()));
        let frame = self.sign(request(method, &transaction_id, &attributes));
        self.write(&frame).await;
        self.read_stun().await
    }

    /// Unauthenticated request of any method → 401 + NONCE.
    async fn challenge_with(&mut self, method: u16, extra: Vec<(u16, Vec<u8>)>) -> Vec<u8> {
        let transaction_id = self.next_id();
        let frame = request(method, &transaction_id, &extra);
        self.write(&frame).await;
        let response = self.read_stun().await;
        for (attr_type, value) in attributes_of(&response) {
            if attr_type == protocol::ATTR_NONCE {
                self.nonce = String::from_utf8(value).expect("nonce is text");
            }
        }
        response
    }

    /// Allocate with an explicit `REQUESTED-TRANSPORT`, challenge included.
    async fn allocate_with(&mut self, transport: u8) -> Vec<u8> {
        let attributes = vec![(ATTR_REQUESTED_TRANSPORT, vec![transport, 0, 0, 0])];
        self.challenge_with(ALLOCATE_METHOD, attributes.clone())
            .await;
        self.request(ALLOCATE_METHOD, attributes).await
    }

    async fn allocate_tcp(&mut self) -> Vec<u8> {
        self.allocate_with(TRANSPORT_TCP).await
    }

    /// Signed `Connect`; the peer address is XORed with this request's tid.
    async fn connect_peer(&mut self, peer: SocketAddr) -> Vec<u8> {
        let transaction_id = self.next_id();
        let frame = self.signed_frame(
            CONNECT_METHOD,
            &transaction_id,
            vec![(
                ATTR_XOR_PEER_ADDRESS,
                protocol::xor_mapped_address_value(peer, &transaction_id),
            )],
        );
        self.write(&frame).await;
        self.read_stun().await
    }

    /// Signed `ConnectionBind` after the ordinary 401 dance (a data connection
    /// has its own nonce challenge; nothing says it inherits the control one).
    async fn connection_bind(&mut self, id: u32) -> Vec<u8> {
        let extra = vec![(ATTR_CONNECTION_ID, id.to_be_bytes().to_vec())];
        self.challenge_with(CONNECTION_BIND_METHOD, extra.clone())
            .await;
        self.request(CONNECTION_BIND_METHOD, extra).await
    }

    /// Signed `CreatePermission` for one peer (the XOR is keyed on this
    /// request's transaction id, so the caller cannot build it).
    async fn create_permission_for(&mut self, peer: SocketAddr) -> Vec<u8> {
        let transaction_id = self.next_id();
        let frame = self.signed_frame(
            CREATE_PERMISSION_METHOD,
            &transaction_id,
            vec![(
                ATTR_XOR_PEER_ADDRESS,
                protocol::xor_mapped_address_value(peer, &transaction_id),
            )],
        );
        self.write(&frame).await;
        self.read_stun().await
    }

    /// `read_stun` bounded in time: a missing `ConnectionAttempt` must fail the
    /// test instead of hanging it.
    async fn read_stun_within(&mut self, millis: u64) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_millis(millis), self.read_stun())
            .await
            .ok()
    }

    async fn refresh(&mut self, seconds: u32) -> Vec<u8> {
        self.request(
            REFRESH_METHOD,
            vec![(ATTR_LIFETIME, seconds.to_be_bytes().to_vec())],
        )
        .await
    }

    /// `request` without writing/reading: the caller frames it itself.
    fn signed_frame(
        &self,
        method: u16,
        transaction_id: &TransactionId,
        extra: Vec<(u16, Vec<u8>)>,
    ) -> Vec<u8> {
        let mut attributes = extra;
        attributes.push((protocol::ATTR_USERNAME, USER.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_REALM, REALM.as_bytes().to_vec()));
        attributes.push((protocol::ATTR_NONCE, self.nonce.as_bytes().to_vec()));
        self.sign(request(method, transaction_id, &attributes))
    }
}

#[tokio::test]
async fn tcp_transport_relays_and_frames_channel_data() {
    let listener = crate::tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let server = listener.local_addr().unwrap();
    let turn = Arc::new(Turn::new(Config::default(), "rstun/test"));
    let stats = Arc::new(ServerStats::default());
    stats.set_turn(turn.clone());
    let context = Arc::new(ServerContext {
        plan: None,
        udp: Vec::new(),
        mapped_address: false,
        admission: None,
        fingerprint: None,
        alternate_server: None,
        auth: Some(long_term_auth()),
    });
    tokio::spawn(crate::serve_tcp(
        listener,
        context.clone(),
        Arc::from("rstun/test"),
        stats.clone(),
    ));

    let mut client = TcpClient::connect(server).await;
    let challenge = client.challenge().await;
    assert_eq!(error_code(&challenge), Some(401));

    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
            ],
        )
        .await;
    assert_eq!(error_code(&response), None, "Allocate over TCP");
    let relay = relayed_address(&response);

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let transaction_id = client.next_id();
    let mut attributes = vec![(
        ATTR_XOR_PEER_ADDRESS,
        protocol::xor_mapped_address_value(peer_addr, &transaction_id),
    )];
    attributes.push((protocol::ATTR_USERNAME, USER.as_bytes().to_vec()));
    attributes.push((protocol::ATTR_REALM, REALM.as_bytes().to_vec()));
    attributes.push((protocol::ATTR_NONCE, client.nonce.as_bytes().to_vec()));
    let frame = client.sign(request(
        CREATE_PERMISSION_METHOD,
        &transaction_id,
        &attributes,
    ));
    client.write(&frame).await;
    assert_eq!(error_code(&client.read_stun().await), None);

    let channel = CHANNEL_MIN + 2;
    let transaction_id = client.next_id();
    let mut value = channel.to_be_bytes().to_vec();
    value.extend_from_slice(&[0, 0]);
    let mut attributes = vec![(ATTR_CHANNEL_NUMBER, value)];
    attributes.push((
        ATTR_XOR_PEER_ADDRESS,
        protocol::xor_mapped_address_value(peer_addr, &transaction_id),
    ));
    attributes.push((protocol::ATTR_USERNAME, USER.as_bytes().to_vec()));
    attributes.push((protocol::ATTR_REALM, REALM.as_bytes().to_vec()));
    attributes.push((protocol::ATTR_NONCE, client.nonce.as_bytes().to_vec()));
    let frame = client.sign(request(CHANNEL_BIND_METHOD, &transaction_id, &attributes));
    client.write(&frame).await;
    assert_eq!(error_code(&client.read_stun().await), None);

    // Peer → relay → client: ChannelData with the 4-byte header + padding.
    send(&peer, b"tcp-in", relay).await;
    let mut header = [0_u8; 4];
    client.read_exact(&mut header).await;
    assert_eq!(u16::from_be_bytes([header[0], header[1]]), channel);
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
    assert_eq!(length, b"tcp-in".len());
    let padded = length + (4 - length % 4) % 4;
    let mut payload = vec![0_u8; padded];
    client.read_exact(&mut payload).await;
    assert_eq!(&payload[..length], b"tcp-in");

    // Client → relay → peer: ChannelData over TCP (7 data bytes + 1 pad).
    let mut frame = channel_data(channel, b"tcp-out");
    frame.push(0);
    client.write(&frame).await;
    assert_eq!(recv(&peer, 1000).await.as_deref(), Some(&b"tcp-out"[..]));

    // Closing the connection releases the allocation (no leftover relay).
    drop(client);
    let mut released = false;
    for _ in 0..100 {
        if turn.active() == 0 {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(released, "TCP close must release its allocation");
}

#[tokio::test]
async fn wrong_password_is_401_and_an_expired_nonce_is_438() {
    // One-second nonce lifetime: the challenge goes stale while we hold it.
    let auth = auth::Auth::long_term(
        REALM.to_string(),
        b"nonce-secret".to_vec(),
        vec![User {
            username: USER.to_string(),
            password: PASS.to_string(),
        }],
        Duration::from_secs(1),
        false,
    );
    let harness = start_with(Config::default(), auth).await;

    // Wrong password: the MAC does not verify → 401.
    let mut wrong = Client::connect(harness.server).await;
    assert_eq!(error_code(&wrong.challenge().await), Some(401));
    wrong.key = b"definitely-not-the-password".to_vec();
    assert_eq!(error_code(&wrong.allocate().await), Some(401));

    // Expired nonce → 438 + a fresh NONCE that does work.
    let mut client = Client::connect(harness.server).await;
    assert_eq!(error_code(&client.challenge().await), Some(401));
    let stale_nonce = client.nonce.clone();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let response = client.allocate().await;
    assert_eq!(error_code(&response), Some(438));
    let renewed = attributes_of(&response)
        .into_iter()
        .find(|(attr_type, _)| *attr_type == protocol::ATTR_NONCE)
        .expect("438 must carry a new NONCE")
        .1;
    assert_ne!(renewed, stale_nonce.as_bytes());
    client.nonce = String::from_utf8(renewed).unwrap();
    assert_eq!(error_code(&client.allocate().await), None);
}

#[tokio::test]
async fn refresh_renews_and_zero_releases() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client.allocate().await;
    assert_eq!(error_code(&response), None);
    let relay = relayed_address(&response);

    // RFC 8656 §7.2: below the default (600 s) the server's default wins.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![(ATTR_LIFETIME, 60_u32.to_be_bytes().to_vec())],
        )
        .await;
    assert_eq!(error_code(&response), None);
    assert_eq!(lifetime_of(&response), 600);

    // RFC 8656 §8.2: Refresh without LIFETIME gets the server default.
    let response = client.request(REFRESH_METHOD, Vec::new()).await;
    assert_eq!(error_code(&response), None);
    assert_eq!(lifetime_of(&response), 600);

    // LIFETIME=0 releases the relay immediately.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![(ATTR_LIFETIME, 0_u32.to_be_bytes().to_vec())],
        )
        .await;
    assert_eq!(error_code(&response), None);
    assert_eq!(lifetime_of(&response), 0);
    assert_eq!(harness.turn.active(), 0);
    assert_ne!(relay.port(), 0);
}

#[tokio::test]
async fn allocate_rejects_tcp_transport_and_missing_requested_transport() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;

    // REQUESTED-TRANSPORT=6 with `--turn-tcp-relay` **off** → the classic 442.
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_TCP, 0, 0, 0]),
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(442));

    // Missing REQUESTED-TRANSPORT → 400.
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![(ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec())],
        )
        .await;
    assert_eq!(error_code(&response), Some(400));

    // DONT-FRAGMENT is comprehension-required. Where the DF bit can be set it
    // is understood (§18.9), so the Allocate goes through; on a build without
    // that path it stays unknown → 420 (§7.2 step 4).
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_DONT_FRAGMENT, Vec::new()),
            ],
        )
        .await;
    if DONT_FRAGMENT_SUPPORTED {
        assert_eq!(error_code(&response), None);
    } else {
        assert_eq!(error_code(&response), Some(420));
    }
}

/// RFC 8656 §7.2 step 7 / §18.6: `REQUESTED-ADDRESS-FAMILY` chooses the relay
/// address family. The relay follows the client, so "IPv4 client + IPv4" must
/// allocate (this is the `turnutils_uclient -e/-X` case that used to get 420),
/// and anything the relay cannot serve is `440`.
#[tokio::test]
async fn requested_address_family_selects_the_relay_family() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;

    // Reserved bits set: §18.6 says ignore them, so this must still allocate.
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x01, 0xff, 0xff, 0xff]),
            ],
        )
        .await;
    assert_eq!(
        error_code(&response),
        None,
        "IPv4 + IPv4 relay must allocate"
    );
    assert!(relayed_address(&response).is_ipv4());
    assert_eq!(harness.turn.active(), 1);

    // Refresh accepts the attribute too (§8.2): a matching family refreshes
    // normally (a mismatch is 443 — covered by its own test).
    let response = client
        .request(
            REFRESH_METHOD,
            vec![
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x01, 0, 0, 0]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), None);
    assert_eq!(lifetime_of(&response), 600);
    assert_eq!(harness.turn.active(), 1);

    // A relay family the client cannot get: 440, and nothing is allocated.
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x02, 0, 0, 0]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(440));
    assert_eq!(harness.turn.active(), 0);
    assert!(harness.turn.snapshot().rejected_family >= 1);

    // A family value that is neither 0x01 nor 0x02: 440 as well.
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x03, 0, 0, 0]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(440));

    // Malformed (3-byte) value → 400, not 440.
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x01, 0, 0]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(400));

    // RESERVATION-TOKEN and REQUESTED-ADDRESS-FAMILY are mutually exclusive
    // (§7.2 step 5), exactly like EVEN-PORT — and step 5 runs **before** the
    // step-7 family comparison, so even a family this relay cannot serve is
    // 400 (coturn's answer), never 440.
    for family in [0x01, 0x02] {
        let response = client
            .request(
                ALLOCATE_METHOD,
                vec![
                    (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                    (ATTR_RESERVATION_TOKEN, vec![0; 8]),
                    (ATTR_REQUESTED_ADDRESS_FAMILY, vec![family, 0, 0, 0]),
                ],
            )
            .await;
        assert_eq!(
            error_code(&response),
            Some(400),
            "RESERVATION-TOKEN + RAF={family:#04x} must be 400 (§7.2 step 5 before step 7)"
        );
    }

    // DONT-FRAGMENT: on unix the DF bit can be set, so the Allocate is accepted
    // (§18.9 capability probe); on a build without that path it stays an
    // unknown comprehension-required attribute → 420 (§7.2 step 4).
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_DONT_FRAGMENT, Vec::new()),
            ],
        )
        .await;
    if DONT_FRAGMENT_SUPPORTED {
        // Every earlier request in this block was refused, so the 5-tuple is
        // still free: the DF capability probe allocates (§18.9).
        assert_eq!(error_code(&response), None);
        assert!(relayed_address(&response).is_ipv4());
        assert_eq!(harness.turn.active(), 1);
    } else {
        assert_eq!(error_code(&response), Some(420));
        let unknown = attributes_of(&response)
            .into_iter()
            .find(|(attr_type, _)| *attr_type == protocol::ATTR_UNKNOWN_ATTRIBUTES)
            .expect("UNKNOWN-ATTRIBUTES")
            .1;
        assert_eq!(unknown, vec![0x00, 0x1A]);
    }
}

/// RFC 8656 §8.2 (MUST): a Refresh whose `REQUESTED-ADDRESS-FAMILY` does not
/// match the allocation's relay family is `443 Peer Address Family Mismatch` —
/// the allocation survives, a mismatched `LIFETIME=0` cannot release it, and a
/// matching value refreshes normally.
#[tokio::test]
async fn refresh_requested_address_family_mismatch_is_443() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client.allocate().await;
    assert_eq!(error_code(&response), None);
    assert!(relayed_address(&response).is_ipv4());

    // Mismatched family → 443 (§8.2), not 200 and not 420.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x02, 0, 0, 0]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(443));
    assert_eq!(
        harness.turn.active(),
        1,
        "443 must not release the allocation"
    );
    assert!(harness.turn.snapshot().rejected_family >= 1);

    // A value that is neither 0x01 nor 0x02 cannot match either → 443.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![(ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x03, 0, 0, 0])],
        )
        .await;
    assert_eq!(error_code(&response), Some(443));

    // A mismatched `LIFETIME=0` must not delete the allocation either.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![
                (ATTR_LIFETIME, 0_u32.to_be_bytes().to_vec()),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x02, 0, 0, 0]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(443));
    assert_eq!(harness.turn.active(), 1);

    // Malformed (3-byte) value → 400.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![(ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x01, 0, 0])],
        )
        .await;
    assert_eq!(error_code(&response), Some(400));

    // Matching family → 200 with the normal granted lifetime.
    let response = client
        .request(
            REFRESH_METHOD,
            vec![
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
                (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x01, 0, 0, 0]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), None);
    assert_eq!(lifetime_of(&response), 600);
    assert_eq!(harness.turn.active(), 1);
}

// ---------------------------------------------------------------------------
// DONT-FRAGMENT (0x001A): §18.9 / §7.2 step 4 / §11.2
// ---------------------------------------------------------------------------

/// Read the DF option back from a socket: `IP_MTU_DISCOVER` on Linux,
/// `IP_DONTFRAG` on macOS. Only the platforms `set_dont_fragment` implements.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
fn dont_fragment_option(socket: &UdpSocket, ipv6: bool) -> libc::c_int {
    use std::os::fd::AsRawFd;

    #[cfg(target_os = "linux")]
    let (level, name) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let (level, name) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG)
    } else {
        (libc::IPPROTO_IP, libc::IP_DONTFRAG)
    };

    let mut value: libc::c_int = -1;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: `value` is a live `c_int` and `length` its exact size; the kernel
    // writes at most `length` bytes into it.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    assert_eq!(rc, 0, "getsockopt: {}", std::io::Error::last_os_error());
    value
}

/// The `(DF on, DF off)` values the platform reports for its option.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
fn dont_fragment_values() -> (libc::c_int, libc::c_int) {
    #[cfg(target_os = "linux")]
    {
        (libc::IP_PMTUDISC_DO, libc::IP_PMTUDISC_WANT)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        (1, 0)
    }
}

/// `set_dont_fragment` really reaches the socket: the option reads back as the
/// platform's "DF set" value and returns to the kernel default afterwards.
/// This is also the fallback evidence for the lab's `df` item when `tcpdump`
/// cannot run.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
#[tokio::test]
async fn set_dont_fragment_round_trips() {
    let (set, cleared) = dont_fragment_values();
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(
        dont_fragment_option(&v4, false),
        cleared,
        "the kernel default is PMTUDISC_WANT / off"
    );
    set_dont_fragment(&v4, true).expect("set DF on an IPv4 socket");
    assert_eq!(dont_fragment_option(&v4, false), set);
    set_dont_fragment(&v4, false).expect("clear DF on an IPv4 socket");
    assert_eq!(dont_fragment_option(&v4, false), cleared);

    // IPv6 uses the v6 spelling of the option; skip hosts without ::1.
    if let Ok(v6) = UdpSocket::bind("[::1]:0").await {
        set_dont_fragment(&v6, true).expect("set DF on an IPv6 socket");
        assert_eq!(dont_fragment_option(&v6, true), set);
        set_dont_fragment(&v6, false).expect("clear DF on an IPv6 socket");
        assert_eq!(dont_fragment_option(&v6, true), cleared);
    }
}

/// §7.2 step 4 / §18.9: `DONT-FRAGMENT` in `Allocate` is the capability probe
/// **and** arms the DF bit on the relay socket for the allocation's lifetime.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
#[tokio::test]
async fn allocate_with_dont_fragment_sets_the_relay_socket() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
                (ATTR_DONT_FRAGMENT, Vec::new()),
            ],
        )
        .await;
    assert_eq!(
        error_code(&response),
        None,
        "DF is supported on this platform (no longer 420)"
    );
    let relay = relayed_address(&response);
    let allocation = harness
        .turn
        .get(&client.key(), Instant::now())
        .expect("allocation");
    assert!(
        allocation.dont_fragment,
        "the allocation records the request"
    );
    let (set, _) = dont_fragment_values();
    assert_eq!(
        dont_fragment_option(allocation.relay.udp().expect("UDP relay"), relay.is_ipv6()),
        set,
        "the relay socket carries DF for its whole life"
    );

    // §18.9: the attribute has no value part, so a value is 400.
    let mut fresh = Client::connect(harness.server).await;
    fresh.challenge().await;
    let response = fresh
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_DONT_FRAGMENT, vec![1]),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(400));
    assert_eq!(harness.turn.active(), 1, "the 400 allocated nothing");
}

/// §7.2 step 4 / §18.9: an `Allocate` that asks for `DONT-FRAGMENT` but whose
/// relay socket refuses the option is an internal failure — `500`, nothing
/// allocated, the port back in the pool, and `rejected_df` counted. This is the
/// only DF branch a healthy kernel never reaches, hence the injected failure.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
#[tokio::test]
async fn allocate_dont_fragment_failure_is_500_and_returns_the_port() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let before = harness.turn.snapshot().rejected_df;

    df_failure::set(true);
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec()),
                (ATTR_DONT_FRAGMENT, Vec::new()),
            ],
        )
        .await;
    // The response only arrives after the handler returned, so the flag can go
    // back immediately.
    df_failure::set(false);

    assert_eq!(
        error_code(&response),
        Some(500),
        "a relay socket that cannot set DF is an internal failure, not a 420"
    );
    assert_eq!(
        harness.turn.active(),
        0,
        "the failed Allocate must not leave an allocation behind"
    );
    assert!(
        harness.turn.snapshot().rejected_df > before,
        "the Allocate DF failure must be counted (rejected_df)"
    );
    assert!(
        lock_lock(&harness.turn.used_ports).is_empty(),
        "the relay port must go back to the pool on the 500 path"
    );

    // The table and the port pool are still usable: the same 5-tuple (whose
    // first Allocate failed) allocates normally now.
    let response = client.allocate().await;
    assert_eq!(error_code(&response), None);
    assert_eq!(harness.turn.active(), 1);
    assert!(
        !lock_lock(&harness.turn.used_ports).is_empty(),
        "the second Allocate must hold a relay port"
    );
}

/// §11.2: `DONT-FRAGMENT` in a `Send` indication is per datagram — the bit is
/// set, the payload goes out, and the socket returns to its allocation-level
/// setting. A malformed value or a DF that cannot be applied discards the
/// indication (§11.2: treat it as an unknown comprehension-required attribute)
/// and counts it; neither is ever forwarded without the bit.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
#[tokio::test]
async fn send_indication_dont_fragment_is_per_datagram() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client.allocate().await;
    assert_eq!(error_code(&response), None);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    assert_eq!(
        error_code(&client.create_permission(&[peer_addr]).await),
        None
    );

    let allocation = harness
        .turn
        .get(&client.key(), Instant::now())
        .expect("allocation");
    assert!(
        !allocation.dont_fragment,
        "this allocation did not ask for DF"
    );
    let (_, cleared) = dont_fragment_values();
    assert_eq!(
        dont_fragment_option(allocation.relay.udp().expect("UDP relay"), false),
        cleared
    );

    // DF on this datagram only.
    let transaction_id = client.next_id();
    let indication = send_indication_with(
        &transaction_id,
        peer_addr,
        b"df-once",
        &[(ATTR_DONT_FRAGMENT, vec![])],
    );
    send(&client.socket, &indication, harness.server).await;
    assert_eq!(
        recv(&peer, 1000)
            .await
            .expect("peer receives the DF payload"),
        b"df-once"
    );
    let mut restored = false;
    for _ in 0..100 {
        if dont_fragment_option(allocation.relay.udp().expect("UDP relay"), false) == cleared {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(restored, "the DF bit must not outlive the datagram");

    // A malformed attribute (§18.9 defines no value part) makes the indication
    // undeliverable: nothing reaches the peer, and it is counted.
    let before = harness.turn.snapshot().rejected_df;
    let transaction_id = client.next_id();
    let indication = send_indication_with(
        &transaction_id,
        peer_addr,
        b"df-malformed",
        &[(ATTR_DONT_FRAGMENT, vec![1])],
    );
    send(&client.socket, &indication, harness.server).await;
    assert!(
        recv(&peer, 500).await.is_none(),
        "a malformed DONT-FRAGMENT must drop the indication (§11.2: treat it as unknown)"
    );
    assert!(
        harness.turn.snapshot().rejected_df > before,
        "a malformed DONT-FRAGMENT must be counted"
    );

    // §11.2: if the DF bit cannot be applied the indication is discarded (not
    // forwarded without the bit). A healthy socket never fails `setsockopt`, so
    // the test injects the failure through `df_failure`.
    let before = harness.turn.snapshot().rejected_df;
    df_failure::set(true);
    let transaction_id = client.next_id();
    let indication = send_indication_with(
        &transaction_id,
        peer_addr,
        b"df-cannot-apply",
        &[(ATTR_DONT_FRAGMENT, vec![])],
    );
    send(&client.socket, &indication, harness.server).await;
    let dropped = recv(&peer, 500).await;
    // Wait until the (dropped) request has been counted, so the flag is only
    // cleared once the server is done with it.
    let mut counted = false;
    for _ in 0..100 {
        if harness.turn.snapshot().rejected_df > before {
            counted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    df_failure::set(false);
    assert!(
        dropped.is_none(),
        "§11.2: an indication whose DF bit cannot be set must be discarded"
    );
    assert!(
        counted,
        "a DF application failure must be counted (rejected_df)"
    );
    // The allocation is untouched: a normal DF Send still relays afterwards.
    let transaction_id = client.next_id();
    let indication = send_indication_with(
        &transaction_id,
        peer_addr,
        b"df-after-failure",
        &[(ATTR_DONT_FRAGMENT, vec![])],
    );
    send(&client.socket, &indication, harness.server).await;
    assert_eq!(
        recv(&peer, 1000)
            .await
            .expect("the allocation survives a dropped indication"),
        b"df-after-failure"
    );
}

/// The capability flag must list exactly the platforms `set_dont_fragment`
/// implements, and `turn_unknown_attributes` must follow it (200 vs 420 is a
/// single decision, not two).
#[test]
fn dont_fragment_support_matches_the_platforms_that_can_set_the_bit() {
    assert_eq!(
        DONT_FRAGMENT_SUPPORTED,
        cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios"
        )),
        "DONT_FRAGMENT_SUPPORTED must match set_dont_fragment's platforms"
    );

    let mut body = Vec::new();
    protocol::push_attribute(&mut body, ATTR_DONT_FRAGMENT, &[]);

    // Both columns of the decision table, executable on any host: `false` is
    // exactly the Windows/FreeBSD answer (unknown → 420), `true` the
    // Linux/macOS one (known → 200/400/500).
    assert_eq!(
        turn_unknown_attributes_with(&body, false, false),
        vec![ATTR_DONT_FRAGMENT],
        "without a setsockopt path 0x001A must stay unknown"
    );
    assert!(
        turn_unknown_attributes_with(&body, true, false).is_empty(),
        "with a setsockopt path 0x001A is understood"
    );

    // And the process-wide wrapper follows the compile-time flag.
    assert_eq!(
        turn_unknown_attributes(&body).is_empty(),
        DONT_FRAGMENT_SUPPORTED,
        "the known-attribute set must follow the capability flag"
    );
}

/// RFC 6062 §5.1 step 3: a **TCP** `Allocate` carrying `DONT-FRAGMENT` is
/// `400 Bad Request` on every platform. On Windows/macOS-without-DF the 420 gate
/// used to fire first (`0x001A` unknown → `420`), which the Windows CI job
/// caught; the gate must let this shape through to the `400` branch, while a
/// **UDP** `Allocate` keeps the RFC 8656 §7.2 step 4 answer (`420`).
#[test]
fn tcp_allocate_dont_fragment_is_400_even_where_df_is_unsupported() {
    let mut body = Vec::new();
    protocol::push_attribute(
        &mut body,
        ATTR_REQUESTED_TRANSPORT,
        &[TRANSPORT_TCP, 0, 0, 0],
    );
    protocol::push_attribute(&mut body, ATTR_DONT_FRAGMENT, &[]);

    // The Windows column: DF cannot be set, but this is a TCP allocation, so
    // the gate must not produce a 420 (the allocation path answers 400).
    assert!(
        turn_unknown_attributes_with(&body, false, true).is_empty(),
        "TCP Allocate + DONT-FRAGMENT must reach the 400 branch on Windows"
    );
    assert!(
        turn_unknown_attributes_with(&body, true, true).is_empty(),
        "the same body is understood on the platform that can set DF"
    );
    // The wrapper derives the TCP shape from the body, so production follows the
    // same decision as the two columns above.
    assert!(turn_unknown_attributes(&body).is_empty());

    // A UDP Allocate with DF keeps the platform rule: unknown → 420 where the
    // bit cannot be set (RFC 8656 §7.2 step 4 explicitly allows it).
    let mut udp = Vec::new();
    protocol::push_attribute(
        &mut udp,
        ATTR_REQUESTED_TRANSPORT,
        &[TRANSPORT_UDP, 0, 0, 0],
    );
    protocol::push_attribute(&mut udp, ATTR_DONT_FRAGMENT, &[]);
    assert_eq!(
        turn_unknown_attributes_with(&udp, false, is_tcp_allocate(&udp)),
        vec![ATTR_DONT_FRAGMENT],
        "UDP Allocate + DF must stay 420 where DF is unsupported"
    );

    // End to end through the allocation path (no auth/network needed): the
    // attribute-presence check runs before ports and platforms, so this is the
    // same `400` on every host.
    let turn = Turn::new(
        Config {
            tcp_relay: true,
            ..Config::default()
        },
        "rstun/test",
    );
    let frame = request(
        ALLOCATE_METHOD,
        &transaction_id(77),
        &[
            (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_TCP, 0, 0, 0]),
            (ATTR_DONT_FRAGMENT, Vec::new()),
        ],
    );
    let message = protocol::parse(&frame).expect("parse");
    let identity = Identity {
        username: USER.to_string(),
        keys: vec![(
            KeyAlgorithm::Md5,
            auth::long_term_key(KeyAlgorithm::Md5, USER, REALM, PASS),
        )],
    };
    let context = ServerContext::default();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    match turn.allocate(
        &message,
        "127.0.0.1:5000".parse().unwrap(),
        "127.0.0.1:3478".parse().unwrap(),
        ClientTransport::Tcp,
        &context,
        Some(&sender),
        &identity,
    ) {
        Decision::Respond(response) => {
            assert_eq!(
                error_code(&response),
                Some(400),
                "TCP Allocate must answer 400 for DONT-FRAGMENT"
            );
        }
        other => panic!("expected a 400 response, got {other:?}"),
    }
}

#[tokio::test]
async fn permission_limit_and_per_ip_quota_are_enforced() {
    // Permission limit: one peer per allocation.
    let harness = start(Config {
        permission_limit: 1,
        ..Config::default()
    })
    .await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    assert_eq!(error_code(&client.allocate().await), None);
    // Permissions are keyed by peer IP, so the two peers only need distinct
    // addresses — nothing is ever sent to them. Do not bind sockets here:
    // `127.0.0.2` is only available on Linux (macOS needs an explicit lo0
    // alias), and binding would make this test platform-dependent.
    let first: SocketAddr = "198.51.100.10:9000".parse().unwrap();
    let second: SocketAddr = "198.51.100.11:9000".parse().unwrap();

    // B3: one request carrying more peers than the quota must install
    // **nothing** (the whole request is rejected atomically with 508).
    assert_eq!(
        error_code(&client.create_permission(&[first, second]).await),
        Some(508)
    );
    // If the failed request had partially installed `first`, this one would
    // already be over the limit; it must still succeed.
    assert_eq!(error_code(&client.create_permission(&[second]).await), None);
    assert_eq!(
        error_code(&client.create_permission(&[first]).await),
        Some(508)
    );
    assert!(harness.turn.snapshot().rejected_quota >= 1);

    // Per-IP quota: one allocation per client IP, even for another user.
    let harness = start(Config {
        max_allocations_per_ip: 1,
        ..Config::default()
    })
    .await;
    let mut first = Client::connect(harness.server).await;
    first.challenge().await;
    assert_eq!(error_code(&first.allocate().await), None);
    let mut second = Client::connect(harness.server).await;
    second.challenge().await;
    assert_eq!(error_code(&second.allocate().await), Some(486));
}

#[tokio::test]
async fn short_channel_data_is_ignored_without_panic() {
    let harness = start(Config::default()).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // One- and two-byte ChannelData prefixes used to be index panics.
    send(&client, &[0x40], harness.server).await;
    send(&client, &[0x40, 0x00], harness.server).await;
    // The listener must still answer a well-formed Binding request.
    let frame = request(protocol::BINDING_REQUEST, &transaction_id(9), &[]);
    send(&client, &frame, harness.server).await;
    let response = recv(&client, 1000).await.expect("server still serving");
    assert_eq!(
        protocol::parse(&response).unwrap().msg_type & 0x0110,
        0x0110
    );
}

#[tokio::test]
async fn another_user_on_the_same_tuple_gets_441() {
    let harness = start_with(Config::default(), long_term_auth_two_users()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client.allocate().await;
    assert_eq!(error_code(&response), None);
    let relay = relayed_address(&response);

    // Bob reuses Alice's socket (same 5-tuple) with his own credentials.
    client.set_identity("otheruser", "otherpass");
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(
        error_code(
            &client
                .request(
                    REFRESH_METHOD,
                    vec![(ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec())],
                )
                .await
        ),
        Some(441)
    );
    assert_eq!(
        error_code(
            &client
                .create_permission(&[peer.local_addr().unwrap()])
                .await
        ),
        Some(441)
    );
    // A `LIFETIME=0` from the wrong user must not delete the allocation.
    assert_eq!(
        error_code(
            &client
                .request(
                    REFRESH_METHOD,
                    vec![(ATTR_LIFETIME, 0_u32.to_be_bytes().to_vec())],
                )
                .await
        ),
        Some(441)
    );
    assert_eq!(harness.turn.active(), 1);

    // Alice can still use it, and the relay is unchanged.
    client.set_identity(USER, PASS);
    let response = client
        .request(
            REFRESH_METHOD,
            vec![(ATTR_LIFETIME, 300_u32.to_be_bytes().to_vec())],
        )
        .await;
    assert_eq!(error_code(&response), None);
    assert_eq!(harness.turn.active(), 1);
    // Touch the relay to show it is the same endpoint.
    assert_ne!(relay.port(), 0);
}

#[tokio::test]
async fn wildcard_listener_rejects_loopback_peers() {
    let harness = start_on("0.0.0.0:0", Config::default(), long_term_auth()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client.allocate().await;
    assert_eq!(error_code(&response), None);

    // The wildcard bind means the exact-address checks cannot see
    // 127.0.0.1:<listen-port>; the loopback rule must catch it.
    assert_eq!(
        error_code(&client.create_permission(&[harness.server]).await),
        Some(403)
    );
    assert_eq!(
        error_code(
            &client
                .create_permission(&["127.0.0.1:9".parse().unwrap()])
                .await
        ),
        Some(403)
    );
    assert!(harness.turn.snapshot().rejected_loopback >= 2);
}

#[tokio::test]
async fn allocate_zero_lifetime_uses_the_server_default() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    let response = client.allocate_with(0).await;
    assert_eq!(error_code(&response), None);
    assert_eq!(lifetime_of(&response), 600);
}

#[tokio::test]
async fn turn_metrics_appear_only_when_enabled() {
    let harness = start(Config::default()).await;
    let state =
        crate::ops::OpsState::new(Vec::new(), harness.stats.clone(), harness.context.clone());
    let text = state.metrics();
    assert!(text.contains("rstun_turn_allocations 0"));
    assert!(text.contains("rstun_turn_bytes_total{direction=\"in\"} 0"));
    assert!(text.contains("rstun_turn_allocations_total{result=\"created\"} 0"));
    assert!(text.contains("rstun_turn_rejected_total{reason=\"loopback\"} 0"));
    assert!(
        text.contains("rstun_turn_rejected_total{reason=\"df\"} 0"),
        "DONT-FRAGMENT failures have their own reason label"
    );
    // RFC 6062: gauges and per-reason counters, emitted with --turn.
    assert!(text.contains("rstun_turn_tcp_connections{state=\"pending\"} 0"));
    assert!(text.contains("rstun_turn_tcp_connections{state=\"bound\"} 0"));
    for reason in [
        "tcp_connect",
        "tcp_bind",
        "tcp_send",
        "tcp_buffer",
        "tcp_quota",
    ] {
        assert!(
            text.contains(&format!(
                "rstun_turn_rejected_total{{reason=\"{reason}\"}} 0"
            )),
            "missing TCP refusal reason {reason}"
        );
    }

    assert!(
        !text.contains("rstun_turn_tls_"),
        "certificate reload metrics need a secure listener"
    );

    let plain = Arc::new(ServerStats::default());
    let context = Arc::new(ServerContext {
        plan: None,
        udp: Vec::new(),
        mapped_address: false,
        admission: None,
        fingerprint: None,
        alternate_server: None,
        auth: None,
    });
    let state = crate::ops::OpsState::new(Vec::new(), plain, context);
    assert!(!state.metrics().contains("rstun_turn"));
}

/// Addresses that must never be turned into a permission, beyond the plain
/// loopback case: the limited broadcast, and IPv4-mapped IPv6 forms (whose
/// `is_loopback()` is false, so they have to be normalised before the
/// address-class checks run). A wildcard listener is used because a loopback
/// listener deliberately allows loopback peers (local development / `-y`).
#[tokio::test]
async fn broadcast_and_v4_mapped_peers_are_refused() {
    let harness = start(Config::default()).await;
    let mut client = Client::connect(harness.server).await;
    client.challenge().await;
    assert_eq!(error_code(&client.allocate().await), None);
    assert_eq!(
        error_code(
            &client
                .create_permission(&["255.255.255.255:9000".parse().unwrap()])
                .await
        ),
        Some(403)
    );

    let wildcard = start_on("0.0.0.0:0", Config::default(), long_term_auth()).await;
    let local = wildcard.context.udp[0].0;
    for peer in [
        "[::ffff:127.0.0.1]:9000",
        "[::ffff:0.0.0.0]:9000",
        "255.255.255.255:9000",
    ] {
        let address: SocketAddr = peer.parse().unwrap();
        assert!(
            wildcard
                .turn
                .is_own_endpoint(address, local, &wildcard.context),
            "{peer} must be refused"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 6062 (TCP allocations): outbound Connect + ConnectionBind
// ---------------------------------------------------------------------------

/// A TURN-over-TCP server harness (`serve_tcp`, the path `turnutils_uclient -T`
/// uses) with `--turn-tcp-relay` on.
struct TcpHarness {
    server: SocketAddr,
    turn: Arc<Turn>,
}

async fn start_tcp(config: Config) -> TcpHarness {
    start_tcp_with(config, long_term_auth()).await
}

async fn start_tcp_with(config: Config, auth: auth::Auth) -> TcpHarness {
    let listener = crate::tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let server = listener.local_addr().unwrap();
    let turn = Arc::new(Turn::new(config, "rstun/test"));
    let stats = Arc::new(ServerStats::default());
    stats.set_turn(turn.clone());
    let context = Arc::new(ServerContext {
        plan: None,
        udp: Vec::new(),
        mapped_address: false,
        admission: None,
        fingerprint: None,
        alternate_server: None,
        auth: Some(auth),
    });
    tokio::spawn(crate::serve_tcp(
        listener,
        context,
        Arc::from("rstun/test"),
        stats,
    ));
    TcpHarness { server, turn }
}

fn tcp_relay_config() -> Config {
    // Every harness needs its **own** relay port window: `tcp_relay_listener`
    // sets `SO_REUSEPORT`, so two concurrent tests that both took the lowest
    // free port of the same range would bind the *same* port and the kernel
    // would round-robin their peers between the two servers. (That is exactly
    // what the default range does, since each `Turn` keeps its own pool.)
    static NEXT_WINDOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let window = NEXT_WINDOW.fetch_add(1, Ordering::Relaxed);
    // `% 400` keeps the arithmetic inside `u16`: 20_000 + 399*100 = 59_900 is the
    // highest window start, so window N and N+400 share a port range (harmless:
    // a harness that far into the run reuses an early window's ports, and no
    // test is still listening there). Without the modulus the multiply would
    // overflow a `u16` at the 456th call (debug panic) and wrap at the 656th.
    let lo = 20_000 + (window % 400) as u16 * 100;
    Config {
        tcp_relay: true,
        relay_ports: (lo, lo + 99),
        ..Config::default()
    }
}

fn connection_id(response: &[u8]) -> Option<u32> {
    let message = protocol::parse(response).ok()?;
    let value = protocol::attributes(message.body)
        .find(|attribute| attribute.attr_type == ATTR_CONNECTION_ID)?
        .value;
    let bytes = <[u8; 4]>::try_from(value).ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// One TCP peer with a listener and an accept task.
async fn peer_listener() -> (tokio::net::TcpListener, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

/// Allocate a TCP relay and connect to `peer`; returns the connection id.
async fn allocate_and_connect(client: &mut TcpClient, peer: SocketAddr) -> (SocketAddr, u32) {
    let allocation = client.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None, "TCP Allocate");
    let relay = relayed_address(&allocation);
    let connected = client.connect_peer(peer).await;
    assert_eq!(error_code(&connected), None, "Connect");
    let id = connection_id(&connected).expect("CONNECTION-ID");
    (relay, id)
}

#[tokio::test]
async fn tcp_allocation_needs_the_switch_and_a_stream_control_connection() {
    // Switch off: the classic `442`, over TCP as well as UDP.
    let off = start_tcp(Config::default()).await;
    let mut client = TcpClient::connect(off.server).await;
    assert_eq!(error_code(&client.allocate_tcp().await), Some(442));

    // Switch on, UDP control connection: RFC 6062 §5.1 step 2 → 400.
    let on = start(Config {
        tcp_relay: true,
        ..Config::default()
    })
    .await;
    let mut udp = Client::connect(on.server).await;
    udp.challenge().await;
    let allocation = udp
        .request(
            ALLOCATE_METHOD,
            vec![(ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_TCP, 0, 0, 0])],
        )
        .await;
    assert_eq!(error_code(&allocation), Some(400));

    // Switch on, TCP control connection: 200 with a relayed address and no
    // CONNECTION-ID (RFC 6062 §5.1 adds none; coturn agrees).
    let harness = start_tcp(tcp_relay_config()).await;
    let mut client = TcpClient::connect(harness.server).await;
    let allocation = client.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None);
    let relay = relayed_address(&allocation);
    assert_ne!(relay.port(), 0);
    assert_eq!(
        connection_id(&allocation),
        None,
        "Allocate has no CONNECTION-ID"
    );
    assert!(
        attributes_of(&allocation)
            .iter()
            .any(|(attr, _)| *attr == protocol::ATTR_SOFTWARE)
    );
    // The relay is a real TCP listener: a plain connect succeeds.
    assert!(TcpStream::connect(relay).await.is_ok());

    // A UDP allocation still works on the same build (regression).
    let mut udp = Client::connect(on.server).await;
    udp.challenge().await;
    assert_eq!(error_code(&udp.allocate().await), None);
}

#[tokio::test]
async fn tcp_allocation_rejects_datagram_only_attributes() {
    let harness = start_tcp(tcp_relay_config()).await;
    for extra in [
        vec![(ATTR_DONT_FRAGMENT, Vec::new())],
        vec![(ATTR_EVEN_PORT, vec![0x80])],
        vec![(ATTR_RESERVATION_TOKEN, vec![0_u8; 8])],
    ] {
        let mut client = TcpClient::connect(harness.server).await;
        client
            .challenge_with(
                ALLOCATE_METHOD,
                vec![(ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_TCP, 0, 0, 0])],
            )
            .await;
        let mut attributes = vec![(ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_TCP, 0, 0, 0])];
        attributes.extend(extra);
        let response = client.request(ALLOCATE_METHOD, attributes).await;
        assert_eq!(
            error_code(&response),
            Some(400),
            "attribute must be refused"
        );
    }
}

#[tokio::test]
async fn connect_error_paths_follow_rfc_6062() {
    let harness = start_tcp(tcp_relay_config()).await;
    // No allocation on this connection → 437.
    let mut bare = TcpClient::connect(harness.server).await;
    bare.challenge().await;
    assert_eq!(
        error_code(&bare.connect_peer("127.0.0.1:9".parse().unwrap()).await),
        Some(437)
    );

    // A UDP allocation is not a TCP one: Connect → 437.
    let mut udp = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&udp.allocate_with(TRANSPORT_UDP).await), None);
    assert_eq!(
        error_code(&udp.connect_peer("127.0.0.1:9".parse().unwrap()).await),
        Some(437)
    );

    // Missing XOR-PEER-ADDRESS → 400.
    let mut client = TcpClient::connect(harness.server).await;
    let allocation = client.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None);
    assert_eq!(
        error_code(&client.request(CONNECT_METHOD, vec![]).await),
        Some(400)
    );

    // Forbidden local policy: unspecified / multicast / the relay itself → 403.
    let relay = relayed_address(&allocation);
    for peer in [
        "0.0.0.0:9000".parse().unwrap(),
        "239.1.2.3:9000".parse().unwrap(),
        relay,
    ] {
        assert_eq!(error_code(&client.connect_peer(peer).await), Some(403));
    }
    // Wrong address family → 443 (§5.2 uses the same rule as permissions).
    assert_eq!(
        error_code(&client.connect_peer("[::1]:9000".parse().unwrap()).await),
        Some(443)
    );

    // A peer that refuses the connection → 447.
    let (listener, closed) = peer_listener().await;
    drop(listener);
    assert_eq!(error_code(&client.connect_peer(closed).await), Some(447));
    assert!(client.turn_rejected_connect(harness.turn.as_ref()) >= 1);
}

#[tokio::test]
async fn connect_from_another_user_on_the_same_tuple_is_441() {
    let harness = start_tcp_with(tcp_relay_config(), long_term_auth_two_users()).await;
    let mut client = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&client.allocate_tcp().await), None);

    // Bob reuses Alice's TCP 5-tuple with his own (valid) credentials. The nonce
    // is IP-bound, not user-bound, so this authenticates and must then be
    // refused with `441` exactly like the other methods (§5 general rule).
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let transaction_id = client.next_id();
    let attributes = vec![
        (
            ATTR_XOR_PEER_ADDRESS,
            protocol::xor_mapped_address_value(peer, &transaction_id),
        ),
        (protocol::ATTR_USERNAME, b"otheruser".to_vec()),
        (protocol::ATTR_REALM, REALM.as_bytes().to_vec()),
        (protocol::ATTR_NONCE, client.nonce.as_bytes().to_vec()),
    ];
    let key = auth::long_term_key(KeyAlgorithm::Md5, "otheruser", REALM, "otherpass");
    let frame = auth::seal(
        request(CONNECT_METHOD, &transaction_id, &attributes),
        &Identity {
            username: "otheruser".to_string(),
            keys: vec![(KeyAlgorithm::Md5, key)],
        },
    );
    client.write(&frame).await;
    assert_eq!(error_code(&client.read_stun().await), Some(441));
    // Alice's allocation is untouched.
    assert_eq!(harness.turn.active(), 1);
}

impl TcpClient {
    fn turn_rejected_connect(&self, turn: &Turn) -> u64 {
        turn.snapshot().rejected_tcp_connect
    }
}

#[tokio::test]
async fn connect_is_idempotent_per_peer_only_until_the_first_succeeds() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move {
        let (stream, seen) = listener.accept().await.unwrap();
        (stream, seen)
    });
    let mut client = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&client.allocate_tcp().await), None);
    let first = client.connect_peer(peer_addr).await;
    assert_eq!(error_code(&first), None);
    assert!(
        connection_id(&first).is_some(),
        "Connect carries CONNECTION-ID"
    );
    // coturn alignment: `Connect ok` has no SOFTWARE.
    assert!(
        !attributes_of(&first)
            .iter()
            .any(|(attr, _)| *attr == protocol::ATTR_SOFTWARE)
    );
    // Same peer again (pending, not bound yet) → 446.
    assert_eq!(error_code(&client.connect_peer(peer_addr).await), Some(446));
    let _ = accept.await.expect("peer accepted");
}

#[tokio::test]
async fn connection_bind_relays_raw_bytes_both_ways() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move {
        let (stream, seen) = listener.accept().await.unwrap();
        (stream, seen)
    });
    let mut control = TcpClient::connect(harness.server).await;
    let (relay, id) = allocate_and_connect(&mut control, peer_addr).await;
    let (mut peer, seen) = accept.await.expect("peer accepted");
    // §5.2: the peer data connection originates from the relayed transport
    // address. Windows has no `SO_REUSEPORT`, so `dial_from_relay` falls back to
    // an ephemeral source port there (`RELAY_SOURCE_PORT_BOUND == false`): the
    // source IP is still the relay IP, only the port assertion is platform-bound.
    assert_eq!(seen.ip(), relay.ip(), "source IP must be the relay IP");
    if RELAY_SOURCE_PORT_BOUND {
        assert_eq!(seen.port(), relay.port(), "source must be the relay port");
    }

    // Peer speaks before the client binds: RFC 6062 §5.2 requires buffering.
    peer.write_all(b"early").await.unwrap();

    let mut data = TcpClient::connect(harness.server).await;
    let bound = data.connection_bind(id).await;
    assert_eq!(error_code(&bound), None, "ConnectionBind");
    assert!(
        attributes_of(&bound)
            .iter()
            .any(|(attr, _)| *attr == protocol::ATTR_SOFTWARE)
    );

    let mut early = [0_u8; 5];
    data.read_exact(&mut early).await;
    assert_eq!(
        &early, b"early",
        "pre-bind bytes are delivered after the bind"
    );

    data.write(b"client->peer").await;
    let mut towards_peer = [0_u8; 12];
    peer.read_exact(&mut towards_peer).await.unwrap();
    assert_eq!(&towards_peer, b"client->peer");

    peer.write_all(b"peer->client").await.unwrap();
    let mut towards_client = [0_u8; 12];
    data.read_exact(&mut towards_client).await;
    assert_eq!(&towards_client, b"peer->client");

    let snapshot = harness.turn.snapshot();
    assert_eq!(snapshot.tcp_bound, 1);
    assert_eq!(snapshot.bytes_in, 12);
    assert_eq!(snapshot.bytes_out, 5 + 12);
}

#[tokio::test]
async fn connection_bind_rejects_a_wrong_id_and_closes_the_connection() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let mut control = TcpClient::connect(harness.server).await;
    let (_, _id) = allocate_and_connect(&mut control, peer_addr).await;
    let _ = accept.await.expect("peer accepted");

    let mut data = TcpClient::connect(harness.server).await;
    let response = data.connection_bind(0xDEAD_BEEF).await;
    assert_eq!(error_code(&response), Some(400));
    // The server answers 400 and then closes (coturn sends a RST instead).
    let mut tail = [0_u8; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut data.stream, &mut tail),
    )
    .await
    .expect("connection closed")
    .expect("read");
    assert_eq!(read, 0);
    assert!(harness.turn.snapshot().rejected_tcp_bind >= 1);
}

#[tokio::test]
async fn half_close_propagates_in_both_directions() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream
    });
    let mut control = TcpClient::connect(harness.server).await;
    let (_, id) = allocate_and_connect(&mut control, peer_addr).await;
    let mut peer = accept.await.expect("peer accepted");
    let mut data = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&data.connection_bind(id).await), None);

    // client write-half closed → peer reads EOF, connection still usable.
    tokio::io::AsyncWriteExt::shutdown(&mut data.stream)
        .await
        .unwrap();
    let mut buffer = [0_u8; 16];
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await
    .expect("peer EOF")
    .expect("read");
    assert_eq!(read, 0, "client half-close reaches the peer as EOF");

    // peer → client still works after the client's EOF.
    peer.write_all(b"still-open").await.unwrap();
    let mut towards_client = [0_u8; 10];
    data.read_exact(&mut towards_client).await;
    assert_eq!(&towards_client, b"still-open");

    // peer write-half closed → client reads EOF; only now does the table drop.
    peer.shutdown().await.unwrap();
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut data.stream, &mut buffer),
    )
    .await
    .expect("client EOF")
    .expect("read");
    assert_eq!(read, 0, "peer half-close reaches the client as EOF");
    for _ in 0..100 {
        if harness.turn.snapshot().tcp_bound == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(harness.turn.snapshot().tcp_bound, 0);
}

#[tokio::test]
async fn lifetime_zero_closes_data_connections_and_frees_the_relay_port() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream
    });
    let mut control = TcpClient::connect(harness.server).await;
    let (relay, id) = allocate_and_connect(&mut control, peer_addr).await;
    let mut peer = accept.await.expect("peer accepted");
    let mut data = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&data.connection_bind(id).await), None);

    assert_eq!(error_code(&control.refresh(0).await), None);
    // Control connection stays open (deliberate difference from coturn, which
    // also tears the control connection down).
    assert_eq!(harness.turn.active(), 0);

    let mut buffer = [0_u8; 8];
    let peer_read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await
    .expect("peer closed")
    .expect("read");
    assert_eq!(peer_read, 0, "data connection closed with its allocation");
    let data_read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut data.stream, &mut buffer),
    )
    .await
    .expect("client data connection closed")
    .expect("read");
    assert_eq!(data_read, 0);
    assert_eq!(harness.turn.snapshot().tcp_bound, 0);

    // The TCP relay port is back in the pool: it can be bound again.
    let mut rebound = false;
    for _ in 0..100 {
        if crate::tcp_listener(relay).is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(rebound, "relay port {relay} must be free after LIFETIME=0");
}

#[tokio::test]
async fn pending_connection_is_closed_after_the_bind_window() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream
    });
    let mut control = TcpClient::connect(harness.server).await;
    let (_, _id) = allocate_and_connect(&mut control, peer_addr).await;
    let mut peer = accept.await.expect("peer accepted");
    assert_eq!(harness.turn.snapshot().tcp_pending, 1);
    // The sweep is what enforces the 30 s window; drive it directly.
    harness
        .turn
        .sweep(Instant::now() + TCP_BIND_TIMEOUT + Duration::from_secs(2));
    let mut buffer = [0_u8; 4];
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await
    .expect("peer closed")
    .expect("read");
    assert_eq!(read, 0, "an unbound peer data connection is closed");
    assert_eq!(harness.turn.snapshot().tcp_pending, 0);
}

#[tokio::test]
async fn channel_bind_and_send_are_refused_on_a_tcp_allocation() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut client = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&client.allocate_tcp().await), None);
    let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    let tid = client.next_id();
    let mut channel = CHANNEL_MIN.to_be_bytes().to_vec();
    channel.extend_from_slice(&[0, 0]);
    let bind = client.signed_frame(
        CHANNEL_BIND_METHOD,
        &tid,
        vec![
            (ATTR_CHANNEL_NUMBER, channel),
            (
                ATTR_XOR_PEER_ADDRESS,
                protocol::xor_mapped_address_value(peer, &tid),
            ),
        ],
    );
    client.write(&bind).await;
    assert_eq!(error_code(&client.read_stun().await), Some(400));

    // A `Send` indication on a TCP allocation is discarded and counted.
    let indication = send_indication(&transaction_id(9), peer, b"drop-me");
    client.write(&indication).await;
    for _ in 0..100 {
        if harness.turn.snapshot().rejected_tcp_send >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(harness.turn.snapshot().rejected_tcp_send, 1);
}

#[tokio::test]
async fn per_allocation_connection_quota_is_508() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut client = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&client.allocate_tcp().await), None);
    let mut listeners = Vec::new();
    for _ in 0..TCP_MAX_CONNECTIONS_PER_ALLOCATION {
        let (listener, address) = peer_listener().await;
        assert_eq!(
            error_code(&client.connect_peer(address).await),
            None,
            "connections below the cap are allowed"
        );
        listeners.push(listener);
    }
    let (extra_listener, extra_address) = peer_listener().await;
    assert_eq!(
        error_code(&client.connect_peer(extra_address).await),
        Some(508)
    );
    assert!(harness.turn.snapshot().rejected_tcp_quota >= 1);
    drop(extra_listener);
    drop(listeners);
}

#[tokio::test]
async fn connection_bind_cannot_replay_an_already_bound_id() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream
    });
    let mut control = TcpClient::connect(harness.server).await;
    let (_, id) = allocate_and_connect(&mut control, peer_addr).await;
    let _peer = accept.await.expect("peer accepted");
    let mut first = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&first.connection_bind(id).await), None);

    // A second connection replaying the same CONNECTION-ID is 400 + close.
    let mut replay = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&replay.connection_bind(id).await), Some(400));
    let mut tail = [0_u8; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut replay.stream, &mut tail),
    )
    .await
    .expect("replay connection closed")
    .expect("read");
    assert_eq!(read, 0);
    assert_eq!(harness.turn.snapshot().tcp_bound, 1);
}

#[tokio::test]
async fn pre_bind_buffer_overflow_closes_the_peer_connection() {
    let harness = start_tcp(tcp_relay_config()).await;
    let (listener, peer_addr) = peer_listener().await;
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream
    });
    let mut control = TcpClient::connect(harness.server).await;
    let (_, id) = allocate_and_connect(&mut control, peer_addr).await;
    let mut peer = accept.await.expect("peer accepted");
    // More than TCP_PREBIND_BUFFER arrives before the client binds.
    let flood = vec![0x5a_u8; TCP_PREBIND_BUFFER + 8 * 1024];
    peer.write_all(&flood).await.ok();
    for _ in 0..200 {
        if harness.turn.snapshot().rejected_tcp_buffer >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(harness.turn.snapshot().rejected_tcp_buffer, 1);
    // The connection is gone: the bind can no longer find it.
    let mut data = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&data.connection_bind(id).await), Some(400));
    assert_eq!(harness.turn.snapshot().tcp_pending, 0);
}

// ---------------------------------------------------------------------------
// RFC 6062 passive mode: peer dials the relay listener (§5.3)
// ---------------------------------------------------------------------------

/// Read a `ConnectionAttempt` off the control connection and return
/// `(CONNECTION-ID, XOR-PEER-ADDRESS, has SOFTWARE)`.
fn connection_attempt(frame: &[u8]) -> (u32, SocketAddr, bool) {
    let message = protocol::parse(frame).expect("ConnectionAttempt parses");
    assert_eq!(
        protocol::message_method(message.msg_type),
        CONNECTION_ATTEMPT_METHOD,
        "method must be ConnectionAttempt"
    );
    assert_eq!(
        protocol::message_class(message.msg_type),
        MessageClass::Indication,
        "ConnectionAttempt is an indication"
    );
    let attributes = attributes_of(frame);
    let id = connection_id(frame).expect("CONNECTION-ID");
    let peer = attributes
        .iter()
        .find(|(attr_type, _)| *attr_type == ATTR_XOR_PEER_ADDRESS)
        .and_then(|(_, value)| protocol::decode_xor_mapped_address(value, &message.transaction_id))
        .expect("XOR-PEER-ADDRESS");
    let software = attributes
        .iter()
        .any(|(attr_type, _)| *attr_type == protocol::ATTR_SOFTWARE);
    (id, peer, software)
}

/// Poll `predicate` for up to two seconds (tasks are asynchronous).
async fn eventually(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    predicate()
}

#[tokio::test]
async fn inbound_peer_is_announced_with_a_connection_attempt_and_binds() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut control = TcpClient::connect(harness.server).await;
    let allocation = control.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None, "TCP Allocate");
    let relay = relayed_address(&allocation);
    // Permission is per IP (RFC 8656 §8), so any 127.0.0.1 port covers the peer.
    assert_eq!(
        error_code(
            &control
                .create_permission_for("127.0.0.1:9".parse().unwrap())
                .await
        ),
        None,
        "CreatePermission"
    );

    // The peer dials the relayed transport address (§5.3 step 1).
    let mut peer = TcpStream::connect(relay).await.expect("relay accepts");
    let seen = peer.local_addr().unwrap();

    let attempt = control
        .read_stun_within(2000)
        .await
        .expect("ConnectionAttempt on the control connection");
    let (id, announced, software) = connection_attempt(&attempt);
    assert_eq!(announced, seen, "XOR-PEER-ADDRESS is the dialling peer");
    assert!(software, "SOFTWARE matches coturn's own indication");

    // §5.2 buffering also applies to the inbound half.
    peer.write_all(b"early").await.unwrap();

    let mut data = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&data.connection_bind(id).await), None, "bind");

    let mut buffered = [0_u8; 5];
    data.read_exact(&mut buffered).await;
    assert_eq!(&buffered, b"early", "pre-bind bytes arrive after the bind");

    data.write(b"client->peer").await;
    let mut towards_peer = [0_u8; 12];
    peer.read_exact(&mut towards_peer).await.unwrap();
    assert_eq!(&towards_peer, b"client->peer");

    peer.write_all(b"peer->client").await.unwrap();
    let mut towards_client = [0_u8; 12];
    data.read_exact(&mut towards_client).await;
    assert_eq!(&towards_client, b"peer->client");

    let snapshot = harness.turn.snapshot();
    assert_eq!(snapshot.tcp_bound, 1);
    assert_eq!(snapshot.bytes_in, 12);
    assert_eq!(snapshot.bytes_out, 5 + 12);
}

#[tokio::test]
async fn connection_attempt_can_go_out_over_a_datagram_sink() {
    // A TCP allocation can only be created on a TCP/TLS control connection
    // (RFC 6062 §5.1 step 2 answers 400 over UDP/DTLS), so the `ClientSink::Udp`
    // branch is not reachable from the wire. The encoder and the sink helper are
    // the shared pieces, so exercise them directly.
    let server = Arc::new(udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let peer: SocketAddr = "203.0.113.7:5000".parse().unwrap();

    let indication = connection_attempt_indication(0x1234_5678, peer, "rstun/test");
    let sink = ClientSink::Udp(server);
    assert!(send_to_client(&sink, indication, client_addr).await);

    let frame = recv(&client, 1000).await.expect("indication arrives");
    let (id, announced, software) = connection_attempt(&frame);
    assert_eq!(id, 0x1234_5678);
    assert_eq!(announced, peer);
    assert!(software);

    // A control connection that is gone (`Queue` whose writer task ended) makes
    // the announcement undeliverable: the caller drops the inbound connection
    // instead of leaving a pending entry nobody can bind.
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let closed = ClientSink::Queue(sender);
    assert!(
        !send_to_client(
            &closed,
            connection_attempt_indication(1, peer, "rstun/test"),
            client_addr
        )
        .await
    );
}

#[tokio::test]
async fn inbound_peer_without_permission_is_closed_without_an_attempt() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut control = TcpClient::connect(harness.server).await;
    let allocation = control.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None);
    let relay = relayed_address(&allocation);

    let mut peer = TcpStream::connect(relay).await.expect("relay accepts");
    let mut buffer = [0_u8; 1];
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await
    .expect("accepted then closed");
    assert!(
        matches!(outcome, Ok(0) | Err(_)),
        "no permission means the peer is closed with no payload"
    );
    assert!(
        control.read_stun_within(300).await.is_none(),
        "no ConnectionAttempt without a permission (§5.3 step 3)"
    );
    assert_eq!(harness.turn.snapshot().tcp_pending, 0);
}

#[tokio::test]
async fn inbound_connection_quota_closes_extra_peers() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut control = TcpClient::connect(harness.server).await;
    let allocation = control.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None);
    let relay = relayed_address(&allocation);
    assert_eq!(
        error_code(
            &control
                .create_permission_for("127.0.0.1:9".parse().unwrap())
                .await
        ),
        None
    );

    let mut peers = Vec::new();
    for index in 0..TCP_MAX_CONNECTIONS_PER_ALLOCATION {
        let peer = TcpStream::connect(relay).await.expect("relay accepts");
        peers.push(peer);
        let attempt = control
            .read_stun_within(2000)
            .await
            .unwrap_or_else(|| panic!("ConnectionAttempt #{index}"));
        assert!(connection_id(&attempt).is_some());
    }
    assert_eq!(
        harness.turn.snapshot().tcp_pending as usize,
        TCP_MAX_CONNECTIONS_PER_ALLOCATION
    );

    // The 17th is closed without an indication (there is no request to answer
    // with 508 on this path) and is counted as `tcp_quota`.
    let mut extra = TcpStream::connect(relay).await.expect("relay accepts");
    let mut buffer = [0_u8; 1];
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut extra, &mut buffer),
    )
    .await
    .expect("quota peer closed");
    assert!(matches!(outcome, Ok(0) | Err(_)));
    assert!(harness.turn.snapshot().rejected_tcp_quota >= 1);
    assert!(control.read_stun_within(300).await.is_none());
    drop(peers);
}

#[tokio::test]
async fn inbound_prebind_overflow_closes_and_counts() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut control = TcpClient::connect(harness.server).await;
    let allocation = control.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None);
    let relay = relayed_address(&allocation);
    assert_eq!(
        error_code(
            &control
                .create_permission_for("127.0.0.1:9".parse().unwrap())
                .await
        ),
        None
    );

    let mut peer = TcpStream::connect(relay).await.expect("relay accepts");
    let attempt = control.read_stun_within(2000).await.expect("attempt");
    let id = connection_id(&attempt).expect("CONNECTION-ID");

    let flood = vec![0x5a_u8; TCP_PREBIND_BUFFER + 8 * 1024];
    let _ = tokio::time::timeout(Duration::from_secs(2), peer.write_all(&flood)).await;
    assert!(
        eventually(|| harness.turn.snapshot().rejected_tcp_buffer >= 1).await,
        "the pre-bind cap must close the inbound connection"
    );
    let mut data = TcpClient::connect(harness.server).await;
    assert_eq!(error_code(&data.connection_bind(id).await), Some(400));
    assert_eq!(harness.turn.snapshot().tcp_pending, 0);
}

#[tokio::test]
async fn inbound_pending_connection_expires_without_a_bind() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut control = TcpClient::connect(harness.server).await;
    let allocation = control.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None);
    let relay = relayed_address(&allocation);
    assert_eq!(
        error_code(
            &control
                .create_permission_for("127.0.0.1:9".parse().unwrap())
                .await
        ),
        None
    );

    let mut peer = TcpStream::connect(relay).await.expect("relay accepts");
    assert!(control.read_stun_within(2000).await.is_some());
    assert_eq!(harness.turn.snapshot().tcp_pending, 1);

    harness
        .turn
        .sweep(Instant::now() + TCP_BIND_TIMEOUT + Duration::from_secs(2));
    let mut buffer = [0_u8; 4];
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await
    .expect("peer closed")
    .expect("read");
    assert_eq!(
        read, 0,
        "an unbound inbound connection is closed after 30 s"
    );
    assert_eq!(harness.turn.snapshot().tcp_pending, 0);
}

#[tokio::test]
async fn lifetime_zero_stops_the_inbound_accept_loop() {
    let harness = start_tcp(tcp_relay_config()).await;
    let mut control = TcpClient::connect(harness.server).await;
    let allocation = control.allocate_tcp().await;
    assert_eq!(error_code(&allocation), None);
    let relay = relayed_address(&allocation);
    assert_eq!(
        error_code(
            &control
                .create_permission_for("127.0.0.1:9".parse().unwrap())
                .await
        ),
        None
    );

    let mut peer = TcpStream::connect(relay).await.expect("relay accepts");
    assert!(control.read_stun_within(2000).await.is_some());

    assert_eq!(error_code(&control.refresh(0).await), None);
    assert_eq!(harness.turn.active(), 0);

    // §5.5: every data connection of the allocation goes away.
    let mut buffer = [0_u8; 4];
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await
    .expect("peer closed")
    .expect("read");
    assert_eq!(read, 0);

    // The accept task is aborted with the allocation, so the relay port stops
    // listening: new dials are refused instead of being accepted forever.
    let mut refused = false;
    for _ in 0..200 {
        match TcpStream::connect(relay).await {
            Err(_) => {
                refused = true;
                break;
            }
            Ok(stream) => {
                drop(stream);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    assert!(refused, "relay {relay} must stop accepting");
}

#[tokio::test]
async fn an_undeliverable_connection_attempt_closes_the_inbound_peer() {
    // The announcement can only fail when the control connection is gone, and
    // that also removes the allocation — so the branch is driven directly: one
    // accept loop with a `Queue` sink whose writer task has already ended.
    let listener = Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    let relay = listener.local_addr().unwrap();
    let now = Instant::now();
    let state = Arc::new(RwLock::new(AllocationState {
        expires_at: now + Duration::from_secs(60),
        permissions: HashMap::from([(relay.ip(), now + PERMISSION_LIFETIME)]),
        channels: HashMap::new(),
        inbound: TokenBucket::new(0, now),
        outbound: TokenBucket::new(0, now),
    }));
    let connections: Arc<Mutex<HashMap<u32, TcpConnection>>> = Arc::new(Mutex::new(HashMap::new()));
    let counters = Arc::new(Counters::default());
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let key = Key {
        client: "127.0.0.1:1234".parse().unwrap(),
        transport: ClientTransport::Tcp,
        server: relay,
    };
    let task = spawn_tcp_accept_loop(
        listener,
        key,
        USER.to_string(),
        "rstun/test".to_string(),
        state,
        ClientSink::Queue(sender),
        connections.clone(),
        counters.clone(),
    );

    let mut peer = TcpStream::connect(relay).await.expect("relay accepts");
    let mut buffer = [0_u8; 1];
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut peer, &mut buffer),
    )
    .await
    .expect("the inbound peer is closed");
    assert!(matches!(outcome, Ok(0) | Err(_)));
    assert_eq!(counters.rejected_tcp_send.load(Ordering::Relaxed), 1);
    assert!(
        lock_lock(&connections).is_empty(),
        "an unannounced connection must not stay pending"
    );
    task.abort();
}
