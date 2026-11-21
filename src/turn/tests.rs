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
    let mut body = Vec::new();
    protocol::push_attribute(
        &mut body,
        ATTR_XOR_PEER_ADDRESS,
        &protocol::xor_mapped_address_value(peer, transaction_id),
    );
    protocol::push_attribute(&mut body, ATTR_DATA, data);
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
}

#[test]
fn unknown_comprehension_required_attributes_are_reported() {
    let mut body = Vec::new();
    protocol::push_attribute(&mut body, ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    protocol::push_attribute(&mut body, 0x001A, &[]); // DONT-FRAGMENT: unsupported
    assert_eq!(turn_unknown_attributes(&body), vec![0x001A]);

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

    // REQUESTED-TRANSPORT=6 (TCP allocation, RFC 6062) is out of scope → 442.
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

    // DONT-FRAGMENT is comprehension-required and unsupported → 420.
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (0x001A, Vec::new()),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(420));
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

    // DONT-FRAGMENT stays unsupported (RFC 8656 §7.2 step 4 allows the 420).
    let response = client
        .request(
            ALLOCATE_METHOD,
            vec![
                (ATTR_REQUESTED_TRANSPORT, vec![TRANSPORT_UDP, 0, 0, 0]),
                (0x001A, Vec::new()),
            ],
        )
        .await;
    assert_eq!(error_code(&response), Some(420));
    let unknown = attributes_of(&response)
        .into_iter()
        .find(|(attr_type, _)| *attr_type == protocol::ATTR_UNKNOWN_ATTRIBUTES)
        .expect("UNKNOWN-ATTRIBUTES")
        .1;
    assert_eq!(unknown, vec![0x00, 0x1A]);
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
