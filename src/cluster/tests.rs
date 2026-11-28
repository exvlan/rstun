//! Unit tests for the internal cluster protocol and the ownership ring. The
//! cross-instance TURN behaviour itself is tested in `turn::tests` with two
//! real `serve_udp` instances.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

const SECRET: &[u8] = b"cluster-test-secret";

fn address(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[test]
fn frames_round_trip_with_and_without_a_secret() {
    for secret in [None, Some(SECRET)] {
        let payload = vec![0xAB; 40];
        let bytes = encode_frame(FrameType::Request, 7, &payload, secret);
        let frame = decode_datagram(&bytes, secret).expect("frame must decode");
        assert_eq!(
            frame,
            Frame {
                kind: FrameType::Request,
                session: 7,
                payload,
            }
        );
        // The reserved byte is 0 and the length covers payload + tag.
        assert_eq!(bytes[7], 0);
        let expected_tail = if secret.is_some() { HMAC_TAG_LEN } else { 0 };
        assert_eq!(
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            40 + expected_tail
        );
    }
}

#[test]
fn a_wrong_hmac_is_refused_and_so_is_an_unsigned_frame() {
    let mut bytes = encode_frame(FrameType::PushData, 1, b"hello", Some(SECRET));
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    assert_eq!(
        decode_datagram(&bytes, Some(SECRET)),
        Err(FrameError::BadHmac)
    );

    let unsigned = encode_frame(FrameType::PushData, 1, b"hello", None);
    assert_eq!(
        decode_datagram(&unsigned, Some(SECRET)),
        Err(FrameError::BadHmac)
    );
    assert!(decode_datagram(&unsigned, None).is_ok());
}

#[test]
fn unknown_types_and_flags_are_refused() {
    let mut bytes = encode_frame(FrameType::Ping, 1, &[], None);
    bytes[4] = 0x7F;
    assert_eq!(
        decode_datagram(&bytes, None),
        Err(FrameError::UnknownType(0x7F))
    );

    let mut bytes = encode_frame(FrameType::Ping, 1, &[], None);
    bytes[6] = 0x80;
    assert_eq!(
        decode_datagram(&bytes, None),
        Err(FrameError::UnknownFlags(0x0080))
    );

    let mut bytes = encode_frame(FrameType::Ping, 1, &[], None);
    bytes[..4].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
    assert_eq!(decode_datagram(&bytes, None), Err(FrameError::TooLarge));
}

#[test]
fn endpoint_and_payload_round_trip_both_families() {
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 5000);
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 6000);
    for (client, transport, payload) in [
        (v4, TransportClass::Udp, b"v4".as_slice()),
        (v6, TransportClass::Tcp, b"v6".as_slice()),
    ] {
        let endpoint = encode_endpoint(client);
        let expected_endpoint = if client.is_ipv4() { 10 } else { 22 };
        assert_eq!(endpoint.len(), expected_endpoint);
        let (decoded_client, rest) = decode_endpoint(&endpoint).expect("endpoint must decode");
        assert_eq!(decoded_client, client);
        assert!(rest.is_empty());

        // Full payload: session | endpoint | transport | listen_port | datagram.
        let encoded = encode_payload(42, client, transport, 3478, payload);
        let (session, decoded_client, decoded_transport, listen_port, datagram) =
            decode_payload(&encoded).expect("payload must decode");
        assert_eq!(session, 42);
        assert_eq!(decoded_client, client);
        assert_eq!(decoded_transport, transport);
        assert_eq!(listen_port, 3478);
        assert_eq!(datagram, payload);
    }
    // A truncated endpoint/payload is a refusal, never a panic.
    assert!(decode_endpoint(&[0x02, 0, 0, 0, 0, 1]).is_none());
    assert!(decode_endpoint(&[0x03, 0, 0, 0, 0, 1, 0, 0]).is_none());
    assert!(decode_payload(&[0, 0]).is_none());
}

/// Design D2/D3: the wildcard address a UDP listener sees and the concrete
/// local address a TCP connection sees must normalize to the same key. This is
/// what makes a client's allocation findable on every instance.
#[test]
fn the_server_address_normalizes_to_the_listen_port() {
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 40000);
    let wildcard = NodeKey::new(client, TransportClass::Udp, normalized_server(3478));
    let concrete = NodeKey::new(client, TransportClass::Udp, address(3478));
    assert_eq!(wildcard, concrete);
    // The canonical Key.server value itself is identical too.
    assert_eq!(normalized_server(3478), normalized_server(3478));
    assert_eq!(
        normalized_server(3478).ip(),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    );
    // A different listen port is a different 5-tuple.
    assert_ne!(
        wildcard,
        NodeKey::new(client, TransportClass::Udp, address(3479))
    );
    // The transport class is part of the key.
    assert_ne!(
        wildcard,
        NodeKey::new(client, TransportClass::Tcp, normalized_server(3478))
    );
    // IPv4-mapped IPv6 is the same client.
    let mapped = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc633, 0x6409)),
        40000,
    );
    assert_eq!(
        NodeKey::new(mapped, TransportClass::Udp, normalized_server(3478)),
        wildcard
    );
}

fn members(ids: &[(&str, u16)]) -> Vec<Member> {
    ids.iter()
        .map(|(id, port)| Member {
            id: (*id).to_string(),
            addr: address(*port),
        })
        .collect()
}

#[test]
fn the_ring_is_deterministic_and_never_names_a_non_member() {
    let forward = Membership::new(members(&[("a", 7001), ("b", 7002), ("c", 7003)])).unwrap();
    let shuffled = Membership::new(members(&[("c", 7003), ("a", 7001), ("b", 7002)])).unwrap();
    let ids: Vec<&str> = forward.members().iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, vec!["a", "b", "c"], "members are sorted by id");
    for client_port in 0..1000_u16 {
        let key = NodeKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), client_port),
            TransportClass::Udp,
            normalized_server(3478),
        );
        let owner = forward.owner(&key);
        assert_eq!(owner, shuffled.owner(&key), "same key, same owner");
        assert!(forward.members().contains(owner));
    }
}

#[test]
fn membership_rejects_duplicate_ids_and_empty_lists() {
    assert!(Membership::new(Vec::new()).is_err());
    let duplicate = members(&[("a", 7001), ("a", 7002)]);
    assert!(Membership::new(duplicate).is_err());
}

#[test]
fn config_needs_members_and_a_secret_on_public_addresses() {
    let private = Config {
        instance_id: "a".to_string(),
        listen: address(7001),
        peers: members(&[("a", 7001), ("b", 7002)]),
        secret: None,
        listen_port: 3478,
        tls_port: None,
        dtls_port: None,
        tcp_relay_ports: None,
        tls_listen: Vec::new(),
        dtls_listen: Vec::new(),
    };
    assert!(private.validate().is_ok());

    let mut empty = private.clone();
    empty.peers.clear();
    assert!(empty.validate().is_err());

    let mut duplicate = private.clone();
    duplicate.peers.push(Member {
        id: "a".to_string(),
        addr: address(7001),
    });
    assert!(duplicate.validate().is_err());

    let mut self_conflict = private.clone();
    self_conflict.peers[0].addr = address(7999);
    assert!(self_conflict.validate().is_err());

    // Public listener without a secret: refused. With one: accepted.
    let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), 7001);
    let mut exposed = private.clone();
    exposed.listen = public;
    exposed.peers = members(&[("a", 7001), ("b", 7002)]);
    exposed.peers[0].addr = public;
    assert!(exposed.validate().is_err());
    exposed.secret = Some(SECRET.to_vec());
    assert!(exposed.validate().is_ok());
}

#[test]
fn a_config_without_a_self_entry_adds_itself_to_the_ring() {
    let config = Config {
        instance_id: "b".to_string(),
        listen: address(7002),
        peers: members(&[("a", 7001)]),
        secret: None,
        listen_port: 3478,
        tls_port: None,
        dtls_port: None,
        tcp_relay_ports: None,
        tls_listen: Vec::new(),
        dtls_listen: Vec::new(),
    };
    let membership = config.membership().unwrap();
    let ids: Vec<&str> = membership.members().iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, vec!["a", "b"]);
}

#[test]
fn hello_requires_identical_ports_and_disjoint_tcp_ranges() {
    let own = Hello {
        version: HELLO_VERSION,
        instance_id: "a".to_string(),
        listen_port: 3478,
        tls_port: 5349,
        dtls_port: 5350,
        tcp_relay_ports: (50000, 50099),
        member_count: 2,
        member_digest: [1; 8],
    };
    let mut peer = own.clone().with_id("b");
    peer.tcp_relay_ports = (50100, 50199);
    assert!(check_hello_ports(&own, &peer).is_ok());

    // A different plain port is exactly the shape that would split one client
    // into two allocations: refused with an actionable message.
    let mut other = own.clone().with_id("b");
    other.listen_port = 3479;
    let error = check_hello_ports(&own, &other).expect_err("port mismatch must fail");
    assert!(error.contains("same --listen port"), "{error}");

    let mut other = own.clone().with_id("b");
    other.tls_port = 0;
    assert!(check_hello_ports(&own, &other).is_err());

    let mut other = own.clone().with_id("b");
    other.tcp_relay_ports = (50050, 50149);
    let error = check_hello_ports(&own, &other).expect_err("overlapping TCP ranges must fail");
    assert!(error.contains("disjoint"), "{error}");

    let mut other = own.clone().with_id("b");
    other.tcp_relay_ports = (50100, 50199);
    assert!(check_hello_ports(&own, &other).is_ok());

    let mut other = own.clone().with_id("b");
    other.tcp_relay_ports = (0, 0);
    assert!(check_hello_ports(&own, &other).is_err());
}

impl Hello {
    fn with_id(mut self, id: &str) -> Self {
        self.instance_id = id.to_string();
        self
    }
}

// ---------------------------------------------------------------------------
// B3: the whole member set must match
// ---------------------------------------------------------------------------

#[test]
fn hello_requires_the_same_member_set() {
    let own = Hello {
        version: HELLO_VERSION,
        instance_id: "a".to_string(),
        listen_port: 3478,
        tls_port: 0,
        dtls_port: 0,
        tcp_relay_ports: (0, 0),
        member_count: 2,
        member_digest: [1; 8],
    };
    let mut peer = own.clone().with_id("b");
    assert!(check_hello_members(&own, &peer).is_ok());

    peer.member_count = 3;
    let error = check_hello_members(&own, &peer).expect_err("a missing member must fail");
    assert!(error.contains("--cluster-peer"), "{error}");

    peer.member_count = 2;
    peer.member_digest = [2; 8];
    assert!(check_hello_members(&own, &peer).is_err());

    // The port/range check stays independent of the member set.
    assert!(check_hello_ports(&own, &peer).is_ok());
}

// ---------------------------------------------------------------------------
// B4: wildcard listeners and frame provenance
// ---------------------------------------------------------------------------

fn cluster_config(id: &str, listen: &str) -> Config {
    let listen: SocketAddr = listen.parse().expect("cluster address");
    Config {
        instance_id: id.to_string(),
        listen,
        peers: vec![Member {
            id: id.to_string(),
            addr: listen,
        }],
        secret: None,
        listen_port: 3478,
        tls_port: None,
        dtls_port: None,
        tcp_relay_ports: None,
        tls_listen: Vec::new(),
        dtls_listen: Vec::new(),
    }
}

/// A wildcard control listener is reachable from every interface, so it needs a
/// secret just like a public address (B4).
#[test]
fn a_wildcard_cluster_listener_needs_a_secret() {
    for listen in ["0.0.0.0:7001", "[::]:7001"] {
        let mut config = cluster_config("a", listen);
        // A distinct peer id so the self-conflict check does not mask this one.
        config.peers = members(&[("b", 7002)]);
        let error = config.validate().expect_err("wildcard without secret");
        assert!(error.contains("--cluster-secret"), "{error}");
        assert!(error.contains("wildcard"), "{error}");
        config.secret = Some(b"secret".to_vec());
        assert!(config.validate().is_ok());
    }
}

#[tokio::test]
async fn a_push_client_from_the_wrong_instance_is_dropped() {
    use tokio::sync::mpsc;

    let (cluster, _listener) = Cluster::bind(cluster_config("a", "127.0.0.1:0"))
        .await
        .expect("bind");
    let (sender, mut receiver) = mpsc::channel(4);
    let session = cluster.register_session(sender);
    let client: SocketAddr = "198.51.100.9:5000".parse().unwrap();
    cluster.claim_session_owner(session, "b");
    let mut body = encode_endpoint(client);
    body.extend_from_slice(b"payload");
    let frame = Frame {
        kind: FrameType::PushClient,
        session,
        payload: body,
    };
    let mut writer = Vec::new();
    // A third instance must not be able to write into this client connection.
    cluster
        .serve_inbound_frame(frame.clone(), &mut writer, Some("c"))
        .await
        .unwrap();
    assert!(receiver.try_recv().is_err());
    // The owner can.
    cluster
        .serve_inbound_frame(frame, &mut writer, Some("b"))
        .await
        .unwrap();
    assert_eq!(receiver.try_recv().unwrap(), b"payload");

    // A session that was never claimed has no legitimate sender either.
    let (sender, mut receiver) = mpsc::channel(1);
    let session = cluster.register_session(sender);
    let mut body = encode_endpoint(client);
    body.push(b'x');
    cluster
        .serve_inbound_frame(
            Frame {
                kind: FrameType::PushClient,
                session,
                payload: body,
            },
            &mut writer,
            Some("b"),
        )
        .await
        .unwrap();
    assert!(receiver.try_recv().is_err());
}

/// N2: a full raw-relay queue must not silently truncate the byte stream; the
/// entry aborts the session instead (the client sees a closed connection).
#[tokio::test]
async fn a_full_raw_relay_queue_aborts_the_session() {
    use tokio::sync::mpsc;

    let (cluster, _listener) = Cluster::bind(cluster_config("a", "127.0.0.1:0"))
        .await
        .expect("bind");
    let (sender, _receiver) = mpsc::channel(1);
    let session = cluster.register_session(sender);
    cluster.claim_session_owner(session, "b");
    let mut close = cluster.session_close(session).expect("session close");
    let mut writer = Vec::new();
    // Capacity 1: the first frame fills the queue, the second overflows.
    for payload in [b"one".to_vec(), b"two".to_vec()] {
        cluster
            .serve_inbound_frame(
                Frame {
                    kind: FrameType::RawRelay,
                    session,
                    payload,
                },
                &mut writer,
                Some("b"),
            )
            .await
            .unwrap();
    }
    close.changed().await.expect("close signal");
    assert_eq!(*close.borrow(), RAW_CLOSE_ABORT);
}

// ---------------------------------------------------------------------------
// S1: the relay address is resolved from the right listener kind
// ---------------------------------------------------------------------------

#[test]
fn owner_local_resolves_each_transport_listener() {
    let mut config = cluster_config("a", "127.0.0.1:7001");
    config.tls_port = Some(5349);
    config.dtls_port = Some(5350);
    config.tls_listen = vec!["127.0.0.2:5349".parse().unwrap()];
    config.dtls_listen = vec!["127.0.0.3:5350".parse().unwrap()];
    let context = crate::ServerContext::default();
    assert_eq!(
        owner_local(&config, &context, ClientTransport::Tcp, 5349),
        "127.0.0.2:5349".parse().unwrap(),
        "a TLS request must resolve the TLS listener's own IP"
    );
    assert_eq!(
        owner_local(&config, &context, ClientTransport::Dtls, 5350),
        "127.0.0.3:5350".parse().unwrap()
    );
    // No listener on that port: the canonical wildcard is the loud fallback.
    assert_eq!(
        owner_local(&config, &context, ClientTransport::Udp, 3478),
        normalized_server(3478)
    );
}

/// N2 (owner side): if the data connection stops reading, a full inbound
/// `RAW_RELAY` queue must abort the relay instead of dropping bytes.
#[tokio::test]
async fn a_full_owner_raw_queue_aborts_the_relay() {
    let (cluster, _listener) = Cluster::bind(cluster_config("a", "127.0.0.1:0"))
        .await
        .expect("bind");
    let entry = Member {
        id: "b".to_string(),
        addr: "127.0.0.1:7999".parse().unwrap(),
    };
    let session = 7;
    let _raw = cluster.open_raw(&entry, session);
    let key = (entry.id.clone(), session);
    assert!(lock_lock(&cluster.raw_in).contains_key(&key));
    // Capacity RAW_CAPACITY: fill it and then one more.
    let mut writer = Vec::new();
    for _ in 0..=RAW_CAPACITY {
        cluster
            .serve_inbound_frame(
                Frame {
                    kind: FrameType::RawRelay,
                    session,
                    payload: b"chunk".to_vec(),
                },
                &mut writer,
                Some("b"),
            )
            .await
            .unwrap();
    }
    assert!(
        !lock_lock(&cluster.raw_in).contains_key(&key),
        "an overflowing raw relay must be torn down, not truncated"
    );
}

/// N-c: the HELLO payload grew with the member digest; a v1 peer must get a
/// clear "version not supported" instead of "malformed HELLO".
#[test]
fn a_hello_from_another_protocol_version_is_refused() {
    let own = Hello {
        version: HELLO_VERSION,
        instance_id: "a".to_string(),
        listen_port: 3478,
        tls_port: 0,
        dtls_port: 0,
        tcp_relay_ports: (0, 0),
        member_count: 2,
        member_digest: [1; 8],
    };
    let mut peer = own.clone().with_id("b");
    assert!(check_hello_version(&peer).is_ok());
    peer.version = 1;
    let error = check_hello_version(&peer).expect_err("v1 must be refused");
    assert!(
        error.contains("version 1 is not supported (expected 2)"),
        "{error}"
    );
}

/// N-f: the derived HELLO port and the listener address list must agree.
#[test]
fn config_rejects_a_port_listener_mismatch() {
    let mut config = cluster_config("a", "127.0.0.1:7001");
    config.tls_port = Some(5349);
    let error = config.validate().expect_err("port without a listener");
    assert!(error.contains("disagree"), "{error}");
    config.tls_listen = vec!["127.0.0.1:5349".parse().unwrap()];
    assert!(config.validate().is_ok());

    let mut config = cluster_config("a", "127.0.0.1:7001");
    config.dtls_listen = vec!["127.0.0.1:5350".parse().unwrap()];
    assert!(config.validate().is_err());
    config.dtls_port = Some(5350);
    assert!(config.validate().is_ok());
}
