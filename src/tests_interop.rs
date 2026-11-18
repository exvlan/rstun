//! T1 互操作：RFC 5769 测试向量 + `stun-types` 双向编解码。
//!
//! 为什么这些断言不能只靠「我们自己编、自己解」：自洽的编解码器可以两边同时错
//! （同一个 XOR 掩码写反、地址族字节写反、padding 算错），只有第三方产物的
//! **固定字节**能证明我们的实现对生态可用。这里是两层证据：
//!
//! * RFC 5769 §2.1–§2.4 的四段**标准字节**（请求、IPv4 响应、IPv6 响应、长凭证请求），
//!   全部来自 RFC 原文，不是我们生成的；
//! * `stun-types` 2.0.5（生态里活跃维护的 STUN 实现，`[dev-dependencies]`）双向：
//!   它编码的请求我们解析、我们编码的响应它解析。
//!
//! 与 `protocol.rs` 里的同类测试互补：那里验「我们 vs `stun-types` 的单个属性」，
//! 这里验「RFC 原文字节」以及「一条完整消息里所有属性同时对得上」。
//!
//! 有意**不**做的事：§2.1/§2.2/§2.3 的 `MESSAGE-INTEGRITY` / `FINGERPRINT` 只断言
//! 存在与长度。本服务器不做鉴权（见 `prd.md` 非目标），所以既不校验 HMAC，
//! 也不会在自己的响应里带这两个属性 —— 拿它当「我们支持鉴权」是误读。

use std::net::SocketAddr;

use crate::protocol::{
    self, ChangeRequest, MessageClass, SuccessResponse, TransactionId, message_class,
};

/// 十六进制串 → 字节（允许空格分组，方便与 RFC 排版对齐）。
fn hex_bytes(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "hex 长度必须是偶数");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
        .collect()
}

/// RFC 5769 §2.1：Sample Request（108 字节，Message Length 88）。
///
/// 一条**真实 ICE 客户端**会发的请求：SOFTWARE + PRIORITY + ICE-CONTROLLED +
/// USERNAME + MESSAGE-INTEGRITY + FINGERPRINT。我们既不支持鉴权、也不实现 ICE，
/// 但这些属性必须「认得」——否则正常 ICE 客户端会被打成 420。
const RFC5769_2_1: &str = "
    000100582112a442b7e7a701bc34d686fa87dfae
    802200105354554e207465737420636c69656e74
    002400046e0001ff
    80290008932ff9b151263b36
    000600096576746a3a68367659202020
    000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2
    80280004e57a3bcf
";

/// RFC 5769 §2.2：Sample IPv4 Response（80 字节，映射 192.0.2.1:32853）。
const RFC5769_2_2: &str = "
    0101003c2112a442b7e7a701bc34d686fa87dfae
    8022000b7465737420766563746f7220
    002000080001a147e112a643
    000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7
    80280004c07d4c96
";

/// RFC 5769 §2.3：Sample IPv6 Response（92 字节，映射 [2001:db8:1234:5678:11:2233:4455:6677]:32853）。
const RFC5769_2_3: &str = "
    010100482112a442b7e7a701bc34d686fa87dfae
    8022000b7465737420766563746f7220
    002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9
    00080014a382954e4be67bf11784c97c8292c275bfe3ed41
    80280004c8fb0b4c
";

/// RFC 5769 §2.4：Sample Request with Long-Term Authentication（116 字节）。
const RFC5769_2_4: &str = "
    000100602112a44278ad3433c6ad72c029da412e
    00060012e3839ee38388e383aae38383e382afe382b90000
    0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341
    0014000b6578616d706c652e6f726700
    00080014f67024656dd64a3e02b8e0712e85c9a28ca89666
";

fn attribute_of<'a>(message: &'a protocol::Message<'a>, attr_type: u16) -> &'a [u8] {
    protocol::attributes(message.body)
        .find(|attribute| attribute.attr_type == attr_type)
        .unwrap_or_else(|| panic!("响应缺少属性 0x{attr_type:04x}"))
        .value
}

#[test]
fn rfc5769_2_1_sample_request_is_understood() {
    let bytes = hex_bytes(RFC5769_2_1);
    assert_eq!(bytes.len(), 108, "RFC 5769 §2.1 是 108 字节");
    assert_eq!(protocol::peek_frame_len(&bytes), Ok(108), "TCP 分帧长度");

    let message = protocol::parse(&bytes).expect("RFC 5769 §2.1 必须能解析");
    assert_eq!(message.msg_type, protocol::BINDING_REQUEST);
    assert_eq!(message_class(message.msg_type), MessageClass::Request);
    assert_eq!(
        message.transaction_id.as_bytes(),
        &hex_bytes("b7e7a701bc34d686fa87dfae")[..]
    );

    assert_eq!(
        attribute_of(&message, protocol::ATTR_SOFTWARE),
        b"STUN test client"
    );
    assert_eq!(
        attribute_of(&message, protocol::ATTR_USERNAME),
        b"evtj:h6vY"
    );
    assert_eq!(
        attribute_of(&message, protocol::ATTR_MESSAGE_INTEGRITY).len(),
        20,
        "MESSAGE-INTEGRITY 是 20 字节 HMAC-SHA1（本服务器不校验，只确认认得）"
    );
    assert_eq!(attribute_of(&message, protocol::ATTR_PRIORITY).len(), 4);
    assert_eq!(
        attribute_of(&message, protocol::ATTR_ICE_CONTROLLED).len(),
        8
    );
    assert_eq!(attribute_of(&message, protocol::ATTR_FINGERPRINT).len(), 4);

    // 关键互操作结论：这条真实请求不会被我们打成 420。
    assert!(
        protocol::unknown_attributes(message.body).is_empty(),
        "RFC 5769 §2.1 里的属性全部必须在已知表内"
    );
    assert_eq!(protocol::change_request(message.body), None);
    assert_eq!(protocol::padding_len(message.body), None);
    assert_eq!(protocol::response_port(message.body), None);
}

#[test]
fn rfc5769_2_2_sample_ipv4_response_decodes_and_we_reencode_the_same_bytes() {
    let bytes = hex_bytes(RFC5769_2_2);
    assert_eq!(bytes.len(), 80, "RFC 5769 §2.2 是 80 字节");
    let message = protocol::parse(&bytes).expect("RFC 5769 §2.2 必须能解析");
    assert_eq!(message.msg_type, protocol::BINDING_SUCCESS_RESPONSE);
    assert_eq!(
        attribute_of(&message, protocol::ATTR_SOFTWARE),
        b"test vector"
    );

    let peer: SocketAddr = "192.0.2.1:32853".parse().unwrap();
    let reference = attribute_of(&message, protocol::ATTR_XOR_MAPPED_ADDRESS);
    assert_eq!(
        protocol::decode_xor_mapped_address(reference, &message.transaction_id),
        Some(peer),
        "RFC 的标准字节必须解出 192.0.2.1:32853"
    );

    // 反向：同一 transaction id / peer 下，我们编出来的 XOR-MAPPED-ADDRESS 必须与
    // RFC 的字节完全一致（掩码、端口异或、地址族都不能有偏差）。
    let response = protocol::binding_success_response(&SuccessResponse {
        transaction_id: &message.transaction_id,
        peer,
        software: "",
        addresses: None,
        mapped_address: false,
        padding: None,
    });
    let ours = protocol::parse(&response).unwrap();
    assert_eq!(
        attribute_of(&ours, protocol::ATTR_XOR_MAPPED_ADDRESS),
        reference
    );
}

#[test]
fn rfc5769_2_3_sample_ipv6_response_decodes_and_we_reencode_the_same_bytes() {
    let bytes = hex_bytes(RFC5769_2_3);
    assert_eq!(bytes.len(), 92, "RFC 5769 §2.3 是 92 字节");
    let message = protocol::parse(&bytes).expect("RFC 5769 §2.3 必须能解析");

    let peer: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
        .parse()
        .unwrap();
    let reference = attribute_of(&message, protocol::ATTR_XOR_MAPPED_ADDRESS);
    assert_eq!(reference.len(), 20, "IPv6 的 XOR-MAPPED-ADDRESS 是 20 字节");
    assert_eq!(
        protocol::decode_xor_mapped_address(reference, &message.transaction_id),
        Some(peer)
    );

    let response = protocol::binding_success_response(&SuccessResponse {
        transaction_id: &message.transaction_id,
        peer,
        software: "",
        addresses: None,
        mapped_address: false,
        padding: None,
    });
    let ours = protocol::parse(&response).unwrap();
    assert_eq!(
        attribute_of(&ours, protocol::ATTR_XOR_MAPPED_ADDRESS),
        reference,
        "IPv6 掩码是 cookie || transaction id，编解码必须一致"
    );
}

#[test]
fn rfc5769_2_4_long_term_auth_request_is_not_turned_into_420() {
    let bytes = hex_bytes(RFC5769_2_4);
    assert_eq!(bytes.len(), 116, "RFC 5769 §2.4 是 116 字节");
    let message = protocol::parse(&bytes).expect("RFC 5769 §2.4 必须能解析");

    assert_eq!(
        attribute_of(&message, protocol::ATTR_USERNAME),
        "マトリックス".as_bytes()
    );
    assert_eq!(attribute_of(&message, protocol::ATTR_REALM), b"example.org");
    assert_eq!(
        attribute_of(&message, protocol::ATTR_NONCE),
        b"f//499k954d6OL34oL9FSTvy64sA"
    );
    assert_eq!(
        attribute_of(&message, protocol::ATTR_MESSAGE_INTEGRITY).len(),
        20
    );

    // 长凭证请求带的是鉴权簇：我们不实现鉴权，但必须「认得」这些属性。
    assert!(
        protocol::unknown_attributes(message.body).is_empty(),
        "USERNAME/REALM/NONCE/MESSAGE-INTEGRITY 不得触发 420"
    );
}

/// `stun-types` 2.0.5 与我们的双向一致：它编的请求我们解、我们编的响应它解。
///
/// 与 `protocol.rs` 里逐属性对比的测试不同，这里走**完整消息**：
/// 头部类型、transaction id、属性顺序、以及「多属性同处一条消息」的 padding 计算。
#[test]
fn stun_types_bidirectional() {
    use stun_types::attribute::{RawAttribute, Software, Username};
    use stun_types::message::{
        BINDING, Message as ReferenceMessage, MessageWrite as _, MessageWriteExt as _,
        MessageWriteVec,
    };

    // ---- (A) 他们编码 → 我们解析 ----
    let mut writer = ReferenceMessage::builder_request(BINDING, MessageWriteVec::new());
    let software = Software::new("stun-types/interop").expect("SOFTWARE 值合法");
    writer.add_attribute(&software).expect("写 SOFTWARE");
    let username = Username::new("ufrag:pass").expect("USERNAME 值合法");
    writer.add_attribute(&username).expect("写 USERNAME");
    // CHANGE-REQUEST（0x0003）：`stun-types` 没有这个属性的类型化封装，
    // 用它的 RawAttribute 编码器写原始 TLV —— 那也是它的编码路径。
    let change_value = 0x0000_0002_u32.to_be_bytes();
    let change = RawAttribute::new(0x0003.into(), &change_value);
    writer.add_attribute(&change).expect("写 CHANGE-REQUEST");
    let request = writer.finish();

    let message = protocol::parse(&request).expect("必须能解析 stun-types 编的请求");
    assert_eq!(message_class(message.msg_type), MessageClass::Request);
    assert!(
        protocol::message_method(message.msg_type) == 0x0001,
        "method 必须是 Binding"
    );
    assert!(
        protocol::unknown_attributes(message.body).is_empty(),
        "stun-types 写的属性不得触发 420"
    );
    assert_eq!(
        attribute_of(&message, protocol::ATTR_SOFTWARE),
        b"stun-types/interop"
    );
    assert_eq!(
        protocol::change_request(message.body),
        Some(ChangeRequest {
            change_ip: false,
            change_port: true
        }),
        "0x02 是「换端口」（RFC 5780 §7.2 bit B）"
    );

    // ---- (B) 我们编码 → 他们解码 ----
    let transaction_id = TransactionId([0x5c; 12]);
    let peer: SocketAddr = "198.51.100.9:4242".parse().unwrap();
    let origin: SocketAddr = "203.0.113.7:34780".parse().unwrap();
    let other: SocketAddr = "203.0.113.8:34781".parse().unwrap();
    let response = protocol::binding_success_response(&SuccessResponse {
        transaction_id: &transaction_id,
        peer,
        software: "rstun/interop",
        addresses: Some(protocol::ResponseAddresses { origin, other }),
        mapped_address: true,
        padding: Some(32),
    });

    let reference =
        ReferenceMessage::from_bytes(&response).expect("stun-types 必须能解析我们的响应");
    assert!(reference.has_class(stun_types::message::MessageClass::Success));
    let mapped = reference
        .attribute::<stun_types::attribute::XorMappedAddress>()
        .expect("XOR-MAPPED-ADDRESS");
    assert_eq!(mapped.addr(reference.transaction_id()), peer);
    assert_eq!(
        reference
            .attribute::<Software>()
            .expect("SOFTWARE")
            .software(),
        "rstun/interop"
    );
    // MAPPED-ADDRESS 与 RFC 5780 的两个地址属性同格式（RFC 5389 §15.1 明文布局），
    // `stun-types` 没有把它们注册成「静态类型属性」，所以走通用 raw 迭代 +
    // 它自己的 `MappedSocketAddr::from_raw` 解码器。
    for (kind, expected) in [
        (protocol::ATTR_MAPPED_ADDRESS, peer),
        (protocol::ATTR_RESPONSE_ORIGIN, origin),
        (protocol::ATTR_OTHER_ADDRESS, other),
    ] {
        let (_, raw) = reference
            .iter_attributes()
            .find(|(_, attribute)| attribute.header.get_type().value() == kind)
            .unwrap_or_else(|| panic!("stun-types 没看到属性 0x{kind:04x}"));
        let decoded =
            stun_types::attribute::MappedSocketAddr::from_raw(&raw).expect("明文地址布局");
        assert_eq!(decoded.addr(), expected, "属性 0x{kind:04x}");
    }
    // PADDING 在我们的实现里是原始属性（`stun-types` 没有类型化封装）：
    // 用它的通用迭代器确认长度与位置，证明第三方按 TLV 也能读出来。
    let padding = reference
        .iter_attributes()
        .find(|(_, attribute)| attribute.header.get_type().value() == protocol::ATTR_PADDING)
        .expect("PADDING");
    assert_eq!(usize::from(padding.1.header.length()), 32);
}
