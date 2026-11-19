//! `rstun` 的解析路径 fuzz 目标。
//!
//! 公网 STUN 入口上，**任何**字节都会到达 `parse()`：一个 panic 就是一次 DoS
//! （tokio 任务 panic 只死一个任务，但 `--tcp` 连接任务与 UDP 监听共用同一批
//! 纯函数；越界/`unwrap` 一旦存在就是可远程触发）。所以这里不是「测 normal case」，
//! 而是把「任意字节」喂给每一条**没有网络副作用**的路径：
//!
//! 1. 分帧：`peek_frame_len`（TCP 用它决定读多少，错一字节就可能读挂连接）
//! 2. 解析：`parse` + 属性迭代器（`attributes` 的越界保护）
//! 3. 解码：`decode_xor_mapped_address` / `decode_address_value`（攻击者可控 value）
//! 4. 决策：`unknown_attributes` / `padding_len` / `response_port` / `change_request` /
//!    `check_fingerprint`（`--check-fingerprint` 开启时攻击者可达）
//! 5. 编码：`binding_success_response` / `unknown_attributes_response` / `error_response`
//!    （用数据派生的地址与长度；断言产出的字节仍能被自己的解析器读回）
//!
//! 不包含 `decide()` / socket 层：那些需要 tokio 与真实 socket，属于 e2e 测试，
//! 放进 fuzz 只会把预算耗在 bind 上。
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;

#[path = "../../src/crc32.rs"]
// `protocol.rs` 里 `use crate::crc32::crc32;`：fuzz 目标按路径单独引入源码时，
// 必须先把 crc32 放到 crate 根，否则 `cargo fuzz build` 会 unresolved import。
#[allow(dead_code)]
mod crc32;

#[path = "../../src/protocol.rs"]
// 只用到解析/编码相关的几个入口，其余 pub 函数在 fuzz 二进制里「未使用」是正常的。
#[allow(dead_code)]
mod protocol;

/// 从输入字节派生一个合法 `SocketAddr`（编码路径需要它，且不应由输入决定 family）。
fn peer_from(data: &[u8]) -> SocketAddr {
    let port = u16::from_be_bytes([*data.first().unwrap_or(&0), *data.get(1).unwrap_or(&0)]);
    if data.get(2).is_some_and(|byte| byte & 1 == 1) {
        let mut octets = [0_u8; 16];
        for (index, byte) in octets.iter_mut().enumerate() {
            *byte = *data.get(index).unwrap_or(&0);
        }
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
    } else {
        let mut octets = [0_u8; 4];
        for (index, byte) in octets.iter_mut().enumerate() {
            *byte = *data.get(index).unwrap_or(&0);
        }
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
    }
}

fuzz_target!(|data: &[u8]| {
    // 1. 分帧：任何输入都不能 panic。
    let _ = protocol::peek_frame_len(data);

    // 1b. FINGERPRINT 校验（`--check-fingerprint` 的攻击者可达路径）：纯函数，
    //     对任意字节都必须只回 verdict，不能 panic 或越界切片。
    let _ = protocol::check_fingerprint(data);

    // 2. 解析：不合法就结束（这是绝大多数输入的自然结局）。
    let Ok(message) = protocol::parse(data) else {
        return;
    };

    // 3. 属性迭代与逐个 value 解码。`parse` 已经校验过边界，迭代器自身也要安全。
    for attribute in protocol::attributes(message.body) {
        let _ = protocol::decode_xor_mapped_address(attribute.value, &message.transaction_id);
        let _ = protocol::decode_address_value(attribute.value);
        let _ = protocol::is_comprehension_required(attribute.attr_type);
        let _ = protocol::is_known_attribute(attribute.attr_type);
    }

    // 4. 决策前的纯函数：420 判定、PADDING 长度、RESPONSE-PORT、CHANGE-REQUEST。
    let unknown = protocol::unknown_attributes(message.body);
    let padding = protocol::padding_len(message.body).map(|length| length.min(2048));
    let _ = protocol::response_port(message.body);
    let _ = protocol::change_request(message.body);

    // 5. 编码路径：产物必须仍能被自己的解析器读回（自洽性/长度字段/padding）。
    let peer = peer_from(data);
    let response = protocol::binding_success_response(&protocol::SuccessResponse {
        transaction_id: &message.transaction_id,
        peer,
        software: "rstun/fuzz",
        addresses: Some(protocol::ResponseAddresses {
            origin: peer,
            other: SocketAddr::new(peer.ip(), peer.port().wrapping_add(1)),
        }),
        mapped_address: data.len() % 2 == 0,
        padding,
    });
    let reparsed = protocol::parse(&response);
    assert!(reparsed.is_ok(), "我们自己的响应必须能被自己解析");

    if !unknown.is_empty() {
        let response =
            protocol::unknown_attributes_response(&message.transaction_id, 0x0001, &unknown);
        assert!(protocol::parse(&response).is_ok(), "420 必须能被自己解析");
    } else {
        let response = protocol::error_response(
            &message.transaction_id,
            0x0001,
            protocol::ERROR_BAD_REQUEST,
            "Bad Request",
        );
        assert!(protocol::parse(&response).is_ok(), "400 必须能被自己解析");
    }
});
