//! rstun 互操作：webrtc-rs 的 `stun` crate（0.17）作为第三方编解码 + 客户端。
//!
//! 与 pion 那一份同构：请求用 `stun` 的 Setter 编码、响应用它的 Decoder 解码，
//! 所以「webrtc-rs 能不能读我们的包」就是第三方互操作结论。双向在同一次交换里
//! 同时成立（他们编码 → 我们解析；我们编码 → 他们解析）。
//!
//! 该 crate 只提供编解码与客户端（没有 STUN 服务端），因此「我们发 → 他们答」
//! 只到编解码层；真实的网络方向由 coturn 那一项覆盖。
//!
//! 由 `script/lab/rstun-interop.sh webrtc-stun` 调用（临时 cargo 工程建在 /tmp 下）。

use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use stun::attributes::{
    ATTR_CHANGE_REQUEST, ATTR_ERROR_CODE, ATTR_PADDING, ATTR_RESPONSE_ORIGIN, ATTR_SOFTWARE,
    ATTR_UNKNOWN_ATTRIBUTES, AttrType,
};
use stun::message::{
    BINDING_ERROR, BINDING_REQUEST, BINDING_SUCCESS, Getter, Message, MessageType,
};
use stun::xoraddr::XorMappedAddress;

const ATTR_USERNAME: AttrType = AttrType(0x0006);
const ATTR_MESSAGE_INTEGRITY: AttrType = AttrType(0x0008);
const ATTR_PRIORITY: AttrType = AttrType(0x0024);
const ATTR_USE_CANDIDATE: AttrType = AttrType(0x0025);
const ATTR_ICE_CONTROLLING: AttrType = AttrType(0x802a);
const ATTR_FINGERPRINT: AttrType = AttrType(0x8028);
const ATTR_RESPONSE_PORT: AttrType = AttrType(0x0027);
const ATTR_OTHER_ADDRESS: AttrType = AttrType(0x802c);
/// 未实现但 comprehension-required：必须被 420 点名。
const ATTR_UNKNOWN_FOR_TEST: AttrType = AttrType(0x0033);

const CHANGE_PORT: u32 = 0x02;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut server = "127.0.0.1:34780".to_string();
    let mut mode = "basic".to_string();
    let mut alt_port: Option<u16> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--server" => {
                server = args[index + 1].clone();
                index += 2;
            }
            "--mode" => {
                mode = args[index + 1].clone();
                index += 2;
            }
            "--alt-port" => {
                alt_port = Some(args[index + 1].parse().expect("--alt-port 需要端口"));
                index += 2;
            }
            other => panic!("未知参数 {other}"),
        }
    }

    // `response-port` 需要第二个 socket 收包，走单独路径（见下）。
    if mode == "response-port" {
        let addr: SocketAddr = server.parse().expect("--server 需要 host:port");
        response_port_probe(addr);
        return;
    }

    let mut failures = 0_usize;
    let mut check = |condition: bool, message: String| {
        if condition {
            println!("ok: {message}");
        } else {
            failures += 1;
            println!("FAIL: {message}");
        }
    };

    // ---- 他们编码：用 webrtc-rs 的 Setter 组一条 Binding Request ----
    let mut request = Message::new();
    request
        .build(&[Box::new(BINDING_REQUEST)])
        .expect("webrtc-rs 编码 Binding Request");
    let transaction_id = request.transaction_id;
    match mode.as_str() {
        "basic" | "tcp" | "ipv6" | "response-port" => {}
        "ice" => {
            request.add(ATTR_USERNAME, b"ufrag:pass");
            request.add(ATTR_MESSAGE_INTEGRITY, &[0_u8; 20]);
            request.add(ATTR_PRIORITY, &0x6e00_01ff_u32.to_be_bytes());
            request.add(ATTR_USE_CANDIDATE, &[]);
            request.add(ATTR_ICE_CONTROLLING, &[0x11_u8; 8]);
            request.add(ATTR_FINGERPRINT, &[0_u8; 4]);
        }
        "unknown" => {
            request.add(ATTR_UNKNOWN_FOR_TEST, &[0xde, 0xad, 0xbe, 0xef]);
        }
        "rfc5780" => {
            request.add(ATTR_CHANGE_REQUEST, &CHANGE_PORT.to_be_bytes());
        }
        "padding" => {
            request.add(ATTR_PADDING, &[0x5a_u8; 200]);
        }
        other => panic!("未知 mode {other}"),
    }
    let request_bytes = request.raw.clone();
    let server_addr: SocketAddr = server.parse().expect("--server 需要 host:port");

    // ---- 网络：UDP 用未连接 socket（CHANGE-REQUEST 的回包会来自另一个源地址）----
    let (response, local, from): (Vec<u8>, SocketAddr, SocketAddr) = if mode == "tcp" {
        let mut stream = TcpStream::connect(server_addr).expect("TCP 连接");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set_read_timeout");
        std::io::Write::write_all(&mut stream, &request_bytes).expect("TCP 写");
        let mut header = [0_u8; 20];
        std::io::Read::read_exact(&mut stream, &mut header).expect("TCP 读头");
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut response = vec![0_u8; 20 + length];
        response[..20].copy_from_slice(&header);
        std::io::Read::read_exact(&mut stream, &mut response[20..]).expect("TCP 读体");
        (
            response,
            stream.local_addr().expect("local_addr"),
            server_addr,
        )
    } else {
        let bind_ip = if server_addr.is_ipv6() {
            IpAddr::from(std::net::Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::from(std::net::Ipv4Addr::LOCALHOST)
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).expect("UDP bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set_read_timeout");
        socket.send_to(&request_bytes, server_addr).expect("UDP 发");
        let mut buffer = [0_u8; 65535];
        let (length, from) = socket.recv_from(&mut buffer).expect("UDP 收");
        (
            buffer[..length].to_vec(),
            socket.local_addr().expect("local_addr"),
            from,
        )
    };

    // ---- 他们解码：webrtc-rs 解析 rstun 的响应 ----
    let mut message = Message::new();
    match message.unmarshal_binary(&response) {
        Ok(()) => check(
            true,
            format!(
                "webrtc-rs 解码响应 type={:?} length={} attrs={}",
                message.typ,
                message.length,
                message.attributes.0.len()
            ),
        ),
        Err(error) => {
            check(false, format!("webrtc-rs 无法解码 rstun 的响应: {error}"));
            std::process::exit(1);
        }
    }

    match mode.as_str() {
        "basic" | "tcp" | "ipv6" => {
            check(
                message.typ == BINDING_SUCCESS,
                format!("响应类型 = {:?}", message.typ),
            );
            check(
                message.transaction_id == transaction_id,
                "transaction id 原样回显".to_string(),
            );
            let mut mapped = XorMappedAddress::default();
            let parsed = mapped.get_from(&message).is_ok();
            check(parsed, "webrtc-rs 解出 XOR-MAPPED-ADDRESS".to_string());
            check(
                SocketAddr::new(mapped.ip, mapped.port) == local,
                format!(
                    "XOR-MAPPED-ADDRESS = {}:{}（本地 {}）",
                    mapped.ip, mapped.port, local
                ),
            );
            let software = message.attributes.get(ATTR_SOFTWARE).0.value.clone();
            check(
                !software.is_empty(),
                format!(
                    "webrtc-rs 解出 SOFTWARE = {:?}",
                    String::from_utf8_lossy(&software)
                ),
            );
        }
        "ice" => {
            check(
                message.typ == BINDING_SUCCESS,
                format!(
                    "带 ICE/鉴权属性的请求仍返回 {:?}（没有被 420）",
                    message.typ
                ),
            );
            check(
                !message.attributes.get(ATTR_UNKNOWN_ATTRIBUTES).1,
                "响应里没有 UNKNOWN-ATTRIBUTES".to_string(),
            );
        }
        "unknown" => {
            check(
                message.typ == BINDING_ERROR,
                format!("响应类型 = {:?}", message.typ),
            );
            let (raw, present) = message.attributes.get(ATTR_ERROR_CODE);
            let code = if present && raw.value.len() >= 4 {
                u16::from(raw.value[2] & 0x07) * 100 + u16::from(raw.value[3])
            } else {
                0
            };
            check(code == 420, format!("ERROR-CODE = {code}（期望 420）"));
            let (raw, present) = message.attributes.get(ATTR_UNKNOWN_ATTRIBUTES);
            check(present, "带 UNKNOWN-ATTRIBUTES".to_string());
            check(
                raw.value.len() == 2,
                format!("UNKNOWN-ATTRIBUTES value 长度 = 2N = {}", raw.value.len()),
            );
            if raw.value.len() >= 2 {
                let listed = u16::from_be_bytes([raw.value[0], raw.value[1]]);
                check(
                    listed == ATTR_UNKNOWN_FOR_TEST.value(),
                    format!("点名的属性 = 0x{listed:04x}"),
                );
            }
        }
        "padding" => {
            check(
                message.typ == BINDING_SUCCESS,
                format!("带 PADDING 的请求返回 {:?}", message.typ),
            );
            let (raw, present) = message.attributes.get(ATTR_PADDING);
            check(
                present && raw.value.len() == 200,
                format!("PADDING 回显 {} 字节（请求 200）", raw.value.len()),
            );
            check(
                response.len() <= request_bytes.len() + 64,
                format!(
                    "响应没有因 PADDING 放大（{} → {}）",
                    request_bytes.len(),
                    response.len()
                ),
            );
        }
        "rfc5780" => {
            check(
                message.typ == BINDING_SUCCESS,
                format!("CHANGE-REQUEST 请求返回 {:?}", message.typ),
            );
            let origin = message.attributes.get(ATTR_RESPONSE_ORIGIN);
            let other = message.attributes.get(ATTR_OTHER_ADDRESS);
            check(origin.1, "带 RESPONSE-ORIGIN".to_string());
            check(other.1, "带 OTHER-ADDRESS".to_string());
            let origin = decode_plain_address(&origin.0.value);
            let other = decode_plain_address(&other.0.value);
            check(
                origin.is_some(),
                format!("webrtc-rs 解出 RESPONSE-ORIGIN = {origin:?}"),
            );
            check(
                other.is_some(),
                format!("webrtc-rs 解出 OTHER-ADDRESS = {other:?}"),
            );
            if let (Some(origin), Some(alt_port)) = (origin, alt_port) {
                check(
                    origin == SocketAddr::new(from.ip(), alt_port),
                    format!(
                        "RESPONSE-ORIGIN 是换端口后的源地址 {origin}（回包源 {from}，alt-port {alt_port}）"
                    ),
                );
            }
        }
        _ => unreachable!(),
    }

    if failures > 0 {
        println!("webrtc-stun/{mode}: {failures} 条断言失败");
        std::process::exit(1);
    }
    println!("webrtc-stun/{mode} 通过");
    // 顺带确认 webrtc-rs 认得出这两个消息类型常量（编译期契约）。
    let _ = (BINDING_REQUEST, BINDING_SUCCESS);
    let _: MessageType = BINDING_ERROR;
}

/// RFC 5780 §7.5 的**目的端口**语义：回包发往 `client_ip:RESPONSE-PORT`，
/// 源地址/源端口保持入口 socket 不变。
///
/// 用两个独立 socket：回包不回请求源端口，connected socket 会把它丢掉。
fn response_port_probe(server: SocketAddr) {
    let bind_ip = IpAddr::from(std::net::Ipv4Addr::LOCALHOST);
    let inbox = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).expect("inbox bind");
    let client = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).expect("client bind");
    for socket in [&inbox, &client] {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set_read_timeout");
    }
    let mut failures = 0_usize;
    let mut check = |condition: bool, message: String| {
        if condition {
            println!("ok: {message}");
        } else {
            failures += 1;
            println!("FAIL: {message}");
        }
    };

    let inbox_port = inbox.local_addr().expect("inbox local_addr").port();
    let mut request = Message::new();
    request
        .build(&[Box::new(BINDING_REQUEST)])
        .expect("webrtc-rs 编码 Binding Request");
    request.add(ATTR_RESPONSE_PORT, &inbox_port.to_be_bytes());
    client
        .send_to(&request.raw, server)
        .expect("向 rstun 发 RESPONSE-PORT 请求");

    let mut buffer = [0_u8; 4096];
    let (length, from) = inbox
        .recv_from(&mut buffer)
        .expect("RESPONSE-PORT 指定的端口没有收到回包");
    check(length >= 20, format!("回包至少 20 字节（{length}）"));
    check(
        from.port() == server.port(),
        format!(
            "回包源端口仍是入口端口 {}（实际 {}）",
            server.port(),
            from.port()
        ),
    );

    let mut message = Message::new();
    match message.unmarshal_binary(&buffer[..length]) {
        Ok(()) => check(
            true,
            format!("webrtc-rs 解码发往 RESPONSE-PORT 的响应（{} 字节）", length),
        ),
        Err(error) => {
            check(false, format!("webrtc-rs 无法解码该响应: {error}"));
            std::process::exit(1);
        }
    }
    let mut mapped = XorMappedAddress::default();
    check(
        mapped.get_from(&message).is_ok(),
        "webrtc-rs 解出 XOR-MAPPED-ADDRESS".to_string(),
    );
    check(
        SocketAddr::new(mapped.ip, mapped.port) == client.local_addr().expect("client local_addr"),
        format!(
            "XOR-MAPPED-ADDRESS = 请求源地址 {}（实际 {}:{}）",
            client.local_addr().expect("client local_addr"),
            mapped.ip,
            mapped.port
        ),
    );

    // 请求源端口必须保持安静，否则就是「同时发两份」，不是 RESPONSE-PORT 语义。
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set_read_timeout");
    match client.recv_from(&mut buffer) {
        Ok(_) => check(false, "请求源端口不应收到第二份响应".to_string()),
        Err(_) => check(true, "请求源端口没有收到第二份响应".to_string()),
    }

    if failures > 0 {
        println!("webrtc-stun/response-port: {failures} 条断言失败");
        std::process::exit(1);
    }
    println!("webrtc-stun/response-port 通过");
}

/// `0 | family | port | address`（RFC 5389 §15.1 的明文布局）。
fn decode_plain_address(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }
    let port = u16::from_be_bytes([value[2], value[3]]);
    let ip = match value[1] {
        0x01 => IpAddr::from(<[u8; 4]>::try_from(&value[4..8]).ok()?),
        0x02 => IpAddr::from(<[u8; 16]>::try_from(&value[4..20]).ok()?),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}
