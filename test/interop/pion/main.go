// rstun 互操作：pion/stun（Go）作为第三方编解码 + 客户端。
//
// 这个程序**不链接 rstun 的任何代码**：请求用 pion 的 Setter 编码、
// 响应用 pion 的 Decoder 解码，所以「pion 能不能读我们的包」就是第三方互操作结论。
// 双向在同一次交换里同时成立：
//
//	· 他们发 → 我们答：pion 编码的请求被 rstun 解析并应答；
//	· 我们发 → 他们答：rstun 编码的响应被 pion 解析，属性逐个断言。
//
// 由 `script/lab/rstun-interop.sh pion` 调用（临时 module 建在 /tmp 下，不入库）。
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/stun/v3"
)

const (
	attrChangeRequest    = stun.AttrType(0x0003)
	attrUsername         = stun.AttrType(0x0006)
	attrMessageIntegrity = stun.AttrType(0x0008)
	attrErrorCode        = stun.AttrType(0x0009)
	attrUnknownAttrs     = stun.AttrType(0x000a)
	attrPriority         = stun.AttrType(0x0024)
	attrUseCandidate     = stun.AttrType(0x0025)
	attrPadding          = stun.AttrType(0x0026)
	attrResponsePort     = stun.AttrType(0x0027)
	attrFingerprint      = stun.AttrType(0x8028)
	attrIceControlling   = stun.AttrType(0x802a)
	attrResponseOrigin   = stun.AttrType(0x802b)
	attrOtherAddress     = stun.AttrType(0x802c)

	changePort = 0x02

	// 未实现但 comprehension-required：必须被 420 点名。
	attrUnknownForTest = stun.AttrType(0x0033)
)

var failures int

func check(condition bool, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if condition {
		fmt.Printf("ok: %s\n", message)
		return
	}
	failures++
	fmt.Printf("FAIL: %s\n", message)
}

func attribute(attrType stun.AttrType, value []byte) stun.RawAttribute {
	return stun.RawAttribute{Type: attrType, Value: value}
}

// exchange 发一条请求，读一条响应；TCP 时按 RFC 5389 §7.2.2 的头长度分帧。
// 返回响应字节、本地地址（= 服务端看到的客户端地址）、回包源地址。
//
// UDP 必须用**未连接**的 socket：RFC 5780 的 CHANGE-REQUEST 会让回包从另一个
// 源地址发出，connected socket 会被内核直接丢弃（表现为「超时」，很容易误判成
// 服务端没回）。
func exchange(network, server string, request []byte) ([]byte, string, net.Addr, error) {
	if network == "tcp" {
		conn, err := net.DialTimeout(network, server, 3*time.Second)
		if err != nil {
			return nil, "", nil, err
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return nil, "", nil, err
		}
		if _, err := conn.Write(request); err != nil {
			return nil, "", nil, err
		}
		buffer := make([]byte, 65535)
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, "", nil, err
		}
		if n < 20 {
			return nil, "", nil, fmt.Errorf("响应不足 20 字节（%d）", n)
		}
		length := int(binary.BigEndian.Uint16(buffer[2:4]))
		for n < 20+length {
			chunk, readErr := conn.Read(buffer[n:])
			if readErr != nil {
				return nil, "", nil, readErr
			}
			n += chunk
		}
		return append([]byte(nil), buffer[:20+length]...), conn.LocalAddr().String(),
			conn.RemoteAddr(), nil
	}

	remote, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, "", nil, err
	}
	// 绑到与服务同一个 IP（回环矩阵里就是 127.0.0.1 / ::1）：LocalAddr 才有意义，
	// 也能收到来自「另一个 IP 的同一个端口」的回包。
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: remote.IP, Zone: remote.Zone})
	if err != nil {
		return nil, "", nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, "", nil, err
	}
	if _, err := conn.WriteToUDP(request, remote); err != nil {
		return nil, "", nil, err
	}
	buffer := make([]byte, 65535)
	n, from, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return nil, "", nil, err
	}
	if n < 20 {
		return nil, "", nil, fmt.Errorf("响应不足 20 字节（%d）", n)
	}
	length := int(binary.BigEndian.Uint16(buffer[2:4]))
	if n < 20+length {
		return nil, "", nil, fmt.Errorf("响应被截断：%d < %d", n, 20+length)
	}
	return append([]byte(nil), buffer[:20+length]...), conn.LocalAddr().String(), from, nil
}

func decode(data []byte) (*stun.Message, error) {
	message := &stun.Message{Raw: data}
	if err := message.Decode(); err != nil {
		return nil, err
	}
	return message, nil
}

func errorCode(message *stun.Message) (int, bool) {
	value, err := message.Get(attrErrorCode)
	if err != nil || len(value) < 4 {
		return 0, false
	}
	return int(value[2]&0x07)*100 + int(value[3]), true
}

func decodePlainAddress(value []byte) (string, error) {
	if len(value) < 8 {
		return "", fmt.Errorf("地址属性太短（%d 字节）", len(value))
	}
	port := int(binary.BigEndian.Uint16(value[2:4]))
	switch value[1] {
	case 0x01:
		return fmt.Sprintf("%s:%d", net.IP(value[4:8]).String(), port), nil
	case 0x02:
		return fmt.Sprintf("[%s]:%d", net.IP(value[4:20]).String(), port), nil
	default:
		return "", fmt.Errorf("未知地址族 0x%02x", value[1])
	}
}

// runResponsePort 验证 RFC 5780 §7.5 的**目的端口**语义：回包发往
// `client_ip:RESPONSE-PORT`，而源地址/源端口仍是服务入口 socket。
//
// 这条不能用普通 connected socket 验：回包故意不回请求源端口，connected socket
// 会直接丢掉它（看起来像「服务端没回」）。
func runResponsePort(server string) {
	remote, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	inbox, err := net.ListenUDP("udp", loopback)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	defer inbox.Close()
	client, err := net.ListenUDP("udp", loopback)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	if err := inbox.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}

	inboxPort := uint16(inbox.LocalAddr().(*net.UDPAddr).Port)
	value := []byte{byte(inboxPort >> 8), byte(inboxPort), 0, 0}
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest,
		attribute(attrResponsePort, value))
	if _, err := client.WriteToUDP(request.Raw, remote); err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}

	buffer := make([]byte, 4096)
	n, from, err := inbox.ReadFromUDP(buffer)
	if err != nil {
		fmt.Printf("FAIL: RESPONSE-PORT 指定的端口没有收到回包: %v\n", err)
		os.Exit(1)
	}
	check(n >= 20, "回包至少 20 字节（%d）", n)
	check(from.Port == remote.Port, "回包源端口仍是入口端口 %d（实际 %d）", remote.Port, from.Port)
	message, err := decode(buffer[:n])
	if err != nil {
		fmt.Printf("FAIL: pion 无法解码发往 RESPONSE-PORT 的响应: %v\n", err)
		os.Exit(1)
	}
	check(message.Type == stun.BindingSuccess, "响应类型 = %s", message.Type)
	mapped := stun.XORMappedAddress{}
	check(mapped.GetFrom(message) == nil, "pion 解出 XOR-MAPPED-ADDRESS")
	check(mapped.String() == client.LocalAddr().String(),
		"XOR-MAPPED-ADDRESS = 请求源地址 %s（实际 %s）", client.LocalAddr(), mapped.String())

	// 请求源端口必须保持安静：回包只发往 RESPONSE-PORT。
	if err := client.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	if _, _, err := client.ReadFromUDP(buffer); err == nil {
		check(false, "请求源端口不应收到第二份响应")
	} else {
		check(true, "请求源端口没有收到第二份响应")
	}

	if failures > 0 {
		fmt.Printf("pion/response-port: %d 条断言失败\n", failures)
		os.Exit(1)
	}
	fmt.Println("pion/response-port 通过")
}

func main() {
	server := flag.String("server", "127.0.0.1:34780", "被测 rstun 地址")
	mode := flag.String("mode", "basic", "basic|ice|unknown|rfc5780|padding|response-port|tcp")
	altPort := flag.Int("alt-port", 0, "RFC 5780 第二端口（rfc5780 模式）")
	flag.Parse()

	var setters []stun.Setter
	switch *mode {
	case "basic", "tcp":
		// 只有头：最接近 `nc` 手发的 20 字节。
	case "ice":
		setters = append(setters,
			attribute(attrUsername, []byte("ufrag:pass")),
			attribute(attrMessageIntegrity, make([]byte, 20)),
			attribute(attrPriority, []byte{0x6e, 0x00, 0x01, 0xff}),
			attribute(attrUseCandidate, nil),
			attribute(attrIceControlling, []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}),
			attribute(attrFingerprint, make([]byte, 4)),
		)
	case "unknown":
		setters = append(setters, attribute(attrUnknownForTest, []byte{0xde, 0xad, 0xbe, 0xef}))
	case "rfc5780":
		setters = append(setters, attribute(attrChangeRequest, []byte{0x00, 0x00, 0x00, changePort}))
	case "padding":
		setters = append(setters, attribute(attrPadding, make([]byte, 200)))
	case "response-port":
		// 下面单独走一条路径（需要第二个 socket 收包），这里不构造属性。
	default:
		fmt.Fprintf(os.Stderr, "未知 mode %q\n", *mode)
		os.Exit(2)
	}

	if *mode == "response-port" {
		runResponsePort(*server)
		return
	}

	request := stun.MustBuild(append([]stun.Setter{stun.TransactionID, stun.BindingRequest}, setters...)...)
	network := "udp"
	if *mode == "tcp" {
		network = "tcp"
	}
	response, local, from, err := exchange(network, *server, request.Raw)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	message, err := decode(response)
	if err != nil {
		fmt.Printf("FAIL: pion 无法解码 rstun 的响应: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("ok: pion 解码响应 type=%s length=%d attrs=%d\n",
		message.Type, len(response)-20, len(message.Attributes))

	switch *mode {
	case "basic", "tcp":
		check(message.Type == stun.BindingSuccess, "响应类型 = %s", message.Type)
		check(message.TransactionID == request.TransactionID, "transaction id 原样回显")
		mapped := stun.XORMappedAddress{}
		check(mapped.GetFrom(message) == nil, "pion 解出 XOR-MAPPED-ADDRESS")
		check(mapped.String() == local, "XOR-MAPPED-ADDRESS = %s（本地 %s）", mapped.String(), local)
		software := stun.Software{}
		check(software.GetFrom(message) == nil, "pion 解出 SOFTWARE = %q", string(software))
	case "ice":
		check(message.Type == stun.BindingSuccess,
			"带 ICE/鉴权属性的请求仍返回 %s（没有被 420）", message.Type)
		check(!message.Contains(attrUnknownAttrs), "响应里没有 UNKNOWN-ATTRIBUTES")
	case "unknown":
		check(message.Type == stun.BindingError, "响应类型 = %s", message.Type)
		code, ok := errorCode(message)
		check(ok && code == 420, "ERROR-CODE = %d（期望 420）", code)
		listed, err := message.Get(attrUnknownAttrs)
		check(err == nil, "带 UNKNOWN-ATTRIBUTES")
		check(len(listed) == 2, "UNKNOWN-ATTRIBUTES value 长度 = 2N = %d", len(listed))
		if len(listed) >= 2 {
			check(binary.BigEndian.Uint16(listed) == attrUnknownForTest.Value(),
				"点名的属性 = 0x%04x", binary.BigEndian.Uint16(listed))
		}
	case "padding":
		check(message.Type == stun.BindingSuccess, "带 PADDING 的请求返回 %s", message.Type)
		echoed, err := message.Get(attrPadding)
		check(err == nil && len(echoed) == 200, "PADDING 回显 %d 字节（请求 200）", len(echoed))
		check(len(response) <= len(request.Raw)+64,
			"响应没有因 PADDING 放大（%d → %d）", len(request.Raw), len(response))
	case "rfc5780":
		check(message.Type == stun.BindingSuccess, "CHANGE-REQUEST 请求返回 %s", message.Type)
		origin, err := message.Get(attrResponseOrigin)
		check(err == nil, "带 RESPONSE-ORIGIN")
		other, err := message.Get(attrOtherAddress)
		check(err == nil, "带 OTHER-ADDRESS")
		decodedOrigin, originErr := decodePlainAddress(origin)
		decodedOther, otherErr := decodePlainAddress(other)
		check(originErr == nil, "pion 解出 RESPONSE-ORIGIN = %s", decodedOrigin)
		check(otherErr == nil, "pion 解出 OTHER-ADDRESS = %s", decodedOther)
		if *altPort != 0 {
			host, _, splitErr := net.SplitHostPort(*server)
			if splitErr != nil {
				host = *server
			}
			expected := net.JoinHostPort(host, fmt.Sprint(*altPort))
			check(decodedOrigin == expected,
				"RESPONSE-ORIGIN 是换端口后的源地址 %s", decodedOrigin)
			// 属性只是「声明」：回包**实际**的源地址也必须换端口。
			// 只比属性值会把「服务端写对了属性、却仍从旧 socket 发出」判成通过。
			fromHost, fromPort, splitErr := net.SplitHostPort(from.String())
			if splitErr != nil {
				fromHost, fromPort = from.String(), ""
			}
			check(fromPort == fmt.Sprint(*altPort),
				"回包实际源端口 = %s（期望 %d；实际来自 %s）", fromPort, *altPort, from)
			check(fromHost == host,
				"回包实际源 IP = %s（期望 %s）", fromHost, host)
		}
	}

	if failures > 0 {
		fmt.Printf("pion/%s: %d 条断言失败\n", *mode, failures)
		os.Exit(1)
	}
	fmt.Printf("pion/%s 通过\n", *mode)
}
