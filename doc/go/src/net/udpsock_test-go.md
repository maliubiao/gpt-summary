Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `net/udpsock_test.go` file.

Here's a breakdown of how to approach this:

1. **Identify the main purpose:** The filename `udpsock_test.go` strongly suggests that this code contains tests for UDP socket functionality in the `net` package.

2. **Examine individual functions:** Go through each function and understand its purpose based on its name and the operations it performs.

3. **Look for patterns and connections:**  Notice how different test functions might be testing related aspects of UDP sockets.

4. **Infer the underlying Go features:** Based on the tests, determine which Go `net` package features are being tested.

5. **Provide code examples:** For important features, demonstrate their usage with simple Go code snippets, including hypothetical inputs and outputs.

6. **Consider command-line arguments:** While the provided code doesn't directly handle command-line arguments, acknowledge the possibility in general network programming.

7. **Identify potential pitfalls:** Based on the tests and the nature of UDP, pinpoint common mistakes users might make.
这段Go语言代码是 `net` 包中关于 UDP socket 功能的测试代码。它包含了多个测试函数和基准测试函数，用于验证和评估 Go 语言中 UDP socket 相关 API 的正确性和性能。

以下是代码中各个部分的功能：

**1. `BenchmarkUDP6LinkLocalUnicast` 函数:**

* **功能:** 这是一个基准测试函数，用于测试 IPv6 链路本地单播 UDP 通信的性能。
* **实现原理:**
    * 它首先检查系统是否支持 IPv6，并获取本地回环接口的信息和链路本地单播地址。
    * 然后，它创建了两个监听在不同端口的 UDP socket (c1 和 c2)，都绑定到相同的链路本地地址和回环接口。
    * 在循环中，它通过 `c1` 向 `c2` 的本地地址发送一个字节的数据，并等待 `c2` 接收到数据。
    * 这个基准测试衡量了在本地进行 IPv6 UDP 数据包收发的性能。

**2. `resolveUDPAddrTest` 结构体和 `resolveUDPAddrTests` 变量，以及 `TestResolveUDPAddr` 函数:**

* **功能:** 这部分代码测试了 `net.ResolveUDPAddr` 函数的功能，该函数用于将一个地址字符串解析为 `UDPAddr` 结构体。
* **实现原理:**
    * `resolveUDPAddrTest` 结构体定义了测试用例，包括网络类型、地址字符串、期望的 `UDPAddr` 结构体和期望的错误。
    * `resolveUDPAddrTests` 变量是一个包含多个 `resolveUDPAddrTest` 结构体的切片，代表了各种不同的测试场景，例如 IPv4 地址、IPv6 地址、带 Zone ID 的 IPv6 地址、端口号解析、域名解析等。
    * `TestResolveUDPAddr` 函数遍历 `resolveUDPAddrTests` 中的每个测试用例，调用 `ResolveUDPAddr` 函数，并将返回的结果与期望的结果进行比较。
* **Go 语言功能实现:** `net.ResolveUDPAddr` 函数用于解析 UDP 地址字符串。
    ```go
    package main

    import (
        "fmt"
        "net"
    )

    func main() {
        addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
        if err != nil {
            fmt.Println("解析地址失败:", err)
            return
        }
        fmt.Println("解析后的地址:", addr) // 假设输出: &{127.0.0.1 8080 <nil>}
    }
    ```
    **假设输入:** 网络类型 "udp"，地址字符串 "127.0.0.1:8080"
    **预期输出:** `&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080, Zone: ""}`

**3. `TestWriteToUDP`，`testWriteToConn` 和 `testWriteToPacketConn` 函数:**

* **功能:** 这部分代码测试了在连接模式和非连接模式下使用 UDP socket 进行数据写入的功能。
* **实现原理:**
    * `TestWriteToUDP` 函数创建了一个监听的 UDP socket，并分别调用 `testWriteToConn` 和 `testWriteToPacketConn` 进行测试。
    * `testWriteToConn` 函数测试了通过 `Dial` 创建的连接模式的 UDP socket 的写入行为。在连接模式下，尝试使用 `WriteToUDP` 和 `WriteTo` 方法指定目标地址会失败，因为连接已经建立。只能使用 `Write` 方法向已连接的目标地址发送数据。`WriteMsgUDP` 也会有相应的行为限制。
    * `testWriteToPacketConn` 函数测试了通过 `ListenPacket` 创建的非连接模式的 UDP socket 的写入行为。在非连接模式下，可以使用 `WriteToUDP` 和 `WriteTo` 方法指定目标地址发送数据。直接使用 `Write` 方法会失败，因为缺少目标地址。`WriteMsgUDP` 可以不指定目标地址。
* **Go 语言功能实现:**
    * `net.Dial("udp", address)`: 创建一个连接到指定地址的 UDP socket。
    * `net.ListenPacket("udp", address)`: 创建一个监听指定地址的 UDP socket (非连接模式)。
    * `(*net.UDPConn).WriteToUDP(b []byte, addr *UDPAddr)`: 向指定的 UDP 地址发送数据 (非连接模式)。
    * `(*net.UDPConn).WriteTo(b []byte, addr Addr)`: 向指定的网络地址发送数据 (非连接模式)。
    * `(*net.Conn).Write(b []byte)`: 向已连接的目标地址发送数据 (连接模式)。
    * `(*net.UDPConn).WriteMsgUDP(b, oob []byte, addr *UDPAddr)`:  带有控制消息的 UDP 数据包发送。

**4. `udpConnLocalNameTests` 变量和 `TestUDPConnLocalName` 函数:**

* **功能:** 这部分代码测试了通过 `ListenUDP` 创建的 UDP socket 的本地地址是否正确设置。
* **实现原理:**
    * `udpConnLocalNameTests` 变量定义了不同的网络类型和本地地址配置。
    * `TestUDPConnLocalName` 函数遍历这些配置，调用 `ListenUDP` 创建 socket，并检查返回的本地地址是否不为空且端口号不为 0。
* **Go 语言功能实现:** `net.ListenUDP(network string, laddr *UDPAddr)`: 监听指定的本地 UDP 地址。

**5. `TestUDPConnLocalAndRemoteNames` 函数:**

* **功能:** 测试通过 `ListenPacket` 和 `DialUDP` 创建的 UDP 连接的本地地址和远程地址是否正确。
* **实现原理:** 它创建了一个监听的 UDP socket (c1)，然后使用 `DialUDP` 创建另一个连接到 c1 的 socket (c2)。接着，它检查 c1 和 c2 的本地地址和远程地址是否已正确设置。
* **Go 语言功能实现:** `net.DialUDP(network string, laddr *UDPAddr, raddr *UDPAddr)`: 创建一个连接到指定远程地址的 UDP socket，并可指定本地地址。

**6. `ipv6LinkLocalUnicastUDPTests` 变量和 `TestIPv6LinkLocalUnicastUDP` 函数:**

* **功能:** 测试 IPv6 链路本地单播 UDP 通信的功能。
* **实现原理:** 它创建监听指定链路本地地址的 socket，然后通过另一个 socket 连接到它，并进行数据收发。
* **Go 语言功能实现:**  与 `BenchmarkUDP6LinkLocalUnicast` 类似，但重点在于测试其功能是否正常。

**7. `TestUDPZeroBytePayload` 函数:**

* **功能:** 测试发送和接收零字节 UDP 数据包的行为。
* **实现原理:** 它创建一个 UDP socket，尝试发送一个零字节的数据包，并检查是否成功。然后尝试读取一个零字节的数据包，并检查是否成功。

**8. `TestUDPZeroByteBuffer` 函数:**

* **功能:** 测试使用零字节缓冲区进行 UDP 数据读取的行为。
* **实现原理:** 它创建一个 UDP socket，发送一些数据，然后尝试使用零字节的缓冲区进行读取，并检查是否会返回错误或超时。

**9. `TestUDPReadSizeError` 函数:**

* **功能:** 测试当读取缓冲区小于接收到的 UDP 数据包大小时的行为。
* **实现原理:** 它创建两个 UDP socket，从一个 socket 发送数据，并在另一个 socket 上使用较小的缓冲区进行读取，检查是否会返回错误，以及实际读取了多少字节。

**10. `TestUDPReadTimeout` 函数:**

* **功能:** 测试在设置读取超时时间后，如果没有数据到达，`ReadFromUDP` 是否会返回超时错误。
* **实现原理:** 它创建一个 UDP socket，设置一个立即过期的读取截止时间，然后调用 `ReadFromUDP`，并验证是否返回了 `os.ErrDeadlineExceeded` 错误。

**11. `TestAllocs` 函数:**

* **功能:** 测试在进行 UDP 数据包收发操作时，内存分配的情况。
* **实现原理:** 它使用 `testing.AllocsPerRun` 来测量在执行 `WriteMsgUDPAddrPort`、`ReadMsgUDPAddrPort`、`WriteToUDPAddrPort`、`ReadFromUDPAddrPort`、`WriteTo` 和 `ReadFromUDP` 等操作时分配的内存数量，期望某些优化过的操作不会产生额外的内存分配。

**12. `BenchmarkReadWriteMsgUDPAddrPort`， `BenchmarkWriteToReadFromUDP` 和 `BenchmarkWriteToReadFromUDPAddrPort` 函数:**

* **功能:** 这些是基准测试函数，用于测试不同 UDP 数据包收发方式的性能。
* **实现原理:** 它们分别测试了使用 `WriteMsgUDPAddrPort`/`ReadMsgUDPAddrPort`， `WriteTo`/`ReadFromUDP` 和 `WriteToUDPAddrPort`/`ReadFromUDPAddrPort` 进行数据收发的性能。

**13. `TestUDPIPVersionReadMsg` 函数:**

* **功能:** 测试使用 `ReadMsgUDPAddrPort` 和 `ReadMsgUDP` 读取数据包时返回的源地址的 IP 版本是否正确。
* **实现原理:** 它创建一个监听 IPv4 地址的 UDP socket，发送一个数据包，然后使用 `ReadMsgUDPAddrPort` 和 `ReadMsgUDP` 读取数据包，并检查返回的源地址是否为 IPv4 地址。

**14. `TestIPv6WriteMsgUDPAddrPortTargetAddrIPVersion` 函数:**

* **功能:** 测试在监听所有 IPv6 地址 ("::") 的 UDP socket 上，`WriteMsgUDPAddrPort` 是否接受 IPv4、IPv4-mapped IPv6 和 IPv6 目标地址。
* **实现原理:** 它创建一个监听所有地址的 UDP socket，然后尝试向 IPv4、IPv4-mapped IPv6 和 IPv6 地址发送数据包，并检查是否成功。

**可以推理出它是什么 go 语言功能的实现:**

这段代码主要测试了 Go 语言 `net` 包中关于 UDP 协议的网络编程功能，包括：

* **创建和监听 UDP socket:** `ListenPacket`, `ListenUDP`
* **连接 UDP socket:** `Dial`, `DialUDP`
* **解析 UDP 地址:** `ResolveUDPAddr`
* **发送和接收 UDP 数据:** `WriteTo`, `ReadFrom`, `WriteToUDP`, `ReadFromUDP`, `WriteMsgUDP`, `ReadMsgUDP`, `WriteToUDPAddrPort`, `ReadFromUDPAddrPort`, `WriteMsgUDPAddrPort`, `ReadMsgUDPAddrPort`
* **获取本地和远程地址:** `LocalAddr`, `RemoteAddr`
* **设置 socket 选项:** `SetDeadline`

**使用者易犯错的点:**

* **连接模式和非连接模式的混淆:**
    * **错误示例:** 在通过 `ListenPacket` 创建的非连接模式的 socket 上使用 `Write` 方法，而不指定目标地址。
    ```go
    conn, _ := net.ListenPacket("udp", "127.0.0.1:0")
    defer conn.Close()
    _, err := conn.Write([]byte("data")) // 错误: 缺少目标地址
    fmt.Println(err) // 可能输出: write udp 127.0.0.1:<端口>->: address is required
    ```
    * **正确做法:** 使用 `WriteTo` 或 `WriteToUDP` 指定目标地址。
    ```go
    conn, _ := net.ListenPacket("udp", "127.0.0.1:0")
    defer conn.Close()
    raddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
    _, err := conn.WriteTo([]byte("data"), raddr)
    fmt.Println(err)
    ```
* **在连接模式的 socket 上使用 `WriteTo` 等方法:**
    * **错误示例:** 在通过 `Dial` 创建的连接模式的 socket 上使用 `WriteTo` 方法指定目标地址。
    ```go
    conn, _ := net.Dial("udp", "127.0.0.1:8080")
    defer conn.Close()
    raddr, _ := net.ResolveUDPAddr("udp", "192.168.1.100:9000") // 尝试写入到不同的地址
    _, err := conn.WriteTo([]byte("data"), raddr)
    fmt.Println(err) // 可能输出: write udp4 127.0.0.1:<本地端口>->192.168.1.100:9000: use of WriteTo with pre-connected connection
    ```
    * **正确做法:**  在连接模式下直接使用 `Write` 方法。
    ```go
    conn, _ := net.Dial("udp", "127.0.0.1:8080")
    defer conn.Close()
    _, err := conn.Write([]byte("data"))
    fmt.Println(err)
    ```
* **忘记处理网络错误和超时:** UDP 是不可靠的协议，数据包可能会丢失或延迟，需要合理设置超时时间和处理网络错误。
* **Zone ID 的处理:** 在使用 IPv6 链路本地地址时，需要正确处理 Zone ID。

这段测试代码对于理解 Go 语言中 UDP socket 的使用方式和各种场景下的行为非常有帮助。

Prompt: 
```
这是路径为go/src/net/udpsock_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"errors"
	"fmt"
	"internal/asan"
	"internal/testenv"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func BenchmarkUDP6LinkLocalUnicast(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	if !supportsIPv6() {
		b.Skip("IPv6 is not supported")
	}
	ifi := loopbackInterface()
	if ifi == nil {
		b.Skip("loopback interface not found")
	}
	lla := ipv6LinkLocalUnicastAddr(ifi)
	if lla == "" {
		b.Skip("IPv6 link-local unicast address not found")
	}

	c1, err := ListenPacket("udp6", JoinHostPort(lla+"%"+ifi.Name, "0"))
	if err != nil {
		b.Fatal(err)
	}
	defer c1.Close()
	c2, err := ListenPacket("udp6", JoinHostPort(lla+"%"+ifi.Name, "0"))
	if err != nil {
		b.Fatal(err)
	}
	defer c2.Close()

	var buf [1]byte
	for i := 0; i < b.N; i++ {
		if _, err := c1.WriteTo(buf[:], c2.LocalAddr()); err != nil {
			b.Fatal(err)
		}
		if _, _, err := c2.ReadFrom(buf[:]); err != nil {
			b.Fatal(err)
		}
	}
}

type resolveUDPAddrTest struct {
	network       string
	litAddrOrName string
	addr          *UDPAddr
	err           error
}

var resolveUDPAddrTests = []resolveUDPAddrTest{
	{"udp", "127.0.0.1:0", &UDPAddr{IP: IPv4(127, 0, 0, 1), Port: 0}, nil},
	{"udp4", "127.0.0.1:65535", &UDPAddr{IP: IPv4(127, 0, 0, 1), Port: 65535}, nil},

	{"udp", "[::1]:0", &UDPAddr{IP: ParseIP("::1"), Port: 0}, nil},
	{"udp6", "[::1]:65535", &UDPAddr{IP: ParseIP("::1"), Port: 65535}, nil},

	{"udp", "[::1%en0]:1", &UDPAddr{IP: ParseIP("::1"), Port: 1, Zone: "en0"}, nil},
	{"udp6", "[::1%911]:2", &UDPAddr{IP: ParseIP("::1"), Port: 2, Zone: "911"}, nil},

	{"", "127.0.0.1:0", &UDPAddr{IP: IPv4(127, 0, 0, 1), Port: 0}, nil}, // Go 1.0 behavior
	{"", "[::1]:0", &UDPAddr{IP: ParseIP("::1"), Port: 0}, nil},         // Go 1.0 behavior

	{"udp", ":12345", &UDPAddr{Port: 12345}, nil},

	{"http", "127.0.0.1:0", nil, UnknownNetworkError("http")},

	{"udp", "127.0.0.1:domain", &UDPAddr{IP: ParseIP("127.0.0.1"), Port: 53}, nil},
	{"udp", "[::ffff:127.0.0.1]:domain", &UDPAddr{IP: ParseIP("::ffff:127.0.0.1"), Port: 53}, nil},
	{"udp", "[2001:db8::1]:domain", &UDPAddr{IP: ParseIP("2001:db8::1"), Port: 53}, nil},
	{"udp4", "127.0.0.1:domain", &UDPAddr{IP: ParseIP("127.0.0.1"), Port: 53}, nil},
	{"udp4", "[::ffff:127.0.0.1]:domain", &UDPAddr{IP: ParseIP("127.0.0.1"), Port: 53}, nil},
	{"udp6", "[2001:db8::1]:domain", &UDPAddr{IP: ParseIP("2001:db8::1"), Port: 53}, nil},

	{"udp4", "[2001:db8::1]:domain", nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: "2001:db8::1"}},
	{"udp6", "127.0.0.1:domain", nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: "127.0.0.1"}},
	{"udp6", "[::ffff:127.0.0.1]:domain", nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: "::ffff:127.0.0.1"}},
}

func TestResolveUDPAddr(t *testing.T) {
	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()
	testHookLookupIP = lookupLocalhost

	for _, tt := range resolveUDPAddrTests {
		addr, err := ResolveUDPAddr(tt.network, tt.litAddrOrName)
		if !reflect.DeepEqual(addr, tt.addr) || !reflect.DeepEqual(err, tt.err) {
			t.Errorf("ResolveUDPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr, err, tt.addr, tt.err)
			continue
		}
		if err == nil {
			addr2, err := ResolveUDPAddr(addr.Network(), addr.String())
			if !reflect.DeepEqual(addr2, tt.addr) || err != tt.err {
				t.Errorf("(%q, %q): ResolveUDPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr.Network(), addr.String(), addr2, err, tt.addr, tt.err)
			}
		}
	}
}

func TestWriteToUDP(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	if !testableNetwork("udp") {
		t.Skipf("skipping: udp not supported")
	}

	c, err := ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	testWriteToConn(t, c.LocalAddr().String())
	testWriteToPacketConn(t, c.LocalAddr().String())
}

func testWriteToConn(t *testing.T, raddr string) {
	c, err := Dial("udp", raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ra, err := ResolveUDPAddr("udp", raddr)
	if err != nil {
		t.Fatal(err)
	}

	b := []byte("CONNECTED-MODE SOCKET")
	_, err = c.(*UDPConn).WriteToUDP(b, ra)
	if err == nil {
		t.Fatal("should fail")
	}
	if err != nil && err.(*OpError).Err != ErrWriteToConnected {
		t.Fatalf("should fail as ErrWriteToConnected: %v", err)
	}
	_, err = c.(*UDPConn).WriteTo(b, ra)
	if err == nil {
		t.Fatal("should fail")
	}
	if err != nil && err.(*OpError).Err != ErrWriteToConnected {
		t.Fatalf("should fail as ErrWriteToConnected: %v", err)
	}
	_, err = c.Write(b)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.(*UDPConn).WriteMsgUDP(b, nil, ra)
	if err == nil {
		t.Fatal("should fail")
	}
	if err != nil && err.(*OpError).Err != ErrWriteToConnected {
		t.Fatalf("should fail as ErrWriteToConnected: %v", err)
	}
	_, _, err = c.(*UDPConn).WriteMsgUDP(b, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func testWriteToPacketConn(t *testing.T, raddr string) {
	c, err := ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ra, err := ResolveUDPAddr("udp", raddr)
	if err != nil {
		t.Fatal(err)
	}

	b := []byte("UNCONNECTED-MODE SOCKET")
	_, err = c.(*UDPConn).WriteToUDP(b, ra)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.WriteTo(b, ra)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.(*UDPConn).Write(b)
	if err == nil {
		t.Fatal("should fail")
	}
	_, _, err = c.(*UDPConn).WriteMsgUDP(b, nil, nil)
	if err == nil {
		t.Fatal("should fail")
	}
	if err != nil && err.(*OpError).Err != errMissingAddress {
		t.Fatalf("should fail as errMissingAddress: %v", err)
	}
	_, _, err = c.(*UDPConn).WriteMsgUDP(b, nil, ra)
	if err != nil {
		t.Fatal(err)
	}
}

var udpConnLocalNameTests = []struct {
	net   string
	laddr *UDPAddr
}{
	{"udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)}},
	{"udp4", &UDPAddr{}},
	{"udp4", nil},
}

func TestUDPConnLocalName(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	for _, tt := range udpConnLocalNameTests {
		t.Run(fmt.Sprint(tt.laddr), func(t *testing.T) {
			if !testableNetwork(tt.net) {
				t.Skipf("skipping: %s not available", tt.net)
			}

			c, err := ListenUDP(tt.net, tt.laddr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			la := c.LocalAddr()
			if a, ok := la.(*UDPAddr); !ok || a.Port == 0 {
				t.Fatalf("got %v; expected a proper address with non-zero port number", la)
			}
		})
	}
}

func TestUDPConnLocalAndRemoteNames(t *testing.T) {
	if !testableNetwork("udp") {
		t.Skipf("skipping: udp not available")
	}

	for _, laddr := range []string{"", "127.0.0.1:0"} {
		c1, err := ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c1.Close()

		var la *UDPAddr
		if laddr != "" {
			var err error
			if la, err = ResolveUDPAddr("udp", laddr); err != nil {
				t.Fatal(err)
			}
		}
		c2, err := DialUDP("udp", la, c1.LocalAddr().(*UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c2.Close()

		var connAddrs = [4]struct {
			got Addr
			ok  bool
		}{
			{c1.LocalAddr(), true},
			{c1.(*UDPConn).RemoteAddr(), false},
			{c2.LocalAddr(), true},
			{c2.RemoteAddr(), true},
		}
		for _, ca := range connAddrs {
			if a, ok := ca.got.(*UDPAddr); ok != ca.ok || ok && a.Port == 0 {
				t.Fatalf("got %v; expected a proper address with non-zero port number", ca.got)
			}
		}
	}
}

func TestIPv6LinkLocalUnicastUDP(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	if !supportsIPv6() {
		t.Skip("IPv6 is not supported")
	}

	for i, tt := range ipv6LinkLocalUnicastUDPTests {
		c1, err := ListenPacket(tt.network, tt.address)
		if err != nil {
			// It might return "LookupHost returned no
			// suitable address" error on some platforms.
			t.Log(err)
			continue
		}
		ls := (&packetListener{PacketConn: c1}).newLocalServer()
		defer ls.teardown()
		ch := make(chan error, 1)
		handler := func(ls *localPacketServer, c PacketConn) { packetTransponder(c, ch) }
		if err := ls.buildup(handler); err != nil {
			t.Fatal(err)
		}
		if la, ok := c1.LocalAddr().(*UDPAddr); !ok || !tt.nameLookup && la.Zone == "" {
			t.Fatalf("got %v; expected a proper address with zone identifier", la)
		}

		c2, err := Dial(tt.network, ls.PacketConn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c2.Close()
		if la, ok := c2.LocalAddr().(*UDPAddr); !ok || !tt.nameLookup && la.Zone == "" {
			t.Fatalf("got %v; expected a proper address with zone identifier", la)
		}
		if ra, ok := c2.RemoteAddr().(*UDPAddr); !ok || !tt.nameLookup && ra.Zone == "" {
			t.Fatalf("got %v; expected a proper address with zone identifier", ra)
		}

		if _, err := c2.Write([]byte("UDP OVER IPV6 LINKLOCAL TEST")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 32)
		if _, err := c2.Read(b); err != nil {
			t.Fatal(err)
		}

		for err := range ch {
			t.Errorf("#%d: %v", i, err)
		}
	}
}

func TestUDPZeroBytePayload(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	case "ios":
		testenv.SkipFlaky(t, 29225)
	}
	if !testableNetwork("udp") {
		t.Skipf("skipping: udp not available")
	}

	c := newLocalPacketListener(t, "udp")
	defer c.Close()

	for _, genericRead := range []bool{false, true} {
		n, err := c.WriteTo(nil, c.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("got %d; want 0", n)
		}
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		var b [1]byte
		var name string
		if genericRead {
			_, err = c.(Conn).Read(b[:])
			name = "Read"
		} else {
			_, _, err = c.ReadFrom(b[:])
			name = "ReadFrom"
		}
		if err != nil {
			t.Errorf("%s of zero byte packet failed: %v", name, err)
		}
	}
}

func TestUDPZeroByteBuffer(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !testableNetwork("udp") {
		t.Skipf("skipping: udp not available")
	}

	c := newLocalPacketListener(t, "udp")
	defer c.Close()

	b := []byte("UDP ZERO BYTE BUFFER TEST")
	for _, genericRead := range []bool{false, true} {
		n, err := c.WriteTo(b, c.LocalAddr())
		if err != nil {
			t.Fatal(err)
		}
		if n != len(b) {
			t.Errorf("got %d; want %d", n, len(b))
		}
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if genericRead {
			_, err = c.(Conn).Read(nil)
		} else {
			_, _, err = c.ReadFrom(nil)
		}
		switch err {
		case nil: // ReadFrom succeeds
		default: // Read may timeout, it depends on the platform
			if nerr, ok := err.(Error); (!ok || !nerr.Timeout()) && runtime.GOOS != "windows" { // Windows returns WSAEMSGSIZE
				t.Fatal(err)
			}
		}
	}
}

func TestUDPReadSizeError(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !testableNetwork("udp") {
		t.Skipf("skipping: udp not available")
	}

	c1 := newLocalPacketListener(t, "udp")
	defer c1.Close()

	c2, err := Dial("udp", c1.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	b1 := []byte("READ SIZE ERROR TEST")
	for _, genericRead := range []bool{false, true} {
		n, err := c2.Write(b1)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(b1) {
			t.Errorf("got %d; want %d", n, len(b1))
		}
		b2 := make([]byte, len(b1)-1)
		if genericRead {
			n, err = c1.(Conn).Read(b2)
		} else {
			n, _, err = c1.ReadFrom(b2)
		}
		if err != nil && runtime.GOOS != "windows" { // Windows returns WSAEMSGSIZE
			t.Fatal(err)
		}
		if n != len(b1)-1 {
			t.Fatalf("got %d; want %d", n, len(b1)-1)
		}
	}
}

// TestUDPReadTimeout verifies that ReadFromUDP with timeout returns an error
// without data or an address.
func TestUDPReadTimeout(t *testing.T) {
	if !testableNetwork("udp4") {
		t.Skipf("skipping: udp4 not available")
	}

	la, err := ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ListenUDP("udp4", la)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.SetDeadline(time.Now())
	b := make([]byte, 1)
	n, addr, err := c.ReadFromUDP(b)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("ReadFromUDP got err %v want os.ErrDeadlineExceeded", err)
	}
	if n != 0 {
		t.Errorf("ReadFromUDP got n %d want 0", n)
	}
	if addr != nil {
		t.Errorf("ReadFromUDP got addr %+#v want nil", addr)
	}
}

func TestAllocs(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "js", "wasip1":
		// These implementations have not been optimized.
		t.Skipf("skipping on %v", runtime.GOOS)
	}
	if !testableNetwork("udp4") {
		t.Skipf("skipping: udp4 not available")
	}
	if asan.Enabled {
		t.Skip("test allocates more with -asan; see #70079")
	}

	// Optimizations are required to remove the allocs.
	testenv.SkipIfOptimizationOff(t)

	conn, err := ListenUDP("udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	addr := conn.LocalAddr()
	addrPort := addr.(*UDPAddr).AddrPort()
	buf := make([]byte, 8)

	allocs := testing.AllocsPerRun(1000, func() {
		_, _, err := conn.WriteMsgUDPAddrPort(buf, nil, addrPort)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, _, err = conn.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	if got := int(allocs); got != 0 {
		t.Errorf("WriteMsgUDPAddrPort/ReadMsgUDPAddrPort allocated %d objects", got)
	}

	allocs = testing.AllocsPerRun(1000, func() {
		_, err := conn.WriteToUDPAddrPort(buf, addrPort)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatal(err)
		}
	})
	if got := int(allocs); got != 0 {
		t.Errorf("WriteToUDPAddrPort/ReadFromUDPAddrPort allocated %d objects", got)
	}

	allocs = testing.AllocsPerRun(1000, func() {
		_, err := conn.WriteTo(buf, addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
	})
	if got := int(allocs); got != 1 {
		t.Errorf("WriteTo/ReadFromUDP allocated %d objects", got)
	}
}

func BenchmarkReadWriteMsgUDPAddrPort(b *testing.B) {
	conn, err := ListenUDP("udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*UDPAddr).AddrPort()
	buf := make([]byte, 8)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := conn.WriteMsgUDPAddrPort(buf, nil, addr)
		if err != nil {
			b.Fatal(err)
		}
		_, _, _, _, err = conn.ReadMsgUDPAddrPort(buf, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteToReadFromUDP(b *testing.B) {
	conn, err := ListenUDP("udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	addr := conn.LocalAddr()
	buf := make([]byte, 8)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := conn.WriteTo(buf, addr)
		if err != nil {
			b.Fatal(err)
		}
		_, _, err = conn.ReadFromUDP(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteToReadFromUDPAddrPort(b *testing.B) {
	conn, err := ListenUDP("udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*UDPAddr).AddrPort()
	buf := make([]byte, 8)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := conn.WriteToUDPAddrPort(buf, addr)
		if err != nil {
			b.Fatal(err)
		}
		_, _, err = conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestUDPIPVersionReadMsg(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("skipping on %v", runtime.GOOS)
	}
	if !testableNetwork("udp4") {
		t.Skipf("skipping: udp4 not available")
	}

	conn, err := ListenUDP("udp4", &UDPAddr{IP: IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	daddr := conn.LocalAddr().(*UDPAddr).AddrPort()
	buf := make([]byte, 8)
	_, err = conn.WriteToUDPAddrPort(buf, daddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, saddr, err := conn.ReadMsgUDPAddrPort(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !saddr.Addr().Is4() {
		t.Error("returned AddrPort is not IPv4")
	}
	_, err = conn.WriteToUDPAddrPort(buf, daddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, soldaddr, err := conn.ReadMsgUDP(buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(soldaddr.IP) != 4 {
		t.Error("returned UDPAddr is not IPv4")
	}
}

// TestIPv6WriteMsgUDPAddrPortTargetAddrIPVersion verifies that
// WriteMsgUDPAddrPort accepts IPv4, IPv4-mapped IPv6, and IPv6 target addresses
// on a UDPConn listening on "::".
func TestIPv6WriteMsgUDPAddrPortTargetAddrIPVersion(t *testing.T) {
	if !testableNetwork("udp4") {
		t.Skipf("skipping: udp4 not available")
	}
	if !testableNetwork("udp6") {
		t.Skipf("skipping: udp6 not available")
	}

	switch runtime.GOOS {
	case "dragonfly", "openbsd":
		// DragonflyBSD's IPv6 sockets are always IPv6-only, according to the man page:
		// https://www.dragonflybsd.org/cgi/web-man?command=ip6 (search for IPV6_V6ONLY).
		// OpenBSD's IPv6 sockets are always IPv6-only, according to the man page:
		// https://man.openbsd.org/ip6#IPV6_V6ONLY
		t.Skipf("skipping on %v", runtime.GOOS)
	}

	conn, err := ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	daddr4 := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 12345)
	daddr4in6 := netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), 12345)
	daddr6 := netip.AddrPortFrom(netip.MustParseAddr("::1"), 12345)
	buf := make([]byte, 8)

	_, _, err = conn.WriteMsgUDPAddrPort(buf, nil, daddr4)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = conn.WriteMsgUDPAddrPort(buf, nil, daddr4in6)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = conn.WriteMsgUDPAddrPort(buf, nil, daddr6)
	if err != nil {
		t.Fatal(err)
	}
}

"""



```