Response:
Let's break down the thought process for analyzing the provided Go code snippet for `net/udpsock.go`.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this specific Go source code file. This involves identifying the data structures and functions defined within it and how they relate to UDP networking. The prompt also requests examples, error identification, and potentially command-line argument handling (though this specific file doesn't directly handle those).

**2. Initial Scan and Keyword Identification:**

I'd start by quickly scanning the code for keywords and recognizable patterns related to networking:

* **`package net`**:  Immediately establishes this is part of the Go standard library's networking package.
* **`UDPAddr`**: This strongly suggests the code deals with UDP addresses.
* **`UDPConn`**: This suggests code related to UDP connections.
* **`ReadFromUDP`, `WriteToUDP`, `ReadMsgUDP`, `WriteMsgUDP`**:  These are clearly functions for sending and receiving UDP data.
* **`DialUDP`, `ListenUDP`, `ListenMulticastUDP`**: These look like functions for creating UDP connections (dialing out) and listening for incoming connections.
* **`netip.AddrPort`**:  Indicates interaction with the newer `netip` package for IP addresses and ports.
* **`syscall`**:  Suggests interaction with the operating system's network APIs.
* **`// BUG(...)`**: These are important to note as they highlight platform-specific limitations.

**3. Analyzing Data Structures:**

* **`UDPAddr`**:  This structure holds the IP address, port, and zone (for IPv6 scope). The associated methods (`AddrPort`, `Network`, `String`, `isWildcard`, `opAddr`) provide ways to interact with and represent this address.
* **`UDPConn`**: This structure embeds a `conn`, suggesting it inherits or leverages functionality from a more general connection type. It has methods for reading, writing, and accessing the underlying syscall connection.
* **`addrPortUDPAddr`**: This seems to be an adapter to make `netip.AddrPort` compatible with the `Addr` interface.

**4. Analyzing Functions (Categorization and Purpose):**

I would categorize the functions based on their apparent purpose:

* **Address Resolution/Creation:**
    * `ResolveUDPAddr`:  Looks up a UDP address from a string.
    * `UDPAddrFromAddrPort`:  Converts a `netip.AddrPort` to a `UDPAddr`.
* **Connection Management:**
    * `DialUDP`:  Creates an outbound UDP connection.
    * `ListenUDP`:  Starts listening for incoming UDP connections on a specific address.
    * `ListenMulticastUDP`:  Starts listening for multicast UDP traffic.
* **Data Transfer (Read):**
    * `ReadFromUDP`: Reads data and the source address into a `UDPAddr`.
    * `readFromUDP`: Internal implementation of `ReadFromUDP`.
    * `ReadFrom`:  Standard `PacketConn` interface implementation (returns a general `Addr`).
    * `ReadFromUDPAddrPort`: Reads data and the source address into a `netip.AddrPort`.
    * `ReadMsgUDP`: Reads data, out-of-band data, flags, and the source address into a `UDPAddr`.
    * `ReadMsgUDPAddrPort`: Reads data, out-of-band data, flags, and the source address into a `netip.AddrPort`.
* **Data Transfer (Write):**
    * `WriteToUDP`: Sends data to a specific `UDPAddr`.
    * `WriteToUDPAddrPort`: Sends data to a specific `netip.AddrPort`.
    * `WriteTo`: Standard `PacketConn` interface implementation (takes a general `Addr`).
    * `WriteMsgUDP`: Sends data and out-of-band data to a specific `UDPAddr`.
    * `WriteMsgUDPAddrPort`: Sends data and out-of-band data to a specific `netip.AddrPort`.
* **Internal/Helper Functions:**
    * `newUDPConn`:  Creates a `UDPConn` from a `netFD`.
    * `(a *UDPAddr) ...`: Methods associated with the `UDPAddr` struct.
    * `(c *UDPConn) SyscallConn()`: Provides access to the underlying system call connection.

**5. Inferring Functionality and Providing Examples:**

Once the purpose of the functions is understood, I would construct examples to illustrate their usage. This involves:

* **Identifying key use cases:**  Sending data, receiving data, listening for connections, dialing connections.
* **Choosing appropriate input values:**  Valid IP addresses, ports, and data payloads.
* **Predicting expected outputs:**  Number of bytes read/written, source/destination addresses, potential errors.

For instance, for `DialUDP`, I'd think: "How do I create a UDP client connection?"  This leads to the example with a local and remote address. Similarly, for `ListenUDP`: "How do I create a UDP server to receive data?"

**6. Identifying Potential Errors and Common Mistakes:**

This step involves thinking about how a user might misuse these functions or encounter common issues:

* **Incorrect network string:**  Passing something other than "udp", "udp4", or "udp6".
* **Nil addresses:**  Not providing necessary address information.
* **Type mismatches:**  Trying to pass a non-`UDPAddr` to a function expecting one (though the `PacketConn` interface handles this more generically).
* **Platform limitations:** The `BUG` comments directly point to these.
* **Unresolved hostnames:** The warning in `ResolveUDPAddr` about hostname resolution is important.
* **Multicast configuration:** The notes about `ListenMulticastUDP` and the need for the `ipv4`/`ipv6` packages highlight potential complexity.

**7. Command-Line Arguments (Consideration and Exclusion):**

I would check if any functions in this snippet directly process command-line arguments. In this case, they don't. The functions are building blocks for network applications, which might *use* command-line arguments to determine addresses or ports, but this code itself doesn't handle that.

**8. Structuring the Answer:**

Finally, I would organize the findings into a clear and structured answer, addressing each point of the original prompt:

* **Functionality List:**  A concise bulleted list of what the code does.
* **Go Language Feature (UDP Networking):** Clearly state that it implements UDP socket functionality.
* **Code Examples:** Provide practical examples for key functions.
* **Code Reasoning (with Assumptions):** Explain the logic behind the examples and the assumed input/output.
* **Command-Line Arguments:**  State that this code doesn't directly handle them.
* **Common Mistakes:**  List potential pitfalls for users.

This iterative process of scanning, analyzing, categorizing, inferring, and exemplifying helps to thoroughly understand the functionality of the given Go code.
这段代码是 Go 语言标准库 `net` 包中关于 UDP 网络编程的一部分，主要实现了 UDP 协议相关的地址表示和连接操作。

**主要功能:**

1. **定义 UDP 地址类型 `UDPAddr`:**
   - 用于表示一个 UDP 端点的地址，包含 IP 地址 (`IP` 字段，可以是 IPv4 或 IPv6)，端口号 (`Port` 字段) 和 IPv6 的 Zone ID (`Zone` 字段)。
   - 提供了将 `UDPAddr` 转换为 `netip.AddrPort` 的方法 (`AddrPort`)，方便与新的 `netip` 包进行互操作。
   - 提供了获取网络类型 (`Network`) 和字符串表示 (`String`) 的方法。
   - 提供了判断是否为通配符地址的方法 (`isWildcard`)。
   - 提供了返回自身 `Addr` 接口的方法 (`opAddr`)。

2. **UDP 地址解析函数 `ResolveUDPAddr`:**
   - 将一个网络类型（如 "udp", "udp4", "udp6"）和地址字符串解析为 `UDPAddr` 结构体。
   - 地址字符串可以是字面 IP 地址和端口号的组合，也可以是主机名和端口号的组合（但不推荐使用主机名，因为它只会返回主机名的第一个 IP 地址）。

3. **`UDPAddr` 与 `netip.AddrPort` 互转函数 `UDPAddrFromAddrPort`:**
   - 将 `netip.AddrPort` 结构体转换为 `UDPAddr` 结构体。

4. **定义 `addrPortUDPAddr` 类型:**
   -  一个基于 `netip.AddrPort` 的 UDP 地址类型，实现了 `Addr` 接口，用于在需要 `Addr` 接口的地方使用 `netip.AddrPort`。

5. **定义 UDP 连接类型 `UDPConn`:**
   - 表示一个 UDP 网络连接，实现了 `Conn` 和 `PacketConn` 接口。
   - 提供了访问底层系统调用连接的方法 (`SyscallConn`)。

6. **UDP 数据读写函数:**
   - `ReadFromUDP`: 从 UDP 连接读取数据，并返回读取的字节数和发送端的 `UDPAddr`。
   - `readFromUDP`:  `ReadFromUDP` 的内部实现，允许预分配 `UDPAddr` 结构，提高效率。
   - `ReadFrom`:  实现了 `PacketConn` 接口的 `ReadFrom` 方法，返回读取的字节数和发送端的 `Addr` 接口。
   - `ReadFromUDPAddrPort`: 从 UDP 连接读取数据，并返回读取的字节数和发送端的 `netip.AddrPort`。
   - `ReadMsgUDP`: 从 UDP 连接读取数据和相关的带外数据 (out-of-band data)，返回读取的字节数、带外数据的字节数、消息标志和发送端的 `UDPAddr`。
   - `ReadMsgUDPAddrPort`:  `ReadMsgUDP` 的 `netip.AddrPort` 版本。
   - `WriteToUDP`: 向指定的 `UDPAddr` 发送数据。
   - `WriteToUDPAddrPort`: 向指定的 `netip.AddrPort` 发送数据。
   - `WriteTo`: 实现了 `PacketConn` 接口的 `WriteTo` 方法，向指定的 `Addr` 接口发送数据。
   - `WriteMsgUDP`: 向指定的 `UDPAddr` 发送数据和带外数据。
   - `WriteMsgUDPAddrPort`: `WriteMsgUDP` 的 `netip.AddrPort` 版本。

7. **UDP 连接创建函数:**
   - `DialUDP`:  创建一个 UDP 连接并连接到指定的远程地址。可以指定本地地址，如果本地地址为 `nil`，则会自动选择。
   - `ListenUDP`:  监听指定的本地 UDP 地址，用于接收 UDP 数据包。
   - `ListenMulticastUDP`: 监听指定网络接口上的多播 UDP 地址。

**它是什么 go 语言功能的实现:**

这段代码是 Go 语言中实现 **UDP Socket 编程** 的核心部分。它提供了创建、连接、监听 UDP 套接字以及发送和接收 UDP 数据报的基本功能。

**Go 代码举例说明:**

**示例 1:  发送和接收 UDP 数据**

```go
package main

import (
	"fmt"
	"net"
)

func main() {
	// 监听本地地址
	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("解析本地地址失败:", err)
		return
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		fmt.Println("监听失败:", err)
		return
	}
	defer conn.Close()

	// 远程地址
	remoteAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:9090")
	if err != nil {
		fmt.Println("解析远程地址失败:", err)
		return
	}

	// 发送数据
	message := []byte("Hello, UDP!")
	_, err = conn.WriteToUDP(message, remoteAddr)
	if err != nil {
		fmt.Println("发送数据失败:", err)
		return
	}
	fmt.Println("已发送:", string(message), "到", remoteAddr)

	// 接收数据
	buffer := make([]byte, 1024)
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("接收数据失败:", err)
		return
	}
	fmt.Println("接收到:", string(buffer[:n]), "来自:", addr)
}
```

**假设输入与输出:**

如果运行上述代码，假设在另一个终端运行一个监听 `127.0.0.1:9090` 的 UDP 服务，则：

**输入:**  无（代码本身会发送数据）

**输出:**

```
已发送: Hello, UDP! 到 127.0.0.1:9090
接收到: Hello, UDP! 来自: 127.0.0.1:9090
```

**示例 2:  创建 UDP 客户端连接**

```go
package main

import (
	"fmt"
	"net"
)

func main() {
	// 远程地址
	remoteAddr, err := net.ResolveUDPAddr("udp", "www.example.com:80")
	if err != nil {
		fmt.Println("解析远程地址失败:", err)
		return
	}

	// 创建 UDP 连接
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		fmt.Println("连接失败:", err)
		return
	}
	defer conn.Close()

	fmt.Println("已连接到:", conn.RemoteAddr())
}
```

**假设输入与输出:**

**输入:** 无

**输出:**  （输出的本地地址可能不同）

```
已连接到: 93.184.216.34:80
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在应用程序的 `main` 函数中，可以使用 `os.Args` 获取，然后传递给 `net` 包中的函数，例如 `ResolveUDPAddr` 的地址字符串参数。

例如，一个简单的 UDP 客户端可能通过命令行参数接收服务器地址和端口：

```go
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("用法: go run main.go <服务器地址> <端口>")
		return
	}

	serverAddr := os.Args[1]
	serverPort := os.Args[2]
	remoteAddrStr := net.JoinHostPort(serverAddr, serverPort)

	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddrStr)
	if err != nil {
		fmt.Println("解析远程地址失败:", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		fmt.Println("连接失败:", err)
		return
	}
	defer conn.Close()

	fmt.Println("已连接到:", conn.RemoteAddr())
}
```

运行这个程序时，需要在命令行指定服务器地址和端口：

```bash
go run main.go 127.0.0.1 9090
```

**使用者易犯错的点:**

1. **网络类型错误:**  在 `ResolveUDPAddr`, `DialUDP`, `ListenUDP` 等函数中，`network` 参数必须是 "udp", "udp4" 或 "udp6"，如果传入其他值会返回 `UnknownNetworkError`。

   ```go
   addr, err := net.ResolveUDPAddr("tcp", "127.0.0.1:8080") // 错误: 使用了 "tcp"
   if err != nil {
       fmt.Println(err) // 输出: unknown network tcp
   }
   ```

2. **地址格式错误:** `ResolveUDPAddr` 的 `address` 参数必须是有效的 IP 地址或主机名加上端口号的形式。

   ```go
   addr, err := net.ResolveUDPAddr("udp", "invalid-address") // 错误: 无效的地址格式
   if err != nil {
       fmt.Println(err)
   }
   ```

3. **忘记关闭连接:** `UDPConn` 使用完后应该调用 `Close()` 方法释放资源，尽管 UDP 是无连接的，但操作系统仍然需要维护相关的资源。

   ```go
   conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 8080})
   if err != nil {
       // ...
   }
   // 忘记调用 conn.Close()
   ```

4. **对无连接的理解不足:** UDP 是无连接的协议，`DialUDP` 创建的连接主要是为了方便发送数据到同一个目标地址，并不像 TCP 那样建立实际的连接。 在接收数据时，需要使用 `ReadFromUDP` 或类似的方法，因为接收到的数据可能来自任何源地址。

5. **多播地址使用不当:** 使用 `ListenMulticastUDP` 时，需要理解多播地址的特性，并确保网络接口和多播组地址的正确配置。

6. **忽略错误处理:** 网络操作很容易出错，例如端口被占用、网络不可达等，必须检查函数的返回值并妥善处理错误。

7. **带外数据 (OOB) 的使用:** `ReadMsgUDP` 和 `WriteMsgUDP` 涉及带外数据，这通常用于传递控制信息，需要对底层网络协议有更深入的理解才能正确使用。

8. **与 `netip` 包的混淆:**  虽然代码中出现了 `netip.AddrPort`，但要注意 `net` 包中的许多函数仍然使用 `UDPAddr`。需要根据具体情况选择合适的类型进行操作，并注意类型转换。

了解这些常见错误可以帮助使用者更有效地使用 Go 语言进行 UDP 网络编程。

Prompt: 
```
这是路径为go/src/net/udpsock.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"internal/itoa"
	"net/netip"
	"syscall"
)

// BUG(mikio): On Plan 9, the ReadMsgUDP and
// WriteMsgUDP methods of UDPConn are not implemented.

// BUG(mikio): On Windows, the File method of UDPConn is not
// implemented.

// BUG(mikio): On JS, methods and functions related to UDPConn are not
// implemented.

// UDPAddr represents the address of a UDP end point.
type UDPAddr struct {
	IP   IP
	Port int
	Zone string // IPv6 scoped addressing zone
}

// AddrPort returns the [UDPAddr] a as a [netip.AddrPort].
//
// If a.Port does not fit in a uint16, it's silently truncated.
//
// If a is nil, a zero value is returned.
func (a *UDPAddr) AddrPort() netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	na, _ := netip.AddrFromSlice(a.IP)
	na = na.WithZone(a.Zone)
	return netip.AddrPortFrom(na, uint16(a.Port))
}

// Network returns the address's network name, "udp".
func (a *UDPAddr) Network() string { return "udp" }

func (a *UDPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	ip := ipEmptyString(a.IP)
	if a.Zone != "" {
		return JoinHostPort(ip+"%"+a.Zone, itoa.Itoa(a.Port))
	}
	return JoinHostPort(ip, itoa.Itoa(a.Port))
}

func (a *UDPAddr) isWildcard() bool {
	if a == nil || a.IP == nil {
		return true
	}
	return a.IP.IsUnspecified()
}

func (a *UDPAddr) opAddr() Addr {
	if a == nil {
		return nil
	}
	return a
}

// ResolveUDPAddr returns an address of UDP end point.
//
// The network must be a UDP network name.
//
// If the host in the address parameter is not a literal IP address or
// the port is not a literal port number, ResolveUDPAddr resolves the
// address to an address of UDP end point.
// Otherwise, it parses the address as a pair of literal IP address
// and port number.
// The address parameter can use a host name, but this is not
// recommended, because it will return at most one of the host name's
// IP addresses.
//
// See func [Dial] for a description of the network and address
// parameters.
func ResolveUDPAddr(network, address string) (*UDPAddr, error) {
	switch network {
	case "udp", "udp4", "udp6":
	case "": // a hint wildcard for Go 1.0 undocumented behavior
		network = "udp"
	default:
		return nil, UnknownNetworkError(network)
	}
	addrs, err := DefaultResolver.internetAddrList(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return addrs.forResolve(network, address).(*UDPAddr), nil
}

// UDPAddrFromAddrPort returns addr as a [UDPAddr]. If addr.IsValid() is false,
// then the returned UDPAddr will contain a nil IP field, indicating an
// address family-agnostic unspecified address.
func UDPAddrFromAddrPort(addr netip.AddrPort) *UDPAddr {
	return &UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Zone: addr.Addr().Zone(),
		Port: int(addr.Port()),
	}
}

// An addrPortUDPAddr is a netip.AddrPort-based UDP address that satisfies the Addr interface.
type addrPortUDPAddr struct {
	netip.AddrPort
}

func (addrPortUDPAddr) Network() string { return "udp" }

// UDPConn is the implementation of the [Conn] and [PacketConn] interfaces
// for UDP network connections.
type UDPConn struct {
	conn
}

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
func (c *UDPConn) SyscallConn() (syscall.RawConn, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	return newRawConn(c.fd), nil
}

// ReadFromUDP acts like [UDPConn.ReadFrom] but returns a UDPAddr.
func (c *UDPConn) ReadFromUDP(b []byte) (n int, addr *UDPAddr, err error) {
	// This function is designed to allow the caller to control the lifetime
	// of the returned *UDPAddr and thereby prevent an allocation.
	// See https://blog.filippo.io/efficient-go-apis-with-the-inliner/.
	// The real work is done by readFromUDP, below.
	return c.readFromUDP(b, &UDPAddr{})
}

// readFromUDP implements ReadFromUDP.
func (c *UDPConn) readFromUDP(b []byte, addr *UDPAddr) (int, *UDPAddr, error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	n, addr, err := c.readFrom(b, addr)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, addr, err
}

// ReadFrom implements the [PacketConn] ReadFrom method.
func (c *UDPConn) ReadFrom(b []byte) (int, Addr, error) {
	n, addr, err := c.readFromUDP(b, &UDPAddr{})
	if addr == nil {
		// Return Addr(nil), not Addr(*UDPConn(nil)).
		return n, nil, err
	}
	return n, addr, err
}

// ReadFromUDPAddrPort acts like ReadFrom but returns a [netip.AddrPort].
//
// If c is bound to an unspecified address, the returned
// netip.AddrPort's address might be an IPv4-mapped IPv6 address.
// Use [netip.Addr.Unmap] to get the address without the IPv6 prefix.
func (c *UDPConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	if !c.ok() {
		return 0, netip.AddrPort{}, syscall.EINVAL
	}
	n, addr, err = c.readFromAddrPort(b)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, addr, err
}

// ReadMsgUDP reads a message from c, copying the payload into b and
// the associated out-of-band data into oob. It returns the number of
// bytes copied into b, the number of bytes copied into oob, the flags
// that were set on the message and the source address of the message.
//
// The packages [golang.org/x/net/ipv4] and [golang.org/x/net/ipv6] can be
// used to manipulate IP-level socket options in oob.
func (c *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *UDPAddr, err error) {
	var ap netip.AddrPort
	n, oobn, flags, ap, err = c.ReadMsgUDPAddrPort(b, oob)
	if ap.IsValid() {
		addr = UDPAddrFromAddrPort(ap)
	}
	return
}

// ReadMsgUDPAddrPort is like [UDPConn.ReadMsgUDP] but returns an [netip.AddrPort] instead of a [UDPAddr].
func (c *UDPConn) ReadMsgUDPAddrPort(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error) {
	if !c.ok() {
		return 0, 0, 0, netip.AddrPort{}, syscall.EINVAL
	}
	n, oobn, flags, addr, err = c.readMsg(b, oob)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return
}

// WriteToUDP acts like [UDPConn.WriteTo] but takes a [UDPAddr].
func (c *UDPConn) WriteToUDP(b []byte, addr *UDPAddr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.writeTo(b, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return n, err
}

// WriteToUDPAddrPort acts like [UDPConn.WriteTo] but takes a [netip.AddrPort].
func (c *UDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.writeToAddrPort(b, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addrPortUDPAddr{addr}, Err: err}
	}
	return n, err
}

// WriteTo implements the [PacketConn] WriteTo method.
func (c *UDPConn) WriteTo(b []byte, addr Addr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	a, ok := addr.(*UDPAddr)
	if !ok {
		return 0, &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr, Err: syscall.EINVAL}
	}
	n, err := c.writeTo(b, a)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: a.opAddr(), Err: err}
	}
	return n, err
}

// WriteMsgUDP writes a message to addr via c if c isn't connected, or
// to c's remote address if c is connected (in which case addr must be
// nil). The payload is copied from b and the associated out-of-band
// data is copied from oob. It returns the number of payload and
// out-of-band bytes written.
//
// The packages [golang.org/x/net/ipv4] and [golang.org/x/net/ipv6] can be
// used to manipulate IP-level socket options in oob.
func (c *UDPConn) WriteMsgUDP(b, oob []byte, addr *UDPAddr) (n, oobn int, err error) {
	if !c.ok() {
		return 0, 0, syscall.EINVAL
	}
	n, oobn, err = c.writeMsg(b, oob, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return
}

// WriteMsgUDPAddrPort is like [UDPConn.WriteMsgUDP] but takes a [netip.AddrPort] instead of a [UDPAddr].
func (c *UDPConn) WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error) {
	if !c.ok() {
		return 0, 0, syscall.EINVAL
	}
	n, oobn, err = c.writeMsgAddrPort(b, oob, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addrPortUDPAddr{addr}, Err: err}
	}
	return
}

func newUDPConn(fd *netFD) *UDPConn { return &UDPConn{conn{fd}} }

// DialUDP acts like [Dial] for UDP networks.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func DialUDP(network string, laddr, raddr *UDPAddr) (*UDPConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if raddr == nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: nil, Err: errMissingAddress}
	}
	sd := &sysDialer{network: network, address: raddr.String()}
	c, err := sd.dialUDP(context.Background(), laddr, raddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	return c, nil
}

// ListenUDP acts like [ListenPacket] for UDP networks.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenUDP listens on all available IP addresses of the local system
// except multicast IP addresses.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ListenUDP(network string, laddr *UDPAddr) (*UDPConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if laddr == nil {
		laddr = &UDPAddr{}
	}
	sl := &sysListener{network: network, address: laddr.String()}
	c, err := sl.listenUDP(context.Background(), laddr)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return c, nil
}

// ListenMulticastUDP acts like [ListenPacket] for UDP networks but
// takes a group address on a specific network interface.
//
// The network must be a UDP network name; see func [Dial] for details.
//
// ListenMulticastUDP listens on all available IP addresses of the
// local system including the group, multicast IP address.
// If ifi is nil, ListenMulticastUDP uses the system-assigned
// multicast interface, although this is not recommended because the
// assignment depends on platforms and sometimes it might require
// routing configuration.
// If the Port field of gaddr is 0, a port number is automatically
// chosen.
//
// ListenMulticastUDP is just for convenience of simple, small
// applications. There are [golang.org/x/net/ipv4] and
// [golang.org/x/net/ipv6] packages for general purpose uses.
//
// Note that ListenMulticastUDP will set the IP_MULTICAST_LOOP socket option
// to 0 under IPPROTO_IP, to disable loopback of multicast packets.
func ListenMulticastUDP(network string, ifi *Interface, gaddr *UDPAddr) (*UDPConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: gaddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if gaddr == nil || gaddr.IP == nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: gaddr.opAddr(), Err: errMissingAddress}
	}
	sl := &sysListener{network: network, address: gaddr.String()}
	c, err := sl.listenMulticastUDP(context.Background(), ifi, gaddr)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: gaddr.opAddr(), Err: err}
	}
	return c, nil
}

"""



```