Response:
Let's break down the thought process for answering this question about `udpsock_posix.go`.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of a Go file related to UDP sockets on POSIX systems. Key aspects to address include: listing functions, inferring the overall purpose, providing code examples (with assumptions and I/O), explaining command-line parameter handling (if any), and highlighting potential pitfalls for users.

**2. High-Level Analysis of the Code:**

* **Package Declaration:** `package net` immediately tells us this code is part of Go's standard network library.
* **Build Constraint:** `//go:build unix || js || wasip1 || windows` indicates this file handles UDP socket operations on Unix-like systems (including some browser/WASI environments) and Windows. This means it's likely a platform-specific implementation detail.
* **Imports:**  `context`, `net/netip`, and `syscall` are crucial. `syscall` strongly suggests direct interaction with the operating system's socket API. `netip` indicates the use of the newer, more efficient IP address representation. `context` hints at potentially asynchronous operations or timeouts.
* **Function Names:**  `sockaddrToUDP`, `family`, `sockaddr`, `readFrom`, `writeTo`, `dialUDP`, `listenUDP`, `listenMulticastUDP`, and similar names strongly suggest this code deals with converting between Go's `net` types and the underlying OS socket structures, as well as performing core UDP operations.

**3. Detailed Function Analysis (Iterative Process):**

I would go through each function and try to understand its purpose. Here's a likely internal monologue:

* **`sockaddrToUDP`:**  Looks like it converts a low-level `syscall.Sockaddr` (from the OS) into a higher-level `net.UDPAddr`. The `switch` statement handles IPv4 and IPv6 differently, which is expected.
* **`family`:** Returns the address family (IPv4 or IPv6) of a `UDPAddr`.
* **`sockaddr`:**  The reverse of `sockaddrToUDP`. Converts a `net.UDPAddr` to a `syscall.Sockaddr`.
* **`toLocal`:** Creates a `UDPAddr` with the loopback IP address and the specified port and zone. Useful for local communication.
* **`readFrom`:** Reads data from a UDP socket and populates a `UDPAddr` with the sender's address. Handles IPv4 and IPv6 separately. The comment about memory allocation (`ip escapes`) is a subtle optimization detail.
* **`readFromAddrPort`:** Similar to `readFrom` but uses the `netip.AddrPort` type for potentially better performance.
* **`readMsg`:** Reads data and ancillary data (OOB - Out-Of-Band) along with the sender's address. Again, IPv4 and IPv6 are handled separately.
* **`writeTo`:** Sends data to a specific UDP address. Checks if the socket is connected (and errors if it is, as `WriteTo` is for connectionless sockets).
* **`writeToAddrPort`:** Similar to `writeTo` but uses `netip.AddrPort`.
* **`writeMsg`:** Sends data and optional OOB data to a UDP address.
* **`writeMsgAddrPort`:** Similar to `writeMsg` but uses `netip.AddrPort`.
* **`dialUDP`:**  Initiates a UDP connection (though UDP is connectionless, this likely sets up a "connected" UDP socket which has a default destination). It uses `internetSocket`, suggesting it's a lower-level function. It also handles `ControlContext` which allows for more fine-grained control during connection establishment.
* **`listenUDP`:**  Binds a UDP socket to a local address and port, making it ready to receive data.
* **`listenMulticastUDP`:**  Specifically sets up a socket to listen for multicast UDP traffic. It calls `listenIPv4MulticastUDP` or `listenIPv6MulticastUDP` depending on the address family.
* **`listenIPv4MulticastUDP`/`listenIPv6MulticastUDP`:**  These functions handle the details of joining multicast groups and setting interface options.

**4. Inferring the Overall Functionality:**

Based on the individual function analysis, the overall purpose becomes clear: This file provides the core implementation for UDP socket operations within Go's `net` package on POSIX-like systems and Windows. It handles:

* **Address Conversion:** Converting between Go's address types (`UDPAddr`, `netip.AddrPort`) and the OS's socket address structures (`syscall.SockaddrInet4`, `syscall.SockaddrInet6`).
* **Basic UDP Operations:**  Sending and receiving UDP packets (`readFrom`, `writeTo`, `readMsg`, `writeMsg`).
* **Connection Management (for "connected" UDP):**  The `dialUDP` function suggests support for the concept of a connected UDP socket.
* **Listening:** Setting up UDP sockets to receive data (`listenUDP`).
* **Multicast:**  Specifically handling multicast UDP communication (`listenMulticastUDP`).

**5. Developing Code Examples:**

For each key functionality (dialing, listening, sending, receiving), I'd construct a simple, illustrative code snippet. This involves:

* **Choosing Relevant Functions:**  For sending, `WriteTo` is a good choice. For receiving, `ReadFrom`. For listening, `ListenUDP`. For dialing, `DialUDP`.
* **Setting up Assumptions:**  Clearly stating the assumed IP addresses, ports, and data being sent. This makes the example concrete.
* **Providing Expected Input/Output:**  Showing what the code will likely send or receive, making it easy to understand the effect.

**6. Addressing Command-Line Arguments:**

After reviewing the code, it's evident that this *specific* file doesn't directly handle command-line arguments. The higher-level `net` package and programs using it would handle that. So, the answer correctly points out this absence.

**7. Identifying Common Mistakes:**

Thinking about how developers might use these functions incorrectly leads to the "common mistakes" section. The key errors revolve around:

* **Using `WriteTo` on a connected socket:** This is a common misunderstanding of connected UDP.
* **Forgetting to handle errors:**  Standard Go best practice.
* **Incorrect address types:** Mixing up `UDPAddr` and `netip.AddrPort` or providing invalid addresses.

**8. Structuring the Answer:**

Finally, organizing the information logically is important for clarity. The chosen structure (function list, inferred functionality, code examples, command-line arguments, common mistakes) is a good way to cover all aspects of the request. Using clear, concise language and code formatting enhances readability.

**Self-Correction/Refinement:**

During the process, I might revisit earlier points. For example, initially, I might not fully grasp the difference between `readFrom` and `readFromAddrPort`. Further examination of the code and the `netip` package would clarify that one uses the older `UDPAddr` while the other leverages the newer, potentially more efficient `netip.AddrPort`. Similarly, understanding the nuance of "connected" UDP requires careful reading of the `dialUDP` and `writeTo` function logic.
这个 `go/src/net/udpsock_posix.go` 文件是 Go 语言标准库 `net` 包中处理 UDP 套接字在 POSIX 兼容操作系统（以及 `js`, `wasip1`, `windows`）上的特定实现。它包含了与底层系统调用交互，以及 Go 语言网络类型 (`UDPAddr`, `UDPConn`) 和系统调用地址结构 (`syscall.SockaddrInet4`, `syscall.SockaddrInet6`) 之间转换的功能。

**以下是该文件的主要功能：**

1. **地址转换:**
   - `sockaddrToUDP(sa syscall.Sockaddr) Addr`: 将底层的 `syscall.Sockaddr` 结构（表示操作系统级别的套接字地址）转换为 Go 语言的 `UDPAddr` 类型。这个函数能够处理 IPv4 和 IPv6 的地址。
   - `(a *UDPAddr) sockaddr(family int) (syscall.Sockaddr, error)`: 将 Go 语言的 `UDPAddr` 类型转换为底层的 `syscall.Sockaddr` 结构。这个是 `sockaddrToUDP` 的逆向操作。
   - `(a *UDPAddr) family() int`: 返回 `UDPAddr` 的地址族（`syscall.AF_INET` for IPv4, `syscall.AF_INET6` for IPv6）。

2. **读取数据:**
   - `(c *UDPConn) readFrom(b []byte, addr *UDPAddr) (int, *UDPAddr, error)`: 从 UDP 连接中读取数据，并将发送方的地址信息填充到 `addr` 中。它根据地址族（IPv4 或 IPv6）调用不同的底层 `readFromInet4` 或 `readFromInet6` 方法。
   - `(c *UDPConn) readFromAddrPort(b []byte) (n int, addr netip.AddrPort, err error)`:  与 `readFrom` 类似，但使用更高效的 `netip.AddrPort` 类型来表示地址和端口。
   - `(c *UDPConn) readMsg(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error)`:  读取数据和辅助数据（out-of-band data），并获取发送方的地址信息（使用 `netip.AddrPort`）。

3. **写入数据:**
   - `(c *UDPConn) writeTo(b []byte, addr *UDPAddr) (int, error)`: 将数据写入到指定的 UDP 地址。它会检查连接是否已经建立（对于 "connected" 的 UDP 连接），并根据地址族调用不同的底层 `writeToInet4` 或 `writeToInet6` 方法。
   - `(c *UDPConn) writeToAddrPort(b []byte, addr netip.AddrPort) (int, error)`: 与 `writeTo` 类似，但使用 `netip.AddrPort` 类型指定目标地址。
   - `(c *UDPConn) writeMsg(b, oob []byte, addr *UDPAddr) (n, oobn int, err error)`:  写入数据和辅助数据到指定的 UDP 地址。
   - `(c *UDPConn) writeMsgAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error)`: 与 `writeMsg` 类似，但使用 `netip.AddrPort` 类型指定目标地址。

4. **连接和监听:**
   - `(sd *sysDialer) dialUDP(ctx context.Context, laddr, raddr *UDPAddr) (*UDPConn, error)`: 用于创建一个 UDP 连接。`laddr` 是本地地址（可以为 `nil`），`raddr` 是远程地址。虽然 UDP 是无连接的协议，但 `DialUDP` 可以创建一个 "connected" 的 UDP 套接字，这意味着后续的 `Write` 操作会默认发送到 `raddr`。
   - `(sl *sysListener) listenUDP(ctx context.Context, laddr *UDPAddr) (*UDPConn, error)`: 用于监听指定的本地 UDP 地址和端口，创建一个可以接收数据的 `UDPConn`。
   - `(sl *sysListener) listenMulticastUDP(ctx context.Context, ifi *Interface, gaddr *UDPAddr) (*UDPConn, error)`:  用于监听指定的组播 UDP 地址。`ifi` 指定网络接口，`gaddr` 是组播地址。
   - `listenIPv4MulticastUDP(c *UDPConn, ifi *Interface, ip IP)` 和 `listenIPv6MulticastUDP(c *UDPConn, ifi *Interface, ip IP)`:  处理 IPv4 和 IPv6 的组播监听的具体设置，包括设置接口、禁用环回以及加入组播组。

5. **辅助功能:**
   - `(a *UDPAddr) toLocal(net string) sockaddr`: 创建一个本地环回地址的 `UDPAddr`，端口号保持不变。
   - `loopbackIP(net string) IP`:  （虽然不在提供的代码片段中，但被 `toLocal` 使用）根据网络类型返回对应的环回 IP 地址（IPv4 或 IPv6）。

**它是什么go语言功能的实现：**

这个文件是 Go 语言 `net` 包中关于 UDP 协议的核心实现之一，负责与操作系统底层的 UDP 套接字 API 进行交互。它允许 Go 程序进行 UDP 通信，包括单播和组播。

**Go 代码举例说明：**

以下代码示例演示了如何使用 `net` 包中的 UDP 相关功能，而 `udpsock_posix.go` 中的代码正是这些功能的底层实现。

```go
package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	// 监听 UDP 地址
	listenAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:20001")
	if err != nil {
		fmt.Println("解析监听地址失败:", err)
		return
	}
	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		fmt.Println("监听 UDP 失败:", err)
		return
	}
	defer conn.Close()
	fmt.Println("监听 UDP 地址:", conn.LocalAddr())

	// 发送数据到 UDP 地址
	remoteAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:20002")
	if err != nil {
		fmt.Println("解析远程地址失败:", err)
		return
	}
	sendConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		fmt.Println("连接 UDP 失败:", err)
		return
	}
	defer sendConn.Close()

	message := []byte("Hello UDP Server!")
	_, err = sendConn.Write(message)
	if err != nil {
		fmt.Println("发送数据失败:", err)
		return
	}
	fmt.Println("发送数据:", string(message), "到", remoteAddr)

	// 从 UDP 接收数据
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 设置读取超时
	n, addr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("接收数据失败:", err)
		return
	}
	fmt.Println("接收到", n, "字节数据来自:", addr, ", 内容:", string(buffer[:n]))
}
```

**假设的输入与输出：**

如果运行上述代码，假设没有防火墙阻止，并且有一个 UDP 服务监听在 `127.0.0.1:20002`，那么输出可能如下：

```
监听 UDP 地址: 127.0.0.1:20001
发送数据: Hello UDP Server! 到 127.0.0.1:20002
接收到 17 字节数据来自: 127.0.0.1:xxxxx, 内容: Hello UDP Server!
```

其中 `xxxxx` 是发送端的临时端口号。

**代码推理：**

`udpsock_posix.go` 中的 `readFromUDP` 和 `writeTo` 等方法会被上层 `net` 包的 `UDPConn` 的 `ReadFromUDP` 和 `WriteTo` 方法调用。例如，当 `conn.ReadFromUDP(buffer)` 被调用时，最终会调用到 `udpsock_posix.go` 中的 `(c *UDPConn) readFrom(b []byte, addr *UDPAddr) (int, *UDPAddr, error)` 方法。

**命令行参数的具体处理：**

该文件本身不直接处理命令行参数。命令行参数的处理通常发生在应用程序的 `main` 函数中，使用 `os.Args` 或 `flag` 包来解析。`udpsock_posix.go` 作为 `net` 包的一部分，其功能是被其他 Go 代码调用的，而不是独立运行的程序。

**使用者易犯错的点：**

1. **在 "connected" 的 UDP 连接上使用 `WriteTo`：**  如果使用 `DialUDP` 创建了一个连接到特定远程地址的 UDP 连接，那么后续应该使用 `Write` 方法发送数据，而不是 `WriteTo`。  `WriteTo` 用于发送数据到任意地址，在已连接的 UDP 套接字上调用会返回 `ErrWriteToConnected` 错误。

   ```go
   // 错误示例：在已连接的 UDP 套接字上使用 WriteTo
   conn, _ := net.DialUDP("udp", nil, remoteAddr)
   defer conn.Close()
   _, err = conn.WriteTo([]byte("数据"), anotherRemoteAddr) // 这是一个错误用法
   if err == net.ErrWriteToConnected {
       fmt.Println("错误：不能在已连接的 UDP 套接字上使用 WriteTo 发送到其他地址")
   }
   ```

2. **忘记处理错误：** 网络操作很容易出错，比如连接失败、读取超时等。必须检查并妥善处理 `error` 返回值。

3. **地址类型混淆：**  `net.UDPAddr` 和 `netip.AddrPort` 是不同的类型。虽然它们都表示网络地址，但在某些新的 API 中推荐使用 `netip.AddrPort` 以获得更好的性能。确保在调用不同的 `net` 包函数时使用正确的地址类型。

总而言之，`go/src/net/udpsock_posix.go` 是 Go 语言网络编程中 UDP 功能的基石，它负责处理与操作系统底层交互的细节，为上层 `net` 包提供可靠的 UDP 通信能力。

### 提示词
```
这是路径为go/src/net/udpsock_posix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix || js || wasip1 || windows

package net

import (
	"context"
	"net/netip"
	"syscall"
)

func sockaddrToUDP(sa syscall.Sockaddr) Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &UDPAddr{IP: sa.Addr[0:], Port: sa.Port}
	case *syscall.SockaddrInet6:
		return &UDPAddr{IP: sa.Addr[0:], Port: sa.Port, Zone: zoneCache.name(int(sa.ZoneId))}
	}
	return nil
}

func (a *UDPAddr) family() int {
	if a == nil || len(a.IP) <= IPv4len {
		return syscall.AF_INET
	}
	if a.IP.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func (a *UDPAddr) sockaddr(family int) (syscall.Sockaddr, error) {
	if a == nil {
		return nil, nil
	}
	return ipToSockaddr(family, a.IP, a.Port, a.Zone)
}

func (a *UDPAddr) toLocal(net string) sockaddr {
	return &UDPAddr{loopbackIP(net), a.Port, a.Zone}
}

func (c *UDPConn) readFrom(b []byte, addr *UDPAddr) (int, *UDPAddr, error) {
	var n int
	var err error
	switch c.fd.family {
	case syscall.AF_INET:
		var from syscall.SockaddrInet4
		n, err = c.fd.readFromInet4(b, &from)
		if err == nil {
			ip := from.Addr // copy from.Addr; ip escapes, so this line allocates 4 bytes
			*addr = UDPAddr{IP: ip[:], Port: from.Port}
		}
	case syscall.AF_INET6:
		var from syscall.SockaddrInet6
		n, err = c.fd.readFromInet6(b, &from)
		if err == nil {
			ip := from.Addr // copy from.Addr; ip escapes, so this line allocates 16 bytes
			*addr = UDPAddr{IP: ip[:], Port: from.Port, Zone: zoneCache.name(int(from.ZoneId))}
		}
	}
	if err != nil {
		// No sockaddr, so don't return UDPAddr.
		addr = nil
	}
	return n, addr, err
}

func (c *UDPConn) readFromAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	var ip netip.Addr
	var port int
	switch c.fd.family {
	case syscall.AF_INET:
		var from syscall.SockaddrInet4
		n, err = c.fd.readFromInet4(b, &from)
		if err == nil {
			ip = netip.AddrFrom4(from.Addr)
			port = from.Port
		}
	case syscall.AF_INET6:
		var from syscall.SockaddrInet6
		n, err = c.fd.readFromInet6(b, &from)
		if err == nil {
			ip = netip.AddrFrom16(from.Addr).WithZone(zoneCache.name(int(from.ZoneId)))
			port = from.Port
		}
	}
	if err == nil {
		addr = netip.AddrPortFrom(ip, uint16(port))
	}
	return n, addr, err
}

func (c *UDPConn) readMsg(b, oob []byte) (n, oobn, flags int, addr netip.AddrPort, err error) {
	switch c.fd.family {
	case syscall.AF_INET:
		var sa syscall.SockaddrInet4
		n, oobn, flags, err = c.fd.readMsgInet4(b, oob, 0, &sa)
		ip := netip.AddrFrom4(sa.Addr)
		addr = netip.AddrPortFrom(ip, uint16(sa.Port))
	case syscall.AF_INET6:
		var sa syscall.SockaddrInet6
		n, oobn, flags, err = c.fd.readMsgInet6(b, oob, 0, &sa)
		ip := netip.AddrFrom16(sa.Addr).WithZone(zoneCache.name(int(sa.ZoneId)))
		addr = netip.AddrPortFrom(ip, uint16(sa.Port))
	}
	return
}

func (c *UDPConn) writeTo(b []byte, addr *UDPAddr) (int, error) {
	if c.fd.isConnected {
		return 0, ErrWriteToConnected
	}
	if addr == nil {
		return 0, errMissingAddress
	}

	switch c.fd.family {
	case syscall.AF_INET:
		sa, err := ipToSockaddrInet4(addr.IP, addr.Port)
		if err != nil {
			return 0, err
		}
		return c.fd.writeToInet4(b, &sa)
	case syscall.AF_INET6:
		sa, err := ipToSockaddrInet6(addr.IP, addr.Port, addr.Zone)
		if err != nil {
			return 0, err
		}
		return c.fd.writeToInet6(b, &sa)
	default:
		return 0, &AddrError{Err: "invalid address family", Addr: addr.IP.String()}
	}
}

func (c *UDPConn) writeToAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if c.fd.isConnected {
		return 0, ErrWriteToConnected
	}
	if !addr.IsValid() {
		return 0, errMissingAddress
	}

	switch c.fd.family {
	case syscall.AF_INET:
		sa, err := addrPortToSockaddrInet4(addr)
		if err != nil {
			return 0, err
		}
		return c.fd.writeToInet4(b, &sa)
	case syscall.AF_INET6:
		sa, err := addrPortToSockaddrInet6(addr)
		if err != nil {
			return 0, err
		}
		return c.fd.writeToInet6(b, &sa)
	default:
		return 0, &AddrError{Err: "invalid address family", Addr: addr.Addr().String()}
	}
}

func (c *UDPConn) writeMsg(b, oob []byte, addr *UDPAddr) (n, oobn int, err error) {
	if c.fd.isConnected && addr != nil {
		return 0, 0, ErrWriteToConnected
	}
	if !c.fd.isConnected && addr == nil {
		return 0, 0, errMissingAddress
	}
	sa, err := addr.sockaddr(c.fd.family)
	if err != nil {
		return 0, 0, err
	}
	return c.fd.writeMsg(b, oob, sa)
}

func (c *UDPConn) writeMsgAddrPort(b, oob []byte, addr netip.AddrPort) (n, oobn int, err error) {
	if c.fd.isConnected && addr.IsValid() {
		return 0, 0, ErrWriteToConnected
	}
	if !c.fd.isConnected && !addr.IsValid() {
		return 0, 0, errMissingAddress
	}

	switch c.fd.family {
	case syscall.AF_INET:
		sa, err := addrPortToSockaddrInet4(addr)
		if err != nil {
			return 0, 0, err
		}
		return c.fd.writeMsgInet4(b, oob, &sa)
	case syscall.AF_INET6:
		sa, err := addrPortToSockaddrInet6(addr)
		if err != nil {
			return 0, 0, err
		}
		return c.fd.writeMsgInet6(b, oob, &sa)
	default:
		return 0, 0, &AddrError{Err: "invalid address family", Addr: addr.Addr().String()}
	}
}

func (sd *sysDialer) dialUDP(ctx context.Context, laddr, raddr *UDPAddr) (*UDPConn, error) {
	ctrlCtxFn := sd.Dialer.ControlContext
	if ctrlCtxFn == nil && sd.Dialer.Control != nil {
		ctrlCtxFn = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return sd.Dialer.Control(network, address, c)
		}
	}
	fd, err := internetSocket(ctx, sd.network, laddr, raddr, syscall.SOCK_DGRAM, 0, "dial", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	return newUDPConn(fd), nil
}

func (sl *sysListener) listenUDP(ctx context.Context, laddr *UDPAddr) (*UDPConn, error) {
	var ctrlCtxFn func(ctx context.Context, network, address string, c syscall.RawConn) error
	if sl.ListenConfig.Control != nil {
		ctrlCtxFn = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return sl.ListenConfig.Control(network, address, c)
		}
	}
	fd, err := internetSocket(ctx, sl.network, laddr, nil, syscall.SOCK_DGRAM, 0, "listen", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	return newUDPConn(fd), nil
}

func (sl *sysListener) listenMulticastUDP(ctx context.Context, ifi *Interface, gaddr *UDPAddr) (*UDPConn, error) {
	var ctrlCtxFn func(ctx context.Context, network, address string, c syscall.RawConn) error
	if sl.ListenConfig.Control != nil {
		ctrlCtxFn = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return sl.ListenConfig.Control(network, address, c)
		}
	}
	fd, err := internetSocket(ctx, sl.network, gaddr, nil, syscall.SOCK_DGRAM, 0, "listen", ctrlCtxFn)
	if err != nil {
		return nil, err
	}
	c := newUDPConn(fd)
	if ip4 := gaddr.IP.To4(); ip4 != nil {
		if err := listenIPv4MulticastUDP(c, ifi, ip4); err != nil {
			c.Close()
			return nil, err
		}
	} else {
		if err := listenIPv6MulticastUDP(c, ifi, gaddr.IP); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

func listenIPv4MulticastUDP(c *UDPConn, ifi *Interface, ip IP) error {
	if ifi != nil {
		if err := setIPv4MulticastInterface(c.fd, ifi); err != nil {
			return err
		}
	}
	if err := setIPv4MulticastLoopback(c.fd, false); err != nil {
		return err
	}
	if err := joinIPv4Group(c.fd, ifi, ip); err != nil {
		return err
	}
	return nil
}

func listenIPv6MulticastUDP(c *UDPConn, ifi *Interface, ip IP) error {
	if ifi != nil {
		if err := setIPv6MulticastInterface(c.fd, ifi); err != nil {
			return err
		}
	}
	if err := setIPv6MulticastLoopback(c.fd, false); err != nil {
		return err
	}
	if err := joinIPv6Group(c.fd, ifi, ip); err != nil {
		return err
	}
	return nil
}
```