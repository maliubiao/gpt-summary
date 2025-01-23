Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `net` package and specifically deals with TCP sockets. I need to:

1. **List the functionalities** present in the code. This involves identifying the purpose of the defined structs, methods, and functions.
2. **Infer the Go language feature being implemented.** Based on the functionalities, I should determine what high-level networking capability this code contributes to.
3. **Provide Go code examples.**  Demonstrate how the identified functionalities can be used in practice.
4. **Include assumptions for code examples.**  Specify the input and expected output of the example code.
5. **Explain command-line parameter handling.** If the code involves processing command-line arguments, I need to detail how it's done. (Based on the code, this seems unlikely, but I should be prepared to address it if needed.)
6. **Point out common mistakes.** Identify potential pitfalls for users when interacting with this part of the `net` package.
7. **Answer in Chinese.**  All the responses should be in Chinese.

**Plan:**

1. Analyze the `TCPAddr` struct and its methods to understand how TCP addresses are represented and manipulated.
2. Analyze the `TCPConn` struct and its methods to understand how TCP connections are handled, including reading, writing, closing, and setting options.
3. Analyze the `TCPListener` struct and its methods to understand how to create and manage TCP listeners for accepting incoming connections.
4. Identify the core Go networking feature being implemented (TCP socket functionality).
5. Create Go code examples demonstrating `DialTCP`, `ListenTCP`, `AcceptTCP`, sending and receiving data, and setting TCP options like `KeepAlive` and `NoDelay`.
6. Define assumed inputs and expected outputs for the code examples.
7. Review the code for any command-line argument processing (none apparent).
8. Identify potential user errors, focusing on incorrect address formats, not closing connections, and misunderstanding TCP options.
9. Format the answer in Chinese.
这段代码是 Go 语言 `net` 包中关于 TCP 套接字实现的一部分，它定义了用于处理 TCP 网络连接的关键类型和方法。以下是它的主要功能：

**1. 表示 TCP 地址 (`TCPAddr`)：**

*   `TCPAddr` 结构体用于表示 TCP 协议的网络端点地址，包含 IP 地址 (`IP`)、端口号 (`Port`) 和 IPv6 的作用域 (`Zone`)。
*   提供了将 `TCPAddr` 转换为 `netip.AddrPort` 的方法 (`AddrPort`)，方便与新的 `net/netip` 包进行互操作。
*   提供了获取网络类型 (`Network()`)，总是返回 "tcp"。
*   提供了将 `TCPAddr` 转换为字符串表示的方法 (`String()`)，格式为 "host:port" 或 "host%zone:port" (对于 IPv6)。
*   提供了判断是否为通配符地址的方法 (`isWildcard()`).
*   提供了转换为通用 `Addr` 接口的方法 (`opAddr()`).

**2. 解析 TCP 地址字符串 (`ResolveTCPAddr`)：**

*   `ResolveTCPAddr` 函数用于将一个网络类型和地址字符串解析为 `TCPAddr` 结构体。
*   它支持将主机名解析为 IP 地址，但也提醒不推荐这样做，因为它只会返回主机名的一个 IP 地址。
*   支持 "tcp"、"tcp4" 和 "tcp6" 等网络类型。

**3. 从 `netip.AddrPort` 创建 `TCPAddr` (`TCPAddrFromAddrPort`)：**

*   `TCPAddrFromAddrPort` 函数用于将 `netip.AddrPort` 结构体转换为 `TCPAddr` 结构体。

**4. 表示 TCP 连接 (`TCPConn`)：**

*   `TCPConn` 结构体是 `Conn` 接口针对 TCP 网络连接的具体实现。
*   它内嵌了 `conn` 结构体，后者包含了底层的文件描述符等信息。
*   提供了获取原始网络连接的方法 (`SyscallConn()`)，返回 `syscall.RawConn` 接口，允许进行更底层的操作。
*   实现了 `io.ReaderFrom` 接口的 `ReadFrom()` 方法，允许从 `io.Reader` 读取数据并写入连接。
*   实现了 `io.WriterTo` 接口的 `WriteTo()` 方法，允许将连接中的数据写入 `io.Writer`。
*   提供了关闭连接读端 (`CloseRead()`) 和写端 (`CloseWrite()`) 的方法。
*   提供了设置连接关闭时行为的方法 (`SetLinger()`)，控制是否等待发送缓冲区的数据发送完毕。
*   提供了设置是否发送 TCP keep-alive 探测报文的方法 (`SetKeepAlive()`)。
*   提供了设置 TCP keep-alive 探测报文发送间隔的方法 (`SetKeepAlivePeriod()`)。
*   提供了设置是否禁用 Nagle 算法的方法 (`SetNoDelay()`)，控制是否立即发送小数据包。
*   提供了查询连接是否使用 Multipath TCP (MPTCP) 的方法 (`MultipathTCP()`)。

**5. 配置 TCP Keep-Alive (`KeepAliveConfig`)：**

*   `KeepAliveConfig` 结构体用于配置 TCP keep-alive 选项，包括是否启用、空闲时间、探测间隔和探测次数。

**6. 创建 TCP 连接 (`DialTCP`)：**

*   `DialTCP` 函数类似于 `Dial` 函数，专门用于创建 TCP 连接。
*   它需要网络类型（如 "tcp"、"tcp4"、"tcp6"）以及本地地址 (`laddr`) 和远程地址 (`raddr`)。
*   如果 `laddr` 为 `nil`，则自动选择本地地址。
*   如果 `raddr` 的 IP 字段为 `nil` 或未指定的 IP 地址，则假定为本地系统。
*   它会根据系统支持情况尝试使用 MPTCP 进行连接。

**7. 表示 TCP 监听器 (`TCPListener`)：**

*   `TCPListener` 结构体是 TCP 网络监听器的实现。
*   它内嵌了 `netFD` 结构体，包含了监听套接字的文件描述符等信息。
*   内嵌了 `ListenConfig` 结构体，用于配置监听器。
*   提供了获取原始网络连接的方法 (`SyscallConn()`)，返回 `syscall.RawConn` 接口，但只支持调用 `Control` 方法。
*   提供了接受新的连接的方法 (`AcceptTCP()`)，返回一个 `TCPConn` 类型的连接。
*   实现了 `Listener` 接口的 `Accept()` 方法，返回一个通用的 `Conn` 接口。
*   提供了停止监听的方法 (`Close()`)。
*   提供了获取监听器本地地址的方法 (`Addr()`)，返回一个 `*TCPAddr`。
*   提供了设置监听器截止时间的方法 (`SetDeadline()`)。
*   提供了获取底层 `os.File` 副本的方法 (`File()`)。

**8. 创建 TCP 监听器 (`ListenTCP`)：**

*   `ListenTCP` 函数类似于 `Listen` 函数，专门用于创建 TCP 监听器。
*   它需要网络类型（如 "tcp"、"tcp4"、"tcp6"）和本地地址 (`laddr`)。
*   如果 `laddr` 的 IP 字段为 `nil` 或未指定的 IP 地址，则监听所有可用的本地 IP 地址。
*   如果 `laddr` 的端口字段为 0，则自动选择一个可用的端口。
*   它会根据系统支持情况尝试使用 MPTCP 进行监听。

**推断的 Go 语言功能实现：**

这段代码是 Go 语言 `net` 包中 **TCP 协议网络编程** 的核心实现。它提供了创建、连接、监听和管理 TCP 连接的能力，是构建基于 TCP 协议的网络应用的基础。

**Go 代码示例：**

以下代码示例展示了如何使用 `DialTCP` 创建 TCP 客户端连接，发送数据并接收响应：

```go
package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

func main() {
	// 假设服务器监听在 127.0.0.1:8080
	serverAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("解析服务器地址失败:", err)
		return
	}

	// 假设本地地址为空
	conn, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		fmt.Println("连接服务器失败:", err)
		return
	}
	defer conn.Close()

	// 假设发送的数据是 "Hello Server!"
	message := "Hello Server!\n"
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Println("发送数据失败:", err)
		return
	}
	fmt.Printf("发送数据: %s", message)

	// 假设接收服务器的响应
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 设置读取超时
	n, err := conn.Read(buffer)
	if err != nil {
		if err == io.EOF {
			fmt.Println("服务器已关闭连接")
		} else {
			fmt.Println("接收数据失败:", err)
		}
		return
	}
	fmt.Printf("接收数据: %s", string(buffer[:n]))

	// 假设输出：
	// 发送数据: Hello Server!
	// 接收数据: Hello from Server!
}
```

以下代码示例展示了如何使用 `ListenTCP` 创建 TCP 服务器监听器，并接受客户端连接：

```go
package main

import (
	"fmt"
	"io"
	"net"
)

func main() {
	// 假设监听在本地所有 IP 的 8080 端口
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 8080})
	if err != nil {
		fmt.Println("创建监听器失败:", err)
		return
	}
	defer listener.Close()
	fmt.Println("监听中...")

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Println("接受连接失败:", err)
			continue
		}
		fmt.Println("接受到来自", conn.RemoteAddr(), "的连接")
		go handleConnection(conn) // 启动 goroutine 处理连接
	}
}

func handleConnection(conn *net.TCPConn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Println("读取数据错误:", err)
			}
			return
		}
		fmt.Printf("收到来自 %s 的数据: %s", conn.RemoteAddr(), string(buffer[:n]))

		// 假设服务器回复 "Hello from Server!"
		_, err = conn.Write([]byte("Hello from Server!\n"))
		if err != nil {
			fmt.Println("发送数据错误:", err)
			return
		}
	}
}

// 假设输出（运行服务器后，客户端连接）：
// 监听中...
// 接受到来自 127.0.0.1:xxxxx 的连接
// 收到来自 127.0.0.1:xxxxx 的数据: Hello Server!
```

**命令行参数处理：**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常在 `main` 函数中使用 `os.Args` 或 `flag` 包来实现。这段代码提供的功能是底层的网络操作，可以被使用在需要进行网络通信的程序中，而这些程序可能会通过命令行参数来指定服务器地址、端口等信息。

**使用者易犯错的点：**

1. **未正确关闭连接：**  创建 TCP 连接后，如果没有显式地调用 `Close()` 方法关闭连接，会导致资源泄漏。应该使用 `defer conn.Close()` 确保连接在使用完毕后被关闭。

    ```go
    // 错误示例
    conn, err := net.DialTCP("tcp", nil, serverAddr)
    if err != nil {
        // ... 错误处理
        return
    }
    // 没有 defer conn.Close()

    // 正确示例
    conn, err := net.DialTCP("tcp", nil, serverAddr)
    if err != nil {
        // ... 错误处理
        return
    }
    defer conn.Close()
    ```

2. **地址解析错误：** 使用 `ResolveTCPAddr` 解析地址时，如果提供的地址字符串格式不正确或者主机名无法解析，会导致错误。需要妥善处理 `ResolveTCPAddr` 返回的错误。

    ```go
    addr, err := net.ResolveTCPAddr("tcp", "invalid-address")
    if err != nil {
        fmt.Println("地址解析失败:", err) // 需要处理 err
        return
    }
    ```

3. **Keep-Alive 配置的平台差异：**  `KeepAliveConfig` 的注释中提到了不同操作系统对 keep-alive 配置的支持程度不同，尤其是在旧版本的 Windows 上。用户需要注意这些平台差异，避免配置不生效或产生意外行为。例如，在 Windows 10 1709 之前的版本，单独设置 `Idle` 和 `Interval` 可能不会生效。

4. **阻塞的 `Read` 操作：**  如果没有设置读取超时时间，`conn.Read()` 方法会一直阻塞等待数据到达。在某些情况下，这可能导致程序无响应。可以使用 `SetReadDeadline()` 设置读取超时。

    ```go
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    n, err := conn.Read(buffer)
    if err != nil {
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            fmt.Println("读取超时")
        } else {
            // ... 其他错误处理
        }
    }
    ```

5. **混淆 `CloseRead` 和 `CloseWrite` 与 `Close`：**  `CloseRead` 和 `CloseWrite` 仅关闭连接的读端或写端，而 `Close` 会关闭整个连接。大多数情况下，应该使用 `Close` 来关闭连接。

总而言之，这段代码提供了 Go 语言进行 TCP 网络编程的基础工具，理解其功能和潜在的陷阱对于开发健壮的网络应用至关重要。

### 提示词
```
这是路径为go/src/net/tcpsock.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package net

import (
	"context"
	"internal/itoa"
	"io"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// BUG(mikio): On JS and Windows, the File method of TCPConn and
// TCPListener is not implemented.

// TCPAddr represents the address of a TCP end point.
type TCPAddr struct {
	IP   IP
	Port int
	Zone string // IPv6 scoped addressing zone
}

// AddrPort returns the [TCPAddr] a as a [netip.AddrPort].
//
// If a.Port does not fit in a uint16, it's silently truncated.
//
// If a is nil, a zero value is returned.
func (a *TCPAddr) AddrPort() netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	na, _ := netip.AddrFromSlice(a.IP)
	na = na.WithZone(a.Zone)
	return netip.AddrPortFrom(na, uint16(a.Port))
}

// Network returns the address's network name, "tcp".
func (a *TCPAddr) Network() string { return "tcp" }

func (a *TCPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	ip := ipEmptyString(a.IP)
	if a.Zone != "" {
		return JoinHostPort(ip+"%"+a.Zone, itoa.Itoa(a.Port))
	}
	return JoinHostPort(ip, itoa.Itoa(a.Port))
}

func (a *TCPAddr) isWildcard() bool {
	if a == nil || a.IP == nil {
		return true
	}
	return a.IP.IsUnspecified()
}

func (a *TCPAddr) opAddr() Addr {
	if a == nil {
		return nil
	}
	return a
}

// ResolveTCPAddr returns an address of TCP end point.
//
// The network must be a TCP network name.
//
// If the host in the address parameter is not a literal IP address or
// the port is not a literal port number, ResolveTCPAddr resolves the
// address to an address of TCP end point.
// Otherwise, it parses the address as a pair of literal IP address
// and port number.
// The address parameter can use a host name, but this is not
// recommended, because it will return at most one of the host name's
// IP addresses.
//
// See func [Dial] for a description of the network and address
// parameters.
func ResolveTCPAddr(network, address string) (*TCPAddr, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	case "": // a hint wildcard for Go 1.0 undocumented behavior
		network = "tcp"
	default:
		return nil, UnknownNetworkError(network)
	}
	addrs, err := DefaultResolver.internetAddrList(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return addrs.forResolve(network, address).(*TCPAddr), nil
}

// TCPAddrFromAddrPort returns addr as a [TCPAddr]. If addr.IsValid() is false,
// then the returned TCPAddr will contain a nil IP field, indicating an
// address family-agnostic unspecified address.
func TCPAddrFromAddrPort(addr netip.AddrPort) *TCPAddr {
	return &TCPAddr{
		IP:   addr.Addr().AsSlice(),
		Zone: addr.Addr().Zone(),
		Port: int(addr.Port()),
	}
}

// TCPConn is an implementation of the [Conn] interface for TCP network
// connections.
type TCPConn struct {
	conn
}

// KeepAliveConfig contains TCP keep-alive options.
//
// If the Idle, Interval, or Count fields are zero, a default value is chosen.
// If a field is negative, the corresponding socket-level option will be left unchanged.
//
// Note that prior to Windows 10 version 1709, neither setting Idle and Interval
// separately nor changing Count (which is usually 10) is supported.
// Therefore, it's recommended to set both Idle and Interval to non-negative values
// in conjunction with a -1 for Count on those old Windows if you intend to customize
// the TCP keep-alive settings.
// By contrast, if only one of Idle and Interval is set to a non-negative value,
// the other will be set to the system default value, and ultimately,
// set both Idle and Interval to negative values if you want to leave them unchanged.
//
// Note that Solaris and its derivatives do not support setting Interval to a non-negative value
// and Count to a negative value, or vice-versa.
type KeepAliveConfig struct {
	// If Enable is true, keep-alive probes are enabled.
	Enable bool

	// Idle is the time that the connection must be idle before
	// the first keep-alive probe is sent.
	// If zero, a default value of 15 seconds is used.
	Idle time.Duration

	// Interval is the time between keep-alive probes.
	// If zero, a default value of 15 seconds is used.
	Interval time.Duration

	// Count is the maximum number of keep-alive probes that
	// can go unanswered before dropping a connection.
	// If zero, a default value of 9 is used.
	Count int
}

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
func (c *TCPConn) SyscallConn() (syscall.RawConn, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	return newRawConn(c.fd), nil
}

// ReadFrom implements the [io.ReaderFrom] ReadFrom method.
func (c *TCPConn) ReadFrom(r io.Reader) (int64, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.readFrom(r)
	if err != nil && err != io.EOF {
		err = &OpError{Op: "readfrom", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, err
}

// WriteTo implements the io.WriterTo WriteTo method.
func (c *TCPConn) WriteTo(w io.Writer) (int64, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.writeTo(w)
	if err != nil && err != io.EOF {
		err = &OpError{Op: "writeto", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, err
}

// CloseRead shuts down the reading side of the TCP connection.
// Most callers should just use Close.
func (c *TCPConn) CloseRead() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.closeRead(); err != nil {
		return &OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// CloseWrite shuts down the writing side of the TCP connection.
// Most callers should just use Close.
func (c *TCPConn) CloseWrite() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.closeWrite(); err != nil {
		return &OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetLinger sets the behavior of Close on a connection which still
// has data waiting to be sent or to be acknowledged.
//
// If sec < 0 (the default), the operating system finishes sending the
// data in the background.
//
// If sec == 0, the operating system discards any unsent or
// unacknowledged data.
//
// If sec > 0, the data is sent in the background as with sec < 0.
// On some operating systems including Linux, this may cause Close to block
// until all data has been sent or discarded.
// On some operating systems after sec seconds have elapsed any remaining
// unsent data may be discarded.
func (c *TCPConn) SetLinger(sec int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setLinger(c.fd, sec); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetKeepAlive sets whether the operating system should send
// keep-alive messages on the connection.
func (c *TCPConn) SetKeepAlive(keepalive bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setKeepAlive(c.fd, keepalive); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetKeepAlivePeriod sets the duration the connection needs to
// remain idle before TCP starts sending keepalive probes.
//
// Note that calling this method on Windows prior to Windows 10 version 1709
// will reset the KeepAliveInterval to the default system value, which is normally 1 second.
func (c *TCPConn) SetKeepAlivePeriod(d time.Duration) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setKeepAliveIdle(c.fd, d); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// SetNoDelay controls whether the operating system should delay
// packet transmission in hopes of sending fewer packets (Nagle's
// algorithm).  The default is true (no delay), meaning that data is
// sent as soon as possible after a Write.
func (c *TCPConn) SetNoDelay(noDelay bool) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setNoDelay(c.fd, noDelay); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// MultipathTCP reports whether the ongoing connection is using MPTCP.
//
// If Multipath TCP is not supported by the host, by the other peer or
// intentionally / accidentally filtered out by a device in between, a
// fallback to TCP will be done. This method does its best to check if
// MPTCP is still being used or not.
//
// On Linux, more conditions are verified on kernels >= v5.16, improving
// the results.
func (c *TCPConn) MultipathTCP() (bool, error) {
	if !c.ok() {
		return false, syscall.EINVAL
	}
	return isUsingMultipathTCP(c.fd), nil
}

func newTCPConn(fd *netFD, keepAliveIdle time.Duration, keepAliveCfg KeepAliveConfig, preKeepAliveHook func(*netFD), keepAliveHook func(KeepAliveConfig)) *TCPConn {
	setNoDelay(fd, true)
	if !keepAliveCfg.Enable && keepAliveIdle >= 0 {
		keepAliveCfg = KeepAliveConfig{
			Enable: true,
			Idle:   keepAliveIdle,
		}
	}
	c := &TCPConn{conn{fd}}
	if keepAliveCfg.Enable {
		if preKeepAliveHook != nil {
			preKeepAliveHook(fd)
		}
		c.SetKeepAliveConfig(keepAliveCfg)
		if keepAliveHook != nil {
			keepAliveHook(keepAliveCfg)
		}
	}
	return c
}

// DialTCP acts like [Dial] for TCP networks.
//
// The network must be a TCP network name; see func Dial for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
func DialTCP(network string, laddr, raddr *TCPAddr) (*TCPConn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if raddr == nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: nil, Err: errMissingAddress}
	}
	sd := &sysDialer{network: network, address: raddr.String()}
	var (
		c   *TCPConn
		err error
	)
	if sd.MultipathTCP() {
		c, err = sd.dialMPTCP(context.Background(), laddr, raddr)
	} else {
		c, err = sd.dialTCP(context.Background(), laddr, raddr)
	}
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	return c, nil
}

// TCPListener is a TCP network listener. Clients should typically
// use variables of type [Listener] instead of assuming TCP.
type TCPListener struct {
	fd *netFD
	lc ListenConfig
}

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
//
// The returned RawConn only supports calling Control. Read and
// Write return an error.
func (l *TCPListener) SyscallConn() (syscall.RawConn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	return newRawListener(l.fd), nil
}

// AcceptTCP accepts the next incoming call and returns the new
// connection.
func (l *TCPListener) AcceptTCP() (*TCPConn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	c, err := l.accept()
	if err != nil {
		return nil, &OpError{Op: "accept", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return c, nil
}

// Accept implements the Accept method in the [Listener] interface; it
// waits for the next call and returns a generic [Conn].
func (l *TCPListener) Accept() (Conn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	c, err := l.accept()
	if err != nil {
		return nil, &OpError{Op: "accept", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return c, nil
}

// Close stops listening on the TCP address.
// Already Accepted connections are not closed.
func (l *TCPListener) Close() error {
	if !l.ok() {
		return syscall.EINVAL
	}
	if err := l.close(); err != nil {
		return &OpError{Op: "close", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return nil
}

// Addr returns the listener's network address, a [*TCPAddr].
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *TCPListener) Addr() Addr { return l.fd.laddr }

// SetDeadline sets the deadline associated with the listener.
// A zero time value disables the deadline.
func (l *TCPListener) SetDeadline(t time.Time) error {
	if !l.ok() {
		return syscall.EINVAL
	}
	return l.fd.SetDeadline(t)
}

// File returns a copy of the underlying [os.File].
// It is the caller's responsibility to close f when finished.
// Closing l does not affect f, and closing f does not affect l.
//
// The returned os.File's file descriptor is different from the
// connection's. Attempting to change properties of the original
// using this duplicate may or may not have the desired effect.
func (l *TCPListener) File() (f *os.File, err error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	f, err = l.file()
	if err != nil {
		return nil, &OpError{Op: "file", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return
}

// ListenTCP acts like [Listen] for TCP networks.
//
// The network must be a TCP network name; see func Dial for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenTCP listens on all available unicast and anycast IP addresses
// of the local system.
// If the Port field of laddr is 0, a port number is automatically
// chosen.
func ListenTCP(network string, laddr *TCPAddr) (*TCPListener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if laddr == nil {
		laddr = &TCPAddr{}
	}
	sl := &sysListener{network: network, address: laddr.String()}
	var (
		ln  *TCPListener
		err error
	)
	if sl.MultipathTCP() {
		ln, err = sl.listenMPTCP(context.Background(), laddr)
	} else {
		ln, err = sl.listenTCP(context.Background(), laddr)
	}
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return ln, nil
}

// roundDurationUp rounds d to the next multiple of to.
func roundDurationUp(d time.Duration, to time.Duration) time.Duration {
	return (d + to - 1) / to
}
```