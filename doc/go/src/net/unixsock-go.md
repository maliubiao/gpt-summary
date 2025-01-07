Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `unixsock.go` file, which is part of the `net` package in Go. This means figuring out what it does, how it's used, potential issues, and providing examples.

**2. Initial Scan and Keyword Recognition:**

A quick skim reveals key terms: `UnixAddr`, `UnixConn`, `UnixListener`, `DialUnix`, `ListenUnix`, `ListenUnixgram`, `ReadFromUnix`, `WriteToUnix`, `ReadMsgUnix`, `WriteMsgUnix`. These immediately suggest the code deals with Unix domain sockets.

**3. Deconstructing by Type/Structure:**

It's helpful to categorize the code by the main types it defines and the functions associated with them:

*   **`UnixAddr`:**  This seems to represent the address of a Unix socket. The methods like `Network()` and `String()` confirm this. `ResolveUnixAddr` is a factory function for creating these addresses.

*   **`UnixConn`:** This appears to be the type representing a connection to a Unix socket. It embeds a `conn` (likely a generic connection struct within the `net` package). Methods like `ReadFrom`, `WriteTo`, `CloseRead`, `CloseWrite`, `SyscallConn`, and the `Msg` variations are clearly related to data transfer and control. `DialUnix` creates these connections.

*   **`UnixListener`:** This represents a listener for incoming Unix socket connections. Methods like `Accept`, `Close`, `Addr`, `SetDeadline`, `File`, and `SyscallConn` fit the pattern of a network listener. `ListenUnix` creates these listeners.

**4. Analyzing Functionality (Method by Method):**

For each significant method, consider:

*   **Purpose:** What does this method do? (Read data, send data, close the connection, etc.)
*   **Parameters:** What inputs does it take? What do they represent?
*   **Return Values:** What does it output?  What do the different return values signify (data, error, address)?
*   **Error Handling:** How does it handle errors? (Returning `error` values, using `OpError`).
*   **Relationship to Underlying System Calls:** The `SyscallConn` method explicitly points to the use of raw system calls. This is a crucial aspect of understanding the low-level nature of the code.

**5. Identifying Core Concepts:**

The code clearly implements the client-server model for Unix domain sockets:

*   **Client (Dial):**  `DialUnix` is the client-side function to establish a connection.
*   **Server (Listen/Accept):** `ListenUnix` and `ListenUnixgram` are server-side functions to create listeners, and `AcceptUnix` accepts incoming connections.
*   **Communication (Read/Write):**  The `ReadFrom`, `WriteTo`, `ReadMsgUnix`, and `WriteMsgUnix` methods handle the actual data exchange.

**6. Inferring Go Language Features:**

*   **Interfaces:** The code explicitly mentions implementing the `Conn` and `Listener` interfaces, demonstrating Go's interface-based polymorphism. `PacketConn` is also mentioned.
*   **Struct Embedding:** `UnixConn` embeds a `conn`, showcasing Go's composition mechanism.
*   **Error Handling:** The use of the `error` interface and the custom `OpError` type is standard Go error handling.
*   **Context:** `context.Context` is used in `DialUnix`, `ListenUnix`, and `ListenUnixgram`, indicating support for cancellation and timeouts.
*   **Sync Package:** `sync.Once` in `UnixListener` demonstrates thread-safe initialization/cleanup.

**7. Developing Examples:**

Once the functionality is understood, create concrete examples:

*   **Basic Client-Server:**  A simple pair of programs that connect and exchange data. This is crucial for demonstrating the core use case.
*   **Datagram Example:** Show how to use connectionless Unix sockets.
*   **Out-of-Band Data:** Illustrate the use of `ReadMsgUnix` and `WriteMsgUnix`.

**8. Considering Edge Cases and Potential Errors:**

Think about common mistakes developers might make:

*   **Incorrect Network Names:** Using the wrong string for `network` in `DialUnix` or `ListenUnix`.
*   **Missing Addresses:** Forgetting to provide an address when required.
*   **Closing Issues:**  Not understanding the difference between `Close`, `CloseRead`, and `CloseWrite`.
*   **Type Assertions:** Forgetting to type-assert the `Addr` interface to `*UnixAddr`.

**9. Structuring the Answer:**

Organize the information logically:

*   Start with a summary of the file's purpose.
*   List the key functionalities clearly.
*   Provide code examples with clear inputs and outputs.
*   Explain any command-line parameters (though this specific file doesn't directly handle them).
*   Highlight common mistakes.

**Self-Correction/Refinement during the Process:**

*   **Initial thought:** "This looks like socket programming."  Refinement: "Specifically, Unix domain socket programming."
*   **Realization:** The BUG comments are important to note limitations on certain platforms.
*   **Clarification:** Distinguish between stream (`unix`, `unixpacket`) and datagram (`unixgram`) sockets in the examples.
*   **Emphasis:** Highlight the importance of error handling in the examples.

By following this systematic approach, combining code analysis with knowledge of networking concepts and Go language features, one can effectively understand and explain the functionality of a complex code snippet like the one provided.
这段Go语言代码是 `net` 包中关于 Unix 域套接字（Unix domain sockets）的实现。它提供了在同一主机上的不同进程之间进行通信的能力。

以下是它的主要功能：

**1. 定义了 Unix 域套接字的地址类型 `UnixAddr`:**

*   `UnixAddr` 结构体包含了 Unix 域套接字的路径 `Name` 和网络类型 `Net` (可以是 "unix", "unixgram", 或 "unixpacket")。
*   提供了获取网络类型 (`Network()`) 和字符串表示 (`String()`) 的方法。
*   `ResolveUnixAddr` 函数用于将网络类型和地址字符串解析为 `UnixAddr` 结构体。

**2. 定义了 Unix 域连接类型 `UnixConn`:**

*   `UnixConn` 结构体实现了 `net.Conn` 接口，用于表示一个 Unix 域套接字连接。
*   提供了 `SyscallConn()` 方法，允许访问底层的系统调用连接。
*   提供了 `CloseRead()` 和 `CloseWrite()` 方法，分别用于关闭连接的读端和写端。
*   提供了 `ReadFromUnix()` 和 `ReadFrom()` 方法，用于从连接中读取数据，对于面向数据报的连接，还会返回发送方的地址。
*   提供了 `ReadMsgUnix()` 方法，用于读取带有辅助数据（例如发送的文件描述符）的消息。
*   提供了 `WriteToUnix()` 和 `WriteTo()` 方法，用于向指定的 Unix 域套接字地址发送数据。
*   提供了 `WriteMsgUnix()` 方法，用于发送带有辅助数据的消息。
*   `DialUnix()` 函数用于创建一个连接到指定 Unix 域套接字地址的 `UnixConn`。

**3. 定义了 Unix 域监听器类型 `UnixListener`:**

*   `UnixListener` 结构体实现了 `net.Listener` 接口，用于监听传入的 Unix 域套接字连接。
*   提供了 `SyscallConn()` 方法，允许访问底层的系统调用监听器。
*   提供了 `AcceptUnix()` 和 `Accept()` 方法，用于接受一个新的连接。
*   提供了 `Close()` 方法，用于关闭监听器。
*   提供了 `Addr()` 方法，返回监听器的网络地址。
*   提供了 `SetDeadline()` 方法，设置监听器的截止时间。
*   提供了 `File()` 方法，返回底层文件描述符的副本。
*   `ListenUnix()` 函数用于创建一个监听指定 Unix 域套接字地址的 `UnixListener`。

**4. 定义了面向数据报的 Unix 域连接类型 `ListenUnixgram` 返回的 `UnixConn`：**

*   `ListenUnixgram()` 函数用于创建一个用于接收 Unix 域数据报的 `UnixConn`。

**它是什么go语言功能的实现？**

这段代码实现了 Go 语言中对 Unix 域套接字的支持。Unix 域套接字是一种进程间通信（IPC）机制，它允许运行在同一主机上的不同进程像使用网络套接字一样进行通信，但效率更高，因为数据不需要经过网络协议栈。

**Go 代码举例说明：**

**假设：** 我们要在两个进程之间通过 Unix 域流式套接字进行通信。

**服务端 (server.go):**

```go
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	addr := &net.UnixAddr{Net: "unix", Name: "/tmp/echo.sock"}
	os.Remove(addr.Name) // 确保之前的套接字文件被删除
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		fmt.Println("监听错误:", err)
		return
	}
	defer ln.Close()
	fmt.Println("监听在", addr.Name)

	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			fmt.Println("接受连接错误:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn *net.UnixConn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("读取错误:", err)
		return
	}
	fmt.Printf("接收到: %s", buf[:n])
	_, err = conn.Write(buf[:n])
	if err != nil {
		fmt.Println("写入错误:", err)
		return
	}
}
```

**客户端 (client.go):**

```go
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	addr := &net.UnixAddr{Net: "unix", Name: "/tmp/echo.sock"}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		fmt.Println("连接错误:", err)
		os.Exit(1)
	}
	defer conn.Close()

	message := "Hello from client!\n"
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Println("写入错误:", err)
		return
	}
	fmt.Println("发送:", message)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("读取错误:", err)
		return
	}
	fmt.Printf("接收到: %s", buf[:n])
}
```

**假设的输入与输出：**

1. **运行服务端:** `go run server.go`
    **输出:** `监听在 /tmp/echo.sock`
2. **运行客户端:** `go run client.go`
    **输出:**
    ```
    发送: Hello from client!
    接收到: Hello from client!
    ```
    **服务端输出:** `接收到: Hello from client!`

**使用者易犯错的点：**

1. **忘记删除套接字文件:**  当使用流式 (`unix`) 或数据包式 (`unixpacket`) 套接字进行监听时，会在文件系统中创建一个套接字文件。如果程序异常退出，这个文件可能不会被删除，导致下次启动监听时出现地址已被使用的错误。需要在监听之前尝试删除该文件，例如使用 `os.Remove(addr.Name)`。

    ```go
    addr := &net.UnixAddr{Net: "unix", Name: "/tmp/my.sock"}
    // 易错点：忘记删除可能存在的套接字文件
    ln, err := net.ListenUnix("unix", addr)
    if err != nil {
        fmt.Println("监听错误:", err) // 可能输出 "bind: address already in use"
        return
    }
    defer ln.Close()
    ```

    **解决方法:** 在监听前显式删除：

    ```go
    addr := &net.UnixAddr{Net: "unix", Name: "/tmp/my.sock"}
    os.Remove(addr.Name) // 尝试删除已存在的套接字文件
    ln, err := net.ListenUnix("unix", addr)
    if err != nil {
        fmt.Println("监听错误:", err)
        return
    }
    defer ln.Close()
    ```

2. **网络类型与操作不匹配:**  使用了错误的网络类型 (`Net`) 会导致运行时错误。例如，尝试在 `unixgram` 连接上使用 `Accept` 方法会引发 panic，因为 `unixgram` 是面向数据报的，不需要接受连接。

    ```go
    addr := &net.UnixAddr{Net: "unixgram", Name: "/tmp/data.sock"}
    ln, err := net.ListenUnix("unixgram", addr) // 正确，应该使用 ListenUnixgram
    if err != nil {
        fmt.Println("监听错误:", err)
        return
    }
    defer ln.Close()

    // 易错点：在 unixgram 上调用 Accept 是错误的
    conn, err := ln.Accept() // 这里会引发 panic
    if err != nil {
        fmt.Println("接受错误:", err)
        return
    }
    ```

    **解决方法:** 对于数据报套接字，应该使用 `net.ListenUnixgram` 创建监听器，并使用 `ReadFrom` 和 `WriteTo` 方法进行通信，而不是 `Accept`。

3. **未处理 `Read` 或 `Write` 的返回值和错误:** 像所有网络操作一样，`Read` 和 `Write` 方法可能会返回错误，并且返回的字节数可能小于缓冲区的大小。必须检查错误并处理部分写入或读取的情况。

    ```go
    conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: "/tmp/my.sock"})
    if err != nil {
        // ... 错误处理
    }
    defer conn.Close()

    data := []byte("some data")
    // 易错点：未检查写入的字节数和错误
    _, err = conn.Write(data)
    if err != nil {
        // ... 错误处理
    }

    buf := make([]byte, 1024)
    // 易错点：未检查读取的字节数和错误
    _, err = conn.Read(buf)
    if err != nil {
        // ... 错误处理
    }
    ```

    **解决方法:** 始终检查 `Read` 和 `Write` 的返回值和错误。

4. **不理解 `unix`、`unixgram` 和 `unixpacket` 的区别:**
    *   `unix`: 提供可靠的、面向连接的字节流服务 (类似于 TCP)。需要 `ListenUnix` 和 `AcceptUnix`。
    *   `unixgram`: 提供不可靠的、面向消息的数据报服务 (类似于 UDP)。使用 `ListenUnixgram` 创建连接，并通过 `ReadFrom` 和 `WriteTo` 通信。
    *   `unixpacket`: 提供可靠的、有序的、面向消息的数据报服务。使用 `ListenUnix` 和 `AcceptUnix`，但每次 `Read` 或 `Write` 操作处理一个完整的数据包。

理解这些区别对于正确使用 Unix 域套接字至关重要。

总而言之，这段代码是 Go 语言网络编程中实现 Unix 域套接字的关键部分，允许开发者在本地进程间进行高效的通信。使用时需要注意网络类型的选择，套接字文件的管理以及错误处理。

Prompt: 
```
这是路径为go/src/net/unixsock.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"os"
	"sync"
	"syscall"
	"time"
)

// BUG(mikio): On JS, WASIP1 and Plan 9, methods and functions related
// to UnixConn and UnixListener are not implemented.

// BUG(mikio): On Windows, methods and functions related to UnixConn
// and UnixListener don't work for "unixgram" and "unixpacket".

// UnixAddr represents the address of a Unix domain socket end point.
type UnixAddr struct {
	Name string
	Net  string
}

// Network returns the address's network name, "unix", "unixgram" or
// "unixpacket".
func (a *UnixAddr) Network() string {
	return a.Net
}

func (a *UnixAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	return a.Name
}

func (a *UnixAddr) isWildcard() bool {
	return a == nil || a.Name == ""
}

func (a *UnixAddr) opAddr() Addr {
	if a == nil {
		return nil
	}
	return a
}

// ResolveUnixAddr returns an address of Unix domain socket end point.
//
// The network must be a Unix network name.
//
// See func [Dial] for a description of the network and address
// parameters.
func ResolveUnixAddr(network, address string) (*UnixAddr, error) {
	switch network {
	case "unix", "unixgram", "unixpacket":
		return &UnixAddr{Name: address, Net: network}, nil
	default:
		return nil, UnknownNetworkError(network)
	}
}

// UnixConn is an implementation of the [Conn] interface for connections
// to Unix domain sockets.
type UnixConn struct {
	conn
}

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
func (c *UnixConn) SyscallConn() (syscall.RawConn, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	return newRawConn(c.fd), nil
}

// CloseRead shuts down the reading side of the Unix domain connection.
// Most callers should just use Close.
func (c *UnixConn) CloseRead() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.closeRead(); err != nil {
		return &OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// CloseWrite shuts down the writing side of the Unix domain connection.
// Most callers should just use Close.
func (c *UnixConn) CloseWrite() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.closeWrite(); err != nil {
		return &OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

// ReadFromUnix acts like [UnixConn.ReadFrom] but returns a [UnixAddr].
func (c *UnixConn) ReadFromUnix(b []byte) (int, *UnixAddr, error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	n, addr, err := c.readFrom(b)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, addr, err
}

// ReadFrom implements the [PacketConn] ReadFrom method.
func (c *UnixConn) ReadFrom(b []byte) (int, Addr, error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	n, addr, err := c.readFrom(b)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	if addr == nil {
		return n, nil, err
	}
	return n, addr, err
}

// ReadMsgUnix reads a message from c, copying the payload into b and
// the associated out-of-band data into oob. It returns the number of
// bytes copied into b, the number of bytes copied into oob, the flags
// that were set on the message and the source address of the message.
//
// Note that if len(b) == 0 and len(oob) > 0, this function will still
// read (and discard) 1 byte from the connection.
func (c *UnixConn) ReadMsgUnix(b, oob []byte) (n, oobn, flags int, addr *UnixAddr, err error) {
	if !c.ok() {
		return 0, 0, 0, nil, syscall.EINVAL
	}
	n, oobn, flags, addr, err = c.readMsg(b, oob)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return
}

// WriteToUnix acts like [UnixConn.WriteTo] but takes a [UnixAddr].
func (c *UnixConn) WriteToUnix(b []byte, addr *UnixAddr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.writeTo(b, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return n, err
}

// WriteTo implements the [PacketConn] WriteTo method.
func (c *UnixConn) WriteTo(b []byte, addr Addr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	a, ok := addr.(*UnixAddr)
	if !ok {
		return 0, &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr, Err: syscall.EINVAL}
	}
	n, err := c.writeTo(b, a)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: a.opAddr(), Err: err}
	}
	return n, err
}

// WriteMsgUnix writes a message to addr via c, copying the payload
// from b and the associated out-of-band data from oob. It returns the
// number of payload and out-of-band bytes written.
//
// Note that if len(b) == 0 and len(oob) > 0, this function will still
// write 1 byte to the connection.
func (c *UnixConn) WriteMsgUnix(b, oob []byte, addr *UnixAddr) (n, oobn int, err error) {
	if !c.ok() {
		return 0, 0, syscall.EINVAL
	}
	n, oobn, err = c.writeMsg(b, oob, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return
}

func newUnixConn(fd *netFD) *UnixConn { return &UnixConn{conn{fd}} }

// DialUnix acts like [Dial] for Unix networks.
//
// The network must be a Unix network name; see func Dial for details.
//
// If laddr is non-nil, it is used as the local address for the
// connection.
func DialUnix(network string, laddr, raddr *UnixAddr) (*UnixConn, error) {
	switch network {
	case "unix", "unixgram", "unixpacket":
	default:
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	sd := &sysDialer{network: network, address: raddr.String()}
	c, err := sd.dialUnix(context.Background(), laddr, raddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	return c, nil
}

// UnixListener is a Unix domain socket listener. Clients should
// typically use variables of type [Listener] instead of assuming Unix
// domain sockets.
type UnixListener struct {
	fd         *netFD
	path       string
	unlink     bool
	unlinkOnce sync.Once
}

func (ln *UnixListener) ok() bool { return ln != nil && ln.fd != nil }

// SyscallConn returns a raw network connection.
// This implements the [syscall.Conn] interface.
//
// The returned RawConn only supports calling Control. Read and
// Write return an error.
func (l *UnixListener) SyscallConn() (syscall.RawConn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	return newRawListener(l.fd), nil
}

// AcceptUnix accepts the next incoming call and returns the new
// connection.
func (l *UnixListener) AcceptUnix() (*UnixConn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	c, err := l.accept()
	if err != nil {
		return nil, &OpError{Op: "accept", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return c, nil
}

// Accept implements the Accept method in the [Listener] interface.
// Returned connections will be of type [*UnixConn].
func (l *UnixListener) Accept() (Conn, error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	c, err := l.accept()
	if err != nil {
		return nil, &OpError{Op: "accept", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return c, nil
}

// Close stops listening on the Unix address. Already accepted
// connections are not closed.
func (l *UnixListener) Close() error {
	if !l.ok() {
		return syscall.EINVAL
	}
	if err := l.close(); err != nil {
		return &OpError{Op: "close", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return nil
}

// Addr returns the listener's network address.
// The Addr returned is shared by all invocations of Addr, so
// do not modify it.
func (l *UnixListener) Addr() Addr { return l.fd.laddr }

// SetDeadline sets the deadline associated with the listener.
// A zero time value disables the deadline.
func (l *UnixListener) SetDeadline(t time.Time) error {
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
func (l *UnixListener) File() (f *os.File, err error) {
	if !l.ok() {
		return nil, syscall.EINVAL
	}
	f, err = l.file()
	if err != nil {
		err = &OpError{Op: "file", Net: l.fd.net, Source: nil, Addr: l.fd.laddr, Err: err}
	}
	return
}

// ListenUnix acts like [Listen] for Unix networks.
//
// The network must be "unix" or "unixpacket".
func ListenUnix(network string, laddr *UnixAddr) (*UnixListener, error) {
	switch network {
	case "unix", "unixpacket":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if laddr == nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: errMissingAddress}
	}
	sl := &sysListener{network: network, address: laddr.String()}
	ln, err := sl.listenUnix(context.Background(), laddr)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return ln, nil
}

// ListenUnixgram acts like [ListenPacket] for Unix networks.
//
// The network must be "unixgram".
func ListenUnixgram(network string, laddr *UnixAddr) (*UnixConn, error) {
	switch network {
	case "unixgram":
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: UnknownNetworkError(network)}
	}
	if laddr == nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: errMissingAddress}
	}
	sl := &sysListener{network: network, address: laddr.String()}
	c, err := sl.listenUnixgram(context.Background(), laddr)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return c, nil
}

"""



```