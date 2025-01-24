Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided Go code and explain it in Chinese, providing examples where possible.

2. **Identify the Core Subject:** The code is part of the `net` package in Go. The initial comments confirm this, stating it provides a portable interface for network I/O.

3. **Break Down the Content:**  The code contains several key elements:
    * **Package Documentation:** The initial block of comments explains the overall purpose of the `net` package. This is a great starting point.
    * **Interfaces:** `Addr`, `Conn`, `PacketConn`, `Listener`, `Error`. These define the core abstractions for network interactions.
    * **Concrete Types:**  `conn`, `OpError`, `ParseError`, `AddrError`, `UnknownNetworkError`, `InvalidAddrError`, `timeoutError`, `DNSConfigError`, `DNSError`, `Buffers`. These are specific implementations and error types.
    * **Functions:**  `listenerBacklog`, `mapErr`, `newDNSError`, `acquireThread`, `releaseThread`, `genericReadFrom`, `genericWriteTo`, `consume`. These provide utility and implementation details.
    * **Variables:**  `listenerBacklogCache`, `errNoSuitableAddress`, `errMissingAddress`, `errCanceled`, `ErrWriteToConnected`, `aLongTimeAgo`, `noDeadline`, `noCancel`, `errNoSuchHost`, `errUnknownPort`, `errClosed`, `threadLimit`, `threadOnce`. These hold state or specific error instances.
    * **Struct Methods:**  Each of the concrete types has methods implementing the interfaces or providing specific functionality.

4. **Analyze Each Element:** Now, let's go through each of these elements systematically:

    * **Package Documentation:**  This is high-level and outlines the key features: TCP/IP, UDP, DNS resolution, Unix domain sockets, `Dial`, `Listen`, `Accept`, `Conn`, `Listener`. It also explains the DNS resolver selection mechanism (Go vs. Cgo). This needs to be summarized in Chinese. Pay attention to keywords like "portable interface," "low-level networking primitives," and the examples of `Dial` and `Listen`. The DNS resolution part is important and warrants a separate, detailed explanation.

    * **Interfaces:**  Focus on the purpose of each interface and its methods. For example:
        * `Addr`: Represents a network address (`Network()` and `String()`).
        * `Conn`: Represents a stream-oriented connection (`Read`, `Write`, `Close`, etc.). Emphasize the blocking nature and the use of deadlines.
        * `PacketConn`: Similar to `Conn` but for packet-oriented communication (`ReadFrom`, `WriteTo`).
        * `Listener`:  Represents a network listener (`Accept`, `Close`, `Addr`).
        * `Error`:  A generic network error with `Timeout()` and `Temporary()` methods.

    * **Concrete Types:**  Understand what each type represents and its purpose.
        * `conn`: The concrete implementation of the `Conn` interface. Note its internal `fd` (file descriptor).
        * `OpError`:  A structured error containing operation details. It's important to explain its fields (`Op`, `Net`, `Source`, `Addr`, `Err`).
        * `ParseError`, `AddrError`, etc.:  Specific error types for parsing and addressing issues.
        * `DNSError`:  A detailed error type for DNS lookup failures. Explain the various flags (`IsTimeout`, `IsTemporary`, `IsNotFound`).
        * `Buffers`: An optimization for batch writing.

    * **Functions:**  Describe the functionality of each function.
        * `listenerBacklog`:  Related to the `Listen` function and the maximum number of pending connections.
        * `mapErr`: Converts context errors to `net` package errors.
        * `newDNSError`: Creates a `DNSError` object.
        * `acquireThread`/`releaseThread`: Used to limit concurrent CGO calls.
        * `genericReadFrom`/`genericWriteTo`: Fallback implementations for `io.ReaderFrom` and `io.WriterTo`.
        * `consume`:  Helper function for the `Buffers` type.

    * **Variables:** Explain the purpose of important variables, especially error instances.

    * **Struct Methods:**  For each method, describe its function and how it interacts with the underlying file descriptor or other data. Pay attention to error handling and the creation of `OpError` instances.

5. **Identify Key Functionality and Provide Examples:** Based on the analysis, identify the core functionalities exposed by the `net` package:
    * **Establishing Connections:**  Illustrate with the `Dial` example.
    * **Listening for Connections:** Illustrate with the `Listen` example.
    * **Reading and Writing Data:** Show the `Read` and `Write` methods of `Conn`.
    * **Handling Deadlines:**  Demonstrate `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`.
    * **DNS Resolution:**  This is a crucial part. Explain `LookupHost` and the different resolver mechanisms with `GODEBUG`.

6. **Address Potential Mistakes:**  Think about common errors developers might make when using the `net` package:
    * **Not handling errors:** This is fundamental.
    * **Ignoring `io.EOF`:**  Important for stream-based connections.
    * **Misunderstanding deadlines:** Explain that deadlines are absolute and apply to future calls.
    * **Incorrectly using `Temporary()`:**  The documentation explicitly deprecates its use for general temporary errors. Focus on `Timeout()`.
    * **Blocking operations in the main goroutine:**  Explain the need for goroutines for handling concurrent connections.

7. **Structure the Output:** Organize the information logically in Chinese:
    * **Overall Functionality:** Start with a general overview of the `net` package.
    * **Key Interfaces and Types:** Explain the purpose of `Addr`, `Conn`, `Listener`, etc.
    * **Code Examples:** Provide clear and concise Go code examples for core functionalities. Include assumed input and output where applicable.
    * **DNS Resolution Details:** Dedicate a section to explaining the DNS resolution mechanism.
    * **Command-Line Parameters (GODEBUG):** Explain how the `GODEBUG` environment variable affects DNS resolution.
    * **Common Mistakes:** List potential pitfalls with illustrative examples.

8. **Refine and Translate:** Review the generated Chinese text for clarity, accuracy, and natural flow. Ensure all technical terms are translated correctly.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Just list the functions and interfaces. **Correction:** Realized that understanding the *purpose* and *relationships* between these elements is more important.
* **Missed detail:**  Initially didn't emphasize the DNS resolver selection as much. **Correction:** Recognized its importance based on the detailed comments and added a dedicated section.
* **Example too simple:** The first example for `Dial` was just connecting. **Correction:** Extended it to show a basic HTTP request.
* **Didn't explain `OpError` sufficiently:**  Initially just mentioned it was an error type. **Correction:**  Explained its structure and the information it provides.
* **Overlooked `GODEBUG`:**  Initially focused only on the code. **Correction:**  Realized the importance of environment variables in controlling the resolver and added a section on `GODEBUG`.

By following this structured approach and iteratively refining the analysis, we arrive at a comprehensive understanding and explanation of the provided Go code.
这段代码是 Go 语言 `net` 包中 `net.go` 文件的一部分，它定义了网络编程的基础接口和一些核心类型。让我们逐一列举其功能并进行解释：

**主要功能:**

1. **定义了网络地址的抽象 `Addr` 接口:**
   - `Network() string`:  返回网络协议的名称，例如 "tcp", "udp"。
   - `String() string`: 返回地址的字符串表示形式，例如 "192.0.2.1:25", "[2001:db8::1]:80"。

2. **定义了面向流的连接的抽象 `Conn` 接口:**
   - `Read(b []byte) (n int, err error)`: 从连接读取数据。
   - `Write(b []byte) (n int, err error)`: 向连接写入数据。
   - `Close() error`: 关闭连接。
   - `LocalAddr() Addr`: 返回本地网络地址。
   - `RemoteAddr() Addr`: 返回远程网络地址。
   - `SetDeadline(t time.Time) error`: 设置读取和写入的截止时间。
   - `SetReadDeadline(t time.Time) error`: 设置读取的截止时间。
   - `SetWriteDeadline(t time.Time) error`: 设置写入的截止时间。

3. **定义了面向数据包的连接的抽象 `PacketConn` 接口:**
   - `ReadFrom(p []byte) (n int, addr Addr, err error)`: 从连接读取一个数据包，并返回发送方地址。
   - `WriteTo(p []byte, addr Addr) (n int, err error)`: 向指定的地址发送一个数据包。
   - 其他方法与 `Conn` 接口类似，用于关闭连接、获取地址和设置截止时间。

4. **定义了网络监听器的抽象 `Listener` 接口:**
   - `Accept() (Conn, error)`: 阻塞等待并接受下一个连接请求。
   - `Close() error`: 关闭监听器。
   - `Addr() Addr`: 返回监听器的网络地址。

5. **定义了网络错误的抽象 `Error` 接口:**
   - `error`: 基础的错误接口。
   - `Timeout() bool`: 指示错误是否是超时错误。
   - `Temporary() bool`:  **已弃用:** 指示错误是否是临时错误（不推荐使用）。

6. **实现了 `Conn` 接口的具体类型 `conn`:** 提供了 `Conn` 接口方法的具体实现，例如 `Read`, `Write`, `Close` 等。这些方法内部会调用 `netFD` 结构体的方法，`netFD` 负责更底层的网络操作。

7. **定义了多种具体的错误类型:**
   - `OpError`:  描述操作、网络类型和地址的错误，例如读取或写入失败。
   - `ParseError`:  表示解析网络地址字符串时发生的错误。
   - `AddrError`:  表示地址相关的错误。
   - `UnknownNetworkError`: 表示未知网络类型的错误。
   - `InvalidAddrError`: 表示无效地址的错误。
   - `timeoutError`: 表示 I/O 超时的错误。
   - `DNSError`:  表示 DNS 查询错误，包含更详细的信息，例如错误描述、查询的名称和服务器。

8. **提供了与 DNS 解析相关的配置和错误类型:**  虽然这段代码本身没有直接实现 DNS 解析，但它定义了 `DNSError` 结构体，用于表示 DNS 解析过程中出现的错误。  注释中详细解释了 Go 语言的 DNS 解析机制，包括 Go 原生解析器和 CGO 解析器的选择逻辑以及如何通过环境变量 `GODEBUG` 进行控制。

9. **定义了 `Buffers` 类型:**  用于优化批量写入操作，可以将多个 `[]byte` 合并成一个逻辑上的写入单元，提高效率。

10. **实现了并发控制机制:** 使用 `threadLimit` channel 和 `sync.Once` 来限制使用 CGO 进行 DNS 查询的并发数量，防止因阻塞的 DNS 请求耗尽系统线程。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `net` 包中**核心网络 I/O 功能**的骨架。它定义了进行网络通信所需的关键抽象和数据结构。`Dial`、`Listen` 和 `Accept` 这些核心的网络操作最终都会依赖于这里定义的接口和类型。

**Go 代码举例说明:**

以下代码示例演示了如何使用 `net` 包中的 `Dial` 函数建立 TCP 连接，并使用 `Conn` 接口的 `Write` 和 `Read` 方法进行数据交换：

```go
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// 假设输入：目标地址为 "tcp://localhost:8080"
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("连接失败:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 假设发送的数据
	message := "Hello Server!\n"

	// 假设输出：成功发送数据
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Println("发送数据失败:", err)
		return
	}
	fmt.Println("成功发送数据:", message)

	// 假设服务器返回的数据
	buffer := make([]byte, 1024)
	// 假设输出：接收到服务器的响应
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("接收数据失败:", err)
		return
	}
	fmt.Println("接收到服务器的响应:", string(buffer[:n]))
}
```

**假设的输入与输出:**

* **假设输入:** 目标地址为 `"tcp://localhost:8080"` (在 `net.Dial` 中)。
* **假设输出 (成功情况):**
  ```
  成功发送数据: Hello Server!
  接收到服务器的响应: ... (取决于服务器的响应)
  ```
* **假设输出 (连接失败):**
  ```
  连接失败: dial tcp 127.0.0.1:8080: connect: connection refused
  ```
* **假设输出 (发送数据失败):**
  ```
  成功发送数据: Hello Server!
  发送数据失败: write tcp 127.0.0.1:12345->127.0.0.1:8080: write: broken pipe
  ```
* **假设输出 (接收数据失败):**
  ```
  成功发送数据: Hello Server!
  接收数据失败: read tcp 127.0.0.1:12345->127.0.0.1:8080: read: connection reset by peer
  ```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。与命令行参数处理更相关的是调用 `net` 包的外部代码，例如使用 `flag` 包来解析命令行参数以获取服务器地址和端口。

然而，这段代码中涉及一个重要的环境变量：`GODEBUG`。

**`GODEBUG=netdns=go`:**  强制使用纯 Go 实现的 DNS 解析器。
**`GODEBUG=netdns=cgo`:** 强制使用基于 CGO 的原生 DNS 解析器（如果可用）。
**`GODEBUG=netdns=1`:**  打印 DNS 解析器决策的调试信息。
**`GODEBUG=netdns=go+1` 或 `GODEBUG=netdns=cgo+1`:** 强制使用指定的解析器并打印调试信息。
**`GODEBUG=netedns0=0`:** 禁用发送 EDNS0 附加头部，这有时可以解决与某些路由器 DNS 服务器的兼容性问题。

这些环境变量在程序运行时影响 `net` 包的 DNS 解析行为，但不是通过命令行参数直接传递的。它们需要在程序启动前设置在环境中。

**使用者易犯错的点:**

1. **不处理错误:**  网络操作很容易出错，例如连接失败、超时、连接中断等。忽略错误会导致程序行为不可预测甚至崩溃。

   ```go
   conn, _ := net.Dial("tcp", "invalid-address") // 错误被忽略了
   // ... 使用 conn，可能会导致 panic
   ```

2. **没有正确处理 `io.EOF`:**  当从 `Conn` 读取数据时，接收到 `io.EOF` 并不一定意味着发生了错误，而是表示连接已正常关闭。应该区分 `io.EOF` 和其他错误。

   ```go
   buffer := make([]byte, 1024)
   n, err := conn.Read(buffer)
   if err != nil {
       fmt.Println("读取错误:", err) // 可能会将正常的 EOF 误判为错误
   }
   ```

3. **对 `SetDeadline` 的理解不正确:** `SetDeadline` 设置的是绝对时间，而不是相对时间。如果需要实现空闲超时，需要在每次成功读取或写入后重新设置截止时间。

   ```go
   conn.SetDeadline(time.Now().Add(5 * time.Second)) // 设置 5 秒超时
   // ... 进行一些操作
   // 如果操作耗时超过 5 秒，后续的 Read 或 Write 都会超时，即使连接是活跃的
   ```

4. **过度依赖 `Temporary()` 方法:**  正如注释中指出的，`Temporary()` 方法的定义不太明确，不推荐使用。应该优先检查更具体的错误类型或使用 `Timeout()` 来判断是否是超时错误。

   ```go
   _, err := conn.Read(buffer)
   if err != nil && err.(net.Error).Temporary() { // 不推荐的用法
       fmt.Println("临时错误")
   }
   ```

5. **在主 Goroutine 中进行阻塞的网络操作:**  例如在 Web 服务器中直接在主 Goroutine 中调用 `Accept`，会导致服务器无法处理其他请求。应该使用 Goroutine 并发处理连接。

   ```go
   ln, _ := net.Listen("tcp", ":8080")
   conn, _ := ln.Accept() // 阻塞操作
   // ... 处理连接
   ```

总而言之，这段代码是 Go 语言 `net` 包的基础，它定义了进行网络编程所需的抽象和核心类型。理解这些接口和类型对于使用 Go 进行网络编程至关重要。

### 提示词
```
这是路径为go/src/net/net.go的go语言实现的一部分， 请列举一下它的功能, 　
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

/*
Package net provides a portable interface for network I/O, including
TCP/IP, UDP, domain name resolution, and Unix domain sockets.

Although the package provides access to low-level networking
primitives, most clients will need only the basic interface provided
by the [Dial], [Listen], and Accept functions and the associated
[Conn] and [Listener] interfaces. The crypto/tls package uses
the same interfaces and similar Dial and Listen functions.

The Dial function connects to a server:

	conn, err := net.Dial("tcp", "golang.org:80")
	if err != nil {
		// handle error
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	// ...

The Listen function creates servers:

	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		// handle error
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
		}
		go handleConnection(conn)
	}

# Name Resolution

The method for resolving domain names, whether indirectly with functions like Dial
or directly with functions like [LookupHost] and [LookupAddr], varies by operating system.

On Unix systems, the resolver has two options for resolving names.
It can use a pure Go resolver that sends DNS requests directly to the servers
listed in /etc/resolv.conf, or it can use a cgo-based resolver that calls C
library routines such as getaddrinfo and getnameinfo.

On Unix the pure Go resolver is preferred over the cgo resolver, because a blocked DNS
request consumes only a goroutine, while a blocked C call consumes an operating system thread.
When cgo is available, the cgo-based resolver is used instead under a variety of
conditions: on systems that do not let programs make direct DNS requests (OS X),
when the LOCALDOMAIN environment variable is present (even if empty),
when the RES_OPTIONS or HOSTALIASES environment variable is non-empty,
when the ASR_CONFIG environment variable is non-empty (OpenBSD only),
when /etc/resolv.conf or /etc/nsswitch.conf specify the use of features that the
Go resolver does not implement.

On all systems (except Plan 9), when the cgo resolver is being used
this package applies a concurrent cgo lookup limit to prevent the system
from running out of system threads. Currently, it is limited to 500 concurrent lookups.

The resolver decision can be overridden by setting the netdns value of the
GODEBUG environment variable (see package runtime) to go or cgo, as in:

	export GODEBUG=netdns=go    # force pure Go resolver
	export GODEBUG=netdns=cgo   # force native resolver (cgo, win32)

The decision can also be forced while building the Go source tree
by setting the netgo or netcgo build tag.
The netgo build tag disables entirely the use of the native (CGO) resolver,
meaning the Go resolver is the only one that can be used.
With the netcgo build tag the native and the pure Go resolver are compiled into the binary,
but the native (CGO) resolver is preferred over the Go resolver.
With netcgo, the Go resolver can still be forced at runtime with GODEBUG=netdns=go.

A numeric netdns setting, as in GODEBUG=netdns=1, causes the resolver
to print debugging information about its decisions.
To force a particular resolver while also printing debugging information,
join the two settings by a plus sign, as in GODEBUG=netdns=go+1.

The Go resolver will send an EDNS0 additional header with a DNS request,
to signal a willingness to accept a larger DNS packet size.
This can reportedly cause sporadic failures with the DNS server run
by some modems and routers. Setting GODEBUG=netedns0=0 will disable
sending the additional header.

On macOS, if Go code that uses the net package is built with
-buildmode=c-archive, linking the resulting archive into a C program
requires passing -lresolv when linking the C code.

On Plan 9, the resolver always accesses /net/cs and /net/dns.

On Windows, in Go 1.18.x and earlier, the resolver always used C
library functions, such as GetAddrInfo and DnsQuery.
*/
package net

import (
	"context"
	"errors"
	"internal/poll"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	_ "unsafe" // for linkname
)

// Addr represents a network end point address.
//
// The two methods [Addr.Network] and [Addr.String] conventionally return strings
// that can be passed as the arguments to [Dial], but the exact form
// and meaning of the strings is up to the implementation.
type Addr interface {
	Network() string // name of the network (for example, "tcp", "udp")
	String() string  // string form of address (for example, "192.0.2.1:25", "[2001:db8::1]:80")
}

// Conn is a generic stream-oriented network connection.
//
// Multiple goroutines may invoke methods on a Conn simultaneously.
type Conn interface {
	// Read reads data from the connection.
	// Read can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetReadDeadline.
	Read(b []byte) (n int, err error)

	// Write writes data to the connection.
	// Write can be made to time out and return an error after a fixed
	// time limit; see SetDeadline and SetWriteDeadline.
	Write(b []byte) (n int, err error)

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// LocalAddr returns the local network address, if known.
	LocalAddr() Addr

	// RemoteAddr returns the remote network address, if known.
	RemoteAddr() Addr

	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	//
	// A deadline is an absolute time after which I/O operations
	// fail instead of blocking. The deadline applies to all future
	// and pending I/O, not just the immediately following call to
	// Read or Write. After a deadline has been exceeded, the
	// connection can be refreshed by setting a deadline in the future.
	//
	// If the deadline is exceeded a call to Read or Write or to other
	// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
	// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
	// The error's Timeout method will return true, but note that there
	// are other possible errors for which the Timeout method will
	// return true even if the deadline has not been exceeded.
	//
	// An idle timeout can be implemented by repeatedly extending
	// the deadline after successful Read or Write calls.
	//
	// A zero value for t means I/O operations will not time out.
	SetDeadline(t time.Time) error

	// SetReadDeadline sets the deadline for future Read calls
	// and any currently-blocked Read call.
	// A zero value for t means Read will not time out.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the deadline for future Write calls
	// and any currently-blocked Write call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means Write will not time out.
	SetWriteDeadline(t time.Time) error
}

type conn struct {
	fd *netFD
}

func (c *conn) ok() bool { return c != nil && c.fd != nil }

// Implementation of the Conn interface.

// Read implements the Conn Read method.
func (c *conn) Read(b []byte) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.fd.Read(b)
	if err != nil && err != io.EOF {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, err
}

// Write implements the Conn Write method.
func (c *conn) Write(b []byte) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.fd.Write(b)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, err
}

// Close closes the connection.
func (c *conn) Close() error {
	if !c.ok() {
		return syscall.EINVAL
	}
	err := c.fd.Close()
	if err != nil {
		err = &OpError{Op: "close", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return err
}

// LocalAddr returns the local network address.
// The Addr returned is shared by all invocations of LocalAddr, so
// do not modify it.
func (c *conn) LocalAddr() Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.laddr
}

// RemoteAddr returns the remote network address.
// The Addr returned is shared by all invocations of RemoteAddr, so
// do not modify it.
func (c *conn) RemoteAddr() Addr {
	if !c.ok() {
		return nil
	}
	return c.fd.raddr
}

// SetDeadline implements the Conn SetDeadline method.
func (c *conn) SetDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetDeadline(t); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr, Err: err}
	}
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (c *conn) SetReadDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetReadDeadline(t); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr, Err: err}
	}
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *conn) SetWriteDeadline(t time.Time) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := c.fd.SetWriteDeadline(t); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr, Err: err}
	}
	return nil
}

// SetReadBuffer sets the size of the operating system's
// receive buffer associated with the connection.
func (c *conn) SetReadBuffer(bytes int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setReadBuffer(c.fd, bytes); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr, Err: err}
	}
	return nil
}

// SetWriteBuffer sets the size of the operating system's
// transmit buffer associated with the connection.
func (c *conn) SetWriteBuffer(bytes int) error {
	if !c.ok() {
		return syscall.EINVAL
	}
	if err := setWriteBuffer(c.fd, bytes); err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: nil, Addr: c.fd.laddr, Err: err}
	}
	return nil
}

// File returns a copy of the underlying [os.File].
// It is the caller's responsibility to close f when finished.
// Closing c does not affect f, and closing f does not affect c.
//
// The returned os.File's file descriptor is different from the connection's.
// Attempting to change properties of the original using this duplicate
// may or may not have the desired effect.
func (c *conn) File() (f *os.File, err error) {
	f, err = c.fd.dup()
	if err != nil {
		err = &OpError{Op: "file", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return
}

// PacketConn is a generic packet-oriented network connection.
//
// Multiple goroutines may invoke methods on a PacketConn simultaneously.
type PacketConn interface {
	// ReadFrom reads a packet from the connection,
	// copying the payload into p. It returns the number of
	// bytes copied into p and the return address that
	// was on the packet.
	// It returns the number of bytes read (0 <= n <= len(p))
	// and any error encountered. Callers should always process
	// the n > 0 bytes returned before considering the error err.
	// ReadFrom can be made to time out and return an error after a
	// fixed time limit; see SetDeadline and SetReadDeadline.
	ReadFrom(p []byte) (n int, addr Addr, err error)

	// WriteTo writes a packet with payload p to addr.
	// WriteTo can be made to time out and return an Error after a
	// fixed time limit; see SetDeadline and SetWriteDeadline.
	// On packet-oriented connections, write timeouts are rare.
	WriteTo(p []byte, addr Addr) (n int, err error)

	// Close closes the connection.
	// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
	Close() error

	// LocalAddr returns the local network address, if known.
	LocalAddr() Addr

	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	//
	// A deadline is an absolute time after which I/O operations
	// fail instead of blocking. The deadline applies to all future
	// and pending I/O, not just the immediately following call to
	// Read or Write. After a deadline has been exceeded, the
	// connection can be refreshed by setting a deadline in the future.
	//
	// If the deadline is exceeded a call to Read or Write or to other
	// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
	// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
	// The error's Timeout method will return true, but note that there
	// are other possible errors for which the Timeout method will
	// return true even if the deadline has not been exceeded.
	//
	// An idle timeout can be implemented by repeatedly extending
	// the deadline after successful ReadFrom or WriteTo calls.
	//
	// A zero value for t means I/O operations will not time out.
	SetDeadline(t time.Time) error

	// SetReadDeadline sets the deadline for future ReadFrom calls
	// and any currently-blocked ReadFrom call.
	// A zero value for t means ReadFrom will not time out.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the deadline for future WriteTo calls
	// and any currently-blocked WriteTo call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means WriteTo will not time out.
	SetWriteDeadline(t time.Time) error
}

var listenerBacklogCache struct {
	sync.Once
	val int
}

// listenerBacklog is a caching wrapper around maxListenerBacklog.
//
// listenerBacklog should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/database64128/tfo-go/v2
//   - github.com/metacubex/tfo-go
//   - github.com/sagernet/tfo-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname listenerBacklog
func listenerBacklog() int {
	listenerBacklogCache.Do(func() { listenerBacklogCache.val = maxListenerBacklog() })
	return listenerBacklogCache.val
}

// A Listener is a generic network listener for stream-oriented protocols.
//
// Multiple goroutines may invoke methods on a Listener simultaneously.
type Listener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (Conn, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() Addr
}

// An Error represents a network error.
type Error interface {
	error
	Timeout() bool // Is the error a timeout?

	// Deprecated: Temporary errors are not well-defined.
	// Most "temporary" errors are timeouts, and the few exceptions are surprising.
	// Do not use this method.
	Temporary() bool
}

// Various errors contained in OpError.
var (
	// For connection setup operations.
	errNoSuitableAddress = errors.New("no suitable address found")

	// For connection setup and write operations.
	errMissingAddress = errors.New("missing address")

	// For both read and write operations.
	errCanceled         = canceledError{}
	ErrWriteToConnected = errors.New("use of WriteTo with pre-connected connection")
)

// canceledError lets us return the same error string we have always
// returned, while still being Is context.Canceled.
type canceledError struct{}

func (canceledError) Error() string { return "operation was canceled" }

func (canceledError) Is(err error) bool { return err == context.Canceled }

// mapErr maps from the context errors to the historical internal net
// error values.
func mapErr(err error) error {
	switch err {
	case context.Canceled:
		return errCanceled
	case context.DeadlineExceeded:
		return errTimeout
	default:
		return err
	}
}

// OpError is the error type usually returned by functions in the net
// package. It describes the operation, network type, and address of
// an error.
type OpError struct {
	// Op is the operation which caused the error, such as
	// "read" or "write".
	Op string

	// Net is the network type on which this error occurred,
	// such as "tcp" or "udp6".
	Net string

	// For operations involving a remote network connection, like
	// Dial, Read, or Write, Source is the corresponding local
	// network address.
	Source Addr

	// Addr is the network address for which this error occurred.
	// For local operations, like Listen or SetDeadline, Addr is
	// the address of the local endpoint being manipulated.
	// For operations involving a remote network connection, like
	// Dial, Read, or Write, Addr is the remote address of that
	// connection.
	Addr Addr

	// Err is the error that occurred during the operation.
	// The Error method panics if the error is nil.
	Err error
}

func (e *OpError) Unwrap() error { return e.Err }

func (e *OpError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := e.Op
	if e.Net != "" {
		s += " " + e.Net
	}
	if e.Source != nil {
		s += " " + e.Source.String()
	}
	if e.Addr != nil {
		if e.Source != nil {
			s += "->"
		} else {
			s += " "
		}
		s += e.Addr.String()
	}
	s += ": " + e.Err.Error()
	return s
}

var (
	// aLongTimeAgo is a non-zero time, far in the past, used for
	// immediate cancellation of dials.
	aLongTimeAgo = time.Unix(1, 0)

	// noDeadline and noCancel are just zero values for
	// readability with functions taking too many parameters.
	noDeadline = time.Time{}
	noCancel   = (chan struct{})(nil)
)

type timeout interface {
	Timeout() bool
}

func (e *OpError) Timeout() bool {
	if ne, ok := e.Err.(*os.SyscallError); ok {
		t, ok := ne.Err.(timeout)
		return ok && t.Timeout()
	}
	t, ok := e.Err.(timeout)
	return ok && t.Timeout()
}

type temporary interface {
	Temporary() bool
}

func (e *OpError) Temporary() bool {
	// Treat ECONNRESET and ECONNABORTED as temporary errors when
	// they come from calling accept. See issue 6163.
	if e.Op == "accept" && isConnError(e.Err) {
		return true
	}

	if ne, ok := e.Err.(*os.SyscallError); ok {
		t, ok := ne.Err.(temporary)
		return ok && t.Temporary()
	}
	t, ok := e.Err.(temporary)
	return ok && t.Temporary()
}

// A ParseError is the error type of literal network address parsers.
type ParseError struct {
	// Type is the type of string that was expected, such as
	// "IP address", "CIDR address".
	Type string

	// Text is the malformed text string.
	Text string
}

func (e *ParseError) Error() string { return "invalid " + e.Type + ": " + e.Text }

func (e *ParseError) Timeout() bool   { return false }
func (e *ParseError) Temporary() bool { return false }

type AddrError struct {
	Err  string
	Addr string
}

func (e *AddrError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := e.Err
	if e.Addr != "" {
		s = "address " + e.Addr + ": " + s
	}
	return s
}

func (e *AddrError) Timeout() bool   { return false }
func (e *AddrError) Temporary() bool { return false }

type UnknownNetworkError string

func (e UnknownNetworkError) Error() string   { return "unknown network " + string(e) }
func (e UnknownNetworkError) Timeout() bool   { return false }
func (e UnknownNetworkError) Temporary() bool { return false }

type InvalidAddrError string

func (e InvalidAddrError) Error() string   { return string(e) }
func (e InvalidAddrError) Timeout() bool   { return false }
func (e InvalidAddrError) Temporary() bool { return false }

// errTimeout exists to return the historical "i/o timeout" string
// for context.DeadlineExceeded. See mapErr.
// It is also used when Dialer.Deadline is exceeded.
// error.Is(errTimeout, context.DeadlineExceeded) returns true.
//
// TODO(iant): We could consider changing this to os.ErrDeadlineExceeded
// in the future, if we make
//
//	errors.Is(os.ErrDeadlineExceeded, context.DeadlineExceeded)
//
// return true.
var errTimeout error = &timeoutError{}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func (e *timeoutError) Is(err error) bool {
	return err == context.DeadlineExceeded
}

// DNSConfigError represents an error reading the machine's DNS configuration.
// (No longer used; kept for compatibility.)
type DNSConfigError struct {
	Err error
}

func (e *DNSConfigError) Unwrap() error   { return e.Err }
func (e *DNSConfigError) Error() string   { return "error reading DNS config: " + e.Err.Error() }
func (e *DNSConfigError) Timeout() bool   { return false }
func (e *DNSConfigError) Temporary() bool { return false }

// Various errors contained in DNSError.
var (
	errNoSuchHost  = &notFoundError{"no such host"}
	errUnknownPort = &notFoundError{"unknown port"}
)

// notFoundError is a special error understood by the newDNSError function,
// which causes a creation of a DNSError with IsNotFound field set to true.
type notFoundError struct{ s string }

func (e *notFoundError) Error() string { return e.s }

// temporaryError is an error type that implements the [Error] interface.
// It returns true from the Temporary method.
type temporaryError struct{ s string }

func (e *temporaryError) Error() string   { return e.s }
func (e *temporaryError) Temporary() bool { return true }
func (e *temporaryError) Timeout() bool   { return false }

// DNSError represents a DNS lookup error.
type DNSError struct {
	UnwrapErr   error  // error returned by the [DNSError.Unwrap] method, might be nil
	Err         string // description of the error
	Name        string // name looked for
	Server      string // server used
	IsTimeout   bool   // if true, timed out; not all timeouts set this
	IsTemporary bool   // if true, error is temporary; not all errors set this

	// IsNotFound is set to true when the requested name does not
	// contain any records of the requested type (data not found),
	// or the name itself was not found (NXDOMAIN).
	IsNotFound bool
}

// newDNSError creates a new *DNSError.
// Based on the err, it sets the UnwrapErr, IsTimeout, IsTemporary, IsNotFound fields.
func newDNSError(err error, name, server string) *DNSError {
	var (
		isTimeout   bool
		isTemporary bool
		unwrapErr   error
	)

	if err, ok := err.(Error); ok {
		isTimeout = err.Timeout()
		isTemporary = err.Temporary()
	}

	// At this time, the only errors we wrap are context errors, to allow
	// users to check for canceled/timed out requests.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		unwrapErr = err
	}

	_, isNotFound := err.(*notFoundError)
	return &DNSError{
		UnwrapErr:   unwrapErr,
		Err:         err.Error(),
		Name:        name,
		Server:      server,
		IsTimeout:   isTimeout,
		IsTemporary: isTemporary,
		IsNotFound:  isNotFound,
	}
}

// Unwrap returns e.UnwrapErr.
func (e *DNSError) Unwrap() error { return e.UnwrapErr }

func (e *DNSError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := "lookup " + e.Name
	if e.Server != "" {
		s += " on " + e.Server
	}
	s += ": " + e.Err
	return s
}

// Timeout reports whether the DNS lookup is known to have timed out.
// This is not always known; a DNS lookup may fail due to a timeout
// and return a [DNSError] for which Timeout returns false.
func (e *DNSError) Timeout() bool { return e.IsTimeout }

// Temporary reports whether the DNS error is known to be temporary.
// This is not always known; a DNS lookup may fail due to a temporary
// error and return a [DNSError] for which Temporary returns false.
func (e *DNSError) Temporary() bool { return e.IsTimeout || e.IsTemporary }

// errClosed exists just so that the docs for ErrClosed don't mention
// the internal package poll.
var errClosed = poll.ErrNetClosing

// ErrClosed is the error returned by an I/O call on a network
// connection that has already been closed, or that is closed by
// another goroutine before the I/O is completed. This may be wrapped
// in another error, and should normally be tested using
// errors.Is(err, net.ErrClosed).
var ErrClosed error = errClosed

// noReadFrom can be embedded alongside another type to
// hide the ReadFrom method of that other type.
type noReadFrom struct{}

// ReadFrom hides another ReadFrom method.
// It should never be called.
func (noReadFrom) ReadFrom(io.Reader) (int64, error) {
	panic("can't happen")
}

// tcpConnWithoutReadFrom implements all the methods of *TCPConn other
// than ReadFrom. This is used to permit ReadFrom to call io.Copy
// without leading to a recursive call to ReadFrom.
type tcpConnWithoutReadFrom struct {
	noReadFrom
	*TCPConn
}

// Fallback implementation of io.ReaderFrom's ReadFrom, when sendfile isn't
// applicable.
func genericReadFrom(c *TCPConn, r io.Reader) (n int64, err error) {
	// Use wrapper to hide existing r.ReadFrom from io.Copy.
	return io.Copy(tcpConnWithoutReadFrom{TCPConn: c}, r)
}

// noWriteTo can be embedded alongside another type to
// hide the WriteTo method of that other type.
type noWriteTo struct{}

// WriteTo hides another WriteTo method.
// It should never be called.
func (noWriteTo) WriteTo(io.Writer) (int64, error) {
	panic("can't happen")
}

// tcpConnWithoutWriteTo implements all the methods of *TCPConn other
// than WriteTo. This is used to permit WriteTo to call io.Copy
// without leading to a recursive call to WriteTo.
type tcpConnWithoutWriteTo struct {
	noWriteTo
	*TCPConn
}

// Fallback implementation of io.WriterTo's WriteTo, when zero-copy isn't applicable.
func genericWriteTo(c *TCPConn, w io.Writer) (n int64, err error) {
	// Use wrapper to hide existing w.WriteTo from io.Copy.
	return io.Copy(w, tcpConnWithoutWriteTo{TCPConn: c})
}

// Limit the number of concurrent cgo-using goroutines, because
// each will block an entire operating system thread. The usual culprit
// is resolving many DNS names in separate goroutines but the DNS
// server is not responding. Then the many lookups each use a different
// thread, and the system or the program runs out of threads.

var threadLimit chan struct{}

var threadOnce sync.Once

func acquireThread(ctx context.Context) error {
	threadOnce.Do(func() {
		threadLimit = make(chan struct{}, concurrentThreadsLimit())
	})
	select {
	case threadLimit <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseThread() {
	<-threadLimit
}

// buffersWriter is the interface implemented by Conns that support a
// "writev"-like batch write optimization.
// writeBuffers should fully consume and write all chunks from the
// provided Buffers, else it should report a non-nil error.
type buffersWriter interface {
	writeBuffers(*Buffers) (int64, error)
}

// Buffers contains zero or more runs of bytes to write.
//
// On certain machines, for certain types of connections, this is
// optimized into an OS-specific batch write operation (such as
// "writev").
type Buffers [][]byte

var (
	_ io.WriterTo = (*Buffers)(nil)
	_ io.Reader   = (*Buffers)(nil)
)

// WriteTo writes contents of the buffers to w.
//
// WriteTo implements [io.WriterTo] for [Buffers].
//
// WriteTo modifies the slice v as well as v[i] for 0 <= i < len(v),
// but does not modify v[i][j] for any i, j.
func (v *Buffers) WriteTo(w io.Writer) (n int64, err error) {
	if wv, ok := w.(buffersWriter); ok {
		return wv.writeBuffers(v)
	}
	for _, b := range *v {
		nb, err := w.Write(b)
		n += int64(nb)
		if err != nil {
			v.consume(n)
			return n, err
		}
	}
	v.consume(n)
	return n, nil
}

// Read from the buffers.
//
// Read implements [io.Reader] for [Buffers].
//
// Read modifies the slice v as well as v[i] for 0 <= i < len(v),
// but does not modify v[i][j] for any i, j.
func (v *Buffers) Read(p []byte) (n int, err error) {
	for len(p) > 0 && len(*v) > 0 {
		n0 := copy(p, (*v)[0])
		v.consume(int64(n0))
		p = p[n0:]
		n += n0
	}
	if len(*v) == 0 {
		err = io.EOF
	}
	return
}

func (v *Buffers) consume(n int64) {
	for len(*v) > 0 {
		ln0 := int64(len((*v)[0]))
		if ln0 > n {
			(*v)[0] = (*v)[0][n:]
			return
		}
		n -= ln0
		(*v)[0] = nil
		*v = (*v)[1:]
	}
}
```