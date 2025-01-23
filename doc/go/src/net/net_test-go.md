Response:
The user wants to understand the functionality of the Go code snippet provided. The code is a test file for the `net` package in Go.

Here's a plan to address the user's request:

1. **Identify the main purpose:** The file `net_test.go` contains unit tests for various network-related functionalities in the `net` package.

2. **Analyze individual test functions:** Go through each test function (`TestCloseRead`, `TestCloseWrite`, etc.) and describe what specific network feature it's testing.

3. **Provide code examples:** For some key functionalities, create simplified Go code examples that illustrate the usage of the tested features. This might involve demonstrating how to close read/write ends of a connection, close a connection entirely, or close a listener.

4. **Address code reasoning:** If a test function involves intricate logic or checks specific error conditions, explain the reasoning behind the test and provide possible input/output scenarios.

5. **Check for command-line arguments:**  The provided code snippet doesn't seem to directly handle command-line arguments. Mention this if it's the case.

6. **Identify potential pitfalls:** Point out common mistakes developers might make when using the tested functionalities, if any are apparent from the test code.

7. **Format the answer:** Structure the response clearly using headings and code blocks for better readability, adhering to the user's request for a Chinese answer.
这段代码是 Go 语言标准库 `net` 包的一部分，位于 `go/src/net/net_test.go` 文件中。它主要的功能是**对 `net` 包中关于连接（`Conn`）、监听器（`Listener`）和数据包连接（`PacketConn`）的关闭操作进行单元测试**。

具体来说，它测试了以下几个方面的功能：

1. **关闭连接的读取端 (`CloseRead`)**:  测试是否可以单独关闭连接的读取方向，以及关闭后读取操作的行为。
2. **关闭连接的写入端 (`CloseWrite`)**: 测试是否可以单独关闭连接的写入方向，以及关闭后读取和写入操作的行为。
3. **关闭连接 (`Close`)**: 测试完全关闭连接后的读取操作行为。
4. **关闭监听器 (`Close`)**: 测试关闭监听器后，新的连接尝试是否会失败。
5. **关闭数据包连接 (`Close`)**: 测试关闭数据包连接后的读取操作行为。
6. **处理被中止的连接请求 (`AcceptIgnoreAbortedConnRequest`)**:  测试当有连接请求被中止时，`Accept` 方法是否能够正确处理，而不会导致程序崩溃或进入错误状态。这通常涉及到模拟网络错误场景。
7. **零字节读取 (`ZeroByteRead`)**: 测试在连接上进行零字节读取操作的行为，确保不会发生意外错误。
8. **读取超时打断阻塞的读取 (`ReadTimeoutUnblocksRead`)**:  测试当设置了读取超时时间，并且在 `Read` 操作阻塞时，如果超时时间已到，`Read` 操作是否会被正确打断并返回错误。
9. **关闭连接打断阻塞的读取 (`CloseUnblocksRead`)**: 测试当在连接的读取操作阻塞时，如果连接被关闭，`Read` 操作是否会被正确打断并返回 `io.EOF` 错误。
10. **`ECONNRESET` 错误不是临时错误 (`TestNotTemporaryRead`)**: 测试在连接被远程重置（`ECONNRESET`）后，读取操作返回的错误是否被正确标记为非临时错误。
11. **错误类型实现了 `Error` 接口 (`TestErrors`)**:  确保 `net` 包中定义的各种错误类型都实现了 `error` 接口。

**以下是用 Go 代码举例说明其中一些功能的实现:**

**1. 关闭连接的读取端 (`CloseRead`)**

假设我们有一个 TCP 服务器和一个客户端，客户端向服务器发送数据后，服务器关闭了读取端。

```go
package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	ln, err := net.Listen("tcp", "localhost:0") // 监听本地端口
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Println("Listening on:", ln.Addr())

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			return
		}
		defer conn.Close()

		// 关闭读取端
		tcpConn, ok := conn.(*net.TCPConn)
		if ok {
			err = tcpConn.CloseRead()
			if err != nil {
				fmt.Println("Error closing read:", err)
				return
			}
			fmt.Println("Server: Read side closed")
		}

		// 尝试读取数据，应该会出错
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		fmt.Printf("Server: Read %d bytes, error: %v\n", n, err) // 预期 n 为 0，err 不为 nil
	}()

	conn, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		fmt.Println("Error dialing:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 发送数据
	_, err = conn.Write([]byte("Hello Server"))
	if err != nil {
		fmt.Println("Error writing:", err)
		return
	}
	fmt.Println("Client: Sent data")

	// 接收数据（服务器已经关闭读取端，这里会收到错误）
	buf := make([]byte, 1024)
	n, err = conn.Read(buf)
	fmt.Printf("Client: Received %d bytes, error: %v\n", n, err) // 预期 n 为 0，err 为 io.EOF 或其他连接关闭错误

	// 保持客户端运行一段时间，观察服务器端的行为
	fmt.Println("Client: Waiting...")
	select {}
}
```

**假设的输入与输出：**

* **输入：** 客户端程序启动，连接到服务器并发送数据。
* **输出：**
    * 服务器端会打印 "Server: Read side closed"。
    * 服务器端尝试读取数据时，会打印类似 "Server: Read 0 bytes, error: read: connection reset by peer" 或其他表示连接已关闭的错误。
    * 客户端发送数据后会打印 "Client: Sent data"。
    * 客户端尝试接收数据时，会打印类似 "Client: Received 0 bytes, error: EOF" 或其他连接关闭的错误。

**2. 读取超时打断阻塞的读取 (`ReadTimeoutUnblocksRead`)**

```go
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Println("Listening on:", ln.Addr())

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			return
		}
		defer conn.Close()

		// 设置读取超时时间为 1 秒
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		fmt.Printf("Server: Read %d bytes, error: %v\n", n, err) // 预期 err 是超时错误
	}()

	conn, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		fmt.Println("Error dialing:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 客户端不发送任何数据，让服务器的 Read 操作阻塞并超时

	fmt.Println("Client: Waiting for server...")
	time.Sleep(3 * time.Second) // 等待足够长的时间让服务器超时
	fmt.Println("Client: Done")
}
```

**假设的输入与输出：**

* **输入：** 客户端程序启动，连接到服务器，但不发送任何数据。
* **输出：**
    * 服务器端在 `Read` 操作超时后，会打印类似 "Server: Read 0 bytes, error: i/o timeout"。

**代码推理 (针对 `AcceptIgnoreAbortedConnRequest`)：**

这个测试模拟了在 `Accept` 系统调用返回特定错误（表示连接请求被中止，例如 `ECONNABORTED` 或 `WSAECONNABORTED`）的情况下，`net` 包的 `Accept` 方法是否能够正确地忽略这些错误，而不会导致程序崩溃。

**假设的输入与输出：**

* **假设的输入：** 操作系统在调用 `Accept` 时，由于某种原因（例如客户端在完成 TCP 握手之前就断开了连接），返回了一个表示连接被中止的错误。
* **推理：** `net` 包的实现应该捕获这些特定的错误，并继续等待新的连接，而不是将错误直接抛给调用者。
* **预期输出：** 测试不会因为 `Accept` 抛出错误而失败。

**命令行参数的具体处理：**

这段代码是单元测试代码，它**不涉及**任何需要用户提供的命令行参数。单元测试通常通过 `go test` 命令运行，不需要额外的命令行输入。

**使用者易犯错的点：**

在 `net` 包的使用中，关于连接关闭，使用者容易犯以下错误：

1. **忘记关闭连接或监听器：**  不及时关闭连接或监听器会导致资源泄漏，最终可能导致程序崩溃或系统资源耗尽。
2. **在错误的goroutine中关闭连接：**  如果在一个goroutine中读取连接，而在另一个goroutine中关闭连接，可能会导致数据竞争或其他并发问题。应该确保在不再需要连接时才关闭它，并且只有一个goroutine负责关闭。
3. **混淆 `CloseRead` 和 `CloseWrite` 与 `Close` 的作用：**
    * `CloseRead` 只关闭读取方向，连接的写入方向仍然可以工作。对端仍然可以向你发送数据，但你的程序将无法读取。
    * `CloseWrite` 只关闭写入方向，连接的读取方向仍然可以工作。你可以继续接收对端发送的数据，但你无法再向对端发送数据。
    * `Close` 会完全关闭连接的读写两个方向。
4. **在 `Accept` 之后没有处理返回的错误：** `ln.Accept()` 可能会返回错误，例如在监听器被关闭后。没有正确处理这些错误会导致程序逻辑错误。

**例子说明错误点 1 (忘记关闭连接):**

```go
package main

import (
	"fmt"
	"net"
	"time"
)

func handleConnection(conn net.Conn) {
	// ... 处理连接的逻辑 ...
	// 忘记关闭 conn.Close()
}

func main() {
	ln, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(conn) // 忘记在 handleConnection 中关闭连接
	}
}
```

在这个例子中，每次有新的连接进来，`handleConnection` 函数处理完后没有关闭连接，会导致连接资源一直被占用，最终可能耗尽系统资源。 应该在 `handleConnection` 函数的结尾添加 `defer conn.Close()` 来确保连接被关闭。

### 提示词
```
这是路径为go/src/net/net_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"errors"
	"fmt"
	"io"
	"net/internal/socktest"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestCloseRead(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	t.Parallel()

	for _, network := range []string{"tcp", "unix", "unixpacket"} {
		network := network
		t.Run(network, func(t *testing.T) {
			if !testableNetwork(network) {
				t.Skipf("network %s is not testable on the current platform", network)
			}
			t.Parallel()

			ln := newLocalListener(t, network)
			switch network {
			case "unix", "unixpacket":
				defer os.Remove(ln.Addr().String())
			}
			defer ln.Close()

			c, err := Dial(ln.Addr().Network(), ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			switch network {
			case "unix", "unixpacket":
				defer os.Remove(c.LocalAddr().String())
			}
			defer c.Close()

			switch c := c.(type) {
			case *TCPConn:
				err = c.CloseRead()
			case *UnixConn:
				err = c.CloseRead()
			}
			if err != nil {
				if perr := parseCloseError(err, true); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}
			var b [1]byte
			n, err := c.Read(b[:])
			if n != 0 || err == nil {
				t.Fatalf("got (%d, %v); want (0, error)", n, err)
			}
		})
	}
}

func TestCloseWrite(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	t.Parallel()
	deadline, _ := t.Deadline()
	if !deadline.IsZero() {
		// Leave 10% headroom on the deadline to report errors and clean up.
		deadline = deadline.Add(-time.Until(deadline) / 10)
	}

	for _, network := range []string{"tcp", "unix", "unixpacket"} {
		network := network
		t.Run(network, func(t *testing.T) {
			if !testableNetwork(network) {
				t.Skipf("network %s is not testable on the current platform", network)
			}
			t.Parallel()

			handler := func(ls *localServer, ln Listener) {
				c, err := ln.Accept()
				if err != nil {
					t.Error(err)
					return
				}

				// Workaround for https://go.dev/issue/49352.
				// On arm64 macOS (current as of macOS 12.4),
				// reading from a socket at the same time as the client
				// is closing it occasionally hangs for 60 seconds before
				// returning ECONNRESET. Sleep for a bit to give the
				// socket time to close before trying to read from it.
				if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
					time.Sleep(10 * time.Millisecond)
				}

				if !deadline.IsZero() {
					c.SetDeadline(deadline)
				}
				defer c.Close()

				var b [1]byte
				n, err := c.Read(b[:])
				if n != 0 || err != io.EOF {
					t.Errorf("got (%d, %v); want (0, io.EOF)", n, err)
					return
				}
				switch c := c.(type) {
				case *TCPConn:
					err = c.CloseWrite()
				case *UnixConn:
					err = c.CloseWrite()
				}
				if err != nil {
					if perr := parseCloseError(err, true); perr != nil {
						t.Error(perr)
					}
					t.Error(err)
					return
				}
				n, err = c.Write(b[:])
				if err == nil {
					t.Errorf("got (%d, %v); want (any, error)", n, err)
					return
				}
			}

			ls := newLocalServer(t, network)
			defer ls.teardown()
			if err := ls.buildup(handler); err != nil {
				t.Fatal(err)
			}

			c, err := Dial(ls.Listener.Addr().Network(), ls.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if !deadline.IsZero() {
				c.SetDeadline(deadline)
			}
			switch network {
			case "unix", "unixpacket":
				defer os.Remove(c.LocalAddr().String())
			}
			defer c.Close()

			switch c := c.(type) {
			case *TCPConn:
				err = c.CloseWrite()
			case *UnixConn:
				err = c.CloseWrite()
			}
			if err != nil {
				if perr := parseCloseError(err, true); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}
			var b [1]byte
			n, err := c.Read(b[:])
			if n != 0 || err != io.EOF {
				t.Fatalf("got (%d, %v); want (0, io.EOF)", n, err)
			}
			n, err = c.Write(b[:])
			if err == nil {
				t.Fatalf("got (%d, %v); want (any, error)", n, err)
			}
		})
	}
}

func TestConnClose(t *testing.T) {
	t.Parallel()
	for _, network := range []string{"tcp", "unix", "unixpacket"} {
		network := network
		t.Run(network, func(t *testing.T) {
			if !testableNetwork(network) {
				t.Skipf("network %s is not testable on the current platform", network)
			}
			t.Parallel()

			ln := newLocalListener(t, network)
			switch network {
			case "unix", "unixpacket":
				defer os.Remove(ln.Addr().String())
			}
			defer ln.Close()

			c, err := Dial(ln.Addr().Network(), ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			switch network {
			case "unix", "unixpacket":
				defer os.Remove(c.LocalAddr().String())
			}
			defer c.Close()

			if err := c.Close(); err != nil {
				if perr := parseCloseError(err, false); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}
			var b [1]byte
			n, err := c.Read(b[:])
			if n != 0 || err == nil {
				t.Fatalf("got (%d, %v); want (0, error)", n, err)
			}
		})
	}
}

func TestListenerClose(t *testing.T) {
	t.Parallel()
	for _, network := range []string{"tcp", "unix", "unixpacket"} {
		network := network
		t.Run(network, func(t *testing.T) {
			if !testableNetwork(network) {
				t.Skipf("network %s is not testable on the current platform", network)
			}
			t.Parallel()

			ln := newLocalListener(t, network)
			switch network {
			case "unix", "unixpacket":
				defer os.Remove(ln.Addr().String())
			}

			if err := ln.Close(); err != nil {
				if perr := parseCloseError(err, false); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}
			c, err := ln.Accept()
			if err == nil {
				c.Close()
				t.Fatal("should fail")
			}

			// Note: we cannot ensure that a subsequent Dial does not succeed, because
			// we do not in general have any guarantee that ln.Addr is not immediately
			// reused. (TCP sockets enter a TIME_WAIT state when closed, but that only
			// applies to existing connections for the port — it does not prevent the
			// port itself from being used for entirely new connections in the
			// meantime.)
		})
	}
}

func TestPacketConnClose(t *testing.T) {
	t.Parallel()
	for _, network := range []string{"udp", "unixgram"} {
		network := network
		t.Run(network, func(t *testing.T) {
			if !testableNetwork(network) {
				t.Skipf("network %s is not testable on the current platform", network)
			}
			t.Parallel()

			c := newLocalPacketListener(t, network)
			switch network {
			case "unixgram":
				defer os.Remove(c.LocalAddr().String())
			}
			defer c.Close()

			if err := c.Close(); err != nil {
				if perr := parseCloseError(err, false); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}
			var b [1]byte
			n, _, err := c.ReadFrom(b[:])
			if n != 0 || err == nil {
				t.Fatalf("got (%d, %v); want (0, error)", n, err)
			}
		})
	}
}

// See golang.org/issue/6163, golang.org/issue/6987.
func TestAcceptIgnoreAbortedConnRequest(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("%s does not have full support of socktest", runtime.GOOS)
	}

	syserr := make(chan error)
	go func() {
		defer close(syserr)
		for _, err := range abortedConnRequestErrors {
			syserr <- err
		}
	}()
	sw.Set(socktest.FilterAccept, func(so *socktest.Status) (socktest.AfterFilter, error) {
		if err, ok := <-syserr; ok {
			return nil, err
		}
		return nil, nil
	})
	defer sw.Set(socktest.FilterAccept, nil)

	operr := make(chan error, 1)
	handler := func(ls *localServer, ln Listener) {
		defer close(operr)
		c, err := ln.Accept()
		if err != nil {
			if perr := parseAcceptError(err); perr != nil {
				operr <- perr
			}
			operr <- err
			return
		}
		c.Close()
	}
	ls := newLocalServer(t, "tcp")
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}

	c, err := Dial(ls.Listener.Addr().Network(), ls.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	for err := range operr {
		t.Error(err)
	}
}

func TestZeroByteRead(t *testing.T) {
	t.Parallel()
	for _, network := range []string{"tcp", "unix", "unixpacket"} {
		network := network
		t.Run(network, func(t *testing.T) {
			if !testableNetwork(network) {
				t.Skipf("network %s is not testable on the current platform", network)
			}
			t.Parallel()

			ln := newLocalListener(t, network)
			connc := make(chan Conn, 1)
			defer func() {
				ln.Close()
				for c := range connc {
					if c != nil {
						c.Close()
					}
				}
			}()
			go func() {
				defer close(connc)
				c, err := ln.Accept()
				if err != nil {
					t.Error(err)
				}
				connc <- c // might be nil
			}()
			c, err := Dial(network, ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			sc := <-connc
			if sc == nil {
				return
			}
			defer sc.Close()

			if runtime.GOOS == "windows" {
				// A zero byte read on Windows caused a wait for readability first.
				// Rather than change that behavior, satisfy it in this test.
				// See Issue 15735.
				go io.WriteString(sc, "a")
			}

			n, err := c.Read(nil)
			if n != 0 || err != nil {
				t.Errorf("%s: zero byte client read = %v, %v; want 0, nil", network, n, err)
			}

			if runtime.GOOS == "windows" {
				// Same as comment above.
				go io.WriteString(c, "a")
			}
			n, err = sc.Read(nil)
			if n != 0 || err != nil {
				t.Errorf("%s: zero byte server read = %v, %v; want 0, nil", network, n, err)
			}
		})
	}
}

// withTCPConnPair sets up a TCP connection between two peers, then
// runs peer1 and peer2 concurrently. withTCPConnPair returns when
// both have completed.
func withTCPConnPair(t *testing.T, peer1, peer2 func(c *TCPConn) error) {
	t.Helper()
	ln := newLocalListener(t, "tcp")
	defer ln.Close()
	errc := make(chan error, 2)
	go func() {
		c1, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		err = peer1(c1.(*TCPConn))
		c1.Close()
		errc <- err
	}()
	go func() {
		c2, err := Dial("tcp", ln.Addr().String())
		if err != nil {
			errc <- err
			return
		}
		err = peer2(c2.(*TCPConn))
		c2.Close()
		errc <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}
}

// Tests that a blocked Read is interrupted by a concurrent SetReadDeadline
// modifying that Conn's read deadline to the past.
// See golang.org/cl/30164 which documented this. The net/http package
// depends on this.
func TestReadTimeoutUnblocksRead(t *testing.T) {
	serverDone := make(chan struct{})
	server := func(cs *TCPConn) error {
		defer close(serverDone)
		errc := make(chan error, 1)
		go func() {
			defer close(errc)
			go func() {
				// TODO: find a better way to wait
				// until we're blocked in the cs.Read
				// call below. Sleep is lame.
				time.Sleep(100 * time.Millisecond)

				// Interrupt the upcoming Read, unblocking it:
				cs.SetReadDeadline(time.Unix(123, 0)) // time in the past
			}()
			var buf [1]byte
			n, err := cs.Read(buf[:1])
			if n != 0 || err == nil {
				errc <- fmt.Errorf("Read = %v, %v; want 0, non-nil", n, err)
			}
		}()
		select {
		case err := <-errc:
			return err
		case <-time.After(5 * time.Second):
			buf := make([]byte, 2<<20)
			buf = buf[:runtime.Stack(buf, true)]
			println("Stacks at timeout:\n", string(buf))
			return errors.New("timeout waiting for Read to finish")
		}

	}
	// Do nothing in the client. Never write. Just wait for the
	// server's half to be done.
	client := func(*TCPConn) error {
		<-serverDone
		return nil
	}
	withTCPConnPair(t, client, server)
}

// Issue 17695: verify that a blocked Read is woken up by a Close.
func TestCloseUnblocksRead(t *testing.T) {
	t.Parallel()
	server := func(cs *TCPConn) error {
		// Give the client time to get stuck in a Read:
		time.Sleep(20 * time.Millisecond)
		cs.Close()
		return nil
	}
	client := func(ss *TCPConn) error {
		n, err := ss.Read([]byte{0})
		if n != 0 || err != io.EOF {
			return fmt.Errorf("Read = %v, %v; want 0, EOF", n, err)
		}
		return nil
	}
	withTCPConnPair(t, client, server)
}

// Issue 24808: verify that ECONNRESET is not temporary for read.
func TestNotTemporaryRead(t *testing.T) {
	t.Parallel()

	ln := newLocalListener(t, "tcp")
	serverDone := make(chan struct{})
	dialed := make(chan struct{})
	go func() {
		defer close(serverDone)

		cs, err := ln.Accept()
		if err != nil {
			return
		}
		<-dialed
		cs.(*TCPConn).SetLinger(0)
		cs.Close()
	}()
	defer func() {
		ln.Close()
		<-serverDone
	}()

	ss, err := Dial("tcp", ln.Addr().String())
	close(dialed)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()

	_, err = ss.Read([]byte{0})
	if err == nil {
		t.Fatal("Read succeeded unexpectedly")
	} else if err == io.EOF {
		// This happens on Plan 9, but for some reason (prior to CL 385314) it was
		// accepted everywhere else too.
		if runtime.GOOS == "plan9" {
			return
		}
		t.Fatal("Read unexpectedly returned io.EOF after socket was abruptly closed")
	}
	if ne, ok := err.(Error); !ok {
		t.Errorf("Read error does not implement net.Error: %v", err)
	} else if ne.Temporary() {
		t.Errorf("Read error is unexpectedly temporary: %v", err)
	}
}

// The various errors should implement the Error interface.
func TestErrors(t *testing.T) {
	var (
		_ Error = &OpError{}
		_ Error = &ParseError{}
		_ Error = &AddrError{}
		_ Error = UnknownNetworkError("")
		_ Error = InvalidAddrError("")
		_ Error = &timeoutError{}
		_ Error = &DNSConfigError{}
		_ Error = &DNSError{}
	)

	// ErrClosed was introduced as type error, so we can't check
	// it using a declaration.
	if _, ok := ErrClosed.(Error); !ok {
		t.Fatal("ErrClosed does not implement Error")
	}
}
```