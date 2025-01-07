Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Understanding the Context:**

* **Filename:** `mockserver_test.go` strongly suggests this file contains helper functions and structures for testing the `net` package's server-side functionalities. The `_test.go` suffix confirms it's part of the testing framework.
* **Package:** `package net` indicates these testing utilities are specifically designed for the `net` package itself, likely used in its internal tests.
* **Copyright:** Standard Go copyright notice, not directly relevant to the functionality.
* **Imports:**  A quick glance at the imports reveals common testing libraries (`testing`), OS interaction (`os`, `path/filepath`), concurrency primitives (`sync`), time manipulation (`time`), and context management (`context`). The presence of `internal/testenv` suggests this is for internal Go testing.

**2. Identifying Key Structures and Functions:**

I'll go through the code and group related components:

* **Address Generation:** The `testUnixAddr` function clearly generates unique Unix socket addresses for testing.
* **Listener Creation:**  Several functions focus on creating `Listener` instances for different network types: `newLocalListener`, `newDualStackListener`, `newLocalPacketListener`, `newDualStackPacketListener`. The `ListenConfig` usage is also noticeable.
* **Server Abstraction:** The `localServer`, `streamListener`, `dualStackServer`, `localPacketServer`, and `packetListener` structs represent different kinds of test servers. They all have a `Listener` or `PacketConn` and methods like `buildup` and `teardown` suggesting a lifecycle management approach.
* **Data Transfer Utilities:**  `transponder`, `transceiver`, `packetTransponder`, `packetTransceiver` seem to handle data exchange between clients and servers during tests.
* **Socket Pair Generation:** `spawnTestSocketPair` creates connected client and server sockets, useful for testing connection-oriented protocols.
* **External Process Simulation:** `startTestSocketPeer` and the `init()` function using `GO_NET_TEST_TRANSFER` environment variables appear to simulate network operations in a separate process, likely for testing scenarios involving file descriptor passing.

**3. Analyzing Function by Function (with a focus on "what does it do?"):**

For each function, I ask:

* **Purpose:** What is this function trying to achieve?
* **Inputs:** What arguments does it take?
* **Outputs:** What does it return?
* **Side Effects:** Does it modify any external state? (e.g., creates files, starts goroutines).

* **`testUnixAddr`:** Creates a unique temporary directory and a socket file path within it. Cleans up the directory after the test.
* **`newLocalListener`:** Creates a listener on a local address (loopback or Unix socket) based on the provided network type. Handles IPv4/IPv6 differences.
* **`newDualStackListener`:** Creates a pair of TCP listeners, one for IPv4 and one for IPv6, on the same port (if possible).
* **`localServer` struct:** Represents a basic test server with a listener and mechanisms to manage its lifecycle.
* **`buildup` (on `localServer`):** Starts a goroutine to handle incoming connections on the listener.
* **`teardown` (on `localServer`):** Closes the listener and any accepted connections, cleaning up resources.
* **`newLocalServer`:** Creates a `localServer` instance.
* **`streamListener` struct:** A thin wrapper around a `Listener`, likely for organization.
* **`dualStackServer` struct:** Manages a pair of listeners (IPv4 and IPv6) for dual-stack testing.
* **`buildup` (on `dualStackServer`):** Starts goroutines for each listener.
* **`teardownNetwork` (on `dualStackServer`):** Tears down only the listener for a specific network.
* **`teardown` (on `dualStackServer`):** Tears down both listeners.
* **`newDualStackServer`:** Creates a `dualStackServer`.
* **`transponder`:** A connection handler that accepts a connection, reads data, and echoes it back.
* **`transceiver`:** Sends data on a connection and reads the response.
* **`newLocalPacketListener`:** Creates a packet listener (UDP or Unixgram).
* **`newDualStackPacketListener`:** Creates a pair of UDP packet listeners (IPv4 and IPv6).
* **`localPacketServer` struct:** Represents a test server for packet-based communication.
* **`buildup` and `teardown` (on `localPacketServer`):** Similar to `localServer` but for packet connections.
* **`newLocalPacketServer`:** Creates a `localPacketServer`.
* **`packetListener` struct:** Wrapper for a `PacketConn`.
* **`packetTransponder`:** Handles incoming packets, potentially resolving the peer address and echoing the data back.
* **`packetTransceiver`:** Sends a packet and receives a response.
* **`spawnTestSocketPair`:** Creates a connected TCP socket pair for testing.
* **`startTestSocketPeer`:** Starts a separate process to simulate network operations using file descriptor passing.
* **`init()`:**  This function, which runs automatically, checks for environment variables related to data transfer and either reads from or writes to a connection (obtained via a file descriptor). This is for the separate process launched by `startTestSocketPeer`.

**4. Identifying Go Language Features:**

As I analyzed the functions, I noted the usage of specific Go features:

* **Interfaces:** `Listener`, `Conn`, `PacketConn` are interfaces, allowing for polymorphism.
* **Goroutines and Channels:** Used extensively for concurrent server handling (`buildup`, `transponder`).
* **Contexts:**  Used in `Listen` and `ListenPacket` for managing timeouts and cancellations.
* **Error Handling:**  Standard Go error handling patterns (`if err != nil`).
* **Defer:** Used for resource cleanup (`ln.Close()`, `c.Close()`, `os.Remove()`).
* **Variadic Functions:** `newLocalListener` and `newLocalPacketListener` accept optional `ListenConfig` arguments.
* **Type Assertions:**  Used to get concrete types from interfaces (e.g., `ln.(*TCPListener)`).
* **File Descriptor Passing:** The `startTestSocketPeer` and `init()` functions demonstrate passing file descriptors to child processes using `cmd.ExtraFiles` and `os.NewFile(uintptr(3), ...)`.

**5. Code Example Generation (based on identified features):**

I picked a representative feature like `newLocalListener` and constructed a simple example showing its usage and potential input/output.

**6. Command-Line Argument Handling:**

I focused on the `startTestSocketPeer` and `init()` functions, recognizing that they use environment variables for communication, which is a form of command-line argument passing in this context.

**7. Common Mistakes:**

I thought about potential pitfalls when using these utilities, particularly around resource management (not closing connections/listeners) and the complexities of dual-stack setup.

**8. Structuring the Answer:**

Finally, I organized the information into logical sections (Functionality, Go Features, Code Examples, etc.) to provide a clear and comprehensive explanation. I made sure to use clear, concise language and provide context where needed.
这个go语言文件 `mockserver_test.go` 的主要功能是为 `net` 包提供**用于测试网络连接和服务器行为的模拟基础设施**。它包含了一系列辅助函数和结构体，用于创建和管理各种类型的网络监听器和连接，方便编写针对 `net` 包中网络功能的单元测试。

更具体地说，它实现了以下功能：

1. **创建本地监听器 (Listeners):**
   - 提供了 `newLocalListener` 函数，可以方便地创建各种本地网络类型的监听器，例如 `tcp`, `tcp4`, `tcp6`, `unix`, `unixpacket`。
   - 考虑了 IPv4 和 IPv6 的支持情况，并根据系统能力选择合适的地址。
   - 对于 Unix 域套接字，使用了 `testUnixAddr` 函数生成唯一的临时地址，避免冲突。
   - 允许传递 `ListenConfig` 来自定义监听器的行为。

2. **创建双栈监听器 (Dual-Stack Listeners):**
   - 提供了 `newDualStackListener` 函数，用于创建同时监听 IPv4 和 IPv6 的 TCP 监听器，方便测试双栈网络环境下的行为。

3. **定义本地服务器结构体 (`localServer`):**
   - 定义了一个 `localServer` 结构体，用于抽象本地 TCP 或 Unix 套接字服务器。
   - 包含一个 `Listener` 接口，表示服务器监听的套接字。
   - 使用 `sync.RWMutex` 进行并发控制。
   - 使用 `done` channel 来通知服务器已停止。
   - 使用 `cl` 切片存储已接受的连接。
   - 提供了 `buildup` 方法来启动服务器，该方法会启动一个 goroutine 来处理连接。
   - 提供了 `teardown` 方法来优雅地关闭服务器和所有连接，并清理 Unix 域套接字文件。
   - 提供了 `newLocalServer` 函数来创建 `localServer` 实例。

4. **定义流式监听器结构体 (`streamListener`):**
   - 定义了一个 `streamListener` 结构体，用于包装 `Listener`，可能用于更具体的测试场景。

5. **定义双栈服务器结构体 (`dualStackServer`):**
   - 定义了一个 `dualStackServer` 结构体，用于抽象同时监听 IPv4 和 IPv6 的 TCP 服务器。
   - 包含一个 `streamListener` 切片，存储两个监听器。
   - 提供了 `buildup` 和 `teardown` 方法来管理服务器的生命周期。
   - 提供了 `teardownNetwork` 方法来单独关闭特定网络的监听器。
   - 提供了 `newDualStackServer` 函数来创建 `dualStackServer` 实例。

6. **实现数据转发的函数 (`transponder`, `transceiver`):**
   - `transponder` 函数用于在服务器端处理连接，它会读取客户端发送的数据并将其回显。
   - `transceiver` 函数用于在客户端向服务器发送数据并接收响应。
   - 这些函数都设置了读写截止时间，防止测试无限期阻塞。

7. **创建本地数据包监听器 (Packet Listeners):**
   - 提供了 `newLocalPacketListener` 函数，用于创建本地 UDP 或 Unix 数据报套接字监听器.
   - 考虑了 IPv4 和 IPv6 的支持情况。

8. **创建双栈数据包监听器 (Dual-Stack Packet Listeners):**
   - 提供了 `newDualStackPacketListener` 函数，用于创建同时监听 IPv4 和 IPv6 的 UDP 数据包监听器.

9. **定义本地数据包服务器结构体 (`localPacketServer`):**
   - 定义了一个 `localPacketServer` 结构体，用于抽象本地 UDP 或 Unix 数据报套接字服务器。
   - 结构和方法与 `localServer` 类似，但针对的是 `PacketConn`。

10. **定义数据包监听器结构体 (`packetListener`):**
    - 类似于 `streamListener`，用于包装 `PacketConn`。

11. **实现数据包转发的函数 (`packetTransponder`, `packetTransceiver`):**
    - `packetTransponder` 函数用于在数据包服务器端处理接收到的数据包，并将其发送回发送者。
    - `packetTransceiver` 函数用于在客户端向数据包服务器发送数据包并接收响应。

12. **创建测试用的套接字对 (`spawnTestSocketPair`):**
    - 提供了一个 `spawnTestSocketPair` 函数，用于快速创建一对已连接的 TCP 套接字，方便进行端到端测试。

13. **启动测试套接字对等端进程 (`startTestSocketPeer`):**
    - 提供了一个 `startTestSocketPeer` 函数，用于启动一个独立的进程来模拟网络操作，例如大文件传输。
    - 它使用了 `os.File` 和文件描述符传递的方式与主测试进程通信。
    - 通过环境变量 `GO_NET_TEST_TRANSFER` 等来控制子进程的行为（读或写，数据块大小，总大小）。

14. **`init` 函数：**
    -  `init` 函数会在包加载时自动执行。
    -  它检查环境变量 `GO_NET_TEST_TRANSFER` 是否设置。如果设置了，则说明当前进程是由 `startTestSocketPeer` 启动的子进程。
    -  子进程会根据环境变量执行相应的网络操作（读或写），用于模拟网络传输。

**它可以推理出是什么go语言功能的实现：**

这个文件主要实现了以下 Go 语言网络编程功能的辅助测试工具：

* **`net.Listen` 和 `net.ListenTCP`, `net.ListenUDP`, `net.ListenUnix` 等:** 用于创建各种类型的网络监听器。
* **`net.Dial`:** 用于创建客户端连接。
* **`net.Accept`:** 用于服务器端接受客户端连接。
* **`net.Conn` 和 `net.PacketConn` 接口:** 代表网络连接和数据包连接。
* **`net.TCPListener`, `net.UnixListener`, `net.UDPConn` 等:**  具体的监听器和连接类型。
* **`context.Context`:** 用于管理监听和连接的生命周期。
* **`sync` 包:** 用于处理并发，例如互斥锁 (`sync.RWMutex`) 和等待组 (`sync.WaitGroup`, 虽然在这个文件中没有直接使用，但很常见于测试场景)。
* **`os` 包:** 用于操作文件系统，例如创建临时目录和文件（用于 Unix 域套接字）。
* **`time` 包:** 用于设置超时时间。
* **`internal/testenv` 包:** Go 内部测试环境工具，用于启动子进程等。

**Go 代码举例说明：**

以下代码展示了如何使用 `newLocalServer` 和 `transponder` 来创建一个简单的回显 TCP 服务器并进行测试：

```go
func TestEchoServer(t *testing.T) {
	server := newLocalServer(t, "tcp")
	defer server.teardown()

	// 定义服务器处理逻辑
	handler := func(ls *localServer, ln Listener) {
		conn, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = conn.Write(buf[:n])
		if err != nil {
			t.Error(err)
			return
		}
	}

	err := server.buildup(handler)
	if err != nil {
		t.Fatal(err)
	}

	// 客户端连接到服务器
	conn, err := Dial(server.Listener.Addr().Network(), server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// 发送数据
	message := "Hello, server!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		t.Fatal(err)
	}

	// 接收响应
	buffer := make([]byte, len(message))
	_, err = conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}

	if string(buffer) != message {
		t.Errorf("Expected '%s', got '%s'", message, string(buffer))
	}
}
```

**假设的输入与输出：**

在上面的 `TestEchoServer` 例子中：

* **输入 (客户端):**  字符串 "Hello, server!"
* **输出 (客户端):**  字符串 "Hello, server!" (服务器回显)

**命令行参数的具体处理：**

这个文件本身并没有直接处理命令行参数。但是，它通过以下方式处理与子进程通信相关的 "命令行参数"：

* **环境变量:** `startTestSocketPeer` 函数会设置一些以 `GO_NET_TEST_TRANSFER_` 开头的环境变量，例如：
    * `GO_NET_TEST_TRANSFER=1`:  标识当前进程是一个用于测试文件传输的子进程。
    * `GO_NET_TEST_TRANSFER_OP`:  指定子进程的操作，可以是 "r" (读) 或 "w" (写)。
    * `GO_NET_TEST_TRANSFER_CHUNK_SIZE`: 指定每次读写的数据块大小。
    * `GO_NET_TEST_TRANSFER_TOTAL_SIZE`: 指定总共需要读写的数据大小。
* **文件描述符传递:** `startTestSocketPeer`  会将一个与网络连接关联的文件描述符通过 `cmd.ExtraFiles` 传递给子进程。子进程在 `init` 函数中使用 `os.NewFile(uintptr(3), ...)` 来重新获取这个文件描述符，从而操作同一个网络连接。  这里 `uintptr(3)` 是一个约定俗成的做法，因为文件描述符 0、1、2 分别是标准输入、标准输出和标准错误。

**使用者易犯错的点：**

1. **忘记关闭监听器和连接:**  在测试结束后，必须确保调用 `teardown()` 方法或手动关闭 `Listener` 和 `Conn`，否则可能导致资源泄漏。

   ```go
   func BadTest() {
       ln := newLocalListener(nil, "tcp") // 忘记使用 t *testing.T
       // ... 一些测试代码 ...
       // 忘记 ln.Close()
   }

   func GoodTest(t *testing.T) {
       ln := newLocalListener(t, "tcp")
       defer ln.Close()
       // ... 一些测试代码 ...
   }
   ```

2. **在并发测试中不正确地使用共享资源:** `localServer` 等结构体中的 `cl` 字段需要使用互斥锁进行保护，如果在多个 goroutine 中同时访问和修改，可能会导致数据竞争。

3. **没有正确处理 `buildup` 的错误:** `buildup` 方法会启动一个 goroutine，如果启动失败，应该在测试中检查并处理返回的错误。

4. **在 `startTestSocketPeer` 中没有正确设置环境变量:**  如果环境变量设置不正确，子进程可能无法按照预期执行，导致测试失败。

5. **对于 Unix 域套接字，忘记清理套接字文件:** 虽然 `teardown` 方法会尝试清理，但在某些异常情况下可能失败，需要注意确保测试环境的干净。

总的来说，`mockserver_test.go` 提供了一套强大的工具，用于在 `net` 包的单元测试中模拟各种网络场景。理解其功能和正确使用这些辅助函数对于编写高质量的网络测试至关重要。

Prompt: 
```
这是路径为go/src/net/mockserver_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
	"fmt"
	"internal/testenv"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// testUnixAddr uses os.MkdirTemp to get a name that is unique.
func testUnixAddr(t testing.TB) string {
	// Pass an empty pattern to get a directory name that is as short as possible.
	// If we end up with a name longer than the sun_path field in the sockaddr_un
	// struct, we won't be able to make the syscall to open the socket.
	d, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(d); err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(d, "sock")
}

func newLocalListener(t testing.TB, network string, lcOpt ...*ListenConfig) Listener {
	var lc *ListenConfig
	switch len(lcOpt) {
	case 0:
		lc = new(ListenConfig)
	case 1:
		lc = lcOpt[0]
	default:
		t.Helper()
		t.Fatal("too many ListenConfigs passed to newLocalListener: want 0 or 1")
	}

	listen := func(net, addr string) Listener {
		ln, err := lc.Listen(context.Background(), net, addr)
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
		return ln
	}

	switch network {
	case "tcp":
		if supportsIPv4() {
			return listen("tcp4", "127.0.0.1:0")
		}
		if supportsIPv6() {
			return listen("tcp6", "[::1]:0")
		}
	case "tcp4":
		if supportsIPv4() {
			return listen("tcp4", "127.0.0.1:0")
		}
	case "tcp6":
		if supportsIPv6() {
			return listen("tcp6", "[::1]:0")
		}
	case "unix", "unixpacket":
		return listen(network, testUnixAddr(t))
	}

	t.Helper()
	t.Fatalf("%s is not supported", network)
	return nil
}

func newDualStackListener() (lns []*TCPListener, err error) {
	var args = []struct {
		network string
		TCPAddr
	}{
		{"tcp4", TCPAddr{IP: IPv4(127, 0, 0, 1)}},
		{"tcp6", TCPAddr{IP: IPv6loopback}},
	}
	for i := 0; i < 64; i++ {
		var port int
		var lns []*TCPListener
		for _, arg := range args {
			arg.TCPAddr.Port = port
			ln, err := ListenTCP(arg.network, &arg.TCPAddr)
			if err != nil {
				continue
			}
			port = ln.Addr().(*TCPAddr).Port
			lns = append(lns, ln)
		}
		if len(lns) != len(args) {
			for _, ln := range lns {
				ln.Close()
			}
			continue
		}
		return lns, nil
	}
	return nil, errors.New("no dualstack port available")
}

type localServer struct {
	lnmu sync.RWMutex
	Listener
	done chan bool // signal that indicates server stopped
	cl   []Conn    // accepted connection list
}

func (ls *localServer) buildup(handler func(*localServer, Listener)) error {
	go func() {
		handler(ls, ls.Listener)
		close(ls.done)
	}()
	return nil
}

func (ls *localServer) teardown() error {
	ls.lnmu.Lock()
	defer ls.lnmu.Unlock()
	if ls.Listener != nil {
		network := ls.Listener.Addr().Network()
		address := ls.Listener.Addr().String()
		ls.Listener.Close()
		for _, c := range ls.cl {
			if err := c.Close(); err != nil {
				return err
			}
		}
		<-ls.done
		ls.Listener = nil
		switch network {
		case "unix", "unixpacket":
			os.Remove(address)
		}
	}
	return nil
}

func newLocalServer(t testing.TB, network string) *localServer {
	t.Helper()
	ln := newLocalListener(t, network)
	return &localServer{Listener: ln, done: make(chan bool)}
}

type streamListener struct {
	network, address string
	Listener
	done chan bool // signal that indicates server stopped
}

func (sl *streamListener) newLocalServer() *localServer {
	return &localServer{Listener: sl.Listener, done: make(chan bool)}
}

type dualStackServer struct {
	lnmu sync.RWMutex
	lns  []streamListener
	port string

	cmu sync.RWMutex
	cs  []Conn // established connections at the passive open side
}

func (dss *dualStackServer) buildup(handler func(*dualStackServer, Listener)) error {
	for i := range dss.lns {
		go func(i int) {
			handler(dss, dss.lns[i].Listener)
			close(dss.lns[i].done)
		}(i)
	}
	return nil
}

func (dss *dualStackServer) teardownNetwork(network string) error {
	dss.lnmu.Lock()
	for i := range dss.lns {
		if network == dss.lns[i].network && dss.lns[i].Listener != nil {
			dss.lns[i].Listener.Close()
			<-dss.lns[i].done
			dss.lns[i].Listener = nil
		}
	}
	dss.lnmu.Unlock()
	return nil
}

func (dss *dualStackServer) teardown() error {
	dss.lnmu.Lock()
	for i := range dss.lns {
		if dss.lns[i].Listener != nil {
			dss.lns[i].Listener.Close()
			<-dss.lns[i].done
		}
	}
	dss.lns = dss.lns[:0]
	dss.lnmu.Unlock()
	dss.cmu.Lock()
	for _, c := range dss.cs {
		c.Close()
	}
	dss.cs = dss.cs[:0]
	dss.cmu.Unlock()
	return nil
}

func newDualStackServer() (*dualStackServer, error) {
	lns, err := newDualStackListener()
	if err != nil {
		return nil, err
	}
	_, port, err := SplitHostPort(lns[0].Addr().String())
	if err != nil {
		lns[0].Close()
		lns[1].Close()
		return nil, err
	}
	return &dualStackServer{
		lns: []streamListener{
			{network: "tcp4", address: lns[0].Addr().String(), Listener: lns[0], done: make(chan bool)},
			{network: "tcp6", address: lns[1].Addr().String(), Listener: lns[1], done: make(chan bool)},
		},
		port: port,
	}, nil
}

func (ls *localServer) transponder(ln Listener, ch chan<- error) {
	defer close(ch)

	switch ln := ln.(type) {
	case *TCPListener:
		ln.SetDeadline(time.Now().Add(someTimeout))
	case *UnixListener:
		ln.SetDeadline(time.Now().Add(someTimeout))
	}
	c, err := ln.Accept()
	if err != nil {
		if perr := parseAcceptError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	ls.cl = append(ls.cl, c)

	network := ln.Addr().Network()
	if c.LocalAddr().Network() != network || c.RemoteAddr().Network() != network {
		ch <- fmt.Errorf("got %v->%v; expected %v->%v", c.LocalAddr().Network(), c.RemoteAddr().Network(), network, network)
		return
	}
	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	b := make([]byte, 256)
	n, err := c.Read(b)
	if err != nil {
		if perr := parseReadError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if _, err := c.Write(b[:n]); err != nil {
		if perr := parseWriteError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
}

func transceiver(c Conn, wb []byte, ch chan<- error) {
	defer close(ch)

	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	n, err := c.Write(wb)
	if err != nil {
		if perr := parseWriteError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if n != len(wb) {
		ch <- fmt.Errorf("wrote %d; want %d", n, len(wb))
	}
	rb := make([]byte, len(wb))
	n, err = c.Read(rb)
	if err != nil {
		if perr := parseReadError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if n != len(wb) {
		ch <- fmt.Errorf("read %d; want %d", n, len(wb))
	}
}

func newLocalPacketListener(t testing.TB, network string, lcOpt ...*ListenConfig) PacketConn {
	var lc *ListenConfig
	switch len(lcOpt) {
	case 0:
		lc = new(ListenConfig)
	case 1:
		lc = lcOpt[0]
	default:
		t.Helper()
		t.Fatal("too many ListenConfigs passed to newLocalListener: want 0 or 1")
	}

	listenPacket := func(net, addr string) PacketConn {
		c, err := lc.ListenPacket(context.Background(), net, addr)
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
		return c
	}

	t.Helper()
	switch network {
	case "udp":
		if supportsIPv4() {
			return listenPacket("udp4", "127.0.0.1:0")
		}
		if supportsIPv6() {
			return listenPacket("udp6", "[::1]:0")
		}
	case "udp4":
		if supportsIPv4() {
			return listenPacket("udp4", "127.0.0.1:0")
		}
	case "udp6":
		if supportsIPv6() {
			return listenPacket("udp6", "[::1]:0")
		}
	case "unixgram":
		return listenPacket(network, testUnixAddr(t))
	}

	t.Fatalf("%s is not supported", network)
	return nil
}

func newDualStackPacketListener() (cs []*UDPConn, err error) {
	var args = []struct {
		network string
		UDPAddr
	}{
		{"udp4", UDPAddr{IP: IPv4(127, 0, 0, 1)}},
		{"udp6", UDPAddr{IP: IPv6loopback}},
	}
	for i := 0; i < 64; i++ {
		var port int
		var cs []*UDPConn
		for _, arg := range args {
			arg.UDPAddr.Port = port
			c, err := ListenUDP(arg.network, &arg.UDPAddr)
			if err != nil {
				continue
			}
			port = c.LocalAddr().(*UDPAddr).Port
			cs = append(cs, c)
		}
		if len(cs) != len(args) {
			for _, c := range cs {
				c.Close()
			}
			continue
		}
		return cs, nil
	}
	return nil, errors.New("no dualstack port available")
}

type localPacketServer struct {
	pcmu sync.RWMutex
	PacketConn
	done chan bool // signal that indicates server stopped
}

func (ls *localPacketServer) buildup(handler func(*localPacketServer, PacketConn)) error {
	go func() {
		handler(ls, ls.PacketConn)
		close(ls.done)
	}()
	return nil
}

func (ls *localPacketServer) teardown() error {
	ls.pcmu.Lock()
	if ls.PacketConn != nil {
		network := ls.PacketConn.LocalAddr().Network()
		address := ls.PacketConn.LocalAddr().String()
		ls.PacketConn.Close()
		<-ls.done
		ls.PacketConn = nil
		switch network {
		case "unixgram":
			os.Remove(address)
		}
	}
	ls.pcmu.Unlock()
	return nil
}

func newLocalPacketServer(t testing.TB, network string) *localPacketServer {
	t.Helper()
	c := newLocalPacketListener(t, network)
	return &localPacketServer{PacketConn: c, done: make(chan bool)}
}

type packetListener struct {
	PacketConn
}

func (pl *packetListener) newLocalServer() *localPacketServer {
	return &localPacketServer{PacketConn: pl.PacketConn, done: make(chan bool)}
}

func packetTransponder(c PacketConn, ch chan<- error) {
	defer close(ch)

	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	b := make([]byte, 256)
	n, peer, err := c.ReadFrom(b)
	if err != nil {
		if perr := parseReadError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if peer == nil { // for connected-mode sockets
		switch c.LocalAddr().Network() {
		case "udp":
			peer, err = ResolveUDPAddr("udp", string(b[:n]))
		case "unixgram":
			peer, err = ResolveUnixAddr("unixgram", string(b[:n]))
		}
		if err != nil {
			ch <- err
			return
		}
	}
	if _, err := c.WriteTo(b[:n], peer); err != nil {
		if perr := parseWriteError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
}

func packetTransceiver(c PacketConn, wb []byte, dst Addr, ch chan<- error) {
	defer close(ch)

	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	n, err := c.WriteTo(wb, dst)
	if err != nil {
		if perr := parseWriteError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if n != len(wb) {
		ch <- fmt.Errorf("wrote %d; want %d", n, len(wb))
	}
	rb := make([]byte, len(wb))
	n, _, err = c.ReadFrom(rb)
	if err != nil {
		if perr := parseReadError(err); perr != nil {
			ch <- perr
		}
		ch <- err
		return
	}
	if n != len(wb) {
		ch <- fmt.Errorf("read %d; want %d", n, len(wb))
	}
}

func spawnTestSocketPair(t testing.TB, net string) (client, server Conn) {
	t.Helper()

	ln := newLocalListener(t, net)
	defer ln.Close()
	var cerr, serr error
	acceptDone := make(chan struct{})
	go func() {
		server, serr = ln.Accept()
		acceptDone <- struct{}{}
	}()
	client, cerr = Dial(ln.Addr().Network(), ln.Addr().String())
	<-acceptDone
	if cerr != nil {
		if server != nil {
			server.Close()
		}
		t.Fatal(cerr)
	}
	if serr != nil {
		if client != nil {
			client.Close()
		}
		t.Fatal(serr)
	}
	return client, server
}

func startTestSocketPeer(t testing.TB, conn Conn, op string, chunkSize, totalSize int) (func(t testing.TB), error) {
	t.Helper()

	if runtime.GOOS == "windows" {
		// TODO(panjf2000): Windows has not yet implemented FileConn,
		//		remove this when it's implemented in https://go.dev/issues/9503.
		t.Fatalf("startTestSocketPeer is not supported on %s", runtime.GOOS)
	}

	f, err := conn.(interface{ File() (*os.File, error) }).File()
	if err != nil {
		return nil, err
	}

	cmd := testenv.Command(t, os.Args[0])
	cmd.Env = []string{
		"GO_NET_TEST_TRANSFER=1",
		"GO_NET_TEST_TRANSFER_OP=" + op,
		"GO_NET_TEST_TRANSFER_CHUNK_SIZE=" + strconv.Itoa(chunkSize),
		"GO_NET_TEST_TRANSFER_TOTAL_SIZE=" + strconv.Itoa(totalSize),
		"TMPDIR=" + os.Getenv("TMPDIR"),
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	cmdCh := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		conn.Close()
		f.Close()
		cmdCh <- err
	}()

	return func(tb testing.TB) {
		err := <-cmdCh
		if err != nil {
			tb.Errorf("process exited with error: %v", err)
		}
	}, nil
}

func init() {
	if os.Getenv("GO_NET_TEST_TRANSFER") == "" {
		return
	}
	defer os.Exit(0)

	f := os.NewFile(uintptr(3), "splice-test-conn")
	defer f.Close()

	conn, err := FileConn(f)
	if err != nil {
		log.Fatal(err)
	}

	var chunkSize int
	if chunkSize, err = strconv.Atoi(os.Getenv("GO_NET_TEST_TRANSFER_CHUNK_SIZE")); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, chunkSize)

	var totalSize int
	if totalSize, err = strconv.Atoi(os.Getenv("GO_NET_TEST_TRANSFER_TOTAL_SIZE")); err != nil {
		log.Fatal(err)
	}

	var fn func([]byte) (int, error)
	switch op := os.Getenv("GO_NET_TEST_TRANSFER_OP"); op {
	case "r":
		fn = conn.Read
	case "w":
		defer conn.Close()

		fn = conn.Write
	default:
		log.Fatalf("unknown op %q", op)
	}

	var n int
	for count := 0; count < totalSize; count += n {
		if count+chunkSize > totalSize {
			buf = buf[:totalSize-count]
		}

		var err error
		if n, err = fn(buf); err != nil {
			return
		}
	}
}

"""



```