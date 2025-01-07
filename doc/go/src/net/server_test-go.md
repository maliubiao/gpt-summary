Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Understand the Goal:** The request asks for an explanation of the Go code, specifically focusing on its functionality, underlying Go features, code examples, handling of command-line arguments, and common pitfalls.

2. **Initial Scan for Keywords:**  I immediately look for key terms and patterns that indicate the purpose of the code. "test," "server," "Listen," "Dial," "TCP," "UDP," "Unix," "Unixpacket," "transceiver," "transponder" stand out. This strongly suggests the code is about testing network server implementations.

3. **Identify the Core Structure:** The code is organized into several test functions: `TestTCPServer`, `TestUnixAndUnixpacketServer`, `TestUDPServer`, and `TestUnixgramServer`. Each function seems to test a specific network protocol.

4. **Analyze `TestTCPServer`:**
    * **`tcpServerTests`:** This variable defines a set of test cases for TCP servers, specifying different combinations of server and client network types and addresses. The `saddr: ":0"` pattern suggests the server is binding to an arbitrary port.
    * **Looping through Tests:** The code iterates through `tcpServerTests`.
    * **`Listen`:**  This is a crucial function indicating the creation of a network listener.
    * **`localServer`:** The code creates `localServer` instances, suggesting some internal test setup. The `buildup` and `teardown` methods hint at managing the server lifecycle.
    * **`transponder`:** This function likely handles the server-side logic for responding to client connections.
    * **`Dialer` and `Dial`:** This indicates the client-side establishing a connection to the server.
    * **`transceiver`:** This function is likely responsible for sending and receiving data over the established connection.
    * **Concurrency:** The use of `go transceiver(...)` suggests concurrent client connections are being tested.
    * **Error Handling:**  The code checks for errors after `Listen` and `Dial` using `if err != nil`. `parseDialError` suggests more specific error analysis.

5. **Analyze `TestUnixAndUnixpacketServer`:** This function follows a similar structure to `TestTCPServer` but uses "unix" and "unixpacket" network types. The `testUnixAddr(t)` function implies the creation of temporary Unix domain socket addresses.

6. **Analyze `TestUDPServer`:**
    * **`udpServerTests`:**  Similar to `tcpServerTests`, but for UDP. The `dial: true` field in some test cases suggests testing both connection-oriented and connectionless UDP scenarios.
    * **`ListenPacket`:** This function is used for creating UDP listeners.
    * **`packetTransponder` and `packetTransceiver`:** These are likely UDP-specific versions of the TCP counterparts, dealing with packets instead of streams.

7. **Analyze `TestUnixgramServer`:**  Focuses on "unixgram," which is a datagram-oriented Unix domain socket. The `dial: true` again indicates different connection modes.

8. **Infer the Purpose:** Based on the repeated patterns of `Listen`/`ListenPacket`, `Dial`, and data exchange functions, the overall purpose is clearly to **test the functionality of Go's network package (`net`) for various server types (TCP, UDP, Unix domain sockets)**. It tests the ability to listen for connections, establish connections from clients, and send/receive data. The multiple test cases cover different network configurations (IPv4, IPv6, loopback, wildcard addresses).

9. **Identify Go Features:**
    * **`net` package:** This is the most obvious feature being tested.
    * **`Listen`, `ListenPacket`:** Core functions for creating network listeners.
    * **`Dial`:**  Core function for initiating network connections.
    * **`Conn`, `Listener`, `PacketConn` interfaces:** These are implicitly used.
    * **Goroutines (`go`) and Channels (`chan error`):**  Used for concurrent testing and error reporting.
    * **Testing framework (`testing` package):** The structure of the code with `func Test...` and `t.Run`, `t.Fatal`, `t.Error` clearly indicates the use of Go's built-in testing framework.

10. **Construct Code Examples:**  Based on the functions used, I can construct simple examples illustrating `Listen`, `Dial`, and basic server/client interaction for TCP and UDP.

11. **Consider Command-Line Arguments:**  Since this is primarily a test file, it doesn't directly process command-line arguments in the way a typical application would. However, the `testing` package itself has command-line flags (like `-test.run`, `-test.v`). The tests might be influenced by environment variables that affect network configuration, but the code itself doesn't explicitly handle them.

12. **Identify Potential Pitfalls:**  Think about common errors developers make when working with networking in Go. Forgetting to close connections, not handling errors properly, and incorrect address/port specifications are common mistakes.

13. **Structure the Answer:** Organize the findings into the requested categories: functionality, underlying features, code examples, command-line arguments, and common pitfalls. Use clear and concise language, and provide illustrative code snippets.

14. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any logical inconsistencies or areas that could be explained better. For example, I initially might have focused too much on the specific test cases and not enough on the general purpose of the file. Reviewing helps correct such imbalances.
这段代码是 Go 语言标准库 `net` 包中 `server_test.go` 文件的一部分，它主要用于**测试 `net` 包中服务器相关的核心功能**。更具体地说，它测试了在不同网络协议（TCP, UDP, Unix domain socket, Unix packet socket）下，创建和管理服务器的能力，以及客户端与服务器之间的基本通信。

以下是它更详细的功能点：

1. **TCP 服务器测试 (`TestTCPServer`)**:
   - 测试在不同的 TCP 网络配置下创建 TCP 监听器 (`Listen`) 是否成功。这些配置包括不同的本地地址 (IPv4, IPv6, 绑定所有接口或特定接口) 和客户端连接的目标地址。
   - 测试并发地接受多个客户端连接并进行读写操作。它创建了多个 `localServer` 实例，每个实例都处理一个连接。
   - 使用 `transponder` 函数模拟服务器端的简单应答逻辑。
   - 使用 `transceiver` 函数模拟客户端发送数据并接收服务器的响应。
   - 验证在并发场景下，服务器能否正确处理多个连接并保持通信。

2. **Unix 和 Unixpacket 服务器测试 (`TestUnixAndUnixpacketServer`)**:
   - 测试创建 Unix 域 socket 和 Unix 数据报 socket 的监听器 (`Listen`) 是否成功。
   - 使用临时文件路径或抽象 socket 地址 (`@nettest/...`) 作为 Unix 域 socket 的地址。
   - 同样测试并发接受连接和读写操作，类似于 TCP 服务器的测试。

3. **UDP 服务器测试 (`TestUDPServer`)**:
   - 测试在不同的 UDP 网络配置下创建 UDP 连接 (`ListenPacket`) 是否成功。配置包括不同的本地地址和客户端的目标地址。
   - 区分了两种客户端连接方式：
     - 使用 `ListenPacket` 创建客户端连接，模拟普通的 UDP 通信。
     - 使用 `Dialer` 的 `Dial` 方法创建连接，这在 UDP 中会创建一个已连接的 UDP socket (connected UDP socket)。
   - 使用 `packetTransponder` 函数模拟 UDP 服务器的接收和发送逻辑。
   - 使用 `packetTransceiver` 或 `transceiver` 函数模拟 UDP 客户端的发送和接收逻辑。

4. **Unixgram 服务器测试 (`TestUnixgramServer`)**:
   - 测试创建 Unix 数据报 socket 的监听器 (`ListenPacket`) 是否成功。
   - 同样支持使用临时文件路径或抽象 socket 地址。
   - 也区分了两种客户端连接方式，与 UDP 类似。

**推理其实现的 Go 语言功能：**

这段代码主要测试了 `net` 包中以下核心功能：

* **`net.Listen(network, address string) (Listener, error)`**:  创建监听指定网络和地址的网络连接。用于 TCP 和 Unix 域 socket。
* **`net.ListenPacket(network, address string) (PacketConn, error)`**: 创建监听指定网络和地址的数据包连接。用于 UDP 和 Unix 数据报 socket。
* **`net.Dial(network, address string) (Conn, error)`**: 连接到指定网络和地址的网络连接。用于 TCP 和某些 UDP 测试场景。
* **`net.Dialer`**:  提供更细粒度的连接控制，例如设置超时时间和本地地址。
* **`net.SplitHostPort(hostport string) (host, port string, err error)`**: 将 "host:port" 格式的字符串分解为主机和端口。
* **`net.JoinHostPort(host, port string) string`**: 将主机和端口组合成 "host:port" 格式的字符串。
* **`net.ResolveUDPAddr(network, address string) (*UDPAddr, error)`**: 将 UDP 地址字符串解析为 `UDPAddr` 结构体。
* **`Listener` 接口**:  表示一个通用的网络监听器，用于接受新的连接。
* **`Conn` 接口**:  表示一个通用的网络连接，支持读写操作。
* **`PacketConn` 接口**: 表示一个通用的数据包连接，支持发送和接收数据包。
* **Goroutines 和 Channels**: 用于实现并发测试，确保服务器能够正确处理多个客户端的并发请求。

**Go 代码举例说明 `net.Listen` 和 `net.Dial` 的使用:**

```go
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// 模拟 TCP 服务器
	listener, err := net.Listen("tcp", "127.0.0.1:0") // 监听本地地址的任意可用端口
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("Listening on:", listener.Addr())

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err.Error())
			return
		}
		defer conn.Close()
		fmt.Println("Accepted connection from:", conn.RemoteAddr())
	}()

	// 模拟 TCP 客户端
	clientConn, err := net.Dial("tcp", listener.Addr().String()) // 连接到服务器监听的地址
	if err != nil {
		fmt.Println("Error dialing:", err.Error())
		os.Exit(1)
	}
	defer clientConn.Close()
	fmt.Println("Connected to:", clientConn.RemoteAddr())
}
```

**假设的输入与输出 (针对上面的代码示例):**

**假设输入:** 运行上述 Go 代码。

**可能输出:**

```
Listening on: 127.0.0.1:xxxxx  // xxxxx 是一个实际分配的端口号
Connected to: 127.0.0.1:xxxxx
Accepted connection from: 127.0.0.1:yyyyy // yyyyy 是客户端的端口号
```

**命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理应用程序的命令行参数。它使用的是 Go 语言的 `testing` 包，该包有自己的命令行参数，例如：

* **`-test.run <regexp>`**:  指定要运行的测试函数，可以使用正则表达式匹配。例如，`go test -test.run TestTCP` 将运行所有名称以 "TestTCP" 开头的测试函数。
* **`-test.v`**:  启用详细输出，显示每个测试函数的运行状态和日志。
* **`-test.timeout <duration>`**: 设置测试的超时时间。

例如，要在包含 `server_test.go` 的目录下运行 TCP 服务器相关的测试，可以在终端中执行：

```bash
go test -v -test.run TestTCPServer ./net
```

这里 `./net` 指的是 `net` 包的路径。

**使用者易犯错的点:**

在编写使用 `net` 包进行网络编程的代码时，常见的错误包括：

1. **忘记关闭连接 (Sockets/Connections)**:  没有显式地调用 `conn.Close()` 或 `listener.Close()` 会导致资源泄露，最终可能导致程序崩溃或系统资源耗尽。
   ```go
   // 错误示例：忘记关闭连接
   func handleConnection(conn net.Conn) {
       // 处理连接
       // ... 没有 conn.Close()
   }

   listener, _ := net.Listen("tcp", ":8080")
   for {
       conn, _ := listener.Accept()
       go handleConnection(conn)
   }
   ```

2. **没有正确处理错误**:  网络操作很容易出错 (例如，连接超时、连接被拒绝、地址已被占用等)。没有检查和处理这些错误会导致程序行为异常或崩溃。
   ```go
   // 错误示例：忽略错误
   conn, _ := net.Dial("tcp", "invalid-address")
   // 接下来使用 conn，但 conn 可能是 nil
   ```

3. **地址和端口冲突**:  尝试绑定已被其他程序占用的地址和端口会导致 `net.Listen` 返回错误。
   ```go
   // 假设 8080 端口已被占用
   listener, err := net.Listen("tcp", ":8080")
   if err != nil {
       fmt.Println("Error:", err) // 需要处理这个错误
   }
   ```

4. **在并发场景下未进行适当的同步**:  当多个 goroutine 访问或修改共享的网络连接资源时，需要使用互斥锁或其他同步机制来避免竞态条件。

5. **超时设置不合理**:  如果未设置或设置了不合理的超时时间，可能会导致程序长时间阻塞等待，或者过早地断开连接。 使用 `net.Dialer` 可以设置连接超时。

总而言之，`go/src/net/server_test.go` 这部分代码是 `net` 包功能的重要测试，它涵盖了创建各种类型的网络服务器、处理客户端连接以及基本的通信流程。通过阅读和理解这段代码，可以更深入地了解 Go 语言网络编程的核心概念和实践方法。

Prompt: 
```
这是路径为go/src/net/server_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"os"
	"testing"
)

var tcpServerTests = []struct {
	snet, saddr string // server endpoint
	tnet, taddr string // target endpoint for client
}{
	{snet: "tcp", saddr: ":0", tnet: "tcp", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "[::]:0", tnet: "tcp", taddr: "::1"},

	{snet: "tcp", saddr: ":0", tnet: "tcp", taddr: "::1"},
	{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp", taddr: "::1"},
	{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp", taddr: "::1"},
	{snet: "tcp", saddr: "[::]:0", tnet: "tcp", taddr: "127.0.0.1"},

	{snet: "tcp", saddr: ":0", tnet: "tcp4", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp4", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp4", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "[::]:0", tnet: "tcp6", taddr: "::1"},

	{snet: "tcp", saddr: ":0", tnet: "tcp6", taddr: "::1"},
	{snet: "tcp", saddr: "0.0.0.0:0", tnet: "tcp6", taddr: "::1"},
	{snet: "tcp", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp6", taddr: "::1"},
	{snet: "tcp", saddr: "[::]:0", tnet: "tcp4", taddr: "127.0.0.1"},

	{snet: "tcp", saddr: "127.0.0.1:0", tnet: "tcp", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "[::ffff:127.0.0.1]:0", tnet: "tcp", taddr: "127.0.0.1"},
	{snet: "tcp", saddr: "[::1]:0", tnet: "tcp", taddr: "::1"},

	{snet: "tcp4", saddr: ":0", tnet: "tcp4", taddr: "127.0.0.1"},
	{snet: "tcp4", saddr: "0.0.0.0:0", tnet: "tcp4", taddr: "127.0.0.1"},
	{snet: "tcp4", saddr: "[::ffff:0.0.0.0]:0", tnet: "tcp4", taddr: "127.0.0.1"},

	{snet: "tcp4", saddr: "127.0.0.1:0", tnet: "tcp4", taddr: "127.0.0.1"},

	{snet: "tcp6", saddr: ":0", tnet: "tcp6", taddr: "::1"},
	{snet: "tcp6", saddr: "[::]:0", tnet: "tcp6", taddr: "::1"},

	{snet: "tcp6", saddr: "[::1]:0", tnet: "tcp6", taddr: "::1"},
}

// TestTCPServer tests concurrent accept-read-write servers.
func TestTCPServer(t *testing.T) {
	const N = 3

	for i, tt := range tcpServerTests {
		t.Run(tt.snet+" "+tt.saddr+"<-"+tt.taddr, func(t *testing.T) {
			if !testableListenArgs(tt.snet, tt.saddr, tt.taddr) {
				t.Skip("not testable")
			}

			ln, err := Listen(tt.snet, tt.saddr)
			if err != nil {
				if perr := parseDialError(err); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}

			var lss []*localServer
			var tpchs []chan error
			defer func() {
				for _, ls := range lss {
					ls.teardown()
				}
			}()
			for i := 0; i < N; i++ {
				ls := (&streamListener{Listener: ln}).newLocalServer()
				lss = append(lss, ls)
				tpchs = append(tpchs, make(chan error, 1))
			}
			for i := 0; i < N; i++ {
				ch := tpchs[i]
				handler := func(ls *localServer, ln Listener) { ls.transponder(ln, ch) }
				if err := lss[i].buildup(handler); err != nil {
					t.Fatal(err)
				}
			}

			var trchs []chan error
			for i := 0; i < N; i++ {
				_, port, err := SplitHostPort(lss[i].Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				d := Dialer{Timeout: someTimeout}
				c, err := d.Dial(tt.tnet, JoinHostPort(tt.taddr, port))
				if err != nil {
					if perr := parseDialError(err); perr != nil {
						t.Error(perr)
					}
					t.Fatal(err)
				}
				defer c.Close()
				trchs = append(trchs, make(chan error, 1))
				go transceiver(c, []byte("TCP SERVER TEST"), trchs[i])
			}

			for _, ch := range trchs {
				for err := range ch {
					t.Errorf("#%d: %v", i, err)
				}
			}
			for _, ch := range tpchs {
				for err := range ch {
					t.Errorf("#%d: %v", i, err)
				}
			}
		})
	}
}

// TestUnixAndUnixpacketServer tests concurrent accept-read-write
// servers
func TestUnixAndUnixpacketServer(t *testing.T) {
	var unixAndUnixpacketServerTests = []struct {
		network, address string
	}{
		{"unix", testUnixAddr(t)},
		{"unix", "@nettest/go/unix"},

		{"unixpacket", testUnixAddr(t)},
		{"unixpacket", "@nettest/go/unixpacket"},
	}

	const N = 3

	for i, tt := range unixAndUnixpacketServerTests {
		if !testableListenArgs(tt.network, tt.address, "") {
			t.Logf("skipping %s test", tt.network+" "+tt.address)
			continue
		}

		ln, err := Listen(tt.network, tt.address)
		if err != nil {
			if perr := parseDialError(err); perr != nil {
				t.Error(perr)
			}
			t.Fatal(err)
		}

		var lss []*localServer
		var tpchs []chan error
		defer func() {
			for _, ls := range lss {
				ls.teardown()
			}
		}()
		for i := 0; i < N; i++ {
			ls := (&streamListener{Listener: ln}).newLocalServer()
			lss = append(lss, ls)
			tpchs = append(tpchs, make(chan error, 1))
		}
		for i := 0; i < N; i++ {
			ch := tpchs[i]
			handler := func(ls *localServer, ln Listener) { ls.transponder(ln, ch) }
			if err := lss[i].buildup(handler); err != nil {
				t.Fatal(err)
			}
		}

		var trchs []chan error
		for i := 0; i < N; i++ {
			d := Dialer{Timeout: someTimeout}
			c, err := d.Dial(lss[i].Listener.Addr().Network(), lss[i].Listener.Addr().String())
			if err != nil {
				if perr := parseDialError(err); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}

			if addr := c.LocalAddr(); addr != nil {
				t.Logf("connected %s->%s", addr, lss[i].Listener.Addr())
			}

			defer c.Close()
			trchs = append(trchs, make(chan error, 1))
			go transceiver(c, []byte("UNIX AND UNIXPACKET SERVER TEST"), trchs[i])
		}

		for _, ch := range trchs {
			for err := range ch {
				t.Errorf("#%d: %v", i, err)
			}
		}
		for _, ch := range tpchs {
			for err := range ch {
				t.Errorf("#%d: %v", i, err)
			}
		}
	}
}

var udpServerTests = []struct {
	snet, saddr string // server endpoint
	tnet, taddr string // target endpoint for client
	dial        bool   // test with Dial
}{
	{snet: "udp", saddr: ":0", tnet: "udp", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "0.0.0.0:0", tnet: "udp", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "[::ffff:0.0.0.0]:0", tnet: "udp", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "[::]:0", tnet: "udp", taddr: "::1"},

	{snet: "udp", saddr: ":0", tnet: "udp", taddr: "::1"},
	{snet: "udp", saddr: "0.0.0.0:0", tnet: "udp", taddr: "::1"},
	{snet: "udp", saddr: "[::ffff:0.0.0.0]:0", tnet: "udp", taddr: "::1"},
	{snet: "udp", saddr: "[::]:0", tnet: "udp", taddr: "127.0.0.1"},

	{snet: "udp", saddr: ":0", tnet: "udp4", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "0.0.0.0:0", tnet: "udp4", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "[::ffff:0.0.0.0]:0", tnet: "udp4", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "[::]:0", tnet: "udp6", taddr: "::1"},

	{snet: "udp", saddr: ":0", tnet: "udp6", taddr: "::1"},
	{snet: "udp", saddr: "0.0.0.0:0", tnet: "udp6", taddr: "::1"},
	{snet: "udp", saddr: "[::ffff:0.0.0.0]:0", tnet: "udp6", taddr: "::1"},
	{snet: "udp", saddr: "[::]:0", tnet: "udp4", taddr: "127.0.0.1"},

	{snet: "udp", saddr: "127.0.0.1:0", tnet: "udp", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "[::ffff:127.0.0.1]:0", tnet: "udp", taddr: "127.0.0.1"},
	{snet: "udp", saddr: "[::1]:0", tnet: "udp", taddr: "::1"},

	{snet: "udp4", saddr: ":0", tnet: "udp4", taddr: "127.0.0.1"},
	{snet: "udp4", saddr: "0.0.0.0:0", tnet: "udp4", taddr: "127.0.0.1"},
	{snet: "udp4", saddr: "[::ffff:0.0.0.0]:0", tnet: "udp4", taddr: "127.0.0.1"},

	{snet: "udp4", saddr: "127.0.0.1:0", tnet: "udp4", taddr: "127.0.0.1"},

	{snet: "udp6", saddr: ":0", tnet: "udp6", taddr: "::1"},
	{snet: "udp6", saddr: "[::]:0", tnet: "udp6", taddr: "::1"},

	{snet: "udp6", saddr: "[::1]:0", tnet: "udp6", taddr: "::1"},

	{snet: "udp", saddr: "127.0.0.1:0", tnet: "udp", taddr: "127.0.0.1", dial: true},

	{snet: "udp", saddr: "[::1]:0", tnet: "udp", taddr: "::1", dial: true},
}

func TestUDPServer(t *testing.T) {
	for i, tt := range udpServerTests {
		i, tt := i, tt
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if !testableListenArgs(tt.snet, tt.saddr, tt.taddr) {
				t.Skipf("skipping %s %s<-%s test", tt.snet, tt.saddr, tt.taddr)
			}
			t.Logf("%s %s<-%s", tt.snet, tt.saddr, tt.taddr)

			c1, err := ListenPacket(tt.snet, tt.saddr)
			if err != nil {
				if perr := parseDialError(err); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}

			ls := (&packetListener{PacketConn: c1}).newLocalServer()
			defer ls.teardown()
			tpch := make(chan error, 1)
			handler := func(ls *localPacketServer, c PacketConn) { packetTransponder(c, tpch) }
			if err := ls.buildup(handler); err != nil {
				t.Fatal(err)
			}

			trch := make(chan error, 1)
			_, port, err := SplitHostPort(ls.PacketConn.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			if tt.dial {
				d := Dialer{Timeout: someTimeout}
				c2, err := d.Dial(tt.tnet, JoinHostPort(tt.taddr, port))
				if err != nil {
					if perr := parseDialError(err); perr != nil {
						t.Error(perr)
					}
					t.Fatal(err)
				}
				defer c2.Close()
				go transceiver(c2, []byte("UDP SERVER TEST"), trch)
			} else {
				c2, err := ListenPacket(tt.tnet, JoinHostPort(tt.taddr, "0"))
				if err != nil {
					if perr := parseDialError(err); perr != nil {
						t.Error(perr)
					}
					t.Fatal(err)
				}
				defer c2.Close()
				dst, err := ResolveUDPAddr(tt.tnet, JoinHostPort(tt.taddr, port))
				if err != nil {
					t.Fatal(err)
				}
				go packetTransceiver(c2, []byte("UDP SERVER TEST"), dst, trch)
			}

			for trch != nil || tpch != nil {
				select {
				case err, ok := <-trch:
					if !ok {
						trch = nil
					}
					if err != nil {
						t.Errorf("client: %v", err)
					}
				case err, ok := <-tpch:
					if !ok {
						tpch = nil
					}
					if err != nil {
						t.Errorf("server: %v", err)
					}
				}
			}
		})
	}
}

func TestUnixgramServer(t *testing.T) {
	var unixgramServerTests = []struct {
		saddr string // server endpoint
		caddr string // client endpoint
		dial  bool   // test with Dial
	}{
		{saddr: testUnixAddr(t), caddr: testUnixAddr(t)},
		{saddr: testUnixAddr(t), caddr: testUnixAddr(t), dial: true},

		{saddr: "@nettest/go/unixgram/server", caddr: "@nettest/go/unixgram/client"},
	}

	for i, tt := range unixgramServerTests {
		i, tt := i, tt
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if !testableListenArgs("unixgram", tt.saddr, "") {
				t.Skipf("skipping unixgram %s<-%s test", tt.saddr, tt.caddr)
			}
			t.Logf("unixgram %s<-%s", tt.saddr, tt.caddr)

			c1, err := ListenPacket("unixgram", tt.saddr)
			if err != nil {
				if perr := parseDialError(err); perr != nil {
					t.Error(perr)
				}
				t.Fatal(err)
			}

			ls := (&packetListener{PacketConn: c1}).newLocalServer()
			defer ls.teardown()
			tpch := make(chan error, 1)
			handler := func(ls *localPacketServer, c PacketConn) { packetTransponder(c, tpch) }
			if err := ls.buildup(handler); err != nil {
				t.Fatal(err)
			}

			trch := make(chan error, 1)
			if tt.dial {
				d := Dialer{Timeout: someTimeout, LocalAddr: &UnixAddr{Net: "unixgram", Name: tt.caddr}}
				c2, err := d.Dial("unixgram", ls.PacketConn.LocalAddr().String())
				if err != nil {
					if perr := parseDialError(err); perr != nil {
						t.Error(perr)
					}
					t.Fatal(err)
				}
				defer os.Remove(c2.LocalAddr().String())
				defer c2.Close()
				go transceiver(c2, []byte(c2.LocalAddr().String()), trch)
			} else {
				c2, err := ListenPacket("unixgram", tt.caddr)
				if err != nil {
					if perr := parseDialError(err); perr != nil {
						t.Error(perr)
					}
					t.Fatal(err)
				}
				defer os.Remove(c2.LocalAddr().String())
				defer c2.Close()
				go packetTransceiver(c2, []byte("UNIXGRAM SERVER TEST"), ls.PacketConn.LocalAddr(), trch)
			}

			for trch != nil || tpch != nil {
				select {
				case err, ok := <-trch:
					if !ok {
						trch = nil
					}
					if err != nil {
						t.Errorf("client: %v", err)
					}
				case err, ok := <-tpch:
					if !ok {
						tpch = nil
					}
					if err != nil {
						t.Errorf("server: %v", err)
					}
				}
			}
		})
	}
}

"""



```