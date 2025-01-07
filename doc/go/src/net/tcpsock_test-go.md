Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Understanding and Context:**

The first line `// Copyright 2012 The Go Authors. All rights reserved.` immediately tells us this is part of the Go standard library. The path `go/src/net/tcpsock_test.go` confirms it's a test file specifically for TCP socket functionality within the `net` package. Knowing this context is crucial.

**2. High-Level Structure Identification:**

Quickly scanning the code, I notice the presence of `func Benchmark...`, `func Test...`, and helper functions like `benchmarkTCP` and `benchmarkTCPConcurrentReadWrite`. This signifies that the file contains benchmark tests and unit tests for TCP socket operations.

**3. Function-by-Function Analysis (and Hypothesis Generation):**

I'll go through each function and try to understand its purpose:

* **`BenchmarkTCP4OneShot`, `BenchmarkTCP4OneShotTimeout`, etc.:**  The names clearly indicate benchmark tests for TCP (IPv4 and IPv6), differentiated by "OneShot" (single connection), "Persistent" (reused connection), and "Timeout" (setting deadlines). This immediately suggests testing the performance of various TCP connection patterns.

* **`benchmarkTCP(b *testing.B, persistent, timeout bool, laddr string)`:** This is a helper function used by the benchmark tests. The parameters `persistent`, `timeout`, and `laddr` (local address) confirm the hypotheses about the different benchmark scenarios. I see it sets up a server and multiple clients, sending and receiving data.

* **`BenchmarkTCP4ConcurrentReadWrite`, `BenchmarkTCP6ConcurrentReadWrite`, `benchmarkTCPConcurrentReadWrite`:** These benchmark tests focus on concurrent read and write operations on the same TCP connection. The comment within `benchmarkTCPConcurrentReadWrite` explicitly states its purpose: stressing concurrent I/O, as used in `net/http` and `net/rpc`.

* **`type resolveTCPAddrTest`, `var resolveTCPAddrTests`, `func TestResolveTCPAddr`:**  The naming and structure strongly suggest tests for the `ResolveTCPAddr` function. The `resolveTCPAddrTest` struct likely defines test cases with input addresses, expected output `TCPAddr` structs, and potential errors. The loop in `TestResolveTCPAddr` iterates through these test cases.

* **`var tcpListenerNameTests`, `func TestTCPListenerName`:**  Similar to the previous set, these test the behavior of `ListenTCP` and verify that the returned listener has a valid address with a non-zero port.

* **`var ipv6LinkLocalUnicastTCPTests`, `func TestIPv6LinkLocalUnicastTCP`:** This focuses on testing IPv6 link-local unicast addresses. The test attempts to listen on and dial to such addresses, checking for correct address and zone identifier handling.

* **`func TestTCPConcurrentAccept`:**  This test likely aims to verify the robustness of `Accept` when multiple clients try to connect concurrently. It spawns multiple goroutines attempting to accept connections.

* **`func TestTCPReadWriteAllocs`:** The name suggests testing memory allocations during read and write operations. The `testing.AllocsPerRun` function confirms this. The checks for `allocs > 0` imply the goal is to have zero allocations for basic read/write.

* **`func TestTCPStress`:** This test likely simulates a high-load scenario with multiple concurrent connections sending and receiving messages.

* **`func TestTCPBig`:** The comment and the use of a large buffer (`int(1 << 30) * 5`) indicate testing the handling of very large reads and writes, potentially exceeding 32-bit limits on 64-bit systems. The `-tcpbig` flag hints at making it an optional, potentially time-consuming test.

* **`func TestCopyPipeIntoTCP`:** This test checks the interaction between a pipe and a TCP connection using `io.Copy`. The comment about Windows `TransmitFile` provides a specific detail about a potential issue being tested.

* **`func BenchmarkSetReadDeadline`:** This is a benchmark test for the `SetReadDeadline` method.

* **`func TestDialTCPDefaultKeepAlive`:** This test verifies the default keep-alive settings when using `DialTCP`. The `testHookSetKeepAlive` mechanism suggests a way to intercept and verify the configuration.

* **`func TestTCPListenAfterClose`:** The comment clearly states it's a regression test for a specific issue (50216) related to calling `Accept` after closing a listener.

**4. Identifying Core Functionality:**

Based on the tests, I can deduce the core functionalities being tested:

* **Basic TCP Connection Establishment:**  `Listen`, `Accept`, `Dial`, `DialTCP`.
* **Data Transfer:** `Read`, `Write`, `io.ReadFull`, `io.Copy`.
* **Address Resolution:** `ResolveTCPAddr`.
* **Connection Options:** `SetDeadline`, keep-alive settings.
* **Concurrency:** Handling multiple concurrent connections and read/write operations.
* **Error Handling:** Checking for expected errors.
* **Performance:** Benchmarking various connection and I/O patterns.
* **Specific Scenarios:** IPv6 link-local addresses, large data transfers, interactions with pipes.

**5. Code Examples and Explanations (if requested):**

If the prompt asked for examples, I would pick key functions like `Listen`, `Accept`, and `Dial` and provide simple code snippets demonstrating their usage.

**6. Identifying Potential Pitfalls:**

While reviewing the code, I'd pay attention to patterns that might lead to errors for users. For example, not closing connections properly is a common mistake, which the tests implicitly demonstrate the importance of by using `defer c.Close()`. The benchmarks also highlight potential performance differences between persistent and one-shot connections.

**7. Command-Line Arguments (if applicable):**

The `-tcpbig` flag is the only explicit command-line argument handling I see.

**Self-Correction/Refinement:**

Initially, I might broadly categorize all tests as just "testing TCP."  However, going through each function more carefully allows me to identify the specific aspects of TCP functionality being targeted by each test. For instance, separating out address resolution tests from basic connection tests provides a more granular understanding. Recognizing the use of benchmark tests and their different scenarios (one-shot vs. persistent, with/without timeout) is also a refinement of the initial understanding.
这个go语言实现的文件 `go/src/net/tcpsock_test.go` 的主要功能是**测试 `net` 包中关于 TCP socket 的相关功能**。它包含了单元测试和性能基准测试，用来验证 TCP 连接的建立、数据传输、地址解析以及其他相关操作的正确性和性能。

下面列举一下它的具体功能：

**1. TCP 连接的基准测试 (Benchmarks):**

* **`BenchmarkTCP4OneShot`, `BenchmarkTCP4OneShotTimeout`, `BenchmarkTCP4Persistent`, `BenchmarkTCP4PersistentTimeout`:**  这些函数测试 IPv4 TCP 连接的性能。
    * `OneShot`: 每次请求都建立新的连接。
    * `Persistent`: 重用已建立的连接进行多次请求。
    * `Timeout`:  在连接上设置了超时时间。
* **`BenchmarkTCP6OneShot`, `BenchmarkTCP6OneShotTimeout`, `BenchmarkTCP6Persistent`, `BenchmarkTCP6PersistentTimeout`:**  与上面的类似，但测试的是 IPv6 TCP 连接的性能。

**2. 并发读写基准测试:**

* **`BenchmarkTCP4ConcurrentReadWrite`, `BenchmarkTCP6ConcurrentReadWrite`:**  测试在同一个 TCP 连接上进行并发读写的性能，模拟 `net/http` 和 `net/rpc` 等包的使用场景。

**3. TCP 地址解析测试:**

* **`TestResolveTCPAddr`:** 测试 `ResolveTCPAddr` 函数，该函数用于将网络地址字符串解析为 `TCPAddr` 结构体。

**4. TCP 监听器名称测试:**

* **`TestTCPListenerName`:** 测试 `ListenTCP` 函数创建的监听器是否具有正确的地址和非零端口号。

**5. IPv6 本地链路单播地址测试:**

* **`TestIPv6LinkLocalUnicastTCP`:** 测试使用 IPv6 本地链路单播地址进行 TCP 连接的情况，包括地址解析和连接建立。

**6. TCP 并发 Accept 测试:**

* **`TestTCPConcurrentAccept`:** 测试在多个客户端同时尝试连接时，服务器端 `Accept` 操作的并发安全性。

**7. TCP 读写分配测试:**

* **`TestTCPReadWriteAllocs`:** 测试 TCP 连接的读写操作是否会产生不必要的内存分配，目标是零分配。

**8. TCP 压力测试:**

* **`TestTCPStress`:**  进行高并发的 TCP 连接和数据传输测试，以验证其稳定性和可靠性。

**9. 大数据包 TCP 测试:**

* **`TestTCPBig`:** 测试 TCP 连接是否能处理大于 32 位（在 64 位系统上）或最大整数（在 32 位系统上）的读写操作。

**10. 将管道数据拷贝到 TCP 连接的测试:**

* **`TestCopyPipeIntoTCP`:** 测试使用 `io.Copy` 将管道中的数据写入 TCP 连接的情况。

**11. 设置读取截止时间的基准测试:**

* **`BenchmarkSetReadDeadline`:** 测试 `SetReadDeadline` 方法的性能。

**12. DialTCP 默认 Keep-Alive 测试:**

* **`TestDialTCPDefaultKeepAlive`:** 测试使用 `DialTCP` 建立连接时，默认的 TCP Keep-Alive 设置是否正确。

**13. 关闭监听器后再次监听的测试:**

* **`TestTCPListenAfterClose`:**  测试在 `Close` 一个 `Listener` 后，再次调用 `Accept` 是否会正确返回错误。

**它是什么go语言功能的实现 (推理和代码示例):**

这个文件主要测试的是 Go 语言 `net` 包中关于 TCP 协议的网络编程功能。它涵盖了创建 TCP 服务端和客户端，进行数据传输，处理连接超时和并发等核心概念。

**Go 代码示例 (基于 `BenchmarkTCP` 函数推理):**

假设我们要测试一个简单的 TCP 回显服务器的性能，每次连接发送和接收一条消息。

```go
package main

import (
	"io"
	"log"
	"net"
	"runtime"
	"testing"
	"time"
)

func benchmarkEchoTCP(b *testing.B) {
	laddr := "127.0.0.1:0"
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				log.Println(err)
				return
			}
		}
	}()

	addr := ln.Addr().String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			b.Fatal(err)
		}
		msg := make([]byte, 512)
		// 填充消息内容...
		_, err = conn.Write(msg)
		if err != nil {
			b.Fatal(err)
		}
		_, err = io.ReadFull(conn, msg) // 读取回显
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

func BenchmarkEcho(b *testing.B) {
	benchmarkEchoTCP(b)
}

func main() {
	// 运行基准测试，可以加上 -bench 参数
	testing.Main(nil, []testing.InternalTest{}, []testing.InternalBenchmark{
		{"BenchmarkEcho", benchmarkEchoTCP},
	})
}
```

**假设的输入与输出 (基于 `TestResolveTCPAddr` 函数推理):**

假设 `TestResolveTCPAddr` 函数的其中一个测试用例是：

* **输入:** `network = "tcp"`, `litAddrOrName = "127.0.0.1:80"`
* **期望的输出:** `addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}`, `err = nil`

测试代码会调用 `net.ResolveTCPAddr("tcp", "127.0.0.1:80")`，如果返回的 `TCPAddr` 结构体的 IP 地址和端口号与期望的相同，且 `error` 为 `nil`，则该测试用例通过。

**命令行参数的具体处理:**

在这个代码片段中，没有看到直接处理命令行参数的逻辑。这些测试通常是通过 `go test` 命令来运行的，Go 的测试框架会处理相关的参数，例如 `-bench` 用于运行性能基准测试，`-v` 用于显示详细输出等。

**使用者易犯错的点 (基于代码推理):**

* **忘记关闭连接:** 在基准测试和单元测试中，都使用了 `defer conn.Close()` 或 `defer ln.Close()` 来确保连接在使用后被关闭。忘记关闭连接会导致资源泄漏。

    ```go
    // 错误示例
    conn, err := net.Dial("tcp", "example.com:80")
    if err != nil {
        log.Fatal(err)
    }
    // 忘记关闭 conn

    // 正确示例
    conn, err := net.Dial("tcp", "example.com:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    ```

* **没有正确处理 `Accept` 返回的错误:**  在 `TestTCPConcurrentAccept` 和 `BenchmarkTCP` 中，都检查了 `ln.Accept()` 返回的错误。如果服务器没有正确处理 `Accept` 错误（例如，监听端口被占用），可能会导致程序崩溃或行为异常。

    ```go
    ln, err := net.Listen("tcp", ":8080")
    if err != nil {
        log.Fatal(err)
    }
    defer ln.Close()

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println("Accept error:", err) // 需要记录或处理错误
            continue
        }
        go handleConnection(conn)
    }
    ```

总而言之，`go/src/net/tcpsock_test.go` 是一个至关重要的测试文件，它确保了 Go 语言 `net` 包中 TCP socket 相关功能的正确性和性能，并为开发者提供了使用这些功能的参考示例。

Prompt: 
```
这是路径为go/src/net/tcpsock_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"context"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

func BenchmarkTCP4OneShot(b *testing.B) {
	benchmarkTCP(b, false, false, "127.0.0.1:0")
}

func BenchmarkTCP4OneShotTimeout(b *testing.B) {
	benchmarkTCP(b, false, true, "127.0.0.1:0")
}

func BenchmarkTCP4Persistent(b *testing.B) {
	benchmarkTCP(b, true, false, "127.0.0.1:0")
}

func BenchmarkTCP4PersistentTimeout(b *testing.B) {
	benchmarkTCP(b, true, true, "127.0.0.1:0")
}

func BenchmarkTCP6OneShot(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkTCP(b, false, false, "[::1]:0")
}

func BenchmarkTCP6OneShotTimeout(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkTCP(b, false, true, "[::1]:0")
}

func BenchmarkTCP6Persistent(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkTCP(b, true, false, "[::1]:0")
}

func BenchmarkTCP6PersistentTimeout(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkTCP(b, true, true, "[::1]:0")
}

func benchmarkTCP(b *testing.B, persistent, timeout bool, laddr string) {
	testHookUninstaller.Do(uninstallTestHooks)

	const msgLen = 512
	conns := b.N
	numConcurrent := runtime.GOMAXPROCS(-1) * 2
	msgs := 1
	if persistent {
		conns = numConcurrent
		msgs = b.N / conns
		if msgs == 0 {
			msgs = 1
		}
		if conns > b.N {
			conns = b.N
		}
	}
	sendMsg := func(c Conn, buf []byte) bool {
		n, err := c.Write(buf)
		if n != len(buf) || err != nil {
			b.Log(err)
			return false
		}
		return true
	}
	recvMsg := func(c Conn, buf []byte) bool {
		for read := 0; read != len(buf); {
			n, err := c.Read(buf)
			read += n
			if err != nil {
				b.Log(err)
				return false
			}
		}
		return true
	}
	ln, err := Listen("tcp", laddr)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	serverSem := make(chan bool, numConcurrent)
	// Acceptor.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			serverSem <- true
			// Server connection.
			go func(c Conn) {
				defer func() {
					c.Close()
					<-serverSem
				}()
				if timeout {
					c.SetDeadline(time.Now().Add(time.Hour)) // Not intended to fire.
				}
				var buf [msgLen]byte
				for m := 0; m < msgs; m++ {
					if !recvMsg(c, buf[:]) || !sendMsg(c, buf[:]) {
						break
					}
				}
			}(c)
		}
	}()
	clientSem := make(chan bool, numConcurrent)
	for i := 0; i < conns; i++ {
		clientSem <- true
		// Client connection.
		go func() {
			defer func() {
				<-clientSem
			}()
			c, err := Dial("tcp", ln.Addr().String())
			if err != nil {
				b.Log(err)
				return
			}
			defer c.Close()
			if timeout {
				c.SetDeadline(time.Now().Add(time.Hour)) // Not intended to fire.
			}
			var buf [msgLen]byte
			for m := 0; m < msgs; m++ {
				if !sendMsg(c, buf[:]) || !recvMsg(c, buf[:]) {
					break
				}
			}
		}()
	}
	for i := 0; i < numConcurrent; i++ {
		clientSem <- true
		serverSem <- true
	}
}

func BenchmarkTCP4ConcurrentReadWrite(b *testing.B) {
	benchmarkTCPConcurrentReadWrite(b, "127.0.0.1:0")
}

func BenchmarkTCP6ConcurrentReadWrite(b *testing.B) {
	if !supportsIPv6() {
		b.Skip("ipv6 is not supported")
	}
	benchmarkTCPConcurrentReadWrite(b, "[::1]:0")
}

func benchmarkTCPConcurrentReadWrite(b *testing.B, laddr string) {
	testHookUninstaller.Do(uninstallTestHooks)

	// The benchmark creates GOMAXPROCS client/server pairs.
	// Each pair creates 4 goroutines: client reader/writer and server reader/writer.
	// The benchmark stresses concurrent reading and writing to the same connection.
	// Such pattern is used in net/http and net/rpc.

	b.StopTimer()

	P := runtime.GOMAXPROCS(0)
	N := b.N / P
	W := 1000

	// Setup P client/server connections.
	clients := make([]Conn, P)
	servers := make([]Conn, P)
	ln, err := Listen("tcp", laddr)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	done := make(chan bool)
	go func() {
		for p := 0; p < P; p++ {
			s, err := ln.Accept()
			if err != nil {
				b.Error(err)
				return
			}
			servers[p] = s
		}
		done <- true
	}()
	for p := 0; p < P; p++ {
		c, err := Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		clients[p] = c
	}
	<-done

	b.StartTimer()

	var wg sync.WaitGroup
	wg.Add(4 * P)
	for p := 0; p < P; p++ {
		// Client writer.
		go func(c Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				v := byte(i)
				for w := 0; w < W; w++ {
					v *= v
				}
				buf[0] = v
				_, err := c.Write(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
			}
		}(clients[p])

		// Pipe between server reader and server writer.
		pipe := make(chan byte, 128)

		// Server reader.
		go func(s Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				_, err := s.Read(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
				pipe <- buf[0]
			}
		}(servers[p])

		// Server writer.
		go func(s Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				v := <-pipe
				for w := 0; w < W; w++ {
					v *= v
				}
				buf[0] = v
				_, err := s.Write(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
			}
			s.Close()
		}(servers[p])

		// Client reader.
		go func(c Conn) {
			defer wg.Done()
			var buf [1]byte
			for i := 0; i < N; i++ {
				_, err := c.Read(buf[:])
				if err != nil {
					b.Error(err)
					return
				}
			}
			c.Close()
		}(clients[p])
	}
	wg.Wait()
}

type resolveTCPAddrTest struct {
	network       string
	litAddrOrName string
	addr          *TCPAddr
	err           error
}

var resolveTCPAddrTests = []resolveTCPAddrTest{
	{"tcp", "127.0.0.1:0", &TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 0}, nil},
	{"tcp4", "127.0.0.1:65535", &TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 65535}, nil},

	{"tcp", "[::1]:0", &TCPAddr{IP: ParseIP("::1"), Port: 0}, nil},
	{"tcp6", "[::1]:65535", &TCPAddr{IP: ParseIP("::1"), Port: 65535}, nil},

	{"tcp", "[::1%en0]:1", &TCPAddr{IP: ParseIP("::1"), Port: 1, Zone: "en0"}, nil},
	{"tcp6", "[::1%911]:2", &TCPAddr{IP: ParseIP("::1"), Port: 2, Zone: "911"}, nil},

	{"", "127.0.0.1:0", &TCPAddr{IP: IPv4(127, 0, 0, 1), Port: 0}, nil}, // Go 1.0 behavior
	{"", "[::1]:0", &TCPAddr{IP: ParseIP("::1"), Port: 0}, nil},         // Go 1.0 behavior

	{"tcp", ":12345", &TCPAddr{Port: 12345}, nil},

	{"http", "127.0.0.1:0", nil, UnknownNetworkError("http")},

	{"tcp", "127.0.0.1:http", &TCPAddr{IP: ParseIP("127.0.0.1"), Port: 80}, nil},
	{"tcp", "[::ffff:127.0.0.1]:http", &TCPAddr{IP: ParseIP("::ffff:127.0.0.1"), Port: 80}, nil},
	{"tcp", "[2001:db8::1]:http", &TCPAddr{IP: ParseIP("2001:db8::1"), Port: 80}, nil},
	{"tcp4", "127.0.0.1:http", &TCPAddr{IP: ParseIP("127.0.0.1"), Port: 80}, nil},
	{"tcp4", "[::ffff:127.0.0.1]:http", &TCPAddr{IP: ParseIP("127.0.0.1"), Port: 80}, nil},
	{"tcp6", "[2001:db8::1]:http", &TCPAddr{IP: ParseIP("2001:db8::1"), Port: 80}, nil},

	{"tcp4", "[2001:db8::1]:http", nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: "2001:db8::1"}},
	{"tcp6", "127.0.0.1:http", nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: "127.0.0.1"}},
	{"tcp6", "[::ffff:127.0.0.1]:http", nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: "::ffff:127.0.0.1"}},
}

func TestResolveTCPAddr(t *testing.T) {
	origTestHookLookupIP := testHookLookupIP
	defer func() { testHookLookupIP = origTestHookLookupIP }()
	testHookLookupIP = lookupLocalhost

	for _, tt := range resolveTCPAddrTests {
		addr, err := ResolveTCPAddr(tt.network, tt.litAddrOrName)
		if !reflect.DeepEqual(addr, tt.addr) || !reflect.DeepEqual(err, tt.err) {
			t.Errorf("ResolveTCPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr, err, tt.addr, tt.err)
			continue
		}
		if err == nil {
			addr2, err := ResolveTCPAddr(addr.Network(), addr.String())
			if !reflect.DeepEqual(addr2, tt.addr) || err != tt.err {
				t.Errorf("(%q, %q): ResolveTCPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr.Network(), addr.String(), addr2, err, tt.addr, tt.err)
			}
		}
	}
}

var tcpListenerNameTests = []struct {
	net   string
	laddr *TCPAddr
}{
	{"tcp4", &TCPAddr{IP: IPv4(127, 0, 0, 1)}},
	{"tcp4", &TCPAddr{}},
	{"tcp4", nil},
}

func TestTCPListenerName(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	for _, tt := range tcpListenerNameTests {
		ln, err := ListenTCP(tt.net, tt.laddr)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		la := ln.Addr()
		if a, ok := la.(*TCPAddr); !ok || a.Port == 0 {
			t.Fatalf("got %v; expected a proper address with non-zero port number", la)
		}
	}
}

func TestIPv6LinkLocalUnicastTCP(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	if !supportsIPv6() {
		t.Skip("IPv6 is not supported")
	}

	for i, tt := range ipv6LinkLocalUnicastTCPTests {
		ln, err := Listen(tt.network, tt.address)
		if err != nil {
			// It might return "LookupHost returned no
			// suitable address" error on some platforms.
			t.Log(err)
			continue
		}
		ls := (&streamListener{Listener: ln}).newLocalServer()
		defer ls.teardown()
		ch := make(chan error, 1)
		handler := func(ls *localServer, ln Listener) { ls.transponder(ln, ch) }
		if err := ls.buildup(handler); err != nil {
			t.Fatal(err)
		}
		if la, ok := ln.Addr().(*TCPAddr); !ok || !tt.nameLookup && la.Zone == "" {
			t.Fatalf("got %v; expected a proper address with zone identifier", la)
		}

		c, err := Dial(tt.network, ls.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if la, ok := c.LocalAddr().(*TCPAddr); !ok || !tt.nameLookup && la.Zone == "" {
			t.Fatalf("got %v; expected a proper address with zone identifier", la)
		}
		if ra, ok := c.RemoteAddr().(*TCPAddr); !ok || !tt.nameLookup && ra.Zone == "" {
			t.Fatalf("got %v; expected a proper address with zone identifier", ra)
		}

		if _, err := c.Write([]byte("TCP OVER IPV6 LINKLOCAL TEST")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 32)
		if _, err := c.Read(b); err != nil {
			t.Fatal(err)
		}

		for err := range ch {
			t.Errorf("#%d: %v", i, err)
		}
	}
}

func TestTCPConcurrentAccept(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	ln, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					break
				}
				c.Close()
			}
			wg.Done()
		}()
	}
	attempts := 10 * N
	fails := 0
	d := &Dialer{Timeout: 200 * time.Millisecond}
	for i := 0; i < attempts; i++ {
		c, err := d.Dial("tcp", ln.Addr().String())
		if err != nil {
			fails++
		} else {
			c.Close()
		}
	}
	ln.Close()
	wg.Wait()
	if fails > attempts/9 { // see issues 7400 and 7541
		t.Fatalf("too many Dial failed: %v", fails)
	}
	if fails > 0 {
		t.Logf("# of failed Dials: %v", fails)
	}
}

func TestTCPReadWriteAllocs(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		// The implementation of asynchronous cancelable
		// I/O on Plan 9 allocates memory.
		// See net/fd_io_plan9.go.
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	ln, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var server Conn
	errc := make(chan error, 1)
	go func() {
		var err error
		server, err = ln.Accept()
		errc <- err
	}()
	client, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	var buf [128]byte
	allocs := testing.AllocsPerRun(1000, func() {
		_, err := server.Write(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadFull(client, buf[:])
		if err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 0 {
		t.Fatalf("got %v; want 0", allocs)
	}

	var bufwrt [128]byte
	ch := make(chan bool)
	defer close(ch)
	go func() {
		for <-ch {
			_, err := server.Write(bufwrt[:])
			errc <- err
		}
	}()
	allocs = testing.AllocsPerRun(1000, func() {
		ch <- true
		if _, err = io.ReadFull(client, buf[:]); err != nil {
			t.Fatal(err)
		}
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 0 {
		t.Fatalf("got %v; want 0", allocs)
	}
}

func TestTCPStress(t *testing.T) {
	const conns = 2
	const msgLen = 512
	msgs := int(1e4)
	if testing.Short() {
		msgs = 1e2
	}

	sendMsg := func(c Conn, buf []byte) bool {
		n, err := c.Write(buf)
		if n != len(buf) || err != nil {
			t.Log(err)
			return false
		}
		return true
	}
	recvMsg := func(c Conn, buf []byte) bool {
		for read := 0; read != len(buf); {
			n, err := c.Read(buf)
			read += n
			if err != nil {
				t.Log(err)
				return false
			}
		}
		return true
	}

	ln, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan bool)
	// Acceptor.
	go func() {
		defer func() {
			done <- true
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			// Server connection.
			go func(c Conn) {
				defer c.Close()
				var buf [msgLen]byte
				for m := 0; m < msgs; m++ {
					if !recvMsg(c, buf[:]) || !sendMsg(c, buf[:]) {
						break
					}
				}
			}(c)
		}
	}()
	for i := 0; i < conns; i++ {
		// Client connection.
		go func() {
			defer func() {
				done <- true
			}()
			c, err := Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Log(err)
				return
			}
			defer c.Close()
			var buf [msgLen]byte
			for m := 0; m < msgs; m++ {
				if !sendMsg(c, buf[:]) || !recvMsg(c, buf[:]) {
					break
				}
			}
		}()
	}
	for i := 0; i < conns; i++ {
		<-done
	}
	ln.Close()
	<-done
}

// Test that >32-bit reads work on 64-bit systems.
// On 32-bit systems this tests that maxint reads work.
func TestTCPBig(t *testing.T) {
	if !*testTCPBig {
		t.Skip("test disabled; use -tcpbig to enable")
	}

	for _, writev := range []bool{false, true} {
		t.Run(fmt.Sprintf("writev=%v", writev), func(t *testing.T) {
			ln := newLocalListener(t, "tcp")
			defer ln.Close()

			x := int(1 << 30)
			x = x*5 + 1<<20 // just over 5 GB on 64-bit, just over 1GB on 32-bit
			done := make(chan int)
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					t.Error(err)
					return
				}
				buf := make([]byte, x)
				var n int
				if writev {
					var n64 int64
					n64, err = (&Buffers{buf}).WriteTo(c)
					n = int(n64)
				} else {
					n, err = c.Write(buf)
				}
				if n != len(buf) || err != nil {
					t.Errorf("Write(buf) = %d, %v, want %d, nil", n, err, x)
				}
				c.Close()
			}()

			c, err := Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, x)
			n, err := io.ReadFull(c, buf)
			if n != len(buf) || err != nil {
				t.Errorf("Read(buf) = %d, %v, want %d, nil", n, err, x)
			}
			c.Close()
			<-done
		})
	}
}

func TestCopyPipeIntoTCP(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skipf("skipping: os.Pipe not supported on %s", runtime.GOOS)
	}

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	errc := make(chan error, 1)
	defer func() {
		if err := <-errc; err != nil {
			t.Error(err)
		}
	}()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()

		buf := make([]byte, 100)
		n, err := io.ReadFull(c, buf)
		if err != io.ErrUnexpectedEOF || n != 2 {
			errc <- fmt.Errorf("got err=%q n=%v; want err=%q n=2", err, n, io.ErrUnexpectedEOF)
			return
		}

		errc <- nil
	}()

	c, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	errc2 := make(chan error, 1)
	defer func() {
		if err := <-errc2; err != nil {
			t.Error(err)
		}
	}()

	defer w.Close()

	go func() {
		_, err := io.Copy(c, r)
		errc2 <- err
	}()

	// Split write into 2 packets. That makes Windows TransmitFile
	// drop second packet.
	packet := make([]byte, 1)
	_, err = w.Write(packet)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_, err = w.Write(packet)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSetReadDeadline(b *testing.B) {
	ln := newLocalListener(b, "tcp")
	defer ln.Close()
	var serv Conn
	done := make(chan error)
	go func() {
		var err error
		serv, err = ln.Accept()
		done <- err
	}()
	c, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	if err := <-done; err != nil {
		b.Fatal(err)
	}
	defer serv.Close()
	c.SetWriteDeadline(time.Now().Add(2 * time.Hour))
	deadline := time.Now().Add(time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.SetReadDeadline(deadline)
		deadline = deadline.Add(1)
	}
}

func TestDialTCPDefaultKeepAlive(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	got := time.Duration(-1)
	testHookSetKeepAlive = func(cfg KeepAliveConfig) { got = cfg.Idle }
	defer func() { testHookSetKeepAlive = func(KeepAliveConfig) {} }()

	c, err := DialTCP("tcp", nil, ln.Addr().(*TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if got != 0 {
		t.Errorf("got keepalive %v; want %v", got, defaultTCPKeepAliveIdle)
	}
}

func TestTCPListenAfterClose(t *testing.T) {
	// Regression test for https://go.dev/issue/50216:
	// after calling Close on a Listener, the fake net implementation would
	// erroneously Accept a connection dialed before the call to Close.

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	d := &Dialer{}
	for n := 2; n > 0; n-- {
		wg.Add(1)
		go func() {
			defer wg.Done()

			c, err := d.DialContext(ctx, ln.Addr().Network(), ln.Addr().String())
			if err == nil {
				<-ctx.Done()
				c.Close()
			}
		}()
	}

	c, err := ln.Accept()
	if err == nil {
		c.Close()
	} else {
		t.Error(err)
	}
	time.Sleep(10 * time.Millisecond)
	cancel()
	wg.Wait()
	ln.Close()

	c, err = ln.Accept()
	if !errors.Is(err, ErrClosed) {
		if err == nil {
			c.Close()
		}
		t.Errorf("after l.Close(), l.Accept() = _, %v\nwant %v", err, ErrClosed)
	}
}

"""



```