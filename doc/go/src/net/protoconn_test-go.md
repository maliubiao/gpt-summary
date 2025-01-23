Response:
Let's break down the thought process for analyzing the Go code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `go/src/net/protoconn_test.go` immediately tells us this is part of the standard Go library's `net` package and is specifically for *testing* connection-related functionalities. The `_test.go` suffix is a strong indicator of testing.
* **Copyright and License:** Standard Go copyright and BSD license information. Not directly relevant to the functionality being tested but good to note.
* **Package Declaration:** `package net` confirms the scope.
* **Imports:**  `internal/testenv`, `os`, `runtime`, `testing`, `time`. These provide clues about the types of tests being performed. `testenv` suggests platform-specific testing or checks, `os` indicates interaction with the operating system, `runtime` for OS checks, `testing` for the test framework itself, and `time` for dealing with timeouts and deadlines.
* **Comment about full stack tests:**  This is a very important clue!  It explicitly states that the *core* IP connection tests have moved to other packages (`golang.org/x/net/ipv4`, etc.). This means the current file is likely focused on testing the *specific methods* of the connection types themselves, not the entire network stack.

**2. Analyzing Individual Test Functions:**

The code is structured as a series of test functions, each named `Test<ConnectionType>SpecificMethods`. This pattern is a standard Go testing convention. Let's go through each one:

* **`TestTCPListenerSpecificMethods`:**
    * **`runtime.GOOS` check:** Skips the test on Plan 9. This highlights platform-specific considerations.
    * **`ResolveTCPAddr`, `ListenTCP`:** Creates a TCP listener. The ":0" port means it will bind to an available port.
    * **`ln.Addr()`:** Checks getting the listener's address.
    * **`mustSetDeadline`:**  Sets a very short deadline (30 nanoseconds) and checks behavior when the deadline expires during `Accept` and `AcceptTCP`. This tests timeout functionality.
    * **`ln.File()`:** Tests getting the underlying file descriptor.

* **`TestTCPConnSpecificMethods`:**
    * Creates a listener (`ListenTCP`) and a client connection (`DialTCP`).
    * **Focus on specific TCP connection methods:** `SetKeepAlive`, `SetKeepAlivePeriod`, `SetLinger`, `SetNoDelay`, `LocalAddr`, `RemoteAddr`, `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`. This confirms the initial hypothesis about testing specific methods.
    * Simple read and write to verify basic connection functionality.

* **`TestUDPConnSpecificMethods`:**
    * Similar pattern to TCP: create a UDP connection (`ListenUDP`).
    * Tests UDP-specific methods: `RemoteAddr` (even though UDP is connectionless), `SetReadBuffer`, `SetWriteBuffer`, `WriteToUDP`, `ReadFromUDP`, `WriteMsgUDP`, `ReadMsgUDP`.
    * Tests `File()` and error handling with `recover()` for potentially nil address scenarios in `WriteToUDP` and `WriteMsgUDP`.

* **`TestIPConnSpecificMethods`:**
    * `testableNetwork("ip4")`:  Checks if IP networking is supported.
    * `ListenIP`: Creates a raw IP socket. The "ip4:icmp" indicates listening for ICMP packets.
    * Checks for `testenv.SyscallIsNotSupported` indicating permission issues (common when dealing with raw sockets).
    * Tests methods: `LocalAddr`, `RemoteAddr`, deadlines, read/write buffer sizes, `File()`, and error handling for nil addresses in `WriteToIP` and `WriteMsgIP`.

* **`TestUnixListenerSpecificMethods`:**
    * `testableNetwork("unix")`: Checks for Unix domain socket support.
    * `testUnixAddr`:  A helper function (not shown but likely generates a unique temporary file path for the socket).
    * `ResolveUnixAddr`, `ListenUnix`: Creates a Unix domain socket listener.
    * Similar deadline and `Accept`/`AcceptUnix` testing as `TestTCPListenerSpecificMethods`.

* **`TestUnixConnSpecificMethods`:**
    * `testableNetwork("unixgram")`: Checks for Unix datagram socket support.
    * Creates multiple Unix domain socket addresses and connections using `DialUnix` and `ListenUnixgram`.
    * Tests Unix-specific methods: `WriteMsgUnix`, `ReadMsgUnix`, `WriteToUnix`, `ReadFromUnix`.
    * Tests `File()` and error handling for nil addresses.

**3. Synthesizing the Functionality:**

By looking at the individual tests, the overall functionality becomes clear:  This file tests the *specific methods* provided by the Go `net` package for different connection types (TCP, UDP, IP, Unix sockets). It's not testing the underlying network stack behavior in depth but rather verifying that the Go API for managing these connections works as expected.

**4. Inferring Go Language Features:**

The code heavily utilizes:

* **Interfaces:**  The `Listener` and `Conn` interfaces are central to the `net` package. The tests operate on concrete types like `TCPListener`, `TCPConn`, etc., but these implement the generic interfaces.
* **Error Handling:**  Extensive use of `if err != nil` for checking and handling errors.
* **Timeouts and Deadlines:**  Demonstrated through `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`.
* **File Descriptors:**  The `File()` method exposes the underlying OS file descriptor.
* **Goroutines and Channels (in `TestTCPConnSpecificMethods`):** Although basic, the setup with `localServer` and a channel hints at potential concurrency aspects, though this specific snippet is not deeply testing concurrency.
* **Platform-Specific Logic:** The `runtime.GOOS` checks demonstrate handling variations between operating systems.
* **Testing Framework:** The `testing` package is used to structure and run the tests.

**5. Predicting Common Mistakes:**

Based on the tested methods, potential mistakes include:

* **Incorrectly setting or interpreting deadlines.**
* **Not handling errors from network operations.**
* **Misunderstanding the behavior of `SetKeepAlive`, `SetLinger`, `SetNoDelay`.**
* **Forgetting to close connections or listeners, leading to resource leaks.**
* **Providing invalid addresses to connection functions.**

This detailed breakdown, going from the high-level purpose to individual test cases and then synthesizing the information, allows for a comprehensive understanding of the code's functionality.
这段Go语言代码文件 `protoconn_test.go` 的主要功能是 **测试 `net` 包中不同类型网络连接（connection）的特定方法 (Specific Methods)。** 它并没有实现新的网络功能，而是对已有的网络连接类型（如 TCP、UDP、IP 和 Unix 域套接字）进行单元测试，确保这些连接类型提供的特定方法能够正常工作。

**具体功能列表:**

1. **测试 `TCPListener` 的特定方法:**
   - `Addr()`: 获取监听器的网络地址。
   - `SetDeadline()`: 设置监听器的超时时间。
   - `Accept()`: 接受一个新的通用连接。
   - `AcceptTCP()`: 接受一个新的 TCP 连接。
   - `File()`: 获取与监听器关联的文件描述符。

2. **测试 `TCPConn` 的特定方法:**
   - `SetKeepAlive()`: 设置是否开启 TCP Keep-Alive 机制。
   - `SetKeepAlivePeriod()`: 设置 TCP Keep-Alive 探测的时间间隔。
   - `SetLinger()`: 设置连接关闭时的延迟行为。
   - `SetNoDelay()`: 设置是否禁用 Nagle 算法。
   - `LocalAddr()`: 获取本地连接地址。
   - `RemoteAddr()`: 获取远程连接地址。
   - `SetDeadline()`: 设置连接的读写超时时间。
   - `SetReadDeadline()`: 设置连接的读取超时时间。
   - `SetWriteDeadline()`: 设置连接的写入超时时间。
   - `Write()`: 向连接写入数据。
   - `Read()`: 从连接读取数据。

3. **测试 `UDPConn` 的特定方法:**
   - `LocalAddr()`: 获取本地连接地址。
   - `RemoteAddr()`: 获取远程连接地址。
   - `SetDeadline()`: 设置连接的读写超时时间。
   - `SetReadDeadline()`: 设置连接的读取超时时间。
   - `SetWriteDeadline()`: 设置连接的写入超时时间。
   - `SetReadBuffer()`: 设置读取缓冲区大小。
   - `SetWriteBuffer()`: 设置写入缓冲区大小。
   - `WriteToUDP()`: 向指定的 UDP 地址写入数据。
   - `ReadFromUDP()`: 从连接读取数据，并返回发送方的 UDP 地址。
   - `WriteMsgUDP()`: 向指定的 UDP 地址写入数据，支持控制消息。
   - `ReadMsgUDP()`: 从连接读取数据，并返回发送方的 UDP 地址和控制消息。
   - `File()`: 获取与连接关联的文件描述符。

4. **测试 `IPConn` 的特定方法:**
   - `LocalAddr()`: 获取本地连接地址。
   - `RemoteAddr()`: 获取远程连接地址。
   - `SetDeadline()`: 设置连接的读写超时时间。
   - `SetReadDeadline()`: 设置连接的读取超时时间。
   - `SetWriteDeadline()`: 设置连接的写入超时时间。
   - `SetReadBuffer()`: 设置读取缓冲区大小。
   - `SetWriteBuffer()`: 设置写入缓冲区大小。
   - `File()`: 获取与连接关联的文件描述符。
   - `WriteToIP()`: 向指定的 IP 地址写入数据。
   - `WriteMsgIP()`: 向指定的 IP 地址写入数据，支持控制消息。

5. **测试 `UnixListener` 的特定方法:**
   - `Addr()`: 获取监听器的网络地址。
   - `SetDeadline()`: 设置监听器的超时时间。
   - `Accept()`: 接受一个新的通用连接。
   - `AcceptUnix()`: 接受一个新的 Unix 域套接字连接。
   - `File()`: 获取与监听器关联的文件描述符。

6. **测试 `UnixConn` 的特定方法:**
   - `LocalAddr()`: 获取本地连接地址。
   - `RemoteAddr()`: 获取远程连接地址。
   - `SetDeadline()`: 设置连接的读写超时时间。
   - `SetReadDeadline()`: 设置连接的读取超时时间。
   - `SetWriteDeadline()`: 设置连接的写入超时时间。
   - `SetReadBuffer()`: 设置读取缓冲区大小。
   - `SetWriteBuffer()`: 设置写入缓冲区大小。
   - `WriteMsgUnix()`: 向指定的 Unix 域套接字地址写入数据，支持控制消息。
   - `ReadMsgUnix()`: 从连接读取数据，并返回发送方的 Unix 域套接字地址和控制消息。
   - `WriteToUnix()`: 向指定的 Unix 域套接字地址写入数据。
   - `ReadFromUnix()`: 从连接读取数据，并返回发送方的 Unix 域套接字地址。
   - `File()`: 获取与连接关联的文件描述符。

**代码推理：测试网络连接的超时设置**

这段代码中多次使用了 `SetDeadline`，`SetReadDeadline` 和 `SetWriteDeadline`，这明显是在测试网络连接的超时功能。  我们可以推理出，这些测试用例会尝试设置一个超时时间，然后执行可能导致超时的操作（比如 `Accept` 或 `Read`），并断言是否返回了超时错误。

**Go 代码举例说明 (测试 TCPListener 的超时功能):**

```go
package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	// 监听本地地址
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer ln.Close()

	// 设置一个非常短的超时时间
	timeout := 10 * time.Millisecond
	err = ln.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		fmt.Println("Error setting deadline:", err)
		return
	}

	// 尝试接受连接，由于超时时间很短，很可能立即超时
	conn, err := ln.Accept()
	if err != nil {
		// 断言错误是超时错误
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Accept timed out as expected.")
		} else {
			fmt.Println("Accept failed with an unexpected error:", err)
		}
		return
	}

	// 如果没有超时，关闭连接
	if conn != nil {
		conn.Close()
		fmt.Println("Unexpected connection accepted before timeout.")
	}
}
```

**假设输入与输出:**

* **假设输入:**  运行上述 Go 代码。
* **预期输出:**  `Accept timed out as expected.`

**代码推理：测试 UDPConn 的写入和读取功能**

代码中 `TestUDPConnSpecificMethods` 测试了 `WriteToUDP` 和 `ReadFromUDP` 等方法。我们可以推理出，测试会创建一个 UDP 连接，然后向自身发送数据，并尝试读取收到的数据。

**Go 代码举例说明 (测试 UDPConn 的写入和读取):**

```go
package main

import (
	"fmt"
	"net"
)

func main() {
	// 监听本地 UDP 地址
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("Error resolving address:", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer conn.Close()

	// 要发送的数据
	message := []byte("Hello, UDP!")

	// 获取本地地址，用于发送数据到自身
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// 发送数据
	_, err = conn.WriteToUDP(message, localAddr)
	if err != nil {
		fmt.Println("Error writing:", err)
		return
	}
	fmt.Println("Sent:", string(message))

	// 接收数据
	buffer := make([]byte, 1024)
	n, remoteAddr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}
	fmt.Printf("Received %d bytes from %v: %s\n", n, remoteAddr, string(buffer[:n]))

	// 检查发送和接收的地址是否一致
	if !localAddr.IP.Equal(remoteAddr.IP) || localAddr.Port != remoteAddr.Port {
		fmt.Println("Warning: Sent to and received from different address!")
	}
}
```

**假设输入与输出:**

* **假设输入:**  运行上述 Go 代码。
* **预期输出:**
  ```
  Sent: Hello, UDP!
  Received 11 bytes from 127.0.0.1:<端口号>: Hello, UDP!
  ```
  （`<端口号>` 会是系统分配的动态端口）

**命令行参数处理:**

这段代码主要用于单元测试，本身不涉及处理命令行参数。`go test` 命令会执行这些测试用例，但这些测试用例内部并没有直接使用 `os.Args` 或 `flag` 包来处理命令行参数。

**使用者易犯错的点:**

1. **忘记关闭连接或监听器:**  在网络编程中，打开的连接和监听器会占用系统资源。如果忘记使用 `defer conn.Close()` 或 `defer ln.Close()` 来确保资源释放，可能会导致资源泄漏。

   ```go
   // 错误示例：忘记关闭连接
   conn, err := net.Dial("tcp", "example.com:80")
   if err != nil {
       // ...错误处理
   }
   // 忘记 conn.Close()

   // 正确示例
   conn, err := net.Dial("tcp", "example.com:80")
   if err != nil {
       // ...错误处理
   }
   defer conn.Close()
   ```

2. **不正确地处理超时:**  网络操作可能会因为网络延迟或其他原因而耗时较长。如果没有设置合适的超时时间，程序可能会一直阻塞等待，或者因为未预料到的超时而崩溃。

   ```go
   // 错误示例：没有设置超时
   conn, err := net.Dial("tcp", "example.com:80")
   if err != nil {
       // ...
   }
   // 如果网络很慢，Read 操作可能会永久阻塞
   buffer := make([]byte, 1024)
   conn.Read(buffer)

   // 正确示例：设置读取超时
   conn, err := net.Dial("tcp", "example.com:80")
   if err != nil {
       // ...
   }
   defer conn.Close()
   conn.SetReadDeadline(time.Now().Add(5 * time.Second))
   buffer := make([]byte, 1024)
   n, err := conn.Read(buffer)
   if err != nil {
       if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
           fmt.Println("读取超时")
       } else {
           fmt.Println("读取错误:", err)
       }
       return
   }
   // ... 处理读取到的数据
   ```

3. **混淆阻塞和非阻塞操作:**  Go 的 `net` 包默认是阻塞操作。如果不了解这一点，可能会在需要非阻塞行为的场景下遇到问题。可以使用 `SetNonblock()` (在某些平台上) 或使用 `select` 和 `channels` 来实现非阻塞的网络操作。

这段测试代码的主要目的是确保 `net` 包中各种连接类型的基本方法能够按照预期工作，为网络编程的正确性提供了保障。

### 提示词
```
这是路径为go/src/net/protoconn_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements API tests across platforms and will never have a build
// tag.

package net

import (
	"internal/testenv"
	"os"
	"runtime"
	"testing"
	"time"
)

// The full stack test cases for IPConn have been moved to the
// following:
//	golang.org/x/net/ipv4
//	golang.org/x/net/ipv6
//	golang.org/x/net/icmp

func TestTCPListenerSpecificMethods(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	la, err := ResolveTCPAddr("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenTCP("tcp4", la)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.Addr()
	mustSetDeadline(t, ln.SetDeadline, 30*time.Nanosecond)

	if c, err := ln.Accept(); err != nil {
		if !err.(Error).Timeout() {
			t.Fatal(err)
		}
	} else {
		c.Close()
	}
	if c, err := ln.AcceptTCP(); err != nil {
		if !err.(Error).Timeout() {
			t.Fatal(err)
		}
	} else {
		c.Close()
	}

	if f, err := ln.File(); err != nil {
		condFatalf(t, "file+net", "%v", err)
	} else {
		f.Close()
	}
}

func TestTCPConnSpecificMethods(t *testing.T) {
	la, err := ResolveTCPAddr("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenTCP("tcp4", la)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan error, 1)
	handler := func(ls *localServer, ln Listener) { ls.transponder(ls.Listener, ch) }
	ls := (&streamListener{Listener: ln}).newLocalServer()
	defer ls.teardown()
	if err := ls.buildup(handler); err != nil {
		t.Fatal(err)
	}

	ra, err := ResolveTCPAddr("tcp4", ls.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := DialTCP("tcp4", nil, ra)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetKeepAlive(false)
	c.SetKeepAlivePeriod(3 * time.Second)
	c.SetLinger(0)
	c.SetNoDelay(false)
	c.LocalAddr()
	c.RemoteAddr()
	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))

	if _, err := c.Write([]byte("TCPCONN TEST")); err != nil {
		t.Fatal(err)
	}
	rb := make([]byte, 128)
	if _, err := c.Read(rb); err != nil {
		t.Fatal(err)
	}

	for err := range ch {
		t.Error(err)
	}
}

func TestUDPConnSpecificMethods(t *testing.T) {
	la, err := ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ListenUDP("udp4", la)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.LocalAddr()
	c.RemoteAddr()
	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))
	c.SetReadBuffer(2048)
	c.SetWriteBuffer(2048)

	wb := []byte("UDPCONN TEST")
	rb := make([]byte, 128)
	if _, err := c.WriteToUDP(wb, c.LocalAddr().(*UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadFromUDP(rb); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.WriteMsgUDP(wb, nil, c.LocalAddr().(*UDPAddr)); err != nil {
		condFatalf(t, c.LocalAddr().Network(), "%v", err)
	}
	if _, _, _, _, err := c.ReadMsgUDP(rb, nil); err != nil {
		condFatalf(t, c.LocalAddr().Network(), "%v", err)
	}

	if f, err := c.File(); err != nil {
		condFatalf(t, "file+net", "%v", err)
	} else {
		f.Close()
	}

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	c.WriteToUDP(wb, nil)
	c.WriteMsgUDP(wb, nil, nil)
}

func TestIPConnSpecificMethods(t *testing.T) {
	if !testableNetwork("ip4") {
		t.Skip("skipping: ip4 not supported")
	}

	la, err := ResolveIPAddr("ip4", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ListenIP("ip4:icmp", la)
	if testenv.SyscallIsNotSupported(err) {
		// May be inside a container that disallows creating a socket or
		// not running as root.
		t.Skipf("skipping: %v", err)
	} else if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.LocalAddr()
	c.RemoteAddr()
	c.SetDeadline(time.Now().Add(someTimeout))
	c.SetReadDeadline(time.Now().Add(someTimeout))
	c.SetWriteDeadline(time.Now().Add(someTimeout))
	c.SetReadBuffer(2048)
	c.SetWriteBuffer(2048)

	if f, err := c.File(); err != nil {
		condFatalf(t, "file+net", "%v", err)
	} else {
		f.Close()
	}

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	wb := []byte("IPCONN TEST")
	c.WriteToIP(wb, nil)
	c.WriteMsgIP(wb, nil, nil)
}

func TestUnixListenerSpecificMethods(t *testing.T) {
	if !testableNetwork("unix") {
		t.Skip("unix test")
	}

	addr := testUnixAddr(t)
	la, err := ResolveUnixAddr("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenUnix("unix", la)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer os.Remove(addr)
	ln.Addr()
	mustSetDeadline(t, ln.SetDeadline, 30*time.Nanosecond)

	if c, err := ln.Accept(); err != nil {
		if !err.(Error).Timeout() {
			t.Fatal(err)
		}
	} else {
		c.Close()
	}
	if c, err := ln.AcceptUnix(); err != nil {
		if !err.(Error).Timeout() {
			t.Fatal(err)
		}
	} else {
		c.Close()
	}

	if f, err := ln.File(); err != nil {
		condFatalf(t, "file+net", "%v", err)
	} else {
		f.Close()
	}
}

func TestUnixConnSpecificMethods(t *testing.T) {
	if !testableNetwork("unixgram") {
		t.Skip("unixgram test")
	}

	addr1, addr2, addr3 := testUnixAddr(t), testUnixAddr(t), testUnixAddr(t)

	a1, err := ResolveUnixAddr("unixgram", addr1)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := DialUnix("unixgram", a1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	defer os.Remove(addr1)
	c1.LocalAddr()
	c1.RemoteAddr()
	c1.SetDeadline(time.Now().Add(someTimeout))
	c1.SetReadDeadline(time.Now().Add(someTimeout))
	c1.SetWriteDeadline(time.Now().Add(someTimeout))
	c1.SetReadBuffer(2048)
	c1.SetWriteBuffer(2048)

	a2, err := ResolveUnixAddr("unixgram", addr2)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := DialUnix("unixgram", a2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	defer os.Remove(addr2)
	c2.LocalAddr()
	c2.RemoteAddr()
	c2.SetDeadline(time.Now().Add(someTimeout))
	c2.SetReadDeadline(time.Now().Add(someTimeout))
	c2.SetWriteDeadline(time.Now().Add(someTimeout))
	c2.SetReadBuffer(2048)
	c2.SetWriteBuffer(2048)

	a3, err := ResolveUnixAddr("unixgram", addr3)
	if err != nil {
		t.Fatal(err)
	}
	c3, err := ListenUnixgram("unixgram", a3)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	defer os.Remove(addr3)
	c3.LocalAddr()
	c3.RemoteAddr()
	c3.SetDeadline(time.Now().Add(someTimeout))
	c3.SetReadDeadline(time.Now().Add(someTimeout))
	c3.SetWriteDeadline(time.Now().Add(someTimeout))
	c3.SetReadBuffer(2048)
	c3.SetWriteBuffer(2048)

	wb := []byte("UNIXCONN TEST")
	rb1 := make([]byte, 128)
	rb2 := make([]byte, 128)
	rb3 := make([]byte, 128)
	if _, _, err := c1.WriteMsgUnix(wb, nil, a2); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := c2.ReadMsgUnix(rb2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUnix(wb, a1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c1.ReadFromUnix(rb1); err != nil {
		t.Fatal(err)
	}
	if _, err := c3.WriteToUnix(wb, a1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c1.ReadFromUnix(rb1); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUnix(wb, a3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c3.ReadFromUnix(rb3); err != nil {
		t.Fatal(err)
	}

	if f, err := c1.File(); err != nil {
		condFatalf(t, "file+net", "%v", err)
	} else {
		f.Close()
	}

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	c1.WriteToUnix(wb, nil)
	c1.WriteMsgUnix(wb, nil, nil)
	c3.WriteToUnix(wb, nil)
	c3.WriteMsgUnix(wb, nil, nil)
}
```