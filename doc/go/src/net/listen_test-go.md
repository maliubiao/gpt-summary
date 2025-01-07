Response:
Let's break down the thought process for analyzing this Go test file.

1. **Understand the Goal:** The filename `listen_test.go` and the presence of `Test` functions strongly suggest this file contains tests for the `net` package's listening functionalities. The `//go:build !plan9` directive tells us these tests are not run on Plan 9 operating systems.

2. **Initial Scan for Keywords and Structures:** I'd quickly scan the code for important keywords related to network listening: `Listen`, `ListenTCP`, `ListenUDP`, `ListenPacket`, `TCPListener`, `UDPConn`, `Addr`, `Close`, and the various `Test...` function names. I'd also look for structs like `tcpListenerTests` and `udpListenerTests`. This gives a high-level overview.

3. **Identify Core Test Cases:** The code clearly structures tests using arrays of structs (`tcpListenerTests`, `udpListenerTests`, `dualStackTCPListenerTests`, `dualStackUDPListenerTests`, `ipv4MulticastListenerTests`, `ipv6MulticastListenerTests`). This suggests the tests cover different scenarios by iterating through these data structures.

4. **Analyze Individual Test Functions:**

   * **`TestTCPListener` and `TestUDPListener`:** These are the most basic. They iterate through predefined network/address combinations and try to listen twice on the same address/port. The key observation is the use of `JoinHostPort(tt.address, "0")` to let the OS pick a port, and then using the discovered port for the second `Listen` call. This tests the behavior of trying to bind to an already bound port. The `checkFirstListener` and `checkSecondListener` functions are called to verify the expected outcomes.

   * **`TestDualStackTCPListener` and `TestDualStackUDPListener`:**  The "dual-stack" name immediately suggests testing scenarios involving both IPv4 and IPv6. The `dualStack...Tests` structs contain pairs of network/address combinations and an `xerr` field, which represents the *expected error*. This hints at testing how different combinations of IPv4 and IPv6 listeners on the same port interact. The `supportsIPv4map()` check is also significant here, as it relates to whether the OS allows IPv6 sockets to handle IPv4 connections.

   * **`TestIPv4MulticastListener` and `TestIPv6MulticastListener`:** The names clearly point to testing multicast functionality. These tests use `ListenMulticastUDP` and iterate through multicast addresses. The use of `loopbackInterface()` and `nil` for the interface indicates testing with both specific and default interfaces. The `multicastRIBContains` function is interesting, suggesting verification of whether the multicast group membership was correctly established.

   * **`TestWildWildcardListener`:**  This test focuses on using empty strings or `nil` for the address in `Listen` calls. It's testing the behavior of binding to all available interfaces.

   * **`TestClosingListener`:** This test specifically examines what happens when a listener is closed while there's an attempt to accept connections. It uses a goroutine to simulate incoming connections.

   * **`TestListenConfigControl`:**  This test introduces `ListenConfig` and its `Control` field. The `controlOnConnSetup` function (not provided in the snippet but implied) is likely a function that can manipulate the underlying socket during the listening process. This points to testing advanced socket configuration options.

5. **Examine Helper Functions:** Functions like `port()`, `checkFirstListener`, `checkSecondListener`, `checkDualStackSecondListener`, `checkDualStackAddrFamily`, and `differentWildcardAddr` provide context and clarify the test logic. For example, `checkFirstListener` often verifies the socket family (IPv4 or IPv6), and the `check...SecondListener` functions check for expected errors.

6. **Infer Go Feature:** Based on the repeated use of `Listen`, `ListenTCP`, `ListenUDP`, and `ListenPacket`, and the variations in network types and addresses, the core Go feature being tested is the **ability to create network listeners for different protocols (TCP, UDP) and address families (IPv4, IPv6), including dual-stack scenarios and multicast.**

7. **Construct Code Examples:**  Based on the test structure, I'd create simple examples demonstrating `Listen` and `ListenPacket` with various network types and addresses. The dual-stack scenario example would highlight the potential for errors when trying to listen on the same port with incompatible address families.

8. **Identify Potential Pitfalls:**  Thinking about how developers might misuse the `net` package, especially related to listening, leads to common mistakes like:
    * Trying to listen on the same address and port multiple times without proper socket options.
    * Forgetting to close listeners, leading to resource leaks.
    * Not handling errors from `Listen` and related functions.
    * Misunderstanding dual-stack behavior.

9. **Review for Completeness and Accuracy:** Finally, I'd reread my analysis and the code to ensure I haven't missed anything and that my explanations are clear and accurate. For instance, the `//go:build !plan9` comment is a key detail to include.

This methodical approach allows for a comprehensive understanding of the test file's purpose and the underlying Go networking features it validates.
这段代码是 Go 语言 `net` 包中 `listen_test.go` 文件的一部分，主要用于测试网络监听相关的功能。

**它的主要功能可以概括为：**

1. **测试 TCP 监听器 (TCPListener):**
   - 验证在不同网络类型（"tcp", "tcp4", "tcp6"）和地址（包括空地址、通配符地址、特定 IP 地址等）下创建 TCP 监听器是否能正常工作。
   - 测试在相同地址族、相同监听地址和相同端口上重复监听的行为，验证是否会返回错误。

2. **测试 UDP 监听器 (UDPConn):**
   - 类似于 TCP 监听器，验证在不同网络类型（"udp", "udp4", "udp6"）和地址下创建 UDP 监听器是否能正常工作。
   - 测试在相同地址族、相同监听地址和相同端口上重复监听的行为。

3. **测试双栈 (Dual-Stack) TCP 监听器:**
   - 测试在同时支持 IPv4 和 IPv6 的系统上，尝试使用不同的地址族（如 "tcp4" 和 "tcp6"）和监听地址（如 "0.0.0.0" 和 "::"）在相同端口上创建监听器的情况。
   - 验证在不同操作系统和配置下，期望的监听行为（成功或失败）是否与实际情况一致。 这涉及到操作系统对 IPv6 的支持以及 `IPV6_V6ONLY` socket 选项的影响。

4. **测试双栈 (Dual-Stack) UDP 监听器:**
   - 类似于双栈 TCP 监听器，测试 UDP 在不同地址族和监听地址下的监听行为。

5. **测试通配符地址监听器:**
   - 测试使用空字符串或 `nil` 作为地址来监听 TCP 和 UDP 连接，验证是否能成功绑定到所有可用的网络接口。

6. **测试 IPv4 和 IPv6 组播 (Multicast) 监听器:**
   - 验证能否成功创建监听指定组播地址和端口的 UDP 连接。
   - 测试在相同的组播地址和端口上重复监听的行为。

7. **测试关闭监听器:**
   - 验证在有连接尝试时关闭监听器是否能正常工作，并且后续尝试在该地址上监听是否成功。

8. **测试 `ListenConfig` 的 `Control` 函数:**
   - 验证使用 `ListenConfig` 结构体，并通过 `Control` 字段设置回调函数，在连接建立时执行自定义操作的功能。

**代码功能实现举例 (基于 `TestTCPListener`):**

这个测试用例验证了能否在相同的地址和端口上连续创建两个 TCP 监听器。

```go
func TestTCPListener(t *testing.T) {
	// ... (平台判断)

	for _, tt := range tcpListenerTests {
		// ... (跳过不支持的测试用例)

		// 第一次监听，让系统自动分配端口
		ln1, err := Listen(tt.network, JoinHostPort(tt.address, "0"))
		if err != nil {
			t.Fatal(err)
		}
		// 检查第一次监听是否成功
		if err := checkFirstListener(tt.network, ln1); err != nil {
			ln1.Close()
			t.Fatal(err)
		}

		// 第二次监听，使用第一次监听器分配的端口
		ln2, err := Listen(tt.network, JoinHostPort(tt.address, ln1.(*TCPListener).port()))
		if err == nil {
			// 如果没有错误，说明第二次监听成功（这在某些情况下是允许的，取决于操作系统配置）
			ln2.Close()
		}
		// 检查第二次监听的结果，根据预期判断是否应该报错
		if err := checkSecondListener(tt.network, tt.address, err); err != nil {
			ln1.Close()
			t.Fatal(err)
		}
		ln1.Close()
	}
}
```

**假设输入与输出 (针对 `TestTCPListener`):**

假设 `tt` 变量当前迭代到 `{"tcp", "127.0.0.1"}`。

1. **第一次 `Listen` 调用:**
   - **输入:** `Listen("tcp", "127.0.0.1:0")`
   - **预期输出:**  `ln1` 是一个 `net.TCPListener` 实例，成功监听在 `127.0.0.1` 的某个可用端口上（例如 `12345`），`err` 为 `nil`。

2. **`ln1.(*TCPListener).port()`:** 获取 `ln1` 监听的端口号，例如 `"12345"`。

3. **第二次 `Listen` 调用:**
   - **输入:** `Listen("tcp", "127.0.0.1:12345")`
   - **预期输出:**  `err` 不为 `nil`，因为在同一个地址和端口上重复监听通常会失败（返回 `syscall.EADDRINUSE` 错误）。

4. **`checkSecondListener` 函数:**  会根据网络类型和地址判断 `err` 是否为预期值。对于 TCP，在相同地址和端口上第二次监听通常会失败，所以如果 `err` 为 `nil`，则会报错。

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。它是一个测试文件，通常由 `go test` 命令运行。  `go test` 命令本身有很多参数，例如指定要运行的测试文件、运行特定测试用例等。

**使用者易犯错的点 (以 `Listen` 函数为例):**

1. **忘记关闭监听器:**  如果创建了监听器后忘记使用 `Close()` 方法关闭，会导致端口资源无法释放，后续程序可能无法在该端口上启动。

   ```go
   // 错误示例
   ln, err := net.Listen("tcp", ":8080")
   if err != nil {
       fmt.Println("Error listening:", err)
       return
   }
   // 忘记调用 ln.Close()
   ```

2. **监听地址冲突:**  尝试监听已经被其他程序占用的端口会导致 `Listen` 函数返回 `syscall.EADDRINUSE` 错误。

   ```go
   // 假设 80 端口已经被占用
   ln, err := net.Listen("tcp", ":80")
   if err != nil {
       fmt.Println("Error listening:", err) // 可能会打印 "Error listening: listen tcp :80: bind: address already in use"
       return
   }
   ln.Close()
   ```

3. **对双栈监听的理解不足:**  在同时支持 IPv4 和 IPv6 的系统上，监听 "tcp" 或 "udp" 时，其行为可能取决于操作系统配置。开发者可能误以为监听 "tcp" 就只监听 IPv4，但实际上它可能同时监听 IPv4 和 IPv6 (取决于 `IPV6_V6ONLY` 设置)。

4. **错误地处理通配符地址:** 使用空字符串或 "0.0.0.0" 监听 IPv4 时会监听所有 IPv4 接口，使用 "[::]" 监听 IPv6 时会监听所有 IPv6 接口。 如果开发者只想监听特定接口，需要指定具体的 IP 地址。

这段测试代码通过各种场景验证了 Go 语言 `net` 包中监听功能的正确性和健壮性，帮助开发者更好地理解和使用相关的 API。

Prompt: 
```
这是路径为go/src/net/listen_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !plan9

package net

import (
	"fmt"
	"internal/testenv"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func (ln *TCPListener) port() string {
	_, port, err := SplitHostPort(ln.Addr().String())
	if err != nil {
		return ""
	}
	return port
}

func (c *UDPConn) port() string {
	_, port, err := SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ""
	}
	return port
}

var tcpListenerTests = []struct {
	network string
	address string
}{
	{"tcp", ""},
	{"tcp", "0.0.0.0"},
	{"tcp", "::ffff:0.0.0.0"},
	{"tcp", "::"},

	{"tcp", "127.0.0.1"},
	{"tcp", "::ffff:127.0.0.1"},
	{"tcp", "::1"},

	{"tcp4", ""},
	{"tcp4", "0.0.0.0"},
	{"tcp4", "::ffff:0.0.0.0"},

	{"tcp4", "127.0.0.1"},
	{"tcp4", "::ffff:127.0.0.1"},

	{"tcp6", ""},
	{"tcp6", "::"},

	{"tcp6", "::1"},
}

// TestTCPListener tests both single and double listen to a test
// listener with same address family, same listening address and
// same port.
func TestTCPListener(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	for _, tt := range tcpListenerTests {
		if !testableListenArgs(tt.network, JoinHostPort(tt.address, "0"), "") {
			t.Logf("skipping %s test", tt.network+" "+tt.address)
			continue
		}

		ln1, err := Listen(tt.network, JoinHostPort(tt.address, "0"))
		if err != nil {
			t.Fatal(err)
		}
		if err := checkFirstListener(tt.network, ln1); err != nil {
			ln1.Close()
			t.Fatal(err)
		}
		ln2, err := Listen(tt.network, JoinHostPort(tt.address, ln1.(*TCPListener).port()))
		if err == nil {
			ln2.Close()
		}
		if err := checkSecondListener(tt.network, tt.address, err); err != nil {
			ln1.Close()
			t.Fatal(err)
		}
		ln1.Close()
	}
}

var udpListenerTests = []struct {
	network string
	address string
}{
	{"udp", ""},
	{"udp", "0.0.0.0"},
	{"udp", "::ffff:0.0.0.0"},
	{"udp", "::"},

	{"udp", "127.0.0.1"},
	{"udp", "::ffff:127.0.0.1"},
	{"udp", "::1"},

	{"udp4", ""},
	{"udp4", "0.0.0.0"},
	{"udp4", "::ffff:0.0.0.0"},

	{"udp4", "127.0.0.1"},
	{"udp4", "::ffff:127.0.0.1"},

	{"udp6", ""},
	{"udp6", "::"},

	{"udp6", "::1"},
}

// TestUDPListener tests both single and double listen to a test
// listener with same address family, same listening address and
// same port.
func TestUDPListener(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	for _, tt := range udpListenerTests {
		if !testableListenArgs(tt.network, JoinHostPort(tt.address, "0"), "") {
			t.Logf("skipping %s test", tt.network+" "+tt.address)
			continue
		}

		c1, err := ListenPacket(tt.network, JoinHostPort(tt.address, "0"))
		if err != nil {
			t.Fatal(err)
		}
		if err := checkFirstListener(tt.network, c1); err != nil {
			c1.Close()
			t.Fatal(err)
		}
		c2, err := ListenPacket(tt.network, JoinHostPort(tt.address, c1.(*UDPConn).port()))
		if err == nil {
			c2.Close()
		}
		if err := checkSecondListener(tt.network, tt.address, err); err != nil {
			c1.Close()
			t.Fatal(err)
		}
		c1.Close()
	}
}

var dualStackTCPListenerTests = []struct {
	network1, address1 string // first listener
	network2, address2 string // second listener
	xerr               error  // expected error value, nil or other
}{
	// Test cases and expected results for the attempting 2nd listen on the same port
	// 1st listen                2nd listen                 darwin  freebsd  linux  openbsd
	// ------------------------------------------------------------------------------------
	// "tcp"  ""                 "tcp"  ""                    -        -       -       -
	// "tcp"  ""                 "tcp"  "0.0.0.0"             -        -       -       -
	// "tcp"  "0.0.0.0"          "tcp"  ""                    -        -       -       -
	// ------------------------------------------------------------------------------------
	// "tcp"  ""                 "tcp"  "[::]"                -        -       -       ok
	// "tcp"  "[::]"             "tcp"  ""                    -        -       -       ok
	// "tcp"  "0.0.0.0"          "tcp"  "[::]"                -        -       -       ok
	// "tcp"  "[::]"             "tcp"  "0.0.0.0"             -        -       -       ok
	// "tcp"  "[::ffff:0.0.0.0]" "tcp"  "[::]"                -        -       -       ok
	// "tcp"  "[::]"             "tcp"  "[::ffff:0.0.0.0]"    -        -       -       ok
	// ------------------------------------------------------------------------------------
	// "tcp4" ""                 "tcp6" ""                    ok       ok      ok      ok
	// "tcp6" ""                 "tcp4" ""                    ok       ok      ok      ok
	// "tcp4" "0.0.0.0"          "tcp6" "[::]"                ok       ok      ok      ok
	// "tcp6" "[::]"             "tcp4" "0.0.0.0"             ok       ok      ok      ok
	// ------------------------------------------------------------------------------------
	// "tcp"  "127.0.0.1"        "tcp"  "[::1]"               ok       ok      ok      ok
	// "tcp"  "[::1]"            "tcp"  "127.0.0.1"           ok       ok      ok      ok
	// "tcp4" "127.0.0.1"        "tcp6" "[::1]"               ok       ok      ok      ok
	// "tcp6" "[::1]"            "tcp4" "127.0.0.1"           ok       ok      ok      ok
	//
	// Platform default configurations:
	// darwin, kernel version 11.3.0
	//	net.inet6.ip6.v6only=0 (overridable by sysctl or IPV6_V6ONLY option)
	// freebsd, kernel version 8.2
	//	net.inet6.ip6.v6only=1 (overridable by sysctl or IPV6_V6ONLY option)
	// linux, kernel version 3.0.0
	//	net.ipv6.bindv6only=0 (overridable by sysctl or IPV6_V6ONLY option)
	// openbsd, kernel version 5.0
	//	net.inet6.ip6.v6only=1 (overriding is prohibited)

	{"tcp", "", "tcp", "", syscall.EADDRINUSE},
	{"tcp", "", "tcp", "0.0.0.0", syscall.EADDRINUSE},
	{"tcp", "0.0.0.0", "tcp", "", syscall.EADDRINUSE},

	{"tcp", "", "tcp", "::", syscall.EADDRINUSE},
	{"tcp", "::", "tcp", "", syscall.EADDRINUSE},
	{"tcp", "0.0.0.0", "tcp", "::", syscall.EADDRINUSE},
	{"tcp", "::", "tcp", "0.0.0.0", syscall.EADDRINUSE},
	{"tcp", "::ffff:0.0.0.0", "tcp", "::", syscall.EADDRINUSE},
	{"tcp", "::", "tcp", "::ffff:0.0.0.0", syscall.EADDRINUSE},

	{"tcp4", "", "tcp6", "", nil},
	{"tcp6", "", "tcp4", "", nil},
	{"tcp4", "0.0.0.0", "tcp6", "::", nil},
	{"tcp6", "::", "tcp4", "0.0.0.0", nil},

	{"tcp", "127.0.0.1", "tcp", "::1", nil},
	{"tcp", "::1", "tcp", "127.0.0.1", nil},
	{"tcp4", "127.0.0.1", "tcp6", "::1", nil},
	{"tcp6", "::1", "tcp4", "127.0.0.1", nil},
}

// TestDualStackTCPListener tests both single and double listen
// to a test listener with various address families, different
// listening address and same port.
//
// On DragonFly BSD, we expect the kernel version of node under test
// to be greater than or equal to 4.4.
func TestDualStackTCPListener(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !supportsIPv4() || !supportsIPv6() {
		t.Skip("both IPv4 and IPv6 are required")
	}

	for _, tt := range dualStackTCPListenerTests {
		if !testableListenArgs(tt.network1, JoinHostPort(tt.address1, "0"), "") {
			t.Logf("skipping %s test", tt.network1+" "+tt.address1)
			continue
		}

		if !supportsIPv4map() && differentWildcardAddr(tt.address1, tt.address2) {
			tt.xerr = nil
		}
		var firstErr, secondErr error
		for i := 0; i < 5; i++ {
			lns, err := newDualStackListener()
			if err != nil {
				t.Fatal(err)
			}
			port := lns[0].port()
			for _, ln := range lns {
				ln.Close()
			}
			var ln1 Listener
			ln1, firstErr = Listen(tt.network1, JoinHostPort(tt.address1, port))
			if firstErr != nil {
				continue
			}
			if err := checkFirstListener(tt.network1, ln1); err != nil {
				ln1.Close()
				t.Fatal(err)
			}
			ln2, err := Listen(tt.network2, JoinHostPort(tt.address2, ln1.(*TCPListener).port()))
			if err == nil {
				ln2.Close()
			}
			if secondErr = checkDualStackSecondListener(tt.network2, tt.address2, err, tt.xerr); secondErr != nil {
				ln1.Close()
				continue
			}
			ln1.Close()
			break
		}
		if firstErr != nil {
			t.Error(firstErr)
		}
		if secondErr != nil {
			t.Error(secondErr)
		}
	}
}

var dualStackUDPListenerTests = []struct {
	network1, address1 string // first listener
	network2, address2 string // second listener
	xerr               error  // expected error value, nil or other
}{
	{"udp", "", "udp", "", syscall.EADDRINUSE},
	{"udp", "", "udp", "0.0.0.0", syscall.EADDRINUSE},
	{"udp", "0.0.0.0", "udp", "", syscall.EADDRINUSE},

	{"udp", "", "udp", "::", syscall.EADDRINUSE},
	{"udp", "::", "udp", "", syscall.EADDRINUSE},
	{"udp", "0.0.0.0", "udp", "::", syscall.EADDRINUSE},
	{"udp", "::", "udp", "0.0.0.0", syscall.EADDRINUSE},
	{"udp", "::ffff:0.0.0.0", "udp", "::", syscall.EADDRINUSE},
	{"udp", "::", "udp", "::ffff:0.0.0.0", syscall.EADDRINUSE},

	{"udp4", "", "udp6", "", nil},
	{"udp6", "", "udp4", "", nil},
	{"udp4", "0.0.0.0", "udp6", "::", nil},
	{"udp6", "::", "udp4", "0.0.0.0", nil},

	{"udp", "127.0.0.1", "udp", "::1", nil},
	{"udp", "::1", "udp", "127.0.0.1", nil},
	{"udp4", "127.0.0.1", "udp6", "::1", nil},
	{"udp6", "::1", "udp4", "127.0.0.1", nil},
}

// TestDualStackUDPListener tests both single and double listen
// to a test listener with various address families, different
// listening address and same port.
//
// On DragonFly BSD, we expect the kernel version of node under test
// to be greater than or equal to 4.4.
func TestDualStackUDPListener(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !supportsIPv4() || !supportsIPv6() {
		t.Skip("both IPv4 and IPv6 are required")
	}

	for _, tt := range dualStackUDPListenerTests {
		if !testableListenArgs(tt.network1, JoinHostPort(tt.address1, "0"), "") {
			t.Logf("skipping %s test", tt.network1+" "+tt.address1)
			continue
		}

		if !supportsIPv4map() && differentWildcardAddr(tt.address1, tt.address2) {
			tt.xerr = nil
		}
		var firstErr, secondErr error
		for i := 0; i < 5; i++ {
			cs, err := newDualStackPacketListener()
			if err != nil {
				t.Fatal(err)
			}
			port := cs[0].port()
			for _, c := range cs {
				c.Close()
			}
			var c1 PacketConn
			c1, firstErr = ListenPacket(tt.network1, JoinHostPort(tt.address1, port))
			if firstErr != nil {
				continue
			}
			if err := checkFirstListener(tt.network1, c1); err != nil {
				c1.Close()
				t.Fatal(err)
			}
			c2, err := ListenPacket(tt.network2, JoinHostPort(tt.address2, c1.(*UDPConn).port()))
			if err == nil {
				c2.Close()
			}
			if secondErr = checkDualStackSecondListener(tt.network2, tt.address2, err, tt.xerr); secondErr != nil {
				c1.Close()
				continue
			}
			c1.Close()
			break
		}
		if firstErr != nil {
			t.Error(firstErr)
		}
		if secondErr != nil {
			t.Error(secondErr)
		}
	}
}

func differentWildcardAddr(i, j string) bool {
	if (i == "" || i == "0.0.0.0" || i == "::ffff:0.0.0.0") && (j == "" || j == "0.0.0.0" || j == "::ffff:0.0.0.0") {
		return false
	}
	if i == "[::]" && j == "[::]" {
		return false
	}
	return true
}

func checkFirstListener(network string, ln any) error {
	switch network {
	case "tcp":
		fd := ln.(*TCPListener).fd
		if err := checkDualStackAddrFamily(fd); err != nil {
			return err
		}
	case "tcp4":
		fd := ln.(*TCPListener).fd
		if fd.family != syscall.AF_INET {
			return fmt.Errorf("%v got %v; want %v", fd.laddr, fd.family, syscall.AF_INET)
		}
	case "tcp6":
		fd := ln.(*TCPListener).fd
		if fd.family != syscall.AF_INET6 {
			return fmt.Errorf("%v got %v; want %v", fd.laddr, fd.family, syscall.AF_INET6)
		}
	case "udp":
		fd := ln.(*UDPConn).fd
		if err := checkDualStackAddrFamily(fd); err != nil {
			return err
		}
	case "udp4":
		fd := ln.(*UDPConn).fd
		if fd.family != syscall.AF_INET {
			return fmt.Errorf("%v got %v; want %v", fd.laddr, fd.family, syscall.AF_INET)
		}
	case "udp6":
		fd := ln.(*UDPConn).fd
		if fd.family != syscall.AF_INET6 {
			return fmt.Errorf("%v got %v; want %v", fd.laddr, fd.family, syscall.AF_INET6)
		}
	default:
		return UnknownNetworkError(network)
	}
	return nil
}

func checkSecondListener(network, address string, err error) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		if err == nil {
			return fmt.Errorf("%s should fail", network+" "+address)
		}
	case "udp", "udp4", "udp6":
		if err == nil {
			return fmt.Errorf("%s should fail", network+" "+address)
		}
	default:
		return UnknownNetworkError(network)
	}
	return nil
}

func checkDualStackSecondListener(network, address string, err, xerr error) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		if xerr == nil && err != nil || xerr != nil && err == nil {
			return fmt.Errorf("%s got %v; want %v", network+" "+address, err, xerr)
		}
	case "udp", "udp4", "udp6":
		if xerr == nil && err != nil || xerr != nil && err == nil {
			return fmt.Errorf("%s got %v; want %v", network+" "+address, err, xerr)
		}
	default:
		return UnknownNetworkError(network)
	}
	return nil
}

func checkDualStackAddrFamily(fd *netFD) error {
	switch a := fd.laddr.(type) {
	case *TCPAddr:
		// If a node under test supports both IPv6 capability
		// and IPv6 IPv4-mapping capability, we can assume
		// that the node listens on a wildcard address with an
		// AF_INET6 socket.
		if supportsIPv4map() && fd.laddr.(*TCPAddr).isWildcard() {
			if fd.family != syscall.AF_INET6 {
				return fmt.Errorf("Listen(%s, %v) returns %v; want %v", fd.net, fd.laddr, fd.family, syscall.AF_INET6)
			}
		} else {
			if fd.family != a.family() {
				return fmt.Errorf("Listen(%s, %v) returns %v; want %v", fd.net, fd.laddr, fd.family, a.family())
			}
		}
	case *UDPAddr:
		// If a node under test supports both IPv6 capability
		// and IPv6 IPv4-mapping capability, we can assume
		// that the node listens on a wildcard address with an
		// AF_INET6 socket.
		if supportsIPv4map() && fd.laddr.(*UDPAddr).isWildcard() {
			if fd.family != syscall.AF_INET6 {
				return fmt.Errorf("ListenPacket(%s, %v) returns %v; want %v", fd.net, fd.laddr, fd.family, syscall.AF_INET6)
			}
		} else {
			if fd.family != a.family() {
				return fmt.Errorf("ListenPacket(%s, %v) returns %v; want %v", fd.net, fd.laddr, fd.family, a.family())
			}
		}
	default:
		return fmt.Errorf("unexpected protocol address type: %T", a)
	}
	return nil
}

func TestWildWildcardListener(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panicked: %v", p)
		}
	}()

	if ln, err := Listen("tcp", ""); err == nil {
		ln.Close()
	}
	if ln, err := ListenPacket("udp", ""); err == nil {
		ln.Close()
	}
	if ln, err := ListenTCP("tcp", nil); err == nil {
		ln.Close()
	}
	if ln, err := ListenUDP("udp", nil); err == nil {
		ln.Close()
	}
	if ln, err := ListenIP("ip:icmp", nil); err == nil {
		ln.Close()
	}
}

var ipv4MulticastListenerTests = []struct {
	net   string
	gaddr *UDPAddr // see RFC 4727
}{
	{"udp", &UDPAddr{IP: IPv4(224, 0, 0, 254), Port: 12345}},

	{"udp4", &UDPAddr{IP: IPv4(224, 0, 0, 254), Port: 12345}},
}

// TestIPv4MulticastListener tests both single and double listen to a
// test listener with same address family, same group address and same
// port.
func TestIPv4MulticastListener(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	switch runtime.GOOS {
	case "android", "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !supportsIPv4() {
		t.Skip("IPv4 is not supported")
	}

	closer := func(cs []*UDPConn) {
		for _, c := range cs {
			if c != nil {
				c.Close()
			}
		}
	}

	for _, ifi := range []*Interface{loopbackInterface(), nil} {
		// Note that multicast interface assignment by system
		// is not recommended because it usually relies on
		// routing stuff for finding out an appropriate
		// nexthop containing both network and link layer
		// adjacencies.
		if ifi == nil || !*testIPv4 {
			continue
		}
		for _, tt := range ipv4MulticastListenerTests {
			var err error
			cs := make([]*UDPConn, 2)
			if cs[0], err = ListenMulticastUDP(tt.net, ifi, tt.gaddr); err != nil {
				t.Fatal(err)
			}
			if err := checkMulticastListener(cs[0], tt.gaddr.IP); err != nil {
				closer(cs)
				t.Fatal(err)
			}
			if cs[1], err = ListenMulticastUDP(tt.net, ifi, tt.gaddr); err != nil {
				closer(cs)
				t.Fatal(err)
			}
			if err := checkMulticastListener(cs[1], tt.gaddr.IP); err != nil {
				closer(cs)
				t.Fatal(err)
			}
			closer(cs)
		}
	}
}

var ipv6MulticastListenerTests = []struct {
	net   string
	gaddr *UDPAddr // see RFC 4727
}{
	{"udp", &UDPAddr{IP: ParseIP("ff01::114"), Port: 12345}},
	{"udp", &UDPAddr{IP: ParseIP("ff02::114"), Port: 12345}},
	{"udp", &UDPAddr{IP: ParseIP("ff04::114"), Port: 12345}},
	{"udp", &UDPAddr{IP: ParseIP("ff05::114"), Port: 12345}},
	{"udp", &UDPAddr{IP: ParseIP("ff08::114"), Port: 12345}},
	{"udp", &UDPAddr{IP: ParseIP("ff0e::114"), Port: 12345}},

	{"udp6", &UDPAddr{IP: ParseIP("ff01::114"), Port: 12345}},
	{"udp6", &UDPAddr{IP: ParseIP("ff02::114"), Port: 12345}},
	{"udp6", &UDPAddr{IP: ParseIP("ff04::114"), Port: 12345}},
	{"udp6", &UDPAddr{IP: ParseIP("ff05::114"), Port: 12345}},
	{"udp6", &UDPAddr{IP: ParseIP("ff08::114"), Port: 12345}},
	{"udp6", &UDPAddr{IP: ParseIP("ff0e::114"), Port: 12345}},
}

// TestIPv6MulticastListener tests both single and double listen to a
// test listener with same address family, same group address and same
// port.
func TestIPv6MulticastListener(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if !supportsIPv6() {
		t.Skip("IPv6 is not supported")
	}
	if os.Getuid() != 0 {
		t.Skip("must be root")
	}

	closer := func(cs []*UDPConn) {
		for _, c := range cs {
			if c != nil {
				c.Close()
			}
		}
	}

	for _, ifi := range []*Interface{loopbackInterface(), nil} {
		// Note that multicast interface assignment by system
		// is not recommended because it usually relies on
		// routing stuff for finding out an appropriate
		// nexthop containing both network and link layer
		// adjacencies.
		if ifi == nil && !*testIPv6 {
			continue
		}
		for _, tt := range ipv6MulticastListenerTests {
			var err error
			cs := make([]*UDPConn, 2)
			if cs[0], err = ListenMulticastUDP(tt.net, ifi, tt.gaddr); err != nil {
				t.Fatal(err)
			}
			if err := checkMulticastListener(cs[0], tt.gaddr.IP); err != nil {
				closer(cs)
				t.Fatal(err)
			}
			if cs[1], err = ListenMulticastUDP(tt.net, ifi, tt.gaddr); err != nil {
				closer(cs)
				t.Fatal(err)
			}
			if err := checkMulticastListener(cs[1], tt.gaddr.IP); err != nil {
				closer(cs)
				t.Fatal(err)
			}
			closer(cs)
		}
	}
}

func checkMulticastListener(c *UDPConn, ip IP) error {
	if ok, err := multicastRIBContains(ip); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%s not found in multicast rib", ip.String())
	}
	la := c.LocalAddr()
	if la, ok := la.(*UDPAddr); !ok || la.Port == 0 {
		return fmt.Errorf("got %v; want a proper address with non-zero port number", la)
	}
	return nil
}

func multicastRIBContains(ip IP) (bool, error) {
	switch runtime.GOOS {
	case "aix", "dragonfly", "netbsd", "openbsd", "plan9", "solaris", "illumos", "windows":
		return true, nil // not implemented yet
	case "linux":
		if runtime.GOARCH == "arm" || runtime.GOARCH == "alpha" {
			return true, nil // not implemented yet
		}
	}
	ift, err := Interfaces()
	if err != nil {
		return false, err
	}
	for _, ifi := range ift {
		ifmat, err := ifi.MulticastAddrs()
		if err != nil {
			return false, err
		}
		for _, ifma := range ifmat {
			if ifma.(*IPAddr).IP.Equal(ip) {
				return true, nil
			}
		}
	}
	return false, nil
}

// Issue 21856.
func TestClosingListener(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	addr := ln.Addr()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Let the goroutine start. We don't sleep long: if the
	// goroutine doesn't start, the test will pass without really
	// testing anything, which is OK.
	time.Sleep(time.Millisecond)

	ln.Close()

	ln2, err := Listen("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	ln2.Close()
}

func TestListenConfigControl(t *testing.T) {
	switch runtime.GOOS {
	case "plan9":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	t.Run("StreamListen", func(t *testing.T) {
		for _, network := range []string{"tcp", "tcp4", "tcp6", "unix", "unixpacket"} {
			if !testableNetwork(network) {
				continue
			}
			ln := newLocalListener(t, network, &ListenConfig{Control: controlOnConnSetup})
			ln.Close()
		}
	})
	t.Run("PacketListen", func(t *testing.T) {
		for _, network := range []string{"udp", "udp4", "udp6", "unixgram"} {
			if !testableNetwork(network) {
				continue
			}
			c := newLocalPacketListener(t, network, &ListenConfig{Control: controlOnConnSetup})
			c.Close()
		}
	})
}

"""



```