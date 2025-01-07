Response:
Let's break down the thought process for analyzing the provided Go code and generating the Chinese explanation.

**1. Understanding the Goal:**

The core request is to analyze a Go test file (`unixsock_test.go`) and describe its functionality, infer its purpose related to Go features, provide examples, and highlight potential pitfalls. The output needs to be in Chinese.

**2. Initial Scan and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of what it's doing. Keywords like `Test...`, `ListenUnixgram`, `Dial`, `Write`, `ReadFrom`, `Close`, `os.Remove`, and `syscall` stand out. The `//go:build ...` comment indicates platform-specific testing. The repeated checks for `testableNetwork("unixgram")` suggest the tests are specifically about Unix domain sockets, particularly the datagram (connectionless) variety (`unixgram`).

**3. Dissecting Individual Test Functions:**

The next step is to analyze each `Test...` function individually:

* **`TestReadUnixgramWithUnnamedSocket`:** The name itself is a big clue. It involves creating a Unixgram listener, sending data to it from an *unnamed* socket (using `syscall.Socket` directly), and verifying the received data. This is about testing the ability to receive data even if the sender doesn't have a bound address.

* **`TestUnixgramZeroBytePayload`:** This focuses on sending zero-byte payloads over Unixgram sockets and how the receiver handles it. It tests both generic `Read` and `ReadFrom`. The interesting part is the handling of potential timeouts and the fact that a zero-byte payload is valid.

* **`TestUnixgramZeroByteBuffer`:** This addresses a specific issue (4352) related to providing a zero-length buffer to `ReadFrom`. It verifies that this doesn't cause an error.

* **`TestUnixgramWrite`:** This seems to be a higher-level test, calling two helper functions: `testUnixgramWriteConn` and `testUnixgramWritePacketConn`. This suggests it's testing different ways of writing to Unixgram sockets.

* **`testUnixgramWriteConn`:**  The name and the checks involving `WriteToUnix`, `WriteTo`, and `WriteMsgUnix` with a *connected* socket (obtained via `Dial`) and a remote address reveal that it tests writing to a connected Unixgram socket with explicit destination addresses, which should fail.

* **`testUnixgramWritePacketConn`:**  This tests writing to an *unconnected* Unixgram socket (obtained via `ListenPacket`) using `WriteToUnix`, `WriteTo`, and `WriteMsgUnix` with a remote address. It also checks that a simple `Write` without a destination fails.

* **`TestUnixConnLocalAndRemoteNames`:**  This test focuses on the `LocalAddr()` and `RemoteAddr()` methods for *stream* Unix sockets (`unix`). It tests scenarios with and without explicitly binding the client socket's address.

* **`TestUnixgramConnLocalAndRemoteNames`:**  Similar to the previous test, but for *datagram* Unix sockets (`unixgram`).

* **`TestUnixUnlink`:** This section is about the lifecycle of Unix domain socket files. It checks if the socket file is removed when the listener is closed, and how `SetUnlinkOnClose` affects this behavior. It also considers the case of `FileListener`.

**4. Inferring Go Feature Implementation:**

Based on the analyzed tests, the primary Go feature being tested is **Unix Domain Sockets**. This includes both stream (`unix`) and datagram (`unixgram`) types. The tests cover fundamental operations like listening, connecting, sending, and receiving data. The `TestUnixUnlink` specifically touches upon the **file system interaction** related to Unix sockets.

**5. Generating Code Examples:**

For each key feature identified, a simple, illustrative Go code example is created. The goal is clarity, not complexity.

* **Unixgram sending and receiving:** Shows a basic send/receive scenario using `ListenUnixgram` and `DialUnix`.
* **Zero-byte payload:** Demonstrates sending an empty slice.
* **Zero-byte buffer for reading:** Shows reading into a `nil` slice.
* **Connected vs. Unconnected Writes:**  Highlights the difference in behavior with `Dial` vs. `ListenPacket`.
* **Local/Remote Addresses:** Shows how to get these addresses.
* **Unlink on Close:** Demonstrates using `SetUnlinkOnClose`.

**6. Identifying Assumptions and Inputs/Outputs:**

For code reasoning sections, it's essential to make explicit any assumptions and provide example inputs and expected outputs to demonstrate the code's behavior.

**7. Detailing Command-Line Arguments:**

In this specific code, there are no direct command-line arguments being parsed. However, the test setup relies on helper functions like `testUnixAddr(t)` to generate temporary socket file paths. This can be considered a form of implicit "input."

**8. Highlighting Common Mistakes:**

Based on the test cases, potential pitfalls are identified:

* **Writing to a connected Unixgram socket with a destination address.**
* **Assuming zero-byte payloads are invalid.**
* **Assuming a zero-length read buffer will always cause an error.**
* **Misunderstanding the `UnlinkOnClose` behavior.**

**9. Structuring the Output in Chinese:**

Finally, the information gathered is organized into a clear and logical structure, using appropriate Chinese terminology. Headings, bullet points, and code blocks enhance readability. Care is taken to translate technical terms accurately.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the `syscall` package usage. Realization: The tests use the higher-level `net` package primarily, and `syscall` is used for specific low-level checks.
* **Realization:** The `//go:build` constraints are important for context – this code is specific to non-Plan 9 and non-Windows systems.
* **Ensuring clarity in examples:**  Making sure the code snippets are self-contained and easy to understand.
* **Double-checking Chinese translations:** Ensuring technical terms are translated correctly and naturally.

By following these steps, a comprehensive and accurate Chinese explanation of the Go test file can be generated.
这是一个Go语言测试文件，路径为 `go/src/net/unixsock_test.go`，它专门用于测试Go语言标准库 `net` 包中关于 **Unix域套接字 (Unix domain sockets)** 的功能。

以下是它包含的主要功能点：

**1. 测试无名套接字接收 Unixgram 数据报的能力:**

   - 它创建了一个绑定的 Unixgram 服务器套接字。
   - 然后，它创建了一个**未绑定任何地址**的 Unixgram 客户端套接字（通过 `syscall.Socket` 直接创建）。
   - 客户端套接字向服务器发送数据。
   - 测试验证服务器是否能成功接收到来自无名客户端的数据，并且接收到的源地址为空（因为客户端未绑定地址）。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net"
       "os"
       "syscall"
       "time"
   )

   func main() {
       addr := "/tmp/test_unnamed_unixgram.sock"
       la, err := net.ResolveUnixAddr("unixgram", addr)
       if err != nil {
           fmt.Println("ResolveUnixAddr error:", err)
           return
       }
       c, err := net.ListenUnixgram("unixgram", la)
       if err != nil {
           fmt.Println("ListenUnixgram error:", err)
           return
       }
       defer func() {
           c.Close()
           os.Remove(addr)
       }()

       off := make(chan bool)
       data := [5]byte{1, 2, 3, 4, 5}
       go func() {
           defer func() { off <- true }()
           s, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
           if err != nil {
               fmt.Println("syscall.Socket error:", err)
               return
           }
           defer syscall.Close(s)
           rsa := &syscall.SockaddrUnix{Name: addr}
           if err := syscall.Sendto(s, data[:], 0, rsa); err != nil {
               fmt.Println("syscall.Sendto error:", err)
               return
           }
       }()

       <-off
       b := make([]byte, 64)
       c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
       n, from, err := c.ReadFrom(b)
       if err != nil {
           fmt.Println("ReadFrom error:", err)
           return
       }
       if from != nil {
           fmt.Println("Unexpected peer address:", from)
           return
       }
       fmt.Printf("Received data: %v\n", b[:n])
   }
   ```

   **假设的输入与输出:**

   * **无输入** (代码中硬编码了地址和数据)
   * **可能的输出:** `Received data: [1 2 3 4 5]`

**2. 测试 Unixgram 套接字处理零字节载荷的能力:**

   - 创建一对 Unixgram 套接字（一个监听，一个连接）。
   - 从连接的套接字发送零字节的数据 ( `c2.Write(nil)` )。
   - 测试监听套接字能否成功接收到零字节的数据报，并验证接收到的对端地址是否为空（对于非连接模式）。
   - 同时测试使用通用的 `Read` 和 `ReadFrom` 方法接收零字节数据的情况。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net"
       "os"
       "time"
   )

   func main() {
       addr := "/tmp/test_zero_payload_unixgram.sock"
       laddr, err := net.ResolveUnixAddr("unixgram", addr)
       if err != nil {
           fmt.Println("ResolveUnixAddr error:", err)
           return
       }
       c1, err := net.ListenUnixgram("unixgram", laddr)
       if err != nil {
           fmt.Println("ListenUnixgram error:", err)
           return
       }
       defer func() {
           c1.Close()
           os.Remove(addr)
       }()

       c2, err := net.DialUnix("unixgram", nil, laddr)
       if err != nil {
           fmt.Println("DialUnix error:", err)
           return
       }
       defer c2.Close()

       n, err := c2.Write(nil)
       if err != nil {
           fmt.Println("Write error:", err)
           return
       }
       fmt.Println("Bytes written:", n)

       b := make([]byte, 1)
       c1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
       _, peer, err := c1.ReadFrom(b)
       if err != nil {
           // 读取可能超时，取决于平台
           if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
               fmt.Println("ReadFrom timed out (expected)")
           } else {
               fmt.Println("ReadFrom error:", err)
           }
           return
       }
       fmt.Println("Received data (length): 0")
       fmt.Println("Peer address:", peer)
   }
   ```

   **假设的输入与输出:**

   * **无输入**
   * **可能的输出:**
     ```
     Bytes written: 0
     ReadFrom timed out (expected)
     ```
     或者 (如果平台立即返回):
     ```
     Bytes written: 0
     Received data (length): 0
     Peer address: <nil>
     ```

**3. 测试使用零长度缓冲区读取 Unixgram 数据报的情况:**

   - 创建一对 Unixgram 套接字。
   - 从一个套接字发送一些数据。
   - 测试在接收端使用零长度的缓冲区 (`c1.ReadFrom(nil)`) 进行读取是否会引发错误。它主要测试的是 `ReadFrom` 系统调用的行为，即使提供了零长度的缓冲区，也应该能够成功接收数据包的来源地址。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net"
       "os"
       "time"
   )

   func main() {
       addr := "/tmp/test_zero_buffer_unixgram.sock"
       laddr, err := net.ResolveUnixAddr("unixgram", addr)
       if err != nil {
           fmt.Println("ResolveUnixAddr error:", err)
           return
       }
       c1, err := net.ListenUnixgram("unixgram", laddr)
       if err != nil {
           fmt.Println("ListenUnixgram error:", err)
           return
       }
       defer func() {
           c1.Close()
           os.Remove(addr)
       }()

       c2, err := net.DialUnix("unixgram", nil, laddr)
       if err != nil {
           fmt.Println("DialUnix error:", err)
           return
       }
       defer c2.Close()

       data := []byte("Hello")
       n, err := c2.Write(data)
       if err != nil {
           fmt.Println("Write error:", err)
           return
       }
       fmt.Println("Bytes written:", n)

       c1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
       _, peer, err := c1.ReadFrom(nil)
       if err != nil {
           // 读取可能超时，取决于平台
           if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
               fmt.Println("ReadFrom timed out (expected)")
           } else {
               fmt.Println("ReadFrom error:", err)
           }
           return
       }
       fmt.Println("Received data (no data, zero-length buffer)")
       fmt.Println("Peer address:", peer)
   }
   ```

   **假设的输入与输出:**

   * **无输入**
   * **可能的输出:**
     ```
     Bytes written: 5
     Received data (no data, zero-length buffer)
     Peer address: &{/tmp/test_zero_buffer_unixgram.sock unixgram}
     ```
     或者 (如果平台超时):
     ```
     Bytes written: 5
     ReadFrom timed out (expected)
     ```

**4. 测试 Unixgram 套接字的写入操作:**

   - 区分了连接模式 (`Dial`) 和非连接模式 (`ListenPacket`) 的 Unixgram 套接字。
   - **连接模式:** 尝试使用 `WriteToUnix`, `WriteTo`, `WriteMsgUnix` 显式指定目标地址进行写入，预期会失败并返回 `ErrWriteToConnected` 错误，因为连接模式的套接字已经绑定了对端地址，不应再指定。使用 `Write` 写入应该成功。
   - **非连接模式:** 使用 `WriteToUnix`, `WriteTo`, `WriteMsgUnix` 显式指定目标地址进行写入应该成功。尝试使用 `Write` 写入应该失败，因为没有指定目标地址。

   **代码示例 (连接模式):**

   ```go
   package main

   import (
       "errors"
       "fmt"
       "net"
       "os"
   )

   func main() {
       raddrStr := "/tmp/server_unixgram.sock"
       raddr, err := net.ResolveUnixAddr("unixgram", raddrStr)
       if err != nil {
           fmt.Println("ResolveUnixAddr error:", err)
           return
       }

       c, err := net.DialUnix("unixgram", nil, raddr)
       if err != nil {
           fmt.Println("DialUnix error:", err)
           return
       }
       defer c.Close()

       b := []byte("CONNECTED-MODE SOCKET")
       _, err = c.(*net.UnixConn).WriteToUnix(b, raddr)
       if err == nil {
           fmt.Println("Should have failed")
       } else if errors.Is(err, net.ErrWriteToConnected) {
           fmt.Println("WriteToUnix failed as expected:", err)
       } else {
           fmt.Println("WriteToUnix failed with unexpected error:", err)
       }

       _, err = c.Write(b)
       if err != nil {
           fmt.Println("Write succeeded:", err)
       } else {
           fmt.Println("Write succeeded")
       }
   }
   ```

   **假设的输入与输出:** (假设服务端已在 `raddrStr` 监听)

   * **无输入**
   * **可能的输出:**
     ```
     WriteToUnix failed as expected: write to connected unix socket
     Write succeeded
     ```

**5. 测试 Unix 和 Unixgram 连接的本地和远程地址:**

   - 对于 `unix` (流式套接字)，测试 `LocalAddr()` 和 `RemoteAddr()` 方法是否返回正确的地址信息，包括在客户端没有显式绑定地址的情况下（系统会自动分配）。
   - 对于 `unixgram` (数据报套接字)，同样测试 `LocalAddr()` 和 `RemoteAddr()`，并验证未连接的 `ListenUnixgram` 返回的连接对象的 `RemoteAddr()` 为 `nil`。

   **代码示例 (Unixgram):**

   ```go
   package main

   import (
       "fmt"
       "net"
       "os"
       "reflect"
   )

   func main() {
       taddrStr := "/tmp/server_unixgram_addr.sock"
       ta, err := net.ResolveUnixAddr("unixgram", taddrStr)
       if err != nil {
           fmt.Println("ResolveUnixAddr error:", err)
           return
       }
       c1, err := net.ListenUnixgram("unixgram", ta)
       if err != nil {
           fmt.Println("ListenUnixgram error:", err)
           return
       }
       defer func() {
           c1.Close()
           os.Remove(taddrStr)
       }()

       c2, err := net.DialUnix("unixgram", nil, ta)
       if err != nil {
           fmt.Println("DialUnix error:", err)
           return
       }
       defer c2.Close()

       fmt.Println("c1 LocalAddr:", c1.LocalAddr())
       fmt.Println("c1 RemoteAddr:", c1.RemoteAddr())
       fmt.Println("c2 LocalAddr:", c2.LocalAddr())
       fmt.Println("c2 RemoteAddr:", c2.RemoteAddr())

       // 验证地址 (简化)
       if c1.RemoteAddr() != nil {
           fmt.Println("Error: c1.RemoteAddr() should be nil")
       }
       if !reflect.DeepEqual(c2.RemoteAddr(), ta) {
           fmt.Println("Error: c2.RemoteAddr() mismatch")
       }
   }
   ```

   **假设的输入与输出:**

   * **无输入**
   * **可能的输出:**
     ```
     c1 LocalAddr: &{/tmp/server_unixgram_addr.sock unixgram}
     c1 RemoteAddr: <nil>
     c2 LocalAddr: &{/tmp/server_unixgram_addr1.sock unixgram}  // 假设自动分配的地址
     c2 RemoteAddr: &{/tmp/server_unixgram_addr.sock unixgram}
     ```

**6. 测试 Unix 套接字文件的取消链接 (unlink) 行为:**

   - 测试当 `ListenUnix` 创建的监听器关闭时，默认情况下是否会自动删除对应的套接字文件。
   - 测试 `FileListener` 创建的监听器关闭时，是否不会删除套接字文件。
   - 测试 `SetUnlinkOnClose` 方法的作用，可以控制监听器关闭时是否删除套接字文件。

   **代码示例 (SetUnlinkOnClose):**

   ```go
   package main

   import (
       "fmt"
       "net"
       "os"
   )

   func main() {
       addr := "/tmp/test_unlink_unix.sock"

       // 创建监听器
       l, err := net.Listen("unix", addr)
       if err != nil {
           fmt.Println("Listen error:", err)
           return
       }
       defer l.Close() // 确保关闭

       // 检查文件是否存在
       if _, err := os.Stat(addr); os.IsNotExist(err) {
           fmt.Println("Error: Socket file does not exist after listen")
           return
       }
       fmt.Println("Socket file exists after listen")

       // 设置关闭时删除
       if ul, ok := l.(*net.UnixListener); ok {
           ul.SetUnlinkOnClose(true)
       }

       // 再次关闭
       l.Close()

       // 检查文件是否被删除
       if _, err := os.Stat(addr); os.IsNotExist(err) {
           fmt.Println("Socket file does not exist after close with SetUnlinkOnClose(true)")
       } else {
           fmt.Println("Error: Socket file still exists after close with SetUnlinkOnClose(true)")
       }
   }
   ```

   **假设的输入与输出:**

   * **无输入**
   * **可能的输出:**
     ```
     Socket file exists after listen
     Socket file does not exist after close with SetUnlinkOnClose(true)
     ```

**涉及的 Go 语言功能:**

- **`net` 包:**  核心网络功能，包括 Unix 域套接字的支持。
- **`os` 包:**  文件系统操作，用于创建和删除套接字文件。
- **`syscall` 包:** 底层系统调用，用于进行更底层的套接字操作（例如创建无名套接字）。
- **`testing` 包:**  Go 语言的测试框架，用于编写和运行测试用例。
- **`reflect` 包:**  用于深度比较对象，例如比较地址信息。
- **`time` 包:**  用于设置读取超时时间。

**命令行参数的具体处理:**

这个测试文件本身是一个测试文件，通常通过 `go test` 命令运行。它不直接处理命令行参数。但是，在测试过程中，可能会使用一些辅助函数（例如 `testUnixAddr(t)`）来生成临时的套接字文件路径，这可以被看作是测试用例的输入。

**使用者易犯错的点:**

1. **向连接模式的 Unixgram 套接字使用 `WriteTo` 等方法指定目标地址:**  这是不允许的，应该使用 `Write` 方法。
   ```go
   conn, _ := net.DialUnix("unixgram", nil, addr)
   // 错误的做法
   // conn.WriteTo([]byte("data"), addr)
   // 正确的做法
   conn.Write([]byte("data"))
   ```

2. **假设零字节的 Unixgram 数据报是无效的:**  实际上，零字节的数据报是可以被发送和接收的。

3. **假设使用零长度的缓冲区进行 `ReadFrom` 会总是出错:**  在 Unix 域套接字中，即使提供零长度的缓冲区，`ReadFrom` 仍然可以返回发送方的地址信息（如果可用）。

4. **不理解 `SetUnlinkOnClose` 的作用:**  默认情况下，通过 `ListenUnix` 创建的监听器在关闭时会自动删除套接字文件。如果使用 `FileListener` 基于已存在的文件描述符创建监听器，或者手动设置 `SetUnlinkOnClose(false)`，则需要手动删除套接字文件。

总而言之，`go/src/net/unixsock_test.go` 这个文件细致地测试了 Go 语言中 Unix 域套接字的各种行为和边缘情况，确保了 `net` 包中相关功能的正确性和健壮性。

Prompt: 
```
这是路径为go/src/net/unixsock_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !plan9 && !windows

package net

import (
	"bytes"
	"internal/testenv"
	"os"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestReadUnixgramWithUnnamedSocket(t *testing.T) {
	if !testableNetwork("unixgram") {
		t.Skip("unixgram test")
	}
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skipf("skipping: syscall.Socket not implemented on %s", runtime.GOOS)
	}
	if runtime.GOOS == "openbsd" {
		testenv.SkipFlaky(t, 15157)
	}

	addr := testUnixAddr(t)
	la, err := ResolveUnixAddr("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ListenUnixgram("unixgram", la)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c.Close()
		os.Remove(addr)
	}()

	off := make(chan bool)
	data := [5]byte{1, 2, 3, 4, 5}
	go func() {
		defer func() { off <- true }()
		s, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer syscall.Close(s)
		rsa := &syscall.SockaddrUnix{Name: addr}
		if err := syscall.Sendto(s, data[:], 0, rsa); err != nil {
			t.Error(err)
			return
		}
	}()

	<-off
	b := make([]byte, 64)
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, from, err := c.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	if from != nil {
		t.Fatalf("unexpected peer address: %v", from)
	}
	if !bytes.Equal(b[:n], data[:]) {
		t.Fatalf("got %v; want %v", b[:n], data[:])
	}
}

func TestUnixgramZeroBytePayload(t *testing.T) {
	if !testableNetwork("unixgram") {
		t.Skip("unixgram test")
	}

	c1 := newLocalPacketListener(t, "unixgram")
	defer os.Remove(c1.LocalAddr().String())
	defer c1.Close()

	c2, err := Dial("unixgram", c1.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(c2.LocalAddr().String())
	defer c2.Close()

	for _, genericRead := range []bool{false, true} {
		n, err := c2.Write(nil)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("got %d; want 0", n)
		}
		c1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var b [1]byte
		var peer Addr
		if genericRead {
			_, err = c1.(Conn).Read(b[:])
		} else {
			_, peer, err = c1.ReadFrom(b[:])
		}
		switch err {
		case nil: // ReadFrom succeeds
			if peer != nil { // peer is connected-mode
				t.Fatalf("unexpected peer address: %v", peer)
			}
		default: // Read may timeout, it depends on the platform
			if !isDeadlineExceeded(err) {
				t.Fatal(err)
			}
		}
	}
}

func TestUnixgramZeroByteBuffer(t *testing.T) {
	if !testableNetwork("unixgram") {
		t.Skip("unixgram test")
	}
	// issue 4352: Recvfrom failed with "address family not
	// supported by protocol family" if zero-length buffer provided

	c1 := newLocalPacketListener(t, "unixgram")
	defer os.Remove(c1.LocalAddr().String())
	defer c1.Close()

	c2, err := Dial("unixgram", c1.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(c2.LocalAddr().String())
	defer c2.Close()

	b := []byte("UNIXGRAM ZERO BYTE BUFFER TEST")
	for _, genericRead := range []bool{false, true} {
		n, err := c2.Write(b)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(b) {
			t.Errorf("got %d; want %d", n, len(b))
		}
		c1.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var peer Addr
		if genericRead {
			_, err = c1.(Conn).Read(nil)
		} else {
			_, peer, err = c1.ReadFrom(nil)
		}
		switch err {
		case nil: // ReadFrom succeeds
			if peer != nil { // peer is connected-mode
				t.Fatalf("unexpected peer address: %v", peer)
			}
		default: // Read may timeout, it depends on the platform
			if !isDeadlineExceeded(err) {
				t.Fatal(err)
			}
		}
	}
}

func TestUnixgramWrite(t *testing.T) {
	if !testableNetwork("unixgram") {
		t.Skip("unixgram test")
	}

	addr := testUnixAddr(t)
	laddr, err := ResolveUnixAddr("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ListenPacket("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(addr)
	defer c.Close()

	testUnixgramWriteConn(t, laddr)
	testUnixgramWritePacketConn(t, laddr)
}

func testUnixgramWriteConn(t *testing.T, raddr *UnixAddr) {
	c, err := Dial("unixgram", raddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	b := []byte("CONNECTED-MODE SOCKET")
	if _, err := c.(*UnixConn).WriteToUnix(b, raddr); err == nil {
		t.Fatal("should fail")
	} else if err.(*OpError).Err != ErrWriteToConnected {
		t.Fatalf("should fail as ErrWriteToConnected: %v", err)
	}
	if _, err = c.(*UnixConn).WriteTo(b, raddr); err == nil {
		t.Fatal("should fail")
	} else if err.(*OpError).Err != ErrWriteToConnected {
		t.Fatalf("should fail as ErrWriteToConnected: %v", err)
	}
	if _, _, err = c.(*UnixConn).WriteMsgUnix(b, nil, raddr); err == nil {
		t.Fatal("should fail")
	} else if err.(*OpError).Err != ErrWriteToConnected {
		t.Fatalf("should fail as ErrWriteToConnected: %v", err)
	}
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func testUnixgramWritePacketConn(t *testing.T, raddr *UnixAddr) {
	addr := testUnixAddr(t)
	c, err := ListenPacket("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(addr)
	defer c.Close()

	b := []byte("UNCONNECTED-MODE SOCKET")
	if _, err := c.(*UnixConn).WriteToUnix(b, raddr); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo(b, raddr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.(*UnixConn).WriteMsgUnix(b, nil, raddr); err != nil {
		t.Fatal(err)
	}
	if _, err := c.(*UnixConn).Write(b); err == nil {
		t.Fatal("should fail")
	}
}

func TestUnixConnLocalAndRemoteNames(t *testing.T) {
	if !testableNetwork("unix") {
		t.Skip("unix test")
	}

	handler := func(ls *localServer, ln Listener) {}
	for _, laddr := range []string{"", testUnixAddr(t)} {
		laddr := laddr
		taddr := testUnixAddr(t)
		ta, err := ResolveUnixAddr("unix", taddr)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := ListenUnix("unix", ta)
		if err != nil {
			t.Fatal(err)
		}
		ls := (&streamListener{Listener: ln}).newLocalServer()
		defer ls.teardown()
		if err := ls.buildup(handler); err != nil {
			t.Fatal(err)
		}

		la, err := ResolveUnixAddr("unix", laddr)
		if err != nil {
			t.Fatal(err)
		}
		c, err := DialUnix("unix", la, ta)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			c.Close()
			if la != nil {
				defer os.Remove(laddr)
			}
		}()
		if _, err := c.Write([]byte("UNIXCONN LOCAL AND REMOTE NAME TEST")); err != nil {
			t.Fatal(err)
		}

		switch runtime.GOOS {
		case "android", "linux":
			if laddr == "" {
				laddr = "@" // autobind feature
			}
		}
		var connAddrs = [3]struct{ got, want Addr }{
			{ln.Addr(), ta},
			{c.LocalAddr(), &UnixAddr{Name: laddr, Net: "unix"}},
			{c.RemoteAddr(), ta},
		}
		for _, ca := range connAddrs {
			if !reflect.DeepEqual(ca.got, ca.want) {
				t.Fatalf("got %#v, expected %#v", ca.got, ca.want)
			}
		}
	}
}

func TestUnixgramConnLocalAndRemoteNames(t *testing.T) {
	if !testableNetwork("unixgram") {
		t.Skip("unixgram test")
	}

	for _, laddr := range []string{"", testUnixAddr(t)} {
		laddr := laddr
		taddr := testUnixAddr(t)
		ta, err := ResolveUnixAddr("unixgram", taddr)
		if err != nil {
			t.Fatal(err)
		}
		c1, err := ListenUnixgram("unixgram", ta)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			c1.Close()
			os.Remove(taddr)
		}()

		var la *UnixAddr
		if laddr != "" {
			if la, err = ResolveUnixAddr("unixgram", laddr); err != nil {
				t.Fatal(err)
			}
		}
		c2, err := DialUnix("unixgram", la, ta)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			c2.Close()
			if la != nil {
				defer os.Remove(laddr)
			}
		}()

		switch runtime.GOOS {
		case "android", "linux":
			if laddr == "" {
				laddr = "@" // autobind feature
			}
		}

		var connAddrs = [4]struct{ got, want Addr }{
			{c1.LocalAddr(), ta},
			{c1.RemoteAddr(), nil},
			{c2.LocalAddr(), &UnixAddr{Name: laddr, Net: "unixgram"}},
			{c2.RemoteAddr(), ta},
		}
		for _, ca := range connAddrs {
			if !reflect.DeepEqual(ca.got, ca.want) {
				t.Fatalf("got %#v; want %#v", ca.got, ca.want)
			}
		}
	}
}

func TestUnixUnlink(t *testing.T) {
	if !testableNetwork("unix") {
		t.Skip("unix test")
	}
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skipf("skipping: %s does not support Unlink", runtime.GOOS)
	}

	name := testUnixAddr(t)

	listen := func(t *testing.T) *UnixListener {
		l, err := Listen("unix", name)
		if err != nil {
			t.Fatal(err)
		}
		return l.(*UnixListener)
	}
	checkExists := func(t *testing.T, desc string) {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("unix socket does not exist %s: %v", desc, err)
		}
	}
	checkNotExists := func(t *testing.T, desc string) {
		if _, err := os.Stat(name); err == nil {
			t.Fatalf("unix socket does exist %s: %v", desc, err)
		}
	}

	// Listener should remove on close.
	t.Run("Listen", func(t *testing.T) {
		l := listen(t)
		checkExists(t, "after Listen")
		l.Close()
		checkNotExists(t, "after Listener close")
	})

	// FileListener should not.
	t.Run("FileListener", func(t *testing.T) {
		l := listen(t)
		f, _ := l.File()
		l1, _ := FileListener(f)
		checkExists(t, "after FileListener")
		f.Close()
		checkExists(t, "after File close")
		l1.Close()
		checkExists(t, "after FileListener close")
		l.Close()
		checkNotExists(t, "after Listener close")
	})

	// Only first call to l.Close should remove.
	t.Run("SecondClose", func(t *testing.T) {
		l := listen(t)
		checkExists(t, "after Listen")
		l.Close()
		checkNotExists(t, "after Listener close")
		if err := os.WriteFile(name, []byte("hello world"), 0666); err != nil {
			t.Fatalf("cannot recreate socket file: %v", err)
		}
		checkExists(t, "after writing temp file")
		l.Close()
		checkExists(t, "after second Listener close")
		os.Remove(name)
	})

	// SetUnlinkOnClose should do what it says.

	t.Run("Listen/SetUnlinkOnClose(true)", func(t *testing.T) {
		l := listen(t)
		checkExists(t, "after Listen")
		l.SetUnlinkOnClose(true)
		l.Close()
		checkNotExists(t, "after Listener close")
	})

	t.Run("Listen/SetUnlinkOnClose(false)", func(t *testing.T) {
		l := listen(t)
		checkExists(t, "after Listen")
		l.SetUnlinkOnClose(false)
		l.Close()
		checkExists(t, "after Listener close")
		os.Remove(name)
	})

	t.Run("FileListener/SetUnlinkOnClose(true)", func(t *testing.T) {
		l := listen(t)
		f, _ := l.File()
		l1, _ := FileListener(f)
		checkExists(t, "after FileListener")
		l1.(*UnixListener).SetUnlinkOnClose(true)
		f.Close()
		checkExists(t, "after File close")
		l1.Close()
		checkNotExists(t, "after FileListener close")
		l.Close()
	})

	t.Run("FileListener/SetUnlinkOnClose(false)", func(t *testing.T) {
		l := listen(t)
		f, _ := l.File()
		l1, _ := FileListener(f)
		checkExists(t, "after FileListener")
		l1.(*UnixListener).SetUnlinkOnClose(false)
		f.Close()
		checkExists(t, "after File close")
		l1.Close()
		checkExists(t, "after FileListener close")
		l.Close()
	})
}

"""



```