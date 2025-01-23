Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Goal Identification:**

First, I quickly scanned the code, noticing the `package net_test` and the `Example...` function names. This immediately suggests the file contains example usages of the `net` package for testing and documentation purposes. The request explicitly asks for the *functionality* of this code. Since it's examples, each `Example...` function likely demonstrates a specific feature of the `net` package.

**2. Analyzing Individual `Example` Functions:**

I then processed each `Example` function one by one, focusing on the core `net` package functions being used:

* **`ExampleListener()`:**  The name and the `net.Listen("tcp", ":2000")` call clearly indicate this demonstrates setting up a network listener. The loop and `conn, err := l.Accept()` followed by a goroutine for `io.Copy(c, c)` points to a simple echo server.

* **`ExampleDialer()`:**  The name and `net.Dialer` with `d.DialContext(...)` clearly show this is about establishing a connection. The use of `context.WithTimeout` is also significant.

* **`ExampleDialer_unix()`:** Similar to the previous example, but the `net.UnixAddr` and the comment about the context applying only to the dial operation are important distinctions.

* **`ExampleIPv4()`:**  Simple usage of `net.IPv4()` to create an IP address.

* **`ExampleParseCIDR()`:**  Uses `net.ParseCIDR()` to parse IP addresses with network prefixes.

* **`ExampleParseIP()`:**  Uses `net.ParseIP()` to parse IP addresses.

* **`ExampleIP_DefaultMask()`:**  Demonstrates retrieving the default subnet mask for an IP address.

* **`ExampleIP_Equal()`:**  Shows how to compare IP addresses for equality.

* **`ExampleIP_IsGlobalUnicast()` through `ExampleIP_IsUnspecified()`:**  A series of examples showcasing different methods to check the properties of an IP address (global unicast, multicast, private, etc.).

* **`ExampleIP_Mask()`:**  Demonstrates how to apply a subnet mask to an IP address.

* **`ExampleIP_String()`:**  Shows how to convert an IP address to its string representation.

* **`ExampleIP_To16()` and `ExampleIP_To4()`:** Illustrate converting IP addresses to their 16-byte (IPv6) and 4-byte (IPv4) representations, respectively.

* **`ExampleCIDRMask()`:** Shows how to generate a network mask from a prefix length.

* **`ExampleIPv4Mask()`:**  Demonstrates creating an IPv4 mask directly using byte values.

* **`ExampleUDPConn_WriteTo()`:**  Focuses on sending UDP packets to a specific address using `WriteTo()` after establishing a non-connected UDP listener with `ListenPacket()`.

**3. Summarizing Functionality:**

After analyzing each example, I grouped the functionalities:

* **Network Listening:**  Demonstrated by `ExampleListener`.
* **Establishing Connections (TCP and Unix Sockets):** Shown by `ExampleDialer` and `ExampleDialer_unix`.
* **IP Address Manipulation:**  Covered by the various `ExampleIP_*` functions, `ExampleIPv4`, `ExampleParseIP`, `ExampleParseCIDR`. This includes creation, parsing, comparison, property checks, masking, and conversion.
* **Network Masks:**  Demonstrated by `ExampleCIDRMask` and `ExampleIPv4Mask`.
* **UDP Packet Sending:** Shown by `ExampleUDPConn_WriteTo`.

**4. Inferring Go Language Features and Providing Examples:**

The request asked to infer the Go language features being demonstrated. This was relatively straightforward:

* **Goroutines and Concurrency:** Clearly shown in `ExampleListener` with the `go func(c net.Conn) { ... }(conn)`.
* **Contexts:**  Used for timeouts in `ExampleDialer` and `ExampleDialer_unix`.
* **Error Handling:**  The consistent use of `if err != nil { log.Fatal(err) }` is a prominent Go pattern.
* **Closures:**  The anonymous function used as a goroutine in `ExampleListener` is a closure.
* **String Conversion:**  Implicit in the `fmt.Println` calls with `net.IP` and other `net` types.

For each inferred feature, I created simple illustrative code snippets (like the `Context` and `Goroutine` examples) separate from the original example functions.

**5. Reasoning about Input/Output and Command-Line Arguments:**

* **Input/Output:**  For functions like `ExampleListener` and `ExampleDialer`, I considered the network data being sent and received. For the IP address manipulation examples, the input is the IP address string or components, and the output is the formatted string or boolean value. I added explicit "假设输入" and "假设输出" sections.
* **Command-Line Arguments:** None of the provided examples directly used `os.Args` or flags. Therefore, I noted that there were no command-line arguments involved.

**6. Identifying Common Mistakes:**

This required some experience with networking and the `net` package:

* **Forgetting to Close Connections/Listeners:** This is a very common resource leak issue. I highlighted the importance of `defer l.Close()` and `defer conn.Close()`.
* **Misunderstanding Contexts with Unix Sockets:** The code itself provided a hint about this, so I emphasized that the context only applies to the `DialContext` call for Unix sockets.
* **Incorrectly Handling Errors in Goroutines:**  Since the goroutine in `ExampleListener` simply uses `log.Fatal`, I pointed out that this wouldn't necessarily shut down the main server and that more robust error handling might be needed.

**7. Structuring the Answer:**

Finally, I organized the information clearly with headings and bullet points to make it easy to read and understand. I adhered to the request for a Chinese answer.

**Self-Correction/Refinement During the Process:**

* Initially, I considered describing the specific TCP/IP concepts (like the three-way handshake for TCP), but realized the request was focused on the *Go code* and its usage of the `net` package, not a networking tutorial.
* I made sure to use the exact wording from the request (e.g., "功能", "推理", "易犯错的点").
* I double-checked that the example code I provided was syntactically correct and relevant to the inferred feature.

By following these steps, I could systematically analyze the code snippet and generate a comprehensive and accurate answer that addressed all aspects of the prompt.
这段代码是 Go 语言标准库 `net` 包的测试用例和示例代码，主要用于演示 `net` 包中各种网络编程相关功能的使用方法。它通过一系列以 `Example` 开头的函数来展示不同场景下的网络操作。

以下是它所展示的功能的详细列表：

**1. 网络监听 (Listening):**

* **功能:** 展示如何创建一个 TCP 监听器，接收客户端连接。
* **对应代码:** `ExampleListener()`
* **Go 语言功能:** 使用 `net.Listen()` 函数创建监听器，使用 `l.Accept()` 接受连接，使用 `go` 关键字创建 Goroutine 并发处理连接。
* **代码示例:**

```go
package main

import (
	"io"
	"log"
	"net"
)

func main() {
	l, err := net.Listen("tcp", ":2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			io.Copy(c, c) // Echo server
			c.Close()
		}(conn)
	}
}
```

**假设输入与输出:**

假设运行上述代码后，另一个程序（比如 `telnet localhost 2000`）连接到本地的 2000 端口并发送 "hello"。

* **假设输入:**  客户端发送 "hello"
* **假设输出:**  服务器会将 "hello" 回显给客户端。

**2. 建立连接 (Dialing):**

* **功能:** 展示如何使用 `net.Dialer` 建立到指定网络地址的连接，并支持设置超时。
* **对应代码:** `ExampleDialer()`
* **Go 语言功能:** 使用 `net.Dialer` 结构体配置连接参数，使用 `d.DialContext()` 函数建立连接，使用 `context.WithTimeout` 设置超时。
* **代码示例:**

```go
package main

import (
	"context"
	"log"
	"net"
	"time"
)

func main() {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "localhost:12345")
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("Hello Server!")); err != nil {
		log.Fatal(err)
	}
}
```

**假设输入与输出:**

假设本地有一个监听在 12345 端口的 TCP 服务。

* **假设输入:**  无，代码内部发送 "Hello Server!"
* **假设输出:**  如果连接成功，服务端会接收到 "Hello Server!"。如果在 5 秒内无法连接，程序会输出 "Failed to dial: ..." 错误信息。

**3. 连接 Unix Socket:**

* **功能:** 展示如何使用 `net.Dialer` 连接 Unix 域套接字，并强调 `context.Context` 仅适用于拨号操作。
* **对应代码:** `ExampleDialer_unix()`
* **Go 语言功能:** 使用 `net.UnixAddr` 结构体指定 Unix 套接字地址，使用 `d.DialContext()` 连接。
* **代码示例:**

```go
package main

import (
	"context"
	"log"
	"net"
	"time"
	"os"
)

func main() {
	socketPath := "/tmp/example.sock"
	// 确保套接字文件存在 (用于演示，实际应用中需要有服务监听)
	_, err := os.Stat(socketPath)
	if os.IsNotExist(err) {
		log.Fatalf("Unix socket file not found: %s", socketPath)
	}

	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	raddr := net.UnixAddr{Name: socketPath, Net: "unix"}
	conn, err := d.DialContext(ctx, "unix", raddr.String())
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("Hello Unix Socket!")); err != nil {
		log.Fatal(err)
	}
}
```

**假设输入与输出:**

假设在 `/tmp/example.sock` 存在一个 Unix 域套接字监听的服务。

* **假设输入:** 无，代码内部发送 "Hello Unix Socket!"
* **假设输出:** 如果连接成功，Unix 域套接字服务会接收到 "Hello Unix Socket!"。如果在 5 秒内无法连接，程序会输出 "Failed to dial: ..." 错误信息。

**4. 创建 IPv4 地址:**

* **功能:** 展示如何使用 `net.IPv4()` 函数创建一个 IPv4 地址。
* **对应代码:** `ExampleIPv4()`
* **Go 语言功能:** 使用 `net.IPv4()` 函数。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:**  无
    * **假设输出:** `8.8.8.8`

**5. 解析 CIDR 表示的 IP 地址和网络:**

* **功能:** 展示如何使用 `net.ParseCIDR()` 函数解析 CIDR 格式的 IP 地址和网络。
* **对应代码:** `ExampleParseCIDR()`
* **Go 语言功能:** 使用 `net.ParseCIDR()` 函数。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:**
        ```
        192.0.2.1
        192.0.2.0/24
        2001:db8:a0b:12f0::1
        2001:db8::/32
        ```

**6. 解析 IP 地址:**

* **功能:** 展示如何使用 `net.ParseIP()` 函数解析 IP 地址字符串。
* **对应代码:** `ExampleParseIP()`
* **Go 语言功能:** 使用 `net.ParseIP()` 函数。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:**
        ```
        192.0.2.1
        2001:db8::68
        <nil>
        ```

**7. 获取 IP 地址的默认子网掩码:**

* **功能:** 展示如何使用 `ip.DefaultMask()` 方法获取 IP 地址的默认子网掩码。
* **对应代码:** `ExampleIP_DefaultMask()`
* **Go 语言功能:** 使用 `net.IP` 类型的 `DefaultMask()` 方法。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:** `fffffe00` (十六进制表示)

**8. 比较 IP 地址是否相等:**

* **功能:** 展示如何使用 `ip.Equal()` 方法比较两个 IP 地址是否相等。
* **对应代码:** `ExampleIP_Equal()`
* **Go 语言功能:** 使用 `net.IP` 类型的 `Equal()` 方法。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:**
        ```
        true
        false
        true
        ```

**9. 判断 IP 地址的类型 (全局单播, 接口本地组播等):**

* **功能:** 展示如何使用 `net.IP` 类型的一系列 `Is...()` 方法判断 IP 地址的类型，例如是否是全局单播地址、接口本地组播地址等。
* **对应代码:** `ExampleIP_IsGlobalUnicast()` 到 `ExampleIP_IsUnspecified()`
* **Go 语言功能:** 使用 `net.IP` 类型的各种 `Is...()` 方法。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**  每个示例都有相应的输出，用于验证判断结果。

**10. 计算 IP 地址的网络地址:**

* **功能:** 展示如何使用 `ip.Mask()` 方法结合子网掩码计算 IP 地址所属的网络地址。
* **对应代码:** `ExampleIP_Mask()`
* **Go 语言功能:** 使用 `net.IP` 类型的 `Mask()` 方法和 `net.CIDRMask()` 函数创建子网掩码。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:**
        ```
        192.0.2.0
        2001:db8::
        ```

**11. 将 IP 地址转换为字符串表示:**

* **功能:** 展示如何使用 `ip.String()` 方法将 IP 地址转换为字符串表示。
* **对应代码:** `ExampleIP_String()`
* **Go 语言功能:** 使用 `net.IP` 类型的 `String()` 方法。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:**
        ```
        fc00::
        10.255.0.0
        ```

**12. 将 IP 地址转换为 16 字节或 4 字节数组:**

* **功能:** 展示如何使用 `ip.To16()` 和 `ip.To4()` 方法将 IP 地址分别转换为 16 字节（IPv6）或 4 字节（IPv4）的数组。
* **对应代码:** `ExampleIP_To16()` 和 `ExampleIP_To4()`
* **Go 语言功能:** 使用 `net.IP` 类型的 `To16()` 和 `To4()` 方法。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:** (注意输出是字节数组的表示)
        ```
        [252 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
        [10 255 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
        <nil>
        [10 255 0 0]
        ```

**13. 创建子网掩码:**

* **功能:** 展示如何使用 `net.CIDRMask()` 和 `net.IPv4Mask()` 函数创建子网掩码。
* **对应代码:** `ExampleCIDRMask()` 和 `ExampleIPv4Mask()`
* **Go 语言功能:** 使用 `net.CIDRMask()` 和 `net.IPv4Mask()` 函数。
* **代码示例:** 见提供的代码本身。
* **假设输入与输出:**
    * **假设输入:** 无
    * **假设输出:** (十六进制表示)
        ```
        ffffffee
        ffffffffffffffff0000000000000000
        ffffff00
        ```

**14. 发送 UDP 数据包 (无连接):**

* **功能:** 展示如何使用 `net.ListenPacket()` 创建一个 UDP 连接，并使用 `conn.WriteTo()` 发送数据包到指定地址。
* **对应代码:** `ExampleUDPConn_WriteTo()`
* **Go 语言功能:** 使用 `net.ListenPacket()` 创建无连接 UDP 连接，使用 `net.ResolveUDPAddr()` 解析 UDP 地址，使用 `conn.WriteTo()` 发送数据。
* **代码示例:**

```go
package main

import (
	"log"
	"net"
)

func main() {
	conn, err := net.ListenPacket("udp", ":0") // 监听任意可用端口
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp", "192.0.2.1:2000")
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.WriteTo([]byte("Hello UDP!"), dst)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("UDP packet sent.")
}
```

**假设输入与输出:**

假设有一个 UDP 服务监听在 `192.0.2.1:2000`。

* **假设输入:** 无，代码内部发送 "Hello UDP!"
* **假设输出:** 如果目标地址有服务监听，该服务会接收到 "Hello UDP!"。 本地程序会输出 "UDP packet sent."

**代码推理：**

这段代码主要通过示例来演示 `net` 包提供的各种网络编程接口。它没有复杂的业务逻辑，主要目的是展示 API 的用法和输出结果。

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。这些 `Example` 函数通常用于 `go test` 命令的运行，以便生成文档或验证代码功能。如果你想在实际应用程序中使用这些功能，你需要根据具体需求编写处理命令行参数的代码，例如使用 `flag` 包。

**使用者易犯错的点:**

1. **忘记关闭连接和监听器:** 在 `ExampleListener` 和 `ExampleDialer` 中，务必使用 `defer l.Close()` 和 `defer conn.Close()` 来确保资源被正确释放，防止资源泄漏。

2. **对 `DialContext` 中 `Context` 的理解偏差:**  在 `ExampleDialer_unix` 中特别指出，对于 Unix 套接字，`Context` 仅应用于拨号操作，连接建立后 `Context` 就失效了。这意味着即使 `Context` 超时，已经建立的连接仍然有效。

3. **在 Goroutine 中直接使用 `log.Fatal`:** 在 `ExampleListener` 的 Goroutine 中，如果 `io.Copy` 出错，会调用 `log.Fatal`，这会直接终止整个程序，而不仅仅是当前的 Goroutine。更合适的做法可能是返回错误并由主 Goroutine 处理，或者使用更轻量的日志记录方式。

4. **UDP 的无连接性:** 在 `ExampleUDPConn_WriteTo` 中，需要理解 UDP 是无连接的，`ListenPacket` 只是创建了一个可以发送和接收 UDP 数据包的 socket，并没有像 TCP 那样建立连接的概念。发送数据前需要明确指定目标地址。

通过这些示例，开发者可以学习如何在 Go 语言中进行网络编程，包括创建服务器、连接到服务器、处理 IP 地址和子网掩码、以及进行 UDP 通信等基本操作。

### 提示词
```
这是路径为go/src/net/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package net_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func ExampleListener() {
	// Listen on TCP port 2000 on all available unicast and
	// anycast IP addresses of the local system.
	l, err := net.Listen("tcp", ":2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c net.Conn) {
			// Echo all incoming data.
			io.Copy(c, c)
			// Shut down the connection.
			c.Close()
		}(conn)
	}
}

func ExampleDialer() {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "localhost:12345")
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("Hello, World!")); err != nil {
		log.Fatal(err)
	}
}

func ExampleDialer_unix() {
	// DialUnix does not take a context.Context parameter. This example shows
	// how to dial a Unix socket with a Context. Note that the Context only
	// applies to the dial operation; it does not apply to the connection once
	// it has been established.
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	d.LocalAddr = nil // if you have a local addr, add it here
	raddr := net.UnixAddr{Name: "/path/to/unix.sock", Net: "unix"}
	conn, err := d.DialContext(ctx, "unix", raddr.String())
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("Hello, socket!")); err != nil {
		log.Fatal(err)
	}
}

func ExampleIPv4() {
	fmt.Println(net.IPv4(8, 8, 8, 8))

	// Output:
	// 8.8.8.8
}

func ExampleParseCIDR() {
	ipv4Addr, ipv4Net, err := net.ParseCIDR("192.0.2.1/24")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ipv4Addr)
	fmt.Println(ipv4Net)

	ipv6Addr, ipv6Net, err := net.ParseCIDR("2001:db8:a0b:12f0::1/32")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ipv6Addr)
	fmt.Println(ipv6Net)

	// Output:
	// 192.0.2.1
	// 192.0.2.0/24
	// 2001:db8:a0b:12f0::1
	// 2001:db8::/32
}

func ExampleParseIP() {
	fmt.Println(net.ParseIP("192.0.2.1"))
	fmt.Println(net.ParseIP("2001:db8::68"))
	fmt.Println(net.ParseIP("192.0.2"))

	// Output:
	// 192.0.2.1
	// 2001:db8::68
	// <nil>
}

func ExampleIP_DefaultMask() {
	ip := net.ParseIP("192.0.2.1")
	fmt.Println(ip.DefaultMask())

	// Output:
	// ffffff00
}

func ExampleIP_Equal() {
	ipv4DNS := net.ParseIP("8.8.8.8")
	ipv4Lo := net.ParseIP("127.0.0.1")
	ipv6DNS := net.ParseIP("0:0:0:0:0:FFFF:0808:0808")

	fmt.Println(ipv4DNS.Equal(ipv4DNS))
	fmt.Println(ipv4DNS.Equal(ipv4Lo))
	fmt.Println(ipv4DNS.Equal(ipv6DNS))

	// Output:
	// true
	// false
	// true
}

func ExampleIP_IsGlobalUnicast() {
	ipv6Global := net.ParseIP("2000::")
	ipv6UniqLocal := net.ParseIP("2000::")
	ipv6Multi := net.ParseIP("FF00::")

	ipv4Private := net.ParseIP("10.255.0.0")
	ipv4Public := net.ParseIP("8.8.8.8")
	ipv4Broadcast := net.ParseIP("255.255.255.255")

	fmt.Println(ipv6Global.IsGlobalUnicast())
	fmt.Println(ipv6UniqLocal.IsGlobalUnicast())
	fmt.Println(ipv6Multi.IsGlobalUnicast())

	fmt.Println(ipv4Private.IsGlobalUnicast())
	fmt.Println(ipv4Public.IsGlobalUnicast())
	fmt.Println(ipv4Broadcast.IsGlobalUnicast())

	// Output:
	// true
	// true
	// false
	// true
	// true
	// false
}

func ExampleIP_IsInterfaceLocalMulticast() {
	ipv6InterfaceLocalMulti := net.ParseIP("ff01::1")
	ipv6Global := net.ParseIP("2000::")
	ipv4 := net.ParseIP("255.0.0.0")

	fmt.Println(ipv6InterfaceLocalMulti.IsInterfaceLocalMulticast())
	fmt.Println(ipv6Global.IsInterfaceLocalMulticast())
	fmt.Println(ipv4.IsInterfaceLocalMulticast())

	// Output:
	// true
	// false
	// false
}

func ExampleIP_IsLinkLocalMulticast() {
	ipv6LinkLocalMulti := net.ParseIP("ff02::2")
	ipv6LinkLocalUni := net.ParseIP("fe80::")
	ipv4LinkLocalMulti := net.ParseIP("224.0.0.0")
	ipv4LinkLocalUni := net.ParseIP("169.254.0.0")

	fmt.Println(ipv6LinkLocalMulti.IsLinkLocalMulticast())
	fmt.Println(ipv6LinkLocalUni.IsLinkLocalMulticast())
	fmt.Println(ipv4LinkLocalMulti.IsLinkLocalMulticast())
	fmt.Println(ipv4LinkLocalUni.IsLinkLocalMulticast())

	// Output:
	// true
	// false
	// true
	// false
}

func ExampleIP_IsLinkLocalUnicast() {
	ipv6LinkLocalUni := net.ParseIP("fe80::")
	ipv6Global := net.ParseIP("2000::")
	ipv4LinkLocalUni := net.ParseIP("169.254.0.0")
	ipv4LinkLocalMulti := net.ParseIP("224.0.0.0")

	fmt.Println(ipv6LinkLocalUni.IsLinkLocalUnicast())
	fmt.Println(ipv6Global.IsLinkLocalUnicast())
	fmt.Println(ipv4LinkLocalUni.IsLinkLocalUnicast())
	fmt.Println(ipv4LinkLocalMulti.IsLinkLocalUnicast())

	// Output:
	// true
	// false
	// true
	// false
}

func ExampleIP_IsLoopback() {
	ipv6Lo := net.ParseIP("::1")
	ipv6 := net.ParseIP("ff02::1")
	ipv4Lo := net.ParseIP("127.0.0.0")
	ipv4 := net.ParseIP("128.0.0.0")

	fmt.Println(ipv6Lo.IsLoopback())
	fmt.Println(ipv6.IsLoopback())
	fmt.Println(ipv4Lo.IsLoopback())
	fmt.Println(ipv4.IsLoopback())

	// Output:
	// true
	// false
	// true
	// false
}

func ExampleIP_IsMulticast() {
	ipv6Multi := net.ParseIP("FF00::")
	ipv6LinkLocalMulti := net.ParseIP("ff02::1")
	ipv6Lo := net.ParseIP("::1")
	ipv4Multi := net.ParseIP("239.0.0.0")
	ipv4LinkLocalMulti := net.ParseIP("224.0.0.0")
	ipv4Lo := net.ParseIP("127.0.0.0")

	fmt.Println(ipv6Multi.IsMulticast())
	fmt.Println(ipv6LinkLocalMulti.IsMulticast())
	fmt.Println(ipv6Lo.IsMulticast())
	fmt.Println(ipv4Multi.IsMulticast())
	fmt.Println(ipv4LinkLocalMulti.IsMulticast())
	fmt.Println(ipv4Lo.IsMulticast())

	// Output:
	// true
	// true
	// false
	// true
	// true
	// false
}

func ExampleIP_IsPrivate() {
	ipv6Private := net.ParseIP("fc00::")
	ipv6Public := net.ParseIP("fe00::")
	ipv4Private := net.ParseIP("10.255.0.0")
	ipv4Public := net.ParseIP("11.0.0.0")

	fmt.Println(ipv6Private.IsPrivate())
	fmt.Println(ipv6Public.IsPrivate())
	fmt.Println(ipv4Private.IsPrivate())
	fmt.Println(ipv4Public.IsPrivate())

	// Output:
	// true
	// false
	// true
	// false
}

func ExampleIP_IsUnspecified() {
	ipv6Unspecified := net.ParseIP("::")
	ipv6Specified := net.ParseIP("fe00::")
	ipv4Unspecified := net.ParseIP("0.0.0.0")
	ipv4Specified := net.ParseIP("8.8.8.8")

	fmt.Println(ipv6Unspecified.IsUnspecified())
	fmt.Println(ipv6Specified.IsUnspecified())
	fmt.Println(ipv4Unspecified.IsUnspecified())
	fmt.Println(ipv4Specified.IsUnspecified())

	// Output:
	// true
	// false
	// true
	// false
}

func ExampleIP_Mask() {
	ipv4Addr := net.ParseIP("192.0.2.1")
	// This mask corresponds to a /24 subnet for IPv4.
	ipv4Mask := net.CIDRMask(24, 32)
	fmt.Println(ipv4Addr.Mask(ipv4Mask))

	ipv6Addr := net.ParseIP("2001:db8:a0b:12f0::1")
	// This mask corresponds to a /32 subnet for IPv6.
	ipv6Mask := net.CIDRMask(32, 128)
	fmt.Println(ipv6Addr.Mask(ipv6Mask))

	// Output:
	// 192.0.2.0
	// 2001:db8::
}

func ExampleIP_String() {
	ipv6 := net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ipv4 := net.IPv4(10, 255, 0, 0)

	fmt.Println(ipv6.String())
	fmt.Println(ipv4.String())

	// Output:
	// fc00::
	// 10.255.0.0
}

func ExampleIP_To16() {
	ipv6 := net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ipv4 := net.IPv4(10, 255, 0, 0)

	fmt.Println(ipv6.To16())
	fmt.Println(ipv4.To16())

	// Output:
	// fc00::
	// 10.255.0.0
}

func ExampleIP_To4() {
	ipv6 := net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ipv4 := net.IPv4(10, 255, 0, 0)

	fmt.Println(ipv6.To4())
	fmt.Println(ipv4.To4())

	// Output:
	// <nil>
	// 10.255.0.0
}

func ExampleCIDRMask() {
	// This mask corresponds to a /31 subnet for IPv4.
	fmt.Println(net.CIDRMask(31, 32))

	// This mask corresponds to a /64 subnet for IPv6.
	fmt.Println(net.CIDRMask(64, 128))

	// Output:
	// fffffffe
	// ffffffffffffffff0000000000000000
}

func ExampleIPv4Mask() {
	fmt.Println(net.IPv4Mask(255, 255, 255, 0))

	// Output:
	// ffffff00
}

func ExampleUDPConn_WriteTo() {
	// Unlike Dial, ListenPacket creates a connection without any
	// association with peers.
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp", "192.0.2.1:2000")
	if err != nil {
		log.Fatal(err)
	}

	// The connection can write data to the desired address.
	_, err = conn.WriteTo([]byte("data"), dst)
	if err != nil {
		log.Fatal(err)
	}
}
```