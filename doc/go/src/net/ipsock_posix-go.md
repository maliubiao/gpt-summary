Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file name `ipsock_posix.go` and the package declaration `package net` immediately suggest this code deals with IP networking on POSIX-like systems. The `//go:build unix || js || wasip1 || windows` build constraint reinforces this, indicating platform-specific networking logic.

2. **Scan for Key Functions:** Look for function definitions. The prominent ones are:
    * `probe()`:  The name suggests some kind of system examination or capability detection.
    * `favoriteAddrFamily()`:  This sounds like a function that makes a decision about address families (IPv4/IPv6). The "favorite" part hints at a preference or strategy.
    * `internetSocket()`: This seems like a higher-level function for creating network sockets, potentially delegating to lower-level operations.
    * `ipToSockaddrInet4()`, `ipToSockaddrInet6()`:  These clearly handle the conversion of IP addresses and ports into specific socket address structures.
    * `ipToSockaddr()`: This appears to be a general dispatcher for the IPv4 and IPv6 specific conversion functions.
    * `addrPortToSockaddrInet4()`, `addrPortToSockaddrInet6()`: Similar to the `ipToSockaddr` family, but working with `netip.AddrPort` which is a more modern representation of IP address and port.

3. **Analyze Individual Function Functionality:**

    * **`probe()`:**
        * **Goal:** Determine the system's IPv4 and IPv6 capabilities, especially regarding IPv4-mapped IPv6.
        * **Mechanism:** It tries to create IPv4 and IPv6 sockets. It also uses `setsockopt` with `IPV6_V6ONLY` to test how the kernel handles IPv4-mapped IPv6 addresses on IPv6 sockets. The special casing for `js` and `wasip1` hints at simulated networking environments. The conditional removal of probes for DragonFly BSD and OpenBSD is an important platform-specific detail.
        * **Output:**  It updates the fields of an `ipStackCapabilities` struct.

    * **`favoriteAddrFamily()`:**
        * **Goal:**  Choose the appropriate address family (AF_INET or AF_INET6) based on the network type (tcp, tcp4, tcp6, etc.), local and remote addresses, and whether it's a listening socket.
        * **Logic:**  It has a lot of conditional logic, especially around listening on wildcard addresses. The comments are crucial here for understanding the reasoning behind the choices (dual-stack, IPv6-only, IPv4-only). The `go:linkname` comment highlights its intended internal use but actual external usage.

    * **`internetSocket()`:**
        * **Goal:**  A wrapper around the lower-level `socket()` function, handling platform-specific address transformations (like `toLocal()` on some systems when dialing a wildcard) and calling `favoriteAddrFamily()` to determine the right address family.

    * **`ipToSockaddrInet4()` / `ipToSockaddrInet6()`:**
        * **Goal:** Convert Go's `net.IP` and port/zone information into the system-level `syscall.SockaddrInet4` and `syscall.SockaddrInet6` structures.
        * **Details:** Includes checks for valid IP addresses and special handling of the zero IP address.

    * **`ipToSockaddr()`:**
        * **Goal:**  A dispatcher function that selects the correct `ipToSockaddrInet4` or `ipToSockaddrInet6` function based on the address family. Again, the `go:linkname` comment is important.

    * **`addrPortToSockaddrInet4()` / `addrPortToSockaddrInet6()`:**
        * **Goal:** Similar to `ipToSockaddrInet4`/`ipToSockaddrInet6` but uses the `netip.AddrPort` type.
        * **Difference:**  Explicitly handles the conversion from `netip.Addr` to the appropriate byte representation. It also doesn't have the special case for zero IP addresses like the `ipToSockaddr` family.

4. **Infer Overall Functionality:**  Putting the pieces together, this code snippet is responsible for:
    * **Probing system capabilities:**  Detecting how the OS handles IPv4 and IPv6.
    * **Selecting the correct address family:**  Making intelligent choices about whether to use IPv4 or IPv6 sockets based on the provided addresses and network type.
    * **Converting Go's network types to system-level socket structures:** Bridging the gap between Go's `net` package and the operating system's socket API.

5. **Consider Examples and Potential Pitfalls:**

    * **`probe()`:**  Hard to directly exemplify with Go code as it's internal.
    * **`favoriteAddrFamily()`:**  Easy to illustrate with different network strings and address types to show how the family and `ipv6only` values change. The "listening on wildcard" scenario is a good focus.
    * **`internetSocket()`:**  Demonstrate basic `Dial` and `Listen` calls and how they implicitly use this function.
    * **`ipToSockaddr` family:** Show how to create `TCPAddr` or `UDPAddr` and how these functions convert them to the underlying `syscall.Sockaddr`.
    * **Pitfalls:** The `favoriteAddrFamily` logic, especially around wildcard addresses and dual-stack, can be tricky to understand. Incorrectly specifying network types (e.g., using "tcp6" with an IPv4 address) is a common mistake. The `go:linkname` comments highlight that relying on these internal functions directly is risky.

6. **Structure the Answer:** Organize the findings logically, starting with a high-level summary, then detailing each function's purpose. Provide clear code examples with assumed inputs and outputs. Address the potential for errors.

7. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Make sure the examples are runnable and illustrative.

This systematic approach, starting with the overall purpose and diving into specifics, helps in understanding complex code like this. The comments in the code are invaluable for deciphering the intent behind the implementation choices.
这段代码是 Go 语言 `net` 包中处理 IP 套接字在 POSIX 系统上（以及一些其他类 Unix 系统和 Windows）实现的一部分。它主要负责以下几个核心功能：

**1. 探测 IP 协议栈能力 (`probe` 函数):**

   - **功能:**  该函数用于检测当前操作系统内核对 IPv4、IPv6 以及 IPv4-mapped IPv6 地址的支持情况。这包括是否启用了 IPv6，以及 IPv6 套接字是否可以处理 IPv4 连接（通过 IPv4-mapped IPv6 地址）。
   - **实现原理:** 它尝试创建 IPv4 和 IPv6 的 TCP 套接字，并尝试设置 `IPV6_V6ONLY` 选项。根据操作系统的不同，某些探测行为会有所调整（例如，DragonFly BSD 和 OpenBSD 不支持 `IPV6_V6ONLY=0`）。
   - **推断的 Go 语言功能实现:**  这部分是 `net` 包在底层确定如何与网络协议栈交互的关键步骤，确保在不同的操作系统上能够正确处理 IP 地址。

**2. 选择合适的地址族 (`favoriteAddrFamily` 函数):**

   - **功能:**  根据给定的网络类型（例如 "tcp", "tcp4", "tcp6"）、本地地址、远程地址以及操作模式（"listen" 或其他），决定应该使用哪个地址族 (`syscall.AF_INET` 代表 IPv4, `syscall.AF_INET6` 代表 IPv6)，以及是否应该设置 `IPV6_V6ONLY` 选项。
   - **实现原理:**  该函数包含复杂的逻辑，特别是对于监听操作和通配符地址。它会考虑系统是否支持 IPv4-mapped IPv6，以及用户指定的网络类型。例如，如果监听的是通配符地址的 "tcp"，且系统支持 IPv4-mapped IPv6，则会倾向于使用 IPv6 套接字并设置 `IPV6_V6ONLY=0`，以便同时监听 IPv4 和 IPv6 连接。
   - **推断的 Go 语言功能实现:**  这是 `net` 包在创建套接字时选择正确协议的关键决策点，确保应用程序能够按照预期的方式监听或连接到网络。

   **Go 代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net"
       "syscall"
   )

   func main() {
       // 假设我们想要监听所有 IPv4 和 IPv6 接口的 8080 端口
       network := "tcp"
       laddr := &net.TCPAddr{Port: 8080}
       var raddr *net.TCPAddr // 远程地址在监听时为空
       mode := "listen"

       family, ipv6only := favoriteAddrFamily(network, laddr.sockaddr(), nil, mode)

       fmt.Printf("对于网络 '%s' 和本地地址 '%v' (监听模式):\n", network, laddr)
       if family == syscall.AF_INET {
           fmt.Println("选择的地址族: IPv4 (syscall.AF_INET)")
       } else if family == syscall.AF_INET6 {
           fmt.Println("选择的地址族: IPv6 (syscall.AF_INET6)")
           fmt.Printf("IPV6_V6ONLY: %t\n", ipv6only)
       }

       // 实际创建监听器会使用这些信息
   }

   // 为了示例目的，我们需要一个 sockaddr 的实现，实际 net 包内部有实现
   type sockaddr interface {
       family() int
       isWildcard() bool
   }

   func (t *net.TCPAddr) sockaddr() sockaddr {
       // 简化实现，实际 net 包的 sockaddr 接口更复杂
       return &tcpSockaddr{addr: t}
   }

   type tcpSockaddr struct {
       addr *net.TCPAddr
   }

   func (t *tcpSockaddr) family() int {
       if t.addr.IP.To4() != nil {
           return syscall.AF_INET
       }
       return syscall.AF_INET6
   }

   func (t *tcpSockaddr) isWildcard() bool {
       return t.addr.IP == nil || t.addr.IP.Equal(net.IPv4zero) || t.addr.IP.Equal(net.IPv6zero)
   }

   // favoriteAddrFamily 函数的简化版本，仅用于示例
   func favoriteAddrFamily(network string, laddr sockaddr, raddr sockaddr, mode string) (family int, ipv6only bool) {
       switch network[len(network)-1] {
       case '4':
           return syscall.AF_INET, false
       case '6':
           return syscall.AF_INET6, true
       }

       if mode == "listen" && (laddr == nil || laddr.isWildcard()) {
           // 这里简化了判断逻辑，实际情况更复杂
           return syscall.AF_INET6, false // 假设支持 IPv4-mapped IPv6
       }

       if (laddr == nil || laddr.family() == syscall.AF_INET) &&
           (raddr == nil || raddr.family() == syscall.AF_INET) {
           return syscall.AF_INET, false
       }
       return syscall.AF_INET6, false
   }
   ```

   **假设的输入与输出:**

   - **输入:** `network = "tcp"`, `laddr = &net.TCPAddr{Port: 8080}`, `mode = "listen"`
   - **输出:** (假设系统支持 IPv4-mapped IPv6) `family = syscall.AF_INET6`, `ipv6only = false`

**3. 创建互联网套接字 (`internetSocket` 函数):**

   - **功能:**  这是一个用于创建 TCP 或 UDP 等互联网协议套接字的辅助函数。它在内部调用 `favoriteAddrFamily` 来确定合适的地址族，并处理一些特定于操作系统的行为（例如，在某些系统上，如果 `dial` 的是通配符地址，则会将其转换为本地地址）。
   - **实现原理:** 它调用更底层的 `socket` 函数（图中未显示）来实际创建套接字。
   - **推断的 Go 语言功能实现:** 这是 `net.Dial` 和 `net.Listen` 等函数在底层创建套接字时使用的关键步骤。

**4. IP 地址到 Socket 地址的转换 (`ipToSockaddrInet4`, `ipToSockaddrInet6`, `ipToSockaddr` 函数):**

   - **功能:**  这些函数负责将 Go 语言中的 `net.IP` 类型和端口号转换为系统调用所需的 `syscall.SockaddrInet4` 和 `syscall.SockaddrInet6` 结构体。`ipToSockaddr` 是一个根据地址族分发到具体转换函数的入口。
   - **实现原理:**  它们将 `net.IP` 类型的字节数组复制到 `syscall.SockaddrInetX` 的地址字段中，并设置端口号。`ipToSockaddrInet6` 还会处理 IPv6 的 Zone ID。
   - **推断的 Go 语言功能实现:**  当 `net` 包需要与底层的 socket API 交互时，这些函数用于准备传递给系统调用的地址信息。

   **Go 代码示例:**

   ```go
   package main

   import (
       "fmt"
       "net"
       "syscall"
   )

   func main() {
       ip := net.ParseIP("192.168.1.100")
       port := 80
       sa4, err := ipToSockaddr(syscall.AF_INET, ip, port, "")
       if err != nil {
           fmt.Println("转换 IPv4 地址失败:", err)
       } else {
           fmt.Printf("IPv4 Socket 地址: %+v\n", sa4.(*syscall.SockaddrInet4))
       }

       ip6 := net.ParseIP("2001:db8::1")
       sa6, err := ipToSockaddr(syscall.AF_INET6, ip6, port, "")
       if err != nil {
           fmt.Println("转换 IPv6 地址失败:", err)
       } else {
           fmt.Printf("IPv6 Socket 地址: %+v\n", sa6.(*syscall.SockaddrInet6))
       }
   }

   // 假设的 ipToSockaddr 实现 (简化)
   func ipToSockaddr(family int, ip net.IP, port int, zone string) (syscall.Sockaddr, error) {
       switch family {
       case syscall.AF_INET:
           sa := syscall.SockaddrInet4{Port: port}
           copy(sa.Addr[:], ip.To4())
           return &sa, nil
       case syscall.AF_INET6:
           sa := syscall.SockaddrInet6{Port: port}
           copy(sa.Addr[:], ip.To16())
           return &sa, nil
       }
       return nil, fmt.Errorf("invalid address family")
   }
   ```

   **假设的输入与输出:**

   - **输入:** `family = syscall.AF_INET`, `ip = net.ParseIP("192.168.1.100")`, `port = 80`, `zone = ""`
   - **输出:** `&syscall.SockaddrInet4{Port: 80, Addr: [192 168 1 100]}`

   - **输入:** `family = syscall.AF_INET6`, `ip = net.ParseIP("2001:db8::1")`, `port = 80`, `zone = ""`
   - **输出:** `&syscall.SockaddrInet6{Port: 80, Addr: [0 32 13 184 0 0 0 0 0 0 0 0 0 0 0 1], ZoneId: 0}`

**5. `netip.AddrPort` 到 Socket 地址的转换 (`addrPortToSockaddrInet4`, `addrPortToSockaddrInet6` 函数):**

   - **功能:** 这些函数与 `ipToSockaddrInet4` 和 `ipToSockaddrInet6` 类似，但它们接受的是 `netip.AddrPort` 类型，这是 Go 1.18 引入的更现代的表示 IP 地址和端口的方式。
   - **实现原理:**  它们从 `netip.AddrPort` 中提取 IP 地址和端口，并将其转换为相应的 `syscall.SockaddrInetX` 结构体。
   - **推断的 Go 语言功能实现:**  `net` 包中使用了 `netip` 包来提供更高效和类型安全的 IP 地址处理，这些函数用于在新旧 API 之间进行转换。

**使用者易犯错的点:**

1. **不理解地址族和网络类型的对应关系:**  容易混淆 "tcp"、"tcp4" 和 "tcp6"，导致在期望使用 IPv4 或 IPv6 时创建了错误的套接字。例如，尝试用 "tcp4" 连接到 IPv6 地址或监听 IPv6 地址。

   ```go
   // 错误示例：尝试用 tcp4 拨号 IPv6 地址
   conn, err := net.Dial("tcp4", "[2001:db8::1]:80")
   if err != nil {
       fmt.Println("拨号失败:", err) // 可能会因为地址族不匹配而失败
   }
   ```

2. **在监听通配符地址时对 IPv4 和 IPv6 的行为理解不足:**  开发者可能不清楚在监听 "tcp" 时，系统如何处理 IPv4 和 IPv6 连接，以及 `IPV6_V6ONLY` 选项的影响。期望只监听 IPv4 或 IPv6，但实际监听了两者（或反之）。

3. **直接使用 `favoriteAddrFamily` 或 `ipToSockaddr` 等 `linkname` 函数:**  这些函数被标记为 `//go:linkname`，意味着它们是内部实现细节，不应该被外部包直接调用。依赖这些函数可能会导致代码在 Go 版本升级时出现兼容性问题。例如，`github.com/database64128/tfo-go/v2` 等包就因为使用了这些内部函数而需要特别注意兼容性。

**命令行参数:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并通过 `flag` 包或其他方式传递给 `net` 包的函数，例如 `net.Dial` 或 `net.Listen`。`net` 包内部的这些函数会间接地使用这段代码中定义的函数来创建和配置套接字。

**总结:**

这段代码是 Go 语言 `net` 包中处理 IP 套接字的核心部分，负责探测系统能力、选择合适的地址族、以及在 Go 的网络类型和操作系统底层的 socket API 之间进行转换。理解这些功能有助于开发者更好地使用 Go 的网络编程功能，并避免一些常见的错误。

### 提示词
```
这是路径为go/src/net/ipsock_posix.go的go语言实现的一部分， 请列举一下它的功能, 　
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

//go:build unix || js || wasip1 || windows

package net

import (
	"context"
	"internal/poll"
	"net/netip"
	"runtime"
	"syscall"
	_ "unsafe" // for linkname
)

// probe probes IPv4, IPv6 and IPv4-mapped IPv6 communication
// capabilities which are controlled by the IPV6_V6ONLY socket option
// and kernel configuration.
//
// Should we try to use the IPv4 socket interface if we're only
// dealing with IPv4 sockets? As long as the host system understands
// IPv4-mapped IPv6, it's okay to pass IPv4-mapped IPv6 addresses to
// the IPv6 interface. That simplifies our code and is most
// general. Unfortunately, we need to run on kernels built without
// IPv6 support too. So probe the kernel to figure it out.
func (p *ipStackCapabilities) probe() {
	switch runtime.GOOS {
	case "js", "wasip1":
		// Both ipv4 and ipv6 are faked; see net_fake.go.
		p.ipv4Enabled = true
		p.ipv6Enabled = true
		p.ipv4MappedIPv6Enabled = true
		return
	}

	s, err := sysSocket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	switch err {
	case syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT:
	case nil:
		poll.CloseFunc(s)
		p.ipv4Enabled = true
	}
	var probes = []struct {
		laddr TCPAddr
		value int
	}{
		// IPv6 communication capability
		{laddr: TCPAddr{IP: ParseIP("::1")}, value: 1},
		// IPv4-mapped IPv6 address communication capability
		{laddr: TCPAddr{IP: IPv4(127, 0, 0, 1)}, value: 0},
	}
	switch runtime.GOOS {
	case "dragonfly", "openbsd":
		// The latest DragonFly BSD and OpenBSD kernels don't
		// support IPV6_V6ONLY=0. They always return an error
		// and we don't need to probe the capability.
		probes = probes[:1]
	}
	for i := range probes {
		s, err := sysSocket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
		if err != nil {
			continue
		}
		defer poll.CloseFunc(s)
		syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, probes[i].value)
		sa, err := probes[i].laddr.sockaddr(syscall.AF_INET6)
		if err != nil {
			continue
		}
		if err := syscall.Bind(s, sa); err != nil {
			continue
		}
		if i == 0 {
			p.ipv6Enabled = true
		} else {
			p.ipv4MappedIPv6Enabled = true
		}
	}
}

// favoriteAddrFamily returns the appropriate address family for the
// given network, laddr, raddr and mode.
//
// If mode indicates "listen" and laddr is a wildcard, we assume that
// the user wants to make a passive-open connection with a wildcard
// address family, both AF_INET and AF_INET6, and a wildcard address
// like the following:
//
//   - A listen for a wildcard communication domain, "tcp" or
//     "udp", with a wildcard address: If the platform supports
//     both IPv6 and IPv4-mapped IPv6 communication capabilities,
//     or does not support IPv4, we use a dual stack, AF_INET6 and
//     IPV6_V6ONLY=0, wildcard address listen. The dual stack
//     wildcard address listen may fall back to an IPv6-only,
//     AF_INET6 and IPV6_V6ONLY=1, wildcard address listen.
//     Otherwise we prefer an IPv4-only, AF_INET, wildcard address
//     listen.
//
//   - A listen for a wildcard communication domain, "tcp" or
//     "udp", with an IPv4 wildcard address: same as above.
//
//   - A listen for a wildcard communication domain, "tcp" or
//     "udp", with an IPv6 wildcard address: same as above.
//
//   - A listen for an IPv4 communication domain, "tcp4" or "udp4",
//     with an IPv4 wildcard address: We use an IPv4-only, AF_INET,
//     wildcard address listen.
//
//   - A listen for an IPv6 communication domain, "tcp6" or "udp6",
//     with an IPv6 wildcard address: We use an IPv6-only, AF_INET6
//     and IPV6_V6ONLY=1, wildcard address listen.
//
// Otherwise guess: If the addresses are IPv4 then returns AF_INET,
// or else returns AF_INET6. It also returns a boolean value what
// designates IPV6_V6ONLY option.
//
// Note that the latest DragonFly BSD and OpenBSD kernels allow
// neither "net.inet6.ip6.v6only=1" change nor IPPROTO_IPV6 level
// IPV6_V6ONLY socket option setting.
//
// favoriteAddrFamily should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/database64128/tfo-go/v2
//   - github.com/metacubex/tfo-go
//   - github.com/sagernet/tfo-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname favoriteAddrFamily
func favoriteAddrFamily(network string, laddr, raddr sockaddr, mode string) (family int, ipv6only bool) {
	switch network[len(network)-1] {
	case '4':
		return syscall.AF_INET, false
	case '6':
		return syscall.AF_INET6, true
	}

	if mode == "listen" && (laddr == nil || laddr.isWildcard()) {
		if supportsIPv4map() || !supportsIPv4() {
			return syscall.AF_INET6, false
		}
		if laddr == nil {
			return syscall.AF_INET, false
		}
		return laddr.family(), false
	}

	if (laddr == nil || laddr.family() == syscall.AF_INET) &&
		(raddr == nil || raddr.family() == syscall.AF_INET) {
		return syscall.AF_INET, false
	}
	return syscall.AF_INET6, false
}

func internetSocket(ctx context.Context, net string, laddr, raddr sockaddr, sotype, proto int, mode string, ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (fd *netFD, err error) {
	switch runtime.GOOS {
	case "aix", "windows", "openbsd", "js", "wasip1":
		if mode == "dial" && raddr.isWildcard() {
			raddr = raddr.toLocal(net)
		}
	}
	family, ipv6only := favoriteAddrFamily(net, laddr, raddr, mode)
	return socket(ctx, net, family, sotype, proto, ipv6only, laddr, raddr, ctrlCtxFn)
}

func ipToSockaddrInet4(ip IP, port int) (syscall.SockaddrInet4, error) {
	if len(ip) == 0 {
		ip = IPv4zero
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return syscall.SockaddrInet4{}, &AddrError{Err: "non-IPv4 address", Addr: ip.String()}
	}
	sa := syscall.SockaddrInet4{Port: port}
	copy(sa.Addr[:], ip4)
	return sa, nil
}

func ipToSockaddrInet6(ip IP, port int, zone string) (syscall.SockaddrInet6, error) {
	// In general, an IP wildcard address, which is either
	// "0.0.0.0" or "::", means the entire IP addressing
	// space. For some historical reason, it is used to
	// specify "any available address" on some operations
	// of IP node.
	//
	// When the IP node supports IPv4-mapped IPv6 address,
	// we allow a listener to listen to the wildcard
	// address of both IP addressing spaces by specifying
	// IPv6 wildcard address.
	if len(ip) == 0 || ip.Equal(IPv4zero) {
		ip = IPv6zero
	}
	// We accept any IPv6 address including IPv4-mapped
	// IPv6 address.
	ip6 := ip.To16()
	if ip6 == nil {
		return syscall.SockaddrInet6{}, &AddrError{Err: "non-IPv6 address", Addr: ip.String()}
	}
	sa := syscall.SockaddrInet6{Port: port, ZoneId: uint32(zoneCache.index(zone))}
	copy(sa.Addr[:], ip6)
	return sa, nil
}

// ipToSockaddr should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/database64128/tfo-go/v2
//   - github.com/metacubex/tfo-go
//   - github.com/sagernet/tfo-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname ipToSockaddr
func ipToSockaddr(family int, ip IP, port int, zone string) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		sa, err := ipToSockaddrInet4(ip, port)
		if err != nil {
			return nil, err
		}
		return &sa, nil
	case syscall.AF_INET6:
		sa, err := ipToSockaddrInet6(ip, port, zone)
		if err != nil {
			return nil, err
		}
		return &sa, nil
	}
	return nil, &AddrError{Err: "invalid address family", Addr: ip.String()}
}

func addrPortToSockaddrInet4(ap netip.AddrPort) (syscall.SockaddrInet4, error) {
	// ipToSockaddrInet4 has special handling here for zero length slices.
	// We do not, because netip has no concept of a generic zero IP address.
	addr := ap.Addr()
	if !addr.Is4() {
		return syscall.SockaddrInet4{}, &AddrError{Err: "non-IPv4 address", Addr: addr.String()}
	}
	sa := syscall.SockaddrInet4{
		Addr: addr.As4(),
		Port: int(ap.Port()),
	}
	return sa, nil
}

func addrPortToSockaddrInet6(ap netip.AddrPort) (syscall.SockaddrInet6, error) {
	// ipToSockaddrInet6 has special handling here for zero length slices.
	// We do not, because netip has no concept of a generic zero IP address.
	//
	// addr is allowed to be an IPv4 address, because As16 will convert it
	// to an IPv4-mapped IPv6 address.
	// The error message is kept consistent with ipToSockaddrInet6.
	addr := ap.Addr()
	if !addr.IsValid() {
		return syscall.SockaddrInet6{}, &AddrError{Err: "non-IPv6 address", Addr: addr.String()}
	}
	sa := syscall.SockaddrInet6{
		Addr:   addr.As16(),
		Port:   int(ap.Port()),
		ZoneId: uint32(zoneCache.index(addr.Zone())),
	}
	return sa, nil
}
```