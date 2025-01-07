Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Understanding - Purpose and Context:**

   - The file path `go/src/net/ipsock.go` immediately suggests this code deals with low-level network operations within the `net` package of the Go standard library. The name "ipsock" hints at handling IP addresses and potentially socket-related functionality.

2. **Copyright and BUG Comment:**

   - The copyright notice confirms it's part of the Go standard library.
   - The `BUG` comment is crucial. It highlights a platform-specific limitation on DragonFly BSD and OpenBSD regarding listening on both IPv4 and IPv6 with a single socket. This gives us an early indication that the code might be involved in handling different IP versions.

3. **`ipStackCapabilities` Structure:**

   - This structure, with a `sync.Once`, clearly indicates a mechanism to detect and cache IP stack capabilities (IPv4, IPv6, IPv4-mapped IPv6). The `sync.Once` ensures this detection happens only once. This suggests the code is involved in determining what networking features are available on the current system.

4. **`supportsIPv4`, `supportsIPv6`, `supportsIPv4map` Functions:**

   - These functions directly use the `ipStackCapabilities` to report the availability of different IP versions. This reinforces the idea that the code is concerned with IP version support. The `ipStackCaps.probe()` call within the `Once.Do` suggests a function (not shown in the snippet) is responsible for the actual capability detection.

5. **`addrList` Type and Related Functions:**

   - `addrList` is a slice of `Addr` (interface representing a network address).
   - `isIPv4` and `isNotIPv4` are utility functions to check the IP version of an `Addr`.
   - `forResolve`:  This function selects an address from an `addrList` based on the desired network (TCP, UDP, IP) and whether the address string contains an IPv6 literal (indicated by colons or square brackets). The preference for IPv4 unless an IPv6 literal is provided is important.
   - `first`: A helper to find the first address matching a given criteria.
   - `partition`: Divides the address list into primaries and fallbacks based on the first address's IP version. This suggests a strategy for trying different addresses.
   - `filterAddrList`:  Filters a list of `IPAddr` based on `ipv4only` or `ipv6only` criteria. The error handling for no suitable addresses is also significant.

6. **`ipv4only` and `ipv6only` Functions:**

   - Simple filters to determine if an `IPAddr` is IPv4 or IPv6 (excluding IPv4-mapped).

7. **`SplitHostPort` Function:**

   - This function is about parsing network addresses ("host:port"). It handles IPv6 literals enclosed in square brackets and considers zone identifiers. The error handling for malformed addresses is important.

8. **`splitHostZone` Function:**

   - Extracts the host and zone identifier from an address string.

9. **`JoinHostPort` Function:**

   - The inverse of `SplitHostPort`. It formats a host and port into a network address, adding square brackets for IPv6 literals.

10. **`internetAddrList` Function:**

   - This is a core function for resolving network addresses. It takes a network type (e.g., "tcp", "udp") and an address string.
   - It uses `SplitHostPort` to separate host and port.
   - It uses a `Resolver` (not fully defined in the snippet) to perform DNS lookups (`r.LookupPort`, `r.lookupIPAddr`).
   - It handles the case where the host is an empty string (representing the "any" address).
   - It includes a fallback mechanism for IPv6 configuration issues (issue 18806).
   - It applies filters (`ipv4only`, `ipv6only`) based on the network type.

11. **`loopbackIP` Function:**

   - Returns the loopback IP address for a given network type (IPv4 or IPv6). The comments about its external usage via `linkname` are important for understanding its unexpected accessibility.

12. **Inferring Go Functionality:**

   - Based on the functions, types, and the `net` package context, the primary functionality implemented in this code is **network address resolution and manipulation**. It helps in:
     - Determining IP stack capabilities.
     - Parsing and formatting network addresses (host:port).
     - Resolving hostnames to IP addresses.
     - Filtering IP addresses based on IP version.
     - Selecting appropriate addresses based on network type and address format.

13. **Code Examples (and Reasoning for Input/Output):**

   - For `SplitHostPort`: Choose examples with IPv4, IPv6 (with and without zone), and invalid formats to demonstrate different parsing scenarios.
   - For `JoinHostPort`: Provide IPv4 and IPv6 hostnames to show how the function handles them.
   - For `internetAddrList`:  Use examples that trigger DNS resolution (valid hostname), direct IP address usage, and scenarios with specific network types (tcp4, tcp6) to demonstrate filtering. Also include a case with an empty address.

14. **Command-Line Arguments:**

   - Since this code is part of the `net` package, it's used *internally* by other Go programs. It doesn't directly process command-line arguments. Focus on how other `net` package functions (like `Dial`) might indirectly use this code and receive host/port from command-line arguments.

15. **Common Mistakes:**

   - Focus on errors related to address formatting (`SplitHostPort`), network type mismatches (`internetAddrList`), and the platform-specific IPv6 listening issue mentioned in the `BUG` comment.

16. **Language - Chinese:**

   - Ensure all explanations and examples are provided in clear and accurate Chinese.

**Self-Correction/Refinement during the process:**

- **Initial thought:** Maybe this is just about socket creation.
- **Correction:** The presence of `SplitHostPort`, `JoinHostPort`, and `internetAddrList` strongly indicates address parsing and resolution are key functions.
- **Initial thought:**  The `ipStackCapabilities` might be about low-level socket options.
- **Correction:**  The names `ipv4Enabled`, `ipv6Enabled`, and the `probe` function suggest it's about *detecting* IP stack features, not configuring sockets directly.
- **Initial thought:** Focus heavily on the `linkname` aspect of `loopbackIP`.
- **Correction:** While the `linkname` is notable, the core functionality of the function itself (returning loopback IPs) is more important for a general understanding. Mention the `linkname` as an interesting quirk.
这段代码是 Go 语言标准库 `net` 包中 `ipsock.go` 文件的一部分，它主要负责处理与 **IP 地址和网络协议栈**相关的底层操作和信息获取。以下是其主要功能：

**1. 探测和报告 IP 协议栈能力:**

   - **`ipStackCapabilities` 结构体:**  用于存储当前操作系统网络协议栈的 IPv4、IPv6 和 IPv4-mapped IPv6 的支持情况。`sync.Once` 确保探测操作只执行一次。
   - **`supportsIPv4()` 函数:**  返回当前平台是否支持 IPv4 网络功能。
   - **`supportsIPv6()` 函数:**  返回当前平台是否支持 IPv6 网络功能。
   - **`supportsIPv4map()` 函数:** 返回当前平台是否支持将 IPv4 地址映射到 IPv6 地址。这个功能在某些操作系统上不受支持（例如 DragonFly BSD 和 OpenBSD）。

**2. 处理和过滤网络地址列表 (`addrList`):**

   - **`addrList` 类型:**  表示网络端点地址的列表，底层是 `[]Addr`，其中 `Addr` 是一个接口，可以代表 `TCPAddr`, `UDPAddr`, `IPAddr` 等具体地址类型。
   - **`isIPv4(addr Addr)` 函数:**  判断给定的 `Addr` 是否包含 IPv4 地址。
   - **`isNotIPv4(addr Addr)` 函数:** 判断给定的 `Addr` 是否不包含 IPv4 地址。
   - **`forResolve(network, addr string) Addr` 函数:**  根据网络类型和地址字符串，从地址列表中选择最合适的地址用于 `ResolveTCPAddr`, `ResolveUDPAddr` 或 `ResolveIPAddr` 等解析函数。它会优先选择 IPv4 地址，除非地址字符串明显是 IPv6 字面量（包含冒号或者用方括号括起来）。
   - **`first(strategy func(Addr) bool) Addr` 函数:** 返回地址列表中第一个满足给定策略的地址，如果没有满足的，则返回列表中的第一个地址。
   - **`partition(strategy func(Addr) bool) (primaries, fallbacks addrList)` 函数:**  将地址列表根据给定的策略函数分成两部分：`primaries`（主要部分，包含第一个地址以及后续满足策略的地址）和 `fallbacks`（不满足策略的地址）。
   - **`filterAddrList(filter func(IPAddr) bool, ips []IPAddr, inetaddr func(IPAddr) Addr, originalAddr string) (addrList, error)` 函数:**  根据给定的过滤器 (`nil`, `ipv4only`, `ipv6only`) 过滤 IP 地址列表，并将其转换为 `addrList`。如果过滤后没有地址，则返回错误。
   - **`ipv4only(addr IPAddr)` 函数:**  判断给定的 `IPAddr` 是否是 IPv4 地址。
   - **`ipv6only(addr IPAddr)` 函数:** 判断给定的 `IPAddr` 是否是 IPv6 地址（不包含 IPv4-mapped IPv6 地址）。

**3. 解析和组合主机名和端口:**

   - **`SplitHostPort(hostport string) (host, port string, err error)` 函数:**  将形如 "host:port", "host%zone:port", "[host]:port" 或 "[host%zone]:port" 的网络地址字符串拆分成主机名（或带 Zone ID 的主机名）和端口号。它能处理 IPv6 字面量地址，这种地址需要用方括号括起来。
   - **`splitHostZone(s string) (host, zone string)` 函数:**  将包含 Zone ID 的主机名（IPv6 的 scope）拆分成主机名和 Zone ID。
   - **`JoinHostPort(host, port string) string` 函数:**  将主机名和端口号组合成网络地址字符串。如果主机名包含冒号（说明是 IPv6 字面量），则会用方括号括起来。

**4. 解析网络地址列表 (`internetAddrList`):**

   - **`internetAddrList(ctx context.Context, net, addr string) (addrList, error)` 函数:**  这是核心的地址解析函数。它接收上下文、网络类型（如 "tcp", "udp"）和地址字符串，然后解析该地址，返回一个包含所有解析到的网络地址的列表。
   - 它首先根据网络类型调用 `SplitHostPort` 分离主机名和端口。
   - 然后使用 `Resolver` (一个结构体，用于进行 DNS 解析，这里只使用了它的方法) 的 `LookupPort` 方法查找端口号，并使用 `lookupIPAddr` 方法进行 IP 地址查找（可能是 DNS 解析）。
   - 如果主机名为空，则返回一个代表 "any" 地址的 `addrList`。
   - 它会尝试将地址字符串解析为字面 IP 地址，如果失败则尝试进行 DNS 解析。
   - 特别处理了 IPv6 配置不完整的情况（Issue 18806），如果解析到的唯一地址是 IPv6 未指定地址 "::"，则会回退到 IPv4 的 0.0.0.0。
   - 最后，根据网络类型（如 "tcp4", "tcp6"）使用 `filterAddrList` 来过滤得到的 IP 地址列表。

**5. 获取回环地址:**

   - **`loopbackIP(net string) IP` 函数:**  根据给定的网络类型（"ip6" 或其他）返回对应的回环 IP 地址（IPv6 的 `::1` 或 IPv4 的 `127.0.0.1`）。
   - **`//go:linkname loopbackIP` 注释** 表明这个函数虽然是内部细节，但被其他包通过 `linkname` 机制访问，这是一种不常见的做法，通常用于绕过 Go 的包访问限制。

**它可以被推理为 Go 语言网络编程中用于处理 IP 地址和进行地址解析的基础设施实现。**  它封装了与 IP 版本检测、地址字符串解析、DNS 查询以及地址过滤等相关的逻辑，为更高级的网络操作（如建立连接、监听端口）提供了必要的支持。

**Go 代码举例说明 `internetAddrList` 的功能:**

```go
package main

import (
	"context"
	"fmt"
	"net"
)

func main() {
	resolver := &net.Resolver{}
	ctx := context.Background()

	// 解析 TCP 地址
	addrs, err := resolver.InternetAddrList(ctx, "tcp", "www.google.com:80")
	if err != nil {
		fmt.Println("解析 TCP 地址失败:", err)
	} else {
		fmt.Println("www.google.com:80 的 TCP 地址:")
		for _, addr := range addrs {
			fmt.Println(addr)
		}
	}

	// 解析 UDP 地址
	addrs, err = resolver.InternetAddrList(ctx, "udp", "localhost:53")
	if err != nil {
		fmt.Println("解析 UDP 地址失败:", err)
	} else {
		fmt.Println("localhost:53 的 UDP 地址:")
		for _, addr := range addrs {
			fmt.Println(addr)
		}
	}

	// 解析 IP 地址 (不带端口)
	addrs, err = resolver.InternetAddrList(ctx, "ip", "::1")
	if err != nil {
		fmt.Println("解析 IP 地址失败:", err)
	} else {
		fmt.Println("::1 的 IP 地址:")
		for _, addr := range addrs {
			fmt.Println(addr)
		}
	}

	// 解析 IPv4 地址
	addrs, err = resolver.InternetAddrList(ctx, "tcp4", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("解析 IPv4 地址失败:", err)
	} else {
		fmt.Println("127.0.0.1:8080 的 IPv4 地址:")
		for _, addr := range addrs {
			fmt.Println(addr)
		}
	}
}
```

**假设的输入与输出:**

假设运行上述代码的机器能够正常访问互联网并解析 DNS。

**输入:**

- `resolver.InternetAddrList(ctx, "tcp", "www.google.com:80")`
- `resolver.InternetAddrList(ctx, "udp", "localhost:53")`
- `resolver.InternetAddrList(ctx, "ip", "::1")`
- `resolver.InternetAddrList(ctx, "tcp4", "127.0.0.1:8080")`

**可能的输出:**

```
www.google.com:80 的 TCP 地址:
&{216.58.209.142 80 } <nil>  // 具体的 IP 地址可能不同
&{[2404:6800:4005:80b::200e] 80 } <nil> // 具体的 IP 地址可能不同
localhost:53 的 UDP 地址:
&{127.0.0.1 53 } <nil>
&{[::1] 53 } <nil>
::1 的 IP 地址:
&{[::1]  }
127.0.0.1:8080 的 IPv4 地址:
&{127.0.0.1 8080 } <nil>
```

**涉及命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。但是，使用 `net` 包的 Go 程序可能会从命令行参数中获取主机名和端口信息，然后传递给 `net` 包中的函数，例如 `net.Dial` 或 `net.Listen`。

例如，一个简单的 TCP 客户端程序可能接收服务器地址作为命令行参数：

```go
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s host:port\n", os.Args[0])
		os.Exit(1)
	}
	serverAddr := os.Args[1]

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("连接服务器失败:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("成功连接到", conn.RemoteAddr())
	// ... 进行数据传输 ...
}
```

在这个例子中，`os.Args[1]` 就是从命令行获取的服务器地址，它会被传递给 `net.Dial` 函数，而 `net.Dial` 内部可能会使用到 `ipsock.go` 中的函数来解析 `serverAddr`。

**使用者易犯错的点:**

1. **`SplitHostPort` 对 IPv6 地址的格式要求:**  初学者容易忘记 IPv6 字面量地址需要用方括号括起来，例如 `"[::1]:80"` 而不是 `::1:80`。如果格式不正确，`SplitHostPort` 会返回错误。

   ```go
   host, port, err := net.SplitHostPort("::1:80")
   if err != nil {
       fmt.Println("错误:", err) // 输出: 错误: missing port in address
   }

   host, port, err = net.SplitHostPort("[::1]:80")
   if err != nil {
       fmt.Println("错误:", err)
   } else {
       fmt.Println("Host:", host, "Port:", port) // 输出: Host: ::1 Port: 80
   }
   ```

2. **在不支持 IPv6 的系统上尝试使用 IPv6 相关功能:**  如果程序尝试连接或监听 IPv6 地址，但在运行的操作系统上 IPv6 未启用或不支持，会导致连接失败或监听失败。`supportsIPv6()` 可以用来预先检查。

3. **混淆网络类型:**  在 `internetAddrList` 或 `net.Dial` 等函数中，错误地指定网络类型（例如，使用 "tcp4" 但传入的地址是 IPv6 地址）会导致解析或连接错误。

   ```go
   resolver := &net.Resolver{}
   ctx := context.Background()
   addrs, err := resolver.InternetAddrList(ctx, "tcp4", "[::1]:80")
   if err != nil {
       fmt.Println("错误:", err) // 可能会输出 "no suitable address found" 类似的错误
   }
   ```

4. **忽略 `BUG` 注释中提到的平台限制:**  在 DragonFly BSD 和 OpenBSD 上，监听 "tcp" 或 "udp" 网络时，默认不会同时监听 IPv4 和 IPv6 连接。开发者需要创建两个独立的 socket 来支持两种地址族。这是一个平台相关的陷阱。

Prompt: 
```
这是路径为go/src/net/ipsock.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"context"
	"internal/bytealg"
	"runtime"
	"sync"
	_ "unsafe" // for linkname
)

// BUG(rsc,mikio): On DragonFly BSD and OpenBSD, listening on the
// "tcp" and "udp" networks does not listen for both IPv4 and IPv6
// connections. This is due to the fact that IPv4 traffic will not be
// routed to an IPv6 socket - two separate sockets are required if
// both address families are to be supported.
// See inet6(4) for details.

type ipStackCapabilities struct {
	sync.Once             // guards following
	ipv4Enabled           bool
	ipv6Enabled           bool
	ipv4MappedIPv6Enabled bool
}

var ipStackCaps ipStackCapabilities

// supportsIPv4 reports whether the platform supports IPv4 networking
// functionality.
func supportsIPv4() bool {
	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv4Enabled
}

// supportsIPv6 reports whether the platform supports IPv6 networking
// functionality.
func supportsIPv6() bool {
	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv6Enabled
}

// supportsIPv4map reports whether the platform supports mapping an
// IPv4 address inside an IPv6 address at transport layer
// protocols. See RFC 4291, RFC 4038 and RFC 3493.
func supportsIPv4map() bool {
	// Some operating systems provide no support for mapping IPv4
	// addresses to IPv6, and a runtime check is unnecessary.
	switch runtime.GOOS {
	case "dragonfly", "openbsd":
		return false
	}

	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv4MappedIPv6Enabled
}

// An addrList represents a list of network endpoint addresses.
type addrList []Addr

// isIPv4 reports whether addr contains an IPv4 address.
func isIPv4(addr Addr) bool {
	switch addr := addr.(type) {
	case *TCPAddr:
		return addr.IP.To4() != nil
	case *UDPAddr:
		return addr.IP.To4() != nil
	case *IPAddr:
		return addr.IP.To4() != nil
	}
	return false
}

// isNotIPv4 reports whether addr does not contain an IPv4 address.
func isNotIPv4(addr Addr) bool { return !isIPv4(addr) }

// forResolve returns the most appropriate address in address for
// a call to ResolveTCPAddr, ResolveUDPAddr, or ResolveIPAddr.
// IPv4 is preferred, unless addr contains an IPv6 literal.
func (addrs addrList) forResolve(network, addr string) Addr {
	var want6 bool
	switch network {
	case "ip":
		// IPv6 literal (addr does NOT contain a port)
		want6 = bytealg.CountString(addr, ':') > 0
	case "tcp", "udp":
		// IPv6 literal. (addr contains a port, so look for '[')
		want6 = bytealg.CountString(addr, '[') > 0
	}
	if want6 {
		return addrs.first(isNotIPv4)
	}
	return addrs.first(isIPv4)
}

// first returns the first address which satisfies strategy, or if
// none do, then the first address of any kind.
func (addrs addrList) first(strategy func(Addr) bool) Addr {
	for _, addr := range addrs {
		if strategy(addr) {
			return addr
		}
	}
	return addrs[0]
}

// partition divides an address list into two categories, using a
// strategy function to assign a boolean label to each address.
// The first address, and any with a matching label, are returned as
// primaries, while addresses with the opposite label are returned
// as fallbacks. For non-empty inputs, primaries is guaranteed to be
// non-empty.
func (addrs addrList) partition(strategy func(Addr) bool) (primaries, fallbacks addrList) {
	var primaryLabel bool
	for i, addr := range addrs {
		label := strategy(addr)
		if i == 0 || label == primaryLabel {
			primaryLabel = label
			primaries = append(primaries, addr)
		} else {
			fallbacks = append(fallbacks, addr)
		}
	}
	return
}

// filterAddrList applies a filter to a list of IP addresses,
// yielding a list of Addr objects. Known filters are nil, ipv4only,
// and ipv6only. It returns every address when the filter is nil.
// The result contains at least one address when error is nil.
func filterAddrList(filter func(IPAddr) bool, ips []IPAddr, inetaddr func(IPAddr) Addr, originalAddr string) (addrList, error) {
	var addrs addrList
	for _, ip := range ips {
		if filter == nil || filter(ip) {
			addrs = append(addrs, inetaddr(ip))
		}
	}
	if len(addrs) == 0 {
		return nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: originalAddr}
	}
	return addrs, nil
}

// ipv4only reports whether addr is an IPv4 address.
func ipv4only(addr IPAddr) bool {
	return addr.IP.To4() != nil
}

// ipv6only reports whether addr is an IPv6 address except IPv4-mapped IPv6 address.
func ipv6only(addr IPAddr) bool {
	return len(addr.IP) == IPv6len && addr.IP.To4() == nil
}

// SplitHostPort splits a network address of the form "host:port",
// "host%zone:port", "[host]:port" or "[host%zone]:port" into host or
// host%zone and port.
//
// A literal IPv6 address in hostport must be enclosed in square
// brackets, as in "[::1]:80", "[::1%lo0]:80".
//
// See func Dial for a description of the hostport parameter, and host
// and port results.
func SplitHostPort(hostport string) (host, port string, err error) {
	const (
		missingPort   = "missing port in address"
		tooManyColons = "too many colons in address"
	)
	addrErr := func(addr, why string) (host, port string, err error) {
		return "", "", &AddrError{Err: why, Addr: addr}
	}
	j, k := 0, 0

	// The port starts after the last colon.
	i := bytealg.LastIndexByteString(hostport, ':')
	if i < 0 {
		return addrErr(hostport, missingPort)
	}

	if hostport[0] == '[' {
		// Expect the first ']' just before the last ':'.
		end := bytealg.IndexByteString(hostport, ']')
		if end < 0 {
			return addrErr(hostport, "missing ']' in address")
		}
		switch end + 1 {
		case len(hostport):
			// There can't be a ':' behind the ']' now.
			return addrErr(hostport, missingPort)
		case i:
			// The expected result.
		default:
			// Either ']' isn't followed by a colon, or it is
			// followed by a colon that is not the last one.
			if hostport[end+1] == ':' {
				return addrErr(hostport, tooManyColons)
			}
			return addrErr(hostport, missingPort)
		}
		host = hostport[1:end]
		j, k = 1, end+1 // there can't be a '[' resp. ']' before these positions
	} else {
		host = hostport[:i]
		if bytealg.IndexByteString(host, ':') >= 0 {
			return addrErr(hostport, tooManyColons)
		}
	}
	if bytealg.IndexByteString(hostport[j:], '[') >= 0 {
		return addrErr(hostport, "unexpected '[' in address")
	}
	if bytealg.IndexByteString(hostport[k:], ']') >= 0 {
		return addrErr(hostport, "unexpected ']' in address")
	}

	port = hostport[i+1:]
	return host, port, nil
}

func splitHostZone(s string) (host, zone string) {
	// The IPv6 scoped addressing zone identifier starts after the
	// last percent sign.
	if i := bytealg.LastIndexByteString(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

// JoinHostPort combines host and port into a network address of the
// form "host:port". If host contains a colon, as found in literal
// IPv6 addresses, then JoinHostPort returns "[host]:port".
//
// See func Dial for a description of the host and port parameters.
func JoinHostPort(host, port string) string {
	// We assume that host is a literal IPv6 address if host has
	// colons.
	if bytealg.IndexByteString(host, ':') >= 0 {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// internetAddrList resolves addr, which may be a literal IP
// address or a DNS name, and returns a list of internet protocol
// family addresses. The result contains at least one address when
// error is nil.
func (r *Resolver) internetAddrList(ctx context.Context, net, addr string) (addrList, error) {
	var (
		err        error
		host, port string
		portnum    int
	)
	switch net {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if addr != "" {
			if host, port, err = SplitHostPort(addr); err != nil {
				return nil, err
			}
			if portnum, err = r.LookupPort(ctx, net, port); err != nil {
				return nil, err
			}
		}
	case "ip", "ip4", "ip6":
		if addr != "" {
			host = addr
		}
	default:
		return nil, UnknownNetworkError(net)
	}
	inetaddr := func(ip IPAddr) Addr {
		switch net {
		case "tcp", "tcp4", "tcp6":
			return &TCPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "udp", "udp4", "udp6":
			return &UDPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "ip", "ip4", "ip6":
			return &IPAddr{IP: ip.IP, Zone: ip.Zone}
		default:
			panic("unexpected network: " + net)
		}
	}
	if host == "" {
		return addrList{inetaddr(IPAddr{})}, nil
	}

	// Try as a literal IP address, then as a DNS name.
	ips, err := r.lookupIPAddr(ctx, net, host)
	if err != nil {
		return nil, err
	}
	// Issue 18806: if the machine has halfway configured
	// IPv6 such that it can bind on "::" (IPv6unspecified)
	// but not connect back to that same address, fall
	// back to dialing 0.0.0.0.
	if len(ips) == 1 && ips[0].IP.Equal(IPv6unspecified) {
		ips = append(ips, IPAddr{IP: IPv4zero})
	}

	var filter func(IPAddr) bool
	if net != "" && net[len(net)-1] == '4' {
		filter = ipv4only
	}
	if net != "" && net[len(net)-1] == '6' {
		filter = ipv6only
	}
	return filterAddrList(filter, ips, inetaddr, host)
}

// loopbackIP should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/database64128/tfo-go/v2
//   - github.com/metacubex/tfo-go
//   - github.com/sagernet/tfo-go
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname loopbackIP
func loopbackIP(net string) IP {
	if net != "" && net[len(net)-1] == '6' {
		return IPv6loopback
	}
	return IP{127, 0, 0, 1}
}

"""



```