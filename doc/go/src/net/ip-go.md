Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The primary goal is to analyze the Go code related to IP addresses and networking, specifically the `net/ip.go` file (or a portion of it). The request asks for functionality, related Go features, examples, potential errors, and all in Chinese.

2. **Initial Scan and Keyword Identification:**  I'll quickly read through the code, looking for keywords and patterns that indicate the purpose of different sections. Keywords like `IP`, `IPMask`, `IPNet`, `IPv4`, `IPv6`, `Mask`, `String`, `ParseIP`, `CIDR`, and function names like `IsUnspecified`, `IsLoopback`, `IsPrivate` jump out. These immediately suggest the code is about representing and manipulating IP addresses and networks.

3. **Identify Core Data Structures:** The code defines three main types:
    * `IP`: Represents a single IP address as a byte slice. Crucially, it notes that IPv4 addresses are handled as 16-byte slices internally by padding with a prefix.
    * `IPMask`: Represents an IP mask as a byte slice.
    * `IPNet`: Represents an IP network, containing an `IP` and an `IPMask`.

4. **Analyze Functions and Their Functionality (Categorization):**  I'll go through the defined functions and group them by their purpose.

    * **IP Creation/Representation:**
        * `IPv4(a, b, c, d byte) IP`: Creates an IPv4 address in 16-byte format.
        * `IPv4Mask(a, b, c, d byte) IPMask`: Creates an IPv4 mask.
        * `CIDRMask(ones, bits int) IPMask`: Creates a mask with a given number of leading ones.
        * `To4() IP`: Converts an IP to a 4-byte IPv4 representation (if possible).
        * `To16() IP`: Converts an IP to a 16-byte representation.
        * `String() string`: Returns a string representation of the IP.
        * `AppendText(b []byte) ([]byte, error)`: Appends the string representation to a byte slice.
        * `MarshalText() ([]byte, error)`:  Marshals to text (like `String`).
        * `UnmarshalText(text []byte) error`: Parses an IP from text.

    * **IP Property Checks:**
        * `IsUnspecified() bool`: Checks if the IP is 0.0.0.0 or ::.
        * `IsLoopback() bool`: Checks if the IP is a loopback address.
        * `IsPrivate() bool`: Checks if the IP is a private address.
        * `IsMulticast() bool`: Checks if the IP is a multicast address.
        * `IsInterfaceLocalMulticast() bool`: Checks for interface-local multicast.
        * `IsLinkLocalMulticast() bool`: Checks for link-local multicast.
        * `IsLinkLocalUnicast() bool`: Checks for link-local unicast.
        * `IsGlobalUnicast() bool`: Checks if it's a global unicast address.

    * **IP Manipulation:**
        * `Mask(mask IPMask) IP`: Applies a mask to an IP address.
        * `DefaultMask() IPMask`: Returns the default mask for an IPv4 address.
        * `Equal(x IP) bool`: Checks if two IPs are equal.

    * **Network Related:**
        * `IPNet`: Structure for representing a network.
        * `Contains(ip IP) bool`: Checks if a network contains a given IP.
        * `String() string` (for `IPNet`): Returns the CIDR notation.
        * `ParseCIDR(s string) (IP, *IPNet, error)`: Parses a CIDR string.

    * **Parsing:**
        * `ParseIP(s string) IP`: Parses a string into an IP address.
        * `parseIP(s string) ([16]byte, bool)`: (Internal helper for parsing).

5. **Identify Underlying Go Features:** I'll link the functionalities to core Go concepts:
    * **Data Structures:** Structs (`IPNet`), slices (`IP`, `IPMask`).
    * **String Manipulation:**  Functions like `String()` and parsing functions relate to string conversion and handling.
    * **Error Handling:** The use of `error` as a return type and the `ParseError` and `AddrError` structs indicate error management.
    * **Constants:**  `IPv4len`, `IPv6len`, and well-known addresses are defined as constants.
    * **Methods on Types:** The functions defined with a receiver (e.g., `(ip IP) IsLoopback()`) are methods.
    * **Internal Packages:** The code imports `internal/bytealg`, `internal/itoa`, and `internal/stringslite`, showing reliance on internal Go utilities.
    * **Third-party Packages (indirectly):**  It uses `net/netip`, which is a newer, more efficient IP address representation within the `net` package. This highlights how Go's standard library evolves.
    * **Interfaces:** `encoding.TextMarshaler` and `encoding.TextUnmarshaler` are implemented, showcasing interface usage for text serialization.

6. **Construct Examples:** For key functionalities, I'll create simple Go code examples. Crucially, I need to include *both* the code and the expected output (based on assumptions about the input). This demonstrates how the functions work in practice.

7. **Address Potential Pitfalls (User Errors):**  I'll think about common mistakes developers might make when using this code:
    * Mixing up IPv4 and IPv6 representations.
    * Incorrectly assuming the length of the `IP` slice.
    * Misunderstanding the meaning of the mask in `IPNet`.
    * Errors in parsing IP address strings.

8. **Structure the Answer in Chinese:** Finally, I'll organize the information logically and translate it into clear and concise Chinese, addressing each part of the original request. This involves:
    * Summarizing the overall functionality.
    * Listing specific functions and their roles.
    * Providing Go code examples with inputs and outputs.
    * Explaining the underlying Go features.
    * Pointing out common mistakes.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe I should explain the bitwise operations in the `CIDRMask` function in detail.
* **Correction:**  While interesting, focusing on the *functionality* is more important for a general understanding. I'll briefly mention its purpose but not get bogged down in the bit manipulation logic unless specifically asked.

* **Initial thought:**  Should I explain the internal details of `netip`?
* **Correction:**  No, the focus is on the provided code snippet. I'll acknowledge the usage of `netip` but won't delve into its implementation.

* **Ensuring clarity in examples:** I need to make sure the examples are self-contained and easy to understand, even for someone not deeply familiar with Go networking. Providing both the code and the expected output is crucial here.

By following these steps, I can systematically analyze the code and generate a comprehensive and helpful answer that meets all the requirements of the original request.
这段代码是 Go 语言标准库 `net` 包中 `ip.go` 文件的一部分，主要负责 **IP 地址和 IP 网络** 的表示和操作。 让我们详细列举一下它的功能：

**核心功能:**

1. **IP 地址表示 (`IP` 类型):**
   - 定义了 `IP` 类型，它是一个 `[]byte` 切片，用于表示 IPv4 或 IPv6 地址。
   - 强调内部统一使用 16 字节表示 IP 地址，即使是 IPv4 地址也会被转换为 IPv4-mapped IPv6 格式。

2. **IP 子网掩码表示 (`IPMask` 类型):**
   - 定义了 `IPMask` 类型，也是一个 `[]byte` 切片，用于表示 IP 子网掩码。

3. **IP 网络表示 (`IPNet` 类型):**
   - 定义了 `IPNet` 类型，包含一个 `IP` 地址和一个 `IPMask`，用于表示一个 IP 网络。

4. **创建 IP 地址:**
   - `IPv4(a, b, c, d byte) IP`:  创建一个 IPv4 地址的 `IP` 对象（内部表示为 16 字节的 IPv4-mapped IPv6 地址）。

5. **创建 IP 子网掩码:**
   - `IPv4Mask(a, b, c, d byte) IPMask`:  创建一个 IPv4 子网掩码的 `IPMask` 对象。
   - `CIDRMask(ones, bits int) IPMask`:  创建一个包含指定数量前导 1 的子网掩码，`bits` 参数指定掩码的总位数（32 for IPv4, 128 for IPv6）。

6. **预定义的常用 IP 地址:**
   - 定义了一些常用的 IPv4 和 IPv6 地址常量，如广播地址、组播地址、回环地址、零地址等。

7. **IP 地址属性判断:**
   - `IsUnspecified() bool`: 判断 IP 地址是否为未指定地址 (0.0.0.0 或 ::)。
   - `IsLoopback() bool`: 判断 IP 地址是否为回环地址 (127.0.0.1 或 ::1)。
   - `IsPrivate() bool`: 判断 IP 地址是否为私有地址 (根据 RFC 1918 和 RFC 4193)。
   - `IsMulticast() bool`: 判断 IP 地址是否为组播地址。
   - `IsInterfaceLocalMulticast() bool`: 判断 IP 地址是否为接口本地组播地址。
   - `IsLinkLocalMulticast() bool`: 判断 IP 地址是否为链路本地组播地址。
   - `IsLinkLocalUnicast() bool`: 判断 IP 地址是否为链路本地单播地址。
   - `IsGlobalUnicast() bool`: 判断 IP 地址是否为全局单播地址。

8. **IP 地址转换:**
   - `To4() IP`:  将 IP 地址转换为 4 字节的 IPv4 表示。如果不是 IPv4 地址，则返回 `nil`。
   - `To16() IP`: 将 IP 地址转换为 16 字节表示。如果长度不正确，则返回 `nil`。

9. **获取默认子网掩码:**
   - `DefaultMask() IPMask`:  根据 IPv4 地址的前缀获取默认的子网掩码 (A 类、B 类、C 类)。对于非 IPv4 地址返回 `nil`。

10. **IP 地址与子网掩码运算:**
    - `Mask(mask IPMask) IP`:  将 IP 地址与子网掩码进行按位与运算，得到网络地址。

11. **IP 地址的字符串表示:**
    - `String() string`: 返回 IP 地址的字符串表示，IPv4 使用点分十进制，IPv6 使用 RFC 5952 定义的格式，其他情况返回十六进制表示。
    - `AppendText(b []byte) ([]byte, error)`: 将 IP 地址的字符串表示追加到字节切片 `b` 中。
    - `MarshalText() ([]byte, error)`: 实现 `encoding.TextMarshaler` 接口，将 IP 地址序列化为文本。
    - `UnmarshalText(text []byte) error`: 实现 `encoding.TextUnmarshaler` 接口，从文本反序列化为 IP 地址。

12. **IP 地址比较:**
    - `Equal(x IP) bool`:  判断两个 IP 地址是否相等。考虑到 IPv4 地址和其 IPv4-mapped IPv6 表示是相等的。

13. **IP 子网掩码操作:**
    - `Size() (ones, bits int)`: 返回子网掩码中前导 1 的数量和总位数。

14. **IP 网络的表示和操作:**
    - `Contains(ip IP) bool`: 判断一个 IP 网络是否包含给定的 IP 地址。
    - `String() string` (for `IPNet`): 返回 IP 网络的 CIDR 表示 (如 "192.168.1.0/24")。如果掩码不是规范形式，则返回 IP 地址加上十六进制表示的掩码。

15. **解析 IP 地址和 CIDR:**
    - `ParseIP(s string) IP`: 将字符串解析为 IP 地址，支持 IPv4、IPv6 和 IPv4-mapped IPv6 格式。
    - `ParseCIDR(s string) (IP, *IPNet, error)`: 将 CIDR 格式的字符串解析为 IP 地址和 IP 网络。

**它是什么 Go 语言功能的实现:**

这段代码是 Go 语言标准库中 **网络编程** 的核心组成部分，特别是关于 IP 地址的处理。它提供了底层的 IP 地址表示和操作，是构建更高级网络功能的基石。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"net"
)

func main() {
	// 创建 IPv4 地址
	ipv4Addr := net.IPv4(192, 168, 1, 100)
	fmt.Println("IPv4 Address:", ipv4Addr.String()) // 输出: IPv4 Address: 192.168.1.100

	// 创建 IPv4 子网掩码
	ipv4Mask := net.IPv4Mask(255, 255, 255, 0)
	fmt.Println("IPv4 Mask:", ipv4Mask.String())   // 输出: IPv4 Mask: ffffff00

	// 创建 CIDR 掩码
	cidrMask := net.CIDRMask(24, 32)
	fmt.Println("CIDR Mask:", cidrMask.String())   // 输出: CIDR Mask: ffffff00

	// 判断 IP 地址属性
	fmt.Println("Is Private:", ipv4Addr.IsPrivate())     // 输出: Is Private: true
	fmt.Println("Is Loopback:", ipv4Addr.IsLoopback())   // 输出: Is Loopback: false

	// IP 地址与子网掩码运算
	networkAddr := ipv4Addr.Mask(ipv4Mask)
	fmt.Println("Network Address:", networkAddr.String()) // 输出: Network Address: 192.168.1.0

	// 创建 IP 网络
	ipNet := &net.IPNet{IP: networkAddr, Mask: ipv4Mask}
	fmt.Println("IP Network:", ipNet.String())         // 输出: IP Network: 192.168.1.0/24

	// 判断 IP 是否在网络中
	otherIP := net.ParseIP("192.168.1.150")
	fmt.Println("Contains:", ipNet.Contains(otherIP))   // 输出: Contains: true

	// 解析 IP 地址
	parsedIP := net.ParseIP("2001:db8::1")
	fmt.Println("Parsed IPv6:", parsedIP.String())     // 输出: Parsed IPv6: 2001:db8::1

	// 解析 CIDR
	parsedIPAddr, parsedNet, err := net.ParseCIDR("192.168.2.0/24")
	if err != nil {
		fmt.Println("Parse CIDR Error:", err)
	} else {
		fmt.Println("Parsed IP from CIDR:", parsedIPAddr.String()) // 输出: Parsed IP from CIDR: 192.168.2.0
		fmt.Println("Parsed Network from CIDR:", parsedNet.String()) // 输出: Parsed Network from CIDR: 192.168.2.0/24
	}
}
```

**假设的输入与输出:**

上面的代码示例中，我们直接在代码中定义了 IP 地址和网络信息，所以输入是硬编码的。输出结果在注释中已给出。 如果 `ParseIP` 或 `ParseCIDR` 接收到无效的字符串，则 `ParseIP` 会返回 `nil`，而 `ParseCIDR` 会返回一个非 `nil` 的 `error`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。处理命令行参数通常会在调用此代码的更上层应用中进行，例如使用 `flag` 包来解析命令行参数，然后将解析到的 IP 地址字符串传递给 `net.ParseIP` 或 `net.ParseCIDR` 函数。

**使用者易犯错的点:**

1. **混淆 IP 地址的内部表示和外部表示:**  用户可能会忘记 `net.IP` 内部统一使用 16 字节表示，即使是 IPv4 地址。这可能会在进行字节级别的操作时产生困惑。 例如，直接访问 IPv4 `IP` 对象的 `ip[0]` 到 `ip[3]` 并不总是正确的方式，应该使用 `To4()` 方法。

2. **错误地假设 `To4()` 的返回值:**  `To4()` 方法只有在 `IP` 对象表示的是 IPv4 地址时才会返回 4 字节的切片，否则返回 `nil`。 使用者需要在使用其返回值前进行判空检查。

   ```go
   ip := net.ParseIP("2001:db8::1")
   ipv4 := ip.To4()
   if ipv4 == nil {
       fmt.Println("Not an IPv4 address")
   } else {
       fmt.Println("IPv4 address:", ipv4) // 不会执行
   }
   ```

3. **不理解子网掩码的含义和用法:**  用户可能不清楚如何创建合适的子网掩码，以及如何使用掩码来获取网络地址或判断 IP 地址是否属于同一网络。

4. **在比较 IP 地址时没有考虑 IPv4 和 IPv6 的兼容性:**  直接使用字节切片的比较 (`==`) 可能无法正确判断 IPv4 地址和其对应的 IPv4-mapped IPv6 地址是否相等。 应该使用 `Equal()` 方法进行比较。

   ```go
   ipv4 := net.ParseIP("192.168.1.1")
   ipv6Mapped := net.ParseIP("::ffff:192.168.1.1")

   fmt.Println(ipv4.Equal(ipv6Mapped)) // 输出: true
   // fmt.Println(ipv4 == ipv6Mapped) // 输出: false (直接比较字节切片)
   ```

总而言之，这段代码提供了 Go 语言中处理 IP 地址和网络的基础工具，理解其核心概念和使用方法对于进行网络编程至关重要。

### 提示词
```
这是路径为go/src/net/ip.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// IP address manipulations
//
// IPv4 addresses are 4 bytes; IPv6 addresses are 16 bytes.
// An IPv4 address can be converted to an IPv6 address by
// adding a canonical prefix (10 zeros, 2 0xFFs).
// This library accepts either size of byte slice but always
// returns 16-byte addresses.

package net

import (
	"internal/bytealg"
	"internal/itoa"
	"internal/stringslite"
	"net/netip"
)

// IP address lengths (bytes).
const (
	IPv4len = 4
	IPv6len = 16
)

// An IP is a single IP address, a slice of bytes.
// Functions in this package accept either 4-byte (IPv4)
// or 16-byte (IPv6) slices as input.
//
// Note that in this documentation, referring to an
// IP address as an IPv4 address or an IPv6 address
// is a semantic property of the address, not just the
// length of the byte slice: a 16-byte slice can still
// be an IPv4 address.
type IP []byte

// An IPMask is a bitmask that can be used to manipulate
// IP addresses for IP addressing and routing.
//
// See type [IPNet] and func [ParseCIDR] for details.
type IPMask []byte

// An IPNet represents an IP network.
type IPNet struct {
	IP   IP     // network number
	Mask IPMask // network mask
}

// IPv4 returns the IP address (in 16-byte form) of the
// IPv4 address a.b.c.d.
func IPv4(a, b, c, d byte) IP {
	p := make(IP, IPv6len)
	copy(p, v4InV6Prefix)
	p[12] = a
	p[13] = b
	p[14] = c
	p[15] = d
	return p
}

var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

// IPv4Mask returns the IP mask (in 4-byte form) of the
// IPv4 mask a.b.c.d.
func IPv4Mask(a, b, c, d byte) IPMask {
	p := make(IPMask, IPv4len)
	p[0] = a
	p[1] = b
	p[2] = c
	p[3] = d
	return p
}

// CIDRMask returns an [IPMask] consisting of 'ones' 1 bits
// followed by 0s up to a total length of 'bits' bits.
// For a mask of this form, CIDRMask is the inverse of [IPMask.Size].
func CIDRMask(ones, bits int) IPMask {
	if bits != 8*IPv4len && bits != 8*IPv6len {
		return nil
	}
	if ones < 0 || ones > bits {
		return nil
	}
	l := bits / 8
	m := make(IPMask, l)
	n := uint(ones)
	for i := 0; i < l; i++ {
		if n >= 8 {
			m[i] = 0xff
			n -= 8
			continue
		}
		m[i] = ^byte(0xff >> n)
		n = 0
	}
	return m
}

// Well-known IPv4 addresses
var (
	IPv4bcast     = IPv4(255, 255, 255, 255) // limited broadcast
	IPv4allsys    = IPv4(224, 0, 0, 1)       // all systems
	IPv4allrouter = IPv4(224, 0, 0, 2)       // all routers
	IPv4zero      = IPv4(0, 0, 0, 0)         // all zeros
)

// Well-known IPv6 addresses
var (
	IPv6zero                   = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	IPv6unspecified            = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	IPv6loopback               = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	IPv6interfacelocalallnodes = IP{0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	IPv6linklocalallnodes      = IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	IPv6linklocalallrouters    = IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
)

// IsUnspecified reports whether ip is an unspecified address, either
// the IPv4 address "0.0.0.0" or the IPv6 address "::".
func (ip IP) IsUnspecified() bool {
	return ip.Equal(IPv4zero) || ip.Equal(IPv6unspecified)
}

// IsLoopback reports whether ip is a loopback address.
func (ip IP) IsLoopback() bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 127
	}
	return ip.Equal(IPv6loopback)
}

// IsPrivate reports whether ip is a private address, according to
// RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
func (ip IP) IsPrivate() bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Following RFC 1918, Section 3. Private Address Space which says:
		//   The Internet Assigned Numbers Authority (IANA) has reserved the
		//   following three blocks of the IP address space for private internets:
		//     10.0.0.0        -   10.255.255.255  (10/8 prefix)
		//     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
		//     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// Following RFC 4193, Section 8. IANA Considerations which says:
	//   The IANA has assigned the FC00::/7 prefix to "Unique Local Unicast".
	return len(ip) == IPv6len && ip[0]&0xfe == 0xfc
}

// IsMulticast reports whether ip is a multicast address.
func (ip IP) IsMulticast() bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0]&0xf0 == 0xe0
	}
	return len(ip) == IPv6len && ip[0] == 0xff
}

// IsInterfaceLocalMulticast reports whether ip is
// an interface-local multicast address.
func (ip IP) IsInterfaceLocalMulticast() bool {
	return len(ip) == IPv6len && ip[0] == 0xff && ip[1]&0x0f == 0x01
}

// IsLinkLocalMulticast reports whether ip is a link-local
// multicast address.
func (ip IP) IsLinkLocalMulticast() bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 224 && ip4[1] == 0 && ip4[2] == 0
	}
	return len(ip) == IPv6len && ip[0] == 0xff && ip[1]&0x0f == 0x02
}

// IsLinkLocalUnicast reports whether ip is a link-local
// unicast address.
func (ip IP) IsLinkLocalUnicast() bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	return len(ip) == IPv6len && ip[0] == 0xfe && ip[1]&0xc0 == 0x80
}

// IsGlobalUnicast reports whether ip is a global unicast
// address.
//
// The identification of global unicast addresses uses address type
// identification as defined in RFC 1122, RFC 4632 and RFC 4291 with
// the exception of IPv4 directed broadcast addresses.
// It returns true even if ip is in IPv4 private address space or
// local IPv6 unicast address space.
func (ip IP) IsGlobalUnicast() bool {
	return (len(ip) == IPv4len || len(ip) == IPv6len) &&
		!ip.Equal(IPv4bcast) &&
		!ip.IsUnspecified() &&
		!ip.IsLoopback() &&
		!ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast()
}

// Is p all zeros?
func isZeros(p IP) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}

// To4 converts the IPv4 address ip to a 4-byte representation.
// If ip is not an IPv4 address, To4 returns nil.
func (ip IP) To4() IP {
	if len(ip) == IPv4len {
		return ip
	}
	if len(ip) == IPv6len &&
		isZeros(ip[0:10]) &&
		ip[10] == 0xff &&
		ip[11] == 0xff {
		return ip[12:16]
	}
	return nil
}

// To16 converts the IP address ip to a 16-byte representation.
// If ip is not an IP address (it is the wrong length), To16 returns nil.
func (ip IP) To16() IP {
	if len(ip) == IPv4len {
		return IPv4(ip[0], ip[1], ip[2], ip[3])
	}
	if len(ip) == IPv6len {
		return ip
	}
	return nil
}

// Default route masks for IPv4.
var (
	classAMask = IPv4Mask(0xff, 0, 0, 0)
	classBMask = IPv4Mask(0xff, 0xff, 0, 0)
	classCMask = IPv4Mask(0xff, 0xff, 0xff, 0)
)

// DefaultMask returns the default IP mask for the IP address ip.
// Only IPv4 addresses have default masks; DefaultMask returns
// nil if ip is not a valid IPv4 address.
func (ip IP) DefaultMask() IPMask {
	if ip = ip.To4(); ip == nil {
		return nil
	}
	switch {
	case ip[0] < 0x80:
		return classAMask
	case ip[0] < 0xC0:
		return classBMask
	default:
		return classCMask
	}
}

func allFF(b []byte) bool {
	for _, c := range b {
		if c != 0xff {
			return false
		}
	}
	return true
}

// Mask returns the result of masking the IP address ip with mask.
func (ip IP) Mask(mask IPMask) IP {
	if len(mask) == IPv6len && len(ip) == IPv4len && allFF(mask[:12]) {
		mask = mask[12:]
	}
	if len(mask) == IPv4len && len(ip) == IPv6len && bytealg.Equal(ip[:12], v4InV6Prefix) {
		ip = ip[12:]
	}
	n := len(ip)
	if n != len(mask) {
		return nil
	}
	out := make(IP, n)
	for i := 0; i < n; i++ {
		out[i] = ip[i] & mask[i]
	}
	return out
}

// String returns the string form of the IP address ip.
// It returns one of 4 forms:
//   - "<nil>", if ip has length 0
//   - dotted decimal ("192.0.2.1"), if ip is an IPv4 or IP4-mapped IPv6 address
//   - IPv6 conforming to RFC 5952 ("2001:db8::1"), if ip is a valid IPv6 address
//   - the hexadecimal form of ip, without punctuation, if no other cases apply
func (ip IP) String() string {
	if len(ip) == 0 {
		return "<nil>"
	}

	if len(ip) != IPv4len && len(ip) != IPv6len {
		return "?" + hexString(ip)
	}

	var buf []byte
	switch len(ip) {
	case IPv4len:
		const maxCap = len("255.255.255.255")
		buf = make([]byte, 0, maxCap)
	case IPv6len:
		const maxCap = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
		buf = make([]byte, 0, maxCap)
	}
	buf = ip.appendTo(buf)
	return string(buf)
}

func hexString(b []byte) string {
	s := make([]byte, len(b)*2)
	for i, tn := range b {
		s[i*2], s[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
	}
	return string(s)
}

// ipEmptyString is like ip.String except that it returns
// an empty string when ip is unset.
func ipEmptyString(ip IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

// appendTo appends the string representation of ip to b and returns the expanded b
// If len(ip) != IPv4len or IPv6len, it appends nothing.
func (ip IP) appendTo(b []byte) []byte {
	// If IPv4, use dotted notation.
	if p4 := ip.To4(); len(p4) == IPv4len {
		ip = p4
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.AppendTo(b)
}

// AppendText implements the [encoding.TextAppender] interface.
// The encoding is the same as returned by [IP.String], with one exception:
// When len(ip) is zero, it appends nothing.
func (ip IP) AppendText(b []byte) ([]byte, error) {
	if len(ip) == 0 {
		return b, nil
	}
	if len(ip) != IPv4len && len(ip) != IPv6len {
		return b, &AddrError{Err: "invalid IP address", Addr: hexString(ip)}
	}

	return ip.appendTo(b), nil
}

// MarshalText implements the [encoding.TextMarshaler] interface.
// The encoding is the same as returned by [IP.String], with one exception:
// When len(ip) is zero, it returns an empty slice.
func (ip IP) MarshalText() ([]byte, error) {
	// 24 is satisfied with all IPv4 addresses and short IPv6 addresses
	b, err := ip.AppendText(make([]byte, 0, 24))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
// The IP address is expected in a form accepted by [ParseIP].
func (ip *IP) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*ip = nil
		return nil
	}
	s := string(text)
	x := ParseIP(s)
	if x == nil {
		return &ParseError{Type: "IP address", Text: s}
	}
	*ip = x
	return nil
}

// Equal reports whether ip and x are the same IP address.
// An IPv4 address and that same address in IPv6 form are
// considered to be equal.
func (ip IP) Equal(x IP) bool {
	if len(ip) == len(x) {
		return bytealg.Equal(ip, x)
	}
	if len(ip) == IPv4len && len(x) == IPv6len {
		return bytealg.Equal(x[0:12], v4InV6Prefix) && bytealg.Equal(ip, x[12:])
	}
	if len(ip) == IPv6len && len(x) == IPv4len {
		return bytealg.Equal(ip[0:12], v4InV6Prefix) && bytealg.Equal(ip[12:], x)
	}
	return false
}

func (ip IP) matchAddrFamily(x IP) bool {
	return ip.To4() != nil && x.To4() != nil || ip.To16() != nil && ip.To4() == nil && x.To16() != nil && x.To4() == nil
}

// If mask is a sequence of 1 bits followed by 0 bits,
// return the number of 1 bits.
func simpleMaskLength(mask IPMask) int {
	var n int
	for i, v := range mask {
		if v == 0xff {
			n += 8
			continue
		}
		// found non-ff byte
		// count 1 bits
		for v&0x80 != 0 {
			n++
			v <<= 1
		}
		// rest must be 0 bits
		if v != 0 {
			return -1
		}
		for i++; i < len(mask); i++ {
			if mask[i] != 0 {
				return -1
			}
		}
		break
	}
	return n
}

// Size returns the number of leading ones and total bits in the mask.
// If the mask is not in the canonical form--ones followed by zeros--then
// Size returns 0, 0.
func (m IPMask) Size() (ones, bits int) {
	ones, bits = simpleMaskLength(m), len(m)*8
	if ones == -1 {
		return 0, 0
	}
	return
}

// String returns the hexadecimal form of m, with no punctuation.
func (m IPMask) String() string {
	if len(m) == 0 {
		return "<nil>"
	}
	return hexString(m)
}

func networkNumberAndMask(n *IPNet) (ip IP, m IPMask) {
	if ip = n.IP.To4(); ip == nil {
		ip = n.IP
		if len(ip) != IPv6len {
			return nil, nil
		}
	}
	m = n.Mask
	switch len(m) {
	case IPv4len:
		if len(ip) != IPv4len {
			return nil, nil
		}
	case IPv6len:
		if len(ip) == IPv4len {
			m = m[12:]
		}
	default:
		return nil, nil
	}
	return
}

// Contains reports whether the network includes ip.
func (n *IPNet) Contains(ip IP) bool {
	nn, m := networkNumberAndMask(n)
	if x := ip.To4(); x != nil {
		ip = x
	}
	l := len(ip)
	if l != len(nn) {
		return false
	}
	for i := 0; i < l; i++ {
		if nn[i]&m[i] != ip[i]&m[i] {
			return false
		}
	}
	return true
}

// Network returns the address's network name, "ip+net".
func (n *IPNet) Network() string { return "ip+net" }

// String returns the CIDR notation of n like "192.0.2.0/24"
// or "2001:db8::/48" as defined in RFC 4632 and RFC 4291.
// If the mask is not in the canonical form, it returns the
// string which consists of an IP address, followed by a slash
// character and a mask expressed as hexadecimal form with no
// punctuation like "198.51.100.0/c000ff00".
func (n *IPNet) String() string {
	if n == nil {
		return "<nil>"
	}
	nn, m := networkNumberAndMask(n)
	if nn == nil || m == nil {
		return "<nil>"
	}
	l := simpleMaskLength(m)
	if l == -1 {
		return nn.String() + "/" + m.String()
	}
	return nn.String() + "/" + itoa.Uitoa(uint(l))
}

// ParseIP parses s as an IP address, returning the result.
// The string s can be in IPv4 dotted decimal ("192.0.2.1"), IPv6
// ("2001:db8::68"), or IPv4-mapped IPv6 ("::ffff:192.0.2.1") form.
// If s is not a valid textual representation of an IP address,
// ParseIP returns nil. The returned address is always 16 bytes,
// IPv4 addresses are returned in IPv4-mapped IPv6 form.
func ParseIP(s string) IP {
	if addr, valid := parseIP(s); valid {
		return IP(addr[:])
	}
	return nil
}

func parseIP(s string) ([16]byte, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return [16]byte{}, false
	}
	return ip.As16(), true
}

// ParseCIDR parses s as a CIDR notation IP address and prefix length,
// like "192.0.2.0/24" or "2001:db8::/32", as defined in
// RFC 4632 and RFC 4291.
//
// It returns the IP address and the network implied by the IP and
// prefix length.
// For example, ParseCIDR("192.0.2.1/24") returns the IP address
// 192.0.2.1 and the network 192.0.2.0/24.
func ParseCIDR(s string) (IP, *IPNet, error) {
	addr, mask, found := stringslite.Cut(s, "/")
	if !found {
		return nil, nil, &ParseError{Type: "CIDR address", Text: s}
	}

	ipAddr, err := netip.ParseAddr(addr)
	if err != nil || ipAddr.Zone() != "" {
		return nil, nil, &ParseError{Type: "CIDR address", Text: s}
	}

	n, i, ok := dtoi(mask)
	if !ok || i != len(mask) || n < 0 || n > ipAddr.BitLen() {
		return nil, nil, &ParseError{Type: "CIDR address", Text: s}
	}
	m := CIDRMask(n, ipAddr.BitLen())
	addr16 := ipAddr.As16()
	return IP(addr16[:]), &IPNet{IP: IP(addr16[:]).Mask(m), Mask: m}, nil
}

func copyIP(x IP) IP {
	y := make(IP, len(x))
	copy(y, x)
	return y
}
```