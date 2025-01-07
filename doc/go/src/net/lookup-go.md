Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the answer.

1. **Understand the Goal:** The primary goal is to analyze a specific Go file (`lookup.go` in the `net` package) and explain its functionality, provide examples, discuss potential pitfalls, and identify the Go feature it implements.

2. **Initial Code Scan and Keyword Identification:** Quickly skim the code, looking for familiar networking terms and data structures. Keywords like `protocols`, `services`, `Resolver`, `LookupHost`, `LookupIP`, `LookupPort`, `LookupCNAME`, `LookupSRV`, `LookupMX`, `LookupNS`, `LookupTXT`, `LookupAddr`, `DNS`, and functions like `lookupProtocolMap`, `lookupPortMap`, `dial`, `goLookupSRV`, etc., immediately stand out. These are strong indicators of DNS resolution and related functionalities.

3. **Section-by-Section Analysis:**  Divide the code into logical blocks based on the keywords and function definitions.

    * **`protocols` and `services` maps:** These are clearly static mappings for common protocol numbers and service port numbers. The comments mention augmentation on Unix systems, which is a relevant detail.

    * **`lookupProtocolMap` and `lookupPortMap`:** These functions handle looking up protocol numbers and port numbers, respectively, using the static maps. They also include error handling for unknown protocols/ports.

    * **`Resolver` struct:** This is a crucial structure. Its fields (`PreferGo`, `StrictErrors`, `Dial`, `lookupGroup`) hint at configurable DNS resolution behavior and internal optimization (like `singleflight`).

    * **`Lookup...` functions (e.g., `LookupHost`, `LookupIP`, etc.):**  These are the public entry points for various DNS lookups. Notice the existence of both package-level functions (using `DefaultResolver`) and methods on the `Resolver` struct, allowing for both simple and more customized usage. Pay attention to the types of lookups each function performs (hostnames, IPs, ports, CNAMEs, etc.).

    * **`lookupIPAddr`:**  This function seems to be a core internal function for IP address lookups, potentially handling caching and concurrent requests through `singleflight.Group`. The context handling here is also important.

    * **`goLookup...` functions (e.g., `goLookupSRV`, `goLookupMX`, etc.):** The "go" prefix suggests these are implementations using Go's native DNS resolver. They involve parsing DNS messages (`dnsmessage` package).

    * **Helper functions:**  Functions like `ipVersion`, `parsePort`, `isDomainName`, `mapErr` provide supporting logic.

4. **Inferring the Core Functionality:** Based on the identified keywords, functions, and data structures, the primary function of this code is **DNS resolution**. It provides a way to translate human-readable domain names into IP addresses, look up service ports, retrieve various DNS records (CNAME, SRV, MX, NS, TXT), and perform reverse lookups.

5. **Illustrative Examples (Go Code):** For each key functionality, think about how a user would interact with it. Write simple, clear examples demonstrating the usage of the `Lookup...` functions. Include expected inputs and outputs (even if just a general description). For example, showing `LookupHost` with a domain name and expecting a list of IP addresses is straightforward. Similarly, demonstrating `LookupPort` with a service name and protocol.

6. **Identifying Potential Pitfalls:**  Consider common mistakes developers might make when using these functions. Examples:

    * **Incorrect network parameter in `LookupPort`:**  Forgetting to specify "tcp" or "udp".
    * **Assuming only one IP address is returned by `LookupHost`:**  Not iterating through the slice.
    * **Not handling errors:** A fundamental programming mistake.

7. **Inferring the Go Feature:** The code heavily uses the `net` package, deals with network addresses, ports, and DNS concepts. It directly implements the **DNS resolution functionality** within the Go standard library.

8. **Command-Line Argument Handling (If Applicable):** Carefully review the code for any interaction with command-line flags or environment variables. In this snippet, `GODEBUG=netdns=go` is mentioned in the context of the `PreferGo` field, but it's not directly handled *within* this code. The code provides a way to *configure* the resolver, but the configuration itself might come from external sources. Therefore, focusing on the `PreferGo` option as a configuration point is relevant.

9. **Structure and Language:** Organize the information logically using clear headings and bullet points. Use precise and concise language. Since the request is for a Chinese answer, ensure the translation is accurate and natural.

10. **Review and Refine:** Read through the entire answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. Make sure the code examples are correct and easy to understand. Ensure the Chinese translation is fluent and conveys the intended meaning.

This systematic approach, combining code analysis, knowledge of networking concepts, and practical examples, allows for a comprehensive and accurate understanding of the provided Go code snippet.
这段代码是 Go 语言标准库 `net` 包中 `lookup.go` 文件的一部分，主要负责实现 **DNS 查询 (DNS resolution)** 和相关的辅助功能。

以下是它的功能列表：

**核心 DNS 查询功能:**

* **`LookupHost(host string) ([]string, error)` 和 `Resolver.LookupHost(ctx context.Context, host string) ([]string, error)`:**  根据给定的主机名 (hostname) 查找其对应的 IP 地址列表 (字符串形式)。这是最基础的 DNS 查询功能，用于将域名解析为 IP 地址。
* **`LookupIP(host string) ([]IP, error)` 和 `Resolver.LookupIPAddr(ctx context.Context, host string) ([]IPAddr, error)`:**  根据给定的主机名查找其对应的 IPv4 和 IPv6 地址列表 (`net.IP` 或 `net.IPAddr` 类型)。
* **`Resolver.LookupIP(ctx context.Context, network, host string) ([]IP, error)` 和 `Resolver.LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)`:**  根据给定的网络类型 ("ip", "ip4", "ip6") 和主机名查找特定 IP 版本的地址列表。
* **`LookupPort(network, service string) (port int, err error)` 和 `Resolver.LookupPort(ctx context.Context, network, service string) (port int, err error)`:**  根据给定的网络协议 ("tcp", "udp" 等) 和服务名查找对应的端口号。
* **`LookupCNAME(host string) (cname string, err error)` 和 `Resolver.LookupCNAME(ctx context.Context, host string) (string, error)`:**  查找给定主机名的规范名称 (Canonical Name)，即 CNAME 记录指向的最终域名。
* **`LookupSRV(service, proto, name string) (cname string, addrs []*SRV, err error)` 和 `Resolver.LookupSRV(ctx context.Context, service, proto, name string) (string, []*SRV, error)`:**  查找给定服务、协议和域名对应的 SRV (Service) 记录。SRV 记录用于定位特定服务的服务器主机名和端口号。
* **`LookupMX(name string) ([]*MX, error)` 和 `Resolver.LookupMX(ctx context.Context, name string) ([]*MX, error)`:**  查找给定域名对应的 MX (Mail Exchanger) 记录，用于邮件路由。
* **`LookupNS(name string) ([]*NS, error)` 和 `Resolver.LookupNS(ctx context.Context, name string) ([]*NS, error)`:**  查找给定域名对应的 NS (Name Server) 记录，列出负责该域名的 DNS 服务器。
* **`LookupTXT(name string) ([]string, error)` 和 `Resolver.LookupTXT(ctx context.Context, name string) ([]string, error)`:**  查找给定域名对应的 TXT (Text) 记录，用于存储任意文本信息。
* **`LookupAddr(addr string) (names []string, err error)` 和 `Resolver.LookupAddr(ctx context.Context, addr string) ([]string, error)`:**  执行反向 DNS 查找，根据给定的 IP 地址查找其对应的域名列表。

**辅助功能:**

* **`protocols` 和 `services` 变量:**  存储了协议名称到协议号以及服务名称到端口号的默认映射。这些映射在 Unix 系统上会被读取系统配置进行扩充。
* **`lookupProtocolMap(name string) (int, error)`:**  根据协议名称查找对应的协议号。
* **`lookupPortMap(network, service string) (port int, error error)` 和 `lookupPortMapWithNetwork(network, errNetwork, service string) (port int, error error)`:** 根据网络协议和服务名称查找对应的端口号，优先使用内部映射。
* **`ipVersion(network string) byte`:**  判断给定的网络字符串是 IPv4 还是 IPv6。
* **`DefaultResolver` 变量:**  默认的 `Resolver` 实例，供包级别的 `Lookup...` 函数使用。
* **`Resolver` 结构体:**  代表一个 DNS 解析器，允许配置一些解析行为，例如是否优先使用 Go 的内置解析器 (`PreferGo`)，以及处理临时错误的方式 (`StrictErrors`)。它还允许自定义拨号器 (`Dial`) 用于连接 DNS 服务器。
* **`singleflight.Group`:** 用于合并对相同主机的并发 DNS 查询请求，避免重复查询，提高效率。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言标准库中 **网络 (networking)** 功能的重要组成部分，具体来说，它实现了 **DNS 域名解析** 的核心功能。

**Go 代码举例说明:**

```go
package main

import (
	"context"
	"fmt"
	"net"
)

func main() {
	// 查找主机名对应的 IP 地址
	ips, err := net.LookupHost("www.google.com")
	if err != nil {
		fmt.Println("查找 IP 地址失败:", err)
		return
	}
	fmt.Println("www.google.com 的 IP 地址:", ips)

	// 查找主机名对应的 IPv4 地址
	ipv4s, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", "www.google.com")
	if err != nil {
		fmt.Println("查找 IPv4 地址失败:", err)
		return
	}
	fmt.Println("www.google.com 的 IPv4 地址:", ipv4s)

	// 查找服务对应的端口号
	port, err := net.LookupPort("tcp", "http")
	if err != nil {
		fmt.Println("查找端口号失败:", err)
		return
	}
	fmt.Println("http 的 TCP 端口号:", port)

	// 查找域名的 MX 记录
	mxRecords, err := net.LookupMX("google.com")
	if err != nil {
		fmt.Println("查找 MX 记录失败:", err)
		return
	}
	fmt.Println("google.com 的 MX 记录:")
	for _, mx := range mxRecords {
		fmt.Printf("  Host: %s, Preference: %d\n", mx.Host, mx.Pref)
	}
}
```

**假设的输入与输出:**

* **`net.LookupHost("www.google.com")`**
    * **假设输出:** `["142.250.180.196", "2404:6800:4007:825::2004"]`, `nil` (或类似的 IP 地址，取决于运行环境)
* **`net.DefaultResolver.LookupIP(context.Background(), "ip4", "www.google.com")`**
    * **假设输出:** `[142.250.180.196]`, `nil` (或类似的 IPv4 地址)
* **`net.LookupPort("tcp", "http")`**
    * **假设输出:** `80`, `nil`
* **`net.LookupMX("google.com")`**
    * **假设输出:** 可能包含多个 MX 记录，例如:
        ```
        &net.MX{Host: "aspmx.l.google.com.", Pref: 1}
        &net.MX{Host: "alt1.aspmx.l.google.com.", Pref: 5}
        // ... 其他 MX 记录
        ```
        以及 `nil` 作为错误值。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。但是，它提供了一些选项可以通过编程方式进行配置，例如 `Resolver` 结构体中的 `PreferGo` 和 `StrictErrors` 字段。

* **`PreferGo`:**  如果设置为 `true`，并且在支持的平台上，Go 的内置 DNS 解析器将被优先使用。这相当于设置环境变量 `GODEBUG=netdns=go`。
* **`StrictErrors`:**  控制在使用 Go 内置解析器时，对临时错误的处理方式。如果设置为 `true`，遇到临时错误会中止整个查询，而不是返回部分结果。

这些配置通常在程序初始化阶段进行设置，而不是通过命令行参数直接控制。例如：

```go
package main

import (
	"context"
	"fmt"
	"net"
)

func main() {
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
	}

	ips, err := resolver.LookupHost(context.Background(), "www.example.com")
	if err != nil {
		fmt.Println("查找 IP 地址失败:", err)
		return
	}
	fmt.Println("www.example.com 的 IP 地址:", ips)
}
```

**使用者易犯错的点:**

1. **错误地假设 `LookupHost` 或 `LookupIP` 只返回一个 IP 地址:**  域名可能解析到多个 IP 地址，特别是对于大型网站。应该遍历返回的切片来获取所有地址。

   ```go
   ips, err := net.LookupHost("www.example.com")
   if err == nil {
       for _, ip := range ips {
           fmt.Println("IP 地址:", ip) // 应该遍历所有 IP 地址
       }
   }
   ```

2. **在需要上下文 (Context) 的地方使用了包级别的 `Lookup...` 函数:** 包级别的函数内部使用 `context.Background()`，无法传递超时、取消等控制信息。在需要精细控制的场景下，应该使用 `Resolver` 的方法并传入自定义的 `context.Context`。

   ```go
   ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
   defer cancel()

   resolver := &net.Resolver{}
   ips, err := resolver.LookupHost(ctx, "www.example.com") // 使用 Resolver 的方法并传递上下文
   if err != nil {
       fmt.Println("查找 IP 地址失败:", err)
   }
   ```

3. **没有处理 DNS 查询可能返回错误的情况:**  DNS 查询可能会因为网络问题、域名不存在等原因失败。应该始终检查返回的 `error` 值。

   ```go
   ips, err := net.LookupHost("nonexistent-domain.invalid")
   if err != nil {
       fmt.Println("查找 IP 地址失败:", err) // 应该处理错误
   }
   ```

4. **混淆了网络类型参数:** 例如，在 `LookupPort` 中，网络类型应该是 "tcp" 或 "udp"，而不是 "tcp4" 或 "udp6"。 "tcp4" 和 "udp6" 主要用于创建特定 IP 版本的连接。

   ```go
   port, err := net.LookupPort("tcp", "http") // 正确
   // port, err := net.LookupPort("tcp4", "http") // 错误
   ```

5. **在使用 `Resolver` 时忘记初始化:**  虽然零值的 `Resolver` 可以工作，但如果你想要配置特定的行为（例如 `PreferGo`），你需要显式地创建并配置 `Resolver` 实例。

这段代码是 Go 语言网络编程的基础，理解其功能对于开发网络应用程序至关重要。

Prompt: 
```
这是路径为go/src/net/lookup.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"internal/nettrace"
	"internal/singleflight"
	"net/netip"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// protocols contains minimal mappings between internet protocol
// names and numbers for platforms that don't have a complete list of
// protocol numbers.
//
// See https://www.iana.org/assignments/protocol-numbers
//
// On Unix, this map is augmented by readProtocols via lookupProtocol.
var protocols = map[string]int{
	"icmp":      1,
	"igmp":      2,
	"tcp":       6,
	"udp":       17,
	"ipv6-icmp": 58,
}

// services contains minimal mappings between services names and port
// numbers for platforms that don't have a complete list of port numbers.
//
// See https://www.iana.org/assignments/service-names-port-numbers
//
// On Unix, this map is augmented by readServices via goLookupPort.
var services = map[string]map[string]int{
	"udp": {
		"domain": 53,
	},
	"tcp": {
		"ftp":         21,
		"ftps":        990,
		"gopher":      70, // ʕ◔ϖ◔ʔ
		"http":        80,
		"https":       443,
		"imap2":       143,
		"imap3":       220,
		"imaps":       993,
		"pop3":        110,
		"pop3s":       995,
		"smtp":        25,
		"submissions": 465,
		"ssh":         22,
		"telnet":      23,
	},
}

// dnsWaitGroup can be used by tests to wait for all DNS goroutines to
// complete. This avoids races on the test hooks.
var dnsWaitGroup sync.WaitGroup

const maxProtoLength = len("RSVP-E2E-IGNORE") + 10 // with room to grow

func lookupProtocolMap(name string) (int, error) {
	var lowerProtocol [maxProtoLength]byte
	n := copy(lowerProtocol[:], name)
	lowerASCIIBytes(lowerProtocol[:n])
	proto, found := protocols[string(lowerProtocol[:n])]
	if !found || n != len(name) {
		return 0, &AddrError{Err: "unknown IP protocol specified", Addr: name}
	}
	return proto, nil
}

// maxPortBufSize is the longest reasonable name of a service
// (non-numeric port).
// Currently the longest known IANA-unregistered name is
// "mobility-header", so we use that length, plus some slop in case
// something longer is added in the future.
const maxPortBufSize = len("mobility-header") + 10

func lookupPortMap(network, service string) (port int, error error) {
	switch network {
	case "ip": // no hints
		if p, err := lookupPortMapWithNetwork("tcp", "ip", service); err == nil {
			return p, nil
		}
		return lookupPortMapWithNetwork("udp", "ip", service)
	case "tcp", "tcp4", "tcp6":
		return lookupPortMapWithNetwork("tcp", "tcp", service)
	case "udp", "udp4", "udp6":
		return lookupPortMapWithNetwork("udp", "udp", service)
	}
	return 0, &DNSError{Err: "unknown network", Name: network + "/" + service}
}

func lookupPortMapWithNetwork(network, errNetwork, service string) (port int, error error) {
	if m, ok := services[network]; ok {
		var lowerService [maxPortBufSize]byte
		n := copy(lowerService[:], service)
		lowerASCIIBytes(lowerService[:n])
		if port, ok := m[string(lowerService[:n])]; ok && n == len(service) {
			return port, nil
		}
		return 0, newDNSError(errUnknownPort, errNetwork+"/"+service, "")
	}
	return 0, &DNSError{Err: "unknown network", Name: errNetwork + "/" + service}
}

// ipVersion returns the provided network's IP version: '4', '6' or 0
// if network does not end in a '4' or '6' byte.
func ipVersion(network string) byte {
	if network == "" {
		return 0
	}
	n := network[len(network)-1]
	if n != '4' && n != '6' {
		n = 0
	}
	return n
}

// DefaultResolver is the resolver used by the package-level Lookup
// functions and by Dialers without a specified Resolver.
var DefaultResolver = &Resolver{}

// A Resolver looks up names and numbers.
//
// A nil *Resolver is equivalent to a zero Resolver.
type Resolver struct {
	// PreferGo controls whether Go's built-in DNS resolver is preferred
	// on platforms where it's available. It is equivalent to setting
	// GODEBUG=netdns=go, but scoped to just this resolver.
	PreferGo bool

	// StrictErrors controls the behavior of temporary errors
	// (including timeout, socket errors, and SERVFAIL) when using
	// Go's built-in resolver. For a query composed of multiple
	// sub-queries (such as an A+AAAA address lookup, or walking the
	// DNS search list), this option causes such errors to abort the
	// whole query instead of returning a partial result. This is
	// not enabled by default because it may affect compatibility
	// with resolvers that process AAAA queries incorrectly.
	StrictErrors bool

	// Dial optionally specifies an alternate dialer for use by
	// Go's built-in DNS resolver to make TCP and UDP connections
	// to DNS services. The host in the address parameter will
	// always be a literal IP address and not a host name, and the
	// port in the address parameter will be a literal port number
	// and not a service name.
	// If the Conn returned is also a PacketConn, sent and received DNS
	// messages must adhere to RFC 1035 section 4.2.1, "UDP usage".
	// Otherwise, DNS messages transmitted over Conn must adhere
	// to RFC 7766 section 5, "Transport Protocol Selection".
	// If nil, the default dialer is used.
	Dial func(ctx context.Context, network, address string) (Conn, error)

	// lookupGroup merges LookupIPAddr calls together for lookups for the same
	// host. The lookupGroup key is the LookupIPAddr.host argument.
	// The return values are ([]IPAddr, error).
	lookupGroup singleflight.Group

	// TODO(bradfitz): optional interface impl override hook
	// TODO(bradfitz): Timeout time.Duration?
}

func (r *Resolver) preferGo() bool     { return r != nil && r.PreferGo }
func (r *Resolver) strictErrors() bool { return r != nil && r.StrictErrors }

func (r *Resolver) getLookupGroup() *singleflight.Group {
	if r == nil {
		return &DefaultResolver.lookupGroup
	}
	return &r.lookupGroup
}

// LookupHost looks up the given host using the local resolver.
// It returns a slice of that host's addresses.
//
// LookupHost uses [context.Background] internally; to specify the context, use
// [Resolver.LookupHost].
func LookupHost(host string) (addrs []string, err error) {
	return DefaultResolver.LookupHost(context.Background(), host)
}

// LookupHost looks up the given host using the local resolver.
// It returns a slice of that host's addresses.
func (r *Resolver) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	// Make sure that no matter what we do later, host=="" is rejected.
	if host == "" {
		return nil, newDNSError(errNoSuchHost, host, "")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{host}, nil
	}
	return r.lookupHost(ctx, host)
}

// LookupIP looks up host using the local resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(host string) ([]IP, error) {
	addrs, err := DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	ips := make([]IP, len(addrs))
	for i, ia := range addrs {
		ips[i] = ia.IP
	}
	return ips, nil
}

// LookupIPAddr looks up host using the local resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]IPAddr, error) {
	return r.lookupIPAddr(ctx, "ip", host)
}

// LookupIP looks up host for the given network using the local resolver.
// It returns a slice of that host's IP addresses of the type specified by
// network.
// network must be one of "ip", "ip4" or "ip6".
func (r *Resolver) LookupIP(ctx context.Context, network, host string) ([]IP, error) {
	afnet, _, err := parseNetwork(ctx, network, false)
	if err != nil {
		return nil, err
	}
	switch afnet {
	case "ip", "ip4", "ip6":
	default:
		return nil, UnknownNetworkError(network)
	}

	if host == "" {
		return nil, newDNSError(errNoSuchHost, host, "")
	}
	addrs, err := r.internetAddrList(ctx, afnet, host)
	if err != nil {
		return nil, err
	}

	ips := make([]IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.(*IPAddr).IP)
	}
	return ips, nil
}

// LookupNetIP looks up host using the local resolver.
// It returns a slice of that host's IP addresses of the type specified by
// network.
// The network must be one of "ip", "ip4" or "ip6".
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	// TODO(bradfitz): make this efficient, making the internal net package
	// type throughout be netip.Addr and only converting to the net.IP slice
	// version at the edge. But for now (2021-10-20), this is a wrapper around
	// the old way.
	ips, err := r.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	ret := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			ret = append(ret, a)
		}
	}
	return ret, nil
}

// onlyValuesCtx is a context that uses an underlying context
// for value lookup if the underlying context hasn't yet expired.
type onlyValuesCtx struct {
	context.Context
	lookupValues context.Context
}

var _ context.Context = (*onlyValuesCtx)(nil)

// Value performs a lookup if the original context hasn't expired.
func (ovc *onlyValuesCtx) Value(key any) any {
	select {
	case <-ovc.lookupValues.Done():
		return nil
	default:
		return ovc.lookupValues.Value(key)
	}
}

// withUnexpiredValuesPreserved returns a context.Context that only uses lookupCtx
// for its values, otherwise it is never canceled and has no deadline.
// If the lookup context expires, any looked up values will return nil.
// See Issue 28600.
func withUnexpiredValuesPreserved(lookupCtx context.Context) context.Context {
	return &onlyValuesCtx{Context: context.Background(), lookupValues: lookupCtx}
}

// lookupIPAddr looks up host using the local resolver and particular network.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func (r *Resolver) lookupIPAddr(ctx context.Context, network, host string) ([]IPAddr, error) {
	// Make sure that no matter what we do later, host=="" is rejected.
	if host == "" {
		return nil, newDNSError(errNoSuchHost, host, "")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []IPAddr{{IP: IP(ip.AsSlice()).To16(), Zone: ip.Zone()}}, nil
	}
	trace, _ := ctx.Value(nettrace.TraceKey{}).(*nettrace.Trace)
	if trace != nil && trace.DNSStart != nil {
		trace.DNSStart(host)
	}
	// The underlying resolver func is lookupIP by default but it
	// can be overridden by tests. This is needed by net/http, so it
	// uses a context key instead of unexported variables.
	resolverFunc := r.lookupIP
	if alt, _ := ctx.Value(nettrace.LookupIPAltResolverKey{}).(func(context.Context, string, string) ([]IPAddr, error)); alt != nil {
		resolverFunc = alt
	}

	// We don't want a cancellation of ctx to affect the
	// lookupGroup operation. Otherwise if our context gets
	// canceled it might cause an error to be returned to a lookup
	// using a completely different context. However we need to preserve
	// only the values in context. See Issue 28600.
	lookupGroupCtx, lookupGroupCancel := context.WithCancel(withUnexpiredValuesPreserved(ctx))

	lookupKey := network + "\000" + host
	dnsWaitGroup.Add(1)
	ch := r.getLookupGroup().DoChan(lookupKey, func() (any, error) {
		return testHookLookupIP(lookupGroupCtx, resolverFunc, network, host)
	})

	dnsWaitGroupDone := func(ch <-chan singleflight.Result, cancelFn context.CancelFunc) {
		<-ch
		dnsWaitGroup.Done()
		cancelFn()
	}
	select {
	case <-ctx.Done():
		// Our context was canceled. If we are the only
		// goroutine looking up this key, then drop the key
		// from the lookupGroup and cancel the lookup.
		// If there are other goroutines looking up this key,
		// let the lookup continue uncanceled, and let later
		// lookups with the same key share the result.
		// See issues 8602, 20703, 22724.
		if r.getLookupGroup().ForgetUnshared(lookupKey) {
			lookupGroupCancel()
			go dnsWaitGroupDone(ch, func() {})
		} else {
			go dnsWaitGroupDone(ch, lookupGroupCancel)
		}
		err := newDNSError(mapErr(ctx.Err()), host, "")
		if trace != nil && trace.DNSDone != nil {
			trace.DNSDone(nil, false, err)
		}
		return nil, err
	case r := <-ch:
		dnsWaitGroup.Done()
		lookupGroupCancel()
		err := r.Err
		if err != nil {
			if _, ok := err.(*DNSError); !ok {
				err = newDNSError(mapErr(err), host, "")
			}
		}
		if trace != nil && trace.DNSDone != nil {
			addrs, _ := r.Val.([]IPAddr)
			trace.DNSDone(ipAddrsEface(addrs), r.Shared, err)
		}
		return lookupIPReturn(r.Val, err, r.Shared)
	}
}

// lookupIPReturn turns the return values from singleflight.Do into
// the return values from LookupIP.
func lookupIPReturn(addrsi any, err error, shared bool) ([]IPAddr, error) {
	if err != nil {
		return nil, err
	}
	addrs := addrsi.([]IPAddr)
	if shared {
		clone := make([]IPAddr, len(addrs))
		copy(clone, addrs)
		addrs = clone
	}
	return addrs, nil
}

// ipAddrsEface returns an empty interface slice of addrs.
func ipAddrsEface(addrs []IPAddr) []any {
	s := make([]any, len(addrs))
	for i, v := range addrs {
		s[i] = v
	}
	return s
}

// LookupPort looks up the port for the given network and service.
//
// LookupPort uses [context.Background] internally; to specify the context, use
// [Resolver.LookupPort].
func LookupPort(network, service string) (port int, err error) {
	return DefaultResolver.LookupPort(context.Background(), network, service)
}

// LookupPort looks up the port for the given network and service.
//
// The network must be one of "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6" or "ip".
func (r *Resolver) LookupPort(ctx context.Context, network, service string) (port int, err error) {
	port, needsLookup := parsePort(service)
	if needsLookup {
		switch network {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip":
		case "": // a hint wildcard for Go 1.0 undocumented behavior
			network = "ip"
		default:
			return 0, &AddrError{Err: "unknown network", Addr: network}
		}
		port, err = r.lookupPort(ctx, network, service)
		if err != nil {
			return 0, err
		}
	}
	if 0 > port || port > 65535 {
		return 0, &AddrError{Err: "invalid port", Addr: service}
	}
	return port, nil
}

// LookupCNAME returns the canonical name for the given host.
// Callers that do not care about the canonical name can call
// [LookupHost] or [LookupIP] directly; both take care of resolving
// the canonical name as part of the lookup.
//
// A canonical name is the final name after following zero
// or more CNAME records.
// LookupCNAME does not return an error if host does not
// contain DNS "CNAME" records, as long as host resolves to
// address records.
//
// The returned canonical name is validated to be a properly
// formatted presentation-format domain name.
//
// LookupCNAME uses [context.Background] internally; to specify the context, use
// [Resolver.LookupCNAME].
func LookupCNAME(host string) (cname string, err error) {
	return DefaultResolver.LookupCNAME(context.Background(), host)
}

// LookupCNAME returns the canonical name for the given host.
// Callers that do not care about the canonical name can call
// [LookupHost] or [LookupIP] directly; both take care of resolving
// the canonical name as part of the lookup.
//
// A canonical name is the final name after following zero
// or more CNAME records.
// LookupCNAME does not return an error if host does not
// contain DNS "CNAME" records, as long as host resolves to
// address records.
//
// The returned canonical name is validated to be a properly
// formatted presentation-format domain name.
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	cname, err := r.lookupCNAME(ctx, host)
	if err != nil {
		return "", err
	}
	if !isDomainName(cname) {
		return "", &DNSError{Err: errMalformedDNSRecordsDetail, Name: host}
	}
	return cname, nil
}

// LookupSRV tries to resolve an [SRV] query of the given service,
// protocol, and domain name. The proto is "tcp" or "udp".
// The returned records are sorted by priority and randomized
// by weight within a priority.
//
// LookupSRV constructs the DNS name to look up following RFC 2782.
// That is, it looks up _service._proto.name. To accommodate services
// publishing SRV records under non-standard names, if both service
// and proto are empty strings, LookupSRV looks up name directly.
//
// The returned service names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func LookupSRV(service, proto, name string) (cname string, addrs []*SRV, err error) {
	return DefaultResolver.LookupSRV(context.Background(), service, proto, name)
}

// LookupSRV tries to resolve an [SRV] query of the given service,
// protocol, and domain name. The proto is "tcp" or "udp".
// The returned records are sorted by priority and randomized
// by weight within a priority.
//
// LookupSRV constructs the DNS name to look up following RFC 2782.
// That is, it looks up _service._proto.name. To accommodate services
// publishing SRV records under non-standard names, if both service
// and proto are empty strings, LookupSRV looks up name directly.
//
// The returned service names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*SRV, error) {
	cname, addrs, err := r.lookupSRV(ctx, service, proto, name)
	if err != nil {
		return "", nil, err
	}
	if cname != "" && !isDomainName(cname) {
		return "", nil, &DNSError{Err: "SRV header name is invalid", Name: name}
	}
	filteredAddrs := make([]*SRV, 0, len(addrs))
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		if !isDomainName(addr.Target) {
			continue
		}
		filteredAddrs = append(filteredAddrs, addr)
	}
	if len(addrs) != len(filteredAddrs) {
		return cname, filteredAddrs, &DNSError{Err: errMalformedDNSRecordsDetail, Name: name}
	}
	return cname, filteredAddrs, nil
}

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
//
// The returned mail server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
//
// LookupMX uses [context.Background] internally; to specify the context, use
// [Resolver.LookupMX].
func LookupMX(name string) ([]*MX, error) {
	return DefaultResolver.LookupMX(context.Background(), name)
}

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
//
// The returned mail server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*MX, error) {
	records, err := r.lookupMX(ctx, name)
	if err != nil {
		return nil, err
	}
	filteredMX := make([]*MX, 0, len(records))
	for _, mx := range records {
		if mx == nil {
			continue
		}
		if !isDomainName(mx.Host) {
			continue
		}
		filteredMX = append(filteredMX, mx)
	}
	if len(records) != len(filteredMX) {
		return filteredMX, &DNSError{Err: errMalformedDNSRecordsDetail, Name: name}
	}
	return filteredMX, nil
}

// LookupNS returns the DNS NS records for the given domain name.
//
// The returned name server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
//
// LookupNS uses [context.Background] internally; to specify the context, use
// [Resolver.LookupNS].
func LookupNS(name string) ([]*NS, error) {
	return DefaultResolver.LookupNS(context.Background(), name)
}

// LookupNS returns the DNS NS records for the given domain name.
//
// The returned name server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*NS, error) {
	records, err := r.lookupNS(ctx, name)
	if err != nil {
		return nil, err
	}
	filteredNS := make([]*NS, 0, len(records))
	for _, ns := range records {
		if ns == nil {
			continue
		}
		if !isDomainName(ns.Host) {
			continue
		}
		filteredNS = append(filteredNS, ns)
	}
	if len(records) != len(filteredNS) {
		return filteredNS, &DNSError{Err: errMalformedDNSRecordsDetail, Name: name}
	}
	return filteredNS, nil
}

// LookupTXT returns the DNS TXT records for the given domain name.
//
// If a DNS TXT record holds multiple strings, they are concatenated as a
// single string.
//
// LookupTXT uses [context.Background] internally; to specify the context, use
// [Resolver.LookupTXT].
func LookupTXT(name string) ([]string, error) {
	return DefaultResolver.lookupTXT(context.Background(), name)
}

// LookupTXT returns the DNS TXT records for the given domain name.
//
// If a DNS TXT record holds multiple strings, they are concatenated as a
// single string.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.lookupTXT(ctx, name)
}

// LookupAddr performs a reverse lookup for the given address, returning a list
// of names mapping to that address.
//
// The returned names are validated to be properly formatted presentation-format
// domain names. If the response contains invalid names, those records are filtered
// out and an error will be returned alongside the remaining results, if any.
//
// When using the host C library resolver, at most one result will be
// returned. To bypass the host resolver, use a custom [Resolver].
//
// LookupAddr uses [context.Background] internally; to specify the context, use
// [Resolver.LookupAddr].
func LookupAddr(addr string) (names []string, err error) {
	return DefaultResolver.LookupAddr(context.Background(), addr)
}

// LookupAddr performs a reverse lookup for the given address, returning a list
// of names mapping to that address.
//
// The returned names are validated to be properly formatted presentation-format
// domain names. If the response contains invalid names, those records are filtered
// out and an error will be returned alongside the remaining results, if any.
func (r *Resolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	names, err := r.lookupAddr(ctx, addr)
	if err != nil {
		return nil, err
	}
	filteredNames := make([]string, 0, len(names))
	for _, name := range names {
		if isDomainName(name) {
			filteredNames = append(filteredNames, name)
		}
	}
	if len(names) != len(filteredNames) {
		return filteredNames, &DNSError{Err: errMalformedDNSRecordsDetail, Name: addr}
	}
	return filteredNames, nil
}

// errMalformedDNSRecordsDetail is the DNSError detail which is returned when a Resolver.Lookup...
// method receives DNS records which contain invalid DNS names. This may be returned alongside
// results which have had the malformed records filtered out.
var errMalformedDNSRecordsDetail = "DNS response contained records which contain invalid names"

// dial makes a new connection to the provided server (which must be
// an IP address) with the provided network type, using either r.Dial
// (if both r and r.Dial are non-nil) or else Dialer.DialContext.
func (r *Resolver) dial(ctx context.Context, network, server string) (Conn, error) {
	// Calling Dial here is scary -- we have to be sure not to
	// dial a name that will require a DNS lookup, or Dial will
	// call back here to translate it. The DNS config parser has
	// already checked that all the cfg.servers are IP
	// addresses, which Dial will use without a DNS lookup.
	var c Conn
	var err error
	if r != nil && r.Dial != nil {
		c, err = r.Dial(ctx, network, server)
	} else {
		var d Dialer
		c, err = d.DialContext(ctx, network, server)
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return c, nil
}

// goLookupSRV returns the SRV records for a target name, built either
// from its component service ("sip"), protocol ("tcp"), and name
// ("example.com."), or from name directly (if service and proto are
// both empty).
//
// In either case, the returned target name ("_sip._tcp.example.com.")
// is also returned on success.
//
// The records are sorted by weight.
func (r *Resolver) goLookupSRV(ctx context.Context, service, proto, name string) (target string, srvs []*SRV, err error) {
	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}
	p, server, err := r.lookup(ctx, target, dnsmessage.TypeSRV, nil)
	if err != nil {
		return "", nil, err
	}
	var cname dnsmessage.Name
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeSRV {
			if err := p.SkipAnswer(); err != nil {
				return "", nil, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		if cname.Length == 0 && h.Name.Length != 0 {
			cname = h.Name
		}
		srv, err := p.SRVResource()
		if err != nil {
			return "", nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		srvs = append(srvs, &SRV{Target: srv.Target.String(), Port: srv.Port, Priority: srv.Priority, Weight: srv.Weight})
	}
	byPriorityWeight(srvs).sort()
	return cname.String(), srvs, nil
}

// goLookupMX returns the MX records for name.
func (r *Resolver) goLookupMX(ctx context.Context, name string) ([]*MX, error) {
	p, server, err := r.lookup(ctx, name, dnsmessage.TypeMX, nil)
	if err != nil {
		return nil, err
	}
	var mxs []*MX
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeMX {
			if err := p.SkipAnswer(); err != nil {
				return nil, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		mx, err := p.MXResource()
		if err != nil {
			return nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		mxs = append(mxs, &MX{Host: mx.MX.String(), Pref: mx.Pref})

	}
	byPref(mxs).sort()
	return mxs, nil
}

// goLookupNS returns the NS records for name.
func (r *Resolver) goLookupNS(ctx context.Context, name string) ([]*NS, error) {
	p, server, err := r.lookup(ctx, name, dnsmessage.TypeNS, nil)
	if err != nil {
		return nil, err
	}
	var nss []*NS
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeNS {
			if err := p.SkipAnswer(); err != nil {
				return nil, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		ns, err := p.NSResource()
		if err != nil {
			return nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		nss = append(nss, &NS{Host: ns.NS.String()})
	}
	return nss, nil
}

// goLookupTXT returns the TXT records from name.
func (r *Resolver) goLookupTXT(ctx context.Context, name string) ([]string, error) {
	p, server, err := r.lookup(ctx, name, dnsmessage.TypeTXT, nil)
	if err != nil {
		return nil, err
	}
	var txts []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return nil, &DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return nil, &DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		// Multiple strings in one TXT record need to be
		// concatenated without separator to be consistent
		// with previous Go resolver.
		n := 0
		for _, s := range txt.TXT {
			n += len(s)
		}
		txtJoin := make([]byte, 0, n)
		for _, s := range txt.TXT {
			txtJoin = append(txtJoin, s...)
		}
		if len(txts) == 0 {
			txts = make([]string, 0, 1)
		}
		txts = append(txts, string(txtJoin))
	}
	return txts, nil
}

func parseCNAMEFromResources(resources []dnsmessage.Resource) (string, error) {
	if len(resources) == 0 {
		return "", errors.New("no CNAME record received")
	}
	c, ok := resources[0].Body.(*dnsmessage.CNAMEResource)
	if !ok {
		return "", errors.New("could not parse CNAME record")
	}
	return c.CNAME.String(), nil
}

"""



```