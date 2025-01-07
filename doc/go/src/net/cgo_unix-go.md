Response:
Let's break down the thought process for analyzing the `cgo_unix.go` file.

**1. Initial Understanding and Context:**

* **File Path:** `go/src/net/cgo_unix.go` immediately tells us this is part of the Go standard library, specifically the `net` package. The `cgo` prefix suggests interaction with C code. The `unix` suffix hints at POSIX-like operating systems.
* **Copyright and Build Tag:** The header comments confirm it's part of Go's standard library. The `//go:build !netgo && ((cgo && unix) || darwin)` line is crucial. This tells us the file is included in builds that *don't* use the pure Go resolver (`!netgo`) and *do* either use CGO on a Unix-like system (`cgo && unix`) or are running on macOS (`darwin`). This immediately highlights the purpose: to leverage system-level name resolution using C libraries when available.
* **Package Declaration:** `package net` reinforces that this is part of the core networking functionality.
* **Imports:**  The imports reveal the dependencies:
    * `context`: For managing operation lifetimes and cancellations.
    * `errors`: For standard error handling.
    * `internal/bytealg`: For optimized byte-slice operations.
    * `net/netip`:  For the newer IP address types.
    * `runtime`: To check the operating system.
    * `syscall`:  For direct system call access (even though the comment says it avoids direct `C.foo`).
    * `unsafe`: For potentially dangerous memory manipulation, which is common in C interop.
    * `golang.org/x/net/dns/dnsmessage`: For parsing DNS messages.

**2. Identifying Key Data Structures and Constants:**

* `cgoAvailable`: This constant being `true` under the given build constraints is a strong indicator that this file is about providing the CGO-based resolver.
* `addrinfoErrno`: This custom type represents errors returned by `getaddrinfo` and `getnameinfo` C functions, including methods for string representation, temporariness, and timeout.

**3. Analyzing Functions and Their Roles (Iterative Process):**

I would go through each function, trying to understand its purpose and how it interacts with the others.

* **`doBlockingWithCtx`:** This function's name and comments are very telling. It's a helper to execute a blocking function (likely a C call) within a Go goroutine while respecting a `context.Context`. This is a common pattern when dealing with C libraries that don't natively support Go's concurrency model. The `acquireThread` and `releaseThread` calls suggest management of OS threads for C calls.
* **`cgoLookupHost`:** This function seems to resolve a hostname to a list of IP addresses. It calls `cgoLookupIP` and converts the `IPAddr` results to strings.
* **`cgoLookupPort`:** This function takes a network and service name and resolves the port number. It uses `getaddrinfo` with hints based on the network type. The `doBlockingWithCtx` pattern appears again.
* **`cgoLookupServicePort`:**  This is the core function for port resolution, handling the low-level C calls to `getaddrinfo`. It deals with potential errors from `getaddrinfo` and extracts the port from the returned socket address structure. The use of `unsafe` to access the `RawSockaddrInet4` and `RawSockaddrInet6` structures is a key detail.
* **`cgoLookupHostIP`:** Similar to `cgoLookupHost`, but returns `IPAddr` objects directly. It uses `getaddrinfo` with specific hints and handles various `getaddrinfo` error codes.
* **`cgoLookupIP`:**  A simple wrapper around `cgoLookupHostIP` using `doBlockingWithCtx`.
* **`cgoLookupPTR`:** This function performs a reverse DNS lookup (IP address to hostname). It uses `netip.ParseAddr` to parse the input and then calls `cgoLookupAddrPTR`.
* **`cgoLookupAddrPTR`:** The core function for reverse DNS lookup, using `cgoNameinfoPTR` (presumably a wrapper for `getnameinfo`). It handles buffer overflow situations by increasing the buffer size.
* **`cgoSockaddr`:** This function converts a Go `IP` and optional zone to a C `sockaddr` structure. This is necessary to pass Go IP addresses to C functions.
* **`cgoLookupCNAME`:**  This function looks up the canonical name (CNAME) for a hostname using the `res_search` family of functions.
* **`resSearch`:**  A wrapper around `cgoResSearch` using `doBlockingWithCtx`.
* **`cgoResSearch`:** This function directly interacts with the C `res_nsearch` function to perform DNS queries. It handles buffer allocation and parsing of the DNS response.

**4. Identifying Functionality and High-Level Purpose:**

Based on the function names and their interactions, it becomes clear that this file implements a DNS resolver that uses the system's native resolver through CGO. It provides functions to:

* Resolve hostnames to IP addresses (`cgoLookupHost`, `cgoLookupIP`).
* Resolve service names to port numbers (`cgoLookupPort`).
* Perform reverse DNS lookups (`cgoLookupPTR`).
* Look up CNAME records (`cgoLookupCNAME`).
* Perform general DNS queries (`resSearch`).

The use of `doBlockingWithCtx` is a central pattern, indicating that many of these operations involve blocking C calls.

**5. Inferring Go Language Feature Implementation:**

The primary Go language feature being implemented here is the **net package's DNS resolution functionality**. Specifically, it's the CGO-based implementation that's used when the `netgo` tag is not present and CGO is enabled (or on macOS).

**6. Considering Examples, Assumptions, and Potential Pitfalls:**

* **Examples:** I would think about simple use cases for each function, like looking up "google.com", resolving the port for "http", or doing a reverse lookup for an IP.
* **Assumptions:** The code assumes the presence of standard C libraries like `libc` and the availability of functions like `getaddrinfo`, `getnameinfo`, and `res_nsearch`.
* **Pitfalls:**  The main potential pitfall for users is related to **blocking operations**. If a DNS lookup takes a long time, it can block the underlying OS thread if not handled correctly. The `doBlockingWithCtx` function attempts to mitigate this by running the blocking call in a separate goroutine, but users still need to be mindful of timeouts and cancellations. Another potential issue could arise from differences in system resolver behavior across different platforms.

**7. Structuring the Answer:**

Finally, I would organize the findings into a clear and structured answer, covering the requested points: functionality, Go feature implementation, code examples, command-line arguments (though none are directly in this file), and potential pitfalls. Using clear headings and bullet points makes the information easier to digest. I would also ensure to use Chinese as requested.

This iterative process of examining the code, understanding its context, and inferring its purpose allows for a comprehensive analysis of the `cgo_unix.go` file.
这是 Go 语言 `net` 包中用于在 Unix 系统上使用 CGO 进行 DNS 查询的一部分实现。它依赖于底层的 C 库函数，例如 `getaddrinfo` 和 `getnameinfo`，以及 `res_nsearch`。

**功能列举:**

1. **`cgoAvailable` 常量:**  指示当前系统是否可以使用 CGO 解析器。在这个文件中，它的值被设置为 `true`，表明在满足构建条件（非 `netgo` 且 `cgo && unix` 或 `darwin`）的情况下，CGO 解析器可用。

2. **`addrinfoErrno` 类型:** 表示 `getaddrinfo` 和 `getnameinfo` 特有的错误码。它实现了 `error` 接口，并提供了判断错误是否是临时性 (`Temporary`) 或超时 (`Timeout`) 的方法。

3. **`doBlockingWithCtx` 函数:**  当提供的 `context` 可取消时，在一个单独的 goroutine 中执行一个阻塞函数。这主要用于那些不支持上下文取消的调用（例如 CGO 和系统调用）。它使用了 `acquireThread` 和 `releaseThread` 来管理线程，以避免阻塞 Go 的调度器。

4. **`cgoLookupHost` 函数:**  使用 CGO 解析器查找给定主机名的 IP 地址。它内部调用 `cgoLookupIP` 并将返回的 `IPAddr` 转换为字符串形式。

5. **`cgoLookupPort` 函数:** 使用 CGO 解析器查找给定网络和服务的端口号。它根据网络类型设置 `addrinfo` 结构的提示信息，并调用 `cgoLookupServicePort` 执行实际的查找。

6. **`cgoLookupServicePort` 函数:**  执行使用 CGO 的实际端口查找。它将服务名转换为 C 字符串，调用 `getaddrinfo`，并解析返回的 `addrinfo` 结构以获取端口号。

7. **`cgoLookupHostIP` 函数:** 使用 CGO 解析器查找给定主机名的 `IPAddr` 列表。它设置 `addrinfo` 结构的提示信息，调用 `getaddrinfo`，并解析返回的 `addrinfo` 结构以获取 IP 地址。

8. **`cgoLookupIP` 函数:**  使用 CGO 解析器查找给定网络和主机名的 IP 地址。它调用 `doBlockingWithCtx` 来执行阻塞的 `cgoLookupHostIP` 操作。

9. **`cgoLookupPTR` 函数:** 使用 CGO 解析器执行反向 DNS 查找，将 IP 地址转换为主机名。它解析输入的 IP 地址，并调用 `cgoLookupAddrPTR` 执行实际的查找。

10. **`cgoLookupAddrPTR` 函数:** 执行使用 CGO 的实际反向 DNS 查找。它调用 `getnameinfo`，并将结果主机名存储在缓冲区中。为了处理缓冲区溢出的情况，它会逐步增加缓冲区的大小。

11. **`cgoSockaddr` 函数:** 将 Go 的 `IP` 地址和可选的 Zone 信息转换为 C 的 `sockaddr` 结构体。

12. **`cgoLookupCNAME` 函数:** 使用 CGO 的 `res_search` 函数查找给定主机名的 CNAME 记录。

13. **`resSearch` 函数:**  作为 `cgoResSearch` 的包装器，使用 `doBlockingWithCtx` 来执行阻塞的 DNS 查询。

14. **`cgoResSearch` 函数:**  直接调用 C 库的 `res_nsearch` 函数来执行 DNS 查询。它处理 `res_ninit` 和 `res_nclose` 的初始化和清理工作，并解析返回的 DNS 响应。

**Go 语言功能实现推断 (DNS 解析器):**

这个文件是 Go 语言 `net` 包中 DNS 解析器的一个特定实现分支。当构建 Go 程序时，如果满足 `!netgo && ((cgo && unix) || darwin)` 的条件，Go 将会使用这个基于 CGO 的 DNS 解析器，而不是纯 Go 实现的解析器。这允许 Go 程序利用操作系统底层的 DNS 解析能力，例如读取 `/etc/hosts` 文件或使用 `nsswitch.conf` 配置的不同解析源。

**Go 代码举例说明 (`cgoLookupHost`):**

假设我们要查找主机名 "www.example.com" 的 IP 地址。

```go
package main

import (
	"context"
	"fmt"
	"net"
)

func main() {
	hosts, err := net.DefaultResolver.LookupHost(context.Background(), "www.example.com")
	if err != nil {
		fmt.Println("查找主机失败:", err)
		return
	}
	fmt.Println("主机 www.example.com 的 IP 地址:", hosts)
}
```

**假设输入与输出:**

**输入:**

* `name` (传递给 `net.DefaultResolver.LookupHost` 的参数): "www.example.com"

**输出 (取决于 DNS 解析结果):**

```
主机 www.example.com 的 IP 地址: [93.184.216.34 2606:2800:220:1:248:1893:25c8:1946]
```

或者，如果解析失败:

```
查找主机失败: lookup www.example.com: no such host
```

**代码推理:**

当调用 `net.DefaultResolver.LookupHost` 时，如果满足构建条件，最终会调用到 `cgoLookupHost` 函数。 `cgoLookupHost` 内部会调用底层的 C 函数 `getaddrinfo` 来进行 DNS 查询。`getaddrinfo` 会根据系统配置（例如 `/etc/resolv.conf`）执行实际的 DNS 解析，并将结果返回给 Go 程序。 `cgoLookupHost` 再将 `getaddrinfo` 返回的地址信息转换为字符串数组返回。

**命令行参数的具体处理:**

在这个文件中，并没有直接处理命令行参数。它主要负责 DNS 查询的核心逻辑。命令行参数的处理通常发生在更高层次的应用程序代码中，例如使用 `flag` 包来解析用户提供的参数，然后将相关的主机名或 IP 地址传递给 `net` 包的函数进行解析。

**使用者易犯错的点 (以 `cgoLookupPort` 为例):**

一个容易犯错的点是在使用 `cgoLookupPort` 时，提供的 `network` 参数不正确或与 `service` 参数不匹配。

**举例说明:**

假设我们想查找 TCP 服务的 "http" 的端口号，但错误地将 `network` 设置为 "udp"。

```go
package main

import (
	"context"
	"fmt"
	"net"
)

func main() {
	port, err := net.DefaultResolver.LookupPort(context.Background(), "udp", "http")
	if err != nil {
		fmt.Println("查找端口失败:", err)
		return
	}
	fmt.Println("服务 http 的端口号 (UDP):", port)
}
```

**输出 (可能):**

```
查找端口失败: lookup udp/http: unknown port
```

**解释:**

`cgoLookupPort` 会根据 `network` 参数设置 `addrinfo` 结构中的 `ai_socktype` 和 `ai_protocol` 字段。如果 `network` 是 "udp"，它会设置查找 UDP 端口。然而，标准的服务 "http" 通常与 TCP 关联。因此，`getaddrinfo` 在查找 UDP 协议下的 "http" 服务时可能会找不到对应的端口号，导致返回 "unknown port" 错误。

**总结:**

`go/src/net/cgo_unix.go` 是 Go 语言 `net` 包中重要的组成部分，它利用 CGO 提供了与底层操作系统 DNS 解析能力对接的桥梁。这使得 Go 程序能够利用系统级的 DNS 配置，但也引入了一些与 C 库交互相关的复杂性。理解其功能和潜在的错误点对于编写健壮的网络应用程序至关重要。

Prompt: 
```
这是路径为go/src/net/cgo_unix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is called cgo_unix.go, but to allow syscalls-to-libc-based
// implementations to share the code, it does not use cgo directly.
// Instead of C.foo it uses _C_foo, which is defined in either
// cgo_unix_cgo.go or cgo_unix_syscall.go

//go:build !netgo && ((cgo && unix) || darwin)

package net

import (
	"context"
	"errors"
	"internal/bytealg"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
)

// cgoAvailable set to true to indicate that the cgo resolver
// is available on this system.
const cgoAvailable = true

// An addrinfoErrno represents a getaddrinfo, getnameinfo-specific
// error number. It's a signed number and a zero value is a non-error
// by convention.
type addrinfoErrno int

func (eai addrinfoErrno) Error() string   { return _C_gai_strerror(_C_int(eai)) }
func (eai addrinfoErrno) Temporary() bool { return eai == _C_EAI_AGAIN }
func (eai addrinfoErrno) Timeout() bool   { return false }

// isAddrinfoErrno is just for testing purposes.
func (eai addrinfoErrno) isAddrinfoErrno() {}

// doBlockingWithCtx executes a blocking function in a separate goroutine when the provided
// context is cancellable. It is intended for use with calls that don't support context
// cancellation (cgo, syscalls). blocking func may still be running after this function finishes.
// For the duration of the execution of the blocking function, the thread is 'acquired' using [acquireThread],
// blocking might not be executed when the context gets canceled early.
func doBlockingWithCtx[T any](ctx context.Context, lookupName string, blocking func() (T, error)) (T, error) {
	if err := acquireThread(ctx); err != nil {
		var zero T
		return zero, &DNSError{
			Name:      lookupName,
			Err:       mapErr(err).Error(),
			IsTimeout: err == context.DeadlineExceeded,
		}
	}

	if ctx.Done() == nil {
		defer releaseThread()
		return blocking()
	}

	type result struct {
		res T
		err error
	}

	res := make(chan result, 1)
	go func() {
		defer releaseThread()
		var r result
		r.res, r.err = blocking()
		res <- r
	}()

	select {
	case r := <-res:
		return r.res, r.err
	case <-ctx.Done():
		var zero T
		return zero, &DNSError{
			Name:      lookupName,
			Err:       mapErr(ctx.Err()).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
}

func cgoLookupHost(ctx context.Context, name string) (hosts []string, err error) {
	addrs, err := cgoLookupIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		hosts = append(hosts, addr.String())
	}
	return hosts, nil
}

func cgoLookupPort(ctx context.Context, network, service string) (port int, err error) {
	var hints _C_struct_addrinfo
	switch network {
	case "ip": // no hints
	case "tcp", "tcp4", "tcp6":
		*_C_ai_socktype(&hints) = _C_SOCK_STREAM
		*_C_ai_protocol(&hints) = _C_IPPROTO_TCP
	case "udp", "udp4", "udp6":
		*_C_ai_socktype(&hints) = _C_SOCK_DGRAM
		*_C_ai_protocol(&hints) = _C_IPPROTO_UDP
	default:
		return 0, &DNSError{Err: "unknown network", Name: network + "/" + service}
	}
	switch ipVersion(network) {
	case '4':
		*_C_ai_family(&hints) = _C_AF_INET
	case '6':
		*_C_ai_family(&hints) = _C_AF_INET6
	}

	return doBlockingWithCtx(ctx, network+"/"+service, func() (int, error) {
		return cgoLookupServicePort(&hints, network, service)
	})
}

func cgoLookupServicePort(hints *_C_struct_addrinfo, network, service string) (port int, err error) {
	cservice, err := syscall.ByteSliceFromString(service)
	if err != nil {
		return 0, &DNSError{Err: err.Error(), Name: network + "/" + service}
	}
	// Lowercase the C service name.
	for i, b := range cservice[:len(service)] {
		cservice[i] = lowerASCII(b)
	}
	var res *_C_struct_addrinfo
	gerrno, err := _C_getaddrinfo(nil, (*_C_char)(unsafe.Pointer(&cservice[0])), hints, &res)
	if gerrno != 0 {
		switch gerrno {
		case _C_EAI_SYSTEM:
			if err == nil { // see golang.org/issue/6232
				err = syscall.EMFILE
			}
			return 0, newDNSError(err, network+"/"+service, "")
		case _C_EAI_SERVICE, _C_EAI_NONAME: // Darwin returns EAI_NONAME.
			return 0, newDNSError(errUnknownPort, network+"/"+service, "")
		default:
			return 0, newDNSError(addrinfoErrno(gerrno), network+"/"+service, "")
		}
	}
	defer _C_freeaddrinfo(res)

	for r := res; r != nil; r = *_C_ai_next(r) {
		switch *_C_ai_family(r) {
		case _C_AF_INET:
			sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(*_C_ai_addr(r)))
			p := (*[2]byte)(unsafe.Pointer(&sa.Port))
			return int(p[0])<<8 | int(p[1]), nil
		case _C_AF_INET6:
			sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(*_C_ai_addr(r)))
			p := (*[2]byte)(unsafe.Pointer(&sa.Port))
			return int(p[0])<<8 | int(p[1]), nil
		}
	}
	return 0, newDNSError(errUnknownPort, network+"/"+service, "")
}

func cgoLookupHostIP(network, name string) (addrs []IPAddr, err error) {
	var hints _C_struct_addrinfo
	*_C_ai_flags(&hints) = cgoAddrInfoFlags
	*_C_ai_socktype(&hints) = _C_SOCK_STREAM
	*_C_ai_family(&hints) = _C_AF_UNSPEC
	switch ipVersion(network) {
	case '4':
		*_C_ai_family(&hints) = _C_AF_INET
	case '6':
		*_C_ai_family(&hints) = _C_AF_INET6
	}

	h, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, &DNSError{Err: err.Error(), Name: name}
	}
	var res *_C_struct_addrinfo
	gerrno, err := _C_getaddrinfo((*_C_char)(unsafe.Pointer(h)), nil, &hints, &res)
	if gerrno != 0 {
		switch gerrno {
		case _C_EAI_SYSTEM:
			if err == nil {
				// err should not be nil, but sometimes getaddrinfo returns
				// gerrno == _C_EAI_SYSTEM with err == nil on Linux.
				// The report claims that it happens when we have too many
				// open files, so use syscall.EMFILE (too many open files in system).
				// Most system calls would return ENFILE (too many open files),
				// so at the least EMFILE should be easy to recognize if this
				// comes up again. golang.org/issue/6232.
				err = syscall.EMFILE
			}
			return nil, newDNSError(err, name, "")
		case _C_EAI_NONAME, _C_EAI_NODATA:
			return nil, newDNSError(errNoSuchHost, name, "")
		case _C_EAI_ADDRFAMILY:
			if runtime.GOOS == "freebsd" {
				// FreeBSD began returning EAI_ADDRFAMILY for valid hosts without
				// an A record in 13.2. We previously returned "no such host" for
				// this case.
				//
				// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=273912
				return nil, newDNSError(errNoSuchHost, name, "")
			}
			fallthrough
		default:
			return nil, newDNSError(addrinfoErrno(gerrno), name, "")
		}

	}
	defer _C_freeaddrinfo(res)

	for r := res; r != nil; r = *_C_ai_next(r) {
		// We only asked for SOCK_STREAM, but check anyhow.
		if *_C_ai_socktype(r) != _C_SOCK_STREAM {
			continue
		}
		switch *_C_ai_family(r) {
		case _C_AF_INET:
			sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(*_C_ai_addr(r)))
			addr := IPAddr{IP: copyIP(sa.Addr[:])}
			addrs = append(addrs, addr)
		case _C_AF_INET6:
			sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(*_C_ai_addr(r)))
			addr := IPAddr{IP: copyIP(sa.Addr[:]), Zone: zoneCache.name(int(sa.Scope_id))}
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

func cgoLookupIP(ctx context.Context, network, name string) (addrs []IPAddr, err error) {
	return doBlockingWithCtx(ctx, name, func() ([]IPAddr, error) {
		return cgoLookupHostIP(network, name)
	})
}

// These are roughly enough for the following:
//
//	 Source		Encoding			Maximum length of single name entry
//	 Unicast DNS		ASCII or			<=253 + a NUL terminator
//				Unicode in RFC 5892		252 * total number of labels + delimiters + a NUL terminator
//	 Multicast DNS	UTF-8 in RFC 5198 or		<=253 + a NUL terminator
//				the same as unicast DNS ASCII	<=253 + a NUL terminator
//	 Local database	various				depends on implementation
const (
	nameinfoLen    = 64
	maxNameinfoLen = 4096
)

func cgoLookupPTR(ctx context.Context, addr string) (names []string, err error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, &DNSError{Err: "invalid address", Name: addr}
	}
	sa, salen := cgoSockaddr(IP(ip.AsSlice()), ip.Zone())
	if sa == nil {
		return nil, &DNSError{Err: "invalid address " + ip.String(), Name: addr}
	}

	return doBlockingWithCtx(ctx, addr, func() ([]string, error) {
		return cgoLookupAddrPTR(addr, sa, salen)
	})
}

func cgoLookupAddrPTR(addr string, sa *_C_struct_sockaddr, salen _C_socklen_t) (names []string, err error) {
	var gerrno int
	var b []byte
	for l := nameinfoLen; l <= maxNameinfoLen; l *= 2 {
		b = make([]byte, l)
		gerrno, err = cgoNameinfoPTR(b, sa, salen)
		if gerrno == 0 || gerrno != _C_EAI_OVERFLOW {
			break
		}
	}
	if gerrno != 0 {
		switch gerrno {
		case _C_EAI_SYSTEM:
			if err == nil { // see golang.org/issue/6232
				err = syscall.EMFILE
			}
			return nil, newDNSError(err, addr, "")
		case _C_EAI_NONAME:
			return nil, newDNSError(errNoSuchHost, addr, "")
		default:
			return nil, newDNSError(addrinfoErrno(gerrno), addr, "")
		}
	}
	if i := bytealg.IndexByte(b, 0); i != -1 {
		b = b[:i]
	}
	return []string{absDomainName(string(b))}, nil
}

func cgoSockaddr(ip IP, zone string) (*_C_struct_sockaddr, _C_socklen_t) {
	if ip4 := ip.To4(); ip4 != nil {
		return cgoSockaddrInet4(ip4), _C_socklen_t(syscall.SizeofSockaddrInet4)
	}
	if ip6 := ip.To16(); ip6 != nil {
		return cgoSockaddrInet6(ip6, zoneCache.index(zone)), _C_socklen_t(syscall.SizeofSockaddrInet6)
	}
	return nil, 0
}

func cgoLookupCNAME(ctx context.Context, name string) (cname string, err error, completed bool) {
	resources, err := resSearch(ctx, name, int(dnsmessage.TypeCNAME), int(dnsmessage.ClassINET))
	if err != nil {
		return
	}
	cname, err = parseCNAMEFromResources(resources)
	if err != nil {
		return "", err, false
	}
	return cname, nil, true
}

// resSearch will make a call to the 'res_nsearch' routine in the C library
// and parse the output as a slice of DNS resources.
func resSearch(ctx context.Context, hostname string, rtype, class int) ([]dnsmessage.Resource, error) {
	return doBlockingWithCtx(ctx, hostname, func() ([]dnsmessage.Resource, error) {
		return cgoResSearch(hostname, rtype, class)
	})
}

func cgoResSearch(hostname string, rtype, class int) ([]dnsmessage.Resource, error) {
	resStateSize := unsafe.Sizeof(_C_struct___res_state{})
	var state *_C_struct___res_state
	if resStateSize > 0 {
		mem := _C_malloc(resStateSize)
		defer _C_free(mem)
		memSlice := unsafe.Slice((*byte)(mem), resStateSize)
		clear(memSlice)
		state = (*_C_struct___res_state)(unsafe.Pointer(&memSlice[0]))
	}
	if err := _C_res_ninit(state); err != nil {
		return nil, errors.New("res_ninit failure: " + err.Error())
	}
	defer _C_res_nclose(state)

	// Some res_nsearch implementations (like macOS) do not set errno.
	// They set h_errno, which is not per-thread and useless to us.
	// res_nsearch returns the size of the DNS response packet.
	// But if the DNS response packet contains failure-like response codes,
	// res_search returns -1 even though it has copied the packet into buf,
	// giving us no way to find out how big the packet is.
	// For now, we are willing to take res_search's word that there's nothing
	// useful in the response, even though there *is* a response.
	bufSize := maxDNSPacketSize
	buf := (*_C_uchar)(_C_malloc(uintptr(bufSize)))
	defer _C_free(unsafe.Pointer(buf))

	s, err := syscall.BytePtrFromString(hostname)
	if err != nil {
		return nil, err
	}

	var size int
	for {
		size := _C_res_nsearch(state, (*_C_char)(unsafe.Pointer(s)), class, rtype, buf, bufSize)
		if size <= 0 || size > 0xffff {
			return nil, errors.New("res_nsearch failure")
		}
		if size <= bufSize {
			break
		}

		// Allocate a bigger buffer to fit the entire msg.
		_C_free(unsafe.Pointer(buf))
		bufSize = size
		buf = (*_C_uchar)(_C_malloc(uintptr(bufSize)))
	}

	var p dnsmessage.Parser
	if _, err := p.Start(unsafe.Slice((*byte)(unsafe.Pointer(buf)), size)); err != nil {
		return nil, err
	}
	p.SkipAllQuestions()
	resources, err := p.AllAnswers()
	if err != nil {
		return nil, err
	}
	return resources, nil
}

"""



```