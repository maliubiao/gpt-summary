Response:
我的思考过程如下：

1. **理解文件路径和语言：**  文件路径 `go/src/net/lookup_windows.go` 明确指出这是 Go 语言标准库 `net` 包中，专门处理 Windows 平台网络查找功能的文件。

2. **通读代码，识别主要功能块：**  快速浏览代码，注意到以下几个重要的函数和常量：
    * `cgoAvailable`:  表明 Windows 下的解析器是否可用（这里是 `true`，但注释说明不真正使用 cgo）。
    * `winError`:  将 Windows 特有的错误转换为 Go 的 `DNSError`。
    * `getprotobyname`:  通过协议名获取协议号。
    * `lookupProtocol`:  封装 `getprotobyname`，并处理并发和上下文。
    * `lookupHost`:  通过主机名查找 IP 地址。
    * `lookupIP`:  核心的 IP 地址查找函数，调用 Windows API `GetAddrInfoW`。
    * `lookupPort`:  通过服务名查找端口号。
    * `lookupCNAME`:  查找域名的 CNAME 记录。
    * `lookupSRV`:  查找 SRV 记录。
    * `lookupMX`:  查找 MX 记录。
    * `lookupNS`:  查找 NS 记录。
    * `lookupTXT`:  查找 TXT 记录。
    * `lookupAddr`:  通过 IP 地址反向查找域名（PTR 记录）。
    * `validRecs` 和 `resolveCNAME`:  辅助函数，用于处理 DNS 记录。
    * `concurrentThreadsLimit`:  限制并发 DNS 查询的线程数。

3. **归纳主要功能：** 基于识别出的功能块，可以总结出这个文件的核心职责是实现 Go 语言 `net` 包在 Windows 平台上的域名解析功能。  具体来说，它提供了查找主机 IP 地址、协议号、端口号、各种 DNS 记录（CNAME、SRV、MX、NS、TXT、PTR）的能力。

4. **推断 Go 语言功能实现：**  结合上下文和函数名，可以推断出这是 `net` 包中用于进行域名解析的实现。  `net.LookupHost`、`net.LookupIP`、`net.LookupPort` 等标准库函数在 Windows 平台上会使用这里的实现。

5. **编写代码示例：**  针对推断出的 Go 语言功能，编写相应的代码示例。  示例应包含常见的域名解析场景，例如查找主机 IP、查找 MX 记录等，并展示如何处理返回的结果和可能的错误。  同时，需要包含假设的输入和输出，以更清晰地说明函数的行为。

6. **分析命令行参数：**  仔细检查代码，发现该文件本身没有直接处理命令行参数。 域名解析的配置（如 DNS 服务器）通常由操作系统配置管理，Go 程序通过系统调用获取这些信息。  因此，需要说明该文件不涉及命令行参数处理，但域名解析依赖于系统配置。

7. **识别易犯错的点：**  阅读代码，特别是错误处理部分，可以发现一些潜在的易错点：
    * **上下文超时：**  代码中多次使用 `context.Context` 来控制超时，如果使用不当，可能导致 DNS 查询过早中断。
    * **Windows 错误码：**  需要了解一些 Windows 特有的 DNS 错误码，例如 `_WSAHOST_NOT_FOUND` 等。
    * **CGO 的理解：** 虽然声明了 `cgoAvailable` 为 `true`，但注释说明实际上没有使用 cgo，这可能会让一些开发者感到困惑。

8. **组织答案并使用中文：** 将以上分析结果组织成结构清晰、逻辑连贯的中文答案。 确保涵盖了所有要求，包括功能列表、Go 代码示例、代码推理、命令行参数、易犯错的点等。  注意代码示例中的注释，以便更好地解释代码的功能和预期输出。

通过以上步骤，我对给定的 Go 语言代码进行了分析和推理，并最终生成了符合要求的中文答案。  重点在于理解代码的功能和其在 Go 语言标准库中的作用，并能够结合实际场景给出示例和解释。
这是 `go/src/net/lookup_windows.go` 文件的功能分析：

**主要功能:**

这个文件实现了 Go 语言 `net` 包在 Windows 操作系统上的域名解析 (DNS resolution) 相关功能。它提供了将主机名解析为 IP 地址、服务名解析为端口号以及查询各种 DNS 记录（如 CNAME, MX, SRV, TXT, NS, PTR）的能力。  该文件使用了 Windows 操作系统提供的原生 DNS 解析 API，例如 `GetAddrInfoW` 和 `DnsQuery`。

**具体功能点:**

1. **错误处理:**  定义了 Windows 特定的 DNS 错误代码（如 `_WSAHOST_NOT_FOUND`, `_WSATRY_AGAIN`, `_WSATYPE_NOT_FOUND` 等），并将这些错误转换为 Go 语言中 `net` 包的通用 DNS 错误类型 (`DNSError`)，方便跨平台使用。

2. **获取协议号:**  实现了 `getprotobyname` 函数，用于根据协议名称（例如 "tcp", "udp"）获取对应的协议号。 `lookupProtocol` 函数则在此基础上增加了上下文管理和并发控制。

3. **查找主机 IP 地址 (`lookupHost`, `lookupIP`):**
   - `lookupHost` 函数是查找主机名对应 IP 地址的便捷方法，返回字符串形式的 IP 地址。
   - `lookupIP` 是核心函数，它使用 Windows 的 `GetAddrInfoW` API 来查询指定主机名的 IP 地址。  可以指定网络类型（"ip"、"tcp"、"udp" 等）和 IP 协议版本（IPv4 或 IPv6）。
   - 它处理了 `context.Context`，允许设置超时和取消操作。
   - 它会尝试根据系统配置选择是否使用 Go 原生的解析器或者 CGO (这里在 Windows 上实际上不使用真正的 CGO，而是直接调用 Windows API)。
   - 内部会根据网络类型 (`network`) 设置 `GetAddrInfoW` 的 `hints` 参数，例如协议族 (`Family`)、套接字类型 (`Socktype`) 和协议 (`Protocol`)。
   - 它处理了 `_WSATRY_AGAIN` 错误，并在超时前进行重试。

4. **查找端口号 (`lookupPort`):**  使用 Windows 的 `GetAddrInfoW` API，但 `nodename` 参数为 `nil`，`servname` 参数为要查找的服务名。它可以根据网络类型（例如 "tcp", "udp"）来查找对应的端口号。

5. **查找 CNAME 记录 (`lookupCNAME`):**  使用 Windows 的 `DnsQuery` API 来查询指定主机名的 CNAME (Canonical Name) 记录。

6. **查找 SRV 记录 (`lookupSRV`):** 使用 Windows 的 `DnsQuery` API 查询指定服务和协议的 SRV (Service Resource) 记录。

7. **查找 MX 记录 (`lookupMX`):** 使用 Windows 的 `DnsQuery` API 查询指定域名的 MX (Mail Exchanger) 记录。

8. **查找 NS 记录 (`lookupNS`):** 使用 Windows 的 `DnsQuery` API 查询指定域名的 NS (Name Server) 记录。

9. **查找 TXT 记录 (`lookupTXT`):** 使用 Windows 的 `DnsQuery` API 查询指定域名的 TXT (Text) 记录。

10. **查找 PTR 记录 (反向 DNS 查找) (`lookupAddr`):**  将 IP 地址转换为 `arpa` 格式，然后使用 Windows 的 `DnsQuery` API 查询对应的 PTR (Pointer) 记录，从而找到与 IP 地址关联的主机名。

11. **辅助函数:**
    - `winError`: 将 Windows 系统调用返回的错误转换为 `net.DNSError`。
    - `validRecs`: 用于过滤 `DnsQuery` 返回的记录，只保留与查询名称和类型匹配的记录，并处理 CNAME 链。
    - `resolveCNAME`: 用于解析 CNAME 链，找到最终的非 CNAME 记录。
    - `concurrentThreadsLimit`:  限制并发 DNS 查询的线程数量。

**它是什么 Go 语言功能的实现:**

这个文件是 Go 语言 `net` 包中进行域名解析功能在 Windows 平台上的具体实现。  用户通常不会直接调用这个文件中的函数，而是使用 `net` 包提供的更高级别的 API，例如：

- `net.LookupHost(name string)`:  查找主机名的 IPv4 和 IPv6 地址。
- `net.LookupIP(name string)`:  更精细地查找主机名的 IP 地址，可以指定 IP 版本。
- `net.LookupPort(network, service string)`: 查找指定网络协议和服务的端口号。
- `net.LookupCNAME(name string)`: 查找域名的规范名称 (CNAME)。
- `net.LookupMX(name string)`:  查找域名的邮件交换服务器 (MX 记录)。
- `net.LookupSRV(service, proto, name string)`: 查找服务的 SRV 记录。
- `net.LookupNS(name string)`: 查找域名的权威名称服务器 (NS 记录)。
- `net.LookupTXT(name string)`: 查找域名的 TXT 记录。
- `net.LookupAddr(addr string)`:  根据 IP 地址反向查找主机名。

**Go 代码举例说明:**

```go
package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 查找主机 IP 地址
	ips, err := net.LookupHost(ctx, "www.google.com")
	if err != nil {
		fmt.Println("LookupHost 错误:", err)
	} else {
		fmt.Println("www.google.com 的 IP 地址:", ips)
	}

	// 查找 MX 记录
	mxRecords, err := net.LookupMX(ctx, "google.com")
	if err != nil {
		fmt.Println("LookupMX 错误:", err)
	} else {
		fmt.Println("google.com 的 MX 记录:")
		for _, mx := range mxRecords {
			fmt.Printf("  Host: %s, Preference: %d\n", mx.Host, mx.Pref)
		}
	}

	// 查找端口号
	port, err := net.LookupPort(ctx, "tcp", "http")
	if err != nil {
		fmt.Println("LookupPort 错误:", err)
	} else {
		fmt.Println("http 的 TCP 端口:", port)
	}
}
```

**假设的输入与输出:**

假设在 Windows 系统上运行上述代码：

**输入:**

无，代码中硬编码了要查询的主机名和服务名。

**可能的输出:**

```
www.google.com 的 IP 地址: [142.250.180.142 2404:6800:4004:816::200e]
google.com 的 MX 记录:
  Host: aspmx.l.google.com., Preference: 1
  Host: alt1.aspmx.l.google.com., Preference: 5
  Host: alt2.aspmx.l.google.com., Preference: 5
  Host: alt3.aspmx.l.google.com., Preference: 10
  Host: alt4.aspmx.l.google.com., Preference: 10
http 的 TCP 端口: 80
```

**代码推理:**

- `net.LookupHost("www.google.com")` 内部会调用 `lookup_windows.go` 中的 `(*Resolver).lookupHost` 函数，最终通过 `GetAddrInfoW` 获取 `www.google.com` 的 IP 地址。
- `net.LookupMX("google.com")` 内部会调用 `(*Resolver).lookupMX` 函数，通过 `DnsQuery` 并指定 `DNS_TYPE_MX` 来获取 `google.com` 的 MX 记录。
- `net.LookupPort("tcp", "http")` 内部会调用 `(*Resolver).lookupPort` 函数，通过 `GetAddrInfoW` 并根据服务名 "http" 和协议 "tcp" 来查找对应的端口号。

**命令行参数的具体处理:**

该文件本身不直接处理命令行参数。Go 程序的域名解析行为通常受到系统网络配置的影响，例如 DNS 服务器的配置。Go 程序会读取操作系统的 DNS 配置来进行域名解析。

**使用者易犯错的点:**

1. **上下文超时设置不合理:**  如果在创建 `context.Context` 时设置的超时时间过短，可能会导致 DNS 查询在完成前就被取消，从而返回错误。

   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond) // 超时时间过短
   defer cancel()
   ips, err := net.LookupHost(ctx, "www.example.com")
   if err != nil {
       fmt.Println("查找失败:", err) // 很可能因为超时而失败
   }
   ```

2. **错误处理不当:**  未能正确处理 `net.DNSError` 返回的各种错误类型，例如未找到主机、连接超时等。  可以检查 `err` 是否是 `*net.DNSError` 类型，并进一步判断 `IsNotFound` 或 `IsTimeout` 属性。

   ```go
   ips, err := net.LookupHost(context.Background(), "nonexistent.example.com")
   if err != nil {
       dnsErr, ok := err.(*net.DNSError)
       if ok {
           if dnsErr.IsNotFound {
               fmt.Println("主机未找到")
           } else if dnsErr.IsTimeout {
               fmt.Println("DNS 查询超时")
           } else {
               fmt.Println("其他 DNS 错误:", dnsErr)
           }
       } else {
           fmt.Println("其他错误:", err)
       }
   }
   ```

3. **假设 DNS 解析总是成功:**  网络环境复杂，DNS 解析可能会因为各种原因失败。应该始终检查 `net.Lookup...` 函数的返回值 `err`，并进行适当的处理。

总而言之，`go/src/net/lookup_windows.go` 是 Go 语言在 Windows 平台上实现网络域名解析功能的关键组成部分，它封装了 Windows 系统的 DNS API，并提供了与 Go 语言 `net` 包兼容的接口。使用者可以通过 `net` 包的高级函数来利用这些功能。

### 提示词
```
这是路径为go/src/net/lookup_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package net

import (
	"context"
	"internal/syscall/windows"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// cgoAvailable set to true to indicate that the cgo resolver
// is available on Windows. Note that on Windows the cgo resolver
// does not actually use cgo.
const cgoAvailable = true

const (
	_DNS_ERROR_RCODE_NAME_ERROR = syscall.Errno(9003)
	_DNS_INFO_NO_RECORDS        = syscall.Errno(9501)

	_WSAHOST_NOT_FOUND = syscall.Errno(11001)
	_WSATRY_AGAIN      = syscall.Errno(11002)
	_WSATYPE_NOT_FOUND = syscall.Errno(10109)
)

func winError(call string, err error) error {
	switch err {
	case _WSAHOST_NOT_FOUND, _DNS_ERROR_RCODE_NAME_ERROR, _DNS_INFO_NO_RECORDS:
		return errNoSuchHost
	}
	return os.NewSyscallError(call, err)
}

func getprotobyname(name string) (proto int, err error) {
	p, err := syscall.GetProtoByName(name)
	if err != nil {
		return 0, winError("getprotobyname", err)
	}
	return int(p.Proto), nil
}

// lookupProtocol looks up IP protocol name and returns correspondent protocol number.
func lookupProtocol(ctx context.Context, name string) (int, error) {
	// GetProtoByName return value is stored in thread local storage.
	// Start new os thread before the call to prevent races.
	type result struct {
		proto int
		err   error
	}
	ch := make(chan result) // unbuffered
	go func() {
		if err := acquireThread(ctx); err != nil {
			ch <- result{err: mapErr(err)}
			return
		}
		defer releaseThread()
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		proto, err := getprotobyname(name)
		select {
		case ch <- result{proto: proto, err: err}:
		case <-ctx.Done():
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			if proto, err := lookupProtocolMap(name); err == nil {
				return proto, nil
			}
			r.err = newDNSError(r.err, name, "")
		}
		return r.proto, r.err
	case <-ctx.Done():
		return 0, mapErr(ctx.Err())
	}
}

func (r *Resolver) lookupHost(ctx context.Context, name string) ([]string, error) {
	ips, err := r.lookupIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	return addrs, nil
}

func (r *Resolver) lookupIP(ctx context.Context, network, name string) ([]IPAddr, error) {
	if order, conf := systemConf().hostLookupOrder(r, name); order != hostLookupCgo {
		return r.goLookupIP(ctx, network, name, order, conf)
	}

	// TODO(bradfitz,brainman): use ctx more. See TODO below.

	var family int32 = syscall.AF_UNSPEC
	switch ipVersion(network) {
	case '4':
		family = syscall.AF_INET
	case '6':
		family = syscall.AF_INET6
	}

	getaddr := func() ([]IPAddr, error) {
		if err := acquireThread(ctx); err != nil {
			return nil, &DNSError{
				Name:      name,
				Err:       mapErr(err).Error(),
				IsTimeout: ctx.Err() == context.DeadlineExceeded,
			}
		}
		defer releaseThread()
		hints := syscall.AddrinfoW{
			Family:   family,
			Socktype: syscall.SOCK_STREAM,
			Protocol: syscall.IPPROTO_IP,
		}
		var result *syscall.AddrinfoW
		name16p, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			return nil, newDNSError(err, name, "")
		}

		dnsConf := getSystemDNSConfig()
		start := time.Now()

		var e error
		for i := 0; i < dnsConf.attempts; i++ {
			e = syscall.GetAddrInfoW(name16p, nil, &hints, &result)
			if e == nil || e != _WSATRY_AGAIN || time.Since(start) > dnsConf.timeout {
				break
			}
		}
		if e != nil {
			return nil, newDNSError(winError("getaddrinfow", e), name, "")
		}
		defer syscall.FreeAddrInfoW(result)
		addrs := make([]IPAddr, 0, 5)
		for ; result != nil; result = result.Next {
			addr := unsafe.Pointer(result.Addr)
			switch result.Family {
			case syscall.AF_INET:
				a := (*syscall.RawSockaddrInet4)(addr).Addr
				addrs = append(addrs, IPAddr{IP: copyIP(a[:])})
			case syscall.AF_INET6:
				a := (*syscall.RawSockaddrInet6)(addr).Addr
				zone := zoneCache.name(int((*syscall.RawSockaddrInet6)(addr).Scope_id))
				addrs = append(addrs, IPAddr{IP: copyIP(a[:]), Zone: zone})
			default:
				return nil, newDNSError(syscall.EWINDOWS, name, "")
			}
		}
		return addrs, nil
	}

	type ret struct {
		addrs []IPAddr
		err   error
	}

	var ch chan ret
	if ctx.Err() == nil {
		ch = make(chan ret, 1)
		go func() {
			addr, err := getaddr()
			ch <- ret{addrs: addr, err: err}
		}()
	}

	select {
	case r := <-ch:
		return r.addrs, r.err
	case <-ctx.Done():
		// TODO(bradfitz,brainman): cancel the ongoing
		// GetAddrInfoW? It would require conditionally using
		// GetAddrInfoEx with lpOverlapped, which requires
		// Windows 8 or newer. I guess we'll need oldLookupIP,
		// newLookupIP, and newerLookUP.
		//
		// For now we just let it finish and write to the
		// buffered channel.
		return nil, newDNSError(mapErr(ctx.Err()), name, "")
	}
}

func (r *Resolver) lookupPort(ctx context.Context, network, service string) (int, error) {
	if systemConf().mustUseGoResolver(r) {
		return lookupPortMap(network, service)
	}

	// TODO(bradfitz): finish ctx plumbing
	if err := acquireThread(ctx); err != nil {
		return 0, &DNSError{
			Name:      network + "/" + service,
			Err:       mapErr(err).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
	defer releaseThread()

	var hints syscall.AddrinfoW

	switch network {
	case "ip": // no hints
	case "tcp", "tcp4", "tcp6":
		hints.Socktype = syscall.SOCK_STREAM
		hints.Protocol = syscall.IPPROTO_TCP
	case "udp", "udp4", "udp6":
		hints.Socktype = syscall.SOCK_DGRAM
		hints.Protocol = syscall.IPPROTO_UDP
	default:
		return 0, &DNSError{Err: "unknown network", Name: network + "/" + service}
	}

	switch ipVersion(network) {
	case '4':
		hints.Family = syscall.AF_INET
	case '6':
		hints.Family = syscall.AF_INET6
	}

	var result *syscall.AddrinfoW
	e := syscall.GetAddrInfoW(nil, syscall.StringToUTF16Ptr(service), &hints, &result)
	if e != nil {
		if port, err := lookupPortMap(network, service); err == nil {
			return port, nil
		}

		// The _WSATYPE_NOT_FOUND error is returned by GetAddrInfoW
		// when the service name is unknown. We are also checking
		// for _WSAHOST_NOT_FOUND here to match the cgo (unix) version
		// cgo_unix.go (cgoLookupServicePort).
		if e == _WSATYPE_NOT_FOUND || e == _WSAHOST_NOT_FOUND {
			return 0, newDNSError(errUnknownPort, network+"/"+service, "")
		}
		return 0, newDNSError(winError("getaddrinfow", e), network+"/"+service, "")
	}
	defer syscall.FreeAddrInfoW(result)
	if result == nil {
		return 0, newDNSError(syscall.EINVAL, network+"/"+service, "")
	}
	addr := unsafe.Pointer(result.Addr)
	switch result.Family {
	case syscall.AF_INET:
		a := (*syscall.RawSockaddrInet4)(addr)
		return int(syscall.Ntohs(a.Port)), nil
	case syscall.AF_INET6:
		a := (*syscall.RawSockaddrInet6)(addr)
		return int(syscall.Ntohs(a.Port)), nil
	}
	return 0, newDNSError(syscall.EINVAL, network+"/"+service, "")
}

func (r *Resolver) lookupCNAME(ctx context.Context, name string) (string, error) {
	if order, conf := systemConf().hostLookupOrder(r, name); order != hostLookupCgo {
		return r.goLookupCNAME(ctx, name, order, conf)
	}

	// TODO(bradfitz): finish ctx plumbing
	if err := acquireThread(ctx); err != nil {
		return "", &DNSError{
			Name:      name,
			Err:       mapErr(err).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
	defer releaseThread()
	var rec *syscall.DNSRecord
	e := syscall.DnsQuery(name, syscall.DNS_TYPE_CNAME, 0, nil, &rec, nil)
	// windows returns DNS_INFO_NO_RECORDS if there are no CNAME-s
	if errno, ok := e.(syscall.Errno); ok && errno == syscall.DNS_INFO_NO_RECORDS {
		// if there are no aliases, the canonical name is the input name
		return absDomainName(name), nil
	}
	if e != nil {
		return "", newDNSError(winError("dnsquery", e), name, "")
	}
	defer syscall.DnsRecordListFree(rec, 1)

	resolved := resolveCNAME(syscall.StringToUTF16Ptr(name), rec)
	cname := windows.UTF16PtrToString(resolved)
	return absDomainName(cname), nil
}

func (r *Resolver) lookupSRV(ctx context.Context, service, proto, name string) (string, []*SRV, error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupSRV(ctx, service, proto, name)
	}
	// TODO(bradfitz): finish ctx plumbing
	if err := acquireThread(ctx); err != nil {
		return "", nil, &DNSError{
			Name:      name,
			Err:       mapErr(err).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
	defer releaseThread()
	var target string
	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}
	var rec *syscall.DNSRecord
	e := syscall.DnsQuery(target, syscall.DNS_TYPE_SRV, 0, nil, &rec, nil)
	if e != nil {
		return "", nil, newDNSError(winError("dnsquery", e), name, "")
	}
	defer syscall.DnsRecordListFree(rec, 1)

	srvs := make([]*SRV, 0, 10)
	for _, p := range validRecs(rec, syscall.DNS_TYPE_SRV, target) {
		v := (*syscall.DNSSRVData)(unsafe.Pointer(&p.Data[0]))
		srvs = append(srvs, &SRV{absDomainName(syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(v.Target))[:])), v.Port, v.Priority, v.Weight})
	}
	byPriorityWeight(srvs).sort()
	return absDomainName(target), srvs, nil
}

func (r *Resolver) lookupMX(ctx context.Context, name string) ([]*MX, error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupMX(ctx, name)
	}
	// TODO(bradfitz): finish ctx plumbing.
	if err := acquireThread(ctx); err != nil {
		return nil, &DNSError{
			Name:      name,
			Err:       mapErr(err).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
	defer releaseThread()
	var rec *syscall.DNSRecord
	e := syscall.DnsQuery(name, syscall.DNS_TYPE_MX, 0, nil, &rec, nil)
	if e != nil {
		return nil, newDNSError(winError("dnsquery", e), name, "")
	}
	defer syscall.DnsRecordListFree(rec, 1)

	mxs := make([]*MX, 0, 10)
	for _, p := range validRecs(rec, syscall.DNS_TYPE_MX, name) {
		v := (*syscall.DNSMXData)(unsafe.Pointer(&p.Data[0]))
		mxs = append(mxs, &MX{absDomainName(windows.UTF16PtrToString(v.NameExchange)), v.Preference})
	}
	byPref(mxs).sort()
	return mxs, nil
}

func (r *Resolver) lookupNS(ctx context.Context, name string) ([]*NS, error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupNS(ctx, name)
	}
	// TODO(bradfitz): finish ctx plumbing.
	if err := acquireThread(ctx); err != nil {
		return nil, &DNSError{
			Name:      name,
			Err:       mapErr(err).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
	defer releaseThread()
	var rec *syscall.DNSRecord
	e := syscall.DnsQuery(name, syscall.DNS_TYPE_NS, 0, nil, &rec, nil)
	if e != nil {
		return nil, newDNSError(winError("dnsquery", e), name, "")
	}
	defer syscall.DnsRecordListFree(rec, 1)

	nss := make([]*NS, 0, 10)
	for _, p := range validRecs(rec, syscall.DNS_TYPE_NS, name) {
		v := (*syscall.DNSPTRData)(unsafe.Pointer(&p.Data[0]))
		nss = append(nss, &NS{absDomainName(syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(v.Host))[:]))})
	}
	return nss, nil
}

func (r *Resolver) lookupTXT(ctx context.Context, name string) ([]string, error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupTXT(ctx, name)
	}
	// TODO(bradfitz): finish ctx plumbing.
	if err := acquireThread(ctx); err != nil {
		return nil, &DNSError{
			Name:      name,
			Err:       mapErr(err).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
	defer releaseThread()
	var rec *syscall.DNSRecord
	e := syscall.DnsQuery(name, syscall.DNS_TYPE_TEXT, 0, nil, &rec, nil)
	if e != nil {
		return nil, newDNSError(winError("dnsquery", e), name, "")
	}
	defer syscall.DnsRecordListFree(rec, 1)

	txts := make([]string, 0, 10)
	for _, p := range validRecs(rec, syscall.DNS_TYPE_TEXT, name) {
		d := (*syscall.DNSTXTData)(unsafe.Pointer(&p.Data[0]))
		s := ""
		for _, v := range (*[1 << 10]*uint16)(unsafe.Pointer(&(d.StringArray[0])))[:d.StringCount:d.StringCount] {
			s += windows.UTF16PtrToString(v)
		}
		txts = append(txts, s)
	}
	return txts, nil
}

func (r *Resolver) lookupAddr(ctx context.Context, addr string) ([]string, error) {
	if order, conf := systemConf().addrLookupOrder(r, addr); order != hostLookupCgo {
		return r.goLookupPTR(ctx, addr, order, conf)
	}

	// TODO(bradfitz): finish ctx plumbing.
	if err := acquireThread(ctx); err != nil {
		return nil, &DNSError{
			Name:      addr,
			Err:       mapErr(err).Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
	defer releaseThread()
	arpa, err := reverseaddr(addr)
	if err != nil {
		return nil, err
	}
	var rec *syscall.DNSRecord
	e := syscall.DnsQuery(arpa, syscall.DNS_TYPE_PTR, 0, nil, &rec, nil)
	if e != nil {
		return nil, newDNSError(winError("dnsquery", e), addr, "")
	}
	defer syscall.DnsRecordListFree(rec, 1)

	ptrs := make([]string, 0, 10)
	for _, p := range validRecs(rec, syscall.DNS_TYPE_PTR, arpa) {
		v := (*syscall.DNSPTRData)(unsafe.Pointer(&p.Data[0]))
		ptrs = append(ptrs, absDomainName(windows.UTF16PtrToString(v.Host)))
	}
	return ptrs, nil
}

const dnsSectionMask = 0x0003

// returns only results applicable to name and resolves CNAME entries.
func validRecs(r *syscall.DNSRecord, dnstype uint16, name string) []*syscall.DNSRecord {
	cname := syscall.StringToUTF16Ptr(name)
	if dnstype != syscall.DNS_TYPE_CNAME {
		cname = resolveCNAME(cname, r)
	}
	rec := make([]*syscall.DNSRecord, 0, 10)
	for p := r; p != nil; p = p.Next {
		// in case of a local machine, DNS records are returned with DNSREC_QUESTION flag instead of DNS_ANSWER
		if p.Dw&dnsSectionMask != syscall.DnsSectionAnswer && p.Dw&dnsSectionMask != syscall.DnsSectionQuestion {
			continue
		}
		if p.Type != dnstype {
			continue
		}
		if !syscall.DnsNameCompare(cname, p.Name) {
			continue
		}
		rec = append(rec, p)
	}
	return rec
}

// returns the last CNAME in chain.
func resolveCNAME(name *uint16, r *syscall.DNSRecord) *uint16 {
	// limit cname resolving to 10 in case of an infinite CNAME loop
Cname:
	for cnameloop := 0; cnameloop < 10; cnameloop++ {
		for p := r; p != nil; p = p.Next {
			if p.Dw&dnsSectionMask != syscall.DnsSectionAnswer {
				continue
			}
			if p.Type != syscall.DNS_TYPE_CNAME {
				continue
			}
			if !syscall.DnsNameCompare(name, p.Name) {
				continue
			}
			name = (*syscall.DNSPTRData)(unsafe.Pointer(&r.Data[0])).Host
			continue Cname
		}
		break
	}
	return name
}

// concurrentThreadsLimit returns the number of threads we permit to
// run concurrently doing DNS lookups.
func concurrentThreadsLimit() int {
	return 500
}
```