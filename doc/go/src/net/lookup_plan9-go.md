Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: Context and Purpose**

The first thing to notice is the package declaration: `package net`. This immediately tells us it's part of Go's standard library, specifically dealing with network functionalities. The filename `lookup_plan9.go` gives a strong hint that this code is tailored for the Plan 9 operating system. The copyright notice further reinforces this.

**2. Core Function: `query`**

The most important function appears to be `query`. It's the central point for interacting with some kind of file-based system. Let's analyze its steps:

* **Input:** `ctx context.Context`, `filename string`, `query string`, `bufSize int`. These suggest a request-response mechanism involving a file, a query string, and a buffer size for reading the response. The `context.Context` indicates support for timeouts and cancellation.
* **`queryAddrs` Inner Function:** This function is responsible for the actual file interaction:
    * Opens a file in read-write mode (`os.OpenFile(filename, os.O_RDWR, 0)`).
    * Seeks to the beginning of the file (`file.Seek(0, io.SeekStart)`).
    * Writes the `query` string to the file (`file.WriteString(query)`). This suggests sending a request by writing to the file.
    * Seeks back to the beginning (`file.Seek(0, io.SeekStart)`). This implies the response is expected to be read from the *same* file.
    * Reads data from the file in chunks of `bufSize` (`file.Read(buf)`).
    * Appends the read data to the `addrs` slice.
* **Concurrency:** The `query` function uses a goroutine and a channel (`ch`) to perform the file I/O asynchronously. This prevents the main thread from blocking while waiting for the file operation to complete.
* **Context Handling:** The `select` statement listens for either a response from the goroutine or for the context to be cancelled (`ctx.Done()`). This implements the timeout/cancellation behavior.
* **Error Handling:**  The code handles file opening errors, write errors, seek errors, and context cancellation errors.

**3. Identifying Higher-Level Functions and Their Purpose**

Now, let's examine the functions that call `query`:

* **`queryCS`:** Takes `net`, `host`, and `service` as input. It formats a query string that looks like `"tcp!host!service"` and calls `query` with `netdir+"/cs"` as the filename. This suggests `netdir+"/cs"` is a file used for looking up network-related information, likely connection states or service details.
* **`queryCS1`:**  Similar to `queryCS`, but seems more specific, potentially for getting connection details (clone and destination). It uses `itoa.Itoa` to convert the port to a string, implying it's dealing with network ports.
* **`queryDNS`:** Takes an `addr` and a `typ` (e.g., "A", "MX", "CNAME") and calls `query` with `netdir+"/dns"`. This strongly indicates that `netdir+"/dns"` is the file used for performing DNS lookups.

**4. Inferring the Role of `netdir`**

The recurring use of `netdir+"/cs"` and `netdir+"/dns"` suggests that `netdir` is a variable (or potentially a constant, although not explicitly declared in the snippet) that represents a directory path. This directory likely contains files that act as interfaces for network lookups and management in the Plan 9 environment.

**5. Understanding `handlePlan9DNSError`**

This function takes an error and a hostname as input. It checks if the error message contains specific strings related to DNS failures ("name does not exist", "resource does not exist", "dns failure"). If so, it replaces the error with `errNoSuchHost`, which is a standard Go error for a non-existent host. This is a platform-specific error handling mechanism.

**6. Analyzing the `lookup...` Functions**

The functions starting with `lookup` (e.g., `lookupProtocol`, `lookupHost`, `lookupIP`, `lookupPort`, `lookupCNAME`, etc.) are clearly implementing different types of network lookups. They utilize the `queryCS` and `queryDNS` functions as their underlying mechanisms.

* **`lookupProtocol`:** Looks up a protocol name (e.g., "tcp", "udp") and returns its corresponding number.
* **`lookupHost`:** Looks up the IP addresses associated with a hostname.
* **`lookupIP`:** Similar to `lookupHost` but returns `IPAddr` structs, which include the zone information (important for IPv6).
* **`lookupPort`:** Looks up the port number for a given service name and network protocol.
* **`lookupCNAME`:** Looks up the canonical name (CNAME) for a given hostname.
* **`lookupSRV`:** Looks up Service Resource Records (SRV records).
* **`lookupMX`:** Looks up Mail Exchanger (MX) records.
* **`lookupNS`:** Looks up Name Server (NS) records.
* **`lookupTXT`:** Looks up Text (TXT) records.
* **`lookupAddr`:** Performs a reverse DNS lookup (from IP address to hostname).

**7. Identifying Plan 9 Specifics**

The reliance on file I/O for network lookups is a strong indicator of a Plan 9 implementation. Standard Go implementations usually rely on system calls or libraries that interact directly with the operating system's network stack. The `netdir` variable and the specific file names (`cs`, `dns`) are likely Plan 9 conventions.

**8. Considering Potential Errors**

The code directly interacts with files, which introduces potential error sources like file not found, permission issues, or incorrect data formats within the files. The asynchronous nature of the `query` function and the use of contexts mean that timeouts are also a possibility.

**9. Structuring the Answer**

Finally, organize the findings into a clear and structured answer, addressing the user's specific questions about functionality, example usage, code reasoning, command-line arguments (or lack thereof), and potential pitfalls. Use code examples to illustrate the functionality and explain the assumptions made during the reasoning process.

By following these steps, we can systematically analyze the code snippet and arrive at a comprehensive understanding of its purpose and implementation details within the context of the Plan 9 operating system.
这段代码是 Go 语言 `net` 包中专门为 Plan 9 操作系统提供的网络查找功能实现。它利用 Plan 9 特有的文件系统接口来进行主机名、IP 地址、端口号、DNS 记录等信息的查询。

**主要功能列举:**

1. **`query(ctx context.Context, filename, query string, bufSize int) (addrs []string, err error)`:**  这是一个核心的底层查询函数。它负责向指定的 `filename` 文件写入 `query` 字符串，然后从同一个文件中读取返回结果。这个函数实现了基本的请求-响应模式，利用 Plan 9 的文件系统作为通信通道。

2. **`queryCS(ctx context.Context, net, host, service string) (res []string, err error)`:**  用于查询连接状态（Connection Status）。它构造一个形如 `"tcp!host!service"` 的查询字符串，然后调用 `query` 函数访问 Plan 9 的网络目录下的 `cs` 文件（通常是 `/net/cs`）。

3. **`queryCS1(ctx context.Context, net string, ip IP, port int) (clone, dest string, err error)`:**  类似于 `queryCS`，但更具体地用于查询特定 IP 地址和端口的连接信息。它返回克隆地址和目标地址。

4. **`queryDNS(ctx context.Context, addr string, typ string) (res []string, err error)`:**  用于执行 DNS 查询。它构造一个形如 `"addr type"` 的查询字符串，然后调用 `query` 函数访问 Plan 9 的网络目录下的 `dns` 文件（通常是 `/net/dns`）。

5. **`handlePlan9DNSError(err error, name string) error`:**  处理 Plan 9 特有的 DNS 错误信息，将其转换为 Go 标准的 `DNSError` 类型。

6. **`lookupProtocol(ctx context.Context, name string) (proto int, err error)`:**  根据协议名称（例如 "tcp" 或 "udp"）查找对应的协议编号。它通过查询 `/net/cs` 文件实现。

7. **`(*Resolver) lookupHost(ctx context.Context, host string) (addrs []string, err error)`:**  根据主机名查找对应的 IP 地址。它使用 `/net/cs` 文件，能够解析本地网络中的主机名。

8. **`(r *Resolver) lookupIP(ctx context.Context, network, host string) (addrs []IPAddr, err error)`:**  与 `lookupHost` 类似，但返回 `IPAddr` 类型的切片，其中包含 IP 地址和可能的 Zone 信息（用于 IPv6 作用域）。

9. **`(r *Resolver) lookupPort(ctx context.Context, network, service string) (port int, err error)`:**  根据网络协议和端口服务名查找对应的端口号。它通过查询 `/net/cs` 文件实现。

10. **`(r *Resolver) lookupPortWithNetwork(ctx context.Context, network, errNetwork, service string) (port int, err error)`:**  `lookupPort` 的辅助函数，用于处理特定网络协议的端口查找。

11. **`(r *Resolver) lookupCNAME(ctx context.Context, name string) (cname string, err error)`:**  查找指定主机名的 CNAME 记录。它通过查询 `/net/dns` 文件实现。

12. **`(r *Resolver) lookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*SRV, err error)`:**  查找指定服务的 SRV 记录。它通过查询 `/net/dns` 文件实现。

13. **`(r *Resolver) lookupMX(ctx context.Context, name string) (mx []*MX, err error)`:**  查找指定域名的 MX 记录。它通过查询 `/net/dns` 文件实现。

14. **`(r *Resolver) lookupNS(ctx context.Context, name string) (ns []*NS, err error)`:**  查找指定域名的 NS 记录。它通过查询 `/net/dns` 文件实现。

15. **`(r *Resolver) lookupTXT(ctx context.Context, name string) (txt []string, err error)`:**  查找指定域名的 TXT 记录。它通过查询 `/net/dns` 文件实现。

16. **`(r *Resolver) lookupAddr(ctx context.Context, addr string) (name []string, err error)`:**  根据 IP 地址反向查找主机名（PTR 记录）。它通过查询 `/net/dns` 文件实现。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `net` 包中用于实现**网络名称解析**功能的特定于 Plan 9 操作系统的实现。在 Go 中，`net` 包提供了跨平台的网络编程接口，但其底层实现会根据不同的操作系统进行调整。在 Plan 9 上，由于其独特的文件系统特性，Go 选择了通过读写特定文件的方式来进行网络信息的查询。

**Go 代码举例说明:**

假设我们想在 Plan 9 上查找 `www.google.com` 的 IP 地址。

```go
package main

import (
	"context"
	"fmt"
	"net"
	"os"
)

func main() {
	// 假设程序运行在 Plan 9 系统上

	if os.Getenv("PLAN9") == "" {
		fmt.Println("This example is intended to be run on Plan 9.")
		return
	}

	resolver := &net.Resolver{} // 使用默认的 Resolver

	ips, err := resolver.LookupHost(context.Background(), "www.google.com")
	if err != nil {
		fmt.Println("Error looking up host:", err)
		return
	}

	fmt.Println("IP addresses for www.google.com:", ips)
}
```

**假设的输入与输出:**

* **假设输入:**  程序运行在 Plan 9 系统上，并且网络配置正确。
* **假设 `/net/cs` 内容 (可能包含本地主机名信息):**
  ```
  # proto=tcp addr=!192.168.1.100!port
  tcp	myhost	!192.168.1.100!
  ```
* **假设 `/net/dns` 内容 (简化示例，实际内容更复杂):**
  ```
  www.google.com.	IN	A	142.250.180.142
  ```

* **预期输出:**
  ```
  IP addresses for www.google.com: [142.250.180.142]
  ```

**代码推理:**

1. `resolver.LookupHost(context.Background(), "www.google.com")`  会被调用。
2. 由于是 Plan 9 系统，实际会执行 `lookup_plan9.go` 中的 `(*Resolver).lookupHost` 函数。
3. `lookupHost` 函数会调用 `queryCS(ctx, "net", host, "1")`，其中 `host` 为 "www.google.com"。
4. `queryCS` 函数会将查询字符串 `"net!www.google.com!1"` 写入 `/net/cs` 文件。
5. Plan 9 的网络服务会处理这个请求，并将结果写入 `/net/cs` 文件（或者如果找不到，可能会通过 DNS 查询，并将结果写入）。
6. `query` 函数读取 `/net/cs` 的内容。如果 `/net/cs` 中没有 `www.google.com` 的信息，它可能会最终回退到 DNS 查询。
7. 如果进行了 DNS 查询， `lookupHost` 可能会调用 `queryDNS(ctx, "www.google.com", "1")` (这里的 "1" 是一种简化表示，实际可能更复杂)。
8. `queryDNS` 函数会将查询字符串 `"www.google.com 1"` 写入 `/net/dns` 文件。
9. Plan 9 的 DNS 服务会处理这个请求，并将结果写入 `/net/dns` 文件，例如 `"www.google.com. IN  A   142.250.180.142" `。
10. `query` 函数读取 `/net/dns` 的内容，并解析出 IP 地址 `142.250.180.142`。
11. `lookupHost` 函数将解析出的 IP 地址返回。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是在 `net` 包内部被调用的，作为网络解析功能的一部分。用户通常不会直接调用这些函数，而是通过更高层次的 `net` 包 API，例如 `net.Dial`、`net.LookupHost` 等。

**使用者易犯错的点:**

1. **运行环境错误:** 这段代码是特定于 Plan 9 的。如果在其他操作系统上运行使用这些函数的 Go 程序，会使用 `net` 包中针对该操作系统的其他实现。这可能导致行为上的差异。

   **错误示例 (在非 Plan 9 系统上运行):**

   如果在一个 Linux 系统上运行上面的示例代码，它会使用 Linux 下的网络解析机制，而不是 Plan 9 的文件系统接口。 `/net/cs` 和 `/net/dns` 在 Linux 上不存在，或者其含义不同，程序可能会得到不同的结果或者报错。

2. **Plan 9 网络配置错误:**  这段代码依赖于 Plan 9 系统正确的网络配置和 `/net/cs` 和 `/net/dns` 文件的正常工作。如果这些文件配置不当或者网络服务出现问题，会导致解析失败。

   **错误示例:**  如果 Plan 9 系统的 DNS 服务未运行，或者 `/net/dns` 文件被错误配置，那么对外部域名的 DNS 查询将会失败，`lookupHost` 等函数会返回错误。

总而言之，这段代码是 Go 语言在 Plan 9 操作系统上实现网络名称解析的关键部分，它利用了 Plan 9 特有的文件系统接口来进行网络信息的查询。理解这段代码需要对 Plan 9 的网络模型有一定的了解。

Prompt: 
```
这是路径为go/src/net/lookup_plan9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"errors"
	"internal/bytealg"
	"internal/itoa"
	"internal/stringslite"
	"io"
	"os"
)

// cgoAvailable set to true to indicate that the cgo resolver
// is available on Plan 9. Note that on Plan 9 the cgo resolver
// does not actually use cgo.
const cgoAvailable = true

func query(ctx context.Context, filename, query string, bufSize int) (addrs []string, err error) {
	queryAddrs := func() (addrs []string, err error) {
		file, err := os.OpenFile(filename, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		_, err = file.WriteString(query)
		if err != nil {
			return nil, err
		}
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, bufSize)
		for {
			n, _ := file.Read(buf)
			if n <= 0 {
				break
			}
			addrs = append(addrs, string(buf[:n]))
		}
		return addrs, nil
	}

	type ret struct {
		addrs []string
		err   error
	}

	ch := make(chan ret, 1)
	go func() {
		addrs, err := queryAddrs()
		ch <- ret{addrs: addrs, err: err}
	}()

	select {
	case r := <-ch:
		return r.addrs, r.err
	case <-ctx.Done():
		return nil, &DNSError{
			Name:      query,
			Err:       ctx.Err().Error(),
			IsTimeout: ctx.Err() == context.DeadlineExceeded,
		}
	}
}

func queryCS(ctx context.Context, net, host, service string) (res []string, err error) {
	switch net {
	case "tcp4", "tcp6":
		net = "tcp"
	case "udp4", "udp6":
		net = "udp"
	}
	if host == "" {
		host = "*"
	}
	return query(ctx, netdir+"/cs", net+"!"+host+"!"+service, 128)
}

func queryCS1(ctx context.Context, net string, ip IP, port int) (clone, dest string, err error) {
	ips := "*"
	if len(ip) != 0 && !ip.IsUnspecified() {
		ips = ip.String()
	}
	lines, err := queryCS(ctx, net, ips, itoa.Itoa(port))
	if err != nil {
		return
	}
	f := getFields(lines[0])
	if len(f) < 2 {
		return "", "", errors.New("bad response from ndb/cs")
	}
	clone, dest = f[0], f[1]
	return
}

func queryDNS(ctx context.Context, addr string, typ string) (res []string, err error) {
	return query(ctx, netdir+"/dns", addr+" "+typ, 1024)
}

func handlePlan9DNSError(err error, name string) error {
	if stringslite.HasSuffix(err.Error(), "dns: name does not exist") ||
		stringslite.HasSuffix(err.Error(), "dns: resource does not exist; negrcode 0") ||
		stringslite.HasSuffix(err.Error(), "dns: resource does not exist; negrcode") ||
		stringslite.HasSuffix(err.Error(), "dns failure") {
		err = errNoSuchHost
	}
	return newDNSError(err, name, "")
}

// toLower returns a lower-case version of in. Restricting us to
// ASCII is sufficient to handle the IP protocol names and allow
// us to not depend on the strings and unicode packages.
func toLower(in string) string {
	for _, c := range in {
		if 'A' <= c && c <= 'Z' {
			// Has upper case; need to fix.
			out := []byte(in)
			for i := 0; i < len(in); i++ {
				c := in[i]
				if 'A' <= c && c <= 'Z' {
					c += 'a' - 'A'
				}
				out[i] = c
			}
			return string(out)
		}
	}
	return in
}

// lookupProtocol looks up IP protocol name and returns
// the corresponding protocol number.
func lookupProtocol(ctx context.Context, name string) (proto int, err error) {
	lines, err := query(ctx, netdir+"/cs", "!protocol="+toLower(name), 128)
	if err != nil {
		return 0, err
	}
	if len(lines) == 0 {
		return 0, UnknownNetworkError(name)
	}
	f := getFields(lines[0])
	if len(f) < 2 {
		return 0, UnknownNetworkError(name)
	}
	s := f[1]
	if n, _, ok := dtoi(s[bytealg.IndexByteString(s, '=')+1:]); ok {
		return n, nil
	}
	return 0, UnknownNetworkError(name)
}

func (*Resolver) lookupHost(ctx context.Context, host string) (addrs []string, err error) {
	// Use netdir/cs instead of netdir/dns because cs knows about
	// host names in local network (e.g. from /lib/ndb/local)
	lines, err := queryCS(ctx, "net", host, "1")
	if err != nil {
		return nil, handlePlan9DNSError(err, host)
	}
loop:
	for _, line := range lines {
		f := getFields(line)
		if len(f) < 2 {
			continue
		}
		addr := f[1]
		if i := bytealg.IndexByteString(addr, '!'); i >= 0 {
			addr = addr[:i] // remove port
		}
		if ParseIP(addr) == nil {
			continue
		}
		// only return unique addresses
		for _, a := range addrs {
			if a == addr {
				continue loop
			}
		}
		addrs = append(addrs, addr)
	}
	return
}

func (r *Resolver) lookupIP(ctx context.Context, network, host string) (addrs []IPAddr, err error) {
	if order, conf := systemConf().hostLookupOrder(r, host); order != hostLookupCgo {
		return r.goLookupIP(ctx, network, host, order, conf)
	}

	lits, err := r.lookupHost(ctx, host)
	if err != nil {
		return
	}
	for _, lit := range lits {
		host, zone := splitHostZone(lit)
		if ip := ParseIP(host); ip != nil {
			addr := IPAddr{IP: ip, Zone: zone}
			addrs = append(addrs, addr)
		}
	}
	return
}

func (r *Resolver) lookupPort(ctx context.Context, network, service string) (port int, err error) {
	switch network {
	case "ip": // no hints
		if p, err := r.lookupPortWithNetwork(ctx, "tcp", "ip", service); err == nil {
			return p, nil
		}
		return r.lookupPortWithNetwork(ctx, "udp", "ip", service)
	case "tcp", "tcp4", "tcp6":
		return r.lookupPortWithNetwork(ctx, "tcp", "tcp", service)
	case "udp", "udp4", "udp6":
		return r.lookupPortWithNetwork(ctx, "udp", "udp", service)
	default:
		return 0, &DNSError{Err: "unknown network", Name: network + "/" + service}
	}
}

func (*Resolver) lookupPortWithNetwork(ctx context.Context, network, errNetwork, service string) (port int, err error) {
	lines, err := queryCS(ctx, network, "127.0.0.1", toLower(service))
	if err != nil {
		if stringslite.HasSuffix(err.Error(), "can't translate service") {
			return 0, &DNSError{Err: "unknown port", Name: errNetwork + "/" + service, IsNotFound: true}
		}
		return
	}
	if len(lines) == 0 {
		return 0, &DNSError{Err: "unknown port", Name: errNetwork + "/" + service, IsNotFound: true}
	}
	f := getFields(lines[0])
	if len(f) < 2 {
		return 0, &DNSError{Err: "unknown port", Name: errNetwork + "/" + service, IsNotFound: true}
	}
	s := f[1]
	if i := bytealg.IndexByteString(s, '!'); i >= 0 {
		s = s[i+1:] // remove address
	}
	if n, _, ok := dtoi(s); ok {
		return n, nil
	}
	return 0, &DNSError{Err: "unknown port", Name: errNetwork + "/" + service, IsNotFound: true}
}

func (r *Resolver) lookupCNAME(ctx context.Context, name string) (cname string, err error) {
	if order, conf := systemConf().hostLookupOrder(r, name); order != hostLookupCgo {
		return r.goLookupCNAME(ctx, name, order, conf)
	}

	lines, err := queryDNS(ctx, name, "cname")
	if err != nil {
		if stringslite.HasSuffix(err.Error(), "dns failure") ||
			stringslite.HasSuffix(err.Error(), "resource does not exist; negrcode 0") ||
			stringslite.HasSuffix(err.Error(), "resource does not exist; negrcode") {
			return absDomainName(name), nil
		}
		return "", handlePlan9DNSError(err, cname)
	}
	if len(lines) > 0 {
		if f := getFields(lines[0]); len(f) >= 3 {
			return f[2] + ".", nil
		}
	}
	return "", errors.New("bad response from ndb/dns")
}

func (r *Resolver) lookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*SRV, err error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupSRV(ctx, service, proto, name)
	}
	var target string
	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}
	lines, err := queryDNS(ctx, target, "srv")
	if err != nil {
		return "", nil, handlePlan9DNSError(err, name)
	}
	for _, line := range lines {
		f := getFields(line)
		if len(f) < 6 {
			continue
		}
		port, _, portOk := dtoi(f[4])
		priority, _, priorityOk := dtoi(f[3])
		weight, _, weightOk := dtoi(f[2])
		if !(portOk && priorityOk && weightOk) {
			continue
		}
		addrs = append(addrs, &SRV{absDomainName(f[5]), uint16(port), uint16(priority), uint16(weight)})
		cname = absDomainName(f[0])
	}
	byPriorityWeight(addrs).sort()
	return
}

func (r *Resolver) lookupMX(ctx context.Context, name string) (mx []*MX, err error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupMX(ctx, name)
	}
	lines, err := queryDNS(ctx, name, "mx")
	if err != nil {
		return nil, handlePlan9DNSError(err, name)
	}
	for _, line := range lines {
		f := getFields(line)
		if len(f) < 4 {
			continue
		}
		if pref, _, ok := dtoi(f[2]); ok {
			mx = append(mx, &MX{absDomainName(f[3]), uint16(pref)})
		}
	}
	byPref(mx).sort()
	return
}

func (r *Resolver) lookupNS(ctx context.Context, name string) (ns []*NS, err error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupNS(ctx, name)
	}
	lines, err := queryDNS(ctx, name, "ns")
	if err != nil {
		return nil, handlePlan9DNSError(err, name)
	}
	for _, line := range lines {
		f := getFields(line)
		if len(f) < 3 {
			continue
		}
		ns = append(ns, &NS{absDomainName(f[2])})
	}
	return
}

func (r *Resolver) lookupTXT(ctx context.Context, name string) (txt []string, err error) {
	if systemConf().mustUseGoResolver(r) {
		return r.goLookupTXT(ctx, name)
	}
	lines, err := queryDNS(ctx, name, "txt")
	if err != nil {
		return nil, handlePlan9DNSError(err, name)
	}
	for _, line := range lines {
		if i := bytealg.IndexByteString(line, '\t'); i >= 0 {
			txt = append(txt, line[i+1:])
		}
	}
	return
}

func (r *Resolver) lookupAddr(ctx context.Context, addr string) (name []string, err error) {
	if order, conf := systemConf().addrLookupOrder(r, addr); order != hostLookupCgo {
		return r.goLookupPTR(ctx, addr, order, conf)
	}
	arpa, err := reverseaddr(addr)
	if err != nil {
		return
	}
	lines, err := queryDNS(ctx, arpa, "ptr")
	if err != nil {
		return nil, handlePlan9DNSError(err, addr)
	}
	for _, line := range lines {
		f := getFields(line)
		if len(f) < 3 {
			continue
		}
		name = append(name, absDomainName(f[2]))
	}
	return
}

// concurrentThreadsLimit returns the number of threads we permit to
// run concurrently doing DNS lookups.
func concurrentThreadsLimit() int {
	return 500
}

"""



```