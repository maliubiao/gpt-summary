Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Reading and Identification of Purpose:** The first step is to read through the code, even if it's a bit dense initially. The comments at the top are crucial: "DNS client: see RFC 1035." and "Has to be linked into package net for Dial."  This immediately tells us the core function: handling DNS queries. The filename `dnsclient_unix.go` suggests it's specifically for Unix-like systems.

2. **Core Functionality Extraction - High Level:**  Skimming the code, we can spot key functions and constants that reveal the main processes:
    * `newRequest`:  This clearly deals with creating a DNS request message.
    * `checkResponse`:  This is for verifying the validity of a received DNS response.
    * `dnsPacketRoundTrip` and `dnsStreamRoundTrip`: These seem to handle the actual sending and receiving of DNS messages over UDP and TCP respectively. The "RoundTrip" suggests a request-response pattern.
    * `exchange`: This function seems to orchestrate the sending of a DNS query and receiving the response, handling both UDP and TCP.
    * `tryOneName`: This function appears to try resolving a single name against configured DNS servers.
    * `lookup`: This function likely manages the overall lookup process, including handling search domains and trying different names.
    * `resolverConfig`:  This structure and its associated functions (`getSystemDNSConfig`, `tryUpdate`) suggest the code handles reading and managing DNS configuration (like `/etc/resolv.conf`).

3. **Detailed Function Analysis (Examples & Logic):**  Now, let's dive deeper into some of the more important functions:

    * **`newRequest`:**
        * **Goal:**  Construct a DNS query message.
        * **Key actions:** Generates a random ID, sets header flags (recursion desired, potentially authentic data), adds the question, and optionally includes an EDNS0 record. Notice the `netedns0` variable which is controlled by `godebug`. This is an interesting detail – a configurable option.
        * **TCP vs. UDP:** It prepares both TCP and UDP versions of the request. The TCP version prepends the length of the message.

    * **`dnsPacketRoundTrip` and `dnsStreamRoundTrip`:**
        * **Goal:** Send a request and receive a response over a connection.
        * **UDP (`dnsPacketRoundTrip`):**  Sends the raw UDP packet and reads a response. It handles potential errors and ignores invalid responses, a security measure.
        * **TCP (`dnsStreamRoundTrip`):** Sends the TCP request (with the prepended length), reads the length prefix, then reads the actual response.

    * **`exchange`:**
        * **Goal:**  A higher-level function to perform a DNS exchange.
        * **Key logic:** Tries both UDP and TCP (unless `useTCP` is forced). Uses contexts for timeouts. Calls the appropriate round-trip function based on the connection type. Handles potential TCP truncation retries.

    * **`tryOneName`:**
        * **Goal:** Resolve a single fully-qualified domain name against multiple DNS servers.
        * **Key logic:** Iterates through configured servers and attempts to exchange the DNS query. Handles errors and the `errNoSuchHost` case.

    * **`lookup`:**
        * **Goal:**  The main function for looking up a hostname.
        * **Key logic:** Handles non-domain names. Gets the DNS configuration. Iterates through possible names derived from search domains. Calls `tryOneName`.

4. **Identifying Go Features:** As we examine the functions, we can identify specific Go features:
    * **Contexts:** Used for managing timeouts and cancellations.
    * **`sync.Once`:** Used for initializing the resolver configuration only once.
    * **`sync.Mutex` (implicitly through `chan struct{}`):**  Used to protect access to the resolver configuration.
    * **`atomic.Pointer`:**  Used for thread-safe access to the `dnsConfig`.
    * **`godebug`:**  Used for conditional behavior (the `netedns0` flag).
    * **Error Handling:**  The code defines custom error types and uses `errors.New` and `fmt.Errorf`.
    * **`dnsmessage` package:**  Clearly the core library for manipulating DNS messages.
    * **Interfaces (`Conn`, `PacketConn`):** Used for abstraction over network connections.

5. **Code Examples (Illustrative):**  Based on the function analysis, we can construct example Go code snippets to demonstrate the usage of these functions (even if they aren't directly exposed). The examples focus on how the request and response mechanisms work.

6. **Command-line Parameters:** The code itself doesn't directly parse command-line arguments. However, the presence of `godebug.New("netedns0")` strongly suggests that the `netedns0` flag *could* be controlled via a command-line environment variable (e.g., `GODEBUG=netedns0=0`). This requires some inference based on common Go practices.

7. **Common Mistakes:**  Thinking about how someone might misuse this functionality requires understanding the asynchronous and error-handling aspects. Forgetting to handle errors, not setting timeouts correctly (though the code handles this internally to some extent), or making assumptions about DNS server behavior are potential pitfalls. The truncation issue with UDP is a good example of a subtle error case.

8. **Structuring the Answer:** Finally, organize the findings logically with clear headings and examples. Use bullet points for lists of functionalities. Provide concrete code examples with input and output (even if the output is a bit simplified for illustration). Explain command-line parameter handling based on the `godebug` observation. Clearly list potential mistakes users might make. Use Chinese as requested.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Is `newRequest` just for UDP?"  **Correction:**  Realize it generates both UDP and TCP versions, with TCP prepending the length.
* **Initial thought:** "How is configuration handled?" **Correction:** Notice the `resolverConfig` and its methods, indicating file-based configuration (specifically `/etc/resolv.conf`).
* **Initial thought:** "Are there any external dependencies beyond `golang.org/x/net/dns/dnsmessage`?" **Correction:**  See the imports of standard library packages like `context`, `errors`, `io`, `os`, `runtime`, `sync`, and `time`.
* **Initial thought:** "The examples might be too detailed." **Correction:** Simplify the output in the code examples to focus on the core concepts. Emphasize the *purpose* of the examples rather than a perfect replication of internal behavior.

By following these steps, combining code reading with logical reasoning and knowledge of Go's standard library and common practices, a comprehensive analysis of the provided code snippet can be achieved.
这段代码是 Go 语言 `net` 包中 DNS 客户端实现的一部分，专门用于 Unix 系统。它负责构建 DNS 查询请求，发送请求到 DNS 服务器，并解析接收到的响应。

以下是它的主要功能：

1. **创建 DNS 查询请求 (`newRequest`):**
   - 生成一个唯一的事务 ID (16 位随机数)。
   - 根据给定的查询问题 (`dnsmessage.Question`) 和是否需要权威数据 (`ad`) 标志，构建 DNS 查询消息的 UDP 和 TCP 格式。
   - 可选地添加 EDNS0 记录以支持更大的 UDP 包大小（由 `netedns0` 调试变量控制）。
   - TCP 格式的请求会在前面加上两字节的长度信息。

2. **检查 DNS 响应 (`checkResponse`):**
   - 验证响应头部的 "Response" 标志是否设置。
   - 验证响应的事务 ID 是否与请求的 ID 匹配。
   - 验证响应的问题部分是否与请求的问题部分一致（类型、类和名称）。

3. **执行 DNS 数据包级别的往返 (`dnsPacketRoundTrip`):**
   - 用于通过无连接的 UDP 协议发送 DNS 查询并接收响应。
   - 将构建好的 UDP 查询数据包写入连接 (`Conn`)。
   - 从连接读取数据，直到收到响应或超时。
   - 忽略无效的 DNS 响应，以防止恶意伪造。
   - 使用 `dnsmessage.Parser` 解析接收到的响应，并检查响应头和问题部分。

4. **执行 DNS 流级别的往返 (`dnsStreamRoundTrip`):**
   - 用于通过面向连接的 TCP 协议发送 DNS 查询并接收响应。
   - 将构建好的 TCP 查询数据包写入连接 (`Conn`)。
   - 先读取前两个字节，获取响应的长度。
   - 根据读取的长度，读取完整的 DNS 响应。
   - 使用 `dnsmessage.Parser` 解析接收到的响应，并检查响应头和问题部分。

5. **与 DNS 服务器交换消息 (`exchange`):**
   - 这是执行 DNS 查询的核心函数。
   - 接收上下文 (`context.Context`)、服务器地址、查询问题、超时时间、是否强制使用 TCP 以及是否需要权威数据等参数。
   - 根据 `useTCP` 参数决定尝试 UDP 或 TCP 连接。
   - 使用 `dial` 方法建立到 DNS 服务器的连接。
   - 根据连接类型（`PacketConn` 或普通 `Conn`）调用 `dnsPacketRoundTrip` 或 `dnsStreamRoundTrip` 发送请求并接收响应。
   - 处理因 UDP 响应的截断标志 (`TC`) 而需要重试 TCP 的情况。
   - 返回解析后的 DNS 响应 (`dnsmessage.Parser`) 和头部信息 (`dnsmessage.Header`)。

6. **检查响应头部 (`checkHeader`):**
   - 对 DNS 响应头部进行基本的健全性检查。
   - 如果响应码 (`RCode`) 是 `NameError`，则返回 `errNoSuchHost`（主机不存在）。
   - 检查答案部分是否存在错误。
   - 如果响应码是成功 (`Success`) 且不是权威应答 (`Authoritative`) 且不支持递归 (`RecursionAvailable`) 且没有额外记录，则可能是一个错误的引用 (`lame referral`)。
   - 处理其他非成功和非 `NameError` 的响应码，将其归类为服务器行为异常。

7. **跳过答案记录直到找到特定类型 (`skipToAnswer`):**
   - 在解析 DNS 响应时，跳过答案部分直到找到指定类型的答案记录。
   - 如果答案部分结束也没有找到指定类型的记录，则返回 `errNoSuchHost`。

8. **提取扩展的响应码 (`extractExtendedRCode`):**
   - 从 OPT 资源记录 (EDNS(0)) 中提取扩展的响应码。
   - 如果没有找到 OPT 记录，则返回头部中的原始响应码。

9. **尝试解析单个名称 (`tryOneName`):**
   - 尝试使用配置的 DNS 服务器解析给定的完全限定域名 (`name`) 和查询类型 (`qtype`).
   - 根据配置的尝试次数和服务器列表，轮询 DNS 服务器。
   - 调用 `exchange` 函数与 DNS 服务器进行通信。
   - 处理各种 DNS 错误，并返回解析后的响应、使用的服务器地址和错误信息。

10. **管理 DNS 解析器配置 (`resolverConfig`):**
    - 结构体 `resolverConfig` 用于表示 DNS 客户端的配置信息，例如 DNS 服务器地址。
    - `getSystemDNSConfig` 函数用于获取系统的 DNS 配置，通常是从 `/etc/resolv.conf` 文件中读取。
    - `tryUpdate` 函数用于定期检查并更新 DNS 配置文件。

11. **执行 DNS 查询 (`lookup`):**
    - 这是进行 DNS 查询的高层函数。
    - 接收上下文、要查询的域名、查询类型和可选的 DNS 配置。
    - 如果域名不是有效的域名，则返回 `errNoSuchHost` 错误。
    - 根据配置的搜索域列表，尝试不同的域名组合进行查询。
    - 调用 `tryOneName` 函数尝试解析每个域名。

12. **判断是否应该避免 DNS 查询 (`avoidDNS`):**
    - 检查给定的主机名是否属于不应使用 DNS 解析的特殊域，目前只包含 `.onion` 域。

13. **生成要查询的域名列表 (`nameList`):**
    - 根据给定的域名和 DNS 配置（搜索域、ndots 等），生成一个要按顺序尝试查询的域名列表。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言 `net` 包中 **DNS 客户端** 功能的核心实现。它使得 Go 程序能够执行 DNS 查询，将域名解析为 IP 地址或其他 DNS 记录。这是网络编程的基础功能，许多其他网络相关的操作（如 HTTP 请求、TCP 连接等）都依赖于 DNS 解析。

**Go 代码示例：**

以下是一个简单的示例，演示了如何使用 `net` 包进行 DNS 查询，虽然你不能直接调用 `dnsclient_unix.go` 中的私有函数，但这个例子展示了它所支持的功能：

```go
package main

import (
	"context"
	"fmt"
	"net"
)

func main() {
	// 使用 net.Resolver 进行 DNS 查询
	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(context.Background(), "www.google.com")
	if err != nil {
		fmt.Println("DNS 查询失败:", err)
		return
	}
	fmt.Println("www.google.com 的 IP 地址:", ips)

	// 也可以查询其他类型的 DNS 记录，例如 CNAME
	cname, err := resolver.LookupCNAME(context.Background(), "mail.google.com")
	if err != nil {
		fmt.Println("CNAME 查询失败:", err)
		return
	}
	fmt.Println("mail.google.com 的 CNAME 记录:", cname)
}
```

**假设的输入与输出（针对内部函数 `newRequest` 的推理）：**

假设我们要查询 `www.example.com` 的 A 记录。

**输入：**

```go
q := dnsmessage.Question{
	Name:  dnsmessage.MustNewName("www.example.com."),
	Type:  dnsmessage.TypeA,
	Class: dnsmessage.ClassINET,
}
ad := false // 不需要权威数据
```

**输出（推测）：**

`newRequest` 函数会返回 `id`（一个随机的 uint16）、`udpReq`（UDP 格式的请求字节切片）和 `tcpReq`（TCP 格式的请求字节切片）。

`udpReq` 的内容可能类似于（简化表示）：

```
[随机ID高字节, 随机ID低字节, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01]
```

`tcpReq` 的内容会在 `udpReq` 的前面加上长度信息：

```
[长度高字节, 长度低字节, 随机ID高字节, 随机ID低字节, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01]
```

**涉及命令行参数的具体处理：**

这段代码中直接涉及的命令行参数处理较少，但它使用了 `internal/godebug` 包来控制 `netedns0` 变量的行为。这意味着可以通过设置 `GODEBUG` 环境变量来影响是否发送 EDNS0 附加头部。

例如，在运行 Go 程序时，可以设置环境变量：

```bash
export GODEBUG=netedns0=0
```

这将禁用发送 EDNS0 记录。如果不设置或设置为其他非 `0` 的值，则会发送 EDNS0 记录。

**使用者易犯错的点：**

1. **不正确处理 DNS 查询错误：** DNS 查询可能会失败，例如域名不存在、DNS 服务器无响应等。使用者需要检查 `LookupHost` 等函数的返回值中的 `error`，并进行适当的处理。

   ```go
   ips, err := net.LookupHost("nonexistent.example.com")
   if err != nil {
       fmt.Println("DNS 查询失败:", err) // 应该处理这个错误
   }
   ```

2. **假设 DNS 查询总是返回单个 IP 地址：** 一个域名可能对应多个 IP 地址。`LookupHost` 返回一个 IP 地址切片，使用者应该遍历处理所有返回的 IP 地址。

   ```go
   ips, _ := net.LookupHost("www.google.com")
   for _, ip := range ips {
       fmt.Println("IP 地址:", ip)
   }
   ```

3. **在高并发场景下不复用 `net.Resolver`：** 每次都创建一个新的 `net.Resolver` 对象可能会导致性能问题。建议复用 `net.Resolver` 对象，因为它内部会管理连接池等资源。

   ```go
   var resolver = &net.Resolver{} // 全局或包级别复用
   func lookup(hostname string) {
       ips, err := resolver.LookupHost(context.Background(), hostname)
       // ...
   }
   ```

4. **忽略 `context.Context` 的使用：** DNS 查询可能会耗时，应该使用 `context.Context` 来控制超时和取消操作，防止程序无限期等待。

   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()
   ips, err := net.DefaultResolver.LookupHost(ctx, "www.example.com")
   if err != nil {
       // 检查是否是超时错误
       if errors.Is(err, context.DeadlineExceeded) {
           fmt.Println("DNS 查询超时")
       }
   }
   ```

这段代码是 Go 语言网络编程的重要组成部分，理解它的功能有助于更好地使用 Go 进行网络相关的开发。

Prompt: 
```
这是路径为go/src/net/dnsclient_unix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS client: see RFC 1035.
// Has to be linked into package net for Dial.

// TODO(rsc):
//	Could potentially handle many outstanding lookups faster.
//	Random UDP source port (net.Dial should do that for us).
//	Random request IDs.

package net

import (
	"context"
	"errors"
	"internal/bytealg"
	"internal/godebug"
	"internal/itoa"
	"internal/stringslite"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// to be used as a useTCP parameter to exchange
	useTCPOnly  = true
	useUDPOrTCP = false

	// Maximum DNS packet size.
	// Value taken from https://dnsflagday.net/2020/.
	maxDNSPacketSize = 1232
)

var (
	errLameReferral              = errors.New("lame referral")
	errCannotUnmarshalDNSMessage = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage   = errors.New("cannot marshal DNS message")
	errServerMisbehaving         = errors.New("server misbehaving")
	errInvalidDNSResponse        = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer     = errors.New("no answer from DNS server")

	// errServerTemporarilyMisbehaving is like errServerMisbehaving, except
	// that when it gets translated to a DNSError, the IsTemporary field
	// gets set to true.
	errServerTemporarilyMisbehaving = &temporaryError{"server misbehaving"}
)

// netedns0 controls whether we send an EDNS0 additional header.
var netedns0 = godebug.New("netedns0")

func newRequest(q dnsmessage.Question, ad bool) (id uint16, udpReq, tcpReq []byte, err error) {
	id = uint16(randInt())
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true, AuthenticData: ad})
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}

	if netedns0.Value() == "0" {
		netedns0.IncNonDefault()
	} else {
		// Accept packets up to maxDNSPacketSize.  RFC 6891.
		if err := b.StartAdditionals(); err != nil {
			return 0, nil, nil, err
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(maxDNSPacketSize, dnsmessage.RCodeSuccess, false); err != nil {
			return 0, nil, nil, err
		}
		if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
			return 0, nil, nil, err
		}
	}

	tcpReq, err = b.Finish()
	if err != nil {
		return 0, nil, nil, err
	}
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, nil
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

func dnsPacketRoundTrip(c Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}

	b = make([]byte, maxDNSPacketSize)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		// Ignore invalid responses as they may be malicious
		// forgery attempts. Instead continue waiting until
		// timeout. See golang.org/issue/13281.
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func dnsStreamRoundTrip(c Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}

	b = make([]byte, 1280) // 1280 is a reasonable initial size for IP over Ethernet, see RFC 4035
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

// exchange sends a query on the connection and hopes for a response.
func (r *Resolver) exchange(ctx context.Context, server string, q dnsmessage.Question, timeout time.Duration, useTCP, ad bool) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := newRequest(q, ad)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotMarshalDNSMessage
	}
	var networks []string
	if useTCP {
		networks = []string{"tcp"}
	} else {
		networks = []string{"udp", "tcp"}
	}
	for _, network := range networks {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

		c, err := r.dial(ctx, network, server)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			c.SetDeadline(d)
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		if _, ok := c.(PacketConn); ok {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		c.Close()
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, mapErr(err)
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
		}
		// RFC 5966 indicates that when a client receives a UDP response with
		// the TC flag set, it should take the TC flag as an indication that it
		// should retry over TCP instead.
		// The case when the TC flag is set in a TCP response is not well specified,
		// so this implements the glibc resolver behavior, returning the existing
		// dns response instead of returning a "errNoAnswerFromDNSServer" error.
		// See go.dev/issue/64896
		if h.Truncated && network == "udp" {
			continue
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, errNoAnswerFromDNSServer
}

// checkHeader performs basic sanity checks on the header.
func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	rcode, hasAdd := extractExtendedRCode(*p, h)

	if rcode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}

	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}

	// libresolv continues to the next server when it receives
	// an invalid referral response. See golang.org/issue/15434.
	if rcode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone && !hasAdd {
		return errLameReferral
	}

	if rcode != dnsmessage.RCodeSuccess && rcode != dnsmessage.RCodeNameError {
		// None of the error codes make sense
		// for the query we sent. If we didn't get
		// a name error and we didn't get success,
		// the server is behaving incorrectly or
		// having temporary trouble.
		if rcode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving
		}
		return errServerMisbehaving
	}

	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

// extractExtendedRCode extracts the extended RCode from the OPT resource (EDNS(0))
// If an OPT record is not found, the RCode from the hdr is returned.
// Another return value indicates whether an additional resource was found.
func extractExtendedRCode(p dnsmessage.Parser, hdr dnsmessage.Header) (dnsmessage.RCode, bool) {
	p.SkipAllAnswers()
	p.SkipAllAuthorities()
	hasAdd := false
	for {
		ahdr, err := p.AdditionalHeader()
		if err != nil {
			return hdr.RCode, hasAdd
		}
		hasAdd = true
		if ahdr.Type == dnsmessage.TypeOPT {
			return ahdr.ExtendedRCode(hdr.RCode), hasAdd
		}
		if err := p.SkipAdditional(); err != nil {
			return hdr.RCode, hasAdd
		}
	}
}

// Do a lookup for a single name, which must be rooted
// (otherwise answer will not find the answers).
func (r *Resolver) tryOneName(ctx context.Context, cfg *dnsConfig, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error
	serverOffset := cfg.serverOffset()
	sLen := uint32(len(cfg.servers))

	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", &DNSError{Err: errCannotMarshalDNSMessage.Error(), Name: name}
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	for i := 0; i < cfg.attempts; i++ {
		for j := uint32(0); j < sLen; j++ {
			server := cfg.servers[(serverOffset+j)%sLen]

			p, h, err := r.exchange(ctx, server, q, cfg.timeout, cfg.useTCP, cfg.trustAD)
			if err != nil {
				dnsErr := newDNSError(err, name, server)
				// Set IsTemporary for socket-level errors. Note that this flag
				// may also be used to indicate a SERVFAIL response.
				if _, ok := err.(*OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				if err == errNoSuchHost {
					// The name does not exist, so trying
					// another server won't help.
					return p, server, newDNSError(errNoSuchHost, name, server)
				}
				lastErr = newDNSError(err, name, server)
				continue
			}

			if err := skipToAnswer(&p, qtype); err != nil {
				if err == errNoSuchHost {
					// The name does not exist, so trying
					// another server won't help.
					return p, server, newDNSError(errNoSuchHost, name, server)
				}
				lastErr = newDNSError(err, name, server)
				continue
			}

			return p, server, nil
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

// A resolverConfig represents a DNS stub resolver configuration.
type resolverConfig struct {
	initOnce sync.Once // guards init of resolverConfig

	// ch is used as a semaphore that only allows one lookup at a
	// time to recheck resolv.conf.
	ch          chan struct{} // guards lastChecked and modTime
	lastChecked time.Time     // last time resolv.conf was checked

	dnsConfig atomic.Pointer[dnsConfig] // parsed resolv.conf structure used in lookups
}

var resolvConf resolverConfig

func getSystemDNSConfig() *dnsConfig {
	resolvConf.tryUpdate("/etc/resolv.conf")
	return resolvConf.dnsConfig.Load()
}

// init initializes conf and is only called via conf.initOnce.
func (conf *resolverConfig) init() {
	// Set dnsConfig and lastChecked so we don't parse
	// resolv.conf twice the first time.
	conf.dnsConfig.Store(dnsReadConfig("/etc/resolv.conf"))
	conf.lastChecked = time.Now()

	// Prepare ch so that only one update of resolverConfig may
	// run at once.
	conf.ch = make(chan struct{}, 1)
}

// tryUpdate tries to update conf with the named resolv.conf file.
// The name variable only exists for testing. It is otherwise always
// "/etc/resolv.conf".
func (conf *resolverConfig) tryUpdate(name string) {
	conf.initOnce.Do(conf.init)

	if conf.dnsConfig.Load().noReload {
		return
	}

	// Ensure only one update at a time checks resolv.conf.
	if !conf.tryAcquireSema() {
		return
	}
	defer conf.releaseSema()

	now := time.Now()
	if conf.lastChecked.After(now.Add(-5 * time.Second)) {
		return
	}
	conf.lastChecked = now

	switch runtime.GOOS {
	case "windows":
		// There's no file on disk, so don't bother checking
		// and failing.
		//
		// The Windows implementation of dnsReadConfig (called
		// below) ignores the name.
	default:
		var mtime time.Time
		if fi, err := os.Stat(name); err == nil {
			mtime = fi.ModTime()
		}
		if mtime.Equal(conf.dnsConfig.Load().mtime) {
			return
		}
	}

	dnsConf := dnsReadConfig(name)
	conf.dnsConfig.Store(dnsConf)
}

func (conf *resolverConfig) tryAcquireSema() bool {
	select {
	case conf.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (conf *resolverConfig) releaseSema() {
	<-conf.ch
}

func (r *Resolver) lookup(ctx context.Context, name string, qtype dnsmessage.Type, conf *dnsConfig) (dnsmessage.Parser, string, error) {
	if !isDomainName(name) {
		// We used to use "invalid domain name" as the error,
		// but that is a detail of the specific lookup mechanism.
		// Other lookups might allow broader name syntax
		// (for example Multicast DNS allows UTF-8; see RFC 6762).
		// For consistency with libc resolvers, report no such host.
		return dnsmessage.Parser{}, "", newDNSError(errNoSuchHost, name, "")
	}

	if conf == nil {
		conf = getSystemDNSConfig()
	}

	var (
		p      dnsmessage.Parser
		server string
		err    error
	)
	for _, fqdn := range conf.nameList(name) {
		p, server, err = r.tryOneName(ctx, conf, fqdn, qtype)
		if err == nil {
			break
		}
		if nerr, ok := err.(Error); ok && nerr.Temporary() && r.strictErrors() {
			// If we hit a temporary error with StrictErrors enabled,
			// stop immediately instead of trying more names.
			break
		}
	}
	if err == nil {
		return p, server, nil
	}
	if err, ok := err.(*DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		err.Name = name
	}
	return dnsmessage.Parser{}, "", err
}

// avoidDNS reports whether this is a hostname for which we should not
// use DNS. Currently this includes only .onion, per RFC 7686. See
// golang.org/issue/13705. Does not cover .local names (RFC 6762),
// see golang.org/issue/16739.
func avoidDNS(name string) bool {
	if name == "" {
		return true
	}
	name = stringslite.TrimSuffix(name, ".")
	return stringsHasSuffixFold(name, ".onion")
}

// nameList returns a list of names for sequential DNS queries.
func (conf *dnsConfig) nameList(name string) []string {
	// Check name length (see isDomainName).
	l := len(name)
	rooted := l > 0 && name[l-1] == '.'
	if l > 254 || l == 254 && !rooted {
		return nil
	}

	// If name is rooted (trailing dot), try only that name.
	if rooted {
		if avoidDNS(name) {
			return nil
		}
		return []string{name}
	}

	hasNdots := bytealg.CountString(name, '.') >= conf.ndots
	name += "."
	l++

	// Build list of search choices.
	names := make([]string, 0, 1+len(conf.search))
	// If name has enough dots, try unsuffixed first.
	if hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	// Try suffixes that are not too long (see isDomainName).
	for _, suffix := range conf.search {
		fqdn := name + suffix
		if !avoidDNS(fqdn) && len(fqdn) <= 254 {
			names = append(names, fqdn)
		}
	}
	// Try unsuffixed, if not tried first above.
	if !hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	return names
}

// hostLookupOrder specifies the order of LookupHost lookup strategies.
// It is basically a simplified representation of nsswitch.conf.
// "files" means /etc/hosts.
type hostLookupOrder int

const (
	// hostLookupCgo means defer to cgo.
	hostLookupCgo      hostLookupOrder = iota
	hostLookupFilesDNS                 // files first
	hostLookupDNSFiles                 // dns first
	hostLookupFiles                    // only files
	hostLookupDNS                      // only DNS
)

var lookupOrderName = map[hostLookupOrder]string{
	hostLookupCgo:      "cgo",
	hostLookupFilesDNS: "files,dns",
	hostLookupDNSFiles: "dns,files",
	hostLookupFiles:    "files",
	hostLookupDNS:      "dns",
}

func (o hostLookupOrder) String() string {
	if s, ok := lookupOrderName[o]; ok {
		return s
	}
	return "hostLookupOrder=" + itoa.Itoa(int(o)) + "??"
}

func (r *Resolver) goLookupHostOrder(ctx context.Context, name string, order hostLookupOrder, conf *dnsConfig) (addrs []string, err error) {
	if order == hostLookupFilesDNS || order == hostLookupFiles {
		// Use entries from /etc/hosts if they match.
		addrs, _ = lookupStaticHost(name)
		if len(addrs) > 0 {
			return
		}

		if order == hostLookupFiles {
			return nil, newDNSError(errNoSuchHost, name, "")
		}
	}
	ips, _, err := r.goLookupIPCNAMEOrder(ctx, "ip", name, order, conf)
	if err != nil {
		return
	}
	addrs = make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	return
}

// lookup entries from /etc/hosts
func goLookupIPFiles(name string) (addrs []IPAddr, canonical string) {
	addr, canonical := lookupStaticHost(name)
	for _, haddr := range addr {
		haddr, zone := splitHostZone(haddr)
		if ip := ParseIP(haddr); ip != nil {
			addr := IPAddr{IP: ip, Zone: zone}
			addrs = append(addrs, addr)
		}
	}
	sortByRFC6724(addrs)
	return addrs, canonical
}

// goLookupIP is the native Go implementation of LookupIP.
// The libc versions are in cgo_*.go.
func (r *Resolver) goLookupIP(ctx context.Context, network, host string, order hostLookupOrder, conf *dnsConfig) (addrs []IPAddr, err error) {
	addrs, _, err = r.goLookupIPCNAMEOrder(ctx, network, host, order, conf)
	return
}

func (r *Resolver) goLookupIPCNAMEOrder(ctx context.Context, network, name string, order hostLookupOrder, conf *dnsConfig) (addrs []IPAddr, cname dnsmessage.Name, err error) {
	if order == hostLookupFilesDNS || order == hostLookupFiles {
		var canonical string
		addrs, canonical = goLookupIPFiles(name)

		if len(addrs) > 0 {
			var err error
			cname, err = dnsmessage.NewName(canonical)
			if err != nil {
				return nil, dnsmessage.Name{}, err
			}
			return addrs, cname, nil
		}

		if order == hostLookupFiles {
			return nil, dnsmessage.Name{}, newDNSError(errNoSuchHost, name, "")
		}
	}

	if !isDomainName(name) {
		// See comment in func lookup above about use of errNoSuchHost.
		return nil, dnsmessage.Name{}, newDNSError(errNoSuchHost, name, "")
	}
	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}

	if conf == nil {
		conf = getSystemDNSConfig()
	}

	lane := make(chan result, 1)
	qtypes := []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	if network == "CNAME" {
		qtypes = append(qtypes, dnsmessage.TypeCNAME)
	}
	switch ipVersion(network) {
	case '4':
		qtypes = []dnsmessage.Type{dnsmessage.TypeA}
	case '6':
		qtypes = []dnsmessage.Type{dnsmessage.TypeAAAA}
	}
	var queryFn func(fqdn string, qtype dnsmessage.Type)
	var responseFn func(fqdn string, qtype dnsmessage.Type) result
	if conf.singleRequest {
		queryFn = func(fqdn string, qtype dnsmessage.Type) {}
		responseFn = func(fqdn string, qtype dnsmessage.Type) result {
			dnsWaitGroup.Add(1)
			defer dnsWaitGroup.Done()
			p, server, err := r.tryOneName(ctx, conf, fqdn, qtype)
			return result{p, server, err}
		}
	} else {
		queryFn = func(fqdn string, qtype dnsmessage.Type) {
			dnsWaitGroup.Add(1)
			go func(qtype dnsmessage.Type) {
				p, server, err := r.tryOneName(ctx, conf, fqdn, qtype)
				lane <- result{p, server, err}
				dnsWaitGroup.Done()
			}(qtype)
		}
		responseFn = func(fqdn string, qtype dnsmessage.Type) result {
			return <-lane
		}
	}
	var lastErr error
	for _, fqdn := range conf.nameList(name) {
		for _, qtype := range qtypes {
			queryFn(fqdn, qtype)
		}
		hitStrictError := false
		for _, qtype := range qtypes {
			result := responseFn(fqdn, qtype)
			if result.error != nil {
				if nerr, ok := result.error.(Error); ok && nerr.Temporary() && r.strictErrors() {
					// This error will abort the nameList loop.
					hitStrictError = true
					lastErr = result.error
				} else if lastErr == nil || fqdn == name+"." {
					// Prefer error for original name.
					lastErr = result.error
				}
				continue
			}

			// Presotto says it's okay to assume that servers listed in
			// /etc/resolv.conf are recursive resolvers.
			//
			// We asked for recursion, so it should have included all the
			// answers we need in this one packet.
			//
			// Further, RFC 1034 section 4.3.1 says that "the recursive
			// response to a query will be... The answer to the query,
			// possibly preface by one or more CNAME RRs that specify
			// aliases encountered on the way to an answer."
			//
			// Therefore, we should be able to assume that we can ignore
			// CNAMEs and that the A and AAAA records we requested are
			// for the canonical name.

		loop:
			for {
				h, err := result.p.AnswerHeader()
				if err != nil && err != dnsmessage.ErrSectionDone {
					lastErr = &DNSError{
						Err:    errCannotUnmarshalDNSMessage.Error(),
						Name:   name,
						Server: result.server,
					}
				}
				if err != nil {
					break
				}
				switch h.Type {
				case dnsmessage.TypeA:
					a, err := result.p.AResource()
					if err != nil {
						lastErr = &DNSError{
							Err:    errCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					addrs = append(addrs, IPAddr{IP: IP(a.A[:])})
					if cname.Length == 0 && h.Name.Length != 0 {
						cname = h.Name
					}

				case dnsmessage.TypeAAAA:
					aaaa, err := result.p.AAAAResource()
					if err != nil {
						lastErr = &DNSError{
							Err:    errCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					addrs = append(addrs, IPAddr{IP: IP(aaaa.AAAA[:])})
					if cname.Length == 0 && h.Name.Length != 0 {
						cname = h.Name
					}

				case dnsmessage.TypeCNAME:
					c, err := result.p.CNAMEResource()
					if err != nil {
						lastErr = &DNSError{
							Err:    errCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					if cname.Length == 0 && c.CNAME.Length > 0 {
						cname = c.CNAME
					}

				default:
					if err := result.p.SkipAnswer(); err != nil {
						lastErr = &DNSError{
							Err:    errCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					continue
				}
			}
		}
		if hitStrictError {
			// If either family hit an error with StrictErrors enabled,
			// discard all addresses. This ensures that network flakiness
			// cannot turn a dualstack hostname IPv4/IPv6-only.
			addrs = nil
			break
		}
		if len(addrs) > 0 || network == "CNAME" && cname.Length > 0 {
			break
		}
	}
	if lastErr, ok := lastErr.(*DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		lastErr.Name = name
	}
	sortByRFC6724(addrs)
	if len(addrs) == 0 && !(network == "CNAME" && cname.Length > 0) {
		if order == hostLookupDNSFiles {
			var canonical string
			addrs, canonical = goLookupIPFiles(name)
			if len(addrs) > 0 {
				var err error
				cname, err = dnsmessage.NewName(canonical)
				if err != nil {
					return nil, dnsmessage.Name{}, err
				}
				return addrs, cname, nil
			}
		}
		if lastErr != nil {
			return nil, dnsmessage.Name{}, lastErr
		}
	}
	return addrs, cname, nil
}

// goLookupCNAME is the native Go (non-cgo) implementation of LookupCNAME.
func (r *Resolver) goLookupCNAME(ctx context.Context, host string, order hostLookupOrder, conf *dnsConfig) (string, error) {
	_, cname, err := r.goLookupIPCNAMEOrder(ctx, "CNAME", host, order, conf)
	return cname.String(), err
}

// goLookupPTR is the native Go implementation of LookupAddr.
func (r *Resolver) goLookupPTR(ctx context.Context, addr string, order hostLookupOrder, conf *dnsConfig) ([]string, error) {
	if order == hostLookupFiles || order == hostLookupFilesDNS {
		names := lookupStaticAddr(addr)
		if len(names) > 0 {
			return names, nil
		}

		if order == hostLookupFiles {
			return nil, newDNSError(errNoSuchHost, addr, "")
		}
	}

	arpa, err := reverseaddr(addr)
	if err != nil {
		return nil, err
	}
	p, server, err := r.lookup(ctx, arpa, dnsmessage.TypePTR, conf)
	if err != nil {
		var dnsErr *DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			if order == hostLookupDNSFiles {
				names := lookupStaticAddr(addr)
				if len(names) > 0 {
					return names, nil
				}
			}
		}
		return nil, err
	}
	var ptrs []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &DNSError{
				Err:    errCannotUnmarshalDNSMessage.Error(),
				Name:   addr,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypePTR {
			err := p.SkipAnswer()
			if err != nil {
				return nil, &DNSError{
					Err:    errCannotUnmarshalDNSMessage.Error(),
					Name:   addr,
					Server: server,
				}
			}
			continue
		}
		ptr, err := p.PTRResource()
		if err != nil {
			return nil, &DNSError{
				Err:    errCannotUnmarshalDNSMessage.Error(),
				Name:   addr,
				Server: server,
			}
		}
		ptrs = append(ptrs, ptr.PTR.String())

	}

	return ptrs, nil
}

"""



```