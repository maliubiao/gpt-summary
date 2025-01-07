Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and High-Level Understanding:**

* **Identify the file:** `go/src/net/http/transport.go`. This immediately tells us it's part of the core HTTP client implementation in Go's standard library.
* **Copyright and License:**  Standard Go boilerplate. Confirms it's an official Go component.
* **Package declaration:** `package http`. Reinforces the location and purpose.
* **Imports:**  A quick glance reveals essential packages like `bufio`, `crypto/tls`, `net`, `net/url`, `sync`, `time`, and importantly,  `net/http` itself (for `httptrace`). These hints at network operations, concurrency, security, and tracing.
* **Comments:** The leading comments are crucial. They explicitly state:
    * "HTTP client implementation. See RFC 7230 through 7235."  Indicates adherence to HTTP standards.
    * "This is the low-level Transport implementation of RoundTripper." This is key. It's *the* mechanism for actually sending and receiving HTTP data, but not the user-facing `Client`.
    * "The high-level interface is in client.go."  This confirms the separation of concerns.

**2. Focusing on Key Structures and Variables:**

* **`DefaultTransport`:**  This is a significant starting point. The comment clearly states it's the default `RoundTripper` used by `DefaultClient`. The initialization of its fields (like `Proxy`, `DialContext`, timeouts, connection limits) provides valuable insights into default HTTP client behavior.
* **`Transport` struct:** The definition of this struct is the core of the snippet. Each field represents a configurable aspect of the HTTP transport. I mentally categorize them:
    * **Connection Management:** `idleMu`, `idleConn`, `idleConnWait`, `idleLRU`, `connsPerHostMu`, `connsPerHost`, `connsPerHostWait`, `dialsInProgress`, `MaxIdleConns`, `MaxIdleConnsPerHost`, `MaxConnsPerHost`, `IdleConnTimeout`. These scream "connection pooling and reuse."
    * **Networking:** `Proxy`, `DialContext`, `Dial`, `DialTLSContext`, `DialTLS`. These relate to how connections are established, including proxy usage and TLS.
    * **TLS Configuration:** `TLSClientConfig`, `TLSHandshakeTimeout`.
    * **Protocol Settings:** `DisableKeepAlives`, `DisableCompression`, `TLSNextProto`, `ForceAttemptHTTP2`, `Protocols`. These control HTTP/1.1 and HTTP/2 behavior.
    * **Timeouts:** `ResponseHeaderTimeout`, `ExpectContinueTimeout`.
    * **Headers and Buffers:** `ProxyConnectHeader`, `GetProxyConnectHeader`, `MaxResponseHeaderBytes`, `WriteBufferSize`, `ReadBufferSize`.
    * **HTTP/2 Specifics:** `nextProtoOnce`, `h2transport`, `HTTP2`. These hint at HTTP/2 support and initialization.
* **Functions associated with `Transport`:**  Methods like `Clone`, `writeBufferSize`, `readBufferSize`, `onceSetNextProtoDefaults`, `protocols`, `roundTrip`, `awaitLegacyCancel`, `setupRewindBody`, `rewindBody`, `shouldRetryRequest`, `RegisterProtocol`, `CloseIdleConnections`, `prepareTransportCancel`, `CancelRequest`. Each of these reveals a specific aspect of the transport's functionality.

**3. Deeper Dive and Inference (Trial and Error/Hypothesizing):**

* **Connection Pooling:** The sheer number of fields related to `idleConn` and connection limits strongly suggests connection pooling for efficiency. The `idleLRU` hints at a Least Recently Used eviction strategy for idle connections.
* **Proxy Handling:** The `Proxy` field and the `ProxyFromEnvironment` and `ProxyURL` functions explicitly deal with configuring and using HTTP proxies.
* **Dialing:** The various `Dial...` fields show the flexibility in how connections are established, supporting custom dialers and TLS configurations.
* **HTTP/2 Support:**  The `ForceAttemptHTTP2`, `TLSNextProto`, `h2transport`, and the `onceSetNextProtoDefaults` function clearly indicate that this `Transport` supports HTTP/2, likely through ALPN negotiation.
* **Request Retries:** The `shouldRetryRequest` function and the logic within `roundTrip` point to the transport's ability to retry failed requests under certain conditions (idempotency, network errors).
* **Error Handling:** The `setError` method in `transportRequest` suggests a mechanism for capturing errors during the request processing.
* **Cancellation:** The `CancelRequest` method and the `prepareTransportCancel` function demonstrate how request cancellation is handled (though the comments highlight the limitations and deprecation of `CancelRequest`).

**4. Structuring the Answer:**

* **Functionality Summary:** Start with a concise overview of the core responsibilities, using the information gleaned from the comments and the structure of the code. Emphasize its role as the low-level `RoundTripper`.
* **Feature Explanation with Code Examples (where possible and relevant):**
    * **Connection Pooling:** Explain the purpose and mention key fields like `MaxIdleConns`, `MaxIdleConnsPerHost`. A simple example showing how multiple requests to the same host might reuse a connection would be illustrative.
    * **Proxy Support:** Explain the `Proxy` function and how to use `ProxyFromEnvironment` or `ProxyURL`. A short code snippet demonstrating setting a proxy.
    * **Custom Dialers:** Explain the `DialContext` and `DialTLSContext` and why someone might use them. A basic example of a custom dialer.
    * **HTTP/2:** Explain the automatic and configurable HTTP/2 support.
    * **Timeouts:** List the various timeout options and their purposes.
    * **Request Retries:** Explain the conditions under which retries occur.
    * **Request Cancellation:**  Explain the `CancelRequest` method and the preferred `WithContext` approach.
* **Code Inference (if any compelling cases arise):** While the provided snippet is mostly declarations, the logic in `roundTrip` (especially the retry loop and the handling of `pconn`) and `shouldRetryRequest` could be candidates for deeper code inference if a more extended snippet were provided.
* **Command-Line Arguments:**  In this specific snippet, there are no direct command-line argument handling. However, I'd mention that environment variables like `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` are implicitly handled through `ProxyFromEnvironment`.
* **Common Mistakes:**  Based on the code and HTTP concepts, I'd think about common pitfalls:
    * **Not reusing `Transport`:**  Creating a new `Transport` for every request is inefficient.
    * **Incorrect timeout settings:** Setting timeouts too short can lead to unnecessary failures.
    * **Misunderstanding connection limits:**  Exceeding `MaxConnsPerHost` can cause blocking.
    * **Deprecated `CancelRequest`:**  Using the older cancellation method instead of context-based cancellation.
* **Functionality Summary (Again):**  End with a brief recap reinforcing the main purpose of the code.

**Self-Correction/Refinement During the Process:**

* **Initial Overwhelm:** The `Transport` struct is large. Don't try to understand everything at once. Focus on the major categories of functionality.
* **Ambiguity:** If a comment or field name isn't immediately clear, look for related code or comments that provide more context. For example, seeing `idleConn` alongside `idleMu` strongly suggests concurrent access and the need for locking.
* **Prioritization:** Focus on the most significant features and concepts first (connection pooling, proxies, HTTP/2). Don't get bogged down in minor details initially.
* **Code Examples:**  Think about what simple, illustrative code examples would best demonstrate the key features. Keep them concise.

By following this structured approach, I can systematically analyze the code snippet and generate a comprehensive and accurate explanation of its functionality.
这段代码是 Go 语言 `net/http` 包中 `transport.go` 文件的一部分，它实现了 HTTP 客户端的核心传输层逻辑。 可以将其归纳为 **HTTP 客户端的底层传输实现**。

更具体地说，它负责处理以下关键功能：

**主要功能归纳:**

1. **建立和管理网络连接:**
   - 负责建立到目标服务器的 TCP 连接 (通过 `DialContext` 或 `Dial`)。
   - 处理 TLS 连接的建立 (通过 `DialTLSContext` 或 `DialTLS`)。
   - 支持通过 HTTP 代理或 HTTPS 代理 (使用 CONNECT 方法) 进行连接。
   - 管理连接的复用 (keep-alive) 以提高性能。

2. **处理 HTTP 请求和响应:**
   - 将 `Request` 对象转换为网络传输的字节流。
   - 发送请求头和请求体。
   - 接收服务器的响应头和响应体。
   - 处理分块传输编码 (chunked transfer encoding)。
   - 处理内容压缩 (gzip)。

3. **连接池管理:**
   - 维护一个连接池 (`idleConn`)，用于缓存空闲的连接以便后续请求复用，减少连接建立的开销。
   - 实现了连接的超时和清理机制 (`IdleConnTimeout`)。
   - 可以配置每个主机允许的最大空闲连接数 (`MaxIdleConnsPerHost`) 和总的空闲连接数 (`MaxIdleConns`)。
   - 可以限制每个主机的最大连接数 (`MaxConnsPerHost`)。

4. **代理支持:**
   - 通过 `Proxy` 函数配置代理服务器。
   - 支持从环境变量 (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) 中读取代理配置。
   - 可以为 CONNECT 请求设置自定义头部 (`ProxyConnectHeader`, `GetProxyConnectHeader`)。

5. **协议协商和升级:**
   - 支持 HTTP/2 协议 (通过 ALPN 协商或 `ForceAttemptHTTP2` 配置)。
   - 允许注册其他协议处理程序 (`RegisterProtocol`)。

6. **超时控制:**
   - 提供多种超时配置，例如 TCP 连接超时 (`Dialer.Timeout`)、TLS 握手超时 (`TLSHandshakeTimeout`)、等待响应头超时 (`ResponseHeaderTimeout`)、等待 "Expect: 100-continue" 响应超时 (`ExpectContinueTimeout`)。

7. **请求取消:**
   - 支持通过 `Request.Cancel` 或 `Transport.CancelRequest` 取消正在进行的请求。 (但注释中提到了 `Transport.CancelRequest` 的局限性和已被 `Request.WithContext` 取代的趋势)。

8. **错误处理和重试:**
   - 处理网络错误和服务器错误。
   - 实现了请求的重试机制，但仅限于幂等请求且在某些特定情况下。

**代码推理和示例:**

这段代码本身主要是结构体和方法的定义，具体的实现细节在后续的代码中。我们可以基于这些定义推断一些功能。

**推断1：连接池的实现**

假设我们发送了两个到同一个主机的 HTTP 请求，并且服务器支持 keep-alive。`Transport` 应该会复用第一个请求建立的连接来发送第二个请求。

```go
package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{}

	// 第一个请求
	resp1, err := client.Get("https://www.example.com")
	if err != nil {
		fmt.Println("请求 1 失败:", err)
		return
	}
	fmt.Println("请求 1 状态码:", resp1.StatusCode)
	resp1.Body.Close()

	// 等待一小段时间，确保连接可能进入空闲状态
	time.Sleep(1 * time.Second)

	// 第二个请求
	resp2, err := client.Get("https://www.example.com/another-page")
	if err != nil {
		fmt.Println("请求 2 失败:", err)
		return
	}
	fmt.Println("请求 2 状态码:", resp2.StatusCode)
	resp2.Body.Close()

	// 我们可以通过一些内部机制（例如反射或者观察日志，如果开启了调试）来验证
	// 两个请求是否使用了同一个底层的 TCP 连接。
}
```

**假设的输入与输出:**

* **输入:**  两个连续的对 `https://www.example.com` 的 GET 请求。
* **输出:**  两个请求都成功返回，并且底层的 `Transport` 尽可能地复用了连接。  (注意：这里只是假设，实际观察需要更底层的机制)。

**推断2：代理的使用**

假设我们设置了 `HTTP_PROXY` 环境变量，`Transport` 会使用该代理来发送 HTTP 请求。

**命令行参数处理:**

这段代码本身不直接处理命令行参数。但是，它通过 `ProxyFromEnvironment` 函数间接地使用了环境变量 `HTTP_PROXY`, `HTTPS_PROXY`, 和 `NO_PROXY` (或其小写版本)。

**详细介绍 `ProxyFromEnvironment`:**

`ProxyFromEnvironment` 函数会检查以下环境变量来确定代理服务器：

1. **与请求 URL Scheme 匹配的代理变量:**
   - 如果请求的 URL Scheme 是 `http`，则检查 `http_proxy` (或 `HTTP_PROXY`)。
   - 如果请求的 URL Scheme 是 `https`，则检查 `https_proxy` (或 `HTTPS_PROXY`)。

2. **`no_proxy` 变量 (或 `NO_PROXY`):**
   - 如果设置了 `no_proxy`，它的值是一个用逗号分隔的主机名或域名列表。
   - 如果请求的目标主机匹配 `no_proxy` 中的任何条目，则不使用代理。通配符 `*` 可以用来匹配所有主机。

3. **代理 URL 格式:**
   - 代理环境变量的值可以是一个完整的 URL (例如 `http://user:password@proxy.example.com:8080`) 或一个 `host[:port]` (例如 `proxy.example.com:8080`)。如果只提供了主机和端口，则默认使用 `http` scheme。

**使用者易犯错的点:**

1. **不重用 `http.Client`:**  每次发送请求都创建一个新的 `http.Client` (及其底层的 `Transport`) 会导致无法有效利用连接池，降低性能。应该尽可能地重用 `http.Client` 实例。

   ```go
   // 错误示例: 每次请求都创建新的 Client
   for i := 0; i < 100; i++ {
       client := &http.Client{}
       resp, _ := client.Get("https://www.example.com")
       if resp != nil {
           resp.Body.Close()
       }
   }

   // 正确示例: 重用 Client
   client := &http.Client{}
   for i := 0; i < 100; i++ {
       resp, _ := client.Get("https://www.example.com")
       if resp != nil {
           resp.Body.Close()
       }
   }
   ```

2. **错误配置或理解超时:**  不了解各个超时选项的作用，或者设置了不合理的超时时间，可能导致请求意外失败或阻塞。例如，将 `Dialer.Timeout` 设置得过短可能导致连接建立失败。

3. **混淆 TCP Keep-Alive 和 HTTP Keep-Alive:** `Transport` 的 `DisableKeepAlives` 字段控制的是 HTTP Keep-Alive，与 TCP 层的 Keep-Alive 是不同的概念。禁用 HTTP Keep-Alive 会强制每个请求都建立新的连接。

4. **在并发场景下修改 `Transport` 的字段:** `Transport` 结构体的大部分字段在创建后不应被并发修改，因为它在多 goroutine 之间共享。如果需要自定义配置，应该创建新的 `Transport` 实例。

**功能归纳 (针对提供的代码片段):**

这段代码定义了 `Transport` 结构体及其相关的辅助结构体和方法，是 Go 语言 `net/http` 包中负责执行实际 HTTP 请求的核心组件。它抽象了底层的网络连接管理、请求发送和响应接收的细节，并提供了丰富的配置选项来满足不同的需求，例如代理设置、超时控制、连接池管理和协议协商。 它是 `http.Client` 实现高层 HTTP 功能的基础。

Prompt: 
```
这是路径为go/src/net/http/transport.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP client implementation. See RFC 7230 through 7235.
//
// This is the low-level Transport implementation of RoundTripper.
// The high-level interface is in client.go.

package http

import (
	"bufio"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"internal/godebug"
	"io"
	"log"
	"maps"
	"net"
	"net/http/httptrace"
	"net/http/internal/ascii"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "unsafe"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http/httpproxy"
)

// DefaultTransport is the default implementation of [Transport] and is
// used by [DefaultClient]. It establishes network connections as needed
// and caches them for reuse by subsequent calls. It uses HTTP proxies
// as directed by the environment variables HTTP_PROXY, HTTPS_PROXY
// and NO_PROXY (or the lowercase versions thereof).
var DefaultTransport RoundTripper = &Transport{
	Proxy: ProxyFromEnvironment,
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}),
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// DefaultMaxIdleConnsPerHost is the default value of [Transport]'s
// MaxIdleConnsPerHost.
const DefaultMaxIdleConnsPerHost = 2

// Transport is an implementation of [RoundTripper] that supports HTTP,
// HTTPS, and HTTP proxies (for either HTTP or HTTPS with CONNECT).
//
// By default, Transport caches connections for future re-use.
// This may leave many open connections when accessing many hosts.
// This behavior can be managed using [Transport.CloseIdleConnections] method
// and the [Transport.MaxIdleConnsPerHost] and [Transport.DisableKeepAlives] fields.
//
// Transports should be reused instead of created as needed.
// Transports are safe for concurrent use by multiple goroutines.
//
// A Transport is a low-level primitive for making HTTP and HTTPS requests.
// For high-level functionality, such as cookies and redirects, see [Client].
//
// Transport uses HTTP/1.1 for HTTP URLs and either HTTP/1.1 or HTTP/2
// for HTTPS URLs, depending on whether the server supports HTTP/2,
// and how the Transport is configured. The [DefaultTransport] supports HTTP/2.
// To explicitly enable HTTP/2 on a transport, set [Transport.Protocols].
//
// Responses with status codes in the 1xx range are either handled
// automatically (100 expect-continue) or ignored. The one
// exception is HTTP status code 101 (Switching Protocols), which is
// considered a terminal status and returned by [Transport.RoundTrip]. To see the
// ignored 1xx responses, use the httptrace trace package's
// ClientTrace.Got1xxResponse.
//
// Transport only retries a request upon encountering a network error
// if the connection has been already been used successfully and if the
// request is idempotent and either has no body or has its [Request.GetBody]
// defined. HTTP requests are considered idempotent if they have HTTP methods
// GET, HEAD, OPTIONS, or TRACE; or if their [Header] map contains an
// "Idempotency-Key" or "X-Idempotency-Key" entry. If the idempotency key
// value is a zero-length slice, the request is treated as idempotent but the
// header is not sent on the wire.
type Transport struct {
	idleMu       sync.Mutex
	closeIdle    bool                                // user has requested to close all idle conns
	idleConn     map[connectMethodKey][]*persistConn // most recently used at end
	idleConnWait map[connectMethodKey]wantConnQueue  // waiting getConns
	idleLRU      connLRU

	reqMu       sync.Mutex
	reqCanceler map[*Request]context.CancelCauseFunc

	altMu    sync.Mutex   // guards changing altProto only
	altProto atomic.Value // of nil or map[string]RoundTripper, key is URI scheme

	connsPerHostMu   sync.Mutex
	connsPerHost     map[connectMethodKey]int
	connsPerHostWait map[connectMethodKey]wantConnQueue // waiting getConns
	dialsInProgress  wantConnQueue

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	//
	// The proxy type is determined by the URL scheme. "http",
	// "https", "socks5", and "socks5h" are supported. If the scheme is empty,
	// "http" is assumed.
	// "socks5" is treated the same as "socks5h".
	//
	// If the proxy URL contains a userinfo subcomponent,
	// the proxy request will pass the username and password
	// in a Proxy-Authorization header.
	//
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*Request) (*url.URL, error)

	// OnProxyConnectResponse is called when the Transport gets an HTTP response from
	// a proxy for a CONNECT request. It's called before the check for a 200 OK response.
	// If it returns an error, the request fails with that error.
	OnProxyConnectResponse func(ctx context.Context, proxyURL *url.URL, connectReq *Request, connectRes *Response) error

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If DialContext is nil (and the deprecated Dial below is also nil),
	// then the transport dials using package net.
	//
	// DialContext runs concurrently with calls to RoundTrip.
	// A RoundTrip call that initiates a dial may end up using
	// a connection dialed previously when the earlier connection
	// becomes idle before the later DialContext completes.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Dial specifies the dial function for creating unencrypted TCP connections.
	//
	// Dial runs concurrently with calls to RoundTrip.
	// A RoundTrip call that initiates a dial may end up using
	// a connection dialed previously when the earlier connection
	// becomes idle before the later Dial completes.
	//
	// Deprecated: Use DialContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialContext takes priority.
	Dial func(network, addr string) (net.Conn, error)

	// DialTLSContext specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// If DialTLSContext is nil (and the deprecated DialTLS below is also nil),
	// DialContext and TLSClientConfig are used.
	//
	// If DialTLSContext is set, the Dial and DialContext hooks are not used for HTTPS
	// requests and the TLSClientConfig and TLSHandshakeTimeout
	// are ignored. The returned net.Conn is assumed to already be
	// past the TLS handshake.
	DialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// Deprecated: Use DialTLSContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialTLSContext takes priority.
	DialTLS func(network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client.
	// If nil, the default configuration is used.
	// If non-nil, HTTP/2 support may not be enabled by default.
	TLSClientConfig *tls.Config

	// TLSHandshakeTimeout specifies the maximum amount of time to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration

	// DisableKeepAlives, if true, disables HTTP keep-alives and
	// will only use the connection to the server for a single
	// HTTP request.
	//
	// This is unrelated to the similarly named TCP keep-alives.
	DisableKeepAlives bool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// MaxIdleConns controls the maximum number of idle (keep-alive)
	// connections across all hosts. Zero means no limit.
	MaxIdleConns int

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) connections to keep per-host. If zero,
	// DefaultMaxIdleConnsPerHost is used.
	MaxIdleConnsPerHost int

	// MaxConnsPerHost optionally limits the total number of
	// connections per host, including connections in the dialing,
	// active, and idle states. On limit violation, dials will block.
	//
	// Zero means no limit.
	MaxConnsPerHost int

	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout, if non-zero, specifies the amount of
	// time to wait for a server's first response headers after fully
	// writing the request headers if the request has an
	// "Expect: 100-continue" header. Zero means no timeout and
	// causes the body to be sent immediately, without
	// waiting for the server to approve.
	// This time does not include the time to send the request header.
	ExpectContinueTimeout time.Duration

	// TLSNextProto specifies how the Transport switches to an
	// alternate protocol (such as HTTP/2) after a TLS ALPN
	// protocol negotiation. If Transport dials a TLS connection
	// with a non-empty protocol name and TLSNextProto contains a
	// map entry for that key (such as "h2"), then the func is
	// called with the request's authority (such as "example.com"
	// or "example.com:1234") and the TLS connection. The function
	// must return a RoundTripper that then handles the request.
	// If TLSNextProto is not nil, HTTP/2 support is not enabled
	// automatically.
	TLSNextProto map[string]func(authority string, c *tls.Conn) RoundTripper

	// ProxyConnectHeader optionally specifies headers to send to
	// proxies during CONNECT requests.
	// To set the header dynamically, see GetProxyConnectHeader.
	ProxyConnectHeader Header

	// GetProxyConnectHeader optionally specifies a func to return
	// headers to send to proxyURL during a CONNECT request to the
	// ip:port target.
	// If it returns an error, the Transport's RoundTrip fails with
	// that error. It can return (nil, nil) to not add headers.
	// If GetProxyConnectHeader is non-nil, ProxyConnectHeader is
	// ignored.
	GetProxyConnectHeader func(ctx context.Context, proxyURL *url.URL, target string) (Header, error)

	// MaxResponseHeaderBytes specifies a limit on how many
	// response bytes are allowed in the server's response
	// header.
	//
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// WriteBufferSize specifies the size of the write buffer used
	// when writing to the transport.
	// If zero, a default (currently 4KB) is used.
	WriteBufferSize int

	// ReadBufferSize specifies the size of the read buffer used
	// when reading from the transport.
	// If zero, a default (currently 4KB) is used.
	ReadBufferSize int

	// nextProtoOnce guards initialization of TLSNextProto and
	// h2transport (via onceSetNextProtoDefaults)
	nextProtoOnce      sync.Once
	h2transport        h2Transport // non-nil if http2 wired up
	tlsNextProtoWasNil bool        // whether TLSNextProto was nil when the Once fired

	// ForceAttemptHTTP2 controls whether HTTP/2 is enabled when a non-zero
	// Dial, DialTLS, or DialContext func or TLSClientConfig is provided.
	// By default, use of any those fields conservatively disables HTTP/2.
	// To use a custom dialer or TLS config and still attempt HTTP/2
	// upgrades, set this to true.
	ForceAttemptHTTP2 bool

	// HTTP2 configures HTTP/2 connections.
	//
	// This field does not yet have any effect.
	// See https://go.dev/issue/67813.
	HTTP2 *HTTP2Config

	// Protocols is the set of protocols supported by the transport.
	//
	// If Protocols includes UnencryptedHTTP2 and does not include HTTP1,
	// the transport will use unencrypted HTTP/2 for requests for http:// URLs.
	//
	// If Protocols is nil, the default is usually HTTP/1 only.
	// If ForceAttemptHTTP2 is true, or if TLSNextProto contains an "h2" entry,
	// the default is HTTP/1 and HTTP/2.
	Protocols *Protocols
}

func (t *Transport) writeBufferSize() int {
	if t.WriteBufferSize > 0 {
		return t.WriteBufferSize
	}
	return 4 << 10
}

func (t *Transport) readBufferSize() int {
	if t.ReadBufferSize > 0 {
		return t.ReadBufferSize
	}
	return 4 << 10
}

// Clone returns a deep copy of t's exported fields.
func (t *Transport) Clone() *Transport {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	t2 := &Transport{
		Proxy:                  t.Proxy,
		OnProxyConnectResponse: t.OnProxyConnectResponse,
		DialContext:            t.DialContext,
		Dial:                   t.Dial,
		DialTLS:                t.DialTLS,
		DialTLSContext:         t.DialTLSContext,
		TLSHandshakeTimeout:    t.TLSHandshakeTimeout,
		DisableKeepAlives:      t.DisableKeepAlives,
		DisableCompression:     t.DisableCompression,
		MaxIdleConns:           t.MaxIdleConns,
		MaxIdleConnsPerHost:    t.MaxIdleConnsPerHost,
		MaxConnsPerHost:        t.MaxConnsPerHost,
		IdleConnTimeout:        t.IdleConnTimeout,
		ResponseHeaderTimeout:  t.ResponseHeaderTimeout,
		ExpectContinueTimeout:  t.ExpectContinueTimeout,
		ProxyConnectHeader:     t.ProxyConnectHeader.Clone(),
		GetProxyConnectHeader:  t.GetProxyConnectHeader,
		MaxResponseHeaderBytes: t.MaxResponseHeaderBytes,
		ForceAttemptHTTP2:      t.ForceAttemptHTTP2,
		WriteBufferSize:        t.WriteBufferSize,
		ReadBufferSize:         t.ReadBufferSize,
	}
	if t.TLSClientConfig != nil {
		t2.TLSClientConfig = t.TLSClientConfig.Clone()
	}
	if t.HTTP2 != nil {
		t2.HTTP2 = &HTTP2Config{}
		*t2.HTTP2 = *t.HTTP2
	}
	if t.Protocols != nil {
		t2.Protocols = &Protocols{}
		*t2.Protocols = *t.Protocols
	}
	if !t.tlsNextProtoWasNil {
		npm := maps.Clone(t.TLSNextProto)
		if npm == nil {
			npm = make(map[string]func(authority string, c *tls.Conn) RoundTripper)
		}
		t2.TLSNextProto = npm
	}
	return t2
}

// h2Transport is the interface we expect to be able to call from
// net/http against an *http2.Transport that's either bundled into
// h2_bundle.go or supplied by the user via x/net/http2.
//
// We name it with the "h2" prefix to stay out of the "http2" prefix
// namespace used by x/tools/cmd/bundle for h2_bundle.go.
type h2Transport interface {
	CloseIdleConnections()
}

func (t *Transport) hasCustomTLSDialer() bool {
	return t.DialTLS != nil || t.DialTLSContext != nil
}

var http2client = godebug.New("http2client")

// onceSetNextProtoDefaults initializes TLSNextProto.
// It must be called via t.nextProtoOnce.Do.
func (t *Transport) onceSetNextProtoDefaults() {
	t.tlsNextProtoWasNil = (t.TLSNextProto == nil)
	if http2client.Value() == "0" {
		http2client.IncNonDefault()
		return
	}

	// If they've already configured http2 with
	// golang.org/x/net/http2 instead of the bundled copy, try to
	// get at its http2.Transport value (via the "https"
	// altproto map) so we can call CloseIdleConnections on it if
	// requested. (Issue 22891)
	altProto, _ := t.altProto.Load().(map[string]RoundTripper)
	if rv := reflect.ValueOf(altProto["https"]); rv.IsValid() && rv.Type().Kind() == reflect.Struct && rv.Type().NumField() == 1 {
		if v := rv.Field(0); v.CanInterface() {
			if h2i, ok := v.Interface().(h2Transport); ok {
				t.h2transport = h2i
				return
			}
		}
	}

	if _, ok := t.TLSNextProto["h2"]; ok {
		// There's an existing HTTP/2 implementation installed.
		return
	}
	protocols := t.protocols()
	if !protocols.HTTP2() && !protocols.UnencryptedHTTP2() {
		return
	}
	if omitBundledHTTP2 {
		return
	}
	t2, err := http2configureTransports(t)
	if err != nil {
		log.Printf("Error enabling Transport HTTP/2 support: %v", err)
		return
	}
	t.h2transport = t2

	// Auto-configure the http2.Transport's MaxHeaderListSize from
	// the http.Transport's MaxResponseHeaderBytes. They don't
	// exactly mean the same thing, but they're close.
	//
	// TODO: also add this to x/net/http2.Configure Transport, behind
	// a +build go1.7 build tag:
	if limit1 := t.MaxResponseHeaderBytes; limit1 != 0 && t2.MaxHeaderListSize == 0 {
		const h2max = 1<<32 - 1
		if limit1 >= h2max {
			t2.MaxHeaderListSize = h2max
		} else {
			t2.MaxHeaderListSize = uint32(limit1)
		}
	}

	// Server.ServeTLS clones the tls.Config before modifying it.
	// Transport doesn't. We may want to make the two consistent some day.
	//
	// http2configureTransport will have already set NextProtos, but adjust it again
	// here to remove HTTP/1.1 if the user has disabled it.
	t.TLSClientConfig.NextProtos = adjustNextProtos(t.TLSClientConfig.NextProtos, protocols)
}

func (t *Transport) protocols() Protocols {
	if t.Protocols != nil {
		return *t.Protocols // user-configured set
	}
	var p Protocols
	p.SetHTTP1(true) // default always includes HTTP/1
	switch {
	case t.TLSNextProto != nil:
		// Setting TLSNextProto to an empty map is a documented way
		// to disable HTTP/2 on a Transport.
		if t.TLSNextProto["h2"] != nil {
			p.SetHTTP2(true)
		}
	case !t.ForceAttemptHTTP2 && (t.TLSClientConfig != nil || t.Dial != nil || t.DialContext != nil || t.hasCustomTLSDialer()):
		// Be conservative and don't automatically enable
		// http2 if they've specified a custom TLS config or
		// custom dialers. Let them opt-in themselves via
		// Transport.Protocols.SetHTTP2(true) so we don't surprise them
		// by modifying their tls.Config. Issue 14275.
		// However, if ForceAttemptHTTP2 is true, it overrides the above checks.
	case http2client.Value() == "0":
	default:
		p.SetHTTP2(true)
	}
	return p
}

// ProxyFromEnvironment returns the URL of the proxy to use for a
// given request, as indicated by the environment variables
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase versions
// thereof). Requests use the proxy from the environment variable
// matching their scheme, unless excluded by NO_PROXY.
//
// The environment values may be either a complete URL or a
// "host[:port]", in which case the "http" scheme is assumed.
// An error is returned if the value is a different form.
//
// A nil URL and nil error are returned if no proxy is defined in the
// environment, or a proxy should not be used for the given request,
// as defined by NO_PROXY.
//
// As a special case, if req.URL.Host is "localhost" (with or without
// a port number), then a nil URL and nil error will be returned.
func ProxyFromEnvironment(req *Request) (*url.URL, error) {
	return envProxyFunc()(req.URL)
}

// ProxyURL returns a proxy function (for use in a [Transport])
// that always returns the same URL.
func ProxyURL(fixedURL *url.URL) func(*Request) (*url.URL, error) {
	return func(*Request) (*url.URL, error) {
		return fixedURL, nil
	}
}

// transportRequest is a wrapper around a *Request that adds
// optional extra headers to write and stores any error to return
// from roundTrip.
type transportRequest struct {
	*Request                        // original request, not to be mutated
	extra    Header                 // extra headers to write, or nil
	trace    *httptrace.ClientTrace // optional

	ctx    context.Context // canceled when we are done with the request
	cancel context.CancelCauseFunc

	mu  sync.Mutex // guards err
	err error      // first setError value for mapRoundTripError to consider
}

func (tr *transportRequest) extraHeaders() Header {
	if tr.extra == nil {
		tr.extra = make(Header)
	}
	return tr.extra
}

func (tr *transportRequest) setError(err error) {
	tr.mu.Lock()
	if tr.err == nil {
		tr.err = err
	}
	tr.mu.Unlock()
}

// useRegisteredProtocol reports whether an alternate protocol (as registered
// with Transport.RegisterProtocol) should be respected for this request.
func (t *Transport) useRegisteredProtocol(req *Request) bool {
	if req.URL.Scheme == "https" && req.requiresHTTP1() {
		// If this request requires HTTP/1, don't use the
		// "https" alternate protocol, which is used by the
		// HTTP/2 code to take over requests if there's an
		// existing cached HTTP/2 connection.
		return false
	}
	return true
}

// alternateRoundTripper returns the alternate RoundTripper to use
// for this request if the Request's URL scheme requires one,
// or nil for the normal case of using the Transport.
func (t *Transport) alternateRoundTripper(req *Request) RoundTripper {
	if !t.useRegisteredProtocol(req) {
		return nil
	}
	altProto, _ := t.altProto.Load().(map[string]RoundTripper)
	return altProto[req.URL.Scheme]
}

func validateHeaders(hdrs Header) string {
	for k, vv := range hdrs {
		if !httpguts.ValidHeaderFieldName(k) {
			return fmt.Sprintf("field name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// Don't include the value in the error,
				// because it may be sensitive.
				return fmt.Sprintf("field value for %q", k)
			}
		}
	}
	return ""
}

// roundTrip implements a RoundTripper over HTTP.
func (t *Transport) roundTrip(req *Request) (_ *Response, err error) {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	ctx := req.Context()
	trace := httptrace.ContextClientTrace(ctx)

	if req.URL == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.Header")
	}
	scheme := req.URL.Scheme
	isHTTP := scheme == "http" || scheme == "https"
	if isHTTP {
		// Validate the outgoing headers.
		if err := validateHeaders(req.Header); err != "" {
			req.closeBody()
			return nil, fmt.Errorf("net/http: invalid header %s", err)
		}

		// Validate the outgoing trailers too.
		if err := validateHeaders(req.Trailer); err != "" {
			req.closeBody()
			return nil, fmt.Errorf("net/http: invalid trailer %s", err)
		}
	}

	origReq := req
	req = setupRewindBody(req)

	if altRT := t.alternateRoundTripper(req); altRT != nil {
		if resp, err := altRT.RoundTrip(req); err != ErrSkipAltProtocol {
			return resp, err
		}
		var err error
		req, err = rewindBody(req)
		if err != nil {
			return nil, err
		}
	}
	if !isHTTP {
		req.closeBody()
		return nil, badStringError("unsupported protocol scheme", scheme)
	}
	if req.Method != "" && !validMethod(req.Method) {
		req.closeBody()
		return nil, fmt.Errorf("net/http: invalid method %q", req.Method)
	}
	if req.URL.Host == "" {
		req.closeBody()
		return nil, errors.New("http: no Host in request URL")
	}

	// Transport request context.
	//
	// If RoundTrip returns an error, it cancels this context before returning.
	//
	// If RoundTrip returns no error:
	//   - For an HTTP/1 request, persistConn.readLoop cancels this context
	//     after reading the request body.
	//   - For an HTTP/2 request, RoundTrip cancels this context after the HTTP/2
	//     RoundTripper returns.
	ctx, cancel := context.WithCancelCause(req.Context())

	// Convert Request.Cancel into context cancelation.
	if origReq.Cancel != nil {
		go awaitLegacyCancel(ctx, cancel, origReq)
	}

	// Convert Transport.CancelRequest into context cancelation.
	//
	// This is lamentably expensive. CancelRequest has been deprecated for a long time
	// and doesn't work on HTTP/2 requests. Perhaps we should drop support for it entirely.
	cancel = t.prepareTransportCancel(origReq, cancel)

	defer func() {
		if err != nil {
			cancel(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			req.closeBody()
			return nil, context.Cause(ctx)
		default:
		}

		// treq gets modified by roundTrip, so we need to recreate for each retry.
		treq := &transportRequest{Request: req, trace: trace, ctx: ctx, cancel: cancel}
		cm, err := t.connectMethodForRequest(treq)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		// Get the cached or newly-created connection to either the
		// host (for http or https), the http proxy, or the http proxy
		// pre-CONNECTed to https server. In any case, we'll be ready
		// to send it requests.
		pconn, err := t.getConn(treq, cm)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		var resp *Response
		if pconn.alt != nil {
			// HTTP/2 path.
			resp, err = pconn.alt.RoundTrip(req)
		} else {
			resp, err = pconn.roundTrip(treq)
		}
		if err == nil {
			if pconn.alt != nil {
				// HTTP/2 requests are not cancelable with CancelRequest,
				// so we have no further need for the request context.
				//
				// On the HTTP/1 path, roundTrip takes responsibility for
				// canceling the context after the response body is read.
				cancel(errRequestDone)
			}
			resp.Request = origReq
			return resp, nil
		}

		// Failed. Clean up and determine whether to retry.
		if http2isNoCachedConnError(err) {
			if t.removeIdleConn(pconn) {
				t.decConnsPerHost(pconn.cacheKey)
			}
		} else if !pconn.shouldRetryRequest(req, err) {
			// Issue 16465: return underlying net.Conn.Read error from peek,
			// as we've historically done.
			if e, ok := err.(nothingWrittenError); ok {
				err = e.error
			}
			if e, ok := err.(transportReadFromServerError); ok {
				err = e.err
			}
			if b, ok := req.Body.(*readTrackingBody); ok && !b.didClose {
				// Issue 49621: Close the request body if pconn.roundTrip
				// didn't do so already. This can happen if the pconn
				// write loop exits without reading the write request.
				req.closeBody()
			}
			return nil, err
		}
		testHookRoundTripRetried()

		// Rewind the body if we're able to.
		req, err = rewindBody(req)
		if err != nil {
			return nil, err
		}
	}
}

func awaitLegacyCancel(ctx context.Context, cancel context.CancelCauseFunc, req *Request) {
	select {
	case <-req.Cancel:
		cancel(errRequestCanceled)
	case <-ctx.Done():
	}
}

var errCannotRewind = errors.New("net/http: cannot rewind body after connection loss")

type readTrackingBody struct {
	io.ReadCloser
	didRead  bool
	didClose bool
}

func (r *readTrackingBody) Read(data []byte) (int, error) {
	r.didRead = true
	return r.ReadCloser.Read(data)
}

func (r *readTrackingBody) Close() error {
	r.didClose = true
	return r.ReadCloser.Close()
}

// setupRewindBody returns a new request with a custom body wrapper
// that can report whether the body needs rewinding.
// This lets rewindBody avoid an error result when the request
// does not have GetBody but the body hasn't been read at all yet.
func setupRewindBody(req *Request) *Request {
	if req.Body == nil || req.Body == NoBody {
		return req
	}
	newReq := *req
	newReq.Body = &readTrackingBody{ReadCloser: req.Body}
	return &newReq
}

// rewindBody returns a new request with the body rewound.
// It returns req unmodified if the body does not need rewinding.
// rewindBody takes care of closing req.Body when appropriate
// (in all cases except when rewindBody returns req unmodified).
func rewindBody(req *Request) (rewound *Request, err error) {
	if req.Body == nil || req.Body == NoBody || (!req.Body.(*readTrackingBody).didRead && !req.Body.(*readTrackingBody).didClose) {
		return req, nil // nothing to rewind
	}
	if !req.Body.(*readTrackingBody).didClose {
		req.closeBody()
	}
	if req.GetBody == nil {
		return nil, errCannotRewind
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	newReq := *req
	newReq.Body = &readTrackingBody{ReadCloser: body}
	return &newReq, nil
}

// shouldRetryRequest reports whether we should retry sending a failed
// HTTP request on a new connection. The non-nil input error is the
// error from roundTrip.
func (pc *persistConn) shouldRetryRequest(req *Request, err error) bool {
	if http2isNoCachedConnError(err) {
		// Issue 16582: if the user started a bunch of
		// requests at once, they can all pick the same conn
		// and violate the server's max concurrent streams.
		// Instead, match the HTTP/1 behavior for now and dial
		// again to get a new TCP connection, rather than failing
		// this request.
		return true
	}
	if err == errMissingHost {
		// User error.
		return false
	}
	if !pc.isReused() {
		// This was a fresh connection. There's no reason the server
		// should've hung up on us.
		//
		// Also, if we retried now, we could loop forever
		// creating new connections and retrying if the server
		// is just hanging up on us because it doesn't like
		// our request (as opposed to sending an error).
		return false
	}
	if _, ok := err.(nothingWrittenError); ok {
		// We never wrote anything, so it's safe to retry, if there's no body or we
		// can "rewind" the body with GetBody.
		return req.outgoingLength() == 0 || req.GetBody != nil
	}
	if !req.isReplayable() {
		// Don't retry non-idempotent requests.
		return false
	}
	if _, ok := err.(transportReadFromServerError); ok {
		// We got some non-EOF net.Conn.Read failure reading
		// the 1st response byte from the server.
		return true
	}
	if err == errServerClosedIdle {
		// The server replied with io.EOF while we were trying to
		// read the response. Probably an unfortunately keep-alive
		// timeout, just as the client was writing a request.
		return true
	}
	return false // conservatively
}

// ErrSkipAltProtocol is a sentinel error value defined by Transport.RegisterProtocol.
var ErrSkipAltProtocol = errors.New("net/http: skip alternate protocol")

// RegisterProtocol registers a new protocol with scheme.
// The [Transport] will pass requests using the given scheme to rt.
// It is rt's responsibility to simulate HTTP request semantics.
//
// RegisterProtocol can be used by other packages to provide
// implementations of protocol schemes like "ftp" or "file".
//
// If rt.RoundTrip returns [ErrSkipAltProtocol], the Transport will
// handle the [Transport.RoundTrip] itself for that one request, as if the
// protocol were not registered.
func (t *Transport) RegisterProtocol(scheme string, rt RoundTripper) {
	t.altMu.Lock()
	defer t.altMu.Unlock()
	oldMap, _ := t.altProto.Load().(map[string]RoundTripper)
	if _, exists := oldMap[scheme]; exists {
		panic("protocol " + scheme + " already registered")
	}
	newMap := maps.Clone(oldMap)
	if newMap == nil {
		newMap = make(map[string]RoundTripper)
	}
	newMap[scheme] = rt
	t.altProto.Store(newMap)
}

// CloseIdleConnections closes any connections which were previously
// connected from previous requests but are now sitting idle in
// a "keep-alive" state. It does not interrupt any connections currently
// in use.
func (t *Transport) CloseIdleConnections() {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	t.idleMu.Lock()
	m := t.idleConn
	t.idleConn = nil
	t.closeIdle = true // close newly idle connections
	t.idleLRU = connLRU{}
	t.idleMu.Unlock()
	for _, conns := range m {
		for _, pconn := range conns {
			pconn.close(errCloseIdleConns)
		}
	}
	t.connsPerHostMu.Lock()
	t.dialsInProgress.all(func(w *wantConn) {
		if w.cancelCtx != nil && !w.waiting() {
			w.cancelCtx()
		}
	})
	t.connsPerHostMu.Unlock()
	if t2 := t.h2transport; t2 != nil {
		t2.CloseIdleConnections()
	}
}

// prepareTransportCancel sets up state to convert Transport.CancelRequest into context cancelation.
func (t *Transport) prepareTransportCancel(req *Request, origCancel context.CancelCauseFunc) context.CancelCauseFunc {
	// Historically, RoundTrip has not modified the Request in any way.
	// We could avoid the need to keep a map of all in-flight requests by adding
	// a field to the Request containing its cancel func, and setting that field
	// while the request is in-flight. Callers aren't supposed to reuse a Request
	// until after the response body is closed, so this wouldn't violate any
	// concurrency guarantees.
	cancel := func(err error) {
		origCancel(err)
		t.reqMu.Lock()
		delete(t.reqCanceler, req)
		t.reqMu.Unlock()
	}
	t.reqMu.Lock()
	if t.reqCanceler == nil {
		t.reqCanceler = make(map[*Request]context.CancelCauseFunc)
	}
	t.reqCanceler[req] = cancel
	t.reqMu.Unlock()
	return cancel
}

// CancelRequest cancels an in-flight request by closing its connection.
// CancelRequest should only be called after [Transport.RoundTrip] has returned.
//
// Deprecated: Use [Request.WithContext] to create a request with a
// cancelable context instead. CancelRequest cannot cancel HTTP/2
// requests. This may become a no-op in a future release of Go.
func (t *Transport) CancelRequest(req *Request) {
	t.reqMu.Lock()
	cancel := t.reqCanceler[req]
	t.reqMu.Unlock()
	if cancel != nil {
		cancel(errRequestCanceled)
	}
}

//
// Private implementation past this poi
"""




```