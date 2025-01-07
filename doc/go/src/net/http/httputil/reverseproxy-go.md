Response:
Let's break down the thought process for analyzing this Go code snippet for `reverseproxy.go`.

**1. Understanding the Core Purpose:**

The initial comments and the package name (`httputil`) immediately suggest this code deals with HTTP utilities, specifically something related to proxying. The name `ReverseProxy` is a strong indicator of its core function. The comments about "taking an incoming request and sending it to another server" confirm this.

**2. Identifying Key Structures:**

I look for the primary data structures. `ReverseProxy` struct is central, as it holds the configuration for the proxy. `ProxyRequest` is another crucial struct, representing the inbound and outbound requests, and how they can be manipulated.

**3. Analyzing the `ReverseProxy` Struct Fields:**

I examine each field in `ReverseProxy` and what it controls:

*   `Rewrite`:  A function to completely customize the outbound request.
*   `Director`:  A simpler function to modify the outbound request, focused on setting the destination.
*   `Transport`:  The mechanism for sending the request (defaults to `http.DefaultTransport`).
*   `FlushInterval`:  Controls how often the response is flushed to the client, important for streaming.
*   `ErrorLog`:  For logging errors.
*   `BufferPool`:  For efficient memory management during response copying.
*   `ModifyResponse`:  A hook to alter the backend response before sending it to the client.
*   `ErrorHandler`:  Handles errors during proxying.

The comments associated with each field provide vital clues about their purpose and usage. The "At most one of Rewrite or Director may be set" comment is an important constraint.

**4. Analyzing the `ProxyRequest` Struct and its Methods:**

I examine `ProxyRequest`:

*   `In`:  The original client request (read-only for `Rewrite`).
*   `Out`: The request to be sent to the backend (modifiable).

Then I look at the methods associated with `ProxyRequest`:

*   `SetURL`:  A convenience method for setting the destination URL. The comment explicitly notes how it rewrites the `Host` header by default and how to override that.
*   `SetXForwarded`:  Handles setting `X-Forwarded-*` headers. The comments explain its behavior and how to combine it with existing headers.

**5. Examining Key Functions:**

I focus on the main functions:

*   `NewSingleHostReverseProxy`:  A convenient way to create a simple reverse proxy for a single backend. I note how it uses the `Director` internally. The comparison with using `ReverseProxy` directly with `Rewrite` is important.
*   `ServeHTTP`: This is the core handler function. I would trace the logic: cloning the request, applying `Director` or `Rewrite`, removing hop-by-hop headers, making the backend request using `Transport.RoundTrip`, handling 1xx and 101 responses, copying headers and body, and handling trailers. The error handling paths are also important.
*   `rewriteRequestURL`, `copyHeader`, `removeHopByHopHeaders`, `flushInterval`, `copyResponse`, `copyBuffer`, `handleUpgradeResponse`: These are helper functions that perform specific tasks within `ServeHTTP`. I would read the comments and code to understand their individual responsibilities.

**6. Identifying Go Language Features:**

As I read the code, I look for specific Go features being used:

*   **Structs and Methods:**  Clearly used for organizing data and behavior (`ReverseProxy`, `ProxyRequest`).
*   **Interfaces:** `http.Handler`, `http.RoundTripper`, `BufferPool`, `io.Reader`, `io.Writer`, `io.ReadWriteCloser`. This shows the use of abstraction and polymorphism.
*   **Closures (Anonymous Functions):** Used for `Director` and `Rewrite` allowing custom logic.
*   **Goroutines and Concurrency:**  Used in `ServeHTTP` to handle `CloseNotifier` and in `handleUpgradeResponse` for bidirectional copying.
*   **Context:** Used for request cancellation and passing request-scoped values.
*   **`net/url`:** For manipulating URLs.
*   **`net/http`:** The core HTTP package.
*   **Error Handling:** Using `error` interface and checking for `nil`.
*   **`sync` package:** For mutexes to protect shared resources.
*   **`time` package:** For timeouts and delays.
*   **Type Assertions:**  Used in `handleUpgradeResponse` to check if `res.Body` is `io.ReadWriteCloser`.

**7. Inferring and Providing Examples:**

Based on the function names and the way the structs are used, I can infer common use cases and provide illustrative Go code examples. For instance, showing how to create a basic proxy using `NewSingleHostReverseProxy` and how to customize it with `Rewrite`.

**8. Identifying Potential Pitfalls:**

By understanding how the proxy works, I can anticipate common mistakes users might make:

*   Forgetting to set either `Director` or `Rewrite`.
*   Misunderstanding how `SetURL` affects the `Host` header.
*   Incorrectly handling `X-Forwarded-*` headers.
*   Not understanding the implications of `FlushInterval`.
*   Errors during upgrade protocols.

**9. Structuring the Answer:**

Finally, I organize the information into a clear and structured answer, addressing each part of the prompt:

*   Listing the functionalities.
*   Providing Go code examples for inferred use cases.
*   Explaining the code's implementation of Go features.
*   Providing input and output examples for code reasoning.
*   Detailing command-line argument handling (if applicable - in this case, not directly).
*   Highlighting common user mistakes.

This systematic approach helps in dissecting the code, understanding its purpose and implementation details, and providing a comprehensive and accurate answer. The focus is on understanding the *what*, *how*, and *why* of the code.
这段代码是 Go 语言标准库 `net/http/httputil` 包中 `reverseproxy.go` 文件的一部分，它实现了 **HTTP 反向代理**的功能。

以下是它的主要功能：

1. **接收客户端请求**: `ReverseProxy` 实现了 `http.Handler` 接口，可以接收客户端发送的 HTTP 请求。
2. **修改请求**:
    *   **`Director` 函数**: 允许用户提供一个函数，该函数可以修改即将发送到后端服务器的请求。这通常用于更改请求的目标 URL、添加或删除头部等。
    *   **`Rewrite` 函数**: 提供更灵活的请求修改方式。它接收一个 `ProxyRequest` 结构体，包含原始请求 (`In`) 和即将发送的请求 (`Out`)。用户可以修改或替换 `Out` 请求。
    *   **`SetURL` 方法**:  `ProxyRequest` 结构体的方法，用于方便地设置出站请求的目标 URL（scheme、host 和 path）。
    *   **`SetXForwarded` 方法**: `ProxyRequest` 结构体的方法，用于设置 `X-Forwarded-For`、`X-Forwarded-Host` 和 `X-Forwarded-Proto` 头部，以向后端服务器传递客户端的原始信息。
3. **转发请求到后端服务器**: 使用 `Transport` 字段指定的 `http.RoundTripper`（默认为 `http.DefaultTransport`）将修改后的请求发送到后端服务器。
4. **处理后端服务器的响应**: 接收后端服务器返回的 HTTP 响应。
5. **修改响应**: `ModifyResponse` 函数允许用户修改从后端服务器接收到的响应。例如，可以修改响应头或响应体。
6. **将响应返回给客户端**: 将后端服务器的响应（可能经过修改）转发回客户端。
7. **处理 WebSocket 和其他协议升级**:  能够处理后端服务器返回的 `101 Switching Protocols` 响应，实现 WebSocket 等协议的代理。
8. **可选的错误处理**: `ErrorHandler` 函数允许用户自定义处理代理过程中发生的错误，例如连接后端服务器失败。
9. **日志记录**:  可以使用 `ErrorLog` 字段指定自定义的日志记录器，用于记录代理过程中发生的错误。
10. **缓冲区池**:  可以使用 `BufferPool` 字段指定一个缓冲区池，以提高复制响应体的效率。
11. **刷新间隔控制**: `FlushInterval` 字段允许控制将响应体刷新到客户端的频率，用于支持流式响应。
12. **移除 Hop-by-hop 头部**:  自动移除 HTTP 的 hop-by-hop 头部（如 `Connection`、`Keep-Alive` 等），以避免代理服务器影响客户端和后端服务器之间的连接。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 **HTTP 反向代理** 功能。反向代理作为中间层，接收客户端的请求，并将这些请求转发到后端的多个服务器上。对于客户端来说，反向代理就像是唯一的服务器。

**Go 代码举例说明:**

以下是一个使用 `httputil.ReverseProxy` 的简单示例，它将所有请求代理到 `http://example.com`：

```go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	targetURL, err := url.Parse("http://example.com")
	if err != nil {
		log.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	log.Println("启动反向代理服务器，监听端口 8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
```

**假设的输入与输出 (针对上述示例):**

**输入 (客户端请求):**

```
GET /api/users HTTP/1.1
Host: localhost:8080
User-Agent: curl/7.64.1
Accept: */*
```

**输出 (发送到 `example.com` 的请求):**

```
GET /api/users HTTP/1.1
Host: example.com
User-Agent: curl/7.64.1
Accept: */*
```

**输出 (从 `example.com` 返回的响应，假设 example.com 返回以下内容):**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 25

[
  {"id": 1, "name": "User"}
]
```

**输出 (返回给客户端的响应):**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 25

[
  {"id": 1, "name": "User"}
]
```

**涉及代码推理的例子 (使用 `Rewrite` 函数):**

假设我们需要在转发请求前，将所有请求的路径都加上 `/prefix` 前缀。

```go
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	targetURL, err := url.Parse("http://example.com")
	if err != nil {
		log.Fatal(err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(targetURL)
			r.Out.URL.Path = "/prefix" + r.Out.URL.Path
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	log.Println("启动反向代理服务器，监听端口 8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
```

**假设的输入与输出 (针对使用 `Rewrite` 的示例):**

**输入 (客户端请求):**

```
GET /api/data HTTP/1.1
Host: localhost:8080
```

**输出 (发送到 `example.com` 的请求):**

```
GET /prefix/api/data HTTP/1.1
Host: example.com
```

**涉及命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。通常，使用 `ReverseProxy` 的应用程序会使用 Go 的 `flag` 包或其他库来解析命令行参数，并根据这些参数配置 `ReverseProxy` 的行为，例如指定后端服务器的地址。

**使用者易犯错的点:**

1. **混淆 `Director` 和 `Rewrite` 的使用**: `ReverseProxy` 的 `Director` 和 `Rewrite` 字段只能设置其中一个，如果同时设置或都不设置，会导致错误。
    ```go
    // 错误示例：同时设置 Director 和 Rewrite
    proxy := &httputil.ReverseProxy{
        Director: func(req *http.Request) {
            req.URL.Host = "backend1.example.com"
        },
        Rewrite: func(r *httputil.ProxyRequest) {
            r.SetURL(&url.URL{Scheme: "http", Host: "backend2.example.com"})
        },
    }
    ```

2. **错误地修改 `ProxyRequest.In`**: `Rewrite` 函数的文档明确指出不应修改 `ProxyRequest.In`，因为它代表了原始的客户端请求。修改它可能会导致不可预测的行为。
    ```go
    // 错误示例：修改 ProxyRequest.In
    proxy := &httputil.ReverseProxy{
        Rewrite: func(r *httputil.ProxyRequest) {
            r.In.Header.Set("X-Hacked", "true") // 不应该修改 r.In
            r.SetURL(targetURL)
        },
    }
    ```

3. **忽略 `SetURL` 对 `Host` 头部的影响**: 默认情况下，`ProxyRequest.SetURL` 会将出站请求的 `Host` 头部设置为目标 URL 的主机名。如果需要保留原始请求的 `Host` 头部，需要手动设置：
    ```go
    // 需要保留原始 Host 头部
    proxy := &httputil.ReverseProxy{
        Rewrite: func(r *httputil.ProxyRequest) {
            r.SetURL(targetURL)
            r.Out.Host = r.In.Host // 保留原始 Host 头部
        },
    }
    ```

4. **不理解 hop-by-hop 头部**:  用户可能会尝试在 `Director` 或 `Rewrite` 中添加 hop-by-hop 头部，但 `ReverseProxy` 会自动移除这些头部，这可能导致他们的意图无法实现。如果需要添加自定义头部，确保它们不是 hop-by-hop 头部。

5. **在 `ModifyResponse` 中不正确地处理响应体**:  `ModifyResponse` 函数接收到的 `http.Response` 其 `Body` 是一个 `io.ReadCloser`，需要正确读取和关闭。如果在修改响应体后没有正确处理，可能会导致资源泄漏或错误。

理解 `ReverseProxy` 的工作原理和各个配置项的作用，可以有效地避免这些常见的错误。

Prompt: 
```
这是路径为go/src/net/http/httputil/reverseproxy.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP reverse proxy handler

package httputil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/internal/ascii"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

// A ProxyRequest contains a request to be rewritten by a [ReverseProxy].
type ProxyRequest struct {
	// In is the request received by the proxy.
	// The Rewrite function must not modify In.
	In *http.Request

	// Out is the request which will be sent by the proxy.
	// The Rewrite function may modify or replace this request.
	// Hop-by-hop headers are removed from this request
	// before Rewrite is called.
	Out *http.Request
}

// SetURL routes the outbound request to the scheme, host, and base path
// provided in target. If the target's path is "/base" and the incoming
// request was for "/dir", the target request will be for "/base/dir".
//
// SetURL rewrites the outbound Host header to match the target's host.
// To preserve the inbound request's Host header (the default behavior
// of [NewSingleHostReverseProxy]):
//
//	rewriteFunc := func(r *httputil.ProxyRequest) {
//		r.SetURL(url)
//		r.Out.Host = r.In.Host
//	}
func (r *ProxyRequest) SetURL(target *url.URL) {
	rewriteRequestURL(r.Out, target)
	r.Out.Host = ""
}

// SetXForwarded sets the X-Forwarded-For, X-Forwarded-Host, and
// X-Forwarded-Proto headers of the outbound request.
//
//   - The X-Forwarded-For header is set to the client IP address.
//   - The X-Forwarded-Host header is set to the host name requested
//     by the client.
//   - The X-Forwarded-Proto header is set to "http" or "https", depending
//     on whether the inbound request was made on a TLS-enabled connection.
//
// If the outbound request contains an existing X-Forwarded-For header,
// SetXForwarded appends the client IP address to it. To append to the
// inbound request's X-Forwarded-For header (the default behavior of
// [ReverseProxy] when using a Director function), copy the header
// from the inbound request before calling SetXForwarded:
//
//	rewriteFunc := func(r *httputil.ProxyRequest) {
//		r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
//		r.SetXForwarded()
//	}
func (r *ProxyRequest) SetXForwarded() {
	clientIP, _, err := net.SplitHostPort(r.In.RemoteAddr)
	if err == nil {
		prior := r.Out.Header["X-Forwarded-For"]
		if len(prior) > 0 {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		r.Out.Header.Set("X-Forwarded-For", clientIP)
	} else {
		r.Out.Header.Del("X-Forwarded-For")
	}
	r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
	if r.In.TLS == nil {
		r.Out.Header.Set("X-Forwarded-Proto", "http")
	} else {
		r.Out.Header.Set("X-Forwarded-Proto", "https")
	}
}

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
//
// 1xx responses are forwarded to the client if the underlying
// transport supports ClientTrace.Got1xxResponse.
type ReverseProxy struct {
	// Rewrite must be a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	// Rewrite must not access the provided ProxyRequest
	// or its contents after returning.
	//
	// The Forwarded, X-Forwarded, X-Forwarded-Host,
	// and X-Forwarded-Proto headers are removed from the
	// outbound request before Rewrite is called. See also
	// the ProxyRequest.SetXForwarded method.
	//
	// Unparsable query parameters are removed from the
	// outbound request before Rewrite is called.
	// The Rewrite function may copy the inbound URL's
	// RawQuery to the outbound URL to preserve the original
	// parameter string. Note that this can lead to security
	// issues if the proxy's interpretation of query parameters
	// does not match that of the downstream server.
	//
	// At most one of Rewrite or Director may be set.
	Rewrite func(*ProxyRequest)

	// Director is a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	// Director must not access the provided Request
	// after returning.
	//
	// By default, the X-Forwarded-For header is set to the
	// value of the client IP address. If an X-Forwarded-For
	// header already exists, the client IP is appended to the
	// existing values. As a special case, if the header
	// exists in the Request.Header map but has a nil value
	// (such as when set by the Director func), the X-Forwarded-For
	// header is not modified.
	//
	// To prevent IP spoofing, be sure to delete any pre-existing
	// X-Forwarded-For header coming from the client or
	// an untrusted proxy.
	//
	// Hop-by-hop headers are removed from the request after
	// Director returns, which can remove headers added by
	// Director. Use a Rewrite function instead to ensure
	// modifications to the request are preserved.
	//
	// Unparsable query parameters are removed from the outbound
	// request if Request.Form is set after Director returns.
	//
	// At most one of Rewrite or Director may be set.
	Director func(*http.Request)

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	// A negative value means to flush immediately
	// after each write to the client.
	// The FlushInterval is ignored when ReverseProxy
	// recognizes a response as a streaming response, or
	// if its ContentLength is -1; for such responses, writes
	// are flushed to the client immediately.
	FlushInterval time.Duration

	// ErrorLog specifies an optional logger for errors
	// that occur when attempting to proxy the request.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	// BufferPool optionally specifies a buffer pool to
	// get byte slices for use by io.CopyBuffer when
	// copying HTTP response bodies.
	BufferPool BufferPool

	// ModifyResponse is an optional function that modifies the
	// Response from the backend. It is called if the backend
	// returns a response at all, with any HTTP status code.
	// If the backend is unreachable, the optional ErrorHandler is
	// called without any call to ModifyResponse.
	//
	// If ModifyResponse returns an error, ErrorHandler is called
	// with its error value. If ErrorHandler is nil, its default
	// implementation is used.
	ModifyResponse func(*http.Response) error

	// ErrorHandler is an optional function that handles errors
	// reaching the backend or errors from ModifyResponse.
	//
	// If nil, the default is to log the provided error and return
	// a 502 Status Bad Gateway response.
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
}

// A BufferPool is an interface for getting and returning temporary
// byte slices for use by [io.CopyBuffer].
type BufferPool interface {
	Get() []byte
	Put([]byte)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

// NewSingleHostReverseProxy returns a new [ReverseProxy] that routes
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir.
//
// NewSingleHostReverseProxy does not rewrite the Host header.
//
// To customize the ReverseProxy behavior beyond what
// NewSingleHostReverseProxy provides, use ReverseProxy directly
// with a Rewrite function. The ProxyRequest SetURL method
// may be used to route the outbound request. (Note that SetURL,
// unlike NewSingleHostReverseProxy, rewrites the Host header
// of the outbound request by default.)
//
//	proxy := &ReverseProxy{
//		Rewrite: func(r *ProxyRequest) {
//			r.SetURL(target)
//			r.Out.Host = r.In.Host // if desired
//		},
//	}
func NewSingleHostReverseProxy(target *url.URL) *ReverseProxy {
	director := func(req *http.Request) {
		rewriteRequestURL(req, target)
	}
	return &ReverseProxy{Director: director}
}

func rewriteRequestURL(req *http.Request, target *url.URL) {
	targetQuery := target.RawQuery
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
	if targetQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = targetQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func (p *ReverseProxy) defaultErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	p.logf("http: proxy error: %v", err)
	rw.WriteHeader(http.StatusBadGateway)
}

func (p *ReverseProxy) getErrorHandler() func(http.ResponseWriter, *http.Request, error) {
	if p.ErrorHandler != nil {
		return p.ErrorHandler
	}
	return p.defaultErrorHandler
}

// modifyResponse conditionally runs the optional ModifyResponse hook
// and reports whether the request should proceed.
func (p *ReverseProxy) modifyResponse(rw http.ResponseWriter, res *http.Response, req *http.Request) bool {
	if p.ModifyResponse == nil {
		return true
	}
	if err := p.ModifyResponse(res); err != nil {
		res.Body.Close()
		p.getErrorHandler()(rw, req, err)
		return false
	}
	return true
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	ctx := req.Context()
	if ctx.Done() != nil {
		// CloseNotifier predates context.Context, and has been
		// entirely superseded by it. If the request contains
		// a Context that carries a cancellation signal, don't
		// bother spinning up a goroutine to watch the CloseNotify
		// channel (if any).
		//
		// If the request Context has a nil Done channel (which
		// means it is either context.Background, or a custom
		// Context implementation with no cancellation signal),
		// then consult the CloseNotifier if available.
	} else if cn, ok := rw.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	outreq := req.Clone(ctx)
	if req.ContentLength == 0 {
		outreq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}
	if outreq.Body != nil {
		// Reading from the request body after returning from a handler is not
		// allowed, and the RoundTrip goroutine that reads the Body can outlive
		// this handler. This can lead to a crash if the handler panics (see
		// Issue 46866). Although calling Close doesn't guarantee there isn't
		// any Read in flight after the handle returns, in practice it's safe to
		// read after closing it.
		defer outreq.Body.Close()
	}
	if outreq.Header == nil {
		outreq.Header = make(http.Header) // Issue 33142: historical behavior was to always allocate
	}

	if (p.Director != nil) == (p.Rewrite != nil) {
		p.getErrorHandler()(rw, req, errors.New("ReverseProxy must have exactly one of Director or Rewrite set"))
		return
	}

	if p.Director != nil {
		p.Director(outreq)
		if outreq.Form != nil {
			outreq.URL.RawQuery = cleanQueryParams(outreq.URL.RawQuery)
		}
	}
	outreq.Close = false

	reqUpType := upgradeType(outreq.Header)
	if !ascii.IsPrint(reqUpType) {
		p.getErrorHandler()(rw, req, fmt.Errorf("client tried to switch to invalid protocol %q", reqUpType))
		return
	}
	removeHopByHopHeaders(outreq.Header)

	// Issue 21096: tell backend applications that care about trailer support
	// that we support trailers. (We do, but we don't go out of our way to
	// advertise that unless the incoming client request thought it was worth
	// mentioning.) Note that we look at req.Header, not outreq.Header, since
	// the latter has passed through removeHopByHopHeaders.
	if httpguts.HeaderValuesContainsToken(req.Header["Te"], "trailers") {
		outreq.Header.Set("Te", "trailers")
	}

	// After stripping all the hop-by-hop connection headers above, add back any
	// necessary for protocol upgrades, such as for websockets.
	if reqUpType != "" {
		outreq.Header.Set("Connection", "Upgrade")
		outreq.Header.Set("Upgrade", reqUpType)
	}

	if p.Rewrite != nil {
		// Strip client-provided forwarding headers.
		// The Rewrite func may use SetXForwarded to set new values
		// for these or copy the previous values from the inbound request.
		outreq.Header.Del("Forwarded")
		outreq.Header.Del("X-Forwarded-For")
		outreq.Header.Del("X-Forwarded-Host")
		outreq.Header.Del("X-Forwarded-Proto")

		// Remove unparsable query parameters from the outbound request.
		outreq.URL.RawQuery = cleanQueryParams(outreq.URL.RawQuery)

		pr := &ProxyRequest{
			In:  req,
			Out: outreq,
		}
		p.Rewrite(pr)
		outreq = pr.Out
	} else {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			// If we aren't the first proxy retain prior
			// X-Forwarded-For information as a comma+space
			// separated list and fold multiple headers into one.
			prior, ok := outreq.Header["X-Forwarded-For"]
			omit := ok && prior == nil // Issue 38079: nil now means don't populate the header
			if len(prior) > 0 {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			if !omit {
				outreq.Header.Set("X-Forwarded-For", clientIP)
			}
		}
	}

	if _, ok := outreq.Header["User-Agent"]; !ok {
		// If the outbound request doesn't have a User-Agent header set,
		// don't send the default Go HTTP client User-Agent.
		outreq.Header.Set("User-Agent", "")
	}

	var (
		roundTripMutex sync.Mutex
		roundTripDone  bool
	)
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			roundTripMutex.Lock()
			defer roundTripMutex.Unlock()
			if roundTripDone {
				// If RoundTrip has returned, don't try to further modify
				// the ResponseWriter's header map.
				return nil
			}
			h := rw.Header()
			copyHeader(h, http.Header(header))
			rw.WriteHeader(code)

			// Clear headers, it's not automatically done by ResponseWriter.WriteHeader() for 1xx responses
			clear(h)
			return nil
		},
	}
	outreq = outreq.WithContext(httptrace.WithClientTrace(outreq.Context(), trace))

	res, err := transport.RoundTrip(outreq)
	roundTripMutex.Lock()
	roundTripDone = true
	roundTripMutex.Unlock()
	if err != nil {
		p.getErrorHandler()(rw, outreq, err)
		return
	}

	// Deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	if res.StatusCode == http.StatusSwitchingProtocols {
		if !p.modifyResponse(rw, res, outreq) {
			return
		}
		p.handleUpgradeResponse(rw, outreq, res)
		return
	}

	removeHopByHopHeaders(res.Header)

	if !p.modifyResponse(rw, res, outreq) {
		return
	}

	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)

	err = p.copyResponse(rw, res.Body, p.flushInterval(res))
	if err != nil {
		defer res.Body.Close()
		// Since we're streaming the response, if we run into an error all we can do
		// is abort the request. Issue 23643: ReverseProxy should use ErrAbortHandler
		// on read error while copying body.
		if !shouldPanicOnCopyError(req) {
			p.logf("suppressing panic for copyResponse error in test; copy error: %v", err)
			return
		}
		panic(http.ErrAbortHandler)
	}
	res.Body.Close() // close now, instead of defer, to populate res.Trailer

	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		http.NewResponseController(rw).Flush()
	}

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer)
		return
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
}

var inOurTests bool // whether we're in our own tests

// shouldPanicOnCopyError reports whether the reverse proxy should
// panic with http.ErrAbortHandler. This is the right thing to do by
// default, but Go 1.10 and earlier did not, so existing unit tests
// weren't expecting panics. Only panic in our own tests, or when
// running under the HTTP server.
func shouldPanicOnCopyError(req *http.Request) bool {
	if inOurTests {
		// Our tests know to handle this panic.
		return true
	}
	if req.Context().Value(http.ServerContextKey) != nil {
		// We seem to be running under an HTTP server, so
		// it'll recover the panic.
		return true
	}
	// Otherwise act like Go 1.10 and earlier to not break
	// existing tests.
	return false
}

// removeHopByHopHeaders removes hop-by-hop headers.
func removeHopByHopHeaders(h http.Header) {
	// RFC 7230, section 6.1: Remove headers listed in the "Connection" header.
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
	// RFC 2616, section 13.5.1: Remove a set of known hop-by-hop headers.
	// This behavior is superseded by the RFC 7230 Connection header, but
	// preserve it for backwards compatibility.
	for _, f := range hopHeaders {
		h.Del(f)
	}
}

// flushInterval returns the p.FlushInterval value, conditionally
// overriding its value for a specific request/response.
func (p *ReverseProxy) flushInterval(res *http.Response) time.Duration {
	resCT := res.Header.Get("Content-Type")

	// For Server-Sent Events responses, flush immediately.
	// The MIME type is defined in https://www.w3.org/TR/eventsource/#text-event-stream
	if baseCT, _, _ := mime.ParseMediaType(resCT); baseCT == "text/event-stream" {
		return -1 // negative means immediately
	}

	// We might have the case of streaming for which Content-Length might be unset.
	if res.ContentLength == -1 {
		return -1
	}

	return p.FlushInterval
}

func (p *ReverseProxy) copyResponse(dst http.ResponseWriter, src io.Reader, flushInterval time.Duration) error {
	var w io.Writer = dst

	if flushInterval != 0 {
		mlw := &maxLatencyWriter{
			dst:     dst,
			flush:   http.NewResponseController(dst).Flush,
			latency: flushInterval,
		}
		defer mlw.stop()

		// set up initial timer so headers get flushed even if body writes are delayed
		mlw.flushPending = true
		mlw.t = time.AfterFunc(flushInterval, mlw.delayedFlush)

		w = mlw
	}

	var buf []byte
	if p.BufferPool != nil {
		buf = p.BufferPool.Get()
		defer p.BufferPool.Put(buf)
	}
	_, err := p.copyBuffer(w, src, buf)
	return err
}

// copyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
func (p *ReverseProxy) copyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			p.logf("httputil: ReverseProxy read error during body copy: %v", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

func (p *ReverseProxy) logf(format string, args ...any) {
	if p.ErrorLog != nil {
		p.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

type maxLatencyWriter struct {
	dst     io.Writer
	flush   func() error
	latency time.Duration // non-zero; negative means to flush immediately

	mu           sync.Mutex // protects t, flushPending, and dst.Flush
	t            *time.Timer
	flushPending bool
}

func (m *maxLatencyWriter) Write(p []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err = m.dst.Write(p)
	if m.latency < 0 {
		m.flush()
		return
	}
	if m.flushPending {
		return
	}
	if m.t == nil {
		m.t = time.AfterFunc(m.latency, m.delayedFlush)
	} else {
		m.t.Reset(m.latency)
	}
	m.flushPending = true
	return
}

func (m *maxLatencyWriter) delayedFlush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.flushPending { // if stop was called but AfterFunc already started this goroutine
		return
	}
	m.flush()
	m.flushPending = false
}

func (m *maxLatencyWriter) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushPending = false
	if m.t != nil {
		m.t.Stop()
	}
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (p *ReverseProxy) handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response) {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !ascii.IsPrint(resUpType) { // We know reqUpType is ASCII, it's checked by the caller.
		p.getErrorHandler()(rw, req, fmt.Errorf("backend tried to switch to invalid protocol %q", resUpType))
		return
	}
	if !ascii.EqualFold(reqUpType, resUpType) {
		p.getErrorHandler()(rw, req, fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType))
		return
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		p.getErrorHandler()(rw, req, fmt.Errorf("internal error: 101 switching protocols response with non-writable body"))
		return
	}

	rc := http.NewResponseController(rw)
	conn, brw, hijackErr := rc.Hijack()
	if errors.Is(hijackErr, http.ErrNotSupported) {
		p.getErrorHandler()(rw, req, fmt.Errorf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw))
		return
	}

	backConnCloseCh := make(chan bool)
	go func() {
		// Ensure that the cancellation of a request closes the backend.
		// See issue https://golang.org/issue/35559.
		select {
		case <-req.Context().Done():
		case <-backConnCloseCh:
		}
		backConn.Close()
	}()
	defer close(backConnCloseCh)

	if hijackErr != nil {
		p.getErrorHandler()(rw, req, fmt.Errorf("Hijack failed on protocol switch: %v", hijackErr))
		return
	}
	defer conn.Close()

	copyHeader(rw.Header(), res.Header)

	res.Header = rw.Header()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		p.getErrorHandler()(rw, req, fmt.Errorf("response write: %v", err))
		return
	}
	if err := brw.Flush(); err != nil {
		p.getErrorHandler()(rw, req, fmt.Errorf("response flush: %v", err))
		return
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc
}

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	_, err := io.Copy(c.user, c.backend)
	errc <- err
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	_, err := io.Copy(c.backend, c.user)
	errc <- err
}

func cleanQueryParams(s string) string {
	reencode := func(s string) string {
		v, _ := url.ParseQuery(s)
		return v.Encode()
	}
	for i := 0; i < len(s); {
		switch s[i] {
		case ';':
			return reencode(s)
		case '%':
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				return reencode(s)
			}
			i += 3
		default:
			i++
		}
	}
	return s
}

func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

"""



```