Response:
The user is asking for a summary of the functionalities implemented in the provided Go code snippet from `go/src/net/http/server.go`. This is the third part of a four-part code snippet. I need to analyze the code and describe its main responsibilities.

Here's a breakdown of the code and its functionalities:

1. **Handling of individual HTTP requests within a connection:** The code manages the processing of a single HTTP request on a persistent connection (`conn`). This involves checking for "Expect: 100-continue" headers, running the request handler, and managing connection reuse.
2. **Support for unencrypted HTTP/2:**  The code includes logic to detect and handle unencrypted HTTP/2 connections (h2c).
3. **Handling "Expect: 100-continue":** The server can respond to "Expect: 100-continue" requests, either by sending a 100 Continue response or a 417 Expectation Failed.
4. **Connection hijacking:** The `Hijack` method allows the handler to take control of the underlying TCP connection.
5. **CloseNotify mechanism:** The `CloseNotify` method provides a channel that is closed when the client closes the connection.
6. **Utility functions for request body handling:** Functions like `registerOnHitEOF` and `requestBodyRemains` help manage the request body.
7. **Implementation of `HandlerFunc`:** This allows ordinary functions to be used as HTTP handlers.
8. **Helper handlers:**  The code provides standard handlers for common scenarios like `Error`, `NotFound`, `StripPrefix`, and `Redirect`.
9. **`ServeMux` implementation:** A crucial part of the code is the implementation of `ServeMux`, the HTTP request multiplexer that matches incoming requests to registered handlers based on patterns.
10. **`Server` struct and related functions:** The `Server` struct defines the configuration for an HTTP server, and functions like `Serve` and `ServeTLS` are used to start the server.
这段代码是 Go 语言 `net/http` 包中 `server.go` 文件的一部分，主要负责处理**单个 HTTP 请求的生命周期**以及**请求的多路复用 (Multiplexing)**。

以下是代码功能的归纳：

1. **处理单个 HTTP 请求:**
    *   **检查 "Expect: 100-continue" 头部:**  代码会检查请求头中是否包含 "Expect: 100-continue"。如果是，并且服务端允许发送 100 Continue 响应，则会配置 `req.Body` 以便在读取请求体时发送 100 Continue。如果 "Expect" 头部存在但不是 "100-continue"，则会发送 "417 Expectation Failed" 错误。
    *   **执行请求处理函数 (`serverHandler.ServeHTTP`)：** 这是 HTTP 服务器的核心，它调用与请求匹配的处理器来生成响应。
    *   **管理请求上下文 (Context)：**  通过 `w.cancelCtx()` 取消与请求关联的上下文。
    *   **处理连接劫持 (Hijacking)：**  如果请求处理器调用了 `Hijack()` 方法，则会跳过后续的响应处理。
    *   **完成请求处理 (`w.finishRequest`)：**  执行请求完成后的清理工作。
    *   **管理连接的 Keep-Alive 状态：** 根据 `shouldReuseConnection()` 的返回值决定是否复用连接。如果不复用，则会关闭写连接。
    *   **设置连接的读写超时时间：**  在连接空闲时设置读超时时间，防止资源浪费。
    *   **等待下一个请求：**  通过 `c.bufr.Peek(4)` 检查连接上是否有新的请求到达。

2. **支持未加密的 HTTP/2 (`maybeServeUnencryptedHTTP2`):**
    *   代码尝试检测传入的连接是否为未加密的 HTTP/2 连接 (h2c)。
    *   它会检查连接的前导字节是否为 "PRI \* HTTP/2.0\r\n\r\nSM\r\n\r\n"。
    *   如果是，则创建一个 `unencryptedHTTP2Request` 处理器并调用 `TLSNextProto` 中注册的 h2c 处理函数。

3. **处理 "Expectation Failed" (`sendExpectationFailed`):**  当收到无法满足的 "Expect" 头部时，会发送 "417 Expectation Failed" 响应。

4. **连接劫持 (`Hijack`):**
    *   允许请求处理器接管底层的 TCP 连接。
    *   在 `ServeHTTP` 完成后调用 `Hijack` 会导致 panic。
    *   释放用于写响应的 `bufio.Writer`。

5. **关闭通知 (`CloseNotify`):**
    *   返回一个通道，当客户端关闭连接时，该通道将被关闭。
    *   在 `ServeHTTP` 完成后调用 `CloseNotify` 会导致 panic。

6. **请求体处理辅助函数 (`registerOnHitEOF`, `requestBodyRemains`):**
    *   `registerOnHitEOF` 用于注册一个在请求体读取到 EOF 时执行的回调函数。
    *   `requestBodyRemains` 用于判断请求体是否还有剩余数据未读取。

7. **`HandlerFunc` 类型:**
    *   允许将普通的函数转换为 `Handler` 接口的实现。

8. **辅助处理器 (`Error`, `NotFound`, `NotFoundHandler`, `StripPrefix`, `Redirect`, `RedirectHandler`):**
    *   提供了一些常用的 HTTP 处理器，例如发送错误响应、404 页面、剥离路径前缀和重定向等。

9. **请求多路复用器 (`ServeMux`):**
    *   `ServeMux` 是 HTTP 请求多路复用器的核心实现。
    *   **模式匹配 (Pattern Matching):**  它根据注册的模式 (patterns) 匹配传入的请求 URL。模式可以包含方法、主机和路径，并支持通配符。
    *   **优先级 (Precedence):**  如果多个模式匹配同一个请求，`ServeMux` 会选择最具体的模式。
    *   **尾部斜杠重定向 (Trailing-slash redirection):**  如果请求的路径与注册的目录模式（以斜杠结尾或包含 "..." 通配符）匹配，但缺少尾部斜杠，`ServeMux` 会自动重定向到带有尾部斜杠的 URL。
    *   **请求清理 (Request sanitizing):**  `ServeMux` 会清理请求路径和 Host 头部，例如去除端口号、处理 "." 和 ".." 段以及重复的斜杠。
    *   **注册处理器 (`Handle`, `HandleFunc`):**  提供方法来注册指定模式的处理器。
    *   **查找处理器 (`Handler`, `findHandler`, `matchOrRedirect`):**  根据请求信息查找匹配的处理器。
    *   **处理请求 (`ServeHTTP`):**  将请求分发到匹配的处理器进行处理。

10. **HTTP 服务器结构体 (`Server`) 和相关函数 (`Serve`, `ServeTLS`):**
    *   `Server` 结构体定义了 HTTP 服务器的配置，例如监听地址、处理器、超时时间等。
    *   `Serve` 函数在给定的监听器上开始接受 HTTP 连接，并使用指定的处理器处理请求。
    *   `ServeTLS` 函数类似 `Serve`，但用于处理 HTTPS 连接，需要提供证书和私钥文件。

**总结这段代码的功能：**

这段代码主要负责接收和处理 HTTP 请求。它管理着单个请求的生命周期，包括检查请求头、执行请求处理器、管理连接状态以及支持连接劫持。同时，它实现了请求的多路复用功能，能够根据预定义的模式将不同的请求路由到不同的处理器。此外，它还提供了一些辅助功能和常用的 HTTP 处理器，简化了 HTTP 服务器的开发。

Prompt: 
```
这是路径为go/src/net/http/server.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
th one that replies on the connection
				req.Body = &expectContinueReader{readCloser: req.Body, resp: w}
				w.canWriteContinue.Store(true)
			}
		} else if req.Header.get("Expect") != "" {
			w.sendExpectationFailed()
			return
		}

		c.curReq.Store(w)

		if requestBodyRemains(req.Body) {
			registerOnHitEOF(req.Body, w.conn.r.startBackgroundRead)
		} else {
			w.conn.r.startBackgroundRead()
		}

		// HTTP cannot have multiple simultaneous active requests.[*]
		// Until the server replies to this request, it can't read another,
		// so we might as well run the handler in this goroutine.
		// [*] Not strictly true: HTTP pipelining. We could let them all process
		// in parallel even if their responses need to be serialized.
		// But we're not going to implement HTTP pipelining because it
		// was never deployed in the wild and the answer is HTTP/2.
		inFlightResponse = w
		serverHandler{c.server}.ServeHTTP(w, w.req)
		inFlightResponse = nil
		w.cancelCtx()
		if c.hijacked() {
			return
		}
		w.finishRequest()
		c.rwc.SetWriteDeadline(time.Time{})
		if !w.shouldReuseConnection() {
			if w.requestBodyLimitHit || w.closedRequestBodyEarly() {
				c.closeWriteAndWait()
			}
			return
		}
		c.setState(c.rwc, StateIdle, runHooks)
		c.curReq.Store(nil)

		if !w.conn.server.doKeepAlives() {
			// We're in shutdown mode. We might've replied
			// to the user without "Connection: close" and
			// they might think they can send another
			// request, but such is life with HTTP/1.1.
			return
		}

		if d := c.server.idleTimeout(); d > 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
		} else {
			c.rwc.SetReadDeadline(time.Time{})
		}

		// Wait for the connection to become readable again before trying to
		// read the next request. This prevents a ReadHeaderTimeout or
		// ReadTimeout from starting until the first bytes of the next request
		// have been received.
		if _, err := c.bufr.Peek(4); err != nil {
			return
		}

		c.rwc.SetReadDeadline(time.Time{})
	}
}

// unencryptedHTTP2Request is an HTTP handler that initializes
// certain uninitialized fields in its *Request.
//
// It's the unencrypted version of initALPNRequest.
type unencryptedHTTP2Request struct {
	ctx context.Context
	c   net.Conn
	h   serverHandler
}

func (h unencryptedHTTP2Request) BaseContext() context.Context { return h.ctx }

func (h unencryptedHTTP2Request) ServeHTTP(rw ResponseWriter, req *Request) {
	if req.Body == nil {
		req.Body = NoBody
	}
	if req.RemoteAddr == "" {
		req.RemoteAddr = h.c.RemoteAddr().String()
	}
	h.h.ServeHTTP(rw, req)
}

// unencryptedNetConnInTLSConn is used to pass an unencrypted net.Conn to
// functions that only accept a *tls.Conn.
type unencryptedNetConnInTLSConn struct {
	net.Conn // panic on all net.Conn methods
	conn     net.Conn
}

func (c unencryptedNetConnInTLSConn) UnencryptedNetConn() net.Conn {
	return c.conn
}

func unencryptedTLSConn(c net.Conn) *tls.Conn {
	return tls.Client(unencryptedNetConnInTLSConn{conn: c}, nil)
}

// TLSNextProto key to use for unencrypted HTTP/2 connections.
// Not actually a TLS-negotiated protocol.
const nextProtoUnencryptedHTTP2 = "unencrypted_http2"

func (c *conn) maybeServeUnencryptedHTTP2(ctx context.Context) bool {
	fn, ok := c.server.TLSNextProto[nextProtoUnencryptedHTTP2]
	if !ok {
		return false
	}
	hasPreface := func(c *conn, preface []byte) bool {
		c.r.setReadLimit(int64(len(preface)) - int64(c.bufr.Buffered()))
		got, err := c.bufr.Peek(len(preface))
		c.r.setInfiniteReadLimit()
		return err == nil && bytes.Equal(got, preface)
	}
	if !hasPreface(c, []byte("PRI * HTTP/2.0")) {
		return false
	}
	if !hasPreface(c, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		return false
	}
	c.setState(c.rwc, StateActive, skipHooks)
	h := unencryptedHTTP2Request{ctx, c.rwc, serverHandler{c.server}}
	fn(c.server, unencryptedTLSConn(c.rwc), h)
	return true
}

func (w *response) sendExpectationFailed() {
	// TODO(bradfitz): let ServeHTTP handlers handle
	// requests with non-standard expectation[s]? Seems
	// theoretical at best, and doesn't fit into the
	// current ServeHTTP model anyway. We'd need to
	// make the ResponseWriter an optional
	// "ExpectReplier" interface or something.
	//
	// For now we'll just obey RFC 7231 5.1.1 which says
	// "A server that receives an Expect field-value other
	// than 100-continue MAY respond with a 417 (Expectation
	// Failed) status code to indicate that the unexpected
	// expectation cannot be met."
	w.Header().Set("Connection", "close")
	w.WriteHeader(StatusExpectationFailed)
	w.finishRequest()
}

// Hijack implements the [Hijacker.Hijack] method. Our response is both a [ResponseWriter]
// and a [Hijacker].
func (w *response) Hijack() (rwc net.Conn, buf *bufio.ReadWriter, err error) {
	if w.handlerDone.Load() {
		panic("net/http: Hijack called after ServeHTTP finished")
	}
	w.disableWriteContinue()
	if w.wroteHeader {
		w.cw.flush()
	}

	c := w.conn
	c.mu.Lock()
	defer c.mu.Unlock()

	// Release the bufioWriter that writes to the chunk writer, it is not
	// used after a connection has been hijacked.
	rwc, buf, err = c.hijackLocked()
	if err == nil {
		putBufioWriter(w.w)
		w.w = nil
	}
	return rwc, buf, err
}

func (w *response) CloseNotify() <-chan bool {
	if w.handlerDone.Load() {
		panic("net/http: CloseNotify called after ServeHTTP finished")
	}
	return w.closeNotifyCh
}

func registerOnHitEOF(rc io.ReadCloser, fn func()) {
	switch v := rc.(type) {
	case *expectContinueReader:
		registerOnHitEOF(v.readCloser, fn)
	case *body:
		v.registerOnHitEOF(fn)
	default:
		panic("unexpected type " + fmt.Sprintf("%T", rc))
	}
}

// requestBodyRemains reports whether future calls to Read
// on rc might yield more data.
func requestBodyRemains(rc io.ReadCloser) bool {
	if rc == NoBody {
		return false
	}
	switch v := rc.(type) {
	case *expectContinueReader:
		return requestBodyRemains(v.readCloser)
	case *body:
		return v.bodyRemains()
	default:
		panic("unexpected type " + fmt.Sprintf("%T", rc))
	}
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// [Handler] that calls f.
type HandlerFunc func(ResponseWriter, *Request)

// ServeHTTP calls f(w, r).
func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
	f(w, r)
}

// Helper handlers

// Error replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
// The error message should be plain text.
//
// Error deletes the Content-Length header,
// sets Content-Type to “text/plain; charset=utf-8”,
// and sets X-Content-Type-Options to “nosniff”.
// This configures the header properly for the error message,
// in case the caller had set it up expecting a successful output.
func Error(w ResponseWriter, error string, code int) {
	h := w.Header()

	// Delete the Content-Length header, which might be for some other content.
	// Assuming the error string fits in the writer's buffer, we'll figure
	// out the correct Content-Length for it later.
	//
	// We don't delete Content-Encoding, because some middleware sets
	// Content-Encoding: gzip and wraps the ResponseWriter to compress on-the-fly.
	// See https://go.dev/issue/66343.
	h.Del("Content-Length")

	// There might be content type already set, but we reset it to
	// text/plain for the error message.
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}

// NotFound replies to the request with an HTTP 404 not found error.
func NotFound(w ResponseWriter, r *Request) { Error(w, "404 page not found", StatusNotFound) }

// NotFoundHandler returns a simple request handler
// that replies to each request with a “404 page not found” reply.
func NotFoundHandler() Handler { return HandlerFunc(NotFound) }

// StripPrefix returns a handler that serves HTTP requests by removing the
// given prefix from the request URL's Path (and RawPath if set) and invoking
// the handler h. StripPrefix handles a request for a path that doesn't begin
// with prefix by replying with an HTTP 404 not found error. The prefix must
// match exactly: if the prefix in the request contains escaped characters
// the reply is also an HTTP 404 not found error.
func StripPrefix(prefix string, h Handler) Handler {
	if prefix == "" {
		return h
	}
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		p := strings.TrimPrefix(r.URL.Path, prefix)
		rp := strings.TrimPrefix(r.URL.RawPath, prefix)
		if len(p) < len(r.URL.Path) && (r.URL.RawPath == "" || len(rp) < len(r.URL.RawPath)) {
			r2 := new(Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.Path = p
			r2.URL.RawPath = rp
			h.ServeHTTP(w, r2)
		} else {
			NotFound(w, r)
		}
	})
}

// Redirect replies to the request with a redirect to url,
// which may be a path relative to the request path.
//
// The provided code should be in the 3xx range and is usually
// [StatusMovedPermanently], [StatusFound] or [StatusSeeOther].
//
// If the Content-Type header has not been set, [Redirect] sets it
// to "text/html; charset=utf-8" and writes a small HTML body.
// Setting the Content-Type header to any value, including nil,
// disables that behavior.
func Redirect(w ResponseWriter, r *Request, url string, code int) {
	if u, err := urlpkg.Parse(url); err == nil {
		// If url was relative, make its path absolute by
		// combining with request path.
		// The client would probably do this for us,
		// but doing it ourselves is more reliable.
		// See RFC 7231, section 7.1.2
		if u.Scheme == "" && u.Host == "" {
			oldpath := r.URL.Path
			if oldpath == "" { // should not happen, but avoid a crash if it does
				oldpath = "/"
			}

			// no leading http://server
			if url == "" || url[0] != '/' {
				// make relative path absolute
				olddir, _ := path.Split(oldpath)
				url = olddir + url
			}

			var query string
			if i := strings.Index(url, "?"); i != -1 {
				url, query = url[:i], url[i:]
			}

			// clean up but preserve trailing slash
			trailing := strings.HasSuffix(url, "/")
			url = path.Clean(url)
			if trailing && !strings.HasSuffix(url, "/") {
				url += "/"
			}
			url += query
		}
	}

	h := w.Header()

	// RFC 7231 notes that a short HTML body is usually included in
	// the response because older user agents may not understand 301/307.
	// Do it only if the request didn't already have a Content-Type header.
	_, hadCT := h["Content-Type"]

	h.Set("Location", hexEscapeNonASCII(url))
	if !hadCT && (r.Method == "GET" || r.Method == "HEAD") {
		h.Set("Content-Type", "text/html; charset=utf-8")
	}
	w.WriteHeader(code)

	// Shouldn't send the body for POST or HEAD; that leaves GET.
	if !hadCT && r.Method == "GET" {
		body := "<a href=\"" + htmlEscape(url) + "\">" + StatusText(code) + "</a>.\n"
		fmt.Fprintln(w, body)
	}
}

var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	// "&#34;" is shorter than "&quot;".
	`"`, "&#34;",
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
	"'", "&#39;",
)

func htmlEscape(s string) string {
	return htmlReplacer.Replace(s)
}

// Redirect to a fixed URL
type redirectHandler struct {
	url  string
	code int
}

func (rh *redirectHandler) ServeHTTP(w ResponseWriter, r *Request) {
	Redirect(w, r, rh.url, rh.code)
}

// RedirectHandler returns a request handler that redirects
// each request it receives to the given url using the given
// status code.
//
// The provided code should be in the 3xx range and is usually
// [StatusMovedPermanently], [StatusFound] or [StatusSeeOther].
func RedirectHandler(url string, code int) Handler {
	return &redirectHandler{url, code}
}

// ServeMux is an HTTP request multiplexer.
// It matches the URL of each incoming request against a list of registered
// patterns and calls the handler for the pattern that
// most closely matches the URL.
//
// # Patterns
//
// Patterns can match the method, host and path of a request.
// Some examples:
//
//   - "/index.html" matches the path "/index.html" for any host and method.
//   - "GET /static/" matches a GET request whose path begins with "/static/".
//   - "example.com/" matches any request to the host "example.com".
//   - "example.com/{$}" matches requests with host "example.com" and path "/".
//   - "/b/{bucket}/o/{objectname...}" matches paths whose first segment is "b"
//     and whose third segment is "o". The name "bucket" denotes the second
//     segment and "objectname" denotes the remainder of the path.
//
// In general, a pattern looks like
//
//	[METHOD ][HOST]/[PATH]
//
// All three parts are optional; "/" is a valid pattern.
// If METHOD is present, it must be followed by at least one space or tab.
//
// Literal (that is, non-wildcard) parts of a pattern match
// the corresponding parts of a request case-sensitively.
//
// A pattern with no method matches every method. A pattern
// with the method GET matches both GET and HEAD requests.
// Otherwise, the method must match exactly.
//
// A pattern with no host matches every host.
// A pattern with a host matches URLs on that host only.
//
// A path can include wildcard segments of the form {NAME} or {NAME...}.
// For example, "/b/{bucket}/o/{objectname...}".
// The wildcard name must be a valid Go identifier.
// Wildcards must be full path segments: they must be preceded by a slash and followed by
// either a slash or the end of the string.
// For example, "/b_{bucket}" is not a valid pattern.
//
// Normally a wildcard matches only a single path segment,
// ending at the next literal slash (not %2F) in the request URL.
// But if the "..." is present, then the wildcard matches the remainder of the URL path, including slashes.
// (Therefore it is invalid for a "..." wildcard to appear anywhere but at the end of a pattern.)
// The match for a wildcard can be obtained by calling [Request.PathValue] with the wildcard's name.
// A trailing slash in a path acts as an anonymous "..." wildcard.
//
// The special wildcard {$} matches only the end of the URL.
// For example, the pattern "/{$}" matches only the path "/",
// whereas the pattern "/" matches every path.
//
// For matching, both pattern paths and incoming request paths are unescaped segment by segment.
// So, for example, the path "/a%2Fb/100%25" is treated as having two segments, "a/b" and "100%".
// The pattern "/a%2fb/" matches it, but the pattern "/a/b/" does not.
//
// # Precedence
//
// If two or more patterns match a request, then the most specific pattern takes precedence.
// A pattern P1 is more specific than P2 if P1 matches a strict subset of P2’s requests;
// that is, if P2 matches all the requests of P1 and more.
// If neither is more specific, then the patterns conflict.
// There is one exception to this rule, for backwards compatibility:
// if two patterns would otherwise conflict and one has a host while the other does not,
// then the pattern with the host takes precedence.
// If a pattern passed to [ServeMux.Handle] or [ServeMux.HandleFunc] conflicts with
// another pattern that is already registered, those functions panic.
//
// As an example of the general rule, "/images/thumbnails/" is more specific than "/images/",
// so both can be registered.
// The former matches paths beginning with "/images/thumbnails/"
// and the latter will match any other path in the "/images/" subtree.
//
// As another example, consider the patterns "GET /" and "/index.html":
// both match a GET request for "/index.html", but the former pattern
// matches all other GET and HEAD requests, while the latter matches any
// request for "/index.html" that uses a different method.
// The patterns conflict.
//
// # Trailing-slash redirection
//
// Consider a [ServeMux] with a handler for a subtree, registered using a trailing slash or "..." wildcard.
// If the ServeMux receives a request for the subtree root without a trailing slash,
// it redirects the request by adding the trailing slash.
// This behavior can be overridden with a separate registration for the path without
// the trailing slash or "..." wildcard. For example, registering "/images/" causes ServeMux
// to redirect a request for "/images" to "/images/", unless "/images" has
// been registered separately.
//
// # Request sanitizing
//
// ServeMux also takes care of sanitizing the URL request path and the Host
// header, stripping the port number and redirecting any request containing . or
// .. segments or repeated slashes to an equivalent, cleaner URL.
// Escaped path elements such as "%2e" for "." and "%2f" for "/" are preserved
// and aren't considered separators for request routing.
//
// # Compatibility
//
// The pattern syntax and matching behavior of ServeMux changed significantly
// in Go 1.22. To restore the old behavior, set the GODEBUG environment variable
// to "httpmuxgo121=1". This setting is read once, at program startup; changes
// during execution will be ignored.
//
// The backwards-incompatible changes include:
//   - Wildcards are just ordinary literal path segments in 1.21.
//     For example, the pattern "/{x}" will match only that path in 1.21,
//     but will match any one-segment path in 1.22.
//   - In 1.21, no pattern was rejected, unless it was empty or conflicted with an existing pattern.
//     In 1.22, syntactically invalid patterns will cause [ServeMux.Handle] and [ServeMux.HandleFunc] to panic.
//     For example, in 1.21, the patterns "/{"  and "/a{x}" match themselves,
//     but in 1.22 they are invalid and will cause a panic when registered.
//   - In 1.22, each segment of a pattern is unescaped; this was not done in 1.21.
//     For example, in 1.22 the pattern "/%61" matches the path "/a" ("%61" being the URL escape sequence for "a"),
//     but in 1.21 it would match only the path "/%2561" (where "%25" is the escape for the percent sign).
//   - When matching patterns to paths, in 1.22 each segment of the path is unescaped; in 1.21, the entire path is unescaped.
//     This change mostly affects how paths with %2F escapes adjacent to slashes are treated.
//     See https://go.dev/issue/21955 for details.
type ServeMux struct {
	mu     sync.RWMutex
	tree   routingNode
	index  routingIndex
	mux121 serveMux121 // used only when GODEBUG=httpmuxgo121=1
}

// NewServeMux allocates and returns a new [ServeMux].
func NewServeMux() *ServeMux {
	return &ServeMux{}
}

// DefaultServeMux is the default [ServeMux] used by [Serve].
var DefaultServeMux = &defaultServeMux

var defaultServeMux ServeMux

// cleanPath returns the canonical path for p, eliminating . and .. elements.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		// Fast path for common case of p being the string we want:
		if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
			np = p
		} else {
			np += "/"
		}
	}
	return np
}

// stripHostPort returns h without any trailing ":<port>".
func stripHostPort(h string) string {
	// If no port on host, return unchanged
	if !strings.Contains(h, ":") {
		return h
	}
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		return h // on error, return unchanged
	}
	return host
}

// Handler returns the handler to use for the given request,
// consulting r.Method, r.Host, and r.URL.Path. It always returns
// a non-nil handler. If the path is not in its canonical form, the
// handler will be an internally-generated handler that redirects
// to the canonical path. If the host contains a port, it is ignored
// when matching handlers.
//
// The path and host are used unchanged for CONNECT requests.
//
// Handler also returns the registered pattern that matches the
// request or, in the case of internally-generated redirects,
// the path that will match after following the redirect.
//
// If there is no registered handler that applies to the request,
// Handler returns a “page not found” handler and an empty pattern.
func (mux *ServeMux) Handler(r *Request) (h Handler, pattern string) {
	if use121 {
		return mux.mux121.findHandler(r)
	}
	h, p, _, _ := mux.findHandler(r)
	return h, p
}

// findHandler finds a handler for a request.
// If there is a matching handler, it returns it and the pattern that matched.
// Otherwise it returns a Redirect or NotFound handler with the path that would match
// after the redirect.
func (mux *ServeMux) findHandler(r *Request) (h Handler, patStr string, _ *pattern, matches []string) {
	var n *routingNode
	host := r.URL.Host
	escapedPath := r.URL.EscapedPath()
	path := escapedPath
	// CONNECT requests are not canonicalized.
	if r.Method == "CONNECT" {
		// If r.URL.Path is /tree and its handler is not registered,
		// the /tree -> /tree/ redirect applies to CONNECT requests
		// but the path canonicalization does not.
		_, _, u := mux.matchOrRedirect(host, r.Method, path, r.URL)
		if u != nil {
			return RedirectHandler(u.String(), StatusMovedPermanently), u.Path, nil, nil
		}
		// Redo the match, this time with r.Host instead of r.URL.Host.
		// Pass a nil URL to skip the trailing-slash redirect logic.
		n, matches, _ = mux.matchOrRedirect(r.Host, r.Method, path, nil)
	} else {
		// All other requests have any port stripped and path cleaned
		// before passing to mux.handler.
		host = stripHostPort(r.Host)
		path = cleanPath(path)

		// If the given path is /tree and its handler is not registered,
		// redirect for /tree/.
		var u *url.URL
		n, matches, u = mux.matchOrRedirect(host, r.Method, path, r.URL)
		if u != nil {
			return RedirectHandler(u.String(), StatusMovedPermanently), u.Path, nil, nil
		}
		if path != escapedPath {
			// Redirect to cleaned path.
			patStr := ""
			if n != nil {
				patStr = n.pattern.String()
			}
			u := &url.URL{Path: path, RawQuery: r.URL.RawQuery}
			return RedirectHandler(u.String(), StatusMovedPermanently), patStr, nil, nil
		}
	}
	if n == nil {
		// We didn't find a match with the request method. To distinguish between
		// Not Found and Method Not Allowed, see if there is another pattern that
		// matches except for the method.
		allowedMethods := mux.matchingMethods(host, path)
		if len(allowedMethods) > 0 {
			return HandlerFunc(func(w ResponseWriter, r *Request) {
				w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
				Error(w, StatusText(StatusMethodNotAllowed), StatusMethodNotAllowed)
			}), "", nil, nil
		}
		return NotFoundHandler(), "", nil, nil
	}
	return n.handler, n.pattern.String(), n.pattern, matches
}

// matchOrRedirect looks up a node in the tree that matches the host, method and path.
//
// If the url argument is non-nil, handler also deals with trailing-slash
// redirection: when a path doesn't match exactly, the match is tried again
// after appending "/" to the path. If that second match succeeds, the last
// return value is the URL to redirect to.
func (mux *ServeMux) matchOrRedirect(host, method, path string, u *url.URL) (_ *routingNode, matches []string, redirectTo *url.URL) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	n, matches := mux.tree.match(host, method, path)
	// If we have an exact match, or we were asked not to try trailing-slash redirection,
	// or the URL already has a trailing slash, then we're done.
	if !exactMatch(n, path) && u != nil && !strings.HasSuffix(path, "/") {
		// If there is an exact match with a trailing slash, then redirect.
		path += "/"
		n2, _ := mux.tree.match(host, method, path)
		if exactMatch(n2, path) {
			return nil, nil, &url.URL{Path: cleanPath(u.Path) + "/", RawQuery: u.RawQuery}
		}
	}
	return n, matches, nil
}

// exactMatch reports whether the node's pattern exactly matches the path.
// As a special case, if the node is nil, exactMatch return false.
//
// Before wildcards were introduced, it was clear that an exact match meant
// that the pattern and path were the same string. The only other possibility
// was that a trailing-slash pattern, like "/", matched a path longer than
// it, like "/a".
//
// With wildcards, we define an inexact match as any one where a multi wildcard
// matches a non-empty string. All other matches are exact.
// For example, these are all exact matches:
//
//	pattern   path
//	/a        /a
//	/{x}      /a
//	/a/{$}    /a/
//	/a/       /a/
//
// The last case has a multi wildcard (implicitly), but the match is exact because
// the wildcard matches the empty string.
//
// Examples of matches that are not exact:
//
//	pattern   path
//	/         /a
//	/a/{x...} /a/b
func exactMatch(n *routingNode, path string) bool {
	if n == nil {
		return false
	}
	// We can't directly implement the definition (empty match for multi
	// wildcard) because we don't record a match for anonymous multis.

	// If there is no multi, the match is exact.
	if !n.pattern.lastSegment().multi {
		return true
	}

	// If the path doesn't end in a trailing slash, then the multi match
	// is non-empty.
	if len(path) > 0 && path[len(path)-1] != '/' {
		return false
	}
	// Only patterns ending in {$} or a multi wildcard can
	// match a path with a trailing slash.
	// For the match to be exact, the number of pattern
	// segments should be the same as the number of slashes in the path.
	// E.g. "/a/b/{$}" and "/a/b/{...}" exactly match "/a/b/", but "/a/" does not.
	return len(n.pattern.segments) == strings.Count(path, "/")
}

// matchingMethods return a sorted list of all methods that would match with the given host and path.
func (mux *ServeMux) matchingMethods(host, path string) []string {
	// Hold the read lock for the entire method so that the two matches are done
	// on the same set of registered patterns.
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	ms := map[string]bool{}
	mux.tree.matchingMethods(host, path, ms)
	// matchOrRedirect will try appending a trailing slash if there is no match.
	if !strings.HasSuffix(path, "/") {
		mux.tree.matchingMethods(host, path+"/", ms)
	}
	return slices.Sorted(maps.Keys(ms))
}

// ServeHTTP dispatches the request to the handler whose
// pattern most closely matches the request URL.
func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request) {
	if r.RequestURI == "*" {
		if r.ProtoAtLeast(1, 1) {
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(StatusBadRequest)
		return
	}
	var h Handler
	if use121 {
		h, _ = mux.mux121.findHandler(r)
	} else {
		h, r.Pattern, r.pat, r.matches = mux.findHandler(r)
	}
	h.ServeHTTP(w, r)
}

// The four functions below all call ServeMux.register so that callerLocation
// always refers to user code.

// Handle registers the handler for the given pattern.
// If the given pattern conflicts, with one that is already registered, Handle
// panics.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if use121 {
		mux.mux121.handle(pattern, handler)
	} else {
		mux.register(pattern, handler)
	}
}

// HandleFunc registers the handler function for the given pattern.
// If the given pattern conflicts, with one that is already registered, HandleFunc
// panics.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	if use121 {
		mux.mux121.handleFunc(pattern, handler)
	} else {
		mux.register(pattern, HandlerFunc(handler))
	}
}

// Handle registers the handler for the given pattern in [DefaultServeMux].
// The documentation for [ServeMux] explains how patterns are matched.
func Handle(pattern string, handler Handler) {
	if use121 {
		DefaultServeMux.mux121.handle(pattern, handler)
	} else {
		DefaultServeMux.register(pattern, handler)
	}
}

// HandleFunc registers the handler function for the given pattern in [DefaultServeMux].
// The documentation for [ServeMux] explains how patterns are matched.
func HandleFunc(pattern string, handler func(ResponseWriter, *Request)) {
	if use121 {
		DefaultServeMux.mux121.handleFunc(pattern, handler)
	} else {
		DefaultServeMux.register(pattern, HandlerFunc(handler))
	}
}

func (mux *ServeMux) register(pattern string, handler Handler) {
	if err := mux.registerErr(pattern, handler); err != nil {
		panic(err)
	}
}

func (mux *ServeMux) registerErr(patstr string, handler Handler) error {
	if patstr == "" {
		return errors.New("http: invalid pattern")
	}
	if handler == nil {
		return errors.New("http: nil handler")
	}
	if f, ok := handler.(HandlerFunc); ok && f == nil {
		return errors.New("http: nil handler")
	}

	pat, err := parsePattern(patstr)
	if err != nil {
		return fmt.Errorf("parsing %q: %w", patstr, err)
	}

	// Get the caller's location, for better conflict error messages.
	// Skip register and whatever calls it.
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		pat.loc = "unknown location"
	} else {
		pat.loc = fmt.Sprintf("%s:%d", file, line)
	}

	mux.mu.Lock()
	defer mux.mu.Unlock()
	// Check for conflict.
	if err := mux.index.possiblyConflictingPatterns(pat, func(pat2 *pattern) error {
		if pat.conflictsWith(pat2) {
			d := describeConflict(pat, pat2)
			return fmt.Errorf("pattern %q (registered at %s) conflicts with pattern %q (registered at %s):\n%s",
				pat, pat.loc, pat2, pat2.loc, d)
		}
		return nil
	}); err != nil {
		return err
	}
	mux.tree.addPattern(pat, handler)
	mux.index.addPattern(pat)
	return nil
}

// Serve accepts incoming HTTP connections on the listener l,
// creating a new service goroutine for each. The service goroutines
// read requests and then call handler to reply to them.
//
// The handler is typically nil, in which case [DefaultServeMux] is used.
//
// HTTP/2 support is only enabled if the Listener returns [*tls.Conn]
// connections and they were configured with "h2" in the TLS
// Config.NextProtos.
//
// Serve always returns a non-nil error.
func Serve(l net.Listener, handler Handler) error {
	srv := &Server{Handler: handler}
	return srv.Serve(l)
}

// ServeTLS accepts incoming HTTPS connections on the listener l,
// creating a new service goroutine for each. The service goroutines
// read requests and then call handler to reply to them.
//
// The handler is typically nil, in which case [DefaultServeMux] is used.
//
// Additionally, files containing a certificate and matching private key
// for the server must be provided. If the certificate is signed by a
// certificate authority, the certFile should be the concatenation
// of the server's certificate, any intermediates, and the CA's certificate.
//
// ServeTLS always returns a non-nil error.
func ServeTLS(l net.Listener, handler Handler, certFile, keyFile string) error {
	srv := &Server{Handler: handler}
	return srv.ServeTLS(l, certFile, keyFile)
}

// A Server defines parameters for running an HTTP server.
// The zero value for Server is a valid configuration.
type Server struct {
	// Addr optionally specifies the TCP address for the server to listen on,
	// in the form "host:port". If empty, ":http" (port 80) is used.
	// The service names are defined in RFC 6335 and assigned by IANA.
	// See net.Dial for details of the address format.
	Addr string

	Handler Handler // handler to invoke, http.DefaultServeMux if nil

	// DisableGeneralOptionsHandler, if true, passes "OPTIONS *" requests to the Handler,
	// otherwise responds with 200 OK and Content-Length: 0.
	DisableGeneralOptionsHandler bool

	// TLSConfig optionally provides a TLS configuration for use
	// by ServeTLS and ListenAndServeTLS. Note that this value is
	// cloned by ServeTLS and ListenAndServeTLS, so it's not
	// possible to modify the configuration with methods like
	// tls.Config.SetSessionTicketKeys. To use
	// SetSessionTicketKeys, use Server.Serve with a TLS Listener
	// instead.
	TLSConfig *tls.Config

	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body. A zero or negative value means
	// there will be no timeout.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body. If zero, the value of
	// ReadTimeout is used. If negative, or if zero and ReadTimeout
	// is zero or negative, there is no timeout.
	ReadHeaderTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request 
"""




```