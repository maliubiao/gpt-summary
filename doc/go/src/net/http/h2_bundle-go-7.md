Response:
The user is asking for a summary of the functionality of the provided Go code snippet, which is part of the `net/http` package and specifically deals with HTTP/2 implementation.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Functionality:** The code revolves around handling HTTP responses within an HTTP/2 connection. Keywords like `ResponseWriter`, `WriteHeader`, `Write`, `Push`, and the presence of HTTP/2 specific structures (like `http2responseWriterState`) strongly suggest response handling.

2. **Trace the Key Functions:**
    * `Write`: This function is responsible for sending the response body. It handles content length checks and calls the underlying writer.
    * `WriteHeader`: This sets the HTTP status code and headers. It distinguishes between initial headers and informational headers (1xx).
    * `Header`: Provides access to the response headers.
    * `Flush`:  Forces buffered data to be sent.
    * `CloseNotify`:  Provides a channel that signals when the client connection closes.
    * `Push`: Implements the HTTP/2 server push mechanism.
    * `promoteUndeclaredTrailers`: Handles the special "Trailer:" prefix in headers for sending trailers after the main headers.
    * `SetReadDeadline` and `SetWriteDeadline`: Allow setting deadlines for read and write operations on the stream.

3. **Recognize HTTP/2 Specifics:**  Look for code patterns related to HTTP/2 features:
    * Handling of the `Connection` header (it's not allowed in HTTP/2).
    * Support for trailers (headers sent after the response body).
    * Implementation of server push (`Push` function).
    * Flow control (`http2outflow`, `http2inflow` in the later parts of the file, even though not directly in this snippet, they are related to the context).
    * Handling of pseudo-headers (like `:status`, although not explicitly shown in this part).

4. **Infer Underlying Structures:** The code interacts with structures like `http2responseWriterState`, `http2responseWriter`, `http2serverConn`, and `http2stream`. Understanding their roles is crucial. `http2responseWriterState` holds the state of the response, `http2responseWriter` implements the `ResponseWriter` interface, `http2serverConn` represents the server-side connection, and `http2stream` represents an individual HTTP/2 stream.

5. **Focus on the "Part 8 of 13" Aspect:** Since the user explicitly mentioned this is part of a larger file, acknowledge that this snippet likely focuses on a specific aspect of response handling and interfaces with other parts of the HTTP/2 implementation.

6. **Identify Potential Pitfalls:** The code highlights the "Trailer:" prefix as a less conventional way to set trailers, implying a potential point of confusion for users who might be more familiar with the standard `ResponseWriter.Trailer()` method.

7. **Structure the Answer:** Organize the information logically:
    * Start with a high-level summary of the file's purpose (response handling in HTTP/2).
    * List the key functionalities and briefly explain each.
    * Mention the HTTP/2 specific features being handled.
    * Highlight any important considerations (like the "Trailer:" prefix).

8. **Review and Refine:**  Ensure the language is clear, concise, and accurate. Remove any redundant information. Double-check that the summary aligns with the code provided. For instance, the code explicitly handles the `Connection: close` header to initiate a graceful shutdown, which is worth mentioning.

By following these steps, we can construct a comprehensive and accurate summary of the provided Go code snippet. The key is to move from the specific functions and structures to a higher-level understanding of the code's role within the larger HTTP/2 implementation.
这是 `go/src/net/http/h2_bundle.go` 文件的一部分，主要负责 **HTTP/2 服务器端响应处理** 的实现。  这是第 8 部分，重点在于 `http2responseWriter` 和 `http2responseWriterState` 结构体及其相关方法，它们共同实现了 `http.ResponseWriter` 接口，用于在 HTTP/2 连接上构建和发送响应。

**具体功能归纳如下:**

1. **实现 `http.ResponseWriter` 接口:**  `http2responseWriter` 实现了 `WriteHeader`, `Write`, `WriteString`, `Header` 等 `http.ResponseWriter` 接口定义的方法，使得 Go 的 HTTP Handler 可以像处理 HTTP/1.1 请求一样处理 HTTP/2 请求。

2. **管理响应状态:** `http2responseWriterState` 结构体存储了响应的状态信息，例如 HTTP 状态码 (`status`)、是否已写入头部 (`wroteHeader`)、已写入的字节数 (`wroteBytes`) 等。

3. **构建响应头部:**
   - `WriteHeader` 方法用于设置 HTTP 状态码。
   - `Header` 方法返回用于设置响应头的 `http.Header`。
   -  处理 informational 状态码 (1xx)，允许发送多个 informational 响应。
   -  在第一次调用 `WriteHeader` 或 `Write` 时发送初始响应头。

4. **发送响应体:**
   - `Write` 和 `WriteString` 方法用于写入响应体数据。
   -  会检查是否允许该状态码发送响应体。
   -  如果设置了 `Content-Length`，会检查写入的字节数是否超过限制。
   -  使用 `bufio.Writer` 进行缓冲，提高写入效率。

5. **支持 Trailers (尾部):**
   -  支持标准的方式通过 `ResponseWriter.Header().Set("Trailer", "...")` 预先声明 Trailers。
   -  引入了 `http2TrailerPrefix` ( "Trailer:") 的机制，允许在响应头发送后动态设置 Trailers。 `promoteUndeclaredTrailers` 方法会将以 "Trailer:" 为前缀的 header 提升为真正的 Trailers。

6. **实现 Server Push:**
   - `Push` 方法允许服务器主动向客户端推送资源，提高了性能。
   -  会进行一系列的校验，例如是否是递归推送，是否超过了客户端的 `SETTINGS_MAX_CONCURRENT_STREAMS` 限制，以及 URL 的有效性。

7. **处理 `Connection: close`:** 虽然 HTTP/2 不允许 `Connection` 头，但如果收到 `Connection: close`，会触发优雅关闭连接的流程。

8. **设置读写 Deadline:** `SetReadDeadline` 和 `SetWriteDeadline` 方法允许为流设置读写超时时间。

9. **实现 Flush:** `Flush` 方法强制将缓冲的数据发送出去，对于需要实时响应的场景很有用。

10. **实现 CloseNotify:** `CloseNotify` 方法返回一个 channel，当客户端断开连接时，该 channel 会被关闭。

**Go 代码示例说明 Server Push 功能:**

假设我们有一个处理 `/index.html` 请求的 Handler，并且想在响应 `/index.html` 的同时，主动推送 `/static/style.css` 和 `/static/script.js` 资源。

```go
package main

import (
	"fmt"
	"net/http"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	pusher, ok := w.(http.Pusher)
	if ok {
		// 推送 CSS 文件
		err := pusher.Push("/static/style.css", &http.PushOptions{
			Header: http.Header{"Content-Type": []string{"text/css"}},
		})
		if err != nil {
			fmt.Printf("Failed to push /static/style.css: %v\n", err)
		}

		// 推送 JS 文件
		err = pusher.Push("/static/script.js", &http.PushOptions{
			Header: http.Header{"Content-Type": []string{"application/javascript"}},
		})
		if err != nil {
			fmt.Printf("Failed to push /static/script.js: %v\n", err)
		}
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "<html><head><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body><h1>Hello, HTTP/2!</h1><script src=\"/static/script.js\"></script></body></html>")
}

func staticFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/static/style.css" {
		w.Header().Set("Content-Type", "text/css")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "body { background-color: lightblue; }")
	} else if r.URL.Path == "/static/script.js" {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "console.log('Hello from pushed script!');")
	} else {
		http.NotFound(w, r)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/index.html", indexHandler)
	mux.HandleFunc("/static/", staticFileHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// 假设你已经配置了 TLS 并启用了 HTTP/2
	err := server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		fmt.Println("ListenAndServeTLS error:", err)
	}
}
```

**假设的输入与输出 (针对 Server Push 示例):**

**输入:** 客户端发起对 `/index.html` 的 HTTP/2 GET 请求。

**输出:**

1. **HTTP 响应 (针对 `/index.html`):**
   - Status Code: 200 OK
   - Headers: `Content-Type: text/html`
   - Body: `<html><head><link rel="stylesheet" href="/static/style.css"></head><body><h1>Hello, HTTP/2!</h1><script src="/static/script.js"></script></body></html>`

2. **Server Push (针对 `/static/style.css`):**
   - 客户端会在收到 `/index.html` 的响应头之前或同时收到一个 PUSH_PROMISE 帧，指示服务器将要推送 `/static/style.css`。
   - 随后，客户端会收到 `/static/style.css` 的响应：
     - Status Code: 200 OK
     - Headers: `Content-Type: text/css`
     - Body: `body { background-color: lightblue; }`

3. **Server Push (针对 `/static/script.js`):**
   - 类似地，客户端会收到 `/static/script.js` 的 PUSH_PROMISE 帧。
   - 随后，客户端会收到 `/static/script.js` 的响应：
     - Status Code: 200 OK
     - Headers: `Content-Type: application/javascript`
     - Body: `console.log('Hello from pushed script!');`

**使用者易犯错的点:**

一个常见的错误是 **在 `WriteHeader` 调用之后尝试设置之前未声明为 Trailer 的 header 并期望它们作为 Trailer 发送**。

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintln(w, "Hello, world!")
    w.Header().Set("Custom-Trailer", "trailer-value") // 期望作为 Trailer 发送，但不会
}
```

在这种情况下，`Custom-Trailer` 不会作为 Trailer 发送，因为它是在 `WriteHeader` 之后设置的，并且没有使用 "Trailer:" 前缀进行声明。 正确的做法是：

1. **预先声明 Trailer:**
   ```go
   func myHandler(w http.ResponseWriter, r *http.Request) {
       w.Header().Set("Trailer", "Custom-Trailer") // 预先声明
       w.Header().Set("Content-Type", "text/plain")
       w.WriteHeader(http.StatusOK)
       fmt.Fprintln(w, "Hello, world!")
       w.Header().Set("Custom-Trailer", "trailer-value") // 设置 Trailer 值
   }
   ```

2. **使用 "Trailer:" 前缀 (用于动态设置):**
   ```go
   func myHandler(w http.ResponseWriter, r *http.Request) {
       w.Header().Set("Content-Type", "text/plain")
       w.WriteHeader(http.StatusOK)
       fmt.Fprintln(w, "Hello, world!")
       w.Header().Set("Trailer:Custom-Trailer", "trailer-value") // 动态设置 Trailer
   }
   ```

总之，这段代码是 Go HTTP/2 服务器端响应处理的核心部分，它实现了 `http.ResponseWriter` 接口，并提供了诸如 Server Push 和 Trailers 等 HTTP/2 特有的功能。 理解 `http2responseWriter` 和 `http2responseWriterState` 的作用是理解 Go HTTP/2 服务器实现的关键。

### 提示词
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第8部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
ngth && clen == "" && rws.handlerDone && http2bodyAllowedForStatus(rws.status) && (len(p) > 0 || !isHeadResp) {
			clen = strconv.Itoa(len(p))
		}
		_, hasContentType := rws.snapHeader["Content-Type"]
		// If the Content-Encoding is non-blank, we shouldn't
		// sniff the body. See Issue golang.org/issue/31753.
		ce := rws.snapHeader.Get("Content-Encoding")
		hasCE := len(ce) > 0
		if !hasCE && !hasContentType && http2bodyAllowedForStatus(rws.status) && len(p) > 0 {
			ctype = DetectContentType(p)
		}
		var date string
		if _, ok := rws.snapHeader["Date"]; !ok {
			// TODO(bradfitz): be faster here, like net/http? measure.
			date = rws.conn.srv.now().UTC().Format(TimeFormat)
		}

		for _, v := range rws.snapHeader["Trailer"] {
			http2foreachHeaderElement(v, rws.declareTrailer)
		}

		// "Connection" headers aren't allowed in HTTP/2 (RFC 7540, 8.1.2.2),
		// but respect "Connection" == "close" to mean sending a GOAWAY and tearing
		// down the TCP connection when idle, like we do for HTTP/1.
		// TODO: remove more Connection-specific header fields here, in addition
		// to "Connection".
		if _, ok := rws.snapHeader["Connection"]; ok {
			v := rws.snapHeader.Get("Connection")
			delete(rws.snapHeader, "Connection")
			if v == "close" {
				rws.conn.startGracefulShutdown()
			}
		}

		endStream := (rws.handlerDone && !rws.hasTrailers() && len(p) == 0) || isHeadResp
		err = rws.conn.writeHeaders(rws.stream, &http2writeResHeaders{
			streamID:      rws.stream.id,
			httpResCode:   rws.status,
			h:             rws.snapHeader,
			endStream:     endStream,
			contentType:   ctype,
			contentLength: clen,
			date:          date,
		})
		if err != nil {
			return 0, err
		}
		if endStream {
			return 0, nil
		}
	}
	if isHeadResp {
		return len(p), nil
	}
	if len(p) == 0 && !rws.handlerDone {
		return 0, nil
	}

	// only send trailers if they have actually been defined by the
	// server handler.
	hasNonemptyTrailers := rws.hasNonemptyTrailers()
	endStream := rws.handlerDone && !hasNonemptyTrailers
	if len(p) > 0 || endStream {
		// only send a 0 byte DATA frame if we're ending the stream.
		if err := rws.conn.writeDataFromHandler(rws.stream, p, endStream); err != nil {
			return 0, err
		}
	}

	if rws.handlerDone && hasNonemptyTrailers {
		err = rws.conn.writeHeaders(rws.stream, &http2writeResHeaders{
			streamID:  rws.stream.id,
			h:         rws.handlerHeader,
			trailers:  rws.trailers,
			endStream: true,
		})
		return len(p), err
	}
	return len(p), nil
}

// TrailerPrefix is a magic prefix for ResponseWriter.Header map keys
// that, if present, signals that the map entry is actually for
// the response trailers, and not the response headers. The prefix
// is stripped after the ServeHTTP call finishes and the values are
// sent in the trailers.
//
// This mechanism is intended only for trailers that are not known
// prior to the headers being written. If the set of trailers is fixed
// or known before the header is written, the normal Go trailers mechanism
// is preferred:
//
//	https://golang.org/pkg/net/http/#ResponseWriter
//	https://golang.org/pkg/net/http/#example_ResponseWriter_trailers
const http2TrailerPrefix = "Trailer:"

// promoteUndeclaredTrailers permits http.Handlers to set trailers
// after the header has already been flushed. Because the Go
// ResponseWriter interface has no way to set Trailers (only the
// Header), and because we didn't want to expand the ResponseWriter
// interface, and because nobody used trailers, and because RFC 7230
// says you SHOULD (but not must) predeclare any trailers in the
// header, the official ResponseWriter rules said trailers in Go must
// be predeclared, and then we reuse the same ResponseWriter.Header()
// map to mean both Headers and Trailers. When it's time to write the
// Trailers, we pick out the fields of Headers that were declared as
// trailers. That worked for a while, until we found the first major
// user of Trailers in the wild: gRPC (using them only over http2),
// and gRPC libraries permit setting trailers mid-stream without
// predeclaring them. So: change of plans. We still permit the old
// way, but we also permit this hack: if a Header() key begins with
// "Trailer:", the suffix of that key is a Trailer. Because ':' is an
// invalid token byte anyway, there is no ambiguity. (And it's already
// filtered out) It's mildly hacky, but not terrible.
//
// This method runs after the Handler is done and promotes any Header
// fields to be trailers.
func (rws *http2responseWriterState) promoteUndeclaredTrailers() {
	for k, vv := range rws.handlerHeader {
		if !strings.HasPrefix(k, http2TrailerPrefix) {
			continue
		}
		trailerKey := strings.TrimPrefix(k, http2TrailerPrefix)
		rws.declareTrailer(trailerKey)
		rws.handlerHeader[CanonicalHeaderKey(trailerKey)] = vv
	}

	if len(rws.trailers) > 1 {
		sorter := http2sorterPool.Get().(*http2sorter)
		sorter.SortStrings(rws.trailers)
		http2sorterPool.Put(sorter)
	}
}

func (w *http2responseWriter) SetReadDeadline(deadline time.Time) error {
	st := w.rws.stream
	if !deadline.IsZero() && deadline.Before(w.rws.conn.srv.now()) {
		// If we're setting a deadline in the past, reset the stream immediately
		// so writes after SetWriteDeadline returns will fail.
		st.onReadTimeout()
		return nil
	}
	w.rws.conn.sendServeMsg(func(sc *http2serverConn) {
		if st.readDeadline != nil {
			if !st.readDeadline.Stop() {
				// Deadline already exceeded, or stream has been closed.
				return
			}
		}
		if deadline.IsZero() {
			st.readDeadline = nil
		} else if st.readDeadline == nil {
			st.readDeadline = sc.srv.afterFunc(deadline.Sub(sc.srv.now()), st.onReadTimeout)
		} else {
			st.readDeadline.Reset(deadline.Sub(sc.srv.now()))
		}
	})
	return nil
}

func (w *http2responseWriter) SetWriteDeadline(deadline time.Time) error {
	st := w.rws.stream
	if !deadline.IsZero() && deadline.Before(w.rws.conn.srv.now()) {
		// If we're setting a deadline in the past, reset the stream immediately
		// so writes after SetWriteDeadline returns will fail.
		st.onWriteTimeout()
		return nil
	}
	w.rws.conn.sendServeMsg(func(sc *http2serverConn) {
		if st.writeDeadline != nil {
			if !st.writeDeadline.Stop() {
				// Deadline already exceeded, or stream has been closed.
				return
			}
		}
		if deadline.IsZero() {
			st.writeDeadline = nil
		} else if st.writeDeadline == nil {
			st.writeDeadline = sc.srv.afterFunc(deadline.Sub(sc.srv.now()), st.onWriteTimeout)
		} else {
			st.writeDeadline.Reset(deadline.Sub(sc.srv.now()))
		}
	})
	return nil
}

func (w *http2responseWriter) EnableFullDuplex() error {
	// We always support full duplex responses, so this is a no-op.
	return nil
}

func (w *http2responseWriter) Flush() {
	w.FlushError()
}

func (w *http2responseWriter) FlushError() error {
	rws := w.rws
	if rws == nil {
		panic("Header called after Handler finished")
	}
	var err error
	if rws.bw.Buffered() > 0 {
		err = rws.bw.Flush()
	} else {
		// The bufio.Writer won't call chunkWriter.Write
		// (writeChunk with zero bytes), so we have to do it
		// ourselves to force the HTTP response header and/or
		// final DATA frame (with END_STREAM) to be sent.
		_, err = http2chunkWriter{rws}.Write(nil)
		if err == nil {
			select {
			case <-rws.stream.cw:
				err = rws.stream.closeErr
			default:
			}
		}
	}
	return err
}

func (w *http2responseWriter) CloseNotify() <-chan bool {
	rws := w.rws
	if rws == nil {
		panic("CloseNotify called after Handler finished")
	}
	rws.closeNotifierMu.Lock()
	ch := rws.closeNotifierCh
	if ch == nil {
		ch = make(chan bool, 1)
		rws.closeNotifierCh = ch
		cw := rws.stream.cw
		go func() {
			cw.Wait() // wait for close
			ch <- true
		}()
	}
	rws.closeNotifierMu.Unlock()
	return ch
}

func (w *http2responseWriter) Header() Header {
	rws := w.rws
	if rws == nil {
		panic("Header called after Handler finished")
	}
	if rws.handlerHeader == nil {
		rws.handlerHeader = make(Header)
	}
	return rws.handlerHeader
}

// checkWriteHeaderCode is a copy of net/http's checkWriteHeaderCode.
func http2checkWriteHeaderCode(code int) {
	// Issue 22880: require valid WriteHeader status codes.
	// For now we only enforce that it's three digits.
	// In the future we might block things over 599 (600 and above aren't defined
	// at http://httpwg.org/specs/rfc7231.html#status.codes).
	// But for now any three digits.
	//
	// We used to send "HTTP/1.1 000 0" on the wire in responses but there's
	// no equivalent bogus thing we can realistically send in HTTP/2,
	// so we'll consistently panic instead and help people find their bugs
	// early. (We can't return an error from WriteHeader even if we wanted to.)
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("invalid WriteHeader code %v", code))
	}
}

func (w *http2responseWriter) WriteHeader(code int) {
	rws := w.rws
	if rws == nil {
		panic("WriteHeader called after Handler finished")
	}
	rws.writeHeader(code)
}

func (rws *http2responseWriterState) writeHeader(code int) {
	if rws.wroteHeader {
		return
	}

	http2checkWriteHeaderCode(code)

	// Handle informational headers
	if code >= 100 && code <= 199 {
		// Per RFC 8297 we must not clear the current header map
		h := rws.handlerHeader

		_, cl := h["Content-Length"]
		_, te := h["Transfer-Encoding"]
		if cl || te {
			h = h.Clone()
			h.Del("Content-Length")
			h.Del("Transfer-Encoding")
		}

		rws.conn.writeHeaders(rws.stream, &http2writeResHeaders{
			streamID:    rws.stream.id,
			httpResCode: code,
			h:           h,
			endStream:   rws.handlerDone && !rws.hasTrailers(),
		})

		return
	}

	rws.wroteHeader = true
	rws.status = code
	if len(rws.handlerHeader) > 0 {
		rws.snapHeader = http2cloneHeader(rws.handlerHeader)
	}
}

func http2cloneHeader(h Header) Header {
	h2 := make(Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

// The Life Of A Write is like this:
//
// * Handler calls w.Write or w.WriteString ->
// * -> rws.bw (*bufio.Writer) ->
// * (Handler might call Flush)
// * -> chunkWriter{rws}
// * -> responseWriterState.writeChunk(p []byte)
// * -> responseWriterState.writeChunk (most of the magic; see comment there)
func (w *http2responseWriter) Write(p []byte) (n int, err error) {
	return w.write(len(p), p, "")
}

func (w *http2responseWriter) WriteString(s string) (n int, err error) {
	return w.write(len(s), nil, s)
}

// either dataB or dataS is non-zero.
func (w *http2responseWriter) write(lenData int, dataB []byte, dataS string) (n int, err error) {
	rws := w.rws
	if rws == nil {
		panic("Write called after Handler finished")
	}
	if !rws.wroteHeader {
		w.WriteHeader(200)
	}
	if !http2bodyAllowedForStatus(rws.status) {
		return 0, ErrBodyNotAllowed
	}
	rws.wroteBytes += int64(len(dataB)) + int64(len(dataS)) // only one can be set
	if rws.sentContentLen != 0 && rws.wroteBytes > rws.sentContentLen {
		// TODO: send a RST_STREAM
		return 0, errors.New("http2: handler wrote more than declared Content-Length")
	}

	if dataB != nil {
		return rws.bw.Write(dataB)
	} else {
		return rws.bw.WriteString(dataS)
	}
}

func (w *http2responseWriter) handlerDone() {
	rws := w.rws
	rws.handlerDone = true
	w.Flush()
	w.rws = nil
	http2responseWriterStatePool.Put(rws)
}

// Push errors.
var (
	http2ErrRecursivePush    = errors.New("http2: recursive push not allowed")
	http2ErrPushLimitReached = errors.New("http2: push would exceed peer's SETTINGS_MAX_CONCURRENT_STREAMS")
)

var _ Pusher = (*http2responseWriter)(nil)

func (w *http2responseWriter) Push(target string, opts *PushOptions) error {
	st := w.rws.stream
	sc := st.sc
	sc.serveG.checkNotOn()

	// No recursive pushes: "PUSH_PROMISE frames MUST only be sent on a peer-initiated stream."
	// http://tools.ietf.org/html/rfc7540#section-6.6
	if st.isPushed() {
		return http2ErrRecursivePush
	}

	if opts == nil {
		opts = new(PushOptions)
	}

	// Default options.
	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.Header == nil {
		opts.Header = Header{}
	}
	wantScheme := "http"
	if w.rws.req.TLS != nil {
		wantScheme = "https"
	}

	// Validate the request.
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if u.Scheme == "" {
		if !strings.HasPrefix(target, "/") {
			return fmt.Errorf("target must be an absolute URL or an absolute path: %q", target)
		}
		u.Scheme = wantScheme
		u.Host = w.rws.req.Host
	} else {
		if u.Scheme != wantScheme {
			return fmt.Errorf("cannot push URL with scheme %q from request with scheme %q", u.Scheme, wantScheme)
		}
		if u.Host == "" {
			return errors.New("URL must have a host")
		}
	}
	for k := range opts.Header {
		if strings.HasPrefix(k, ":") {
			return fmt.Errorf("promised request headers cannot include pseudo header %q", k)
		}
		// These headers are meaningful only if the request has a body,
		// but PUSH_PROMISE requests cannot have a body.
		// http://tools.ietf.org/html/rfc7540#section-8.2
		// Also disallow Host, since the promised URL must be absolute.
		if http2asciiEqualFold(k, "content-length") ||
			http2asciiEqualFold(k, "content-encoding") ||
			http2asciiEqualFold(k, "trailer") ||
			http2asciiEqualFold(k, "te") ||
			http2asciiEqualFold(k, "expect") ||
			http2asciiEqualFold(k, "host") {
			return fmt.Errorf("promised request headers cannot include %q", k)
		}
	}
	if err := http2checkValidHTTP2RequestHeaders(opts.Header); err != nil {
		return err
	}

	// The RFC effectively limits promised requests to GET and HEAD:
	// "Promised requests MUST be cacheable [GET, HEAD, or POST], and MUST be safe [GET or HEAD]"
	// http://tools.ietf.org/html/rfc7540#section-8.2
	if opts.Method != "GET" && opts.Method != "HEAD" {
		return fmt.Errorf("method %q must be GET or HEAD", opts.Method)
	}

	msg := &http2startPushRequest{
		parent: st,
		method: opts.Method,
		url:    u,
		header: http2cloneHeader(opts.Header),
		done:   http2errChanPool.Get().(chan error),
	}

	select {
	case <-sc.doneServing:
		return http2errClientDisconnected
	case <-st.cw:
		return http2errStreamClosed
	case sc.serveMsgCh <- msg:
	}

	select {
	case <-sc.doneServing:
		return http2errClientDisconnected
	case <-st.cw:
		return http2errStreamClosed
	case err := <-msg.done:
		http2errChanPool.Put(msg.done)
		return err
	}
}

type http2startPushRequest struct {
	parent *http2stream
	method string
	url    *url.URL
	header Header
	done   chan error
}

func (sc *http2serverConn) startPush(msg *http2startPushRequest) {
	sc.serveG.check()

	// http://tools.ietf.org/html/rfc7540#section-6.6.
	// PUSH_PROMISE frames MUST only be sent on a peer-initiated stream that
	// is in either the "open" or "half-closed (remote)" state.
	if msg.parent.state != http2stateOpen && msg.parent.state != http2stateHalfClosedRemote {
		// responseWriter.Push checks that the stream is peer-initiated.
		msg.done <- http2errStreamClosed
		return
	}

	// http://tools.ietf.org/html/rfc7540#section-6.6.
	if !sc.pushEnabled {
		msg.done <- ErrNotSupported
		return
	}

	// PUSH_PROMISE frames must be sent in increasing order by stream ID, so
	// we allocate an ID for the promised stream lazily, when the PUSH_PROMISE
	// is written. Once the ID is allocated, we start the request handler.
	allocatePromisedID := func() (uint32, error) {
		sc.serveG.check()

		// Check this again, just in case. Technically, we might have received
		// an updated SETTINGS by the time we got around to writing this frame.
		if !sc.pushEnabled {
			return 0, ErrNotSupported
		}
		// http://tools.ietf.org/html/rfc7540#section-6.5.2.
		if sc.curPushedStreams+1 > sc.clientMaxStreams {
			return 0, http2ErrPushLimitReached
		}

		// http://tools.ietf.org/html/rfc7540#section-5.1.1.
		// Streams initiated by the server MUST use even-numbered identifiers.
		// A server that is unable to establish a new stream identifier can send a GOAWAY
		// frame so that the client is forced to open a new connection for new streams.
		if sc.maxPushPromiseID+2 >= 1<<31 {
			sc.startGracefulShutdownInternal()
			return 0, http2ErrPushLimitReached
		}
		sc.maxPushPromiseID += 2
		promisedID := sc.maxPushPromiseID

		// http://tools.ietf.org/html/rfc7540#section-8.2.
		// Strictly speaking, the new stream should start in "reserved (local)", then
		// transition to "half closed (remote)" after sending the initial HEADERS, but
		// we start in "half closed (remote)" for simplicity.
		// See further comments at the definition of stateHalfClosedRemote.
		promised := sc.newStream(promisedID, msg.parent.id, http2stateHalfClosedRemote)
		rw, req, err := sc.newWriterAndRequestNoBody(promised, http2requestParam{
			method:    msg.method,
			scheme:    msg.url.Scheme,
			authority: msg.url.Host,
			path:      msg.url.RequestURI(),
			header:    http2cloneHeader(msg.header), // clone since handler runs concurrently with writing the PUSH_PROMISE
		})
		if err != nil {
			// Should not happen, since we've already validated msg.url.
			panic(fmt.Sprintf("newWriterAndRequestNoBody(%+v): %v", msg.url, err))
		}

		sc.curHandlers++
		go sc.runHandler(rw, req, sc.handler.ServeHTTP)
		return promisedID, nil
	}

	sc.writeFrame(http2FrameWriteRequest{
		write: &http2writePushPromise{
			streamID:           msg.parent.id,
			method:             msg.method,
			url:                msg.url,
			h:                  msg.header,
			allocatePromisedID: allocatePromisedID,
		},
		stream: msg.parent,
		done:   msg.done,
	})
}

// foreachHeaderElement splits v according to the "#rule" construction
// in RFC 7230 section 7 and calls fn for each non-empty element.
func http2foreachHeaderElement(v string, fn func(string)) {
	v = textproto.TrimString(v)
	if v == "" {
		return
	}
	if !strings.Contains(v, ",") {
		fn(v)
		return
	}
	for _, f := range strings.Split(v, ",") {
		if f = textproto.TrimString(f); f != "" {
			fn(f)
		}
	}
}

// From http://httpwg.org/specs/rfc7540.html#rfc.section.8.1.2.2
var http2connHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Transfer-Encoding",
	"Upgrade",
}

// checkValidHTTP2RequestHeaders checks whether h is a valid HTTP/2 request,
// per RFC 7540 Section 8.1.2.2.
// The returned error is reported to users.
func http2checkValidHTTP2RequestHeaders(h Header) error {
	for _, k := range http2connHeaders {
		if _, ok := h[k]; ok {
			return fmt.Errorf("request header %q is not valid in HTTP/2", k)
		}
	}
	te := h["Te"]
	if len(te) > 0 && (len(te) > 1 || (te[0] != "trailers" && te[0] != "")) {
		return errors.New(`request header "TE" may only be "trailers" in HTTP/2`)
	}
	return nil
}

func http2new400Handler(err error) HandlerFunc {
	return func(w ResponseWriter, r *Request) {
		Error(w, err.Error(), StatusBadRequest)
	}
}

// h1ServerKeepAlivesDisabled reports whether hs has its keep-alives
// disabled. See comments on h1ServerShutdownChan above for why
// the code is written this way.
func http2h1ServerKeepAlivesDisabled(hs *Server) bool {
	var x interface{} = hs
	type I interface {
		doKeepAlives() bool
	}
	if hs, ok := x.(I); ok {
		return !hs.doKeepAlives()
	}
	return false
}

func (sc *http2serverConn) countError(name string, err error) error {
	if sc == nil || sc.srv == nil {
		return err
	}
	f := sc.countErrorFunc
	if f == nil {
		return err
	}
	var typ string
	var code http2ErrCode
	switch e := err.(type) {
	case http2ConnectionError:
		typ = "conn"
		code = http2ErrCode(e)
	case http2StreamError:
		typ = "stream"
		code = http2ErrCode(e.Code)
	default:
		return err
	}
	codeStr := http2errCodeName[code]
	if codeStr == "" {
		codeStr = strconv.Itoa(int(code))
	}
	f(fmt.Sprintf("%s_%s_%s", typ, codeStr, name))
	return err
}

// A timer is a time.Timer, as an interface which can be replaced in tests.
type http2timer = interface {
	C() <-chan time.Time
	Reset(d time.Duration) bool
	Stop() bool
}

// timeTimer adapts a time.Timer to the timer interface.
type http2timeTimer struct {
	*time.Timer
}

func (t http2timeTimer) C() <-chan time.Time { return t.Timer.C }

const (
	// transportDefaultConnFlow is how many connection-level flow control
	// tokens we give the server at start-up, past the default 64k.
	http2transportDefaultConnFlow = 1 << 30

	// transportDefaultStreamFlow is how many stream-level flow
	// control tokens we announce to the peer, and how many bytes
	// we buffer per stream.
	http2transportDefaultStreamFlow = 4 << 20

	http2defaultUserAgent = "Go-http-client/2.0"

	// initialMaxConcurrentStreams is a connections maxConcurrentStreams until
	// it's received servers initial SETTINGS frame, which corresponds with the
	// spec's minimum recommended value.
	http2initialMaxConcurrentStreams = 100

	// defaultMaxConcurrentStreams is a connections default maxConcurrentStreams
	// if the server doesn't include one in its initial SETTINGS frame.
	http2defaultMaxConcurrentStreams = 1000
)

// Transport is an HTTP/2 Transport.
//
// A Transport internally caches connections to servers. It is safe
// for concurrent use by multiple goroutines.
type http2Transport struct {
	// DialTLSContext specifies an optional dial function with context for
	// creating TLS connections for requests.
	//
	// If DialTLSContext and DialTLS is nil, tls.Dial is used.
	//
	// If the returned net.Conn has a ConnectionState method like tls.Conn,
	// it will be used to set http.Response.TLS.
	DialTLSContext func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for requests.
	//
	// If DialTLSContext and DialTLS is nil, tls.Dial is used.
	//
	// Deprecated: Use DialTLSContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialTLSContext takes priority.
	DialTLS func(network, addr string, cfg *tls.Config) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// ConnPool optionally specifies an alternate connection pool to use.
	// If nil, the default is used.
	ConnPool http2ClientConnPool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// AllowHTTP, if true, permits HTTP/2 requests using the insecure,
	// plain-text "http" scheme. Note that this does not enable h2c support.
	AllowHTTP bool

	// MaxHeaderListSize is the http2 SETTINGS_MAX_HEADER_LIST_SIZE to
	// send in the initial settings frame. It is how many bytes
	// of response headers are allowed. Unlike the http2 spec, zero here
	// means to use a default limit (currently 10MB). If you actually
	// want to advertise an unlimited value to the peer, Transport
	// interprets the highest possible value here (0xffffffff or 1<<32-1)
	// to mean no limit.
	MaxHeaderListSize uint32

	// MaxReadFrameSize is the http2 SETTINGS_MAX_FRAME_SIZE to send in the
	// initial settings frame. It is the size in bytes of the largest frame
	// payload that the sender is willing to receive. If 0, no setting is
	// sent, and the value is provided by the peer, which should be 16384
	// according to the spec:
	// https://datatracker.ietf.org/doc/html/rfc7540#section-6.5.2.
	// Values are bounded in the range 16k to 16M.
	MaxReadFrameSize uint32

	// MaxDecoderHeaderTableSize optionally specifies the http2
	// SETTINGS_HEADER_TABLE_SIZE to send in the initial settings frame. It
	// informs the remote endpoint of the maximum size of the header compression
	// table used to decode header blocks, in octets. If zero, the default value
	// of 4096 is used.
	MaxDecoderHeaderTableSize uint32

	// MaxEncoderHeaderTableSize optionally specifies an upper limit for the
	// header compression table used for encoding request headers. Received
	// SETTINGS_HEADER_TABLE_SIZE settings are capped at this limit. If zero,
	// the default value of 4096 is used.
	MaxEncoderHeaderTableSize uint32

	// StrictMaxConcurrentStreams controls whether the server's
	// SETTINGS_MAX_CONCURRENT_STREAMS should be respected
	// globally. If false, new TCP connections are created to the
	// server as needed to keep each under the per-connection
	// SETTINGS_MAX_CONCURRENT_STREAMS limit. If true, the
	// server's SETTINGS_MAX_CONCURRENT_STREAMS is interpreted as
	// a global limit and callers of RoundTrip block when needed,
	// waiting for their turn.
	StrictMaxConcurrentStreams bool

	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration

	// ReadIdleTimeout is the timeout after which a health check using ping
	// frame will be carried out if no frame is received on the connection.
	// Note that a ping response will is considered a received frame, so if
	// there is no other traffic on the connection, the health check will
	// be performed every ReadIdleTimeout interval.
	// If zero, no health check is performed.
	ReadIdleTimeout time.Duration

	// PingTimeout is the timeout after which the connection will be closed
	// if a response to Ping is not received.
	// Defaults to 15s.
	PingTimeout time.Duration

	// WriteByteTimeout is the timeout after which the connection will be
	// closed no data can be written to it. The timeout begins when data is
	// available to write, and is extended whenever any bytes are written.
	WriteByteTimeout time.Duration

	// CountError, if non-nil, is called on HTTP/2 transport errors.
	// It's intended to increment a metric for monitoring, such
	// as an expvar or Prometheus metric.
	// The errType consists of only ASCII word characters.
	CountError func(errType string)

	// t1, if non-nil, is the standard library Transport using
	// this transport. Its settings are used (but not its
	// RoundTrip method, etc).
	t1 *Transport

	connPoolOnce  sync.Once
	connPoolOrDef http2ClientConnPool // non-nil version of ConnPool

	*http2transportTestHooks
}

// Hook points used for testing.
// Outside of tests, t.transportTestHooks is nil and these all have minimal implementations.
// Inside tests, see the testSyncHooks function docs.

type http2transportTestHooks struct {
	newclientconn func(*http2ClientConn)
	group         http2synctestGroupInterface
}

func (t *http2Transport) markNewGoroutine() {
	if t != nil && t.http2transportTestHooks != nil {
		t.http2transportTestHooks.group.Join()
	}
}

func (t *http2Transport) now() time.Time {
	if t != nil && t.http2transportTestHooks != nil {
		return t.http2transportTestHooks.group.Now()
	}
	return time.Now()
}

func (t *http2Transport) timeSince(when time.Time) time.Duration {
	if t != nil && t.http2transportTestHooks != nil {
		return t.now().Sub(when)
	}
	return time.Since(when)
}

// newTimer creates a new time.Timer, or a synthetic timer in tests.
func (t *http2Transport) newTimer(d time.Duration) http2timer {
	if t.http2transportTestHooks != nil {
		return t.http2transportTestHooks.group.NewTimer(d)
	}
	return http2timeTimer{time.NewTimer(d)}
}

// afterFunc creates a new time.AfterFunc timer, or a synthetic timer in tests.
func (t *http2Transport) afterFunc(d time.Duration, f func()) http2timer {
	if t.http2transportTestHooks != nil {
		return t.http2transportTestHooks.group.AfterFunc(d, f)
	}
	return http2timeTimer{time.AfterFunc(d, f)}
}

func (t *http2Transport) contextWithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if t.http2transportTestHooks != nil {
		return t.http2transportTestHooks.group.ContextWithTimeout(ctx, d)
	}
	return context.WithTimeout(ctx, d)
}

func (t *http2Transport) maxHeaderListSize() uint32 {
	n := int64(t.MaxHeaderListSize)
	if t.t1 != nil && t.t1.MaxResponseHeaderBytes != 0 {
		n = t.t1.MaxResponseHeaderBytes
		if n > 0 {
			n = http2adjustHTTP1MaxHeaderSize(n)
		}
	}
	if n <= 0 {
		return 10 << 20
	}
	if n >= 0xffffffff {
		return 0
	}
	return uint32(n)
}

func (t *http2Transport) disableCompression() bool {
	return t.DisableCompression || (t.t1 != nil && t.t1.DisableCompression)
}

// ConfigureTransport configures a net/http HTTP/1 Transport to use HTTP/2.
// It returns an error if t1 has already been HTTP/2-enabled.
//
// Use ConfigureTransports instead to configure the HTTP/2 Transport.
func http2ConfigureTransport(t1 *Transport) error {
	_, err := http2ConfigureTransports(t1)
	return err
}

// ConfigureTransports configures a net/http HTTP/1 Transport to use HTTP/2.
// It returns a new HTTP/2 Transport for further configuration.
// It returns an error if t1 has already been HTTP/2-enabled.
func http2ConfigureTransports(t1 *Transport) (*http2Transport, error) {
	return http2configureTransports(t1)
}

func http2configureTransports(t1 *Transport) (*http2Transport, error) {
	connPool := new(http2clientConnPool)
	t2 := &http2Transport{
		ConnPool: http2noDialClientConnPool{connPool},
		t1:       t1,
	}
	connPool.t = t2
	if err := http2registerHTTPSProtocol(t1, http2noDialH2RoundTripper{t2}); err != nil {
		return nil, err
	}
	if t1.TLSClientConfig == nil {
		t1.TLSClientConfig = new(tls.Config)
	}
	if !http2strSliceContains(t1.TLSClientConfig.NextProtos, "h2") {
		t1.TLSClientConfig.NextProtos = append([]string{"h2"}, t1.TLSClientConfig.NextProtos...)
	}
	if !http2strSliceContains(t1.TLSClientConfig.NextProtos, "http/1.1") {
		t1.TLSClientConfig.NextProtos = append(t1.TLSClientConfig.NextProtos, "http/1.1")
	}
	upgradeFn := func(scheme, authority string, c net.Conn) RoundTripper {
		addr := http2authorityAddr(scheme, authority)
		if used, err := connPool.addConnIfNeeded(addr, t2, c); err != nil {
			go c.Close()
			return http2erringRoundTripper{err}
		} else if !used {
			// Turns out we don't need this c.
			// For example, two goroutines made requests to the same host
			// at the same time, both kicking off TCP dials. (since protocol
			// was unknown)
			go c.Close()
		}
		if scheme == "http" {
			return (*http2unencryptedTransport)(t2)
		}
		return t2
	}
	if t1.TLSNextProto == nil {
		t1.TLSNextProto = make(map[string]func(string, *tls.Conn) RoundTripper)
	}
	t1.TLSNextProto[http2NextProtoTLS] = func(authority string, c *tls.Conn) RoundTripper {
		return upgradeFn("https", authority, c)
	}
	// The "unencrypted_http2" TLSNextProto key is used to pass off non-TLS HTTP/2 conns.
	t1.TLSNextProto[http2nextProtoUnencryptedHTTP2] = func(authority string, c *tls.Conn) RoundTripper {
		nc, err := http2unencryptedNetConnFromTLSConn(c)
		if err != nil {
			go c.Close()
			return http2erringRoundTripper{err}
		}
		return upgradeFn("http", authority, nc)
	}
	return t2, nil
}

// unencryptedTransport is a Transport with a RoundTrip method that
// always permits http:// URLs.
type http2unencryptedTransport http2Transport

func (t *http2unencryptedTransport) RoundTrip(req *Request) (*Response, error) {
	return (*http2Transport)(t).RoundTripOpt(req, http2RoundTripOpt{allowHTTP: true})
}

func (t *http2Transport) connPool() http2ClientConnPool {
	t.connPoolOnce.Do(t.initConnPool)
	return t.connPoolOrDef
}

func (t *http2Transport) initConnPool() {
	if t.ConnPool != nil {
		t.connPoolOrDef = t.ConnPool
	} else {
		t.connPoolOrDef = &http2clientConnPool{t: t}
	}
}

// ClientConn is the state of a single HTTP/2 client connection to an
// HTTP/2 server.
type http2ClientConn struct {
	t             *http2Transport
	tconn         net.Conn             // usually *tls.Conn, except specialized impls
	tlsState      *tls.ConnectionState // nil only for specialized impls
	atomicReused  uint32               // whether conn is being reused; atomic
	singleUse     bool                 // whether being used for a single http.Request
	getConnCalled bool                 // used by clientConnPool

	// readLoop goroutine fields:
	readerDone chan struct{} // closed on error
	readerErr  error         // set before readerDone is closed

	idleTimeout time.Duration // or 0 for never
	idleTimer   http2timer

	mu               sync.Mutex   // guards following
	cond             *sync.Cond   // hold mu; broadcast on flow/closed changes
	flow             http2outflow // our conn-level flow control quota (cs.outflow is per stream)
	inflow           http2inflow  // peer's conn-level flow control
	doNotReuse       bool         // whether conn is marked to not be reused for any future requests
	closing          bool
	closed           bool
	seenSettings     bool                          // true if we've seen a settings frame, false otherwise
	seenSettingsChan chan struct{}
```