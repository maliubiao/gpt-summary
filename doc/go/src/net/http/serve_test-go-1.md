Response:
The user wants a summary of the functionality of the provided Go code snippet, which is a part of `go/src/net/http/serve_test.go`. This file seems to contain tests for the `net/http` package, specifically focusing on the server-side behavior.

I need to analyze the code and identify the different test cases and what aspects of the HTTP server they are testing.

Here's a breakdown of the code's functionality:

1. **Content-Length Handling:** Tests how the server handles `Content-Length` headers, including cases where the written response body doesn't match the declared length.
2. **Transfer-Encoding:** Checks how the server responds with different `Transfer-Encoding` values (identity, chunked).
3. **Connection Closing:** Tests various scenarios that lead to the server closing the TCP connection, such as HTTP/1.0 requests, client-initiated closure, server-initiated closure using the `Connection: close` header, and HTTP/2 upgrade requests.
4. **Keep-Alive Connections:** Verifies that connections are kept alive for subsequent requests in certain scenarios, particularly with HTTP/1.0 and HTTP/1.1 and specific status codes like 204 and 304.
5. **Remote Address:** Tests that the server correctly sets the `r.RemoteAddr` field in the request. It also includes a more complex test to handle cases where accessing the remote address might block.
6. **HEAD Requests:** Ensures that `HEAD` requests are handled correctly, including setting `Content-Type` and `Content-Length` headers without sending the body.
7. **TLS Handshake Timeout:** Checks if the server handles TLS handshake timeouts as expected.
8. **TLS Server Basics:** Verifies basic TLS functionality, such as the `r.TLS` field being set and the handshake being complete.
9. **ServeTLS Function:** Tests the `ServeTLS` function, which allows starting an HTTPS server with a specified TLS configuration.
10. **Rejecting Plain HTTP on TLS:**  Ensures that an HTTPS server rejects plaintext HTTP requests.
11. **Automatic HTTP/2 Configuration:** Tests how the server automatically configures HTTP/2 based on the TLS configuration provided.
12. **Expect Header Handling:** Tests the server's behavior when receiving requests with the `Expect` header, specifically for "100-continue".
13. **Handling Unread Request Bodies:** Examines how the server deals with unread request bodies, with different behavior for small and large bodies.
14. **Handler Body Closing:** Tests the behavior of closing the request body in the handler, particularly regarding searching for the end of the request and handling subsequent requests on the same connection.
15. **Request Body Read Errors:** Checks if the server closes the connection when encountering errors while reading the request body.
16. **Invalid Trailers:** Tests if the server closes the connection when encountering invalid HTTP trailers.
这段代码是 `go/src/net/http/serve_test.go` 文件的一部分，它主要测试了 `net/http` 包中 **HTTP 服务器** 处理请求和响应的各种细节，特别是关于 **连接管理、Content-Length、Transfer-Encoding、Expect 头部、TLS 以及错误处理** 等方面。

总的来说，这段代码的主要功能可以归纳为：**测试 `net/http` 包中 HTTP 服务器在各种场景下的正确性和健壮性。**

更具体地来说，它测试了以下几个方面：

1. **验证服务器对 `Content-Length` 的处理：**
   - 检查服务器在响应中设置正确的 `Content-Length` 头部。
   - 测试当实际写入的响应体长度与 `Content-Length` 不符时服务器的行为（例如，写入过多会返回 `ErrContentLength`，写入过少在 HTTP/1.1 下会导致连接关闭）。

2. **验证服务器对 `Transfer-Encoding` 的处理：**
   - 检查服务器如何处理请求中的 `Transfer-Encoding` 头部。
   - 测试在没有指定 `Transfer-Encoding` 或指定为 `identity` 时，服务器如何处理响应。

3. **验证服务器对连接关闭的处理：**
   - 测试在 HTTP/1.0 请求后连接会被关闭。
   - 测试客户端可以通过发送 `Connection: close` 头部来强制关闭连接。
   - 测试服务端可以通过设置 `Connection: close` 头部来强制关闭连接，即使是 HTTP/1.1 请求。
   - 测试 HTTP/2 升级请求会导致连接关闭。

4. **验证服务器对连接保持活跃的处理：**
   - 测试在 HTTP/1.0 请求中包含 `Connection: keep-alive` 头部，并且响应状态码为 204 或 304 时，连接会保持活跃。
   - 测试 HTTP/1.1 请求默认保持连接活跃。

5. **验证服务器如何设置 `r.RemoteAddr`：**
   - 确保请求处理函数中 `r.RemoteAddr` 包含了客户端的 IP 地址和端口。
   - 测试即使在 `RemoteAddr()` 方法阻塞的情况下，服务器也能正常处理请求。

6. **验证服务器对 `HEAD` 请求的处理：**
   - 确保 `HEAD` 请求的响应包含了正确的头部信息（如 `Content-Type` 和 `Content-Length`），但不包含响应体。
   - 测试 `ResponseWriter.ReadFrom` 在处理 `HEAD` 请求时不会写入响应体。

7. **验证服务器的 TLS 相关功能：**
   - 测试服务器处理 TLS 握手超时的情况。
   - 验证在 HTTPS 服务器中，请求的 `r.TLS` 字段会被正确设置。
   - 测试 `ServeTLS` 函数可以正常启动 HTTPS 服务器。
   - 验证 HTTPS 服务器会拒绝普通的 HTTP 请求。

8. **验证 HTTP/2 的自动配置：**
   - 测试当 `Server` 的 `TLSConfig` 设置为支持 HTTP/2 时，HTTP/2 会自动启用。
   - 测试 `ListenAndServeTLS` 在配置了 TLS 的情况下，会自动支持 HTTP/2。

9. **验证服务器对 `Expect` 请求头的处理：**
   - 测试服务器如何响应包含 `Expect: 100-continue` 的请求。
   - 检查服务器在收到包含 `Expect` 头部但无法满足期望时，返回 `417 Expectation Failed`。

10. **验证服务器对未读取的请求体的处理：**
    - 测试对于小的未读取的请求体，服务器会消耗掉剩余的数据。
    - 测试对于大的未读取的请求体，服务器会关闭连接。

11. **验证在请求处理函数中关闭请求体 `r.Body.Close()` 的行为：**
    - 测试 `r.Body.Close()` 是否会读取剩余的请求体数据，以便复用连接。
    - 针对不同大小、是否分块以及是否设置 `Connection: close` 头部的情况进行测试。

12. **验证读取请求体时发生错误时的处理：**
    - 测试当读取请求体时发生错误（例如，分块编码格式错误）时，服务器会关闭连接。

13. **验证无效的 Trailer 的处理：**
    - 测试当请求中包含无效的 Trailer 时，服务器会关闭连接。

**功能归纳：**

这段代码主要测试了 Go 语言 `net/http` 包中 **HTTP 服务器的核心功能，涵盖了连接管理、请求和响应的头部处理、TLS 支持以及错误处理机制。** 它通过构造各种不同的 HTTP 请求场景，并断言服务器的响应和行为是否符合预期，从而保证了 HTTP 服务器的正确性和可靠性。

**代码示例（验证服务器对 `Content-Length` 的处理）：**

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContentLengthMismatch(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		n, err := w.Write([]byte("hello world"))
		if err != nil {
			t.Errorf("写入错误: %v", err)
		}
		if n != len("hello world") {
			t.Errorf("写入字节数不匹配: got %d, want %d", n, len("hello world"))
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 假设的输入：服务器返回 "hello world"，Content-Length 为 5
	// 假设的输出：客户端可能会收到截断的响应，或者连接会被关闭（取决于 HTTP 版本）。

	body, err := io.ReadAll(resp.Body)
	if err == nil { // 对于 HTTP/1.1，可能会出现错误
		t.Logf("响应体: %s", string(body))
	} else {
		t.Logf("读取响应体时发生错误: %v", err)
	}

	// 在 serve_test.go 中，会更细致地检查是否返回了 ErrContentLength
}

func main() {
	testing.Main(func(pattern, str string) bool { return true }, []testing.InternalTest{
		{Name: "TestContentLengthMismatch", F: TestContentLengthMismatch},
	}, []testing.InternalBenchmark{})
}
```

**易犯错的点：**

在测试 HTTP 服务器时，一个常见的错误是 **没有正确地处理连接的关闭**。例如，如果服务器在处理完请求后没有关闭连接，而客户端认为连接已经关闭，则后续的请求可能会失败。

**例子：**

假设一个 HTTP/1.0 服务器处理完请求后没有主动关闭连接，而客户端又立即发送了下一个请求，可能会导致服务器无法正确解析第二个请求。

这段代码通过大量的测试用例，覆盖了各种连接管理场景，有助于开发者理解和避免这些常见的错误。

### 提示词
```
这是路径为go/src/net/http/serve_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
tent-Length", "3")
		rw.Header().Set("Transfer-Encoding", req.FormValue("te"))
		switch {
		case req.FormValue("overwrite") == "1":
			_, err := rw.Write([]byte("foo TOO LONG"))
			if err != ErrContentLength {
				t.Errorf("expected ErrContentLength; got %v", err)
			}
		case req.FormValue("underwrite") == "1":
			rw.Header().Set("Content-Length", "500")
			rw.Write([]byte("too short"))
		default:
			rw.Write([]byte("foo"))
		}
	})

	ts := newClientServerTest(t, mode, handler).ts
	c := ts.Client()

	// Note: this relies on the assumption (which is true) that
	// Get sends HTTP/1.1 or greater requests. Otherwise the
	// server wouldn't have the choice to send back chunked
	// responses.
	for _, te := range []string{"", "identity"} {
		url := ts.URL + "/?te=" + te
		res, err := c.Get(url)
		if err != nil {
			t.Fatalf("error with Get of %s: %v", url, err)
		}
		if cl, expected := res.ContentLength, int64(3); cl != expected {
			t.Errorf("for %s expected res.ContentLength of %d; got %d", url, expected, cl)
		}
		if cl, expected := res.Header.Get("Content-Length"), "3"; cl != expected {
			t.Errorf("for %s expected Content-Length header of %q; got %q", url, expected, cl)
		}
		if tl, expected := len(res.TransferEncoding), 0; tl != expected {
			t.Errorf("for %s expected len(res.TransferEncoding) of %d; got %d (%v)",
				url, expected, tl, res.TransferEncoding)
		}
		res.Body.Close()
	}

	// Verify that ErrContentLength is returned
	url := ts.URL + "/?overwrite=1"
	res, err := c.Get(url)
	if err != nil {
		t.Fatalf("error with Get of %s: %v", url, err)
	}
	res.Body.Close()

	if mode != http1Mode {
		return
	}

	// Verify that the connection is closed when the declared Content-Length
	// is larger than what the handler wrote.
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("error dialing: %v", err)
	}
	_, err = conn.Write([]byte("GET /?underwrite=1 HTTP/1.1\r\nHost: foo\r\n\r\n"))
	if err != nil {
		t.Fatalf("error writing: %v", err)
	}

	// The ReadAll will hang for a failing test.
	got, _ := io.ReadAll(conn)
	expectedSuffix := "\r\n\r\ntoo short"
	if !strings.HasSuffix(string(got), expectedSuffix) {
		t.Errorf("Expected output to end with %q; got response body %q",
			expectedSuffix, string(got))
	}
}

func testTCPConnectionCloses(t *testing.T, req string, h Handler) {
	setParallel(t)
	s := newClientServerTest(t, http1Mode, h).ts

	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal("dial error:", err)
	}
	defer conn.Close()

	_, err = fmt.Fprint(conn, req)
	if err != nil {
		t.Fatal("print error:", err)
	}

	r := bufio.NewReader(conn)
	res, err := ReadResponse(r, &Request{Method: "GET"})
	if err != nil {
		t.Fatal("ReadResponse error:", err)
	}

	_, err = io.ReadAll(r)
	if err != nil {
		t.Fatal("read error:", err)
	}

	if !res.Close {
		t.Errorf("Response.Close = false; want true")
	}
}

func testTCPConnectionStaysOpen(t *testing.T, req string, handler Handler) {
	setParallel(t)
	ts := newClientServerTest(t, http1Mode, handler).ts
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatal(err)
		}
		res, err := ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("res %d: %v", i+1, err)
		}
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			t.Fatalf("res %d body copy: %v", i+1, err)
		}
		res.Body.Close()
	}
}

// TestServeHTTP10Close verifies that HTTP/1.0 requests won't be kept alive.
func TestServeHTTP10Close(t *testing.T) {
	testTCPConnectionCloses(t, "GET / HTTP/1.0\r\n\r\n", HandlerFunc(func(w ResponseWriter, r *Request) {
		ServeFile(w, r, "testdata/file")
	}))
}

// TestClientCanClose verifies that clients can also force a connection to close.
func TestClientCanClose(t *testing.T) {
	testTCPConnectionCloses(t, "GET / HTTP/1.1\r\nHost: foo\r\nConnection: close\r\n\r\n", HandlerFunc(func(w ResponseWriter, r *Request) {
		// Nothing.
	}))
}

// TestHandlersCanSetConnectionClose verifies that handlers can force a connection to close,
// even for HTTP/1.1 requests.
func TestHandlersCanSetConnectionClose11(t *testing.T) {
	testTCPConnectionCloses(t, "GET / HTTP/1.1\r\nHost: foo\r\n\r\n\r\n", HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Connection", "close")
	}))
}

func TestHandlersCanSetConnectionClose10(t *testing.T) {
	testTCPConnectionCloses(t, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Connection", "close")
	}))
}

func TestHTTP2UpgradeClosesConnection(t *testing.T) {
	testTCPConnectionCloses(t, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", HandlerFunc(func(w ResponseWriter, r *Request) {
		// Nothing. (if not hijacked, the server should close the connection
		// afterwards)
	}))
}

func send204(w ResponseWriter, r *Request) { w.WriteHeader(204) }
func send304(w ResponseWriter, r *Request) { w.WriteHeader(304) }

// Issue 15647: 204 responses can't have bodies, so HTTP/1.0 keep-alive conns should stay open.
func TestHTTP10KeepAlive204Response(t *testing.T) {
	testTCPConnectionStaysOpen(t, "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", HandlerFunc(send204))
}

func TestHTTP11KeepAlive204Response(t *testing.T) {
	testTCPConnectionStaysOpen(t, "GET / HTTP/1.1\r\nHost: foo\r\n\r\n", HandlerFunc(send204))
}

func TestHTTP10KeepAlive304Response(t *testing.T) {
	testTCPConnectionStaysOpen(t,
		"GET / HTTP/1.0\r\nConnection: keep-alive\r\nIf-Modified-Since: Mon, 02 Jan 2006 15:04:05 GMT\r\n\r\n",
		HandlerFunc(send304))
}

// Issue 15703
func TestKeepAliveFinalChunkWithEOF(t *testing.T) { run(t, testKeepAliveFinalChunkWithEOF) }
func testKeepAliveFinalChunkWithEOF(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.(Flusher).Flush() // force chunked encoding
		w.Write([]byte("{\"Addr\": \"" + r.RemoteAddr + "\"}"))
	}))
	type data struct {
		Addr string
	}
	var addrs [2]data
	for i := range addrs {
		res, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewDecoder(res.Body).Decode(&addrs[i]); err != nil {
			t.Fatal(err)
		}
		if addrs[i].Addr == "" {
			t.Fatal("no address")
		}
		res.Body.Close()
	}
	if addrs[0] != addrs[1] {
		t.Fatalf("connection not reused")
	}
}

func TestSetsRemoteAddr(t *testing.T) { run(t, testSetsRemoteAddr) }
func testSetsRemoteAddr(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "%s", r.RemoteAddr)
	}))

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	ip := string(body)
	if !strings.HasPrefix(ip, "127.0.0.1:") && !strings.HasPrefix(ip, "[::1]:") {
		t.Fatalf("Expected local addr; got %q", ip)
	}
}

type blockingRemoteAddrListener struct {
	net.Listener
	conns chan<- net.Conn
}

func (l *blockingRemoteAddrListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	brac := &blockingRemoteAddrConn{
		Conn:  c,
		addrs: make(chan net.Addr, 1),
	}
	l.conns <- brac
	return brac, nil
}

type blockingRemoteAddrConn struct {
	net.Conn
	addrs chan net.Addr
}

func (c *blockingRemoteAddrConn) RemoteAddr() net.Addr {
	return <-c.addrs
}

// Issue 12943
func TestServerAllowsBlockingRemoteAddr(t *testing.T) {
	run(t, testServerAllowsBlockingRemoteAddr, []testMode{http1Mode})
}
func testServerAllowsBlockingRemoteAddr(t *testing.T, mode testMode) {
	conns := make(chan net.Conn)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "RA:%s", r.RemoteAddr)
	}), func(ts *httptest.Server) {
		ts.Listener = &blockingRemoteAddrListener{
			Listener: ts.Listener,
			conns:    conns,
		}
	}).ts

	c := ts.Client()
	// Force separate connection for each:
	c.Transport.(*Transport).DisableKeepAlives = true

	fetch := func(num int, response chan<- string) {
		resp, err := c.Get(ts.URL)
		if err != nil {
			t.Errorf("Request %d: %v", num, err)
			response <- ""
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Request %d: %v", num, err)
			response <- ""
			return
		}
		response <- string(body)
	}

	// Start a request. The server will block on getting conn.RemoteAddr.
	response1c := make(chan string, 1)
	go fetch(1, response1c)

	// Wait for the server to accept it; grab the connection.
	conn1 := <-conns

	// Start another request and grab its connection
	response2c := make(chan string, 1)
	go fetch(2, response2c)
	conn2 := <-conns

	// Send a response on connection 2.
	conn2.(*blockingRemoteAddrConn).addrs <- &net.TCPAddr{
		IP: net.ParseIP("12.12.12.12"), Port: 12}

	// ... and see it
	response2 := <-response2c
	if g, e := response2, "RA:12.12.12.12:12"; g != e {
		t.Fatalf("response 2 addr = %q; want %q", g, e)
	}

	// Finish the first response.
	conn1.(*blockingRemoteAddrConn).addrs <- &net.TCPAddr{
		IP: net.ParseIP("21.21.21.21"), Port: 21}

	// ... and see it
	response1 := <-response1c
	if g, e := response1, "RA:21.21.21.21:21"; g != e {
		t.Fatalf("response 1 addr = %q; want %q", g, e)
	}
}

// TestHeadResponses verifies that all MIME type sniffing and Content-Length
// counting of GET requests also happens on HEAD requests.
func TestHeadResponses(t *testing.T) { run(t, testHeadResponses) }
func testHeadResponses(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := w.Write([]byte("<html>"))
		if err != nil {
			t.Errorf("ResponseWriter.Write: %v", err)
		}

		// Also exercise the ReaderFrom path
		_, err = io.Copy(w, struct{ io.Reader }{strings.NewReader("789a")})
		if err != nil {
			t.Errorf("Copy(ResponseWriter, ...): %v", err)
		}
	}))
	res, err := cst.c.Head(cst.ts.URL)
	if err != nil {
		t.Error(err)
	}
	if len(res.TransferEncoding) > 0 {
		t.Errorf("expected no TransferEncoding; got %v", res.TransferEncoding)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type: %q; want text/html; charset=utf-8", ct)
	}
	if v := res.ContentLength; v != 10 {
		t.Errorf("Content-Length: %d; want 10", v)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}
	if len(body) > 0 {
		t.Errorf("got unexpected body %q", string(body))
	}
}

// Ensure ResponseWriter.ReadFrom doesn't write a body in response to a HEAD request.
// https://go.dev/issue/68609
func TestHeadReaderFrom(t *testing.T) { run(t, testHeadReaderFrom, []testMode{http1Mode}) }
func testHeadReaderFrom(t *testing.T, mode testMode) {
	// Body is large enough to exceed the content-sniffing length.
	wantBody := strings.Repeat("a", 4096)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.(io.ReaderFrom).ReadFrom(strings.NewReader(wantBody))
	}))
	res, err := cst.c.Head(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	res, err = cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	gotBody, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBody) != wantBody {
		t.Errorf("got unexpected body len=%v, want %v", len(gotBody), len(wantBody))
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	run(t, testTLSHandshakeTimeout, []testMode{https1Mode, http2Mode})
}
func testTLSHandshakeTimeout(t *testing.T, mode testMode) {
	errLog := new(strings.Builder)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {}),
		func(ts *httptest.Server) {
			ts.Config.ReadTimeout = 250 * time.Millisecond
			ts.Config.ErrorLog = log.New(errLog, "", 0)
		},
	)
	ts := cst.ts

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if err == nil || n != 0 {
		t.Errorf("Read = %d, %v; want an error and no bytes", n, err)
	}
	conn.Close()

	cst.close()
	if v := errLog.String(); !strings.Contains(v, "timeout") && !strings.Contains(v, "TLS handshake") {
		t.Errorf("expected a TLS handshake timeout error; got %q", v)
	}
}

func TestTLSServer(t *testing.T) { run(t, testTLSServer, []testMode{https1Mode, http2Mode}) }
func testTLSServer(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.TLS != nil {
			w.Header().Set("X-TLS-Set", "true")
			if r.TLS.HandshakeComplete {
				w.Header().Set("X-TLS-HandshakeComplete", "true")
			}
		}
	}), func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	}).ts

	// Connect an idle TCP connection to this server before we run
	// our real tests. This idle connection used to block forever
	// in the TLS handshake, preventing future connections from
	// being accepted. It may prevent future accidental blocking
	// in newConn.
	idleConn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer idleConn.Close()

	if !strings.HasPrefix(ts.URL, "https://") {
		t.Errorf("expected test TLS server to start with https://, got %q", ts.URL)
		return
	}
	client := ts.Client()
	res, err := client.Get(ts.URL)
	if err != nil {
		t.Error(err)
		return
	}
	if res == nil {
		t.Errorf("got nil Response")
		return
	}
	defer res.Body.Close()
	if res.Header.Get("X-TLS-Set") != "true" {
		t.Errorf("expected X-TLS-Set response header")
		return
	}
	if res.Header.Get("X-TLS-HandshakeComplete") != "true" {
		t.Errorf("expected X-TLS-HandshakeComplete header")
	}
}

func TestServeTLS(t *testing.T) {
	CondSkipHTTP2(t)
	// Not parallel: uses global test hooks.
	defer afterTest(t)
	defer SetTestHookServerServe(nil)

	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln := newLocalListener(t)
	defer ln.Close()
	addr := ln.Addr().String()

	serving := make(chan bool, 1)
	SetTestHookServerServe(func(s *Server, ln net.Listener) {
		serving <- true
	})
	handler := HandlerFunc(func(w ResponseWriter, r *Request) {})
	s := &Server{
		Addr:      addr,
		TLSConfig: tlsConf,
		Handler:   handler,
	}
	errc := make(chan error, 1)
	go func() { errc <- s.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		t.Fatalf("ServeTLS: %v", err)
	case <-serving:
	}

	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got, want := c.ConnectionState().NegotiatedProtocol, "h2"; got != want {
		t.Errorf("NegotiatedProtocol = %q; want %q", got, want)
	}
	if got, want := c.ConnectionState().NegotiatedProtocolIsMutual, true; got != want {
		t.Errorf("NegotiatedProtocolIsMutual = %v; want %v", got, want)
	}
}

// Test that the HTTPS server nicely rejects plaintext HTTP/1.x requests.
func TestTLSServerRejectHTTPRequests(t *testing.T) {
	run(t, testTLSServerRejectHTTPRequests, []testMode{https1Mode, http2Mode})
}
func testTLSServerRejectHTTPRequests(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		t.Error("unexpected HTTPS request")
	}), func(ts *httptest.Server) {
		var errBuf bytes.Buffer
		ts.Config.ErrorLog = log.New(&errBuf, "", 0)
	}).ts
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: foo\r\n\r\n")
	slurp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	const wantPrefix = "HTTP/1.0 400 Bad Request\r\n"
	if !strings.HasPrefix(string(slurp), wantPrefix) {
		t.Errorf("response = %q; wanted prefix %q", slurp, wantPrefix)
	}
}

// Issue 15908
func TestAutomaticHTTP2_Serve_NoTLSConfig(t *testing.T) {
	testAutomaticHTTP2_Serve(t, nil, true)
}

func TestAutomaticHTTP2_Serve_NonH2TLSConfig(t *testing.T) {
	testAutomaticHTTP2_Serve(t, &tls.Config{}, false)
}

func TestAutomaticHTTP2_Serve_H2TLSConfig(t *testing.T) {
	testAutomaticHTTP2_Serve(t, &tls.Config{NextProtos: []string{"h2"}}, true)
}

func testAutomaticHTTP2_Serve(t *testing.T, tlsConf *tls.Config, wantH2 bool) {
	setParallel(t)
	defer afterTest(t)
	ln := newLocalListener(t)
	ln.Close() // immediately (not a defer!)
	var s Server
	s.TLSConfig = tlsConf
	if err := s.Serve(ln); err == nil {
		t.Fatal("expected an error")
	}
	gotH2 := s.TLSNextProto["h2"] != nil
	if gotH2 != wantH2 {
		t.Errorf("http2 configured = %v; want %v", gotH2, wantH2)
	}
}

func TestAutomaticHTTP2_Serve_WithTLSConfig(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	ln := newLocalListener(t)
	ln.Close() // immediately (not a defer!)
	var s Server
	// Set the TLSConfig. In reality, this would be the
	// *tls.Config given to tls.NewListener.
	s.TLSConfig = &tls.Config{
		NextProtos: []string{"h2"},
	}
	if err := s.Serve(ln); err == nil {
		t.Fatal("expected an error")
	}
	on := s.TLSNextProto["h2"] != nil
	if !on {
		t.Errorf("http2 wasn't automatically enabled")
	}
}

func TestAutomaticHTTP2_ListenAndServe(t *testing.T) {
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	testAutomaticHTTP2_ListenAndServe(t, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
}

func TestAutomaticHTTP2_ListenAndServe_GetCertificate(t *testing.T) {
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	testAutomaticHTTP2_ListenAndServe(t, &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	})
}

func TestAutomaticHTTP2_ListenAndServe_GetConfigForClient(t *testing.T) {
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	conf := &tls.Config{
		// GetConfigForClient requires specifying a full tls.Config so we must set
		// NextProtos ourselves.
		NextProtos:   []string{"h2"},
		Certificates: []tls.Certificate{cert},
	}
	testAutomaticHTTP2_ListenAndServe(t, &tls.Config{
		GetConfigForClient: func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
			return conf, nil
		},
	})
}

func testAutomaticHTTP2_ListenAndServe(t *testing.T, tlsConf *tls.Config) {
	CondSkipHTTP2(t)
	// Not parallel: uses global test hooks.
	defer afterTest(t)
	defer SetTestHookServerServe(nil)
	var ok bool
	var s *Server
	const maxTries = 5
	var ln net.Listener
Try:
	for try := 0; try < maxTries; try++ {
		ln = newLocalListener(t)
		addr := ln.Addr().String()
		ln.Close()
		t.Logf("Got %v", addr)
		lnc := make(chan net.Listener, 1)
		SetTestHookServerServe(func(s *Server, ln net.Listener) {
			lnc <- ln
		})
		s = &Server{
			Addr:      addr,
			TLSConfig: tlsConf,
		}
		errc := make(chan error, 1)
		go func() { errc <- s.ListenAndServeTLS("", "") }()
		select {
		case err := <-errc:
			t.Logf("On try #%v: %v", try+1, err)
			continue
		case ln = <-lnc:
			ok = true
			t.Logf("Listening on %v", ln.Addr().String())
			break Try
		}
	}
	if !ok {
		t.Fatalf("Failed to start up after %d tries", maxTries)
	}
	defer ln.Close()
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got, want := c.ConnectionState().NegotiatedProtocol, "h2"; got != want {
		t.Errorf("NegotiatedProtocol = %q; want %q", got, want)
	}
	if got, want := c.ConnectionState().NegotiatedProtocolIsMutual, true; got != want {
		t.Errorf("NegotiatedProtocolIsMutual = %v; want %v", got, want)
	}
}

type serverExpectTest struct {
	contentLength    int // of request body
	chunked          bool
	expectation      string // e.g. "100-continue"
	readBody         bool   // whether handler should read the body (if false, sends StatusUnauthorized)
	expectedResponse string // expected substring in first line of http response
}

func expectTest(contentLength int, expectation string, readBody bool, expectedResponse string) serverExpectTest {
	return serverExpectTest{
		contentLength:    contentLength,
		expectation:      expectation,
		readBody:         readBody,
		expectedResponse: expectedResponse,
	}
}

var serverExpectTests = []serverExpectTest{
	// Normal 100-continues, case-insensitive.
	expectTest(100, "100-continue", true, "100 Continue"),
	expectTest(100, "100-cOntInUE", true, "100 Continue"),

	// No 100-continue.
	expectTest(100, "", true, "200 OK"),

	// 100-continue but requesting client to deny us,
	// so it never reads the body.
	expectTest(100, "100-continue", false, "401 Unauthorized"),
	// Likewise without 100-continue:
	expectTest(100, "", false, "401 Unauthorized"),

	// Non-standard expectations are failures
	expectTest(0, "a-pony", false, "417 Expectation Failed"),

	// Expect-100 requested but no body (is apparently okay: Issue 7625)
	expectTest(0, "100-continue", true, "200 OK"),
	// Expect-100 requested but handler doesn't read the body
	expectTest(0, "100-continue", false, "401 Unauthorized"),
	// Expect-100 continue with no body, but a chunked body.
	{
		expectation:      "100-continue",
		readBody:         true,
		chunked:          true,
		expectedResponse: "100 Continue",
	},
}

// Tests that the server responds to the "Expect" request header
// correctly.
func TestServerExpect(t *testing.T) { run(t, testServerExpect, []testMode{http1Mode}) }
func testServerExpect(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// Note using r.FormValue("readbody") because for POST
		// requests that would read from r.Body, which we only
		// conditionally want to do.
		if strings.Contains(r.URL.RawQuery, "readbody=true") {
			io.ReadAll(r.Body)
			w.Write([]byte("Hi"))
		} else {
			w.WriteHeader(StatusUnauthorized)
		}
	})).ts

	runTest := func(test serverExpectTest) {
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()

		// Only send the body immediately if we're acting like an HTTP client
		// that doesn't send 100-continue expectations.
		writeBody := test.contentLength != 0 && strings.ToLower(test.expectation) != "100-continue"

		wg := sync.WaitGroup{}
		wg.Add(1)
		defer wg.Wait()

		go func() {
			defer wg.Done()

			contentLen := fmt.Sprintf("Content-Length: %d", test.contentLength)
			if test.chunked {
				contentLen = "Transfer-Encoding: chunked"
			}
			_, err := fmt.Fprintf(conn, "POST /?readbody=%v HTTP/1.1\r\n"+
				"Connection: close\r\n"+
				"%s\r\n"+
				"Expect: %s\r\nHost: foo\r\n\r\n",
				test.readBody, contentLen, test.expectation)
			if err != nil {
				t.Errorf("On test %#v, error writing request headers: %v", test, err)
				return
			}
			if writeBody {
				var targ io.WriteCloser = struct {
					io.Writer
					io.Closer
				}{
					conn,
					io.NopCloser(nil),
				}
				if test.chunked {
					targ = httputil.NewChunkedWriter(conn)
				}
				body := strings.Repeat("A", test.contentLength)
				_, err = fmt.Fprint(targ, body)
				if err == nil {
					err = targ.Close()
				}
				if err != nil {
					if !test.readBody {
						// Server likely already hung up on us.
						// See larger comment below.
						t.Logf("On test %#v, acceptable error writing request body: %v", test, err)
						return
					}
					t.Errorf("On test %#v, error writing request body: %v", test, err)
				}
			}
		}()
		bufr := bufio.NewReader(conn)
		line, err := bufr.ReadString('\n')
		if err != nil {
			if writeBody && !test.readBody {
				// This is an acceptable failure due to a possible TCP race:
				// We were still writing data and the server hung up on us. A TCP
				// implementation may send a RST if our request body data was known
				// to be lost, which may trigger our reads to fail.
				// See RFC 1122 page 88.
				t.Logf("On test %#v, acceptable error from ReadString: %v", test, err)
				return
			}
			t.Fatalf("On test %#v, ReadString: %v", test, err)
		}
		if !strings.Contains(line, test.expectedResponse) {
			t.Errorf("On test %#v, got first line = %q; want %q", test, line, test.expectedResponse)
		}
	}

	for _, test := range serverExpectTests {
		runTest(test)
	}
}

// Under a ~256KB (maxPostHandlerReadBytes) threshold, the server
// should consume client request bodies that a handler didn't read.
func TestServerUnreadRequestBodyLittle(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	conn := new(testConn)
	body := strings.Repeat("x", 100<<10)
	conn.readBuf.Write([]byte(fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: test\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n", len(body))))
	conn.readBuf.Write([]byte(body))

	done := make(chan bool)

	readBufLen := func() int {
		conn.readMu.Lock()
		defer conn.readMu.Unlock()
		return conn.readBuf.Len()
	}

	ls := &oneConnListener{conn}
	go Serve(ls, HandlerFunc(func(rw ResponseWriter, req *Request) {
		defer close(done)
		if bufLen := readBufLen(); bufLen < len(body)/2 {
			t.Errorf("on request, read buffer length is %d; expected about 100 KB", bufLen)
		}
		rw.WriteHeader(200)
		rw.(Flusher).Flush()
		if g, e := readBufLen(), 0; g != e {
			t.Errorf("after WriteHeader, read buffer length is %d; want %d", g, e)
		}
		if c := rw.Header().Get("Connection"); c != "" {
			t.Errorf(`Connection header = %q; want ""`, c)
		}
	}))
	<-done
}

// Over a ~256KB (maxPostHandlerReadBytes) threshold, the server
// should ignore client request bodies that a handler didn't read
// and close the connection.
func TestServerUnreadRequestBodyLarge(t *testing.T) {
	setParallel(t)
	if testing.Short() && testenv.Builder() == "" {
		t.Log("skipping in short mode")
	}
	conn := new(testConn)
	body := strings.Repeat("x", 1<<20)
	conn.readBuf.Write([]byte(fmt.Sprintf(
		"POST / HTTP/1.1\r\n"+
			"Host: test\r\n"+
			"Content-Length: %d\r\n"+
			"\r\n", len(body))))
	conn.readBuf.Write([]byte(body))
	conn.closec = make(chan bool, 1)

	ls := &oneConnListener{conn}
	go Serve(ls, HandlerFunc(func(rw ResponseWriter, req *Request) {
		if conn.readBuf.Len() < len(body)/2 {
			t.Errorf("on request, read buffer length is %d; expected about 1MB", conn.readBuf.Len())
		}
		rw.WriteHeader(200)
		rw.(Flusher).Flush()
		if conn.readBuf.Len() < len(body)/2 {
			t.Errorf("post-WriteHeader, read buffer length is %d; expected about 1MB", conn.readBuf.Len())
		}
	}))
	<-conn.closec

	if res := conn.writeBuf.String(); !strings.Contains(res, "Connection: close") {
		t.Errorf("Expected a Connection: close header; got response: %s", res)
	}
}

type handlerBodyCloseTest struct {
	bodySize     int
	bodyChunked  bool
	reqConnClose bool

	wantEOFSearch bool // should Handler's Body.Close do Reads, looking for EOF?
	wantNextReq   bool // should it find the next request on the same conn?
}

func (t handlerBodyCloseTest) connectionHeader() string {
	if t.reqConnClose {
		return "Connection: close\r\n"
	}
	return ""
}

var handlerBodyCloseTests = [...]handlerBodyCloseTest{
	// Small enough to slurp past to the next request +
	// has Content-Length.
	0: {
		bodySize:      20 << 10,
		bodyChunked:   false,
		reqConnClose:  false,
		wantEOFSearch: true,
		wantNextReq:   true,
	},

	// Small enough to slurp past to the next request +
	// is chunked.
	1: {
		bodySize:      20 << 10,
		bodyChunked:   true,
		reqConnClose:  false,
		wantEOFSearch: true,
		wantNextReq:   true,
	},

	// Small enough to slurp past to the next request +
	// has Content-Length +
	// declares Connection: close (so pointless to read more).
	2: {
		bodySize:      20 << 10,
		bodyChunked:   false,
		reqConnClose:  true,
		wantEOFSearch: false,
		wantNextReq:   false,
	},

	// Small enough to slurp past to the next request +
	// declares Connection: close,
	// but chunked, so it might have trailers.
	// TODO: maybe skip this search if no trailers were declared
	// in the headers.
	3: {
		bodySize:      20 << 10,
		bodyChunked:   true,
		reqConnClose:  true,
		wantEOFSearch: true,
		wantNextReq:   false,
	},

	// Big with Content-Length, so give up immediately if we know it's too big.
	4: {
		bodySize:      1 << 20,
		bodyChunked:   false, // has a Content-Length
		reqConnClose:  false,
		wantEOFSearch: false,
		wantNextReq:   false,
	},

	// Big chunked, so read a bit before giving up.
	5: {
		bodySize:      1 << 20,
		bodyChunked:   true,
		reqConnClose:  false,
		wantEOFSearch: true,
		wantNextReq:   false,
	},

	// Big with Connection: close, but chunked, so search for trailers.
	// TODO: maybe skip this search if no trailers were declared
	// in the headers.
	6: {
		bodySize:      1 << 20,
		bodyChunked:   true,
		reqConnClose:  true,
		wantEOFSearch: true,
		wantNextReq:   false,
	},

	// Big with Connection: close, so don't do any reads on Close.
	// With Content-Length.
	7: {
		bodySize:      1 << 20,
		bodyChunked:   false,
		reqConnClose:  true,
		wantEOFSearch: false,
		wantNextReq:   false,
	},
}

func TestHandlerBodyClose(t *testing.T) {
	setParallel(t)
	if testing.Short() && testenv.Builder() == "" {
		t.Skip("skipping in -short mode")
	}
	for i, tt := range handlerBodyCloseTests {
		testHandlerBodyClose(t, i, tt)
	}
}

func testHandlerBodyClose(t *testing.T, i int, tt handlerBodyCloseTest) {
	conn := new(testConn)
	body := strings.Repeat("x", tt.bodySize)
	if tt.bodyChunked {
		conn.readBuf.WriteString("POST / HTTP/1.1\r\n" +
			"Host: test\r\n" +
			tt.connectionHeader() +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n")
		cw := internal.NewChunkedWriter(&conn.readBuf)
		io.WriteString(cw, body)
		cw.Close()
		conn.readBuf.WriteString("\r\n")
	} else {
		conn.readBuf.Write([]byte(fmt.Sprintf(
			"POST / HTTP/1.1\r\n"+
				"Host: test\r\n"+
				tt.connectionHeader()+
				"Content-Length: %d\r\n"+
				"\r\n", len(body))))
		conn.readBuf.Write([]byte(body))
	}
	if !tt.reqConnClose {
		conn.readBuf.WriteString("GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	}
	conn.closec = make(chan bool, 1)

	readBufLen := func() int {
		conn.readMu.Lock()
		defer conn.readMu.Unlock()
		return conn.readBuf.Len()
	}

	ls := &oneConnListener{conn}
	var numReqs int
	var size0, size1 int
	go Serve(ls, HandlerFunc(func(rw ResponseWriter, req *Request) {
		numReqs++
		if numReqs == 1 {
			size0 = readBufLen()
			req.Body.Close()
			size1 = readBufLen()
		}
	}))
	<-conn.closec
	if numReqs < 1 || numReqs > 2 {
		t.Fatalf("%d. bug in test. unexpected number of requests = %d", i, numReqs)
	}
	didSearch := size0 != size1
	if didSearch != tt.wantEOFSearch {
		t.Errorf("%d. did EOF search = %v; want %v (size went from %d to %d)", i, didSearch, !didSearch, size0, size1)
	}
	if tt.wantNextReq && numReqs != 2 {
		t.Errorf("%d. numReq = %d; want 2", i, numReqs)
	}
}

// testHandlerBodyConsumer represents a function injected into a test handler to
// vary work done on a request Body.
type testHandlerBodyConsumer struct {
	name string
	f    func(io.ReadCloser)
}

var testHandlerBodyConsumers = []testHandlerBodyConsumer{
	{"nil", func(io.ReadCloser) {}},
	{"close", func(r io.ReadCloser) { r.Close() }},
	{"discard", func(r io.ReadCloser) { io.Copy(io.Discard, r) }},
}

func TestRequestBodyReadErrorClosesConnection(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	for _, handler := range testHandlerBodyConsumers {
		conn := new(testConn)
		conn.readBuf.WriteString("POST /public HTTP/1.1\r\n" +
			"Host: test\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"hax\r\n" + // Invalid chunked encoding
			"GET /secret HTTP/1.1\r\n" +
			"Host: test\r\n" +
			"\r\n")

		conn.closec = make(chan bool, 1)
		ls := &oneConnListener{conn}
		var numReqs int
		go Serve(ls, HandlerFunc(func(_ ResponseWriter, req *Request) {
			numReqs++
			if strings.Contains(req.URL.Path, "secret") {
				t.Error("Request for /secret encountered, should not have happened.")
			}
			handler.f(req.Body)
		}))
		<-conn.closec
		if numReqs != 1 {
			t.Errorf("Handler %v: got %d reqs; want 1", handler.name, numReqs)
		}
	}
}

func TestInvalidTrailerClosesConnection(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	for _, handler := range testHandlerBodyConsumers {
		conn := new(testConn)
		conn.readBuf.WriteString("POST /public HTTP/1.1\r\n" +
			"Host: test\r\n" +
			"Trailer: hack\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"3\r\n" +
			"hax\r\n" +
			"0\r\n" +
			"I'm not a valid trailer\r\n" +
			"GET /secret HTTP/1.1\r\n" +
			"Host: test\r\n" +
			"\r\n")

		conn.closec = make(chan bool, 1)
		ln := &oneConnListener{conn}
		var numReqs
```