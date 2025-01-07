Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of `go/src/net/http/serve_test.go`.

The code primarily focuses on testing various aspects of the `net/http` server, particularly around request handling, timeouts, connection management, and error conditions like panics.

Here's a breakdown of the code's functionalities:

1. **Testing Request Body Timeout:**  `TestRequestBodyTimeoutClosesConnection` verifies that a server closes the connection if the client sends the request body too slowly and exceeds the `ReadTimeout`.

2. **Simulating Slow Connections:** The `slowTestConn` struct simulates a network connection with delays and deadlines to test timeout scenarios.

3. **Testing `TimeoutHandler`:**  `TestTimeoutHandler` checks the behavior of the `TimeoutHandler`, which wraps another handler and returns a timeout error if the wrapped handler takes too long. It also tests that panics in the timed-out handler are recovered.

4. **Testing `TimeoutHandler` Concurrency:** `TestTimeoutHandlerRace` and `TestTimeoutHandlerRaceHeader` are concurrency tests to ensure the `TimeoutHandler` is thread-safe and doesn't panic under load, especially when dealing with headers.

5. **Testing `TimeoutHandler` Context Cancellation:** `TestTimeoutHandlerContextCanceled` verifies that the `TimeoutHandler` respects context cancellation.

6. **Testing `TimeoutHandler` with Empty Responses:** `TestTimeoutHandlerEmptyResponse` checks how `TimeoutHandler` behaves when the wrapped handler doesn't write a response.

7. **Testing Panic Recovery:** `TestHandlerPanicNil`, `TestHandlerPanic`, and `TestHandlerPanicWithHijack` test that the server recovers from panics in handlers and logs the error. The `TestHandlerPanicWithHijack` specifically tests panics in hijacking scenarios.

8. **Testing Hijacked Connections:** `TestServerWriteHijackZeroBytes` tests writing zero bytes on a hijacked connection.

9. **Testing Header Handling:** `TestServerNoDate` and `TestServerContentType` check that the server correctly handles cases where specific headers like `Date` or `Content-Type` are explicitly removed.

10. **Testing `StripPrefix`:** `TestStripPrefix` verifies the functionality of the `StripPrefix` handler, which removes a specified prefix from the request URL path. `TestStripPrefixNotModifyRequest` ensures that `StripPrefix` doesn't modify the original request object.

11. **Testing Request Header Limits:** `TestRequestLimit` checks that the server enforces the `DefaultMaxHeaderBytes` limit and responds appropriately when exceeded.

12. **Testing Request Body Limits:** `TestRequestBodyLimit` checks the `MaxBytesReader` which limits the size of the request body.

13. **Testing Client Write Shutdown:** `TestClientWriteShutdown` verifies that the server doesn't send a "400 Bad Request" if the client closes the write side of the connection.

14. **Testing Server Buffered Chunking:** `TestServerBufferedChunking` verifies that chunked responses are correctly buffered.

15. **Testing Graceful Connection Closing:** `TestServerGracefulClose` tests the server's behavior when closing a connection after sending a response but before the client finishes sending the request body.

16. **Testing Case Sensitivity of HTTP Method:** `TestCaseSensitiveMethod` checks if the server correctly handles the case sensitivity of HTTP methods (though it seems the test asserts the method is lowercase, which might be incorrect for standard HTTP).

17. **Testing `Content-Length: 0`:** `TestContentLengthZero` verifies that the server adds a `Content-Length: 0` header for responses with no body.

18. **Testing `CloseNotifier`:** `TestCloseNotifier` checks the functionality of the `CloseNotifier` interface, which allows handlers to be notified when a client disconnects. `TestCloseNotifierPipelined` tests that the `CloseNotifier` doesn't fire prematurely for pipelined requests.

I will now generate the summary in Chinese.
这个代码片段是 `go/src/net/http/serve_test.go` 文件的一部分，主要负责测试 Go 语言 `net/http` 包中服务器（`Serve`）的各种功能，特别是关于请求处理和连接管理的方面。

**归纳一下它的功能:**

这段代码主要集中在测试以下 `net/http` 服务器的功能点：

* **测试请求体读取超时:**  验证服务器在读取请求体时，如果客户端发送速度过慢，导致超过预设的读取超时时间，服务器会正确地关闭连接。
* **模拟慢速连接:** 通过自定义的 `slowTestConn` 类型，模拟网络连接缓慢的情况，用于测试服务器在面对慢速连接时的行为，例如超时处理。
* **测试 `TimeoutHandler` 的功能:**  验证 `TimeoutHandler` 的行为。`TimeoutHandler` 是一个中间件，它可以包裹其他的 `Handler`，并在被包裹的 `Handler` 执行时间超过指定时长后返回一个超时的错误响应。测试包括正常情况下的超时处理，以及当被包裹的 `Handler` 发生 panic 时的恢复机制。
* **测试 `TimeoutHandler` 的并发安全性:**  通过并发请求测试 `TimeoutHandler` 在高并发场景下的稳定性和线程安全性，避免出现竞态条件或 panic。
* **测试 `TimeoutHandler` 对 Context 取消的响应:**  验证 `TimeoutHandler` 是否能够正确响应请求的 Context 被取消的情况。
* **测试 `TimeoutHandler` 处理空响应的情况:**  检查当被 `TimeoutHandler` 包裹的 `Handler` 没有写入任何响应时，`TimeoutHandler` 的行为是否符合预期。
* **测试 Handler 中的 Panic 恢复:**  验证服务器能够从 `Handler` 中发生的 panic 中恢复，并记录错误日志，而不是导致服务器崩溃。测试了普通 Handler 和实现了 `Hijacker` 接口的 Handler 发生 panic 的情况。
* **测试 Hijack 连接的写入行为:**  验证在连接被劫持 (Hijack) 后，向 `ResponseWriter` 写入零字节的行为是否正确。
* **测试移除默认 Header 的情况:**  验证当 `Handler` 显式地移除某些默认的响应头（例如 `Date` 或 `Content-Type`）时，服务器的行为是否正确。
* **测试 `StripPrefix` Handler 的功能:**  验证 `StripPrefix` 中间件能够正确地从请求的 URL 路径中移除指定的前缀。同时测试了 `StripPrefix` 不会修改原始请求对象。
* **测试请求头的限制:**  验证服务器能够正确地处理超过 `DefaultMaxHeaderBytes` 限制的请求头，并返回相应的错误状态码。
* **测试请求体的限制:**  验证 `MaxBytesReader` 能够正确限制请求体的大小，并在超出限制时返回错误。
* **测试客户端关闭写入端的情况:**  验证当客户端关闭 TCP 连接的写入端时，服务器不会发送 "400 Bad Request" 错误。
* **测试服务器的 Chunked 编码缓冲:**  验证服务器在使用 chunked 编码时，是否会在添加 chunk 头部之前先缓冲响应数据。
* **测试服务器的优雅关闭:**  验证服务器在忽略响应体的情况下，会先发送响应头，然后等待一段时间再强制关闭 TCP 连接，避免客户端立即收到 RST 包。
* **测试 HTTP 方法的大小写敏感性:**  验证服务器处理 HTTP 方法时是否区分大小写。
* **测试 `Content-Length: 0` 的添加:**  验证对于没有响应体的请求，服务器会自动添加 `Content-Length: 0` 响应头。
* **测试 `CloseNotifier` 接口:**  验证 `CloseNotifier` 接口的功能，该接口允许 Handler 监听客户端连接的关闭事件。同时也测试了在处理 pipeline 请求时，`CloseNotifier` 不会被错误地触发。

总而言之，这段代码覆盖了 `net/http` 服务器在处理各种正常和异常情况下的行为，确保其稳定性和可靠性。

Prompt: 
```
这是路径为go/src/net/http/serve_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共7部分，请归纳一下它的功能

"""
 int
		go Serve(ln, HandlerFunc(func(_ ResponseWriter, req *Request) {
			numReqs++
			if strings.Contains(req.URL.Path, "secret") {
				t.Errorf("Handler %s, Request for /secret encountered, should not have happened.", handler.name)
			}
			handler.f(req.Body)
		}))
		<-conn.closec
		if numReqs != 1 {
			t.Errorf("Handler %s: got %d reqs; want 1", handler.name, numReqs)
		}
	}
}

// slowTestConn is a net.Conn that provides a means to simulate parts of a
// request being received piecemeal. Deadlines can be set and enforced in both
// Read and Write.
type slowTestConn struct {
	// over multiple calls to Read, time.Durations are slept, strings are read.
	script []any
	closec chan bool

	mu     sync.Mutex // guards rd/wd
	rd, wd time.Time  // read, write deadline
	noopConn
}

func (c *slowTestConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *slowTestConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rd = t
	return nil
}

func (c *slowTestConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wd = t
	return nil
}

func (c *slowTestConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
restart:
	if !c.rd.IsZero() && time.Now().After(c.rd) {
		return 0, syscall.ETIMEDOUT
	}
	if len(c.script) == 0 {
		return 0, io.EOF
	}

	switch cue := c.script[0].(type) {
	case time.Duration:
		if !c.rd.IsZero() {
			// If the deadline falls in the middle of our sleep window, deduct
			// part of the sleep, then return a timeout.
			if remaining := time.Until(c.rd); remaining < cue {
				c.script[0] = cue - remaining
				time.Sleep(remaining)
				return 0, syscall.ETIMEDOUT
			}
		}
		c.script = c.script[1:]
		time.Sleep(cue)
		goto restart

	case string:
		n = copy(b, cue)
		// If cue is too big for the buffer, leave the end for the next Read.
		if len(cue) > n {
			c.script[0] = cue[n:]
		} else {
			c.script = c.script[1:]
		}

	default:
		panic("unknown cue in slowTestConn script")
	}

	return
}

func (c *slowTestConn) Close() error {
	select {
	case c.closec <- true:
	default:
	}
	return nil
}

func (c *slowTestConn) Write(b []byte) (int, error) {
	if !c.wd.IsZero() && time.Now().After(c.wd) {
		return 0, syscall.ETIMEDOUT
	}
	return len(b), nil
}

func TestRequestBodyTimeoutClosesConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	defer afterTest(t)
	for _, handler := range testHandlerBodyConsumers {
		conn := &slowTestConn{
			script: []any{
				"POST /public HTTP/1.1\r\n" +
					"Host: test\r\n" +
					"Content-Length: 10000\r\n" +
					"\r\n",
				"foo bar baz",
				600 * time.Millisecond, // Request deadline should hit here
				"GET /secret HTTP/1.1\r\n" +
					"Host: test\r\n" +
					"\r\n",
			},
			closec: make(chan bool, 1),
		}
		ls := &oneConnListener{conn}

		var numReqs int
		s := Server{
			Handler: HandlerFunc(func(_ ResponseWriter, req *Request) {
				numReqs++
				if strings.Contains(req.URL.Path, "secret") {
					t.Error("Request for /secret encountered, should not have happened.")
				}
				handler.f(req.Body)
			}),
			ReadTimeout: 400 * time.Millisecond,
		}
		go s.Serve(ls)
		<-conn.closec

		if numReqs != 1 {
			t.Errorf("Handler %v: got %d reqs; want 1", handler.name, numReqs)
		}
	}
}

// cancelableTimeoutContext overwrites the error message to DeadlineExceeded
type cancelableTimeoutContext struct {
	context.Context
}

func (c cancelableTimeoutContext) Err() error {
	if c.Context.Err() != nil {
		return context.DeadlineExceeded
	}
	return nil
}

func TestTimeoutHandler(t *testing.T) { run(t, testTimeoutHandler) }
func testTimeoutHandler(t *testing.T, mode testMode) {
	sendHi := make(chan bool, 1)
	writeErrors := make(chan error, 1)
	sayHi := HandlerFunc(func(w ResponseWriter, r *Request) {
		<-sendHi
		_, werr := w.Write([]byte("hi"))
		writeErrors <- werr
	})
	ctx, cancel := context.WithCancel(context.Background())
	h := NewTestTimeoutHandler(sayHi, cancelableTimeoutContext{ctx})
	cst := newClientServerTest(t, mode, h)

	// Succeed without timing out:
	sendHi <- true
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Error(err)
	}
	if g, e := res.StatusCode, StatusOK; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	body, _ := io.ReadAll(res.Body)
	if g, e := string(body), "hi"; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
	if g := <-writeErrors; g != nil {
		t.Errorf("got unexpected Write error on first request: %v", g)
	}

	// Times out:
	cancel()

	res, err = cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Error(err)
	}
	if g, e := res.StatusCode, StatusServiceUnavailable; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	body, _ = io.ReadAll(res.Body)
	if !strings.Contains(string(body), "<title>Timeout</title>") {
		t.Errorf("expected timeout body; got %q", string(body))
	}
	if g, w := res.Header.Get("Content-Type"), "text/html; charset=utf-8"; g != w {
		t.Errorf("response content-type = %q; want %q", g, w)
	}

	// Now make the previously-timed out handler speak again,
	// which verifies the panic is handled:
	sendHi <- true
	if g, e := <-writeErrors, ErrHandlerTimeout; g != e {
		t.Errorf("expected Write error of %v; got %v", e, g)
	}
}

// See issues 8209 and 8414.
func TestTimeoutHandlerRace(t *testing.T) { run(t, testTimeoutHandlerRace) }
func testTimeoutHandlerRace(t *testing.T, mode testMode) {
	delayHi := HandlerFunc(func(w ResponseWriter, r *Request) {
		ms, _ := strconv.Atoi(r.URL.Path[1:])
		if ms == 0 {
			ms = 1
		}
		for i := 0; i < ms; i++ {
			w.Write([]byte("hi"))
			time.Sleep(time.Millisecond)
		}
	})

	ts := newClientServerTest(t, mode, TimeoutHandler(delayHi, 20*time.Millisecond, "")).ts

	c := ts.Client()

	var wg sync.WaitGroup
	gate := make(chan bool, 10)
	n := 50
	if testing.Short() {
		n = 10
		gate = make(chan bool, 3)
	}
	for i := 0; i < n; i++ {
		gate <- true
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			res, err := c.Get(fmt.Sprintf("%s/%d", ts.URL, rand.Intn(50)))
			if err == nil {
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}()
	}
	wg.Wait()
}

// See issues 8209 and 8414.
// Both issues involved panics in the implementation of TimeoutHandler.
func TestTimeoutHandlerRaceHeader(t *testing.T) { run(t, testTimeoutHandlerRaceHeader) }
func testTimeoutHandlerRaceHeader(t *testing.T, mode testMode) {
	delay204 := HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(204)
	})

	ts := newClientServerTest(t, mode, TimeoutHandler(delay204, time.Nanosecond, "")).ts

	var wg sync.WaitGroup
	gate := make(chan bool, 50)
	n := 500
	if testing.Short() {
		n = 10
	}

	c := ts.Client()
	for i := 0; i < n; i++ {
		gate <- true
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			res, err := c.Get(ts.URL)
			if err != nil {
				// We see ECONNRESET from the connection occasionally,
				// and that's OK: this test is checking that the server does not panic.
				t.Log(err)
				return
			}
			defer res.Body.Close()
			io.Copy(io.Discard, res.Body)
		}()
	}
	wg.Wait()
}

// Issue 9162
func TestTimeoutHandlerRaceHeaderTimeout(t *testing.T) { run(t, testTimeoutHandlerRaceHeaderTimeout) }
func testTimeoutHandlerRaceHeaderTimeout(t *testing.T, mode testMode) {
	sendHi := make(chan bool, 1)
	writeErrors := make(chan error, 1)
	sayHi := HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Type", "text/plain")
		<-sendHi
		_, werr := w.Write([]byte("hi"))
		writeErrors <- werr
	})
	ctx, cancel := context.WithCancel(context.Background())
	h := NewTestTimeoutHandler(sayHi, cancelableTimeoutContext{ctx})
	cst := newClientServerTest(t, mode, h)

	// Succeed without timing out:
	sendHi <- true
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Error(err)
	}
	if g, e := res.StatusCode, StatusOK; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	body, _ := io.ReadAll(res.Body)
	if g, e := string(body), "hi"; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
	if g := <-writeErrors; g != nil {
		t.Errorf("got unexpected Write error on first request: %v", g)
	}

	// Times out:
	cancel()

	res, err = cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Error(err)
	}
	if g, e := res.StatusCode, StatusServiceUnavailable; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	body, _ = io.ReadAll(res.Body)
	if !strings.Contains(string(body), "<title>Timeout</title>") {
		t.Errorf("expected timeout body; got %q", string(body))
	}

	// Now make the previously-timed out handler speak again,
	// which verifies the panic is handled:
	sendHi <- true
	if g, e := <-writeErrors, ErrHandlerTimeout; g != e {
		t.Errorf("expected Write error of %v; got %v", e, g)
	}
}

// Issue 14568.
func TestTimeoutHandlerStartTimerWhenServing(t *testing.T) {
	run(t, testTimeoutHandlerStartTimerWhenServing)
}
func testTimeoutHandlerStartTimerWhenServing(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping sleeping test in -short mode")
	}
	var handler HandlerFunc = func(w ResponseWriter, _ *Request) {
		w.WriteHeader(StatusNoContent)
	}
	timeout := 300 * time.Millisecond
	ts := newClientServerTest(t, mode, TimeoutHandler(handler, timeout, "")).ts
	defer ts.Close()

	c := ts.Client()

	// Issue was caused by the timeout handler starting the timer when
	// was created, not when the request. So wait for more than the timeout
	// to ensure that's not the case.
	time.Sleep(2 * timeout)
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != StatusNoContent {
		t.Errorf("got res.StatusCode %d, want %v", res.StatusCode, StatusNoContent)
	}
}

func TestTimeoutHandlerContextCanceled(t *testing.T) { run(t, testTimeoutHandlerContextCanceled) }
func testTimeoutHandlerContextCanceled(t *testing.T, mode testMode) {
	writeErrors := make(chan error, 1)
	sayHi := HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Type", "text/plain")
		var err error
		// The request context has already been canceled, but
		// retry the write for a while to give the timeout handler
		// a chance to notice.
		for i := 0; i < 100; i++ {
			_, err = w.Write([]byte("a"))
			if err != nil {
				break
			}
			time.Sleep(1 * time.Millisecond)
		}
		writeErrors <- err
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := NewTestTimeoutHandler(sayHi, ctx)
	cst := newClientServerTest(t, mode, h)
	defer cst.close()

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Error(err)
	}
	if g, e := res.StatusCode, StatusServiceUnavailable; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	body, _ := io.ReadAll(res.Body)
	if g, e := string(body), ""; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
	if g, e := <-writeErrors, context.Canceled; g != e {
		t.Errorf("got unexpected Write in handler: %v, want %g", g, e)
	}
}

// https://golang.org/issue/15948
func TestTimeoutHandlerEmptyResponse(t *testing.T) { run(t, testTimeoutHandlerEmptyResponse) }
func testTimeoutHandlerEmptyResponse(t *testing.T, mode testMode) {
	var handler HandlerFunc = func(w ResponseWriter, _ *Request) {
		// No response.
	}
	timeout := 300 * time.Millisecond
	ts := newClientServerTest(t, mode, TimeoutHandler(handler, timeout, "")).ts

	c := ts.Client()

	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != StatusOK {
		t.Errorf("got res.StatusCode %d, want %v", res.StatusCode, StatusOK)
	}
}

// https://golang.org/issues/22084
func TestTimeoutHandlerPanicRecovery(t *testing.T) {
	wrapper := func(h Handler) Handler {
		return TimeoutHandler(h, time.Second, "")
	}
	run(t, func(t *testing.T, mode testMode) {
		testHandlerPanic(t, false, mode, wrapper, "intentional death for testing")
	}, testNotParallel)
}

func TestRedirectBadPath(t *testing.T) {
	// This used to crash. It's not valid input (bad path), but it
	// shouldn't crash.
	rr := httptest.NewRecorder()
	req := &Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "http",
			Path:   "not-empty-but-no-leading-slash", // bogus
		},
	}
	Redirect(rr, req, "", 304)
	if rr.Code != 304 {
		t.Errorf("Code = %d; want 304", rr.Code)
	}
}

// Test different URL formats and schemes
func TestRedirect(t *testing.T) {
	req, _ := NewRequest("GET", "http://example.com/qux/", nil)

	var tests = []struct {
		in   string
		want string
	}{
		// normal http
		{"http://foobar.com/baz", "http://foobar.com/baz"},
		// normal https
		{"https://foobar.com/baz", "https://foobar.com/baz"},
		// custom scheme
		{"test://foobar.com/baz", "test://foobar.com/baz"},
		// schemeless
		{"//foobar.com/baz", "//foobar.com/baz"},
		// relative to the root
		{"/foobar.com/baz", "/foobar.com/baz"},
		// relative to the current path
		{"foobar.com/baz", "/qux/foobar.com/baz"},
		// relative to the current path (+ going upwards)
		{"../quux/foobar.com/baz", "/quux/foobar.com/baz"},
		// incorrect number of slashes
		{"///foobar.com/baz", "/foobar.com/baz"},

		// Verifies we don't path.Clean() on the wrong parts in redirects:
		{"/foo?next=http://bar.com/", "/foo?next=http://bar.com/"},
		{"http://localhost:8080/_ah/login?continue=http://localhost:8080/",
			"http://localhost:8080/_ah/login?continue=http://localhost:8080/"},

		{"/фубар", "/%d1%84%d1%83%d0%b1%d0%b0%d1%80"},
		{"http://foo.com/фубар", "http://foo.com/%d1%84%d1%83%d0%b1%d0%b0%d1%80"},
	}

	for _, tt := range tests {
		rec := httptest.NewRecorder()
		Redirect(rec, req, tt.in, 302)
		if got, want := rec.Code, 302; got != want {
			t.Errorf("Redirect(%q) generated status code %v; want %v", tt.in, got, want)
		}
		if got := rec.Header().Get("Location"); got != tt.want {
			t.Errorf("Redirect(%q) generated Location header %q; want %q", tt.in, got, tt.want)
		}
	}
}

// Test that Redirect sets Content-Type header for GET and HEAD requests
// and writes a short HTML body, unless the request already has a Content-Type header.
func TestRedirectContentTypeAndBody(t *testing.T) {
	type ctHeader struct {
		Values []string
	}

	var tests = []struct {
		method   string
		ct       *ctHeader // Optional Content-Type header to set.
		wantCT   string
		wantBody string
	}{
		{MethodGet, nil, "text/html; charset=utf-8", "<a href=\"/foo\">Found</a>.\n\n"},
		{MethodHead, nil, "text/html; charset=utf-8", ""},
		{MethodPost, nil, "", ""},
		{MethodDelete, nil, "", ""},
		{"foo", nil, "", ""},
		{MethodGet, &ctHeader{[]string{"application/test"}}, "application/test", ""},
		{MethodGet, &ctHeader{[]string{}}, "", ""},
		{MethodGet, &ctHeader{nil}, "", ""},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, "http://example.com/qux/", nil)
		rec := httptest.NewRecorder()
		if tt.ct != nil {
			rec.Header()["Content-Type"] = tt.ct.Values
		}
		Redirect(rec, req, "/foo", 302)
		if got, want := rec.Code, 302; got != want {
			t.Errorf("Redirect(%q, %#v) generated status code %v; want %v", tt.method, tt.ct, got, want)
		}
		if got, want := rec.Header().Get("Content-Type"), tt.wantCT; got != want {
			t.Errorf("Redirect(%q, %#v) generated Content-Type header %q; want %q", tt.method, tt.ct, got, want)
		}
		resp := rec.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(body), tt.wantBody; got != want {
			t.Errorf("Redirect(%q, %#v) generated Body %q; want %q", tt.method, tt.ct, got, want)
		}
	}
}

// TestZeroLengthPostAndResponse exercises an optimization done by the Transport:
// when there is no body (either because the method doesn't permit a body, or an
// explicit Content-Length of zero is present), then the transport can re-use the
// connection immediately. But when it re-uses the connection, it typically closes
// the previous request's body, which is not optimal for zero-lengthed bodies,
// as the client would then see http.ErrBodyReadAfterClose and not 0, io.EOF.
func TestZeroLengthPostAndResponse(t *testing.T) { run(t, testZeroLengthPostAndResponse) }

func testZeroLengthPostAndResponse(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, r *Request) {
		all, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("handler ReadAll: %v", err)
		}
		if len(all) != 0 {
			t.Errorf("handler got %d bytes; expected 0", len(all))
		}
		rw.Header().Set("Content-Length", "0")
	}))

	req, err := NewRequest("POST", cst.ts.URL, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 0

	var resp [5]*Response
	for i := range resp {
		resp[i], err = cst.c.Do(req)
		if err != nil {
			t.Fatalf("client post #%d: %v", i, err)
		}
	}

	for i := range resp {
		all, err := io.ReadAll(resp[i].Body)
		if err != nil {
			t.Fatalf("req #%d: client ReadAll: %v", i, err)
		}
		if len(all) != 0 {
			t.Errorf("req #%d: client got %d bytes; expected 0", i, len(all))
		}
	}
}

func TestHandlerPanicNil(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testHandlerPanic(t, false, mode, nil, nil)
	}, testNotParallel)
}

func TestHandlerPanic(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testHandlerPanic(t, false, mode, nil, "intentional death for testing")
	}, testNotParallel)
}

func TestHandlerPanicWithHijack(t *testing.T) {
	// Only testing HTTP/1, and our http2 server doesn't support hijacking.
	run(t, func(t *testing.T, mode testMode) {
		testHandlerPanic(t, true, mode, nil, "intentional death for testing")
	}, []testMode{http1Mode})
}

func testHandlerPanic(t *testing.T, withHijack bool, mode testMode, wrapper func(Handler) Handler, panicValue any) {
	// Direct log output to a pipe.
	//
	// We read from the pipe to verify that the handler actually caught the panic
	// and logged something.
	//
	// We use a pipe rather than a buffer, because when testing connection hijacking
	// server shutdown doesn't wait for the hijacking handler to return, so the
	// log may occur after the server has shut down.
	pr, pw := io.Pipe()
	defer pw.Close()

	var handler Handler = HandlerFunc(func(w ResponseWriter, r *Request) {
		if withHijack {
			rwc, _, err := w.(Hijacker).Hijack()
			if err != nil {
				t.Logf("unexpected error: %v", err)
			}
			defer rwc.Close()
		}
		panic(panicValue)
	})
	if wrapper != nil {
		handler = wrapper(handler)
	}
	cst := newClientServerTest(t, mode, handler, func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(pw, "", 0)
	})

	// Do a blocking read on the log output pipe.
	done := make(chan bool, 1)
	go func() {
		buf := make([]byte, 4<<10)
		_, err := pr.Read(buf)
		pr.Close()
		if err != nil && err != io.EOF {
			t.Error(err)
		}
		done <- true
	}()

	_, err := cst.c.Get(cst.ts.URL)
	if err == nil {
		t.Logf("expected an error")
	}

	if panicValue == nil {
		return
	}

	<-done
}

type terrorWriter struct{ t *testing.T }

func (w terrorWriter) Write(p []byte) (int, error) {
	w.t.Errorf("%s", p)
	return len(p), nil
}

// Issue 16456: allow writing 0 bytes on hijacked conn to test hijack
// without any log spam.
func TestServerWriteHijackZeroBytes(t *testing.T) {
	run(t, testServerWriteHijackZeroBytes, []testMode{http1Mode})
}
func testServerWriteHijackZeroBytes(t *testing.T, mode testMode) {
	done := make(chan struct{})
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		defer close(done)
		w.(Flusher).Flush()
		conn, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		_, err = w.Write(nil)
		if err != ErrHijacked {
			t.Errorf("Write error = %v; want ErrHijacked", err)
		}
	}), func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(terrorWriter{t}, "Unexpected write: ", 0)
	}).ts

	c := ts.Client()
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	<-done
}

func TestServerNoDate(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testServerNoHeader(t, mode, "Date")
	})
}

func TestServerContentType(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testServerNoHeader(t, mode, "Content-Type")
	})
}

func testServerNoHeader(t *testing.T, mode testMode, header string) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header()[header] = nil
		io.WriteString(w, "<html>foo</html>") // non-empty
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got, ok := res.Header[header]; ok {
		t.Fatalf("Expected no %s header; got %q", header, got)
	}
}

func TestStripPrefix(t *testing.T) { run(t, testStripPrefix) }
func testStripPrefix(t *testing.T, mode testMode) {
	h := HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Path", r.URL.Path)
		w.Header().Set("X-RawPath", r.URL.RawPath)
	})
	ts := newClientServerTest(t, mode, StripPrefix("/foo/bar", h)).ts

	c := ts.Client()

	cases := []struct {
		reqPath string
		path    string // If empty we want a 404.
		rawPath string
	}{
		{"/foo/bar/qux", "/qux", ""},
		{"/foo/bar%2Fqux", "/qux", "%2Fqux"},
		{"/foo%2Fbar/qux", "", ""}, // Escaped prefix does not match.
		{"/bar", "", ""},           // No prefix match.
	}
	for _, tc := range cases {
		t.Run(tc.reqPath, func(t *testing.T) {
			res, err := c.Get(ts.URL + tc.reqPath)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if tc.path == "" {
				if res.StatusCode != StatusNotFound {
					t.Errorf("got %q, want 404 Not Found", res.Status)
				}
				return
			}
			if res.StatusCode != StatusOK {
				t.Fatalf("got %q, want 200 OK", res.Status)
			}
			if g, w := res.Header.Get("X-Path"), tc.path; g != w {
				t.Errorf("got Path %q, want %q", g, w)
			}
			if g, w := res.Header.Get("X-RawPath"), tc.rawPath; g != w {
				t.Errorf("got RawPath %q, want %q", g, w)
			}
		})
	}
}

// https://golang.org/issue/18952.
func TestStripPrefixNotModifyRequest(t *testing.T) {
	h := StripPrefix("/foo", NotFoundHandler())
	req := httptest.NewRequest("GET", "/foo/bar", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if req.URL.Path != "/foo/bar" {
		t.Errorf("StripPrefix should not modify the provided Request, but it did")
	}
}

func TestRequestLimit(t *testing.T) { run(t, testRequestLimit) }
func testRequestLimit(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		t.Fatalf("didn't expect to get request in Handler")
	}), optQuietLog)
	req, _ := NewRequest("GET", cst.ts.URL, nil)
	var bytesPerHeader = len("header12345: val12345\r\n")
	for i := 0; i < ((DefaultMaxHeaderBytes+4096)/bytesPerHeader)+1; i++ {
		req.Header.Set(fmt.Sprintf("header%05d", i), fmt.Sprintf("val%05d", i))
	}
	res, err := cst.c.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if mode == http2Mode {
		// In HTTP/2, the result depends on a race. If the client has received the
		// server's SETTINGS before RoundTrip starts sending the request, then RoundTrip
		// will fail with an error. Otherwise, the client should receive a 431 from the
		// server.
		if err == nil && res.StatusCode != 431 {
			t.Fatalf("expected 431 response status; got: %d %s", res.StatusCode, res.Status)
		}
	} else {
		// In HTTP/1, we expect a 431 from the server.
		// Some HTTP clients may fail on this undefined behavior (server replying and
		// closing the connection while the request is still being written), but
		// we do support it (at least currently), so we expect a response below.
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if res.StatusCode != 431 {
			t.Fatalf("expected 431 response status; got: %d %s", res.StatusCode, res.Status)
		}
	}
}

type neverEnding byte

func (b neverEnding) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

type bodyLimitReader struct {
	mu     sync.Mutex
	count  int
	limit  int
	closed chan struct{}
}

func (r *bodyLimitReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.closed:
		return 0, errors.New("closed")
	default:
	}
	if r.count > r.limit {
		return 0, errors.New("at limit")
	}
	r.count += len(p)
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func (r *bodyLimitReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	close(r.closed)
	return nil
}

func TestRequestBodyLimit(t *testing.T) { run(t, testRequestBodyLimit) }
func testRequestBodyLimit(t *testing.T, mode testMode) {
	const limit = 1 << 20
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		r.Body = MaxBytesReader(w, r.Body, limit)
		n, err := io.Copy(io.Discard, r.Body)
		if err == nil {
			t.Errorf("expected error from io.Copy")
		}
		if n != limit {
			t.Errorf("io.Copy = %d, want %d", n, limit)
		}
		mbErr, ok := err.(*MaxBytesError)
		if !ok {
			t.Errorf("expected MaxBytesError, got %T", err)
		}
		if mbErr.Limit != limit {
			t.Errorf("MaxBytesError.Limit = %d, want %d", mbErr.Limit, limit)
		}
	}))

	body := &bodyLimitReader{
		closed: make(chan struct{}),
		limit:  limit * 200,
	}
	req, _ := NewRequest("POST", cst.ts.URL, body)

	// Send the POST, but don't care it succeeds or not. The
	// remote side is going to reply and then close the TCP
	// connection, and HTTP doesn't really define if that's
	// allowed or not. Some HTTP clients will get the response
	// and some (like ours, currently) will complain that the
	// request write failed, without reading the response.
	//
	// But that's okay, since what we're really testing is that
	// the remote side hung up on us before we wrote too much.
	resp, err := cst.c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	// Wait for the Transport to finish writing the request body.
	// It will close the body when done.
	<-body.closed

	if body.count > limit*100 {
		t.Errorf("handler restricted the request body to %d bytes, but client managed to write %d",
			limit, body.count)
	}
}

// TestClientWriteShutdown tests that if the client shuts down the write
// side of their TCP connection, the server doesn't send a 400 Bad Request.
func TestClientWriteShutdown(t *testing.T) { run(t, testClientWriteShutdown) }
func testClientWriteShutdown(t *testing.T, mode testMode) {
	if runtime.GOOS == "plan9" {
		t.Skip("skipping test; see https://golang.org/issue/17906")
	}
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {})).ts
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	err = conn.(*net.TCPConn).CloseWrite()
	if err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	bs, err := io.ReadAll(conn)
	if err != nil {
		t.Errorf("ReadAll: %v", err)
	}
	got := string(bs)
	if got != "" {
		t.Errorf("read %q from server; want nothing", got)
	}
}

// Tests that chunked server responses that write 1 byte at a time are
// buffered before chunk headers are added, not after chunk headers.
func TestServerBufferedChunking(t *testing.T) {
	conn := new(testConn)
	conn.readBuf.Write([]byte("GET / HTTP/1.1\r\nHost: foo\r\n\r\n"))
	conn.closec = make(chan bool, 1)
	ls := &oneConnListener{conn}
	go Serve(ls, HandlerFunc(func(rw ResponseWriter, req *Request) {
		rw.(Flusher).Flush() // force the Header to be sent, in chunking mode, not counting the length
		rw.Write([]byte{'x'})
		rw.Write([]byte{'y'})
		rw.Write([]byte{'z'})
	}))
	<-conn.closec
	if !bytes.HasSuffix(conn.writeBuf.Bytes(), []byte("\r\n\r\n3\r\nxyz\r\n0\r\n\r\n")) {
		t.Errorf("response didn't end with a single 3 byte 'xyz' chunk; got:\n%q",
			conn.writeBuf.Bytes())
	}
}

// Tests that the server flushes its response headers out when it's
// ignoring the response body and waits a bit before forcefully
// closing the TCP connection, causing the client to get a RST.
// See https://golang.org/issue/3595
func TestServerGracefulClose(t *testing.T) {
	// Not parallel: modifies the global rstAvoidanceDelay.
	run(t, testServerGracefulClose, []testMode{http1Mode}, testNotParallel)
}
func testServerGracefulClose(t *testing.T, mode testMode) {
	runTimeSensitiveTest(t, []time.Duration{
		1 * time.Millisecond,
		5 * time.Millisecond,
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
		time.Second,
		5 * time.Second,
	}, func(t *testing.T, timeout time.Duration) error {
		SetRSTAvoidanceDelay(t, timeout)
		t.Logf("set RST avoidance delay to %v", timeout)

		const bodySize = 5 << 20
		req := []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: foo.com\r\nContent-Length: %d\r\n\r\n", bodySize))
		for i := 0; i < bodySize; i++ {
			req = append(req, 'x')
		}

		cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			Error(w, "bye", StatusUnauthorized)
		}))
		// We need to close cst explicitly here so that in-flight server
		// requests don't race with the call to SetRSTAvoidanceDelay for a retry.
		defer cst.close()
		ts := cst.ts

		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			return err
		}
		writeErr := make(chan error)
		go func() {
			_, err := conn.Write(req)
			writeErr <- err
		}()
		defer func() {
			conn.Close()
			// Wait for write to finish. This is a broken pipe on both
			// Darwin and Linux, but checking this isn't the point of
			// the test.
			<-writeErr
		}()

		br := bufio.NewReader(conn)
		lineNum := 0
		for {
			line, err := br.ReadString('\n')
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("ReadLine: %v", err)
			}
			lineNum++
			if lineNum == 1 && !strings.Contains(line, "401 Unauthorized") {
				t.Errorf("Response line = %q; want a 401", line)
			}
		}
		return nil
	})
}

func TestCaseSensitiveMethod(t *testing.T) { run(t, testCaseSensitiveMethod) }
func testCaseSensitiveMethod(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "get" {
			t.Errorf(`Got method %q; want "get"`, r.Method)
		}
	}))
	defer cst.close()
	req, _ := NewRequest("get", cst.ts.URL, nil)
	res, err := cst.c.Do(req)
	if err != nil {
		t.Error(err)
		return
	}

	res.Body.Close()
}

// TestContentLengthZero tests that for both an HTTP/1.0 and HTTP/1.1
// request (both keep-alive), when a Handler never writes any
// response, the net/http package adds a "Content-Length: 0" response
// header.
func TestContentLengthZero(t *testing.T) {
	run(t, testContentLengthZero, []testMode{http1Mode})
}
func testContentLengthZero(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {})).ts

	for _, version := range []string{"HTTP/1.0", "HTTP/1.1"} {
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatalf("error dialing: %v", err)
		}
		_, err = fmt.Fprintf(conn, "GET / %v\r\nConnection: keep-alive\r\nHost: foo\r\n\r\n", version)
		if err != nil {
			t.Fatalf("error writing: %v", err)
		}
		req, _ := NewRequest("GET", "/", nil)
		res, err := ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatalf("error reading response: %v", err)
		}
		if te := res.TransferEncoding; len(te) > 0 {
			t.Errorf("For version %q, Transfer-Encoding = %q; want none", version, te)
		}
		if cl := res.ContentLength; cl != 0 {
			t.Errorf("For version %q, Content-Length = %v; want 0", version, cl)
		}
		conn.Close()
	}
}

func TestCloseNotifier(t *testing.T) {
	run(t, testCloseNotifier, []testMode{http1Mode})
}
func testCloseNotifier(t *testing.T, mode testMode) {
	gotReq := make(chan bool, 1)
	sawClose := make(chan bool, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		gotReq <- true
		cc := rw.(CloseNotifier).CloseNotify()
		<-cc
		sawClose <- true
	})).ts
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("error dialing: %v", err)
	}
	diec := make(chan bool)
	go func() {
		_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nConnection: keep-alive\r\nHost: foo\r\n\r\n")
		if err != nil {
			t.Error(err)
			return
		}
		<-diec
		conn.Close()
	}()
For:
	for {
		select {
		case <-gotReq:
			diec <- true
		case <-sawClose:
			break For
		}
	}
	ts.Close()
}

// Tests that a pipelined request does not cause the first request's
// Handler's CloseNotify channel to fire.
//
// Issue 13165 (where it used to deadlock), but behavior changed in Issue 23921.
func TestCloseNotifierPipelined(t *testing.T) {
	run(t, testCloseNotifierPipelined, []testMode{http1Mode})
}
func testCloseNotifierPipelined(t *testing.T, mode testMode) {
	gotReq := make(chan bool, 2)
	sawClose := make(chan bool, 2)
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		gotReq <- true
		cc := rw.(CloseNotifier).CloseNotify()
		select {
		case <-cc:
			t.Error("unexpecte
"""




```