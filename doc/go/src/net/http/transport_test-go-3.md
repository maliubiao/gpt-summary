Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `transport_test.go` file in the `net/http` package. I need to go through each test function and describe its purpose. Since this is part 4 of 7, the summary should focus on the functionalities covered in this specific part.

Here's a breakdown of the tests and their functions:

1. `TestExpectContinueTimeout`: Tests the timeout mechanism for the "Expect: 100-continue" header.
2. `TestTLSHShakeTimeout`: Tests the timeout for TLS handshake.
3. `TestTLSServerClosesConnection`: Tests how the client handles a TLS server closing the connection after sending some data.
4. `TestTransportNoReuseAfterEarlyResponse`: Tests that a connection is not reused if the server sends a response before the request is fully written.
5. `TestTransportIssue10457`: Tests that the transport doesn't leak goroutines when a server closes the connection immediately after indicating keep-alive.
6. `TestRetryRequestsOnError`: Tests the retry mechanism for requests that fail due to connection errors. It verifies that idempotent requests or requests where no data was sent are retried.
7. `TestTransportClosesBodyOnError`: Tests that the request body is closed if an error occurs during the request.
8. `TestTransportDialTLS`: Tests the `DialTLS` hook in the `Transport` for custom TLS connection setup.
9. `TestTransportDialContext`: Tests the `DialContext` hook for custom connection setup with context.
10. `TestTransportDialTLSContext`: Tests the `DialTLSContext` hook for custom TLS connection setup with context.
11. `TestRoundTripReturnsProxyError`: Tests that the `RoundTrip` method returns errors from the proxy function.
12. `TestTransportCloseIdleConnsThenReturn`: Tests the behavior of `CloseIdleConnections` and the ability to add connections back to the idle pool.
13. `TestTransportTraceGotConnH2IdleConns`: Tests that the `GotConn` trace hook is not called for HTTP/2 idle connections.
14. `TestTransportIdleConnRacesRequest`: Tests a race condition where a request and the idle connection timeout occur simultaneously.
15. `TestTransportRemovesConnsAfterIdle`: Tests that idle connections are removed from the pool after the `IdleConnTimeout`.
16. `TestTransportRemovesConnsAfterBroken`: Tests that broken connections are removed from the pool.
17. `TestTransportRangeAndGzip`: Tests that a request with a "Range" header doesn't automatically include gzip in the "Accept-Encoding" header.
18. `TestTransportResponseCancelRace`: Tests a race condition involving canceling a request and reusing the connection.
19. `TestTransportContentEncodingCaseInsensitive`: Tests that the `Content-Encoding` header is treated case-insensitively.
20. `TestConnClosedBeforeRequestIsWritten`: Tests the scenario where the connection is closed before the request is fully written.
21. `TestTransportFlushesBodyChunks`: Tests that the transport flushes body chunks correctly.
22. `TestTransportFlushesRequestHeader`: Tests that request headers are flushed even if the body might block.
23. `TestTransportPrefersResponseOverWriteError`: Tests that the transport prefers a valid response over a write error when both occur near the same time.
24. `TestTransportAutomaticHTTP2`: Tests automatic HTTP/2 negotiation.

Based on the provided snippet, it includes tests from `TestExpectContinueTimeout` up to `TestTransportAutomaticHTTP2`. I need to summarise the core functionalities covered by these tests.
这是 `go/src/net/http/transport_test.go` 文件的一部分，主要功能是测试 `net/http` 包中 `Transport` 类型的各种行为和边缘情况。`Transport` 负责管理 HTTP 客户端请求的底层连接和传输过程。

在这个代码片段中，涵盖了以下主要功能：

1. **处理超时:**  测试了连接建立时的超时（TLS 握手超时）和发送带有 `Expect: 100-continue` 头的请求时的超时处理。
2. **连接生命周期管理:**
    *   测试了当服务端主动关闭连接时的客户端行为，包括在发送部分数据后关闭连接的情况。
    *   测试了当服务端在发送响应前关闭连接，以及发送响应后立即关闭连接的情况，并验证客户端是否能正确处理，以及避免资源泄漏（例如 goroutine）。
    *   测试了连接的复用机制，特别是当服务端在客户端完全发送请求前就发送了响应时，连接不应该被复用。
    *   测试了空闲连接的清理机制，包括手动调用 `CloseIdleConnections` 和基于 `IdleConnTimeout` 的自动清理。
    *   测试了当连接发生错误时的处理，包括连接中断的情况，并验证客户端是否会重试请求（针对幂等请求或未发送任何数据的请求）。
3. **请求和响应处理:**
    *   测试了在请求过程中发生错误时，请求的 `Body` 是否会被正确关闭。
    *   测试了客户端发送带有 `Range` 头的请求时，是否会错误地添加 `Accept-Encoding: gzip` 头。
    *   测试了对 `Content-Encoding` 头部的解析是否是大小写不敏感的。
    *   测试了请求体分块传输时，数据是否被正确刷新发送。
    *   测试了即使请求体可能阻塞读取，请求头也会被先刷新发送。
4. **自定义连接处理:**
    *   测试了 `Transport` 提供的 `DialTLS` 钩子，允许用户自定义 TLS 连接的建立过程。
    *   测试了 `Transport` 提供的 `DialContext` 钩子，允许用户在建立连接时传入上下文信息。
    *   测试了 `Transport` 提供的 `DialTLSContext` 钩子，允许用户自定义 TLS 连接的建立过程，并传入上下文信息。
5. **代理处理:** 测试了当 `Transport` 的 `Proxy` 函数返回错误时，`RoundTrip` 方法能否正确返回该错误。
6. **并发控制:** 测试了在取消请求后，是否会发生连接复用的竞争条件。
7. **HTTP/2 相关:** 测试了对于 HTTP/2 的空闲连接，`httptrace.GotConn` 钩子是否被正确调用。
8. **请求重试机制:** 详细测试了在遇到特定错误时，`Transport` 的请求重试机制，包括对幂等请求和非幂等请求的处理。

**以下是用 Go 代码举例说明其中一些功能的实现:**

**1. TLS 握手超时测试:**

```go
// 假设服务端故意延迟 TLS 握手
func slowTLSServer() *httptest.Server {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "Hello, client")
		}),
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		conn := tls.Server(c, &tls.Config{
			Certificates: []tls.Certificate{testCert},
		})
		// 故意延迟握手
		time.Sleep(2 * time.Second)
		conn.Handshake()
		srv.Serve(tlsListen{ln, conn})
	}()
	return &httptest.Server{
		Listener: ln,
		Config:   srv,
	}
}

func ExampleTestTLSHShakeTimeout() {
	ts := slowTLSServer()
	defer ts.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	_, err := client.Get(ts.URL)
	if err != nil {
		ue, ok := err.(*url.Error)
		if ok {
			ne, ok := ue.Err.(net.Error)
			if ok && ne.Timeout() && strings.Contains(err.Error(), "handshake timeout") {
				fmt.Println("TLS handshake timeout occurred as expected.")
			} else {
				fmt.Printf("Unexpected error: %v\n", err)
			}
		} else {
			fmt.Printf("Unexpected error type: %T\n", err)
		}
	} else {
		fmt.Println("Expected a timeout error, but got a response.")
	}

	// Output: TLS handshake timeout occurred as expected.
}
```

**假设的输入与输出:**

在上面的 `ExampleTestTLSHShakeTimeout` 中：

*   **输入:**  一个故意延迟 TLS 握手的服务端地址。客户端设置了较短的 `TLSHandshakeTimeout`。
*   **输出:** 客户端会因为 TLS 握手超时而返回一个包含 "handshake timeout" 的 `url.Error`。

**2. 请求重试测试 (部分):**

```go
// 假设一个临时的、会失败的连接实现
type FailingConn struct {
	net.Conn
	failCount int
	writeCount int
}

func (c *FailingConn) Write(p []byte) (n int, err error) {
	c.writeCount++
	if c.writeCount <= c.failCount {
		return 0, errors.New("intentional write failure")
	}
	return c.Conn.Write(p)
}

func ExampleTestRetryRequestsOnError() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello")
	}))
	defer ts.Close()

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := net.Dial(network, ts.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			return &FailingConn{Conn: conn, failCount: 1}, nil
		},
	}
	client := &http.Client{Transport: tr}

	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed after retries: %v\n", err)
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Request succeeded after retry, response: %s\n", string(body))
	}

	// Output: Request succeeded after retry, response: Hello
}
```

**假设的输入与输出:**

在上面的 `ExampleTestRetryRequestsOnError` 中：

*   **输入:**  一个服务端地址。客户端的 `Transport` 被配置为在第一次尝试写入时返回错误。这是一个 GET 请求，是幂等的。
*   **输出:**  第一次请求会失败，但由于是 GET 请求且没有接收到响应头，`Transport` 会自动重试，第二次请求成功并返回 "Hello"。

**关于命令行参数:**

这个代码片段主要是单元测试，不直接处理命令行参数。`go test` 命令会执行这些测试，但测试本身是通过 Go 代码逻辑驱动的，而不是通过解析命令行参数。

**使用者易犯错的点 (示例):**

一个可能易犯的错误是，当自定义 `Transport` 的 `DialTLS` 或 `DialContext` 时，没有正确处理错误或进行必要的资源清理，例如没有调用 `conn.Close()`，这可能导致连接泄漏。

**归纳一下它的功能:**

这段代码主要用于测试 `net/http.Transport` 的以下功能：**连接超时处理（包括 TLS 握手超时），服务端主动关闭连接的处理，连接复用机制，请求重试机制（针对特定错误），请求体和响应头的处理细节，以及自定义连接建立过程的接口。** 它是 `net/http` 包中客户端 HTTP 请求处理核心组件 `Transport` 的健壮性和正确性的重要保障。

### 提示词
```
这是路径为go/src/net/http/transport_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
rl.Error)
	if !ok {
		t.Errorf("expected url.Error; got %#v", err)
		return
	}
	ne, ok := ue.Err.(net.Error)
	if !ok {
		t.Errorf("expected net.Error; got %#v", err)
		return
	}
	if !ne.Timeout() {
		t.Errorf("expected timeout error; got %v", err)
	}
	if !strings.Contains(err.Error(), "handshake timeout") {
		t.Errorf("expected 'handshake timeout' in error; got %v", err)
	}
}

// Trying to repro golang.org/issue/3514
func TestTLSServerClosesConnection(t *testing.T) {
	run(t, testTLSServerClosesConnection, []testMode{https1Mode})
}
func testTLSServerClosesConnection(t *testing.T, mode testMode) {
	closedc := make(chan bool, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if strings.Contains(r.URL.Path, "/keep-alive-then-die") {
			conn, _, _ := w.(Hijacker).Hijack()
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nfoo"))
			conn.Close()
			closedc <- true
			return
		}
		fmt.Fprintf(w, "hello")
	})).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)

	var nSuccess = 0
	var errs []error
	const trials = 20
	for i := 0; i < trials; i++ {
		tr.CloseIdleConnections()
		res, err := c.Get(ts.URL + "/keep-alive-then-die")
		if err != nil {
			t.Fatal(err)
		}
		<-closedc
		slurp, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(slurp) != "foo" {
			t.Errorf("Got %q, want foo", slurp)
		}

		// Now try again and see if we successfully
		// pick a new connection.
		res, err = c.Get(ts.URL + "/")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		slurp, err = io.ReadAll(res.Body)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		nSuccess++
	}
	if nSuccess > 0 {
		t.Logf("successes = %d of %d", nSuccess, trials)
	} else {
		t.Errorf("All runs failed:")
	}
	for _, err := range errs {
		t.Logf("  err: %v", err)
	}
}

// byteFromChanReader is an io.Reader that reads a single byte at a
// time from the channel. When the channel is closed, the reader
// returns io.EOF.
type byteFromChanReader chan byte

func (c byteFromChanReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	b, ok := <-c
	if !ok {
		return 0, io.EOF
	}
	p[0] = b
	return 1, nil
}

// Verifies that the Transport doesn't reuse a connection in the case
// where the server replies before the request has been fully
// written. We still honor that reply (see TestIssue3595), but don't
// send future requests on the connection because it's then in a
// questionable state.
// golang.org/issue/7569
func TestTransportNoReuseAfterEarlyResponse(t *testing.T) {
	run(t, testTransportNoReuseAfterEarlyResponse, []testMode{http1Mode}, testNotParallel)
}
func testTransportNoReuseAfterEarlyResponse(t *testing.T, mode testMode) {
	defer func(d time.Duration) {
		*MaxWriteWaitBeforeConnReuse = d
	}(*MaxWriteWaitBeforeConnReuse)
	*MaxWriteWaitBeforeConnReuse = 10 * time.Millisecond
	var sconn struct {
		sync.Mutex
		c net.Conn
	}
	var getOkay bool
	var copying sync.WaitGroup
	closeConn := func() {
		sconn.Lock()
		defer sconn.Unlock()
		if sconn.c != nil {
			sconn.c.Close()
			sconn.c = nil
			if !getOkay {
				t.Logf("Closed server connection")
			}
		}
	}
	defer func() {
		closeConn()
		copying.Wait()
	}()

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method == "GET" {
			io.WriteString(w, "bar")
			return
		}
		conn, _, _ := w.(Hijacker).Hijack()
		sconn.Lock()
		sconn.c = conn
		sconn.Unlock()
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nfoo")) // keep-alive

		copying.Add(1)
		go func() {
			io.Copy(io.Discard, conn)
			copying.Done()
		}()
	})).ts
	c := ts.Client()

	const bodySize = 256 << 10
	finalBit := make(byteFromChanReader, 1)
	req, _ := NewRequest("POST", ts.URL, io.MultiReader(io.LimitReader(neverEnding('x'), bodySize-1), finalBit))
	req.ContentLength = bodySize
	res, err := c.Do(req)
	if err := wantBody(res, err, "foo"); err != nil {
		t.Errorf("POST response: %v", err)
	}

	res, err = c.Get(ts.URL)
	if err := wantBody(res, err, "bar"); err != nil {
		t.Errorf("GET response: %v", err)
		return
	}
	getOkay = true  // suppress test noise
	finalBit <- 'x' // unblock the writeloop of the first Post
	close(finalBit)
}

// Tests that we don't leak Transport persistConn.readLoop goroutines
// when a server hangs up immediately after saying it would keep-alive.
func TestTransportIssue10457(t *testing.T) { run(t, testTransportIssue10457, []testMode{http1Mode}) }
func testTransportIssue10457(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// Send a response with no body, keep-alive
		// (implicit), and then lie and immediately close the
		// connection. This forces the Transport's readLoop to
		// immediately Peek an io.EOF and get to the point
		// that used to hang.
		conn, _, _ := w.(Hijacker).Hijack()
		conn.Write([]byte("HTTP/1.1 200 OK\r\nFoo: Bar\r\nContent-Length: 0\r\n\r\n")) // keep-alive
		conn.Close()
	})).ts
	c := ts.Client()

	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()

	// Just a sanity check that we at least get the response. The real
	// test here is that the "defer afterTest" above doesn't find any
	// leaked goroutines.
	if got, want := res.Header.Get("Foo"), "Bar"; got != want {
		t.Errorf("Foo header = %q; want %q", got, want)
	}
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type writerFuncConn struct {
	net.Conn
	write func(p []byte) (n int, err error)
}

func (c writerFuncConn) Write(p []byte) (n int, err error) { return c.write(p) }

// Issues 4677, 18241, and 17844. If we try to reuse a connection that the
// server is in the process of closing, we may end up successfully writing out
// our request (or a portion of our request) only to find a connection error
// when we try to read from (or finish writing to) the socket.
//
// NOTE: we resend a request only if:
//   - we reused a keep-alive connection
//   - we haven't yet received any header data
//   - either we wrote no bytes to the server, or the request is idempotent
//
// This automatically prevents an infinite resend loop because we'll run out of
// the cached keep-alive connections eventually.
func TestRetryRequestsOnError(t *testing.T) {
	run(t, testRetryRequestsOnError, testNotParallel, []testMode{http1Mode})
}
func testRetryRequestsOnError(t *testing.T, mode testMode) {
	newRequest := func(method, urlStr string, body io.Reader) *Request {
		req, err := NewRequest(method, urlStr, body)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	testCases := []struct {
		name       string
		failureN   int
		failureErr error
		// Note that we can't just re-use the Request object across calls to c.Do
		// because we need to rewind Body between calls.  (GetBody is only used to
		// rewind Body on failure and redirects, not just because it's done.)
		req       func() *Request
		reqString string
	}{
		{
			name: "IdempotentNoBodySomeWritten",
			// Believe that we've written some bytes to the server, so we know we're
			// not just in the "retry when no bytes sent" case".
			failureN: 1,
			// Use the specific error that shouldRetryRequest looks for with idempotent requests.
			failureErr: ExportErrServerClosedIdle,
			req: func() *Request {
				return newRequest("GET", "http://fake.golang", nil)
			},
			reqString: `GET / HTTP/1.1\r\nHost: fake.golang\r\nUser-Agent: Go-http-client/1.1\r\nAccept-Encoding: gzip\r\n\r\n`,
		},
		{
			name: "IdempotentGetBodySomeWritten",
			// Believe that we've written some bytes to the server, so we know we're
			// not just in the "retry when no bytes sent" case".
			failureN: 1,
			// Use the specific error that shouldRetryRequest looks for with idempotent requests.
			failureErr: ExportErrServerClosedIdle,
			req: func() *Request {
				return newRequest("GET", "http://fake.golang", strings.NewReader("foo\n"))
			},
			reqString: `GET / HTTP/1.1\r\nHost: fake.golang\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 4\r\nAccept-Encoding: gzip\r\n\r\nfoo\n`,
		},
		{
			name: "NothingWrittenNoBody",
			// It's key that we return 0 here -- that's what enables Transport to know
			// that nothing was written, even though this is a non-idempotent request.
			failureN:   0,
			failureErr: errors.New("second write fails"),
			req: func() *Request {
				return newRequest("DELETE", "http://fake.golang", nil)
			},
			reqString: `DELETE / HTTP/1.1\r\nHost: fake.golang\r\nUser-Agent: Go-http-client/1.1\r\nAccept-Encoding: gzip\r\n\r\n`,
		},
		{
			name: "NothingWrittenGetBody",
			// It's key that we return 0 here -- that's what enables Transport to know
			// that nothing was written, even though this is a non-idempotent request.
			failureN:   0,
			failureErr: errors.New("second write fails"),
			// Note that NewRequest will set up GetBody for strings.Reader, which is
			// required for the retry to occur
			req: func() *Request {
				return newRequest("POST", "http://fake.golang", strings.NewReader("foo\n"))
			},
			reqString: `POST / HTTP/1.1\r\nHost: fake.golang\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 4\r\nAccept-Encoding: gzip\r\n\r\nfoo\n`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu     sync.Mutex
				logbuf strings.Builder
			)
			logf := func(format string, args ...any) {
				mu.Lock()
				defer mu.Unlock()
				fmt.Fprintf(&logbuf, format, args...)
				logbuf.WriteByte('\n')
			}

			ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
				logf("Handler")
				w.Header().Set("X-Status", "ok")
			})).ts

			var writeNumAtomic int32
			c := ts.Client()
			c.Transport.(*Transport).Dial = func(network, addr string) (net.Conn, error) {
				logf("Dial")
				c, err := net.Dial(network, ts.Listener.Addr().String())
				if err != nil {
					logf("Dial error: %v", err)
					return nil, err
				}
				return &writerFuncConn{
					Conn: c,
					write: func(p []byte) (n int, err error) {
						if atomic.AddInt32(&writeNumAtomic, 1) == 2 {
							logf("intentional write failure")
							return tc.failureN, tc.failureErr
						}
						logf("Write(%q)", p)
						return c.Write(p)
					},
				}, nil
			}

			SetRoundTripRetried(func() {
				logf("Retried.")
			})
			defer SetRoundTripRetried(nil)

			for i := 0; i < 3; i++ {
				t0 := time.Now()
				req := tc.req()
				res, err := c.Do(req)
				if err != nil {
					if time.Since(t0) < *MaxWriteWaitBeforeConnReuse/2 {
						mu.Lock()
						got := logbuf.String()
						mu.Unlock()
						t.Fatalf("i=%d: Do = %v; log:\n%s", i, err, got)
					}
					t.Skipf("connection likely wasn't recycled within %d, interfering with actual test; skipping", *MaxWriteWaitBeforeConnReuse)
				}
				res.Body.Close()
				if res.Request != req {
					t.Errorf("Response.Request != original request; want identical Request")
				}
			}

			mu.Lock()
			got := logbuf.String()
			mu.Unlock()
			want := fmt.Sprintf(`Dial
Write("%s")
Handler
intentional write failure
Retried.
Dial
Write("%s")
Handler
Write("%s")
Handler
`, tc.reqString, tc.reqString, tc.reqString)
			if got != want {
				t.Errorf("Log of events differs. Got:\n%s\nWant:\n%s", got, want)
			}
		})
	}
}

// Issue 6981
func TestTransportClosesBodyOnError(t *testing.T) { run(t, testTransportClosesBodyOnError) }
func testTransportClosesBodyOnError(t *testing.T, mode testMode) {
	readBody := make(chan error, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := io.ReadAll(r.Body)
		readBody <- err
	})).ts
	c := ts.Client()
	fakeErr := errors.New("fake error")
	didClose := make(chan bool, 1)
	req, _ := NewRequest("POST", ts.URL, struct {
		io.Reader
		io.Closer
	}{
		io.MultiReader(io.LimitReader(neverEnding('x'), 1<<20), iotest.ErrReader(fakeErr)),
		closerFunc(func() error {
			select {
			case didClose <- true:
			default:
			}
			return nil
		}),
	})
	res, err := c.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), fakeErr.Error()) {
		t.Fatalf("Do error = %v; want something containing %q", err, fakeErr.Error())
	}
	if err := <-readBody; err == nil {
		t.Errorf("Unexpected success reading request body from handler; want 'unexpected EOF reading trailer'")
	}
	select {
	case <-didClose:
	default:
		t.Errorf("didn't see Body.Close")
	}
}

func TestTransportDialTLS(t *testing.T) {
	run(t, testTransportDialTLS, []testMode{https1Mode, http2Mode})
}
func testTransportDialTLS(t *testing.T, mode testMode) {
	var mu sync.Mutex // guards following
	var gotReq, didDial bool

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		mu.Lock()
		gotReq = true
		mu.Unlock()
	})).ts
	c := ts.Client()
	c.Transport.(*Transport).DialTLS = func(netw, addr string) (net.Conn, error) {
		mu.Lock()
		didDial = true
		mu.Unlock()
		c, err := tls.Dial(netw, addr, c.Transport.(*Transport).TLSClientConfig)
		if err != nil {
			return nil, err
		}
		return c, c.Handshake()
	}

	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	mu.Lock()
	if !gotReq {
		t.Error("didn't get request")
	}
	if !didDial {
		t.Error("didn't use dial hook")
	}
}

func TestTransportDialContext(t *testing.T) { run(t, testTransportDialContext) }
func testTransportDialContext(t *testing.T, mode testMode) {
	ctxKey := "some-key"
	ctxValue := "some-value"
	var (
		mu          sync.Mutex // guards following
		gotReq      bool
		gotCtxValue any
	)

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		mu.Lock()
		gotReq = true
		mu.Unlock()
	})).ts
	c := ts.Client()
	c.Transport.(*Transport).DialContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		mu.Lock()
		gotCtxValue = ctx.Value(ctxKey)
		mu.Unlock()
		return net.Dial(netw, addr)
	}

	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctxKey, ctxValue)
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	mu.Lock()
	if !gotReq {
		t.Error("didn't get request")
	}
	if got, want := gotCtxValue, ctxValue; got != want {
		t.Errorf("got context with value %v, want %v", got, want)
	}
}

func TestTransportDialTLSContext(t *testing.T) {
	run(t, testTransportDialTLSContext, []testMode{https1Mode, http2Mode})
}
func testTransportDialTLSContext(t *testing.T, mode testMode) {
	ctxKey := "some-key"
	ctxValue := "some-value"
	var (
		mu          sync.Mutex // guards following
		gotReq      bool
		gotCtxValue any
	)

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		mu.Lock()
		gotReq = true
		mu.Unlock()
	})).ts
	c := ts.Client()
	c.Transport.(*Transport).DialTLSContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		mu.Lock()
		gotCtxValue = ctx.Value(ctxKey)
		mu.Unlock()
		c, err := tls.Dial(netw, addr, c.Transport.(*Transport).TLSClientConfig)
		if err != nil {
			return nil, err
		}
		return c, c.HandshakeContext(ctx)
	}

	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctxKey, ctxValue)
	res, err := c.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	mu.Lock()
	if !gotReq {
		t.Error("didn't get request")
	}
	if got, want := gotCtxValue, ctxValue; got != want {
		t.Errorf("got context with value %v, want %v", got, want)
	}
}

// Test for issue 8755
// Ensure that if a proxy returns an error, it is exposed by RoundTrip
func TestRoundTripReturnsProxyError(t *testing.T) {
	badProxy := func(*Request) (*url.URL, error) {
		return nil, errors.New("errorMessage")
	}

	tr := &Transport{Proxy: badProxy}

	req, _ := NewRequest("GET", "http://example.com", nil)

	_, err := tr.RoundTrip(req)

	if err == nil {
		t.Error("Expected proxy error to be returned by RoundTrip")
	}
}

// tests that putting an idle conn after a call to CloseIdleConns does return it
func TestTransportCloseIdleConnsThenReturn(t *testing.T) {
	tr := &Transport{}
	wantIdle := func(when string, n int) bool {
		got := tr.IdleConnCountForTesting("http", "example.com") // key used by PutIdleTestConn
		if got == n {
			return true
		}
		t.Errorf("%s: idle conns = %d; want %d", when, got, n)
		return false
	}
	wantIdle("start", 0)
	if !tr.PutIdleTestConn("http", "example.com") {
		t.Fatal("put failed")
	}
	if !tr.PutIdleTestConn("http", "example.com") {
		t.Fatal("second put failed")
	}
	wantIdle("after put", 2)
	tr.CloseIdleConnections()
	if !tr.IsIdleForTesting() {
		t.Error("should be idle after CloseIdleConnections")
	}
	wantIdle("after close idle", 0)
	if tr.PutIdleTestConn("http", "example.com") {
		t.Fatal("put didn't fail")
	}
	wantIdle("after second put", 0)

	tr.QueueForIdleConnForTesting() // should toggle the transport out of idle mode
	if tr.IsIdleForTesting() {
		t.Error("shouldn't be idle after QueueForIdleConnForTesting")
	}
	if !tr.PutIdleTestConn("http", "example.com") {
		t.Fatal("after re-activation")
	}
	wantIdle("after final put", 1)
}

// Test for issue 34282
// Ensure that getConn doesn't call the GotConn trace hook on an HTTP/2 idle conn
func TestTransportTraceGotConnH2IdleConns(t *testing.T) {
	tr := &Transport{}
	wantIdle := func(when string, n int) bool {
		got := tr.IdleConnCountForTesting("https", "example.com:443") // key used by PutIdleTestConnH2
		if got == n {
			return true
		}
		t.Errorf("%s: idle conns = %d; want %d", when, got, n)
		return false
	}
	wantIdle("start", 0)
	alt := funcRoundTripper(func() {})
	if !tr.PutIdleTestConnH2("https", "example.com:443", alt) {
		t.Fatal("put failed")
	}
	wantIdle("after put", 1)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			// tr.getConn should leave it for the HTTP/2 alt to call GotConn.
			t.Error("GotConn called")
		},
	})
	req, _ := NewRequestWithContext(ctx, MethodGet, "https://example.com", nil)
	_, err := tr.RoundTrip(req)
	if err != errFakeRoundTrip {
		t.Errorf("got error: %v; want %q", err, errFakeRoundTrip)
	}
	wantIdle("after round trip", 1)
}

// https://go.dev/issue/70515
//
// When the first request on a new connection fails, we do not retry the request.
// If the first request on a connection races with IdleConnTimeout,
// we should not fail the request.
func TestTransportIdleConnRacesRequest(t *testing.T) {
	// Use unencrypted HTTP/2, since the *tls.Conn interfers with our ability to
	// block the connection closing.
	runSynctest(t, testTransportIdleConnRacesRequest, []testMode{http1Mode, http2UnencryptedMode})
}
func testTransportIdleConnRacesRequest(t testing.TB, mode testMode) {
	if mode == http2UnencryptedMode {
		t.Skip("remove skip when #70515 is fixed")
	}
	timeout := 1 * time.Millisecond
	trFunc := func(tr *Transport) {
		tr.IdleConnTimeout = timeout
	}
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
	}), trFunc, optFakeNet)
	cst.li.trackConns = true

	// We want to put a connection into the pool which has never had a request made on it.
	//
	// Make a request and cancel it before the dial completes.
	// Then complete the dial.
	dialc := make(chan struct{})
	cst.li.onDial = func() {
		<-dialc
	}
	ctx, cancel := context.WithCancel(context.Background())
	req1c := make(chan error)
	go func() {
		req, _ := NewRequestWithContext(ctx, "GET", cst.ts.URL, nil)
		resp, err := cst.c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		req1c <- err
	}()
	// Wait for the connection attempt to start.
	synctest.Wait()
	// Cancel the request.
	cancel()
	synctest.Wait()
	if err := <-req1c; err == nil {
		t.Fatal("expected request to fail, but it succeeded")
	}
	// Unblock the dial, placing a new, unused connection into the Transport's pool.
	close(dialc)

	// We want IdleConnTimeout to race with a new request.
	//
	// There's no perfect way to do this, but the following exercises the bug in #70515:
	// Block net.Conn.Close, wait until IdleConnTimeout occurs, and make a request while
	// the connection close is still blocked.
	//
	// First: Wait for IdleConnTimeout. The net.Conn.Close blocks.
	synctest.Wait()
	closec := make(chan struct{})
	cst.li.conns[0].peer.onClose = func() {
		<-closec
	}
	time.Sleep(timeout)
	synctest.Wait()
	// Make a request, which will use a new connection (since the existing one is closing).
	req2c := make(chan error)
	go func() {
		resp, err := cst.c.Get(cst.ts.URL)
		if err == nil {
			resp.Body.Close()
		}
		req2c <- err
	}()
	// Don't synctest.Wait here: The HTTP/1 transport closes the idle conn
	// with a mutex held, and we'll end up in a deadlock.
	close(closec)
	if err := <-req2c; err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestTransportRemovesConnsAfterIdle(t *testing.T) {
	runSynctest(t, testTransportRemovesConnsAfterIdle)
}
func testTransportRemovesConnsAfterIdle(t testing.TB, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	timeout := 1 * time.Second
	trFunc := func(tr *Transport) {
		tr.MaxConnsPerHost = 1
		tr.MaxIdleConnsPerHost = 1
		tr.IdleConnTimeout = timeout
	}
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Addr", r.RemoteAddr)
	}), trFunc, optFakeNet)

	// makeRequest returns the local address a request was made from
	// (unique for each connection).
	makeRequest := func() string {
		resp, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			t.Fatalf("got error: %s", err)
		}
		resp.Body.Close()
		return resp.Header.Get("X-Addr")
	}

	addr1 := makeRequest()

	time.Sleep(timeout / 2)
	synctest.Wait()
	addr2 := makeRequest()
	if addr1 != addr2 {
		t.Fatalf("two requests made within IdleConnTimeout should have used the same conn, but used %v, %v", addr1, addr2)
	}

	time.Sleep(timeout)
	synctest.Wait()
	addr3 := makeRequest()
	if addr1 == addr3 {
		t.Fatalf("two requests made more than IdleConnTimeout apart should have used different conns, but used %v, %v", addr1, addr3)
	}
}

func TestTransportRemovesConnsAfterBroken(t *testing.T) {
	runSynctest(t, testTransportRemovesConnsAfterBroken)
}
func testTransportRemovesConnsAfterBroken(t testing.TB, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	trFunc := func(tr *Transport) {
		tr.MaxConnsPerHost = 1
		tr.MaxIdleConnsPerHost = 1
	}
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Addr", r.RemoteAddr)
	}), trFunc, optFakeNet)
	cst.li.trackConns = true

	// makeRequest returns the local address a request was made from
	// (unique for each connection).
	makeRequest := func() string {
		resp, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			t.Fatalf("got error: %s", err)
		}
		resp.Body.Close()
		return resp.Header.Get("X-Addr")
	}

	addr1 := makeRequest()
	addr2 := makeRequest()
	if addr1 != addr2 {
		t.Fatalf("successive requests should have used the same conn, but used %v, %v", addr1, addr2)
	}

	// The connection breaks.
	synctest.Wait()
	cst.li.conns[0].peer.Close()
	synctest.Wait()
	addr3 := makeRequest()
	if addr1 == addr3 {
		t.Fatalf("successive requests made with conn broken between should have used different conns, but used %v, %v", addr1, addr3)
	}
}

// This tests that a client requesting a content range won't also
// implicitly ask for gzip support. If they want that, they need to do it
// on their own.
// golang.org/issue/8923
func TestTransportRangeAndGzip(t *testing.T) { run(t, testTransportRangeAndGzip) }
func testTransportRangeAndGzip(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Error("Transport advertised gzip support in the Accept header")
		}
		if r.Header.Get("Range") == "" {
			t.Error("no Range in request")
		}
	})).ts
	c := ts.Client()

	req, _ := NewRequest("GET", ts.URL, nil)
	req.Header.Set("Range", "bytes=7-11")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

// Test for issue 10474
func TestTransportResponseCancelRace(t *testing.T) { run(t, testTransportResponseCancelRace) }
func testTransportResponseCancelRace(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// important that this response has a body.
		var b [1024]byte
		w.Write(b[:])
	})).ts
	tr := ts.Client().Transport.(*Transport)

	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	// If we do an early close, Transport just throws the connection away and
	// doesn't reuse it. In order to trigger the bug, it has to reuse the connection
	// so read the body
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		t.Fatal(err)
	}

	req2, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.CancelRequest(req)
	res, err = tr.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

// Test for issue 19248: Content-Encoding's value is case insensitive.
func TestTransportContentEncodingCaseInsensitive(t *testing.T) {
	run(t, testTransportContentEncodingCaseInsensitive)
}
func testTransportContentEncodingCaseInsensitive(t *testing.T, mode testMode) {
	for _, ce := range []string{"gzip", "GZIP"} {
		ce := ce
		t.Run(ce, func(t *testing.T) {
			const encodedString = "Hello Gopher"
			ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
				w.Header().Set("Content-Encoding", ce)
				gz := gzip.NewWriter(w)
				gz.Write([]byte(encodedString))
				gz.Close()
			})).ts

			res, err := ts.Client().Get(ts.URL)
			if err != nil {
				t.Fatal(err)
			}

			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}

			if string(body) != encodedString {
				t.Fatalf("Expected body %q, got: %q\n", encodedString, string(body))
			}
		})
	}
}

// https://go.dev/issue/49621
func TestConnClosedBeforeRequestIsWritten(t *testing.T) {
	run(t, testConnClosedBeforeRequestIsWritten, testNotParallel, []testMode{http1Mode})
}
func testConnClosedBeforeRequestIsWritten(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {}),
		func(tr *Transport) {
			tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				// Connection immediately returns errors.
				return &funcConn{
					read: func([]byte) (int, error) {
						return 0, errors.New("error")
					},
					write: func([]byte) (int, error) {
						return 0, errors.New("error")
					},
				}, nil
			}
		},
	).ts
	// Set a short delay in RoundTrip to give the persistConn time to notice
	// the connection is broken. We want to exercise the path where writeLoop exits
	// before it reads the request to send. If this delay is too short, we may instead
	// exercise the path where writeLoop accepts the request and then fails to write it.
	// That's fine, so long as we get the desired path often enough.
	SetEnterRoundTripHook(func() {
		time.Sleep(1 * time.Millisecond)
	})
	defer SetEnterRoundTripHook(nil)
	var closes int
	_, err := ts.Client().Post(ts.URL, "text/plain", countCloseReader{&closes, strings.NewReader("hello")})
	if err == nil {
		t.Fatalf("expected request to fail, but it did not")
	}
	if closes != 1 {
		t.Errorf("after RoundTrip, request body was closed %v times; want 1", closes)
	}
}

// logWritesConn is a net.Conn that logs each Write call to writes
// and then proxies to w.
// It proxies Read calls to a reader it receives from rch.
type logWritesConn struct {
	net.Conn // nil. crash on use.

	w io.Writer

	rch <-chan io.Reader
	r   io.Reader // nil until received by rch

	mu     sync.Mutex
	writes []string
}

func (c *logWritesConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, string(p))
	return c.w.Write(p)
}

func (c *logWritesConn) Read(p []byte) (n int, err error) {
	if c.r == nil {
		c.r = <-c.rch
	}
	return c.r.Read(p)
}

func (c *logWritesConn) Close() error { return nil }

// Issue 6574
func TestTransportFlushesBodyChunks(t *testing.T) {
	defer afterTest(t)
	resBody := make(chan io.Reader, 1)
	connr, connw := io.Pipe() // connection pipe pair
	lw := &logWritesConn{
		rch: resBody,
		w:   connw,
	}
	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return lw, nil
		},
	}
	bodyr, bodyw := io.Pipe() // body pipe pair
	go func() {
		defer bodyw.Close()
		for i := 0; i < 3; i++ {
			fmt.Fprintf(bodyw, "num%d\n", i)
		}
	}()
	resc := make(chan *Response)
	go func() {
		req, _ := NewRequest("POST", "http://localhost:8080", bodyr)
		req.Header.Set("User-Agent", "x") // known value for test
		res, err := tr.RoundTrip(req)
		if err != nil {
			t.Errorf("RoundTrip: %v", err)
			close(resc)
			return
		}
		resc <- res

	}()
	// Fully consume the request before checking the Write log vs. want.
	req, err := ReadRequest(bufio.NewReader(connr))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, req.Body)

	// Unblock the transport's roundTrip goroutine.
	resBody <- strings.NewReader("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
	res, ok := <-resc
	if !ok {
		return
	}
	defer res.Body.Close()

	want := []string{
		"POST / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: x\r\nTransfer-Encoding: chunked\r\nAccept-Encoding: gzip\r\n\r\n",
		"5\r\nnum0\n\r\n",
		"5\r\nnum1\n\r\n",
		"5\r\nnum2\n\r\n",
		"0\r\n\r\n",
	}
	if !slices.Equal(lw.writes, want) {
		t.Errorf("Writes differed.\n Got: %q\nWant: %q\n", lw.writes, want)
	}
}

// Issue 22088: flush Transport request headers if we're not sure the body won't block on read.
func TestTransportFlushesRequestHeader(t *testing.T) { run(t, testTransportFlushesRequestHeader) }
func testTransportFlushesRequestHeader(t *testing.T, mode testMode) {
	gotReq := make(chan struct{})
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		close(gotReq)
	}))

	pr, pw := io.Pipe()
	req, err := NewRequest("POST", cst.ts.URL, pr)
	if err != nil {
		t.Fatal(err)
	}
	gotRes := make(chan struct{})
	go func() {
		defer close(gotRes)
		res, err := cst.tr.RoundTrip(req)
		if err != nil {
			t.Error(err)
			return
		}
		res.Body.Close()
	}()

	<-gotReq
	pw.Close()
	<-gotRes
}

type wgReadCloser struct {
	io.Reader
	wg     *sync.WaitGroup
	closed bool
}

func (c *wgReadCloser) Close() error {
	if c.closed {
		return net.ErrClosed
	}
	c.closed = true
	c.wg.Done()
	return nil
}

// Issue 11745.
func TestTransportPrefersResponseOverWriteError(t *testing.T) {
	// Not parallel: modifies the global rstAvoidanceDelay.
	run(t, testTransportPrefersResponseOverWriteError, testNotParallel)
}
func testTransportPrefersResponseOverWriteError(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

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

		const contentLengthLimit = 1024 * 1024 // 1MB
		cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			if r.ContentLength >= contentLengthLimit {
				w.WriteHeader(StatusBadRequest)
				r.Body.Close()
				return
			}
			w.WriteHeader(StatusOK)
		}))
		// We need to close cst explicitly here so that in-flight server
		// requests don't race with the call to SetRSTAvoidanceDelay for a retry.
		defer cst.close()
		ts := cst.ts
		c := ts.Client()

		count := 100

		bigBody := strings.Repeat("a", contentLengthLimit*2)
		var wg sync.WaitGroup
		defer wg.Wait()
		getBody := func() (io.ReadCloser, error) {
			wg.Add(1)
			body := &wgReadCloser{
				Reader: strings.NewReader(bigBody),
				wg:     &wg,
			}
			return body, nil
		}

		for i := 0; i < count; i++ {
			reqBody, _ := getBody()
			req, err := NewRequest("PUT", ts.URL, reqBody)
			if err != nil {
				reqBody.Close()
				t.Fatal(err)
			}
			req.ContentLength = int64(len(bigBody))
			req.GetBody = getBody

			resp, err := c.Do(req)
			if err != nil {
				return fmt.Errorf("Do %d: %v", i, err)
			} else {
				resp.Body.Close()
				if resp.StatusCode != 400 {
					t.Errorf("Expected status code 400, got %v", resp.Status)
				}
			}
		}
		return nil
	})
}

func TestTransportAutomaticHTTP2(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{}, true)
}

func T
```