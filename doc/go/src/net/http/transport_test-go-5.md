Response:
The user wants a summary of the Go code provided, which is part of the `transport_test.go` file in the `net/http` package. This is the 6th part of a 7-part sequence, suggesting the previous parts have already covered other functionalities of the HTTP transport implementation.

I need to:
1. **Identify the functionalities** demonstrated in the given code snippet.
2. **Summarize** these functionalities in Chinese.

Looking at the code, it covers several test cases related to HTTP transport behavior:
- Handling of responses with missing status text.
- Preventing body reads on 304 responses with chunked encoding.
- Early checking of context cancellation in `Transport.RoundTrip`.
- Closing connections when client requests time out (both before and after headers are sent).
- Handling protocol switching (101 responses) and making the response body writable.
- Testing the `CONNECT` method for proxying and bidirectional communication.
- Determining if a request is replayable based on its method and headers.
- Testing the use of `ReadFrom` for efficient body transmission.
- Cloning a `Transport` and ensuring fields are copied.
- Identifying 408 "Request Timeout" responses.
- Ignoring subsequent 408 responses on a persistent connection.
- Handling responses with invalid header formatting.
- Ensuring the request body is closed when invalid requests are made.
- Preventing broken HTTP/2 connections from being cached.
- Addressing a concurrency issue where removing an idle connection could lead to multiple decrements of active connections.
- Testing alternative protocol cancellation mechanisms.
- Ensuring the request body is reset after `ErrSkipAltProtocol`.
- Rejecting `Content-Length` headers with signs (+/-).
- A race condition test involving request cancellation and body access.
- Preventing request cancellation from affecting other requests using the same connection.
这段Go代码是`net/http`包中`transport_test.go`文件的一部分，它主要测试了`Transport`类型的多种功能，特别是关于连接管理、请求处理和错误处理的场景。作为第6部分，它延续了对HTTP传输层各种细节的测试。

以下是这段代码的功能归纳：

1. **测试处理缺少状态描述的HTTP响应**: 验证当服务器返回的HTTP响应行缺少状态描述时，客户端不会panic，并且能够返回包含 "unknown status code" 错误的响应。

2. **测试禁止读取带有分块编码的304响应体**:  确保对于状态码为304 (Not Modified) 且使用分块传输编码的响应，客户端不会尝试读取响应体，即使服务端发送了额外的数据。

3. **测试`Transport`提前检查Context是否已取消**: 验证`Transport`的`RoundTrip`方法会提前检查请求的Context是否已经取消，如果已取消则立即返回错误。

4. **测试客户端超时会关闭连接 (请求头之前)**: 验证当客户端设置了超时时间，且服务器在发送任何响应头之前超时时，`Transport`会关闭底层的连接，避免连接被复用。

5. **测试客户端超时会关闭连接 (请求头之后)**: 验证当客户端设置了超时时间，且服务器已经发送了响应头，但在发送响应体时超时，`Transport`也会关闭底层的连接。

6. **测试协议切换后响应体可写**:  验证当服务器返回状态码 101 (Switching Protocols) 时，客户端接收到的响应体可以被当作 `io.ReadWriteCloser` 使用，用于后续的双向通信。

7. **测试 `CONNECT` 方法的双向通信**:  测试使用 `CONNECT` 方法建立隧道代理时，客户端和代理服务器之间可以进行双向通信。

8. **测试请求是否可重放**:  定义了一系列测试用例，用于判断不同HTTP方法的请求是否可以被安全地重放（例如，GET请求可以重放，而POST请求通常不行，除非有幂等性相关的Header）。

9. **测试 `Transport` 请求写入的 `ReadFrom` 调用**:  验证当发送带有已知长度的文件作为请求体时，`Transport` 会调用底层 `net.TCPConn` 的 `ReadFrom` 方法来提高传输效率。

10. **测试 `Transport` 的克隆**: 验证 `Transport` 类型的 `Clone` 方法能够创建一个新的 `Transport` 实例，并复制原始实例的各种配置。

11. **测试判断是否为 408 响应**:  定义了一系列测试用例，判断给定的字节流是否表示一个 408 "Request Timeout" 的 HTTP 响应。

12. **测试 `Transport` 忽略后续的 408 响应**:  验证当一个持久连接上收到一个成功的响应后又收到一个 408 响应时，`Transport` 会忽略这个 408 响应，避免影响正常的连接复用。

13. **测试无效Header的响应处理**: 验证当服务器返回包含格式错误的Header时，客户端能够正确处理，不会因为格式错误而崩溃，但可能无法正确解析这些错误的Header。

14. **测试在无效请求时关闭请求体**: 确保当客户端构建了一个无效的请求（例如，方法名非法、URL为空等）并调用 `Client.Do` 时，即使请求发送失败，请求体也会被正确关闭。

15. **测试不缓存损坏的 HTTP/2 连接**: 验证当 HTTP/2 连接在使用过程中发生错误时，`Transport` 不会将这个损坏的连接加入连接池进行复用，而是会建立新的连接。

16. **测试当空闲连接被移除时只减少一次连接计数**:  解决了一个并发问题，即在高并发情况下，当连接池中的空闲连接被移除时，可能会错误地多次减少活跃连接的计数。

17. **测试备用协议取消**: 验证当使用 `RegisterProtocol` 注册的备用协议时，请求的取消机制仍然能正常工作。

18. **测试 `ErrSkipAltProtocol` 后 Body 被重置**:  确保在使用备用协议时，如果 `RoundTrip` 返回 `ErrSkipAltProtocol`，原始请求的 Body 会被正确地重置，以便后续的请求可以正常读取 Body。

19. **测试 `Transport` 拒绝 Content-Length 中的符号**:  验证 HTTP/1 传输层会拒绝包含符号（例如 "+3"）的 `Content-Length` Header，符合 RFC 规范。

20. **竞态测试**:  一个用于检测并发场景下 `Transport` 实现是否存在数据竞争的测试用例，模拟请求取消和请求体访问的并发操作。

21. **测试共享连接时取消请求**: 验证当多个请求复用同一个连接时，取消其中一个请求不会影响到其他正在进行的请求。

**总结这段代码的功能:**

这段代码主要集中在测试 `net/http.Transport` 的各种边缘情况和错误处理机制。它覆盖了从基本的请求响应处理，到更复杂的连接管理、超时控制、协议切换以及并发安全等多个方面。 通过这些细致的测试，可以确保 `net/http.Transport` 在各种网络环境和异常情况下都能稳定可靠地工作。

### 提示词
```
这是路径为go/src/net/http/transport_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x00, 0x17, 0x00, 0xe8, 0xff,
	0x42, 0x88, 0x21, 0xc4, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
	0x17, 0x00, 0xe8, 0xff, 0x42, 0x12, 0x46, 0x16,
	0x06, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x08,
	0x00, 0xf7, 0xff, 0x3d, 0xb1, 0x20, 0x85, 0xfa,
	0x00, 0x00, 0x00, 0x42, 0x12, 0x46, 0x16, 0x06,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x08, 0x00,
	0xf7, 0xff, 0x3d, 0xb1, 0x20, 0x85, 0xfa, 0x00,
	0x00, 0x00, 0x3d, 0xb1, 0x20, 0x85, 0xfa, 0x00,
	0x00, 0x00,
}

// Ensure that a missing status doesn't make the server panic
// See Issue https://golang.org/issues/21701
func TestMissingStatusNoPanic(t *testing.T) {
	t.Parallel()

	const want = "unknown status code"

	ln := newLocalListener(t)
	addr := ln.Addr().String()
	done := make(chan bool)
	fullAddrURL := fmt.Sprintf("http://%s", addr)
	raw := "HTTP/1.1 400\r\n" +
		"Date: Wed, 30 Aug 2017 19:09:27 GMT\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: 10\r\n" +
		"Last-Modified: Wed, 30 Aug 2017 19:02:02 GMT\r\n" +
		"Vary: Accept-Encoding\r\n\r\n" +
		"Aloha Olaa"

	go func() {
		defer close(done)

		conn, _ := ln.Accept()
		if conn != nil {
			io.WriteString(conn, raw)
			io.ReadAll(conn)
			conn.Close()
		}
	}()

	proxyURL, err := url.Parse(fullAddrURL)
	if err != nil {
		t.Fatalf("proxyURL: %v", err)
	}

	tr := &Transport{Proxy: ProxyURL(proxyURL)}

	req, _ := NewRequest("GET", "https://golang.org/", nil)
	res, err, panicked := doFetchCheckPanic(tr, req)
	if panicked {
		t.Error("panicked, expecting an error")
	}
	if res != nil && res.Body != nil {
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}

	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got=%v want=%q", err, want)
	}

	ln.Close()
	<-done
}

func doFetchCheckPanic(tr *Transport, req *Request) (res *Response, err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
		}
	}()
	res, err = tr.RoundTrip(req)
	return
}

// Issue 22330: do not allow the response body to be read when the status code
// forbids a response body.
func TestNoBodyOnChunked304Response(t *testing.T) {
	run(t, testNoBodyOnChunked304Response, []testMode{http1Mode})
}
func testNoBodyOnChunked304Response(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		conn, buf, _ := w.(Hijacker).Hijack()
		buf.Write([]byte("HTTP/1.1 304 NOT MODIFIED\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
		buf.Flush()
		conn.Close()
	}))

	// Our test server above is sending back bogus data after the
	// response (the "0\r\n\r\n" part), which causes the Transport
	// code to log spam. Disable keep-alives so we never even try
	// to reuse the connection.
	cst.tr.DisableKeepAlives = true

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if res.Body != NoBody {
		t.Errorf("Unexpected body on 304 response")
	}
}

type funcWriter func([]byte) (int, error)

func (f funcWriter) Write(p []byte) (int, error) { return f(p) }

type doneContext struct {
	context.Context
	err error
}

func (doneContext) Done() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

func (d doneContext) Err() error { return d.err }

// Issue 25852: Transport should check whether Context is done early.
func TestTransportCheckContextDoneEarly(t *testing.T) {
	tr := &Transport{}
	req, _ := NewRequest("GET", "http://fake.example/", nil)
	wantErr := errors.New("some error")
	req = req.WithContext(doneContext{context.Background(), wantErr})
	_, err := tr.RoundTrip(req)
	if err != wantErr {
		t.Errorf("error = %v; want %v", err, wantErr)
	}
}

// Issue 23399: verify that if a client request times out, the Transport's
// conn is closed so that it's not reused.
//
// This is the test variant that times out before the server replies with
// any response headers.
func TestClientTimeoutKillsConn_BeforeHeaders(t *testing.T) {
	run(t, testClientTimeoutKillsConn_BeforeHeaders, []testMode{http1Mode})
}
func testClientTimeoutKillsConn_BeforeHeaders(t *testing.T, mode testMode) {
	timeout := 1 * time.Millisecond
	for {
		inHandler := make(chan bool)
		cancelHandler := make(chan struct{})
		handlerDone := make(chan bool)
		cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			<-r.Context().Done()

			select {
			case <-cancelHandler:
				return
			case inHandler <- true:
			}
			defer func() { handlerDone <- true }()

			// Read from the conn until EOF to verify that it was correctly closed.
			conn, _, err := w.(Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			n, err := conn.Read([]byte{0})
			if n != 0 || err != io.EOF {
				t.Errorf("unexpected Read result: %v, %v", n, err)
			}
			conn.Close()
		}))

		cst.c.Timeout = timeout

		_, err := cst.c.Get(cst.ts.URL)
		if err == nil {
			close(cancelHandler)
			t.Fatal("unexpected Get success")
		}

		tooSlow := time.NewTimer(timeout * 10)
		select {
		case <-tooSlow.C:
			// If we didn't get into the Handler, that probably means the builder was
			// just slow and the Get failed in that time but never made it to the
			// server. That's fine; we'll try again with a longer timeout.
			t.Logf("no handler seen in %v; retrying with longer timeout", timeout)
			close(cancelHandler)
			cst.close()
			timeout *= 2
			continue
		case <-inHandler:
			tooSlow.Stop()
			<-handlerDone
		}
		break
	}
}

// Issue 23399: verify that if a client request times out, the Transport's
// conn is closed so that it's not reused.
//
// This is the test variant that has the server send response headers
// first, and time out during the write of the response body.
func TestClientTimeoutKillsConn_AfterHeaders(t *testing.T) {
	run(t, testClientTimeoutKillsConn_AfterHeaders, []testMode{http1Mode})
}
func testClientTimeoutKillsConn_AfterHeaders(t *testing.T, mode testMode) {
	inHandler := make(chan bool)
	cancelHandler := make(chan struct{})
	handlerDone := make(chan bool)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "100")
		w.(Flusher).Flush()

		select {
		case <-cancelHandler:
			return
		case inHandler <- true:
		}
		defer func() { handlerDone <- true }()

		conn, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Write([]byte("foo"))

		n, err := conn.Read([]byte{0})
		// The error should be io.EOF or "read tcp
		// 127.0.0.1:35827->127.0.0.1:40290: read: connection
		// reset by peer" depending on timing. Really we just
		// care that it returns at all. But if it returns with
		// data, that's weird.
		if n != 0 || err == nil {
			t.Errorf("unexpected Read result: %v, %v", n, err)
		}
		conn.Close()
	}))

	// Set Timeout to something very long but non-zero to exercise
	// the codepaths that check for it. But rather than wait for it to fire
	// (which would make the test slow), we send on the req.Cancel channel instead,
	// which happens to exercise the same code paths.
	cst.c.Timeout = 24 * time.Hour // just to be non-zero, not to hit it.
	req, _ := NewRequest("GET", cst.ts.URL, nil)
	cancelReq := make(chan struct{})
	req.Cancel = cancelReq

	res, err := cst.c.Do(req)
	if err != nil {
		close(cancelHandler)
		t.Fatalf("Get error: %v", err)
	}

	// Cancel the request while the handler is still blocked on sending to the
	// inHandler channel. Then read it until it fails, to verify that the
	// connection is broken before the handler itself closes it.
	close(cancelReq)
	got, err := io.ReadAll(res.Body)
	if err == nil {
		t.Errorf("unexpected success; read %q, nil", got)
	}

	// Now unblock the handler and wait for it to complete.
	<-inHandler
	<-handlerDone
}

func TestTransportResponseBodyWritableOnProtocolSwitch(t *testing.T) {
	run(t, testTransportResponseBodyWritableOnProtocolSwitch, []testMode{http1Mode})
}
func testTransportResponseBodyWritableOnProtocolSwitch(t *testing.T, mode testMode) {
	done := make(chan struct{})
	defer close(done)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		conn, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 101 Switching Protocols Hi\r\nConnection: upgRADe\r\nUpgrade: foo\r\n\r\nSome buffered data\n")
		bs := bufio.NewScanner(conn)
		bs.Scan()
		fmt.Fprintf(conn, "%s\n", strings.ToUpper(bs.Text()))
		<-done
	}))

	req, _ := NewRequest("GET", cst.ts.URL, nil)
	req.Header.Set("Upgrade", "foo")
	req.Header.Set("Connection", "upgrade")
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("expected 101 switching protocols; got %v, %v", res.Status, res.Header)
	}
	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("expected a ReadWriteCloser; got a %T", res.Body)
	}
	defer rwc.Close()
	bs := bufio.NewScanner(rwc)
	if !bs.Scan() {
		t.Fatalf("expected readable input")
	}
	if got, want := bs.Text(), "Some buffered data"; got != want {
		t.Errorf("read %q; want %q", got, want)
	}
	io.WriteString(rwc, "echo\n")
	if !bs.Scan() {
		t.Fatalf("expected another line")
	}
	if got, want := bs.Text(), "ECHO"; got != want {
		t.Errorf("read %q; want %q", got, want)
	}
}

func TestTransportCONNECTBidi(t *testing.T) { run(t, testTransportCONNECTBidi, []testMode{http1Mode}) }
func testTransportCONNECTBidi(t *testing.T, mode testMode) {
	const target = "backend:443"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "CONNECT" {
			t.Errorf("unexpected method %q", r.Method)
			w.WriteHeader(500)
			return
		}
		if r.RequestURI != target {
			t.Errorf("unexpected CONNECT target %q", r.RequestURI)
			w.WriteHeader(500)
			return
		}
		nc, brw, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer nc.Close()
		nc.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		// Switch to a little protocol that capitalize its input lines:
		for {
			line, err := brw.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					t.Error(err)
				}
				return
			}
			io.WriteString(brw, strings.ToUpper(line))
			brw.Flush()
		}
	}))
	pr, pw := io.Pipe()
	defer pw.Close()
	req, err := NewRequest("CONNECT", cst.ts.URL, pr)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.Opaque = target
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status code = %d; want 200", res.StatusCode)
	}
	br := bufio.NewReader(res.Body)
	for _, str := range []string{"foo", "bar", "baz"} {
		fmt.Fprintf(pw, "%s\n", str)
		got, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		got = strings.TrimSpace(got)
		want := strings.ToUpper(str)
		if got != want {
			t.Fatalf("got %q; want %q", got, want)
		}
	}
}

func TestTransportRequestReplayable(t *testing.T) {
	someBody := io.NopCloser(strings.NewReader(""))
	tests := []struct {
		name string
		req  *Request
		want bool
	}{
		{
			name: "GET",
			req:  &Request{Method: "GET"},
			want: true,
		},
		{
			name: "GET_http.NoBody",
			req:  &Request{Method: "GET", Body: NoBody},
			want: true,
		},
		{
			name: "GET_body",
			req:  &Request{Method: "GET", Body: someBody},
			want: false,
		},
		{
			name: "POST",
			req:  &Request{Method: "POST"},
			want: false,
		},
		{
			name: "POST_idempotency-key",
			req:  &Request{Method: "POST", Header: Header{"Idempotency-Key": {"x"}}},
			want: true,
		},
		{
			name: "POST_x-idempotency-key",
			req:  &Request{Method: "POST", Header: Header{"X-Idempotency-Key": {"x"}}},
			want: true,
		},
		{
			name: "POST_body",
			req:  &Request{Method: "POST", Header: Header{"Idempotency-Key": {"x"}}, Body: someBody},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.ExportIsReplayable()
			if got != tt.want {
				t.Errorf("replyable = %v; want %v", got, tt.want)
			}
		})
	}
}

// testMockTCPConn is a mock TCP connection used to test that
// ReadFrom is called when sending the request body.
type testMockTCPConn struct {
	*net.TCPConn

	ReadFromCalled bool
}

func (c *testMockTCPConn) ReadFrom(r io.Reader) (int64, error) {
	c.ReadFromCalled = true
	return c.TCPConn.ReadFrom(r)
}

func TestTransportRequestWriteRoundTrip(t *testing.T) { run(t, testTransportRequestWriteRoundTrip) }
func testTransportRequestWriteRoundTrip(t *testing.T, mode testMode) {
	nBytes := int64(1 << 10)
	newFileFunc := func() (r io.Reader, done func(), err error) {
		f, err := os.CreateTemp("", "net-http-newfilefunc")
		if err != nil {
			return nil, nil, err
		}

		// Write some bytes to the file to enable reading.
		if _, err := io.CopyN(f, rand.Reader, nBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to write data to file: %v", err)
		}
		if _, err := f.Seek(0, 0); err != nil {
			return nil, nil, fmt.Errorf("failed to seek to front: %v", err)
		}

		done = func() {
			f.Close()
			os.Remove(f.Name())
		}

		return f, done, nil
	}

	newBufferFunc := func() (io.Reader, func(), error) {
		return bytes.NewBuffer(make([]byte, nBytes)), func() {}, nil
	}

	cases := []struct {
		name             string
		readerFunc       func() (io.Reader, func(), error)
		contentLength    int64
		expectedReadFrom bool
	}{
		{
			name:             "file, length",
			readerFunc:       newFileFunc,
			contentLength:    nBytes,
			expectedReadFrom: true,
		},
		{
			name:       "file, no length",
			readerFunc: newFileFunc,
		},
		{
			name:          "file, negative length",
			readerFunc:    newFileFunc,
			contentLength: -1,
		},
		{
			name:          "buffer",
			contentLength: nBytes,
			readerFunc:    newBufferFunc,
		},
		{
			name:       "buffer, no length",
			readerFunc: newBufferFunc,
		},
		{
			name:          "buffer, length -1",
			contentLength: -1,
			readerFunc:    newBufferFunc,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, cleanup, err := tc.readerFunc()
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			tConn := &testMockTCPConn{}
			trFunc := func(tr *Transport) {
				tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					var d net.Dialer
					conn, err := d.DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}

					tcpConn, ok := conn.(*net.TCPConn)
					if !ok {
						return nil, fmt.Errorf("%s/%s does not provide a *net.TCPConn", network, addr)
					}

					tConn.TCPConn = tcpConn
					return tConn, nil
				}
			}

			cst := newClientServerTest(
				t,
				mode,
				HandlerFunc(func(w ResponseWriter, r *Request) {
					io.Copy(io.Discard, r.Body)
					r.Body.Close()
					w.WriteHeader(200)
				}),
				trFunc,
			)

			req, err := NewRequest("PUT", cst.ts.URL, r)
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = tc.contentLength
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := cst.c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status code = %d; want 200", resp.StatusCode)
			}

			expectedReadFrom := tc.expectedReadFrom
			if mode != http1Mode {
				expectedReadFrom = false
			}
			if !tConn.ReadFromCalled && expectedReadFrom {
				t.Fatalf("did not call ReadFrom")
			}

			if tConn.ReadFromCalled && !expectedReadFrom {
				t.Fatalf("ReadFrom was unexpectedly invoked")
			}
		})
	}
}

func TestTransportClone(t *testing.T) {
	tr := &Transport{
		Proxy: func(*Request) (*url.URL, error) { panic("") },
		OnProxyConnectResponse: func(ctx context.Context, proxyURL *url.URL, connectReq *Request, connectRes *Response) error {
			return nil
		},
		DialContext:            func(ctx context.Context, network, addr string) (net.Conn, error) { panic("") },
		Dial:                   func(network, addr string) (net.Conn, error) { panic("") },
		DialTLS:                func(network, addr string) (net.Conn, error) { panic("") },
		DialTLSContext:         func(ctx context.Context, network, addr string) (net.Conn, error) { panic("") },
		TLSClientConfig:        new(tls.Config),
		TLSHandshakeTimeout:    time.Second,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxIdleConns:           1,
		MaxIdleConnsPerHost:    1,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        time.Second,
		ResponseHeaderTimeout:  time.Second,
		ExpectContinueTimeout:  time.Second,
		ProxyConnectHeader:     Header{},
		GetProxyConnectHeader:  func(context.Context, *url.URL, string) (Header, error) { return nil, nil },
		MaxResponseHeaderBytes: 1,
		ForceAttemptHTTP2:      true,
		HTTP2:                  &HTTP2Config{MaxConcurrentStreams: 1},
		Protocols:              &Protocols{},
		TLSNextProto: map[string]func(authority string, c *tls.Conn) RoundTripper{
			"foo": func(authority string, c *tls.Conn) RoundTripper { panic("") },
		},
		ReadBufferSize:  1,
		WriteBufferSize: 1,
	}
	tr.Protocols.SetHTTP1(true)
	tr.Protocols.SetHTTP2(true)
	tr2 := tr.Clone()
	rv := reflect.ValueOf(tr2).Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if !token.IsExported(sf.Name) {
			continue
		}
		if rv.Field(i).IsZero() {
			t.Errorf("cloned field t2.%s is zero", sf.Name)
		}
	}

	if _, ok := tr2.TLSNextProto["foo"]; !ok {
		t.Errorf("cloned Transport lacked TLSNextProto 'foo' key")
	}

	// But test that a nil TLSNextProto is kept nil:
	tr = new(Transport)
	tr2 = tr.Clone()
	if tr2.TLSNextProto != nil {
		t.Errorf("Transport.TLSNextProto unexpected non-nil")
	}
}

func TestIs408(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"HTTP/1.0 408", true},
		{"HTTP/1.1 408", true},
		{"HTTP/1.8 408", true},
		{"HTTP/2.0 408", false}, // maybe h2c would do this? but false for now.
		{"HTTP/1.1 408 ", true},
		{"HTTP/1.1 40", false},
		{"http/1.0 408", false},
		{"HTTP/1-1 408", false},
	}
	for _, tt := range tests {
		if got := Export_is408Message([]byte(tt.in)); got != tt.want {
			t.Errorf("is408Message(%q) = %v; want %v", tt.in, got, tt.want)
		}
	}
}

func TestTransportIgnores408(t *testing.T) {
	run(t, testTransportIgnores408, []testMode{http1Mode}, testNotParallel)
}
func testTransportIgnores408(t *testing.T, mode testMode) {
	// Not parallel. Relies on mutating the log package's global Output.
	defer log.SetOutput(log.Writer())

	var logout strings.Builder
	log.SetOutput(&logout)

	const target = "backend:443"

	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		nc, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer nc.Close()
		nc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		nc.Write([]byte("HTTP/1.1 408 bye\r\n")) // changing 408 to 409 makes test fail
	}))
	req, err := NewRequest("GET", cst.ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(slurp) != "ok" {
		t.Fatalf("got %q; want ok", slurp)
	}

	waitCondition(t, 1*time.Millisecond, func(d time.Duration) bool {
		if n := cst.tr.IdleConnKeyCountForTesting(); n != 0 {
			if d > 0 {
				t.Logf("%v idle conns still present after %v", n, d)
			}
			return false
		}
		return true
	})
	if got := logout.String(); got != "" {
		t.Fatalf("expected no log output; got: %s", got)
	}
}

func TestInvalidHeaderResponse(t *testing.T) {
	run(t, testInvalidHeaderResponse, []testMode{http1Mode})
}
func testInvalidHeaderResponse(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		conn, buf, _ := w.(Hijacker).Hijack()
		buf.Write([]byte("HTTP/1.1 200 OK\r\n" +
			"Date: Wed, 30 Aug 2017 19:09:27 GMT\r\n" +
			"Content-Type: text/html; charset=utf-8\r\n" +
			"Content-Length: 0\r\n" +
			"Foo : bar\r\n\r\n"))
		buf.Flush()
		conn.Close()
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if v := res.Header.Get("Foo"); v != "" {
		t.Errorf(`unexpected "Foo" header: %q`, v)
	}
	if v := res.Header.Get("Foo "); v != "bar" {
		t.Errorf(`bad "Foo " header value: %q, want %q`, v, "bar")
	}
}

type bodyCloser bool

func (bc *bodyCloser) Close() error {
	*bc = true
	return nil
}
func (bc *bodyCloser) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

// Issue 35015: ensure that Transport closes the body on any error
// with an invalid request, as promised by Client.Do docs.
func TestTransportClosesBodyOnInvalidRequests(t *testing.T) {
	run(t, testTransportClosesBodyOnInvalidRequests)
}
func testTransportClosesBodyOnInvalidRequests(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		t.Errorf("Should not have been invoked")
	})).ts

	u, _ := url.Parse(cst.URL)

	tests := []struct {
		name    string
		req     *Request
		wantErr string
	}{
		{
			name: "invalid method",
			req: &Request{
				Method: " ",
				URL:    u,
			},
			wantErr: `invalid method " "`,
		},
		{
			name: "nil URL",
			req: &Request{
				Method: "GET",
			},
			wantErr: `nil Request.URL`,
		},
		{
			name: "invalid header key",
			req: &Request{
				Method: "GET",
				Header: Header{"💡": {"emoji"}},
				URL:    u,
			},
			wantErr: `invalid header field name "💡"`,
		},
		{
			name: "invalid header value",
			req: &Request{
				Method: "POST",
				Header: Header{"key": {"\x19"}},
				URL:    u,
			},
			wantErr: `invalid header field value for "key"`,
		},
		{
			name: "non HTTP(s) scheme",
			req: &Request{
				Method: "POST",
				URL:    &url.URL{Scheme: "faux"},
			},
			wantErr: `unsupported protocol scheme "faux"`,
		},
		{
			name: "no Host in URL",
			req: &Request{
				Method: "POST",
				URL:    &url.URL{Scheme: "http"},
			},
			wantErr: `no Host in request URL`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bc bodyCloser
			req := tt.req
			req.Body = &bc
			_, err := cst.Client().Do(tt.req)
			if err == nil {
				t.Fatal("Expected an error")
			}
			if !bc {
				t.Fatal("Expected body to have been closed")
			}
			if g, w := err.Error(), tt.wantErr; !strings.HasSuffix(g, w) {
				t.Fatalf("Error mismatch: %q does not end with %q", g, w)
			}
		})
	}
}

// breakableConn is a net.Conn wrapper with a Write method
// that will fail when its brokenState is true.
type breakableConn struct {
	net.Conn
	*brokenState
}

type brokenState struct {
	sync.Mutex
	broken bool
}

func (w *breakableConn) Write(b []byte) (n int, err error) {
	w.Lock()
	defer w.Unlock()
	if w.broken {
		return 0, errors.New("some write error")
	}
	return w.Conn.Write(b)
}

// Issue 34978: don't cache a broken HTTP/2 connection
func TestDontCacheBrokenHTTP2Conn(t *testing.T) {
	run(t, testDontCacheBrokenHTTP2Conn, []testMode{http2Mode})
}
func testDontCacheBrokenHTTP2Conn(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {}), optQuietLog)

	var brokenState brokenState

	const numReqs = 5
	var numDials, gotConns uint32 // atomic

	cst.tr.Dial = func(netw, addr string) (net.Conn, error) {
		atomic.AddUint32(&numDials, 1)
		c, err := net.Dial(netw, addr)
		if err != nil {
			t.Errorf("unexpected Dial error: %v", err)
			return nil, err
		}
		return &breakableConn{c, &brokenState}, err
	}

	for i := 1; i <= numReqs; i++ {
		brokenState.Lock()
		brokenState.broken = false
		brokenState.Unlock()

		// doBreak controls whether we break the TCP connection after the TLS
		// handshake (before the HTTP/2 handshake). We test a few failures
		// in a row followed by a final success.
		doBreak := i != numReqs

		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				t.Logf("got conn: %v, reused=%v, wasIdle=%v, idleTime=%v", info.Conn.LocalAddr(), info.Reused, info.WasIdle, info.IdleTime)
				atomic.AddUint32(&gotConns, 1)
			},
			TLSHandshakeDone: func(cfg tls.ConnectionState, err error) {
				brokenState.Lock()
				defer brokenState.Unlock()
				if doBreak {
					brokenState.broken = true
				}
			},
		})
		req, err := NewRequestWithContext(ctx, "GET", cst.ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cst.c.Do(req)
		if doBreak != (err != nil) {
			t.Errorf("for iteration %d, doBreak=%v; unexpected error %v", i, doBreak, err)
		}
	}
	if got, want := atomic.LoadUint32(&gotConns), 1; int(got) != want {
		t.Errorf("GotConn calls = %v; want %v", got, want)
	}
	if got, want := atomic.LoadUint32(&numDials), numReqs; int(got) != want {
		t.Errorf("Dials = %v; want %v", got, want)
	}
}

// Issue 34941
// When the client has too many concurrent requests on a single connection,
// http.http2noCachedConnError is reported on multiple requests. There should
// only be one decrement regardless of the number of failures.
func TestTransportDecrementConnWhenIdleConnRemoved(t *testing.T) {
	run(t, testTransportDecrementConnWhenIdleConnRemoved, []testMode{http2Mode})
}
func testTransportDecrementConnWhenIdleConnRemoved(t *testing.T, mode testMode) {
	CondSkipHTTP2(t)

	h := HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := w.Write([]byte("foo"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	})

	ts := newClientServerTest(t, mode, h).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.MaxConnsPerHost = 1

	errCh := make(chan error, 300)
	doReq := func() {
		resp, err := c.Get(ts.URL)
		if err != nil {
			errCh <- fmt.Errorf("request failed: %v", err)
			return
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		if err != nil {
			errCh <- fmt.Errorf("read body failed: %v", err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doReq()
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("error occurred: %v", err)
	}
}

// Issue 36820
// Test that we use the older backward compatible cancellation protocol
// when a RoundTripper is registered via RegisterProtocol.
func TestAltProtoCancellation(t *testing.T) {
	defer afterTest(t)
	tr := &Transport{}
	c := &Client{
		Transport: tr,
		Timeout:   time.Millisecond,
	}
	tr.RegisterProtocol("cancel", cancelProto{})
	_, err := c.Get("cancel://bar.com/path")
	if err == nil {
		t.Error("request unexpectedly succeeded")
	} else if !strings.Contains(err.Error(), errCancelProto.Error()) {
		t.Errorf("got error %q, does not contain expected string %q", err, errCancelProto)
	}
}

var errCancelProto = errors.New("canceled as expected")

type cancelProto struct{}

func (cancelProto) RoundTrip(req *Request) (*Response, error) {
	<-req.Cancel
	return nil, errCancelProto
}

type roundTripFunc func(r *Request) (*Response, error)

func (f roundTripFunc) RoundTrip(r *Request) (*Response, error) { return f(r) }

// Issue 32441: body is not reset after ErrSkipAltProtocol
func TestIssue32441(t *testing.T) { run(t, testIssue32441, []testMode{http1Mode}) }
func testIssue32441(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if n, _ := io.Copy(io.Discard, r.Body); n == 0 {
			t.Error("body length is zero")
		}
	})).ts
	c := ts.Client()
	c.Transport.(*Transport).RegisterProtocol("http", roundTripFunc(func(r *Request) (*Response, error) {
		// Draining body to trigger failure condition on actual request to server.
		if n, _ := io.Copy(io.Discard, r.Body); n == 0 {
			t.Error("body length is zero during round trip")
		}
		return nil, ErrSkipAltProtocol
	}))
	if _, err := c.Post(ts.URL, "application/octet-stream", bytes.NewBufferString("data")); err != nil {
		t.Error(err)
	}
}

// Issue 39017. Ensure that HTTP/1 transports reject Content-Length headers
// that contain a sign (eg. "+3"), per RFC 2616, Section 14.13.
func TestTransportRejectsSignInContentLength(t *testing.T) {
	run(t, testTransportRejectsSignInContentLength, []testMode{http1Mode})
}
func testTransportRejectsSignInContentLength(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "+3")
		w.Write([]byte("abc"))
	})).ts

	c := cst.Client()
	res, err := c.Get(cst.URL)
	if err == nil || res != nil {
		t.Fatal("Expected a non-nil error and a nil http.Response")
	}
	if got, want := err.Error(), `bad Content-Length "+3"`; !strings.Contains(got, want) {
		t.Fatalf("Error mismatch\nGot: %q\nWanted substring: %q", got, want)
	}
}

// dumpConn is a net.Conn which writes to Writer and reads from Reader
type dumpConn struct {
	io.Writer
	io.Reader
}

func (c *dumpConn) Close() error                       { return nil }
func (c *dumpConn) LocalAddr() net.Addr                { return nil }
func (c *dumpConn) RemoteAddr() net.Addr               { return nil }
func (c *dumpConn) SetDeadline(t time.Time) error      { return nil }
func (c *dumpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dumpConn) SetWriteDeadline(t time.Time) error { return nil }

// delegateReader is a reader that delegates to another reader,
// once it arrives on a channel.
type delegateReader struct {
	c chan io.Reader
	r io.Reader // nil until received from c
}

func (r *delegateReader) Read(p []byte) (int, error) {
	if r.r == nil {
		var ok bool
		if r.r, ok = <-r.c; !ok {
			return 0, errors.New("delegate closed")
		}
	}
	return r.r.Read(p)
}

func testTransportRace(req *Request) {
	save := req.Body
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	dr := &delegateReader{c: make(chan io.Reader)}

	t := &Transport{
		Dial: func(net, addr string) (net.Conn, error) {
			return &dumpConn{pw, dr}, nil
		},
	}
	defer t.CloseIdleConnections()

	quitReadCh := make(chan struct{})
	// Wait for the request before replying with a dummy response:
	go func() {
		defer close(quitReadCh)

		req, err := ReadRequest(bufio.NewReader(pr))
		if err == nil {
			// Ensure all the body is read; otherwise
			// we'll get a partial dump.
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
		}
		select {
		case dr.c <- strings.NewReader("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"):
		case quitReadCh <- struct{}{}:
			// Ensure delegate is closed so Read doesn't block forever.
			close(dr.c)
		}
	}()

	t.RoundTrip(req)

	// Ensure the reader returns before we reset req.Body to prevent
	// a data race on req.Body.
	pw.Close()
	<-quitReadCh

	req.Body = save
}

// Issue 37669
// Test that a cancellation doesn't result in a data race due to the writeLoop
// goroutine being left running, if the caller mutates the processed Request
// upon completion.
func TestErrorWriteLoopRace(t *testing.T) {
	if testing.Short() {
		return
	}
	t.Parallel()
	for i := 0; i < 1000; i++ {
		delay := time.Duration(mrand.Intn(5)) * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), delay)
		defer cancel()

		r := bytes.NewBuffer(make([]byte, 10000))
		req, err := NewRequestWithContext(ctx, MethodPost, "http://example.com", r)
		if err != nil {
			t.Fatal(err)
		}

		testTransportRace(req)
	}
}

// Issue 41600
// Test that a new request which uses the connection of an active request
// cannot cause it to be canceled as well.
func TestCancelRequestWhenSharingConnection(t *testing.T) {
	run(t, testCancelRequestWhenSharingConnection, []testMode{http1Mode})
}
func testCancelRequestWhenSharingConnection(t *testing.T, mode testMode) {
	reqc := make(chan chan struct{}, 2)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, req *Request) {
		ch := make(chan struct{}, 1)
		reqc <- ch
		<-ch
		w.Header().Add("Content-Length", "0")
	})).ts

	client := ts.Client()
	transport := client.Transport.(*Transport)
	transport.MaxIdleConns = 1
	transport.MaxConnsPerHost = 1

	var wg sync.WaitGroup

	wg.Add(1)
	putidlec := make(chan chan struct{}, 1)
	reqerrc := make(chan error, 1)
	go func() {
		defer wg.Done()
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			PutIdleConn: func(error) {
				// Signal that the idle conn has been returned to the pool,
				// and wait for the order to proceed.
				ch := make(chan struct{})
				putidlec <- ch
				close(putidlec) // panic if PutIdleConn runs twice for some reason
				<-ch
			},
		})
		req, _ := NewRequestWithContext(ctx, "GET", ts.URL, nil)
		res, err := client.Do(req)
		if err != nil {
			reqerrc <- err
		} else {
			res.Body.Close()
		}
	}()

	// Wait for the first request to receive a response and return the
	// connection to the idle pool.
	select {
	case err := <-reqerrc:
		t.Fatalf("request 1: got err %v, want nil", err)
	case
```