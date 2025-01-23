Response:
The user wants a summary of the functionality of the provided Go code snippet from `go/src/net/http/transport_test.go`. This snippet mainly focuses on testing the `Transport` type's behavior related to automatic HTTP/2 upgrades and various connection management aspects.

Here's a breakdown of the code's functionality:

1. **Automatic HTTP/2 Tests:**  Tests scenarios where the `Transport` attempts to upgrade to HTTP/2. This involves checking configurations like `ForceAttemptHTTP2`, `TLSClientConfig`, `TLSNextProto`, `ExpectContinueTimeout`, `Dial`, `DialContext`, and `DialTLS`. The `testTransportAutoHTTP` function seems to be a helper for these tests.

2. **Connection Reuse:** Tests related to reusing TCP connections, particularly for empty response bodies and gzipped responses. It ensures that subsequent requests can utilize the same underlying connection.

3. **Alternative Connection Handling:** Tests a scenario where an alternative protocol (like "foo") is negotiated during TLS handshake. It verifies that the correct `RoundTripper` is associated with the alternative protocol and that the main `Dial` function isn't called.

4. **Response Header Length Limit:** Tests the `MaxResponseHeaderBytes` functionality, ensuring that the `Transport` correctly limits the size of response headers.

5. **`httptrace` Integration:** Several tests focus on the integration with the `httptrace` package, verifying that various hooks (like DNS lookup, connection establishment, TLS handshake, etc.) are triggered correctly. There are tests for both regular scenarios and cases with no hooks configured.

6. **DNS Handling:** Tests involving both successful and unsuccessful DNS lookups, including scenarios with a fake DNS server and real DNS resolution. It also checks for DNS hijacking.

7. **Port Validation:** Tests that the `Transport` correctly rejects URLs with invalid port numbers.

8. **TLS Handshake Tracing:** Tests the `TLSHandshakeStart` and `TLSHandshakeDone` hooks in `httptrace` for HTTPS connections.

9. **Max Idle Connections:** Tests the `MaxIdleConns` setting, ensuring that the `Transport` limits the number of idle connections it keeps for different hosts.

10. **Idle Connection Timeout:** Tests the `IdleConnTimeout` setting, verifying that idle connections are closed after the specified duration.

11. **HTTP/2 Idle Connection Crash:**  A specific test to address a past crash related to HTTP/2 idle connections when a connection is established but the caller cancels the request.

12. **Error Propagation:** Tests that the `Transport` correctly returns the raw `net.Conn.Read` error from `Peek`.

13. **International Domain Names (IDNA):** Tests that the `Transport` correctly handles international domain names, including punycode conversion.

14. **Proxy CONNECT Header:** Tests the functionality of setting custom headers for the `CONNECT` method used when connecting through a proxy, using both `ProxyConnectHeader` and `GetProxyConnectHeader`.

Based on this analysis, I can now formulate the summary and examples.
这个go语言代码文件 `transport_test.go` 的一部分主要功能是测试 `net/http` 包中 `Transport` 类型的**自动HTTP/2升级机制**以及一些**连接复用和管理**相关的特性。

具体来说，这段代码测试了以下几个方面：

1. **自动HTTP/2协议协商：**  测试 `Transport` 如何根据不同的配置尝试自动升级到HTTP/2协议。

2. **连接池和连接复用：** 测试 `Transport` 如何复用已经建立的TCP连接，包括在接收到空响应体和gzip压缩响应时的情况。

3. **备用协议（Alternative Protocol）处理：** 测试当服务端协商了备用协议时，`Transport` 的处理方式。

4. **响应头长度限制：** 测试 `Transport` 如何处理超出 `MaxResponseHeaderBytes` 限制的响应头。

5. **`httptrace`事件跟踪：**  测试 `Transport` 与 `httptrace` 包的集成，验证在网络请求的不同阶段是否正确触发了相应的事件。

以下分别对这些功能进行代码举例说明：

**1. 自动HTTP/2协议协商**

`TestTransportAutomaticHTTP2_DialerAndTLSConfigSupportsHTTP2AndTLSConfig` 等一系列以 `TestTransportAutomaticHTTP2_` 开头的函数都在测试 `Transport` 的自动HTTP/2协议协商。

```go
func TestTransportAutomaticHTTP2_ForceAttemptHTTP2(t *testing.T) {
	// 假设我们创建了一个 Transport 实例，并强制尝试 HTTP/2
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
	}

	// 假设我们发起一个 HTTPS 请求
	req, _ := http.NewRequest("GET", "https://example.com", nil)

	// 假设在 RoundTrip 过程中，Transport 会尝试与服务端协商 HTTP/2
	// 如果协商成功，tr.TLSNextProto["h2"] 应该不为空

	// 这里我们模拟调用 RoundTrip，实际的 HTTP/2 协商发生在内部
	_, err := tr.RoundTrip(req)

	// 假设错误发生，我们可以检查 tr.TLSNextProto 的状态
	wantH2Registered := true // 因为 ForceAttemptHTTP2 为 true，我们期望注册了 h2
	isH2Registered := tr.TLSNextProto["h2"] != nil

	if isH2Registered != wantH2Registered {
		t.Errorf("HTTP/2 registered = %v, want %v", isH2Registered, wantH2Registered)
	}

	// 假设输出：如果协商成功，tr.TLSNextProto["h2"] 会包含一个处理 HTTP/2 连接的函数
}
```

**2. 连接池和连接复用**

`TestTransportReuseConnEmptyResponseBody` 和 `TestTransportReuseConnection_Gzip_Chunked` 等函数测试了连接复用。

```go
func TestTransportReuseConnection_EmptyBody(t *testing.T) {
	// 假设我们启动一个本地 HTTP 服务，该服务返回一个空的响应体
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Addr", r.RemoteAddr) // 设置一个 Header 用于追踪连接
		// 空响应体
	}))
	defer ts.Close()

	// 创建一个 HTTP 客户端
	client := ts.Client()

	var firstAddr string
	numRequests := 2
	for i := 0; i < numRequests; i++ {
		resp, err := client.Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		currentAddr := resp.Header.Get("X-Addr")
		if i == 0 {
			firstAddr = currentAddr
		} else if currentAddr != firstAddr {
			t.Errorf("Request %d 使用了不同的连接地址: %s, 第一次请求地址: %s", i+1, currentAddr, firstAddr)
		}
	}

	// 假设输出：如果两次请求的 X-Addr 相同，则表示连接被复用了
}
```

**3. 备用协议（Alternative Protocol）处理**

`TestNoCrashReturningTransportAltConn` 函数测试了备用协议的处理。

```go
func TestAlternativeProtocolHandling(t *testing.T) {
	// 假设我们创建了一个 Transport，并设置了 TLSNextProto 来处理 "foo" 协议
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
			"foo": func(authority string, conn *tls.Conn) http.RoundTripper {
				// 返回一个自定义的 RoundTripper，用于处理 "foo" 协议的请求
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Handled by foo protocol"))
				})
			},
		},
		DialTLS: func(network, addr string) (net.Conn, error) {
			// 模拟 TLS 连接建立并协商 "foo" 协议
			conf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"foo"}}
			conn, err := tls.Dial(network, addr, conf)
			if err != nil {
				return nil, err
			}
			// 假设协商成功
			return conn, nil
		},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://example.com") // 假设 example.com 支持 "foo" 协议
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))

	// 假设输出：如果协商成功，并且 "foo" 协议的 RoundTripper 被调用，则输出 "Handled by foo protocol"
}
```

**4. 响应头长度限制**

`TestTransportResponseHeaderLength` 函数测试了响应头长度限制。

```go
func TestResponseHeaderLimit(t *testing.T) {
	// 假设我们启动一个本地 HTTP 服务，该服务在特定路径下返回超长的响应头
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/long" {
			w.Header().Set("Long", strings.Repeat("a", 1<<20)) // 设置一个 1MB 的响应头
		}
	}))
	defer ts.Close()

	// 创建一个 HTTP 客户端，并设置最大响应头长度
	client := ts.Client()
	transport := client.Transport.(*http.Transport)
	transport.MaxResponseHeaderBytes = 512 * 1024 // 512KB

	// 发送一个请求到正常路径，应该成功
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 发送一个请求到返回超长响应头的路径，应该失败
	resp, err = client.Get(ts.URL + "/long")
	if err == nil {
		resp.Body.Close()
		t.Fatal("Expected error for long response header")
	}

	// 假设输出：错误信息应该包含 "server response headers exceeded 524288 bytes"
	if !strings.Contains(err.Error(), "server response headers exceeded 524288 bytes") {
		t.Errorf("Error message is not as expected: %v", err)
	}
}
```

**5. `httptrace`事件跟踪**

`TestTransportEventTrace` 等函数测试了 `httptrace` 的集成。

```go
func TestHTTPTraceIntegration(t *testing.T) {
	// 假设我们启动一个本地 HTTP 服务
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ...
	}))
	defer ts.Close()

	// 创建一个 HTTP 客户端
	client := ts.Client()

	// 创建一个 ClientTrace 实例，用于监听事件
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			fmt.Println("DNS Lookup started for:", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			fmt.Println("DNS Lookup finished, Addrs:", info.Addrs, "Error:", info.Err)
		},
		// ... 其他事件
	}

	// 创建一个带有 trace 上下文的请求
	req, _ := http.NewRequest("GET", ts.URL, nil)
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	req = req.WithContext(ctx)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// 假设输出：在请求过程中，会打印出 "DNS Lookup started for: ..." 和 "DNS Lookup finished, Addrs: ..." 等信息
}
```

**命令行参数处理：**

这段代码本身是测试代码，不涉及直接的命令行参数处理。它通过 Go 的 `testing` 包运行，相关的参数通常由 `go test` 命令提供，例如 `-v`（显示详细输出）、`-short`（运行时间较短的测试）等。

**使用者易犯错的点：**

这段代码是测试代码，其目的是为了发现 `net/http` 包中 `Transport` 类型的潜在错误。使用者在使用 `Transport` 时，可能会犯的错误包括：

*   **不正确地配置 `ForceAttemptHTTP2`：**  如果设置为 `true`，但服务端不支持 HTTP/2，可能会导致连接错误。
*   **错误地理解连接池的行为：**  例如，假设每次请求都会建立新的连接，而没有考虑到连接复用的情况。
*   **`TLSClientConfig` 配置不当：**  例如，缺少必要的 CA 证书或 ServerName 配置，导致 TLS 握手失败。
*   **不理解 `httptrace` 的事件触发时机：**  导致无法正确监控网络请求的状态。

**总结其功能：**

这段 `transport_test.go` 代码片段的功能是 **全面测试 `net/http.Transport` 类型在自动HTTP/2升级、连接管理、备用协议处理、响应头长度限制以及 `httptrace` 集成等方面的正确性和健壮性**。它通过模拟各种网络场景和配置，验证 `Transport` 是否按照预期工作，并帮助开发者发现潜在的bug。

### 提示词
```
这是路径为go/src/net/http/transport_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
estTransportAutomaticHTTP2_DialerAndTLSConfigSupportsHTTP2AndTLSConfig(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   new(tls.Config),
	}, true)
}

// golang.org/issue/14391: also check DefaultTransport
func TestTransportAutomaticHTTP2_DefaultTransport(t *testing.T) {
	testTransportAutoHTTP(t, DefaultTransport.(*Transport), true)
}

func TestTransportAutomaticHTTP2_TLSNextProto(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		TLSNextProto: make(map[string]func(string, *tls.Conn) RoundTripper),
	}, false)
}

func TestTransportAutomaticHTTP2_TLSConfig(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		TLSClientConfig: new(tls.Config),
	}, false)
}

func TestTransportAutomaticHTTP2_ExpectContinueTimeout(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		ExpectContinueTimeout: 1 * time.Second,
	}, true)
}

func TestTransportAutomaticHTTP2_Dial(t *testing.T) {
	var d net.Dialer
	testTransportAutoHTTP(t, &Transport{
		Dial: d.Dial,
	}, false)
}

func TestTransportAutomaticHTTP2_DialContext(t *testing.T) {
	var d net.Dialer
	testTransportAutoHTTP(t, &Transport{
		DialContext: d.DialContext,
	}, false)
}

func TestTransportAutomaticHTTP2_DialTLS(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			panic("unused")
		},
	}, false)
}

func testTransportAutoHTTP(t *testing.T, tr *Transport, wantH2 bool) {
	CondSkipHTTP2(t)
	_, err := tr.RoundTrip(new(Request))
	if err == nil {
		t.Error("expected error from RoundTrip")
	}
	if reg := tr.TLSNextProto["h2"] != nil; reg != wantH2 {
		t.Errorf("HTTP/2 registered = %v; want %v", reg, wantH2)
	}
}

// Issue 13633: there was a race where we returned bodyless responses
// to callers before recycling the persistent connection, which meant
// a client doing two subsequent requests could end up on different
// connections. It's somewhat harmless but enough tests assume it's
// not true in order to test other things that it's worth fixing.
// Plus it's nice to be consistent and not have timing-dependent
// behavior.
func TestTransportReuseConnEmptyResponseBody(t *testing.T) {
	run(t, testTransportReuseConnEmptyResponseBody)
}
func testTransportReuseConnEmptyResponseBody(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Addr", r.RemoteAddr)
		// Empty response body.
	}))
	n := 100
	if testing.Short() {
		n = 10
	}
	var firstAddr string
	for i := 0; i < n; i++ {
		res, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			log.Fatal(err)
		}
		addr := res.Header.Get("X-Addr")
		if i == 0 {
			firstAddr = addr
		} else if addr != firstAddr {
			t.Fatalf("On request %d, addr %q != original addr %q", i+1, addr, firstAddr)
		}
		res.Body.Close()
	}
}

// Issue 13839
func TestNoCrashReturningTransportAltConn(t *testing.T) {
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	ln := newLocalListener(t)
	defer ln.Close()

	var wg sync.WaitGroup
	SetPendingDialHooks(func() { wg.Add(1) }, wg.Done)
	defer SetPendingDialHooks(nil, nil)

	testDone := make(chan struct{})
	defer close(testDone)
	go func() {
		tln := tls.NewListener(ln, &tls.Config{
			NextProtos:   []string{"foo"},
			Certificates: []tls.Certificate{cert},
		})
		sc, err := tln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		if err := sc.(*tls.Conn).Handshake(); err != nil {
			t.Error(err)
			return
		}
		<-testDone
		sc.Close()
	}()

	addr := ln.Addr().String()

	req, _ := NewRequest("GET", "https://fake.tld/", nil)
	cancel := make(chan struct{})
	req.Cancel = cancel

	doReturned := make(chan bool, 1)
	madeRoundTripper := make(chan bool, 1)

	tr := &Transport{
		DisableKeepAlives: true,
		TLSNextProto: map[string]func(string, *tls.Conn) RoundTripper{
			"foo": func(authority string, c *tls.Conn) RoundTripper {
				madeRoundTripper <- true
				return funcRoundTripper(func() {
					t.Error("foo RoundTripper should not be called")
				})
			},
		},
		Dial: func(_, _ string) (net.Conn, error) {
			panic("shouldn't be called")
		},
		DialTLS: func(_, _ string) (net.Conn, error) {
			tc, err := tls.Dial("tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"foo"},
			})
			if err != nil {
				return nil, err
			}
			if err := tc.Handshake(); err != nil {
				return nil, err
			}
			close(cancel)
			<-doReturned
			return tc, nil
		},
	}
	c := &Client{Transport: tr}

	_, err = c.Do(req)
	if ue, ok := err.(*url.Error); !ok || ue.Err != ExportErrRequestCanceledConn {
		t.Fatalf("Do error = %v; want url.Error with errRequestCanceledConn", err)
	}

	doReturned <- true
	<-madeRoundTripper
	wg.Wait()
}

func TestTransportReuseConnection_Gzip_Chunked(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testTransportReuseConnection_Gzip(t, mode, true)
	})
}

func TestTransportReuseConnection_Gzip_ContentLength(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testTransportReuseConnection_Gzip(t, mode, false)
	})
}

// Make sure we re-use underlying TCP connection for gzipped responses too.
func testTransportReuseConnection_Gzip(t *testing.T, mode testMode, chunked bool) {
	addr := make(chan string, 2)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		addr <- r.RemoteAddr
		w.Header().Set("Content-Encoding", "gzip")
		if chunked {
			w.(Flusher).Flush()
		}
		w.Write(rgz) // arbitrary gzip response
	})).ts
	c := ts.Client()

	trace := &httptrace.ClientTrace{
		GetConn:      func(hostPort string) { t.Logf("GetConn(%q)", hostPort) },
		GotConn:      func(ci httptrace.GotConnInfo) { t.Logf("GotConn(%+v)", ci) },
		PutIdleConn:  func(err error) { t.Logf("PutIdleConn(%v)", err) },
		ConnectStart: func(network, addr string) { t.Logf("ConnectStart(%q, %q)", network, addr) },
		ConnectDone:  func(network, addr string, err error) { t.Logf("ConnectDone(%q, %q, %v)", network, addr, err) },
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)

	for i := 0; i < 2; i++ {
		req, _ := NewRequest("GET", ts.URL, nil)
		req = req.WithContext(ctx)
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(rgz))
		if n, err := io.ReadFull(res.Body, buf); err != nil {
			t.Errorf("%d. ReadFull = %v, %v", i, n, err)
		}
		// Note: no res.Body.Close call. It should work without it,
		// since the flate.Reader's internal buffering will hit EOF
		// and that should be sufficient.
	}
	a1, a2 := <-addr, <-addr
	if a1 != a2 {
		t.Fatalf("didn't reuse connection")
	}
}

func TestTransportResponseHeaderLength(t *testing.T) { run(t, testTransportResponseHeaderLength) }
func testTransportResponseHeaderLength(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("HTTP/2 Transport doesn't support MaxResponseHeaderBytes")
	}
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.URL.Path == "/long" {
			w.Header().Set("Long", strings.Repeat("a", 1<<20))
		}
	})).ts
	c := ts.Client()
	c.Transport.(*Transport).MaxResponseHeaderBytes = 512 << 10

	if res, err := c.Get(ts.URL); err != nil {
		t.Fatal(err)
	} else {
		res.Body.Close()
	}

	res, err := c.Get(ts.URL + "/long")
	if err == nil {
		defer res.Body.Close()
		var n int64
		for k, vv := range res.Header {
			for _, v := range vv {
				n += int64(len(k)) + int64(len(v))
			}
		}
		t.Fatalf("Unexpected success. Got %v and %d bytes of response headers", res.Status, n)
	}
	if want := "server response headers exceeded 524288 bytes"; !strings.Contains(err.Error(), want) {
		t.Errorf("got error: %v; want %q", err, want)
	}
}

func TestTransportEventTrace(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testTransportEventTrace(t, mode, false)
	}, testNotParallel)
}

// test a non-nil httptrace.ClientTrace but with all hooks set to zero.
func TestTransportEventTrace_NoHooks(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testTransportEventTrace(t, mode, true)
	}, testNotParallel)
}

func testTransportEventTrace(t *testing.T, mode testMode, noHooks bool) {
	const resBody = "some body"
	gotWroteReqEvent := make(chan struct{}, 500)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method == "GET" {
			// Do nothing for the second request.
			return
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Error(err)
		}
		if !noHooks {
			<-gotWroteReqEvent
		}
		io.WriteString(w, resBody)
	}), func(tr *Transport) {
		if tr.TLSClientConfig != nil {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}
	})
	defer cst.close()

	cst.tr.ExpectContinueTimeout = 1 * time.Second

	var mu sync.Mutex // guards buf
	var buf strings.Builder
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, format, args...)
		buf.WriteByte('\n')
	}

	addrStr := cst.ts.Listener.Addr().String()
	ip, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		t.Fatal(err)
	}

	// Install a fake DNS server.
	ctx := context.WithValue(context.Background(), nettrace.LookupIPAltResolverKey{}, func(ctx context.Context, network, host string) ([]net.IPAddr, error) {
		if host != "dns-is-faked.golang" {
			t.Errorf("unexpected DNS host lookup for %q/%q", network, host)
			return nil, nil
		}
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	})

	body := "some body"
	req, _ := NewRequest("POST", cst.scheme()+"://dns-is-faked.golang:"+port, strings.NewReader(body))
	req.Header["X-Foo-Multiple-Vals"] = []string{"bar", "baz"}
	trace := &httptrace.ClientTrace{
		GetConn:              func(hostPort string) { logf("Getting conn for %v ...", hostPort) },
		GotConn:              func(ci httptrace.GotConnInfo) { logf("got conn: %+v", ci) },
		GotFirstResponseByte: func() { logf("first response byte") },
		PutIdleConn:          func(err error) { logf("PutIdleConn = %v", err) },
		DNSStart:             func(e httptrace.DNSStartInfo) { logf("DNS start: %+v", e) },
		DNSDone:              func(e httptrace.DNSDoneInfo) { logf("DNS done: %+v", e) },
		ConnectStart:         func(network, addr string) { logf("ConnectStart: Connecting to %s %s ...", network, addr) },
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				t.Errorf("ConnectDone: %v", err)
			}
			logf("ConnectDone: connected to %s %s = %v", network, addr, err)
		},
		WroteHeaderField: func(key string, value []string) {
			logf("WroteHeaderField: %s: %v", key, value)
		},
		WroteHeaders: func() {
			logf("WroteHeaders")
		},
		Wait100Continue: func() { logf("Wait100Continue") },
		Got100Continue:  func() { logf("Got100Continue") },
		WroteRequest: func(e httptrace.WroteRequestInfo) {
			logf("WroteRequest: %+v", e)
			gotWroteReqEvent <- struct{}{}
		},
	}
	if mode == http2Mode {
		trace.TLSHandshakeStart = func() { logf("tls handshake start") }
		trace.TLSHandshakeDone = func(s tls.ConnectionState, err error) {
			logf("tls handshake done. ConnectionState = %v \n err = %v", s, err)
		}
	}
	if noHooks {
		// zero out all func pointers, trying to get some path to crash
		*trace = httptrace.ClientTrace{}
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	req.Header.Set("Expect", "100-continue")
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	logf("got roundtrip.response")
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	logf("consumed body")
	if string(slurp) != resBody || res.StatusCode != 200 {
		t.Fatalf("Got %q, %v; want %q, 200 OK", slurp, res.Status, resBody)
	}
	res.Body.Close()

	if noHooks {
		// Done at this point. Just testing a full HTTP
		// requests can happen with a trace pointing to a zero
		// ClientTrace, full of nil func pointers.
		return
	}

	mu.Lock()
	got := buf.String()
	mu.Unlock()

	wantOnce := func(sub string) {
		if strings.Count(got, sub) != 1 {
			t.Errorf("expected substring %q exactly once in output.", sub)
		}
	}
	wantOnceOrMore := func(sub string) {
		if strings.Count(got, sub) == 0 {
			t.Errorf("expected substring %q at least once in output.", sub)
		}
	}
	wantOnce("Getting conn for dns-is-faked.golang:" + port)
	wantOnce("DNS start: {Host:dns-is-faked.golang}")
	wantOnce("DNS done: {Addrs:[{IP:" + ip + " Zone:}] Err:<nil> Coalesced:false}")
	wantOnce("got conn: {")
	wantOnceOrMore("Connecting to tcp " + addrStr)
	wantOnceOrMore("connected to tcp " + addrStr + " = <nil>")
	wantOnce("Reused:false WasIdle:false IdleTime:0s")
	wantOnce("first response byte")
	if mode == http2Mode {
		wantOnce("tls handshake start")
		wantOnce("tls handshake done")
	} else {
		wantOnce("PutIdleConn = <nil>")
		wantOnce("WroteHeaderField: User-Agent: [Go-http-client/1.1]")
		// TODO(meirf): issue 19761. Make these agnostic to h1/h2. (These are not h1 specific, but the
		// WroteHeaderField hook is not yet implemented in h2.)
		wantOnce(fmt.Sprintf("WroteHeaderField: Host: [dns-is-faked.golang:%s]", port))
		wantOnce(fmt.Sprintf("WroteHeaderField: Content-Length: [%d]", len(body)))
		wantOnce("WroteHeaderField: X-Foo-Multiple-Vals: [bar baz]")
		wantOnce("WroteHeaderField: Accept-Encoding: [gzip]")
	}
	wantOnce("WroteHeaders")
	wantOnce("Wait100Continue")
	wantOnce("Got100Continue")
	wantOnce("WroteRequest: {Err:<nil>}")
	if strings.Contains(got, " to udp ") {
		t.Errorf("should not see UDP (DNS) connections")
	}
	if t.Failed() {
		t.Errorf("Output:\n%s", got)
	}

	// And do a second request:
	req, _ = NewRequest("GET", cst.scheme()+"://dns-is-faked.golang:"+port, nil)
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	res, err = cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	res.Body.Close()

	mu.Lock()
	got = buf.String()
	mu.Unlock()

	sub := "Getting conn for dns-is-faked.golang:"
	if gotn, want := strings.Count(got, sub), 2; gotn != want {
		t.Errorf("substring %q appeared %d times; want %d. Log:\n%s", sub, gotn, want, got)
	}

}

func TestTransportEventTraceTLSVerify(t *testing.T) {
	run(t, testTransportEventTraceTLSVerify, []testMode{https1Mode, http2Mode})
}
func testTransportEventTraceTLSVerify(t *testing.T, mode testMode) {
	var mu sync.Mutex
	var buf strings.Builder
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, format, args...)
		buf.WriteByte('\n')
	}

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		t.Error("Unexpected request")
	}), func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(funcWriter(func(p []byte) (int, error) {
			logf("%s", p)
			return len(p), nil
		}), "", 0)
	}).ts

	certpool := x509.NewCertPool()
	certpool.AddCert(ts.Certificate())

	c := &Client{Transport: &Transport{
		TLSClientConfig: &tls.Config{
			ServerName: "dns-is-faked.golang",
			RootCAs:    certpool,
		},
	}}

	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { logf("TLSHandshakeStart") },
		TLSHandshakeDone: func(s tls.ConnectionState, err error) {
			logf("TLSHandshakeDone: ConnectionState = %v \n err = %v", s, err)
		},
	}

	req, _ := NewRequest("GET", ts.URL, nil)
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))
	_, err := c.Do(req)
	if err == nil {
		t.Error("Expected request to fail TLS verification")
	}

	mu.Lock()
	got := buf.String()
	mu.Unlock()

	wantOnce := func(sub string) {
		if strings.Count(got, sub) != 1 {
			t.Errorf("expected substring %q exactly once in output.", sub)
		}
	}

	wantOnce("TLSHandshakeStart")
	wantOnce("TLSHandshakeDone")
	wantOnce("err = tls: failed to verify certificate: x509: certificate is valid for example.com")

	if t.Failed() {
		t.Errorf("Output:\n%s", got)
	}
}

var isDNSHijacked = sync.OnceValue(func() bool {
	addrs, _ := net.LookupHost("dns-should-not-resolve.golang")
	return len(addrs) != 0
})

func skipIfDNSHijacked(t *testing.T) {
	// Skip this test if the user is using a shady/ISP
	// DNS server hijacking queries.
	// See issues 16732, 16716.
	if isDNSHijacked() {
		t.Skip("skipping; test requires non-hijacking DNS server")
	}
}

func TestTransportEventTraceRealDNS(t *testing.T) {
	skipIfDNSHijacked(t)
	defer afterTest(t)
	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := &Client{Transport: tr}

	var mu sync.Mutex // guards buf
	var buf strings.Builder
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, format, args...)
		buf.WriteByte('\n')
	}

	req, _ := NewRequest("GET", "http://dns-should-not-resolve.golang:80", nil)
	trace := &httptrace.ClientTrace{
		DNSStart:     func(e httptrace.DNSStartInfo) { logf("DNSStart: %+v", e) },
		DNSDone:      func(e httptrace.DNSDoneInfo) { logf("DNSDone: %+v", e) },
		ConnectStart: func(network, addr string) { logf("ConnectStart: %s %s", network, addr) },
		ConnectDone:  func(network, addr string, err error) { logf("ConnectDone: %s %s %v", network, addr, err) },
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error during DNS lookup")
	}

	mu.Lock()
	got := buf.String()
	mu.Unlock()

	wantSub := func(sub string) {
		if !strings.Contains(got, sub) {
			t.Errorf("expected substring %q in output.", sub)
		}
	}
	wantSub("DNSStart: {Host:dns-should-not-resolve.golang}")
	wantSub("DNSDone: {Addrs:[] Err:")
	if strings.Contains(got, "ConnectStart") || strings.Contains(got, "ConnectDone") {
		t.Errorf("should not see Connect events")
	}
	if t.Failed() {
		t.Errorf("Output:\n%s", got)
	}
}

// Issue 14353: port can only contain digits.
func TestTransportRejectsAlphaPort(t *testing.T) {
	res, err := Get("http://dummy.tld:123foo/bar")
	if err == nil {
		res.Body.Close()
		t.Fatal("unexpected success")
	}
	ue, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("got %#v; want *url.Error", err)
	}
	got := ue.Err.Error()
	want := `invalid port ":123foo" after host`
	if got != want {
		t.Errorf("got error %q; want %q", got, want)
	}
}

// Test the httptrace.TLSHandshake{Start,Done} hooks with an https http1
// connections. The http2 test is done in TestTransportEventTrace_h2
func TestTLSHandshakeTrace(t *testing.T) {
	run(t, testTLSHandshakeTrace, []testMode{https1Mode, http2Mode})
}
func testTLSHandshakeTrace(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {})).ts

	var mu sync.Mutex
	var start, done bool
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			mu.Lock()
			defer mu.Unlock()
			start = true
		},
		TLSHandshakeDone: func(s tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			done = true
			if err != nil {
				t.Fatal("Expected error to be nil but was:", err)
			}
		},
	}

	c := ts.Client()
	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal("Unable to construct test request:", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	r, err := c.Do(req)
	if err != nil {
		t.Fatal("Unexpected error making request:", err)
	}
	r.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if !start {
		t.Fatal("Expected TLSHandshakeStart to be called, but wasn't")
	}
	if !done {
		t.Fatal("Expected TLSHandshakeDone to be called, but wasn't")
	}
}

func TestTransportMaxIdleConns(t *testing.T) {
	run(t, testTransportMaxIdleConns, []testMode{http1Mode})
}
func testTransportMaxIdleConns(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// No body for convenience.
	})).ts
	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.MaxIdleConns = 4

	ip, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), nettrace.LookupIPAltResolverKey{}, func(ctx context.Context, _, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	})

	hitHost := func(n int) {
		req, _ := NewRequest("GET", fmt.Sprintf("http://host-%d.dns-is-faked.golang:"+port, n), nil)
		req = req.WithContext(ctx)
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	for i := 0; i < 4; i++ {
		hitHost(i)
	}
	want := []string{
		"|http|host-0.dns-is-faked.golang:" + port,
		"|http|host-1.dns-is-faked.golang:" + port,
		"|http|host-2.dns-is-faked.golang:" + port,
		"|http|host-3.dns-is-faked.golang:" + port,
	}
	if got := tr.IdleConnKeysForTesting(); !slices.Equal(got, want) {
		t.Fatalf("idle conn keys mismatch.\n got: %q\nwant: %q\n", got, want)
	}

	// Now hitting the 5th host should kick out the first host:
	hitHost(4)
	want = []string{
		"|http|host-1.dns-is-faked.golang:" + port,
		"|http|host-2.dns-is-faked.golang:" + port,
		"|http|host-3.dns-is-faked.golang:" + port,
		"|http|host-4.dns-is-faked.golang:" + port,
	}
	if got := tr.IdleConnKeysForTesting(); !slices.Equal(got, want) {
		t.Fatalf("idle conn keys mismatch after 5th host.\n got: %q\nwant: %q\n", got, want)
	}
}

func TestTransportIdleConnTimeout(t *testing.T) { run(t, testTransportIdleConnTimeout) }
func testTransportIdleConnTimeout(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	timeout := 1 * time.Millisecond
timeoutLoop:
	for {
		cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			// No body for convenience.
		}))
		tr := cst.tr
		tr.IdleConnTimeout = timeout
		defer tr.CloseIdleConnections()
		c := &Client{Transport: tr}

		idleConns := func() []string {
			if mode == http2Mode {
				return tr.IdleConnStrsForTesting_h2()
			} else {
				return tr.IdleConnStrsForTesting()
			}
		}

		var conn string
		doReq := func(n int) (timeoutOk bool) {
			req, _ := NewRequest("GET", cst.ts.URL, nil)
			req = req.WithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
				PutIdleConn: func(err error) {
					if err != nil {
						t.Errorf("failed to keep idle conn: %v", err)
					}
				},
			}))
			res, err := c.Do(req)
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					t.Logf("req %v: connection closed prematurely", n)
					return false
				}
			}
			if err == nil {
				res.Body.Close()
			}
			conns := idleConns()
			if len(conns) != 1 {
				if len(conns) == 0 {
					t.Logf("req %v: no idle conns", n)
					return false
				}
				t.Fatalf("req %v: unexpected number of idle conns: %q", n, conns)
			}
			if conn == "" {
				conn = conns[0]
			}
			if conn != conns[0] {
				t.Logf("req %v: cached connection changed; expected the same one throughout the test", n)
				return false
			}
			return true
		}
		for i := 0; i < 3; i++ {
			if !doReq(i) {
				t.Logf("idle conn timeout %v appears to be too short; retrying with longer", timeout)
				timeout *= 2
				cst.close()
				continue timeoutLoop
			}
			time.Sleep(timeout / 2)
		}

		waitCondition(t, timeout/2, func(d time.Duration) bool {
			if got := idleConns(); len(got) != 0 {
				if d >= timeout*3/2 {
					t.Logf("after %v, idle conns = %q", d, got)
				}
				return false
			}
			return true
		})
		break
	}
}

// Issue 16208: Go 1.7 crashed after Transport.IdleConnTimeout if an
// HTTP/2 connection was established but its caller no longer
// wanted it. (Assuming the connection cache was enabled, which it is
// by default)
//
// This test reproduced the crash by setting the IdleConnTimeout low
// (to make the test reasonable) and then making a request which is
// canceled by the DialTLS hook, which then also waits to return the
// real connection until after the RoundTrip saw the error.  Then we
// know the successful tls.Dial from DialTLS will need to go into the
// idle pool. Then we give it a of time to explode.
func TestIdleConnH2Crash(t *testing.T) { run(t, testIdleConnH2Crash, []testMode{http2Mode}) }
func testIdleConnH2Crash(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// nothing
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sawDoErr := make(chan bool, 1)
	testDone := make(chan struct{})
	defer close(testDone)

	cst.tr.IdleConnTimeout = 5 * time.Millisecond
	cst.tr.DialTLS = func(network, addr string) (net.Conn, error) {
		c, err := tls.Dial(network, addr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		if err != nil {
			t.Error(err)
			return nil, err
		}
		if cs := c.ConnectionState(); cs.NegotiatedProtocol != "h2" {
			t.Errorf("protocol = %q; want %q", cs.NegotiatedProtocol, "h2")
			c.Close()
			return nil, errors.New("bogus")
		}

		cancel()

		select {
		case <-sawDoErr:
		case <-testDone:
		}
		return c, nil
	}

	req, _ := NewRequest("GET", cst.ts.URL, nil)
	req = req.WithContext(ctx)
	res, err := cst.c.Do(req)
	if err == nil {
		res.Body.Close()
		t.Fatal("unexpected success")
	}
	sawDoErr <- true

	// Wait for the explosion.
	time.Sleep(cst.tr.IdleConnTimeout * 10)
}

type funcConn struct {
	net.Conn
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
}

func (c funcConn) Read(p []byte) (int, error)  { return c.read(p) }
func (c funcConn) Write(p []byte) (int, error) { return c.write(p) }
func (c funcConn) Close() error                { return nil }

// Issue 16465: Transport.RoundTrip should return the raw net.Conn.Read error from Peek
// back to the caller.
func TestTransportReturnsPeekError(t *testing.T) {
	errValue := errors.New("specific error value")

	wrote := make(chan struct{})
	wroteOnce := sync.OnceFunc(func() { close(wrote) })

	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			c := funcConn{
				read: func([]byte) (int, error) {
					<-wrote
					return 0, errValue
				},
				write: func(p []byte) (int, error) {
					wroteOnce()
					return len(p), nil
				},
			}
			return c, nil
		},
	}
	_, err := tr.RoundTrip(httptest.NewRequest("GET", "http://fake.tld/", nil))
	if err != errValue {
		t.Errorf("error = %#v; want %v", err, errValue)
	}
}

// Issue 13835: international domain names should work
func TestTransportIDNA(t *testing.T) { run(t, testTransportIDNA) }
func testTransportIDNA(t *testing.T, mode testMode) {
	const uniDomain = "гофер.го"
	const punyDomain = "xn--c1ae0ajs.xn--c1aw"

	var port string
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		want := punyDomain + ":" + port
		if r.Host != want {
			t.Errorf("Host header = %q; want %q", r.Host, want)
		}
		if mode == http2Mode {
			if r.TLS == nil {
				t.Errorf("r.TLS == nil")
			} else if r.TLS.ServerName != punyDomain {
				t.Errorf("TLS.ServerName = %q; want %q", r.TLS.ServerName, punyDomain)
			}
		}
		w.Header().Set("Hit-Handler", "1")
	}), func(tr *Transport) {
		if tr.TLSClientConfig != nil {
			tr.TLSClientConfig.InsecureSkipVerify = true
		}
	})

	ip, port, err := net.SplitHostPort(cst.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Install a fake DNS server.
	ctx := context.WithValue(context.Background(), nettrace.LookupIPAltResolverKey{}, func(ctx context.Context, network, host string) ([]net.IPAddr, error) {
		if host != punyDomain {
			t.Errorf("got DNS host lookup for %q/%q; want %q", network, host, punyDomain)
			return nil, nil
		}
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	})

	req, _ := NewRequest("GET", cst.scheme()+"://"+uniDomain+":"+port, nil)
	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			want := net.JoinHostPort(punyDomain, port)
			if hostPort != want {
				t.Errorf("getting conn for %q; want %q", hostPort, want)
			}
		},
		DNSStart: func(e httptrace.DNSStartInfo) {
			if e.Host != punyDomain {
				t.Errorf("DNSStart Host = %q; want %q", e.Host, punyDomain)
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	res, err := cst.tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Hit-Handler") != "1" {
		out, err := httputil.DumpResponse(res, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Errorf("Response body wasn't from Handler. Got:\n%s\n", out)
	}
}

// Issue 13290: send User-Agent in proxy CONNECT
func TestTransportProxyConnectHeader(t *testing.T) {
	run(t, testTransportProxyConnectHeader, []testMode{http1Mode})
}
func testTransportProxyConnectHeader(t *testing.T, mode testMode) {
	reqc := make(chan *Request, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "CONNECT" {
			t.Errorf("method = %q; want CONNECT", r.Method)
		}
		reqc <- r
		c, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		c.Close()
	})).ts

	c := ts.Client()
	c.Transport.(*Transport).Proxy = func(r *Request) (*url.URL, error) {
		return url.Parse(ts.URL)
	}
	c.Transport.(*Transport).ProxyConnectHeader = Header{
		"User-Agent": {"foo"},
		"Other":      {"bar"},
	}

	res, err := c.Get("https://dummy.tld/") // https to force a CONNECT
	if err == nil {
		res.Body.Close()
		t.Errorf("unexpected success")
	}

	r := <-reqc
	if got, want := r.Header.Get("User-Agent"), "foo"; got != want {
		t.Errorf("CONNECT request User-Agent = %q; want %q", got, want)
	}
	if got, want := r.Header.Get("Other"), "bar"; got != want {
		t.Errorf("CONNECT request Other = %q; want %q", got, want)
	}
}

func TestTransportProxyGetConnectHeader(t *testing.T) {
	run(t, testTransportProxyGetConnectHeader, []testMode{http1Mode})
}
func testTransportProxyGetConnectHeader(t *testing.T, mode testMode) {
	reqc := make(chan *Request, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "CONNECT" {
			t.Errorf("method = %q; want CONNECT", r.Method)
		}
		reqc <- r
		c, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		c.Close()
	})).ts

	c := ts.Client()
	c.Transport.(*Transport).Proxy = func(r *Request) (*url.URL, error) {
		return url.Parse(ts.URL)
	}
	// These should be ignored:
	c.Transport.(*Transport).ProxyConnectHeader = Header{
		"User-Agent": {"foo"},
		"Other":      {"bar"},
	}
	c.Transport.(*Transport).GetProxyConnectHeader = func(ctx context.Context, proxyURL *url.URL, target string) (Header, error) {
		return Header{
			"User-Agent": {"foo2"},
			"Other":      {"bar2"},
		}, nil
	}

	res, err := c.Get("https://dummy.tld/") // https to force a CONNECT
	if err == nil {
		res.Body.Close()
		t.Errorf("unexpected success")
	}

	r := <-reqc
	if got, want := r.Header.Get("User-Agent"), "foo2"; got != want {
		t.Errorf("CONNECT request User-Agent = %q; want %q", got, want)
	}
	if got, want := r.Header.Get("Other"), "bar2"; got != want {
		t.Errorf("CONNECT request Other = %q; want %q", got, want)
	}
}

var errFakeRoundTrip = errors.New("fake roundtrip")

type funcRoundTripper func()

func (fn funcRoundTripper) RoundTrip(*Request) (*Response, error) {
	fn()
	return nil, errFakeRoundTrip
}

func wantBody(res *Response, err error, want string) error {
	if err != nil {
		return err
	}
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %v", err)
	}
	if string(slurp) != want {
		return fmt.Errorf("body = %q; want %q", slurp, want)
	}
	if err := res.Body.Close(); err != nil {
		return fmt.Errorf("body Close = %v", err)
	}
	return nil
}

func newLocalListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

type countCloseReader struct {
	n *int
	io.Reader
}

func (cr countCloseReader) Close() error {
	(*cr.n)++
	return nil
}

// rgz is a gzip quine that uncompresses to itself.
var rgz = []byte{
	0x1f, 0x8b, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73,
	0x69, 0x76, 0x65, 0x00, 0x92, 0xef, 0xe6, 0xe0,
	0x60, 0x00, 0x83, 0xa2, 0xd4, 0xe4, 0xd2, 0xa2,
	0xe2, 0xcc, 0xb2, 0x54, 0x06, 0x00, 0x00, 0x17,
	0x00, 0xe8, 0xff, 0x92, 0xef, 0xe6, 0xe0, 0x60,
	0x00, 0x83, 0xa2, 0xd4, 0xe4, 0xd2, 0xa2, 0xe2,
	0xcc, 0xb2, 0x54, 0x06, 0x00, 0x00, 0x17, 0x00,
	0xe8, 0xff, 0x42, 0x12, 0x46, 0x16, 0x06, 0x00,
	0x05, 0x00, 0xfa, 0xff, 0x42, 0x12, 0x46, 0x16,
	0x06, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x00, 0x05,
	0x00, 0xfa, 0xff, 0x00, 0x14, 0x00, 0xeb, 0xff,
	0x42, 0x12, 0x46, 0x16, 0x06, 0x00, 0x05, 0x00,
	0xfa, 0xff, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x00,
	0x14, 0x00, 0xeb, 0xff, 0x42, 0x88, 0x21, 0xc4,
	0x00, 0x00, 0x14, 0x00, 0xeb, 0xff, 0x42, 0x88,
	0x21, 0xc4, 0x00, 0x00, 0x14, 0x00, 0xeb, 0xff,
	0x42, 0x88, 0x21, 0xc4, 0x00, 0x00, 0x14, 0x00,
	0xeb, 0xff, 0x42, 0x88, 0x21, 0xc4, 0x00, 0x00,
	0x14, 0x00, 0xeb, 0xff, 0x42, 0x88, 0x21, 0xc4,
	0x00, 0x
```