Response:
Let's break down the thought process for summarizing the provided Go code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the code looking for recognizable patterns and keywords related to HTTP and testing. Immediately, terms like `Transport`, `Head`, `Expect: 100-continue`, `Proxy`, `SOCKS5`, `CONNECT`, `gzip`, `goroutine`, `timeout`, and `net.Conn` stand out. These keywords give a high-level understanding of the code's purpose. The file path `go/src/net/http/transport_test.go` confirms this is part of the HTTP transport testing framework.

**2. Identifying Test Structures:**

The code defines several test functions (starting with `Test...`) and helper structures (like `transport100ContinueTest`). This indicates a focus on unit testing specific aspects of the `Transport` type.

**3. Grouping Functionality by Test Cases:**

The next step is to group the test functions and associated helper functions based on the specific feature they are testing. This involves looking for common prefixes or related concepts within the test function names and the setup code.

*   **`TestTransportExpect100Continue...`:**  Clearly related to the "Expect: 100-continue" header. The `transport100ContinueTest` struct and its methods (`newTransport100ContinueTest`, `respond`, `wantBodySent`, `wantRequestDone`) are key components of this test group.

*   **`TestSOCKS5Proxy` and `testSOCKS5Proxy`:**  Directly testing SOCKS5 proxy functionality.

*   **`TestTransportProxy`:**  General HTTP proxy testing, including CONNECT method handling for HTTPS proxies.

*   **`TestOnProxyConnectResponse`:**  Specifically testing the `OnProxyConnectResponse` hook.

*   **`TestTransportProxyHTTPSConnectLeak`:**  Testing for connection leaks in HTTPS proxy scenarios.

*   **`TestTransportDialPreservesNetOpProxyError`:** Testing error handling during proxy connection.

*   **`TestTransportProxyDialDoesNotMutateProxyConnectHeader`:**  Testing for unintended side effects when using proxy headers.

*   **`TestTransportGzip...`:** Testing gzip compression handling, including recursive and short gzip bodies.

*   **`TestTransportPersistConnLeak...`:**  A series of tests focused on preventing connection and goroutine leaks related to persistent connections under various conditions (normal usage, short bodies, never-idle connections, max connections per host).

*   **`TestTransportIdleConnCrash`:** A specific test for a potential crash scenario.

*   **`TestIssue3644`:**  Testing for proper handling of response bodies and preventing early connection closure.

*   **`TestIssue3595`:** Testing the interaction between request bodies and server responses, particularly concerning RST packets.

*   **`TestChunkedNoContent`:** Testing handling of chunked responses with no content.

*   **`TestTransportConcurrency`:**  Testing the transport's behavior under concurrent requests.

*   **`TestIssue4191_InfiniteGetTimeout`:** Testing scenarios with potentially long-running or timed-out requests.

**4. Synthesizing High-Level Summaries for Each Group:**

For each identified group, formulate a concise summary of its purpose. Focus on the core feature being tested and any specific edge cases or potential issues being addressed.

*   Example: For `TestTransportExpect100Continue...`, the summary would be about testing the client-side behavior when sending "Expect: 100-continue" requests and how the transport reacts to different server responses (100 Continue, 200 OK, timeouts).

**5. Overall Function Summary:**

Finally, combine the individual group summaries into a broader overview of the code's functionality. Emphasize that this section of the file is dedicated to testing various aspects of the `http.Transport`.

**Self-Correction/Refinement During the Process:**

*   Initially, I might have just listed individual test function names. However, grouping them by feature provides a more organized and understandable summary.
*   Recognizing the pattern of `Test...` functions calling underlying `test...` functions (like `TestSOCKS5Proxy` calling `testSOCKS5Proxy`) helps understand the overall test structure.
*   Noting the use of helper functions and structs like `newClientServerTest` and `transport100ContinueTest` indicates a modular testing approach.

By following these steps, we can systematically analyze the code and produce a comprehensive and well-structured summary of its functionality, as demonstrated in the provided good answer.
这是 `go/src/net/http/transport_test.go` 文件的第二部分，主要集中在测试 `http.Transport` 类型在处理特定 HTTP 功能和场景时的行为，特别是与连接管理、代理和一些边缘情况相关的测试。

以下是本部分代码的功能归纳：

1. **测试 `HEAD` 请求:** 验证 `Transport` 可以正确发送和处理 `HEAD` 请求，并能获取到正确的状态码。

2. **测试 `Expect: 100-continue` 功能:**  这部分定义了一个 `transport100ContinueTest` 结构体和相关方法，用于详细测试客户端发送带有 `Expect: 100-continue` 头的请求时 `Transport` 的行为。涵盖了以下几种情况：
    *   服务器响应 `100 Continue` 后，客户端发送请求体。
    *   服务器直接响应 `200 OK`，没有 `100 Continue`，包括有和没有 `Connection: close` 头的情况。
    *   服务器响应 `500` 错误，没有 `100 Continue`，包括有和没有 `Connection: close` 头的情况。
    *   在 `ExpectContinueTimeout` 超时后，客户端发送请求体。

3. **测试 SOCKS5 代理:**  这部分测试 `Transport` 如何通过 SOCKS5 代理进行连接。它创建了一个本地监听器来模拟 SOCKS5 代理服务器，并验证客户端是否能正确地与目标服务器建立连接并通过代理发送请求。涵盖了 HTTP 和 HTTPS 两种情况。

4. **测试 HTTP(S) 代理:**  这部分测试 `Transport` 作为 HTTP 或 HTTPS 客户端通过 HTTP 或 HTTPS 代理服务器进行连接的情况。它覆盖了多种组合，包括：
    *   HTTP 站点通过 HTTP 代理
    *   HTTP 站点通过 HTTPS 代理
    *   HTTPS 站点通过 HTTP 代理 (需要 CONNECT 方法)
    *   HTTPS 站点通过 HTTPS 代理 (需要 CONNECT 方法)
    *   验证了通过代理发送请求时的方法 (例如 `CONNECT` 用于 HTTPS 代理) 和 URL。

5. **测试 `OnProxyConnectResponse` 回调:**  这部分测试 `Transport` 的 `OnProxyConnectResponse` 钩子函数，允许用户自定义处理代理服务器对 `CONNECT` 请求的响应。它验证了回调函数的参数，以及当回调函数返回错误时 `Transport` 的行为（例如关闭连接）。

6. **测试 HTTPS 代理连接泄漏问题:** 专门测试当 HTTPS 代理服务器对 `CONNECT` 请求响应缓慢时，`Transport` 是否会泄漏 TCP 连接。

7. **测试代理连接错误处理:**  验证当 `Dial` 函数返回错误时，`Transport` 是否能正确地将错误包装成 `url.Error` 和 `net.OpError` 并传递给上层。

8. **测试代理连接头部不被修改:** 验证 `Transport` 在处理代理连接时不会意外地修改共享的 `ProxyConnectHeader` 实例，防止数据竞争。

9. **测试 Gzip 压缩处理 (递归和短响应):**
    *   **递归 Gzip:** 测试当服务器返回一个自身 Gzip 压缩版本时，客户端是否能正确解压，防止无限递归。同时也验证了 `Content-Encoding` 头部被移除。
    *   **短 Gzip 响应:** 测试客户端如何处理服务器返回的不完整的 Gzip 压缩数据。

10. **测试持久连接泄漏:**  一系列测试用于检查在各种情况下（正常请求、请求体长度不匹配、连接不保持空闲等），`Transport` 是否会泄漏 Goroutine 和 TCP 连接。

11. **测试空闲连接导致的崩溃问题:**  重现并修复了一个由于在请求处理过程中关闭空闲连接可能导致的崩溃问题。

12. **测试确保在读取完响应体之前不关闭连接:** 验证即使服务器设置了 `Connection: close`，客户端也会在读取完整个响应体后再关闭连接。

13. **测试服务器不读取完整请求体时的客户端行为:**  验证即使服务器没有读取完客户端发送的请求体就返回了响应，客户端也能正确接收响应。

14. **测试无内容主体的分块编码响应:** 验证客户端可以正确处理状态码为 `204 No Content` 的分块编码响应。

15. **测试 `Transport` 的并发安全性:**  通过并发发送大量请求来测试 `Transport` 在高并发环境下的稳定性和正确性。

16. **测试无限 `Get` 请求超时问题:**  测试当使用无限超时时间的 `Get` 请求时，连接处理是否正确。

总而言之，这部分代码主要关注 `http.Transport` 在各种复杂的 HTTP 场景下的健壮性和正确性，特别是围绕连接管理、代理功能和一些可能导致资源泄漏或错误的边缘情况进行细致的测试。

### 提示词
```
这是路径为go/src/net/http/transport_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
lways weird.
	res, err := c.Head(ts.URL)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("Head status=%d; want=200", res.StatusCode)
	}
}

// A transport100Continue test exercises Transport behaviors when sending a
// request with an Expect: 100-continue header.
type transport100ContinueTest struct {
	t *testing.T

	reqdone chan struct{}
	resp    *Response
	respErr error

	conn   net.Conn
	reader *bufio.Reader
}

const transport100ContinueTestBody = "request body"

// newTransport100ContinueTest creates a Transport and sends an Expect: 100-continue
// request on it.
func newTransport100ContinueTest(t *testing.T, timeout time.Duration) *transport100ContinueTest {
	ln := newLocalListener(t)
	defer ln.Close()

	test := &transport100ContinueTest{
		t:       t,
		reqdone: make(chan struct{}),
	}

	tr := &Transport{
		ExpectContinueTimeout: timeout,
	}
	go func() {
		defer close(test.reqdone)
		body := strings.NewReader(transport100ContinueTestBody)
		req, _ := NewRequest("PUT", "http://"+ln.Addr().String(), body)
		req.Header.Set("Expect", "100-continue")
		req.ContentLength = int64(len(transport100ContinueTestBody))
		test.resp, test.respErr = tr.RoundTrip(req)
		test.resp.Body.Close()
	}()

	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() {
		c.Close()
	})
	br := bufio.NewReader(c)
	_, err = ReadRequest(br)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	test.conn = c
	test.reader = br
	t.Cleanup(func() {
		<-test.reqdone
		tr.CloseIdleConnections()
		got, _ := io.ReadAll(test.reader)
		if len(got) > 0 {
			t.Fatalf("Transport sent unexpected bytes: %q", got)
		}
	})

	return test
}

// respond sends response lines from the server to the transport.
func (test *transport100ContinueTest) respond(lines ...string) {
	for _, line := range lines {
		if _, err := test.conn.Write([]byte(line + "\r\n")); err != nil {
			test.t.Fatalf("Write: %v", err)
		}
	}
	if _, err := test.conn.Write([]byte("\r\n")); err != nil {
		test.t.Fatalf("Write: %v", err)
	}
}

// wantBodySent ensures the transport has sent the request body to the server.
func (test *transport100ContinueTest) wantBodySent() {
	got, err := io.ReadAll(io.LimitReader(test.reader, int64(len(transport100ContinueTestBody))))
	if err != nil {
		test.t.Fatalf("unexpected error reading body: %v", err)
	}
	if got, want := string(got), transport100ContinueTestBody; got != want {
		test.t.Fatalf("unexpected body: got %q, want %q", got, want)
	}
}

// wantRequestDone ensures the Transport.RoundTrip has completed with the expected status.
func (test *transport100ContinueTest) wantRequestDone(want int) {
	<-test.reqdone
	if test.respErr != nil {
		test.t.Fatalf("unexpected RoundTrip error: %v", test.respErr)
	}
	if got := test.resp.StatusCode; got != want {
		test.t.Fatalf("unexpected response code: got %v, want %v", got, want)
	}
}

func TestTransportExpect100ContinueSent(t *testing.T) {
	test := newTransport100ContinueTest(t, 1*time.Hour)
	// Server sends a 100 Continue response, and the client sends the request body.
	test.respond("HTTP/1.1 100 Continue")
	test.wantBodySent()
	test.respond("HTTP/1.1 200", "Content-Length: 0")
	test.wantRequestDone(200)
}

func TestTransportExpect100Continue200ResponseNoConnClose(t *testing.T) {
	test := newTransport100ContinueTest(t, 1*time.Hour)
	// No 100 Continue response, no Connection: close header.
	test.respond("HTTP/1.1 200", "Content-Length: 0")
	test.wantBodySent()
	test.wantRequestDone(200)
}

func TestTransportExpect100Continue200ResponseWithConnClose(t *testing.T) {
	test := newTransport100ContinueTest(t, 1*time.Hour)
	// No 100 Continue response, Connection: close header set.
	test.respond("HTTP/1.1 200", "Connection: close", "Content-Length: 0")
	test.wantRequestDone(200)
}

func TestTransportExpect100Continue500ResponseNoConnClose(t *testing.T) {
	test := newTransport100ContinueTest(t, 1*time.Hour)
	// No 100 Continue response, no Connection: close header.
	test.respond("HTTP/1.1 500", "Content-Length: 0")
	test.wantBodySent()
	test.wantRequestDone(500)
}

func TestTransportExpect100Continue500ResponseTimeout(t *testing.T) {
	test := newTransport100ContinueTest(t, 5*time.Millisecond) // short timeout
	test.wantBodySent()                                        // after timeout
	test.respond("HTTP/1.1 200", "Content-Length: 0")
	test.wantRequestDone(200)
}

func TestSOCKS5Proxy(t *testing.T) {
	run(t, testSOCKS5Proxy, []testMode{http1Mode, https1Mode, http2Mode})
}
func testSOCKS5Proxy(t *testing.T, mode testMode) {
	ch := make(chan string, 1)
	l := newLocalListener(t)
	defer l.Close()
	defer close(ch)
	proxy := func(t *testing.T) {
		s, err := l.Accept()
		if err != nil {
			t.Errorf("socks5 proxy Accept(): %v", err)
			return
		}
		defer s.Close()
		var buf [22]byte
		if _, err := io.ReadFull(s, buf[:3]); err != nil {
			t.Errorf("socks5 proxy initial read: %v", err)
			return
		}
		if want := []byte{5, 1, 0}; !bytes.Equal(buf[:3], want) {
			t.Errorf("socks5 proxy initial read: got %v, want %v", buf[:3], want)
			return
		}
		if _, err := s.Write([]byte{5, 0}); err != nil {
			t.Errorf("socks5 proxy initial write: %v", err)
			return
		}
		if _, err := io.ReadFull(s, buf[:4]); err != nil {
			t.Errorf("socks5 proxy second read: %v", err)
			return
		}
		if want := []byte{5, 1, 0}; !bytes.Equal(buf[:3], want) {
			t.Errorf("socks5 proxy second read: got %v, want %v", buf[:3], want)
			return
		}
		var ipLen int
		switch buf[3] {
		case 1:
			ipLen = net.IPv4len
		case 4:
			ipLen = net.IPv6len
		default:
			t.Errorf("socks5 proxy second read: unexpected address type %v", buf[4])
			return
		}
		if _, err := io.ReadFull(s, buf[4:ipLen+6]); err != nil {
			t.Errorf("socks5 proxy address read: %v", err)
			return
		}
		ip := net.IP(buf[4 : ipLen+4])
		port := binary.BigEndian.Uint16(buf[ipLen+4 : ipLen+6])
		copy(buf[:3], []byte{5, 0, 0})
		if _, err := s.Write(buf[:ipLen+6]); err != nil {
			t.Errorf("socks5 proxy connect write: %v", err)
			return
		}
		ch <- fmt.Sprintf("proxy for %s:%d", ip, port)

		// Implement proxying.
		targetHost := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
		targetConn, err := net.Dial("tcp", targetHost)
		if err != nil {
			t.Errorf("net.Dial failed")
			return
		}
		go io.Copy(targetConn, s)
		io.Copy(s, targetConn) // Wait for the client to close the socket.
		targetConn.Close()
	}

	pu, err := url.Parse("socks5://" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	sentinelHeader := "X-Sentinel"
	sentinelValue := "12345"
	h := HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set(sentinelHeader, sentinelValue)
	})
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("useTLS=%v", useTLS), func(t *testing.T) {
			ts := newClientServerTest(t, mode, h).ts
			go proxy(t)
			c := ts.Client()
			c.Transport.(*Transport).Proxy = ProxyURL(pu)
			r, err := c.Head(ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			if r.Header.Get(sentinelHeader) != sentinelValue {
				t.Errorf("Failed to retrieve sentinel value")
			}
			got := <-ch
			ts.Close()
			tsu, err := url.Parse(ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			want := "proxy for " + tsu.Host
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestTransportProxy(t *testing.T) {
	defer afterTest(t)
	testCases := []struct{ siteMode, proxyMode testMode }{
		{http1Mode, http1Mode},
		{http1Mode, https1Mode},
		{https1Mode, http1Mode},
		{https1Mode, https1Mode},
	}
	for _, testCase := range testCases {
		siteMode := testCase.siteMode
		proxyMode := testCase.proxyMode
		t.Run(fmt.Sprintf("site=%v/proxy=%v", siteMode, proxyMode), func(t *testing.T) {
			siteCh := make(chan *Request, 1)
			h1 := HandlerFunc(func(w ResponseWriter, r *Request) {
				siteCh <- r
			})
			proxyCh := make(chan *Request, 1)
			h2 := HandlerFunc(func(w ResponseWriter, r *Request) {
				proxyCh <- r
				// Implement an entire CONNECT proxy
				if r.Method == "CONNECT" {
					hijacker, ok := w.(Hijacker)
					if !ok {
						t.Errorf("hijack not allowed")
						return
					}
					clientConn, _, err := hijacker.Hijack()
					if err != nil {
						t.Errorf("hijacking failed")
						return
					}
					res := &Response{
						StatusCode: StatusOK,
						Proto:      "HTTP/1.1",
						ProtoMajor: 1,
						ProtoMinor: 1,
						Header:     make(Header),
					}

					targetConn, err := net.Dial("tcp", r.URL.Host)
					if err != nil {
						t.Errorf("net.Dial(%q) failed: %v", r.URL.Host, err)
						return
					}

					if err := res.Write(clientConn); err != nil {
						t.Errorf("Writing 200 OK failed: %v", err)
						return
					}

					go io.Copy(targetConn, clientConn)
					go func() {
						io.Copy(clientConn, targetConn)
						targetConn.Close()
					}()
				}
			})
			ts := newClientServerTest(t, siteMode, h1).ts
			proxy := newClientServerTest(t, proxyMode, h2).ts

			pu, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}

			// If neither server is HTTPS or both are, then c may be derived from either.
			// If only one server is HTTPS, c must be derived from that server in order
			// to ensure that it is configured to use the fake root CA from testcert.go.
			c := proxy.Client()
			if siteMode == https1Mode {
				c = ts.Client()
			}

			c.Transport.(*Transport).Proxy = ProxyURL(pu)
			if _, err := c.Head(ts.URL); err != nil {
				t.Error(err)
			}
			got := <-proxyCh
			c.Transport.(*Transport).CloseIdleConnections()
			ts.Close()
			proxy.Close()
			if siteMode == https1Mode {
				// First message should be a CONNECT, asking for a socket to the real server,
				if got.Method != "CONNECT" {
					t.Errorf("Wrong method for secure proxying: %q", got.Method)
				}
				gotHost := got.URL.Host
				pu, err := url.Parse(ts.URL)
				if err != nil {
					t.Fatal("Invalid site URL")
				}
				if wantHost := pu.Host; gotHost != wantHost {
					t.Errorf("Got CONNECT host %q, want %q", gotHost, wantHost)
				}

				// The next message on the channel should be from the site's server.
				next := <-siteCh
				if next.Method != "HEAD" {
					t.Errorf("Wrong method at destination: %s", next.Method)
				}
				if nextURL := next.URL.String(); nextURL != "/" {
					t.Errorf("Wrong URL at destination: %s", nextURL)
				}
			} else {
				if got.Method != "HEAD" {
					t.Errorf("Wrong method for destination: %q", got.Method)
				}
				gotURL := got.URL.String()
				wantURL := ts.URL + "/"
				if gotURL != wantURL {
					t.Errorf("Got URL %q, want %q", gotURL, wantURL)
				}
			}
		})
	}
}

func TestOnProxyConnectResponse(t *testing.T) {

	var tcases = []struct {
		proxyStatusCode int
		err             error
	}{
		{
			StatusOK,
			nil,
		},
		{
			StatusForbidden,
			errors.New("403"),
		},
	}
	for _, tcase := range tcases {
		h1 := HandlerFunc(func(w ResponseWriter, r *Request) {

		})

		h2 := HandlerFunc(func(w ResponseWriter, r *Request) {
			// Implement an entire CONNECT proxy
			if r.Method == "CONNECT" {
				if tcase.proxyStatusCode != StatusOK {
					w.WriteHeader(tcase.proxyStatusCode)
					return
				}
				hijacker, ok := w.(Hijacker)
				if !ok {
					t.Errorf("hijack not allowed")
					return
				}
				clientConn, _, err := hijacker.Hijack()
				if err != nil {
					t.Errorf("hijacking failed")
					return
				}
				res := &Response{
					StatusCode: StatusOK,
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(Header),
				}

				targetConn, err := net.Dial("tcp", r.URL.Host)
				if err != nil {
					t.Errorf("net.Dial(%q) failed: %v", r.URL.Host, err)
					return
				}

				if err := res.Write(clientConn); err != nil {
					t.Errorf("Writing 200 OK failed: %v", err)
					return
				}

				go io.Copy(targetConn, clientConn)
				go func() {
					io.Copy(clientConn, targetConn)
					targetConn.Close()
				}()
			}
		})
		ts := newClientServerTest(t, https1Mode, h1).ts
		proxy := newClientServerTest(t, https1Mode, h2).ts

		pu, err := url.Parse(proxy.URL)
		if err != nil {
			t.Fatal(err)
		}

		c := proxy.Client()

		var (
			dials  atomic.Int32
			closes atomic.Int32
		)
		c.Transport.(*Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			dials.Add(1)
			return noteCloseConn{
				Conn: conn,
				closeFunc: func() {
					closes.Add(1)
				},
			}, nil
		}

		c.Transport.(*Transport).Proxy = ProxyURL(pu)
		c.Transport.(*Transport).OnProxyConnectResponse = func(ctx context.Context, proxyURL *url.URL, connectReq *Request, connectRes *Response) error {
			if proxyURL.String() != pu.String() {
				t.Errorf("proxy url got %s, want %s", proxyURL, pu)
			}

			if "https://"+connectReq.URL.String() != ts.URL {
				t.Errorf("connect url got %s, want %s", connectReq.URL, ts.URL)
			}
			return tcase.err
		}
		wantCloses := int32(0)
		if _, err := c.Head(ts.URL); err != nil {
			wantCloses = 1
			if tcase.err != nil && !strings.Contains(err.Error(), tcase.err.Error()) {
				t.Errorf("got %v, want %v", err, tcase.err)
			}
		} else {
			if tcase.err != nil {
				t.Errorf("got %v, want nil", err)
			}
		}
		if got, want := dials.Load(), int32(1); got != want {
			t.Errorf("got %v dials, want %v", got, want)
		}
		// #64804: If OnProxyConnectResponse returns an error, we should close the conn.
		if got, want := closes.Load(), wantCloses; got != want {
			t.Errorf("got %v closes, want %v", got, want)
		}
	}
}

// Issue 28012: verify that the Transport closes its TCP connection to http proxies
// when they're slow to reply to HTTPS CONNECT responses.
func TestTransportProxyHTTPSConnectLeak(t *testing.T) {
	cancelc := make(chan struct{})
	SetTestHookProxyConnectTimeout(t, func(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-cancelc:
			case <-ctx.Done():
			}
			cancel()
		}()
		return ctx, cancel
	})

	defer afterTest(t)

	ln := newLocalListener(t)
	defer ln.Close()
	listenerDone := make(chan struct{})
	go func() {
		defer close(listenerDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer c.Close()
		// Read the CONNECT request
		br := bufio.NewReader(c)
		cr, err := ReadRequest(br)
		if err != nil {
			t.Errorf("proxy server failed to read CONNECT request")
			return
		}
		if cr.Method != "CONNECT" {
			t.Errorf("unexpected method %q", cr.Method)
			return
		}

		// Now hang and never write a response; instead, cancel the request and wait
		// for the client to close.
		// (Prior to Issue 28012 being fixed, we never closed.)
		close(cancelc)
		var buf [1]byte
		_, err = br.Read(buf[:])
		if err != io.EOF {
			t.Errorf("proxy server Read err = %v; want EOF", err)
		}
		return
	}()

	c := &Client{
		Transport: &Transport{
			Proxy: func(*Request) (*url.URL, error) {
				return url.Parse("http://" + ln.Addr().String())
			},
		},
	}
	req, err := NewRequest("GET", "https://golang.fake.tld/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(req)
	if err == nil {
		t.Errorf("unexpected Get success")
	}

	// Wait unconditionally for the listener goroutine to exit: this should never
	// hang, so if it does we want a full goroutine dump — and that's exactly what
	// the testing package will give us when the test run times out.
	<-listenerDone
}

// Issue 16997: test transport dial preserves typed errors
func TestTransportDialPreservesNetOpProxyError(t *testing.T) {
	defer afterTest(t)

	var errDial = errors.New("some dial error")

	tr := &Transport{
		Proxy: func(*Request) (*url.URL, error) {
			return url.Parse("http://proxy.fake.tld/")
		},
		Dial: func(string, string) (net.Conn, error) {
			return nil, errDial
		},
	}
	defer tr.CloseIdleConnections()

	c := &Client{Transport: tr}
	req, _ := NewRequest("GET", "http://fake.tld", nil)
	res, err := c.Do(req)
	if err == nil {
		res.Body.Close()
		t.Fatal("wanted a non-nil error")
	}

	uerr, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("got %T, want *url.Error", err)
	}
	oe, ok := uerr.Err.(*net.OpError)
	if !ok {
		t.Fatalf("url.Error.Err =  %T; want *net.OpError", uerr.Err)
	}
	want := &net.OpError{
		Op:  "proxyconnect",
		Net: "tcp",
		Err: errDial, // original error, unwrapped.
	}
	if !reflect.DeepEqual(oe, want) {
		t.Errorf("Got error %#v; want %#v", oe, want)
	}
}

// Issue 36431: calls to RoundTrip should not mutate t.ProxyConnectHeader.
//
// (A bug caused dialConn to instead write the per-request Proxy-Authorization
// header through to the shared Header instance, introducing a data race.)
func TestTransportProxyDialDoesNotMutateProxyConnectHeader(t *testing.T) {
	run(t, testTransportProxyDialDoesNotMutateProxyConnectHeader)
}
func testTransportProxyDialDoesNotMutateProxyConnectHeader(t *testing.T, mode testMode) {
	proxy := newClientServerTest(t, mode, NotFoundHandler()).ts
	defer proxy.Close()
	c := proxy.Client()

	tr := c.Transport.(*Transport)
	tr.Proxy = func(*Request) (*url.URL, error) {
		u, _ := url.Parse(proxy.URL)
		u.User = url.UserPassword("aladdin", "opensesame")
		return u, nil
	}
	h := tr.ProxyConnectHeader
	if h == nil {
		h = make(Header)
	}
	tr.ProxyConnectHeader = h.Clone()

	req, err := NewRequest("GET", "https://golang.fake.tld/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(req)
	if err == nil {
		t.Errorf("unexpected Get success")
	}

	if !reflect.DeepEqual(tr.ProxyConnectHeader, h) {
		t.Errorf("tr.ProxyConnectHeader = %v; want %v", tr.ProxyConnectHeader, h)
	}
}

// TestTransportGzipRecursive sends a gzip quine and checks that the
// client gets the same value back. This is more cute than anything,
// but checks that we don't recurse forever, and checks that
// Content-Encoding is removed.
func TestTransportGzipRecursive(t *testing.T) { run(t, testTransportGzipRecursive) }
func testTransportGzipRecursive(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(rgz)
	})).ts

	c := ts.Client()
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, rgz) {
		t.Fatalf("Incorrect result from recursive gz:\nhave=%x\nwant=%x",
			body, rgz)
	}
	if g, e := res.Header.Get("Content-Encoding"), ""; g != e {
		t.Fatalf("Content-Encoding = %q; want %q", g, e)
	}
}

// golang.org/issue/7750: request fails when server replies with
// a short gzip body
func TestTransportGzipShort(t *testing.T) { run(t, testTransportGzipShort) }
func testTransportGzipShort(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte{0x1f, 0x8b})
	})).ts

	c := ts.Client()
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	_, err = io.ReadAll(res.Body)
	if err == nil {
		t.Fatal("Expect an error from reading a body.")
	}
	if err != io.ErrUnexpectedEOF {
		t.Errorf("ReadAll error = %v; want io.ErrUnexpectedEOF", err)
	}
}

// Wait until number of goroutines is no greater than nmax, or time out.
func waitNumGoroutine(nmax int) int {
	nfinal := runtime.NumGoroutine()
	for ntries := 10; ntries > 0 && nfinal > nmax; ntries-- {
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		nfinal = runtime.NumGoroutine()
	}
	return nfinal
}

// tests that persistent goroutine connections shut down when no longer desired.
func TestTransportPersistConnLeak(t *testing.T) {
	run(t, testTransportPersistConnLeak, testNotParallel)
}
func testTransportPersistConnLeak(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("flaky in HTTP/2")
	}
	// Not parallel: counts goroutines

	const numReq = 25
	gotReqCh := make(chan bool, numReq)
	unblockCh := make(chan bool, numReq)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		gotReqCh <- true
		<-unblockCh
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(204)
	})).ts
	c := ts.Client()
	tr := c.Transport.(*Transport)

	n0 := runtime.NumGoroutine()

	didReqCh := make(chan bool, numReq)
	failed := make(chan bool, numReq)
	for i := 0; i < numReq; i++ {
		go func() {
			res, err := c.Get(ts.URL)
			didReqCh <- true
			if err != nil {
				t.Logf("client fetch error: %v", err)
				failed <- true
				return
			}
			res.Body.Close()
		}()
	}

	// Wait for all goroutines to be stuck in the Handler.
	for i := 0; i < numReq; i++ {
		select {
		case <-gotReqCh:
			// ok
		case <-failed:
			// Not great but not what we are testing:
			// sometimes an overloaded system will fail to make all the connections.
		}
	}

	nhigh := runtime.NumGoroutine()

	// Tell all handlers to unblock and reply.
	close(unblockCh)

	// Wait for all HTTP clients to be done.
	for i := 0; i < numReq; i++ {
		<-didReqCh
	}

	tr.CloseIdleConnections()
	nfinal := waitNumGoroutine(n0 + 5)

	growth := nfinal - n0

	// We expect 0 or 1 extra goroutine, empirically. Allow up to 5.
	// Previously we were leaking one per numReq.
	if int(growth) > 5 {
		t.Logf("goroutine growth: %d -> %d -> %d (delta: %d)", n0, nhigh, nfinal, growth)
		t.Error("too many new goroutines")
	}
}

// golang.org/issue/4531: Transport leaks goroutines when
// request.ContentLength is explicitly short
func TestTransportPersistConnLeakShortBody(t *testing.T) {
	run(t, testTransportPersistConnLeakShortBody, testNotParallel)
}
func testTransportPersistConnLeakShortBody(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("flaky in HTTP/2")
	}

	// Not parallel: measures goroutines.
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
	})).ts
	c := ts.Client()
	tr := c.Transport.(*Transport)

	n0 := runtime.NumGoroutine()
	body := []byte("Hello")
	for i := 0; i < 20; i++ {
		req, err := NewRequest("POST", ts.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = int64(len(body) - 2) // explicitly short
		_, err = c.Do(req)
		if err == nil {
			t.Fatal("Expect an error from writing too long of a body.")
		}
	}
	nhigh := runtime.NumGoroutine()
	tr.CloseIdleConnections()
	nfinal := waitNumGoroutine(n0 + 5)

	growth := nfinal - n0

	// We expect 0 or 1 extra goroutine, empirically. Allow up to 5.
	// Previously we were leaking one per numReq.
	t.Logf("goroutine growth: %d -> %d -> %d (delta: %d)", n0, nhigh, nfinal, growth)
	if int(growth) > 5 {
		t.Error("too many new goroutines")
	}
}

// A countedConn is a net.Conn that decrements an atomic counter when finalized.
type countedConn struct {
	net.Conn
}

// A countingDialer dials connections and counts the number that remain reachable.
type countingDialer struct {
	dialer      net.Dialer
	mu          sync.Mutex
	total, live int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	counted := new(countedConn)
	counted.Conn = conn

	d.mu.Lock()
	defer d.mu.Unlock()
	d.total++
	d.live++

	runtime.SetFinalizer(counted, d.decrement)
	return counted, nil
}

func (d *countingDialer) decrement(*countedConn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.live--
}

func (d *countingDialer) Read() (total, live int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.total, d.live
}

func TestTransportPersistConnLeakNeverIdle(t *testing.T) {
	run(t, testTransportPersistConnLeakNeverIdle, []testMode{http1Mode})
}
func testTransportPersistConnLeakNeverIdle(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// Close every connection so that it cannot be kept alive.
		conn, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack failed unexpectedly: %v", err)
			return
		}
		conn.Close()
	})).ts

	var d countingDialer
	c := ts.Client()
	c.Transport.(*Transport).DialContext = d.DialContext

	body := []byte("Hello")
	for i := 0; ; i++ {
		total, live := d.Read()
		if live < total {
			break
		}
		if i >= 1<<12 {
			t.Fatalf("Count of live client net.Conns (%d) not lower than total (%d) after %d Do / GC iterations.", live, total, i)
		}

		req, err := NewRequest("POST", ts.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Do(req)
		if err == nil {
			t.Fatal("expected broken connection")
		}

		runtime.GC()
	}
}

type countedContext struct {
	context.Context
}

type contextCounter struct {
	mu   sync.Mutex
	live int64
}

func (cc *contextCounter) Track(ctx context.Context) context.Context {
	counted := new(countedContext)
	counted.Context = ctx
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.live++
	runtime.SetFinalizer(counted, cc.decrement)
	return counted
}

func (cc *contextCounter) decrement(*countedContext) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.live--
}

func (cc *contextCounter) Read() (live int64) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.live
}

func TestTransportPersistConnContextLeakMaxConnsPerHost(t *testing.T) {
	run(t, testTransportPersistConnContextLeakMaxConnsPerHost)
}
func testTransportPersistConnContextLeakMaxConnsPerHost(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("https://go.dev/issue/56021")
	}

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		runtime.Gosched()
		w.WriteHeader(StatusOK)
	})).ts

	c := ts.Client()
	c.Transport.(*Transport).MaxConnsPerHost = 1

	ctx := context.Background()
	body := []byte("Hello")
	doPosts := func(cc *contextCounter) {
		var wg sync.WaitGroup
		for n := 64; n > 0; n-- {
			wg.Add(1)
			go func() {
				defer wg.Done()

				ctx := cc.Track(ctx)
				req, err := NewRequest("POST", ts.URL, bytes.NewReader(body))
				if err != nil {
					t.Error(err)
				}

				_, err = c.Do(req.WithContext(ctx))
				if err != nil {
					t.Errorf("Do failed with error: %v", err)
				}
			}()
		}
		wg.Wait()
	}

	var initialCC contextCounter
	doPosts(&initialCC)

	// flushCC exists only to put pressure on the GC to finalize the initialCC
	// contexts: the flushCC allocations should eventually displace the initialCC
	// allocations.
	var flushCC contextCounter
	for i := 0; ; i++ {
		live := initialCC.Read()
		if live == 0 {
			break
		}
		if i >= 100 {
			t.Fatalf("%d Contexts still not finalized after %d GC cycles.", live, i)
		}
		doPosts(&flushCC)
		runtime.GC()
	}
}

// This used to crash; https://golang.org/issue/3266
func TestTransportIdleConnCrash(t *testing.T) { run(t, testTransportIdleConnCrash) }
func testTransportIdleConnCrash(t *testing.T, mode testMode) {
	var tr *Transport

	unblockCh := make(chan bool, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		<-unblockCh
		tr.CloseIdleConnections()
	})).ts
	c := ts.Client()
	tr = c.Transport.(*Transport)

	didreq := make(chan bool)
	go func() {
		res, err := c.Get(ts.URL)
		if err != nil {
			t.Error(err)
		} else {
			res.Body.Close() // returns idle conn
		}
		didreq <- true
	}()
	unblockCh <- true
	<-didreq
}

// Test that the transport doesn't close the TCP connection early,
// before the response body has been read. This was a regression
// which sadly lacked a triggering test. The large response body made
// the old race easier to trigger.
func TestIssue3644(t *testing.T) { run(t, testIssue3644) }
func testIssue3644(t *testing.T, mode testMode) {
	const numFoos = 5000
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Connection", "close")
		for i := 0; i < numFoos; i++ {
			w.Write([]byte("foo "))
		}
	})).ts
	c := ts.Client()
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	bs, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != numFoos*len("foo ") {
		t.Errorf("unexpected response length")
	}
}

// Test that a client receives a server's reply, even if the server doesn't read
// the entire request body.
func TestIssue3595(t *testing.T) {
	// Not parallel: modifies the global rstAvoidanceDelay.
	run(t, testIssue3595, testNotParallel)
}
func testIssue3595(t *testing.T, mode testMode) {
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

		const deniedMsg = "sorry, denied."
		cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			Error(w, deniedMsg, StatusUnauthorized)
		}))
		// We need to close cst explicitly here so that in-flight server
		// requests don't race with the call to SetRSTAvoidanceDelay for a retry.
		defer cst.close()
		ts := cst.ts
		c := ts.Client()

		res, err := c.Post(ts.URL, "application/octet-stream", neverEnding('a'))
		if err != nil {
			return fmt.Errorf("Post: %v", err)
		}
		got, err := io.ReadAll(res.Body)
		if err != nil {
			return fmt.Errorf("Body ReadAll: %v", err)
		}
		t.Logf("server response:\n%s", got)
		if !strings.Contains(string(got), deniedMsg) {
			// If we got an RST packet too early, we should have seen an error
			// from io.ReadAll, not a silently-truncated body.
			t.Errorf("Known bug: response %q does not contain %q", got, deniedMsg)
		}
		return nil
	})
}

// From https://golang.org/issue/4454 ,
// "client fails to handle requests with no body and chunked encoding"
func TestChunkedNoContent(t *testing.T) { run(t, testChunkedNoContent) }
func testChunkedNoContent(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusNoContent)
	})).ts

	c := ts.Client()
	for _, closeBody := range []bool{true, false} {
		const n = 4
		for i := 1; i <= n; i++ {
			res, err := c.Get(ts.URL)
			if err != nil {
				t.Errorf("closingBody=%v, req %d/%d: %v", closeBody, i, n, err)
			} else {
				if closeBody {
					res.Body.Close()
				}
			}
		}
	}
}

func TestTransportConcurrency(t *testing.T) {
	run(t, testTransportConcurrency, testNotParallel, []testMode{http1Mode})
}
func testTransportConcurrency(t *testing.T, mode testMode) {
	// Not parallel: uses global test hooks.
	maxProcs, numReqs := 16, 500
	if testing.Short() {
		maxProcs, numReqs = 4, 50
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(maxProcs))
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "%v", r.FormValue("echo"))
	})).ts

	var wg sync.WaitGroup
	wg.Add(numReqs)

	// Due to the Transport's "socket late binding" (see
	// idleConnCh in transport.go), the numReqs HTTP requests
	// below can finish with a dial still outstanding. To keep
	// the leak checker happy, keep track of pending dials and
	// wait for them to finish (and be closed or returned to the
	// idle pool) before we close idle connections.
	SetPendingDialHooks(func() { wg.Add(1) }, wg.Done)
	defer SetPendingDialHooks(nil, nil)

	c := ts.Client()
	reqs := make(chan string)
	defer close(reqs)

	for i := 0; i < maxProcs*2; i++ {
		go func() {
			for req := range reqs {
				res, err := c.Get(ts.URL + "/?echo=" + req)
				if err != nil {
					if runtime.GOOS == "netbsd" && strings.HasSuffix(err.Error(), ": connection reset by peer") {
						// https://go.dev/issue/52168: this test was observed to fail with
						// ECONNRESET errors in Dial on various netbsd builders.
						t.Logf("error on req %s: %v", req, err)
						t.Logf("(see https://go.dev/issue/52168)")
					} else {
						t.Errorf("error on req %s: %v", req, err)
					}
					wg.Done()
					continue
				}
				all, err := io.ReadAll(res.Body)
				if err != nil {
					t.Errorf("read error on req %s: %v", req, err)
				} else if string(all) != req {
					t.Errorf("body of req %s = %q; want %q", req, all, req)
				}
				res.Body.Close()
				wg.Done()
			}
		}()
	}
	for i := 0; i < numReqs; i++ {
		reqs <- fmt.Sprintf("request-%d", i)
	}
	wg.Wait()
}

func TestIssue4191_InfiniteGetTimeout(t *testing.T) { run(t, testIssue4191_InfiniteGetTimeout) }
func testIssue4191_InfiniteGetTimeout(t *testing.T, mode testMode) {
	mux := NewServeMux()
	mux.HandleFunc("/get", func(w ResponseWriter, r *Request) {
		io.Copy(w, neverEnding('a'))
	})
	ts := newClientServerTest(t, mode, mux).ts

	connc := make(chan net.Conn, 1)
	c := ts.Client()
	c.Transport.(*Transport).Dial = func(n, addr string) (net.Conn, error) {
		conn, err := net.Dial(n, addr)
		if err != nil {
			return nil, err
		}
		select {
		cas
```