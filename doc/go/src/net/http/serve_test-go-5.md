Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided Go code, which is a part of the `net/http/serve_test.go` file. The request asks for a description of the functions, examples of their usage, reasoning about the underlying Go features, handling of command-line arguments (though this specific snippet doesn't have any apparent command-line argument handling), common mistakes, and a summary of the overall functionality.

2. **Initial Scan for Test Functions:** The code is clearly a test file. The names of the functions starting with `Test` immediately stand out. This tells us that the code is designed to verify the behavior of the `net/http` package, specifically related to serving HTTP requests.

3. **Categorize Test Functions by Functionality:**  Read through the test function names and try to group them based on what aspect of the HTTP server they are testing. For example:
    * **Shutdown/Close:** `TestServerShutdownStateNew`, `TestServerCloseDeadlock`, `TestServerCloseListenerOnce`, `TestServerShutdownThenServe`
    * **Keep-Alive:** `TestServerKeepAlivesEnabled`, `TestDisableKeepAliveUpgrade`
    * **Timeouts:** `TestServerCancelsReadTimeoutWhenIdle`, `TestServerCancelsReadHeaderTimeoutWhenIdle`, `TestTimeoutHandlerSuperfluousLogs`
    * **Request Handling:** `TestServerDuplicateBackgroundRead`, `TestServerHijackGetsBackgroundByte`, `TestServerHijackGetsBackgroundByte_big`, `TestServerValidatesMethod`, `TestUnsupportedTransferEncodingsReturn501`, `TestContentEncodingNoSniffing`, `TestWriteHeaderSwitchingProtocols`, `TestQuerySemicolon`, `TestMaxBytesHandler`
    * **Contexts:** `TestServerContexts`, `TestConnContextNotModifyingAllContexts`
    * **Other:** `TestServerListenNotComparableListener`, `TestStripPortFromHost`, `TestMuxRedirectRelative`, `BenchmarkResponseStatusLine`

4. **Analyze Individual Test Functions:** For each test function (or group of related functions), try to understand the core behavior being verified. Look for:
    * **Setup:** How is the test server created? What handlers are being used?  Are there any specific configurations being set (e.g., timeouts, keep-alive settings)?
    * **Action:** What actions are being performed against the server (e.g., sending requests, closing connections, calling `Shutdown`)?
    * **Assertion:** What checks are being performed to verify the expected behavior?  Look for `t.Errorf`, `t.Fatalf`, and conditions being checked.

5. **Identify Key `net/http` Features Being Tested:** Based on the test function analysis, identify the underlying `net/http` functionalities being exercised. Examples:
    * `Server.Shutdown()` and `Server.Close()`
    * `Server.SetKeepAlivesEnabled()`
    * `Server.ReadTimeout`, `Server.ReadHeaderTimeout`, `TimeoutHandler`
    * The background read mechanism of the server
    * `ResponseWriter.(Hijacker).Hijack()`
    * Request method validation
    * Handling of `Transfer-Encoding` headers
    * Content type sniffing and the effect of `Content-Encoding`
    * `ServeMux` behavior
    * `Server.BaseContext` and `Server.ConnContext`
    * Handling of unsupported transfer encodings
    * `MaxBytesHandler`

6. **Code Examples (Where Applicable):**  For some functionalities, providing a concise Go code example demonstrates the usage. Focus on the core functionality being tested. For instance, for `Server.Shutdown()`, show a basic server setup and a call to `Shutdown()`. For `Hijacker`, show a handler using `Hijack()`.

7. **Reasoning and Underlying Mechanisms:** Explain *why* the tests are written the way they are. What aspects of the Go HTTP server are being probed? This involves understanding the expected behavior of the HTTP protocol and how Go's `net/http` package implements it. For example, the tests for timeouts verify that the server behaves correctly when connections are idle or take too long to send data. The tests for `Hijacker` check that the raw connection can be accessed.

8. **Command-Line Arguments:**  Carefully review the code for any use of `os.Args` or flags from the `flag` package. In this specific snippet, there are no apparent command-line arguments being processed.

9. **Common Mistakes:**  Think about scenarios where a developer might misuse the features being tested. For example, forgetting to close the response body, not understanding the behavior of `Shutdown()` with active connections, or misconfiguring timeouts.

10. **Summarize Functionality:** Condense the findings into a concise summary of the overall purpose of the code snippet. Emphasize that it's a test file for verifying the behavior of Go's HTTP server implementation.

11. **Structure the Answer:** Organize the information logically, using headings and bullet points to improve readability. Address each part of the original request clearly.

12. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where the explanation could be improved. For example, make sure the code examples are runnable and illustrate the intended point.

**Self-Correction Example During the Process:**

* **Initial thought:** "This test seems to be about shutting down the server immediately."
* **Correction during analysis of `TestServerShutdownStateNew`:** "Actually, this test is more nuanced. It's specifically checking the behavior of `Shutdown()` when there's an *idle* connection. It waits for the idle timeout before the connection is closed. This highlights the interaction between `Shutdown()` and idle connection management."  This deeper understanding leads to a more accurate explanation.

By following this structured approach, you can effectively analyze and explain the functionality of complex code snippets like the one provided.
这是 Go 语言 `net/http` 包中 `serve_test.go` 文件的一部分，主要功能是**测试 `http.Server` 类型在不同场景下的行为和特性**。

从这段代码片段来看，它侧重于以下几个方面的测试：

1. **服务器关闭 (Shutdown) 状态:**  测试在调用 `Shutdown` 后，服务器对新连接和现有连接的处理方式，以及状态转换。
2. **`Server.Close()` 的行为:** 验证可以安全地多次调用 `Server.Close()`，并且不会导致死锁。
3. **`Server.SetKeepAlivesEnabled()` 的作用:** 测试是否能正确启用或禁用 HTTP/1 和 HTTP/2 的 Keep-Alive 功能。
4. **服务器超时 (Timeouts) 的处理:**
    * 测试服务器在空闲状态下是否会取消 `ReadTimeout`，避免不必要的超时。
    * 测试服务器在空闲状态下是否会取消 `ReadHeaderTimeout`，确保超时仅在接收请求头时生效。
5. **服务器的后台读取行为:** 验证服务器在处理完请求后，不会重复尝试进行后台读取。
6. **`Hijacker` 接口的实现:**  测试通过 `Hijacker` 接口获取的 `bufio.Reader` 是否包含了服务器在后台读取的字节。
7. **请求方法的验证:** 测试服务器是否能正确拒绝无效的 HTTP 请求方法。
8. **处理不可比较的 `net.Listener`:**  测试服务器在 `Serve` 方法中使用不可比较的 `net.Listener` 时不会崩溃。
9. **`Server.Shutdown()` 对 `net.Listener.Close()` 的调用:** 验证 `Shutdown` 方法不会多次调用 `Listener.Close()`。
10. **先调用 `Shutdown` 后调用 `Serve` 的行为:** 测试在这种情况下 `Serve` 方法是否会立即返回 `ErrServerClosed` 错误。
11. **`ServeMux` 处理带端口号的 Host 头:** 测试 `ServeMux` 在路由时是否会忽略 Host 头中的端口号。
12. **服务器上下文 (Contexts):** 测试 `Server` 提供的 `BaseContext` 和 `ConnContext` 功能，以及它们如何为请求处理提供上下文信息。
13. **`ConnContext` 不会影响其他连接的上下文:** 验证在一个连接中设置的 `ConnContext` 不会影响其他连接。
14. **处理不支持的 `Transfer-Encoding`:** 测试服务器是否会针对不支持的传输编码返回 `501 Not Implemented` 错误。
15. **禁用 Content-Encoding 时的内容嗅探:** 测试当设置了 `Content-Encoding` 头部时，服务器是否会跳过内容类型嗅探。
16. **`TimeoutHandler` 的日志记录:** 测试 `TimeoutHandler` 是否会正确记录多余的 `WriteHeader` 调用。
17. **`DisableKeepAlives` 和 Upgrade 连接:** 测试当禁用 Keep-Alive 且发生 Upgrade 连接时，服务器的处理方式。
18. **`WriteHeader` 和 `StatusSwitchingProtocols`:** 测试在发送 `101 Switching Protocols` 状态码后，尝试写入头部或 body 的行为。
19. **`ServeMux` 的重定向行为:** 测试 `ServeMux` 在没有匹配的处理器时，会将请求重定向到根路径。
20. **查询参数中的分号处理:** 测试是否允许在 URL 查询参数中使用分号，以及如何配置。
21. **`MaxBytesHandler` 的功能:** 测试 `MaxBytesHandler` 中间件限制请求体大小的功能。

**如果你能推理出它是什么 go 语言功能的实现，请用 go 代码举例说明:**

**1. 测试服务器关闭 (Shutdown) 状态:**

```go
func ExampleServer_Shutdown() {
	srv := &http.Server{Addr: ":8080"}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, World!")
	})

	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// 模拟等待一段时间，让服务器处理一些请求
	time.Sleep(time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Println("Server gracefully stopped")
}
```

**假设输入与输出:**  无特定的输入输出，这个例子主要演示了如何使用 `Server.Shutdown()` 方法来优雅地关闭服务器。当执行这段代码时，服务器会监听 8080 端口，处理一些请求后，会开始优雅关闭，不再接受新连接，并等待现有连接处理完毕或超时。

**2. `Hijacker` 接口的实现:**

```go
func ExampleResponseWriter_Hijack() {
	http.HandleFunc("/hijack", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// 现在你可以直接操作底层的 TCP 连接
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n")
		fmt.Fprintf(conn, "Upgrade: MyCustomProtocol\r\n")
		fmt.Fprintf(conn, "Connection: Upgrade\r\n")
		fmt.Fprintf(conn, "\r\n")

		// 进行自定义协议的通信
		fmt.Fprintln(conn, "Hello from custom protocol!")
	})

	http.ListenAndServe(":8080", nil)
}
```

**假设输入与输出:** 如果客户端发送一个 GET 请求到 `/hijack` 路径，服务器会尝试劫持连接。成功后，服务器会发送一个 HTTP 101 响应，并将连接升级到 `MyCustomProtocol`。之后，客户端和服务器可以直接通过 TCP 连接发送自定义协议的数据。

**3. `MaxBytesHandler` 的功能:**

```go
func ExampleMaxBytesHandler() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "Received body: %s", body)
	})

	maxBytesHandler := http.MaxBytesHandler(handler, 10) // 限制请求体最大为 10 字节

	http.ListenAndServe(":8080", maxBytesHandler)
}
```

**假设输入与输出:** 如果客户端发送一个 POST 请求到服务器，请求体小于等于 10 字节，服务器会读取并返回请求体。如果请求体超过 10 字节，`MaxBytesHandler` 会返回一个 `413 Request Entity Too Large` 错误。

**如果涉及命令行参数的具体处理，请详细介绍一下:**

在这个代码片段中，**没有直接涉及命令行参数的处理**。这些测试都是通过 Go 的 `testing` 包和 `net/http/httptest` 包来模拟服务器和客户端行为，而不需要外部的命令行输入。

**如果有哪些使用者易犯错的点，请举例说明:**

* **`Server.Shutdown` 的使用:** 容易忘记设置 `context.Context` 的超时时间，导致 `Shutdown` 方法一直阻塞，或者设置的超时时间过短，导致服务器无法优雅关闭。
* **`Hijacker` 的使用:** 在调用 `Hijack()` 后，需要负责管理底层的 TCP 连接，包括关闭连接，容易忘记或者处理不当。并且在 `Hijack()` 之后，就不能再使用 `ResponseWriter` 的其他方法来发送 HTTP 响应头或 body 了。
* **超时设置:** 对 `ReadTimeout` 和 `WriteTimeout` 的理解不准确，或者设置不合理，导致连接被意外关闭。例如，`ReadTimeout` 是指从客户端读取 *完整请求* 的最长时间，而不是单个数据包的读取时间。
* **Keep-Alive 的配置:** 不理解 `SetKeepAlivesEnabled(false)` 的作用，或者在客户端没有正确处理 Keep-Alive 连接，导致连接泄漏或者性能问题。
* **`MaxBytesHandler` 的使用:**  错误地估计请求体的大小限制，或者忘记处理 `MaxBytesHandler` 返回的错误，导致程序行为不符合预期。

**请归纳一下它的功能 (作为第 6 部分):**

作为第 6 部分，这个代码片段的主要功能是**深入测试 `net/http.Server` 类型的各种高级特性和边界情况**。它涵盖了服务器的生命周期管理（启动、关闭）、连接管理（Keep-Alive）、超时控制、请求处理的细节（方法验证、请求体大小限制）、连接劫持、上下文管理以及一些不太常见但重要的场景（如处理不可比较的 Listener、不支持的传输编码）。  通过这些细致的测试，可以确保 `net/http.Server` 在各种复杂情况下都能稳定可靠地运行，并符合 HTTP 协议规范。

Prompt: 
```
这是路径为go/src/net/http/serve_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共7部分，请归纳一下它的功能

"""
tdown is broken.

	if states := <-statesRes; states[StateActive] != 1 {
		t.Errorf("connection in wrong state, %v", states)
	}
}

func TestServerShutdownStateNew(t *testing.T) { runSynctest(t, testServerShutdownStateNew) }
func testServerShutdownStateNew(t testing.TB, mode testMode) {
	if testing.Short() {
		t.Skip("test takes 5-6 seconds; skipping in short mode")
	}

	listener := fakeNetListen()
	defer listener.Close()

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// nothing.
	}), func(ts *httptest.Server) {
		ts.Listener.Close()
		ts.Listener = listener
		// Ignore irrelevant error about TLS handshake failure.
		ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	}).ts

	// Start a connection but never write to it.
	c := listener.connect()
	defer c.Close()
	synctest.Wait()

	shutdownRes := runAsync(func() (struct{}, error) {
		return struct{}{}, ts.Config.Shutdown(context.Background())
	})

	// TODO(#59037): This timeout is hard-coded in closeIdleConnections.
	// It is undocumented, and some users may find it surprising.
	// Either document it, or switch to a less surprising behavior.
	const expectTimeout = 5 * time.Second

	// Wait until just before the expected timeout.
	time.Sleep(expectTimeout - 1)
	synctest.Wait()
	if shutdownRes.done() {
		t.Fatal("shutdown too soon")
	}
	if c.IsClosedByPeer() {
		t.Fatal("connection was closed by server too soon")
	}

	// closeIdleConnections isn't precise about its actual shutdown time.
	// Wait long enough for it to definitely have shut down.
	//
	// (It would be good to make closeIdleConnections less sloppy.)
	time.Sleep(2 * time.Second)
	synctest.Wait()
	if _, err := shutdownRes.result(); err != nil {
		t.Fatalf("Shutdown() = %v, want complete", err)
	}
	if !c.IsClosedByPeer() {
		t.Fatalf("connection was not closed by server after shutdown")
	}
}

// Issue 17878: tests that we can call Close twice.
func TestServerCloseDeadlock(t *testing.T) {
	var s Server
	s.Close()
	s.Close()
}

// Issue 17717: tests that Server.SetKeepAlivesEnabled is respected by
// both HTTP/1 and HTTP/2.
func TestServerKeepAlivesEnabled(t *testing.T) { run(t, testServerKeepAlivesEnabled, testNotParallel) }
func testServerKeepAlivesEnabled(t *testing.T, mode testMode) {
	if mode == http2Mode {
		restore := ExportSetH2GoawayTimeout(10 * time.Millisecond)
		defer restore()
	}
	// Not parallel: messes with global variable. (http2goAwayTimeout)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {}))
	defer cst.close()
	srv := cst.ts.Config
	srv.SetKeepAlivesEnabled(false)
	for try := 0; try < 2; try++ {
		waitCondition(t, 10*time.Millisecond, func(d time.Duration) bool {
			if !srv.ExportAllConnsIdle() {
				if d > 0 {
					t.Logf("test server still has active conns after %v", d)
				}
				return false
			}
			return true
		})
		conns := 0
		var info httptrace.GotConnInfo
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			GotConn: func(v httptrace.GotConnInfo) {
				conns++
				info = v
			},
		})
		req, err := NewRequestWithContext(ctx, "GET", cst.ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := cst.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if conns != 1 {
			t.Fatalf("request %v: got %v conns, want 1", try, conns)
		}
		if info.Reused || info.WasIdle {
			t.Fatalf("request %v: Reused=%v (want false), WasIdle=%v (want false)", try, info.Reused, info.WasIdle)
		}
	}
}

// Issue 18447: test that the Server's ReadTimeout is stopped while
// the server's doing its 1-byte background read between requests,
// waiting for the connection to maybe close.
func TestServerCancelsReadTimeoutWhenIdle(t *testing.T) { run(t, testServerCancelsReadTimeoutWhenIdle) }
func testServerCancelsReadTimeoutWhenIdle(t *testing.T, mode testMode) {
	runTimeSensitiveTest(t, []time.Duration{
		10 * time.Millisecond,
		50 * time.Millisecond,
		250 * time.Millisecond,
		time.Second,
		2 * time.Second,
	}, func(t *testing.T, timeout time.Duration) error {
		cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			select {
			case <-time.After(2 * timeout):
				fmt.Fprint(w, "ok")
			case <-r.Context().Done():
				fmt.Fprint(w, r.Context().Err())
			}
		}), func(ts *httptest.Server) {
			ts.Config.ReadTimeout = timeout
			t.Logf("Server.Config.ReadTimeout = %v", timeout)
		})
		defer cst.close()
		ts := cst.ts

		var retries atomic.Int32
		cst.c.Transport.(*Transport).Proxy = func(*Request) (*url.URL, error) {
			if retries.Add(1) != 1 {
				return nil, errors.New("too many retries")
			}
			return nil, nil
		}

		c := ts.Client()

		res, err := c.Get(ts.URL)
		if err != nil {
			return fmt.Errorf("Get: %v", err)
		}
		slurp, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return fmt.Errorf("Body ReadAll: %v", err)
		}
		if string(slurp) != "ok" {
			return fmt.Errorf("got: %q, want ok", slurp)
		}
		return nil
	})
}

// Issue 54784: test that the Server's ReadHeaderTimeout only starts once the
// beginning of a request has been received, rather than including time the
// connection spent idle.
func TestServerCancelsReadHeaderTimeoutWhenIdle(t *testing.T) {
	run(t, testServerCancelsReadHeaderTimeoutWhenIdle, []testMode{http1Mode})
}
func testServerCancelsReadHeaderTimeoutWhenIdle(t *testing.T, mode testMode) {
	runTimeSensitiveTest(t, []time.Duration{
		10 * time.Millisecond,
		50 * time.Millisecond,
		250 * time.Millisecond,
		time.Second,
		2 * time.Second,
	}, func(t *testing.T, timeout time.Duration) error {
		cst := newClientServerTest(t, mode, serve(200), func(ts *httptest.Server) {
			ts.Config.ReadHeaderTimeout = timeout
			ts.Config.IdleTimeout = 0 // disable idle timeout
		})
		defer cst.close()
		ts := cst.ts

		// rather than using an http.Client, create a single connection, so that
		// we can ensure this connection is not closed.
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		br := bufio.NewReader(conn)
		defer conn.Close()

		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")); err != nil {
			return fmt.Errorf("writing first request failed: %v", err)
		}

		if _, err := ReadResponse(br, nil); err != nil {
			return fmt.Errorf("first response (before timeout) failed: %v", err)
		}

		// wait for longer than the server's ReadHeaderTimeout, and then send
		// another request
		time.Sleep(timeout * 3 / 2)

		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")); err != nil {
			return fmt.Errorf("writing second request failed: %v", err)
		}

		if _, err := ReadResponse(br, nil); err != nil {
			return fmt.Errorf("second response (after timeout) failed: %v", err)
		}

		return nil
	})
}

// runTimeSensitiveTest runs test with the provided durations until one passes.
// If they all fail, t.Fatal is called with the last one's duration and error value.
func runTimeSensitiveTest(t *testing.T, durations []time.Duration, test func(t *testing.T, d time.Duration) error) {
	for i, d := range durations {
		err := test(t, d)
		if err == nil {
			return
		}
		if i == len(durations)-1 || t.Failed() {
			t.Fatalf("failed with duration %v: %v", d, err)
		}
		t.Logf("retrying after error with duration %v: %v", d, err)
	}
}

// Issue 18535: test that the Server doesn't try to do a background
// read if it's already done one.
func TestServerDuplicateBackgroundRead(t *testing.T) {
	run(t, testServerDuplicateBackgroundRead, []testMode{http1Mode})
}
func testServerDuplicateBackgroundRead(t *testing.T, mode testMode) {
	if runtime.GOOS == "netbsd" && runtime.GOARCH == "arm" {
		testenv.SkipFlaky(t, 24826)
	}

	goroutines := 5
	requests := 2000
	if testing.Short() {
		goroutines = 3
		requests = 100
	}

	hts := newClientServerTest(t, mode, HandlerFunc(NotFound)).ts

	reqBytes := []byte("GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cn, err := net.Dial("tcp", hts.Listener.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer cn.Close()

			wg.Add(1)
			go func() {
				defer wg.Done()
				io.Copy(io.Discard, cn)
			}()

			for j := 0; j < requests; j++ {
				if t.Failed() {
					return
				}
				_, err := cn.Write(reqBytes)
				if err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Test that the bufio.Reader returned by Hijack includes any buffered
// byte (from the Server's backgroundRead) in its buffer. We want the
// Handler code to be able to tell that a byte is available via
// bufio.Reader.Buffered(), without resorting to Reading it
// (potentially blocking) to get at it.
func TestServerHijackGetsBackgroundByte(t *testing.T) {
	run(t, testServerHijackGetsBackgroundByte, []testMode{http1Mode})
}
func testServerHijackGetsBackgroundByte(t *testing.T, mode testMode) {
	if runtime.GOOS == "plan9" {
		t.Skip("skipping test; see https://golang.org/issue/18657")
	}
	done := make(chan struct{})
	inHandler := make(chan bool, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		defer close(done)

		// Tell the client to send more data after the GET request.
		inHandler <- true

		conn, buf, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		peek, err := buf.Reader.Peek(3)
		if string(peek) != "foo" || err != nil {
			t.Errorf("Peek = %q, %v; want foo, nil", peek, err)
		}

		select {
		case <-r.Context().Done():
			t.Error("context unexpectedly canceled")
		default:
		}
	})).ts

	cn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()
	if _, err := cn.Write([]byte("GET / HTTP/1.1\r\nHost: e.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	<-inHandler
	if _, err := cn.Write([]byte("foo")); err != nil {
		t.Fatal(err)
	}

	if err := cn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	<-done
}

// Like TestServerHijackGetsBackgroundByte above but sending a
// immediate 1MB of data to the server to fill up the server's 4KB
// buffer.
func TestServerHijackGetsBackgroundByte_big(t *testing.T) {
	run(t, testServerHijackGetsBackgroundByte_big, []testMode{http1Mode})
}
func testServerHijackGetsBackgroundByte_big(t *testing.T, mode testMode) {
	if runtime.GOOS == "plan9" {
		t.Skip("skipping test; see https://golang.org/issue/18657")
	}
	done := make(chan struct{})
	const size = 8 << 10
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		defer close(done)

		conn, buf, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		slurp, err := io.ReadAll(buf.Reader)
		if err != nil {
			t.Errorf("Copy: %v", err)
		}
		allX := true
		for _, v := range slurp {
			if v != 'x' {
				allX = false
			}
		}
		if len(slurp) != size {
			t.Errorf("read %d; want %d", len(slurp), size)
		} else if !allX {
			t.Errorf("read %q; want %d 'x'", slurp, size)
		}
	})).ts

	cn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()
	if _, err := fmt.Fprintf(cn, "GET / HTTP/1.1\r\nHost: e.com\r\n\r\n%s",
		strings.Repeat("x", size)); err != nil {
		t.Fatal(err)
	}
	if err := cn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	<-done
}

// Issue 18319: test that the Server validates the request method.
func TestServerValidatesMethod(t *testing.T) {
	tests := []struct {
		method string
		want   int
	}{
		{"GET", 200},
		{"GE(T", 400},
	}
	for _, tt := range tests {
		conn := newTestConn()
		io.WriteString(&conn.readBuf, tt.method+" / HTTP/1.1\r\nHost: foo.example\r\n\r\n")

		ln := &oneConnListener{conn}
		go Serve(ln, serve(200))
		<-conn.closec
		res, err := ReadResponse(bufio.NewReader(&conn.writeBuf), nil)
		if err != nil {
			t.Errorf("For %s, ReadResponse: %v", tt.method, res)
			continue
		}
		if res.StatusCode != tt.want {
			t.Errorf("For %s, Status = %d; want %d", tt.method, res.StatusCode, tt.want)
		}
	}
}

// Listener for TestServerListenNotComparableListener.
type eofListenerNotComparable []int

func (eofListenerNotComparable) Accept() (net.Conn, error) { return nil, io.EOF }
func (eofListenerNotComparable) Addr() net.Addr            { return nil }
func (eofListenerNotComparable) Close() error              { return nil }

// Issue 24812: don't crash on non-comparable Listener
func TestServerListenNotComparableListener(t *testing.T) {
	var s Server
	s.Serve(make(eofListenerNotComparable, 1)) // used to panic
}

// countCloseListener is a Listener wrapper that counts the number of Close calls.
type countCloseListener struct {
	net.Listener
	closes int32 // atomic
}

func (p *countCloseListener) Close() error {
	var err error
	if n := atomic.AddInt32(&p.closes, 1); n == 1 && p.Listener != nil {
		err = p.Listener.Close()
	}
	return err
}

// Issue 24803: don't call Listener.Close on Server.Shutdown.
func TestServerCloseListenerOnce(t *testing.T) {
	setParallel(t)
	defer afterTest(t)

	ln := newLocalListener(t)
	defer ln.Close()

	cl := &countCloseListener{Listener: ln}
	server := &Server{}
	sdone := make(chan bool, 1)

	go func() {
		server.Serve(cl)
		sdone <- true
	}()
	time.Sleep(10 * time.Millisecond)
	server.Shutdown(context.Background())
	ln.Close()
	<-sdone

	nclose := atomic.LoadInt32(&cl.closes)
	if nclose != 1 {
		t.Errorf("Close calls = %v; want 1", nclose)
	}
}

// Issue 20239: don't block in Serve if Shutdown is called first.
func TestServerShutdownThenServe(t *testing.T) {
	var srv Server
	cl := &countCloseListener{Listener: nil}
	srv.Shutdown(context.Background())
	got := srv.Serve(cl)
	if got != ErrServerClosed {
		t.Errorf("Serve err = %v; want ErrServerClosed", got)
	}
	nclose := atomic.LoadInt32(&cl.closes)
	if nclose != 1 {
		t.Errorf("Close calls = %v; want 1", nclose)
	}
}

// Issue 23351: document and test behavior of ServeMux with ports
func TestStripPortFromHost(t *testing.T) {
	mux := NewServeMux()

	mux.HandleFunc("example.com/", func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "OK")
	})
	mux.HandleFunc("example.com:9000/", func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "uh-oh!")
	})

	req := httptest.NewRequest("GET", "http://example.com:9000/", nil)
	rw := httptest.NewRecorder()

	mux.ServeHTTP(rw, req)

	response := rw.Body.String()
	if response != "OK" {
		t.Errorf("Response gotten was %q", response)
	}
}

func TestServerContexts(t *testing.T) { run(t, testServerContexts) }
func testServerContexts(t *testing.T, mode testMode) {
	type baseKey struct{}
	type connKey struct{}
	ch := make(chan context.Context, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, r *Request) {
		ch <- r.Context()
	}), func(ts *httptest.Server) {
		ts.Config.BaseContext = func(ln net.Listener) context.Context {
			if strings.Contains(reflect.TypeOf(ln).String(), "onceClose") {
				t.Errorf("unexpected onceClose listener type %T", ln)
			}
			return context.WithValue(context.Background(), baseKey{}, "base")
		}
		ts.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			if got, want := ctx.Value(baseKey{}), "base"; got != want {
				t.Errorf("in ConnContext, base context key = %#v; want %q", got, want)
			}
			return context.WithValue(ctx, connKey{}, "conn")
		}
	}).ts
	res, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	ctx := <-ch
	if got, want := ctx.Value(baseKey{}), "base"; got != want {
		t.Errorf("base context key = %#v; want %q", got, want)
	}
	if got, want := ctx.Value(connKey{}), "conn"; got != want {
		t.Errorf("conn context key = %#v; want %q", got, want)
	}
}

// Issue 35750: check ConnContext not modifying context for other connections
func TestConnContextNotModifyingAllContexts(t *testing.T) {
	run(t, testConnContextNotModifyingAllContexts)
}
func testConnContextNotModifyingAllContexts(t *testing.T, mode testMode) {
	type connKey struct{}
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, r *Request) {
		rw.Header().Set("Connection", "close")
	}), func(ts *httptest.Server) {
		ts.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			if got := ctx.Value(connKey{}); got != nil {
				t.Errorf("in ConnContext, unexpected context key = %#v", got)
			}
			return context.WithValue(ctx, connKey{}, "conn")
		}
	}).ts

	var res *Response
	var err error

	res, err = ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	res, err = ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

// Issue 30710: ensure that as per the spec, a server responds
// with 501 Not Implemented for unsupported transfer-encodings.
func TestUnsupportedTransferEncodingsReturn501(t *testing.T) {
	run(t, testUnsupportedTransferEncodingsReturn501, []testMode{http1Mode})
}
func testUnsupportedTransferEncodingsReturn501(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write([]byte("Hello, World!"))
	})).ts

	serverURL, err := url.Parse(cst.URL)
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}

	unsupportedTEs := []string{
		"fugazi",
		"foo-bar",
		"unknown",
		`" chunked"`,
	}

	for _, badTE := range unsupportedTEs {
		http1ReqBody := fmt.Sprintf(""+
			"POST / HTTP/1.1\r\nConnection: close\r\n"+
			"Host: localhost\r\nTransfer-Encoding: %s\r\n\r\n", badTE)

		gotBody, err := fetchWireResponse(serverURL.Host, []byte(http1ReqBody))
		if err != nil {
			t.Errorf("%q. unexpected error: %v", badTE, err)
			continue
		}

		wantBody := fmt.Sprintf("" +
			"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain; charset=utf-8\r\n" +
			"Connection: close\r\n\r\nUnsupported transfer encoding")

		if string(gotBody) != wantBody {
			t.Errorf("%q. body\ngot\n%q\nwant\n%q", badTE, gotBody, wantBody)
		}
	}
}

// Issue 31753: don't sniff when Content-Encoding is set
func TestContentEncodingNoSniffing(t *testing.T) { run(t, testContentEncodingNoSniffing) }
func testContentEncodingNoSniffing(t *testing.T, mode testMode) {
	type setting struct {
		name string
		body []byte

		// setting contentEncoding as an interface instead of a string
		// directly, so as to differentiate between 3 states:
		//    unset, empty string "" and set string "foo/bar".
		contentEncoding any
		wantContentType string
	}

	settings := []*setting{
		{
			name:            "gzip content-encoding, gzipped", // don't sniff.
			contentEncoding: "application/gzip",
			wantContentType: "",
			body: func() []byte {
				buf := new(bytes.Buffer)
				gzw := gzip.NewWriter(buf)
				gzw.Write([]byte("doctype html><p>Hello</p>"))
				gzw.Close()
				return buf.Bytes()
			}(),
		},
		{
			name:            "zlib content-encoding, zlibbed", // don't sniff.
			contentEncoding: "application/zlib",
			wantContentType: "",
			body: func() []byte {
				buf := new(bytes.Buffer)
				zw := zlib.NewWriter(buf)
				zw.Write([]byte("doctype html><p>Hello</p>"))
				zw.Close()
				return buf.Bytes()
			}(),
		},
		{
			name:            "no content-encoding", // must sniff.
			wantContentType: "application/x-gzip",
			body: func() []byte {
				buf := new(bytes.Buffer)
				gzw := gzip.NewWriter(buf)
				gzw.Write([]byte("doctype html><p>Hello</p>"))
				gzw.Close()
				return buf.Bytes()
			}(),
		},
		{
			name:            "phony content-encoding", // don't sniff.
			contentEncoding: "foo/bar",
			body:            []byte("doctype html><p>Hello</p>"),
		},
		{
			name:            "empty but set content-encoding",
			contentEncoding: "",
			wantContentType: "audio/mpeg",
			body:            []byte("ID3"),
		},
	}

	for _, tt := range settings {
		t.Run(tt.name, func(t *testing.T) {
			cst := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, r *Request) {
				if tt.contentEncoding != nil {
					rw.Header().Set("Content-Encoding", tt.contentEncoding.(string))
				}
				rw.Write(tt.body)
			}))

			res, err := cst.c.Get(cst.ts.URL)
			if err != nil {
				t.Fatalf("Failed to fetch URL: %v", err)
			}
			defer res.Body.Close()

			if g, w := res.Header.Get("Content-Encoding"), tt.contentEncoding; g != w {
				if w != nil { // The case where contentEncoding was set explicitly.
					t.Errorf("Content-Encoding mismatch\n\tgot:  %q\n\twant: %q", g, w)
				} else if g != "" { // "" should be the equivalent when the contentEncoding is unset.
					t.Errorf("Unexpected Content-Encoding %q", g)
				}
			}

			if g, w := res.Header.Get("Content-Type"), tt.wantContentType; g != w {
				t.Errorf("Content-Type mismatch\n\tgot:  %q\n\twant: %q", g, w)
			}
		})
	}
}

// Issue 30803: ensure that TimeoutHandler logs spurious
// WriteHeader calls, for consistency with other Handlers.
func TestTimeoutHandlerSuperfluousLogs(t *testing.T) {
	run(t, testTimeoutHandlerSuperfluousLogs, []testMode{http1Mode})
}
func testTimeoutHandlerSuperfluousLogs(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	pc, curFile, _, _ := runtime.Caller(0)
	curFileBaseName := filepath.Base(curFile)
	testFuncName := runtime.FuncForPC(pc).Name()

	timeoutMsg := "timed out here!"

	tests := []struct {
		name        string
		mustTimeout bool
		wantResp    string
	}{
		{
			name:     "return before timeout",
			wantResp: "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:        "return after timeout",
			mustTimeout: true,
			wantResp: fmt.Sprintf("HTTP/1.1 503 Service Unavailable\r\nContent-Length: %d\r\n\r\n%s",
				len(timeoutMsg), timeoutMsg),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			exitHandler := make(chan bool, 1)
			defer close(exitHandler)
			lastLine := make(chan int, 1)

			sh := HandlerFunc(func(w ResponseWriter, r *Request) {
				w.WriteHeader(404)
				w.WriteHeader(404)
				w.WriteHeader(404)
				w.WriteHeader(404)
				_, _, line, _ := runtime.Caller(0)
				lastLine <- line
				<-exitHandler
			})

			if !tt.mustTimeout {
				exitHandler <- true
			}

			logBuf := new(strings.Builder)
			srvLog := log.New(logBuf, "", 0)
			// When expecting to timeout, we'll keep the duration short.
			dur := 20 * time.Millisecond
			if !tt.mustTimeout {
				// Otherwise, make it arbitrarily long to reduce the risk of flakes.
				dur = 10 * time.Second
			}
			th := TimeoutHandler(sh, dur, timeoutMsg)
			cst := newClientServerTest(t, mode, th, optWithServerLog(srvLog))
			defer cst.close()

			res, err := cst.c.Get(cst.ts.URL)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Deliberately removing the "Date" header since it is highly ephemeral
			// and will cause failure if we try to match it exactly.
			res.Header.Del("Date")
			res.Header.Del("Content-Type")

			// Match the response.
			blob, _ := httputil.DumpResponse(res, true)
			if g, w := string(blob), tt.wantResp; g != w {
				t.Errorf("Response mismatch\nGot\n%q\n\nWant\n%q", g, w)
			}

			// Given 4 w.WriteHeader calls, only the first one is valid
			// and the rest should be reported as the 3 spurious logs.
			logEntries := strings.Split(strings.TrimSpace(logBuf.String()), "\n")
			if g, w := len(logEntries), 3; g != w {
				blob, _ := json.MarshalIndent(logEntries, "", "  ")
				t.Fatalf("Server logs count mismatch\ngot %d, want %d\n\nGot\n%s\n", g, w, blob)
			}

			lastSpuriousLine := <-lastLine
			firstSpuriousLine := lastSpuriousLine - 3
			// Now ensure that the regexes match exactly.
			//      "http: superfluous response.WriteHeader call from <fn>.func\d.\d (<curFile>:lastSpuriousLine-[1, 3]"
			for i, logEntry := range logEntries {
				wantLine := firstSpuriousLine + i
				pat := fmt.Sprintf("^http: superfluous response.WriteHeader call from %s.func\\d+.\\d+ \\(%s:%d\\)$",
					testFuncName, curFileBaseName, wantLine)
				re := regexp.MustCompile(pat)
				if !re.MatchString(logEntry) {
					t.Errorf("Log entry mismatch\n\t%s\ndoes not match\n\t%s", logEntry, pat)
				}
			}
		})
	}
}

// fetchWireResponse is a helper for dialing to host,
// sending http1ReqBody as the payload and retrieving
// the response as it was sent on the wire.
func fetchWireResponse(host string, http1ReqBody []byte) ([]byte, error) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(http1ReqBody); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

func BenchmarkResponseStatusLine(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		bw := bufio.NewWriter(io.Discard)
		var buf3 [3]byte
		for pb.Next() {
			Export_writeStatusLine(bw, true, 200, buf3[:])
		}
	})
}

func TestDisableKeepAliveUpgrade(t *testing.T) {
	run(t, testDisableKeepAliveUpgrade, []testMode{http1Mode})
}
func testDisableKeepAliveUpgrade(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	s := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "someProto")
		w.WriteHeader(StatusSwitchingProtocols)
		c, buf, err := w.(Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()

		// Copy from the *bufio.ReadWriter, which may contain buffered data.
		// Copy to the net.Conn, to avoid buffering the output.
		io.Copy(c, buf)
	}), func(ts *httptest.Server) {
		ts.Config.SetKeepAlivesEnabled(false)
	}).ts

	cl := s.Client()
	cl.Transport.(*Transport).DisableKeepAlives = true

	resp, err := cl.Get(s.URL)
	if err != nil {
		t.Fatalf("failed to perform request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusSwitchingProtocols {
		t.Fatalf("unexpected status code: %v", resp.StatusCode)
	}

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("Response.Body is not an io.ReadWriteCloser: %T", resp.Body)
	}

	_, err = rwc.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("failed to write to body: %v", err)
	}

	b := make([]byte, 5)
	_, err = io.ReadFull(rwc, b)
	if err != nil {
		t.Fatalf("failed to read from body: %v", err)
	}

	if string(b) != "hello" {
		t.Fatalf("unexpected value read from body:\ngot: %q\nwant: %q", b, "hello")
	}
}

type tlogWriter struct{ t *testing.T }

func (w tlogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestWriteHeaderSwitchingProtocols(t *testing.T) {
	run(t, testWriteHeaderSwitchingProtocols, []testMode{http1Mode})
}
func testWriteHeaderSwitchingProtocols(t *testing.T, mode testMode) {
	const wantBody = "want"
	const wantUpgrade = "someProto"
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", wantUpgrade)
		w.WriteHeader(StatusSwitchingProtocols)
		NewResponseController(w).Flush()

		// Writing headers or the body after sending a 101 header should fail.
		w.WriteHeader(200)
		if _, err := w.Write([]byte("x")); err == nil {
			t.Errorf("Write to body after 101 Switching Protocols unexpectedly succeeded")
		}

		c, _, err := NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer c.Close()
		if _, err := c.Write([]byte(wantBody)); err != nil {
			t.Errorf("Write to hijacked body: %v", err)
		}
	}), func(ts *httptest.Server) {
		// Don't spam log with warning about superfluous WriteHeader call.
		ts.Config.ErrorLog = log.New(tlogWriter{t}, "log: ", 0)
	}).ts

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: foo\r\n\r\n"))
	if err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)
	res, err := ReadResponse(r, &Request{Method: "GET"})
	if err != nil {
		t.Fatal("ReadResponse error:", err)
	}
	if res.StatusCode != StatusSwitchingProtocols {
		t.Errorf("Response StatusCode=%v, want 101", res.StatusCode)
	}
	if got := res.Header.Get("Upgrade"); got != wantUpgrade {
		t.Errorf("Response Upgrade header = %q, want %q", got, wantUpgrade)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Error(err)
	}
	if string(body) != wantBody {
		t.Errorf("Response body = %q, want %q", string(body), wantBody)
	}
}

func TestMuxRedirectRelative(t *testing.T) {
	setParallel(t)
	req, err := ReadRequest(bufio.NewReader(strings.NewReader("GET http://example.com HTTP/1.1\r\nHost: test\r\n\r\n")))
	if err != nil {
		t.Errorf("%s", err)
	}
	mux := NewServeMux()
	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, req)
	if got, want := resp.Header().Get("Location"), "/"; got != want {
		t.Errorf("Location header expected %q; got %q", want, got)
	}
	if got, want := resp.Code, StatusMovedPermanently; got != want {
		t.Errorf("Expected response code %d; got %d", want, got)
	}
}

// TestQuerySemicolon tests the behavior of semicolons in queries. See Issue 25192.
func TestQuerySemicolon(t *testing.T) {
	t.Cleanup(func() { afterTest(t) })

	tests := []struct {
		query              string
		xNoSemicolons      string
		xWithSemicolons    string
		expectParseFormErr bool
	}{
		{"?a=1;x=bad&x=good", "good", "bad", true},
		{"?a=1;b=bad&x=good", "good", "good", true},
		{"?a=1%3Bx=bad&x=good%3B", "good;", "good;", false},
		{"?a=1;x=good;x=bad", "", "good", true},
	}

	run(t, func(t *testing.T, mode testMode) {
		for _, tt := range tests {
			t.Run(tt.query+"/allow=false", func(t *testing.T) {
				allowSemicolons := false
				testQuerySemicolon(t, mode, tt.query, tt.xNoSemicolons, allowSemicolons, tt.expectParseFormErr)
			})
			t.Run(tt.query+"/allow=true", func(t *testing.T) {
				allowSemicolons, expectParseFormErr := true, false
				testQuerySemicolon(t, mode, tt.query, tt.xWithSemicolons, allowSemicolons, expectParseFormErr)
			})
		}
	})
}

func testQuerySemicolon(t *testing.T, mode testMode, query string, wantX string, allowSemicolons, expectParseFormErr bool) {
	writeBackX := func(w ResponseWriter, r *Request) {
		x := r.URL.Query().Get("x")
		if expectParseFormErr {
			if err := r.ParseForm(); err == nil || !strings.Contains(err.Error(), "semicolon") {
				t.Errorf("expected error mentioning semicolons from ParseForm, got %v", err)
			}
		} else {
			if err := r.ParseForm(); err != nil {
				t.Errorf("expected no error from ParseForm, got %v", err)
			}
		}
		if got := r.FormValue("x"); x != got {
			t.Errorf("got %q from FormValue, want %q", got, x)
		}
		fmt.Fprintf(w, "%s", x)
	}

	h := Handler(HandlerFunc(writeBackX))
	if allowSemicolons {
		h = AllowQuerySemicolons(h)
	}

	logBuf := &strings.Builder{}
	ts := newClientServerTest(t, mode, h, func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(logBuf, "", 0)
	}).ts

	req, _ := NewRequest("GET", ts.URL+query, nil)
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	slurp, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("Status = %d; want = %d", got, want)
	}
	if got, want := string(slurp), wantX; got != want {
		t.Errorf("Body = %q; want = %q", got, want)
	}
}

func TestMaxBytesHandler(t *testing.T) {
	// Not parallel: modifies the global rstAvoidanceDelay.
	defer afterTest(t)

	for _, maxSize := range []int64{100, 1_000, 1_000_000} {
		for _, requestSize := range []int64{100, 1_000, 1_000_000} {
			t.Run(fmt.Sprintf("max size %d request size %d", maxSize, requestSize),
				func(t *testing.T) {
					run(t, func(t *testing.T, mode testMode) {
						testMaxBytesHandler(t, mode, maxSize, requestSize)
					}, testNotParallel)
				})
		}
	}
}

func testMaxBytesHandler(t *testing.T, mode testMode, maxSize, requestSize int64) {
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

		var (
			handlerN   int64
			handlerErr error
		)
		echo := HandlerFunc(func(w ResponseWriter, r *Request) {
			var buf bytes.Buffer
			handlerN, handlerErr = io.Copy(&buf, r.Body)
			io.Copy(w, &buf)
		})

		cst := newClientServerTest(t, mode, MaxBytesHandler(echo, maxSize))
		// We need to close cst explicitly here so that in-flight server
		// requests don't race with the call to SetRSTAvoidanceDelay for a retry.
		defer cst.close()
		ts := cst.ts
		c := ts.Client()

		body := strings.Repeat("a", int(requestSize))
		var wg sync.WaitGroup
		defer wg.Wait()
		getBody := func() (io.ReadCloser, error) {
			wg.Add(1)
			body := &wgRead
"""




```