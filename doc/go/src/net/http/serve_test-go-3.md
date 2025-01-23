Response:
The user wants me to analyze a Go code snippet from `go/src/net/http/serve_test.go`.
This is part 4 of a 7-part analysis. I need to:
1. **Summarize the functionality** of the provided code.
2. **Infer the Go language feature being tested** and provide a Go code example.
3. **If code inference is involved**:
    - Provide hypothetical input and output.
4. **If command-line arguments are handled**:
    - Explain the handling in detail.
5. **If there are common mistakes for users**:
    - Give examples of such mistakes.
6. **Since this is part 4**:
    - Summarize the functionality of this specific part.

Let's break down the code section by section:

- **`TestCloseNotifyOnKeepAlive`**: Tests the `CloseNotifier` interface when using keep-alive connections. It verifies that the `CloseNotify()` channel receives a signal when the connection is closed by the server after processing two requests.
- **`TestCloseNotifierChanLeak`**: Tests for potential goroutine leaks when using `CloseNotifier`. It ensures that goroutines are not leaked even if the return value of `CloseNotify()` is ignored.
- **`TestHijackAfterCloseNotifier`**: Tests that `Hijack` can be called on a connection after `CloseNotifier` has been used. It also checks that the internal `connReader` correctly handles the background read for `CloseNotifier`.
- **`TestHijackBeforeRequestBodyRead`**: Tests calling `Hijack` before the request body has been fully read. It verifies that the server correctly reads and processes the remaining request body even after the hijack.
- **`TestOptions`**: Tests the handling of `OPTIONS` requests, including `OPTIONS *` and regular path-based `OPTIONS`. It also verifies the behavior of the `ServeMux` for such requests.
- **`TestOptionsHandler`**: Tests the behavior when the `DisableGeneralOptionsHandler` option is set, ensuring that a custom handler receives `OPTIONS *` requests.
- **`TestHeaderToWire`**: A comprehensive set of tests checking the order of `Write`, `WriteHeader`, `Header`, and `Flush` calls and how they affect the headers sent over the wire. It verifies the Go 1.0/1.1 compatibility regarding header flushing.
- **`TestAcceptMaxFds`**: Tests the server's behavior when the `accept` syscall returns `EMFILE` (too many open files).
- **`TestWriteAfterHijack`**: Tests writing to the hijacked connection and the `bufio.ReadWriter` obtained from `Hijack`.
- **`TestDoubleHijack`**: Tests that calling `Hijack` twice on the same `ResponseWriter` results in an error.
- **`TestHTTP10ConnectionHeader`**: Tests how the server handles the `Connection` header in HTTP/1.0 requests.
- **`TestServerReaderFromOrder`**: Tests the interaction between reading from the request body and writing to the response body using `io.Copy`.
- **`TestCodesPreventingContentTypeAndBody`**: Tests that for certain status codes (like 304 and 204), the server correctly suppresses `Content-Length` and the response body.
- **`TestContentTypeOkayOn204`**: Tests that a `Content-Type` header is allowed even with a 204 status code.
- **`TestTransportAndServerSharedBodyRace`**: Tests for potential race conditions when the request body is shared between the server handler and the `http.Transport`.
- **`TestRequestBodyCloseDoesntBlock`**: Tests that closing the request body in the handler doesn't block even if another goroutine is still reading from it.
- **`TestResponseWriterWriteString`**: Tests if `ResponseWriter` implements the `io.StringWriter` interface.
- **`TestAppendTime`**: Tests the `AppendTime` function used for formatting HTTP dates.
- **`TestServerConnState`**: Tests the `ConnState` hook, which allows tracking the state transitions of a connection.
- **`TestServerKeepAlivesEnabledResultClose`**: Tests the `SetKeepAlivesEnabled` option and its effect on the `res.Close` flag.
- **`TestServerEmptyBodyRace`**: Tests for race conditions when handling multiple requests with empty bodies.
- **`TestServerConnStateNew`**: Specifically tests that the `ConnState` hook is called with `StateNew` when a new connection is established.
- **`TestCloseWrite`**: Tests the `CloseWrite` method of the `http.conn` type.
- **`TestServerFlushAndHijack`**: Tests that `Flush` can be called before `Hijack`.
- **`TestServerKeepAliveAfterWriteError`**: Tests that the server doesn't reuse a connection after encountering a write error.

The primary Go features being tested here are:

- **`net/http` package functionality**: Specifically, the `Server`, `Handler`, `ResponseWriter`, `Request`, `CloseNotifier`, `Hijacker`, `Flusher`, `ServeMux`, and related components.
- **Concurrency**: The tests extensively use goroutines and channels to simulate concurrent requests and test for race conditions and proper synchronization.
- **Interfaces**:  The tests verify the implementation of specific interfaces like `CloseNotifier`, `Hijacker`, `Flusher`, and `io.StringWriter`.
- **HTTP Protocol**: The tests cover various aspects of the HTTP protocol, including request methods (`GET`, `POST`, `OPTIONS`), headers (`Connection`, `Content-Length`, `Content-Type`), status codes, and keep-alive connections.
这是 `go/src/net/http/serve_test.go` 文件的一部分，主要功能是**测试 `net/http` 包中服务器 (Server) 的各种行为和特性**。

具体来说，这部分代码主要测试了以下功能点：

1. **`CloseNotifier` 接口在 keep-alive 连接中的行为**: 测试当客户端使用 keep-alive 连接发送多个请求时，服务器关闭连接后，`ResponseWriter` 实现的 `CloseNotifier` 接口是否能正确通知处理器。这可以用于在连接关闭时执行清理操作。

   ```go
   // 假设输入：客户端发送两个 keep-alive 请求到服务器
   // 预期的输出：服务器处理完两个请求后关闭连接，处理器通过 CloseNotify() 接收到关闭信号

   package main

   import (
       "fmt"
       "io"
       "net/http"
       "time"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       fmt.Fprintf(w, "Hello\n")
       cn, ok := w.(http.CloseNotifier)
       if ok {
           <-cn.CloseNotify()
           fmt.Println("Connection closed")
       }
   }

   func main() {
       http.HandleFunc("/", handler)
       server := &http.Server{Addr: ":8080", Handler: nil}
       go func() {
           server.ListenAndServe()
       }()
       time.Sleep(time.Millisecond * 100) // 等待服务器启动

       // 模拟客户端发送两个 keep-alive 请求 (简化)
       conn, err := http.Dial("tcp", "localhost:8080")
       if err != nil {
           panic(err)
       }
       defer conn.Close()

       req1 := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
       _, err = io.WriteString(conn, req1)
       if err != nil {
           panic(err)
       }
       // 读取响应 ...

       req2 := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
       _, err = io.WriteString(conn, req2)
       if err != nil {
           panic(err)
       }
       // 读取响应 ...

       // 服务器处理完请求后可能会关闭连接
       time.Sleep(time.Second) // 模拟服务器处理时间

       fmt.Println("Client done")
   }
   ```

2. **避免 `CloseNotifier` 通道泄漏**: 确保即使处理器不读取 `CloseNotify()` 返回的通道，也不会导致 goroutine 泄漏。

3. **在调用 `CloseNotifier` 后调用 `Hijack`**: 测试在同一个连接上，先使用 `CloseNotifier` 监听连接关闭，然后再调用 `Hijacker` 接口的 `Hijack()` 方法来接管连接的情况。这验证了内部连接管理机制的正确性。

4. **在读取请求体之前调用 `Hijack`**: 测试在处理器尚未读取完客户端发送的请求体时，调用 `Hijacker` 接口的 `Hijack()` 方法来接管连接的情况。这验证了服务器在这种场景下能否正确处理。

   ```go
   // 假设输入：客户端发送一个带有请求体的 POST 请求，服务器在读取请求体之前调用 Hijack
   // 预期的输出：Hijack 成功，并且可以读取到完整的请求体 (尽管是在接管连接后)

   package main

   import (
       "bufio"
       "fmt"
       "io"
       "net"
       "net/http"
       "strings"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
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

       fmt.Fprint(conn, "HTTP/1.1 200 OK\r\n")
       // ... 其他响应头 ...
       fmt.Fprint(conn, "\r\n")

       // 读取并处理请求体
       reader := bufio.NewReader(conn)
       for {
           line, err := reader.ReadString('\n')
           if err != nil {
               if err != io.EOF {
                   fmt.Println("Error reading:", err)
               }
               break
           }
           fmt.Println("Received from client:", strings.TrimSpace(line))
       }
   }

   func main() {
       http.HandleFunc("/", handler)
       http.ListenAndServe(":8080", nil)
   }
   ```

5. **处理 `OPTIONS` 请求**: 测试服务器如何处理 `OPTIONS` 方法的请求，包括针对特定资源 (`OPTIONS /resource`) 和针对整个服务器 (`OPTIONS *`) 的请求。

6. **自定义 `OPTIONS` 请求处理器**: 测试当禁用默认的 `OPTIONS` 请求处理器时，自定义的处理器能否接收到 `OPTIONS *` 请求。

7. **`Write`、`WriteHeader`、`Header` 和 `Flush` 调用的顺序**: 这部分进行了大量的测试，验证在不同的调用顺序下，响应头是如何被写入到连接中的。它关注 Go 1.0 和 Go 1.1 之间关于响应头处理的兼容性问题，特别是 `WriteHeader` 调用是否会立即刷新头部。

8. **处理 `accept` 系统调用的 `EMFILE` 错误**: 测试当服务器达到最大文件描述符限制时，处理新的连接请求失败的情况。

9. **在 `Hijack` 后进行写入**: 测试在调用 `Hijack` 接管连接后，通过 `ResponseWriter` 和 `Hijacker` 返回的连接进行写入操作。

10. **多次调用 `Hijack`**: 测试在同一个请求处理过程中多次调用 `Hijack` 是否会产生错误。

11. **HTTP/1.0 的 `Connection` 头**: 测试服务器如何处理 HTTP/1.0 请求中的 `Connection` 头，例如 `Connection: keep-alive`。

12. **`Server` 的 `ReaderFrom` 方法的顺序**: 测试在处理请求时，读取请求体和写入响应体的顺序和可能的并发问题。

13. **阻止 `Content-Type` 和响应体的状态码**: 测试对于某些特定的 HTTP 状态码（如 304 Not Modified 和 204 No Content），服务器是否正确地阻止了 `Content-Length` 头和响应体的发送。

14. **状态码 204 的 `Content-Type`**: 验证即使状态码是 204，设置 `Content-Type` 头也是允许的。

15. **`Transport` 和 `Server` 共享请求体时的竞争**: 测试当服务器的处理器将接收到的请求体传递给客户端的 `Transport` 进行转发时，可能出现的竞争条件。

16. **`RequestBody.Close` 不会阻塞**: 测试在处理器中关闭请求体不会因为其他 goroutine 正在读取请求体而发生阻塞。

17. **`ResponseWriter` 实现 `io.StringWriter`**: 验证 `ResponseWriter` 是否实现了 `io.StringWriter` 接口，允许直接写入字符串。

18. **`AppendTime` 函数**: 测试用于格式化 HTTP 日期的 `AppendTime` 函数的正确性。

19. **`Server` 的 `ConnState` 回调**: 测试 `Server` 的 `ConnState` 选项，允许在连接状态改变时执行回调函数，例如连接建立、活跃、空闲和关闭等状态。

20. **禁用 keep-alive 时的服务器行为**: 测试当服务器禁用 keep-alive 时，响应的 `Body.Close` 方法是否返回 `true`。

21. **处理空请求体的竞争**: 测试并发处理多个带有空请求体的请求时可能出现的竞争条件。

22. **`Server` 的 `ConnState` 的 `StateNew` 状态**: 专门测试当建立新连接时，`ConnState` 回调是否会被调用，并且状态是 `StateNew`。

23. **`CloseWrite` 方法**: 测试 `http.conn` 类型的 `CloseWrite` 方法。

24. **先 `Flush` 后 `Hijack`**: 验证处理器可以先调用 `Flusher` 接口的 `Flush` 方法刷新响应，然后再调用 `Hijacker` 接口的 `Hijack` 方法接管连接。

25. **写入错误后服务器的 keep-alive 行为**: 测试当服务器在连接上遇到写入错误时，是否会正确地关闭连接，而不是继续尝试使用 keep-alive。

**总结一下这部分的功能:**

这部分代码主要针对 `net/http` 包中的服务器实现进行了详尽的单元测试，涵盖了连接管理（keep-alive, close-notify, hijack）、请求处理的各个阶段（头部写入、请求体读取）、对不同 HTTP 方法的处理（OPTIONS）、错误处理以及并发场景下的各种边界情况。通过这些测试，可以确保 `net/http` 服务器的稳定性和可靠性。

作为第 4 部分，它延续了对 `net/http` 服务器功能的测试，更深入地探讨了连接生命周期管理、高级特性（如 Hijack）以及在各种复杂场景下的行为。之前的部分可能已经涵盖了基本的请求处理和响应生成，而这部分则着重于更精细的控制和异常情况的处理。

### 提示词
```
这是路径为go/src/net/http/serve_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
d CloseNotify")
		case <-time.After(100 * time.Millisecond):
		}
		sawClose <- true
	})).ts
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("error dialing: %v", err)
	}
	diec := make(chan bool, 1)
	defer close(diec)
	go func() {
		const req = "GET / HTTP/1.1\r\nConnection: keep-alive\r\nHost: foo\r\n\r\n"
		_, err = io.WriteString(conn, req+req) // two requests
		if err != nil {
			t.Error(err)
			return
		}
		<-diec
		conn.Close()
	}()
	reqs := 0
	closes := 0
	for {
		select {
		case <-gotReq:
			reqs++
			if reqs > 2 {
				t.Fatal("too many requests")
			}
		case <-sawClose:
			closes++
			if closes > 1 {
				return
			}
		}
	}
}

func TestCloseNotifierChanLeak(t *testing.T) {
	defer afterTest(t)
	req := reqBytes("GET / HTTP/1.0\nHost: golang.org")
	for i := 0; i < 20; i++ {
		var output bytes.Buffer
		conn := &rwTestConn{
			Reader: bytes.NewReader(req),
			Writer: &output,
			closec: make(chan bool, 1),
		}
		ln := &oneConnListener{conn: conn}
		handler := HandlerFunc(func(rw ResponseWriter, r *Request) {
			// Ignore the return value and never read from
			// it, testing that we don't leak goroutines
			// on the sending side:
			_ = rw.(CloseNotifier).CloseNotify()
		})
		go Serve(ln, handler)
		<-conn.closec
	}
}

// Tests that we can use CloseNotifier in one request, and later call Hijack
// on a second request on the same connection.
//
// It also tests that the connReader stitches together its background
// 1-byte read for CloseNotifier when CloseNotifier doesn't fire with
// the rest of the second HTTP later.
//
// Issue 9763.
// HTTP/1-only test. (http2 doesn't have Hijack)
func TestHijackAfterCloseNotifier(t *testing.T) {
	run(t, testHijackAfterCloseNotifier, []testMode{http1Mode})
}
func testHijackAfterCloseNotifier(t *testing.T, mode testMode) {
	script := make(chan string, 2)
	script <- "closenotify"
	script <- "hijack"
	close(script)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		plan := <-script
		switch plan {
		default:
			panic("bogus plan; too many requests")
		case "closenotify":
			w.(CloseNotifier).CloseNotify() // discard result
			w.Header().Set("X-Addr", r.RemoteAddr)
		case "hijack":
			c, _, err := w.(Hijacker).Hijack()
			if err != nil {
				t.Errorf("Hijack in Handler: %v", err)
				return
			}
			if _, ok := c.(*net.TCPConn); !ok {
				// Verify it's not wrapped in some type.
				// Not strictly a go1 compat issue, but in practice it probably is.
				t.Errorf("type of hijacked conn is %T; want *net.TCPConn", c)
			}
			fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nX-Addr: %v\r\nContent-Length: 0\r\n\r\n", r.RemoteAddr)
			c.Close()
			return
		}
	})).ts
	res1, err := ts.Client().Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	res2, err := ts.Client().Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	addr1 := res1.Header.Get("X-Addr")
	addr2 := res2.Header.Get("X-Addr")
	if addr1 == "" || addr1 != addr2 {
		t.Errorf("addr1, addr2 = %q, %q; want same", addr1, addr2)
	}
}

func TestHijackBeforeRequestBodyRead(t *testing.T) {
	run(t, testHijackBeforeRequestBodyRead, []testMode{http1Mode})
}
func testHijackBeforeRequestBodyRead(t *testing.T, mode testMode) {
	var requestBody = bytes.Repeat([]byte("a"), 1<<20)
	bodyOkay := make(chan bool, 1)
	gotCloseNotify := make(chan bool, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		defer close(bodyOkay) // caller will read false if nothing else

		reqBody := r.Body
		r.Body = nil // to test that server.go doesn't use this value.

		gone := w.(CloseNotifier).CloseNotify()
		slurp, err := io.ReadAll(reqBody)
		if err != nil {
			t.Errorf("Body read: %v", err)
			return
		}
		if len(slurp) != len(requestBody) {
			t.Errorf("Backend read %d request body bytes; want %d", len(slurp), len(requestBody))
			return
		}
		if !bytes.Equal(slurp, requestBody) {
			t.Error("Backend read wrong request body.") // 1MB; omitting details
			return
		}
		bodyOkay <- true
		<-gone
		gotCloseNotify <- true
	})).ts

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: foo\r\nContent-Length: %d\r\n\r\n%s",
		len(requestBody), requestBody)
	if !<-bodyOkay {
		// already failed.
		return
	}
	conn.Close()
	<-gotCloseNotify
}

func TestOptions(t *testing.T) { run(t, testOptions, []testMode{http1Mode}) }
func testOptions(t *testing.T, mode testMode) {
	uric := make(chan string, 2) // only expect 1, but leave space for 2
	mux := NewServeMux()
	mux.HandleFunc("/", func(w ResponseWriter, r *Request) {
		uric <- r.RequestURI
	})
	ts := newClientServerTest(t, mode, mux).ts

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// An OPTIONS * request should succeed.
	_, err = conn.Write([]byte("OPTIONS * HTTP/1.1\r\nHost: foo.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := ReadResponse(br, &Request{Method: "OPTIONS"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Errorf("Got non-200 response to OPTIONS *: %#v", res)
	}

	// A GET * request on a ServeMux should fail.
	_, err = conn.Write([]byte("GET * HTTP/1.1\r\nHost: foo.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	res, err = ReadResponse(br, &Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 400 {
		t.Errorf("Got non-400 response to GET *: %#v", res)
	}

	res, err = Get(ts.URL + "/second")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := <-uric; got != "/second" {
		t.Errorf("Handler saw request for %q; want /second", got)
	}
}

func TestOptionsHandler(t *testing.T) { run(t, testOptionsHandler, []testMode{http1Mode}) }
func testOptionsHandler(t *testing.T, mode testMode) {
	rc := make(chan *Request, 1)

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		rc <- r
	}), func(ts *httptest.Server) {
		ts.Config.DisableGeneralOptionsHandler = true
	}).ts

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("OPTIONS * HTTP/1.1\r\nHost: foo.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	if got := <-rc; got.Method != "OPTIONS" || got.RequestURI != "*" {
		t.Errorf("Expected OPTIONS * request, got %v", got)
	}
}

// Tests regarding the ordering of Write, WriteHeader, Header, and
// Flush calls. In Go 1.0, rw.WriteHeader immediately flushed the
// (*response).header to the wire. In Go 1.1, the actual wire flush is
// delayed, so we could maybe tack on a Content-Length and better
// Content-Type after we see more (or all) of the output. To preserve
// compatibility with Go 1, we need to be careful to track which
// headers were live at the time of WriteHeader, so we write the same
// ones, even if the handler modifies them (~erroneously) after the
// first Write.
func TestHeaderToWire(t *testing.T) {
	tests := []struct {
		name    string
		handler func(ResponseWriter, *Request)
		check   func(got, logs string) error
	}{
		{
			name: "write without Header",
			handler: func(rw ResponseWriter, r *Request) {
				rw.Write([]byte("hello world"))
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Content-Length:") {
					return errors.New("no content-length")
				}
				if !strings.Contains(got, "Content-Type: text/plain") {
					return errors.New("no content-type")
				}
				return nil
			},
		},
		{
			name: "Header mutation before write",
			handler: func(rw ResponseWriter, r *Request) {
				h := rw.Header()
				h.Set("Content-Type", "some/type")
				rw.Write([]byte("hello world"))
				h.Set("Too-Late", "bogus")
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Content-Length:") {
					return errors.New("no content-length")
				}
				if !strings.Contains(got, "Content-Type: some/type") {
					return errors.New("wrong content-type")
				}
				if strings.Contains(got, "Too-Late") {
					return errors.New("don't want too-late header")
				}
				return nil
			},
		},
		{
			name: "write then useless Header mutation",
			handler: func(rw ResponseWriter, r *Request) {
				rw.Write([]byte("hello world"))
				rw.Header().Set("Too-Late", "Write already wrote headers")
			},
			check: func(got, logs string) error {
				if strings.Contains(got, "Too-Late") {
					return errors.New("header appeared from after WriteHeader")
				}
				return nil
			},
		},
		{
			name: "flush then write",
			handler: func(rw ResponseWriter, r *Request) {
				rw.(Flusher).Flush()
				rw.Write([]byte("post-flush"))
				rw.Header().Set("Too-Late", "Write already wrote headers")
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Transfer-Encoding: chunked") {
					return errors.New("not chunked")
				}
				if strings.Contains(got, "Too-Late") {
					return errors.New("header appeared from after WriteHeader")
				}
				return nil
			},
		},
		{
			name: "header then flush",
			handler: func(rw ResponseWriter, r *Request) {
				rw.Header().Set("Content-Type", "some/type")
				rw.(Flusher).Flush()
				rw.Write([]byte("post-flush"))
				rw.Header().Set("Too-Late", "Write already wrote headers")
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Transfer-Encoding: chunked") {
					return errors.New("not chunked")
				}
				if strings.Contains(got, "Too-Late") {
					return errors.New("header appeared from after WriteHeader")
				}
				if !strings.Contains(got, "Content-Type: some/type") {
					return errors.New("wrong content-type")
				}
				return nil
			},
		},
		{
			name: "sniff-on-first-write content-type",
			handler: func(rw ResponseWriter, r *Request) {
				rw.Write([]byte("<html><head></head><body>some html</body></html>"))
				rw.Header().Set("Content-Type", "x/wrong")
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Content-Type: text/html") {
					return errors.New("wrong content-type; want html")
				}
				return nil
			},
		},
		{
			name: "explicit content-type wins",
			handler: func(rw ResponseWriter, r *Request) {
				rw.Header().Set("Content-Type", "some/type")
				rw.Write([]byte("<html><head></head><body>some html</body></html>"))
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Content-Type: some/type") {
					return errors.New("wrong content-type; want html")
				}
				return nil
			},
		},
		{
			name: "empty handler",
			handler: func(rw ResponseWriter, r *Request) {
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Content-Length: 0") {
					return errors.New("want 0 content-length")
				}
				return nil
			},
		},
		{
			name: "only Header, no write",
			handler: func(rw ResponseWriter, r *Request) {
				rw.Header().Set("Some-Header", "some-value")
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "Some-Header") {
					return errors.New("didn't get header")
				}
				return nil
			},
		},
		{
			name: "WriteHeader call",
			handler: func(rw ResponseWriter, r *Request) {
				rw.WriteHeader(404)
				rw.Header().Set("Too-Late", "some-value")
			},
			check: func(got, logs string) error {
				if !strings.Contains(got, "404") {
					return errors.New("wrong status")
				}
				if strings.Contains(got, "Too-Late") {
					return errors.New("shouldn't have seen Too-Late")
				}
				return nil
			},
		},
	}
	for _, tc := range tests {
		ht := newHandlerTest(HandlerFunc(tc.handler))
		got := ht.rawResponse("GET / HTTP/1.1\nHost: golang.org")
		logs := ht.logbuf.String()
		if err := tc.check(got, logs); err != nil {
			t.Errorf("%s: %v\nGot response:\n%s\n\n%s", tc.name, err, got, logs)
		}
	}
}

type errorListener struct {
	errs []error
}

func (l *errorListener) Accept() (c net.Conn, err error) {
	if len(l.errs) == 0 {
		return nil, io.EOF
	}
	err = l.errs[0]
	l.errs = l.errs[1:]
	return
}

func (l *errorListener) Close() error {
	return nil
}

func (l *errorListener) Addr() net.Addr {
	return dummyAddr("test-address")
}

func TestAcceptMaxFds(t *testing.T) {
	setParallel(t)

	ln := &errorListener{[]error{
		&net.OpError{
			Op:  "accept",
			Err: syscall.EMFILE,
		}}}
	server := &Server{
		Handler:  HandlerFunc(HandlerFunc(func(ResponseWriter, *Request) {})),
		ErrorLog: log.New(io.Discard, "", 0), // noisy otherwise
	}
	err := server.Serve(ln)
	if err != io.EOF {
		t.Errorf("got error %v, want EOF", err)
	}
}

func TestWriteAfterHijack(t *testing.T) {
	req := reqBytes("GET / HTTP/1.1\nHost: golang.org")
	var buf strings.Builder
	wrotec := make(chan bool, 1)
	conn := &rwTestConn{
		Reader: bytes.NewReader(req),
		Writer: &buf,
		closec: make(chan bool, 1),
	}
	handler := HandlerFunc(func(rw ResponseWriter, r *Request) {
		conn, bufrw, err := rw.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		go func() {
			bufrw.Write([]byte("[hijack-to-bufw]"))
			bufrw.Flush()
			conn.Write([]byte("[hijack-to-conn]"))
			conn.Close()
			wrotec <- true
		}()
	})
	ln := &oneConnListener{conn: conn}
	go Serve(ln, handler)
	<-conn.closec
	<-wrotec
	if g, w := buf.String(), "[hijack-to-bufw][hijack-to-conn]"; g != w {
		t.Errorf("wrote %q; want %q", g, w)
	}
}

func TestDoubleHijack(t *testing.T) {
	req := reqBytes("GET / HTTP/1.1\nHost: golang.org")
	var buf bytes.Buffer
	conn := &rwTestConn{
		Reader: bytes.NewReader(req),
		Writer: &buf,
		closec: make(chan bool, 1),
	}
	handler := HandlerFunc(func(rw ResponseWriter, r *Request) {
		conn, _, err := rw.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _, err = rw.(Hijacker).Hijack()
		if err == nil {
			t.Errorf("got err = nil;  want err != nil")
		}
		conn.Close()
	})
	ln := &oneConnListener{conn: conn}
	go Serve(ln, handler)
	<-conn.closec
}

// https://golang.org/issue/5955
// Note that this does not test the "request too large"
// exit path from the http server. This is intentional;
// not sending Connection: close is just a minor wire
// optimization and is pointless if dealing with a
// badly behaved client.
func TestHTTP10ConnectionHeader(t *testing.T) {
	run(t, testHTTP10ConnectionHeader, []testMode{http1Mode})
}
func testHTTP10ConnectionHeader(t *testing.T, mode testMode) {
	mux := NewServeMux()
	mux.Handle("/", HandlerFunc(func(ResponseWriter, *Request) {}))
	ts := newClientServerTest(t, mode, mux).ts

	// net/http uses HTTP/1.1 for requests, so write requests manually
	tests := []struct {
		req    string   // raw http request
		expect []string // expected Connection header(s)
	}{
		{
			req:    "GET / HTTP/1.0\r\n\r\n",
			expect: nil,
		},
		{
			req:    "OPTIONS * HTTP/1.0\r\n\r\n",
			expect: nil,
		},
		{
			req:    "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
			expect: []string{"keep-alive"},
		},
	}

	for _, tt := range tests {
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal("dial err:", err)
		}

		_, err = fmt.Fprint(conn, tt.req)
		if err != nil {
			t.Fatal("conn write err:", err)
		}

		resp, err := ReadResponse(bufio.NewReader(conn), &Request{Method: "GET"})
		if err != nil {
			t.Fatal("ReadResponse err:", err)
		}
		conn.Close()
		resp.Body.Close()

		got := resp.Header["Connection"]
		if !slices.Equal(got, tt.expect) {
			t.Errorf("wrong Connection headers for request %q. Got %q expect %q", tt.req, got, tt.expect)
		}
	}
}

// See golang.org/issue/5660
func TestServerReaderFromOrder(t *testing.T) { run(t, testServerReaderFromOrder) }
func testServerReaderFromOrder(t *testing.T, mode testMode) {
	pr, pw := io.Pipe()
	const size = 3 << 20
	cst := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		rw.Header().Set("Content-Type", "text/plain") // prevent sniffing path
		done := make(chan bool)
		go func() {
			io.Copy(rw, pr)
			close(done)
		}()
		time.Sleep(25 * time.Millisecond) // give Copy a chance to break things
		n, err := io.Copy(io.Discard, req.Body)
		if err != nil {
			t.Errorf("handler Copy: %v", err)
			return
		}
		if n != size {
			t.Errorf("handler Copy = %d; want %d", n, size)
		}
		pw.Write([]byte("hi"))
		pw.Close()
		<-done
	}))

	req, err := NewRequest("POST", cst.ts.URL, io.LimitReader(neverEnding('a'), size))
	if err != nil {
		t.Fatal(err)
	}
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if string(all) != "hi" {
		t.Errorf("Body = %q; want hi", all)
	}
}

// Issue 6157, Issue 6685
func TestCodesPreventingContentTypeAndBody(t *testing.T) {
	for _, code := range []int{StatusNotModified, StatusNoContent} {
		ht := newHandlerTest(HandlerFunc(func(w ResponseWriter, r *Request) {
			if r.URL.Path == "/header" {
				w.Header().Set("Content-Length", "123")
			}
			w.WriteHeader(code)
			if r.URL.Path == "/more" {
				w.Write([]byte("stuff"))
			}
		}))
		for _, req := range []string{
			"GET / HTTP/1.0",
			"GET /header HTTP/1.0",
			"GET /more HTTP/1.0",
			"GET / HTTP/1.1\nHost: foo",
			"GET /header HTTP/1.1\nHost: foo",
			"GET /more HTTP/1.1\nHost: foo",
		} {
			got := ht.rawResponse(req)
			wantStatus := fmt.Sprintf("%d %s", code, StatusText(code))
			if !strings.Contains(got, wantStatus) {
				t.Errorf("Code %d: Wanted %q Modified for %q: %s", code, wantStatus, req, got)
			} else if strings.Contains(got, "Content-Length") {
				t.Errorf("Code %d: Got a Content-Length from %q: %s", code, req, got)
			} else if strings.Contains(got, "stuff") {
				t.Errorf("Code %d: Response contains a body from %q: %s", code, req, got)
			}
		}
	}
}

func TestContentTypeOkayOn204(t *testing.T) {
	ht := newHandlerTest(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "123") // suppressed
		w.Header().Set("Content-Type", "foo/bar")
		w.WriteHeader(204)
	}))
	got := ht.rawResponse("GET / HTTP/1.1\nHost: foo")
	if !strings.Contains(got, "Content-Type: foo/bar") {
		t.Errorf("Response = %q; want Content-Type: foo/bar", got)
	}
	if strings.Contains(got, "Content-Length: 123") {
		t.Errorf("Response = %q; don't want a Content-Length", got)
	}
}

// Issue 6995
// A server Handler can receive a Request, and then turn around and
// give a copy of that Request.Body out to the Transport (e.g. any
// proxy).  So then two people own that Request.Body (both the server
// and the http client), and both think they can close it on failure.
// Therefore, all incoming server requests Bodies need to be thread-safe.
func TestTransportAndServerSharedBodyRace(t *testing.T) {
	run(t, testTransportAndServerSharedBodyRace, testNotParallel)
}
func testTransportAndServerSharedBodyRace(t *testing.T, mode testMode) {
	// The proxy server in the middle of the stack for this test potentially
	// from its handler after only reading half of the body.
	// That can trigger https://go.dev/issue/3595, which is otherwise
	// irrelevant to this test.
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

		const bodySize = 1 << 20

		var wg sync.WaitGroup
		backend := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
			// Work around https://go.dev/issue/38370: clientServerTest uses
			// an httptest.Server under the hood, and in HTTP/2 mode it does not always
			// “[block] until all outstanding requests on this server have completed”,
			// causing the call to Logf below to race with the end of the test.
			//
			// Since the client doesn't cancel the request until we have copied half
			// the body, this call to add happens before the test is cleaned up,
			// preventing the race.
			wg.Add(1)
			defer wg.Done()

			n, err := io.CopyN(rw, req.Body, bodySize)
			t.Logf("backend CopyN: %v, %v", n, err)
			<-req.Context().Done()
		}))
		// We need to close explicitly here so that in-flight server
		// requests don't race with the call to SetRSTAvoidanceDelay for a retry.
		defer func() {
			wg.Wait()
			backend.close()
		}()

		var proxy *clientServerTest
		proxy = newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
			req2, _ := NewRequest("POST", backend.ts.URL, req.Body)
			req2.ContentLength = bodySize
			cancel := make(chan struct{})
			req2.Cancel = cancel

			bresp, err := proxy.c.Do(req2)
			if err != nil {
				t.Errorf("Proxy outbound request: %v", err)
				return
			}
			_, err = io.CopyN(io.Discard, bresp.Body, bodySize/2)
			if err != nil {
				t.Errorf("Proxy copy error: %v", err)
				return
			}
			t.Cleanup(func() { bresp.Body.Close() })

			// Try to cause a race. Canceling the client request will cause the client
			// transport to close req2.Body. Returning from the server handler will
			// cause the server to close req.Body. Since they are the same underlying
			// ReadCloser, that will result in concurrent calls to Close (and possibly a
			// Read concurrent with a Close).
			if mode == http2Mode {
				close(cancel)
			} else {
				proxy.c.Transport.(*Transport).CancelRequest(req2)
			}
			rw.Write([]byte("OK"))
		}))
		defer proxy.close()

		req, _ := NewRequest("POST", proxy.ts.URL, io.LimitReader(neverEnding('a'), bodySize))
		res, err := proxy.c.Do(req)
		if err != nil {
			return fmt.Errorf("original request: %v", err)
		}
		res.Body.Close()
		return nil
	})
}

// Test that a hanging Request.Body.Read from another goroutine can't
// cause the Handler goroutine's Request.Body.Close to block.
// See issue 7121.
func TestRequestBodyCloseDoesntBlock(t *testing.T) {
	run(t, testRequestBodyCloseDoesntBlock, []testMode{http1Mode})
}
func testRequestBodyCloseDoesntBlock(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}

	readErrCh := make(chan error, 1)
	errCh := make(chan error, 2)

	server := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		go func(body io.Reader) {
			_, err := body.Read(make([]byte, 100))
			readErrCh <- err
		}(req.Body)
		time.Sleep(500 * time.Millisecond)
	})).ts

	closeConn := make(chan bool)
	defer close(closeConn)
	go func() {
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("POST / HTTP/1.1\r\nConnection: close\r\nHost: foo\r\nContent-Length: 100000\r\n\r\n"))
		if err != nil {
			errCh <- err
			return
		}
		// And now just block, making the server block on our
		// 100000 bytes of body that will never arrive.
		<-closeConn
	}()
	select {
	case err := <-readErrCh:
		if err == nil {
			t.Error("Read was nil. Expected error.")
		}
	case err := <-errCh:
		t.Error(err)
	}
}

// test that ResponseWriter implements io.StringWriter.
func TestResponseWriterWriteString(t *testing.T) {
	okc := make(chan bool, 1)
	ht := newHandlerTest(HandlerFunc(func(w ResponseWriter, r *Request) {
		_, ok := w.(io.StringWriter)
		okc <- ok
	}))
	ht.rawResponse("GET / HTTP/1.0")
	select {
	case ok := <-okc:
		if !ok {
			t.Error("ResponseWriter did not implement io.StringWriter")
		}
	default:
		t.Error("handler was never called")
	}
}

func TestAppendTime(t *testing.T) {
	var b [len(TimeFormat)]byte
	t1 := time.Date(2013, 9, 21, 15, 41, 0, 0, time.FixedZone("CEST", 2*60*60))
	res := ExportAppendTime(b[:0], t1)
	t2, err := ParseTime(string(res))
	if err != nil {
		t.Fatalf("Error parsing time: %s", err)
	}
	if !t1.Equal(t2) {
		t.Fatalf("Times differ; expected: %v, got %v (%s)", t1, t2, string(res))
	}
}

func TestServerConnState(t *testing.T) { run(t, testServerConnState, []testMode{http1Mode}) }
func testServerConnState(t *testing.T, mode testMode) {
	handler := map[string]func(w ResponseWriter, r *Request){
		"/": func(w ResponseWriter, r *Request) {
			fmt.Fprintf(w, "Hello.")
		},
		"/close": func(w ResponseWriter, r *Request) {
			w.Header().Set("Connection", "close")
			fmt.Fprintf(w, "Hello.")
		},
		"/hijack": func(w ResponseWriter, r *Request) {
			c, _, _ := w.(Hijacker).Hijack()
			c.Write([]byte("HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello."))
			c.Close()
		},
		"/hijack-panic": func(w ResponseWriter, r *Request) {
			c, _, _ := w.(Hijacker).Hijack()
			c.Write([]byte("HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello."))
			c.Close()
			panic("intentional panic")
		},
	}

	// A stateLog is a log of states over the lifetime of a connection.
	type stateLog struct {
		active   net.Conn // The connection for which the log is recorded; set to the first connection seen in StateNew.
		got      []ConnState
		want     []ConnState
		complete chan<- struct{} // If non-nil, closed when either 'got' is equal to 'want', or 'got' is no longer a prefix of 'want'.
	}
	activeLog := make(chan *stateLog, 1)

	// wantLog invokes doRequests, then waits for the resulting connection to
	// either pass through the sequence of states in want or enter a state outside
	// of that sequence.
	wantLog := func(doRequests func(), want ...ConnState) {
		t.Helper()
		complete := make(chan struct{})
		activeLog <- &stateLog{want: want, complete: complete}

		doRequests()

		<-complete
		sl := <-activeLog
		if !slices.Equal(sl.got, sl.want) {
			t.Errorf("Request(s) produced unexpected state sequence.\nGot:  %v\nWant: %v", sl.got, sl.want)
		}
		// Don't return sl to activeLog: we don't expect any further states after
		// this point, and want to keep the ConnState callback blocked until the
		// next call to wantLog.
	}

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		handler[r.URL.Path](w, r)
	}), func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(io.Discard, "", 0)
		ts.Config.ConnState = func(c net.Conn, state ConnState) {
			if c == nil {
				t.Errorf("nil conn seen in state %s", state)
				return
			}
			sl := <-activeLog
			if sl.active == nil && state == StateNew {
				sl.active = c
			} else if sl.active != c {
				t.Errorf("unexpected conn in state %s", state)
				activeLog <- sl
				return
			}
			sl.got = append(sl.got, state)
			if sl.complete != nil && (len(sl.got) >= len(sl.want) || !slices.Equal(sl.got, sl.want[:len(sl.got)])) {
				close(sl.complete)
				sl.complete = nil
			}
			activeLog <- sl
		}
	}).ts
	defer func() {
		activeLog <- &stateLog{} // If the test failed, allow any remaining ConnState callbacks to complete.
		ts.Close()
	}()

	c := ts.Client()

	mustGet := func(url string, headers ...string) {
		t.Helper()
		req, err := NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		for len(headers) > 0 {
			req.Header.Add(headers[0], headers[1])
			headers = headers[2:]
		}
		res, err := c.Do(req)
		if err != nil {
			t.Errorf("Error fetching %s: %v", url, err)
			return
		}
		_, err = io.ReadAll(res.Body)
		defer res.Body.Close()
		if err != nil {
			t.Errorf("Error reading %s: %v", url, err)
		}
	}

	wantLog(func() {
		mustGet(ts.URL + "/")
		mustGet(ts.URL + "/close")
	}, StateNew, StateActive, StateIdle, StateActive, StateClosed)

	wantLog(func() {
		mustGet(ts.URL + "/")
		mustGet(ts.URL+"/", "Connection", "close")
	}, StateNew, StateActive, StateIdle, StateActive, StateClosed)

	wantLog(func() {
		mustGet(ts.URL + "/hijack")
	}, StateNew, StateActive, StateHijacked)

	wantLog(func() {
		mustGet(ts.URL + "/hijack-panic")
	}, StateNew, StateActive, StateHijacked)

	wantLog(func() {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}, StateNew, StateClosed)

	wantLog(func() {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, "BOGUS REQUEST\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		c.Read(make([]byte, 1)) // block until server hangs up on us
		c.Close()
	}, StateNew, StateActive, StateClosed)

	wantLog(func() {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: foo\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		res, err := ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			t.Fatal(err)
		}
		c.Close()
	}, StateNew, StateActive, StateIdle, StateClosed)
}

func TestServerKeepAlivesEnabledResultClose(t *testing.T) {
	run(t, testServerKeepAlivesEnabledResultClose, []testMode{http1Mode})
}
func testServerKeepAlivesEnabledResultClose(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
	}), func(ts *httptest.Server) {
		ts.Config.SetKeepAlivesEnabled(false)
	}).ts
	res, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if !res.Close {
		t.Errorf("Body.Close == false; want true")
	}
}

// golang.org/issue/7856
func TestServerEmptyBodyRace(t *testing.T) { run(t, testServerEmptyBodyRace) }
func testServerEmptyBodyRace(t *testing.T, mode testMode) {
	var n int32
	cst := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		atomic.AddInt32(&n, 1)
	}), optQuietLog)
	var wg sync.WaitGroup
	const reqs = 20
	for i := 0; i < reqs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := cst.c.Get(cst.ts.URL)
			if err != nil {
				// Try to deflake spurious "connection reset by peer" under load.
				// See golang.org/issue/22540.
				time.Sleep(10 * time.Millisecond)
				res, err = cst.c.Get(cst.ts.URL)
				if err != nil {
					t.Error(err)
					return
				}
			}
			defer res.Body.Close()
			_, err = io.Copy(io.Discard, res.Body)
			if err != nil {
				t.Error(err)
				return
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&n); got != reqs {
		t.Errorf("handler ran %d times; want %d", got, reqs)
	}
}

func TestServerConnStateNew(t *testing.T) {
	sawNew := false // if the test is buggy, we'll race on this variable.
	srv := &Server{
		ConnState: func(c net.Conn, state ConnState) {
			if state == StateNew {
				sawNew = true // testing that this write isn't racy
			}
		},
		Handler: HandlerFunc(func(w ResponseWriter, r *Request) {}), // irrelevant
	}
	srv.Serve(&oneConnListener{
		conn: &rwTestConn{
			Reader: strings.NewReader("GET / HTTP/1.1\r\nHost: foo\r\n\r\n"),
			Writer: io.Discard,
		},
	})
	if !sawNew { // testing that this read isn't racy
		t.Error("StateNew not seen")
	}
}

type closeWriteTestConn struct {
	rwTestConn
	didCloseWrite bool
}

func (c *closeWriteTestConn) CloseWrite() error {
	c.didCloseWrite = true
	return nil
}

func TestCloseWrite(t *testing.T) {
	SetRSTAvoidanceDelay(t, 1*time.Millisecond)

	var srv Server
	var testConn closeWriteTestConn
	c := ExportServerNewConn(&srv, &testConn)
	ExportCloseWriteAndWait(c)
	if !testConn.didCloseWrite {
		t.Error("didn't see CloseWrite call")
	}
}

// This verifies that a handler can Flush and then Hijack.
//
// A similar test crashed once during development, but it was only
// testing this tangentially and temporarily until another TODO was
// fixed.
//
// So add an explicit test for this.
func TestServerFlushAndHijack(t *testing.T) { run(t, testServerFlushAndHijack, []testMode{http1Mode}) }
func testServerFlushAndHijack(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, "Hello, ")
		w.(Flusher).Flush()
		conn, buf, _ := w.(Hijacker).Hijack()
		buf.WriteString("6\r\nworld!\r\n0\r\n\r\n")
		if err := buf.Flush(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})).ts
	res, err := Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	all, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if want := "Hello, world!"; string(all) != want {
		t.Errorf("Got %q; want %q", all, want)
	}
}

// golang.org/issue/8534 -- the Server shouldn't reuse a connection
// for keep-alive after it's seen any Write error (e.g. a timeout) on
// that net.Conn.
//
// To test, verify we don't timeout or see fewer unique client
// addresses (== unique connections) than requests.
func TestServerKeepAliveAfterWriteError(t *testing.T) {
	run(t, testServerKeepAliveAfterWriteError, []testMode{http1Mode})
}
func testServerKeepAliveAfterWriteError(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	const numReq = 3
	addrc := make(chan string, numReq)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		addrc <- r.Rem
```