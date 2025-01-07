Response:
Let's break down the thought process for analyzing this Go test code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code, which is part of the `net/http` package's test suite. The emphasis is on identifying the specific HTTP client/server functionalities being tested.

2. **Initial Scan for Key Words and Patterns:**  A quick scan reveals recurring patterns and keywords that hint at the functionalities being tested:
    * `Test...`:  Indicates test functions.
    * `cst := newClientServerTest(...)`:  Suggests the setup of a test HTTP server and client.
    * `HandlerFunc(...)`:  Points to the definition of HTTP request handlers.
    * `cst.c.Do(req)`, `cst.c.Get(...)`, `cst.c.Post(...)`:  These are standard HTTP client methods.
    * `w.WriteHeader(...)`, `w.Header().Set(...)`, `io.WriteString(w, ...)`: These are common HTTP response writer methods.
    * `res.Body`, `io.ReadAll(res.Body)`, `res.Body.Close()`: Operations on the HTTP response body.
    * Specific header names like "Content-Encoding", "Content-Length", "Trailer", "Connection", "Upgrade", "Transfer-Encoding", "Link".
    * Error handling: `if err != nil { t.Fatal(err) }`.
    * Concepts like "Keep-Alives", "Invalid Headers", "Panic", "Gzip", "Idle Connections", "Trailers", "Hijacking", "Reverse Proxy", "WebSocket", "Early Hints".

3. **Group Tests by Functionality:**  As I scan, I start grouping the tests based on the keywords and actions I see. This allows for a more organized summary.

    * **Basic Request Handling:**  Many tests involve making requests and checking responses, so this forms a foundational category.
    * **Header Manipulation:** Several tests deal with specific headers, both valid and invalid.
    * **Error Handling/Edge Cases:** Tests involving panics, bad responses, and unexpected behavior fall into this group.
    * **Advanced Features:** Concepts like Keep-Alives, Trailers, Hijacking, Reverse Proxy, WebSocket, and Early Hints represent more complex HTTP features.

4. **Analyze Individual Test Functions:** For each test function (or closely related groups of tests within a `run` block), I try to pinpoint its primary focus:

    * `TestTransportRejectsInvalidHeaders`: Clearly tests the client's ability to reject requests with invalid header keys or values *before* sending them to the server. The `dialedc` channel and the check for whether a dial happened are crucial here.
    * `TestInterruptWithPanic`:  Focuses on how the server handles panics during request handling. The logging of stack traces is a key aspect.
    * `TestH12_AutoGzipWithDumpResponse`: Examines the client's behavior when receiving a gzip-encoded response, especially in conjunction with `httputil.DumpResponse`. The "Uncompressed" flag is a significant indicator.
    * `TestCloseIdleConnections`:  Verifies that explicitly closing idle connections works as expected, leading to new connections for subsequent requests.
    * `TestNoSniffExpectRequestBody`: Tests the interaction of the "Expect: 100-continue" header with request body handling.
    * `TestServerUndeclaredTrailers`: Explores the server sending trailers even if they weren't declared in the initial headers.
    * `TestBadResponseAfterReadingBody`: Checks how the client handles unexpected data after the declared response body. The `Hijacker` interface is a key element.
    * `TestWriteHeader0`: Focuses on the server's handling of invalid `WriteHeader` calls with a status code of 0.
    * `TestWriteHeaderNoCodeCheck`, `TestWriteHeaderNoCodeCheck_h1hijack`, `testWriteHeaderAfterWrite`: These tests examine `WriteHeader` calls after the response has already started being written (or after hijacking).
    * `TestBidiStreamReverseProxy`:  Tests a reverse proxy setup and verifies bidirectional streaming using `io.Copy`.
    * `TestH12_WebSocketUpgrade`:  Specifically tests that WebSocket upgrade requests are always done over HTTP/1.1.
    * `TestIdentityTransferEncoding`: Checks the handling of the "Transfer-Encoding: identity" header.
    * `TestEarlyHintsRequest`: Examines the client and server interaction with HTTP Early Hints (103 status code). The `httptrace` package is used to observe the 1xx responses.

5. **Infer Go Feature Implementations:** Based on the tested functionalities, I can infer which Go `net/http` features are being exercised:
    * HTTP client (`http.Client`) and server (`net/http/httptest.Server`) basics.
    * Request and response header manipulation (`r.Header`, `w.Header()`).
    * Request and response body handling (`r.Body`, `w.Write()`, `io.Copy`).
    * HTTP status codes (`w.WriteHeader()`, `res.StatusCode`).
    * Keep-alive connections (`cst.tr.DisableKeepAlives`, `cst.tr.CloseIdleConnections()`).
    * Handling of invalid headers.
    * Server-side error handling and panic recovery.
    * Automatic decompression of gzip content.
    * HTTP trailers.
    * HTTP hijacking (`ResponseWriter.(Hijacker)`).
    * Reverse proxies (`httputil.NewSingleHostReverseProxy`).
    * WebSocket upgrades.
    * The "Expect: 100-continue" mechanism.
    * The "Transfer-Encoding: identity" header.
    * HTTP Early Hints (103 status code).
    * Client tracing (`httptrace`).

6. **Construct Code Examples:** For important functionalities, I create simplified Go code examples to illustrate their usage. This involves taking the essence of the test logic and presenting it in a standalone, understandable manner. I need to invent plausible inputs and outputs for these examples.

7. **Address Command-Line Arguments (If Applicable):**  In this specific snippet, there aren't direct command-line argument handling tests. If there were (e.g., using the `flag` package), I'd explain how those arguments are used within the tests.

8. **Identify Potential Pitfalls:**  Based on the tests, I consider common mistakes developers might make:
    * Incorrectly setting header values (e.g., including invalid characters).
    * Calling `WriteHeader` after already writing to the response body.
    * Misunderstanding how trailers work.

9. **Synthesize the Summary:** Finally, I synthesize the information gathered into a concise summary of the code's functionality. I group related tests together for clarity.

10. **Review and Refine:** I reread the summary and examples to ensure accuracy, clarity, and completeness, referencing the original code as needed. I make sure the language is consistent and easy to understand. I also double-check that I've answered all parts of the original request.
这是 Go 语言 `net/http` 包中 `clientserver_test.go` 文件的第二部分，主要包含以下功能的测试：

**归纳其功能：** 这部分代码主要集中在测试 `net/http` 包中客户端和服务端在处理各种复杂和边界情况下的行为，包括：

* **处理无效的 HTTP 头部：** 测试客户端是否能在发送请求前正确拒绝包含非法字符的头部。
* **处理服务端 Panic：** 测试服务端在处理请求时发生 panic 后的客户端行为，以及错误日志的记录。
* **处理自动 Gzip 解压与 DumpResponse：** 测试客户端接收到 Gzip 压缩的响应时，`httputil.DumpResponse` 的行为。
* **管理空闲连接：** 测试客户端的 `CloseIdleConnections` 方法是否能正确关闭空闲的 HTTP 连接。
* **处理 Expect 头部与请求体：** 测试在设置 `Expect: 100-continue` 头部时，客户端如何处理请求体。
* **处理服务端未声明的 Trailer 头部：** 测试服务端发送未在初始头部声明的 Trailer 头部时，客户端的解析行为。
* **处理读取响应体后服务端发送错误响应：** 测试客户端读取部分响应体后，服务端发送非法的后续数据时的处理情况。
* **处理 `WriteHeader(0)` 的情况：** 测试服务端调用 `WriteHeader(0)` 时的 panic 行为。
* **处理在写入响应后调用 `WriteHeader` 的情况：** 测试服务端在已经开始写入响应体后再次调用 `WriteHeader` 的行为，以及对 Hijack 连接的影响。
* **双向流的反向代理：** 测试 HTTP/2 下的反向代理是否能正确处理双向数据流。
* **WebSocket 升级请求：**  测试 WebSocket 升级请求是否始终使用 HTTP/1.1 协议。
* **处理 `Transfer-Encoding: identity` 头部：** 测试服务端显式设置 `Transfer-Encoding: identity` 时的请求和响应处理。
* **处理 Early Hints (103 状态码) 请求：** 测试客户端和服务端如何处理 Early Hints 响应。

**具体功能及代码示例：**

1. **处理无效的 HTTP 头部 (TestTransportRejectsInvalidHeaders):**

   这个测试验证了 `http.Transport` 在发送请求前会检查头部是否有效。如果头部键或值包含不允许的字符（如 `\n`, `\0`, 空格等），客户端应该直接返回错误，而不是尝试发送请求。

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       client := &http.Client{}
       req, _ := http.NewRequest("GET", "http://example.com", nil)
       req.Header.Set("Invalid\nKey", "value") // 设置包含换行符的非法头部键

       resp, err := client.Do(req)
       if err != nil {
           fmt.Println("Error:", err) // 预期会输出错误，因为头部无效
       } else {
           fmt.Println("Response:", resp.Status)
           resp.Body.Close()
       }
   }
   ```

   **假设的输入与输出：**

   * **输入：** 创建一个包含非法头部键 "Invalid\nKey" 的 HTTP 请求。
   * **输出：** 客户端会返回一个错误，例如 "net/http: invalid header field name \"Invalid\\nKey\""。由于请求在客户端就被拦截，不会实际发送到服务器。

2. **处理服务端 Panic (TestInterruptWithPanic 和 testInterruptWithPanic):**

   这个测试模拟了服务端在处理请求时发生 `panic` 的情况。它检查客户端是否能正常接收到部分响应（在 panic 发生前发送的部分），并检查服务端是否记录了错误日志（包括 panic 的堆栈信息）。

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       fmt.Fprint(w, "Hello, ")
       panic("Something went wrong!")
   }

   func main() {
       http.HandleFunc("/", handler)
       server := &http.Server{Addr: ":8080"}
       go server.ListenAndServe()

       client := &http.Client{}
       resp, err := client.Get("http://localhost:8080")
       if err != nil {
           fmt.Println("Client Error:", err) // 客户端可能会收到连接被中断的错误
       } else {
           fmt.Println("Response Status:", resp.Status)
           // 客户端可能只能读取部分 "Hello, "
           // ...
           resp.Body.Close()
       }
       // 服务端会记录 panic 的信息到错误日志
   }
   ```

   **假设的输入与输出：**

   * **输入：** 客户端向一个会触发 panic 的服务端发送请求。
   * **输出：** 客户端可能会收到类似 "connection reset by peer" 的错误，或者只能读取到 panic 前服务端发送的部分数据。服务端会在其错误日志中记录 panic 的类型和堆栈信息。

3. **处理自动 Gzip 解压与 DumpResponse (TestH12_AutoGzipWithDumpResponse):**

   这个测试验证了当服务端发送 `Content-Encoding: gzip` 的响应时，客户端会自动解压。同时，它测试了 `httputil.DumpResponse` 函数在处理这类响应时的行为，确保 `Uncompressed` 字段被正确设置，并且 dump 的响应中不包含 "Connection: close" 头部 (因为 HTTP/1.1 默认使用 Keep-Alive)。

   ```go
   package main

   import (
       "bytes"
       "compress/gzip"
       "fmt"
       "io"
       "net/http"
       "net/http/httputil"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       var b bytes.Buffer
       gz := gzip.NewWriter(&b)
       gz.Write([]byte("This is compressed data"))
       gz.Close()

       w.Header().Set("Content-Encoding", "gzip")
       w.Write(b.Bytes())
   }

   func main() {
       http.HandleFunc("/", handler)
       server := &http.Server{Addr: ":8080"}
       go server.ListenAndServe()

       client := &http.Client{}
       resp, err := client.Get("http://localhost:8080")
       if err != nil {
           fmt.Println("Error:", err)
           return
       }
       defer resp.Body.Close()

       dump, _ := httputil.DumpResponse(resp, true)
       fmt.Printf("Dumped Response:\n%s\n", dump)

       body, _ := io.ReadAll(resp.Body)
       fmt.Printf("Uncompressed Body: %s\n", string(body)) // 输出 "This is compressed data"
   }
   ```

   **假设的输入与输出：**

   * **输入：** 客户端请求一个发送 Gzip 压缩响应的服务端。
   * **输出：** `httputil.DumpResponse` 会输出包含 `Content-Encoding: gzip` 的原始响应头。客户端读取 `resp.Body` 时会自动解压，输出 "This is compressed data"。`resp.Uncompressed` 字段会被设置为 `true`。

4. **管理空闲连接 (TestCloseIdleConnections 和 testCloseIdleConnections):**

   这个测试验证了客户端的 `Transport.CloseIdleConnections()` 方法可以强制关闭所有空闲的 HTTP 连接。这可以通过比较连续两次请求的 `RemoteAddr` 来判断是否使用了同一个连接。

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       w.Header().Set("X-Addr", r.RemoteAddr)
       fmt.Fprint(w, "OK")
   }

   func main() {
       http.HandleFunc("/", handler)
       server := &http.Server{Addr: ":8080"}
       go server.ListenAndServe()

       client := &http.Client{}

       getResponse := func() string {
           resp, err := client.Get("http://localhost:8080")
           if err != nil {
               panic(err)
           }
           defer resp.Body.Close()
           return resp.Header.Get("X-Addr")
       }

       addr1 := getResponse()
       client.Transport.(*http.Transport).CloseIdleConnections()
       addr2 := getResponse()

       fmt.Println("Address 1:", addr1)
       fmt.Println("Address 2:", addr2)

       if addr1 == addr2 {
           fmt.Println("连接未关闭")
       } else {
           fmt.Println("连接已关闭")
       }
   }
   ```

   **假设的输入与输出：**

   * **输入：** 客户端首次请求服务端，然后调用 `CloseIdleConnections()`，再进行第二次请求。
   * **输出：** 第一次请求和第二次请求的 `X-Addr` 头部值（即 `r.RemoteAddr`）会不同，表明第二次请求使用了新的连接。

5. **处理服务端未声明的 Trailer 头部 (TestServerUndeclaredTrailers 和 testServerUndeclaredTrailers):**

   这个测试验证了服务端可以发送未在初始头部通过 `Trailer` 字段声明的 Trailer 头部。客户端在读取完响应体后，仍然可以访问这些 Trailer 头部。

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       w.Header().Set("Content-Type", "text/plain")
       w.Header().Set("Foo", "Bar")
       flusher, ok := w.(http.Flusher)
       if !ok {
           panic("expected http.ResponseWriter to be an http.Flusher")
       }
       flusher.Flush() // 发送初始头部和部分响应体

       w.Header().Set("Trailer:My-Trailer", "Value1") // 添加 Trailer 头部
       w.Header().Add("Trailer:My-Trailer", "Value2")
   }

   func main() {
       http.HandleFunc("/", handler)
       server := &http.Server{Addr: ":8080"}
       go server.ListenAndServe()

       client := &http.Client{}
       resp, err := client.Get("http://localhost:8080")
       if err != nil {
           fmt.Println("Error:", err)
           return
       }
       defer resp.Body.Close()

       // 读取响应体
       io.ReadAll(resp.Body)

       fmt.Println("Headers:", resp.Header)
       fmt.Println("Trailers:", resp.Trailer)
   }
   ```

   **假设的输入与输出：**

   * **输入：** 客户端请求一个发送未声明 Trailer 头部（例如 "Trailer:My-Trailer"）的服务端。
   * **输出：** `resp.Header` 会包含初始设置的头部，如 "Foo: Bar"。`resp.Trailer` 会包含服务端在响应结束后发送的 Trailer 头部，如 "My-Trailer: [Value1 Value2]"。

总而言之，这部分测试代码深入地检验了 `net/http` 包在各种边界场景下的健壮性和正确性，覆盖了 HTTP 协议的多个重要特性。

Prompt: 
```
这是路径为go/src/net/http/clientserver_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
	res, err := cst.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(res.Body); err != nil {
			t.Fatal(err)
		}
		if err := res.Body.Close(); err != nil {
			t.Fatal(err)
		}
	})()
	for {
		select {
		case <-didGC:
			return
		case <-time.After(1 * time.Millisecond):
			runtime.GC()
		}
	}
}

func TestTransportRejectsInvalidHeaders(t *testing.T) { run(t, testTransportRejectsInvalidHeaders) }
func testTransportRejectsInvalidHeaders(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "Handler saw headers: %q", r.Header)
	}), optQuietLog)
	cst.tr.DisableKeepAlives = true

	tests := []struct {
		key, val string
		ok       bool
	}{
		{"Foo", "capital-key", true}, // verify h2 allows capital keys
		{"Foo", "foo\x00bar", false}, // \x00 byte in value not allowed
		{"Foo", "two\nlines", false}, // \n byte in value not allowed
		{"bogus\nkey", "v", false},   // \n byte also not allowed in key
		{"A space", "v", false},      // spaces in keys not allowed
		{"имя", "v", false},          // key must be ascii
		{"name", "валю", true},       // value may be non-ascii
		{"", "v", false},             // key must be non-empty
		{"k", "", true},              // value may be empty
	}
	for _, tt := range tests {
		dialedc := make(chan bool, 1)
		cst.tr.Dial = func(netw, addr string) (net.Conn, error) {
			dialedc <- true
			return net.Dial(netw, addr)
		}
		req, _ := NewRequest("GET", cst.ts.URL, nil)
		req.Header[tt.key] = []string{tt.val}
		res, err := cst.c.Do(req)
		var body []byte
		if err == nil {
			body, _ = io.ReadAll(res.Body)
			res.Body.Close()
		}
		var dialed bool
		select {
		case <-dialedc:
			dialed = true
		default:
		}

		if !tt.ok && dialed {
			t.Errorf("For key %q, value %q, transport dialed. Expected local failure. Response was: (%v, %v)\nServer replied with: %s", tt.key, tt.val, res, err, body)
		} else if (err == nil) != tt.ok {
			t.Errorf("For key %q, value %q; got err = %v; want ok=%v", tt.key, tt.val, err, tt.ok)
		}
	}
}

func TestInterruptWithPanic(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		t.Run("boom", func(t *testing.T) { testInterruptWithPanic(t, mode, "boom") })
		t.Run("nil", func(t *testing.T) { t.Setenv("GODEBUG", "panicnil=1"); testInterruptWithPanic(t, mode, nil) })
		t.Run("ErrAbortHandler", func(t *testing.T) { testInterruptWithPanic(t, mode, ErrAbortHandler) })
	}, testNotParallel)
}
func testInterruptWithPanic(t *testing.T, mode testMode, panicValue any) {
	const msg = "hello"

	testDone := make(chan struct{})
	defer close(testDone)

	var errorLog lockedBytesBuffer
	gotHeaders := make(chan bool, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, msg)
		w.(Flusher).Flush()

		select {
		case <-gotHeaders:
		case <-testDone:
		}
		panic(panicValue)
	}), func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(&errorLog, "", 0)
	})
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	gotHeaders <- true
	defer res.Body.Close()
	slurp, err := io.ReadAll(res.Body)
	if string(slurp) != msg {
		t.Errorf("client read %q; want %q", slurp, msg)
	}
	if err == nil {
		t.Errorf("client read all successfully; want some error")
	}
	logOutput := func() string {
		errorLog.Lock()
		defer errorLog.Unlock()
		return errorLog.String()
	}
	wantStackLogged := panicValue != nil && panicValue != ErrAbortHandler

	waitCondition(t, 10*time.Millisecond, func(d time.Duration) bool {
		gotLog := logOutput()
		if !wantStackLogged {
			if gotLog == "" {
				return true
			}
			t.Fatalf("want no log output; got: %s", gotLog)
		}
		if gotLog == "" {
			if d > 0 {
				t.Logf("wanted a stack trace logged; got nothing after %v", d)
			}
			return false
		}
		if !strings.Contains(gotLog, "created by ") && strings.Count(gotLog, "\n") < 6 {
			if d > 0 {
				t.Logf("output doesn't look like a panic stack trace after %v. Got: %s", d, gotLog)
			}
			return false
		}
		return true
	})
}

type lockedBytesBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *lockedBytesBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}

// Issue 15366
func TestH12_AutoGzipWithDumpResponse(t *testing.T) {
	h12Compare{
		Handler: func(w ResponseWriter, r *Request) {
			h := w.Header()
			h.Set("Content-Encoding", "gzip")
			h.Set("Content-Length", "23")
			io.WriteString(w, "\x1f\x8b\b\x00\x00\x00\x00\x00\x00\x00s\xf3\xf7\a\x00\xab'\xd4\x1a\x03\x00\x00\x00")
		},
		EarlyCheckResponse: func(proto string, res *Response) {
			if !res.Uncompressed {
				t.Errorf("%s: expected Uncompressed to be set", proto)
			}
			dump, err := httputil.DumpResponse(res, true)
			if err != nil {
				t.Errorf("%s: DumpResponse: %v", proto, err)
				return
			}
			if strings.Contains(string(dump), "Connection: close") {
				t.Errorf("%s: should not see \"Connection: close\" in dump; got:\n%s", proto, dump)
			}
			if !strings.Contains(string(dump), "FOO") {
				t.Errorf("%s: should see \"FOO\" in response; got:\n%s", proto, dump)
			}
		},
	}.run(t)
}

// Issue 14607
func TestCloseIdleConnections(t *testing.T) { run(t, testCloseIdleConnections) }
func testCloseIdleConnections(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Addr", r.RemoteAddr)
	}))
	get := func() string {
		res, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		v := res.Header.Get("X-Addr")
		if v == "" {
			t.Fatal("didn't get X-Addr")
		}
		return v
	}
	a1 := get()
	cst.tr.CloseIdleConnections()
	a2 := get()
	if a1 == a2 {
		t.Errorf("didn't close connection")
	}
}

type noteCloseConn struct {
	net.Conn
	closeFunc func()
}

func (x noteCloseConn) Close() error {
	x.closeFunc()
	return x.Conn.Close()
}

type testErrorReader struct{ t *testing.T }

func (r testErrorReader) Read(p []byte) (n int, err error) {
	r.t.Error("unexpected Read call")
	return 0, io.EOF
}

func TestNoSniffExpectRequestBody(t *testing.T) { run(t, testNoSniffExpectRequestBody) }
func testNoSniffExpectRequestBody(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusUnauthorized)
	}))

	// Set ExpectContinueTimeout non-zero so RoundTrip won't try to write it.
	cst.tr.ExpectContinueTimeout = 10 * time.Second

	req, err := NewRequest("POST", cst.ts.URL, testErrorReader{t})
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 0 // so transport is tempted to sniff it
	req.Header.Set("Expect", "100-continue")
	res, err := cst.tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != StatusUnauthorized {
		t.Errorf("status code = %v; want %v", res.StatusCode, StatusUnauthorized)
	}
}

func TestServerUndeclaredTrailers(t *testing.T) { run(t, testServerUndeclaredTrailers) }
func testServerUndeclaredTrailers(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Foo", "Bar")
		w.Header().Set("Trailer:Foo", "Baz")
		w.(Flusher).Flush()
		w.Header().Add("Trailer:Foo", "Baz2")
		w.Header().Set("Trailer:Bar", "Quux")
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	delete(res.Header, "Date")
	delete(res.Header, "Content-Type")

	if want := (Header{"Foo": {"Bar"}}); !reflect.DeepEqual(res.Header, want) {
		t.Errorf("Header = %#v; want %#v", res.Header, want)
	}
	if want := (Header{"Foo": {"Baz", "Baz2"}, "Bar": {"Quux"}}); !reflect.DeepEqual(res.Trailer, want) {
		t.Errorf("Trailer = %#v; want %#v", res.Trailer, want)
	}
}

func TestBadResponseAfterReadingBody(t *testing.T) {
	run(t, testBadResponseAfterReadingBody, []testMode{http1Mode})
}
func testBadResponseAfterReadingBody(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintln(c, "some bogus crap")
	}))

	closes := 0
	res, err := cst.c.Post(cst.ts.URL, "text/plain", countCloseReader{&closes, strings.NewReader("hello")})
	if err == nil {
		res.Body.Close()
		t.Fatal("expected an error to be returned from Post")
	}
	if closes != 1 {
		t.Errorf("closes = %d; want 1", closes)
	}
}

func TestWriteHeader0(t *testing.T) { run(t, testWriteHeader0) }
func testWriteHeader0(t *testing.T, mode testMode) {
	gotpanic := make(chan bool, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		defer close(gotpanic)
		defer func() {
			if e := recover(); e != nil {
				got := fmt.Sprintf("%T, %v", e, e)
				want := "string, invalid WriteHeader code 0"
				if got != want {
					t.Errorf("unexpected panic value:\n got: %v\nwant: %v\n", got, want)
				}
				gotpanic <- true

				// Set an explicit 503. This also tests that the WriteHeader call panics
				// before it recorded that an explicit value was set and that bogus
				// value wasn't stuck.
				w.WriteHeader(503)
			}
		}()
		w.WriteHeader(0)
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 503 {
		t.Errorf("Response: %v %q; want 503", res.StatusCode, res.Status)
	}
	if !<-gotpanic {
		t.Error("expected panic in handler")
	}
}

// Issue 23010: don't be super strict checking WriteHeader's code if
// it's not even valid to call WriteHeader then anyway.
func TestWriteHeaderNoCodeCheck(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testWriteHeaderAfterWrite(t, mode, false)
	})
}
func TestWriteHeaderNoCodeCheck_h1hijack(t *testing.T) {
	testWriteHeaderAfterWrite(t, http1Mode, true)
}
func testWriteHeaderAfterWrite(t *testing.T, mode testMode, hijack bool) {
	var errorLog lockedBytesBuffer
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if hijack {
			conn, _, _ := w.(Hijacker).Hijack()
			defer conn.Close()
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nfoo"))
			w.WriteHeader(0) // verify this doesn't panic if there's already output; Issue 23010
			conn.Write([]byte("bar"))
			return
		}
		io.WriteString(w, "foo")
		w.(Flusher).Flush()
		w.WriteHeader(0) // verify this doesn't panic if there's already output; Issue 23010
		io.WriteString(w, "bar")
	}), func(ts *httptest.Server) {
		ts.Config.ErrorLog = log.New(&errorLog, "", 0)
	})
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "foobar"; got != want {
		t.Errorf("got = %q; want %q", got, want)
	}

	// Also check the stderr output:
	if mode == http2Mode {
		// TODO: also emit this log message for HTTP/2?
		// We historically haven't, so don't check.
		return
	}
	gotLog := strings.TrimSpace(errorLog.String())
	wantLog := "http: superfluous response.WriteHeader call from net/http_test.testWriteHeaderAfterWrite.func1 (clientserver_test.go:"
	if hijack {
		wantLog = "http: response.WriteHeader on hijacked connection from net/http_test.testWriteHeaderAfterWrite.func1 (clientserver_test.go:"
	}
	if !strings.HasPrefix(gotLog, wantLog) {
		t.Errorf("stderr output = %q; want %q", gotLog, wantLog)
	}
}

func TestBidiStreamReverseProxy(t *testing.T) {
	run(t, testBidiStreamReverseProxy, []testMode{http2Mode})
}
func testBidiStreamReverseProxy(t *testing.T, mode testMode) {
	backend := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if _, err := io.Copy(w, r.Body); err != nil {
			log.Printf("bidi backend copy: %v", err)
		}
	}))

	backURL, err := url.Parse(backend.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(backURL)
	rp.Transport = backend.tr
	proxy := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		rp.ServeHTTP(w, r)
	}))

	bodyRes := make(chan any, 1) // error or hash.Hash
	pr, pw := io.Pipe()
	req, _ := NewRequest("PUT", proxy.ts.URL, pr)
	const size = 4 << 20
	go func() {
		h := sha1.New()
		_, err := io.CopyN(io.MultiWriter(h, pw), rand.Reader, size)
		go pw.Close()
		if err != nil {
			t.Errorf("body copy: %v", err)
			bodyRes <- err
		} else {
			bodyRes <- h
		}
	}()
	res, err := backend.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	hgot := sha1.New()
	n, err := io.Copy(hgot, res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if n != size {
		t.Fatalf("got %d bytes; want %d", n, size)
	}
	select {
	case v := <-bodyRes:
		switch v := v.(type) {
		default:
			t.Fatalf("body copy: %v", err)
		case hash.Hash:
			if !bytes.Equal(v.Sum(nil), hgot.Sum(nil)) {
				t.Errorf("written bytes didn't match received bytes")
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}

}

// Always use HTTP/1.1 for WebSocket upgrades.
func TestH12_WebSocketUpgrade(t *testing.T) {
	h12Compare{
		Handler: func(w ResponseWriter, r *Request) {
			h := w.Header()
			h.Set("Foo", "bar")
		},
		ReqFunc: func(c *Client, url string) (*Response, error) {
			req, _ := NewRequest("GET", url, nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "WebSocket")
			return c.Do(req)
		},
		EarlyCheckResponse: func(proto string, res *Response) {
			if res.Proto != "HTTP/1.1" {
				t.Errorf("%s: expected HTTP/1.1, got %q", proto, res.Proto)
			}
			res.Proto = "HTTP/IGNORE" // skip later checks that Proto must be 1.1 vs 2.0
		},
	}.run(t)
}

func TestIdentityTransferEncoding(t *testing.T) { run(t, testIdentityTransferEncoding) }
func testIdentityTransferEncoding(t *testing.T, mode testMode) {
	const body = "body"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		gotBody, _ := io.ReadAll(r.Body)
		if got, want := string(gotBody), body; got != want {
			t.Errorf("got request body = %q; want %q", got, want)
		}
		w.Header().Set("Transfer-Encoding", "identity")
		w.WriteHeader(StatusOK)
		w.(Flusher).Flush()
		io.WriteString(w, body)
	}))
	req, _ := NewRequest("GET", cst.ts.URL, strings.NewReader(body))
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	gotBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(gotBody), body; got != want {
		t.Errorf("got response body = %q; want %q", got, want)
	}
}

func TestEarlyHintsRequest(t *testing.T) { run(t, testEarlyHintsRequest) }
func testEarlyHintsRequest(t *testing.T, mode testMode) {
	var wg sync.WaitGroup
	wg.Add(1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		h := w.Header()

		h.Add("Content-Length", "123") // must be ignored
		h.Add("Link", "</style.css>; rel=preload; as=style")
		h.Add("Link", "</script.js>; rel=preload; as=script")
		w.WriteHeader(StatusEarlyHints)

		wg.Wait()

		h.Add("Link", "</foo.js>; rel=preload; as=script")
		w.WriteHeader(StatusEarlyHints)

		w.Write([]byte("Hello"))
	}))

	checkLinkHeaders := func(t *testing.T, expected, got []string) {
		t.Helper()

		if len(expected) != len(got) {
			t.Errorf("got %d expected %d", len(got), len(expected))
		}

		for i := range expected {
			if expected[i] != got[i] {
				t.Errorf("got %q expected %q", got[i], expected[i])
			}
		}
	}

	checkExcludedHeaders := func(t *testing.T, header textproto.MIMEHeader) {
		t.Helper()

		for _, h := range []string{"Content-Length", "Transfer-Encoding"} {
			if v, ok := header[h]; ok {
				t.Errorf("%s is %q; must not be sent", h, v)
			}
		}
	}

	var respCounter uint8
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			switch respCounter {
			case 0:
				checkLinkHeaders(t, []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"}, header["Link"])
				checkExcludedHeaders(t, header)

				wg.Done()
			case 1:
				checkLinkHeaders(t, []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script", "</foo.js>; rel=preload; as=script"}, header["Link"])
				checkExcludedHeaders(t, header)

			default:
				t.Error("Unexpected 1xx response")
			}

			respCounter++

			return nil
		},
	}
	req, _ := NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", cst.ts.URL, nil)

	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	checkLinkHeaders(t, []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script", "</foo.js>; rel=preload; as=script"}, res.Header["Link"])
	if cl := res.Header.Get("Content-Length"); cl != "123" {
		t.Errorf("Content-Length is %q; want 123", cl)
	}

	body, _ := io.ReadAll(res.Body)
	if string(body) != "Hello" {
		t.Errorf("Read body %q; want Hello", body)
	}
}

"""




```