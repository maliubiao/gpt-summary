Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the given Go code, which is a part of `serve_test.go` in the `net/http` package. It also asks for a summary as part 5 of 7. This means the focus is on what aspects of the HTTP server's behavior are being tested.

2. **Initial Skim and Keyword Spotting:** Quickly read through the code, looking for familiar Go testing patterns and HTTP-related keywords. Keywords like `Test...`, `run(t, ...)`, `httptest.Server`, `HandlerFunc`, `ResponseWriter`, `Request`, `Header`, `io.WriteString`, `net.Dial`, `bufio.NewScanner`, `Serve`, `Expect`, `Content-Length`, `Transfer-Encoding`, `Host`, `Context`, `CloseNotify`, `Shutdown`, etc., immediately stand out.

3. **Isolate Individual Test Functions:** Notice the distinct test functions like `TestTimeoutWriteNotHang`, `TestNoContentLengthIfTransferEncoding`, `TestTolerateCRLFBeforeRequestLine`, and so on. Each `Test...` function likely focuses on a specific aspect of the HTTP server's functionality.

4. **Analyze Each Test Function:**  For each test function, try to determine its purpose:

    * **`TestTimeoutWriteNotHang`:**  This test clearly deals with write timeouts. It sets a `WriteTimeout` on the server and then sends multiple requests, checking if the server handles the timeout correctly by not hanging. The `Flusher` interface is used, indicating this test is likely related to streaming responses.

    * **`TestNoContentLengthIfTransferEncoding`:** The name itself is very descriptive. The test sets a `Transfer-Encoding` header and verifies that the server *doesn't* automatically add `Content-Length` or `Content-Type`. This confirms correct handling of chunked transfer encoding.

    * **`TestTolerateCRLFBeforeRequestLine`:** This test sends a malformed request with extra CRLFs before the actual request line. It checks if the server gracefully handles this instead of failing.

    * **`TestIssue13893_Expect100`:**  The name points to a specific issue. The test sends an `Expect: 100-continue` header and verifies that the server doesn't filter it out.

    * **`TestIssue11549_Expect100`:** Similar to the previous one, but this one sends multiple requests including one with `Expect: 100-continue` and checks that the server responds with `Connection: close` after handling the initial request.

    * **`TestHandlerFinishSkipBigContentLengthRead`:** This test sends a request with a very large `Content-Length` but the handler finishes without reading the entire body. It verifies the server implicitly tries to read from the body after the handler returns.

    * **`TestHandlerSetsBodyNil`:** This test sets `r.Body = nil` in the handler and verifies that connection reuse still works, suggesting the server handles this case correctly.

    * **`TestServerValidatesHostHeader`:** This test has a comprehensive set of test cases for different `Host` header values (and lack thereof) with various HTTP versions, checking for expected status codes (400, 505, 200). This focuses on host header validation.

    * **`TestServerHandlersCanHandleH2PRI`:** This tests the server's ability to handle the HTTP/2 preface (`PRI * HTTP/2.0`).

    * **`TestServerValidatesHeaders`:**  This test validates the correctness of various HTTP header values, checking for errors like invalid characters, too large headers, etc.

    * **`TestServerRequestContextCancel_ServeHTTPDone`:** This test checks if the request context is correctly canceled *after* the `ServeHTTP` method has finished.

    * **`TestServerRequestContextCancel_ConnClose`:** This tests if the request context is canceled when the client closes the connection prematurely.

    * **`TestServerContext_ServerContextKey`:**  This checks if the `ServerContextKey` is correctly set in the request's context.

    * **`TestServerContext_LocalAddrContextKey`:** This checks if the `LocalAddrContextKey` is correctly set in the request's context.

    * **`TestHandlerSetTransferEncodingChunked`:** Verifies that setting `Transfer-Encoding: chunked` in the handler works correctly.

    * **`TestHandlerSetTransferEncodingGzip`:** Checks that setting `Transfer-Encoding: gzip` also implies `chunked` encoding.

    * **Benchmark Functions:**  The `Benchmark...` functions are for performance testing of different scenarios.

    * **`TestConcurrentServerServe`:** Checks for race conditions when calling `Serve` concurrently on different listeners.

    * **`TestServerIdleTimeout`:** Tests the server's idle timeout functionality.

    * **`TestServerSetKeepAlivesEnabledClosesConns`:** Verifies that disabling keep-alives closes existing idle connections.

    * **`TestServerShutdown`:** Tests the graceful shutdown functionality of the server.

5. **Group Functionalities:**  Based on the analysis of individual tests, group them into broader categories:

    * **Timeout Handling:** (`TestTimeoutWriteNotHang`, `TestServerIdleTimeout`)
    * **Header Handling:** (`TestNoContentLengthIfTransferEncoding`, `TestServerValidatesHostHeader`, `TestServerValidatesHeaders`, `TestHandlerSetTransferEncodingChunked`, `TestHandlerSetTransferEncodingGzip`)
    * **Request Parsing and Handling:** (`TestTolerateCRLFBeforeRequestLine`, `TestIssue13893_Expect100`, `TestIssue11549_Expect100`, `TestHandlerFinishSkipBigContentLengthRead`, `TestHandlerSetsBodyNil`, `TestServerHandlersCanHandleH2PRI`)
    * **Request Context:** (`TestServerRequestContextCancel_ServeHTTPDone`, `TestServerRequestContextCancel_ConnClose`, `TestServerContext_ServerContextKey`, `TestServerContext_LocalAddrContextKey`)
    * **Connection Management:** (`TestServerSetKeepAlivesEnabledClosesConns`)
    * **Server Lifecycle:** (`TestServerShutdown`)
    * **Performance:** (Benchmark functions)
    * **Concurrency:** (`TestConcurrentServerServe`)
    * **CloseNotifier:** (`BenchmarkCloseNotifier`)

6. **Synthesize the Summary (for Part 5):** Based on the groupings, write a concise summary of the functionality covered in the code snippet. Emphasize the key areas of HTTP server behavior being tested.

7. **Provide Code Examples (as requested):** Choose a few representative tests and explain the core Go language features and HTTP concepts they demonstrate. Include hypothetical inputs and outputs if relevant.

8. **Address Potential Pitfalls:**  Think about common mistakes users might make related to the tested features and provide examples.

9. **Review and Refine:**  Read through the entire explanation to ensure clarity, accuracy, and completeness. Make sure the language is accessible and addresses all aspects of the original request. Pay attention to the "part 5 of 7" instruction, ensuring the summary is appropriate for a mid-section.
这是 `go/src/net/http/serve_test.go` 文件的一部分，它主要包含了一系列针对 Go 语言 `net/http` 包中 **服务器 (Server)** 功能的单元测试和基准测试。

**功能归纳 (作为第 5 部分):**

这部分代码主要测试了 `net/http` 服务器在处理 HTTP 请求和响应过程中的以下关键特性：

* **超时处理:** 测试了服务器的写超时 ( `WriteTimeout`) 功能，确保在写入响应数据超时时能够正常断开连接，并且不会出现永久阻塞的情况。
* **Transfer-Encoding 处理:** 验证了当 Handler 显式设置了 `Transfer-Encoding` 头时，服务器不会自动添加 `Content-Length` 或 `Content-Type` 头，确保了 chunked 传输编码的正确性。
* **请求解析的健壮性:** 测试了服务器对请求行前的额外 CRLF 的容忍度，即使客户端发送了不完全符合规范的请求，服务器也能正确处理。
* **`Expect: 100-continue` 处理:** 验证了服务器不会过滤掉 `Expect` 请求头，并且在处理带有 `Expect: 100-continue` 的请求后能够正确处理后续请求，并在必要时发送 `Connection: close`。
* **Handler 完成后的行为:**  测试了当 Handler 处理完请求但请求 Body 未完全读取时，服务器会尝试隐式读取剩余的 Body 数据。
* **请求上下文 (Request Context):**
    * 验证了 Handler 可以设置 `r.Body = nil` 而不影响连接复用。
    * 测试了请求的上下文在 `ServeHTTP` 方法执行完毕后会被标记为完成 (Done)。
    * 测试了当客户端断开连接时，请求的上下文也会被取消 (Canceled)。
    * 验证了请求的上下文中包含了 `ServerContextKey` 和 `LocalAddrContextKey` 这两个特定的 key。
* **Header 验证:** 详细测试了服务器对 `Host` 请求头的验证规则，包括不同 HTTP 版本下的要求和非法字符的处理。同时也测试了服务器对其他请求头的合法性验证，例如是否存在非法字符、空格、是否过大等。
* **HTTP/2 `PRI` 方法处理:**  测试了服务器能够处理 HTTP/2 协商的 `PRI` 请求。
* **Transfer-Encoding 的设置:**  验证了 Handler 可以设置 `Transfer-Encoding: chunked` 和 `Transfer-Encoding: gzip`，并且服务器会正确处理。
* **性能测试 (Benchmarks):**  包含了多个基准测试，用于评估不同场景下服务器的性能，例如基本的请求处理、并行处理、有无 Keep-Alive 等。同时也包含了一些用于分析服务器和客户端性能的辅助基准测试。
* **CloseNotifier 接口:** 测试了 `CloseNotifier` 接口的功能，验证了当连接关闭时，Handler 可以收到通知。
* **并发 `Serve` 调用:** 测试了在不同的 Listener 上并发调用 `Serve` 方法时是否存在竞态条件。
* **空闲超时 (Idle Timeout):** 测试了服务器的空闲超时机制，确保空闲连接会被正确关闭。
* **禁用 Keep-Alive:** 测试了调用 `Server.SetKeepAlivesEnabled(false)` 是否会关闭当前已有的空闲连接。
* **优雅关闭 (Shutdown):** 测试了服务器的优雅关闭功能，确保在关闭过程中正在处理的请求能够完成，并且不再接受新的连接。

**Go 语言功能示例：**

以下代码示例演示了 `TestNoContentLengthIfTransferEncoding` 这个测试所涉及的 Go 语言功能：

```go
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testNoContentLengthExample(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "foo")
		io.WriteString(w, "<html>")
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+ts.Listener.Addr().String()+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	bs := bufio.NewScanner(conn)
	var got strings.Builder
	for bs.Scan() {
		if strings.TrimSpace(bs.Text()) == "" {
			break
		}
		got.WriteString(bs.Text())
		got.WriteByte('\n')
	}
	if err := bs.Err(); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(got.String(), "Content-Length") {
		t.Errorf("Unexpected Content-Length in response headers: %s", got.String())
	}
	if strings.Contains(got.String(), "Content-Type") {
		t.Errorf("Unexpected Content-Type in response headers: %s", got.String())
	}
}

func main() {
	testing.Main(func(pattern, fn string) (bool, error) {
		if pattern == "TestNoContentLengthExample" {
			test := testing.T{}
			testNoContentLengthExample(&test)
			return !test.Failed(), nil
		}
		return false, nil
	}, []testing.InternalTest{
		{Name: "TestNoContentLengthExample", F: func(t *testing.T) { testNoContentLengthExample(t) }},
	}, []testing.InternalBenchmark{})
}
```

**假设的输入与输出：**

在这个例子中，假设客户端发送一个简单的 GET 请求到测试服务器。

**输入:**

```
GET / HTTP/1.1
Host: <服务器地址>
```

**输出:** (服务器的响应头)

```
HTTP/1.1 200 OK
Transfer-Encoding: foo
Date: ...
```

**注意：** 输出中不包含 `Content-Length` 或 `Content-Type` 头。

**命令行参数处理：**

这段代码主要是单元测试和基准测试，通常不直接涉及命令行参数的处理。但是，Go 的测试框架 `go test` 提供了丰富的命令行参数，例如：

* `-v`:  显示更详细的测试输出。
* `-run <正则表达式>`:  只运行匹配正则表达式的测试用例。
* `-bench <正则表达式>`:  只运行匹配正则表达式的基准测试。
* `-benchtime <时间或次数>`:  指定基准测试的运行时间或迭代次数。
* `-cpuprofile <文件>`:  将 CPU 性能分析结果写入指定文件。
* `-memprofile <文件>`:  将内存性能分析结果写入指定文件。

例如，要运行 `TestNoContentLengthIfTransferEncoding` 这个测试用例，可以使用以下命令：

```bash
go test -v -run TestNoContentLengthIfTransferEncoding ./serve_test.go
```

**使用者易犯错的点：**

* **忘记设置 `Transfer-Encoding` 时假设服务器会自动处理 chunked 编码。**  如果 Handler 没有设置 `Transfer-Encoding` 并且响应体大小未知，服务器通常会尝试设置 `Content-Length`，如果无法确定则可能关闭连接。
* **在设置了 `Transfer-Encoding` 的同时又设置了 `Content-Length`。**  这会导致语义冲突，服务器会忽略 `Content-Length`。
* **对 `Expect: 100-continue` 的理解不足。**  客户端发送此头部表示希望在发送请求体之前得到服务器的确认。服务器可以选择立即拒绝，或者返回 100 Continue 状态码允许客户端发送请求体。错误地处理此头部可能导致客户端请求失败或性能问题。
* **依赖服务器自动处理所有 Header。**  例如，认为只要返回数据，`Content-Type` 就会自动设置。实际上，服务器有一定的默认行为（例如基于内容前几个字节的 "嗅探"），但显式设置通常更可靠。
* **在高并发场景下不理解连接复用和 Keep-Alive 的行为。**  不正确的连接管理可能导致性能下降或资源浪费。

总而言之，这部分代码覆盖了 `net/http` 服务器的很多核心功能，并通过详尽的测试用例确保了其行为的正确性和健壮性。理解这些测试用例可以帮助开发者更好地理解和使用 Go 语言的 HTTP 服务器功能。

Prompt: 
```
这是路径为go/src/net/http/serve_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能

"""
oteAddr
		time.Sleep(500 * time.Millisecond)
		w.(Flusher).Flush()
	}), func(ts *httptest.Server) {
		ts.Config.WriteTimeout = 250 * time.Millisecond
	}).ts

	errc := make(chan error, numReq)
	go func() {
		defer close(errc)
		for i := 0; i < numReq; i++ {
			res, err := Get(ts.URL)
			if res != nil {
				res.Body.Close()
			}
			errc <- err
		}
	}()

	addrSeen := map[string]bool{}
	numOkay := 0
	for {
		select {
		case v := <-addrc:
			addrSeen[v] = true
		case err, ok := <-errc:
			if !ok {
				if len(addrSeen) != numReq {
					t.Errorf("saw %d unique client addresses; want %d", len(addrSeen), numReq)
				}
				if numOkay != 0 {
					t.Errorf("got %d successful client requests; want 0", numOkay)
				}
				return
			}
			if err == nil {
				numOkay++
			}
		}
	}
}

// Issue 9987: shouldn't add automatic Content-Length (or
// Content-Type) if a Transfer-Encoding was set by the handler.
func TestNoContentLengthIfTransferEncoding(t *testing.T) {
	run(t, testNoContentLengthIfTransferEncoding, []testMode{http1Mode})
}
func testNoContentLengthIfTransferEncoding(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Transfer-Encoding", "foo")
		io.WriteString(w, "<html>")
	})).ts
	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: foo\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	bs := bufio.NewScanner(c)
	var got strings.Builder
	for bs.Scan() {
		if strings.TrimSpace(bs.Text()) == "" {
			break
		}
		got.WriteString(bs.Text())
		got.WriteByte('\n')
	}
	if err := bs.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.String(), "Content-Length") {
		t.Errorf("Unexpected Content-Length in response headers: %s", got.String())
	}
	if strings.Contains(got.String(), "Content-Type") {
		t.Errorf("Unexpected Content-Type in response headers: %s", got.String())
	}
}

// tolerate extra CRLF(s) before Request-Line on subsequent requests on a conn
// Issue 10876.
func TestTolerateCRLFBeforeRequestLine(t *testing.T) {
	req := []byte("POST / HTTP/1.1\r\nHost: golang.org\r\nContent-Length: 3\r\n\r\nABC" +
		"\r\n\r\n" + // <-- this stuff is bogus, but we'll ignore it
		"GET / HTTP/1.1\r\nHost: golang.org\r\n\r\n")
	var buf bytes.Buffer
	conn := &rwTestConn{
		Reader: bytes.NewReader(req),
		Writer: &buf,
		closec: make(chan bool, 1),
	}
	ln := &oneConnListener{conn: conn}
	numReq := 0
	go Serve(ln, HandlerFunc(func(rw ResponseWriter, r *Request) {
		numReq++
	}))
	<-conn.closec
	if numReq != 2 {
		t.Errorf("num requests = %d; want 2", numReq)
		t.Logf("Res: %s", buf.Bytes())
	}
}

func TestIssue13893_Expect100(t *testing.T) {
	// test that the Server doesn't filter out Expect headers.
	req := reqBytes(`PUT /readbody HTTP/1.1
User-Agent: PycURL/7.22.0
Host: 127.0.0.1:9000
Accept: */*
Expect: 100-continue
Content-Length: 10

HelloWorld

`)
	var buf bytes.Buffer
	conn := &rwTestConn{
		Reader: bytes.NewReader(req),
		Writer: &buf,
		closec: make(chan bool, 1),
	}
	ln := &oneConnListener{conn: conn}
	go Serve(ln, HandlerFunc(func(w ResponseWriter, r *Request) {
		if _, ok := r.Header["Expect"]; !ok {
			t.Error("Expect header should not be filtered out")
		}
	}))
	<-conn.closec
}

func TestIssue11549_Expect100(t *testing.T) {
	req := reqBytes(`PUT /readbody HTTP/1.1
User-Agent: PycURL/7.22.0
Host: 127.0.0.1:9000
Accept: */*
Expect: 100-continue
Content-Length: 10

HelloWorldPUT /noreadbody HTTP/1.1
User-Agent: PycURL/7.22.0
Host: 127.0.0.1:9000
Accept: */*
Expect: 100-continue
Content-Length: 10

GET /should-be-ignored HTTP/1.1
Host: foo

`)
	var buf strings.Builder
	conn := &rwTestConn{
		Reader: bytes.NewReader(req),
		Writer: &buf,
		closec: make(chan bool, 1),
	}
	ln := &oneConnListener{conn: conn}
	numReq := 0
	go Serve(ln, HandlerFunc(func(w ResponseWriter, r *Request) {
		numReq++
		if r.URL.Path == "/readbody" {
			io.ReadAll(r.Body)
		}
		io.WriteString(w, "Hello world!")
	}))
	<-conn.closec
	if numReq != 2 {
		t.Errorf("num requests = %d; want 2", numReq)
	}
	if !strings.Contains(buf.String(), "Connection: close\r\n") {
		t.Errorf("expected 'Connection: close' in response; got: %s", buf.String())
	}
}

// If a Handler finishes and there's an unread request body,
// verify the server implicitly tries to do a read on it before replying.
func TestHandlerFinishSkipBigContentLengthRead(t *testing.T) {
	setParallel(t)
	conn := newTestConn()
	conn.readBuf.WriteString(
		"POST / HTTP/1.1\r\n" +
			"Host: test\r\n" +
			"Content-Length: 9999999999\r\n" +
			"\r\n" + strings.Repeat("a", 1<<20))

	ls := &oneConnListener{conn}
	var inHandlerLen int
	go Serve(ls, HandlerFunc(func(rw ResponseWriter, req *Request) {
		inHandlerLen = conn.readBuf.Len()
		rw.WriteHeader(404)
	}))
	<-conn.closec
	afterHandlerLen := conn.readBuf.Len()

	if afterHandlerLen != inHandlerLen {
		t.Errorf("unexpected implicit read. Read buffer went from %d -> %d", inHandlerLen, afterHandlerLen)
	}
}

func TestHandlerSetsBodyNil(t *testing.T) { run(t, testHandlerSetsBodyNil) }
func testHandlerSetsBodyNil(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		r.Body = nil
		fmt.Fprintf(w, "%v", r.RemoteAddr)
	}))
	get := func() string {
		res, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		slurp, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(slurp)
	}
	a, b := get(), get()
	if a != b {
		t.Errorf("Failed to reuse connections between requests: %v vs %v", a, b)
	}
}

// Test that we validate the Host header.
// Issue 11206 (invalid bytes in Host) and 13624 (Host present in HTTP/1.1)
func TestServerValidatesHostHeader(t *testing.T) {
	tests := []struct {
		proto string
		host  string
		want  int
	}{
		{"HTTP/0.9", "", 505},

		{"HTTP/1.1", "", 400},
		{"HTTP/1.1", "Host: \r\n", 200},
		{"HTTP/1.1", "Host: 1.2.3.4\r\n", 200},
		{"HTTP/1.1", "Host: foo.com\r\n", 200},
		{"HTTP/1.1", "Host: foo-bar_baz.com\r\n", 200},
		{"HTTP/1.1", "Host: foo.com:80\r\n", 200},
		{"HTTP/1.1", "Host: ::1\r\n", 200},
		{"HTTP/1.1", "Host: [::1]\r\n", 200}, // questionable without port, but accept it
		{"HTTP/1.1", "Host: [::1]:80\r\n", 200},
		{"HTTP/1.1", "Host: [::1%25en0]:80\r\n", 200},
		{"HTTP/1.1", "Host: 1.2.3.4\r\n", 200},
		{"HTTP/1.1", "Host: \x06\r\n", 400},
		{"HTTP/1.1", "Host: \xff\r\n", 400},
		{"HTTP/1.1", "Host: {\r\n", 400},
		{"HTTP/1.1", "Host: }\r\n", 400},
		{"HTTP/1.1", "Host: first\r\nHost: second\r\n", 400},

		// HTTP/1.0 can lack a host header, but if present
		// must play by the rules too:
		{"HTTP/1.0", "", 200},
		{"HTTP/1.0", "Host: first\r\nHost: second\r\n", 400},
		{"HTTP/1.0", "Host: \xff\r\n", 400},

		// Make an exception for HTTP upgrade requests:
		{"PRI * HTTP/2.0", "", 200},

		// Also an exception for CONNECT requests: (Issue 18215)
		{"CONNECT golang.org:443 HTTP/1.1", "", 200},

		// But not other HTTP/2 stuff:
		{"PRI / HTTP/2.0", "", 505},
		{"GET / HTTP/2.0", "", 505},
		{"GET / HTTP/3.0", "", 505},
	}
	for _, tt := range tests {
		conn := newTestConn()
		methodTarget := "GET / "
		if !strings.HasPrefix(tt.proto, "HTTP/") {
			methodTarget = ""
		}
		io.WriteString(&conn.readBuf, methodTarget+tt.proto+"\r\n"+tt.host+"\r\n")

		ln := &oneConnListener{conn}
		srv := Server{
			ErrorLog: quietLog,
			Handler:  HandlerFunc(func(ResponseWriter, *Request) {}),
		}
		go srv.Serve(ln)
		<-conn.closec
		res, err := ReadResponse(bufio.NewReader(&conn.writeBuf), nil)
		if err != nil {
			t.Errorf("For %s %q, ReadResponse: %v", tt.proto, tt.host, res)
			continue
		}
		if res.StatusCode != tt.want {
			t.Errorf("For %s %q, Status = %d; want %d", tt.proto, tt.host, res.StatusCode, tt.want)
		}
	}
}

func TestServerHandlersCanHandleH2PRI(t *testing.T) {
	run(t, testServerHandlersCanHandleH2PRI, []testMode{http1Mode})
}
func testServerHandlersCanHandleH2PRI(t *testing.T, mode testMode) {
	const upgradeResponse = "upgrade here"
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		conn, br, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if r.Method != "PRI" || r.RequestURI != "*" {
			t.Errorf("Got method/target %q %q; want PRI *", r.Method, r.RequestURI)
			return
		}
		if !r.Close {
			t.Errorf("Request.Close = true; want false")
		}
		const want = "SM\r\n\r\n"
		buf := make([]byte, len(want))
		n, err := io.ReadFull(br, buf)
		if err != nil || string(buf[:n]) != want {
			t.Errorf("Read = %v, %v (%q), want %q", n, err, buf[:n], want)
			return
		}
		io.WriteString(conn, upgradeResponse)
	})).ts

	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	slurp, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(slurp) != upgradeResponse {
		t.Errorf("Handler response = %q; want %q", slurp, upgradeResponse)
	}
}

// Test that we validate the valid bytes in HTTP/1 headers.
// Issue 11207.
func TestServerValidatesHeaders(t *testing.T) {
	setParallel(t)
	tests := []struct {
		header string
		want   int
	}{
		{"", 200},
		{"Foo: bar\r\n", 200},
		{"X-Foo: bar\r\n", 200},
		{"Foo: a space\r\n", 200},

		{"A space: foo\r\n", 400},                            // space in header
		{"foo\xffbar: foo\r\n", 400},                         // binary in header
		{"foo\x00bar: foo\r\n", 400},                         // binary in header
		{"Foo: " + strings.Repeat("x", 1<<21) + "\r\n", 431}, // header too large
		// Spaces between the header key and colon are not allowed.
		// See RFC 7230, Section 3.2.4.
		{"Foo : bar\r\n", 400},
		{"Foo\t: bar\r\n", 400},

		// Empty header keys are invalid.
		// See RFC 7230, Section 3.2.
		{": empty key\r\n", 400},

		// Requests with invalid Content-Length headers should be rejected
		// regardless of the presence of a Transfer-Encoding header.
		// Check out RFC 9110, Section 8.6 and RFC 9112, Section 6.3.3.
		{"Content-Length: notdigits\r\n", 400},
		{"Content-Length: notdigits\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400},

		{"foo: foo foo\r\n", 200},    // LWS space is okay
		{"foo: foo\tfoo\r\n", 200},   // LWS tab is okay
		{"foo: foo\x00foo\r\n", 400}, // CTL 0x00 in value is bad
		{"foo: foo\x7ffoo\r\n", 400}, // CTL 0x7f in value is bad
		{"foo: foo\xfffoo\r\n", 200}, // non-ASCII high octets in value are fine
	}
	for _, tt := range tests {
		conn := newTestConn()
		io.WriteString(&conn.readBuf, "GET / HTTP/1.1\r\nHost: foo\r\n"+tt.header+"\r\n")

		ln := &oneConnListener{conn}
		srv := Server{
			ErrorLog: quietLog,
			Handler:  HandlerFunc(func(ResponseWriter, *Request) {}),
		}
		go srv.Serve(ln)
		<-conn.closec
		res, err := ReadResponse(bufio.NewReader(&conn.writeBuf), nil)
		if err != nil {
			t.Errorf("For %q, ReadResponse: %v", tt.header, res)
			continue
		}
		if res.StatusCode != tt.want {
			t.Errorf("For %q, Status = %d; want %d", tt.header, res.StatusCode, tt.want)
		}
	}
}

func TestServerRequestContextCancel_ServeHTTPDone(t *testing.T) {
	run(t, testServerRequestContextCancel_ServeHTTPDone)
}
func testServerRequestContextCancel_ServeHTTPDone(t *testing.T, mode testMode) {
	ctxc := make(chan context.Context, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ctx := r.Context()
		select {
		case <-ctx.Done():
			t.Error("should not be Done in ServeHTTP")
		default:
		}
		ctxc <- ctx
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	ctx := <-ctxc
	select {
	case <-ctx.Done():
	default:
		t.Error("context should be done after ServeHTTP completes")
	}
}

// Tests that the Request.Context available to the Handler is canceled
// if the peer closes their TCP connection. This requires that the server
// is always blocked in a Read call so it notices the EOF from the client.
// See issues 15927 and 15224.
func TestServerRequestContextCancel_ConnClose(t *testing.T) {
	run(t, testServerRequestContextCancel_ConnClose, []testMode{http1Mode})
}
func testServerRequestContextCancel_ConnClose(t *testing.T, mode testMode) {
	inHandler := make(chan struct{})
	handlerDone := make(chan struct{})
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		close(inHandler)
		<-r.Context().Done()
		close(handlerDone)
	})).ts
	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: foo\r\n\r\n")
	<-inHandler
	c.Close() // this should trigger the context being done
	<-handlerDone
}

func TestServerContext_ServerContextKey(t *testing.T) {
	run(t, testServerContext_ServerContextKey)
}
func testServerContext_ServerContextKey(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ctx := r.Context()
		got := ctx.Value(ServerContextKey)
		if _, ok := got.(*Server); !ok {
			t.Errorf("context value = %T; want *http.Server", got)
		}
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestServerContext_LocalAddrContextKey(t *testing.T) {
	run(t, testServerContext_LocalAddrContextKey)
}
func testServerContext_LocalAddrContextKey(t *testing.T, mode testMode) {
	ch := make(chan any, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ch <- r.Context().Value(LocalAddrContextKey)
	}))
	if _, err := cst.c.Head(cst.ts.URL); err != nil {
		t.Fatal(err)
	}

	host := cst.ts.Listener.Addr().String()
	got := <-ch
	if addr, ok := got.(net.Addr); !ok {
		t.Errorf("local addr value = %T; want net.Addr", got)
	} else if fmt.Sprint(addr) != host {
		t.Errorf("local addr = %v; want %v", addr, host)
	}
}

// https://golang.org/issue/15960
func TestHandlerSetTransferEncodingChunked(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	ht := newHandlerTest(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Write([]byte("hello"))
	}))
	resp := ht.rawResponse("GET / HTTP/1.1\nHost: foo")
	const hdr = "Transfer-Encoding: chunked"
	if n := strings.Count(resp, hdr); n != 1 {
		t.Errorf("want 1 occurrence of %q in response, got %v\nresponse: %v", hdr, n, resp)
	}
}

// https://golang.org/issue/16063
func TestHandlerSetTransferEncodingGzip(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	ht := newHandlerTest(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Transfer-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("hello"))
		gz.Close()
	}))
	resp := ht.rawResponse("GET / HTTP/1.1\nHost: foo")
	for _, v := range []string{"gzip", "chunked"} {
		hdr := "Transfer-Encoding: " + v
		if n := strings.Count(resp, hdr); n != 1 {
			t.Errorf("want 1 occurrence of %q in response, got %v\nresponse: %v", hdr, n, resp)
		}
	}
}

func BenchmarkClientServer(b *testing.B) {
	run(b, benchmarkClientServer, []testMode{http1Mode, https1Mode, http2Mode})
}
func benchmarkClientServer(b *testing.B, mode testMode) {
	b.ReportAllocs()
	b.StopTimer()
	ts := newClientServerTest(b, mode, HandlerFunc(func(rw ResponseWriter, r *Request) {
		fmt.Fprintf(rw, "Hello world.\n")
	})).ts
	b.StartTimer()

	c := ts.Client()
	for i := 0; i < b.N; i++ {
		res, err := c.Get(ts.URL)
		if err != nil {
			b.Fatal("Get:", err)
		}
		all, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			b.Fatal("ReadAll:", err)
		}
		body := string(all)
		if body != "Hello world.\n" {
			b.Fatal("Got body:", body)
		}
	}

	b.StopTimer()
}

func BenchmarkClientServerParallel(b *testing.B) {
	for _, parallelism := range []int{4, 64} {
		b.Run(fmt.Sprint(parallelism), func(b *testing.B) {
			run(b, func(b *testing.B, mode testMode) {
				benchmarkClientServerParallel(b, parallelism, mode)
			}, []testMode{http1Mode, https1Mode, http2Mode})
		})
	}
}

func benchmarkClientServerParallel(b *testing.B, parallelism int, mode testMode) {
	b.ReportAllocs()
	ts := newClientServerTest(b, mode, HandlerFunc(func(rw ResponseWriter, r *Request) {
		fmt.Fprintf(rw, "Hello world.\n")
	})).ts
	b.ResetTimer()
	b.SetParallelism(parallelism)
	b.RunParallel(func(pb *testing.PB) {
		c := ts.Client()
		for pb.Next() {
			res, err := c.Get(ts.URL)
			if err != nil {
				b.Logf("Get: %v", err)
				continue
			}
			all, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				b.Logf("ReadAll: %v", err)
				continue
			}
			body := string(all)
			if body != "Hello world.\n" {
				panic("Got body: " + body)
			}
		}
	})
}

// A benchmark for profiling the server without the HTTP client code.
// The client code runs in a subprocess.
//
// For use like:
//
//	$ go test -c
//	$ ./http.test -test.run='^$' -test.bench='^BenchmarkServer$' -test.benchtime=15s -test.cpuprofile=http.prof
//	$ go tool pprof http.test http.prof
//	(pprof) web
func BenchmarkServer(b *testing.B) {
	b.ReportAllocs()
	// Child process mode;
	if url := os.Getenv("TEST_BENCH_SERVER_URL"); url != "" {
		n, err := strconv.Atoi(os.Getenv("TEST_BENCH_CLIENT_N"))
		if err != nil {
			panic(err)
		}
		for i := 0; i < n; i++ {
			res, err := Get(url)
			if err != nil {
				log.Panicf("Get: %v", err)
			}
			all, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				log.Panicf("ReadAll: %v", err)
			}
			body := string(all)
			if body != "Hello world.\n" {
				log.Panicf("Got body: %q", body)
			}
		}
		os.Exit(0)
		return
	}

	var res = []byte("Hello world.\n")
	b.StopTimer()
	ts := httptest.NewServer(HandlerFunc(func(rw ResponseWriter, r *Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write(res)
	}))
	defer ts.Close()
	b.StartTimer()

	cmd := testenv.Command(b, os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkServer$")
	cmd.Env = append([]string{
		fmt.Sprintf("TEST_BENCH_CLIENT_N=%d", b.N),
		fmt.Sprintf("TEST_BENCH_SERVER_URL=%s", ts.URL),
	}, os.Environ()...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		b.Errorf("Test failure: %v, with output: %s", err, out)
	}
}

// getNoBody wraps Get but closes any Response.Body before returning the response.
func getNoBody(urlStr string) (*Response, error) {
	res, err := Get(urlStr)
	if err != nil {
		return nil, err
	}
	res.Body.Close()
	return res, nil
}

// A benchmark for profiling the client without the HTTP server code.
// The server code runs in a subprocess.
func BenchmarkClient(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	defer afterTest(b)

	var data = []byte("Hello world.\n")
	if server := os.Getenv("TEST_BENCH_SERVER"); server != "" {
		// Server process mode.
		port := os.Getenv("TEST_BENCH_SERVER_PORT") // can be set by user
		if port == "" {
			port = "0"
		}
		ln, err := net.Listen("tcp", "localhost:"+port)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		fmt.Println(ln.Addr().String())
		HandleFunc("/", func(w ResponseWriter, r *Request) {
			r.ParseForm()
			if r.Form.Get("stop") != "" {
				os.Exit(0)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
		})
		var srv Server
		log.Fatal(srv.Serve(ln))
	}

	// Start server process.
	ctx, cancel := context.WithCancel(context.Background())
	cmd := testenv.CommandContext(b, ctx, os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkClient$")
	cmd.Env = append(cmd.Environ(), "TEST_BENCH_SERVER=yes")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		b.Fatalf("subprocess failed to start: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	// Wait for the server in the child process to respond and tell us
	// its listening address, once it's started listening:
	bs := bufio.NewScanner(stdout)
	if !bs.Scan() {
		b.Fatalf("failed to read listening URL from child: %v", bs.Err())
	}
	url := "http://" + strings.TrimSpace(bs.Text()) + "/"
	if _, err := getNoBody(url); err != nil {
		b.Fatalf("initial probe of child process failed: %v", err)
	}

	// Do b.N requests to the server.
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		res, err := Get(url)
		if err != nil {
			b.Fatalf("Get: %v", err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			b.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(body, data) {
			b.Fatalf("Got body: %q", body)
		}
	}
	b.StopTimer()

	// Instruct server process to stop.
	getNoBody(url + "?stop=yes")
	if err := <-done; err != nil {
		b.Fatalf("subprocess failed: %v", err)
	}
}

func BenchmarkServerFakeConnNoKeepAlive(b *testing.B) {
	b.ReportAllocs()
	req := reqBytes(`GET / HTTP/1.0
Host: golang.org
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.52 Safari/537.17
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
`)
	res := []byte("Hello world!\n")

	conn := newTestConn()
	handler := HandlerFunc(func(rw ResponseWriter, r *Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write(res)
	})
	ln := new(oneConnListener)
	for i := 0; i < b.N; i++ {
		conn.readBuf.Reset()
		conn.writeBuf.Reset()
		conn.readBuf.Write(req)
		ln.conn = conn
		Serve(ln, handler)
		<-conn.closec
	}
}

// repeatReader reads content count times, then EOFs.
type repeatReader struct {
	content []byte
	count   int
	off     int
}

func (r *repeatReader) Read(p []byte) (n int, err error) {
	if r.count <= 0 {
		return 0, io.EOF
	}
	n = copy(p, r.content[r.off:])
	r.off += n
	if r.off == len(r.content) {
		r.count--
		r.off = 0
	}
	return
}

func BenchmarkServerFakeConnWithKeepAlive(b *testing.B) {
	b.ReportAllocs()

	req := reqBytes(`GET / HTTP/1.1
Host: golang.org
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.52 Safari/537.17
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
`)
	res := []byte("Hello world!\n")

	conn := &rwTestConn{
		Reader: &repeatReader{content: req, count: b.N},
		Writer: io.Discard,
		closec: make(chan bool, 1),
	}
	handled := 0
	handler := HandlerFunc(func(rw ResponseWriter, r *Request) {
		handled++
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write(res)
	})
	ln := &oneConnListener{conn: conn}
	go Serve(ln, handler)
	<-conn.closec
	if b.N != handled {
		b.Errorf("b.N=%d but handled %d", b.N, handled)
	}
}

// same as above, but representing the most simple possible request
// and handler. Notably: the handler does not call rw.Header().
func BenchmarkServerFakeConnWithKeepAliveLite(b *testing.B) {
	b.ReportAllocs()

	req := reqBytes(`GET / HTTP/1.1
Host: golang.org
`)
	res := []byte("Hello world!\n")

	conn := &rwTestConn{
		Reader: &repeatReader{content: req, count: b.N},
		Writer: io.Discard,
		closec: make(chan bool, 1),
	}
	handled := 0
	handler := HandlerFunc(func(rw ResponseWriter, r *Request) {
		handled++
		rw.Write(res)
	})
	ln := &oneConnListener{conn: conn}
	go Serve(ln, handler)
	<-conn.closec
	if b.N != handled {
		b.Errorf("b.N=%d but handled %d", b.N, handled)
	}
}

const someResponse = "<html>some response</html>"

// A Response that's just no bigger than 2KB, the buffer-before-chunking threshold.
var response = bytes.Repeat([]byte(someResponse), 2<<10/len(someResponse))

// Both Content-Type and Content-Length set. Should be no buffering.
func BenchmarkServerHandlerTypeLen(b *testing.B) {
	benchmarkHandler(b, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(len(response)))
		w.Write(response)
	}))
}

// A Content-Type is set, but no length. No sniffing, but will count the Content-Length.
func BenchmarkServerHandlerNoLen(b *testing.B) {
	benchmarkHandler(b, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(response)
	}))
}

// A Content-Length is set, but the Content-Type will be sniffed.
func BenchmarkServerHandlerNoType(b *testing.B) {
	benchmarkHandler(b, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(response)))
		w.Write(response)
	}))
}

// Neither a Content-Type or Content-Length, so sniffed and counted.
func BenchmarkServerHandlerNoHeader(b *testing.B) {
	benchmarkHandler(b, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write(response)
	}))
}

func benchmarkHandler(b *testing.B, h Handler) {
	b.ReportAllocs()
	req := reqBytes(`GET / HTTP/1.1
Host: golang.org
`)
	conn := &rwTestConn{
		Reader: &repeatReader{content: req, count: b.N},
		Writer: io.Discard,
		closec: make(chan bool, 1),
	}
	handled := 0
	handler := HandlerFunc(func(rw ResponseWriter, r *Request) {
		handled++
		h.ServeHTTP(rw, r)
	})
	ln := &oneConnListener{conn: conn}
	go Serve(ln, handler)
	<-conn.closec
	if b.N != handled {
		b.Errorf("b.N=%d but handled %d", b.N, handled)
	}
}

func BenchmarkServerHijack(b *testing.B) {
	b.ReportAllocs()
	req := reqBytes(`GET / HTTP/1.1
Host: golang.org
`)
	h := HandlerFunc(func(w ResponseWriter, r *Request) {
		conn, _, err := w.(Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		conn.Close()
	})
	conn := &rwTestConn{
		Writer: io.Discard,
		closec: make(chan bool, 1),
	}
	ln := &oneConnListener{conn: conn}
	for i := 0; i < b.N; i++ {
		conn.Reader = bytes.NewReader(req)
		ln.conn = conn
		Serve(ln, h)
		<-conn.closec
	}
}

func BenchmarkCloseNotifier(b *testing.B) { run(b, benchmarkCloseNotifier, []testMode{http1Mode}) }
func benchmarkCloseNotifier(b *testing.B, mode testMode) {
	b.ReportAllocs()
	b.StopTimer()
	sawClose := make(chan bool)
	ts := newClientServerTest(b, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		<-rw.(CloseNotifier).CloseNotify()
		sawClose <- true
	})).ts
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			b.Fatalf("error dialing: %v", err)
		}
		_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nConnection: keep-alive\r\nHost: foo\r\n\r\n")
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
		<-sawClose
	}
	b.StopTimer()
}

// Verify this doesn't race (Issue 16505)
func TestConcurrentServerServe(t *testing.T) {
	setParallel(t)
	for i := 0; i < 100; i++ {
		ln1 := &oneConnListener{conn: nil}
		ln2 := &oneConnListener{conn: nil}
		srv := Server{}
		go func() { srv.Serve(ln1) }()
		go func() { srv.Serve(ln2) }()
	}
}

func TestServerIdleTimeout(t *testing.T) { run(t, testServerIdleTimeout, []testMode{http1Mode}) }
func testServerIdleTimeout(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	runTimeSensitiveTest(t, []time.Duration{
		10 * time.Millisecond,
		100 * time.Millisecond,
		1 * time.Second,
		10 * time.Second,
	}, func(t *testing.T, readHeaderTimeout time.Duration) error {
		cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, r.RemoteAddr)
		}), func(ts *httptest.Server) {
			ts.Config.ReadHeaderTimeout = readHeaderTimeout
			ts.Config.IdleTimeout = 2 * readHeaderTimeout
		})
		defer cst.close()
		ts := cst.ts
		t.Logf("ReadHeaderTimeout = %v", ts.Config.ReadHeaderTimeout)
		t.Logf("IdleTimeout = %v", ts.Config.IdleTimeout)
		c := ts.Client()

		get := func() (string, error) {
			res, err := c.Get(ts.URL)
			if err != nil {
				return "", err
			}
			defer res.Body.Close()
			slurp, err := io.ReadAll(res.Body)
			if err != nil {
				// If we're at this point the headers have definitely already been
				// read and the server is not idle, so neither timeout applies:
				// this should never fail.
				t.Fatal(err)
			}
			return string(slurp), nil
		}

		a1, err := get()
		if err != nil {
			return err
		}
		a2, err := get()
		if err != nil {
			return err
		}
		if a1 != a2 {
			return fmt.Errorf("did requests on different connections")
		}
		time.Sleep(ts.Config.IdleTimeout * 3 / 2)
		a3, err := get()
		if err != nil {
			return err
		}
		if a2 == a3 {
			return fmt.Errorf("request three unexpectedly on same connection")
		}

		// And test that ReadHeaderTimeout still works:
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: foo.com\r\n"))
		time.Sleep(ts.Config.ReadHeaderTimeout * 2)
		if _, err := io.CopyN(io.Discard, conn, 1); err == nil {
			return fmt.Errorf("copy byte succeeded; want err")
		}

		return nil
	})
}

func get(t *testing.T, c *Client, url string) string {
	res, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(slurp)
}

// Tests that calls to Server.SetKeepAlivesEnabled(false) closes any
// currently-open connections.
func TestServerSetKeepAlivesEnabledClosesConns(t *testing.T) {
	run(t, testServerSetKeepAlivesEnabledClosesConns, []testMode{http1Mode})
}
func testServerSetKeepAlivesEnabledClosesConns(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, r.RemoteAddr)
	})).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)

	get := func() string { return get(t, c, ts.URL) }

	a1, a2 := get(), get()
	if a1 == a2 {
		t.Logf("made two requests from a single conn %q (as expected)", a1)
	} else {
		t.Errorf("server reported requests from %q and %q; expected same connection", a1, a2)
	}

	// The two requests should have used the same connection,
	// and there should not have been a second connection that
	// was created by racing dial against reuse.
	// (The first get was completed when the second get started.)
	if conns := tr.IdleConnStrsForTesting(); len(conns) != 1 {
		t.Errorf("found %d idle conns (%q); want 1", len(conns), conns)
	}

	// SetKeepAlivesEnabled should discard idle conns.
	ts.Config.SetKeepAlivesEnabled(false)

	waitCondition(t, 10*time.Millisecond, func(d time.Duration) bool {
		if conns := tr.IdleConnStrsForTesting(); len(conns) > 0 {
			if d > 0 {
				t.Logf("idle conns %v after SetKeepAlivesEnabled called = %q; waiting for empty", d, conns)
			}
			return false
		}
		return true
	})

	// If we make a third request it should use a new connection, but in general
	// we have no way to verify that: the new connection could happen to reuse the
	// exact same ports from the previous connection.
}

func TestServerShutdown(t *testing.T) { run(t, testServerShutdown) }
func testServerShutdown(t *testing.T, mode testMode) {
	var cst *clientServerTest

	var once sync.Once
	statesRes := make(chan map[ConnState]int, 1)
	shutdownRes := make(chan error, 1)
	gotOnShutdown := make(chan struct{})
	handler := HandlerFunc(func(w ResponseWriter, r *Request) {
		first := false
		once.Do(func() {
			statesRes <- cst.ts.Config.ExportAllConnsByState()
			go func() {
				shutdownRes <- cst.ts.Config.Shutdown(context.Background())
			}()
			first = true
		})

		if first {
			// Shutdown is graceful, so it should not interrupt this in-flight response
			// but should reject new requests. (Since this request is still in flight,
			// the server's port should not be reused for another server yet.)
			<-gotOnShutdown
			// TODO(#59038): The HTTP/2 server empirically does not always reject new
			// requests. As a workaround, loop until we see a failure.
			for !t.Failed() {
				res, err := cst.c.Get(cst.ts.URL)
				if err != nil {
					break
				}
				out, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if mode == http2Mode {
					t.Logf("%v: unexpected success (%q). Listener should be closed before OnShutdown is called.", cst.ts.URL, out)
					t.Logf("Retrying to work around https://go.dev/issue/59038.")
					continue
				}
				t.Errorf("%v: unexpected success (%q). Listener should be closed before OnShutdown is called.", cst.ts.URL, out)
			}
		}

		io.WriteString(w, r.RemoteAddr)
	})

	cst = newClientServerTest(t, mode, handler, func(srv *httptest.Server) {
		srv.Config.RegisterOnShutdown(func() { close(gotOnShutdown) })
	})

	out := get(t, cst.c, cst.ts.URL) // calls t.Fail on failure
	t.Logf("%v: %q", cst.ts.URL, out)

	if err := <-shutdownRes; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	<-gotOnShutdown // Will hang if RegisterOnShu
"""




```