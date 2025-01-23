Response:
My goal is to analyze the provided Go code snippet and provide a comprehensive summary of its functionalities, along with illustrative examples. Here's a breakdown of the thinking process:

1. **Initial Scan for Keywords and Structure:** I first scanned the code for keywords like `test`, `serve`, `http`, `conn`, `listener`, `handler`, and import statements. This immediately suggests that the code is related to testing HTTP server functionality. The presence of `package http_test` confirms this. The numerous imports from the `net/http` package and related sub-packages like `httptest` and `httputil` reinforce this.

2. **Identify Core Types and Functions:** I then started to identify the core data structures and functions defined within the snippet.

    * **Connection-related types:** `dummyAddr`, `oneConnListener`, `noopConn`, `rwTestConn`, `testConn`. These clearly simulate different types of network connections for testing purposes. The names themselves are quite descriptive (e.g., `oneConnListener` suggests a listener that accepts only one connection).

    * **Request/Response Handling:**  The `reqBytes` function is a helper for constructing raw HTTP request bytes. The `handlerTest` struct and its `rawResponse` method are designed for testing handlers in isolation without a full server setup.

    * **Test Cases:** Functions starting with `Test...` like `TestConsumingBodyOnNextConn`, `TestHostHandlers`, `TestServeMuxHandler`, etc., are clearly individual test cases.

3. **Group Functionalities:**  Based on the identified types and functions, I started to group related functionalities:

    * **Simulating Network Connections:** The `dummyAddr`, `oneConnListener`, `noopConn`, `rwTestConn`, and `testConn` types are all about creating controlled environments for simulating network interactions in tests.

    * **Testing Handlers:** The `handlerTest` struct and `rawResponse` method provide a way to test the logic of individual `Handler` implementations without the overhead of a full HTTP server.

    * **Testing Server Behavior:** The various `Test...` functions are focused on verifying different aspects of the `net/http` server's behavior, such as handling multiple requests on the same connection, routing requests based on host and path, handling redirects, and managing timeouts.

4. **Infer Purpose of Specific Code Blocks:**  I then looked at the implementation details of the identified types and functions to understand their specific roles:

    * **`oneConnListener`:**  The `Accept` method confirms its purpose: to return a specific, pre-configured connection once and then return an EOF error. This is useful for testing scenarios where the server processes a single request per connection.

    * **`rwTestConn` and `testConn`:** These are in-memory connections that allow writing request data and reading response data without involving actual network sockets. The buffers (`bytes.Buffer`) within `testConn` are key to this.

    * **`reqBytes`:** The replacement of `\n` with `\r\n` and the addition of `\r\n\r\n` clearly indicate the construction of a standard HTTP request format.

    * **`handlerTest.rawResponse`:** This function sets up a temporary server with a `oneConnListener` and a given handler, sends a raw request to it, waits for the connection to close, and returns the raw response. This is a way to perform low-level testing of handler behavior.

5. **Identify Go Language Features (and Prepare Examples):** As I understood the code's purpose, I started to identify the Go language features being demonstrated.

    * **Interfaces:**  The `net.Conn`, `net.Listener`, and `http.Handler` interfaces are central to the code's design. This allows for the creation of mock implementations for testing. I noted this down to potentially create an example.

    * **Structs and Methods:**  The code heavily uses structs to represent data and methods to define behavior. This is a fundamental aspect of Go.

    * **Concurrency (Goroutines and Channels):** The `TestConsumingBodyOnNextConn` function uses goroutines and channels to manage concurrent execution, which is a common pattern in Go for handling network operations. This is another potential area for an example.

    * **Testing Framework (`testing` package):** The presence of `import "testing"` and functions starting with `Test` clearly indicates the use of Go's built-in testing framework.

6. **Draft the Summary:** Based on the above analysis, I started drafting the summary, focusing on the main functionalities: setting up test environments, simulating connections, testing request handling, and verifying server behavior.

7. **Refine and Elaborate:** I then refined the summary, adding more detail and clarifying the purpose of specific components. I also structured the answer to follow the user's prompt, addressing the request for Go language features and examples.

8. **Construct Illustrative Examples (Mental Outline):**  I considered what kind of Go code examples would be most illustrative. I decided on examples demonstrating:

    * A simple custom `net.Listener` (similar to `oneConnListener`).
    * A basic `http.Handler` implementation.
    * How to use `httptest.NewRecorder` for testing handlers.

9. **Address Potential Pitfalls (Based on Code):**  I reviewed the code for any obvious areas where users might make mistakes when using or extending this kind of testing code. The tight coupling of the `oneConnListener` with a single connection was one such point – if users expect it to handle multiple connections, they'll run into problems.

10. **Final Review:** I performed a final review of the summary and examples to ensure accuracy, clarity, and completeness. I also made sure to explicitly state that this was "part 1 of 7" as per the prompt.

This iterative process of scanning, identifying, grouping, inferring, and refining allowed me to build a comprehensive understanding of the code and generate the detailed summary. The focus was on understanding the *intent* behind the code, rather than just a superficial description of each line.
这是 `go/src/net/http/serve_test.go` 文件的一部分，它主要专注于对 `net/http` 包中 **服务器（Server）** 和 **请求多路复用器（ServeMux）** 的功能进行**端到端（End-to-End）的集成测试**。

**功能归纳:**

这段代码的主要功能是构建各种测试辅助工具和测试用例，以验证 `net/http` 包中服务器处理 HTTP 请求和响应的正确性。具体来说，它涵盖了以下几个方面：

1. **模拟网络连接:**  定义了多种用于模拟网络连接的类型，例如 `dummyAddr`, `oneConnListener`, `noopConn`, `rwTestConn`, 和 `testConn`。这些类型允许在测试环境中创建虚拟的客户端和服务端连接，而无需实际的网络通信。

2. **测试请求体消费:** 包含测试用例 `TestConsumingBodyOnNextConn`，用于验证服务器是否正确地消费了请求体，以便在同一个连接上处理下一个请求。

3. **测试基于 Host 的请求分发 (Host-based routing):** 包含了测试用例 `TestHostHandlers`，用于验证 `ServeMux` 如何根据请求的 `Host` 头部来选择合适的处理器 (Handler)。

4. **测试请求多路复用器 (ServeMux) 的处理逻辑:** 包含了 `TestServeMuxHandler`, `TestServeMuxHandleFuncWithNilHandler`, `TestServeMuxHandlerRedirects` 等多个测试用例，用于验证 `ServeMux` 注册和查找处理器、处理重定向以及处理带有查询参数的请求等功能。

5. **测试 URL 规范化和重定向:**  包含了 `TestMuxRedirectLeadingSlashes`, `TestServeWithSlashRedirectKeepsQueryString`, `TestServeWithSlashRedirectForHostPatterns` 等测试用例，用于验证 `ServeMux` 如何处理 URL 中的前导斜杠，以及在添加或删除尾部斜杠时如何进行重定向，并确保重定向时保留查询字符串。

6. **测试服务器超时机制:** 包含了 `TestServerTimeouts`, `TestServerReadTimeout`, `TestServerNoReadTimeout`, `TestServerWriteTimeout`, `TestServerNoWriteTimeout` 等一系列测试用例，用于验证服务器的读取超时 (`ReadTimeout`, `ReadHeaderTimeout`) 和写入超时 (`WriteTimeout`) 功能是否正常工作。这些测试覆盖了 HTTP/1.1 和 HTTP/2 的情况。

7. **基准测试:** 包含了 `BenchmarkServeMux` 和 `BenchmarkServeMux_SkipServe` 两个基准测试，用于评估 `ServeMux` 的性能。

**它是什么 Go 语言功能的实现？**

这段代码主要测试的是 `net/http` 包中 `Server` 和 `ServeMux` 的实现。

* **`Server`**:  负责监听端口，接收连接，并为每个连接创建 goroutine 来处理请求。它管理着连接的生命周期，并应用配置的超时设置。
* **`ServeMux`**:  是一个 HTTP 请求多路复用器。它将接收到的请求的 URL 与已注册的模式进行匹配，并将请求路由到相应的 `Handler` 处理。它负责根据 Host 和 Path 进行路由选择，并处理尾部斜杠的重定向。

**Go 代码举例说明:**

以下代码示例展示了 `ServeMux` 如何根据 URL 路径将请求分发到不同的处理器：

```go
package main

import (
	"fmt"
	"net/http"
)

// 处理器 1
func handlerOne(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello from handler one!")
}

// 处理器 2
func handlerTwo(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello from handler two!")
}

func main() {
	// 创建一个新的 ServeMux
	mux := http.NewServeMux()

	// 注册处理器和对应的路径模式
	mux.HandleFunc("/one", handlerOne)
	mux.HandleFunc("/two/", handlerTwo) // 注意尾部的斜杠

	// 创建一个 HTTP 服务器并使用我们自定义的 ServeMux
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Println("Server listening on :8080")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
```

**假设的输入与输出:**

* **输入 (请求到 `/one`):**
  ```
  GET /one HTTP/1.1
  Host: localhost:8080
  ```
* **输出:**
  ```
  HTTP/1.1 200 OK
  Date: ...
  Content-Type: text/plain; charset=utf-8
  Content-Length: 23

  Hello from handler one!
  ```

* **输入 (请求到 `/two/`)**:
  ```
  GET /two/anything HTTP/1.1
  Host: localhost:8080
  ```
* **输出:**
  ```
  HTTP/1.1 200 OK
  Date: ...
  Content-Type: text/plain; charset=utf-8
  Content-Length: 23

  Hello from handler two!
  ```

* **输入 (请求到 `/two`, 注意缺少尾部斜杠):**
  ```
  GET /two HTTP/1.1
  Host: localhost:8080
  ```
* **输出:**
  ```
  HTTP/1.1 301 Moved Permanently
  Date: ...
  Location: /two/
  Content-Length: 0
  ```
  (ServeMux 会自动重定向到带有尾部斜杠的路径)

**命令行参数:**

这段代码本身是测试代码，不涉及直接的命令行参数处理。 `net/http` 包的服务器实现可以通过代码配置监听地址和端口，例如在上面的例子中使用了 `server := &http.Server{Addr: ":8080", Handler: mux}`。

**使用者易犯错的点 (基于这段代码的测试内容):**

1. **忘记处理请求体:**  如 `TestConsumingBodyOnNextConn` 所测试的，如果 Handler 没有完全读取请求体，可能会导致后续在同一连接上的请求处理出现问题。
   ```go
   // 错误示例：没有读取请求体
   func myHandler(w http.ResponseWriter, r *http.Request) {
       // ... 没有读取 r.Body ...
       fmt.Fprintln(w, "Processed")
   }
   ```

2. **对 ServeMux 的路径匹配规则理解不准确:**  例如，忘记尾部斜杠的重要性，导致预期的处理器没有被调用。
   ```go
   mux := http.NewServeMux()
   mux.HandleFunc("/api", apiHandler) // 只能匹配 /api，不能匹配 /api/
   mux.HandleFunc("/data/", dataHandler) // 可以匹配 /data/ 或 /data/something
   ```

3. **没有正确设置或理解服务器的超时时间:**  `ReadTimeout` 和 `WriteTimeout` 的设置会直接影响服务器处理慢客户端或慢处理请求的能力。不合理的超时设置可能导致服务不稳定。

4. **在 Host 路由中忽略端口:**  `ServeMux` 的 Host 匹配是精确匹配，包括端口号。
   ```go
   mux.Handle("example.com/", handlerForExample)
   // 请求 Host: example.com:8080 将不会匹配到上面的 handler
   mux.Handle("example.com:8080/", handlerForExampleWithPort)
   ```

总之，这段代码通过大量的测试用例，覆盖了 `net/http` 包中服务器和请求多路复用器的关键功能，帮助开发者理解和正确使用这些核心组件。它揭示了在实际使用中可能遇到的一些常见问题和陷阱。

### 提示词
```
这是路径为go/src/net/http/serve_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// End-to-end serving tests

package http_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"internal/synctest"
	"internal/testenv"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	. "net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/http/internal"
	"net/http/internal/testcert"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type dummyAddr string
type oneConnListener struct {
	conn net.Conn
}

func (l *oneConnListener) Accept() (c net.Conn, err error) {
	c = l.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	l.conn = nil
	return
}

func (l *oneConnListener) Close() error {
	return nil
}

func (l *oneConnListener) Addr() net.Addr {
	return dummyAddr("test-address")
}

func (a dummyAddr) Network() string {
	return string(a)
}

func (a dummyAddr) String() string {
	return string(a)
}

type noopConn struct{}

func (noopConn) LocalAddr() net.Addr                { return dummyAddr("local-addr") }
func (noopConn) RemoteAddr() net.Addr               { return dummyAddr("remote-addr") }
func (noopConn) SetDeadline(t time.Time) error      { return nil }
func (noopConn) SetReadDeadline(t time.Time) error  { return nil }
func (noopConn) SetWriteDeadline(t time.Time) error { return nil }

type rwTestConn struct {
	io.Reader
	io.Writer
	noopConn

	closeFunc func() error // called if non-nil
	closec    chan bool    // else, if non-nil, send value to it on close
}

func (c *rwTestConn) Close() error {
	if c.closeFunc != nil {
		return c.closeFunc()
	}
	select {
	case c.closec <- true:
	default:
	}
	return nil
}

type testConn struct {
	readMu   sync.Mutex // for TestHandlerBodyClose
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
	closec   chan bool // 1-buffered; receives true when Close is called
	noopConn
}

func newTestConn() *testConn {
	return &testConn{closec: make(chan bool, 1)}
}

func (c *testConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.readBuf.Read(b)
}

func (c *testConn) Write(b []byte) (int, error) {
	return c.writeBuf.Write(b)
}

func (c *testConn) Close() error {
	select {
	case c.closec <- true:
	default:
	}
	return nil
}

// reqBytes treats req as a request (with \n delimiters) and returns it with \r\n delimiters,
// ending in \r\n\r\n
func reqBytes(req string) []byte {
	return []byte(strings.ReplaceAll(strings.TrimSpace(req), "\n", "\r\n") + "\r\n\r\n")
}

type handlerTest struct {
	logbuf  bytes.Buffer
	handler Handler
}

func newHandlerTest(h Handler) handlerTest {
	return handlerTest{handler: h}
}

func (ht *handlerTest) rawResponse(req string) string {
	reqb := reqBytes(req)
	var output strings.Builder
	conn := &rwTestConn{
		Reader: bytes.NewReader(reqb),
		Writer: &output,
		closec: make(chan bool, 1),
	}
	ln := &oneConnListener{conn: conn}
	srv := &Server{
		ErrorLog: log.New(&ht.logbuf, "", 0),
		Handler:  ht.handler,
	}
	go srv.Serve(ln)
	<-conn.closec
	return output.String()
}

func TestConsumingBodyOnNextConn(t *testing.T) {
	t.Parallel()
	defer afterTest(t)
	conn := new(testConn)
	for i := 0; i < 2; i++ {
		conn.readBuf.Write([]byte(
			"POST / HTTP/1.1\r\n" +
				"Host: test\r\n" +
				"Content-Length: 11\r\n" +
				"\r\n" +
				"foo=1&bar=1"))
	}

	reqNum := 0
	ch := make(chan *Request)
	servech := make(chan error)
	listener := &oneConnListener{conn}
	handler := func(res ResponseWriter, req *Request) {
		reqNum++
		ch <- req
	}

	go func() {
		servech <- Serve(listener, HandlerFunc(handler))
	}()

	var req *Request
	req = <-ch
	if req == nil {
		t.Fatal("Got nil first request.")
	}
	if req.Method != "POST" {
		t.Errorf("For request #1's method, got %q; expected %q",
			req.Method, "POST")
	}

	req = <-ch
	if req == nil {
		t.Fatal("Got nil first request.")
	}
	if req.Method != "POST" {
		t.Errorf("For request #2's method, got %q; expected %q",
			req.Method, "POST")
	}

	if serveerr := <-servech; serveerr != io.EOF {
		t.Errorf("Serve returned %q; expected EOF", serveerr)
	}
}

type stringHandler string

func (s stringHandler) ServeHTTP(w ResponseWriter, r *Request) {
	w.Header().Set("Result", string(s))
}

var handlers = []struct {
	pattern string
	msg     string
}{
	{"/", "Default"},
	{"/someDir/", "someDir"},
	{"/#/", "hash"},
	{"someHost.com/someDir/", "someHost.com/someDir"},
}

var vtests = []struct {
	url      string
	expected string
}{
	{"http://localhost/someDir/apage", "someDir"},
	{"http://localhost/%23/apage", "hash"},
	{"http://localhost/otherDir/apage", "Default"},
	{"http://someHost.com/someDir/apage", "someHost.com/someDir"},
	{"http://otherHost.com/someDir/apage", "someDir"},
	{"http://otherHost.com/aDir/apage", "Default"},
	// redirections for trees
	{"http://localhost/someDir", "/someDir/"},
	{"http://localhost/%23", "/%23/"},
	{"http://someHost.com/someDir", "/someDir/"},
}

func TestHostHandlers(t *testing.T) { run(t, testHostHandlers, []testMode{http1Mode}) }
func testHostHandlers(t *testing.T, mode testMode) {
	mux := NewServeMux()
	for _, h := range handlers {
		mux.Handle(h.pattern, stringHandler(h.msg))
	}
	ts := newClientServerTest(t, mode, mux).ts

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cc := httputil.NewClientConn(conn, nil)
	for _, vt := range vtests {
		var r *Response
		var req Request
		if req.URL, err = url.Parse(vt.url); err != nil {
			t.Errorf("cannot parse url: %v", err)
			continue
		}
		if err := cc.Write(&req); err != nil {
			t.Errorf("writing request: %v", err)
			continue
		}
		r, err := cc.Read(&req)
		if err != nil {
			t.Errorf("reading response: %v", err)
			continue
		}
		switch r.StatusCode {
		case StatusOK:
			s := r.Header.Get("Result")
			if s != vt.expected {
				t.Errorf("Get(%q) = %q, want %q", vt.url, s, vt.expected)
			}
		case StatusMovedPermanently:
			s := r.Header.Get("Location")
			if s != vt.expected {
				t.Errorf("Get(%q) = %q, want %q", vt.url, s, vt.expected)
			}
		default:
			t.Errorf("Get(%q) unhandled status code %d", vt.url, r.StatusCode)
		}
	}
}

var serveMuxRegister = []struct {
	pattern string
	h       Handler
}{
	{"/dir/", serve(200)},
	{"/search", serve(201)},
	{"codesearch.google.com/search", serve(202)},
	{"codesearch.google.com/", serve(203)},
	{"example.com/", HandlerFunc(checkQueryStringHandler)},
}

// serve returns a handler that sends a response with the given code.
func serve(code int) HandlerFunc {
	return func(w ResponseWriter, r *Request) {
		w.WriteHeader(code)
	}
}

// checkQueryStringHandler checks if r.URL.RawQuery has the same value
// as the URL excluding the scheme and the query string and sends 200
// response code if it is, 500 otherwise.
func checkQueryStringHandler(w ResponseWriter, r *Request) {
	u := *r.URL
	u.Scheme = "http"
	u.Host = r.Host
	u.RawQuery = ""
	if "http://"+r.URL.RawQuery == u.String() {
		w.WriteHeader(200)
	} else {
		w.WriteHeader(500)
	}
}

var serveMuxTests = []struct {
	method  string
	host    string
	path    string
	code    int
	pattern string
}{
	{"GET", "google.com", "/", 404, ""},
	{"GET", "google.com", "/dir", 301, "/dir/"},
	{"GET", "google.com", "/dir/", 200, "/dir/"},
	{"GET", "google.com", "/dir/file", 200, "/dir/"},
	{"GET", "google.com", "/search", 201, "/search"},
	{"GET", "google.com", "/search/", 404, ""},
	{"GET", "google.com", "/search/foo", 404, ""},
	{"GET", "codesearch.google.com", "/search", 202, "codesearch.google.com/search"},
	{"GET", "codesearch.google.com", "/search/", 203, "codesearch.google.com/"},
	{"GET", "codesearch.google.com", "/search/foo", 203, "codesearch.google.com/"},
	{"GET", "codesearch.google.com", "/", 203, "codesearch.google.com/"},
	{"GET", "codesearch.google.com:443", "/", 203, "codesearch.google.com/"},
	{"GET", "images.google.com", "/search", 201, "/search"},
	{"GET", "images.google.com", "/search/", 404, ""},
	{"GET", "images.google.com", "/search/foo", 404, ""},
	{"GET", "google.com", "/../search", 301, "/search"},
	{"GET", "google.com", "/dir/..", 301, ""},
	{"GET", "google.com", "/dir/..", 301, ""},
	{"GET", "google.com", "/dir/./file", 301, "/dir/"},

	// The /foo -> /foo/ redirect applies to CONNECT requests
	// but the path canonicalization does not.
	{"CONNECT", "google.com", "/dir", 301, "/dir/"},
	{"CONNECT", "google.com", "/../search", 404, ""},
	{"CONNECT", "google.com", "/dir/..", 200, "/dir/"},
	{"CONNECT", "google.com", "/dir/..", 200, "/dir/"},
	{"CONNECT", "google.com", "/dir/./file", 200, "/dir/"},
}

func TestServeMuxHandler(t *testing.T) {
	setParallel(t)
	mux := NewServeMux()
	for _, e := range serveMuxRegister {
		mux.Handle(e.pattern, e.h)
	}

	for _, tt := range serveMuxTests {
		r := &Request{
			Method: tt.method,
			Host:   tt.host,
			URL: &url.URL{
				Path: tt.path,
			},
		}
		h, pattern := mux.Handler(r)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if pattern != tt.pattern || rr.Code != tt.code {
			t.Errorf("%s %s %s = %d, %q, want %d, %q", tt.method, tt.host, tt.path, rr.Code, pattern, tt.code, tt.pattern)
		}
	}
}

// Issue 24297
func TestServeMuxHandleFuncWithNilHandler(t *testing.T) {
	setParallel(t)
	defer func() {
		if err := recover(); err == nil {
			t.Error("expected call to mux.HandleFunc to panic")
		}
	}()
	mux := NewServeMux()
	mux.HandleFunc("/", nil)
}

var serveMuxTests2 = []struct {
	method  string
	host    string
	url     string
	code    int
	redirOk bool
}{
	{"GET", "google.com", "/", 404, false},
	{"GET", "example.com", "/test/?example.com/test/", 200, false},
	{"GET", "example.com", "test/?example.com/test/", 200, true},
}

// TestServeMuxHandlerRedirects tests that automatic redirects generated by
// mux.Handler() shouldn't clear the request's query string.
func TestServeMuxHandlerRedirects(t *testing.T) {
	setParallel(t)
	mux := NewServeMux()
	for _, e := range serveMuxRegister {
		mux.Handle(e.pattern, e.h)
	}

	for _, tt := range serveMuxTests2 {
		tries := 1 // expect at most 1 redirection if redirOk is true.
		turl := tt.url
		for {
			u, e := url.Parse(turl)
			if e != nil {
				t.Fatal(e)
			}
			r := &Request{
				Method: tt.method,
				Host:   tt.host,
				URL:    u,
			}
			h, _ := mux.Handler(r)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if rr.Code != 301 {
				if rr.Code != tt.code {
					t.Errorf("%s %s %s = %d, want %d", tt.method, tt.host, tt.url, rr.Code, tt.code)
				}
				break
			}
			if !tt.redirOk {
				t.Errorf("%s %s %s, unexpected redirect", tt.method, tt.host, tt.url)
				break
			}
			turl = rr.HeaderMap.Get("Location")
			tries--
		}
		if tries < 0 {
			t.Errorf("%s %s %s, too many redirects", tt.method, tt.host, tt.url)
		}
	}
}

// Tests for https://golang.org/issue/900
func TestMuxRedirectLeadingSlashes(t *testing.T) {
	setParallel(t)
	paths := []string{"//foo.txt", "///foo.txt", "/../../foo.txt"}
	for _, path := range paths {
		req, err := ReadRequest(bufio.NewReader(strings.NewReader("GET " + path + " HTTP/1.1\r\nHost: test\r\n\r\n")))
		if err != nil {
			t.Errorf("%s", err)
		}
		mux := NewServeMux()
		resp := httptest.NewRecorder()

		mux.ServeHTTP(resp, req)

		if loc, expected := resp.Header().Get("Location"), "/foo.txt"; loc != expected {
			t.Errorf("Expected Location header set to %q; got %q", expected, loc)
			return
		}

		if code, expected := resp.Code, StatusMovedPermanently; code != expected {
			t.Errorf("Expected response code of StatusMovedPermanently; got %d", code)
			return
		}
	}
}

// Test that the special cased "/route" redirect
// implicitly created by a registered "/route/"
// properly sets the query string in the redirect URL.
// See Issue 17841.
func TestServeWithSlashRedirectKeepsQueryString(t *testing.T) {
	run(t, testServeWithSlashRedirectKeepsQueryString, []testMode{http1Mode})
}
func testServeWithSlashRedirectKeepsQueryString(t *testing.T, mode testMode) {
	writeBackQuery := func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "%s", r.URL.RawQuery)
	}

	mux := NewServeMux()
	mux.HandleFunc("/testOne", writeBackQuery)
	mux.HandleFunc("/testTwo/", writeBackQuery)
	mux.HandleFunc("/testThree", writeBackQuery)
	mux.HandleFunc("/testThree/", func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "%s:bar", r.URL.RawQuery)
	})

	ts := newClientServerTest(t, mode, mux).ts

	tests := [...]struct {
		path     string
		method   string
		want     string
		statusOk bool
	}{
		0: {"/testOne?this=that", "GET", "this=that", true},
		1: {"/testTwo?foo=bar", "GET", "foo=bar", true},
		2: {"/testTwo?a=1&b=2&a=3", "GET", "a=1&b=2&a=3", true},
		3: {"/testTwo?", "GET", "", true},
		4: {"/testThree?foo", "GET", "foo", true},
		5: {"/testThree/?foo", "GET", "foo:bar", true},
		6: {"/testThree?foo", "CONNECT", "foo", true},
		7: {"/testThree/?foo", "CONNECT", "foo:bar", true},

		// canonicalization or not
		8: {"/testOne/foo/..?foo", "GET", "foo", true},
		9: {"/testOne/foo/..?foo", "CONNECT", "404 page not found\n", false},
	}

	for i, tt := range tests {
		req, _ := NewRequest(tt.method, ts.URL+tt.path, nil)
		res, err := ts.Client().Do(req)
		if err != nil {
			continue
		}
		slurp, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !tt.statusOk {
			if got, want := res.StatusCode, 404; got != want {
				t.Errorf("#%d: Status = %d; want = %d", i, got, want)
			}
		}
		if got, want := string(slurp), tt.want; got != want {
			t.Errorf("#%d: Body = %q; want = %q", i, got, want)
		}
	}
}

func TestServeWithSlashRedirectForHostPatterns(t *testing.T) {
	setParallel(t)

	mux := NewServeMux()
	mux.Handle("example.com/pkg/foo/", stringHandler("example.com/pkg/foo/"))
	mux.Handle("example.com/pkg/bar", stringHandler("example.com/pkg/bar"))
	mux.Handle("example.com/pkg/bar/", stringHandler("example.com/pkg/bar/"))
	mux.Handle("example.com:3000/pkg/connect/", stringHandler("example.com:3000/pkg/connect/"))
	mux.Handle("example.com:9000/", stringHandler("example.com:9000/"))
	mux.Handle("/pkg/baz/", stringHandler("/pkg/baz/"))

	tests := []struct {
		method string
		url    string
		code   int
		loc    string
		want   string
	}{
		{"GET", "http://example.com/", 404, "", ""},
		{"GET", "http://example.com/pkg/foo", 301, "/pkg/foo/", ""},
		{"GET", "http://example.com/pkg/bar", 200, "", "example.com/pkg/bar"},
		{"GET", "http://example.com/pkg/bar/", 200, "", "example.com/pkg/bar/"},
		{"GET", "http://example.com/pkg/baz", 301, "/pkg/baz/", ""},
		{"GET", "http://example.com:3000/pkg/foo", 301, "/pkg/foo/", ""},
		{"CONNECT", "http://example.com/", 404, "", ""},
		{"CONNECT", "http://example.com:3000/", 404, "", ""},
		{"CONNECT", "http://example.com:9000/", 200, "", "example.com:9000/"},
		{"CONNECT", "http://example.com/pkg/foo", 301, "/pkg/foo/", ""},
		{"CONNECT", "http://example.com:3000/pkg/foo", 404, "", ""},
		{"CONNECT", "http://example.com:3000/pkg/baz", 301, "/pkg/baz/", ""},
		{"CONNECT", "http://example.com:3000/pkg/connect", 301, "/pkg/connect/", ""},
	}

	for i, tt := range tests {
		req, _ := NewRequest(tt.method, tt.url, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if got, want := w.Code, tt.code; got != want {
			t.Errorf("#%d: Status = %d; want = %d", i, got, want)
		}

		if tt.code == 301 {
			if got, want := w.HeaderMap.Get("Location"), tt.loc; got != want {
				t.Errorf("#%d: Location = %q; want = %q", i, got, want)
			}
		} else {
			if got, want := w.HeaderMap.Get("Result"), tt.want; got != want {
				t.Errorf("#%d: Result = %q; want = %q", i, got, want)
			}
		}
	}
}

// Test that we don't attempt trailing-slash redirect on a path that already has
// a trailing slash.
// See issue #65624.
func TestMuxNoSlashRedirectWithTrailingSlash(t *testing.T) {
	mux := NewServeMux()
	mux.HandleFunc("/{x}/", func(w ResponseWriter, r *Request) {
		fmt.Fprintln(w, "ok")
	})
	w := httptest.NewRecorder()
	req, _ := NewRequest("GET", "/", nil)
	mux.ServeHTTP(w, req)
	if g, w := w.Code, 404; g != w {
		t.Errorf("got %d, want %d", g, w)
	}
}

// Test that we don't attempt trailing-slash response 405 on a path that already has
// a trailing slash.
// See issue #67657.
func TestMuxNoSlash405WithTrailingSlash(t *testing.T) {
	mux := NewServeMux()
	mux.HandleFunc("GET /{x}/", func(w ResponseWriter, r *Request) {
		fmt.Fprintln(w, "ok")
	})
	w := httptest.NewRecorder()
	req, _ := NewRequest("GET", "/", nil)
	mux.ServeHTTP(w, req)
	if g, w := w.Code, 404; g != w {
		t.Errorf("got %d, want %d", g, w)
	}
}

func TestShouldRedirectConcurrency(t *testing.T) { run(t, testShouldRedirectConcurrency) }
func testShouldRedirectConcurrency(t *testing.T, mode testMode) {
	mux := NewServeMux()
	newClientServerTest(t, mode, mux)
	mux.HandleFunc("/", func(w ResponseWriter, r *Request) {})
}

func BenchmarkServeMux(b *testing.B)           { benchmarkServeMux(b, true) }
func BenchmarkServeMux_SkipServe(b *testing.B) { benchmarkServeMux(b, false) }
func benchmarkServeMux(b *testing.B, runHandler bool) {
	type test struct {
		path string
		code int
		req  *Request
	}

	// Build example handlers and requests
	var tests []test
	endpoints := []string{"search", "dir", "file", "change", "count", "s"}
	for _, e := range endpoints {
		for i := 200; i < 230; i++ {
			p := fmt.Sprintf("/%s/%d/", e, i)
			tests = append(tests, test{
				path: p,
				code: i,
				req:  &Request{Method: "GET", Host: "localhost", URL: &url.URL{Path: p}},
			})
		}
	}
	mux := NewServeMux()
	for _, tt := range tests {
		mux.Handle(tt.path, serve(tt.code))
	}

	rw := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tt := range tests {
			*rw = httptest.ResponseRecorder{}
			h, pattern := mux.Handler(tt.req)
			if runHandler {
				h.ServeHTTP(rw, tt.req)
				if pattern != tt.path || rw.Code != tt.code {
					b.Fatalf("got %d, %q, want %d, %q", rw.Code, pattern, tt.code, tt.path)
				}
			}
		}
	}
}

func TestServerTimeouts(t *testing.T) { run(t, testServerTimeouts, []testMode{http1Mode}) }
func testServerTimeouts(t *testing.T, mode testMode) {
	runTimeSensitiveTest(t, []time.Duration{
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
	}, func(t *testing.T, timeout time.Duration) error {
		return testServerTimeoutsWithTimeout(t, timeout, mode)
	})
}

func testServerTimeoutsWithTimeout(t *testing.T, timeout time.Duration, mode testMode) error {
	var reqNum atomic.Int32
	cst := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {
		fmt.Fprintf(res, "req=%d", reqNum.Add(1))
	}), func(ts *httptest.Server) {
		ts.Config.ReadTimeout = timeout
		ts.Config.WriteTimeout = timeout
	})
	defer cst.close()
	ts := cst.ts

	// Hit the HTTP server successfully.
	c := ts.Client()
	r, err := c.Get(ts.URL)
	if err != nil {
		return fmt.Errorf("http Get #1: %v", err)
	}
	got, err := io.ReadAll(r.Body)
	expected := "req=1"
	if string(got) != expected || err != nil {
		return fmt.Errorf("Unexpected response for request #1; got %q ,%v; expected %q, nil",
			string(got), err, expected)
	}

	// Slow client that should timeout.
	t1 := time.Now()
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		return fmt.Errorf("Dial: %v", err)
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	conn.Close()
	latency := time.Since(t1)
	if n != 0 || err != io.EOF {
		return fmt.Errorf("Read = %v, %v, wanted %v, %v", n, err, 0, io.EOF)
	}
	minLatency := timeout / 5 * 4
	if latency < minLatency {
		return fmt.Errorf("got EOF after %s, want >= %s", latency, minLatency)
	}

	// Hit the HTTP server successfully again, verifying that the
	// previous slow connection didn't run our handler.  (that we
	// get "req=2", not "req=3")
	r, err = c.Get(ts.URL)
	if err != nil {
		return fmt.Errorf("http Get #2: %v", err)
	}
	got, err = io.ReadAll(r.Body)
	r.Body.Close()
	expected = "req=2"
	if string(got) != expected || err != nil {
		return fmt.Errorf("Get #2 got %q, %v, want %q, nil", string(got), err, expected)
	}

	if !testing.Short() {
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			return fmt.Errorf("long Dial: %v", err)
		}
		defer conn.Close()
		go io.Copy(io.Discard, conn)
		for i := 0; i < 5; i++ {
			_, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: foo\r\n\r\n"))
			if err != nil {
				return fmt.Errorf("on write %d: %v", i, err)
			}
			time.Sleep(timeout / 2)
		}
	}
	return nil
}

func TestServerReadTimeout(t *testing.T) { run(t, testServerReadTimeout) }
func testServerReadTimeout(t *testing.T, mode testMode) {
	respBody := "response body"
	for timeout := 5 * time.Millisecond; ; timeout *= 2 {
		cst := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {
			_, err := io.Copy(io.Discard, req.Body)
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("server timed out reading request body: got err %v; want os.ErrDeadlineExceeded", err)
			}
			res.Write([]byte(respBody))
		}), func(ts *httptest.Server) {
			ts.Config.ReadHeaderTimeout = -1 // don't time out while reading headers
			ts.Config.ReadTimeout = timeout
			t.Logf("Server.Config.ReadTimeout = %v", timeout)
		})

		var retries atomic.Int32
		cst.c.Transport.(*Transport).Proxy = func(*Request) (*url.URL, error) {
			if retries.Add(1) != 1 {
				return nil, errors.New("too many retries")
			}
			return nil, nil
		}

		pr, pw := io.Pipe()
		res, err := cst.c.Post(cst.ts.URL, "text/apocryphal", pr)
		if err != nil {
			t.Logf("Get error, retrying: %v", err)
			cst.close()
			continue
		}
		defer res.Body.Close()
		got, err := io.ReadAll(res.Body)
		if string(got) != respBody || err != nil {
			t.Errorf("client read response body: %q, %v; want %q, nil", string(got), err, respBody)
		}
		pw.Close()
		break
	}
}

func TestServerNoReadTimeout(t *testing.T) { run(t, testServerNoReadTimeout) }
func testServerNoReadTimeout(t *testing.T, mode testMode) {
	reqBody := "Hello, Gophers!"
	resBody := "Hi, Gophers!"
	for _, timeout := range []time.Duration{0, -1} {
		cst := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {
			ctl := NewResponseController(res)
			ctl.EnableFullDuplex()
			res.WriteHeader(StatusOK)
			// Flush the headers before processing the request body
			// to unblock the client from the RoundTrip.
			if err := ctl.Flush(); err != nil {
				t.Errorf("server flush response: %v", err)
				return
			}
			got, err := io.ReadAll(req.Body)
			if string(got) != reqBody || err != nil {
				t.Errorf("server read request body: %v; got %q, want %q", err, got, reqBody)
			}
			res.Write([]byte(resBody))
		}), func(ts *httptest.Server) {
			ts.Config.ReadTimeout = timeout
			t.Logf("Server.Config.ReadTimeout = %d", timeout)
		})

		pr, pw := io.Pipe()
		res, err := cst.c.Post(cst.ts.URL, "text/plain", pr)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()

		// TODO(panjf2000): sleep is not so robust, maybe find a better way to test this?
		time.Sleep(10 * time.Millisecond) // stall sending body to server to test server doesn't time out
		pw.Write([]byte(reqBody))
		pw.Close()

		got, err := io.ReadAll(res.Body)
		if string(got) != resBody || err != nil {
			t.Errorf("client read response body: %v; got %v, want %q", err, got, resBody)
		}
	}
}

func TestServerWriteTimeout(t *testing.T) { run(t, testServerWriteTimeout) }
func testServerWriteTimeout(t *testing.T, mode testMode) {
	for timeout := 5 * time.Millisecond; ; timeout *= 2 {
		errc := make(chan error, 2)
		cst := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {
			errc <- nil
			_, err := io.Copy(res, neverEnding('a'))
			errc <- err
		}), func(ts *httptest.Server) {
			ts.Config.WriteTimeout = timeout
			t.Logf("Server.Config.WriteTimeout = %v", timeout)
		})

		// The server's WriteTimeout parameter also applies to reads during the TLS
		// handshake. The client makes the last write during the handshake, and if
		// the server happens to time out during the read of that write, the client
		// may think that the connection was accepted even though the server thinks
		// it timed out.
		//
		// The client only notices that the server connection is gone when it goes
		// to actually write the request — and when that fails, it retries
		// internally (the same as if the server had closed the connection due to a
		// racing idle-timeout).
		//
		// With unlucky and very stable scheduling (as may be the case with the fake wasm
		// net stack), this can result in an infinite retry loop that doesn't
		// propagate the error up far enough for us to adjust the WriteTimeout.
		//
		// To avoid that problem, we explicitly forbid internal retries by rejecting
		// them in a Proxy hook in the transport.
		var retries atomic.Int32
		cst.c.Transport.(*Transport).Proxy = func(*Request) (*url.URL, error) {
			if retries.Add(1) != 1 {
				return nil, errors.New("too many retries")
			}
			return nil, nil
		}

		res, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			// Probably caused by the write timeout expiring before the handler runs.
			t.Logf("Get error, retrying: %v", err)
			cst.close()
			continue
		}
		defer res.Body.Close()
		_, err = io.Copy(io.Discard, res.Body)
		if err == nil {
			t.Errorf("client reading from truncated request body: got nil error, want non-nil")
		}
		select {
		case <-errc:
			err = <-errc // io.Copy error
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("server timed out writing request body: got err %v; want os.ErrDeadlineExceeded", err)
			}
			return
		default:
			// The write timeout expired before the handler started.
			t.Logf("handler didn't run, retrying")
			cst.close()
		}
	}
}

func TestServerNoWriteTimeout(t *testing.T) { run(t, testServerNoWriteTimeout) }
func testServerNoWriteTimeout(t *testing.T, mode testMode) {
	for _, timeout := range []time.Duration{0, -1} {
		cst := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {
			_, err := io.Copy(res, neverEnding('a'))
			t.Logf("server write response: %v", err)
		}), func(ts *httptest.Server) {
			ts.Config.WriteTimeout = timeout
			t.Logf("Server.Config.WriteTimeout = %d", timeout)
		})

		res, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		n, err := io.CopyN(io.Discard, res.Body, 1<<20) // 1MB should be sufficient to prove the point
		if n != 1<<20 || err != nil {
			t.Errorf("client read response body: %d, %v", n, err)
		}
		// This shutdown really should be automatic, but it isn't right now.
		// Shutdown (rather than Close) ensures the handler is done before we return.
		res.Body.Close()
		cst.ts.Config.Shutdown(context.Background())
	}
}

// Test that the HTTP/2 server handles Server.WriteTimeout (Issue 18437)
func TestWriteDeadlineExtendedOnNewRequest(t *testing.T) {
	run(t, testWriteDeadlineExtendedOnNewRequest)
}
func testWriteDeadlineExtendedOnNewRequest(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	ts := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {}),
		func(ts *httptest.Server) {
			ts.Config.WriteTimeout = 250 * time.Millisecond
		},
	).ts

	c := ts.Client()

	for i := 1; i <= 3; i++ {
		req, err := NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}

		r, err := c.Do(req)
		if err != nil {
			t.Fatalf("http2 Get #%d: %v", i, err)
		}
		r.Body.Close()
		time.Sleep(ts.Config.WriteTimeout / 2)
	}
}

// tryTimeouts runs testFunc with increasing timeouts. Test passes on first success,
// and fails if all timeouts fail.
func tryTimeouts(t *testing.T, testFunc func(timeout time.Duration) error) {
	tries := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second}
	for i, timeout := range tries {
		err := testFunc(timeout)
		if err == nil {
			return
		}
		t.Logf("failed at %v: %v", timeout, err)
		if i != len(tries)-1 {
			t.Logf("retrying at %v ...", tries[i+1])
		}
	}
	t.Fatal("all attempts failed")
}

// Test that the HTTP/2 server RSTs stream on slow write.
func TestWriteDeadlineEnforcedPerStream(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	setParallel(t)
	run(t, func(t *testing.T, mode testMode) {
		tryTimeouts(t, func(timeout time.Duration) error {
			return testWriteDeadlineEnforcedPerStream(t, mode, timeout)
		})
	})
}

func testWriteDeadlineEnforcedPerStream(t *testing.T, mode testMode, timeout time.Duration) error {
	firstRequest := make(chan bool, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {
		select {
		case firstRequest <- true:
			// first request succeeds
		default:
			// second request times out
			time.Sleep(timeout)
		}
	}), func(ts *httptest.Server) {
		ts.Config.WriteTimeout = timeout / 2
	})
	defer cst.close()
	ts := cst.ts

	c := ts.Client()

	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		return fmt.Errorf("NewRequest: %v", err)
	}
	r, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("Get #1: %v", err)
	}
	r.Body.Close()

	req, err = NewRequest("GET", ts.URL, nil)
	if err != nil {
		return fmt.Errorf("NewRequest: %v", err)
	}
	r, err = c.Do(req)
	if err == nil {
		r.Body.Close()
		return fmt.Errorf("Get #2 expected error, got nil")
	}
	if mode == http2Mode {
		expected := "stream ID 3; INTERNAL_ERROR" // client IDs are odd, second stream should be 3
		if !strings.Contains(err.Error(), expected) {
			return fmt.Errorf("http2 Get #2: expected error to contain %q, got %q", expected, err)
		}
	}
	return nil
}

// Test that the HTTP/2 server does not send RST when WriteDeadline not set.
func TestNoWriteDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	setParallel(t)
	defer afterTest(t)
	run(t, func(t *testing.T, mode testMode) {
		tryTimeouts(t, func(timeout time.Duration) error {
			return testNoWriteDeadline(t, mode, timeout)
		})
	})
}

func testNoWriteDeadline(t *testing.T, mode testMode, timeout time.Duration) error {
	firstRequest := make(chan bool, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(res ResponseWriter, req *Request) {
		select {
		case firstRequest <- true:
			// first request succeeds
		default:
			// second request times out
			time.Sleep(timeout)
		}
	}))
	defer cst.close()
	ts := cst.ts

	c := ts.Client()

	for i := 0; i < 2; i++ {
		req, err := NewRequest("GET", ts.URL, nil)
		if err != nil {
			return fmt.Errorf("NewRequest: %v", err)
		}
		r, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("Get #%d: %v", i, err)
		}
		r.Body.Close()
	}
	return nil
}

// golang.org/issue/4741 -- setting only a write timeout that triggers
// shouldn't cause a handler to block forever on reads (next HTTP
// request) that will never happen.
func TestOnlyWriteTimeout(t *testing.T) { run(t, testOnlyWriteTimeout, []testMode{http1Mode}) }
func testOnlyWriteTimeout(t *testing.T, mode testMode) {
	var (
		mu   sync.RWMutex
		conn net.Conn
	)
	var afterTimeoutErrc = make(chan error, 1)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, req *Request) {
		buf := make([]byte, 512<<10)
		_, err := w.Write(buf)
		if err != nil {
			t.Errorf("handler Write error: %v", err)
			return
		}
		mu.RLock()
		defer mu.RUnlock()
		if conn == nil {
			t.Error("no established connection found")
			return
		}
		conn.SetWriteDeadline(time.Now().Add(-30 * time.Second))
		_, err = w.Write(buf)
		afterTimeoutErrc <- err
	}), func(ts *httptest.Server) {
		ts.Listener = trackLastConnListener{ts.Listener, &mu, &conn}
	}).ts

	c := ts.Client()

	err := func() error {
		res, err := c.Get(ts.URL)
		if err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return err
	}()
	if err == nil {
		t.Errorf("expected an error copying body from Get request")
	}

	if err := <-afterTimeoutErrc; err == nil {
		t.Error("expected write error after timeout")
	}
}

// trackLastConnListener tracks the last net.Conn that was accepted.
type trackLastConnListener struct {
	net.Listener

	mu   *sync.RWMutex
	last *net.Conn // destination
}

func (l trackLastConnListener) Accept() (c net.Conn, err error) {
	c, err = l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		*l.last = c
		l.mu.Unlock()
	}
	return
}

// TestIdentityResponse verifies that a handler can unset
func TestIdentityResponse(t *testing.T) { run(t, testIdentityResponse) }
func testIdentityResponse(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("https://go.dev/issue/56019")
	}

	handler := HandlerFunc(func(rw ResponseWriter, req *Request) {
		rw.Header().Set("Con
```