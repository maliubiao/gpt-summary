Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - The Big Picture:**

The first thing I notice is the import statement `package http_test`. This immediately tells me this code is part of the standard Go library's `net/http` package, specifically its *testing* infrastructure. The comment `// Tests that use both the client & server, in both HTTP/1 and HTTP/2 mode.` reinforces this. The filename `clientserver_test.go` further confirms it's about testing interactions between HTTP clients and servers.

**2. Identifying Key Data Structures and Functions:**

I start scanning the code for important types and functions.

* **`testMode` and constants (`http1Mode`, `https1Mode`, etc.):** These clearly define the different HTTP protocols being tested. This is central to the code's purpose.
* **`run` function:** This function appears to be a test runner. It takes a testing object (`T`), a test function (`f`), and options. The loop iterating over `modes` suggests it runs the test function for each specified HTTP mode. The `parallel` flag indicates control over parallel test execution.
* **`newClientServerTest` function:**  This looks like a helper to set up a testing environment. It takes a `testMode`, a `Handler`, and options. The name strongly suggests it creates both a client and a server for testing. The options seem to allow customization of the server and client.
* **`clientServerTest` struct:**  This struct likely holds the components of the test environment: the testing object, the HTTP handler, the test server (`httptest.Server`), the transport (`Transport`), and the client (`Client`).
* **`h12Compare` struct:**  This struct is interesting. The name implies it's used to compare behavior between HTTP/1 and HTTP/2. It has fields for a handler, request function, and response checking functions. This is a powerful abstraction for writing cross-protocol tests.

**3. Deeper Dive into Core Functions:**

* **`run` function's logic:** I analyze the options handling. It extracts the `modes` and the `parallel` flag. It then iterates through the `modes`, running the provided test function `f` within a subtest named after the mode. This setup is crucial for organized testing across different protocols.
* **`newClientServerTest` function's logic:**  I observe how it sets up the `httptest.Server`. It handles different modes (HTTP/1, HTTPS/1, HTTP/2, unencrypted HTTP/2). The use of `httptest.NewUnstartedServer` and then starting it with `Start()`, `StartTLS()`, etc., depending on the mode, is important. The handling of the `optFakeNet` option points to a capability for isolated testing using a mock network. The configuration of the `Transport` based on the mode is also key.
* **`h12Compare` function's `run` method:**  This function sets up two `clientServerTest` instances, one for HTTP/1 and one for HTTP/2. It executes the request function on both and then compares the responses. The `normalizeRes` function suggests a way to make the responses more comparable by removing protocol-specific differences (like the `Date` header).

**4. Identifying Patterns and Abstractions:**

The code heavily uses functional options (`opts ...any`) for configuring the test environment. This is a common and clean pattern in Go. The `h12Compare` struct and its `run` method demonstrate a clear design pattern for writing tests that verify consistency across different HTTP versions.

**5. Inferring Functionality and Purpose:**

Based on the identified components and their interactions, I can deduce the overall functionality:

* **Comprehensive HTTP Client-Server Testing:** The code provides a framework for writing tests that exercise the Go HTTP client and server implementations.
* **HTTP/1.1 and HTTP/2 Support:**  A primary goal is to ensure that the client and server behave correctly under both HTTP/1.1 and HTTP/2.
* **Test Organization:** The `run` function and subtests provide a structured way to organize and execute tests for different HTTP modes.
* **Test Environment Setup:**  `newClientServerTest` simplifies the process of creating a test server and client with the desired configuration.
* **Cross-Protocol Comparison:** `h12Compare` allows for direct comparison of behavior between HTTP/1.1 and HTTP/2, ensuring consistency where expected.
* **Flexibility and Customization:** The use of functional options allows for flexible configuration of the test environment.

**6. Considering Potential Go Language Features:**

The code demonstrates several key Go features:

* **Interfaces:**  The `TBRun` interface is used for type-safe testing. The `Handler` interface is fundamental to Go's HTTP server implementation. `io.Reader`, `io.Writer`, `io.ReadCloser` are used extensively.
* **Structs and Methods:**  The code defines several structs (`clientServerTest`, `h12Compare`, etc.) with associated methods.
* **Goroutines and Concurrency:** The `run` function uses `t.Parallel()` suggesting support for concurrent test execution. The `TestConcurrentReadWriteReqBody` function explicitly tests concurrent behavior.
* **Closures and Anonymous Functions:** The handlers in the tests are often defined as anonymous functions.
* **Reflection:** The `reflect.DeepEqual` function is used for comparing complex data structures.
* **Error Handling:**  The code consistently checks for errors and uses `t.Fatal` or `t.Error` for reporting failures.
* **Testing Package:** The code heavily relies on the `testing` package for its infrastructure.
* **`net/http/httptest`:**  This package is used to create lightweight HTTP servers for testing.
* **Functional Options:** As mentioned earlier, this is a prominent pattern.

**7. Drafting the Explanation:**

Finally, I structure my explanation based on the deductions above, focusing on the main functionalities, potential Go features demonstrated, and how the code facilitates testing. I use clear and concise language, providing examples where appropriate. I also think about potential user errors based on the code structure (like forgetting to close response bodies).
这是对 Go 语言 `net/http` 包中 `clientserver_test.go` 文件一部分代码的分析。 这段代码的主要目的是构建一个测试框架，用于测试 HTTP 客户端和服务器在不同 HTTP 协议版本（HTTP/1.1 和 HTTP/2）下的交互行为。

**功能归纳:**

这段代码的核心功能是提供了一套工具和方法，用于方便地创建和运行集成测试，这些测试涉及到一个 HTTP 客户端向一个 HTTP 服务器发起请求并处理响应。 它主要关注以下几个方面：

1. **多协议支持测试:**  它允许测试在 HTTP/1.1 和 HTTP/2 两种协议下的客户端和服务端交互。
2. **灵活的测试配置:**  它提供了一种灵活的方式来配置测试环境，包括指定使用的 HTTP 协议版本，以及通过选项配置服务器和客户端的行为。
3. **简化测试用例编写:**  它封装了一些常用的测试设置，例如创建测试服务器和客户端，使得编写测试用例更加简洁。
4. **HTTP/1 和 HTTP/2 行为对比:**  它提供了一种机制 (`h12Compare`) 来对比 HTTP/1.1 和 HTTP/2 在处理相同请求时的行为差异，这对于确保两种协议实现的一致性非常重要。
5. **支持同步测试环境:**  它考虑了在 `synctest` 环境下进行测试的需求，并提供了相应的支持。

**推断的 Go 语言功能实现及代码举例:**

这段代码主要围绕 Go 语言标准库中的 `net/http` 和 `testing` 包进行构建。它展示了以下 Go 语言功能的运用：

* **`net/http` 包的核心概念:**
    * **`Handler` 接口:**  用于定义服务器端处理请求的逻辑。
    * **`Request` 结构体:**  表示客户端发起的 HTTP 请求。
    * **`Response` 结构体:**  表示服务器返回的 HTTP 响应。
    * **`ResponseWriter` 接口:**  用于服务器端构建 HTTP 响应。
    * **`Client` 结构体:**  用于发起 HTTP 请求。
    * **`Transport` 结构体:**  控制 HTTP 客户端的底层行为，例如连接池管理、TLS 配置等。
    * **`httptest` 包:**  提供用于 HTTP 测试的工具，例如 `httptest.Server` 用于创建测试服务器。
* **`testing` 包:**  用于编写和运行测试。
* **接口和类型断言:**  例如 `w.(Flusher).Flush()`，用于调用特定接口的方法。
* **匿名函数 (closures):**  在 `run` 函数和 `newClientServerTest` 函数中，使用了匿名函数作为参数，方便地定义了测试逻辑和配置。
* **变长参数 (variadic functions):**  例如 `run(t T, f func(t T, mode testMode), opts ...any)` 和 `newClientServerTest(t testing.TB, mode testMode, h Handler, opts ...any)`，用于接收不同类型的配置选项。
* **结构体和方法:**  定义了 `testMode`, `clientServerTest`, `h12Compare` 等结构体，并为其定义了方法。
* **Goroutines 和并发:**  虽然这段代码本身没有直接展示 `go` 关键字的使用，但 `run` 函数中调用了 `t.Parallel()`，表明测试用例可以并行执行。`TestConcurrentReadWriteReqBody` 函数就明确展示了并发读写请求体的测试。
* **类型参数 (Generics):**  `TBRun[T any]` 是一个泛型接口，用于约束 `run` 函数的第一个参数。

**Go 代码举例:**

以下是一个基于这段代码框架的简单测试用例示例，用于测试一个简单的 HTTP 服务器：

```go
package http_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"
)

func TestSimpleServer(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, World!")
	})

	testFunc := func(t *testing.T, mode testMode) {
		cst := newClientServerTest(t, mode, handler)
		defer cst.close()

		resp, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			t.Fatalf("Get request failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Error reading response body: %v", err)
		}

		if string(body) != "Hello, World!" {
			t.Errorf("Unexpected response body: %q", string(body))
		}
	}

	run(t, testFunc)
}
```

**假设的输入与输出:**

在上面的 `TestSimpleServer` 例子中：

* **假设输入:**  一个 HTTP GET 请求被发送到测试服务器。
* **预期输出:**  服务器返回一个 HTTP 响应，状态码为 200 OK，并且响应体为 "Hello, World!"。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个测试框架，用于组织和运行测试用例。Go 语言的 `go test` 命令用于执行测试，它有一些标准的命令行参数，例如：

* `-v`:  显示更详细的测试输出。
* `-run <正则表达式>`:  只运行匹配指定正则表达式的测试用例。
* `-count <n>`:  多次运行每个测试用例。

这些参数是 `go test` 命令提供的，而不是这段代码本身处理的。

**使用者易犯错的点:**

这段代码定义了测试框架，使用者在使用时可能犯的错误包括：

* **忘记关闭响应体:**  在测试用例中，读取完响应体后，需要调用 `resp.Body.Close()` 关闭连接，否则可能导致资源泄漏。 例如，在上面的 `TestSimpleServer` 示例中，如果遗漏 `defer resp.Body.Close()`，就可能造成问题。
* **不理解 `run` 函数的用法:**  `run` 函数负责在不同的 HTTP 协议模式下运行测试用例，使用者需要理解如何正确地使用它来覆盖不同的协议。
* **对 `h12Compare` 的误用:** `h12Compare` 用于对比 HTTP/1 和 HTTP/2 的行为，使用者需要确保提供的 `Handler` 在两种协议下行为是可比较的。
* **不正确地配置测试服务器或客户端:** `newClientServerTest` 接受选项参数来配置服务器和客户端，使用者可能不熟悉这些选项的作用和使用方法。

总而言之，这段代码是 `net/http` 包测试套件的关键组成部分，它提供了一个强大且灵活的框架，用于验证 HTTP 客户端和服务器在不同场景下的正确性。 它体现了 Go 语言在构建可测试和可靠的网络应用方面的优势。

Prompt: 
```
这是路径为go/src/net/http/clientserver_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests that use both the client & server, in both HTTP/1 and HTTP/2 mode.

package http_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"hash"
	"internal/synctest"
	"io"
	"log"
	"maps"
	"net"
	. "net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testMode string

const (
	http1Mode            = testMode("h1")            // HTTP/1.1
	https1Mode           = testMode("https1")        // HTTPS/1.1
	http2Mode            = testMode("h2")            // HTTP/2
	http2UnencryptedMode = testMode("h2unencrypted") // HTTP/2
)

type testNotParallelOpt struct{}

var (
	testNotParallel = testNotParallelOpt{}
)

type TBRun[T any] interface {
	testing.TB
	Run(string, func(T)) bool
}

// run runs a client/server test in a variety of test configurations.
//
// Tests execute in HTTP/1.1 and HTTP/2 modes by default.
// To run in a different set of configurations, pass a []testMode option.
//
// Tests call t.Parallel() by default.
// To disable parallel execution, pass the testNotParallel option.
func run[T TBRun[T]](t T, f func(t T, mode testMode), opts ...any) {
	t.Helper()
	modes := []testMode{http1Mode, http2Mode}
	parallel := true
	for _, opt := range opts {
		switch opt := opt.(type) {
		case []testMode:
			modes = opt
		case testNotParallelOpt:
			parallel = false
		default:
			t.Fatalf("unknown option type %T", opt)
		}
	}
	if t, ok := any(t).(*testing.T); ok && parallel {
		setParallel(t)
	}
	for _, mode := range modes {
		t.Run(string(mode), func(t T) {
			t.Helper()
			if t, ok := any(t).(*testing.T); ok && parallel {
				setParallel(t)
			}
			t.Cleanup(func() {
				afterTest(t)
			})
			f(t, mode)
		})
	}
}

// cleanupT wraps a testing.T and adds its own Cleanup method.
// Used to execute cleanup functions within a synctest bubble.
type cleanupT struct {
	*testing.T
	cleanups []func()
}

// Cleanup replaces T.Cleanup.
func (t *cleanupT) Cleanup(f func()) {
	t.cleanups = append(t.cleanups, f)
}

func (t *cleanupT) done() {
	for _, f := range slices.Backward(t.cleanups) {
		f()
	}
}

// runSynctest is run combined with synctest.Run.
//
// The TB passed to f arranges for cleanup functions to be run in the synctest bubble.
func runSynctest(t *testing.T, f func(t testing.TB, mode testMode), opts ...any) {
	run(t, func(t *testing.T, mode testMode) {
		synctest.Run(func() {
			ct := &cleanupT{T: t}
			defer ct.done()
			f(ct, mode)
		})
	}, opts...)
}

type clientServerTest struct {
	t  testing.TB
	h2 bool
	h  Handler
	ts *httptest.Server
	tr *Transport
	c  *Client
	li *fakeNetListener
}

func (t *clientServerTest) close() {
	t.tr.CloseIdleConnections()
	t.ts.Close()
}

func (t *clientServerTest) getURL(u string) string {
	res, err := t.c.Get(u)
	if err != nil {
		t.t.Fatal(err)
	}
	defer res.Body.Close()
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		t.t.Fatal(err)
	}
	return string(slurp)
}

func (t *clientServerTest) scheme() string {
	if t.h2 {
		return "https"
	}
	return "http"
}

var optQuietLog = func(ts *httptest.Server) {
	ts.Config.ErrorLog = quietLog
}

func optWithServerLog(lg *log.Logger) func(*httptest.Server) {
	return func(ts *httptest.Server) {
		ts.Config.ErrorLog = lg
	}
}

var optFakeNet = new(struct{})

// newClientServerTest creates and starts an httptest.Server.
//
// The mode parameter selects the implementation to test:
// HTTP/1, HTTP/2, etc. Tests using newClientServerTest should use
// the 'run' function, which will start a subtests for each tested mode.
//
// The vararg opts parameter can include functions to configure the
// test server or transport.
//
//	func(*httptest.Server) // run before starting the server
//	func(*http.Transport)
//
// The optFakeNet option configures the server and client to use a fake network implementation,
// suitable for use in testing/synctest tests.
func newClientServerTest(t testing.TB, mode testMode, h Handler, opts ...any) *clientServerTest {
	if mode == http2Mode {
		CondSkipHTTP2(t)
	}
	cst := &clientServerTest{
		t:  t,
		h2: mode == http2Mode,
		h:  h,
	}

	var transportFuncs []func(*Transport)

	if idx := slices.Index(opts, any(optFakeNet)); idx >= 0 {
		opts = slices.Delete(opts, idx, idx+1)
		cst.li = fakeNetListen()
		cst.ts = &httptest.Server{
			Config:   &Server{Handler: h},
			Listener: cst.li,
		}
		transportFuncs = append(transportFuncs, func(tr *Transport) {
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return cst.li.connect(), nil
			}
		})
	} else {
		cst.ts = httptest.NewUnstartedServer(h)
	}

	if mode == http2UnencryptedMode {
		p := &Protocols{}
		p.SetUnencryptedHTTP2(true)
		cst.ts.Config.Protocols = p
	}

	for _, opt := range opts {
		switch opt := opt.(type) {
		case func(*Transport):
			transportFuncs = append(transportFuncs, opt)
		case func(*httptest.Server):
			opt(cst.ts)
		default:
			t.Fatalf("unhandled option type %T", opt)
		}
	}

	if cst.ts.Config.ErrorLog == nil {
		cst.ts.Config.ErrorLog = log.New(testLogWriter{t}, "", 0)
	}

	switch mode {
	case http1Mode:
		cst.ts.Start()
	case https1Mode:
		cst.ts.StartTLS()
	case http2UnencryptedMode:
		ExportHttp2ConfigureServer(cst.ts.Config, nil)
		cst.ts.Start()
	case http2Mode:
		ExportHttp2ConfigureServer(cst.ts.Config, nil)
		cst.ts.TLS = cst.ts.Config.TLSConfig
		cst.ts.StartTLS()
	default:
		t.Fatalf("unknown test mode %v", mode)
	}
	cst.c = cst.ts.Client()
	cst.tr = cst.c.Transport.(*Transport)
	if mode == http2Mode || mode == http2UnencryptedMode {
		if err := ExportHttp2ConfigureTransport(cst.tr); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range transportFuncs {
		f(cst.tr)
	}

	if mode == http2UnencryptedMode {
		p := &Protocols{}
		p.SetUnencryptedHTTP2(true)
		cst.tr.Protocols = p
	}

	t.Cleanup(func() {
		cst.close()
	})
	return cst
}

type testLogWriter struct {
	t testing.TB
}

func (w testLogWriter) Write(b []byte) (int, error) {
	w.t.Logf("server log: %v", strings.TrimSpace(string(b)))
	return len(b), nil
}

// Testing the newClientServerTest helper itself.
func TestNewClientServerTest(t *testing.T) {
	modes := []testMode{http1Mode, https1Mode, http2Mode}
	t.Run("realnet", func(t *testing.T) {
		run(t, func(t *testing.T, mode testMode) {
			testNewClientServerTest(t, mode)
		}, modes)
	})
	t.Run("synctest", func(t *testing.T) {
		runSynctest(t, func(t testing.TB, mode testMode) {
			testNewClientServerTest(t, mode, optFakeNet)
		}, modes)
	})
}
func testNewClientServerTest(t testing.TB, mode testMode, opts ...any) {
	var got struct {
		sync.Mutex
		proto  string
		hasTLS bool
	}
	h := HandlerFunc(func(w ResponseWriter, r *Request) {
		got.Lock()
		defer got.Unlock()
		got.proto = r.Proto
		got.hasTLS = r.TLS != nil
	})
	cst := newClientServerTest(t, mode, h, opts...)
	if _, err := cst.c.Head(cst.ts.URL); err != nil {
		t.Fatal(err)
	}
	var wantProto string
	var wantTLS bool
	switch mode {
	case http1Mode:
		wantProto = "HTTP/1.1"
		wantTLS = false
	case https1Mode:
		wantProto = "HTTP/1.1"
		wantTLS = true
	case http2Mode:
		wantProto = "HTTP/2.0"
		wantTLS = true
	}
	if got.proto != wantProto {
		t.Errorf("req.Proto = %q, want %q", got.proto, wantProto)
	}
	if got.hasTLS != wantTLS {
		t.Errorf("req.TLS set: %v, want %v", got.hasTLS, wantTLS)
	}
}

func TestChunkedResponseHeaders(t *testing.T) { run(t, testChunkedResponseHeaders) }
func testChunkedResponseHeaders(t *testing.T, mode testMode) {
	log.SetOutput(io.Discard) // is noisy otherwise
	defer log.SetOutput(os.Stderr)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "intentional gibberish") // we check that this is deleted
		w.(Flusher).Flush()
		fmt.Fprintf(w, "I am a chunked response.")
	}))

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	defer res.Body.Close()
	if g, e := res.ContentLength, int64(-1); g != e {
		t.Errorf("expected ContentLength of %d; got %d", e, g)
	}
	wantTE := []string{"chunked"}
	if mode == http2Mode {
		wantTE = nil
	}
	if !slices.Equal(res.TransferEncoding, wantTE) {
		t.Errorf("TransferEncoding = %v; want %v", res.TransferEncoding, wantTE)
	}
	if got, haveCL := res.Header["Content-Length"]; haveCL {
		t.Errorf("Unexpected Content-Length: %q", got)
	}
}

type reqFunc func(c *Client, url string) (*Response, error)

// h12Compare is a test that compares HTTP/1 and HTTP/2 behavior
// against each other.
type h12Compare struct {
	Handler            func(ResponseWriter, *Request)    // required
	ReqFunc            reqFunc                           // optional
	CheckResponse      func(proto string, res *Response) // optional
	EarlyCheckResponse func(proto string, res *Response) // optional; pre-normalize
	Opts               []any
}

func (tt h12Compare) reqFunc() reqFunc {
	if tt.ReqFunc == nil {
		return (*Client).Get
	}
	return tt.ReqFunc
}

func (tt h12Compare) run(t *testing.T) {
	setParallel(t)
	cst1 := newClientServerTest(t, http1Mode, HandlerFunc(tt.Handler), tt.Opts...)
	defer cst1.close()
	cst2 := newClientServerTest(t, http2Mode, HandlerFunc(tt.Handler), tt.Opts...)
	defer cst2.close()

	res1, err := tt.reqFunc()(cst1.c, cst1.ts.URL)
	if err != nil {
		t.Errorf("HTTP/1 request: %v", err)
		return
	}
	res2, err := tt.reqFunc()(cst2.c, cst2.ts.URL)
	if err != nil {
		t.Errorf("HTTP/2 request: %v", err)
		return
	}

	if fn := tt.EarlyCheckResponse; fn != nil {
		fn("HTTP/1.1", res1)
		fn("HTTP/2.0", res2)
	}

	tt.normalizeRes(t, res1, "HTTP/1.1")
	tt.normalizeRes(t, res2, "HTTP/2.0")
	res1body, res2body := res1.Body, res2.Body

	eres1 := mostlyCopy(res1)
	eres2 := mostlyCopy(res2)
	if !reflect.DeepEqual(eres1, eres2) {
		t.Errorf("Response headers to handler differed:\nhttp/1 (%v):\n\t%#v\nhttp/2 (%v):\n\t%#v",
			cst1.ts.URL, eres1, cst2.ts.URL, eres2)
	}
	if !reflect.DeepEqual(res1body, res2body) {
		t.Errorf("Response bodies to handler differed.\nhttp1: %v\nhttp2: %v\n", res1body, res2body)
	}
	if fn := tt.CheckResponse; fn != nil {
		res1.Body, res2.Body = res1body, res2body
		fn("HTTP/1.1", res1)
		fn("HTTP/2.0", res2)
	}
}

func mostlyCopy(r *Response) *Response {
	c := *r
	c.Body = nil
	c.TransferEncoding = nil
	c.TLS = nil
	c.Request = nil
	return &c
}

type slurpResult struct {
	io.ReadCloser
	body []byte
	err  error
}

func (sr slurpResult) String() string { return fmt.Sprintf("body %q; err %v", sr.body, sr.err) }

func (tt h12Compare) normalizeRes(t *testing.T, res *Response, wantProto string) {
	if res.Proto == wantProto || res.Proto == "HTTP/IGNORE" {
		res.Proto, res.ProtoMajor, res.ProtoMinor = "", 0, 0
	} else {
		t.Errorf("got %q response; want %q", res.Proto, wantProto)
	}
	slurp, err := io.ReadAll(res.Body)

	res.Body.Close()
	res.Body = slurpResult{
		ReadCloser: io.NopCloser(bytes.NewReader(slurp)),
		body:       slurp,
		err:        err,
	}
	for i, v := range res.Header["Date"] {
		res.Header["Date"][i] = strings.Repeat("x", len(v))
	}
	if res.Request == nil {
		t.Errorf("for %s, no request", wantProto)
	}
	if (res.TLS != nil) != (wantProto == "HTTP/2.0") {
		t.Errorf("TLS set = %v; want %v", res.TLS != nil, res.TLS == nil)
	}
}

// Issue 13532
func TestH12_HeadContentLengthNoBody(t *testing.T) {
	h12Compare{
		ReqFunc: (*Client).Head,
		Handler: func(w ResponseWriter, r *Request) {
		},
	}.run(t)
}

func TestH12_HeadContentLengthSmallBody(t *testing.T) {
	h12Compare{
		ReqFunc: (*Client).Head,
		Handler: func(w ResponseWriter, r *Request) {
			io.WriteString(w, "small")
		},
	}.run(t)
}

func TestH12_HeadContentLengthLargeBody(t *testing.T) {
	h12Compare{
		ReqFunc: (*Client).Head,
		Handler: func(w ResponseWriter, r *Request) {
			chunk := strings.Repeat("x", 512<<10)
			for i := 0; i < 10; i++ {
				io.WriteString(w, chunk)
			}
		},
	}.run(t)
}

func TestH12_200NoBody(t *testing.T) {
	h12Compare{Handler: func(w ResponseWriter, r *Request) {}}.run(t)
}

func TestH2_204NoBody(t *testing.T) { testH12_noBody(t, 204) }
func TestH2_304NoBody(t *testing.T) { testH12_noBody(t, 304) }
func TestH2_404NoBody(t *testing.T) { testH12_noBody(t, 404) }

func testH12_noBody(t *testing.T, status int) {
	h12Compare{Handler: func(w ResponseWriter, r *Request) {
		w.WriteHeader(status)
	}}.run(t)
}

func TestH12_SmallBody(t *testing.T) {
	h12Compare{Handler: func(w ResponseWriter, r *Request) {
		io.WriteString(w, "small body")
	}}.run(t)
}

func TestH12_ExplicitContentLength(t *testing.T) {
	h12Compare{Handler: func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "3")
		io.WriteString(w, "foo")
	}}.run(t)
}

func TestH12_FlushBeforeBody(t *testing.T) {
	h12Compare{Handler: func(w ResponseWriter, r *Request) {
		w.(Flusher).Flush()
		io.WriteString(w, "foo")
	}}.run(t)
}

func TestH12_FlushMidBody(t *testing.T) {
	h12Compare{Handler: func(w ResponseWriter, r *Request) {
		io.WriteString(w, "foo")
		w.(Flusher).Flush()
		io.WriteString(w, "bar")
	}}.run(t)
}

func TestH12_Head_ExplicitLen(t *testing.T) {
	h12Compare{
		ReqFunc: (*Client).Head,
		Handler: func(w ResponseWriter, r *Request) {
			if r.Method != "HEAD" {
				t.Errorf("unexpected method %q", r.Method)
			}
			w.Header().Set("Content-Length", "1235")
		},
	}.run(t)
}

func TestH12_Head_ImplicitLen(t *testing.T) {
	h12Compare{
		ReqFunc: (*Client).Head,
		Handler: func(w ResponseWriter, r *Request) {
			if r.Method != "HEAD" {
				t.Errorf("unexpected method %q", r.Method)
			}
			io.WriteString(w, "foo")
		},
	}.run(t)
}

func TestH12_HandlerWritesTooLittle(t *testing.T) {
	h12Compare{
		Handler: func(w ResponseWriter, r *Request) {
			w.Header().Set("Content-Length", "3")
			io.WriteString(w, "12") // one byte short
		},
		CheckResponse: func(proto string, res *Response) {
			sr, ok := res.Body.(slurpResult)
			if !ok {
				t.Errorf("%s body is %T; want slurpResult", proto, res.Body)
				return
			}
			if sr.err != io.ErrUnexpectedEOF {
				t.Errorf("%s read error = %v; want io.ErrUnexpectedEOF", proto, sr.err)
			}
			if string(sr.body) != "12" {
				t.Errorf("%s body = %q; want %q", proto, sr.body, "12")
			}
		},
	}.run(t)
}

// Tests that the HTTP/1 and HTTP/2 servers prevent handlers from
// writing more than they declared. This test does not test whether
// the transport deals with too much data, though, since the server
// doesn't make it possible to send bogus data. For those tests, see
// transport_test.go (for HTTP/1) or x/net/http2/transport_test.go
// (for HTTP/2).
func TestHandlerWritesTooMuch(t *testing.T) { run(t, testHandlerWritesTooMuch) }
func testHandlerWritesTooMuch(t *testing.T, mode testMode) {
	wantBody := []byte("123")
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		rc := NewResponseController(w)
		w.Header().Set("Content-Length", fmt.Sprintf("%v", len(wantBody)))
		rc.Flush()
		w.Write(wantBody)
		rc.Flush()
		n, err := io.WriteString(w, "x") // too many
		if err == nil {
			err = rc.Flush()
		}
		// TODO: Check that this is ErrContentLength, not just any error.
		if err == nil {
			t.Errorf("for proto %q, final write = %v, %v; want _, some error", r.Proto, n, err)
		}
	}))

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	gotBody, _ := io.ReadAll(res.Body)
	if !bytes.Equal(gotBody, wantBody) {
		t.Fatalf("got response body: %q; want %q", gotBody, wantBody)
	}
}

// Verify that both our HTTP/1 and HTTP/2 request and auto-decompress gzip.
// Some hosts send gzip even if you don't ask for it; see golang.org/issue/13298
func TestH12_AutoGzip(t *testing.T) {
	h12Compare{
		Handler: func(w ResponseWriter, r *Request) {
			if ae := r.Header.Get("Accept-Encoding"); ae != "gzip" {
				t.Errorf("%s Accept-Encoding = %q; want gzip", r.Proto, ae)
			}
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			io.WriteString(gz, "I am some gzipped content. Go go go go go go go go go go go go should compress well.")
			gz.Close()
		},
	}.run(t)
}

func TestH12_AutoGzip_Disabled(t *testing.T) {
	h12Compare{
		Opts: []any{
			func(tr *Transport) { tr.DisableCompression = true },
		},
		Handler: func(w ResponseWriter, r *Request) {
			fmt.Fprintf(w, "%q", r.Header["Accept-Encoding"])
			if ae := r.Header.Get("Accept-Encoding"); ae != "" {
				t.Errorf("%s Accept-Encoding = %q; want empty", r.Proto, ae)
			}
		},
	}.run(t)
}

// Test304Responses verifies that 304s don't declare that they're
// chunking in their response headers and aren't allowed to produce
// output.
func Test304Responses(t *testing.T) { run(t, test304Responses) }
func test304Responses(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusNotModified)
		_, err := w.Write([]byte("illegal body"))
		if err != ErrBodyNotAllowed {
			t.Errorf("on Write, expected ErrBodyNotAllowed, got %v", err)
		}
	}))
	defer cst.close()
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TransferEncoding) > 0 {
		t.Errorf("expected no TransferEncoding; got %v", res.TransferEncoding)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}
	if len(body) > 0 {
		t.Errorf("got unexpected body %q", string(body))
	}
}

func TestH12_ServerEmptyContentLength(t *testing.T) {
	h12Compare{
		Handler: func(w ResponseWriter, r *Request) {
			w.Header()["Content-Type"] = []string{""}
			io.WriteString(w, "<html><body>hi</body></html>")
		},
	}.run(t)
}

func TestH12_RequestContentLength_Known_NonZero(t *testing.T) {
	h12requestContentLength(t, func() io.Reader { return strings.NewReader("FOUR") }, 4)
}

func TestH12_RequestContentLength_Known_Zero(t *testing.T) {
	h12requestContentLength(t, func() io.Reader { return nil }, 0)
}

func TestH12_RequestContentLength_Unknown(t *testing.T) {
	h12requestContentLength(t, func() io.Reader { return struct{ io.Reader }{strings.NewReader("Stuff")} }, -1)
}

func h12requestContentLength(t *testing.T, bodyfn func() io.Reader, wantLen int64) {
	h12Compare{
		Handler: func(w ResponseWriter, r *Request) {
			w.Header().Set("Got-Length", fmt.Sprint(r.ContentLength))
			fmt.Fprintf(w, "Req.ContentLength=%v", r.ContentLength)
		},
		ReqFunc: func(c *Client, url string) (*Response, error) {
			return c.Post(url, "text/plain", bodyfn())
		},
		CheckResponse: func(proto string, res *Response) {
			if got, want := res.Header.Get("Got-Length"), fmt.Sprint(wantLen); got != want {
				t.Errorf("Proto %q got length %q; want %q", proto, got, want)
			}
		},
	}.run(t)
}

// Tests that closing the Request.Cancel channel also while still
// reading the response body. Issue 13159.
func TestCancelRequestMidBody(t *testing.T) { run(t, testCancelRequestMidBody) }
func testCancelRequestMidBody(t *testing.T, mode testMode) {
	unblock := make(chan bool)
	didFlush := make(chan bool, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, "Hello")
		w.(Flusher).Flush()
		didFlush <- true
		<-unblock
		io.WriteString(w, ", world.")
	}))
	defer close(unblock)

	req, _ := NewRequest("GET", cst.ts.URL, nil)
	cancel := make(chan struct{})
	req.Cancel = cancel

	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	<-didFlush

	// Read a bit before we cancel. (Issue 13626)
	// We should have "Hello" at least sitting there.
	firstRead := make([]byte, 10)
	n, err := res.Body.Read(firstRead)
	if err != nil {
		t.Fatal(err)
	}
	firstRead = firstRead[:n]

	close(cancel)

	rest, err := io.ReadAll(res.Body)
	all := string(firstRead) + string(rest)
	if all != "Hello" {
		t.Errorf("Read %q (%q + %q); want Hello", all, firstRead, rest)
	}
	if err != ExportErrRequestCanceled {
		t.Errorf("ReadAll error = %v; want %v", err, ExportErrRequestCanceled)
	}
}

// Tests that clients can send trailers to a server and that the server can read them.
func TestTrailersClientToServer(t *testing.T) { run(t, testTrailersClientToServer) }
func testTrailersClientToServer(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		slurp, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Server reading request body: %v", err)
		}
		if string(slurp) != "foo" {
			t.Errorf("Server read request body %q; want foo", slurp)
		}
		if r.Trailer == nil {
			io.WriteString(w, "nil Trailer")
		} else {
			decl := slices.Sorted(maps.Keys(r.Trailer))
			fmt.Fprintf(w, "decl: %v, vals: %s, %s",
				decl,
				r.Trailer.Get("Client-Trailer-A"),
				r.Trailer.Get("Client-Trailer-B"))
		}
	}))

	var req *Request
	req, _ = NewRequest("POST", cst.ts.URL, io.MultiReader(
		eofReaderFunc(func() {
			req.Trailer["Client-Trailer-A"] = []string{"valuea"}
		}),
		strings.NewReader("foo"),
		eofReaderFunc(func() {
			req.Trailer["Client-Trailer-B"] = []string{"valueb"}
		}),
	))
	req.Trailer = Header{
		"Client-Trailer-A": nil, //  to be set later
		"Client-Trailer-B": nil, //  to be set later
	}
	req.ContentLength = -1
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := wantBody(res, err, "decl: [Client-Trailer-A Client-Trailer-B], vals: valuea, valueb"); err != nil {
		t.Error(err)
	}
}

// Tests that servers send trailers to a client and that the client can read them.
func TestTrailersServerToClient(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testTrailersServerToClient(t, mode, false)
	})
}
func TestTrailersServerToClientFlush(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		testTrailersServerToClient(t, mode, true)
	})
}

func testTrailersServerToClient(t *testing.T, mode testMode, flush bool) {
	const body = "Some body"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Trailer", "Server-Trailer-A, Server-Trailer-B")
		w.Header().Add("Trailer", "Server-Trailer-C")

		io.WriteString(w, body)
		if flush {
			w.(Flusher).Flush()
		}

		// How handlers set Trailers: declare it ahead of time
		// with the Trailer header, and then mutate the
		// Header() of those values later, after the response
		// has been written (we wrote to w above).
		w.Header().Set("Server-Trailer-A", "valuea")
		w.Header().Set("Server-Trailer-C", "valuec") // skipping B
		w.Header().Set("Server-Trailer-NotDeclared", "should be omitted")
	}))

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	wantHeader := Header{
		"Content-Type": {"text/plain; charset=utf-8"},
	}
	wantLen := -1
	if mode == http2Mode && !flush {
		// In HTTP/1.1, any use of trailers forces HTTP/1.1
		// chunking and a flush at the first write. That's
		// unnecessary with HTTP/2's framing, so the server
		// is able to calculate the length while still sending
		// trailers afterwards.
		wantLen = len(body)
		wantHeader["Content-Length"] = []string{fmt.Sprint(wantLen)}
	}
	if res.ContentLength != int64(wantLen) {
		t.Errorf("ContentLength = %v; want %v", res.ContentLength, wantLen)
	}

	delete(res.Header, "Date") // irrelevant for test
	if !reflect.DeepEqual(res.Header, wantHeader) {
		t.Errorf("Header = %v; want %v", res.Header, wantHeader)
	}

	if got, want := res.Trailer, (Header{
		"Server-Trailer-A": nil,
		"Server-Trailer-B": nil,
		"Server-Trailer-C": nil,
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("Trailer before body read = %v; want %v", got, want)
	}

	if err := wantBody(res, nil, body); err != nil {
		t.Fatal(err)
	}

	if got, want := res.Trailer, (Header{
		"Server-Trailer-A": {"valuea"},
		"Server-Trailer-B": nil,
		"Server-Trailer-C": {"valuec"},
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("Trailer after body read = %v; want %v", got, want)
	}
}

// Don't allow a Body.Read after Body.Close. Issue 13648.
func TestResponseBodyReadAfterClose(t *testing.T) { run(t, testResponseBodyReadAfterClose) }
func testResponseBodyReadAfterClose(t *testing.T, mode testMode) {
	const body = "Some body"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, body)
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if len(data) != 0 || err == nil {
		t.Fatalf("ReadAll returned %q, %v; want error", data, err)
	}
}

func TestConcurrentReadWriteReqBody(t *testing.T) { run(t, testConcurrentReadWriteReqBody) }
func testConcurrentReadWriteReqBody(t *testing.T, mode testMode) {
	const reqBody = "some request body"
	const resBody = "some response body"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		var wg sync.WaitGroup
		wg.Add(2)
		didRead := make(chan bool, 1)
		// Read in one goroutine.
		go func() {
			defer wg.Done()
			data, err := io.ReadAll(r.Body)
			if string(data) != reqBody {
				t.Errorf("Handler read %q; want %q", data, reqBody)
			}
			if err != nil {
				t.Errorf("Handler Read: %v", err)
			}
			didRead <- true
		}()
		// Write in another goroutine.
		go func() {
			defer wg.Done()
			if mode != http2Mode {
				// our HTTP/1 implementation intentionally
				// doesn't permit writes during read (mostly
				// due to it being undefined); if that is ever
				// relaxed, change this.
				<-didRead
			}
			io.WriteString(w, resBody)
		}()
		wg.Wait()
	}))
	req, _ := NewRequest("POST", cst.ts.URL, strings.NewReader(reqBody))
	req.Header.Add("Expect", "100-continue") // just to complicate things
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != resBody {
		t.Errorf("read %q; want %q", data, resBody)
	}
}

func TestConnectRequest(t *testing.T) { run(t, testConnectRequest) }
func testConnectRequest(t *testing.T, mode testMode) {
	gotc := make(chan *Request, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		gotc <- r
	}))

	u, err := url.Parse(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		req  *Request
		want string
	}{
		{
			req: &Request{
				Method: "CONNECT",
				Header: Header{},
				URL:    u,
			},
			want: u.Host,
		},
		{
			req: &Request{
				Method: "CONNECT",
				Header: Header{},
				URL:    u,
				Host:   "example.com:123",
			},
			want: "example.com:123",
		},
	}

	for i, tt := range tests {
		res, err := cst.c.Do(tt.req)
		if err != nil {
			t.Errorf("%d. RoundTrip = %v", i, err)
			continue
		}
		res.Body.Close()
		req := <-gotc
		if req.Method != "CONNECT" {
			t.Errorf("method = %q; want CONNECT", req.Method)
		}
		if req.Host != tt.want {
			t.Errorf("Host = %q; want %q", req.Host, tt.want)
		}
		if req.URL.Host != tt.want {
			t.Errorf("URL.Host = %q; want %q", req.URL.Host, tt.want)
		}
	}
}

func TestTransportUserAgent(t *testing.T) { run(t, testTransportUserAgent) }
func testTransportUserAgent(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "%q", r.Header["User-Agent"])
	}))

	either := func(a, b string) string {
		if mode == http2Mode {
			return b
		}
		return a
	}

	tests := []struct {
		setup func(*Request)
		want  string
	}{
		{
			func(r *Request) {},
			either(`["Go-http-client/1.1"]`, `["Go-http-client/2.0"]`),
		},
		{
			func(r *Request) { r.Header.Set("User-Agent", "foo/1.2.3") },
			`["foo/1.2.3"]`,
		},
		{
			func(r *Request) { r.Header["User-Agent"] = []string{"single", "or", "multiple"} },
			`["single"]`,
		},
		{
			func(r *Request) { r.Header.Set("User-Agent", "") },
			`[]`,
		},
		{
			func(r *Request) { r.Header["User-Agent"] = nil },
			`[]`,
		},
	}
	for i, tt := range tests {
		req, _ := NewRequest("GET", cst.ts.URL, nil)
		tt.setup(req)
		res, err := cst.c.Do(req)
		if err != nil {
			t.Errorf("%d. RoundTrip = %v", i, err)
			continue
		}
		slurp, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Errorf("%d. read body = %v", i, err)
			continue
		}
		if string(slurp) != tt.want {
			t.Errorf("%d. body mismatch.\n got: %s\nwant: %s\n", i, slurp, tt.want)
		}
	}
}

func TestStarRequestMethod(t *testing.T) {
	for _, method := range []string{"FOO", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			run(t, func(t *testing.T, mode testMode) {
				testStarRequest(t, method, mode)
			})
		})
	}
}
func testStarRequest(t *testing.T, method string, mode testMode) {
	gotc := make(chan *Request, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("foo", "bar")
		gotc <- r
		w.(Flusher).Flush()
	}))

	u, err := url.Parse(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "*"

	req := &Request{
		Method: method,
		Header: Header{},
		URL:    u,
	}

	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatalf("RoundTrip = %v", err)
	}
	res.Body.Close()

	wantFoo := "bar"
	wantLen := int64(-1)
	if method == "OPTIONS" {
		wantFoo = ""
		wantLen = 0
	}
	if res.StatusCode != 200 {
		t.Errorf("status code = %v; want %d", res.Status, 200)
	}
	if res.ContentLength != wantLen {
		t.Errorf("content length = %v; want %d", res.ContentLength, wantLen)
	}
	if got := res.Header.Get("foo"); got != wantFoo {
		t.Errorf("response \"foo\" header = %q; want %q", got, wantFoo)
	}
	select {
	case req = <-gotc:
	default:
		req = nil
	}
	if req == nil {
		if method != "OPTIONS" {
			t.Fatalf("handler never got request")
		}
		return
	}
	if req.Method != method {
		t.Errorf("method = %q; want %q", req.Method, method)
	}
	if req.URL.Path != "*" {
		t.Errorf("URL.Path = %q; want *", req.URL.Path)
	}
	if req.RequestURI != "*" {
		t.Errorf("RequestURI = %q; want *", req.RequestURI)
	}
}

// Issue 13957
func TestTransportDiscardsUnneededConns(t *testing.T) {
	run(t, testTransportDiscardsUnneededConns, []testMode{http2Mode})
}
func testTransportDiscardsUnneededConns(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "Hello, %v", r.RemoteAddr)
	}))
	defer cst.close()

	var numOpen, numClose int32 // atomic

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tr := &Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: func(_, addr string) (net.Conn, error) {
			time.Sleep(10 * time.Millisecond)
			rc, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			atomic.AddInt32(&numOpen, 1)
			c := noteCloseConn{rc, func() { atomic.AddInt32(&numClose, 1) }}
			return tls.Client(c, tlsConfig), nil
		},
	}
	if err := ExportHttp2ConfigureTransport(tr); err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()

	c := &Client{Transport: tr}

	const N = 10
	gotBody := make(chan string, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(cst.ts.URL)
			if err != nil {
				// Try to work around spurious connection reset on loaded system.
				// See golang.org/issue/33585 and golang.org/issue/36797.
				time.Sleep(10 * time.Millisecond)
				resp, err = c.Get(cst.ts.URL)
				if err != nil {
					t.Errorf("Get: %v", err)
					return
				}
			}
			defer resp.Body.Close()
			slurp, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Error(err)
			}
			gotBody <- string(slurp)
		}()
	}
	wg.Wait()
	close(gotBody)

	var last string
	for got := range gotBody {
		if last == "" {
			last = got
			continue
		}
		if got != last {
			t.Errorf("Response body changed: %q -> %q", last, got)
		}
	}

	var open, close int32
	for i := 0; i < 150; i++ {
		open, close = atomic.LoadInt32(&numOpen), atomic.LoadInt32(&numClose)
		if open < 1 {
			t.Fatalf("open = %d; want at least", open)
		}
		if close == open-1 {
			// Success
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("%d connections opened, %d closed; want %d to close", open, close, open-1)
}

// tests that Transport doesn't retain a pointer to the provided request.
func TestTransportGCRequest(t *testing.T) {
	run(t, func(t *testing.T, mode testMode) {
		t.Run("Body", func(t *testing.T) { testTransportGCRequest(t, mode, true) })
		t.Run("NoBody", func(t *testing.T) { testTransportGCRequest(t, mode, false) })
	})
}
func testTransportGCRequest(t *testing.T, mode testMode, body bool) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.ReadAll(r.Body)
		if body {
			io.WriteString(w, "Hello.")
		}
	}))

	didGC := make(chan struct{})
	(func() {
		body := strings.NewReader("some body")
		req, _ := NewRequest("POST", cst.ts.URL, body)
		runtime.SetFinalizer(req, func(*Request) { close(didGC) })
	
"""




```