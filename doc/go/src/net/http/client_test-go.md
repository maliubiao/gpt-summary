Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file path `go/src/net/http/client_test.go` strongly suggests this code is for testing the `net/http` package's client-side functionality. The `_test.go` suffix confirms it's a test file.

2. **Scan Imports for Clues:**  Look at the `import` statements. This gives a quick overview of the functionalities being tested:
    * `"bytes"`: Working with byte buffers, likely for request/response bodies.
    * `"context"`: Dealing with request cancellation and deadlines.
    * `"crypto/tls"`:  Testing secure (HTTPS) connections.
    * `"encoding/base64"`:  Might be related to authentication (Basic Auth).
    * `"errors"`: Creating and handling errors.
    * `"fmt"`:  Formatting output (often for test assertions).
    * `"internal/testenv"`:  Likely for managing test environment specifics.
    * `"io"`: Basic input/output operations.
    * `"log"`:  Logging for debugging or error reporting (though less common in final tests).
    * `"net"`:  Lower-level networking functionality (sockets, connections).
    * `. "net/http"`:  Crucially, the package being tested. The dot import makes the package's identifiers directly accessible (like `Get`, `Post`, etc.).
    * `"net/http/cookiejar"`: Testing cookie handling.
    * `"net/http/httptest"`: Using test servers to simulate HTTP interactions.
    * `"net/url"`: Working with URLs.
    * `"reflect"`:  Reflection (less common in basic tests, might indicate more complex scenarios).
    * `"runtime"`:  Accessing runtime information (could be for OS-specific tests).
    * `"strconv"`:  String conversion (e.g., to/from integers for status codes).
    * `"strings"`: String manipulation.
    * `"sync"`:  Concurrency primitives (mutexes, wait groups).
    * `"sync/atomic"`: Atomic operations (for thread-safe counters or flags).
    * `"testing"`: The core Go testing package.
    * `"time"`: Working with time (timeouts, delays).

3. **Examine Top-Level Declarations:** Look for global variables and functions defined outside of test functions.
    * `robotsTxtHandler`:  A simple HTTP handler, likely used in basic `Get` tests.
    * `pedanticReadAll`: A custom reader that rigorously checks `io.Reader` contract compliance. This suggests testing the robustness of body reading.

4. **Identify Test Functions:** Functions starting with `Test` are the actual tests. Note their naming convention (e.g., `TestClient`, `TestClientHead`). This gives a good high-level overview of the areas being tested.

5. **Analyze Individual Test Functions (High-Level):**  Read the names and first few lines of each test function to understand its specific focus:
    * `TestClient`: Basic `Get` request.
    * `TestClientHead`: `HEAD` request testing.
    * `TestGetRequestFormat`, `TestPostRequestFormat`, `TestPostFormRequestFormat`: Testing the structure of outgoing requests for different methods.
    * `TestClientRedirects`, `TestClientRedirectsContext`: Testing HTTP redirect handling, including context propagation.
    * `TestPostRedirects`, `TestDeleteRedirects`:  Testing redirects with specific HTTP methods and status codes.
    * `TestClientRedirectUseResponse`: Testing the `CheckRedirect` function's ability to use the last response.
    * `TestClientRedirectNoLocation`: Testing handling of redirects without a `Location` header.
    * `TestClientRedirect308NoGetBody`: Testing 307/308 redirects when the request body cannot be re-read.
    * `TestClientSendsCookieFromJar`, `TestRedirectCookiesJar`, `TestJarCalls`: Testing cookie management with a custom or default jar.
    * `TestStreamingGet`: Testing streaming responses.
    * `TestClientWrites`: Checking if client writes are buffered.
    * `TestClientInsecureTransport`: Testing insecure (skipping TLS verification) connections.
    * `TestClientErrorWithRequestURI`: Testing error handling for invalid `RequestURI`.
    * `TestClientWithCorrectTLSServerName`, `TestClientWithIncorrectTLSServerName`: Testing TLS `ServerName` configuration.
    * `TestTransportUsesTLSConfigServerName`: Further testing TLS `ServerName` precedence.
    * `TestResponseSetsTLSConnectionState`: Verifying that the `Response` contains TLS connection information.
    * `TestHTTPSClientDetectsHTTPServer`: Testing error handling when an HTTPS client connects to an HTTP server.
    * `TestClientHeadContentLength`: Testing the `Content-Length` header for `HEAD` requests.
    * `TestEmptyPasswordAuth`, `TestBasicAuth`, `TestBasicAuthHeadersPreserved`: Testing HTTP Basic Authentication.

6. **Identify Helper Functions and Structures:**  Look for types and functions that aren't test functions but are used by them:
    * `newClientServerTest`:  A common setup function for creating a test HTTP server and client. This is a very important pattern in `net/http` testing.
    * `recordingTransport`: A custom `Transport` used to inspect the outgoing request without actually making a network call.
    * `TestJar`, `RecordingJar`: Custom `http.CookieJar` implementations for testing cookie behavior.
    * `matchReturnedCookies`: A helper to compare expected and received cookies.
    * `run`: A function likely used to execute tests with different test modes (HTTP/1.1, HTTP/2, etc.). The `testMode` type is also relevant here (though not shown in this snippet).
    * `setParallel`, `afterTest`: Standard testing utilities.
    * `removeCommonLines`: A helper for diffing multiline strings, likely used for comparing request logs.

7. **Synthesize the Functionality Summary:** Based on the above analysis, group the tests into logical categories and describe the overall purpose of the file. Focus on the major areas of client functionality being tested.

8. **Look for Specific Go Language Features:**  Note the use of:
    * **`.` import:**  For direct access to `net/http` identifiers.
    * **`httptest` package:** For easy setup of test servers.
    * **Custom `Transport`:**  For intercepting and inspecting requests.
    * **Custom `CookieJar`:** For detailed cookie testing.
    * **Contexts:** For managing request cancellation.
    * **`CheckRedirect` hook:** For customizing redirect behavior.

9. **Construct Code Examples (If Requested):** Choose a representative test function (e.g., `TestClient`) and explain the code, including setup, execution, and assertions. Invent reasonable input and output scenarios if necessary to illustrate the test's purpose.

10. **Address Specific Instructions:**  Make sure to cover all the points raised in the prompt, such as:
    * Listing functionalities.
    * Providing code examples.
    * Inferring Go features.
    * Describing command-line arguments (if any are relevant, though unlikely in this specific test file).
    * Identifying common mistakes (based on the tests themselves - what edge cases are they trying to catch?).

By following this structured approach, you can effectively analyze even relatively large code snippets and extract the key information. The key is to start broad and then progressively narrow down your focus, using the code itself as your primary source of information.
这个Go语言源文件 `go/src/net/http/client_test.go` 的一部分，主要用于测试 `net/http` 包中客户端（`Client`）的各项功能。

**功能归纳：**

这部分代码主要测试了以下 `net/http.Client` 的核心功能：

1. **基本的HTTP请求方法 (GET, HEAD, POST, POSTForm):**  验证客户端能够正确发起这些请求，并能设置正确的请求头、URL和请求体。

2. **HTTP重定向处理:** 测试客户端是否能够按照HTTP协议处理各种重定向状态码 (301, 302, 303, 307, 308)，包括：
    * 默认的重定向次数限制。
    * 自定义重定向策略 (`CheckRedirect` 字段)。
    * 重定向时的 Referer 头部的设置。
    * 重定向请求的上下文 (Context) 的继承。
    * 不同HTTP方法在重定向时的行为差异 (例如，POST 请求在某些重定向状态码下会变成 GET 请求)。
    * 当重定向响应没有 `Location` 头部时的处理。
    * 当无法重新发送请求体 (例如，`GetBody` 为 `nil`) 时对 307/308 重定向的处理。

3. **Cookie管理:** 测试客户端如何与 `http.CookieJar` 协同工作来发送和接收 Cookie。

4. **HTTPS支持:**
    * 测试客户端能够处理不安全的连接 (跳过 TLS 验证)。
    * 测试客户端能够设置正确的 TLS Server Name (SNI)。
    * 测试客户端在连接到 HTTP 服务时，如果使用 HTTPS 协议，能够检测到错误。
    * 验证 `Response` 对象中是否正确设置了 `TLSConnectionState`。

5. **身份验证 (Basic Auth):** 测试客户端如何通过 URL 中的用户名密码或者 `SetBasicAuth` 方法设置 `Authorization` 请求头。

**Go语言功能的实现举例：**

**1. 发起 GET 请求并检查响应体:**

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func main() {
	// 假设我们有一个运行在 http://example.com/robots.txt 的服务器，返回 robots.txt 内容
	resp, err := http.Get("http://example.com/robots.txt")
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应体失败:", err)
		return
	}

	if strings.HasPrefix(string(body), "User-agent:") {
		fmt.Println("成功获取 robots.txt 内容!")
	} else {
		fmt.Println("响应体内容不符合预期:", string(body))
	}
}
```

**假设的输入与输出：**

* **假设的输入:** 访问 `http://example.com/robots.txt`，该 URL 对应的服务器返回以下内容：
  ```
  User-agent: *
  Disallow: /admin/
  ```
* **假设的输出:** `成功获取 robots.txt 内容!`

**2. 处理 HTTP 重定向:**

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	// 假设 http://example.com/old-page 会重定向到 http://example.com/new-page
	resp, err := http.Get("http://example.com/old-page")
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("最终访问的 URL:", resp.Request.URL.String())
}
```

**假设的输入与输出：**

* **假设的输入:** 访问 `http://example.com/old-page`，该 URL 对应的服务器返回 302 重定向到 `http://example.com/new-page`。
* **假设的输出:** `最终访问的 URL: http://example.com/new-page`

**命令行参数的具体处理：**

这段代码主要是单元测试，不涉及命令行参数的具体处理。`net/http` 包本身在创建服务器时会用到端口号等参数，但这些参数通常是在程序内部配置，而不是通过命令行传递给测试用例。

**使用者易犯错的点：**

在 `net/http.Client` 的使用中，以下是一些容易犯错的点 (尽管这段测试代码没有直接展示这些错误，但它测试的功能与这些错误密切相关)：

* **忘记关闭响应体 (Response Body):**  如果不关闭 `resp.Body`，会导致资源泄露。测试代码中的 `defer resp.Body.Close()` 就是为了避免这个问题。

* **不正确处理重定向:**  默认的 `Client` 会自动处理一定次数的重定向，但如果需要自定义重定向行为 (例如，禁止重定向)，则需要设置 `Client.CheckRedirect` 字段。忘记设置或设置不当会导致程序行为不符合预期。

* **HTTPS 连接的证书问题:**  在生产环境中，通常需要验证服务器的 TLS 证书。如果使用了自签名证书或者域名不匹配，可能会遇到连接错误。测试代码中通过 `InsecureSkipVerify` 允许跳过证书验证，但这在生产环境是危险的。

* **Cookie 的管理:**  如果不使用 `http.CookieJar`，客户端默认不会保存和发送 Cookie。如果应用程序依赖 Cookie 来维持会话状态，则需要正确配置和使用 `CookieJar`。

* **并发请求的安全性:** `http.Client` 的零值是可用的，但其内部的 `Transport` 可能是共享的。在高并发场景下，建议创建自定义的 `Client` 并配置其 `Transport` 以获得更好的控制和性能。

总而言之，这段代码通过一系列的测试用例，覆盖了 `net/http.Client` 的核心功能，确保其在各种场景下能够按照预期工作，并帮助开发者理解和正确使用 HTTP 客户端。

Prompt: 
```
这是路径为go/src/net/http/client_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for client.go

package http_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"log"
	"net"
	. "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var robotsTxtHandler = HandlerFunc(func(w ResponseWriter, r *Request) {
	w.Header().Set("Last-Modified", "sometime")
	fmt.Fprintf(w, "User-agent: go\nDisallow: /something/")
})

// pedanticReadAll works like io.ReadAll but additionally
// verifies that r obeys the documented io.Reader contract.
func pedanticReadAll(r io.Reader) (b []byte, err error) {
	var bufa [64]byte
	buf := bufa[:]
	for {
		n, err := r.Read(buf)
		if n == 0 && err == nil {
			return nil, fmt.Errorf("Read: n=0 with err=nil")
		}
		b = append(b, buf[:n]...)
		if err == io.EOF {
			n, err := r.Read(buf)
			if n != 0 || err != io.EOF {
				return nil, fmt.Errorf("Read: n=%d err=%#v after EOF", n, err)
			}
			return b, nil
		}
		if err != nil {
			return b, err
		}
	}
}

func TestClient(t *testing.T) { run(t, testClient) }
func testClient(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, robotsTxtHandler).ts

	c := ts.Client()
	r, err := c.Get(ts.URL)
	var b []byte
	if err == nil {
		b, err = pedanticReadAll(r.Body)
		r.Body.Close()
	}
	if err != nil {
		t.Error(err)
	} else if s := string(b); !strings.HasPrefix(s, "User-agent:") {
		t.Errorf("Incorrect page body (did not begin with User-agent): %q", s)
	}
}

func TestClientHead(t *testing.T) { run(t, testClientHead) }
func testClientHead(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, robotsTxtHandler)
	r, err := cst.c.Head(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Header["Last-Modified"]; !ok {
		t.Error("Last-Modified header not found.")
	}
}

type recordingTransport struct {
	req *Request
}

func (t *recordingTransport) RoundTrip(req *Request) (resp *Response, err error) {
	t.req = req
	return nil, errors.New("dummy impl")
}

func TestGetRequestFormat(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	tr := &recordingTransport{}
	client := &Client{Transport: tr}
	url := "http://dummy.faketld/"
	client.Get(url) // Note: doesn't hit network
	if tr.req.Method != "GET" {
		t.Errorf("expected method %q; got %q", "GET", tr.req.Method)
	}
	if tr.req.URL.String() != url {
		t.Errorf("expected URL %q; got %q", url, tr.req.URL.String())
	}
	if tr.req.Header == nil {
		t.Errorf("expected non-nil request Header")
	}
}

func TestPostRequestFormat(t *testing.T) {
	defer afterTest(t)
	tr := &recordingTransport{}
	client := &Client{Transport: tr}

	url := "http://dummy.faketld/"
	json := `{"key":"value"}`
	b := strings.NewReader(json)
	client.Post(url, "application/json", b) // Note: doesn't hit network

	if tr.req.Method != "POST" {
		t.Errorf("got method %q, want %q", tr.req.Method, "POST")
	}
	if tr.req.URL.String() != url {
		t.Errorf("got URL %q, want %q", tr.req.URL.String(), url)
	}
	if tr.req.Header == nil {
		t.Fatalf("expected non-nil request Header")
	}
	if tr.req.Close {
		t.Error("got Close true, want false")
	}
	if g, e := tr.req.ContentLength, int64(len(json)); g != e {
		t.Errorf("got ContentLength %d, want %d", g, e)
	}
}

func TestPostFormRequestFormat(t *testing.T) {
	defer afterTest(t)
	tr := &recordingTransport{}
	client := &Client{Transport: tr}

	urlStr := "http://dummy.faketld/"
	form := make(url.Values)
	form.Set("foo", "bar")
	form.Add("foo", "bar2")
	form.Set("bar", "baz")
	client.PostForm(urlStr, form) // Note: doesn't hit network

	if tr.req.Method != "POST" {
		t.Errorf("got method %q, want %q", tr.req.Method, "POST")
	}
	if tr.req.URL.String() != urlStr {
		t.Errorf("got URL %q, want %q", tr.req.URL.String(), urlStr)
	}
	if tr.req.Header == nil {
		t.Fatalf("expected non-nil request Header")
	}
	if g, e := tr.req.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; g != e {
		t.Errorf("got Content-Type %q, want %q", g, e)
	}
	if tr.req.Close {
		t.Error("got Close true, want false")
	}
	// Depending on map iteration, body can be either of these.
	expectedBody := "foo=bar&foo=bar2&bar=baz"
	expectedBody1 := "bar=baz&foo=bar&foo=bar2"
	if g, e := tr.req.ContentLength, int64(len(expectedBody)); g != e {
		t.Errorf("got ContentLength %d, want %d", g, e)
	}
	bodyb, err := io.ReadAll(tr.req.Body)
	if err != nil {
		t.Fatalf("ReadAll on req.Body: %v", err)
	}
	if g := string(bodyb); g != expectedBody && g != expectedBody1 {
		t.Errorf("got body %q, want %q or %q", g, expectedBody, expectedBody1)
	}
}

func TestClientRedirects(t *testing.T) { run(t, testClientRedirects) }
func testClientRedirects(t *testing.T, mode testMode) {
	var ts *httptest.Server
	ts = newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		n, _ := strconv.Atoi(r.FormValue("n"))
		// Test Referer header. (7 is arbitrary position to test at)
		if n == 7 {
			if g, e := r.Referer(), ts.URL+"/?n=6"; e != g {
				t.Errorf("on request ?n=7, expected referer of %q; got %q", e, g)
			}
		}
		if n < 15 {
			Redirect(w, r, fmt.Sprintf("/?n=%d", n+1), StatusTemporaryRedirect)
			return
		}
		fmt.Fprintf(w, "n=%d", n)
	})).ts

	c := ts.Client()
	_, err := c.Get(ts.URL)
	if e, g := `Get "/?n=10": stopped after 10 redirects`, fmt.Sprintf("%v", err); e != g {
		t.Errorf("with default client Get, expected error %q, got %q", e, g)
	}

	// HEAD request should also have the ability to follow redirects.
	_, err = c.Head(ts.URL)
	if e, g := `Head "/?n=10": stopped after 10 redirects`, fmt.Sprintf("%v", err); e != g {
		t.Errorf("with default client Head, expected error %q, got %q", e, g)
	}

	// Do should also follow redirects.
	greq, _ := NewRequest("GET", ts.URL, nil)
	_, err = c.Do(greq)
	if e, g := `Get "/?n=10": stopped after 10 redirects`, fmt.Sprintf("%v", err); e != g {
		t.Errorf("with default client Do, expected error %q, got %q", e, g)
	}

	// Requests with an empty Method should also redirect (Issue 12705)
	greq.Method = ""
	_, err = c.Do(greq)
	if e, g := `Get "/?n=10": stopped after 10 redirects`, fmt.Sprintf("%v", err); e != g {
		t.Errorf("with default client Do and empty Method, expected error %q, got %q", e, g)
	}

	var checkErr error
	var lastVia []*Request
	var lastReq *Request
	c.CheckRedirect = func(req *Request, via []*Request) error {
		lastReq = req
		lastVia = via
		return checkErr
	}
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	res.Body.Close()
	finalURL := res.Request.URL.String()
	if e, g := "<nil>", fmt.Sprintf("%v", err); e != g {
		t.Errorf("with custom client, expected error %q, got %q", e, g)
	}
	if !strings.HasSuffix(finalURL, "/?n=15") {
		t.Errorf("expected final url to end in /?n=15; got url %q", finalURL)
	}
	if e, g := 15, len(lastVia); e != g {
		t.Errorf("expected lastVia to have contained %d elements; got %d", e, g)
	}

	// Test that Request.Cancel is propagated between requests (Issue 14053)
	creq, _ := NewRequest("HEAD", ts.URL, nil)
	cancel := make(chan struct{})
	creq.Cancel = cancel
	if _, err := c.Do(creq); err != nil {
		t.Fatal(err)
	}
	if lastReq == nil {
		t.Fatal("didn't see redirect")
	}
	if lastReq.Cancel != cancel {
		t.Errorf("expected lastReq to have the cancel channel set on the initial req")
	}

	checkErr = errors.New("no redirects allowed")
	res, err = c.Get(ts.URL)
	if urlError, ok := err.(*url.Error); !ok || urlError.Err != checkErr {
		t.Errorf("with redirects forbidden, expected a *url.Error with our 'no redirects allowed' error inside; got %#v (%q)", err, err)
	}
	if res == nil {
		t.Fatalf("Expected a non-nil Response on CheckRedirect failure (https://golang.org/issue/3795)")
	}
	res.Body.Close()
	if res.Header.Get("Location") == "" {
		t.Errorf("no Location header in Response")
	}
}

// Tests that Client redirects' contexts are derived from the original request's context.
func TestClientRedirectsContext(t *testing.T) { run(t, testClientRedirectsContext) }
func testClientRedirectsContext(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		Redirect(w, r, "/", StatusTemporaryRedirect)
	})).ts

	ctx, cancel := context.WithCancel(context.Background())
	c := ts.Client()
	c.CheckRedirect = func(req *Request, via []*Request) error {
		cancel()
		select {
		case <-req.Context().Done():
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("redirected request's context never expired after root request canceled")
		}
	}
	req, _ := NewRequestWithContext(ctx, "GET", ts.URL, nil)
	_, err := c.Do(req)
	ue, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("got error %T; want *url.Error", err)
	}
	if ue.Err != context.Canceled {
		t.Errorf("url.Error.Err = %v; want %v", ue.Err, context.Canceled)
	}
}

type redirectTest struct {
	suffix       string
	want         int // response code
	redirectBody string
}

func TestPostRedirects(t *testing.T) {
	postRedirectTests := []redirectTest{
		{"/", 200, "first"},
		{"/?code=301&next=302", 200, "c301"},
		{"/?code=302&next=302", 200, "c302"},
		{"/?code=303&next=301", 200, "c303wc301"}, // Issue 9348
		{"/?code=304", 304, "c304"},
		{"/?code=305", 305, "c305"},
		{"/?code=307&next=303,308,302", 200, "c307"},
		{"/?code=308&next=302,301", 200, "c308"},
		{"/?code=404", 404, "c404"},
	}

	wantSegments := []string{
		`POST / "first"`,
		`POST /?code=301&next=302 "c301"`,
		`GET /?code=302 ""`,
		`GET / ""`,
		`POST /?code=302&next=302 "c302"`,
		`GET /?code=302 ""`,
		`GET / ""`,
		`POST /?code=303&next=301 "c303wc301"`,
		`GET /?code=301 ""`,
		`GET / ""`,
		`POST /?code=304 "c304"`,
		`POST /?code=305 "c305"`,
		`POST /?code=307&next=303,308,302 "c307"`,
		`POST /?code=303&next=308,302 "c307"`,
		`GET /?code=308&next=302 ""`,
		`GET /?code=302 ""`,
		`GET / ""`,
		`POST /?code=308&next=302,301 "c308"`,
		`POST /?code=302&next=301 "c308"`,
		`GET /?code=301 ""`,
		`GET / ""`,
		`POST /?code=404 "c404"`,
	}
	want := strings.Join(wantSegments, "\n")
	run(t, func(t *testing.T, mode testMode) {
		testRedirectsByMethod(t, mode, "POST", postRedirectTests, want)
	})
}

func TestDeleteRedirects(t *testing.T) {
	deleteRedirectTests := []redirectTest{
		{"/", 200, "first"},
		{"/?code=301&next=302,308", 200, "c301"},
		{"/?code=302&next=302", 200, "c302"},
		{"/?code=303", 200, "c303"},
		{"/?code=307&next=301,308,303,302,304", 304, "c307"},
		{"/?code=308&next=307", 200, "c308"},
		{"/?code=404", 404, "c404"},
	}

	wantSegments := []string{
		`DELETE / "first"`,
		`DELETE /?code=301&next=302,308 "c301"`,
		`GET /?code=302&next=308 ""`,
		`GET /?code=308 ""`,
		`GET / ""`,
		`DELETE /?code=302&next=302 "c302"`,
		`GET /?code=302 ""`,
		`GET / ""`,
		`DELETE /?code=303 "c303"`,
		`GET / ""`,
		`DELETE /?code=307&next=301,308,303,302,304 "c307"`,
		`DELETE /?code=301&next=308,303,302,304 "c307"`,
		`GET /?code=308&next=303,302,304 ""`,
		`GET /?code=303&next=302,304 ""`,
		`GET /?code=302&next=304 ""`,
		`GET /?code=304 ""`,
		`DELETE /?code=308&next=307 "c308"`,
		`DELETE /?code=307 "c308"`,
		`DELETE / "c308"`,
		`DELETE /?code=404 "c404"`,
	}
	want := strings.Join(wantSegments, "\n")
	run(t, func(t *testing.T, mode testMode) {
		testRedirectsByMethod(t, mode, "DELETE", deleteRedirectTests, want)
	})
}

func testRedirectsByMethod(t *testing.T, mode testMode, method string, table []redirectTest, want string) {
	var log struct {
		sync.Mutex
		bytes.Buffer
	}
	var ts *httptest.Server
	ts = newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		log.Lock()
		slurp, _ := io.ReadAll(r.Body)
		fmt.Fprintf(&log.Buffer, "%s %s %q", r.Method, r.RequestURI, slurp)
		if cl := r.Header.Get("Content-Length"); r.Method == "GET" && len(slurp) == 0 && (r.ContentLength != 0 || cl != "") {
			fmt.Fprintf(&log.Buffer, " (but with body=%T, content-length = %v, %q)", r.Body, r.ContentLength, cl)
		}
		log.WriteByte('\n')
		log.Unlock()
		urlQuery := r.URL.Query()
		if v := urlQuery.Get("code"); v != "" {
			location := ts.URL
			if final := urlQuery.Get("next"); final != "" {
				first, rest, _ := strings.Cut(final, ",")
				location = fmt.Sprintf("%s?code=%s", location, first)
				if rest != "" {
					location = fmt.Sprintf("%s&next=%s", location, rest)
				}
			}
			code, _ := strconv.Atoi(v)
			if code/100 == 3 {
				w.Header().Set("Location", location)
			}
			w.WriteHeader(code)
		}
	})).ts

	c := ts.Client()
	for _, tt := range table {
		content := tt.redirectBody
		req, _ := NewRequest(method, ts.URL+tt.suffix, strings.NewReader(content))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(content)), nil }
		res, err := c.Do(req)

		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != tt.want {
			t.Errorf("POST %s: status code = %d; want %d", tt.suffix, res.StatusCode, tt.want)
		}
	}
	log.Lock()
	got := log.String()
	log.Unlock()

	got = strings.TrimSpace(got)
	want = strings.TrimSpace(want)

	if got != want {
		got, want, lines := removeCommonLines(got, want)
		t.Errorf("Log differs after %d common lines.\n\nGot:\n%s\n\nWant:\n%s\n", lines, got, want)
	}
}

func removeCommonLines(a, b string) (asuffix, bsuffix string, commonLines int) {
	for {
		nl := strings.IndexByte(a, '\n')
		if nl < 0 {
			return a, b, commonLines
		}
		line := a[:nl+1]
		if !strings.HasPrefix(b, line) {
			return a, b, commonLines
		}
		commonLines++
		a = a[len(line):]
		b = b[len(line):]
	}
}

func TestClientRedirectUseResponse(t *testing.T) { run(t, testClientRedirectUseResponse) }
func testClientRedirectUseResponse(t *testing.T, mode testMode) {
	const body = "Hello, world."
	var ts *httptest.Server
	ts = newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if strings.Contains(r.URL.Path, "/other") {
			io.WriteString(w, "wrong body")
		} else {
			w.Header().Set("Location", ts.URL+"/other")
			w.WriteHeader(StatusFound)
			io.WriteString(w, body)
		}
	})).ts

	c := ts.Client()
	c.CheckRedirect = func(req *Request, via []*Request) error {
		if req.Response == nil {
			t.Error("expected non-nil Request.Response")
		}
		return ErrUseLastResponse
	}
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != StatusFound {
		t.Errorf("status = %d; want %d", res.StatusCode, StatusFound)
	}
	defer res.Body.Close()
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(slurp) != body {
		t.Errorf("body = %q; want %q", slurp, body)
	}
}

// Issues 17773 and 49281: don't follow a 3xx if the response doesn't
// have a Location header.
func TestClientRedirectNoLocation(t *testing.T) { run(t, testClientRedirectNoLocation) }
func testClientRedirectNoLocation(t *testing.T, mode testMode) {
	for _, code := range []int{301, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			setParallel(t)
			cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
				w.Header().Set("Foo", "Bar")
				w.WriteHeader(code)
			}))
			res, err := cst.c.Get(cst.ts.URL)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != code {
				t.Errorf("status = %d; want %d", res.StatusCode, code)
			}
			if got := res.Header.Get("Foo"); got != "Bar" {
				t.Errorf("Foo header = %q; want Bar", got)
			}
		})
	}
}

// Don't follow a 307/308 if we can't resent the request body.
func TestClientRedirect308NoGetBody(t *testing.T) { run(t, testClientRedirect308NoGetBody) }
func testClientRedirect308NoGetBody(t *testing.T, mode testMode) {
	const fakeURL = "https://localhost:1234/" // won't be hit
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Location", fakeURL)
		w.WriteHeader(308)
	})).ts
	req, err := NewRequest("POST", ts.URL, strings.NewReader("some body"))
	if err != nil {
		t.Fatal(err)
	}
	c := ts.Client()
	req.GetBody = nil // so it can't rewind.
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 308 {
		t.Errorf("status = %d; want %d", res.StatusCode, 308)
	}
	if got := res.Header.Get("Location"); got != fakeURL {
		t.Errorf("Location header = %q; want %q", got, fakeURL)
	}
}

var expectedCookies = []*Cookie{
	{Name: "ChocolateChip", Value: "tasty"},
	{Name: "First", Value: "Hit"},
	{Name: "Second", Value: "Hit"},
}

var echoCookiesRedirectHandler = HandlerFunc(func(w ResponseWriter, r *Request) {
	for _, cookie := range r.Cookies() {
		SetCookie(w, cookie)
	}
	if r.URL.Path == "/" {
		SetCookie(w, expectedCookies[1])
		Redirect(w, r, "/second", StatusMovedPermanently)
	} else {
		SetCookie(w, expectedCookies[2])
		w.Write([]byte("hello"))
	}
})

func TestClientSendsCookieFromJar(t *testing.T) {
	defer afterTest(t)
	tr := &recordingTransport{}
	client := &Client{Transport: tr}
	client.Jar = &TestJar{perURL: make(map[string][]*Cookie)}
	us := "http://dummy.faketld/"
	u, _ := url.Parse(us)
	client.Jar.SetCookies(u, expectedCookies)

	client.Get(us) // Note: doesn't hit network
	matchReturnedCookies(t, expectedCookies, tr.req.Cookies())

	client.Head(us) // Note: doesn't hit network
	matchReturnedCookies(t, expectedCookies, tr.req.Cookies())

	client.Post(us, "text/plain", strings.NewReader("body")) // Note: doesn't hit network
	matchReturnedCookies(t, expectedCookies, tr.req.Cookies())

	client.PostForm(us, url.Values{}) // Note: doesn't hit network
	matchReturnedCookies(t, expectedCookies, tr.req.Cookies())

	req, _ := NewRequest("GET", us, nil)
	client.Do(req) // Note: doesn't hit network
	matchReturnedCookies(t, expectedCookies, tr.req.Cookies())

	req, _ = NewRequest("POST", us, nil)
	client.Do(req) // Note: doesn't hit network
	matchReturnedCookies(t, expectedCookies, tr.req.Cookies())
}

// Just enough correctness for our redirect tests. Uses the URL.Host as the
// scope of all cookies.
type TestJar struct {
	m      sync.Mutex
	perURL map[string][]*Cookie
}

func (j *TestJar) SetCookies(u *url.URL, cookies []*Cookie) {
	j.m.Lock()
	defer j.m.Unlock()
	if j.perURL == nil {
		j.perURL = make(map[string][]*Cookie)
	}
	j.perURL[u.Host] = cookies
}

func (j *TestJar) Cookies(u *url.URL) []*Cookie {
	j.m.Lock()
	defer j.m.Unlock()
	return j.perURL[u.Host]
}

func TestRedirectCookiesJar(t *testing.T) { run(t, testRedirectCookiesJar) }
func testRedirectCookiesJar(t *testing.T, mode testMode) {
	var ts *httptest.Server
	ts = newClientServerTest(t, mode, echoCookiesRedirectHandler).ts
	c := ts.Client()
	c.Jar = new(TestJar)
	u, _ := url.Parse(ts.URL)
	c.Jar.SetCookies(u, []*Cookie{expectedCookies[0]})
	resp, err := c.Get(ts.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
	matchReturnedCookies(t, expectedCookies, resp.Cookies())
}

func matchReturnedCookies(t *testing.T, expected, given []*Cookie) {
	if len(given) != len(expected) {
		t.Logf("Received cookies: %v", given)
		t.Errorf("Expected %d cookies, got %d", len(expected), len(given))
	}
	for _, ec := range expected {
		foundC := false
		for _, c := range given {
			if ec.Name == c.Name && ec.Value == c.Value {
				foundC = true
				break
			}
		}
		if !foundC {
			t.Errorf("Missing cookie %v", ec)
		}
	}
}

func TestJarCalls(t *testing.T) { run(t, testJarCalls, []testMode{http1Mode}) }
func testJarCalls(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		pathSuffix := r.RequestURI[1:]
		if r.RequestURI == "/nosetcookie" {
			return // don't set cookies for this path
		}
		SetCookie(w, &Cookie{Name: "name" + pathSuffix, Value: "val" + pathSuffix})
		if r.RequestURI == "/" {
			Redirect(w, r, "http://secondhost.fake/secondpath", 302)
		}
	})).ts
	jar := new(RecordingJar)
	c := ts.Client()
	c.Jar = jar
	c.Transport.(*Transport).Dial = func(_ string, _ string) (net.Conn, error) {
		return net.Dial("tcp", ts.Listener.Addr().String())
	}
	_, err := c.Get("http://firsthost.fake/")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get("http://firsthost.fake/nosetcookie")
	if err != nil {
		t.Fatal(err)
	}
	got := jar.log.String()
	want := `Cookies("http://firsthost.fake/")
SetCookie("http://firsthost.fake/", [name=val])
Cookies("http://secondhost.fake/secondpath")
SetCookie("http://secondhost.fake/secondpath", [namesecondpath=valsecondpath])
Cookies("http://firsthost.fake/nosetcookie")
`
	if got != want {
		t.Errorf("Got Jar calls:\n%s\nWant:\n%s", got, want)
	}
}

// RecordingJar keeps a log of calls made to it, without
// tracking any cookies.
type RecordingJar struct {
	mu  sync.Mutex
	log bytes.Buffer
}

func (j *RecordingJar) SetCookies(u *url.URL, cookies []*Cookie) {
	j.logf("SetCookie(%q, %v)\n", u, cookies)
}

func (j *RecordingJar) Cookies(u *url.URL) []*Cookie {
	j.logf("Cookies(%q)\n", u)
	return nil
}

func (j *RecordingJar) logf(format string, args ...any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	fmt.Fprintf(&j.log, format, args...)
}

func TestStreamingGet(t *testing.T) { run(t, testStreamingGet) }
func testStreamingGet(t *testing.T, mode testMode) {
	say := make(chan string)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.(Flusher).Flush()
		for str := range say {
			w.Write([]byte(str))
			w.(Flusher).Flush()
		}
	}))

	c := cst.c
	res, err := c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	var buf [10]byte
	for _, str := range []string{"i", "am", "also", "known", "as", "comet"} {
		say <- str
		n, err := io.ReadFull(res.Body, buf[:len(str)])
		if err != nil {
			t.Fatalf("ReadFull on %q: %v", str, err)
		}
		if n != len(str) {
			t.Fatalf("Receiving %q, only read %d bytes", str, n)
		}
		got := string(buf[0:n])
		if got != str {
			t.Fatalf("Expected %q, got %q", str, got)
		}
	}
	close(say)
	_, err = io.ReadFull(res.Body, buf[0:1])
	if err != io.EOF {
		t.Fatalf("at end expected EOF, got %v", err)
	}
}

type writeCountingConn struct {
	net.Conn
	count *int
}

func (c *writeCountingConn) Write(p []byte) (int, error) {
	*c.count++
	return c.Conn.Write(p)
}

// TestClientWrites verifies that client requests are buffered and we
// don't send a TCP packet per line of the http request + body.
func TestClientWrites(t *testing.T) { run(t, testClientWrites, []testMode{http1Mode}) }
func testClientWrites(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
	})).ts

	writes := 0
	dialer := func(netz string, addr string) (net.Conn, error) {
		c, err := net.Dial(netz, addr)
		if err == nil {
			c = &writeCountingConn{c, &writes}
		}
		return c, err
	}
	c := ts.Client()
	c.Transport.(*Transport).Dial = dialer

	_, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Errorf("Get request did %d Write calls, want 1", writes)
	}

	writes = 0
	_, err = c.PostForm(ts.URL, url.Values{"foo": {"bar"}})
	if err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Errorf("Post request did %d Write calls, want 1", writes)
	}
}

func TestClientInsecureTransport(t *testing.T) {
	run(t, testClientInsecureTransport, []testMode{https1Mode, http2Mode})
}
func testClientInsecureTransport(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write([]byte("Hello"))
	}))
	ts := cst.ts
	errLog := new(strings.Builder)
	ts.Config.ErrorLog = log.New(errLog, "", 0)

	// TODO(bradfitz): add tests for skipping hostname checks too?
	// would require a new cert for testing, and probably
	// redundant with these tests.
	c := ts.Client()
	for _, insecure := range []bool{true, false} {
		c.Transport.(*Transport).TLSClientConfig = &tls.Config{
			InsecureSkipVerify: insecure,
		}
		res, err := c.Get(ts.URL)
		if (err == nil) != insecure {
			t.Errorf("insecure=%v: got unexpected err=%v", insecure, err)
		}
		if res != nil {
			res.Body.Close()
		}
	}

	cst.close()
	if !strings.Contains(errLog.String(), "TLS handshake error") {
		t.Errorf("expected an error log message containing 'TLS handshake error'; got %q", errLog)
	}
}

func TestClientErrorWithRequestURI(t *testing.T) {
	defer afterTest(t)
	req, _ := NewRequest("GET", "http://localhost:1234/", nil)
	req.RequestURI = "/this/field/is/illegal/and/should/error/"
	_, err := DefaultClient.Do(req)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if !strings.Contains(err.Error(), "RequestURI") {
		t.Errorf("wanted error mentioning RequestURI; got error: %v", err)
	}
}

func TestClientWithCorrectTLSServerName(t *testing.T) {
	run(t, testClientWithCorrectTLSServerName, []testMode{https1Mode, http2Mode})
}
func testClientWithCorrectTLSServerName(t *testing.T, mode testMode) {
	const serverName = "example.com"
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.TLS.ServerName != serverName {
			t.Errorf("expected client to set ServerName %q, got: %q", serverName, r.TLS.ServerName)
		}
	})).ts

	c := ts.Client()
	c.Transport.(*Transport).TLSClientConfig.ServerName = serverName
	if _, err := c.Get(ts.URL); err != nil {
		t.Fatalf("expected successful TLS connection, got error: %v", err)
	}
}

func TestClientWithIncorrectTLSServerName(t *testing.T) {
	run(t, testClientWithIncorrectTLSServerName, []testMode{https1Mode, http2Mode})
}
func testClientWithIncorrectTLSServerName(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {}))
	ts := cst.ts
	errLog := new(strings.Builder)
	ts.Config.ErrorLog = log.New(errLog, "", 0)

	c := ts.Client()
	c.Transport.(*Transport).TLSClientConfig.ServerName = "badserver"
	_, err := c.Get(ts.URL)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") || !strings.Contains(err.Error(), "badserver") {
		t.Errorf("wanted error mentioning 127.0.0.1 and badserver; got error: %v", err)
	}

	cst.close()
	if !strings.Contains(errLog.String(), "TLS handshake error") {
		t.Errorf("expected an error log message containing 'TLS handshake error'; got %q", errLog)
	}
}

// Test for golang.org/issue/5829; the Transport should respect TLSClientConfig.ServerName
// when not empty.
//
// tls.Config.ServerName (non-empty, set to "example.com") takes
// precedence over "some-other-host.tld" which previously incorrectly
// took precedence. We don't actually connect to (or even resolve)
// "some-other-host.tld", though, because of the Transport.Dial hook.
//
// The httptest.Server has a cert with "example.com" as its name.
func TestTransportUsesTLSConfigServerName(t *testing.T) {
	run(t, testTransportUsesTLSConfigServerName, []testMode{https1Mode, http2Mode})
}
func testTransportUsesTLSConfigServerName(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write([]byte("Hello"))
	})).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.TLSClientConfig.ServerName = "example.com" // one of httptest's Server cert names
	tr.Dial = func(netw, addr string) (net.Conn, error) {
		return net.Dial(netw, ts.Listener.Addr().String())
	}
	res, err := c.Get("https://some-other-host.tld/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestResponseSetsTLSConnectionState(t *testing.T) {
	run(t, testResponseSetsTLSConnectionState, []testMode{https1Mode})
}
func testResponseSetsTLSConnectionState(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write([]byte("Hello"))
	})).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.TLSClientConfig.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	tr.TLSClientConfig.MaxVersion = tls.VersionTLS12 // to get to pick the cipher suite
	tr.Dial = func(netw, addr string) (net.Conn, error) {
		return net.Dial(netw, ts.Listener.Addr().String())
	}
	res, err := c.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.TLS == nil {
		t.Fatal("Response didn't set TLS Connection State.")
	}
	if got, want := res.TLS.CipherSuite, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256; got != want {
		t.Errorf("TLS Cipher Suite = %d; want %d", got, want)
	}
}

// Check that an HTTPS client can interpret a particular TLS error
// to determine that the server is speaking HTTP.
// See golang.org/issue/11111.
func TestHTTPSClientDetectsHTTPServer(t *testing.T) {
	run(t, testHTTPSClientDetectsHTTPServer, []testMode{http1Mode})
}
func testHTTPSClientDetectsHTTPServer(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {})).ts
	ts.Config.ErrorLog = quietLog

	_, err := Get(strings.Replace(ts.URL, "http", "https", 1))
	if got := err.Error(); !strings.Contains(got, "HTTP response to HTTPS client") {
		t.Fatalf("error = %q; want error indicating HTTP response to HTTPS request", got)
	}
}

// Verify Response.ContentLength is populated. https://golang.org/issue/4126
func TestClientHeadContentLength(t *testing.T) { run(t, testClientHeadContentLength) }
func testClientHeadContentLength(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if v := r.FormValue("cl"); v != "" {
			w.Header().Set("Content-Length", v)
		}
	}))
	tests := []struct {
		suffix string
		want   int64
	}{
		{"/?cl=1234", 1234},
		{"/?cl=0", 0},
		{"", -1},
	}
	for _, tt := range tests {
		req, _ := NewRequest("HEAD", cst.ts.URL+tt.suffix, nil)
		res, err := cst.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if res.ContentLength != tt.want {
			t.Errorf("Content-Length = %d; want %d", res.ContentLength, tt.want)
		}
		bs, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(bs) != 0 {
			t.Errorf("Unexpected content: %q", bs)
		}
	}
}

func TestEmptyPasswordAuth(t *testing.T) { run(t, testEmptyPasswordAuth) }
func testEmptyPasswordAuth(t *testing.T, mode testMode) {
	gopher := "gopher"
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Basic ") {
			encoded := auth[6:]
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			expected := gopher + ":"
			s := string(decoded)
			if expected != s {
				t.Errorf("Invalid Authorization header. Got %q, wanted %q", s, expected)
			}
		} else {
			t.Errorf("Invalid auth %q", auth)
		}
	})).ts
	defer ts.Close()
	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.User = url.User(gopher)
	c := ts.Client()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
}

func TestBasicAuth(t *testing.T) {
	defer afterTest(t)
	tr := &recordingTransport{}
	client := &Client{Transport: tr}

	url := "http://My%20User:My%20Pass@dummy.faketld/"
	expected := "My User:My Pass"
	client.Get(url)

	if tr.req.Method != "GET" {
		t.Errorf("got method %q, want %q", tr.req.Method, "GET")
	}
	if tr.req.URL.String() != url {
		t.Errorf("got URL %q, want %q", tr.req.URL.String(), url)
	}
	if tr.req.Header == nil {
		t.Fatalf("expected non-nil request Header")
	}
	auth := tr.req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		encoded := auth[6:]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		s := string(decoded)
		if expected != s {
			t.Errorf("Invalid Authorization header. Got %q, wanted %q", s, expected)
		}
	} else {
		t.Errorf("Invalid auth %q", auth)
	}
}

func TestBasicAuthHeadersPreserved(t *testing.T) {
	defer afterTest(t)
	tr := &recordingTransport{}
	client := &Client{Transport: tr}

	// If Authorization header is provided, username in URL should not override it
	url := "http://My%20User@dummy.faketld/"
	req, err := NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("My User", "My Pass")
	expected := "My User:My Pass"
	client.Do(req)

	if tr.req.Method != "GET" {
		t.Errorf("got method %q, want %q", tr.req.Method, "GET")
	}
	if tr.req.URL.String() != url {
		t.Errorf("got URL %q, want %q", tr.req.URL.String(), url)
	}
	if tr.req.Header == nil {
		t.Fatalf("expected non-nil request Header")
	}
	auth := tr.req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		encoded := auth[6:]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		s := string(decoded)
		if expected != s {
			t.Errorf("Invalid Authorization header. Got %q, wanted %q", s, expected)
		}
	} else {
		t.Errorf("Invalid auth %q", auth)
	}

}

func TestStripPasswordFromError(t *testing.T) {
	client := &Client{Transpor
"""




```