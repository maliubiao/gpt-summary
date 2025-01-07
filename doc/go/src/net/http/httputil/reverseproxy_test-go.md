Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet (`reverseproxy_test.go`). It also encourages providing examples and identifying potential pitfalls. The key here is *summarizing* and *inferring purpose* from the tests themselves.

2. **Identify the Core Subject:** The code is in `net/http/httputil` and the filename is `reverseproxy_test.go`. This immediately tells me the core subject is testing the `ReverseProxy` functionality in Go's standard library.

3. **Analyze the Imports:** The imports confirm the subject matter: `net/http`, `net/url`, etc., are all related to HTTP handling.

4. **Examine the Test Functions:** The names of the test functions are highly informative. I'll go through them one by one and extract the tested feature:

    * `TestReverseProxy`: This is a general test covering basic reverse proxy functionality (status codes, headers, body).
    * `TestReverseProxyStripHeadersPresentInConnection`:  Focuses on how the proxy handles the "Connection" header.
    * `TestReverseProxyStripEmptyConnection`: Specifically tests the case of empty values in the "Connection" header.
    * `TestXForwardedFor`:  Tests the handling of the `X-Forwarded-For` header.
    * `TestXForwardedFor_Omit`: Tests a specific scenario where `X-Forwarded-For` is explicitly set to `nil`.
    * `TestReverseProxyRewriteStripsForwarded`: Checks if the `Rewrite` function clears forwarding-related headers.
    * `TestReverseProxyQuery`:  Tests how query parameters are handled and forwarded.
    * `TestReverseProxyFlushInterval`: Tests the `FlushInterval` setting for streaming responses.
    * `TestReverseProxyResponseControllerFlushInterval`: Tests flushing with middleware.
    * `TestReverseProxyFlushIntervalHeaders`:  Tests header handling with flushing.
    * `TestReverseProxyCancellation`:  Tests how the proxy handles request cancellation.
    * `TestNilBody`: Tests the behavior with a `nil` request body (an edge case).
    * `TestUserAgentHeader`:  Tests the forwarding of the `User-Agent` header.
    * `TestReverseProxyGetPutBuffer`:  Tests the custom buffer pool functionality.
    * `TestReverseProxy_Post`: Tests handling of POST requests with larger bodies.
    * `TestReverseProxy_NilBody`: Another test related to `nil` bodies, but this time on the *backend* request.
    * `TestReverseProxy_AllocatedHeader`: Checks if headers are always allocated.
    * `TestReverseProxyModifyResponse`: Tests the `ModifyResponse` hook.
    * `TestReverseProxyErrorHandler`: Tests the custom error handler.
    * `TestReverseProxy_CopyBuffer`: Tests error logging during body copying.
    * `BenchmarkServeHTTP`:  A performance benchmark.
    * `TestServeHTTPDeepCopy`: Checks for deep copying of request URLs.
    * `TestClonesRequestHeaders`: Tests for deep copying of request headers.

5. **Group and Summarize Functionality:** Based on the test function analysis, I can group the functionalities:

    * **Basic Proxying:** Forwarding requests, handling responses, status codes, bodies.
    * **Header Handling:** Specifically dealing with `Connection`, `X-Forwarded-For`, `User-Agent`, and stripping hop-by-hop headers.
    * **Query Parameter Handling:**  Forwarding query parameters correctly.
    * **Streaming and Flushing:**  Testing the `FlushInterval` for real-time responses.
    * **Request Modification:** Using the `Director` and `Rewrite` functions.
    * **Response Modification:** Using the `ModifyResponse` function.
    * **Error Handling:** Default behavior and custom `ErrorHandler`.
    * **Cancellation:** Handling client-side request cancellations.
    * **Body Handling:**  Specific tests for `nil` bodies and POST requests.
    * **Buffering:** Testing the custom `BufferPool`.
    * **Internal Mechanics:** Testing for deep copying of headers and URLs.

6. **Infer the Go Feature:** The core Go feature being tested is the `httputil.ReverseProxy`. This is explicitly used in the tests.

7. **Consider Examples (as requested):**  While the tests themselves *are* examples, the request asks for Go code examples. I would think about the most common use cases and construct simplified scenarios illustrating the `ReverseProxy`. A simple setup with a backend and frontend server is a good starting point.

8. **Identify Potential Pitfalls:** Analyze the tests for scenarios that might cause issues for users. Misunderstanding header handling (especially `Connection` and forwarding headers), incorrect error handling, and assumptions about body handling are common pitfalls.

9. **Structure the Answer:**  Organize the information logically, starting with a general summary and then going into more detail for each aspect. Use clear headings and bullet points for readability.

10. **Review and Refine:**  Read through the answer to ensure it is accurate, comprehensive, and easy to understand. Make sure the examples are correct and the explanations are clear. Double-check that all parts of the original request have been addressed.

By following this process, I can systematically analyze the code, extract its functionality, and provide a comprehensive and informative answer to the request.
这个go语言文件的主要功能是**测试 `net/http/httputil` 包中的 `ReverseProxy` 结构体的各种功能**。  `ReverseProxy` 是 Go 语言标准库中用于实现反向代理的核心组件。

**归纳一下它的功能（针对第1部分）：**

这个测试文件的第1部分主要集中在以下 `ReverseProxy` 的核心功能和行为的测试：

1. **基本的反向代理功能：**
   - 测试能否正确地将客户端的请求转发到后端服务器。
   - 测试能否正确地接收并转发后端服务器的响应。
   - 测试能否正确地处理后端服务器返回的状态码。
   - 测试能否正确地转发响应体。

2. **请求头的处理：**
   - **`X-Forwarded-For` 头：** 测试反向代理是否会自动添加或更新 `X-Forwarded-For` 头，记录客户端的 IP 地址。
   - **`Connection` 头：** 测试反向代理是否正确地移除或处理 `Connection` 头中指定的跳跃头（hop-by-hop headers），避免它们被转发到后端。
   - **`Te` 头：** 测试反向代理是否正确设置 `Te` 头为 "trailers"。
   - **`Upgrade` 和 `Proxy-Connection` 头：** 测试反向代理是否会移除这两个连接相关的头。
   - **自定义的跳跃头：** 通过 `hopHeaders` 变量测试反向代理是否会移除自定义的跳跃头。
   - **多值 Header：** 测试反向代理是否能正确处理和转发具有多个值的 Header。
   - **Cookie：** 测试反向代理是否能正确转发后端设置的 Cookie。
   - **Trailer：** 测试反向代理对 HTTP Trailer 的处理，包括已声明和未声明的 Trailer。

3. **后端连接异常处理：**
   - 测试当后端服务器无法访问或提前关闭连接时，反向代理是否会返回 `StatusBadGateway` (502) 错误。

4. **清理 `Connection` 头中指定的 Header：**
   - 测试当客户端请求的 `Connection` 头中列出了一些自定义的 Header 时，反向代理是否会将其从转发到后端的请求中移除。

5. **处理空的 `Connection` 头：**
   - 测试当 `Connection` 头的值为空时，反向代理的行为。

6. **`X-Forwarded-For` 头的处理细节：**
   - 测试当请求中已经存在 `X-Forwarded-For` 头时，反向代理是否会正确追加客户端 IP。
   - 测试当通过 `Director` 函数将 `X-Forwarded-For` 头设置为 `nil` 时，反向代理是否会忽略它而不添加新的值。

7. **`Rewrite` 函数的功能：**
   - 测试通过 `Rewrite` 函数修改请求 URL 后，是否会清除客户端请求中的 `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` 等 Forwarded 相关的 Header。

8. **查询参数的处理：**
   - 测试反向代理是否能正确合并前端请求和后端 URL 中的查询参数。

**代码示例：反向代理的基本使用**

假设我们有一个运行在 `http://localhost:8081` 的后端服务器，我们想通过一个反向代理 `http://localhost:8080` 来访问它。

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	// 后端服务器的地址
	backendURL, err := url.Parse("http://localhost:8081")
	if err != nil {
		log.Fatal(err)
	}

	// 创建反向代理处理器
	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	// 前端服务器处理请求
	frontendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	// 启动前端服务器 (反向代理)
	fmt.Println("反向代理服务器运行在 http://localhost:8080")
	err = http.ListenAndServe(":8080", frontendHandler)
	if err != nil {
		log.Fatal(err)
	}
}
```

**假设的输入与输出：**

**输入 (访问反向代理)：**

```
GET /api/data?param1=value1 HTTP/1.1
Host: localhost:8080
User-Agent: MyClient
```

**输出 (后端服务器接收到的请求，部分)：**

```
GET /api/data?param1=value1 HTTP/1.1
Host: localhost:8081  // 默认情况下，Host 头会被重写为后端服务器的 Host
X-Forwarded-For: 127.0.0.1 // 假设客户端 IP 是 127.0.0.1
User-Agent: MyClient
Te: trailers
```

**命令行参数处理：**

在这个代码片段中，没有直接涉及到命令行参数的处理。`ReverseProxy` 的配置主要通过代码来完成，例如设置 `Director`、`Transport`、`ModifyResponse` 等字段。 通常，如果需要从命令行读取配置，会在 `main` 函数中使用 `flag` 包或其他命令行参数解析库。

**使用者易犯错的点：**

* **不理解 `Connection` 头的处理：** 容易错误地认为所有的 Header 都会被直接转发到后端。 忘记 `Connection` 头的作用以及反向代理会移除其中指定的跳跃头。  例如，如果客户端发送 `Connection: close`，反向代理会处理掉，不会传递给后端，除非后端也发送 `Connection: close`。

* **`X-Forwarded-For` 的信任问题：**  如果反向代理链路上有多个代理，后端服务器接收到的 `X-Forwarded-For` 可能包含伪造的 IP 地址。 需要谨慎处理，并可能需要配置信任的代理 IP 范围。

* **错误处理：**  没有正确配置 `ErrorHandler`，导致默认的错误页面不够友好或者没有记录必要的错误信息。

* **WebSocket 和长连接：** 对于需要升级协议（例如 WebSocket）或保持长连接的应用，`ReverseProxy` 的默认行为可能需要额外的配置或者自定义处理。

* **Host 头的理解：** 默认情况下，`ReverseProxy` 会将转发到后端的请求的 `Host` 头设置为后端服务器的地址。 如果后端应用依赖于原始的 `Host` 头，需要自定义 `Director` 函数来修改。

这个测试文件的第1部分主要关注 `ReverseProxy` 的基本转发、请求头处理和一些基础的错误处理场景。 后续部分可能会涉及更高级的功能，例如负载均衡、会话保持等。

Prompt: 
```
这是路径为go/src/net/http/httputil/reverseproxy_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Reverse proxy tests.

package httputil

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/internal/ascii"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const fakeHopHeader = "X-Fake-Hop-Header-For-Test"

func init() {
	inOurTests = true
	hopHeaders = append(hopHeaders, fakeHopHeader)
}

func TestReverseProxy(t *testing.T) {
	const backendResponse = "I am the backend"
	const backendStatus = 404
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.FormValue("mode") == "hangup" {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		if len(r.TransferEncoding) > 0 {
			t.Errorf("backend got unexpected TransferEncoding: %v", r.TransferEncoding)
		}
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Errorf("didn't get X-Forwarded-For header")
		}
		if c := r.Header.Get("Connection"); c != "" {
			t.Errorf("handler got Connection header value %q", c)
		}
		if c := r.Header.Get("Te"); c != "trailers" {
			t.Errorf("handler got Te header value %q; want 'trailers'", c)
		}
		if c := r.Header.Get("Upgrade"); c != "" {
			t.Errorf("handler got Upgrade header value %q", c)
		}
		if c := r.Header.Get("Proxy-Connection"); c != "" {
			t.Errorf("handler got Proxy-Connection header value %q", c)
		}
		if g, e := r.Host, "some-name"; g != e {
			t.Errorf("backend got Host header %q, want %q", g, e)
		}
		w.Header().Set("Trailers", "not a special header field name")
		w.Header().Set("Trailer", "X-Trailer")
		w.Header().Set("X-Foo", "bar")
		w.Header().Set("Upgrade", "foo")
		w.Header().Set(fakeHopHeader, "foo")
		w.Header().Add("X-Multi-Value", "foo")
		w.Header().Add("X-Multi-Value", "bar")
		http.SetCookie(w, &http.Cookie{Name: "flavor", Value: "chocolateChip"})
		w.WriteHeader(backendStatus)
		w.Write([]byte(backendResponse))
		w.Header().Set("X-Trailer", "trailer_value")
		w.Header().Set(http.TrailerPrefix+"X-Unannounced-Trailer", "unannounced_trailer_value")
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()
	frontendClient := frontend.Client()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Host = "some-name"
	getReq.Header.Set("Connection", "close, TE")
	getReq.Header.Add("Te", "foo")
	getReq.Header.Add("Te", "bar, trailers")
	getReq.Header.Set("Proxy-Connection", "should be deleted")
	getReq.Header.Set("Upgrade", "foo")
	getReq.Close = true
	res, err := frontendClient.Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g, e := res.StatusCode, backendStatus; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	if g, e := res.Header.Get("X-Foo"), "bar"; g != e {
		t.Errorf("got X-Foo %q; expected %q", g, e)
	}
	if c := res.Header.Get(fakeHopHeader); c != "" {
		t.Errorf("got %s header value %q", fakeHopHeader, c)
	}
	if g, e := res.Header.Get("Trailers"), "not a special header field name"; g != e {
		t.Errorf("header Trailers = %q; want %q", g, e)
	}
	if g, e := len(res.Header["X-Multi-Value"]), 2; g != e {
		t.Errorf("got %d X-Multi-Value header values; expected %d", g, e)
	}
	if g, e := len(res.Header["Set-Cookie"]), 1; g != e {
		t.Fatalf("got %d SetCookies, want %d", g, e)
	}
	if g, e := res.Trailer, (http.Header{"X-Trailer": nil}); !reflect.DeepEqual(g, e) {
		t.Errorf("before reading body, Trailer = %#v; want %#v", g, e)
	}
	if cookie := res.Cookies()[0]; cookie.Name != "flavor" {
		t.Errorf("unexpected cookie %q", cookie.Name)
	}
	bodyBytes, _ := io.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendResponse; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
	if g, e := res.Trailer.Get("X-Trailer"), "trailer_value"; g != e {
		t.Errorf("Trailer(X-Trailer) = %q ; want %q", g, e)
	}
	if g, e := res.Trailer.Get("X-Unannounced-Trailer"), "unannounced_trailer_value"; g != e {
		t.Errorf("Trailer(X-Unannounced-Trailer) = %q ; want %q", g, e)
	}
	res.Body.Close()

	// Test that a backend failing to be reached or one which doesn't return
	// a response results in a StatusBadGateway.
	getReq, _ = http.NewRequest("GET", frontend.URL+"/?mode=hangup", nil)
	getReq.Close = true
	res, err = frontendClient.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("request to bad proxy = %v; want 502 StatusBadGateway", res.Status)
	}

}

// Issue 16875: remove any proxied headers mentioned in the "Connection"
// header value.
func TestReverseProxyStripHeadersPresentInConnection(t *testing.T) {
	const fakeConnectionToken = "X-Fake-Connection-Token"
	const backendResponse = "I am the backend"

	// someConnHeader is some arbitrary header to be declared as a hop-by-hop header
	// in the Request's Connection header.
	const someConnHeader = "X-Some-Conn-Header"

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := r.Header.Get("Connection"); c != "" {
			t.Errorf("handler got header %q = %q; want empty", "Connection", c)
		}
		if c := r.Header.Get(fakeConnectionToken); c != "" {
			t.Errorf("handler got header %q = %q; want empty", fakeConnectionToken, c)
		}
		if c := r.Header.Get(someConnHeader); c != "" {
			t.Errorf("handler got header %q = %q; want empty", someConnHeader, c)
		}
		w.Header().Add("Connection", "Upgrade, "+fakeConnectionToken)
		w.Header().Add("Connection", someConnHeader)
		w.Header().Set(someConnHeader, "should be deleted")
		w.Header().Set(fakeConnectionToken, "should be deleted")
		io.WriteString(w, backendResponse)
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHandler.ServeHTTP(w, r)
		if c := r.Header.Get(someConnHeader); c != "should be deleted" {
			t.Errorf("handler modified header %q = %q; want %q", someConnHeader, c, "should be deleted")
		}
		if c := r.Header.Get(fakeConnectionToken); c != "should be deleted" {
			t.Errorf("handler modified header %q = %q; want %q", fakeConnectionToken, c, "should be deleted")
		}
		c := r.Header["Connection"]
		var cf []string
		for _, f := range c {
			for _, sf := range strings.Split(f, ",") {
				if sf = strings.TrimSpace(sf); sf != "" {
					cf = append(cf, sf)
				}
			}
		}
		slices.Sort(cf)
		expectedValues := []string{"Upgrade", someConnHeader, fakeConnectionToken}
		slices.Sort(expectedValues)
		if !slices.Equal(cf, expectedValues) {
			t.Errorf("handler modified header %q = %q; want %q", "Connection", cf, expectedValues)
		}
	}))
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Header.Add("Connection", "Upgrade, "+fakeConnectionToken)
	getReq.Header.Add("Connection", someConnHeader)
	getReq.Header.Set(someConnHeader, "should be deleted")
	getReq.Header.Set(fakeConnectionToken, "should be deleted")
	res, err := frontend.Client().Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if got, want := string(bodyBytes), backendResponse; got != want {
		t.Errorf("got body %q; want %q", got, want)
	}
	if c := res.Header.Get("Connection"); c != "" {
		t.Errorf("handler got header %q = %q; want empty", "Connection", c)
	}
	if c := res.Header.Get(someConnHeader); c != "" {
		t.Errorf("handler got header %q = %q; want empty", someConnHeader, c)
	}
	if c := res.Header.Get(fakeConnectionToken); c != "" {
		t.Errorf("handler got header %q = %q; want empty", fakeConnectionToken, c)
	}
}

func TestReverseProxyStripEmptyConnection(t *testing.T) {
	// See Issue 46313.
	const backendResponse = "I am the backend"

	// someConnHeader is some arbitrary header to be declared as a hop-by-hop header
	// in the Request's Connection header.
	const someConnHeader = "X-Some-Conn-Header"

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := r.Header.Values("Connection"); len(c) != 0 {
			t.Errorf("handler got header %q = %v; want empty", "Connection", c)
		}
		if c := r.Header.Get(someConnHeader); c != "" {
			t.Errorf("handler got header %q = %q; want empty", someConnHeader, c)
		}
		w.Header().Add("Connection", "")
		w.Header().Add("Connection", someConnHeader)
		w.Header().Set(someConnHeader, "should be deleted")
		io.WriteString(w, backendResponse)
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHandler.ServeHTTP(w, r)
		if c := r.Header.Get(someConnHeader); c != "should be deleted" {
			t.Errorf("handler modified header %q = %q; want %q", someConnHeader, c, "should be deleted")
		}
	}))
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Header.Add("Connection", "")
	getReq.Header.Add("Connection", someConnHeader)
	getReq.Header.Set(someConnHeader, "should be deleted")
	res, err := frontend.Client().Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if got, want := string(bodyBytes), backendResponse; got != want {
		t.Errorf("got body %q; want %q", got, want)
	}
	if c := res.Header.Get("Connection"); c != "" {
		t.Errorf("handler got header %q = %q; want empty", "Connection", c)
	}
	if c := res.Header.Get(someConnHeader); c != "" {
		t.Errorf("handler got header %q = %q; want empty", someConnHeader, c)
	}
}

func TestXForwardedFor(t *testing.T) {
	const prevForwardedFor = "client ip"
	const backendResponse = "I am the backend"
	const backendStatus = 404
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Errorf("didn't get X-Forwarded-For header")
		}
		if !strings.Contains(r.Header.Get("X-Forwarded-For"), prevForwardedFor) {
			t.Errorf("X-Forwarded-For didn't contain prior data")
		}
		w.WriteHeader(backendStatus)
		w.Write([]byte(backendResponse))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Header.Set("Connection", "close")
	getReq.Header.Set("X-Forwarded-For", prevForwardedFor)
	getReq.Close = true
	res, err := frontend.Client().Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	if g, e := res.StatusCode, backendStatus; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	bodyBytes, _ := io.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendResponse; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

// Issue 38079: don't append to X-Forwarded-For if it's present but nil
func TestXForwardedFor_Omit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			t.Errorf("got X-Forwarded-For header: %q", v)
		}
		w.Write([]byte("hi"))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	oldDirector := proxyHandler.Director
	proxyHandler.Director = func(r *http.Request) {
		r.Header["X-Forwarded-For"] = nil
		oldDirector(r)
	}

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Host = "some-name"
	getReq.Close = true
	res, err := frontend.Client().Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()
}

func TestReverseProxyRewriteStripsForwarded(t *testing.T) {
	headers := []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range headers {
			if v := r.Header.Get(h); v != "" {
				t.Errorf("got %v header: %q", h, v)
			}
		}
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := &ReverseProxy{
		Rewrite: func(r *ProxyRequest) {
			r.SetURL(backendURL)
		},
	}
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Host = "some-name"
	getReq.Close = true
	for _, h := range headers {
		getReq.Header.Set(h, "x")
	}
	res, err := frontend.Client().Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()
}

var proxyQueryTests = []struct {
	baseSuffix string // suffix to add to backend URL
	reqSuffix  string // suffix to add to frontend's request URL
	want       string // what backend should see for final request URL (without ?)
}{
	{"", "", ""},
	{"?sta=tic", "?us=er", "sta=tic&us=er"},
	{"", "?us=er", "us=er"},
	{"?sta=tic", "", "sta=tic"},
}

func TestReverseProxyQuery(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Query", r.URL.RawQuery)
		w.Write([]byte("hi"))
	}))
	defer backend.Close()

	for i, tt := range proxyQueryTests {
		backendURL, err := url.Parse(backend.URL + tt.baseSuffix)
		if err != nil {
			t.Fatal(err)
		}
		frontend := httptest.NewServer(NewSingleHostReverseProxy(backendURL))
		req, _ := http.NewRequest("GET", frontend.URL+tt.reqSuffix, nil)
		req.Close = true
		res, err := frontend.Client().Do(req)
		if err != nil {
			t.Fatalf("%d. Get: %v", i, err)
		}
		if g, e := res.Header.Get("X-Got-Query"), tt.want; g != e {
			t.Errorf("%d. got query %q; expected %q", i, g, e)
		}
		res.Body.Close()
		frontend.Close()
	}
}

func TestReverseProxyFlushInterval(t *testing.T) {
	const expected = "hi"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expected))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.FlushInterval = time.Microsecond

	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	req, _ := http.NewRequest("GET", frontend.URL, nil)
	req.Close = true
	res, err := frontend.Client().Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	if bodyBytes, _ := io.ReadAll(res.Body); string(bodyBytes) != expected {
		t.Errorf("got body %q; expected %q", bodyBytes, expected)
	}
}

type mockFlusher struct {
	http.ResponseWriter
	flushed bool
}

func (m *mockFlusher) Flush() {
	m.flushed = true
}

type wrappedRW struct {
	http.ResponseWriter
}

func (w *wrappedRW) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func TestReverseProxyResponseControllerFlushInterval(t *testing.T) {
	const expected = "hi"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expected))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	mf := &mockFlusher{}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.FlushInterval = -1 // flush immediately
	proxyWithMiddleware := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mf.ResponseWriter = w
		w = &wrappedRW{mf}
		proxyHandler.ServeHTTP(w, r)
	})

	frontend := httptest.NewServer(proxyWithMiddleware)
	defer frontend.Close()

	req, _ := http.NewRequest("GET", frontend.URL, nil)
	req.Close = true
	res, err := frontend.Client().Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	if bodyBytes, _ := io.ReadAll(res.Body); string(bodyBytes) != expected {
		t.Errorf("got body %q; expected %q", bodyBytes, expected)
	}
	if !mf.flushed {
		t.Errorf("response writer was not flushed")
	}
}

func TestReverseProxyFlushIntervalHeaders(t *testing.T) {
	const expected = "hi"
	stopCh := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("MyHeader", expected)
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-stopCh
	}))
	defer backend.Close()
	defer close(stopCh)

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.FlushInterval = time.Microsecond

	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	req, _ := http.NewRequest("GET", frontend.URL, nil)
	req.Close = true

	ctx, cancel := context.WithTimeout(req.Context(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	res, err := frontend.Client().Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()

	if res.Header.Get("MyHeader") != expected {
		t.Errorf("got header %q; expected %q", res.Header.Get("MyHeader"), expected)
	}
}

func TestReverseProxyCancellation(t *testing.T) {
	const backendResponse = "I am the backend"

	reqInFlight := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reqInFlight) // cause the client to cancel its request

		select {
		case <-time.After(10 * time.Second):
			// Note: this should only happen in broken implementations, and the
			// closenotify case should be instantaneous.
			t.Error("Handler never saw CloseNotify")
			return
		case <-w.(http.CloseNotifier).CloseNotify():
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(backendResponse))
	}))

	defer backend.Close()

	backend.Config.ErrorLog = log.New(io.Discard, "", 0)

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler := NewSingleHostReverseProxy(backendURL)

	// Discards errors of the form:
	// http: proxy error: read tcp 127.0.0.1:44643: use of closed network connection
	proxyHandler.ErrorLog = log.New(io.Discard, "", 0)

	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()
	frontendClient := frontend.Client()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	go func() {
		<-reqInFlight
		frontendClient.Transport.(*http.Transport).CancelRequest(getReq)
	}()
	res, err := frontendClient.Do(getReq)
	if res != nil {
		t.Errorf("got response %v; want nil", res.Status)
	}
	if err == nil {
		// This should be an error like:
		// Get "http://127.0.0.1:58079": read tcp 127.0.0.1:58079:
		//    use of closed network connection
		t.Error("Server.Client().Do() returned nil error; want non-nil error")
	}
}

func req(t *testing.T, v string) *http.Request {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(v)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// Issue 12344
func TestNilBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi"))
	}))
	defer backend.Close()

	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backURL, _ := url.Parse(backend.URL)
		rp := NewSingleHostReverseProxy(backURL)
		r := req(t, "GET / HTTP/1.0\r\n\r\n")
		r.Body = nil // this accidentally worked in Go 1.4 and below, so keep it working
		rp.ServeHTTP(w, r)
	}))
	defer frontend.Close()

	res, err := http.Get(frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	slurp, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(slurp) != "hi" {
		t.Errorf("Got %q; want %q", slurp, "hi")
	}
}

// Issue 15524
func TestUserAgentHeader(t *testing.T) {
	var gotUA string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler := new(ReverseProxy)
	proxyHandler.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
	proxyHandler.Director = func(req *http.Request) {
		req.URL = backendURL
	}
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()
	frontendClient := frontend.Client()

	for _, sentUA := range []string{"explicit UA", ""} {
		getReq, _ := http.NewRequest("GET", frontend.URL, nil)
		getReq.Header.Set("User-Agent", sentUA)
		getReq.Close = true
		res, err := frontendClient.Do(getReq)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		res.Body.Close()
		if got, want := gotUA, sentUA; got != want {
			t.Errorf("got forwarded User-Agent %q, want %q", got, want)
		}
	}
}

type bufferPool struct {
	get func() []byte
	put func([]byte)
}

func (bp bufferPool) Get() []byte  { return bp.get() }
func (bp bufferPool) Put(v []byte) { bp.put(v) }

func TestReverseProxyGetPutBuffer(t *testing.T) {
	const msg = "hi"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, msg)
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu  sync.Mutex
		log []string
	)
	addLog := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		log = append(log, event)
	}
	rp := NewSingleHostReverseProxy(backendURL)
	const size = 1234
	rp.BufferPool = bufferPool{
		get: func() []byte {
			addLog("getBuf")
			return make([]byte, size)
		},
		put: func(p []byte) {
			addLog("putBuf-" + strconv.Itoa(len(p)))
		},
	}
	frontend := httptest.NewServer(rp)
	defer frontend.Close()

	req, _ := http.NewRequest("GET", frontend.URL, nil)
	req.Close = true
	res, err := frontend.Client().Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	slurp, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(slurp) != msg {
		t.Errorf("msg = %q; want %q", slurp, msg)
	}
	wantLog := []string{"getBuf", "putBuf-" + strconv.Itoa(size)}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(log, wantLog) {
		t.Errorf("Log events = %q; want %q", log, wantLog)
	}
}

func TestReverseProxy_Post(t *testing.T) {
	const backendResponse = "I am the backend"
	const backendStatus = 200
	var requestBody = bytes.Repeat([]byte("a"), 1<<20)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slurp, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Backend body read = %v", err)
		}
		if len(slurp) != len(requestBody) {
			t.Errorf("Backend read %d request body bytes; want %d", len(slurp), len(requestBody))
		}
		if !bytes.Equal(slurp, requestBody) {
			t.Error("Backend read wrong request body.") // 1MB; omitting details
		}
		w.Write([]byte(backendResponse))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	postReq, _ := http.NewRequest("POST", frontend.URL, bytes.NewReader(requestBody))
	res, err := frontend.Client().Do(postReq)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()
	if g, e := res.StatusCode, backendStatus; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	bodyBytes, _ := io.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendResponse; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

type RoundTripperFunc func(*http.Request) (*http.Response, error)

func (fn RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

// Issue 16036: send a Request with a nil Body when possible
func TestReverseProxy_NilBody(t *testing.T) {
	backendURL, _ := url.Parse("http://fake.tld/")
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
	proxyHandler.Transport = RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			t.Error("Body != nil; want a nil Body")
		}
		return nil, errors.New("done testing the interesting part; so force a 502 Gateway error")
	})
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	res, err := frontend.Client().Get(frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 502 {
		t.Errorf("status code = %v; want 502 (Gateway Error)", res.Status)
	}
}

// Issue 33142: always allocate the request headers
func TestReverseProxy_AllocatedHeader(t *testing.T) {
	proxyHandler := new(ReverseProxy)
	proxyHandler.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
	proxyHandler.Director = func(*http.Request) {}     // noop
	proxyHandler.Transport = RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header == nil {
			t.Error("Header == nil; want a non-nil Header")
		}
		return nil, errors.New("done testing the interesting part; so force a 502 Gateway error")
	})

	proxyHandler.ServeHTTP(httptest.NewRecorder(), &http.Request{
		Method:     "GET",
		URL:        &url.URL{Scheme: "http", Host: "fake.tld", Path: "/"},
		Proto:      "HTTP/1.0",
		ProtoMajor: 1,
	})
}

// Issue 14237. Test ModifyResponse and that an error from it
// causes the proxy to return StatusBadGateway, or StatusOK otherwise.
func TestReverseProxyModifyResponse(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Hit-Mod", fmt.Sprintf("%v", r.URL.Path == "/mod"))
	}))
	defer backendServer.Close()

	rpURL, _ := url.Parse(backendServer.URL)
	rproxy := NewSingleHostReverseProxy(rpURL)
	rproxy.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
	rproxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Header.Get("X-Hit-Mod") != "true" {
			return fmt.Errorf("tried to by-pass proxy")
		}
		return nil
	}

	frontendProxy := httptest.NewServer(rproxy)
	defer frontendProxy.Close()

	tests := []struct {
		url      string
		wantCode int
	}{
		{frontendProxy.URL + "/mod", http.StatusOK},
		{frontendProxy.URL + "/schedule", http.StatusBadGateway},
	}

	for i, tt := range tests {
		resp, err := http.Get(tt.url)
		if err != nil {
			t.Fatalf("failed to reach proxy: %v", err)
		}
		if g, e := resp.StatusCode, tt.wantCode; g != e {
			t.Errorf("#%d: got res.StatusCode %d; expected %d", i, g, e)
		}
		resp.Body.Close()
	}
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("some error")
}

type staticResponseRoundTripper struct{ res *http.Response }

func (rt staticResponseRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return rt.res, nil
}

func TestReverseProxyErrorHandler(t *testing.T) {
	tests := []struct {
		name           string
		wantCode       int
		errorHandler   func(http.ResponseWriter, *http.Request, error)
		transport      http.RoundTripper // defaults to failingRoundTripper
		modifyResponse func(*http.Response) error
	}{
		{
			name:     "default",
			wantCode: http.StatusBadGateway,
		},
		{
			name:         "errorhandler",
			wantCode:     http.StatusTeapot,
			errorHandler: func(rw http.ResponseWriter, req *http.Request, err error) { rw.WriteHeader(http.StatusTeapot) },
		},
		{
			name: "modifyresponse_noerr",
			transport: staticResponseRoundTripper{
				&http.Response{StatusCode: 345, Body: http.NoBody},
			},
			modifyResponse: func(res *http.Response) error {
				res.StatusCode++
				return nil
			},
			errorHandler: func(rw http.ResponseWriter, req *http.Request, err error) { rw.WriteHeader(http.StatusTeapot) },
			wantCode:     346,
		},
		{
			name: "modifyresponse_err",
			transport: staticResponseRoundTripper{
				&http.Response{StatusCode: 345, Body: http.NoBody},
			},
			modifyResponse: func(res *http.Response) error {
				res.StatusCode++
				return errors.New("some error to trigger errorHandler")
			},
			errorHandler: func(rw http.ResponseWriter, req *http.Request, err error) { rw.WriteHeader(http.StatusTeapot) },
			wantCode:     http.StatusTeapot,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &url.URL{
				Scheme: "http",
				Host:   "dummy.tld",
				Path:   "/",
			}
			rproxy := NewSingleHostReverseProxy(target)
			rproxy.Transport = tt.transport
			rproxy.ModifyResponse = tt.modifyResponse
			if rproxy.Transport == nil {
				rproxy.Transport = failingRoundTripper{}
			}
			rproxy.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
			if tt.errorHandler != nil {
				rproxy.ErrorHandler = tt.errorHandler
			}
			frontendProxy := httptest.NewServer(rproxy)
			defer frontendProxy.Close()

			resp, err := http.Get(frontendProxy.URL + "/test")
			if err != nil {
				t.Fatalf("failed to reach proxy: %v", err)
			}
			if g, e := resp.StatusCode, tt.wantCode; g != e {
				t.Errorf("got res.StatusCode %d; expected %d", g, e)
			}
			resp.Body.Close()
		})
	}
}

// Issue 16659: log errors from short read
func TestReverseProxy_CopyBuffer(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := "this call was relayed by the reverse proxy"
		// Coerce a wrong content length to induce io.UnexpectedEOF
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)*2))
		fmt.Fprintln(w, out)
	}))
	defer backendServer.Close()

	rpURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	var proxyLog bytes.Buffer
	rproxy := NewSingleHostReverseProxy(rpURL)
	rproxy.ErrorLog = log.New(&proxyLog, "", log.Lshortfile)
	donec := make(chan bool, 1)
	frontendProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { donec <- true }()
		rproxy.ServeHTTP(w, r)
	}))
	defer frontendProxy.Close()

	if _, err = frontendProxy.Client().Get(frontendProxy.URL); err == nil {
		t.Fatalf("want non-nil error")
	}
	// The race detector complains about the proxyLog usage in logf in copyBuffer
	// and our usage below with proxyLog.Bytes() so we're explicitly using a
	// channel to ensure that the ReverseProxy's ServeHTTP is done before we
	// continue after Get.
	<-donec

	expected := []string{
		"EOF",
		"read",
	}
	for _, phrase := range expected {
		if !bytes.Contains(proxyLog.Bytes(), []byte(phrase)) {
			t.Errorf("expected log to contain phrase %q", phrase)
		}
	}
}

type staticTransport struct {
	res *http.Response
}

func (t *staticTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.res, nil
}

func BenchmarkServeHTTP(b *testing.B) {
	res := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("")),
	}
	proxy := &ReverseProxy{
		Director:  func(*http.Request) {},
		Transport: &staticTransport{res},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		proxy.ServeHTTP(w, r)
	}
}

func TestServeHTTPDeepCopy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Gopher!"))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		before, after string
	}

	resultChan := make(chan result, 1)
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		before := r.URL.String()
		proxyHandler.ServeHTTP(w, r)
		after := r.URL.String()
		resultChan <- result{before: before, after: after}
	}))
	defer frontend.Close()

	want := result{before: "/", after: "/"}

	res, err := frontend.Client().Get(frontend.URL)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	res.Body.Close()

	got := <-resultChan
	if got != want {
		t.Errorf("got = %+v; want = %+v", got, want)
	}
}

// Issue 18327: verify we always do a deep copy of the Request.Header map
// before any mutations.
func TestClonesRequestHeaders(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	req, _ := http.NewRequest("GET", "http://foo.tld/
"""




```