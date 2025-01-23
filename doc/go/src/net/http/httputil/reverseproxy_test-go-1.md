Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The prompt clearly states this is part of `go/src/net/http/httputil/reverseproxy_test.go`. This tells us we're dealing with tests for the `ReverseProxy` type in the `net/http/httputil` package. Knowing it's a testing file is crucial because it means the code focuses on verifying the behavior of `ReverseProxy` under different conditions.

2. **Identify the Core Component:** The key element is `ReverseProxy`. The tests are designed to exercise its functionality.

3. **Analyze Individual Test Functions:**  Go tests are functions starting with `Test`. We need to examine each one individually to understand what aspect of `ReverseProxy` it's testing.

4. **Deconstruct Each Test:** For each `Test...` function, ask:
    * **What is being set up?** This usually involves creating a `ReverseProxy` instance, a backend server (often using `httptest`), and sometimes specific configurations like `Director`, `Transport`, `ModifyResponse`, or `Rewrite`.
    * **What action is being performed?** This is typically calling `rp.ServeHTTP` or making a request to a frontend server that uses the `ReverseProxy`.
    * **What is being asserted?**  This is where the `t.Errorf` calls come in. They check for expected outcomes based on the setup and actions.

5. **Group Tests by Functionality:**  As you analyze the tests, you'll notice patterns. Some tests focus on:
    * Header manipulation (`TestDirectorHeaderMutation`, `TestModifyResponseClosesBody`, `TestReverseProxyWebSocket`)
    * Error handling (`TestReverseProxy_PanicBodyError`, `TestReverseProxy_PanicClosesIncomingBody`)
    * WebSocket proxying (`TestReverseProxyWebSocket`, `TestReverseProxyWebSocketCancellation`)
    * Flush intervals (`TestSelectFlushInterval`)
    * Request rewriting (`TestSetURL`, `TestReverseProxyRewriteReplacesOut`)
    * Query parameter handling (`TestReverseProxyQueryParameterSmuggling...`)
    * 1xx (Informational) responses (`Test1xxHeadersNotModifiedAfterRoundTrip`, `Test1xxResponses`)
    * Trailer headers (`TestUnannouncedTrailer`)

6. **Infer the Overall Functionality:** Based on the individual test functionalities, you can deduce the primary purpose of `ReverseProxy`: to act as a gateway, forwarding requests to backend servers and relaying responses back to clients, potentially modifying requests and responses along the way.

7. **Identify Key Concepts and Components:**  Note the use of:
    * `Director`: For modifying outgoing requests.
    * `Transport`: For customizing how requests are sent to the backend.
    * `ModifyResponse`: For altering responses from the backend.
    * `Rewrite`: For complete control over the outgoing request.
    * `httptest`: For easily creating mock HTTP servers.
    * `http.Hijacker`: For handling WebSocket connections.

8. **Address Specific Prompt Questions:**
    * **Functionality Listing:** Simply list the functionalities observed in the tests.
    * **Go Feature Illustration:** Choose relevant tests and provide simplified code examples. For instance, the `Director` test directly demonstrates header manipulation.
    * **Code Reasoning (Input/Output):**  Pick a test like `TestDirectorHeaderMutation` and explain the input request and the expected modification.
    * **Command-Line Arguments:**  The code doesn't directly show command-line argument processing for `ReverseProxy` itself, but the tests use `httptest.NewServer` which implicitly handles port selection. Mention this if applicable.
    * **Common Mistakes:**  Look for patterns where the tests are designed to *prevent* mistakes, such as the header mutation test showing that the original request isn't modified. The WebSocket tests also highlight the complexity of proper handling.
    * **Part 2 Summary:** Synthesize the observations into a concise summary of `ReverseProxy`'s role.

9. **Structure the Answer:** Organize the information logically using headings and bullet points for clarity. Use code blocks for examples and ensure the language is clear and concise.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about proxying HTTP."  **Correction:** Realize there's specific handling for WebSockets, 1xx responses, and the ability to deeply customize request/response flow, making it more sophisticated than a simple forwarder.
* **Focusing too much on low-level details:**  **Correction:**  Shift focus to the higher-level *purpose* and *capabilities* of `ReverseProxy` as revealed by the tests.
* **Overlooking the test's negative assertions:** **Correction:**  Pay attention to what the tests are *checking not to happen* (like the original request being modified). This provides insights into the intended behavior and potential pitfalls.

By following these steps and engaging in this kind of iterative analysis and refinement, we can arrive at a comprehensive and accurate understanding of the provided Go code snippet and answer the prompt effectively.
这是 Go 语言标准库 `net/http/httputil` 包中 `ReverseProxy` 的测试代码片段的第二部分。延续第一部分，这部分测试继续验证 `ReverseProxy` 的各种功能和边界情况。

以下是这部分代码的功能归纳：

**核心功能测试和增强：**

* **测试 `ModifyResponse` 的行为:**
    * 验证 `ModifyResponse` 函数是否能在处理响应后被调用。
    * 确认当 `ModifyResponse` 返回错误时，ReverseProxy 能正确处理并记录错误，并且关闭响应体。
* **处理后端响应体读取错误:**
    * 测试当后端响应体读取过程中发生错误（例如内容长度不匹配导致 `io.ErrUnexpectedEOF`）时，ReverseProxy 不会 panic，而是返回 `http.StatusBadRequest` 错误。
    * 验证在这种情况下，ReverseProxy 会调用 `http.ErrAbortHandler` 来终止请求处理。
* **处理上游请求体关闭:**
    * 测试当上游请求的 Body 在 ReverseProxy 处理过程中被关闭时，ReverseProxy 能否正确处理，避免 panic。这主要针对高并发场景，确保资源得到释放。
* **选择合适的 Flush 间隔:**
    * 测试 `flushInterval` 方法根据响应头信息（例如 `Content-Type: text/event-stream` 或 `Content-Length: -1`）来动态调整 Flush 间隔的能力，以优化性能或支持特定协议（如 Server-Sent Events）。
* **WebSocket 代理:**
    * 测试 ReverseProxy 作为 WebSocket 代理的功能。
    * 验证 Upgrade 请求头被正确传递。
    * 确认代理能正确转发 WebSocket 握手。
    * 检查 `ModifyResponse` 是否能在 WebSocket 场景下修改响应头。
    * 测试 WebSocket 连接建立后的消息转发。
* **WebSocket 取消（Context）：**
    * 测试当请求的 Context 被取消时，ReverseProxy 能否正确中断 WebSocket 连接的代理过程。
    * 验证在这种情况下，后端服务器的写入操作会失败。
* **处理未声明的 Trailer Headers:**
    * 测试 ReverseProxy 能否正确处理后端返回的未在 `Trailer` 字段中声明的 Trailer Headers。
* **使用 `Rewrite` 函数修改请求:**
    * 测试通过 `Rewrite` 函数完全自定义转发请求的能力，例如修改目标 URL。
* **测试 `singleJoiningSlash` 函数:**
    * 验证 `singleJoiningSlash` 函数正确拼接 URL 路径。
* **测试 `joinURLPath` 函数:**
    * 验证 `joinURLPath` 函数正确合并两个 URL 的 Path 和 RawPath。
* **使用 `Rewrite` 替换整个 Outgoing Request:**
    * 测试 `Rewrite` 函数可以将 `ProxyRequest` 中的 `Out` 字段替换为全新的请求，从而实现更复杂的转发逻辑。
* **确保 1xx 响应头在 RoundTrip 后不被修改:**
    * 测试在处理 1xx 响应（Informational Responses）时，即使在 `RoundTrip` 返回后发生错误，也不会修改 `ResponseWriter` 的头部信息，避免潜在的数据竞争。
* **处理 1xx 响应:**
    * 测试 ReverseProxy 能正确处理并转发 1xx 状态码的响应。
    * 使用 `httptrace.ClientTrace` 捕获和验证 1xx 响应的头部信息。
* **查询参数处理和防止注入:**
    * 测试 ReverseProxy 在处理查询参数时的不同策略：
        * `Director` 不解析 Form：保持原始的 `RawQuery`。
        * `Director` 解析 Form：移除无法解析的或重复的键。
        * 使用 `Rewrite`：可以清理或保持 `RawQuery`。
    * 重点在于防止恶意构造的查询参数注入。

**涉及的 Go 语言功能实现：**

* **`net/http` 包:**
    * **`http.Request` 和 `http.Response`:**  表示 HTTP 请求和响应。
    * **`http.Handler` 和 `http.HandlerFunc`:**  处理 HTTP 请求的接口和函数类型。
    * **`httptest` 包:**  用于创建测试用的 HTTP 服务器和客户端。
    * **`http.Hijacker`:**  用于劫持 HTTP 连接，以便进行 WebSocket 通信。
    * **`http.Header`:**  表示 HTTP 头部。
    * **`http.TrailerPrefix`:**  用于表示 Trailer Header 的前缀。
    * **`http.Flusher`:**  用于刷新 HTTP 响应。
    * **`http.Client`:**  用于发起 HTTP 请求。
* **`net/url` 包:**
    * **`url.URL`:**  表示 URL。
    * **`url.Parse`:**  解析 URL 字符串。
* **`io` 包:**
    * **`io.Reader`、`io.Writer` 和 `io.ReadWriteCloser`:**  用于读写数据流的接口。
    * **`io.Copy`:**  用于高效地复制数据流。
    * **`io.EOF` 和 `io.ErrUnexpectedEOF`:**  表示文件结束或意外的文件结束错误。
* **`strings` 包:**
    * **`strings.Builder`:**  用于高效地构建字符串。
    * **`strings.Contains`:**  检查字符串是否包含子字符串。
* **`log` 包:**
    * **`log.New`:**  创建新的日志记录器。
* **`sync` 包:**
    * **`sync.WaitGroup`:**  用于等待一组 goroutine 完成。
* **`context` 包:**
    * **`context.Context` 和 `context.WithCancel`:**  用于传递请求的上下文信息和实现取消操作。
* **`bufio` 包:**
    * **`bufio.NewScanner` 和 `bufio.NewReader`:**  提供缓冲的输入操作，用于读取行或字符串。
* **`time` 包:**
    * **`time.Duration` 和 `time.Sleep`:**  用于表示时间间隔和暂停执行。
* **`fmt` 包:**
    * **`fmt.Sprintf` 和 `fmt.Fprintln`:**  格式化字符串输出。
* **`unicode/ascii` 包:**
    * **`ascii.EqualFold`:**  用于不区分大小写地比较 ASCII 字符串。
* **`net/http/httptrace` 包:**
    * **`httptrace.ClientTrace` 和 `httptrace.WithClientTrace`:**  用于追踪 HTTP 客户端请求的生命周期事件，例如接收到 1xx 响应。
* **`mime/multipart` 包 (虽然本段代码未直接使用，但在处理 POST 请求时可能会涉及)**: 用于处理 `multipart/form-data`。
* **类型断言:**  例如 `w.(http.Hijacker)`，用于将接口类型转换为具体的类型。
* **匿名函数和闭包:**  在 `Director`、`Transport`、`ModifyResponse` 和 `Rewrite` 字段中使用了匿名函数来定义自定义的行为。

**Go 代码示例：**

**1. 使用 `Director` 修改请求头:**

```go
rp := &httputil.ReverseProxy{
	Director: func(req *http.Request) {
		req.Header.Set("X-Custom-Header", "custom-value")
	},
	Transport: &http.Transport{ /* ... */ },
}

// 假设有一个前端请求
req, _ := http.NewRequest("GET", "/api/resource", nil)
w := httptest.NewRecorder()
rp.ServeHTTP(w, req)

// 当请求被转发到后端时，会包含 X-Custom-Header: custom-value
```

**假设输入与输出 (针对 `TestDirectorHeaderMutation`):**

**输入:**

* 一个指向 `/` 的 GET 请求 `req`，`req.RemoteAddr` 为 "1.2.3.4:56789"。
* `ReverseProxy` 实例 `rp`，其 `Director` 设置了 `req.Header.Set("From-Director", "1")`，`Transport` 验证了 `req.Header.Get("From-Director")` 的值。

**输出:**

* `Transport` 中的断言会通过，因为 `Director` 正确设置了请求头。
* 原始的 `req.Header` 不会被 `Director` 的修改所影响，`X-Forwarded-For` 和 `From-Director` 头部在调用者的请求中仍然为空。

**命令行参数的具体处理:**

这段代码本身是测试代码，没有直接处理命令行参数。`ReverseProxy` 的配置通常是在代码中完成的，例如设置 `Director`、`Transport` 等字段。实际使用 `ReverseProxy` 的服务可能会通过命令行参数或配置文件来决定后端服务器的地址等信息，但这部分逻辑不在 `ReverseProxy` 本身。例如，可能会有如下形式的命令行参数：

```bash
./myproxy --backend-url=http://backend.example.com
```

然后在代码中解析这个参数，并配置 `ReverseProxy` 的 `Director` 或 `Transport`。

**使用者易犯错的点：**

* **错误地修改原始请求的 Header 或 URL:** `ReverseProxy` 的 `Director` 应该修改传入的 `*http.Request` 指针指向的请求，但需要注意不要在 `Director` 外部修改传递给 `ServeHTTP` 的原始请求对象，否则可能导致意外的副作用。测试 `TestDirectorHeaderMutation` 就是为了验证这一点。
* **不理解 `X-Forwarded-For` 的工作原理:** 用户可能期望 `ReverseProxy` 自动添加 `X-Forwarded-For` 头，但如果配置不当或使用了自定义的 `Director`，可能导致该头部丢失或不正确。
* **在 `ModifyResponse` 中修改了不应该修改的内容:**  例如，尝试修改已经发送到客户端的头部。`ModifyResponse` 在响应完全生成后调用，此时修改部分头部可能无效。
* **WebSocket 代理配置错误:**  没有正确设置 `Upgrade` 和 `Connection` 头，导致 WebSocket 握手失败。
* **忽略处理 1xx 响应:**  一些应用可能会忽略或错误处理 1xx 状态码的响应，导致性能优化机会的丢失。

**总结一下它的功能**

这部分代码延续了第一部分的工作，深入测试了 `net/http/httputil.ReverseProxy` 的更多高级特性和边界情况，包括：

* **响应修改和错误处理:**  验证 `ModifyResponse` 的功能和错误处理机制。
* **请求体和响应体处理:**  测试在读取请求体或响应体时发生错误的情况。
* **动态 Flush 间隔:**  验证根据响应头动态调整 Flush 间隔的能力。
* **WebSocket 代理的完整功能:**  包括握手、消息转发和连接取消。
* **请求重写机制:**  测试使用 `Rewrite` 函数修改转发请求的能力。
* **1xx 响应的处理:**  验证对 Informational 响应的处理和转发。
* **查询参数处理策略:**  测试不同的查询参数处理策略以及防止注入的机制。

总而言之，这部分测试覆盖了 `ReverseProxy` 的更复杂和细致的功能，确保了其在各种场景下的稳定性和正确性，特别是涉及到 WebSocket、1xx 响应和请求/响应修改等高级用法。

### 提示词
```
这是路径为go/src/net/http/httputil/reverseproxy_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
", nil)
	req.RemoteAddr = "1.2.3.4:56789"
	rp := &ReverseProxy{
		Director: func(req *http.Request) {
			req.Header.Set("From-Director", "1")
		},
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if v := req.Header.Get("From-Director"); v != "1" {
				t.Errorf("From-Directory value = %q; want 1", v)
			}
			return nil, io.EOF
		}),
	}
	rp.ServeHTTP(httptest.NewRecorder(), req)

	for _, h := range []string{
		"From-Director",
		"X-Forwarded-For",
	} {
		if req.Header.Get(h) != "" {
			t.Errorf("%v header mutation modified caller's request", h)
		}
	}
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestModifyResponseClosesBody(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://foo.tld/", nil)
	req.RemoteAddr = "1.2.3.4:56789"
	closeCheck := new(checkCloser)
	logBuf := new(strings.Builder)
	outErr := errors.New("ModifyResponse error")
	rp := &ReverseProxy{
		Director: func(req *http.Request) {},
		Transport: &staticTransport{&http.Response{
			StatusCode: 200,
			Body:       closeCheck,
		}},
		ErrorLog: log.New(logBuf, "", 0),
		ModifyResponse: func(*http.Response) error {
			return outErr
		},
	}
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	res := rec.Result()
	if g, e := res.StatusCode, http.StatusBadGateway; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	if !closeCheck.closed {
		t.Errorf("body should have been closed")
	}
	if g, e := logBuf.String(), outErr.Error(); !strings.Contains(g, e) {
		t.Errorf("ErrorLog %q does not contain %q", g, e)
	}
}

type checkCloser struct {
	closed bool
}

func (cc *checkCloser) Close() error {
	cc.closed = true
	return nil
}

func (cc *checkCloser) Read(b []byte) (int, error) {
	return len(b), nil
}

// Issue 23643: panic on body copy error
func TestReverseProxy_PanicBodyError(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := "this call was relayed by the reverse proxy"
		// Coerce a wrong content length to induce io.ErrUnexpectedEOF
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)*2))
		fmt.Fprintln(w, out)
	}))
	defer backendServer.Close()

	rpURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	rproxy := NewSingleHostReverseProxy(rpURL)

	// Ensure that the handler panics when the body read encounters an
	// io.ErrUnexpectedEOF
	defer func() {
		err := recover()
		if err == nil {
			t.Fatal("handler should have panicked")
		}
		if err != http.ErrAbortHandler {
			t.Fatal("expected ErrAbortHandler, got", err)
		}
	}()
	req, _ := http.NewRequest("GET", "http://foo.tld/", nil)
	rproxy.ServeHTTP(httptest.NewRecorder(), req)
}

// Issue #46866: panic without closing incoming request body causes a panic
func TestReverseProxy_PanicClosesIncomingBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := "this call was relayed by the reverse proxy"
		// Coerce a wrong content length to induce io.ErrUnexpectedEOF
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)*2))
		fmt.Fprintln(w, out)
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

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				const reqLen = 6 * 1024 * 1024
				req, _ := http.NewRequest("POST", frontend.URL, &io.LimitedReader{R: neverEnding('x'), N: reqLen})
				req.ContentLength = reqLen
				resp, _ := frontendClient.Transport.RoundTrip(req)
				if resp != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func TestSelectFlushInterval(t *testing.T) {
	tests := []struct {
		name string
		p    *ReverseProxy
		res  *http.Response
		want time.Duration
	}{
		{
			name: "default",
			res:  &http.Response{},
			p:    &ReverseProxy{FlushInterval: 123},
			want: 123,
		},
		{
			name: "server-sent events overrides non-zero",
			res: &http.Response{
				Header: http.Header{
					"Content-Type": {"text/event-stream"},
				},
			},
			p:    &ReverseProxy{FlushInterval: 123},
			want: -1,
		},
		{
			name: "server-sent events overrides zero",
			res: &http.Response{
				Header: http.Header{
					"Content-Type": {"text/event-stream"},
				},
			},
			p:    &ReverseProxy{FlushInterval: 0},
			want: -1,
		},
		{
			name: "server-sent events with media-type parameters overrides non-zero",
			res: &http.Response{
				Header: http.Header{
					"Content-Type": {"text/event-stream;charset=utf-8"},
				},
			},
			p:    &ReverseProxy{FlushInterval: 123},
			want: -1,
		},
		{
			name: "server-sent events with media-type parameters overrides zero",
			res: &http.Response{
				Header: http.Header{
					"Content-Type": {"text/event-stream;charset=utf-8"},
				},
			},
			p:    &ReverseProxy{FlushInterval: 0},
			want: -1,
		},
		{
			name: "Content-Length: -1, overrides non-zero",
			res: &http.Response{
				ContentLength: -1,
			},
			p:    &ReverseProxy{FlushInterval: 123},
			want: -1,
		},
		{
			name: "Content-Length: -1, overrides zero",
			res: &http.Response{
				ContentLength: -1,
			},
			p:    &ReverseProxy{FlushInterval: 0},
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p.flushInterval(tt.res)
			if got != tt.want {
				t.Errorf("flushLatency = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestReverseProxyWebSocket(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upgradeType(r.Header) != "websocket" {
			t.Error("unexpected backend request")
			http.Error(w, "unexpected request", 400)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: WebSocket\r\n\r\n")
		bs := bufio.NewScanner(c)
		if !bs.Scan() {
			t.Errorf("backend failed to read line from client: %v", bs.Err())
			return
		}
		fmt.Fprintf(c, "backend got %q\n", bs.Text())
	}))
	defer backendServer.Close()

	backURL, _ := url.Parse(backendServer.URL)
	rproxy := NewSingleHostReverseProxy(backURL)
	rproxy.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
	rproxy.ModifyResponse = func(res *http.Response) error {
		res.Header.Add("X-Modified", "true")
		return nil
	}

	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Header", "X-Value")
		rproxy.ServeHTTP(rw, req)
		if got, want := rw.Header().Get("X-Modified"), "true"; got != want {
			t.Errorf("response writer X-Modified header = %q; want %q", got, want)
		}
	})

	frontendProxy := httptest.NewServer(handler)
	defer frontendProxy.Close()

	req, _ := http.NewRequest("GET", frontendProxy.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	c := frontendProxy.Client()
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("status = %v; want 101", res.Status)
	}

	got := res.Header.Get("X-Header")
	want := "X-Value"
	if got != want {
		t.Errorf("Header(XHeader) = %q; want %q", got, want)
	}

	if !ascii.EqualFold(upgradeType(res.Header), "websocket") {
		t.Fatalf("not websocket upgrade; got %#v", res.Header)
	}
	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("response body is of type %T; does not implement ReadWriteCloser", res.Body)
	}
	defer rwc.Close()

	if got, want := res.Header.Get("X-Modified"), "true"; got != want {
		t.Errorf("response X-Modified header = %q; want %q", got, want)
	}

	io.WriteString(rwc, "Hello\n")
	bs := bufio.NewScanner(rwc)
	if !bs.Scan() {
		t.Fatalf("Scan: %v", bs.Err())
	}
	got = bs.Text()
	want = `backend got "Hello"`
	if got != want {
		t.Errorf("got %#q, want %#q", got, want)
	}
}

func TestReverseProxyWebSocketCancellation(t *testing.T) {
	n := 5
	triggerCancelCh := make(chan bool, n)
	nthResponse := func(i int) string {
		return fmt.Sprintf("backend response #%d\n", i)
	}
	terminalMsg := "final message"

	cst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g, ws := upgradeType(r.Header), "websocket"; g != ws {
			t.Errorf("Unexpected upgrade type %q, want %q", g, ws)
			http.Error(w, "Unexpected request", 400)
			return
		}
		conn, bufrw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		upgradeMsg := "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: WebSocket\r\n\r\n"
		if _, err := io.WriteString(conn, upgradeMsg); err != nil {
			t.Error(err)
			return
		}
		if _, _, err := bufrw.ReadLine(); err != nil {
			t.Errorf("Failed to read line from client: %v", err)
			return
		}

		for i := 0; i < n; i++ {
			if _, err := bufrw.WriteString(nthResponse(i)); err != nil {
				select {
				case <-triggerCancelCh:
				default:
					t.Errorf("Writing response #%d failed: %v", i, err)
				}
				return
			}
			bufrw.Flush()
			time.Sleep(time.Second)
		}
		if _, err := bufrw.WriteString(terminalMsg); err != nil {
			select {
			case <-triggerCancelCh:
			default:
				t.Errorf("Failed to write terminal message: %v", err)
			}
		}
		bufrw.Flush()
	}))
	defer cst.Close()

	backendURL, _ := url.Parse(cst.URL)
	rproxy := NewSingleHostReverseProxy(backendURL)
	rproxy.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests
	rproxy.ModifyResponse = func(res *http.Response) error {
		res.Header.Add("X-Modified", "true")
		return nil
	}

	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("X-Header", "X-Value")
		ctx, cancel := context.WithCancel(req.Context())
		go func() {
			<-triggerCancelCh
			cancel()
		}()
		rproxy.ServeHTTP(rw, req.WithContext(ctx))
	})

	frontendProxy := httptest.NewServer(handler)
	defer frontendProxy.Close()

	req, _ := http.NewRequest("GET", frontendProxy.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res, err := frontendProxy.Client().Do(req)
	if err != nil {
		t.Fatalf("Dialing to frontend proxy: %v", err)
	}
	defer res.Body.Close()
	if g, w := res.StatusCode, 101; g != w {
		t.Fatalf("Switching protocols failed, got: %d, want: %d", g, w)
	}

	if g, w := res.Header.Get("X-Header"), "X-Value"; g != w {
		t.Errorf("X-Header mismatch\n\tgot:  %q\n\twant: %q", g, w)
	}

	if g, w := upgradeType(res.Header), "websocket"; !ascii.EqualFold(g, w) {
		t.Fatalf("Upgrade header mismatch\n\tgot:  %q\n\twant: %q", g, w)
	}

	rwc, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("Response body type mismatch, got %T, want io.ReadWriteCloser", res.Body)
	}

	if got, want := res.Header.Get("X-Modified"), "true"; got != want {
		t.Errorf("response X-Modified header = %q; want %q", got, want)
	}

	if _, err := io.WriteString(rwc, "Hello\n"); err != nil {
		t.Fatalf("Failed to write first message: %v", err)
	}

	// Read loop.

	br := bufio.NewReader(rwc)
	for {
		line, err := br.ReadString('\n')
		switch {
		case line == terminalMsg: // this case before "err == io.EOF"
			t.Fatalf("The websocket request was not canceled, unfortunately!")

		case err == io.EOF:
			return

		case err != nil:
			t.Fatalf("Unexpected error: %v", err)

		case line == nthResponse(0): // We've gotten the first response back
			// Let's trigger a cancel.
			close(triggerCancelCh)
		}
	}
}

func TestUnannouncedTrailer(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
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

	res, err := frontendClient.Get(frontend.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	io.ReadAll(res.Body)
	res.Body.Close()
	if g, w := res.Trailer.Get("X-Unannounced-Trailer"), "unannounced_trailer_value"; g != w {
		t.Errorf("Trailer(X-Unannounced-Trailer) = %q; want %q", g, w)
	}

}

func TestSetURL(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Host))
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
	frontendClient := frontend.Client()

	res, err := frontendClient.Get(frontend.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Reading body: %v", err)
	}

	if got, want := string(body), backendURL.Host; got != want {
		t.Errorf("backend got Host %q, want %q", got, want)
	}
}

func TestSingleJoinSlash(t *testing.T) {
	tests := []struct {
		slasha   string
		slashb   string
		expected string
	}{
		{"https://www.google.com/", "/favicon.ico", "https://www.google.com/favicon.ico"},
		{"https://www.google.com", "/favicon.ico", "https://www.google.com/favicon.ico"},
		{"https://www.google.com", "favicon.ico", "https://www.google.com/favicon.ico"},
		{"https://www.google.com", "", "https://www.google.com/"},
		{"", "favicon.ico", "/favicon.ico"},
	}
	for _, tt := range tests {
		if got := singleJoiningSlash(tt.slasha, tt.slashb); got != tt.expected {
			t.Errorf("singleJoiningSlash(%q,%q) want %q got %q",
				tt.slasha,
				tt.slashb,
				tt.expected,
				got)
		}
	}
}

func TestJoinURLPath(t *testing.T) {
	tests := []struct {
		a        *url.URL
		b        *url.URL
		wantPath string
		wantRaw  string
	}{
		{&url.URL{Path: "/a/b"}, &url.URL{Path: "/c"}, "/a/b/c", ""},
		{&url.URL{Path: "/a/b", RawPath: "badpath"}, &url.URL{Path: "c"}, "/a/b/c", "/a/b/c"},
		{&url.URL{Path: "/a/b", RawPath: "/a%2Fb"}, &url.URL{Path: "/c"}, "/a/b/c", "/a%2Fb/c"},
		{&url.URL{Path: "/a/b", RawPath: "/a%2Fb"}, &url.URL{Path: "/c"}, "/a/b/c", "/a%2Fb/c"},
		{&url.URL{Path: "/a/b/", RawPath: "/a%2Fb%2F"}, &url.URL{Path: "c"}, "/a/b//c", "/a%2Fb%2F/c"},
		{&url.URL{Path: "/a/b/", RawPath: "/a%2Fb/"}, &url.URL{Path: "/c/d", RawPath: "/c%2Fd"}, "/a/b/c/d", "/a%2Fb/c%2Fd"},
	}

	for _, tt := range tests {
		p, rp := joinURLPath(tt.a, tt.b)
		if p != tt.wantPath || rp != tt.wantRaw {
			t.Errorf("joinURLPath(URL(%q,%q),URL(%q,%q)) want (%q,%q) got (%q,%q)",
				tt.a.Path, tt.a.RawPath,
				tt.b.Path, tt.b.RawPath,
				tt.wantPath, tt.wantRaw,
				p, rp)
		}
	}
}

func TestReverseProxyRewriteReplacesOut(t *testing.T) {
	const content = "response_content"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer backend.Close()
	proxyHandler := &ReverseProxy{
		Rewrite: func(r *ProxyRequest) {
			r.Out, _ = http.NewRequest("GET", backend.URL, nil)
		},
	}
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	res, err := frontend.Client().Get(frontend.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if got, want := string(body), content; got != want {
		t.Errorf("got response %q, want %q", got, want)
	}
}

func Test1xxHeadersNotModifiedAfterRoundTrip(t *testing.T) {
	// https://go.dev/issue/65123: We use httptrace.Got1xxResponse to capture 1xx responses
	// and proxy them. httptrace handlers can execute after RoundTrip returns, in particular
	// after experiencing connection errors. When this happens, we shouldn't modify the
	// ResponseWriter headers after ReverseProxy.ServeHTTP returns.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 5; i++ {
			w.WriteHeader(103)
		}
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.ErrorLog = log.New(io.Discard, "", 0) // quiet for tests

	rw := &testResponseWriter{}
	func() {
		// Cancel the request (and cause RoundTrip to return) immediately upon
		// seeing a 1xx response.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
				cancel()
				return nil
			},
		})

		req, _ := http.NewRequestWithContext(ctx, "GET", "http://go.dev/", nil)
		proxyHandler.ServeHTTP(rw, req)
	}()
	// Trigger data race while iterating over response headers.
	// When run with -race, this causes the condition in https://go.dev/issue/65123 often
	// enough to detect reliably.
	for _ = range rw.Header() {
	}
}

func Test1xxResponses(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Link", "</style.css>; rel=preload; as=style")
		h.Add("Link", "</script.js>; rel=preload; as=script")
		w.WriteHeader(http.StatusEarlyHints)

		h.Add("Link", "</foo.js>; rel=preload; as=script")
		w.WriteHeader(http.StatusProcessing)

		w.Write([]byte("Hello"))
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

	checkLinkHeaders := func(t *testing.T, expected, got []string) {
		t.Helper()

		if len(expected) != len(got) {
			t.Errorf("Expected %d link headers; got %d", len(expected), len(got))
		}

		for i := range expected {
			if i >= len(got) {
				t.Errorf("Expected %q link header; got nothing", expected[i])

				continue
			}

			if expected[i] != got[i] {
				t.Errorf("Expected %q link header; got %q", expected[i], got[i])
			}
		}
	}

	var respCounter uint8
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			switch code {
			case http.StatusEarlyHints:
				checkLinkHeaders(t, []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script"}, header["Link"])
			case http.StatusProcessing:
				checkLinkHeaders(t, []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script", "</foo.js>; rel=preload; as=script"}, header["Link"])
			default:
				t.Error("Unexpected 1xx response")
			}

			respCounter++

			return nil
		},
	}
	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", frontend.URL, nil)

	res, err := frontendClient.Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	defer res.Body.Close()

	if respCounter != 2 {
		t.Errorf("Expected 2 1xx responses; got %d", respCounter)
	}
	checkLinkHeaders(t, []string{"</style.css>; rel=preload; as=style", "</script.js>; rel=preload; as=script", "</foo.js>; rel=preload; as=script"}, res.Header["Link"])

	body, _ := io.ReadAll(res.Body)
	if string(body) != "Hello" {
		t.Errorf("Read body %q; want Hello", body)
	}
}

const (
	testWantsCleanQuery = true
	testWantsRawQuery   = false
)

func TestReverseProxyQueryParameterSmugglingDirectorDoesNotParseForm(t *testing.T) {
	testReverseProxyQueryParameterSmuggling(t, testWantsRawQuery, func(u *url.URL) *ReverseProxy {
		proxyHandler := NewSingleHostReverseProxy(u)
		oldDirector := proxyHandler.Director
		proxyHandler.Director = func(r *http.Request) {
			oldDirector(r)
		}
		return proxyHandler
	})
}

func TestReverseProxyQueryParameterSmugglingDirectorParsesForm(t *testing.T) {
	testReverseProxyQueryParameterSmuggling(t, testWantsCleanQuery, func(u *url.URL) *ReverseProxy {
		proxyHandler := NewSingleHostReverseProxy(u)
		oldDirector := proxyHandler.Director
		proxyHandler.Director = func(r *http.Request) {
			// Parsing the form causes ReverseProxy to remove unparsable
			// query parameters before forwarding.
			r.FormValue("a")
			oldDirector(r)
		}
		return proxyHandler
	})
}

func TestReverseProxyQueryParameterSmugglingRewrite(t *testing.T) {
	testReverseProxyQueryParameterSmuggling(t, testWantsCleanQuery, func(u *url.URL) *ReverseProxy {
		return &ReverseProxy{
			Rewrite: func(r *ProxyRequest) {
				r.SetURL(u)
			},
		}
	})
}

func TestReverseProxyQueryParameterSmugglingRewritePreservesRawQuery(t *testing.T) {
	testReverseProxyQueryParameterSmuggling(t, testWantsRawQuery, func(u *url.URL) *ReverseProxy {
		return &ReverseProxy{
			Rewrite: func(r *ProxyRequest) {
				r.SetURL(u)
				r.Out.URL.RawQuery = r.In.URL.RawQuery
			},
		}
	})
}

func testReverseProxyQueryParameterSmuggling(t *testing.T, wantCleanQuery bool, newProxy func(*url.URL) *ReverseProxy) {
	const content = "response_content"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.RawQuery))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := newProxy(backendURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	// Don't spam output with logs of queries containing semicolons.
	backend.Config.ErrorLog = log.New(io.Discard, "", 0)
	frontend.Config.ErrorLog = log.New(io.Discard, "", 0)

	for _, test := range []struct {
		rawQuery   string
		cleanQuery string
	}{{
		rawQuery:   "a=1&a=2;b=3",
		cleanQuery: "a=1",
	}, {
		rawQuery:   "a=1&a=%zz&b=3",
		cleanQuery: "a=1&b=3",
	}} {
		res, err := frontend.Client().Get(frontend.URL + "?" + test.rawQuery)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		wantQuery := test.rawQuery
		if wantCleanQuery {
			wantQuery = test.cleanQuery
		}
		if got, want := string(body), wantQuery; got != want {
			t.Errorf("proxy forwarded raw query %q as %q, want %q", test.rawQuery, got, want)
		}
	}
}

type testResponseWriter struct {
	h           http.Header
	writeHeader func(int)
	write       func([]byte) (int, error)
}

func (rw *testResponseWriter) Header() http.Header {
	if rw.h == nil {
		rw.h = make(http.Header)
	}
	return rw.h
}

func (rw *testResponseWriter) WriteHeader(statusCode int) {
	if rw.writeHeader != nil {
		rw.writeHeader(statusCode)
	}
}

func (rw *testResponseWriter) Write(p []byte) (int, error) {
	if rw.write != nil {
		return rw.write(p)
	}
	return len(p), nil
}
```