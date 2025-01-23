Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the given Go code, which is a part of `go/src/net/http/client_test.go`. This means the code is testing the `net/http` client functionality.

2. **Identify Key Components:**  The code is organized into Go test functions. Each function likely tests a specific aspect of the HTTP client. We can identify these individual tests by the `func Test...` and `func test...` naming convention.

3. **Analyze Individual Test Functions:**  Go through each test function and understand its purpose. Look for clues within the function name, variable names, and the operations being performed.

    * **`TestClientGetErrorURLPassword` and `testClientGetErrorURLPassword`:** The variable names `in` and `out` and the string comparisons suggest this test is about how the client handles URLs with passwords in error messages. Specifically, it appears to be verifying that passwords are redacted (replaced with "***").

    * **`TestClientTimeout` and `testClientTimeout`:** The names and the use of `time.Millisecond` and checks for errors containing "Client.Timeout" clearly indicate this test focuses on the client's timeout mechanism. It appears to be testing scenarios where a timeout occurs while waiting for a response body.

    * **`TestClientTimeout_Headers` and `testClientTimeout_Headers`:** Similar to the previous test, but the name suggests a focus on timeouts occurring *before* receiving response headers.

    * **`TestClientTimeoutCancel` and `testClientTimeoutCancel`:** The use of `context.WithCancel` in the function name points to testing the interaction between the client's timeout and request cancellation. It looks like it's verifying that cancellation takes precedence over the timeout.

    * **`TestClientTimeoutDoesNotExpire` and `testClientTimeoutDoesNotExpire`:** This name suggests testing a scenario where a timeout is set but the request completes successfully *before* the timeout.

    * **`TestClientRedirectEatsBody_h1` and `testClientRedirectEatsBody`:** The name "RedirectEatsBody" is a strong hint. This likely tests that when a redirect occurs, the client correctly consumes the body of the redirect response (even though it's not used). The comparison of `r.RemoteAddr` before and after the redirect is interesting and warrants attention.

    * **`TestReferer`:** The function name clearly indicates this test is about the "Referer" header. The various test cases suggest different scenarios for setting or omitting the Referer header during requests.

    * **`TestClientRedirectResponseWithoutRequest`:**  The comment and the custom `issue15577Tripper` suggest this tests a specific edge case where a `RoundTripper` returns a redirect response without setting the `Request` field, and verifies the client doesn't crash.

    * **`TestClientCopyHeadersOnRedirect` and `testClientCopyHeadersOnRedirect`:** The name clearly points to testing header copying during redirects. The test checks if specific headers like "User-Agent", "X-Foo", "Cookie", and "Authorization" are correctly forwarded after a redirect.

    * **`TestClientCopyHostOnRedirect` and `testClientCopyHostOnRedirect`:** This focuses on copying the `Host` header during redirects, especially relative redirects. The use of a "virtual host" adds complexity and suggests testing how the client handles different hostname scenarios.

    * **`TestClientAltersCookiesOnRedirect` and `testClientAltersCookiesOnRedirect`:** This test is specifically about how cookies are managed when redirects occur. It checks how cookies are added, deleted, and modified during redirect sequences.

    * **`TestShouldCopyHeaderOnRedirect`:** This test function appears to be testing the internal logic of `shouldCopyHeaderOnRedirect`, determining which headers should be copied during redirects based on the source and destination URLs.

    * **`TestClientRedirectTypes` and `testClientRedirectTypes`:** This test covers different HTTP redirect status codes (301, 302, 303, 307, 308) and verifies that the client uses the correct HTTP method after the redirect based on the status code.

    * **`TestTransportBodyReadError` and `testTransportBodyReadError`:** The name and the use of a custom `issue18239Body` with a specific error suggest testing how the `Transport` handles errors when reading the request body, particularly in the context of retries.

    * **`TestClientCloseIdleConnections`:** This test checks the functionality of `Client.CloseIdleConnections`.

    * **`TestClientPropagatesTimeoutToContext`:** This test verifies that the `Client.Timeout` setting is correctly propagated to the request's context as a deadline.

    * **`TestClientDoCanceledVsTimeout` and `testClientDoCanceledVsTimeout`:** This test explicitly compares the behavior of `Client.Do` when a request is canceled versus when it times out.

    * **`TestClientPopulatesNilResponseBody`:** This test addresses a specific case where the server returns a response with a `nil` body, and verifies the client correctly handles this.

    * **`TestClientCallsCloseOnlyOnce` and `testClientCallsCloseOnlyOnce`:** This test uses a custom body reader (`issue40382Body`) to ensure that the client calls `Close` on the request body only once, even in error scenarios.

    * **`TestProbeZeroLengthBody` and `testProbeZeroLengthBody`:** This test investigates how the client handles request bodies where the size is initially unknown (e.g., using a pipe). It appears to test a mechanism where the client waits briefly before sending the request to try and determine the body length.

4. **Synthesize a Summary:** After analyzing each test, group related functionalities and summarize the overall purpose of the code. Emphasize that it's a *test* file for the HTTP client, and therefore its function is to verify various aspects of client behavior.

5. **Provide Code Examples:** For key functionalities identified, construct simple Go code examples that demonstrate the tested features. This requires making educated guesses about the intended usage based on the test code. For example, the timeout tests lead to an example showing how to set `Client.Timeout`.

6. **Address Potential Pitfalls:** Think about common mistakes developers might make when using the functionalities being tested. The timeout tests naturally suggest mentioning the need to check for `context.DeadlineExceeded`. The redirect tests might suggest potential issues with cookie handling or header forwarding.

7. **Review and Refine:** Read through the summary and examples, ensuring clarity, accuracy, and completeness. Check that the language is in Chinese as requested. Make sure the connection back to the original file path (`go/src/net/http/client_test.go`) is clear.
这是 `go/src/net/http/client_test.go` 文件的一部分，主要功能是**测试 Go 语言 `net/http` 包中 `Client` 类型的各种功能和行为**。

这是该测试文件的第 2 部分，所以我们来归纳一下这部分代码的功能：

**本部分代码主要测试了以下 `net/http.Client` 的功能：**

1. **处理包含密码的 URL 时的错误信息脱敏：** 验证当 `Client` 尝试访问包含用户名和密码的 URL 发生错误时，错误信息中密码部分会被替换为 `***`，以防止敏感信息泄露。

2. **客户端超时机制：**
   - 测试 `Client.Timeout` 字段的功能，验证在指定时间内未完成请求时，客户端会返回超时错误。
   - 涵盖了在接收到部分响应体后超时的情况。
   - 测试在尚未接收到响应头时就发生超时的情况。
   - 测试当使用 `context.WithCancel` 取消请求时，即使设置了 `Client.Timeout`，取消操作会优先于超时。
   - 验证当设置了 `Client.Timeout` 但请求在超时前完成时，不会返回超时错误。

3. **处理重定向时的行为：**
   - **确保在重定向后消费掉原始响应的 Body：**  避免资源泄漏。
   - **正确设置 `Referer` 请求头：** 验证在重定向时，`Referer` 请求头的设置规则，例如不包含用户名密码，以及 HTTPS 到 HTTP 的降级时不发送 `Referer`。
   - **处理 `RoundTripper` 返回的重定向响应中缺少 `Request` 字段的情况：** 确保客户端不会因此崩溃。
   - **在重定向时复制请求头：** 测试哪些请求头（如 `User-Agent`，自定义头）会在重定向时被复制，以及哪些敏感头（如 `Cookie`，`Authorization`）在跨域或降级时不被复制。
   - **在相对重定向时复制 `Host` 请求头：** 确保即使是相对路径的重定向，`Host` 头也会被正确传递。
   - **在重定向时修改 Cookie：** 验证在重定向过程中，`Set-Cookie` 响应头能够正确地更新客户端的 Cookie Jar。
   - **判断哪些请求头应该在重定向时被复制的内部逻辑：**  测试 `shouldCopyHeaderOnRedirect` 函数的逻辑。
   - **根据不同的重定向状态码 (301, 302, 303, 307, 308) 使用正确的请求方法：**  例如，POST 请求在遇到 301 或 302 时会被转换为 GET 请求，而 307 和 308 会保持原有的请求方法。

4. **处理请求体读取错误：**
   - 验证当 `Request.Body` 的 `Read` 方法返回错误时，`Transport` 不会重试请求，除非 `Request` 实现了 `GetBody` 方法。

5. **管理空闲连接：**
   - 测试 `Client.CloseIdleConnections` 方法的功能，确保能够正常调用，即使底层的 `Transport` 没有实现该方法。

6. **将 `Client.Timeout` 传递到 `context.Context`：** 验证设置在 `Client` 上的超时时间会正确地传递到请求的 `context.Context` 中，作为截止时间 (deadline)。

7. **区分请求取消和超时错误：** 验证使用 `context.WithCancel` 取消的请求会返回 `context.Canceled` 错误，而因超时发生的错误会返回 `context.DeadlineExceeded` 错误。

8. **处理响应体为 `nil` 的情况：** 验证当服务器返回的响应体的 `Body` 为 `nil` 时，客户端能够正常处理，并提供一个可以正常 `Close` 和读取 (返回空) 的虚拟 `Body`。

9. **确保 `Request.Body` 的 `Close` 方法只被调用一次：**  即使在请求过程中发生错误，也要保证 `Body` 的 `Close` 方法不会被多次调用。

10. **探测零长度请求体：**  测试当请求体是一个管道 (pipe) 且初始时长度未知时，客户端会短暂等待，尝试探测请求体的长度，然后再发送请求。

总而言之，这部分测试代码覆盖了 `net/http.Client` 在处理各种复杂场景下的行为，包括错误处理、超时控制、重定向处理、请求头和 Cookie 的管理等，确保了 `net/http` 包的健壮性和可靠性。

### 提示词
```
这是路径为go/src/net/http/client_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
t: &recordingTransport{}}
	testCases := []struct {
		desc string
		in   string
		out  string
	}{
		{
			desc: "Strip password from error message",
			in:   "http://user:password@dummy.faketld/",
			out:  `Get "http://user:***@dummy.faketld/": dummy impl`,
		},
		{
			desc: "Don't Strip password from domain name",
			in:   "http://user:password@password.faketld/",
			out:  `Get "http://user:***@password.faketld/": dummy impl`,
		},
		{
			desc: "Don't Strip password from path",
			in:   "http://user:password@dummy.faketld/password",
			out:  `Get "http://user:***@dummy.faketld/password": dummy impl`,
		},
		{
			desc: "Strip escaped password",
			in:   "http://user:pa%2Fssword@dummy.faketld/",
			out:  `Get "http://user:***@dummy.faketld/": dummy impl`,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			_, err := client.Get(tC.in)
			if err.Error() != tC.out {
				t.Errorf("Unexpected output for %q: expected %q, actual %q",
					tC.in, tC.out, err.Error())
			}
		})
	}
}

func TestClientTimeout(t *testing.T) { run(t, testClientTimeout) }
func testClientTimeout(t *testing.T, mode testMode) {
	var (
		mu           sync.Mutex
		nonce        string // a unique per-request string
		sawSlowNonce bool   // true if the handler saw /slow?nonce=<nonce>
	)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/" {
			Redirect(w, r, "/slow?nonce="+r.Form.Get("nonce"), StatusFound)
			return
		}
		if r.URL.Path == "/slow" {
			mu.Lock()
			if r.Form.Get("nonce") == nonce {
				sawSlowNonce = true
			} else {
				t.Logf("mismatched nonce: received %s, want %s", r.Form.Get("nonce"), nonce)
			}
			mu.Unlock()

			w.Write([]byte("Hello"))
			w.(Flusher).Flush()
			<-r.Context().Done()
			return
		}
	}))

	// Try to trigger a timeout after reading part of the response body.
	// The initial timeout is empirically usually long enough on a decently fast
	// machine, but if we undershoot we'll retry with exponentially longer
	// timeouts until the test either passes or times out completely.
	// This keeps the test reasonably fast in the typical case but allows it to
	// also eventually succeed on arbitrarily slow machines.
	timeout := 10 * time.Millisecond
	nextNonce := 0
	for ; ; timeout *= 2 {
		if timeout <= 0 {
			// The only way we can feasibly hit this while the test is running is if
			// the request fails without actually waiting for the timeout to occur.
			t.Fatalf("timeout overflow")
		}
		if deadline, ok := t.Deadline(); ok && !time.Now().Add(timeout).Before(deadline) {
			t.Fatalf("failed to produce expected timeout before test deadline")
		}
		t.Logf("attempting test with timeout %v", timeout)
		cst.c.Timeout = timeout

		mu.Lock()
		nonce = fmt.Sprint(nextNonce)
		nextNonce++
		sawSlowNonce = false
		mu.Unlock()
		res, err := cst.c.Get(cst.ts.URL + "/?nonce=" + nonce)
		if err != nil {
			if strings.Contains(err.Error(), "Client.Timeout") {
				// Timed out before handler could respond.
				t.Logf("timeout before response received")
				continue
			}
			if runtime.GOOS == "windows" && strings.HasPrefix(runtime.GOARCH, "arm") {
				testenv.SkipFlaky(t, 43120)
			}
			t.Fatal(err)
		}

		mu.Lock()
		ok := sawSlowNonce
		mu.Unlock()
		if !ok {
			t.Fatal("handler never got /slow request, but client returned response")
		}

		_, err = io.ReadAll(res.Body)
		res.Body.Close()

		if err == nil {
			t.Fatal("expected error from ReadAll")
		}
		ne, ok := err.(net.Error)
		if !ok {
			t.Errorf("error value from ReadAll was %T; expected some net.Error", err)
		} else if !ne.Timeout() {
			t.Errorf("net.Error.Timeout = false; want true")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("ReadAll error = %q; expected some context.DeadlineExceeded", err)
		}
		if got := ne.Error(); !strings.Contains(got, "(Client.Timeout") {
			if runtime.GOOS == "windows" && strings.HasPrefix(runtime.GOARCH, "arm") {
				testenv.SkipFlaky(t, 43120)
			}
			t.Errorf("error string = %q; missing timeout substring", got)
		}

		break
	}
}

// Client.Timeout firing before getting to the body
func TestClientTimeout_Headers(t *testing.T) { run(t, testClientTimeout_Headers) }
func testClientTimeout_Headers(t *testing.T, mode testMode) {
	donec := make(chan bool, 1)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		<-donec
	}), optQuietLog)
	// Note that we use a channel send here and not a close.
	// The race detector doesn't know that we're waiting for a timeout
	// and thinks that the waitgroup inside httptest.Server is added to concurrently
	// with us closing it. If we timed out immediately, we could close the testserver
	// before we entered the handler. We're not timing out immediately and there's
	// no way we would be done before we entered the handler, but the race detector
	// doesn't know this, so synchronize explicitly.
	defer func() { donec <- true }()

	cst.c.Timeout = 5 * time.Millisecond
	res, err := cst.c.Get(cst.ts.URL)
	if err == nil {
		res.Body.Close()
		t.Fatal("got response from Get; expected error")
	}
	if _, ok := err.(*url.Error); !ok {
		t.Fatalf("Got error of type %T; want *url.Error", err)
	}
	ne, ok := err.(net.Error)
	if !ok {
		t.Fatalf("Got error of type %T; want some net.Error", err)
	}
	if !ne.Timeout() {
		t.Error("net.Error.Timeout = false; want true")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ReadAll error = %q; expected some context.DeadlineExceeded", err)
	}
	if got := ne.Error(); !strings.Contains(got, "Client.Timeout exceeded") {
		if runtime.GOOS == "windows" && strings.HasPrefix(runtime.GOARCH, "arm") {
			testenv.SkipFlaky(t, 43120)
		}
		t.Errorf("error string = %q; missing timeout substring", got)
	}
}

// Issue 16094: if Client.Timeout is set but not hit, a Timeout error shouldn't be
// returned.
func TestClientTimeoutCancel(t *testing.T) { run(t, testClientTimeoutCancel) }
func testClientTimeoutCancel(t *testing.T, mode testMode) {
	testDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.(Flusher).Flush()
		<-testDone
	}))
	defer close(testDone)

	cst.c.Timeout = 1 * time.Hour
	req, _ := NewRequest("GET", cst.ts.URL, nil)
	req.Cancel = ctx.Done()
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = io.Copy(io.Discard, res.Body)
	if err != ExportErrRequestCanceled {
		t.Fatalf("error = %v; want errRequestCanceled", err)
	}
}

// Issue 49366: if Client.Timeout is set but not hit, no error should be returned.
func TestClientTimeoutDoesNotExpire(t *testing.T) { run(t, testClientTimeoutDoesNotExpire) }
func testClientTimeoutDoesNotExpire(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write([]byte("body"))
	}))

	cst.c.Timeout = 1 * time.Hour
	req, _ := NewRequest("GET", cst.ts.URL, nil)
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, res.Body); err != nil {
		t.Fatalf("io.Copy(io.Discard, res.Body) = %v, want nil", err)
	}
	if err = res.Body.Close(); err != nil {
		t.Fatalf("res.Body.Close() = %v, want nil", err)
	}
}

func TestClientRedirectEatsBody_h1(t *testing.T) { run(t, testClientRedirectEatsBody) }
func testClientRedirectEatsBody(t *testing.T, mode testMode) {
	saw := make(chan string, 2)
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		saw <- r.RemoteAddr
		if r.URL.Path == "/" {
			Redirect(w, r, "/foo", StatusFound) // which includes a body
		}
	}))

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	var first string
	select {
	case first = <-saw:
	default:
		t.Fatal("server didn't see a request")
	}

	var second string
	select {
	case second = <-saw:
	default:
		t.Fatal("server didn't see a second request")
	}

	if first != second {
		t.Fatal("server saw different client ports before & after the redirect")
	}
}

// eofReaderFunc is an io.Reader that runs itself, and then returns io.EOF.
type eofReaderFunc func()

func (f eofReaderFunc) Read(p []byte) (n int, err error) {
	f()
	return 0, io.EOF
}

func TestReferer(t *testing.T) {
	tests := []struct {
		lastReq, newReq, explicitRef string // from -> to URLs, explicitly set Referer value
		want                         string
	}{
		// don't send user:
		{lastReq: "http://gopher@test.com", newReq: "http://link.com", want: "http://test.com"},
		{lastReq: "https://gopher@test.com", newReq: "https://link.com", want: "https://test.com"},

		// don't send a user and password:
		{lastReq: "http://gopher:go@test.com", newReq: "http://link.com", want: "http://test.com"},
		{lastReq: "https://gopher:go@test.com", newReq: "https://link.com", want: "https://test.com"},

		// nothing to do:
		{lastReq: "http://test.com", newReq: "http://link.com", want: "http://test.com"},
		{lastReq: "https://test.com", newReq: "https://link.com", want: "https://test.com"},

		// https to http doesn't send a referer:
		{lastReq: "https://test.com", newReq: "http://link.com", want: ""},
		{lastReq: "https://gopher:go@test.com", newReq: "http://link.com", want: ""},

		// https to http should remove an existing referer:
		{lastReq: "https://test.com", newReq: "http://link.com", explicitRef: "https://foo.com", want: ""},
		{lastReq: "https://gopher:go@test.com", newReq: "http://link.com", explicitRef: "https://foo.com", want: ""},

		// don't override an existing referer:
		{lastReq: "https://test.com", newReq: "https://link.com", explicitRef: "https://foo.com", want: "https://foo.com"},
		{lastReq: "https://gopher:go@test.com", newReq: "https://link.com", explicitRef: "https://foo.com", want: "https://foo.com"},
	}
	for _, tt := range tests {
		l, err := url.Parse(tt.lastReq)
		if err != nil {
			t.Fatal(err)
		}
		n, err := url.Parse(tt.newReq)
		if err != nil {
			t.Fatal(err)
		}
		r := ExportRefererForURL(l, n, tt.explicitRef)
		if r != tt.want {
			t.Errorf("refererForURL(%q, %q) = %q; want %q", tt.lastReq, tt.newReq, r, tt.want)
		}
	}
}

// issue15577Tripper returns a Response with a redirect response
// header and doesn't populate its Response.Request field.
type issue15577Tripper struct{}

func (issue15577Tripper) RoundTrip(*Request) (*Response, error) {
	resp := &Response{
		StatusCode: 303,
		Header:     map[string][]string{"Location": {"http://www.example.com/"}},
		Body:       io.NopCloser(strings.NewReader("")),
	}
	return resp, nil
}

// Issue 15577: don't assume the roundtripper's response populates its Request field.
func TestClientRedirectResponseWithoutRequest(t *testing.T) {
	c := &Client{
		CheckRedirect: func(*Request, []*Request) error { return fmt.Errorf("no redirects!") },
		Transport:     issue15577Tripper{},
	}
	// Check that this doesn't crash:
	c.Get("http://dummy.tld")
}

// Issue 4800: copy (some) headers when Client follows a redirect.
// Issue 35104: Since both URLs have the same host (localhost)
// but different ports, sensitive headers like Cookie and Authorization
// are preserved.
func TestClientCopyHeadersOnRedirect(t *testing.T) { run(t, testClientCopyHeadersOnRedirect) }
func testClientCopyHeadersOnRedirect(t *testing.T, mode testMode) {
	const (
		ua   = "some-agent/1.2"
		xfoo = "foo-val"
	)
	var ts2URL string
	ts1 := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		want := Header{
			"User-Agent":      []string{ua},
			"X-Foo":           []string{xfoo},
			"Referer":         []string{ts2URL},
			"Accept-Encoding": []string{"gzip"},
			"Cookie":          []string{"foo=bar"},
			"Authorization":   []string{"secretpassword"},
		}
		if !reflect.DeepEqual(r.Header, want) {
			t.Errorf("Request.Header = %#v; want %#v", r.Header, want)
		}
		if t.Failed() {
			w.Header().Set("Result", "got errors")
		} else {
			w.Header().Set("Result", "ok")
		}
	})).ts
	ts2 := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		Redirect(w, r, ts1.URL, StatusFound)
	})).ts
	ts2URL = ts2.URL

	c := ts1.Client()
	c.CheckRedirect = func(r *Request, via []*Request) error {
		want := Header{
			"User-Agent":    []string{ua},
			"X-Foo":         []string{xfoo},
			"Referer":       []string{ts2URL},
			"Cookie":        []string{"foo=bar"},
			"Authorization": []string{"secretpassword"},
		}
		if !reflect.DeepEqual(r.Header, want) {
			t.Errorf("CheckRedirect Request.Header = %#v; want %#v", r.Header, want)
		}
		return nil
	}

	req, _ := NewRequest("GET", ts2.URL, nil)
	req.Header.Add("User-Agent", ua)
	req.Header.Add("X-Foo", xfoo)
	req.Header.Add("Cookie", "foo=bar")
	req.Header.Add("Authorization", "secretpassword")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
	if got := res.Header.Get("Result"); got != "ok" {
		t.Errorf("result = %q; want ok", got)
	}
}

// Issue 22233: copy host when Client follows a relative redirect.
func TestClientCopyHostOnRedirect(t *testing.T) { run(t, testClientCopyHostOnRedirect) }
func testClientCopyHostOnRedirect(t *testing.T, mode testMode) {
	// Virtual hostname: should not receive any request.
	virtual := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		t.Errorf("Virtual host received request %v", r.URL)
		w.WriteHeader(403)
		io.WriteString(w, "should not see this response")
	})).ts
	defer virtual.Close()
	virtualHost := strings.TrimPrefix(virtual.URL, "http://")
	virtualHost = strings.TrimPrefix(virtualHost, "https://")
	t.Logf("Virtual host is %v", virtualHost)

	// Actual hostname: should not receive any request.
	const wantBody = "response body"
	var tsURL string
	var tsHost string
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		switch r.URL.Path {
		case "/":
			// Relative redirect.
			if r.Host != virtualHost {
				t.Errorf("Serving /: Request.Host = %#v; want %#v", r.Host, virtualHost)
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Location", "/hop")
			w.WriteHeader(302)
		case "/hop":
			// Absolute redirect.
			if r.Host != virtualHost {
				t.Errorf("Serving /hop: Request.Host = %#v; want %#v", r.Host, virtualHost)
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Location", tsURL+"/final")
			w.WriteHeader(302)
		case "/final":
			if r.Host != tsHost {
				t.Errorf("Serving /final: Request.Host = %#v; want %#v", r.Host, tsHost)
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(200)
			io.WriteString(w, wantBody)
		default:
			t.Errorf("Serving unexpected path %q", r.URL.Path)
			w.WriteHeader(404)
		}
	})).ts
	tsURL = ts.URL
	tsHost = strings.TrimPrefix(ts.URL, "http://")
	tsHost = strings.TrimPrefix(tsHost, "https://")
	t.Logf("Server host is %v", tsHost)

	c := ts.Client()
	req, _ := NewRequest("GET", ts.URL, nil)
	req.Host = virtualHost
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	if got, err := io.ReadAll(resp.Body); err != nil || string(got) != wantBody {
		t.Errorf("body = %q; want %q", got, wantBody)
	}
}

// Issue 17494: cookies should be altered when Client follows redirects.
func TestClientAltersCookiesOnRedirect(t *testing.T) { run(t, testClientAltersCookiesOnRedirect) }
func testClientAltersCookiesOnRedirect(t *testing.T, mode testMode) {
	cookieMap := func(cs []*Cookie) map[string][]string {
		m := make(map[string][]string)
		for _, c := range cs {
			m[c.Name] = append(m[c.Name], c.Value)
		}
		return m
	}

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		var want map[string][]string
		got := cookieMap(r.Cookies())

		c, _ := r.Cookie("Cycle")
		switch c.Value {
		case "0":
			want = map[string][]string{
				"Cookie1": {"OldValue1a", "OldValue1b"},
				"Cookie2": {"OldValue2"},
				"Cookie3": {"OldValue3a", "OldValue3b"},
				"Cookie4": {"OldValue4"},
				"Cycle":   {"0"},
			}
			SetCookie(w, &Cookie{Name: "Cycle", Value: "1", Path: "/"})
			SetCookie(w, &Cookie{Name: "Cookie2", Path: "/", MaxAge: -1}) // Delete cookie from Header
			Redirect(w, r, "/", StatusFound)
		case "1":
			want = map[string][]string{
				"Cookie1": {"OldValue1a", "OldValue1b"},
				"Cookie3": {"OldValue3a", "OldValue3b"},
				"Cookie4": {"OldValue4"},
				"Cycle":   {"1"},
			}
			SetCookie(w, &Cookie{Name: "Cycle", Value: "2", Path: "/"})
			SetCookie(w, &Cookie{Name: "Cookie3", Value: "NewValue3", Path: "/"}) // Modify cookie in Header
			SetCookie(w, &Cookie{Name: "Cookie4", Value: "NewValue4", Path: "/"}) // Modify cookie in Jar
			Redirect(w, r, "/", StatusFound)
		case "2":
			want = map[string][]string{
				"Cookie1": {"OldValue1a", "OldValue1b"},
				"Cookie3": {"NewValue3"},
				"Cookie4": {"NewValue4"},
				"Cycle":   {"2"},
			}
			SetCookie(w, &Cookie{Name: "Cycle", Value: "3", Path: "/"})
			SetCookie(w, &Cookie{Name: "Cookie5", Value: "NewValue5", Path: "/"}) // Insert cookie into Jar
			Redirect(w, r, "/", StatusFound)
		case "3":
			want = map[string][]string{
				"Cookie1": {"OldValue1a", "OldValue1b"},
				"Cookie3": {"NewValue3"},
				"Cookie4": {"NewValue4"},
				"Cookie5": {"NewValue5"},
				"Cycle":   {"3"},
			}
			// Don't redirect to ensure the loop ends.
		default:
			t.Errorf("unexpected redirect cycle")
			return
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("redirect %s, Cookie = %v, want %v", c.Value, got, want)
		}
	})).ts

	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar

	u, _ := url.Parse(ts.URL)
	req, _ := NewRequest("GET", ts.URL, nil)
	req.AddCookie(&Cookie{Name: "Cookie1", Value: "OldValue1a"})
	req.AddCookie(&Cookie{Name: "Cookie1", Value: "OldValue1b"})
	req.AddCookie(&Cookie{Name: "Cookie2", Value: "OldValue2"})
	req.AddCookie(&Cookie{Name: "Cookie3", Value: "OldValue3a"})
	req.AddCookie(&Cookie{Name: "Cookie3", Value: "OldValue3b"})
	jar.SetCookies(u, []*Cookie{{Name: "Cookie4", Value: "OldValue4", Path: "/"}})
	jar.SetCookies(u, []*Cookie{{Name: "Cycle", Value: "0", Path: "/"}})
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.Status)
	}
}

// Part of Issue 4800
func TestShouldCopyHeaderOnRedirect(t *testing.T) {
	tests := []struct {
		header     string
		initialURL string
		destURL    string
		want       bool
	}{
		{"User-Agent", "http://foo.com/", "http://bar.com/", true},
		{"X-Foo", "http://foo.com/", "http://bar.com/", true},

		// Sensitive headers:
		{"cookie", "http://foo.com/", "http://bar.com/", false},
		{"cookie2", "http://foo.com/", "http://bar.com/", false},
		{"authorization", "http://foo.com/", "http://bar.com/", false},
		{"authorization", "http://foo.com/", "https://foo.com/", true},
		{"authorization", "http://foo.com:1234/", "http://foo.com:4321/", true},
		{"www-authenticate", "http://foo.com/", "http://bar.com/", false},
		{"authorization", "http://foo.com/", "http://[::1%25.foo.com]/", false},

		// But subdomains should work:
		{"www-authenticate", "http://foo.com/", "http://foo.com/", true},
		{"www-authenticate", "http://foo.com/", "http://sub.foo.com/", true},
		{"www-authenticate", "http://foo.com/", "http://notfoo.com/", false},
		{"www-authenticate", "http://foo.com/", "https://foo.com/", true},
		{"www-authenticate", "http://foo.com:80/", "http://foo.com/", true},
		{"www-authenticate", "http://foo.com:80/", "http://sub.foo.com/", true},
		{"www-authenticate", "http://foo.com:443/", "https://foo.com/", true},
		{"www-authenticate", "http://foo.com:443/", "https://sub.foo.com/", true},
		{"www-authenticate", "http://foo.com:1234/", "http://foo.com/", true},

		{"authorization", "http://foo.com/", "http://foo.com/", true},
		{"authorization", "http://foo.com/", "http://sub.foo.com/", true},
		{"authorization", "http://foo.com/", "http://notfoo.com/", false},
		{"authorization", "http://foo.com/", "https://foo.com/", true},
		{"authorization", "http://foo.com:80/", "http://foo.com/", true},
		{"authorization", "http://foo.com:80/", "http://sub.foo.com/", true},
		{"authorization", "http://foo.com:443/", "https://foo.com/", true},
		{"authorization", "http://foo.com:443/", "https://sub.foo.com/", true},
		{"authorization", "http://foo.com:1234/", "http://foo.com/", true},
	}
	for i, tt := range tests {
		u0, err := url.Parse(tt.initialURL)
		if err != nil {
			t.Errorf("%d. initial URL %q parse error: %v", i, tt.initialURL, err)
			continue
		}
		u1, err := url.Parse(tt.destURL)
		if err != nil {
			t.Errorf("%d. dest URL %q parse error: %v", i, tt.destURL, err)
			continue
		}
		got := Export_shouldCopyHeaderOnRedirect(tt.header, u0, u1)
		if got != tt.want {
			t.Errorf("%d. shouldCopyHeaderOnRedirect(%q, %q => %q) = %v; want %v",
				i, tt.header, tt.initialURL, tt.destURL, got, tt.want)
		}
	}
}

func TestClientRedirectTypes(t *testing.T) { run(t, testClientRedirectTypes) }
func testClientRedirectTypes(t *testing.T, mode testMode) {
	tests := [...]struct {
		method       string
		serverStatus int
		wantMethod   string // desired subsequent client method
	}{
		0: {method: "POST", serverStatus: 301, wantMethod: "GET"},
		1: {method: "POST", serverStatus: 302, wantMethod: "GET"},
		2: {method: "POST", serverStatus: 303, wantMethod: "GET"},
		3: {method: "POST", serverStatus: 307, wantMethod: "POST"},
		4: {method: "POST", serverStatus: 308, wantMethod: "POST"},

		5: {method: "HEAD", serverStatus: 301, wantMethod: "HEAD"},
		6: {method: "HEAD", serverStatus: 302, wantMethod: "HEAD"},
		7: {method: "HEAD", serverStatus: 303, wantMethod: "HEAD"},
		8: {method: "HEAD", serverStatus: 307, wantMethod: "HEAD"},
		9: {method: "HEAD", serverStatus: 308, wantMethod: "HEAD"},

		10: {method: "GET", serverStatus: 301, wantMethod: "GET"},
		11: {method: "GET", serverStatus: 302, wantMethod: "GET"},
		12: {method: "GET", serverStatus: 303, wantMethod: "GET"},
		13: {method: "GET", serverStatus: 307, wantMethod: "GET"},
		14: {method: "GET", serverStatus: 308, wantMethod: "GET"},

		15: {method: "DELETE", serverStatus: 301, wantMethod: "GET"},
		16: {method: "DELETE", serverStatus: 302, wantMethod: "GET"},
		17: {method: "DELETE", serverStatus: 303, wantMethod: "GET"},
		18: {method: "DELETE", serverStatus: 307, wantMethod: "DELETE"},
		19: {method: "DELETE", serverStatus: 308, wantMethod: "DELETE"},

		20: {method: "PUT", serverStatus: 301, wantMethod: "GET"},
		21: {method: "PUT", serverStatus: 302, wantMethod: "GET"},
		22: {method: "PUT", serverStatus: 303, wantMethod: "GET"},
		23: {method: "PUT", serverStatus: 307, wantMethod: "PUT"},
		24: {method: "PUT", serverStatus: 308, wantMethod: "PUT"},

		25: {method: "MADEUPMETHOD", serverStatus: 301, wantMethod: "GET"},
		26: {method: "MADEUPMETHOD", serverStatus: 302, wantMethod: "GET"},
		27: {method: "MADEUPMETHOD", serverStatus: 303, wantMethod: "GET"},
		28: {method: "MADEUPMETHOD", serverStatus: 307, wantMethod: "MADEUPMETHOD"},
		29: {method: "MADEUPMETHOD", serverStatus: 308, wantMethod: "MADEUPMETHOD"},
	}

	handlerc := make(chan HandlerFunc, 1)

	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		h := <-handlerc
		h(rw, req)
	})).ts

	c := ts.Client()
	for i, tt := range tests {
		handlerc <- func(w ResponseWriter, r *Request) {
			w.Header().Set("Location", ts.URL)
			w.WriteHeader(tt.serverStatus)
		}

		req, err := NewRequest(tt.method, ts.URL, nil)
		if err != nil {
			t.Errorf("#%d: NewRequest: %v", i, err)
			continue
		}

		c.CheckRedirect = func(req *Request, via []*Request) error {
			if got, want := req.Method, tt.wantMethod; got != want {
				return fmt.Errorf("#%d: got next method %q; want %q", i, got, want)
			}
			handlerc <- func(rw ResponseWriter, req *Request) {
				// TODO: Check that the body is valid when we do 307 and 308 support
			}
			return nil
		}

		res, err := c.Do(req)
		if err != nil {
			t.Errorf("#%d: Response: %v", i, err)
			continue
		}

		res.Body.Close()
	}
}

// issue18239Body is an io.ReadCloser for TestTransportBodyReadError.
// Its Read returns readErr and increments *readCalls atomically.
// Its Close returns nil and increments *closeCalls atomically.
type issue18239Body struct {
	readCalls  *int32
	closeCalls *int32
	readErr    error
}

func (b issue18239Body) Read([]byte) (int, error) {
	atomic.AddInt32(b.readCalls, 1)
	return 0, b.readErr
}

func (b issue18239Body) Close() error {
	atomic.AddInt32(b.closeCalls, 1)
	return nil
}

// Issue 18239: make sure the Transport doesn't retry requests with bodies
// if Request.GetBody is not defined.
func TestTransportBodyReadError(t *testing.T) { run(t, testTransportBodyReadError) }
func testTransportBodyReadError(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.URL.Path == "/ping" {
			return
		}
		buf := make([]byte, 1)
		n, err := r.Body.Read(buf)
		w.Header().Set("X-Body-Read", fmt.Sprintf("%v, %v", n, err))
	})).ts
	c := ts.Client()
	tr := c.Transport.(*Transport)

	// Do one initial successful request to create an idle TCP connection
	// for the subsequent request to reuse. (The Transport only retries
	// requests on reused connections.)
	res, err := c.Get(ts.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	var readCallsAtomic int32
	var closeCallsAtomic int32 // atomic
	someErr := errors.New("some body read error")
	body := issue18239Body{&readCallsAtomic, &closeCallsAtomic, someErr}

	req, err := NewRequest("POST", ts.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithT(t)
	_, err = tr.RoundTrip(req)
	if err != someErr {
		t.Errorf("Got error: %v; want Request.Body read error: %v", err, someErr)
	}

	// And verify that our Body wasn't used multiple times, which
	// would indicate retries. (as it buggily was during part of
	// Go 1.8's dev cycle)
	readCalls := atomic.LoadInt32(&readCallsAtomic)
	closeCalls := atomic.LoadInt32(&closeCallsAtomic)
	if readCalls != 1 {
		t.Errorf("read calls = %d; want 1", readCalls)
	}
	if closeCalls != 1 {
		t.Errorf("close calls = %d; want 1", closeCalls)
	}
}

type roundTripperWithoutCloseIdle struct{}

func (roundTripperWithoutCloseIdle) RoundTrip(*Request) (*Response, error) { panic("unused") }

type roundTripperWithCloseIdle func() // underlying func is CloseIdleConnections func

func (roundTripperWithCloseIdle) RoundTrip(*Request) (*Response, error) { panic("unused") }
func (f roundTripperWithCloseIdle) CloseIdleConnections()               { f() }

func TestClientCloseIdleConnections(t *testing.T) {
	c := &Client{Transport: roundTripperWithoutCloseIdle{}}
	c.CloseIdleConnections() // verify we don't crash at least

	closed := false
	var tr RoundTripper = roundTripperWithCloseIdle(func() {
		closed = true
	})
	c = &Client{Transport: tr}
	c.CloseIdleConnections()
	if !closed {
		t.Error("not closed")
	}
}

type testRoundTripper func(*Request) (*Response, error)

func (t testRoundTripper) RoundTrip(req *Request) (*Response, error) {
	return t(req)
}

func TestClientPropagatesTimeoutToContext(t *testing.T) {
	c := &Client{
		Timeout: 5 * time.Second,
		Transport: testRoundTripper(func(req *Request) (*Response, error) {
			ctx := req.Context()
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Error("no deadline")
			} else {
				t.Logf("deadline in %v", deadline.Sub(time.Now()).Round(time.Second/10))
			}
			return nil, errors.New("not actually making a request")
		}),
	}
	c.Get("https://example.tld/")
}

// Issue 33545: lock-in the behavior promised by Client.Do's
// docs about request cancellation vs timing out.
func TestClientDoCanceledVsTimeout(t *testing.T) { run(t, testClientDoCanceledVsTimeout) }
func testClientDoCanceledVsTimeout(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write([]byte("Hello, World!"))
	}))

	cases := []string{"timeout", "canceled"}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			var cancel func()
			if name == "timeout" {
				ctx, cancel = context.WithTimeout(context.Background(), -time.Nanosecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			}
			defer cancel()

			req, _ := NewRequestWithContext(ctx, "GET", cst.ts.URL, nil)
			_, err := cst.c.Do(req)
			if err == nil {
				t.Fatal("Unexpectedly got a nil error")
			}

			ue := err.(*url.Error)

			var wantIsTimeout bool
			var wantErr error = context.Canceled
			if name == "timeout" {
				wantErr = context.DeadlineExceeded
				wantIsTimeout = true
			}
			if g, w := ue.Timeout(), wantIsTimeout; g != w {
				t.Fatalf("url.Timeout() = %t, want %t", g, w)
			}
			if g, w := ue.Err, wantErr; g != w {
				t.Errorf("url.Error.Err = %v; want %v", g, w)
			}
			if got := errors.Is(err, context.DeadlineExceeded); got != wantIsTimeout {
				t.Errorf("errors.Is(err, context.DeadlineExceeded) = %v, want %v", got, wantIsTimeout)
			}
		})
	}
}

type nilBodyRoundTripper struct{}

func (nilBodyRoundTripper) RoundTrip(req *Request) (*Response, error) {
	return &Response{
		StatusCode: StatusOK,
		Status:     StatusText(StatusOK),
		Body:       nil,
		Request:    req,
	}, nil
}

func TestClientPopulatesNilResponseBody(t *testing.T) {
	c := &Client{Transport: nilBodyRoundTripper{}}

	resp, err := c.Get("http://localhost/anything")
	if err != nil {
		t.Fatalf("Client.Get rejected Response with nil Body: %v", err)
	}

	if resp.Body == nil {
		t.Fatalf("Client failed to provide a non-nil Body as documented")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("error from Close on substitute Response.Body: %v", err)
		}
	}()

	if b, err := io.ReadAll(resp.Body); err != nil {
		t.Errorf("read error from substitute Response.Body: %v", err)
	} else if len(b) != 0 {
		t.Errorf("substitute Response.Body was unexpectedly non-empty: %q", b)
	}
}

// Issue 40382: Client calls Close multiple times on Request.Body.
func TestClientCallsCloseOnlyOnce(t *testing.T) { run(t, testClientCallsCloseOnlyOnce) }
func testClientCallsCloseOnlyOnce(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusNoContent)
	}))

	// Issue occurred non-deterministically: needed to occur after a successful
	// write (into TCP buffer) but before end of body.
	for i := 0; i < 50 && !t.Failed(); i++ {
		body := &issue40382Body{t: t, n: 300000}
		req, err := NewRequest(MethodPost, cst.ts.URL, body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := cst.tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
}

// issue40382Body is an io.ReadCloser for TestClientCallsCloseOnlyOnce.
// Its Read reads n bytes before returning io.EOF.
// Its Close returns nil but fails the test if called more than once.
type issue40382Body struct {
	t                *testing.T
	n                int
	closeCallsAtomic int32
}

func (b *issue40382Body) Read(p []byte) (int, error) {
	switch {
	case b.n == 0:
		return 0, io.EOF
	case b.n < len(p):
		p = p[:b.n]
		fallthrough
	default:
		for i := range p {
			p[i] = 'x'
		}
		b.n -= len(p)
		return len(p), nil
	}
}

func (b *issue40382Body) Close() error {
	if atomic.AddInt32(&b.closeCallsAtomic, 1) == 2 {
		b.t.Error("Body closed more than once")
	}
	return nil
}

func TestProbeZeroLengthBody(t *testing.T) { run(t, testProbeZeroLengthBody) }
func testProbeZeroLengthBody(t *testing.T, mode testMode) {
	reqc := make(chan struct{})
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		close(reqc)
		if _, err := io.Copy(w, r.Body); err != nil {
			t.Errorf("error copying request body: %v", err)
		}
	}))

	bodyr, bodyw := io.Pipe()
	var gotBody string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := NewRequest("GET", cst.ts.URL, bodyr)
		res, err := cst.c.Do(req)
		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Error(err)
		}
		gotBody = string(b)
	}()

	select {
	case <-reqc:
		// Request should be sent after trying to probe the request body for 200ms.
	case <-time.After(60 * time.Second):
		t.Errorf("request not sent after 60s")
	}

	// Write the request body and wait for the request to complete.
	const content = "body"
	bodyw.Write([]byte(content))
	bodyw.Close()
	wg.Wait()
	if gotBody != content {
		t.Fatalf("server got body %q, want %q", gotBody, content)
	}
}
```