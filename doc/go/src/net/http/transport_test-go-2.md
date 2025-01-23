Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Goal:** The overarching goal is to understand the functionality of this specific part of `transport_test.go`. This involves identifying the individual test functions and their purpose within the context of HTTP transport. The prompt also asks about related Go features, code examples, potential errors, and a summary.

2. **Initial Scan for Test Functions:** The first step is to quickly scan the code for function names starting with `Test`. This immediately highlights the primary units of functionality being tested. We see functions like `TestIssue4191_InfiniteGetToPutTimeout`, `TestTransportResponseHeaderTimeout`, `TestTransportCancelRequest`, etc. This provides a high-level overview of the areas being covered.

3. **Analyzing Individual Test Functions:**  For each test function, the next step is to analyze the corresponding helper function (e.g., `testIssue4191_InfiniteGetToPutTimeout` for `TestIssue4191_InfiniteGetToPutTimeout`). Here's the general approach:

    * **Identify Setup:** Look for setup code that creates servers (`newClientServerTest`), configures clients (`ts.Client()`, modifying the `Transport`), and defines handlers (`NewServeMux`, `HandleFunc`).
    * **Identify the Core Action:** Determine the HTTP operations being performed (GET, PUT, POST, etc.) and the sequence of these operations. Pay attention to how requests are created (`NewRequest`), executed (`c.Do`, `c.Get`), and how responses are handled.
    * **Identify Assertions:** Look for `t.Fatalf`, `t.Errorf`, and `t.Logf` calls. These indicate the conditions being checked to determine if the test passes or fails. Understand what properties are being verified (e.g., error type, error message, status code, body content, timeouts).
    * **Identify Special Configurations:** Note any specific configurations of the `Transport` (e.g., `Dial`, `ResponseHeaderTimeout`, `DisableKeepAlives`, `MaxResponseHeaderBytes`). These are often the key elements being tested.
    * **Identify Concurrency Mechanisms:** Look for `sync.WaitGroup`, channels, and goroutines. These are important for understanding asynchronous operations and timeouts.
    * **Infer the Purpose:** Based on the setup, actions, and assertions, try to summarize the intent of the test. What specific behavior or edge case is being verified?

4. **Looking for Patterns and Common Themes:**  As you analyze multiple test functions, look for recurring patterns. In this snippet, common themes include:

    * **Timeout Testing:** Several tests focus on various timeout scenarios (`TestIssue4191_InfiniteGetToPutTimeout`, `TestTransportResponseHeaderTimeout`, `TestTransportTLSHandshakeTimeout`).
    * **Request Cancellation:** A significant portion of the code deals with request cancellation using different mechanisms (`Transport.CancelRequest`, `Request.Cancel`, context cancellation).
    * **Error Handling:** Tests often verify specific error types and messages.
    * **HTTP/1.1 and HTTP/2 Mode:** The `testMode` and conditional logic indicate that the code is testing both HTTP versions.
    * **Custom `Transport` Configurations:**  Tests frequently modify the default `Transport` behavior through fields like `Dial`.

5. **Identifying Go Features:**  As you understand the purpose of the tests, you can connect them to specific Go features:

    * **`net/http`:** The core package being tested.
    * **`testing`:** The testing framework.
    * **Goroutines and Channels:** Used for concurrency and communication, especially in timeout and cancellation scenarios.
    * **Contexts:** Used for request cancellation and deadlines.
    * **Interfaces:** `ResponseWriter`, `Flusher`, `Hijacker`, `io.Reader`, `io.Closer`, `net.Conn`, `net.Error`.
    * **Closures:** Used extensively in handler functions and `Transport.Dial` modifications.
    * **Error Handling:**  Using `errors.Is` for checking specific error types.

6. **Considering Code Examples:** For each identified Go feature, think about how it's used in the code and how you could illustrate it with a simpler example. For instance, the request cancellation tests naturally lead to examples using contexts and `Transport.CancelRequest`.

7. **Identifying Potential Errors:** Based on the test scenarios, consider the common mistakes developers might make. Timeouts, improper resource management (closing bodies), and incorrect cancellation logic are frequent sources of errors.

8. **Summarizing Functionality:** After analyzing the individual tests, synthesize the information into a concise summary of the overall functionality being tested in this code snippet.

9. **Structuring the Answer:** Organize the findings logically, starting with a high-level summary and then detailing the individual test functions, related Go features, code examples, potential errors, and finally, a concise summary of the section. Use clear and concise language, and provide code examples where appropriate. Pay attention to the specific requirements of the prompt (e.g., using Chinese).

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This section seems to be mostly about testing HTTP requests."  **Refinement:** "It's more specifically focused on testing the `http.Transport`'s behavior around timeouts, cancellations, and certain edge cases like handling 1xx responses."
* **Initial thought:** "Just list all the test functions." **Refinement:** "Group related test functions by the feature they are testing (e.g., grouping cancellation tests together) to provide a more coherent explanation."
* **Initial thought:** "Just show the code as is." **Refinement:** "Provide simplified, illustrative code examples to demonstrate the Go features being used, rather than just copying the complex test code."

By following this structured approach, combining detailed analysis with higher-level summarization, and iteratively refining understanding, one can effectively analyze and explain the functionality of a complex code snippet like this.
这是 `go/src/net/http/transport_test.go` 文件的一部分，主要关注 `http.Transport` 类型在处理各种网络场景，特别是超时和取消请求时的行为。这是该文件的第 3 部分，让我们归纳一下这部分的功能：

**主要功能归纳：**

这部分代码主要测试了 `http.Transport` 的以下功能：

1. **处理无限流的场景和超时机制:** 验证了当服务器端返回无限数据流时，客户端如何处理以及超时机制是否正常工作。
2. **`ResponseHeaderTimeout` 配置项:**  测试了 `Transport` 的 `ResponseHeaderTimeout` 选项，确保在指定时间内未收到响应头时能够正确超时。
3. **请求取消 (Request Cancellation):**
    * **多种取消方式:** 测试了通过 `Transport.CancelRequest`，`Request.Cancel` channel，以及使用 `context.Context` 来取消正在进行的 HTTP 请求。
    * **取消时机:** 测试了在请求的不同阶段取消请求，包括在连接建立之前 (Dial 阶段)，在发送请求之后，接收响应头之前，以及接收部分响应体之后。
    * **取消后的错误处理:** 验证了取消请求后，客户端是否会收到预期的错误 (例如 `errRequestCanceled`, `errRequestCanceledConn`, `context.Canceled`)。
    * **资源清理:** 验证了取消请求后，相关的网络连接和 goroutine 是否能够正确释放。
4. **关闭响应体 (Response Body):** 测试了显式关闭 `Response.Body` 是否会关闭底层的 TCP 连接。
5. **替代协议 (Alternate Protocols):**  演示了如何通过 `Transport.RegisterProtocol` 注册和使用非 HTTP 协议。
6. **缺少 Host 头的处理:** 验证了当请求的 URL 中缺少 Host 信息时，`Transport` 是否会返回正确的错误。
7. **空 Method 的处理:** 验证了当请求的 Method 为空字符串时，`Transport` 是否会默认将其视为 "GET" 请求。
8. **连接的延迟绑定 (Socket Late Binding):** 测试了在某些情况下，多个请求可以复用同一个底层的 TCP 连接，即使这些请求在不同的时间点发起。
9. **处理 100 Continue 响应:** 验证了客户端能够正确处理服务器发送的 `100 Continue` 响应。
10. **忽略和限制 1xx 信息性响应:** 测试了客户端如何忽略未知的 1xx 响应，并验证了对于过多的 1xx 响应的限制机制。
11. **将 101 响应视为最终响应:** 验证了客户端会将 `101 Switching Protocols` 响应视为最终响应，而不是继续等待后续的响应。
12. **从环境变量获取代理配置:** 测试了 `ProxyFromEnvironment` 函数如何从环境变量 (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) 中读取代理配置信息。
13. **空闲连接通道泄漏 (Idle Connection Channel Leak):**  测试了在请求完成后，空闲连接是否能够正确地放入或移除空闲连接池，避免资源泄漏。
14. **关闭请求体 (Request Body):** 验证了 `Client.Post` 方法在发送请求后会关闭实现了 `io.Closer` 接口的请求体。
15. **TLS 握手超时 (TLS Handshake Timeout):** 测试了 `Transport` 的 `TLSHandshakeTimeout` 选项，确保在 TLS 握手超时后能够返回错误。

**更详细的功能和代码示例:**

由于篇幅限制，这里无法详细列出每个测试用例。但是，我可以针对几个关键功能提供更具体的解释和代码示例：

**1. 请求取消 (Request Cancellation) 使用 `context.Context`:**

```go
func TestTransportCancelRequestWithContext(t *testing.T) {
	runCancelTestContext(t, testTransportCancelRequestWithContext)
}

func testTransportCancelRequestWithContext(t *testing.T, test cancelTest) {
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}

	const msg = "Hello"
	unblockc := make(chan bool)
	ts := newClientServerTest(t, test.mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, msg)
		w.(Flusher).Flush() // send headers and some body
		<-unblockc
	})).ts
	defer close(unblockc)

	c := ts.Client()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 确保 context 在测试结束后被取消

	req, _ := NewRequestWithContext(ctx, "GET", ts.URL, nil)

	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len(msg))
	n, _ := io.ReadFull(res.Body, body)
	if n != len(body) || !bytes.Equal(body, []byte(msg)) {
		t.Errorf("Body = %q; want %q", body[:n], msg)
	}

	// 在读取部分响应后取消请求
	cancel()

	tail, err := io.ReadAll(res.Body)
	res.Body.Close()
	test.checkErr("Body.Read", err) // 期望收到 context.Canceled 错误
	if len(tail) > 0 {
		t.Errorf("Spurious bytes from Body.Read: %q", tail)
	}
}
```

**假设的输入与输出:**

* **输入:**  一个运行在 `ts.URL` 的 HTTP 服务器，它会先发送 "Hello" 字符串，然后等待 `unblockc` 信号。客户端发起一个 GET 请求到该服务器，并使用一个可以被取消的 `context.Context`。在客户端读取到部分响应 ("Hello") 后，context 被取消。
* **输出:** 客户端在尝试继续读取响应体时会收到一个 `context.Canceled` 类型的错误。

**2. `ResponseHeaderTimeout` 的使用:**

```go
func TestTransportResponseHeaderTimeoutExample(t *testing.T) {
	// 创建一个测试服务器，该服务器对于 "/slow" 路径的请求会故意延迟发送响应头
	mux := NewServeMux()
	mux.HandleFunc("/fast", func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusOK)
	})
	mux.HandleFunc("/slow", func(w ResponseWriter, r *Request) {
		time.Sleep(5 * time.Millisecond) // 故意延迟
		w.WriteHeader(StatusOK)
	})
	ts := newClientServerTest(t, http1Mode, mux).ts
	defer ts.Close()

	// 创建一个客户端，并设置 ResponseHeaderTimeout
	client := ts.Client()
	client.Transport.(*Transport).ResponseHeaderTimeout = 1 * time.Millisecond

	// 测试快速响应的路径
	resFast, errFast := client.Get(ts.URL + "/fast")
	if errFast != nil {
		t.Fatalf("Get /fast failed: %v", errFast)
	}
	resFast.Body.Close()

	// 测试慢速响应的路径，期望超时
	resSlow, errSlow := client.Get(ts.URL + "/slow")
	if errSlow == nil {
		t.Fatalf("Get /slow should have timed out")
	}

	urlErr, ok := errSlow.(*url.Error)
	if !ok {
		t.Fatalf("Expected url.Error, got %T", errSlow)
	}
	netErr, ok := urlErr.Err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Errorf("Expected timeout error, got: %v", errSlow)
	}
	if !strings.Contains(errSlow.Error(), "timeout awaiting response headers") {
		t.Errorf("Expected specific timeout message, got: %v", errSlow)
	}
}
```

**假设的输入与输出:**

* **输入:** 一个 HTTP 服务器，其中 `/slow` 路径的处理函数会延迟 5 毫秒发送响应头。一个客户端，其 `ResponseHeaderTimeout` 被设置为 1 毫秒。
* **输出:**  当客户端请求 `/fast` 时，能够成功获取响应。当客户端请求 `/slow` 时，会因为超过 `ResponseHeaderTimeout` 而返回一个包含 "timeout awaiting response headers" 的超时错误。

**使用者易犯错的点:**

* **忘记关闭 `Response.Body`:** 如果不关闭 `Response.Body`，底层的 TCP 连接可能无法被复用，最终导致资源泄漏。
* **不理解请求取消的机制:**  可能会混淆 `Transport.CancelRequest` 和 `Request.Cancel` channel 以及 `context.Context` 的使用场景和生命周期。例如，在请求开始之前调用 `Transport.CancelRequest` 是无效的。
* **不正确地设置超时时间:**  将超时时间设置得过短可能会导致正常的请求失败。

**总结:**

这部分 `transport_test.go` 代码主要集中在测试 `http.Transport` 在处理各种超时场景和请求取消时的正确性和健壮性。它覆盖了多种取消请求的方式，并验证了在不同阶段取消请求的行为和错误处理。此外，它还测试了与连接管理、错误处理以及其他 HTTP 协议特性相关的边缘情况。理解这部分测试用例有助于开发者更好地理解 `http.Transport` 的工作原理以及如何避免在使用 HTTP 客户端时可能遇到的问题。

### 提示词
```
这是路径为go/src/net/http/transport_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
e connc <- conn:
		default:
		}
		return conn, nil
	}

	res, err := c.Get(ts.URL + "/get")
	if err != nil {
		t.Fatalf("Error issuing GET: %v", err)
	}
	defer res.Body.Close()

	conn := <-connc
	conn.SetDeadline(time.Now().Add(1 * time.Millisecond))
	_, err = io.Copy(io.Discard, res.Body)
	if err == nil {
		t.Errorf("Unexpected successful copy")
	}
}

func TestIssue4191_InfiniteGetToPutTimeout(t *testing.T) {
	run(t, testIssue4191_InfiniteGetToPutTimeout, []testMode{http1Mode})
}
func testIssue4191_InfiniteGetToPutTimeout(t *testing.T, mode testMode) {
	const debug = false
	mux := NewServeMux()
	mux.HandleFunc("/get", func(w ResponseWriter, r *Request) {
		io.Copy(w, neverEnding('a'))
	})
	mux.HandleFunc("/put", func(w ResponseWriter, r *Request) {
		defer r.Body.Close()
		io.Copy(io.Discard, r.Body)
	})
	ts := newClientServerTest(t, mode, mux).ts
	timeout := 100 * time.Millisecond

	c := ts.Client()
	c.Transport.(*Transport).Dial = func(n, addr string) (net.Conn, error) {
		conn, err := net.Dial(n, addr)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(timeout))
		if debug {
			conn = NewLoggingConn("client", conn)
		}
		return conn, nil
	}

	getFailed := false
	nRuns := 5
	if testing.Short() {
		nRuns = 1
	}
	for i := 0; i < nRuns; i++ {
		if debug {
			println("run", i+1, "of", nRuns)
		}
		sres, err := c.Get(ts.URL + "/get")
		if err != nil {
			if !getFailed {
				// Make the timeout longer, once.
				getFailed = true
				t.Logf("increasing timeout")
				i--
				timeout *= 10
				continue
			}
			t.Errorf("Error issuing GET: %v", err)
			break
		}
		req, _ := NewRequest("PUT", ts.URL+"/put", sres.Body)
		_, err = c.Do(req)
		if err == nil {
			sres.Body.Close()
			t.Errorf("Unexpected successful PUT")
			break
		}
		sres.Body.Close()
	}
	if debug {
		println("tests complete; waiting for handlers to finish")
	}
	ts.Close()
}

func TestTransportResponseHeaderTimeout(t *testing.T) { run(t, testTransportResponseHeaderTimeout) }
func testTransportResponseHeaderTimeout(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping timeout test in -short mode")
	}

	timeout := 2 * time.Millisecond
	retry := true
	for retry && !t.Failed() {
		var srvWG sync.WaitGroup
		inHandler := make(chan bool, 1)
		mux := NewServeMux()
		mux.HandleFunc("/fast", func(w ResponseWriter, r *Request) {
			inHandler <- true
			srvWG.Done()
		})
		mux.HandleFunc("/slow", func(w ResponseWriter, r *Request) {
			inHandler <- true
			<-r.Context().Done()
			srvWG.Done()
		})
		ts := newClientServerTest(t, mode, mux).ts

		c := ts.Client()
		c.Transport.(*Transport).ResponseHeaderTimeout = timeout

		retry = false
		srvWG.Add(3)
		tests := []struct {
			path        string
			wantTimeout bool
		}{
			{path: "/fast"},
			{path: "/slow", wantTimeout: true},
			{path: "/fast"},
		}
		for i, tt := range tests {
			req, _ := NewRequest("GET", ts.URL+tt.path, nil)
			req = req.WithT(t)
			res, err := c.Do(req)
			<-inHandler
			if err != nil {
				uerr, ok := err.(*url.Error)
				if !ok {
					t.Errorf("error is not a url.Error; got: %#v", err)
					continue
				}
				nerr, ok := uerr.Err.(net.Error)
				if !ok {
					t.Errorf("error does not satisfy net.Error interface; got: %#v", err)
					continue
				}
				if !nerr.Timeout() {
					t.Errorf("want timeout error; got: %q", nerr)
					continue
				}
				if !tt.wantTimeout {
					if !retry {
						// The timeout may be set too short. Retry with a longer one.
						t.Logf("unexpected timeout for path %q after %v; retrying with longer timeout", tt.path, timeout)
						timeout *= 2
						retry = true
					}
				}
				if !strings.Contains(err.Error(), "timeout awaiting response headers") {
					t.Errorf("%d. unexpected error: %v", i, err)
				}
				continue
			}
			if tt.wantTimeout {
				t.Errorf(`no error for path %q; expected "timeout awaiting response headers"`, tt.path)
				continue
			}
			if res.StatusCode != 200 {
				t.Errorf("%d for path %q status = %d; want 200", i, tt.path, res.StatusCode)
			}
		}

		srvWG.Wait()
		ts.Close()
	}
}

// A cancelTest is a test of request cancellation.
type cancelTest struct {
	mode     testMode
	newReq   func(req *Request) *Request       // prepare the request to cancel
	cancel   func(tr *Transport, req *Request) // cancel the request
	checkErr func(when string, err error)      // verify the expected error
}

// runCancelTestTransport uses Transport.CancelRequest.
func runCancelTestTransport(t *testing.T, mode testMode, f func(t *testing.T, test cancelTest)) {
	t.Run("TransportCancel", func(t *testing.T) {
		f(t, cancelTest{
			mode: mode,
			newReq: func(req *Request) *Request {
				return req
			},
			cancel: func(tr *Transport, req *Request) {
				tr.CancelRequest(req)
			},
			checkErr: func(when string, err error) {
				if !errors.Is(err, ExportErrRequestCanceled) && !errors.Is(err, ExportErrRequestCanceledConn) {
					t.Errorf("%v error = %v, want errRequestCanceled or errRequestCanceledConn", when, err)
				}
			},
		})
	})
}

// runCancelTestChannel uses Request.Cancel.
func runCancelTestChannel(t *testing.T, mode testMode, f func(t *testing.T, test cancelTest)) {
	cancelc := make(chan struct{})
	cancelOnce := sync.OnceFunc(func() { close(cancelc) })
	f(t, cancelTest{
		mode: mode,
		newReq: func(req *Request) *Request {
			req.Cancel = cancelc
			return req
		},
		cancel: func(tr *Transport, req *Request) {
			cancelOnce()
		},
		checkErr: func(when string, err error) {
			if !errors.Is(err, ExportErrRequestCanceled) && !errors.Is(err, ExportErrRequestCanceledConn) {
				t.Errorf("%v error = %v, want errRequestCanceled or errRequestCanceledConn", when, err)
			}
		},
	})
}

// runCancelTestContext uses a request context.
func runCancelTestContext(t *testing.T, mode testMode, f func(t *testing.T, test cancelTest)) {
	ctx, cancel := context.WithCancel(context.Background())
	f(t, cancelTest{
		mode: mode,
		newReq: func(req *Request) *Request {
			return req.WithContext(ctx)
		},
		cancel: func(tr *Transport, req *Request) {
			cancel()
		},
		checkErr: func(when string, err error) {
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%v error = %v, want context.Canceled", when, err)
			}
		},
	})
}

func runCancelTest(t *testing.T, f func(t *testing.T, test cancelTest), opts ...any) {
	run(t, func(t *testing.T, mode testMode) {
		if mode == http1Mode {
			t.Run("TransportCancel", func(t *testing.T) {
				runCancelTestTransport(t, mode, f)
			})
		}
		t.Run("RequestCancel", func(t *testing.T) {
			runCancelTestChannel(t, mode, f)
		})
		t.Run("ContextCancel", func(t *testing.T) {
			runCancelTestContext(t, mode, f)
		})
	}, opts...)
}

func TestTransportCancelRequest(t *testing.T) {
	runCancelTest(t, testTransportCancelRequest)
}
func testTransportCancelRequest(t *testing.T, test cancelTest) {
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}

	const msg = "Hello"
	unblockc := make(chan bool)
	ts := newClientServerTest(t, test.mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, msg)
		w.(Flusher).Flush() // send headers and some body
		<-unblockc
	})).ts
	defer close(unblockc)

	c := ts.Client()
	tr := c.Transport.(*Transport)

	req, _ := NewRequest("GET", ts.URL, nil)
	req = test.newReq(req)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len(msg))
	n, _ := io.ReadFull(res.Body, body)
	if n != len(body) || !bytes.Equal(body, []byte(msg)) {
		t.Errorf("Body = %q; want %q", body[:n], msg)
	}
	test.cancel(tr, req)

	tail, err := io.ReadAll(res.Body)
	res.Body.Close()
	test.checkErr("Body.Read", err)
	if len(tail) > 0 {
		t.Errorf("Spurious bytes from Body.Read: %q", tail)
	}

	// Verify no outstanding requests after readLoop/writeLoop
	// goroutines shut down.
	waitCondition(t, 10*time.Millisecond, func(d time.Duration) bool {
		n := tr.NumPendingRequestsForTesting()
		if n > 0 {
			if d > 0 {
				t.Logf("pending requests = %d after %v (want 0)", n, d)
			}
			return false
		}
		return true
	})
}

func testTransportCancelRequestInDo(t *testing.T, test cancelTest, body io.Reader) {
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}
	unblockc := make(chan bool)
	ts := newClientServerTest(t, test.mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		<-unblockc
	})).ts
	defer close(unblockc)

	c := ts.Client()
	tr := c.Transport.(*Transport)

	donec := make(chan bool)
	req, _ := NewRequest("GET", ts.URL, body)
	req = test.newReq(req)
	go func() {
		defer close(donec)
		c.Do(req)
	}()

	unblockc <- true
	waitCondition(t, 10*time.Millisecond, func(d time.Duration) bool {
		test.cancel(tr, req)
		select {
		case <-donec:
			return true
		default:
			if d > 0 {
				t.Logf("Do of canceled request has not returned after %v", d)
			}
			return false
		}
	})
}

func TestTransportCancelRequestInDo(t *testing.T) {
	runCancelTest(t, func(t *testing.T, test cancelTest) {
		testTransportCancelRequestInDo(t, test, nil)
	})
}

func TestTransportCancelRequestWithBodyInDo(t *testing.T) {
	runCancelTest(t, func(t *testing.T, test cancelTest) {
		testTransportCancelRequestInDo(t, test, bytes.NewBuffer([]byte{0}))
	})
}

func TestTransportCancelRequestInDial(t *testing.T) {
	runCancelTest(t, testTransportCancelRequestInDial)
}
func testTransportCancelRequestInDial(t *testing.T, test cancelTest) {
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}
	var logbuf strings.Builder
	eventLog := log.New(&logbuf, "", 0)

	unblockDial := make(chan bool)
	defer close(unblockDial)

	inDial := make(chan bool)
	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			eventLog.Println("dial: blocking")
			if !<-inDial {
				return nil, errors.New("main Test goroutine exited")
			}
			<-unblockDial
			return nil, errors.New("nope")
		},
	}
	cl := &Client{Transport: tr}
	gotres := make(chan bool)
	req, _ := NewRequest("GET", "http://something.no-network.tld/", nil)
	req = test.newReq(req)
	go func() {
		_, err := cl.Do(req)
		eventLog.Printf("Get error = %v", err != nil)
		test.checkErr("Get", err)
		gotres <- true
	}()

	inDial <- true

	eventLog.Printf("canceling")
	test.cancel(tr, req)
	test.cancel(tr, req) // used to panic on second call to Transport.Cancel

	if d, ok := t.Deadline(); ok {
		// When the test's deadline is about to expire, log the pending events for
		// better debugging.
		timeout := time.Until(d) * 19 / 20 // Allow 5% for cleanup.
		timer := time.AfterFunc(timeout, func() {
			panic(fmt.Sprintf("hang in %s. events are: %s", t.Name(), logbuf.String()))
		})
		defer timer.Stop()
	}
	<-gotres

	got := logbuf.String()
	want := `dial: blocking
canceling
Get error = true
`
	if got != want {
		t.Errorf("Got events:\n%s\nWant:\n%s", got, want)
	}
}

// Issue 51354
func TestTransportCancelRequestWithBody(t *testing.T) {
	runCancelTest(t, testTransportCancelRequestWithBody)
}
func testTransportCancelRequestWithBody(t *testing.T, test cancelTest) {
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}

	const msg = "Hello"
	unblockc := make(chan struct{})
	ts := newClientServerTest(t, test.mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, msg)
		w.(Flusher).Flush() // send headers and some body
		<-unblockc
	})).ts
	defer close(unblockc)

	c := ts.Client()
	tr := c.Transport.(*Transport)

	req, _ := NewRequest("POST", ts.URL, strings.NewReader("withbody"))
	req = test.newReq(req)

	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len(msg))
	n, _ := io.ReadFull(res.Body, body)
	if n != len(body) || !bytes.Equal(body, []byte(msg)) {
		t.Errorf("Body = %q; want %q", body[:n], msg)
	}
	test.cancel(tr, req)

	tail, err := io.ReadAll(res.Body)
	res.Body.Close()
	test.checkErr("Body.Read", err)
	if len(tail) > 0 {
		t.Errorf("Spurious bytes from Body.Read: %q", tail)
	}

	// Verify no outstanding requests after readLoop/writeLoop
	// goroutines shut down.
	waitCondition(t, 10*time.Millisecond, func(d time.Duration) bool {
		n := tr.NumPendingRequestsForTesting()
		if n > 0 {
			if d > 0 {
				t.Logf("pending requests = %d after %v (want 0)", n, d)
			}
			return false
		}
		return true
	})
}

func TestTransportCancelRequestBeforeDo(t *testing.T) {
	// We can't cancel a request that hasn't started using Transport.CancelRequest.
	run(t, func(t *testing.T, mode testMode) {
		t.Run("RequestCancel", func(t *testing.T) {
			runCancelTestChannel(t, mode, testTransportCancelRequestBeforeDo)
		})
		t.Run("ContextCancel", func(t *testing.T) {
			runCancelTestContext(t, mode, testTransportCancelRequestBeforeDo)
		})
	})
}
func testTransportCancelRequestBeforeDo(t *testing.T, test cancelTest) {
	unblockc := make(chan bool)
	cst := newClientServerTest(t, test.mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		<-unblockc
	}))
	defer close(unblockc)

	c := cst.ts.Client()

	req, _ := NewRequest("GET", cst.ts.URL, nil)
	req = test.newReq(req)
	test.cancel(cst.tr, req)

	_, err := c.Do(req)
	test.checkErr("Do", err)
}

// Issue 11020. The returned error message should be errRequestCanceled
func TestTransportCancelRequestBeforeResponseHeaders(t *testing.T) {
	runCancelTest(t, testTransportCancelRequestBeforeResponseHeaders, []testMode{http1Mode})
}
func testTransportCancelRequestBeforeResponseHeaders(t *testing.T, test cancelTest) {
	defer afterTest(t)

	serverConnCh := make(chan net.Conn, 1)
	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			cc, sc := net.Pipe()
			serverConnCh <- sc
			return cc, nil
		},
	}
	defer tr.CloseIdleConnections()
	errc := make(chan error, 1)
	req, _ := NewRequest("GET", "http://example.com/", nil)
	req = test.newReq(req)
	go func() {
		_, err := tr.RoundTrip(req)
		errc <- err
	}()

	sc := <-serverConnCh
	verb := make([]byte, 3)
	if _, err := io.ReadFull(sc, verb); err != nil {
		t.Errorf("Error reading HTTP verb from server: %v", err)
	}
	if string(verb) != "GET" {
		t.Errorf("server received %q; want GET", verb)
	}
	defer sc.Close()

	test.cancel(tr, req)

	err := <-errc
	if err == nil {
		t.Fatalf("unexpected success from RoundTrip")
	}
	test.checkErr("RoundTrip", err)
}

// golang.org/issue/3672 -- Client can't close HTTP stream
// Calling Close on a Response.Body used to just read until EOF.
// Now it actually closes the TCP connection.
func TestTransportCloseResponseBody(t *testing.T) { run(t, testTransportCloseResponseBody) }
func testTransportCloseResponseBody(t *testing.T, mode testMode) {
	writeErr := make(chan error, 1)
	msg := []byte("young\n")
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		for {
			_, err := w.Write(msg)
			if err != nil {
				writeErr <- err
				return
			}
			w.(Flusher).Flush()
		}
	})).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)

	req, _ := NewRequest("GET", ts.URL, nil)
	defer tr.CancelRequest(req)

	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	const repeats = 3
	buf := make([]byte, len(msg)*repeats)
	want := bytes.Repeat(msg, repeats)

	_, err = io.ReadFull(res.Body, buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("read %q; want %q", buf, want)
	}

	if err := res.Body.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}

	if err := <-writeErr; err == nil {
		t.Errorf("expected non-nil write error")
	}
}

type fooProto struct{}

func (fooProto) RoundTrip(req *Request) (*Response, error) {
	res := &Response{
		Status:     "200 OK",
		StatusCode: 200,
		Header:     make(Header),
		Body:       io.NopCloser(strings.NewReader("You wanted " + req.URL.String())),
	}
	return res, nil
}

func TestTransportAltProto(t *testing.T) {
	defer afterTest(t)
	tr := &Transport{}
	c := &Client{Transport: tr}
	tr.RegisterProtocol("foo", fooProto{})
	res, err := c.Get("foo://bar.com/path")
	if err != nil {
		t.Fatal(err)
	}
	bodyb, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyb)
	if e := "You wanted foo://bar.com/path"; body != e {
		t.Errorf("got response %q, want %q", body, e)
	}
}

func TestTransportNoHost(t *testing.T) {
	defer afterTest(t)
	tr := &Transport{}
	_, err := tr.RoundTrip(&Request{
		Header: make(Header),
		URL: &url.URL{
			Scheme: "http",
		},
	})
	want := "http: no Host in request URL"
	if got := fmt.Sprint(err); got != want {
		t.Errorf("error = %v; want %q", err, want)
	}
}

// Issue 13311
func TestTransportEmptyMethod(t *testing.T) {
	req, _ := NewRequest("GET", "http://foo.com/", nil)
	req.Method = ""                                 // docs say "For client requests an empty string means GET"
	got, err := httputil.DumpRequestOut(req, false) // DumpRequestOut uses Transport
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "GET ") {
		t.Fatalf("expected substring 'GET '; got: %s", got)
	}
}

func TestTransportSocketLateBinding(t *testing.T) { run(t, testTransportSocketLateBinding) }
func testTransportSocketLateBinding(t *testing.T, mode testMode) {
	mux := NewServeMux()
	fooGate := make(chan bool, 1)
	mux.HandleFunc("/foo", func(w ResponseWriter, r *Request) {
		w.Header().Set("foo-ipport", r.RemoteAddr)
		w.(Flusher).Flush()
		<-fooGate
	})
	mux.HandleFunc("/bar", func(w ResponseWriter, r *Request) {
		w.Header().Set("bar-ipport", r.RemoteAddr)
	})
	ts := newClientServerTest(t, mode, mux).ts

	dialGate := make(chan bool, 1)
	dialing := make(chan bool)
	c := ts.Client()
	c.Transport.(*Transport).Dial = func(n, addr string) (net.Conn, error) {
		for {
			select {
			case ok := <-dialGate:
				if !ok {
					return nil, errors.New("manually closed")
				}
				return net.Dial(n, addr)
			case dialing <- true:
			}
		}
	}
	defer close(dialGate)

	dialGate <- true // only allow one dial
	fooRes, err := c.Get(ts.URL + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	fooAddr := fooRes.Header.Get("foo-ipport")
	if fooAddr == "" {
		t.Fatal("No addr on /foo request")
	}

	fooDone := make(chan struct{})
	go func() {
		// We know that the foo Dial completed and reached the handler because we
		// read its header. Wait for the bar request to block in Dial, then
		// let the foo response finish so we can use its connection for /bar.

		if mode == http2Mode {
			// In HTTP/2 mode, the second Dial won't happen because the protocol
			// multiplexes the streams by default. Just sleep for an arbitrary time;
			// the test should pass regardless of how far the bar request gets by this
			// point.
			select {
			case <-dialing:
				t.Errorf("unexpected second Dial in HTTP/2 mode")
			case <-time.After(10 * time.Millisecond):
			}
		} else {
			<-dialing
		}
		fooGate <- true
		io.Copy(io.Discard, fooRes.Body)
		fooRes.Body.Close()
		close(fooDone)
	}()
	defer func() {
		<-fooDone
	}()

	barRes, err := c.Get(ts.URL + "/bar")
	if err != nil {
		t.Fatal(err)
	}
	barAddr := barRes.Header.Get("bar-ipport")
	if barAddr != fooAddr {
		t.Fatalf("/foo came from conn %q; /bar came from %q instead", fooAddr, barAddr)
	}
	barRes.Body.Close()
}

// Issue 2184
func TestTransportReading100Continue(t *testing.T) {
	defer afterTest(t)

	const numReqs = 5
	reqBody := func(n int) string { return fmt.Sprintf("request body %d", n) }
	reqID := func(n int) string { return fmt.Sprintf("REQ-ID-%d", n) }

	send100Response := func(w *io.PipeWriter, r *io.PipeReader) {
		defer w.Close()
		defer r.Close()
		br := bufio.NewReader(r)
		n := 0
		for {
			n++
			req, err := ReadRequest(br)
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			slurp, err := io.ReadAll(req.Body)
			if err != nil {
				t.Errorf("Server request body slurp: %v", err)
				return
			}
			id := req.Header.Get("Request-Id")
			resCode := req.Header.Get("X-Want-Response-Code")
			if resCode == "" {
				resCode = "100 Continue"
				if string(slurp) != reqBody(n) {
					t.Errorf("Server got %q, %v; want %q", slurp, err, reqBody(n))
				}
			}
			body := fmt.Sprintf("Response number %d", n)
			v := []byte(strings.Replace(fmt.Sprintf(`HTTP/1.1 %s
Date: Thu, 28 Feb 2013 17:55:41 GMT

HTTP/1.1 200 OK
Content-Type: text/html
Echo-Request-Id: %s
Content-Length: %d

%s`, resCode, id, len(body), body), "\n", "\r\n", -1))
			w.Write(v)
			if id == reqID(numReqs) {
				return
			}
		}

	}

	tr := &Transport{
		Dial: func(n, addr string) (net.Conn, error) {
			sr, sw := io.Pipe() // server read/write
			cr, cw := io.Pipe() // client read/write
			conn := &rwTestConn{
				Reader: cr,
				Writer: sw,
				closeFunc: func() error {
					sw.Close()
					cw.Close()
					return nil
				},
			}
			go send100Response(cw, sr)
			return conn, nil
		},
		DisableKeepAlives: false,
	}
	defer tr.CloseIdleConnections()
	c := &Client{Transport: tr}

	testResponse := func(req *Request, name string, wantCode int) {
		t.Helper()
		res, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: Do: %v", name, err)
		}
		if res.StatusCode != wantCode {
			t.Fatalf("%s: Response Statuscode=%d; want %d", name, res.StatusCode, wantCode)
		}
		if id, idBack := req.Header.Get("Request-Id"), res.Header.Get("Echo-Request-Id"); id != "" && id != idBack {
			t.Errorf("%s: response id %q != request id %q", name, idBack, id)
		}
		_, err = io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("%s: Slurp error: %v", name, err)
		}
	}

	// Few 100 responses, making sure we're not off-by-one.
	for i := 1; i <= numReqs; i++ {
		req, _ := NewRequest("POST", "http://dummy.tld/", strings.NewReader(reqBody(i)))
		req.Header.Set("Request-Id", reqID(i))
		testResponse(req, fmt.Sprintf("100, %d/%d", i, numReqs), 200)
	}
}

// Issue 17739: the HTTP client must ignore any unknown 1xx
// informational responses before the actual response.
func TestTransportIgnore1xxResponses(t *testing.T) {
	run(t, testTransportIgnore1xxResponses, []testMode{http1Mode})
}
func testTransportIgnore1xxResponses(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		conn, buf, _ := w.(Hijacker).Hijack()
		buf.Write([]byte("HTTP/1.1 123 OneTwoThree\r\nFoo: bar\r\n\r\nHTTP/1.1 200 OK\r\nBar: baz\r\nContent-Length: 5\r\n\r\nHello"))
		buf.Flush()
		conn.Close()
	}))
	cst.tr.DisableKeepAlives = true // prevent log spam; our test server is hanging up anyway

	var got strings.Builder

	req, _ := NewRequest("GET", cst.ts.URL, nil)
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			fmt.Fprintf(&got, "1xx: code=%v, header=%v\n", code, header)
			return nil
		},
	}))
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	res.Write(&got)
	want := "1xx: code=123, header=map[Foo:[bar]]\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\nBar: baz\r\n\r\nHello"
	if got.String() != want {
		t.Errorf(" got: %q\nwant: %q\n", got.String(), want)
	}
}

func TestTransportLimits1xxResponses(t *testing.T) { run(t, testTransportLimits1xxResponses) }
func testTransportLimits1xxResponses(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Add("X-Header", strings.Repeat("a", 100))
		for i := 0; i < 10; i++ {
			w.WriteHeader(123)
		}
		w.WriteHeader(204)
	}))
	cst.tr.DisableKeepAlives = true // prevent log spam; our test server is hanging up anyway
	cst.tr.MaxResponseHeaderBytes = 1000

	res, err := cst.c.Get(cst.ts.URL)
	if err == nil {
		res.Body.Close()
		t.Fatalf("RoundTrip succeeded; want error")
	}
	for _, want := range []string{
		"response headers exceeded",
		"too many 1xx",
		"header list too large",
	} {
		if strings.Contains(err.Error(), want) {
			return
		}
	}
	t.Errorf(`got error %q; want "response headers exceeded" or "too many 1xx"`, err)
}

func TestTransportDoesNotLimitDelivered1xxResponses(t *testing.T) {
	run(t, testTransportDoesNotLimitDelivered1xxResponses)
}
func testTransportDoesNotLimitDelivered1xxResponses(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("skip until x/net/http2 updated")
	}
	const num1xx = 10
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Add("X-Header", strings.Repeat("a", 100))
		for i := 0; i < 10; i++ {
			w.WriteHeader(123)
		}
		w.WriteHeader(204)
	}))
	cst.tr.DisableKeepAlives = true // prevent log spam; our test server is hanging up anyway
	cst.tr.MaxResponseHeaderBytes = 1000

	got1xx := 0
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			got1xx++
			return nil
		},
	})
	req, _ := NewRequestWithContext(ctx, "GET", cst.ts.URL, nil)
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got1xx != num1xx {
		t.Errorf("Got %v 1xx responses, want %x", got1xx, num1xx)
	}
}

// Issue 26161: the HTTP client must treat 101 responses
// as the final response.
func TestTransportTreat101Terminal(t *testing.T) {
	run(t, testTransportTreat101Terminal, []testMode{http1Mode})
}
func testTransportTreat101Terminal(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		conn, buf, _ := w.(Hijacker).Hijack()
		buf.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
		buf.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
		buf.Flush()
		conn.Close()
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != StatusSwitchingProtocols {
		t.Errorf("StatusCode = %v; want 101 Switching Protocols", res.StatusCode)
	}
}

type proxyFromEnvTest struct {
	req string // URL to fetch; blank means "http://example.com"

	env      string // HTTP_PROXY
	httpsenv string // HTTPS_PROXY
	noenv    string // NO_PROXY
	reqmeth  string // REQUEST_METHOD

	want    string
	wanterr error
}

func (t proxyFromEnvTest) String() string {
	var buf strings.Builder
	space := func() {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
	}
	if t.env != "" {
		fmt.Fprintf(&buf, "http_proxy=%q", t.env)
	}
	if t.httpsenv != "" {
		space()
		fmt.Fprintf(&buf, "https_proxy=%q", t.httpsenv)
	}
	if t.noenv != "" {
		space()
		fmt.Fprintf(&buf, "no_proxy=%q", t.noenv)
	}
	if t.reqmeth != "" {
		space()
		fmt.Fprintf(&buf, "request_method=%q", t.reqmeth)
	}
	req := "http://example.com"
	if t.req != "" {
		req = t.req
	}
	space()
	fmt.Fprintf(&buf, "req=%q", req)
	return strings.TrimSpace(buf.String())
}

var proxyFromEnvTests = []proxyFromEnvTest{
	{env: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
	{env: "cache.corp.example.com:1234", want: "http://cache.corp.example.com:1234"},
	{env: "cache.corp.example.com", want: "http://cache.corp.example.com"},
	{env: "https://cache.corp.example.com", want: "https://cache.corp.example.com"},
	{env: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
	{env: "https://127.0.0.1:8080", want: "https://127.0.0.1:8080"},
	{env: "socks5://127.0.0.1", want: "socks5://127.0.0.1"},
	{env: "socks5h://127.0.0.1", want: "socks5h://127.0.0.1"},

	// Don't use secure for http
	{req: "http://insecure.tld/", env: "http.proxy.tld", httpsenv: "secure.proxy.tld", want: "http://http.proxy.tld"},
	// Use secure for https.
	{req: "https://secure.tld/", env: "http.proxy.tld", httpsenv: "secure.proxy.tld", want: "http://secure.proxy.tld"},
	{req: "https://secure.tld/", env: "http.proxy.tld", httpsenv: "https://secure.proxy.tld", want: "https://secure.proxy.tld"},

	// Issue 16405: don't use HTTP_PROXY in a CGI environment,
	// where HTTP_PROXY can be attacker-controlled.
	{env: "http://10.1.2.3:8080", reqmeth: "POST",
		want:    "<nil>",
		wanterr: errors.New("refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy")},

	{want: "<nil>"},

	{noenv: "example.com", req: "http://example.com/", env: "proxy", want: "<nil>"},
	{noenv: ".example.com", req: "http://example.com/", env: "proxy", want: "http://proxy"},
	{noenv: "ample.com", req: "http://example.com/", env: "proxy", want: "http://proxy"},
	{noenv: "example.com", req: "http://foo.example.com/", env: "proxy", want: "<nil>"},
	{noenv: ".foo.com", req: "http://example.com/", env: "proxy", want: "http://proxy"},
}

func testProxyForRequest(t *testing.T, tt proxyFromEnvTest, proxyForRequest func(req *Request) (*url.URL, error)) {
	t.Helper()
	reqURL := tt.req
	if reqURL == "" {
		reqURL = "http://example.com"
	}
	req, _ := NewRequest("GET", reqURL, nil)
	url, err := proxyForRequest(req)
	if g, e := fmt.Sprintf("%v", err), fmt.Sprintf("%v", tt.wanterr); g != e {
		t.Errorf("%v: got error = %q, want %q", tt, g, e)
		return
	}
	if got := fmt.Sprintf("%s", url); got != tt.want {
		t.Errorf("%v: got URL = %q, want %q", tt, url, tt.want)
	}
}

func TestProxyFromEnvironment(t *testing.T) {
	ResetProxyEnv()
	defer ResetProxyEnv()
	for _, tt := range proxyFromEnvTests {
		testProxyForRequest(t, tt, func(req *Request) (*url.URL, error) {
			os.Setenv("HTTP_PROXY", tt.env)
			os.Setenv("HTTPS_PROXY", tt.httpsenv)
			os.Setenv("NO_PROXY", tt.noenv)
			os.Setenv("REQUEST_METHOD", tt.reqmeth)
			ResetCachedEnvironment()
			return ProxyFromEnvironment(req)
		})
	}
}

func TestProxyFromEnvironmentLowerCase(t *testing.T) {
	ResetProxyEnv()
	defer ResetProxyEnv()
	for _, tt := range proxyFromEnvTests {
		testProxyForRequest(t, tt, func(req *Request) (*url.URL, error) {
			os.Setenv("http_proxy", tt.env)
			os.Setenv("https_proxy", tt.httpsenv)
			os.Setenv("no_proxy", tt.noenv)
			os.Setenv("REQUEST_METHOD", tt.reqmeth)
			ResetCachedEnvironment()
			return ProxyFromEnvironment(req)
		})
	}
}

func TestIdleConnChannelLeak(t *testing.T) {
	run(t, testIdleConnChannelLeak, []testMode{http1Mode}, testNotParallel)
}
func testIdleConnChannelLeak(t *testing.T, mode testMode) {
	// Not parallel: uses global test hooks.
	var mu sync.Mutex
	var n int

	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		mu.Lock()
		n++
		mu.Unlock()
	})).ts

	const nReqs = 5
	didRead := make(chan bool, nReqs)
	SetReadLoopBeforeNextReadHook(func() { didRead <- true })
	defer SetReadLoopBeforeNextReadHook(nil)

	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.Dial = func(netw, addr string) (net.Conn, error) {
		return net.Dial(netw, ts.Listener.Addr().String())
	}

	// First, without keep-alives.
	for _, disableKeep := range []bool{true, false} {
		tr.DisableKeepAlives = disableKeep
		for i := 0; i < nReqs; i++ {
			_, err := c.Get(fmt.Sprintf("http://foo-host-%d.tld/", i))
			if err != nil {
				t.Fatal(err)
			}
			// Note: no res.Body.Close is needed here, since the
			// response Content-Length is zero. Perhaps the test
			// should be more explicit and use a HEAD, but tests
			// elsewhere guarantee that zero byte responses generate
			// a "Content-Length: 0" instead of chunking.
		}

		// At this point, each of the 5 Transport.readLoop goroutines
		// are scheduling noting that there are no response bodies (see
		// earlier comment), and are then calling putIdleConn, which
		// decrements this count. Usually that happens quickly, which is
		// why this test has seemed to work for ages. But it's still
		// racey: we have wait for them to finish first. See Issue 10427
		for i := 0; i < nReqs; i++ {
			<-didRead
		}

		if got := tr.IdleConnWaitMapSizeForTesting(); got != 0 {
			t.Fatalf("for DisableKeepAlives = %v, map size = %d; want 0", disableKeep, got)
		}
	}
}

// Verify the status quo: that the Client.Post function coerces its
// body into a ReadCloser if it's a Closer, and that the Transport
// then closes it.
func TestTransportClosesRequestBody(t *testing.T) {
	run(t, testTransportClosesRequestBody, []testMode{http1Mode})
}
func testTransportClosesRequestBody(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.Copy(io.Discard, r.Body)
	})).ts

	c := ts.Client()

	closes := 0

	res, err := c.Post(ts.URL, "text/plain", countCloseReader{&closes, strings.NewReader("hello")})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if closes != 1 {
		t.Errorf("closes = %d; want 1", closes)
	}
}

func TestTransportTLSHandshakeTimeout(t *testing.T) {
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	ln := newLocalListener(t)
	defer ln.Close()
	testdonec := make(chan struct{})
	defer close(testdonec)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		<-testdonec
		c.Close()
	}()

	tr := &Transport{
		Dial: func(_, _ string) (net.Conn, error) {
			return net.Dial("tcp", ln.Addr().String())
		},
		TLSHandshakeTimeout: 250 * time.Millisecond,
	}
	cl := &Client{Transport: tr}
	_, err := cl.Get("https://dummy.tld/")
	if err == nil {
		t.Error("expected error")
		return
	}
	ue, ok := err.(*u
```