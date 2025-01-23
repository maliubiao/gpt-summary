Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for an analysis of a Go source code file (`transport_test.go`) focusing on its functionality, related Go features, code examples with input/output, command-line argument handling, common pitfalls, and a final summary of its purpose. The "part 7 of 7" indicates this is the concluding section, so a summarization is crucial.

2. **Initial Scan and Structure Recognition:** Quickly skim the code to identify the major components. Notice the presence of:
    * Test functions (`Test...`) suggesting this is a testing file.
    * Helper functions (e.g., `run`, `newClientServerTest`, `neverEnding`).
    * Use of standard Go libraries like `net/http`, `context`, `sync`, `errors`, `io`, `url`, `crypto/tls`, `crypto/x509`, and `strings`.
    * Specific test cases covering various scenarios related to HTTP transport.

3. **Analyze Individual Test Functions:**  Go through each `test...` function and understand its purpose.

    * **`testCancelRequestWhileIdle`:** Focus on the `context.WithCancel` and the blocking/unblocking of goroutines. The names `reqc`, `putidlec`, `cancelctx`, `cancel` strongly suggest request management and cancellation.

    * **`testHandlerAbortRacesBodyRead`:** The `panic(ErrAbortHandler)` and the `io.Copy(io.Discard, req.Body)` within the handler point to testing race conditions related to abruptly terminating request processing and reading the request body. The loop also suggests stress testing.

    * **`testRequestSanitization`:** The header check (`req.Header["X-Evil"]`) and the manipulation of `req.Host` with `\r\nX-Evil:evil` clearly indicate a test for preventing header injection vulnerabilities.

    * **`testProxyAuthHeader`:** The use of `t.Setenv("HTTP_PROXY", ...)` and `r2.BasicAuth()` strongly suggests testing the handling of proxy authentication headers.

    * **`TestTransportReqCancelerCleanupOnRequestBodyWriteError`:**  The `io.LimitReader(neverEnding('x'), 1<<30)` and the server-side code that reads before sending a response hint at testing cleanup of resources when writing the request body fails. The `NumPendingRequestsForTesting` confirms this suspicion.

    * **`testValidateClientRequestTrailers`:** The `req.Trailer` and the error checking for invalid characters suggest testing the validation of HTTP trailers.

    * **`TestTransportServerProtocols`:**  The loop iterating through different scenarios involving `tr.Protocols`, `srv.Protocols`, `TLSNextProto`, and environment variables (`GODEBUG`) clearly indicates a test for negotiating HTTP versions (HTTP/1.1, HTTP/2) between client and server.

4. **Identify Key Go Features Demonstrated:** As each test function is analyzed, note the Go features it utilizes:
    * **Goroutines and Channels:** For concurrency and communication between different parts of the test.
    * **Context:** For request cancellation and propagation of deadlines.
    * **`net/http`:**  Central to the testing, covering requests, responses, handlers, clients, servers, and transport mechanisms.
    * **`sync.WaitGroup`:** For waiting for goroutines to complete.
    * **`errors.Is`:** For checking specific error types.
    * **`io` package:** For reading, writing, and discarding data.
    * **`url` package:** For parsing URLs.
    * **`crypto/tls` and `crypto/x509`:** For testing HTTPS and TLS configurations.
    * **Environment variables (using `t.Setenv`):**  For influencing the behavior of the HTTP client and server (specifically for `HTTP_PROXY` and `GODEBUG`).
    * **`testing` package:**  The foundation for the test framework.
    * **Closures:** Used within `HandlerFunc` and goroutines.

5. **Construct Code Examples:**  For key functionalities, create simplified Go code snippets illustrating their usage. Focus on the core concepts demonstrated in the test functions. Include:
    * Request cancellation with `context`.
    * Handling panics in HTTP handlers (`ErrAbortHandler`).
    * Setting proxy authentication.
    * Validating request trailers.
    * Configuring HTTP/2 on both client and server.

6. **Infer Input/Output for Code Examples:**  For the code examples, describe the expected input and output based on the functionality being demonstrated. This helps clarify how the code works.

7. **Analyze Command-Line Arguments:** Carefully examine the code for any explicit parsing of command-line arguments. In this case, there are none directly within the provided snippet. However, the use of `t.Setenv("GODEBUG", ...)` is important as it indirectly interacts with environment variables that can be set via the command line before running the tests. Explain how `GODEBUG` influences HTTP/2 behavior.

8. **Identify Common Pitfalls:**  Think about the potential mistakes developers might make when working with the features demonstrated in the code. Examples include:
    * Not closing response bodies.
    * Incorrectly handling request cancellation.
    * Security vulnerabilities related to header injection.
    * Issues with proxy configuration.
    * Misunderstanding HTTP/2 configuration.

9. **Summarize the Functionality:** Based on the analysis of all the test functions, provide a concise summary of the overall purpose of the code. Focus on testing the `Transport` type in the `net/http` package and its various aspects.

10. **Review and Refine:**  Read through the entire analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. Make sure the language is clear and easy to understand for someone familiar with Go. Specifically check if the explanation for each test function aligns with the provided code. For example, ensure the explanation for `testHandlerAbortRacesBodyRead` mentions the race condition aspect.

This structured approach allows for a comprehensive and accurate analysis of the Go code snippet, addressing all the requirements of the original request.
这是一个 Go 语言 `net/http` 包中 `transport_test.go` 文件的一部分，主要用于测试 `http.Transport` 类型的各种功能和边界情况。

**具体功能列举：**

1. **测试在连接空闲时的请求取消:**  验证当一个请求正在等待连接变得空闲时，可以通过 `context.Context` 取消该请求。
2. **测试处理程序中止时与读取请求体的竞态条件:**  模拟处理请求时发生 `panic(ErrAbortHandler)` 的情况，并测试此时并发读取请求体是否会产生竞态条件。
3. **测试请求的清理 (Sanitization):** 验证 `http.Transport` 会清理请求头中的非法字符，防止潜在的安全漏洞（如 HTTP 响应拆分）。
4. **测试代理身份验证头 (Proxy Authentication Header):** 验证 `http.Transport` 是否正确处理 `Proxy-Authorization` 请求头，并能通过 `Request.BasicAuth()` 正确解析用户名和密码。
5. **测试请求体写入错误时的 Transport 请求取消器清理:** 验证当写入请求体时发生错误，`http.Transport` 能否正确清理相关资源，避免goroutine泄漏。
6. **测试验证客户端请求 Trailer:**  验证客户端设置的 Trailer Header 是否符合规范，如果包含非法字符会返回错误。
7. **测试 Transport 的服务器协议协商:** 测试 `http.Transport` 如何根据自身和服务器的配置（包括 `Protocols` 字段、`TLSNextProto` 和环境变量 `GODEBUG`）来协商使用的 HTTP 版本（HTTP/1.1 或 HTTP/2.0）。

**Go 语言功能实现举例说明:**

**1. 测试在连接空闲时的请求取消:**

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func main() {
	// 创建一个自定义的 Transport，限制最大空闲连接数为 0，迫使请求等待连接
	tr := &http.Transport{
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
	}
	client := &http.Client{Transport: tr}

	// 创建一个服务器，处理请求时休眠一段时间
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Server received request")
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello from server")
	})
	go http.ListenAndServe(":8080", nil)

	// 创建一个带有取消功能的 Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 创建一个请求
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:8080", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 执行请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error during request:", err) // 输出：Error during request: Get "http://localhost:8080": context deadline exceeded
		return
	}
	defer resp.Body.Close()

	fmt.Println("Response status:", resp.Status)
}
```

**假设输入与输出:**

* **输入:** 运行上述代码，服务器监听在 `localhost:8080`。
* **输出:** 由于设置了 1 秒的超时时间，而服务器处理请求需要 2 秒，因此 `client.Do(req)` 会因为 `context deadline exceeded` 错误而失败。 这模拟了当连接空闲时取消请求的场景。

**2. 测试请求的清理 (Sanitization):**

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
)

func main() {
	// 创建一个测试服务器
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Received request headers:", r.Header)
		if _, ok := r.Header["X-Evil"]; ok {
			fmt.Println("Error: X-Evil header found!")
		} else {
			fmt.Println("X-Evil header not found, request sanitized.")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := ts.Client()

	// 创建一个包含恶意 Host 头的请求
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Host = "example.com\r\nX-Evil: malicious" // 尝试注入 X-Evil 头

	// 执行请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error during request:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Response status:", resp.Status)
}
```

**假设输入与输出:**

* **输入:** 运行上述代码。
* **输出:** 服务器的输出会显示 `X-Evil header not found, request sanitized.`，这意味着 `http.Transport` 在发送请求前移除了 `req.Host` 中注入的恶意头部。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。 然而，`TestTransportServerProtocols` 函数中使用了 `t.Setenv("GODEBUG", ...)` 来设置环境变量。 `GODEBUG` 环境变量可以影响 Go 程序的运行时行为，包括 HTTP/2 的启用和禁用。

例如，在运行测试时，可以通过命令行设置 `GODEBUG`：

```bash
go test -v -run TestTransportServerProtocols  -exec 'env GODEBUG=http2client=0'
```

这个命令会设置 `http2client=0`，强制禁用 HTTP/2 客户端，从而测试在禁用 HTTP/2 客户端的情况下的协议协商。

**使用者易犯错的点：**

在与 `http.Transport` 交互时，用户容易犯以下错误：

1. **不关闭响应体 (Response Body):**  在完成请求处理后，必须关闭 `resp.Body` 以释放连接资源。 如果不关闭，可能会导致连接泄漏，最终耗尽可用连接。

   ```go
   resp, err := client.Get("https://example.com")
   if err != nil {
       // 处理错误
   }
   // 忘记关闭 resp.Body
   ```

2. **在取消请求后仍然尝试使用响应:**  如果通过 `context` 取消了一个请求，应该避免继续读取或操作响应，因为此时连接可能已经被关闭。

   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
   defer cancel()
   req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com", nil)
   resp, err := client.Do(req)
   if err != nil {
       // 处理取消错误
   } else {
       defer resp.Body.Close() // 如果请求被取消，这里可能会出错
       // ... 使用 resp.Body ...
   }
   ```

3. **错误地配置 `Transport` 的参数:**  例如，错误地设置 `MaxIdleConns` 或 `IdleConnTimeout` 可能会影响连接的重用和性能。

**归纳一下它的功能 (作为第 7 部分):**

作为 `go/src/net/http/transport_test.go` 的最后一部分，这段代码主要集中在 **`http.Transport` 的健壮性和边界情况测试**。 它涵盖了以下关键方面：

* **请求生命周期管理:**  包括请求的取消、连接的空闲管理以及在异常情况下的资源清理。
* **安全性:**  验证了 `Transport` 对请求的清理能力，以防止潜在的安全漏洞。
* **代理支持:**  测试了 `Transport` 处理代理身份验证的能力。
* **协议协商:**  深入测试了 `Transport` 如何根据各种配置和环境因素来协商使用的 HTTP 版本（HTTP/1.1 和 HTTP/2.0）。
* **错误处理和竞态条件:**  模拟并测试了在请求处理过程中可能出现的错误和并发情况。

总而言之，这段代码通过一系列详尽的测试用例，确保 `http.Transport` 能够可靠、安全、高效地处理各种 HTTP 通信场景，并能正确处理各种边界情况和潜在的错误。 它是 `net/http` 包稳定性的重要保障。

### 提示词
```
这是路径为go/src/net/http/transport_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
r1c := <-reqc:
		close(r1c)
	}
	var idlec chan struct{}
	select {
	case err := <-reqerrc:
		t.Fatalf("request 1: got err %v, want nil", err)
	case idlec = <-putidlec:
	}

	wg.Add(1)
	cancelctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer wg.Done()
		req, _ := NewRequestWithContext(cancelctx, "GET", ts.URL, nil)
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("request 2: got err %v, want Canceled", err)
		}

		// Unblock the first request.
		close(idlec)
	}()

	// Wait for the second request to arrive at the server, and then cancel
	// the request context.
	r2c := <-reqc
	cancel()

	<-idlec

	close(r2c)
	wg.Wait()
}

func TestHandlerAbortRacesBodyRead(t *testing.T) { run(t, testHandlerAbortRacesBodyRead) }
func testHandlerAbortRacesBodyRead(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		go io.Copy(io.Discard, req.Body)
		panic(ErrAbortHandler)
	})).ts

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				const reqLen = 6 * 1024 * 1024
				req, _ := NewRequest("POST", ts.URL, &io.LimitedReader{R: neverEnding('x'), N: reqLen})
				req.ContentLength = reqLen
				resp, _ := ts.Client().Transport.RoundTrip(req)
				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func TestRequestSanitization(t *testing.T) { run(t, testRequestSanitization) }
func testRequestSanitization(t *testing.T, mode testMode) {
	if mode == http2Mode {
		// Remove this after updating x/net.
		t.Skip("https://go.dev/issue/60374 test fails when run with HTTP/2")
	}
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		if h, ok := req.Header["X-Evil"]; ok {
			t.Errorf("request has X-Evil header: %q", h)
		}
	})).ts
	req, _ := NewRequest("GET", ts.URL, nil)
	req.Host = "go.dev\r\nX-Evil:evil"
	resp, _ := ts.Client().Do(req)
	if resp != nil {
		resp.Body.Close()
	}
}

func TestProxyAuthHeader(t *testing.T) {
	// Not parallel: Sets an environment variable.
	run(t, testProxyAuthHeader, []testMode{http1Mode}, testNotParallel)
}
func testProxyAuthHeader(t *testing.T, mode testMode) {
	const username = "u"
	const password = "@/?!"
	cst := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		// Copy the Proxy-Authorization header to a new Request,
		// since Request.BasicAuth only parses the Authorization header.
		var r2 Request
		r2.Header = Header{
			"Authorization": req.Header["Proxy-Authorization"],
		}
		gotuser, gotpass, ok := r2.BasicAuth()
		if !ok || gotuser != username || gotpass != password {
			t.Errorf("req.BasicAuth() = %q, %q, %v; want %q, %q, true", gotuser, gotpass, ok, username, password)
		}
	}))
	u, err := url.Parse(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(username, password)
	t.Setenv("HTTP_PROXY", u.String())
	cst.tr.Proxy = ProxyURL(u)
	resp, err := cst.c.Get("http://_/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// Issue 61708
func TestTransportReqCancelerCleanupOnRequestBodyWriteError(t *testing.T) {
	ln := newLocalListener(t)
	addr := ln.Addr().String()

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("ln.Accept: %v", err)
			return
		}
		// Start reading request before sending response to avoid
		// "Unsolicited response received on idle HTTP channel" RoundTrip error.
		if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
			t.Errorf("conn.Read: %v", err)
			return
		}
		io.WriteString(conn, "HTTP/1.1 200\r\nContent-Length: 3\r\n\r\nfoo")
		<-done
		conn.Close()
	}()

	didRead := make(chan bool)
	SetReadLoopBeforeNextReadHook(func() { didRead <- true })
	defer SetReadLoopBeforeNextReadHook(nil)

	tr := &Transport{}

	// Send a request with a body guaranteed to fail on write.
	req, err := NewRequest("POST", "http://"+addr, io.LimitReader(neverEnding('x'), 1<<30))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("tr.RoundTrip: %v", err)
	}

	close(done)

	// Before closing response body wait for readLoopDone goroutine
	// to complete due to closed connection by writeLoop.
	<-didRead

	resp.Body.Close()

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

func TestValidateClientRequestTrailers(t *testing.T) {
	run(t, testValidateClientRequestTrailers)
}

func testValidateClientRequestTrailers(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		rw.Write([]byte("Hello"))
	})).ts

	cases := []struct {
		trailer Header
		wantErr string
	}{
		{Header{"Trx": {"x\r\nX-Another-One"}}, `invalid trailer field value for "Trx"`},
		{Header{"\r\nTrx": {"X-Another-One"}}, `invalid trailer field name "\r\nTrx"`},
	}

	for i, tt := range cases {
		testName := fmt.Sprintf("%s%d", mode, i)
		t.Run(testName, func(t *testing.T) {
			req, err := NewRequest("GET", cst.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Trailer = tt.trailer
			res, err := cst.Client().Do(req)
			if err == nil {
				t.Fatal("Expected an error")
			}
			if g, w := err.Error(), tt.wantErr; !strings.Contains(g, w) {
				t.Fatalf("Mismatched error\n\t%q\ndoes not contain\n\t%q", g, w)
			}
			if res != nil {
				t.Fatal("Unexpected non-nil response")
			}
		})
	}
}

func TestTransportServerProtocols(t *testing.T) {
	CondSkipHTTP2(t)
	DefaultTransport.(*Transport).CloseIdleConnections()

	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	certpool := x509.NewCertPool()
	certpool.AddCert(leafCert)

	for _, test := range []struct {
		name      string
		scheme    string
		setup     func(t *testing.T)
		transport func(*Transport)
		server    func(*Server)
		want      string
	}{{
		name:   "http default",
		scheme: "http",
		want:   "HTTP/1.1",
	}, {
		name:   "https default",
		scheme: "https",
		transport: func(tr *Transport) {
			// Transport default is HTTP/1.
		},
		want: "HTTP/1.1",
	}, {
		name:   "https transport protocols include HTTP2",
		scheme: "https",
		transport: func(tr *Transport) {
			// Server default is to support HTTP/2, so if the Transport enables
			// HTTP/2 we get it.
			tr.Protocols = &Protocols{}
			tr.Protocols.SetHTTP1(true)
			tr.Protocols.SetHTTP2(true)
		},
		want: "HTTP/2.0",
	}, {
		name:   "https transport protocols only include HTTP1",
		scheme: "https",
		transport: func(tr *Transport) {
			// Explicitly enable only HTTP/1.
			tr.Protocols = &Protocols{}
			tr.Protocols.SetHTTP1(true)
		},
		want: "HTTP/1.1",
	}, {
		name:   "https transport ForceAttemptHTTP2",
		scheme: "https",
		transport: func(tr *Transport) {
			// Pre-Protocols-field way of enabling HTTP/2.
			tr.ForceAttemptHTTP2 = true
		},
		want: "HTTP/2.0",
	}, {
		name:   "https transport protocols override TLSNextProto",
		scheme: "https",
		transport: func(tr *Transport) {
			// Setting TLSNextProto to an empty map is the historical way
			// of disabling HTTP/2. Explicitly enabling HTTP2 in the Protocols
			// field takes precedence.
			tr.Protocols = &Protocols{}
			tr.Protocols.SetHTTP1(true)
			tr.Protocols.SetHTTP2(true)
			tr.TLSNextProto = map[string]func(string, *tls.Conn) RoundTripper{}
		},
		want: "HTTP/2.0",
	}, {
		name:   "https server disables HTTP2 with TLSNextProto",
		scheme: "https",
		server: func(srv *Server) {
			// Disable HTTP/2 on the server with TLSNextProto,
			// use default Protocols value.
			srv.TLSNextProto = map[string]func(*Server, *tls.Conn, Handler){}
		},
		want: "HTTP/1.1",
	}, {
		name:   "https server Protocols overrides empty TLSNextProto",
		scheme: "https",
		server: func(srv *Server) {
			// Explicitly enabling HTTP2 in the Protocols field takes precedence
			// over setting an empty TLSNextProto.
			srv.Protocols = &Protocols{}
			srv.Protocols.SetHTTP1(true)
			srv.Protocols.SetHTTP2(true)
			srv.TLSNextProto = map[string]func(*Server, *tls.Conn, Handler){}
		},
		want: "HTTP/2.0",
	}, {
		name:   "https server protocols only include HTTP1",
		scheme: "https",
		server: func(srv *Server) {
			srv.Protocols = &Protocols{}
			srv.Protocols.SetHTTP1(true)
		},
		want: "HTTP/1.1",
	}, {
		name:   "https server protocols include HTTP2",
		scheme: "https",
		server: func(srv *Server) {
			srv.Protocols = &Protocols{}
			srv.Protocols.SetHTTP1(true)
			srv.Protocols.SetHTTP2(true)
		},
		want: "HTTP/2.0",
	}, {
		name:   "GODEBUG disables HTTP2 client",
		scheme: "https",
		setup: func(t *testing.T) {
			t.Setenv("GODEBUG", "http2client=0")
		},
		transport: func(tr *Transport) {
			// Server default is to support HTTP/2, so if the Transport enables
			// HTTP/2 we get it.
			tr.Protocols = &Protocols{}
			tr.Protocols.SetHTTP1(true)
			tr.Protocols.SetHTTP2(true)
		},
		want: "HTTP/1.1",
	}, {
		name:   "GODEBUG disables HTTP2 server",
		scheme: "https",
		setup: func(t *testing.T) {
			t.Setenv("GODEBUG", "http2server=0")
		},
		transport: func(tr *Transport) {
			// Server default is to support HTTP/2, so if the Transport enables
			// HTTP/2 we get it.
			tr.Protocols = &Protocols{}
			tr.Protocols.SetHTTP1(true)
			tr.Protocols.SetHTTP2(true)
		},
		want: "HTTP/1.1",
	}, {
		name:   "unencrypted HTTP2 with prior knowledge",
		scheme: "http",
		transport: func(tr *Transport) {
			tr.Protocols = &Protocols{}
			tr.Protocols.SetUnencryptedHTTP2(true)
		},
		server: func(srv *Server) {
			srv.Protocols = &Protocols{}
			srv.Protocols.SetHTTP1(true)
			srv.Protocols.SetUnencryptedHTTP2(true)
		},
		want: "HTTP/2.0",
	}, {
		name:   "unencrypted HTTP2 only on server",
		scheme: "http",
		transport: func(tr *Transport) {
			tr.Protocols = &Protocols{}
			tr.Protocols.SetUnencryptedHTTP2(true)
		},
		server: func(srv *Server) {
			srv.Protocols = &Protocols{}
			srv.Protocols.SetUnencryptedHTTP2(true)
		},
		want: "HTTP/2.0",
	}, {
		name:   "unencrypted HTTP2 with no server support",
		scheme: "http",
		transport: func(tr *Transport) {
			tr.Protocols = &Protocols{}
			tr.Protocols.SetUnencryptedHTTP2(true)
		},
		server: func(srv *Server) {
			srv.Protocols = &Protocols{}
			srv.Protocols.SetHTTP1(true)
		},
		want: "error",
	}, {
		name:   "HTTP1 with no server support",
		scheme: "http",
		transport: func(tr *Transport) {
			tr.Protocols = &Protocols{}
			tr.Protocols.SetHTTP1(true)
		},
		server: func(srv *Server) {
			srv.Protocols = &Protocols{}
			srv.Protocols.SetUnencryptedHTTP2(true)
		},
		want: "error",
	}, {
		name:   "HTTPS1 with no server support",
		scheme: "https",
		transport: func(tr *Transport) {
			tr.Protocols = &Protocols{}
			tr.Protocols.SetHTTP1(true)
		},
		server: func(srv *Server) {
			srv.Protocols = &Protocols{}
			srv.Protocols.SetHTTP2(true)
		},
		want: "error",
	}} {
		t.Run(test.name, func(t *testing.T) {
			// We don't use httptest here because it makes its own decisions
			// about how to enable/disable HTTP/2.
			srv := &Server{
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
				},
				Handler: HandlerFunc(func(w ResponseWriter, req *Request) {
					w.Header().Set("X-Proto", req.Proto)
				}),
			}
			tr := &Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certpool,
				},
			}

			if test.setup != nil {
				test.setup(t)
			}
			if test.server != nil {
				test.server(srv)
			}
			if test.transport != nil {
				test.transport(tr)
			} else {
				tr.Protocols = &Protocols{}
				tr.Protocols.SetHTTP1(true)
				tr.Protocols.SetHTTP2(true)
			}

			listener := newLocalListener(t)
			srvc := make(chan error, 1)
			go func() {
				switch test.scheme {
				case "http":
					srvc <- srv.Serve(listener)
				case "https":
					srvc <- srv.ServeTLS(listener, "", "")
				}
			}()
			t.Cleanup(func() {
				srv.Close()
				<-srvc
			})

			client := &Client{Transport: tr}
			resp, err := client.Get(test.scheme + "://" + listener.Addr().String())
			if err != nil {
				if test.want == "error" {
					return
				}
				t.Fatal(err)
			}
			if got := resp.Header.Get("X-Proto"); got != test.want {
				t.Fatalf("request proto %q, want %q", got, test.want)
			}
		})
	}
}
```