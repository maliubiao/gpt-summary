Response:
Let's break down the thought process for analyzing this Go test file.

**1. Initial Scan and Understanding the Context:**

* **File Path:** `go/src/net/http/serve_test.go` immediately tells us this is a test file for the `net/http` package, specifically related to server-side functionalities. The `serve_` prefix likely indicates tests related to request handling and response generation within the HTTP server.
* **Test Functions:**  The presence of functions like `Test...` (`TestRequestBodyCancel`, `TestEarlyHints`, etc.) confirms it's a testing file. The names of these functions give hints about the specific features being tested.
* **Core Testing Structure:**  Many tests use a common pattern involving `newHandlerTest` or `newClientServerTest`. This suggests a setup where a test HTTP server is created to simulate interactions.
* **Keywords:**  Terms like `ResponseWriter`, `Request`, `Header`, `Body`, `StatusCode` point to core HTTP concepts.

**2. Analyzing Individual Test Functions (Iterative Process):**

For each `Test...` function, the thought process is similar:

* **Identify the Goal:** What specific HTTP behavior is this test trying to verify? Look at the handler function's logic and the assertions made in the test.
* **Understand the Handler Logic:**  What does the `HandlerFunc` do? Does it set headers? Write to the response body?  Does it introduce any delays or specific response codes?
* **Understand the Client Request:** How is the client making the request? What method is used? What headers are set? What body is sent?
* **Analyze the Assertions:** What checks are being performed on the response? Status code? Headers? Body content? Errors?
* **Look for Edge Cases or Specific Scenarios:** Are there any particular conditions being tested, like large request bodies, specific headers (e.g., `Expect: 100-continue`), or error conditions?

**Example: Analyzing `TestRequestBodyCancel`:**

1. **Goal:** The name suggests it's testing what happens when a client cancels a request body upload.
2. **Handler Logic:** The handler reads the request body in chunks and simulates a delay. It tracks the amount of data received. It also echoes back the received data.
3. **Client Request:** A `POST` request is made with a large body. The `GetBody` function is set up to simulate a cancellable reader.
4. **Assertions:** The test verifies:
    * The handler received less than the full body.
    * The handler did not encounter an error during the early cancellation.
    * The echoed response reflects the amount of data received by the handler.
5. **Specific Scenario:** The use of `Closer` with a `sync.WaitGroup` is a key detail. This simulates closing the request body prematurely.

**3. Identifying Common Themes and Go Features:**

As you analyze multiple test functions, patterns emerge:

* **Testing HTTP Handlers:**  The core functionality being tested is how HTTP handlers behave in various scenarios.
* **Request Body Handling:** Several tests focus on reading and processing the request body (e.g., `TestRequestBodyCancel`, `TestPostMaxSizeHandler`, `testHeadBody`).
* **Response Headers:** Tests like `TestEarlyHints` and `TestDisableContentLength` focus on setting and manipulating response headers.
* **Status Codes:**  Tests check for specific status codes like `StatusEarlyHints` (103) and `StatusProcessing` (102).
* **Multipart Forms:** `TestParseFormCleanup` deals with handling file uploads using multipart forms.
* **100 Continue:** Tests like `TestServerReadAfterWriteHeader100Continue` explore the "Expect: 100-continue" mechanism.
* **Go Concurrency:**  The use of `sync.WaitGroup` in `TestRequestBodyCancel` and goroutines in `TestServerReadAfterHandlerDone100Continue` highlights the concurrent nature of Go's HTTP server.
* **Go Interfaces:** The use of `io.Reader` and `io.Closer` are common, reflecting Go's emphasis on interfaces for abstraction.

**4. Inferring Go Feature Implementations:**

Based on the tests, you can infer which Go features are being exercised:

* **`http.HandlerFunc`:** Used to create simple HTTP handlers.
* **`http.ResponseWriter`:**  The interface for writing HTTP responses.
* **`http.Request`:** The struct representing an HTTP request.
* **`http.NewRequest`:**  Creating new HTTP request objects.
* **`http.Client`:** Making HTTP requests.
* **`httptest.NewServer`:**  Creating temporary test HTTP servers.
* **`multipart` package:** Handling multipart form data.
* **Status Code Constants:** Using constants like `http.StatusEarlyHints`.

**5. Addressing Specific Questions in the Prompt:**

* **Function Listing:** This involves summarizing the purpose of each `Test...` function.
* **Go Feature Implementation:**  Provide code examples demonstrating the inferred Go features (as done in the prompt's desired output).
* **Code Reasoning with Input/Output:**  For tests with more complex logic (like `TestRequestBodyCancel`), describe the expected behavior with a given input and the observed output/assertions.
* **Command Line Arguments:**  In this specific code snippet, there's no direct interaction with command-line arguments. If there were, you'd analyze how `flag` or similar packages are used.
* **Common Mistakes:**  Think about potential pitfalls when using the tested features. For example, with `ParseMultipartForm`, not handling temporary files correctly can lead to issues.
* **Overall Functionality (for the final part):**  Synthesize the individual test functionalities into a broader description of what the file tests.

**Self-Correction/Refinement during the process:**

* **Initial Misinterpretations:** You might initially misinterpret the purpose of a test. Rereading the code and assertions will help correct this.
* **Missing Details:**  You might initially overlook certain aspects, like the `ExpectContinueTimeout` in some tests. Careful examination of the setup code is necessary.
* **Clarity of Explanation:**  Ensure your explanations are clear and concise, especially when describing code logic and test scenarios.

By following this structured approach, you can effectively analyze and understand the functionality of Go test files like the one provided.
这是 `go/src/net/http/serve_test.go` 文件的一部分，它专注于测试 `net/http` 包中与 **HTTP 服务器请求处理和响应生成**相关的特定功能。由于这是第 7 部分，也是最后一部分，我们需要总结整个文件的功能。

**归纳一下 `go/src/net/http/serve_test.go` 的功能:**

总的来说，这个测试文件旨在全面测试 `net/http` 包中 HTTP 服务器的核心行为和各种边缘情况。它涵盖了请求的接收、处理、以及响应的生成和发送过程。  它通过模拟客户端请求并断言服务器的响应是否符合预期来验证 `net/http` 包的正确性。

**更具体地，从提供的代码片段来看，它测试了以下功能：**

1. **请求体取消 (Request Body Cancellation):** 测试客户端在上传请求体过程中取消请求时，服务器端的处理情况，以及是否能正确释放资源。
2. **请求体大小限制 (Request Body Size Limit):** 测试服务器端对请求体大小的限制是否生效，以及超出限制时的处理情况。
3. **提前提示 (Early Hints):**  测试 HTTP/1.1 的 103 Early Hints 功能，验证服务器是否能正确发送提前提示响应头。
4. **处理中状态 (Processing Status):** 测试 HTTP 的 102 Processing 状态码的处理。
5. **`ParseForm` 清理 (ParseForm Cleanup):**  测试 `r.ParseMultipartForm` 在处理文件上传后，是否能正确清理临时文件。
6. **HEAD 和 GET 请求体处理 (HEAD and GET Body Handling):** 测试 `HEAD` 和 `GET` 请求方法在携带请求体时的服务器处理情况，以及能否正确读取请求体。
7. **禁用 Content-Length (Disable Content-Length):** 测试如何通过设置 `Content-Length` header 为 `nil` 来禁用服务器自动设置 `Content-Length` 响应头。
8. **错误处理中的 Content-Length (Error Content-Length):** 测试在使用 `Error` 函数返回错误响应时，`Content-Length` header 的处理方式。
9. **`Error` 函数 (Error Function):** 测试 `http.Error` 函数是否能正确设置响应状态码、`Content-Type` 和 `X-Content-Type-Options` 响应头。
10. **100 Continue 后的读取 (Read After 100 Continue):**  测试在客户端发送 `Expect: 100-continue` 后，服务器在发送 100 Continue 响应后读取请求体的行为，包括正常读取、处理完成和处理中止等场景。

**Go 语言功能实现示例:**

**1. 请求体取消 (Request Body Cancellation):**

```go
import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRequestBodyCancelExample(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, err := r.Body.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Println("Error reading body:", err)
		}
		fmt.Printf("Read %d bytes from request body\n", n)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("Received %d bytes", n)))
	})

	srv := &http.Server{Addr: ":8080", Handler: handler}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			t.Errorf("ListenAndServe error: %v", err)
		}
	}()
	defer srv.Close()
	time.Sleep(time.Millisecond * 100) // 等待服务器启动

	bodyString := strings.Repeat("A", 1024*10) // 10KB 的数据
	bodyReader := &cancelableReader{
		Reader: strings.NewReader(bodyString),
		cancel: make(chan struct{}),
	}

	req, err := http.NewRequest("POST", "http://localhost:8080", bodyReader)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	time.Sleep(time.Millisecond * 50) // 模拟客户端在发送一部分数据后取消
	close(bodyReader.cancel)

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println("Response from server:", string(respBody))
}

type cancelableReader struct {
	io.Reader
	cancel chan struct{}
	closed bool
}

func (r *cancelableReader) Read(p []byte) (n int, err error) {
	select {
	case <-r.cancel:
		if !r.closed {
			fmt.Println("Request body cancelled by client")
			r.closed = true
			return 0, io.ErrUnexpectedEOF // 或者其他合适的错误
		}
		return 0, io.EOF
	default:
		return r.Reader.Read(p)
	}
}
```

**假设的输入与输出:**

**输入:** 客户端发送一个包含 10KB 数据的 POST 请求，但在发送一部分数据后取消了请求。

**输出:** 服务器端可能会输出类似 `Read [小于 10240 的值] bytes from request body` 的信息，并且响应体可能指示接收到的字节数少于 10KB。  客户端可能会收到一个错误，例如 `io.ErrUnexpectedEOF`，取决于服务器端的具体实现和网络情况。

**2. 提前提示 (Early Hints):**

```go
import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEarlyHintsExample(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello, world!")
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// 注意：标准的 http.Client 默认不会处理 1xx 状态码的响应。
	// 需要更底层的机制或者特定的库来捕获 Early Hints 响应。
	fmt.Println("Response Status:", resp.Status)
	// ... 更复杂的逻辑来检查是否收到了 Early Hints ...
}
```

**假设的输入与输出:**

**输入:** 客户端发送一个 GET 请求到服务器。

**输出:** 服务器应该首先发送一个 HTTP/1.1 103 Early Hints 响应，包含 `Link` header。 随后发送 HTTP/1.1 200 OK 响应，包含 "Hello, world!"。  但是，使用标准的 `http.Client` 可能无法直接捕获到 103 响应。

**命令行参数处理:**

在这个代码片段中，没有直接涉及到命令行参数的处理。 `net/http` 包本身负责处理 HTTP 协议的细节，包括解析请求行和头部。 如果涉及到自定义服务器配置，可能会使用 `flag` 包或其他方式来处理命令行参数，但这不在这个测试文件的范围内。

**使用者易犯错的点 (基于提供的代码片段):**

1. **在发送包含 `Expect: 100-continue` 的请求后，没有正确处理 100 Continue 响应。**  客户端需要等待服务器发送 100 Continue 状态码后，再继续发送请求体。 如果服务器没有发送 100 Continue，客户端可能会超时或者发送失败。

   ```go
   // 错误的示例
   req, _ := http.NewRequest("POST", "http://example.com", strings.NewReader("request body"))
   req.Header.Set("Expect", "100-continue")
   resp, err := client.Do(req) // 可能会立即发送请求体，导致问题
   ```

   **正确的做法需要更复杂的逻辑来处理 100 Continue 响应。**

2. **错误地认为标准的 `http.Client` 会自动处理所有 1xx 状态码，例如 Early Hints。**  需要使用更底层的机制或者特定的库来捕获和处理这些中间响应。

**总结第 7 部分的功能:**

提供的代码片段主要测试了以下几个关键的 HTTP 服务器功能：

* **请求体的处理和取消:** 确保服务器能够优雅地处理客户端中断的请求。
* **提前提示 (Early Hints):** 验证服务器是否支持并能正确发送 103 Early Hints 响应。
* **处理中状态 (Processing):** 测试服务器发送 102 Processing 状态码的能力。
* **资源清理:** 确保服务器在处理请求后能正确清理资源，例如临时文件。
* **不同请求方法下的请求体处理:** 测试 `HEAD` 和 `GET` 请求在携带请求体时的处理。
* **响应头的控制:**  验证禁用默认 `Content-Length` 响应头的功能。
* **错误响应的生成:** 测试 `http.Error` 函数的正确性。
* **`Expect: 100-continue` 的处理:**  测试服务器在处理包含 `Expect: 100-continue` 的请求时的行为，包括发送 100 Continue 响应后读取请求体。

由于这是最后一部分，结合之前几部分的内容，整个 `go/src/net/http/serve_test.go` 文件旨在对 `net/http` 包的 HTTP 服务器功能进行全面和细致的测试，覆盖了请求处理的各个方面，包括请求头的解析、请求体的读取、响应头的生成、错误处理以及各种边缘情况。

Prompt: 
```
这是路径为go/src/net/http/serve_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共7部分，请归纳一下它的功能

"""
Closer{
				Reader: strings.NewReader(body),
				wg:     &wg,
			}
			return body, nil
		}
		reqBody, _ := getBody()
		req, err := NewRequest("POST", ts.URL, reqBody)
		if err != nil {
			reqBody.Close()
			t.Fatal(err)
		}
		req.ContentLength = int64(len(body))
		req.GetBody = getBody
		req.Header.Set("Content-Type", "text/plain")

		var buf strings.Builder
		res, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("unexpected connection error: %v", err)
		} else {
			_, err = io.Copy(&buf, res.Body)
			res.Body.Close()
			if err != nil {
				return fmt.Errorf("unexpected read error: %v", err)
			}
		}
		// We don't expect any of the errors after this point to occur due
		// to rstAvoidanceDelay being too short, so we use t.Errorf for those
		// instead of returning a (retriable) error.

		if handlerN > maxSize {
			t.Errorf("expected max request body %d; got %d", maxSize, handlerN)
		}
		if requestSize > maxSize && handlerErr == nil {
			t.Error("expected error on handler side; got nil")
		}
		if requestSize <= maxSize {
			if handlerErr != nil {
				t.Errorf("%d expected nil error on handler side; got %v", requestSize, handlerErr)
			}
			if handlerN != requestSize {
				t.Errorf("expected request of size %d; got %d", requestSize, handlerN)
			}
		}
		if buf.Len() != int(handlerN) {
			t.Errorf("expected echo of size %d; got %d", handlerN, buf.Len())
		}

		return nil
	})
}

func TestEarlyHints(t *testing.T) {
	ht := newHandlerTest(HandlerFunc(func(w ResponseWriter, r *Request) {
		h := w.Header()
		h.Add("Link", "</style.css>; rel=preload; as=style")
		h.Add("Link", "</script.js>; rel=preload; as=script")
		w.WriteHeader(StatusEarlyHints)

		h.Add("Link", "</foo.js>; rel=preload; as=script")
		w.WriteHeader(StatusEarlyHints)

		w.Write([]byte("stuff"))
	}))

	got := ht.rawResponse("GET / HTTP/1.1\nHost: golang.org")
	expected := "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\nLink: </script.js>; rel=preload; as=script\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\nLink: </script.js>; rel=preload; as=script\r\nLink: </foo.js>; rel=preload; as=script\r\n\r\nHTTP/1.1 200 OK\r\nLink: </style.css>; rel=preload; as=style\r\nLink: </script.js>; rel=preload; as=script\r\nLink: </foo.js>; rel=preload; as=script\r\nDate: " // dynamic content expected
	if !strings.Contains(got, expected) {
		t.Errorf("unexpected response; got %q; should start by %q", got, expected)
	}
}
func TestProcessing(t *testing.T) {
	ht := newHandlerTest(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusProcessing)
		w.Write([]byte("stuff"))
	}))

	got := ht.rawResponse("GET / HTTP/1.1\nHost: golang.org")
	expected := "HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nDate: " // dynamic content expected
	if !strings.Contains(got, expected) {
		t.Errorf("unexpected response; got %q; should start by %q", got, expected)
	}
}

func TestParseFormCleanup(t *testing.T) { run(t, testParseFormCleanup) }
func testParseFormCleanup(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("https://go.dev/issue/20253")
	}

	const maxMemory = 1024
	const key = "file"

	if runtime.GOOS == "windows" {
		// Windows sometimes refuses to remove a file that was just closed.
		t.Skip("https://go.dev/issue/25965")
	}

	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		r.ParseMultipartForm(maxMemory)
		f, _, err := r.FormFile(key)
		if err != nil {
			t.Errorf("r.FormFile(%q) = %v", key, err)
			return
		}
		of, ok := f.(*os.File)
		if !ok {
			t.Errorf("r.FormFile(%q) returned type %T, want *os.File", key, f)
			return
		}
		w.Write([]byte(of.Name()))
	}))

	fBuf := new(bytes.Buffer)
	mw := multipart.NewWriter(fBuf)
	mf, err := mw.CreateFormFile(key, "myfile.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mf.Write(bytes.Repeat([]byte("A"), maxMemory*2)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := NewRequest("POST", cst.ts.URL, fBuf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	fname, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	cst.close()
	if _, err := os.Stat(string(fname)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file %q exists after HTTP handler returned", string(fname))
	}
}

func TestHeadBody(t *testing.T) {
	const identityMode = false
	const chunkedMode = true
	run(t, func(t *testing.T, mode testMode) {
		t.Run("identity", func(t *testing.T) { testHeadBody(t, mode, identityMode, "HEAD") })
		t.Run("chunked", func(t *testing.T) { testHeadBody(t, mode, chunkedMode, "HEAD") })
	})
}

func TestGetBody(t *testing.T) {
	const identityMode = false
	const chunkedMode = true
	run(t, func(t *testing.T, mode testMode) {
		t.Run("identity", func(t *testing.T) { testHeadBody(t, mode, identityMode, "GET") })
		t.Run("chunked", func(t *testing.T) { testHeadBody(t, mode, chunkedMode, "GET") })
	})
}

func testHeadBody(t *testing.T, mode testMode, chunked bool, method string) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("server reading body: %v", err)
			return
		}
		w.Header().Set("X-Request-Body", string(b))
		w.Header().Set("Content-Length", "0")
	}))
	defer cst.close()
	for _, reqBody := range []string{
		"",
		"",
		"request_body",
		"",
	} {
		var bodyReader io.Reader
		if reqBody != "" {
			bodyReader = strings.NewReader(reqBody)
			if chunked {
				bodyReader = bufio.NewReader(bodyReader)
			}
		}
		req, err := NewRequest(method, cst.ts.URL, bodyReader)
		if err != nil {
			t.Fatal(err)
		}
		res, err := cst.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if got, want := res.StatusCode, 200; got != want {
			t.Errorf("%v request with %d-byte body: StatusCode = %v, want %v", method, len(reqBody), got, want)
		}
		if got, want := res.Header.Get("X-Request-Body"), reqBody; got != want {
			t.Errorf("%v request with %d-byte body: handler read body %q, want %q", method, len(reqBody), got, want)
		}
	}
}

// TestDisableContentLength verifies that the Content-Length is set by default
// or disabled when the header is set to nil.
func TestDisableContentLength(t *testing.T) { run(t, testDisableContentLength) }
func testDisableContentLength(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("skipping until h2_bundle.go is updated; see https://go-review.googlesource.com/c/net/+/471535")
	}

	noCL := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header()["Content-Length"] = nil // disable the default Content-Length response
		fmt.Fprintf(w, "OK")
	}))

	res, err := noCL.c.Get(noCL.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got, haveCL := res.Header["Content-Length"]; haveCL {
		t.Errorf("Unexpected Content-Length: %q", got)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}

	withCL := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "OK")
	}))

	res, err = withCL.c.Get(withCL.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Header.Get("Content-Length"); got != "2" {
		t.Errorf("Content-Length: %q; want 2", got)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestErrorContentLength(t *testing.T) { run(t, testErrorContentLength) }
func testErrorContentLength(t *testing.T, mode testMode) {
	const errorBody = "an error occurred"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "1000")
		Error(w, errorBody, 400)
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatalf("Get(%q) = %v", cst.ts.URL, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(res.Body) = %v", err)
	}
	if string(body) != errorBody+"\n" {
		t.Fatalf("read body: %q, want %q", string(body), errorBody)
	}
}

func TestError(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Length", "1")
	w.Header().Set("X-Content-Type-Options", "scratch and sniff")
	w.Header().Set("Other", "foo")
	Error(w, "oops", 432)

	h := w.Header()
	for _, hdr := range []string{"Content-Length"} {
		if v, ok := h[hdr]; ok {
			t.Errorf("%s: %q, want not present", hdr, v)
		}
	}
	if v := h.Get("Content-Type"); v != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type: %q, want %q", v, "text/plain; charset=utf-8")
	}
	if v := h.Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("X-Content-Type-Options: %q, want %q", v, "nosniff")
	}
}

func TestServerReadAfterWriteHeader100Continue(t *testing.T) {
	run(t, testServerReadAfterWriteHeader100Continue)
}
func testServerReadAfterWriteHeader100Continue(t *testing.T, mode testMode) {
	t.Skip("https://go.dev/issue/67555")
	body := []byte("body")
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(200)
		NewResponseController(w).Flush()
		io.ReadAll(r.Body)
		w.Write(body)
	}), func(tr *Transport) {
		tr.ExpectContinueTimeout = 24 * time.Hour // forever
	})

	req, _ := NewRequest("GET", cst.ts.URL, strings.NewReader("body"))
	req.Header.Set("Expect", "100-continue")
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatalf("Get(%q) = %v", cst.ts.URL, err)
	}
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(res.Body) = %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("response body = %q, want %q", got, body)
	}
}

func TestServerReadAfterHandlerDone100Continue(t *testing.T) {
	run(t, testServerReadAfterHandlerDone100Continue)
}
func testServerReadAfterHandlerDone100Continue(t *testing.T, mode testMode) {
	t.Skip("https://go.dev/issue/67555")
	readyc := make(chan struct{})
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		go func() {
			<-readyc
			io.ReadAll(r.Body)
			<-readyc
		}()
	}), func(tr *Transport) {
		tr.ExpectContinueTimeout = 24 * time.Hour // forever
	})

	req, _ := NewRequest("GET", cst.ts.URL, strings.NewReader("body"))
	req.Header.Set("Expect", "100-continue")
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatalf("Get(%q) = %v", cst.ts.URL, err)
	}
	res.Body.Close()
	readyc <- struct{}{} // server starts reading from the request body
	readyc <- struct{}{} // server finishes reading from the request body
}

func TestServerReadAfterHandlerAbort100Continue(t *testing.T) {
	run(t, testServerReadAfterHandlerAbort100Continue)
}
func testServerReadAfterHandlerAbort100Continue(t *testing.T, mode testMode) {
	t.Skip("https://go.dev/issue/67555")
	readyc := make(chan struct{})
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		go func() {
			<-readyc
			io.ReadAll(r.Body)
			<-readyc
		}()
		panic(ErrAbortHandler)
	}), func(tr *Transport) {
		tr.ExpectContinueTimeout = 24 * time.Hour // forever
	})

	req, _ := NewRequest("GET", cst.ts.URL, strings.NewReader("body"))
	req.Header.Set("Expect", "100-continue")
	res, err := cst.c.Do(req)
	if err == nil {
		res.Body.Close()
	}
	readyc <- struct{}{} // server starts reading from the request body
	readyc <- struct{}{} // server finishes reading from the request body
}

"""




```