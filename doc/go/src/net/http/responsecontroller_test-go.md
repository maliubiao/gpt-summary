Response:
Let's break down the thought process for analyzing this Go code.

**1. Initial Understanding: The Goal**

The first thing to do is understand the *purpose* of the code. The filename `responsecontroller_test.go` and the package `http_test` strongly suggest this is testing functionality related to controlling HTTP responses in Go's `net/http` package. The names of the test functions (e.g., `TestResponseControllerFlush`) give further hints about the specific aspects being tested.

**2. Identifying Key Components:**

Next, identify the core types and functions being used. Scanning the imports reveals:

* `. "net/http"`: This is the main target of the tests. The dot import means we're directly using types and functions from this package without the `http.` prefix. We'll be looking for things like `ResponseWriter`, `Request`, `HandlerFunc`, and especially `NewResponseController`.
* `"testing"`:  Standard Go testing library.
* `"time"`: For dealing with deadlines.
* `"io"`: For input/output operations, especially `io.Copy`, `io.ReadAll`, and `io.Pipe`.
* `"errors"`: For checking error types.
* `"os"`: Specifically for `os.ErrDeadlineExceeded`.
* `"sync"`: For synchronization primitives like `sync.WaitGroup`.
* `"fmt"`: For formatted output, mainly in the `Hijack` test.

The key function that stands out is `NewResponseController(w ResponseWriter)`. This strongly implies the code is testing the behavior of an object that *controls* the response being written.

**3. Analyzing Individual Test Functions:**

Now, go through each `Test...` function and its corresponding `test...` helper function. For each test:

* **Identify the Action:** What specific method of `ResponseController` is being tested? (e.g., `Flush`, `Hijack`, `SetWriteDeadline`, `SetReadDeadline`, `EnableFullDuplex`).
* **Understand the Setup:** How is the test environment created?  Look for `newClientServerTest`, which sets up a local HTTP server and client. This is a common pattern for integration testing HTTP functionality.
* **Trace the Server-Side Logic:** What does the `HandlerFunc` do? This is where the `ResponseController` methods are actually called.
* **Trace the Client-Side Logic:** How does the client interact with the server? What requests are made, and what responses are expected?
* **Identify Assertions:** What checks are performed using `t.Errorf`, `t.Fatalf`, etc.?  These tell us what the expected behavior is.

**Example Breakdown (for `TestResponseControllerFlush`):**

1. **Action:** Testing `ctl.Flush()`.
2. **Setup:** `newClientServerTest` creates a server and client.
3. **Server Logic:**
   * `NewResponseController(w)` gets a controller.
   * `w.Write([]byte("one"))` writes some initial data.
   * `ctl.Flush()` is called. *Hypothesis: This likely sends the currently buffered data to the client.*
   * `<-continuec` waits for a signal from the client.
   * `w.Write([]byte("two"))` writes more data.
4. **Client Logic:**
   * `cst.c.Get(cst.ts.URL)` makes a GET request.
   * `res.Body.Read(buf)` reads from the response.
   * `close(continuec)` signals the server to continue.
   * `io.ReadAll(res.Body)` reads the rest of the response.
5. **Assertions:**
   * Checks that the first read gets "one".
   * Checks that the second read gets "two".

**4. Inferring Functionality:**

Based on the tests, we can start to infer the behavior of `ResponseController`:

* **`Flush()`:** Sends buffered data immediately. This allows for sending partial responses.
* **`Hijack()`:** Takes over the connection, allowing raw socket manipulation (HTTP/1.1). Fails in HTTP/2 because the connection model is different.
* **`SetWriteDeadline()`:** Sets a timeout for sending data.
* **`SetReadDeadline()`:** Sets a timeout for receiving data from the client.
* **`EnableFullDuplex()`:**  Attempts to enable bidirectional communication on the connection (fails in HTTP/2).

**5. Code Examples and Reasoning:**

Once the functionality is understood, create simple code examples to demonstrate how these methods are used. The examples should align with the scenarios tested in the code. Explain the *why* behind the code – how the `ResponseController` methods affect the request/response flow.

**6. Command-Line Arguments and Error Handling:**

This specific code doesn't show explicit handling of command-line arguments. The `testMode` parameter suggests that the tests might be run in different modes (like HTTP/1.1 and HTTP/2), but this is likely controlled by the testing framework itself, not command-line arguments within this file.

Regarding error handling, the tests explicitly check for expected errors (e.g., when setting past deadlines or when `Hijack` fails in HTTP/2).

**7. Common Mistakes:**

Think about how developers might misuse these features. For example:

* Forgetting to `Flush()` when wanting to send partial data.
* Trying to `Hijack()` in HTTP/2.
* Not understanding the stickiness of deadline errors.

**8. Structuring the Answer:**

Finally, organize the findings into a clear and comprehensive answer, following the prompt's structure:

* **功能 (Features):** List the inferred functionalities.
* **Go 代码举例 (Go Code Examples):** Provide illustrative code snippets with explanations, assumptions, and expected outputs.
* **代码推理 (Code Reasoning):** Explain the logic behind the test cases, showing how they validate the functionality.
* **命令行参数 (Command-Line Arguments):** State that no explicit command-line handling is present in this file.
* **易犯错的点 (Common Mistakes):** List potential pitfalls for developers using these features.

By following this systematic approach, you can effectively analyze and understand the functionality of complex Go code, even without prior knowledge of the specific package being tested. The key is to break it down into smaller, manageable parts and focus on understanding the purpose and behavior of each component.
这段Go语言代码是 `net/http` 包的一部分，专门用于测试 `ResponseController` 的功能。`ResponseController` 提供了一种更细粒度地控制HTTP响应的方式，允许在标准的 `ResponseWriter` 接口之上进行额外的操作，例如手动刷新缓冲区、劫持连接、设置读写截止时间以及启用全双工通信。

以下是这段代码中各个测试函数的功能：

**1. `TestResponseControllerFlush` 和 `testResponseControllerFlush`:**

* **功能:** 测试 `ResponseController` 的 `Flush()` 方法。`Flush()` 方法用于将任何缓冲的响应数据立即发送到客户端。
* **Go 代码举例:**
```go
package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctl := http.NewResponseController(w)
	w.Write([]byte("第一部分内容"))
	ctl.Flush() // 立即发送 "第一部分内容"
	fmt.Println("第一部分内容已发送")
	// 模拟一些耗时操作
	// ...
	w.Write([]byte("第二部分内容"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
```
* **假设的输入与输出:**
    * **客户端请求:**  访问 `http://localhost:8080/`
    * **服务器输出 (控制台):**
      ```
      第一部分内容已发送
      ```
    * **客户端接收的响应:**  客户端会先接收到 "第一部分内容"，然后在一段时间后接收到 "第二部分内容"。
* **代码推理:** 测试用例中，服务器先写入 "one"，然后调用 `Flush()`，客户端应该能立即读取到 "one"。之后服务器继续写入 "two"，客户端读取剩余部分。

**2. `TestResponseControllerHijack` 和 `testResponseControllerHijack`:**

* **功能:** 测试 `ResponseController` 的 `Hijack()` 方法。`Hijack()` 方法允许接管HTTP连接，不再使用 `ResponseWriter`，而是直接操作底层的 `net.Conn`。这通常用于实现WebSocket等协议。
* **Go 代码举例:**
```go
package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctl := http.NewResponseController(w)
	conn, _, err := ctl.Hijack()
	if err != nil {
		fmt.Println("劫持连接失败:", err)
		return
	}
	defer conn.Close()
	fmt.Fprint(conn, "HTTP/1.0 200 OK\r\nX-Custom-Header: hijacked\r\nContent-Length: 10\r\n\r\nHello World")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
```
* **假设的输入与输出:**
    * **客户端请求:**  访问 `http://localhost:8080/`
    * **客户端接收的响应 (Header):**
      ```
      HTTP/1.0 200 OK
      X-Custom-Header: hijacked
      Content-Length: 10
      ```
    * **客户端接收的响应 (Body):**
      ```
      Hello World
      ```
* **代码推理:** 测试用例中，服务器调用 `Hijack()` 接管连接，并手动构造HTTP响应头和内容发送到客户端。需要注意的是，在HTTP/2模式下，`Hijack()` 通常会返回错误，因为HTTP/2的连接管理方式不同。

**3. `TestResponseControllerSetPastWriteDeadline` 和 `testResponseControllerSetPastWriteDeadline`:**

* **功能:** 测试 `ResponseController` 的 `SetWriteDeadline()` 方法，当设置的截止时间是过去的时间时会发生什么。`SetWriteDeadline()` 用于设置写入操作的超时时间。
* **Go 代码推理:** 当设置了过去的写入截止时间后，后续的写入操作（例如 `Flush()`）应该会失败，因为已经超时。测试用例验证了即使重置截止时间，之前的错误状态也会持续存在（连接错误是“粘性的”）。

**4. `TestResponseControllerSetFutureWriteDeadline` 和 `testResponseControllerSetFutureWriteDeadline`:**

* **功能:** 测试 `ResponseController` 的 `SetWriteDeadline()` 方法，当设置的截止时间是未来的时间时会发生什么。
* **Go 代码推理:** 服务器在客户端读取响应头后设置一个很短的未来写入截止时间。然后尝试写入无限数据流。客户端读取响应体会因为服务器的写入超时而中断，并收到 `os.ErrDeadlineExceeded` 错误。

**5. `TestResponseControllerSetPastReadDeadline` 和 `testResponseControllerSetPastReadDeadline`:**

* **功能:** 测试 `ResponseController` 的 `SetReadDeadline()` 方法，当设置的截止时间是过去的时间时会发生什么。`SetReadDeadline()` 用于设置读取客户端请求体的超时时间。
* **Go 代码推理:** 服务器先正常读取一部分请求体，然后设置一个过去的读取截止时间。后续的读取操作应该会失败。测试用例也验证了重置读取截止时间后，之前的错误状态仍然存在。

**6. `TestResponseControllerSetFutureReadDeadline` 和 `testResponseControllerSetFutureReadDeadline`:**

* **功能:** 测试 `ResponseController` 的 `SetReadDeadline()` 方法，当设置的截止时间是未来的时间时会发生什么。
* **Go 代码推理:** 服务器设置一个很短的未来读取截止时间，然后尝试从请求体中读取数据。由于超时，读取操作会返回 `os.ErrDeadlineExceeded` 错误。但服务器仍然能够正常写入响应体并发送给客户端。

**7. `TestWrappedResponseController` 和 `testWrappedResponseController`:**

* **功能:** 测试当 `ResponseWriter` 被包装（wrapped）后，`ResponseController` 是否仍然能够正常工作。
* **Go 代码推理:** 这个测试用例创建了一个简单的包装器 `wrapWriter`，它实现了 `Unwrap()` 方法。测试用例验证了即使 `ResponseWriter` 被包装，`ResponseController` 的 `Flush()`, `SetReadDeadline()`, 和 `SetWriteDeadline()` 方法仍然可以调用且不会出错。这表明 `ResponseController` 能够处理实现了 `http.ResponseWriter` 和可选的 `http.Hijacker` 接口的包装器。

**8. `TestResponseControllerEnableFullDuplex` 和 `testResponseControllerEnableFullDuplex`:**

* **功能:** 测试 `ResponseController` 的 `EnableFullDuplex()` 方法。`EnableFullDuplex()` 尝试启用HTTP连接的全双工模式，允许在服务器发送响应的同时接收客户端的请求数据。
* **Go 代码推理:** 服务器调用 `EnableFullDuplex()`。在HTTP/1.x中，这通常需要升级协议（例如使用Upgrade头）。在HTTP/2中，全双工是默认行为。测试用例模拟了客户端发送数据，服务器接收并回显的场景。由于当前的 `x/net/http2` 库可能不支持 `EnableFullDuplex` 的完整功能，因此在HTTP/2模式下，该方法调用可能会失败，测试用例也考虑到了这一点。

**9. `TestIssue58237`:**

* **功能:**  这是一个针对特定issue（#58237）的回归测试。
* **Go 代码推理:**  该测试用例主要关注在HTTP/2模式下，设置一个很短的读取截止时间后，即使没有实际读取操作，连接是否能正常关闭而不会发生意外的错误或阻塞。

**涉及的 Go 语言功能实现：**

这段代码主要测试的是 `net/http` 包中与HTTP请求处理和响应控制相关的部分，特别是 `ResponseController` 提供的额外功能。它涵盖了以下 Go 语言功能：

* **HTTP 处理:** 使用 `http.HandlerFunc` 定义HTTP请求处理函数。
* **HTTP 客户端:** 使用 `http.Client` 发起HTTP请求。
* **HTTP 服务器:** 使用 `http.ListenAndServe` 启动HTTP服务器（在测试辅助函数 `newClientServerTest` 中）。
* **接口:** `http.ResponseWriter` 接口的实现和使用，以及 `http.Hijacker` 接口的潜在使用。
* **通道 (Channels):** 使用通道进行 Goroutine 间的同步和通信，例如 `continuec`, `errc`, `startwritec`, `readc`, `donec`。
* **Goroutines:** 使用 `go` 关键字启动并发执行的函数。
* **错误处理:** 使用 `error` 类型和 `errors.Is` 函数进行错误检查。
* **时间操作:** 使用 `time` 包进行时间相关的操作，例如设置截止时间。
* **IO 操作:** 使用 `io` 包进行输入输出操作，例如 `io.Copy`, `io.ReadAll`, `io.Pipe`。
* **同步:** 使用 `sync.WaitGroup` 等进行 Goroutine 的同步。

**命令行参数的具体处理:**

这段代码本身是测试代码，不涉及直接的命令行参数处理。测试框架（通常是 `go test` 命令）可能会接受一些参数来控制测试的执行，例如选择要运行的测试用例、设置超时时间等，但这不属于这段代码的职责。测试用例中的 `testMode` 参数是通过代码内部控制的，用于在不同的HTTP模式（例如 HTTP/1.1 和 HTTP/2）下运行测试。

**使用者易犯错的点：**

* **忘记调用 `Flush()`:**  当需要分段发送响应数据时，如果忘记调用 `Flush()`，客户端可能要等待所有数据都准备好后才能接收到。
    ```go
    func handler(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("准备发送第一部分..."))
        // 假设这里有一些耗时操作
        // w.Flush() // 容易忘记调用 Flush()
        w.Write([]byte("准备发送第二部分..."))
    }
    ```
    在这种情况下，客户端可能要等到 "准备发送第二部分..." 也写入完成后才能看到任何响应。

* **在 HTTP/2 中使用 `Hijack()`:**  `Hijack()` 方法在 HTTP/2 中通常不可用或没有意义，因为 HTTP/2 的连接管理方式与 HTTP/1.x 不同。尝试在 HTTP/2 中调用 `Hijack()` 可能会导致错误。
    ```go
    func handler(w http.ResponseWriter, r *http.Request) {
        ctl := http.NewResponseController(w)
        conn, _, err := ctl.Hijack() // 在 HTTP/2 中可能返回错误
        if err != nil {
            fmt.Println("Hijack 失败:", err)
            return
        }
        // ...
    }
    ```

* **不理解截止时间的粘性:**  一旦设置了过去的读或写截止时间并导致了错误，即使之后重置了截止时间，之前的错误状态可能仍然存在，需要重新建立连接或采取其他措施。

总而言之，这段测试代码全面地验证了 `net/http` 包中 `ResponseController` 的各项功能，确保其在不同的场景下都能按预期工作。它也揭示了在使用这些高级响应控制功能时需要注意的一些细节和潜在的陷阱。

Prompt: 
```
这是路径为go/src/net/http/responsecontroller_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http_test

import (
	"errors"
	"fmt"
	"io"
	. "net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func TestResponseControllerFlush(t *testing.T) { run(t, testResponseControllerFlush) }
func testResponseControllerFlush(t *testing.T, mode testMode) {
	continuec := make(chan struct{})
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ctl := NewResponseController(w)
		w.Write([]byte("one"))
		if err := ctl.Flush(); err != nil {
			t.Errorf("ctl.Flush() = %v, want nil", err)
			return
		}
		<-continuec
		w.Write([]byte("two"))
	}))

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatalf("unexpected connection error: %v", err)
	}
	defer res.Body.Close()

	buf := make([]byte, 16)
	n, err := res.Body.Read(buf)
	close(continuec)
	if err != nil || string(buf[:n]) != "one" {
		t.Fatalf("Body.Read = %q, %v, want %q, nil", string(buf[:n]), err, "one")
	}

	got, err := io.ReadAll(res.Body)
	if err != nil || string(got) != "two" {
		t.Fatalf("Body.Read = %q, %v, want %q, nil", string(got), err, "two")
	}
}

func TestResponseControllerHijack(t *testing.T) { run(t, testResponseControllerHijack) }
func testResponseControllerHijack(t *testing.T, mode testMode) {
	const header = "X-Header"
	const value = "set"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ctl := NewResponseController(w)
		c, _, err := ctl.Hijack()
		if mode == http2Mode {
			if err == nil {
				t.Errorf("ctl.Hijack = nil, want error")
			}
			w.Header().Set(header, value)
			return
		}
		if err != nil {
			t.Errorf("ctl.Hijack = _, _, %v, want _, _, nil", err)
			return
		}
		fmt.Fprintf(c, "HTTP/1.0 200 OK\r\n%v: %v\r\nContent-Length: 0\r\n\r\n", header, value)
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := res.Header.Get(header), value; got != want {
		t.Errorf("response header %q = %q, want %q", header, got, want)
	}
}

func TestResponseControllerSetPastWriteDeadline(t *testing.T) {
	run(t, testResponseControllerSetPastWriteDeadline)
}
func testResponseControllerSetPastWriteDeadline(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ctl := NewResponseController(w)
		w.Write([]byte("one"))
		if err := ctl.Flush(); err != nil {
			t.Errorf("before setting deadline: ctl.Flush() = %v, want nil", err)
		}
		if err := ctl.SetWriteDeadline(time.Now().Add(-10 * time.Second)); err != nil {
			t.Errorf("ctl.SetWriteDeadline() = %v, want nil", err)
		}

		w.Write([]byte("two"))
		if err := ctl.Flush(); err == nil {
			t.Errorf("after setting deadline: ctl.Flush() = nil, want non-nil")
		}
		// Connection errors are sticky, so resetting the deadline does not permit
		// making more progress. We might want to change this in the future, but verify
		// the current behavior for now. If we do change this, we'll want to make sure
		// to do so only for writing the response body, not headers.
		if err := ctl.SetWriteDeadline(time.Now().Add(1 * time.Hour)); err != nil {
			t.Errorf("ctl.SetWriteDeadline() = %v, want nil", err)
		}
		w.Write([]byte("three"))
		if err := ctl.Flush(); err == nil {
			t.Errorf("after resetting deadline: ctl.Flush() = nil, want non-nil")
		}
	}))

	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatalf("unexpected connection error: %v", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if string(b) != "one" {
		t.Errorf("unexpected body: %q", string(b))
	}
}

func TestResponseControllerSetFutureWriteDeadline(t *testing.T) {
	run(t, testResponseControllerSetFutureWriteDeadline)
}
func testResponseControllerSetFutureWriteDeadline(t *testing.T, mode testMode) {
	errc := make(chan error, 1)
	startwritec := make(chan struct{})
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		ctl := NewResponseController(w)
		w.WriteHeader(200)
		if err := ctl.Flush(); err != nil {
			t.Errorf("ctl.Flush() = %v, want nil", err)
		}
		<-startwritec // don't set the deadline until the client reads response headers
		if err := ctl.SetWriteDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
			t.Errorf("ctl.SetWriteDeadline() = %v, want nil", err)
		}
		_, err := io.Copy(w, neverEnding('a'))
		errc <- err
	}))

	res, err := cst.c.Get(cst.ts.URL)
	close(startwritec)
	if err != nil {
		t.Fatalf("unexpected connection error: %v", err)
	}
	defer res.Body.Close()
	_, err = io.Copy(io.Discard, res.Body)
	if err == nil {
		t.Errorf("client reading from truncated request body: got nil error, want non-nil")
	}
	err = <-errc // io.Copy error
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("server timed out writing request body: got err %v; want os.ErrDeadlineExceeded", err)
	}
}

func TestResponseControllerSetPastReadDeadline(t *testing.T) {
	run(t, testResponseControllerSetPastReadDeadline)
}
func testResponseControllerSetPastReadDeadline(t *testing.T, mode testMode) {
	readc := make(chan struct{})
	donec := make(chan struct{})
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		defer close(donec)
		ctl := NewResponseController(w)
		b := make([]byte, 3)
		n, err := io.ReadFull(r.Body, b)
		b = b[:n]
		if err != nil || string(b) != "one" {
			t.Errorf("before setting read deadline: Read = %v, %q, want nil, %q", err, string(b), "one")
			return
		}
		if err := ctl.SetReadDeadline(time.Now()); err != nil {
			t.Errorf("ctl.SetReadDeadline() = %v, want nil", err)
			return
		}
		b, err = io.ReadAll(r.Body)
		if err == nil || string(b) != "" {
			t.Errorf("after setting read deadline: Read = %q, nil, want error", string(b))
		}
		close(readc)
		// Connection errors are sticky, so resetting the deadline does not permit
		// making more progress. We might want to change this in the future, but verify
		// the current behavior for now.
		if err := ctl.SetReadDeadline(time.Time{}); err != nil {
			t.Errorf("ctl.SetReadDeadline() = %v, want nil", err)
			return
		}
		b, err = io.ReadAll(r.Body)
		if err == nil {
			t.Errorf("after resetting read deadline: Read = %q, nil, want error", string(b))
		}
	}))

	pr, pw := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer pw.Close()
		pw.Write([]byte("one"))
		select {
		case <-readc:
		case <-donec:
			select {
			case <-readc:
			default:
				t.Errorf("server handler unexpectedly exited without closing readc")
				return
			}
		}
		pw.Write([]byte("two"))
	}()
	defer wg.Wait()
	res, err := cst.c.Post(cst.ts.URL, "text/foo", pr)
	if err == nil {
		defer res.Body.Close()
	}
}

func TestResponseControllerSetFutureReadDeadline(t *testing.T) {
	run(t, testResponseControllerSetFutureReadDeadline)
}
func testResponseControllerSetFutureReadDeadline(t *testing.T, mode testMode) {
	respBody := "response body"
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, req *Request) {
		ctl := NewResponseController(w)
		if err := ctl.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
			t.Errorf("ctl.SetReadDeadline() = %v, want nil", err)
		}
		_, err := io.Copy(io.Discard, req.Body)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("server timed out reading request body: got err %v; want os.ErrDeadlineExceeded", err)
		}
		w.Write([]byte(respBody))
	}))
	pr, pw := io.Pipe()
	res, err := cst.c.Post(cst.ts.URL, "text/apocryphal", pr)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if string(got) != respBody || err != nil {
		t.Errorf("client read response body: %q, %v; want %q, nil", string(got), err, respBody)
	}
	pw.Close()
}

type wrapWriter struct {
	ResponseWriter
}

func (w wrapWriter) Unwrap() ResponseWriter {
	return w.ResponseWriter
}

func TestWrappedResponseController(t *testing.T) { run(t, testWrappedResponseController) }
func testWrappedResponseController(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w = wrapWriter{w}
		ctl := NewResponseController(w)
		if err := ctl.Flush(); err != nil {
			t.Errorf("ctl.Flush() = %v, want nil", err)
		}
		if err := ctl.SetReadDeadline(time.Time{}); err != nil {
			t.Errorf("ctl.SetReadDeadline() = %v, want nil", err)
		}
		if err := ctl.SetWriteDeadline(time.Time{}); err != nil {
			t.Errorf("ctl.SetWriteDeadline() = %v, want nil", err)
		}
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatalf("unexpected connection error: %v", err)
	}
	io.Copy(io.Discard, res.Body)
	defer res.Body.Close()
}

func TestResponseControllerEnableFullDuplex(t *testing.T) {
	run(t, testResponseControllerEnableFullDuplex)
}
func testResponseControllerEnableFullDuplex(t *testing.T, mode testMode) {
	cst := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, req *Request) {
		ctl := NewResponseController(w)
		if err := ctl.EnableFullDuplex(); err != nil {
			// TODO: Drop test for HTTP/2 when x/net is updated to support
			// EnableFullDuplex. Since HTTP/2 supports full duplex by default,
			// the rest of the test is fine; it's just the EnableFullDuplex call
			// that fails.
			if mode != http2Mode {
				t.Errorf("ctl.EnableFullDuplex() = %v, want nil", err)
			}
		}
		w.WriteHeader(200)
		ctl.Flush()
		for {
			var buf [1]byte
			n, err := req.Body.Read(buf[:])
			if n != 1 || err != nil {
				break
			}
			w.Write(buf[:])
			ctl.Flush()
		}
	}))
	pr, pw := io.Pipe()
	res, err := cst.c.Post(cst.ts.URL, "text/apocryphal", pr)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	for i := byte(0); i < 10; i++ {
		if _, err := pw.Write([]byte{i}); err != nil {
			t.Fatalf("Write: %v", err)
		}
		var buf [1]byte
		if n, err := res.Body.Read(buf[:]); n != 1 || err != nil {
			t.Fatalf("Read: %v, %v", n, err)
		}
		if buf[0] != i {
			t.Fatalf("read byte %v, want %v", buf[0], i)
		}
	}
	pw.Close()
}

func TestIssue58237(t *testing.T) {
	cst := newClientServerTest(t, http2Mode, HandlerFunc(func(w ResponseWriter, req *Request) {
		ctl := NewResponseController(w)
		if err := ctl.SetReadDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
			t.Errorf("ctl.SetReadDeadline() = %v, want nil", err)
		}
		time.Sleep(10 * time.Millisecond)
	}))
	res, err := cst.c.Get(cst.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

"""



```