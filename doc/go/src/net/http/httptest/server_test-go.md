Response:
Let's break down the thought process to analyze the provided Go code and generate the desired Chinese explanation.

**1. Understanding the Goal:**

The request asks for an analysis of a specific Go file (`server_test.go`) focusing on its functionality, underlying Go features, code examples, handling of command-line arguments (if any), and common pitfalls. The output should be in Chinese.

**2. Initial Code Scan and Identification of Core Components:**

The first step is to quickly read through the code to identify the main elements:

* **Package `httptest`:** This immediately suggests the code is related to testing HTTP functionality.
* **`import` statements:**  `net/http`, `testing`, `io`, `net`, `sync`, `bufio` are key indicators of the areas the code touches. The presence of `testing` confirms it's a test file.
* **`newServerFunc` type:** This defines a function signature that creates an `*httptest.Server`. This is central to the testing setup.
* **`newServers` map:**  This map stores different ways to create test servers (standard and TLS versions, manual and automatic). This is a key organizational structure for the tests.
* **`TestServer` function:**  This is the main test function, iterating through different server creation methods and running sub-tests.
* **Individual `test...` functions:**  These are the specific test cases covering various scenarios (basic server operation, closing servers, client connections, TLS, HTTP/2, etc.).

**3. Deconstructing the Functionality (Answering "它的功能"):**

Based on the identified components, the core functionality is clear: **This file provides utilities for creating and testing HTTP servers in Go.**  It allows for easy setup of temporary servers for integration testing. Specific functionalities include:

* Creating HTTP and HTTPS servers.
* Manually controlling server creation.
* Testing basic request/response cycles.
* Testing server closure behavior (blocking, client connection handling).
* Testing TLS server functionality without certificate warnings.
* Testing HTTP/2 support.
* Testing connection hijacking scenarios.

**4. Identifying Underlying Go Features (Answering "是什么go语言功能的实现"):**

The code demonstrates several core Go features:

* **Interfaces:** `http.Handler` is a key interface. The `newServerFunc` type also uses interfaces implicitly.
* **Functions as first-class citizens:**  `newServerFunc` and the values in the `newServers` map are examples of this.
* **Maps:** The `newServers` map is used for organizing different server creation functions.
* **Closures:** The anonymous functions used in `http.HandlerFunc` are closures.
* **Goroutines and `sync.WaitGroup`:** Used in `TestCloseHijackedConnection` for concurrent testing.
* **`net` package:** For low-level network operations in tests like `testServerCloseBlocking`.
* **`testing` package:**  The core of the testing framework.
* **`defer` statements:** Used for resource cleanup (`ts.Close()`, `res.Body.Close()`).
* **Structs:** `Server` struct and anonymous structs in tests.

**5. Generating Code Examples (Answering "用go代码举例说明"):**

The request specifically asks for code examples. Good examples should showcase the core functionality. The `testServer` and `testServerClient` functions in the source code itself provide excellent templates. The key is to simplify and highlight the essential usage pattern: creating a server, making a request, and verifying the response.

* **Standard Server Example:**  Adapt `testServer` to a simpler example showcasing `NewServer`.
* **TLS Server Example:** Adapt `testServerClient` to a simpler example showcasing `NewTLSServer`.

For the examples, consider:

* **Minimalism:** Focus on the core concept.
* **Clarity:** Use descriptive variable names.
* **Output:** Include expected output to demonstrate correctness.

**6. Handling Command-Line Arguments (Answering "命令行参数的具体处理"):**

Carefully review the code. There is no explicit handling of command-line arguments in this file. This needs to be stated clearly.

**7. Identifying Common Pitfalls (Answering "使用者易犯错的点"):**

Analyze the test cases and consider common scenarios where developers might make mistakes when using `httptest.Server`. The `testGetAfterClose` test points to a potential pitfall: trying to use the server after it's closed.

* **Accessing the server after closing:** This is a direct consequence of the `testGetAfterClose` test. Provide a clear example of this error.

**8. Structuring the Answer and Using Chinese:**

Organize the information logically according to the request's prompts. Use clear and concise Chinese. Pay attention to technical terms and ensure accurate translation. Use headings and bullet points for better readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus only on the `Server` struct.
* **Correction:** Realize that the `newServers` map and the different creation functions are crucial to understanding the file's structure and testing approach.
* **Initial thought:**  Provide very complex code examples.
* **Correction:** Simplify the code examples to highlight the core concepts, making them easier to understand.
* **Initial thought:**  Assume command-line arguments exist.
* **Correction:**  Carefully re-examine the code and confirm the absence of command-line argument handling.

By following these steps, combining code analysis, understanding the underlying concepts, and focusing on the specific requirements of the prompt, a comprehensive and accurate Chinese explanation can be generated.
这段代码是 Go 语言标准库 `net/http/httptest` 包中 `server_test.go` 文件的一部分，它主要的功能是 **测试 `httptest` 包提供的用于创建测试 HTTP 和 HTTPS 服务器的功能**。

具体来说，它测试了 `httptest` 包中的 `NewServer` 和 `NewTLSServer` 函数，以及它们的手动创建变体，来确保这些函数能够正确地创建和管理用于测试的 HTTP 服务器。

下面我将分别列举其功能，并用 Go 代码举例说明其实现。

**1. 测试 `NewServer` 和 `NewTLSServer` 的基本功能:**

这段代码测试了使用 `NewServer` 和 `NewTLSServer` 创建的服务器是否能够正常处理 HTTP 请求。

```go
func TestServer(t *testing.T) {
	for _, name := range []string{"NewServer", "NewServerManual"} {
		t.Run(name, func(t *testing.T) {
			newServer := newServers[name]
			t.Run("Server", func(t *testing.T) { testServer(t, newServer) })
			// ... 其他测试用例
		})
	}
	for _, name := range []string{"NewTLSServer", "NewTLSServerManual"} {
		t.Run(name, func(t *testing.T) {
			newServer := newServers[name]
			t.Run("ServerClient", func(t *testing.T) { testServerClient(t, newServer) })
			// ... 其他测试用例
		})
	}
}

func testServer(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", string(got))
	}
}
```

**代码推理:**

* **假设输入:** `newServer` 是 `NewServer` 函数。
* **执行过程:**
    * `newServer` 创建了一个临时的 HTTP 服务器，该服务器的处理器会返回 "hello"。
    * 使用 `http.Get` 向该服务器发送请求。
    * 检查响应状态和内容是否符合预期。
* **预期输出:**  如果一切正常，测试将通过。如果响应内容不是 "hello"，测试将失败并输出错误信息。

**2. 测试在服务器关闭后尝试请求的行为:**

`testGetAfterClose` 函数测试了当服务器关闭后，尝试向其发送请求时是否会发生错误。

```go
func testGetAfterClose(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want hello", string(got))
	}

	ts.Close()

	res, err = http.Get(ts.URL)
	if err == nil {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("Unexpected response after close: %v, %v, %s", res.Status, res.Header, body)
	}
}
```

**代码推理:**

* **假设输入:** `newServer` 是 `NewServer` 函数。
* **执行过程:**
    * 创建并启动一个 HTTP 服务器。
    * 向服务器发送一个请求并验证响应。
    * 关闭服务器。
    * 再次尝试向已关闭的服务器发送请求。
* **预期输出:**  第二次请求应该会返回一个错误，因为服务器已经关闭。如果 `err` 为 `nil`，则测试失败，表明在服务器关闭后仍然收到了响应，这是不期望的行为。

**3. 测试服务器关闭时阻塞连接的情况:**

`testServerCloseBlocking` 函数测试了当有客户端连接处于不同状态时关闭服务器是否会发生阻塞。

```go
func testServerCloseBlocking(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// Keep one connection in StateNew (connected, but not sending anything)
	cnew := dial()
	defer cnew.Close()

	// Keep one connection in StateIdle (idle after a request)
	cidle := dial()
	defer cidle.Close()
	cidle.Write([]byte("HEAD / HTTP/1.1\r\nHost: foo\r\n\r\n"))
	_, err := http.ReadResponse(bufio.NewReader(cidle), nil)
	if err != nil {
		t.Fatal(err)
	}

	ts.Close() // test we don't hang here forever.
}
```

**代码推理:**

* **假设输入:** `newServer` 是 `NewServer` 函数。
* **执行过程:**
    * 创建并启动一个 HTTP 服务器。
    * 创建两个 TCP 连接：一个连接已建立但未发送任何数据 (StateNew)，另一个连接已发送请求并处于空闲状态 (StateIdle)。
    * 尝试关闭服务器。
* **预期输出:** `ts.Close()` 应该能够正常返回，不会因为有活动的或空闲的连接而无限期地阻塞。

**4. 测试 `CloseClientConnections` 方法:**

`testServerCloseClientConnections` 函数测试了 `Server` 结构体的 `CloseClientConnections` 方法，该方法用于立即关闭所有活动的客户端连接。

```go
func testServerCloseClientConnections(t *testing.T, newServer newServerFunc) {
	var s *Server
	s = newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.CloseClientConnections()
	}))
	defer s.Close()
	res, err := http.Get(s.URL)
	if err == nil {
		res.Body.Close()
		t.Fatalf("Unexpected response: %#v", res)
	}
}
```

**代码推理:**

* **假设输入:** `newServer` 是 `NewServer` 函数。
* **执行过程:**
    * 创建一个服务器，其处理器在收到请求后会调用 `s.CloseClientConnections()`。
    * 使用 `http.Get` 发送一个请求。
* **预期输出:**  由于服务器在处理请求时调用了 `CloseClientConnections`，因此客户端应该无法成功接收到响应。`http.Get` 应该返回一个错误。如果 `err` 为 `nil`，则表示收到了意外的响应，测试将失败。

**5. 测试 `Server.Client` 方法:**

`testServerClient` 和 `testTLSServerClientTransportType` 函数测试了 `Server` 结构体的 `Client` 方法，该方法返回一个配置好的 `http.Client`，可以安全地与测试服务器通信，特别是对于 TLS 服务器，避免证书错误。

```go
func testServerClient(t *testing.T, newTLSServer newServerFunc) {
	ts := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer ts.Close()
	client := ts.Client()
	res, err := client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", string(got))
	}
}

func testServerClientTransportType(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()
	client := ts.Client()
	if _, ok := client.Transport.(*http.Transport); !ok {
		t.Errorf("got %T, want *http.Transport", client.Transport)
	}
}
```

**代码推理:**

* **假设输入:** `newTLSServer` 是 `NewTLSServer` 函数。
* **执行过程:**
    * 创建一个 TLS 服务器。
    * 调用 `ts.Client()` 获取一个 `http.Client`。
    * 使用返回的 `client` 向服务器发送请求。
* **预期输出:**  `client.Get(ts.URL)` 应该能够成功发送请求并接收响应，即使是 TLS 服务器，也不会因为自签名证书而报错。 `testServerClientTransportType` 还会检查返回的 `Client` 的 `Transport` 是否是 `*http.Transport` 类型。

**6. 测试零值 `Server` 结构的 `Close` 方法:**

`TestServerZeroValueClose` 测试了当直接创建一个 `Server` 结构体，而不是通过构造函数时，调用其 `Close` 方法是否会发生 panic。

```go
func TestServerZeroValueClose(t *testing.T) {
	ts := &Server{
		Listener: onlyCloseListener{},
		Config:   &http.Server{},
	}

	ts.Close() // tests that it doesn't panic
}
```

**代码推理:**

* **执行过程:** 直接创建一个 `Server` 结构体，并初始化部分字段。然后调用其 `Close` 方法。
* **预期输出:** 调用 `ts.Close()` 不应该导致 panic。

**7. 测试连接劫持场景下的关闭:**

`TestCloseHijackedConnection` 测试了当一个连接被劫持 (hijacked) 后，在服务器关闭的同时关闭该连接是否会引发问题。

```go
func TestCloseHijackedConnection(t *testing.T) {
	hijacked := make(chan net.Conn)
	ts := NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(hijacked)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("failed to hijack")
		}
		c, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		hijacked <- c
	}))

	// ... (后续的 goroutine 用于模拟客户端请求，关闭连接和服务器)
}
```

**代码推理:**

* **执行过程:**
    * 创建一个服务器，其处理器会劫持连接。
    * 启动多个 goroutine：一个模拟客户端发送请求，一个接收被劫持的连接并关闭它，另一个关闭服务器。
* **预期输出:**  服务器和被劫持的连接应该能够安全地关闭，不会发生死锁或 panic。

**8. 测试 HTTP/2 支持:**

`TestTLSServerWithHTTP2` 测试了 `NewUnstartedServer` 的 `EnableHTTP2` 选项是否能正确启用 HTTP/2 协议。

```go
func TestTLSServerWithHTTP2(t *testing.T) {
	modes := []struct {
		name      string
		wantProto string
	}{
		{"http1", "HTTP/1.1"},
		{"http2", "HTTP/2.0"},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			cst := NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Proto", r.Proto)
			}))

			switch tt.name {
			case "http2":
				cst.EnableHTTP2 = true
				cst.StartTLS()
			default:
				cst.Start()
			}

			defer cst.Close()

			res, err := cst.Client().Get(cst.URL)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			if g, w := res.Header.Get("X-Proto"), tt.wantProto; g != w {
				t.Fatalf("X-Proto header mismatch:\n\tgot:  %q\n\twant: %q", g, w)
			}
		})
	}
}
```

**代码推理:**

* **假设输入:** `tt.name` 可以是 "http1" 或 "http2"。
* **执行过程:**
    * 创建一个未启动的服务器。
    * 如果 `tt.name` 是 "http2"，则启用 HTTP/2 并启动 TLS 服务器；否则，直接启动服务器。
    * 使用服务器的客户端发送请求。
    * 检查响应头中的 "X-Proto" 字段，该字段应该反映实际使用的 HTTP 协议。
* **预期输出:**  如果启用 HTTP/2，"X-Proto" 应该为 "HTTP/2.0"；否则，应该为 "HTTP/1.1"。

**关于 Go 语言功能的实现:**

这段代码大量使用了 Go 语言的以下功能：

* **匿名函数和闭包:** 用于定义 HTTP 处理函数。
* **结构体和方法:** `Server` 结构体及其相关方法。
* **接口:** `http.Handler` 和 `http.Hijacker` 接口。
* **Goroutine 和通道:** 用于并发测试，例如在 `TestCloseHijackedConnection` 中。
* **`defer` 语句:** 用于资源清理，例如关闭服务器和响应体。
* **`testing` 包:** Go 语言的测试框架。

**命令行参数的具体处理:**

这段代码本身并不处理任何命令行参数。它是测试代码，主要通过 `go test` 命令运行，该命令有一些自身的命令行参数，但这段代码内部没有涉及。

**使用者易犯错的点:**

一个容易犯错的点是 **在 `httptest.Server` 关闭后仍然尝试使用其 `URL` 发送请求**。正如 `testGetAfterClose` 测试所展示的，这样做会导致错误。

**例子:**

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
)

func main() {
	// 创建一个测试服务器
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	// 正常使用服务器
	res, err := http.Get(ts.URL)
	if err != nil {
		fmt.Println("Error during initial request:", err)
		return
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	fmt.Println("Response:", string(body))

	// 关闭服务器
	ts.Close()

	// 尝试在服务器关闭后再次请求 (易错点)
	res2, err2 := http.Get(ts.URL)
	if err2 != nil {
		fmt.Println("Error after server closed:", err2) // 这里会输出错误
	} else {
		body2, _ := io.ReadAll(res2.Body)
		res2.Body.Close()
		fmt.Println("Unexpected response after close:", string(body2))
	}
}
```

在这个例子中，在 `ts.Close()` 被调用后，尝试使用 `ts.URL` 会导致一个错误，因为服务器已经不再监听。 开发者需要确保在测试完成后正确关闭服务器，并且不再使用已关闭的服务器的资源。

Prompt: 
```
这是路径为go/src/net/http/httptest/server_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httptest

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

type newServerFunc func(http.Handler) *Server

var newServers = map[string]newServerFunc{
	"NewServer":    NewServer,
	"NewTLSServer": NewTLSServer,

	// The manual variants of newServer create a Server manually by only filling
	// in the exported fields of Server.
	"NewServerManual": func(h http.Handler) *Server {
		ts := &Server{Listener: newLocalListener(), Config: &http.Server{Handler: h}}
		ts.Start()
		return ts
	},
	"NewTLSServerManual": func(h http.Handler) *Server {
		ts := &Server{Listener: newLocalListener(), Config: &http.Server{Handler: h}}
		ts.StartTLS()
		return ts
	},
}

func TestServer(t *testing.T) {
	for _, name := range []string{"NewServer", "NewServerManual"} {
		t.Run(name, func(t *testing.T) {
			newServer := newServers[name]
			t.Run("Server", func(t *testing.T) { testServer(t, newServer) })
			t.Run("GetAfterClose", func(t *testing.T) { testGetAfterClose(t, newServer) })
			t.Run("ServerCloseBlocking", func(t *testing.T) { testServerCloseBlocking(t, newServer) })
			t.Run("ServerCloseClientConnections", func(t *testing.T) { testServerCloseClientConnections(t, newServer) })
			t.Run("ServerClientTransportType", func(t *testing.T) { testServerClientTransportType(t, newServer) })
		})
	}
	for _, name := range []string{"NewTLSServer", "NewTLSServerManual"} {
		t.Run(name, func(t *testing.T) {
			newServer := newServers[name]
			t.Run("ServerClient", func(t *testing.T) { testServerClient(t, newServer) })
			t.Run("TLSServerClientTransportType", func(t *testing.T) { testTLSServerClientTransportType(t, newServer) })
		})
	}
}

func testServer(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", string(got))
	}
}

// Issue 12781
func testGetAfterClose(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want hello", string(got))
	}

	ts.Close()

	res, err = http.Get(ts.URL)
	if err == nil {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("Unexpected response after close: %v, %v, %s", res.Status, res.Header, body)
	}
}

func testServerCloseBlocking(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// Keep one connection in StateNew (connected, but not sending anything)
	cnew := dial()
	defer cnew.Close()

	// Keep one connection in StateIdle (idle after a request)
	cidle := dial()
	defer cidle.Close()
	cidle.Write([]byte("HEAD / HTTP/1.1\r\nHost: foo\r\n\r\n"))
	_, err := http.ReadResponse(bufio.NewReader(cidle), nil)
	if err != nil {
		t.Fatal(err)
	}

	ts.Close() // test we don't hang here forever.
}

// Issue 14290
func testServerCloseClientConnections(t *testing.T, newServer newServerFunc) {
	var s *Server
	s = newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.CloseClientConnections()
	}))
	defer s.Close()
	res, err := http.Get(s.URL)
	if err == nil {
		res.Body.Close()
		t.Fatalf("Unexpected response: %#v", res)
	}
}

// Tests that the Server.Client method works and returns an http.Client that can hit
// NewTLSServer without cert warnings.
func testServerClient(t *testing.T, newTLSServer newServerFunc) {
	ts := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer ts.Close()
	client := ts.Client()
	res, err := client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", string(got))
	}
}

// Tests that the Server.Client.Transport interface is implemented
// by a *http.Transport.
func testServerClientTransportType(t *testing.T, newServer newServerFunc) {
	ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()
	client := ts.Client()
	if _, ok := client.Transport.(*http.Transport); !ok {
		t.Errorf("got %T, want *http.Transport", client.Transport)
	}
}

// Tests that the TLS Server.Client.Transport interface is implemented
// by a *http.Transport.
func testTLSServerClientTransportType(t *testing.T, newTLSServer newServerFunc) {
	ts := newTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()
	client := ts.Client()
	if _, ok := client.Transport.(*http.Transport); !ok {
		t.Errorf("got %T, want *http.Transport", client.Transport)
	}
}

type onlyCloseListener struct {
	net.Listener
}

func (onlyCloseListener) Close() error { return nil }

// Issue 19729: panic in Server.Close for values created directly
// without a constructor (so the unexported client field is nil).
func TestServerZeroValueClose(t *testing.T) {
	ts := &Server{
		Listener: onlyCloseListener{},
		Config:   &http.Server{},
	}

	ts.Close() // tests that it doesn't panic
}

// Issue 51799: test hijacking a connection and then closing it
// concurrently with closing the server.
func TestCloseHijackedConnection(t *testing.T) {
	hijacked := make(chan net.Conn)
	ts := NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(hijacked)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("failed to hijack")
		}
		c, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		hijacked <- c
	}))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, err := http.NewRequest("GET", ts.URL, nil)
		if err != nil {
			t.Log(err)
		}
		// Use a client not associated with the Server.
		var c http.Client
		resp, err := c.Do(req)
		if err != nil {
			t.Log(err)
			return
		}
		resp.Body.Close()
	}()

	wg.Add(1)
	conn := <-hijacked
	go func(conn net.Conn) {
		defer wg.Done()
		// Close the connection and then inform the Server that
		// we closed it.
		conn.Close()
		ts.Config.ConnState(conn, http.StateClosed)
	}(conn)

	wg.Add(1)
	go func() {
		defer wg.Done()
		ts.Close()
	}()
	wg.Wait()
}

func TestTLSServerWithHTTP2(t *testing.T) {
	modes := []struct {
		name      string
		wantProto string
	}{
		{"http1", "HTTP/1.1"},
		{"http2", "HTTP/2.0"},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			cst := NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Proto", r.Proto)
			}))

			switch tt.name {
			case "http2":
				cst.EnableHTTP2 = true
				cst.StartTLS()
			default:
				cst.Start()
			}

			defer cst.Close()

			res, err := cst.Client().Get(cst.URL)
			if err != nil {
				t.Fatalf("Failed to make request: %v", err)
			}
			if g, w := res.Header.Get("X-Proto"), tt.wantProto; g != w {
				t.Fatalf("X-Proto header mismatch:\n\tgot:  %q\n\twant: %q", g, w)
			}
		})
	}
}

"""



```