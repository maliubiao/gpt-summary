Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Understanding the Context:**

The first thing I do is scan the code for keywords and structure. I see:

* `package httputil` - This tells me it's part of the `net/http/httputil` package, likely providing HTTP utilities.
* `import` statements - These indicate dependencies on `bufio`, `errors`, `io`, `net`, `net/http`, and `net/textproto`. This confirms it's related to network and HTTP operations.
* Comments starting with "// Deprecated:" -  This is a huge red flag! It immediately tells me these components (`ErrPersistEOF`, `ErrClosed`, `ErrPipeline`, `ServerConn`, `NewServerConn`, `ClientConn`, `NewClientConn`, `NewProxyClientConn`) are outdated and shouldn't be used in new code. This is the most important piece of information.
* Struct definitions (`ServerConn`, `ClientConn`) - These represent data structures, likely holding the state of a connection.
* Methods associated with the structs (e.g., `Read`, `Write`, `Hijack`, `Close`, `Pending`, `Do`). These define the operations that can be performed on these connection objects.
* Synchronization primitives (`sync.Mutex`) - Suggests these connection types are designed to be used in concurrent environments and need protection against race conditions.
* A `textproto.Pipeline` field -  Indicates support for HTTP pipelining.

**2. Identifying Core Functionality (Despite Deprecation):**

Even though the code is deprecated, I still need to understand *what it was designed to do*. By looking at the methods, I can infer:

* **`ServerConn`**: This seems to handle incoming HTTP requests on the server-side of a connection. The `Read()` method reads a request, and `Write()` sends a response. The `Pending()` method tracks the number of requests waiting for responses.
* **`ClientConn`**: This handles outgoing HTTP requests on the client-side. `Write()` sends a request, `Read()` receives a response, and `Pending()` tracks sent requests awaiting responses.
* **`Hijack()`**:  This allows taking control of the underlying network connection, bypassing the `ServerConn` or `ClientConn` abstraction.
* **`Close()`**:  Closes the connection.

**3. Understanding the "Why" Behind the Deprecation:**

The comments clearly state the reason for deprecation: "low-level, old, and unused by Go's current HTTP stack."  This is crucial. It implies that the standard `net/http` package now provides higher-level and more robust ways to handle HTTP connections. Knowing this helps to explain *why* the code is structured the way it is and why newer code shouldn't use it.

**4. Inferring the Intended Use Case (Despite Deprecation):**

Based on the method names and the pipelining aspect, I can deduce that these types were designed for managing persistent HTTP connections, allowing multiple requests and responses to be sent over the same TCP connection. The `Pending()` methods and the `textproto.Pipeline` reinforce this idea.

**5. Considering Potential Errors and Misuse:**

The deprecation itself is the biggest point of misuse. New developers might stumble upon this code and try to use it, thinking it's the correct way to handle HTTP. Therefore, clearly stating the deprecation and pointing to the modern alternatives is essential.

The `Hijack()` method is another potential area for errors. If used incorrectly (e.g., while Read/Write is in progress), it could lead to unexpected behavior and data corruption.

**6. Constructing the Explanation (in Chinese):**

Now, I translate my understanding into clear, concise Chinese, following the prompt's requirements:

* **功能列举:** I list the apparent functionalities based on the method names and struct definitions. I emphasize the request/response handling and connection management aspects.
* **Go语言功能推理:** I identify the core concept as persistent HTTP connection management. I use the term "HTTP 持久连接" (HTTP persistent connection).
* **代码举例 (with caveat):**  Since the code is deprecated, providing a *correct* modern example is more helpful than showing how to use the deprecated types. I demonstrate the use of `http.ListenAndServe` for the server and `http.Client` for the client, highlighting the modern approach. I explicitly state that the provided code snippet represents an *older* way of doing things.
* **假设输入与输出:** For the example, I provide basic request and response details.
* **命令行参数处理:**  This section is not applicable as the provided code doesn't directly handle command-line arguments.
* **易犯错的点:** I focus on the most critical mistake: using the deprecated types. I explain why this is a problem and suggest using the modern `net/http` package instead. I also mention the potential misuse of `Hijack()`.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps provide a detailed example of using `ServerConn` and `ClientConn`.
* **Correction:**  Realized that demonstrating deprecated code is counterproductive. Focus on showing the *correct* way to do it now. Emphasize the deprecation heavily.
* **Initial thought:**  Focus heavily on the pipelining aspect.
* **Correction:** While pipelining is present, the core message is about deprecation. Keep the explanation of pipelining brief and within the context of what the code *was* intended for.
* **Initial thought:**  Assume the user has deep knowledge of HTTP.
* **Correction:**  Write the explanation in a way that is understandable even to someone with a basic understanding of HTTP concepts.

By following this structured thought process, I can effectively analyze the code snippet, identify its purpose (both intended and current status), and provide a comprehensive and helpful answer in Chinese, addressing all the points in the prompt.
这段Go语言代码是 `net/http/httputil` 包的一部分，它定义了用于处理 **HTTP 持久连接** 的低级结构体 `ServerConn` 和 `ClientConn`。  但是，代码中的注释已经明确指出这些结构体和相关方法已经被 **废弃 (Deprecated)**，并且 Go 语言的当前 HTTP 栈不再使用它们。建议使用 `net/http` 包中的 `Server` 和 `Client` 或 `Transport` 来替代。

尽管如此，我们仍然可以分析一下这些废弃的结构体的功能：

**`ServerConn` 的功能 (已被废弃):**

* **管理服务器端的持久连接:** `ServerConn` 负责处理客户端建立的持久 HTTP 连接，允许在同一个 TCP 连接上处理多个 HTTP 请求和响应。
* **读取请求:** `Read()` 方法从连接中读取下一个 HTTP 请求。
* **发送响应:** `Write()` 方法将 HTTP 响应发送回客户端。
* **管道化 (Pipelining) 支持:**  通过 `textproto.Pipeline` 字段，可以推断其支持 HTTP 管道化，即在不需要等待前一个请求的响应的情况下，发送多个请求。
* **连接劫持:** `Hijack()` 方法允许“劫持”连接，返回底层的 `net.Conn` 和 `bufio.Reader`，使调用者可以绕过 `ServerConn` 直接操作连接。
* **关闭连接:** `Close()` 方法关闭底层的网络连接。
* **跟踪未响应的请求:** `Pending()` 方法返回连接上已接收但尚未发送响应的请求数量。

**`ClientConn` 的功能 (已被废弃):**

* **管理客户端的持久连接:** `ClientConn` 负责管理客户端与服务器建立的持久 HTTP 连接。
* **发送请求:** `Write()` 方法将 HTTP 请求发送到服务器。
* **接收响应:** `Read()` 方法从服务器读取 HTTP 响应。
* **管道化 (Pipelining) 支持:** 同样通过 `textproto.Pipeline` 字段，推断其支持客户端的 HTTP 管道化。
* **连接劫持:** `Hijack()` 方法允许劫持连接。
* **关闭连接:** `Close()` 方法关闭底层的网络连接。
* **跟踪未响应的请求:** `Pending()` 方法返回连接上已发送但尚未收到响应的请求数量。
* **便捷的发送请求和接收响应:** `Do()` 方法提供了一个方便的方式来发送请求并立即接收响应。

**它可以被推理为 Go 语言早期 HTTP 功能的实现，用于处理 HTTP/1.0 和 HTTP/1.1 的持久连接和管道化。**  在 Go 语言的早期版本中，可能没有像现在 `net/http` 包中那样完善的高级抽象，因此提供了这些低级别的结构体供开发者直接操作连接。

**Go 代码举例 (说明其早期用途，不建议在新代码中使用):**

以下代码演示了 `ServerConn` 和 `ClientConn` 的一种可能的使用方式，**但请注意，这只是为了说明其概念，不应该在新的 Go 代码中使用。**  应该使用 `net/http` 包的标准库功能。

```go
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
)

func handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	serverConn := httputil.NewServerConn(conn, reader)

	for {
		req, err := serverConn.Read()
		if err != nil {
			fmt.Println("Error reading request:", err)
			return
		}

		fmt.Println("Received request:", req.URL)

		resp := &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": {"text/plain"}},
			Body:       nopCloser(fmt.Sprintf("You requested: %s\n", req.URL.Path)),
			Request:    req,
		}

		err = serverConn.Write(req, resp)
		if err != nil {
			fmt.Println("Error writing response:", err)
			return
		}

		if req.Close {
			return
		}
	}
}

func clientRequest(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	clientConn := httputil.NewClientConn(conn, reader)

	req, err := http.NewRequest("GET", "/hello", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	err = clientConn.Write(req)
	if err != nil {
		fmt.Println("Error writing request:", err)
		return
	}

	resp, err := clientConn.Read(req)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Client received response:", resp.Status)
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	fmt.Println("Response body:", buf.String())
}

type nopCloser string

func (n nopCloser) Read(p []byte) (int, error) {
	return strings.NewReader(string(n)).Read(p)
}

func (n nopCloser) Close() error {
	return nil
}

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer ln.Close()

	go func() {
		conn, err := net.Dial("tcp", "localhost:8080")
		if err != nil {
			fmt.Println("Client error dialing:", err)
			return
		}
		clientRequest(conn)
	}()

	conn, err := ln.Accept()
	if err != nil {
		fmt.Println("Error accepting:", err)
		return
	}
	handleConn(conn)
}
```

**假设的输入与输出:**

**服务器端 (handleConn):**

* **输入:** 客户端通过 `clientRequest` 发送一个 GET 请求到 `/hello` 路径。
* **输出:** 服务器端接收到请求，打印 "Received request: /hello"，然后构建一个包含 "You requested: /hello\n" 的响应并发送回客户端。

**客户端 (clientRequest):**

* **输入:**  建立到服务器的 TCP 连接。
* **输出:** 客户端发送 GET 请求到 `/hello`，然后接收到服务器的响应，打印 "Client received response: 200 OK" 和 "Response body: You requested: /hello\n"。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它的主要功能是处理已建立的 TCP 连接上的 HTTP 通信。如果需要处理命令行参数，通常会在 `main` 函数中使用 `os.Args` 和 `flag` 包来实现。

**使用者易犯错的点:**

最大的易错点就是 **使用这些已废弃的结构体**。Go 语言的 `net/http` 包已经提供了更加高级、方便和安全的 API 来处理 HTTP 客户端和服务器。

例如，对于服务器端，应该使用 `http.ListenAndServe` 或 `http.Server` 结构体，以及 `http.HandleFunc` 等来注册处理器函数。

对于客户端，应该使用 `http.Client` 结构体来发送请求。

**正确的服务器端代码示例 (使用 `net/http`):**

```go
package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "You requested: %s\n", r.URL.Path)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server listening on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
```

**正确的客户端代码示例 (使用 `net/http`):**

```go
package main

import (
	"fmt"
	"io/ioutil"	
	"net/http"
)

func main() {
	resp, err := http.Get("http://localhost:8080
### 提示词
```
这是路径为go/src/net/http/httputil/persist.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"sync"
)

var (
	// Deprecated: No longer used.
	ErrPersistEOF = &http.ProtocolError{ErrorString: "persistent connection closed"}

	// Deprecated: No longer used.
	ErrClosed = &http.ProtocolError{ErrorString: "connection closed by user"}

	// Deprecated: No longer used.
	ErrPipeline = &http.ProtocolError{ErrorString: "pipeline error"}
)

// This is an API usage error - the local side is closed.
// ErrPersistEOF (above) reports that the remote side is closed.
var errClosed = errors.New("i/o operation on closed connection")

// ServerConn is an artifact of Go's early HTTP implementation.
// It is low-level, old, and unused by Go's current HTTP stack.
// We should have deleted it before Go 1.
//
// Deprecated: Use the Server in package [net/http] instead.
type ServerConn struct {
	mu              sync.Mutex // read-write protects the following fields
	c               net.Conn
	r               *bufio.Reader
	re, we          error // read/write errors
	lastbody        io.ReadCloser
	nread, nwritten int
	pipereq         map[*http.Request]uint

	pipe textproto.Pipeline
}

// NewServerConn is an artifact of Go's early HTTP implementation.
// It is low-level, old, and unused by Go's current HTTP stack.
// We should have deleted it before Go 1.
//
// Deprecated: Use the Server in package [net/http] instead.
func NewServerConn(c net.Conn, r *bufio.Reader) *ServerConn {
	if r == nil {
		r = bufio.NewReader(c)
	}
	return &ServerConn{c: c, r: r, pipereq: make(map[*http.Request]uint)}
}

// Hijack detaches the [ServerConn] and returns the underlying connection as well
// as the read-side bufio which may have some left over data. Hijack may be
// called before Read has signaled the end of the keep-alive logic. The user
// should not call Hijack while [ServerConn.Read] or [ServerConn.Write] is in progress.
func (sc *ServerConn) Hijack() (net.Conn, *bufio.Reader) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	c := sc.c
	r := sc.r
	sc.c = nil
	sc.r = nil
	return c, r
}

// Close calls [ServerConn.Hijack] and then also closes the underlying connection.
func (sc *ServerConn) Close() error {
	c, _ := sc.Hijack()
	if c != nil {
		return c.Close()
	}
	return nil
}

// Read returns the next request on the wire. An [ErrPersistEOF] is returned if
// it is gracefully determined that there are no more requests (e.g. after the
// first request on an HTTP/1.0 connection, or after a Connection:close on a
// HTTP/1.1 connection).
func (sc *ServerConn) Read() (*http.Request, error) {
	var req *http.Request
	var err error

	// Ensure ordered execution of Reads and Writes
	id := sc.pipe.Next()
	sc.pipe.StartRequest(id)
	defer func() {
		sc.pipe.EndRequest(id)
		if req == nil {
			sc.pipe.StartResponse(id)
			sc.pipe.EndResponse(id)
		} else {
			// Remember the pipeline id of this request
			sc.mu.Lock()
			sc.pipereq[req] = id
			sc.mu.Unlock()
		}
	}()

	sc.mu.Lock()
	if sc.we != nil { // no point receiving if write-side broken or closed
		defer sc.mu.Unlock()
		return nil, sc.we
	}
	if sc.re != nil {
		defer sc.mu.Unlock()
		return nil, sc.re
	}
	if sc.r == nil { // connection closed by user in the meantime
		defer sc.mu.Unlock()
		return nil, errClosed
	}
	r := sc.r
	lastbody := sc.lastbody
	sc.lastbody = nil
	sc.mu.Unlock()

	// Make sure body is fully consumed, even if user does not call body.Close
	if lastbody != nil {
		// body.Close is assumed to be idempotent and multiple calls to
		// it should return the error that its first invocation
		// returned.
		err = lastbody.Close()
		if err != nil {
			sc.mu.Lock()
			defer sc.mu.Unlock()
			sc.re = err
			return nil, err
		}
	}

	req, err = http.ReadRequest(r)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			// A close from the opposing client is treated as a
			// graceful close, even if there was some unparse-able
			// data before the close.
			sc.re = ErrPersistEOF
			return nil, sc.re
		} else {
			sc.re = err
			return req, err
		}
	}
	sc.lastbody = req.Body
	sc.nread++
	if req.Close {
		sc.re = ErrPersistEOF
		return req, sc.re
	}
	return req, err
}

// Pending returns the number of unanswered requests
// that have been received on the connection.
func (sc *ServerConn) Pending() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.nread - sc.nwritten
}

// Write writes resp in response to req. To close the connection gracefully, set the
// Response.Close field to true. Write should be considered operational until
// it returns an error, regardless of any errors returned on the [ServerConn.Read] side.
func (sc *ServerConn) Write(req *http.Request, resp *http.Response) error {

	// Retrieve the pipeline ID of this request/response pair
	sc.mu.Lock()
	id, ok := sc.pipereq[req]
	delete(sc.pipereq, req)
	if !ok {
		sc.mu.Unlock()
		return ErrPipeline
	}
	sc.mu.Unlock()

	// Ensure pipeline order
	sc.pipe.StartResponse(id)
	defer sc.pipe.EndResponse(id)

	sc.mu.Lock()
	if sc.we != nil {
		defer sc.mu.Unlock()
		return sc.we
	}
	if sc.c == nil { // connection closed by user in the meantime
		defer sc.mu.Unlock()
		return ErrClosed
	}
	c := sc.c
	if sc.nread <= sc.nwritten {
		defer sc.mu.Unlock()
		return errors.New("persist server pipe count")
	}
	if resp.Close {
		// After signaling a keep-alive close, any pipelined unread
		// requests will be lost. It is up to the user to drain them
		// before signaling.
		sc.re = ErrPersistEOF
	}
	sc.mu.Unlock()

	err := resp.Write(c)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if err != nil {
		sc.we = err
		return err
	}
	sc.nwritten++

	return nil
}

// ClientConn is an artifact of Go's early HTTP implementation.
// It is low-level, old, and unused by Go's current HTTP stack.
// We should have deleted it before Go 1.
//
// Deprecated: Use Client or Transport in package [net/http] instead.
type ClientConn struct {
	mu              sync.Mutex // read-write protects the following fields
	c               net.Conn
	r               *bufio.Reader
	re, we          error // read/write errors
	lastbody        io.ReadCloser
	nread, nwritten int
	pipereq         map[*http.Request]uint

	pipe     textproto.Pipeline
	writeReq func(*http.Request, io.Writer) error
}

// NewClientConn is an artifact of Go's early HTTP implementation.
// It is low-level, old, and unused by Go's current HTTP stack.
// We should have deleted it before Go 1.
//
// Deprecated: Use the Client or Transport in package [net/http] instead.
func NewClientConn(c net.Conn, r *bufio.Reader) *ClientConn {
	if r == nil {
		r = bufio.NewReader(c)
	}
	return &ClientConn{
		c:        c,
		r:        r,
		pipereq:  make(map[*http.Request]uint),
		writeReq: (*http.Request).Write,
	}
}

// NewProxyClientConn is an artifact of Go's early HTTP implementation.
// It is low-level, old, and unused by Go's current HTTP stack.
// We should have deleted it before Go 1.
//
// Deprecated: Use the Client or Transport in package [net/http] instead.
func NewProxyClientConn(c net.Conn, r *bufio.Reader) *ClientConn {
	cc := NewClientConn(c, r)
	cc.writeReq = (*http.Request).WriteProxy
	return cc
}

// Hijack detaches the [ClientConn] and returns the underlying connection as well
// as the read-side bufio which may have some left over data. Hijack may be
// called before the user or Read have signaled the end of the keep-alive
// logic. The user should not call Hijack while [ClientConn.Read] or ClientConn.Write is in progress.
func (cc *ClientConn) Hijack() (c net.Conn, r *bufio.Reader) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	c = cc.c
	r = cc.r
	cc.c = nil
	cc.r = nil
	return
}

// Close calls [ClientConn.Hijack] and then also closes the underlying connection.
func (cc *ClientConn) Close() error {
	c, _ := cc.Hijack()
	if c != nil {
		return c.Close()
	}
	return nil
}

// Write writes a request. An [ErrPersistEOF] error is returned if the connection
// has been closed in an HTTP keep-alive sense. If req.Close equals true, the
// keep-alive connection is logically closed after this request and the opposing
// server is informed. An ErrUnexpectedEOF indicates the remote closed the
// underlying TCP connection, which is usually considered as graceful close.
func (cc *ClientConn) Write(req *http.Request) error {
	var err error

	// Ensure ordered execution of Writes
	id := cc.pipe.Next()
	cc.pipe.StartRequest(id)
	defer func() {
		cc.pipe.EndRequest(id)
		if err != nil {
			cc.pipe.StartResponse(id)
			cc.pipe.EndResponse(id)
		} else {
			// Remember the pipeline id of this request
			cc.mu.Lock()
			cc.pipereq[req] = id
			cc.mu.Unlock()
		}
	}()

	cc.mu.Lock()
	if cc.re != nil { // no point sending if read-side closed or broken
		defer cc.mu.Unlock()
		return cc.re
	}
	if cc.we != nil {
		defer cc.mu.Unlock()
		return cc.we
	}
	if cc.c == nil { // connection closed by user in the meantime
		defer cc.mu.Unlock()
		return errClosed
	}
	c := cc.c
	if req.Close {
		// We write the EOF to the write-side error, because there
		// still might be some pipelined reads
		cc.we = ErrPersistEOF
	}
	cc.mu.Unlock()

	err = cc.writeReq(req, c)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if err != nil {
		cc.we = err
		return err
	}
	cc.nwritten++

	return nil
}

// Pending returns the number of unanswered requests
// that have been sent on the connection.
func (cc *ClientConn) Pending() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.nwritten - cc.nread
}

// Read reads the next response from the wire. A valid response might be
// returned together with an [ErrPersistEOF], which means that the remote
// requested that this be the last request serviced. Read can be called
// concurrently with [ClientConn.Write], but not with another Read.
func (cc *ClientConn) Read(req *http.Request) (resp *http.Response, err error) {
	// Retrieve the pipeline ID of this request/response pair
	cc.mu.Lock()
	id, ok := cc.pipereq[req]
	delete(cc.pipereq, req)
	if !ok {
		cc.mu.Unlock()
		return nil, ErrPipeline
	}
	cc.mu.Unlock()

	// Ensure pipeline order
	cc.pipe.StartResponse(id)
	defer cc.pipe.EndResponse(id)

	cc.mu.Lock()
	if cc.re != nil {
		defer cc.mu.Unlock()
		return nil, cc.re
	}
	if cc.r == nil { // connection closed by user in the meantime
		defer cc.mu.Unlock()
		return nil, errClosed
	}
	r := cc.r
	lastbody := cc.lastbody
	cc.lastbody = nil
	cc.mu.Unlock()

	// Make sure body is fully consumed, even if user does not call body.Close
	if lastbody != nil {
		// body.Close is assumed to be idempotent and multiple calls to
		// it should return the error that its first invocation
		// returned.
		err = lastbody.Close()
		if err != nil {
			cc.mu.Lock()
			defer cc.mu.Unlock()
			cc.re = err
			return nil, err
		}
	}

	resp, err = http.ReadResponse(r, req)
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if err != nil {
		cc.re = err
		return resp, err
	}
	cc.lastbody = resp.Body

	cc.nread++

	if resp.Close {
		cc.re = ErrPersistEOF // don't send any more requests
		return resp, cc.re
	}
	return resp, err
}

// Do is convenience method that writes a request and reads a response.
func (cc *ClientConn) Do(req *http.Request) (*http.Response, error) {
	err := cc.Write(req)
	if err != nil {
		return nil, err
	}
	return cc.Read(req)
}
```