Response:
Let's break down the thought process for analyzing the provided Go code snippet for `go/src/net/http/fcgi/child.go`.

**1. Understanding the Goal:**

The primary goal is to explain the functionality of this specific Go file within the `net/http/fcgi` package. This involves identifying its role in the broader FastCGI implementation, detailing its key components, and pinpointing potential pitfalls for developers.

**2. Initial Scan and Keyword Spotting:**

A quick scan of the code reveals important keywords and types:

* `package fcgi`:  Immediately identifies the package.
* `FastCGI`:  Confirms the file's purpose.
* `child`:  Suggests this file deals with the "child" side of the FastCGI interaction (as opposed to the "server" side).
* `request`, `response`:  Indicates handling of HTTP requests and responses within the FastCGI context.
* `conn`:  Likely manages the connection to the FastCGI server.
* `handler http.Handler`:  Points to the integration with the standard `net/http` request handling mechanism.
* `Serve`: A common function name for starting a server.
* `io.Pipe`:  Suggests a mechanism for decoupling data flow.

**3. Deeper Dive into Key Structures and Functions:**

* **`request` struct:**  This seems to hold the state of an incoming FastCGI request. Key fields like `reqId`, `params`, and `rawParams` are important. The `parseParams` method is clearly responsible for decoding FastCGI parameters.
* **`response` struct:**  Represents the response being sent back to the FastCGI server. The integration with `http.ResponseWriter` is evident in methods like `Header()`, `Write()`, and `WriteHeader()`. The `writeCGIHeader` function is specific to FastCGI.
* **`child` struct:** The central structure for managing a single FastCGI connection. It holds the connection (`conn`), the HTTP handler (`handler`), and a map of active requests (`requests`).
* **`serve()` method:** The main loop for processing incoming FastCGI records. It reads records and dispatches them to `handleRecord`.
* **`handleRecord()` method:**  This is the core logic for interpreting FastCGI record types (e.g., `typeBeginRequest`, `typeParams`, `typeStdin`). It's crucial for understanding the FastCGI protocol interaction.
* **`serveRequest()` method:**  This bridges the gap between the FastCGI request and the standard `http.Handler`. It creates an `http.Request` from the FastCGI data and calls the handler.
* **`Serve()` function:** The entry point for starting the FastCGI child process. It handles listening for connections and creating `child` instances.
* **`ProcessEnv()` function:** This function extracts environment variables specific to the FastCGI request that aren't directly part of the `http.Request`.

**4. Inferring Functionality and Generating Examples:**

Based on the code analysis, we can infer the primary functions:

* **Receiving and Parsing FastCGI Requests:**  The `handleRecord` method handles different FastCGI record types, extracting request IDs, parameters, and the request body. The `parseParams` method decodes the parameter data.
* **Mapping to `http.Request`:**  The `serveRequest` function shows how the FastCGI request data is transformed into an `http.Request` object, enabling the use of standard Go HTTP handlers. The use of `cgi.RequestFromMap` is key here.
* **Handling Responses:** The `response` struct implements `http.ResponseWriter`, allowing the handler to generate standard HTTP responses. The `writeCGIHeader` method formats the headers according to the FastCGI specification.
* **Managing Connections:** The `child` struct and its `serve` method manage the lifecycle of a FastCGI connection.

To illustrate these points, we can create Go code examples:

* **Illustrating `ProcessEnv`:** This is straightforward as it directly interacts with the `http.Request` context.
* **Illustrating `Serve`:** This shows how to start a FastCGI server using the `fcgi.Serve` function, listening on a network socket or standard input.

**5. Identifying Potential Pitfalls:**

By carefully examining the code, we can identify potential issues:

* **Blocking on `req.pw.Write()`:** The comment in `handleRecord` highlights a potential blocking issue if the handler is slow to consume the request body.
* **Ignoring unknown request IDs:**  While the spec says to ignore them, it's something to be aware of during debugging.
* **Body consumption in `serveRequest`:** The comment about consuming the entire body to avoid RST errors is a significant point.

**6. Structuring the Answer:**

Finally, the information needs to be organized logically and presented clearly in Chinese, as requested:

* **功能列表:**  Start with a concise summary of the file's main functions.
* **Go语言功能实现推理:** Explain *how* the code implements FastCGI, linking specific code sections to FastCGI concepts. Provide the Go code examples here to illustrate the `Serve` and `ProcessEnv` functions.
* **代码推理 (with assumptions):**  Elaborate on specific code sections like `handleRecord` and `serveRequest`, detailing the assumed inputs and outputs based on the FastCGI protocol.
* **命令行参数处理:** Since the provided code doesn't directly handle command-line arguments, explicitly state that. The `Serve` function can take a `net.Listener`, which *could* be based on command-line configuration in a larger application, but that's outside the scope of *this* file.
* **使用者易犯错的点:** Clearly list the potential pitfalls identified during the code analysis.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus on the low-level byte handling.
* **Correction:** Shift focus to the higher-level functionality and how it relates to standard `net/http`. The low-level details are important but supporting the main purpose.
* **Initial thought:**  Provide a very detailed breakdown of each FastCGI record type.
* **Correction:**  Keep it concise, focusing on the key record types and their handling in the code. Overly detailed explanations might be too much for the initial request.
* **Initial thought:**  Assume specific command-line arguments.
* **Correction:**  Stick to what the code *actually* does. Acknowledge that a larger application might use command-line arguments, but this file itself doesn't directly parse them.

By following these steps, combining careful code reading with an understanding of the FastCGI protocol, and focusing on the user's request for clarity and actionable information, we can construct a comprehensive and helpful answer.
这段代码是 Go 语言 `net/http/fcgi` 包中 `child.go` 文件的一部分，它实现了 **FastCGI 协议中子进程（或应用进程）的功能**。

**功能列表:**

1. **接收和解析来自 FastCGI Web 服务器的请求:**  代码定义了 `request` 结构体来存储单个请求的状态，包括请求 ID、参数、原始参数数据等。 `handleRecord` 函数负责接收来自服务器的 FastCGI 记录，并根据记录类型进行处理，例如 `typeBeginRequest` 开始新的请求， `typeParams` 接收请求参数，`typeStdin` 接收请求体。
2. **将 FastCGI 请求转换为 `http.Request`:** `serveRequest` 函数将解析出的 FastCGI 请求信息（参数、请求体等）转换为标准的 `net/http.Request` 对象，以便能够使用 Go 标准库中的 HTTP 处理逻辑。
3. **处理 HTTP 请求:** `serveRequest` 函数调用用户提供的 `http.Handler` 来处理转换后的 `http.Request`。
4. **将 `http.ResponseWriter` 的输出转换为 FastCGI 响应:** 代码定义了 `response` 结构体，它实现了 `http.ResponseWriter` 接口。当用户的 Handler 向 `response` 写入数据或设置 Header 时，这些操作会被转换为符合 FastCGI 协议的响应数据，并通过连接发送回 Web 服务器。
5. **管理 FastCGI 连接:** `child` 结构体代表一个 FastCGI 子进程，它维护着与 Web 服务器的连接 (`conn`) 以及当前正在处理的请求 (`requests`)。 `serve` 函数是子进程的主循环，负责读取和处理来自连接的数据。
6. **处理 FastCGI 特定的控制消息:** 例如 `typeGetValues` 用于获取服务器的配置信息，`typeAbortRequest` 用于处理请求中止。
7. **处理环境变量:** `ProcessEnv` 函数允许获取 FastCGI 请求相关的环境变量，这些变量可能没有直接包含在 `http.Request` 中，而是存储在请求的上下文中。

**Go 语言功能实现推理 (使用代码举例):**

这段代码主要实现了 **FastCGI 协议的服务器端 (子进程) 的逻辑**，允许 Go 应用作为 FastCGI 应用运行在支持 FastCGI 的 Web 服务器 (如 Nginx, Apache) 后面。

**示例：使用 `fcgi.Serve` 启动 FastCGI 子进程**

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/fcgi"
	"net"
	"os"
)

func myHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from FastCGI!\n")
	fmt.Fprintf(w, "Request URI: %s\n", r.RequestURI)
	env := fcgi.ProcessEnv(r)
	fmt.Fprintf(w, "Remote User: %s\n", env["REMOTE_USER"]) // 获取 FastCGI 环境变量
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:9000") // 监听 TCP 端口
	if err != nil {
		fmt.Println("监听失败:", err)
		os.Exit(1)
	}
	defer listener.Close()

	handler := http.HandlerFunc(myHandler)
	err = fcgi.Serve(listener, handler)
	if err != nil {
		fmt.Println("FastCGI 服务启动失败:", err)
		os.Exit(1)
	}
}
```

**假设的输入与输出 (针对 `handleRecord` 函数):**

**假设输入：**

接收到一个 `typeParams` 类型的 FastCGI 记录，其 `rec.content()` 返回包含以下参数的字节切片（FastCGI 参数以长度-值对编码）：

```
\x00\x04KEY1\x00\x06VALUE1\x00\x04KEY2\x00\x06VALUE2
```

这表示两个参数：`KEY1=VALUE1` 和 `KEY2=VALUE2`。同时假设 `rec.h.Id` 为 `1`，表示这个参数记录属于请求 ID 为 `1` 的请求。

**假设输出：**

在 `handleRecord` 函数中，当处理到 `typeParams` 类型的记录时，会找到对应的 `request` 对象（假设已经通过 `typeBeginRequest` 创建），并调用 `req.parseParams()`。 `req.parseParams()` 会解析字节切片，并将参数存储到 `req.params` map 中。最终，对于请求 ID 为 `1` 的请求对象 `req`，其 `req.params` 将包含：

```
map[string]string{"KEY1": "VALUE1", "KEY2": "VALUE2"}
```

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。`fcgi.Serve` 函数主要接受一个 `net.Listener` 和一个 `http.Handler` 作为参数。

* **`net.Listener`:**  可以是从 `net.Listen` 创建的监听器（如上面的 TCP 示例），也可以是通过 `net.FileListener(os.Stdin)` 创建的基于标准输入的监听器。后者常用于传统的 CGI 或 FastCGI 部署方式，Web 服务器会将连接通过标准输入传递给 FastCGI 子进程。
* **`http.Handler`:**  是处理 HTTP 请求的实际逻辑。

如果需要通过命令行参数配置 FastCGI 监听的地址或端口，需要在调用 `fcgi.Serve` 之前进行处理，例如使用 `flag` 包解析命令行参数，然后根据参数创建 `net.Listener`。

**示例：使用命令行参数配置监听地址**

```go
package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/fcgi"
	"net"
	"os"
)

var addr = flag.String("addr", "127.0.0.1:9000", "监听地址和端口")

// ... (myHandler 函数保持不变)

func main() {
	flag.Parse() // 解析命令行参数

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Println("监听失败:", err)
		os.Exit(1)
	}
	defer listener.Close()

	handler := http.HandlerFunc(myHandler)
	err = fcgi.Serve(listener, handler)
	if err != nil {
		fmt.Println("FastCGI 服务启动失败:", err)
		os.Exit(1)
	}
}
```

在这个例子中，可以使用 `go run main.go -addr=:8080` 来指定监听端口为 8080。

**使用者易犯错的点：**

1. **没有正确处理请求体:**  FastCGI 的请求体是通过 `typeStdin` 类型的记录发送的。开发者需要确保他们的 `http.Handler` 正确读取 `r.Body` 中的数据。如果没有读取完 `r.Body`，可能会导致连接阻塞或异常。

   **示例错误：**

   ```go
   func myHandler(w http.ResponseWriter, r *http.Request) {
       // 没有读取 r.Body
       fmt.Fprintf(w, "Processed request.\n")
   }
   ```

   **正确做法：**

   ```go
   import "io/ioutil"

   func myHandler(w http.ResponseWriter, r *http.Request) {
       body, _ := ioutil.ReadAll(r.Body) // 读取请求体
       r.Body.Close() // 记得关闭 body
       fmt.Fprintf(w, "Processed request with body: %s\n", body)
   }
   ```

2. **在 Handler 中过早关闭 `http.ResponseWriter`:**  `fcgi.Serve` 会管理 `response` 的生命周期和 FastCGI 消息的发送。在 Handler 中手动关闭 `w` (类型为 `*response`) 可能会导致提前发送响应，或者在后续的 FastCGI 处理中出现错误。应该让 `fcgi.Serve` 来负责关闭连接。

   **示例错误：**

   ```go
   func myHandler(w http.ResponseWriter, r *http.Request) {
       fmt.Fprintf(w, "Hello!\n")
       w.(*fcgi.response).Close() // 不应该手动关闭
   }
   ```

   **正确做法：**  只需在 Handler 中正常使用 `http.ResponseWriter` 的方法 (如 `Write`, `WriteHeader`) 即可。

3. **对 FastCGI 协议的理解不足:**  FastCGI 协议是基于记录的，需要理解不同记录类型的含义和交互方式。如果对协议理解不足，可能会在处理请求或响应时出现逻辑错误。

这段代码是 Go 语言标准库中实现 FastCGI 的关键部分，它抽象了底层的 FastCGI 协议细节，使得开发者可以使用熟悉的 `net/http` 包的接口来开发 FastCGI 应用。

### 提示词
```
这是路径为go/src/net/http/fcgi/child.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fcgi

// This file implements FastCGI from the perspective of a child process.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"os"
	"strings"
	"time"
)

// request holds the state for an in-progress request. As soon as it's complete,
// it's converted to an http.Request.
type request struct {
	pw        *io.PipeWriter
	reqId     uint16
	params    map[string]string
	buf       [1024]byte
	rawParams []byte
	keepConn  bool
}

// envVarsContextKey uniquely identifies a mapping of CGI
// environment variables to their values in a request context
type envVarsContextKey struct{}

func newRequest(reqId uint16, flags uint8) *request {
	r := &request{
		reqId:    reqId,
		params:   map[string]string{},
		keepConn: flags&flagKeepConn != 0,
	}
	r.rawParams = r.buf[:0]
	return r
}

// parseParams reads an encoded []byte into Params.
func (r *request) parseParams() {
	text := r.rawParams
	r.rawParams = nil
	for len(text) > 0 {
		keyLen, n := readSize(text)
		if n == 0 {
			return
		}
		text = text[n:]
		valLen, n := readSize(text)
		if n == 0 {
			return
		}
		text = text[n:]
		if int(keyLen)+int(valLen) > len(text) {
			return
		}
		key := readString(text, keyLen)
		text = text[keyLen:]
		val := readString(text, valLen)
		text = text[valLen:]
		r.params[key] = val
	}
}

// response implements http.ResponseWriter.
type response struct {
	req            *request
	header         http.Header
	code           int
	wroteHeader    bool
	wroteCGIHeader bool
	w              *bufWriter
}

func newResponse(c *child, req *request) *response {
	return &response{
		req:    req,
		header: http.Header{},
		w:      newWriter(c.conn, typeStdout, req.reqId),
	}
}

func (r *response) Header() http.Header {
	return r.header
}

func (r *response) Write(p []byte) (n int, err error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if !r.wroteCGIHeader {
		r.writeCGIHeader(p)
	}
	return r.w.Write(p)
}

func (r *response) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.code = code
	if code == http.StatusNotModified {
		// Must not have body.
		r.header.Del("Content-Type")
		r.header.Del("Content-Length")
		r.header.Del("Transfer-Encoding")
	}
	if r.header.Get("Date") == "" {
		r.header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}
}

// writeCGIHeader finalizes the header sent to the client and writes it to the output.
// p is not written by writeHeader, but is the first chunk of the body
// that will be written. It is sniffed for a Content-Type if none is
// set explicitly.
func (r *response) writeCGIHeader(p []byte) {
	if r.wroteCGIHeader {
		return
	}
	r.wroteCGIHeader = true
	fmt.Fprintf(r.w, "Status: %d %s\r\n", r.code, http.StatusText(r.code))
	if _, hasType := r.header["Content-Type"]; r.code != http.StatusNotModified && !hasType {
		r.header.Set("Content-Type", http.DetectContentType(p))
	}
	r.header.Write(r.w)
	r.w.WriteString("\r\n")
	r.w.Flush()
}

func (r *response) Flush() {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	r.w.Flush()
}

func (r *response) Close() error {
	r.Flush()
	return r.w.Close()
}

type child struct {
	conn    *conn
	handler http.Handler

	requests map[uint16]*request // keyed by request ID
}

func newChild(rwc io.ReadWriteCloser, handler http.Handler) *child {
	return &child{
		conn:     newConn(rwc),
		handler:  handler,
		requests: make(map[uint16]*request),
	}
}

func (c *child) serve() {
	defer c.conn.Close()
	defer c.cleanUp()
	var rec record
	for {
		if err := rec.read(c.conn.rwc); err != nil {
			return
		}
		if err := c.handleRecord(&rec); err != nil {
			return
		}
	}
}

var errCloseConn = errors.New("fcgi: connection should be closed")

var emptyBody = io.NopCloser(strings.NewReader(""))

// ErrRequestAborted is returned by Read when a handler attempts to read the
// body of a request that has been aborted by the web server.
var ErrRequestAborted = errors.New("fcgi: request aborted by web server")

// ErrConnClosed is returned by Read when a handler attempts to read the body of
// a request after the connection to the web server has been closed.
var ErrConnClosed = errors.New("fcgi: connection to web server closed")

func (c *child) handleRecord(rec *record) error {
	req, ok := c.requests[rec.h.Id]
	if !ok && rec.h.Type != typeBeginRequest && rec.h.Type != typeGetValues {
		// The spec says to ignore unknown request IDs.
		return nil
	}

	switch rec.h.Type {
	case typeBeginRequest:
		if req != nil {
			// The server is trying to begin a request with the same ID
			// as an in-progress request. This is an error.
			return errors.New("fcgi: received ID that is already in-flight")
		}

		var br beginRequest
		if err := br.read(rec.content()); err != nil {
			return err
		}
		if br.role != roleResponder {
			c.conn.writeEndRequest(rec.h.Id, 0, statusUnknownRole)
			return nil
		}
		req = newRequest(rec.h.Id, br.flags)
		c.requests[rec.h.Id] = req
		return nil
	case typeParams:
		// NOTE(eds): Technically a key-value pair can straddle the boundary
		// between two packets. We buffer until we've received all parameters.
		if len(rec.content()) > 0 {
			req.rawParams = append(req.rawParams, rec.content()...)
			return nil
		}
		req.parseParams()
		return nil
	case typeStdin:
		content := rec.content()
		if req.pw == nil {
			var body io.ReadCloser
			if len(content) > 0 {
				// body could be an io.LimitReader, but it shouldn't matter
				// as long as both sides are behaving.
				body, req.pw = io.Pipe()
			} else {
				body = emptyBody
			}
			go c.serveRequest(req, body)
		}
		if len(content) > 0 {
			// TODO(eds): This blocks until the handler reads from the pipe.
			// If the handler takes a long time, it might be a problem.
			req.pw.Write(content)
		} else {
			delete(c.requests, req.reqId)
			if req.pw != nil {
				req.pw.Close()
			}
		}
		return nil
	case typeGetValues:
		values := map[string]string{"FCGI_MPXS_CONNS": "1"}
		c.conn.writePairs(typeGetValuesResult, 0, values)
		return nil
	case typeData:
		// If the filter role is implemented, read the data stream here.
		return nil
	case typeAbortRequest:
		delete(c.requests, rec.h.Id)
		c.conn.writeEndRequest(rec.h.Id, 0, statusRequestComplete)
		if req.pw != nil {
			req.pw.CloseWithError(ErrRequestAborted)
		}
		if !req.keepConn {
			// connection will close upon return
			return errCloseConn
		}
		return nil
	default:
		b := make([]byte, 8)
		b[0] = byte(rec.h.Type)
		c.conn.writeRecord(typeUnknownType, 0, b)
		return nil
	}
}

// filterOutUsedEnvVars returns a new map of env vars without the
// variables in the given envVars map that are read for creating each http.Request
func filterOutUsedEnvVars(envVars map[string]string) map[string]string {
	withoutUsedEnvVars := make(map[string]string)
	for k, v := range envVars {
		if addFastCGIEnvToContext(k) {
			withoutUsedEnvVars[k] = v
		}
	}
	return withoutUsedEnvVars
}

func (c *child) serveRequest(req *request, body io.ReadCloser) {
	r := newResponse(c, req)
	httpReq, err := cgi.RequestFromMap(req.params)
	if err != nil {
		// there was an error reading the request
		r.WriteHeader(http.StatusInternalServerError)
		c.conn.writeRecord(typeStderr, req.reqId, []byte(err.Error()))
	} else {
		httpReq.Body = body
		withoutUsedEnvVars := filterOutUsedEnvVars(req.params)
		envVarCtx := context.WithValue(httpReq.Context(), envVarsContextKey{}, withoutUsedEnvVars)
		httpReq = httpReq.WithContext(envVarCtx)
		c.handler.ServeHTTP(r, httpReq)
	}
	// Make sure we serve something even if nothing was written to r
	r.Write(nil)
	r.Close()
	c.conn.writeEndRequest(req.reqId, 0, statusRequestComplete)

	// Consume the entire body, so the host isn't still writing to
	// us when we close the socket below in the !keepConn case,
	// otherwise we'd send a RST. (golang.org/issue/4183)
	// TODO(bradfitz): also bound this copy in time. Or send
	// some sort of abort request to the host, so the host
	// can properly cut off the client sending all the data.
	// For now just bound it a little and
	io.CopyN(io.Discard, body, 100<<20)
	body.Close()

	if !req.keepConn {
		c.conn.Close()
	}
}

func (c *child) cleanUp() {
	for _, req := range c.requests {
		if req.pw != nil {
			// race with call to Close in c.serveRequest doesn't matter because
			// Pipe(Reader|Writer).Close are idempotent
			req.pw.CloseWithError(ErrConnClosed)
		}
	}
}

// Serve accepts incoming FastCGI connections on the listener l, creating a new
// goroutine for each. The goroutine reads requests and then calls handler
// to reply to them.
// If l is nil, Serve accepts connections from os.Stdin.
// If handler is nil, [http.DefaultServeMux] is used.
func Serve(l net.Listener, handler http.Handler) error {
	if l == nil {
		var err error
		l, err = net.FileListener(os.Stdin)
		if err != nil {
			return err
		}
		defer l.Close()
	}
	if handler == nil {
		handler = http.DefaultServeMux
	}
	for {
		rw, err := l.Accept()
		if err != nil {
			return err
		}
		c := newChild(rw, handler)
		go c.serve()
	}
}

// ProcessEnv returns FastCGI environment variables associated with the request r
// for which no effort was made to be included in the request itself - the data
// is hidden in the request's context. As an example, if REMOTE_USER is set for a
// request, it will not be found anywhere in r, but it will be included in
// ProcessEnv's response (via r's context).
func ProcessEnv(r *http.Request) map[string]string {
	env, _ := r.Context().Value(envVarsContextKey{}).(map[string]string)
	return env
}

// addFastCGIEnvToContext reports whether to include the FastCGI environment variable s
// in the http.Request.Context, accessible via ProcessEnv.
func addFastCGIEnvToContext(s string) bool {
	// Exclude things supported by net/http natively:
	switch s {
	case "CONTENT_LENGTH", "CONTENT_TYPE", "HTTPS",
		"PATH_INFO", "QUERY_STRING", "REMOTE_ADDR",
		"REMOTE_HOST", "REMOTE_PORT", "REQUEST_METHOD",
		"REQUEST_URI", "SCRIPT_NAME", "SERVER_PROTOCOL":
		return false
	}
	if strings.HasPrefix(s, "HTTP_") {
		return false
	}
	// Explicitly include FastCGI-specific things.
	// This list is redundant with the default "return true" below.
	// Consider this documentation of the sorts of things we expect
	// to maybe see.
	switch s {
	case "REMOTE_USER":
		return true
	}
	// Unknown, so include it to be safe.
	return true
}
```