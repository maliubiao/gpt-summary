Response:
我的目标是对提供的 Go 代码片段进行功能分析、使用场景推断、代码示例构建、潜在错误点说明，并全部用中文回答。

**第一步：通读代码，识别核心结构和类型**

我首先会浏览代码，关注主要类型定义（`transferWriter`、`transferReader`、`body` 等）和关键函数（`newTransferWriter`、`writeHeader`、`writeBody`、`readTransfer` 等）。通过类型定义，我可以初步了解代码处理的数据结构，例如请求和响应的头部、主体、传输编码等信息。关键函数则揭示了代码的主要操作，比如写入头部、写入主体、读取数据等。

**第二步：分析各个类型和函数的功能**

* **`transferWriter`**:  这个结构体很明显是用来处理 HTTP 请求或响应的写入过程。它的字段包含了写入所需的所有信息：方法、主体、内容长度、传输编码、头部、尾部等。`newTransferWriter` 函数负责根据传入的 `Request` 或 `Response` 初始化 `transferWriter`，并进行一些必要的校验和规范化操作。`writeHeader` 和 `writeBody` 函数分别负责将 HTTP 头部和主体写入底层的 `io.Writer`。

* **`transferReader`**:  与 `transferWriter` 相对，这个结构体用于处理 HTTP 请求或响应的读取过程。它的字段包含了读取到的头部信息，以及用于读取主体的 `io.ReadCloser`。 `readTransfer` 函数是核心，它负责解析 HTTP 头部，根据头部信息（如 `Transfer-Encoding` 和 `Content-Length`）创建合适的 `io.ReadCloser` 来读取主体，并将结果存储在传入的 `Request` 或 `Response` 结构体中。

* **`body`**:  这是一个 `io.ReadCloser` 的实现，用于封装 HTTP 消息的主体读取。它处理分块传输的解码，并在读取完成后处理 Trailer 头部。`Close` 方法会确保主体被完全读取，并读取 Trailer。

* **辅助函数**: 还有一些辅助函数，如 `chunked` 用于判断是否使用分块传输，`fixLength` 用于确定消息体的预期长度，`shouldClose` 用于判断连接是否应该关闭， `parseContentLength` 用于解析 `Content-Length` 头部等。

**第三步：推断代码实现的 Go 语言功能**

通过分析 `transferWriter` 和 `transferReader` 的功能，我可以推断出这段代码是 `net/http` 包中处理 HTTP 请求和响应传输的核心逻辑。它负责将高级的 `Request` 和 `Response` 结构体转换为可以在网络上传输的字节流，以及将接收到的字节流解析为 `Request` 和 `Response` 结构体。  这涉及到处理不同的传输编码方式（如分块传输）、处理 `Content-Length` 头部、处理连接管理（`Connection: close` 或 `keep-alive`）等。

**第四步：构建代码示例**

针对 `transferWriter` 和 `transferReader` 的功能，我可以分别构建发送请求和接收响应的示例代码。  发送请求的例子会创建一个 `Request` 对象，设置头部和主体，然后使用 `transferWriter` 将其写入一个 `io.Pipe` 的 writer 端，并从 reader 端读取发送出去的内容。接收响应的例子会模拟从网络接收到的 HTTP 响应，将其写入一个 `bytes.Buffer`，然后使用 `bufio.Reader` 读取，并用 `transferReader` 解析成 `Response` 对象。

**第五步：识别潜在的错误点**

我需要仔细分析代码中可能出现错误的地方，特别是使用者容易犯错的地方。例如，设置了 `ContentLength` 但 `Body` 为 `nil`，或者在使用了分块传输时错误地设置了 `ContentLength`，这些都是潜在的错误点。此外，在读取响应 body 之后尝试再次读取也会导致错误。

**第六步：组织答案，使用中文**

最后，我将所有分析结果组织成中文答案，确保表达清晰易懂。  我会按照提问的要求，分别列举功能、推断 Go 语言功能并举例、说明代码推理过程、解释命令行参数处理（虽然这段代码没有直接处理命令行参数，但可以说明相关概念）、以及指出易犯错误点。

**代码推理过程的自我审视:**

在构建代码示例时，我需要模拟输入和预期输出。对于发送请求的例子，输入是构造的 `Request` 对象，输出是写入 `io.Pipe` 的字节流。对于接收响应的例子，输入是模拟的 HTTP 响应字符串，输出是解析后的 `Response` 对象。

**命令行参数处理的自我审视:**

虽然代码本身没有直接处理命令行参数，但 `internal/godebug` 包的使用可以被提及，说明 Go 运行时的一些行为可以通过环境变量或命令行参数进行配置。

**易犯错误点的自我审视:**

我需要确保列举的错误点是实际可能发生的，并且能够通过代码分析找到依据。例如，`ContentLength` 和 `Transfer-Encoding` 的冲突，以及 body 的重复读取等。

通过以上步骤，我能够系统地分析提供的 Go 代码片段，并给出符合要求的中文解答。
这段代码是 Go 语言 `net/http` 包中 `transfer.go` 文件的一部分，它主要负责处理 HTTP 请求和响应的 **传输编码 (Transfer Encoding)** 和 **内容长度 (Content Length)** 相关的逻辑。 它的核心目标是确保 HTTP 消息的正确构建和解析，以便客户端和服务器能够可靠地交换数据。

**功能列举:**

1. **`transferWriter` 结构体和相关函数 (`newTransferWriter`, `writeHeader`, `writeBody`)**:
   - **封装 HTTP 请求或响应的写入逻辑**: 它接收一个 `Request` 或 `Response` 对象，并从中提取出需要写入网络连接的关键信息，如方法、Body、头部、尾部等。
   - **处理 `Content-Length` 和 `Transfer-Encoding` 头部**:  根据请求或响应的 Body、已设置的头部信息，以及 HTTP 协议版本，决定如何设置 `Content-Length` 和 `Transfer-Encoding` 头部。例如，如果 Body 不为 `nil` 且未明确设置 `Content-Length`，则可能会添加 `Transfer-Encoding: chunked` 头部。
   - **支持分块传输编码 (Chunked Transfer Encoding)**:  当需要发送未知大小的 Body 时，它会使用分块传输编码，将 Body 分成多个块进行发送，并在最后发送一个空块表示结束。
   - **写入 HTTP 头部**:  `writeHeader` 函数负责将构造好的 HTTP 头部信息写入底层的 `io.Writer`。
   - **写入 HTTP Body**: `writeBody` 函数负责将 HTTP Body 写入底层的 `io.Writer`，根据是否使用了分块传输进行相应的处理。
   - **写入 HTTP Trailer (尾部)**:  如果使用了分块传输，并且设置了 `Trailer` 头部，`writeBody` 会在 Body 结束后写入 Trailer 头部。
   - **探测请求 Body**:  对于某些不应该有 Body 的请求方法（如 GET），如果用户设置了 Body 但未设置 `Content-Length`，它会尝试读取 Body 的第一个字节来判断 Body 是否为空，从而避免发送不必要的 chunked Body。

2. **`transferReader` 结构体和相关函数 (`readTransfer`, `parseTransferEncoding`, `fixLength`, `fixTrailer`)**:
   - **封装 HTTP 请求或响应的读取逻辑**:  它接收一个 `Request` 或 `Response` 对象和一个 `bufio.Reader`，用于从网络连接读取数据。
   - **解析 `Transfer-Encoding` 头部**: `parseTransferEncoding` 函数解析 `Transfer-Encoding` 头部，判断是否使用了分块传输。目前只支持 `chunked` 编码。
   - **确定消息体的预期长度**: `fixLength` 函数根据 `Content-Length` 头部和 `Transfer-Encoding` 头部来确定消息体的预期长度。如果使用了分块传输，`Content-Length` 将被忽略。
   - **处理 HTTP Trailer (尾部)**: `fixTrailer` 函数解析 `Trailer` 头部，如果使用了分块传输，会将 Trailer 头部信息存储到 `Response` 或 `Request` 的 `Trailer` 字段中。
   - **创建用于读取 Body 的 `io.ReadCloser`**: 根据解析出的传输编码和内容长度信息，创建合适的 `io.ReadCloser` 用于读取 Body。如果是分块传输，会使用 `internal.NewChunkedReader`。如果指定了 `Content-Length`，会使用 `io.LimitReader`。
   - **处理连接关闭**: 根据 HTTP 协议版本和 `Connection` 头部判断是否需要在读取完当前消息后关闭连接。

3. **`body` 结构体**:
   - **作为 `io.ReadCloser` 封装 HTTP Body 的读取**: 它包装了底层的 `io.Reader`，并提供了 `Close` 方法。
   - **处理分块传输解码**:  如果使用了分块传输，它的 `Read` 方法会负责解码分块数据。
   - **读取 HTTP Trailer (尾部)**:  在读取完分块传输的最后一个空块后，它的 `readTrailer` 方法会读取并解析 Trailer 头部。
   - **防止重复读取**: `Close` 方法确保 Body 被完全读取，防止连接复用时出现问题。

**推断 Go 语言功能的实现:**

这段代码是 `net/http` 包实现 HTTP 协议的核心部分，它处理了 HTTP/1.x 的消息体传输。

**Go 代码示例:**

以下示例演示了如何使用 `transferWriter` 手动构建一个 HTTP 请求：

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
)

func main() {
	bodyData := []byte("This is the request body.")
	req, err := http.NewRequest("POST", "http://example.com", bytes.NewReader(bodyData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "text/plain")

	// 手动创建 transferWriter
	tw, err := newTransferWriter(req)
	if err != nil {
		fmt.Println("Error creating transferWriter:", err)
		return
	}

	// 创建一个用于写入的 buffer
	var buf bytes.Buffer

	// 写入头部
	err = tw.writeHeader(&buf, &httptrace.ClientTrace{})
	if err != nil {
		fmt.Println("Error writing header:", err)
		return
	}
	buf.WriteString("\r\n") // 头部和 Body 之间需要一个空行

	// 写入 Body
	err = tw.writeBody(&buf)
	if err != nil {
		fmt.Println("Error writing body:", err)
		return
	}

	fmt.Println(buf.String())

	// 模拟接收响应 (简化示例)
	respStr := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 19\r\n\r\nThis is the response"
	respBuf := bytes.NewBufferString(respStr)
	br := textproto.NewReader(bufio.NewReader(respBuf))
	resp, err := http.ReadResponse(br.R, nil)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println("Response Body:", string(respBody))
}
```

**假设输入与输出 (针对 `transferWriter` 示例):**

**输入:** 一个 `http.Request` 对象，包含方法 (POST), URL, 头部 (Content-Type), 和 Body (`"This is the request body."`)。

**输出:** 写入 `bytes.Buffer` 的 HTTP 请求字符串，例如：

```
POST / HTTP/1.1
Host: example.com
Content-Type: text/plain
Content-Length: 24
User-Agent: Go-http-client/1.1

This is the request body.
```

**假设输入与输出 (针对 `transferReader` 示例，在上面的代码中有所体现):**

**输入:** 一个包含 HTTP 响应字符串的 `bytes.Buffer`。

**输出:** 一个 `http.Response` 对象，其 `StatusCode` 为 200，头部包含 `Content-Type` 和 `Content-Length`，并且 `Body` 可以读取到 `"This is the response"`。

**代码推理:**

`newTransferWriter` 函数会检查 `Request` 的 `ContentLength` 和 `Body`，如果 `ContentLength` 不为 0 但 `Body` 为 `nil`，则会返回错误。它还会根据 `Request` 的属性和 HTTP 协议版本决定是否添加 `Transfer-Encoding: chunked` 头部。 `writeHeader` 函数会将 `Connection`, `Content-Length`, `Transfer-Encoding`, `Trailer` 等头部写入 `io.Writer`。 `writeBody` 函数会根据 `Transfer-Encoding` 的值选择直接写入 Body 或者使用分块编码写入。

`readTransfer` 函数会解析 HTTP 头部，根据 `Transfer-Encoding` 和 `Content-Length` 的值来决定如何读取 Body。`parseTransferEncoding` 负责解析 `Transfer-Encoding` 头部，`fixLength` 负责确定 Body 的长度。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。但是，`internal/godebug` 包被用于启用或禁用一些调试特性，这通常可以通过设置环境变量来实现，例如：

```bash
export GODEBUG=httplaxcontentlength=1
```

在这个例子中，`httplaxcontentlength` 是一个调试选项，可以通过设置环境变量 `GODEBUG` 来启用。当设置为 `1` 时，它会允许解析空的 `Content-Length` 头部，并将其视为没有设置 `Content-Length`。

**使用者易犯错的点:**

1. **同时设置 `Content-Length` 和 `Transfer-Encoding: chunked`**:  HTTP/1.1 规范中明确指出，如果同时存在这两个头部，`Transfer-Encoding` 优先，`Content-Length` 应该被忽略。但是，某些服务器或代理可能会因此产生歧义，导致请求处理错误或安全问题（HTTP 请求走私）。这段代码会优先处理 `Transfer-Encoding`。

2. **在使用了分块传输后，没有发送空的终止块**:  如果手动构建使用了分块传输的请求或响应，必须确保在所有数据块发送完毕后，发送一个空的块 (`0\r\n\r\n`)，否则接收方会一直等待更多数据。这段代码中的 `internal.ChunkedWriter` 负责处理这个问题。

3. **读取完 Body 后没有正确关闭**:  `Response.Body` 和 `Request.Body` 都是 `io.ReadCloser` 类型，使用完毕后必须调用 `Close()` 方法。对于接收到的分块传输的响应，`Close()` 方法还会负责读取并处理 Trailer 头部。如果没有正确关闭，可能会导致资源泄露或连接无法复用。

4. **错误地假设没有 Body 的请求 (如 GET, HEAD) 可以设置 `Content-Length`**:  虽然规范允许，但实践中，对于这些方法设置 `Content-Length` 并发送 Body 是不常见的，可能会导致某些服务器行为异常。这段代码中的 `shouldSendChunkedRequestBody` 方法会尝试避免为通常没有 Body 的请求发送 chunked Body。

5. **手动设置 `Transfer-Encoding` 为非 `chunked` 的值**:  `net/http` 包主要支持 `chunked` 编码。手动设置其他值可能会导致不可预测的行为，因为底层的处理逻辑可能没有实现对其他编码的支持。这段代码中的 `parseTransferEncoding` 就只接受 `chunked`。

总之，`go/src/net/http/transfer.go` 中的代码是 `net/http` 包中至关重要的部分，它负责处理 HTTP 消息的传输细节，确保客户端和服务器之间能够正确地通信。理解这段代码的功能有助于我们更好地理解 HTTP 协议以及如何在 Go 中构建和处理 HTTP 请求和响应。

Prompt: 
```
这是路径为go/src/net/http/transfer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"internal/godebug"
	"io"
	"maps"
	"net/http/httptrace"
	"net/http/internal"
	"net/http/internal/ascii"
	"net/textproto"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

// ErrLineTooLong is returned when reading request or response bodies
// with malformed chunked encoding.
var ErrLineTooLong = internal.ErrLineTooLong

type errorReader struct {
	err error
}

func (r errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

type byteReader struct {
	b    byte
	done bool
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	if br.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	br.done = true
	p[0] = br.b
	return 1, io.EOF
}

// transferWriter inspects the fields of a user-supplied Request or Response,
// sanitizes them without changing the user object and provides methods for
// writing the respective header, body and trailer in wire format.
type transferWriter struct {
	Method           string
	Body             io.Reader
	BodyCloser       io.Closer
	ResponseToHEAD   bool
	ContentLength    int64 // -1 means unknown, 0 means exactly none
	Close            bool
	TransferEncoding []string
	Header           Header
	Trailer          Header
	IsResponse       bool
	bodyReadError    error // any non-EOF error from reading Body

	FlushHeaders bool            // flush headers to network before body
	ByteReadCh   chan readResult // non-nil if probeRequestBody called
}

func newTransferWriter(r any) (t *transferWriter, err error) {
	t = &transferWriter{}

	// Extract relevant fields
	atLeastHTTP11 := false
	switch rr := r.(type) {
	case *Request:
		if rr.ContentLength != 0 && rr.Body == nil {
			return nil, fmt.Errorf("http: Request.ContentLength=%d with nil Body", rr.ContentLength)
		}
		t.Method = valueOrDefault(rr.Method, "GET")
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.outgoingLength()
		if t.ContentLength < 0 && len(t.TransferEncoding) == 0 && t.shouldSendChunkedRequestBody() {
			t.TransferEncoding = []string{"chunked"}
		}
		// If there's a body, conservatively flush the headers
		// to any bufio.Writer we're writing to, just in case
		// the server needs the headers early, before we copy
		// the body and possibly block. We make an exception
		// for the common standard library in-memory types,
		// though, to avoid unnecessary TCP packets on the
		// wire. (Issue 22088.)
		if t.ContentLength != 0 && !isKnownInMemoryReader(t.Body) {
			t.FlushHeaders = true
		}

		atLeastHTTP11 = true // Transport requests are always 1.1 or 2.0
	case *Response:
		t.IsResponse = true
		if rr.Request != nil {
			t.Method = rr.Request.Method
		}
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.ContentLength
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		atLeastHTTP11 = rr.ProtoAtLeast(1, 1)
		t.ResponseToHEAD = noResponseBodyExpected(t.Method)
	}

	// Sanitize Body,ContentLength,TransferEncoding
	if t.ResponseToHEAD {
		t.Body = nil
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		}
	} else {
		if !atLeastHTTP11 || t.Body == nil {
			t.TransferEncoding = nil
		}
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		} else if t.Body == nil { // no chunking, no body
			t.ContentLength = 0
		}
	}

	// Sanitize Trailer
	if !chunked(t.TransferEncoding) {
		t.Trailer = nil
	}

	return t, nil
}

// shouldSendChunkedRequestBody reports whether we should try to send a
// chunked request body to the server. In particular, the case we really
// want to prevent is sending a GET or other typically-bodyless request to a
// server with a chunked body when the body has zero bytes, since GETs with
// bodies (while acceptable according to specs), even zero-byte chunked
// bodies, are approximately never seen in the wild and confuse most
// servers. See Issue 18257, as one example.
//
// The only reason we'd send such a request is if the user set the Body to a
// non-nil value (say, io.NopCloser(bytes.NewReader(nil))) and didn't
// set ContentLength, or NewRequest set it to -1 (unknown), so then we assume
// there's bytes to send.
//
// This code tries to read a byte from the Request.Body in such cases to see
// whether the body actually has content (super rare) or is actually just
// a non-nil content-less ReadCloser (the more common case). In that more
// common case, we act as if their Body were nil instead, and don't send
// a body.
func (t *transferWriter) shouldSendChunkedRequestBody() bool {
	// Note that t.ContentLength is the corrected content length
	// from rr.outgoingLength, so 0 actually means zero, not unknown.
	if t.ContentLength >= 0 || t.Body == nil { // redundant checks; caller did them
		return false
	}
	if t.Method == "CONNECT" {
		return false
	}
	if requestMethodUsuallyLacksBody(t.Method) {
		// Only probe the Request.Body for GET/HEAD/DELETE/etc
		// requests, because it's only those types of requests
		// that confuse servers.
		t.probeRequestBody() // adjusts t.Body, t.ContentLength
		return t.Body != nil
	}
	// For all other request types (PUT, POST, PATCH, or anything
	// made-up we've never heard of), assume it's normal and the server
	// can deal with a chunked request body. Maybe we'll adjust this
	// later.
	return true
}

// probeRequestBody reads a byte from t.Body to see whether it's empty
// (returns io.EOF right away).
//
// But because we've had problems with this blocking users in the past
// (issue 17480) when the body is a pipe (perhaps waiting on the response
// headers before the pipe is fed data), we need to be careful and bound how
// long we wait for it. This delay will only affect users if all the following
// are true:
//   - the request body blocks
//   - the content length is not set (or set to -1)
//   - the method doesn't usually have a body (GET, HEAD, DELETE, ...)
//   - there is no transfer-encoding=chunked already set.
//
// In other words, this delay will not normally affect anybody, and there
// are workarounds if it does.
func (t *transferWriter) probeRequestBody() {
	t.ByteReadCh = make(chan readResult, 1)
	go func(body io.Reader) {
		var buf [1]byte
		var rres readResult
		rres.n, rres.err = body.Read(buf[:])
		if rres.n == 1 {
			rres.b = buf[0]
		}
		t.ByteReadCh <- rres
		close(t.ByteReadCh)
	}(t.Body)
	timer := time.NewTimer(200 * time.Millisecond)
	select {
	case rres := <-t.ByteReadCh:
		timer.Stop()
		if rres.n == 0 && rres.err == io.EOF {
			// It was empty.
			t.Body = nil
			t.ContentLength = 0
		} else if rres.n == 1 {
			if rres.err != nil {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, errorReader{rres.err})
			} else {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, t.Body)
			}
		} else if rres.err != nil {
			t.Body = errorReader{rres.err}
		}
	case <-timer.C:
		// Too slow. Don't wait. Read it later, and keep
		// assuming that this is ContentLength == -1
		// (unknown), which means we'll send a
		// "Transfer-Encoding: chunked" header.
		t.Body = io.MultiReader(finishAsyncByteRead{t}, t.Body)
		// Request that Request.Write flush the headers to the
		// network before writing the body, since our body may not
		// become readable until it's seen the response headers.
		t.FlushHeaders = true
	}
}

func noResponseBodyExpected(requestMethod string) bool {
	return requestMethod == "HEAD"
}

func (t *transferWriter) shouldSendContentLength() bool {
	if chunked(t.TransferEncoding) {
		return false
	}
	if t.ContentLength > 0 {
		return true
	}
	if t.ContentLength < 0 {
		return false
	}
	// Many servers expect a Content-Length for these methods
	if t.Method == "POST" || t.Method == "PUT" || t.Method == "PATCH" {
		return true
	}
	if t.ContentLength == 0 && isIdentity(t.TransferEncoding) {
		if t.Method == "GET" || t.Method == "HEAD" {
			return false
		}
		return true
	}

	return false
}

func (t *transferWriter) writeHeader(w io.Writer, trace *httptrace.ClientTrace) error {
	if t.Close && !hasToken(t.Header.get("Connection"), "close") {
		if _, err := io.WriteString(w, "Connection: close\r\n"); err != nil {
			return err
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField("Connection", []string{"close"})
		}
	}

	// Write Content-Length and/or Transfer-Encoding whose values are a
	// function of the sanitized field triple (Body, ContentLength,
	// TransferEncoding)
	if t.shouldSendContentLength() {
		if _, err := io.WriteString(w, "Content-Length: "); err != nil {
			return err
		}
		if _, err := io.WriteString(w, strconv.FormatInt(t.ContentLength, 10)+"\r\n"); err != nil {
			return err
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField("Content-Length", []string{strconv.FormatInt(t.ContentLength, 10)})
		}
	} else if chunked(t.TransferEncoding) {
		if _, err := io.WriteString(w, "Transfer-Encoding: chunked\r\n"); err != nil {
			return err
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField("Transfer-Encoding", []string{"chunked"})
		}
	}

	// Write Trailer header
	if t.Trailer != nil {
		keys := make([]string, 0, len(t.Trailer))
		for k := range t.Trailer {
			k = CanonicalHeaderKey(k)
			switch k {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				return badStringError("invalid Trailer key", k)
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			slices.Sort(keys)
			// TODO: could do better allocation-wise here, but trailers are rare,
			// so being lazy for now.
			if _, err := io.WriteString(w, "Trailer: "+strings.Join(keys, ",")+"\r\n"); err != nil {
				return err
			}
			if trace != nil && trace.WroteHeaderField != nil {
				trace.WroteHeaderField("Trailer", keys)
			}
		}
	}

	return nil
}

// always closes t.BodyCloser
func (t *transferWriter) writeBody(w io.Writer) (err error) {
	var ncopy int64
	closed := false
	defer func() {
		if closed || t.BodyCloser == nil {
			return
		}
		if closeErr := t.BodyCloser.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	// Write body. We "unwrap" the body first if it was wrapped in a
	// nopCloser or readTrackingBody. This is to ensure that we can take advantage of
	// OS-level optimizations in the event that the body is an
	// *os.File.
	if !t.ResponseToHEAD && t.Body != nil {
		var body = t.unwrapBody()
		if chunked(t.TransferEncoding) {
			if bw, ok := w.(*bufio.Writer); ok && !t.IsResponse {
				w = &internal.FlushAfterChunkWriter{Writer: bw}
			}
			cw := internal.NewChunkedWriter(w)
			_, err = t.doBodyCopy(cw, body)
			if err == nil {
				err = cw.Close()
			}
		} else if t.ContentLength == -1 {
			dst := w
			if t.Method == "CONNECT" {
				dst = bufioFlushWriter{dst}
			}
			ncopy, err = t.doBodyCopy(dst, body)
		} else {
			ncopy, err = t.doBodyCopy(w, io.LimitReader(body, t.ContentLength))
			if err != nil {
				return err
			}
			var nextra int64
			nextra, err = t.doBodyCopy(io.Discard, body)
			ncopy += nextra
		}
		if err != nil {
			return err
		}
	}
	if t.BodyCloser != nil {
		closed = true
		if err := t.BodyCloser.Close(); err != nil {
			return err
		}
	}

	if !t.ResponseToHEAD && t.ContentLength != -1 && t.ContentLength != ncopy {
		return fmt.Errorf("http: ContentLength=%d with Body length %d",
			t.ContentLength, ncopy)
	}

	if !t.ResponseToHEAD && chunked(t.TransferEncoding) {
		// Write Trailer header
		if t.Trailer != nil {
			if err := t.Trailer.Write(w); err != nil {
				return err
			}
		}
		// Last chunk, empty trailer
		_, err = io.WriteString(w, "\r\n")
	}
	return err
}

// doBodyCopy wraps a copy operation, with any resulting error also
// being saved in bodyReadError.
//
// This function is only intended for use in writeBody.
func (t *transferWriter) doBodyCopy(dst io.Writer, src io.Reader) (n int64, err error) {
	buf := getCopyBuf()
	defer putCopyBuf(buf)

	n, err = io.CopyBuffer(dst, src, buf)
	if err != nil && err != io.EOF {
		t.bodyReadError = err
	}
	return
}

// unwrapBody unwraps the body's inner reader if it's a
// nopCloser. This is to ensure that body writes sourced from local
// files (*os.File types) are properly optimized.
//
// This function is only intended for use in writeBody.
func (t *transferWriter) unwrapBody() io.Reader {
	if r, ok := unwrapNopCloser(t.Body); ok {
		return r
	}
	if r, ok := t.Body.(*readTrackingBody); ok {
		r.didRead = true
		return r.ReadCloser
	}
	return t.Body
}

type transferReader struct {
	// Input
	Header        Header
	StatusCode    int
	RequestMethod string
	ProtoMajor    int
	ProtoMinor    int
	// Output
	Body          io.ReadCloser
	ContentLength int64
	Chunked       bool
	Close         bool
	Trailer       Header
}

func (t *transferReader) protoAtLeast(m, n int) bool {
	return t.ProtoMajor > m || (t.ProtoMajor == m && t.ProtoMinor >= n)
}

// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 7230, section 3.3.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

var (
	suppressedHeaders304    = []string{"Content-Type", "Content-Length", "Transfer-Encoding"}
	suppressedHeadersNoBody = []string{"Content-Length", "Transfer-Encoding"}
	excludedHeadersNoBody   = map[string]bool{"Content-Length": true, "Transfer-Encoding": true}
)

func suppressedHeaders(status int) []string {
	switch {
	case status == 304:
		// RFC 7232 section 4.1
		return suppressedHeaders304
	case !bodyAllowedForStatus(status):
		return suppressedHeadersNoBody
	}
	return nil
}

// msg is *Request or *Response.
func readTransfer(msg any, r *bufio.Reader) (err error) {
	t := &transferReader{RequestMethod: "GET"}

	// Unify input
	isResponse := false
	switch rr := msg.(type) {
	case *Response:
		t.Header = rr.Header
		t.StatusCode = rr.StatusCode
		t.ProtoMajor = rr.ProtoMajor
		t.ProtoMinor = rr.ProtoMinor
		t.Close = shouldClose(t.ProtoMajor, t.ProtoMinor, t.Header, true)
		isResponse = true
		if rr.Request != nil {
			t.RequestMethod = rr.Request.Method
		}
	case *Request:
		t.Header = rr.Header
		t.RequestMethod = rr.Method
		t.ProtoMajor = rr.ProtoMajor
		t.ProtoMinor = rr.ProtoMinor
		// Transfer semantics for Requests are exactly like those for
		// Responses with status code 200, responding to a GET method
		t.StatusCode = 200
		t.Close = rr.Close
	default:
		panic("unexpected type")
	}

	// Default to HTTP/1.1
	if t.ProtoMajor == 0 && t.ProtoMinor == 0 {
		t.ProtoMajor, t.ProtoMinor = 1, 1
	}

	// Transfer-Encoding: chunked, and overriding Content-Length.
	if err := t.parseTransferEncoding(); err != nil {
		return err
	}

	realLength, err := fixLength(isResponse, t.StatusCode, t.RequestMethod, t.Header, t.Chunked)
	if err != nil {
		return err
	}
	if isResponse && t.RequestMethod == "HEAD" {
		if n, err := parseContentLength(t.Header["Content-Length"]); err != nil {
			return err
		} else {
			t.ContentLength = n
		}
	} else {
		t.ContentLength = realLength
	}

	// Trailer
	t.Trailer, err = fixTrailer(t.Header, t.Chunked)
	if err != nil {
		return err
	}

	// If there is no Content-Length or chunked Transfer-Encoding on a *Response
	// and the status is not 1xx, 204 or 304, then the body is unbounded.
	// See RFC 7230, section 3.3.
	switch msg.(type) {
	case *Response:
		if realLength == -1 && !t.Chunked && bodyAllowedForStatus(t.StatusCode) {
			// Unbounded body.
			t.Close = true
		}
	}

	// Prepare body reader. ContentLength < 0 means chunked encoding
	// or close connection when finished, since multipart is not supported yet
	switch {
	case t.Chunked:
		if isResponse && (noResponseBodyExpected(t.RequestMethod) || !bodyAllowedForStatus(t.StatusCode)) {
			t.Body = NoBody
		} else {
			t.Body = &body{src: internal.NewChunkedReader(r), hdr: msg, r: r, closing: t.Close}
		}
	case realLength == 0:
		t.Body = NoBody
	case realLength > 0:
		t.Body = &body{src: io.LimitReader(r, realLength), closing: t.Close}
	default:
		// realLength < 0, i.e. "Content-Length" not mentioned in header
		if t.Close {
			// Close semantics (i.e. HTTP/1.0)
			t.Body = &body{src: r, closing: t.Close}
		} else {
			// Persistent connection (i.e. HTTP/1.1)
			t.Body = NoBody
		}
	}

	// Unify output
	switch rr := msg.(type) {
	case *Request:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		if t.Chunked {
			rr.TransferEncoding = []string{"chunked"}
		}
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	case *Response:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		if t.Chunked {
			rr.TransferEncoding = []string{"chunked"}
		}
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	}

	return nil
}

// Checks whether chunked is part of the encodings stack.
func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }

// Checks whether the encoding is explicitly "identity".
func isIdentity(te []string) bool { return len(te) == 1 && te[0] == "identity" }

// unsupportedTEError reports unsupported transfer-encodings.
type unsupportedTEError struct {
	err string
}

func (uste *unsupportedTEError) Error() string {
	return uste.err
}

// isUnsupportedTEError checks if the error is of type
// unsupportedTEError. It is usually invoked with a non-nil err.
func isUnsupportedTEError(err error) bool {
	_, ok := err.(*unsupportedTEError)
	return ok
}

// parseTransferEncoding sets t.Chunked based on the Transfer-Encoding header.
func (t *transferReader) parseTransferEncoding() error {
	raw, present := t.Header["Transfer-Encoding"]
	if !present {
		return nil
	}
	delete(t.Header, "Transfer-Encoding")

	// Issue 12785; ignore Transfer-Encoding on HTTP/1.0 requests.
	if !t.protoAtLeast(1, 1) {
		return nil
	}

	// Like nginx, we only support a single Transfer-Encoding header field, and
	// only if set to "chunked". This is one of the most security sensitive
	// surfaces in HTTP/1.1 due to the risk of request smuggling, so we keep it
	// strict and simple.
	if len(raw) != 1 {
		return &unsupportedTEError{fmt.Sprintf("too many transfer encodings: %q", raw)}
	}
	if !ascii.EqualFold(raw[0], "chunked") {
		return &unsupportedTEError{fmt.Sprintf("unsupported transfer encoding: %q", raw[0])}
	}

	t.Chunked = true
	return nil
}

// Determine the expected body length, using RFC 7230 Section 3.3. This
// function is not a method, because ultimately it should be shared by
// ReadResponse and ReadRequest.
func fixLength(isResponse bool, status int, requestMethod string, header Header, chunked bool) (n int64, err error) {
	isRequest := !isResponse
	contentLens := header["Content-Length"]

	// Hardening against HTTP request smuggling
	if len(contentLens) > 1 {
		// Per RFC 7230 Section 3.3.2, prevent multiple
		// Content-Length headers if they differ in value.
		// If there are dups of the value, remove the dups.
		// See Issue 16490.
		first := textproto.TrimString(contentLens[0])
		for _, ct := range contentLens[1:] {
			if first != textproto.TrimString(ct) {
				return 0, fmt.Errorf("http: message cannot contain multiple Content-Length headers; got %q", contentLens)
			}
		}

		// deduplicate Content-Length
		header.Del("Content-Length")
		header.Add("Content-Length", first)

		contentLens = header["Content-Length"]
	}

	// Reject requests with invalid Content-Length headers.
	if len(contentLens) > 0 {
		n, err = parseContentLength(contentLens)
		if err != nil {
			return -1, err
		}
	}

	// Logic based on response type or status
	if isResponse && noResponseBodyExpected(requestMethod) {
		return 0, nil
	}
	if status/100 == 1 {
		return 0, nil
	}
	switch status {
	case 204, 304:
		return 0, nil
	}

	// According to RFC 9112, "If a message is received with both a
	// Transfer-Encoding and a Content-Length header field, the Transfer-Encoding
	// overrides the Content-Length. Such a message might indicate an attempt to
	// perform request smuggling (Section 11.2) or response splitting (Section 11.1)
	// and ought to be handled as an error. An intermediary that chooses to forward
	// the message MUST first remove the received Content-Length field and process
	// the Transfer-Encoding (as described below) prior to forwarding the message downstream."
	//
	// Chunked-encoding requests with either valid Content-Length
	// headers or no Content-Length headers are accepted after removing
	// the Content-Length field from header.
	//
	// Logic based on Transfer-Encoding
	if chunked {
		header.Del("Content-Length")
		return -1, nil
	}

	// Logic based on Content-Length
	if len(contentLens) > 0 {
		return n, nil
	}

	header.Del("Content-Length")

	if isRequest {
		// RFC 7230 neither explicitly permits nor forbids an
		// entity-body on a GET request so we permit one if
		// declared, but we default to 0 here (not -1 below)
		// if there's no mention of a body.
		// Likewise, all other request methods are assumed to have
		// no body if neither Transfer-Encoding chunked nor a
		// Content-Length are set.
		return 0, nil
	}

	// Body-EOF logic based on other methods (like closing, or chunked coding)
	return -1, nil
}

// Determine whether to hang up after sending a request and body, or
// receiving a response and body
// 'header' is the request headers.
func shouldClose(major, minor int, header Header, removeCloseHeader bool) bool {
	if major < 1 {
		return true
	}

	conv := header["Connection"]
	hasClose := httpguts.HeaderValuesContainsToken(conv, "close")
	if major == 1 && minor == 0 {
		return hasClose || !httpguts.HeaderValuesContainsToken(conv, "keep-alive")
	}

	if hasClose && removeCloseHeader {
		header.Del("Connection")
	}

	return hasClose
}

// Parse the trailer header.
func fixTrailer(header Header, chunked bool) (Header, error) {
	vv, ok := header["Trailer"]
	if !ok {
		return nil, nil
	}
	if !chunked {
		// Trailer and no chunking:
		// this is an invalid use case for trailer header.
		// Nevertheless, no error will be returned and we
		// let users decide if this is a valid HTTP message.
		// The Trailer header will be kept in Response.Header
		// but not populate Response.Trailer.
		// See issue #27197.
		return nil, nil
	}
	header.Del("Trailer")

	trailer := make(Header)
	var err error
	for _, v := range vv {
		foreachHeaderElement(v, func(key string) {
			key = CanonicalHeaderKey(key)
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				if err == nil {
					err = badStringError("bad trailer key", key)
					return
				}
			}
			trailer[key] = nil
		})
	}
	if err != nil {
		return nil, err
	}
	if len(trailer) == 0 {
		return nil, nil
	}
	return trailer, nil
}

// body turns a Reader into a ReadCloser.
// Close ensures that the body has been fully read
// and then reads the trailer if necessary.
type body struct {
	src          io.Reader
	hdr          any           // non-nil (Response or Request) value means read trailer
	r            *bufio.Reader // underlying wire-format reader for the trailer
	closing      bool          // is the connection to be closed after reading body?
	doEarlyClose bool          // whether Close should stop early

	mu         sync.Mutex // guards following, and calls to Read and Close
	sawEOF     bool
	closed     bool
	earlyClose bool   // Close called and we didn't read to the end of src
	onHitEOF   func() // if non-nil, func to call when EOF is Read
}

// ErrBodyReadAfterClose is returned when reading a [Request] or [Response]
// Body after the body has been closed. This typically happens when the body is
// read after an HTTP [Handler] calls WriteHeader or Write on its
// [ResponseWriter].
var ErrBodyReadAfterClose = errors.New("http: invalid Read on closed Body")

func (b *body) Read(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return b.readLocked(p)
}

// Must hold b.mu.
func (b *body) readLocked(p []byte) (n int, err error) {
	if b.sawEOF {
		return 0, io.EOF
	}
	n, err = b.src.Read(p)

	if err == io.EOF {
		b.sawEOF = true
		// Chunked case. Read the trailer.
		if b.hdr != nil {
			if e := b.readTrailer(); e != nil {
				err = e
				// Something went wrong in the trailer, we must not allow any
				// further reads of any kind to succeed from body, nor any
				// subsequent requests on the server connection. See
				// golang.org/issue/12027
				b.sawEOF = false
				b.closed = true
			}
			b.hdr = nil
		} else {
			// If the server declared the Content-Length, our body is a LimitedReader
			// and we need to check whether this EOF arrived early.
			if lr, ok := b.src.(*io.LimitedReader); ok && lr.N > 0 {
				err = io.ErrUnexpectedEOF
			}
		}
	}

	// If we can return an EOF here along with the read data, do
	// so. This is optional per the io.Reader contract, but doing
	// so helps the HTTP transport code recycle its connection
	// earlier (since it will see this EOF itself), even if the
	// client doesn't do future reads or Close.
	if err == nil && n > 0 {
		if lr, ok := b.src.(*io.LimitedReader); ok && lr.N == 0 {
			err = io.EOF
			b.sawEOF = true
		}
	}

	if b.sawEOF && b.onHitEOF != nil {
		b.onHitEOF()
	}

	return n, err
}

var (
	singleCRLF = []byte("\r\n")
	doubleCRLF = []byte("\r\n\r\n")
)

func seeUpcomingDoubleCRLF(r *bufio.Reader) bool {
	for peekSize := 4; ; peekSize++ {
		// This loop stops when Peek returns an error,
		// which it does when r's buffer has been filled.
		buf, err := r.Peek(peekSize)
		if bytes.HasSuffix(buf, doubleCRLF) {
			return true
		}
		if err != nil {
			break
		}
	}
	return false
}

var errTrailerEOF = errors.New("http: unexpected EOF reading trailer")

func (b *body) readTrailer() error {
	// The common case, since nobody uses trailers.
	buf, err := b.r.Peek(2)
	if bytes.Equal(buf, singleCRLF) {
		b.r.Discard(2)
		return nil
	}
	if len(buf) < 2 {
		return errTrailerEOF
	}
	if err != nil {
		return err
	}

	// Make sure there's a header terminator coming up, to prevent
	// a DoS with an unbounded size Trailer. It's not easy to
	// slip in a LimitReader here, as textproto.NewReader requires
	// a concrete *bufio.Reader. Also, we can't get all the way
	// back up to our conn's LimitedReader that *might* be backing
	// this bufio.Reader. Instead, a hack: we iteratively Peek up
	// to the bufio.Reader's max size, looking for a double CRLF.
	// This limits the trailer to the underlying buffer size, typically 4kB.
	if !seeUpcomingDoubleCRLF(b.r) {
		return errors.New("http: suspiciously long trailer after chunked body")
	}

	hdr, err := textproto.NewReader(b.r).ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			return errTrailerEOF
		}
		return err
	}
	switch rr := b.hdr.(type) {
	case *Request:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	case *Response:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	}
	return nil
}

func mergeSetHeader(dst *Header, src Header) {
	if *dst == nil {
		*dst = src
		return
	}
	maps.Copy(*dst, src)
}

// unreadDataSizeLocked returns the number of bytes of unread input.
// It returns -1 if unknown.
// b.mu must be held.
func (b *body) unreadDataSizeLocked() int64 {
	if lr, ok := b.src.(*io.LimitedReader); ok {
		return lr.N
	}
	return -1
}

func (b *body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	var err error
	switch {
	case b.sawEOF:
		// Already saw EOF, so no need going to look for it.
	case b.hdr == nil && b.closing:
		// no trailer and closing the connection next.
		// no point in reading to EOF.
	case b.doEarlyClose:
		// Read up to maxPostHandlerReadBytes bytes of the body, looking
		// for EOF (and trailers), so we can re-use this connection.
		if lr, ok := b.src.(*io.LimitedReader); ok && lr.N > maxPostHandlerReadBytes {
			// There was a declared Content-Length, and we have more bytes remaining
			// than our maxPostHandlerReadBytes tolerance. So, give up.
			b.earlyClose = true
		} else {
			var n int64
			// Consume the body, or, which will also lead to us reading
			// the trailer headers after the body, if present.
			n, err = io.CopyN(io.Discard, bodyLocked{b}, maxPostHandlerReadBytes)
			if err == io.EOF {
				err = nil
			}
			if n == maxPostHandlerReadBytes {
				b.earlyClose = true
			}
		}
	default:
		// Fully consume the body, which will also lead to us reading
		// the trailer headers after the body, if present.
		_, err = io.Copy(io.Discard, bodyLocked{b})
	}
	b.closed = true
	return err
}

func (b *body) didEarlyClose() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.earlyClose
}

// bodyRemains reports whether future Read calls might
// yield data.
func (b *body) bodyRemains() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.sawEOF
}

func (b *body) registerOnHitEOF(fn func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onHitEOF = fn
}

// bodyLocked is an io.Reader reading from a *body when its mutex is
// already held.
type bodyLocked struct {
	b *body
}

func (bl bodyLocked) Read(p []byte) (n int, err error) {
	if bl.b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return bl.b.readLocked(p)
}

var httplaxcontentlength = godebug.New("httplaxcontentlength")

// parseContentLength checks that the header is valid and then trims
// whitespace. It returns -1 if no value is set otherwise the value
// if it's >= 0.
func parseContentLength(clHeaders []string) (int64, error) {
	if len(clHeaders) == 0 {
		return -1, nil
	}
	cl := textproto.TrimString(clHeaders[0])

	// The Content-Length must be a valid numeric value.
	// See: https://datatracker.ietf.org/doc/html/rfc2616/#section-14.13
	if cl == "" {
		if httplaxcontentlength.Value() == "1" {
			httplaxcontentlength.IncNonDefault()
			return -1, nil
		}
		return 0, badStringError("invalid empty Content-Length", cl)
	}
	n, err := strconv.ParseUint(cl, 10, 63)
	if err != nil {
		return 0, badStringError("bad Content-Length", cl)
	}
	return int64(n), nil
}

// finishAsyncByteRead finishes reading the 1-byte sniff
// from the ContentLength==0, Body!=nil case.
type finishAsyncByteRead struct {
	tw *transferWriter
}

func (fr finishAsyncByteRead) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	rres := <-fr.tw.ByteReadCh
	n, err = rres.n, rres.err
	if n == 1 {
		p[0] = rres.b
	}
	if err == nil {
		err = io.EOF
	}
	return
}

var nopCloserType = reflect.TypeOf(io.NopCloser(nil))
var nopCloserWriterToType = reflect.TypeOf(io.NopCloser(struct {
	io.Reader
	io.WriterTo
}{}))

// unwrapNopCloser return the underlying reader and true if r is a NopCloser
// else it return false.
func unwrapNopCloser(r io.Reader) (underlyingReader io.Reader, isNopCloser bool) {
	switch reflect.TypeOf(r) {
	case nopCloserType, nopCloserWriterToType:
		return reflect.ValueOf(r).Field(0).Interface().(io.Reader), true
	default:
		return nil, false
	}
}

// isKnownInMemoryReader reports whether r is a type known to not
// block on Read. Its caller uses this as an optional optimization to
// send fewer TCP packets.
func isKnownInMemoryReader(r io.Reader) bool {
	switch r.(type) {
	case *bytes.Reader, *bytes.Buffer, *strings.Reader:
		return true
	}
	if r, ok := unwrapNopCloser(r); ok {
		return isKnownInMemoryReader(r)
	}
	if r, ok := r.(*readTrackingBody); ok {
		return isKnownInMemoryReader(r.ReadCloser)
	}
	return false
}

// bufioFlushWriter is an io.Writer wrapper that flushes all writes
// on its wrapped writer if it's a *bufio.Writer.
type bufioFlushWriter struct{ w io.Writer }

func (fw bufioFlushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if bw, ok := fw.w.(*bufio.Writer); n > 0 && ok {
		ferr := bw.Flush()
		if ferr != nil && err == nil {
			err = ferr
		}
	}
	return
}

"""



```