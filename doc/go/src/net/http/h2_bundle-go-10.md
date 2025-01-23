Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Keywords:**

The first step is to quickly scan the code for recognizable patterns and keywords. I'm looking for things like:

* `case` statements in a `switch`: This often indicates handling different types of data or events.
* Function names like `process...`, `handle...`, `write...`: These suggest distinct processing or action steps.
* Struct names with `Frame` suffix:  `http2PushPromiseFrame`, `http2WindowUpdateFrame`, etc. This strongly hints at handling HTTP/2 frames.
* Data structures like `Header`, `Response`:  These relate to HTTP concepts.
* Method calls on `rl` (likely a receiver): This indicates the context of the code within a larger structure.
* Locking mechanisms (`cc.mu.Lock()`, `cc.wmu.Lock()`): This suggests concurrency control.
* `io.EOF`, `errors.New`: Standard Go error handling patterns.

**2. Identifying the Core Functionality (The `switch` statement):**

The central `switch` statement in `func (rl *http2clientConnReadLoop) run() error` immediately stands out. It's handling different types of HTTP/2 frames received from the server. This becomes the focal point for understanding the code's purpose. The cases directly tell us what types of frames are being processed: `http2MetaHeadersFrame`, `http2DataFrame`, `http2SettingsFrame`, etc.

**3. Analyzing Individual Case Handlers:**

Next, I go through each `case` and its corresponding handler function (`rl.processHeaders(f)`, `rl.processData(f)`, etc.). For each handler:

* **Purpose:** What is the responsibility of this handler?  The function name usually gives a good clue.
* **Input:** What type of frame does it receive?
* **Actions:** What does it do with the frame data? Does it update internal state (`cs.pastHeaders`), create new objects (`Response`), send data, or signal other parts of the system?
* **Error Handling:**  How does it handle errors? Does it return an error, close the connection, or just log a message?

**4. Focusing on Complex Logic (`processHeaders` and `processData`):**

Some handlers are more complex than others. `processHeaders` and `processData` are good examples. I look for:

* **State Management:** How does the code track the state of a stream (`cs.readClosed`, `cs.pastHeaders`, `cs.firstByte`)?
* **Data Flow:** How is data read from the frame and used (e.g., extracting headers, writing data to a buffer)?
* **Edge Cases:** What special conditions are handled (e.g., informational responses (1xx), HEAD requests, trailers)?
* **Interactions:** How does this handler interact with other parts of the system (e.g., sending window updates, ending a stream)?

**5. Inferring the Larger Context (`http2clientConnReadLoop`):**

The receiver `rl *http2clientConnReadLoop` tells us this code is part of the logic for reading data on an HTTP/2 client connection. The "read loop" suggests a continuous process of receiving and processing frames. The methods called on `cc` (presumably a `http2ClientConn`) indicate it's managing the overall connection state.

**6. Connecting to HTTP/2 Concepts:**

I bring my knowledge of HTTP/2 to bear. Concepts like streams, frames, headers, data, settings, flow control, push promises, and error handling help me understand the purpose of the code.

**7. Considering "What Go Feature is This Implementing?":**

This part requires connecting the specific code to broader Go language features. Key features used here include:

* **Goroutines and Channels:** The locking mechanisms and the mention of `donec`, `respHeaderRecv`, and `on100` channels suggest concurrent processing of requests and responses.
* **Interfaces:** The use of `io.ReadCloser` for the response body is a standard Go pattern.
* **Structs and Methods:** The entire code is built around structs (`http2clientConnReadLoop`, `http2clientStream`, etc.) and their associated methods, demonstrating object-oriented principles in Go.
* **Error Handling:**  Explicit error returns and the use of the `errors` package are core to Go's error handling.

**8. Constructing the Explanation (Iteration and Refinement):**

As I analyze the code, I start forming a mental outline of the explanation. I try to organize it logically, starting with the main purpose and then drilling down into details. I iterate on the explanation, refining it for clarity and accuracy. For example, initially, I might just say "handles headers," but then refine it to explain the different stages of header processing (initial headers vs. trailers) and the handling of 1xx responses.

**9. Code Examples (If Applicable):**

For the "Go feature" part, concrete examples are crucial. I think about the simplest way to demonstrate the feature being used. In this case, showing how to make an HTTP/2 request and access the response body or trailers is a good approach.

**10. Hypothesizing Input/Output:**

For code reasoning, I consider a simple successful scenario (e.g., a basic GET request) and a potentially error-prone scenario (e.g., a server sending data before headers). This helps illustrate the code's behavior.

**11. Considering Common Mistakes:**

I reflect on my experience with HTTP/2 and Go's `net/http` package. What are common pitfalls developers might encounter?  Not handling trailers correctly or misunderstanding flow control are possibilities.

**12. Addressing Command-Line Arguments (If Present):**

In this snippet, there are no explicit command-line arguments being processed. If there were, I'd look for `os.Args` or flags being parsed.

**13. Summarizing the Functionality (For the "Part X of Y" Instruction):**

Finally, I synthesize a concise summary of the code's role within the larger system, based on the detailed analysis.

By following these steps, I can systematically dissect the Go code snippet and provide a comprehensive and informative explanation. The process is iterative, and I might revisit earlier steps as I gain a deeper understanding of the code.这是 `go/src/net/http/h2_bundle.go` 文件中 `http2clientConnReadLoop` 类型的 `run` 方法的一部分，以及该类型的一些其他方法。它主要负责 **处理从 HTTP/2 服务器接收到的各种帧 (frames)**，并根据帧的类型采取相应的行动。

**主要功能归纳:**

这段代码的核心功能是 **HTTP/2 客户端连接的读取循环**。它在一个 Goroutine 中运行，持续监听并处理来自服务器的 HTTP/2 帧，并将这些帧转换为客户端可以理解的响应和事件。

更具体地说，它的功能可以细分为：

1. **帧类型分发:**  `run` 方法使用 `switch` 语句根据接收到的帧类型 (`http2MetaHeadersFrame`, `http2DataFrame`, `http2SettingsFrame` 等) 将帧分发给不同的处理函数。

2. **处理 HEADERS 帧 (`processHeaders`):**
   - 解析响应头信息，包括状态码、Headers 和 Trailes。
   - 创建 `http.Response` 对象。
   - 处理 1xx 状态码的中间响应。
   - 处理 `Content-Length` 头，确定响应体的大小。
   - 设置响应体 (`http2transportResponseBody`)，并根据 `Content-Encoding` 处理 gzip 压缩。
   - 处理 Trailer 头。

3. **处理 DATA 帧 (`processData`):**
   - 接收响应体数据。
   - 进行流控检查，确保不超过连接和流的窗口大小。
   - 将数据写入流的缓冲区 (`cs.bufPipe`)。
   - 在数据接收完成后发送 WINDOW_UPDATE 帧，告知服务器可以发送更多数据。

4. **处理 SETTINGS 帧 (`processSettings`):**
   - 处理服务器发送的 SETTINGS 帧，更新客户端连接的配置，例如最大帧大小、最大并发流数、初始窗口大小等。
   - 发送 SETTINGS 帧的 ACK。

5. **处理 WINDOW_UPDATE 帧 (`processWindowUpdate`):**
   - 处理服务器发送的 WINDOW_UPDATE 帧，增加连接或流的可用窗口大小。

6. **处理 PING 帧 (`processPing`):**
   - 响应服务器发送的 PING 帧，发送 PING ACK。
   - 处理客户端自己发送的 PING 帧的 ACK。

7. **处理 PUSH_PROMISE 帧 (`processPushPromise`):**
   - 根据 HTTP/2 规范，如果客户端禁用了服务器推送，则收到 PUSH_PROMISE 帧视为连接错误。

8. **处理 GOAWAY 帧 (`processGoAway`):**
   - 处理服务器发送的 GOAWAY 帧，表示服务器要关闭连接。
   - 将连接标记为死亡，不再重用。

9. **处理 RST_STREAM 帧 (`processResetStream`):**
   - 处理服务器发送的 RST_STREAM 帧，表示服务器要终止某个流。
   - 中止相应的客户端流。

10. **管理流的状态:**  跟踪每个流的状态，例如是否已接收到 Headers、Data 或 Trailer，是否已关闭等。

11. **流控:**  实现 HTTP/2 的流控机制，防止发送方发送过多数据压垮接收方。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 Go 语言的 **网络编程** 和 **并发** 特性。

* **网络编程:** 使用底层的网络连接 (`net.Conn`) 和自定义的帧处理逻辑来与 HTTP/2 服务器通信。
* **并发:**  使用 Goroutine (`go rl.run()`) 来异步地读取和处理来自服务器的数据，提高性能。
* **接口:**  定义了 `http2writeContext` 和 `http2writeFramer` 等接口，用于抽象帧的写入操作。
* **错误处理:**  使用 `error` 类型来处理各种网络和协议错误。
* **标准库:**  使用了 `errors`、`strconv`、`io`、`context`、`sync`、`math/rand`、`compress/gzip` 等标准库。

**Go 代码举例说明 (处理 HEADERS 帧):**

假设服务器响应一个 GET 请求，发送如下 HEADERS 帧 (简化表示):

```
HEADERS {
  StreamID: 1,
  Flags: END_HEADERS,
  Headers: [
    { ":status", "200" },
    { "Content-Type", "text/html" },
    { "Content-Length", "13" }
  ]
}
```

以下代码片段模拟了 `processHeaders` 函数处理这个帧的过程：

```go
package main

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// 模拟的 http2MetaHeadersFrame
type mockMetaHeadersFrame struct {
	StreamID uint32
	Headers  []mockHeaderField
}

func (m *mockMetaHeadersFrame) PseudoValue(name string) string {
	for _, hf := range m.Headers {
		if hf.Name == name && hf.IsPseudo {
			return hf.Value
		}
	}
	return ""
}

func (m *mockMetaHeadersFrame) RegularFields() []mockHeaderField {
	var regularFields []mockHeaderField
	for _, hf := range m.Headers {
		if !hf.IsPseudo {
			regularFields = append(regularFields, hf)
		}
	}
	return regularFields
}

// 模拟的 Header Field
type mockHeaderField struct {
	Name     string
	Value    string
	IsPseudo bool
}

// 模拟的 http2clientStream
type mockClientStream struct {
	id  uint32
	res *http.Response
}

// 模拟的 http2clientConnReadLoop
type mockClientConnReadLoop struct {
	streams map[uint32]*mockClientStream
}

func (rl *mockClientConnReadLoop) streamByID(id uint32, headerOrDataFrame bool) *mockClientStream {
	return rl.streams[id]
}

func (rl *mockClientConnReadLoop) handleResponse(cs *mockClientStream, f *mockMetaHeadersFrame) (*http.Response, error) {
	status := f.PseudoValue(":status")
	if status == "" {
		return nil, errors.New("malformed response: missing status pseudo header")
	}
	statusCode, err := strconv.Atoi(status)
	if err != nil {
		return nil, errors.New("malformed response: malformed status pseudo header")
	}

	header := make(http.Header)
	for _, hf := range f.RegularFields() {
		header.Add(hf.Name, hf.Value)
	}

	res := &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
	}
	return res, nil
}

func (rl *mockClientConnReadLoop) processHeaders(f *mockMetaHeadersFrame) error {
	cs := rl.streamByID(f.StreamID, true)
	if cs == nil {
		return nil // 假设流已取消
	}

	res, err := rl.handleResponse(cs, f)
	if err != nil {
		fmt.Println("处理响应出错:", err)
		return err
	}
	cs.res = res
	return nil
}

func main() {
	rl := &mockClientConnReadLoop{
		streams: map[uint32]*mockClientStream{
			1: {id: 1},
		},
	}

	frame := &mockMetaHeadersFrame{
		StreamID: 1,
		Headers: []mockHeaderField{
			{":status", "200", true},
			{"Content-Type", "text/html", false},
			{"Content-Length", "13", false},
		},
	}

	err := rl.processHeaders(frame)
	if err != nil {
		fmt.Println("处理 HEADERS 帧出错:", err)
	} else {
		fmt.Printf("成功处理 HEADERS 帧，响应状态码: %d, Content-Type: %s\n", rl.streams[1].res.StatusCode, rl.streams[1].res.Header.Get("Content-Type"))
	}
}
```

**假设的输入与输出:**

**输入 (模拟的 HEADERS 帧):**

```
&mockMetaHeadersFrame{
  StreamID: 1,
  Headers: []mockHeaderField{
    {Name: ":status", Value: "200", IsPseudo: true},
    {Name: "Content-Type", Value: "text/html", IsPseudo: false},
    {Name: "Content-Length", Value: "13", IsPseudo: false},
  },
}
```

**输出:**

```
成功处理 HEADERS 帧，响应状态码: 200, Content-Type: text/html
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。HTTP/2 的配置通常通过 `http.Transport` 结构体的字段进行设置，而不是通过命令行参数。例如，可以使用 `TLSClientConfig` 来配置 TLS 连接，或者使用 `MaxIdleConnsPerHost` 来设置每个主机的最大空闲连接数。

**使用者易犯错的点:**

虽然这段代码是内部实现，普通使用者不会直接接触，但理解其背后的原理可以帮助避免一些使用 `net/http` 包时的常见错误：

1. **没有正确处理 Trailer 头:**  一些应用可能会忽略 HTTP/2 的 Trailer 头，而这些头可能包含重要的元数据。`processTrailers` 方法负责解析这些 Trailer 头，使用者需要确保在读取响应体后也能正确获取和处理这些 Trailer。

2. **不理解 HTTP/2 的流控:**  如果客户端发送大量数据而没有等待服务器的 WINDOW_UPDATE 帧，可能会导致性能问题甚至连接错误。这段代码中的 `processData` 方法处理了流控逻辑，使用者不需要直接干预，但理解流控的概念有助于理解 HTTP/2 的工作方式。

3. **错误地配置 HTTP/2 的 Transport:**  例如，没有正确配置 TLS 或 ALPN 协议，可能导致无法建立 HTTP/2 连接。`http2Transport` 结构体负责管理 HTTP/2 连接的配置。

**这是第11部分，共13部分，请归纳一下它的功能**

作为第 11 部分，这段代码主要关注 **HTTP/2 客户端连接中接收数据并将其转换为 Go 的 `net/http` 抽象的过程**。它实现了客户端接收循环的核心逻辑，负责解析和处理各种类型的 HTTP/2 帧，并将这些底层帧数据转化为上层可以理解的 HTTP 响应和事件。  它是客户端 HTTP/2 实现中至关重要的一部分，连接了底层的帧处理和上层的 HTTP 请求/响应模型。

### 提示词
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第11部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
err = rl.processSettings(f)
		case *http2PushPromiseFrame:
			err = rl.processPushPromise(f)
		case *http2WindowUpdateFrame:
			err = rl.processWindowUpdate(f)
		case *http2PingFrame:
			err = rl.processPing(f)
		default:
			cc.logf("Transport: unhandled response frame type %T", f)
		}
		if err != nil {
			if http2VerboseLogs {
				cc.vlogf("http2: Transport conn %p received error from processing frame %v: %v", cc, http2summarizeFrame(f), err)
			}
			if !cc.seenSettings {
				close(cc.seenSettingsChan)
			}
			return err
		}
	}
}

func (rl *http2clientConnReadLoop) processHeaders(f *http2MetaHeadersFrame) error {
	cs := rl.streamByID(f.StreamID, http2headerOrDataFrame)
	if cs == nil {
		// We'd get here if we canceled a request while the
		// server had its response still in flight. So if this
		// was just something we canceled, ignore it.
		return nil
	}
	if cs.readClosed {
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
			Cause:    errors.New("protocol error: headers after END_STREAM"),
		})
		return nil
	}
	if !cs.firstByte {
		if cs.trace != nil {
			// TODO(bradfitz): move first response byte earlier,
			// when we first read the 9 byte header, not waiting
			// until all the HEADERS+CONTINUATION frames have been
			// merged. This works for now.
			http2traceFirstResponseByte(cs.trace)
		}
		cs.firstByte = true
	}
	if !cs.pastHeaders {
		cs.pastHeaders = true
	} else {
		return rl.processTrailers(cs, f)
	}

	res, err := rl.handleResponse(cs, f)
	if err != nil {
		if _, ok := err.(http2ConnectionError); ok {
			return err
		}
		// Any other error type is a stream error.
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
			Cause:    err,
		})
		return nil // return nil from process* funcs to keep conn alive
	}
	if res == nil {
		// (nil, nil) special case. See handleResponse docs.
		return nil
	}
	cs.resTrailer = &res.Trailer
	cs.res = res
	close(cs.respHeaderRecv)
	if f.StreamEnded() {
		rl.endStream(cs)
	}
	return nil
}

// may return error types nil, or ConnectionError. Any other error value
// is a StreamError of type ErrCodeProtocol. The returned error in that case
// is the detail.
//
// As a special case, handleResponse may return (nil, nil) to skip the
// frame (currently only used for 1xx responses).
func (rl *http2clientConnReadLoop) handleResponse(cs *http2clientStream, f *http2MetaHeadersFrame) (*Response, error) {
	if f.Truncated {
		return nil, http2errResponseHeaderListSize
	}

	status := f.PseudoValue("status")
	if status == "" {
		return nil, errors.New("malformed response from server: missing status pseudo header")
	}
	statusCode, err := strconv.Atoi(status)
	if err != nil {
		return nil, errors.New("malformed response from server: malformed non-numeric status pseudo header")
	}

	regularFields := f.RegularFields()
	strs := make([]string, len(regularFields))
	header := make(Header, len(regularFields))
	res := &Response{
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     header,
		StatusCode: statusCode,
		Status:     status + " " + StatusText(statusCode),
	}
	for _, hf := range regularFields {
		key := http2canonicalHeader(hf.Name)
		if key == "Trailer" {
			t := res.Trailer
			if t == nil {
				t = make(Header)
				res.Trailer = t
			}
			http2foreachHeaderElement(hf.Value, func(v string) {
				t[http2canonicalHeader(v)] = nil
			})
		} else {
			vv := header[key]
			if vv == nil && len(strs) > 0 {
				// More than likely this will be a single-element key.
				// Most headers aren't multi-valued.
				// Set the capacity on strs[0] to 1, so any future append
				// won't extend the slice into the other strings.
				vv, strs = strs[:1:1], strs[1:]
				vv[0] = hf.Value
				header[key] = vv
			} else {
				header[key] = append(vv, hf.Value)
			}
		}
	}

	if statusCode >= 100 && statusCode <= 199 {
		if f.StreamEnded() {
			return nil, errors.New("1xx informational response with END_STREAM flag")
		}
		if fn := cs.get1xxTraceFunc(); fn != nil {
			// If the 1xx response is being delivered to the user,
			// then they're responsible for limiting the number
			// of responses.
			if err := fn(statusCode, textproto.MIMEHeader(header)); err != nil {
				return nil, err
			}
		} else {
			// If the user didn't examine the 1xx response, then we
			// limit the size of all 1xx headers.
			//
			// This differs a bit from the HTTP/1 implementation, which
			// limits the size of all 1xx headers plus the final response.
			// Use the larger limit of MaxHeaderListSize and
			// net/http.Transport.MaxResponseHeaderBytes.
			limit := int64(cs.cc.t.maxHeaderListSize())
			if t1 := cs.cc.t.t1; t1 != nil && t1.MaxResponseHeaderBytes > limit {
				limit = t1.MaxResponseHeaderBytes
			}
			for _, h := range f.Fields {
				cs.totalHeaderSize += int64(h.Size())
			}
			if cs.totalHeaderSize > limit {
				if http2VerboseLogs {
					log.Printf("http2: 1xx informational responses too large")
				}
				return nil, errors.New("header list too large")
			}
		}
		if statusCode == 100 {
			http2traceGot100Continue(cs.trace)
			select {
			case cs.on100 <- struct{}{}:
			default:
			}
		}
		cs.pastHeaders = false // do it all again
		return nil, nil
	}

	res.ContentLength = -1
	if clens := res.Header["Content-Length"]; len(clens) == 1 {
		if cl, err := strconv.ParseUint(clens[0], 10, 63); err == nil {
			res.ContentLength = int64(cl)
		} else {
			// TODO: care? unlike http/1, it won't mess up our framing, so it's
			// more safe smuggling-wise to ignore.
		}
	} else if len(clens) > 1 {
		// TODO: care? unlike http/1, it won't mess up our framing, so it's
		// more safe smuggling-wise to ignore.
	} else if f.StreamEnded() && !cs.isHead {
		res.ContentLength = 0
	}

	if cs.isHead {
		res.Body = http2noBody
		return res, nil
	}

	if f.StreamEnded() {
		if res.ContentLength > 0 {
			res.Body = http2missingBody{}
		} else {
			res.Body = http2noBody
		}
		return res, nil
	}

	cs.bufPipe.setBuffer(&http2dataBuffer{expected: res.ContentLength})
	cs.bytesRemain = res.ContentLength
	res.Body = http2transportResponseBody{cs}

	if cs.requestedGzip && http2asciiEqualFold(res.Header.Get("Content-Encoding"), "gzip") {
		res.Header.Del("Content-Encoding")
		res.Header.Del("Content-Length")
		res.ContentLength = -1
		res.Body = &http2gzipReader{body: res.Body}
		res.Uncompressed = true
	}
	return res, nil
}

func (rl *http2clientConnReadLoop) processTrailers(cs *http2clientStream, f *http2MetaHeadersFrame) error {
	if cs.pastTrailers {
		// Too many HEADERS frames for this stream.
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	cs.pastTrailers = true
	if !f.StreamEnded() {
		// We expect that any headers for trailers also
		// has END_STREAM.
		return http2ConnectionError(http2ErrCodeProtocol)
	}
	if len(f.PseudoFields()) > 0 {
		// No pseudo header fields are defined for trailers.
		// TODO: ConnectionError might be overly harsh? Check.
		return http2ConnectionError(http2ErrCodeProtocol)
	}

	trailer := make(Header)
	for _, hf := range f.RegularFields() {
		key := http2canonicalHeader(hf.Name)
		trailer[key] = append(trailer[key], hf.Value)
	}
	cs.trailer = trailer

	rl.endStream(cs)
	return nil
}

// transportResponseBody is the concrete type of Transport.RoundTrip's
// Response.Body. It is an io.ReadCloser.
type http2transportResponseBody struct {
	cs *http2clientStream
}

func (b http2transportResponseBody) Read(p []byte) (n int, err error) {
	cs := b.cs
	cc := cs.cc

	if cs.readErr != nil {
		return 0, cs.readErr
	}
	n, err = b.cs.bufPipe.Read(p)
	if cs.bytesRemain != -1 {
		if int64(n) > cs.bytesRemain {
			n = int(cs.bytesRemain)
			if err == nil {
				err = errors.New("net/http: server replied with more than declared Content-Length; truncated")
				cs.abortStream(err)
			}
			cs.readErr = err
			return int(cs.bytesRemain), err
		}
		cs.bytesRemain -= int64(n)
		if err == io.EOF && cs.bytesRemain > 0 {
			err = io.ErrUnexpectedEOF
			cs.readErr = err
			return n, err
		}
	}
	if n == 0 {
		// No flow control tokens to send back.
		return
	}

	cc.mu.Lock()
	connAdd := cc.inflow.add(n)
	var streamAdd int32
	if err == nil { // No need to refresh if the stream is over or failed.
		streamAdd = cs.inflow.add(n)
	}
	cc.mu.Unlock()

	if connAdd != 0 || streamAdd != 0 {
		cc.wmu.Lock()
		defer cc.wmu.Unlock()
		if connAdd != 0 {
			cc.fr.WriteWindowUpdate(0, http2mustUint31(connAdd))
		}
		if streamAdd != 0 {
			cc.fr.WriteWindowUpdate(cs.ID, http2mustUint31(streamAdd))
		}
		cc.bw.Flush()
	}
	return
}

var http2errClosedResponseBody = errors.New("http2: response body closed")

func (b http2transportResponseBody) Close() error {
	cs := b.cs
	cc := cs.cc

	cs.bufPipe.BreakWithError(http2errClosedResponseBody)
	cs.abortStream(http2errClosedResponseBody)

	unread := cs.bufPipe.Len()
	if unread > 0 {
		cc.mu.Lock()
		// Return connection-level flow control.
		connAdd := cc.inflow.add(unread)
		cc.mu.Unlock()

		// TODO(dneil): Acquiring this mutex can block indefinitely.
		// Move flow control return to a goroutine?
		cc.wmu.Lock()
		// Return connection-level flow control.
		if connAdd > 0 {
			cc.fr.WriteWindowUpdate(0, uint32(connAdd))
		}
		cc.bw.Flush()
		cc.wmu.Unlock()
	}

	select {
	case <-cs.donec:
	case <-cs.ctx.Done():
		// See golang/go#49366: The net/http package can cancel the
		// request context after the response body is fully read.
		// Don't treat this as an error.
		return nil
	case <-cs.reqCancel:
		return http2errRequestCanceled
	}
	return nil
}

func (rl *http2clientConnReadLoop) processData(f *http2DataFrame) error {
	cc := rl.cc
	cs := rl.streamByID(f.StreamID, http2headerOrDataFrame)
	data := f.Data()
	if cs == nil {
		cc.mu.Lock()
		neverSent := cc.nextStreamID
		cc.mu.Unlock()
		if f.StreamID >= neverSent {
			// We never asked for this.
			cc.logf("http2: Transport received unsolicited DATA frame; closing connection")
			return http2ConnectionError(http2ErrCodeProtocol)
		}
		// We probably did ask for this, but canceled. Just ignore it.
		// TODO: be stricter here? only silently ignore things which
		// we canceled, but not things which were closed normally
		// by the peer? Tough without accumulating too much state.

		// But at least return their flow control:
		if f.Length > 0 {
			cc.mu.Lock()
			ok := cc.inflow.take(f.Length)
			connAdd := cc.inflow.add(int(f.Length))
			cc.mu.Unlock()
			if !ok {
				return http2ConnectionError(http2ErrCodeFlowControl)
			}
			if connAdd > 0 {
				cc.wmu.Lock()
				cc.fr.WriteWindowUpdate(0, uint32(connAdd))
				cc.bw.Flush()
				cc.wmu.Unlock()
			}
		}
		return nil
	}
	if cs.readClosed {
		cc.logf("protocol error: received DATA after END_STREAM")
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
		})
		return nil
	}
	if !cs.pastHeaders {
		cc.logf("protocol error: received DATA before a HEADERS frame")
		rl.endStreamError(cs, http2StreamError{
			StreamID: f.StreamID,
			Code:     http2ErrCodeProtocol,
		})
		return nil
	}
	if f.Length > 0 {
		if cs.isHead && len(data) > 0 {
			cc.logf("protocol error: received DATA on a HEAD request")
			rl.endStreamError(cs, http2StreamError{
				StreamID: f.StreamID,
				Code:     http2ErrCodeProtocol,
			})
			return nil
		}
		// Check connection-level flow control.
		cc.mu.Lock()
		if !http2takeInflows(&cc.inflow, &cs.inflow, f.Length) {
			cc.mu.Unlock()
			return http2ConnectionError(http2ErrCodeFlowControl)
		}
		// Return any padded flow control now, since we won't
		// refund it later on body reads.
		var refund int
		if pad := int(f.Length) - len(data); pad > 0 {
			refund += pad
		}

		didReset := false
		var err error
		if len(data) > 0 {
			if _, err = cs.bufPipe.Write(data); err != nil {
				// Return len(data) now if the stream is already closed,
				// since data will never be read.
				didReset = true
				refund += len(data)
			}
		}

		sendConn := cc.inflow.add(refund)
		var sendStream int32
		if !didReset {
			sendStream = cs.inflow.add(refund)
		}
		cc.mu.Unlock()

		if sendConn > 0 || sendStream > 0 {
			cc.wmu.Lock()
			if sendConn > 0 {
				cc.fr.WriteWindowUpdate(0, uint32(sendConn))
			}
			if sendStream > 0 {
				cc.fr.WriteWindowUpdate(cs.ID, uint32(sendStream))
			}
			cc.bw.Flush()
			cc.wmu.Unlock()
		}

		if err != nil {
			rl.endStreamError(cs, err)
			return nil
		}
	}

	if f.StreamEnded() {
		rl.endStream(cs)
	}
	return nil
}

func (rl *http2clientConnReadLoop) endStream(cs *http2clientStream) {
	// TODO: check that any declared content-length matches, like
	// server.go's (*stream).endStream method.
	if !cs.readClosed {
		cs.readClosed = true
		// Close cs.bufPipe and cs.peerClosed with cc.mu held to avoid a
		// race condition: The caller can read io.EOF from Response.Body
		// and close the body before we close cs.peerClosed, causing
		// cleanupWriteRequest to send a RST_STREAM.
		rl.cc.mu.Lock()
		defer rl.cc.mu.Unlock()
		cs.bufPipe.closeWithErrorAndCode(io.EOF, cs.copyTrailers)
		close(cs.peerClosed)
	}
}

func (rl *http2clientConnReadLoop) endStreamError(cs *http2clientStream, err error) {
	cs.readAborted = true
	cs.abortStream(err)
}

// Constants passed to streamByID for documentation purposes.
const (
	http2headerOrDataFrame    = true
	http2notHeaderOrDataFrame = false
)

// streamByID returns the stream with the given id, or nil if no stream has that id.
// If headerOrData is true, it clears rst.StreamPingsBlocked.
func (rl *http2clientConnReadLoop) streamByID(id uint32, headerOrData bool) *http2clientStream {
	rl.cc.mu.Lock()
	defer rl.cc.mu.Unlock()
	if headerOrData {
		// Work around an unfortunate gRPC behavior.
		// See comment on ClientConn.rstStreamPingsBlocked for details.
		rl.cc.rstStreamPingsBlocked = false
	}
	cs := rl.cc.streams[id]
	if cs != nil && !cs.readAborted {
		return cs
	}
	return nil
}

func (cs *http2clientStream) copyTrailers() {
	for k, vv := range cs.trailer {
		t := cs.resTrailer
		if *t == nil {
			*t = make(Header)
		}
		(*t)[k] = vv
	}
}

func (rl *http2clientConnReadLoop) processGoAway(f *http2GoAwayFrame) error {
	cc := rl.cc
	cc.t.connPool().MarkDead(cc)
	if f.ErrCode != 0 {
		// TODO: deal with GOAWAY more. particularly the error code
		cc.vlogf("transport got GOAWAY with error code = %v", f.ErrCode)
		if fn := cc.t.CountError; fn != nil {
			fn("recv_goaway_" + f.ErrCode.stringToken())
		}
	}
	cc.setGoAway(f)
	return nil
}

func (rl *http2clientConnReadLoop) processSettings(f *http2SettingsFrame) error {
	cc := rl.cc
	// Locking both mu and wmu here allows frame encoding to read settings with only wmu held.
	// Acquiring wmu when f.IsAck() is unnecessary, but convenient and mostly harmless.
	cc.wmu.Lock()
	defer cc.wmu.Unlock()

	if err := rl.processSettingsNoWrite(f); err != nil {
		return err
	}
	if !f.IsAck() {
		cc.fr.WriteSettingsAck()
		cc.bw.Flush()
	}
	return nil
}

func (rl *http2clientConnReadLoop) processSettingsNoWrite(f *http2SettingsFrame) error {
	cc := rl.cc
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if f.IsAck() {
		if cc.wantSettingsAck {
			cc.wantSettingsAck = false
			return nil
		}
		return http2ConnectionError(http2ErrCodeProtocol)
	}

	var seenMaxConcurrentStreams bool
	err := f.ForeachSetting(func(s http2Setting) error {
		switch s.ID {
		case http2SettingMaxFrameSize:
			cc.maxFrameSize = s.Val
		case http2SettingMaxConcurrentStreams:
			cc.maxConcurrentStreams = s.Val
			seenMaxConcurrentStreams = true
		case http2SettingMaxHeaderListSize:
			cc.peerMaxHeaderListSize = uint64(s.Val)
		case http2SettingInitialWindowSize:
			// Values above the maximum flow-control
			// window size of 2^31-1 MUST be treated as a
			// connection error (Section 5.4.1) of type
			// FLOW_CONTROL_ERROR.
			if s.Val > math.MaxInt32 {
				return http2ConnectionError(http2ErrCodeFlowControl)
			}

			// Adjust flow control of currently-open
			// frames by the difference of the old initial
			// window size and this one.
			delta := int32(s.Val) - int32(cc.initialWindowSize)
			for _, cs := range cc.streams {
				cs.flow.add(delta)
			}
			cc.cond.Broadcast()

			cc.initialWindowSize = s.Val
		case http2SettingHeaderTableSize:
			cc.henc.SetMaxDynamicTableSize(s.Val)
			cc.peerMaxHeaderTableSize = s.Val
		case http2SettingEnableConnectProtocol:
			if err := s.Valid(); err != nil {
				return err
			}
			// If the peer wants to send us SETTINGS_ENABLE_CONNECT_PROTOCOL,
			// we require that it do so in the first SETTINGS frame.
			//
			// When we attempt to use extended CONNECT, we wait for the first
			// SETTINGS frame to see if the server supports it. If we let the
			// server enable the feature with a later SETTINGS frame, then
			// users will see inconsistent results depending on whether we've
			// seen that frame or not.
			if !cc.seenSettings {
				cc.extendedConnectAllowed = s.Val == 1
			}
		default:
			cc.vlogf("Unhandled Setting: %v", s)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if !cc.seenSettings {
		if !seenMaxConcurrentStreams {
			// This was the servers initial SETTINGS frame and it
			// didn't contain a MAX_CONCURRENT_STREAMS field so
			// increase the number of concurrent streams this
			// connection can establish to our default.
			cc.maxConcurrentStreams = http2defaultMaxConcurrentStreams
		}
		close(cc.seenSettingsChan)
		cc.seenSettings = true
	}

	return nil
}

func (rl *http2clientConnReadLoop) processWindowUpdate(f *http2WindowUpdateFrame) error {
	cc := rl.cc
	cs := rl.streamByID(f.StreamID, http2notHeaderOrDataFrame)
	if f.StreamID != 0 && cs == nil {
		return nil
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	fl := &cc.flow
	if cs != nil {
		fl = &cs.flow
	}
	if !fl.add(int32(f.Increment)) {
		// For stream, the sender sends RST_STREAM with an error code of FLOW_CONTROL_ERROR
		if cs != nil {
			rl.endStreamError(cs, http2StreamError{
				StreamID: f.StreamID,
				Code:     http2ErrCodeFlowControl,
			})
			return nil
		}

		return http2ConnectionError(http2ErrCodeFlowControl)
	}
	cc.cond.Broadcast()
	return nil
}

func (rl *http2clientConnReadLoop) processResetStream(f *http2RSTStreamFrame) error {
	cs := rl.streamByID(f.StreamID, http2notHeaderOrDataFrame)
	if cs == nil {
		// TODO: return error if server tries to RST_STREAM an idle stream
		return nil
	}
	serr := http2streamError(cs.ID, f.ErrCode)
	serr.Cause = http2errFromPeer
	if f.ErrCode == http2ErrCodeProtocol {
		rl.cc.SetDoNotReuse()
	}
	if fn := cs.cc.t.CountError; fn != nil {
		fn("recv_rststream_" + f.ErrCode.stringToken())
	}
	cs.abortStream(serr)

	cs.bufPipe.CloseWithError(serr)
	return nil
}

// Ping sends a PING frame to the server and waits for the ack.
func (cc *http2ClientConn) Ping(ctx context.Context) error {
	c := make(chan struct{})
	// Generate a random payload
	var p [8]byte
	for {
		if _, err := rand.Read(p[:]); err != nil {
			return err
		}
		cc.mu.Lock()
		// check for dup before insert
		if _, found := cc.pings[p]; !found {
			cc.pings[p] = c
			cc.mu.Unlock()
			break
		}
		cc.mu.Unlock()
	}
	var pingError error
	errc := make(chan struct{})
	go func() {
		cc.t.markNewGoroutine()
		cc.wmu.Lock()
		defer cc.wmu.Unlock()
		if pingError = cc.fr.WritePing(false, p); pingError != nil {
			close(errc)
			return
		}
		if pingError = cc.bw.Flush(); pingError != nil {
			close(errc)
			return
		}
	}()
	select {
	case <-c:
		return nil
	case <-errc:
		return pingError
	case <-ctx.Done():
		return ctx.Err()
	case <-cc.readerDone:
		// connection closed
		return cc.readerErr
	}
}

func (rl *http2clientConnReadLoop) processPing(f *http2PingFrame) error {
	if f.IsAck() {
		cc := rl.cc
		cc.mu.Lock()
		defer cc.mu.Unlock()
		// If ack, notify listener if any
		if c, ok := cc.pings[f.Data]; ok {
			close(c)
			delete(cc.pings, f.Data)
		}
		if cc.pendingResets > 0 {
			// See clientStream.cleanupWriteRequest.
			cc.pendingResets = 0
			cc.rstStreamPingsBlocked = true
			cc.cond.Broadcast()
		}
		return nil
	}
	cc := rl.cc
	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	if err := cc.fr.WritePing(true, f.Data); err != nil {
		return err
	}
	return cc.bw.Flush()
}

func (rl *http2clientConnReadLoop) processPushPromise(f *http2PushPromiseFrame) error {
	// We told the peer we don't want them.
	// Spec says:
	// "PUSH_PROMISE MUST NOT be sent if the SETTINGS_ENABLE_PUSH
	// setting of the peer endpoint is set to 0. An endpoint that
	// has set this setting and has received acknowledgement MUST
	// treat the receipt of a PUSH_PROMISE frame as a connection
	// error (Section 5.4.1) of type PROTOCOL_ERROR."
	return http2ConnectionError(http2ErrCodeProtocol)
}

// writeStreamReset sends a RST_STREAM frame.
// When ping is true, it also sends a PING frame with a random payload.
func (cc *http2ClientConn) writeStreamReset(streamID uint32, code http2ErrCode, ping bool, err error) {
	// TODO: map err to more interesting error codes, once the
	// HTTP community comes up with some. But currently for
	// RST_STREAM there's no equivalent to GOAWAY frame's debug
	// data, and the error codes are all pretty vague ("cancel").
	cc.wmu.Lock()
	cc.fr.WriteRSTStream(streamID, code)
	if ping {
		var payload [8]byte
		rand.Read(payload[:])
		cc.fr.WritePing(false, payload)
	}
	cc.bw.Flush()
	cc.wmu.Unlock()
}

var (
	http2errResponseHeaderListSize = errors.New("http2: response header list larger than advertised limit")
	http2errRequestHeaderListSize  = errors.New("http2: request header list larger than peer's advertised limit")
)

func (cc *http2ClientConn) logf(format string, args ...interface{}) {
	cc.t.logf(format, args...)
}

func (cc *http2ClientConn) vlogf(format string, args ...interface{}) {
	cc.t.vlogf(format, args...)
}

func (t *http2Transport) vlogf(format string, args ...interface{}) {
	if http2VerboseLogs {
		t.logf(format, args...)
	}
}

func (t *http2Transport) logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

var http2noBody io.ReadCloser = http2noBodyReader{}

type http2noBodyReader struct{}

func (http2noBodyReader) Close() error { return nil }

func (http2noBodyReader) Read([]byte) (int, error) { return 0, io.EOF }

type http2missingBody struct{}

func (http2missingBody) Close() error { return nil }

func (http2missingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func http2strSliceContains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

type http2erringRoundTripper struct{ err error }

func (rt http2erringRoundTripper) RoundTripErr() error { return rt.err }

func (rt http2erringRoundTripper) RoundTrip(*Request) (*Response, error) { return nil, rt.err }

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type http2gzipReader struct {
	_    http2incomparable
	body io.ReadCloser // underlying Response.Body
	zr   *gzip.Reader  // lazily-initialized gzip reader
	zerr error         // sticky error
}

func (gz *http2gzipReader) Read(p []byte) (n int, err error) {
	if gz.zerr != nil {
		return 0, gz.zerr
	}
	if gz.zr == nil {
		gz.zr, err = gzip.NewReader(gz.body)
		if err != nil {
			gz.zerr = err
			return 0, err
		}
	}
	return gz.zr.Read(p)
}

func (gz *http2gzipReader) Close() error {
	if err := gz.body.Close(); err != nil {
		return err
	}
	gz.zerr = fs.ErrClosed
	return nil
}

type http2errorReader struct{ err error }

func (r http2errorReader) Read(p []byte) (int, error) { return 0, r.err }

// isConnectionCloseRequest reports whether req should use its own
// connection for a single request and then close the connection.
func http2isConnectionCloseRequest(req *Request) bool {
	return req.Close || httpguts.HeaderValuesContainsToken(req.Header["Connection"], "close")
}

// registerHTTPSProtocol calls Transport.RegisterProtocol but
// converting panics into errors.
func http2registerHTTPSProtocol(t *Transport, rt http2noDialH2RoundTripper) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()
	t.RegisterProtocol("https", rt)
	return nil
}

// noDialH2RoundTripper is a RoundTripper which only tries to complete the request
// if there's already has a cached connection to the host.
// (The field is exported so it can be accessed via reflect from net/http; tested
// by TestNoDialH2RoundTripperType)
type http2noDialH2RoundTripper struct{ *http2Transport }

func (rt http2noDialH2RoundTripper) RoundTrip(req *Request) (*Response, error) {
	res, err := rt.http2Transport.RoundTrip(req)
	if http2isNoCachedConnError(err) {
		return nil, ErrSkipAltProtocol
	}
	return res, err
}

func (t *http2Transport) idleConnTimeout() time.Duration {
	// to keep things backwards compatible, we use non-zero values of
	// IdleConnTimeout, followed by using the IdleConnTimeout on the underlying
	// http1 transport, followed by 0
	if t.IdleConnTimeout != 0 {
		return t.IdleConnTimeout
	}

	if t.t1 != nil {
		return t.t1.IdleConnTimeout
	}

	return 0
}

func http2traceGetConn(req *Request, hostPort string) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace == nil || trace.GetConn == nil {
		return
	}
	trace.GetConn(hostPort)
}

func http2traceGotConn(req *Request, cc *http2ClientConn, reused bool) {
	trace := httptrace.ContextClientTrace(req.Context())
	if trace == nil || trace.GotConn == nil {
		return
	}
	ci := httptrace.GotConnInfo{Conn: cc.tconn}
	ci.Reused = reused
	cc.mu.Lock()
	ci.WasIdle = len(cc.streams) == 0 && reused
	if ci.WasIdle && !cc.lastActive.IsZero() {
		ci.IdleTime = cc.t.timeSince(cc.lastActive)
	}
	cc.mu.Unlock()

	trace.GotConn(ci)
}

func http2traceWroteHeaders(trace *httptrace.ClientTrace) {
	if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}
}

func http2traceGot100Continue(trace *httptrace.ClientTrace) {
	if trace != nil && trace.Got100Continue != nil {
		trace.Got100Continue()
	}
}

func http2traceWait100Continue(trace *httptrace.ClientTrace) {
	if trace != nil && trace.Wait100Continue != nil {
		trace.Wait100Continue()
	}
}

func http2traceWroteRequest(trace *httptrace.ClientTrace, err error) {
	if trace != nil && trace.WroteRequest != nil {
		trace.WroteRequest(httptrace.WroteRequestInfo{Err: err})
	}
}

func http2traceFirstResponseByte(trace *httptrace.ClientTrace) {
	if trace != nil && trace.GotFirstResponseByte != nil {
		trace.GotFirstResponseByte()
	}
}

func http2traceHasWroteHeaderField(trace *httptrace.ClientTrace) bool {
	return trace != nil && trace.WroteHeaderField != nil
}

func http2traceWroteHeaderField(trace *httptrace.ClientTrace, k, v string) {
	if trace != nil && trace.WroteHeaderField != nil {
		trace.WroteHeaderField(k, []string{v})
	}
}

func http2traceGot1xxResponseFunc(trace *httptrace.ClientTrace) func(int, textproto.MIMEHeader) error {
	if trace != nil {
		return trace.Got1xxResponse
	}
	return nil
}

// dialTLSWithContext uses tls.Dialer, added in Go 1.15, to open a TLS
// connection.
func (t *http2Transport) dialTLSWithContext(ctx context.Context, network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		Config: cfg,
	}
	cn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsCn := cn.(*tls.Conn) // DialContext comment promises this will always succeed
	return tlsCn, nil
}

const http2nextProtoUnencryptedHTTP2 = "unencrypted_http2"

// unencryptedNetConnFromTLSConn retrieves a net.Conn wrapped in a *tls.Conn.
//
// TLSNextProto functions accept a *tls.Conn.
//
// When passing an unencrypted HTTP/2 connection to a TLSNextProto function,
// we pass a *tls.Conn with an underlying net.Conn containing the unencrypted connection.
// To be extra careful about mistakes (accidentally dropping TLS encryption in a place
// where we want it), the tls.Conn contains a net.Conn with an UnencryptedNetConn method
// that returns the actual connection we want to use.
func http2unencryptedNetConnFromTLSConn(tc *tls.Conn) (net.Conn, error) {
	conner, ok := tc.NetConn().(interface {
		UnencryptedNetConn() net.Conn
	})
	if !ok {
		return nil, errors.New("http2: TLS conn unexpectedly found in unencrypted handoff")
	}
	return conner.UnencryptedNetConn(), nil
}

// writeFramer is implemented by any type that is used to write frames.
type http2writeFramer interface {
	writeFrame(http2writeContext) error

	// staysWithinBuffer reports whether this writer promises that
	// it will only write less than or equal to size bytes, and it
	// won't Flush the write context.
	staysWithinBuffer(size int) bool
}

// writeContext is the interface needed by the various frame writer
// types below. All the writeFrame methods below are scheduled via the
// frame writing scheduler (see writeScheduler in writesched.go).
//
// This interface is implemented by *serverConn.
//
// TODO: decide whether to a) use this in the client code (which didn't
// end up using this yet, because it has a simpler design, not
// currently implementing priorities), or b) delete this and
// make the server code a bit more concrete.
type http2writeContext interface {
	Framer() *http2Framer
	Flush() error
	CloseConn() error
	// HeaderEncoder returns an HPACK encoder that writes to the
	// returned buffer.
	HeaderEncoder() (*hpack.Encoder, *bytes.Buffer)
}

// writeEndsStream reports whether w writes a frame that will transition
// the stream to a half-closed local state. This returns false for RST_STREAM,
// which closes the entire stream (not just the local half).
func http2writeEndsStream(w http2writeFramer) bool {
	switch v := w.(type) {
	case *http2writeData:
		return v.endStream
	case *http2writeResHeaders:
		return v.endStream
	case nil:
		// This can only happen if the caller reuses w after it's
		// been intentionally nil'ed out to prevent use. Keep this
		// here to catch future refactoring breaking it.
		panic("writeEndsStream called on nil writeFramer")
	}
	return false
}

type http2flushFrameWriter struct{}

func (http2flushFrameWriter) writeFrame(ctx http2writeContext) error {
	return ctx.Flush()
}

func (http2flushFrameWriter) staysWithinBuffer(max int) bool { return false }

type http2writeSettings []http2Setting

func (s http2writeSettings) staysWithinBuffer(max int) bool {
	const settingSize = 6 // uint16 + uint32
	return http2frameHeaderLen+settingSize*len(s) <= max

}

func (s http2writeSettings) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteSettings([]http2Setting(s)...)
}

type http2writeGoAway struct {
	maxStreamID uint32
	code        http2ErrCode
}

func (p *http2writeGoAway) writeFrame(ctx http2writeContext) error {
	err := ctx.Framer().WriteGoAway(p.maxStreamID, p.code, nil)
	ctx.Flush() // ignore error: we're hanging up on them anyway
	return err
}

func (*http2writeGoAway) staysWithinBuffer(max int) bool { return false } // flushes

type http2writeData struct {
	streamID  uint32
	p         []byte
	endStream bool
}

func (w *http2writeData) String() string {
	return fmt.Sprintf("writeData(stream=%d, p=%d, endStream=%v)", w.streamID, len(w.p), w.endStream)
}

func (w *http2writeData) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteData(w.streamID, w.endStream, w.p)
}

func (w *http2writeData) staysWithinBuffer(max int) bool {
	return http2frameHeaderLen+len(w.p) <= max
}

// handlerPanicRST is the message sent from handler goroutines when
// the handler panics.
type http2handlerPanicRST struct {
	StreamID uint32
}

func (hp http2handlerPanicRST) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteRSTStream(hp.StreamID, http2ErrCodeInternal)
}

func (hp http2handlerPanicRST) staysWithinBuffer(max int) bool { return http2frameHeaderLen+4 <= max }

func (se http2StreamError) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteRSTStream(se.StreamID, se.Code)
}

func (se http2StreamError) staysWithinBuffer(max int) bool { return http2frameHeaderLen+4 <= max }

type http2writePing struct {
	data [8]byte
}

func (w http2writePing) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WritePing(false, w.data)
}

func (w http2writePing) staysWithinBuffer(max int) bool {
	return http2frameHeaderLen+len(w.data) <= max
}

type http2writePingAck struct{ pf *http2PingFrame }

func (w http2writePingAck) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WritePing(true, w.pf.Data)
}

func (w http2writePingAck) staysWithinBuffer(max int) bool {
	return http2frameHeaderLen+len(w.pf.Data) <= max
}

type http2writeSettingsAck struct{}

func (http2writeSettingsAck) writeFrame(ctx http2writeContext) error {
	return ctx.Framer().WriteSettingsAck()
}

func (http2writeSettingsAck) staysWithinBuffer(max int) bool { return http2frameHeaderLen <= max }

// splitHeaderBlock splits headerBlock into fragments so that each fragment fits
// in a single frame, then calls fn for
```