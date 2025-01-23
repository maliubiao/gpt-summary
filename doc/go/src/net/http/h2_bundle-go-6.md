Response:
My thought process to answer the request goes through these stages:

1. **Understanding the Goal:** The user wants a summary of the Go code's functionality, inferring its purpose within the `net/http` package, and providing illustrative examples where applicable. The context is HTTP/2 server-side processing. The request also emphasizes common pitfalls and handling of command-line arguments (though this specific snippet doesn't show CLI interaction).

2. **Decomposition and Keyword Identification:** I scan the code for key function names and data structures. Important keywords emerge:
    * `http2serverConn`:  This is clearly the central structure, representing an HTTP/2 server connection.
    * `process*`:  Functions like `processSettings`, `processData`, `processHeaders`, `processGoAway`, `processPriority` indicate the code handles different HTTP/2 frame types.
    * `closeStream`:  Deals with closing HTTP/2 streams.
    * `newStream`, `newWriterAndRequest`:  Functions related to creating new streams and handling incoming requests.
    * `scheduleHandler`, `runHandler`:  Focus on the execution of HTTP request handlers.
    * `write*`:  Functions like `writeHeaders`, `writeChunk` are responsible for sending data back to the client.
    * `http2stream`: Represents an individual HTTP/2 stream.
    * `http2requestBody`, `http2responseWriter`:  The types used to interact with request and response bodies within the Go `net/http` framework.
    * States like `http2stateIdle`, `http2stateOpen`, `http2stateClosed`:  Crucial for understanding the lifecycle of a stream.
    * Error handling (`countError`, specific error types like `http2ErrCodeProtocol`, `http2ErrCodeStreamClosed`).
    * Flow control (`sendWindowUpdate`, `inflow`).
    * Settings (`http2Setting*` constants).
    * Priorities (`http2PriorityParam`).
    * Trailers.
    * Timeouts (`ReadTimeout`, `WriteTimeout`).
    * Push.

3. **Inferring the High-Level Functionality:** Based on the keywords, I can infer that this code is responsible for:
    * **Managing the lifecycle of HTTP/2 connections and streams.** This includes handling state transitions, opening and closing streams, and managing concurrent streams.
    * **Receiving and processing different types of HTTP/2 frames** from the client, such as `SETTINGS`, `DATA`, `HEADERS`, `GOAWAY`, and `PRIORITY`.
    * **Handling incoming HTTP requests** by creating `Request` objects and dispatching them to the appropriate handlers.
    * **Sending HTTP responses** back to the client, including headers, body, and trailers.
    * **Implementing flow control** to manage the rate at which data is sent and received.
    * **Enforcing HTTP/2 protocol rules** and handling errors.
    * **Managing server settings** received from the client.
    * **Supporting server push** (indicated by `pushEnabled`).
    * **Handling timeouts** for read and write operations on streams.
    * **Graceful shutdown** of the connection.

4. **Structuring the Answer:** I organize the answer into logical sections to make it easy to understand:
    * **核心功能:** Start with the most important overall functionalities.
    * **具体功能:** Break down the core functionalities into more granular details, directly mapping to the identified keywords and function groups.
    * **Go语言功能实现推断 (with Example):** Focus on a specific, illustrative example. The "processing headers" and creation of a new request is a good choice as it combines several concepts. Include assumptions about input and the expected output or behavior.
    * **代码推理 (with Assumptions and I/O):** Select a more complex piece of logic for in-depth analysis. The `processData` function is a good candidate because it involves state checks, flow control, and handling of the request body. Clearly state assumptions about the input frame and explain the expected actions and potential outputs.
    * **命令行参数处理:** Explicitly address this, noting that this particular snippet doesn't handle them directly, but explaining *where* such handling might occur in a larger HTTP/2 server implementation.
    * **易犯错的点:**  Think about common mistakes developers make when working with HTTP/2, especially related to stream states, flow control, and header/trailer handling.
    * **归纳功能:**  Summarize the key takeaways.

5. **Crafting the Code Examples and Explanations:**  For the code examples, I aim for clarity and conciseness. I make sure to:
    * **Provide clear input data structures or scenarios.**
    * **Explain the expected behavior or output based on the code logic.**
    * **Focus on illustrating the specific concept being discussed.**
    * **Use comments to clarify the code.**

6. **Review and Refinement:** After drafting the initial answer, I review it for:
    * **Accuracy:** Ensure the explanation correctly reflects the code's behavior.
    * **Completeness:**  Cover all the key functionalities identified.
    * **Clarity:**  Use clear and concise language. Avoid jargon where possible or explain it.
    * **Organization:**  Ensure the sections flow logically and are easy to follow.
    * **Addressing all parts of the prompt:** Double-check that I've answered every question in the user's request.

This systematic approach, moving from high-level understanding to detailed analysis and then structuring the information clearly, helps to generate a comprehensive and helpful answer to the user's request.
这是提供的 Go 语言代码片段（`go/src/net/http/h2_bundle.go` 的一部分，第 7/13 部分）主要负责处理 HTTP/2 服务器连接中接收到的各种帧，并根据帧的类型执行相应的操作。它涵盖了连接和流的生命周期管理、错误处理、设置处理、数据传输、首部和尾部处理以及优先级管理等方面。

以下是对其功能的详细列举和推断：

**核心功能:**

1. **处理 RST_STREAM 帧:** 当接收到 `RST_STREAM` 帧时，会取消对应流的上下文，并关闭该流，表明该流已被客户端或服务器终止。对于空闲状态的流接收到 `RST_STREAM` 帧会被视为连接错误。
2. **关闭流 (`closeStream`):**  负责安全地关闭一个 HTTP/2 流。这包括更新连接和流的状态，停止相关的定时器，释放资源，通知监听器流已关闭，并处理流相关的错误。如果流是被推送的，会更新推送流的计数。
3. **处理 SETTINGS 帧 (`processSettings`, `processSetting`, `processSettingInitialWindowSize`):**  处理来自客户端的 `SETTINGS` 帧，更新服务器的内部设置，例如头部表大小、是否启用推送、最大并发流数、初始窗口大小和最大帧大小等。它还负责发送 `SETTINGS` 确认帧。
4. **处理 DATA 帧 (`processData`):**  处理来自客户端的 `DATA` 帧，接收请求体数据。它会检查流的状态、内容长度是否匹配、流控等，并将数据写入请求体的管道中。如果接收到流结束标志，则标记流结束。
5. **处理 GOAWAY 帧 (`processGoAway`):**  处理来自客户端的 `GOAWAY` 帧，表明客户端将要关闭连接。服务器会开始优雅关闭过程，并且不再创建新的推送流。
6. **处理 HEADERS 帧 (`processHeaders`):** 处理来自客户端的 `HEADERS` 帧，用于创建新的流或发送尾部。它会检查流 ID 的有效性，处理优先级信息，创建请求和响应写入器，并将请求交给处理函数。对于接收到尾部的情况，会调用 `processTrailerHeaders` 进行处理。
7. **处理优先级 (`processPriority`, `checkPriority`):** 处理客户端发送的 `PRIORITY` 帧，调整流的优先级。会检查优先级依赖的有效性，避免流依赖自身。
8. **创建新的流 (`newStream`):**  创建新的 HTTP/2 流，初始化流的状态、上下文、流控窗口、定时器等，并将其添加到连接的流列表中。
9. **创建请求和响应写入器 (`newWriterAndRequest`, `newWriterAndRequestNoBody`, `newResponseWriter`):**  根据接收到的首部信息创建 `http.Request` 对象和 `http.ResponseWriter` 对象，以便处理函数可以处理请求并发送响应。
10. **调度和运行处理函数 (`scheduleHandler`, `runHandler`, `handlerDone`):**  管理 HTTP 请求处理函数的执行。它会控制并发处理的请求数量，并将请求交给 Goroutine 执行。当处理函数完成时，会清理资源并可能启动下一个等待处理的请求。
11. **处理尾部 (`processTrailerHeaders`, `copyTrailersToHandlerRequest`):** 处理 `HEADERS` 帧作为尾部发送的情况，将尾部信息添加到 `Request.Trailer` 中。
12. **处理超时 (`onReadTimeout`, `onWriteTimeout`):**  处理流的读写超时，当超时发生时，会关闭连接或发送 RST_STREAM 帧。
13. **升级请求 (`upgradeRequest`):**  处理 HTTP 升级到 HTTP/2 的场景，为升级后的连接创建初始流和请求/响应结构。

**Go 语言功能实现推断 (带代码示例):**

这个代码片段是 `net/http` 包中 HTTP/2 服务器连接管理的核心部分。它利用 Goroutine 并发处理多个请求，使用 channel 进行 Goroutine 间的通信，例如 `bodyReadCh`。错误处理使用了自定义的错误类型，例如 `http2ConnectionError` 和 `http2streamError`。

**示例：处理 HEADERS 帧创建新流和请求**

假设服务器接收到一个来自客户端的 `HEADERS` 帧，其 `StreamID` 为 1，表示一个客户端发起的新请求。

```go
// 假设接收到的 HEADERS 帧
f := &http2MetaHeadersFrame{
	FrameHeader: http2FrameHeader{
		Type:     http2FrameTypeHeaders,
		Flags:    http2FlagHeadersEndHeaders,
		StreamID: 1,
	},
	// 假设首部信息
	hf: []http2HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/index.html"},
		{Name: ":scheme", Value: "https"},
		{Name: "Host", Value: "example.com"},
	},
}

// 假设当前服务器连接对象 sc
sc := &http2serverConn{
	maxClientStreamID: 0, // 假设当前最大客户端流 ID 为 0
	streams:           make(map[uint32]*http2stream),
	curClientStreams:  0,
	advMaxStreams:     100, // 假设允许的最大并发流数为 100
	handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("处理请求:", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, HTTP/2!"))
	}),
	// ... 其他字段
}

// 调用 processHeaders 处理
err := sc.processHeaders(f)
if err != nil {
	fmt.Println("处理 HEADERS 帧出错:", err)
}

// 假设处理成功，预期输出：
// - sc.maxClientStreamID 将变为 1
// - sc.streams 中会添加一个 StreamID 为 1 的 http2stream 对象
// - 会创建一个 http.Request 对象，其 URL.Path 为 "/index.html"
// - 一个 Goroutine 会被启动来执行 sc.handler 处理该请求，并打印 "处理请求: /index.html"
```

**代码推理 (带假设的输入与输出):**

**场景：处理 DATA 帧**

假设服务器当前处理一个 `StreamID` 为 1 的请求，并且已经接收到了一些首部信息。现在接收到一个 `DATA` 帧，包含一些请求体数据。

**假设输入:**

```go
f := &http2DataFrame{
	FrameHeader: http2FrameHeader{
		Type:     http2FrameTypeData,
		Flags:    http2FlagDataEndStream, // 假设这是最后一个数据帧
		StreamID: 1,
		Length:   13,
	},
	payload: []byte("request body"),
}

// 假设 sc.streams[1] 存在，并且其 state 为 http2stateOpen
st := sc.streams[1]
st.body = &http2requestBody{pipe: &http2pipe{b: &http2dataBuffer{}}} // 假设 body 已初始化
```

**代码执行过程:**

1. `processData(f)` 被调用。
2. 检查 `f.StreamID` (1) 和流的状态 (假设为 `http2stateOpen`)。
3. 获取 `f.Data()` ( "request body" )。
4. 调用 `st.body.Write(f.Data())` 将数据写入请求体管道。
5. 如果 `f.StreamEnded()` 为 true，则调用 `st.endStream()` 关闭请求体管道。

**预期输出:**

- 数据 "request body" 被写入 `st.body` 的管道中。
- 如果 `http2FlagDataEndStream` 被设置，`st.state` 将变为 `http2stateHalfClosedRemote`。
- 如果发生流控错误或数据长度不匹配，可能会返回错误。

**命令行参数的具体处理:**

在这个代码片段中，没有直接处理命令行参数的逻辑。HTTP/2 服务器的命令行参数处理通常发生在服务器启动的入口点，例如 `main` 函数中。这些参数可能包括监听地址、TLS 证书路径、超时时间等。`net/http` 包的 `ListenAndServeTLS` 或 `ListenAndServe` 函数会接收这些参数。

**使用者易犯错的点:**

1. **流状态管理错误:**  没有正确理解 HTTP/2 流的状态转换，例如在 `HALF_CLOSED_REMOTE` 状态下尝试发送数据。
2. **流控理解不足:**  不理解 HTTP/2 的流控机制，导致发送超过窗口大小的数据，或者没有及时更新窗口。
3. **首部和尾部处理错误:**  错误地发送或接收尾部，例如在非尾部的 `HEADERS` 帧中包含尾部首部，或者重复发送尾部。
4. **并发处理不当:**  在处理函数中直接修改共享的连接状态，可能导致竞态条件。
5. **超时配置不合理:**  设置过短的超时时间可能导致正常请求失败，设置过长的超时时间可能导致资源浪费。

**归纳功能:**

总而言之，这个代码片段是 Go 语言 `net/http` 包中 HTTP/2 服务器连接处理的核心逻辑，负责接收和处理来自客户端的各种 HTTP/2 帧，管理连接和流的生命周期，实施流控，并将请求调度到处理函数，是构建高性能 HTTP/2 服务器的关键组成部分。它确保了服务器能够正确地与 HTTP/2 客户端进行通信，并遵循 HTTP/2 协议规范。

### 提示词
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
== http2stateIdle {
		// 6.4 "RST_STREAM frames MUST NOT be sent for a
		// stream in the "idle" state. If a RST_STREAM frame
		// identifying an idle stream is received, the
		// recipient MUST treat this as a connection error
		// (Section 5.4.1) of type PROTOCOL_ERROR.
		return sc.countError("reset_idle_stream", http2ConnectionError(http2ErrCodeProtocol))
	}
	if st != nil {
		st.cancelCtx()
		sc.closeStream(st, http2streamError(f.StreamID, f.ErrCode))
	}
	return nil
}

func (sc *http2serverConn) closeStream(st *http2stream, err error) {
	sc.serveG.check()
	if st.state == http2stateIdle || st.state == http2stateClosed {
		panic(fmt.Sprintf("invariant; can't close stream in state %v", st.state))
	}
	st.state = http2stateClosed
	if st.readDeadline != nil {
		st.readDeadline.Stop()
	}
	if st.writeDeadline != nil {
		st.writeDeadline.Stop()
	}
	if st.isPushed() {
		sc.curPushedStreams--
	} else {
		sc.curClientStreams--
	}
	delete(sc.streams, st.id)
	if len(sc.streams) == 0 {
		sc.setConnState(StateIdle)
		if sc.srv.IdleTimeout > 0 && sc.idleTimer != nil {
			sc.idleTimer.Reset(sc.srv.IdleTimeout)
		}
		if http2h1ServerKeepAlivesDisabled(sc.hs) {
			sc.startGracefulShutdownInternal()
		}
	}
	if p := st.body; p != nil {
		// Return any buffered unread bytes worth of conn-level flow control.
		// See golang.org/issue/16481
		sc.sendWindowUpdate(nil, p.Len())

		p.CloseWithError(err)
	}
	if e, ok := err.(http2StreamError); ok {
		if e.Cause != nil {
			err = e.Cause
		} else {
			err = http2errStreamClosed
		}
	}
	st.closeErr = err
	st.cancelCtx()
	st.cw.Close() // signals Handler's CloseNotifier, unblocks writes, etc
	sc.writeSched.CloseStream(st.id)
}

func (sc *http2serverConn) processSettings(f *http2SettingsFrame) error {
	sc.serveG.check()
	if f.IsAck() {
		sc.unackedSettings--
		if sc.unackedSettings < 0 {
			// Why is the peer ACKing settings we never sent?
			// The spec doesn't mention this case, but
			// hang up on them anyway.
			return sc.countError("ack_mystery", http2ConnectionError(http2ErrCodeProtocol))
		}
		return nil
	}
	if f.NumSettings() > 100 || f.HasDuplicates() {
		// This isn't actually in the spec, but hang up on
		// suspiciously large settings frames or those with
		// duplicate entries.
		return sc.countError("settings_big_or_dups", http2ConnectionError(http2ErrCodeProtocol))
	}
	if err := f.ForeachSetting(sc.processSetting); err != nil {
		return err
	}
	// TODO: judging by RFC 7540, Section 6.5.3 each SETTINGS frame should be
	// acknowledged individually, even if multiple are received before the ACK.
	sc.needToSendSettingsAck = true
	sc.scheduleFrameWrite()
	return nil
}

func (sc *http2serverConn) processSetting(s http2Setting) error {
	sc.serveG.check()
	if err := s.Valid(); err != nil {
		return err
	}
	if http2VerboseLogs {
		sc.vlogf("http2: server processing setting %v", s)
	}
	switch s.ID {
	case http2SettingHeaderTableSize:
		sc.hpackEncoder.SetMaxDynamicTableSize(s.Val)
	case http2SettingEnablePush:
		sc.pushEnabled = s.Val != 0
	case http2SettingMaxConcurrentStreams:
		sc.clientMaxStreams = s.Val
	case http2SettingInitialWindowSize:
		return sc.processSettingInitialWindowSize(s.Val)
	case http2SettingMaxFrameSize:
		sc.maxFrameSize = int32(s.Val) // the maximum valid s.Val is < 2^31
	case http2SettingMaxHeaderListSize:
		sc.peerMaxHeaderListSize = s.Val
	case http2SettingEnableConnectProtocol:
		// Receipt of this parameter by a server does not
		// have any impact
	default:
		// Unknown setting: "An endpoint that receives a SETTINGS
		// frame with any unknown or unsupported identifier MUST
		// ignore that setting."
		if http2VerboseLogs {
			sc.vlogf("http2: server ignoring unknown setting %v", s)
		}
	}
	return nil
}

func (sc *http2serverConn) processSettingInitialWindowSize(val uint32) error {
	sc.serveG.check()
	// Note: val already validated to be within range by
	// processSetting's Valid call.

	// "A SETTINGS frame can alter the initial flow control window
	// size for all current streams. When the value of
	// SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST
	// adjust the size of all stream flow control windows that it
	// maintains by the difference between the new value and the
	// old value."
	old := sc.initialStreamSendWindowSize
	sc.initialStreamSendWindowSize = int32(val)
	growth := int32(val) - old // may be negative
	for _, st := range sc.streams {
		if !st.flow.add(growth) {
			// 6.9.2 Initial Flow Control Window Size
			// "An endpoint MUST treat a change to
			// SETTINGS_INITIAL_WINDOW_SIZE that causes any flow
			// control window to exceed the maximum size as a
			// connection error (Section 5.4.1) of type
			// FLOW_CONTROL_ERROR."
			return sc.countError("setting_win_size", http2ConnectionError(http2ErrCodeFlowControl))
		}
	}
	return nil
}

func (sc *http2serverConn) processData(f *http2DataFrame) error {
	sc.serveG.check()
	id := f.Header().StreamID

	data := f.Data()
	state, st := sc.state(id)
	if id == 0 || state == http2stateIdle {
		// Section 6.1: "DATA frames MUST be associated with a
		// stream. If a DATA frame is received whose stream
		// identifier field is 0x0, the recipient MUST respond
		// with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR."
		//
		// Section 5.1: "Receiving any frame other than HEADERS
		// or PRIORITY on a stream in this state MUST be
		// treated as a connection error (Section 5.4.1) of
		// type PROTOCOL_ERROR."
		return sc.countError("data_on_idle", http2ConnectionError(http2ErrCodeProtocol))
	}

	// "If a DATA frame is received whose stream is not in "open"
	// or "half closed (local)" state, the recipient MUST respond
	// with a stream error (Section 5.4.2) of type STREAM_CLOSED."
	if st == nil || state != http2stateOpen || st.gotTrailerHeader || st.resetQueued {
		// This includes sending a RST_STREAM if the stream is
		// in stateHalfClosedLocal (which currently means that
		// the http.Handler returned, so it's done reading &
		// done writing). Try to stop the client from sending
		// more DATA.

		// But still enforce their connection-level flow control,
		// and return any flow control bytes since we're not going
		// to consume them.
		if !sc.inflow.take(f.Length) {
			return sc.countError("data_flow", http2streamError(id, http2ErrCodeFlowControl))
		}
		sc.sendWindowUpdate(nil, int(f.Length)) // conn-level

		if st != nil && st.resetQueued {
			// Already have a stream error in flight. Don't send another.
			return nil
		}
		return sc.countError("closed", http2streamError(id, http2ErrCodeStreamClosed))
	}
	if st.body == nil {
		panic("internal error: should have a body in this state")
	}

	// Sender sending more than they'd declared?
	if st.declBodyBytes != -1 && st.bodyBytes+int64(len(data)) > st.declBodyBytes {
		if !sc.inflow.take(f.Length) {
			return sc.countError("data_flow", http2streamError(id, http2ErrCodeFlowControl))
		}
		sc.sendWindowUpdate(nil, int(f.Length)) // conn-level

		st.body.CloseWithError(fmt.Errorf("sender tried to send more than declared Content-Length of %d bytes", st.declBodyBytes))
		// RFC 7540, sec 8.1.2.6: A request or response is also malformed if the
		// value of a content-length header field does not equal the sum of the
		// DATA frame payload lengths that form the body.
		return sc.countError("send_too_much", http2streamError(id, http2ErrCodeProtocol))
	}
	if f.Length > 0 {
		// Check whether the client has flow control quota.
		if !http2takeInflows(&sc.inflow, &st.inflow, f.Length) {
			return sc.countError("flow_on_data_length", http2streamError(id, http2ErrCodeFlowControl))
		}

		if len(data) > 0 {
			st.bodyBytes += int64(len(data))
			wrote, err := st.body.Write(data)
			if err != nil {
				// The handler has closed the request body.
				// Return the connection-level flow control for the discarded data,
				// but not the stream-level flow control.
				sc.sendWindowUpdate(nil, int(f.Length)-wrote)
				return nil
			}
			if wrote != len(data) {
				panic("internal error: bad Writer")
			}
		}

		// Return any padded flow control now, since we won't
		// refund it later on body reads.
		// Call sendWindowUpdate even if there is no padding,
		// to return buffered flow control credit if the sent
		// window has shrunk.
		pad := int32(f.Length) - int32(len(data))
		sc.sendWindowUpdate32(nil, pad)
		sc.sendWindowUpdate32(st, pad)
	}
	if f.StreamEnded() {
		st.endStream()
	}
	return nil
}

func (sc *http2serverConn) processGoAway(f *http2GoAwayFrame) error {
	sc.serveG.check()
	if f.ErrCode != http2ErrCodeNo {
		sc.logf("http2: received GOAWAY %+v, starting graceful shutdown", f)
	} else {
		sc.vlogf("http2: received GOAWAY %+v, starting graceful shutdown", f)
	}
	sc.startGracefulShutdownInternal()
	// http://tools.ietf.org/html/rfc7540#section-6.8
	// We should not create any new streams, which means we should disable push.
	sc.pushEnabled = false
	return nil
}

// isPushed reports whether the stream is server-initiated.
func (st *http2stream) isPushed() bool {
	return st.id%2 == 0
}

// endStream closes a Request.Body's pipe. It is called when a DATA
// frame says a request body is over (or after trailers).
func (st *http2stream) endStream() {
	sc := st.sc
	sc.serveG.check()

	if st.declBodyBytes != -1 && st.declBodyBytes != st.bodyBytes {
		st.body.CloseWithError(fmt.Errorf("request declared a Content-Length of %d but only wrote %d bytes",
			st.declBodyBytes, st.bodyBytes))
	} else {
		st.body.closeWithErrorAndCode(io.EOF, st.copyTrailersToHandlerRequest)
		st.body.CloseWithError(io.EOF)
	}
	st.state = http2stateHalfClosedRemote
}

// copyTrailersToHandlerRequest is run in the Handler's goroutine in
// its Request.Body.Read just before it gets io.EOF.
func (st *http2stream) copyTrailersToHandlerRequest() {
	for k, vv := range st.trailer {
		if _, ok := st.reqTrailer[k]; ok {
			// Only copy it over it was pre-declared.
			st.reqTrailer[k] = vv
		}
	}
}

// onReadTimeout is run on its own goroutine (from time.AfterFunc)
// when the stream's ReadTimeout has fired.
func (st *http2stream) onReadTimeout() {
	if st.body != nil {
		// Wrap the ErrDeadlineExceeded to avoid callers depending on us
		// returning the bare error.
		st.body.CloseWithError(fmt.Errorf("%w", os.ErrDeadlineExceeded))
	}
}

// onWriteTimeout is run on its own goroutine (from time.AfterFunc)
// when the stream's WriteTimeout has fired.
func (st *http2stream) onWriteTimeout() {
	st.sc.writeFrameFromHandler(http2FrameWriteRequest{write: http2StreamError{
		StreamID: st.id,
		Code:     http2ErrCodeInternal,
		Cause:    os.ErrDeadlineExceeded,
	}})
}

func (sc *http2serverConn) processHeaders(f *http2MetaHeadersFrame) error {
	sc.serveG.check()
	id := f.StreamID
	// http://tools.ietf.org/html/rfc7540#section-5.1.1
	// Streams initiated by a client MUST use odd-numbered stream
	// identifiers. [...] An endpoint that receives an unexpected
	// stream identifier MUST respond with a connection error
	// (Section 5.4.1) of type PROTOCOL_ERROR.
	if id%2 != 1 {
		return sc.countError("headers_even", http2ConnectionError(http2ErrCodeProtocol))
	}
	// A HEADERS frame can be used to create a new stream or
	// send a trailer for an open one. If we already have a stream
	// open, let it process its own HEADERS frame (trailers at this
	// point, if it's valid).
	if st := sc.streams[f.StreamID]; st != nil {
		if st.resetQueued {
			// We're sending RST_STREAM to close the stream, so don't bother
			// processing this frame.
			return nil
		}
		// RFC 7540, sec 5.1: If an endpoint receives additional frames, other than
		// WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in
		// this state, it MUST respond with a stream error (Section 5.4.2) of
		// type STREAM_CLOSED.
		if st.state == http2stateHalfClosedRemote {
			return sc.countError("headers_half_closed", http2streamError(id, http2ErrCodeStreamClosed))
		}
		return st.processTrailerHeaders(f)
	}

	// [...] The identifier of a newly established stream MUST be
	// numerically greater than all streams that the initiating
	// endpoint has opened or reserved. [...]  An endpoint that
	// receives an unexpected stream identifier MUST respond with
	// a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
	if id <= sc.maxClientStreamID {
		return sc.countError("stream_went_down", http2ConnectionError(http2ErrCodeProtocol))
	}
	sc.maxClientStreamID = id

	if sc.idleTimer != nil {
		sc.idleTimer.Stop()
	}

	// http://tools.ietf.org/html/rfc7540#section-5.1.2
	// [...] Endpoints MUST NOT exceed the limit set by their peer. An
	// endpoint that receives a HEADERS frame that causes their
	// advertised concurrent stream limit to be exceeded MUST treat
	// this as a stream error (Section 5.4.2) of type PROTOCOL_ERROR
	// or REFUSED_STREAM.
	if sc.curClientStreams+1 > sc.advMaxStreams {
		if sc.unackedSettings == 0 {
			// They should know better.
			return sc.countError("over_max_streams", http2streamError(id, http2ErrCodeProtocol))
		}
		// Assume it's a network race, where they just haven't
		// received our last SETTINGS update. But actually
		// this can't happen yet, because we don't yet provide
		// a way for users to adjust server parameters at
		// runtime.
		return sc.countError("over_max_streams_race", http2streamError(id, http2ErrCodeRefusedStream))
	}

	initialState := http2stateOpen
	if f.StreamEnded() {
		initialState = http2stateHalfClosedRemote
	}
	st := sc.newStream(id, 0, initialState)

	if f.HasPriority() {
		if err := sc.checkPriority(f.StreamID, f.Priority); err != nil {
			return err
		}
		sc.writeSched.AdjustStream(st.id, f.Priority)
	}

	rw, req, err := sc.newWriterAndRequest(st, f)
	if err != nil {
		return err
	}
	st.reqTrailer = req.Trailer
	if st.reqTrailer != nil {
		st.trailer = make(Header)
	}
	st.body = req.Body.(*http2requestBody).pipe // may be nil
	st.declBodyBytes = req.ContentLength

	handler := sc.handler.ServeHTTP
	if f.Truncated {
		// Their header list was too long. Send a 431 error.
		handler = http2handleHeaderListTooLong
	} else if err := http2checkValidHTTP2RequestHeaders(req.Header); err != nil {
		handler = http2new400Handler(err)
	}

	// The net/http package sets the read deadline from the
	// http.Server.ReadTimeout during the TLS handshake, but then
	// passes the connection off to us with the deadline already
	// set. Disarm it here after the request headers are read,
	// similar to how the http1 server works. Here it's
	// technically more like the http1 Server's ReadHeaderTimeout
	// (in Go 1.8), though. That's a more sane option anyway.
	if sc.hs.ReadTimeout > 0 {
		sc.conn.SetReadDeadline(time.Time{})
		st.readDeadline = sc.srv.afterFunc(sc.hs.ReadTimeout, st.onReadTimeout)
	}

	return sc.scheduleHandler(id, rw, req, handler)
}

func (sc *http2serverConn) upgradeRequest(req *Request) {
	sc.serveG.check()
	id := uint32(1)
	sc.maxClientStreamID = id
	st := sc.newStream(id, 0, http2stateHalfClosedRemote)
	st.reqTrailer = req.Trailer
	if st.reqTrailer != nil {
		st.trailer = make(Header)
	}
	rw := sc.newResponseWriter(st, req)

	// Disable any read deadline set by the net/http package
	// prior to the upgrade.
	if sc.hs.ReadTimeout > 0 {
		sc.conn.SetReadDeadline(time.Time{})
	}

	// This is the first request on the connection,
	// so start the handler directly rather than going
	// through scheduleHandler.
	sc.curHandlers++
	go sc.runHandler(rw, req, sc.handler.ServeHTTP)
}

func (st *http2stream) processTrailerHeaders(f *http2MetaHeadersFrame) error {
	sc := st.sc
	sc.serveG.check()
	if st.gotTrailerHeader {
		return sc.countError("dup_trailers", http2ConnectionError(http2ErrCodeProtocol))
	}
	st.gotTrailerHeader = true
	if !f.StreamEnded() {
		return sc.countError("trailers_not_ended", http2streamError(st.id, http2ErrCodeProtocol))
	}

	if len(f.PseudoFields()) > 0 {
		return sc.countError("trailers_pseudo", http2streamError(st.id, http2ErrCodeProtocol))
	}
	if st.trailer != nil {
		for _, hf := range f.RegularFields() {
			key := sc.canonicalHeader(hf.Name)
			if !httpguts.ValidTrailerHeader(key) {
				// TODO: send more details to the peer somehow. But http2 has
				// no way to send debug data at a stream level. Discuss with
				// HTTP folk.
				return sc.countError("trailers_bogus", http2streamError(st.id, http2ErrCodeProtocol))
			}
			st.trailer[key] = append(st.trailer[key], hf.Value)
		}
	}
	st.endStream()
	return nil
}

func (sc *http2serverConn) checkPriority(streamID uint32, p http2PriorityParam) error {
	if streamID == p.StreamDep {
		// Section 5.3.1: "A stream cannot depend on itself. An endpoint MUST treat
		// this as a stream error (Section 5.4.2) of type PROTOCOL_ERROR."
		// Section 5.3.3 says that a stream can depend on one of its dependencies,
		// so it's only self-dependencies that are forbidden.
		return sc.countError("priority", http2streamError(streamID, http2ErrCodeProtocol))
	}
	return nil
}

func (sc *http2serverConn) processPriority(f *http2PriorityFrame) error {
	if err := sc.checkPriority(f.StreamID, f.http2PriorityParam); err != nil {
		return err
	}
	sc.writeSched.AdjustStream(f.StreamID, f.http2PriorityParam)
	return nil
}

func (sc *http2serverConn) newStream(id, pusherID uint32, state http2streamState) *http2stream {
	sc.serveG.check()
	if id == 0 {
		panic("internal error: cannot create stream with id 0")
	}

	ctx, cancelCtx := context.WithCancel(sc.baseCtx)
	st := &http2stream{
		sc:        sc,
		id:        id,
		state:     state,
		ctx:       ctx,
		cancelCtx: cancelCtx,
	}
	st.cw.Init()
	st.flow.conn = &sc.flow // link to conn-level counter
	st.flow.add(sc.initialStreamSendWindowSize)
	st.inflow.init(sc.initialStreamRecvWindowSize)
	if sc.hs.WriteTimeout > 0 {
		st.writeDeadline = sc.srv.afterFunc(sc.hs.WriteTimeout, st.onWriteTimeout)
	}

	sc.streams[id] = st
	sc.writeSched.OpenStream(st.id, http2OpenStreamOptions{PusherID: pusherID})
	if st.isPushed() {
		sc.curPushedStreams++
	} else {
		sc.curClientStreams++
	}
	if sc.curOpenStreams() == 1 {
		sc.setConnState(StateActive)
	}

	return st
}

func (sc *http2serverConn) newWriterAndRequest(st *http2stream, f *http2MetaHeadersFrame) (*http2responseWriter, *Request, error) {
	sc.serveG.check()

	rp := http2requestParam{
		method:    f.PseudoValue("method"),
		scheme:    f.PseudoValue("scheme"),
		authority: f.PseudoValue("authority"),
		path:      f.PseudoValue("path"),
		protocol:  f.PseudoValue("protocol"),
	}

	// extended connect is disabled, so we should not see :protocol
	if http2disableExtendedConnectProtocol && rp.protocol != "" {
		return nil, nil, sc.countError("bad_connect", http2streamError(f.StreamID, http2ErrCodeProtocol))
	}

	isConnect := rp.method == "CONNECT"
	if isConnect {
		if rp.protocol == "" && (rp.path != "" || rp.scheme != "" || rp.authority == "") {
			return nil, nil, sc.countError("bad_connect", http2streamError(f.StreamID, http2ErrCodeProtocol))
		}
	} else if rp.method == "" || rp.path == "" || (rp.scheme != "https" && rp.scheme != "http") {
		// See 8.1.2.6 Malformed Requests and Responses:
		//
		// Malformed requests or responses that are detected
		// MUST be treated as a stream error (Section 5.4.2)
		// of type PROTOCOL_ERROR."
		//
		// 8.1.2.3 Request Pseudo-Header Fields
		// "All HTTP/2 requests MUST include exactly one valid
		// value for the :method, :scheme, and :path
		// pseudo-header fields"
		return nil, nil, sc.countError("bad_path_method", http2streamError(f.StreamID, http2ErrCodeProtocol))
	}

	rp.header = make(Header)
	for _, hf := range f.RegularFields() {
		rp.header.Add(sc.canonicalHeader(hf.Name), hf.Value)
	}
	if rp.authority == "" {
		rp.authority = rp.header.Get("Host")
	}
	if rp.protocol != "" {
		rp.header.Set(":protocol", rp.protocol)
	}

	rw, req, err := sc.newWriterAndRequestNoBody(st, rp)
	if err != nil {
		return nil, nil, err
	}
	bodyOpen := !f.StreamEnded()
	if bodyOpen {
		if vv, ok := rp.header["Content-Length"]; ok {
			if cl, err := strconv.ParseUint(vv[0], 10, 63); err == nil {
				req.ContentLength = int64(cl)
			} else {
				req.ContentLength = 0
			}
		} else {
			req.ContentLength = -1
		}
		req.Body.(*http2requestBody).pipe = &http2pipe{
			b: &http2dataBuffer{expected: req.ContentLength},
		}
	}
	return rw, req, nil
}

type http2requestParam struct {
	method                  string
	scheme, authority, path string
	protocol                string
	header                  Header
}

func (sc *http2serverConn) newWriterAndRequestNoBody(st *http2stream, rp http2requestParam) (*http2responseWriter, *Request, error) {
	sc.serveG.check()

	var tlsState *tls.ConnectionState // nil if not scheme https
	if rp.scheme == "https" {
		tlsState = sc.tlsState
	}

	needsContinue := httpguts.HeaderValuesContainsToken(rp.header["Expect"], "100-continue")
	if needsContinue {
		rp.header.Del("Expect")
	}
	// Merge Cookie headers into one "; "-delimited value.
	if cookies := rp.header["Cookie"]; len(cookies) > 1 {
		rp.header.Set("Cookie", strings.Join(cookies, "; "))
	}

	// Setup Trailers
	var trailer Header
	for _, v := range rp.header["Trailer"] {
		for _, key := range strings.Split(v, ",") {
			key = CanonicalHeaderKey(textproto.TrimString(key))
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				// Bogus. (copy of http1 rules)
				// Ignore.
			default:
				if trailer == nil {
					trailer = make(Header)
				}
				trailer[key] = nil
			}
		}
	}
	delete(rp.header, "Trailer")

	var url_ *url.URL
	var requestURI string
	if rp.method == "CONNECT" && rp.protocol == "" {
		url_ = &url.URL{Host: rp.authority}
		requestURI = rp.authority // mimic HTTP/1 server behavior
	} else {
		var err error
		url_, err = url.ParseRequestURI(rp.path)
		if err != nil {
			return nil, nil, sc.countError("bad_path", http2streamError(st.id, http2ErrCodeProtocol))
		}
		requestURI = rp.path
	}

	body := &http2requestBody{
		conn:          sc,
		stream:        st,
		needsContinue: needsContinue,
	}
	req := &Request{
		Method:     rp.method,
		URL:        url_,
		RemoteAddr: sc.remoteAddrStr,
		Header:     rp.header,
		RequestURI: requestURI,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		TLS:        tlsState,
		Host:       rp.authority,
		Body:       body,
		Trailer:    trailer,
	}
	req = req.WithContext(st.ctx)

	rw := sc.newResponseWriter(st, req)
	return rw, req, nil
}

func (sc *http2serverConn) newResponseWriter(st *http2stream, req *Request) *http2responseWriter {
	rws := http2responseWriterStatePool.Get().(*http2responseWriterState)
	bwSave := rws.bw
	*rws = http2responseWriterState{} // zero all the fields
	rws.conn = sc
	rws.bw = bwSave
	rws.bw.Reset(http2chunkWriter{rws})
	rws.stream = st
	rws.req = req
	return &http2responseWriter{rws: rws}
}

type http2unstartedHandler struct {
	streamID uint32
	rw       *http2responseWriter
	req      *Request
	handler  func(ResponseWriter, *Request)
}

// scheduleHandler starts a handler goroutine,
// or schedules one to start as soon as an existing handler finishes.
func (sc *http2serverConn) scheduleHandler(streamID uint32, rw *http2responseWriter, req *Request, handler func(ResponseWriter, *Request)) error {
	sc.serveG.check()
	maxHandlers := sc.advMaxStreams
	if sc.curHandlers < maxHandlers {
		sc.curHandlers++
		go sc.runHandler(rw, req, handler)
		return nil
	}
	if len(sc.unstartedHandlers) > int(4*sc.advMaxStreams) {
		return sc.countError("too_many_early_resets", http2ConnectionError(http2ErrCodeEnhanceYourCalm))
	}
	sc.unstartedHandlers = append(sc.unstartedHandlers, http2unstartedHandler{
		streamID: streamID,
		rw:       rw,
		req:      req,
		handler:  handler,
	})
	return nil
}

func (sc *http2serverConn) handlerDone() {
	sc.serveG.check()
	sc.curHandlers--
	i := 0
	maxHandlers := sc.advMaxStreams
	for ; i < len(sc.unstartedHandlers); i++ {
		u := sc.unstartedHandlers[i]
		if sc.streams[u.streamID] == nil {
			// This stream was reset before its goroutine had a chance to start.
			continue
		}
		if sc.curHandlers >= maxHandlers {
			break
		}
		sc.curHandlers++
		go sc.runHandler(u.rw, u.req, u.handler)
		sc.unstartedHandlers[i] = http2unstartedHandler{} // don't retain references
	}
	sc.unstartedHandlers = sc.unstartedHandlers[i:]
	if len(sc.unstartedHandlers) == 0 {
		sc.unstartedHandlers = nil
	}
}

// Run on its own goroutine.
func (sc *http2serverConn) runHandler(rw *http2responseWriter, req *Request, handler func(ResponseWriter, *Request)) {
	sc.srv.markNewGoroutine()
	defer sc.sendServeMsg(http2handlerDoneMsg)
	didPanic := true
	defer func() {
		rw.rws.stream.cancelCtx()
		if req.MultipartForm != nil {
			req.MultipartForm.RemoveAll()
		}
		if didPanic {
			e := recover()
			sc.writeFrameFromHandler(http2FrameWriteRequest{
				write:  http2handlerPanicRST{rw.rws.stream.id},
				stream: rw.rws.stream,
			})
			// Same as net/http:
			if e != nil && e != ErrAbortHandler {
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				sc.logf("http2: panic serving %v: %v\n%s", sc.conn.RemoteAddr(), e, buf)
			}
			return
		}
		rw.handlerDone()
	}()
	handler(rw, req)
	didPanic = false
}

func http2handleHeaderListTooLong(w ResponseWriter, r *Request) {
	// 10.5.1 Limits on Header Block Size:
	// .. "A server that receives a larger header block than it is
	// willing to handle can send an HTTP 431 (Request Header Fields Too
	// Large) status code"
	const statusRequestHeaderFieldsTooLarge = 431 // only in Go 1.6+
	w.WriteHeader(statusRequestHeaderFieldsTooLarge)
	io.WriteString(w, "<h1>HTTP Error 431</h1><p>Request Header Field(s) Too Large</p>")
}

// called from handler goroutines.
// h may be nil.
func (sc *http2serverConn) writeHeaders(st *http2stream, headerData *http2writeResHeaders) error {
	sc.serveG.checkNotOn() // NOT on
	var errc chan error
	if headerData.h != nil {
		// If there's a header map (which we don't own), so we have to block on
		// waiting for this frame to be written, so an http.Flush mid-handler
		// writes out the correct value of keys, before a handler later potentially
		// mutates it.
		errc = http2errChanPool.Get().(chan error)
	}
	if err := sc.writeFrameFromHandler(http2FrameWriteRequest{
		write:  headerData,
		stream: st,
		done:   errc,
	}); err != nil {
		return err
	}
	if errc != nil {
		select {
		case err := <-errc:
			http2errChanPool.Put(errc)
			return err
		case <-sc.doneServing:
			return http2errClientDisconnected
		case <-st.cw:
			return http2errStreamClosed
		}
	}
	return nil
}

// called from handler goroutines.
func (sc *http2serverConn) write100ContinueHeaders(st *http2stream) {
	sc.writeFrameFromHandler(http2FrameWriteRequest{
		write:  http2write100ContinueHeadersFrame{st.id},
		stream: st,
	})
}

// A bodyReadMsg tells the server loop that the http.Handler read n
// bytes of the DATA from the client on the given stream.
type http2bodyReadMsg struct {
	st *http2stream
	n  int
}

// called from handler goroutines.
// Notes that the handler for the given stream ID read n bytes of its body
// and schedules flow control tokens to be sent.
func (sc *http2serverConn) noteBodyReadFromHandler(st *http2stream, n int, err error) {
	sc.serveG.checkNotOn() // NOT on
	if n > 0 {
		select {
		case sc.bodyReadCh <- http2bodyReadMsg{st, n}:
		case <-sc.doneServing:
		}
	}
}

func (sc *http2serverConn) noteBodyRead(st *http2stream, n int) {
	sc.serveG.check()
	sc.sendWindowUpdate(nil, n) // conn-level
	if st.state != http2stateHalfClosedRemote && st.state != http2stateClosed {
		// Don't send this WINDOW_UPDATE if the stream is closed
		// remotely.
		sc.sendWindowUpdate(st, n)
	}
}

// st may be nil for conn-level
func (sc *http2serverConn) sendWindowUpdate32(st *http2stream, n int32) {
	sc.sendWindowUpdate(st, int(n))
}

// st may be nil for conn-level
func (sc *http2serverConn) sendWindowUpdate(st *http2stream, n int) {
	sc.serveG.check()
	var streamID uint32
	var send int32
	if st == nil {
		send = sc.inflow.add(n)
	} else {
		streamID = st.id
		send = st.inflow.add(n)
	}
	if send == 0 {
		return
	}
	sc.writeFrame(http2FrameWriteRequest{
		write:  http2writeWindowUpdate{streamID: streamID, n: uint32(send)},
		stream: st,
	})
}

// requestBody is the Handler's Request.Body type.
// Read and Close may be called concurrently.
type http2requestBody struct {
	_             http2incomparable
	stream        *http2stream
	conn          *http2serverConn
	closeOnce     sync.Once  // for use by Close only
	sawEOF        bool       // for use by Read only
	pipe          *http2pipe // non-nil if we have an HTTP entity message body
	needsContinue bool       // need to send a 100-continue
}

func (b *http2requestBody) Close() error {
	b.closeOnce.Do(func() {
		if b.pipe != nil {
			b.pipe.BreakWithError(http2errClosedBody)
		}
	})
	return nil
}

func (b *http2requestBody) Read(p []byte) (n int, err error) {
	if b.needsContinue {
		b.needsContinue = false
		b.conn.write100ContinueHeaders(b.stream)
	}
	if b.pipe == nil || b.sawEOF {
		return 0, io.EOF
	}
	n, err = b.pipe.Read(p)
	if err == io.EOF {
		b.sawEOF = true
	}
	if b.conn == nil && http2inTests {
		return
	}
	b.conn.noteBodyReadFromHandler(b.stream, n, err)
	return
}

// responseWriter is the http.ResponseWriter implementation. It's
// intentionally small (1 pointer wide) to minimize garbage. The
// responseWriterState pointer inside is zeroed at the end of a
// request (in handlerDone) and calls on the responseWriter thereafter
// simply crash (caller's mistake), but the much larger responseWriterState
// and buffers are reused between multiple requests.
type http2responseWriter struct {
	rws *http2responseWriterState
}

// Optional http.ResponseWriter interfaces implemented.
var (
	_ CloseNotifier     = (*http2responseWriter)(nil)
	_ Flusher           = (*http2responseWriter)(nil)
	_ http2stringWriter = (*http2responseWriter)(nil)
)

type http2responseWriterState struct {
	// immutable within a request:
	stream *http2stream
	req    *Request
	conn   *http2serverConn

	// TODO: adjust buffer writing sizes based on server config, frame size updates from peer, etc
	bw *bufio.Writer // writing to a chunkWriter{this *responseWriterState}

	// mutated by http.Handler goroutine:
	handlerHeader Header   // nil until called
	snapHeader    Header   // snapshot of handlerHeader at WriteHeader time
	trailers      []string // set in writeChunk
	status        int      // status code passed to WriteHeader
	wroteHeader   bool     // WriteHeader called (explicitly or implicitly). Not necessarily sent to user yet.
	sentHeader    bool     // have we sent the header frame?
	handlerDone   bool     // handler has finished

	sentContentLen int64 // non-zero if handler set a Content-Length header
	wroteBytes     int64

	closeNotifierMu sync.Mutex // guards closeNotifierCh
	closeNotifierCh chan bool  // nil until first used
}

type http2chunkWriter struct{ rws *http2responseWriterState }

func (cw http2chunkWriter) Write(p []byte) (n int, err error) {
	n, err = cw.rws.writeChunk(p)
	if err == http2errStreamClosed {
		// If writing failed because the stream has been closed,
		// return the reason it was closed.
		err = cw.rws.stream.closeErr
	}
	return n, err
}

func (rws *http2responseWriterState) hasTrailers() bool { return len(rws.trailers) > 0 }

func (rws *http2responseWriterState) hasNonemptyTrailers() bool {
	for _, trailer := range rws.trailers {
		if _, ok := rws.handlerHeader[trailer]; ok {
			return true
		}
	}
	return false
}

// declareTrailer is called for each Trailer header when the
// response header is written. It notes that a header will need to be
// written in the trailers at the end of the response.
func (rws *http2responseWriterState) declareTrailer(k string) {
	k = CanonicalHeaderKey(k)
	if !httpguts.ValidTrailerHeader(k) {
		// Forbidden by RFC 7230, section 4.1.2.
		rws.conn.logf("ignoring invalid trailer %q", k)
		return
	}
	if !http2strSliceContains(rws.trailers, k) {
		rws.trailers = append(rws.trailers, k)
	}
}

// writeChunk writes chunks from the bufio.Writer. But because
// bufio.Writer may bypass its chunking, sometimes p may be
// arbitrarily large.
//
// writeChunk is also responsible (on the first chunk) for sending the
// HEADER response.
func (rws *http2responseWriterState) writeChunk(p []byte) (n int, err error) {
	if !rws.wroteHeader {
		rws.writeHeader(200)
	}

	if rws.handlerDone {
		rws.promoteUndeclaredTrailers()
	}

	isHeadResp := rws.req.Method == "HEAD"
	if !rws.sentHeader {
		rws.sentHeader = true
		var ctype, clen string
		if clen = rws.snapHeader.Get("Content-Length"); clen != "" {
			rws.snapHeader.Del("Content-Length")
			if cl, err := strconv.ParseUint(clen, 10, 63); err == nil {
				rws.sentContentLen = int64(cl)
			} else {
				clen = ""
			}
		}
		_, hasContentLength := rws.snapHeader["Content-Length"]
		if !hasContentLe
```