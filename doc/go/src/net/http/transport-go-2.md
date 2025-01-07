Response:
The user wants a summary of the functionalities provided by the Go code snippet. This is the third part of a larger code segment related to HTTP transport.

Here's a breakdown of the code's responsibilities:

1. **Managing persistent connections (`persistConn` struct):** The code defines a `persistConn` struct which represents a persistent HTTP connection. It holds information about the underlying network connection, request/response state, idle status, and error handling.

2. **Reading responses (`readLoop` function):**  The `readLoop` function is responsible for reading HTTP responses from the server on a persistent connection. It handles:
    - Peeking for server activity.
    - Receiving requests from the `reqch`.
    - Reading the response headers using `ReadResponse`.
    - Handling "Expect: 100-continue" responses.
    - Managing response body reading, including gzip decompression.
    - Putting the connection back to the idle pool if keep-alive is enabled.
    - Handling connection closure and errors.

3. **Handling request writing (`writeLoop` function):** The `writeLoop` function manages writing HTTP requests to the server. It receives write requests from `writech`, writes the request using `req.Request.write`, and flushes the buffered writer. It also handles errors during the write process.

4. **Coordinating request/response flow (`roundTrip` function):** The `roundTrip` function orchestrates the process of sending an HTTP request and receiving the response using a persistent connection. It handles:
    - Incrementing the expected response count.
    - Applying header mutation functions.
    - Adding "Accept-Encoding: gzip" header if appropriate.
    - Handling "Expect: 100-continue".
    - Sending the write request to `writeLoop`.
    - Sending the request information to `readLoop`.
    - Waiting for the response or errors from `readLoop` or `writeLoop`.
    - Handling timeouts and cancellations.

5. **Error handling and connection management:**  The code includes functions for checking the connection state (`isBroken`, `canceled`, `isReused`), canceling requests (`cancelRequest`), closing connections (`close`, `closeLocked`), and handling various errors that can occur during the HTTP transaction.

6. **Supporting features like timeouts, gzip decompression, and "Expect: 100-continue".**

7. **Providing hooks for testing.**

Based on this understanding, I can now formulate the summary.
这是 `go/src/net/http/transport.go` 文件中关于 **持久连接（`persistConn`）** 管理和 **HTTP/1.x 协议的读写操作** 的最后一部分代码，主要负责以下功能：

**1. HTTP 响应的读取循环 ( `readLoop` 函数 )**

*   **功能：** 这个 goroutine 负责从底层的网络连接中读取 HTTP 响应。它会一直运行，直到连接关闭。
*   **流程：**
    *   循环读取响应头，使用 `pc.br.Peek(1)` 检查是否有数据可读。
    *   接收来自 `pc.reqch` 的请求信息 (`requestAndChan`)。
    *   调用 `pc.readResponse` 读取完整的 HTTP 响应。
    *   处理 100 Continue 状态码。
    *   如果响应没有 body 或者 body 可以写入（例如 101 Switching Protocols），则尝试将连接放回空闲连接池。
    *   如果响应有 body，则创建一个 `bodyEOFSignal` 包装器来确保 body 被完全读取后再进行后续操作。
    *   处理 gzip 解压缩 (如果请求中加入了 `Accept-Encoding: gzip` 并且响应头中指示 gzip 编码)。
    *   根据响应头中的 `Connection` 和请求中的 `Close` 字段决定是否保持连接。
    *   处理请求取消和连接关闭事件。
*   **错误处理：**  如果读取响应时发生错误，会将错误发送到 `rc.ch`，并可能会关闭连接。
*   **与 `roundTrip` 的交互：** `readLoop` 通过 `pc.reqch` 接收请求，并通过 `rc.ch` 将响应发送回发起请求的 `roundTrip` 函数。

**2. 检查空闲连接的健康状态 (`readLoopPeekFailLocked` 函数 )**

*   **功能：** 当在一个空闲的持久连接上尝试读取数据失败时（例如，使用 `Peek` 发现错误），此函数会被调用。
*   **判断依据：** 它会检查是否是由于服务器主动关闭了空闲连接 (发送了类似 408 Request Timeout 的响应或直接 EOF)。
*   **处理：** 如果判断是服务器关闭，则将连接标记为已关闭，并记录日志。

**3. 判断是否为 HTTP 408 响应 (`is408Message` 函数 )**

*   **功能：** 检查给定的字节切片是否以 "HTTP/1.x 408" 开头，用于判断是否是服务器发送的 408 Request Timeout 响应。

**4. 读取 HTTP 响应 ( `readResponse` 函数 )**

*   **功能：** 从 `bufio.Reader` 中读取一个完整的 HTTP 响应，包括处理 1xx 状态码和 "Expect: 100-continue" 机制。
*   **处理 1xx 状态码：**  会循环读取直到遇到非 1xx 的最终响应。如果启用了 `httptrace.ClientTrace`，会调用 `Got1xxResponse` 回调。
*   **处理 "Expect: 100-continue"：** 如果请求发送了 `Expect: 100-continue` 头，并且服务器返回了 100 Continue，则会通知 `writeLoop` 可以发送请求 body。
*   **协议切换：** 如果响应是 101 Switching Protocols，则将响应 body 设置为可以直接读写的 `readWriteCloserBody`，允许用户直接操作底层的连接。
*   **TLS 信息：**  将 `pc.tlsState` 赋值给响应的 `TLS` 字段。

**5. 等待 "Expect: 100-continue" 响应 ( `waitForContinue` 函数 )**

*   **功能：**  创建一个匿名函数，用于阻塞等待服务器的 100 Continue 响应、超时或连接关闭。
*   **返回值：** 返回的函数会返回一个布尔值，指示是否应该发送请求 body。

**6. 创建可读写的响应 Body ( `newReadWriteCloserBody` 函数 )**

*   **功能：**  创建一个 `readWriteCloserBody` 类型的响应 body，用于处理 101 Switching Protocols 等需要用户直接操作连接的情况。

**7. 可读写的 Body 类型 (`readWriteCloserBody` 结构体和方法 )**

*   **功能：**  实现了 `io.ReadWriteCloser` 接口，允许用户直接读写底层的连接。用于处理像 WebSocket 握手这样的场景。
*   **实现：**  在初始阶段，会先读取 `bufio.Reader` 中缓存的数据，读取完毕后再直接操作底层的 `io.ReadWriteCloser`。

**8. 表示零字节写入错误的类型 (`nothingWrittenError` 结构体和方法 )**

*   **功能：**  包装了一个写入错误，表示写入操作没有写入任何字节。

**9. HTTP 请求的写入循环 ( `writeLoop` 函数 )**

*   **功能：** 这个 goroutine 负责将 HTTP 请求写入到底层的网络连接中。
*   **流程：**
    *   循环接收来自 `pc.writech` 的写入请求 (`writeRequest`)。
    *   调用 `wr.req.Request.write` 将请求头和 body 写入到 `pc.bw` (buffered writer)。
    *   如果请求头包含 `Expect: 100-continue`，会等待 `wr.continueCh` 接收信号后再发送 body。
    *   刷新 `pc.bw`，确保数据发送到网络。
    *   将写入结果（错误或 nil）发送到 `pc.writeErrCh` (用于通知 body reader，可能用于连接复用) 和 `wr.ch` (用于通知 `roundTrip` 函数)。
    *   如果发生错误，则关闭连接。
*   **与 `roundTrip` 的交互：** `writeLoop` 接收来自 `roundTrip` 的写入请求，并通过 channel 将写入结果返回。

**10. 检查请求是否已成功写入 (`wroteRequest` 函数 )**

*   **功能：** 在尝试复用连接之前，此函数会检查之前的写入操作是否已经完成并且没有发生错误。
*   **实现：** 它会尝试从 `pc.writeErrCh` 接收错误信息。如果能立即接收到 `nil`，则表示写入成功。如果 channel 为空，则会启动一个定时器，等待一段时间，如果超时仍未收到信息，则认为写入可能失败，不复用连接。

**11. 用于在读写 goroutine 之间传递响应和错误的结构体 (`responseAndError` )**

*   **功能：**  定义了一个结构体，用于 `readLoop` 将读取到的响应或错误传递给 `roundTrip` 函数。

**12. 用于在 `roundTrip` 和 `readLoop` 之间传递请求信息的结构体 (`requestAndChan` )**

*   **功能：** 定义了一个结构体，用于 `roundTrip` 将请求信息传递给 `readLoop` goroutine。包含了请求本身、用于接收响应的 channel、是否添加了 gzip 头、用于处理 "Expect: 100-continue" 的 channel 以及一个用于通知 `readLoop` 调用者已退出的 channel。

**13. 用于在 `roundTrip` 和 `writeLoop` 之间传递写入请求的结构体 (`writeRequest` )**

*   **功能：** 定义了一个结构体，用于 `roundTrip` 将写入请求传递给 `writeLoop` goroutine。包含了要写入的请求、用于接收写入结果的 channel 以及用于处理 "Expect: 100-continue" 的 channel。

**14. 超时错误类型 (`timeoutError` 结构体和方法 )**

*   **功能：**  自定义的超时错误类型，实现了 `net.Error` 接口。

**15. 请求取消相关的错误变量 (`errRequestCanceled`, `errRequestCanceledConn`, `errRequestDone` )**

*   **功能：**  定义了一些表示请求取消状态的错误变量。

**16. 空操作函数 (`nop` ) 和 测试钩子 (`testHookEnterRoundTrip` 等 )**

*   **功能：**  提供一些用于测试和调试的钩子函数，在正常运行时是空操作。

**17. `roundTrip` 函数 (持久连接上的请求处理)**

*   **功能：**  使用当前的持久连接 (`persistConn`) 执行一个 HTTP 请求的完整过程。
*   **流程：**
    *   增加预期响应的数量。
    *   调用 `mutateHeaderFunc` 修改请求头。
    *   根据配置和请求头决定是否添加 `Accept-Encoding: gzip`。
    *   如果请求有 body 并且需要发送 `Expect: 100-continue`，则创建相应的 channel。
    *   如果禁用了 Keep-Alive 或者请求显式要求关闭连接，则设置 `Connection: close` 头。
    *   创建一个 channel `gone`，当 `roundTrip` 的调用者返回时关闭。
    *   将写入请求发送到 `pc.writech`。
    *   将请求信息发送到 `pc.reqch`。
    *   使用 `select` 语句等待来自 `writeErrCh` 的写入结果、来自 `pcClosed` 的连接关闭信号、来自 `respHeaderTimer` 的响应头超时信号、来自 `resc` 的响应或错误、或者来自 `ctxDoneChan` 的请求上下文取消信号。
    *   根据接收到的信号进行相应的处理，例如处理写入错误、连接关闭、超时、接收响应等。
    *   返回接收到的响应或错误。

**18. 获取测试调试上下文的日志函数 (`logf` 方法 )**

*   **功能：**  如果请求的上下文中包含测试日志函数 (`tLogKey`)，则使用该函数记录日志。

**19. 标记连接为已复用 (`markReused` 方法 )**

*   **功能：**  将连接标记为已成功用于请求和响应。

**20. 关闭连接 (`close` 和 `closeLocked` 方法 )**

*   **功能：**  关闭底层的 TCP 连接并关闭 `pc.closech` channel。`closeLocked` 是在持有锁的情况下执行关闭操作。
*   **错误处理：**  `closeLocked` 会将连接标记为 broken，并记录关闭错误。

**21. 端口映射 (`portMap` 变量 ) 和 标准地址获取 (`canonicalAddr` 函数 )**

*   **功能：**  `portMap` 存储了常见协议的默认端口。`canonicalAddr` 函数根据 URL 获取标准化的地址，包括主机名和端口号。

**22. 用于标记 Body 读取结束的结构体 (`bodyEOFSignal` )**

*   **功能：**  包装了响应的 `io.ReadCloser`，用于确保响应 body 被完全读取后再进行后续操作，例如将连接放回空闲连接池。
*   **实现：**  在 `Read` 方法中，如果读取到 EOF，或者在 `Close` 方法被调用时，会执行一个回调函数 (`fn`)。

**23. gzip 解压缩 Reader (`gzipReader` 结构体和方法 )**

*   **功能：**  包装了响应的 body，用于在第一次调用 `Read` 时懒加载地创建 `gzip.Reader` 进行 gzip 解压缩。

**24. TLS 握手超时错误类型 (`tlsHandshakeTimeoutError` 结构体和方法 )**

*   **功能：**  表示 TLS 握手超时的错误类型。

**25. 空锁 (`fakeLocker` 结构体和方法 )**

*   **功能：**  在非测试环境下用作互斥锁，但实际上不执行任何操作，避免原子操作的开销。

**26. 克隆 TLS 配置 (`cloneTLSConfig` 函数 )**

*   **功能：**  创建一个 TLS 配置的浅拷贝，用于避免并发访问时的竞争条件。

**27. 连接 LRU 缓存 (`connLRU` 结构体和方法 )**

*   **功能：**  实现了一个简单的最近最少使用 (LRU) 缓存，用于管理空闲的持久连接。

**归纳一下它的功能：**

这部分代码主要负责 **管理 HTTP/1.x 的持久连接**，包括 **建立连接、发送请求、接收响应、处理各种协议细节（如 100 Continue、gzip 压缩、连接关闭）、错误处理和连接复用**。它定义了 `persistConn` 结构体来表示一个持久连接，并实现了读取响应的 `readLoop`、写入请求的 `writeLoop` 以及协调请求响应流程的 `roundTrip` 函数。 此外，它还包含了一些辅助功能，如连接健康检查、gzip 解压缩、TLS 配置管理和连接缓存等，共同构建了 HTTP/1.x 协议在 `net/http` 包中的核心实现。

Prompt: 
```
这是路径为go/src/net/http/transport.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
est   // written by roundTrip; read by writeLoop
	closech   chan struct{}       // closed when conn closed
	isProxy   bool
	sawEOF    bool  // whether we've seen EOF from conn; owned by readLoop
	readLimit int64 // bytes allowed to be read; owned by readLoop
	// writeErrCh passes the request write error (usually nil)
	// from the writeLoop goroutine to the readLoop which passes
	// it off to the res.Body reader, which then uses it to decide
	// whether or not a connection can be reused. Issue 7569.
	writeErrCh chan error

	writeLoopDone chan struct{} // closed when write loop ends

	// Both guarded by Transport.idleMu:
	idleAt    time.Time   // time it last become idle
	idleTimer *time.Timer // holding an AfterFunc to close it

	mu                   sync.Mutex // guards following fields
	numExpectedResponses int
	closed               error // set non-nil when conn is closed, before closech is closed
	canceledErr          error // set non-nil if conn is canceled
	broken               bool  // an error has happened on this connection; marked broken so it's not reused.
	reused               bool  // whether conn has had successful request/response and is being reused.
	// mutateHeaderFunc is an optional func to modify extra
	// headers on each outbound request before it's written. (the
	// original Request given to RoundTrip is not modified)
	mutateHeaderFunc func(Header)
}

func (pc *persistConn) maxHeaderResponseSize() int64 {
	if v := pc.t.MaxResponseHeaderBytes; v != 0 {
		return v
	}
	return 10 << 20 // conservative default; same as http2
}

func (pc *persistConn) Read(p []byte) (n int, err error) {
	if pc.readLimit <= 0 {
		return 0, fmt.Errorf("read limit of %d bytes exhausted", pc.maxHeaderResponseSize())
	}
	if int64(len(p)) > pc.readLimit {
		p = p[:pc.readLimit]
	}
	n, err = pc.conn.Read(p)
	if err == io.EOF {
		pc.sawEOF = true
	}
	pc.readLimit -= int64(n)
	return
}

// isBroken reports whether this connection is in a known broken state.
func (pc *persistConn) isBroken() bool {
	pc.mu.Lock()
	b := pc.closed != nil
	pc.mu.Unlock()
	return b
}

// canceled returns non-nil if the connection was closed due to
// CancelRequest or due to context cancellation.
func (pc *persistConn) canceled() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.canceledErr
}

// isReused reports whether this connection has been used before.
func (pc *persistConn) isReused() bool {
	pc.mu.Lock()
	r := pc.reused
	pc.mu.Unlock()
	return r
}

func (pc *persistConn) cancelRequest(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.canceledErr = err
	pc.closeLocked(errRequestCanceled)
}

// closeConnIfStillIdle closes the connection if it's still sitting idle.
// This is what's called by the persistConn's idleTimer, and is run in its
// own goroutine.
func (pc *persistConn) closeConnIfStillIdle() {
	t := pc.t
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if _, ok := t.idleLRU.m[pc]; !ok {
		// Not idle.
		return
	}
	t.removeIdleConnLocked(pc)
	pc.close(errIdleConnTimeout)
}

// mapRoundTripError returns the appropriate error value for
// persistConn.roundTrip.
//
// The provided err is the first error that (*persistConn).roundTrip
// happened to receive from its select statement.
//
// The startBytesWritten value should be the value of pc.nwrite before the roundTrip
// started writing the request.
func (pc *persistConn) mapRoundTripError(req *transportRequest, startBytesWritten int64, err error) error {
	if err == nil {
		return nil
	}

	// Wait for the writeLoop goroutine to terminate to avoid data
	// races on callers who mutate the request on failure.
	//
	// When resc in pc.roundTrip and hence rc.ch receives a responseAndError
	// with a non-nil error it implies that the persistConn is either closed
	// or closing. Waiting on pc.writeLoopDone is hence safe as all callers
	// close closech which in turn ensures writeLoop returns.
	<-pc.writeLoopDone

	// If the request was canceled, that's better than network
	// failures that were likely the result of tearing down the
	// connection.
	if cerr := pc.canceled(); cerr != nil {
		return cerr
	}

	// See if an error was set explicitly.
	req.mu.Lock()
	reqErr := req.err
	req.mu.Unlock()
	if reqErr != nil {
		return reqErr
	}

	if err == errServerClosedIdle {
		// Don't decorate
		return err
	}

	if _, ok := err.(transportReadFromServerError); ok {
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		// Don't decorate
		return err
	}
	if pc.isBroken() {
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		return fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", err)
	}
	return err
}

// errCallerOwnsConn is an internal sentinel error used when we hand
// off a writable response.Body to the caller. We use this to prevent
// closing a net.Conn that is now owned by the caller.
var errCallerOwnsConn = errors.New("read loop ending; caller owns writable underlying conn")

func (pc *persistConn) readLoop() {
	closeErr := errReadLoopExiting // default value, if not changed below
	defer func() {
		pc.close(closeErr)
		pc.t.removeIdleConn(pc)
	}()

	tryPutIdleConn := func(treq *transportRequest) bool {
		trace := treq.trace
		if err := pc.t.tryPutIdleConn(pc); err != nil {
			closeErr = err
			if trace != nil && trace.PutIdleConn != nil && err != errKeepAlivesDisabled {
				trace.PutIdleConn(err)
			}
			return false
		}
		if trace != nil && trace.PutIdleConn != nil {
			trace.PutIdleConn(nil)
		}
		return true
	}

	// eofc is used to block caller goroutines reading from Response.Body
	// at EOF until this goroutines has (potentially) added the connection
	// back to the idle pool.
	eofc := make(chan struct{})
	defer close(eofc) // unblock reader on errors

	// Read this once, before loop starts. (to avoid races in tests)
	testHookMu.Lock()
	testHookReadLoopBeforeNextRead := testHookReadLoopBeforeNextRead
	testHookMu.Unlock()

	alive := true
	for alive {
		pc.readLimit = pc.maxHeaderResponseSize()
		_, err := pc.br.Peek(1)

		pc.mu.Lock()
		if pc.numExpectedResponses == 0 {
			pc.readLoopPeekFailLocked(err)
			pc.mu.Unlock()
			return
		}
		pc.mu.Unlock()

		rc := <-pc.reqch
		trace := rc.treq.trace

		var resp *Response
		if err == nil {
			resp, err = pc.readResponse(rc, trace)
		} else {
			err = transportReadFromServerError{err}
			closeErr = err
		}

		if err != nil {
			if pc.readLimit <= 0 {
				err = fmt.Errorf("net/http: server response headers exceeded %d bytes; aborted", pc.maxHeaderResponseSize())
			}

			select {
			case rc.ch <- responseAndError{err: err}:
			case <-rc.callerGone:
				return
			}
			return
		}
		pc.readLimit = maxInt64 // effectively no limit for response bodies

		pc.mu.Lock()
		pc.numExpectedResponses--
		pc.mu.Unlock()

		bodyWritable := resp.bodyIsWritable()
		hasBody := rc.treq.Request.Method != "HEAD" && resp.ContentLength != 0

		if resp.Close || rc.treq.Request.Close || resp.StatusCode <= 199 || bodyWritable {
			// Don't do keep-alive on error if either party requested a close
			// or we get an unexpected informational (1xx) response.
			// StatusCode 100 is already handled above.
			alive = false
		}

		if !hasBody || bodyWritable {
			// Put the idle conn back into the pool before we send the response
			// so if they process it quickly and make another request, they'll
			// get this same conn. But we use the unbuffered channel 'rc'
			// to guarantee that persistConn.roundTrip got out of its select
			// potentially waiting for this persistConn to close.
			alive = alive &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(rc.treq)

			if bodyWritable {
				closeErr = errCallerOwnsConn
			}

			select {
			case rc.ch <- responseAndError{res: resp}:
			case <-rc.callerGone:
				return
			}

			rc.treq.cancel(errRequestDone)

			// Now that they've read from the unbuffered channel, they're safely
			// out of the select that also waits on this goroutine to die, so
			// we're allowed to exit now if needed (if alive is false)
			testHookReadLoopBeforeNextRead()
			continue
		}

		waitForBodyRead := make(chan bool, 2)
		body := &bodyEOFSignal{
			body: resp.Body,
			earlyCloseFn: func() error {
				waitForBodyRead <- false
				<-eofc // will be closed by deferred call at the end of the function
				return nil

			},
			fn: func(err error) error {
				isEOF := err == io.EOF
				waitForBodyRead <- isEOF
				if isEOF {
					<-eofc // see comment above eofc declaration
				} else if err != nil {
					if cerr := pc.canceled(); cerr != nil {
						return cerr
					}
				}
				return err
			},
		}

		resp.Body = body
		if rc.addedGzip && ascii.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			resp.Body = &gzipReader{body: body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}

		select {
		case rc.ch <- responseAndError{res: resp}:
		case <-rc.callerGone:
			return
		}

		// Before looping back to the top of this function and peeking on
		// the bufio.Reader, wait for the caller goroutine to finish
		// reading the response body. (or for cancellation or death)
		select {
		case bodyEOF := <-waitForBodyRead:
			alive = alive &&
				bodyEOF &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(rc.treq)
			if bodyEOF {
				eofc <- struct{}{}
			}
		case <-rc.treq.ctx.Done():
			alive = false
			pc.cancelRequest(context.Cause(rc.treq.ctx))
		case <-pc.closech:
			alive = false
		}

		rc.treq.cancel(errRequestDone)
		testHookReadLoopBeforeNextRead()
	}
}

func (pc *persistConn) readLoopPeekFailLocked(peekErr error) {
	if pc.closed != nil {
		return
	}
	if n := pc.br.Buffered(); n > 0 {
		buf, _ := pc.br.Peek(n)
		if is408Message(buf) {
			pc.closeLocked(errServerClosedIdle)
			return
		} else {
			log.Printf("Unsolicited response received on idle HTTP channel starting with %q; err=%v", buf, peekErr)
		}
	}
	if peekErr == io.EOF {
		// common case.
		pc.closeLocked(errServerClosedIdle)
	} else {
		pc.closeLocked(fmt.Errorf("readLoopPeekFailLocked: %w", peekErr))
	}
}

// is408Message reports whether buf has the prefix of an
// HTTP 408 Request Timeout response.
// See golang.org/issue/32310.
func is408Message(buf []byte) bool {
	if len(buf) < len("HTTP/1.x 408") {
		return false
	}
	if string(buf[:7]) != "HTTP/1." {
		return false
	}
	return string(buf[8:12]) == " 408"
}

// readResponse reads an HTTP response (or two, in the case of "Expect:
// 100-continue") from the server. It returns the final non-100 one.
// trace is optional.
func (pc *persistConn) readResponse(rc requestAndChan, trace *httptrace.ClientTrace) (resp *Response, err error) {
	if trace != nil && trace.GotFirstResponseByte != nil {
		if peek, err := pc.br.Peek(1); err == nil && len(peek) == 1 {
			trace.GotFirstResponseByte()
		}
	}

	continueCh := rc.continueCh
	for {
		resp, err = ReadResponse(pc.br, rc.treq.Request)
		if err != nil {
			return
		}
		resCode := resp.StatusCode
		if continueCh != nil && resCode == StatusContinue {
			if trace != nil && trace.Got100Continue != nil {
				trace.Got100Continue()
			}
			continueCh <- struct{}{}
			continueCh = nil
		}
		is1xx := 100 <= resCode && resCode <= 199
		// treat 101 as a terminal status, see issue 26161
		is1xxNonTerminal := is1xx && resCode != StatusSwitchingProtocols
		if is1xxNonTerminal {
			if trace != nil && trace.Got1xxResponse != nil {
				if err := trace.Got1xxResponse(resCode, textproto.MIMEHeader(resp.Header)); err != nil {
					return nil, err
				}
				// If the 1xx response was delivered to the user,
				// then they're responsible for limiting the number of
				// responses. Reset the header limit.
				//
				// If the user didn't examine the 1xx response, then we
				// limit the size of all headers (including both 1xx
				// and the final response) to maxHeaderResponseSize.
				pc.readLimit = pc.maxHeaderResponseSize() // reset the limit
			}
			continue
		}
		break
	}
	if resp.isProtocolSwitch() {
		resp.Body = newReadWriteCloserBody(pc.br, pc.conn)
	}
	if continueCh != nil {
		// We send an "Expect: 100-continue" header, but the server
		// responded with a terminal status and no 100 Continue.
		//
		// If we're going to keep using the connection, we need to send the request body.
		// Tell writeLoop to skip sending the body if we're going to close the connection,
		// or to send it otherwise.
		//
		// The case where we receive a 101 Switching Protocols response is a bit
		// ambiguous, since we don't know what protocol we're switching to.
		// Conceivably, it's one that doesn't need us to send the body.
		// Given that we'll send the body if ExpectContinueTimeout expires,
		// be consistent and always send it if we aren't closing the connection.
		if resp.Close || rc.treq.Request.Close {
			close(continueCh) // don't send the body; the connection will close
		} else {
			continueCh <- struct{}{} // send the body
		}
	}

	resp.TLS = pc.tlsState
	return
}

// waitForContinue returns the function to block until
// any response, timeout or connection close. After any of them,
// the function returns a bool which indicates if the body should be sent.
func (pc *persistConn) waitForContinue(continueCh <-chan struct{}) func() bool {
	if continueCh == nil {
		return nil
	}
	return func() bool {
		timer := time.NewTimer(pc.t.ExpectContinueTimeout)
		defer timer.Stop()

		select {
		case _, ok := <-continueCh:
			return ok
		case <-timer.C:
			return true
		case <-pc.closech:
			return false
		}
	}
}

func newReadWriteCloserBody(br *bufio.Reader, rwc io.ReadWriteCloser) io.ReadWriteCloser {
	body := &readWriteCloserBody{ReadWriteCloser: rwc}
	if br.Buffered() != 0 {
		body.br = br
	}
	return body
}

// readWriteCloserBody is the Response.Body type used when we want to
// give users write access to the Body through the underlying
// connection (TCP, unless using custom dialers). This is then
// the concrete type for a Response.Body on the 101 Switching
// Protocols response, as used by WebSockets, h2c, etc.
type readWriteCloserBody struct {
	_  incomparable
	br *bufio.Reader // used until empty
	io.ReadWriteCloser
}

func (b *readWriteCloserBody) Read(p []byte) (n int, err error) {
	if b.br != nil {
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.ReadWriteCloser.Read(p)
}

// nothingWrittenError wraps a write errors which ended up writing zero bytes.
type nothingWrittenError struct {
	error
}

func (nwe nothingWrittenError) Unwrap() error {
	return nwe.error
}

func (pc *persistConn) writeLoop() {
	defer close(pc.writeLoopDone)
	for {
		select {
		case wr := <-pc.writech:
			startBytesWritten := pc.nwrite
			err := wr.req.Request.write(pc.bw, pc.isProxy, wr.req.extra, pc.waitForContinue(wr.continueCh))
			if bre, ok := err.(requestBodyReadError); ok {
				err = bre.error
				// Errors reading from the user's
				// Request.Body are high priority.
				// Set it here before sending on the
				// channels below or calling
				// pc.close() which tears down
				// connections and causes other
				// errors.
				wr.req.setError(err)
			}
			if err == nil {
				err = pc.bw.Flush()
			}
			if err != nil {
				if pc.nwrite == startBytesWritten {
					err = nothingWrittenError{err}
				}
			}
			pc.writeErrCh <- err // to the body reader, which might recycle us
			wr.ch <- err         // to the roundTrip function
			if err != nil {
				pc.close(err)
				return
			}
		case <-pc.closech:
			return
		}
	}
}

// maxWriteWaitBeforeConnReuse is how long the a Transport RoundTrip
// will wait to see the Request's Body.Write result after getting a
// response from the server. See comments in (*persistConn).wroteRequest.
//
// In tests, we set this to a large value to avoid flakiness from inconsistent
// recycling of connections.
var maxWriteWaitBeforeConnReuse = 50 * time.Millisecond

// wroteRequest is a check before recycling a connection that the previous write
// (from writeLoop above) happened and was successful.
func (pc *persistConn) wroteRequest() bool {
	select {
	case err := <-pc.writeErrCh:
		// Common case: the write happened well before the response, so
		// avoid creating a timer.
		return err == nil
	default:
		// Rare case: the request was written in writeLoop above but
		// before it could send to pc.writeErrCh, the reader read it
		// all, processed it, and called us here. In this case, give the
		// write goroutine a bit of time to finish its send.
		//
		// Less rare case: We also get here in the legitimate case of
		// Issue 7569, where the writer is still writing (or stalled),
		// but the server has already replied. In this case, we don't
		// want to wait too long, and we want to return false so this
		// connection isn't re-used.
		t := time.NewTimer(maxWriteWaitBeforeConnReuse)
		defer t.Stop()
		select {
		case err := <-pc.writeErrCh:
			return err == nil
		case <-t.C:
			return false
		}
	}
}

// responseAndError is how the goroutine reading from an HTTP/1 server
// communicates with the goroutine doing the RoundTrip.
type responseAndError struct {
	_   incomparable
	res *Response // else use this response (see res method)
	err error
}

type requestAndChan struct {
	_    incomparable
	treq *transportRequest
	ch   chan responseAndError // unbuffered; always send in select on callerGone

	// whether the Transport (as opposed to the user client code)
	// added the Accept-Encoding gzip header. If the Transport
	// set it, only then do we transparently decode the gzip.
	addedGzip bool

	// Optional blocking chan for Expect: 100-continue (for send).
	// If the request has an "Expect: 100-continue" header and
	// the server responds 100 Continue, readLoop send a value
	// to writeLoop via this chan.
	continueCh chan<- struct{}

	callerGone <-chan struct{} // closed when roundTrip caller has returned
}

// A writeRequest is sent by the caller's goroutine to the
// writeLoop's goroutine to write a request while the read loop
// concurrently waits on both the write response and the server's
// reply.
type writeRequest struct {
	req *transportRequest
	ch  chan<- error

	// Optional blocking chan for Expect: 100-continue (for receive).
	// If not nil, writeLoop blocks sending request body until
	// it receives from this chan.
	continueCh <-chan struct{}
}

// httpTimeoutError represents a timeout.
// It implements net.Error and wraps context.DeadlineExceeded.
type timeoutError struct {
	err string
}

func (e *timeoutError) Error() string     { return e.err }
func (e *timeoutError) Timeout() bool     { return true }
func (e *timeoutError) Temporary() bool   { return true }
func (e *timeoutError) Is(err error) bool { return err == context.DeadlineExceeded }

var errTimeout error = &timeoutError{"net/http: timeout awaiting response headers"}

// errRequestCanceled is set to be identical to the one from h2 to facilitate
// testing.
var errRequestCanceled = http2errRequestCanceled
var errRequestCanceledConn = errors.New("net/http: request canceled while waiting for connection") // TODO: unify?

// errRequestDone is used to cancel the round trip Context after a request is successfully done.
// It should not be seen by the user.
var errRequestDone = errors.New("net/http: request completed")

func nop() {}

// testHooks. Always non-nil.
var (
	testHookEnterRoundTrip   = nop
	testHookWaitResLoop      = nop
	testHookRoundTripRetried = nop
	testHookPrePendingDial   = nop
	testHookPostPendingDial  = nop

	testHookMu                     sync.Locker = fakeLocker{} // guards following
	testHookReadLoopBeforeNextRead             = nop
)

func (pc *persistConn) roundTrip(req *transportRequest) (resp *Response, err error) {
	testHookEnterRoundTrip()
	pc.mu.Lock()
	pc.numExpectedResponses++
	headerFn := pc.mutateHeaderFunc
	pc.mu.Unlock()

	if headerFn != nil {
		headerFn(req.extraHeaders())
	}

	// Ask for a compressed version if the caller didn't set their
	// own value for Accept-Encoding. We only attempt to
	// uncompress the gzip stream if we were the layer that
	// requested it.
	requestedGzip := false
	if !pc.t.DisableCompression &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   https://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		requestedGzip = true
		req.extraHeaders().Set("Accept-Encoding", "gzip")
	}

	var continueCh chan struct{}
	if req.ProtoAtLeast(1, 1) && req.Body != nil && req.expectsContinue() {
		continueCh = make(chan struct{}, 1)
	}

	if pc.t.DisableKeepAlives &&
		!req.wantsClose() &&
		!isProtocolSwitchHeader(req.Header) {
		req.extraHeaders().Set("Connection", "close")
	}

	gone := make(chan struct{})
	defer close(gone)

	const debugRoundTrip = false

	// Write the request concurrently with waiting for a response,
	// in case the server decides to reply before reading our full
	// request body.
	startBytesWritten := pc.nwrite
	writeErrCh := make(chan error, 1)
	pc.writech <- writeRequest{req, writeErrCh, continueCh}

	resc := make(chan responseAndError)
	pc.reqch <- requestAndChan{
		treq:       req,
		ch:         resc,
		addedGzip:  requestedGzip,
		continueCh: continueCh,
		callerGone: gone,
	}

	handleResponse := func(re responseAndError) (*Response, error) {
		if (re.res == nil) == (re.err == nil) {
			panic(fmt.Sprintf("internal error: exactly one of res or err should be set; nil=%v", re.res == nil))
		}
		if debugRoundTrip {
			req.logf("resc recv: %p, %T/%#v", re.res, re.err, re.err)
		}
		if re.err != nil {
			return nil, pc.mapRoundTripError(req, startBytesWritten, re.err)
		}
		return re.res, nil
	}

	var respHeaderTimer <-chan time.Time
	ctxDoneChan := req.ctx.Done()
	pcClosed := pc.closech
	for {
		testHookWaitResLoop()
		select {
		case err := <-writeErrCh:
			if debugRoundTrip {
				req.logf("writeErrCh recv: %T/%#v", err, err)
			}
			if err != nil {
				pc.close(fmt.Errorf("write error: %w", err))
				return nil, pc.mapRoundTripError(req, startBytesWritten, err)
			}
			if d := pc.t.ResponseHeaderTimeout; d > 0 {
				if debugRoundTrip {
					req.logf("starting timer for %v", d)
				}
				timer := time.NewTimer(d)
				defer timer.Stop() // prevent leaks
				respHeaderTimer = timer.C
			}
		case <-pcClosed:
			select {
			case re := <-resc:
				// The pconn closing raced with the response to the request,
				// probably after the server wrote a response and immediately
				// closed the connection. Use the response.
				return handleResponse(re)
			default:
			}
			if debugRoundTrip {
				req.logf("closech recv: %T %#v", pc.closed, pc.closed)
			}
			return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)
		case <-respHeaderTimer:
			if debugRoundTrip {
				req.logf("timeout waiting for response headers.")
			}
			pc.close(errTimeout)
			return nil, errTimeout
		case re := <-resc:
			return handleResponse(re)
		case <-ctxDoneChan:
			select {
			case re := <-resc:
				// readLoop is responsible for canceling req.ctx after
				// it reads the response body. Check for a response racing
				// the context close, and use the response if available.
				return handleResponse(re)
			default:
			}
			pc.cancelRequest(context.Cause(req.ctx))
		}
	}
}

// tLogKey is a context WithValue key for test debugging contexts containing
// a t.Logf func. See export_test.go's Request.WithT method.
type tLogKey struct{}

func (tr *transportRequest) logf(format string, args ...any) {
	if logf, ok := tr.Request.Context().Value(tLogKey{}).(func(string, ...any)); ok {
		logf(time.Now().Format(time.RFC3339Nano)+": "+format, args...)
	}
}

// markReused marks this connection as having been successfully used for a
// request and response.
func (pc *persistConn) markReused() {
	pc.mu.Lock()
	pc.reused = true
	pc.mu.Unlock()
}

// close closes the underlying TCP connection and closes
// the pc.closech channel.
//
// The provided err is only for testing and debugging; in normal
// circumstances it should never be seen by users.
func (pc *persistConn) close(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.closeLocked(err)
}

func (pc *persistConn) closeLocked(err error) {
	if err == nil {
		panic("nil error")
	}
	pc.broken = true
	if pc.closed == nil {
		pc.closed = err
		pc.t.decConnsPerHost(pc.cacheKey)
		// Close HTTP/1 (pc.alt == nil) connection.
		// HTTP/2 closes its connection itself.
		if pc.alt == nil {
			if err != errCallerOwnsConn {
				pc.conn.Close()
			}
			close(pc.closech)
		}
	}
	pc.mutateHeaderFunc = nil
}

var portMap = map[string]string{
	"http":    "80",
	"https":   "443",
	"socks5":  "1080",
	"socks5h": "1080",
}

func idnaASCIIFromURL(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	return addr
}

// canonicalAddr returns url.Host but always with a ":port" suffix.
func canonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(idnaASCIIFromURL(url), port)
}

// bodyEOFSignal is used by the HTTP/1 transport when reading response
// bodies to make sure we see the end of a response body before
// proceeding and reading on the connection again.
//
// It wraps a ReadCloser but runs fn (if non-nil) at most
// once, right before its final (error-producing) Read or Close call
// returns. fn should return the new error to return from Read or Close.
//
// If earlyCloseFn is non-nil and Close is called before io.EOF is
// seen, earlyCloseFn is called instead of fn, and its return value is
// the return value from Close.
type bodyEOFSignal struct {
	body         io.ReadCloser
	mu           sync.Mutex        // guards following 4 fields
	closed       bool              // whether Close has been called
	rerr         error             // sticky Read error
	fn           func(error) error // err will be nil on Read io.EOF
	earlyCloseFn func() error      // optional alt Close func used if io.EOF not seen
}

var errReadOnClosedResBody = errors.New("http: read on closed response body")

func (es *bodyEOFSignal) Read(p []byte) (n int, err error) {
	es.mu.Lock()
	closed, rerr := es.closed, es.rerr
	es.mu.Unlock()
	if closed {
		return 0, errReadOnClosedResBody
	}
	if rerr != nil {
		return 0, rerr
	}

	n, err = es.body.Read(p)
	if err != nil {
		es.mu.Lock()
		defer es.mu.Unlock()
		if es.rerr == nil {
			es.rerr = err
		}
		err = es.condfn(err)
	}
	return
}

func (es *bodyEOFSignal) Close() error {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.closed {
		return nil
	}
	es.closed = true
	if es.earlyCloseFn != nil && es.rerr != io.EOF {
		return es.earlyCloseFn()
	}
	err := es.body.Close()
	return es.condfn(err)
}

// caller must hold es.mu.
func (es *bodyEOFSignal) condfn(err error) error {
	if es.fn == nil {
		return err
	}
	err = es.fn(err)
	es.fn = nil
	return err
}

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type gzipReader struct {
	_    incomparable
	body *bodyEOFSignal // underlying HTTP/1 response body framing
	zr   *gzip.Reader   // lazily-initialized gzip reader
	zerr error          // any error from gzip.NewReader; sticky
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	if gz.zr == nil {
		if gz.zerr == nil {
			gz.zr, gz.zerr = gzip.NewReader(gz.body)
		}
		if gz.zerr != nil {
			return 0, gz.zerr
		}
	}

	gz.body.mu.Lock()
	if gz.body.closed {
		err = errReadOnClosedResBody
	}
	gz.body.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return gz.zr.Read(p)
}

func (gz *gzipReader) Close() error {
	return gz.body.Close()
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

// fakeLocker is a sync.Locker which does nothing. It's used to guard
// test-only fields when not under test, to avoid runtime atomic
// overhead.
type fakeLocker struct{}

func (fakeLocker) Lock()   {}
func (fakeLocker) Unlock() {}

// cloneTLSConfig returns a shallow clone of cfg, or a new zero tls.Config if
// cfg is nil. This is safe to call even if cfg is in active use by a TLS
// client or server.
//
// cloneTLSConfig should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/searKing/golang
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname cloneTLSConfig
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

type connLRU struct {
	ll *list.List // list.Element.Value type is of *persistConn
	m  map[*persistConn]*list.Element
}

// add adds pc to the head of the linked list.
func (cl *connLRU) add(pc *persistConn) {
	if cl.ll == nil {
		cl.ll = list.New()
		cl.m = make(map[*persistConn]*list.Element)
	}
	ele := cl.ll.PushFront(pc)
	if _, ok := cl.m[pc]; ok {
		panic("persistConn was already in LRU")
	}
	cl.m[pc] = ele
}

func (cl *connLRU) removeOldest() *persistConn {
	ele := cl.ll.Back()
	pc := ele.Value.(*persistConn)
	cl.ll.Remove(ele)
	delete(cl.m, pc)
	return pc
}

// remove removes pc from cl.
func (cl *connLRU) remove(pc *persistConn) {
	if ele, ok := cl.m[pc]; ok {
		cl.ll.Remove(ele)
		delete(cl.m, pc)
	}
}

// len returns the number of items in the cache.
func (cl *connLRU) len() int {
	return len(cl.m)
}

"""




```