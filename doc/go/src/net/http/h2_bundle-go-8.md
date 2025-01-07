Response:
Let's break down the thought process for analyzing this Go code snippet and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided Go code, which is a part of the HTTP/2 implementation in the Go standard library. The request asks for a summary of its functions, identification of implemented Go features with examples, code reasoning with hypothetical inputs/outputs, details on command-line arguments (if any), common mistakes, and finally, a concise summary of its function as part 9 of 13.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for recognizable keywords and structures:

* **`type`:**  This immediately signals the definition of custom data structures (structs). `http2ClientConn`, `http2clientStream`, `http2RoundTripOpt`, `http2stickyErrWriter`, etc., are defined. This suggests the code is managing connection and stream states.
* **`func`:** This indicates function definitions, the core logic of the code. Functions like `RoundTrip`, `dialClientConn`, `newClientConn`, `Close`, `Shutdown`, etc., appear frequently, pointing to lifecycle management and request handling.
* **Fields within structs:**  Examining the fields of `http2ClientConn` and `http2clientStream` provides crucial insights into the state they maintain:  `streams`, `nextStreamID`, `pendingRequests`, `goAway`, `wantSettingsAck`, `br`, `bw`, `mu`, `wmu`, `abort`, `peerClosed`, etc. These suggest connection management, stream multiplexing, error handling, and synchronization.
* **Comments:**  The comments are extremely valuable. They explain the purpose of certain fields and the reasoning behind some decisions (e.g., the `rstStreamPingsBlocked` comment).
* **Constants and Variables:**  `http2clientPreface`, `http2NextProtoTLS`, `http2ErrNoCachedConn`, etc., are defined, indicating protocol-specific values and error types.
* **Standard Library Packages:**  Imports like `net`, `bufio`, `sync`, `time`, `context`, `crypto/tls`, `errors`, `fmt`, `strings`, `sort`, `net/url`, `net/http`, `golang.org/x/net/idna`, `golang.org/x/net/http2/hpack`, and `net/http/httptrace` indicate the code interacts with networking, buffering, synchronization, timing, TLS, error handling, string manipulation, HTTP concepts, and HTTP tracing.

**3. Grouping Functionality:**

Based on the initial scan, we can start grouping related functions and data structures:

* **Connection Management:** `http2ClientConn`, `dialClientConn`, `newClientConn`, `Close`, `Shutdown`, `closeIfIdle`, `forceCloseConn`, `healthCheck`, `CanTakeNewRequest`, `ReserveNewRequest`, `setGoAway`, `idleState`, `tooIdleLocked`.
* **Stream Management:** `http2clientStream`, `abortStream`, `abortRequestBodyWrite`, `RoundTrip`, `roundTrip`, `decrStreamReservations`.
* **Request Handling:**  `RoundTrip`, `RoundTripOpt`, `shouldRetryRequest`, `actualContentLength`, `checkConnHeaders`, `commaSeparatedTrailers`.
* **Error Handling:** `http2stickyErrWriter`, `http2ErrNoCachedConn`, `closeForError`, `closeForLostPing`, `http2canRetryError`.
* **Configuration:**  `http2Transport` (though not fully shown in this snippet, its methods are used), `http2configFromTransport`, `newTLSConfig`.
* **Utility Functions:** `http2authorityAddr`, `http2isNoCachedConnError`, `http2commaSeparatedTrailers`, `http2checkConnHeaders`, `http2actualContentLength`.

**4. Inferring Go Features:**

With the identified functionalities, we can deduce the Go features being used:

* **Structs:** For defining data structures.
* **Methods:** Associated with the structs to operate on their data.
* **Pointers:** Used extensively to modify struct fields directly.
* **Interfaces:**  `http2synctestGroupInterface`, the anonymous interface for `IsHTTP2NoCachedConnError`, and likely others implicitly.
* **Goroutines and Channels:**  For concurrent operations (e.g., `readLoop`, `onIdleTimeout`, request handling) and communication between them (`readerDone`, `abort`, `peerClosed`, `donec`, `on100`, `reqHeaderMu`, `pings`).
* **`sync` Package:** For synchronization primitives like `Mutex`, `Once`, `Cond`.
* **`time` Package:** For timeouts and timers.
* **Error Handling:** Using the `error` interface and custom error types.
* **Context Package:** For managing request lifecycles and cancellations.

**5. Code Reasoning and Examples:**

This requires understanding how the different parts interact. For instance, the `RoundTrip` function retrieves a connection, and `clientConn.RoundTrip` on that connection manages the stream. We can then create hypothetical scenarios (e.g., a successful request, a request that needs retrying, a connection timeout) and trace the flow of execution and state changes. This is where the examples in the initial answer come from.

**6. Command-Line Arguments:**

A careful review of the code reveals no direct parsing of command-line arguments. The configuration seems to be done programmatically through the `http2Transport` struct.

**7. Common Mistakes:**

Thinking about how a developer might misuse this code leads to identifying potential pitfalls, such as not handling errors from `RoundTrip`, misunderstanding connection reuse, or issues with request body handling during retries.

**8. Summarization (Part 9 of 13):**

Finally, the request asks for a summary specifically for this "part 9". Looking at the code, it focuses on the `http2ClientConn` and `http2clientStream` structures and their associated methods. Therefore, the summary should highlight their roles in managing client-side HTTP/2 connections and individual streams, including connection establishment, stream creation, request handling, error management, and connection lifecycle.

**Self-Correction/Refinement during the process:**

* **Initial Assumption about Command-Line Arguments:**  At first glance, one might think there could be command-line arguments for configuring the transport. However, closer inspection reveals that the configuration is done through the `http2Transport` struct's fields.
* **Focusing on the "Part 9" Aspect:**  It's important to keep in mind that this is a *part* of a larger implementation. The summary should reflect what this specific section contributes. While `http2Transport` methods are used, the core focus is the connection and stream structs defined here.
* **Clarity and Conciseness:**  The explanations should be in clear and understandable Chinese, avoiding overly technical jargon where possible, and staying concise.

By following these steps – from a high-level overview to detailed code analysis and reasoning – we can effectively understand and explain the functionality of the given Go code snippet.
这段代码是 Go 语言 `net/http` 包中 HTTP/2 协议客户端连接(`http2ClientConn`)和客户端流(`http2clientStream`)实现的一部分。它是客户端 HTTP/2 连接的核心数据结构和方法定义。

**功能归纳 (第 9 部分):**

这部分代码主要定义了 **客户端 HTTP/2 连接(`http2ClientConn`)** 的结构体及其相关方法，以及 **客户端 HTTP/2 流(`http2clientStream`)** 的结构体及其部分方法。  其核心功能在于：

1. **定义客户端连接状态:**  `http2ClientConn` 结构体维护了客户端连接的所有重要状态信息，例如：
    * 连接的底层网络连接 (`tconn`)
    * 读写缓冲区 (`br`, `bw`) 和 HTTP/2 帧处理 (`fr`)
    * 流的管理 (`streams`)，包括已创建的流、下一个可用的流 ID (`nextStreamID`) 和挂起的请求 (`pendingRequests`)
    * 连接设置 (`maxFrameSize`, `maxConcurrentStreams` 等)
    * 连接的生命周期状态 (`closed`, `closing`, `goAway`)
    * 用于同步访问的互斥锁 (`mu`, `wmu`) 和条件变量 (`cond`)
    *  Ping 管理 (`pings`)
    * 超时设置 (`readIdleTimeout`, `pingTimeout`)

2. **定义客户端流的状态:** `http2clientStream` 结构体维护了单个 HTTP/2 请求/响应流的状态信息，例如：
    * 所属的客户端连接 (`cc`)
    * 请求上下文 (`ctx`) 和取消信号 (`reqCancel`)
    * 流 ID (`ID`)
    * 请求和响应体相关的管道 (`bufPipe`) 和标志位 (`requestedGzip`, `isHead`)
    * 流的生命周期状态 (`abort`, `peerClosed`, `donec`)
    * 头部接收状态 (`respHeaderRecv`) 和响应 (`res`)
    * 流量控制 (`flow`, `inflow`)
    * 请求体相关的信息 (`reqBody`, `reqBodyContentLength`)
    *  头部和尾部信息 (`trailer`, `resTrailer`)

3. **实现客户端连接的建立和管理:**  代码中包含了 `newClientConn` 方法，负责创建并初始化一个新的客户端 HTTP/2 连接，包括发送 HTTP/2 序言和初始设置帧。

4. **实现客户端请求的发送和处理:**  `RoundTrip` 和 `roundTrip` 方法是客户端发送 HTTP 请求的核心，它们负责获取连接，创建流，并将请求数据写入连接。

5. **实现连接的关闭和清理:**  代码包含了 `Close`, `Shutdown`, `closeIfIdle`, `closeForError`, `closeForLostPing` 等方法，用于不同场景下的连接关闭和清理操作。

6. **实现连接状态的查询:**  `CanTakeNewRequest`, `ReserveNewRequest`, `State`, `idleState` 等方法用于查询连接的当前状态，判断是否可以发送新的请求。

7. **实现连接的健康检查:** `healthCheck` 方法用于发送 Ping 帧来检查连接的活性。

8. **处理连接级别的错误:** 代码中定义了一些连接级别的错误，例如 `http2errClientConnClosed`, `http2errClientConnUnusable`, `http2errClientConnGotGoAway`，并提供了 `shouldRetryRequest` 和 `canRetryError` 函数来判断请求是否可以重试。

**可以推理出的一些 Go 语言功能的实现，并用代码举例说明:**

**1. Goroutine 和 Channel 的使用 (并发处理):**

`http2ClientConn` 中的 `readLoop` (虽然这段代码未完全包含，但可以推断存在) 会在一个独立的 goroutine 中运行，负责从连接读取 HTTP/2 帧。  `http2clientStream` 中的 `abort`, `peerClosed`, `donec`, `on100`, `respHeaderRecv` 等都是 channel，用于在不同的 goroutine 之间同步状态和传递信号。

```go
// 假设在 http2ClientConn 中有这样一个方法处理收到的 SETTINGS 帧
func (cc *http2ClientConn) handleSettings(frame *http2SettingsFrame) {
	// ... 处理 SETTINGS 帧的逻辑

	// 当收到 SETTINGS ACK 时，通知等待的 goroutine
	if frame.IsAck() {
		close(cc.seenSettingsChan)
	}
}

// 在 newClientConn 中启动一个 goroutine 等待 SETTINGS ACK
go func() {
	<-cc.seenSettingsChan // 阻塞直到收到 SETTINGS ACK
	fmt.Println("Received SETTINGS ACK from server")
}()
```

**2. Mutex 和 Condition Variable 的使用 (同步和互斥):**

`http2ClientConn` 中的 `mu` 和 `wmu` 是互斥锁，用于保护共享资源 (如 `streams`, 连接状态等) 的并发访问。 `cond` 是条件变量，用于在特定条件满足时通知等待的 goroutine。

```go
func (cc *http2ClientConn) getNextStreamID() uint32 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.nextStreamID += 2
	return cc.nextStreamID - 2
}

func (cc *http2ClientConn) waitForAvailableStream() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	for len(cc.streams) >= int(cc.maxConcurrentStreams) {
		cc.cond.Wait() // 等待直到有流完成并发出信号
	}
}

func (cc *http2ClientConn) onStreamFinished() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	// ... 清理流信息
	cc.cond.Signal() // 通知等待流资源的 goroutine
}
```

**3. `sync.Once` 的使用 (确保操作只执行一次):**

`http2clientStream` 中的 `abortOnce` 用于确保 `abort` channel 只被关闭一次，即使在多个地方尝试中止流。

```go
func (cs *http2clientStream) abortStream(err error) {
	cs.abortOnce.Do(func() {
		cs.abortErr = err
		close(cs.abort)
	})
	// ... 其他中止流的逻辑
}
```

**涉及代码推理的示例:**

**假设输入:**  一个 HTTP/2 客户端尝试向服务器发送一个请求。此时客户端连接 `cc` 的 `maxConcurrentStreams` 设置为 10，`streams` 中已经有 9 个活跃的流。

**代码推理:** 当调用 `cc.CanTakeNewRequest()` 时，`idleStateLocked` 方法会被调用。由于 `len(cc.streams)` (9) 小于 `cc.maxConcurrentStreams` (10)，并且没有其他阻止创建新请求的条件 (例如 `goAway` 不为 nil, `closed` 为 false 等)，该方法将返回 `true`。

**假设输入:**  在上面的场景中，客户端调用了 `cc.ReserveNewRequest()`。

**代码推理:** `ReserveNewRequest` 方法会将 `cc.streamsReserved` 的值增加 1。这意味着即使当前 `len(cc.streams)` 仍然是 9，但由于有 1 个预留的流，下次调用 `idleStateLocked` 时，`currentRequestCountLocked()` 的结果将是 10，仍然小于 `maxConcurrentStreams`。 当真正的请求发送并创建一个新的 `http2clientStream` 时， `streamsReserved` 会在 `RoundTrip` 中被递减。

**涉及命令行参数的具体处理:**

在这段代码中，没有直接涉及到命令行参数的处理。HTTP/2 客户端连接的配置通常是通过 `http2Transport` 结构体的字段来完成的，例如 `TLSClientConfig`，`AllowHTTP` 等。 这些配置可以在创建 `http2Transport` 实例时进行设置，而不是通过命令行参数。

**使用者易犯错的点:**

1. **不正确地处理 `RoundTrip` 返回的错误:**  `RoundTrip` 可能会返回多种错误，例如网络错误、HTTP 协议错误等。使用者需要仔细检查错误类型，并根据需要进行重试或其他处理。

2. **在高并发场景下不注意连接的复用:** HTTP/2 的一个重要特性是连接的复用。如果使用者为每个请求都创建一个新的连接，会降低性能。应该使用 `http.Client` 来管理连接池，以便复用连接。

3. **不理解 HTTP/2 的流量控制机制:**  HTTP/2 具有流量控制机制，如果发送端发送数据的速度超过接收端的处理能力，可能会导致阻塞。使用者应该理解流量控制的概念，并避免发送过多的数据而没有收到窗口更新。

4. **错误地使用 `Request.Cancel`:**  虽然可以使用 `Request.Cancel` 来取消请求，但需要注意在适当的时机调用，避免过早或过晚取消导致资源泄漏或其他问题。

总的来说，这段代码定义了 Go 语言 `net/http` 包中 HTTP/2 客户端连接和流的核心数据结构和管理逻辑，为实现高效的 HTTP/2 通信奠定了基础。 它利用了 Go 语言的并发特性 (goroutine, channel)，同步机制 (mutex, condition variable, sync.Once) 以及标准库提供的网络和 HTTP 相关功能。

Prompt: 
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第9部分，共13部分，请归纳一下它的功能

"""
// closed when seenSettings is true or frame reading fails
	wantSettingsAck  bool                          // we sent a SETTINGS frame and haven't heard back
	goAway           *http2GoAwayFrame             // if non-nil, the GoAwayFrame we received
	goAwayDebug      string                        // goAway frame's debug data, retained as a string
	streams          map[uint32]*http2clientStream // client-initiated
	streamsReserved  int                           // incr by ReserveNewRequest; decr on RoundTrip
	nextStreamID     uint32
	pendingRequests  int                       // requests blocked and waiting to be sent because len(streams) == maxConcurrentStreams
	pings            map[[8]byte]chan struct{} // in flight ping data to notification channel
	br               *bufio.Reader
	lastActive       time.Time
	lastIdle         time.Time // time last idle
	// Settings from peer: (also guarded by wmu)
	maxFrameSize                uint32
	maxConcurrentStreams        uint32
	peerMaxHeaderListSize       uint64
	peerMaxHeaderTableSize      uint32
	initialWindowSize           uint32
	initialStreamRecvWindowSize int32
	readIdleTimeout             time.Duration
	pingTimeout                 time.Duration
	extendedConnectAllowed      bool

	// rstStreamPingsBlocked works around an unfortunate gRPC behavior.
	// gRPC strictly limits the number of PING frames that it will receive.
	// The default is two pings per two hours, but the limit resets every time
	// the gRPC endpoint sends a HEADERS or DATA frame. See golang/go#70575.
	//
	// rstStreamPingsBlocked is set after receiving a response to a PING frame
	// bundled with an RST_STREAM (see pendingResets below), and cleared after
	// receiving a HEADERS or DATA frame.
	rstStreamPingsBlocked bool

	// pendingResets is the number of RST_STREAM frames we have sent to the peer,
	// without confirming that the peer has received them. When we send a RST_STREAM,
	// we bundle it with a PING frame, unless a PING is already in flight. We count
	// the reset stream against the connection's concurrency limit until we get
	// a PING response. This limits the number of requests we'll try to send to a
	// completely unresponsive connection.
	pendingResets int

	// reqHeaderMu is a 1-element semaphore channel controlling access to sending new requests.
	// Write to reqHeaderMu to lock it, read from it to unlock.
	// Lock reqmu BEFORE mu or wmu.
	reqHeaderMu chan struct{}

	// wmu is held while writing.
	// Acquire BEFORE mu when holding both, to avoid blocking mu on network writes.
	// Only acquire both at the same time when changing peer settings.
	wmu  sync.Mutex
	bw   *bufio.Writer
	fr   *http2Framer
	werr error        // first write error that has occurred
	hbuf bytes.Buffer // HPACK encoder writes into this
	henc *hpack.Encoder
}

// clientStream is the state for a single HTTP/2 stream. One of these
// is created for each Transport.RoundTrip call.
type http2clientStream struct {
	cc *http2ClientConn

	// Fields of Request that we may access even after the response body is closed.
	ctx       context.Context
	reqCancel <-chan struct{}

	trace         *httptrace.ClientTrace // or nil
	ID            uint32
	bufPipe       http2pipe // buffered pipe with the flow-controlled response payload
	requestedGzip bool
	isHead        bool

	abortOnce sync.Once
	abort     chan struct{} // closed to signal stream should end immediately
	abortErr  error         // set if abort is closed

	peerClosed chan struct{} // closed when the peer sends an END_STREAM flag
	donec      chan struct{} // closed after the stream is in the closed state
	on100      chan struct{} // buffered; written to if a 100 is received

	respHeaderRecv chan struct{} // closed when headers are received
	res            *Response     // set if respHeaderRecv is closed

	flow        http2outflow // guarded by cc.mu
	inflow      http2inflow  // guarded by cc.mu
	bytesRemain int64        // -1 means unknown; owned by transportResponseBody.Read
	readErr     error        // sticky read error; owned by transportResponseBody.Read

	reqBody              io.ReadCloser
	reqBodyContentLength int64         // -1 means unknown
	reqBodyClosed        chan struct{} // guarded by cc.mu; non-nil on Close, closed when done

	// owned by writeRequest:
	sentEndStream bool // sent an END_STREAM flag to the peer
	sentHeaders   bool

	// owned by clientConnReadLoop:
	firstByte       bool  // got the first response byte
	pastHeaders     bool  // got first MetaHeadersFrame (actual headers)
	pastTrailers    bool  // got optional second MetaHeadersFrame (trailers)
	readClosed      bool  // peer sent an END_STREAM flag
	readAborted     bool  // read loop reset the stream
	totalHeaderSize int64 // total size of 1xx headers seen

	trailer    Header  // accumulated trailers
	resTrailer *Header // client's Response.Trailer
}

var http2got1xxFuncForTests func(int, textproto.MIMEHeader) error

// get1xxTraceFunc returns the value of request's httptrace.ClientTrace.Got1xxResponse func,
// if any. It returns nil if not set or if the Go version is too old.
func (cs *http2clientStream) get1xxTraceFunc() func(int, textproto.MIMEHeader) error {
	if fn := http2got1xxFuncForTests; fn != nil {
		return fn
	}
	return http2traceGot1xxResponseFunc(cs.trace)
}

func (cs *http2clientStream) abortStream(err error) {
	cs.cc.mu.Lock()
	defer cs.cc.mu.Unlock()
	cs.abortStreamLocked(err)
}

func (cs *http2clientStream) abortStreamLocked(err error) {
	cs.abortOnce.Do(func() {
		cs.abortErr = err
		close(cs.abort)
	})
	if cs.reqBody != nil {
		cs.closeReqBodyLocked()
	}
	// TODO(dneil): Clean up tests where cs.cc.cond is nil.
	if cs.cc.cond != nil {
		// Wake up writeRequestBody if it is waiting on flow control.
		cs.cc.cond.Broadcast()
	}
}

func (cs *http2clientStream) abortRequestBodyWrite() {
	cc := cs.cc
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cs.reqBody != nil && cs.reqBodyClosed == nil {
		cs.closeReqBodyLocked()
		cc.cond.Broadcast()
	}
}

func (cs *http2clientStream) closeReqBodyLocked() {
	if cs.reqBodyClosed != nil {
		return
	}
	cs.reqBodyClosed = make(chan struct{})
	reqBodyClosed := cs.reqBodyClosed
	go func() {
		cs.cc.t.markNewGoroutine()
		cs.reqBody.Close()
		close(reqBodyClosed)
	}()
}

type http2stickyErrWriter struct {
	group   http2synctestGroupInterface
	conn    net.Conn
	timeout time.Duration
	err     *error
}

func (sew http2stickyErrWriter) Write(p []byte) (n int, err error) {
	if *sew.err != nil {
		return 0, *sew.err
	}
	n, err = http2writeWithByteTimeout(sew.group, sew.conn, sew.timeout, p)
	*sew.err = err
	return n, err
}

// noCachedConnError is the concrete type of ErrNoCachedConn, which
// needs to be detected by net/http regardless of whether it's its
// bundled version (in h2_bundle.go with a rewritten type name) or
// from a user's x/net/http2. As such, as it has a unique method name
// (IsHTTP2NoCachedConnError) that net/http sniffs for via func
// isNoCachedConnError.
type http2noCachedConnError struct{}

func (http2noCachedConnError) IsHTTP2NoCachedConnError() {}

func (http2noCachedConnError) Error() string { return "http2: no cached connection was available" }

// isNoCachedConnError reports whether err is of type noCachedConnError
// or its equivalent renamed type in net/http2's h2_bundle.go. Both types
// may coexist in the same running program.
func http2isNoCachedConnError(err error) bool {
	_, ok := err.(interface{ IsHTTP2NoCachedConnError() })
	return ok
}

var http2ErrNoCachedConn error = http2noCachedConnError{}

// RoundTripOpt are options for the Transport.RoundTripOpt method.
type http2RoundTripOpt struct {
	// OnlyCachedConn controls whether RoundTripOpt may
	// create a new TCP connection. If set true and
	// no cached connection is available, RoundTripOpt
	// will return ErrNoCachedConn.
	OnlyCachedConn bool

	allowHTTP bool // allow http:// URLs
}

func (t *http2Transport) RoundTrip(req *Request) (*Response, error) {
	return t.RoundTripOpt(req, http2RoundTripOpt{})
}

// authorityAddr returns a given authority (a host/IP, or host:port / ip:port)
// and returns a host:port. The port 443 is added if needed.
func http2authorityAddr(scheme string, authority string) (addr string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil { // authority didn't have a port
		host = authority
		port = ""
	}
	if port == "" { // authority's port was empty
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	if a, err := idna.ToASCII(host); err == nil {
		host = a
	}
	// IPv6 address literal, without a port:
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

// RoundTripOpt is like RoundTrip, but takes options.
func (t *http2Transport) RoundTripOpt(req *Request, opt http2RoundTripOpt) (*Response, error) {
	switch req.URL.Scheme {
	case "https":
		// Always okay.
	case "http":
		if !t.AllowHTTP && !opt.allowHTTP {
			return nil, errors.New("http2: unencrypted HTTP/2 not enabled")
		}
	default:
		return nil, errors.New("http2: unsupported scheme")
	}

	addr := http2authorityAddr(req.URL.Scheme, req.URL.Host)
	for retry := 0; ; retry++ {
		cc, err := t.connPool().GetClientConn(req, addr)
		if err != nil {
			t.vlogf("http2: Transport failed to get client conn for %s: %v", addr, err)
			return nil, err
		}
		reused := !atomic.CompareAndSwapUint32(&cc.atomicReused, 0, 1)
		http2traceGotConn(req, cc, reused)
		res, err := cc.RoundTrip(req)
		if err != nil && retry <= 6 {
			roundTripErr := err
			if req, err = http2shouldRetryRequest(req, err); err == nil {
				// After the first retry, do exponential backoff with 10% jitter.
				if retry == 0 {
					t.vlogf("RoundTrip retrying after failure: %v", roundTripErr)
					continue
				}
				backoff := float64(uint(1) << (uint(retry) - 1))
				backoff += backoff * (0.1 * mathrand.Float64())
				d := time.Second * time.Duration(backoff)
				tm := t.newTimer(d)
				select {
				case <-tm.C():
					t.vlogf("RoundTrip retrying after failure: %v", roundTripErr)
					continue
				case <-req.Context().Done():
					tm.Stop()
					err = req.Context().Err()
				}
			}
		}
		if err == http2errClientConnNotEstablished {
			// This ClientConn was created recently,
			// this is the first request to use it,
			// and the connection is closed and not usable.
			//
			// In this state, cc.idleTimer will remove the conn from the pool
			// when it fires. Stop the timer and remove it here so future requests
			// won't try to use this connection.
			//
			// If the timer has already fired and we're racing it, the redundant
			// call to MarkDead is harmless.
			if cc.idleTimer != nil {
				cc.idleTimer.Stop()
			}
			t.connPool().MarkDead(cc)
		}
		if err != nil {
			t.vlogf("RoundTrip failure: %v", err)
			return nil, err
		}
		return res, nil
	}
}

// CloseIdleConnections closes any connections which were previously
// connected from previous requests but are now sitting idle.
// It does not interrupt any connections currently in use.
func (t *http2Transport) CloseIdleConnections() {
	if cp, ok := t.connPool().(http2clientConnPoolIdleCloser); ok {
		cp.closeIdleConnections()
	}
}

var (
	http2errClientConnClosed         = errors.New("http2: client conn is closed")
	http2errClientConnUnusable       = errors.New("http2: client conn not usable")
	http2errClientConnNotEstablished = errors.New("http2: client conn could not be established")
	http2errClientConnGotGoAway      = errors.New("http2: Transport received Server's graceful shutdown GOAWAY")
)

// shouldRetryRequest is called by RoundTrip when a request fails to get
// response headers. It is always called with a non-nil error.
// It returns either a request to retry (either the same request, or a
// modified clone), or an error if the request can't be replayed.
func http2shouldRetryRequest(req *Request, err error) (*Request, error) {
	if !http2canRetryError(err) {
		return nil, err
	}
	// If the Body is nil (or http.NoBody), it's safe to reuse
	// this request and its Body.
	if req.Body == nil || req.Body == NoBody {
		return req, nil
	}

	// If the request body can be reset back to its original
	// state via the optional req.GetBody, do that.
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		newReq := *req
		newReq.Body = body
		return &newReq, nil
	}

	// The Request.Body can't reset back to the beginning, but we
	// don't seem to have started to read from it yet, so reuse
	// the request directly.
	if err == http2errClientConnUnusable {
		return req, nil
	}

	return nil, fmt.Errorf("http2: Transport: cannot retry err [%v] after Request.Body was written; define Request.GetBody to avoid this error", err)
}

func http2canRetryError(err error) bool {
	if err == http2errClientConnUnusable || err == http2errClientConnGotGoAway {
		return true
	}
	if se, ok := err.(http2StreamError); ok {
		if se.Code == http2ErrCodeProtocol && se.Cause == http2errFromPeer {
			// See golang/go#47635, golang/go#42777
			return true
		}
		return se.Code == http2ErrCodeRefusedStream
	}
	return false
}

func (t *http2Transport) dialClientConn(ctx context.Context, addr string, singleUse bool) (*http2ClientConn, error) {
	if t.http2transportTestHooks != nil {
		return t.newClientConn(nil, singleUse)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	tconn, err := t.dialTLS(ctx, "tcp", addr, t.newTLSConfig(host))
	if err != nil {
		return nil, err
	}
	return t.newClientConn(tconn, singleUse)
}

func (t *http2Transport) newTLSConfig(host string) *tls.Config {
	cfg := new(tls.Config)
	if t.TLSClientConfig != nil {
		*cfg = *t.TLSClientConfig.Clone()
	}
	if !http2strSliceContains(cfg.NextProtos, http2NextProtoTLS) {
		cfg.NextProtos = append([]string{http2NextProtoTLS}, cfg.NextProtos...)
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}

func (t *http2Transport) dialTLS(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	if t.DialTLSContext != nil {
		return t.DialTLSContext(ctx, network, addr, tlsCfg)
	} else if t.DialTLS != nil {
		return t.DialTLS(network, addr, tlsCfg)
	}

	tlsCn, err := t.dialTLSWithContext(ctx, network, addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	state := tlsCn.ConnectionState()
	if p := state.NegotiatedProtocol; p != http2NextProtoTLS {
		return nil, fmt.Errorf("http2: unexpected ALPN protocol %q; want %q", p, http2NextProtoTLS)
	}
	if !state.NegotiatedProtocolIsMutual {
		return nil, errors.New("http2: could not negotiate protocol mutually")
	}
	return tlsCn, nil
}

// disableKeepAlives reports whether connections should be closed as
// soon as possible after handling the first request.
func (t *http2Transport) disableKeepAlives() bool {
	return t.t1 != nil && t.t1.DisableKeepAlives
}

func (t *http2Transport) expectContinueTimeout() time.Duration {
	if t.t1 == nil {
		return 0
	}
	return t.t1.ExpectContinueTimeout
}

func (t *http2Transport) NewClientConn(c net.Conn) (*http2ClientConn, error) {
	return t.newClientConn(c, t.disableKeepAlives())
}

func (t *http2Transport) newClientConn(c net.Conn, singleUse bool) (*http2ClientConn, error) {
	conf := http2configFromTransport(t)
	cc := &http2ClientConn{
		t:                           t,
		tconn:                       c,
		readerDone:                  make(chan struct{}),
		nextStreamID:                1,
		maxFrameSize:                16 << 10, // spec default
		initialWindowSize:           65535,    // spec default
		initialStreamRecvWindowSize: conf.MaxUploadBufferPerStream,
		maxConcurrentStreams:        http2initialMaxConcurrentStreams, // "infinite", per spec. Use a smaller value until we have received server settings.
		peerMaxHeaderListSize:       0xffffffffffffffff,               // "infinite", per spec. Use 2^64-1 instead.
		streams:                     make(map[uint32]*http2clientStream),
		singleUse:                   singleUse,
		seenSettingsChan:            make(chan struct{}),
		wantSettingsAck:             true,
		readIdleTimeout:             conf.SendPingTimeout,
		pingTimeout:                 conf.PingTimeout,
		pings:                       make(map[[8]byte]chan struct{}),
		reqHeaderMu:                 make(chan struct{}, 1),
		lastActive:                  t.now(),
	}
	var group http2synctestGroupInterface
	if t.http2transportTestHooks != nil {
		t.markNewGoroutine()
		t.http2transportTestHooks.newclientconn(cc)
		c = cc.tconn
		group = t.group
	}
	if http2VerboseLogs {
		t.vlogf("http2: Transport creating client conn %p to %v", cc, c.RemoteAddr())
	}

	cc.cond = sync.NewCond(&cc.mu)
	cc.flow.add(int32(http2initialWindowSize))

	// TODO: adjust this writer size to account for frame size +
	// MTU + crypto/tls record padding.
	cc.bw = bufio.NewWriter(http2stickyErrWriter{
		group:   group,
		conn:    c,
		timeout: conf.WriteByteTimeout,
		err:     &cc.werr,
	})
	cc.br = bufio.NewReader(c)
	cc.fr = http2NewFramer(cc.bw, cc.br)
	cc.fr.SetMaxReadFrameSize(conf.MaxReadFrameSize)
	if t.CountError != nil {
		cc.fr.countError = t.CountError
	}
	maxHeaderTableSize := conf.MaxDecoderHeaderTableSize
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(maxHeaderTableSize, nil)
	cc.fr.MaxHeaderListSize = t.maxHeaderListSize()

	cc.henc = hpack.NewEncoder(&cc.hbuf)
	cc.henc.SetMaxDynamicTableSizeLimit(conf.MaxEncoderHeaderTableSize)
	cc.peerMaxHeaderTableSize = http2initialHeaderTableSize

	if cs, ok := c.(http2connectionStater); ok {
		state := cs.ConnectionState()
		cc.tlsState = &state
	}

	initialSettings := []http2Setting{
		{ID: http2SettingEnablePush, Val: 0},
		{ID: http2SettingInitialWindowSize, Val: uint32(cc.initialStreamRecvWindowSize)},
	}
	initialSettings = append(initialSettings, http2Setting{ID: http2SettingMaxFrameSize, Val: conf.MaxReadFrameSize})
	if max := t.maxHeaderListSize(); max != 0 {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingMaxHeaderListSize, Val: max})
	}
	if maxHeaderTableSize != http2initialHeaderTableSize {
		initialSettings = append(initialSettings, http2Setting{ID: http2SettingHeaderTableSize, Val: maxHeaderTableSize})
	}

	cc.bw.Write(http2clientPreface)
	cc.fr.WriteSettings(initialSettings...)
	cc.fr.WriteWindowUpdate(0, uint32(conf.MaxUploadBufferPerConnection))
	cc.inflow.init(conf.MaxUploadBufferPerConnection + http2initialWindowSize)
	cc.bw.Flush()
	if cc.werr != nil {
		cc.Close()
		return nil, cc.werr
	}

	// Start the idle timer after the connection is fully initialized.
	if d := t.idleConnTimeout(); d != 0 {
		cc.idleTimeout = d
		cc.idleTimer = t.afterFunc(d, cc.onIdleTimeout)
	}

	go cc.readLoop()
	return cc, nil
}

func (cc *http2ClientConn) healthCheck() {
	pingTimeout := cc.pingTimeout
	// We don't need to periodically ping in the health check, because the readLoop of ClientConn will
	// trigger the healthCheck again if there is no frame received.
	ctx, cancel := cc.t.contextWithTimeout(context.Background(), pingTimeout)
	defer cancel()
	cc.vlogf("http2: Transport sending health check")
	err := cc.Ping(ctx)
	if err != nil {
		cc.vlogf("http2: Transport health check failure: %v", err)
		cc.closeForLostPing()
	} else {
		cc.vlogf("http2: Transport health check success")
	}
}

// SetDoNotReuse marks cc as not reusable for future HTTP requests.
func (cc *http2ClientConn) SetDoNotReuse() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.doNotReuse = true
}

func (cc *http2ClientConn) setGoAway(f *http2GoAwayFrame) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	old := cc.goAway
	cc.goAway = f

	// Merge the previous and current GoAway error frames.
	if cc.goAwayDebug == "" {
		cc.goAwayDebug = string(f.DebugData())
	}
	if old != nil && old.ErrCode != http2ErrCodeNo {
		cc.goAway.ErrCode = old.ErrCode
	}
	last := f.LastStreamID
	for streamID, cs := range cc.streams {
		if streamID <= last {
			// The server's GOAWAY indicates that it received this stream.
			// It will either finish processing it, or close the connection
			// without doing so. Either way, leave the stream alone for now.
			continue
		}
		if streamID == 1 && cc.goAway.ErrCode != http2ErrCodeNo {
			// Don't retry the first stream on a connection if we get a non-NO error.
			// If the server is sending an error on a new connection,
			// retrying the request on a new one probably isn't going to work.
			cs.abortStreamLocked(fmt.Errorf("http2: Transport received GOAWAY from server ErrCode:%v", cc.goAway.ErrCode))
		} else {
			// Aborting the stream with errClentConnGotGoAway indicates that
			// the request should be retried on a new connection.
			cs.abortStreamLocked(http2errClientConnGotGoAway)
		}
	}
}

// CanTakeNewRequest reports whether the connection can take a new request,
// meaning it has not been closed or received or sent a GOAWAY.
//
// If the caller is going to immediately make a new request on this
// connection, use ReserveNewRequest instead.
func (cc *http2ClientConn) CanTakeNewRequest() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.canTakeNewRequestLocked()
}

// ReserveNewRequest is like CanTakeNewRequest but also reserves a
// concurrent stream in cc. The reservation is decremented on the
// next call to RoundTrip.
func (cc *http2ClientConn) ReserveNewRequest() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if st := cc.idleStateLocked(); !st.canTakeNewRequest {
		return false
	}
	cc.streamsReserved++
	return true
}

// ClientConnState describes the state of a ClientConn.
type http2ClientConnState struct {
	// Closed is whether the connection is closed.
	Closed bool

	// Closing is whether the connection is in the process of
	// closing. It may be closing due to shutdown, being a
	// single-use connection, being marked as DoNotReuse, or
	// having received a GOAWAY frame.
	Closing bool

	// StreamsActive is how many streams are active.
	StreamsActive int

	// StreamsReserved is how many streams have been reserved via
	// ClientConn.ReserveNewRequest.
	StreamsReserved int

	// StreamsPending is how many requests have been sent in excess
	// of the peer's advertised MaxConcurrentStreams setting and
	// are waiting for other streams to complete.
	StreamsPending int

	// MaxConcurrentStreams is how many concurrent streams the
	// peer advertised as acceptable. Zero means no SETTINGS
	// frame has been received yet.
	MaxConcurrentStreams uint32

	// LastIdle, if non-zero, is when the connection last
	// transitioned to idle state.
	LastIdle time.Time
}

// State returns a snapshot of cc's state.
func (cc *http2ClientConn) State() http2ClientConnState {
	cc.wmu.Lock()
	maxConcurrent := cc.maxConcurrentStreams
	if !cc.seenSettings {
		maxConcurrent = 0
	}
	cc.wmu.Unlock()

	cc.mu.Lock()
	defer cc.mu.Unlock()
	return http2ClientConnState{
		Closed:               cc.closed,
		Closing:              cc.closing || cc.singleUse || cc.doNotReuse || cc.goAway != nil,
		StreamsActive:        len(cc.streams) + cc.pendingResets,
		StreamsReserved:      cc.streamsReserved,
		StreamsPending:       cc.pendingRequests,
		LastIdle:             cc.lastIdle,
		MaxConcurrentStreams: maxConcurrent,
	}
}

// clientConnIdleState describes the suitability of a client
// connection to initiate a new RoundTrip request.
type http2clientConnIdleState struct {
	canTakeNewRequest bool
}

func (cc *http2ClientConn) idleState() http2clientConnIdleState {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.idleStateLocked()
}

func (cc *http2ClientConn) idleStateLocked() (st http2clientConnIdleState) {
	if cc.singleUse && cc.nextStreamID > 1 {
		return
	}
	var maxConcurrentOkay bool
	if cc.t.StrictMaxConcurrentStreams {
		// We'll tell the caller we can take a new request to
		// prevent the caller from dialing a new TCP
		// connection, but then we'll block later before
		// writing it.
		maxConcurrentOkay = true
	} else {
		// We can take a new request if the total of
		//   - active streams;
		//   - reservation slots for new streams; and
		//   - streams for which we have sent a RST_STREAM and a PING,
		//     but received no subsequent frame
		// is less than the concurrency limit.
		maxConcurrentOkay = cc.currentRequestCountLocked() < int(cc.maxConcurrentStreams)
	}

	st.canTakeNewRequest = cc.goAway == nil && !cc.closed && !cc.closing && maxConcurrentOkay &&
		!cc.doNotReuse &&
		int64(cc.nextStreamID)+2*int64(cc.pendingRequests) < math.MaxInt32 &&
		!cc.tooIdleLocked()

	// If this connection has never been used for a request and is closed,
	// then let it take a request (which will fail).
	//
	// This avoids a situation where an error early in a connection's lifetime
	// goes unreported.
	if cc.nextStreamID == 1 && cc.streamsReserved == 0 && cc.closed {
		st.canTakeNewRequest = true
	}

	return
}

// currentRequestCountLocked reports the number of concurrency slots currently in use,
// including active streams, reserved slots, and reset streams waiting for acknowledgement.
func (cc *http2ClientConn) currentRequestCountLocked() int {
	return len(cc.streams) + cc.streamsReserved + cc.pendingResets
}

func (cc *http2ClientConn) canTakeNewRequestLocked() bool {
	st := cc.idleStateLocked()
	return st.canTakeNewRequest
}

// tooIdleLocked reports whether this connection has been been sitting idle
// for too much wall time.
func (cc *http2ClientConn) tooIdleLocked() bool {
	// The Round(0) strips the monontonic clock reading so the
	// times are compared based on their wall time. We don't want
	// to reuse a connection that's been sitting idle during
	// VM/laptop suspend if monotonic time was also frozen.
	return cc.idleTimeout != 0 && !cc.lastIdle.IsZero() && cc.t.timeSince(cc.lastIdle.Round(0)) > cc.idleTimeout
}

// onIdleTimeout is called from a time.AfterFunc goroutine. It will
// only be called when we're idle, but because we're coming from a new
// goroutine, there could be a new request coming in at the same time,
// so this simply calls the synchronized closeIfIdle to shut down this
// connection. The timer could just call closeIfIdle, but this is more
// clear.
func (cc *http2ClientConn) onIdleTimeout() {
	cc.closeIfIdle()
}

func (cc *http2ClientConn) closeConn() {
	t := time.AfterFunc(250*time.Millisecond, cc.forceCloseConn)
	defer t.Stop()
	cc.tconn.Close()
}

// A tls.Conn.Close can hang for a long time if the peer is unresponsive.
// Try to shut it down more aggressively.
func (cc *http2ClientConn) forceCloseConn() {
	tc, ok := cc.tconn.(*tls.Conn)
	if !ok {
		return
	}
	if nc := tc.NetConn(); nc != nil {
		nc.Close()
	}
}

func (cc *http2ClientConn) closeIfIdle() {
	cc.mu.Lock()
	if len(cc.streams) > 0 || cc.streamsReserved > 0 {
		cc.mu.Unlock()
		return
	}
	cc.closed = true
	nextID := cc.nextStreamID
	// TODO: do clients send GOAWAY too? maybe? Just Close:
	cc.mu.Unlock()

	if http2VerboseLogs {
		cc.vlogf("http2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)", cc, cc.singleUse, nextID-2)
	}
	cc.closeConn()
}

func (cc *http2ClientConn) isDoNotReuseAndIdle() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.doNotReuse && len(cc.streams) == 0
}

var http2shutdownEnterWaitStateHook = func() {}

// Shutdown gracefully closes the client connection, waiting for running streams to complete.
func (cc *http2ClientConn) Shutdown(ctx context.Context) error {
	if err := cc.sendGoAway(); err != nil {
		return err
	}
	// Wait for all in-flight streams to complete or connection to close
	done := make(chan struct{})
	cancelled := false // guarded by cc.mu
	go func() {
		cc.t.markNewGoroutine()
		cc.mu.Lock()
		defer cc.mu.Unlock()
		for {
			if len(cc.streams) == 0 || cc.closed {
				cc.closed = true
				close(done)
				break
			}
			if cancelled {
				break
			}
			cc.cond.Wait()
		}
	}()
	http2shutdownEnterWaitStateHook()
	select {
	case <-done:
		cc.closeConn()
		return nil
	case <-ctx.Done():
		cc.mu.Lock()
		// Free the goroutine above
		cancelled = true
		cc.cond.Broadcast()
		cc.mu.Unlock()
		return ctx.Err()
	}
}

func (cc *http2ClientConn) sendGoAway() error {
	cc.mu.Lock()
	closing := cc.closing
	cc.closing = true
	maxStreamID := cc.nextStreamID
	cc.mu.Unlock()
	if closing {
		// GOAWAY sent already
		return nil
	}

	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	// Send a graceful shutdown frame to server
	if err := cc.fr.WriteGoAway(maxStreamID, http2ErrCodeNo, nil); err != nil {
		return err
	}
	if err := cc.bw.Flush(); err != nil {
		return err
	}
	// Prevent new requests
	return nil
}

// closes the client connection immediately. In-flight requests are interrupted.
// err is sent to streams.
func (cc *http2ClientConn) closeForError(err error) {
	cc.mu.Lock()
	cc.closed = true
	for _, cs := range cc.streams {
		cs.abortStreamLocked(err)
	}
	cc.cond.Broadcast()
	cc.mu.Unlock()
	cc.closeConn()
}

// Close closes the client connection immediately.
//
// In-flight requests are interrupted. For a graceful shutdown, use Shutdown instead.
func (cc *http2ClientConn) Close() error {
	err := errors.New("http2: client connection force closed via ClientConn.Close")
	cc.closeForError(err)
	return nil
}

// closes the client connection immediately. In-flight requests are interrupted.
func (cc *http2ClientConn) closeForLostPing() {
	err := errors.New("http2: client connection lost")
	if f := cc.t.CountError; f != nil {
		f("conn_close_lost_ping")
	}
	cc.closeForError(err)
}

// errRequestCanceled is a copy of net/http's errRequestCanceled because it's not
// exported. At least they'll be DeepEqual for h1-vs-h2 comparisons tests.
var http2errRequestCanceled = errors.New("net/http: request canceled")

func http2commaSeparatedTrailers(req *Request) (string, error) {
	keys := make([]string, 0, len(req.Trailer))
	for k := range req.Trailer {
		k = http2canonicalHeader(k)
		switch k {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			return "", fmt.Errorf("invalid Trailer key %q", k)
		}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return strings.Join(keys, ","), nil
	}
	return "", nil
}

func (cc *http2ClientConn) responseHeaderTimeout() time.Duration {
	if cc.t.t1 != nil {
		return cc.t.t1.ResponseHeaderTimeout
	}
	// No way to do this (yet?) with just an http2.Transport. Probably
	// no need. Request.Cancel this is the new way. We only need to support
	// this for compatibility with the old http.Transport fields when
	// we're doing transparent http2.
	return 0
}

// checkConnHeaders checks whether req has any invalid connection-level headers.
// per RFC 7540 section 8.1.2.2: Connection-Specific Header Fields.
// Certain headers are special-cased as okay but not transmitted later.
func http2checkConnHeaders(req *Request) error {
	if v := req.Header.Get("Upgrade"); v != "" {
		return fmt.Errorf("http2: invalid Upgrade request header: %q", req.Header["Upgrade"])
	}
	if vv := req.Header["Transfer-Encoding"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && vv[0] != "chunked") {
		return fmt.Errorf("http2: invalid Transfer-Encoding request header: %q", vv)
	}
	if vv := req.Header["Connection"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && !http2asciiEqualFold(vv[0], "close") && !http2asciiEqualFold(vv[0], "keep-alive")) {
		return fmt.Errorf("http2: invalid Connection request header: %q", vv)
	}
	return nil
}

// actualContentLength returns a sanitized version of
// req.ContentLength, where 0 actually means zero (not unknown) and -1
// means unknown.
func http2actualContentLength(req *Request) int64 {
	if req.Body == nil || req.Body == NoBody {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}

func (cc *http2ClientConn) decrStreamReservations() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.decrStreamReservationsLocked()
}

func (cc *http2ClientConn) decrStreamReservationsLocked() {
	if cc.streamsReserved > 0 {
		cc.streamsReserved--
	}
}

func (cc *http2ClientConn) RoundTrip(req *Request) (*Response, error) {
	return cc.roundTrip(req, nil)
}

func (cc *http2ClientConn) roundTrip(req *Request, streamf func(*http2clientStream)) (*Response, error) {
	ctx := req.Context()
	cs := &http2clientStream{
		cc:                   cc,
		ctx:                  ctx,
		reqCancel:            req.Cancel,
		isHead:               req.Method == "HEAD",
		reqBody:              req.Body,
		reqBodyContentLength: http2actualContentLength(req),
		trace:                httptrace.ContextClientTrace(ctx),
		peerClosed:           make(chan struct{}),
		abort:                make(chan struct{}),
		respHeaderRecv:       make(chan struct{}),
		donec:                make(chan struct{}),
	}

	// TODO(bradfitz): this is a copy of the logic in net/http. Unify somewhere?
	if !cc.t.disableCompression() &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		!cs.isHead {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as unive
"""




```