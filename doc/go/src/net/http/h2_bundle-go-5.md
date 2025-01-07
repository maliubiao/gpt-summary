Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The core request is to understand the functionality of a specific Go source file segment (`h2_bundle.go`) related to HTTP/2 server connections. The prompt asks for a summary of functionality, inference of Go features, code examples, command-line argument handling (if any), potential pitfalls, and a concluding summary of this particular part.

2. **Initial Scan and Identification of Key Structures:**  The first thing to do is to quickly read through the code and identify the major data structures and functions. In this snippet, the `http2serverConn` struct stands out as central. We also see functions associated with it, like `Framer`, `CloseConn`, `Flush`, `HeaderEncoder`, `state`, `setConnState`, logging functions (`vlogf`, `logf`, `condlogf`), frame reading/writing functions (`readFrames`, `writeFrameAsync`, `writeFrameFromHandler`, `writeFrame`), and processing functions (`processFrameFromReader`, `processFrame`). The `http2stream` struct is also important, representing an individual HTTP/2 stream.

3. **Focus on `http2serverConn`:** Since it seems to be the core of this section, analyze its fields. This provides clues about its responsibilities:
    * `sc        *http2serverConn`: A self-reference, likely used in methods.
    * `id        uint32`: Stream identifier.
    * `body      *http2pipe`:  Handles request body data.
    * `cw        http2closeWaiter`: For managing stream closure.
    * `ctx       context.Context`, `cancelCtx func()`:  Context management for the stream.
    * `bodyBytes`, `declBodyBytes`: Tracking request body sizes.
    * `flow`, `inflow`: Flow control management.
    * `state`: The current state of the stream.
    * `resetQueued`: Indicates if a RST_STREAM is pending.
    * `gotTrailerHeader`, `wroteHeaders`: Tracking header and trailer status.
    * `readDeadline`, `writeDeadline`:  Timeouts.
    * `closeErr`:  Stores closure errors.
    * `trailer`, `reqTrailer`: Header storage.

4. **Analyze the Methods:**  Go through the methods associated with `http2serverConn` and `http2stream`, grouping them by functionality:
    * **Basic Accessors:** `Framer`, `CloseConn`, `Flush`, `HeaderEncoder`. These are straightforward getters and wrappers.
    * **State Management:** `state`, `setConnState`. These manage the lifecycle of the connection and individual streams. Notice the logic in `state` for implicitly closing idle streams.
    * **Logging:** `vlogf`, `logf`, `condlogf`. Different levels of logging.
    * **Error Handling:** `http2errno`, `http2isClosedConnError`. Specifically handling closed connection errors across platforms.
    * **Header Handling:** `canonicalHeader`. Canonicalization and caching of header keys.
    * **Frame Reading:** `readFrames`, `http2readFrameResult`. A loop for reading incoming frames asynchronously. The `readMore` function is a key detail for flow control of frame processing.
    * **Frame Writing:** `writeFrameAsync`, `http2frameWriteResult`, `writeFrame`, `writeFrameFromHandler`, `startFrameWrite`, `wroteFrame`, `scheduleFrameWrite`. This is a complex area involving asynchronous writing, scheduling, and handling results. Pay attention to the different functions for calling from the serve goroutine vs. handler goroutines.
    * **Connection Lifecycle:** `closeAllStreamsOnConnClose`, `stopShutdownTimer`, `notePanic`, `serve`. The `serve` function is the main loop for handling the connection.
    * **Graceful Shutdown:** `startGracefulShutdown`, `startGracefulShutdownInternal`, `goAway`, `shutDownIn`.
    * **Stream Reset:** `resetStream`.
    * **Frame Processing:** `processFrameFromReader`, `processFrame`, and specific frame processing functions (e.g., `processSettings`, `processHeaders`, `processPing`, etc.).
    * **Timers:** `handlePingTimer`, `onSettingsTimer`, `onIdleTimer`, `onReadIdleTimer`, `onShutdownTimer`.
    * **Preface Handling:** `readPreface`. Ensuring the client sends the correct initial greeting.
    * **Data Handling:** `writeDataFromHandler`. Writing data from the handler.

5. **Infer Go Features:** As you analyze the code, identify the Go features being used:
    * **Structs and Methods:**  The core building blocks.
    * **Pointers:**  Extensive use for managing shared state.
    * **Context:** For managing request lifecycle and cancellation.
    * **Channels:** For communication between goroutines (e.g., `readFrameCh`, `wroteFrameCh`, `wantWriteFrameCh`, `serveMsgCh`).
    * **Goroutines:** For concurrency (e.g., `readFrames`, `writeFrameAsync`, the main `serve` loop).
    * **`select` Statement:** For handling multiple channel operations.
    * **`sync.Once`:** For ensuring code runs only once (e.g., `shutdownOnce`).
    * **`sync.Pool`:** For reusing objects (e.g., `http2errChanPool`, `http2writeDataPool`).
    * **Interfaces:**  The `http2Frame` interface is evident.
    * **Error Handling:**  Returning and checking `error` values. The `errors.Is` function is used.
    * **Closures:**  Used in `gateDone` and anonymous functions within goroutines.
    * **Timers:** Using `time.Timer`.
    * **Reflection:** Used in `http2errno` (though noted as a temporary workaround).
    * **Atomic Operations (Implicit):**  While not explicitly shown as `sync/atomic` functions, the need for thread-safe operations on shared state suggests their likely use elsewhere in the full code.

6. **Construct Code Examples:**  Based on the identified features, create simple, illustrative code examples. Focus on the most prominent functionalities:
    * Creating a server connection (although this is more implicit in the provided snippet).
    * Handling incoming frames (demonstrating the `readFrameCh` and processing).
    * Writing frames (showing `wantWriteFrameCh`).
    * Managing stream state.
    * Using context.

7. **Identify Potential Pitfalls:** Think about common errors developers might make when using this code or related HTTP/2 concepts:
    * Incorrectly managing stream states.
    * Not handling asynchronous operations properly (deadlocks with channels).
    * Ignoring flow control.
    * Misunderstanding the HTTP/2 connection lifecycle.
    * Not handling errors from frame processing.

8. **Command-Line Arguments:** Scan the code for any explicit handling of `os.Args` or flags. If none are present, explicitly state that.

9. **Summarize Functionality:**  Condense the analysis into a clear and concise summary of the code's purpose.

10. **Review and Refine:** Read through the entire analysis to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. Ensure the examples are easy to understand and directly relate to the code. For instance, initially, one might just say "handles frame reading."  Refining this would involve mentioning the asynchronous nature and the role of channels and goroutines. Similarly, "manages stream states" could be refined to highlight the specific states and the transitions between them.

This iterative process of scanning, analyzing specific components, inferring language features, creating examples, and summarizing helps to systematically understand the functionality of the given code snippet. The focus on the `http2serverConn` struct and its methods is crucial for grasping the overall responsibilities of this code segment.
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能,
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共13部分，请归纳一下它的功能
```

这段代码是 Go 语言 `net/http` 包中 HTTP/2 服务器连接 (`http2serverConn`) 实现的一部分，主要负责处理 HTTP/2 连接的生命周期、帧的读取和写入、流的管理以及错误处理等核心功能。

**功能列表:**

1. **定义了 `http2stream` 结构体:** 表示一个 HTTP/2 的流，包含流的各种状态信息，例如流ID、请求体、上下文、流量控制、状态、截止时间、Trailer 等。
2. **定义了 `http2serverConn` 的一些辅助方法:**
    * `Framer()`: 返回用于帧操作的 `http2Framer` 实例。
    * `CloseConn()`: 关闭底层的网络连接。
    * `Flush()`: 刷新输出缓冲。
    * `HeaderEncoder()`: 返回用于 HPACK 编码的编码器和缓冲区。
    * `state(streamID uint32)`: 获取指定流 ID 的状态和 `http2stream` 对象。
    * `setConnState(state ConnState)`: 设置连接的状态（使用 `net/http` 的 `ConnState`）。
    * `vlogf(format string, args ...interface{})` 和 `logf(format string, args ...interface{})`: 提供带条件的详细日志和普通日志输出功能。
    * `http2errno(v error) uintptr`:  一个平台相关的辅助函数，用于获取错误的底层 uintptr (可能用于判断连接关闭错误)。
    * `http2isClosedConnError(err error) bool`: 判断给定的错误是否是由于连接关闭引起的。
    * `condlogf(err error, format string, args ...interface{})`: 根据错误类型有条件地输出日志。
    * `canonicalHeader(v string) string`:  规范化 HTTP 头部键，并进行缓存以提高性能。
3. **定义了帧读取相关功能:**
    * `http2readFrameResult` 结构体:  表示读取帧的结果，包含帧数据、错误以及一个回调函数 `readMore`。
    * `readFrames()`:  一个独立的 goroutine 运行的函数，负责循环读取来自客户端的 HTTP/2 帧，并将结果发送到 `readFrameCh` 通道。它保证一次只读取一个帧，直到消费者处理完毕。
4. **定义了帧写入相关功能:**
    * `http2frameWriteResult` 结构体: 表示帧写入操作的结果。
    * `writeFrameAsync(wr http2FrameWriteRequest, wd *http2writeData)`: 一个独立的 goroutine 运行的函数，负责异步地将单个帧写入到连接，并将结果发送到 `wroteFrameCh` 通道。
5. **定义了连接关闭和错误处理相关功能:**
    * `closeAllStreamsOnConnClose()`: 在连接关闭时关闭所有相关的流。
    * `stopShutdownTimer()`: 停止连接关闭的定时器。
    * `notePanic()`:  记录 `serve` goroutine 中发生的 panic，并执行测试钩子。
6. **定义了 `serve` 方法:** 这是 `http2serverConn` 的核心方法，在一个独立的 goroutine 中运行，负责处理整个 HTTP/2 连接的生命周期。它包含了：
    * 设置初始的 SETTINGS 帧。
    * 读取客户端的连接前导码 (preface)。
    * 设置连接状态为 `StateActive` 和 `StateIdle`。
    * 启动和管理空闲超时定时器 (`idleTimer`)。
    * 启动和管理读取空闲超时定时器 (`readIdleTimer`)，用于发送 PING 帧检测连接活性。
    * 启动 `readFrames()` goroutine。
    * 启动一个定时器 (`settingsTimer`) 等待客户端发送 SETTINGS 帧。
    * 进入主循环，通过 `select` 监听各种事件，例如：
        * 来自 `wantWriteFrameCh` 的写入帧请求。
        * 来自 `wroteFrameCh` 的帧写入结果。
        * 来自 `readFrameCh` 的读取帧结果。
        * 来自 `bodyReadCh` 的请求体读取通知。
        * 来自 `serveMsgCh` 的各种服务器消息（例如定时器触发、优雅关闭请求等）。
    * 处理控制帧队列过多的情况，防止内存耗尽。
    * 管理优雅关闭的定时器 (`shutdownTimer`)。
7. **定义了 PING 帧处理逻辑:** `handlePingTimer` 函数负责发送和接收 PING 帧，以检测连接的活性。
8. **定义了 `http2serverMessage` 类型和相关的常量:** 用于在 `serve` goroutine 内部传递消息。
9. **定义了各种定时器触发的处理函数:** `onSettingsTimer`, `onIdleTimer`, `onReadIdleTimer`, `onShutdownTimer`。
10. **定义了 `sendServeMsg` 函数:** 用于向 `serveMsgCh` 发送消息。
11. **定义了读取客户端前导码的功能:** `readPreface` 函数负责读取客户端发送的 `http2ClientPreface` 字符串，并处理超时和错误情况。
12. **定义了用于 `writeDataFromHandler` 的对象池:** `http2errChanPool` 和 `http2writeDataPool` 用于复用 channel 和 `http2writeData` 结构体，提高性能。
13. **定义了从 Handler 写入 DATA 帧的功能:** `writeDataFromHandler` 函数用于将 HTTP Handler 生成的数据写入到 HTTP/2 流中。
14. **定义了 `writeFrameFromHandler` 函数:** 用于从非 `serve` goroutine（例如 Handler 的 goroutine）安全地发送写入帧请求到 `serve` goroutine。
15. **定义了 `writeFrame` 函数:**  在 `serve` goroutine 中调度帧的写入。
16. **定义了 `startFrameWrite` 函数:** 启动一个 goroutine 来实际执行帧的写入操作。
17. **定义了 `wroteFrame` 函数:**  在帧写入完成后，在 `serve` goroutine 中处理写入结果，更新流的状态。
18. **定义了 `scheduleFrameWrite` 函数:**  调度下一个要写入的帧，并处理缓冲刷新等操作。
19. **定义了优雅关闭连接的功能:** `startGracefulShutdown` 和 `startGracefulShutdownInternal` 函数用于发送 GOAWAY 帧并等待所有流完成后关闭连接。
20. **定义了非优雅关闭连接的功能:** `goAway` 函数用于发送带有错误码的 GOAWAY 帧。
21. **定义了设置关闭定时器的功能:** `shutDownIn` 函数用于设置连接关闭的定时器。
22. **定义了重置流的功能:** `resetStream` 函数用于发送 RST_STREAM 帧来终止一个流。
23. **定义了处理从帧读取器接收到的帧的功能:** `processFrameFromReader` 函数接收来自 `readFrames` goroutine 的帧，并根据帧类型调用相应的处理函数。
24. **定义了 `processFrame` 函数:**  根据帧的类型分发到不同的处理函数。
25. **定义了各种帧类型的处理函数:** 例如 `processSettings`, `processPing`, `processWindowUpdate`, `processResetStream` 等，用于处理不同类型的 HTTP/2 帧。

**推理的 Go 语言功能实现:**

这段代码是 Go 语言 `net/http` 包中 HTTP/2 服务器连接的核心实现。它利用了 Go 语言的以下特性：

* **Goroutine 和 Channel:**  用于并发处理连接和帧的读写，以及在不同的 goroutine 之间传递消息。例如，`readFrames` 和 `writeFrameAsync` 都是独立的 goroutine，通过 channel 与 `serve` goroutine 通信。
* **Struct 和 Method:**  使用结构体 `http2serverConn` 和 `http2stream` 来组织数据和行为。
* **Interface:**  `http2Frame` 是一个接口，用于表示不同类型的 HTTP/2 帧，方便进行统一处理。
* **Select 语句:**  在 `serve` 方法的主循环中使用 `select` 语句来监听多个 channel 事件，实现非阻塞的事件处理。
* **Context:** 使用 `context.Context` 来管理流的生命周期和取消操作。
* **Timer:** 使用 `time.Timer` 实现连接的超时控制，例如空闲超时和关闭超时。
* **Error Handling:** 使用 `error` 接口来处理各种错误情况。
* **Sync 包:** 使用 `sync.Once` 来确保某些操作只执行一次（例如优雅关闭），使用 `sync.Pool` 来复用对象，减少内存分配。
* **反射 (Reflection):** 在 `http2errno` 函数中使用了反射来获取错误的底层 uintptr，但这在代码注释中被标记为 TODO，未来可能会使用 build tags 来替代。

**Go 代码举例说明:**

假设我们接收到一个 HEADERS 帧，`processFrame` 方法会调用 `processHeaders` (代码未包含在当前片段中) 来处理该帧，可能会创建一个新的 `http2stream` 对象来表示这个新的 HTTP/2 流。

```go
// 假设的 processHeaders 函数 (未在代码片段中)
func (sc *http2serverConn) processHeaders(frame *http2MetaHeadersFrame) error {
	sc.serveG.check()

	streamID := frame.Header().StreamID
	state, _ := sc.state(streamID)

	if state == http2stateIdle {
		// 创建新的流
		stream := &http2stream{
			sc:  sc,
			id:  streamID,
			// ... 初始化其他字段
		}
		sc.streams[streamID] = stream
		// ... 其他处理逻辑，例如解析头部，创建 http.Request 等
		fmt.Printf("接收到 Stream ID 为 %d 的 HEADERS 帧\n", streamID)
		return nil
	} else {
		fmt.Printf("接收到 Stream ID 为 %d 的 HEADERS 帧，但流状态不是 idle\n", streamID)
		// ... 处理非 idle 状态的 HEADERS 帧
		return nil
	}
}

// 假设的输入: 一个 Stream ID 为 5 的 HEADERS 帧
// 假设的输出: "接收到 Stream ID 为 5 的 HEADERS 帧" (如果流 5 之前不存在)
```

**命令行参数处理:**

这段代码本身没有直接处理命令行参数。HTTP/2 的配置通常是通过 `http.Server` 结构体的字段或者 `http2.ConfigureServer` 函数进行配置，而不是通过命令行参数。

**使用者易犯错的点:**

这段代码是 `net/http` 包的内部实现，普通使用者不会直接操作这些结构体和方法。但是，理解其背后的原理对于排查 HTTP/2 相关的问题很有帮助。

* **不理解 HTTP/2 的流状态:**  容易在不正确的流状态下尝试发送帧，例如在流已经关闭后尝试写入数据。
* **不理解流量控制:**  可能会因为发送过多数据而导致连接或流被阻塞。
* **不理解连接生命周期:**  可能会在连接已经进入 GO_AWAY 状态后仍然尝试创建新的流。
* **在高并发场景下不当使用连接池:** 虽然代码本身没有直接涉及连接池，但在实际应用中，不当的连接池管理可能导致性能问题。

**功能归纳:**

这段代码主要实现了 Go 语言 `net/http` 包中 HTTP/2 服务器连接的核心管理和处理逻辑。它负责接收和发送 HTTP/2 帧，管理连接和流的状态，处理连接生命周期，以及提供错误处理和日志记录等功能。它是 HTTP/2 服务器实现的关键组成部分，为上层 `net/http` 包提供了底层的 HTTP/2 连接处理能力。

Prompt: 
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共13部分，请归纳一下它的功能

"""
dler ending nils out the
// responseWriter's state field.
type http2stream struct {
	// immutable:
	sc        *http2serverConn
	id        uint32
	body      *http2pipe       // non-nil if expecting DATA frames
	cw        http2closeWaiter // closed wait stream transitions to closed state
	ctx       context.Context
	cancelCtx func()

	// owned by serverConn's serve loop:
	bodyBytes        int64        // body bytes seen so far
	declBodyBytes    int64        // or -1 if undeclared
	flow             http2outflow // limits writing from Handler to client
	inflow           http2inflow  // what the client is allowed to POST/etc to us
	state            http2streamState
	resetQueued      bool       // RST_STREAM queued for write; set by sc.resetStream
	gotTrailerHeader bool       // HEADER frame for trailers was seen
	wroteHeaders     bool       // whether we wrote headers (not status 100)
	readDeadline     http2timer // nil if unused
	writeDeadline    http2timer // nil if unused
	closeErr         error      // set before cw is closed

	trailer    Header // accumulated trailers
	reqTrailer Header // handler's Request.Trailer
}

func (sc *http2serverConn) Framer() *http2Framer { return sc.framer }

func (sc *http2serverConn) CloseConn() error { return sc.conn.Close() }

func (sc *http2serverConn) Flush() error { return sc.bw.Flush() }

func (sc *http2serverConn) HeaderEncoder() (*hpack.Encoder, *bytes.Buffer) {
	return sc.hpackEncoder, &sc.headerWriteBuf
}

func (sc *http2serverConn) state(streamID uint32) (http2streamState, *http2stream) {
	sc.serveG.check()
	// http://tools.ietf.org/html/rfc7540#section-5.1
	if st, ok := sc.streams[streamID]; ok {
		return st.state, st
	}
	// "The first use of a new stream identifier implicitly closes all
	// streams in the "idle" state that might have been initiated by
	// that peer with a lower-valued stream identifier. For example, if
	// a client sends a HEADERS frame on stream 7 without ever sending a
	// frame on stream 5, then stream 5 transitions to the "closed"
	// state when the first frame for stream 7 is sent or received."
	if streamID%2 == 1 {
		if streamID <= sc.maxClientStreamID {
			return http2stateClosed, nil
		}
	} else {
		if streamID <= sc.maxPushPromiseID {
			return http2stateClosed, nil
		}
	}
	return http2stateIdle, nil
}

// setConnState calls the net/http ConnState hook for this connection, if configured.
// Note that the net/http package does StateNew and StateClosed for us.
// There is currently no plan for StateHijacked or hijacking HTTP/2 connections.
func (sc *http2serverConn) setConnState(state ConnState) {
	if sc.hs.ConnState != nil {
		sc.hs.ConnState(sc.conn, state)
	}
}

func (sc *http2serverConn) vlogf(format string, args ...interface{}) {
	if http2VerboseLogs {
		sc.logf(format, args...)
	}
}

func (sc *http2serverConn) logf(format string, args ...interface{}) {
	if lg := sc.hs.ErrorLog; lg != nil {
		lg.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// errno returns v's underlying uintptr, else 0.
//
// TODO: remove this helper function once http2 can use build
// tags. See comment in isClosedConnError.
func http2errno(v error) uintptr {
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Uintptr {
		return uintptr(rv.Uint())
	}
	return 0
}

// isClosedConnError reports whether err is an error from use of a closed
// network connection.
func http2isClosedConnError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, net.ErrClosed) {
		return true
	}

	// TODO(bradfitz): x/tools/cmd/bundle doesn't really support
	// build tags, so I can't make an http2_windows.go file with
	// Windows-specific stuff. Fix that and move this, once we
	// have a way to bundle this into std's net/http somehow.
	if runtime.GOOS == "windows" {
		if oe, ok := err.(*net.OpError); ok && oe.Op == "read" {
			if se, ok := oe.Err.(*os.SyscallError); ok && se.Syscall == "wsarecv" {
				const WSAECONNABORTED = 10053
				const WSAECONNRESET = 10054
				if n := http2errno(se.Err); n == WSAECONNRESET || n == WSAECONNABORTED {
					return true
				}
			}
		}
	}
	return false
}

func (sc *http2serverConn) condlogf(err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF || http2isClosedConnError(err) || err == http2errPrefaceTimeout {
		// Boring, expected errors.
		sc.vlogf(format, args...)
	} else {
		sc.logf(format, args...)
	}
}

// maxCachedCanonicalHeadersKeysSize is an arbitrarily-chosen limit on the size
// of the entries in the canonHeader cache.
// This should be larger than the size of unique, uncommon header keys likely to
// be sent by the peer, while not so high as to permit unreasonable memory usage
// if the peer sends an unbounded number of unique header keys.
const http2maxCachedCanonicalHeadersKeysSize = 2048

func (sc *http2serverConn) canonicalHeader(v string) string {
	sc.serveG.check()
	http2buildCommonHeaderMapsOnce()
	cv, ok := http2commonCanonHeader[v]
	if ok {
		return cv
	}
	cv, ok = sc.canonHeader[v]
	if ok {
		return cv
	}
	if sc.canonHeader == nil {
		sc.canonHeader = make(map[string]string)
	}
	cv = CanonicalHeaderKey(v)
	size := 100 + len(v)*2 // 100 bytes of map overhead + key + value
	if sc.canonHeaderKeysSize+size <= http2maxCachedCanonicalHeadersKeysSize {
		sc.canonHeader[v] = cv
		sc.canonHeaderKeysSize += size
	}
	return cv
}

type http2readFrameResult struct {
	f   http2Frame // valid until readMore is called
	err error

	// readMore should be called once the consumer no longer needs or
	// retains f. After readMore, f is invalid and more frames can be
	// read.
	readMore func()
}

// readFrames is the loop that reads incoming frames.
// It takes care to only read one frame at a time, blocking until the
// consumer is done with the frame.
// It's run on its own goroutine.
func (sc *http2serverConn) readFrames() {
	sc.srv.markNewGoroutine()
	gate := make(chan struct{})
	gateDone := func() { gate <- struct{}{} }
	for {
		f, err := sc.framer.ReadFrame()
		select {
		case sc.readFrameCh <- http2readFrameResult{f, err, gateDone}:
		case <-sc.doneServing:
			return
		}
		select {
		case <-gate:
		case <-sc.doneServing:
			return
		}
		if http2terminalReadFrameError(err) {
			return
		}
	}
}

// frameWriteResult is the message passed from writeFrameAsync to the serve goroutine.
type http2frameWriteResult struct {
	_   http2incomparable
	wr  http2FrameWriteRequest // what was written (or attempted)
	err error                  // result of the writeFrame call
}

// writeFrameAsync runs in its own goroutine and writes a single frame
// and then reports when it's done.
// At most one goroutine can be running writeFrameAsync at a time per
// serverConn.
func (sc *http2serverConn) writeFrameAsync(wr http2FrameWriteRequest, wd *http2writeData) {
	sc.srv.markNewGoroutine()
	var err error
	if wd == nil {
		err = wr.write.writeFrame(sc)
	} else {
		err = sc.framer.endWrite()
	}
	sc.wroteFrameCh <- http2frameWriteResult{wr: wr, err: err}
}

func (sc *http2serverConn) closeAllStreamsOnConnClose() {
	sc.serveG.check()
	for _, st := range sc.streams {
		sc.closeStream(st, http2errClientDisconnected)
	}
}

func (sc *http2serverConn) stopShutdownTimer() {
	sc.serveG.check()
	if t := sc.shutdownTimer; t != nil {
		t.Stop()
	}
}

func (sc *http2serverConn) notePanic() {
	// Note: this is for serverConn.serve panicking, not http.Handler code.
	if http2testHookOnPanicMu != nil {
		http2testHookOnPanicMu.Lock()
		defer http2testHookOnPanicMu.Unlock()
	}
	if http2testHookOnPanic != nil {
		if e := recover(); e != nil {
			if http2testHookOnPanic(sc, e) {
				panic(e)
			}
		}
	}
}

func (sc *http2serverConn) serve(conf http2http2Config) {
	sc.serveG.check()
	defer sc.notePanic()
	defer sc.conn.Close()
	defer sc.closeAllStreamsOnConnClose()
	defer sc.stopShutdownTimer()
	defer close(sc.doneServing) // unblocks handlers trying to send

	if http2VerboseLogs {
		sc.vlogf("http2: server connection from %v on %p", sc.conn.RemoteAddr(), sc.hs)
	}

	settings := http2writeSettings{
		{http2SettingMaxFrameSize, conf.MaxReadFrameSize},
		{http2SettingMaxConcurrentStreams, sc.advMaxStreams},
		{http2SettingMaxHeaderListSize, sc.maxHeaderListSize()},
		{http2SettingHeaderTableSize, conf.MaxDecoderHeaderTableSize},
		{http2SettingInitialWindowSize, uint32(sc.initialStreamRecvWindowSize)},
	}
	if !http2disableExtendedConnectProtocol {
		settings = append(settings, http2Setting{http2SettingEnableConnectProtocol, 1})
	}
	sc.writeFrame(http2FrameWriteRequest{
		write: settings,
	})
	sc.unackedSettings++

	// Each connection starts with initialWindowSize inflow tokens.
	// If a higher value is configured, we add more tokens.
	if diff := conf.MaxUploadBufferPerConnection - http2initialWindowSize; diff > 0 {
		sc.sendWindowUpdate(nil, int(diff))
	}

	if err := sc.readPreface(); err != nil {
		sc.condlogf(err, "http2: server: error reading preface from client %v: %v", sc.conn.RemoteAddr(), err)
		return
	}
	// Now that we've got the preface, get us out of the
	// "StateNew" state. We can't go directly to idle, though.
	// Active means we read some data and anticipate a request. We'll
	// do another Active when we get a HEADERS frame.
	sc.setConnState(StateActive)
	sc.setConnState(StateIdle)

	if sc.srv.IdleTimeout > 0 {
		sc.idleTimer = sc.srv.afterFunc(sc.srv.IdleTimeout, sc.onIdleTimer)
		defer sc.idleTimer.Stop()
	}

	if conf.SendPingTimeout > 0 {
		sc.readIdleTimeout = conf.SendPingTimeout
		sc.readIdleTimer = sc.srv.afterFunc(conf.SendPingTimeout, sc.onReadIdleTimer)
		defer sc.readIdleTimer.Stop()
	}

	go sc.readFrames() // closed by defer sc.conn.Close above

	settingsTimer := sc.srv.afterFunc(http2firstSettingsTimeout, sc.onSettingsTimer)
	defer settingsTimer.Stop()

	lastFrameTime := sc.srv.now()
	loopNum := 0
	for {
		loopNum++
		select {
		case wr := <-sc.wantWriteFrameCh:
			if se, ok := wr.write.(http2StreamError); ok {
				sc.resetStream(se)
				break
			}
			sc.writeFrame(wr)
		case res := <-sc.wroteFrameCh:
			sc.wroteFrame(res)
		case res := <-sc.readFrameCh:
			lastFrameTime = sc.srv.now()
			// Process any written frames before reading new frames from the client since a
			// written frame could have triggered a new stream to be started.
			if sc.writingFrameAsync {
				select {
				case wroteRes := <-sc.wroteFrameCh:
					sc.wroteFrame(wroteRes)
				default:
				}
			}
			if !sc.processFrameFromReader(res) {
				return
			}
			res.readMore()
			if settingsTimer != nil {
				settingsTimer.Stop()
				settingsTimer = nil
			}
		case m := <-sc.bodyReadCh:
			sc.noteBodyRead(m.st, m.n)
		case msg := <-sc.serveMsgCh:
			switch v := msg.(type) {
			case func(int):
				v(loopNum) // for testing
			case *http2serverMessage:
				switch v {
				case http2settingsTimerMsg:
					sc.logf("timeout waiting for SETTINGS frames from %v", sc.conn.RemoteAddr())
					return
				case http2idleTimerMsg:
					sc.vlogf("connection is idle")
					sc.goAway(http2ErrCodeNo)
				case http2readIdleTimerMsg:
					sc.handlePingTimer(lastFrameTime)
				case http2shutdownTimerMsg:
					sc.vlogf("GOAWAY close timer fired; closing conn from %v", sc.conn.RemoteAddr())
					return
				case http2gracefulShutdownMsg:
					sc.startGracefulShutdownInternal()
				case http2handlerDoneMsg:
					sc.handlerDone()
				default:
					panic("unknown timer")
				}
			case *http2startPushRequest:
				sc.startPush(v)
			case func(*http2serverConn):
				v(sc)
			default:
				panic(fmt.Sprintf("unexpected type %T", v))
			}
		}

		// If the peer is causing us to generate a lot of control frames,
		// but not reading them from us, assume they are trying to make us
		// run out of memory.
		if sc.queuedControlFrames > http2maxQueuedControlFrames {
			sc.vlogf("http2: too many control frames in send queue, closing connection")
			return
		}

		// Start the shutdown timer after sending a GOAWAY. When sending GOAWAY
		// with no error code (graceful shutdown), don't start the timer until
		// all open streams have been completed.
		sentGoAway := sc.inGoAway && !sc.needToSendGoAway && !sc.writingFrame
		gracefulShutdownComplete := sc.goAwayCode == http2ErrCodeNo && sc.curOpenStreams() == 0
		if sentGoAway && sc.shutdownTimer == nil && (sc.goAwayCode != http2ErrCodeNo || gracefulShutdownComplete) {
			sc.shutDownIn(http2goAwayTimeout)
		}
	}
}

func (sc *http2serverConn) handlePingTimer(lastFrameReadTime time.Time) {
	if sc.pingSent {
		sc.vlogf("timeout waiting for PING response")
		sc.conn.Close()
		return
	}

	pingAt := lastFrameReadTime.Add(sc.readIdleTimeout)
	now := sc.srv.now()
	if pingAt.After(now) {
		// We received frames since arming the ping timer.
		// Reset it for the next possible timeout.
		sc.readIdleTimer.Reset(pingAt.Sub(now))
		return
	}

	sc.pingSent = true
	// Ignore crypto/rand.Read errors: It generally can't fail, and worse case if it does
	// is we send a PING frame containing 0s.
	_, _ = rand.Read(sc.sentPingData[:])
	sc.writeFrame(http2FrameWriteRequest{
		write: &http2writePing{data: sc.sentPingData},
	})
	sc.readIdleTimer.Reset(sc.pingTimeout)
}

type http2serverMessage int

// Message values sent to serveMsgCh.
var (
	http2settingsTimerMsg    = new(http2serverMessage)
	http2idleTimerMsg        = new(http2serverMessage)
	http2readIdleTimerMsg    = new(http2serverMessage)
	http2shutdownTimerMsg    = new(http2serverMessage)
	http2gracefulShutdownMsg = new(http2serverMessage)
	http2handlerDoneMsg      = new(http2serverMessage)
)

func (sc *http2serverConn) onSettingsTimer() { sc.sendServeMsg(http2settingsTimerMsg) }

func (sc *http2serverConn) onIdleTimer() { sc.sendServeMsg(http2idleTimerMsg) }

func (sc *http2serverConn) onReadIdleTimer() { sc.sendServeMsg(http2readIdleTimerMsg) }

func (sc *http2serverConn) onShutdownTimer() { sc.sendServeMsg(http2shutdownTimerMsg) }

func (sc *http2serverConn) sendServeMsg(msg interface{}) {
	sc.serveG.checkNotOn() // NOT
	select {
	case sc.serveMsgCh <- msg:
	case <-sc.doneServing:
	}
}

var http2errPrefaceTimeout = errors.New("timeout waiting for client preface")

// readPreface reads the ClientPreface greeting from the peer or
// returns errPrefaceTimeout on timeout, or an error if the greeting
// is invalid.
func (sc *http2serverConn) readPreface() error {
	if sc.sawClientPreface {
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		// Read the client preface
		buf := make([]byte, len(http2ClientPreface))
		if _, err := io.ReadFull(sc.conn, buf); err != nil {
			errc <- err
		} else if !bytes.Equal(buf, http2clientPreface) {
			errc <- fmt.Errorf("bogus greeting %q", buf)
		} else {
			errc <- nil
		}
	}()
	timer := sc.srv.newTimer(http2prefaceTimeout) // TODO: configurable on *Server?
	defer timer.Stop()
	select {
	case <-timer.C():
		return http2errPrefaceTimeout
	case err := <-errc:
		if err == nil {
			if http2VerboseLogs {
				sc.vlogf("http2: server: client %v said hello", sc.conn.RemoteAddr())
			}
		}
		return err
	}
}

var http2errChanPool = sync.Pool{
	New: func() interface{} { return make(chan error, 1) },
}

var http2writeDataPool = sync.Pool{
	New: func() interface{} { return new(http2writeData) },
}

// writeDataFromHandler writes DATA response frames from a handler on
// the given stream.
func (sc *http2serverConn) writeDataFromHandler(stream *http2stream, data []byte, endStream bool) error {
	ch := http2errChanPool.Get().(chan error)
	writeArg := http2writeDataPool.Get().(*http2writeData)
	*writeArg = http2writeData{stream.id, data, endStream}
	err := sc.writeFrameFromHandler(http2FrameWriteRequest{
		write:  writeArg,
		stream: stream,
		done:   ch,
	})
	if err != nil {
		return err
	}
	var frameWriteDone bool // the frame write is done (successfully or not)
	select {
	case err = <-ch:
		frameWriteDone = true
	case <-sc.doneServing:
		return http2errClientDisconnected
	case <-stream.cw:
		// If both ch and stream.cw were ready (as might
		// happen on the final Write after an http.Handler
		// ends), prefer the write result. Otherwise this
		// might just be us successfully closing the stream.
		// The writeFrameAsync and serve goroutines guarantee
		// that the ch send will happen before the stream.cw
		// close.
		select {
		case err = <-ch:
			frameWriteDone = true
		default:
			return http2errStreamClosed
		}
	}
	http2errChanPool.Put(ch)
	if frameWriteDone {
		http2writeDataPool.Put(writeArg)
	}
	return err
}

// writeFrameFromHandler sends wr to sc.wantWriteFrameCh, but aborts
// if the connection has gone away.
//
// This must not be run from the serve goroutine itself, else it might
// deadlock writing to sc.wantWriteFrameCh (which is only mildly
// buffered and is read by serve itself). If you're on the serve
// goroutine, call writeFrame instead.
func (sc *http2serverConn) writeFrameFromHandler(wr http2FrameWriteRequest) error {
	sc.serveG.checkNotOn() // NOT
	select {
	case sc.wantWriteFrameCh <- wr:
		return nil
	case <-sc.doneServing:
		// Serve loop is gone.
		// Client has closed their connection to the server.
		return http2errClientDisconnected
	}
}

// writeFrame schedules a frame to write and sends it if there's nothing
// already being written.
//
// There is no pushback here (the serve goroutine never blocks). It's
// the http.Handlers that block, waiting for their previous frames to
// make it onto the wire
//
// If you're not on the serve goroutine, use writeFrameFromHandler instead.
func (sc *http2serverConn) writeFrame(wr http2FrameWriteRequest) {
	sc.serveG.check()

	// If true, wr will not be written and wr.done will not be signaled.
	var ignoreWrite bool

	// We are not allowed to write frames on closed streams. RFC 7540 Section
	// 5.1.1 says: "An endpoint MUST NOT send frames other than PRIORITY on
	// a closed stream." Our server never sends PRIORITY, so that exception
	// does not apply.
	//
	// The serverConn might close an open stream while the stream's handler
	// is still running. For example, the server might close a stream when it
	// receives bad data from the client. If this happens, the handler might
	// attempt to write a frame after the stream has been closed (since the
	// handler hasn't yet been notified of the close). In this case, we simply
	// ignore the frame. The handler will notice that the stream is closed when
	// it waits for the frame to be written.
	//
	// As an exception to this rule, we allow sending RST_STREAM after close.
	// This allows us to immediately reject new streams without tracking any
	// state for those streams (except for the queued RST_STREAM frame). This
	// may result in duplicate RST_STREAMs in some cases, but the client should
	// ignore those.
	if wr.StreamID() != 0 {
		_, isReset := wr.write.(http2StreamError)
		if state, _ := sc.state(wr.StreamID()); state == http2stateClosed && !isReset {
			ignoreWrite = true
		}
	}

	// Don't send a 100-continue response if we've already sent headers.
	// See golang.org/issue/14030.
	switch wr.write.(type) {
	case *http2writeResHeaders:
		wr.stream.wroteHeaders = true
	case http2write100ContinueHeadersFrame:
		if wr.stream.wroteHeaders {
			// We do not need to notify wr.done because this frame is
			// never written with wr.done != nil.
			if wr.done != nil {
				panic("wr.done != nil for write100ContinueHeadersFrame")
			}
			ignoreWrite = true
		}
	}

	if !ignoreWrite {
		if wr.isControl() {
			sc.queuedControlFrames++
			// For extra safety, detect wraparounds, which should not happen,
			// and pull the plug.
			if sc.queuedControlFrames < 0 {
				sc.conn.Close()
			}
		}
		sc.writeSched.Push(wr)
	}
	sc.scheduleFrameWrite()
}

// startFrameWrite starts a goroutine to write wr (in a separate
// goroutine since that might block on the network), and updates the
// serve goroutine's state about the world, updated from info in wr.
func (sc *http2serverConn) startFrameWrite(wr http2FrameWriteRequest) {
	sc.serveG.check()
	if sc.writingFrame {
		panic("internal error: can only be writing one frame at a time")
	}

	st := wr.stream
	if st != nil {
		switch st.state {
		case http2stateHalfClosedLocal:
			switch wr.write.(type) {
			case http2StreamError, http2handlerPanicRST, http2writeWindowUpdate:
				// RFC 7540 Section 5.1 allows sending RST_STREAM, PRIORITY, and WINDOW_UPDATE
				// in this state. (We never send PRIORITY from the server, so that is not checked.)
			default:
				panic(fmt.Sprintf("internal error: attempt to send frame on a half-closed-local stream: %v", wr))
			}
		case http2stateClosed:
			panic(fmt.Sprintf("internal error: attempt to send frame on a closed stream: %v", wr))
		}
	}
	if wpp, ok := wr.write.(*http2writePushPromise); ok {
		var err error
		wpp.promisedID, err = wpp.allocatePromisedID()
		if err != nil {
			sc.writingFrameAsync = false
			wr.replyToWriter(err)
			return
		}
	}

	sc.writingFrame = true
	sc.needsFrameFlush = true
	if wr.write.staysWithinBuffer(sc.bw.Available()) {
		sc.writingFrameAsync = false
		err := wr.write.writeFrame(sc)
		sc.wroteFrame(http2frameWriteResult{wr: wr, err: err})
	} else if wd, ok := wr.write.(*http2writeData); ok {
		// Encode the frame in the serve goroutine, to ensure we don't have
		// any lingering asynchronous references to data passed to Write.
		// See https://go.dev/issue/58446.
		sc.framer.startWriteDataPadded(wd.streamID, wd.endStream, wd.p, nil)
		sc.writingFrameAsync = true
		go sc.writeFrameAsync(wr, wd)
	} else {
		sc.writingFrameAsync = true
		go sc.writeFrameAsync(wr, nil)
	}
}

// errHandlerPanicked is the error given to any callers blocked in a read from
// Request.Body when the main goroutine panics. Since most handlers read in the
// main ServeHTTP goroutine, this will show up rarely.
var http2errHandlerPanicked = errors.New("http2: handler panicked")

// wroteFrame is called on the serve goroutine with the result of
// whatever happened on writeFrameAsync.
func (sc *http2serverConn) wroteFrame(res http2frameWriteResult) {
	sc.serveG.check()
	if !sc.writingFrame {
		panic("internal error: expected to be already writing a frame")
	}
	sc.writingFrame = false
	sc.writingFrameAsync = false

	if res.err != nil {
		sc.conn.Close()
	}

	wr := res.wr

	if http2writeEndsStream(wr.write) {
		st := wr.stream
		if st == nil {
			panic("internal error: expecting non-nil stream")
		}
		switch st.state {
		case http2stateOpen:
			// Here we would go to stateHalfClosedLocal in
			// theory, but since our handler is done and
			// the net/http package provides no mechanism
			// for closing a ResponseWriter while still
			// reading data (see possible TODO at top of
			// this file), we go into closed state here
			// anyway, after telling the peer we're
			// hanging up on them. We'll transition to
			// stateClosed after the RST_STREAM frame is
			// written.
			st.state = http2stateHalfClosedLocal
			// Section 8.1: a server MAY request that the client abort
			// transmission of a request without error by sending a
			// RST_STREAM with an error code of NO_ERROR after sending
			// a complete response.
			sc.resetStream(http2streamError(st.id, http2ErrCodeNo))
		case http2stateHalfClosedRemote:
			sc.closeStream(st, http2errHandlerComplete)
		}
	} else {
		switch v := wr.write.(type) {
		case http2StreamError:
			// st may be unknown if the RST_STREAM was generated to reject bad input.
			if st, ok := sc.streams[v.StreamID]; ok {
				sc.closeStream(st, v)
			}
		case http2handlerPanicRST:
			sc.closeStream(wr.stream, http2errHandlerPanicked)
		}
	}

	// Reply (if requested) to unblock the ServeHTTP goroutine.
	wr.replyToWriter(res.err)

	sc.scheduleFrameWrite()
}

// scheduleFrameWrite tickles the frame writing scheduler.
//
// If a frame is already being written, nothing happens. This will be called again
// when the frame is done being written.
//
// If a frame isn't being written and we need to send one, the best frame
// to send is selected by writeSched.
//
// If a frame isn't being written and there's nothing else to send, we
// flush the write buffer.
func (sc *http2serverConn) scheduleFrameWrite() {
	sc.serveG.check()
	if sc.writingFrame || sc.inFrameScheduleLoop {
		return
	}
	sc.inFrameScheduleLoop = true
	for !sc.writingFrameAsync {
		if sc.needToSendGoAway {
			sc.needToSendGoAway = false
			sc.startFrameWrite(http2FrameWriteRequest{
				write: &http2writeGoAway{
					maxStreamID: sc.maxClientStreamID,
					code:        sc.goAwayCode,
				},
			})
			continue
		}
		if sc.needToSendSettingsAck {
			sc.needToSendSettingsAck = false
			sc.startFrameWrite(http2FrameWriteRequest{write: http2writeSettingsAck{}})
			continue
		}
		if !sc.inGoAway || sc.goAwayCode == http2ErrCodeNo {
			if wr, ok := sc.writeSched.Pop(); ok {
				if wr.isControl() {
					sc.queuedControlFrames--
				}
				sc.startFrameWrite(wr)
				continue
			}
		}
		if sc.needsFrameFlush {
			sc.startFrameWrite(http2FrameWriteRequest{write: http2flushFrameWriter{}})
			sc.needsFrameFlush = false // after startFrameWrite, since it sets this true
			continue
		}
		break
	}
	sc.inFrameScheduleLoop = false
}

// startGracefulShutdown gracefully shuts down a connection. This
// sends GOAWAY with ErrCodeNo to tell the client we're gracefully
// shutting down. The connection isn't closed until all current
// streams are done.
//
// startGracefulShutdown returns immediately; it does not wait until
// the connection has shut down.
func (sc *http2serverConn) startGracefulShutdown() {
	sc.serveG.checkNotOn() // NOT
	sc.shutdownOnce.Do(func() { sc.sendServeMsg(http2gracefulShutdownMsg) })
}

// After sending GOAWAY with an error code (non-graceful shutdown), the
// connection will close after goAwayTimeout.
//
// If we close the connection immediately after sending GOAWAY, there may
// be unsent data in our kernel receive buffer, which will cause the kernel
// to send a TCP RST on close() instead of a FIN. This RST will abort the
// connection immediately, whether or not the client had received the GOAWAY.
//
// Ideally we should delay for at least 1 RTT + epsilon so the client has
// a chance to read the GOAWAY and stop sending messages. Measuring RTT
// is hard, so we approximate with 1 second. See golang.org/issue/18701.
//
// This is a var so it can be shorter in tests, where all requests uses the
// loopback interface making the expected RTT very small.
//
// TODO: configurable?
var http2goAwayTimeout = 1 * time.Second

func (sc *http2serverConn) startGracefulShutdownInternal() {
	sc.goAway(http2ErrCodeNo)
}

func (sc *http2serverConn) goAway(code http2ErrCode) {
	sc.serveG.check()
	if sc.inGoAway {
		if sc.goAwayCode == http2ErrCodeNo {
			sc.goAwayCode = code
		}
		return
	}
	sc.inGoAway = true
	sc.needToSendGoAway = true
	sc.goAwayCode = code
	sc.scheduleFrameWrite()
}

func (sc *http2serverConn) shutDownIn(d time.Duration) {
	sc.serveG.check()
	sc.shutdownTimer = sc.srv.afterFunc(d, sc.onShutdownTimer)
}

func (sc *http2serverConn) resetStream(se http2StreamError) {
	sc.serveG.check()
	sc.writeFrame(http2FrameWriteRequest{write: se})
	if st, ok := sc.streams[se.StreamID]; ok {
		st.resetQueued = true
	}
}

// processFrameFromReader processes the serve loop's read from readFrameCh from the
// frame-reading goroutine.
// processFrameFromReader returns whether the connection should be kept open.
func (sc *http2serverConn) processFrameFromReader(res http2readFrameResult) bool {
	sc.serveG.check()
	err := res.err
	if err != nil {
		if err == http2ErrFrameTooLarge {
			sc.goAway(http2ErrCodeFrameSize)
			return true // goAway will close the loop
		}
		clientGone := err == io.EOF || err == io.ErrUnexpectedEOF || http2isClosedConnError(err)
		if clientGone {
			// TODO: could we also get into this state if
			// the peer does a half close
			// (e.g. CloseWrite) because they're done
			// sending frames but they're still wanting
			// our open replies?  Investigate.
			// TODO: add CloseWrite to crypto/tls.Conn first
			// so we have a way to test this? I suppose
			// just for testing we could have a non-TLS mode.
			return false
		}
	} else {
		f := res.f
		if http2VerboseLogs {
			sc.vlogf("http2: server read frame %v", http2summarizeFrame(f))
		}
		err = sc.processFrame(f)
		if err == nil {
			return true
		}
	}

	switch ev := err.(type) {
	case http2StreamError:
		sc.resetStream(ev)
		return true
	case http2goAwayFlowError:
		sc.goAway(http2ErrCodeFlowControl)
		return true
	case http2ConnectionError:
		if res.f != nil {
			if id := res.f.Header().StreamID; id > sc.maxClientStreamID {
				sc.maxClientStreamID = id
			}
		}
		sc.logf("http2: server connection error from %v: %v", sc.conn.RemoteAddr(), ev)
		sc.goAway(http2ErrCode(ev))
		return true // goAway will handle shutdown
	default:
		if res.err != nil {
			sc.vlogf("http2: server closing client connection; error reading frame from client %s: %v", sc.conn.RemoteAddr(), err)
		} else {
			sc.logf("http2: server closing client connection: %v", err)
		}
		return false
	}
}

func (sc *http2serverConn) processFrame(f http2Frame) error {
	sc.serveG.check()

	// First frame received must be SETTINGS.
	if !sc.sawFirstSettings {
		if _, ok := f.(*http2SettingsFrame); !ok {
			return sc.countError("first_settings", http2ConnectionError(http2ErrCodeProtocol))
		}
		sc.sawFirstSettings = true
	}

	// Discard frames for streams initiated after the identified last
	// stream sent in a GOAWAY, or all frames after sending an error.
	// We still need to return connection-level flow control for DATA frames.
	// RFC 9113 Section 6.8.
	if sc.inGoAway && (sc.goAwayCode != http2ErrCodeNo || f.Header().StreamID > sc.maxClientStreamID) {

		if f, ok := f.(*http2DataFrame); ok {
			if !sc.inflow.take(f.Length) {
				return sc.countError("data_flow", http2streamError(f.Header().StreamID, http2ErrCodeFlowControl))
			}
			sc.sendWindowUpdate(nil, int(f.Length)) // conn-level
		}
		return nil
	}

	switch f := f.(type) {
	case *http2SettingsFrame:
		return sc.processSettings(f)
	case *http2MetaHeadersFrame:
		return sc.processHeaders(f)
	case *http2WindowUpdateFrame:
		return sc.processWindowUpdate(f)
	case *http2PingFrame:
		return sc.processPing(f)
	case *http2DataFrame:
		return sc.processData(f)
	case *http2RSTStreamFrame:
		return sc.processResetStream(f)
	case *http2PriorityFrame:
		return sc.processPriority(f)
	case *http2GoAwayFrame:
		return sc.processGoAway(f)
	case *http2PushPromiseFrame:
		// A client cannot push. Thus, servers MUST treat the receipt of a PUSH_PROMISE
		// frame as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
		return sc.countError("push_promise", http2ConnectionError(http2ErrCodeProtocol))
	default:
		sc.vlogf("http2: server ignoring frame: %v", f.Header())
		return nil
	}
}

func (sc *http2serverConn) processPing(f *http2PingFrame) error {
	sc.serveG.check()
	if f.IsAck() {
		if sc.pingSent && sc.sentPingData == f.Data {
			// This is a response to a PING we sent.
			sc.pingSent = false
			sc.readIdleTimer.Reset(sc.readIdleTimeout)
		}
		// 6.7 PING: " An endpoint MUST NOT respond to PING frames
		// containing this flag."
		return nil
	}
	if f.StreamID != 0 {
		// "PING frames are not associated with any individual
		// stream. If a PING frame is received with a stream
		// identifier field value other than 0x0, the recipient MUST
		// respond with a connection error (Section 5.4.1) of type
		// PROTOCOL_ERROR."
		return sc.countError("ping_on_stream", http2ConnectionError(http2ErrCodeProtocol))
	}
	sc.writeFrame(http2FrameWriteRequest{write: http2writePingAck{f}})
	return nil
}

func (sc *http2serverConn) processWindowUpdate(f *http2WindowUpdateFrame) error {
	sc.serveG.check()
	switch {
	case f.StreamID != 0: // stream-level flow control
		state, st := sc.state(f.StreamID)
		if state == http2stateIdle {
			// Section 5.1: "Receiving any frame other than HEADERS
			// or PRIORITY on a stream in this state MUST be
			// treated as a connection error (Section 5.4.1) of
			// type PROTOCOL_ERROR."
			return sc.countError("stream_idle", http2ConnectionError(http2ErrCodeProtocol))
		}
		if st == nil {
			// "WINDOW_UPDATE can be sent by a peer that has sent a
			// frame bearing the END_STREAM flag. This means that a
			// receiver could receive a WINDOW_UPDATE frame on a "half
			// closed (remote)" or "closed" stream. A receiver MUST
			// NOT treat this as an error, see Section 5.1."
			return nil
		}
		if !st.flow.add(int32(f.Increment)) {
			return sc.countError("bad_flow", http2streamError(f.StreamID, http2ErrCodeFlowControl))
		}
	default: // connection-level flow control
		if !sc.flow.add(int32(f.Increment)) {
			return http2goAwayFlowError{}
		}
	}
	sc.scheduleFrameWrite()
	return nil
}

func (sc *http2serverConn) processResetStream(f *http2RSTStreamFrame) error {
	sc.serveG.check()

	state, st := sc.state(f.StreamID)
	if state 
"""




```