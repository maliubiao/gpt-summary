Response:
The user wants a summary of the functionality of the provided Go code snippet.
This snippet seems to be a part of the HTTP/2 implementation in the `net/http` package.

Here's a breakdown of the code and its purpose:

1. **Constants and Pools:** Defines constants like `http2bufWriterPoolBufferSize` and uses `sync.Pool` for efficient allocation and reuse of `bufio.Writer` instances.
2. **`http2bufferedWriter`:** Implements a buffered writer that utilizes the `sync.Pool` for underlying `bufio.Writer`. It provides `Available`, `Write`, and `Flush` methods. The `Flush` method returns the `bufio.Writer` to the pool.
3. **Timeout Writer:**  Introduces `http2bufferedWriterTimeoutWriter` and `http2writeWithByteTimeout` to implement a byte-level timeout for write operations. This ensures that a write operation doesn't block indefinitely if no bytes are being written.
4. **Utilities:** Includes utility functions like `http2mustUint31` for range checking and `http2bodyAllowedForStatus` to determine if a given HTTP status code allows a response body.
5. **Error Handling:** Defines a custom error type `http2httpError` that includes information about timeouts.
6. **Header Sorting:** Uses `sync.Pool` for a `http2sorter` to efficiently sort HTTP headers.
7. **Path Validation:** Provides `http2validPseudoPath` to validate the `:path` pseudo-header in HTTP/2 requests.
8. **Non-Comparable Type:** Defines `http2incomparable` to make structs non-comparable.
9. **Synchronization Interface:** Defines `http2synctestGroupInterface` for testing purposes, allowing mocking of time-related functions.
10. **`http2pipe`:** Implements a goroutine-safe in-memory pipe for communication between different parts of the HTTP/2 implementation. It supports buffered writing and error handling.
11. **Constants:** Defines various constants related to timeouts, buffer sizes, and default limits for HTTP/2 connections.
12. **Error Variables:** Defines common error variables specific to the HTTP/2 implementation.
13. **`http2responseWriterStatePool`:** Uses a `sync.Pool` to manage the state of response writers.
14. **Test Hooks:** Defines variables for test hooks to inject behavior during testing.
15. **`http2Server`:** Represents the HTTP/2 server configuration and state. It includes options like maximum concurrent streams, timeouts, and error handling.
16. **Server Internal State:** Defines `http2serverInternalState` to manage active connections in the server.
17. **`http2ConfigureServer`:**  Configures a standard `net/http.Server` to support HTTP/2. This involves setting up TLS configurations and the `TLSNextProto` map.
18. **`http2ServeConnOpts`:** Defines options for serving an HTTP/2 connection.
19. **`ServeConn`:** The core function for handling an HTTP/2 connection. It initializes the `http2serverConn` and starts the serving process.
20. **`http2serverConnBaseContext`:** Creates the base context for an HTTP/2 connection.
21. **`rejectConn`:** A helper function to reject a connection by sending a GOAWAY frame.
22. **`http2serverConn`:** Represents the state of a single HTTP/2 connection. This includes information about streams, flow control, and timeouts.
23. **Helper functions for `http2serverConn`:** Includes `maxHeaderListSize` and `curOpenStreams` to get information about the connection state.
24. **Stream Representation:**  A comment indicating that the `stream` struct (defined elsewhere) holds minimal metadata for the serve goroutine.

**Overall Functionality:** This code snippet implements the core mechanisms for handling HTTP/2 connections in Go's `net/http` package. It deals with buffering, timeouts, connection management, error handling, and configuration of the HTTP/2 server.
这是 `go/src/net/http/h2_bundle.go` 文件的一部分，主要负责 **HTTP/2 服务器连接的处理和生命周期管理**。

**具体功能归纳如下：**

1. **高效的缓冲写入:**  通过 `sync.Pool` 管理 `bufio.Writer`，实现了高效的缓冲写入机制，减少了内存分配和 GC 压力。`http2bufferedWriter` 封装了这一逻辑，用于向底层的 `net.Conn` 写入数据。
2. **基于字节的写入超时控制:** 引入了 `http2writeWithByteTimeout` 函数，实现了更精细的写入超时控制。如果一段时间内没有任何字节写入到连接，则写入操作会失败，防止因网络问题导致的永久阻塞。
3. **HTTP 状态码的校验:** 提供了 `http2bodyAllowedForStatus` 函数，用于判断给定的 HTTP 状态码是否允许包含响应体，遵循 RFC 7230 的规范。
4. **自定义错误类型:** 定义了 `http2httpError` 结构体，用于表示 HTTP/2 相关的错误，并实现了 `Timeout()` 和 `Temporary()` 方法，方便错误处理。
5. **HTTP 头部排序优化:** 使用 `sync.Pool` 管理 `http2sorter`，用于高效地对 HTTP 头部进行排序，这在某些场景下（例如构建 canonical header）是必要的。
6. **HTTP/2 路径校验:**  `http2validPseudoPath` 函数用于校验 HTTP/2 的 `:path` 伪头部是否合法。
7. **并发控制接口:** 定义了 `http2synctestGroupInterface`，这是一个用于测试的接口，允许在测试环境下模拟并发和时间。
8. **线程安全的管道:**  实现了 `http2pipe` 结构体，这是一个线程安全的 `io.Reader`/`io.Writer` 对，用于在不同的 Goroutine 之间进行数据传递。
9. **HTTP/2 服务器配置:** 定义了 `http2Server` 结构体，用于存储 HTTP/2 服务器的配置信息，例如最大并发流、各种超时时间等。
10. **`net/http.Server` 的 HTTP/2 配置:** 提供了 `http2ConfigureServer` 函数，用于将 HTTP/2 支持添加到标准的 `net/http.Server`。它会配置 TLS 设置 (`NextProtos`)，并注册 HTTP/2 的处理函数。
11. **HTTP/2 连接服务:**  `ServeConn` 方法是处理 HTTP/2 连接的核心入口。它负责初始化连接状态 (`http2serverConn`)，处理客户端的连接前言 (preface) 和设置 (SETTINGS) 帧，并启动连接的服务循环。
12. **HTTP/2 连接状态管理:** `http2serverConn` 结构体维护了单个 HTTP/2 连接的所有状态信息，包括流管理、流量控制、帧读写、超时控制等。
13. **连接拒绝机制:**  `rejectConn` 函数用于拒绝连接，并发送 GOAWAY 帧给客户端。

**它是什么go语言功能的实现？**

这段代码主要实现了以下 Go 语言功能的应用：

*   **`sync.Pool`:** 用于对象池，提高对象分配和回收的效率，例如 `bufio.Writer` 和 header sorter。
*   **`io.Reader` 和 `io.Writer` 接口:**  `http2bufferedWriter` 和 `http2pipe` 实现了这些接口，用于数据读写。
*   **`net.Conn` 接口:**  直接操作底层的网络连接。
*   **`time` 包:** 用于实现各种超时控制。
*   **`sync` 包:** 用于实现并发控制，例如 `sync.Mutex` 和 `sync.Cond`。
*   **`errors` 包:** 用于创建和判断错误。
*   **`sort` 包:** 用于排序 HTTP 头部。
*   **`context` 包:** 用于传递请求上下文信息。
*   **类型嵌入 (Embedding):** `http2bufferedWriterTimeoutWriter` 嵌入了 `http2bufferedWriter`。

**Go 代码举例说明：**

假设我们有一个 HTTP/2 服务器在监听，客户端发起了一个连接。以下代码展示了 `http2bufferedWriter` 的使用：

```go
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"
	"errors"
	"os"
	"sync"
)

const http2bufWriterPoolBufferSize = 4 << 10

var http2bufWriterPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewWriterSize(nil, http2bufWriterPoolBufferSize)
	},
}

type http2bufferedWriter struct {
	conn net.Conn
	bw   *bufio.Writer
}

func (w *http2bufferedWriter) Available() int {
	if w.bw == nil {
		return http2bufWriterPoolBufferSize
	}
	return w.bw.Available()
}

func (w *http2bufferedWriter) Write(p []byte) (n int, err error) {
	if w.bw == nil {
		bw := http2bufWriterPool.Get().(*bufio.Writer)
		bw.Reset(w.conn) // 假设 w.conn 已经初始化
		w.bw = bw
	}
	return w.bw.Write(p)
}

func (w *http2bufferedWriter) Flush() error {
	bw := w.bw
	if bw == nil {
		return nil
	}
	err := bw.Flush()
	bw.Reset(nil)
	http2bufWriterPool.Put(bw)
	w.bw = nil
	return err
}

func main() {
	// 假设 conn 是一个已经建立的 net.Conn 连接
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	bufferedWriter := &http2bufferedWriter{conn: conn}

	data := []byte("HTTP/2 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!")
	n, err := bufferedWriter.Write(data)
	fmt.Printf("Written %d bytes, error: %v\n", n, err)

	err = bufferedWriter.Flush()
	fmt.Printf("Flush error: %v\n", err)
}
```

**假设的输入与输出：**

*   **输入:** 客户端连接到服务器，`conn` 代表该连接。
*   **输出:**  服务器通过 `bufferedWriter` 将 HTTP/2 响应数据写入到 `conn`。控制台输出类似：
    ```
    Written 68 bytes, error: <nil>
    Flush error: <nil>
    ```

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。HTTP/2 服务器的配置通常通过 `http2Server` 结构体的字段进行，这些字段可以在创建 `http2Server` 实例时设置，或者通过 `http2ConfigureServer` 函数应用到 `net/http.Server`。`net/http.Server` 的监听地址等参数通常通过 `net/http` 包的函数（例如 `http.ListenAndServe`）处理。

**使用者易犯错的点：**

*   **不正确的 TLS 配置:**  HTTP/2 强制要求 TLS 1.2 或更高版本，并且对使用的密码套件有要求。开发者容易忘记配置正确的 TLS 设置，导致连接失败。例如，如果 `TLSConfig.MinVersion` 小于 `tls.VersionTLS12`，或者 `TLSConfig.CipherSuites` 中缺少必要的密码套件，`http2ConfigureServer` 会返回错误。
*   **忘记调用 `http2ConfigureServer`:**  在使用 HTTP/2 之前，必须调用 `http2ConfigureServer` 来配置 `net/http.Server`。如果忘记调用，服务器将无法处理 HTTP/2 连接。
*   **在连接建立后修改配置:**  `http2Server` 的配置需要在服务器开始监听之前完成。在连接建立之后修改配置可能不会生效，或者导致不可预测的行为。
*   **对 `http2pipe` 的不当使用:** `http2pipe` 需要先通过 `setBuffer` 初始化缓冲区才能进行写入。如果直接调用 `Write` 而未初始化，会返回 `http2errUninitializedPipeWrite` 错误。

这段代码是 HTTP/2 服务器实现的关键部分，负责底层的连接管理和数据传输，为上层 HTTP 请求处理提供了基础。

### 提示词
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
ated using bufWriterPool.
//
// TODO: pick a less arbitrary value? this is a bit under
// (3 x typical 1500 byte MTU) at least. Other than that,
// not much thought went into it.
const http2bufWriterPoolBufferSize = 4 << 10

var http2bufWriterPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewWriterSize(nil, http2bufWriterPoolBufferSize)
	},
}

func (w *http2bufferedWriter) Available() int {
	if w.bw == nil {
		return http2bufWriterPoolBufferSize
	}
	return w.bw.Available()
}

func (w *http2bufferedWriter) Write(p []byte) (n int, err error) {
	if w.bw == nil {
		bw := http2bufWriterPool.Get().(*bufio.Writer)
		bw.Reset((*http2bufferedWriterTimeoutWriter)(w))
		w.bw = bw
	}
	return w.bw.Write(p)
}

func (w *http2bufferedWriter) Flush() error {
	bw := w.bw
	if bw == nil {
		return nil
	}
	err := bw.Flush()
	bw.Reset(nil)
	http2bufWriterPool.Put(bw)
	w.bw = nil
	return err
}

type http2bufferedWriterTimeoutWriter http2bufferedWriter

func (w *http2bufferedWriterTimeoutWriter) Write(p []byte) (n int, err error) {
	return http2writeWithByteTimeout(w.group, w.conn, w.byteTimeout, p)
}

// writeWithByteTimeout writes to conn.
// If more than timeout passes without any bytes being written to the connection,
// the write fails.
func http2writeWithByteTimeout(group http2synctestGroupInterface, conn net.Conn, timeout time.Duration, p []byte) (n int, err error) {
	if timeout <= 0 {
		return conn.Write(p)
	}
	for {
		var now time.Time
		if group == nil {
			now = time.Now()
		} else {
			now = group.Now()
		}
		conn.SetWriteDeadline(now.Add(timeout))
		nn, err := conn.Write(p[n:])
		n += nn
		if n == len(p) || nn == 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			// Either we finished the write, made no progress, or hit the deadline.
			// Whichever it is, we're done now.
			conn.SetWriteDeadline(time.Time{})
			return n, err
		}
	}
}

func http2mustUint31(v int32) uint32 {
	if v < 0 || v > 2147483647 {
		panic("out of range")
	}
	return uint32(v)
}

// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 7230, section 3.3.
func http2bodyAllowedForStatus(status int) bool {
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

type http2httpError struct {
	_       http2incomparable
	msg     string
	timeout bool
}

func (e *http2httpError) Error() string { return e.msg }

func (e *http2httpError) Timeout() bool { return e.timeout }

func (e *http2httpError) Temporary() bool { return true }

var http2errTimeout error = &http2httpError{msg: "http2: timeout awaiting response headers", timeout: true}

type http2connectionStater interface {
	ConnectionState() tls.ConnectionState
}

var http2sorterPool = sync.Pool{New: func() interface{} { return new(http2sorter) }}

type http2sorter struct {
	v []string // owned by sorter
}

func (s *http2sorter) Len() int { return len(s.v) }

func (s *http2sorter) Swap(i, j int) { s.v[i], s.v[j] = s.v[j], s.v[i] }

func (s *http2sorter) Less(i, j int) bool { return s.v[i] < s.v[j] }

// Keys returns the sorted keys of h.
//
// The returned slice is only valid until s used again or returned to
// its pool.
func (s *http2sorter) Keys(h Header) []string {
	keys := s.v[:0]
	for k := range h {
		keys = append(keys, k)
	}
	s.v = keys
	sort.Sort(s)
	return keys
}

func (s *http2sorter) SortStrings(ss []string) {
	// Our sorter works on s.v, which sorter owns, so
	// stash it away while we sort the user's buffer.
	save := s.v
	s.v = ss
	sort.Sort(s)
	s.v = save
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//   - a non-empty string starting with '/'
//   - the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func http2validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

// incomparable is a zero-width, non-comparable type. Adding it to a struct
// makes that struct also non-comparable, and generally doesn't add
// any size (as long as it's first).
type http2incomparable [0]func()

// synctestGroupInterface is the methods of synctestGroup used by Server and Transport.
// It's defined as an interface here to let us keep synctestGroup entirely test-only
// and not a part of non-test builds.
type http2synctestGroupInterface interface {
	Join()
	Now() time.Time
	NewTimer(d time.Duration) http2timer
	AfterFunc(d time.Duration, f func()) http2timer
	ContextWithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc)
}

// pipe is a goroutine-safe io.Reader/io.Writer pair. It's like
// io.Pipe except there are no PipeReader/PipeWriter halves, and the
// underlying buffer is an interface. (io.Pipe is always unbuffered)
type http2pipe struct {
	mu       sync.Mutex
	c        sync.Cond       // c.L lazily initialized to &p.mu
	b        http2pipeBuffer // nil when done reading
	unread   int             // bytes unread when done
	err      error           // read error once empty. non-nil means closed.
	breakErr error           // immediate read error (caller doesn't see rest of b)
	donec    chan struct{}   // closed on error
	readFn   func()          // optional code to run in Read before error
}

type http2pipeBuffer interface {
	Len() int
	io.Writer
	io.Reader
}

// setBuffer initializes the pipe buffer.
// It has no effect if the pipe is already closed.
func (p *http2pipe) setBuffer(b http2pipeBuffer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.breakErr != nil {
		return
	}
	p.b = b
}

func (p *http2pipe) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.b == nil {
		return p.unread
	}
	return p.b.Len()
}

// Read waits until data is available and copies bytes
// from the buffer into p.
func (p *http2pipe) Read(d []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	for {
		if p.breakErr != nil {
			return 0, p.breakErr
		}
		if p.b != nil && p.b.Len() > 0 {
			return p.b.Read(d)
		}
		if p.err != nil {
			if p.readFn != nil {
				p.readFn()     // e.g. copy trailers
				p.readFn = nil // not sticky like p.err
			}
			p.b = nil
			return 0, p.err
		}
		p.c.Wait()
	}
}

var (
	http2errClosedPipeWrite        = errors.New("write on closed buffer")
	http2errUninitializedPipeWrite = errors.New("write on uninitialized buffer")
)

// Write copies bytes from p into the buffer and wakes a reader.
// It is an error to write more data than the buffer can hold.
func (p *http2pipe) Write(d []byte) (n int, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	defer p.c.Signal()
	if p.err != nil || p.breakErr != nil {
		return 0, http2errClosedPipeWrite
	}
	// pipe.setBuffer is never invoked, leaving the buffer uninitialized.
	// We shouldn't try to write to an uninitialized pipe,
	// but returning an error is better than panicking.
	if p.b == nil {
		return 0, http2errUninitializedPipeWrite
	}
	return p.b.Write(d)
}

// CloseWithError causes the next Read (waking up a current blocked
// Read if needed) to return the provided err after all data has been
// read.
//
// The error must be non-nil.
func (p *http2pipe) CloseWithError(err error) { p.closeWithError(&p.err, err, nil) }

// BreakWithError causes the next Read (waking up a current blocked
// Read if needed) to return the provided err immediately, without
// waiting for unread data.
func (p *http2pipe) BreakWithError(err error) { p.closeWithError(&p.breakErr, err, nil) }

// closeWithErrorAndCode is like CloseWithError but also sets some code to run
// in the caller's goroutine before returning the error.
func (p *http2pipe) closeWithErrorAndCode(err error, fn func()) { p.closeWithError(&p.err, err, fn) }

func (p *http2pipe) closeWithError(dst *error, err error, fn func()) {
	if err == nil {
		panic("err must be non-nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c.L == nil {
		p.c.L = &p.mu
	}
	defer p.c.Signal()
	if *dst != nil {
		// Already been done.
		return
	}
	p.readFn = fn
	if dst == &p.breakErr {
		if p.b != nil {
			p.unread += p.b.Len()
		}
		p.b = nil
	}
	*dst = err
	p.closeDoneLocked()
}

// requires p.mu be held.
func (p *http2pipe) closeDoneLocked() {
	if p.donec == nil {
		return
	}
	// Close if unclosed. This isn't racy since we always
	// hold p.mu while closing.
	select {
	case <-p.donec:
	default:
		close(p.donec)
	}
}

// Err returns the error (if any) first set by BreakWithError or CloseWithError.
func (p *http2pipe) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.breakErr != nil {
		return p.breakErr
	}
	return p.err
}

// Done returns a channel which is closed if and when this pipe is closed
// with CloseWithError.
func (p *http2pipe) Done() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.donec == nil {
		p.donec = make(chan struct{})
		if p.err != nil || p.breakErr != nil {
			// Already hit an error.
			p.closeDoneLocked()
		}
	}
	return p.donec
}

const (
	http2prefaceTimeout        = 10 * time.Second
	http2firstSettingsTimeout  = 2 * time.Second // should be in-flight with preface anyway
	http2handlerChunkWriteSize = 4 << 10
	http2defaultMaxStreams     = 250 // TODO: make this 100 as the GFE seems to?

	// maxQueuedControlFrames is the maximum number of control frames like
	// SETTINGS, PING and RST_STREAM that will be queued for writing before
	// the connection is closed to prevent memory exhaustion attacks.
	http2maxQueuedControlFrames = 10000
)

var (
	http2errClientDisconnected = errors.New("client disconnected")
	http2errClosedBody         = errors.New("body closed by handler")
	http2errHandlerComplete    = errors.New("http2: request body closed due to handler exiting")
	http2errStreamClosed       = errors.New("http2: stream closed")
)

var http2responseWriterStatePool = sync.Pool{
	New: func() interface{} {
		rws := &http2responseWriterState{}
		rws.bw = bufio.NewWriterSize(http2chunkWriter{rws}, http2handlerChunkWriteSize)
		return rws
	},
}

// Test hooks.
var (
	http2testHookOnConn        func()
	http2testHookGetServerConn func(*http2serverConn)
	http2testHookOnPanicMu     *sync.Mutex // nil except in tests
	http2testHookOnPanic       func(sc *http2serverConn, panicVal interface{}) (rePanic bool)
)

// Server is an HTTP/2 server.
type http2Server struct {
	// MaxHandlers limits the number of http.Handler ServeHTTP goroutines
	// which may run at a time over all connections.
	// Negative or zero no limit.
	// TODO: implement
	MaxHandlers int

	// MaxConcurrentStreams optionally specifies the number of
	// concurrent streams that each client may have open at a
	// time. This is unrelated to the number of http.Handler goroutines
	// which may be active globally, which is MaxHandlers.
	// If zero, MaxConcurrentStreams defaults to at least 100, per
	// the HTTP/2 spec's recommendations.
	MaxConcurrentStreams uint32

	// MaxDecoderHeaderTableSize optionally specifies the http2
	// SETTINGS_HEADER_TABLE_SIZE to send in the initial settings frame. It
	// informs the remote endpoint of the maximum size of the header compression
	// table used to decode header blocks, in octets. If zero, the default value
	// of 4096 is used.
	MaxDecoderHeaderTableSize uint32

	// MaxEncoderHeaderTableSize optionally specifies an upper limit for the
	// header compression table used for encoding request headers. Received
	// SETTINGS_HEADER_TABLE_SIZE settings are capped at this limit. If zero,
	// the default value of 4096 is used.
	MaxEncoderHeaderTableSize uint32

	// MaxReadFrameSize optionally specifies the largest frame
	// this server is willing to read. A valid value is between
	// 16k and 16M, inclusive. If zero or otherwise invalid, a
	// default value is used.
	MaxReadFrameSize uint32

	// PermitProhibitedCipherSuites, if true, permits the use of
	// cipher suites prohibited by the HTTP/2 spec.
	PermitProhibitedCipherSuites bool

	// IdleTimeout specifies how long until idle clients should be
	// closed with a GOAWAY frame. PING frames are not considered
	// activity for the purposes of IdleTimeout.
	// If zero or negative, there is no timeout.
	IdleTimeout time.Duration

	// ReadIdleTimeout is the timeout after which a health check using a ping
	// frame will be carried out if no frame is received on the connection.
	// If zero, no health check is performed.
	ReadIdleTimeout time.Duration

	// PingTimeout is the timeout after which the connection will be closed
	// if a response to a ping is not received.
	// If zero, a default of 15 seconds is used.
	PingTimeout time.Duration

	// WriteByteTimeout is the timeout after which a connection will be
	// closed if no data can be written to it. The timeout begins when data is
	// available to write, and is extended whenever any bytes are written.
	// If zero or negative, there is no timeout.
	WriteByteTimeout time.Duration

	// MaxUploadBufferPerConnection is the size of the initial flow
	// control window for each connections. The HTTP/2 spec does not
	// allow this to be smaller than 65535 or larger than 2^32-1.
	// If the value is outside this range, a default value will be
	// used instead.
	MaxUploadBufferPerConnection int32

	// MaxUploadBufferPerStream is the size of the initial flow control
	// window for each stream. The HTTP/2 spec does not allow this to
	// be larger than 2^32-1. If the value is zero or larger than the
	// maximum, a default value will be used instead.
	MaxUploadBufferPerStream int32

	// NewWriteScheduler constructs a write scheduler for a connection.
	// If nil, a default scheduler is chosen.
	NewWriteScheduler func() http2WriteScheduler

	// CountError, if non-nil, is called on HTTP/2 server errors.
	// It's intended to increment a metric for monitoring, such
	// as an expvar or Prometheus metric.
	// The errType consists of only ASCII word characters.
	CountError func(errType string)

	// Internal state. This is a pointer (rather than embedded directly)
	// so that we don't embed a Mutex in this struct, which will make the
	// struct non-copyable, which might break some callers.
	state *http2serverInternalState

	// Synchronization group used for testing.
	// Outside of tests, this is nil.
	group http2synctestGroupInterface
}

func (s *http2Server) markNewGoroutine() {
	if s.group != nil {
		s.group.Join()
	}
}

func (s *http2Server) now() time.Time {
	if s.group != nil {
		return s.group.Now()
	}
	return time.Now()
}

// newTimer creates a new time.Timer, or a synthetic timer in tests.
func (s *http2Server) newTimer(d time.Duration) http2timer {
	if s.group != nil {
		return s.group.NewTimer(d)
	}
	return http2timeTimer{time.NewTimer(d)}
}

// afterFunc creates a new time.AfterFunc timer, or a synthetic timer in tests.
func (s *http2Server) afterFunc(d time.Duration, f func()) http2timer {
	if s.group != nil {
		return s.group.AfterFunc(d, f)
	}
	return http2timeTimer{time.AfterFunc(d, f)}
}

type http2serverInternalState struct {
	mu          sync.Mutex
	activeConns map[*http2serverConn]struct{}
}

func (s *http2serverInternalState) registerConn(sc *http2serverConn) {
	if s == nil {
		return // if the Server was used without calling ConfigureServer
	}
	s.mu.Lock()
	s.activeConns[sc] = struct{}{}
	s.mu.Unlock()
}

func (s *http2serverInternalState) unregisterConn(sc *http2serverConn) {
	if s == nil {
		return // if the Server was used without calling ConfigureServer
	}
	s.mu.Lock()
	delete(s.activeConns, sc)
	s.mu.Unlock()
}

func (s *http2serverInternalState) startGracefulShutdown() {
	if s == nil {
		return // if the Server was used without calling ConfigureServer
	}
	s.mu.Lock()
	for sc := range s.activeConns {
		sc.startGracefulShutdown()
	}
	s.mu.Unlock()
}

// ConfigureServer adds HTTP/2 support to a net/http Server.
//
// The configuration conf may be nil.
//
// ConfigureServer must be called before s begins serving.
func http2ConfigureServer(s *Server, conf *http2Server) error {
	if s == nil {
		panic("nil *http.Server")
	}
	if conf == nil {
		conf = new(http2Server)
	}
	conf.state = &http2serverInternalState{activeConns: make(map[*http2serverConn]struct{})}
	if h1, h2 := s, conf; h2.IdleTimeout == 0 {
		if h1.IdleTimeout != 0 {
			h2.IdleTimeout = h1.IdleTimeout
		} else {
			h2.IdleTimeout = h1.ReadTimeout
		}
	}
	s.RegisterOnShutdown(conf.state.startGracefulShutdown)

	if s.TLSConfig == nil {
		s.TLSConfig = new(tls.Config)
	} else if s.TLSConfig.CipherSuites != nil && s.TLSConfig.MinVersion < tls.VersionTLS13 {
		// If they already provided a TLS 1.0–1.2 CipherSuite list, return an
		// error if it is missing ECDHE_RSA_WITH_AES_128_GCM_SHA256 or
		// ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
		haveRequired := false
		for _, cs := range s.TLSConfig.CipherSuites {
			switch cs {
			case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				// Alternative MTI cipher to not discourage ECDSA-only servers.
				// See http://golang.org/cl/30721 for further information.
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
				haveRequired = true
			}
		}
		if !haveRequired {
			return fmt.Errorf("http2: TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher (need at least one of TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)")
		}
	}

	// Note: not setting MinVersion to tls.VersionTLS12,
	// as we don't want to interfere with HTTP/1.1 traffic
	// on the user's server. We enforce TLS 1.2 later once
	// we accept a connection. Ideally this should be done
	// during next-proto selection, but using TLS <1.2 with
	// HTTP/2 is still the client's bug.

	s.TLSConfig.PreferServerCipherSuites = true

	if !http2strSliceContains(s.TLSConfig.NextProtos, http2NextProtoTLS) {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, http2NextProtoTLS)
	}
	if !http2strSliceContains(s.TLSConfig.NextProtos, "http/1.1") {
		s.TLSConfig.NextProtos = append(s.TLSConfig.NextProtos, "http/1.1")
	}

	if s.TLSNextProto == nil {
		s.TLSNextProto = map[string]func(*Server, *tls.Conn, Handler){}
	}
	protoHandler := func(hs *Server, c net.Conn, h Handler, sawClientPreface bool) {
		if http2testHookOnConn != nil {
			http2testHookOnConn()
		}
		// The TLSNextProto interface predates contexts, so
		// the net/http package passes down its per-connection
		// base context via an exported but unadvertised
		// method on the Handler. This is for internal
		// net/http<=>http2 use only.
		var ctx context.Context
		type baseContexter interface {
			BaseContext() context.Context
		}
		if bc, ok := h.(baseContexter); ok {
			ctx = bc.BaseContext()
		}
		conf.ServeConn(c, &http2ServeConnOpts{
			Context:          ctx,
			Handler:          h,
			BaseConfig:       hs,
			SawClientPreface: sawClientPreface,
		})
	}
	s.TLSNextProto[http2NextProtoTLS] = func(hs *Server, c *tls.Conn, h Handler) {
		protoHandler(hs, c, h, false)
	}
	// The "unencrypted_http2" TLSNextProto key is used to pass off non-TLS HTTP/2 conns.
	//
	// A connection passed in this method has already had the HTTP/2 preface read from it.
	s.TLSNextProto[http2nextProtoUnencryptedHTTP2] = func(hs *Server, c *tls.Conn, h Handler) {
		nc, err := http2unencryptedNetConnFromTLSConn(c)
		if err != nil {
			if lg := hs.ErrorLog; lg != nil {
				lg.Print(err)
			} else {
				log.Print(err)
			}
			go c.Close()
			return
		}
		protoHandler(hs, nc, h, true)
	}
	return nil
}

// ServeConnOpts are options for the Server.ServeConn method.
type http2ServeConnOpts struct {
	// Context is the base context to use.
	// If nil, context.Background is used.
	Context context.Context

	// BaseConfig optionally sets the base configuration
	// for values. If nil, defaults are used.
	BaseConfig *Server

	// Handler specifies which handler to use for processing
	// requests. If nil, BaseConfig.Handler is used. If BaseConfig
	// or BaseConfig.Handler is nil, http.DefaultServeMux is used.
	Handler Handler

	// UpgradeRequest is an initial request received on a connection
	// undergoing an h2c upgrade. The request body must have been
	// completely read from the connection before calling ServeConn,
	// and the 101 Switching Protocols response written.
	UpgradeRequest *Request

	// Settings is the decoded contents of the HTTP2-Settings header
	// in an h2c upgrade request.
	Settings []byte

	// SawClientPreface is set if the HTTP/2 connection preface
	// has already been read from the connection.
	SawClientPreface bool
}

func (o *http2ServeConnOpts) context() context.Context {
	if o != nil && o.Context != nil {
		return o.Context
	}
	return context.Background()
}

func (o *http2ServeConnOpts) baseConfig() *Server {
	if o != nil && o.BaseConfig != nil {
		return o.BaseConfig
	}
	return new(Server)
}

func (o *http2ServeConnOpts) handler() Handler {
	if o != nil {
		if o.Handler != nil {
			return o.Handler
		}
		if o.BaseConfig != nil && o.BaseConfig.Handler != nil {
			return o.BaseConfig.Handler
		}
	}
	return DefaultServeMux
}

// ServeConn serves HTTP/2 requests on the provided connection and
// blocks until the connection is no longer readable.
//
// ServeConn starts speaking HTTP/2 assuming that c has not had any
// reads or writes. It writes its initial settings frame and expects
// to be able to read the preface and settings frame from the
// client. If c has a ConnectionState method like a *tls.Conn, the
// ConnectionState is used to verify the TLS ciphersuite and to set
// the Request.TLS field in Handlers.
//
// ServeConn does not support h2c by itself. Any h2c support must be
// implemented in terms of providing a suitably-behaving net.Conn.
//
// The opts parameter is optional. If nil, default values are used.
func (s *http2Server) ServeConn(c net.Conn, opts *http2ServeConnOpts) {
	s.serveConn(c, opts, nil)
}

func (s *http2Server) serveConn(c net.Conn, opts *http2ServeConnOpts, newf func(*http2serverConn)) {
	baseCtx, cancel := http2serverConnBaseContext(c, opts)
	defer cancel()

	http1srv := opts.baseConfig()
	conf := http2configFromServer(http1srv, s)
	sc := &http2serverConn{
		srv:                         s,
		hs:                          http1srv,
		conn:                        c,
		baseCtx:                     baseCtx,
		remoteAddrStr:               c.RemoteAddr().String(),
		bw:                          http2newBufferedWriter(s.group, c, conf.WriteByteTimeout),
		handler:                     opts.handler(),
		streams:                     make(map[uint32]*http2stream),
		readFrameCh:                 make(chan http2readFrameResult),
		wantWriteFrameCh:            make(chan http2FrameWriteRequest, 8),
		serveMsgCh:                  make(chan interface{}, 8),
		wroteFrameCh:                make(chan http2frameWriteResult, 1), // buffered; one send in writeFrameAsync
		bodyReadCh:                  make(chan http2bodyReadMsg),         // buffering doesn't matter either way
		doneServing:                 make(chan struct{}),
		clientMaxStreams:            math.MaxUint32, // Section 6.5.2: "Initially, there is no limit to this value"
		advMaxStreams:               conf.MaxConcurrentStreams,
		initialStreamSendWindowSize: http2initialWindowSize,
		initialStreamRecvWindowSize: conf.MaxUploadBufferPerStream,
		maxFrameSize:                http2initialMaxFrameSize,
		pingTimeout:                 conf.PingTimeout,
		countErrorFunc:              conf.CountError,
		serveG:                      http2newGoroutineLock(),
		pushEnabled:                 true,
		sawClientPreface:            opts.SawClientPreface,
	}
	if newf != nil {
		newf(sc)
	}

	s.state.registerConn(sc)
	defer s.state.unregisterConn(sc)

	// The net/http package sets the write deadline from the
	// http.Server.WriteTimeout during the TLS handshake, but then
	// passes the connection off to us with the deadline already set.
	// Write deadlines are set per stream in serverConn.newStream.
	// Disarm the net.Conn write deadline here.
	if sc.hs.WriteTimeout > 0 {
		sc.conn.SetWriteDeadline(time.Time{})
	}

	if s.NewWriteScheduler != nil {
		sc.writeSched = s.NewWriteScheduler()
	} else {
		sc.writeSched = http2newRoundRobinWriteScheduler()
	}

	// These start at the RFC-specified defaults. If there is a higher
	// configured value for inflow, that will be updated when we send a
	// WINDOW_UPDATE shortly after sending SETTINGS.
	sc.flow.add(http2initialWindowSize)
	sc.inflow.init(http2initialWindowSize)
	sc.hpackEncoder = hpack.NewEncoder(&sc.headerWriteBuf)
	sc.hpackEncoder.SetMaxDynamicTableSizeLimit(conf.MaxEncoderHeaderTableSize)

	fr := http2NewFramer(sc.bw, c)
	if conf.CountError != nil {
		fr.countError = conf.CountError
	}
	fr.ReadMetaHeaders = hpack.NewDecoder(conf.MaxDecoderHeaderTableSize, nil)
	fr.MaxHeaderListSize = sc.maxHeaderListSize()
	fr.SetMaxReadFrameSize(conf.MaxReadFrameSize)
	sc.framer = fr

	if tc, ok := c.(http2connectionStater); ok {
		sc.tlsState = new(tls.ConnectionState)
		*sc.tlsState = tc.ConnectionState()
		// 9.2 Use of TLS Features
		// An implementation of HTTP/2 over TLS MUST use TLS
		// 1.2 or higher with the restrictions on feature set
		// and cipher suite described in this section. Due to
		// implementation limitations, it might not be
		// possible to fail TLS negotiation. An endpoint MUST
		// immediately terminate an HTTP/2 connection that
		// does not meet the TLS requirements described in
		// this section with a connection error (Section
		// 5.4.1) of type INADEQUATE_SECURITY.
		if sc.tlsState.Version < tls.VersionTLS12 {
			sc.rejectConn(http2ErrCodeInadequateSecurity, "TLS version too low")
			return
		}

		if sc.tlsState.ServerName == "" {
			// Client must use SNI, but we don't enforce that anymore,
			// since it was causing problems when connecting to bare IP
			// addresses during development.
			//
			// TODO: optionally enforce? Or enforce at the time we receive
			// a new request, and verify the ServerName matches the :authority?
			// But that precludes proxy situations, perhaps.
			//
			// So for now, do nothing here again.
		}

		if !conf.PermitProhibitedCipherSuites && http2isBadCipher(sc.tlsState.CipherSuite) {
			// "Endpoints MAY choose to generate a connection error
			// (Section 5.4.1) of type INADEQUATE_SECURITY if one of
			// the prohibited cipher suites are negotiated."
			//
			// We choose that. In my opinion, the spec is weak
			// here. It also says both parties must support at least
			// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 so there's no
			// excuses here. If we really must, we could allow an
			// "AllowInsecureWeakCiphers" option on the server later.
			// Let's see how it plays out first.
			sc.rejectConn(http2ErrCodeInadequateSecurity, fmt.Sprintf("Prohibited TLS 1.2 Cipher Suite: %x", sc.tlsState.CipherSuite))
			return
		}
	}

	if opts.Settings != nil {
		fr := &http2SettingsFrame{
			http2FrameHeader: http2FrameHeader{valid: true},
			p:                opts.Settings,
		}
		if err := fr.ForeachSetting(sc.processSetting); err != nil {
			sc.rejectConn(http2ErrCodeProtocol, "invalid settings")
			return
		}
		opts.Settings = nil
	}

	if hook := http2testHookGetServerConn; hook != nil {
		hook(sc)
	}

	if opts.UpgradeRequest != nil {
		sc.upgradeRequest(opts.UpgradeRequest)
		opts.UpgradeRequest = nil
	}

	sc.serve(conf)
}

func http2serverConnBaseContext(c net.Conn, opts *http2ServeConnOpts) (ctx context.Context, cancel func()) {
	ctx, cancel = context.WithCancel(opts.context())
	ctx = context.WithValue(ctx, LocalAddrContextKey, c.LocalAddr())
	if hs := opts.baseConfig(); hs != nil {
		ctx = context.WithValue(ctx, ServerContextKey, hs)
	}
	return
}

func (sc *http2serverConn) rejectConn(err http2ErrCode, debug string) {
	sc.vlogf("http2: server rejecting conn: %v, %s", err, debug)
	// ignoring errors. hanging up anyway.
	sc.framer.WriteGoAway(0, err, []byte(debug))
	sc.bw.Flush()
	sc.conn.Close()
}

type http2serverConn struct {
	// Immutable:
	srv              *http2Server
	hs               *Server
	conn             net.Conn
	bw               *http2bufferedWriter // writing to conn
	handler          Handler
	baseCtx          context.Context
	framer           *http2Framer
	doneServing      chan struct{}               // closed when serverConn.serve ends
	readFrameCh      chan http2readFrameResult   // written by serverConn.readFrames
	wantWriteFrameCh chan http2FrameWriteRequest // from handlers -> serve
	wroteFrameCh     chan http2frameWriteResult  // from writeFrameAsync -> serve, tickles more frame writes
	bodyReadCh       chan http2bodyReadMsg       // from handlers -> serve
	serveMsgCh       chan interface{}            // misc messages & code to send to / run on the serve loop
	flow             http2outflow                // conn-wide (not stream-specific) outbound flow control
	inflow           http2inflow                 // conn-wide inbound flow control
	tlsState         *tls.ConnectionState        // shared by all handlers, like net/http
	remoteAddrStr    string
	writeSched       http2WriteScheduler
	countErrorFunc   func(errType string)

	// Everything following is owned by the serve loop; use serveG.check():
	serveG                      http2goroutineLock // used to verify funcs are on serve()
	pushEnabled                 bool
	sawClientPreface            bool // preface has already been read, used in h2c upgrade
	sawFirstSettings            bool // got the initial SETTINGS frame after the preface
	needToSendSettingsAck       bool
	unackedSettings             int    // how many SETTINGS have we sent without ACKs?
	queuedControlFrames         int    // control frames in the writeSched queue
	clientMaxStreams            uint32 // SETTINGS_MAX_CONCURRENT_STREAMS from client (our PUSH_PROMISE limit)
	advMaxStreams               uint32 // our SETTINGS_MAX_CONCURRENT_STREAMS advertised the client
	curClientStreams            uint32 // number of open streams initiated by the client
	curPushedStreams            uint32 // number of open streams initiated by server push
	curHandlers                 uint32 // number of running handler goroutines
	maxClientStreamID           uint32 // max ever seen from client (odd), or 0 if there have been no client requests
	maxPushPromiseID            uint32 // ID of the last push promise (even), or 0 if there have been no pushes
	streams                     map[uint32]*http2stream
	unstartedHandlers           []http2unstartedHandler
	initialStreamSendWindowSize int32
	initialStreamRecvWindowSize int32
	maxFrameSize                int32
	peerMaxHeaderListSize       uint32            // zero means unknown (default)
	canonHeader                 map[string]string // http2-lower-case -> Go-Canonical-Case
	canonHeaderKeysSize         int               // canonHeader keys size in bytes
	writingFrame                bool              // started writing a frame (on serve goroutine or separate)
	writingFrameAsync           bool              // started a frame on its own goroutine but haven't heard back on wroteFrameCh
	needsFrameFlush             bool              // last frame write wasn't a flush
	inGoAway                    bool              // we've started to or sent GOAWAY
	inFrameScheduleLoop         bool              // whether we're in the scheduleFrameWrite loop
	needToSendGoAway            bool              // we need to schedule a GOAWAY frame write
	pingSent                    bool
	sentPingData                [8]byte
	goAwayCode                  http2ErrCode
	shutdownTimer               http2timer // nil until used
	idleTimer                   http2timer // nil if unused
	readIdleTimeout             time.Duration
	pingTimeout                 time.Duration
	readIdleTimer               http2timer // nil if unused

	// Owned by the writeFrameAsync goroutine:
	headerWriteBuf bytes.Buffer
	hpackEncoder   *hpack.Encoder

	// Used by startGracefulShutdown.
	shutdownOnce sync.Once
}

func (sc *http2serverConn) maxHeaderListSize() uint32 {
	n := sc.hs.MaxHeaderBytes
	if n <= 0 {
		n = DefaultMaxHeaderBytes
	}
	return uint32(http2adjustHTTP1MaxHeaderSize(int64(n)))
}

func (sc *http2serverConn) curOpenStreams() uint32 {
	sc.serveG.check()
	return sc.curClientStreams + sc.curPushedStreams
}

// stream represents a stream. This is the minimal metadata needed by
// the serve goroutine. Most of the actual stream state is owned by
// the http.Handler's goroutine in the responseWriter. Because the
// responseWriter's responseWriterState is recycled at the end of a
// handler, this struct intentionally has no pointer to the
// *responseWriter{,State} itself, as the Han
```