Response:
The user wants a summary of the functionalities present in the provided Go code snippet, which is part 4 of a larger file (`go/src/net/http/server.go`). This specific part seems to focus on the `Server` type's methods for shutting down, managing connections, and handling different server configurations.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core subject:** The code heavily features the `Server` struct and its associated methods. This will be the central theme of the summary.

2. **Group related functionalities:**  Scan the code for methods and fields that perform similar tasks. Key areas emerge:
    * **Shutdown:** `Close`, `Shutdown`, `RegisterOnShutdown`, `closeIdleConns`, `closeListenersLocked`.
    * **Connection Management:** `trackListener`, `trackConn`, the `ConnState` type and related constants.
    * **Serving/Listening:** `ListenAndServe`, `ListenAndServeTLS`, `Serve`, `ServeTLS`.
    * **Configuration:**  Various fields within the `Server` struct like `WriteTimeout`, `IdleTimeout`, `TLSConfig`, `Protocols`, and the `setupHTTP2_*` methods.
    * **Timeouts:** `TimeoutHandler`, `ErrHandlerTimeout`.
    * **Internal Helpers:** `serverHandler`, `AllowQuerySemicolons`, `onceCloseListener`, `globalOptionsHandler`, `initALPNRequest`, etc.

3. **Summarize each group's purpose:**  For each group, articulate the main goal. For example:
    * Shutdown:  Methods to gracefully or abruptly stop the server.
    * Connection Management:  Tracking and managing the lifecycle of client connections.
    * Serving/Listening:  Ways to start the server and handle incoming requests.
    * Configuration: Settings that customize the server's behavior.
    * Timeouts: Mechanisms to limit the duration of request handling.
    * Internal Helpers:  Supporting structures for the main server logic.

4. **Highlight key concepts and data structures:**  Mention important types like `ConnState` and the significance of the `Server` struct's fields.

5. **Address specific instructions:** Review the user's request for mentions of:
    * **Go language features:** The code implements core HTTP server functionalities using Go's concurrency primitives (goroutines, mutexes, wait groups), networking (`net` package), and TLS support (`crypto/tls`). Mention the use of interfaces and structs for defining server behavior.
    * **Code examples:** While the user asked for examples, this particular section doesn't lend itself to simple, illustrative examples without significant context from other parts of the `server.go` file. Acknowledge this limitation.
    * **Input/output reasoning:**  Similar to the code examples, reasoning about input and output is difficult without understanding how the surrounding code sets up the server and handles requests. Explain this dependency.
    * **Command-line arguments:** This section of the code doesn't directly handle command-line arguments. Note this.
    * **Common mistakes:**  The `SetKeepAlivesEnabled` method and the shutdown process offer opportunities for errors. Point these out.

6. **Structure the answer:** Organize the summary logically, starting with the main purpose and then detailing the sub-functions. Use clear headings and bullet points for readability.

7. **Review and refine:**  Read through the generated summary to ensure accuracy, clarity, and completeness. Make sure it addresses all parts of the user's request. For example, ensure the final "归纳一下它的功能" section provides a concise overall summary.

**(Self-Correction during the process):**

* Initially, I might have focused too much on individual methods. It's more effective to group related methods by functionality.
* I realized that providing code examples and input/output reasoning would require pulling in context from other parts of the file, which wasn't feasible given the isolated snippet. It's important to explain *why* these couldn't be fully addressed.
* I needed to explicitly state that this is *part* of the server implementation and relies on other components.
这是 `go/src/net/http/server.go` 文件的**第四部分**，它主要集中在 `http.Server` 类型及其相关的生命周期管理和配置上。以下是它的功能归纳：

**核心功能总结：**

这部分代码主要负责 `http.Server` 的**优雅关闭、强制关闭、连接状态管理、超时设置、协议配置（包括 HTTP/2）以及一些辅助工具函数的实现。**  它提供了控制服务器生命周期和行为的关键机制。

**具体功能列举：**

1. **服务器关闭 (Shutdown & Close)：**
    *   **`Close()`**:  立即关闭所有监听器和 `StateNew`, `StateActive`, `StateIdle` 状态的连接。不处理被劫持的连接（如 WebSocket）。
    *   **`Shutdown(ctx context.Context)`**:  优雅地关闭服务器。先关闭所有监听器，然后关闭所有空闲连接，并等待所有连接返回空闲状态并关闭。如果提供的 `context` 超时，则返回 `context` 的错误。
    *   **`RegisterOnShutdown(f func())`**:  注册在 `Shutdown` 方法被调用时需要执行的函数，用于处理 ALPN 协议升级或被劫持的连接的优雅关闭。

2. **连接管理：**
    *   **`ConnState func(net.Conn, ConnState)`**:  一个可选的回调函数，在客户端连接状态改变时被调用。`ConnState` 类型定义了连接的不同状态（`StateNew`，`StateActive`，`StateIdle`，`StateHijacked`，`StateClosed`）。
    *   **`trackListener(ln *net.Listener, add bool)`**:  跟踪服务器正在监听的 `net.Listener`。
    *   **`trackConn(c *conn, add bool)`**:  跟踪服务器的活动连接。
    *   **`closeIdleConns() bool`**:  关闭所有空闲连接，并报告服务器是否处于静止状态（没有活动连接）。

3. **超时设置：**
    *   **`WriteTimeout time.Duration`**:  设置写入响应的最大时间。
    *   **`IdleTimeout time.Duration`**:  设置启用 Keep-Alive 后等待下一个请求的最大时间。
    *   **`ReadTimeout time.Duration`**: （在之前的代码中定义）影响 `IdleTimeout` 的默认值。
    *   **`TimeoutHandler(h Handler, dt time.Duration, msg string)`**:  返回一个 `Handler`，它在给定的时间限制内运行 `h`。如果超过时间限制，则返回 503 错误。

4. **协议配置：**
    *   **`Protocols *Protocols`**:  指定服务器接受的协议集，例如 `UnencryptedHTTP2`。
    *   **`TLSNextProto map[string]func(*Server, *tls.Conn, Handler)`**:  允许在 ALPN 协议升级发生时接管 TLS 连接。
    *   **`setupHTTP2_Serve()` 和 `setupHTTP2_ServeTLS()`**:  条件性地配置 HTTP/2 支持。
    *   **`adjustNextProtos(nextProtos []string, protos Protocols) []string`**:  根据 `Protocols` 设置调整 `tls.Config.NextProtos` 列表。

5. **监听和处理请求：**
    *   **`ListenAndServe() error`**:  在 `s.Addr` 上监听 TCP 连接，并调用 `Serve` 处理传入的连接。
    *   **`ListenAndServeTLS(certFile, keyFile string) error`**:  与 `ListenAndServe` 类似，但处理 HTTPS 连接，需要提供证书和私钥文件。
    *   **`Serve(l net.Listener) error`**:  接受监听器 `l` 上的传入连接，为每个连接创建一个新的 goroutine 来处理请求。
    *   **`ServeTLS(l net.Listener, certFile, keyFile string) error`**:  与 `Serve` 类似，但处理 TLS 连接。

6. **其他配置和工具函数：**
    *   **`MaxHeaderBytes int`**:  控制服务器读取请求头键值对的最大字节数。
    *   **`ErrorLog *log.Logger`**:  指定一个可选的错误日志记录器。
    *   **`BaseContext func(net.Listener) context.Context`**:  为传入的请求指定基础上下文。
    *   **`ConnContext func(ctx context.Context, c net.Conn) context.Context`**:  修改用于新连接的上下文。
    *   **`HTTP2 *HTTP2Config`**:  配置 HTTP/2 连接 (目前尚无实际作用)。
    *   **`SetKeepAlivesEnabled(v bool)`**:  控制是否启用 HTTP Keep-Alive。
    *   **`AllowQuerySemicolons(h Handler) Handler`**:  返回一个处理程序，它将 URL 查询中未转义的分号转换为与号。
    *   **`serverHandler` struct 和 `ServeHTTP` 方法**:  内部处理程序，负责调用用户的 `Handler` 或 `DefaultServeMux`。
    *   **`onceCloseListener`**:  包装 `net.Listener`，防止多次关闭。
    *   **`globalOptionsHandler`**:  处理 "OPTIONS \*" 请求。
    *   **`initALPNRequest`**:  处理来自 ALPN 协议处理程序的请求初始化。
    *   **`MaxBytesHandler(h Handler, n int64) Handler`**: 返回一个 `Handler`，其 `ResponseWriter` 和 `Request.Body` 被 `MaxBytesReader` 包装。

**它是什么Go语言功能的实现：**

这部分代码是 Go 语言 `net/http` 包中构建 HTTP 服务器的核心部分。它利用了 Go 的以下特性：

*   **Goroutines 和并发:**  使用 `go` 关键字为每个连接启动一个 goroutine 来处理请求，实现并发处理。
*   **Mutex 和同步:** 使用 `sync.Mutex` 和 `sync.WaitGroup` 来保护共享资源和等待 goroutine 完成。
*   **Context:** 使用 `context.Context` 来传递请求的上下文信息，包括超时和取消信号。
*   **接口 (Interfaces):**  例如 `net.Listener`，`Handler`，`ResponseWriter`，`Pusher` 等，定义了服务器组件之间的交互方式。
*   **结构体 (Structs):**  `Server` 结构体封装了服务器的配置和状态。
*   **原子操作:** 使用 `sync/atomic` 包中的类型进行原子布尔操作，例如 `inShutdown` 和 `disableKeepAlives`。
*   **TLS 支持:** 通过 `crypto/tls` 包实现 HTTPS 支持。
*   **网络编程:** 使用 `net` 包进行底层的 TCP 监听和连接管理。

**Go 代码举例说明：**

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!")
}

func main() {
	// 创建一个 HTTP 服务器
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      http.HandlerFunc(handler),
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  10 * time.Second,
	}

	// 启动服务器并监听连接
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe error: %v", err)
		}
	}()

	// 模拟一段时间后关闭服务器
	time.Sleep(5 * time.Second)
	fmt.Println("Shutting down the server...")

	// 创建一个带有超时时间的 Context 用于 Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 优雅地关闭服务器
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	fmt.Println("Server gracefully stopped.")
}
```

**假设的输入与输出：**

*   **输入:**  运行上述代码。
*   **输出:**
    *   服务器开始在 `localhost:8080` 上监听。
    *   在 5 秒后，控制台输出 "Shutting down the server..."。
    *   服务器尝试优雅地关闭。
    *   如果 3 秒内所有连接都已处理完毕，控制台输出 "Server gracefully stopped."。
    *   如果在 3 秒内还有活动连接，可能会输出 `Server Shutdown Failed` 的错误信息（具体取决于连接处理时间）。

**命令行参数的具体处理：**

这部分代码本身**不直接处理命令行参数**。命令行参数的处理通常发生在应用程序的主入口点 (`main` 函数) 中，开发者可以使用 `flag` 包或其他库来解析命令行参数，并将解析后的值传递给 `http.Server` 的配置字段。

**使用者易犯错的点：**

1. **不正确使用 `Shutdown` 导致连接中断：**  如果 `Shutdown` 使用的 `context` 超时时间过短，可能会在连接完成处理前强制关闭，导致客户端连接中断或请求失败。

    ```go
    // 错误示例：超时时间过短
    ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
    defer cancel()
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatalf("Server Shutdown Failed:%+v", err) // 可能因为超时而失败
    }
    ```

2. **忘记等待 `Shutdown` 返回：**  调用 `Shutdown` 后，程序需要等待其返回，以确保服务器已安全关闭。如果程序在 `Shutdown` 完成前退出，可能会导致资源泄漏或其他问题。

    ```go
    // 错误示例：未等待 Shutdown 完成
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
        defer cancel()
        srv.Shutdown(ctx) // 直接调用，未等待
    }()
    // 程序可能在这里直接退出，不等 Shutdown 完成
    ```

3. **混淆 `Close` 和 `Shutdown` 的用途：**  `Close` 是强制关闭，可能导致数据丢失或连接中断。`Shutdown` 应该作为首选的关闭方式，除非需要立即停止服务。

4. **没有正确处理被劫持的连接：** `Shutdown` 不会自动关闭被劫持的连接（例如 WebSocket）。需要在 `RegisterOnShutdown` 中注册处理这些连接关闭的函数。

**总结一下它的功能：**

这部分代码是 `net/http` 包中 `Server` 类型实现的核心部分，负责管理 HTTP 服务器的生命周期，包括启动、监听连接、处理请求、配置超时、支持多种协议（如 HTTP/2）以及安全、优雅地关闭服务器。它提供了丰富的功能来定制服务器的行为并确保其稳定可靠地运行。

### 提示词
```
这是路径为go/src/net/http/server.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
basis.
	// A zero or negative value means there will be no timeout.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If zero, the value
	// of ReadTimeout is used. If negative, or if zero and ReadTimeout
	// is zero or negative, there is no timeout.
	IdleTimeout time.Duration

	// MaxHeaderBytes controls the maximum number of bytes the
	// server will read parsing the request header's keys and
	// values, including the request line. It does not limit the
	// size of the request body.
	// If zero, DefaultMaxHeaderBytes is used.
	MaxHeaderBytes int

	// TLSNextProto optionally specifies a function to take over
	// ownership of the provided TLS connection when an ALPN
	// protocol upgrade has occurred. The map key is the protocol
	// name negotiated. The Handler argument should be used to
	// handle HTTP requests and will initialize the Request's TLS
	// and RemoteAddr if not already set. The connection is
	// automatically closed when the function returns.
	// If TLSNextProto is not nil, HTTP/2 support is not enabled
	// automatically.
	TLSNextProto map[string]func(*Server, *tls.Conn, Handler)

	// ConnState specifies an optional callback function that is
	// called when a client connection changes state. See the
	// ConnState type and associated constants for details.
	ConnState func(net.Conn, ConnState)

	// ErrorLog specifies an optional logger for errors accepting
	// connections, unexpected behavior from handlers, and
	// underlying FileSystem errors.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	// BaseContext optionally specifies a function that returns
	// the base context for incoming requests on this server.
	// The provided Listener is the specific Listener that's
	// about to start accepting requests.
	// If BaseContext is nil, the default is context.Background().
	// If non-nil, it must return a non-nil context.
	BaseContext func(net.Listener) context.Context

	// ConnContext optionally specifies a function that modifies
	// the context used for a new connection c. The provided ctx
	// is derived from the base context and has a ServerContextKey
	// value.
	ConnContext func(ctx context.Context, c net.Conn) context.Context

	// HTTP2 configures HTTP/2 connections.
	//
	// This field does not yet have any effect.
	// See https://go.dev/issue/67813.
	HTTP2 *HTTP2Config

	// Protocols is the set of protocols accepted by the server.
	//
	// If Protocols includes UnencryptedHTTP2, the server will accept
	// unencrypted HTTP/2 connections. The server can serve both
	// HTTP/1 and unencrypted HTTP/2 on the same address and port.
	//
	// If Protocols is nil, the default is usually HTTP/1 and HTTP/2.
	// If TLSNextProto is non-nil and does not contain an "h2" entry,
	// the default is HTTP/1 only.
	Protocols *Protocols

	inShutdown atomic.Bool // true when server is in shutdown

	disableKeepAlives atomic.Bool
	nextProtoOnce     sync.Once // guards setupHTTP2_* init
	nextProtoErr      error     // result of http2.ConfigureServer if used

	mu         sync.Mutex
	listeners  map[*net.Listener]struct{}
	activeConn map[*conn]struct{}
	onShutdown []func()

	listenerGroup sync.WaitGroup
}

// Close immediately closes all active net.Listeners and any
// connections in state [StateNew], [StateActive], or [StateIdle]. For a
// graceful shutdown, use [Server.Shutdown].
//
// Close does not attempt to close (and does not even know about)
// any hijacked connections, such as WebSockets.
//
// Close returns any error returned from closing the [Server]'s
// underlying Listener(s).
func (s *Server) Close() error {
	s.inShutdown.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.closeListenersLocked()

	// Unlock s.mu while waiting for listenerGroup.
	// The group Add and Done calls are made with s.mu held,
	// to avoid adding a new listener in the window between
	// us setting inShutdown above and waiting here.
	s.mu.Unlock()
	s.listenerGroup.Wait()
	s.mu.Lock()

	for c := range s.activeConn {
		c.rwc.Close()
		delete(s.activeConn, c)
	}
	return err
}

// shutdownPollIntervalMax is the max polling interval when checking
// quiescence during Server.Shutdown. Polling starts with a small
// interval and backs off to the max.
// Ideally we could find a solution that doesn't involve polling,
// but which also doesn't have a high runtime cost (and doesn't
// involve any contentious mutexes), but that is left as an
// exercise for the reader.
const shutdownPollIntervalMax = 500 * time.Millisecond

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners, then closing all idle connections, and then waiting
// indefinitely for connections to return to idle and then shut down.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error, otherwise it returns any
// error returned from closing the [Server]'s underlying Listener(s).
//
// When Shutdown is called, [Serve], [ListenAndServe], and
// [ListenAndServeTLS] immediately return [ErrServerClosed]. Make sure the
// program doesn't exit and waits instead for Shutdown to return.
//
// Shutdown does not attempt to close nor wait for hijacked
// connections such as WebSockets. The caller of Shutdown should
// separately notify such long-lived connections of shutdown and wait
// for them to close, if desired. See [Server.RegisterOnShutdown] for a way to
// register shutdown notification functions.
//
// Once Shutdown has been called on a server, it may not be reused;
// future calls to methods such as Serve will return ErrServerClosed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.inShutdown.Store(true)

	s.mu.Lock()
	lnerr := s.closeListenersLocked()
	for _, f := range s.onShutdown {
		go f()
	}
	s.mu.Unlock()
	s.listenerGroup.Wait()

	pollIntervalBase := time.Millisecond
	nextPollInterval := func() time.Duration {
		// Add 10% jitter.
		interval := pollIntervalBase + time.Duration(rand.Intn(int(pollIntervalBase/10)))
		// Double and clamp for next time.
		pollIntervalBase *= 2
		if pollIntervalBase > shutdownPollIntervalMax {
			pollIntervalBase = shutdownPollIntervalMax
		}
		return interval
	}

	timer := time.NewTimer(nextPollInterval())
	defer timer.Stop()
	for {
		if s.closeIdleConns() {
			return lnerr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(nextPollInterval())
		}
	}
}

// RegisterOnShutdown registers a function to call on [Server.Shutdown].
// This can be used to gracefully shutdown connections that have
// undergone ALPN protocol upgrade or that have been hijacked.
// This function should start protocol-specific graceful shutdown,
// but should not wait for shutdown to complete.
func (s *Server) RegisterOnShutdown(f func()) {
	s.mu.Lock()
	s.onShutdown = append(s.onShutdown, f)
	s.mu.Unlock()
}

// closeIdleConns closes all idle connections and reports whether the
// server is quiescent.
func (s *Server) closeIdleConns() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	quiescent := true
	for c := range s.activeConn {
		st, unixSec := c.getState()
		// Issue 22682: treat StateNew connections as if
		// they're idle if we haven't read the first request's
		// header in over 5 seconds.
		if st == StateNew && unixSec < time.Now().Unix()-5 {
			st = StateIdle
		}
		if st != StateIdle || unixSec == 0 {
			// Assume unixSec == 0 means it's a very new
			// connection, without state set yet.
			quiescent = false
			continue
		}
		c.rwc.Close()
		delete(s.activeConn, c)
	}
	return quiescent
}

func (s *Server) closeListenersLocked() error {
	var err error
	for ln := range s.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// A ConnState represents the state of a client connection to a server.
// It's used by the optional [Server.ConnState] hook.
type ConnState int

const (
	// StateNew represents a new connection that is expected to
	// send a request immediately. Connections begin at this
	// state and then transition to either StateActive or
	// StateClosed.
	StateNew ConnState = iota

	// StateActive represents a connection that has read 1 or more
	// bytes of a request. The Server.ConnState hook for
	// StateActive fires before the request has entered a handler
	// and doesn't fire again until the request has been
	// handled. After the request is handled, the state
	// transitions to StateClosed, StateHijacked, or StateIdle.
	// For HTTP/2, StateActive fires on the transition from zero
	// to one active request, and only transitions away once all
	// active requests are complete. That means that ConnState
	// cannot be used to do per-request work; ConnState only notes
	// the overall state of the connection.
	StateActive

	// StateIdle represents a connection that has finished
	// handling a request and is in the keep-alive state, waiting
	// for a new request. Connections transition from StateIdle
	// to either StateActive or StateClosed.
	StateIdle

	// StateHijacked represents a hijacked connection.
	// This is a terminal state. It does not transition to StateClosed.
	StateHijacked

	// StateClosed represents a closed connection.
	// This is a terminal state. Hijacked connections do not
	// transition to StateClosed.
	StateClosed
)

var stateName = map[ConnState]string{
	StateNew:      "new",
	StateActive:   "active",
	StateIdle:     "idle",
	StateHijacked: "hijacked",
	StateClosed:   "closed",
}

func (c ConnState) String() string {
	return stateName[c]
}

// serverHandler delegates to either the server's Handler or
// DefaultServeMux and also handles "OPTIONS *" requests.
type serverHandler struct {
	srv *Server
}

// ServeHTTP should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/erda-project/erda-infra
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname badServeHTTP net/http.serverHandler.ServeHTTP
func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request) {
	handler := sh.srv.Handler
	if handler == nil {
		handler = DefaultServeMux
	}
	if !sh.srv.DisableGeneralOptionsHandler && req.RequestURI == "*" && req.Method == "OPTIONS" {
		handler = globalOptionsHandler{}
	}

	handler.ServeHTTP(rw, req)
}

func badServeHTTP(serverHandler, ResponseWriter, *Request)

// AllowQuerySemicolons returns a handler that serves requests by converting any
// unescaped semicolons in the URL query to ampersands, and invoking the handler h.
//
// This restores the pre-Go 1.17 behavior of splitting query parameters on both
// semicolons and ampersands. (See golang.org/issue/25192). Note that this
// behavior doesn't match that of many proxies, and the mismatch can lead to
// security issues.
//
// AllowQuerySemicolons should be invoked before [Request.ParseForm] is called.
func AllowQuerySemicolons(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		if strings.Contains(r.URL.RawQuery, ";") {
			r2 := new(Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.RawQuery = strings.ReplaceAll(r.URL.RawQuery, ";", "&")
			h.ServeHTTP(w, r2)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls [Serve] to handle requests on incoming connections.
// Accepted connections are configured to enable TCP keep-alives.
//
// If s.Addr is blank, ":http" is used.
//
// ListenAndServe always returns a non-nil error. After [Server.Shutdown] or [Server.Close],
// the returned error is [ErrServerClosed].
func (s *Server) ListenAndServe() error {
	if s.shuttingDown() {
		return ErrServerClosed
	}
	addr := s.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

var testHookServerServe func(*Server, net.Listener) // used if non-nil

// shouldConfigureHTTP2ForServe reports whether Server.Serve should configure
// automatic HTTP/2. (which sets up the s.TLSNextProto map)
func (s *Server) shouldConfigureHTTP2ForServe() bool {
	if s.TLSConfig == nil {
		// Compatibility with Go 1.6:
		// If there's no TLSConfig, it's possible that the user just
		// didn't set it on the http.Server, but did pass it to
		// tls.NewListener and passed that listener to Serve.
		// So we should configure HTTP/2 (to set up s.TLSNextProto)
		// in case the listener returns an "h2" *tls.Conn.
		return true
	}
	if s.protocols().UnencryptedHTTP2() {
		return true
	}
	// The user specified a TLSConfig on their http.Server.
	// In this, case, only configure HTTP/2 if their tls.Config
	// explicitly mentions "h2". Otherwise http2.ConfigureServer
	// would modify the tls.Config to add it, but they probably already
	// passed this tls.Config to tls.NewListener. And if they did,
	// it's too late anyway to fix it. It would only be potentially racy.
	// See Issue 15908.
	return slices.Contains(s.TLSConfig.NextProtos, http2NextProtoTLS)
}

// ErrServerClosed is returned by the [Server.Serve], [ServeTLS], [ListenAndServe],
// and [ListenAndServeTLS] methods after a call to [Server.Shutdown] or [Server.Close].
var ErrServerClosed = errors.New("http: Server closed")

// Serve accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutines read requests and
// then call s.Handler to reply to them.
//
// HTTP/2 support is only enabled if the Listener returns [*tls.Conn]
// connections and they were configured with "h2" in the TLS
// Config.NextProtos.
//
// Serve always returns a non-nil error and closes l.
// After [Server.Shutdown] or [Server.Close], the returned error is [ErrServerClosed].
func (s *Server) Serve(l net.Listener) error {
	if fn := testHookServerServe; fn != nil {
		fn(s, l) // call hook with unwrapped listener
	}

	origListener := l
	l = &onceCloseListener{Listener: l}
	defer l.Close()

	if err := s.setupHTTP2_Serve(); err != nil {
		return err
	}

	if !s.trackListener(&l, true) {
		return ErrServerClosed
	}
	defer s.trackListener(&l, false)

	baseCtx := context.Background()
	if s.BaseContext != nil {
		baseCtx = s.BaseContext(origListener)
		if baseCtx == nil {
			panic("BaseContext returned a nil context")
		}
	}

	var tempDelay time.Duration // how long to sleep on accept failure

	ctx := context.WithValue(baseCtx, ServerContextKey, s)
	for {
		rw, err := l.Accept()
		if err != nil {
			if s.shuttingDown() {
				return ErrServerClosed
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				s.logf("http: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		connCtx := ctx
		if cc := s.ConnContext; cc != nil {
			connCtx = cc(connCtx, rw)
			if connCtx == nil {
				panic("ConnContext returned nil")
			}
		}
		tempDelay = 0
		c := s.newConn(rw)
		c.setState(c.rwc, StateNew, runHooks) // before Serve can return
		go c.serve(connCtx)
	}
}

// ServeTLS accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutines perform TLS
// setup and then read requests, calling s.Handler to reply to them.
//
// Files containing a certificate and matching private key for the
// server must be provided if neither the [Server]'s
// TLSConfig.Certificates, TLSConfig.GetCertificate nor
// config.GetConfigForClient are populated.
// If the certificate is signed by a certificate authority, the
// certFile should be the concatenation of the server's certificate,
// any intermediates, and the CA's certificate.
//
// ServeTLS always returns a non-nil error. After [Server.Shutdown] or [Server.Close], the
// returned error is [ErrServerClosed].
func (s *Server) ServeTLS(l net.Listener, certFile, keyFile string) error {
	// Setup HTTP/2 before s.Serve, to initialize s.TLSConfig
	// before we clone it and create the TLS Listener.
	if err := s.setupHTTP2_ServeTLS(); err != nil {
		return err
	}

	config := cloneTLSConfig(s.TLSConfig)
	config.NextProtos = adjustNextProtos(config.NextProtos, s.protocols())

	configHasCert := len(config.Certificates) > 0 || config.GetCertificate != nil || config.GetConfigForClient != nil
	if !configHasCert || certFile != "" || keyFile != "" {
		var err error
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}

	tlsListener := tls.NewListener(l, config)
	return s.Serve(tlsListener)
}

func (s *Server) protocols() Protocols {
	if s.Protocols != nil {
		return *s.Protocols // user-configured set
	}

	// The historic way of disabling HTTP/2 is to set TLSNextProto to
	// a non-nil map with no "h2" entry.
	_, hasH2 := s.TLSNextProto["h2"]
	http2Disabled := s.TLSNextProto != nil && !hasH2

	// If GODEBUG=http2server=0, then HTTP/2 is disabled unless
	// the user has manually added an "h2" entry to TLSNextProto
	// (probably by using x/net/http2 directly).
	if http2server.Value() == "0" && !hasH2 {
		http2Disabled = true
	}

	var p Protocols
	p.SetHTTP1(true) // default always includes HTTP/1
	if !http2Disabled {
		p.SetHTTP2(true)
	}
	return p
}

// adjustNextProtos adds or removes "http/1.1" and "h2" entries from
// a tls.Config.NextProtos list, according to the set of protocols in protos.
func adjustNextProtos(nextProtos []string, protos Protocols) []string {
	var have Protocols
	nextProtos = slices.DeleteFunc(nextProtos, func(s string) bool {
		switch s {
		case "http/1.1":
			if !protos.HTTP1() {
				return true
			}
			have.SetHTTP1(true)
		case "h2":
			if !protos.HTTP2() {
				return true
			}
			have.SetHTTP2(true)
		}
		return false
	})
	if protos.HTTP2() && !have.HTTP2() {
		nextProtos = append(nextProtos, "h2")
	}
	if protos.HTTP1() && !have.HTTP1() {
		nextProtos = append(nextProtos, "http/1.1")
	}
	return nextProtos
}

// trackListener adds or removes a net.Listener to the set of tracked
// listeners.
//
// We store a pointer to interface in the map set, in case the
// net.Listener is not comparable. This is safe because we only call
// trackListener via Serve and can track+defer untrack the same
// pointer to local variable there. We never need to compare a
// Listener from another caller.
//
// It reports whether the server is still up (not Shutdown or Closed).
func (s *Server) trackListener(ln *net.Listener, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners == nil {
		s.listeners = make(map[*net.Listener]struct{})
	}
	if add {
		if s.shuttingDown() {
			return false
		}
		s.listeners[ln] = struct{}{}
		s.listenerGroup.Add(1)
	} else {
		delete(s.listeners, ln)
		s.listenerGroup.Done()
	}
	return true
}

func (s *Server) trackConn(c *conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeConn == nil {
		s.activeConn = make(map[*conn]struct{})
	}
	if add {
		s.activeConn[c] = struct{}{}
	} else {
		delete(s.activeConn, c)
	}
}

func (s *Server) idleTimeout() time.Duration {
	if s.IdleTimeout != 0 {
		return s.IdleTimeout
	}
	return s.ReadTimeout
}

func (s *Server) readHeaderTimeout() time.Duration {
	if s.ReadHeaderTimeout != 0 {
		return s.ReadHeaderTimeout
	}
	return s.ReadTimeout
}

func (s *Server) doKeepAlives() bool {
	return !s.disableKeepAlives.Load() && !s.shuttingDown()
}

func (s *Server) shuttingDown() bool {
	return s.inShutdown.Load()
}

// SetKeepAlivesEnabled controls whether HTTP keep-alives are enabled.
// By default, keep-alives are always enabled. Only very
// resource-constrained environments or servers in the process of
// shutting down should disable them.
func (s *Server) SetKeepAlivesEnabled(v bool) {
	if v {
		s.disableKeepAlives.Store(false)
		return
	}
	s.disableKeepAlives.Store(true)

	// Close idle HTTP/1 conns:
	s.closeIdleConns()

	// TODO: Issue 26303: close HTTP/2 conns as soon as they become idle.
}

func (s *Server) logf(format string, args ...any) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// logf prints to the ErrorLog of the *Server associated with request r
// via ServerContextKey. If there's no associated server, or if ErrorLog
// is nil, logging is done via the log package's standard logger.
func logf(r *Request, format string, args ...any) {
	s, _ := r.Context().Value(ServerContextKey).(*Server)
	if s != nil && s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// ListenAndServe listens on the TCP network address addr and then calls
// [Serve] with handler to handle requests on incoming connections.
// Accepted connections are configured to enable TCP keep-alives.
//
// The handler is typically nil, in which case [DefaultServeMux] is used.
//
// ListenAndServe always returns a non-nil error.
func ListenAndServe(addr string, handler Handler) error {
	server := &Server{Addr: addr, Handler: handler}
	return server.ListenAndServe()
}

// ListenAndServeTLS acts identically to [ListenAndServe], except that it
// expects HTTPS connections. Additionally, files containing a certificate and
// matching private key for the server must be provided. If the certificate
// is signed by a certificate authority, the certFile should be the concatenation
// of the server's certificate, any intermediates, and the CA's certificate.
func ListenAndServeTLS(addr, certFile, keyFile string, handler Handler) error {
	server := &Server{Addr: addr, Handler: handler}
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServeTLS listens on the TCP network address s.Addr and
// then calls [ServeTLS] to handle requests on incoming TLS connections.
// Accepted connections are configured to enable TCP keep-alives.
//
// Filenames containing a certificate and matching private key for the
// server must be provided if neither the [Server]'s TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the server's certificate, any intermediates, and
// the CA's certificate.
//
// If s.Addr is blank, ":https" is used.
//
// ListenAndServeTLS always returns a non-nil error. After [Server.Shutdown] or
// [Server.Close], the returned error is [ErrServerClosed].
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	if s.shuttingDown() {
		return ErrServerClosed
	}
	addr := s.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	defer ln.Close()

	return s.ServeTLS(ln, certFile, keyFile)
}

// setupHTTP2_ServeTLS conditionally configures HTTP/2 on
// s and reports whether there was an error setting it up. If it is
// not configured for policy reasons, nil is returned.
func (s *Server) setupHTTP2_ServeTLS() error {
	s.nextProtoOnce.Do(s.onceSetNextProtoDefaults)
	return s.nextProtoErr
}

// setupHTTP2_Serve is called from (*Server).Serve and conditionally
// configures HTTP/2 on s using a more conservative policy than
// setupHTTP2_ServeTLS because Serve is called after tls.Listen,
// and may be called concurrently. See shouldConfigureHTTP2ForServe.
//
// The tests named TestTransportAutomaticHTTP2* and
// TestConcurrentServerServe in server_test.go demonstrate some
// of the supported use cases and motivations.
func (s *Server) setupHTTP2_Serve() error {
	s.nextProtoOnce.Do(s.onceSetNextProtoDefaults_Serve)
	return s.nextProtoErr
}

func (s *Server) onceSetNextProtoDefaults_Serve() {
	if s.shouldConfigureHTTP2ForServe() {
		s.onceSetNextProtoDefaults()
	}
}

var http2server = godebug.New("http2server")

// onceSetNextProtoDefaults configures HTTP/2, if the user hasn't
// configured otherwise. (by setting s.TLSNextProto non-nil)
// It must only be called via s.nextProtoOnce (use s.setupHTTP2_*).
func (s *Server) onceSetNextProtoDefaults() {
	if omitBundledHTTP2 {
		return
	}
	p := s.protocols()
	if !p.HTTP2() && !p.UnencryptedHTTP2() {
		return
	}
	if http2server.Value() == "0" {
		http2server.IncNonDefault()
		return
	}
	if _, ok := s.TLSNextProto["h2"]; ok {
		// TLSNextProto already contains an HTTP/2 implementation.
		// The user probably called golang.org/x/net/http2.ConfigureServer
		// to add it.
		return
	}
	conf := &http2Server{}
	s.nextProtoErr = http2ConfigureServer(s, conf)
}

// TimeoutHandler returns a [Handler] that runs h with the given time limit.
//
// The new Handler calls h.ServeHTTP to handle each request, but if a
// call runs for longer than its time limit, the handler responds with
// a 503 Service Unavailable error and the given message in its body.
// (If msg is empty, a suitable default message will be sent.)
// After such a timeout, writes by h to its [ResponseWriter] will return
// [ErrHandlerTimeout].
//
// TimeoutHandler supports the [Pusher] interface but does not support
// the [Hijacker] or [Flusher] interfaces.
func TimeoutHandler(h Handler, dt time.Duration, msg string) Handler {
	return &timeoutHandler{
		handler: h,
		body:    msg,
		dt:      dt,
	}
}

// ErrHandlerTimeout is returned on [ResponseWriter] Write calls
// in handlers which have timed out.
var ErrHandlerTimeout = errors.New("http: Handler timeout")

type timeoutHandler struct {
	handler Handler
	body    string
	dt      time.Duration

	// When set, no context will be created and this context will
	// be used instead.
	testContext context.Context
}

func (h *timeoutHandler) errorBody() string {
	if h.body != "" {
		return h.body
	}
	return "<html><head><title>Timeout</title></head><body><h1>Timeout</h1></body></html>"
}

func (h *timeoutHandler) ServeHTTP(w ResponseWriter, r *Request) {
	ctx := h.testContext
	if ctx == nil {
		var cancelCtx context.CancelFunc
		ctx, cancelCtx = context.WithTimeout(r.Context(), h.dt)
		defer cancelCtx()
	}
	r = r.WithContext(ctx)
	done := make(chan struct{})
	tw := &timeoutWriter{
		w:   w,
		h:   make(Header),
		req: r,
	}
	panicChan := make(chan any, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				panicChan <- p
			}
		}()
		h.handler.ServeHTTP(tw, r)
		close(done)
	}()
	select {
	case p := <-panicChan:
		panic(p)
	case <-done:
		tw.mu.Lock()
		defer tw.mu.Unlock()
		dst := w.Header()
		maps.Copy(dst, tw.h)
		if !tw.wroteHeader {
			tw.code = StatusOK
		}
		w.WriteHeader(tw.code)
		w.Write(tw.wbuf.Bytes())
	case <-ctx.Done():
		tw.mu.Lock()
		defer tw.mu.Unlock()
		switch err := ctx.Err(); err {
		case context.DeadlineExceeded:
			w.WriteHeader(StatusServiceUnavailable)
			io.WriteString(w, h.errorBody())
			tw.err = ErrHandlerTimeout
		default:
			w.WriteHeader(StatusServiceUnavailable)
			tw.err = err
		}
	}
}

type timeoutWriter struct {
	w    ResponseWriter
	h    Header
	wbuf bytes.Buffer
	req  *Request

	mu          sync.Mutex
	err         error
	wroteHeader bool
	code        int
}

var _ Pusher = (*timeoutWriter)(nil)

// Push implements the [Pusher] interface.
func (tw *timeoutWriter) Push(target string, opts *PushOptions) error {
	if pusher, ok := tw.w.(Pusher); ok {
		return pusher.Push(target, opts)
	}
	return ErrNotSupported
}

func (tw *timeoutWriter) Header() Header { return tw.h }

func (tw *timeoutWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.err != nil {
		return 0, tw.err
	}
	if !tw.wroteHeader {
		tw.writeHeaderLocked(StatusOK)
	}
	return tw.wbuf.Write(p)
}

func (tw *timeoutWriter) writeHeaderLocked(code int) {
	checkWriteHeaderCode(code)

	switch {
	case tw.err != nil:
		return
	case tw.wroteHeader:
		if tw.req != nil {
			caller := relevantCaller()
			logf(tw.req, "http: superfluous response.WriteHeader call from %s (%s:%d)", caller.Function, path.Base(caller.File), caller.Line)
		}
	default:
		tw.wroteHeader = true
		tw.code = code
	}
}

func (tw *timeoutWriter) WriteHeader(code int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.writeHeaderLocked(code)
}

// onceCloseListener wraps a net.Listener, protecting it from
// multiple Close calls.
type onceCloseListener struct {
	net.Listener
	once     sync.Once
	closeErr error
}

func (oc *onceCloseListener) Close() error {
	oc.once.Do(oc.close)
	return oc.closeErr
}

func (oc *onceCloseListener) close() { oc.closeErr = oc.Listener.Close() }

// globalOptionsHandler responds to "OPTIONS *" requests.
type globalOptionsHandler struct{}

func (globalOptionsHandler) ServeHTTP(w ResponseWriter, r *Request) {
	w.Header().Set("Content-Length", "0")
	if r.ContentLength != 0 {
		// Read up to 4KB of OPTIONS body (as mentioned in the
		// spec as being reserved for future use), but anything
		// over that is considered a waste of server resources
		// (or an attack) and we abort and close the connection,
		// courtesy of MaxBytesReader's EOF behavior.
		mb := MaxBytesReader(w, r.Body, 4<<10)
		io.Copy(io.Discard, mb)
	}
}

// initALPNRequest is an HTTP handler that initializes certain
// uninitialized fields in its *Request. Such partially-initialized
// Requests come from ALPN protocol handlers.
type initALPNRequest struct {
	ctx context.Context
	c   *tls.Conn
	h   serverHandler
}

// BaseContext is an exported but unadvertised [http.Handler] method
// recognized by x/net/http2 to pass down a context; the TLSNextProto
// API predates context support so we shoehorn through the only
// interface we have available.
func (h initALPNRequest) BaseContext() context.Context { return h.ctx }

func (h initALPNRequest) ServeHTTP(rw ResponseWriter, req *Request) {
	if req.TLS == nil {
		req.TLS = &tls.ConnectionState{}
		*req.TLS = h.c.ConnectionState()
	}
	if req.Body == nil {
		req.Body = NoBody
	}
	if req.RemoteAddr == "" {
		req.RemoteAddr = h.c.RemoteAddr().String()
	}
	h.h.ServeHTTP(rw, req)
}

// loggingConn is used for debugging.
type loggingConn struct {
	name string
	net.Conn
}

var (
	uniqNameMu   sync.Mutex
	uniqNameNext = make(map[string]int)
)

func newLoggingConn(baseName string, c net.Conn) net.Conn {
	uniqNameMu.Lock()
	defer uniqNameMu.Unlock()
	uniqNameNext[baseName]++
	return &loggingConn{
		name: fmt.Sprintf("%s-%d", baseName, uniqNameNext[baseName]),
		Conn: c,
	}
}

func (c *loggingConn) Write(p []byte) (n int, err error) {
	log.Printf("%s.Write(%d) = ....", c.name, len(p))
	n, err = c.Conn.Write(p)
	log.Printf("%s.Write(%d) = %d, %v", c.name, len(p), n, err)
	return
}

func (c *loggingConn) Read(p []byte) (n int, err error) {
	log.Printf("%s.Read(%d) = ....", c.name, len(p))
	n, err = c.Conn.Read(p)
	log.Printf("%s.Read(%d) = %d, %v", c.name, len(p), n, err)
	return
}

func (c *loggingConn) Close() (err error) {
	log.Printf("%s.Close() = ...", c.name)
	err = c.Conn.Close()
	log.Printf("%s.Close() = %v", c.name, err)
	return
}

// checkConnErrorWriter writes to c.rwc and records any write errors to c.werr.
// It only contains one field (and a pointer field at that), so it
// fits in an interface value without an extra allocation.
type checkConnErrorWriter struct {
	c *conn
}

func (w checkConnErrorWriter) Write(p []byte) (n int, err error) {
	n, err = w.c.rwc.Write(p)
	if err != nil && w.c.werr == nil {
		w.c.werr = err
		w.c.cancelCtx()
	}
	return
}

func numLeadingCRorLF(v []byte) (n int) {
	for _, b := range v {
		if b == '\r' || b == '\n' {
			n++
			continue
		}
		break
	}
	return
}

// tlsRecordHeaderLooksLikeHTTP reports whether a TLS record header
// looks like it might've been a misdirected plaintext HTTP request.
func tlsRecordHeaderLooksLikeHTTP(hdr [5]byte) bool {
	switch string(hdr[:]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

// MaxBytesHandler returns a [Handler] that runs h with its [ResponseWriter] and [Request.Body] wrapped by a MaxBytesReader.
func MaxBytesHandler(h Handler, n int64) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		r2 := *r
		r2.Body = MaxBytesReader(w, r.Body, n)
		h.ServeHTTP(w, &r2)
	})
}
```