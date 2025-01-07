Response:
Let's break down the thought process for analyzing this Go test file.

**1. Understanding the Purpose of `export_test.go`:**

The first and most crucial step is to recognize the comment at the top: `"Bridge package to expose http internals to tests in the http_test package."`  This immediately tells us the file isn't about defining core HTTP functionality. Instead, it's a testing mechanism. The keywords here are "expose" and "internals."  This means it's providing access to things that are normally private within the `net/http` package. Why?  Because tests often need to peek into the implementation details to verify behavior.

**2. Identifying Exported Variables and Functions:**

The next step is to scan the file for exported identifiers. Go uses uppercase for exports, so we look for `var` and `func` declarations with capital letters. The comment `//` preceding many of these declarations confirms they are the intended exports.

* **Variables:** `DefaultUserAgent`, `MaxWriteWaitBeforeConnReuse`, and a few error variables. These likely hold internal states or configurations.
* **Functions:** A significant number of functions starting with `Export...`. This naming convention is a strong indicator of their purpose: to expose internal functions for testing.

**3. Categorizing the Exported Items:**

Now, we need to group these exports by what they represent. Looking at the names provides clues:

* **Constants/Values:** `DefaultUserAgent`, `MaxWriteWaitBeforeConnReuse` seem like configuration or constant values.
* **Internal Functions:**  The `Export...` functions clearly expose internal logic. Examples include `ExportAppendTime`, `ExportRefererForURL`, `ExportServerNewConn`, `ExportCloseWriteAndWait`, etc. These allow tests to call internal logic directly.
* **State Inspection:**  Functions like `NumPendingRequestsForTesting`, `IdleConnKeysForTesting`, `IdleConnCountForTesting`, `ExportAllConnsIdle`, `ExportAllConnsByState` provide ways to examine the internal state of the `Transport` and `Server` types.
* **Hooks:** The `Set...Hook` functions (e.g., `SetEnterRoundTripHook`, `SetReadLoopBeforeNextReadHook`) suggest a mechanism for injecting custom behavior into the HTTP processing pipeline during tests.
* **Type Creation/Modification:**  `NewLoggingConn`, `NewTestTimeoutHandler`, `ExportHttp2ConfigureTransport`. These let tests create or manipulate internal structures.

**4. Inferring the Purpose of Specific Exports:**

With the categories in mind, we can deduce the purpose of individual exports:

* `ExportAppendTime`:  Allows testing of the time formatting logic.
* `ExportRefererForURL`:  Allows testing how referer headers are determined.
* `ExportServerNewConn`:  Allows tests to simulate the creation of new server connections.
* `NumPendingRequestsForTesting`: Lets tests check how many requests are currently being handled by a `Transport`.
* `IdleConnKeysForTesting`:  Enables inspection of the keys used to identify idle connections.
* `SetEnterRoundTripHook`: Allows injecting code before an HTTP round trip happens, likely for debugging or asserting conditions.

**5. Identifying Go Language Features:**

Several Go features are evident:

* **Package-level variables:** The `var` declarations outside any function.
* **Functions:** The `func` keyword.
* **Methods:** Functions associated with a type receiver (e.g., `(t *Transport) NumPendingRequestsForTesting()`).
* **Closures:**  The anonymous functions used in the `init` block and for setting hooks.
* **Pointers:**  Used extensively, especially for modifying state and for `hookSetter`.
* **Interfaces:** Implicitly used through `Handler` and `RoundTripper`.
* **Mutexes:** For managing concurrent access to shared state (`sync.Mutex`).
* **Channels:**  Used in `persistConn` (`closech`).
* **Context:** Used in `NewTestTimeoutHandler` and `WithT`.
* **Testing Package:** The import of `testing` and usage of `testing.TB` and `t.Skip`.
* **Build Tags:** The comment about `nethttpomithttp2` highlights the use of build tags for conditional compilation.

**6. Considering Examples and Potential Issues:**

Thinking about how tests might *use* these exports leads to example scenarios:

* Testing caching by examining idle connections.
* Testing error handling by simulating connection closures.
* Testing timeouts using `NewTestTimeoutHandler`.
* Testing HTTP/2 specific behavior using the `ExportHttp2...` functions.

Potential mistakes users might make:

* Misunderstanding the purpose of the exported functions – they are for *testing*, not for general use.
* Relying on the specific implementation details exposed here, which could change.

**7. Structuring the Answer:**

Finally, organize the information logically, using clear headings and examples where appropriate. Start with the overall purpose, then detail the functionalities, the Go features used, and conclude with potential pitfalls. Using code snippets helps illustrate the concepts.

This iterative process of reading the code, understanding the comments, identifying key elements, and then inferring the purpose and usage of those elements is crucial for analyzing code, especially in situations like this where a specific file serves a supporting role for a larger system.
这个`go/src/net/http/export_test.go` 文件是 Go 语言 `net/http` 标准库的一部分，它的主要功能是**桥接 `net/http` 包的内部实现，以便 `net/http_test` 包中的测试代码能够访问和测试这些内部细节**。

简单来说，由于 Go 语言的可见性规则，默认情况下，一个包内的未导出（小写字母开头）的变量、函数、结构体等是无法被其他包直接访问的。但是，为了进行更深入的单元测试，`net/http_test` 包需要能够触及 `net/http` 包的内部状态和逻辑。`export_test.go` 就扮演了这样一个“出口”的角色，它通过声明一些全局的、导出的变量和函数，将 `net/http` 包内部的一些私有成员暴露出来，供测试使用。

以下是它具体的功能以及对应的 Go 代码示例：

**1. 暴露内部变量：**

   - `DefaultUserAgent = defaultUserAgent`: 暴露了默认的 User-Agent 字符串。
   - `MaxWriteWaitBeforeConnReuse = &maxWriteWaitBeforeConnReuse`: 暴露了在连接重用前等待写入的最大时间。
   - `ExportErrRequestCanceled = errRequestCanceled`: 暴露了请求取消错误。
   - `ExportErrRequestCanceledConn = errRequestCanceledConn`: 暴露了连接相关的请求取消错误。
   - `ExportErrServerClosedIdle = errServerClosedIdle`: 暴露了服务器关闭空闲连接的错误。

   **Go 代码示例：**

   ```go
   package http_test

   import (
       "net/http"
       "testing"
   )

   func TestExportedVariables(t *testing.T) {
       if http.DefaultUserAgent == "" {
           t.Error("DefaultUserAgent should not be empty")
       }

       // 假设我们想测试在特定情况下是否会返回请求取消错误
       err := http.ExportErrRequestCanceled
       // ... 进行一些操作，可能会导致请求取消 ...
       // if theOperationReturnedError == err {
       //     // 测试通过
       // }
   }
   ```

   **假设的输入与输出：**  这里主要是访问静态的变量，没有特定的输入，输出就是这些变量的值。例如，`http.DefaultUserAgent` 的输出可能类似 `"Go-http-client/1.1"`。

**2. 暴露内部函数：**

   - `NewLoggingConn = newLoggingConn`: 暴露了创建用于日志记录的连接的函数。
   - `ExportAppendTime = appendTime`: 暴露了用于格式化时间的内部函数。
   - `ExportRefererForURL = refererForURL`: 暴露了根据 URL 获取 Referer 的内部函数。
   - `ExportServerNewConn = (*Server).newConn`: 暴露了 `Server` 类型创建新连接的方法。
   - `ExportCloseWriteAndWait = (*conn).closeWriteAndWait`: 暴露了 `conn` 类型关闭写端并等待的方法。
   - `ExportServeFile = serveFile`: 暴露了用于服务静态文件的内部函数。
   - `ExportScanETag = scanETag`: 暴露了扫描 ETag 头的内部函数。
   - `ExportHttp2ConfigureServer = http2ConfigureServer`: 暴露了配置 HTTP/2 服务器的内部函数。
   - `Export_shouldCopyHeaderOnRedirect = shouldCopyHeaderOnRedirect`: 暴露了判断重定向时是否应该复制 Header 的内部函数。
   - `Export_writeStatusLine = writeStatusLine`: 暴露了写入状态行的内部函数.
   - `Export_is408Message = is408Message`: 暴露了判断是否为 408 请求超时的内部函数。

   **Go 代码示例：**

   ```go
   package http_test

   import (
       "net/http"
       "net/url"
       "testing"
       "time"
   )

   func TestExportedFunctions(t *testing.T) {
       u, _ := url.Parse("https://example.com/path")
       referer := http.ExportRefererForURL(u)
       // 测试 referer 是否符合预期
       if referer != "https://example.com/" {
           t.Errorf("Expected referer 'https://example.com/', got '%s'", referer)
       }

       now := time.Now()
       formattedTime := http.ExportAppendTime(nil, now)
       // 测试时间格式是否正确
       // ...
   }
   ```

   **假设的输入与输出：**  以 `ExportRefererForURL` 为例，输入是 `*url.URL`，输出是 `string` 类型的 Referer 值。

**3. 暴露类型的方法：**

   - `ExportAllConnsIdle = (*Server).ExportAllConnsIdle`: 暴露了检查服务器所有连接是否都处于空闲状态的方法。
   - `ExportAllConnsByState = (*Server).ExportAllConnsByState`: 暴露了获取服务器所有连接状态的方法。
   - `ExportIsReplayable = (*Request).ExportIsReplayable`: 暴露了判断请求是否可重放的方法。

   **Go 代码示例：**

   ```go
   package http_test

   import (
       "net/http"
       "net/http/httptest"
       "testing"
   )

   func TestExportedMethods(t *testing.T) {
       s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           w.WriteHeader(http.StatusOK)
       }))
       defer s.Close()

       client := &http.Client{}
       req, _ := http.NewRequest("GET", s.URL, nil)
       resp, _ := client.Do(req)
       resp.Body.Close()

       // 在某些测试场景下，可能需要检查服务器的所有连接是否都已空闲
       server := s.Config // 获取 httptest.Server 底层的 http.Server
       if !server.ExportAllConnsIdle() {
           t.Error("Expected all connections to be idle")
       }
   }
   ```

   **假设的输入与输出：**  以 `ExportAllConnsIdle` 为例，输入是一个 `*http.Server` 实例，输出是 `bool` 类型，表示所有连接是否空闲。

**4. 提供测试辅助函数和钩子 (Hooks)：**

   - `CondSkipHTTP2(t testing.TB)`:  在禁用 HTTP/2 的构建标签下跳过 HTTP/2 测试。
   - `SetEnterRoundTripHook`: 设置在 HTTP 请求 RoundTrip 开始前执行的钩子函数。
   - `SetRoundTripRetried`: 设置在 HTTP 请求 RoundTrip 重试时执行的钩子函数。
   - `SetReadLoopBeforeNextReadHook`: 设置在连接读取循环的下一次读取前执行的钩子函数。
   - `SetPendingDialHooks`: 设置在处理挂起的拨号操作前后执行的钩子函数。
   - `SetTestHookServerServe`: 设置在服务器开始监听和处理连接时执行的钩子函数。
   - `SetTestHookProxyConnectTimeout`: 设置测试代理连接超时的钩子函数。
   - `NewTestTimeoutHandler`: 创建一个带有上下文的超时处理器，用于测试超时场景。
   - `ResetCachedEnvironment`: 重置缓存的环境变量，用于隔离测试环境。
   - `NumPendingRequestsForTesting`: 获取 `Transport` 中挂起的请求数量。
   - `IdleConnKeysForTesting`: 获取 `Transport` 中空闲连接的键。
   - `IdleConnKeyCountForTesting`: 获取 `Transport` 中空闲连接键的数量。
   - `IdleConnStrsForTesting`: 获取 `Transport` 中空闲连接的字符串表示。
   - `IdleConnCountForTesting`: 获取 `Transport` 中特定 scheme 和地址的空闲连接数量。
   - `IdleConnWaitMapSizeForTesting`: 获取 `Transport` 中等待空闲连接的 map 大小。
   - `IsIdleForTesting`: 检查 `Transport` 是否处于空闲状态。
   - `QueueForIdleConnForTesting`: 将连接排队等待空闲。
   - `PutIdleTestConn`: 向 `Transport` 的空闲连接池中放入一个测试连接。
   - `PutIdleTestConnH2`: 向 `Transport` 的空闲连接池中放入一个 HTTP/2 测试连接。
   - `ExportHttp2ConfigureTransport`: 允许测试代码手动配置 `Transport` 的 HTTP/2 支持。
   - `ExportCloseTransportConnsAbruptly`:  用于测试场景，突然关闭 `Transport` 的所有空闲连接。
   - `ResponseWriterConnForTesting`: 获取 `ResponseWriter` 底层的 `net.Conn`。
   - `SetRSTAvoidanceDelay`: 设置避免 RST 报文的延迟，用于测试。

   **Go 代码示例 (Hook 的使用)：**

   ```go
   package http_test

   import (
       "context"
       "fmt"
       "net/http"
       "net/http/httptest"
       "testing"
   )

   func TestRequestRetries(t *testing.T) {
       retried := false
       http.SetRoundTripRetried(func() {
           retried = true
       })
       defer http.SetRoundTripRetried(nil) // 清理 hook

       handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           w.WriteHeader(http.StatusInternalServerError) // 模拟错误
       })
       server := httptest.NewServer(handler)
       defer server.Close()

       client := &http.Client{}
       req, _ := http.NewRequest("GET", server.URL, nil)
       _, err := client.Do(req)
       if err == nil {
           t.Fatal("Expected an error")
       }

       if !retried {
           t.Error("Expected the request to be retried")
       }
   }
   ```

   **假设的输入与输出：** Hook 函数的输入取决于其具体的作用。例如，`SetRoundTripRetried` 的钩子函数没有输入或输出，它的作用是捕获重试事件。

**涉及命令行参数的具体处理：**

这个文件中本身并没有直接处理命令行参数。但是，它利用了构建标签 (`omitBundledHTTP2`) 来决定是否跳过 HTTP/2 的测试。构建标签是通过 `go test` 命令的 `-tags` 参数来指定的。例如：

```bash
go test -tags=nethttpomithttp2 ./net/http
```

如果使用了 `nethttpomithttp2` 标签进行构建和测试，`CondSkipHTTP2` 函数就会跳过相关的 HTTP/2 测试。

**使用者易犯错的点：**

1. **误用导出功能：** `export_test.go` 中的导出功能是专门为测试设计的，不应该在正常的应用程序代码中使用。依赖这些内部细节可能会导致代码不稳定，因为 `net/http` 包的内部实现可能会在没有通知的情况下改变。

   **错误示例：**

   ```go
   package main

   import (
       "fmt"
       "net/http"
   )

   func main() {
       fmt.Println(http.DefaultUserAgent) // 不应该在生产代码中直接使用
   }
   ```

2. **过度依赖内部状态：**  测试代码应该主要关注外部行为和接口，而不是过度依赖内部状态。虽然 `export_test.go` 提供了访问内部状态的能力，但过度使用可能会使测试变得脆弱，当内部实现改变时，测试也需要随之改变。

3. **Hook 函数使用不当：**  Hook 函数可能会改变 `net/http` 包的内部行为，如果不小心设置或清理 Hook，可能会影响到其他测试的执行，导致难以追踪的错误。务必在使用完 Hook 后进行清理（通常是通过 `defer` 调用设置为 `nil` 的函数）。

总而言之，`go/src/net/http/export_test.go` 是 `net/http` 包为了提升其可测试性而设计的一个特殊的桥接文件。它允许测试代码深入到内部实现进行验证，但同时也提醒开发者，这些暴露的功能仅供测试使用，不应在生产代码中依赖。

Prompt: 
```
这是路径为go/src/net/http/export_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Bridge package to expose http internals to tests in the http_test
// package.

package http

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"
)

var (
	DefaultUserAgent                  = defaultUserAgent
	NewLoggingConn                    = newLoggingConn
	ExportAppendTime                  = appendTime
	ExportRefererForURL               = refererForURL
	ExportServerNewConn               = (*Server).newConn
	ExportCloseWriteAndWait           = (*conn).closeWriteAndWait
	ExportErrRequestCanceled          = errRequestCanceled
	ExportErrRequestCanceledConn      = errRequestCanceledConn
	ExportErrServerClosedIdle         = errServerClosedIdle
	ExportServeFile                   = serveFile
	ExportScanETag                    = scanETag
	ExportHttp2ConfigureServer        = http2ConfigureServer
	Export_shouldCopyHeaderOnRedirect = shouldCopyHeaderOnRedirect
	Export_writeStatusLine            = writeStatusLine
	Export_is408Message               = is408Message
)

var MaxWriteWaitBeforeConnReuse = &maxWriteWaitBeforeConnReuse

func init() {
	// We only want to pay for this cost during testing.
	// When not under test, these values are always nil
	// and never assigned to.
	testHookMu = new(sync.Mutex)

	testHookClientDoResult = func(res *Response, err error) {
		if err != nil {
			if _, ok := err.(*url.Error); !ok {
				panic(fmt.Sprintf("unexpected Client.Do error of type %T; want *url.Error", err))
			}
		} else {
			if res == nil {
				panic("Client.Do returned nil, nil")
			}
			if res.Body == nil {
				panic("Client.Do returned nil res.Body and no error")
			}
		}
	}
}

func CondSkipHTTP2(t testing.TB) {
	if omitBundledHTTP2 {
		t.Skip("skipping HTTP/2 test when nethttpomithttp2 build tag in use")
	}
}

var (
	SetEnterRoundTripHook = hookSetter(&testHookEnterRoundTrip)
	SetRoundTripRetried   = hookSetter(&testHookRoundTripRetried)
)

func SetReadLoopBeforeNextReadHook(f func()) {
	unnilTestHook(&f)
	testHookReadLoopBeforeNextRead = f
}

// SetPendingDialHooks sets the hooks that run before and after handling
// pending dials.
func SetPendingDialHooks(before, after func()) {
	unnilTestHook(&before)
	unnilTestHook(&after)
	testHookPrePendingDial, testHookPostPendingDial = before, after
}

func SetTestHookServerServe(fn func(*Server, net.Listener)) { testHookServerServe = fn }

func SetTestHookProxyConnectTimeout(t *testing.T, f func(context.Context, time.Duration) (context.Context, context.CancelFunc)) {
	orig := testHookProxyConnectTimeout
	t.Cleanup(func() {
		testHookProxyConnectTimeout = orig
	})
	testHookProxyConnectTimeout = f
}

func NewTestTimeoutHandler(handler Handler, ctx context.Context) Handler {
	return &timeoutHandler{
		handler:     handler,
		testContext: ctx,
		// (no body)
	}
}

func ResetCachedEnvironment() {
	resetProxyConfig()
}

func (t *Transport) NumPendingRequestsForTesting() int {
	t.reqMu.Lock()
	defer t.reqMu.Unlock()
	return len(t.reqCanceler)
}

func (t *Transport) IdleConnKeysForTesting() (keys []string) {
	keys = make([]string, 0)
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	for key := range t.idleConn {
		keys = append(keys, key.String())
	}
	slices.Sort(keys)
	return
}

func (t *Transport) IdleConnKeyCountForTesting() int {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	return len(t.idleConn)
}

func (t *Transport) IdleConnStrsForTesting() []string {
	var ret []string
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	for _, conns := range t.idleConn {
		for _, pc := range conns {
			ret = append(ret, pc.conn.LocalAddr().String()+"/"+pc.conn.RemoteAddr().String())
		}
	}
	slices.Sort(ret)
	return ret
}

func (t *Transport) IdleConnStrsForTesting_h2() []string {
	var ret []string
	noDialPool := t.h2transport.(*http2Transport).ConnPool.(http2noDialClientConnPool)
	pool := noDialPool.http2clientConnPool

	pool.mu.Lock()
	defer pool.mu.Unlock()

	for k, ccs := range pool.conns {
		for _, cc := range ccs {
			if cc.idleState().canTakeNewRequest {
				ret = append(ret, k)
			}
		}
	}

	slices.Sort(ret)
	return ret
}

func (t *Transport) IdleConnCountForTesting(scheme, addr string) int {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	key := connectMethodKey{"", scheme, addr, false}
	cacheKey := key.String()
	for k, conns := range t.idleConn {
		if k.String() == cacheKey {
			return len(conns)
		}
	}
	return 0
}

func (t *Transport) IdleConnWaitMapSizeForTesting() int {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	return len(t.idleConnWait)
}

func (t *Transport) IsIdleForTesting() bool {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	return t.closeIdle
}

func (t *Transport) QueueForIdleConnForTesting() {
	t.queueForIdleConn(nil)
}

// PutIdleTestConn reports whether it was able to insert a fresh
// persistConn for scheme, addr into the idle connection pool.
func (t *Transport) PutIdleTestConn(scheme, addr string) bool {
	c, _ := net.Pipe()
	key := connectMethodKey{"", scheme, addr, false}

	if t.MaxConnsPerHost > 0 {
		// Transport is tracking conns-per-host.
		// Increment connection count to account
		// for new persistConn created below.
		t.connsPerHostMu.Lock()
		if t.connsPerHost == nil {
			t.connsPerHost = make(map[connectMethodKey]int)
		}
		t.connsPerHost[key]++
		t.connsPerHostMu.Unlock()
	}

	return t.tryPutIdleConn(&persistConn{
		t:        t,
		conn:     c,                   // dummy
		closech:  make(chan struct{}), // so it can be closed
		cacheKey: key,
	}) == nil
}

// PutIdleTestConnH2 reports whether it was able to insert a fresh
// HTTP/2 persistConn for scheme, addr into the idle connection pool.
func (t *Transport) PutIdleTestConnH2(scheme, addr string, alt RoundTripper) bool {
	key := connectMethodKey{"", scheme, addr, false}

	if t.MaxConnsPerHost > 0 {
		// Transport is tracking conns-per-host.
		// Increment connection count to account
		// for new persistConn created below.
		t.connsPerHostMu.Lock()
		if t.connsPerHost == nil {
			t.connsPerHost = make(map[connectMethodKey]int)
		}
		t.connsPerHost[key]++
		t.connsPerHostMu.Unlock()
	}

	return t.tryPutIdleConn(&persistConn{
		t:        t,
		alt:      alt,
		cacheKey: key,
	}) == nil
}

// All test hooks must be non-nil so they can be called directly,
// but the tests use nil to mean hook disabled.
func unnilTestHook(f *func()) {
	if *f == nil {
		*f = nop
	}
}

func hookSetter(dst *func()) func(func()) {
	return func(fn func()) {
		unnilTestHook(&fn)
		*dst = fn
	}
}

func ExportHttp2ConfigureTransport(t *Transport) error {
	t2, err := http2configureTransports(t)
	if err != nil {
		return err
	}
	t.h2transport = t2
	return nil
}

func (s *Server) ExportAllConnsIdle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.activeConn {
		st, unixSec := c.getState()
		if unixSec == 0 || st != StateIdle {
			return false
		}
	}
	return true
}

func (s *Server) ExportAllConnsByState() map[ConnState]int {
	states := map[ConnState]int{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.activeConn {
		st, _ := c.getState()
		states[st] += 1
	}
	return states
}

func (r *Request) WithT(t *testing.T) *Request {
	return r.WithContext(context.WithValue(r.Context(), tLogKey{}, t.Logf))
}

func ExportSetH2GoawayTimeout(d time.Duration) (restore func()) {
	old := http2goAwayTimeout
	http2goAwayTimeout = d
	return func() { http2goAwayTimeout = old }
}

func (r *Request) ExportIsReplayable() bool { return r.isReplayable() }

// ExportCloseTransportConnsAbruptly closes all idle connections from
// tr in an abrupt way, just reaching into the underlying Conns and
// closing them, without telling the Transport or its persistConns
// that it's doing so. This is to simulate the server closing connections
// on the Transport.
func ExportCloseTransportConnsAbruptly(tr *Transport) {
	tr.idleMu.Lock()
	for _, pcs := range tr.idleConn {
		for _, pc := range pcs {
			pc.conn.Close()
		}
	}
	tr.idleMu.Unlock()
}

// ResponseWriterConnForTesting returns w's underlying connection, if w
// is a regular *response ResponseWriter.
func ResponseWriterConnForTesting(w ResponseWriter) (c net.Conn, ok bool) {
	if r, ok := w.(*response); ok {
		return r.conn.rwc, true
	}
	return nil, false
}

func init() {
	// Set the default rstAvoidanceDelay to the minimum possible value to shake
	// out tests that unexpectedly depend on it. Such tests should use
	// runTimeSensitiveTest and SetRSTAvoidanceDelay to explicitly raise the delay
	// if needed.
	rstAvoidanceDelay = 1 * time.Nanosecond
}

// SetRSTAvoidanceDelay sets how long we are willing to wait between calling
// CloseWrite on a connection and fully closing the connection.
func SetRSTAvoidanceDelay(t *testing.T, d time.Duration) {
	prevDelay := rstAvoidanceDelay
	t.Cleanup(func() {
		rstAvoidanceDelay = prevDelay
	})
	rstAvoidanceDelay = d
}

"""



```