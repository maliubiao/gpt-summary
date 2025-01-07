Response:
The user wants me to analyze a Go code snippet from `go/src/net/http/h2_bundle.go`.
Specifically, this is part 10 of 13.

My plan is to:
1. **Summarize the functionality of this code snippet.**  Based on the code, it seems to handle the core logic of sending HTTP/2 requests, managing client streams, and handling responses.
2. **Identify the Go features implemented.** This involves looking for patterns related to goroutines, channels, mutexes, and error handling.
3. **Provide Go code examples.** Illustrate the identified features with simple examples.
4. **Infer the overall Go feature.**  Based on the code, it's clearly implementing the HTTP/2 client-side transport.
5. **Explain command-line parameters (if any).** This snippet doesn't seem to directly handle command-line arguments.
6. **Point out common mistakes (if any).**  Consider aspects like incorrect header usage or body handling.
7. **Summarize the functionality of this part.** Focus on the specific responsibilities within this section of the code.
这段代码是Go语言 `net/http` 包中 HTTP/2 客户端实现的一部分，主要负责处理 **发送 HTTP/2 请求** 和 **接收响应** 的流程。

**功能归纳 (基于提供的代码片段):**

*   **发起 HTTP/2 请求 (`RoundTrip`)**:
    *   为请求创建一个新的客户端流 (`http2clientStream`)。
    *   设置请求头，包括处理 gzip 压缩的请求头。
    *   异步执行请求发送 (`doRequest`)。
    *   等待请求完成或被取消。
    *   处理响应头，并根据状态码决定是否中止请求体的写入。
    *   处理请求取消的情况，包括等待请求体关闭。
    *   循环等待响应头到达、请求被中止或上下文过期。
*   **执行请求发送 (`doRequest`)**:
    *   标记一个新的 goroutine。
    *   调用 `writeRequest` 实际写入请求。
    *   执行请求后的清理工作 (`cleanupWriteRequest`)。
*   **写入请求 (`writeRequest`)**:
    *   检查连接相关的请求头是否合法。
    *   处理 Extended CONNECT 请求。
    *   获取请求头的互斥锁 (`reqHeaderMu`)，保证并发安全。
    *   获取新的流 ID 并添加到连接的流列表中。
    *   调用 `streamf` 回调函数 (如果存在)。
    *   处理 `Expect: 100-continue` 请求头。
    *   编码并写入请求头 (`encodeAndWriteHeaders`)。
    *   根据请求是否有 body，以及是否需要发送 trailers，来决定是否发送 `END_STREAM` 标志。
    *   写入请求体 (`writeRequestBody`)。
    *   等待对端关闭流或请求被中止。
*   **编码并写入请求头 (`encodeAndWriteHeaders`)**:
    *   获取写入互斥锁 (`wmu`)。
    *   对请求头进行编码，包括处理 trailers 和 content-length。
    *   写入 HEADERS 帧和可能的 CONTINUATION 帧。
*   **清理请求 (`cleanupWriteRequest`)**:
    *   如果请求在创建流之前被取消，则释放流的预留。
    *   关闭请求体 (如果需要)。
    *   如果 `writeRequest` 返回错误且流未关闭，则发送 RST\_STREAM 帧给对端。
    *   更新连接的流列表。
*   **等待流的空闲槽位 (`awaitOpenSlotForStreamLocked`)**:
    *   在可以创建新流之前，等待当前连接的流数量小于 `maxConcurrentStreams`。
*   **写入 HEADERS 帧 (`writeHeaders`)**:
    *   将编码后的请求头数据分片写入 HEADERS 或 CONTINUATION 帧。
*   **写入请求体 (`writeRequestBody`)**:
    *   从请求体读取数据，并根据流量控制和最大帧大小进行分片。
    *   写入 DATA 帧。
    *   处理 trailers。
*   **等待流量控制 (`awaitFlowControl`)**:
    *   等待服务器允许发送更多数据的流量控制窗口。
*   **编码 trailers (`encodeTrailers`)**:
    *   对请求的 trailers 进行编码。
*   **添加流到连接 (`addStreamLocked`)**:
    *   初始化流的流量控制参数，并分配一个新的流 ID。
*   **忘记流 ID (`forgetStreamID`)**:
    *   从连接的流列表中移除指定的流。

**实现的 Go 语言功能:**

1. **Goroutines 和 Channels:**
    *   `go cs.doRequest(req, streamf)`：使用 goroutine 异步执行请求发送。
    *   `cs.donec`, `cs.respHeaderRecv`, `cs.abort`, `cs.reqCancel`, `cs.on100`, `cs.peerClosed`：使用 channel 进行 goroutine 间的通信和同步。例如，`cs.respHeaderRecv` 用于通知响应头已接收。
    *   `cc.seenSettingsChan`:  用于等待接收到 SETTINGS 帧。

    ```go
    package main

    import "fmt"
    import "time"

    func worker(done chan bool) {
        fmt.Println("working...")
        time.Sleep(time.Second)
        fmt.Println("done")
        done <- true
    }

    func main() {
        done := make(chan bool, 1)
        go worker(done)
        <-done // 等待 worker 完成
    }
    ```

    **假设输入:** 无
    **输出:**
    ```
    working...
    (等待一秒)
    done
    ```

2. **Mutexes (`sync.Mutex`) 和 读写锁 (`sync.RWMutex`):**
    *   `cc.mu sync.Mutex`:  用于保护连接级别的共享状态，例如 `cc.streams`, `cc.nextStreamID` 等。
    *   `cc.wmu sync.Mutex`: 用于保护写入相关的操作，例如写入帧。
    *   `cc.reqHeaderMu chan struct{}`:  用作互斥锁，保护分配新流 ID 的过程。

    ```go
    package main

    import (
        "fmt"
        "sync"
        "time"
    )

    var counter int
    var mu sync.Mutex

    func increment() {
        mu.Lock()
        defer mu.Unlock()
        counter++
    }

    func main() {
        for i := 0; i < 1000; i++ {
            go increment()
        }
        time.Sleep(time.Second) // 等待所有 goroutine 完成
        fmt.Println("Counter:", counter)
    }
    ```
    **假设输入:** 无
    **输出:**
    ```
    Counter: 1000
    ```

3. **Context (`context.Context`)**:
    *   `ctx := cs.ctx`:  使用 context 来传递请求的截止时间和取消信号。
    *   `<-ctx.Done()`:  用于监听 context 的取消信号。

    ```go
    package main

    import (
        "context"
        "fmt"
        "time"
    )

    func doWork(ctx context.Context) {
        for {
            select {
            case <-ctx.Done():
                fmt.Println("工作取消:", ctx.Err())
                return
            default:
                fmt.Println("工作中...")
                time.Sleep(500 * time.Millisecond)
            }
        }
    }

    func main() {
        ctx, cancel := context.WithCancel(context.Background())
        go doWork(ctx)
        time.Sleep(2 * time.Second)
        cancel() // 取消工作
        time.Sleep(1 * time.Second)
    }
    ```
    **假设输入:** 无
    **输出:** (时间可能略有不同)
    ```
    工作中...
    工作中...
    工作中...
    工作中...
    工作取消: context canceled
    ```

4. **Errors (`errors.New`, `fmt.Errorf`)**:
    *   定义和处理各种错误，例如 `http2errRequestCanceled`, `http2errExtendedConnectNotSupported`。

    ```go
    package main

    import (
        "errors"
        "fmt"
    )

    var ErrInvalidInput = errors.New("输入无效")

    func processInput(input string) error {
        if input == "" {
            return fmt.Errorf("处理输入时发生错误: %w", ErrInvalidInput)
        }
        fmt.Println("处理输入:", input)
        return nil
    }

    func main() {
        err := processInput("")
        if err != nil {
            fmt.Println(err)
        }
    }
    ```
    **假设输入:** 无
    **输出:**
    ```
    处理输入时发生错误: 输入无效
    ```

**推理出的 Go 语言功能实现:**

这段代码是 Go 语言 `net/http` 包中 **HTTP/2 客户端传输层** 的核心实现部分。它负责建立 HTTP/2 连接，管理并发请求，并处理请求和响应的发送和接收。

**命令行参数:**

这段代码本身不直接处理命令行参数。`net/http` 包的使用者可以通过标准库的方式，例如 `flag` 包，来处理与 HTTP 客户端相关的命令行配置（例如，设置代理、超时时间等），但这些参数的解析和处理是在更高的层次进行的，不会直接体现在这段传输层的代码中。

**使用者易犯错的点:**

这段代码是 `net/http` 内部实现，用户通常不会直接操作它。但是，在使用 `net/http` 发送 HTTP/2 请求时，一些常见的错误可能与这里的功能有关：

1. **不正确的 Header 使用:**  HTTP/2 对 header 有更严格的要求，例如不允许出现某些 connection-specific 的 header。如果用户尝试设置这些 header，可能会导致请求失败。

    ```go
    package main

    import (
        "fmt"
        "net/http"
    )

    func main() {
        client := &http.Client{}
        req, err := http.NewRequest("GET", "https://example.com", nil)
        if err != nil {
            fmt.Println(err)
            return
        }
        req.Header.Set("Connection", "close") // HTTP/2 不允许
        resp, err := client.Do(req)
        if err != nil {
            fmt.Println(err)
            return
        }
        defer resp.Body.Close()
        fmt.Println("Response Status:", resp.Status)
    }
    ```
    在 HTTP/2 下，设置 "Connection" header 通常会被忽略或导致错误。

2. **错误地处理请求体:**  如果请求的 `Content-Length` 与实际发送的 body 大小不符，HTTP/2 会报错。

    ```go
    package main

    import (
        "bytes"
        "fmt"
        "net/http"
        "strings"
    )

    func main() {
        client := &http.Client{}
        body := strings.NewReader("short body")
        req, err := http.NewRequest("POST", "https://example.com", body)
        if err != nil {
            fmt.Println(err)
            return
        }
        req.ContentLength = 100 // 错误的 Content-Length
        resp, err := client.Do(req)
        if err != nil {
            fmt.Println(err)
            return
        }
        defer resp.Body.Close()
        fmt.Println("Response Status:", resp.Status)
    }
    ```
    如果 `ContentLength` 设置错误，服务器可能会拒绝请求。

**这段代码的功能总结 (第 10 部分):**

这段代码主要负责 **处理单个 HTTP/2 请求的生命周期**，从创建流、发送请求头和体、等待响应头、处理响应体，到最后的清理工作。它涉及到请求的构建、发送、流的管理、错误处理以及与连接的交互。 核心功能是 `RoundTrip` 方法及其调用的其他辅助方法，这些方法共同完成了发送和接收 HTTP/2 请求的全过程。

Prompt: 
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第10部分，共13部分，请归纳一下它的功能

"""
rsally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   http://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		cs.requestedGzip = true
	}

	go cs.doRequest(req, streamf)

	waitDone := func() error {
		select {
		case <-cs.donec:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-cs.reqCancel:
			return http2errRequestCanceled
		}
	}

	handleResponseHeaders := func() (*Response, error) {
		res := cs.res
		if res.StatusCode > 299 {
			// On error or status code 3xx, 4xx, 5xx, etc abort any
			// ongoing write, assuming that the server doesn't care
			// about our request body. If the server replied with 1xx or
			// 2xx, however, then assume the server DOES potentially
			// want our body (e.g. full-duplex streaming:
			// golang.org/issue/13444). If it turns out the server
			// doesn't, they'll RST_STREAM us soon enough. This is a
			// heuristic to avoid adding knobs to Transport. Hopefully
			// we can keep it.
			cs.abortRequestBodyWrite()
		}
		res.Request = req
		res.TLS = cc.tlsState
		if res.Body == http2noBody && http2actualContentLength(req) == 0 {
			// If there isn't a request or response body still being
			// written, then wait for the stream to be closed before
			// RoundTrip returns.
			if err := waitDone(); err != nil {
				return nil, err
			}
		}
		return res, nil
	}

	cancelRequest := func(cs *http2clientStream, err error) error {
		cs.cc.mu.Lock()
		bodyClosed := cs.reqBodyClosed
		cs.cc.mu.Unlock()
		// Wait for the request body to be closed.
		//
		// If nothing closed the body before now, abortStreamLocked
		// will have started a goroutine to close it.
		//
		// Closing the body before returning avoids a race condition
		// with net/http checking its readTrackingBody to see if the
		// body was read from or closed. See golang/go#60041.
		//
		// The body is closed in a separate goroutine without the
		// connection mutex held, but dropping the mutex before waiting
		// will keep us from holding it indefinitely if the body
		// close is slow for some reason.
		if bodyClosed != nil {
			<-bodyClosed
		}
		return err
	}

	for {
		select {
		case <-cs.respHeaderRecv:
			return handleResponseHeaders()
		case <-cs.abort:
			select {
			case <-cs.respHeaderRecv:
				// If both cs.respHeaderRecv and cs.abort are signaling,
				// pick respHeaderRecv. The server probably wrote the
				// response and immediately reset the stream.
				// golang.org/issue/49645
				return handleResponseHeaders()
			default:
				waitDone()
				return nil, cs.abortErr
			}
		case <-ctx.Done():
			err := ctx.Err()
			cs.abortStream(err)
			return nil, cancelRequest(cs, err)
		case <-cs.reqCancel:
			cs.abortStream(http2errRequestCanceled)
			return nil, cancelRequest(cs, http2errRequestCanceled)
		}
	}
}

// doRequest runs for the duration of the request lifetime.
//
// It sends the request and performs post-request cleanup (closing Request.Body, etc.).
func (cs *http2clientStream) doRequest(req *Request, streamf func(*http2clientStream)) {
	cs.cc.t.markNewGoroutine()
	err := cs.writeRequest(req, streamf)
	cs.cleanupWriteRequest(err)
}

var http2errExtendedConnectNotSupported = errors.New("net/http: extended connect not supported by peer")

// writeRequest sends a request.
//
// It returns nil after the request is written, the response read,
// and the request stream is half-closed by the peer.
//
// It returns non-nil if the request ends otherwise.
// If the returned error is StreamError, the error Code may be used in resetting the stream.
func (cs *http2clientStream) writeRequest(req *Request, streamf func(*http2clientStream)) (err error) {
	cc := cs.cc
	ctx := cs.ctx

	if err := http2checkConnHeaders(req); err != nil {
		return err
	}

	// wait for setting frames to be received, a server can change this value later,
	// but we just wait for the first settings frame
	var isExtendedConnect bool
	if req.Method == "CONNECT" && req.Header.Get(":protocol") != "" {
		isExtendedConnect = true
	}

	// Acquire the new-request lock by writing to reqHeaderMu.
	// This lock guards the critical section covering allocating a new stream ID
	// (requires mu) and creating the stream (requires wmu).
	if cc.reqHeaderMu == nil {
		panic("RoundTrip on uninitialized ClientConn") // for tests
	}
	if isExtendedConnect {
		select {
		case <-cs.reqCancel:
			return http2errRequestCanceled
		case <-ctx.Done():
			return ctx.Err()
		case <-cc.seenSettingsChan:
			if !cc.extendedConnectAllowed {
				return http2errExtendedConnectNotSupported
			}
		}
	}
	select {
	case cc.reqHeaderMu <- struct{}{}:
	case <-cs.reqCancel:
		return http2errRequestCanceled
	case <-ctx.Done():
		return ctx.Err()
	}

	cc.mu.Lock()
	if cc.idleTimer != nil {
		cc.idleTimer.Stop()
	}
	cc.decrStreamReservationsLocked()
	if err := cc.awaitOpenSlotForStreamLocked(cs); err != nil {
		cc.mu.Unlock()
		<-cc.reqHeaderMu
		return err
	}
	cc.addStreamLocked(cs) // assigns stream ID
	if http2isConnectionCloseRequest(req) {
		cc.doNotReuse = true
	}
	cc.mu.Unlock()

	if streamf != nil {
		streamf(cs)
	}

	continueTimeout := cc.t.expectContinueTimeout()
	if continueTimeout != 0 {
		if !httpguts.HeaderValuesContainsToken(req.Header["Expect"], "100-continue") {
			continueTimeout = 0
		} else {
			cs.on100 = make(chan struct{}, 1)
		}
	}

	// Past this point (where we send request headers), it is possible for
	// RoundTrip to return successfully. Since the RoundTrip contract permits
	// the caller to "mutate or reuse" the Request after closing the Response's Body,
	// we must take care when referencing the Request from here on.
	err = cs.encodeAndWriteHeaders(req)
	<-cc.reqHeaderMu
	if err != nil {
		return err
	}

	hasBody := cs.reqBodyContentLength != 0
	if !hasBody {
		cs.sentEndStream = true
	} else {
		if continueTimeout != 0 {
			http2traceWait100Continue(cs.trace)
			timer := time.NewTimer(continueTimeout)
			select {
			case <-timer.C:
				err = nil
			case <-cs.on100:
				err = nil
			case <-cs.abort:
				err = cs.abortErr
			case <-ctx.Done():
				err = ctx.Err()
			case <-cs.reqCancel:
				err = http2errRequestCanceled
			}
			timer.Stop()
			if err != nil {
				http2traceWroteRequest(cs.trace, err)
				return err
			}
		}

		if err = cs.writeRequestBody(req); err != nil {
			if err != http2errStopReqBodyWrite {
				http2traceWroteRequest(cs.trace, err)
				return err
			}
		} else {
			cs.sentEndStream = true
		}
	}

	http2traceWroteRequest(cs.trace, err)

	var respHeaderTimer <-chan time.Time
	var respHeaderRecv chan struct{}
	if d := cc.responseHeaderTimeout(); d != 0 {
		timer := cc.t.newTimer(d)
		defer timer.Stop()
		respHeaderTimer = timer.C()
		respHeaderRecv = cs.respHeaderRecv
	}
	// Wait until the peer half-closes its end of the stream,
	// or until the request is aborted (via context, error, or otherwise),
	// whichever comes first.
	for {
		select {
		case <-cs.peerClosed:
			return nil
		case <-respHeaderTimer:
			return http2errTimeout
		case <-respHeaderRecv:
			respHeaderRecv = nil
			respHeaderTimer = nil // keep waiting for END_STREAM
		case <-cs.abort:
			return cs.abortErr
		case <-ctx.Done():
			return ctx.Err()
		case <-cs.reqCancel:
			return http2errRequestCanceled
		}
	}
}

func (cs *http2clientStream) encodeAndWriteHeaders(req *Request) error {
	cc := cs.cc
	ctx := cs.ctx

	cc.wmu.Lock()
	defer cc.wmu.Unlock()

	// If the request was canceled while waiting for cc.mu, just quit.
	select {
	case <-cs.abort:
		return cs.abortErr
	case <-ctx.Done():
		return ctx.Err()
	case <-cs.reqCancel:
		return http2errRequestCanceled
	default:
	}

	// Encode headers.
	//
	// we send: HEADERS{1}, CONTINUATION{0,} + DATA{0,} (DATA is
	// sent by writeRequestBody below, along with any Trailers,
	// again in form HEADERS{1}, CONTINUATION{0,})
	trailers, err := http2commaSeparatedTrailers(req)
	if err != nil {
		return err
	}
	hasTrailers := trailers != ""
	contentLen := http2actualContentLength(req)
	hasBody := contentLen != 0
	hdrs, err := cc.encodeHeaders(req, cs.requestedGzip, trailers, contentLen)
	if err != nil {
		return err
	}

	// Write the request.
	endStream := !hasBody && !hasTrailers
	cs.sentHeaders = true
	err = cc.writeHeaders(cs.ID, endStream, int(cc.maxFrameSize), hdrs)
	http2traceWroteHeaders(cs.trace)
	return err
}

// cleanupWriteRequest performs post-request tasks.
//
// If err (the result of writeRequest) is non-nil and the stream is not closed,
// cleanupWriteRequest will send a reset to the peer.
func (cs *http2clientStream) cleanupWriteRequest(err error) {
	cc := cs.cc

	if cs.ID == 0 {
		// We were canceled before creating the stream, so return our reservation.
		cc.decrStreamReservations()
	}

	// TODO: write h12Compare test showing whether
	// Request.Body is closed by the Transport,
	// and in multiple cases: server replies <=299 and >299
	// while still writing request body
	cc.mu.Lock()
	mustCloseBody := false
	if cs.reqBody != nil && cs.reqBodyClosed == nil {
		mustCloseBody = true
		cs.reqBodyClosed = make(chan struct{})
	}
	bodyClosed := cs.reqBodyClosed
	closeOnIdle := cc.singleUse || cc.doNotReuse || cc.t.disableKeepAlives() || cc.goAway != nil
	cc.mu.Unlock()
	if mustCloseBody {
		cs.reqBody.Close()
		close(bodyClosed)
	}
	if bodyClosed != nil {
		<-bodyClosed
	}

	if err != nil && cs.sentEndStream {
		// If the connection is closed immediately after the response is read,
		// we may be aborted before finishing up here. If the stream was closed
		// cleanly on both sides, there is no error.
		select {
		case <-cs.peerClosed:
			err = nil
		default:
		}
	}
	if err != nil {
		cs.abortStream(err) // possibly redundant, but harmless
		if cs.sentHeaders {
			if se, ok := err.(http2StreamError); ok {
				if se.Cause != http2errFromPeer {
					cc.writeStreamReset(cs.ID, se.Code, false, err)
				}
			} else {
				// We're cancelling an in-flight request.
				//
				// This could be due to the server becoming unresponsive.
				// To avoid sending too many requests on a dead connection,
				// we let the request continue to consume a concurrency slot
				// until we can confirm the server is still responding.
				// We do this by sending a PING frame along with the RST_STREAM
				// (unless a ping is already in flight).
				//
				// For simplicity, we don't bother tracking the PING payload:
				// We reset cc.pendingResets any time we receive a PING ACK.
				//
				// We skip this if the conn is going to be closed on idle,
				// because it's short lived and will probably be closed before
				// we get the ping response.
				ping := false
				if !closeOnIdle {
					cc.mu.Lock()
					// rstStreamPingsBlocked works around a gRPC behavior:
					// see comment on the field for details.
					if !cc.rstStreamPingsBlocked {
						if cc.pendingResets == 0 {
							ping = true
						}
						cc.pendingResets++
					}
					cc.mu.Unlock()
				}
				cc.writeStreamReset(cs.ID, http2ErrCodeCancel, ping, err)
			}
		}
		cs.bufPipe.CloseWithError(err) // no-op if already closed
	} else {
		if cs.sentHeaders && !cs.sentEndStream {
			cc.writeStreamReset(cs.ID, http2ErrCodeNo, false, nil)
		}
		cs.bufPipe.CloseWithError(http2errRequestCanceled)
	}
	if cs.ID != 0 {
		cc.forgetStreamID(cs.ID)
	}

	cc.wmu.Lock()
	werr := cc.werr
	cc.wmu.Unlock()
	if werr != nil {
		cc.Close()
	}

	close(cs.donec)
}

// awaitOpenSlotForStreamLocked waits until len(streams) < maxConcurrentStreams.
// Must hold cc.mu.
func (cc *http2ClientConn) awaitOpenSlotForStreamLocked(cs *http2clientStream) error {
	for {
		if cc.closed && cc.nextStreamID == 1 && cc.streamsReserved == 0 {
			// This is the very first request sent to this connection.
			// Return a fatal error which aborts the retry loop.
			return http2errClientConnNotEstablished
		}
		cc.lastActive = cc.t.now()
		if cc.closed || !cc.canTakeNewRequestLocked() {
			return http2errClientConnUnusable
		}
		cc.lastIdle = time.Time{}
		if cc.currentRequestCountLocked() < int(cc.maxConcurrentStreams) {
			return nil
		}
		cc.pendingRequests++
		cc.cond.Wait()
		cc.pendingRequests--
		select {
		case <-cs.abort:
			return cs.abortErr
		default:
		}
	}
}

// requires cc.wmu be held
func (cc *http2ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error {
	first := true // first frame written (HEADERS is first, then CONTINUATION)
	for len(hdrs) > 0 && cc.werr == nil {
		chunk := hdrs
		if len(chunk) > maxFrameSize {
			chunk = chunk[:maxFrameSize]
		}
		hdrs = hdrs[len(chunk):]
		endHeaders := len(hdrs) == 0
		if first {
			cc.fr.WriteHeaders(http2HeadersFrameParam{
				StreamID:      streamID,
				BlockFragment: chunk,
				EndStream:     endStream,
				EndHeaders:    endHeaders,
			})
			first = false
		} else {
			cc.fr.WriteContinuation(streamID, endHeaders, chunk)
		}
	}
	cc.bw.Flush()
	return cc.werr
}

// internal error values; they don't escape to callers
var (
	// abort request body write; don't send cancel
	http2errStopReqBodyWrite = errors.New("http2: aborting request body write")

	// abort request body write, but send stream reset of cancel.
	http2errStopReqBodyWriteAndCancel = errors.New("http2: canceling request")

	http2errReqBodyTooLong = errors.New("http2: request body larger than specified content length")
)

// frameScratchBufferLen returns the length of a buffer to use for
// outgoing request bodies to read/write to/from.
//
// It returns max(1, min(peer's advertised max frame size,
// Request.ContentLength+1, 512KB)).
func (cs *http2clientStream) frameScratchBufferLen(maxFrameSize int) int {
	const max = 512 << 10
	n := int64(maxFrameSize)
	if n > max {
		n = max
	}
	if cl := cs.reqBodyContentLength; cl != -1 && cl+1 < n {
		// Add an extra byte past the declared content-length to
		// give the caller's Request.Body io.Reader a chance to
		// give us more bytes than they declared, so we can catch it
		// early.
		n = cl + 1
	}
	if n < 1 {
		return 1
	}
	return int(n) // doesn't truncate; max is 512K
}

// Seven bufPools manage different frame sizes. This helps to avoid scenarios where long-running
// streaming requests using small frame sizes occupy large buffers initially allocated for prior
// requests needing big buffers. The size ranges are as follows:
// {0 KB, 16 KB], {16 KB, 32 KB], {32 KB, 64 KB], {64 KB, 128 KB], {128 KB, 256 KB],
// {256 KB, 512 KB], {512 KB, infinity}
// In practice, the maximum scratch buffer size should not exceed 512 KB due to
// frameScratchBufferLen(maxFrameSize), thus the "infinity pool" should never be used.
// It exists mainly as a safety measure, for potential future increases in max buffer size.
var http2bufPools [7]sync.Pool // of *[]byte

func http2bufPoolIndex(size int) int {
	if size <= 16384 {
		return 0
	}
	size -= 1
	bits := bits.Len(uint(size))
	index := bits - 14
	if index >= len(http2bufPools) {
		return len(http2bufPools) - 1
	}
	return index
}

func (cs *http2clientStream) writeRequestBody(req *Request) (err error) {
	cc := cs.cc
	body := cs.reqBody
	sentEnd := false // whether we sent the final DATA frame w/ END_STREAM

	hasTrailers := req.Trailer != nil
	remainLen := cs.reqBodyContentLength
	hasContentLen := remainLen != -1

	cc.mu.Lock()
	maxFrameSize := int(cc.maxFrameSize)
	cc.mu.Unlock()

	// Scratch buffer for reading into & writing from.
	scratchLen := cs.frameScratchBufferLen(maxFrameSize)
	var buf []byte
	index := http2bufPoolIndex(scratchLen)
	if bp, ok := http2bufPools[index].Get().(*[]byte); ok && len(*bp) >= scratchLen {
		defer http2bufPools[index].Put(bp)
		buf = *bp
	} else {
		buf = make([]byte, scratchLen)
		defer http2bufPools[index].Put(&buf)
	}

	var sawEOF bool
	for !sawEOF {
		n, err := body.Read(buf)
		if hasContentLen {
			remainLen -= int64(n)
			if remainLen == 0 && err == nil {
				// The request body's Content-Length was predeclared and
				// we just finished reading it all, but the underlying io.Reader
				// returned the final chunk with a nil error (which is one of
				// the two valid things a Reader can do at EOF). Because we'd prefer
				// to send the END_STREAM bit early, double-check that we're actually
				// at EOF. Subsequent reads should return (0, EOF) at this point.
				// If either value is different, we return an error in one of two ways below.
				var scratch [1]byte
				var n1 int
				n1, err = body.Read(scratch[:])
				remainLen -= int64(n1)
			}
			if remainLen < 0 {
				err = http2errReqBodyTooLong
				return err
			}
		}
		if err != nil {
			cc.mu.Lock()
			bodyClosed := cs.reqBodyClosed != nil
			cc.mu.Unlock()
			switch {
			case bodyClosed:
				return http2errStopReqBodyWrite
			case err == io.EOF:
				sawEOF = true
				err = nil
			default:
				return err
			}
		}

		remain := buf[:n]
		for len(remain) > 0 && err == nil {
			var allowed int32
			allowed, err = cs.awaitFlowControl(len(remain))
			if err != nil {
				return err
			}
			cc.wmu.Lock()
			data := remain[:allowed]
			remain = remain[allowed:]
			sentEnd = sawEOF && len(remain) == 0 && !hasTrailers
			err = cc.fr.WriteData(cs.ID, sentEnd, data)
			if err == nil {
				// TODO(bradfitz): this flush is for latency, not bandwidth.
				// Most requests won't need this. Make this opt-in or
				// opt-out?  Use some heuristic on the body type? Nagel-like
				// timers?  Based on 'n'? Only last chunk of this for loop,
				// unless flow control tokens are low? For now, always.
				// If we change this, see comment below.
				err = cc.bw.Flush()
			}
			cc.wmu.Unlock()
		}
		if err != nil {
			return err
		}
	}

	if sentEnd {
		// Already sent END_STREAM (which implies we have no
		// trailers) and flushed, because currently all
		// WriteData frames above get a flush. So we're done.
		return nil
	}

	// Since the RoundTrip contract permits the caller to "mutate or reuse"
	// a request after the Response's Body is closed, verify that this hasn't
	// happened before accessing the trailers.
	cc.mu.Lock()
	trailer := req.Trailer
	err = cs.abortErr
	cc.mu.Unlock()
	if err != nil {
		return err
	}

	cc.wmu.Lock()
	defer cc.wmu.Unlock()
	var trls []byte
	if len(trailer) > 0 {
		trls, err = cc.encodeTrailers(trailer)
		if err != nil {
			return err
		}
	}

	// Two ways to send END_STREAM: either with trailers, or
	// with an empty DATA frame.
	if len(trls) > 0 {
		err = cc.writeHeaders(cs.ID, true, maxFrameSize, trls)
	} else {
		err = cc.fr.WriteData(cs.ID, true, nil)
	}
	if ferr := cc.bw.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	return err
}

// awaitFlowControl waits for [1, min(maxBytes, cc.cs.maxFrameSize)] flow
// control tokens from the server.
// It returns either the non-zero number of tokens taken or an error
// if the stream is dead.
func (cs *http2clientStream) awaitFlowControl(maxBytes int) (taken int32, err error) {
	cc := cs.cc
	ctx := cs.ctx
	cc.mu.Lock()
	defer cc.mu.Unlock()
	for {
		if cc.closed {
			return 0, http2errClientConnClosed
		}
		if cs.reqBodyClosed != nil {
			return 0, http2errStopReqBodyWrite
		}
		select {
		case <-cs.abort:
			return 0, cs.abortErr
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-cs.reqCancel:
			return 0, http2errRequestCanceled
		default:
		}
		if a := cs.flow.available(); a > 0 {
			take := a
			if int(take) > maxBytes {

				take = int32(maxBytes) // can't truncate int; take is int32
			}
			if take > int32(cc.maxFrameSize) {
				take = int32(cc.maxFrameSize)
			}
			cs.flow.take(take)
			return take, nil
		}
		cc.cond.Wait()
	}
}

func http2validateHeaders(hdrs Header) string {
	for k, vv := range hdrs {
		if !httpguts.ValidHeaderFieldName(k) && k != ":protocol" {
			return fmt.Sprintf("name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// Don't include the value in the error,
				// because it may be sensitive.
				return fmt.Sprintf("value for header %q", k)
			}
		}
	}
	return ""
}

var http2errNilRequestURL = errors.New("http2: Request.URI is nil")

func http2isNormalConnect(req *Request) bool {
	return req.Method == "CONNECT" && req.Header.Get(":protocol") == ""
}

// requires cc.wmu be held.
func (cc *http2ClientConn) encodeHeaders(req *Request, addGzipHeader bool, trailers string, contentLength int64) ([]byte, error) {
	cc.hbuf.Reset()
	if req.URL == nil {
		return nil, http2errNilRequestURL
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return nil, err
	}
	if !httpguts.ValidHostHeader(host) {
		return nil, errors.New("http2: invalid Host header")
	}

	var path string
	if !http2isNormalConnect(req) {
		path = req.URL.RequestURI()
		if !http2validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !http2validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return nil, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return nil, fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	// Check for any invalid headers+trailers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	if err := http2validateHeaders(req.Header); err != "" {
		return nil, fmt.Errorf("invalid HTTP header %s", err)
	}
	if err := http2validateHeaders(req.Trailer); err != "" {
		return nil, fmt.Errorf("invalid HTTP trailer %s", err)
	}

	enumerateHeaders := func(f func(name, value string)) {
		// 8.1.2.3 Request Pseudo-Header Fields
		// The :path pseudo-header field includes the path and query parts of the
		// target URI (the path-absolute production and optionally a '?' character
		// followed by the query production, see Sections 3.3 and 3.4 of
		// [RFC3986]).
		f(":authority", host)
		m := req.Method
		if m == "" {
			m = MethodGet
		}
		f(":method", m)
		if !http2isNormalConnect(req) {
			f(":path", path)
			f(":scheme", req.URL.Scheme)
		}
		if trailers != "" {
			f("trailer", trailers)
		}

		var didUA bool
		for k, vv := range req.Header {
			if http2asciiEqualFold(k, "host") || http2asciiEqualFold(k, "content-length") {
				// Host is :authority, already sent.
				// Content-Length is automatic, set below.
				continue
			} else if http2asciiEqualFold(k, "connection") ||
				http2asciiEqualFold(k, "proxy-connection") ||
				http2asciiEqualFold(k, "transfer-encoding") ||
				http2asciiEqualFold(k, "upgrade") ||
				http2asciiEqualFold(k, "keep-alive") {
				// Per 8.1.2.2 Connection-Specific Header
				// Fields, don't send connection-specific
				// fields. We have already checked if any
				// are error-worthy so just ignore the rest.
				continue
			} else if http2asciiEqualFold(k, "user-agent") {
				// Match Go's http1 behavior: at most one
				// User-Agent. If set to nil or empty string,
				// then omit it. Otherwise if not mentioned,
				// include the default (below).
				didUA = true
				if len(vv) < 1 {
					continue
				}
				vv = vv[:1]
				if vv[0] == "" {
					continue
				}
			} else if http2asciiEqualFold(k, "cookie") {
				// Per 8.1.2.5 To allow for better compression efficiency, the
				// Cookie header field MAY be split into separate header fields,
				// each with one or more cookie-pairs.
				for _, v := range vv {
					for {
						p := strings.IndexByte(v, ';')
						if p < 0 {
							break
						}
						f("cookie", v[:p])
						p++
						// strip space after semicolon if any.
						for p+1 <= len(v) && v[p] == ' ' {
							p++
						}
						v = v[p:]
					}
					if len(v) > 0 {
						f("cookie", v)
					}
				}
				continue
			}

			for _, v := range vv {
				f(k, v)
			}
		}
		if http2shouldSendReqContentLength(req.Method, contentLength) {
			f("content-length", strconv.FormatInt(contentLength, 10))
		}
		if addGzipHeader {
			f("accept-encoding", "gzip")
		}
		if !didUA {
			f("user-agent", http2defaultUserAgent)
		}
	}

	// Do a first pass over the headers counting bytes to ensure
	// we don't exceed cc.peerMaxHeaderListSize. This is done as a
	// separate pass before encoding the headers to prevent
	// modifying the hpack state.
	hlSize := uint64(0)
	enumerateHeaders(func(name, value string) {
		hf := hpack.HeaderField{Name: name, Value: value}
		hlSize += uint64(hf.Size())
	})

	if hlSize > cc.peerMaxHeaderListSize {
		return nil, http2errRequestHeaderListSize
	}

	trace := httptrace.ContextClientTrace(req.Context())
	traceHeaders := http2traceHasWroteHeaderField(trace)

	// Header list size is ok. Write the headers.
	enumerateHeaders(func(name, value string) {
		name, ascii := http2lowerHeader(name)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			return
		}
		cc.writeHeader(name, value)
		if traceHeaders {
			http2traceWroteHeaderField(trace, name, value)
		}
	})

	return cc.hbuf.Bytes(), nil
}

// shouldSendReqContentLength reports whether the http2.Transport should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func http2shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// requires cc.wmu be held.
func (cc *http2ClientConn) encodeTrailers(trailer Header) ([]byte, error) {
	cc.hbuf.Reset()

	hlSize := uint64(0)
	for k, vv := range trailer {
		for _, v := range vv {
			hf := hpack.HeaderField{Name: k, Value: v}
			hlSize += uint64(hf.Size())
		}
	}
	if hlSize > cc.peerMaxHeaderListSize {
		return nil, http2errRequestHeaderListSize
	}

	for k, vv := range trailer {
		lowKey, ascii := http2lowerHeader(k)
		if !ascii {
			// Skip writing invalid headers. Per RFC 7540, Section 8.1.2, header
			// field names have to be ASCII characters (just as in HTTP/1.x).
			continue
		}
		// Transfer-Encoding, etc.. have already been filtered at the
		// start of RoundTrip
		for _, v := range vv {
			cc.writeHeader(lowKey, v)
		}
	}
	return cc.hbuf.Bytes(), nil
}

func (cc *http2ClientConn) writeHeader(name, value string) {
	if http2VerboseLogs {
		log.Printf("http2: Transport encoding header %q = %q", name, value)
	}
	cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

type http2resAndError struct {
	_   http2incomparable
	res *Response
	err error
}

// requires cc.mu be held.
func (cc *http2ClientConn) addStreamLocked(cs *http2clientStream) {
	cs.flow.add(int32(cc.initialWindowSize))
	cs.flow.setConnFlow(&cc.flow)
	cs.inflow.init(cc.initialStreamRecvWindowSize)
	cs.ID = cc.nextStreamID
	cc.nextStreamID += 2
	cc.streams[cs.ID] = cs
	if cs.ID == 0 {
		panic("assigned stream ID 0")
	}
}

func (cc *http2ClientConn) forgetStreamID(id uint32) {
	cc.mu.Lock()
	slen := len(cc.streams)
	delete(cc.streams, id)
	if len(cc.streams) != slen-1 {
		panic("forgetting unknown stream id")
	}
	cc.lastActive = cc.t.now()
	if len(cc.streams) == 0 && cc.idleTimer != nil {
		cc.idleTimer.Reset(cc.idleTimeout)
		cc.lastIdle = cc.t.now()
	}
	// Wake up writeRequestBody via clientStream.awaitFlowControl and
	// wake up RoundTrip if there is a pending request.
	cc.cond.Broadcast()

	closeOnIdle := cc.singleUse || cc.doNotReuse || cc.t.disableKeepAlives() || cc.goAway != nil
	if closeOnIdle && cc.streamsReserved == 0 && len(cc.streams) == 0 {
		if http2VerboseLogs {
			cc.vlogf("http2: Transport closing idle conn %p (forSingleUse=%v, maxStream=%v)", cc, cc.singleUse, cc.nextStreamID-2)
		}
		cc.closed = true
		defer cc.closeConn()
	}

	cc.mu.Unlock()
}

// clientConnReadLoop is the state owned by the clientConn's frame-reading readLoop.
type http2clientConnReadLoop struct {
	_  http2incomparable
	cc *http2ClientConn
}

// readLoop runs in its own goroutine and reads and dispatches frames.
func (cc *http2ClientConn) readLoop() {
	cc.t.markNewGoroutine()
	rl := &http2clientConnReadLoop{cc: cc}
	defer rl.cleanup()
	cc.readerErr = rl.run()
	if ce, ok := cc.readerErr.(http2ConnectionError); ok {
		cc.wmu.Lock()
		cc.fr.WriteGoAway(0, http2ErrCode(ce), nil)
		cc.wmu.Unlock()
	}
}

// GoAwayError is returned by the Transport when the server closes the
// TCP connection after sending a GOAWAY frame.
type http2GoAwayError struct {
	LastStreamID uint32
	ErrCode      http2ErrCode
	DebugData    string
}

func (e http2GoAwayError) Error() string {
	return fmt.Sprintf("http2: server sent GOAWAY and closed the connection; LastStreamID=%v, ErrCode=%v, debug=%q",
		e.LastStreamID, e.ErrCode, e.DebugData)
}

func http2isEOFOrNetReadError(err error) bool {
	if err == io.EOF {
		return true
	}
	ne, ok := err.(*net.OpError)
	return ok && ne.Op == "read"
}

func (rl *http2clientConnReadLoop) cleanup() {
	cc := rl.cc
	defer cc.closeConn()
	defer close(cc.readerDone)

	if cc.idleTimer != nil {
		cc.idleTimer.Stop()
	}

	// Close any response bodies if the server closes prematurely.
	// TODO: also do this if we've written the headers but not
	// gotten a response yet.
	err := cc.readerErr
	cc.mu.Lock()
	if cc.goAway != nil && http2isEOFOrNetReadError(err) {
		err = http2GoAwayError{
			LastStreamID: cc.goAway.LastStreamID,
			ErrCode:      cc.goAway.ErrCode,
			DebugData:    cc.goAwayDebug,
		}
	} else if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	cc.closed = true

	// If the connection has never been used, and has been open for only a short time,
	// leave it in the connection pool for a little while.
	//
	// This avoids a situation where new connections are constantly created,
	// added to the pool, fail, and are removed from the pool, without any error
	// being surfaced to the user.
	const unusedWaitTime = 5 * time.Second
	idleTime := cc.t.now().Sub(cc.lastActive)
	if atomic.LoadUint32(&cc.atomicReused) == 0 && idleTime < unusedWaitTime {
		cc.idleTimer = cc.t.afterFunc(unusedWaitTime-idleTime, func() {
			cc.t.connPool().MarkDead(cc)
		})
	} else {
		cc.mu.Unlock() // avoid any deadlocks in MarkDead
		cc.t.connPool().MarkDead(cc)
		cc.mu.Lock()
	}

	for _, cs := range cc.streams {
		select {
		case <-cs.peerClosed:
			// The server closed the stream before closing the conn,
			// so no need to interrupt it.
		default:
			cs.abortStreamLocked(err)
		}
	}
	cc.cond.Broadcast()
	cc.mu.Unlock()
}

// countReadFrameError calls Transport.CountError with a string
// representing err.
func (cc *http2ClientConn) countReadFrameError(err error) {
	f := cc.t.CountError
	if f == nil || err == nil {
		return
	}
	if ce, ok := err.(http2ConnectionError); ok {
		errCode := http2ErrCode(ce)
		f(fmt.Sprintf("read_frame_conn_error_%s", errCode.stringToken()))
		return
	}
	if errors.Is(err, io.EOF) {
		f("read_frame_eof")
		return
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		f("read_frame_unexpected_eof")
		return
	}
	if errors.Is(err, http2ErrFrameTooLarge) {
		f("read_frame_too_large")
		return
	}
	f("read_frame_other")
}

func (rl *http2clientConnReadLoop) run() error {
	cc := rl.cc
	gotSettings := false
	readIdleTimeout := cc.readIdleTimeout
	var t http2timer
	if readIdleTimeout != 0 {
		t = cc.t.afterFunc(readIdleTimeout, cc.healthCheck)
	}
	for {
		f, err := cc.fr.ReadFrame()
		if t != nil {
			t.Reset(readIdleTimeout)
		}
		if err != nil {
			cc.vlogf("http2: Transport readFrame error on conn %p: (%T) %v", cc, err, err)
		}
		if se, ok := err.(http2StreamError); ok {
			if cs := rl.streamByID(se.StreamID, http2notHeaderOrDataFrame); cs != nil {
				if se.Cause == nil {
					se.Cause = cc.fr.errDetail
				}
				rl.endStreamError(cs, se)
			}
			continue
		} else if err != nil {
			cc.countReadFrameError(err)
			return err
		}
		if http2VerboseLogs {
			cc.vlogf("http2: Transport received %s", http2summarizeFrame(f))
		}
		if !gotSettings {
			if _, ok := f.(*http2SettingsFrame); !ok {
				cc.logf("protocol error: received %T before a SETTINGS frame", f)
				return http2ConnectionError(http2ErrCodeProtocol)
			}
			gotSettings = true
		}

		switch f := f.(type) {
		case *http2MetaHeadersFrame:
			err = rl.processHeaders(f)
		case *http2DataFrame:
			err = rl.processData(f)
		case *http2GoAwayFrame:
			err = rl.processGoAway(f)
		case *http2RSTStreamFrame:
			err = rl.processResetStream(f)
		case *http2SettingsFrame:
			
"""




```