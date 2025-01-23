Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the `transport_test.go` file in the `net/http` package.

My plan is to:
1. Read through the code and identify the different test functions and their purposes based on their names and the operations they perform.
2. Group related tests together and summarize their collective function.
3. Pay attention to the imported packages, as they often hint at the areas being tested (e.g., `crypto/tls`, `net`, `compress/gzip`).
4. Note any helper functions or data structures defined within the snippet, as they are likely used by the tests.这段Go代码是 `net/http` 包中 `transport_test.go` 文件的一部分，主要功能是**测试 `http.Transport` 的各种行为和特性**。

具体来说，从提供的代码片段中，可以归纳出以下功能测试点：

1. **连接复用和关闭:**
   - 测试 `Transport` 是否正确地复用连接（keep-alive）以及在各种情况下关闭连接，例如服务器发送 `Connection: close` 头部、客户端设置 `Request.Close` 为 `true`、以及 `Transport` 设置 `DisableKeepAlives`。
   - 使用 `testConnSet` 和 `makeTestDial` 辅助跟踪和检查连接的关闭状态。

2. **请求的重用:**
   - 测试客户端是否可以重用同一个 `Request` 对象进行多次请求。

3. **`Connection: close` 的处理:**
   - 测试 `Transport` 在接收到服务端 `Connection: close` 响应头后的行为，验证是否会断开连接。
   - 测试 `Transport` 在 `Request` 设置了 `Close` 属性时，是否会在请求头中发送 `Connection: close`。
   - 测试当 `Transport` 的 `DisableKeepAlives` 设置为 `true` 时，是否所有请求都会发送 `Connection: close`。
   - 验证当多种方式（`DisableKeepAlives` 和 `Request.Close`）都要求关闭连接时，`Transport` 只发送一个 `Connection: close` 头部。

4. **空闲连接缓存的管理:**
   - 测试 `Transport` 如何管理空闲连接的缓存，包括缓存键的生成和关闭空闲连接。

5. **读取完响应体后的连接复用:**
   - 测试当客户端读取完响应体而没有显式关闭时，连接是否会被 `Transport` 复用。

6. **`MaxIdleConnsPerHost` 的限制:**
   - 测试 `Transport` 的 `MaxIdleConnsPerHost` 选项是否生效，限制每个主机保持的空闲连接数。

7. **`MaxConnsPerHost` 的限制:**
   - 测试 `Transport` 的 `MaxConnsPerHost` 选项是否生效，限制每个主机的并发连接数，包括正在建立连接的连接。
   - 测试在 `MaxConnsPerHost` 限制下，当连接数达到上限时，新的连接请求是否会被阻塞，以及在连接建立过程中被取消的情况。

8. **清理失效的空闲连接:**
   - 测试 `Transport` 是否能够检测并移除服务端意外关闭的空闲连接。

9. **处理服务端意外断开连接的情况:**
   - 测试当服务器在保持连接的情况下意外关闭连接时，客户端 `Transport` 的处理行为和重试机制。

10. **压力测试服务端意外断开连接:**
    - 进行高并发的请求，模拟服务端在发送部分响应后断开连接的情况，验证客户端的健壮性。

11. **处理 HEAD 请求:**
    - 测试 `Transport` 如何处理 `HEAD` 请求的响应，包括 `Content-Length` 头部和空响应体。
    - 测试 `Transport` 在接收到 `HEAD` 请求的 chunked 响应时，是否会忽略 `Transfer-Encoding: chunked` 头部。

12. **处理 Gzip 压缩:**
    - 测试 `Transport` 是否正确处理服务端返回的 Gzip 压缩的响应。
    - 测试 `Transport` 在发送请求时，在没有设置 `Accept-Encoding` 的情况下，是否会自动添加 `Accept-Encoding: gzip`。
    - 测试 `RoundTrip` 方法是否会修改原始的 `Request` 对象的头部，以及返回的 `Response` 对象的头部信息。

总而言之，这段代码主要关注 `http.Transport` 作为 HTTP 客户端的核心组件，在连接管理、请求处理、以及与服务器交互的各种场景下的正确性和健壮性。

### 提示词
```
这是路径为go/src/net/http/transport_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for transport.go.
//
// More tests are in clientserver_test.go (for things testing both client & server for both
// HTTP/1 and HTTP/2). This

package http_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"go/token"
	"internal/nettrace"
	"internal/synctest"
	"io"
	"log"
	mrand "math/rand"
	"net"
	. "net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"net/http/internal/testcert"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/net/http/httpguts"
)

// TODO: test 5 pipelined requests with responses: 1) OK, 2) OK, Connection: Close
// and then verify that the final 2 responses get errors back.

// hostPortHandler writes back the client's "host:port".
var hostPortHandler = HandlerFunc(func(w ResponseWriter, r *Request) {
	if r.FormValue("close") == "true" {
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("X-Saw-Close", fmt.Sprint(r.Close))
	w.Write([]byte(r.RemoteAddr))

	// Include the address of the net.Conn in addition to the RemoteAddr,
	// in case kernels reuse source ports quickly (see Issue 52450)
	if c, ok := ResponseWriterConnForTesting(w); ok {
		fmt.Fprintf(w, ", %T %p", c, c)
	}
})

// testCloseConn is a net.Conn tracked by a testConnSet.
type testCloseConn struct {
	net.Conn
	set *testConnSet
}

func (c *testCloseConn) Close() error {
	c.set.remove(c)
	return c.Conn.Close()
}

// testConnSet tracks a set of TCP connections and whether they've
// been closed.
type testConnSet struct {
	t      *testing.T
	mu     sync.Mutex // guards closed and list
	closed map[net.Conn]bool
	list   []net.Conn // in order created
}

func (tcs *testConnSet) insert(c net.Conn) {
	tcs.mu.Lock()
	defer tcs.mu.Unlock()
	tcs.closed[c] = false
	tcs.list = append(tcs.list, c)
}

func (tcs *testConnSet) remove(c net.Conn) {
	tcs.mu.Lock()
	defer tcs.mu.Unlock()
	tcs.closed[c] = true
}

// some tests use this to manage raw tcp connections for later inspection
func makeTestDial(t *testing.T) (*testConnSet, func(n, addr string) (net.Conn, error)) {
	connSet := &testConnSet{
		t:      t,
		closed: make(map[net.Conn]bool),
	}
	dial := func(n, addr string) (net.Conn, error) {
		c, err := net.Dial(n, addr)
		if err != nil {
			return nil, err
		}
		tc := &testCloseConn{c, connSet}
		connSet.insert(tc)
		return tc, nil
	}
	return connSet, dial
}

func (tcs *testConnSet) check(t *testing.T) {
	tcs.mu.Lock()
	defer tcs.mu.Unlock()
	for i := 4; i >= 0; i-- {
		for i, c := range tcs.list {
			if tcs.closed[c] {
				continue
			}
			if i != 0 {
				// TODO(bcmills): What is the Sleep here doing, and why is this
				// Unlock/Sleep/Lock cycle needed at all?
				tcs.mu.Unlock()
				time.Sleep(50 * time.Millisecond)
				tcs.mu.Lock()
				continue
			}
			t.Errorf("TCP connection #%d, %p (of %d total) was not closed", i+1, c, len(tcs.list))
		}
	}
}

func TestReuseRequest(t *testing.T) { run(t, testReuseRequest) }
func testReuseRequest(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Write([]byte("{}"))
	})).ts

	c := ts.Client()
	req, _ := NewRequest("GET", ts.URL, nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	err = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	res, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	err = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Two subsequent requests and verify their response is the same.
// The response from the server is our own IP:port
func TestTransportKeepAlives(t *testing.T) { run(t, testTransportKeepAlives, []testMode{http1Mode}) }
func testTransportKeepAlives(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, hostPortHandler).ts

	c := ts.Client()
	for _, disableKeepAlive := range []bool{false, true} {
		c.Transport.(*Transport).DisableKeepAlives = disableKeepAlive
		fetch := func(n int) string {
			res, err := c.Get(ts.URL)
			if err != nil {
				t.Fatalf("error in disableKeepAlive=%v, req #%d, GET: %v", disableKeepAlive, n, err)
			}
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("error in disableKeepAlive=%v, req #%d, ReadAll: %v", disableKeepAlive, n, err)
			}
			return string(body)
		}

		body1 := fetch(1)
		body2 := fetch(2)

		bodiesDiffer := body1 != body2
		if bodiesDiffer != disableKeepAlive {
			t.Errorf("error in disableKeepAlive=%v. unexpected bodiesDiffer=%v; body1=%q; body2=%q",
				disableKeepAlive, bodiesDiffer, body1, body2)
		}
	}
}

func TestTransportConnectionCloseOnResponse(t *testing.T) {
	run(t, testTransportConnectionCloseOnResponse)
}
func testTransportConnectionCloseOnResponse(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, hostPortHandler).ts

	connSet, testDial := makeTestDial(t)

	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.Dial = testDial

	for _, connectionClose := range []bool{false, true} {
		fetch := func(n int) string {
			req := new(Request)
			var err error
			req.URL, err = url.Parse(ts.URL + fmt.Sprintf("/?close=%v", connectionClose))
			if err != nil {
				t.Fatalf("URL parse error: %v", err)
			}
			req.Method = "GET"
			req.Proto = "HTTP/1.1"
			req.ProtoMajor = 1
			req.ProtoMinor = 1

			res, err := c.Do(req)
			if err != nil {
				t.Fatalf("error in connectionClose=%v, req #%d, Do: %v", connectionClose, n, err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("error in connectionClose=%v, req #%d, ReadAll: %v", connectionClose, n, err)
			}
			return string(body)
		}

		body1 := fetch(1)
		body2 := fetch(2)
		bodiesDiffer := body1 != body2
		if bodiesDiffer != connectionClose {
			t.Errorf("error in connectionClose=%v. unexpected bodiesDiffer=%v; body1=%q; body2=%q",
				connectionClose, bodiesDiffer, body1, body2)
		}

		tr.CloseIdleConnections()
	}

	connSet.check(t)
}

// TestTransportConnectionCloseOnRequest tests that the Transport's doesn't reuse
// an underlying TCP connection after making an http.Request with Request.Close set.
//
// It tests the behavior by making an HTTP request to a server which
// describes the source connection it got (remote port number +
// address of its net.Conn).
func TestTransportConnectionCloseOnRequest(t *testing.T) {
	run(t, testTransportConnectionCloseOnRequest, []testMode{http1Mode})
}
func testTransportConnectionCloseOnRequest(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, hostPortHandler).ts

	connSet, testDial := makeTestDial(t)

	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.Dial = testDial
	for _, reqClose := range []bool{false, true} {
		fetch := func(n int) string {
			req := new(Request)
			var err error
			req.URL, err = url.Parse(ts.URL)
			if err != nil {
				t.Fatalf("URL parse error: %v", err)
			}
			req.Method = "GET"
			req.Proto = "HTTP/1.1"
			req.ProtoMajor = 1
			req.ProtoMinor = 1
			req.Close = reqClose

			res, err := c.Do(req)
			if err != nil {
				t.Fatalf("error in Request.Close=%v, req #%d, Do: %v", reqClose, n, err)
			}
			if got, want := res.Header.Get("X-Saw-Close"), fmt.Sprint(reqClose); got != want {
				t.Errorf("for Request.Close = %v; handler's X-Saw-Close was %v; want %v",
					reqClose, got, !reqClose)
			}
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("for Request.Close=%v, on request %v/2: ReadAll: %v", reqClose, n, err)
			}
			return string(body)
		}

		body1 := fetch(1)
		body2 := fetch(2)

		got := 1
		if body1 != body2 {
			got++
		}
		want := 1
		if reqClose {
			want = 2
		}
		if got != want {
			t.Errorf("for Request.Close=%v: server saw %v unique connections, wanted %v\n\nbodies were: %q and %q",
				reqClose, got, want, body1, body2)
		}

		tr.CloseIdleConnections()
	}

	connSet.check(t)
}

// if the Transport's DisableKeepAlives is set, all requests should
// send Connection: close.
// HTTP/1-only (Connection: close doesn't exist in h2)
func TestTransportConnectionCloseOnRequestDisableKeepAlive(t *testing.T) {
	run(t, testTransportConnectionCloseOnRequestDisableKeepAlive, []testMode{http1Mode})
}
func testTransportConnectionCloseOnRequestDisableKeepAlive(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, hostPortHandler).ts

	c := ts.Client()
	c.Transport.(*Transport).DisableKeepAlives = true

	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("X-Saw-Close") != "true" {
		t.Errorf("handler didn't see Connection: close ")
	}
}

// Test that Transport only sends one "Connection: close", regardless of
// how "close" was indicated.
func TestTransportRespectRequestWantsClose(t *testing.T) {
	run(t, testTransportRespectRequestWantsClose, []testMode{http1Mode})
}
func testTransportRespectRequestWantsClose(t *testing.T, mode testMode) {
	tests := []struct {
		disableKeepAlives bool
		close             bool
	}{
		{disableKeepAlives: false, close: false},
		{disableKeepAlives: false, close: true},
		{disableKeepAlives: true, close: false},
		{disableKeepAlives: true, close: true},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("DisableKeepAlive=%v,RequestClose=%v", tc.disableKeepAlives, tc.close),
			func(t *testing.T) {
				ts := newClientServerTest(t, mode, hostPortHandler).ts

				c := ts.Client()
				c.Transport.(*Transport).DisableKeepAlives = tc.disableKeepAlives
				req, err := NewRequest("GET", ts.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				trace := &httptrace.ClientTrace{
					WroteHeaderField: func(key string, field []string) {
						if key != "Connection" {
							return
						}
						if httpguts.HeaderValuesContainsToken(field, "close") {
							count += 1
						}
					},
				}
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
				req.Close = tc.close
				res, err := c.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if want := tc.disableKeepAlives || tc.close; count > 1 || (count == 1) != want {
					t.Errorf("expecting want:%v, got 'Connection: close':%d", want, count)
				}
			})
	}

}

func TestTransportIdleCacheKeys(t *testing.T) {
	run(t, testTransportIdleCacheKeys, []testMode{http1Mode})
}
func testTransportIdleCacheKeys(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, hostPortHandler).ts
	c := ts.Client()
	tr := c.Transport.(*Transport)

	if e, g := 0, len(tr.IdleConnKeysForTesting()); e != g {
		t.Errorf("After CloseIdleConnections expected %d idle conn cache keys; got %d", e, g)
	}

	resp, err := c.Get(ts.URL)
	if err != nil {
		t.Error(err)
	}
	io.ReadAll(resp.Body)

	keys := tr.IdleConnKeysForTesting()
	if e, g := 1, len(keys); e != g {
		t.Fatalf("After Get expected %d idle conn cache keys; got %d", e, g)
	}

	if e := "|http|" + ts.Listener.Addr().String(); keys[0] != e {
		t.Errorf("Expected idle cache key %q; got %q", e, keys[0])
	}

	tr.CloseIdleConnections()
	if e, g := 0, len(tr.IdleConnKeysForTesting()); e != g {
		t.Errorf("After CloseIdleConnections expected %d idle conn cache keys; got %d", e, g)
	}
}

// Tests that the HTTP transport re-uses connections when a client
// reads to the end of a response Body without closing it.
func TestTransportReadToEndReusesConn(t *testing.T) { run(t, testTransportReadToEndReusesConn) }
func testTransportReadToEndReusesConn(t *testing.T, mode testMode) {
	const msg = "foobar"

	var addrSeen map[string]int
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		addrSeen[r.RemoteAddr]++
		if r.URL.Path == "/chunked/" {
			w.WriteHeader(200)
			w.(Flusher).Flush()
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(msg)))
			w.WriteHeader(200)
		}
		w.Write([]byte(msg))
	})).ts

	for pi, path := range []string{"/content-length/", "/chunked/"} {
		wantLen := []int{len(msg), -1}[pi]
		addrSeen = make(map[string]int)
		for i := 0; i < 3; i++ {
			res, err := ts.Client().Get(ts.URL + path)
			if err != nil {
				t.Errorf("Get %s: %v", path, err)
				continue
			}
			// We want to close this body eventually (before the
			// defer afterTest at top runs), but not before the
			// len(addrSeen) check at the bottom of this test,
			// since Closing this early in the loop would risk
			// making connections be re-used for the wrong reason.
			defer res.Body.Close()

			if res.ContentLength != int64(wantLen) {
				t.Errorf("%s res.ContentLength = %d; want %d", path, res.ContentLength, wantLen)
			}
			got, err := io.ReadAll(res.Body)
			if string(got) != msg || err != nil {
				t.Errorf("%s ReadAll(Body) = %q, %v; want %q, nil", path, string(got), err, msg)
			}
		}
		if len(addrSeen) != 1 {
			t.Errorf("for %s, server saw %d distinct client addresses; want 1", path, len(addrSeen))
		}
	}
}

func TestTransportMaxPerHostIdleConns(t *testing.T) {
	run(t, testTransportMaxPerHostIdleConns, []testMode{http1Mode})
}
func testTransportMaxPerHostIdleConns(t *testing.T, mode testMode) {
	stop := make(chan struct{}) // stop marks the exit of main Test goroutine
	defer close(stop)

	resch := make(chan string)
	gotReq := make(chan bool)
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		gotReq <- true
		var msg string
		select {
		case <-stop:
			return
		case msg = <-resch:
		}
		_, err := w.Write([]byte(msg))
		if err != nil {
			t.Errorf("Write: %v", err)
			return
		}
	})).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)
	maxIdleConnsPerHost := 2
	tr.MaxIdleConnsPerHost = maxIdleConnsPerHost

	// Start 3 outstanding requests and wait for the server to get them.
	// Their responses will hang until we write to resch, though.
	donech := make(chan bool)
	doReq := func() {
		defer func() {
			select {
			case <-stop:
				return
			case donech <- t.Failed():
			}
		}()
		resp, err := c.Get(ts.URL)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Errorf("ReadAll: %v", err)
			return
		}
	}
	go doReq()
	<-gotReq
	go doReq()
	<-gotReq
	go doReq()
	<-gotReq

	if e, g := 0, len(tr.IdleConnKeysForTesting()); e != g {
		t.Fatalf("Before writes, expected %d idle conn cache keys; got %d", e, g)
	}

	resch <- "res1"
	<-donech
	keys := tr.IdleConnKeysForTesting()
	if e, g := 1, len(keys); e != g {
		t.Fatalf("after first response, expected %d idle conn cache keys; got %d", e, g)
	}
	addr := ts.Listener.Addr().String()
	cacheKey := "|http|" + addr
	if keys[0] != cacheKey {
		t.Fatalf("Expected idle cache key %q; got %q", cacheKey, keys[0])
	}
	if e, g := 1, tr.IdleConnCountForTesting("http", addr); e != g {
		t.Errorf("after first response, expected %d idle conns; got %d", e, g)
	}

	resch <- "res2"
	<-donech
	if g, w := tr.IdleConnCountForTesting("http", addr), 2; g != w {
		t.Errorf("after second response, idle conns = %d; want %d", g, w)
	}

	resch <- "res3"
	<-donech
	if g, w := tr.IdleConnCountForTesting("http", addr), maxIdleConnsPerHost; g != w {
		t.Errorf("after third response, idle conns = %d; want %d", g, w)
	}
}

func TestTransportMaxConnsPerHostIncludeDialInProgress(t *testing.T) {
	run(t, testTransportMaxConnsPerHostIncludeDialInProgress)
}
func testTransportMaxConnsPerHostIncludeDialInProgress(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := w.Write([]byte("foo"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	})).ts
	c := ts.Client()
	tr := c.Transport.(*Transport)
	dialStarted := make(chan struct{})
	stallDial := make(chan struct{})
	tr.Dial = func(network, addr string) (net.Conn, error) {
		dialStarted <- struct{}{}
		<-stallDial
		return net.Dial(network, addr)
	}

	tr.DisableKeepAlives = true
	tr.MaxConnsPerHost = 1

	preDial := make(chan struct{})
	reqComplete := make(chan struct{})
	doReq := func(reqId string) {
		req, _ := NewRequest("GET", ts.URL, nil)
		trace := &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				preDial <- struct{}{}
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Errorf("unexpected error for request %s: %v", reqId, err)
		}
		_, err = io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("unexpected error for request %s: %v", reqId, err)
		}
		reqComplete <- struct{}{}
	}
	// get req1 to dial-in-progress
	go doReq("req1")
	<-preDial
	<-dialStarted

	// get req2 to waiting on conns per host to go down below max
	go doReq("req2")
	<-preDial
	select {
	case <-dialStarted:
		t.Error("req2 dial started while req1 dial in progress")
		return
	default:
	}

	// let req1 complete
	stallDial <- struct{}{}
	<-reqComplete

	// let req2 complete
	<-dialStarted
	stallDial <- struct{}{}
	<-reqComplete
}

func TestTransportMaxConnsPerHost(t *testing.T) {
	run(t, testTransportMaxConnsPerHost, []testMode{http1Mode, https1Mode, http2Mode})
}
func testTransportMaxConnsPerHost(t *testing.T, mode testMode) {
	CondSkipHTTP2(t)

	h := HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := w.Write([]byte("foo"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	})

	ts := newClientServerTest(t, mode, h).ts
	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.MaxConnsPerHost = 1

	mu := sync.Mutex{}
	var conns []net.Conn
	var dialCnt, gotConnCnt, tlsHandshakeCnt int32
	tr.Dial = func(network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dialCnt, 1)
		c, err := net.Dial(network, addr)
		mu.Lock()
		defer mu.Unlock()
		conns = append(conns, c)
		return c, err
	}

	doReq := func() {
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				if !connInfo.Reused {
					atomic.AddInt32(&gotConnCnt, 1)
				}
			},
			TLSHandshakeStart: func() {
				atomic.AddInt32(&tlsHandshakeCnt, 1)
			},
		}
		req, _ := NewRequest("GET", ts.URL, nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body failed: %v", err)
		}
	}

	wg := sync.WaitGroup{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doReq()
		}()
	}
	wg.Wait()

	expected := int32(tr.MaxConnsPerHost)
	if dialCnt != expected {
		t.Errorf("round 1: too many dials: %d != %d", dialCnt, expected)
	}
	if gotConnCnt != expected {
		t.Errorf("round 1: too many get connections: %d != %d", gotConnCnt, expected)
	}
	if ts.TLS != nil && tlsHandshakeCnt != expected {
		t.Errorf("round 1: too many tls handshakes: %d != %d", tlsHandshakeCnt, expected)
	}

	if t.Failed() {
		t.FailNow()
	}

	mu.Lock()
	for _, c := range conns {
		c.Close()
	}
	conns = nil
	mu.Unlock()
	tr.CloseIdleConnections()

	doReq()
	expected++
	if dialCnt != expected {
		t.Errorf("round 2: too many dials: %d", dialCnt)
	}
	if gotConnCnt != expected {
		t.Errorf("round 2: too many get connections: %d != %d", gotConnCnt, expected)
	}
	if ts.TLS != nil && tlsHandshakeCnt != expected {
		t.Errorf("round 2: too many tls handshakes: %d != %d", tlsHandshakeCnt, expected)
	}
}

func TestTransportMaxConnsPerHostDialCancellation(t *testing.T) {
	run(t, testTransportMaxConnsPerHostDialCancellation,
		testNotParallel, // because test uses SetPendingDialHooks
		[]testMode{http1Mode, https1Mode, http2Mode},
	)
}

func testTransportMaxConnsPerHostDialCancellation(t *testing.T, mode testMode) {
	CondSkipHTTP2(t)

	h := HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := w.Write([]byte("foo"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	})

	cst := newClientServerTest(t, mode, h)
	defer cst.close()
	ts := cst.ts
	c := ts.Client()
	tr := c.Transport.(*Transport)
	tr.MaxConnsPerHost = 1

	// This request is canceled when dial is queued, which preempts dialing.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	SetPendingDialHooks(cancel, nil)
	defer SetPendingDialHooks(nil, nil)

	req, _ := NewRequestWithContext(ctx, "GET", ts.URL, nil)
	_, err := c.Do(req)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error %v, got %v", context.Canceled, err)
	}

	// This request should succeed.
	SetPendingDialHooks(nil, nil)
	req, _ = NewRequest("GET", ts.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
}

func TestTransportRemovesDeadIdleConnections(t *testing.T) {
	run(t, testTransportRemovesDeadIdleConnections, []testMode{http1Mode})
}
func testTransportRemovesDeadIdleConnections(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, r.RemoteAddr)
	})).ts

	c := ts.Client()
	tr := c.Transport.(*Transport)

	doReq := func(name string) {
		// Do a POST instead of a GET to prevent the Transport's
		// idempotent request retry logic from kicking in...
		res, err := c.Post(ts.URL, "", nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.StatusCode != 200 {
			t.Fatalf("%s: %v", name, res.Status)
		}
		defer res.Body.Close()
		slurp, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: ok (%q)", name, slurp)
	}

	doReq("first")
	keys1 := tr.IdleConnKeysForTesting()

	ts.CloseClientConnections()

	var keys2 []string
	waitCondition(t, 10*time.Millisecond, func(d time.Duration) bool {
		keys2 = tr.IdleConnKeysForTesting()
		if len(keys2) != 0 {
			if d > 0 {
				t.Logf("Transport hasn't noticed idle connection's death in %v.\nbefore: %q\n after: %q\n", d, keys1, keys2)
			}
			return false
		}
		return true
	})

	doReq("second")
}

// Test that the Transport notices when a server hangs up on its
// unexpectedly (a keep-alive connection is closed).
func TestTransportServerClosingUnexpectedly(t *testing.T) {
	run(t, testTransportServerClosingUnexpectedly, []testMode{http1Mode})
}
func testTransportServerClosingUnexpectedly(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, hostPortHandler).ts
	c := ts.Client()

	fetch := func(n, retries int) string {
		condFatalf := func(format string, arg ...any) {
			if retries <= 0 {
				t.Fatalf(format, arg...)
			}
			t.Logf("retrying shortly after expected error: "+format, arg...)
			time.Sleep(time.Second / time.Duration(retries))
		}
		for retries >= 0 {
			retries--
			res, err := c.Get(ts.URL)
			if err != nil {
				condFatalf("error in req #%d, GET: %v", n, err)
				continue
			}
			body, err := io.ReadAll(res.Body)
			if err != nil {
				condFatalf("error in req #%d, ReadAll: %v", n, err)
				continue
			}
			res.Body.Close()
			return string(body)
		}
		panic("unreachable")
	}

	body1 := fetch(1, 0)
	body2 := fetch(2, 0)

	// Close all the idle connections in a way that's similar to
	// the server hanging up on us. We don't use
	// httptest.Server.CloseClientConnections because it's
	// best-effort and stops blocking after 5 seconds. On a loaded
	// machine running many tests concurrently it's possible for
	// that method to be async and cause the body3 fetch below to
	// run on an old connection. This function is synchronous.
	ExportCloseTransportConnsAbruptly(c.Transport.(*Transport))

	body3 := fetch(3, 5)

	if body1 != body2 {
		t.Errorf("expected body1 and body2 to be equal")
	}
	if body2 == body3 {
		t.Errorf("expected body2 and body3 to be different")
	}
}

// Test for https://golang.org/issue/2616 (appropriate issue number)
// This fails pretty reliably with GOMAXPROCS=100 or something high.
func TestStressSurpriseServerCloses(t *testing.T) {
	run(t, testStressSurpriseServerCloses, []testMode{http1Mode})
}
func testStressSurpriseServerCloses(t *testing.T, mode testMode) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello"))
		w.(Flusher).Flush()
		conn, buf, _ := w.(Hijacker).Hijack()
		buf.Flush()
		conn.Close()
	})).ts
	c := ts.Client()

	// Do a bunch of traffic from different goroutines. Send to activityc
	// after each request completes, regardless of whether it failed.
	// If these are too high, OS X exhausts its ephemeral ports
	// and hangs waiting for them to transition TCP states. That's
	// not what we want to test. TODO(bradfitz): use an io.Pipe
	// dialer for this test instead?
	const (
		numClients    = 20
		reqsPerClient = 25
	)
	var wg sync.WaitGroup
	wg.Add(numClients * reqsPerClient)
	for i := 0; i < numClients; i++ {
		go func() {
			for i := 0; i < reqsPerClient; i++ {
				res, err := c.Get(ts.URL)
				if err == nil {
					// We expect errors since the server is
					// hanging up on us after telling us to
					// send more requests, so we don't
					// actually care what the error is.
					// But we want to close the body in cases
					// where we won the race.
					res.Body.Close()
				}
				wg.Done()
			}
		}()
	}

	// Make sure all the request come back, one way or another.
	wg.Wait()
}

// TestTransportHeadResponses verifies that we deal with Content-Lengths
// with no bodies properly
func TestTransportHeadResponses(t *testing.T) { run(t, testTransportHeadResponses) }
func testTransportHeadResponses(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "HEAD" {
			panic("expected HEAD; got " + r.Method)
		}
		w.Header().Set("Content-Length", "123")
		w.WriteHeader(200)
	})).ts
	c := ts.Client()

	for i := 0; i < 2; i++ {
		res, err := c.Head(ts.URL)
		if err != nil {
			t.Errorf("error on loop %d: %v", i, err)
			continue
		}
		if e, g := "123", res.Header.Get("Content-Length"); e != g {
			t.Errorf("loop %d: expected Content-Length header of %q, got %q", i, e, g)
		}
		if e, g := int64(123), res.ContentLength; e != g {
			t.Errorf("loop %d: expected res.ContentLength of %v, got %v", i, e, g)
		}
		if all, err := io.ReadAll(res.Body); err != nil {
			t.Errorf("loop %d: Body ReadAll: %v", i, err)
		} else if len(all) != 0 {
			t.Errorf("Bogus body %q", all)
		}
	}
}

// TestTransportHeadChunkedResponse verifies that we ignore chunked transfer-encoding
// on responses to HEAD requests.
func TestTransportHeadChunkedResponse(t *testing.T) {
	run(t, testTransportHeadChunkedResponse, []testMode{http1Mode}, testNotParallel)
}
func testTransportHeadChunkedResponse(t *testing.T, mode testMode) {
	ts := newClientServerTest(t, mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "HEAD" {
			panic("expected HEAD; got " + r.Method)
		}
		w.Header().Set("Transfer-Encoding", "chunked") // client should ignore
		w.Header().Set("x-client-ipport", r.RemoteAddr)
		w.WriteHeader(200)
	})).ts
	c := ts.Client()

	// Ensure that we wait for the readLoop to complete before
	// calling Head again
	didRead := make(chan bool)
	SetReadLoopBeforeNextReadHook(func() { didRead <- true })
	defer SetReadLoopBeforeNextReadHook(nil)

	res1, err := c.Head(ts.URL)
	<-didRead

	if err != nil {
		t.Fatalf("request 1 error: %v", err)
	}

	res2, err := c.Head(ts.URL)
	<-didRead

	if err != nil {
		t.Fatalf("request 2 error: %v", err)
	}
	if v1, v2 := res1.Header.Get("x-client-ipport"), res2.Header.Get("x-client-ipport"); v1 != v2 {
		t.Errorf("ip/ports differed between head requests: %q vs %q", v1, v2)
	}
}

var roundTripTests = []struct {
	accept       string
	expectAccept string
	compressed   bool
}{
	// Requests with no accept-encoding header use transparent compression
	{"", "gzip", false},
	// Requests with other accept-encoding should pass through unmodified
	{"foo", "foo", false},
	// Requests with accept-encoding == gzip should be passed through
	{"gzip", "gzip", true},
}

// Test that the modification made to the Request by the RoundTripper is cleaned up
func TestRoundTripGzip(t *testing.T) { run(t, testRoundTripGzip) }
func testRoundTripGzip(t *testing.T, mode testMode) {
	const responseBody = "test response body"
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		accept := req.Header.Get("Accept-Encoding")
		if expect := req.FormValue("expect_accept"); accept != expect {
			t.Errorf("in handler, test %v: Accept-Encoding = %q, want %q",
				req.FormValue("testnum"), accept, expect)
		}
		if accept == "gzip" {
			rw.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(rw)
			gz.Write([]byte(responseBody))
			gz.Close()
		} else {
			rw.Header().Set("Content-Encoding", accept)
			rw.Write([]byte(responseBody))
		}
	})).ts
	tr := ts.Client().Transport.(*Transport)

	for i, test := range roundTripTests {
		// Test basic request (no accept-encoding)
		req, _ := NewRequest("GET", fmt.Sprintf("%s/?testnum=%d&expect_accept=%s", ts.URL, i, test.expectAccept), nil)
		if test.accept != "" {
			req.Header.Set("Accept-Encoding", test.accept)
		}
		res, err := tr.RoundTrip(req)
		if err != nil {
			t.Errorf("%d. RoundTrip: %v", i, err)
			continue
		}
		var body []byte
		if test.compressed {
			var r *gzip.Reader
			r, err = gzip.NewReader(res.Body)
			if err != nil {
				t.Errorf("%d. gzip NewReader: %v", i, err)
				continue
			}
			body, err = io.ReadAll(r)
			res.Body.Close()
		} else {
			body, err = io.ReadAll(res.Body)
		}
		if err != nil {
			t.Errorf("%d. Error: %q", i, err)
			continue
		}
		if g, e := string(body), responseBody; g != e {
			t.Errorf("%d. body = %q; want %q", i, g, e)
		}
		if g, e := req.Header.Get("Accept-Encoding"), test.accept; g != e {
			t.Errorf("%d. Accept-Encoding = %q; want %q (it was mutated, in violation of RoundTrip contract)", i, g, e)
		}
		if g, e := res.Header.Get("Content-Encoding"), test.accept; g != e {
			t.Errorf("%d. Content-Encoding = %q; want %q", i, g, e)
		}
	}

}

func TestTransportGzip(t *testing.T) { run(t, testTransportGzip) }
func testTransportGzip(t *testing.T, mode testMode) {
	if mode == http2Mode {
		t.Skip("https://go.dev/issue/56020")
	}
	const testString = "The test string aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const nRandBytes = 1024 * 1024
	ts := newClientServerTest(t, mode, HandlerFunc(func(rw ResponseWriter, req *Request) {
		if req.Method == "HEAD" {
			if g := req.Header.Get("Accept-Encoding"); g != "" {
				t.Errorf("HEAD request sent with Accept-Encoding of %q; want none", g)
			}
			return
		}
		if g, e := req.Header.Get("Accept-Encoding"), "gzip"; g != e {
			t.Errorf("Accept-Encoding = %q, want %q", g, e)
		}
		rw.Header().Set("Content-Encoding", "gzip")

		var w io.Writer = rw
		var buf bytes.Buffer
		if req.FormValue("chunked") == "0" {
			w = &buf
			defer io.Copy(rw, &buf)
			defer func() {
				rw.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
			}()
		}
		gz := gzip.NewWriter(w)
		gz.Write([]byte(testString))
		if req.FormValue("body") == "large" {
			io.CopyN(gz, rand.Reader, nRandBytes)
		}
		gz.Close()
	})).ts
	c := ts.Client()

	for _, chunked := range []string{"1", "0"} {
		// First fetch something large, but only read some of it.
		res, err := c.Get(ts.URL + "/?body=large&chunked=" + chunked)
		if err != nil {
			t.Fatalf("large get: %v", err)
		}
		buf := make([]byte, len(testString))
		n, err := io.ReadFull(res.Body, buf)
		if err != nil {
			t.Fatalf("partial read of large response: size=%d, %v", n, err)
		}
		if e, g := testString, string(buf); e != g {
			t.Errorf("partial read got %q, expected %q", g, e)
		}
		res.Body.Close()
		// Read on the body, even though it's closed
		n, err = res.Body.Read(buf)
		if n != 0 || err == nil {
			t.Errorf("expected error post-closed large Read; got = %d, %v", n, err)
		}

		// Then something small.
		res, err = c.Get(ts.URL + "/?chunked=" + chunked)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if g, e := string(body), testString; g != e {
			t.Fatalf("body = %q; want %q", g, e)
		}
		if g, e := res.Header.Get("Content-Encoding"), ""; g != e {
			t.Fatalf("Content-Encoding = %q; want %q", g, e)
		}

		// Read on the body after it's been fully read:
		n, err = res.Body.Read(buf)
		if n != 0 || err == nil {
			t.Errorf("expected Read error after exhausted reads; got %d, %v", n, err)
		}
		res.Body.Close()
		n, err = res.Body.Read(buf)
		if n != 0 || err == nil {
			t.Errorf("expected Read error after Close; got %d, %v", n, err)
		}
	}

	// And a HEAD request too, because they're a
```