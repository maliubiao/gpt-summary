Response:
The user wants to understand the functionality of the provided Go code snippet from `net/http/client.go`. I need to analyze the code and explain its purpose, identify any relevant Go language features, provide code examples with hypothetical inputs and outputs, discuss command-line argument handling (if any), point out common mistakes users might make, and finally, summarize the overall functionality of this part of the code.

**Plan:**

1. **Identify Core Types and Functions:**  Focus on the `Client` struct and its methods like `Do`, `Get`, `Post`, `Head`, and supporting functions like `send`, `setRequestCancel`, `redirectBehavior`. Also, look at the `RoundTripper` interface.
2. **Explain `Client` Functionality:** Describe its role in making HTTP requests, handling redirects, cookies, timeouts, and using a `Transport`.
3. **Explain `RoundTripper` Functionality:** Describe its role in executing a single HTTP transaction.
4. **Go Language Features:**  Identify features like interfaces (`RoundTripper`), structs (`Client`), methods, error handling, context, and concurrency primitives (sync).
5. **Code Examples:**  Show basic usage of `Client` with `Get`, `Post`. Demonstrate how to set headers and handle redirects.
6. **Code Reasoning (If applicable):**  If any complex logic requires it, provide step-by-step reasoning with inputs and outputs. The redirect logic seems like a good candidate.
7. **Command-Line Arguments:** Check if the code snippet directly handles command-line arguments. If not, mention this.
8. **Common Mistakes:** Point out potential issues like not closing response bodies, misunderstanding redirect behavior, and incorrect timeout settings.
9. **Summary:** Concisely summarize the responsibilities of the code.
这是 `go/src/net/http/client.go` 文件中 `http` 包关于 HTTP 客户端实现的一部分代码。它定义了客户端的核心结构 `Client` 及其相关方法，负责发起 HTTP 请求并处理响应。

**主要功能归纳:**

这部分代码主要定义了 `http.Client` 类型，它是一个用于发送 HTTP 请求的高级客户端。`Client` 依赖于底层的 `RoundTripper` 接口（通常是 `Transport` 类型）来实际执行网络请求。`Client` 的主要功能包括：

1. **发起 HTTP 请求:**  提供了 `Get`, `Post`, `Head`, `Do` 等方法来发送不同类型的 HTTP 请求。
2. **处理 HTTP 重定向:**  能够根据服务器返回的重定向状态码（如 301, 302, 307, 308）自动跟踪重定向。可以通过 `CheckRedirect` 字段自定义重定向策略。
3. **管理 Cookie:**  通过 `Jar` 字段，可以存储和发送 Cookie，实现客户端的会话管理。
4. **设置超时:**  允许通过 `Timeout` 字段设置请求的超时时间，包括连接时间、重定向和读取响应体的时间。
5. **处理认证:**  能够处理基本的 HTTP 认证，例如在请求头中设置 `Authorization`。
6. **提供默认客户端:**  定义了一个全局默认客户端 `DefaultClient`，方便快速发起简单的 HTTP 请求。
7. **定义 `RoundTripper` 接口:**  定义了执行单个 HTTP 事务的底层接口。

**Go 语言功能实现举例:**

**1. 使用 `Client` 发起 GET 请求:**

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	resp, err := http.Get("https://www.example.com")
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
```

**假设输入:** 无，直接访问 `https://www.example.com`。

**预期输出:**  `https://www.example.com` 的 HTML 内容。

**2. 使用 `Client` 和 `Do` 方法发送带有自定义 Header 的 POST 请求:**

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	data := []byte(`{"key": "value"}`)
	req, err := http.NewRequest("POST", "https://httpbin.org/post", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("Error creating request:", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "my-custom-value")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		os.Exit(1)
	}
	fmt.Println(string(body))
}
```

**假设输入:**  向 `https://httpbin.org/post` 发送 JSON 数据 `{"key": "value"}`，并带有自定义 Header。

**预期输出:**  `httpbin.org` 返回的包含请求信息的 JSON，其中会包含我们设置的 `Content-Type` 和 `X-Custom-Header`。

**代码推理 (重定向处理):**

`Client` 的 `Do` 方法会处理重定向。让我们假设我们请求的 URL 返回一个 302 重定向到另一个 URL。

**假设输入:**

1. 请求 URL: `http://example.com/original`
2. `http://example.com/original` 返回状态码 302，并设置 `Location` Header 为 `http://example.com/redirected`。

**代码执行流程:**

1. `c.Do(req)` 被调用，其中 `req.URL` 是 `http://example.com/original`。
2. `c.send(req, deadline)` 发送初始请求。
3. 服务器返回 302 状态码和 `Location` Header。
4. `redirectBehavior` 函数判断需要重定向。
5. `c.checkRedirect(req, reqs)` 被调用，使用默认的 `defaultCheckRedirect`，如果重定向次数小于 10，则返回 `nil`。
6. 创建一个新的 `Request` 对象，其 `URL` 被设置为 `http://example.com/redirected`。
7. 初始请求的 Header 会被复制到新的请求中 (根据 `shouldCopyHeaderOnRedirect` 函数的规则)。
8. `c.send` 再次被调用，这次请求的是 `http://example.com/redirected`。
9. 最终返回 `http://example.com/redirected` 的响应。

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。HTTP 客户端通常在应用程序内部使用，应用程序可能会通过 `flag` 包或其他方式解析命令行参数，然后根据这些参数构建 HTTP 请求。

**使用者易犯错的点:**

1. **忘记关闭响应体 (`resp.Body.Close()`):**  如果不关闭响应体，可能会导致资源泄漏，特别是当使用 keep-alive 连接时，连接可能无法被复用。

    ```go
    resp, err := http.Get("https://www.example.com")
    if err != nil {
        // ... handle error
    }
    // 忘记添加 defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    fmt.Println(string(body))
    ```

2. **对重定向行为的误解:**  没有理解默认的重定向次数限制 (10次) 或者没有意识到敏感 Header 在跨域重定向时可能不会被转发。

    ```go
    client := &http.Client{}
    req, _ := http.NewRequest("GET", "http://initial-domain.com/redirect", nil)
    req.Header.Set("Authorization", "Bearer token") // 假设 initial-domain.com 会重定向到 another-domain.com
    resp, err := client.Do(req) // "Authorization" Header 可能不会被转发
    ```

**总结:**

这部分 `go/src/net/http/client.go` 代码定义了 Go 语言中进行 HTTP 客户端编程的核心抽象和实现。它提供了灵活且易用的接口来发送各种 HTTP 请求，并处理常见的 HTTP 协议细节，如重定向和 Cookie 管理。`Client` 依赖于 `RoundTripper` 进行底层的网络传输，并通过可配置的选项（如 `CheckRedirect` 和 `Timeout`) 来满足不同的应用场景需求。

Prompt: 
```
这是路径为go/src/net/http/client.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP client. See RFC 7230 through 7235.
//
// This is the high-level Client interface.
// The low-level implementation is in transport.go.

package http

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http/internal/ascii"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A Client is an HTTP client. Its zero value ([DefaultClient]) is a
// usable client that uses [DefaultTransport].
//
// The [Client.Transport] typically has internal state (cached TCP
// connections), so Clients should be reused instead of created as
// needed. Clients are safe for concurrent use by multiple goroutines.
//
// A Client is higher-level than a [RoundTripper] (such as [Transport])
// and additionally handles HTTP details such as cookies and
// redirects.
//
// When following redirects, the Client will forward all headers set on the
// initial [Request] except:
//
//   - when forwarding sensitive headers like "Authorization",
//     "WWW-Authenticate", and "Cookie" to untrusted targets.
//     These headers will be ignored when following a redirect to a domain
//     that is not a subdomain match or exact match of the initial domain.
//     For example, a redirect from "foo.com" to either "foo.com" or "sub.foo.com"
//     will forward the sensitive headers, but a redirect to "bar.com" will not.
//   - when forwarding the "Cookie" header with a non-nil cookie Jar.
//     Since each redirect may mutate the state of the cookie jar,
//     a redirect may possibly alter a cookie set in the initial request.
//     When forwarding the "Cookie" header, any mutated cookies will be omitted,
//     with the expectation that the Jar will insert those mutated cookies
//     with the updated values (assuming the origin matches).
//     If Jar is nil, the initial cookies are forwarded without change.
type Client struct {
	// Transport specifies the mechanism by which individual
	// HTTP requests are made.
	// If nil, DefaultTransport is used.
	Transport RoundTripper

	// CheckRedirect specifies the policy for handling redirects.
	// If CheckRedirect is not nil, the client calls it before
	// following an HTTP redirect. The arguments req and via are
	// the upcoming request and the requests made already, oldest
	// first. If CheckRedirect returns an error, the Client's Get
	// method returns both the previous Response (with its Body
	// closed) and CheckRedirect's error (wrapped in a url.Error)
	// instead of issuing the Request req.
	// As a special case, if CheckRedirect returns ErrUseLastResponse,
	// then the most recent response is returned with its body
	// unclosed, along with a nil error.
	//
	// If CheckRedirect is nil, the Client uses its default policy,
	// which is to stop after 10 consecutive requests.
	CheckRedirect func(req *Request, via []*Request) error

	// Jar specifies the cookie jar.
	//
	// The Jar is used to insert relevant cookies into every
	// outbound Request and is updated with the cookie values
	// of every inbound Response. The Jar is consulted for every
	// redirect that the Client follows.
	//
	// If Jar is nil, cookies are only sent if they are explicitly
	// set on the Request.
	Jar CookieJar

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time, any
	// redirects, and reading the response body. The timer remains
	// running after Get, Head, Post, or Do return and will
	// interrupt reading of the Response.Body.
	//
	// A Timeout of zero means no timeout.
	//
	// The Client cancels requests to the underlying Transport
	// as if the Request's Context ended.
	//
	// For compatibility, the Client will also use the deprecated
	// CancelRequest method on Transport if found. New
	// RoundTripper implementations should use the Request's Context
	// for cancellation instead of implementing CancelRequest.
	Timeout time.Duration
}

// DefaultClient is the default [Client] and is used by [Get], [Head], and [Post].
var DefaultClient = &Client{}

// RoundTripper is an interface representing the ability to execute a
// single HTTP transaction, obtaining the [Response] for a given [Request].
//
// A RoundTripper must be safe for concurrent use by multiple
// goroutines.
type RoundTripper interface {
	// RoundTrip executes a single HTTP transaction, returning
	// a Response for the provided Request.
	//
	// RoundTrip should not attempt to interpret the response. In
	// particular, RoundTrip must return err == nil if it obtained
	// a response, regardless of the response's HTTP status code.
	// A non-nil err should be reserved for failure to obtain a
	// response. Similarly, RoundTrip should not attempt to
	// handle higher-level protocol details such as redirects,
	// authentication, or cookies.
	//
	// RoundTrip should not modify the request, except for
	// consuming and closing the Request's Body. RoundTrip may
	// read fields of the request in a separate goroutine. Callers
	// should not mutate or reuse the request until the Response's
	// Body has been closed.
	//
	// RoundTrip must always close the body, including on errors,
	// but depending on the implementation may do so in a separate
	// goroutine even after RoundTrip returns. This means that
	// callers wanting to reuse the body for subsequent requests
	// must arrange to wait for the Close call before doing so.
	//
	// The Request's URL and Header fields must be initialized.
	RoundTrip(*Request) (*Response, error)
}

// refererForURL returns a referer without any authentication info or
// an empty string if lastReq scheme is https and newReq scheme is http.
// If the referer was explicitly set, then it will continue to be used.
func refererForURL(lastReq, newReq *url.URL, explicitRef string) string {
	// https://tools.ietf.org/html/rfc7231#section-5.5.2
	//   "Clients SHOULD NOT include a Referer header field in a
	//    (non-secure) HTTP request if the referring page was
	//    transferred with a secure protocol."
	if lastReq.Scheme == "https" && newReq.Scheme == "http" {
		return ""
	}
	if explicitRef != "" {
		return explicitRef
	}

	referer := lastReq.String()
	if lastReq.User != nil {
		// This is not very efficient, but is the best we can
		// do without:
		// - introducing a new method on URL
		// - creating a race condition
		// - copying the URL struct manually, which would cause
		//   maintenance problems down the line
		auth := lastReq.User.String() + "@"
		referer = strings.Replace(referer, auth, "", 1)
	}
	return referer
}

// didTimeout is non-nil only if err != nil.
func (c *Client) send(req *Request, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
	if c.Jar != nil {
		for _, cookie := range c.Jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
	}
	resp, didTimeout, err = send(req, c.transport(), deadline)
	if err != nil {
		return nil, didTimeout, err
	}
	if c.Jar != nil {
		if rc := resp.Cookies(); len(rc) > 0 {
			c.Jar.SetCookies(req.URL, rc)
		}
	}
	return resp, nil, nil
}

func (c *Client) deadline() time.Time {
	if c.Timeout > 0 {
		return time.Now().Add(c.Timeout)
	}
	return time.Time{}
}

func (c *Client) transport() RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return DefaultTransport
}

// ErrSchemeMismatch is returned when a server returns an HTTP response to an HTTPS client.
var ErrSchemeMismatch = errors.New("http: server gave HTTP response to HTTPS client")

// send issues an HTTP request.
// Caller should close resp.Body when done reading from it.
func send(ireq *Request, rt RoundTripper, deadline time.Time) (resp *Response, didTimeout func() bool, err error) {
	req := ireq // req is either the original request, or a modified fork

	if rt == nil {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: no Client.Transport or DefaultTransport")
	}

	if req.URL == nil {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: nil Request.URL")
	}

	if req.RequestURI != "" {
		req.closeBody()
		return nil, alwaysFalse, errors.New("http: Request.RequestURI can't be set in client requests")
	}

	// forkReq forks req into a shallow clone of ireq the first
	// time it's called.
	forkReq := func() {
		if ireq == req {
			req = new(Request)
			*req = *ireq // shallow clone
		}
	}

	// Most the callers of send (Get, Post, et al) don't need
	// Headers, leaving it uninitialized. We guarantee to the
	// Transport that this has been initialized, though.
	if req.Header == nil {
		forkReq()
		req.Header = make(Header)
	}

	if u := req.URL.User; u != nil && req.Header.Get("Authorization") == "" {
		username := u.Username()
		password, _ := u.Password()
		forkReq()
		req.Header = cloneOrMakeHeader(ireq.Header)
		req.Header.Set("Authorization", "Basic "+basicAuth(username, password))
	}

	if !deadline.IsZero() {
		forkReq()
	}
	stopTimer, didTimeout := setRequestCancel(req, rt, deadline)

	resp, err = rt.RoundTrip(req)
	if err != nil {
		stopTimer()
		if resp != nil {
			log.Printf("RoundTripper returned a response & error; ignoring response")
		}
		if tlsErr, ok := err.(tls.RecordHeaderError); ok {
			// If we get a bad TLS record header, check to see if the
			// response looks like HTTP and give a more helpful error.
			// See golang.org/issue/11111.
			if string(tlsErr.RecordHeader[:]) == "HTTP/" {
				err = ErrSchemeMismatch
			}
		}
		return nil, didTimeout, err
	}
	if resp == nil {
		return nil, didTimeout, fmt.Errorf("http: RoundTripper implementation (%T) returned a nil *Response with a nil error", rt)
	}
	if resp.Body == nil {
		// The documentation on the Body field says “The http Client and Transport
		// guarantee that Body is always non-nil, even on responses without a body
		// or responses with a zero-length body.” Unfortunately, we didn't document
		// that same constraint for arbitrary RoundTripper implementations, and
		// RoundTripper implementations in the wild (mostly in tests) assume that
		// they can use a nil Body to mean an empty one (similar to Request.Body).
		// (See https://golang.org/issue/38095.)
		//
		// If the ContentLength allows the Body to be empty, fill in an empty one
		// here to ensure that it is non-nil.
		if resp.ContentLength > 0 && req.Method != "HEAD" {
			return nil, didTimeout, fmt.Errorf("http: RoundTripper implementation (%T) returned a *Response with content length %d but a nil Body", rt, resp.ContentLength)
		}
		resp.Body = io.NopCloser(strings.NewReader(""))
	}
	if !deadline.IsZero() {
		resp.Body = &cancelTimerBody{
			stop:          stopTimer,
			rc:            resp.Body,
			reqDidTimeout: didTimeout,
		}
	}
	return resp, nil, nil
}

// timeBeforeContextDeadline reports whether the non-zero Time t is
// before ctx's deadline, if any. If ctx does not have a deadline, it
// always reports true (the deadline is considered infinite).
func timeBeforeContextDeadline(t time.Time, ctx context.Context) bool {
	d, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return t.Before(d)
}

// knownRoundTripperImpl reports whether rt is a RoundTripper that's
// maintained by the Go team and known to implement the latest
// optional semantics (notably contexts). The Request is used
// to check whether this particular request is using an alternate protocol,
// in which case we need to check the RoundTripper for that protocol.
func knownRoundTripperImpl(rt RoundTripper, req *Request) bool {
	switch t := rt.(type) {
	case *Transport:
		if altRT := t.alternateRoundTripper(req); altRT != nil {
			return knownRoundTripperImpl(altRT, req)
		}
		return true
	case *http2Transport, http2noDialH2RoundTripper:
		return true
	}
	// There's a very minor chance of a false positive with this.
	// Instead of detecting our golang.org/x/net/http2.Transport,
	// it might detect a Transport type in a different http2
	// package. But I know of none, and the only problem would be
	// some temporarily leaked goroutines if the transport didn't
	// support contexts. So this is a good enough heuristic:
	if reflect.TypeOf(rt).String() == "*http2.Transport" {
		return true
	}
	return false
}

// setRequestCancel sets req.Cancel and adds a deadline context to req
// if deadline is non-zero. The RoundTripper's type is used to
// determine whether the legacy CancelRequest behavior should be used.
//
// As background, there are three ways to cancel a request:
// First was Transport.CancelRequest. (deprecated)
// Second was Request.Cancel.
// Third was Request.Context.
// This function populates the second and third, and uses the first if it really needs to.
func setRequestCancel(req *Request, rt RoundTripper, deadline time.Time) (stopTimer func(), didTimeout func() bool) {
	if deadline.IsZero() {
		return nop, alwaysFalse
	}
	knownTransport := knownRoundTripperImpl(rt, req)
	oldCtx := req.Context()

	if req.Cancel == nil && knownTransport {
		// If they already had a Request.Context that's
		// expiring sooner, do nothing:
		if !timeBeforeContextDeadline(deadline, oldCtx) {
			return nop, alwaysFalse
		}

		var cancelCtx func()
		req.ctx, cancelCtx = context.WithDeadline(oldCtx, deadline)
		return cancelCtx, func() bool { return time.Now().After(deadline) }
	}
	initialReqCancel := req.Cancel // the user's original Request.Cancel, if any

	var cancelCtx func()
	if timeBeforeContextDeadline(deadline, oldCtx) {
		req.ctx, cancelCtx = context.WithDeadline(oldCtx, deadline)
	}

	cancel := make(chan struct{})
	req.Cancel = cancel

	doCancel := func() {
		// The second way in the func comment above:
		close(cancel)
		// The first way, used only for RoundTripper
		// implementations written before Go 1.5 or Go 1.6.
		type canceler interface{ CancelRequest(*Request) }
		if v, ok := rt.(canceler); ok {
			v.CancelRequest(req)
		}
	}

	stopTimerCh := make(chan struct{})
	stopTimer = sync.OnceFunc(func() {
		close(stopTimerCh)
		if cancelCtx != nil {
			cancelCtx()
		}
	})

	timer := time.NewTimer(time.Until(deadline))
	var timedOut atomic.Bool

	go func() {
		select {
		case <-initialReqCancel:
			doCancel()
			timer.Stop()
		case <-timer.C:
			timedOut.Store(true)
			doCancel()
		case <-stopTimerCh:
			timer.Stop()
		}
	}()

	return stopTimer, timedOut.Load
}

// See 2 (end of page 4) https://www.ietf.org/rfc/rfc2617.txt
// "To receive authorization, the client sends the userid and password,
// separated by a single colon (":") character, within a base64
// encoded string in the credentials."
// It is not meant to be urlencoded.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Get issues a GET to the specified URL. If the response is one of
// the following redirect codes, Get follows the redirect, up to a
// maximum of 10 redirects:
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// An error is returned if there were too many redirects or if there
// was an HTTP protocol error. A non-2xx response doesn't cause an
// error. Any returned error will be of type [*url.Error]. The url.Error
// value's Timeout method will report true if the request timed out.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// Get is a wrapper around DefaultClient.Get.
//
// To make a request with custom headers, use [NewRequest] and
// DefaultClient.Do.
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and DefaultClient.Do.
func Get(url string) (resp *Response, err error) {
	return DefaultClient.Get(url)
}

// Get issues a GET to the specified URL. If the response is one of the
// following redirect codes, Get follows the redirect after calling the
// [Client.CheckRedirect] function:
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// An error is returned if the [Client.CheckRedirect] function fails
// or if there was an HTTP protocol error. A non-2xx response doesn't
// cause an error. Any returned error will be of type [*url.Error]. The
// url.Error value's Timeout method will report true if the request
// timed out.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// To make a request with custom headers, use [NewRequest] and [Client.Do].
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and Client.Do.
func (c *Client) Get(url string) (resp *Response, err error) {
	req, err := NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func alwaysFalse() bool { return false }

// ErrUseLastResponse can be returned by Client.CheckRedirect hooks to
// control how redirects are processed. If returned, the next request
// is not sent and the most recent response is returned with its body
// unclosed.
var ErrUseLastResponse = errors.New("net/http: use last response")

// checkRedirect calls either the user's configured CheckRedirect
// function, or the default.
func (c *Client) checkRedirect(req *Request, via []*Request) error {
	fn := c.CheckRedirect
	if fn == nil {
		fn = defaultCheckRedirect
	}
	return fn(req, via)
}

// redirectBehavior describes what should happen when the
// client encounters a 3xx status code from the server.
func redirectBehavior(reqMethod string, resp *Response, ireq *Request) (redirectMethod string, shouldRedirect, includeBody bool) {
	switch resp.StatusCode {
	case 301, 302, 303:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = false

		// RFC 2616 allowed automatic redirection only with GET and
		// HEAD requests. RFC 7231 lifts this restriction, but we still
		// restrict other methods to GET to maintain compatibility.
		// See Issue 18570.
		if reqMethod != "GET" && reqMethod != "HEAD" {
			redirectMethod = "GET"
		}
	case 307, 308:
		redirectMethod = reqMethod
		shouldRedirect = true
		includeBody = true

		if ireq.GetBody == nil && ireq.outgoingLength() != 0 {
			// We had a request body, and 307/308 require
			// re-sending it, but GetBody is not defined. So just
			// return this response to the user instead of an
			// error, like we did in Go 1.7 and earlier.
			shouldRedirect = false
		}
	}
	return redirectMethod, shouldRedirect, includeBody
}

// urlErrorOp returns the (*url.Error).Op value to use for the
// provided (*Request).Method value.
func urlErrorOp(method string) string {
	if method == "" {
		return "Get"
	}
	if lowerMethod, ok := ascii.ToLower(method); ok {
		return method[:1] + lowerMethod[1:]
	}
	return method
}

// Do sends an HTTP request and returns an HTTP response, following
// policy (such as redirects, cookies, auth) as configured on the
// client.
//
// An error is returned if caused by client policy (such as
// CheckRedirect), or failure to speak HTTP (such as a network
// connectivity problem). A non-2xx status code doesn't cause an
// error.
//
// If the returned error is nil, the [Response] will contain a non-nil
// Body which the user is expected to close. If the Body is not both
// read to EOF and closed, the [Client]'s underlying [RoundTripper]
// (typically [Transport]) may not be able to re-use a persistent TCP
// connection to the server for a subsequent "keep-alive" request.
//
// The request Body, if non-nil, will be closed by the underlying
// Transport, even on errors. The Body may be closed asynchronously after
// Do returns.
//
// On error, any Response can be ignored. A non-nil Response with a
// non-nil error only occurs when CheckRedirect fails, and even then
// the returned [Response.Body] is already closed.
//
// Generally [Get], [Post], or [PostForm] will be used instead of Do.
//
// If the server replies with a redirect, the Client first uses the
// CheckRedirect function to determine whether the redirect should be
// followed. If permitted, a 301, 302, or 303 redirect causes
// subsequent requests to use HTTP method GET
// (or HEAD if the original request was HEAD), with no body.
// A 307 or 308 redirect preserves the original HTTP method and body,
// provided that the [Request.GetBody] function is defined.
// The [NewRequest] function automatically sets GetBody for common
// standard library body types.
//
// Any returned error will be of type [*url.Error]. The url.Error
// value's Timeout method will report true if the request timed out.
func (c *Client) Do(req *Request) (*Response, error) {
	return c.do(req)
}

var testHookClientDoResult func(retres *Response, reterr error)

func (c *Client) do(req *Request) (retres *Response, reterr error) {
	if testHookClientDoResult != nil {
		defer func() { testHookClientDoResult(retres, reterr) }()
	}
	if req.URL == nil {
		req.closeBody()
		return nil, &url.Error{
			Op:  urlErrorOp(req.Method),
			Err: errors.New("http: nil Request.URL"),
		}
	}
	_ = *c // panic early if c is nil; see go.dev/issue/53521

	var (
		deadline      = c.deadline()
		reqs          []*Request
		resp          *Response
		copyHeaders   = c.makeHeadersCopier(req)
		reqBodyClosed = false // have we closed the current req.Body?

		// Redirect behavior:
		redirectMethod string
		includeBody    = true
	)
	uerr := func(err error) error {
		// the body may have been closed already by c.send()
		if !reqBodyClosed {
			req.closeBody()
		}
		var urlStr string
		if resp != nil && resp.Request != nil {
			urlStr = stripPassword(resp.Request.URL)
		} else {
			urlStr = stripPassword(req.URL)
		}
		return &url.Error{
			Op:  urlErrorOp(reqs[0].Method),
			URL: urlStr,
			Err: err,
		}
	}
	for {
		// For all but the first request, create the next
		// request hop and replace req.
		if len(reqs) > 0 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				// While most 3xx responses include a Location, it is not
				// required and 3xx responses without a Location have been
				// observed in the wild. See issues #17773 and #49281.
				return resp, nil
			}
			u, err := req.URL.Parse(loc)
			if err != nil {
				resp.closeBody()
				return nil, uerr(fmt.Errorf("failed to parse Location header %q: %v", loc, err))
			}
			host := ""
			if req.Host != "" && req.Host != req.URL.Host {
				// If the caller specified a custom Host header and the
				// redirect location is relative, preserve the Host header
				// through the redirect. See issue #22233.
				if u, _ := url.Parse(loc); u != nil && !u.IsAbs() {
					host = req.Host
				}
			}
			ireq := reqs[0]
			req = &Request{
				Method:   redirectMethod,
				Response: resp,
				URL:      u,
				Header:   make(Header),
				Host:     host,
				Cancel:   ireq.Cancel,
				ctx:      ireq.ctx,
			}
			if includeBody && ireq.GetBody != nil {
				req.Body, err = ireq.GetBody()
				if err != nil {
					resp.closeBody()
					return nil, uerr(err)
				}
				req.ContentLength = ireq.ContentLength
			}

			// Copy original headers before setting the Referer,
			// in case the user set Referer on their first request.
			// If they really want to override, they can do it in
			// their CheckRedirect func.
			copyHeaders(req)

			// Add the Referer header from the most recent
			// request URL to the new one, if it's not https->http:
			if ref := refererForURL(reqs[len(reqs)-1].URL, req.URL, req.Header.Get("Referer")); ref != "" {
				req.Header.Set("Referer", ref)
			}
			err = c.checkRedirect(req, reqs)

			// Sentinel error to let users select the
			// previous response, without closing its
			// body. See Issue 10069.
			if err == ErrUseLastResponse {
				return resp, nil
			}

			// Close the previous response's body. But
			// read at least some of the body so if it's
			// small the underlying TCP connection will be
			// re-used. No need to check for errors: if it
			// fails, the Transport won't reuse it anyway.
			const maxBodySlurpSize = 2 << 10
			if resp.ContentLength == -1 || resp.ContentLength <= maxBodySlurpSize {
				io.CopyN(io.Discard, resp.Body, maxBodySlurpSize)
			}
			resp.Body.Close()

			if err != nil {
				// Special case for Go 1 compatibility: return both the response
				// and an error if the CheckRedirect function failed.
				// See https://golang.org/issue/3795
				// The resp.Body has already been closed.
				ue := uerr(err)
				ue.(*url.Error).URL = loc
				return resp, ue
			}
		}

		reqs = append(reqs, req)
		var err error
		var didTimeout func() bool
		if resp, didTimeout, err = c.send(req, deadline); err != nil {
			// c.send() always closes req.Body
			reqBodyClosed = true
			if !deadline.IsZero() && didTimeout() {
				err = &timeoutError{err.Error() + " (Client.Timeout exceeded while awaiting headers)"}
			}
			return nil, uerr(err)
		}

		var shouldRedirect, includeBodyOnHop bool
		redirectMethod, shouldRedirect, includeBodyOnHop = redirectBehavior(req.Method, resp, reqs[0])
		if !shouldRedirect {
			return resp, nil
		}
		if !includeBodyOnHop {
			// Once a hop drops the body, we never send it again
			// (because we're now handling a redirect for a request with no body).
			includeBody = false
		}

		req.closeBody()
	}
}

// makeHeadersCopier makes a function that copies headers from the
// initial Request, ireq. For every redirect, this function must be called
// so that it can copy headers into the upcoming Request.
func (c *Client) makeHeadersCopier(ireq *Request) func(*Request) {
	// The headers to copy are from the very initial request.
	// We use a closured callback to keep a reference to these original headers.
	var (
		ireqhdr  = cloneOrMakeHeader(ireq.Header)
		icookies map[string][]*Cookie
	)
	if c.Jar != nil && ireq.Header.Get("Cookie") != "" {
		icookies = make(map[string][]*Cookie)
		for _, c := range ireq.Cookies() {
			icookies[c.Name] = append(icookies[c.Name], c)
		}
	}

	preq := ireq // The previous request
	return func(req *Request) {
		// If Jar is present and there was some initial cookies provided
		// via the request header, then we may need to alter the initial
		// cookies as we follow redirects since each redirect may end up
		// modifying a pre-existing cookie.
		//
		// Since cookies already set in the request header do not contain
		// information about the original domain and path, the logic below
		// assumes any new set cookies override the original cookie
		// regardless of domain or path.
		//
		// See https://golang.org/issue/17494
		if c.Jar != nil && icookies != nil {
			var changed bool
			resp := req.Response // The response that caused the upcoming redirect
			for _, c := range resp.Cookies() {
				if _, ok := icookies[c.Name]; ok {
					delete(icookies, c.Name)
					changed = true
				}
			}
			if changed {
				ireqhdr.Del("Cookie")
				var ss []string
				for _, cs := range icookies {
					for _, c := range cs {
						ss = append(ss, c.Name+"="+c.Value)
					}
				}
				slices.Sort(ss) // Ensure deterministic headers
				ireqhdr.Set("Cookie", strings.Join(ss, "; "))
			}
		}

		// Copy the initial request's Header values
		// (at least the safe ones).
		for k, vv := range ireqhdr {
			if shouldCopyHeaderOnRedirect(k, preq.URL, req.URL) {
				req.Header[k] = vv
			}
		}

		preq = req // Update previous Request with the current request
	}
}

func defaultCheckRedirect(req *Request, via []*Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// Post issues a POST to the specified URL.
//
// Caller should close resp.Body when done reading from it.
//
// If the provided body is an [io.Closer], it is closed after the
// request.
//
// Post is a wrapper around DefaultClient.Post.
//
// To set custom headers, use [NewRequest] and DefaultClient.Do.
//
// See the [Client.Do] method documentation for details on how redirects
// are handled.
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and DefaultClient.Do.
func Post(url, contentType string, body io.Reader) (resp *Response, err error) {
	return DefaultClient.Post(url, contentType, body)
}

// Post issues a POST to the specified URL.
//
// Caller should close resp.Body when done reading from it.
//
// If the provided body is an [io.Closer], it is closed after the
// request.
//
// To set custom headers, use [NewRequest] and [Client.Do].
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and [Client.Do].
//
// See the Client.Do method documentation for details on how redirects
// are handled.
func (c *Client) Post(url, contentType string, body io.Reader) (resp *Response, err error) {
	req, err := NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostForm issues a POST to the specified URL, with data's keys and
// values URL-encoded as the request body.
//
// The Content-Type header is set to application/x-www-form-urlencoded.
// To set other headers, use [NewRequest] and DefaultClient.Do.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// PostForm is a wrapper around DefaultClient.PostForm.
//
// See the [Client.Do] method documentation for details on how redirects
// are handled.
//
// To make a request with a specified [context.Context], use [NewRequestWithContext]
// and DefaultClient.Do.
func PostForm(url string, data url.Values) (resp *Response, err error) {
	return DefaultClient.PostForm(url, data)
}

// PostForm issues a POST to the specified URL,
// with data's keys and values URL-encoded as the request body.
//
// The Content-Type header is set to application/x-www-form-urlencoded.
// To set other headers, use [NewRequest] and [Client.Do].
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// See the Client.Do method documentation for details on how redirects
// are handled.
//
// To make a request with a specified context.Context, use [NewRequestWithContext]
// and Client.Do.
func (c *Client) PostForm(url string, data url.Values) (resp *Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Head issues a HEAD to the specified URL. If the response is one of
// the following redirect codes, Head follows the redirect, up to a
// maximum of 10 redirects:
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// Head is a wrapper around DefaultClient.Head.
//
// To make a request with a specified [context.Context], use [NewRequestWithContext]
// and DefaultClient.Do.
func Head(url string) (resp *Response, err error) {
	return DefaultClient.Head(url)
}

// Head issues a HEAD to the specified URL. If the response is one of the
// following redirect codes, Head follows the redirect after calling the
// [Client.CheckRedirect] function:
//
//	301 (Moved Permanently)
//	302 (Found)
//	303 (See Other)
//	307 (Temporary Redirect)
//	308 (Permanent Redirect)
//
// To make a request with a specified [context.Context], use [NewRequestWithContext]
// and [Client.Do].
func (c *Client) Head(url string) (resp *Response, err error) {
	req, err := NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// CloseIdleConnections closes any connections on its [Transport] which
// were previously connected from previous requests but are now
// sitting idle in a "keep-alive" state. It does not interrupt any
// connections currently in use.
//
// If [Client.Transport] does not have a [Client.CloseIdleConnections] method
// then this method does nothing.
func (c *Client) CloseIdleConnections() {
	type closeIdler interface {
		CloseIdleConnections()
	}
	if tr, ok := c.transport().(closeIdler); ok {
		tr.CloseIdleConnections()
	}
}

// cancelTimerBody is an io.ReadCloser that wraps rc with two features:
//  1. On Read error or close, the stop func is called.
//  2. On Read failure, if reqDidTimeout is true, the error is wrapped and
//     marked as net.Error that hit its timeout.
type cancelTimerBody struct {
	stop          func() // stops the time.Timer waiting to cancel the request
	rc            io.ReadCloser
	reqDidTimeout func() bool
}

func (b *cancelTimerBody) Read(p []byte) (n int, err error) {
	n, err = b.rc.Read(p)
	if err == nil {
		return n, nil
	}
	if err == io.EOF {
		return n, err
	}
	if b.reqDidTimeout() {
		err = &timeoutError{err.Error() + " (Client.Timeout or context cancellation while reading body)"}
	}
	return n, err
}

func (b *cancelTimerBody) Close() error {
	err := b
"""




```