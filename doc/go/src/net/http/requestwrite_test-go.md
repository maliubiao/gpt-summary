Response:
The user wants to understand the functionality of the Go code provided, which is a test file for request writing in the `net/http` package. I need to analyze the code and explain:

1. **Purpose of the test file:** What aspects of request writing are being tested?
2. **Go features demonstrated:** Can I identify specific Go language features being used in the tests?
3. **Code examples:** Provide concrete Go code examples based on the tests.
4. **Input and Output:** For code examples, explain the assumed input and expected output.
5. **Command-line arguments:**  Are any command-line arguments relevant to this test file?
6. **Common mistakes:** Are there any common pitfalls users might encounter when working with request writing based on these tests?

Let's break down the analysis:

*   The file `requestwrite_test.go` clearly contains test cases for the `Request.Write` and `Request.WriteProxy` methods.
*   The `reqWriteTest` struct defines the structure of each test case, including the request itself, optional body, expected output for `Write` and `WriteProxy`, and expected errors.
*   The `reqWriteTests` variable is a slice of these test cases, covering various scenarios like different HTTP methods, headers, body types, content lengths, and HTTP versions.
*   The `TestRequestWrite` function iterates through these test cases and calls `Req.Write` and `Req.WriteProxy`, comparing the output with the expected values.
*   The `TestRequestWriteTransport` function seems to be testing the request writing behavior within the context of a `Transport`, likely focusing on how the `Transport` handles things like chunking and content length.
*   The `TestRequestWriteClosesBody` function specifically tests if the `Request.Write` method correctly closes the request body.
*   The `TestRequestWriteError` function tests error handling during the write process.
*   The `dumpRequestOut` function is a helper function to simulate writing a request to a network connection and capturing the output.

Based on this, I can structure the answer to address each point requested by the user.
这个go语言文件 `go/src/net/http/requestwrite_test.go` 是 `net/http` 标准库中用来测试 HTTP 请求写入功能的测试文件。它主要测试了 `http.Request` 类型的 `Write` 和 `WriteProxy` 方法，这两个方法负责将 `http.Request` 对象序列化为符合 HTTP 协议的字节流，以便发送到服务器或代理服务器。

**主要功能列举:**

1. **测试 `Request.Write` 方法:**  验证将 `http.Request` 对象写入 `io.Writer` 时，生成的 HTTP 请求报文是否符合预期。这包括：
    *   请求行（Method, URL, Protocol Version）的正确格式化。
    *   请求头的正确写入，包括标准头和自定义头。
    *   请求体的处理，包括无 body、固定长度 body 和 chunked 编码 body。
    *   对不同 HTTP 版本（例如 HTTP/1.1）的支持。
    *   处理 `Content-Length` 和 `Transfer-Encoding` 头部的逻辑。
    *   处理 `Host` 头部的逻辑，包括当 `Request.Host` 和 `Request.URL.Host` 都存在或不存在的情况。
    *   处理包含特殊字符的 URL。
    *   处理 `CONNECT` 方法的请求。
    *   处理空的 header 值。
    *   当提供错误的 `ContentLength` 时，是否返回预期的错误。

2. **测试 `Request.WriteProxy` 方法:**  验证在通过代理服务器发送请求时，将 `http.Request` 对象写入 `io.Writer` 时，生成的 HTTP 请求报文是否符合预期。与 `Request.Write` 的主要区别在于，`WriteProxy` 方法会将完整的 URL (包括 scheme 和 host) 写入请求行。

3. **测试 `Request.Write` 方法的错误处理:** 验证在写入过程中发生错误时，`Request.Write` 方法是否能正确返回错误。

4. **测试 `Request.Write` 是否关闭请求体:** 验证在 `Request.Write` 方法执行完毕后，如果请求体 `Body` 实现了 `io.Closer` 接口，是否会被正确关闭。

5. **间接测试 `NewRequest`:** 虽然不是直接测试 `NewRequest`，但测试用例中创建 `http.Request` 对象时经常会使用 `NewRequest`，这可以间接验证 `NewRequest` 创建的请求对象是否能被正确写入。

**Go 语言功能的实现举例 (基于代码推理):**

这个测试文件主要测试的是 `net/http` 包中与请求写入相关的逻辑，这些逻辑通常涉及到字符串格式化、`io.Writer` 接口的使用以及对 HTTP 协议规范的实现。

以下是一个基于测试用例 **#1** 的简化代码示例，演示了 `Request.Write` 的基本使用：

```go
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
)

func main() {
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "http",
			Host:   "www.google.com",
			Path:   "/search",
		},
		ProtoMajor:       1,
		ProtoMinor:       1,
		Header:           http.Header{},
		TransferEncoding: []string{"chunked"},
	}

	body := []byte("abcdef")
	req.Body = http.NopCloser(bytes.NewReader(body))

	var buf bytes.Buffer
	err := req.Write(&buf)
	if err != nil {
		fmt.Println("写入请求失败:", err)
		return
	}

	fmt.Println("写入的请求内容:\n", buf.String())
}
```

**假设输入与输出:**

在上面的示例中，假设我们创建了一个 `GET` 请求，目标是 `http://www.google.com/search`，并设置了 chunked 编码的请求体 "abcdef"。

**预期输出:**

```
写入的请求内容:
 GET /search HTTP/1.1
 Host: www.google.com
 User-Agent: Go-http-client/1.1
 Transfer-Encoding: chunked

 6
 abcdef
 0

```

**代码推理:**

*   `req.Write(&buf)` 方法将 `req` 对象的内容写入到 `bytes.Buffer` 类型的 `buf` 中。
*   由于 `req.TransferEncoding` 设置为 `chunked`，所以请求体会被编码为 chunked 格式。
*   输出包含了请求行、必要的头部（Host 和 User-Agent 是默认添加的），以及 chunked 编码的请求体。

**命令行参数:**

这个测试文件本身是一个 Go 语言的测试文件，通常通过 `go test` 命令来运行，例如：

```bash
go test -run TestRequestWrite net/http
```

这个命令会运行 `net/http` 包中所有名称匹配 `TestRequestWrite` 的测试函数。 `go test` 命令有很多其他的命令行参数，例如 `-v` 用于显示更详细的输出，`-count` 用于指定运行测试的次数等等。 这些参数并不直接控制 `requestwrite_test.go` 文件中的逻辑，而是 Go 测试框架提供的通用功能。

**使用者易犯错的点:**

1. **错误地设置 `ContentLength` 和请求体大小不一致:**  如果手动设置了 `Request.ContentLength`，但实际提供的 `Body` 的长度与之不符，`Request.Write` 会返回错误。

    ```go
    req := &http.Request{
        Method:        "POST",
        URL:           &url.URL{Path: "/"},
        Host:          "example.com",
        ContentLength: 10,
    }
    req.Body = http.NopCloser(bytes.NewReader([]byte("short"))) // 实际只有 5 字节

    var buf bytes.Buffer
    err := req.Write(&buf)
    fmt.Println(err) // 输出: http: ContentLength=10 with Body length 5
    ```

2. **忘记设置必要的头部:** 有些服务器会要求特定的头部，例如 `Host`。如果创建 `http.Request` 对象时没有正确设置这些头部，可能会导致请求失败。虽然 `Request.Write` 会自动添加一些默认头部（例如 `User-Agent`），但其他必要的头部需要用户显式设置。

3. **对 `WriteProxy` 的理解偏差:**  新手可能不清楚 `Write` 和 `WriteProxy` 的区别，在需要发送到代理服务器的请求时，仍然使用 `Write` 方法，导致代理服务器无法正确处理请求。

    ```go
    // 错误的使用方式 (假设需要通过代理)
    req := &http.Request{
        Method: "GET",
        URL: &url.URL{
            Scheme: "http",
            Host:   "www.example.com",
            Path:   "/",
        },
        Host: "www.example.com",
    }

    var buf bytes.Buffer
    err := req.Write(&buf) // 本应使用 req.WriteProxy()
    // ...
    ```

    正确的做法是使用 `WriteProxy` 方法。

4. **混淆 `Request.Host` 和 `Request.URL.Host`:**  `Request.Host` 优先于 `Request.URL.Host` 用于设置 HTTP 请求中的 `Host` 头部。如果两者设置不一致，可能会导致意外的结果。理解它们之间的关系和优先级很重要。

总而言之， `go/src/net/http/requestwrite_test.go` 通过大量的测试用例，细致地验证了 `net/http` 包中请求写入功能的正确性和健壮性，为开发者正确使用 `http.Request` 提供了保障。

### 提示词
```
这是路径为go/src/net/http/requestwrite_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

type reqWriteTest struct {
	Req  Request
	Body any // optional []byte or func() io.ReadCloser to populate Req.Body

	// Any of these three may be empty to skip that test.
	WantWrite string // Request.Write
	WantProxy string // Request.WriteProxy

	WantError error // wanted error from Request.Write
}

var reqWriteTests = []reqWriteTest{
	// HTTP/1.1 => chunked coding; no body; no trailer
	0: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Scheme: "http",
				Host:   "www.techcrunch.com",
				Path:   "/",
			},
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: Header{
				"Accept":           {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
				"Accept-Charset":   {"ISO-8859-1,utf-8;q=0.7,*;q=0.7"},
				"Accept-Encoding":  {"gzip,deflate"},
				"Accept-Language":  {"en-us,en;q=0.5"},
				"Keep-Alive":       {"300"},
				"Proxy-Connection": {"keep-alive"},
				"User-Agent":       {"Fake"},
			},
			Body:  nil,
			Close: false,
			Host:  "www.techcrunch.com",
			Form:  map[string][]string{},
		},

		WantWrite: "GET / HTTP/1.1\r\n" +
			"Host: www.techcrunch.com\r\n" +
			"User-Agent: Fake\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
			"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n" +
			"Accept-Encoding: gzip,deflate\r\n" +
			"Accept-Language: en-us,en;q=0.5\r\n" +
			"Keep-Alive: 300\r\n" +
			"Proxy-Connection: keep-alive\r\n\r\n",

		WantProxy: "GET http://www.techcrunch.com/ HTTP/1.1\r\n" +
			"Host: www.techcrunch.com\r\n" +
			"User-Agent: Fake\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
			"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n" +
			"Accept-Encoding: gzip,deflate\r\n" +
			"Accept-Language: en-us,en;q=0.5\r\n" +
			"Keep-Alive: 300\r\n" +
			"Proxy-Connection: keep-alive\r\n\r\n",
	},
	// HTTP/1.1 => chunked coding; body; empty trailer
	1: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Scheme: "http",
				Host:   "www.google.com",
				Path:   "/search",
			},
			ProtoMajor:       1,
			ProtoMinor:       1,
			Header:           Header{},
			TransferEncoding: []string{"chunked"},
		},

		Body: []byte("abcdef"),

		WantWrite: "GET /search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			chunk("abcdef") + chunk(""),

		WantProxy: "GET http://www.google.com/search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			chunk("abcdef") + chunk(""),
	},
	// HTTP/1.1 POST => chunked coding; body; empty trailer
	2: {
		Req: Request{
			Method: "POST",
			URL: &url.URL{
				Scheme: "http",
				Host:   "www.google.com",
				Path:   "/search",
			},
			ProtoMajor:       1,
			ProtoMinor:       1,
			Header:           Header{},
			Close:            true,
			TransferEncoding: []string{"chunked"},
		},

		Body: []byte("abcdef"),

		WantWrite: "POST /search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Connection: close\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			chunk("abcdef") + chunk(""),

		WantProxy: "POST http://www.google.com/search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Connection: close\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			chunk("abcdef") + chunk(""),
	},

	// HTTP/1.1 POST with Content-Length, no chunking
	3: {
		Req: Request{
			Method: "POST",
			URL: &url.URL{
				Scheme: "http",
				Host:   "www.google.com",
				Path:   "/search",
			},
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        Header{},
			Close:         true,
			ContentLength: 6,
		},

		Body: []byte("abcdef"),

		WantWrite: "POST /search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 6\r\n" +
			"\r\n" +
			"abcdef",

		WantProxy: "POST http://www.google.com/search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 6\r\n" +
			"\r\n" +
			"abcdef",
	},

	// HTTP/1.1 POST with Content-Length in headers
	4: {
		Req: Request{
			Method: "POST",
			URL:    mustParseURL("http://example.com/"),
			Host:   "example.com",
			Header: Header{
				"Content-Length": []string{"10"}, // ignored
			},
			ContentLength: 6,
		},

		Body: []byte("abcdef"),

		WantWrite: "POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 6\r\n" +
			"\r\n" +
			"abcdef",

		WantProxy: "POST http://example.com/ HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 6\r\n" +
			"\r\n" +
			"abcdef",
	},

	// default to HTTP/1.1
	5: {
		Req: Request{
			Method: "GET",
			URL:    mustParseURL("/search"),
			Host:   "www.google.com",
		},

		WantWrite: "GET /search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"\r\n",
	},

	// Request with a 0 ContentLength and a 0 byte body.
	6: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0, // as if unset by user
		},

		Body: func() io.ReadCloser { return io.NopCloser(io.LimitReader(strings.NewReader("xx"), 0)) },

		WantWrite: "POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n0\r\n\r\n",

		WantProxy: "POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n0\r\n\r\n",
	},

	// Request with a 0 ContentLength and a nil body.
	7: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0, // as if unset by user
		},

		Body: func() io.ReadCloser { return nil },

		WantWrite: "POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",

		WantProxy: "POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	},

	// Request with a 0 ContentLength and a 1 byte body.
	8: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0, // as if unset by user
		},

		Body: func() io.ReadCloser { return io.NopCloser(io.LimitReader(strings.NewReader("xx"), 1)) },

		WantWrite: "POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			chunk("x") + chunk(""),

		WantProxy: "POST / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			chunk("x") + chunk(""),
	},

	// Request with a ContentLength of 10 but a 5 byte body.
	9: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 10, // but we're going to send only 5 bytes
		},
		Body:      []byte("12345"),
		WantError: errors.New("http: ContentLength=10 with Body length 5"),
	},

	// Request with a ContentLength of 4 but an 8 byte body.
	10: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 4, // but we're going to try to send 8 bytes
		},
		Body:      []byte("12345678"),
		WantError: errors.New("http: ContentLength=4 with Body length 8"),
	},

	// Request with a 5 ContentLength and nil body.
	11: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 5, // but we'll omit the body
		},
		WantError: errors.New("http: Request.ContentLength=5 with nil Body"),
	},

	// Request with a 0 ContentLength and a body with 1 byte content and an error.
	12: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0, // as if unset by user
		},

		Body: func() io.ReadCloser {
			err := errors.New("Custom reader error")
			errReader := iotest.ErrReader(err)
			return io.NopCloser(io.MultiReader(strings.NewReader("x"), errReader))
		},

		WantError: errors.New("Custom reader error"),
	},

	// Request with a 0 ContentLength and a body without content and an error.
	13: {
		Req: Request{
			Method:        "POST",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0, // as if unset by user
		},

		Body: func() io.ReadCloser {
			err := errors.New("Custom reader error")
			errReader := iotest.ErrReader(err)
			return io.NopCloser(errReader)
		},

		WantError: errors.New("Custom reader error"),
	},

	// Verify that DumpRequest preserves the HTTP version number, doesn't add a Host,
	// and doesn't add a User-Agent.
	14: {
		Req: Request{
			Method:     "GET",
			URL:        mustParseURL("/foo"),
			ProtoMajor: 1,
			ProtoMinor: 0,
			Header: Header{
				"X-Foo": []string{"X-Bar"},
			},
		},

		WantWrite: "GET /foo HTTP/1.1\r\n" +
			"Host: \r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"X-Foo: X-Bar\r\n\r\n",
	},

	// If no Request.Host and no Request.URL.Host, we send
	// an empty Host header, and don't use
	// Request.Header["Host"]. This is just testing that
	// we don't change Go 1.0 behavior.
	15: {
		Req: Request{
			Method: "GET",
			Host:   "",
			URL: &url.URL{
				Scheme: "http",
				Host:   "",
				Path:   "/search",
			},
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: Header{
				"Host": []string{"bad.example.com"},
			},
		},

		WantWrite: "GET /search HTTP/1.1\r\n" +
			"Host: \r\n" +
			"User-Agent: Go-http-client/1.1\r\n\r\n",
	},

	// Opaque test #1 from golang.org/issue/4860
	16: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Scheme: "http",
				Host:   "www.google.com",
				Opaque: "/%2F/%2F/",
			},
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     Header{},
		},

		WantWrite: "GET /%2F/%2F/ HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n\r\n",
	},

	// Opaque test #2 from golang.org/issue/4860
	17: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Scheme: "http",
				Host:   "x.google.com",
				Opaque: "//y.google.com/%2F/%2F/",
			},
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     Header{},
		},

		WantWrite: "GET http://y.google.com/%2F/%2F/ HTTP/1.1\r\n" +
			"Host: x.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n\r\n",
	},

	// Testing custom case in header keys. Issue 5022.
	18: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Scheme: "http",
				Host:   "www.google.com",
				Path:   "/",
			},
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: Header{
				"ALL-CAPS": {"x"},
			},
		},

		WantWrite: "GET / HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"ALL-CAPS: x\r\n" +
			"\r\n",
	},

	// Request with host header field; IPv6 address with zone identifier
	19: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Host: "[fe80::1%en0]",
			},
		},

		WantWrite: "GET / HTTP/1.1\r\n" +
			"Host: [fe80::1]\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"\r\n",
	},

	// Request with optional host header field; IPv6 address with zone identifier
	20: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Host: "www.example.com",
			},
			Host: "[fe80::1%en0]:8080",
		},

		WantWrite: "GET / HTTP/1.1\r\n" +
			"Host: [fe80::1]:8080\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"\r\n",
	},

	// CONNECT without Opaque
	21: {
		Req: Request{
			Method: "CONNECT",
			URL: &url.URL{
				Scheme: "https", // of proxy.com
				Host:   "proxy.com",
			},
		},
		// What we used to do, locking that behavior in:
		WantWrite: "CONNECT proxy.com HTTP/1.1\r\n" +
			"Host: proxy.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"\r\n",
	},

	// CONNECT with Opaque
	22: {
		Req: Request{
			Method: "CONNECT",
			URL: &url.URL{
				Scheme: "https", // of proxy.com
				Host:   "proxy.com",
				Opaque: "backend:443",
			},
		},
		WantWrite: "CONNECT backend:443 HTTP/1.1\r\n" +
			"Host: proxy.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"\r\n",
	},

	// Verify that a nil header value doesn't get written.
	23: {
		Req: Request{
			Method: "GET",
			URL:    mustParseURL("/foo"),
			Header: Header{
				"X-Foo":             []string{"X-Bar"},
				"X-Idempotency-Key": nil,
			},
		},

		WantWrite: "GET /foo HTTP/1.1\r\n" +
			"Host: \r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"X-Foo: X-Bar\r\n\r\n",
	},
	24: {
		Req: Request{
			Method: "GET",
			URL:    mustParseURL("/foo"),
			Header: Header{
				"X-Foo":             []string{"X-Bar"},
				"X-Idempotency-Key": []string{},
			},
		},

		WantWrite: "GET /foo HTTP/1.1\r\n" +
			"Host: \r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"X-Foo: X-Bar\r\n\r\n",
	},

	25: {
		Req: Request{
			Method: "GET",
			URL: &url.URL{
				Host:     "www.example.com",
				RawQuery: "new\nline", // or any CTL
			},
		},
		WantError: errors.New("net/http: can't write control character in Request.URL"),
	},

	26: { // Request with nil body and PATCH method. Issue #40978
		Req: Request{
			Method:        "PATCH",
			URL:           mustParseURL("/"),
			Host:          "example.com",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0, // as if unset by user
		},
		Body: nil,
		WantWrite: "PATCH / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 0\r\n\r\n",
		WantProxy: "PATCH / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 0\r\n\r\n",
	},
}

func TestRequestWrite(t *testing.T) {
	for i := range reqWriteTests {
		tt := &reqWriteTests[i]

		setBody := func() {
			if tt.Body == nil {
				return
			}
			switch b := tt.Body.(type) {
			case []byte:
				tt.Req.Body = io.NopCloser(bytes.NewReader(b))
			case func() io.ReadCloser:
				tt.Req.Body = b()
			}
		}
		setBody()
		if tt.Req.Header == nil {
			tt.Req.Header = make(Header)
		}

		var braw strings.Builder
		err := tt.Req.Write(&braw)
		if g, e := fmt.Sprintf("%v", err), fmt.Sprintf("%v", tt.WantError); g != e {
			t.Errorf("writing #%d, err = %q, want %q", i, g, e)
			continue
		}
		if err != nil {
			continue
		}

		if tt.WantWrite != "" {
			sraw := braw.String()
			if sraw != tt.WantWrite {
				t.Errorf("Test %d, expecting:\n%s\nGot:\n%s\n", i, tt.WantWrite, sraw)
				continue
			}
		}

		if tt.WantProxy != "" {
			setBody()
			var praw strings.Builder
			err = tt.Req.WriteProxy(&praw)
			if err != nil {
				t.Errorf("WriteProxy #%d: %s", i, err)
				continue
			}
			sraw := praw.String()
			if sraw != tt.WantProxy {
				t.Errorf("Test Proxy %d, expecting:\n%s\nGot:\n%s\n", i, tt.WantProxy, sraw)
				continue
			}
		}
	}
}

func TestRequestWriteTransport(t *testing.T) {
	t.Parallel()

	matchSubstr := func(substr string) func(string) error {
		return func(written string) error {
			if !strings.Contains(written, substr) {
				return fmt.Errorf("expected substring %q in request: %s", substr, written)
			}
			return nil
		}
	}

	noContentLengthOrTransferEncoding := func(req string) error {
		if strings.Contains(req, "Content-Length: ") {
			return fmt.Errorf("unexpected Content-Length in request: %s", req)
		}
		if strings.Contains(req, "Transfer-Encoding: ") {
			return fmt.Errorf("unexpected Transfer-Encoding in request: %s", req)
		}
		return nil
	}

	all := func(checks ...func(string) error) func(string) error {
		return func(req string) error {
			for _, c := range checks {
				if err := c(req); err != nil {
					return err
				}
			}
			return nil
		}
	}

	type testCase struct {
		method string
		clen   int64 // ContentLength
		body   io.ReadCloser
		want   func(string) error

		// optional:
		init         func(*testCase)
		afterReqRead func()
	}

	tests := []testCase{
		{
			method: "GET",
			want:   noContentLengthOrTransferEncoding,
		},
		{
			method: "GET",
			body:   io.NopCloser(strings.NewReader("")),
			want:   noContentLengthOrTransferEncoding,
		},
		{
			method: "GET",
			clen:   -1,
			body:   io.NopCloser(strings.NewReader("")),
			want:   noContentLengthOrTransferEncoding,
		},
		// A GET with a body, with explicit content length:
		{
			method: "GET",
			clen:   7,
			body:   io.NopCloser(strings.NewReader("foobody")),
			want: all(matchSubstr("Content-Length: 7"),
				matchSubstr("foobody")),
		},
		// A GET with a body, sniffing the leading "f" from "foobody".
		{
			method: "GET",
			clen:   -1,
			body:   io.NopCloser(strings.NewReader("foobody")),
			want: all(matchSubstr("Transfer-Encoding: chunked"),
				matchSubstr("\r\n1\r\nf\r\n"),
				matchSubstr("oobody")),
		},
		// But a POST request is expected to have a body, so
		// no sniffing happens:
		{
			method: "POST",
			clen:   -1,
			body:   io.NopCloser(strings.NewReader("foobody")),
			want: all(matchSubstr("Transfer-Encoding: chunked"),
				matchSubstr("foobody")),
		},
		{
			method: "POST",
			clen:   -1,
			body:   io.NopCloser(strings.NewReader("")),
			want:   all(matchSubstr("Transfer-Encoding: chunked")),
		},
		// Verify that a blocking Request.Body doesn't block forever.
		{
			method: "GET",
			clen:   -1,
			init: func(tt *testCase) {
				pr, pw := io.Pipe()
				tt.afterReqRead = func() {
					pw.Close()
				}
				tt.body = io.NopCloser(pr)
			},
			want: matchSubstr("Transfer-Encoding: chunked"),
		},
	}

	for i, tt := range tests {
		if tt.init != nil {
			tt.init(&tt)
		}
		req := &Request{
			Method: tt.method,
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
			},
			Header:        make(Header),
			ContentLength: tt.clen,
			Body:          tt.body,
		}
		got, err := dumpRequestOut(req, tt.afterReqRead)
		if err != nil {
			t.Errorf("test[%d]: %v", i, err)
			continue
		}
		if err := tt.want(string(got)); err != nil {
			t.Errorf("test[%d]: %v", i, err)
		}
	}
}

type closeChecker struct {
	io.Reader
	closed bool
}

func (rc *closeChecker) Close() error {
	rc.closed = true
	return nil
}

// TestRequestWriteClosesBody tests that Request.Write closes its request.Body.
// It also indirectly tests NewRequest and that it doesn't wrap an existing Closer
// inside a NopCloser, and that it serializes it correctly.
func TestRequestWriteClosesBody(t *testing.T) {
	rc := &closeChecker{Reader: strings.NewReader("my body")}
	req, err := NewRequest("POST", "http://foo.com/", rc)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(strings.Builder)
	if err := req.Write(buf); err != nil {
		t.Error(err)
	}
	if !rc.closed {
		t.Error("body not closed after write")
	}
	expected := "POST / HTTP/1.1\r\n" +
		"Host: foo.com\r\n" +
		"User-Agent: Go-http-client/1.1\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" +
		chunk("my body") +
		chunk("")
	if buf.String() != expected {
		t.Errorf("write:\n got: %s\nwant: %s", buf.String(), expected)
	}
}

func chunk(s string) string {
	return fmt.Sprintf("%x\r\n%s\r\n", len(s), s)
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(fmt.Sprintf("Error parsing URL %q: %v", s, err))
	}
	return u
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestRequestWriteError tests the Write err != nil checks in (*Request).write.
func TestRequestWriteError(t *testing.T) {
	failAfter, writeCount := 0, 0
	errFail := errors.New("fake write failure")

	// w is the buffered io.Writer to write the request to. It
	// fails exactly once on its Nth Write call, as controlled by
	// failAfter. It also tracks the number of calls in
	// writeCount.
	w := struct {
		io.ByteWriter // to avoid being wrapped by a bufio.Writer
		io.Writer
	}{
		nil,
		writerFunc(func(p []byte) (n int, err error) {
			writeCount++
			if failAfter == 0 {
				err = errFail
			}
			failAfter--
			return len(p), err
		}),
	}

	req, _ := NewRequest("GET", "http://example.com/", nil)
	const writeCalls = 4 // number of Write calls in current implementation
	sawGood := false
	for n := 0; n <= writeCalls+2; n++ {
		failAfter = n
		writeCount = 0
		err := req.Write(w)
		var wantErr error
		if n < writeCalls {
			wantErr = errFail
		}
		if err != wantErr {
			t.Errorf("for fail-after %d Writes, err = %v; want %v", n, err, wantErr)
			continue
		}
		if err == nil {
			sawGood = true
			if writeCount != writeCalls {
				t.Fatalf("writeCalls constant is outdated in test")
			}
		}
		if writeCount > writeCalls || writeCount > n+1 {
			t.Errorf("for fail-after %d, saw unexpectedly high (%d) write calls", n, writeCount)
		}
	}
	if !sawGood {
		t.Fatalf("writeCalls constant is outdated in test")
	}
}

// dumpRequestOut is a modified copy of net/http/httputil.DumpRequestOut.
// Unlike the original, this version doesn't mutate the req.Body and
// try to restore it. It always dumps the whole body.
// And it doesn't support https.
func dumpRequestOut(req *Request, onReadHeaders func()) ([]byte, error) {

	// Use the actual Transport code to record what we would send
	// on the wire, but not using TCP.  Use a Transport with a
	// custom dialer that returns a fake net.Conn that waits
	// for the full input (and recording it), and then responds
	// with a dummy response.
	var buf bytes.Buffer // records the output
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	dr := &delegateReader{c: make(chan io.Reader)}

	t := &Transport{
		Dial: func(net, addr string) (net.Conn, error) {
			return &dumpConn{io.MultiWriter(&buf, pw), dr}, nil
		},
	}
	defer t.CloseIdleConnections()

	// Wait for the request before replying with a dummy response:
	go func() {
		req, err := ReadRequest(bufio.NewReader(pr))
		if err == nil {
			if onReadHeaders != nil {
				onReadHeaders()
			}
			// Ensure all the body is read; otherwise
			// we'll get a partial dump.
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
		}
		dr.c <- strings.NewReader("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
	}()

	_, err := t.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// delegateReader is a reader that delegates to another reader,
// once it arrives on a channel.
type delegateReader struct {
	c chan io.Reader
	r io.Reader // nil until received from c
}

func (r *delegateReader) Read(p []byte) (int, error) {
	if r.r == nil {
		r.r = <-r.c
	}
	return r.r.Read(p)
}

// dumpConn is a net.Conn that writes to Writer and reads from Reader.
type dumpConn struct {
	io.Writer
	io.Reader
}

func (c *dumpConn) Close() error                       { return nil }
func (c *dumpConn) LocalAddr() net.Addr                { return nil }
func (c *dumpConn) RemoteAddr() net.Addr               { return nil }
func (c *dumpConn) SetDeadline(t time.Time) error      { return nil }
func (c *dumpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dumpConn) SetWriteDeadline(t time.Time) error { return nil }
```