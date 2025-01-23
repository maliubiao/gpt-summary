Response:
Let's break down the thought process for analyzing the provided Go code snippet for `go/src/net/http/response.go`.

**1. Understanding the Goal:**

The request asks for a comprehensive explanation of the provided Go code, focusing on its functionality, potential Go language features it implements, code examples, command-line argument handling (if any), and common pitfalls for users. The context is clearly the `net/http` package, specifically the part dealing with HTTP responses.

**2. Initial Code Scan and Keyword Identification:**

I'll start by quickly scanning the code for prominent keywords and structures:

* `package http`:  Confirms the package context.
* `import`: Lists dependencies, hinting at functionalities like buffering (`bufio`), cryptography (`crypto/tls`), error handling (`errors`), input/output (`io`), text processing (`net/textproto`, `strings`), URL parsing (`net/url`), and string conversion (`strconv`). The presence of `golang.org/x/net/http/httpguts` suggests internal HTTP utilities.
* `var respExcludeHeader`:  Indicates a set of headers to be excluded during some processing, likely related to response writing.
* `type Response struct`: This is the central data structure. I'll pay close attention to its fields and their documentation. The comments in the `Response` struct are very informative, which will be crucial.
* Function definitions like `Cookies()`, `Location()`, `ReadResponse()`, `fixPragmaCacheControl()`, `ProtoAtLeast()`, `Write()`, `closeBody()`, `bodyIsWritable()`, `isProtocolSwitch()`, `isProtocolSwitchResponse()`, `isProtocolSwitchHeader()`: These are the core actions the code performs. I need to understand what each function does.
* Comments: The comments are generally well-written and provide valuable insights into the purpose and behavior of different parts of the code.

**3. Deconstructing the Functionality - The "What":**

Based on the code and comments, I start listing the core functionalities:

* **Represents an HTTP Response:** The `Response` struct is the central element.
* **Parsing HTTP Responses:** The `ReadResponse` function is clearly responsible for taking a raw data stream and converting it into a usable `Response` struct. This involves parsing the status line, headers, and setting up the body reader.
* **Accessing Response Information:** Functions like `Cookies()`, `Location()`, and the public fields of the `Response` struct provide ways to access different parts of the response data.
* **Writing HTTP Responses:** The `Write()` function handles the reverse process – taking a `Response` struct and formatting it into an HTTP response stream.
* **Handling Specific HTTP Features:**  I see code related to:
    * Transfer encoding (`TransferEncoding` field, `readTransfer` function, `newTransferWriter`).
    * Trailers (`Trailer` field).
    * Content length (`ContentLength` field).
    * Connection closing (`Close` field).
    * Compression (`Uncompressed` field).
    * Protocol switching (`isProtocolSwitch` functions).
    * Cookies (`Cookies()` function).
    * Redirects (`Location()` function).
    * Caching (`fixPragmaCacheControl()` function).
* **Managing the Response Body:** The `Body` field (an `io.ReadCloser`) is fundamental. The comments highlight the streaming nature and the need to close it.

**4. Identifying Go Language Features - The "How":**

Now, I look for specific Go features used in the implementation:

* **Structs:** The `Response` struct is a key example.
* **Methods:** Functions associated with the `Response` struct (e.g., `r.Cookies()`).
* **Interfaces:** `io.Reader`, `io.ReadCloser`, `io.Writer` are heavily used, demonstrating interface-based programming for handling data streams.
* **Error Handling:** The code uses `error` as a return type and checks for errors. `errors.New()` is used to create custom errors.
* **Maps:** `Header` and `Trailer` are `map[string][]string`, used for storing HTTP headers.
* **Slices:** `TransferEncoding` is a slice of strings.
* **String Manipulation:** Functions from the `strings` package are used for parsing the status line and headers.
* **String Conversion:** `strconv.Atoi()` is used to convert the status code to an integer.
* **Type Embedding (Implicit):** The `tw.writeHeader()` and `tw.writeBody()` suggest the use of a separate `transferWriter` type, likely used to encapsulate the logic for writing the body and handling transfer encodings.
* **Pointers:** Used extensively for passing and modifying `Response` objects and related data.

**5. Crafting Code Examples - Putting it Together:**

For each identified feature, I think about simple, illustrative examples. I consider:

* **Reading a response:** Demonstrating how to make a request and access the `Response` fields.
* **Writing a response:** Showing how to create a `Response` struct and send it.
* **Handling headers:**  Accessing and iterating through headers.
* **Reading the body:** Showing the basic read and close pattern.
* **Following redirects:**  Demonstrating the use of `Location()`.
* **Checking the protocol version:**  Using `ProtoAtLeast()`.

**6. Considering Command-Line Arguments:**

I review the code specifically for any interaction with `os.Args` or other mechanisms for handling command-line arguments. I don't find any in this snippet, so I conclude it's not directly involved in command-line processing.

**7. Identifying Common Pitfalls:**

I focus on aspects that might confuse or lead to errors for users:

* **Not closing the body:**  The documentation strongly emphasizes this. I'll provide a clear example of the correct and incorrect usage.
* **Concurrent access to `Trailer`:**  The comments warn about this. I'll reiterate this point.
* **Modifying `Response.Header` directly:** While possible, the comments explain that some fields are authoritative. It's a potential source of confusion.
* **Assuming the body is fully in memory:**  The streaming nature of the body needs to be highlighted.

**8. Structuring the Answer:**

I organize the information logically, following the prompt's structure:

* **功能列举:** Start with a concise list of the main functionalities.
* **Go 语言功能实现举例:** Provide code examples for the identified Go language features. Use comments to explain the purpose of each example. Include assumptions for inputs and expected outputs where relevant.
* **代码推理 (Implicit):** The examples themselves involve a degree of code reasoning, showing how the different parts of the `Response` struct are used.
* **命令行参数处理:** Clearly state that this part of the code doesn't handle command-line arguments.
* **易犯错的点:**  Provide concrete examples of common mistakes and explain why they are problematic.

**Self-Correction/Refinement:**

During the process, I might realize I've missed something or made an assumption. For example:

* Initially, I might not have fully grasped the significance of `respExcludeHeader`. On closer inspection of the `Write()` function, I see its use in `r.Header.WriteSubset()`, indicating it's for selectively writing headers.
* I might need to refine the examples to be clearer or more concise.
* I'll double-check the comments in the code to ensure my explanations align with the intended behavior.

By following these steps, I can generate a comprehensive and accurate explanation of the provided Go code snippet, addressing all aspects of the request.
这段代码是 Go 语言 `net/http` 包中处理 HTTP 响应的一部分，主要负责表示、读取和写入 HTTP 响应。

**它的主要功能包括：**

1. **表示 HTTP 响应:**  `Response` 结构体定义了 HTTP 响应的各种属性，例如状态码、状态文本、协议版本、头部信息、响应体、内容长度、传输编码等。
2. **读取 HTTP 响应:**  `ReadResponse` 函数负责从 `bufio.Reader` 中读取 HTTP 响应，并将其解析成 `Response` 结构体。它处理了状态行、头部信息和传输编码。
3. **解析 HTTP 头部:**  代码中涉及到解析和处理 HTTP 头部信息，例如 `readSetCookies`（虽然未在此代码片段中直接显示，但 `Cookies()` 方法调用了它），以及 `fixPragmaCacheControl` 用于处理 `Pragma` 头部。
4. **处理重定向 Location 头部:**  `Location()` 方法用于获取响应头部的 `Location` 字段，并解析成 URL，用于处理 HTTP 重定向。
5. **写入 HTTP 响应:**  `Write` 函数负责将 `Response` 结构体格式化为符合 HTTP/1.x 协议的响应报文，并写入到 `io.Writer` 中。它处理了状态行、头部信息、响应体和 Trailer。
6. **处理传输编码:**  代码中涉及到 `TransferEncoding` 字段和 `readTransfer` 函数，用于处理 HTTP 传输编码，例如分块传输。
7. **处理 Trailer 头部:** `Trailer` 字段用于存储 HTTP Trailer 头部信息，这些信息在响应体的最后发送。
8. **判断协议版本:** `ProtoAtLeast` 方法用于判断响应的 HTTP 协议版本是否至少为指定的版本。
9. **判断是否是协议切换响应:** `isProtocolSwitch` 和 `isProtocolSwitchResponse` 函数用于判断响应是否是协议切换响应（例如 WebSocket 握手）。
10. **管理响应体:** `Body` 字段表示响应体，并且强调了需要在使用后关闭 `Body` 的重要性。 代码中也处理了响应体为空的情况。
11. **判断响应体是否可写:** `bodyIsWritable` 方法用于判断响应体是否可写，这通常用于协议切换的场景。

**它是什么 Go 语言功能的实现：**

这段代码主要实现了 Go 语言标准库 `net/http` 包中处理 HTTP 客户端接收到的响应的功能。 它定义了表示响应的数据结构，并提供了读取和写入响应的方法。

**Go 代码举例说明：**

**1. 读取和使用 HTTP 响应：**

```go
package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

func main() {
	// 模拟一个 HTTP 响应
	responseStr := `HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 13

Hello, world!`

	buf := bufio.NewReader(strings.NewReader(responseStr))

	resp, err := http.ReadResponse(buf, nil)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Status:", resp.Status)
	fmt.Println("StatusCode:", resp.StatusCode)
	fmt.Println("Proto:", resp.Proto)
	fmt.Println("Header:", resp.Header)

	// 读取响应体
	bodyBuf := new(strings.Builder)
	_, err = bodyBuf.ReadFrom(resp.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return
	}
	fmt.Println("Body:", bodyBuf.String())
}
```

**假设输入:**  无，代码直接创建了一个模拟的响应字符串。

**输出:**

```
Status: 200 OK
StatusCode: 200
Proto: HTTP/1.1
Header: map[Content-Length:[13] Content-Type:[text/plain]]
Body: Hello, world!
```

**2. 获取重定向的 Location：**

```go
package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

func main() {
	// 模拟一个重定向响应
	responseStr := `HTTP/1.1 302 Found
Location: /new_resource
Content-Length: 0
`

	buf := bufio.NewReader(strings.NewReader(responseStr))

	// 模拟请求的 URL，用于解析相对路径的 Location
	reqURL, _ := url.Parse("http://example.com/old_resource")
	req := &http.Request{URL: reqURL}

	resp, err := http.ReadResponse(buf, req)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	defer resp.Body.Close()

	locationURL, err := resp.Location()
	if err != nil {
		fmt.Println("Error getting location:", err)
		return
	}
	fmt.Println("Location URL:", locationURL)
}
```

**假设输入:**  无，代码直接创建了一个模拟的重定向响应字符串。

**输出:**

```
Location URL: http://example.com/new_resource
```

**3. 写入 HTTP 响应（服务器端示例）：**

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       http.NoBody, // 或者 io.NopCloser(strings.NewReader("Response body"))
		}
		err := resp.Write(w)
		if err != nil {
			fmt.Println("Error writing response:", err)
		}
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	fmt.Println("Response Written:")
	fmt.Println(w.Result().Status)
	fmt.Println(w.Body.String())
}
```

**假设输入:**  一个 HTTP GET 请求到根路径 `/`。

**输出:**

```
Response Written:
200 OK

```

**代码推理（结合示例 1）：**

在示例 1 中，`http.ReadResponse` 函数接收一个 `bufio.Reader`，其中包含了模拟的 HTTP 响应报文。函数内部会执行以下推理步骤：

1. **读取状态行:**  读取第一行 `HTTP/1.1 200 OK`，并解析出协议版本 (`Proto`、`ProtoMajor`、`ProtoMinor`)、状态码 (`StatusCode`) 和状态文本 (`Status`)。
2. **读取头部:**  读取后续的头部信息，直到遇到空行 `\r\n`。将每个头部字段名和值存储到 `resp.Header` 中。
3. **处理传输编码:** `readTransfer` 函数会根据 `Transfer-Encoding` 头部来设置 `resp.Body` 的读取方式，例如处理分块传输。在本例中没有 `Transfer-Encoding`，所以按默认方式处理。
4. **设置响应体:**  根据 `Content-Length` 头部，`resp.Body` 会被设置为一个 `io.ReadCloser`，用于读取指定长度的响应体数据。

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。HTTP 客户端或服务器程序可能会在主函数中使用 `os.Args` 或其他库来解析命令行参数，但这部分逻辑不在 `response.go` 文件中。

**使用者易犯错的点：**

1. **忘记关闭 `resp.Body`:** 这是最常见的错误。HTTP 连接资源是有限的，如果不关闭响应体，可能会导致连接泄漏，最终耗尽资源。

    ```go
    resp, err := http.Get("https://example.com")
    if err != nil {
        // ... handle error
    }
    // 忘记 defer resp.Body.Close() 或者手动关闭
    // ... 读取 resp.Body
    ```

    **正确的做法：**

    ```go
    resp, err := http.Get("https://example.com")
    if err != nil {
        // ... handle error
    }
    defer resp.Body.Close() // 确保函数退出时关闭
    // ... 读取 resp.Body
    ```

2. **并发访问 `Trailer` 而未完成 `Body` 的读取:**  `Trailer` 头部是在响应体读取完毕后发送的。如果在 `Body` 未读取到 `io.EOF` 之前就并发访问 `Trailer`，可能会导致数据竞争或不确定的行为。

    ```go
    resp, err := http.Get("https://example.com")
    if err != nil {
        // ... handle error
    }
    defer resp.Body.Close()

    // 错误的做法：在 Body 读取完成前尝试访问 Trailer
    go func() {
        // 可能会在 Body 读取完成前访问 Trailer，导致问题
        fmt.Println(resp.Trailer)
    }()

    // 读取 Body
    io.Copy(io.Discard, resp.Body)

    // 正确的做法：在 Body 读取完成后访问 Trailer
    fmt.Println(resp.Trailer)
    ```

这段代码是 `net/http` 包中非常核心的一部分，理解其功能对于编写可靠的 HTTP 客户端和服务器至关重要。

### 提示词
```
这是路径为go/src/net/http/response.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP Response reading and parsing.

package http

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

var respExcludeHeader = map[string]bool{
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// Response represents the response from an HTTP request.
//
// The [Client] and [Transport] return Responses from servers once
// the response headers have been received. The response body
// is streamed on demand as the Body field is read.
type Response struct {
	Status     string // e.g. "200 OK"
	StatusCode int    // e.g. 200
	Proto      string // e.g. "HTTP/1.0"
	ProtoMajor int    // e.g. 1
	ProtoMinor int    // e.g. 0

	// Header maps header keys to values. If the response had multiple
	// headers with the same key, they may be concatenated, with comma
	// delimiters.  (RFC 7230, section 3.2.2 requires that multiple headers
	// be semantically equivalent to a comma-delimited sequence.) When
	// Header values are duplicated by other fields in this struct (e.g.,
	// ContentLength, TransferEncoding, Trailer), the field values are
	// authoritative.
	//
	// Keys in the map are canonicalized (see CanonicalHeaderKey).
	Header Header

	// Body represents the response body.
	//
	// The response body is streamed on demand as the Body field
	// is read. If the network connection fails or the server
	// terminates the response, Body.Read calls return an error.
	//
	// The http Client and Transport guarantee that Body is always
	// non-nil, even on responses without a body or responses with
	// a zero-length body. It is the caller's responsibility to
	// close Body. The default HTTP client's Transport may not
	// reuse HTTP/1.x "keep-alive" TCP connections if the Body is
	// not read to completion and closed.
	//
	// The Body is automatically dechunked if the server replied
	// with a "chunked" Transfer-Encoding.
	//
	// As of Go 1.12, the Body will also implement io.Writer
	// on a successful "101 Switching Protocols" response,
	// as used by WebSockets and HTTP/2's "h2c" mode.
	Body io.ReadCloser

	// ContentLength records the length of the associated content. The
	// value -1 indicates that the length is unknown. Unless Request.Method
	// is "HEAD", values >= 0 indicate that the given number of bytes may
	// be read from Body.
	ContentLength int64

	// Contains transfer encodings from outer-most to inner-most. Value is
	// nil, means that "identity" encoding is used.
	TransferEncoding []string

	// Close records whether the header directed that the connection be
	// closed after reading Body. The value is advice for clients: neither
	// ReadResponse nor Response.Write ever closes a connection.
	Close bool

	// Uncompressed reports whether the response was sent compressed but
	// was decompressed by the http package. When true, reading from
	// Body yields the uncompressed content instead of the compressed
	// content actually set from the server, ContentLength is set to -1,
	// and the "Content-Length" and "Content-Encoding" fields are deleted
	// from the responseHeader. To get the original response from
	// the server, set Transport.DisableCompression to true.
	Uncompressed bool

	// Trailer maps trailer keys to values in the same
	// format as Header.
	//
	// The Trailer initially contains only nil values, one for
	// each key specified in the server's "Trailer" header
	// value. Those values are not added to Header.
	//
	// Trailer must not be accessed concurrently with Read calls
	// on the Body.
	//
	// After Body.Read has returned io.EOF, Trailer will contain
	// any trailer values sent by the server.
	Trailer Header

	// Request is the request that was sent to obtain this Response.
	// Request's Body is nil (having already been consumed).
	// This is only populated for Client requests.
	Request *Request

	// TLS contains information about the TLS connection on which the
	// response was received. It is nil for unencrypted responses.
	// The pointer is shared between responses and should not be
	// modified.
	TLS *tls.ConnectionState
}

// Cookies parses and returns the cookies set in the Set-Cookie headers.
func (r *Response) Cookies() []*Cookie {
	return readSetCookies(r.Header)
}

// ErrNoLocation is returned by the [Response.Location] method
// when no Location header is present.
var ErrNoLocation = errors.New("http: no Location header in response")

// Location returns the URL of the response's "Location" header,
// if present. Relative redirects are resolved relative to
// [Response.Request]. [ErrNoLocation] is returned if no
// Location header is present.
func (r *Response) Location() (*url.URL, error) {
	lv := r.Header.Get("Location")
	if lv == "" {
		return nil, ErrNoLocation
	}
	if r.Request != nil && r.Request.URL != nil {
		return r.Request.URL.Parse(lv)
	}
	return url.Parse(lv)
}

// ReadResponse reads and returns an HTTP response from r.
// The req parameter optionally specifies the [Request] that corresponds
// to this [Response]. If nil, a GET request is assumed.
// Clients must call resp.Body.Close when finished reading resp.Body.
// After that call, clients can inspect resp.Trailer to find key/value
// pairs included in the response trailer.
func ReadResponse(r *bufio.Reader, req *Request) (*Response, error) {
	tp := textproto.NewReader(r)
	resp := &Response{
		Request: req,
	}

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	proto, status, ok := strings.Cut(line, " ")
	if !ok {
		return nil, badStringError("malformed HTTP response", line)
	}
	resp.Proto = proto
	resp.Status = strings.TrimLeft(status, " ")

	statusCode, _, _ := strings.Cut(resp.Status, " ")
	if len(statusCode) != 3 {
		return nil, badStringError("malformed HTTP status code", statusCode)
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil || resp.StatusCode < 0 {
		return nil, badStringError("malformed HTTP status code", statusCode)
	}
	if resp.ProtoMajor, resp.ProtoMinor, ok = ParseHTTPVersion(resp.Proto); !ok {
		return nil, badStringError("malformed HTTP version", resp.Proto)
	}

	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = Header(mimeHeader)

	fixPragmaCacheControl(resp.Header)

	err = readTransfer(resp, r)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// RFC 7234, section 5.4: Should treat
//
//	Pragma: no-cache
//
// like
//
//	Cache-Control: no-cache
func fixPragmaCacheControl(header Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}

// ProtoAtLeast reports whether the HTTP protocol used
// in the response is at least major.minor.
func (r *Response) ProtoAtLeast(major, minor int) bool {
	return r.ProtoMajor > major ||
		r.ProtoMajor == major && r.ProtoMinor >= minor
}

// Write writes r to w in the HTTP/1.x server response format,
// including the status line, headers, body, and optional trailer.
//
// This method consults the following fields of the response r:
//
//	StatusCode
//	ProtoMajor
//	ProtoMinor
//	Request.Method
//	TransferEncoding
//	Trailer
//	Body
//	ContentLength
//	Header, values for non-canonical keys will have unpredictable behavior
//
// The Response Body is closed after it is sent.
func (r *Response) Write(w io.Writer) error {
	// Status line
	text := r.Status
	if text == "" {
		text = StatusText(r.StatusCode)
		if text == "" {
			text = "status code " + strconv.Itoa(r.StatusCode)
		}
	} else {
		// Just to reduce stutter, if user set r.Status to "200 OK" and StatusCode to 200.
		// Not important.
		text = strings.TrimPrefix(text, strconv.Itoa(r.StatusCode)+" ")
	}

	if _, err := fmt.Fprintf(w, "HTTP/%d.%d %03d %s\r\n", r.ProtoMajor, r.ProtoMinor, r.StatusCode, text); err != nil {
		return err
	}

	// Clone it, so we can modify r1 as needed.
	r1 := new(Response)
	*r1 = *r
	if r1.ContentLength == 0 && r1.Body != nil {
		// Is it actually 0 length? Or just unknown?
		var buf [1]byte
		n, err := r1.Body.Read(buf[:])
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			// Reset it to a known zero reader, in case underlying one
			// is unhappy being read repeatedly.
			r1.Body = NoBody
		} else {
			r1.ContentLength = -1
			r1.Body = struct {
				io.Reader
				io.Closer
			}{
				io.MultiReader(bytes.NewReader(buf[:1]), r.Body),
				r.Body,
			}
		}
	}
	// If we're sending a non-chunked HTTP/1.1 response without a
	// content-length, the only way to do that is the old HTTP/1.0
	// way, by noting the EOF with a connection close, so we need
	// to set Close.
	if r1.ContentLength == -1 && !r1.Close && r1.ProtoAtLeast(1, 1) && !chunked(r1.TransferEncoding) && !r1.Uncompressed {
		r1.Close = true
	}

	// Process Body,ContentLength,Close,Trailer
	tw, err := newTransferWriter(r1)
	if err != nil {
		return err
	}
	err = tw.writeHeader(w, nil)
	if err != nil {
		return err
	}

	// Rest of header
	err = r.Header.WriteSubset(w, respExcludeHeader)
	if err != nil {
		return err
	}

	// contentLengthAlreadySent may have been already sent for
	// POST/PUT requests, even if zero length. See Issue 8180.
	contentLengthAlreadySent := tw.shouldSendContentLength()
	if r1.ContentLength == 0 && !chunked(r1.TransferEncoding) && !contentLengthAlreadySent && bodyAllowedForStatus(r.StatusCode) {
		if _, err := io.WriteString(w, "Content-Length: 0\r\n"); err != nil {
			return err
		}
	}

	// End-of-header
	if _, err := io.WriteString(w, "\r\n"); err != nil {
		return err
	}

	// Write body and trailer
	err = tw.writeBody(w)
	if err != nil {
		return err
	}

	// Success
	return nil
}

func (r *Response) closeBody() {
	if r.Body != nil {
		r.Body.Close()
	}
}

// bodyIsWritable reports whether the Body supports writing. The
// Transport returns Writable bodies for 101 Switching Protocols
// responses.
// The Transport uses this method to determine whether a persistent
// connection is done being managed from its perspective. Once we
// return a writable response body to a user, the net/http package is
// done managing that connection.
func (r *Response) bodyIsWritable() bool {
	_, ok := r.Body.(io.Writer)
	return ok
}

// isProtocolSwitch reports whether the response code and header
// indicate a successful protocol upgrade response.
func (r *Response) isProtocolSwitch() bool {
	return isProtocolSwitchResponse(r.StatusCode, r.Header)
}

// isProtocolSwitchResponse reports whether the response code and
// response header indicate a successful protocol upgrade response.
func isProtocolSwitchResponse(code int, h Header) bool {
	return code == StatusSwitchingProtocols && isProtocolSwitchHeader(h)
}

// isProtocolSwitchHeader reports whether the request or response header
// is for a protocol switch.
func isProtocolSwitchHeader(h Header) bool {
	return h.Get("Upgrade") != "" &&
		httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade")
}
```