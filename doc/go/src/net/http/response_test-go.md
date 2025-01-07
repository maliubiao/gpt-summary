Response:
Let's break down the thought process for analyzing the given Go code.

1. **Understand the Goal:** The request asks for an explanation of the Go code's functionality, identification of the Go feature it's testing, example usage, potential errors, and a clear Chinese response. The key is to focus on the testing aspect of the code.

2. **Initial Code Scan:** Quickly skim the code to get a high-level overview. Key observations:
    * The package is `net/http`.
    * The file name is `response_test.go`, clearly indicating this is a test file.
    * There's a `respTest` struct holding raw HTTP response strings, parsed `Response` structs, and body strings.
    * There's a slice of `respTest` called `respTests`. This likely contains various HTTP response scenarios for testing.
    * There are functions like `dummyReq`, `TestReadResponse`, `TestWriteResponse`, `TestReadResponseCloseInMiddle`, `TestLocationResponse`, `TestResponseContentLengthShortBody`, and `TestReadResponseErrors`. These function names strongly suggest what they're testing.
    * The `diff` function suggests a comparison mechanism between expected and actual `Response` structs.

3. **Focus on the Core Testing Logic:** The `respTests` slice is central. Each element defines:
    * `Raw`: A string representing a raw HTTP response.
    * `RawOut`: The expected output when the parsed `Response` is written back out. This suggests testing the `Write` functionality.
    * `Resp`: The expected parsed `Response` struct after reading `Raw`. This implies testing the `ReadResponse` functionality.
    * `Body`: The expected body content of the response.

4. **Identify the Go Feature:** Based on the `ReadResponse` and `Response` struct, the primary Go feature being tested is the `net/http` package's ability to parse and represent HTTP responses. Specifically, it's testing the `ReadResponse` function and the `Response` struct.

5. **Example Usage (Illustrating `ReadResponse`):**  To demonstrate the functionality, create a simple example using `ReadResponse`. This involves:
    * Defining a raw HTTP response string (taking an example from `respTests` is a good idea).
    * Creating a `bufio.Reader` from the string.
    * Calling `http.ReadResponse`.
    * Inspecting the returned `Response` struct and its `Body`.

6. **Example Usage (Illustrating `Write`):**  Show how to use the `Write` method of the `Response` struct. This involves:
    * Parsing a raw response using `ReadResponse`.
    * Creating a `bytes.Buffer`.
    * Calling the `Write` method on the parsed `Response`.
    * Comparing the buffer's content to the expected `RawOut`.

7. **Code Reasoning (`TestReadResponse`):** Explain how `TestReadResponse` works:
    * It iterates through `respTests`.
    * It calls `ReadResponse` with the `Raw` string.
    * It compares the parsed `Response` with the expected `Resp` using the `diff` function.
    * It reads and compares the body content.

8. **Code Reasoning (`TestWriteResponse`):** Explain how `TestWriteResponse` works:
    * It iterates through `respTests`.
    * It parses the `Raw` response using `ReadResponse`.
    * It writes the parsed `Response` to a buffer using `resp.Write`.
    * It compares the buffer's content with the expected `RawOut`.

9. **Command Line Arguments:** Scan the code for any usage of `os.Args` or `flag`. In this case, there are none related to command-line arguments.

10. **Common Mistakes:** Consider what could go wrong when *using* the `net/http` package to read responses. A likely mistake is not closing the response body, which can lead to resource leaks. Provide an example of this.

11. **Structure the Chinese Response:** Organize the information clearly using headings and bullet points. Use precise Chinese terminology for programming concepts. Ensure the code examples are complete and runnable (or close to it).

12. **Review and Refine:** Read through the entire response to ensure accuracy, clarity, and completeness. Check for any grammatical errors or awkward phrasing. Ensure the code examples are correct and easy to understand. For example, ensure the imports are included in the code snippets. Make sure the explanation of the test functions is accurate and reflects the code's logic.

Self-Correction Example During the Process:

* **Initial thought:**  This code is testing HTTP client functionality.
* **Correction:** While related to HTTP, the focus is specifically on *response* parsing and serialization, not necessarily making requests. The tests use raw response strings as input. Refocus the description on response processing.

* **Initial thought:**  Just describe what each test function does.
* **Correction:**  Group related test functions and explain the underlying Go feature they are verifying (e.g., `ReadResponse`, `Write`). This provides a more thematic and understandable explanation.

By following these steps, combining code analysis with an understanding of testing principles and potential user errors, we can arrive at a comprehensive and accurate explanation of the provided Go test code.
这段代码是 Go 语言 `net/http` 包中 `response_test.go` 文件的一部分，它主要用于测试 **HTTP 响应的读取和写入功能**。

具体来说，它测试了 `net/http` 包中的 `ReadResponse` 函数和 `Response` 结构体，以及 `Response` 结构体的 `Write` 方法。

以下是其功能的详细列表：

1. **`respTest` 结构体定义:** 定义了一个用于存储测试用例的结构体 `respTest`，包含了原始的 HTTP 响应字符串 (`Raw`)、期望的写入输出 (`RawOut`)、期望解析出的 `Response` 结构体 (`Resp`) 和期望的响应体内容 (`Body`)。

2. **`dummyReq` 和 `dummyReq11` 函数:**  创建用于测试的 `Request` 结构体，分别代表 HTTP/1.0 和 HTTP/1.1 的请求。这些请求主要用于 `ReadResponse` 函数的第二个参数，以便在解析响应时关联到对应的请求。

3. **`respTests` 切片:** 定义了一个 `respTest` 结构体的切片，包含了各种不同的 HTTP 响应场景，例如：
    * 未分块的响应，有或没有 `Content-Length`。
    * HTTP/1.0 和 HTTP/1.1 响应。
    * 状态码为 204 的响应。
    * 分块传输编码 (chunked) 的响应。
    * 带有 Trailer 头的响应。
    * 针对 HEAD 请求的响应。
    * 内容编码 (Content-Encoding) 为 gzip 的响应。
    * 状态行格式不规范的情况。
    * 包含多个 `Connection` 头的响应。
    * 包含无效 `Transfer-Encoding` 头的响应。

4. **`TestReadResponse` 函数:** 测试 `ReadResponse` 函数的正确性。
    * 遍历 `respTests` 中的每个测试用例。
    * 使用 `bufio.NewReader` 从 `tt.Raw` 创建一个读取器。
    * 调用 `ReadResponse` 函数，传入读取器和预期的请求对象 (`tt.Resp.Request`)。
    * 比较返回的 `Response` 结构体与期望的 `tt.Resp` 结构体是否一致（忽略 `Body` 字段）。
    * 读取返回的 `Response.Body` 并与期望的 `tt.Body` 进行比较。

5. **`TestWriteResponse` 函数:** 测试 `Response` 结构体的 `Write` 方法的正确性。
    * 遍历 `respTests` 中的每个测试用例。
    * 首先使用 `ReadResponse` 解析原始响应字符串 `tt.Raw`。
    * 然后调用解析得到的 `Response` 结构体的 `Write` 方法，将响应写入到 `bytes.Buffer` 中。
    * 比较 `bytes.Buffer` 的内容与期望的输出 `tt.RawOut` 是否一致。

6. **`readResponseCloseInMiddleTests` 切片和 `TestReadResponseCloseInMiddle` 函数:**  测试在读取响应体过程中提前关闭 `Body` 的行为。这验证了 `ReadResponse` 是否能正确处理这种情况，并能继续读取后续的内容。它测试了分块和非分块，以及压缩和非压缩的情况。

7. **`diff` 函数:**  一个辅助函数，用于比较两个结构体的值是否深度相等，用于 `TestReadResponse` 中比较解析出的 `Response` 和期望的 `Response`。

8. **`responseLocationTests` 切片和 `TestLocationResponse` 函数:** 测试 `Response` 结构体的 `Location` 方法，该方法用于获取重定向的 URL。

9. **`TestResponseStatusStutter` 函数:** 测试 `Response` 结构体的写入方法是否会重复写入状态码。

10. **`TestResponseContentLengthShortBody` 函数:** 测试当响应头的 `Content-Length` 大于实际响应体长度时，`ReadResponse` 的行为。这验证了它会返回 `io.ErrUnexpectedEOF` 错误。

11. **`TestReadResponseErrors` 函数:** 测试 `ReadResponse` 函数在遇到各种错误输入时的行为，例如：
    * 不完整的 HTTP 响应。
    * 格式错误的 HTTP 版本或状态码。
    * 存在多个 `Content-Length` 头的响应。
    * `Content-Length` 头为空。
    * 头部存在前导空格或制表符。

12. **`matchErr` 函数:**  一个辅助函数，用于在 `TestReadResponseErrors` 中比较实际的错误和期望的错误。

13. **`TestResponseWritesOnlySingleConnectionClose` 函数:**  测试 `Response` 写入时是否只会生成一个 `Connection: close` 头部，即使在读取时可能遇到多个 `Connection` 头部。

**它是什么 Go 语言功能的实现？**

这段代码主要测试了 `net/http` 包中处理 HTTP 响应的功能，特别是以下部分：

* **`net/http.ReadResponse` 函数:**  该函数用于从 `io.Reader` 中读取并解析 HTTP 响应，返回一个 `Response` 结构体。
* **`net/http.Response` 结构体:**  该结构体用于表示一个 HTTP 响应，包含了状态码、头部信息、请求信息和响应体等。
* **`net/http.Response.Write` 方法:**  该方法用于将 `Response` 结构体的内容写入到 `io.Writer` 中，生成符合 HTTP 规范的响应字符串。

**Go 代码举例说明:**

以下代码演示了如何使用 `http.ReadResponse` 读取一个简单的 HTTP 响应：

```go
package main

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
)

func main() {
	rawResponse := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nHello, World!"
	reader := bufio.NewReader(strings.NewReader(rawResponse))

	// 通常这里会传入实际的 Request，但这里为了演示可以传入 nil
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Status:", resp.Status)
	fmt.Println("StatusCode:", resp.StatusCode)
	fmt.Println("Header:", resp.Header)

	body := make([]byte, resp.ContentLength)
	_, err = resp.Body.Read(body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return
	}
	fmt.Println("Body:", string(body))
}
```

**假设的输入与输出 (针对 `TestReadResponse`):**

假设 `respTests` 中有一个测试用例如下：

```go
{
    Raw: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello",
    RawOut: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello",
    Resp: Response{
        Status:     "200 OK",
        StatusCode: 200,
        Proto:      "HTTP/1.1",
        ProtoMajor: 1,
        ProtoMinor: 1,
        Request:    dummyReq("GET"), // 假设 dummyReq("GET") 返回一个 GET 请求
        Header: Header{
            "Content-Length": {"5"},
        },
        Close:         false,
        ContentLength: 5,
    },
    Body: "Hello",
}
```

**输入:**  将 `Raw` 字段的字符串 `"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"`  传递给 `bufio.NewReader`。

**输出:** `TestReadResponse` 函数会断言以下内容：

* 解析出的 `Response` 结构体的 `Status` 为 `"200 OK"`。
* 解析出的 `Response` 结构体的 `StatusCode` 为 `200`。
* 解析出的 `Response` 结构体的 `Header` 包含 `"Content-Length: [5]"`。
* 读取 `Response.Body` 的内容为 `"Hello"`。

**命令行参数的具体处理:**

这段代码本身是一个测试文件，不涉及任何命令行参数的处理。它是通过 `go test` 命令来运行的。

**使用者易犯错的点:**

1. **忘记关闭 `Response.Body`:**  `Response.Body` 是一个 `io.ReadCloser`，使用完毕后必须关闭，以释放底层的连接资源。如果忘记关闭，可能会导致资源泄露。

   ```go
   resp, err := http.Get("https://example.com")
   if err != nil {
       // 处理错误
   }
   // 忘记关闭 resp.Body
   // ... 后续代码
   ```

   **正确的做法:**

   ```go
   resp, err := http.Get("https://example.com")
   if err != nil {
       // 处理错误
   }
   defer resp.Body.Close() // 确保 body 被关闭
   // ... 后续代码
   ```

2. **错误地假设响应体可以多次读取:** `Response.Body` 只能读取一次。如果尝试多次读取，第二次及以后的读取将会返回 EOF。

   ```go
   resp, err := http.Get("https://example.com")
   if err != nil {
       // 处理错误
   }
   defer resp.Body.Close()

   body, _ := io.ReadAll(resp.Body)
   fmt.Println(string(body))

   body2, _ := io.ReadAll(resp.Body) // body2 将为空
   fmt.Println(string(body2))
   ```

这段测试代码通过覆盖各种 HTTP 响应场景，确保 `net/http` 包能够正确地解析和处理 HTTP 响应，对于理解 Go 语言 `net/http` 包的底层实现非常有帮助。

Prompt: 
```
这是路径为go/src/net/http/response_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"go/token"
	"io"
	"net/http/internal"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

type respTest struct {
	Raw    string
	RawOut string
	Resp   Response
	Body   string
}

func dummyReq(method string) *Request {
	return &Request{Method: method}
}

func dummyReq11(method string) *Request {
	return &Request{Method: method, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
}

var respTests = []respTest{
	// Unchunked response without Content-Length.
	{
		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Request:    dummyReq("GET"),
			Header: Header{
				"Connection": {"close"}, // TODO(rsc): Delete?
			},
			Close:         true,
			ContentLength: -1,
		},

		"Body here\n",
	},

	// Unchunked HTTP/1.1 response without Content-Length or
	// Connection headers.
	{
		"HTTP/1.1 200 OK\r\n" +
			"\r\n" +
			"Body here\n",

		"HTTP/1.1 200 OK\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        Header{},
			Request:       dummyReq("GET"),
			Close:         true,
			ContentLength: -1,
		},

		"Body here\n",
	},

	// Unchunked HTTP/1.1 204 response without Content-Length.
	{
		"HTTP/1.1 204 No Content\r\n" +
			"\r\n" +
			"Body should not be read!\n",

		"HTTP/1.1 204 No Content\r\n" +
			"\r\n",

		Response{
			Status:        "204 No Content",
			StatusCode:    204,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        Header{},
			Request:       dummyReq("GET"),
			Close:         false,
			ContentLength: 0,
		},

		"",
	},

	// Unchunked response with Content-Length.
	{
		"HTTP/1.0 200 OK\r\n" +
			"Content-Length: 10\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		"HTTP/1.0 200 OK\r\n" +
			"Content-Length: 10\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Request:    dummyReq("GET"),
			Header: Header{
				"Connection":     {"close"},
				"Content-Length": {"10"},
			},
			Close:         true,
			ContentLength: 10,
		},

		"Body here\n",
	},

	// Chunked response without Content-Length.
	{
		"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0a\r\n" +
			"Body here\n\r\n" +
			"09\r\n" +
			"continued\r\n" +
			"0\r\n" +
			"\r\n",

		"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"13\r\n" +
			"Body here\ncontinued\r\n" +
			"0\r\n" +
			"\r\n",

		Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.1",
			ProtoMajor:       1,
			ProtoMinor:       1,
			Request:          dummyReq("GET"),
			Header:           Header{},
			Close:            false,
			ContentLength:    -1,
			TransferEncoding: []string{"chunked"},
		},

		"Body here\ncontinued",
	},

	// Trailer header but no TransferEncoding
	{
		"HTTP/1.0 200 OK\r\n" +
			"Trailer: Content-MD5, Content-Sources\r\n" +
			"Content-Length: 10\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		"HTTP/1.0 200 OK\r\n" +
			"Content-Length: 10\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Request:    dummyReq("GET"),
			Header: Header{
				"Connection":     {"close"},
				"Content-Length": {"10"},
				"Trailer":        []string{"Content-MD5, Content-Sources"},
			},
			Close:         true,
			ContentLength: 10,
		},

		"Body here\n",
	},

	// Chunked response with Content-Length.
	{
		"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"0a\r\n" +
			"Body here\n\r\n" +
			"0\r\n" +
			"\r\n",

		"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"a\r\n" +
			"Body here\n\r\n" +
			"0\r\n" +
			"\r\n",

		Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.1",
			ProtoMajor:       1,
			ProtoMinor:       1,
			Request:          dummyReq("GET"),
			Header:           Header{},
			Close:            false,
			ContentLength:    -1,
			TransferEncoding: []string{"chunked"},
		},

		"Body here\n",
	},

	// Chunked response in response to a HEAD request
	{
		"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",

		"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n",

		Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.1",
			ProtoMajor:       1,
			ProtoMinor:       1,
			Request:          dummyReq("HEAD"),
			Header:           Header{},
			TransferEncoding: []string{"chunked"},
			Close:            false,
			ContentLength:    -1,
		},

		"",
	},

	// Content-Length in response to a HEAD request
	{
		"HTTP/1.0 200 OK\r\n" +
			"Content-Length: 256\r\n" +
			"\r\n",

		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 256\r\n" +
			"\r\n",

		Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.0",
			ProtoMajor:       1,
			ProtoMinor:       0,
			Request:          dummyReq("HEAD"),
			Header:           Header{"Content-Length": {"256"}},
			TransferEncoding: nil,
			Close:            true,
			ContentLength:    256,
		},

		"",
	},

	// Content-Length in response to a HEAD request with HTTP/1.1
	{
		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 256\r\n" +
			"\r\n",

		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 256\r\n" +
			"\r\n",

		Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.1",
			ProtoMajor:       1,
			ProtoMinor:       1,
			Request:          dummyReq("HEAD"),
			Header:           Header{"Content-Length": {"256"}},
			TransferEncoding: nil,
			Close:            false,
			ContentLength:    256,
		},

		"",
	},

	// No Content-Length or Chunked in response to a HEAD request
	{
		"HTTP/1.0 200 OK\r\n" +
			"\r\n",

		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"\r\n",

		Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.0",
			ProtoMajor:       1,
			ProtoMinor:       0,
			Request:          dummyReq("HEAD"),
			Header:           Header{},
			TransferEncoding: nil,
			Close:            true,
			ContentLength:    -1,
		},

		"",
	},

	// explicit Content-Length of 0.
	{
		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",

		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Request:    dummyReq("GET"),
			Header: Header{
				"Content-Length": {"0"},
			},
			Close:         false,
			ContentLength: 0,
		},

		"",
	},

	// Status line without a Reason-Phrase, but trailing space.
	// (permitted by RFC 7230, section 3.1.2)
	{
		"HTTP/1.0 303 \r\n\r\n",

		"HTTP/1.0 303 \r\n" +
			"Connection: close\r\n" +
			"\r\n",

		Response{
			Status:        "303 ",
			StatusCode:    303,
			Proto:         "HTTP/1.0",
			ProtoMajor:    1,
			ProtoMinor:    0,
			Request:       dummyReq("GET"),
			Header:        Header{},
			Close:         true,
			ContentLength: -1,
		},

		"",
	},

	// Status line without a Reason-Phrase, and no trailing space.
	// (not permitted by RFC 7230, but we'll accept it anyway)
	{
		"HTTP/1.0 303\r\n\r\n",

		"HTTP/1.0 303 303\r\n" +
			"Connection: close\r\n" +
			"\r\n",

		Response{
			Status:        "303",
			StatusCode:    303,
			Proto:         "HTTP/1.0",
			ProtoMajor:    1,
			ProtoMinor:    0,
			Request:       dummyReq("GET"),
			Header:        Header{},
			Close:         true,
			ContentLength: -1,
		},

		"",
	},

	// golang.org/issue/4767: don't special-case multipart/byteranges responses
	{
		`HTTP/1.1 206 Partial Content
Connection: close
Content-Type: multipart/byteranges; boundary=18a75608c8f47cef

some body`,

		"HTTP/1.1 206 Partial Content\r\n" +
			"Connection: close\r\n" +
			"Content-Type: multipart/byteranges; boundary=18a75608c8f47cef\r\n" +
			"\r\n" +
			"some body",

		Response{
			Status:     "206 Partial Content",
			StatusCode: 206,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Request:    dummyReq("GET"),
			Header: Header{
				"Content-Type": []string{"multipart/byteranges; boundary=18a75608c8f47cef"},
			},
			Close:         true,
			ContentLength: -1,
		},

		"some body",
	},

	// Unchunked response without Content-Length, Request is nil
	{
		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Header: Header{
				"Connection": {"close"}, // TODO(rsc): Delete?
			},
			Close:         true,
			ContentLength: -1,
		},

		"Body here\n",
	},

	// 206 Partial Content. golang.org/issue/8923
	{
		"HTTP/1.1 206 Partial Content\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Accept-Ranges: bytes\r\n" +
			"Content-Range: bytes 0-5/1862\r\n" +
			"Content-Length: 6\r\n\r\n" +
			"foobar",

		"HTTP/1.1 206 Partial Content\r\n" +
			"Content-Length: 6\r\n" +
			"Accept-Ranges: bytes\r\n" +
			"Content-Range: bytes 0-5/1862\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"\r\n" +
			"foobar",

		Response{
			Status:     "206 Partial Content",
			StatusCode: 206,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Request:    dummyReq("GET"),
			Header: Header{
				"Accept-Ranges":  []string{"bytes"},
				"Content-Length": []string{"6"},
				"Content-Type":   []string{"text/plain; charset=utf-8"},
				"Content-Range":  []string{"bytes 0-5/1862"},
			},
			ContentLength: 6,
		},

		"foobar",
	},

	// Both keep-alive and close, on the same Connection line. (Issue 8840)
	{
		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 256\r\n" +
			"Connection: keep-alive, close\r\n" +
			"\r\n",

		"HTTP/1.1 200 OK\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 256\r\n" +
			"\r\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Request:    dummyReq("HEAD"),
			Header: Header{
				"Content-Length": {"256"},
			},
			TransferEncoding: nil,
			Close:            true,
			ContentLength:    256,
		},

		"",
	},

	// Both keep-alive and close, on different Connection lines. (Issue 8840)
	{
		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 256\r\n" +
			"Connection: keep-alive\r\n" +
			"Connection: close\r\n" +
			"\r\n",

		"HTTP/1.1 200 OK\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 256\r\n" +
			"\r\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Request:    dummyReq("HEAD"),
			Header: Header{
				"Content-Length": {"256"},
			},
			TransferEncoding: nil,
			Close:            true,
			ContentLength:    256,
		},

		"",
	},

	// Issue 12785: HTTP/1.0 response with bogus (to be ignored) Transfer-Encoding.
	// Without a Content-Length.
	{
		"HTTP/1.0 200 OK\r\n" +
			"Transfer-Encoding: bogus\r\n" +
			"\r\n" +
			"Body here\n",

		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"Body here\n",

		Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/1.0",
			ProtoMajor:    1,
			ProtoMinor:    0,
			Request:       dummyReq("GET"),
			Header:        Header{},
			Close:         true,
			ContentLength: -1,
		},

		"Body here\n",
	},

	// Issue 12785: HTTP/1.0 response with bogus (to be ignored) Transfer-Encoding.
	// With a Content-Length.
	{
		"HTTP/1.0 200 OK\r\n" +
			"Transfer-Encoding: bogus\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"Body here\n",

		"HTTP/1.0 200 OK\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"Body here\n",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Request:    dummyReq("GET"),
			Header: Header{
				"Content-Length": {"10"},
			},
			Close:         true,
			ContentLength: 10,
		},

		"Body here\n",
	},

	{
		"HTTP/1.1 200 OK\r\n" +
			"Content-Encoding: gzip\r\n" +
			"Content-Length: 23\r\n" +
			"Connection: keep-alive\r\n" +
			"Keep-Alive: timeout=7200\r\n\r\n" +
			"\x1f\x8b\b\x00\x00\x00\x00\x00\x00\x00s\xf3\xf7\a\x00\xab'\xd4\x1a\x03\x00\x00\x00",

		"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 23\r\n" +
			"Connection: keep-alive\r\n" +
			"Content-Encoding: gzip\r\n" +
			"Keep-Alive: timeout=7200\r\n\r\n" +
			"\x1f\x8b\b\x00\x00\x00\x00\x00\x00\x00s\xf3\xf7\a\x00\xab'\xd4\x1a\x03\x00\x00\x00",

		Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Request:    dummyReq("GET"),
			Header: Header{
				"Content-Length":   {"23"},
				"Content-Encoding": {"gzip"},
				"Connection":       {"keep-alive"},
				"Keep-Alive":       {"timeout=7200"},
			},
			Close:         false,
			ContentLength: 23,
		},
		"\x1f\x8b\b\x00\x00\x00\x00\x00\x00\x00s\xf3\xf7\a\x00\xab'\xd4\x1a\x03\x00\x00\x00",
	},

	// Issue 19989: two spaces between HTTP version and status.
	{
		"HTTP/1.0  401 Unauthorized\r\n" +
			"Content-type: text/html\r\n" +
			"WWW-Authenticate: Basic realm=\"\"\r\n\r\n" +
			"Your Authentication failed.\r\n",

		"HTTP/1.0 401 Unauthorized\r\n" +
			"Connection: close\r\n" +
			"Content-Type: text/html\r\n" +
			"Www-Authenticate: Basic realm=\"\"\r\n" +
			"\r\n" +
			"Your Authentication failed.\r\n",

		Response{
			Status:     "401 Unauthorized",
			StatusCode: 401,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Request:    dummyReq("GET"),
			Header: Header{
				"Content-Type":     {"text/html"},
				"Www-Authenticate": {`Basic realm=""`},
			},
			Close:         true,
			ContentLength: -1,
		},
		"Your Authentication failed.\r\n",
	},
}

// tests successful calls to ReadResponse, and inspects the returned Response.
// For error cases, see TestReadResponseErrors below.
func TestReadResponse(t *testing.T) {
	for i, tt := range respTests {
		resp, err := ReadResponse(bufio.NewReader(strings.NewReader(tt.Raw)), tt.Resp.Request)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		rbody := resp.Body
		resp.Body = nil
		diff(t, fmt.Sprintf("#%d Response", i), resp, &tt.Resp)
		var bout strings.Builder
		if rbody != nil {
			_, err = io.Copy(&bout, rbody)
			if err != nil {
				t.Errorf("#%d: %v", i, err)
				continue
			}
			rbody.Close()
		}
		body := bout.String()
		if body != tt.Body {
			t.Errorf("#%d: Body = %q want %q", i, body, tt.Body)
		}
	}
}

func TestWriteResponse(t *testing.T) {
	for i, tt := range respTests {
		resp, err := ReadResponse(bufio.NewReader(strings.NewReader(tt.Raw)), tt.Resp.Request)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		var buf bytes.Buffer
		err = resp.Write(&buf)
		if err != nil {
			t.Errorf("#%d: %v", i, err)
			continue
		}
		if got, want := buf.String(), tt.RawOut; got != want {
			t.Errorf("#%d: response differs; got:\n----\n%v\n----\nwant:\n----\n%v\n----\n",
				i,
				strings.ReplaceAll(got, "\r", "\\r"),
				strings.ReplaceAll(want, "\r", "\\r"))
		}
	}
}

var readResponseCloseInMiddleTests = []struct {
	chunked, compressed bool
}{
	{false, false},
	{true, false},
	{true, true},
}

type readerAndCloser struct {
	io.Reader
	io.Closer
}

// TestReadResponseCloseInMiddle tests that closing a body after
// reading only part of its contents advances the read to the end of
// the request, right up until the next request.
func TestReadResponseCloseInMiddle(t *testing.T) {
	t.Parallel()
	for _, test := range readResponseCloseInMiddleTests {
		fatalf := func(format string, args ...any) {
			args = append([]any{test.chunked, test.compressed}, args...)
			t.Fatalf("on test chunked=%v, compressed=%v: "+format, args...)
		}
		checkErr := func(err error, msg string) {
			if err == nil {
				return
			}
			fatalf(msg+": %v", err)
		}
		var buf bytes.Buffer
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		if test.chunked {
			buf.WriteString("Transfer-Encoding: chunked\r\n")
		} else {
			buf.WriteString("Content-Length: 1000000\r\n")
		}
		var wr io.Writer = &buf
		if test.chunked {
			wr = internal.NewChunkedWriter(wr)
		}
		if test.compressed {
			buf.WriteString("Content-Encoding: gzip\r\n")
			wr = gzip.NewWriter(wr)
		}
		buf.WriteString("\r\n")

		chunk := bytes.Repeat([]byte{'x'}, 1000)
		for i := 0; i < 1000; i++ {
			if test.compressed {
				// Otherwise this compresses too well.
				_, err := io.ReadFull(rand.Reader, chunk)
				checkErr(err, "rand.Reader ReadFull")
			}
			wr.Write(chunk)
		}
		if test.compressed {
			err := wr.(*gzip.Writer).Close()
			checkErr(err, "compressor close")
		}
		if test.chunked {
			buf.WriteString("0\r\n\r\n")
		}
		buf.WriteString("Next Request Here")

		bufr := bufio.NewReader(&buf)
		resp, err := ReadResponse(bufr, dummyReq("GET"))
		checkErr(err, "ReadResponse")
		expectedLength := int64(-1)
		if !test.chunked {
			expectedLength = 1000000
		}
		if resp.ContentLength != expectedLength {
			fatalf("expected response length %d, got %d", expectedLength, resp.ContentLength)
		}
		if resp.Body == nil {
			fatalf("nil body")
		}
		if test.compressed {
			gzReader, err := gzip.NewReader(resp.Body)
			checkErr(err, "gzip.NewReader")
			resp.Body = &readerAndCloser{gzReader, resp.Body}
		}

		rbuf := make([]byte, 2500)
		n, err := io.ReadFull(resp.Body, rbuf)
		checkErr(err, "2500 byte ReadFull")
		if n != 2500 {
			fatalf("ReadFull only read %d bytes", n)
		}
		if test.compressed == false && !bytes.Equal(bytes.Repeat([]byte{'x'}, 2500), rbuf) {
			fatalf("ReadFull didn't read 2500 'x'; got %q", string(rbuf))
		}
		resp.Body.Close()

		rest, err := io.ReadAll(bufr)
		checkErr(err, "ReadAll on remainder")
		if e, g := "Next Request Here", string(rest); e != g {
			g = regexp.MustCompile(`(xx+)`).ReplaceAllStringFunc(g, func(match string) string {
				return fmt.Sprintf("x(repeated x%d)", len(match))
			})
			fatalf("remainder = %q, expected %q", g, e)
		}
	}
}

func diff(t *testing.T, prefix string, have, want any) {
	t.Helper()
	hv := reflect.ValueOf(have).Elem()
	wv := reflect.ValueOf(want).Elem()
	if hv.Type() != wv.Type() {
		t.Errorf("%s: type mismatch %v want %v", prefix, hv.Type(), wv.Type())
	}
	for i := 0; i < hv.NumField(); i++ {
		name := hv.Type().Field(i).Name
		if !token.IsExported(name) {
			continue
		}
		hf := hv.Field(i).Interface()
		wf := wv.Field(i).Interface()
		if !reflect.DeepEqual(hf, wf) {
			t.Errorf("%s: %s = %v want %v", prefix, name, hf, wf)
		}
	}
}

type responseLocationTest struct {
	location string // Response's Location header or ""
	requrl   string // Response.Request.URL or ""
	want     string
	wantErr  error
}

var responseLocationTests = []responseLocationTest{
	{"/foo", "http://bar.com/baz", "http://bar.com/foo", nil},
	{"http://foo.com/", "http://bar.com/baz", "http://foo.com/", nil},
	{"", "http://bar.com/baz", "", ErrNoLocation},
	{"/bar", "", "/bar", nil},
}

func TestLocationResponse(t *testing.T) {
	for i, tt := range responseLocationTests {
		res := new(Response)
		res.Header = make(Header)
		res.Header.Set("Location", tt.location)
		if tt.requrl != "" {
			res.Request = &Request{}
			var err error
			res.Request.URL, err = url.Parse(tt.requrl)
			if err != nil {
				t.Fatalf("bad test URL %q: %v", tt.requrl, err)
			}
		}

		got, err := res.Location()
		if tt.wantErr != nil {
			if err == nil {
				t.Errorf("%d. err=nil; want %q", i, tt.wantErr)
				continue
			}
			if g, e := err.Error(), tt.wantErr.Error(); g != e {
				t.Errorf("%d. err=%q; want %q", i, g, e)
				continue
			}
			continue
		}
		if err != nil {
			t.Errorf("%d. err=%q", i, err)
			continue
		}
		if g, e := got.String(), tt.want; g != e {
			t.Errorf("%d. Location=%q; want %q", i, g, e)
		}
	}
}

func TestResponseStatusStutter(t *testing.T) {
	r := &Response{
		Status:     "123 some status",
		StatusCode: 123,
		ProtoMajor: 1,
		ProtoMinor: 3,
	}
	var buf strings.Builder
	r.Write(&buf)
	if strings.Contains(buf.String(), "123 123") {
		t.Errorf("stutter in status: %s", buf.String())
	}
}

func TestResponseContentLengthShortBody(t *testing.T) {
	const shortBody = "Short body, not 123 bytes."
	br := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\n" +
		"Content-Length: 123\r\n" +
		"\r\n" +
		shortBody))
	res, err := ReadResponse(br, &Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.ContentLength != 123 {
		t.Fatalf("Content-Length = %d; want 123", res.ContentLength)
	}
	var buf strings.Builder
	n, err := io.Copy(&buf, res.Body)
	if n != int64(len(shortBody)) {
		t.Errorf("Copied %d bytes; want %d, len(%q)", n, len(shortBody), shortBody)
	}
	if buf.String() != shortBody {
		t.Errorf("Read body %q; want %q", buf.String(), shortBody)
	}
	if err != io.ErrUnexpectedEOF {
		t.Errorf("io.Copy error = %#v; want io.ErrUnexpectedEOF", err)
	}
}

// Test various ReadResponse error cases. (also tests success cases, but mostly
// it's about errors).  This does not test anything involving the bodies. Only
// the return value from ReadResponse itself.
func TestReadResponseErrors(t *testing.T) {
	type testCase struct {
		name    string // optional, defaults to in
		in      string
		wantErr any // nil, err value, bool value, or string substring
	}

	status := func(s string, wantErr any) testCase {
		if wantErr == true {
			wantErr = "malformed HTTP status code"
		}
		return testCase{
			name:    fmt.Sprintf("status %q", s),
			in:      "HTTP/1.1 " + s + "\r\nFoo: bar\r\n\r\n",
			wantErr: wantErr,
		}
	}

	version := func(s string, wantErr any) testCase {
		if wantErr == true {
			wantErr = "malformed HTTP version"
		}
		return testCase{
			name:    fmt.Sprintf("version %q", s),
			in:      s + " 200 OK\r\n\r\n",
			wantErr: wantErr,
		}
	}

	contentLength := func(status, body string, wantErr any) testCase {
		return testCase{
			name:    fmt.Sprintf("status %q %q", status, body),
			in:      fmt.Sprintf("HTTP/1.1 %s\r\n%s", status, body),
			wantErr: wantErr,
		}
	}

	errMultiCL := "message cannot contain multiple Content-Length headers"
	errEmptyCL := "invalid empty Content-Length"

	tests := []testCase{
		{"", "", io.ErrUnexpectedEOF},
		{"", "HTTP/1.1 301 Moved Permanently\r\nFoo: bar", io.ErrUnexpectedEOF},
		{"", "HTTP/1.1", "malformed HTTP response"},
		{"", "HTTP/2.0", "malformed HTTP response"},
		status("20X Unknown", true),
		status("abcd Unknown", true),
		status("二百/两百 OK", true),
		status(" Unknown", true),
		status("c8 OK", true),
		status("0x12d Moved Permanently", true),
		status("200 OK", nil),
		status("000 OK", nil),
		status("001 OK", nil),
		status("404 NOTFOUND", nil),
		status("20 OK", true),
		status("00 OK", true),
		status("-10 OK", true),
		status("1000 OK", true),
		status("999 Done", nil),
		status("-1 OK", true),
		status("-200 OK", true),
		version("HTTP/1.2", nil),
		version("HTTP/2.0", nil),
		version("HTTP/1.100000000002", true),
		version("HTTP/1.-1", true),
		version("HTTP/A.B", true),
		version("HTTP/1", true),
		version("http/1.1", true),

		contentLength("200 OK", "Content-Length: 10\r\nContent-Length: 7\r\n\r\nGopher hey\r\n", errMultiCL),
		contentLength("200 OK", "Content-Length: 7\r\nContent-Length: 7\r\n\r\nGophers\r\n", nil),
		contentLength("201 OK", "Content-Length: 0\r\nContent-Length: 7\r\n\r\nGophers\r\n", errMultiCL),
		contentLength("300 OK", "Content-Length: 0\r\nContent-Length: 0 \r\n\r\nGophers\r\n", nil),
		contentLength("200 OK", "Content-Length:\r\nContent-Length:\r\n\r\nGophers\r\n", errEmptyCL),
		contentLength("206 OK", "Content-Length:\r\nContent-Length: 0 \r\nConnection: close\r\n\r\nGophers\r\n", errMultiCL),

		// multiple content-length headers for 204 and 304 should still be checked
		contentLength("204 OK", "Content-Length: 7\r\nContent-Length: 8\r\n\r\n", errMultiCL),
		contentLength("204 OK", "Content-Length: 3\r\nContent-Length: 3\r\n\r\n", nil),
		contentLength("304 OK", "Content-Length: 880\r\nContent-Length: 1\r\n\r\n", errMultiCL),
		contentLength("304 OK", "Content-Length: 961\r\nContent-Length: 961\r\n\r\n", nil),

		// golang.org/issue/22464
		{"leading space in header", "HTTP/1.1 200 OK\r\n Content-type: text/html\r\nFoo: bar\r\n\r\n", "malformed MIME"},
		{"leading tab in header", "HTTP/1.1 200 OK\r\n\tContent-type: text/html\r\nFoo: bar\r\n\r\n", "malformed MIME"},
	}

	for i, tt := range tests {
		br := bufio.NewReader(strings.NewReader(tt.in))
		_, rerr := ReadResponse(br, nil)
		if err := matchErr(rerr, tt.wantErr); err != nil {
			name := tt.name
			if name == "" {
				name = fmt.Sprintf("%d. input %q", i, tt.in)
			}
			t.Errorf("%s: %v", name, err)
		}
	}
}

// wantErr can be nil, an error value to match exactly, or type string to
// match a substring.
func matchErr(err error, wantErr any) error {
	if err == nil {
		if wantErr == nil {
			return nil
		}
		if sub, ok := wantErr.(string); ok {
			return fmt.Errorf("unexpected success; want error with substring %q", sub)
		}
		return fmt.Errorf("unexpected success; want error %v", wantErr)
	}
	if wantErr == nil {
		return fmt.Errorf("%v; want success", err)
	}
	if sub, ok := wantErr.(string); ok {
		if strings.Contains(err.Error(), sub) {
			return nil
		}
		return fmt.Errorf("error = %v; want an error with substring %q", err, sub)
	}
	if err == wantErr {
		return nil
	}
	return fmt.Errorf("%v; want %v", err, wantErr)
}

// A response should only write out single Connection: close header. Tests #19499.
func TestResponseWritesOnlySingleConnectionClose(t *testing.T) {
	const connectionCloseHeader = "Connection: close"

	res, err := ReadResponse(bufio.NewReader(strings.NewReader("HTTP/1.0 200 OK\r\n\r\nAAAA")), nil)
	if err != nil {
		t.Fatalf("ReadResponse failed %v", err)
	}

	var buf1 bytes.Buffer
	if err = res.Write(&buf1); err != nil {
		t.Fatalf("Write failed %v", err)
	}
	if res, err = ReadResponse(bufio.NewReader(&buf1), nil); err != nil {
		t.Fatalf("ReadResponse failed %v", err)
	}

	var buf2 strings.Builder
	if err = res.Write(&buf2); err != nil {
		t.Fatalf("Write failed %v", err)
	}
	if count := strings.Count(buf2.String(), connectionCloseHeader); count != 1 {
		t.Errorf("Found %d %q header", count, connectionCloseHeader)
	}
}

"""



```