Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The request asks for an explanation of the functionality of `fcgi_test.go`, specifically focusing on the FastCGI implementation in Go's `net/http/fcgi` package. The request also asks for examples, input/output scenarios, command-line arguments (if applicable), and common pitfalls.

**2. Initial Code Scan and High-Level Overview:**

The first step is to quickly scan the code to get a general sense of what's being tested. I see:

* **Import statements:** `bytes`, `errors`, `io`, `net/http`, `strings`, `testing`, `time`. This tells me it's definitely about network communication (specifically HTTP), input/output operations, string manipulation, and testing. The `fcgi` package import is a strong indicator of the core functionality.
* **Test functions:**  Functions starting with `Test` (e.g., `TestSize`, `TestStreams`, `TestGetValues`). This is the core of the code – it's testing various aspects of the FastCGI implementation.
* **Data structures:**  `sizeTests`, `streamTests`, `cleanUpTests`, `envVarTests`. These are likely test cases defining inputs and expected outputs for different scenarios.
* **Helper functions/types:**  `nilCloser`, `writeOnlyConn`, `nameValuePair11`, `makeRecord`, `nopWriteCloser`, `rwNopCloser`, `signalingNopWriteCloser`. These are utility functions and custom types designed to aid in testing.
* **Constants:** Although not explicitly present as `const` in the provided snippet, the literal byte slices used as expected outputs hint at constants defined elsewhere in the full `fcgi` package.

**3. Analyzing Individual Test Functions:**

Now, I go through each test function and try to understand what specific feature it's verifying:

* **`TestSize`:** Focuses on the `encodeSize` and `readSize` functions. The `sizeTests` data provides various integer sizes and their corresponding byte representations. This suggests these functions are for encoding and decoding sizes in the FastCGI protocol. *Hypothesis: This relates to how the length of data chunks is represented in the FastCGI stream.*
* **`TestStreams`:**  Deals with `recType`, `reqId`, and `content`. The `streamTests` have `raw` byte arrays. This looks like testing the reading and writing of FastCGI records. The "two records" test case hints at handling data larger than a single record. *Hypothesis: This tests the core record structure and how data is segmented in the FastCGI protocol.*
* **`TestGetValues`:**  Calls `handleRecord` and checks the output written to a `writeOnlyConn`. The expected output string contains "FCGI_MPXS_CONNS". *Hypothesis: This might be testing the handling of a `typeGetValues` record, which is likely used to query FastCGI server capabilities.*
* **`TestChildServeCleansUp`:**  Deals with `typeAbortRequest` and error conditions (`ErrRequestAborted`, `ErrConnClosed`). It seems to be testing how the FastCGI server cleans up resources when requests are aborted or when errors occur. *Hypothesis: Focuses on proper resource management, especially closing connections and request bodies.*
* **`TestMalformedParams`:**  The input byte array seems deliberately malformed. The function name and the comment "Verifies it doesn't crash" indicate a robustness test for handling invalid input. *Hypothesis: Testing error handling and preventing crashes due to malformed FastCGI data.*
* **`TestChildServeReadsEnvVars`:**  Checks environment variables. The `envVarTests` specify input, expected environment variable names, and values. *Hypothesis: Tests how FastCGI parameters are translated into HTTP request environment variables.*
* **`TestResponseWriterSniffsContentType`:**  Checks the `Content-Type` header based on the response body. *Hypothesis: Testing the automatic content type detection feature of the FastCGI response writer.*
* **`TestSlowRequest`:**  Introduces delays and uses `io.Pipe`. It checks if the server handles slow requests correctly. *Hypothesis: Testing connection management and timeout handling for slow clients.*

**4. Connecting to Go Concepts and Providing Examples:**

Based on the analysis of the test functions, I can now link them to specific Go features:

* **`encodeSize`/`readSize`:** This is a custom implementation for encoding/decoding variable-length integers, a common technique in binary protocols. I can provide a simple example of using these functions.
* **Record structure and reading/writing:** This directly relates to structs and byte manipulation in Go. The `record` struct likely has fields for the header and content. I can illustrate the basic structure of a FastCGI record.
* **Handling different record types:** The `recType` suggests an enum or a set of constants defining different FastCGI message types.
* **`http.HandlerFunc` and `http.ResponseWriter`:** This clearly ties into Go's standard HTTP handling mechanisms. The FastCGI implementation bridges the FastCGI protocol to Go's HTTP handler interface.
* **`io.Pipe`:** Used for simulating asynchronous communication, allowing the test to control the rate at which data is sent.

**5. Identifying Potential Pitfalls:**

By understanding how the code works, I can think about common mistakes users might make when interacting with FastCGI:

* **Incorrectly handling record boundaries:**  Sending data that doesn't align with the FastCGI record structure.
* **Not closing request bodies:**  Leading to resource leaks.
* **Misunderstanding environment variable handling:**  Expecting certain variables to be present when they might be filtered out.
* **Timeout issues:**  Not configuring appropriate timeouts for long-running requests.

**6. Considering Command-Line Arguments:**

Since the code snippet is a test file, it doesn't directly handle command-line arguments. However, a real FastCGI server would likely have arguments for specifying the listening address, socket path, etc. I need to acknowledge this distinction.

**7. Structuring the Answer:**

Finally, I organize the information into a clear and structured answer, addressing each part of the original request:

* **Functionality Summary:** Provide a concise overview of the test file's purpose.
* **Go Feature Illustration:**  Choose a key feature (like size encoding) and provide a code example with input and output.
* **Code Inference:** Explain the likely implementation of record handling, even without seeing the full `fcgi.go` file.
* **Command-Line Arguments:** Explicitly state that the test file doesn't handle them but a real server would.
* **Common Mistakes:** List the potential pitfalls with illustrative examples.

This detailed thought process allows me to dissect the code snippet effectively and generate a comprehensive and accurate answer. It involves understanding the code's purpose, analyzing individual components, connecting them to relevant Go concepts, and anticipating potential user errors.
这段代码是 Go 语言标准库 `net/http/fcgi` 包中 `fcgi_test.go` 文件的一部分，它主要用于测试 FastCGI 协议的实现。 让我们逐个分析其功能。

**主要功能:**

1. **测试 FastCGI 数据包的大小编码和解码 (`TestSize`)**:
   - FastCGI 协议使用一种特殊的变长方式来编码数据包的大小。这个测试函数验证了 `encodeSize` 函数能否正确地将一个 `uint32` 的大小编码成字节数组，以及 `readSize` 函数能否正确地从字节数组中解码出 `uint32` 的大小。
   - 它定义了一组测试用例 `sizeTests`，包含了不同的 `uint32` 大小和预期的字节编码。

2. **测试 FastCGI 数据流的读写 (`TestStreams`)**:
   - 这个测试函数模拟了 FastCGI 数据流的发送和接收，使用了不同的记录类型 (`recType`)、请求 ID (`reqId`) 和内容 (`content`)。
   - 它定义了一组测试用例 `streamTests`，包含了不同的场景，例如单个记录和需要拆分成多个记录的大数据。
   - 它测试了 `record` 结构体的 `read` 方法能否正确解析 FastCGI 数据，以及 `writer` 类型的 `Write` 和 `Close` 方法能否正确地构建和发送 FastCGI 数据包。

3. **测试处理 `typeGetValues` 类型的 FastCGI 记录 (`TestGetValues`)**:
   - `typeGetValues` 记录用于请求 FastCGI 服务的一些配置信息。这个测试验证了当 FastCGI 服务接收到 `typeGetValues` 类型的请求时，能否返回预期的信息，例如 `FCGI_MPXS_CONNS`（表示是否支持多路连接）。

4. **测试在请求中止或连接关闭时的清理工作 (`TestChildServeCleansUp`)**:
   - 这个测试模拟了请求被中止 (`typeAbortRequest`) 或连接意外关闭的情况，验证 FastCGI 服务器能否正确地关闭相关的资源，例如请求的 Body。这对于防止资源泄漏非常重要。

5. **测试处理格式错误的 FastCGI 参数 (`TestMalformedParams`)**:
   - 这个测试用例提供了一个格式错误的参数记录，用来验证 FastCGI 服务器在遇到非法输入时是否能健壮地处理，而不会崩溃。

6. **测试 FastCGI 参数如何转换为 HTTP 请求的环境变量 (`TestChildServeReadsEnvVars`)**:
   - FastCGI 协议通过 `typeParams` 类型的记录传递请求参数。这个测试验证了这些参数能否正确地被 FastCGI 服务器解析，并转换为 HTTP 请求的相应环境变量，例如 `REQUEST_METHOD` 和 `REMOTE_USER`。
   - 它还测试了某些参数（如 `QUERY_STRING`）是否会被按照预期过滤掉。

7. **测试 `ResponseWriter` 能否嗅探内容类型 (`TestResponseWriterSniffsContentType`)**:
   - 在没有显式设置 `Content-Type` 的情况下，HTTP 响应的 `ResponseWriter` 会尝试根据响应的内容来自动设置 `Content-Type`。这个测试验证了 `net/http/fcgi` 包中的 `response` 类型是否具有这种嗅探功能。

8. **测试处理慢速请求的能力 (`TestSlowRequest`)**:
   - 这个测试模拟了一个客户端发送请求数据很慢的情况，验证 FastCGI 服务器能否正确处理这种场景，而不会出现死锁或其他问题。

**Go 语言功能实现示例 (基于代码推理):**

虽然没有直接给出 `fcgi.go` 的实现，但我们可以根据测试代码推断出一些关键的 Go 语言功能的使用。

**1. FastCGI 数据包的结构体定义:**

```go
type recordHeader struct {
	Version       uint8
	Type          recType // recType 可能是一个枚举或常量定义
	Id            uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

type record struct {
	h recordHeader
	buf bytes.Buffer // 用于存储内容数据
}

type recType uint8

const (
	typeBeginRequest recType = 1
	typeAbortRequest recType = 2
	typeEndRequest   recType = 3
	typeParams       recType = 4
	typeStdin        recType = 5
	typeStdout       recType = 6
	typeStderr       recType = 7
	typeGetValues    recType = 9
	typeGetValuesResult recType = 10
)
```

**假设的输入与输出 (针对 `TestSize`):**

**输入:**
```go
size := uint32(1000)
b := make([]byte, 4)
```

**输出 (基于 `sizeTests` 中的定义):**
`encodeSize(b, size)` 后， `b` 的前几个字节应该是 `[]byte{0x80, 0x00, 0x03, 0xE8}`，并且返回值 `n` 应该是 4。
`readSize([]byte{0x80, 0x00, 0x03, 0xE8})` 的返回值应该是 `size = 1000` 和 `n = 4`。

**假设的输入与输出 (针对 `TestStreams`,  "single record" 测试用例):**

**输入 (raw 数据):**
`[]byte{1, byte(typeStdout), 0, 1, 0, 0, 0, 0}`

**输出 (读取后):**
`rec.h.Type` 将会是 `typeStdout` (假设其值为 6)。
`rec.h.Id` 将会是 `1`。
`rec.content()` 将会返回一个空的 `[]byte`。

**代码推理:**

- **变长大小编码 (`encodeSize`, `readSize`):**  FastCGI 使用一个字节来表示小的数值（0-127），对于更大的数值，它会设置最高位为 1，并使用接下来的 3 个字节来表示大小。这在 `TestSize` 中得到了验证。
- **FastCGI 记录结构 (`record`, `recordHeader`):** 可以推断出 `record` 结构体包含了头部信息 (`recordHeader`) 和内容数据。头部信息包含了版本、类型、请求 ID、内容长度等关键信息。
- **连接管理 (`newConn`, `newChild`):**  `newConn` 可能是创建一个 FastCGI 连接的包装器，而 `newChild` 可能是用于处理单个 FastCGI 子进程或请求的结构体。
- **写入器 (`newWriter`):** `newWriter` 函数可能创建了一个用于向 FastCGI 连接写入特定类型数据的辅助结构体。
- **HTTP 处理 (`http.HandlerFunc`, `http.ResponseWriter`, `http.Request`):**  代码中使用了标准的 `net/http` 包的类型，表明 `net/http/fcgi` 包的目标是将 FastCGI 请求转换为 `http.Request`，并将 `http.ResponseWriter` 的操作转换为 FastCGI 响应。

**命令行参数:**

这段代码本身是测试代码，并不直接处理命令行参数。但是，`net/http/fcgi` 包提供的实际 FastCGI 服务端实现（通常在 `fcgi.Serve` 函数中）可能会接受一些命令行参数，例如：

- **监听地址和端口:**  指定 FastCGI 服务监听的网络地址和端口，例如 `-addr :9000` 或 `-bind 127.0.0.1:9000`。
- **监听 Socket 文件:**  指定 FastCGI 服务监听的 Unix domain socket 文件路径，例如 `-sock /var/run/fcgi.sock`。

**使用者易犯错的点:**

1. **不正确地处理 FastCGI 记录边界:** 用户如果直接操作底层的 IO，可能会错误地分割或组合 FastCGI 记录，导致解析错误。`net/http/fcgi` 包已经封装了这些细节，但如果需要自定义底层交互，则需要注意。

   **错误示例 (假设手动构建 FastCGI 记录):**

   ```go
   // 错误地将一个完整的 Params 记录拆分成两部分发送
   conn.Write([]byte{1, byte(typeParams), 0, 1, 0, 5, 0, 0, /* 部分数据 */})
   conn.Write([]byte{byte(len("VAR")), byte(len("VALUE"))})
   conn.Write([]byte("VARVALUE"))
   ```

   正确的做法应该确保一次写入一个完整的 FastCGI 记录。

2. **忘记关闭请求的 Body:** 当处理 FastCGI 请求时，HTTP 请求的 `Body` (通常是 `r.Body`) 需要在使用后显式关闭。否则，可能会导致资源泄漏或服务端无法正确处理后续请求。

   **错误示例:**

   ```go
   http.HandleFunc("/process", func(w http.ResponseWriter, r *http.Request) {
       // ... 处理请求 ...
       // 忘记关闭 r.Body
       // return
   })
   ```

   **正确做法:**

   ```go
   http.HandleFunc("/process", func(w http.ResponseWriter, r *http.Request) {
       defer r.Body.Close()
       // ... 处理请求 ...
   })
   ```

3. **误解 FastCGI 环境变量的处理:**  并非所有的 FastCGI 参数都会直接映射到 HTTP 请求的头部或环境变量中。例如，像 `QUERY_STRING` 这样的参数通常会被 HTTP 服务器处理，而不是直接作为环境变量传递给应用程序。这段测试代码也验证了这一点，`QUERY_STRING` 被预期过滤掉。

总而言之，这段测试代码覆盖了 `net/http/fcgi` 包中 FastCGI 协议实现的多个关键方面，包括数据包的编码解码、数据流的处理、特定类型的记录处理、错误处理、环境变量转换以及内容类型嗅探等功能。通过这些测试，可以确保 Go 语言的 FastCGI 实现的正确性和健壮性。

Prompt: 
```
这是路径为go/src/net/http/fcgi/fcgi_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fcgi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

var sizeTests = []struct {
	size  uint32
	bytes []byte
}{
	{0, []byte{0x00}},
	{127, []byte{0x7F}},
	{128, []byte{0x80, 0x00, 0x00, 0x80}},
	{1000, []byte{0x80, 0x00, 0x03, 0xE8}},
	{33554431, []byte{0x81, 0xFF, 0xFF, 0xFF}},
}

func TestSize(t *testing.T) {
	b := make([]byte, 4)
	for i, test := range sizeTests {
		n := encodeSize(b, test.size)
		if !bytes.Equal(b[:n], test.bytes) {
			t.Errorf("%d expected %x, encoded %x", i, test.bytes, b)
		}
		size, n := readSize(test.bytes)
		if size != test.size {
			t.Errorf("%d expected %d, read %d", i, test.size, size)
		}
		if len(test.bytes) != n {
			t.Errorf("%d did not consume all the bytes", i)
		}
	}
}

var streamTests = []struct {
	desc    string
	recType recType
	reqId   uint16
	content []byte
	raw     []byte
}{
	{"single record", typeStdout, 1, nil,
		[]byte{1, byte(typeStdout), 0, 1, 0, 0, 0, 0},
	},
	// this data will have to be split into two records
	{"two records", typeStdin, 300, make([]byte, 66000),
		bytes.Join([][]byte{
			// header for the first record
			{1, byte(typeStdin), 0x01, 0x2C, 0xFF, 0xFF, 1, 0},
			make([]byte, 65536),
			// header for the second
			{1, byte(typeStdin), 0x01, 0x2C, 0x01, 0xD1, 7, 0},
			make([]byte, 472),
			// header for the empty record
			{1, byte(typeStdin), 0x01, 0x2C, 0, 0, 0, 0},
		},
			nil),
	},
}

type nilCloser struct {
	io.ReadWriter
}

func (c *nilCloser) Close() error { return nil }

func TestStreams(t *testing.T) {
	var rec record
outer:
	for _, test := range streamTests {
		buf := bytes.NewBuffer(test.raw)
		var content []byte
		for buf.Len() > 0 {
			if err := rec.read(buf); err != nil {
				t.Errorf("%s: error reading record: %v", test.desc, err)
				continue outer
			}
			content = append(content, rec.content()...)
		}
		if rec.h.Type != test.recType {
			t.Errorf("%s: got type %d expected %d", test.desc, rec.h.Type, test.recType)
			continue
		}
		if rec.h.Id != test.reqId {
			t.Errorf("%s: got request ID %d expected %d", test.desc, rec.h.Id, test.reqId)
			continue
		}
		if !bytes.Equal(content, test.content) {
			t.Errorf("%s: read wrong content", test.desc)
			continue
		}
		buf.Reset()
		c := newConn(&nilCloser{buf})
		w := newWriter(c, test.recType, test.reqId)
		if _, err := w.Write(test.content); err != nil {
			t.Errorf("%s: error writing record: %v", test.desc, err)
			continue
		}
		if err := w.Close(); err != nil {
			t.Errorf("%s: error closing stream: %v", test.desc, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.raw) {
			t.Errorf("%s: wrote wrong content", test.desc)
		}
	}
}

type writeOnlyConn struct {
	buf []byte
}

func (c *writeOnlyConn) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *writeOnlyConn) Read(p []byte) (int, error) {
	return 0, errors.New("conn is write-only")
}

func (c *writeOnlyConn) Close() error {
	return nil
}

func TestGetValues(t *testing.T) {
	var rec record
	rec.h.Type = typeGetValues

	wc := new(writeOnlyConn)
	c := newChild(wc, nil)
	err := c.handleRecord(&rec)
	if err != nil {
		t.Fatalf("handleRecord: %v", err)
	}

	const want = "\x01\n\x00\x00\x00\x12\x06\x00" +
		"\x0f\x01FCGI_MPXS_CONNS1" +
		"\x00\x00\x00\x00\x00\x00\x01\n\x00\x00\x00\x00\x00\x00"
	if got := string(wc.buf); got != want {
		t.Errorf(" got: %q\nwant: %q\n", got, want)
	}
}

func nameValuePair11(nameData, valueData string) []byte {
	return bytes.Join(
		[][]byte{
			{byte(len(nameData)), byte(len(valueData))},
			[]byte(nameData),
			[]byte(valueData),
		},
		nil,
	)
}

func makeRecord(
	recordType recType,
	requestId uint16,
	contentData []byte,
) []byte {
	requestIdB1 := byte(requestId >> 8)
	requestIdB0 := byte(requestId)

	contentLength := len(contentData)
	contentLengthB1 := byte(contentLength >> 8)
	contentLengthB0 := byte(contentLength)
	return bytes.Join([][]byte{
		{1, byte(recordType), requestIdB1, requestIdB0, contentLengthB1,
			contentLengthB0, 0, 0},
		contentData,
	},
		nil)
}

// a series of FastCGI records that start a request and begin sending the
// request body
var streamBeginTypeStdin = bytes.Join([][]byte{
	// set up request 1
	makeRecord(typeBeginRequest, 1,
		[]byte{0, byte(roleResponder), 0, 0, 0, 0, 0, 0}),
	// add required parameters to request 1
	makeRecord(typeParams, 1, nameValuePair11("REQUEST_METHOD", "GET")),
	makeRecord(typeParams, 1, nameValuePair11("SERVER_PROTOCOL", "HTTP/1.1")),
	makeRecord(typeParams, 1, nil),
	// begin sending body of request 1
	makeRecord(typeStdin, 1, []byte("0123456789abcdef")),
},
	nil)

var cleanUpTests = []struct {
	input []byte
	err   error
}{
	// confirm that child.handleRecord closes req.pw after aborting req
	{
		bytes.Join([][]byte{
			streamBeginTypeStdin,
			makeRecord(typeAbortRequest, 1, nil),
		},
			nil),
		ErrRequestAborted,
	},
	// confirm that child.serve closes all pipes after error reading record
	{
		bytes.Join([][]byte{
			streamBeginTypeStdin,
			nil,
		},
			nil),
		ErrConnClosed,
	},
}

type nopWriteCloser struct {
	io.Reader
}

func (nopWriteCloser) Write(buf []byte) (int, error) {
	return len(buf), nil
}

func (nopWriteCloser) Close() error {
	return nil
}

// Test that child.serve closes the bodies of aborted requests and closes the
// bodies of all requests before returning. Causes deadlock if either condition
// isn't met. See issue 6934.
func TestChildServeCleansUp(t *testing.T) {
	for _, tt := range cleanUpTests {
		input := make([]byte, len(tt.input))
		copy(input, tt.input)
		rc := nopWriteCloser{bytes.NewReader(input)}
		done := make(chan struct{})
		c := newChild(rc, http.HandlerFunc(func(
			w http.ResponseWriter,
			r *http.Request,
		) {
			// block on reading body of request
			_, err := io.Copy(io.Discard, r.Body)
			if err != tt.err {
				t.Errorf("Expected %#v, got %#v", tt.err, err)
			}
			// not reached if body of request isn't closed
			close(done)
		}))
		c.serve()
		// wait for body of request to be closed or all goroutines to block
		<-done
	}
}

type rwNopCloser struct {
	io.Reader
	io.Writer
}

func (rwNopCloser) Close() error {
	return nil
}

// Verifies it doesn't crash. 	Issue 11824.
func TestMalformedParams(t *testing.T) {
	input := []byte{
		// beginRequest, requestId=1, contentLength=8, role=1, keepConn=1
		1, 1, 0, 1, 0, 8, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0,
		// params, requestId=1, contentLength=10, k1Len=50, v1Len=50 (malformed, wrong length)
		1, 4, 0, 1, 0, 10, 0, 0, 50, 50, 3, 4, 5, 6, 7, 8, 9, 10,
		// end of params
		1, 4, 0, 1, 0, 0, 0, 0,
	}
	rw := rwNopCloser{bytes.NewReader(input), io.Discard}
	c := newChild(rw, http.DefaultServeMux)
	c.serve()
}

// a series of FastCGI records that start and end a request
var streamFullRequestStdin = bytes.Join([][]byte{
	// set up request
	makeRecord(typeBeginRequest, 1,
		[]byte{0, byte(roleResponder), 0, 0, 0, 0, 0, 0}),
	// add required parameters
	makeRecord(typeParams, 1, nameValuePair11("REQUEST_METHOD", "GET")),
	makeRecord(typeParams, 1, nameValuePair11("SERVER_PROTOCOL", "HTTP/1.1")),
	// set optional parameters
	makeRecord(typeParams, 1, nameValuePair11("REMOTE_USER", "jane.doe")),
	makeRecord(typeParams, 1, nameValuePair11("QUERY_STRING", "/foo/bar")),
	makeRecord(typeParams, 1, nil),
	// begin sending body of request
	makeRecord(typeStdin, 1, []byte("0123456789abcdef")),
	// end request
	makeRecord(typeEndRequest, 1, nil),
},
	nil)

var envVarTests = []struct {
	input               []byte
	envVar              string
	expectedVal         string
	expectedFilteredOut bool
}{
	{
		streamFullRequestStdin,
		"REMOTE_USER",
		"jane.doe",
		false,
	},
	{
		streamFullRequestStdin,
		"QUERY_STRING",
		"",
		true,
	},
}

// Test that environment variables set for a request can be
// read by a handler. Ensures that variables not set will not
// be exposed to a handler.
func TestChildServeReadsEnvVars(t *testing.T) {
	for _, tt := range envVarTests {
		input := make([]byte, len(tt.input))
		copy(input, tt.input)
		rc := nopWriteCloser{bytes.NewReader(input)}
		done := make(chan struct{})
		c := newChild(rc, http.HandlerFunc(func(
			w http.ResponseWriter,
			r *http.Request,
		) {
			env := ProcessEnv(r)
			if _, ok := env[tt.envVar]; ok && tt.expectedFilteredOut {
				t.Errorf("Expected environment variable %s to not be set, but set to %s",
					tt.envVar, env[tt.envVar])
			} else if env[tt.envVar] != tt.expectedVal {
				t.Errorf("Expected %s, got %s", tt.expectedVal, env[tt.envVar])
			}
			close(done)
		}))
		c.serve()
		<-done
	}
}

func TestResponseWriterSniffsContentType(t *testing.T) {
	var tests = []struct {
		name   string
		body   string
		wantCT string
	}{
		{
			name:   "no body",
			wantCT: "text/plain; charset=utf-8",
		},
		{
			name:   "html",
			body:   "<html><head><title>test page</title></head><body>This is a body</body></html>",
			wantCT: "text/html; charset=utf-8",
		},
		{
			name:   "text",
			body:   strings.Repeat("gopher", 86),
			wantCT: "text/plain; charset=utf-8",
		},
		{
			name:   "jpg",
			body:   "\xFF\xD8\xFF" + strings.Repeat("B", 1024),
			wantCT: "image/jpeg",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, len(streamFullRequestStdin))
			copy(input, streamFullRequestStdin)
			rc := nopWriteCloser{bytes.NewReader(input)}
			done := make(chan struct{})
			var resp *response
			c := newChild(rc, http.HandlerFunc(func(
				w http.ResponseWriter,
				r *http.Request,
			) {
				io.WriteString(w, tt.body)
				resp = w.(*response)
				close(done)
			}))
			c.serve()
			<-done
			if got := resp.Header().Get("Content-Type"); got != tt.wantCT {
				t.Errorf("got a Content-Type of %q; expected it to start with %q", got, tt.wantCT)
			}
		})
	}
}

type signalingNopWriteCloser struct {
	io.ReadCloser
	closed chan bool
}

func (*signalingNopWriteCloser) Write(buf []byte) (int, error) {
	return len(buf), nil
}

func (rc *signalingNopWriteCloser) Close() error {
	close(rc.closed)
	return rc.ReadCloser.Close()
}

// Test whether server properly closes connection when processing slow
// requests
func TestSlowRequest(t *testing.T) {
	pr, pw := io.Pipe()

	writerDone := make(chan struct{})
	go func() {
		for _, buf := range [][]byte{
			streamBeginTypeStdin,
			makeRecord(typeStdin, 1, nil),
		} {
			pw.Write(buf)
			time.Sleep(100 * time.Millisecond)
		}
		close(writerDone)
	}()
	defer func() {
		<-writerDone
		pw.Close()
	}()

	rc := &signalingNopWriteCloser{pr, make(chan bool)}
	handlerDone := make(chan bool)

	c := newChild(rc, http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		w.WriteHeader(200)
		close(handlerDone)
	}))
	c.serve()

	<-handlerDone
	<-rc.closed
	t.Log("FastCGI child closed connection")
}

"""



```