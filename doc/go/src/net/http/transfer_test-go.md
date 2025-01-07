Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for an analysis of a Go source file (`transfer_test.go`) related to HTTP. The key is to understand *what* aspects of HTTP transfer this code is testing.

**2. Identifying the Core Functionality:**

The filename `transfer_test.go` strongly suggests this code is testing the mechanisms of HTTP data transfer. Looking at the function names immediately confirms this:

* `TestBodyReadBadTrailer`: Deals with reading HTTP bodies and handling trailers.
* `TestFinalChunkedBodyReadEOF`: Focuses on reading chunked transfer-encoded bodies, especially reaching the end.
* `TestDetectInMemoryReaders`:  Checks if certain `io.Reader` types are recognized as residing in memory.
* `TestTransferWriterWriteBodyReaderTypes`: Examines how different `io.Reader` types are handled when writing HTTP bodies.
* `TestParseTransferEncoding`: Tests the parsing of the `Transfer-Encoding` header.
* `TestParseContentLength`: Tests the parsing of the `Content-Length` header.

Each test function isolates a specific part of the HTTP transfer process.

**3. Analyzing Individual Test Functions:**

Now, let's dissect each function to understand its specific purpose and how it achieves it:

* **`TestBodyReadBadTrailer`:** This test simulates a scenario where a trailer is expected but something goes wrong during its read (although in the given code, the trailer is an empty string, it's designed to test the logic of *attempting* to read a trailer). The key elements are setting `hdr: true` on the `body` struct to trigger trailer reading and then checking for errors after reading the main body.

* **`TestFinalChunkedBodyReadEOF`:** This test constructs an HTTP response with `Transfer-Encoding: chunked`. It then reads the body and verifies that the `io.EOF` error is returned correctly after all chunks are read. The input is a raw HTTP response string, and the expected output is the concatenated body content and the `io.EOF` error.

* **`TestDetectInMemoryReaders`:** This function uses a table-driven approach to test the `isKnownInMemoryReader` function. It provides various `io.Reader` implementations (pipes, `bytes.Reader`, `bytes.Buffer`, `strings.Reader`, and `io.NopCloser` wrappers around them) and asserts whether they are correctly identified as in-memory readers. This likely relates to optimization decisions within the `net/http` package.

* **`TestTransferWriterWriteBodyReaderTypes`:** This is a more complex test. It focuses on the `transferWriter` struct's `writeBody` method. It creates different types of `io.Reader` (files, buffers), with and without `Content-Length` and `Transfer-Encoding: chunked`. It then checks if the `transferWriter` calls the appropriate methods on a mock writer (`mockTransferWriter`). The key here is understanding how the `net/http` package optimizes body writing based on the reader type and headers. The use of `reflect` is crucial for checking the *type* of the reader passed to the mock.

* **`TestParseTransferEncoding`:** This test validates the parsing logic for the `Transfer-Encoding` header. It checks for various invalid and valid combinations of encoding values and ensures that the `parseTransferEncoding` method returns the expected errors (or nil).

* **`TestParseContentLength`:** This test focuses on parsing the `Content-Length` header. It tests valid and invalid string representations of content lengths, including positive, negative, and very large numbers. The goal is to ensure that the parsing is robust and handles potential errors correctly.

**4. Inferring the Go Language Features:**

Based on the code, several Go features are prominent:

* **Testing:** The `testing` package and the `t *testing.T` argument in test functions are fundamental.
* **String Manipulation:**  `strings.NewReader` is used extensively for creating `io.Reader` from strings.
* **Byte Buffers:** `bytes.NewReader` and `bytes.NewBuffer` are used for in-memory data.
* **Interfaces:** The `io.Reader` and `io.ReaderFrom` interfaces are central to how data is handled.
* **Error Handling:**  The code checks for errors (`err != nil`) and uses `t.Fatal`, `t.Errorf`, and `reflect.DeepEqual` for assertions.
* **Reflection:** The `reflect` package is used in `TestTransferWriterWriteBodyReaderTypes` to examine the types of objects at runtime.
* **HTTP Concepts:** The tests directly deal with HTTP headers like `Transfer-Encoding` and `Content-Length`, and the chunked transfer encoding.

**5. Developing Go Code Examples:**

Now, based on the understanding of each test, we can construct concrete Go examples illustrating the functionality being tested. The key is to show how the `net/http` package (or the underlying mechanisms being tested) behaves in different scenarios.

**6. Identifying Potential Mistakes (Common Pitfalls):**

Thinking about how developers might misuse these features leads to identifying common mistakes:

* Incorrectly setting `Content-Length` and `Transfer-Encoding` simultaneously.
* Not handling `io.EOF` correctly when reading chunked responses.
* Assuming all `io.Reader` implementations behave the same when the underlying implementation matters for optimization.
* Passing invalid values for `Content-Length`.

**7. Structuring the Answer:**

Finally, the answer needs to be organized and presented clearly, using the requested format (Chinese). This involves:

* Starting with a general overview of the file's purpose.
* Explaining the functionality of each test function.
* Providing illustrative Go code examples with input and output.
* Detailing any relevant command-line parameters (in this case, there aren't any directly used by the *test* code itself, so this section can be skipped or noted).
* Listing potential mistakes developers might make.

By following these steps, we can systematically analyze the provided code snippet and generate a comprehensive and informative answer. The key is to understand the *purpose* of the tests and how they relate to the underlying HTTP transfer mechanisms.
这段代码是 Go 语言标准库 `net/http` 包中 `transfer_test.go` 文件的一部分，它主要用于测试 HTTP 传输相关的底层实现细节，特别是关于请求和响应的 body 处理以及 transfer encoding 的解析。

以下是它主要的功能点：

1. **测试 `body` 结构体的 `Read` 方法处理错误的 Trailer 的情况 (`TestBodyReadBadTrailer`)**:
   - 它模拟了一个 HTTP 响应 body，当 body 的内容被读取完毕后，尝试读取一个实际上不存在或格式错误的 trailer。
   - 它的目的是确保 `body` 结构体在尝试读取 trailer 时能够正确地返回错误，避免程序因此进入未知的状态。

2. **测试分块传输编码 (Chunked Transfer Encoding) 的 body 读取到达 EOF 的情况 (`TestFinalChunkedBodyReadEOF`)**:
   - 它构造了一个包含分块编码的 HTTP 响应。
   - 它的目的是验证当分块编码的 body 被完全读取后，`Body.Read()` 方法能够正确返回 `io.EOF` 错误，表明数据已经读取完毕。

3. **检测给定的 `io.Reader` 是否已知是内存中的 Reader (`TestDetectInMemoryReaders`)**:
   - 它定义了一个 `isKnownInMemoryReader` 函数（虽然代码中没有给出完整实现，但可以推断其功能）。
   - 它测试了多种 `io.Reader` 的实现，例如 `bytes.Reader`, `bytes.Buffer`, `strings.Reader` 等，以及用 `io.NopCloser` 包装后的情况。
   - 它的目的是了解 `net/http` 包是否能够识别出这些内存中的 reader，这可能用于内部优化，例如避免不必要的拷贝。

4. **测试 `transferWriter` 结构体的 `writeBody` 方法如何处理不同类型的 Body `io.Reader` (`TestTransferWriterWriteBodyReaderTypes`)**:
   - 它创建了一个 `mockTransferWriter` 结构体，用于模拟实际的写入操作。
   - 它测试了当 HTTP 请求的 body 是不同类型的 `io.Reader` (例如文件 `*os.File` 和 `bytes.Buffer`) 时，`transferWriter` 的 `writeBody` 方法是否会调用 `io.ReaderFrom` 接口（如果 body 实现了该接口，可以进行零拷贝优化）或者直接调用 `Write` 方法。
   - 它覆盖了有 `Content-Length` 和使用 `Transfer-Encoding: chunked` 的不同情况。

5. **测试解析 `Transfer-Encoding` HTTP 头部字段的逻辑 (`TestParseTransferEncoding`)**:
   - 它测试了各种有效的和无效的 `Transfer-Encoding` 字段值。
   - 它的目的是验证 `parseTransferEncoding` 函数能够正确地解析该头部，识别出不支持的编码类型，以及处理多种编码值的情况。

6. **测试解析 `Content-Length` HTTP 头部字段的逻辑 (`TestParseContentLength`)**:
   - 它测试了各种有效的和无效的 `Content-Length` 字段值，包括空字符串、正数、带符号的数字以及超出 `int64` 范围的数字。
   - 它的目的是验证 `parseContentLength` 函数能够正确地解析该头部，并处理潜在的错误格式。

## Go 语言功能实现示例

以下是一些根据代码推断出的 Go 语言功能实现示例：

**1. `isKnownInMemoryReader` 函数的推断实现：**

```go
func isKnownInMemoryReader(r io.Reader) bool {
	switch r.(type) {
	case *bytes.Reader, *bytes.Buffer, *strings.Reader:
		return true
	case interface{ Underlying() io.Reader }: // 处理 io.NopCloser 等包装器
		return isKnownInMemoryReader(r.(interface{ Underlying() io.Reader }).Underlying())
	default:
		return false
	}
}
```

**假设的输入与输出：**

- 输入: `bytes.NewReader([]byte("hello"))`
- 输出: `true`

- 输入: `os.Stdin`
- 输出: `false`

- 输入: `io.NopCloser(strings.NewReader("world"))`
- 输出: `true`

**2. `parseTransferEncoding` 函数的部分推断实现：**

```go
func parseTransferEncoding(header Header) error {
	te := header["Transfer-Encoding"]
	if len(te) == 0 {
		return nil
	}
	if len(te) > 1 {
		return &unsupportedTEError{fmt.Sprintf("too many transfer encodings: %v", te)}
	}
	parts := strings.Split(te[0], ",")
	for _, part := range parts {
		trimmedPart := strings.TrimSpace(part)
		if trimmedPart == "chunked" {
			continue
		} else if trimmedPart == "identity" {
			// identity is allowed but should be the last one, and with chunked it's invalid.
			if len(parts) > 1 {
				return &unsupportedTEError{fmt.Sprintf("unsupported transfer encoding: %q", te[0])}
			}
			continue
		} else if trimmedPart == "" {
			return &unsupportedTEError{`unsupported transfer encoding: ""`}}
		else if strings.ContainsAny(trimmedPart, "\x00-\x1f") {
			return &unsupportedTEError{fmt.Sprintf("unsupported transfer encoding: %q", trimmedPart)}
		}
		return &unsupportedTEError{fmt.Sprintf("unsupported transfer encoding: %q", trimmedPart)}
	}
	return nil
}

type unsupportedTEError struct {
	msg string
}

func (e *unsupportedTEError) Error() string {
	return e.msg
}
```

**假设的输入与输出：**

- 输入: `Header{"Transfer-Encoding": {"chunked"}}`
- 输出: `nil`

- 输入: `Header{"Transfer-Encoding": {"gzip"}}`
- 输出: `&unsupportedTEError{msg:"unsupported transfer encoding: \"gzip\""}`

- 输入: `Header{"Transfer-Encoding": {"chunked, identity"}}`
- 输出: `&unsupportedTEError{msg:"unsupported transfer encoding: \"chunked, identity\""}`

**3. `parseContentLength` 函数的推断实现：**

```go
import "strconv"

type badStringError string

func (e badStringError) Error() string { return string(e) }

func parseContentLength(cl []string) (int64, error) {
	if len(cl) != 1 {
		return 0, badStringError("invalid Content-Length") // 实际上 http 包会处理多个 Content-Length
	}
	s := cl[0]
	if s == "" {
		return 0, badStringError("invalid empty Content-Length")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || s[0] == '+' { // 禁止以加号开头
		return 0, badStringError("bad Content-Length " + s)
	}
	return n, nil
}
```

**假设的输入与输出：**

- 输入: `[]string{"1024"}`
- 输出: `1024, nil`

- 输入: `[]string{"+1024"}`
- 输出: `0, badStringError("bad Content-Length +1024")`

- 输入: `[]string{"-1024"}`
- 输出: `0, badStringError("bad Content-Length -1024")`

## 命令行参数

这段代码是测试代码，通常不涉及直接的命令行参数处理。这些测试是通过 `go test` 命令来运行的。`go test` 提供了一些常用的参数，例如：

- `-v`:  显示更详细的测试输出。
- `-run <regexp>`:  只运行名称匹配正则表达式的测试函数。
- `-coverprofile <file>`:  生成代码覆盖率报告。

例如，要运行 `transfer_test.go` 文件中的所有测试，可以在该文件所在的目录下执行：

```bash
go test -v ./net/http
```

要只运行 `TestBodyReadBadTrailer` 这个测试，可以执行：

```bash
go test -v -run TestBodyReadBadTrailer ./net/http
```

## 使用者易犯错的点

在与 HTTP 传输相关的开发中，使用者容易犯以下错误，而这些测试代码正是为了确保 `net/http` 包能够正确处理这些情况：

1. **同时设置 `Content-Length` 和 `Transfer-Encoding: chunked`**:  HTTP 规范中明确指出，当使用分块传输编码时，不应该设置 `Content-Length`。如果同时设置，可能会导致行为不明确。`net/http` 包的实现会优先考虑 `Transfer-Encoding: chunked`。

   **示例：**

   ```go
   req, _ := http.NewRequest("POST", "http://example.com", strings.NewReader("some data"))
   req.ContentLength = 10 // 假设数据长度为 10
   req.TransferEncoding = []string{"chunked"} // 错误地同时设置

   client := &http.Client{}
   resp, err := client.Do(req)
   // ...
   ```

   在这种情况下，`net/http` 会忽略 `ContentLength` 并使用分块编码发送请求。

2. **没有正确处理分块编码的响应的 `io.EOF`**: 当读取分块编码的响应 body 时，需要循环读取直到 `io.Read` 返回 `io.EOF`，这表示所有 chunk 都已读取完毕。忽略 `io.EOF` 可能会导致数据读取不完整。

   **示例：**

   ```go
   resp, err := http.Get("http://example.com/chunked-data")
   if err != nil {
       // ...
   }
   defer resp.Body.Close()

   buf := new(bytes.Buffer)
   _, err = io.Copy(buf, resp.Body) // 正确的做法，io.Copy 会处理 io.EOF
   if err != nil {
       // ...
   }

   // 错误的做法，可能没有读取完所有 chunk
   data := make([]byte, 1024)
   n, err := resp.Body.Read(data)
   // 仅读取了一部分数据，如果响应 body 很大且是分块的，就会有问题
   ```

3. **错误地假设所有 `io.Reader` 都是一样的**:  `net/http` 包内部会对不同类型的 `io.Reader` 进行优化处理。例如，对于实现了 `io.ReaderFrom` 接口的 reader (如 `*os.File`)，可以直接进行零拷贝传输。强制将所有 body 都当作普通的 reader 处理可能会损失性能。

   **示例 (虽然使用者不常直接操作 `transferWriter`，但理解其原理很重要):**

   假设你自定义了一个 `io.Reader`，并期望 `net/http` 能像处理文件一样进行零拷贝，但你的 reader 没有实现 `io.ReaderFrom`。在这种情况下，`net/http` 可能会回退到普通的读写操作。

4. **传递不合法的 `Content-Length` 值**: `Content-Length` 必须是非负的整数。传递负数或非数字字符串会导致错误。`TestParseContentLength` 正是测试了这种边界情况。

这段测试代码对于理解 `net/http` 包如何处理 HTTP 传输的底层细节非常有帮助，也提醒开发者在进行相关开发时需要注意的一些关键点。

Prompt: 
```
这是路径为go/src/net/http/transfer_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestBodyReadBadTrailer(t *testing.T) {
	b := &body{
		src: strings.NewReader("foobar"),
		hdr: true, // force reading the trailer
		r:   bufio.NewReader(strings.NewReader("")),
	}
	buf := make([]byte, 7)
	n, err := b.Read(buf[:3])
	got := string(buf[:n])
	if got != "foo" || err != nil {
		t.Fatalf(`first Read = %d (%q), %v; want 3 ("foo")`, n, got, err)
	}

	n, err = b.Read(buf[:])
	got = string(buf[:n])
	if got != "bar" || err != nil {
		t.Fatalf(`second Read = %d (%q), %v; want 3 ("bar")`, n, got, err)
	}

	n, err = b.Read(buf[:])
	got = string(buf[:n])
	if err == nil {
		t.Errorf("final Read was successful (%q), expected error from trailer read", got)
	}
}

func TestFinalChunkedBodyReadEOF(t *testing.T) {
	res, err := ReadResponse(bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"0a\r\n"+
			"Body here\n\r\n"+
			"09\r\n"+
			"continued\r\n"+
			"0\r\n"+
			"\r\n")), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "Body here\ncontinued"
	buf := make([]byte, len(want))
	n, err := res.Body.Read(buf)
	if n != len(want) || err != io.EOF {
		t.Logf("body = %#v", res.Body)
		t.Errorf("Read = %v, %v; want %d, EOF", n, err, len(want))
	}
	if string(buf) != want {
		t.Errorf("buf = %q; want %q", buf, want)
	}
}

func TestDetectInMemoryReaders(t *testing.T) {
	pr, _ := io.Pipe()
	tests := []struct {
		r    io.Reader
		want bool
	}{
		{pr, false},

		{bytes.NewReader(nil), true},
		{bytes.NewBuffer(nil), true},
		{strings.NewReader(""), true},

		{io.NopCloser(pr), false},

		{io.NopCloser(bytes.NewReader(nil)), true},
		{io.NopCloser(bytes.NewBuffer(nil)), true},
		{io.NopCloser(strings.NewReader("")), true},
	}
	for i, tt := range tests {
		got := isKnownInMemoryReader(tt.r)
		if got != tt.want {
			t.Errorf("%d: got = %v; want %v", i, got, tt.want)
		}
	}
}

type mockTransferWriter struct {
	CalledReader io.Reader
	WriteCalled  bool
}

var _ io.ReaderFrom = (*mockTransferWriter)(nil)

func (w *mockTransferWriter) ReadFrom(r io.Reader) (int64, error) {
	w.CalledReader = r
	return io.Copy(io.Discard, r)
}

func (w *mockTransferWriter) Write(p []byte) (int, error) {
	w.WriteCalled = true
	return io.Discard.Write(p)
}

func TestTransferWriterWriteBodyReaderTypes(t *testing.T) {
	fileType := reflect.TypeFor[*os.File]()
	bufferType := reflect.TypeFor[*bytes.Buffer]()

	nBytes := int64(1 << 10)
	newFileFunc := func() (r io.Reader, done func(), err error) {
		f, err := os.CreateTemp("", "net-http-newfilefunc")
		if err != nil {
			return nil, nil, err
		}

		// Write some bytes to the file to enable reading.
		if _, err := io.CopyN(f, rand.Reader, nBytes); err != nil {
			return nil, nil, fmt.Errorf("failed to write data to file: %v", err)
		}
		if _, err := f.Seek(0, 0); err != nil {
			return nil, nil, fmt.Errorf("failed to seek to front: %v", err)
		}

		done = func() {
			f.Close()
			os.Remove(f.Name())
		}

		return f, done, nil
	}

	newBufferFunc := func() (io.Reader, func(), error) {
		return bytes.NewBuffer(make([]byte, nBytes)), func() {}, nil
	}

	cases := []struct {
		name             string
		bodyFunc         func() (io.Reader, func(), error)
		method           string
		contentLength    int64
		transferEncoding []string
		limitedReader    bool
		expectedReader   reflect.Type
		expectedWrite    bool
	}{
		{
			name:           "file, non-chunked, size set",
			bodyFunc:       newFileFunc,
			method:         "PUT",
			contentLength:  nBytes,
			limitedReader:  true,
			expectedReader: fileType,
		},
		{
			name:   "file, non-chunked, size set, nopCloser wrapped",
			method: "PUT",
			bodyFunc: func() (io.Reader, func(), error) {
				r, cleanup, err := newFileFunc()
				return io.NopCloser(r), cleanup, err
			},
			contentLength:  nBytes,
			limitedReader:  true,
			expectedReader: fileType,
		},
		{
			name:           "file, non-chunked, negative size",
			method:         "PUT",
			bodyFunc:       newFileFunc,
			contentLength:  -1,
			expectedReader: fileType,
		},
		{
			name:           "file, non-chunked, CONNECT, negative size",
			method:         "CONNECT",
			bodyFunc:       newFileFunc,
			contentLength:  -1,
			expectedReader: fileType,
		},
		{
			name:             "file, chunked",
			method:           "PUT",
			bodyFunc:         newFileFunc,
			transferEncoding: []string{"chunked"},
			expectedWrite:    true,
		},
		{
			name:           "buffer, non-chunked, size set",
			bodyFunc:       newBufferFunc,
			method:         "PUT",
			contentLength:  nBytes,
			limitedReader:  true,
			expectedReader: bufferType,
		},
		{
			name:   "buffer, non-chunked, size set, nopCloser wrapped",
			method: "PUT",
			bodyFunc: func() (io.Reader, func(), error) {
				r, cleanup, err := newBufferFunc()
				return io.NopCloser(r), cleanup, err
			},
			contentLength:  nBytes,
			limitedReader:  true,
			expectedReader: bufferType,
		},
		{
			name:          "buffer, non-chunked, negative size",
			method:        "PUT",
			bodyFunc:      newBufferFunc,
			contentLength: -1,
			expectedWrite: true,
		},
		{
			name:          "buffer, non-chunked, CONNECT, negative size",
			method:        "CONNECT",
			bodyFunc:      newBufferFunc,
			contentLength: -1,
			expectedWrite: true,
		},
		{
			name:             "buffer, chunked",
			method:           "PUT",
			bodyFunc:         newBufferFunc,
			transferEncoding: []string{"chunked"},
			expectedWrite:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, cleanup, err := tc.bodyFunc()
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()

			mw := &mockTransferWriter{}
			tw := &transferWriter{
				Body:             body,
				ContentLength:    tc.contentLength,
				TransferEncoding: tc.transferEncoding,
			}

			if err := tw.writeBody(mw); err != nil {
				t.Fatal(err)
			}

			if tc.expectedReader != nil {
				if mw.CalledReader == nil {
					t.Fatal("did not call ReadFrom")
				}

				var actualReader reflect.Type
				lr, ok := mw.CalledReader.(*io.LimitedReader)
				if ok && tc.limitedReader {
					actualReader = reflect.TypeOf(lr.R)
				} else {
					actualReader = reflect.TypeOf(mw.CalledReader)
					// We have to handle this special case for genericWriteTo in os,
					// this struct is introduced to support a zero-copy optimization,
					// check out https://go.dev/issue/58808 for details.
					if actualReader.Kind() == reflect.Struct && actualReader.PkgPath() == "os" && actualReader.Name() == "fileWithoutWriteTo" {
						actualReader = actualReader.Field(1).Type
					}
				}

				if tc.expectedReader != actualReader {
					t.Fatalf("got reader %s want %s", actualReader, tc.expectedReader)
				}
			}

			if tc.expectedWrite && !mw.WriteCalled {
				t.Fatal("did not invoke Write")
			}
		})
	}
}

func TestParseTransferEncoding(t *testing.T) {
	tests := []struct {
		hdr     Header
		wantErr error
	}{
		{
			hdr:     Header{"Transfer-Encoding": {"fugazi"}},
			wantErr: &unsupportedTEError{`unsupported transfer encoding: "fugazi"`},
		},
		{
			hdr:     Header{"Transfer-Encoding": {"chunked, chunked", "identity", "chunked"}},
			wantErr: &unsupportedTEError{`too many transfer encodings: ["chunked, chunked" "identity" "chunked"]`},
		},
		{
			hdr:     Header{"Transfer-Encoding": {""}},
			wantErr: &unsupportedTEError{`unsupported transfer encoding: ""`},
		},
		{
			hdr:     Header{"Transfer-Encoding": {"chunked, identity"}},
			wantErr: &unsupportedTEError{`unsupported transfer encoding: "chunked, identity"`},
		},
		{
			hdr:     Header{"Transfer-Encoding": {"chunked", "identity"}},
			wantErr: &unsupportedTEError{`too many transfer encodings: ["chunked" "identity"]`},
		},
		{
			hdr:     Header{"Transfer-Encoding": {"\x0bchunked"}},
			wantErr: &unsupportedTEError{`unsupported transfer encoding: "\vchunked"`},
		},
		{
			hdr:     Header{"Transfer-Encoding": {"chunked"}},
			wantErr: nil,
		},
	}

	for i, tt := range tests {
		tr := &transferReader{
			Header:     tt.hdr,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		gotErr := tr.parseTransferEncoding()
		if !reflect.DeepEqual(gotErr, tt.wantErr) {
			t.Errorf("%d.\ngot error:\n%v\nwant error:\n%v\n\n", i, gotErr, tt.wantErr)
		}
	}
}

// issue 39017 - disallow Content-Length values such as "+3"
func TestParseContentLength(t *testing.T) {
	tests := []struct {
		cl      string
		wantErr error
	}{
		{
			cl:      "",
			wantErr: badStringError("invalid empty Content-Length", ""),
		},
		{
			cl:      "3",
			wantErr: nil,
		},
		{
			cl:      "+3",
			wantErr: badStringError("bad Content-Length", "+3"),
		},
		{
			cl:      "-3",
			wantErr: badStringError("bad Content-Length", "-3"),
		},
		{
			// max int64, for safe conversion before returning
			cl:      "9223372036854775807",
			wantErr: nil,
		},
		{
			cl:      "9223372036854775808",
			wantErr: badStringError("bad Content-Length", "9223372036854775808"),
		},
	}

	for _, tt := range tests {
		if _, gotErr := parseContentLength([]string{tt.cl}); !reflect.DeepEqual(gotErr, tt.wantErr) {
			t.Errorf("%q:\n\tgot=%v\n\twant=%v", tt.cl, gotErr, tt.wantErr)
		}
	}
}

"""



```