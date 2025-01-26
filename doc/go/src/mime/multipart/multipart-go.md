Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `mime/multipart` package. I need to break down the code and explain what it does. Specifically, the request asks for:

1. **Functionality Listing:**  A summary of what the code does.
2. **Go Feature Implementation (with examples):** Identify the high-level Go feature being implemented (multipart parsing) and provide a Go code example.
3. **Code Reasoning (with input/output):**  If explaining internal logic, provide example input and expected output.
4. **Command-Line Argument Handling:**  Explain how any command-line arguments are processed.
5. **Common Mistakes:** Point out common errors users might make.

Let's break down the code section by section and identify the key functionalities:

* **Package and Imports:** The code belongs to the `mime/multipart` package and imports several standard Go libraries related to I/O, text processing, and MIME. This immediately indicates it's involved in handling MIME multipart data.
* **Constants and Variables:** `peekBufferSize`, `emptyParams`. `peekBufferSize` is likely used for buffered reading, and `emptyParams` for default values.
* **`Part` Struct:** This represents a single part within a multipart message. It contains fields for headers, the parent reader, content disposition information, and an `io.Reader` for the part's body.
* **`Part` Methods:**
    * `FormName()`: Extracts the "name" parameter from the "Content-Disposition" header if it's "form-data".
    * `FileName()`: Extracts the "filename" parameter from the "Content-Disposition" header, applying `filepath.Base`.
    * `parseContentDisposition()`: Parses the "Content-Disposition" header.
    * `Read()`: Reads the body of the part, handling potential content transfer encoding.
    * `Close()`: Discards the remaining content of the part.
* **`NewReader()` Function:** Creates a new `Reader` to parse a multipart body, taking an `io.Reader` and the boundary string as input.
* **`stickyErrorReader` Struct:** A helper struct to prevent further reads after an error. This is a detail of the implementation to handle the nuances of the `io.Reader` interface.
* **`newPart()` Function:** Creates a new `Part` object, populating its headers and setting up the reader based on whether raw content is requested.
* **`populateHeaders()` Function:** Reads and parses the headers of a part.
* **`partReader` Struct:**  An `io.Reader` implementation specifically for reading the raw bytes of a part.
* **`partReader.Read()` Function:**  The core logic for reading the part's body while respecting the boundaries. This includes the `scanUntilBoundary` function.
* **`scanUntilBoundary()` Function:**  The crucial function for identifying the boundary between parts within the data stream.
* **`matchAfterPrefix()` Function:** A helper for `scanUntilBoundary` to determine if a sequence matches the boundary.
* **`Reader` Struct:**  The main struct for iterating over parts in a multipart body. It holds the `bufio.Reader`, boundary information, and state related to the parsing process.
* **Global Variables for Limits:** `maxMIMEHeaderSize`, `multipartmaxheaders`. These indicate built-in protections against excessively large or complex multipart messages, configurable via `GODEBUG`.
* **`maxMIMEHeaders()` Function:**  Retrieves the maximum number of headers, respecting the `GODEBUG` setting.
* **`NextPart()` Function:** Returns the next part in the multipart, handling "quoted-printable" encoding.
* **`NextRawPart()` Function:** Returns the next part without special handling for "quoted-printable".
* **`nextPart()` Function:** The internal implementation for retrieving the next part, handling boundary detection and part creation.
* **Boundary Detection Functions:** `isFinalBoundary()`, `isBoundaryDelimiterLine()`. These functions are critical for correctly identifying the start and end of parts.
* **`skipLWSPChar()` Function:**  A utility function for skipping whitespace.

**High-Level Functionality:** The code implements a parser for MIME multipart encoded data, allowing users to iterate through individual parts, access their headers, and read their content.

**Go Feature:** The core Go feature being implemented is the parsing and handling of data streams, particularly related to network protocols like HTTP where multipart encoding is common for file uploads and complex form submissions. The use of `io.Reader` and `bufio.Reader` is central to this.

**Command-Line Arguments (GODEBUG):** The code uses `internal/godebug` to allow users to adjust limits via environment variables. This needs to be explained clearly.

**Common Mistakes:**  Thinking about how users might misuse the API, like not handling `io.EOF` or misinterpreting the role of `NextPart` vs. `NextRawPart`.
这个Go语言代码片段是 `mime/multipart` 包的一部分，它实现了 **MIME multipart 数据的解析功能**，符合 RFC 2046 规范。更具体地说，它提供了处理由 HTTP（RFC 2388）以及常见浏览器生成的 multipart 消息体的能力。

以下是代码片段的主要功能：

1. **定义了 `Part` 结构体:** `Part` 结构体代表了 multipart 消息体中的一个单独的部分。它包含了该部分的头部信息 (`Header`)、读取器 (`mr` 和 `r`)，以及用于跟踪读取状态的字段。
2. **提供了获取部分信息的便捷方法:**
    *   `FormName()`: 如果该部分的 `Content-Disposition` 头部类型为 "form-data"，则返回其 "name" 参数值。
    *   `FileName()`: 返回该部分的 `Content-Disposition` 头部中的 "filename" 参数值，并使用 `filepath.Base` 进行处理以去除路径信息。
    *   `parseContentDisposition()`: 解析 `Content-Disposition` 头部，提取类型和参数。
3. **提供了创建 `Reader` 的方法:** `NewReader()` 函数用于创建一个新的 `Reader`，它可以从给定的 `io.Reader` 中读取数据，并使用提供的边界字符串来分隔不同的部分。
4. **实现了 `stickyErrorReader` 类型:**  这是一个内部辅助类型，用于包装底层的 `io.Reader`。它的作用是，一旦遇到读取错误，就停止从底层读取器读取数据，避免后续的 `Read` 调用出现未定义的行为。
5. **提供了创建 `Part` 的方法:** `newPart()` 函数用于创建一个新的 `Part` 结构体，并读取和解析该部分的头部信息。它还根据 `Content-Transfer-Encoding` 头部来选择是否需要对内容进行解码 (例如，对于 "quoted-printable" 编码)。
6. **实现了 `Part` 的读取功能:** `Part` 结构体的 `Read()` 方法用于读取该部分的内容。它实际上是通过 `partReader` 来实现的，该读取器会处理边界的检测。
7. **实现了 `partReader` 类型:**  这是一个实现了 `io.Reader` 接口的类型，专门用于读取 `Part` 的原始字节流，不进行任何传输编码的解码。
8. **实现了边界扫描逻辑:** `scanUntilBoundary()` 函数是核心逻辑，用于在数据流中查找 multipart 边界。它会判断哪些数据属于当前部分的内容，哪些是下一个部分的开始或结束边界。
9. **定义了 `Reader` 结构体:** `Reader` 结构体是用于迭代 multipart 消息体的核心类型。它维护了读取器的状态、边界信息等。
10. **设置了处理限制:**  定义了 `maxMIMEHeaderSize` 常量和 `multipartmaxheaders` 变量，用于限制 MIME 头部的大小和数量，以防止恶意输入。可以通过 `GODEBUG` 环境变量进行调整。
11. **提供了迭代 `Part` 的方法:**
    *   `NextPart()`: 返回 multipart 中的下一个部分。如果 `Content-Transfer-Encoding` 为 "quoted-printable"，则会自动进行解码。
    *   `NextRawPart()`: 返回 multipart 中的下一个部分，但不进行任何内容解码。
    *   `nextPart()`: 是 `NextPart` 和 `NextRawPart` 的内部实现，负责实际的边界查找、部分创建和头部解析。
12. **实现了边界检测逻辑:** `isFinalBoundary()` 和 `isBoundaryDelimiterLine()` 函数用于判断当前读取的行是否为最终边界或者部分分隔符边界。
13. **提供了跳过空白字符的辅助函数:** `skipLWSPChar()` 用于跳过行首的空格和制表符。

**Go 语言功能实现示例：**

这个代码片段实现了 **MIME multipart 数据的解析** 功能。在 Web 开发中，这通常用于处理包含文件上传的表单数据。

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

func main() {
	// 模拟一个 multipart 表单数据
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	// 添加一个文本字段
	bodyWriter.WriteField("name", "John Doe")

	// 添加一个文件字段
	fileWriter, err := bodyWriter.CreateFormFile("avatar", "avatar.png")
	if err != nil {
		fmt.Println("error creating form file:", err)
		return
	}
	fileContent := []byte("This is the content of the avatar file.")
	fileWriter.Write(fileContent)

	bodyWriter.Close()

	// 获取 Content-Type，其中包含 boundary
	contentType := bodyWriter.FormDataContentType()

	// 创建一个 io.Reader 用于模拟请求体
	bodyReader := bytes.NewReader(bodyBuf.Bytes())

	// 创建 multipart.Reader
	mr := multipart.NewReader(bodyReader, contentType[len("multipart/form-data; boundary="):])

	// 循环读取 parts
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break // 没有更多 part 了
		}
		if err != nil {
			fmt.Println("error reading part:", err)
			return
		}

		fmt.Printf("Part Name: %q\n", part.FormName())
		fmt.Printf("Part Filename: %q\n", part.FileName())
		fmt.Printf("Part Header: %+v\n", part.Header)

		partContent, _ := io.ReadAll(part)
		fmt.Printf("Part Content: %s\n", string(partContent))
		fmt.Println("---")
	}
}
```

**假设的输入与输出：**

**输入 (模拟的 multipart 表单数据):**

```
--your_boundary
Content-Disposition: form-data; name="name"

John Doe
--your_boundary
Content-Disposition: form-data; name="avatar"; filename="avatar.png"
Content-Type: application/octet-stream

This is the content of the avatar file.
--your_boundary--
```

**输出:**

```
Part Name: "name"
Part Filename: ""
Part Header: map[Content-Disposition:[form-data; name="name"]]
Part Content: John Doe
---
Part Name: "avatar"
Part Filename: "avatar.png"
Part Header: map[Content-Disposition:[form-data; name="avatar"; filename="avatar.png"] Content-Type:[application/octet-stream]]
Part Content: This is the content of the avatar file.
---
```

**命令行参数的具体处理：**

该代码片段本身不直接处理命令行参数。但是，它使用了 `internal/godebug` 包来允许通过 **`GODEBUG` 环境变量** 来调整某些限制。

*   **`GODEBUG=multipartmaxheaders=<values>`:**  设置每个 part 中允许的最大头部数量，以及 `ReadForm` 方法中所有 `FileHeader` 的总头部数量上限。例如，`GODEBUG=multipartmaxheaders=5000` 将最大头部数量设置为 5000。
*   **`GODEBUG=multipartmaxparts=<value>`:** (虽然这段代码中没有直接体现，但在 `multipart` 包的其他部分可能会有) 设置 `ReadForm` 方法中允许的最大 part 数量。

这些环境变量需要在程序运行前设置，例如：

```bash
export GODEBUG=multipartmaxheaders=5000
go run your_program.go
```

**使用者易犯错的点：**

1. **未正确处理 `io.EOF`:** 在使用 `Reader.NextPart()` 或 `Reader.NextRawPart()` 循环读取 parts 时，需要检查返回的错误是否为 `io.EOF`，以判断是否已经读取完所有部分。没有正确处理 `io.EOF` 可能导致无限循环。

    ```go
    mr := multipart.NewReader(bodyReader, boundary)
    for {
        part, err := mr.NextPart()
        if err == io.EOF { // 正确处理 EOF
            break
        }
        if err != nil {
            // 处理其他错误
            fmt.Println("Error:", err)
            return
        }
        // ... 处理 part
    }
    ```

2. **混淆 `NextPart()` 和 `NextRawPart()`:**  `NextPart()` 会自动处理 "quoted-printable" 编码，而 `NextRawPart()` 不会。如果发送方使用了 "quoted-printable" 编码，但接收方使用了 `NextRawPart()`，则读取到的内容将是编码后的原始数据，而不是解码后的数据。

    ```go
    // 如果知道内容可能使用了 quoted-printable 编码
    part, err := mr.NextPart()

    // 如果需要读取原始编码的数据
    part, err := mr.NextRawPart()
    ```

3. **没有完全读取 Part 的内容:** 在调用 `NextPart()` 获取到一个 `Part` 后，需要读取该 `Part` 的内容。如果没有完全读取内容就调用 `NextPart()` 获取下一个 `Part`，可能会导致数据丢失或解析错误，因为底层的 `bufio.Reader` 可能还没有完全读取当前 `Part` 的内容。可以使用 `io.Copy(io.Discard, part)` 来丢弃 `Part` 的剩余内容。

    ```go
    part, err := mr.NextPart()
    if err == nil {
        // ... 处理 Part 的头部
        content, _ := io.ReadAll(part) // 完全读取 Part 的内容
        fmt.Println("Part Content:", string(content))
    }
    ```

4. **错误地构造或解析 `Content-Type` 头部:**  `multipart.NewReader` 需要正确的边界字符串。这个边界字符串通常是从 `Content-Type` 头部中提取的。如果 `Content-Type` 头部格式错误或者边界提取不正确，会导致解析失败。

    ```go
    contentType := r.Header.Get("Content-Type")
    _, params, err := mime.ParseMediaType(contentType)
    if err != nil {
        // 处理 Content-Type 解析错误
        return
    }
    boundary, ok := params["boundary"]
    if !ok {
        // 处理缺少 boundary 的情况
        return
    }
    mr := multipart.NewReader(r.Body, boundary)
    ```

Prompt: 
```
这是路径为go/src/mime/multipart/multipart.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

/*
Package multipart implements MIME multipart parsing, as defined in RFC
2046.

The implementation is sufficient for HTTP (RFC 2388) and the multipart
bodies generated by popular browsers.

# Limits

To protect against malicious inputs, this package sets limits on the size
of the MIME data it processes.

[Reader.NextPart] and [Reader.NextRawPart] limit the number of headers in a
part to 10000 and [Reader.ReadForm] limits the total number of headers in all
FileHeaders to 10000.
These limits may be adjusted with the GODEBUG=multipartmaxheaders=<values>
setting.

Reader.ReadForm further limits the number of parts in a form to 1000.
This limit may be adjusted with the GODEBUG=multipartmaxparts=<value>
setting.
*/
package multipart

import (
	"bufio"
	"bytes"
	"fmt"
	"internal/godebug"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"
)

var emptyParams = make(map[string]string)

// This constant needs to be at least 76 for this package to work correctly.
// This is because \r\n--separator_of_len_70- would fill the buffer and it
// wouldn't be safe to consume a single byte from it.
const peekBufferSize = 4096

// A Part represents a single part in a multipart body.
type Part struct {
	// The headers of the body, if any, with the keys canonicalized
	// in the same fashion that the Go http.Request headers are.
	// For example, "foo-bar" changes case to "Foo-Bar"
	Header textproto.MIMEHeader

	mr *Reader

	disposition       string
	dispositionParams map[string]string

	// r is either a reader directly reading from mr, or it's a
	// wrapper around such a reader, decoding the
	// Content-Transfer-Encoding
	r io.Reader

	n       int   // known data bytes waiting in mr.bufReader
	total   int64 // total data bytes read already
	err     error // error to return when n == 0
	readErr error // read error observed from mr.bufReader
}

// FormName returns the name parameter if p has a Content-Disposition
// of type "form-data".  Otherwise it returns the empty string.
func (p *Part) FormName() string {
	// See https://tools.ietf.org/html/rfc2183 section 2 for EBNF
	// of Content-Disposition value format.
	if p.dispositionParams == nil {
		p.parseContentDisposition()
	}
	if p.disposition != "form-data" {
		return ""
	}
	return p.dispositionParams["name"]
}

// FileName returns the filename parameter of the [Part]'s Content-Disposition
// header. If not empty, the filename is passed through filepath.Base (which is
// platform dependent) before being returned.
func (p *Part) FileName() string {
	if p.dispositionParams == nil {
		p.parseContentDisposition()
	}
	filename := p.dispositionParams["filename"]
	if filename == "" {
		return ""
	}
	// RFC 7578, Section 4.2 requires that if a filename is provided, the
	// directory path information must not be used.
	return filepath.Base(filename)
}

func (p *Part) parseContentDisposition() {
	v := p.Header.Get("Content-Disposition")
	var err error
	p.disposition, p.dispositionParams, err = mime.ParseMediaType(v)
	if err != nil {
		p.dispositionParams = emptyParams
	}
}

// NewReader creates a new multipart [Reader] reading from r using the
// given MIME boundary.
//
// The boundary is usually obtained from the "boundary" parameter of
// the message's "Content-Type" header. Use [mime.ParseMediaType] to
// parse such headers.
func NewReader(r io.Reader, boundary string) *Reader {
	b := []byte("\r\n--" + boundary + "--")
	return &Reader{
		bufReader:        bufio.NewReaderSize(&stickyErrorReader{r: r}, peekBufferSize),
		nl:               b[:2],
		nlDashBoundary:   b[:len(b)-2],
		dashBoundaryDash: b[2:],
		dashBoundary:     b[2 : len(b)-2],
	}
}

// stickyErrorReader is an io.Reader which never calls Read on its
// underlying Reader once an error has been seen. (the io.Reader
// interface's contract promises nothing about the return values of
// Read calls after an error, yet this package does do multiple Reads
// after error)
type stickyErrorReader struct {
	r   io.Reader
	err error
}

func (r *stickyErrorReader) Read(p []byte) (n int, _ error) {
	if r.err != nil {
		return 0, r.err
	}
	n, r.err = r.r.Read(p)
	return n, r.err
}

func newPart(mr *Reader, rawPart bool, maxMIMEHeaderSize, maxMIMEHeaders int64) (*Part, error) {
	bp := &Part{
		Header: make(map[string][]string),
		mr:     mr,
	}
	if err := bp.populateHeaders(maxMIMEHeaderSize, maxMIMEHeaders); err != nil {
		return nil, err
	}
	bp.r = partReader{bp}

	// rawPart is used to switch between Part.NextPart and Part.NextRawPart.
	if !rawPart {
		const cte = "Content-Transfer-Encoding"
		if strings.EqualFold(bp.Header.Get(cte), "quoted-printable") {
			bp.Header.Del(cte)
			bp.r = quotedprintable.NewReader(bp.r)
		}
	}
	return bp, nil
}

func (p *Part) populateHeaders(maxMIMEHeaderSize, maxMIMEHeaders int64) error {
	r := textproto.NewReader(p.mr.bufReader)
	header, err := readMIMEHeader(r, maxMIMEHeaderSize, maxMIMEHeaders)
	if err == nil {
		p.Header = header
	}
	// TODO: Add a distinguishable error to net/textproto.
	if err != nil && err.Error() == "message too large" {
		err = ErrMessageTooLarge
	}
	return err
}

// Read reads the body of a part, after its headers and before the
// next part (if any) begins.
func (p *Part) Read(d []byte) (n int, err error) {
	return p.r.Read(d)
}

// partReader implements io.Reader by reading raw bytes directly from the
// wrapped *Part, without doing any Transfer-Encoding decoding.
type partReader struct {
	p *Part
}

func (pr partReader) Read(d []byte) (int, error) {
	p := pr.p
	br := p.mr.bufReader

	// Read into buffer until we identify some data to return,
	// or we find a reason to stop (boundary or read error).
	for p.n == 0 && p.err == nil {
		peek, _ := br.Peek(br.Buffered())
		p.n, p.err = scanUntilBoundary(peek, p.mr.dashBoundary, p.mr.nlDashBoundary, p.total, p.readErr)
		if p.n == 0 && p.err == nil {
			// Force buffered I/O to read more into buffer.
			_, p.readErr = br.Peek(len(peek) + 1)
			if p.readErr == io.EOF {
				p.readErr = io.ErrUnexpectedEOF
			}
		}
	}

	// Read out from "data to return" part of buffer.
	if p.n == 0 {
		return 0, p.err
	}
	n := len(d)
	if n > p.n {
		n = p.n
	}
	n, _ = br.Read(d[:n])
	p.total += int64(n)
	p.n -= n
	if p.n == 0 {
		return n, p.err
	}
	return n, nil
}

// scanUntilBoundary scans buf to identify how much of it can be safely
// returned as part of the Part body.
// dashBoundary is "--boundary".
// nlDashBoundary is "\r\n--boundary" or "\n--boundary", depending on what mode we are in.
// The comments below (and the name) assume "\n--boundary", but either is accepted.
// total is the number of bytes read out so far. If total == 0, then a leading "--boundary" is recognized.
// readErr is the read error, if any, that followed reading the bytes in buf.
// scanUntilBoundary returns the number of data bytes from buf that can be
// returned as part of the Part body and also the error to return (if any)
// once those data bytes are done.
func scanUntilBoundary(buf, dashBoundary, nlDashBoundary []byte, total int64, readErr error) (int, error) {
	if total == 0 {
		// At beginning of body, allow dashBoundary.
		if bytes.HasPrefix(buf, dashBoundary) {
			switch matchAfterPrefix(buf, dashBoundary, readErr) {
			case -1:
				return len(dashBoundary), nil
			case 0:
				return 0, nil
			case +1:
				return 0, io.EOF
			}
		}
		if bytes.HasPrefix(dashBoundary, buf) {
			return 0, readErr
		}
	}

	// Search for "\n--boundary".
	if i := bytes.Index(buf, nlDashBoundary); i >= 0 {
		switch matchAfterPrefix(buf[i:], nlDashBoundary, readErr) {
		case -1:
			return i + len(nlDashBoundary), nil
		case 0:
			return i, nil
		case +1:
			return i, io.EOF
		}
	}
	if bytes.HasPrefix(nlDashBoundary, buf) {
		return 0, readErr
	}

	// Otherwise, anything up to the final \n is not part of the boundary
	// and so must be part of the body.
	// Also if the section from the final \n onward is not a prefix of the boundary,
	// it too must be part of the body.
	i := bytes.LastIndexByte(buf, nlDashBoundary[0])
	if i >= 0 && bytes.HasPrefix(nlDashBoundary, buf[i:]) {
		return i, nil
	}
	return len(buf), readErr
}

// matchAfterPrefix checks whether buf should be considered to match the boundary.
// The prefix is "--boundary" or "\r\n--boundary" or "\n--boundary",
// and the caller has verified already that bytes.HasPrefix(buf, prefix) is true.
//
// matchAfterPrefix returns +1 if the buffer does match the boundary,
// meaning the prefix is followed by a double dash, space, tab, cr, nl,
// or end of input.
// It returns -1 if the buffer definitely does NOT match the boundary,
// meaning the prefix is followed by some other character.
// For example, "--foobar" does not match "--foo".
// It returns 0 more input needs to be read to make the decision,
// meaning that len(buf) == len(prefix) and readErr == nil.
func matchAfterPrefix(buf, prefix []byte, readErr error) int {
	if len(buf) == len(prefix) {
		if readErr != nil {
			return +1
		}
		return 0
	}
	c := buf[len(prefix)]

	if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
		return +1
	}

	// Try to detect boundaryDash
	if c == '-' {
		if len(buf) == len(prefix)+1 {
			if readErr != nil {
				// Prefix + "-" does not match
				return -1
			}
			return 0
		}
		if buf[len(prefix)+1] == '-' {
			return +1
		}
	}

	return -1
}

func (p *Part) Close() error {
	io.Copy(io.Discard, p)
	return nil
}

// Reader is an iterator over parts in a MIME multipart body.
// Reader's underlying parser consumes its input as needed. Seeking
// isn't supported.
type Reader struct {
	bufReader *bufio.Reader
	tempDir   string // used in tests

	currentPart *Part
	partsRead   int

	nl               []byte // "\r\n" or "\n" (set after seeing first boundary line)
	nlDashBoundary   []byte // nl + "--boundary"
	dashBoundaryDash []byte // "--boundary--"
	dashBoundary     []byte // "--boundary"
}

// maxMIMEHeaderSize is the maximum size of a MIME header we will parse,
// including header keys, values, and map overhead.
const maxMIMEHeaderSize = 10 << 20

// multipartmaxheaders is the maximum number of header entries NextPart will return,
// as well as the maximum combined total of header entries Reader.ReadForm will return
// in FileHeaders.
var multipartmaxheaders = godebug.New("multipartmaxheaders")

func maxMIMEHeaders() int64 {
	if s := multipartmaxheaders.Value(); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil && v >= 0 {
			multipartmaxheaders.IncNonDefault()
			return v
		}
	}
	return 10000
}

// NextPart returns the next part in the multipart or an error.
// When there are no more parts, the error [io.EOF] is returned.
//
// As a special case, if the "Content-Transfer-Encoding" header
// has a value of "quoted-printable", that header is instead
// hidden and the body is transparently decoded during Read calls.
func (r *Reader) NextPart() (*Part, error) {
	return r.nextPart(false, maxMIMEHeaderSize, maxMIMEHeaders())
}

// NextRawPart returns the next part in the multipart or an error.
// When there are no more parts, the error [io.EOF] is returned.
//
// Unlike [Reader.NextPart], it does not have special handling for
// "Content-Transfer-Encoding: quoted-printable".
func (r *Reader) NextRawPart() (*Part, error) {
	return r.nextPart(true, maxMIMEHeaderSize, maxMIMEHeaders())
}

func (r *Reader) nextPart(rawPart bool, maxMIMEHeaderSize, maxMIMEHeaders int64) (*Part, error) {
	if r.currentPart != nil {
		r.currentPart.Close()
	}
	if string(r.dashBoundary) == "--" {
		return nil, fmt.Errorf("multipart: boundary is empty")
	}
	expectNewPart := false
	for {
		line, err := r.bufReader.ReadSlice('\n')

		if err == io.EOF && r.isFinalBoundary(line) {
			// If the buffer ends in "--boundary--" without the
			// trailing "\r\n", ReadSlice will return an error
			// (since it's missing the '\n'), but this is a valid
			// multipart EOF so we need to return io.EOF instead of
			// a fmt-wrapped one.
			return nil, io.EOF
		}
		if err != nil {
			return nil, fmt.Errorf("multipart: NextPart: %w", err)
		}

		if r.isBoundaryDelimiterLine(line) {
			r.partsRead++
			bp, err := newPart(r, rawPart, maxMIMEHeaderSize, maxMIMEHeaders)
			if err != nil {
				return nil, err
			}
			r.currentPart = bp
			return bp, nil
		}

		if r.isFinalBoundary(line) {
			// Expected EOF
			return nil, io.EOF
		}

		if expectNewPart {
			return nil, fmt.Errorf("multipart: expecting a new Part; got line %q", string(line))
		}

		if r.partsRead == 0 {
			// skip line
			continue
		}

		// Consume the "\n" or "\r\n" separator between the
		// body of the previous part and the boundary line we
		// now expect will follow. (either a new part or the
		// end boundary)
		if bytes.Equal(line, r.nl) {
			expectNewPart = true
			continue
		}

		return nil, fmt.Errorf("multipart: unexpected line in Next(): %q", line)
	}
}

// isFinalBoundary reports whether line is the final boundary line
// indicating that all parts are over.
// It matches `^--boundary--[ \t]*(\r\n)?$`
func (r *Reader) isFinalBoundary(line []byte) bool {
	if !bytes.HasPrefix(line, r.dashBoundaryDash) {
		return false
	}
	rest := line[len(r.dashBoundaryDash):]
	rest = skipLWSPChar(rest)
	return len(rest) == 0 || bytes.Equal(rest, r.nl)
}

func (r *Reader) isBoundaryDelimiterLine(line []byte) (ret bool) {
	// https://tools.ietf.org/html/rfc2046#section-5.1
	//   The boundary delimiter line is then defined as a line
	//   consisting entirely of two hyphen characters ("-",
	//   decimal value 45) followed by the boundary parameter
	//   value from the Content-Type header field, optional linear
	//   whitespace, and a terminating CRLF.
	if !bytes.HasPrefix(line, r.dashBoundary) {
		return false
	}
	rest := line[len(r.dashBoundary):]
	rest = skipLWSPChar(rest)

	// On the first part, see our lines are ending in \n instead of \r\n
	// and switch into that mode if so. This is a violation of the spec,
	// but occurs in practice.
	if r.partsRead == 0 && len(rest) == 1 && rest[0] == '\n' {
		r.nl = r.nl[1:]
		r.nlDashBoundary = r.nlDashBoundary[1:]
	}
	return bytes.Equal(rest, r.nl)
}

// skipLWSPChar returns b with leading spaces and tabs removed.
// RFC 822 defines:
//
//	LWSP-char = SPACE / HTAB
func skipLWSPChar(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

"""



```