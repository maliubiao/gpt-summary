Response:
Let's break down the thought process for analyzing the provided Go code snippet for `multipart_test.go`.

1. **Understand the Goal:** The core goal is to analyze a Go test file related to the `mime/multipart` package. We need to identify what functionalities are being tested and how. The request specifically asks for the functionalities being *tested*, not necessarily all the internal workings of the `multipart` package itself.

2. **Initial Scan for Key Structures:**  A quick scan reveals several top-level function definitions starting with `Test`. This immediately tells us these are test functions using the `testing` package. This is the primary focus for understanding the code's purpose.

3. **Analyze Individual Test Functions:**  Go through each `Test` function, one by one, to understand its specific purpose:

    * **`TestBoundaryLine`:** This seems to test a function called `isBoundaryDelimiterLine`. It provides different byte slices and checks if they are correctly identified as boundary lines based on a predefined boundary string ("myBoundary").

    * **`TestNameAccessors`:** This test deals with accessing information from the `Content-Disposition` header within a multipart part. It checks the `FormName()` and `FileName()` methods.

    * **`TestMultipart`:** This is a more complex test. It uses a predefined `testMultipartBody` string and calls another function `testMultipart`. It appears to test the basic parsing of a multipart body with `\r\n` line endings.

    * **`TestMultipartOnlyNewlines`:** Similar to `TestMultipart`, but it uses `\n` as line endings, suggesting it's testing how the parser handles different newline conventions.

    * **`TestMultipartSlowInput`:** This test introduces a `slowReader`, indicating it's testing how the parser handles input that arrives in small chunks.

    * **`testMultipart`:** This is the worker function called by the previous `TestMultipart` functions. It uses `NewReader` to create a `multipart.Reader` and then iterates through the parts using `NextPart()`, verifying headers and content.

    * **`TestVariousTextLineEndings`:** This test has a loop iterating through different ways of representing line endings within the content of a multipart part.

    * **`TestLineLimit`:** This test uses a `maliciousReader` which potentially reads a lot of data and seems to be testing some kind of limit on the size of a line or header.

    * **`TestMultipartTruncated`:**  This test provides truncated multipart bodies and checks if the parser correctly reports an `io.ErrUnexpectedEOF` error.

    * **`TestMultipartStreamReadahead`:** This test uses a `sentinelReader` and aims to verify that the parser doesn't block when reading past the end of a part, relevant for streaming scenarios.

    * **`TestLineContinuation`:** This test specifically deals with parsing headers that span multiple lines using line continuation (indentation).

    * **`TestQuotedPrintableEncoding`:**  This test focuses on handling `quoted-printable` encoding in multipart parts, testing both uppercase and lowercase variants of the encoding name.

    * **`TestRawPart`:** This test introduces `NextRawPart()`, suggesting it tests the ability to get a part's content without automatic decoding (like quoted-printable).

    * **`TestNested`:**  This test reads data from a file ("nested-mime") and checks the parsing of nested multipart structures.

    * **`TestParse`:** This test uses a `parseTests` slice which defines various multipart bodies and their expected parsed structure. It's a more comprehensive test of the core parsing logic.

    * **`TestParseAllSizes`:**  This test iterates through different sizes of part content to ensure the parser works correctly with varying data lengths.

    * **`TestNoBoundary`:**  A simple test to check the error handling when no boundary is provided.

4. **Identify Key Functionalities and Corresponding Code Examples:** Based on the analysis of the test functions, we can extract the key functionalities being tested and provide code examples. For example, `TestBoundaryLine` directly shows how boundary lines are recognized. `TestNameAccessors` demonstrates how to get the form name and filename. The `TestMultipart` family of functions demonstrates the core parsing process.

5. **Infer Go Language Features:**  We can infer that the code tests features related to:

    * **Parsing multipart data:**  This is the central theme.
    * **Handling different line endings:** Demonstrated by `TestMultipartOnlyNewlines` and `TestVariousTextLineEndings`.
    * **Accessing header information:** Shown in `TestNameAccessors` and throughout other tests.
    * **Handling different content transfer encodings:** Explicitly tested by `TestQuotedPrintableEncoding` and `TestRawPart`.
    * **Handling nested multipart structures:** Covered by `TestNested`.
    * **Error handling:** Seen in `TestMultipartTruncated` and `TestNoBoundary`.
    * **Streaming input:**  Touched upon by `TestMultipartSlowInput` and `TestMultipartStreamReadahead`.

6. **Code Examples and Explanations:** For each identified functionality, construct a simple Go code example. This involves:

    * Creating a sample multipart body string.
    * Using `NewReader` with the appropriate boundary.
    * Calling `NextPart()` to iterate through parts.
    * Accessing headers and reading the body of each part.

7. **Input and Output Examples:** For code examples involving parsing, it's useful to provide the input multipart body and the expected output (the parsed parts with their headers and bodies).

8. **Command-Line Arguments (If Applicable):**  In this specific code, there are no explicit command-line arguments being processed. The tests are driven by the internal logic and predefined data.

9. **Common Mistakes:** Think about potential pitfalls when *using* the `mime/multipart` package. For example, using the wrong boundary, not handling errors correctly, or misunderstanding how different content transfer encodings are handled.

10. **Structure and Language:** Organize the answer clearly using headings and bullet points. Use precise and concise language. Explain technical terms where necessary. Since the request was in Chinese, the answer should also be in Chinese.

11. **Review and Refine:** After drafting the answer, review it to ensure accuracy, completeness, and clarity. Check if all aspects of the prompt have been addressed.

By following these steps, we can systematically analyze the provided Go code snippet and generate a comprehensive and informative answer. The process involves understanding the code's purpose, identifying the functionalities being tested, inferring the underlying Go language features, and providing illustrative examples.
这段代码是 Go 语言标准库 `mime/multipart` 包的一部分，专门用于测试 `multipart` 包的功能。 它的主要功能可以归纳为以下几点：

1. **测试边界线识别 (`TestBoundaryLine`)**:
   - 验证 `Reader` 结构体的 `isBoundaryDelimiterLine` 方法是否能正确识别 multipart 消息中的边界分隔符行。
   - 测试了不同形式的边界线，包括尾部有空格，以及不正确的边界线格式。

2. **测试访问 Part 的名称和文件名 (`TestNameAccessors`)**:
   - 验证 `Part` 结构体的 `FormName()` 和 `FileName()` 方法能否正确从 `Content-Disposition` header 中提取 `name` 和 `filename` 属性值。
   - 测试了 `Content-Disposition` header 中 `name` 和 `filename` 属性的不同表示形式和顺序。

3. **测试基本的 multipart 消息解析 (`TestMultipart`, `TestMultipartOnlyNewlines`, `TestMultipartSlowInput`, `testMultipart`)**:
   - 验证 `NewReader` 函数和 `Reader` 结构体的 `NextPart()` 方法能否正确解析包含多个 part 的 multipart 消息。
   - 测试了使用 `\r\n` 和 `\n` 作为行尾符的情况。
   - `TestMultipartSlowInput` 模拟了慢速读取输入流的情况，确保解析器能够正确处理。
   - `testMultipart` 是一个辅助测试函数，包含了具体的解析逻辑和断言。

4. **测试不同的文本行尾符 (`TestVariousTextLineEndings`)**:
   - 验证解析器能否处理 multipart part 中不同的文本行尾符，包括 `\n`, `\r\n`, `\r` 等。

5. **测试行长度限制 (`TestLineLimit`)**:
   - 验证解析器在遇到过长的行时是否会触发错误，防止资源消耗过多。
   - 使用 `maliciousReader` 模拟读取大量数据的场景。

6. **测试截断的 multipart 消息 (`TestMultipartTruncated`)**:
   - 验证解析器在遇到不完整的 multipart 消息时是否能正确返回 `io.ErrUnexpectedEOF` 错误。

7. **测试流式读取 multipart 消息 (`TestMultipartStreamReadahead`)**:
   - 验证 `PartReader` 不会在读取超出当前 part 结尾时阻塞，这对于处理像 `multipart/x-mixed-replace` 这样的流式 multipart 数据很重要。

8. **测试头部行的连续 (`TestLineContinuation`)**:
   - 验证解析器能否正确处理跨多行的 HTTP 头部。

9. **测试 Quoted-Printable 编码 (`TestQuotedPrintableEncoding`, `testQuotedPrintableEncoding`)**:
   - 验证解析器能否正确解码 `Content-Transfer-Encoding` 为 `quoted-printable` 的 part 的内容。

10. **测试原始 Part 读取 (`TestRawPart`)**:
    - 验证 `NextRawPart()` 方法可以获取未经任何解码的原始 part 内容。

11. **测试嵌套的 multipart 消息 (`TestNested`)**:
    - 验证解析器能否正确处理嵌套的 multipart 结构。

12. **更全面的解析测试用例 (`TestParse`)**:
    - 使用 `parseTests` 数组定义了各种复杂的 multipart 消息，并验证解析结果是否符合预期。 这些测试用例涵盖了各种边界情况，例如空 part，结尾为空，以及包含与边界相似内容的数据。

13. **测试不同大小的 Part 内容解析 (`TestParseAllSizes`)**:
    - 验证解析器能否处理不同大小的 part 内容，包括非常小和接近缓冲区大小的内容。

14. **测试没有边界的情况 (`TestNoBoundary`)**:
    - 验证在创建 `Reader` 时没有提供边界字符串时是否会返回正确的错误。

**它是什么 Go 语言功能的实现？**

这段代码主要是对 `mime/multipart` 包中 `Reader` 结构体的实现进行测试。`multipart` 包实现了 **解析 `multipart/form-data` 格式的数据** 的功能，这种格式常用于 HTTP 表单提交中上传文件等场景。

**Go 代码举例说明：**

假设我们有以下 multipart 消息：

```
--my-boundary
Content-Disposition: form-data; name="field1"

value1
--my-boundary
Content-Disposition: form-data; name="file1"; filename="test.txt"
Content-Type: text/plain

This is the content of the file.
--my-boundary--
```

我们可以使用 `multipart` 包的 `Reader` 来解析它：

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
)

func main() {
	body := `
--my-boundary
Content-Disposition: form-data; name="field1"

value1
--my-boundary
Content-Disposition: form-data; name="file1"; filename="test.txt"
Content-Type: text/plain

This is the content of the file.
--my-boundary--
`
	bodyReader := bytes.NewReader([]byte(body))
	boundary := "my-boundary"

	reader := multipart.NewReader(bodyReader, boundary)

	// 读取第一个 part
	part1, err := reader.NextPart()
	if err != nil {
		panic(err)
	}
	fmt.Println("Part 1 Header:", part1.Header)
	part1Content, err := io.ReadAll(part1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Part 1 Content: %s\n", part1Content)

	// 读取第二个 part
	part2, err := reader.NextPart()
	if err != nil {
		panic(err)
	}
	fmt.Println("Part 2 Header:", part2.Header)
	part2Content, err := io.ReadAll(part2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Part 2 Content: %s\n", part2Content)

	// 尝试读取下一个 part，应该返回 io.EOF
	part3, err := reader.NextPart()
	if err != io.EOF {
		fmt.Println("Expected io.EOF, but got:", err)
	}
	if part3 != nil {
		fmt.Println("Expected nil part, but got:", part3.Header)
	}
}
```

**假设的输入与输出：**

**输入 (即上面的 `body` 变量):**

```
--my-boundary
Content-Disposition: form-data; name="field1"

value1
--my-boundary
Content-Disposition: form-data; name="file1"; filename="test.txt"
Content-Type: text/plain

This is the content of the file.
--my-boundary--
```

**输出:**

```
Part 1 Header: map[Content-Disposition:[form-data; name="field1"]]
Part 1 Content: value1
Part 2 Header: map[Content-Disposition:[form-data; filename="test.txt"; name="file1"] Content-Type:[text/plain]]
Part 2 Content: This is the content of the file.
Expected io.EOF, but got: <nil>
Expected nil part, but got: <nil>
```

**命令行参数的具体处理：**

这段测试代码本身不涉及命令行参数的处理。它主要关注的是 `multipart` 包内部的逻辑。`multipart` 包在实际应用中，通常会处理 HTTP 请求的 `Body`，而 HTTP 请求的头信息（包括 `Content-Type` 中的 `boundary`）可能来自 HTTP 服务器或客户端的实现，但这部分不是由 `multipart` 包直接处理的命令行参数。

**使用者易犯错的点：**

1. **边界 (Boundary) 错误：**
   - **错误地指定边界字符串：**  如果传递给 `NewReader` 的边界字符串与实际 multipart 消息中的边界不一致，解析会失败。

     ```go
     // 错误的边界
     reader := multipart.NewReader(bodyReader, "wrong-boundary")
     part, err := reader.NextPart()
     // err 将会是 io.ErrUnexpectedEOF 或者其他错误，part 为 nil
     ```

2. **没有正确处理 `NextPart()` 返回的 `io.EOF`：**
   - `NextPart()` 在读取完所有 part 后会返回 `io.EOF`，表示没有更多 part 了。使用者需要正确处理这个错误来结束循环。

     ```go
     reader := multipart.NewReader(bodyReader, boundary)
     for {
         part, err := reader.NextPart()
         if err == io.EOF {
             break // 正确结束循环
         }
         if err != nil {
             // 处理其他错误
             panic(err)
         }
         // 处理 part
     }
     ```

3. **假设 Part 的顺序或存在性：**
   - 在处理 multipart 消息时，不能假设 part 的顺序或者一定会存在某些特定的 part。应该根据实际情况处理每个 part。

4. **忘记读取 Part 的内容：**
   - 调用 `NextPart()` 获取到 `Part` 结构体后，需要通过 `io.ReadAll(part)` 或其他 `io.Reader` 的方法读取 part 的内容。如果不读取，可能会导致后续的解析出现问题。

5. **处理嵌套的 Multipart 消息：**
   - 如果一个 Part 的 `Content-Type` 是 `multipart/*`，则需要递归地使用 `NewReader` 来解析这个嵌套的 multipart 消息。容易忘记处理嵌套的情况。

     ```go
     part, err := reader.NextPart()
     if err != nil {
         // ...
     }
     if strings.HasPrefix(part.Header.Get("Content-Type"), "multipart/") {
         nestedBoundary, _ := getBoundaryFromContentType(part.Header.Get("Content-Type"))
         nestedReader := multipart.NewReader(part, nestedBoundary)
         // 解析 nestedReader
     } else {
         // 处理非 multipart 的 part
     }
     ```

总而言之，这段测试代码覆盖了 `mime/multipart` 包中 `Reader` 类型的核心功能，确保了它能够正确解析各种格式和边界情况的 multipart 消息，为开发者使用这个包提供了信心保障。

Prompt: 
```
这是路径为go/src/mime/multipart/multipart_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package multipart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestBoundaryLine(t *testing.T) {
	mr := NewReader(strings.NewReader(""), "myBoundary")
	if !mr.isBoundaryDelimiterLine([]byte("--myBoundary\r\n")) {
		t.Error("expected")
	}
	if !mr.isBoundaryDelimiterLine([]byte("--myBoundary \r\n")) {
		t.Error("expected")
	}
	if !mr.isBoundaryDelimiterLine([]byte("--myBoundary \n")) {
		t.Error("expected")
	}
	if mr.isBoundaryDelimiterLine([]byte("--myBoundary bogus \n")) {
		t.Error("expected fail")
	}
	if mr.isBoundaryDelimiterLine([]byte("--myBoundary bogus--")) {
		t.Error("expected fail")
	}
}

func escapeString(v string) string {
	bytes, _ := json.Marshal(v)
	return string(bytes)
}

func expectEq(t *testing.T, expected, actual, what string) {
	if expected == actual {
		return
	}
	t.Errorf("Unexpected value for %s; got %s (len %d) but expected: %s (len %d)",
		what, escapeString(actual), len(actual), escapeString(expected), len(expected))
}

func TestNameAccessors(t *testing.T) {
	tests := [...][3]string{
		{`form-data; name="foo"`, "foo", ""},
		{` form-data ; name=foo`, "foo", ""},
		{`FORM-DATA;name="foo"`, "foo", ""},
		{` FORM-DATA ; name="foo"`, "foo", ""},
		{` FORM-DATA ; name="foo"`, "foo", ""},
		{` FORM-DATA ; name=foo`, "foo", ""},
		{` FORM-DATA ; filename="foo.txt"; name=foo; baz=quux`, "foo", "foo.txt"},
		{` not-form-data ; filename="bar.txt"; name=foo; baz=quux`, "", "bar.txt"},
	}
	for i, test := range tests {
		p := &Part{Header: make(map[string][]string)}
		p.Header.Set("Content-Disposition", test[0])
		if g, e := p.FormName(), test[1]; g != e {
			t.Errorf("test %d: FormName() = %q; want %q", i, g, e)
		}
		if g, e := p.FileName(), test[2]; g != e {
			t.Errorf("test %d: FileName() = %q; want %q", i, g, e)
		}
	}
}

var longLine = strings.Repeat("\n\n\r\r\r\n\r\000", (1<<20)/8)

func testMultipartBody(sep string) string {
	testBody := `
This is a multi-part message.  This line is ignored.
--MyBoundary
Header1: value1
HEADER2: value2
foo-bar: baz

My value
The end.
--MyBoundary
name: bigsection

[longline]
--MyBoundary
Header1: value1b
HEADER2: value2b
foo-bar: bazb

Line 1
Line 2
Line 3 ends in a newline, but just one.

--MyBoundary

never read data
--MyBoundary--


useless trailer
`
	testBody = strings.ReplaceAll(testBody, "\n", sep)
	return strings.Replace(testBody, "[longline]", longLine, 1)
}

func TestMultipart(t *testing.T) {
	bodyReader := strings.NewReader(testMultipartBody("\r\n"))
	testMultipart(t, bodyReader, false)
}

func TestMultipartOnlyNewlines(t *testing.T) {
	bodyReader := strings.NewReader(testMultipartBody("\n"))
	testMultipart(t, bodyReader, true)
}

func TestMultipartSlowInput(t *testing.T) {
	bodyReader := strings.NewReader(testMultipartBody("\r\n"))
	testMultipart(t, &slowReader{bodyReader}, false)
}

func testMultipart(t *testing.T, r io.Reader, onlyNewlines bool) {
	t.Parallel()
	reader := NewReader(r, "MyBoundary")
	buf := new(strings.Builder)

	// Part1
	part, err := reader.NextPart()
	if part == nil || err != nil {
		t.Error("Expected part1")
		return
	}
	if x := part.Header.Get("Header1"); x != "value1" {
		t.Errorf("part.Header.Get(%q) = %q, want %q", "Header1", x, "value1")
	}
	if x := part.Header.Get("foo-bar"); x != "baz" {
		t.Errorf("part.Header.Get(%q) = %q, want %q", "foo-bar", x, "baz")
	}
	if x := part.Header.Get("Foo-Bar"); x != "baz" {
		t.Errorf("part.Header.Get(%q) = %q, want %q", "Foo-Bar", x, "baz")
	}
	buf.Reset()
	if _, err := io.Copy(buf, part); err != nil {
		t.Errorf("part 1 copy: %v", err)
	}

	adjustNewlines := func(s string) string {
		if onlyNewlines {
			return strings.ReplaceAll(s, "\r\n", "\n")
		}
		return s
	}

	expectEq(t, adjustNewlines("My value\r\nThe end."), buf.String(), "Value of first part")

	// Part2
	part, err = reader.NextPart()
	if err != nil {
		t.Fatalf("Expected part2; got: %v", err)
		return
	}
	if e, g := "bigsection", part.Header.Get("name"); e != g {
		t.Errorf("part2's name header: expected %q, got %q", e, g)
	}
	buf.Reset()
	if _, err := io.Copy(buf, part); err != nil {
		t.Errorf("part 2 copy: %v", err)
	}
	s := buf.String()
	if len(s) != len(longLine) {
		t.Errorf("part2 body expected long line of length %d; got length %d",
			len(longLine), len(s))
	}
	if s != longLine {
		t.Errorf("part2 long body didn't match")
	}

	// Part3
	part, err = reader.NextPart()
	if part == nil || err != nil {
		t.Error("Expected part3")
		return
	}
	if part.Header.Get("foo-bar") != "bazb" {
		t.Error("Expected foo-bar: bazb")
	}
	buf.Reset()
	if _, err := io.Copy(buf, part); err != nil {
		t.Errorf("part 3 copy: %v", err)
	}
	expectEq(t, adjustNewlines("Line 1\r\nLine 2\r\nLine 3 ends in a newline, but just one.\r\n"),
		buf.String(), "body of part 3")

	// Part4
	part, err = reader.NextPart()
	if part == nil || err != nil {
		t.Error("Expected part 4 without errors")
		return
	}

	// Non-existent part5
	part, err = reader.NextPart()
	if part != nil {
		t.Error("Didn't expect a fifth part.")
	}
	if err != io.EOF {
		t.Errorf("On fifth part expected io.EOF; got %v", err)
	}
}

func TestVariousTextLineEndings(t *testing.T) {
	tests := [...]string{
		"Foo\nBar",
		"Foo\nBar\n",
		"Foo\r\nBar",
		"Foo\r\nBar\r\n",
		"Foo\rBar",
		"Foo\rBar\r",
		"\x00\x01\x02\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
	}

	for testNum, expectedBody := range tests {
		body := "--BOUNDARY\r\n" +
			"Content-Disposition: form-data; name=\"value\"\r\n" +
			"\r\n" +
			expectedBody +
			"\r\n--BOUNDARY--\r\n"
		bodyReader := strings.NewReader(body)

		reader := NewReader(bodyReader, "BOUNDARY")
		buf := new(bytes.Buffer)
		part, err := reader.NextPart()
		if part == nil {
			t.Errorf("Expected a body part on text %d", testNum)
			continue
		}
		if err != nil {
			t.Errorf("Unexpected error on text %d: %v", testNum, err)
			continue
		}
		written, err := io.Copy(buf, part)
		expectEq(t, expectedBody, buf.String(), fmt.Sprintf("test %d", testNum))
		if err != nil {
			t.Errorf("Error copying multipart; bytes=%v, error=%v", written, err)
		}

		part, err = reader.NextPart()
		if part != nil {
			t.Errorf("Unexpected part in test %d", testNum)
		}
		if err != io.EOF {
			t.Errorf("On test %d expected io.EOF; got %v", testNum, err)
		}

	}
}

type maliciousReader struct {
	t *testing.T
	n int
}

const maxReadThreshold = 1 << 20

func (mr *maliciousReader) Read(b []byte) (n int, err error) {
	mr.n += len(b)
	if mr.n >= maxReadThreshold {
		mr.t.Fatal("too much was read")
		return 0, io.EOF
	}
	return len(b), nil
}

func TestLineLimit(t *testing.T) {
	mr := &maliciousReader{t: t}
	r := NewReader(mr, "fooBoundary")
	part, err := r.NextPart()
	if part != nil {
		t.Errorf("unexpected part read")
	}
	if err == nil {
		t.Errorf("expected an error")
	}
	if mr.n >= maxReadThreshold {
		t.Errorf("expected to read < %d bytes; read %d", maxReadThreshold, mr.n)
	}
}

func TestMultipartTruncated(t *testing.T) {
	for _, body := range []string{
		`
This is a multi-part message.  This line is ignored.
--MyBoundary
foo-bar: baz

Oh no, premature EOF!
`,
		`
This is a multi-part message.  This line is ignored.
--MyBoundary
foo-bar: baz

Oh no, premature EOF!
--MyBoundary-`,
	} {
		body = strings.ReplaceAll(body, "\n", "\r\n")
		bodyReader := strings.NewReader(body)
		r := NewReader(bodyReader, "MyBoundary")

		part, err := r.NextPart()
		if err != nil {
			t.Fatalf("didn't get a part")
		}
		_, err = io.Copy(io.Discard, part)
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("expected error io.ErrUnexpectedEOF; got %v", err)
		}
	}
}

type slowReader struct {
	r io.Reader
}

func (s *slowReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return s.r.Read(p)
	}
	return s.r.Read(p[:1])
}

type sentinelReader struct {
	// done is closed when this reader is read from.
	done chan struct{}
}

func (s *sentinelReader) Read([]byte) (int, error) {
	if s.done != nil {
		close(s.done)
		s.done = nil
	}
	return 0, io.EOF
}

// TestMultipartStreamReadahead tests that PartReader does not block
// on reading past the end of a part, ensuring that it can be used on
// a stream like multipart/x-mixed-replace. See golang.org/issue/15431
func TestMultipartStreamReadahead(t *testing.T) {
	testBody1 := `
This is a multi-part message.  This line is ignored.
--MyBoundary
foo-bar: baz

Body
--MyBoundary
`
	testBody2 := `foo-bar: bop

Body 2
--MyBoundary--
`
	done1 := make(chan struct{})
	reader := NewReader(
		io.MultiReader(
			strings.NewReader(testBody1),
			&sentinelReader{done1},
			strings.NewReader(testBody2)),
		"MyBoundary")

	var i int
	readPart := func(hdr textproto.MIMEHeader, body string) {
		part, err := reader.NextPart()
		if part == nil || err != nil {
			t.Fatalf("Part %d: NextPart failed: %v", i, err)
		}

		if !reflect.DeepEqual(part.Header, hdr) {
			t.Errorf("Part %d: part.Header = %v, want %v", i, part.Header, hdr)
		}
		data, err := io.ReadAll(part)
		expectEq(t, body, string(data), fmt.Sprintf("Part %d body", i))
		if err != nil {
			t.Fatalf("Part %d: ReadAll failed: %v", i, err)
		}
		i++
	}

	readPart(textproto.MIMEHeader{"Foo-Bar": {"baz"}}, "Body")

	select {
	case <-done1:
		t.Errorf("Reader read past second boundary")
	default:
	}

	readPart(textproto.MIMEHeader{"Foo-Bar": {"bop"}}, "Body 2")
}

func TestLineContinuation(t *testing.T) {
	// This body, extracted from an email, contains headers that span multiple
	// lines.

	// TODO: The original mail ended with a double-newline before the
	// final delimiter; this was manually edited to use a CRLF.
	testBody :=
		"\n--Apple-Mail-2-292336769\nContent-Transfer-Encoding: 7bit\nContent-Type: text/plain;\n\tcharset=US-ASCII;\n\tdelsp=yes;\n\tformat=flowed\n\nI'm finding the same thing happening on my system (10.4.1).\n\n\n--Apple-Mail-2-292336769\nContent-Transfer-Encoding: quoted-printable\nContent-Type: text/html;\n\tcharset=ISO-8859-1\n\n<HTML><BODY>I'm finding the same thing =\nhappening on my system (10.4.1).=A0 But I built it with XCode =\n2.0.</BODY></=\nHTML>=\n\r\n--Apple-Mail-2-292336769--\n"

	r := NewReader(strings.NewReader(testBody), "Apple-Mail-2-292336769")

	for i := 0; i < 2; i++ {
		part, err := r.NextPart()
		if err != nil {
			t.Fatalf("didn't get a part")
		}
		var buf strings.Builder
		n, err := io.Copy(&buf, part)
		if err != nil {
			t.Errorf("error reading part: %v\nread so far: %q", err, buf.String())
		}
		if n <= 0 {
			t.Errorf("read %d bytes; expected >0", n)
		}
	}
}

func TestQuotedPrintableEncoding(t *testing.T) {
	for _, cte := range []string{"quoted-printable", "Quoted-PRINTABLE"} {
		t.Run(cte, func(t *testing.T) {
			testQuotedPrintableEncoding(t, cte)
		})
	}
}

func testQuotedPrintableEncoding(t *testing.T, cte string) {
	// From https://golang.org/issue/4411
	body := "--0016e68ee29c5d515f04cedf6733\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=text\r\nContent-Transfer-Encoding: " + cte + "\r\n\r\nwords words words words words words words words words words words words wor=\r\nds words words words words words words words words words words words words =\r\nwords words words words words words words words words words words words wor=\r\nds words words words words words words words words words words words words =\r\nwords words words words words words words words words\r\n--0016e68ee29c5d515f04cedf6733\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=submit\r\n\r\nSubmit\r\n--0016e68ee29c5d515f04cedf6733--"
	r := NewReader(strings.NewReader(body), "0016e68ee29c5d515f04cedf6733")
	part, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if te, ok := part.Header["Content-Transfer-Encoding"]; ok {
		t.Errorf("unexpected Content-Transfer-Encoding of %q", te)
	}
	var buf strings.Builder
	_, err = io.Copy(&buf, part)
	if err != nil {
		t.Error(err)
	}
	got := buf.String()
	want := "words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words words"
	if got != want {
		t.Errorf("wrong part value:\n got: %q\nwant: %q", got, want)
	}
}

func TestRawPart(t *testing.T) {
	// https://github.com/golang/go/issues/29090

	body := strings.Replace(`--0016e68ee29c5d515f04cedf6733
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello World.</div>
--0016e68ee29c5d515f04cedf6733
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello World.</div>
--0016e68ee29c5d515f04cedf6733--`, "\n", "\r\n", -1)

	r := NewReader(strings.NewReader(body), "0016e68ee29c5d515f04cedf6733")

	// This part is expected to be raw, bypassing the automatic handling
	// of quoted-printable.
	part, err := r.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := part.Header["Content-Transfer-Encoding"]; !ok {
		t.Errorf("missing Content-Transfer-Encoding")
	}
	var buf strings.Builder
	_, err = io.Copy(&buf, part)
	if err != nil {
		t.Error(err)
	}
	got := buf.String()
	// Data is still quoted-printable.
	want := `<div dir=3D"ltr">Hello World.</div>`
	if got != want {
		t.Errorf("wrong part value:\n got: %q\nwant: %q", got, want)
	}

	// This part is expected to have automatic decoding of quoted-printable.
	part, err = r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if te, ok := part.Header["Content-Transfer-Encoding"]; ok {
		t.Errorf("unexpected Content-Transfer-Encoding of %q", te)
	}

	buf.Reset()
	_, err = io.Copy(&buf, part)
	if err != nil {
		t.Error(err)
	}
	got = buf.String()
	// QP data has been decoded.
	want = `<div dir="ltr">Hello World.</div>`
	if got != want {
		t.Errorf("wrong part value:\n got: %q\nwant: %q", got, want)
	}
}

// Test parsing an image attachment from gmail, which previously failed.
func TestNested(t *testing.T) {
	// nested-mime is the body part of a multipart/mixed email
	// with boundary e89a8ff1c1e83553e304be640612
	f, err := os.Open("testdata/nested-mime")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mr := NewReader(f, "e89a8ff1c1e83553e304be640612")
	p, err := mr.NextPart()
	if err != nil {
		t.Fatalf("error reading first section (alternative): %v", err)
	}

	// Read the inner text/plain and text/html sections of the multipart/alternative.
	mr2 := NewReader(p, "e89a8ff1c1e83553e004be640610")
	p, err = mr2.NextPart()
	if err != nil {
		t.Fatalf("reading text/plain part: %v", err)
	}
	if b, err := io.ReadAll(p); string(b) != "*body*\r\n" || err != nil {
		t.Fatalf("reading text/plain part: got %q, %v", b, err)
	}
	p, err = mr2.NextPart()
	if err != nil {
		t.Fatalf("reading text/html part: %v", err)
	}
	if b, err := io.ReadAll(p); string(b) != "<b>body</b>\r\n" || err != nil {
		t.Fatalf("reading text/html part: got %q, %v", b, err)
	}

	p, err = mr2.NextPart()
	if err != io.EOF {
		t.Fatalf("final inner NextPart = %v; want io.EOF", err)
	}

	// Back to the outer multipart/mixed, reading the image attachment.
	_, err = mr.NextPart()
	if err != nil {
		t.Fatalf("error reading the image attachment at the end: %v", err)
	}

	_, err = mr.NextPart()
	if err != io.EOF {
		t.Fatalf("final outer NextPart = %v; want io.EOF", err)
	}
}

type headerBody struct {
	header textproto.MIMEHeader
	body   string
}

func formData(key, value string) headerBody {
	return headerBody{
		textproto.MIMEHeader{
			"Content-Type":        {"text/plain; charset=ISO-8859-1"},
			"Content-Disposition": {"form-data; name=" + key},
		},
		value,
	}
}

type parseTest struct {
	name    string
	in, sep string
	want    []headerBody
}

var parseTests = []parseTest{
	// Actual body from App Engine on a blob upload. The final part (the
	// Content-Type: message/external-body) is what App Engine replaces
	// the uploaded file with. The other form fields (prefixed with
	// "other" in their form-data name) are unchanged. A bug was
	// reported with blob uploads failing when the other fields were
	// empty. This was the MIME POST body that previously failed.
	{
		name: "App Engine post",
		sep:  "00151757727e9583fd04bfbca4c6",
		in:   "--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherEmpty1\r\n\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherFoo1\r\n\r\nfoo\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherFoo2\r\n\r\nfoo\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherEmpty2\r\n\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherRepeatFoo\r\n\r\nfoo\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherRepeatFoo\r\n\r\nfoo\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherRepeatEmpty\r\n\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=otherRepeatEmpty\r\n\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: text/plain; charset=ISO-8859-1\r\nContent-Disposition: form-data; name=submit\r\n\r\nSubmit\r\n--00151757727e9583fd04bfbca4c6\r\nContent-Type: message/external-body; charset=ISO-8859-1; blob-key=AHAZQqG84qllx7HUqO_oou5EvdYQNS3Mbbkb0RjjBoM_Kc1UqEN2ygDxWiyCPulIhpHRPx-VbpB6RX4MrsqhWAi_ZxJ48O9P2cTIACbvATHvg7IgbvZytyGMpL7xO1tlIvgwcM47JNfv_tGhy1XwyEUO8oldjPqg5Q\r\nContent-Disposition: form-data; name=file; filename=\"fall.png\"\r\n\r\nContent-Type: image/png\r\nContent-Length: 232303\r\nX-AppEngine-Upload-Creation: 2012-05-10 23:14:02.715173\r\nContent-MD5: MzRjODU1ZDZhZGU1NmRlOWEwZmMwMDdlODBmZTA0NzA=\r\nContent-Disposition: form-data; name=file; filename=\"fall.png\"\r\n\r\n\r\n--00151757727e9583fd04bfbca4c6--",
		want: []headerBody{
			formData("otherEmpty1", ""),
			formData("otherFoo1", "foo"),
			formData("otherFoo2", "foo"),
			formData("otherEmpty2", ""),
			formData("otherRepeatFoo", "foo"),
			formData("otherRepeatFoo", "foo"),
			formData("otherRepeatEmpty", ""),
			formData("otherRepeatEmpty", ""),
			formData("submit", "Submit"),
			{textproto.MIMEHeader{
				"Content-Type":        {"message/external-body; charset=ISO-8859-1; blob-key=AHAZQqG84qllx7HUqO_oou5EvdYQNS3Mbbkb0RjjBoM_Kc1UqEN2ygDxWiyCPulIhpHRPx-VbpB6RX4MrsqhWAi_ZxJ48O9P2cTIACbvATHvg7IgbvZytyGMpL7xO1tlIvgwcM47JNfv_tGhy1XwyEUO8oldjPqg5Q"},
				"Content-Disposition": {"form-data; name=file; filename=\"fall.png\""},
			}, "Content-Type: image/png\r\nContent-Length: 232303\r\nX-AppEngine-Upload-Creation: 2012-05-10 23:14:02.715173\r\nContent-MD5: MzRjODU1ZDZhZGU1NmRlOWEwZmMwMDdlODBmZTA0NzA=\r\nContent-Disposition: form-data; name=file; filename=\"fall.png\"\r\n\r\n"},
		},
	},

	// Single empty part, ended with --boundary immediately after headers.
	{
		name: "single empty part, --boundary",
		sep:  "abc",
		in:   "--abc\r\nFoo: bar\r\n\r\n--abc--",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, ""},
		},
	},

	// Single empty part, ended with \r\n--boundary immediately after headers.
	{
		name: "single empty part, \r\n--boundary",
		sep:  "abc",
		in:   "--abc\r\nFoo: bar\r\n\r\n\r\n--abc--",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, ""},
		},
	},

	// Final part empty.
	{
		name: "final part empty",
		sep:  "abc",
		in:   "--abc\r\nFoo: bar\r\n\r\n--abc\r\nFoo2: bar2\r\n\r\n--abc--",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, ""},
			{textproto.MIMEHeader{"Foo2": {"bar2"}}, ""},
		},
	},

	// Final part empty with newlines after final separator.
	{
		name: "final part empty then crlf",
		sep:  "abc",
		in:   "--abc\r\nFoo: bar\r\n\r\n--abc--\r\n",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, ""},
		},
	},

	// Final part empty with lwsp-chars after final separator.
	{
		name: "final part empty then lwsp",
		sep:  "abc",
		in:   "--abc\r\nFoo: bar\r\n\r\n--abc-- \t",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, ""},
		},
	},

	// No parts (empty form as submitted by Chrome)
	{
		name: "no parts",
		sep:  "----WebKitFormBoundaryQfEAfzFOiSemeHfA",
		in:   "------WebKitFormBoundaryQfEAfzFOiSemeHfA--\r\n",
		want: []headerBody{},
	},

	// Part containing data starting with the boundary, but with additional suffix.
	{
		name: "fake separator as data",
		sep:  "sep",
		in:   "--sep\r\nFoo: bar\r\n\r\n--sepFAKE\r\n--sep--",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, "--sepFAKE"},
		},
	},

	// Part containing a boundary with whitespace following it.
	{
		name: "boundary with whitespace",
		sep:  "sep",
		in:   "--sep \r\nFoo: bar\r\n\r\ntext\r\n--sep--",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, "text"},
		},
	},

	// With ignored leading line.
	{
		name: "leading line",
		sep:  "MyBoundary",
		in: strings.Replace(`This is a multi-part message.  This line is ignored.
--MyBoundary
foo: bar


--MyBoundary--`, "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, ""},
		},
	},

	// Issue 10616; minimal
	{
		name: "issue 10616 minimal",
		sep:  "sep",
		in: "--sep \r\nFoo: bar\r\n\r\n" +
			"a\r\n" +
			"--sep_alt\r\n" +
			"b\r\n" +
			"\r\n--sep--",
		want: []headerBody{
			{textproto.MIMEHeader{"Foo": {"bar"}}, "a\r\n--sep_alt\r\nb\r\n"},
		},
	},

	// Issue 10616; full example from bug.
	{
		name: "nested separator prefix is outer separator",
		sep:  "----=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9",
		in: strings.Replace(`------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9
Content-Type: multipart/alternative; boundary="----=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt"

------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit

This is a multi-part message in MIME format.

------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 8bit

html things
------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt--
------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9--`, "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Content-Type": {`multipart/alternative; boundary="----=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt"`}},
				strings.Replace(`------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 8bit

This is a multi-part message in MIME format.

------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: 8bit

html things
------=_NextPart_4c2fbafd7ec4c8bf08034fe724b608d9_alt--`, "\n", "\r\n", -1),
			},
		},
	},

	// Issue 12662: Check that we don't consume the leading \r if the peekBuffer
	// ends in '\r\n--separator-'
	{
		name: "peek buffer boundary condition",
		sep:  "00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db",
		in: strings.Replace(`--00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db
Content-Disposition: form-data; name="block"; filename="block"
Content-Type: application/octet-stream

`+strings.Repeat("A", peekBufferSize-65)+"\n--00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db--", "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Content-Type": {`application/octet-stream`}, "Content-Disposition": {`form-data; name="block"; filename="block"`}},
				strings.Repeat("A", peekBufferSize-65),
			},
		},
	},

	// Issue 12662: Same test as above with \r\n at the end
	{
		name: "peek buffer boundary condition",
		sep:  "00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db",
		in: strings.Replace(`--00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db
Content-Disposition: form-data; name="block"; filename="block"
Content-Type: application/octet-stream

`+strings.Repeat("A", peekBufferSize-65)+"\n--00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db--\n", "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Content-Type": {`application/octet-stream`}, "Content-Disposition": {`form-data; name="block"; filename="block"`}},
				strings.Repeat("A", peekBufferSize-65),
			},
		},
	},

	// Issue 12662v2: We want to make sure that for short buffers that end with
	// '\r\n--separator-' we always consume at least one (valid) symbol from the
	// peekBuffer
	{
		name: "peek buffer boundary condition",
		sep:  "aaaaaaaaaa00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db",
		in: strings.Replace(`--aaaaaaaaaa00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db
Content-Disposition: form-data; name="block"; filename="block"
Content-Type: application/octet-stream

`+strings.Repeat("A", peekBufferSize)+"\n--aaaaaaaaaa00ffded004d4dd0fdf945fbdef9d9050cfd6a13a821846299b27fc71b9db--", "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Content-Type": {`application/octet-stream`}, "Content-Disposition": {`form-data; name="block"; filename="block"`}},
				strings.Repeat("A", peekBufferSize),
			},
		},
	},

	// Context: https://github.com/camlistore/camlistore/issues/642
	// If the file contents in the form happens to have a size such as:
	// size = peekBufferSize - (len("\n--") + len(boundary) + len("\r") + 1), (modulo peekBufferSize)
	// then peekBufferSeparatorIndex was wrongly returning (-1, false), which was leading to an nCopy
	// cut such as:
	// "somedata\r| |\n--Boundary\r" (instead of "somedata| |\r\n--Boundary\r"), which was making the
	// subsequent Read miss the boundary.
	{
		name: "safeCount off by one",
		sep:  "08b84578eabc563dcba967a945cdf0d9f613864a8f4a716f0e81caa71a74",
		in: strings.Replace(`--08b84578eabc563dcba967a945cdf0d9f613864a8f4a716f0e81caa71a74
Content-Disposition: form-data; name="myfile"; filename="my-file.txt"
Content-Type: application/octet-stream

`, "\n", "\r\n", -1) +
			strings.Repeat("A", peekBufferSize-(len("\n--")+len("08b84578eabc563dcba967a945cdf0d9f613864a8f4a716f0e81caa71a74")+len("\r")+1)) +
			strings.Replace(`
--08b84578eabc563dcba967a945cdf0d9f613864a8f4a716f0e81caa71a74
Content-Disposition: form-data; name="key"

val
--08b84578eabc563dcba967a945cdf0d9f613864a8f4a716f0e81caa71a74--
`, "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Content-Type": {`application/octet-stream`}, "Content-Disposition": {`form-data; name="myfile"; filename="my-file.txt"`}},
				strings.Repeat("A", peekBufferSize-(len("\n--")+len("08b84578eabc563dcba967a945cdf0d9f613864a8f4a716f0e81caa71a74")+len("\r")+1)),
			},
			{textproto.MIMEHeader{"Content-Disposition": {`form-data; name="key"`}},
				"val",
			},
		},
	},

	// Issue 46042; a nested multipart uses the outer separator followed by
	// a dash.
	{
		name: "nested separator prefix is outer separator followed by a dash",
		sep:  "foo",
		in: strings.Replace(`--foo
Content-Type: multipart/alternative; boundary="foo-bar"

--foo-bar

Body
--foo-bar

Body2
--foo-bar--
--foo--`, "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Content-Type": {`multipart/alternative; boundary="foo-bar"`}},
				strings.Replace(`--foo-bar

Body
--foo-bar

Body2
--foo-bar--`, "\n", "\r\n", -1),
			},
		},
	},

	// A nested boundary cannot be the outer separator followed by double dash.
	{
		name: "nested separator prefix is outer separator followed by double dash",
		sep:  "foo",
		in: strings.Replace(`--foo
Content-Type: multipart/alternative; boundary="foo--"

--foo--

Body

--foo--`, "\n", "\r\n", -1),
		want: []headerBody{
			{textproto.MIMEHeader{"Content-Type": {`multipart/alternative; boundary="foo--"`}}, ""},
		},
	},

	roundTripParseTest(),
}

func TestParse(t *testing.T) {
Cases:
	for _, tt := range parseTests {
		r := NewReader(strings.NewReader(tt.in), tt.sep)
		got := []headerBody{}
		for {
			p, err := r.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("in test %q, NextPart: %v", tt.name, err)
				continue Cases
			}
			pbody, err := io.ReadAll(p)
			if err != nil {
				t.Errorf("in test %q, error reading part: %v", tt.name, err)
				continue Cases
			}
			got = append(got, headerBody{p.Header, string(pbody)})
		}
		if !reflect.DeepEqual(tt.want, got) {
			t.Errorf("test %q:\n got: %v\nwant: %v", tt.name, got, tt.want)
			if len(tt.want) != len(got) {
				t.Errorf("test %q: got %d parts, want %d", tt.name, len(got), len(tt.want))
			} else if len(got) > 1 {
				for pi, wantPart := range tt.want {
					if !reflect.DeepEqual(wantPart, got[pi]) {
						t.Errorf("test %q, part %d:\n got: %v\nwant: %v", tt.name, pi, got[pi], wantPart)
					}
				}
			}
		}
	}
}

func partsFromReader(r *Reader) ([]headerBody, error) {
	got := []headerBody{}
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			return got, nil
		}
		if err != nil {
			return nil, fmt.Errorf("NextPart: %v", err)
		}
		pbody, err := io.ReadAll(p)
		if err != nil {
			return nil, fmt.Errorf("error reading part: %v", err)
		}
		got = append(got, headerBody{p.Header, string(pbody)})
	}
}

func TestParseAllSizes(t *testing.T) {
	t.Parallel()
	maxSize := 5 << 10
	if testing.Short() {
		maxSize = 512
	}
	var buf bytes.Buffer
	body := strings.Repeat("a", maxSize)
	bodyb := []byte(body)
	for size := 0; size < maxSize; size++ {
		buf.Reset()
		w := NewWriter(&buf)
		part, _ := w.CreateFormField("f")
		part.Write(bodyb[:size])
		part, _ = w.CreateFormField("key")
		part.Write([]byte("val"))
		w.Close()
		r := NewReader(&buf, w.Boundary())
		got, err := partsFromReader(r)
		if err != nil {
			t.Errorf("For size %d: %v", size, err)
			continue
		}
		if len(got) != 2 {
			t.Errorf("For size %d, num parts = %d; want 2", size, len(got))
			continue
		}
		if got[0].body != body[:size] {
			t.Errorf("For size %d, got unexpected len %d: %q", size, len(got[0].body), got[0].body)
		}
	}
}

func roundTripParseTest() parseTest {
	t := parseTest{
		name: "round trip",
		want: []headerBody{
			formData("empty", ""),
			formData("lf", "\n"),
			formData("cr", "\r"),
			formData("crlf", "\r\n"),
			formData("foo", "bar"),
		},
	}
	var buf strings.Builder
	w := NewWriter(&buf)
	for _, p := range t.want {
		pw, err := w.CreatePart(p.header)
		if err != nil {
			panic(err)
		}
		_, err = pw.Write([]byte(p.body))
		if err != nil {
			panic(err)
		}
	}
	w.Close()
	t.in = buf.String()
	t.sep = w.Boundary()
	return t
}

func TestNoBoundary(t *testing.T) {
	mr := NewReader(strings.NewReader(""), "")
	_, err := mr.NextPart()
	if got, want := fmt.Sprint(err), "multipart: boundary is empty"; got != want {
		t.Errorf("NextPart error = %v; want %v", got, want)
	}
}

"""



```