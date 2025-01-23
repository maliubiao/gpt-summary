Response:
Let's break down the thought process to analyze the provided Go code snippet and answer the user's request.

**1. Understanding the Goal:**

The primary goal is to understand what the Go code in `reader_test.go` does and explain it in Chinese. The focus is on the *functionality* being tested.

**2. High-Level Overview:**

The filename `reader_test.go` immediately suggests that this code contains test functions for a `Reader` type. The package name `textproto` hints that this `Reader` likely deals with text-based protocols. Scanning the import statements confirms this (`bufio`, `io`, `net`, `strings`).

**3. Analyzing Individual Test Functions:**

I'll go through each `Test...` function and determine what aspect of the `Reader` it's testing.

* **`TestReadLine`:** Tests reading a single line delimited by `\n`. It checks both successful reads and reaching the end of the input (EOF).
* **`TestReadLineLongLine`:**  Focuses on reading very long lines. This is important to check for buffer overflow issues or performance problems with large inputs.
* **`TestReadContinuedLine`:**  This is interesting. It tests the scenario where a line is "continued" onto the next line by a leading space or tab. This is a common pattern in some text protocols (like email headers).
* **`TestReadCodeLine`:** This test looks for a numeric code at the beginning of a line, followed by a message. It also tests error handling when the code doesn't match the expected prefix.
* **`TestReadDotLines`:** This one is specific. It appears to be testing a mechanism where a line containing just a dot (`.`) signifies the end of a block of lines. The code also shows how escaping a leading dot with another dot works (`..bar`).
* **`TestReadDotBytes`:**  Similar to `TestReadDotLines`, but it collects the lines as bytes instead of strings.
* **`TestReadMIMEHeader`:** This test is crucial. It's clearly testing the parsing of MIME headers (like those found in HTTP or email). It checks for correct parsing of key-value pairs, handling of continued lines, and case-insensitivity of header keys.
* **`TestReadMIMEHeaderSingle`:** A simpler case of MIME header parsing with only one header.
* **`TestReaderUpcomingHeaderKeys`:** This test mentions it's testing an internal function. By examining the code, it seems to be counting how many header keys can be identified in the input before actually parsing them.
* **`TestReadMIMEHeaderNoKey`:** Tests the behavior when a line starts with a colon (invalid header).
* **`TestLargeReadMIMEHeader`:** Checks the handling of very large header values.
* **`TestReadMIMEHeaderNonCompliant`:** Tests that the parser *doesn't* normalize headers with spaces around colons or spaces in keys, even though this is technically against RFCs. This is important for compatibility with real-world systems that might not strictly adhere to the standards.
* **`TestReadMIMEHeaderMalformed`:**  A series of tests for various invalid MIME header formats. This ensures robust error handling.
* **`TestReadMIMEHeaderBytes`:**  Tests the allowed characters in header keys and values.
* **`TestReadMIMEHeaderTrimContinued`:** Specifically tests that leading and trailing spaces on continued lines are trimmed correctly.
* **`TestReadMIMEHeaderAllocations`:**  A performance-related test. It checks that the `ReadMIMEHeader` function doesn't allocate an excessive amount of memory.
* **`TestRFC959Lines`:**  Tests `ReadResponse`, which seems designed for handling multi-line responses with a numeric code prefix, as defined in RFC 959 (likely for FTP or similar protocols).
* **`TestReadMultiLineError`:**  Similar to `TestRFC959Lines` but specifically focuses on error responses.
* **`TestCommonHeaders`:** This test seems to be verifying a performance optimization related to caching common HTTP headers.
* **`TestIssue46363`:** A concurrency test to ensure there are no race conditions when initializing the common header cache.
* **`BenchmarkReadMIMEHeader`:** Benchmarks the performance of `ReadMIMEHeader` on different types of headers.
* **`BenchmarkUncommon`:** Benchmarks `ReadMIMEHeader` specifically with uncommon headers.

**4. Identifying the Core Functionality:**

From analyzing the tests, it's clear the central piece of functionality being tested is the `Reader` type within the `textproto` package. This `Reader` provides methods for reading text-based protocol elements like:

* Single lines (`ReadLine`)
* Continued lines (`ReadContinuedLine`)
* Lines with numeric codes (`ReadCodeLine`, `ReadResponse`)
* Dot-terminated blocks of lines (`ReadDotLines`, `ReadDotBytes`)
* MIME headers (`ReadMIMEHeader`)

**5. Inferring the Go Language Feature:**

Based on the package name and the methods, the `textproto` package likely provides utility functions for working with text-based network protocols. It's an abstraction layer on top of `bufio` that simplifies parsing common structures found in protocols like HTTP, SMTP, POP3, etc.

**6. Providing Go Code Examples:**

Now, I can create Go code examples demonstrating the usage of the `Reader` methods, based on the test cases. This involves creating a `strings.Reader`, wrapping it in a `bufio.Reader`, and then creating a `textproto.Reader`.

**7. Reasoning and Assumptions:**

When providing examples, I need to make reasonable assumptions about the input and expected output. The test cases themselves provide excellent examples.

**8. Command-Line Arguments:**

This code primarily focuses on the internal logic of the `textproto` package. It doesn't seem to involve handling command-line arguments directly. The tests are run using the `go test` command, but the code itself isn't parsing command-line flags.

**9. Common Mistakes:**

Thinking about how developers might misuse this package, potential issues include:

* Incorrectly assuming all text protocols use the same line endings (the code handles `\n` and `\r\n`).
* Forgetting about continued lines when parsing headers.
* Not handling the dot-termination correctly when reading multi-line data.
* Making assumptions about the case-sensitivity of headers (the package handles canonicalization).

**10. Structuring the Answer:**

Finally, I organize the information into a clear and structured Chinese response, covering the requested points: functionality, inferred Go feature, code examples, assumptions, command-line arguments (or lack thereof), and common mistakes.

This detailed thought process helps in systematically understanding the code, inferring its purpose, and generating a comprehensive and accurate answer to the user's request.
这段代码是 Go 语言标准库 `net/textproto` 包中 `reader_test.go` 文件的一部分，它包含了对 `textproto.Reader` 类型进行单元测试的各种测试函数。

**`textproto.Reader` 的功能**

通过分析这些测试函数，我们可以推断出 `textproto.Reader` 的主要功能是提供一种方便的方式来读取和解析符合特定文本协议格式的数据流。它在 `bufio.Reader` 的基础上进行了封装，添加了针对文本协议的常用操作。

具体来说，`textproto.Reader` 提供了以下功能：

1. **按行读取 (`ReadLine`)**: 读取以换行符 (`\n` 或 `\r\n`) 结尾的单行文本。
2. **读取连续行 (`ReadContinuedLine`)**:  读取逻辑上的一行文本，即使该行被换行符分隔成了多行，后续行以空格或制表符开头。这在处理例如 HTTP 头部等场景非常有用。
3. **读取带有状态码的行 (`ReadCodeLine`)**: 读取以数字状态码开头的行，并将其解析为状态码和消息。
4. **读取点终止的行 (`ReadDotLines`)**: 读取一系列行，直到遇到只包含一个点的行 (`.`) 为止，常用于例如 SMTP 协议中消息体的处理。
5. **读取点终止的字节 (`ReadDotBytes`)**:  类似于 `ReadDotLines`，但返回的是字节切片。
6. **读取 MIME 头部 (`ReadMIMEHeader`)**: 读取和解析 MIME 格式的头部信息，将其存储在 `MIMEHeader` 类型的 map 中。

**Go 语言功能实现推断与代码示例**

`textproto.Reader` 的实现很可能利用了 `bufio.Reader` 提供的缓冲读取功能，并在其基础上添加了对特定文本协议格式的解析逻辑。

以下是用 Go 代码演示 `textproto.Reader` 几种主要功能的示例：

```go
package main

import (
	"bufio"
	"fmt"
	"net/textproto"
	"strings"
	"io"
)

func main() {
	// 示例 1: ReadLine
	r1 := textproto.NewReader(bufio.NewReader(strings.NewReader("line1\nline2\n")))
	line1, _ := r1.ReadLine()
	fmt.Println("ReadLine:", line1) // 输出: ReadLine: line1
	line2, _ := r1.ReadLine()
	fmt.Println("ReadLine:", line2) // 输出: ReadLine: line2
	_, err1 := r1.ReadLine()
	fmt.Println("ReadLine EOF:", err1 == io.EOF) // 输出: ReadLine EOF: true

	// 示例 2: ReadContinuedLine
	r2 := textproto.NewReader(bufio.NewReader(strings.NewReader("lineA\n lineB\nlineC\n")))
	continuedLine, _ := r2.ReadContinuedLine()
	fmt.Println("ReadContinuedLine:", continuedLine) // 输出: ReadContinuedLine: lineA lineB
	lineC, _ := r2.ReadContinuedLine()
	fmt.Println("ReadContinuedLine:", lineC)       // 输出: ReadContinuedLine: lineC
	_, err2 := r2.ReadContinuedLine()
	fmt.Println("ReadContinuedLine EOF:", err2 == io.EOF) // 输出: ReadContinuedLine EOF: true

	// 示例 3: ReadCodeLine
	r3 := textproto.NewReader(bufio.NewReader(strings.NewReader("200 OK\n404 Not Found\n")))
	code1, msg1, _ := r3.ReadCodeLine(20)
	fmt.Printf("ReadCodeLine: Code=%d, Msg=%s\n", code1, msg1) // 输出: ReadCodeLine: Code=200, Msg=OK
	code2, msg2, _ := r3.ReadCodeLine(40)
	fmt.Printf("ReadCodeLine: Code=%d, Msg=%s\n", code2, msg2) // 输出: ReadCodeLine: Code=404, Msg=Not Found
	_, _, err3 := r3.ReadCodeLine(50)
	fmt.Println("ReadCodeLine EOF:", err3 == io.EOF)        // 输出: ReadCodeLine EOF: true

	// 示例 4: ReadMIMEHeader
	r4 := textproto.NewReader(bufio.NewReader(strings.NewReader("Content-Type: text/plain\r\nUser-Agent: MyBrowser\r\n\r\n")))
	header, _ := r4.ReadMIMEHeader()
	fmt.Println("ReadMIMEHeader:", header)
	// 输出: ReadMIMEHeader: map[Content-Type:[text/plain] User-Agent:[MyBrowser]]
}
```

**假设的输入与输出 (针对代码推理)**

以 `TestReadContinuedLine` 为例：

**假设输入:**

```
line1
 line2
line3
```

**预期输出:**

第一次调用 `ReadContinuedLine` 返回 `"line1 line2"`，`err` 为 `nil`。
第二次调用 `ReadContinuedLine` 返回 `"line3"`，`err` 为 `nil`。
第三次调用 `ReadContinuedLine` 返回 `""`，`err` 为 `io.EOF`。

**命令行参数的具体处理**

从提供的代码片段来看，这是一个测试文件，它主要关注的是 `textproto.Reader` 内部的逻辑测试。它本身不涉及命令行参数的处理。通常，`net/textproto` 包会在网络编程中使用，例如在实现客户端或服务器端程序处理特定协议时，但参数的解析和处理会发生在调用 `textproto` 包的上层应用中。例如，一个 SMTP 客户端可能会使用命令行参数来指定服务器地址和端口。

**使用者易犯错的点**

1. **混淆 `ReadLine` 和 `ReadContinuedLine`**:  初学者可能会错误地使用 `ReadLine` 来读取可能包含连续行的头部信息，导致解析错误。应该根据文本协议的规范选择合适的方法。

   **错误示例:**

   ```go
   r := textproto.NewReader(bufio.NewReader(strings.NewReader("Header1: value1\n  continued value\nHeader2: value2\n")))
   line1, _ := r.ReadLine() // 错误地使用 ReadLine
   fmt.Println(line1) // 输出: Header1: value1
   line2, _ := r.ReadLine()
   fmt.Println(line2) // 输出:   continued value (这并不是期望的完整 Header1 的值)
   ```

   **正确示例:**

   ```go
   r := textproto.NewReader(bufio.NewReader(strings.NewReader("Header1: value1\n  continued value\nHeader2: value2\n")))
   header1, _ := r.ReadContinuedLine() // 正确使用 ReadContinuedLine
   fmt.Println(header1) // 输出: Header1: value1  continued value
   ```

2. **忘记处理点终止行 (`.`)**: 在处理类似 SMTP 消息体等数据时，如果没有正确使用 `ReadDotLines` 或 `ReadDotBytes`，可能会提前结束读取，或者将表示结束的 `.` 也当作数据的一部分。

   **错误示例:**

   ```go
   r := textproto.NewReader(bufio.NewReader(strings.NewReader("line1\nline2\n.\n")))
   line1, _ := r.ReadLine()
   fmt.Println(line1) // 输出: line1
   line2, _ := r.ReadLine()
   fmt.Println(line2) // 输出: line2
   line3, _ := r.ReadLine()
   fmt.Println(line3) // 输出: . (本应作为结束符)
   ```

   **正确示例:**

   ```go
   r := textproto.NewReader(bufio.NewReader(strings.NewReader("line1\nline2\n.\n")))
   lines, _ := r.ReadDotLines()
   fmt.Println(lines) // 输出: [line1 line2]
   ```

总而言之，`go/src/net/textproto/reader_test.go` 文件通过一系列单元测试，验证了 `textproto.Reader` 类型在读取和解析各种格式的文本协议数据时的正确性。 `textproto.Reader` 旨在简化网络编程中对基于文本协议的数据处理。

### 提示词
```
这是路径为go/src/net/textproto/reader_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package textproto

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

func reader(s string) *Reader {
	return NewReader(bufio.NewReader(strings.NewReader(s)))
}

func TestReadLine(t *testing.T) {
	r := reader("line1\nline2\n")
	s, err := r.ReadLine()
	if s != "line1" || err != nil {
		t.Fatalf("Line 1: %s, %v", s, err)
	}
	s, err = r.ReadLine()
	if s != "line2" || err != nil {
		t.Fatalf("Line 2: %s, %v", s, err)
	}
	s, err = r.ReadLine()
	if s != "" || err != io.EOF {
		t.Fatalf("EOF: %s, %v", s, err)
	}
}

func TestReadLineLongLine(t *testing.T) {
	line := strings.Repeat("12345", 10000)
	r := reader(line + "\r\n")
	s, err := r.ReadLine()
	if err != nil {
		t.Fatalf("Line 1: %v", err)
	}
	if s != line {
		t.Fatalf("%v-byte line does not match expected %v-byte line", len(s), len(line))
	}
}

func TestReadContinuedLine(t *testing.T) {
	r := reader("line1\nline\n 2\nline3\n")
	s, err := r.ReadContinuedLine()
	if s != "line1" || err != nil {
		t.Fatalf("Line 1: %s, %v", s, err)
	}
	s, err = r.ReadContinuedLine()
	if s != "line 2" || err != nil {
		t.Fatalf("Line 2: %s, %v", s, err)
	}
	s, err = r.ReadContinuedLine()
	if s != "line3" || err != nil {
		t.Fatalf("Line 3: %s, %v", s, err)
	}
	s, err = r.ReadContinuedLine()
	if s != "" || err != io.EOF {
		t.Fatalf("EOF: %s, %v", s, err)
	}
}

func TestReadCodeLine(t *testing.T) {
	r := reader("123 hi\n234 bye\n345 no way\n")
	code, msg, err := r.ReadCodeLine(0)
	if code != 123 || msg != "hi" || err != nil {
		t.Fatalf("Line 1: %d, %s, %v", code, msg, err)
	}
	code, msg, err = r.ReadCodeLine(23)
	if code != 234 || msg != "bye" || err != nil {
		t.Fatalf("Line 2: %d, %s, %v", code, msg, err)
	}
	code, msg, err = r.ReadCodeLine(346)
	if code != 345 || msg != "no way" || err == nil {
		t.Fatalf("Line 3: %d, %s, %v", code, msg, err)
	}
	if e, ok := err.(*Error); !ok || e.Code != code || e.Msg != msg {
		t.Fatalf("Line 3: wrong error %v\n", err)
	}
	code, msg, err = r.ReadCodeLine(1)
	if code != 0 || msg != "" || err != io.EOF {
		t.Fatalf("EOF: %d, %s, %v", code, msg, err)
	}
}

func TestReadDotLines(t *testing.T) {
	r := reader("dotlines\r\n.foo\r\n..bar\n...baz\nquux\r\n\r\n.\r\nanother\n")
	s, err := r.ReadDotLines()
	want := []string{"dotlines", "foo", ".bar", "..baz", "quux", ""}
	if !slices.Equal(s, want) || err != nil {
		t.Fatalf("ReadDotLines: %v, %v", s, err)
	}

	s, err = r.ReadDotLines()
	want = []string{"another"}
	if !slices.Equal(s, want) || err != io.ErrUnexpectedEOF {
		t.Fatalf("ReadDotLines2: %v, %v", s, err)
	}
}

func TestReadDotBytes(t *testing.T) {
	r := reader("dotlines\r\n.foo\r\n..bar\n...baz\nquux\r\n\r\n.\r\nanot.her\r\n")
	b, err := r.ReadDotBytes()
	want := []byte("dotlines\nfoo\n.bar\n..baz\nquux\n\n")
	if !slices.Equal(b, want) || err != nil {
		t.Fatalf("ReadDotBytes: %q, %v", b, err)
	}

	b, err = r.ReadDotBytes()
	want = []byte("anot.her\n")
	if !slices.Equal(b, want) || err != io.ErrUnexpectedEOF {
		t.Fatalf("ReadDotBytes2: %q, %v", b, err)
	}
}

func TestReadMIMEHeader(t *testing.T) {
	r := reader("my-key: Value 1  \r\nLong-key: Even \n Longer Value\r\nmy-Key: Value 2\r\n\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{
		"My-Key":   {"Value 1", "Value 2"},
		"Long-Key": {"Even Longer Value"},
	}
	if !reflect.DeepEqual(m, want) || err != nil {
		t.Fatalf("ReadMIMEHeader: %v, %v; want %v", m, err, want)
	}
}

func TestReadMIMEHeaderSingle(t *testing.T) {
	r := reader("Foo: bar\n\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{"Foo": {"bar"}}
	if !reflect.DeepEqual(m, want) || err != nil {
		t.Fatalf("ReadMIMEHeader: %v, %v; want %v", m, err, want)
	}
}

// TestReaderUpcomingHeaderKeys is testing an internal function, but it's very
// difficult to test well via the external API.
func TestReaderUpcomingHeaderKeys(t *testing.T) {
	for _, test := range []struct {
		input string
		want  int
	}{{
		input: "",
		want:  0,
	}, {
		input: "A: v",
		want:  1,
	}, {
		input: "A: v\r\nB: v\r\n",
		want:  2,
	}, {
		input: "A: v\nB: v\n",
		want:  2,
	}, {
		input: "A: v\r\n  continued\r\n  still continued\r\nB: v\r\n\r\n",
		want:  2,
	}, {
		input: "A: v\r\n\r\nB: v\r\nC: v\r\n",
		want:  1,
	}, {
		input: "A: v" + strings.Repeat("\n", 1000),
		want:  1,
	}} {
		r := reader(test.input)
		got := r.upcomingHeaderKeys()
		if test.want != got {
			t.Fatalf("upcomingHeaderKeys(%q): %v; want %v", test.input, got, test.want)
		}
	}
}

func TestReadMIMEHeaderNoKey(t *testing.T) {
	r := reader(": bar\ntest-1: 1\n\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{}
	if !reflect.DeepEqual(m, want) || err == nil {
		t.Fatalf("ReadMIMEHeader: %v, %v; want %v", m, err, want)
	}
}

func TestLargeReadMIMEHeader(t *testing.T) {
	data := make([]byte, 16*1024)
	for i := 0; i < len(data); i++ {
		data[i] = 'x'
	}
	sdata := string(data)
	r := reader("Cookie: " + sdata + "\r\n\n")
	m, err := r.ReadMIMEHeader()
	if err != nil {
		t.Fatalf("ReadMIMEHeader: %v", err)
	}
	cookie := m.Get("Cookie")
	if cookie != sdata {
		t.Fatalf("ReadMIMEHeader: %v bytes, want %v bytes", len(cookie), len(sdata))
	}
}

// TestReadMIMEHeaderNonCompliant checks that we don't normalize headers
// with spaces before colons, and accept spaces in keys.
func TestReadMIMEHeaderNonCompliant(t *testing.T) {
	// These invalid headers will be rejected by net/http according to RFC 7230.
	r := reader("Foo: bar\r\n" +
		"Content-Language: en\r\n" +
		"SID : 0\r\n" +
		"Audio Mode : None\r\n" +
		"Privilege : 127\r\n\r\n")
	m, err := r.ReadMIMEHeader()
	want := MIMEHeader{
		"Foo":              {"bar"},
		"Content-Language": {"en"},
		"SID ":             {"0"},
		"Audio Mode ":      {"None"},
		"Privilege ":       {"127"},
	}
	if !reflect.DeepEqual(m, want) || err != nil {
		t.Fatalf("ReadMIMEHeader =\n%v, %v; want:\n%v", m, err, want)
	}
}

func TestReadMIMEHeaderMalformed(t *testing.T) {
	inputs := []string{
		"No colon first line\r\nFoo: foo\r\n\r\n",
		" No colon first line with leading space\r\nFoo: foo\r\n\r\n",
		"\tNo colon first line with leading tab\r\nFoo: foo\r\n\r\n",
		" First: line with leading space\r\nFoo: foo\r\n\r\n",
		"\tFirst: line with leading tab\r\nFoo: foo\r\n\r\n",
		"Foo: foo\r\nNo colon second line\r\n\r\n",
		"Foo-\n\tBar: foo\r\n\r\n",
		"Foo-\r\n\tBar: foo\r\n\r\n",
		"Foo\r\n\t: foo\r\n\r\n",
		"Foo-\n\tBar",
		"Foo \tBar: foo\r\n\r\n",
		": empty key\r\n\r\n",
	}
	for _, input := range inputs {
		r := reader(input)
		if m, err := r.ReadMIMEHeader(); err == nil || err == io.EOF {
			t.Errorf("ReadMIMEHeader(%q) = %v, %v; want nil, err", input, m, err)
		}
	}
}

func TestReadMIMEHeaderBytes(t *testing.T) {
	for i := 0; i <= 0xff; i++ {
		s := "Foo" + string(rune(i)) + "Bar: foo\r\n\r\n"
		r := reader(s)
		wantErr := true
		switch {
		case i >= '0' && i <= '9':
			wantErr = false
		case i >= 'a' && i <= 'z':
			wantErr = false
		case i >= 'A' && i <= 'Z':
			wantErr = false
		case i == '!' || i == '#' || i == '$' || i == '%' || i == '&' || i == '\'' || i == '*' || i == '+' || i == '-' || i == '.' || i == '^' || i == '_' || i == '`' || i == '|' || i == '~':
			wantErr = false
		case i == ':':
			// Special case: "Foo:Bar: foo" is the header "Foo".
			wantErr = false
		case i == ' ':
			wantErr = false
		}
		m, err := r.ReadMIMEHeader()
		if err != nil != wantErr {
			t.Errorf("ReadMIMEHeader(%q) = %v, %v; want error=%v", s, m, err, wantErr)
		}
	}
	for i := 0; i <= 0xff; i++ {
		s := "Foo: foo" + string(rune(i)) + "bar\r\n\r\n"
		r := reader(s)
		wantErr := true
		switch {
		case i >= 0x21 && i <= 0x7e:
			wantErr = false
		case i == ' ':
			wantErr = false
		case i == '\t':
			wantErr = false
		case i >= 0x80 && i <= 0xff:
			wantErr = false
		}
		m, err := r.ReadMIMEHeader()
		if (err != nil) != wantErr {
			t.Errorf("ReadMIMEHeader(%q) = %v, %v; want error=%v", s, m, err, wantErr)
		}
	}
}

// Test that continued lines are properly trimmed. Issue 11204.
func TestReadMIMEHeaderTrimContinued(t *testing.T) {
	// In this header, \n and \r\n terminated lines are mixed on purpose.
	// We expect each line to be trimmed (prefix and suffix) before being concatenated.
	// Keep the spaces as they are.
	r := reader("" + // for code formatting purpose.
		"a:\n" +
		" 0 \r\n" +
		"b:1 \t\r\n" +
		"c: 2\r\n" +
		" 3\t\n" +
		"  \t 4  \r\n\n")
	m, err := r.ReadMIMEHeader()
	if err != nil {
		t.Fatal(err)
	}
	want := MIMEHeader{
		"A": {"0"},
		"B": {"1"},
		"C": {"2 3 4"},
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("ReadMIMEHeader mismatch.\n got: %q\nwant: %q", m, want)
	}
}

// Test that reading a header doesn't overallocate. Issue 58975.
func TestReadMIMEHeaderAllocations(t *testing.T) {
	var totalAlloc uint64
	const count = 200
	for i := 0; i < count; i++ {
		r := reader("A: b\r\n\r\n" + strings.Repeat("\n", 4096))
		var m1, m2 runtime.MemStats
		runtime.ReadMemStats(&m1)
		_, err := r.ReadMIMEHeader()
		if err != nil {
			t.Fatalf("ReadMIMEHeader: %v", err)
		}
		runtime.ReadMemStats(&m2)
		totalAlloc += m2.TotalAlloc - m1.TotalAlloc
	}
	// 32k is large and we actually allocate substantially less,
	// but prior to the fix for #58975 we allocated ~400k in this case.
	if got, want := totalAlloc/count, uint64(32768); got > want {
		t.Fatalf("ReadMIMEHeader allocated %v bytes, want < %v", got, want)
	}
}

type readResponseTest struct {
	in       string
	inCode   int
	wantCode int
	wantMsg  string
}

var readResponseTests = []readResponseTest{
	{"230-Anonymous access granted, restrictions apply\n" +
		"Read the file README.txt,\n" +
		"230  please",
		23,
		230,
		"Anonymous access granted, restrictions apply\nRead the file README.txt,\n please",
	},

	{"230 Anonymous access granted, restrictions apply\n",
		23,
		230,
		"Anonymous access granted, restrictions apply",
	},

	{"400-A\n400-B\n400 C",
		4,
		400,
		"A\nB\nC",
	},

	{"400-A\r\n400-B\r\n400 C\r\n",
		4,
		400,
		"A\nB\nC",
	},
}

// See https://www.ietf.org/rfc/rfc959.txt page 36.
func TestRFC959Lines(t *testing.T) {
	for i, tt := range readResponseTests {
		r := reader(tt.in + "\nFOLLOWING DATA")
		code, msg, err := r.ReadResponse(tt.inCode)
		if err != nil {
			t.Errorf("#%d: ReadResponse: %v", i, err)
			continue
		}
		if code != tt.wantCode {
			t.Errorf("#%d: code=%d, want %d", i, code, tt.wantCode)
		}
		if msg != tt.wantMsg {
			t.Errorf("#%d: msg=%q, want %q", i, msg, tt.wantMsg)
		}
	}
}

// Test that multi-line errors are appropriately and fully read. Issue 10230.
func TestReadMultiLineError(t *testing.T) {
	r := reader("550-5.1.1 The email account that you tried to reach does not exist. Please try\n" +
		"550-5.1.1 double-checking the recipient's email address for typos or\n" +
		"550-5.1.1 unnecessary spaces. Learn more at\n" +
		"Unexpected but legal text!\n" +
		"550 5.1.1 https://support.google.com/mail/answer/6596 h20si25154304pfd.166 - gsmtp\n")

	wantMsg := "5.1.1 The email account that you tried to reach does not exist. Please try\n" +
		"5.1.1 double-checking the recipient's email address for typos or\n" +
		"5.1.1 unnecessary spaces. Learn more at\n" +
		"Unexpected but legal text!\n" +
		"5.1.1 https://support.google.com/mail/answer/6596 h20si25154304pfd.166 - gsmtp"

	code, msg, err := r.ReadResponse(250)
	if err == nil {
		t.Errorf("ReadResponse: no error, want error")
	}
	if code != 550 {
		t.Errorf("ReadResponse: code=%d, want %d", code, 550)
	}
	if msg != wantMsg {
		t.Errorf("ReadResponse: msg=%q, want %q", msg, wantMsg)
	}
	if err != nil && err.Error() != "550 "+wantMsg {
		t.Errorf("ReadResponse: error=%q, want %q", err.Error(), "550 "+wantMsg)
	}
}

func TestCommonHeaders(t *testing.T) {
	commonHeaderOnce.Do(initCommonHeader)
	for h := range commonHeader {
		if h != CanonicalMIMEHeaderKey(h) {
			t.Errorf("Non-canonical header %q in commonHeader", h)
		}
	}
	b := []byte("content-Length")
	want := "Content-Length"
	n := testing.AllocsPerRun(200, func() {
		if x, _ := canonicalMIMEHeaderKey(b); x != want {
			t.Fatalf("canonicalMIMEHeaderKey(%q) = %q; want %q", b, x, want)
		}
	})
	if n > 0 {
		t.Errorf("canonicalMIMEHeaderKey allocs = %v; want 0", n)
	}
}

func TestIssue46363(t *testing.T) {
	// Regression test for data race reported in issue 46363:
	// ReadMIMEHeader reads commonHeader before commonHeader has been initialized.
	// Run this test with the race detector enabled to catch the reported data race.

	// Reset commonHeaderOnce, so that commonHeader will have to be initialized
	commonHeaderOnce = sync.Once{}
	commonHeader = nil

	// Test for data race by calling ReadMIMEHeader and CanonicalMIMEHeaderKey concurrently

	// Send MIME header over net.Conn
	r, w := net.Pipe()
	go func() {
		// ReadMIMEHeader calls canonicalMIMEHeaderKey, which reads from commonHeader
		NewConn(r).ReadMIMEHeader()
	}()
	w.Write([]byte("A: 1\r\nB: 2\r\nC: 3\r\n\r\n"))

	// CanonicalMIMEHeaderKey calls commonHeaderOnce.Do(initCommonHeader) which initializes commonHeader
	CanonicalMIMEHeaderKey("a")

	if commonHeader == nil {
		t.Fatal("CanonicalMIMEHeaderKey should initialize commonHeader")
	}
}

var clientHeaders = strings.Replace(`Host: golang.org
Connection: keep-alive
Cache-Control: max-age=0
Accept: application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
User-Agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.3 (KHTML, like Gecko) Chrome/6.0.472.63 Safari/534.3
Accept-Encoding: gzip,deflate,sdch
Accept-Language: en-US,en;q=0.8,fr-CH;q=0.6
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3
COOKIE: __utma=000000000.0000000000.0000000000.0000000000.0000000000.00; __utmb=000000000.0.00.0000000000; __utmc=000000000; __utmz=000000000.0000000000.00.0.utmcsr=code.google.com|utmccn=(referral)|utmcmd=referral|utmcct=/p/go/issues/detail
Non-Interned: test

`, "\n", "\r\n", -1)

var serverHeaders = strings.Replace(`Content-Type: text/html; charset=utf-8
Content-Encoding: gzip
Date: Thu, 27 Sep 2012 09:03:33 GMT
Server: Google Frontend
Cache-Control: private
Content-Length: 2298
VIA: 1.1 proxy.example.com:80 (XXX/n.n.n-nnn)
Connection: Close
Non-Interned: test

`, "\n", "\r\n", -1)

func BenchmarkReadMIMEHeader(b *testing.B) {
	b.ReportAllocs()
	for _, set := range []struct {
		name    string
		headers string
	}{
		{"client_headers", clientHeaders},
		{"server_headers", serverHeaders},
	} {
		b.Run(set.name, func(b *testing.B) {
			var buf bytes.Buffer
			br := bufio.NewReader(&buf)
			r := NewReader(br)

			for i := 0; i < b.N; i++ {
				buf.WriteString(set.headers)
				if _, err := r.ReadMIMEHeader(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUncommon(b *testing.B) {
	b.ReportAllocs()
	var buf bytes.Buffer
	br := bufio.NewReader(&buf)
	r := NewReader(br)
	for i := 0; i < b.N; i++ {
		buf.WriteString("uncommon-header-for-benchmark: foo\r\n\r\n")
		h, err := r.ReadMIMEHeader()
		if err != nil {
			b.Fatal(err)
		}
		if _, ok := h["Uncommon-Header-For-Benchmark"]; !ok {
			b.Fatal("Missing result header.")
		}
	}
}
```