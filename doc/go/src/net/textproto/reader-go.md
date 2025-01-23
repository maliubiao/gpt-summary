Response:
Let's break down the thought process to generate the answer about `net/textproto/reader.go`.

**1. Understanding the Goal:**

The request asks for an analysis of the provided Go code snippet, specifically the `textproto.Reader` type. The core tasks are:

* **List functionalities:** Identify what the code does.
* **Infer purpose:**  Figure out what broader Go feature it contributes to.
* **Provide Go examples:** Demonstrate usage with code snippets.
* **Handle code inference:**  If reasoning about code behavior, include example inputs and outputs.
* **Address command-line arguments:** Explain any command-line interaction (though this isn't relevant in this specific code).
* **Highlight common mistakes:** Point out potential pitfalls for users.
* **Respond in Chinese.**

**2. Initial Code Scan and High-Level Understanding:**

A quick read-through reveals several key aspects:

* **`package textproto`:** This immediately suggests handling text-based network protocols.
* **`Reader` struct:**  This is the central type, containing a `bufio.Reader`. This signals buffered reading from an underlying `io.Reader`.
* **Methods like `ReadLine`, `ReadContinuedLine`, `ReadCodeLine`, `ReadResponse`, `DotReader`, `ReadMIMEHeader`:** These names strongly indicate parsing and processing of structured text data commonly found in network protocols (like HTTP, SMTP, etc.).
* **Error handling (e.g., `errMessageTooLarge`, `ProtocolError`):**  Indicates robustness and awareness of potential issues.

**3. Deeper Dive into Functionalities:**

Now, examine each method in more detail:

* **`NewReader`:**  Simple constructor. The comment about `io.LimitReader` is important for security.
* **`ReadLine`, `ReadLineBytes`:** Basic line reading, removing newline characters. The distinction between string and byte slice is clear.
* **`readContinuedLineSlice`, `ReadContinuedLine`, `ReadContinuedLineBytes`:** This handles the common pattern of continued lines (starting with space/tab) in some protocols. The `trim` function is relevant here.
* **`skipSpace`:**  Utility for skipping leading whitespace.
* **`readCodeLine`, `parseCodeLine`, `ReadCodeLine`:** Deals with parsing response codes, often seen in protocols like SMTP, FTP. The `expectCode` parameter is crucial.
* **`ReadResponse`:** Handles multi-line responses based on status codes.
* **`DotReader`, `dotReader`, `ReadDotBytes`, `ReadDotLines`:**  Implements "dot encoding," a specific framing mechanism used in some protocols (like SMTP for message bodies). The state machine in `dotReader.Read` is the core logic here.
* **`ReadMIMEHeader`, `readMIMEHeader`, helper functions (`mustHaveFieldNameColon`, `canonicalMIMEHeaderKey`, etc.):**  Focuses on parsing MIME headers, which are key-value pairs with potential line continuations. This strongly suggests applications in email, HTTP, etc.

**4. Inferring the Go Language Feature:**

Based on the functionality, the most likely Go feature being implemented is **support for text-based network protocols.**  The methods align perfectly with common tasks when interacting with such protocols.

**5. Crafting Go Examples:**

For each significant functionality, create a concise Go example. Think about:

* **Basic usage:**  Demonstrate the simplest case.
* **Illustrative input:**  Provide sample text that the function would process.
* **Expected output:** Show what the function would return for the given input.

For example, for `ReadContinuedLine`, the example should show a continued line and the expected merged output. For `ReadCodeLine`, demonstrate both successful and error cases based on `expectCode`. For `DotReader`, show the input with dot-encoding and the decoded output. For `ReadMIMEHeader`, provide a typical header structure and the resulting map.

**6. Addressing Code Inference (Inputs and Outputs):**

This was largely covered in the "Crafting Go Examples" step. The examples inherently involve code inference by showing the transformation of input to output.

**7. Command-Line Arguments:**

Recognize that this code doesn't directly deal with command-line arguments. State this explicitly.

**8. Identifying Common Mistakes:**

Think about potential errors users might make when using this package:

* **Forgetting to use `io.LimitReader`:** This is a security concern, so it's a high-priority mistake to highlight.
* **Misunderstanding `expectCode` in `ReadCodeLine` and `ReadResponse`:** Explain how it filters responses.
* **Incorrectly handling dot-encoding:** Emphasize the need for the ending ".\r\n".
* **MIME header parsing issues:** Point out common pitfalls like missing colons or incorrect formatting.

**9. Structuring the Answer:**

Organize the information logically:

* Start with a summary of the overall functionality.
* Detail each function's purpose.
* Explain the inferred Go feature.
* Provide illustrative Go examples.
* Address code inference with input/output.
* State the absence of command-line argument handling.
* Discuss common mistakes.
* Conclude with a summary.

**10. Translation to Chinese:**

Translate all the generated text into clear and accurate Chinese. Pay attention to technical terms and ensure the meaning is preserved. This requires careful wording and potentially using more formal language when describing technical concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is just about basic text reading.
* **Correction:** The specific methods for handling continued lines, response codes, and MIME headers point to network protocols.
* **Initial example:** A simple `ReadLine` example is good, but also show the byte slice version.
* **Refinement:**  The `DotReader` example needs to clearly demonstrate the dot escaping and the final ".".
* **Initial explanation of `expectCode`:** Could be clearer. Emphasize the filtering aspect.

By following these steps, systematically analyzing the code, and refining the explanation, we can arrive at a comprehensive and accurate answer like the example provided in the prompt.
这段 Go 语言代码是 `net/textproto` 包中 `reader.go` 文件的一部分，它定义了一个 `Reader` 结构体和相关方法，用于方便地从文本协议网络连接中读取请求或响应。

**主要功能:**

1. **基本的行读取:**
   - `ReadLine()`: 读取单行文本，并移除行尾的 `\n` 或 `\r\n`。返回字符串。
   - `ReadLineBytes()`: 与 `ReadLine()` 类似，但返回 `[]byte` 切片。
   - `readLineSlice()`:  `ReadLine` 和 `ReadLineBytes` 的底层实现，可以限制读取的字节数。

2. **读取连续行:**
   - `ReadContinuedLine()`: 读取可能被续行的文本。如果后续行以空格或制表符开头，则被认为是前一行的延续。续行会合并到前一行，并用单个空格分隔。
   - `ReadContinuedLineBytes()`: 与 `ReadContinuedLine()` 类似，但返回 `[]byte` 切片。
   - `readContinuedLineSlice()`: `ReadContinuedLine` 和 `ReadContinuedLineBytes` 的底层实现，处理续行逻辑。

3. **跳过空格:**
   - `skipSpace()`: 跳过输入流中的所有空格和制表符，并返回跳过的字节数。

4. **读取状态码行:**
   - `ReadCodeLine(expectCode int)`: 读取类似 "220 plan9.bell-labs.com ESMTP" 格式的响应代码行。它会检查状态码是否与 `expectCode` 的前缀匹配（如果 `expectCode > 0`）。如果响应是多行的，则返回错误。
   - `readCodeLine(expectCode int)`: `ReadCodeLine` 的底层实现，返回状态码、是否续行以及消息内容。
   - `parseCodeLine(line string, expectCode int)`: 解析代码行，提取状态码、是否续行以及消息。

5. **读取多行响应:**
   - `ReadResponse(expectCode int)`: 读取类似如下格式的多行响应：
     ```
     code-message line 1
     code-message line 2
     ...
     code message line n
     ```
     它会检查每行的状态码前缀，并将多行消息合并成一个字符串。

6. **处理 Dot-Encoding (点编码):**
   - `DotReader() io.Reader`: 返回一个新的 `io.Reader`，它解码从原始 `Reader` 读取的 dot-encoded 数据块。Dot-encoding 是一种常见的文本协议数据块 framing 方式，例如 SMTP。
   - `dotReader` 结构体和其 `Read()` 方法: 实现了 Dot-encoding 的解码逻辑。
   - `ReadDotBytes()`: 读取 dot-encoding 的数据并返回解码后的 `[]byte`。
   - `ReadDotLines()`: 读取 dot-encoding 的数据并返回解码后的行切片。
   - `closeDot()`: 清理当前的 `DotReader`。

7. **读取 MIME 头部:**
   - `ReadMIMEHeader() MIMEHeader`: 读取 MIME 风格的头部信息。头部由一系列可能续行的 "Key: Value" 行组成，以一个空行结束。返回一个 `MIMEHeader` 类型的 map。
   - `readMIMEHeader()`: `ReadMIMEHeader` 的底层实现，可以限制头部大小。
   - 辅助函数: `mustHaveFieldNameColon`, `canonicalMIMEHeaderKey`, `validHeaderFieldByte`, `validHeaderValueByte`, `upcomingHeaderKeys` 用于 MIME 头部解析。

**推理：这是 Go 语言 `net/textproto` 包中用于处理文本协议的一部分实现。**

该包旨在简化编写与基于文本的网络协议（如 HTTP、SMTP、FTP 等）交互的 Go 程序。 `Reader` 结构体提供了一系列方法来方便地解析这些协议中常见的文本格式，例如行、续行、状态码和头部信息。

**Go 代码示例:**

以下示例演示了 `Reader` 的一些功能：

```go
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

func main() {
	// 假设我们有一个网络连接
	conn, err := net.Dial("tcp", "smtp.example.com:25")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	reader := textproto.NewReader(bufio.NewReader(conn))

	// 读取服务器的欢迎消息
	code, msg, err := reader.ReadCodeLine(2) // 期望以 2 开头的状态码
	if err != nil {
		fmt.Println("Error reading welcome message:", err)
		return
	}
	fmt.Printf("Welcome message: %d %s\n", code, msg)

	// 发送 EHLO 命令
	fmt.Fprintf(conn, "EHLO mydomain.com\r\n")

	// 读取 EHLO 响应
	code, msg, err = reader.ReadResponse(2) // 期望以 2 开头的状态码的多行响应
	if err != nil {
		fmt.Println("Error reading EHLO response:", err)
		return
	}
	fmt.Printf("EHLO response: %d\n%s\n", code, msg)

	// 读取 MIME 头部 (假设有这样一个场景)
	headerText := `Content-Type: text/plain; charset=utf-8
Subject: Test Email
X-Custom-Header: Value 1
 X-Custom-Header: Value 2

`
	headerReader := textproto.NewReader(bufio.NewReader(strings.NewReader(headerText)))
	mimeHeader, err := headerReader.ReadMIMEHeader()
	if err != nil {
		fmt.Println("Error reading MIME header:", err)
		return
	}
	fmt.Println("MIME Header:", mimeHeader)

	// 读取 Dot-Encoded 数据 (假设有这样一个场景)
	dotEncodedData := `This is line 1.
This is line 2.
.
This is after the dot.
`
	dotReader := textproto.NewReader(bufio.NewReader(strings.NewReader(dotEncodedData)))
	dotDataReader := dotReader.DotReader()
	buf := new(strings.Builder)
	_, err = buf.ReadFrom(dotDataReader)
	if err != nil {
		fmt.Println("Error reading dot-encoded data:", err)
		return
	}
	fmt.Println("Decoded Dot Data:\n", buf.String())
}
```

**代码推理 (以 `ReadContinuedLine` 为例):**

**假设输入:**

```
Line 1
  continued...
Line 2
```

**执行 `ReadContinuedLine()` 第一次:**

1. `readLineSlice()` 读取第一行 "Line 1"。
2. `readContinuedLineSlice()` 发现下一行以空格开头。
3. 再次调用 `readLineSlice()` 读取 "  continued..."。
4. `trim()` 函数移除 "  continued..." 前后的空格，得到 "continued..."。
5. 将 "continued..." 添加到 "Line 1" 后面，中间加一个空格，结果为 "Line 1 continued..."。
6. 返回 "Line 1 continued...", `err` 为 `nil`。

**执行 `ReadContinuedLine()` 第二次:**

1. `readLineSlice()` 读取 "Line 2"。
2. 因为下一行不是以空格或制表符开头，所以不认为是续行。
3. 返回 "Line 2", `err` 为 `nil`。

**假设输入字节数超过限制 (在 `readContinuedLineSlice` 中 `lim` 有效):**

```
This is a very long line that exceeds the limit.
  This part continues the long line.
```

**执行 `ReadContinuedLine()` (假设 `lim` 设置了一个较小的值):**

1. `readLineSlice()` 在读取第一行时，如果超过 `lim`，会返回 `errMessageTooLarge` 错误。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。 `net/textproto` 包主要用于网络协议处理，通常在服务器或客户端程序中使用，这些程序可能会通过其他方式（例如 `flag` 包）处理命令行参数。

**使用者易犯错的点:**

1. **忘记使用 `io.LimitReader` 进行安全限制:**  `NewReader` 的文档中明确指出，为了防止拒绝服务攻击，应该使用 `io.LimitReader` 或类似的 Reader 来限制响应的大小。如果不对输入进行限制，恶意服务器可能会发送巨大的响应，导致程序消耗大量内存甚至崩溃。

   **错误示例:**

   ```go
   conn, _ := net.Dial("tcp", "vulnerable.example.com:80")
   reader := textproto.NewReader(bufio.NewReader(conn)) // 潜在的安全风险
   line, _ := reader.ReadLine()
   ```

   **正确示例:**

   ```go
   conn, _ := net.Dial("tcp", "vulnerable.example.com:80")
   limitedReader := io.LimitReader(conn, 1024) // 限制读取 1KB
   reader := textproto.NewReader(bufio.NewReader(limitedReader))
   line, err := reader.ReadLine()
   if err == io.ErrUnexpectedEOF {
       fmt.Println("Response too large")
   }
   ```

2. **对 `ReadCodeLine` 和 `ReadResponse` 的 `expectCode` 理解错误:**  `expectCode` 不是期望的完整状态码，而是状态码的前缀。例如，如果期望 2xx 范围内的状态码，应该传递 `2`。如果传递了完整的状态码，只会匹配完全相同的状态码，这通常不是预期的行为。

   **错误示例 (期望任何 2xx 状态码，但传递了 200):**

   ```go
   code, _, err := reader.ReadCodeLine(200) // 只会匹配状态码 200
   if err != nil {
       // 如果服务器返回 220，这里会出错
   }
   ```

   **正确示例 (期望任何 2xx 状态码):**

   ```go
   code, _, err := reader.ReadCodeLine(2) // 会匹配 200, 220, 250 等
   if err != nil {
       // 处理错误
   }
   ```

3. **不理解 Dot-Encoding 的结束符:** 使用 `DotReader` 时，必须确保输入流以 ".\r\n" 结尾，否则 `Read` 方法会一直读取下去，直到遇到 EOF 或错误。

   **易错场景:**  手动构造 Dot-Encoded 数据时忘记添加结束符。

4. **MIME 头部格式错误:** MIME 头部有严格的格式要求，例如键值对之间必须用冒号分隔，第一行不能以空格或制表符开头等。不符合规范的头部会导致 `ReadMIMEHeader` 返回错误。

这段代码为处理文本协议提供了强大的工具，但使用者需要注意潜在的安全风险和 API 的正确使用方式。

### 提示词
```
这是路径为go/src/net/textproto/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	_ "unsafe" // for linkname
)

// TODO: This should be a distinguishable error (ErrMessageTooLarge)
// to allow mime/multipart to detect it.
var errMessageTooLarge = errors.New("message too large")

// A Reader implements convenience methods for reading requests
// or responses from a text protocol network connection.
type Reader struct {
	R   *bufio.Reader
	dot *dotReader
	buf []byte // a re-usable buffer for readContinuedLineSlice
}

// NewReader returns a new [Reader] reading from r.
//
// To avoid denial of service attacks, the provided [bufio.Reader]
// should be reading from an [io.LimitReader] or similar Reader to bound
// the size of responses.
func NewReader(r *bufio.Reader) *Reader {
	return &Reader{R: r}
}

// ReadLine reads a single line from r,
// eliding the final \n or \r\n from the returned string.
func (r *Reader) ReadLine() (string, error) {
	line, err := r.readLineSlice(-1)
	return string(line), err
}

// ReadLineBytes is like [Reader.ReadLine] but returns a []byte instead of a string.
func (r *Reader) ReadLineBytes() ([]byte, error) {
	line, err := r.readLineSlice(-1)
	if line != nil {
		line = bytes.Clone(line)
	}
	return line, err
}

// readLineSlice reads a single line from r,
// up to lim bytes long (or unlimited if lim is less than 0),
// eliding the final \r or \r\n from the returned string.
func (r *Reader) readLineSlice(lim int64) ([]byte, error) {
	r.closeDot()
	var line []byte
	for {
		l, more, err := r.R.ReadLine()
		if err != nil {
			return nil, err
		}
		if lim >= 0 && int64(len(line))+int64(len(l)) > lim {
			return nil, errMessageTooLarge
		}
		// Avoid the copy if the first call produced a full line.
		if line == nil && !more {
			return l, nil
		}
		line = append(line, l...)
		if !more {
			break
		}
	}
	return line, nil
}

// ReadContinuedLine reads a possibly continued line from r,
// eliding the final trailing ASCII white space.
// Lines after the first are considered continuations if they
// begin with a space or tab character. In the returned data,
// continuation lines are separated from the previous line
// only by a single space: the newline and leading white space
// are removed.
//
// For example, consider this input:
//
//	Line 1
//	  continued...
//	Line 2
//
// The first call to ReadContinuedLine will return "Line 1 continued..."
// and the second will return "Line 2".
//
// Empty lines are never continued.
func (r *Reader) ReadContinuedLine() (string, error) {
	line, err := r.readContinuedLineSlice(-1, noValidation)
	return string(line), err
}

// trim returns s with leading and trailing spaces and tabs removed.
// It does not assume Unicode or UTF-8.
func trim(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	n := len(s)
	for n > i && (s[n-1] == ' ' || s[n-1] == '\t') {
		n--
	}
	return s[i:n]
}

// ReadContinuedLineBytes is like [Reader.ReadContinuedLine] but
// returns a []byte instead of a string.
func (r *Reader) ReadContinuedLineBytes() ([]byte, error) {
	line, err := r.readContinuedLineSlice(-1, noValidation)
	if line != nil {
		line = bytes.Clone(line)
	}
	return line, err
}

// readContinuedLineSlice reads continued lines from the reader buffer,
// returning a byte slice with all lines. The validateFirstLine function
// is run on the first read line, and if it returns an error then this
// error is returned from readContinuedLineSlice.
// It reads up to lim bytes of data (or unlimited if lim is less than 0).
func (r *Reader) readContinuedLineSlice(lim int64, validateFirstLine func([]byte) error) ([]byte, error) {
	if validateFirstLine == nil {
		return nil, fmt.Errorf("missing validateFirstLine func")
	}

	// Read the first line.
	line, err := r.readLineSlice(lim)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 { // blank line - no continuation
		return line, nil
	}

	if err := validateFirstLine(line); err != nil {
		return nil, err
	}

	// Optimistically assume that we have started to buffer the next line
	// and it starts with an ASCII letter (the next header key), or a blank
	// line, so we can avoid copying that buffered data around in memory
	// and skipping over non-existent whitespace.
	if r.R.Buffered() > 1 {
		peek, _ := r.R.Peek(2)
		if len(peek) > 0 && (isASCIILetter(peek[0]) || peek[0] == '\n') ||
			len(peek) == 2 && peek[0] == '\r' && peek[1] == '\n' {
			return trim(line), nil
		}
	}

	// ReadByte or the next readLineSlice will flush the read buffer;
	// copy the slice into buf.
	r.buf = append(r.buf[:0], trim(line)...)

	if lim < 0 {
		lim = math.MaxInt64
	}
	lim -= int64(len(r.buf))

	// Read continuation lines.
	for r.skipSpace() > 0 {
		r.buf = append(r.buf, ' ')
		if int64(len(r.buf)) >= lim {
			return nil, errMessageTooLarge
		}
		line, err := r.readLineSlice(lim - int64(len(r.buf)))
		if err != nil {
			break
		}
		r.buf = append(r.buf, trim(line)...)
	}
	return r.buf, nil
}

// skipSpace skips R over all spaces and returns the number of bytes skipped.
func (r *Reader) skipSpace() int {
	n := 0
	for {
		c, err := r.R.ReadByte()
		if err != nil {
			// Bufio will keep err until next read.
			break
		}
		if c != ' ' && c != '\t' {
			r.R.UnreadByte()
			break
		}
		n++
	}
	return n
}

func (r *Reader) readCodeLine(expectCode int) (code int, continued bool, message string, err error) {
	line, err := r.ReadLine()
	if err != nil {
		return
	}
	return parseCodeLine(line, expectCode)
}

func parseCodeLine(line string, expectCode int) (code int, continued bool, message string, err error) {
	if len(line) < 4 || line[3] != ' ' && line[3] != '-' {
		err = ProtocolError("short response: " + line)
		return
	}
	continued = line[3] == '-'
	code, err = strconv.Atoi(line[0:3])
	if err != nil || code < 100 {
		err = ProtocolError("invalid response code: " + line)
		return
	}
	message = line[4:]
	if 1 <= expectCode && expectCode < 10 && code/100 != expectCode ||
		10 <= expectCode && expectCode < 100 && code/10 != expectCode ||
		100 <= expectCode && expectCode < 1000 && code != expectCode {
		err = &Error{code, message}
	}
	return
}

// ReadCodeLine reads a response code line of the form
//
//	code message
//
// where code is a three-digit status code and the message
// extends to the rest of the line. An example of such a line is:
//
//	220 plan9.bell-labs.com ESMTP
//
// If the prefix of the status does not match the digits in expectCode,
// ReadCodeLine returns with err set to &Error{code, message}.
// For example, if expectCode is 31, an error will be returned if
// the status is not in the range [310,319].
//
// If the response is multi-line, ReadCodeLine returns an error.
//
// An expectCode <= 0 disables the check of the status code.
func (r *Reader) ReadCodeLine(expectCode int) (code int, message string, err error) {
	code, continued, message, err := r.readCodeLine(expectCode)
	if err == nil && continued {
		err = ProtocolError("unexpected multi-line response: " + message)
	}
	return
}

// ReadResponse reads a multi-line response of the form:
//
//	code-message line 1
//	code-message line 2
//	...
//	code message line n
//
// where code is a three-digit status code. The first line starts with the
// code and a hyphen. The response is terminated by a line that starts
// with the same code followed by a space. Each line in message is
// separated by a newline (\n).
//
// See page 36 of RFC 959 (https://www.ietf.org/rfc/rfc959.txt) for
// details of another form of response accepted:
//
//	code-message line 1
//	message line 2
//	...
//	code message line n
//
// If the prefix of the status does not match the digits in expectCode,
// ReadResponse returns with err set to &Error{code, message}.
// For example, if expectCode is 31, an error will be returned if
// the status is not in the range [310,319].
//
// An expectCode <= 0 disables the check of the status code.
func (r *Reader) ReadResponse(expectCode int) (code int, message string, err error) {
	code, continued, message, err := r.readCodeLine(expectCode)
	multi := continued
	for continued {
		line, err := r.ReadLine()
		if err != nil {
			return 0, "", err
		}

		var code2 int
		var moreMessage string
		code2, continued, moreMessage, err = parseCodeLine(line, 0)
		if err != nil || code2 != code {
			message += "\n" + strings.TrimRight(line, "\r\n")
			continued = true
			continue
		}
		message += "\n" + moreMessage
	}
	if err != nil && multi && message != "" {
		// replace one line error message with all lines (full message)
		err = &Error{code, message}
	}
	return
}

// DotReader returns a new [Reader] that satisfies Reads using the
// decoded text of a dot-encoded block read from r.
// The returned Reader is only valid until the next call
// to a method on r.
//
// Dot encoding is a common framing used for data blocks
// in text protocols such as SMTP.  The data consists of a sequence
// of lines, each of which ends in "\r\n".  The sequence itself
// ends at a line containing just a dot: ".\r\n".  Lines beginning
// with a dot are escaped with an additional dot to avoid
// looking like the end of the sequence.
//
// The decoded form returned by the Reader's Read method
// rewrites the "\r\n" line endings into the simpler "\n",
// removes leading dot escapes if present, and stops with error [io.EOF]
// after consuming (and discarding) the end-of-sequence line.
func (r *Reader) DotReader() io.Reader {
	r.closeDot()
	r.dot = &dotReader{r: r}
	return r.dot
}

type dotReader struct {
	r     *Reader
	state int
}

// Read satisfies reads by decoding dot-encoded data read from d.r.
func (d *dotReader) Read(b []byte) (n int, err error) {
	// Run data through a simple state machine to
	// elide leading dots, rewrite trailing \r\n into \n,
	// and detect ending .\r\n line.
	const (
		stateBeginLine = iota // beginning of line; initial state; must be zero
		stateDot              // read . at beginning of line
		stateDotCR            // read .\r at beginning of line
		stateCR               // read \r (possibly at end of line)
		stateData             // reading data in middle of line
		stateEOF              // reached .\r\n end marker line
	)
	br := d.r.R
	for n < len(b) && d.state != stateEOF {
		var c byte
		c, err = br.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			break
		}
		switch d.state {
		case stateBeginLine:
			if c == '.' {
				d.state = stateDot
				continue
			}
			if c == '\r' {
				d.state = stateCR
				continue
			}
			d.state = stateData

		case stateDot:
			if c == '\r' {
				d.state = stateDotCR
				continue
			}
			if c == '\n' {
				d.state = stateEOF
				continue
			}
			d.state = stateData

		case stateDotCR:
			if c == '\n' {
				d.state = stateEOF
				continue
			}
			// Not part of .\r\n.
			// Consume leading dot and emit saved \r.
			br.UnreadByte()
			c = '\r'
			d.state = stateData

		case stateCR:
			if c == '\n' {
				d.state = stateBeginLine
				break
			}
			// Not part of \r\n. Emit saved \r
			br.UnreadByte()
			c = '\r'
			d.state = stateData

		case stateData:
			if c == '\r' {
				d.state = stateCR
				continue
			}
			if c == '\n' {
				d.state = stateBeginLine
			}
		}
		b[n] = c
		n++
	}
	if err == nil && d.state == stateEOF {
		err = io.EOF
	}
	if err != nil && d.r.dot == d {
		d.r.dot = nil
	}
	return
}

// closeDot drains the current DotReader if any,
// making sure that it reads until the ending dot line.
func (r *Reader) closeDot() {
	if r.dot == nil {
		return
	}
	buf := make([]byte, 128)
	for r.dot != nil {
		// When Read reaches EOF or an error,
		// it will set r.dot == nil.
		r.dot.Read(buf)
	}
}

// ReadDotBytes reads a dot-encoding and returns the decoded data.
//
// See the documentation for the [Reader.DotReader] method for details about dot-encoding.
func (r *Reader) ReadDotBytes() ([]byte, error) {
	return io.ReadAll(r.DotReader())
}

// ReadDotLines reads a dot-encoding and returns a slice
// containing the decoded lines, with the final \r\n or \n elided from each.
//
// See the documentation for the [Reader.DotReader] method for details about dot-encoding.
func (r *Reader) ReadDotLines() ([]string, error) {
	// We could use ReadDotBytes and then Split it,
	// but reading a line at a time avoids needing a
	// large contiguous block of memory and is simpler.
	var v []string
	var err error
	for {
		var line string
		line, err = r.ReadLine()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			break
		}

		// Dot by itself marks end; otherwise cut one dot.
		if len(line) > 0 && line[0] == '.' {
			if len(line) == 1 {
				break
			}
			line = line[1:]
		}
		v = append(v, line)
	}
	return v, err
}

var colon = []byte(":")

// ReadMIMEHeader reads a MIME-style header from r.
// The header is a sequence of possibly continued Key: Value lines
// ending in a blank line.
// The returned map m maps [CanonicalMIMEHeaderKey](key) to a
// sequence of values in the same order encountered in the input.
//
// For example, consider this input:
//
//	My-Key: Value 1
//	Long-Key: Even
//	       Longer Value
//	My-Key: Value 2
//
// Given that input, ReadMIMEHeader returns the map:
//
//	map[string][]string{
//		"My-Key": {"Value 1", "Value 2"},
//		"Long-Key": {"Even Longer Value"},
//	}
func (r *Reader) ReadMIMEHeader() (MIMEHeader, error) {
	return readMIMEHeader(r, math.MaxInt64, math.MaxInt64)
}

// readMIMEHeader is accessed from mime/multipart.
//go:linkname readMIMEHeader

// readMIMEHeader is a version of ReadMIMEHeader which takes a limit on the header size.
// It is called by the mime/multipart package.
func readMIMEHeader(r *Reader, maxMemory, maxHeaders int64) (MIMEHeader, error) {
	// Avoid lots of small slice allocations later by allocating one
	// large one ahead of time which we'll cut up into smaller
	// slices. If this isn't big enough later, we allocate small ones.
	var strs []string
	hint := r.upcomingHeaderKeys()
	if hint > 0 {
		if hint > 1000 {
			hint = 1000 // set a cap to avoid overallocation
		}
		strs = make([]string, hint)
	}

	m := make(MIMEHeader, hint)

	// Account for 400 bytes of overhead for the MIMEHeader, plus 200 bytes per entry.
	// Benchmarking map creation as of go1.20, a one-entry MIMEHeader is 416 bytes and large
	// MIMEHeaders average about 200 bytes per entry.
	maxMemory -= 400
	const mapEntryOverhead = 200

	// The first line cannot start with a leading space.
	if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t') {
		const errorLimit = 80 // arbitrary limit on how much of the line we'll quote
		line, err := r.readLineSlice(errorLimit)
		if err != nil {
			return m, err
		}
		return m, ProtocolError("malformed MIME header initial line: " + string(line))
	}

	for {
		kv, err := r.readContinuedLineSlice(maxMemory, mustHaveFieldNameColon)
		if len(kv) == 0 {
			return m, err
		}

		// Key ends at first colon.
		k, v, ok := bytes.Cut(kv, colon)
		if !ok {
			return m, ProtocolError("malformed MIME header line: " + string(kv))
		}
		key, ok := canonicalMIMEHeaderKey(k)
		if !ok {
			return m, ProtocolError("malformed MIME header line: " + string(kv))
		}
		for _, c := range v {
			if !validHeaderValueByte(c) {
				return m, ProtocolError("malformed MIME header line: " + string(kv))
			}
		}

		maxHeaders--
		if maxHeaders < 0 {
			return nil, errMessageTooLarge
		}

		// Skip initial spaces in value.
		value := string(bytes.TrimLeft(v, " \t"))

		vv := m[key]
		if vv == nil {
			maxMemory -= int64(len(key))
			maxMemory -= mapEntryOverhead
		}
		maxMemory -= int64(len(value))
		if maxMemory < 0 {
			return m, errMessageTooLarge
		}
		if vv == nil && len(strs) > 0 {
			// More than likely this will be a single-element key.
			// Most headers aren't multi-valued.
			// Set the capacity on strs[0] to 1, so any future append
			// won't extend the slice into the other strings.
			vv, strs = strs[:1:1], strs[1:]
			vv[0] = value
			m[key] = vv
		} else {
			m[key] = append(vv, value)
		}

		if err != nil {
			return m, err
		}
	}
}

// noValidation is a no-op validation func for readContinuedLineSlice
// that permits any lines.
func noValidation(_ []byte) error { return nil }

// mustHaveFieldNameColon ensures that, per RFC 7230, the
// field-name is on a single line, so the first line must
// contain a colon.
func mustHaveFieldNameColon(line []byte) error {
	if bytes.IndexByte(line, ':') < 0 {
		return ProtocolError(fmt.Sprintf("malformed MIME header: missing colon: %q", line))
	}
	return nil
}

var nl = []byte("\n")

// upcomingHeaderKeys returns an approximation of the number of keys
// that will be in this header. If it gets confused, it returns 0.
func (r *Reader) upcomingHeaderKeys() (n int) {
	// Try to determine the 'hint' size.
	r.R.Peek(1) // force a buffer load if empty
	s := r.R.Buffered()
	if s == 0 {
		return
	}
	peek, _ := r.R.Peek(s)
	for len(peek) > 0 && n < 1000 {
		var line []byte
		line, peek, _ = bytes.Cut(peek, nl)
		if len(line) == 0 || (len(line) == 1 && line[0] == '\r') {
			// Blank line separating headers from the body.
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Folded continuation of the previous line.
			continue
		}
		n++
	}
	return n
}

// CanonicalMIMEHeaderKey returns the canonical format of the
// MIME header key s. The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase. For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// MIME header keys are assumed to be ASCII only.
// If s contains a space or invalid header field bytes, it is
// returned without modifications.
func CanonicalMIMEHeaderKey(s string) string {
	// Quick check for canonical encoding.
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !validHeaderFieldByte(c) {
			return s
		}
		if upper && 'a' <= c && c <= 'z' {
			s, _ = canonicalMIMEHeaderKey([]byte(s))
			return s
		}
		if !upper && 'A' <= c && c <= 'Z' {
			s, _ = canonicalMIMEHeaderKey([]byte(s))
			return s
		}
		upper = c == '-'
	}
	return s
}

const toLower = 'a' - 'A'

// validHeaderFieldByte reports whether c is a valid byte in a header
// field name. RFC 7230 says:
//
//	header-field   = field-name ":" OWS field-value OWS
//	field-name     = token
//	tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//	        "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
//	token = 1*tchar
func validHeaderFieldByte(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c >= 128, then 1<<c and 1<<(c-64) will both be zero,
	// and this function will return false.
	const mask = 0 |
		(1<<(10)-1)<<'0' |
		(1<<(26)-1)<<'a' |
		(1<<(26)-1)<<'A' |
		1<<'!' |
		1<<'#' |
		1<<'$' |
		1<<'%' |
		1<<'&' |
		1<<'\'' |
		1<<'*' |
		1<<'+' |
		1<<'-' |
		1<<'.' |
		1<<'^' |
		1<<'_' |
		1<<'`' |
		1<<'|' |
		1<<'~'
	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}

// validHeaderValueByte reports whether c is a valid byte in a header
// field value. RFC 7230 says:
//
//	field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
//	field-vchar    = VCHAR / obs-text
//	obs-text       = %x80-FF
//
// RFC 5234 says:
//
//	HTAB           =  %x09
//	SP             =  %x20
//	VCHAR          =  %x21-7E
func validHeaderValueByte(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c >= 128, then 1<<c and 1<<(c-64) will both be zero.
	// Since this is the obs-text range, we invert the mask to
	// create a bitmap with 1s for disallowed bytes.
	const mask = 0 |
		(1<<(0x7f-0x21)-1)<<0x21 | // VCHAR: %x21-7E
		1<<0x20 | // SP: %x20
		1<<0x09 // HTAB: %x09
	return ((uint64(1)<<c)&^(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&^(mask>>64)) == 0
}

// canonicalMIMEHeaderKey is like CanonicalMIMEHeaderKey but is
// allowed to mutate the provided byte slice before returning the
// string.
//
// For invalid inputs (if a contains spaces or non-token bytes), a
// is unchanged and a string copy is returned.
//
// ok is true if the header key contains only valid characters and spaces.
// ReadMIMEHeader accepts header keys containing spaces, but does not
// canonicalize them.
func canonicalMIMEHeaderKey(a []byte) (_ string, ok bool) {
	if len(a) == 0 {
		return "", false
	}

	// See if a looks like a header key. If not, return it unchanged.
	noCanon := false
	for _, c := range a {
		if validHeaderFieldByte(c) {
			continue
		}
		// Don't canonicalize.
		if c == ' ' {
			// We accept invalid headers with a space before the
			// colon, but must not canonicalize them.
			// See https://go.dev/issue/34540.
			noCanon = true
			continue
		}
		return string(a), false
	}
	if noCanon {
		return string(a), true
	}

	upper := true
	for i, c := range a {
		// Canonicalize: first letter upper case
		// and upper case after each dash.
		// (Host, User-Agent, If-Modified-Since).
		// MIME headers are ASCII only, so no Unicode issues.
		if upper && 'a' <= c && c <= 'z' {
			c -= toLower
		} else if !upper && 'A' <= c && c <= 'Z' {
			c += toLower
		}
		a[i] = c
		upper = c == '-' // for next time
	}
	commonHeaderOnce.Do(initCommonHeader)
	// The compiler recognizes m[string(byteSlice)] as a special
	// case, so a copy of a's bytes into a new string does not
	// happen in this map lookup:
	if v := commonHeader[string(a)]; v != "" {
		return v, true
	}
	return string(a), true
}

// commonHeader interns common header strings.
var commonHeader map[string]string

var commonHeaderOnce sync.Once

func initCommonHeader() {
	commonHeader = make(map[string]string)
	for _, v := range []string{
		"Accept",
		"Accept-Charset",
		"Accept-Encoding",
		"Accept-Language",
		"Accept-Ranges",
		"Cache-Control",
		"Cc",
		"Connection",
		"Content-Id",
		"Content-Language",
		"Content-Length",
		"Content-Transfer-Encoding",
		"Content-Type",
		"Cookie",
		"Date",
		"Dkim-Signature",
		"Etag",
		"Expires",
		"From",
		"Host",
		"If-Modified-Since",
		"If-None-Match",
		"In-Reply-To",
		"Last-Modified",
		"Location",
		"Message-Id",
		"Mime-Version",
		"Pragma",
		"Received",
		"Return-Path",
		"Server",
		"Set-Cookie",
		"Subject",
		"To",
		"User-Agent",
		"Via",
		"X-Forwarded-For",
		"X-Imforwards",
		"X-Powered-By",
	} {
		commonHeader[v] = v
	}
}
```