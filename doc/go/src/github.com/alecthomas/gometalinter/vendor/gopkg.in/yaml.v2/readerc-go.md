Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file name `readerc.go` and the package name `yaml` immediately suggest that this code is involved in reading YAML data. The "c" in `readerc.go` likely hints at some lower-level or core reading functionality.

2. **Examine Key Functions:**  The first step is to look at the exported functions (those with uppercase names). We see:
    * `yaml_parser_set_reader_error`:  This clearly deals with error handling during the reading process.
    * `yaml_parser_determine_encoding`: This suggests the code needs to figure out how the input YAML is encoded (UTF-8, UTF-16).
    * `yaml_parser_update_raw_buffer`: This looks like a function to load more raw bytes from the input source.
    * `yaml_parser_update_buffer`:  This seems to be a higher-level function that manages a buffer of decoded characters.

3. **Analyze Data Structures:**  The code refers to `yaml_parser_t`. While the full definition isn't here, we can infer some of its members:
    * `error`:  Likely an error code or enum.
    * `problem`: A string describing the error.
    * `problem_offset`: The byte offset where the error occurred.
    * `problem_value`:  Potentially the problematic byte/character value.
    * `raw_buffer`: A byte slice to hold raw input data.
    * `raw_buffer_pos`: An integer indicating the current position in `raw_buffer`.
    * `eof`: A boolean flag for "end of file."
    * `encoding`: An enum or constant representing the text encoding.
    * `offset`:  The overall byte offset in the input stream.
    * `read_handler`: A function or method responsible for actually reading data from the source.
    * `buffer`: A byte slice to hold decoded characters.
    * `buffer_pos`:  The current position in the `buffer`.
    * `unread`: The number of decoded characters available in `buffer`.

4. **Trace the Workflow (Hypothesize):** Based on the function names and the inferred data structures, we can create a mental model of how the reading process might work:
    * An input stream needs to be read.
    * The encoding might be specified or needs to be detected (using BOM).
    * Raw bytes are read into `raw_buffer`.
    * The raw bytes are decoded into characters based on the encoding and stored in `buffer`.
    * The `unread` counter keeps track of the available decoded characters.
    * Errors during reading or decoding are reported using `yaml_parser_set_reader_error`.

5. **Focus on Key Logic within Functions:**
    * **`yaml_parser_determine_encoding`:**  It checks for Byte Order Marks (BOMs) to determine UTF-8, UTF-16LE, or UTF-16BE encoding. If no BOM is found, it defaults to UTF-8.
    * **`yaml_parser_update_raw_buffer`:** It reads data from the `read_handler` (which is assumed to be set up elsewhere) into the `raw_buffer`. It handles potential `io.EOF` and other errors.
    * **`yaml_parser_update_buffer`:** This is the most complex function. It ensures that the `buffer` contains at least `length` decoded characters. It handles:
        * Calling `yaml_parser_determine_encoding` if the encoding isn't known.
        * Moving existing, unread characters to the beginning of the buffer.
        * Filling the raw buffer if needed.
        * Decoding characters from the raw buffer based on the detected encoding (handling UTF-8, UTF-16LE, and UTF-16BE).
        * Performing error checking during decoding (invalid UTF-8 sequences, surrogate pair issues, invalid characters).

6. **Relate to Go Concepts:** Recognize the use of `io.Reader` (implied by the `read_handler`), byte slices (`[]byte`), runes (`rune`), and error handling (`error`, `io.EOF`). The logic within `yaml_parser_update_buffer` shows a manual implementation of character decoding, something Go usually handles more transparently. This suggests this might be a performance-critical part of the YAML parsing or dealing with encodings beyond basic ASCII.

7. **Construct Example:** To illustrate the encoding detection, create a simple Go program that demonstrates providing input with and without a BOM. This helps solidify the understanding of how `yaml_parser_determine_encoding` works.

8. **Identify Potential Pitfalls:**  Think about common mistakes developers might make when using a YAML parser. Not being aware of encoding issues is a classic one. Forcing a specific encoding when the input is different can lead to errors. This leads to the example of providing UTF-16 encoded data without explicitly telling the parser.

9. **Refine and Organize:**  Structure the explanation logically, starting with the overall functionality, then diving into details of specific functions, providing code examples, and finally addressing potential issues. Use clear and concise language.

10. **Review and Iterate:**  Read through the explanation to ensure accuracy and clarity. Are there any ambiguities?  Are the examples easy to understand? Could anything be explained better? For instance, initially, I might have focused too much on the low-level byte manipulation without clearly stating the high-level goal of reading and decoding YAML. Revising would involve making that connection more explicit.

By following these steps, we can systematically analyze the provided Go code snippet and arrive at a comprehensive and informative answer. The key is to combine code analysis with a bit of deduction and understanding of the underlying problem the code is trying to solve.
这段 Go 语言代码是 `gopkg.in/yaml.v2` 库中负责 **读取和解码 YAML 输入流** 的一部分核心实现。它主要关注底层的字节流处理和字符编码识别。

下面详细列举其功能并进行推理和代码举例：

**1. 错误处理:**

* **功能:** 提供了一个设置读取器错误信息的函数 `yaml_parser_set_reader_error`。
* **推理:**  在解析 YAML 的过程中，如果遇到无法识别或不符合规范的输入，就需要记录错误信息。这个函数用于设置解析器 (`yaml_parser_t`) 的错误状态，包括错误类型、错误描述、发生错误的字节偏移量和相关的值。
* **Go 代码举例:** (假设我们有一个 `yaml_parser_t` 类型的变量 `parserInstance`)
```go
package main

import "fmt"

// 模拟 yaml_parser_t 和相关的常量 (简化)
type yaml_parser_t struct {
	error        int
	problem      string
	problem_offset int
	problem_value int
}

const yaml_READER_ERROR = 1 // 假设的常量

func yaml_parser_set_reader_error(parser *yaml_parser_t, problem string, offset int, value int) bool {
	parser.error = yaml_READER_ERROR
	parser.problem = problem
	parser.problem_offset = offset
	parser.problem_value = value
	return false
}

func main() {
	parser := &yaml_parser_t{}
	if !yaml_parser_set_reader_error(parser, "Invalid character", 10, int('!')) {
		fmt.Printf("Error set: Type=%d, Message='%s', Offset=%d, Value=%d\n",
			parser.error, parser.problem, parser.problem_offset, parser.problem_value)
	}
}

// 假设的输出: Error set: Type=1, Message='Invalid character', Offset=10, Value=33
```
* **假设输入与输出:** 上面的代码示例中，我们假设在偏移量 10 处遇到了一个无效字符 `'!'` (ASCII 码 33)，`yaml_parser_set_reader_error` 函数被调用来记录这个错误。

**2. 识别字节顺序标记 (BOM):**

* **功能:**  `yaml_parser_determine_encoding` 函数用于检测输入流的编码方式，通过检查文件开头的字节顺序标记 (BOM)。
* **推理:**  YAML 文件可以使用不同的字符编码，例如 UTF-8、UTF-16LE 和 UTF-16BE。BOM 是一种可选的标记，用于指示文件的编码方式。这个函数读取输入流的开头几个字节，检查是否存在 BOM，从而确定编码。如果找不到 BOM，则默认认为是 UTF-8 编码。
* **Go 代码举例:** (假设我们有一个 `yaml_parser_t` 类型的变量 `parserInstance` 和一个包含 YAML 内容的 `io.Reader`)
```go
package main

import (
	"bytes"
	"fmt"
	"io"
)

// 模拟 yaml_parser_t 和相关的常量 (简化)
type yaml_parser_t struct {
	encoding      int
	raw_buffer    []byte
	raw_buffer_pos int
	offset        int
	eof           bool
	read_handler  func(parser *yaml_parser_t, out []byte) (int, error)
}

const (
	yaml_ANY_ENCODING = 0
	yaml_UTF8_ENCODING    = 1
	yaml_UTF16LE_ENCODING = 2
	yaml_UTF16BE_ENCODING = 3

	bom_UTF8    = "\xef\xbb\xbf"
	bom_UTF16LE = "\xff\xfe"
	bom_UTF16BE = "\xfe\xff"
)

func yaml_parser_determine_encoding(parser *yaml_parser_t) bool {
	// 简化实现，假设 raw_buffer 已经填充
	buf := parser.raw_buffer
	pos := parser.raw_buffer_pos
	avail := len(buf) - pos
	if avail >= 2 && buf[pos] == bom_UTF16LE[0] && buf[pos+1] == bom_UTF16LE[1] {
		parser.encoding = yaml_UTF16LE_ENCODING
		parser.raw_buffer_pos += 2
		parser.offset += 2
	} else if avail >= 2 && buf[pos] == bom_UTF16BE[0] && buf[pos+1] == bom_UTF16BE[1] {
		parser.encoding = yaml_UTF16BE_ENCODING
		parser.raw_buffer_pos += 2
		parser.offset += 2
	} else if avail >= 3 && buf[pos] == bom_UTF8[0] && buf[pos+1] == bom_UTF8[1] && buf[pos+2] == bom_UTF8[2] {
		parser.encoding = yaml_UTF8_ENCODING
		parser.raw_buffer_pos += 3
		parser.offset += 3
	} else {
		parser.encoding = yaml_UTF8_ENCODING
	}
	return true
}

func main() {
	// 带有 UTF-8 BOM 的 YAML 内容
	yamlWithUTF8BOM := bom_UTF8 + "name: value"
	parser1 := &yaml_parser_t{raw_buffer: []byte(yamlWithUTF8BOM)}
	yaml_parser_determine_encoding(parser1)
	fmt.Printf("Encoding for YAML with UTF-8 BOM: %d (Expected: %d)\n", parser1.encoding, yaml_UTF8_ENCODING)

	// 不带 BOM 的 YAML 内容
	yamlNoBOM := "name: value"
	parser2 := &yaml_parser_t{raw_buffer: []byte(yamlNoBOM)}
	yaml_parser_determine_encoding(parser2)
	fmt.Printf("Encoding for YAML without BOM: %d (Expected: %d)\n", parser2.encoding, yaml_UTF8_ENCODING)

	// 带有 UTF-16LE BOM 的 YAML 内容 (需要将字符串转换为对应的字节)
	yamlWithUTF16LEBOM := []byte{0xff, 0xfe, 'n', 0x00, 'a', 0x00, 'm', 0x00, 'e', 0x00, ':', 0x00, ' ', 0x00, 'v', 0x00, 'a', 0x00, 'l', 0x00, 'u', 0x00, 'e', 0x00}
	parser3 := &yaml_parser_t{raw_buffer: yamlWithUTF16LEBOM}
	yaml_parser_determine_encoding(parser3)
	fmt.Printf("Encoding for YAML with UTF-16LE BOM: %d (Expected: %d)\n", parser3.encoding, yaml_UTF16LE_ENCODING)
}

// 假设的输出:
// Encoding for YAML with UTF-8 BOM: 1 (Expected: 1)
// Encoding for YAML without BOM: 1 (Expected: 1)
// Encoding for YAML with UTF-16LE BOM: 2 (Expected: 2)
```
* **假设输入与输出:**  我们提供了三种不同的输入：
    * 以 UTF-8 BOM 开头的 YAML 字符串。预期 `yaml_parser_determine_encoding` 会将其编码识别为 `yaml_UTF8_ENCODING`。
    * 不带 BOM 的 YAML 字符串。预期会被识别为默认的 `yaml_UTF8_ENCODING`。
    * 以 UTF-16LE BOM 开头的 YAML 字节序列。预期会被识别为 `yaml_UTF16LE_ENCODING`。

**3. 更新原始缓冲区:**

* **功能:** `yaml_parser_update_raw_buffer` 函数用于从输入流中读取更多的原始字节数据到解析器的缓冲区 (`parser.raw_buffer`)。
* **推理:**  解析器需要读取输入流的内容才能进行解析。这个函数负责与底层的读取操作交互。它会检查缓冲区是否已满或已到达文件末尾，然后调用 `parser.read_handler` (一个由调用者提供的函数) 来实际读取数据。如果读取过程中发生错误 (例如 `io.EOF` 或其他 I/O 错误)，会设置相应的错误状态。
* **Go 代码举例:** (假设我们有一个 `yaml_parser_t` 类型的变量 `parserInstance` 和一个包含 YAML 内容的 `io.Reader`)
```go
package main

import (
	"bytes"
	"fmt"
	"io"
)

// 模拟 yaml_parser_t 和相关的常量 (简化)
type yaml_parser_t struct {
	raw_buffer    []byte
	raw_buffer_pos int
	eof           bool
	offset        int
	read_handler  func(parser *yaml_parser_t, out []byte) (int, error)
}

func yaml_parser_set_reader_error(parser *yaml_parser_t, problem string, offset int, value int) bool {
	parser.eof = true // 简化错误处理
	return false
}

func yaml_parser_update_raw_buffer(parser *yaml_parser_t) bool {
	// 返回如果原始缓冲区已满
	if parser.raw_buffer_pos == 0 && len(parser.raw_buffer) == cap(parser.raw_buffer) {
		return true
	}

	// 返回如果已经到达文件末尾
	if parser.eof {
		return true
	}

	// 移动剩余字节到缓冲区开头
	if parser.raw_buffer_pos > 0 && parser.raw_buffer_pos < len(parser.raw_buffer) {
		copy(parser.raw_buffer, parser.raw_buffer[parser.raw_buffer_pos:])
	}
	parser.raw_buffer = parser.raw_buffer[:len(parser.raw_buffer)-parser.raw_buffer_pos]
	parser.raw_buffer_pos = 0

	// 调用读取处理函数填充缓冲区
	n, err := parser.read_handler(parser, parser.raw_buffer[len(parser.raw_buffer):cap(parser.raw_buffer)])
	parser.raw_buffer = parser.raw_buffer[:len(parser.raw_buffer)+n]
	if err == io.EOF {
		parser.eof = true
	} else if err != nil {
		return yaml_parser_set_reader_error(parser, "input error: "+err.Error(), parser.offset, -1)
	}
	return true
}

func main() {
	yamlContent := "name: value\n"
	reader := bytes.NewReader([]byte(yamlContent))
	parser := &yaml_parser_t{
		raw_buffer: make([]byte, 10), // 缓冲区大小为 10
		read_handler: func(p *yaml_parser_t, out []byte) (int, error) {
			return reader.Read(out)
		},
	}

	fmt.Printf("Initial raw buffer: '%s'\n", string(parser.raw_buffer[:len(parser.raw_buffer)-parser.raw_buffer_pos]))

	yaml_parser_update_raw_buffer(parser)
	fmt.Printf("Raw buffer after first update: '%s', EOF: %t\n", string(parser.raw_buffer), parser.eof)

	yaml_parser_update_raw_buffer(parser)
	fmt.Printf("Raw buffer after second update: '%s', EOF: %t\n", string(parser.raw_buffer), parser.eof)

	yaml_parser_update_raw_buffer(parser)
	fmt.Printf("Raw buffer after third update: '%s', EOF: %t\n", string(parser.raw_buffer), parser.eof)
}

// 假设的输出 (输出可能略有不同，取决于 io.Reader 的读取行为):
// Initial raw buffer: ''
// Raw buffer after first update: 'name: valu', EOF: false
// Raw buffer after second update: 'e
// ', EOF: false
// Raw buffer after third update: 'e
// ', EOF: true
```
* **假设输入与输出:** 我们使用一个字符串作为输入源，并设置了 `read_handler` 来模拟从 `io.Reader` 读取数据。每次调用 `yaml_parser_update_raw_buffer`，都会尝试从输入源读取最多缓冲区剩余的空间大小的数据。

**4. 更新字符缓冲区:**

* **功能:** `yaml_parser_update_buffer` 函数确保解析器的字符缓冲区 (`parser.buffer`) 至少包含指定长度 (`length`) 的已解码字符。
* **推理:**  在 YAML 解析过程中，我们需要处理的是字符而不是原始字节。这个函数负责从原始缓冲区解码字符，并将它们存储到字符缓冲区中。它会考虑当前的编码方式，处理多字节字符 (例如 UTF-8)，并进行一些基本的字符有效性检查。如果需要，它会调用 `yaml_parser_update_raw_buffer` 来获取更多的原始字节。
* **Go 代码举例:** (由于此函数比较复杂，这里只展示一个简化的概念示例，不包含完整的 UTF-8 解码逻辑)
```go
package main

import (
	"fmt"
)

// 模拟 yaml_parser_t 和相关的常量 (简化)
type yaml_parser_t struct {
	raw_buffer    []byte
	raw_buffer_pos int
	buffer        []byte // 简化为 byte slice，实际应为 rune slice
	buffer_pos    int
	unread        int
	eof           bool
	encoding      int
	offset        int
	read_handler  func(parser *yaml_parser_t, out []byte) (int, error)
}

const yaml_UTF8_ENCODING = 1

func yaml_parser_set_reader_error(parser *yaml_parser_t, problem string, offset int, value int) bool {
	parser.eof = true
	return false
}

func yaml_parser_update_raw_buffer(parser *yaml_parser_t) bool {
	// ... (简化实现，假设总是成功)
	return true
}

func yaml_parser_determine_encoding(parser *yaml_parser_t) bool {
	parser.encoding = yaml_UTF8_ENCODING
	return true
}

func yaml_parser_update_buffer(parser *yaml_parser_t, length int) bool {
	if parser.read_handler == nil {
		panic("read handler must be set")
	}

	if parser.eof && parser.raw_buffer_pos == len(parser.raw_buffer) {
		return true
	}

	if parser.unread >= length {
		return true
	}

	if parser.encoding == 0 {
		if !yaml_parser_determine_encoding(parser) {
			return false
		}
	}

	// 简化解码过程，假设所有字符都是单字节的 ASCII
	for parser.unread < length && parser.raw_buffer_pos < len(parser.raw_buffer) {
		parser.buffer = append(parser.buffer, parser.raw_buffer[parser.raw_buffer_pos])
		parser.raw_buffer_pos++
		parser.unread++
		parser.offset++
	}
	return true
}

func main() {
	yamlContent := "name"
	parser := &yaml_parser_t{
		raw_buffer: []byte(yamlContent),
		buffer:     make([]byte, 0),
	}

	fmt.Printf("Initial buffer: '%s', unread: %d\n", string(parser.buffer), parser.unread)

	yaml_parser_update_buffer(parser, 2)
	fmt.Printf("Buffer after update (length 2): '%s', unread: %d\n", string(parser.buffer), parser.unread)

	yaml_parser_update_buffer(parser, 4)
	fmt.Printf("Buffer after update (length 4): '%s', unread: %d\n", string(parser.buffer), parser.unread)
}

// 假设的输出:
// Initial buffer: '', unread: 0
// Buffer after update (length 2): 'na', unread: 2
// Buffer after update (length 4): 'name', unread: 4
```
* **假设输入与输出:**  我们提供了一个简单的字符串 "name"。我们逐步调用 `yaml_parser_update_buffer`，要求缓冲区至少包含 2 个和 4 个字符。可以看到缓冲区逐步填充。

**它是什么 Go 语言功能的实现？**

这段代码实现的是 YAML 解析器中 **底层的输入处理和字符解码** 功能。它类似于 `bufio.Reader` 的一些功能，但更加专注于处理不同字符编码和 YAML 特定的错误。它不直接暴露给用户，而是作为 YAML 解析过程的基础构建模块。

**涉及命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。命令行参数的处理通常在调用 YAML 解析器的上层代码中完成，例如读取指定的文件或从标准输入读取。

**使用者易犯错的点:**

由于这段代码是底层的实现细节，用户通常不会直接与之交互。然而，理解其功能有助于避免一些与 YAML 文件编码相关的问题：

* **编码不匹配:**  如果 YAML 文件的实际编码与解析器假设的编码不一致 (例如，文件是 UTF-16 编码，但解析器默认按 UTF-8 处理)，会导致解析错误或乱码。
* **忽略 BOM:**  虽然 BOM 可以帮助自动识别编码，但并非所有 YAML 文件都包含 BOM。依赖 BOM 进行编码检测可能导致某些文件无法正确解析。用户可能需要显式指定文件的编码方式，尤其是在处理非 UTF-8 编码的文件时。

**例子:**

假设一个用户创建了一个 UTF-16LE 编码的 YAML 文件 `data.yaml`，内容为：

```yaml
name: значение
```

如果用户使用一个默认按 UTF-8 解析的 YAML 库来读取这个文件，可能会得到乱码或者解析错误。这个底层的 `readerc.go` 模块的作用就是先正确识别编码 (如果文件有 BOM) 或者根据上层提供的线索进行解码，从而避免这种错误。

总而言之，这段 `readerc.go` 代码是 `gopkg.in/yaml.v2` 库中至关重要的组成部分，它负责从字节流中可靠地读取和解码 YAML 数据，为上层的解析器提供正确的字符输入。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/readerc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package yaml

import (
	"io"
)

// Set the reader error and return 0.
func yaml_parser_set_reader_error(parser *yaml_parser_t, problem string, offset int, value int) bool {
	parser.error = yaml_READER_ERROR
	parser.problem = problem
	parser.problem_offset = offset
	parser.problem_value = value
	return false
}

// Byte order marks.
const (
	bom_UTF8    = "\xef\xbb\xbf"
	bom_UTF16LE = "\xff\xfe"
	bom_UTF16BE = "\xfe\xff"
)

// Determine the input stream encoding by checking the BOM symbol. If no BOM is
// found, the UTF-8 encoding is assumed. Return 1 on success, 0 on failure.
func yaml_parser_determine_encoding(parser *yaml_parser_t) bool {
	// Ensure that we had enough bytes in the raw buffer.
	for !parser.eof && len(parser.raw_buffer)-parser.raw_buffer_pos < 3 {
		if !yaml_parser_update_raw_buffer(parser) {
			return false
		}
	}

	// Determine the encoding.
	buf := parser.raw_buffer
	pos := parser.raw_buffer_pos
	avail := len(buf) - pos
	if avail >= 2 && buf[pos] == bom_UTF16LE[0] && buf[pos+1] == bom_UTF16LE[1] {
		parser.encoding = yaml_UTF16LE_ENCODING
		parser.raw_buffer_pos += 2
		parser.offset += 2
	} else if avail >= 2 && buf[pos] == bom_UTF16BE[0] && buf[pos+1] == bom_UTF16BE[1] {
		parser.encoding = yaml_UTF16BE_ENCODING
		parser.raw_buffer_pos += 2
		parser.offset += 2
	} else if avail >= 3 && buf[pos] == bom_UTF8[0] && buf[pos+1] == bom_UTF8[1] && buf[pos+2] == bom_UTF8[2] {
		parser.encoding = yaml_UTF8_ENCODING
		parser.raw_buffer_pos += 3
		parser.offset += 3
	} else {
		parser.encoding = yaml_UTF8_ENCODING
	}
	return true
}

// Update the raw buffer.
func yaml_parser_update_raw_buffer(parser *yaml_parser_t) bool {
	size_read := 0

	// Return if the raw buffer is full.
	if parser.raw_buffer_pos == 0 && len(parser.raw_buffer) == cap(parser.raw_buffer) {
		return true
	}

	// Return on EOF.
	if parser.eof {
		return true
	}

	// Move the remaining bytes in the raw buffer to the beginning.
	if parser.raw_buffer_pos > 0 && parser.raw_buffer_pos < len(parser.raw_buffer) {
		copy(parser.raw_buffer, parser.raw_buffer[parser.raw_buffer_pos:])
	}
	parser.raw_buffer = parser.raw_buffer[:len(parser.raw_buffer)-parser.raw_buffer_pos]
	parser.raw_buffer_pos = 0

	// Call the read handler to fill the buffer.
	size_read, err := parser.read_handler(parser, parser.raw_buffer[len(parser.raw_buffer):cap(parser.raw_buffer)])
	parser.raw_buffer = parser.raw_buffer[:len(parser.raw_buffer)+size_read]
	if err == io.EOF {
		parser.eof = true
	} else if err != nil {
		return yaml_parser_set_reader_error(parser, "input error: "+err.Error(), parser.offset, -1)
	}
	return true
}

// Ensure that the buffer contains at least `length` characters.
// Return true on success, false on failure.
//
// The length is supposed to be significantly less that the buffer size.
func yaml_parser_update_buffer(parser *yaml_parser_t, length int) bool {
	if parser.read_handler == nil {
		panic("read handler must be set")
	}

	// If the EOF flag is set and the raw buffer is empty, do nothing.
	if parser.eof && parser.raw_buffer_pos == len(parser.raw_buffer) {
		return true
	}

	// Return if the buffer contains enough characters.
	if parser.unread >= length {
		return true
	}

	// Determine the input encoding if it is not known yet.
	if parser.encoding == yaml_ANY_ENCODING {
		if !yaml_parser_determine_encoding(parser) {
			return false
		}
	}

	// Move the unread characters to the beginning of the buffer.
	buffer_len := len(parser.buffer)
	if parser.buffer_pos > 0 && parser.buffer_pos < buffer_len {
		copy(parser.buffer, parser.buffer[parser.buffer_pos:])
		buffer_len -= parser.buffer_pos
		parser.buffer_pos = 0
	} else if parser.buffer_pos == buffer_len {
		buffer_len = 0
		parser.buffer_pos = 0
	}

	// Open the whole buffer for writing, and cut it before returning.
	parser.buffer = parser.buffer[:cap(parser.buffer)]

	// Fill the buffer until it has enough characters.
	first := true
	for parser.unread < length {

		// Fill the raw buffer if necessary.
		if !first || parser.raw_buffer_pos == len(parser.raw_buffer) {
			if !yaml_parser_update_raw_buffer(parser) {
				parser.buffer = parser.buffer[:buffer_len]
				return false
			}
		}
		first = false

		// Decode the raw buffer.
	inner:
		for parser.raw_buffer_pos != len(parser.raw_buffer) {
			var value rune
			var width int

			raw_unread := len(parser.raw_buffer) - parser.raw_buffer_pos

			// Decode the next character.
			switch parser.encoding {
			case yaml_UTF8_ENCODING:
				// Decode a UTF-8 character.  Check RFC 3629
				// (http://www.ietf.org/rfc/rfc3629.txt) for more details.
				//
				// The following table (taken from the RFC) is used for
				// decoding.
				//
				//    Char. number range |        UTF-8 octet sequence
				//      (hexadecimal)    |              (binary)
				//   --------------------+------------------------------------
				//   0000 0000-0000 007F | 0xxxxxxx
				//   0000 0080-0000 07FF | 110xxxxx 10xxxxxx
				//   0000 0800-0000 FFFF | 1110xxxx 10xxxxxx 10xxxxxx
				//   0001 0000-0010 FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
				//
				// Additionally, the characters in the range 0xD800-0xDFFF
				// are prohibited as they are reserved for use with UTF-16
				// surrogate pairs.

				// Determine the length of the UTF-8 sequence.
				octet := parser.raw_buffer[parser.raw_buffer_pos]
				switch {
				case octet&0x80 == 0x00:
					width = 1
				case octet&0xE0 == 0xC0:
					width = 2
				case octet&0xF0 == 0xE0:
					width = 3
				case octet&0xF8 == 0xF0:
					width = 4
				default:
					// The leading octet is invalid.
					return yaml_parser_set_reader_error(parser,
						"invalid leading UTF-8 octet",
						parser.offset, int(octet))
				}

				// Check if the raw buffer contains an incomplete character.
				if width > raw_unread {
					if parser.eof {
						return yaml_parser_set_reader_error(parser,
							"incomplete UTF-8 octet sequence",
							parser.offset, -1)
					}
					break inner
				}

				// Decode the leading octet.
				switch {
				case octet&0x80 == 0x00:
					value = rune(octet & 0x7F)
				case octet&0xE0 == 0xC0:
					value = rune(octet & 0x1F)
				case octet&0xF0 == 0xE0:
					value = rune(octet & 0x0F)
				case octet&0xF8 == 0xF0:
					value = rune(octet & 0x07)
				default:
					value = 0
				}

				// Check and decode the trailing octets.
				for k := 1; k < width; k++ {
					octet = parser.raw_buffer[parser.raw_buffer_pos+k]

					// Check if the octet is valid.
					if (octet & 0xC0) != 0x80 {
						return yaml_parser_set_reader_error(parser,
							"invalid trailing UTF-8 octet",
							parser.offset+k, int(octet))
					}

					// Decode the octet.
					value = (value << 6) + rune(octet&0x3F)
				}

				// Check the length of the sequence against the value.
				switch {
				case width == 1:
				case width == 2 && value >= 0x80:
				case width == 3 && value >= 0x800:
				case width == 4 && value >= 0x10000:
				default:
					return yaml_parser_set_reader_error(parser,
						"invalid length of a UTF-8 sequence",
						parser.offset, -1)
				}

				// Check the range of the value.
				if value >= 0xD800 && value <= 0xDFFF || value > 0x10FFFF {
					return yaml_parser_set_reader_error(parser,
						"invalid Unicode character",
						parser.offset, int(value))
				}

			case yaml_UTF16LE_ENCODING, yaml_UTF16BE_ENCODING:
				var low, high int
				if parser.encoding == yaml_UTF16LE_ENCODING {
					low, high = 0, 1
				} else {
					low, high = 1, 0
				}

				// The UTF-16 encoding is not as simple as one might
				// naively think.  Check RFC 2781
				// (http://www.ietf.org/rfc/rfc2781.txt).
				//
				// Normally, two subsequent bytes describe a Unicode
				// character.  However a special technique (called a
				// surrogate pair) is used for specifying character
				// values larger than 0xFFFF.
				//
				// A surrogate pair consists of two pseudo-characters:
				//      high surrogate area (0xD800-0xDBFF)
				//      low surrogate area (0xDC00-0xDFFF)
				//
				// The following formulas are used for decoding
				// and encoding characters using surrogate pairs:
				//
				//  U  = U' + 0x10000   (0x01 00 00 <= U <= 0x10 FF FF)
				//  U' = yyyyyyyyyyxxxxxxxxxx   (0 <= U' <= 0x0F FF FF)
				//  W1 = 110110yyyyyyyyyy
				//  W2 = 110111xxxxxxxxxx
				//
				// where U is the character value, W1 is the high surrogate
				// area, W2 is the low surrogate area.

				// Check for incomplete UTF-16 character.
				if raw_unread < 2 {
					if parser.eof {
						return yaml_parser_set_reader_error(parser,
							"incomplete UTF-16 character",
							parser.offset, -1)
					}
					break inner
				}

				// Get the character.
				value = rune(parser.raw_buffer[parser.raw_buffer_pos+low]) +
					(rune(parser.raw_buffer[parser.raw_buffer_pos+high]) << 8)

				// Check for unexpected low surrogate area.
				if value&0xFC00 == 0xDC00 {
					return yaml_parser_set_reader_error(parser,
						"unexpected low surrogate area",
						parser.offset, int(value))
				}

				// Check for a high surrogate area.
				if value&0xFC00 == 0xD800 {
					width = 4

					// Check for incomplete surrogate pair.
					if raw_unread < 4 {
						if parser.eof {
							return yaml_parser_set_reader_error(parser,
								"incomplete UTF-16 surrogate pair",
								parser.offset, -1)
						}
						break inner
					}

					// Get the next character.
					value2 := rune(parser.raw_buffer[parser.raw_buffer_pos+low+2]) +
						(rune(parser.raw_buffer[parser.raw_buffer_pos+high+2]) << 8)

					// Check for a low surrogate area.
					if value2&0xFC00 != 0xDC00 {
						return yaml_parser_set_reader_error(parser,
							"expected low surrogate area",
							parser.offset+2, int(value2))
					}

					// Generate the value of the surrogate pair.
					value = 0x10000 + ((value & 0x3FF) << 10) + (value2 & 0x3FF)
				} else {
					width = 2
				}

			default:
				panic("impossible")
			}

			// Check if the character is in the allowed range:
			//      #x9 | #xA | #xD | [#x20-#x7E]               (8 bit)
			//      | #x85 | [#xA0-#xD7FF] | [#xE000-#xFFFD]    (16 bit)
			//      | [#x10000-#x10FFFF]                        (32 bit)
			switch {
			case value == 0x09:
			case value == 0x0A:
			case value == 0x0D:
			case value >= 0x20 && value <= 0x7E:
			case value == 0x85:
			case value >= 0xA0 && value <= 0xD7FF:
			case value >= 0xE000 && value <= 0xFFFD:
			case value >= 0x10000 && value <= 0x10FFFF:
			default:
				return yaml_parser_set_reader_error(parser,
					"control characters are not allowed",
					parser.offset, int(value))
			}

			// Move the raw pointers.
			parser.raw_buffer_pos += width
			parser.offset += width

			// Finally put the character into the buffer.
			if value <= 0x7F {
				// 0000 0000-0000 007F . 0xxxxxxx
				parser.buffer[buffer_len+0] = byte(value)
				buffer_len += 1
			} else if value <= 0x7FF {
				// 0000 0080-0000 07FF . 110xxxxx 10xxxxxx
				parser.buffer[buffer_len+0] = byte(0xC0 + (value >> 6))
				parser.buffer[buffer_len+1] = byte(0x80 + (value & 0x3F))
				buffer_len += 2
			} else if value <= 0xFFFF {
				// 0000 0800-0000 FFFF . 1110xxxx 10xxxxxx 10xxxxxx
				parser.buffer[buffer_len+0] = byte(0xE0 + (value >> 12))
				parser.buffer[buffer_len+1] = byte(0x80 + ((value >> 6) & 0x3F))
				parser.buffer[buffer_len+2] = byte(0x80 + (value & 0x3F))
				buffer_len += 3
			} else {
				// 0001 0000-0010 FFFF . 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
				parser.buffer[buffer_len+0] = byte(0xF0 + (value >> 18))
				parser.buffer[buffer_len+1] = byte(0x80 + ((value >> 12) & 0x3F))
				parser.buffer[buffer_len+2] = byte(0x80 + ((value >> 6) & 0x3F))
				parser.buffer[buffer_len+3] = byte(0x80 + (value & 0x3F))
				buffer_len += 4
			}

			parser.unread++
		}

		// On EOF, put NUL into the buffer and return.
		if parser.eof {
			parser.buffer[buffer_len] = 0
			buffer_len++
			parser.unread++
			break
		}
	}
	parser.buffer = parser.buffer[:buffer_len]
	return true
}

"""



```