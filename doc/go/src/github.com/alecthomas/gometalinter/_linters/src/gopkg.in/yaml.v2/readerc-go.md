Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Understanding and Context:**

   - The code is part of a YAML parser implementation in Go (`gopkg.in/yaml.v2`).
   - The file path (`go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/readerc.go`) suggests it's related to reading and processing the input YAML data.
   - The `package yaml` declaration confirms this.

2. **Function-by-Function Analysis:**

   - **`yaml_parser_set_reader_error`:**
     - The name clearly indicates error handling related to reading.
     - It takes a `yaml_parser_t` (likely a struct representing the parser state), an error `problem` (string), an `offset` (integer), and a `value` (integer).
     - It sets the parser's error status, problem description, offset, and value.
     - It returns `false`, suggesting this function is called when an error occurs, and the operation failed.

   - **Constants (`bom_UTF8`, `bom_UTF16LE`, `bom_UTF16BE`):**
     - These are byte sequences (BOM - Byte Order Mark) used to identify the encoding of the input file. This immediately points to encoding detection functionality.

   - **`yaml_parser_determine_encoding`:**
     - The name explicitly states its purpose.
     - It checks for BOMs at the beginning of the input.
     - It updates the `parser.encoding` based on the detected BOM.
     - If no BOM is found, it defaults to UTF-8.
     - It calls `yaml_parser_update_raw_buffer` to ensure enough data is available to check for BOMs.

   - **`yaml_parser_update_raw_buffer`:**
     - This function manages the raw input buffer.
     - It reads data from the input source using `parser.read_handler`.
     - It handles EOF (End Of File) conditions.
     - It shifts remaining data in the buffer to the beginning to make space for new data.
     - It calls `yaml_parser_set_reader_error` if an error occurs during reading.

   - **`yaml_parser_update_buffer`:**
     - This is the most complex function. The name suggests it updates a processed buffer.
     - It has a crucial comment about ensuring a minimum `length` of characters are available.
     - It first checks if enough unread characters are already available.
     - It calls `yaml_parser_determine_encoding` if the encoding isn't yet known.
     - It moves unread characters to the start of the buffer.
     - It contains a large `switch` statement based on `parser.encoding`. This is where the actual decoding from the raw bytes to Unicode characters happens.
     - It handles UTF-8, UTF-16LE, and UTF-16BE decoding, including surrogate pairs for UTF-16.
     - It performs validation of the decoded characters, checking for invalid or control characters.
     - It updates the `parser.buffer` with the decoded characters.
     - It increments `parser.unread`.
     - The function has a note about the Go implementation differing slightly from the C version it's likely based on, specifically concerning guaranteeing the requested `length` even at EOF.

3. **Identifying Key Functionality:**

   Based on the function names and their internal logic, the primary functionalities are:

   - **Error Handling:**  `yaml_parser_set_reader_error`
   - **Encoding Detection:** `yaml_parser_determine_encoding`
   - **Raw Input Buffer Management:** `yaml_parser_update_raw_buffer`
   - **Decoding and Character Buffer Management:** `yaml_parser_update_buffer`

4. **Inferring Go Language Feature Implementation:**

   - The code is implementing the reading and decoding part of a YAML parser. This involves:
     - Reading bytes from an `io.Reader`.
     - Detecting the encoding (UTF-8, UTF-16).
     - Decoding byte sequences into Unicode characters.
     - Storing these characters in a buffer for further processing.

5. **Code Examples (with Assumptions and Input/Output):**

   - To provide examples, we need to make assumptions about how the `yaml_parser_t` struct is defined and how the `read_handler` is implemented.

   - **Encoding Detection:**  The example demonstrates how `yaml_parser_determine_encoding` identifies the encoding based on the BOM.

   - **Updating the Buffer:** The example shows how `yaml_parser_update_buffer` decodes UTF-8 characters and stores them in the buffer.

6. **Command-Line Arguments:**

   - The provided code snippet doesn't directly handle command-line arguments. This functionality would likely be in the higher-level code that uses this parser.

7. **Common Mistakes:**

   - The analysis of `yaml_parser_update_buffer` revealed a potential issue with handling EOF and ensuring the requested buffer length. This becomes a good candidate for a common mistake.

8. **Structuring the Answer:**

   - Organize the answer by the requested points: Functionality, Go Feature Implementation, Code Examples, Command-Line Arguments, Common Mistakes.
   - Use clear and concise language.
   - Provide explanations for the code examples, including assumptions and expected input/output.
   - Highlight the differences between the Go implementation and the original C (if inferred).

9. **Review and Refinement:**

   - Read through the generated answer to ensure accuracy, completeness, and clarity.
   - Check if the code examples are valid Go code and effectively illustrate the concepts.
   - Make sure the explanation of common mistakes is clear and provides a concrete example.

This detailed breakdown illustrates the step-by-step process of understanding and analyzing the provided code, leading to the comprehensive answer. The key is to break down the code into smaller, manageable parts, understand the purpose of each part, and then synthesize that knowledge to understand the overall functionality.
这段 Go 语言代码是 YAML 解析器的一部分，专注于**读取和初步处理 YAML 输入流**。它的主要功能可以归纳为以下几点：

1. **错误处理:** 提供了 `yaml_parser_set_reader_error` 函数，用于在读取输入流时发生错误时设置解析器的错误状态，包括错误类型、错误信息、偏移量和相关的值。

2. **字节顺序标记 (BOM) 检测:** 定义了 UTF-8、UTF-16LE 和 UTF-16BE 的 BOM 常量。`yaml_parser_determine_encoding` 函数会检查输入流的开头是否存在这些 BOM，从而自动检测输入流的编码格式。如果未检测到 BOM，则默认使用 UTF-8 编码。

3. **原始缓冲区管理:** `yaml_parser_update_raw_buffer` 函数负责更新用于存储原始输入数据的缓冲区。它从底层的 `io.Reader` 读取数据，并将其填充到缓冲区中。它还处理了读取到文件末尾 (EOF) 的情况。

4. **解码缓冲区管理:** `yaml_parser_update_buffer` 函数是核心部分，它负责将原始缓冲区中的字节按照检测到的编码（UTF-8, UTF-16LE, UTF-16BE）解码成 Unicode 字符，并存储到解析器的字符缓冲区中。它还负责处理 UTF-16 的代理对。此函数确保缓冲区中至少有 `length` 个字符可用，以便后续的解析操作可以安全地读取。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了对 `io.Reader` 的读取，并根据不同的编码格式将字节流转换为 Unicode 字符流的功能。这涉及到以下 Go 语言特性：

* **`io.Reader` 接口:** 代码中的 `parser.read_handler` 字段很可能是一个实现了 `io.Reader` 接口的函数或方法，用于实际从输入源读取字节数据。
* **字节切片 (`[]byte`) 和字符串 (`string`):**  用于存储和处理原始的字节数据和 BOM。
* **`rune` 类型:** 用于表示 Unicode 字符。
* **`switch` 语句:** 用于根据不同的编码格式进行不同的解码操作。
* **`copy` 函数:** 用于在缓冲区中移动数据。

**Go 代码举例说明:**

假设我们有一个简单的 `read_handler` 函数，它从一个 `strings.Reader` 读取数据：

```go
package main

import (
	"fmt"
	"io"
	"strings"
)

// 模拟 yaml_parser_t 结构体，只包含本例需要的字段
type yaml_parser_t struct {
	raw_buffer     []byte
	raw_buffer_pos int
	offset         int
	eof            bool
	encoding       int
	read_handler   func(parser *yaml_parser_t, out []byte) (int, error)
	buffer         []byte
	buffer_pos     int
	unread         int
}

const (
	yaml_ANY_ENCODING    = 0
	yaml_UTF8_ENCODING   = 1
	yaml_UTF16LE_ENCODING = 2
	yaml_UTF16BE_ENCODING = 3
)

// 模拟 yaml_parser_set_reader_error (简化版)
func yaml_parser_set_reader_error(parser *yaml_parser_t, problem string, offset int, value int) bool {
	fmt.Printf("Error: %s at offset %d\n", problem, offset)
	return false
}

// Byte order marks.
const (
	bom_UTF8    = "\xef\xbb\xbf"
	bom_UTF16LE = "\xff\xfe"
	bom_UTF16BE = "\xfe\xff"
)

// 模拟 yaml_parser_update_raw_buffer (简化版)
func yaml_parser_update_raw_buffer(parser *yaml_parser_t) bool {
	if parser.eof {
		return true
	}
	if parser.raw_buffer_pos > 0 {
		copy(parser.raw_buffer, parser.raw_buffer[parser.raw_buffer_pos:])
		parser.raw_buffer = parser.raw_buffer[:len(parser.raw_buffer)-parser.raw_buffer_pos]
		parser.raw_buffer_pos = 0
	}
	n, err := parser.read_handler(parser, parser.raw_buffer[len(parser.raw_buffer):cap(parser.raw_buffer)])
	if err == io.EOF {
		parser.eof = true
	} else if err != nil {
		yaml_parser_set_reader_error(parser, "input error: "+err.Error(), parser.offset, -1)
		return false
	}
	parser.raw_buffer = parser.raw_buffer[:len(parser.raw_buffer)+n]
	return true
}

// 模拟 yaml_parser_determine_encoding
func yaml_parser_determine_encoding(parser *yaml_parser_t) bool {
	for !parser.eof && len(parser.raw_buffer)-parser.raw_buffer_pos < 3 {
		if !yaml_parser_update_raw_buffer(parser) {
			return false
		}
	}

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

// 模拟 yaml_parser_update_buffer (部分实现，只处理 UTF-8)
func yaml_parser_update_buffer(parser *yaml_parser_t, length int) bool {
	if parser.read_handler == nil {
		panic("read handler must be set")
	}

	if parser.eof && parser.raw_buffer_pos == len(parser.raw_buffer) {
		// ... (根据文档的理解，此处可能需要修改)
	}

	if parser.unread >= length {
		return true
	}

	if parser.encoding == yaml_ANY_ENCODING {
		if !yaml_parser_determine_encoding(parser) {
			return false
		}
	}

	buffer_len := len(parser.buffer)
	if parser.buffer_pos > 0 && parser.buffer_pos < buffer_len {
		copy(parser.buffer, parser.buffer[parser.buffer_pos:])
		buffer_len -= parser.buffer_pos
		parser.buffer_pos = 0
	} else if parser.buffer_pos == buffer_len {
		buffer_len = 0
		parser.buffer_pos = 0
	}

	parser.buffer = parser.buffer[:cap(parser.buffer)]

	first := true
	for parser.unread < length {
		if !first || parser.raw_buffer_pos == len(parser.raw_buffer) {
			if !yaml_parser_update_raw_buffer(parser) {
				parser.buffer = parser.buffer[:buffer_len]
				return false
			}
		}
		first = false

		inner:
		for parser.raw_buffer_pos != len(parser.raw_buffer) {
			if parser.encoding == yaml_UTF8_ENCODING {
				octet := parser.raw_buffer[parser.raw_buffer_pos]
				width := 0
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
					yaml_parser_set_reader_error(parser, "invalid leading UTF-8 octet", parser.offset, int(octet))
					parser.buffer = parser.buffer[:buffer_len]
					return false
				}

				if width > len(parser.raw_buffer)-parser.raw_buffer_pos {
					if parser.eof {
						yaml_parser_set_reader_error(parser, "incomplete UTF-8 octet sequence", parser.offset, -1)
						parser.buffer = parser.buffer[:buffer_len]
						return false
					}
					break inner
				}

				value := rune(0)
				switch {
				case width == 1:
					value = rune(octet & 0x7F)
				case width == 2:
					value = rune(octet&0x1F)<<6 + rune(parser.raw_buffer[parser.raw_buffer_pos+1]&0x3F)
				case width == 3:
					value = rune(octet&0x0F)<<12 + rune(parser.raw_buffer[parser.raw_buffer_pos+1]&0x3F)<<6 + rune(parser.raw_buffer[parser.raw_buffer_pos+2]&0x3F)
				case width == 4:
					value = rune(octet&0x07)<<18 + rune(parser.raw_buffer[parser.raw_buffer_pos+1]&0x3F)<<12 + rune(parser.raw_buffer[parser.raw_buffer_pos+2]&0x3F)<<6 + rune(parser.raw_buffer[parser.raw_buffer_pos+3]&0x3F)
				}

				parser.raw_buffer_pos += width
				parser.offset += width

				if value <= 0x7F {
					parser.buffer = append(parser.buffer, byte(value))
					buffer_len++
				} else if value <= 0x7FF {
					parser.buffer = append(parser.buffer, byte(0xC0+value>>6), byte(0x80+value&0x3F))
					buffer_len += 2
				} else if value <= 0xFFFF {
					parser.buffer = append(parser.buffer, byte(0xE0+value>>12), byte(0x80+value>>6&0x3F), byte(0x80+value&0x3F))
					buffer_len += 3
				} else {
					parser.buffer = append(parser.buffer, byte(0xF0+value>>18), byte(0x80+value>>12&0x3F), byte(0x80+value>>6&0x3F), byte(0x80+value&0x3F))
					buffer_len += 4
				}
				parser.unread++
			} else {
				panic("unsupported encoding in example")
			}
		}

		if parser.eof {
			parser.buffer = append(parser.buffer, 0)
			buffer_len++
			parser.unread++
			break
		}
	}
	for buffer_len < length {
		parser.buffer = append(parser.buffer, 0)
		buffer_len++
	}
	return true
}

func main() {
	input := "hello world"
	reader := strings.NewReader(input)

	parser := &yaml_parser_t{
		raw_buffer: make([]byte, 10), // 假设缓冲区大小为 10
		buffer:     make([]byte, 0, 20), // 假设字符缓冲区容量为 20
		read_handler: func(p *yaml_parser_t, out []byte) (int, error) {
			return reader.Read(out)
		},
	}

	// 尝试读取 5 个字符
	if yaml_parser_update_buffer(parser, 5) {
		fmt.Printf("成功读取 %d 个字符: %s\n", parser.unread, string(parser.buffer[:parser.unread]))
	}
}
```

**假设的输入与输出:**

**输入:** 字符串 "hello world"

**输出:**
```
成功读取 5 个字符: hello
```

**代码推理:**

1. `main` 函数创建了一个 `strings.Reader` 作为输入源，并初始化了一个 `yaml_parser_t` 结构体。
2. `yaml_parser_update_buffer` 被调用，要求至少有 5 个字符可用。
3. 由于初始状态下 `parser.encoding` 是 `yaml_ANY_ENCODING`，`yaml_parser_determine_encoding` 会被调用。由于输入字符串没有 BOM，编码会被确定为 `yaml_UTF8_ENCODING`。
4. `yaml_parser_update_raw_buffer` 会被调用来填充原始缓冲区。
5. `yaml_parser_update_buffer` 的 UTF-8 解码部分会将原始缓冲区中的字节解码成 Unicode 字符，并添加到 `parser.buffer` 中。
6. 当解码了 "hello" 这 5 个字符后，`parser.unread` 达到 5，函数返回 `true`。
7. `main` 函数打印出成功读取的字符。

**涉及命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在调用此代码的更上层逻辑中。例如，可能会有一个读取文件内容的函数，该函数会接收文件名作为命令行参数，然后打开文件并创建一个 `io.Reader` 传递给 YAML 解析器。

**使用者易犯错的点:**

* **`read_handler` 的实现错误:** 如果 `read_handler` 的实现不正确，例如读取的数据量不对，或者在遇到错误时不返回错误，会导致解析器无法正常工作。
* **缓冲区大小设置不合理:**  `raw_buffer` 和 `buffer` 的大小如果设置得太小，可能会导致频繁的缓冲区更新操作，影响性能。如果设置得过大，可能会浪费内存。
* **假设输入总是 UTF-8:**  如果使用者没有意识到需要处理不同的编码格式，可能会在处理非 UTF-8 编码的 YAML 文件时遇到问题。这段代码虽然有 BOM 检测机制，但依赖于输入流提供正确的 BOM。如果输入流没有 BOM 且不是 UTF-8，解析可能会出错。
* **错误处理不当:**  使用者可能会忽略 `yaml_parser_set_reader_error` 返回的 `false`，从而没有正确处理读取过程中发生的错误。

**易犯错的例子:**

假设使用者编写了一个 `read_handler`，在遇到错误时不返回 `error`：

```go
func badReadHandler(parser *yaml_parser_t, out []byte) (int, error) {
	n, _ := parser.r.Read(out) // 忽略了可能的错误
	return n, nil
}
```

如果底层的 `parser.r.Read(out)` 遇到了错误（比如文件不存在），`badReadHandler` 会忽略这个错误并返回 `nil`。这会导致 `yaml_parser_update_raw_buffer` 认为读取成功，但实际上数据可能没有正确读取，从而导致后续的解析错误，并且错误信息可能不准确。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/readerc.go的go语言实现的一部分， 请列举一下它的功能, 　
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

	// [Go] This function was changed to guarantee the requested length size at EOF.
	// The fact we need to do this is pretty awful, but the description above implies
	// for that to be the case, and there are tests 

	// If the EOF flag is set and the raw buffer is empty, do nothing.
	if parser.eof && parser.raw_buffer_pos == len(parser.raw_buffer) {
		// [Go] ACTUALLY! Read the documentation of this function above.
		// This is just broken. To return true, we need to have the
		// given length in the buffer. Not doing that means every single
		// check that calls this function to make sure the buffer has a
		// given length is Go) panicking; or C) accessing invalid memory.
		//return true
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
	// [Go] Read the documentation of this function above. To return true,
	// we need to have the given length in the buffer. Not doing that means
	// every single check that calls this function to make sure the buffer
	// has a given length is Go) panicking; or C) accessing invalid memory.
	// This happens here due to the EOF above breaking early.
	for buffer_len < length {
		parser.buffer[buffer_len] = 0
		buffer_len++
	}
	parser.buffer = parser.buffer[:buffer_len]
	return true
}

"""



```