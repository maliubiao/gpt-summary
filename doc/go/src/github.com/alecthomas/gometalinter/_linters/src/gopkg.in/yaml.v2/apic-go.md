Response:
Let's break down the thought process for analyzing this Go code snippet and generating the response.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, its role in a larger context (YAML parsing/emitting), and potential usage examples and pitfalls.

2. **Initial Code Scan - Identify Key Structures and Functions:**  A quick read reveals several distinct function prefixes: `yaml_parser_*`, `yaml_emitter_*`, `yaml_stream_*_event_*`, `yaml_document_*_event_*`, `yaml_scalar_event_*`, etc. This immediately suggests two primary areas: parsing and emitting YAML. The presence of `_t` suffixes in type names like `yaml_parser_t` hints at a C-style implementation or binding approach.

3. **Focus on `yaml_parser_*` Functions:**
    * `yaml_parser_initialize`: Likely sets up a new parser object. Consider what initialization a parser might need (buffers, state).
    * `yaml_parser_delete`:  The counterpart to initialization, likely freeing resources.
    * `yaml_string_read_handler` and `yaml_reader_read_handler`: These strongly suggest handling input from either a string or an `io.Reader`. The function signatures give this away.
    * `yaml_parser_set_input_string` and `yaml_parser_set_input_reader`: These are the methods to actually configure the input source. The `panic` if called more than once is an important detail.
    * `yaml_parser_set_encoding`:  Configuring the character encoding of the input. The `panic` again highlights a "set once" requirement.
    * `yaml_insert_token`: This function's name and parameters suggest it's involved in the tokenization process of parsing, inserting a token at a specific position in a token stream.

4. **Focus on `yaml_emitter_*` Functions:**  The patterns here mirror the parser functions:
    * `yaml_emitter_initialize`: Sets up an emitter object (output buffers, states, events).
    * `yaml_emitter_delete`:  Frees emitter resources.
    * `yaml_string_write_handler` and `yaml_writer_write_handler`: Handle outputting YAML to either a byte slice or an `io.Writer`.
    * `yaml_emitter_set_output_string` and `yaml_emitter_set_output_writer`: Configure the output destination. Again, the "set once" panic.
    * `yaml_emitter_set_encoding`: Sets the output encoding.
    * `yaml_emitter_set_canonical`, `yaml_emitter_set_indent`, `yaml_emitter_set_width`, `yaml_emitter_set_unicode`, `yaml_emitter_set_break`: These are clearly settings for controlling the formatting of the emitted YAML.

5. **Focus on `yaml_*_event_initialize` Functions:** These functions (e.g., `yaml_stream_start_event_initialize`, `yaml_document_start_event_initialize`, `yaml_scalar_event_initialize`) are responsible for creating specific YAML events. These events represent the structural elements of a YAML document.

6. **Identify Core Functionality:** Based on the function groups, the code clearly implements the core functionality for:
    * **Parsing YAML:** Taking a stream of bytes (string or reader) and breaking it down into meaningful tokens.
    * **Emitting YAML:** Taking structured data (represented by events) and generating a YAML string.

7. **Infer Go Language Feature:**  The naming convention and the existence of `_t` structs strongly suggest this code is a direct port or very thin wrapper around a C library for YAML. This is a common pattern for performance-critical libraries.

8. **Construct Go Code Examples:** To illustrate the usage, create simple examples for both parsing and emitting:
    * **Parsing:** Show how to initialize a parser, set the input source (string), and potentially mention how to retrieve tokens (though the provided snippet doesn't show that part explicitly). A simple YAML string is a good input.
    * **Emitting:** Show how to initialize an emitter, set the output target (byte slice), create some basic events (stream start, document start, scalar, document end, stream end), and then how the output is accumulated in the byte slice.

9. **Address Command-Line Arguments:**  Since this snippet focuses on the core API, command-line arguments are unlikely to be directly handled here. State that it's part of a larger library that might use command-line tools.

10. **Identify Potential Pitfalls:** The "set once" restriction on input/output sources and encoding is a prime candidate for common errors. Provide a simple code example demonstrating this issue and the resulting panic.

11. **Structure the Response:** Organize the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the functionalities of the parser and emitter components.
    * Explain the likely underlying Go feature (C interop).
    * Provide clear, concise Go code examples with input and output.
    * Address command-line arguments (or the lack thereof).
    * Highlight common mistakes.
    * Use clear and precise Chinese.

12. **Review and Refine:** Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where further explanation might be helpful. For instance, initially, I might have just said "parsing," but refining it to "tokenizing the input stream" is more accurate for `yaml_insert_token`. Similarly, clarifying the "set once" constraint with explicit examples improves understanding.
这段代码是Go语言中用于处理YAML数据的一个库 (`gopkg.in/yaml.v2`) 的内部实现细节，主要负责 YAML 的解析 (parsing) 和生成 (emitting) 过程中的底层操作。  它更像是对 YAML 规范的底层C语言实现的Go语言绑定或移植。

**主要功能：**

1. **YAML 解析器 (Parser) 的管理：**
   - `yaml_parser_initialize`: 初始化一个新的 YAML 解析器对象 (`yaml_parser_t`)，为其分配缓冲区 (buffer) 用于存储原始输入数据 (`raw_buffer`) 和处理后的数据 (`buffer`)。
   - `yaml_parser_delete`: 销毁一个 YAML 解析器对象，释放其占用的资源。
   - `yaml_insert_token`:  在解析过程中，将一个 YAML 标记 (token) 插入到解析器的标记队列中。这个函数涉及到对标记队列的管理，包括在队列满时进行内存调整。
   - `yaml_string_read_handler`:  设置解析器从一个字符串 (`[]byte`) 读取输入。它实现了 `io.Reader` 的部分功能，每次被调用时从输入字符串中读取数据到缓冲区。
   - `yaml_reader_read_handler`: 设置解析器从一个 `io.Reader` 接口读取输入。
   - `yaml_parser_set_input_string`:  为解析器设置字符串输入源。
   - `yaml_parser_set_input_reader`: 为解析器设置 `io.Reader` 输入源。
   - `yaml_parser_set_encoding`: 设置解析器期望的输入编码（如 UTF-8, UTF-16BE, UTF-16LE）。

2. **YAML 生成器 (Emitter) 的管理：**
   - `yaml_emitter_initialize`: 初始化一个新的 YAML 生成器对象 (`yaml_emitter_t`)，为其分配缓冲区用于存储输出数据 (`buffer`, `raw_buffer`)，以及维护生成状态 (`states`) 和待生成的事件队列 (`events`)。
   - `yaml_emitter_delete`: 销毁一个 YAML 生成器对象，释放其占用的资源。
   - `yaml_string_write_handler`: 设置生成器将输出写入到一个 `[]byte` 切片中。
   - `yaml_writer_write_handler`: 设置生成器将输出写入到一个 `io.Writer` 接口中。
   - `yaml_emitter_set_output_string`:  为生成器设置字符串输出目标。
   - `yaml_emitter_set_output_writer`: 为生成器设置 `io.Writer` 输出目标。
   - `yaml_emitter_set_encoding`: 设置生成器的输出编码。
   - `yaml_emitter_set_canonical`: 设置生成器是否以规范的 YAML 格式输出。
   - `yaml_emitter_set_indent`: 设置生成器的缩进量。
   - `yaml_emitter_set_width`: 设置生成器的首选行宽。
   - `yaml_emitter_set_unicode`: 设置生成器是否允许输出未转义的非 ASCII 字符。
   - `yaml_emitter_set_break`: 设置生成器的换行符类型。

3. **YAML 事件 (Event) 的创建：**
   - 代码中定义了一系列以 `yaml_*_event_initialize` 为前缀的函数，用于创建不同类型的 YAML 事件，这些事件是 YAML 数据结构的基本组成部分。例如：
     - `yaml_stream_start_event_initialize`: 创建流开始事件 (STREAM-START)。
     - `yaml_stream_end_event_initialize`: 创建流结束事件 (STREAM-END)。
     - `yaml_document_start_event_initialize`: 创建文档开始事件 (DOCUMENT-START)。
     - `yaml_document_end_event_initialize`: 创建文档结束事件 (DOCUMENT-END)。
     - `yaml_scalar_event_initialize`: 创建标量事件 (SCALAR)，表示一个 YAML 标量值。
     - `yaml_sequence_start_event_initialize`: 创建序列开始事件 (SEQUENCE-START)。
     - `yaml_sequence_end_event_initialize`: 创建序列结束事件 (SEQUENCE-END)。
     - `yaml_mapping_start_event_initialize`: 创建映射开始事件 (MAPPING-START)。
     - `yaml_mapping_end_event_initialize`: 创建映射结束事件 (MAPPING-END)。
   - `yaml_event_delete`:  销毁一个事件对象。

**它是什么Go语言功能的实现（推理）：**

这段代码很像是对一个底层的 YAML 解析/生成 C 语言库的 Go 语言绑定。Go 语言通过 `cgo` 工具可以调用 C 语言的代码。虽然这段代码本身没有 `import "C"`，但考虑到其命名风格（例如 `yaml_parser_t`，`yaml_event_t`）以及函数命名方式，这强烈暗示了它是在 Go 语言中重新实现或包装了类似 libyaml 这样的 C 语言库的功能。

**Go 代码举例说明：**

**假设：** 我们已经有了 `yaml_parser_t`， `yaml_token_t` 等类型的定义，这些定义可能通过 `cgo` 引入，或者是在 Go 语言中重新定义的结构体来模拟 C 结构。

```go
package main

import (
	"fmt"
	"io"
)

// 假设的类型定义 (可能通过 cgo 引入或者在Go中定义)
type yaml_parser_t struct {
	tokens      []yaml_token_t
	tokens_head int
	input       []byte
	input_pos   int
	input_reader io.Reader
	read_handler func(*yaml_parser_t, []byte) (int, error)
	encoding    yaml_encoding_t
	raw_buffer  []byte
	buffer      []byte
}

type yaml_token_t struct {
	typ int // 代表 token 类型，例如 YAML_SCALAR_TOKEN
	// ... 其他 token 相关的数据
}

type yaml_encoding_t int

const yaml_ANY_ENCODING yaml_encoding_t = 0

func main() {
	// 解析 YAML 字符串
	yamlString := []byte("name: Alice\nage: 30")
	parser := &yaml_parser_t{}
	yaml_parser_initialize(parser)
	yaml_parser_set_input_string(parser, yamlString)
	yaml_parser_set_encoding(parser, yaml_ANY_ENCODING) // 设置编码

	// 模拟插入一个 token (实际使用中会有更复杂的逻辑来识别 token)
	token := &yaml_token_t{typ: 10} // 假设 10 代表某种 token 类型
	yaml_insert_token(parser, -1, token) // 在末尾插入

	fmt.Println("解析器中的 tokens 数量:", len(parser.tokens))

	// 从 io.Reader 解析 YAML
	reader := io.Reader(strings.NewReader("city: New York"))
	parser2 := &yaml_parser_t{}
	yaml_parser_initialize(parser2)
	yaml_parser_set_input_reader(parser2, reader)
	yaml_parser_set_encoding(parser2, yaml_ANY_ENCODING)

	// ... 后续会有读取 token 的逻辑，这里省略 ...

	yaml_parser_delete(parser)
	yaml_parser_delete(parser2)
}
```

**假设的输入与输出（针对 `yaml_insert_token`）：**

**输入:**

```go
parser := &yaml_parser_t{
	tokens:      make([]yaml_token_t, 0, 5),
	tokens_head: 0,
}
token1 := &yaml_token_t{typ: 1}
token2 := &yaml_token_t{typ: 2}
yaml_insert_token(parser, -1, token1) // 在末尾插入 token1
yaml_insert_token(parser, -1, token2) // 在末尾插入 token2
```

**输出 (解析器 `parser` 的 `tokens` 字段):**

```
[{typ:1} {typ:2}]
```

**输入 (继续上面的例子，并在中间插入):**

```go
token3 := &yaml_token_t{typ: 3}
yaml_insert_token(parser, 0, token3) // 在索引 0 的位置插入 token3
```

**输出 (解析器 `parser` 的 `tokens` 字段):**

```
[{typ:3} {typ:1} {typ:2}]
```

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在调用这个库的上层代码中。例如，一个使用这个 YAML 库的命令行工具可能会使用 `flag` 包来解析命令行参数，以指定 YAML 输入文件的路径、输出文件的路径、或者其他格式化选项。

**使用者易犯错的点：**

1. **多次设置输入/输出源：**  代码中多次使用了 `panic("must set the input source only once")` 和 `panic("must set the output target only once")`。这意味着，对于一个 `yaml_parser_t` 或 `yaml_emitter_t` 对象，只能调用一次 `yaml_parser_set_input_string` 或 `yaml_parser_set_input_reader`，以及一次 `yaml_emitter_set_output_string` 或 `yaml_emitter_set_output_writer`。

   **错误示例：**

   ```go
   parser := &yaml_parser_t{}
   yaml_parser_initialize(parser)
   yaml_parser_set_input_string(parser, []byte("input1"))
   yaml_parser_set_input_string(parser, []byte("input2")) // 这里会 panic
   ```

2. **多次设置编码：** 类似于输入/输出源，编码也只能设置一次。

   **错误示例：**

   ```go
   parser := &yaml_parser_t{}
   yaml_parser_initialize(parser)
   yaml_parser_set_encoding(parser, yaml_ANY_ENCODING)
   yaml_parser_set_encoding(parser, 1) // 假设 1 代表另一种编码，这里会 panic
   ```

理解这些底层细节有助于深入理解 `gopkg.in/yaml.v2` 库的工作原理，虽然在日常使用中，开发者通常会使用更高级别的 API 来解析和生成 YAML。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/apic.go的go语言实现的一部分， 请列举一下它的功能, 　
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

func yaml_insert_token(parser *yaml_parser_t, pos int, token *yaml_token_t) {
	//fmt.Println("yaml_insert_token", "pos:", pos, "typ:", token.typ, "head:", parser.tokens_head, "len:", len(parser.tokens))

	// Check if we can move the queue at the beginning of the buffer.
	if parser.tokens_head > 0 && len(parser.tokens) == cap(parser.tokens) {
		if parser.tokens_head != len(parser.tokens) {
			copy(parser.tokens, parser.tokens[parser.tokens_head:])
		}
		parser.tokens = parser.tokens[:len(parser.tokens)-parser.tokens_head]
		parser.tokens_head = 0
	}
	parser.tokens = append(parser.tokens, *token)
	if pos < 0 {
		return
	}
	copy(parser.tokens[parser.tokens_head+pos+1:], parser.tokens[parser.tokens_head+pos:])
	parser.tokens[parser.tokens_head+pos] = *token
}

// Create a new parser object.
func yaml_parser_initialize(parser *yaml_parser_t) bool {
	*parser = yaml_parser_t{
		raw_buffer: make([]byte, 0, input_raw_buffer_size),
		buffer:     make([]byte, 0, input_buffer_size),
	}
	return true
}

// Destroy a parser object.
func yaml_parser_delete(parser *yaml_parser_t) {
	*parser = yaml_parser_t{}
}

// String read handler.
func yaml_string_read_handler(parser *yaml_parser_t, buffer []byte) (n int, err error) {
	if parser.input_pos == len(parser.input) {
		return 0, io.EOF
	}
	n = copy(buffer, parser.input[parser.input_pos:])
	parser.input_pos += n
	return n, nil
}

// Reader read handler.
func yaml_reader_read_handler(parser *yaml_parser_t, buffer []byte) (n int, err error) {
	return parser.input_reader.Read(buffer)
}

// Set a string input.
func yaml_parser_set_input_string(parser *yaml_parser_t, input []byte) {
	if parser.read_handler != nil {
		panic("must set the input source only once")
	}
	parser.read_handler = yaml_string_read_handler
	parser.input = input
	parser.input_pos = 0
}

// Set a file input.
func yaml_parser_set_input_reader(parser *yaml_parser_t, r io.Reader) {
	if parser.read_handler != nil {
		panic("must set the input source only once")
	}
	parser.read_handler = yaml_reader_read_handler
	parser.input_reader = r
}

// Set the source encoding.
func yaml_parser_set_encoding(parser *yaml_parser_t, encoding yaml_encoding_t) {
	if parser.encoding != yaml_ANY_ENCODING {
		panic("must set the encoding only once")
	}
	parser.encoding = encoding
}

// Create a new emitter object.
func yaml_emitter_initialize(emitter *yaml_emitter_t) {
	*emitter = yaml_emitter_t{
		buffer:     make([]byte, output_buffer_size),
		raw_buffer: make([]byte, 0, output_raw_buffer_size),
		states:     make([]yaml_emitter_state_t, 0, initial_stack_size),
		events:     make([]yaml_event_t, 0, initial_queue_size),
	}
}

// Destroy an emitter object.
func yaml_emitter_delete(emitter *yaml_emitter_t) {
	*emitter = yaml_emitter_t{}
}

// String write handler.
func yaml_string_write_handler(emitter *yaml_emitter_t, buffer []byte) error {
	*emitter.output_buffer = append(*emitter.output_buffer, buffer...)
	return nil
}

// yaml_writer_write_handler uses emitter.output_writer to write the
// emitted text.
func yaml_writer_write_handler(emitter *yaml_emitter_t, buffer []byte) error {
	_, err := emitter.output_writer.Write(buffer)
	return err
}

// Set a string output.
func yaml_emitter_set_output_string(emitter *yaml_emitter_t, output_buffer *[]byte) {
	if emitter.write_handler != nil {
		panic("must set the output target only once")
	}
	emitter.write_handler = yaml_string_write_handler
	emitter.output_buffer = output_buffer
}

// Set a file output.
func yaml_emitter_set_output_writer(emitter *yaml_emitter_t, w io.Writer) {
	if emitter.write_handler != nil {
		panic("must set the output target only once")
	}
	emitter.write_handler = yaml_writer_write_handler
	emitter.output_writer = w
}

// Set the output encoding.
func yaml_emitter_set_encoding(emitter *yaml_emitter_t, encoding yaml_encoding_t) {
	if emitter.encoding != yaml_ANY_ENCODING {
		panic("must set the output encoding only once")
	}
	emitter.encoding = encoding
}

// Set the canonical output style.
func yaml_emitter_set_canonical(emitter *yaml_emitter_t, canonical bool) {
	emitter.canonical = canonical
}

//// Set the indentation increment.
func yaml_emitter_set_indent(emitter *yaml_emitter_t, indent int) {
	if indent < 2 || indent > 9 {
		indent = 2
	}
	emitter.best_indent = indent
}

// Set the preferred line width.
func yaml_emitter_set_width(emitter *yaml_emitter_t, width int) {
	if width < 0 {
		width = -1
	}
	emitter.best_width = width
}

// Set if unescaped non-ASCII characters are allowed.
func yaml_emitter_set_unicode(emitter *yaml_emitter_t, unicode bool) {
	emitter.unicode = unicode
}

// Set the preferred line break character.
func yaml_emitter_set_break(emitter *yaml_emitter_t, line_break yaml_break_t) {
	emitter.line_break = line_break
}

///*
// * Destroy a token object.
// */
//
//YAML_DECLARE(void)
//yaml_token_delete(yaml_token_t *token)
//{
//    assert(token);  // Non-NULL token object expected.
//
//    switch (token.type)
//    {
//        case YAML_TAG_DIRECTIVE_TOKEN:
//            yaml_free(token.data.tag_directive.handle);
//            yaml_free(token.data.tag_directive.prefix);
//            break;
//
//        case YAML_ALIAS_TOKEN:
//            yaml_free(token.data.alias.value);
//            break;
//
//        case YAML_ANCHOR_TOKEN:
//            yaml_free(token.data.anchor.value);
//            break;
//
//        case YAML_TAG_TOKEN:
//            yaml_free(token.data.tag.handle);
//            yaml_free(token.data.tag.suffix);
//            break;
//
//        case YAML_SCALAR_TOKEN:
//            yaml_free(token.data.scalar.value);
//            break;
//
//        default:
//            break;
//    }
//
//    memset(token, 0, sizeof(yaml_token_t));
//}
//
///*
// * Check if a string is a valid UTF-8 sequence.
// *
// * Check 'reader.c' for more details on UTF-8 encoding.
// */
//
//static int
//yaml_check_utf8(yaml_char_t *start, size_t length)
//{
//    yaml_char_t *end = start+length;
//    yaml_char_t *pointer = start;
//
//    while (pointer < end) {
//        unsigned char octet;
//        unsigned int width;
//        unsigned int value;
//        size_t k;
//
//        octet = pointer[0];
//        width = (octet & 0x80) == 0x00 ? 1 :
//                (octet & 0xE0) == 0xC0 ? 2 :
//                (octet & 0xF0) == 0xE0 ? 3 :
//                (octet & 0xF8) == 0xF0 ? 4 : 0;
//        value = (octet & 0x80) == 0x00 ? octet & 0x7F :
//                (octet & 0xE0) == 0xC0 ? octet & 0x1F :
//                (octet & 0xF0) == 0xE0 ? octet & 0x0F :
//                (octet & 0xF8) == 0xF0 ? octet & 0x07 : 0;
//        if (!width) return 0;
//        if (pointer+width > end) return 0;
//        for (k = 1; k < width; k ++) {
//            octet = pointer[k];
//            if ((octet & 0xC0) != 0x80) return 0;
//            value = (value << 6) + (octet & 0x3F);
//        }
//        if (!((width == 1) ||
//            (width == 2 && value >= 0x80) ||
//            (width == 3 && value >= 0x800) ||
//            (width == 4 && value >= 0x10000))) return 0;
//
//        pointer += width;
//    }
//
//    return 1;
//}
//

// Create STREAM-START.
func yaml_stream_start_event_initialize(event *yaml_event_t, encoding yaml_encoding_t) {
	*event = yaml_event_t{
		typ:      yaml_STREAM_START_EVENT,
		encoding: encoding,
	}
}

// Create STREAM-END.
func yaml_stream_end_event_initialize(event *yaml_event_t) {
	*event = yaml_event_t{
		typ: yaml_STREAM_END_EVENT,
	}
}

// Create DOCUMENT-START.
func yaml_document_start_event_initialize(
	event *yaml_event_t,
	version_directive *yaml_version_directive_t,
	tag_directives []yaml_tag_directive_t,
	implicit bool,
) {
	*event = yaml_event_t{
		typ:               yaml_DOCUMENT_START_EVENT,
		version_directive: version_directive,
		tag_directives:    tag_directives,
		implicit:          implicit,
	}
}

// Create DOCUMENT-END.
func yaml_document_end_event_initialize(event *yaml_event_t, implicit bool) {
	*event = yaml_event_t{
		typ:      yaml_DOCUMENT_END_EVENT,
		implicit: implicit,
	}
}

///*
// * Create ALIAS.
// */
//
//YAML_DECLARE(int)
//yaml_alias_event_initialize(event *yaml_event_t, anchor *yaml_char_t)
//{
//    mark yaml_mark_t = { 0, 0, 0 }
//    anchor_copy *yaml_char_t = NULL
//
//    assert(event) // Non-NULL event object is expected.
//    assert(anchor) // Non-NULL anchor is expected.
//
//    if (!yaml_check_utf8(anchor, strlen((char *)anchor))) return 0
//
//    anchor_copy = yaml_strdup(anchor)
//    if (!anchor_copy)
//        return 0
//
//    ALIAS_EVENT_INIT(*event, anchor_copy, mark, mark)
//
//    return 1
//}

// Create SCALAR.
func yaml_scalar_event_initialize(event *yaml_event_t, anchor, tag, value []byte, plain_implicit, quoted_implicit bool, style yaml_scalar_style_t) bool {
	*event = yaml_event_t{
		typ:             yaml_SCALAR_EVENT,
		anchor:          anchor,
		tag:             tag,
		value:           value,
		implicit:        plain_implicit,
		quoted_implicit: quoted_implicit,
		style:           yaml_style_t(style),
	}
	return true
}

// Create SEQUENCE-START.
func yaml_sequence_start_event_initialize(event *yaml_event_t, anchor, tag []byte, implicit bool, style yaml_sequence_style_t) bool {
	*event = yaml_event_t{
		typ:      yaml_SEQUENCE_START_EVENT,
		anchor:   anchor,
		tag:      tag,
		implicit: implicit,
		style:    yaml_style_t(style),
	}
	return true
}

// Create SEQUENCE-END.
func yaml_sequence_end_event_initialize(event *yaml_event_t) bool {
	*event = yaml_event_t{
		typ: yaml_SEQUENCE_END_EVENT,
	}
	return true
}

// Create MAPPING-START.
func yaml_mapping_start_event_initialize(event *yaml_event_t, anchor, tag []byte, implicit bool, style yaml_mapping_style_t) {
	*event = yaml_event_t{
		typ:      yaml_MAPPING_START_EVENT,
		anchor:   anchor,
		tag:      tag,
		implicit: implicit,
		style:    yaml_style_t(style),
	}
}

// Create MAPPING-END.
func yaml_mapping_end_event_initialize(event *yaml_event_t) {
	*event = yaml_event_t{
		typ: yaml_MAPPING_END_EVENT,
	}
}

// Destroy an event object.
func yaml_event_delete(event *yaml_event_t) {
	*event = yaml_event_t{}
}

///*
// * Create a document object.
// */
//
//YAML_DECLARE(int)
//yaml_document_initialize(document *yaml_document_t,
//        version_directive *yaml_version_directive_t,
//        tag_directives_start *yaml_tag_directive_t,
//        tag_directives_end *yaml_tag_directive_t,
//        start_implicit int, end_implicit int)
//{
//    struct {
//        error yaml_error_type_t
//    } context
//    struct {
//        start *yaml_node_t
//        end *yaml_node_t
//        top *yaml_node_t
//    } nodes = { NULL, NULL, NULL }
//    version_directive_copy *yaml_version_directive_t = NULL
//    struct {
//        start *yaml_tag_directive_t
//        end *yaml_tag_directive_t
//        top *yaml_tag_directive_t
//    } tag_directives_copy = { NULL, NULL, NULL }
//    value yaml_tag_directive_t = { NULL, NULL }
//    mark yaml_mark_t = { 0, 0, 0 }
//
//    assert(document) // Non-NULL document object is expected.
//    assert((tag_directives_start && tag_directives_end) ||
//            (tag_directives_start == tag_directives_end))
//                            // Valid tag directives are expected.
//
//    if (!STACK_INIT(&context, nodes, INITIAL_STACK_SIZE)) goto error
//
//    if (version_directive) {
//        version_directive_copy = yaml_malloc(sizeof(yaml_version_directive_t))
//        if (!version_directive_copy) goto error
//        version_directive_copy.major = version_directive.major
//        version_directive_copy.minor = version_directive.minor
//    }
//
//    if (tag_directives_start != tag_directives_end) {
//        tag_directive *yaml_tag_directive_t
//        if (!STACK_INIT(&context, tag_directives_copy, INITIAL_STACK_SIZE))
//            goto error
//        for (tag_directive = tag_directives_start
//                tag_directive != tag_directives_end; tag_directive ++) {
//            assert(tag_directive.handle)
//            assert(tag_directive.prefix)
//            if (!yaml_check_utf8(tag_directive.handle,
//                        strlen((char *)tag_directive.handle)))
//                goto error
//            if (!yaml_check_utf8(tag_directive.prefix,
//                        strlen((char *)tag_directive.prefix)))
//                goto error
//            value.handle = yaml_strdup(tag_directive.handle)
//            value.prefix = yaml_strdup(tag_directive.prefix)
//            if (!value.handle || !value.prefix) goto error
//            if (!PUSH(&context, tag_directives_copy, value))
//                goto error
//            value.handle = NULL
//            value.prefix = NULL
//        }
//    }
//
//    DOCUMENT_INIT(*document, nodes.start, nodes.end, version_directive_copy,
//            tag_directives_copy.start, tag_directives_copy.top,
//            start_implicit, end_implicit, mark, mark)
//
//    return 1
//
//error:
//    STACK_DEL(&context, nodes)
//    yaml_free(version_directive_copy)
//    while (!STACK_EMPTY(&context, tag_directives_copy)) {
//        value yaml_tag_directive_t = POP(&context, tag_directives_copy)
//        yaml_free(value.handle)
//        yaml_free(value.prefix)
//    }
//    STACK_DEL(&context, tag_directives_copy)
//    yaml_free(value.handle)
//    yaml_free(value.prefix)
//
//    return 0
//}
//
///*
// * Destroy a document object.
// */
//
//YAML_DECLARE(void)
//yaml_document_delete(document *yaml_document_t)
//{
//    struct {
//        error yaml_error_type_t
//    } context
//    tag_directive *yaml_tag_directive_t
//
//    context.error = YAML_NO_ERROR // Eliminate a compiler warning.
//
//    assert(document) // Non-NULL document object is expected.
//
//    while (!STACK_EMPTY(&context, document.nodes)) {
//        node yaml_node_t = POP(&context, document.nodes)
//        yaml_free(node.tag)
//        switch (node.type) {
//            case YAML_SCALAR_NODE:
//                yaml_free(node.data.scalar.value)
//                break
//            case YAML_SEQUENCE_NODE:
//                STACK_DEL(&context, node.data.sequence.items)
//                break
//            case YAML_MAPPING_NODE:
//                STACK_DEL(&context, node.data.mapping.pairs)
//                break
//            default:
//                assert(0) // Should not happen.
//        }
//    }
//    STACK_DEL(&context, document.nodes)
//
//    yaml_free(document.version_directive)
//    for (tag_directive = document.tag_directives.start
//            tag_directive != document.tag_directives.end
//            tag_directive++) {
//        yaml_free(tag_directive.handle)
//        yaml_free(tag_directive.prefix)
//    }
//    yaml_free(document.tag_directives.start)
//
//    memset(document, 0, sizeof(yaml_document_t))
//}
//
///**
// * Get a document node.
// */
//
//YAML_DECLARE(yaml_node_t *)
//yaml_document_get_node(document *yaml_document_t, index int)
//{
//    assert(document) // Non-NULL document object is expected.
//
//    if (index > 0 && document.nodes.start + index <= document.nodes.top) {
//        return document.nodes.start + index - 1
//    }
//    return NULL
//}
//
///**
// * Get the root object.
// */
//
//YAML_DECLARE(yaml_node_t *)
//yaml_document_get_root_node(document *yaml_document_t)
//{
//    assert(document) // Non-NULL document object is expected.
//
//    if (document.nodes.top != document.nodes.start) {
//        return document.nodes.start
//    }
//    return NULL
//}
//
///*
// * Add a scalar node to a document.
// */
//
//YAML_DECLARE(int)
//yaml_document_add_scalar(document *yaml_document_t,
//        tag *yaml_char_t, value *yaml_char_t, length int,
//        style yaml_scalar_style_t)
//{
//    struct {
//        error yaml_error_type_t
//    } context
//    mark yaml_mark_t = { 0, 0, 0 }
//    tag_copy *yaml_char_t = NULL
//    value_copy *yaml_char_t = NULL
//    node yaml_node_t
//
//    assert(document) // Non-NULL document object is expected.
//    assert(value) // Non-NULL value is expected.
//
//    if (!tag) {
//        tag = (yaml_char_t *)YAML_DEFAULT_SCALAR_TAG
//    }
//
//    if (!yaml_check_utf8(tag, strlen((char *)tag))) goto error
//    tag_copy = yaml_strdup(tag)
//    if (!tag_copy) goto error
//
//    if (length < 0) {
//        length = strlen((char *)value)
//    }
//
//    if (!yaml_check_utf8(value, length)) goto error
//    value_copy = yaml_malloc(length+1)
//    if (!value_copy) goto error
//    memcpy(value_copy, value, length)
//    value_copy[length] = '\0'
//
//    SCALAR_NODE_INIT(node, tag_copy, value_copy, length, style, mark, mark)
//    if (!PUSH(&context, document.nodes, node)) goto error
//
//    return document.nodes.top - document.nodes.start
//
//error:
//    yaml_free(tag_copy)
//    yaml_free(value_copy)
//
//    return 0
//}
//
///*
// * Add a sequence node to a document.
// */
//
//YAML_DECLARE(int)
//yaml_document_add_sequence(document *yaml_document_t,
//        tag *yaml_char_t, style yaml_sequence_style_t)
//{
//    struct {
//        error yaml_error_type_t
//    } context
//    mark yaml_mark_t = { 0, 0, 0 }
//    tag_copy *yaml_char_t = NULL
//    struct {
//        start *yaml_node_item_t
//        end *yaml_node_item_t
//        top *yaml_node_item_t
//    } items = { NULL, NULL, NULL }
//    node yaml_node_t
//
//    assert(document) // Non-NULL document object is expected.
//
//    if (!tag) {
//        tag = (yaml_char_t *)YAML_DEFAULT_SEQUENCE_TAG
//    }
//
//    if (!yaml_check_utf8(tag, strlen((char *)tag))) goto error
//    tag_copy = yaml_strdup(tag)
//    if (!tag_copy) goto error
//
//    if (!STACK_INIT(&context, items, INITIAL_STACK_SIZE)) goto error
//
//    SEQUENCE_NODE_INIT(node, tag_copy, items.start, items.end,
//            style, mark, mark)
//    if (!PUSH(&context, document.nodes, node)) goto error
//
//    return document.nodes.top - document.nodes.start
//
//error:
//    STACK_DEL(&context, items)
//    yaml_free(tag_copy)
//
//    return 0
//}
//
///*
// * Add a mapping node to a document.
// */
//
//YAML_DECLARE(int)
//yaml_document_add_mapping(document *yaml_document_t,
//        tag *yaml_char_t, style yaml_mapping_style_t)
//{
//    struct {
//        error yaml_error_type_t
//    } context
//    mark yaml_mark_t = { 0, 0, 0 }
//    tag_copy *yaml_char_t = NULL
//    struct {
//        start *yaml_node_pair_t
//        end *yaml_node_pair_t
//        top *yaml_node_pair_t
//    } pairs = { NULL, NULL, NULL }
//    node yaml_node_t
//
//    assert(document) // Non-NULL document object is expected.
//
//    if (!tag) {
//        tag = (yaml_char_t *)YAML_DEFAULT_MAPPING_TAG
//    }
//
//    if (!yaml_check_utf8(tag, strlen((char *)tag))) goto error
//    tag_copy = yaml_strdup(tag)
//    if (!tag_copy) goto error
//
//    if (!STACK_INIT(&context, pairs, INITIAL_STACK_SIZE)) goto error
//
//    MAPPING_NODE_INIT(node, tag_copy, pairs.start, pairs.end,
//            style, mark, mark)
//    if (!PUSH(&context, document.nodes, node)) goto error
//
//    return document.nodes.top - document.nodes.start
//
//error:
//    STACK_DEL(&context, pairs)
//    yaml_free(tag_copy)
//
//    return 0
//}
//
///*
// * Append an item to a sequence node.
// */
//
//YAML_DECLARE(int)
//yaml_document_append_sequence_item(document *yaml_document_t,
//        sequence int, item int)
//{
//    struct {
//        error yaml_error_type_t
//    } context
//
//    assert(document) // Non-NULL document is required.
//    assert(sequence > 0
//            && document.nodes.start + sequence <= document.nodes.top)
//                            // Valid sequence id is required.
//    assert(document.nodes.start[sequence-1].type == YAML_SEQUENCE_NODE)
//                            // A sequence node is required.
//    assert(item > 0 && document.nodes.start + item <= document.nodes.top)
//                            // Valid item id is required.
//
//    if (!PUSH(&context,
//                document.nodes.start[sequence-1].data.sequence.items, item))
//        return 0
//
//    return 1
//}
//
///*
// * Append a pair of a key and a value to a mapping node.
// */
//
//YAML_DECLARE(int)
//yaml_document_append_mapping_pair(document *yaml_document_t,
//        mapping int, key int, value int)
//{
//    struct {
//        error yaml_error_type_t
//    } context
//
//    pair yaml_node_pair_t
//
//    assert(document) // Non-NULL document is required.
//    assert(mapping > 0
//            && document.nodes.start + mapping <= document.nodes.top)
//                            // Valid mapping id is required.
//    assert(document.nodes.start[mapping-1].type == YAML_MAPPING_NODE)
//                            // A mapping node is required.
//    assert(key > 0 && document.nodes.start + key <= document.nodes.top)
//                            // Valid key id is required.
//    assert(value > 0 && document.nodes.start + value <= document.nodes.top)
//                            // Valid value id is required.
//
//    pair.key = key
//    pair.value = value
//
//    if (!PUSH(&context,
//                document.nodes.start[mapping-1].data.mapping.pairs, pair))
//        return 0
//
//    return 1
//}
//
//

"""



```