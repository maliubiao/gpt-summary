Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first step is to recognize that this code is part of a YAML library in Go. The package declaration `package yaml` and the function names containing "yaml_" are strong indicators. The filename `apic.go` might suggest it's dealing with core API components.

2. **Categorize Functions:**  Start grouping the functions by their apparent purpose. Looking at the prefixes of function names is helpful here:
    * `yaml_parser_*`:  Likely related to parsing YAML input.
    * `yaml_emitter_*`: Likely related to generating YAML output.
    * `yaml_event_*`: Likely related to representing YAML events (like document start, scalar, etc.).
    * `yaml_document_*`: Likely related to managing YAML documents in memory.
    * `yaml_insert_token`: Seems like an internal utility for managing tokens during parsing.

3. **Analyze Individual Function Functionality (Parser):**
    * **`yaml_insert_token`:**  The name and the manipulation of `parser.tokens` strongly suggest it's involved in managing a queue or buffer of tokens during the parsing process. The logic involving `tokens_head` and `copy` indicates efficient buffer management, likely to avoid excessive allocations.
    * **`yaml_parser_initialize`:**  Clearly initializes a `yaml_parser_t` struct. The creation of `raw_buffer` and `buffer` suggests handling of input data.
    * **`yaml_parser_delete`:**  The opposite of initialize, freeing resources by zeroing out the struct.
    * **`yaml_string_read_handler`:** The name and the logic of copying from `parser.input` to a buffer indicate a handler for reading YAML input from a string. It simulates an `io.Reader`.
    * **`yaml_file_read_handler`:**  Similar to the string handler, but uses `parser.input_file.Read`, indicating it reads from a file.
    * **`yaml_parser_set_input_string` and `yaml_parser_set_input_file`:** These functions configure the parser to read from either a string or a file, respectively. They set the `read_handler` and the input source. The `panic` if `read_handler` is already set highlights the "set once" constraint.
    * **`yaml_parser_set_encoding`:** Sets the encoding of the input. The `panic` suggests this should only be done once.

4. **Analyze Individual Function Functionality (Emitter):**
    * **`yaml_emitter_initialize` and `yaml_emitter_delete`:**  Analogous to the parser's initialize and delete, but for output.
    * **`yaml_string_write_handler` and `yaml_file_write_handler`:** Handlers for writing YAML output to a string buffer or a file, respectively, mimicking `io.Writer`.
    * **`yaml_emitter_set_output_string` and `yaml_emitter_set_output_file`:**  Configure the emitter's output target. The "set once" constraint is again present.
    * **`yaml_emitter_set_encoding`:** Sets the output encoding.
    * **`yaml_emitter_set_canonical`, `yaml_emitter_set_indent`, `yaml_emitter_set_width`, `yaml_emitter_set_unicode`, `yaml_emitter_set_break`:**  These functions configure various formatting options for the YAML output.

5. **Analyze Individual Function Functionality (Events):**
    * **`yaml_stream_start_event_initialize`, `yaml_stream_end_event_initialize`, `yaml_document_start_event_initialize`, `yaml_document_end_event_initialize`, `yaml_scalar_event_initialize`, `yaml_sequence_start_event_initialize`, `yaml_sequence_end_event_initialize`, `yaml_mapping_start_event_initialize`, `yaml_mapping_end_event_initialize`, `yaml_event_delete`:** These functions are clearly responsible for creating and destroying various types of YAML events. The function names directly correspond to YAML concepts. The initialization functions populate the `yaml_event_t` struct with the appropriate type and relevant data.

6. **Infer Go Concepts:**  Connect the C-like code to Go equivalents.
    * `yaml_parser_t`, `yaml_emitter_t`, `yaml_event_t`:  Likely struct types in Go.
    * Pointers (`*yaml_parser_t`): Standard Go pointers.
    * `make([]byte, ...)`:  Go's way of creating byte slices (like buffers).
    * `io.Reader`, `io.Writer`:  Standard Go interfaces being implemented.
    * `panic(...)`: Go's way of handling runtime errors.

7. **Code Example (Parser):**  Focus on demonstrating how to use the parser setup functions. Create a simple example showing setting input from a string and from a file.

8. **Code Example (Emitter):**  Focus on showing how to use the emitter setup functions, similar to the parser example.

9. **Common Mistakes:** Think about how a user might misuse the API. The "set input/output only once" constraint is the most obvious pitfall based on the `panic` statements.

10. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Double-check the code examples and explanations. Make sure the language is clear and concise. Ensure all aspects of the prompt are addressed. For example, I initially missed the `yaml_insert_token` function in my high-level categorization and had to go back and include it. I also initially forgot to include the explanation of `yaml_event_delete`.

This methodical approach, breaking the code down into logical parts and analyzing each function's purpose, allows for a comprehensive understanding of the provided Go code snippet and its functionality within a YAML library.
这段代码是 Go 语言实现的 YAML 解析和生成库的一部分，具体来说，它主要包含了以下功能：

**1. YAML 解析器 (Parser) 的初始化、销毁和输入设置:**

* **`yaml_parser_initialize(parser *yaml_parser_t) bool`**:  初始化一个新的 YAML 解析器对象。它会为解析器内部的缓冲区 `raw_buffer` 和 `buffer` 分配内存。这就像创建一个新的“阅读器”，准备读取 YAML 数据。
* **`yaml_parser_delete(parser *yaml_parser_t)`**: 销毁一个 YAML 解析器对象，释放其占用的资源。这就像关闭“阅读器”，不再需要它了。
* **`yaml_parser_set_input_string(parser *yaml_parser_t, input []byte)`**: 设置解析器的输入源为一个字符串。它会设置一个读取处理函数 `yaml_string_read_handler`，该函数从给定的字节切片 `input` 中读取数据。
* **`yaml_parser_set_input_file(parser *yaml_parser_t, file *os.File)`**: 设置解析器的输入源为一个文件。它会设置读取处理函数 `yaml_file_read_handler`，该函数从给定的 `os.File` 文件对象中读取数据。
* **`yaml_parser_set_encoding(parser *yaml_parser_t, encoding yaml_encoding_t)`**: 设置解析器期望的输入编码格式。

**2. YAML 生成器 (Emitter) 的初始化、销毁和输出设置:**

* **`yaml_emitter_initialize(emitter *yaml_emitter_t) bool`**: 初始化一个新的 YAML 生成器对象。它会为生成器内部的缓冲区 `buffer` 和 `raw_buffer`，以及状态栈 `states` 和事件队列 `events` 分配内存。这就像创建一个新的“写入器”，准备生成 YAML 数据。
* **`yaml_emitter_delete(emitter *yaml_emitter_t)`**: 销毁一个 YAML 生成器对象，释放其占用的资源。这就像关闭“写入器”，不再需要它了。
* **`yaml_emitter_set_output_string(emitter *yaml_emitter_t, output_buffer *[]byte)`**: 设置生成器的输出目标为一个字符串缓冲区。它会设置一个写入处理函数 `yaml_string_write_handler`，该函数将生成的 YAML 数据追加到给定的字节切片 `output_buffer` 中。
* **`yaml_emitter_set_output_file(emitter *yaml_emitter_t, file io.Writer)`**: 设置生成器的输出目标为一个文件。它会设置写入处理函数 `yaml_file_write_handler`，该函数将生成的 YAML 数据写入到给定的 `io.Writer` 对象中。
* **`yaml_emitter_set_encoding(emitter *yaml_emitter_t, encoding yaml_encoding_t)`**: 设置生成器输出的编码格式。
* **`yaml_emitter_set_canonical(emitter *yaml_emitter_t, canonical bool)`**: 设置是否生成规范的 YAML 输出。
* **`yaml_emitter_set_indent(emitter *yaml_emitter_t, indent int)`**: 设置 YAML 缩进的空格数。
* **`yaml_emitter_set_width(emitter *yaml_emitter_t, width int)`**: 设置 YAML 输出的 preferred 行宽。
* **`yaml_emitter_set_unicode(emitter *yaml_emitter_t, unicode bool)`**: 设置是否允许输出未转义的非 ASCII 字符。
* **`yaml_emitter_set_break(emitter *yaml_emitter_t, line_break yaml_break_t)`**: 设置 YAML 输出的换行符类型。

**3. YAML 事件 (Event) 的创建和销毁:**

这段代码定义了创建和销毁不同类型 YAML 事件的函数，这些事件是 YAML 解析和生成过程中的基本单元。

* **`yaml_stream_start_event_initialize(event *yaml_event_t, encoding yaml_encoding_t) bool`**: 创建一个表示 YAML 流开始的事件。
* **`yaml_stream_end_event_initialize(event *yaml_event_t) bool`**: 创建一个表示 YAML 流结束的事件。
* **`yaml_document_start_event_initialize(event *yaml_event_t, version_directive *yaml_version_directive_t, tag_directives []yaml_tag_directive_t, implicit bool) bool`**: 创建一个表示 YAML 文档开始的事件。
* **`yaml_document_end_event_initialize(event *yaml_event_t, implicit bool) bool`**: 创建一个表示 YAML 文档结束的事件。
* **`yaml_scalar_event_initialize(event *yaml_event_t, anchor, tag, value []byte, plain_implicit, quoted_implicit bool, style yaml_scalar_style_t) bool`**: 创建一个表示 YAML 标量值的事件。
* **`yaml_sequence_start_event_initialize(event *yaml_event_t, anchor, tag []byte, implicit bool, style yaml_sequence_style_t) bool`**: 创建一个表示 YAML 序列（列表）开始的事件。
* **`yaml_sequence_end_event_initialize(event *yaml_event_t) bool`**: 创建一个表示 YAML 序列结束的事件。
* **`yaml_mapping_start_event_initialize(event *yaml_event_t, anchor, tag []byte, implicit bool, style yaml_mapping_style_t) bool`**: 创建一个表示 YAML 映射（字典）开始的事件。
* **`yaml_mapping_end_event_initialize(event *yaml_event_t) bool`**: 创建一个表示 YAML 映射结束的事件。
* **`yaml_event_delete(event *yaml_event_t)`**: 销毁一个 YAML 事件对象。

**4. 内部工具函数:**

* **`yaml_insert_token(parser *yaml_parser_t, pos int, token *yaml_token_t)`**:  这是一个内部函数，用于在解析器的 token 队列的指定位置插入一个新的 token。它涉及到对 token 队列的内存管理和数据移动。
* **`yaml_string_read_handler(parser *yaml_parser_t, buffer []byte) (n int, err error)`**:  当解析器的输入源是字符串时，该函数负责从字符串中读取数据到缓冲区。它模拟了 `io.Reader` 的行为。
* **`yaml_file_read_handler(parser *yaml_parser_t, buffer []byte) (n int, err error)`**: 当解析器的输入源是文件时，该函数负责从文件中读取数据到缓冲区。它也模拟了 `io.Reader` 的行为。
* **`yaml_string_write_handler(emitter *yaml_emitter_t, buffer []byte) error`**: 当生成器的输出目标是字符串缓冲区时，该函数负责将数据写入到缓冲区。它模拟了 `io.Writer` 的行为。
* **`yaml_file_write_handler(emitter *yaml_emitter_t, buffer []byte) error`**: 当生成器的输出目标是文件时，该函数负责将数据写入到文件。它也模拟了 `io.Writer` 的行为。

**推理其是什么 Go 语言功能的实现：**

从函数命名和参数类型来看，这部分代码很像是 **C 语言风格的 API 在 Go 语言中的实现**。  这可以从以下几点推断出来：

* **显式的初始化和销毁函数:**  像 `yaml_parser_initialize` 和 `yaml_parser_delete` 这样的命名方式，以及需要传递指针来修改对象状态，是典型的 C 风格。在 Go 中，通常更倾向于使用构造函数和垃圾回收。
* **`yaml_parser_t`、`yaml_emitter_t`、`yaml_event_t` 等类型:** 这些很可能是用 `type` 关键字定义的结构体 (struct)。
* **手动管理缓冲区:** 代码中出现了对 `parser.tokens` 等切片的 append 和 copy 操作，以及对缓冲区大小的考虑，这表明了对内存的显式管理。在 Go 中，对于简单的缓冲，通常会利用 Go 的内置机制。
* **`yaml_string_read_handler` 和 `yaml_file_read_handler` 的实现:**  这两个函数模拟了 `io.Reader` 接口的行为，表明这部分代码可能在底层与 Go 的 IO 模型进行了集成。

**Go 代码举例说明 (假设):**

假设 `yaml_parser_t` 和 `yaml_emitter_t` 的定义如下：

```go
package yaml

import "os"

type yaml_parser_t struct {
	raw_buffer     []byte
	buffer         []byte
	tokens         []yaml_token_t
	tokens_head    int
	input          []byte // for string input
	input_pos      int
	input_file     *os.File // for file input
	read_handler   func(*yaml_parser_t, []byte) (int, error)
	encoding       yaml_encoding_t
}

type yaml_emitter_t struct {
	buffer         []byte
	raw_buffer     []byte
	states         []yaml_emitter_state_t
	events         []yaml_event_t
	output_buffer  *[]byte // for string output
	output_file    io.Writer // for file output
	write_handler  func(*yaml_emitter_t, []byte) error
	encoding       yaml_encoding_t
	canonical      bool
	best_indent    int
	best_width     int
	unicode        bool
	line_break     yaml_break_t
}

type yaml_token_t struct {
	typ int // 假设用 int 表示 token 类型
	// ... 其他 token 数据
}

type yaml_event_t struct {
	typ               int // 假设用 int 表示事件类型
	encoding          yaml_encoding_t
	version_directive *yaml_version_directive_t
	tag_directives    []yaml_tag_directive_t
	implicit          bool
	anchor          []byte
	tag             []byte
	value           []byte
	quoted_implicit bool
	style           yaml_style_t
	// ... 其他事件数据
}

type yaml_encoding_t int
type yaml_style_t int
type yaml_break_t int
type yaml_version_directive_t struct {
	major int
	minor int
}
type yaml_tag_directive_t struct {
	handle []byte
	prefix []byte
}
type yaml_emitter_state_t int
```

**解析器使用示例:**

```go
package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v2" // 假设你的包路径
)

func main() {
	// 从字符串解析 YAML
	parser := &yaml.yaml_parser_t{}
	yaml.yaml_parser_initialize(parser)
	defer yaml.yaml_parser_delete(parser)

	inputString := []byte("name: Alice\nage: 30")
	yaml.yaml_parser_set_input_string(parser, inputString)

	// 这里需要调用解析函数 (这段代码未提供) 来实际解析 token 或事件

	fmt.Println("已设置字符串输入")

	// 从文件解析 YAML
	parser2 := &yaml.yaml_parser_t{}
	yaml.yaml_parser_initialize(parser2)
	defer yaml.yaml_parser_delete(parser2)

	file, err := os.Open("data.yaml")
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer file.Close()

	yaml.yaml_parser_set_input_file(parser2, file)
	fmt.Println("已设置文件输入")

	// 注意：这段代码只展示了如何设置输入，实际的解析逻辑需要其他函数
}
```

**生成器使用示例:**

```go
package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v2" // 假设你的包路径
)

func main() {
	// 生成 YAML 到字符串
	emitter := &yaml.yaml_emitter_t{}
	yaml.yaml_emitter_initialize(emitter)
	defer yaml.yaml_emitter_delete(emitter)

	var outputBuffer []byte
	yaml.yaml_emitter_set_output_string(emitter, &outputBuffer)

	// 创建并发送 YAML 事件 (这段代码未提供) 来生成 YAML 内容
	streamStartEvent := &yaml.yaml_event_t{}
	yaml.yaml_stream_start_event_initialize(streamStartEvent, yaml.yaml_ANY_ENCODING)
	// ... 其他事件 ...
	streamEndEvent := &yaml.yaml_event_t{}
	yaml.yaml_stream_end_event_initialize(streamEndEvent)

	// 假设有发送事件的函数 (这段代码未提供)
	// emitEvent(emitter, streamStartEvent)
	// ...
	// emitEvent(emitter, streamEndEvent)

	fmt.Println("生成的 YAML (字符串):\n", string(outputBuffer))

	// 生成 YAML 到文件
	emitter2 := &yaml.yaml_emitter_t{}
	yaml.yaml_emitter_initialize(emitter2)
	defer yaml.yaml_emitter_delete(emitter2)

	file, err := os.Create("output.yaml")
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer file.Close()

	yaml.yaml_emitter_set_output_file(emitter2, file)
	fmt.Println("已设置文件输出")

	// 再次创建并发送事件到文件 (逻辑类似上面)
}
```

**命令行参数处理:**

这段代码本身没有直接处理命令行参数的功能。  命令行参数的处理通常会在调用这些底层 API 的更上层代码中进行。例如，一个使用这个 YAML 库的命令行工具可能会使用 `flag` 包或者其他库来解析用户提供的参数，如输入/输出文件路径、缩进量等，然后将这些参数传递给 `yaml_parser_set_input_file`、`yaml_emitter_set_output_file`、`yaml_emitter_set_indent` 等函数。

**使用者易犯错的点:**

1. **多次设置输入/输出源:**  代码中 `yaml_parser_set_input_string`、`yaml_parser_set_input_file`、`yaml_emitter_set_output_string` 和 `yaml_emitter_set_output_file` 函数的开头都有检查 `parser.read_handler != nil` 或 `emitter.write_handler != nil` 的逻辑，如果已经设置过，会 `panic`。这说明一个解析器或生成器对象只能设置一次输入或输出源。

   **错误示例:**

   ```go
   parser := &yaml.yaml_parser_t{}
   yaml.yaml_parser_initialize(parser)
   defer yaml.yaml_parser_delete(parser)

   inputString1 := []byte("name: Alice")
   yaml.yaml_parser_set_input_string(parser, inputString1)

   inputString2 := []byte("age: 30")
   // 错误！read_handler 已经设置
   yaml.yaml_parser_set_input_string(parser, inputString2)
   ```

2. **忘记初始化或销毁对象:**  由于使用了类似 C 风格的 API，需要显式调用 `yaml_parser_initialize` 和 `yaml_parser_delete` (或者 `yaml_emitter_initialize` 和 `yaml_emitter_delete`) 来管理对象的生命周期。忘记初始化可能导致空指针引用，忘记销毁可能导致资源泄漏。

   **错误示例:**

   ```go
   parser := &yaml.yaml_parser_t{} // 忘记初始化
   yaml.yaml_parser_set_input_string(parser, []byte("data")) // 可能导致 panic
   ```

3. **编码设置不匹配:** 如果输入 YAML 文件的编码与通过 `yaml_parser_set_encoding` 设置的编码不一致，或者希望生成的 YAML 编码与通过 `yaml_emitter_set_encoding` 设置的编码不符，可能会导致解析或生成错误。

希望以上解释能够帮助你理解这段 Go 代码的功能。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/apic.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package yaml

import (
	"io"
	"os"
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

// File read handler.
func yaml_file_read_handler(parser *yaml_parser_t, buffer []byte) (n int, err error) {
	return parser.input_file.Read(buffer)
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
func yaml_parser_set_input_file(parser *yaml_parser_t, file *os.File) {
	if parser.read_handler != nil {
		panic("must set the input source only once")
	}
	parser.read_handler = yaml_file_read_handler
	parser.input_file = file
}

// Set the source encoding.
func yaml_parser_set_encoding(parser *yaml_parser_t, encoding yaml_encoding_t) {
	if parser.encoding != yaml_ANY_ENCODING {
		panic("must set the encoding only once")
	}
	parser.encoding = encoding
}

// Create a new emitter object.
func yaml_emitter_initialize(emitter *yaml_emitter_t) bool {
	*emitter = yaml_emitter_t{
		buffer:     make([]byte, output_buffer_size),
		raw_buffer: make([]byte, 0, output_raw_buffer_size),
		states:     make([]yaml_emitter_state_t, 0, initial_stack_size),
		events:     make([]yaml_event_t, 0, initial_queue_size),
	}
	return true
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

// File write handler.
func yaml_file_write_handler(emitter *yaml_emitter_t, buffer []byte) error {
	_, err := emitter.output_file.Write(buffer)
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
func yaml_emitter_set_output_file(emitter *yaml_emitter_t, file io.Writer) {
	if emitter.write_handler != nil {
		panic("must set the output target only once")
	}
	emitter.write_handler = yaml_file_write_handler
	emitter.output_file = file
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
func yaml_stream_start_event_initialize(event *yaml_event_t, encoding yaml_encoding_t) bool {
	*event = yaml_event_t{
		typ:      yaml_STREAM_START_EVENT,
		encoding: encoding,
	}
	return true
}

// Create STREAM-END.
func yaml_stream_end_event_initialize(event *yaml_event_t) bool {
	*event = yaml_event_t{
		typ: yaml_STREAM_END_EVENT,
	}
	return true
}

// Create DOCUMENT-START.
func yaml_document_start_event_initialize(event *yaml_event_t, version_directive *yaml_version_directive_t,
	tag_directives []yaml_tag_directive_t, implicit bool) bool {
	*event = yaml_event_t{
		typ:               yaml_DOCUMENT_START_EVENT,
		version_directive: version_directive,
		tag_directives:    tag_directives,
		implicit:          implicit,
	}
	return true
}

// Create DOCUMENT-END.
func yaml_document_end_event_initialize(event *yaml_event_t, implicit bool) bool {
	*event = yaml_event_t{
		typ:      yaml_DOCUMENT_END_EVENT,
		implicit: implicit,
	}
	return true
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
func yaml_mapping_start_event_initialize(event *yaml_event_t, anchor, tag []byte, implicit bool, style yaml_mapping_style_t) bool {
	*event = yaml_event_t{
		typ:      yaml_MAPPING_START_EVENT,
		anchor:   anchor,
		tag:      tag,
		implicit: implicit,
		style:    yaml_style_t(style),
	}
	return true
}

// Create MAPPING-END.
func yaml_mapping_end_event_initialize(event *yaml_event_t) bool {
	*event = yaml_event_t{
		typ: yaml_MAPPING_END_EVENT,
	}
	return true
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
//    context.error = YAML_NO_ERROR // Eliminate a compliler warning.
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