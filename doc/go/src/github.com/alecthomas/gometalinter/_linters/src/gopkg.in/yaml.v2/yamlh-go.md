Response:
Let's break down the request and the provided Go code to arrive at the comprehensive answer.

**1. Understanding the Request:**

The core request is to analyze a Go file (`yamlh.go`) which is part of a YAML library. The key tasks are:

* **List Functionality:**  Identify what this code does. Since it's mostly type definitions and constants, the focus should be on the data structures it defines and their purpose in the context of YAML processing.
* **Infer Go Feature:** Determine what Go language features are being used and how. This is straightforward: structs, constants, `iota`, string methods on enums.
* **Provide Go Code Examples:** Illustrate the usage of these features. This requires imagining how other parts of the library *might* use these types. I need to make reasonable assumptions.
* **Code Inference (with assumptions):** If I infer logic, provide hypothetical input and output. In this specific case, the code *doesn't contain logic*, so I need to infer how these data structures would be used by a parser/emitter.
* **Command-Line Arguments:** Examine for command-line processing. This file *doesn't* handle command-line arguments directly, so this should be stated clearly.
* **Common Mistakes:** Identify potential pitfalls for users. This requires understanding how these types and constants are likely to be used and what could go wrong.
* **Use Chinese:**  The final output must be in Chinese.

**2. Analyzing the Code (`yamlh.go`):**

The code primarily defines types and constants related to YAML parsing and emitting. Here's a breakdown of the key elements:

* **Directives:** `yaml_version_directive_t`, `yaml_tag_directive_t` represent YAML directives.
* **Encoding and Line Breaks:** `yaml_encoding_t`, `yaml_break_t` define possible encoding and line break styles.
* **Error Handling:** `yaml_error_type_t` enumerates possible error conditions.
* **Position Tracking:** `yaml_mark_t` is crucial for error reporting and potentially other features like source mapping.
* **Node Styles:** `yaml_style_t`, `yaml_scalar_style_t`, `yaml_sequence_style_t`, `yaml_mapping_style_t` define various styling options for YAML elements.
* **Tokens:** `yaml_token_type_t`, `yaml_token_t` are fundamental for the parsing stage, representing lexical units.
* **Events:** `yaml_event_type_t`, `yaml_event_t` represent higher-level parsing constructs.
* **Nodes:** `yaml_node_type_t`, `yaml_node_t` represent the abstract syntax tree of the YAML document.
* **Documents:** `yaml_document_t` encapsulates a complete YAML document.
* **Parser Structures:** `yaml_read_handler_t`, `yaml_simple_key_t`, `yaml_parser_state_t`, `yaml_alias_data_t`, `yaml_parser_t` are all related to the YAML parsing process. `yaml_parser_t` seems to be the core parser state.
* **Emitter Structures:** `yaml_write_handler_t`, `yaml_emitter_state_t`, `yaml_emitter_t` are related to the YAML emitting process. `yaml_emitter_t` appears to be the core emitter state.

**3. Formulating the Answer (Iterative Process):**

* **Functionality List:**  Start by listing the categories of definitions. Group related types together (e.g., error handling, token types, node types). Describe the purpose of each group.

* **Go Feature Inference:** Identify the core Go features used: `type`, `struct`, `const`, `iota`, methods on enums. Provide simple examples to illustrate these.

* **Code Examples (Inferring Usage):** This is where assumptions are needed. Think about how a parser or emitter would *use* these types. For example:
    * How would a parser store the current token?  Using a `yaml_token_t` variable.
    * How would a parser represent an error? Setting the `error` field in `yaml_parser_t`.
    * How would an emitter decide on the style of a scalar? Checking the `style` field in `yaml_event_t`.

* **Code Inference (Parsing/Emitting Logic):** The provided code *doesn't have this logic*. Acknowledge this. Briefly describe how the defined types would *enable* parsing/emitting (e.g., tokens for scanning, events for semantic representation, nodes for the document tree). No need for complex examples here since the code doesn't implement it.

* **Command-Line Arguments:** Clearly state that this file doesn't handle them.

* **Common Mistakes:** Consider how a user interacting with a YAML library built upon these definitions could make mistakes. For example:
    * Incorrectly assuming a default encoding.
    * Not handling potential parsing errors.
    * Using the wrong style constants.

* **Translation to Chinese:**  Translate all the identified points accurately and naturally into Chinese. Pay attention to technical terms.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe I should dive deep into the specific parsing/emitting algorithms.
* **Correction:**  The provided code *doesn't* contain those algorithms. Focus on the *data structures* and how they *facilitate* those processes.
* **Initial Thought:** Should I provide very complex code examples?
* **Correction:** Keep the examples concise and focused on illustrating the *use* of the defined types, not the entire YAML parsing/emitting process.
* **Initial Thought:** How much detail should I go into for each type?
* **Correction:** Provide a high-level overview of the purpose of each category of types. Don't need to explain every field in detail unless it's particularly important for understanding the functionality.

By following these steps and iterating on the approach, I can arrive at the detailed and accurate Chinese explanation provided in the initial prompt's answer.
这段Go语言代码是 `gopkg.in/yaml.v2` 库中负责定义YAML数据结构和相关常量的一部分。它并没有实现具体的YAML解析或生成逻辑，而是为库的内部操作定义了各种类型和枚举，相当于YAML处理的“骨架”。

以下是代码的主要功能：

**1. 定义了表示YAML文档结构的各种数据类型：**

* **指令 (Directives):**
    * `yaml_version_directive_t`: 表示 YAML 版本指令，包含主版本号 (`major`) 和次版本号 (`minor`)。
    * `yaml_tag_directive_t`: 表示 YAML 标签指令，包含标签句柄 (`handle`) 和标签前缀 (`prefix`)。

* **编码和换行符 (Encoding and Line Breaks):**
    * `yaml_encoding_t`: 定义了 YAML 流的编码方式，包括 `yaml_ANY_ENCODING` (自动检测), `yaml_UTF8_ENCODING`, `yaml_UTF16LE_ENCODING`, `yaml_UTF16BE_ENCODING`。
    * `yaml_break_t`: 定义了 YAML 流的换行符类型，包括 `yaml_ANY_BREAK` (自动检测), `yaml_CR_BREAK` (Mac), `yaml_LN_BREAK` (Unix), `yaml_CRLN_BREAK` (DOS)。

* **错误类型 (Error Types):**
    * `yaml_error_type_t`: 枚举了 YAML 处理过程中可能发生的各种错误，例如内存错误、读取错误、扫描错误、解析错误、组合错误、写入错误、发射错误。

* **位置标记 (Position Mark):**
    * `yaml_mark_t`:  用于记录在输入流中的位置，包括字符索引 (`index`)、行号 (`line`) 和列号 (`column`)，这对于错误报告非常重要。

* **节点样式 (Node Styles):**
    * `yaml_style_t`: 作为通用样式类型。
    * `yaml_scalar_style_t`: 定义了标量节点的样式，如 `yaml_PLAIN_SCALAR_STYLE` (普通), `yaml_SINGLE_QUOTED_SCALAR_STYLE` (单引号), `yaml_DOUBLE_QUOTED_SCALAR_STYLE` (双引号), `yaml_LITERAL_SCALAR_STYLE` (字面量), `yaml_FOLDED_SCALAR_STYLE` (折叠)。
    * `yaml_sequence_style_t`: 定义了序列节点的样式，如 `yaml_BLOCK_SEQUENCE_STYLE` (块序列), `yaml_FLOW_SEQUENCE_STYLE` (流序列)。
    * `yaml_mapping_style_t`: 定义了映射节点的样式，如 `yaml_BLOCK_MAPPING_STYLE` (块映射), `yaml_FLOW_MAPPING_STYLE` (流映射)。

* **词法单元 (Tokens):**
    * `yaml_token_type_t`: 枚举了 YAML 扫描器生成的各种词法单元类型，例如流的开始和结束、指令、文档的开始和结束、块/流序列/映射的开始和结束、条目、键、值、别名、锚点、标签、标量等。
    * `yaml_token_t`: 表示一个具体的词法单元，包含类型、起始和结束位置、编码（对于流开始）、值（对于别名、锚点、标量、标签指令）、后缀（对于标签）、前缀（对于标签指令）、样式（对于标量）以及版本指令的major/minor。

* **事件 (Events):**
    * `yaml_event_type_t`: 枚举了 YAML 解析器生成的各种事件类型，例如流的开始和结束、文档的开始和结束、别名、标量、序列的开始和结束、映射的开始和结束。
    * `yaml_event_t`: 表示一个具体的事件，包含类型、起始和结束位置、编码（对于流开始）、版本指令、标签指令列表、锚点、标签、值、是否隐式、样式等信息。

* **节点 (Nodes):**
    * 定义了一些预定义的常用标签，如 `yaml_NULL_TAG`, `yaml_BOOL_TAG`, `yaml_STR_TAG`, `yaml_INT_TAG`, `yaml_FLOAT_TAG`, `yaml_TIMESTAMP_TAG`, `yaml_SEQ_TAG`, `yaml_MAP_TAG` 等。
    * `yaml_node_type_t`: 枚举了 YAML 节点的类型，包括标量、序列和映射。
    * `yaml_node_item_t`:  用于表示序列节点中的元素（实际上只是一个 `int`）。
    * `yaml_node_pair_t`: 用于表示映射节点中的键值对，包含键的索引 (`key`) 和值的索引 (`value`)。
    * `yaml_node_t`: 表示一个 YAML 节点，包含类型、标签、节点数据（根据类型不同，包含标量的值和样式，或序列/映射的子节点信息）以及起始和结束位置。

* **文档 (Documents):**
    * `yaml_document_t`: 表示一个 YAML 文档，包含节点列表、版本指令、标签指令列表、是否隐式开始/结束以及起始和结束位置。

* **解析器状态 (Parser State):**
    * `yaml_read_handler_t`: 定义了从输入流读取数据的处理函数类型。
    * `yaml_simple_key_t`: 描述了潜在的简单键的信息。
    * `yaml_parser_state_t`: 枚举了 YAML 解析器的各种状态。
    * `yaml_alias_data_t`: 用于存储别名数据。
    * `yaml_parser_t`:  表示 YAML 解析器的状态，包含了错误处理信息、读取器信息、扫描器信息、解析器信息以及别名数据和当前文档的指针。

* **发射器状态 (Emitter State):**
    * `yaml_write_handler_t`: 定义了向输出流写入数据的处理函数类型。
    * `yaml_emitter_state_t`: 枚举了 YAML 发射器的各种状态。
    * `yaml_emitter_t`: 表示 YAML 发射器的状态，包含了错误处理信息、写入器信息、发射器配置信息、事件队列、缩进信息、标签指令、锚点和标签分析数据、标量分析数据以及当前文档的指针。

**2. 定义了各种常量，用于表示不同的状态和样式：**

* 例如，`yaml_UTF8_ENCODING`，`yaml_CR_BREAK`，`yaml_MEMORY_ERROR`，`yaml_PLAIN_SCALAR_STYLE`，`yaml_STREAM_START_TOKEN`，`yaml_SCALAR_EVENT`，`yaml_SCALAR_NODE` 等。

**可以推理出它是什么Go语言功能的实现：**

这段代码是构建一个YAML解析器和生成器的基础数据结构定义。它利用了Go语言的以下特性：

* **结构体 (struct):** 用于定义复杂的数据结构，例如 `yaml_token_t` 和 `yaml_event_t`。
* **常量 (const):** 用于定义不可变的枚举值，例如 `yaml_UTF8_ENCODING` 和 `yaml_SCALAR_NODE`。
* **枚举 (iota):**  简化了定义一系列相关常量的值的过程。
* **类型别名 (type):**  例如 `yaml_scalar_style_t yaml_style_t`，用于更清晰地表达类型的用途。
* **方法 (method):**  例如 `(tt yaml_token_type_t) String() string`，为枚举类型提供字符串表示，方便调试和日志输出。

**Go代码举例说明：**

假设在解析YAML时，扫描器遇到了一个字符串 "hello"，它会被表示为一个 `yaml_token_t` 结构体：

```go
package main

import (
	"fmt"
	yaml "gopkg.in/yaml.v2" // 假设文件在正确路径
)

func main() {
	token := yaml.Yaml_token_t{
		Typ: yaml.Yaml_SCALAR_TOKEN,
		Start_mark: yaml.Yaml_mark_t{
			Index:  0,
			Line:   1,
			Column: 1,
		},
		End_mark: yaml.Yaml_mark_t{
			Index:  5,
			Line:   1,
			Column: 6,
		},
		Value: []byte("hello"),
		Style: yaml.Yaml_PLAIN_SCALAR_STYLE,
	}

	fmt.Printf("Token Type: %s\n", token.Typ)
	fmt.Printf("Token Value: %s\n", token.Value)
	fmt.Printf("Token Start: Line %d, Column %d\n", token.Start_mark.Line, token.Start_mark.Column)
}
```

**假设的输入与输出：**

在这个例子中，输入是 YAML 源代码中的 "hello" 字符串。输出是创建的 `yaml_token_t` 结构体，它包含了关于这个词法单元的信息。

**命令行参数的具体处理：**

这段代码本身**没有**处理任何命令行参数。它只是定义了数据结构。命令行参数的处理逻辑会在使用这些数据结构的上层代码中实现，例如在解析YAML文件或字符串的函数中。

**使用者易犯错的点：**

使用者在使用这个库时，可能会在以下方面犯错：

* **错误地使用常量:**  例如，在设置节点样式时，使用了错误的 `yaml_scalar_style_t` 常量，导致生成的YAML不符合预期。

    ```go
    // 错误示例：假设用户想使用单引号，但错误地使用了双引号的常量
    event := yaml.Yaml_event_t{
        Typ:   yaml.Yaml_SCALAR_EVENT,
        Style: yaml.Yaml_DOUBLE_QUOTED_SCALAR_STYLE, // 应该使用 yaml.Yaml_SINGLE_QUOTED_SCALAR_STYLE
        Value: []byte("some text"),
    }
    ```

* **不理解不同类型之间的关系:**  例如，混淆 `yaml_token_t` 和 `yaml_event_t` 的用途。 `yaml_token_t` 是扫描器的输出，更底层；而 `yaml_event_t` 是解析器的输出，更抽象。

* **直接操作这些底层结构:**  通常情况下，使用者应该使用库提供的更高级的 API 来解析和生成 YAML，而不是直接操作这些底层的结构体。直接操作容易出错，并且可能破坏库的内部状态。

总而言之，这段 `yamlh.go` 文件是 `gopkg.in/yaml.v2` 库的核心类型定义，为 YAML 的解析和生成过程提供了必要的数据结构和枚举常量。它本身不包含具体的业务逻辑或命令行参数处理。使用者需要理解这些类型的含义和用途，才能正确地使用这个库。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/yamlh.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package yaml

import (
	"fmt"
	"io"
)

// The version directive data.
type yaml_version_directive_t struct {
	major int8 // The major version number.
	minor int8 // The minor version number.
}

// The tag directive data.
type yaml_tag_directive_t struct {
	handle []byte // The tag handle.
	prefix []byte // The tag prefix.
}

type yaml_encoding_t int

// The stream encoding.
const (
	// Let the parser choose the encoding.
	yaml_ANY_ENCODING yaml_encoding_t = iota

	yaml_UTF8_ENCODING    // The default UTF-8 encoding.
	yaml_UTF16LE_ENCODING // The UTF-16-LE encoding with BOM.
	yaml_UTF16BE_ENCODING // The UTF-16-BE encoding with BOM.
)

type yaml_break_t int

// Line break types.
const (
	// Let the parser choose the break type.
	yaml_ANY_BREAK yaml_break_t = iota

	yaml_CR_BREAK   // Use CR for line breaks (Mac style).
	yaml_LN_BREAK   // Use LN for line breaks (Unix style).
	yaml_CRLN_BREAK // Use CR LN for line breaks (DOS style).
)

type yaml_error_type_t int

// Many bad things could happen with the parser and emitter.
const (
	// No error is produced.
	yaml_NO_ERROR yaml_error_type_t = iota

	yaml_MEMORY_ERROR   // Cannot allocate or reallocate a block of memory.
	yaml_READER_ERROR   // Cannot read or decode the input stream.
	yaml_SCANNER_ERROR  // Cannot scan the input stream.
	yaml_PARSER_ERROR   // Cannot parse the input stream.
	yaml_COMPOSER_ERROR // Cannot compose a YAML document.
	yaml_WRITER_ERROR   // Cannot write to the output stream.
	yaml_EMITTER_ERROR  // Cannot emit a YAML stream.
)

// The pointer position.
type yaml_mark_t struct {
	index  int // The position index.
	line   int // The position line.
	column int // The position column.
}

// Node Styles

type yaml_style_t int8

type yaml_scalar_style_t yaml_style_t

// Scalar styles.
const (
	// Let the emitter choose the style.
	yaml_ANY_SCALAR_STYLE yaml_scalar_style_t = iota

	yaml_PLAIN_SCALAR_STYLE         // The plain scalar style.
	yaml_SINGLE_QUOTED_SCALAR_STYLE // The single-quoted scalar style.
	yaml_DOUBLE_QUOTED_SCALAR_STYLE // The double-quoted scalar style.
	yaml_LITERAL_SCALAR_STYLE       // The literal scalar style.
	yaml_FOLDED_SCALAR_STYLE        // The folded scalar style.
)

type yaml_sequence_style_t yaml_style_t

// Sequence styles.
const (
	// Let the emitter choose the style.
	yaml_ANY_SEQUENCE_STYLE yaml_sequence_style_t = iota

	yaml_BLOCK_SEQUENCE_STYLE // The block sequence style.
	yaml_FLOW_SEQUENCE_STYLE  // The flow sequence style.
)

type yaml_mapping_style_t yaml_style_t

// Mapping styles.
const (
	// Let the emitter choose the style.
	yaml_ANY_MAPPING_STYLE yaml_mapping_style_t = iota

	yaml_BLOCK_MAPPING_STYLE // The block mapping style.
	yaml_FLOW_MAPPING_STYLE  // The flow mapping style.
)

// Tokens

type yaml_token_type_t int

// Token types.
const (
	// An empty token.
	yaml_NO_TOKEN yaml_token_type_t = iota

	yaml_STREAM_START_TOKEN // A STREAM-START token.
	yaml_STREAM_END_TOKEN   // A STREAM-END token.

	yaml_VERSION_DIRECTIVE_TOKEN // A VERSION-DIRECTIVE token.
	yaml_TAG_DIRECTIVE_TOKEN     // A TAG-DIRECTIVE token.
	yaml_DOCUMENT_START_TOKEN    // A DOCUMENT-START token.
	yaml_DOCUMENT_END_TOKEN      // A DOCUMENT-END token.

	yaml_BLOCK_SEQUENCE_START_TOKEN // A BLOCK-SEQUENCE-START token.
	yaml_BLOCK_MAPPING_START_TOKEN  // A BLOCK-SEQUENCE-END token.
	yaml_BLOCK_END_TOKEN            // A BLOCK-END token.

	yaml_FLOW_SEQUENCE_START_TOKEN // A FLOW-SEQUENCE-START token.
	yaml_FLOW_SEQUENCE_END_TOKEN   // A FLOW-SEQUENCE-END token.
	yaml_FLOW_MAPPING_START_TOKEN  // A FLOW-MAPPING-START token.
	yaml_FLOW_MAPPING_END_TOKEN    // A FLOW-MAPPING-END token.

	yaml_BLOCK_ENTRY_TOKEN // A BLOCK-ENTRY token.
	yaml_FLOW_ENTRY_TOKEN  // A FLOW-ENTRY token.
	yaml_KEY_TOKEN         // A KEY token.
	yaml_VALUE_TOKEN       // A VALUE token.

	yaml_ALIAS_TOKEN  // An ALIAS token.
	yaml_ANCHOR_TOKEN // An ANCHOR token.
	yaml_TAG_TOKEN    // A TAG token.
	yaml_SCALAR_TOKEN // A SCALAR token.
)

func (tt yaml_token_type_t) String() string {
	switch tt {
	case yaml_NO_TOKEN:
		return "yaml_NO_TOKEN"
	case yaml_STREAM_START_TOKEN:
		return "yaml_STREAM_START_TOKEN"
	case yaml_STREAM_END_TOKEN:
		return "yaml_STREAM_END_TOKEN"
	case yaml_VERSION_DIRECTIVE_TOKEN:
		return "yaml_VERSION_DIRECTIVE_TOKEN"
	case yaml_TAG_DIRECTIVE_TOKEN:
		return "yaml_TAG_DIRECTIVE_TOKEN"
	case yaml_DOCUMENT_START_TOKEN:
		return "yaml_DOCUMENT_START_TOKEN"
	case yaml_DOCUMENT_END_TOKEN:
		return "yaml_DOCUMENT_END_TOKEN"
	case yaml_BLOCK_SEQUENCE_START_TOKEN:
		return "yaml_BLOCK_SEQUENCE_START_TOKEN"
	case yaml_BLOCK_MAPPING_START_TOKEN:
		return "yaml_BLOCK_MAPPING_START_TOKEN"
	case yaml_BLOCK_END_TOKEN:
		return "yaml_BLOCK_END_TOKEN"
	case yaml_FLOW_SEQUENCE_START_TOKEN:
		return "yaml_FLOW_SEQUENCE_START_TOKEN"
	case yaml_FLOW_SEQUENCE_END_TOKEN:
		return "yaml_FLOW_SEQUENCE_END_TOKEN"
	case yaml_FLOW_MAPPING_START_TOKEN:
		return "yaml_FLOW_MAPPING_START_TOKEN"
	case yaml_FLOW_MAPPING_END_TOKEN:
		return "yaml_FLOW_MAPPING_END_TOKEN"
	case yaml_BLOCK_ENTRY_TOKEN:
		return "yaml_BLOCK_ENTRY_TOKEN"
	case yaml_FLOW_ENTRY_TOKEN:
		return "yaml_FLOW_ENTRY_TOKEN"
	case yaml_KEY_TOKEN:
		return "yaml_KEY_TOKEN"
	case yaml_VALUE_TOKEN:
		return "yaml_VALUE_TOKEN"
	case yaml_ALIAS_TOKEN:
		return "yaml_ALIAS_TOKEN"
	case yaml_ANCHOR_TOKEN:
		return "yaml_ANCHOR_TOKEN"
	case yaml_TAG_TOKEN:
		return "yaml_TAG_TOKEN"
	case yaml_SCALAR_TOKEN:
		return "yaml_SCALAR_TOKEN"
	}
	return "<unknown token>"
}

// The token structure.
type yaml_token_t struct {
	// The token type.
	typ yaml_token_type_t

	// The start/end of the token.
	start_mark, end_mark yaml_mark_t

	// The stream encoding (for yaml_STREAM_START_TOKEN).
	encoding yaml_encoding_t

	// The alias/anchor/scalar value or tag/tag directive handle
	// (for yaml_ALIAS_TOKEN, yaml_ANCHOR_TOKEN, yaml_SCALAR_TOKEN, yaml_TAG_TOKEN, yaml_TAG_DIRECTIVE_TOKEN).
	value []byte

	// The tag suffix (for yaml_TAG_TOKEN).
	suffix []byte

	// The tag directive prefix (for yaml_TAG_DIRECTIVE_TOKEN).
	prefix []byte

	// The scalar style (for yaml_SCALAR_TOKEN).
	style yaml_scalar_style_t

	// The version directive major/minor (for yaml_VERSION_DIRECTIVE_TOKEN).
	major, minor int8
}

// Events

type yaml_event_type_t int8

// Event types.
const (
	// An empty event.
	yaml_NO_EVENT yaml_event_type_t = iota

	yaml_STREAM_START_EVENT   // A STREAM-START event.
	yaml_STREAM_END_EVENT     // A STREAM-END event.
	yaml_DOCUMENT_START_EVENT // A DOCUMENT-START event.
	yaml_DOCUMENT_END_EVENT   // A DOCUMENT-END event.
	yaml_ALIAS_EVENT          // An ALIAS event.
	yaml_SCALAR_EVENT         // A SCALAR event.
	yaml_SEQUENCE_START_EVENT // A SEQUENCE-START event.
	yaml_SEQUENCE_END_EVENT   // A SEQUENCE-END event.
	yaml_MAPPING_START_EVENT  // A MAPPING-START event.
	yaml_MAPPING_END_EVENT    // A MAPPING-END event.
)

var eventStrings = []string{
	yaml_NO_EVENT:             "none",
	yaml_STREAM_START_EVENT:   "stream start",
	yaml_STREAM_END_EVENT:     "stream end",
	yaml_DOCUMENT_START_EVENT: "document start",
	yaml_DOCUMENT_END_EVENT:   "document end",
	yaml_ALIAS_EVENT:          "alias",
	yaml_SCALAR_EVENT:         "scalar",
	yaml_SEQUENCE_START_EVENT: "sequence start",
	yaml_SEQUENCE_END_EVENT:   "sequence end",
	yaml_MAPPING_START_EVENT:  "mapping start",
	yaml_MAPPING_END_EVENT:    "mapping end",
}

func (e yaml_event_type_t) String() string {
	if e < 0 || int(e) >= len(eventStrings) {
		return fmt.Sprintf("unknown event %d", e)
	}
	return eventStrings[e]
}

// The event structure.
type yaml_event_t struct {

	// The event type.
	typ yaml_event_type_t

	// The start and end of the event.
	start_mark, end_mark yaml_mark_t

	// The document encoding (for yaml_STREAM_START_EVENT).
	encoding yaml_encoding_t

	// The version directive (for yaml_DOCUMENT_START_EVENT).
	version_directive *yaml_version_directive_t

	// The list of tag directives (for yaml_DOCUMENT_START_EVENT).
	tag_directives []yaml_tag_directive_t

	// The anchor (for yaml_SCALAR_EVENT, yaml_SEQUENCE_START_EVENT, yaml_MAPPING_START_EVENT, yaml_ALIAS_EVENT).
	anchor []byte

	// The tag (for yaml_SCALAR_EVENT, yaml_SEQUENCE_START_EVENT, yaml_MAPPING_START_EVENT).
	tag []byte

	// The scalar value (for yaml_SCALAR_EVENT).
	value []byte

	// Is the document start/end indicator implicit, or the tag optional?
	// (for yaml_DOCUMENT_START_EVENT, yaml_DOCUMENT_END_EVENT, yaml_SEQUENCE_START_EVENT, yaml_MAPPING_START_EVENT, yaml_SCALAR_EVENT).
	implicit bool

	// Is the tag optional for any non-plain style? (for yaml_SCALAR_EVENT).
	quoted_implicit bool

	// The style (for yaml_SCALAR_EVENT, yaml_SEQUENCE_START_EVENT, yaml_MAPPING_START_EVENT).
	style yaml_style_t
}

func (e *yaml_event_t) scalar_style() yaml_scalar_style_t     { return yaml_scalar_style_t(e.style) }
func (e *yaml_event_t) sequence_style() yaml_sequence_style_t { return yaml_sequence_style_t(e.style) }
func (e *yaml_event_t) mapping_style() yaml_mapping_style_t   { return yaml_mapping_style_t(e.style) }

// Nodes

const (
	yaml_NULL_TAG      = "tag:yaml.org,2002:null"      // The tag !!null with the only possible value: null.
	yaml_BOOL_TAG      = "tag:yaml.org,2002:bool"      // The tag !!bool with the values: true and false.
	yaml_STR_TAG       = "tag:yaml.org,2002:str"       // The tag !!str for string values.
	yaml_INT_TAG       = "tag:yaml.org,2002:int"       // The tag !!int for integer values.
	yaml_FLOAT_TAG     = "tag:yaml.org,2002:float"     // The tag !!float for float values.
	yaml_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp" // The tag !!timestamp for date and time values.

	yaml_SEQ_TAG = "tag:yaml.org,2002:seq" // The tag !!seq is used to denote sequences.
	yaml_MAP_TAG = "tag:yaml.org,2002:map" // The tag !!map is used to denote mapping.

	// Not in original libyaml.
	yaml_BINARY_TAG = "tag:yaml.org,2002:binary"
	yaml_MERGE_TAG  = "tag:yaml.org,2002:merge"

	yaml_DEFAULT_SCALAR_TAG   = yaml_STR_TAG // The default scalar tag is !!str.
	yaml_DEFAULT_SEQUENCE_TAG = yaml_SEQ_TAG // The default sequence tag is !!seq.
	yaml_DEFAULT_MAPPING_TAG  = yaml_MAP_TAG // The default mapping tag is !!map.
)

type yaml_node_type_t int

// Node types.
const (
	// An empty node.
	yaml_NO_NODE yaml_node_type_t = iota

	yaml_SCALAR_NODE   // A scalar node.
	yaml_SEQUENCE_NODE // A sequence node.
	yaml_MAPPING_NODE  // A mapping node.
)

// An element of a sequence node.
type yaml_node_item_t int

// An element of a mapping node.
type yaml_node_pair_t struct {
	key   int // The key of the element.
	value int // The value of the element.
}

// The node structure.
type yaml_node_t struct {
	typ yaml_node_type_t // The node type.
	tag []byte           // The node tag.

	// The node data.

	// The scalar parameters (for yaml_SCALAR_NODE).
	scalar struct {
		value  []byte              // The scalar value.
		length int                 // The length of the scalar value.
		style  yaml_scalar_style_t // The scalar style.
	}

	// The sequence parameters (for YAML_SEQUENCE_NODE).
	sequence struct {
		items_data []yaml_node_item_t    // The stack of sequence items.
		style      yaml_sequence_style_t // The sequence style.
	}

	// The mapping parameters (for yaml_MAPPING_NODE).
	mapping struct {
		pairs_data  []yaml_node_pair_t   // The stack of mapping pairs (key, value).
		pairs_start *yaml_node_pair_t    // The beginning of the stack.
		pairs_end   *yaml_node_pair_t    // The end of the stack.
		pairs_top   *yaml_node_pair_t    // The top of the stack.
		style       yaml_mapping_style_t // The mapping style.
	}

	start_mark yaml_mark_t // The beginning of the node.
	end_mark   yaml_mark_t // The end of the node.

}

// The document structure.
type yaml_document_t struct {

	// The document nodes.
	nodes []yaml_node_t

	// The version directive.
	version_directive *yaml_version_directive_t

	// The list of tag directives.
	tag_directives_data  []yaml_tag_directive_t
	tag_directives_start int // The beginning of the tag directives list.
	tag_directives_end   int // The end of the tag directives list.

	start_implicit int // Is the document start indicator implicit?
	end_implicit   int // Is the document end indicator implicit?

	// The start/end of the document.
	start_mark, end_mark yaml_mark_t
}

// The prototype of a read handler.
//
// The read handler is called when the parser needs to read more bytes from the
// source. The handler should write not more than size bytes to the buffer.
// The number of written bytes should be set to the size_read variable.
//
// [in,out]   data        A pointer to an application data specified by
//                        yaml_parser_set_input().
// [out]      buffer      The buffer to write the data from the source.
// [in]       size        The size of the buffer.
// [out]      size_read   The actual number of bytes read from the source.
//
// On success, the handler should return 1.  If the handler failed,
// the returned value should be 0. On EOF, the handler should set the
// size_read to 0 and return 1.
type yaml_read_handler_t func(parser *yaml_parser_t, buffer []byte) (n int, err error)

// This structure holds information about a potential simple key.
type yaml_simple_key_t struct {
	possible     bool        // Is a simple key possible?
	required     bool        // Is a simple key required?
	token_number int         // The number of the token.
	mark         yaml_mark_t // The position mark.
}

// The states of the parser.
type yaml_parser_state_t int

const (
	yaml_PARSE_STREAM_START_STATE yaml_parser_state_t = iota

	yaml_PARSE_IMPLICIT_DOCUMENT_START_STATE           // Expect the beginning of an implicit document.
	yaml_PARSE_DOCUMENT_START_STATE                    // Expect DOCUMENT-START.
	yaml_PARSE_DOCUMENT_CONTENT_STATE                  // Expect the content of a document.
	yaml_PARSE_DOCUMENT_END_STATE                      // Expect DOCUMENT-END.
	yaml_PARSE_BLOCK_NODE_STATE                        // Expect a block node.
	yaml_PARSE_BLOCK_NODE_OR_INDENTLESS_SEQUENCE_STATE // Expect a block node or indentless sequence.
	yaml_PARSE_FLOW_NODE_STATE                         // Expect a flow node.
	yaml_PARSE_BLOCK_SEQUENCE_FIRST_ENTRY_STATE        // Expect the first entry of a block sequence.
	yaml_PARSE_BLOCK_SEQUENCE_ENTRY_STATE              // Expect an entry of a block sequence.
	yaml_PARSE_INDENTLESS_SEQUENCE_ENTRY_STATE         // Expect an entry of an indentless sequence.
	yaml_PARSE_BLOCK_MAPPING_FIRST_KEY_STATE           // Expect the first key of a block mapping.
	yaml_PARSE_BLOCK_MAPPING_KEY_STATE                 // Expect a block mapping key.
	yaml_PARSE_BLOCK_MAPPING_VALUE_STATE               // Expect a block mapping value.
	yaml_PARSE_FLOW_SEQUENCE_FIRST_ENTRY_STATE         // Expect the first entry of a flow sequence.
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_STATE               // Expect an entry of a flow sequence.
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_KEY_STATE   // Expect a key of an ordered mapping.
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE_STATE // Expect a value of an ordered mapping.
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_END_STATE   // Expect the and of an ordered mapping entry.
	yaml_PARSE_FLOW_MAPPING_FIRST_KEY_STATE            // Expect the first key of a flow mapping.
	yaml_PARSE_FLOW_MAPPING_KEY_STATE                  // Expect a key of a flow mapping.
	yaml_PARSE_FLOW_MAPPING_VALUE_STATE                // Expect a value of a flow mapping.
	yaml_PARSE_FLOW_MAPPING_EMPTY_VALUE_STATE          // Expect an empty value of a flow mapping.
	yaml_PARSE_END_STATE                               // Expect nothing.
)

func (ps yaml_parser_state_t) String() string {
	switch ps {
	case yaml_PARSE_STREAM_START_STATE:
		return "yaml_PARSE_STREAM_START_STATE"
	case yaml_PARSE_IMPLICIT_DOCUMENT_START_STATE:
		return "yaml_PARSE_IMPLICIT_DOCUMENT_START_STATE"
	case yaml_PARSE_DOCUMENT_START_STATE:
		return "yaml_PARSE_DOCUMENT_START_STATE"
	case yaml_PARSE_DOCUMENT_CONTENT_STATE:
		return "yaml_PARSE_DOCUMENT_CONTENT_STATE"
	case yaml_PARSE_DOCUMENT_END_STATE:
		return "yaml_PARSE_DOCUMENT_END_STATE"
	case yaml_PARSE_BLOCK_NODE_STATE:
		return "yaml_PARSE_BLOCK_NODE_STATE"
	case yaml_PARSE_BLOCK_NODE_OR_INDENTLESS_SEQUENCE_STATE:
		return "yaml_PARSE_BLOCK_NODE_OR_INDENTLESS_SEQUENCE_STATE"
	case yaml_PARSE_FLOW_NODE_STATE:
		return "yaml_PARSE_FLOW_NODE_STATE"
	case yaml_PARSE_BLOCK_SEQUENCE_FIRST_ENTRY_STATE:
		return "yaml_PARSE_BLOCK_SEQUENCE_FIRST_ENTRY_STATE"
	case yaml_PARSE_BLOCK_SEQUENCE_ENTRY_STATE:
		return "yaml_PARSE_BLOCK_SEQUENCE_ENTRY_STATE"
	case yaml_PARSE_INDENTLESS_SEQUENCE_ENTRY_STATE:
		return "yaml_PARSE_INDENTLESS_SEQUENCE_ENTRY_STATE"
	case yaml_PARSE_BLOCK_MAPPING_FIRST_KEY_STATE:
		return "yaml_PARSE_BLOCK_MAPPING_FIRST_KEY_STATE"
	case yaml_PARSE_BLOCK_MAPPING_KEY_STATE:
		return "yaml_PARSE_BLOCK_MAPPING_KEY_STATE"
	case yaml_PARSE_BLOCK_MAPPING_VALUE_STATE:
		return "yaml_PARSE_BLOCK_MAPPING_VALUE_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_FIRST_ENTRY_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_FIRST_ENTRY_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_KEY_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_KEY_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_END_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_END_STATE"
	case yaml_PARSE_FLOW_MAPPING_FIRST_KEY_STATE:
		return "yaml_PARSE_FLOW_MAPPING_FIRST_KEY_STATE"
	case yaml_PARSE_FLOW_MAPPING_KEY_STATE:
		return "yaml_PARSE_FLOW_MAPPING_KEY_STATE"
	case yaml_PARSE_FLOW_MAPPING_VALUE_STATE:
		return "yaml_PARSE_FLOW_MAPPING_VALUE_STATE"
	case yaml_PARSE_FLOW_MAPPING_EMPTY_VALUE_STATE:
		return "yaml_PARSE_FLOW_MAPPING_EMPTY_VALUE_STATE"
	case yaml_PARSE_END_STATE:
		return "yaml_PARSE_END_STATE"
	}
	return "<unknown parser state>"
}

// This structure holds aliases data.
type yaml_alias_data_t struct {
	anchor []byte      // The anchor.
	index  int         // The node id.
	mark   yaml_mark_t // The anchor mark.
}

// The parser structure.
//
// All members are internal. Manage the structure using the
// yaml_parser_ family of functions.
type yaml_parser_t struct {

	// Error handling

	error yaml_error_type_t // Error type.

	problem string // Error description.

	// The byte about which the problem occurred.
	problem_offset int
	problem_value  int
	problem_mark   yaml_mark_t

	// The error context.
	context      string
	context_mark yaml_mark_t

	// Reader stuff

	read_handler yaml_read_handler_t // Read handler.

	input_reader io.Reader // File input data.
	input        []byte    // String input data.
	input_pos    int

	eof bool // EOF flag

	buffer     []byte // The working buffer.
	buffer_pos int    // The current position of the buffer.

	unread int // The number of unread characters in the buffer.

	raw_buffer     []byte // The raw buffer.
	raw_buffer_pos int    // The current position of the buffer.

	encoding yaml_encoding_t // The input encoding.

	offset int         // The offset of the current position (in bytes).
	mark   yaml_mark_t // The mark of the current position.

	// Scanner stuff

	stream_start_produced bool // Have we started to scan the input stream?
	stream_end_produced   bool // Have we reached the end of the input stream?

	flow_level int // The number of unclosed '[' and '{' indicators.

	tokens          []yaml_token_t // The tokens queue.
	tokens_head     int            // The head of the tokens queue.
	tokens_parsed   int            // The number of tokens fetched from the queue.
	token_available bool           // Does the tokens queue contain a token ready for dequeueing.

	indent  int   // The current indentation level.
	indents []int // The indentation levels stack.

	simple_key_allowed bool                // May a simple key occur at the current position?
	simple_keys        []yaml_simple_key_t // The stack of simple keys.

	// Parser stuff

	state          yaml_parser_state_t    // The current parser state.
	states         []yaml_parser_state_t  // The parser states stack.
	marks          []yaml_mark_t          // The stack of marks.
	tag_directives []yaml_tag_directive_t // The list of TAG directives.

	// Dumper stuff

	aliases []yaml_alias_data_t // The alias data.

	document *yaml_document_t // The currently parsed document.
}

// Emitter Definitions

// The prototype of a write handler.
//
// The write handler is called when the emitter needs to flush the accumulated
// characters to the output.  The handler should write @a size bytes of the
// @a buffer to the output.
//
// @param[in,out]   data        A pointer to an application data specified by
//                              yaml_emitter_set_output().
// @param[in]       buffer      The buffer with bytes to be written.
// @param[in]       size        The size of the buffer.
//
// @returns On success, the handler should return @c 1.  If the handler failed,
// the returned value should be @c 0.
//
type yaml_write_handler_t func(emitter *yaml_emitter_t, buffer []byte) error

type yaml_emitter_state_t int

// The emitter states.
const (
	// Expect STREAM-START.
	yaml_EMIT_STREAM_START_STATE yaml_emitter_state_t = iota

	yaml_EMIT_FIRST_DOCUMENT_START_STATE       // Expect the first DOCUMENT-START or STREAM-END.
	yaml_EMIT_DOCUMENT_START_STATE             // Expect DOCUMENT-START or STREAM-END.
	yaml_EMIT_DOCUMENT_CONTENT_STATE           // Expect the content of a document.
	yaml_EMIT_DOCUMENT_END_STATE               // Expect DOCUMENT-END.
	yaml_EMIT_FLOW_SEQUENCE_FIRST_ITEM_STATE   // Expect the first item of a flow sequence.
	yaml_EMIT_FLOW_SEQUENCE_ITEM_STATE         // Expect an item of a flow sequence.
	yaml_EMIT_FLOW_MAPPING_FIRST_KEY_STATE     // Expect the first key of a flow mapping.
	yaml_EMIT_FLOW_MAPPING_KEY_STATE           // Expect a key of a flow mapping.
	yaml_EMIT_FLOW_MAPPING_SIMPLE_VALUE_STATE  // Expect a value for a simple key of a flow mapping.
	yaml_EMIT_FLOW_MAPPING_VALUE_STATE         // Expect a value of a flow mapping.
	yaml_EMIT_BLOCK_SEQUENCE_FIRST_ITEM_STATE  // Expect the first item of a block sequence.
	yaml_EMIT_BLOCK_SEQUENCE_ITEM_STATE        // Expect an item of a block sequence.
	yaml_EMIT_BLOCK_MAPPING_FIRST_KEY_STATE    // Expect the first key of a block mapping.
	yaml_EMIT_BLOCK_MAPPING_KEY_STATE          // Expect the key of a block mapping.
	yaml_EMIT_BLOCK_MAPPING_SIMPLE_VALUE_STATE // Expect a value for a simple key of a block mapping.
	yaml_EMIT_BLOCK_MAPPING_VALUE_STATE        // Expect a value of a block mapping.
	yaml_EMIT_END_STATE                        // Expect nothing.
)

// The emitter structure.
//
// All members are internal.  Manage the structure using the @c yaml_emitter_
// family of functions.
type yaml_emitter_t struct {

	// Error handling

	error   yaml_error_type_t // Error type.
	problem string            // Error description.

	// Writer stuff

	write_handler yaml_write_handler_t // Write handler.

	output_buffer *[]byte   // String output data.
	output_writer io.Writer // File output data.

	buffer     []byte // The working buffer.
	buffer_pos int    // The current position of the buffer.

	raw_buffer     []byte // The raw buffer.
	raw_buffer_pos int    // The current position of the buffer.

	encoding yaml_encoding_t // The stream encoding.

	// Emitter stuff

	canonical   bool         // If the output is in the canonical style?
	best_indent int          // The number of indentation spaces.
	best_width  int          // The preferred width of the output lines.
	unicode     bool         // Allow unescaped non-ASCII characters?
	line_break  yaml_break_t // The preferred line break.

	state  yaml_emitter_state_t   // The current emitter state.
	states []yaml_emitter_state_t // The stack of states.

	events      []yaml_event_t // The event queue.
	events_head int            // The head of the event queue.

	indents []int // The stack of indentation levels.

	tag_directives []yaml_tag_directive_t // The list of tag directives.

	indent int // The current indentation level.

	flow_level int // The current flow level.

	root_context       bool // Is it the document root context?
	sequence_context   bool // Is it a sequence context?
	mapping_context    bool // Is it a mapping context?
	simple_key_context bool // Is it a simple mapping key context?

	line       int  // The current line.
	column     int  // The current column.
	whitespace bool // If the last character was a whitespace?
	indention  bool // If the last character was an indentation character (' ', '-', '?', ':')?
	open_ended bool // If an explicit document end is required?

	// Anchor analysis.
	anchor_data struct {
		anchor []byte // The anchor value.
		alias  bool   // Is it an alias?
	}

	// Tag analysis.
	tag_data struct {
		handle []byte // The tag handle.
		suffix []byte // The tag suffix.
	}

	// Scalar analysis.
	scalar_data struct {
		value                 []byte              // The scalar value.
		multiline             bool                // Does the scalar contain line breaks?
		flow_plain_allowed    bool                // Can the scalar be expessed in the flow plain style?
		block_plain_allowed   bool                // Can the scalar be expressed in the block plain style?
		single_quoted_allowed bool                // Can the scalar be expressed in the single quoted style?
		block_allowed         bool                // Can the scalar be expressed in the literal or folded styles?
		style                 yaml_scalar_style_t // The output style.
	}

	// Dumper stuff

	opened bool // If the stream was already opened?
	closed bool // If the stream was already closed?

	// The information associated with the document nodes.
	anchors *struct {
		references int  // The number of references.
		anchor     int  // The anchor id.
		serialized bool // If the node has been emitted?
	}

	last_anchor_id int // The last assigned anchor id.

	document *yaml_document_t // The currently emitted document.
}

"""



```