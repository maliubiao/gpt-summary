Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Initial Scan and Purpose Identification:**  The first thing I notice are the `package yaml` and the filename `yamlh.go`. The `h` often suggests a header or definitions file. A quick scan reveals a lot of `type` and `const` declarations. These are the building blocks of data structures and enumerated values. This immediately suggests the file's primary purpose is *defining the data structures and constants used to represent YAML data and processing steps*.

2. **Categorizing the Definitions:**  To understand the functionality, I start grouping the definitions. I see:
    * **Directives:** `yaml_version_directive_t`, `yaml_tag_directive_t`. These seem related to YAML directives.
    * **Encodings and Breaks:** `yaml_encoding_t`, `yaml_break_t`. These deal with how the YAML text is encoded and line breaks are represented.
    * **Error Handling:** `yaml_error_type_t`, `yaml_mark_t`. This is about reporting errors and tracking locations within the YAML.
    * **Styles:** `yaml_style_t`, `yaml_scalar_style_t`, `yaml_sequence_style_t`, `yaml_mapping_style_t`. These define the different ways YAML elements can be formatted.
    * **Tokens:** `yaml_token_type_t`, `yaml_token_t`. These represent the low-level lexical elements of YAML. The `String()` method for `yaml_token_type_t` reinforces this.
    * **Events:** `yaml_event_type_t`, `yaml_event_t`. These seem like higher-level notifications about the parsing or emitting process.
    * **Nodes:** `yaml_node_type_t`, `yaml_node_t`, and related constants (`yaml_NULL_TAG`, `yaml_BOOL_TAG`, etc.). These are clearly representations of the actual YAML data structure (scalars, sequences, mappings).
    * **Documents:** `yaml_document_t`. This holds a collection of nodes, representing a complete YAML document.
    * **Parser-Specific:** `yaml_read_handler_t`, `yaml_simple_key_t`, `yaml_parser_state_t`, `yaml_parser_t`, `yaml_alias_data_t`. These are structures and types specifically for the *parsing* process. The state machine (`yaml_parser_state_t`) is a strong indicator of a parsing implementation.
    * **Emitter-Specific:** `yaml_write_handler_t`, `yaml_emitter_state_t`, `yaml_emitter_t`. These are structures and types specifically for the *emitting* (writing) process. Similar to the parser, the state machine (`yaml_emitter_state_t`) is key.

3. **Inferring Functionality based on Types:** Based on these categories, I can start inferring the functionalities:
    * **Representing YAML Data:** The `node`, `document`, `scalar_style`, `sequence_style`, and `mapping_style` types are clearly about representing the structure and style of YAML.
    * **Parsing YAML:** The presence of `token`, `event`, `parser_state`, and `parser_t` strongly suggests functionality for taking a stream of characters and turning it into a structured representation. The `read_handler` indicates a customizable input mechanism.
    * **Emitting YAML:** Similarly, `event`, `emitter_state`, and `emitter_t` suggest functionality for taking a structured representation and outputting YAML text. The `write_handler` points to a customizable output.

4. **Code Examples and Reasoning:** Now I look for concrete examples.
    * **YAML Structure:**  The `yaml_node_t` and its associated `yaml_node_type_t` are the most direct representation of YAML's core structures. I can easily create a Go struct to represent a simple YAML mapping based on this.
    * **Parsing Flow:**  The `yaml_parser_t` struct and the `yaml_parser_state_t` enum scream "state machine parser."  I can imagine how a parser would transition through these states while processing the input. The `yaml_token_t` and `yaml_event_t` types represent the intermediate steps in this process. I can conceptually link the token types to the parsing states. For instance, encountering `yaml_BLOCK_SEQUENCE_START_TOKEN` would likely cause a transition to a state related to parsing block sequences.
    * **Emitting Flow:** Similar reasoning applies to the emitter with its states and event queue.

5. **Command-Line Arguments and User Errors:**  Since this is just a *definitions* file, it doesn't handle command-line arguments directly. Command-line parsing would occur in the code that *uses* these definitions (like the main YAML parsing and emitting logic). For user errors, I focus on potential misinterpretations of the constants or incorrect usage of the data structures. For example, trying to set an invalid encoding or using the wrong style for a particular node type.

6. **Structuring the Answer:** Finally, I organize the information into the requested format:
    * List the functionalities directly observed from the code.
    * Provide Go code examples to illustrate the data structures, linking them to YAML concepts.
    * Explain the parsing and emitting logic based on the presence of state machines and handler functions.
    * Explicitly state that this file doesn't handle command-line arguments.
    * Provide examples of potential user errors based on misusing the defined types and constants.

7. **Refinement:** I review my answer for clarity, accuracy, and completeness. I make sure to use clear and concise language and explain the reasoning behind my inferences. I also double-check that my Go code examples are correct and relevant. I made sure to explicitly mention that this file is *part of* a larger YAML implementation.

This structured approach, moving from high-level observation to detailed analysis and then back to a structured explanation, helps to thoroughly understand the purpose and functionality of the provided code snippet.
这个 `yamlh.go` 文件是 `gopkg.in/yaml.v2` 库中定义 YAML 数据结构和相关常量的核心头文件。它并没有包含具体的 YAML 解析或生成逻辑的实现，而是为这些功能提供了蓝图。

以下是 `yamlh.go` 中定义的主要功能和概念：

**1. 定义了表示 YAML 文档结构的数据类型：**

* **`yaml_version_directive_t`**:  表示 YAML 版本指令（例如 `%YAML 1.2`）。
* **`yaml_tag_directive_t`**: 表示 YAML 标签指令（例如 `%TAG ! foo:`）。
* **`yaml_document_t`**: 表示一个完整的 YAML 文档，包含节点、版本指令和标签指令。
* **`yaml_node_t`**:  表示 YAML 文档中的一个节点，可以是标量（scalar）、序列（sequence）或映射（mapping）。
* **`yaml_scalar_style_t`**, **`yaml_sequence_style_t`**, **`yaml_mapping_style_t`**:  枚举了 YAML 中不同的标量、序列和映射的样式（例如，单引号、双引号、块状等）。

**2. 定义了表示 YAML 流和事件的数据类型：**

* **`yaml_encoding_t`**:  枚举了 YAML 流的编码方式（UTF-8, UTF-16LE, UTF-16BE）。
* **`yaml_break_t`**: 枚举了 YAML 流的换行符类型（CR, LN, CRLN）。
* **`yaml_token_t`**: 表示 YAML 解析器生成的词法单元（tokens），例如流的开始/结束、文档的开始/结束、键、值、标量等。
* **`yaml_event_t`**: 表示 YAML 解析器生成的事件，是比 token 更高级别的抽象，例如流的开始/结束、文档的开始/结束、标量、序列的开始/结束、映射的开始/结束等。

**3. 定义了错误处理相关的类型：**

* **`yaml_error_type_t`**: 枚举了 YAML 解析或生成过程中可能出现的错误类型（例如内存错误、读取错误、解析错误等）。
* **`yaml_mark_t`**: 表示 YAML 流中某个位置的标记，包含索引、行号和列号，用于错误报告。

**4. 定义了与解析器（Parser）和生成器（Emitter）相关的类型：**

* **`yaml_parser_t`**:  表示 YAML 解析器的状态和上下文信息。它包含了输入流、缓冲区、token 队列、解析状态等。
* **`yaml_parser_state_t`**: 枚举了 YAML 解析器的不同状态，表示解析过程中的不同阶段。
* **`yaml_read_handler_t`**: 定义了读取输入流的回调函数类型，允许自定义输入源。
* **`yaml_emitter_t`**: 表示 YAML 生成器的状态和上下文信息。它包含了输出流、缓冲区、事件队列、生成状态等。
* **`yaml_emitter_state_t`**: 枚举了 YAML 生成器的不同状态，表示生成过程中的不同阶段。
* **`yaml_write_handler_t`**: 定义了写入输出流的回调函数类型，允许自定义输出目标。

**它可以被推断为是 libyaml 库的 Go 绑定中的头文件部分。**  `gopkg.in/yaml.v2` 是一个流行的 Go YAML 库，它基于 C 语言的 libyaml 库。 这个 `yamlh.go` 文件很可能定义了与 libyaml 中结构体和枚举类型对应的 Go 类型。

**Go 代码示例 (推断):**

假设我们要创建一个简单的 YAML 映射，可以这样使用这里定义的类型（注意：这只是类型定义，实际使用需要配合解析器/生成器的实现）：

```go
package main

import "fmt"

// 假设这是从 yamlh.go 文件中复制过来的类型定义
type yaml_node_type_t int
const (
	yaml_MAPPING_NODE yaml_node_type_t = iota + 2 // 根据定义，映射节点的值为 2
	yaml_SCALAR_NODE
)

type yaml_scalar_style_t int8
const (
	yaml_PLAIN_SCALAR_STYLE yaml_scalar_style_t = iota + 1
)

type yaml_node_t struct {
	typ yaml_node_type_t
	tag []byte
	scalar struct {
		value []byte
		length int
		style yaml_scalar_style_t
	}
	mapping struct {
		pairs_data []yaml_node_pair_t
	}
}

type yaml_node_pair_t struct {
	key   int
	value int
}

func main() {
	// 模拟创建一个 YAML 映射: { name: "Alice", age: 30 }

	// 假设我们已经通过某种方式获得了 "name" 和 "Alice" 的节点索引
	nameNodeIndex := 1
	aliceNodeIndex := 2
	ageNodeIndex := 3
	thirtyNodeIndex := 4

	mappingNode := yaml_node_t{
		typ: yaml_MAPPING_NODE,
		mapping: struct{ pairs_data []yaml_node_pair_t }{
			pairs_data: []yaml_node_pair_t{
				{key: nameNodeIndex, value: aliceNodeIndex},
				{key: ageNodeIndex, value: thirtyNodeIndex},
			},
		},
	}

	fmt.Printf("Mapping Node Type: %d\n", mappingNode.typ)
	fmt.Printf("Mapping Pairs: %+v\n", mappingNode.mapping.pairs_data)
}
```

**假设的输入与输出：**

上面的代码示例没有直接的输入输出，因为它只是使用了定义的数据结构。如果结合一个实际的 YAML 解析器，例如，对于 YAML 字符串 `"{ name: Alice, age: 30 }"`，解析器可能会生成一个 `yaml_document_t` 结构，其中包含一个类型为 `yaml_MAPPING_NODE` 的根节点，其 `mapping` 字段会包含指向表示 `"name"`, `"Alice"`, `"age"`, `30` 等标量节点的索引。

**命令行参数处理：**

这个文件本身不涉及命令行参数处理。命令行参数的处理通常发生在调用 YAML 库的应用程序中。例如，一个使用 `gopkg.in/yaml.v2` 的程序可能会使用 `flag` 包来解析命令行参数，指定要解析的 YAML 文件路径。

**使用者易犯错的点 (推断):**

由于 `yamlh.go` 只是定义，使用者直接使用这些类型定义的机会不多。不过，在理解和使用基于这些定义的更高级别的 API 时，可能会犯以下错误：

1. **错误地理解或使用枚举常量：**  例如，不小心使用了错误的 `yaml_encoding_t` 值，导致解析器使用错误的编码方式处理输入。

   ```go
   // 错误示例：假设要解析 UTF-8 编码的 YAML，但错误地使用了 UTF16 编码常量
   var parser yaml_parser_t
   // ... 初始化 parser ...
   parser.encoding = yaml_UTF16LE_ENCODING // 错误！应该使用 yaml_UTF8_ENCODING
   ```

2. **直接操作这些底层结构体：**  通常，YAML 库会提供更高级别的 API 来处理 YAML 的解析和生成，用户应该使用这些 API 而不是直接操作 `yaml_node_t` 等结构体，因为这很容易出错并且不符合库的设计意图。直接操作可能导致内存管理问题或数据结构不一致。

3. **混淆 Token 和 Event 的概念：**  开发者可能会混淆 `yaml_token_t` 和 `yaml_event_t` 的用途。Token 是词法分析的产物，更底层；Event 是语法分析的产物，更高级。错误地尝试直接处理 Token 而不是 Event 可能会导致逻辑错误。

总而言之，`yamlh.go` 是 `gopkg.in/yaml.v2` 库的核心类型定义文件，它为 YAML 的解析和生成提供了基础的数据结构和常量。开发者通常不需要直接操作这个文件中的类型，而是应该使用库提供的高级 API。理解这些定义有助于更深入地理解 YAML 库的工作原理。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/yamlh.go的go语言实现的一部分， 请列举一下它的功能, 　
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

	// The byte about which the problem occured.
	problem_offset int
	problem_value  int
	problem_mark   yaml_mark_t

	// The error context.
	context      string
	context_mark yaml_mark_t

	// Reader stuff

	read_handler yaml_read_handler_t // Read handler.

	input_file io.Reader // File input data.
	input      []byte    // String input data.
	input_pos  int

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
	output_file   io.Writer // File output data.

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