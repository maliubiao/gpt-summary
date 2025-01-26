Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Reading and Identifying the Core Purpose:**

The first step is to read through the code and try to understand the overall theme. Keywords like `emitter`, `buffer`, `flush`, `put`, `write`, `break`, `event`, and state-related terms like `yaml_EMIT_*_STATE` immediately suggest that this code is responsible for *generating* or *outputting* YAML. The `emitterc.go` filename reinforces this idea ("emitter core" perhaps?).

**2. Focusing on Key Data Structures:**

The code frequently uses a pointer `emitter *yaml_emitter_t`. This is clearly the central data structure. We need to understand what it likely contains. By observing how it's used, we can infer its members:

* `buffer`:  Used for temporary storage of the output.
* `buffer_pos`:  Keeps track of the current position in the buffer.
* `column`, `line`:  Track the current position in the output stream (for formatting).
* `line_break`:  Stores the desired line break style (CR, LN, CRLF).
* `events`:  A queue or list of events to be processed.
* `events_head`: Index of the next event to process.
* `state`:  Represents the current state of the emitter (e.g., emitting a stream start, document start, etc.).
* `indents`:  A stack to manage indentation levels.
* `indent`: Current indentation level.
* `best_indent`, `best_width`: Configuration options for formatting.
* `tag_directives`:  Stores tag directives (like `%TAG !foo! tag:example.com`).
* `error`, `problem`:  For error reporting.

**3. Analyzing Individual Functions:**

Now, go through each function and determine its specific role:

* **`flush`**:  Checks if the buffer is almost full and calls `yaml_emitter_flush` if necessary. This suggests `yaml_emitter_flush` is the low-level function that actually writes the buffer content to the output.
* **`put`**: Adds a single byte to the buffer, updating position and column. It also calls `flush` if the buffer is near capacity.
* **`put_break`**: Adds a line break to the buffer, respecting the configured `line_break` style and updating line/column.
* **`write`**: Writes a possibly multi-byte character from a byte slice to the buffer. It handles UTF-8 encoding by looking at the width of the character.
* **`write_all`**:  Writes an entire byte slice to the buffer using `write`.
* **`write_break`**: Writes a line break character, handling both `\n` and platform-specific line endings.
* **`yaml_emitter_set_emitter_error`**: Sets the error state in the emitter.
* **`yaml_emitter_emit`**: Appends an event to the event queue and then processes events until no more are needed.
* **`yaml_emitter_need_more_events`**: Determines if more events need to be buffered based on the types of the current and pending events. This seems related to lookahead or buffering for complex YAML structures.
* **`yaml_emitter_append_tag_directive`**:  Adds a tag directive to the emitter's list, checking for duplicates.
* **`yaml_emitter_increase_indent`**:  Increases the indentation level.
* **`yaml_emitter_state_machine`**: A central dispatcher that calls specific state-handling functions based on the current `emitter.state`.
* **`yaml_emitter_emit_stream_start``, `yaml_emitter_emit_document_start`, etc.**: These functions handle the logic for emitting specific YAML structures (stream start, document start, scalars, sequences, mappings). They manage the output buffer, indentation, and state transitions.
* **`yaml_emitter_emit_node`**: A higher-level function that dispatches to specific event emitters based on the event type (scalar, sequence, mapping, alias).
* **`yaml_emitter_check_empty_document`, `yaml_emitter_check_empty_sequence`, `yaml_emitter_check_empty_mapping`**:  Functions to peek ahead in the event stream to detect empty structures.
* **`yaml_emitter_check_simple_key`**:  Checks if a key can be represented in a "simple key" style (no quotes).
* **`yaml_emitter_select_scalar_style`**:  Determines the appropriate quoting style for a scalar value.
* **`yaml_emitter_process_anchor`, `yaml_emitter_process_tag`, `yaml_emitter_process_scalar`**: Functions to handle the output of anchors, tags, and scalar values respectively.
* **`yaml_emitter_analyze_version_directive`, `yaml_emitter_analyze_tag_directive`, `yaml_emitter_analyze_anchor`, `yaml_emitter_analyze_tag`, `yaml_emitter_analyze_scalar`**:  These functions validate the components of YAML structures before emitting them.

**4. Inferring the Overall Functionality:**

By understanding the individual functions, we can infer the overall functionality. This code is part of a YAML *emitter*. It takes a series of events representing a YAML document and converts them into a formatted YAML string. It handles:

* **Buffering:**  Optimizing output by writing to a buffer and flushing it periodically.
* **Formatting:**  Managing indentation, line breaks, and quoting styles.
* **State Management:**  Using a state machine to ensure the correct sequence of YAML elements is emitted.
* **Event Processing:**  Consuming a stream of events that represent the YAML structure.
* **Validation:**  Checking the validity of YAML constructs.

**5. Formulating the Summary:**

Finally, summarize the findings in clear and concise language, as presented in the initial example answer. Highlight the key responsibilities and the general workflow.

This systematic approach of reading, identifying key structures, analyzing individual components, and then synthesizing the overall purpose is crucial for understanding complex code like this. The process often involves making educated guesses and refining them as more information becomes available.
这段Go语言代码是 `gopkg.in/yaml.v2` 库中 YAML **发射器 (Emitter)** 的一部分，负责将 YAML 的内部事件 (events) 转换成最终的 YAML 文本输出。

**功能归纳:**

这段代码的核心功能是 **高效地将 YAML 的逻辑结构 (通过事件表示) 转换为格式化的 YAML 文本并输出**。 它主要负责以下方面：

1. **缓冲输出:**  它使用缓冲区 (`emitter.buffer`) 来暂存要输出的 YAML 文本，避免频繁的底层写入操作，提高效率。
2. **基本的字符和换行符写入:** 提供了 `put` 和 `put_break` 函数，用于向缓冲区写入单个字符和换行符，并根据配置的换行符类型 (`yaml_CR_BREAK`, `yaml_LN_BREAK`, `yaml_CRLN_BREAK`) 进行处理。
3. **字符串写入:** 提供了 `write` 和 `write_all` 函数，用于将字符串写入缓冲区，`write` 函数还能处理 UTF-8 字符的宽度。
4. **事件处理和状态机:**  `yaml_emitter_emit` 函数接收 YAML 事件，并将它们添加到事件队列中。 `yaml_emitter_state_machine` 函数是一个状态机，根据当前的发射器状态 (`emitter.state`) 和接收到的事件类型，调用相应的处理函数来生成 YAML 输出。
5. **管理事件队列:** `yaml_emitter_need_more_events` 函数判断是否需要更多的事件才能继续发射 YAML 结构，这在处理嵌套结构（如序列和映射）时很重要。
6. **处理指令 (Directives):**  `yaml_emitter_append_tag_directive` 函数用于添加和管理 YAML 的指令，例如 `%TAG`。
7. **管理缩进:** `yaml_emitter_increase_indent` 函数用于增加缩进级别，控制 YAML 输出的格式。
8. **错误处理:** `yaml_emitter_set_emitter_error` 函数用于设置发射器错误状态。
9. **具体的 YAML 结构发射:**  以 `yaml_emitter_emit_` 开头的函数（例如 `yaml_emitter_emit_stream_start`, `yaml_emitter_emit_document_start`, `yaml_emitter_emit_scalar` 等）负责根据不同的 YAML 事件生成相应的 YAML 文本片段。
10. **YAML 元素分析和校验:**  以 `yaml_emitter_analyze_` 开头的函数（例如 `yaml_emitter_analyze_version_directive`, `yaml_emitter_analyze_tag_directive`, `yaml_emitter_analyze_scalar` 等）负责在发射前分析和校验 YAML 元素的有效性，例如标签、锚点、标量等。
11. **格式化控制:** 代码中涉及到对 YAML 输出格式的控制，例如是否使用 canonical 格式、缩进大小、行宽限制等。
12. **处理锚点和标签:** `yaml_emitter_process_anchor` 和 `yaml_emitter_process_tag` 函数负责输出 YAML 的锚点 (`&` 和 `*`) 和标签。
13. **选择标量样式:** `yaml_emitter_select_scalar_style` 函数根据标量的内容和上下文选择合适的标量样式（例如，plain, single-quoted, double-quoted, literal, folded）。
14. **检查空结构:** `yaml_emitter_check_empty_document`, `yaml_emitter_check_empty_sequence`, `yaml_emitter_check_empty_mapping` 函数用于检查是否是空的文档、序列或映射。
15. **检查简单键:** `yaml_emitter_check_simple_key` 函数用于判断一个键是否可以作为简单键输出 (不带引号)。

**它是什么Go语言功能的实现：**

这段代码实现了一个 **状态驱动的有限状态机 (Finite State Machine)**。

* **状态 (`emitter.state`)**: 代表了发射器当前正在处理的 YAML 结构部分 (例如，正在发射文档的开始，正在发射序列的元素等)。
* **事件 (`yaml_event_t`)**:  触发状态转换的输入。 每个事件代表了 YAML 文档中的一个逻辑单元 (例如，流的开始，文档的开始，标量值，序列的开始等)。
* **状态转换函数 (`yaml_emitter_state_machine` 和 `yaml_emitter_emit_*`)**:  根据当前状态和接收到的事件，执行相应的操作，生成 YAML 文本，并可能将发射器状态转移到下一个状态。

**Go 代码举例说明 (推理):**

虽然我们没有看到 `yaml_emitter_t` 和 `yaml_event_t` 的完整定义，但我们可以根据代码推断其大致结构。假设我们有以下 YAML 内容要生成：

```yaml
name: Alice
age: 30
```

发射器会接收到一系列事件，然后根据状态机逐步生成文本。以下是一个简化的模拟：

```go
package main

import "fmt"

// 假设的事件类型
type yaml_event_type int

const (
	yaml_STREAM_START_EVENT yaml_event_type = iota
	yaml_DOCUMENT_START_EVENT
	yaml_MAPPING_START_EVENT
	yaml_SCALAR_EVENT
	yaml_MAPPING_END_EVENT
	yaml_DOCUMENT_END_EVENT
	yaml_STREAM_END_EVENT
)

// 假设的事件结构
type yaml_event_t struct {
	typ          yaml_event_type
	value        []byte // 标量值
	implicit     bool
	scalar_style int // 标量样式
	// ... 其他字段
}

// 假设的发射器结构 (部分)
type yaml_emitter_t struct {
	buffer     []byte
	buffer_pos int
	column     int
	line       int
	state      int // 代表发射器状态
	// ... 其他字段
}

func main() {
	emitter := &yaml_emitter_t{
		buffer: make([]byte, 1024), // 初始化缓冲区
		state:  0,                  // 假设初始状态为 0
	}

	// 模拟接收事件
	events := []yaml_event_t{
		{typ: yaml_STREAM_START_EVENT},
		{typ: yaml_DOCUMENT_START_EVENT},
		{typ: yaml_MAPPING_START_EVENT},
		{typ: yaml_SCALAR_EVENT, value: []byte("name")},
		{typ: yaml_SCALAR_EVENT, value: []byte("Alice")},
		{typ: yaml_SCALAR_EVENT, value: []byte("age")},
		{typ: yaml_SCALAR_EVENT, value: []byte("30")},
		{typ: yaml_MAPPING_END_EVENT},
		{typ: yaml_DOCUMENT_END_EVENT},
		{typ: yaml_STREAM_END_EVENT},
	}

	// 模拟发射过程 (简化)
	for _, event := range events {
		switch event.typ {
		case yaml_STREAM_START_EVENT:
			fmt.Println("开始输出流")
		case yaml_DOCUMENT_START_EVENT:
			fmt.Println("---")
		case yaml_MAPPING_START_EVENT:
			// ...
		case yaml_SCALAR_EVENT:
			// 这里会根据状态和标量值调用 put 或 write 函数将文本添加到 emitter.buffer
			fmt.Println(string(event.value) + ": ") // 简化输出
		case yaml_MAPPING_END_EVENT:
			// ...
		case yaml_DOCUMENT_END_EVENT:
			fmt.Println("...")
		case yaml_STREAM_END_EVENT:
			fmt.Println("流结束")
		}
	}

	// 最终 emitter.buffer 中会包含生成的 YAML 文本
	// fmt.Println(string(emitter.buffer[:emitter.buffer_pos]))
}
```

**假设的输入与输出 (基于上述代码):**

**输入 (模拟的事件序列):**

```
事件类型: yaml_STREAM_START_EVENT
事件类型: yaml_DOCUMENT_START_EVENT
事件类型: yaml_MAPPING_START_EVENT
事件类型: yaml_SCALAR_EVENT, 值: "name"
事件类型: yaml_SCALAR_EVENT, 值: "Alice"
事件类型: yaml_SCALAR_EVENT, 值: "age"
事件类型: yaml_SCALAR_EVENT, 值: "30"
事件类型: yaml_MAPPING_END_EVENT
事件类型: yaml_DOCUMENT_END_EVENT
事件类型: yaml_STREAM_END_EVENT
```

**输出 (模拟的简化输出):**

```
开始输出流
---
name:
Alice:
age:
30:
...
流结束
```

**注意:**  实际的输出会更复杂，包括正确的缩进、冒号和空格等格式。这个例子只是为了说明事件驱动和状态机的概念。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。 命令行参数的处理通常发生在调用这个库的更上层代码中。 上层代码会根据命令行参数配置发射器的行为，例如：

* **缩进量:**  可能会影响 `emitter.best_indent` 的值。
* **行宽限制:** 可能会影响 `emitter.best_width` 的值。
* **是否使用 canonical 格式:** 可能会设置 `emitter.canonical` 的值。
* **换行符类型:** 可能会设置 `emitter.line_break` 的值。

**使用者易犯错的点 (推理):**

虽然我们没有看到用户直接调用这些底层函数的例子，但根据其功能，可以推测以下易错点：

* **不正确的事件序列:**  使用者需要按照 YAML 规范生成正确的事件序列。例如，在 `yaml_MAPPING_START_EVENT` 之后，应该交替出现键和值的 `yaml_SCALAR_EVENT` 或其他复合节点的开始事件，最后以 `yaml_MAPPING_END_EVENT` 结束。如果事件顺序错误，会导致生成的 YAML 不符合规范。
* **标量值的格式不当:** 虽然发射器会尝试选择合适的标量样式，但如果提供的标量值包含特殊字符，使用者可能需要显式地设置标量样式以确保正确转义或引用。
* **忘记结束复合节点:**  例如，在开始一个序列 (`yaml_SEQUENCE_START_EVENT`) 或映射 (`yaml_MAPPING_START_EVENT`) 后，必须确保最终有对应的结束事件 (`yaml_SEQUENCE_END_EVENT` 或 `yaml_MAPPING_END_EVENT`)。
* **对齐问题 (间接):**  虽然这段代码负责处理缩进，但生成事件的上层代码需要正确地指示何时开始和结束需要缩进的结构。如果上层代码逻辑错误，即使发射器工作正常，也可能导致输出的 YAML 对齐不正确。

**总结:**

这段 `emitterc.go` 代码是 `gopkg.in/yaml.v2` 库中 YAML 发射器的核心部分，它使用状态机模式，通过处理 YAML 事件，高效且正确地将 YAML 的逻辑结构转换为最终的 YAML 文本输出。 它负责缓冲、格式化、处理指令、管理缩进、处理锚点和标签以及选择合适的标量样式。 使用者需要生成正确的事件序列才能利用这个发射器生成有效的 YAML 文档.

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/emitterc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
package yaml

import (
	"bytes"
	"fmt"
)

// Flush the buffer if needed.
func flush(emitter *yaml_emitter_t) bool {
	if emitter.buffer_pos+5 >= len(emitter.buffer) {
		return yaml_emitter_flush(emitter)
	}
	return true
}

// Put a character to the output buffer.
func put(emitter *yaml_emitter_t, value byte) bool {
	if emitter.buffer_pos+5 >= len(emitter.buffer) && !yaml_emitter_flush(emitter) {
		return false
	}
	emitter.buffer[emitter.buffer_pos] = value
	emitter.buffer_pos++
	emitter.column++
	return true
}

// Put a line break to the output buffer.
func put_break(emitter *yaml_emitter_t) bool {
	if emitter.buffer_pos+5 >= len(emitter.buffer) && !yaml_emitter_flush(emitter) {
		return false
	}
	switch emitter.line_break {
	case yaml_CR_BREAK:
		emitter.buffer[emitter.buffer_pos] = '\r'
		emitter.buffer_pos += 1
	case yaml_LN_BREAK:
		emitter.buffer[emitter.buffer_pos] = '\n'
		emitter.buffer_pos += 1
	case yaml_CRLN_BREAK:
		emitter.buffer[emitter.buffer_pos+0] = '\r'
		emitter.buffer[emitter.buffer_pos+1] = '\n'
		emitter.buffer_pos += 2
	default:
		panic("unknown line break setting")
	}
	emitter.column = 0
	emitter.line++
	return true
}

// Copy a character from a string into buffer.
func write(emitter *yaml_emitter_t, s []byte, i *int) bool {
	if emitter.buffer_pos+5 >= len(emitter.buffer) && !yaml_emitter_flush(emitter) {
		return false
	}
	p := emitter.buffer_pos
	w := width(s[*i])
	switch w {
	case 4:
		emitter.buffer[p+3] = s[*i+3]
		fallthrough
	case 3:
		emitter.buffer[p+2] = s[*i+2]
		fallthrough
	case 2:
		emitter.buffer[p+1] = s[*i+1]
		fallthrough
	case 1:
		emitter.buffer[p+0] = s[*i+0]
	default:
		panic("unknown character width")
	}
	emitter.column++
	emitter.buffer_pos += w
	*i += w
	return true
}

// Write a whole string into buffer.
func write_all(emitter *yaml_emitter_t, s []byte) bool {
	for i := 0; i < len(s); {
		if !write(emitter, s, &i) {
			return false
		}
	}
	return true
}

// Copy a line break character from a string into buffer.
func write_break(emitter *yaml_emitter_t, s []byte, i *int) bool {
	if s[*i] == '\n' {
		if !put_break(emitter) {
			return false
		}
		*i++
	} else {
		if !write(emitter, s, i) {
			return false
		}
		emitter.column = 0
		emitter.line++
	}
	return true
}

// Set an emitter error and return false.
func yaml_emitter_set_emitter_error(emitter *yaml_emitter_t, problem string) bool {
	emitter.error = yaml_EMITTER_ERROR
	emitter.problem = problem
	return false
}

// Emit an event.
func yaml_emitter_emit(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	emitter.events = append(emitter.events, *event)
	for !yaml_emitter_need_more_events(emitter) {
		event := &emitter.events[emitter.events_head]
		if !yaml_emitter_analyze_event(emitter, event) {
			return false
		}
		if !yaml_emitter_state_machine(emitter, event) {
			return false
		}
		yaml_event_delete(event)
		emitter.events_head++
	}
	return true
}

// Check if we need to accumulate more events before emitting.
//
// We accumulate extra
//  - 1 event for DOCUMENT-START
//  - 2 events for SEQUENCE-START
//  - 3 events for MAPPING-START
//
func yaml_emitter_need_more_events(emitter *yaml_emitter_t) bool {
	if emitter.events_head == len(emitter.events) {
		return true
	}
	var accumulate int
	switch emitter.events[emitter.events_head].typ {
	case yaml_DOCUMENT_START_EVENT:
		accumulate = 1
		break
	case yaml_SEQUENCE_START_EVENT:
		accumulate = 2
		break
	case yaml_MAPPING_START_EVENT:
		accumulate = 3
		break
	default:
		return false
	}
	if len(emitter.events)-emitter.events_head > accumulate {
		return false
	}
	var level int
	for i := emitter.events_head; i < len(emitter.events); i++ {
		switch emitter.events[i].typ {
		case yaml_STREAM_START_EVENT, yaml_DOCUMENT_START_EVENT, yaml_SEQUENCE_START_EVENT, yaml_MAPPING_START_EVENT:
			level++
		case yaml_STREAM_END_EVENT, yaml_DOCUMENT_END_EVENT, yaml_SEQUENCE_END_EVENT, yaml_MAPPING_END_EVENT:
			level--
		}
		if level == 0 {
			return false
		}
	}
	return true
}

// Append a directive to the directives stack.
func yaml_emitter_append_tag_directive(emitter *yaml_emitter_t, value *yaml_tag_directive_t, allow_duplicates bool) bool {
	for i := 0; i < len(emitter.tag_directives); i++ {
		if bytes.Equal(value.handle, emitter.tag_directives[i].handle) {
			if allow_duplicates {
				return true
			}
			return yaml_emitter_set_emitter_error(emitter, "duplicate %TAG directive")
		}
	}

	// [Go] Do we actually need to copy this given garbage collection
	// and the lack of deallocating destructors?
	tag_copy := yaml_tag_directive_t{
		handle: make([]byte, len(value.handle)),
		prefix: make([]byte, len(value.prefix)),
	}
	copy(tag_copy.handle, value.handle)
	copy(tag_copy.prefix, value.prefix)
	emitter.tag_directives = append(emitter.tag_directives, tag_copy)
	return true
}

// Increase the indentation level.
func yaml_emitter_increase_indent(emitter *yaml_emitter_t, flow, indentless bool) bool {
	emitter.indents = append(emitter.indents, emitter.indent)
	if emitter.indent < 0 {
		if flow {
			emitter.indent = emitter.best_indent
		} else {
			emitter.indent = 0
		}
	} else if !indentless {
		emitter.indent += emitter.best_indent
	}
	return true
}

// State dispatcher.
func yaml_emitter_state_machine(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	switch emitter.state {
	default:
	case yaml_EMIT_STREAM_START_STATE:
		return yaml_emitter_emit_stream_start(emitter, event)

	case yaml_EMIT_FIRST_DOCUMENT_START_STATE:
		return yaml_emitter_emit_document_start(emitter, event, true)

	case yaml_EMIT_DOCUMENT_START_STATE:
		return yaml_emitter_emit_document_start(emitter, event, false)

	case yaml_EMIT_DOCUMENT_CONTENT_STATE:
		return yaml_emitter_emit_document_content(emitter, event)

	case yaml_EMIT_DOCUMENT_END_STATE:
		return yaml_emitter_emit_document_end(emitter, event)

	case yaml_EMIT_FLOW_SEQUENCE_FIRST_ITEM_STATE:
		return yaml_emitter_emit_flow_sequence_item(emitter, event, true)

	case yaml_EMIT_FLOW_SEQUENCE_ITEM_STATE:
		return yaml_emitter_emit_flow_sequence_item(emitter, event, false)

	case yaml_EMIT_FLOW_MAPPING_FIRST_KEY_STATE:
		return yaml_emitter_emit_flow_mapping_key(emitter, event, true)

	case yaml_EMIT_FLOW_MAPPING_KEY_STATE:
		return yaml_emitter_emit_flow_mapping_key(emitter, event, false)

	case yaml_EMIT_FLOW_MAPPING_SIMPLE_VALUE_STATE:
		return yaml_emitter_emit_flow_mapping_value(emitter, event, true)

	case yaml_EMIT_FLOW_MAPPING_VALUE_STATE:
		return yaml_emitter_emit_flow_mapping_value(emitter, event, false)

	case yaml_EMIT_BLOCK_SEQUENCE_FIRST_ITEM_STATE:
		return yaml_emitter_emit_block_sequence_item(emitter, event, true)

	case yaml_EMIT_BLOCK_SEQUENCE_ITEM_STATE:
		return yaml_emitter_emit_block_sequence_item(emitter, event, false)

	case yaml_EMIT_BLOCK_MAPPING_FIRST_KEY_STATE:
		return yaml_emitter_emit_block_mapping_key(emitter, event, true)

	case yaml_EMIT_BLOCK_MAPPING_KEY_STATE:
		return yaml_emitter_emit_block_mapping_key(emitter, event, false)

	case yaml_EMIT_BLOCK_MAPPING_SIMPLE_VALUE_STATE:
		return yaml_emitter_emit_block_mapping_value(emitter, event, true)

	case yaml_EMIT_BLOCK_MAPPING_VALUE_STATE:
		return yaml_emitter_emit_block_mapping_value(emitter, event, false)

	case yaml_EMIT_END_STATE:
		return yaml_emitter_set_emitter_error(emitter, "expected nothing after STREAM-END")
	}
	panic("invalid emitter state")
}

// Expect STREAM-START.
func yaml_emitter_emit_stream_start(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	if event.typ != yaml_STREAM_START_EVENT {
		return yaml_emitter_set_emitter_error(emitter, "expected STREAM-START")
	}
	if emitter.encoding == yaml_ANY_ENCODING {
		emitter.encoding = event.encoding
		if emitter.encoding == yaml_ANY_ENCODING {
			emitter.encoding = yaml_UTF8_ENCODING
		}
	}
	if emitter.best_indent < 2 || emitter.best_indent > 9 {
		emitter.best_indent = 2
	}
	if emitter.best_width >= 0 && emitter.best_width <= emitter.best_indent*2 {
		emitter.best_width = 80
	}
	if emitter.best_width < 0 {
		emitter.best_width = 1<<31 - 1
	}
	if emitter.line_break == yaml_ANY_BREAK {
		emitter.line_break = yaml_LN_BREAK
	}

	emitter.indent = -1
	emitter.line = 0
	emitter.column = 0
	emitter.whitespace = true
	emitter.indention = true

	if emitter.encoding != yaml_UTF8_ENCODING {
		if !yaml_emitter_write_bom(emitter) {
			return false
		}
	}
	emitter.state = yaml_EMIT_FIRST_DOCUMENT_START_STATE
	return true
}

// Expect DOCUMENT-START or STREAM-END.
func yaml_emitter_emit_document_start(emitter *yaml_emitter_t, event *yaml_event_t, first bool) bool {

	if event.typ == yaml_DOCUMENT_START_EVENT {

		if event.version_directive != nil {
			if !yaml_emitter_analyze_version_directive(emitter, event.version_directive) {
				return false
			}
		}

		for i := 0; i < len(event.tag_directives); i++ {
			tag_directive := &event.tag_directives[i]
			if !yaml_emitter_analyze_tag_directive(emitter, tag_directive) {
				return false
			}
			if !yaml_emitter_append_tag_directive(emitter, tag_directive, false) {
				return false
			}
		}

		for i := 0; i < len(default_tag_directives); i++ {
			tag_directive := &default_tag_directives[i]
			if !yaml_emitter_append_tag_directive(emitter, tag_directive, true) {
				return false
			}
		}

		implicit := event.implicit
		if !first || emitter.canonical {
			implicit = false
		}

		if emitter.open_ended && (event.version_directive != nil || len(event.tag_directives) > 0) {
			if !yaml_emitter_write_indicator(emitter, []byte("..."), true, false, false) {
				return false
			}
			if !yaml_emitter_write_indent(emitter) {
				return false
			}
		}

		if event.version_directive != nil {
			implicit = false
			if !yaml_emitter_write_indicator(emitter, []byte("%YAML"), true, false, false) {
				return false
			}
			if !yaml_emitter_write_indicator(emitter, []byte("1.1"), true, false, false) {
				return false
			}
			if !yaml_emitter_write_indent(emitter) {
				return false
			}
		}

		if len(event.tag_directives) > 0 {
			implicit = false
			for i := 0; i < len(event.tag_directives); i++ {
				tag_directive := &event.tag_directives[i]
				if !yaml_emitter_write_indicator(emitter, []byte("%TAG"), true, false, false) {
					return false
				}
				if !yaml_emitter_write_tag_handle(emitter, tag_directive.handle) {
					return false
				}
				if !yaml_emitter_write_tag_content(emitter, tag_directive.prefix, true) {
					return false
				}
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
			}
		}

		if yaml_emitter_check_empty_document(emitter) {
			implicit = false
		}
		if !implicit {
			if !yaml_emitter_write_indent(emitter) {
				return false
			}
			if !yaml_emitter_write_indicator(emitter, []byte("---"), true, false, false) {
				return false
			}
			if emitter.canonical {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
			}
		}

		emitter.state = yaml_EMIT_DOCUMENT_CONTENT_STATE
		return true
	}

	if event.typ == yaml_STREAM_END_EVENT {
		if emitter.open_ended {
			if !yaml_emitter_write_indicator(emitter, []byte("..."), true, false, false) {
				return false
			}
			if !yaml_emitter_write_indent(emitter) {
				return false
			}
		}
		if !yaml_emitter_flush(emitter) {
			return false
		}
		emitter.state = yaml_EMIT_END_STATE
		return true
	}

	return yaml_emitter_set_emitter_error(emitter, "expected DOCUMENT-START or STREAM-END")
}

// Expect the root node.
func yaml_emitter_emit_document_content(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	emitter.states = append(emitter.states, yaml_EMIT_DOCUMENT_END_STATE)
	return yaml_emitter_emit_node(emitter, event, true, false, false, false)
}

// Expect DOCUMENT-END.
func yaml_emitter_emit_document_end(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	if event.typ != yaml_DOCUMENT_END_EVENT {
		return yaml_emitter_set_emitter_error(emitter, "expected DOCUMENT-END")
	}
	if !yaml_emitter_write_indent(emitter) {
		return false
	}
	if !event.implicit {
		// [Go] Allocate the slice elsewhere.
		if !yaml_emitter_write_indicator(emitter, []byte("..."), true, false, false) {
			return false
		}
		if !yaml_emitter_write_indent(emitter) {
			return false
		}
	}
	if !yaml_emitter_flush(emitter) {
		return false
	}
	emitter.state = yaml_EMIT_DOCUMENT_START_STATE
	emitter.tag_directives = emitter.tag_directives[:0]
	return true
}

// Expect a flow item node.
func yaml_emitter_emit_flow_sequence_item(emitter *yaml_emitter_t, event *yaml_event_t, first bool) bool {
	if first {
		if !yaml_emitter_write_indicator(emitter, []byte{'['}, true, true, false) {
			return false
		}
		if !yaml_emitter_increase_indent(emitter, true, false) {
			return false
		}
		emitter.flow_level++
	}

	if event.typ == yaml_SEQUENCE_END_EVENT {
		emitter.flow_level--
		emitter.indent = emitter.indents[len(emitter.indents)-1]
		emitter.indents = emitter.indents[:len(emitter.indents)-1]
		if emitter.canonical && !first {
			if !yaml_emitter_write_indicator(emitter, []byte{','}, false, false, false) {
				return false
			}
			if !yaml_emitter_write_indent(emitter) {
				return false
			}
		}
		if !yaml_emitter_write_indicator(emitter, []byte{']'}, false, false, false) {
			return false
		}
		emitter.state = emitter.states[len(emitter.states)-1]
		emitter.states = emitter.states[:len(emitter.states)-1]

		return true
	}

	if !first {
		if !yaml_emitter_write_indicator(emitter, []byte{','}, false, false, false) {
			return false
		}
	}

	if emitter.canonical || emitter.column > emitter.best_width {
		if !yaml_emitter_write_indent(emitter) {
			return false
		}
	}
	emitter.states = append(emitter.states, yaml_EMIT_FLOW_SEQUENCE_ITEM_STATE)
	return yaml_emitter_emit_node(emitter, event, false, true, false, false)
}

// Expect a flow key node.
func yaml_emitter_emit_flow_mapping_key(emitter *yaml_emitter_t, event *yaml_event_t, first bool) bool {
	if first {
		if !yaml_emitter_write_indicator(emitter, []byte{'{'}, true, true, false) {
			return false
		}
		if !yaml_emitter_increase_indent(emitter, true, false) {
			return false
		}
		emitter.flow_level++
	}

	if event.typ == yaml_MAPPING_END_EVENT {
		emitter.flow_level--
		emitter.indent = emitter.indents[len(emitter.indents)-1]
		emitter.indents = emitter.indents[:len(emitter.indents)-1]
		if emitter.canonical && !first {
			if !yaml_emitter_write_indicator(emitter, []byte{','}, false, false, false) {
				return false
			}
			if !yaml_emitter_write_indent(emitter) {
				return false
			}
		}
		if !yaml_emitter_write_indicator(emitter, []byte{'}'}, false, false, false) {
			return false
		}
		emitter.state = emitter.states[len(emitter.states)-1]
		emitter.states = emitter.states[:len(emitter.states)-1]
		return true
	}

	if !first {
		if !yaml_emitter_write_indicator(emitter, []byte{','}, false, false, false) {
			return false
		}
	}
	if emitter.canonical || emitter.column > emitter.best_width {
		if !yaml_emitter_write_indent(emitter) {
			return false
		}
	}

	if !emitter.canonical && yaml_emitter_check_simple_key(emitter) {
		emitter.states = append(emitter.states, yaml_EMIT_FLOW_MAPPING_SIMPLE_VALUE_STATE)
		return yaml_emitter_emit_node(emitter, event, false, false, true, true)
	}
	if !yaml_emitter_write_indicator(emitter, []byte{'?'}, true, false, false) {
		return false
	}
	emitter.states = append(emitter.states, yaml_EMIT_FLOW_MAPPING_VALUE_STATE)
	return yaml_emitter_emit_node(emitter, event, false, false, true, false)
}

// Expect a flow value node.
func yaml_emitter_emit_flow_mapping_value(emitter *yaml_emitter_t, event *yaml_event_t, simple bool) bool {
	if simple {
		if !yaml_emitter_write_indicator(emitter, []byte{':'}, false, false, false) {
			return false
		}
	} else {
		if emitter.canonical || emitter.column > emitter.best_width {
			if !yaml_emitter_write_indent(emitter) {
				return false
			}
		}
		if !yaml_emitter_write_indicator(emitter, []byte{':'}, true, false, false) {
			return false
		}
	}
	emitter.states = append(emitter.states, yaml_EMIT_FLOW_MAPPING_KEY_STATE)
	return yaml_emitter_emit_node(emitter, event, false, false, true, false)
}

// Expect a block item node.
func yaml_emitter_emit_block_sequence_item(emitter *yaml_emitter_t, event *yaml_event_t, first bool) bool {
	if first {
		if !yaml_emitter_increase_indent(emitter, false, emitter.mapping_context && !emitter.indention) {
			return false
		}
	}
	if event.typ == yaml_SEQUENCE_END_EVENT {
		emitter.indent = emitter.indents[len(emitter.indents)-1]
		emitter.indents = emitter.indents[:len(emitter.indents)-1]
		emitter.state = emitter.states[len(emitter.states)-1]
		emitter.states = emitter.states[:len(emitter.states)-1]
		return true
	}
	if !yaml_emitter_write_indent(emitter) {
		return false
	}
	if !yaml_emitter_write_indicator(emitter, []byte{'-'}, true, false, true) {
		return false
	}
	emitter.states = append(emitter.states, yaml_EMIT_BLOCK_SEQUENCE_ITEM_STATE)
	return yaml_emitter_emit_node(emitter, event, false, true, false, false)
}

// Expect a block key node.
func yaml_emitter_emit_block_mapping_key(emitter *yaml_emitter_t, event *yaml_event_t, first bool) bool {
	if first {
		if !yaml_emitter_increase_indent(emitter, false, false) {
			return false
		}
	}
	if event.typ == yaml_MAPPING_END_EVENT {
		emitter.indent = emitter.indents[len(emitter.indents)-1]
		emitter.indents = emitter.indents[:len(emitter.indents)-1]
		emitter.state = emitter.states[len(emitter.states)-1]
		emitter.states = emitter.states[:len(emitter.states)-1]
		return true
	}
	if !yaml_emitter_write_indent(emitter) {
		return false
	}
	if yaml_emitter_check_simple_key(emitter) {
		emitter.states = append(emitter.states, yaml_EMIT_BLOCK_MAPPING_SIMPLE_VALUE_STATE)
		return yaml_emitter_emit_node(emitter, event, false, false, true, true)
	}
	if !yaml_emitter_write_indicator(emitter, []byte{'?'}, true, false, true) {
		return false
	}
	emitter.states = append(emitter.states, yaml_EMIT_BLOCK_MAPPING_VALUE_STATE)
	return yaml_emitter_emit_node(emitter, event, false, false, true, false)
}

// Expect a block value node.
func yaml_emitter_emit_block_mapping_value(emitter *yaml_emitter_t, event *yaml_event_t, simple bool) bool {
	if simple {
		if !yaml_emitter_write_indicator(emitter, []byte{':'}, false, false, false) {
			return false
		}
	} else {
		if !yaml_emitter_write_indent(emitter) {
			return false
		}
		if !yaml_emitter_write_indicator(emitter, []byte{':'}, true, false, true) {
			return false
		}
	}
	emitter.states = append(emitter.states, yaml_EMIT_BLOCK_MAPPING_KEY_STATE)
	return yaml_emitter_emit_node(emitter, event, false, false, true, false)
}

// Expect a node.
func yaml_emitter_emit_node(emitter *yaml_emitter_t, event *yaml_event_t,
	root bool, sequence bool, mapping bool, simple_key bool) bool {

	emitter.root_context = root
	emitter.sequence_context = sequence
	emitter.mapping_context = mapping
	emitter.simple_key_context = simple_key

	switch event.typ {
	case yaml_ALIAS_EVENT:
		return yaml_emitter_emit_alias(emitter, event)
	case yaml_SCALAR_EVENT:
		return yaml_emitter_emit_scalar(emitter, event)
	case yaml_SEQUENCE_START_EVENT:
		return yaml_emitter_emit_sequence_start(emitter, event)
	case yaml_MAPPING_START_EVENT:
		return yaml_emitter_emit_mapping_start(emitter, event)
	default:
		return yaml_emitter_set_emitter_error(emitter,
			fmt.Sprintf("expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS, but got %v", event.typ))
	}
}

// Expect ALIAS.
func yaml_emitter_emit_alias(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	if !yaml_emitter_process_anchor(emitter) {
		return false
	}
	emitter.state = emitter.states[len(emitter.states)-1]
	emitter.states = emitter.states[:len(emitter.states)-1]
	return true
}

// Expect SCALAR.
func yaml_emitter_emit_scalar(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	if !yaml_emitter_select_scalar_style(emitter, event) {
		return false
	}
	if !yaml_emitter_process_anchor(emitter) {
		return false
	}
	if !yaml_emitter_process_tag(emitter) {
		return false
	}
	if !yaml_emitter_increase_indent(emitter, true, false) {
		return false
	}
	if !yaml_emitter_process_scalar(emitter) {
		return false
	}
	emitter.indent = emitter.indents[len(emitter.indents)-1]
	emitter.indents = emitter.indents[:len(emitter.indents)-1]
	emitter.state = emitter.states[len(emitter.states)-1]
	emitter.states = emitter.states[:len(emitter.states)-1]
	return true
}

// Expect SEQUENCE-START.
func yaml_emitter_emit_sequence_start(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	if !yaml_emitter_process_anchor(emitter) {
		return false
	}
	if !yaml_emitter_process_tag(emitter) {
		return false
	}
	if emitter.flow_level > 0 || emitter.canonical || event.sequence_style() == yaml_FLOW_SEQUENCE_STYLE ||
		yaml_emitter_check_empty_sequence(emitter) {
		emitter.state = yaml_EMIT_FLOW_SEQUENCE_FIRST_ITEM_STATE
	} else {
		emitter.state = yaml_EMIT_BLOCK_SEQUENCE_FIRST_ITEM_STATE
	}
	return true
}

// Expect MAPPING-START.
func yaml_emitter_emit_mapping_start(emitter *yaml_emitter_t, event *yaml_event_t) bool {
	if !yaml_emitter_process_anchor(emitter) {
		return false
	}
	if !yaml_emitter_process_tag(emitter) {
		return false
	}
	if emitter.flow_level > 0 || emitter.canonical || event.mapping_style() == yaml_FLOW_MAPPING_STYLE ||
		yaml_emitter_check_empty_mapping(emitter) {
		emitter.state = yaml_EMIT_FLOW_MAPPING_FIRST_KEY_STATE
	} else {
		emitter.state = yaml_EMIT_BLOCK_MAPPING_FIRST_KEY_STATE
	}
	return true
}

// Check if the document content is an empty scalar.
func yaml_emitter_check_empty_document(emitter *yaml_emitter_t) bool {
	return false // [Go] Huh?
}

// Check if the next events represent an empty sequence.
func yaml_emitter_check_empty_sequence(emitter *yaml_emitter_t) bool {
	if len(emitter.events)-emitter.events_head < 2 {
		return false
	}
	return emitter.events[emitter.events_head].typ == yaml_SEQUENCE_START_EVENT &&
		emitter.events[emitter.events_head+1].typ == yaml_SEQUENCE_END_EVENT
}

// Check if the next events represent an empty mapping.
func yaml_emitter_check_empty_mapping(emitter *yaml_emitter_t) bool {
	if len(emitter.events)-emitter.events_head < 2 {
		return false
	}
	return emitter.events[emitter.events_head].typ == yaml_MAPPING_START_EVENT &&
		emitter.events[emitter.events_head+1].typ == yaml_MAPPING_END_EVENT
}

// Check if the next node can be expressed as a simple key.
func yaml_emitter_check_simple_key(emitter *yaml_emitter_t) bool {
	length := 0
	switch emitter.events[emitter.events_head].typ {
	case yaml_ALIAS_EVENT:
		length += len(emitter.anchor_data.anchor)
	case yaml_SCALAR_EVENT:
		if emitter.scalar_data.multiline {
			return false
		}
		length += len(emitter.anchor_data.anchor) +
			len(emitter.tag_data.handle) +
			len(emitter.tag_data.suffix) +
			len(emitter.scalar_data.value)
	case yaml_SEQUENCE_START_EVENT:
		if !yaml_emitter_check_empty_sequence(emitter) {
			return false
		}
		length += len(emitter.anchor_data.anchor) +
			len(emitter.tag_data.handle) +
			len(emitter.tag_data.suffix)
	case yaml_MAPPING_START_EVENT:
		if !yaml_emitter_check_empty_mapping(emitter) {
			return false
		}
		length += len(emitter.anchor_data.anchor) +
			len(emitter.tag_data.handle) +
			len(emitter.tag_data.suffix)
	default:
		return false
	}
	return length <= 128
}

// Determine an acceptable scalar style.
func yaml_emitter_select_scalar_style(emitter *yaml_emitter_t, event *yaml_event_t) bool {

	no_tag := len(emitter.tag_data.handle) == 0 && len(emitter.tag_data.suffix) == 0
	if no_tag && !event.implicit && !event.quoted_implicit {
		return yaml_emitter_set_emitter_error(emitter, "neither tag nor implicit flags are specified")
	}

	style := event.scalar_style()
	if style == yaml_ANY_SCALAR_STYLE {
		style = yaml_PLAIN_SCALAR_STYLE
	}
	if emitter.canonical {
		style = yaml_DOUBLE_QUOTED_SCALAR_STYLE
	}
	if emitter.simple_key_context && emitter.scalar_data.multiline {
		style = yaml_DOUBLE_QUOTED_SCALAR_STYLE
	}

	if style == yaml_PLAIN_SCALAR_STYLE {
		if emitter.flow_level > 0 && !emitter.scalar_data.flow_plain_allowed ||
			emitter.flow_level == 0 && !emitter.scalar_data.block_plain_allowed {
			style = yaml_SINGLE_QUOTED_SCALAR_STYLE
		}
		if len(emitter.scalar_data.value) == 0 && (emitter.flow_level > 0 || emitter.simple_key_context) {
			style = yaml_SINGLE_QUOTED_SCALAR_STYLE
		}
		if no_tag && !event.implicit {
			style = yaml_SINGLE_QUOTED_SCALAR_STYLE
		}
	}
	if style == yaml_SINGLE_QUOTED_SCALAR_STYLE {
		if !emitter.scalar_data.single_quoted_allowed {
			style = yaml_DOUBLE_QUOTED_SCALAR_STYLE
		}
	}
	if style == yaml_LITERAL_SCALAR_STYLE || style == yaml_FOLDED_SCALAR_STYLE {
		if !emitter.scalar_data.block_allowed || emitter.flow_level > 0 || emitter.simple_key_context {
			style = yaml_DOUBLE_QUOTED_SCALAR_STYLE
		}
	}

	if no_tag && !event.quoted_implicit && style != yaml_PLAIN_SCALAR_STYLE {
		emitter.tag_data.handle = []byte{'!'}
	}
	emitter.scalar_data.style = style
	return true
}

// Write an anchor.
func yaml_emitter_process_anchor(emitter *yaml_emitter_t) bool {
	if emitter.anchor_data.anchor == nil {
		return true
	}
	c := []byte{'&'}
	if emitter.anchor_data.alias {
		c[0] = '*'
	}
	if !yaml_emitter_write_indicator(emitter, c, true, false, false) {
		return false
	}
	return yaml_emitter_write_anchor(emitter, emitter.anchor_data.anchor)
}

// Write a tag.
func yaml_emitter_process_tag(emitter *yaml_emitter_t) bool {
	if len(emitter.tag_data.handle) == 0 && len(emitter.tag_data.suffix) == 0 {
		return true
	}
	if len(emitter.tag_data.handle) > 0 {
		if !yaml_emitter_write_tag_handle(emitter, emitter.tag_data.handle) {
			return false
		}
		if len(emitter.tag_data.suffix) > 0 {
			if !yaml_emitter_write_tag_content(emitter, emitter.tag_data.suffix, false) {
				return false
			}
		}
	} else {
		// [Go] Allocate these slices elsewhere.
		if !yaml_emitter_write_indicator(emitter, []byte("!<"), true, false, false) {
			return false
		}
		if !yaml_emitter_write_tag_content(emitter, emitter.tag_data.suffix, false) {
			return false
		}
		if !yaml_emitter_write_indicator(emitter, []byte{'>'}, false, false, false) {
			return false
		}
	}
	return true
}

// Write a scalar.
func yaml_emitter_process_scalar(emitter *yaml_emitter_t) bool {
	switch emitter.scalar_data.style {
	case yaml_PLAIN_SCALAR_STYLE:
		return yaml_emitter_write_plain_scalar(emitter, emitter.scalar_data.value, !emitter.simple_key_context)

	case yaml_SINGLE_QUOTED_SCALAR_STYLE:
		return yaml_emitter_write_single_quoted_scalar(emitter, emitter.scalar_data.value, !emitter.simple_key_context)

	case yaml_DOUBLE_QUOTED_SCALAR_STYLE:
		return yaml_emitter_write_double_quoted_scalar(emitter, emitter.scalar_data.value, !emitter.simple_key_context)

	case yaml_LITERAL_SCALAR_STYLE:
		return yaml_emitter_write_literal_scalar(emitter, emitter.scalar_data.value)

	case yaml_FOLDED_SCALAR_STYLE:
		return yaml_emitter_write_folded_scalar(emitter, emitter.scalar_data.value)
	}
	panic("unknown scalar style")
}

// Check if a %YAML directive is valid.
func yaml_emitter_analyze_version_directive(emitter *yaml_emitter_t, version_directive *yaml_version_directive_t) bool {
	if version_directive.major != 1 || version_directive.minor != 1 {
		return yaml_emitter_set_emitter_error(emitter, "incompatible %YAML directive")
	}
	return true
}

// Check if a %TAG directive is valid.
func yaml_emitter_analyze_tag_directive(emitter *yaml_emitter_t, tag_directive *yaml_tag_directive_t) bool {
	handle := tag_directive.handle
	prefix := tag_directive.prefix
	if len(handle) == 0 {
		return yaml_emitter_set_emitter_error(emitter, "tag handle must not be empty")
	}
	if handle[0] != '!' {
		return yaml_emitter_set_emitter_error(emitter, "tag handle must start with '!'")
	}
	if handle[len(handle)-1] != '!' {
		return yaml_emitter_set_emitter_error(emitter, "tag handle must end with '!'")
	}
	for i := 1; i < len(handle)-1; i += width(handle[i]) {
		if !is_alpha(handle, i) {
			return yaml_emitter_set_emitter_error(emitter, "tag handle must contain alphanumerical characters only")
		}
	}
	if len(prefix) == 0 {
		return yaml_emitter_set_emitter_error(emitter, "tag prefix must not be empty")
	}
	return true
}

// Check if an anchor is valid.
func yaml_emitter_analyze_anchor(emitter *yaml_emitter_t, anchor []byte, alias bool) bool {
	if len(anchor) == 0 {
		problem := "anchor value must not be empty"
		if alias {
			problem = "alias value must not be empty"
		}
		return yaml_emitter_set_emitter_error(emitter, problem)
	}
	for i := 0; i < len(anchor); i += width(anchor[i]) {
		if !is_alpha(anchor, i) {
			problem := "anchor value must contain alphanumerical characters only"
			if alias {
				problem = "alias value must contain alphanumerical characters only"
			}
			return yaml_emitter_set_emitter_error(emitter, problem)
		}
	}
	emitter.anchor_data.anchor = anchor
	emitter.anchor_data.alias = alias
	return true
}

// Check if a tag is valid.
func yaml_emitter_analyze_tag(emitter *yaml_emitter_t, tag []byte) bool {
	if len(tag) == 0 {
		return yaml_emitter_set_emitter_error(emitter, "tag value must not be empty")
	}
	for i := 0; i < len(emitter.tag_directives); i++ {
		tag_directive := &emitter.tag_directives[i]
		if bytes.HasPrefix(tag, tag_directive.prefix) {
			emitter.tag_data.handle = tag_directive.handle
			emitter.tag_data.suffix = tag[len(tag_directive.prefix):]
			return true
		}
	}
	emitter.tag_data.suffix = tag
	return true
}

// Check if a scalar is valid.
func yaml_emitter_analyze_scalar(emitter *yaml_emitter_t, value []byte) bool {
	var (
		block_indicators   = false
		flow_indicators    = false
		line_breaks        = false
		special_characters = false

		leading_space  = false
		leading_break  = false
		trailing_space = false
		trailing_break = false
		break_space    = false
		space_break    = false

		preceded_by_whitespace = false
		followed_by_whitespace = false
		previous_space         = false
		previous_break         = false
	)

	emitter.scalar_data.value = value

	if len(value) == 0 {
		emitter.scalar_data.multiline = false
		emitter.scalar_data.flow_plain_allowed = false
		emitter.scalar_data.block_plain_allowed = true
		emitter.scalar_data.single_quoted_allowed = true
		emitter.scalar_data.block_allowed = false
		return true
	}

	if len(value) >= 3 && ((value[0] == '-' && value[1] == '-' && value[2] == '-') || (value[0] == '.' && value[1] == '.' && value[2] == '.')) {
		block_indicators = true
		flow_indicators = true
	}

	preceded_by_whitespace = true
	for i, w := 0, 0; i < len(value); i += w {
		w = width(value[i])
		followed_by_whitespace = i+w >= len(value) || is_blank(value, i+w)

		if i == 0 {
			switch value[i] {
			case '#', ',', '[', ']', '{', '}', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`':
				flow_indicators = true
				block_indicators = true
			case '?', ':':
				flow_indicators = true
				if followed_by_whitespace {
					block_indicators = true
				}
			case '-':
				if followed_by_whitespace {
					flow_indicators = true
					block_indicators = true
				}
			}
		} else {
			switch value[i] {
			case ',', '?', '[', ']', '{', '}':
				flow_indicators = true
			case ':':
				flow_indicators = true
				if followed_by_whitespace {
					block_indicators = true
				}
			case '#':
				if preceded_by_whitespace {
					flow_indicators = true
					block_indicators = true
				}
			}
		}

		if !is_printable(value, i) || !is_ascii(value, i) && !emitter.unicode {
			special_characters = true
		}
		if is_space(value, i) {
			if i == 0 {
				leading_space = true
			}
			if i+width(value[i]) == len(value) {
				trailing_space = true
			}
			if previous_break {
				break_space = true
			}
			previous_space = true
			previous_break = false
		} else if is_break(value, i) {
			line_breaks = true
			if i == 0 {
				leading_break = true
			}
			if i+width(value[i]) == len(value) {
				trailing_break = true
			}
			if previous_space {
				space_break = true
			}
			previous_space = false
			previous_break = true
		} else {
			previous_space = false
			previous_break = false
		}

		// [Go]: Why 'z'? Couldn't be the end of the string as that's the loop condition.
		preceded_by_whitespace = is_blankz(value, i)
	}

	emitter.scalar_data.multiline = line_breaks
	emitter.scalar_data.flow_plain_allowed = true
	emitter.scalar_data.block_plain_allowed = true
	emitter.scalar_data.single_quoted_allowed = true
	emitter.scalar_data.block_allowed = true

	if leading_space || leading_break || trailing_space || trailing_break {
		emitter.scalar_data.flow_plain_allowed = false
		emitter.scalar_data.block_plain_allowed = false
	}
	if trailing_space {
		emitter.scalar_data.block_allowed = false
	}
	if break_space {
		emitter.scalar_data.flow_plain_allowed = false
		emitter.scalar_data.block_plain_allowed = false
		emitter.scalar_data.single_quoted_allowed = false
	}
	if space_break || special_characters {
		emitter.scalar_data.flow_pla
"""




```