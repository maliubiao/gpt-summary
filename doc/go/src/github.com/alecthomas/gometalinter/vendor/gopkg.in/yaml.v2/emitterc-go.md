Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file path `go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/emitterc.go` strongly suggests this code is part of a YAML emitter or serializer. The "emitterc" part might indicate it's a core or lower-level component of the emitter.

2. **Examine Package and Imports:** The `package yaml` declaration confirms the YAML context. The `import "bytes"` hints at string/byte array manipulation, which is common in serialization.

3. **Analyze Individual Functions (Iterative Process):**  Go through each function, understand its role, and how it interacts with the `yaml_emitter_t` struct (though the struct definition isn't provided here, the usage gives clues).

    * **`flush(emitter *yaml_emitter_t)`:**  The name and logic (checking buffer position against length) clearly indicate this function handles writing the accumulated output buffer to the underlying output stream when it's full or near full.

    * **`put(emitter *yaml_emitter_t, value byte)`:** This function adds a single byte to the buffer. The call to `flush` if the buffer is almost full confirms its role in buffer management. The incrementing of `emitter.column` suggests tracking the current column for formatting.

    * **`put_break(emitter *yaml_emitter_t)`:**  This function handles inserting line breaks. The `switch` statement based on `emitter.line_break` indicates support for different line ending conventions (CR, LN, CRLF). The updating of `emitter.line` and resetting of `emitter.column` reinforces its line break handling.

    * **`write(emitter *yaml_emitter_t, s []byte, i *int)`:** This function writes a single UTF-8 character (potentially multi-byte) from a byte slice to the buffer. The `width` function call (not shown but implied) and the `switch` on width confirm it handles UTF-8 encoding. The `*i += w` updates the index in the input string.

    * **`write_all(emitter *yaml_emitter_t, s []byte)`:** A straightforward helper function that repeatedly calls `write` to write the entire string.

    * **`write_break(emitter *yaml_emitter_t, s []byte, i *int)`:** This function specifically handles writing line breaks encountered in the input string. It checks for `\n` and uses `put_break`, otherwise using `write`. The update of `emitter.column` and `emitter.line` is important here as well.

    * **`yaml_emitter_set_emitter_error(emitter *yaml_emitter_t, problem string)`:**  This function is for error handling. It sets an error flag and stores the error message within the emitter. The naming convention `yaml_emitter_...` suggests this is part of the public API for interacting with the emitter.

    * **`yaml_emitter_emit(emitter *yaml_emitter_t, event *yaml_event_t)`:** This is a central function. It appends an event to a queue and then processes the queue. The calls to `yaml_emitter_analyze_event` and `yaml_emitter_state_machine` suggest a state-machine based approach to emitting YAML. `yaml_event_delete` indicates memory management for events.

    * **`yaml_emitter_need_more_events(emitter *yaml_emitter_t)`:** This function determines if more events need to be buffered before processing. The logic based on event types (DOCUMENT_START, SEQUENCE_START, MAPPING_START) and tracking the nesting level indicates it's managing the flow of events for proper YAML structure.

    * **`yaml_emitter_append_tag_directive(emitter *yaml_emitter_t, value *yaml_tag_directive_t, allow_duplicates bool)`:**  This function handles adding tag directives (like `%TAG !foo! http://example.com/`) to the emitter's internal storage. It checks for duplicates based on the `allow_duplicates` flag.

    * **`yaml_emitter_increase_indent(emitter *yaml_emitter_t, flow, indentless bool)`:** This function manages the indentation level. The `flow` and `indentless` parameters suggest different indentation rules for block and flow styles in YAML.

    * **`yaml_emitter_state_machine(emitter *yaml_emitter_t, event *yaml_event_t)`:** This is the core of the emitter's logic. It uses a `switch` statement based on the emitter's current `state` to call specific handler functions for each state. This is a classic state machine implementation. The various `yaml_emitter_emit_...` functions are responsible for emitting the actual YAML syntax based on the current state and event.

    * **`yaml_emitter_emit_stream_start` through `yaml_emitter_emit_mapping_start`:** These functions handle the emission of specific YAML structures (stream start, document start, sequences, mappings, scalars, aliases) by writing the corresponding YAML syntax to the buffer and updating the emitter's state.

    * **`yaml_emitter_check_empty_document`, `yaml_emitter_check_empty_sequence`, `yaml_emitter_check_empty_mapping`, `yaml_emitter_check_simple_key`:** These functions are lookahead functions. They examine the upcoming events to make decisions about how to format the YAML. For example, `check_empty_sequence` helps decide if `[]` can be used.

    * **`yaml_emitter_select_scalar_style`:** This function determines the appropriate quoting style (plain, single-quoted, double-quoted, literal, folded) for a scalar value based on various factors like context, content, and user preferences.

    * **`yaml_emitter_process_anchor`, `yaml_emitter_process_tag`, `yaml_emitter_process_scalar`:** These functions handle the emission of anchors, tags, and scalar values, respectively, utilizing helper functions to write the specific syntax.

    * **`yaml_emitter_analyze_version_directive`, `yaml_emitter_analyze_tag_directive`, `yaml_emitter_analyze_anchor`, `yaml_emitter_analyze_tag`, `yaml_emitter_analyze_scalar`:** These functions perform validation and analysis of YAML constructs (version directives, tag directives, anchors, tags, scalars) before emitting them. They ensure the generated YAML is valid.

4. **Identify Key Data Structures:** While not fully defined here, the code clearly relies on:

    * `yaml_emitter_t`:  A struct holding the emitter's state (buffer, position, line/column, indentation, current state, event queue, etc.).
    * `yaml_event_t`: A struct representing a YAML event (e.g., start of document, start of sequence, scalar value).
    * `yaml_tag_directive_t`, `yaml_version_directive_t`: Structs representing YAML directives.

5. **Infer Overall Functionality:** Based on the individual function analysis, the code implements a state-machine driven YAML emitter. It takes a stream of YAML events as input and generates a YAML document as output. It handles buffering, indentation, different YAML styles (block/flow), and validation.

6. **Consider Potential Issues (Error Prone Areas):** Think about what could go wrong: buffer overflows (though the code tries to prevent this), incorrect state transitions, invalid event sequences, and handling of different YAML features like anchors and tags.

7. **Structure the Answer:** Organize the findings into logical sections: Functionality Summary, Core Go Feature (State Machine), Code Example (illustrating the state transitions conceptually), Handling of Command-Line Arguments (acknowledging its absence), Common Mistakes (focusing on providing invalid events), and Overall Function Summary (concisely restating the main purpose).
## 功能归纳：

这段Go代码是YAML库中负责将YAML事件序列转换为YAML文本输出的核心部分，主要功能可以概括为：

**1. 缓冲输出管理:**

*   **`flush(emitter *yaml_emitter_t)`:**  负责将缓冲区中的内容输出到实际的输出流（未在此代码片段中展示）。当缓冲区接近满时会被调用，以避免溢出。
*   **`put(emitter *yaml_emitter_t, value byte)`:** 向缓冲区中添加单个字符。如果缓冲区即将满，会先调用 `flush`。
*   **`put_break(emitter *yaml_emitter_t)`:** 向缓冲区中添加换行符，并根据配置的换行符类型 (`yaml_CR_BREAK`, `yaml_LN_BREAK`, `yaml_CRLN_BREAK`) 写入不同的字符。同时会更新行号和列号。
*   **`write(emitter *yaml_emitter_t, s []byte, i *int)`:** 从给定的字节切片 `s` 中复制一个 UTF-8 字符到缓冲区。会根据字符的宽度更新索引 `i`。
*   **`write_all(emitter *yaml_emitter_t, s []byte)`:** 将整个字节切片 `s` 写入缓冲区，通过循环调用 `write` 实现。
*   **`write_break(emitter *yaml_emitter_t, s []byte, i *int)`:**  处理输入字符串中的换行符。如果遇到 `\n`，则调用 `put_break`，否则调用 `write` 写入字符并更新行列号。

**2. 错误处理:**

*   **`yaml_emitter_set_emitter_error(emitter *yaml_emitter_t, problem string)`:**  设置 emitter 的错误状态，记录错误类型为 `yaml_EMITTER_ERROR` 并保存错误信息 `problem`。

**3. 事件处理与状态管理:**

*   **`yaml_emitter_emit(emitter *yaml_emitter_t, event *yaml_event_t)`:**  接收一个 YAML 事件，将其添加到事件队列中。然后循环处理事件队列，调用 `yaml_emitter_analyze_event` (未在此代码片段中) 分析事件，并根据当前状态调用 `yaml_emitter_state_machine` 来执行相应的输出操作。
*   **`yaml_emitter_need_more_events(emitter *yaml_emitter_t)`:**  判断是否需要从上层接收更多的 YAML 事件才能继续处理。这与 YAML 的结构有关，例如在处理 `SEQUENCE-START` 或 `MAPPING-START` 事件时，可能需要预先读取更多的事件信息。
*   **`yaml_emitter_state_machine(emitter *yaml_emitter_t, event *yaml_event_t)`:**  这是状态机的主体部分。根据 emitter 的当前状态 (`emitter.state`) 和接收到的事件类型 (`event.typ`)，分发到不同的状态处理函数（例如 `yaml_emitter_emit_stream_start`, `yaml_emitter_emit_document_start` 等，这些函数在后续代码片段中）。
*   一系列以 `yaml_emitter_emit_` 开头的函数 (例如 `yaml_emitter_emit_stream_start`, `yaml_emitter_emit_document_start` 等):  这些函数是状态机不同状态下的具体处理逻辑，负责根据当前事件生成相应的 YAML 文本，并更新 emitter 的状态。

**4. 指令处理:**

*   **`yaml_emitter_append_tag_directive(emitter *yaml_emitter_t, value *yaml_tag_directive_t, allow_duplicates bool)`:**  用于添加和管理 YAML 的 `%TAG` 指令。它会检查是否允许重复的指令。

**5. 缩进管理:**

*   **`yaml_emitter_increase_indent(emitter *yaml_emitter_t, flow, indentless bool)`:**  用于增加缩进级别。`flow` 参数指示是否处于流式风格 (flow style)，`indentless` 参数指示是否无缩进。

**总结来说，这段代码的核心功能是构建 YAML 输出的底层机制，负责缓冲输出、处理 YAML 事件、管理 emitter 的状态，并为生成最终的 YAML 文本做准备。它通过状态机模式驱动整个输出过程。**

由于这是第 1 部分，主要涉及缓冲管理、基础的事件处理框架和状态机的初步搭建。具体的 YAML 语法生成逻辑，例如如何输出标量、序列、映射等，应该在后续的部分中实现。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/emitterc.go的go语言实现的一部分， 请列举一下它的功能, 　
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
			"expected SCALAR, SEQUENCE-START, MAPPING-START, or ALIAS")
	}
	return false
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

// Write an achor.
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

		preceeded_by_whitespace = false
		followed_by_whitespace  = false
		previous_space          = false
		previous_break          = false
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

	preceeded_by_whitespace = true
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
				if preceeded_by_whitespace {
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
		preceeded_by_whitespace = is_blankz(value, i)
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
		emitter.scalar_data.flow_plain_allowed = false
		em
"""




```