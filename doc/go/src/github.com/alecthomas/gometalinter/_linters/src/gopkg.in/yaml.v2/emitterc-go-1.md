Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understanding the Goal:** The request asks for a summary of the functionality of the given Go code, which is a part of a YAML emitter. The request also specifies it's the *second part* of a larger code snippet. This means I shouldn't repeat information from the first part and focus on the new functions presented here.

2. **Initial Scan and Identification of Key Functions:**  I'll quickly scan the code to identify the defined functions. The key function names stand out: `yaml_emitter_analyze_format`, `yaml_emitter_analyze_event`, `yaml_emitter_write_bom`, `yaml_emitter_write_indent`, and various `yaml_emitter_write_*` functions related to writing different YAML elements (indicators, anchors, tags, and scalar types).

3. **Categorizing Functions by Purpose:**  Now, I'll group the functions based on their apparent purpose:

    * **Analysis/Validation:** `yaml_emitter_analyze_format`, `yaml_emitter_analyze_event`. These functions seem to be involved in checking the validity of the YAML data being processed. The names suggest they analyze the format and specific events.
    * **Writing/Outputting:** The `yaml_emitter_write_*` functions clearly deal with writing different parts of the YAML output. I'll further categorize these based on what they write (BOM, indentation, indicators, anchors, tags, and different types of scalars).
    * **Helper Functions (Implicit):** While not explicitly asked for in this part,  I noticed calls to functions like `flush`, `put`, `put_break`, `write_all`, `write`, `write_break`, `is_space`, `is_break`, `width`, `is_alpha`, `is_printable`, `is_ascii`, `is_bom`, `is_blank`, `is_blankz`. These are likely lower-level helper functions for buffer management and character checking. Since they are called by the main functions, their existence indirectly contributes to the overall functionality. I'll make a mental note of their purpose.

4. **Detailed Analysis of Each Function (Focus on Logic and Purpose):**  I'll go through each function and analyze its internal logic.

    * **`yaml_emitter_analyze_format`:** This function manipulates the `emitter.scalar_data` fields based on boolean inputs related to character restrictions (`in_allowed`, `line_breaks`, `flow_indicators`, `block_indicators`). It seems to be setting constraints on how scalars can be formatted.
    * **`yaml_emitter_analyze_event`:** This function switches on the `event.typ` (e.g., `yaml_ALIAS_EVENT`, `yaml_SCALAR_EVENT`) and calls other `yaml_emitter_analyze_*` functions (like `yaml_emitter_analyze_anchor`, `yaml_emitter_analyze_tag`, `yaml_emitter_analyze_scalar`). It's responsible for validating different types of YAML events.
    * **`yaml_emitter_write_bom`:**  This function writes the Byte Order Mark (BOM) to the output buffer.
    * **`yaml_emitter_write_indent`:**  This function handles indentation by adding spaces to the output buffer.
    * **`yaml_emitter_write_indicator`:** Writes a specific indicator (like '-', ':', '[') along with optional whitespace.
    * **`yaml_emitter_write_anchor`:** Writes an anchor.
    * **`yaml_emitter_write_tag_handle` and `yaml_emitter_write_tag_content`:** Write the tag handle and content, handling URL encoding for special characters in the content.
    * **`yaml_emitter_write_plain_scalar`, `yaml_emitter_write_single_quoted_scalar`, `yaml_emitter_write_double_quoted_scalar`, `yaml_emitter_write_literal_scalar`, `yaml_emitter_write_folded_scalar`:**  These are the core functions for writing different types of scalar values, handling whitespace, line breaks, quoting, and escaping as needed for each style. I need to understand the nuances of each style (plain, single-quoted, double-quoted, literal, folded).
    * **`yaml_emitter_write_block_scalar_hints`:** This function writes hints for block scalars regarding indentation and chomping behavior.

5. **Synthesizing the Summary:** Now, I'll put together the summary in Chinese, focusing on the core functionalities revealed by the analyzed functions.

    * Start by mentioning that this is the second part and aims to complete the functionality of the YAML emitter.
    * Group the functions logically (analysis/validation, writing).
    * Briefly describe the purpose of each group and some of the key functions within them.
    * Highlight the different scalar writing functions and their respective YAML scalar styles.
    * Mention the functions related to writing other YAML constructs like anchors and tags.
    * Emphasize that these functions work together to generate the final YAML output.

6. **Review and Refine:**  I'll read through the summary to ensure it's accurate, concise, and easy to understand. I'll make sure the Chinese is grammatically correct and flows well. I'll also double-check that I've addressed all aspects of the request (functionality, code illustration if possible). Since no specific input/output or command-line arguments are obvious in *this part* of the code, I'll omit those sections in the summary for this specific part. I also won't invent error-prone user scenarios if they aren't apparent from the code itself.

This systematic approach ensures that I cover all the important aspects of the code and generate a comprehensive and accurate summary. The key is to break down the problem into smaller, manageable steps and then synthesize the findings into a coherent explanation.
这是第二部分代码，延续了第一部分的功能，主要集中在 YAML 数据的分析和写入操作上。 让我们归纳一下它的功能：

**总览：**

这部分代码主要负责 YAML 数据的最终生成和写入，以及在写入之前对数据进行必要的分析和格式化。它包含了多个函数，分别处理不同 YAML 元素的写入，例如 BOM、缩进、指示符（如 `-`, `:`, `[`, `]` 等）、锚点、标签以及不同类型的标量（字符串）。

**具体功能归纳：**

1. **数据格式分析与校验 (`yaml_emitter_analyze_format`, `yaml_emitter_analyze_event`)：**
   - `yaml_emitter_analyze_format`:  这个函数用于分析和设置标量（字符串）的格式限制。它根据布尔标志 `in_allowed` (是否允许特定字符), `line_breaks` (是否允许换行符), `flow_indicators` (是否允许流式指示符), `block_indicators` (是否允许块式指示符) 来设置 `emitter.scalar_data` 中的各种允许标志。这些标志会影响后续标量值的写入方式。
   - `yaml_emitter_analyze_event`: 这个函数用于分析不同类型的 YAML 事件（例如别名、标量、序列开始、映射开始）。它会根据事件类型调用相应的分析函数，例如 `yaml_emitter_analyze_anchor` 和 `yaml_emitter_analyze_tag`（这些函数在第一部分中可能定义）。对于标量事件，它还会调用 `yaml_emitter_analyze_scalar` 来分析标量值。这个函数的主要目的是在实际写入之前，检查事件数据是否符合 YAML 规范。

2. **BOM 写入 (`yaml_emitter_write_bom`)：**
   - 这个函数负责写入 UTF-8 字节顺序标记 (BOM)。BOM 不是 YAML 强制要求的，但有时会被用来指示文件的编码。

3. **缩进写入 (`yaml_emitter_write_indent`)：**
   - 这个函数负责根据当前的缩进级别在输出缓冲区中写入适当数量的空格。它会检查当前列的位置和是否需要新的缩进。

4. **指示符写入 (`yaml_emitter_write_indicator`)：**
   - 这个函数用于写入 YAML 的各种指示符，例如 `-`, `:`, `[`, `]`, `{`, `}` 等。它可以选择在指示符之前添加空格。

5. **锚点写入 (`yaml_emitter_write_anchor`)：**
   - 这个函数负责写入锚点，例如 `&my_anchor`。

6. **标签写入 (`yaml_emitter_write_tag_handle`, `yaml_emitter_write_tag_content`)：**
   - `yaml_emitter_write_tag_handle`: 写入标签的前缀部分，例如 `!` 或 `!!`.
   - `yaml_emitter_write_tag_content`: 写入标签的具体内容，并对特殊字符进行 URL 编码。

7. **标量写入 (多种函数处理不同风格的标量)：**
   - `yaml_emitter_write_plain_scalar`: 写入普通标量（不带引号）。它会处理空格和换行，并根据 `emitter.best_width` 进行折行。
   - `yaml_emitter_write_single_quoted_scalar`: 写入单引号标量。它会转义单引号 `'` 为 `''`。
   - `yaml_emitter_write_double_quoted_scalar`: 写入双引号标量。它会对多种特殊字符进行转义，例如 `\n`, `\t`, `\\`, `\"` 以及 Unicode 字符。
   - `yaml_emitter_write_block_scalar_hints`:  为块标量（literal 和 folded）写入提示符，例如指示缩进和尾部换行的处理方式。
   - `yaml_emitter_write_literal_scalar`: 写入 literal 块标量（使用 `|` 指示）。它会保留换行符。
   - `yaml_emitter_write_folded_scalar`: 写入 folded 块标量（使用 `>` 指示）。它会将单行换行符转换为空格，并将多行换行符保留为换行。

**可以推理出它是什么 go 语言功能的实现：**

这部分代码是 YAML 编码器（Emitter）的核心实现。它负责将 YAML 的逻辑结构（通过事件表示）转换为最终的 YAML 文本格式。  这涉及到字符串处理、缓冲区的管理以及对 YAML 规范的理解和实现。

**代码举例说明（针对标量写入）：**

假设我们有一个 `yaml_emitter_t` 结构 `emitter` 已经初始化，并且我们想要写入一个标量值 "Hello\nWorld"。

```go
package main

import (
	"fmt"
)

// 假设 yaml_emitter_t 和相关的辅助函数已经定义（来自完整代码）

func main() {
	emitter := &yaml_emitter_t{
		// ... 初始化 emitter 的其他字段
		indent:     2,
		best_width: 80,
	}
	value := []byte("Hello\nWorld")

	// 写入普通标量
	emitter.scalar_data.flow_plain_allowed = true
	emitter.scalar_data.block_plain_allowed = true
	yaml_emitter_write_plain_scalar(emitter, value, true)
	fmt.Println(string(emitter.buffer[:emitter.buffer_pos])) // 输出:  Hello World (可能会被折行)

	// 重置 buffer
	emitter.buffer_pos = 0
	emitter.column = 0
	emitter.whitespace = true

	// 写入单引号标量
	yaml_emitter_write_single_quoted_scalar(emitter, value, true)
	fmt.Println(string(emitter.buffer[:emitter.buffer_pos])) // 输出: 'Hello\nWorld'

	// 重置 buffer
	emitter.buffer_pos = 0
	emitter.column = 0
	emitter.whitespace = true

	// 写入双引号标量
	yaml_emitter_write_double_quoted_scalar(emitter, value, true)
	fmt.Println(string(emitter.buffer[:emitter.buffer_pos])) // 输出: "Hello\nWorld"

	// 重置 buffer
	emitter.buffer_pos = 0
	emitter.column = 0
	emitter.whitespace = true

	// 写入 literal 块标量
	yaml_emitter_write_literal_scalar(emitter, value)
	fmt.Println(string(emitter.buffer[:emitter.buffer_pos]))
	// 输出:
	//   |
	//   Hello
	//   World

	// 重置 buffer
	emitter.buffer_pos = 0
	emitter.column = 0
	emitter.whitespace = true

	// 写入 folded 块标量
	yaml_emitter_write_folded_scalar(emitter, value)
	fmt.Println(string(emitter.buffer[:emitter.buffer_pos]))
	// 输出:
	//   >
	//   Hello
	//   World
}
```

**假设的输入与输出:**

上面的代码示例中，输入是字符串 "Hello\nWorld" 和 `emitter` 的状态。输出是根据不同的标量写入函数生成的不同 YAML 字符串表示。

**命令行参数的具体处理:**

这部分代码本身不直接处理命令行参数。命令行参数的处理通常发生在调用此代码的上层逻辑中，例如解析用户提供的 YAML 数据或指定输出选项。

**使用者易犯错的点:**

使用者在使用这个库时，可能不需要直接调用这些底层的 `yaml_emitter_write_*` 函数。库的更高层 API 应该会处理这些细节。 但是，理解这些底层机制有助于理解 YAML 生成的原理。

如果直接使用这些函数，可能会犯以下错误：

* **不正确的 `emitter` 状态初始化:** `emitter` 的各个字段（例如 `indent`, `column`, `whitespace` 等）需要正确维护，否则可能导致格式错误。
* **标量类型选择错误:** 根据数据的特点选择合适的标量类型（plain, single-quoted, double-quoted, literal, folded）非常重要，错误的类型可能导致 YAML 解析器无法正确理解。例如，包含特殊字符的字符串需要使用引号括起来。
* **混合使用底层和高层 API:**  如果库提供了更高层的 API 来生成 YAML，则应该优先使用这些 API，而不是直接操作底层的 emitter 函数，以避免手动管理状态的复杂性。

**总结:**

这部分代码是 `gopkg.in/yaml.v2` 库中 YAML 编码器的核心组件，负责将分析过的 YAML 数据转换为最终的文本输出。它包含了处理各种 YAML 结构（包括标量、指示符、锚点和标签）的函数，并提供了多种标量写入风格以满足不同的 YAML 格式需求。它依赖于第一部分提供的基础数据结构和辅助函数来实现其功能。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/emitterc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
in_allowed = false
		emitter.scalar_data.block_plain_allowed = false
		emitter.scalar_data.single_quoted_allowed = false
		emitter.scalar_data.block_allowed = false
	}
	if line_breaks {
		emitter.scalar_data.flow_plain_allowed = false
		emitter.scalar_data.block_plain_allowed = false
	}
	if flow_indicators {
		emitter.scalar_data.flow_plain_allowed = false
	}
	if block_indicators {
		emitter.scalar_data.block_plain_allowed = false
	}
	return true
}

// Check if the event data is valid.
func yaml_emitter_analyze_event(emitter *yaml_emitter_t, event *yaml_event_t) bool {

	emitter.anchor_data.anchor = nil
	emitter.tag_data.handle = nil
	emitter.tag_data.suffix = nil
	emitter.scalar_data.value = nil

	switch event.typ {
	case yaml_ALIAS_EVENT:
		if !yaml_emitter_analyze_anchor(emitter, event.anchor, true) {
			return false
		}

	case yaml_SCALAR_EVENT:
		if len(event.anchor) > 0 {
			if !yaml_emitter_analyze_anchor(emitter, event.anchor, false) {
				return false
			}
		}
		if len(event.tag) > 0 && (emitter.canonical || (!event.implicit && !event.quoted_implicit)) {
			if !yaml_emitter_analyze_tag(emitter, event.tag) {
				return false
			}
		}
		if !yaml_emitter_analyze_scalar(emitter, event.value) {
			return false
		}

	case yaml_SEQUENCE_START_EVENT:
		if len(event.anchor) > 0 {
			if !yaml_emitter_analyze_anchor(emitter, event.anchor, false) {
				return false
			}
		}
		if len(event.tag) > 0 && (emitter.canonical || !event.implicit) {
			if !yaml_emitter_analyze_tag(emitter, event.tag) {
				return false
			}
		}

	case yaml_MAPPING_START_EVENT:
		if len(event.anchor) > 0 {
			if !yaml_emitter_analyze_anchor(emitter, event.anchor, false) {
				return false
			}
		}
		if len(event.tag) > 0 && (emitter.canonical || !event.implicit) {
			if !yaml_emitter_analyze_tag(emitter, event.tag) {
				return false
			}
		}
	}
	return true
}

// Write the BOM character.
func yaml_emitter_write_bom(emitter *yaml_emitter_t) bool {
	if !flush(emitter) {
		return false
	}
	pos := emitter.buffer_pos
	emitter.buffer[pos+0] = '\xEF'
	emitter.buffer[pos+1] = '\xBB'
	emitter.buffer[pos+2] = '\xBF'
	emitter.buffer_pos += 3
	return true
}

func yaml_emitter_write_indent(emitter *yaml_emitter_t) bool {
	indent := emitter.indent
	if indent < 0 {
		indent = 0
	}
	if !emitter.indention || emitter.column > indent || (emitter.column == indent && !emitter.whitespace) {
		if !put_break(emitter) {
			return false
		}
	}
	for emitter.column < indent {
		if !put(emitter, ' ') {
			return false
		}
	}
	emitter.whitespace = true
	emitter.indention = true
	return true
}

func yaml_emitter_write_indicator(emitter *yaml_emitter_t, indicator []byte, need_whitespace, is_whitespace, is_indention bool) bool {
	if need_whitespace && !emitter.whitespace {
		if !put(emitter, ' ') {
			return false
		}
	}
	if !write_all(emitter, indicator) {
		return false
	}
	emitter.whitespace = is_whitespace
	emitter.indention = (emitter.indention && is_indention)
	emitter.open_ended = false
	return true
}

func yaml_emitter_write_anchor(emitter *yaml_emitter_t, value []byte) bool {
	if !write_all(emitter, value) {
		return false
	}
	emitter.whitespace = false
	emitter.indention = false
	return true
}

func yaml_emitter_write_tag_handle(emitter *yaml_emitter_t, value []byte) bool {
	if !emitter.whitespace {
		if !put(emitter, ' ') {
			return false
		}
	}
	if !write_all(emitter, value) {
		return false
	}
	emitter.whitespace = false
	emitter.indention = false
	return true
}

func yaml_emitter_write_tag_content(emitter *yaml_emitter_t, value []byte, need_whitespace bool) bool {
	if need_whitespace && !emitter.whitespace {
		if !put(emitter, ' ') {
			return false
		}
	}
	for i := 0; i < len(value); {
		var must_write bool
		switch value[i] {
		case ';', '/', '?', ':', '@', '&', '=', '+', '$', ',', '_', '.', '~', '*', '\'', '(', ')', '[', ']':
			must_write = true
		default:
			must_write = is_alpha(value, i)
		}
		if must_write {
			if !write(emitter, value, &i) {
				return false
			}
		} else {
			w := width(value[i])
			for k := 0; k < w; k++ {
				octet := value[i]
				i++
				if !put(emitter, '%') {
					return false
				}

				c := octet >> 4
				if c < 10 {
					c += '0'
				} else {
					c += 'A' - 10
				}
				if !put(emitter, c) {
					return false
				}

				c = octet & 0x0f
				if c < 10 {
					c += '0'
				} else {
					c += 'A' - 10
				}
				if !put(emitter, c) {
					return false
				}
			}
		}
	}
	emitter.whitespace = false
	emitter.indention = false
	return true
}

func yaml_emitter_write_plain_scalar(emitter *yaml_emitter_t, value []byte, allow_breaks bool) bool {
	if !emitter.whitespace {
		if !put(emitter, ' ') {
			return false
		}
	}

	spaces := false
	breaks := false
	for i := 0; i < len(value); {
		if is_space(value, i) {
			if allow_breaks && !spaces && emitter.column > emitter.best_width && !is_space(value, i+1) {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
				i += width(value[i])
			} else {
				if !write(emitter, value, &i) {
					return false
				}
			}
			spaces = true
		} else if is_break(value, i) {
			if !breaks && value[i] == '\n' {
				if !put_break(emitter) {
					return false
				}
			}
			if !write_break(emitter, value, &i) {
				return false
			}
			emitter.indention = true
			breaks = true
		} else {
			if breaks {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
			}
			if !write(emitter, value, &i) {
				return false
			}
			emitter.indention = false
			spaces = false
			breaks = false
		}
	}

	emitter.whitespace = false
	emitter.indention = false
	if emitter.root_context {
		emitter.open_ended = true
	}

	return true
}

func yaml_emitter_write_single_quoted_scalar(emitter *yaml_emitter_t, value []byte, allow_breaks bool) bool {

	if !yaml_emitter_write_indicator(emitter, []byte{'\''}, true, false, false) {
		return false
	}

	spaces := false
	breaks := false
	for i := 0; i < len(value); {
		if is_space(value, i) {
			if allow_breaks && !spaces && emitter.column > emitter.best_width && i > 0 && i < len(value)-1 && !is_space(value, i+1) {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
				i += width(value[i])
			} else {
				if !write(emitter, value, &i) {
					return false
				}
			}
			spaces = true
		} else if is_break(value, i) {
			if !breaks && value[i] == '\n' {
				if !put_break(emitter) {
					return false
				}
			}
			if !write_break(emitter, value, &i) {
				return false
			}
			emitter.indention = true
			breaks = true
		} else {
			if breaks {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
			}
			if value[i] == '\'' {
				if !put(emitter, '\'') {
					return false
				}
			}
			if !write(emitter, value, &i) {
				return false
			}
			emitter.indention = false
			spaces = false
			breaks = false
		}
	}
	if !yaml_emitter_write_indicator(emitter, []byte{'\''}, false, false, false) {
		return false
	}
	emitter.whitespace = false
	emitter.indention = false
	return true
}

func yaml_emitter_write_double_quoted_scalar(emitter *yaml_emitter_t, value []byte, allow_breaks bool) bool {
	spaces := false
	if !yaml_emitter_write_indicator(emitter, []byte{'"'}, true, false, false) {
		return false
	}

	for i := 0; i < len(value); {
		if !is_printable(value, i) || (!emitter.unicode && !is_ascii(value, i)) ||
			is_bom(value, i) || is_break(value, i) ||
			value[i] == '"' || value[i] == '\\' {

			octet := value[i]

			var w int
			var v rune
			switch {
			case octet&0x80 == 0x00:
				w, v = 1, rune(octet&0x7F)
			case octet&0xE0 == 0xC0:
				w, v = 2, rune(octet&0x1F)
			case octet&0xF0 == 0xE0:
				w, v = 3, rune(octet&0x0F)
			case octet&0xF8 == 0xF0:
				w, v = 4, rune(octet&0x07)
			}
			for k := 1; k < w; k++ {
				octet = value[i+k]
				v = (v << 6) + (rune(octet) & 0x3F)
			}
			i += w

			if !put(emitter, '\\') {
				return false
			}

			var ok bool
			switch v {
			case 0x00:
				ok = put(emitter, '0')
			case 0x07:
				ok = put(emitter, 'a')
			case 0x08:
				ok = put(emitter, 'b')
			case 0x09:
				ok = put(emitter, 't')
			case 0x0A:
				ok = put(emitter, 'n')
			case 0x0b:
				ok = put(emitter, 'v')
			case 0x0c:
				ok = put(emitter, 'f')
			case 0x0d:
				ok = put(emitter, 'r')
			case 0x1b:
				ok = put(emitter, 'e')
			case 0x22:
				ok = put(emitter, '"')
			case 0x5c:
				ok = put(emitter, '\\')
			case 0x85:
				ok = put(emitter, 'N')
			case 0xA0:
				ok = put(emitter, '_')
			case 0x2028:
				ok = put(emitter, 'L')
			case 0x2029:
				ok = put(emitter, 'P')
			default:
				if v <= 0xFF {
					ok = put(emitter, 'x')
					w = 2
				} else if v <= 0xFFFF {
					ok = put(emitter, 'u')
					w = 4
				} else {
					ok = put(emitter, 'U')
					w = 8
				}
				for k := (w - 1) * 4; ok && k >= 0; k -= 4 {
					digit := byte((v >> uint(k)) & 0x0F)
					if digit < 10 {
						ok = put(emitter, digit+'0')
					} else {
						ok = put(emitter, digit+'A'-10)
					}
				}
			}
			if !ok {
				return false
			}
			spaces = false
		} else if is_space(value, i) {
			if allow_breaks && !spaces && emitter.column > emitter.best_width && i > 0 && i < len(value)-1 {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
				if is_space(value, i+1) {
					if !put(emitter, '\\') {
						return false
					}
				}
				i += width(value[i])
			} else if !write(emitter, value, &i) {
				return false
			}
			spaces = true
		} else {
			if !write(emitter, value, &i) {
				return false
			}
			spaces = false
		}
	}
	if !yaml_emitter_write_indicator(emitter, []byte{'"'}, false, false, false) {
		return false
	}
	emitter.whitespace = false
	emitter.indention = false
	return true
}

func yaml_emitter_write_block_scalar_hints(emitter *yaml_emitter_t, value []byte) bool {
	if is_space(value, 0) || is_break(value, 0) {
		indent_hint := []byte{'0' + byte(emitter.best_indent)}
		if !yaml_emitter_write_indicator(emitter, indent_hint, false, false, false) {
			return false
		}
	}

	emitter.open_ended = false

	var chomp_hint [1]byte
	if len(value) == 0 {
		chomp_hint[0] = '-'
	} else {
		i := len(value) - 1
		for value[i]&0xC0 == 0x80 {
			i--
		}
		if !is_break(value, i) {
			chomp_hint[0] = '-'
		} else if i == 0 {
			chomp_hint[0] = '+'
			emitter.open_ended = true
		} else {
			i--
			for value[i]&0xC0 == 0x80 {
				i--
			}
			if is_break(value, i) {
				chomp_hint[0] = '+'
				emitter.open_ended = true
			}
		}
	}
	if chomp_hint[0] != 0 {
		if !yaml_emitter_write_indicator(emitter, chomp_hint[:], false, false, false) {
			return false
		}
	}
	return true
}

func yaml_emitter_write_literal_scalar(emitter *yaml_emitter_t, value []byte) bool {
	if !yaml_emitter_write_indicator(emitter, []byte{'|'}, true, false, false) {
		return false
	}
	if !yaml_emitter_write_block_scalar_hints(emitter, value) {
		return false
	}
	if !put_break(emitter) {
		return false
	}
	emitter.indention = true
	emitter.whitespace = true
	breaks := true
	for i := 0; i < len(value); {
		if is_break(value, i) {
			if !write_break(emitter, value, &i) {
				return false
			}
			emitter.indention = true
			breaks = true
		} else {
			if breaks {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
			}
			if !write(emitter, value, &i) {
				return false
			}
			emitter.indention = false
			breaks = false
		}
	}

	return true
}

func yaml_emitter_write_folded_scalar(emitter *yaml_emitter_t, value []byte) bool {
	if !yaml_emitter_write_indicator(emitter, []byte{'>'}, true, false, false) {
		return false
	}
	if !yaml_emitter_write_block_scalar_hints(emitter, value) {
		return false
	}

	if !put_break(emitter) {
		return false
	}
	emitter.indention = true
	emitter.whitespace = true

	breaks := true
	leading_spaces := true
	for i := 0; i < len(value); {
		if is_break(value, i) {
			if !breaks && !leading_spaces && value[i] == '\n' {
				k := 0
				for is_break(value, k) {
					k += width(value[k])
				}
				if !is_blankz(value, k) {
					if !put_break(emitter) {
						return false
					}
				}
			}
			if !write_break(emitter, value, &i) {
				return false
			}
			emitter.indention = true
			breaks = true
		} else {
			if breaks {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
				leading_spaces = is_blank(value, i)
			}
			if !breaks && is_space(value, i) && !is_space(value, i+1) && emitter.column > emitter.best_width {
				if !yaml_emitter_write_indent(emitter) {
					return false
				}
				i += width(value[i])
			} else {
				if !write(emitter, value, &i) {
					return false
				}
			}
			emitter.indention = false
			breaks = false
		}
	}
	return true
}

"""




```