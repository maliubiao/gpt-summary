Response:
Let's break down the thought process for analyzing this Go code snippet and generating the response.

**1. Understanding the Request:**

The request asks for a functional summary of the provided Go code, which is stated to be part of a YAML emitter. Key aspects to identify are: what it does, how it relates to broader YAML functionality, and any potential pitfalls for users. Since this is the second part of a larger piece, the request specifically asks for a summarization of *this* part.

**2. Initial Code Scan and Keyword Identification:**

I quickly scanned the code for recurring keywords and function names. I noticed:

* `yaml_emitter_t`: This strongly suggests a struct representing the YAML emitter's internal state.
* `yaml_event_t`: Likely a struct representing YAML events (like scalar, sequence start, etc.).
* Functions starting with `yaml_emitter_`: These are obviously the core functions of the emitter.
* Functions like `yaml_emitter_analyze_event`, `yaml_emitter_write_bom`, `yaml_emitter_write_indent`, `yaml_emitter_write_indicator`, `yaml_emitter_write_scalar` (with variations like `plain`, `single_quoted`, `double_quoted`, `block`). These clearly indicate different stages of processing and different YAML output formats.
* Boolean return values in many functions:  Suggests error handling or success/failure signaling.
* Logic related to indentation, whitespace, and line breaks:  Essential for formatting YAML.
* Checks for `emitter.canonical`: Suggests a "canonical" output mode.
* References to "anchors" and "tags":  Key YAML features.
* Different scalar styles (plain, single-quoted, double-quoted, literal, folded):  Crucial for YAML representation.

**3. Grouping Functions by Functionality:**

Based on the keywords and function names, I started mentally grouping functions:

* **Event Analysis:** `yaml_emitter_analyze_event`, `yaml_emitter_analyze_anchor`, `yaml_emitter_analyze_tag`, `yaml_emitter_analyze_scalar`. These seem to be validating and preparing event data for emission.
* **Writing Basic Elements:** `yaml_emitter_write_bom`, `yaml_emitter_write_indent`, `yaml_emitter_write_indicator`, `yaml_emitter_write_anchor`, `yaml_emitter_write_tag_handle`, `yaml_emitter_write_tag_content`. These are low-level writing functions.
* **Writing Scalars:** `yaml_emitter_write_plain_scalar`, `yaml_emitter_write_single_quoted_scalar`, `yaml_emitter_write_double_quoted_scalar`, `yaml_emitter_write_literal_scalar`, `yaml_emitter_write_folded_scalar`, `yaml_emitter_write_block_scalar_hints`. These handle the different ways scalars are represented in YAML.

**4. Inferring High-Level Functionality:**

By grouping the functions, a higher-level picture emerged:

* This code segment is responsible for taking parsed YAML events and converting them into a formatted YAML string.
* It handles different aspects of YAML syntax, including anchors, tags, and various scalar representations.
* It manages indentation and whitespace to ensure valid YAML structure.
* It appears to perform some validation or analysis of the event data before writing.

**5. Considering the "What Go Feature is This Implementing?" Question:**

Given the function names and the overall goal of generating YAML, the most obvious answer is **YAML serialization (or marshalling)**. This is the process of converting Go data structures into a YAML string representation.

**6. Generating Go Code Examples:**

To illustrate YAML serialization, I needed a simple Go data structure and the `yaml.v2` library (as indicated by the file path). The example should demonstrate how the emitter would be used implicitly. I chose a simple struct with fields of different types (string, int) to show how they would be represented in YAML. I included the expected YAML output.

**7. Identifying Potential User Errors:**

Based on the code, I considered potential issues users might encounter:

* **Incorrect Event Construction:**  The emitter relies on receiving valid `yaml_event_t` structures. Users creating these events incorrectly could lead to errors or unexpected output. I focused on the `yaml.v2` package as the likely source of these events, and how incorrect usage of its API could lead to issues.
* **Mixing Emitter Settings:** The code has various settings (e.g., `canonical`, allowed scalar styles). Users might misunderstand how these settings affect the output and produce YAML that doesn't meet their expectations.

**8. Addressing Command-Line Arguments:**

I scanned the code for explicit handling of command-line arguments. Since there wasn't any, I explicitly stated that this part of the code doesn't directly handle them. However, I acknowledged that the *wider* `gometalinter` tool likely uses command-line arguments, but this specific file is focused on the emission logic.

**9. Summarizing the Functionality (Part 2):**

The request specifically asked for a summary of *this* part. I reviewed the functions and their roles to synthesize a concise summary focusing on:

* Core responsibility: Converting events to YAML text.
* Key features: Handling different YAML elements (scalars, anchors, tags), scalar styles, indentation, and basic validation.
* Its position in the broader process:  Being the output generation stage after parsing and analysis.

**10. Review and Refinement:**

I reviewed my generated response to ensure clarity, accuracy, and completeness. I made sure the examples were correct and easy to understand. I double-checked that I had addressed all parts of the request. For example, ensuring I emphasized this being *part* of a larger system and focusing on *this specific code segment's* functionality.
这是 `go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/emitterc.go` 文件中关于 YAML emitter (发射器) 的一部分代码，它主要负责将 YAML 的结构化事件转换为最终的 YAML 文本输出。

**归纳一下它的功能 (针对提供的代码片段):**

这段代码主要负责以下几个核心功能：

1. **分析事件属性并设置输出选项:**
   - `yaml_emitter_set_output_format`:  根据用户设置的输出格式（例如是否允许块格式、单引号等）来调整 emitter 内部的 `scalar_data` 字段，限制后续标量值的输出方式。
   - `yaml_emitter_analyze_event`:  检查传入的 YAML 事件 (`yaml_event_t`) 的属性，例如锚点 (`anchor`)、标签 (`tag`) 和标量值 (`value`)，并根据事件类型（如别名、标量、序列开始、映射开始）进行相应的分析和预处理。这个函数会调用其他 `yaml_emitter_analyze_*` 函数来进一步分析锚点、标签和标量。

2. **编写 YAML 输出的基础元素:**
   - `yaml_emitter_write_bom`:  如果需要，写入 BOM (Byte Order Mark) 字符。
   - `yaml_emitter_write_indent`:  根据当前的缩进级别写入缩进空格。
   - `yaml_emitter_write_indicator`:  写入 YAML 的指示符，如 `-` (序列项), `:` (映射键值分隔符) 等，并根据需要添加前导空格。
   - `yaml_emitter_write_anchor`:  写入锚点名称。
   - `yaml_emitter_write_tag_handle` 和 `yaml_emitter_write_tag_content`:  写入标签。

3. **编写不同类型的 YAML 标量:**
   - `yaml_emitter_write_plain_scalar`:  写入普通标量，不使用引号，但会处理换行和空格。
   - `yaml_emitter_write_single_quoted_scalar`:  写入单引号标量，需要转义单引号。
   - `yaml_emitter_write_double_quoted_scalar`:  写入双引号标量，需要转义特殊字符。
   - `yaml_emitter_write_block_scalar_hints`:  为块标量（文字型和折叠型）写入提示符，例如缩进提示和 chomping 指示符。
   - `yaml_emitter_write_literal_scalar`:  写入文字型块标量，保留所有换行。
   - `yaml_emitter_write_folded_scalar`:  写入折叠型块标量，将单行换行符转换为空格。

**它是什么 Go 语言功能的实现？**

这段代码实现的是 YAML 的 **序列化 (Serialization)** 或者更准确地说是 **发射 (Emitting)** 功能。它将代表 YAML 结构的内部事件逐步转化为最终的 YAML 文本格式。

**Go 代码举例说明:**

虽然这段代码本身是底层的 C 绑定代码，但我们可以用 `gopkg.in/yaml.v2` 包来演示其高层的使用。这个包会调用底层的 emitterc 代码来生成 YAML。

```go
package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
)

type Person struct {
	Name string `yaml:"name"`
	Age  int    `yaml:"age"`
}

func main() {
	p := Person{Name: "张三", Age: 30}

	// 将 Go 结构体序列化为 YAML 字符串
	yamlData, err := yaml.Marshal(p)
	if err != nil {
		fmt.Println("Error marshaling YAML:", err)
		return
	}

	fmt.Println(string(yamlData))
}
```

**假设输入与输出：**

在上面的 Go 代码例子中：

**输入 (Go 结构体):**

```go
Person{Name: "张三", Age: 30}
```

**输出 (YAML 字符串):**

```yaml
name: 张三
age: 30
```

底层的 `emitterc.go` 中的函数会在 `yaml.Marshal` 内部被调用，将 `Person` 结构体的字段名和值转换为 YAML 的键值对，并根据规则选择合适的标量表示方式（在这个例子中是普通标量）。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是一个库的内部实现细节。然而，包含它的 `gometalinter` 工具可能会使用命令行参数来控制 YAML 输出的某些方面，例如缩进级别或是否使用 canonical 格式。  具体的命令行参数需要查看 `gometalinter` 的文档。

**使用者易犯错的点 (针对 `gopkg.in/yaml.v2` 包的使用者):**

虽然这段代码是底层的，但基于其功能，我们可以推断出 `gopkg.in/yaml.v2` 的使用者可能犯的错误：

1. **对 YAML 标签的理解不足:**  错误地指定或忽略 YAML 标签可能导致反序列化时类型不匹配或逻辑错误。
2. **对 YAML 锚点的使用不当:**  错误地使用锚点和别名可能导致循环引用或数据重复。
3. **期望特定的 YAML 标量格式，但未进行配置:**  例如，期望所有字符串都用双引号括起来，但默认情况下可能使用普通标量。用户可能需要通过配置 `yaml.v2` 包的选项（如果提供）或者调整数据结构来影响输出格式。

**总结 `emitterc.go` 的功能（结合第 1 部分和第 2 部分的理解）:**

综合来看，`emitterc.go` 是 `gopkg.in/yaml.v2` 库中负责将 YAML 的内部表示形式（一系列事件）转换为最终 YAML 文本的关键组件。它涵盖了 YAML 规范中关于输出格式的各种细节，包括：

* **基本结构元素:** 文档开始/结束，流/块序列/映射的开始/结束。
* **内容元素:**  标量（不同引号方式和块格式）、锚点和标签。
* **格式控制:** 缩进、空白、换行符、BOM。
* **输出选项:**  例如是否使用 canonical 格式，以及对不同标量类型的允许设置。

它通过一系列的 `yaml_emitter_write_*` 函数，根据分析的事件信息和预设的输出选项，逐步将 YAML 的各个组成部分写入缓冲区，最终生成符合 YAML 规范的文本输出。  `emitterc.go` 的核心职责是 **将抽象的 YAML 结构具象化为可读的文本**。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/emitterc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
itter.scalar_data.block_plain_allowed = false
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