Response:
Let's break down the thought process for analyzing this Go code snippet and generating the answer.

**1. Understanding the Goal:**

The request asks for the *functionality* of the provided Go code, which is part of a YAML parser's scanner. It also asks for related information like Go examples, error points, and a summary. Crucially, it's the *third* part of a larger piece, so the focus should be on the specific code provided.

**2. Initial Code Scan and Keyword Spotting:**

I immediately scan the code for keywords and patterns that suggest its purpose:

* **`yaml_parser_scan_quoted_scalar` and `yaml_parser_scan_plain_scalar`:** These function names are the most direct clues. They suggest the code is responsible for scanning and identifying scalar values in YAML, differentiated by whether they are quoted or plain.
* **`parser *yaml_parser_t` and `token *yaml_token_t`:**  This strongly indicates the code operates on a parser state (`yaml_parser_t`) and produces tokens (`yaml_token_t`), which are common steps in parsing.
* **Loops and conditional checks:** The code is full of `for` loops and `if` statements checking characters in the `parser.buffer`. This suggests character-by-character processing of the input YAML.
* **Escape sequences (e.g., `\n`, `\t`, `\x`, `\u`, `\U`):**  These are prominent in the `yaml_parser_scan_quoted_scalar` function, indicating handling of escape characters within quoted strings.
* **Error handling:**  Calls to `yaml_parser_set_scanner_error` suggest the code is responsible for detecting and reporting syntax errors in the YAML.
* **Document indicators (`---`, `...`):** The code explicitly checks for these at the beginning of lines within scalars.
* **Whitespace handling:**  Variables like `leading_break`, `trailing_breaks`, and `whitespaces` along with checks for `is_blank` and `is_break` point to detailed whitespace processing.
* **Indentation:** The `yaml_parser_scan_plain_scalar` function refers to `parser.indent`, suggesting indentation awareness is part of parsing plain scalars.
* **Flow level:** The check `parser.flow_level > 0` hints at handling YAML within flow constructs (like lists and maps enclosed in brackets/braces).
* **Token creation:**  The lines assigning values to `token.typ`, `token.start_mark`, `token.end_mark`, `token.value`, and `token.style` clearly show the construction of a token.

**3. Deeper Dive into Each Function:**

* **`yaml_parser_scan_quoted_scalar`:**
    * **Purpose:**  Clearly handles both single-quoted (`'`) and double-quoted (`"`) strings.
    * **Escape handling:**  The `switch` statement within the double-quoted case handles various escape sequences. The code for handling `\x`, `\u`, and `\U` for Unicode characters is notable.
    * **Whitespace:** Manages leading and trailing whitespace and line breaks within the quotes.
    * **Error conditions:** Checks for unexpected document indicators and EOF.

* **`yaml_parser_scan_plain_scalar`:**
    * **Purpose:** Handles unquoted scalar values.
    * **Termination conditions:**  Looks for characters that signal the end of a plain scalar (like `:`, `#`, `,`, `?`, `[`, `]`, `{`, `}`).
    * **Whitespace and indentation:** Carefully manages whitespace, including handling line folding and checking for indentation errors (tabs used incorrectly).
    * **`simple_key_allowed`:**  The modification of this flag suggests a connection to how YAML keys are parsed.

**4. Inferring the Go Functionality:**

Based on the analysis, the code implements the part of a YAML parser responsible for recognizing and extracting scalar values (strings). The two functions handle the distinct cases of quoted and unquoted scalars, respecting YAML's syntax rules for each.

**5. Crafting the Go Example (with Input and Output):**

To illustrate, I create a simple example that showcases both quoted and plain scalars and how the hypothetical parser would extract them into tokens. The input YAML is designed to trigger both functions. The output is a simplified representation of the tokens that *would* be generated. This doesn't need to be runnable code but should clearly demonstrate the *conceptual* input and output.

**6. Identifying Error-Prone Areas:**

I think about common YAML syntax mistakes users might make:

* **Incorrect escaping:** Forgetting to escape special characters or using incorrect escape sequences.
* **Indentation errors (especially with tabs):** YAML is sensitive to indentation.
* **Unintended interpretation of plain scalars:**  Using characters in plain scalars that YAML interprets as special delimiters.

**7. Detailing Command-Line Arguments (If Applicable):**

In this specific code snippet, there are no direct command-line argument processing. This part of the question can be skipped.

**8. Summarizing the Functionality (Part 3):**

The final summary focuses on the core task of these two functions: recognizing and extracting scalar tokens from the YAML input stream, differentiating between quoted and plain styles, and handling their respective syntax rules.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this is just about string handling. *Correction:* The presence of `yaml_parser_t` and `yaml_token_t` makes it clear this is part of a larger parsing process, specifically the scanning phase.
* **Focusing on code details:** I might initially get bogged down in the minutiae of buffer handling. *Refinement:*  The focus should be on the *high-level functionality* – what these functions achieve in terms of YAML parsing.
* **Example complexity:** I could try to create a very complex Go example. *Refinement:* A simple, illustrative example is better for demonstrating the core concepts.

By following this systematic approach, focusing on identifying key elements and their purpose, and then synthesizing that information into a clear explanation with supporting examples, the comprehensive answer can be constructed.
这是提供的Go语言代码片段的第三部分，与前两部分共同构成了一个YAML解析器的扫描器（Scanner）组件中处理标量（Scalar）值的逻辑。

**归纳一下它的功能:**

这部分代码的核心功能是扫描并识别YAML文档中的两种类型的标量值：**带引号的标量 (quoted scalar)** 和 **普通标量 (plain scalar)**。它负责从输入流中读取字符，根据YAML语法规则判断标量的边界和内容，并将其封装成 `yaml_token_t` 类型的 Token，以便后续的解析器进行处理。

具体来说，`yaml_parser_scan_quoted_scalar` 函数处理被单引号 (`'`) 或双引号 (`"`) 包围的标量值，它需要处理转义字符，并正确解析引号内的内容。 `yaml_parser_scan_plain_scalar` 函数处理不带引号的标量值，它需要根据 YAML 语法规则判断普通标量的结束位置，例如遇到空白字符、特定分隔符或新的缩进层级。

**更详细的功能分解:**

1. **`yaml_parser_scan_quoted_scalar(parser *yaml_parser_t, token *yaml_token_t) bool`**:
   - **识别带引号标量的开始:**  假设在之前的扫描过程中，已经识别到单引号或双引号的起始符。
   - **处理转义字符:**  对于双引号括起来的标量，能够识别并解析各种转义序列，如 `\n` (换行符), `\t` (制表符), `\\` (反斜杠), `\"` (双引号), `\'` (单引号), 以及 Unicode 转义 (`\xNN`, `\uNNNN`, `\UNNNNNNNN`)。
   - **处理连续的相同引号:** 对于单引号标量，`''` 表示一个 `\'` 字符。
   - **处理行尾折叠:**  双引号标量中，反斜杠加换行符 `\` 可以用来折叠长行。
   - **处理空白字符:**  识别并处理引号内的空格和制表符。
   - **检查非法文档指示符:**  在扫描过程中，如果遇到 `---` 或 `...` 这样的文档结束符，会报错。
   - **检查文件结束符 (EOF):** 如果在引号未闭合的情况下遇到文件结束符，会报错。
   - **创建标量 Token:**  成功扫描到完整的带引号标量后，创建一个 `yaml_SCALAR_TOKEN` 类型的 Token，包含标量的值 (`value`) 和样式 (`style`: `yaml_SINGLE_QUOTED_SCALAR_STYLE` 或 `yaml_DOUBLE_QUOTED_SCALAR_STYLE`) 以及开始和结束的标记 (`start_mark`, `end_mark`)。

2. **`yaml_parser_scan_plain_scalar(parser *yaml_parser_t, token *yaml_token_t) bool`**:
   - **识别普通标量的开始:** 假设在之前的扫描过程中，已经识别到可能是一个普通标量的起始位置。
   - **判断普通标量的结束:**  根据 YAML 语法规则，当遇到以下情况时，普通标量结束：
     - 行首出现文档指示符 (`---` 或 `...`)
     - 遇到注释符 (`#`)
     - 遇到可能结束普通标量的指示符，例如冒号 (`:`) 后跟空白字符，或者在 Flow 样式上下文中遇到逗号 (`,`)、问号 (`?`)、方括号 (`[]`)、花括号 (`{}`) 等。
   - **处理行尾折叠:**  如果行尾是空白字符，下一行也是空白字符开始，则会将换行符折叠成空格。
   - **处理空白字符:**  识别并处理空格和制表符，但会检查制表符是否违反了缩进规则。
   - **检查缩进级别:**  在非 Flow 样式上下文中，如果当前行的缩进小于期望的缩进级别，则认为普通标量结束。
   - **创建标量 Token:**  成功扫描到完整的普通标量后，创建一个 `yaml_SCALAR_TOKEN` 类型的 Token，包含标量的值 (`value`) 和样式 (`style`: `yaml_PLAIN_SCALAR_STYLE`) 以及开始和结束的标记。
   - **更新 `simple_key_allowed` 标志:**  如果普通标量之前存在前导空白，则将解析器的 `simple_key_allowed` 标志设置为 `true`，这与 YAML 中简单键的解析有关。

**Go 代码举例说明:**

由于这段代码是 YAML 解析器内部的实现细节，直接使用 Go 标准库中的 `encoding/yaml` 包无法直接触发这些函数。  以下是一个**概念性**的例子，展示了输入 YAML 可能如何被这两个函数处理，以及预期的 Token 输出。

**假设的输入 YAML 片段:**

```yaml
name: "John Doe"
age: 30
message: 'This is a multi-line\nstring.'
description:  This is a
  plain scalar
  with line folding.
```

**假设的 `yaml_parser_scan_quoted_scalar` 处理 `"John Doe"` 的过程:**

```go
// 假设 parser 的状态已经指向了双引号 "
parser := &yaml_parser_t{
	buffer:     []byte("\"John Doe\""),
	buffer_pos: 0, // 指向双引号
	mark:       yaml_mark_t{line: 0, column: 6}, // 假设 " 在第 0 行第 6 列
}
token := &yaml_token_t{}

success := yaml_parser_scan_quoted_scalar(parser, token)

// 假设 success 为 true
if success {
	fmt.Printf("Token Type: %d\n", token.typ)          // Output: Token Type: 4 (假设 yaml_SCALAR_TOKEN 的值为 4)
	fmt.Printf("Token Value: %s\n", string(token.value)) // Output: Token Value: John Doe
	fmt.Printf("Token Style: %d\n", token.style)        // Output: Token Style: 2 (假设 yaml_DOUBLE_QUOTED_SCALAR_STYLE 的值为 2)
	fmt.Printf("Start Mark: Line %d, Column %d\n", token.start_mark.line, token.start_mark.column) // 实际的行列号
	fmt.Printf("End Mark: Line %d, Column %d\n", token.end_mark.line, token.end_mark.column)     // 实际的行列号
}
```

**假设的 `yaml_parser_scan_plain_scalar` 处理 `30` 的过程:**

```go
// 假设 parser 的状态已经指向了字符 3
parser := &yaml_parser_t{
	buffer:     []byte("30\n"),
	buffer_pos: 0, // 指向 '3'
	mark:       yaml_mark_t{line: 1, column: 5}, // 假设 3 在第 1 行第 5 列
}
token := &yaml_token_t{}

success := yaml_parser_scan_plain_scalar(parser, token)

// 假设 success 为 true
if success {
	fmt.Printf("Token Type: %d\n", token.typ)          // Output: Token Type: 4
	fmt.Printf("Token Value: %s\n", string(token.value)) // Output: Token Value: 30
	fmt.Printf("Token Style: %d\n", token.style)        // Output: Token Style: 1 (假设 yaml_PLAIN_SCALAR_STYLE 的值为 1)
	fmt.Printf("Start Mark: Line %d, Column %d\n", token.start_mark.line, token.start_mark.column) // 实际的行列号
	fmt.Printf("End Mark: Line %d, Column %d\n", token.end_mark.line, token.end_mark.column)     // 实际的行列号
}
```

**使用者易犯错的点 (假设你是直接操作这个底层的扫描器):**

1. **不正确的转义:**  在双引号字符串中，忘记转义特殊字符，或者使用了错误的转义序列。例如，希望表示反斜杠时只写了一个 `\`，而不是 `\\`。
2. **普通标量中使用了特殊字符:**  在不加引号的情况下，在标量值中使用了 YAML 语法中的特殊字符（如 `:`, `-`, `#` 等），导致解析器提前结束标量的扫描。
3. **缩进错误 (仅限普通标量):**  在普通标量跨越多行时，后续行的缩进不一致，可能导致解析器错误地判断标量的结束位置。尤其是在混合使用空格和制表符缩进时容易出错。

总结来说，这段代码是 YAML 解析器中至关重要的组成部分，负责将输入的字符流转化为有意义的标量 Token，为后续的语法分析和语义理解奠定基础。它需要精确地遵循 YAML 规范，处理各种细节情况，包括转义、空白符和行尾折叠等。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/scannerc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
 parser.mark
	skip(parser)

	// Consume the content of the quoted scalar.
	var s, leading_break, trailing_breaks, whitespaces []byte
	for {
		// Check that there are no document indicators at the beginning of the line.
		if parser.unread < 4 && !yaml_parser_update_buffer(parser, 4) {
			return false
		}

		if parser.mark.column == 0 &&
			((parser.buffer[parser.buffer_pos+0] == '-' &&
				parser.buffer[parser.buffer_pos+1] == '-' &&
				parser.buffer[parser.buffer_pos+2] == '-') ||
				(parser.buffer[parser.buffer_pos+0] == '.' &&
					parser.buffer[parser.buffer_pos+1] == '.' &&
					parser.buffer[parser.buffer_pos+2] == '.')) &&
			is_blankz(parser.buffer, parser.buffer_pos+3) {
			yaml_parser_set_scanner_error(parser, "while scanning a quoted scalar",
				start_mark, "found unexpected document indicator")
			return false
		}

		// Check for EOF.
		if is_z(parser.buffer, parser.buffer_pos) {
			yaml_parser_set_scanner_error(parser, "while scanning a quoted scalar",
				start_mark, "found unexpected end of stream")
			return false
		}

		// Consume non-blank characters.
		leading_blanks := false
		for !is_blankz(parser.buffer, parser.buffer_pos) {
			if single && parser.buffer[parser.buffer_pos] == '\'' && parser.buffer[parser.buffer_pos+1] == '\'' {
				// Is is an escaped single quote.
				s = append(s, '\'')
				skip(parser)
				skip(parser)

			} else if single && parser.buffer[parser.buffer_pos] == '\'' {
				// It is a right single quote.
				break
			} else if !single && parser.buffer[parser.buffer_pos] == '"' {
				// It is a right double quote.
				break

			} else if !single && parser.buffer[parser.buffer_pos] == '\\' && is_break(parser.buffer, parser.buffer_pos+1) {
				// It is an escaped line break.
				if parser.unread < 3 && !yaml_parser_update_buffer(parser, 3) {
					return false
				}
				skip(parser)
				skip_line(parser)
				leading_blanks = true
				break

			} else if !single && parser.buffer[parser.buffer_pos] == '\\' {
				// It is an escape sequence.
				code_length := 0

				// Check the escape character.
				switch parser.buffer[parser.buffer_pos+1] {
				case '0':
					s = append(s, 0)
				case 'a':
					s = append(s, '\x07')
				case 'b':
					s = append(s, '\x08')
				case 't', '\t':
					s = append(s, '\x09')
				case 'n':
					s = append(s, '\x0A')
				case 'v':
					s = append(s, '\x0B')
				case 'f':
					s = append(s, '\x0C')
				case 'r':
					s = append(s, '\x0D')
				case 'e':
					s = append(s, '\x1B')
				case ' ':
					s = append(s, '\x20')
				case '"':
					s = append(s, '"')
				case '\'':
					s = append(s, '\'')
				case '\\':
					s = append(s, '\\')
				case 'N': // NEL (#x85)
					s = append(s, '\xC2')
					s = append(s, '\x85')
				case '_': // #xA0
					s = append(s, '\xC2')
					s = append(s, '\xA0')
				case 'L': // LS (#x2028)
					s = append(s, '\xE2')
					s = append(s, '\x80')
					s = append(s, '\xA8')
				case 'P': // PS (#x2029)
					s = append(s, '\xE2')
					s = append(s, '\x80')
					s = append(s, '\xA9')
				case 'x':
					code_length = 2
				case 'u':
					code_length = 4
				case 'U':
					code_length = 8
				default:
					yaml_parser_set_scanner_error(parser, "while parsing a quoted scalar",
						start_mark, "found unknown escape character")
					return false
				}

				skip(parser)
				skip(parser)

				// Consume an arbitrary escape code.
				if code_length > 0 {
					var value int

					// Scan the character value.
					if parser.unread < code_length && !yaml_parser_update_buffer(parser, code_length) {
						return false
					}
					for k := 0; k < code_length; k++ {
						if !is_hex(parser.buffer, parser.buffer_pos+k) {
							yaml_parser_set_scanner_error(parser, "while parsing a quoted scalar",
								start_mark, "did not find expected hexdecimal number")
							return false
						}
						value = (value << 4) + as_hex(parser.buffer, parser.buffer_pos+k)
					}

					// Check the value and write the character.
					if (value >= 0xD800 && value <= 0xDFFF) || value > 0x10FFFF {
						yaml_parser_set_scanner_error(parser, "while parsing a quoted scalar",
							start_mark, "found invalid Unicode character escape code")
						return false
					}
					if value <= 0x7F {
						s = append(s, byte(value))
					} else if value <= 0x7FF {
						s = append(s, byte(0xC0+(value>>6)))
						s = append(s, byte(0x80+(value&0x3F)))
					} else if value <= 0xFFFF {
						s = append(s, byte(0xE0+(value>>12)))
						s = append(s, byte(0x80+((value>>6)&0x3F)))
						s = append(s, byte(0x80+(value&0x3F)))
					} else {
						s = append(s, byte(0xF0+(value>>18)))
						s = append(s, byte(0x80+((value>>12)&0x3F)))
						s = append(s, byte(0x80+((value>>6)&0x3F)))
						s = append(s, byte(0x80+(value&0x3F)))
					}

					// Advance the pointer.
					for k := 0; k < code_length; k++ {
						skip(parser)
					}
				}
			} else {
				// It is a non-escaped non-blank character.
				s = read(parser, s)
			}
			if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
				return false
			}
		}

		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}

		// Check if we are at the end of the scalar.
		if single {
			if parser.buffer[parser.buffer_pos] == '\'' {
				break
			}
		} else {
			if parser.buffer[parser.buffer_pos] == '"' {
				break
			}
		}

		// Consume blank characters.
		for is_blank(parser.buffer, parser.buffer_pos) || is_break(parser.buffer, parser.buffer_pos) {
			if is_blank(parser.buffer, parser.buffer_pos) {
				// Consume a space or a tab character.
				if !leading_blanks {
					whitespaces = read(parser, whitespaces)
				} else {
					skip(parser)
				}
			} else {
				if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
					return false
				}

				// Check if it is a first line break.
				if !leading_blanks {
					whitespaces = whitespaces[:0]
					leading_break = read_line(parser, leading_break)
					leading_blanks = true
				} else {
					trailing_breaks = read_line(parser, trailing_breaks)
				}
			}
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		// Join the whitespaces or fold line breaks.
		if leading_blanks {
			// Do we need to fold line breaks?
			if len(leading_break) > 0 && leading_break[0] == '\n' {
				if len(trailing_breaks) == 0 {
					s = append(s, ' ')
				} else {
					s = append(s, trailing_breaks...)
				}
			} else {
				s = append(s, leading_break...)
				s = append(s, trailing_breaks...)
			}
			trailing_breaks = trailing_breaks[:0]
			leading_break = leading_break[:0]
		} else {
			s = append(s, whitespaces...)
			whitespaces = whitespaces[:0]
		}
	}

	// Eat the right quote.
	skip(parser)
	end_mark := parser.mark

	// Create a token.
	*token = yaml_token_t{
		typ:        yaml_SCALAR_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
		style:      yaml_SINGLE_QUOTED_SCALAR_STYLE,
	}
	if !single {
		token.style = yaml_DOUBLE_QUOTED_SCALAR_STYLE
	}
	return true
}

// Scan a plain scalar.
func yaml_parser_scan_plain_scalar(parser *yaml_parser_t, token *yaml_token_t) bool {

	var s, leading_break, trailing_breaks, whitespaces []byte
	var leading_blanks bool
	var indent = parser.indent + 1

	start_mark := parser.mark
	end_mark := parser.mark

	// Consume the content of the plain scalar.
	for {
		// Check for a document indicator.
		if parser.unread < 4 && !yaml_parser_update_buffer(parser, 4) {
			return false
		}
		if parser.mark.column == 0 &&
			((parser.buffer[parser.buffer_pos+0] == '-' &&
				parser.buffer[parser.buffer_pos+1] == '-' &&
				parser.buffer[parser.buffer_pos+2] == '-') ||
				(parser.buffer[parser.buffer_pos+0] == '.' &&
					parser.buffer[parser.buffer_pos+1] == '.' &&
					parser.buffer[parser.buffer_pos+2] == '.')) &&
			is_blankz(parser.buffer, parser.buffer_pos+3) {
			break
		}

		// Check for a comment.
		if parser.buffer[parser.buffer_pos] == '#' {
			break
		}

		// Consume non-blank characters.
		for !is_blankz(parser.buffer, parser.buffer_pos) {

			// Check for indicators that may end a plain scalar.
			if (parser.buffer[parser.buffer_pos] == ':' && is_blankz(parser.buffer, parser.buffer_pos+1)) ||
				(parser.flow_level > 0 &&
					(parser.buffer[parser.buffer_pos] == ',' ||
						parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == '[' ||
						parser.buffer[parser.buffer_pos] == ']' || parser.buffer[parser.buffer_pos] == '{' ||
						parser.buffer[parser.buffer_pos] == '}')) {
				break
			}

			// Check if we need to join whitespaces and breaks.
			if leading_blanks || len(whitespaces) > 0 {
				if leading_blanks {
					// Do we need to fold line breaks?
					if leading_break[0] == '\n' {
						if len(trailing_breaks) == 0 {
							s = append(s, ' ')
						} else {
							s = append(s, trailing_breaks...)
						}
					} else {
						s = append(s, leading_break...)
						s = append(s, trailing_breaks...)
					}
					trailing_breaks = trailing_breaks[:0]
					leading_break = leading_break[:0]
					leading_blanks = false
				} else {
					s = append(s, whitespaces...)
					whitespaces = whitespaces[:0]
				}
			}

			// Copy the character.
			s = read(parser, s)

			end_mark = parser.mark
			if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
				return false
			}
		}

		// Is it the end?
		if !(is_blank(parser.buffer, parser.buffer_pos) || is_break(parser.buffer, parser.buffer_pos)) {
			break
		}

		// Consume blank characters.
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}

		for is_blank(parser.buffer, parser.buffer_pos) || is_break(parser.buffer, parser.buffer_pos) {
			if is_blank(parser.buffer, parser.buffer_pos) {

				// Check for tab characters that abuse indentation.
				if leading_blanks && parser.mark.column < indent && is_tab(parser.buffer, parser.buffer_pos) {
					yaml_parser_set_scanner_error(parser, "while scanning a plain scalar",
						start_mark, "found a tab character that violates indentation")
					return false
				}

				// Consume a space or a tab character.
				if !leading_blanks {
					whitespaces = read(parser, whitespaces)
				} else {
					skip(parser)
				}
			} else {
				if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
					return false
				}

				// Check if it is a first line break.
				if !leading_blanks {
					whitespaces = whitespaces[:0]
					leading_break = read_line(parser, leading_break)
					leading_blanks = true
				} else {
					trailing_breaks = read_line(parser, trailing_breaks)
				}
			}
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		// Check indentation level.
		if parser.flow_level == 0 && parser.mark.column < indent {
			break
		}
	}

	// Create a token.
	*token = yaml_token_t{
		typ:        yaml_SCALAR_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
		style:      yaml_PLAIN_SCALAR_STYLE,
	}

	// Note that we change the 'simple_key_allowed' flag.
	if leading_blanks {
		parser.simple_key_allowed = true
	}
	return true
}

"""




```