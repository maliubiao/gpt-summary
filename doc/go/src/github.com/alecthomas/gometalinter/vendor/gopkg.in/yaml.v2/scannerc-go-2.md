Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of a YAML parser. This is the third part of a three-part explanation. I need to summarize the functionalities described in the previous parts (implicitly).

Based on the code, this part seems to handle the scanning of different types of YAML scalars:
- Flow scalars (single and double quoted strings)
- Plain scalars (unquoted strings)

I will break down the functionality of each function:

- `yaml_parser_scan_block_scalar_indentation`: This function appears to determine the indentation level for block scalars.
- `yaml_parser_scan_flow_scalar`: This function scans single-quoted and double-quoted strings, handling escape sequences and line breaks.
- `yaml_parser_scan_plain_scalar`: This function scans plain, unquoted strings, handling line breaks and checking for characters that might end the scalar.

I need to summarize these functionalities.
这是 `go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/scannerc.go` 文件中 YAML 解析器的词法扫描部分，专注于识别和提取 YAML 中的标量（scalar）值。

综合前两部分的内容，这个词法扫描器（scanner）的主要功能是读取输入的 YAML 文本，并将其分解成一系列的 token。这些 token 代表了 YAML 文档的基本构成单元，例如：

* **指示符 (indicators):**  `'`, `"`, `-`, `:`, `?`, `[`, `]`, `{`, `}`, `#`, `&`, `*`, `!`, `%`, `@`
* **空白符 (whitespaces):** 空格、制表符
* **换行符 (line breaks)**
* **缩进 (indentation)**
* **流标量 (flow scalars):**  单引号或双引号包围的字符串
* **块标量 (block scalars):**  多行文本块，可以用字面量形式 (`|`) 或折叠形式 (`>`) 表示
* **锚点 (anchors)** 和 **别名 (aliases)**
* **标签 (tags)**
* **文档开始 (document start)** 和 **结束 (document end)** 指示符

而**这第三部分主要负责识别和处理 YAML 中的不同类型的标量值：流标量和普通标量。**

具体来说，这部分代码实现了以下功能：

1. **`yaml_parser_scan_block_scalar_indentation`**:  确定块标量（例如，使用 `|` 或 `>` 定义的多行字符串）的缩进级别。这对于正确解析块标量的内容至关重要。

2. **`yaml_parser_scan_flow_scalar`**:  扫描流标量，也就是用单引号 (`'`) 或双引号 (`"`) 包围的字符串。
    * 它会识别并移除引号。
    * 它会处理单引号和双引号字符串中的转义序列（例如 `\n` 表示换行，`\"` 表示双引号）。
    * 对于单引号字符串，`''` 被视为一个字面的单引号。
    * 它会处理行尾的换行符，根据情况将其转换为空格或直接移除。

3. **`yaml_parser_scan_plain_scalar`**:  扫描普通标量，也就是没有引号的字符串。
    * 它会持续读取字符直到遇到可能结束标量的字符，例如空白符、换行符、某些指示符（例如 `:` 在键值对中，`,` 在序列中）或注释符 `#`。
    * 它会处理行尾的换行符，根据情况将其转换为空格或直接移除。
    * 它会检查缩进，确保普通标量没有违反当前的缩进级别。
    * 在流上下文中，它会特别检查冒号 `:` 的使用，避免将其误认为键值对的分隔符。

**总结一下这部分的功能：**  这部分代码主要负责识别和提取 YAML 文件中的不同形式的字符串值（标量），包括带引号的和不带引号的，并处理其中的转义和换行规则，为后续的语法分析提供标量类型的 token。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/scannerc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
t+1 {
			*indent = parser.indent + 1
		}
		if *indent < 1 {
			*indent = 1
		}
	}
	return true
}

// Scan a quoted scalar.
func yaml_parser_scan_flow_scalar(parser *yaml_parser_t, token *yaml_token_t, single bool) bool {
	// Eat the left quote.
	start_mark := parser.mark
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
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}

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

			// Check for 'x:x' in the flow context. TODO: Fix the test "spec-08-13".
			if parser.flow_level > 0 &&
				parser.buffer[parser.buffer_pos] == ':' &&
				!is_blankz(parser.buffer, parser.buffer_pos+1) {
				yaml_parser_set_scanner_error(parser, "while scanning a plain scalar",
					start_mark, "found unexpected ':'")
				return false
			}

			// Check for indicators that may end a plain scalar.
			if (parser.buffer[parser.buffer_pos] == ':' && is_blankz(parser.buffer, parser.buffer_pos+1)) ||
				(parser.flow_level > 0 &&
					(parser.buffer[parser.buffer_pos] == ',' || parser.buffer[parser.buffer_pos] == ':' ||
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

				// Check for tab character that abuse indentation.
				if leading_blanks && parser.mark.column < indent && is_tab(parser.buffer, parser.buffer_pos) {
					yaml_parser_set_scanner_error(parser, "while scanning a plain scalar",
						start_mark, "found a tab character that violate indentation")
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