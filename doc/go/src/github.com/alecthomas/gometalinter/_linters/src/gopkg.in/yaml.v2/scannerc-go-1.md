Response:
The user wants a summary of the functionality of the provided Go code snippet. This snippet seems to be part of a YAML parser's scanner, responsible for recognizing and producing different types of YAML tokens.

To achieve this, I need to go through each function in the code and understand its purpose. I'll then group related functionalities and provide a concise summary.

Here's a breakdown of the functions and their roles:

- `yaml_parser_fetch_flow_collection_end`: Handles the end of flow sequences or mappings (']' or '}').
- `yaml_parser_fetch_flow_entry`: Handles the ',' separator in flow collections.
- `yaml_parser_fetch_block_entry`: Handles the '-' indicator for block sequence entries.
- `yaml_parser_fetch_key`: Handles the '?' indicator for mapping keys.
- `yaml_parser_fetch_value`: Handles the ':' indicator for mapping values.
- `yaml_parser_fetch_anchor`: Handles the '&' indicator for anchors.
- `yaml_parser_fetch_tag`: Handles the '!' indicator for tags.
- `yaml_parser_fetch_block_scalar`: Handles block scalars (literal '|' or folded '>').
- `yaml_parser_fetch_flow_scalar`: Handles flow scalars (single or double quotes).
- `yaml_parser_fetch_plain_scalar`: Handles plain scalars.
- `yaml_parser_scan_to_next_token`: Skips whitespace and comments to find the next token.
- `yaml_parser_scan_directive`: Handles `%` directives (YAML and TAG).
- `yaml_parser_scan_directive_name`: Scans the name of a directive.
- `yaml_parser_scan_version_directive_value`: Scans the value of a YAML directive.
- `yaml_parser_scan_version_directive_number`: Scans the version number in a YAML directive.
- `yaml_parser_scan_tag_directive_value`: Scans the value of a TAG directive.
- `yaml_parser_scan_anchor`: Scans the value of an anchor or alias.
- `yaml_parser_scan_tag`: Scans the value of a tag.
- `yaml_parser_scan_tag_handle`: Scans the handle part of a tag.
- `yaml_parser_scan_tag_uri`: Scans the URI part of a tag.
- `yaml_parser_scan_uri_escapes`: Decodes URI escape sequences in tags.
- `yaml_parser_scan_block_scalar`: Scans the content of a block scalar.
- `yaml_parser_scan_block_scalar_breaks`: Scans indentation and line breaks within block scalars.
- `yaml_parser_scan_flow_scalar`: Scans the content of a flow scalar.

Based on this, the main function of this part of the code is to identify and extract different YAML tokens from the input stream. It handles various syntactic elements of YAML, such as flow and block structures, scalars, anchors, tags, and directives.
这段代码是 YAML 解析器（parser）的扫描器（scanner）部分，专门负责识别和提取 YAML 文档中的各种 **token（令牌）**。 这些 token 是构成 YAML 语法的基础单元。

具体来说，这段代码实现的功能可以归纳为以下几点：

1. **识别和生成表示 YAML 结构开始和结束的 token：**
   - `yaml_parser_fetch_flow_collection_end`:  识别并生成 `FLOW-SEQUENCE-END` (对应 `]`) 或 `FLOW-MAPPING-END` (对应 `}`) token，用于结束 flow 风格的序列或映射。
   - 代码逻辑会检查并移除当前 flow 层级的简单键（simple key），减少 flow 层级，并设置 `simple_key_allowed` 标志。

2. **识别和生成 flow 风格集合中的分隔符 token：**
   - `yaml_parser_fetch_flow_entry`: 识别并生成 `FLOW-ENTRY` (对应 `,`) token，用于分隔 flow 风格序列或映射中的元素。
   - 代码逻辑会检查并移除简单键，并设置 `simple_key_allowed` 标志，因为在 `,` 之后可以出现简单键。

3. **识别和生成 block 风格集合中的条目开始 token：**
   - `yaml_parser_fetch_block_entry`: 识别并生成 `BLOCK-ENTRY` (对应 `-`) token，用于开始 block 风格序列中的一个条目。
   - 代码逻辑会检查当前是否处于 block 上下文 (`flow_level == 0`)，以及是否允许开始新的条目。如果需要，还会生成 `BLOCK-SEQUENCE-START` token。

4. **识别和生成映射中的键 token：**
   - `yaml_parser_fetch_key`: 识别并生成 `KEY` (对应 `?`) token，用于标识映射中的一个键。
   - 代码逻辑会检查 block 上下文的条件，如果需要，会生成 `BLOCK-MAPPING-START` token。

5. **识别和生成映射中的值 token：**
   - `yaml_parser_fetch_value`: 识别并生成 `VALUE` (对应 `:`) token，用于标识映射中的一个值。
   - 代码逻辑会处理简单键的情况，如果存在简单键，会先生成 `KEY` token。在 block 上下文中，如果需要，会生成 `BLOCK-MAPPING-START` token。

6. **识别和生成锚点和别名 token：**
   - `yaml_parser_fetch_anchor`: 识别并生成 `ALIAS` (对应 `*`) 或 `ANCHOR` (对应 `&`) token。
   - 代码逻辑会保存简单键信息，并禁止在锚点或别名后出现简单键。实际的锚点或别名值由 `yaml_parser_scan_anchor` 函数扫描。

7. **识别和生成标签 token：**
   - `yaml_parser_fetch_tag`: 识别并生成 `TAG` (对应 `!`) token。
   - 代码逻辑会保存简单键信息，并禁止在标签后出现简单键。实际的标签值由 `yaml_parser_scan_tag` 函数扫描。

8. **识别和生成标量 token（不同风格）：**
   - `yaml_parser_fetch_block_scalar`: 识别并生成 block 风格的标量 `SCALAR` token (对应 `|` 或 `>` 引导的文字或折叠标量)。
   - `yaml_parser_fetch_flow_scalar`: 识别并生成 flow 风格的标量 `SCALAR` token (对应单引号 `'` 或双引号 `"` 包裹的标量)。
   - `yaml_parser_fetch_plain_scalar`: 识别并生成普通标量 `SCALAR` token (没有引号的标量)。
   - 这些函数会调用相应的 `yaml_parser_scan_*_scalar` 函数来扫描标量的内容。

9. **跳过空白和注释：**
   - `yaml_parser_scan_to_next_token`:  负责跳过输入流中的空格、制表符、注释 (`#`) 和换行符，直到找到下一个有效的 token。

10. **扫描指令 token：**
    - `yaml_parser_scan_directive`: 识别并生成指令 token，如 `YAML-DIRECTIVE` (对应 `%YAML`) 和 `TAG-DIRECTIVE` (对应 `%TAG`)。
    - 相关的辅助函数 `yaml_parser_scan_directive_name`, `yaml_parser_scan_version_directive_value`, `yaml_parser_scan_tag_directive_value` 用于解析指令的具体内容。

11. **扫描锚点、别名和标签的具体值：**
    - `yaml_parser_scan_anchor`: 扫描 `*` 或 `&` 符号后面的锚点或别名名称。
    - `yaml_parser_scan_tag`: 扫描 `!` 符号后面的标签值，包括短格式和长格式。
    - `yaml_parser_scan_tag_handle` 和 `yaml_parser_scan_tag_uri` 是扫描标签值时用到的辅助函数，分别用于扫描标签的句柄和 URI 部分。
    - `yaml_parser_scan_uri_escapes` 用于解码标签 URI 中的转义字符。

12. **扫描不同风格标量的具体内容：**
    - `yaml_parser_scan_block_scalar`: 扫描 block 风格标量的具体内容，包括处理缩进、换行和尾部裁剪指示符。
    - `yaml_parser_scan_block_scalar_breaks`:  辅助函数，用于扫描 block 标量中的缩进空格和换行符，并确定缩进级别。
    - `yaml_parser_scan_flow_scalar`: 扫描 flow 风格标量的具体内容，包括处理转义字符。

总而言之，这段代码是 YAML 解析器中至关重要的词法分析部分，它将原始的字符流转换成一系列具有语义意义的 token，为后续的语法分析（parsing）阶段提供基础。它负责识别 YAML 语法中的各种关键符号和结构，并将其封装成结构化的 token 数据。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/scannerc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
 FLOW-SEQUENCE-END or FLOW-MAPPING-END token.
func yaml_parser_fetch_flow_collection_end(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	// Reset any potential simple key on the current flow level.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	// Decrease the flow level.
	if !yaml_parser_decrease_flow_level(parser) {
		return false
	}

	// No simple keys after the indicators ']' and '}'.
	parser.simple_key_allowed = false

	// Consume the token.

	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	// Create the FLOW-SEQUENCE-END of FLOW-MAPPING-END token.
	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	// Append the token to the queue.
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the FLOW-ENTRY token.
func yaml_parser_fetch_flow_entry(parser *yaml_parser_t) bool {
	// Reset any potential simple keys on the current flow level.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	// Simple keys are allowed after ','.
	parser.simple_key_allowed = true

	// Consume the token.
	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	// Create the FLOW-ENTRY token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_FLOW_ENTRY_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the BLOCK-ENTRY token.
func yaml_parser_fetch_block_entry(parser *yaml_parser_t) bool {
	// Check if the scanner is in the block context.
	if parser.flow_level == 0 {
		// Check if we are allowed to start a new entry.
		if !parser.simple_key_allowed {
			return yaml_parser_set_scanner_error(parser, "", parser.mark,
				"block sequence entries are not allowed in this context")
		}
		// Add the BLOCK-SEQUENCE-START token if needed.
		if !yaml_parser_roll_indent(parser, parser.mark.column, -1, yaml_BLOCK_SEQUENCE_START_TOKEN, parser.mark) {
			return false
		}
	} else {
		// It is an error for the '-' indicator to occur in the flow context,
		// but we let the Parser detect and report about it because the Parser
		// is able to point to the context.
	}

	// Reset any potential simple keys on the current flow level.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	// Simple keys are allowed after '-'.
	parser.simple_key_allowed = true

	// Consume the token.
	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	// Create the BLOCK-ENTRY token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_BLOCK_ENTRY_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the KEY token.
func yaml_parser_fetch_key(parser *yaml_parser_t) bool {

	// In the block context, additional checks are required.
	if parser.flow_level == 0 {
		// Check if we are allowed to start a new key (not nessesary simple).
		if !parser.simple_key_allowed {
			return yaml_parser_set_scanner_error(parser, "", parser.mark,
				"mapping keys are not allowed in this context")
		}
		// Add the BLOCK-MAPPING-START token if needed.
		if !yaml_parser_roll_indent(parser, parser.mark.column, -1, yaml_BLOCK_MAPPING_START_TOKEN, parser.mark) {
			return false
		}
	}

	// Reset any potential simple keys on the current flow level.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	// Simple keys are allowed after '?' in the block context.
	parser.simple_key_allowed = parser.flow_level == 0

	// Consume the token.
	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	// Create the KEY token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_KEY_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the VALUE token.
func yaml_parser_fetch_value(parser *yaml_parser_t) bool {

	simple_key := &parser.simple_keys[len(parser.simple_keys)-1]

	// Have we found a simple key?
	if simple_key.possible {
		// Create the KEY token and insert it into the queue.
		token := yaml_token_t{
			typ:        yaml_KEY_TOKEN,
			start_mark: simple_key.mark,
			end_mark:   simple_key.mark,
		}
		yaml_insert_token(parser, simple_key.token_number-parser.tokens_parsed, &token)

		// In the block context, we may need to add the BLOCK-MAPPING-START token.
		if !yaml_parser_roll_indent(parser, simple_key.mark.column,
			simple_key.token_number,
			yaml_BLOCK_MAPPING_START_TOKEN, simple_key.mark) {
			return false
		}

		// Remove the simple key.
		simple_key.possible = false

		// A simple key cannot follow another simple key.
		parser.simple_key_allowed = false

	} else {
		// The ':' indicator follows a complex key.

		// In the block context, extra checks are required.
		if parser.flow_level == 0 {

			// Check if we are allowed to start a complex value.
			if !parser.simple_key_allowed {
				return yaml_parser_set_scanner_error(parser, "", parser.mark,
					"mapping values are not allowed in this context")
			}

			// Add the BLOCK-MAPPING-START token if needed.
			if !yaml_parser_roll_indent(parser, parser.mark.column, -1, yaml_BLOCK_MAPPING_START_TOKEN, parser.mark) {
				return false
			}
		}

		// Simple keys after ':' are allowed in the block context.
		parser.simple_key_allowed = parser.flow_level == 0
	}

	// Consume the token.
	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	// Create the VALUE token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_VALUE_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the ALIAS or ANCHOR token.
func yaml_parser_fetch_anchor(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	// An anchor or an alias could be a simple key.
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	// A simple key cannot follow an anchor or an alias.
	parser.simple_key_allowed = false

	// Create the ALIAS or ANCHOR token and append it to the queue.
	var token yaml_token_t
	if !yaml_parser_scan_anchor(parser, &token, typ) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the TAG token.
func yaml_parser_fetch_tag(parser *yaml_parser_t) bool {
	// A tag could be a simple key.
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	// A simple key cannot follow a tag.
	parser.simple_key_allowed = false

	// Create the TAG token and append it to the queue.
	var token yaml_token_t
	if !yaml_parser_scan_tag(parser, &token) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the SCALAR(...,literal) or SCALAR(...,folded) tokens.
func yaml_parser_fetch_block_scalar(parser *yaml_parser_t, literal bool) bool {
	// Remove any potential simple keys.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	// A simple key may follow a block scalar.
	parser.simple_key_allowed = true

	// Create the SCALAR token and append it to the queue.
	var token yaml_token_t
	if !yaml_parser_scan_block_scalar(parser, &token, literal) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the SCALAR(...,single-quoted) or SCALAR(...,double-quoted) tokens.
func yaml_parser_fetch_flow_scalar(parser *yaml_parser_t, single bool) bool {
	// A plain scalar could be a simple key.
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	// A simple key cannot follow a flow scalar.
	parser.simple_key_allowed = false

	// Create the SCALAR token and append it to the queue.
	var token yaml_token_t
	if !yaml_parser_scan_flow_scalar(parser, &token, single) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the SCALAR(...,plain) token.
func yaml_parser_fetch_plain_scalar(parser *yaml_parser_t) bool {
	// A plain scalar could be a simple key.
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	// A simple key cannot follow a flow scalar.
	parser.simple_key_allowed = false

	// Create the SCALAR token and append it to the queue.
	var token yaml_token_t
	if !yaml_parser_scan_plain_scalar(parser, &token) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Eat whitespaces and comments until the next token is found.
func yaml_parser_scan_to_next_token(parser *yaml_parser_t) bool {

	// Until the next token is not found.
	for {
		// Allow the BOM mark to start a line.
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		if parser.mark.column == 0 && is_bom(parser.buffer, parser.buffer_pos) {
			skip(parser)
		}

		// Eat whitespaces.
		// Tabs are allowed:
		//  - in the flow context
		//  - in the block context, but not at the beginning of the line or
		//  after '-', '?', or ':' (complex value).
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}

		for parser.buffer[parser.buffer_pos] == ' ' || ((parser.flow_level > 0 || !parser.simple_key_allowed) && parser.buffer[parser.buffer_pos] == '\t') {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		// Eat a comment until a line break.
		if parser.buffer[parser.buffer_pos] == '#' {
			for !is_breakz(parser.buffer, parser.buffer_pos) {
				skip(parser)
				if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
					return false
				}
			}
		}

		// If it is a line break, eat it.
		if is_break(parser.buffer, parser.buffer_pos) {
			if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
				return false
			}
			skip_line(parser)

			// In the block context, a new line may start a simple key.
			if parser.flow_level == 0 {
				parser.simple_key_allowed = true
			}
		} else {
			break // We have found a token.
		}
	}

	return true
}

// Scan a YAML-DIRECTIVE or TAG-DIRECTIVE token.
//
// Scope:
//      %YAML    1.1    # a comment \n
//      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//      %TAG    !yaml!  tag:yaml.org,2002:  \n
//      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//
func yaml_parser_scan_directive(parser *yaml_parser_t, token *yaml_token_t) bool {
	// Eat '%'.
	start_mark := parser.mark
	skip(parser)

	// Scan the directive name.
	var name []byte
	if !yaml_parser_scan_directive_name(parser, start_mark, &name) {
		return false
	}

	// Is it a YAML directive?
	if bytes.Equal(name, []byte("YAML")) {
		// Scan the VERSION directive value.
		var major, minor int8
		if !yaml_parser_scan_version_directive_value(parser, start_mark, &major, &minor) {
			return false
		}
		end_mark := parser.mark

		// Create a VERSION-DIRECTIVE token.
		*token = yaml_token_t{
			typ:        yaml_VERSION_DIRECTIVE_TOKEN,
			start_mark: start_mark,
			end_mark:   end_mark,
			major:      major,
			minor:      minor,
		}

		// Is it a TAG directive?
	} else if bytes.Equal(name, []byte("TAG")) {
		// Scan the TAG directive value.
		var handle, prefix []byte
		if !yaml_parser_scan_tag_directive_value(parser, start_mark, &handle, &prefix) {
			return false
		}
		end_mark := parser.mark

		// Create a TAG-DIRECTIVE token.
		*token = yaml_token_t{
			typ:        yaml_TAG_DIRECTIVE_TOKEN,
			start_mark: start_mark,
			end_mark:   end_mark,
			value:      handle,
			prefix:     prefix,
		}

		// Unknown directive.
	} else {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "found unknown directive name")
		return false
	}

	// Eat the rest of the line including any comments.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if parser.buffer[parser.buffer_pos] == '#' {
		for !is_breakz(parser.buffer, parser.buffer_pos) {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}
	}

	// Check if we are at the end of the line.
	if !is_breakz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "did not find expected comment or line break")
		return false
	}

	// Eat a line break.
	if is_break(parser.buffer, parser.buffer_pos) {
		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}
		skip_line(parser)
	}

	return true
}

// Scan the directive name.
//
// Scope:
//      %YAML   1.1     # a comment \n
//       ^^^^
//      %TAG    !yaml!  tag:yaml.org,2002:  \n
//       ^^^
//
func yaml_parser_scan_directive_name(parser *yaml_parser_t, start_mark yaml_mark_t, name *[]byte) bool {
	// Consume the directive name.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	var s []byte
	for is_alpha(parser.buffer, parser.buffer_pos) {
		s = read(parser, s)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	// Check if the name is empty.
	if len(s) == 0 {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "could not find expected directive name")
		return false
	}

	// Check for an blank character after the name.
	if !is_blankz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "found unexpected non-alphabetical character")
		return false
	}
	*name = s
	return true
}

// Scan the value of VERSION-DIRECTIVE.
//
// Scope:
//      %YAML   1.1     # a comment \n
//           ^^^^^^
func yaml_parser_scan_version_directive_value(parser *yaml_parser_t, start_mark yaml_mark_t, major, minor *int8) bool {
	// Eat whitespaces.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	// Consume the major version number.
	if !yaml_parser_scan_version_directive_number(parser, start_mark, major) {
		return false
	}

	// Eat '.'.
	if parser.buffer[parser.buffer_pos] != '.' {
		return yaml_parser_set_scanner_error(parser, "while scanning a %YAML directive",
			start_mark, "did not find expected digit or '.' character")
	}

	skip(parser)

	// Consume the minor version number.
	if !yaml_parser_scan_version_directive_number(parser, start_mark, minor) {
		return false
	}
	return true
}

const max_number_length = 2

// Scan the version number of VERSION-DIRECTIVE.
//
// Scope:
//      %YAML   1.1     # a comment \n
//              ^
//      %YAML   1.1     # a comment \n
//                ^
func yaml_parser_scan_version_directive_number(parser *yaml_parser_t, start_mark yaml_mark_t, number *int8) bool {

	// Repeat while the next character is digit.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	var value, length int8
	for is_digit(parser.buffer, parser.buffer_pos) {
		// Check if the number is too long.
		length++
		if length > max_number_length {
			return yaml_parser_set_scanner_error(parser, "while scanning a %YAML directive",
				start_mark, "found extremely long version number")
		}
		value = value*10 + int8(as_digit(parser.buffer, parser.buffer_pos))
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	// Check if the number was present.
	if length == 0 {
		return yaml_parser_set_scanner_error(parser, "while scanning a %YAML directive",
			start_mark, "did not find expected version number")
	}
	*number = value
	return true
}

// Scan the value of a TAG-DIRECTIVE token.
//
// Scope:
//      %TAG    !yaml!  tag:yaml.org,2002:  \n
//          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//
func yaml_parser_scan_tag_directive_value(parser *yaml_parser_t, start_mark yaml_mark_t, handle, prefix *[]byte) bool {
	var handle_value, prefix_value []byte

	// Eat whitespaces.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	// Scan a handle.
	if !yaml_parser_scan_tag_handle(parser, true, start_mark, &handle_value) {
		return false
	}

	// Expect a whitespace.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if !is_blank(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a %TAG directive",
			start_mark, "did not find expected whitespace")
		return false
	}

	// Eat whitespaces.
	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	// Scan a prefix.
	if !yaml_parser_scan_tag_uri(parser, true, nil, start_mark, &prefix_value) {
		return false
	}

	// Expect a whitespace or line break.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if !is_blankz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a %TAG directive",
			start_mark, "did not find expected whitespace or line break")
		return false
	}

	*handle = handle_value
	*prefix = prefix_value
	return true
}

func yaml_parser_scan_anchor(parser *yaml_parser_t, token *yaml_token_t, typ yaml_token_type_t) bool {
	var s []byte

	// Eat the indicator character.
	start_mark := parser.mark
	skip(parser)

	// Consume the value.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	for is_alpha(parser.buffer, parser.buffer_pos) {
		s = read(parser, s)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	end_mark := parser.mark

	/*
	 * Check if length of the anchor is greater than 0 and it is followed by
	 * a whitespace character or one of the indicators:
	 *
	 *      '?', ':', ',', ']', '}', '%', '@', '`'.
	 */

	if len(s) == 0 ||
		!(is_blankz(parser.buffer, parser.buffer_pos) || parser.buffer[parser.buffer_pos] == '?' ||
			parser.buffer[parser.buffer_pos] == ':' || parser.buffer[parser.buffer_pos] == ',' ||
			parser.buffer[parser.buffer_pos] == ']' || parser.buffer[parser.buffer_pos] == '}' ||
			parser.buffer[parser.buffer_pos] == '%' || parser.buffer[parser.buffer_pos] == '@' ||
			parser.buffer[parser.buffer_pos] == '`') {
		context := "while scanning an alias"
		if typ == yaml_ANCHOR_TOKEN {
			context = "while scanning an anchor"
		}
		yaml_parser_set_scanner_error(parser, context, start_mark,
			"did not find expected alphabetic or numeric character")
		return false
	}

	// Create a token.
	*token = yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
	}

	return true
}

/*
 * Scan a TAG token.
 */

func yaml_parser_scan_tag(parser *yaml_parser_t, token *yaml_token_t) bool {
	var handle, suffix []byte

	start_mark := parser.mark

	// Check if the tag is in the canonical form.
	if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
		return false
	}

	if parser.buffer[parser.buffer_pos+1] == '<' {
		// Keep the handle as ''

		// Eat '!<'
		skip(parser)
		skip(parser)

		// Consume the tag value.
		if !yaml_parser_scan_tag_uri(parser, false, nil, start_mark, &suffix) {
			return false
		}

		// Check for '>' and eat it.
		if parser.buffer[parser.buffer_pos] != '>' {
			yaml_parser_set_scanner_error(parser, "while scanning a tag",
				start_mark, "did not find the expected '>'")
			return false
		}

		skip(parser)
	} else {
		// The tag has either the '!suffix' or the '!handle!suffix' form.

		// First, try to scan a handle.
		if !yaml_parser_scan_tag_handle(parser, false, start_mark, &handle) {
			return false
		}

		// Check if it is, indeed, handle.
		if handle[0] == '!' && len(handle) > 1 && handle[len(handle)-1] == '!' {
			// Scan the suffix now.
			if !yaml_parser_scan_tag_uri(parser, false, nil, start_mark, &suffix) {
				return false
			}
		} else {
			// It wasn't a handle after all.  Scan the rest of the tag.
			if !yaml_parser_scan_tag_uri(parser, false, handle, start_mark, &suffix) {
				return false
			}

			// Set the handle to '!'.
			handle = []byte{'!'}

			// A special case: the '!' tag.  Set the handle to '' and the
			// suffix to '!'.
			if len(suffix) == 0 {
				handle, suffix = suffix, handle
			}
		}
	}

	// Check the character which ends the tag.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if !is_blankz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a tag",
			start_mark, "did not find expected whitespace or line break")
		return false
	}

	end_mark := parser.mark

	// Create a token.
	*token = yaml_token_t{
		typ:        yaml_TAG_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      handle,
		suffix:     suffix,
	}
	return true
}

// Scan a tag handle.
func yaml_parser_scan_tag_handle(parser *yaml_parser_t, directive bool, start_mark yaml_mark_t, handle *[]byte) bool {
	// Check the initial '!' character.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if parser.buffer[parser.buffer_pos] != '!' {
		yaml_parser_set_scanner_tag_error(parser, directive,
			start_mark, "did not find expected '!'")
		return false
	}

	var s []byte

	// Copy the '!' character.
	s = read(parser, s)

	// Copy all subsequent alphabetical and numerical characters.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	for is_alpha(parser.buffer, parser.buffer_pos) {
		s = read(parser, s)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	// Check if the trailing character is '!' and copy it.
	if parser.buffer[parser.buffer_pos] == '!' {
		s = read(parser, s)
	} else {
		// It's either the '!' tag or not really a tag handle.  If it's a %TAG
		// directive, it's an error.  If it's a tag token, it must be a part of URI.
		if directive && string(s) != "!" {
			yaml_parser_set_scanner_tag_error(parser, directive,
				start_mark, "did not find expected '!'")
			return false
		}
	}

	*handle = s
	return true
}

// Scan a tag.
func yaml_parser_scan_tag_uri(parser *yaml_parser_t, directive bool, head []byte, start_mark yaml_mark_t, uri *[]byte) bool {
	//size_t length = head ? strlen((char *)head) : 0
	var s []byte
	hasTag := len(head) > 0

	// Copy the head if needed.
	//
	// Note that we don't copy the leading '!' character.
	if len(head) > 1 {
		s = append(s, head[1:]...)
	}

	// Scan the tag.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	// The set of characters that may appear in URI is as follows:
	//
	//      '0'-'9', 'A'-'Z', 'a'-'z', '_', '-', ';', '/', '?', ':', '@', '&',
	//      '=', '+', '$', ',', '.', '!', '~', '*', '\'', '(', ')', '[', ']',
	//      '%'.
	// [Go] Convert this into more reasonable logic.
	for is_alpha(parser.buffer, parser.buffer_pos) || parser.buffer[parser.buffer_pos] == ';' ||
		parser.buffer[parser.buffer_pos] == '/' || parser.buffer[parser.buffer_pos] == '?' ||
		parser.buffer[parser.buffer_pos] == ':' || parser.buffer[parser.buffer_pos] == '@' ||
		parser.buffer[parser.buffer_pos] == '&' || parser.buffer[parser.buffer_pos] == '=' ||
		parser.buffer[parser.buffer_pos] == '+' || parser.buffer[parser.buffer_pos] == '$' ||
		parser.buffer[parser.buffer_pos] == ',' || parser.buffer[parser.buffer_pos] == '.' ||
		parser.buffer[parser.buffer_pos] == '!' || parser.buffer[parser.buffer_pos] == '~' ||
		parser.buffer[parser.buffer_pos] == '*' || parser.buffer[parser.buffer_pos] == '\'' ||
		parser.buffer[parser.buffer_pos] == '(' || parser.buffer[parser.buffer_pos] == ')' ||
		parser.buffer[parser.buffer_pos] == '[' || parser.buffer[parser.buffer_pos] == ']' ||
		parser.buffer[parser.buffer_pos] == '%' {
		// Check if it is a URI-escape sequence.
		if parser.buffer[parser.buffer_pos] == '%' {
			if !yaml_parser_scan_uri_escapes(parser, directive, start_mark, &s) {
				return false
			}
		} else {
			s = read(parser, s)
		}
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		hasTag = true
	}

	if !hasTag {
		yaml_parser_set_scanner_tag_error(parser, directive,
			start_mark, "did not find expected tag URI")
		return false
	}
	*uri = s
	return true
}

// Decode an URI-escape sequence corresponding to a single UTF-8 character.
func yaml_parser_scan_uri_escapes(parser *yaml_parser_t, directive bool, start_mark yaml_mark_t, s *[]byte) bool {

	// Decode the required number of characters.
	w := 1024
	for w > 0 {
		// Check for a URI-escaped octet.
		if parser.unread < 3 && !yaml_parser_update_buffer(parser, 3) {
			return false
		}

		if !(parser.buffer[parser.buffer_pos] == '%' &&
			is_hex(parser.buffer, parser.buffer_pos+1) &&
			is_hex(parser.buffer, parser.buffer_pos+2)) {
			return yaml_parser_set_scanner_tag_error(parser, directive,
				start_mark, "did not find URI escaped octet")
		}

		// Get the octet.
		octet := byte((as_hex(parser.buffer, parser.buffer_pos+1) << 4) + as_hex(parser.buffer, parser.buffer_pos+2))

		// If it is the leading octet, determine the length of the UTF-8 sequence.
		if w == 1024 {
			w = width(octet)
			if w == 0 {
				return yaml_parser_set_scanner_tag_error(parser, directive,
					start_mark, "found an incorrect leading UTF-8 octet")
			}
		} else {
			// Check if the trailing octet is correct.
			if octet&0xC0 != 0x80 {
				return yaml_parser_set_scanner_tag_error(parser, directive,
					start_mark, "found an incorrect trailing UTF-8 octet")
			}
		}

		// Copy the octet and move the pointers.
		*s = append(*s, octet)
		skip(parser)
		skip(parser)
		skip(parser)
		w--
	}
	return true
}

// Scan a block scalar.
func yaml_parser_scan_block_scalar(parser *yaml_parser_t, token *yaml_token_t, literal bool) bool {
	// Eat the indicator '|' or '>'.
	start_mark := parser.mark
	skip(parser)

	// Scan the additional block scalar indicators.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	// Check for a chomping indicator.
	var chomping, increment int
	if parser.buffer[parser.buffer_pos] == '+' || parser.buffer[parser.buffer_pos] == '-' {
		// Set the chomping method and eat the indicator.
		if parser.buffer[parser.buffer_pos] == '+' {
			chomping = +1
		} else {
			chomping = -1
		}
		skip(parser)

		// Check for an indentation indicator.
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		if is_digit(parser.buffer, parser.buffer_pos) {
			// Check that the indentation is greater than 0.
			if parser.buffer[parser.buffer_pos] == '0' {
				yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
					start_mark, "found an indentation indicator equal to 0")
				return false
			}

			// Get the indentation level and eat the indicator.
			increment = as_digit(parser.buffer, parser.buffer_pos)
			skip(parser)
		}

	} else if is_digit(parser.buffer, parser.buffer_pos) {
		// Do the same as above, but in the opposite order.

		if parser.buffer[parser.buffer_pos] == '0' {
			yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
				start_mark, "found an indentation indicator equal to 0")
			return false
		}
		increment = as_digit(parser.buffer, parser.buffer_pos)
		skip(parser)

		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		if parser.buffer[parser.buffer_pos] == '+' || parser.buffer[parser.buffer_pos] == '-' {
			if parser.buffer[parser.buffer_pos] == '+' {
				chomping = +1
			} else {
				chomping = -1
			}
			skip(parser)
		}
	}

	// Eat whitespaces and comments to the end of the line.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}
	if parser.buffer[parser.buffer_pos] == '#' {
		for !is_breakz(parser.buffer, parser.buffer_pos) {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}
	}

	// Check if we are at the end of the line.
	if !is_breakz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
			start_mark, "did not find expected comment or line break")
		return false
	}

	// Eat a line break.
	if is_break(parser.buffer, parser.buffer_pos) {
		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}
		skip_line(parser)
	}

	end_mark := parser.mark

	// Set the indentation level if it was specified.
	var indent int
	if increment > 0 {
		if parser.indent >= 0 {
			indent = parser.indent + increment
		} else {
			indent = increment
		}
	}

	// Scan the leading line breaks and determine the indentation level if needed.
	var s, leading_break, trailing_breaks []byte
	if !yaml_parser_scan_block_scalar_breaks(parser, &indent, &trailing_breaks, start_mark, &end_mark) {
		return false
	}

	// Scan the block scalar content.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	var leading_blank, trailing_blank bool
	for parser.mark.column == indent && !is_z(parser.buffer, parser.buffer_pos) {
		// We are at the beginning of a non-empty line.

		// Is it a trailing whitespace?
		trailing_blank = is_blank(parser.buffer, parser.buffer_pos)

		// Check if we need to fold the leading line break.
		if !literal && !leading_blank && !trailing_blank && len(leading_break) > 0 && leading_break[0] == '\n' {
			// Do we need to join the lines by space?
			if len(trailing_breaks) == 0 {
				s = append(s, ' ')
			}
		} else {
			s = append(s, leading_break...)
		}
		leading_break = leading_break[:0]

		// Append the remaining line breaks.
		s = append(s, trailing_breaks...)
		trailing_breaks = trailing_breaks[:0]

		// Is it a leading whitespace?
		leading_blank = is_blank(parser.buffer, parser.buffer_pos)

		// Consume the current line.
		for !is_breakz(parser.buffer, parser.buffer_pos) {
			s = read(parser, s)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		// Consume the line break.
		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}

		leading_break = read_line(parser, leading_break)

		// Eat the following indentation spaces and line breaks.
		if !yaml_parser_scan_block_scalar_breaks(parser, &indent, &trailing_breaks, start_mark, &end_mark) {
			return false
		}
	}

	// Chomp the tail.
	if chomping != -1 {
		s = append(s, leading_break...)
	}
	if chomping == 1 {
		s = append(s, trailing_breaks...)
	}

	// Create a token.
	*token = yaml_token_t{
		typ:        yaml_SCALAR_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
		style:      yaml_LITERAL_SCALAR_STYLE,
	}
	if !literal {
		token.style = yaml_FOLDED_SCALAR_STYLE
	}
	return true
}

// Scan indentation spaces and line breaks for a block scalar.  Determine the
// indentation level if needed.
func yaml_parser_scan_block_scalar_breaks(parser *yaml_parser_t, indent *int, breaks *[]byte, start_mark yaml_mark_t, end_mark *yaml_mark_t) bool {
	*end_mark = parser.mark

	// Eat the indentation spaces and line breaks.
	max_indent := 0
	for {
		// Eat the indentation spaces.
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		for (*indent == 0 || parser.mark.column < *indent) && is_space(parser.buffer, parser.buffer_pos) {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}
		if parser.mark.column > max_indent {
			max_indent = parser.mark.column
		}

		// Check for a tab character messing the indentation.
		if (*indent == 0 || parser.mark.column < *indent) && is_tab(parser.buffer, parser.buffer_pos) {
			return yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
				start_mark, "found a tab character where an indentation space is expected")
		}

		// Have we found a non-empty line?
		if !is_break(parser.buffer, parser.buffer_pos) {
			break
		}

		// Consume the line break.
		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}
		// [Go] Should really be returning breaks instead.
		*breaks = read_line(parser, *breaks)
		*end_mark = parser.mark
	}

	// Determine the indentation level if needed.
	if *indent == 0 {
		*indent = max_indent
		if *indent < parser.indent+1 {
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
	start_mark :=
"""




```