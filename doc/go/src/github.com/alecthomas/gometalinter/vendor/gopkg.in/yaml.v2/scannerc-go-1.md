Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of a YAML parser's scanner component. The scanner's main job is to break down the raw YAML input into a stream of tokens. The functions in this part seem responsible for recognizing and creating specific YAML tokens.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The code resides within `scannerc.go` and contains functions prefixed with `yaml_parser_fetch_`. This strongly suggests these functions are responsible for *fetching* or creating YAML tokens.

2. **Analyze Individual Functions:** Go through each function and identify the type of token it's responsible for creating, based on the function name and the `yaml_token_type_t` it uses:
    * `yaml_parser_fetch_flow_collection_start`: `yaml_FLOW_SEQUENCE_START_TOKEN` or `yaml_FLOW_MAPPING_START_TOKEN`
    * `yaml_parser_fetch_flow_collection_end`: `yaml_FLOW_SEQUENCE_END_TOKEN` or `yaml_FLOW_MAPPING_END_TOKEN`
    * `yaml_parser_fetch_flow_entry`: `yaml_FLOW_ENTRY_TOKEN`
    * `yaml_parser_fetch_block_entry`: `yaml_BLOCK_ENTRY_TOKEN`
    * `yaml_parser_fetch_key`: `yaml_KEY_TOKEN`
    * `yaml_parser_fetch_value`: `yaml_VALUE_TOKEN`
    * `yaml_parser_fetch_anchor`: `yaml_ALIAS_TOKEN` or `yaml_ANCHOR_TOKEN`
    * `yaml_parser_fetch_tag`: `yaml_TAG_TOKEN`
    * `yaml_parser_fetch_block_scalar`: `yaml_SCALAR_TOKEN` (literal or folded)
    * `yaml_parser_fetch_flow_scalar`: `yaml_SCALAR_TOKEN` (single or double quoted)
    * `yaml_parser_fetch_plain_scalar`: `yaml_SCALAR_TOKEN` (plain)

3. **Identify Common Patterns:** Notice the pattern of:
    * Checking context (flow level, simple key allowed).
    * Calling `yaml_parser_remove_simple_key` or `yaml_parser_save_simple_key`.
    * Consuming the relevant indicator (e.g., `[`, `{`, `-`, `?`, `:`).
    * Creating a `yaml_token_t` struct.
    * Appending the token to the parser's token queue using `yaml_insert_token`.

4. **Group Functions by Functionality:**  The functions naturally group based on the type of YAML structure they handle:
    * Flow collections (sequences and mappings)
    * Block sequences
    * Mapping keys and values
    * Anchors and aliases
    * Tags
    * Different types of scalars (block, flow, plain)

5. **Synthesize a High-Level Summary:** Combine the observations into a concise description of the code's purpose. Emphasize that it's part of the YAML scanning process and focuses on creating different token types.

6. **Review and Refine:** Ensure the summary is accurate and covers the main responsibilities of the code. The summary should highlight that the code handles different YAML constructs (sequences, mappings, scalars, etc.) and manages the state of the parser (e.g., `simple_key_allowed`, `flow_level`).
这段代码是 Go 语言实现的 YAML 解析器的一部分，具体来说是扫描器（scanner）组件的一部分。它包含了一系列用于识别 YAML 语法元素并生成对应 token 的函数。

**功能归纳:**

这段代码的主要功能是**识别和生成代表 YAML 结构和内容的各种类型的 token**。这些 token 是 YAML 解析过程中的中间表示，会被后续的解析器组件使用。

具体来说，这些函数负责识别并生成以下类型的 token：

* **流式集合的开始和结束:**  `yaml_FLOW_SEQUENCE_START_TOKEN`, `yaml_FLOW_MAPPING_START_TOKEN`, `yaml_FLOW_SEQUENCE_END_TOKEN`, `yaml_FLOW_MAPPING_END_TOKEN`，用于表示流式数组 `[]` 和流式对象 `{}` 的开始和结束。
* **流式集合的条目分隔符:** `yaml_FLOW_ENTRY_TOKEN`，用于表示流式集合中的逗号 `,`。
* **块级集合的条目:** `yaml_BLOCK_ENTRY_TOKEN`，用于表示块级数组的 `-` 开头的条目。
* **键值对的键和值:** `yaml_KEY_TOKEN`, `yaml_VALUE_TOKEN`，分别用于表示键值对中的 `?` 或隐式键和 `:`。
* **锚点和别名:** `yaml_ALIAS_TOKEN`, `yaml_ANCHOR_TOKEN`，用于表示 YAML 中的锚点 `&` 和别名 `*`。
* **标签:** `yaml_TAG_TOKEN`，用于表示 YAML 中的标签 `!`。
* **标量:** `yaml_SCALAR_TOKEN`，用于表示 YAML 中的文本内容，包括不同风格的标量：
    * 块级标量 (literal `|` 和 folded `>`)
    * 流式标量 (单引号 `'` 和双引号 `"`)
    * 普通标量 (没有引号)

总而言之，这段代码是 YAML 扫描器的核心部分，负责将输入的 YAML 文本分解成有意义的语法单元（token），为后续的 YAML 解析过程提供基础。它根据当前解析上下文和读取到的字符，判断应该生成哪种类型的 token，并记录 token 的起始和结束位置。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/scannerc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
 FLOW-SEQUENCE-START of FLOW-MAPPING-START token.
	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	// Append the token to the queue.
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the FLOW-SEQUENCE-END or FLOW-MAPPING-END token.
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
		if directive && !(s[0] == '!' && s[1] == 0) {
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
	}

	// Check if the tag is non-empty.
	if len(s) == 0 {
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
		if *indent < parser.inden
"""




```