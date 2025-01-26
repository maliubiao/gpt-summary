Response:
The user wants a summary of the functionality of the provided Go code snippet, which is a part of a YAML scanner implementation.

Here's a breakdown of the thinking process to arrive at the summary:

1. **Identify the Core Purpose:** The code starts with a clear introduction explaining the separation of YAML processing into scanning and parsing. This snippet is specifically about the *scanning* phase. The key takeaway is transforming the input stream into a sequence of *tokens*.

2. **List the Tokens:** The code explicitly lists all the token types the scanner can produce. This is a central piece of information and needs to be included in the summary. Categorize them for better readability (stream, directives, document boundaries, scalars, flow collections, block collections).

3. **Explain the Scanning Process (High-Level):** The introduction mentions the "clever" aspects of scanning, particularly "block collection start" and "simple keys". Although the code doesn't implement these directly in this snippet, the concept is important for understanding the scanner's role. The code provided focuses on *identifying* tokens based on character sequences.

4. **Highlight Key Concepts:**
    * **Virtual Tokens:**  The `STREAM-START` and `STREAM-END` tokens are special and should be mentioned.
    * **Indentation:** The handling of indentation for block structures (`BLOCK-SEQUENCE-START`, `BLOCK-MAPPING-START`, `BLOCK-END`) is a crucial aspect of YAML and should be noted, even though the detailed logic isn't fully present in *this* snippet. The code mentions `yaml_parser_roll_indent` and `yaml_parser_unroll_indent`.
    * **Simple Keys:**  The concept of simple keys and the `KEY` token is explicitly mentioned and should be included.

5. **Focus on the Provided Code:**  The provided Go code contains helper functions like `cache`, `skip`, `read`, and `yaml_parser_scan`. These are lower-level utilities for managing the input buffer and extracting characters. The core logic for identifying and emitting tokens resides in functions like `yaml_parser_fetch_next_token` and the various `yaml_parser_fetch_*` functions (although not fully present in this snippet).

6. **Structure the Summary:** Organize the information logically. Start with the main purpose, then list the tokens, and then briefly discuss the underlying mechanics.

7. **Review and Refine:** Check for clarity and accuracy. Ensure the summary aligns with the information presented in the code comments.

Applying these steps leads to the following summary:

* **核心功能:** 将 YAML 输入流转换为一系列的 *token*（标记）。这是 YAML 处理的第一步，为后续的解析器提供结构化的输入。

* **主要任务:**  识别 YAML 语法中的各种元素，例如：
    * **流的开始和结束:**  `STREAM-START`, `STREAM-END`
    * **指令:**  `VERSION-DIRECTIVE`, `TAG-DIRECTIVE`
    * **文档的开始和结束:** `DOCUMENT-START`, `DOCUMENT-END`
    * **标量 (基本数据类型):** `SCALAR`
    * **别名和锚点:** `ALIAS`, `ANCHOR`
    * **标签:** `TAG`
    * **流动集合 (行内):** `FLOW-SEQUENCE-START`, `FLOW-SEQUENCE-END`, `FLOW-MAPPING-START`, `FLOW-MAPPING-END`, `FLOW-ENTRY`, `KEY`, `VALUE`
    * **块集合 (基于缩进):** `BLOCK-SEQUENCE-START`, `BLOCK-MAPPING-START`, `BLOCK-END`, `BLOCK-ENTRY`, `KEY`, `VALUE`

* **实现机制 (基于代码片段):**  代码片段中包含了一些辅助函数，用于：
    * **缓冲区管理:**  例如 `cache` 确保缓冲区有足够的字符，`skip` 用于移动缓冲区指针。
    * **字符读取:**  `read` 和 `read_line` 用于从缓冲区读取字符或行。
    * **获取下一个 token:** `yaml_parser_scan` 是获取下一个 token 的主要函数，它依赖于 `yaml_parser_fetch_more_tokens` 和 `yaml_parser_fetch_next_token`。
    * **错误处理:** `yaml_parser_set_scanner_error` 用于设置扫描过程中的错误。
    * **缩进处理:** `yaml_parser_roll_indent` 和 `yaml_parser_unroll_indent` 用于处理块结构中的缩进。
    * **简单键处理:**  `yaml_parser_stale_simple_keys`, `yaml_parser_save_simple_key`, `yaml_parser_remove_simple_key` 用于管理简单键。

* **关键概念:**
    * **Token 化:** 将连续的字符流分解成离散的、有意义的单元。
    * **缩进敏感:**  对于块结构，缩进的变化会产生 `BLOCK-SEQUENCE-START`, `BLOCK-MAPPING-START` 和 `BLOCK-END` 等 token。
    * **简单键:**  在某些情况下，键可以不使用 `?` 显式标记。scanner 需要识别这些情况。

This detailed thought process ensures that the summary is comprehensive, accurate, and addresses the key aspects of the provided code snippet and its role in the larger YAML processing context.
## 功能归纳：YAML 扫描器（Scanner）的实现 - 第 1 部分

这份代码是 Go 语言实现的 YAML 解析器的一部分，具体来说，它是 **扫描器（Scanner）** 的实现。扫描器的主要功能是将输入的 YAML 文本流转换为一系列的 **token（标记）**。

更具体地说，这份代码定义了扫描器能够识别和产生的各种 token 类型，并提供了一些辅助函数来管理输入缓冲区和生成这些 token。

**主要功能点可以归纳如下：**

1. **定义了 YAML 扫描器产生的各种 Token 类型:**  代码详细列出了扫描器能够识别出的所有 token 类型，例如 `STREAM-START`（流开始）、`STREAM-END`（流结束）、`VERSION-DIRECTIVE`（版本指令）、`TAG-DIRECTIVE`（标签指令）、`DOCUMENT-START`（文档开始）、`DOCUMENT-END`（文档结束）、各种标量类型 (`SCALAR`)、别名 (`ALIAS`)、锚点 (`ANCHOR`)、标签 (`TAG`) 以及用于表示集合的 token，如 `BLOCK-SEQUENCE-START`（块序列开始）、`BLOCK-MAPPING-START`（块映射开始）、`FLOW-SEQUENCE-START`（流动序列开始）、`FLOW-MAPPING-START`（流动映射开始）等等。

2. **描述了扫描过程和 Token 的含义:**  代码的注释部分详细解释了每个 token 的含义以及在 YAML 文档中的表示形式，并提供了示例来展示 YAML 文本如何被转换为对应的 token 序列。

3. **提供了一些底层的辅助函数来处理输入流:**  例如 `cache` 用于确保缓冲区有足够的字符，`skip` 用于移动缓冲区指针，`read` 用于读取字符，`read_line` 用于读取行等。这些函数是扫描器实现的基础。

4. **实现了 `yaml_parser_scan` 函数:**  这个函数是扫描器的主要入口点，用于从输入流中获取下一个 token。它依赖于更底层的 `yaml_parser_fetch_more_tokens` 和 `yaml_parser_fetch_next_token` 函数。

5. **实现了错误处理机制:**  `yaml_parser_set_scanner_error` 函数用于在扫描过程中发生错误时设置错误信息。

6. **初步涉及了缩进和简单键的处理:**  虽然这部分代码是第一部分，但已经可以看到与缩进处理相关的函数，如 `yaml_parser_roll_indent` 和 `yaml_parser_unroll_indent`，以及与简单键处理相关的函数，如 `yaml_parser_stale_simple_keys`，`yaml_parser_save_simple_key` 和 `yaml_parser_remove_simple_key`。这些是 YAML 语法中比较复杂的部分。

**简单来说，这份代码是 YAML 解析器中负责将原始文本分解成结构化标记的“词法分析器”。**

在接下来的部分，很可能会看到更多关于如何识别和生成各种 token 的具体实现逻辑，以及如何处理 YAML 语法中的复杂规则，例如缩进、简单键等。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/scannerc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
package yaml

import (
	"bytes"
	"fmt"
)

// Introduction
// ************
//
// The following notes assume that you are familiar with the YAML specification
// (http://yaml.org/spec/1.2/spec.html).  We mostly follow it, although in
// some cases we are less restrictive that it requires.
//
// The process of transforming a YAML stream into a sequence of events is
// divided on two steps: Scanning and Parsing.
//
// The Scanner transforms the input stream into a sequence of tokens, while the
// parser transform the sequence of tokens produced by the Scanner into a
// sequence of parsing events.
//
// The Scanner is rather clever and complicated. The Parser, on the contrary,
// is a straightforward implementation of a recursive-descendant parser (or,
// LL(1) parser, as it is usually called).
//
// Actually there are two issues of Scanning that might be called "clever", the
// rest is quite straightforward.  The issues are "block collection start" and
// "simple keys".  Both issues are explained below in details.
//
// Here the Scanning step is explained and implemented.  We start with the list
// of all the tokens produced by the Scanner together with short descriptions.
//
// Now, tokens:
//
//      STREAM-START(encoding)          # The stream start.
//      STREAM-END                      # The stream end.
//      VERSION-DIRECTIVE(major,minor)  # The '%YAML' directive.
//      TAG-DIRECTIVE(handle,prefix)    # The '%TAG' directive.
//      DOCUMENT-START                  # '---'
//      DOCUMENT-END                    # '...'
//      BLOCK-SEQUENCE-START            # Indentation increase denoting a block
//      BLOCK-MAPPING-START             # sequence or a block mapping.
//      BLOCK-END                       # Indentation decrease.
//      FLOW-SEQUENCE-START             # '['
//      FLOW-SEQUENCE-END               # ']'
//      BLOCK-SEQUENCE-START            # '{'
//      BLOCK-SEQUENCE-END              # '}'
//      BLOCK-ENTRY                     # '-'
//      FLOW-ENTRY                      # ','
//      KEY                             # '?' or nothing (simple keys).
//      VALUE                           # ':'
//      ALIAS(anchor)                   # '*anchor'
//      ANCHOR(anchor)                  # '&anchor'
//      TAG(handle,suffix)              # '!handle!suffix'
//      SCALAR(value,style)             # A scalar.
//
// The following two tokens are "virtual" tokens denoting the beginning and the
// end of the stream:
//
//      STREAM-START(encoding)
//      STREAM-END
//
// We pass the information about the input stream encoding with the
// STREAM-START token.
//
// The next two tokens are responsible for tags:
//
//      VERSION-DIRECTIVE(major,minor)
//      TAG-DIRECTIVE(handle,prefix)
//
// Example:
//
//      %YAML   1.1
//      %TAG    !   !foo
//      %TAG    !yaml!  tag:yaml.org,2002:
//      ---
//
// The correspoding sequence of tokens:
//
//      STREAM-START(utf-8)
//      VERSION-DIRECTIVE(1,1)
//      TAG-DIRECTIVE("!","!foo")
//      TAG-DIRECTIVE("!yaml","tag:yaml.org,2002:")
//      DOCUMENT-START
//      STREAM-END
//
// Note that the VERSION-DIRECTIVE and TAG-DIRECTIVE tokens occupy a whole
// line.
//
// The document start and end indicators are represented by:
//
//      DOCUMENT-START
//      DOCUMENT-END
//
// Note that if a YAML stream contains an implicit document (without '---'
// and '...' indicators), no DOCUMENT-START and DOCUMENT-END tokens will be
// produced.
//
// In the following examples, we present whole documents together with the
// produced tokens.
//
//      1. An implicit document:
//
//          'a scalar'
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          SCALAR("a scalar",single-quoted)
//          STREAM-END
//
//      2. An explicit document:
//
//          ---
//          'a scalar'
//          ...
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          DOCUMENT-START
//          SCALAR("a scalar",single-quoted)
//          DOCUMENT-END
//          STREAM-END
//
//      3. Several documents in a stream:
//
//          'a scalar'
//          ---
//          'another scalar'
//          ---
//          'yet another scalar'
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          SCALAR("a scalar",single-quoted)
//          DOCUMENT-START
//          SCALAR("another scalar",single-quoted)
//          DOCUMENT-START
//          SCALAR("yet another scalar",single-quoted)
//          STREAM-END
//
// We have already introduced the SCALAR token above.  The following tokens are
// used to describe aliases, anchors, tag, and scalars:
//
//      ALIAS(anchor)
//      ANCHOR(anchor)
//      TAG(handle,suffix)
//      SCALAR(value,style)
//
// The following series of examples illustrate the usage of these tokens:
//
//      1. A recursive sequence:
//
//          &A [ *A ]
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          ANCHOR("A")
//          FLOW-SEQUENCE-START
//          ALIAS("A")
//          FLOW-SEQUENCE-END
//          STREAM-END
//
//      2. A tagged scalar:
//
//          !!float "3.14"  # A good approximation.
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          TAG("!!","float")
//          SCALAR("3.14",double-quoted)
//          STREAM-END
//
//      3. Various scalar styles:
//
//          --- # Implicit empty plain scalars do not produce tokens.
//          --- a plain scalar
//          --- 'a single-quoted scalar'
//          --- "a double-quoted scalar"
//          --- |-
//            a literal scalar
//          --- >-
//            a folded
//            scalar
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          DOCUMENT-START
//          DOCUMENT-START
//          SCALAR("a plain scalar",plain)
//          DOCUMENT-START
//          SCALAR("a single-quoted scalar",single-quoted)
//          DOCUMENT-START
//          SCALAR("a double-quoted scalar",double-quoted)
//          DOCUMENT-START
//          SCALAR("a literal scalar",literal)
//          DOCUMENT-START
//          SCALAR("a folded scalar",folded)
//          STREAM-END
//
// Now it's time to review collection-related tokens. We will start with
// flow collections:
//
//      FLOW-SEQUENCE-START
//      FLOW-SEQUENCE-END
//      FLOW-MAPPING-START
//      FLOW-MAPPING-END
//      FLOW-ENTRY
//      KEY
//      VALUE
//
// The tokens FLOW-SEQUENCE-START, FLOW-SEQUENCE-END, FLOW-MAPPING-START, and
// FLOW-MAPPING-END represent the indicators '[', ']', '{', and '}'
// correspondingly.  FLOW-ENTRY represent the ',' indicator.  Finally the
// indicators '?' and ':', which are used for denoting mapping keys and values,
// are represented by the KEY and VALUE tokens.
//
// The following examples show flow collections:
//
//      1. A flow sequence:
//
//          [item 1, item 2, item 3]
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          FLOW-SEQUENCE-START
//          SCALAR("item 1",plain)
//          FLOW-ENTRY
//          SCALAR("item 2",plain)
//          FLOW-ENTRY
//          SCALAR("item 3",plain)
//          FLOW-SEQUENCE-END
//          STREAM-END
//
//      2. A flow mapping:
//
//          {
//              a simple key: a value,  # Note that the KEY token is produced.
//              ? a complex key: another value,
//          }
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          FLOW-MAPPING-START
//          KEY
//          SCALAR("a simple key",plain)
//          VALUE
//          SCALAR("a value",plain)
//          FLOW-ENTRY
//          KEY
//          SCALAR("a complex key",plain)
//          VALUE
//          SCALAR("another value",plain)
//          FLOW-ENTRY
//          FLOW-MAPPING-END
//          STREAM-END
//
// A simple key is a key which is not denoted by the '?' indicator.  Note that
// the Scanner still produce the KEY token whenever it encounters a simple key.
//
// For scanning block collections, the following tokens are used (note that we
// repeat KEY and VALUE here):
//
//      BLOCK-SEQUENCE-START
//      BLOCK-MAPPING-START
//      BLOCK-END
//      BLOCK-ENTRY
//      KEY
//      VALUE
//
// The tokens BLOCK-SEQUENCE-START and BLOCK-MAPPING-START denote indentation
// increase that precedes a block collection (cf. the INDENT token in Python).
// The token BLOCK-END denote indentation decrease that ends a block collection
// (cf. the DEDENT token in Python).  However YAML has some syntax pecularities
// that makes detections of these tokens more complex.
//
// The tokens BLOCK-ENTRY, KEY, and VALUE are used to represent the indicators
// '-', '?', and ':' correspondingly.
//
// The following examples show how the tokens BLOCK-SEQUENCE-START,
// BLOCK-MAPPING-START, and BLOCK-END are emitted by the Scanner:
//
//      1. Block sequences:
//
//          - item 1
//          - item 2
//          -
//            - item 3.1
//            - item 3.2
//          -
//            key 1: value 1
//            key 2: value 2
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-ENTRY
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 3.1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 3.2",plain)
//          BLOCK-END
//          BLOCK-ENTRY
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
//      2. Block mappings:
//
//          a simple key: a value   # The KEY token is produced here.
//          ? a complex key
//          : another value
//          a mapping:
//            key 1: value 1
//            key 2: value 2
//          a sequence:
//            - item 1
//            - item 2
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("a simple key",plain)
//          VALUE
//          SCALAR("a value",plain)
//          KEY
//          SCALAR("a complex key",plain)
//          VALUE
//          SCALAR("another value",plain)
//          KEY
//          SCALAR("a mapping",plain)
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          KEY
//          SCALAR("a sequence",plain)
//          VALUE
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
// YAML does not always require to start a new block collection from a new
// line.  If the current line contains only '-', '?', and ':' indicators, a new
// block collection may start at the current line.  The following examples
// illustrate this case:
//
//      1. Collections in a sequence:
//
//          - - item 1
//            - item 2
//          - key 1: value 1
//            key 2: value 2
//          - ? complex key
//            : complex value
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-END
//          BLOCK-ENTRY
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          BLOCK-ENTRY
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("complex key")
//          VALUE
//          SCALAR("complex value")
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
//      2. Collections in a mapping:
//
//          ? a sequence
//          : - item 1
//            - item 2
//          ? a mapping
//          : key 1: value 1
//            key 2: value 2
//
//      Tokens:
//
//          STREAM-START(utf-8)
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("a sequence",plain)
//          VALUE
//          BLOCK-SEQUENCE-START
//          BLOCK-ENTRY
//          SCALAR("item 1",plain)
//          BLOCK-ENTRY
//          SCALAR("item 2",plain)
//          BLOCK-END
//          KEY
//          SCALAR("a mapping",plain)
//          VALUE
//          BLOCK-MAPPING-START
//          KEY
//          SCALAR("key 1",plain)
//          VALUE
//          SCALAR("value 1",plain)
//          KEY
//          SCALAR("key 2",plain)
//          VALUE
//          SCALAR("value 2",plain)
//          BLOCK-END
//          BLOCK-END
//          STREAM-END
//
// YAML also permits non-indented sequences if they are included into a block
// mapping.  In this case, the token BLOCK-SEQUENCE-START is not produced:
//
//      key:
//      - item 1    # BLOCK-SEQUENCE-START is NOT produced here.
//      - item 2
//
// Tokens:
//
//      STREAM-START(utf-8)
//      BLOCK-MAPPING-START
//      KEY
//      SCALAR("key",plain)
//      VALUE
//      BLOCK-ENTRY
//      SCALAR("item 1",plain)
//      BLOCK-ENTRY
//      SCALAR("item 2",plain)
//      BLOCK-END
//

// Ensure that the buffer contains the required number of characters.
// Return true on success, false on failure (reader error or memory error).
func cache(parser *yaml_parser_t, length int) bool {
	// [Go] This was inlined: !cache(A, B) -> unread < B && !update(A, B)
	return parser.unread >= length || yaml_parser_update_buffer(parser, length)
}

// Advance the buffer pointer.
func skip(parser *yaml_parser_t) {
	parser.mark.index++
	parser.mark.column++
	parser.unread--
	parser.buffer_pos += width(parser.buffer[parser.buffer_pos])
}

func skip_line(parser *yaml_parser_t) {
	if is_crlf(parser.buffer, parser.buffer_pos) {
		parser.mark.index += 2
		parser.mark.column = 0
		parser.mark.line++
		parser.unread -= 2
		parser.buffer_pos += 2
	} else if is_break(parser.buffer, parser.buffer_pos) {
		parser.mark.index++
		parser.mark.column = 0
		parser.mark.line++
		parser.unread--
		parser.buffer_pos += width(parser.buffer[parser.buffer_pos])
	}
}

// Copy a character to a string buffer and advance pointers.
func read(parser *yaml_parser_t, s []byte) []byte {
	w := width(parser.buffer[parser.buffer_pos])
	if w == 0 {
		panic("invalid character sequence")
	}
	if len(s) == 0 {
		s = make([]byte, 0, 32)
	}
	if w == 1 && len(s)+w <= cap(s) {
		s = s[:len(s)+1]
		s[len(s)-1] = parser.buffer[parser.buffer_pos]
		parser.buffer_pos++
	} else {
		s = append(s, parser.buffer[parser.buffer_pos:parser.buffer_pos+w]...)
		parser.buffer_pos += w
	}
	parser.mark.index++
	parser.mark.column++
	parser.unread--
	return s
}

// Copy a line break character to a string buffer and advance pointers.
func read_line(parser *yaml_parser_t, s []byte) []byte {
	buf := parser.buffer
	pos := parser.buffer_pos
	switch {
	case buf[pos] == '\r' && buf[pos+1] == '\n':
		// CR LF . LF
		s = append(s, '\n')
		parser.buffer_pos += 2
		parser.mark.index++
		parser.unread--
	case buf[pos] == '\r' || buf[pos] == '\n':
		// CR|LF . LF
		s = append(s, '\n')
		parser.buffer_pos += 1
	case buf[pos] == '\xC2' && buf[pos+1] == '\x85':
		// NEL . LF
		s = append(s, '\n')
		parser.buffer_pos += 2
	case buf[pos] == '\xE2' && buf[pos+1] == '\x80' && (buf[pos+2] == '\xA8' || buf[pos+2] == '\xA9'):
		// LS|PS . LS|PS
		s = append(s, buf[parser.buffer_pos:pos+3]...)
		parser.buffer_pos += 3
	default:
		return s
	}
	parser.mark.index++
	parser.mark.column = 0
	parser.mark.line++
	parser.unread--
	return s
}

// Get the next token.
func yaml_parser_scan(parser *yaml_parser_t, token *yaml_token_t) bool {
	// Erase the token object.
	*token = yaml_token_t{} // [Go] Is this necessary?

	// No tokens after STREAM-END or error.
	if parser.stream_end_produced || parser.error != yaml_NO_ERROR {
		return true
	}

	// Ensure that the tokens queue contains enough tokens.
	if !parser.token_available {
		if !yaml_parser_fetch_more_tokens(parser) {
			return false
		}
	}

	// Fetch the next token from the queue.
	*token = parser.tokens[parser.tokens_head]
	parser.tokens_head++
	parser.tokens_parsed++
	parser.token_available = false

	if token.typ == yaml_STREAM_END_TOKEN {
		parser.stream_end_produced = true
	}
	return true
}

// Set the scanner error and return false.
func yaml_parser_set_scanner_error(parser *yaml_parser_t, context string, context_mark yaml_mark_t, problem string) bool {
	parser.error = yaml_SCANNER_ERROR
	parser.context = context
	parser.context_mark = context_mark
	parser.problem = problem
	parser.problem_mark = parser.mark
	return false
}

func yaml_parser_set_scanner_tag_error(parser *yaml_parser_t, directive bool, context_mark yaml_mark_t, problem string) bool {
	context := "while parsing a tag"
	if directive {
		context = "while parsing a %TAG directive"
	}
	return yaml_parser_set_scanner_error(parser, context, context_mark, "did not find URI escaped octet")
}

func trace(args ...interface{}) func() {
	pargs := append([]interface{}{"+++"}, args...)
	fmt.Println(pargs...)
	pargs = append([]interface{}{"---"}, args...)
	return func() { fmt.Println(pargs...) }
}

// Ensure that the tokens queue contains at least one token which can be
// returned to the Parser.
func yaml_parser_fetch_more_tokens(parser *yaml_parser_t) bool {
	// While we need more tokens to fetch, do it.
	for {
		// Check if we really need to fetch more tokens.
		need_more_tokens := false

		if parser.tokens_head == len(parser.tokens) {
			// Queue is empty.
			need_more_tokens = true
		} else {
			// Check if any potential simple key may occupy the head position.
			if !yaml_parser_stale_simple_keys(parser) {
				return false
			}

			for i := range parser.simple_keys {
				simple_key := &parser.simple_keys[i]
				if simple_key.possible && simple_key.token_number == parser.tokens_parsed {
					need_more_tokens = true
					break
				}
			}
		}

		// We are finished.
		if !need_more_tokens {
			break
		}
		// Fetch the next token.
		if !yaml_parser_fetch_next_token(parser) {
			return false
		}
	}

	parser.token_available = true
	return true
}

// The dispatcher for token fetchers.
func yaml_parser_fetch_next_token(parser *yaml_parser_t) bool {
	// Ensure that the buffer is initialized.
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	// Check if we just started scanning.  Fetch STREAM-START then.
	if !parser.stream_start_produced {
		return yaml_parser_fetch_stream_start(parser)
	}

	// Eat whitespaces and comments until we reach the next token.
	if !yaml_parser_scan_to_next_token(parser) {
		return false
	}

	// Remove obsolete potential simple keys.
	if !yaml_parser_stale_simple_keys(parser) {
		return false
	}

	// Check the indentation level against the current column.
	if !yaml_parser_unroll_indent(parser, parser.mark.column) {
		return false
	}

	// Ensure that the buffer contains at least 4 characters.  4 is the length
	// of the longest indicators ('--- ' and '... ').
	if parser.unread < 4 && !yaml_parser_update_buffer(parser, 4) {
		return false
	}

	// Is it the end of the stream?
	if is_z(parser.buffer, parser.buffer_pos) {
		return yaml_parser_fetch_stream_end(parser)
	}

	// Is it a directive?
	if parser.mark.column == 0 && parser.buffer[parser.buffer_pos] == '%' {
		return yaml_parser_fetch_directive(parser)
	}

	buf := parser.buffer
	pos := parser.buffer_pos

	// Is it the document start indicator?
	if parser.mark.column == 0 && buf[pos] == '-' && buf[pos+1] == '-' && buf[pos+2] == '-' && is_blankz(buf, pos+3) {
		return yaml_parser_fetch_document_indicator(parser, yaml_DOCUMENT_START_TOKEN)
	}

	// Is it the document end indicator?
	if parser.mark.column == 0 && buf[pos] == '.' && buf[pos+1] == '.' && buf[pos+2] == '.' && is_blankz(buf, pos+3) {
		return yaml_parser_fetch_document_indicator(parser, yaml_DOCUMENT_END_TOKEN)
	}

	// Is it the flow sequence start indicator?
	if buf[pos] == '[' {
		return yaml_parser_fetch_flow_collection_start(parser, yaml_FLOW_SEQUENCE_START_TOKEN)
	}

	// Is it the flow mapping start indicator?
	if parser.buffer[parser.buffer_pos] == '{' {
		return yaml_parser_fetch_flow_collection_start(parser, yaml_FLOW_MAPPING_START_TOKEN)
	}

	// Is it the flow sequence end indicator?
	if parser.buffer[parser.buffer_pos] == ']' {
		return yaml_parser_fetch_flow_collection_end(parser,
			yaml_FLOW_SEQUENCE_END_TOKEN)
	}

	// Is it the flow mapping end indicator?
	if parser.buffer[parser.buffer_pos] == '}' {
		return yaml_parser_fetch_flow_collection_end(parser,
			yaml_FLOW_MAPPING_END_TOKEN)
	}

	// Is it the flow entry indicator?
	if parser.buffer[parser.buffer_pos] == ',' {
		return yaml_parser_fetch_flow_entry(parser)
	}

	// Is it the block entry indicator?
	if parser.buffer[parser.buffer_pos] == '-' && is_blankz(parser.buffer, parser.buffer_pos+1) {
		return yaml_parser_fetch_block_entry(parser)
	}

	// Is it the key indicator?
	if parser.buffer[parser.buffer_pos] == '?' && (parser.flow_level > 0 || is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_key(parser)
	}

	// Is it the value indicator?
	if parser.buffer[parser.buffer_pos] == ':' && (parser.flow_level > 0 || is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_value(parser)
	}

	// Is it an alias?
	if parser.buffer[parser.buffer_pos] == '*' {
		return yaml_parser_fetch_anchor(parser, yaml_ALIAS_TOKEN)
	}

	// Is it an anchor?
	if parser.buffer[parser.buffer_pos] == '&' {
		return yaml_parser_fetch_anchor(parser, yaml_ANCHOR_TOKEN)
	}

	// Is it a tag?
	if parser.buffer[parser.buffer_pos] == '!' {
		return yaml_parser_fetch_tag(parser)
	}

	// Is it a literal scalar?
	if parser.buffer[parser.buffer_pos] == '|' && parser.flow_level == 0 {
		return yaml_parser_fetch_block_scalar(parser, true)
	}

	// Is it a folded scalar?
	if parser.buffer[parser.buffer_pos] == '>' && parser.flow_level == 0 {
		return yaml_parser_fetch_block_scalar(parser, false)
	}

	// Is it a single-quoted scalar?
	if parser.buffer[parser.buffer_pos] == '\'' {
		return yaml_parser_fetch_flow_scalar(parser, true)
	}

	// Is it a double-quoted scalar?
	if parser.buffer[parser.buffer_pos] == '"' {
		return yaml_parser_fetch_flow_scalar(parser, false)
	}

	// Is it a plain scalar?
	//
	// A plain scalar may start with any non-blank characters except
	//
	//      '-', '?', ':', ',', '[', ']', '{', '}',
	//      '#', '&', '*', '!', '|', '>', '\'', '\"',
	//      '%', '@', '`'.
	//
	// In the block context (and, for the '-' indicator, in the flow context
	// too), it may also start with the characters
	//
	//      '-', '?', ':'
	//
	// if it is followed by a non-space character.
	//
	// The last rule is more restrictive than the specification requires.
	// [Go] Make this logic more reasonable.
	//switch parser.buffer[parser.buffer_pos] {
	//case '-', '?', ':', ',', '?', '-', ',', ':', ']', '[', '}', '{', '&', '#', '!', '*', '>', '|', '"', '\'', '@', '%', '-', '`':
	//}
	if !(is_blankz(parser.buffer, parser.buffer_pos) || parser.buffer[parser.buffer_pos] == '-' ||
		parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == ':' ||
		parser.buffer[parser.buffer_pos] == ',' || parser.buffer[parser.buffer_pos] == '[' ||
		parser.buffer[parser.buffer_pos] == ']' || parser.buffer[parser.buffer_pos] == '{' ||
		parser.buffer[parser.buffer_pos] == '}' || parser.buffer[parser.buffer_pos] == '#' ||
		parser.buffer[parser.buffer_pos] == '&' || parser.buffer[parser.buffer_pos] == '*' ||
		parser.buffer[parser.buffer_pos] == '!' || parser.buffer[parser.buffer_pos] == '|' ||
		parser.buffer[parser.buffer_pos] == '>' || parser.buffer[parser.buffer_pos] == '\'' ||
		parser.buffer[parser.buffer_pos] == '"' || parser.buffer[parser.buffer_pos] == '%' ||
		parser.buffer[parser.buffer_pos] == '@' || parser.buffer[parser.buffer_pos] == '`') ||
		(parser.buffer[parser.buffer_pos] == '-' && !is_blank(parser.buffer, parser.buffer_pos+1)) ||
		(parser.flow_level == 0 &&
			(parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == ':') &&
			!is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_plain_scalar(parser)
	}

	// If we don't determine the token type so far, it is an error.
	return yaml_parser_set_scanner_error(parser,
		"while scanning for the next token", parser.mark,
		"found character that cannot start any token")
}

// Check the list of potential simple keys and remove the positions that
// cannot contain simple keys anymore.
func yaml_parser_stale_simple_keys(parser *yaml_parser_t) bool {
	// Check for a potential simple key for each flow level.
	for i := range parser.simple_keys {
		simple_key := &parser.simple_keys[i]

		// The specification requires that a simple key
		//
		//  - is limited to a single line,
		//  - is shorter than 1024 characters.
		if simple_key.possible && (simple_key.mark.line < parser.mark.line || simple_key.mark.index+1024 < parser.mark.index) {

			// Check if the potential simple key to be removed is required.
			if simple_key.required {
				return yaml_parser_set_scanner_error(parser,
					"while scanning a simple key", simple_key.mark,
					"could not find expected ':'")
			}
			simple_key.possible = false
		}
	}
	return true
}

// Check if a simple key may start at the current position and add it if
// needed.
func yaml_parser_save_simple_key(parser *yaml_parser_t) bool {
	// A simple key is required at the current position if the scanner is in
	// the block context and the current column coincides with the indentation
	// level.

	required := parser.flow_level == 0 && parser.indent == parser.mark.column

	// A simple key is required only when it is the first token in the current
	// line.  Therefore it is always allowed.  But we add a check anyway.
	if required && !parser.simple_key_allowed {
		panic("should not happen")
	}

	//
	// If the current position may start a simple key, save it.
	//
	if parser.simple_key_allowed {
		simple_key := yaml_simple_key_t{
			possible:     true,
			required:     required,
			token_number: parser.tokens_parsed + (len(parser.tokens) - parser.tokens_head),
		}
		simple_key.mark = parser.mark

		if !yaml_parser_remove_simple_key(parser) {
			return false
		}
		parser.simple_keys[len(parser.simple_keys)-1] = simple_key
	}
	return true
}

// Remove a potential simple key at the current flow level.
func yaml_parser_remove_simple_key(parser *yaml_parser_t) bool {
	i := len(parser.simple_keys) - 1
	if parser.simple_keys[i].possible {
		// If the key is required, it is an error.
		if parser.simple_keys[i].required {
			return yaml_parser_set_scanner_error(parser,
				"while scanning a simple key", parser.simple_keys[i].mark,
				"could not find expected ':'")
		}
	}
	// Remove the key from the stack.
	parser.simple_keys[i].possible = false
	return true
}

// Increase the flow level and resize the simple key list if needed.
func yaml_parser_increase_flow_level(parser *yaml_parser_t) bool {
	// Reset the simple key on the next level.
	parser.simple_keys = append(parser.simple_keys, yaml_simple_key_t{})

	// Increase the flow level.
	parser.flow_level++
	return true
}

// Decrease the flow level.
func yaml_parser_decrease_flow_level(parser *yaml_parser_t) bool {
	if parser.flow_level > 0 {
		parser.flow_level--
		parser.simple_keys = parser.simple_keys[:len(parser.simple_keys)-1]
	}
	return true
}

// Push the current indentation level to the stack and set the new level
// the current column is greater than the indentation level.  In this case,
// append or insert the specified token into the token queue.
func yaml_parser_roll_indent(parser *yaml_parser_t, column, number int, typ yaml_token_type_t, mark yaml_mark_t) bool {
	// In the flow context, do nothing.
	if parser.flow_level > 0 {
		return true
	}

	if parser.indent < column {
		// Push the current indentation level to the stack and set the new
		// indentation level.
		parser.indents = append(parser.indents, parser.indent)
		parser.indent = column

		// Create a token and insert it into the queue.
		token := yaml_token_t{
			typ:        typ,
			start_mark: mark,
			end_mark:   mark,
		}
		if number > -1 {
			number -= parser.tokens_parsed
		}
		yaml_insert_token(parser, number, &token)
	}
	return true
}

// Pop indentation levels from the indents stack until the current level
// becomes less or equal to the column.  For each indentation level, append
// the BLOCK-END token.
func yaml_parser_unroll_indent(parser *yaml_parser_t, column int) bool {
	// In the flow context, do nothing.
	if parser.flow_level > 0 {
		return true
	}

	// Loop through the indentation levels in the stack.
	for parser.indent > column {
		// Create a token and append it to the queue.
		token := yaml_token_t{
			typ:        yaml_BLOCK_END_TOKEN,
			start_mark: parser.mark,
			end_mark:   parser.mark,
		}
		yaml_insert_token(parser, -1, &token)

		// Pop the indentation level.
		parser.indent = parser.indents[len(parser.indents)-1]
		parser.indents = parser.indents[:len(parser.indents)-1]
	}
	return true
}

// Initialize the scanner and produce the STREAM-START token.
func yaml_parser_fetch_stream_start(parser *yaml_parser_t) bool {

	// Set the initial indentation.
	parser.indent = -1

	// Initialize the simple key stack.
	parser.simple_keys = append(parser.simple_keys, yaml_simple_key_t{})

	// A simple key is allowed at the beginning of the stream.
	parser.simple_key_allowed = true

	// We have started.
	parser.stream_start_produced = true

	// Create the STREAM-START token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_STREAM_START_TOKEN,
		start_mark: parser.mark,
		end_mark:   parser.mark,
		encoding:   parser.encoding,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the STREAM-END token and shut down the scanner.
func yaml_parser_fetch_stream_end(parser *yaml_parser_t) bool {

	// Force new line.
	if parser.mark.column != 0 {
		parser.mark.column = 0
		parser.mark.line++
	}

	// Reset the indentation level.
	if !yaml_parser_unroll_indent(parser, -1) {
		return false
	}

	// Reset simple keys.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	// Create the STREAM-END token and append it to the queue.
	token := yaml_token_t{
		typ:        yaml_STREAM_END_TOKEN,
		start_mark: parser.mark,
		end_mark:   parser.mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce a VERSION-DIRECTIVE or TAG-DIRECTIVE token.
func yaml_parser_fetch_directive(parser *yaml_parser_t) bool {
	// Reset the indentation level.
	if !yaml_parser_unroll_indent(parser, -1) {
		return false
	}

	// Reset simple keys.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	// Create the YAML-DIRECTIVE or TAG-DIRECTIVE token.
	token := yaml_token_t{}
	if !yaml_parser_scan_directive(parser, &token) {
		return false
	}
	// Append the token to the queue.
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the DOCUMENT-START or DOCUMENT-END token.
func yaml_parser_fetch_document_indicator(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	// Reset the indentation level.
	if !yaml_parser_unroll_indent(parser, -1) {
		return false
	}

	// Reset simple keys.
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	// Consume the token.
	start_mark := parser.mark

	skip(parser)
	skip(parser)
	skip(parser)

	end_mark := parser.mark

	// Create the DOCUMENT-START or DOCUMENT-END token.
	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	// Append the token to the queue.
	yaml_insert_token(parser, -1, &token)
	return true
}

// Produce the FLOW-SEQUENCE-START or FLOW-MAPPING-START token.
func yaml_parser_fetch_flow_collection_start(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	// The indicators '[' and '{' may start a simple key.
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	// Increase the flow level.
	if !yaml_parser_increase_flow_level(parser) {
		return false
	}

	// A simple key may follow the indicators '[' and '{'.
	parser.simple_key_allowed = true

	// Consume the token.
	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	// Create the
"""




```