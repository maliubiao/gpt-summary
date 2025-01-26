Response:
Let's break down the thought process for analyzing the `lex.go` file.

1. **Identify the Core Purpose:** The filename `lex.go` and the package name `parse` strongly suggest this code is responsible for lexical analysis (scanning or tokenizing) within a larger parsing process. The comments at the beginning reinforce this, mentioning "token or text string returned from the scanner."

2. **Examine Key Data Structures:**

   * **`item` struct:** This is fundamental. It represents a single token. The fields `typ`, `pos`, `val`, and `line` are standard components of a token structure, holding the token type, its position in the input, its value, and the line number.
   * **`itemType` enum (or `const` block):** This defines the different types of tokens the lexer can recognize. The names are self-explanatory (e.g., `itemIdentifier`, `itemString`, `itemLeftDelim`). The `iota` keyword suggests it's an enumeration.
   * **`lexer` struct:** This holds the state of the lexer during the scanning process. Key fields include the input string, delimiters, current position, and the `item` being built. The `stateFn` field hints at a state machine implementation.
   * **`stateFn` type:** This is a function type that takes a `*lexer` and returns another `stateFn`. This is the hallmark of a state machine based lexer.

3. **Analyze Key Functions:**

   * **`lex(name, input, left, right string) *lexer`:** This is the constructor for the `lexer`. It initializes the lexer with the input and delimiters. This is the entry point to start the lexing process.
   * **`next()`:**  Fetches the next rune from the input, handling UTF-8 decoding and line counting.
   * **`peek()`:** Looks at the next rune without consuming it.
   * **`backup()`:** Moves the current position back one rune.
   * **`emit(t itemType)` and `emitItem(i item)`:** These functions create and send tokens to the parser.
   * **`nextItem()`:**  This is the core loop of the lexer. It repeatedly calls the current `stateFn` until it returns `nil`, indicating a token has been emitted. The initial state depends on whether the lexer is inside an action.
   * **`lexText(l *lexer) stateFn`:** This state scans plain text until it encounters the left delimiter.
   * **`lexLeftDelim(l *lexer) stateFn`:** Handles the left delimiter, including trim markers.
   * **`lexRightDelim(l *lexer) stateFn`:** Handles the right delimiter, including trim markers.
   * **`lexInsideAction(l *lexer) stateFn`:**  This is the main state for scanning within the action delimiters. It dispatches to other `lex...` functions based on the encountered characters.
   * **Various `lex...` functions (e.g., `lexIdentifier`, `lexString`, `lexNumber`):** These functions handle the recognition of specific token types within actions.

4. **Identify the Lexing Logic:** The use of `stateFn` and the various `lex...` functions clearly indicates a state machine approach. The lexer transitions between states based on the input characters. The `nextItem()` function drives this state machine.

5. **Infer the Functionality (Connecting the Dots):** Based on the token types and the state functions, it becomes clear that this code is designed to tokenize a template language. The delimiters `{{` and `}}`, keywords like `if`, `range`, `define`, and variables starting with `$`, all point towards a template engine.

6. **Construct Example Code:**  To demonstrate the functionality, create a simple template string and simulate the lexing process. Show how the input is broken down into tokens of different types. Include examples of variables, keywords, and text.

7. **Address Command-Line Arguments:** Review the code for any direct handling of command-line arguments. In this case, the lexer takes the input string as an argument to the `lex` function, but there's no explicit command-line parsing within this file itself. Explain that the *parser* or the overall template engine would likely handle command-line arguments.

8. **Identify Potential Pitfalls:** Think about common mistakes users might make when writing templates. Unclosed delimiters, incorrect syntax within actions, and issues with trim markers are good candidates. Provide examples of such errors.

9. **Structure the Answer:** Organize the findings logically:
    * Start with a high-level overview of the functionality.
    * Explain the core data structures.
    * Provide a code example with input and expected output.
    * Discuss command-line argument handling (or the lack thereof).
    * Highlight common user errors.

10. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Double-check the example code and the explanations of the concepts.

This systematic approach of examining the code structure, key functions, and overall logic allows for a comprehensive understanding of the `lex.go` file and its role in the template parsing process.
这段代码是 Go 语言 `text/template` 包中负责词法分析（lexical analysis）的部分，文件名 `lex.go` 表明了其核心功能。 词法分析是编译原理中的一个重要阶段，它的任务是将输入的文本流分解成一个个有意义的单元，称为“词法单元”或“token”。

**主要功能:**

1. **扫描输入文本:**  `lex.go` 中的 `lexer` 结构体和相关方法负责读取输入的模板字符串。
2. **识别词法单元:**  它根据预定义的规则识别出不同的词法单元，例如：
   - **文本 (itemText):**  模板中不属于任何特殊指令的普通文本。
   - **分隔符 (itemLeftDelim, itemRightDelim):**  用于标记模板动作起始和结束的符号，通常是 `{{` 和 `}}`。
   - **变量 (itemVariable):**  以 `$` 开头的标识符，用于引用数据，例如 `$name`。
   - **标识符 (itemIdentifier):**  字母数字组成的字符串，不以 `.` 开头，例如函数名、变量名等。
   - **字段 (itemField):**  以 `.` 开头的标识符，用于访问结构体或 map 的字段，例如 `.Name`。
   - **字符串 (itemString, itemRawString):**  用双引号或反引号包围的字符串字面量。
   - **数字 (itemNumber, itemComplex):**  整数、浮点数或复数。
   - **布尔值 (itemBool):**  `true` 或 `false`。
   - **关键字 (itemBlock, itemIf, itemRange 等):**  模板语言的保留字，用于控制结构和内置功能。
   - **运算符 (itemAssign, itemDeclare, itemPipe):**  赋值、声明和管道符号。
   - **注释 (itemComment):**  被 `/*` 和 `*/` 包围的注释内容。
   - **空格 (itemSpace):**  用于分隔不同词法单元的空白字符。
   - **括号 (itemLeftParen, itemRightParen):**  用于表达式分组。
3. **生成词法单元序列:**  `lexer` 将识别出的词法单元封装成 `item` 结构体，并按照在输入文本中出现的顺序生成一个词法单元的序列。每个 `item` 包含了词法单元的类型 (`itemType`)、在输入文本中的起始位置 (`pos`)、值 (`val`) 和起始行号 (`line`)。
4. **处理空白修剪:**  `lex.go` 还实现了对模板动作前后空白字符的修剪功能。例如，`{{- ... }}` 会移除动作前的空白，`{{ ... -}}` 会移除动作后的空白。
5. **错误处理:**  当遇到无法识别的字符或不符合语法规则的情况时，`lexer` 会生成 `itemError` 类型的词法单元，包含错误信息。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `text/template` 包中实现 **模板引擎** 的一部分。模板引擎允许开发者将动态数据嵌入到预定义的模板文本中，生成最终的输出。`lex.go` 负责将模板文本分解成程序可以理解的词法单元，为后续的语法分析和代码生成阶段做准备。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"text/template/parse"
)

func main() {
	input := `Hello, {{.Name}}! You are {{if .IsAdmin}}an admin{{else}}a user{{end}}.`
	lexer := parse.Lex("myTemplate", input, "{{", "}}")

	for {
		item := lexer.NextItem()
		fmt.Printf("%s: %q\n", item.Type, item.Val)
		if item.Type == parse.ItemEOF || item.Type == parse.ItemError {
			break
		}
	}
}
```

**假设的输入与输出:**

**输入 (input):**

```
Hello, {{.Name}}! You are {{if .IsAdmin}}an admin{{else}}a user{{end}}.
```

**输出:**

```
TEXT: "Hello, "
LEFT_DELIM: "{{"
FIELD: ".Name"
RIGHT_DELIM: "}}"
TEXT: "! You are "
LEFT_DELIM: "{{"
IF: "if"
SPACE: " "
FIELD: ".IsAdmin"
RIGHT_DELIM: "}}"
TEXT: "an admin"
LEFT_DELIM: "{{"
ELSE: "else"
RIGHT_DELIM: "}}"
TEXT: "a user"
LEFT_DELIM: "{{"
END: "end"
RIGHT_DELIM: "}}"
TEXT: "."
EOF: "EOF"
```

**代码推理:**

1. 我们创建了一个包含模板语法的字符串 `input`。
2. 使用 `parse.Lex` 函数创建了一个 `lexer` 实例，指定了模板的名称和分隔符。
3. 进入一个循环，不断调用 `lexer.NextItem()` 获取下一个词法单元。
4. 打印每个词法单元的类型和值。
5. 当遇到 `ItemEOF` (文件结束符) 或 `ItemError` (错误) 时，循环结束。

输出结果展示了 `lexer` 如何将输入字符串分解成不同的词法单元，例如文本、分隔符、字段、关键字等。

**命令行参数的具体处理:**

`lex.go` 本身不直接处理命令行参数。 词法分析器通常是模板引擎内部的一个组件，它接收由其他部分提供的模板字符串作为输入。

模板引擎可能会通过命令行参数来指定模板文件的路径、要传递给模板的数据等。例如，Go 的 `html/template` 和 `text/template` 包通常会配合 `os` 和 `flag` 包来处理命令行参数，加载模板文件，并解析 JSON 或其他格式的数据作为模板的输入。

**使用者易犯错的点:**

1. **未闭合的分隔符:** 忘记写 `}}` 来闭合 `{{` 可能会导致词法分析器报错，因为它会一直扫描下去，直到遇到文件结尾。

   **错误示例:**

   ```go
   input := `Hello, {{.Name}! ` // 缺少结尾的 }}`
   ```

   词法分析器会报 "unclosed action" 的错误。

2. **分隔符内部的语法错误:**  在 `{{` 和 `}}` 之间的代码必须符合模板语言的语法规则。例如，变量名拼写错误、使用了不存在的函数等。

   **错误示例:**

   ```go
   input := `Hello, {{.Nmae}}!` // 变量名拼写错误
   ```

   虽然词法分析器可以正确识别 `{{`, `.Nmae`, 和 `}}`，但后续的语法分析器会报错，因为它无法识别 `.Nmae` 这个字段。

3. **错误地使用空白修剪标记:**  虽然空白修剪很方便，但如果使用不当可能会导致意外的输出。例如，在需要保留空格的情况下使用了修剪标记。

   **示例:**

   ```go
   input := `Hello - {{- .Name -}} !`
   data := map[string]string{"Name": "World"}
   // 如果没有正确理解修剪，可能会认为输出是 "Hello - World !", 但实际可能是 "Hello-World!"
   ```

   使用者需要理解 ` {{-` 会移除前面的空格，`-}}` 会移除后面的空格。

4. **注释未闭合:**  如果使用 `/*` 开始注释，但忘记使用 `*/` 结束，词法分析器会报错。

   **错误示例:**

   ```go
   input := `Hello, {{/* This is a comment ` // 缺少结尾的 */
   ```

   词法分析器会报 "unclosed comment" 的错误。

总而言之，`lex.go` 是 `text/template` 包中至关重要的组成部分，它负责将模板字符串分解成可理解的词法单元，为后续的模板解析和执行奠定基础。理解其工作原理有助于更好地使用 Go 语言的模板功能，并避免一些常见的错误。

Prompt: 
```
这是路径为go/src/text/template/parse/lex.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package parse

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// item represents a token or text string returned from the scanner.
type item struct {
	typ  itemType // The type of this item.
	pos  Pos      // The starting position, in bytes, of this item in the input string.
	val  string   // The value of this item.
	line int      // The line number at the start of this item.
}

func (i item) String() string {
	switch {
	case i.typ == itemEOF:
		return "EOF"
	case i.typ == itemError:
		return i.val
	case i.typ > itemKeyword:
		return fmt.Sprintf("<%s>", i.val)
	case len(i.val) > 10:
		return fmt.Sprintf("%.10q...", i.val)
	}
	return fmt.Sprintf("%q", i.val)
}

// itemType identifies the type of lex items.
type itemType int

const (
	itemError        itemType = iota // error occurred; value is text of error
	itemBool                         // boolean constant
	itemChar                         // printable ASCII character; grab bag for comma etc.
	itemCharConstant                 // character constant
	itemComment                      // comment text
	itemComplex                      // complex constant (1+2i); imaginary is just a number
	itemAssign                       // equals ('=') introducing an assignment
	itemDeclare                      // colon-equals (':=') introducing a declaration
	itemEOF
	itemField      // alphanumeric identifier starting with '.'
	itemIdentifier // alphanumeric identifier not starting with '.'
	itemLeftDelim  // left action delimiter
	itemLeftParen  // '(' inside action
	itemNumber     // simple number, including imaginary
	itemPipe       // pipe symbol
	itemRawString  // raw quoted string (includes quotes)
	itemRightDelim // right action delimiter
	itemRightParen // ')' inside action
	itemSpace      // run of spaces separating arguments
	itemString     // quoted string (includes quotes)
	itemText       // plain text
	itemVariable   // variable starting with '$', such as '$' or  '$1' or '$hello'
	// Keywords appear after all the rest.
	itemKeyword  // used only to delimit the keywords
	itemBlock    // block keyword
	itemBreak    // break keyword
	itemContinue // continue keyword
	itemDot      // the cursor, spelled '.'
	itemDefine   // define keyword
	itemElse     // else keyword
	itemEnd      // end keyword
	itemIf       // if keyword
	itemNil      // the untyped nil constant, easiest to treat as a keyword
	itemRange    // range keyword
	itemTemplate // template keyword
	itemWith     // with keyword
)

var key = map[string]itemType{
	".":        itemDot,
	"block":    itemBlock,
	"break":    itemBreak,
	"continue": itemContinue,
	"define":   itemDefine,
	"else":     itemElse,
	"end":      itemEnd,
	"if":       itemIf,
	"range":    itemRange,
	"nil":      itemNil,
	"template": itemTemplate,
	"with":     itemWith,
}

const eof = -1

// Trimming spaces.
// If the action begins "{{- " rather than "{{", then all space/tab/newlines
// preceding the action are trimmed; conversely if it ends " -}}" the
// leading spaces are trimmed. This is done entirely in the lexer; the
// parser never sees it happen. We require an ASCII space (' ', \t, \r, \n)
// to be present to avoid ambiguity with things like "{{-3}}". It reads
// better with the space present anyway. For simplicity, only ASCII
// does the job.
const (
	spaceChars    = " \t\r\n"  // These are the space characters defined by Go itself.
	trimMarker    = '-'        // Attached to left/right delimiter, trims trailing spaces from preceding/following text.
	trimMarkerLen = Pos(1 + 1) // marker plus space before or after
)

// stateFn represents the state of the scanner as a function that returns the next state.
type stateFn func(*lexer) stateFn

// lexer holds the state of the scanner.
type lexer struct {
	name         string // the name of the input; used only for error reports
	input        string // the string being scanned
	leftDelim    string // start of action marker
	rightDelim   string // end of action marker
	pos          Pos    // current position in the input
	start        Pos    // start position of this item
	atEOF        bool   // we have hit the end of input and returned eof
	parenDepth   int    // nesting depth of ( ) exprs
	line         int    // 1+number of newlines seen
	startLine    int    // start line of this item
	item         item   // item to return to parser
	insideAction bool   // are we inside an action?
	options      lexOptions
}

// lexOptions control behavior of the lexer. All default to false.
type lexOptions struct {
	emitComment bool // emit itemComment tokens.
	breakOK     bool // break keyword allowed
	continueOK  bool // continue keyword allowed
}

// next returns the next rune in the input.
func (l *lexer) next() rune {
	if int(l.pos) >= len(l.input) {
		l.atEOF = true
		return eof
	}
	r, w := utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += Pos(w)
	if r == '\n' {
		l.line++
	}
	return r
}

// peek returns but does not consume the next rune in the input.
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

// backup steps back one rune.
func (l *lexer) backup() {
	if !l.atEOF && l.pos > 0 {
		r, w := utf8.DecodeLastRuneInString(l.input[:l.pos])
		l.pos -= Pos(w)
		// Correct newline count.
		if r == '\n' {
			l.line--
		}
	}
}

// thisItem returns the item at the current input point with the specified type
// and advances the input.
func (l *lexer) thisItem(t itemType) item {
	i := item{t, l.start, l.input[l.start:l.pos], l.startLine}
	l.start = l.pos
	l.startLine = l.line
	return i
}

// emit passes the trailing text as an item back to the parser.
func (l *lexer) emit(t itemType) stateFn {
	return l.emitItem(l.thisItem(t))
}

// emitItem passes the specified item to the parser.
func (l *lexer) emitItem(i item) stateFn {
	l.item = i
	return nil
}

// ignore skips over the pending input before this point.
// It tracks newlines in the ignored text, so use it only
// for text that is skipped without calling l.next.
func (l *lexer) ignore() {
	l.line += strings.Count(l.input[l.start:l.pos], "\n")
	l.start = l.pos
	l.startLine = l.line
}

// accept consumes the next rune if it's from the valid set.
func (l *lexer) accept(valid string) bool {
	if strings.ContainsRune(valid, l.next()) {
		return true
	}
	l.backup()
	return false
}

// acceptRun consumes a run of runes from the valid set.
func (l *lexer) acceptRun(valid string) {
	for strings.ContainsRune(valid, l.next()) {
	}
	l.backup()
}

// errorf returns an error token and terminates the scan by passing
// back a nil pointer that will be the next state, terminating l.nextItem.
func (l *lexer) errorf(format string, args ...any) stateFn {
	l.item = item{itemError, l.start, fmt.Sprintf(format, args...), l.startLine}
	l.start = 0
	l.pos = 0
	l.input = l.input[:0]
	return nil
}

// nextItem returns the next item from the input.
// Called by the parser, not in the lexing goroutine.
func (l *lexer) nextItem() item {
	l.item = item{itemEOF, l.pos, "EOF", l.startLine}
	state := lexText
	if l.insideAction {
		state = lexInsideAction
	}
	for {
		state = state(l)
		if state == nil {
			return l.item
		}
	}
}

// lex creates a new scanner for the input string.
func lex(name, input, left, right string) *lexer {
	if left == "" {
		left = leftDelim
	}
	if right == "" {
		right = rightDelim
	}
	l := &lexer{
		name:         name,
		input:        input,
		leftDelim:    left,
		rightDelim:   right,
		line:         1,
		startLine:    1,
		insideAction: false,
	}
	return l
}

// state functions

const (
	leftDelim    = "{{"
	rightDelim   = "}}"
	leftComment  = "/*"
	rightComment = "*/"
)

// lexText scans until an opening action delimiter, "{{".
func lexText(l *lexer) stateFn {
	if x := strings.Index(l.input[l.pos:], l.leftDelim); x >= 0 {
		if x > 0 {
			l.pos += Pos(x)
			// Do we trim any trailing space?
			trimLength := Pos(0)
			delimEnd := l.pos + Pos(len(l.leftDelim))
			if hasLeftTrimMarker(l.input[delimEnd:]) {
				trimLength = rightTrimLength(l.input[l.start:l.pos])
			}
			l.pos -= trimLength
			l.line += strings.Count(l.input[l.start:l.pos], "\n")
			i := l.thisItem(itemText)
			l.pos += trimLength
			l.ignore()
			if len(i.val) > 0 {
				return l.emitItem(i)
			}
		}
		return lexLeftDelim
	}
	l.pos = Pos(len(l.input))
	// Correctly reached EOF.
	if l.pos > l.start {
		l.line += strings.Count(l.input[l.start:l.pos], "\n")
		return l.emit(itemText)
	}
	return l.emit(itemEOF)
}

// rightTrimLength returns the length of the spaces at the end of the string.
func rightTrimLength(s string) Pos {
	return Pos(len(s) - len(strings.TrimRight(s, spaceChars)))
}

// atRightDelim reports whether the lexer is at a right delimiter, possibly preceded by a trim marker.
func (l *lexer) atRightDelim() (delim, trimSpaces bool) {
	if hasRightTrimMarker(l.input[l.pos:]) && strings.HasPrefix(l.input[l.pos+trimMarkerLen:], l.rightDelim) { // With trim marker.
		return true, true
	}
	if strings.HasPrefix(l.input[l.pos:], l.rightDelim) { // Without trim marker.
		return true, false
	}
	return false, false
}

// leftTrimLength returns the length of the spaces at the beginning of the string.
func leftTrimLength(s string) Pos {
	return Pos(len(s) - len(strings.TrimLeft(s, spaceChars)))
}

// lexLeftDelim scans the left delimiter, which is known to be present, possibly with a trim marker.
// (The text to be trimmed has already been emitted.)
func lexLeftDelim(l *lexer) stateFn {
	l.pos += Pos(len(l.leftDelim))
	trimSpace := hasLeftTrimMarker(l.input[l.pos:])
	afterMarker := Pos(0)
	if trimSpace {
		afterMarker = trimMarkerLen
	}
	if strings.HasPrefix(l.input[l.pos+afterMarker:], leftComment) {
		l.pos += afterMarker
		l.ignore()
		return lexComment
	}
	i := l.thisItem(itemLeftDelim)
	l.insideAction = true
	l.pos += afterMarker
	l.ignore()
	l.parenDepth = 0
	return l.emitItem(i)
}

// lexComment scans a comment. The left comment marker is known to be present.
func lexComment(l *lexer) stateFn {
	l.pos += Pos(len(leftComment))
	x := strings.Index(l.input[l.pos:], rightComment)
	if x < 0 {
		return l.errorf("unclosed comment")
	}
	l.pos += Pos(x + len(rightComment))
	delim, trimSpace := l.atRightDelim()
	if !delim {
		return l.errorf("comment ends before closing delimiter")
	}
	l.line += strings.Count(l.input[l.start:l.pos], "\n")
	i := l.thisItem(itemComment)
	if trimSpace {
		l.pos += trimMarkerLen
	}
	l.pos += Pos(len(l.rightDelim))
	if trimSpace {
		l.pos += leftTrimLength(l.input[l.pos:])
	}
	l.ignore()
	if l.options.emitComment {
		return l.emitItem(i)
	}
	return lexText
}

// lexRightDelim scans the right delimiter, which is known to be present, possibly with a trim marker.
func lexRightDelim(l *lexer) stateFn {
	_, trimSpace := l.atRightDelim()
	if trimSpace {
		l.pos += trimMarkerLen
		l.ignore()
	}
	l.pos += Pos(len(l.rightDelim))
	i := l.thisItem(itemRightDelim)
	if trimSpace {
		l.pos += leftTrimLength(l.input[l.pos:])
		l.ignore()
	}
	l.insideAction = false
	return l.emitItem(i)
}

// lexInsideAction scans the elements inside action delimiters.
func lexInsideAction(l *lexer) stateFn {
	// Either number, quoted string, or identifier.
	// Spaces separate arguments; runs of spaces turn into itemSpace.
	// Pipe symbols separate and are emitted.
	delim, _ := l.atRightDelim()
	if delim {
		if l.parenDepth == 0 {
			return lexRightDelim
		}
		return l.errorf("unclosed left paren")
	}
	switch r := l.next(); {
	case r == eof:
		return l.errorf("unclosed action")
	case isSpace(r):
		l.backup() // Put space back in case we have " -}}".
		return lexSpace
	case r == '=':
		return l.emit(itemAssign)
	case r == ':':
		if l.next() != '=' {
			return l.errorf("expected :=")
		}
		return l.emit(itemDeclare)
	case r == '|':
		return l.emit(itemPipe)
	case r == '"':
		return lexQuote
	case r == '`':
		return lexRawQuote
	case r == '$':
		return lexVariable
	case r == '\'':
		return lexChar
	case r == '.':
		// special look-ahead for ".field" so we don't break l.backup().
		if l.pos < Pos(len(l.input)) {
			r := l.input[l.pos]
			if r < '0' || '9' < r {
				return lexField
			}
		}
		fallthrough // '.' can start a number.
	case r == '+' || r == '-' || ('0' <= r && r <= '9'):
		l.backup()
		return lexNumber
	case isAlphaNumeric(r):
		l.backup()
		return lexIdentifier
	case r == '(':
		l.parenDepth++
		return l.emit(itemLeftParen)
	case r == ')':
		l.parenDepth--
		if l.parenDepth < 0 {
			return l.errorf("unexpected right paren")
		}
		return l.emit(itemRightParen)
	case r <= unicode.MaxASCII && unicode.IsPrint(r):
		return l.emit(itemChar)
	default:
		return l.errorf("unrecognized character in action: %#U", r)
	}
}

// lexSpace scans a run of space characters.
// We have not consumed the first space, which is known to be present.
// Take care if there is a trim-marked right delimiter, which starts with a space.
func lexSpace(l *lexer) stateFn {
	var r rune
	var numSpaces int
	for {
		r = l.peek()
		if !isSpace(r) {
			break
		}
		l.next()
		numSpaces++
	}
	// Be careful about a trim-marked closing delimiter, which has a minus
	// after a space. We know there is a space, so check for the '-' that might follow.
	if hasRightTrimMarker(l.input[l.pos-1:]) && strings.HasPrefix(l.input[l.pos-1+trimMarkerLen:], l.rightDelim) {
		l.backup() // Before the space.
		if numSpaces == 1 {
			return lexRightDelim // On the delim, so go right to that.
		}
	}
	return l.emit(itemSpace)
}

// lexIdentifier scans an alphanumeric.
func lexIdentifier(l *lexer) stateFn {
	for {
		switch r := l.next(); {
		case isAlphaNumeric(r):
			// absorb.
		default:
			l.backup()
			word := l.input[l.start:l.pos]
			if !l.atTerminator() {
				return l.errorf("bad character %#U", r)
			}
			switch {
			case key[word] > itemKeyword:
				item := key[word]
				if item == itemBreak && !l.options.breakOK || item == itemContinue && !l.options.continueOK {
					return l.emit(itemIdentifier)
				}
				return l.emit(item)
			case word[0] == '.':
				return l.emit(itemField)
			case word == "true", word == "false":
				return l.emit(itemBool)
			default:
				return l.emit(itemIdentifier)
			}
		}
	}
}

// lexField scans a field: .Alphanumeric.
// The . has been scanned.
func lexField(l *lexer) stateFn {
	return lexFieldOrVariable(l, itemField)
}

// lexVariable scans a Variable: $Alphanumeric.
// The $ has been scanned.
func lexVariable(l *lexer) stateFn {
	if l.atTerminator() { // Nothing interesting follows -> "$".
		return l.emit(itemVariable)
	}
	return lexFieldOrVariable(l, itemVariable)
}

// lexFieldOrVariable scans a field or variable: [.$]Alphanumeric.
// The . or $ has been scanned.
func lexFieldOrVariable(l *lexer, typ itemType) stateFn {
	if l.atTerminator() { // Nothing interesting follows -> "." or "$".
		if typ == itemVariable {
			return l.emit(itemVariable)
		}
		return l.emit(itemDot)
	}
	var r rune
	for {
		r = l.next()
		if !isAlphaNumeric(r) {
			l.backup()
			break
		}
	}
	if !l.atTerminator() {
		return l.errorf("bad character %#U", r)
	}
	return l.emit(typ)
}

// atTerminator reports whether the input is at valid termination character to
// appear after an identifier. Breaks .X.Y into two pieces. Also catches cases
// like "$x+2" not being acceptable without a space, in case we decide one
// day to implement arithmetic.
func (l *lexer) atTerminator() bool {
	r := l.peek()
	if isSpace(r) {
		return true
	}
	switch r {
	case eof, '.', ',', '|', ':', ')', '(':
		return true
	}
	return strings.HasPrefix(l.input[l.pos:], l.rightDelim)
}

// lexChar scans a character constant. The initial quote is already
// scanned. Syntax checking is done by the parser.
func lexChar(l *lexer) stateFn {
Loop:
	for {
		switch l.next() {
		case '\\':
			if r := l.next(); r != eof && r != '\n' {
				break
			}
			fallthrough
		case eof, '\n':
			return l.errorf("unterminated character constant")
		case '\'':
			break Loop
		}
	}
	return l.emit(itemCharConstant)
}

// lexNumber scans a number: decimal, octal, hex, float, or imaginary. This
// isn't a perfect number scanner - for instance it accepts "." and "0x0.2"
// and "089" - but when it's wrong the input is invalid and the parser (via
// strconv) will notice.
func lexNumber(l *lexer) stateFn {
	if !l.scanNumber() {
		return l.errorf("bad number syntax: %q", l.input[l.start:l.pos])
	}
	if sign := l.peek(); sign == '+' || sign == '-' {
		// Complex: 1+2i. No spaces, must end in 'i'.
		if !l.scanNumber() || l.input[l.pos-1] != 'i' {
			return l.errorf("bad number syntax: %q", l.input[l.start:l.pos])
		}
		return l.emit(itemComplex)
	}
	return l.emit(itemNumber)
}

func (l *lexer) scanNumber() bool {
	// Optional leading sign.
	l.accept("+-")
	// Is it hex?
	digits := "0123456789_"
	if l.accept("0") {
		// Note: Leading 0 does not mean octal in floats.
		if l.accept("xX") {
			digits = "0123456789abcdefABCDEF_"
		} else if l.accept("oO") {
			digits = "01234567_"
		} else if l.accept("bB") {
			digits = "01_"
		}
	}
	l.acceptRun(digits)
	if l.accept(".") {
		l.acceptRun(digits)
	}
	if len(digits) == 10+1 && l.accept("eE") {
		l.accept("+-")
		l.acceptRun("0123456789_")
	}
	if len(digits) == 16+6+1 && l.accept("pP") {
		l.accept("+-")
		l.acceptRun("0123456789_")
	}
	// Is it imaginary?
	l.accept("i")
	// Next thing mustn't be alphanumeric.
	if isAlphaNumeric(l.peek()) {
		l.next()
		return false
	}
	return true
}

// lexQuote scans a quoted string.
func lexQuote(l *lexer) stateFn {
Loop:
	for {
		switch l.next() {
		case '\\':
			if r := l.next(); r != eof && r != '\n' {
				break
			}
			fallthrough
		case eof, '\n':
			return l.errorf("unterminated quoted string")
		case '"':
			break Loop
		}
	}
	return l.emit(itemString)
}

// lexRawQuote scans a raw quoted string.
func lexRawQuote(l *lexer) stateFn {
Loop:
	for {
		switch l.next() {
		case eof:
			return l.errorf("unterminated raw quoted string")
		case '`':
			break Loop
		}
	}
	return l.emit(itemRawString)
}

// isSpace reports whether r is a space character.
func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || r == '\n'
}

// isAlphaNumeric reports whether r is an alphabetic, digit, or underscore.
func isAlphaNumeric(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func hasLeftTrimMarker(s string) bool {
	return len(s) >= 2 && s[0] == trimMarker && isSpace(rune(s[1]))
}

func hasRightTrimMarker(s string) bool {
	return len(s) >= 2 && isSpace(rune(s[0])) && s[1] == trimMarker
}

"""



```