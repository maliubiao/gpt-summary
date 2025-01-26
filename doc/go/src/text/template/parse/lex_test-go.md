Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - The Goal:**

The core request is to understand what the Go code does, specifically the `lex_test.go` file within the `text/template/parse` package. The keywords "test" and "lex" immediately suggest this is about testing the *lexical analysis* part of a template parser. Lexical analysis (or scanning) is the first stage of compilation/interpretation where the input text is broken down into meaningful tokens.

**2. Deconstructing the Code - Identifying Key Components:**

I started by looking for the most prominent structures and their roles:

* **`itemName` map:** This maps `itemType` constants to their string representations. This is clearly for making the output of the lexer more human-readable.
* **`itemType` enum (implicit):**  The keys of `itemName` (`itemError`, `itemBool`, etc.) define the different types of tokens the lexer can identify.
* **`item` struct:** This structure represents a single token, holding its type (`typ`), value (`val`), and potentially position/line number (though those are used in later tests, not immediately apparent in the `item` definition itself).
* **`lexTest` struct:** This is the core testing structure. Each `lexTest` defines a test case with a name, input string, and the expected sequence of `item` tokens.
* **`mkItem` function:** A helper function to create `item` instances, simplifying test case creation.
* **Global `item` variables (e.g., `tDot`, `tBlock`, `tEOF`):** These are pre-defined `item` instances for commonly used tokens, making the `lexTests` array more concise.
* **`lexTests` array:** The primary set of test cases for the default delimiters.
* **`lexDelimTests` array:** Test cases specifically for testing custom delimiters.
* **`lexPosTests` array:** Test cases designed to verify the correct tracking of token positions and line numbers.
* **`collect` function:** This is crucial. It takes a `lexTest`, the left and right delimiters, and *runs the lexer* on the input. It then collects the emitted tokens into a slice. The `l := lex(...)` part confirms this is where the actual lexing happens. The `l.nextItem()` loop iterates through the tokens.
* **`equal` function:** A utility to compare two slices of `item` tokens, with an option to check position information.
* **`TestLex` function:** The main test function for the default delimiters. It iterates through `lexTests`, runs `collect`, and uses `equal` to compare the results.
* **`TestDelims` function:** Tests the lexer with custom delimiters defined in `lexDelimTests`.
* **`TestDelimsAlphaNumeric`, `TestDelimsAndMarkers`:** More specialized tests for custom delimiters with alphanumeric characters and those that resemble markers.
* **`TestPos` function:**  Specifically tests the position and line number tracking of the lexer.
* **`parseLexer` function:** This function, while part of the code, is not directly *testing* the lexer in the same way as the other `Test...` functions. It demonstrates how the output of the lexer would be consumed by a parser.

**3. Inferring Functionality:**

Based on the identified components, I could deduce the primary function:

* **Lexical Analysis (Tokenization):** The code tests a lexer, which is responsible for breaking down a string of text (likely a template) into a sequence of meaningful tokens. The `itemType` enum defines the vocabulary of these tokens.

**4. Providing Go Code Examples:**

To illustrate the functionality, I considered a simple template snippet and how the lexer would process it:

* **Simple Example:**  A basic template with a variable and some text. I manually mapped the input to the expected tokens, demonstrating the lexer's role in identifying delimiters, identifiers, and plain text.

**5. Code Inference (Hypothetical):**

The `collect` function clearly calls a `lex` function. Since the provided code doesn't *define* `lex`, I inferred its likely signature and internal logic:

* **`lex` Function Signature:** It likely takes the test name, input string, and delimiter strings as arguments and returns a lexer object (or a channel of items).
* **`lexer` Structure:** I imagined a `lexer` struct holding the input, current position, delimiters, and methods like `nextItem` to produce tokens.
* **`nextItem` Logic:** This would involve state transitions based on the input characters, identifying delimiters, keywords, identifiers, etc. I highlighted potential state transitions for encountering `{{`, `/*`, quotes, etc.

**6. Command-Line Arguments (Not Applicable):**

Since this is a unit test file, it's executed using `go test`. There are no command-line arguments handled *within this specific file*. The delimiters are set programmatically in the test cases.

**7. Common Mistakes (Based on Test Cases):**

I looked at the error test cases in `lexTests` to identify potential issues:

* **Unclosed Actions/Quotes/Comments:** These are common syntax errors in template languages.
* **Bad Number Syntax:** Illustrates the need for the lexer to validate basic syntax.
* **Unexpected Right Parentheses:** Shows the importance of matching parentheses.

**8. Structuring the Answer:**

Finally, I organized the information into clear sections with headings, providing explanations, code examples, and addressing each part of the original request. I used code blocks for clarity and tried to explain concepts in a way that someone unfamiliar with template parsing could understand. I used bolding to highlight key terms.
这段Go语言代码是 `go/src/text/template/parse/lex_test.go` 文件的一部分，它的主要功能是**测试 `text/template/parse` 包中词法分析器（lexer）的实现**。

更具体地说，它定义了一系列的测试用例，每个用例包含一个输入字符串（代表模板内容）和期望的词法单元（tokens）序列。然后，它使用 `lex` 函数（这个函数在这段代码中没有定义，但可以推断出是词法分析器的核心）将输入字符串分解成词法单元，并将实际生成的词法单元与期望的词法单元进行比较，以验证词法分析器的正确性。

**它实现的Go语言功能是模板解析中的词法分析（Lexical Analysis 或 Scanning）。**

词法分析是编译器或解释器将源代码分解成一系列称为“词法单元”（tokens）的过程。每个词法单元代表源代码中一个有意义的组成部分，例如关键字、标识符、运算符、字面量等。在模板引擎的上下文中，词法单元可能包括变量、控制结构（如 `if`、`range`）、字面文本、分隔符等。

**Go 代码举例说明:**

假设 `lex` 函数（虽然未在此代码段中定义）接收一个输入字符串和左右分隔符，并返回一个词法单元的通道或列表。

```go
// 假设的 lex 函数，实际实现可能更复杂
func lex(name, input, leftDelim, rightDelim string) *lexer {
	// ... 词法分析器的初始化逻辑 ...
	return &lexer{
		input:     input,
		leftDelim: leftDelim,
		rightDelim: rightDelim,
		// ... 其他必要的状态 ...
	}
}

type lexer struct {
	input      string
	position   int
	start      int
	width      int
	state      stateFn
	items      chan item
	leftDelim  string
	rightDelim string
	// ... 其他字段 ...
}

func (l *lexer) nextItem() item {
	// ... 从输入中扫描下一个词法单元 ...
	return item{} // 返回扫描到的词法单元
}

// item 结构体定义如代码段中所示
type item struct {
	typ itemType
	pos int
	val string
	line int
}

// itemType 枚举定义如代码段中所示
type itemType int
```

**代码推理（带假设的输入与输出）:**

考虑 `lexTests` 中的一个测试用例：

```go
{"for", `{{for}}`, []item{tLeft, tFor, tRight, tEOF}},
```

**假设输入:** `{{for}}`

**推断的 `lex` 函数处理过程:**

1. 词法分析器从头开始扫描输入字符串。
2. 遇到 `{{`，识别为左分隔符，生成 `item{itemLeftDelim, 0, "{{", 1}` (假设位置从0开始，行号为1)。
3. 遇到 `for`，识别为关键字 `for`，生成 `item{itemFor, 2, "for", 1}`。
4. 遇到 `}}`，识别为右分隔符，生成 `item{itemRightDelim, 5, "}}", 1}`。
5. 到达字符串末尾，生成 `item{itemEOF, 7, "", 1}`。

**期望输出 (与 `lexTests` 中定义一致):**

```
[]item{
    {itemLeftDelim, 0, "{{", 1},
    {itemFor, 2, "for", 1},
    {itemRightDelim, 5, "}}", 1},
    {itemEOF, 7, "", 1},
}
```

**命令行参数的具体处理:**

这段代码本身是一个测试文件，不直接处理命令行参数。它通过 `go test` 命令来运行。`go test` 命令会查找以 `_test.go` 结尾的文件，并执行其中的测试函数（以 `Test` 开头的函数）。

在这个特定的文件中，可以通过修改 `collect` 函数的调用来测试不同的左右分隔符，例如 `TestDelims` 函数所示：

```go
func TestDelims(t *testing.T) {
	for _, test := range lexDelimTests {
		items := collect(&test, "$$", "@@") // 这里指定了左右分隔符为 "$$" 和 "@@"
		if !equal(items, test.items, false) {
			t.Errorf("%s: got\n\t%v\nexpected\n\t%v", test.name, items, test.items)
		}
	}
}
```

**使用者易犯错的点:**

对于使用 `text/template` 包的开发者来说，理解模板语法的词法规则很重要，以下是一些常见的错误点，这些测试用例也覆盖了部分：

1. **分隔符不匹配:**  忘记闭合 `{{` 或 `}}`。测试用例 `{"unclosed action", "{{", ...}` 验证了这种情况。

    ```go
    // 错误示例
    t, err := template.New("test").Parse("Hello {{.Name")
    ```

2. **字符串或字符常量未闭合:**  忘记闭合引号 `"` 或单引号 `'`。测试用例 `{"unclosed quote", "{{\"\n\"}}", ...}` 和 `{"unclosed char constant", "{{'\n}}", ...}` 验证了这种情况。

    ```go
    // 错误示例
    t, err := template.New("test").Parse(`{{ "hello world }}`)
    ```

3. **注释未闭合:**  忘记闭合 `/*` 和 `*/`。测试用例 `{"text with bad comment", "hello-{{/*/}}-world", ...}` 验证了这种情况。

    ```go
    // 错误示例
    t, err := template.New("test").Parse("Hello {{/* This is a comment ")
    ```

4. **错误的数字语法:**  使用了词法分析器无法识别的数字格式。测试用例 `{"bad number", "{{3k}}", ...}` 验证了这种情况。

    ```go
    // 错误示例
    t, err := template.New("test").Parse("{{ 1.2.3 }}") // 多个小数点
    ```

5. **括号不匹配:**  在表达式中，左右括号的数量不一致。测试用例 `{"unclosed paren", "{{(3}}", ...}` 和 `{"extra right paren", "{{3)}}", ...}` 验证了这种情况。

    ```go
    // 错误示例
    t, err := template.New("test").Parse("{{ if ( ( .Age > 18 ) }} ... {{ end }}") // 多了一个左括号
    ```

总而言之，这段测试代码确保了 `text/template/parse` 包中的词法分析器能够正确地将模板字符串分解成预期的词法单元，这是模板引擎正确解析和执行模板的基础。

Prompt: 
```
这是路径为go/src/text/template/parse/lex_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"testing"
)

// Make the types prettyprint.
var itemName = map[itemType]string{
	itemError:        "error",
	itemBool:         "bool",
	itemChar:         "char",
	itemCharConstant: "charconst",
	itemComment:      "comment",
	itemComplex:      "complex",
	itemDeclare:      ":=",
	itemEOF:          "EOF",
	itemField:        "field",
	itemIdentifier:   "identifier",
	itemLeftDelim:    "left delim",
	itemLeftParen:    "(",
	itemNumber:       "number",
	itemPipe:         "pipe",
	itemRawString:    "raw string",
	itemRightDelim:   "right delim",
	itemRightParen:   ")",
	itemSpace:        "space",
	itemString:       "string",
	itemVariable:     "variable",

	// keywords
	itemDot:      ".",
	itemBlock:    "block",
	itemBreak:    "break",
	itemContinue: "continue",
	itemDefine:   "define",
	itemElse:     "else",
	itemIf:       "if",
	itemEnd:      "end",
	itemNil:      "nil",
	itemRange:    "range",
	itemTemplate: "template",
	itemWith:     "with",
}

func (i itemType) String() string {
	s := itemName[i]
	if s == "" {
		return fmt.Sprintf("item%d", int(i))
	}
	return s
}

type lexTest struct {
	name  string
	input string
	items []item
}

func mkItem(typ itemType, text string) item {
	return item{
		typ: typ,
		val: text,
	}
}

var (
	tDot        = mkItem(itemDot, ".")
	tBlock      = mkItem(itemBlock, "block")
	tEOF        = mkItem(itemEOF, "")
	tFor        = mkItem(itemIdentifier, "for")
	tLeft       = mkItem(itemLeftDelim, "{{")
	tLpar       = mkItem(itemLeftParen, "(")
	tPipe       = mkItem(itemPipe, "|")
	tQuote      = mkItem(itemString, `"abc \n\t\" "`)
	tRange      = mkItem(itemRange, "range")
	tRight      = mkItem(itemRightDelim, "}}")
	tRpar       = mkItem(itemRightParen, ")")
	tSpace      = mkItem(itemSpace, " ")
	raw         = "`" + `abc\n\t\" ` + "`"
	rawNL       = "`now is{{\n}}the time`" // Contains newline inside raw quote.
	tRawQuote   = mkItem(itemRawString, raw)
	tRawQuoteNL = mkItem(itemRawString, rawNL)
)

var lexTests = []lexTest{
	{"empty", "", []item{tEOF}},
	{"spaces", " \t\n", []item{mkItem(itemText, " \t\n"), tEOF}},
	{"text", `now is the time`, []item{mkItem(itemText, "now is the time"), tEOF}},
	{"text with comment", "hello-{{/* this is a comment */}}-world", []item{
		mkItem(itemText, "hello-"),
		mkItem(itemComment, "/* this is a comment */"),
		mkItem(itemText, "-world"),
		tEOF,
	}},
	{"punctuation", "{{,@% }}", []item{
		tLeft,
		mkItem(itemChar, ","),
		mkItem(itemChar, "@"),
		mkItem(itemChar, "%"),
		tSpace,
		tRight,
		tEOF,
	}},
	{"parens", "{{((3))}}", []item{
		tLeft,
		tLpar,
		tLpar,
		mkItem(itemNumber, "3"),
		tRpar,
		tRpar,
		tRight,
		tEOF,
	}},
	{"empty action", `{{}}`, []item{tLeft, tRight, tEOF}},
	{"for", `{{for}}`, []item{tLeft, tFor, tRight, tEOF}},
	{"block", `{{block "foo" .}}`, []item{
		tLeft, tBlock, tSpace, mkItem(itemString, `"foo"`), tSpace, tDot, tRight, tEOF,
	}},
	{"quote", `{{"abc \n\t\" "}}`, []item{tLeft, tQuote, tRight, tEOF}},
	{"raw quote", "{{" + raw + "}}", []item{tLeft, tRawQuote, tRight, tEOF}},
	{"raw quote with newline", "{{" + rawNL + "}}", []item{tLeft, tRawQuoteNL, tRight, tEOF}},
	{"numbers", "{{1 02 0x14 0X14 -7.2i 1e3 1E3 +1.2e-4 4.2i 1+2i 1_2 0x1.e_fp4 0X1.E_FP4}}", []item{
		tLeft,
		mkItem(itemNumber, "1"),
		tSpace,
		mkItem(itemNumber, "02"),
		tSpace,
		mkItem(itemNumber, "0x14"),
		tSpace,
		mkItem(itemNumber, "0X14"),
		tSpace,
		mkItem(itemNumber, "-7.2i"),
		tSpace,
		mkItem(itemNumber, "1e3"),
		tSpace,
		mkItem(itemNumber, "1E3"),
		tSpace,
		mkItem(itemNumber, "+1.2e-4"),
		tSpace,
		mkItem(itemNumber, "4.2i"),
		tSpace,
		mkItem(itemComplex, "1+2i"),
		tSpace,
		mkItem(itemNumber, "1_2"),
		tSpace,
		mkItem(itemNumber, "0x1.e_fp4"),
		tSpace,
		mkItem(itemNumber, "0X1.E_FP4"),
		tRight,
		tEOF,
	}},
	{"characters", `{{'a' '\n' '\'' '\\' '\u00FF' '\xFF' '本'}}`, []item{
		tLeft,
		mkItem(itemCharConstant, `'a'`),
		tSpace,
		mkItem(itemCharConstant, `'\n'`),
		tSpace,
		mkItem(itemCharConstant, `'\''`),
		tSpace,
		mkItem(itemCharConstant, `'\\'`),
		tSpace,
		mkItem(itemCharConstant, `'\u00FF'`),
		tSpace,
		mkItem(itemCharConstant, `'\xFF'`),
		tSpace,
		mkItem(itemCharConstant, `'本'`),
		tRight,
		tEOF,
	}},
	{"bools", "{{true false}}", []item{
		tLeft,
		mkItem(itemBool, "true"),
		tSpace,
		mkItem(itemBool, "false"),
		tRight,
		tEOF,
	}},
	{"dot", "{{.}}", []item{
		tLeft,
		tDot,
		tRight,
		tEOF,
	}},
	{"nil", "{{nil}}", []item{
		tLeft,
		mkItem(itemNil, "nil"),
		tRight,
		tEOF,
	}},
	{"dots", "{{.x . .2 .x.y.z}}", []item{
		tLeft,
		mkItem(itemField, ".x"),
		tSpace,
		tDot,
		tSpace,
		mkItem(itemNumber, ".2"),
		tSpace,
		mkItem(itemField, ".x"),
		mkItem(itemField, ".y"),
		mkItem(itemField, ".z"),
		tRight,
		tEOF,
	}},
	{"keywords", "{{range if else end with}}", []item{
		tLeft,
		mkItem(itemRange, "range"),
		tSpace,
		mkItem(itemIf, "if"),
		tSpace,
		mkItem(itemElse, "else"),
		tSpace,
		mkItem(itemEnd, "end"),
		tSpace,
		mkItem(itemWith, "with"),
		tRight,
		tEOF,
	}},
	{"variables", "{{$c := printf $ $hello $23 $ $var.Field .Method}}", []item{
		tLeft,
		mkItem(itemVariable, "$c"),
		tSpace,
		mkItem(itemDeclare, ":="),
		tSpace,
		mkItem(itemIdentifier, "printf"),
		tSpace,
		mkItem(itemVariable, "$"),
		tSpace,
		mkItem(itemVariable, "$hello"),
		tSpace,
		mkItem(itemVariable, "$23"),
		tSpace,
		mkItem(itemVariable, "$"),
		tSpace,
		mkItem(itemVariable, "$var"),
		mkItem(itemField, ".Field"),
		tSpace,
		mkItem(itemField, ".Method"),
		tRight,
		tEOF,
	}},
	{"variable invocation", "{{$x 23}}", []item{
		tLeft,
		mkItem(itemVariable, "$x"),
		tSpace,
		mkItem(itemNumber, "23"),
		tRight,
		tEOF,
	}},
	{"pipeline", `intro {{echo hi 1.2 |noargs|args 1 "hi"}} outro`, []item{
		mkItem(itemText, "intro "),
		tLeft,
		mkItem(itemIdentifier, "echo"),
		tSpace,
		mkItem(itemIdentifier, "hi"),
		tSpace,
		mkItem(itemNumber, "1.2"),
		tSpace,
		tPipe,
		mkItem(itemIdentifier, "noargs"),
		tPipe,
		mkItem(itemIdentifier, "args"),
		tSpace,
		mkItem(itemNumber, "1"),
		tSpace,
		mkItem(itemString, `"hi"`),
		tRight,
		mkItem(itemText, " outro"),
		tEOF,
	}},
	{"declaration", "{{$v := 3}}", []item{
		tLeft,
		mkItem(itemVariable, "$v"),
		tSpace,
		mkItem(itemDeclare, ":="),
		tSpace,
		mkItem(itemNumber, "3"),
		tRight,
		tEOF,
	}},
	{"2 declarations", "{{$v , $w := 3}}", []item{
		tLeft,
		mkItem(itemVariable, "$v"),
		tSpace,
		mkItem(itemChar, ","),
		tSpace,
		mkItem(itemVariable, "$w"),
		tSpace,
		mkItem(itemDeclare, ":="),
		tSpace,
		mkItem(itemNumber, "3"),
		tRight,
		tEOF,
	}},
	{"field of parenthesized expression", "{{(.X).Y}}", []item{
		tLeft,
		tLpar,
		mkItem(itemField, ".X"),
		tRpar,
		mkItem(itemField, ".Y"),
		tRight,
		tEOF,
	}},
	{"trimming spaces before and after", "hello- {{- 3 -}} -world", []item{
		mkItem(itemText, "hello-"),
		tLeft,
		mkItem(itemNumber, "3"),
		tRight,
		mkItem(itemText, "-world"),
		tEOF,
	}},
	{"trimming spaces before and after comment", "hello- {{- /* hello */ -}} -world", []item{
		mkItem(itemText, "hello-"),
		mkItem(itemComment, "/* hello */"),
		mkItem(itemText, "-world"),
		tEOF,
	}},
	// errors
	{"badchar", "#{{\x01}}", []item{
		mkItem(itemText, "#"),
		tLeft,
		mkItem(itemError, "unrecognized character in action: U+0001"),
	}},
	{"unclosed action", "{{", []item{
		tLeft,
		mkItem(itemError, "unclosed action"),
	}},
	{"EOF in action", "{{range", []item{
		tLeft,
		tRange,
		mkItem(itemError, "unclosed action"),
	}},
	{"unclosed quote", "{{\"\n\"}}", []item{
		tLeft,
		mkItem(itemError, "unterminated quoted string"),
	}},
	{"unclosed raw quote", "{{`xx}}", []item{
		tLeft,
		mkItem(itemError, "unterminated raw quoted string"),
	}},
	{"unclosed char constant", "{{'\n}}", []item{
		tLeft,
		mkItem(itemError, "unterminated character constant"),
	}},
	{"bad number", "{{3k}}", []item{
		tLeft,
		mkItem(itemError, `bad number syntax: "3k"`),
	}},
	{"unclosed paren", "{{(3}}", []item{
		tLeft,
		tLpar,
		mkItem(itemNumber, "3"),
		mkItem(itemError, `unclosed left paren`),
	}},
	{"extra right paren", "{{3)}}", []item{
		tLeft,
		mkItem(itemNumber, "3"),
		mkItem(itemError, "unexpected right paren"),
	}},

	// Fixed bugs
	// Many elements in an action blew the lookahead until
	// we made lexInsideAction not loop.
	{"long pipeline deadlock", "{{|||||}}", []item{
		tLeft,
		tPipe,
		tPipe,
		tPipe,
		tPipe,
		tPipe,
		tRight,
		tEOF,
	}},
	{"text with bad comment", "hello-{{/*/}}-world", []item{
		mkItem(itemText, "hello-"),
		mkItem(itemError, `unclosed comment`),
	}},
	{"text with comment close separated from delim", "hello-{{/* */ }}-world", []item{
		mkItem(itemText, "hello-"),
		mkItem(itemError, `comment ends before closing delimiter`),
	}},
	// This one is an error that we can't catch because it breaks templates with
	// minimized JavaScript. Should have fixed it before Go 1.1.
	{"unmatched right delimiter", "hello-{.}}-world", []item{
		mkItem(itemText, "hello-{.}}-world"),
		tEOF,
	}},
}

// collect gathers the emitted items into a slice.
func collect(t *lexTest, left, right string) (items []item) {
	l := lex(t.name, t.input, left, right)
	l.options = lexOptions{
		emitComment: true,
		breakOK:     true,
		continueOK:  true,
	}
	for {
		item := l.nextItem()
		items = append(items, item)
		if item.typ == itemEOF || item.typ == itemError {
			break
		}
	}
	return
}

func equal(i1, i2 []item, checkPos bool) bool {
	if len(i1) != len(i2) {
		return false
	}
	for k := range i1 {
		if i1[k].typ != i2[k].typ {
			return false
		}
		if i1[k].val != i2[k].val {
			return false
		}
		if checkPos && i1[k].pos != i2[k].pos {
			return false
		}
		if checkPos && i1[k].line != i2[k].line {
			return false
		}
	}
	return true
}

func TestLex(t *testing.T) {
	for _, test := range lexTests {
		items := collect(&test, "", "")
		if !equal(items, test.items, false) {
			t.Errorf("%s: got\n\t%+v\nexpected\n\t%v", test.name, items, test.items)
			return // TODO
		}
		t.Log(test.name, "OK")
	}
}

// Some easy cases from above, but with delimiters $$ and @@
var lexDelimTests = []lexTest{
	{"punctuation", "$$,@%{{}}@@", []item{
		tLeftDelim,
		mkItem(itemChar, ","),
		mkItem(itemChar, "@"),
		mkItem(itemChar, "%"),
		mkItem(itemChar, "{"),
		mkItem(itemChar, "{"),
		mkItem(itemChar, "}"),
		mkItem(itemChar, "}"),
		tRightDelim,
		tEOF,
	}},
	{"empty action", `$$@@`, []item{tLeftDelim, tRightDelim, tEOF}},
	{"for", `$$for@@`, []item{tLeftDelim, tFor, tRightDelim, tEOF}},
	{"quote", `$$"abc \n\t\" "@@`, []item{tLeftDelim, tQuote, tRightDelim, tEOF}},
	{"raw quote", "$$" + raw + "@@", []item{tLeftDelim, tRawQuote, tRightDelim, tEOF}},
}

var (
	tLeftDelim  = mkItem(itemLeftDelim, "$$")
	tRightDelim = mkItem(itemRightDelim, "@@")
)

func TestDelims(t *testing.T) {
	for _, test := range lexDelimTests {
		items := collect(&test, "$$", "@@")
		if !equal(items, test.items, false) {
			t.Errorf("%s: got\n\t%v\nexpected\n\t%v", test.name, items, test.items)
		}
	}
}

func TestDelimsAlphaNumeric(t *testing.T) {
	test := lexTest{"right delimiter with alphanumeric start", "{{hub .host hub}}", []item{
		mkItem(itemLeftDelim, "{{hub"),
		mkItem(itemSpace, " "),
		mkItem(itemField, ".host"),
		mkItem(itemSpace, " "),
		mkItem(itemRightDelim, "hub}}"),
		tEOF,
	}}
	items := collect(&test, "{{hub", "hub}}")

	if !equal(items, test.items, false) {
		t.Errorf("%s: got\n\t%v\nexpected\n\t%v", test.name, items, test.items)
	}
}

func TestDelimsAndMarkers(t *testing.T) {
	test := lexTest{"delims that look like markers", "{{- .x -}} {{- - .x - -}}", []item{
		mkItem(itemLeftDelim, "{{- "),
		mkItem(itemField, ".x"),
		mkItem(itemRightDelim, " -}}"),
		mkItem(itemLeftDelim, "{{- "),
		mkItem(itemField, ".x"),
		mkItem(itemRightDelim, " -}}"),
		tEOF,
	}}
	items := collect(&test, "{{- ", " -}}")

	if !equal(items, test.items, false) {
		t.Errorf("%s: got\n\t%v\nexpected\n\t%v", test.name, items, test.items)
	}
}

var lexPosTests = []lexTest{
	{"empty", "", []item{{itemEOF, 0, "", 1}}},
	{"punctuation", "{{,@%#}}", []item{
		{itemLeftDelim, 0, "{{", 1},
		{itemChar, 2, ",", 1},
		{itemChar, 3, "@", 1},
		{itemChar, 4, "%", 1},
		{itemChar, 5, "#", 1},
		{itemRightDelim, 6, "}}", 1},
		{itemEOF, 8, "", 1},
	}},
	{"sample", "0123{{hello}}xyz", []item{
		{itemText, 0, "0123", 1},
		{itemLeftDelim, 4, "{{", 1},
		{itemIdentifier, 6, "hello", 1},
		{itemRightDelim, 11, "}}", 1},
		{itemText, 13, "xyz", 1},
		{itemEOF, 16, "", 1},
	}},
	{"trimafter", "{{x -}}\n{{y}}", []item{
		{itemLeftDelim, 0, "{{", 1},
		{itemIdentifier, 2, "x", 1},
		{itemRightDelim, 5, "}}", 1},
		{itemLeftDelim, 8, "{{", 2},
		{itemIdentifier, 10, "y", 2},
		{itemRightDelim, 11, "}}", 2},
		{itemEOF, 13, "", 2},
	}},
	{"trimbefore", "{{x}}\n{{- y}}", []item{
		{itemLeftDelim, 0, "{{", 1},
		{itemIdentifier, 2, "x", 1},
		{itemRightDelim, 3, "}}", 1},
		{itemLeftDelim, 6, "{{", 2},
		{itemIdentifier, 10, "y", 2},
		{itemRightDelim, 11, "}}", 2},
		{itemEOF, 13, "", 2},
	}},
	{"longcomment", "{{/*\n*/}}\n{{undefinedFunction \"test\"}}", []item{
		{itemComment, 2, "/*\n*/", 1},
		{itemText, 9, "\n", 2},
		{itemLeftDelim, 10, "{{", 3},
		{itemIdentifier, 12, "undefinedFunction", 3},
		{itemSpace, 29, " ", 3},
		{itemString, 30, "\"test\"", 3},
		{itemRightDelim, 36, "}}", 3},
		{itemEOF, 38, "", 3},
	}},
}

// The other tests don't check position, to make the test cases easier to construct.
// This one does.
func TestPos(t *testing.T) {
	for _, test := range lexPosTests {
		items := collect(&test, "", "")
		if !equal(items, test.items, true) {
			t.Errorf("%s: got\n\t%v\nexpected\n\t%v", test.name, items, test.items)
			if len(items) == len(test.items) {
				// Detailed print; avoid item.String() to expose the position value.
				for i := range items {
					if !equal(items[i:i+1], test.items[i:i+1], true) {
						i1 := items[i]
						i2 := test.items[i]
						t.Errorf("\t#%d: got {%v %d %q %d} expected {%v %d %q %d}",
							i, i1.typ, i1.pos, i1.val, i1.line, i2.typ, i2.pos, i2.val, i2.line)
					}
				}
			}
		}
	}
}

// parseLexer is a local version of parse that lets us pass in the lexer instead of building it.
// We expect an error, so the tree set and funcs list are explicitly nil.
func (t *Tree) parseLexer(lex *lexer) (tree *Tree, err error) {
	defer t.recover(&err)
	t.ParseName = t.Name
	t.startParse(nil, lex, map[string]*Tree{})
	t.parse()
	t.add()
	t.stopParse()
	return t, nil
}

"""



```