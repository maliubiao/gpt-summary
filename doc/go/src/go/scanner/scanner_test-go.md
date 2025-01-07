Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Request:** The core request is to analyze a part of the Go scanner test file (`scanner_test.go`). The key tasks are:
    * Identify its purpose/functionality.
    * Infer the related Go language feature.
    * Provide Go code examples demonstrating the feature.
    * If applicable, explain command-line argument handling.
    * Point out potential user errors.
    * Finally, summarize the functionality of the given code snippet (the first part of the file).

2. **Initial Code Scan (Skimming for Keywords and Structures):**  A quick skim reveals:
    * `package scanner`:  This immediately tells us it's related to the `go/scanner` package.
    * `import`:  Imports related packages like `go/token`, `os`, `path/filepath`, `runtime`, `strings`, and `testing`. `go/token` is a strong indicator this code deals with lexical tokens.
    * `var fset = token.NewFileSet()`:  A `FileSet` is used to manage source files and their positions.
    * `const /* class */ (...)`: Defines constants related to token classes (special, literal, operator, keyword).
    * `func tokenclass(tok token.Token) int`:  A function to categorize tokens.
    * `type elt struct`:  A structure likely representing an expected token with its type, literal value, and class.
    * `var tokens = []elt{ ... }`:  A large slice of `elt` structs. This looks like a comprehensive list of various Go language tokens and their corresponding string representations. This is a *huge* clue about the code's purpose.
    * `const whitespace = ...`: Defines whitespace used to separate tokens in the test source.
    * `var source = func() []byte { ... }()`:  Dynamically constructs a source string by concatenating the literal values of tokens with whitespace in between. This strongly suggests this code is *testing* the scanner by feeding it pre-defined sequences of tokens.
    * `func newlineCount(s string) int`: Utility to count newlines.
    * `func checkPos(...)`:  A function to verify the position (filename, offset, line, column) of a token.
    * `func TestScan(t *testing.T)`:  A test function, confirming this is a test file. This function initializes a scanner and iterates through the expected tokens, comparing the results of `s.Scan()`.
    * `func TestStripCR(t *testing.T)`:  Another test function, specifically for stripping carriage returns.
    * `func checkSemi(...)`:  A function related to checking semicolon insertion.
    * `var semicolonTests = [...]struct{ input, want string }{ ... }`: Test cases for semicolon insertion.
    * `func TestSemicolons(t *testing.T)`:  Tests the semicolon insertion logic.
    * `type segment struct`:  A structure to define segments of source code for line directive testing.
    * `var segments = []segment{ ... }`: Test cases for line directives.
    * `func TestLineDirectives(t *testing.T)`: Tests line directive handling.
    * `func testSegments(...)`:  Helper function to run line directive tests.
    * `var invalidSegments = []segment{ ... }`: Test cases for *invalid* line directives.
    * `func TestInvalidLineDirectives(t *testing.T)`: Tests handling of invalid line directives.
    * `func TestInit(t *testing.T)`: Tests initializing the scanner multiple times.
    * `func TestStdErrorHandler(t *testing.T)`: Tests the standard error handler.
    * `type errorCollector struct`:  A structure to collect scanner errors.
    * `func checkError(...)`:  Helper to check for specific scanner errors.
    * `var errors = []struct{ ... }{ ... }`: A large list of test cases for various scanner errors.
    * `func TestScanErrors(t *testing.T)`: Tests the error reporting of the scanner.
    * `func TestIssue...`:  Test functions for specific reported issues.
    * `func BenchmarkScan(...)`: Benchmark for scanning.
    * `func BenchmarkScanFiles(...)`: Benchmark for scanning larger files.
    * `func TestNumbers(...)`: Tests scanning of various number formats.

3. **Inferring the Go Language Feature:** Based on the package name (`scanner`), the focus on tokens, and the test cases covering various lexical elements of Go (identifiers, literals, operators, keywords, comments, semicolons, line directives, and error conditions), it's clear this code is part of the implementation and testing of the **Go language scanner (lexical analyzer)**.

4. **Providing Go Code Examples (Illustrative):**  To demonstrate the scanner's functionality, we can create simple examples of Go code snippets and explain how the scanner would tokenize them.

5. **Command-Line Arguments (Not Applicable):**  This code is a test file. It doesn't directly process command-line arguments. The `go test` command is used to run it, but the test file itself doesn't handle specific flags.

6. **Potential User Errors (Focus on Scanner Users - Developers):**  Consider common mistakes developers might make that the scanner would catch. Examples include:
    * Unterminated string or rune literals.
    * Invalid escape sequences.
    * Illegal characters.
    * Incorrect number formats.

7. **Summarizing Functionality (for Part 1):**  Focus on the elements present in the provided code snippet. It sets up the testing environment, defines expected tokens, constructs a test source, and includes a basic test function (`TestScan`). It doesn't yet cover semicolon insertion or line directives.

8. **Structuring the Answer:** Organize the findings logically, addressing each part of the request. Use clear and concise language. Provide code examples that are easy to understand.

**Self-Correction/Refinement:**

* **Initial thought:**  Maybe this is *just* about tokenizing.
* **Correction:**  Realized the inclusion of `TestSemicolons` and `TestLineDirectives` means it's testing more than just basic tokenization, but also features like automatic semicolon insertion and handling of line directives. However, *this specific snippet* (Part 1) only contains the basic tokenization tests. The broader file covers more.

* **Initial thought:**  Focus heavily on the `Scan()` function.
* **Refinement:** Recognize the importance of the `tokens` slice as the *source of truth* for the expected behavior of the scanner. The `TestScan` function primarily compares the scanner's output to this predefined data.

By following this thought process, we can systematically analyze the code snippet and provide a comprehensive and accurate answer to the user's request.
这是 `go/src/go/scanner/scanner_test.go` 文件的一部分，它主要的功能是**测试 Go 语言的词法分析器（Scanner）**。

**具体功能归纳:**

1. **定义了用于测试的常量和数据结构:**
   - `special`, `literal`, `operator`, `keyword` 这些常量定义了词法单元的类别。
   - `tokenclass` 函数根据 `token.Token` 判断其所属的类别。
   - `elt` 结构体用于表示一个预期的词法单元，包含其 `token.Token` 类型、字面值 (`lit`) 和类别 (`class`)。
   - `tokens` 变量是一个 `elt` 结构体的切片，包含了大量预期的 Go 语言词法单元及其对应的字面值和类别。这个 `tokens` 切片是测试的核心数据，覆盖了各种合法的 Go 语言 token，包括注释、标识符、字面量（整数、浮点数、复数、字符、字符串）、操作符、分隔符和关键字。
   - `whitespace` 定义了用于分隔测试用例中 token 的空白符。
   - `source` 变量是一个通过拼接 `tokens` 中的字面值和 `whitespace` 构建出来的完整的测试源代码字符串。

2. **提供了用于比较扫描结果的辅助函数:**
   - `newlineCount` 函数用于计算字符串中的换行符数量。
   - `checkPos` 函数用于比较扫描器返回的词法单元的位置信息（文件名、偏移量、行号、列号）与预期的位置信息是否一致。

3. **实现了基本的扫描测试用例 `TestScan`:**
   - 该测试用例初始化一个 `Scanner`，并使用预先构建的 `source` 作为输入。
   - 它逐个调用 `s.Scan()` 方法来扫描词法单元。
   - 对于每个扫描到的词法单元，它会检查其位置、token 类型、类别和字面值是否与 `tokens` 变量中预期的值相符。

**可以推理出它是什么 Go 语言功能的实现:**

基于其测试内容，可以推断出这部分代码是用于测试 **`go/scanner` 包中的 `Scanner` 类型** 的功能。`Scanner` 类型是 Go 语言标准库中用于执行词法分析的关键组件。它的主要职责是将输入的源代码文本分解成一个个独立的词法单元（token）。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"go/scanner"
	"go/token"
)

func main() {
	src := []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"Hello, Go!\")\n}\n")
	fset := token.NewFileSet()
	file := fset.AddFile("hello.go", fset.Base(), len(src))

	var s scanner.Scanner
	s.Init(file, src, nil, scanner.ScanComments) // 初始化 Scanner，可以设置扫描注释

	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		fmt.Printf("%s\t%s\t%q\n", fset.Position(pos), tok, lit)
	}
}
```

**假设的输入与输出:**

对于上述代码示例，`Scanner` 的输出（部分）可能如下：

```
hello.go:1:1	PACKAGE	"package"
hello.go:1:9	IDENT	"main"
hello.go:3:1	IMPORT	"import"
hello.go:3:8	STRING	"\"fmt\""
hello.go:5:1	FUNC	"func"
hello.go:5:6	IDENT	"main"
hello.go:5:10	LPAREN	"("
hello.go:5:11	RPAREN	")"
hello.go:5:13	LBRACE	"{"
hello.go:6:2	IDENT	"fmt"
hello.go:6:5	PERIOD	"."
hello.go:6:6	IDENT	"Println"
hello.go:6:13	LPAREN	"("
hello.go:6:14	STRING	"\"Hello, Go!\""
hello.go:6:26	RPAREN	")"
hello.go:7:1	RBRACE	"}"
```

**代码推理:**

`TestScan` 函数的核心逻辑是：

1. **初始化 Scanner:**  创建一个 `scanner.Scanner` 实例，并使用 `Init` 方法设置其输入源 (`source`)、文件名、错误处理函数等。`ScanComments|dontInsertSemis` 是一些扫描模式的标志，表示扫描注释但不自动插入分号。
2. **循环扫描:**  在一个循环中不断调用 `s.Scan()`。`Scan()` 方法会返回当前扫描到的词法单元的位置 (`pos`)、token 类型 (`tok`) 和字面值 (`lit`)。
3. **断言比较:**  对于每个扫描到的 token，`TestScan` 函数会将其与 `tokens` 切片中预期的值进行比较，包括位置信息（通过 `checkPos` 函数）、token 类型、token 类别（通过 `tokenclass` 函数）和字面值。
4. **位置更新:**  在每次成功扫描后，会根据当前 token 的长度和分隔符的长度来更新预期的下一个 token 的位置信息。

**功能归纳 (针对提供的代码片段):**

这部分 `scanner_test.go` 代码的主要功能是**验证 `go/scanner` 包中的 `Scanner` 类型能够正确地将 Go 源代码分解成预期的词法单元**。它通过定义一系列预期的 token 和构建测试源代码，然后使用 `Scanner` 进行扫描，并逐个比对扫描结果与预期值，从而确保词法分析器的正确性。

由于这是第 1 部分，它主要集中在**基本的 token 扫描**，还没有涉及到更复杂的特性，例如自动分号插入或更细致的错误处理测试（这些可能会在第 2 部分中出现）。

Prompt: 
```
这是路径为go/src/go/scanner/scanner_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scanner

import (
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var fset = token.NewFileSet()

const /* class */ (
	special = iota
	literal
	operator
	keyword
)

func tokenclass(tok token.Token) int {
	switch {
	case tok.IsLiteral():
		return literal
	case tok.IsOperator():
		return operator
	case tok.IsKeyword():
		return keyword
	}
	return special
}

type elt struct {
	tok   token.Token
	lit   string
	class int
}

var tokens = []elt{
	// Special tokens
	{token.COMMENT, "/* a comment */", special},
	{token.COMMENT, "// a comment \n", special},
	{token.COMMENT, "/*\r*/", special},
	{token.COMMENT, "/**\r/*/", special}, // issue 11151
	{token.COMMENT, "/**\r\r/*/", special},
	{token.COMMENT, "//\r\n", special},

	// Identifiers and basic type literals
	{token.IDENT, "foobar", literal},
	{token.IDENT, "a۰۱۸", literal},
	{token.IDENT, "foo६४", literal},
	{token.IDENT, "bar９８７６", literal},
	{token.IDENT, "ŝ", literal},    // was bug (issue 4000)
	{token.IDENT, "ŝfoo", literal}, // was bug (issue 4000)
	{token.INT, "0", literal},
	{token.INT, "1", literal},
	{token.INT, "123456789012345678890", literal},
	{token.INT, "01234567", literal},
	{token.INT, "0xcafebabe", literal},
	{token.FLOAT, "0.", literal},
	{token.FLOAT, ".0", literal},
	{token.FLOAT, "3.14159265", literal},
	{token.FLOAT, "1e0", literal},
	{token.FLOAT, "1e+100", literal},
	{token.FLOAT, "1e-100", literal},
	{token.FLOAT, "2.71828e-1000", literal},
	{token.IMAG, "0i", literal},
	{token.IMAG, "1i", literal},
	{token.IMAG, "012345678901234567889i", literal},
	{token.IMAG, "123456789012345678890i", literal},
	{token.IMAG, "0.i", literal},
	{token.IMAG, ".0i", literal},
	{token.IMAG, "3.14159265i", literal},
	{token.IMAG, "1e0i", literal},
	{token.IMAG, "1e+100i", literal},
	{token.IMAG, "1e-100i", literal},
	{token.IMAG, "2.71828e-1000i", literal},
	{token.CHAR, "'a'", literal},
	{token.CHAR, "'\\000'", literal},
	{token.CHAR, "'\\xFF'", literal},
	{token.CHAR, "'\\uff16'", literal},
	{token.CHAR, "'\\U0000ff16'", literal},
	{token.STRING, "`foobar`", literal},
	{token.STRING, "`" + `foo
	                        bar` +
		"`",
		literal,
	},
	{token.STRING, "`\r`", literal},
	{token.STRING, "`foo\r\nbar`", literal},

	// Operators and delimiters
	{token.ADD, "+", operator},
	{token.SUB, "-", operator},
	{token.MUL, "*", operator},
	{token.QUO, "/", operator},
	{token.REM, "%", operator},

	{token.AND, "&", operator},
	{token.OR, "|", operator},
	{token.XOR, "^", operator},
	{token.SHL, "<<", operator},
	{token.SHR, ">>", operator},
	{token.AND_NOT, "&^", operator},

	{token.ADD_ASSIGN, "+=", operator},
	{token.SUB_ASSIGN, "-=", operator},
	{token.MUL_ASSIGN, "*=", operator},
	{token.QUO_ASSIGN, "/=", operator},
	{token.REM_ASSIGN, "%=", operator},

	{token.AND_ASSIGN, "&=", operator},
	{token.OR_ASSIGN, "|=", operator},
	{token.XOR_ASSIGN, "^=", operator},
	{token.SHL_ASSIGN, "<<=", operator},
	{token.SHR_ASSIGN, ">>=", operator},
	{token.AND_NOT_ASSIGN, "&^=", operator},

	{token.LAND, "&&", operator},
	{token.LOR, "||", operator},
	{token.ARROW, "<-", operator},
	{token.INC, "++", operator},
	{token.DEC, "--", operator},

	{token.EQL, "==", operator},
	{token.LSS, "<", operator},
	{token.GTR, ">", operator},
	{token.ASSIGN, "=", operator},
	{token.NOT, "!", operator},

	{token.NEQ, "!=", operator},
	{token.LEQ, "<=", operator},
	{token.GEQ, ">=", operator},
	{token.DEFINE, ":=", operator},
	{token.ELLIPSIS, "...", operator},

	{token.LPAREN, "(", operator},
	{token.LBRACK, "[", operator},
	{token.LBRACE, "{", operator},
	{token.COMMA, ",", operator},
	{token.PERIOD, ".", operator},

	{token.RPAREN, ")", operator},
	{token.RBRACK, "]", operator},
	{token.RBRACE, "}", operator},
	{token.SEMICOLON, ";", operator},
	{token.COLON, ":", operator},
	{token.TILDE, "~", operator},

	// Keywords
	{token.BREAK, "break", keyword},
	{token.CASE, "case", keyword},
	{token.CHAN, "chan", keyword},
	{token.CONST, "const", keyword},
	{token.CONTINUE, "continue", keyword},

	{token.DEFAULT, "default", keyword},
	{token.DEFER, "defer", keyword},
	{token.ELSE, "else", keyword},
	{token.FALLTHROUGH, "fallthrough", keyword},
	{token.FOR, "for", keyword},

	{token.FUNC, "func", keyword},
	{token.GO, "go", keyword},
	{token.GOTO, "goto", keyword},
	{token.IF, "if", keyword},
	{token.IMPORT, "import", keyword},

	{token.INTERFACE, "interface", keyword},
	{token.MAP, "map", keyword},
	{token.PACKAGE, "package", keyword},
	{token.RANGE, "range", keyword},
	{token.RETURN, "return", keyword},

	{token.SELECT, "select", keyword},
	{token.STRUCT, "struct", keyword},
	{token.SWITCH, "switch", keyword},
	{token.TYPE, "type", keyword},
	{token.VAR, "var", keyword},
}

const whitespace = "  \t  \n\n\n" // to separate tokens

var source = func() []byte {
	var src []byte
	for _, t := range tokens {
		src = append(src, t.lit...)
		src = append(src, whitespace...)
	}
	return src
}()

func newlineCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			n++
		}
	}
	return n
}

func checkPos(t *testing.T, lit string, p token.Pos, expected token.Position) {
	pos := fset.Position(p)
	// Check cleaned filenames so that we don't have to worry about
	// different os.PathSeparator values.
	if pos.Filename != expected.Filename && filepath.Clean(pos.Filename) != filepath.Clean(expected.Filename) {
		t.Errorf("bad filename for %q: got %s, expected %s", lit, pos.Filename, expected.Filename)
	}
	if pos.Offset != expected.Offset {
		t.Errorf("bad position for %q: got %d, expected %d", lit, pos.Offset, expected.Offset)
	}
	if pos.Line != expected.Line {
		t.Errorf("bad line for %q: got %d, expected %d", lit, pos.Line, expected.Line)
	}
	if pos.Column != expected.Column {
		t.Errorf("bad column for %q: got %d, expected %d", lit, pos.Column, expected.Column)
	}
}

// Verify that calling Scan() provides the correct results.
func TestScan(t *testing.T) {
	whitespace_linecount := newlineCount(whitespace)

	// error handler
	eh := func(_ token.Position, msg string) {
		t.Errorf("error handler called (msg = %s)", msg)
	}

	// verify scan
	var s Scanner
	s.Init(fset.AddFile("", fset.Base(), len(source)), source, eh, ScanComments|dontInsertSemis)

	// set up expected position
	epos := token.Position{
		Filename: "",
		Offset:   0,
		Line:     1,
		Column:   1,
	}

	index := 0
	for {
		pos, tok, lit := s.Scan()

		// check position
		if tok == token.EOF {
			// correction for EOF
			epos.Line = newlineCount(string(source))
			epos.Column = 2
		}
		checkPos(t, lit, pos, epos)

		// check token
		e := elt{token.EOF, "", special}
		if index < len(tokens) {
			e = tokens[index]
			index++
		}
		if tok != e.tok {
			t.Errorf("bad token for %q: got %s, expected %s", lit, tok, e.tok)
		}

		// check token class
		if tokenclass(tok) != e.class {
			t.Errorf("bad class for %q: got %d, expected %d", lit, tokenclass(tok), e.class)
		}

		// check literal
		elit := ""
		switch e.tok {
		case token.COMMENT:
			// no CRs in comments
			elit = string(stripCR([]byte(e.lit), e.lit[1] == '*'))
			//-style comment literal doesn't contain newline
			if elit[1] == '/' {
				elit = elit[0 : len(elit)-1]
			}
		case token.IDENT:
			elit = e.lit
		case token.SEMICOLON:
			elit = ";"
		default:
			if e.tok.IsLiteral() {
				// no CRs in raw string literals
				elit = e.lit
				if elit[0] == '`' {
					elit = string(stripCR([]byte(elit), false))
				}
			} else if e.tok.IsKeyword() {
				elit = e.lit
			}
		}
		if lit != elit {
			t.Errorf("bad literal for %q: got %q, expected %q", lit, lit, elit)
		}

		if tok == token.EOF {
			break
		}

		// update position
		epos.Offset += len(e.lit) + len(whitespace)
		epos.Line += newlineCount(e.lit) + whitespace_linecount

	}

	if s.ErrorCount != 0 {
		t.Errorf("found %d errors", s.ErrorCount)
	}
}

func TestStripCR(t *testing.T) {
	for _, test := range []struct{ have, want string }{
		{"//\n", "//\n"},
		{"//\r\n", "//\n"},
		{"//\r\r\r\n", "//\n"},
		{"//\r*\r/\r\n", "//*/\n"},
		{"/**/", "/**/"},
		{"/*\r/*/", "/*/*/"},
		{"/*\r*/", "/**/"},
		{"/**\r/*/", "/**\r/*/"},
		{"/*\r/\r*\r/*/", "/*/*\r/*/"},
		{"/*\r\r\r\r*/", "/**/"},
	} {
		got := string(stripCR([]byte(test.have), len(test.have) >= 2 && test.have[1] == '*'))
		if got != test.want {
			t.Errorf("stripCR(%q) = %q; want %q", test.have, got, test.want)
		}
	}
}

func checkSemi(t *testing.T, input, want string, mode Mode) {
	if mode&ScanComments == 0 {
		want = strings.ReplaceAll(want, "COMMENT ", "")
		want = strings.ReplaceAll(want, " COMMENT", "") // if at end
		want = strings.ReplaceAll(want, "COMMENT", "")  // if sole token
	}

	file := fset.AddFile("TestSemis", fset.Base(), len(input))
	var scan Scanner
	scan.Init(file, []byte(input), nil, mode)
	var tokens []string
	for {
		pos, tok, lit := scan.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.SEMICOLON && lit != ";" {
			// Artificial semicolon:
			// assert that position is EOF or that of a newline.
			off := file.Offset(pos)
			if off != len(input) && input[off] != '\n' {
				t.Errorf("scanning <<%s>>, got SEMICOLON at offset %d, want newline or EOF", input, off)
			}
		}
		lit = tok.String() // "\n" => ";"
		tokens = append(tokens, lit)
	}
	if got := strings.Join(tokens, " "); got != want {
		t.Errorf("scanning <<%s>>, got [%s], want [%s]", input, got, want)
	}
}

var semicolonTests = [...]struct{ input, want string }{
	{"", ""},
	{"\ufeff;", ";"}, // first BOM is ignored
	{";", ";"},
	{"foo\n", "IDENT ;"},
	{"123\n", "INT ;"},
	{"1.2\n", "FLOAT ;"},
	{"'x'\n", "CHAR ;"},
	{`"x"` + "\n", "STRING ;"},
	{"`x`\n", "STRING ;"},

	{"+\n", "+"},
	{"-\n", "-"},
	{"*\n", "*"},
	{"/\n", "/"},
	{"%\n", "%"},

	{"&\n", "&"},
	{"|\n", "|"},
	{"^\n", "^"},
	{"<<\n", "<<"},
	{">>\n", ">>"},
	{"&^\n", "&^"},

	{"+=\n", "+="},
	{"-=\n", "-="},
	{"*=\n", "*="},
	{"/=\n", "/="},
	{"%=\n", "%="},

	{"&=\n", "&="},
	{"|=\n", "|="},
	{"^=\n", "^="},
	{"<<=\n", "<<="},
	{">>=\n", ">>="},
	{"&^=\n", "&^="},

	{"&&\n", "&&"},
	{"||\n", "||"},
	{"<-\n", "<-"},
	{"++\n", "++ ;"},
	{"--\n", "-- ;"},

	{"==\n", "=="},
	{"<\n", "<"},
	{">\n", ">"},
	{"=\n", "="},
	{"!\n", "!"},

	{"!=\n", "!="},
	{"<=\n", "<="},
	{">=\n", ">="},
	{":=\n", ":="},
	{"...\n", "..."},

	{"(\n", "("},
	{"[\n", "["},
	{"{\n", "{"},
	{",\n", ","},
	{".\n", "."},

	{")\n", ") ;"},
	{"]\n", "] ;"},
	{"}\n", "} ;"},
	{";\n", ";"},
	{":\n", ":"},

	{"break\n", "break ;"},
	{"case\n", "case"},
	{"chan\n", "chan"},
	{"const\n", "const"},
	{"continue\n", "continue ;"},

	{"default\n", "default"},
	{"defer\n", "defer"},
	{"else\n", "else"},
	{"fallthrough\n", "fallthrough ;"},
	{"for\n", "for"},

	{"func\n", "func"},
	{"go\n", "go"},
	{"goto\n", "goto"},
	{"if\n", "if"},
	{"import\n", "import"},

	{"interface\n", "interface"},
	{"map\n", "map"},
	{"package\n", "package"},
	{"range\n", "range"},
	{"return\n", "return ;"},

	{"select\n", "select"},
	{"struct\n", "struct"},
	{"switch\n", "switch"},
	{"type\n", "type"},
	{"var\n", "var"},

	{"foo//comment\n", "IDENT COMMENT ;"},
	{"foo//comment", "IDENT COMMENT ;"},
	{"foo/*comment*/\n", "IDENT COMMENT ;"},
	{"foo/*\n*/", "IDENT COMMENT ;"},
	{"foo/*comment*/    \n", "IDENT COMMENT ;"},
	{"foo/*\n*/    ", "IDENT COMMENT ;"},

	{"foo    // comment\n", "IDENT COMMENT ;"},
	{"foo    // comment", "IDENT COMMENT ;"},
	{"foo    /*comment*/\n", "IDENT COMMENT ;"},
	{"foo    /*\n*/", "IDENT COMMENT ;"},
	{"foo    /*  */ /* \n */ bar/**/\n", "IDENT COMMENT COMMENT ; IDENT COMMENT ;"},
	{"foo    /*0*/ /*1*/ /*2*/\n", "IDENT COMMENT COMMENT COMMENT ;"},

	{"foo    /*comment*/    \n", "IDENT COMMENT ;"},
	{"foo    /*0*/ /*1*/ /*2*/    \n", "IDENT COMMENT COMMENT COMMENT ;"},
	{"foo	/**/ /*-------------*/       /*----\n*/bar       /*  \n*/baa\n", "IDENT COMMENT COMMENT COMMENT ; IDENT COMMENT ; IDENT ;"},
	{"foo    /* an EOF terminates a line */", "IDENT COMMENT ;"},
	{"foo    /* an EOF terminates a line */ /*", "IDENT COMMENT COMMENT ;"},
	{"foo    /* an EOF terminates a line */ //", "IDENT COMMENT COMMENT ;"},

	{"package main\n\nfunc main() {\n\tif {\n\t\treturn /* */ }\n}\n", "package IDENT ; func IDENT ( ) { if { return COMMENT } ; } ;"},
	{"package main", "package IDENT ;"},
}

func TestSemicolons(t *testing.T) {
	for _, test := range semicolonTests {
		input, want := test.input, test.want
		checkSemi(t, input, want, 0)
		checkSemi(t, input, want, ScanComments)

		// if the input ended in newlines, the input must tokenize the
		// same with or without those newlines
		for i := len(input) - 1; i >= 0 && input[i] == '\n'; i-- {
			checkSemi(t, input[0:i], want, 0)
			checkSemi(t, input[0:i], want, ScanComments)
		}
	}
}

type segment struct {
	srcline      string // a line of source text
	filename     string // filename for current token; error message for invalid line directives
	line, column int    // line and column for current token; error position for invalid line directives
}

var segments = []segment{
	// exactly one token per line since the test consumes one token per segment
	{"  line1", "TestLineDirectives", 1, 3},
	{"\nline2", "TestLineDirectives", 2, 1},
	{"\nline3  //line File1.go:100", "TestLineDirectives", 3, 1}, // bad line comment, ignored
	{"\nline4", "TestLineDirectives", 4, 1},
	{"\n//line File1.go:100\n  line100", "File1.go", 100, 0},
	{"\n//line  \t :42\n  line1", " \t ", 42, 0},
	{"\n//line File2.go:200\n  line200", "File2.go", 200, 0},
	{"\n//line foo\t:42\n  line42", "foo\t", 42, 0},
	{"\n //line foo:42\n  line43", "foo\t", 44, 0}, // bad line comment, ignored (use existing, prior filename)
	{"\n//line foo 42\n  line44", "foo\t", 46, 0},  // bad line comment, ignored (use existing, prior filename)
	{"\n//line /bar:42\n  line45", "/bar", 42, 0},
	{"\n//line ./foo:42\n  line46", "foo", 42, 0},
	{"\n//line a/b/c/File1.go:100\n  line100", "a/b/c/File1.go", 100, 0},
	{"\n//line c:\\bar:42\n  line200", "c:\\bar", 42, 0},
	{"\n//line c:\\dir\\File1.go:100\n  line201", "c:\\dir\\File1.go", 100, 0},

	// tests for new line directive syntax
	{"\n//line :100\na1", "", 100, 0}, // missing filename means empty filename
	{"\n//line bar:100\nb1", "bar", 100, 0},
	{"\n//line :100:10\nc1", "bar", 100, 10}, // missing filename means current filename
	{"\n//line foo:100:10\nd1", "foo", 100, 10},

	{"\n/*line :100*/a2", "", 100, 0}, // missing filename means empty filename
	{"\n/*line bar:100*/b2", "bar", 100, 0},
	{"\n/*line :100:10*/c2", "bar", 100, 10}, // missing filename means current filename
	{"\n/*line foo:100:10*/d2", "foo", 100, 10},
	{"\n/*line foo:100:10*/    e2", "foo", 100, 14}, // line-directive relative column
	{"\n/*line foo:100:10*/\n\nf2", "foo", 102, 1},  // absolute column since on new line
}

var dirsegments = []segment{
	// exactly one token per line since the test consumes one token per segment
	{"  line1", "TestLineDir/TestLineDirectives", 1, 3},
	{"\n//line File1.go:100\n  line100", "TestLineDir/File1.go", 100, 0},
}

var dirUnixSegments = []segment{
	{"\n//line /bar:42\n  line42", "/bar", 42, 0},
}

var dirWindowsSegments = []segment{
	{"\n//line c:\\bar:42\n  line42", "c:\\bar", 42, 0},
}

// Verify that line directives are interpreted correctly.
func TestLineDirectives(t *testing.T) {
	testSegments(t, segments, "TestLineDirectives")
	testSegments(t, dirsegments, "TestLineDir/TestLineDirectives")
	if runtime.GOOS == "windows" {
		testSegments(t, dirWindowsSegments, "TestLineDir/TestLineDirectives")
	} else {
		testSegments(t, dirUnixSegments, "TestLineDir/TestLineDirectives")
	}
}

func testSegments(t *testing.T, segments []segment, filename string) {
	var src string
	for _, e := range segments {
		src += e.srcline
	}

	// verify scan
	var S Scanner
	file := fset.AddFile(filename, fset.Base(), len(src))
	S.Init(file, []byte(src), func(pos token.Position, msg string) { t.Error(Error{pos, msg}) }, dontInsertSemis)
	for _, s := range segments {
		p, _, lit := S.Scan()
		pos := file.Position(p)
		checkPos(t, lit, p, token.Position{
			Filename: s.filename,
			Offset:   pos.Offset,
			Line:     s.line,
			Column:   s.column,
		})
	}

	if S.ErrorCount != 0 {
		t.Errorf("got %d errors", S.ErrorCount)
	}
}

// The filename is used for the error message in these test cases.
// The first line directive is valid and used to control the expected error line.
var invalidSegments = []segment{
	{"\n//line :1:1\n//line foo:42 extra text\ndummy", "invalid line number: 42 extra text", 1, 12},
	{"\n//line :2:1\n//line foobar:\ndummy", "invalid line number: ", 2, 15},
	{"\n//line :5:1\n//line :0\ndummy", "invalid line number: 0", 5, 9},
	{"\n//line :10:1\n//line :1:0\ndummy", "invalid column number: 0", 10, 11},
	{"\n//line :1:1\n//line :foo:0\ndummy", "invalid line number: 0", 1, 13}, // foo is considered part of the filename
}

// Verify that invalid line directives get the correct error message.
func TestInvalidLineDirectives(t *testing.T) {
	// make source
	var src string
	for _, e := range invalidSegments {
		src += e.srcline
	}

	// verify scan
	var S Scanner
	var s segment // current segment
	file := fset.AddFile(filepath.Join("dir", "TestInvalidLineDirectives"), fset.Base(), len(src))
	S.Init(file, []byte(src), func(pos token.Position, msg string) {
		if msg != s.filename {
			t.Errorf("got error %q; want %q", msg, s.filename)
		}
		if pos.Line != s.line || pos.Column != s.column {
			t.Errorf("got position %d:%d; want %d:%d", pos.Line, pos.Column, s.line, s.column)
		}
	}, dontInsertSemis)
	for _, s = range invalidSegments {
		S.Scan()
	}

	if S.ErrorCount != len(invalidSegments) {
		t.Errorf("got %d errors; want %d", S.ErrorCount, len(invalidSegments))
	}
}

// Verify that initializing the same scanner more than once works correctly.
func TestInit(t *testing.T) {
	var s Scanner

	// 1st init
	src1 := "if true { }"
	f1 := fset.AddFile("src1", fset.Base(), len(src1))
	s.Init(f1, []byte(src1), nil, dontInsertSemis)
	if f1.Size() != len(src1) {
		t.Errorf("bad file size: got %d, expected %d", f1.Size(), len(src1))
	}
	s.Scan()              // if
	s.Scan()              // true
	_, tok, _ := s.Scan() // {
	if tok != token.LBRACE {
		t.Errorf("bad token: got %s, expected %s", tok, token.LBRACE)
	}

	// 2nd init
	src2 := "go true { ]"
	f2 := fset.AddFile("src2", fset.Base(), len(src2))
	s.Init(f2, []byte(src2), nil, dontInsertSemis)
	if f2.Size() != len(src2) {
		t.Errorf("bad file size: got %d, expected %d", f2.Size(), len(src2))
	}
	_, tok, _ = s.Scan() // go
	if tok != token.GO {
		t.Errorf("bad token: got %s, expected %s", tok, token.GO)
	}

	if s.ErrorCount != 0 {
		t.Errorf("found %d errors", s.ErrorCount)
	}
}

func TestStdErrorHandler(t *testing.T) {
	const src = "@\n" + // illegal character, cause an error
		"@ @\n" + // two errors on the same line
		"//line File2:20\n" +
		"@\n" + // different file, but same line
		"//line File2:1\n" +
		"@ @\n" + // same file, decreasing line number
		"//line File1:1\n" +
		"@ @ @" // original file, line 1 again

	var list ErrorList
	eh := func(pos token.Position, msg string) { list.Add(pos, msg) }

	var s Scanner
	s.Init(fset.AddFile("File1", fset.Base(), len(src)), []byte(src), eh, dontInsertSemis)
	for {
		if _, tok, _ := s.Scan(); tok == token.EOF {
			break
		}
	}

	if len(list) != s.ErrorCount {
		t.Errorf("found %d errors, expected %d", len(list), s.ErrorCount)
	}

	if len(list) != 9 {
		t.Errorf("found %d raw errors, expected 9", len(list))
		PrintError(os.Stderr, list)
	}

	list.Sort()
	if len(list) != 9 {
		t.Errorf("found %d sorted errors, expected 9", len(list))
		PrintError(os.Stderr, list)
	}

	list.RemoveMultiples()
	if len(list) != 4 {
		t.Errorf("found %d one-per-line errors, expected 4", len(list))
		PrintError(os.Stderr, list)
	}
}

type errorCollector struct {
	cnt int            // number of errors encountered
	msg string         // last error message encountered
	pos token.Position // last error position encountered
}

func checkError(t *testing.T, src string, tok token.Token, pos int, lit, err string) {
	var s Scanner
	var h errorCollector
	eh := func(pos token.Position, msg string) {
		h.cnt++
		h.msg = msg
		h.pos = pos
	}
	s.Init(fset.AddFile("", fset.Base(), len(src)), []byte(src), eh, ScanComments|dontInsertSemis)
	_, tok0, lit0 := s.Scan()
	if tok0 != tok {
		t.Errorf("%q: got %s, expected %s", src, tok0, tok)
	}
	if tok0 != token.ILLEGAL && lit0 != lit {
		t.Errorf("%q: got literal %q, expected %q", src, lit0, lit)
	}
	cnt := 0
	if err != "" {
		cnt = 1
	}
	if h.cnt != cnt {
		t.Errorf("%q: got cnt %d, expected %d", src, h.cnt, cnt)
	}
	if h.msg != err {
		t.Errorf("%q: got msg %q, expected %q", src, h.msg, err)
	}
	if h.pos.Offset != pos {
		t.Errorf("%q: got offset %d, expected %d", src, h.pos.Offset, pos)
	}
}

var errors = []struct {
	src string
	tok token.Token
	pos int
	lit string
	err string
}{
	{"\a", token.ILLEGAL, 0, "", "illegal character U+0007"},
	{`#`, token.ILLEGAL, 0, "", "illegal character U+0023 '#'"},
	{`…`, token.ILLEGAL, 0, "", "illegal character U+2026 '…'"},
	{"..", token.PERIOD, 0, "", ""}, // two periods, not invalid token (issue #28112)
	{`' '`, token.CHAR, 0, `' '`, ""},
	{`''`, token.CHAR, 0, `''`, "illegal rune literal"},
	{`'12'`, token.CHAR, 0, `'12'`, "illegal rune literal"},
	{`'123'`, token.CHAR, 0, `'123'`, "illegal rune literal"},
	{`'\0'`, token.CHAR, 3, `'\0'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\07'`, token.CHAR, 4, `'\07'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\8'`, token.CHAR, 2, `'\8'`, "unknown escape sequence"},
	{`'\08'`, token.CHAR, 3, `'\08'`, "illegal character U+0038 '8' in escape sequence"},
	{`'\x'`, token.CHAR, 3, `'\x'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\x0'`, token.CHAR, 4, `'\x0'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\x0g'`, token.CHAR, 4, `'\x0g'`, "illegal character U+0067 'g' in escape sequence"},
	{`'\u'`, token.CHAR, 3, `'\u'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\u0'`, token.CHAR, 4, `'\u0'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\u00'`, token.CHAR, 5, `'\u00'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\u000'`, token.CHAR, 6, `'\u000'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\u000`, token.CHAR, 6, `'\u000`, "escape sequence not terminated"},
	{`'\u0000'`, token.CHAR, 0, `'\u0000'`, ""},
	{`'\U'`, token.CHAR, 3, `'\U'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U0'`, token.CHAR, 4, `'\U0'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U00'`, token.CHAR, 5, `'\U00'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U000'`, token.CHAR, 6, `'\U000'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U0000'`, token.CHAR, 7, `'\U0000'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U00000'`, token.CHAR, 8, `'\U00000'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U000000'`, token.CHAR, 9, `'\U000000'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U0000000'`, token.CHAR, 10, `'\U0000000'`, "illegal character U+0027 ''' in escape sequence"},
	{`'\U0000000`, token.CHAR, 10, `'\U0000000`, "escape sequence not terminated"},
	{`'\U00000000'`, token.CHAR, 0, `'\U00000000'`, ""},
	{`'\Uffffffff'`, token.CHAR, 2, `'\Uffffffff'`, "escape sequence is invalid Unicode code point"},
	{`'`, token.CHAR, 0, `'`, "rune literal not terminated"},
	{`'\`, token.CHAR, 2, `'\`, "escape sequence not terminated"},
	{"'\n", token.CHAR, 0, "'", "rune literal not terminated"},
	{"'\n   ", token.CHAR, 0, "'", "rune literal not terminated"},
	{`""`, token.STRING, 0, `""`, ""},
	{`"abc`, token.STRING, 0, `"abc`, "string literal not terminated"},
	{"\"abc\n", token.STRING, 0, `"abc`, "string literal not terminated"},
	{"\"abc\n   ", token.STRING, 0, `"abc`, "string literal not terminated"},
	{"``", token.STRING, 0, "``", ""},
	{"`", token.STRING, 0, "`", "raw string literal not terminated"},
	{"/**/", token.COMMENT, 0, "/**/", ""},
	{"/*", token.COMMENT, 0, "/*", "comment not terminated"},
	{"077", token.INT, 0, "077", ""},
	{"078.", token.FLOAT, 0, "078.", ""},
	{"07801234567.", token.FLOAT, 0, "07801234567.", ""},
	{"078e0", token.FLOAT, 0, "078e0", ""},
	{"0E", token.FLOAT, 2, "0E", "exponent has no digits"}, // issue 17621
	{"078", token.INT, 2, "078", "invalid digit '8' in octal literal"},
	{"07090000008", token.INT, 3, "07090000008", "invalid digit '9' in octal literal"},
	{"0x", token.INT, 2, "0x", "hexadecimal literal has no digits"},
	{"\"abc\x00def\"", token.STRING, 4, "\"abc\x00def\"", "illegal character NUL"},
	{"\"abc\x80def\"", token.STRING, 4, "\"abc\x80def\"", "illegal UTF-8 encoding"},
	{"\ufeff\ufeff", token.ILLEGAL, 3, "\ufeff\ufeff", "illegal byte order mark"},                        // only first BOM is ignored
	{"//\ufeff", token.COMMENT, 2, "//\ufeff", "illegal byte order mark"},                                // only first BOM is ignored
	{"'\ufeff" + `'`, token.CHAR, 1, "'\ufeff" + `'`, "illegal byte order mark"},                         // only first BOM is ignored
	{`"` + "abc\ufeffdef" + `"`, token.STRING, 4, `"` + "abc\ufeffdef" + `"`, "illegal byte order mark"}, // only first BOM is ignored
	{"abc\x00def", token.IDENT, 3, "abc", "illegal character NUL"},
	{"abc\x00", token.IDENT, 3, "abc", "illegal character NUL"},
	{"“abc”", token.ILLEGAL, 0, "abc", `curly quotation mark '“' (use neutral '"')`},
}

func TestScanErrors(t *testing.T) {
	for _, e := range errors {
		checkError(t, e.src, e.tok, e.pos, e.lit, e.err)
	}
}

// Verify that no comments show up as literal values when skipping comments.
func TestIssue10213(t *testing.T) {
	const src = `
		var (
			A = 1 // foo
		)

		var (
			B = 2
			// foo
		)

		var C = 3 // foo

		var D = 4
		// foo

		func anycode() {
		// foo
		}
	`
	var s Scanner
	s.Init(fset.AddFile("", fset.Base(), len(src)), []byte(src), nil, 0)
	for {
		pos, tok, lit := s.Scan()
		class := tokenclass(tok)
		if lit != "" && class != keyword && class != literal && tok != token.SEMICOLON {
			t.Errorf("%s: tok = %s, lit = %q", fset.Position(pos), tok, lit)
		}
		if tok <= token.EOF {
			break
		}
	}
}

func TestIssue28112(t *testing.T) {
	const src = "... .. 0.. .." // make sure to have stand-alone ".." immediately before EOF to test EOF behavior
	tokens := []token.Token{token.ELLIPSIS, token.PERIOD, token.PERIOD, token.FLOAT, token.PERIOD, token.PERIOD, token.PERIOD, token.EOF}
	var s Scanner
	s.Init(fset.AddFile("", fset.Base(), len(src)), []byte(src), nil, 0)
	for _, want := range tokens {
		pos, got, lit := s.Scan()
		if got != want {
			t.Errorf("%s: got %s, want %s", fset.Position(pos), got, want)
		}
		// literals expect to have a (non-empty) literal string and we don't care about other tokens for this test
		if tokenclass(got) == literal && lit == "" {
			t.Errorf("%s: for %s got empty literal string", fset.Position(pos), got)
		}
	}
}

func BenchmarkScan(b *testing.B) {
	b.StopTimer()
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(source))
	var s Scanner
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		s.Init(file, source, nil, ScanComments)
		for {
			_, tok, _ := s.Scan()
			if tok == token.EOF {
				break
			}
		}
	}
}

func BenchmarkScanFiles(b *testing.B) {
	// Scan a few arbitrary large files, and one small one, to provide some
	// variety in benchmarks.
	for _, p := range []string{
		"go/types/expr.go",
		"go/parser/parser.go",
		"net/http/server.go",
		"go/scanner/errors.go",
	} {
		b.Run(p, func(b *testing.B) {
			b.StopTimer()
			filename := filepath.Join("..", "..", filepath.FromSlash(p))
			src, err := os.ReadFile(filename)
			if err != nil {
				b.Fatal(err)
			}
			fset := token.NewFileSet()
			file := fset.AddFile(filename, fset.Base(), len(src))
			b.SetBytes(int64(len(src)))
			var s Scanner
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				s.Init(file, src, nil, ScanComments)
				for {
					_, tok, _ := s.Scan()
					if tok == token.EOF {
						break
					}
				}
			}
		})
	}
}

func TestNumbers(t *testing.T) {
	for _, test := range []struct {
		tok              token.Token
		src, tokens, err string
	}{
		// binaries
		{token.INT, "0b0", "0b0", ""},
		{token.INT, "0b1010", "0b1010", ""},
		{token.INT, "0B1110", "0B1110", ""},

		{token.INT, "0b", "0b", "binary literal has no digits"},
		{token.INT, "0b0190", "0b0190", "invalid digit '9' in binary literal"},
		{token.INT, "0b01a0", "0b01 a0", ""}, // only accept 0-9

		{token.FLOAT, "0b.", "0b.", "invalid radix point in binary literal"},
		{token.FLOAT, "0b.1", "0b.1", "invalid radix point in binary literal"},
		{token.FLOAT, "0b1.0", "0b1.0", "invalid radix point in binary literal"},
		{token.FLOAT, "0b1e10", "0b1e10", "'e' exponent requires decimal mantissa"},
		{token.FLOAT, "0b1P-1", "0b1P-1", "'P' exponent requires hexadecimal mantissa"},

		{token.IMAG, "0b10i", "0b10i", ""},
		{token.IMAG, "0b10.0i", "0b10.0i", "invalid radix point in binary literal"},

		// octals
		{token.INT, "0o0", "0o0", ""},
		{token.INT, "0o1234", "0o1234", ""},
		{token.INT, "0O1234", "0O1234", ""},

		{token.INT, "0o", "0o", "octal literal has no digits"},
		{token.INT, "0o8123", "0o8123", "invalid digit '8' in octal literal"},
		{token.INT, "0o1293", "0o1293", "invalid digit '9' in octal literal"},
		{token.INT, "0o12a3", "0o12 a3", ""}, // only accept 0-9

		{token.FLOAT, "0o.", "0o.", "invalid radix point in octal literal"},
		{token.FLOAT, "0o.2", "0o.2", "invalid radix point in octal literal"},
		{token.FLOAT, "0o1.2", "0o1.2", "invalid radix point in octal literal"},
		{token.FLOAT, "0o1E+2", "0o1E+2", "'E' exponent requires decimal mantissa"},
		{token.FLOAT, "0o1p10", "0o1p10", "'p' exponent requires hexadecimal mantissa"},

		{token.IMAG, "0o10i", "0o10i", ""},
		{token.IMAG, "0o10e0i", "0o10e0i", "'e' exponent requires decimal mantissa"},

		// 0-octals
		{token.INT, "0", "0", ""},
		{token.INT, "0123", "0123", ""},

		{token.INT, "08123", "08123", "invalid digit '8' in octal literal"},
		{token.INT, "01293", "01293", "invalid digit '9' in octal literal"},
		{token.INT, "0F.", "0 F .", ""}, // only accept 0-9
		{token.INT, "0123F.", "0123 F .", ""},
		{token.INT, "0123456x", "0123456 x", ""},

		// decimals
		{token.INT, "1", "1", ""},
		{token.INT, "1234", "1234", ""},

		{token.INT, "1f", "1 f", ""}, // only accept 0-9

		{token.IMAG, "0i", "0i", ""},
		{token.IMAG, "0678i", "0678i", ""},

		// decimal floats
		{token.FLOAT, "0.", "0.", ""},
		{token.FLOAT, "123.", "123.", ""},
		{token.FLOAT, "0123.", "0123.", ""},

		{token.FLOAT, ".0", ".0", ""},
		{token.FLOAT, ".123", ".123", ""},
		{token.FLOAT, ".0123", ".0123", ""},

		{token.FLOAT, "0.0", "0.0", ""},
		{token.FLOAT, "123.123", "123.123", ""},
		{token.FLOAT, "0123.0123", "0123.0123", ""},

		{token.FLOAT, "0e0", "0e0", ""},
		{token.FLOAT, "123e+0", "123e+0", ""},
		{token.FLOAT, "0123E-1", "0123E-1", ""},

		{token.FLOAT, "0.e+1", "0.e+1", ""},
		{token.FLOAT, "123.E-10", "123.E-10", ""},
		{token.FLOAT, "0123.e123", "0123.e123", ""},

		{token.FLOAT, ".0e-1", ".0e-1", ""},
		{token.FLOAT, ".123E+10", ".123E+10", ""},
		{token.FLOAT, ".0123E123", ".0123E123", ""},

		{token.FLOAT, "0.0e1", "0.0e1", ""},
		{token.FLOAT, "123.123E-10", "123.123E-10", ""},
		{token.FLOAT, "0123.0123e+456", "0123.0123e+456", ""},

		{token.FLOAT, "0e", "0e", "exponent has no digits"},
		{token.FLOAT, "0E+", "0E+", "exponent has no digits"},
		{token.FLOAT, "1e+f", "1e+ f", "exponent has no digits"},
		{token.FLOAT, "0p0", "0p0", "'p' exponent requires hexadecimal mantissa"},
		{token.FLOAT, "1.0P-1", "1.0P-1", "'P' exponent requires hexadecimal mantissa"},

		{token.IMAG, "0.i", "0.i", ""},
		{token.IMAG, ".123i", ".123i", ""},
		{token.IMAG, "123.123i", "123.123i", ""},
		{token.IMAG, "123e+0i", "123e+0i", ""},
		{token.IMAG, "123.E-10i", "123.E-10i", ""},
		{token.IMAG, ".123E+10i", ".123E+10i", ""},

		// hexadecimals
		{token.INT, "0x0", "0x0", ""},
		{token.INT, "0x1234", "0x1234", ""},
		{token.INT, "0xcafef00d", "0xcafef00d", ""},
		{token.INT, "0XCAFEF00D", "0XCAFEF00D", ""},

		{token.INT, "0x", "0x", "hexadecimal literal has no digits"},
		{token.INT, "0x1g", "0x1 g", ""},

		{token.IMAG, "0xf00i", "0xf00i", ""},

		// hexadecimal floats
		{token.FLOAT, "0x0p0", "0x0p0", ""},
		{token.FLOAT, "0x12efp-123", "0x12efp-123", ""},
		{token.FLOAT, "0xABCD.p+0", "0xABCD.p+0", ""},
		{token.FLOAT, "0x.0189P-0", "0x.0189P-0", ""},
		{token.FLOAT, "0x1.ffffp+1023", "0x1.ffffp+1023", ""},

		{token.FLOAT, "0x.", "0x.", "hexadecimal literal has no digits"},
		{token.FLOAT, "0x0.", "0x0.", "hexadecimal mantissa requires a 'p' exponent"},
		{token.FLOAT, "0x.0", "0x.0", "hexadecimal man
"""




```