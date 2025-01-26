Response:
Let's break down the thought process for analyzing the Go scanner test code.

1. **Understand the Goal:** The core task is to understand the purpose and functionality of the provided Go code snippet, which is a test file for the `scanner` package in the `godef` project.

2. **Identify the Core Functionality:** The filename `scanner_test.go` immediately suggests this is a testing file. The `package scanner` declaration confirms it's testing the `scanner` package. The imports like `testing`, `token`, and the structure of test functions (e.g., `TestScan`, `TestSemis`) solidify this.

3. **Analyze Key Data Structures:**

   * **`tokens` array:** This is a crucial piece of information. It's an array of `elt` structs. Each `elt` defines an expected token, its literal representation, and its class (special, literal, operator, keyword). This immediately tells us the test is designed to verify the scanner correctly identifies and categorizes different types of tokens.

   * **`whitespace` constant:**  This explains how tokens are separated in the test source string.

   * **`lines` array:** This array of strings seems to be designed for testing semicolon insertion rules. The comments with `#` and `$` provide hints.

   * **`segments` array (and `unixsegments`, `winsegments`):**  These arrays look related to testing how the scanner handles `//line` comments that modify file and line number information. The platform-specific variations are a clue about testing platform-dependent path handling.

   * **`errors` array:**  This clearly lists test cases for error handling during scanning.

4. **Examine Key Functions:**

   * **`tokenclass`:** This helper function categorizes tokens. It's a simple but important part of the testing logic.

   * **`TestScan`:** This is the main test function for basic token scanning. It constructs a test source string by concatenating the literals from the `tokens` array. It then initializes a `Scanner` and iterates through the tokens, comparing the scanned results with the expected values in the `tokens` array. The `checkPos` function confirms position information.

   * **`TestSemis`:** This function focuses on testing semicolon insertion. It iterates through the `lines` array and uses the `checkSemi` function.

   * **`checkSemi`:** This function sets up a scanner for a single line and checks if semicolons are correctly inserted (or present as indicated by `#`). The `AllowIllegalChars` and `InsertSemis` flags suggest configuration options for the scanner.

   * **`TestLineComments`:** This function tests the interpretation of `//line` comments. It constructs a source from the `segments` array and checks if the scanner correctly updates the file and line information.

   * **`TestInit`:** This tests if the scanner can be initialized multiple times correctly.

   * **`TestIllegalChars`:** This tests how the scanner handles illegal characters when the `AllowIllegalChars` flag is set.

   * **`TestStdErrorHander`:** This tests the standard error handler and different ways of collecting and reporting errors.

   * **`TestScanErrors`:** This function uses the `errors` array and the `checkError` function to verify error reporting for various invalid input scenarios.

   * **`checkError`:** This function sets up a scanner and verifies that the expected error is reported at the correct position.

5. **Infer Functionality and Provide Examples:** Based on the analysis of data structures and test functions, we can infer that the code implements the lexical scanning (tokenization) of Go source code. Provide simple Go code examples illustrating the different token types being tested (identifiers, literals, operators, keywords).

6. **Address Command-Line Arguments:**  Recognize that this is a *test* file. Go tests are typically run with the `go test` command. While the `scanner` package *might* be used in command-line tools, the *test file itself* doesn't directly process command-line arguments in the usual sense. Explain this distinction.

7. **Identify Potential Pitfalls:** Look for areas where users might make mistakes when *using* a Go scanner (though this test file itself is an internal test). Common pitfalls include:

   * **Incorrectly handling whitespace:**  The tests explicitly use whitespace to separate tokens, highlighting its importance.
   * **Misunderstanding semicolon insertion rules:** The `TestSemis` function directly addresses this.
   * **Not accounting for `//line` directives:** The `TestLineComments` function showcases this.
   * **Incorrectly interpreting error messages:** The `TestStdErrorHander` and `TestScanErrors` functions relate to this.

8. **Structure the Answer:**  Organize the information logically with clear headings: 功能, Go语言功能实现, 代码举例, 命令行参数, 易犯错的点. Use clear and concise Chinese.

9. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Double-check the code examples and explanations. Ensure all parts of the prompt have been addressed. For example, the initial prompt specifically asked about "reasoning" and "assumptions" for code inference. While the inference here is relatively direct given the test structure, explicitly mentioning that the structure of the test code itself is a strong indicator is important.
这段代码是 Go 语言 `go/scanner` 包的一部分，专门用于测试 `scanner` 包的功能。`scanner` 包的作用是将 Go 源代码分解成一系列的 token（词法单元）。

以下是它的主要功能：

1. **词法分析 (Tokenization) 功能测试:**
   - 代码的核心目标是验证 `scanner` 包能否正确地将各种 Go 语言的语法元素（例如：标识符、字面量、运算符、关键字、注释等）识别为对应的 token。
   - `tokens` 变量定义了一个包含各种 Go 语言 token 及其字面值和分类的切片。
   - `TestScan` 函数通过构造包含这些 token 的源字符串，然后使用 `scanner.Scanner` 进行扫描，并将扫描结果与预期的 token 类型、字面值和分类进行比较，从而测试基本的词法分析功能。

2. **分号插入规则测试:**
   - `TestSemis` 和 `checkSemi` 函数用于测试 Go 语言自动分号插入的规则。
   - `lines` 变量定义了一系列包含或不包含显式分号的 Go 代码行。
   - `checkSemi` 函数使用 `scanner.Scanner` 扫描这些代码行，并验证在应该插入分号的位置是否正确插入了分号。

3. **`//line` 注释处理测试:**
   - `TestLineComments` 函数测试 `scanner` 包是否能正确解析 `//line filename:line` 形式的特殊注释，并据此更新后续 token 的文件和行号信息。
   - `segments`、`unixsegments` 和 `winsegments` 变量定义了包含 `//line` 注释的不同代码片段，用于测试在不同操作系统下的路径处理。

4. **多次初始化 Scanner 测试:**
   - `TestInit` 函数验证 `scanner.Scanner` 对象是否可以被多次初始化并正确扫描不同的源代码。

5. **非法字符处理测试:**
   - `TestIllegalChars` 函数测试当 `scanner` 初始化时使用 `AllowIllegalChars` 模式时，如何处理非法的字符。

6. **错误处理测试:**
   - `TestStdErrorHander` 函数测试了默认的错误处理机制，以及如何收集和报告扫描过程中遇到的错误。
   - `TestScanErrors` 和 `checkError` 函数使用 `errors` 变量中定义的各种包含语法错误的代码片段，验证 `scanner` 能否正确识别这些错误并报告相应的错误信息和位置。

**Go 语言功能实现示例 (基于 `TestScan` 功能推理):**

这段测试代码主要验证了 Go 语言的词法分析器 (lexer) 的实现。词法分析器负责将源代码分解成一个个有意义的单元，为后续的语法分析做准备。

**假设输入:**  以下字符串是 `TestScan` 函数中构建的 `src` 变量的一部分，包含了几个不同的 token。

```go
src := "foobar  \t  \n\n\n0  \t  \n\n\n+  \t  \n\n\nbreak  \t  \n\n\n"
```

**Go 代码示例 (模拟 scanner 的行为):**

```go
package main

import (
	"fmt"
	"go/scanner"
	"go/token"
)

func main() {
	fset := token.NewFileSet()
	src := "foobar 0 +\nbreak"
	file := fset.AddFile("test.go", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, []byte(src), nil, scanner.ScanComments)

	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		fmt.Printf("Token: %s, Literal: %q, Position: %s\n", tok, lit, fset.Position(pos))
	}
}
```

**假设输出:** 上述代码会模拟 `scanner` 的行为，输出类似的结果：

```
Token: IDENT, Literal: "foobar", Position: test.go:1:1
Token: INT, Literal: "0", Position: test.go:1:8
Token: ADD, Literal: "+", Position: test.go:1:10
Token: BREAK, Literal: "break", Position: test.go:2:1
```

**代码推理:**

- `TestScan` 函数通过构建包含各种 token 的字符串 `src` 来模拟源代码输入。
- `scanner.Scanner` 的 `Init` 方法用于初始化扫描器，指定了文件集、源代码、错误处理器和扫描模式。
- `s.Scan()` 方法是扫描器的核心，它会返回当前 token 的位置、类型和字面值。
- `TestScan` 函数通过循环调用 `s.Scan()` 来遍历整个源代码，并与预期的 token 信息进行比较。
- `tokenclass` 函数用于将 token 分类为 `special`, `literal`, `operator`, 或 `keyword`，方便测试。

**命令行参数的具体处理:**

这个测试文件本身并不直接处理命令行参数。它是作为 `go test` 命令的一部分运行的。`go test` 命令会编译并运行当前目录或指定包中的所有测试文件。

当你运行 `go test ./go/scanner` 或在 `go/src/github.com/rogpeppe/godef/go/scanner/` 目录下运行 `go test` 时，Go 的测试框架会自动执行 `scanner_test.go` 中的所有以 `Test` 开头的函数。

**使用者易犯错的点 (针对 `scanner` 包的使用者，而非测试代码的使用者):**

虽然这段代码是测试代码，但它可以帮助我们理解使用 `scanner` 包时可能遇到的问题：

1. **没有正确处理错误:**  `scanner.Scanner` 在遇到无法识别的字符或不符合语法规则的情况时会报告错误。使用者需要提供一个 `ErrorHandler` 来处理这些错误，否则错误会被忽略。

   ```go
   package main

   import (
       "fmt"
       "go/scanner"
       "go/token"
   )

   type ErrorHandler struct{}

   func (h ErrorHandler) Error(pos token.Position, msg string) {
       fmt.Printf("Error at %s: %s\n", pos, msg)
   }

   func main() {
       fset := token.NewFileSet()
       src := "invalid@char"
       file := fset.AddFile("test.go", fset.Base(), len(src))
       var s scanner.Scanner
       var errHandler ErrorHandler
       s.Init(file, []byte(src), errHandler.Error, 0) // 注意这里传入了错误处理函数

       for {
           _, tok, _ := s.Scan()
           if tok == token.EOF {
               break
           }
       }
   }
   ```
   **输出:**
   ```
   Error at test.go:1:8: illegal character U+0040 '@'
   ```

2. **误解分号插入规则:** Go 语言会自动插入分号，但规则比较微妙。使用者可能会因为不理解这些规则而写出不符合预期的代码。`TestSemis` 涵盖了这些规则的测试用例。例如，在某些情况下，换行符会被解释为分号。

3. **忽略 `//line` 注释的影响:** 如果源代码中包含 `//line` 注释，`scanner` 会更新后续 token 的位置信息。如果使用者没有意识到这一点，可能会在处理 token 位置时遇到困惑。

总而言之，这段测试代码详细地验证了 `go/scanner` 包的词法分析功能，包括基本 token 识别、分号插入、特殊注释处理和错误处理等。通过阅读和理解这些测试用例，可以更深入地了解 Go 语言的词法结构以及 `scanner` 包的工作原理。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/go/scanner/scanner_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rogpeppe/godef/go/token"
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

var tokens = [...]elt{
	// Special tokens
	{token.COMMENT, "/* a comment */", special},
	{token.COMMENT, "// a comment \n", special},

	// Identifiers and basic type literals
	{token.IDENT, "foobar", literal},
	{token.IDENT, "a۰۱۸", literal},
	{token.IDENT, "foo६४", literal},
	{token.IDENT, "bar９８７６", literal},
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

type testErrorHandler struct {
	t *testing.T
}

func (h *testErrorHandler) Error(pos token.Position, msg string) {
	h.t.Errorf("Error() called (msg = %s)", msg)
}

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
	if pos.Filename != expected.Filename {
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
	// make source
	var src string
	for _, e := range tokens {
		src += e.lit + whitespace
	}
	src_linecount := newlineCount(src)
	whitespace_linecount := newlineCount(whitespace)

	// verify scan
	var s Scanner
	s.Init(fset.AddFile("", fset.Base(), len(src)), []byte(src), &testErrorHandler{t}, ScanComments)
	index := 0
	epos := token.Position{"", 0, 1, 1} // expected position
	for {
		pos, tok, lit := s.Scan()
		e := elt{token.EOF, "", special}
		if index < len(tokens) {
			e = tokens[index]
		}
		if tok == token.EOF {
			lit = "<EOF>"
			epos.Line = src_linecount
			epos.Column = 2
		}
		checkPos(t, lit, pos, epos)
		if tok != e.tok {
			t.Errorf("bad token for %q: got %s, expected %s", lit, tok.String(), e.tok.String())
		}
		if e.tok.IsLiteral() && lit != e.lit {
			t.Errorf("bad literal for %q: got %q, expected %q", lit, lit, e.lit)
		}
		if tokenclass(tok) != e.class {
			t.Errorf("bad class for %q: got %d, expected %d", lit, tokenclass(tok), e.class)
		}
		epos.Offset += len(lit) + len(whitespace)
		epos.Line += newlineCount(lit) + whitespace_linecount
		if tok == token.COMMENT && lit[1] == '/' {
			// correct for unaccounted '/n' in //-style comment
			epos.Offset++
			epos.Line++
		}
		index++
		if tok == token.EOF {
			break
		}
	}
	if s.ErrorCount != 0 {
		t.Errorf("found %d errors", s.ErrorCount)
	}
}

func checkSemi(t *testing.T, line string, mode uint) {
	var S Scanner
	file := fset.AddFile("TestSemis", fset.Base(), len(line))
	S.Init(file, []byte(line), nil, mode)
	pos, tok, lit := S.Scan()
	for tok != token.EOF {
		if tok == token.ILLEGAL {
			// the illegal token literal indicates what
			// kind of semicolon literal to expect
			semiLit := "\n"
			if lit[0] == '#' {
				semiLit = ";"
			}
			// next token must be a semicolon
			semiPos := file.Position(pos)
			semiPos.Offset++
			semiPos.Column++
			pos, tok, lit = S.Scan()
			if tok == token.SEMICOLON {
				if lit != semiLit {
					t.Errorf(`bad literal for %q: got %q, expected %q`, line, lit, semiLit)
				}
				checkPos(t, line, pos, semiPos)
			} else {
				t.Errorf("bad token for %q: got %s, expected ;", line, tok.String())
			}
		} else if tok == token.SEMICOLON {
			t.Errorf("bad token for %q: got ;, expected no ;", line)
		}
		pos, tok, lit = S.Scan()
	}
}

var lines = []string{
	// # indicates a semicolon present in the source
	// $ indicates an automatically inserted semicolon
	"",
	"#;",
	"foo$\n",
	"123$\n",
	"1.2$\n",
	"'x'$\n",
	`"x"` + "$\n",
	"`x`$\n",

	"+\n",
	"-\n",
	"*\n",
	"/\n",
	"%\n",

	"&\n",
	"|\n",
	"^\n",
	"<<\n",
	">>\n",
	"&^\n",

	"+=\n",
	"-=\n",
	"*=\n",
	"/=\n",
	"%=\n",

	"&=\n",
	"|=\n",
	"^=\n",
	"<<=\n",
	">>=\n",
	"&^=\n",

	"&&\n",
	"||\n",
	"<-\n",
	"++$\n",
	"--$\n",

	"==\n",
	"<\n",
	">\n",
	"=\n",
	"!\n",

	"!=\n",
	"<=\n",
	">=\n",
	":=\n",
	"...\n",

	"(\n",
	"[\n",
	"{\n",
	",\n",
	".\n",

	")$\n",
	"]$\n",
	"}$\n",
	"#;\n",
	":\n",

	"break$\n",
	"case\n",
	"chan\n",
	"const\n",
	"continue$\n",

	"default\n",
	"defer\n",
	"else\n",
	"fallthrough$\n",
	"for\n",

	"func\n",
	"go\n",
	"goto\n",
	"if\n",
	"import\n",

	"interface\n",
	"map\n",
	"package\n",
	"range\n",
	"return$\n",

	"select\n",
	"struct\n",
	"switch\n",
	"type\n",
	"var\n",

	"foo$//comment\n",
	"foo$//comment",
	"foo$/*comment*/\n",
	"foo$/*\n*/",
	"foo$/*comment*/    \n",
	"foo$/*\n*/    ",

	"foo    $// comment\n",
	"foo    $// comment",
	"foo    $/*comment*/\n",
	"foo    $/*\n*/",
	"foo    $/*  */ /* \n */ bar$/**/\n",
	"foo    $/*0*/ /*1*/ /*2*/\n",

	"foo    $/*comment*/    \n",
	"foo    $/*0*/ /*1*/ /*2*/    \n",
	"foo	$/**/ /*-------------*/       /*----\n*/bar       $/*  \n*/baa$\n",
	"foo    $/* an EOF terminates a line */",
	"foo    $/* an EOF terminates a line */ /*",
	"foo    $/* an EOF terminates a line */ //",

	"package main$\n\nfunc main() {\n\tif {\n\t\treturn /* */ }$\n}$\n",
	"package main$",
}

func TestSemis(t *testing.T) {
	for _, line := range lines {
		checkSemi(t, line, AllowIllegalChars|InsertSemis)
		checkSemi(t, line, AllowIllegalChars|InsertSemis|ScanComments)

		// if the input ended in newlines, the input must tokenize the
		// same with or without those newlines
		for i := len(line) - 1; i >= 0 && line[i] == '\n'; i-- {
			checkSemi(t, line[0:i], AllowIllegalChars|InsertSemis)
			checkSemi(t, line[0:i], AllowIllegalChars|InsertSemis|ScanComments)
		}
	}
}

type segment struct {
	srcline  string // a line of source text
	filename string // filename for current token
	line     int    // line number for current token
}

var segments = []segment{
	// exactly one token per line since the test consumes one token per segment
	{"  line1", filepath.Join("dir", "TestLineComments"), 1},
	{"\nline2", filepath.Join("dir", "TestLineComments"), 2},
	{"\nline3  //line File1.go:100", filepath.Join("dir", "TestLineComments"), 3}, // bad line comment, ignored
	{"\nline4", filepath.Join("dir", "TestLineComments"), 4},
	{"\n//line File1.go:100\n  line100", filepath.Join("dir", "File1.go"), 100},
	{"\n//line File2.go:200\n  line200", filepath.Join("dir", "File2.go"), 200},
	{"\n//line :1\n  line1", "dir", 1},
	{"\n//line foo:42\n  line42", filepath.Join("dir", "foo"), 42},
	{"\n //line foo:42\n  line44", filepath.Join("dir", "foo"), 44},           // bad line comment, ignored
	{"\n//line foo 42\n  line46", filepath.Join("dir", "foo"), 46},            // bad line comment, ignored
	{"\n//line foo:42 extra text\n  line48", filepath.Join("dir", "foo"), 48}, // bad line comment, ignored
	{"\n//line ./foo:42\n  line42", filepath.Join("dir", "foo"), 42},
	{"\n//line a/b/c/File1.go:100\n  line100", filepath.Join("dir", "a", "b", "c", "File1.go"), 100},
}

var unixsegments = []segment{
	{"\n//line /bar:42\n  line42", "/bar", 42},
}

var winsegments = []segment{
	{"\n//line c:\\bar:42\n  line42", "c:\\bar", 42},
	{"\n//line c:\\dir\\File1.go:100\n  line100", "c:\\dir\\File1.go", 100},
}

// Verify that comments of the form "//line filename:line" are interpreted correctly.
func TestLineComments(t *testing.T) {
	segs := segments
	if runtime.GOOS == "windows" {
		segs = append(segs, winsegments...)
	} else {
		segs = append(segs, unixsegments...)
	}

	// make source
	var src string
	for _, e := range segs {
		src += e.srcline
	}

	// verify scan
	var S Scanner
	file := fset.AddFile(filepath.Join("dir", "TestLineComments"), fset.Base(), len(src))
	S.Init(file, []byte(src), nil, 0)
	for _, s := range segs {
		p, _, lit := S.Scan()
		pos := file.Position(p)
		checkPos(t, lit, p, token.Position{s.filename, pos.Offset, s.line, pos.Column})
	}

	if S.ErrorCount != 0 {
		t.Errorf("found %d errors", S.ErrorCount)
	}
}

// Verify that initializing the same scanner more then once works correctly.
func TestInit(t *testing.T) {
	var s Scanner

	// 1st init
	src1 := "if true { }"
	f1 := fset.AddFile("src1", fset.Base(), len(src1))
	s.Init(f1, []byte(src1), nil, 0)
	if f1.Size() != len(src1) {
		t.Errorf("bad file size: got %d, expected %d", f1.Size(), len(src1))
	}
	s.Scan()              // if
	s.Scan()              // true
	_, tok, _ := s.Scan() // {
	if tok != token.LBRACE {
		t.Errorf("bad token: got %s, expected %s", tok.String(), token.LBRACE)
	}

	// 2nd init
	src2 := "go true { ]"
	f2 := fset.AddFile("src2", fset.Base(), len(src2))
	s.Init(f2, []byte(src2), nil, 0)
	if f2.Size() != len(src2) {
		t.Errorf("bad file size: got %d, expected %d", f2.Size(), len(src2))
	}
	_, tok, _ = s.Scan() // go
	if tok != token.GO {
		t.Errorf("bad token: got %s, expected %s", tok.String(), token.GO)
	}

	if s.ErrorCount != 0 {
		t.Errorf("found %d errors", s.ErrorCount)
	}
}

func TestIllegalChars(t *testing.T) {
	var s Scanner

	const src = "*?*$*@*"
	file := fset.AddFile("", fset.Base(), len(src))
	s.Init(file, []byte(src), &testErrorHandler{t}, AllowIllegalChars)
	for offs, ch := range src {
		pos, tok, lit := s.Scan()
		if poffs := file.Offset(pos); poffs != offs {
			t.Errorf("bad position for %s: got %d, expected %d", lit, poffs, offs)
		}
		if tok == token.ILLEGAL && lit != string(ch) {
			t.Errorf("bad token: got %s, expected %s", lit, string(ch))
		}
	}

	if s.ErrorCount != 0 {
		t.Errorf("found %d errors", s.ErrorCount)
	}
}

func TestStdErrorHander(t *testing.T) {
	const src = "@\n" + // illegal character, cause an error
		"@ @\n" + // two errors on the same line
		"//line File2:20\n" +
		"@\n" + // different file, but same line
		"//line File2:1\n" +
		"@ @\n" + // same file, decreasing line number
		"//line File1:1\n" +
		"@ @ @" // original file, line 1 again

	v := new(ErrorVector)
	var s Scanner
	s.Init(fset.AddFile("File1", fset.Base(), len(src)), []byte(src), v, 0)
	for {
		if _, tok, _ := s.Scan(); tok == token.EOF {
			break
		}
	}

	list := v.GetErrorList(Raw)
	if len(list) != 9 {
		t.Errorf("found %d raw errors, expected 9", len(list))
		PrintError(os.Stderr, list)
	}

	list = v.GetErrorList(Sorted)
	if len(list) != 9 {
		t.Errorf("found %d sorted errors, expected 9", len(list))
		PrintError(os.Stderr, list)
	}

	list = v.GetErrorList(NoMultiples)
	if len(list) != 4 {
		t.Errorf("found %d one-per-line errors, expected 4", len(list))
		PrintError(os.Stderr, list)
	}

	if v.ErrorCount() != s.ErrorCount {
		t.Errorf("found %d errors, expected %d", v.ErrorCount(), s.ErrorCount)
	}
}

type errorCollector struct {
	cnt int            // number of errors encountered
	msg string         // last error message encountered
	pos token.Position // last error position encountered
}

func (h *errorCollector) Error(pos token.Position, msg string) {
	h.cnt++
	h.msg = msg
	h.pos = pos
}

func checkError(t *testing.T, src string, tok token.Token, pos int, err string) {
	var s Scanner
	var h errorCollector
	s.Init(fset.AddFile("", fset.Base(), len(src)), []byte(src), &h, ScanComments)
	_, tok0, _ := s.Scan()
	_, tok1, _ := s.Scan()
	if tok0 != tok {
		t.Errorf("%q: got %s, expected %s", src, tok0, tok)
	}
	if tok1 != token.EOF {
		t.Errorf("%q: got %s, expected EOF", src, tok1)
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
	err string
}{
	{"\a", token.ILLEGAL, 0, "illegal character U+0007"},
	{`#`, token.ILLEGAL, 0, "illegal character U+0023 '#'"},
	{`…`, token.ILLEGAL, 0, "illegal character U+2026 '…'"},
	{`' '`, token.CHAR, 0, ""},
	{`''`, token.CHAR, 0, "illegal character literal"},
	{`'\8'`, token.CHAR, 2, "unknown escape sequence"},
	{`'\08'`, token.CHAR, 3, "illegal character in escape sequence"},
	{`'\x0g'`, token.CHAR, 4, "illegal character in escape sequence"},
	{`'\Uffffffff'`, token.CHAR, 2, "escape sequence is invalid Unicode code point"},
	{`'`, token.CHAR, 0, "character literal not terminated"},
	{`""`, token.STRING, 0, ""},
	{`"`, token.STRING, 0, "string not terminated"},
	{"``", token.STRING, 0, ""},
	{"`", token.STRING, 0, "string not terminated"},
	{"/**/", token.COMMENT, 0, ""},
	{"/*", token.COMMENT, 0, "comment not terminated"},
	{"077", token.INT, 0, ""},
	{"078.", token.FLOAT, 0, ""},
	{"07801234567.", token.FLOAT, 0, ""},
	{"078e0", token.FLOAT, 0, ""},
	{"078", token.INT, 0, "illegal octal number"},
	{"07800000009", token.INT, 0, "illegal octal number"},
	{"0x", token.INT, 0, "illegal hexadecimal number"},
	{"0X", token.INT, 0, "illegal hexadecimal number"},
	{"\"abc\x00def\"", token.STRING, 4, "illegal character NUL"},
	{"\"abc\x80def\"", token.STRING, 4, "illegal UTF-8 encoding"},
}

func TestScanErrors(t *testing.T) {
	for _, e := range errors {
		checkError(t, e.src, e.tok, e.pos, e.err)
	}
}

"""



```