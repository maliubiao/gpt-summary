Response:
My thought process for analyzing the Go code and generating the response went through these stages:

1. **Understand the Goal:** The request asks for the functionality of a Go file (`scanner_test.go`) related to the Go compiler's `syntax` package. It also requests examples, potential errors, and details about command-line arguments if applicable.

2. **Initial Skim and Identify Key Components:** I quickly skimmed the code looking for test functions (functions starting with `Test`), data structures, and important function calls. This immediately highlighted:
    * Test functions like `TestSmoke`, `TestTokens`, `TestScanner`, `TestEmbeddedTokens`, `TestComments`, `TestNumbers`, `TestScanErrors`, `TestDirectives`, `TestIssue21938`, and `TestIssue33961`. This strongly suggests the file is for testing a scanner or lexer.
    * The `scanner` struct and its `init` and `next` methods, which are central to the testing logic.
    * The `tokens` slice in `TestSmoke` and `sampleTokens` slice, which seem to represent expected token sequences.
    * The error handler function `errh` and the anonymous error handler functions used in the tests.
    * The use of `strings.NewReader` to provide input to the scanner.

3. **Focus on Core Functionality (The Scanner):** Based on the presence of `scanner`, `init`, and `next`, and the way the tests are structured, I deduced that the primary purpose of this code is to test the **lexical scanner** of the Go compiler's syntax package. This scanner's job is to break down Go source code into a stream of tokens.

4. **Analyze Individual Test Functions:** I then examined each test function more closely to understand its specific purpose:
    * **`TestSmoke`:** A basic sanity check to see if the scanner can tokenize a small, representative snippet of Go code. This is the "smoke test".
    * **`TestTokens`:** Tests the scanner against a predefined set of `sampleTokens`, ensuring it correctly identifies the token type and literal value for various Go language constructs.
    * **`TestScanner`:**  A more comprehensive test that reads a Go source file (specified by the `-src` flag) and tokenizes it, printing the tokens found (if verbose mode is enabled). This reveals the scanner's ability to handle real Go code.
    * **`TestEmbeddedTokens`:** Tests the scanner's ability to handle tokens embedded within comments and with leading/trailing whitespace. It also checks for correct line number tracking.
    * **`TestComments`:** Specifically tests the scanner's ability to identify and handle different types of comments (`//` and `/* ... */`).
    * **`TestNumbers`:** A detailed test suite focusing on the correct parsing of various numeric literals (binary, octal, decimal, hexadecimal, floating-point, imaginary). It also verifies error detection for invalid numeric formats.
    * **`TestScanErrors`:** Tests the scanner's ability to correctly identify and report various lexical errors, including invalid characters, unterminated literals, and incorrect escape sequences.
    * **`TestDirectives`:** Checks if the scanner correctly identifies and handles compiler directives like `//line` and `//go:`.
    * **`TestIssue21938` and `TestIssue33961`:** These likely test specific bug fixes related to scanner behavior in particular edge cases.

5. **Identify Go Language Feature:** The core Go language feature being tested is **lexical analysis**, the first stage of compilation where the source code is broken down into tokens.

6. **Construct Go Code Examples:** To illustrate the scanner's function, I created a simple Go code example and showed how the scanner would tokenize it, mimicking the output of the `TestScanner` function. I included different token types (keywords, identifiers, operators, literals).

7. **Infer Command-Line Arguments:** The `TestScanner` function uses `*src_`, which is likely populated by a command-line flag. I correctly identified the `-src` flag and explained its purpose in specifying the input Go source file. I also noted the `-test.v` flag for verbose output.

8. **Identify Potential Pitfalls:** I thought about common errors developers might make related to lexical analysis and how this scanner helps catch them. I focused on:
    * Incorrectly formatted literals (especially numbers and strings).
    * Unterminated string or rune literals.
    * Invalid characters in identifiers.
    * Forgetting to handle or being unaware of compiler directives.

9. **Structure the Response:** I organized the information logically:
    * Start with a summary of the file's functionality.
    * Provide a Go code example demonstrating the scanner's behavior.
    * Explain the command-line arguments.
    * List common mistakes users might make.

10. **Refine and Review:** I reviewed my response for clarity, accuracy, and completeness, ensuring that it addressed all aspects of the original request. I made sure the code examples were clear and the explanations were easy to understand.

This iterative process of skimming, in-depth analysis of key components, deduction, and example construction allowed me to generate a comprehensive and accurate response to the request. The test function names were particularly helpful in guiding my understanding of the code's purpose.
这是 `go/src/cmd/compile/internal/syntax/scanner_test.go` 文件的一部分，它主要的功能是**测试 Go 语言的词法分析器（scanner）**。

更具体地说，这个文件中的测试用例验证了词法分析器能否正确地将 Go 源代码分解成一系列的 token（词法单元）。

**功能列表:**

1. **`TestSmoke`**:  一个基本的冒烟测试，用于快速检查词法分析器是否能够处理一个简单的 Go 代码片段，并生成预期的 token 序列。
2. **`TestTokens`**:  使用预定义的 `sampleTokens` 数据，详细测试词法分析器对各种 Go 语言 token 的识别，包括关键字、标识符、字面量、操作符等。
3. **`TestScanner`**:  这是一个更全面的测试，它读取一个实际的 Go 源代码文件（通过命令行参数 `-src` 指定），并对整个文件进行词法分析。如果开启了 verbose 模式（通过 `-test.v` 标志），它会将每个 token 的信息打印出来。
4. **`TestEmbeddedTokens`**:  测试词法分析器处理嵌入在代码中的 token 的能力，例如带有前导/尾随空格的 token，以及包含 `//line` 指令的注释。
5. **`TestComments`**:  专门测试词法分析器对不同类型的注释（单行 `//` 和多行 `/* ... */`）的识别和处理。
6. **`TestNumbers`**:  详细测试词法分析器对各种数字字面量的解析，包括二进制、八进制、十进制、十六进制整数和浮点数，以及复数。它还测试了对非法数字格式的错误处理。
7. **`TestScanErrors`**:  测试词法分析器在遇到各种词法错误时的处理能力，例如非法的 UTF-8 编码、未终止的字符串或 rune 字面量、无效的转义序列等。
8. **`TestDirectives`**:  测试词法分析器对编译器指令（directives）的识别和处理，例如 `//line` 和 `//go:`.
9. **`TestIssue21938` 和 `TestIssue33961`**:  这两个测试用例是为了复现和验证特定 issue 的修复，通常是边界情况或错误处理方面的问题。

**Go 语言功能实现推理与代码示例:**

这个文件测试的是 Go 语言编译器的词法分析阶段，这是将源代码转换为可以被编译器进一步处理的 token 序列的第一步。

以下是一个简单的 Go 代码示例，并展示了词法分析器可能生成的 token 序列：

**假设输入 (Go 代码):**

```go
package main

import "fmt"

func main() {
	x := 10
	fmt.Println(x)
}
```

**可能的输出 (Token 序列):**

```
_Package "package"
_Name "main"
_Semi "\n"
_Import "import"
_Literal "\"fmt\""
_Semi "\n"
_Func "func"
_Name "main"
_Lparen "("
_Rparen ")"
_Lbrace "{"
_Name "x"
_Define ":="
_Literal "10"
_Semi "\n"
_Name "fmt"
_Dot "."
_Name "Println"
_Lparen "("
_Name "x"
_Rparen ")"
_Semi "\n"
_Rbrace "}"
_Semi "\n"
_EOF
```

**代码推理与假设输入输出 (基于 `TestSmoke`):**

`TestSmoke` 函数提供了一个很好的例子。

**假设输入 (字符串):**

```
"if (+foo\t+=..123/***/0.9_0e-0i'a'`raw`\"string\"..f;//$"
```

**预期输出 (Token 序列):**

```
_If
_Lparen
_Operator
_Name
_AssignOp
_Dot
_Literal
_Literal
_Literal
_Literal
_Literal
_Dot
_Dot
_Name
_Semi
_EOF
```

**推理:**

`TestSmoke` 初始化了一个 `scanner`，并逐个调用 `next()` 方法来获取下一个 token。它将获取到的 token 类型 `got.tok` 与预期的 token 类型 `want` 进行比较。如果 token 类型不匹配，则测试失败并报告错误。

**命令行参数的具体处理:**

`TestScanner` 函数展示了对命令行参数的处理：

```go
filename := *src_ // can be changed via -src flag
```

这里的 `src_` 是一个包级别的变量，它很可能在测试的入口点（例如 `init()` 函数或者通过 `flag` 包）与命令行参数 `-src` 绑定。

**使用方法:**

要运行包含 `TestScanner` 的测试，你需要使用 `go test` 命令，并通过 `-src` 标志指定要扫描的 Go 源代码文件的路径：

```bash
go test -v -src=your_go_file.go
```

* **`-v`**:  表示 verbose 模式，会输出更详细的测试信息，包括 `TestScanner` 中打印的 token 信息。
* **`-src=your_go_file.go`**:  指定要进行词法分析的 Go 源代码文件的路径。

**使用者易犯错的点:**

在编写 Go 代码时，一些常见的词法错误可能会被词法分析器捕获：

1. **不正确的数字字面量格式:**
   ```go
   // 错误：八进制数不能包含 8 或 9
   x := 018
   y := 09
   ```
   词法分析器会报错，例如在 `TestNumbers` 中测试的场景。

2. **未终止的字符串或 rune 字面量:**
   ```go
   // 错误：字符串没有用双引号闭合
   str := "hello
   // 错误：rune 没有用单引号闭合
   r := 'a
   ```
   `TestScanErrors` 中包含了这类错误的测试。

3. **使用了非法字符:**
   ```go
   // 错误：标识符中包含 $ 符号
   var my$variable int
   ```
   词法分析器会识别出非法字符。

4. **不正确的转义序列:**
   ```go
   // 错误：\z 不是有效的转义序列
   str := "hello\zworld"
   ```
   `TestScanErrors` 也会测试这类错误。

5. **忘记或错误使用编译器指令:**
   虽然 `scanner_test.go` 主要测试扫描器本身，但开发者可能会在使用编译器指令时犯错，例如拼写错误或位置不当，这虽然不是扫描器本身的问题，但会影响编译过程。

总而言之，`go/src/cmd/compile/internal/syntax/scanner_test.go` 是 Go 编译器中至关重要的测试文件，它确保了词法分析器能够准确无误地将 Go 源代码转换为 token 流，为后续的语法分析和代码生成奠定基础。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/syntax/scanner_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syntax

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// errh is a default error handler for basic tests.
func errh(line, col uint, msg string) {
	panic(fmt.Sprintf("%d:%d: %s", line, col, msg))
}

// Don't bother with other tests if TestSmoke doesn't pass.
func TestSmoke(t *testing.T) {
	const src = "if (+foo\t+=..123/***/0.9_0e-0i'a'`raw`\"string\"..f;//$"
	tokens := []token{_If, _Lparen, _Operator, _Name, _AssignOp, _Dot, _Literal, _Literal, _Literal, _Literal, _Literal, _Dot, _Dot, _Name, _Semi, _EOF}

	var got scanner
	got.init(strings.NewReader(src), errh, 0)
	for _, want := range tokens {
		got.next()
		if got.tok != want {
			t.Errorf("%d:%d: got %s; want %s", got.line, got.col, got.tok, want)
			continue
		}
	}
}

// Once TestSmoke passes, run TestTokens next.
func TestTokens(t *testing.T) {
	var got scanner
	for _, want := range sampleTokens {
		got.init(strings.NewReader(want.src), func(line, col uint, msg string) {
			t.Errorf("%s:%d:%d: %s", want.src, line, col, msg)
		}, 0)
		got.next()
		if got.tok != want.tok {
			t.Errorf("%s: got %s; want %s", want.src, got.tok, want.tok)
			continue
		}
		if (got.tok == _Name || got.tok == _Literal) && got.lit != want.src {
			t.Errorf("%s: got %q; want %q", want.src, got.lit, want.src)
		}
	}
}

func TestScanner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	filename := *src_ // can be changed via -src flag
	src, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	var s scanner
	s.init(src, errh, 0)
	for {
		s.next()
		if s.tok == _EOF {
			break
		}
		if !testing.Verbose() {
			continue
		}
		switch s.tok {
		case _Name, _Literal:
			fmt.Printf("%s:%d:%d: %s => %s\n", filename, s.line, s.col, s.tok, s.lit)
		case _Operator:
			fmt.Printf("%s:%d:%d: %s => %s (prec = %d)\n", filename, s.line, s.col, s.tok, s.op, s.prec)
		default:
			fmt.Printf("%s:%d:%d: %s\n", filename, s.line, s.col, s.tok)
		}
	}
}

func TestEmbeddedTokens(t *testing.T) {
	// make source
	var buf bytes.Buffer
	for i, s := range sampleTokens {
		buf.WriteString("\t\t\t\t"[:i&3])                 // leading indentation
		buf.WriteString(s.src)                            // token
		buf.WriteString("        "[:i&7])                 // trailing spaces
		fmt.Fprintf(&buf, "/*line foo:%d */ // bar\n", i) // comments + newline (don't crash w/o directive handler)
	}

	// scan source
	var got scanner
	var src string
	got.init(&buf, func(line, col uint, msg string) {
		t.Fatalf("%s:%d:%d: %s", src, line, col, msg)
	}, 0)
	got.next()
	for i, want := range sampleTokens {
		src = want.src
		nlsemi := false

		if got.line-linebase != uint(i) {
			t.Errorf("%s: got line %d; want %d", src, got.line-linebase, i)
		}

		if got.tok != want.tok {
			t.Errorf("%s: got tok %s; want %s", src, got.tok, want.tok)
			continue
		}

		switch want.tok {
		case _Semi:
			if got.lit != "semicolon" {
				t.Errorf("%s: got %s; want semicolon", src, got.lit)
			}

		case _Name, _Literal:
			if got.lit != want.src {
				t.Errorf("%s: got lit %q; want %q", src, got.lit, want.src)
				continue
			}
			nlsemi = true

		case _Operator, _AssignOp, _IncOp:
			if got.op != want.op {
				t.Errorf("%s: got op %s; want %s", src, got.op, want.op)
				continue
			}
			if got.prec != want.prec {
				t.Errorf("%s: got prec %d; want %d", src, got.prec, want.prec)
				continue
			}
			nlsemi = want.tok == _IncOp

		case _Rparen, _Rbrack, _Rbrace, _Break, _Continue, _Fallthrough, _Return:
			nlsemi = true
		}

		if nlsemi {
			got.next()
			if got.tok != _Semi {
				t.Errorf("%s: got tok %s; want ;", src, got.tok)
				continue
			}
			if got.lit != "newline" {
				t.Errorf("%s: got %s; want newline", src, got.lit)
			}
		}

		got.next()
	}

	if got.tok != _EOF {
		t.Errorf("got %q; want _EOF", got.tok)
	}
}

var sampleTokens = [...]struct {
	tok  token
	src  string
	op   Operator
	prec int
}{
	// name samples
	{_Name, "x", 0, 0},
	{_Name, "X123", 0, 0},
	{_Name, "foo", 0, 0},
	{_Name, "Foo123", 0, 0},
	{_Name, "foo_bar", 0, 0},
	{_Name, "_", 0, 0},
	{_Name, "_foobar", 0, 0},
	{_Name, "a۰۱۸", 0, 0},
	{_Name, "foo६४", 0, 0},
	{_Name, "bar９８７６", 0, 0},
	{_Name, "ŝ", 0, 0},
	{_Name, "ŝfoo", 0, 0},

	// literal samples
	{_Literal, "0", 0, 0},
	{_Literal, "1", 0, 0},
	{_Literal, "12345", 0, 0},
	{_Literal, "123456789012345678890123456789012345678890", 0, 0},
	{_Literal, "01234567", 0, 0},
	{_Literal, "0_1_234_567", 0, 0},
	{_Literal, "0X0", 0, 0},
	{_Literal, "0xcafebabe", 0, 0},
	{_Literal, "0x_cafe_babe", 0, 0},
	{_Literal, "0O0", 0, 0},
	{_Literal, "0o000", 0, 0},
	{_Literal, "0o_000", 0, 0},
	{_Literal, "0B1", 0, 0},
	{_Literal, "0b01100110", 0, 0},
	{_Literal, "0b_0110_0110", 0, 0},
	{_Literal, "0.", 0, 0},
	{_Literal, "0.e0", 0, 0},
	{_Literal, "0.e-1", 0, 0},
	{_Literal, "0.e+123", 0, 0},
	{_Literal, ".0", 0, 0},
	{_Literal, ".0E00", 0, 0},
	{_Literal, ".0E-0123", 0, 0},
	{_Literal, ".0E+12345678901234567890", 0, 0},
	{_Literal, ".45e1", 0, 0},
	{_Literal, "3.14159265", 0, 0},
	{_Literal, "1e0", 0, 0},
	{_Literal, "1e+100", 0, 0},
	{_Literal, "1e-100", 0, 0},
	{_Literal, "2.71828e-1000", 0, 0},
	{_Literal, "0i", 0, 0},
	{_Literal, "1i", 0, 0},
	{_Literal, "012345678901234567889i", 0, 0},
	{_Literal, "123456789012345678890i", 0, 0},
	{_Literal, "0.i", 0, 0},
	{_Literal, ".0i", 0, 0},
	{_Literal, "3.14159265i", 0, 0},
	{_Literal, "1e0i", 0, 0},
	{_Literal, "1e+100i", 0, 0},
	{_Literal, "1e-100i", 0, 0},
	{_Literal, "2.71828e-1000i", 0, 0},
	{_Literal, "'a'", 0, 0},
	{_Literal, "'\\000'", 0, 0},
	{_Literal, "'\\xFF'", 0, 0},
	{_Literal, "'\\uff16'", 0, 0},
	{_Literal, "'\\U0000ff16'", 0, 0},
	{_Literal, "`foobar`", 0, 0},
	{_Literal, "`foo\tbar`", 0, 0},
	{_Literal, "`\r`", 0, 0},

	// operators
	{_Operator, "!", Not, 0},
	{_Operator, "~", Tilde, 0},

	{_Operator, "||", OrOr, precOrOr},

	{_Operator, "&&", AndAnd, precAndAnd},

	{_Operator, "==", Eql, precCmp},
	{_Operator, "!=", Neq, precCmp},
	{_Operator, "<", Lss, precCmp},
	{_Operator, "<=", Leq, precCmp},
	{_Operator, ">", Gtr, precCmp},
	{_Operator, ">=", Geq, precCmp},

	{_Operator, "+", Add, precAdd},
	{_Operator, "-", Sub, precAdd},
	{_Operator, "|", Or, precAdd},
	{_Operator, "^", Xor, precAdd},

	{_Star, "*", Mul, precMul},
	{_Operator, "/", Div, precMul},
	{_Operator, "%", Rem, precMul},
	{_Operator, "&", And, precMul},
	{_Operator, "&^", AndNot, precMul},
	{_Operator, "<<", Shl, precMul},
	{_Operator, ">>", Shr, precMul},

	// assignment operations
	{_AssignOp, "+=", Add, precAdd},
	{_AssignOp, "-=", Sub, precAdd},
	{_AssignOp, "|=", Or, precAdd},
	{_AssignOp, "^=", Xor, precAdd},

	{_AssignOp, "*=", Mul, precMul},
	{_AssignOp, "/=", Div, precMul},
	{_AssignOp, "%=", Rem, precMul},
	{_AssignOp, "&=", And, precMul},
	{_AssignOp, "&^=", AndNot, precMul},
	{_AssignOp, "<<=", Shl, precMul},
	{_AssignOp, ">>=", Shr, precMul},

	// other operations
	{_IncOp, "++", Add, precAdd},
	{_IncOp, "--", Sub, precAdd},
	{_Assign, "=", 0, 0},
	{_Define, ":=", 0, 0},
	{_Arrow, "<-", 0, 0},

	// delimiters
	{_Lparen, "(", 0, 0},
	{_Lbrack, "[", 0, 0},
	{_Lbrace, "{", 0, 0},
	{_Rparen, ")", 0, 0},
	{_Rbrack, "]", 0, 0},
	{_Rbrace, "}", 0, 0},
	{_Comma, ",", 0, 0},
	{_Semi, ";", 0, 0},
	{_Colon, ":", 0, 0},
	{_Dot, ".", 0, 0},
	{_DotDotDot, "...", 0, 0},

	// keywords
	{_Break, "break", 0, 0},
	{_Case, "case", 0, 0},
	{_Chan, "chan", 0, 0},
	{_Const, "const", 0, 0},
	{_Continue, "continue", 0, 0},
	{_Default, "default", 0, 0},
	{_Defer, "defer", 0, 0},
	{_Else, "else", 0, 0},
	{_Fallthrough, "fallthrough", 0, 0},
	{_For, "for", 0, 0},
	{_Func, "func", 0, 0},
	{_Go, "go", 0, 0},
	{_Goto, "goto", 0, 0},
	{_If, "if", 0, 0},
	{_Import, "import", 0, 0},
	{_Interface, "interface", 0, 0},
	{_Map, "map", 0, 0},
	{_Package, "package", 0, 0},
	{_Range, "range", 0, 0},
	{_Return, "return", 0, 0},
	{_Select, "select", 0, 0},
	{_Struct, "struct", 0, 0},
	{_Switch, "switch", 0, 0},
	{_Type, "type", 0, 0},
	{_Var, "var", 0, 0},
}

func TestComments(t *testing.T) {
	type comment struct {
		line, col uint // 0-based
		text      string
	}

	for _, test := range []struct {
		src  string
		want comment
	}{
		// no comments
		{"no comment here", comment{0, 0, ""}},
		{" /", comment{0, 0, ""}},
		{"\n /*/", comment{0, 0, ""}},

		//-style comments
		{"// line comment\n", comment{0, 0, "// line comment"}},
		{"package p // line comment\n", comment{0, 10, "// line comment"}},
		{"//\n//\n\t// want this one\r\n", comment{2, 1, "// want this one\r"}},
		{"\n\n//\n", comment{2, 0, "//"}},
		{"//", comment{0, 0, "//"}},

		/*-style comments */
		{"123/* regular comment */", comment{0, 3, "/* regular comment */"}},
		{"package p /* regular comment", comment{0, 0, ""}},
		{"\n\n\n/*\n*//* want this one */", comment{4, 2, "/* want this one */"}},
		{"\n\n/**/", comment{2, 0, "/**/"}},
		{"/*", comment{0, 0, ""}},
	} {
		var s scanner
		var got comment
		s.init(strings.NewReader(test.src), func(line, col uint, msg string) {
			if msg[0] != '/' {
				// error
				if msg != "comment not terminated" {
					t.Errorf("%q: %s", test.src, msg)
				}
				return
			}
			got = comment{line - linebase, col - colbase, msg} // keep last one
		}, comments)

		for {
			s.next()
			if s.tok == _EOF {
				break
			}
		}

		want := test.want
		if got.line != want.line || got.col != want.col {
			t.Errorf("%q: got position %d:%d; want %d:%d", test.src, got.line, got.col, want.line, want.col)
		}
		if got.text != want.text {
			t.Errorf("%q: got %q; want %q", test.src, got.text, want.text)
		}
	}
}

func TestNumbers(t *testing.T) {
	for _, test := range []struct {
		kind             LitKind
		src, tokens, err string
	}{
		// binaries
		{IntLit, "0b0", "0b0", ""},
		{IntLit, "0b1010", "0b1010", ""},
		{IntLit, "0B1110", "0B1110", ""},

		{IntLit, "0b", "0b", "binary literal has no digits"},
		{IntLit, "0b0190", "0b0190", "invalid digit '9' in binary literal"},
		{IntLit, "0b01a0", "0b01 a0", ""}, // only accept 0-9

		{FloatLit, "0b.", "0b.", "invalid radix point in binary literal"},
		{FloatLit, "0b.1", "0b.1", "invalid radix point in binary literal"},
		{FloatLit, "0b1.0", "0b1.0", "invalid radix point in binary literal"},
		{FloatLit, "0b1e10", "0b1e10", "'e' exponent requires decimal mantissa"},
		{FloatLit, "0b1P-1", "0b1P-1", "'P' exponent requires hexadecimal mantissa"},

		{ImagLit, "0b10i", "0b10i", ""},
		{ImagLit, "0b10.0i", "0b10.0i", "invalid radix point in binary literal"},

		// octals
		{IntLit, "0o0", "0o0", ""},
		{IntLit, "0o1234", "0o1234", ""},
		{IntLit, "0O1234", "0O1234", ""},

		{IntLit, "0o", "0o", "octal literal has no digits"},
		{IntLit, "0o8123", "0o8123", "invalid digit '8' in octal literal"},
		{IntLit, "0o1293", "0o1293", "invalid digit '9' in octal literal"},
		{IntLit, "0o12a3", "0o12 a3", ""}, // only accept 0-9

		{FloatLit, "0o.", "0o.", "invalid radix point in octal literal"},
		{FloatLit, "0o.2", "0o.2", "invalid radix point in octal literal"},
		{FloatLit, "0o1.2", "0o1.2", "invalid radix point in octal literal"},
		{FloatLit, "0o1E+2", "0o1E+2", "'E' exponent requires decimal mantissa"},
		{FloatLit, "0o1p10", "0o1p10", "'p' exponent requires hexadecimal mantissa"},

		{ImagLit, "0o10i", "0o10i", ""},
		{ImagLit, "0o10e0i", "0o10e0i", "'e' exponent requires decimal mantissa"},

		// 0-octals
		{IntLit, "0", "0", ""},
		{IntLit, "0123", "0123", ""},

		{IntLit, "08123", "08123", "invalid digit '8' in octal literal"},
		{IntLit, "01293", "01293", "invalid digit '9' in octal literal"},
		{IntLit, "0F.", "0 F .", ""}, // only accept 0-9
		{IntLit, "0123F.", "0123 F .", ""},
		{IntLit, "0123456x", "0123456 x", ""},

		// decimals
		{IntLit, "1", "1", ""},
		{IntLit, "1234", "1234", ""},

		{IntLit, "1f", "1 f", ""}, // only accept 0-9

		{ImagLit, "0i", "0i", ""},
		{ImagLit, "0678i", "0678i", ""},

		// decimal floats
		{FloatLit, "0.", "0.", ""},
		{FloatLit, "123.", "123.", ""},
		{FloatLit, "0123.", "0123.", ""},

		{FloatLit, ".0", ".0", ""},
		{FloatLit, ".123", ".123", ""},
		{FloatLit, ".0123", ".0123", ""},

		{FloatLit, "0.0", "0.0", ""},
		{FloatLit, "123.123", "123.123", ""},
		{FloatLit, "0123.0123", "0123.0123", ""},

		{FloatLit, "0e0", "0e0", ""},
		{FloatLit, "123e+0", "123e+0", ""},
		{FloatLit, "0123E-1", "0123E-1", ""},

		{FloatLit, "0.e+1", "0.e+1", ""},
		{FloatLit, "123.E-10", "123.E-10", ""},
		{FloatLit, "0123.e123", "0123.e123", ""},

		{FloatLit, ".0e-1", ".0e-1", ""},
		{FloatLit, ".123E+10", ".123E+10", ""},
		{FloatLit, ".0123E123", ".0123E123", ""},

		{FloatLit, "0.0e1", "0.0e1", ""},
		{FloatLit, "123.123E-10", "123.123E-10", ""},
		{FloatLit, "0123.0123e+456", "0123.0123e+456", ""},

		{FloatLit, "0e", "0e", "exponent has no digits"},
		{FloatLit, "0E+", "0E+", "exponent has no digits"},
		{FloatLit, "1e+f", "1e+ f", "exponent has no digits"},
		{FloatLit, "0p0", "0p0", "'p' exponent requires hexadecimal mantissa"},
		{FloatLit, "1.0P-1", "1.0P-1", "'P' exponent requires hexadecimal mantissa"},

		{ImagLit, "0.i", "0.i", ""},
		{ImagLit, ".123i", ".123i", ""},
		{ImagLit, "123.123i", "123.123i", ""},
		{ImagLit, "123e+0i", "123e+0i", ""},
		{ImagLit, "123.E-10i", "123.E-10i", ""},
		{ImagLit, ".123E+10i", ".123E+10i", ""},

		// hexadecimals
		{IntLit, "0x0", "0x0", ""},
		{IntLit, "0x1234", "0x1234", ""},
		{IntLit, "0xcafef00d", "0xcafef00d", ""},
		{IntLit, "0XCAFEF00D", "0XCAFEF00D", ""},

		{IntLit, "0x", "0x", "hexadecimal literal has no digits"},
		{IntLit, "0x1g", "0x1 g", ""},

		{ImagLit, "0xf00i", "0xf00i", ""},

		// hexadecimal floats
		{FloatLit, "0x0p0", "0x0p0", ""},
		{FloatLit, "0x12efp-123", "0x12efp-123", ""},
		{FloatLit, "0xABCD.p+0", "0xABCD.p+0", ""},
		{FloatLit, "0x.0189P-0", "0x.0189P-0", ""},
		{FloatLit, "0x1.ffffp+1023", "0x1.ffffp+1023", ""},

		{FloatLit, "0x.", "0x.", "hexadecimal literal has no digits"},
		{FloatLit, "0x0.", "0x0.", "hexadecimal mantissa requires a 'p' exponent"},
		{FloatLit, "0x.0", "0x.0", "hexadecimal mantissa requires a 'p' exponent"},
		{FloatLit, "0x1.1", "0x1.1", "hexadecimal mantissa requires a 'p' exponent"},
		{FloatLit, "0x1.1e0", "0x1.1e0", "hexadecimal mantissa requires a 'p' exponent"},
		{FloatLit, "0x1.2gp1a", "0x1.2 gp1a", "hexadecimal mantissa requires a 'p' exponent"},
		{FloatLit, "0x0p", "0x0p", "exponent has no digits"},
		{FloatLit, "0xeP-", "0xeP-", "exponent has no digits"},
		{FloatLit, "0x1234PAB", "0x1234P AB", "exponent has no digits"},
		{FloatLit, "0x1.2p1a", "0x1.2p1 a", ""},

		{ImagLit, "0xf00.bap+12i", "0xf00.bap+12i", ""},

		// separators
		{IntLit, "0b_1000_0001", "0b_1000_0001", ""},
		{IntLit, "0o_600", "0o_600", ""},
		{IntLit, "0_466", "0_466", ""},
		{IntLit, "1_000", "1_000", ""},
		{FloatLit, "1_000.000_1", "1_000.000_1", ""},
		{ImagLit, "10e+1_2_3i", "10e+1_2_3i", ""},
		{IntLit, "0x_f00d", "0x_f00d", ""},
		{FloatLit, "0x_f00d.0p1_2", "0x_f00d.0p1_2", ""},

		{IntLit, "0b__1000", "0b__1000", "'_' must separate successive digits"},
		{IntLit, "0o60___0", "0o60___0", "'_' must separate successive digits"},
		{IntLit, "0466_", "0466_", "'_' must separate successive digits"},
		{FloatLit, "1_.", "1_.", "'_' must separate successive digits"},
		{FloatLit, "0._1", "0._1", "'_' must separate successive digits"},
		{FloatLit, "2.7_e0", "2.7_e0", "'_' must separate successive digits"},
		{ImagLit, "10e+12_i", "10e+12_i", "'_' must separate successive digits"},
		{IntLit, "0x___0", "0x___0", "'_' must separate successive digits"},
		{FloatLit, "0x1.0_p0", "0x1.0_p0", "'_' must separate successive digits"},
	} {
		var s scanner
		var err string
		s.init(strings.NewReader(test.src), func(_, _ uint, msg string) {
			if err == "" {
				err = msg
			}
		}, 0)

		for i, want := range strings.Split(test.tokens, " ") {
			err = ""
			s.next()

			if err != "" && !s.bad {
				t.Errorf("%q: got error but bad not set", test.src)
			}

			// compute lit where s.lit is not defined
			var lit string
			switch s.tok {
			case _Name, _Literal:
				lit = s.lit
			case _Dot:
				lit = "."
			}

			if i == 0 {
				if s.tok != _Literal || s.kind != test.kind {
					t.Errorf("%q: got token %s (kind = %d); want literal (kind = %d)", test.src, s.tok, s.kind, test.kind)
				}
				if err != test.err {
					t.Errorf("%q: got error %q; want %q", test.src, err, test.err)
				}
			}

			if lit != want {
				t.Errorf("%q: got literal %q (%s); want %s", test.src, lit, s.tok, want)
			}
		}

		// make sure we read all
		s.next()
		if s.tok == _Semi {
			s.next()
		}
		if s.tok != _EOF {
			t.Errorf("%q: got %s; want EOF", test.src, s.tok)
		}
	}
}

func TestScanErrors(t *testing.T) {
	for _, test := range []struct {
		src, err  string
		line, col uint // 0-based
	}{
		// Note: Positions for lexical errors are the earliest position
		// where the error is apparent, not the beginning of the respective
		// token.

		// rune-level errors
		{"fo\x00o", "invalid NUL character", 0, 2},
		{"foo\n\ufeff bar", "invalid BOM in the middle of the file", 1, 0},
		{"foo\n\n\xff    ", "invalid UTF-8 encoding", 2, 0},

		// token-level errors
		{"\u00BD" /* ½ */, "invalid character U+00BD '½' in identifier", 0, 0},
		{"\U0001d736\U0001d737\U0001d738_½" /* 𝜶𝜷𝜸_½ */, "invalid character U+00BD '½' in identifier", 0, 13 /* byte offset */},
		{"\U0001d7d8" /* 𝟘 */, "identifier cannot begin with digit U+1D7D8 '𝟘'", 0, 0},
		{"foo\U0001d7d8_½" /* foo𝟘_½ */, "invalid character U+00BD '½' in identifier", 0, 8 /* byte offset */},

		{"x + #y", "invalid character U+0023 '#'", 0, 4},
		{"foo$bar = 0", "invalid character U+0024 '$'", 0, 3},
		{"0123456789", "invalid digit '8' in octal literal", 0, 8},
		{"0123456789. /* foobar", "comment not terminated", 0, 12},   // valid float constant
		{"0123456789e0 /*\nfoobar", "comment not terminated", 0, 13}, // valid float constant
		{"var a, b = 09, 07\n", "invalid digit '9' in octal literal", 0, 12},

		{`''`, "empty rune literal or unescaped '", 0, 1},
		{"'\n", "newline in rune literal", 0, 1},
		{`'\`, "rune literal not terminated", 0, 0},
		{`'\'`, "rune literal not terminated", 0, 0},
		{`'\x`, "rune literal not terminated", 0, 0},
		{`'\x'`, "invalid character '\\'' in hexadecimal escape", 0, 3},
		{`'\y'`, "unknown escape", 0, 2},
		{`'\x0'`, "invalid character '\\'' in hexadecimal escape", 0, 4},
		{`'\00'`, "invalid character '\\'' in octal escape", 0, 4},
		{`'\377' /*`, "comment not terminated", 0, 7}, // valid octal escape
		{`'\378`, "invalid character '8' in octal escape", 0, 4},
		{`'\400'`, "octal escape value 256 > 255", 0, 5},
		{`'xx`, "rune literal not terminated", 0, 0},
		{`'xx'`, "more than one character in rune literal", 0, 0},

		{"\n   \"foo\n", "newline in string", 1, 7},
		{`"`, "string not terminated", 0, 0},
		{`"foo`, "string not terminated", 0, 0},
		{"`", "string not terminated", 0, 0},
		{"`foo", "string not terminated", 0, 0},
		{"/*/", "comment not terminated", 0, 0},
		{"/*\n\nfoo", "comment not terminated", 0, 0},
		{`"\`, "string not terminated", 0, 0},
		{`"\"`, "string not terminated", 0, 0},
		{`"\x`, "string not terminated", 0, 0},
		{`"\x"`, "invalid character '\"' in hexadecimal escape", 0, 3},
		{`"\y"`, "unknown escape", 0, 2},
		{`"\x0"`, "invalid character '\"' in hexadecimal escape", 0, 4},
		{`"\00"`, "invalid character '\"' in octal escape", 0, 4},
		{`"\377" /*`, "comment not terminated", 0, 7}, // valid octal escape
		{`"\378"`, "invalid character '8' in octal escape", 0, 4},
		{`"\400"`, "octal escape value 256 > 255", 0, 5},

		{`s := "foo\z"`, "unknown escape", 0, 10},
		{`s := "foo\z00\nbar"`, "unknown escape", 0, 10},
		{`"\x`, "string not terminated", 0, 0},
		{`"\x"`, "invalid character '\"' in hexadecimal escape", 0, 3},
		{`var s string = "\x"`, "invalid character '\"' in hexadecimal escape", 0, 18},
		{`return "\Uffffffff"`, "escape is invalid Unicode code point U+FFFFFFFF", 0, 18},

		{"0b.0", "invalid radix point in binary literal", 0, 2},
		{"0x.p0\n", "hexadecimal literal has no digits", 0, 3},

		// former problem cases
		{"package p\n\n\xef", "invalid UTF-8 encoding", 2, 0},
	} {
		var s scanner
		var line, col uint
		var err string
		s.init(strings.NewReader(test.src), func(l, c uint, msg string) {
			if err == "" {
				line, col = l-linebase, c-colbase
				err = msg
			}
		}, 0)

		for {
			s.next()
			if s.tok == _EOF {
				break
			}
		}

		if err != "" {
			if err != test.err {
				t.Errorf("%q: got err = %q; want %q", test.src, err, test.err)
			}
			if line != test.line {
				t.Errorf("%q: got line = %d; want %d", test.src, line, test.line)
			}
			if col != test.col {
				t.Errorf("%q: got col = %d; want %d", test.src, col, test.col)
			}
		} else {
			t.Errorf("%q: got no error; want %q", test.src, test.err)
		}
	}
}

func TestDirectives(t *testing.T) {
	for _, src := range []string{
		"line",
		"// line",
		"//line",
		"//line foo",
		"//line foo%bar",

		"go",
		"// go:",
		"//go:",
		"//go :foo",
		"//go:foo",
		"//go:foo%bar",
	} {
		got := ""
		var s scanner
		s.init(strings.NewReader(src), func(_, col uint, msg string) {
			if col != colbase {
				t.Errorf("%s: got col = %d; want %d", src, col, colbase)
			}
			if msg == "" {
				t.Errorf("%s: handler called with empty msg", src)
			}
			got = msg
		}, directives)

		s.next()
		if strings.HasPrefix(src, "//line ") || strings.HasPrefix(src, "//go:") {
			// handler should have been called
			if got != src {
				t.Errorf("got %s; want %s", got, src)
			}
		} else {
			// handler should not have been called
			if got != "" {
				t.Errorf("got %s for %s", got, src)
			}
		}
	}
}

func TestIssue21938(t *testing.T) {
	s := "/*" + strings.Repeat(" ", 4089) + "*/ .5"

	var got scanner
	got.init(strings.NewReader(s), errh, 0)
	got.next()

	if got.tok != _Literal || got.lit != ".5" {
		t.Errorf("got %s %q; want %s %q", got.tok, got.lit, _Literal, ".5")
	}
}

func TestIssue33961(t *testing.T) {
	literals := `08__ 0b.p 0b_._p 0x.e 0x.p`
	for _, lit := range strings.Split(literals, " ") {
		n := 0
		var got scanner
		got.init(strings.NewReader(lit), func(_, _ uint, msg string) {
			// fmt.Printf("%s: %s\n", lit, msg) // uncomment for debugging
			n++
		}, 0)
		got.next()

		if n != 1 {
			t.Errorf("%q: got %d errors; want 1", lit, n)
			continue
		}

		if !got.bad {
			t.Errorf("%q: got error but bad not set", lit)
		}
	}
}

"""



```