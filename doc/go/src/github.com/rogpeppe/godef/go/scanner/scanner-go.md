Response:
Here's a breakdown of the thought process to answer the question:

1. **Understand the Core Request:** The request asks for a functional description of the provided Go code snippet, identification of the Go feature it implements, code examples, command-line argument handling (if any), and common pitfalls.

2. **Identify the Package and Core Functionality:** The preamble clearly states `package scanner` and describes it as implementing a "scanner for Go source text." This immediately points to lexical analysis or tokenization. The `Scan()` method is mentioned prominently in the usage example, further solidifying this.

3. **Analyze the `Scanner` Struct:**  Examine the fields within the `Scanner` struct. Key fields include:
    * `file *token.File`:  Indicates interaction with file metadata.
    * `src []byte`: Stores the source code.
    * `err ErrorHandler`: Handles errors during scanning.
    * `mode uint`: Suggests configurable scanning behavior (comments, illegal chars, semicolons).
    * `ch rune`:  The current character being processed.
    * `offset`, `rdOffset`, `lineOffset`:  Track the scanner's position.
    * `insertSemi`: Handles automatic semicolon insertion.

4. **Examine Key Methods:**
    * `Init()`:  Initializes the scanner. Notice the `mode` parameter, which is significant. The example usage shows how `token.NewFileSet()` and `file.AddFile()` are used to provide context.
    * `next()`: Advances the scanner to the next character, handling UTF-8 and line breaks.
    * `Scan()`: The core method. It skips whitespace and then uses a `switch` statement to identify tokens based on the current character. It returns the position, token type, and literal value.
    * `scanIdentifier()`, `scanNumber()`, `scanString()`, etc.:  These are helper methods to scan specific types of tokens.
    * `scanComment()`: Handles both `//` and `/* */` comments. The `ScanComments` mode flag is relevant here.
    * `skipWhitespace()`:  Crucial for moving between tokens.
    * `switch2`, `switch3`, `switch4`:  Helper functions for multi-character operators (e.g., `+=`, `>>=`).

5. **Identify the Go Feature:** Based on the analysis, the code is clearly implementing a **lexical scanner** or **tokenizer**. This is a fundamental part of any compiler or interpreter, responsible for breaking down the source code into meaningful units (tokens).

6. **Construct Code Examples:**  Demonstrate the basic usage pattern shown in the package documentation. Include setting up `token.FileSet`, `token.File`, initializing the `Scanner`, and the loop using `s.Scan()` to iterate through tokens. Show cases with and without comments to illustrate the `ScanComments` mode.

7. **Infer Command-Line Argument Handling:**  The provided code *itself* doesn't directly handle command-line arguments. However, it's a *component* that would be used in tools that *do* process command-line arguments to read source files. Explain that this scanner would be part of a larger program that reads files specified on the command line.

8. **Identify Potential Pitfalls:**  Focus on aspects that might confuse users or lead to errors:
    * **Manual Semicolon Insertion:** Explain how Go automatically inserts semicolons and when the scanner does this. Give examples of when this works and when it might lead to unexpected behavior.
    * **Error Handling:** Emphasize the importance of checking `ErrorCount` or providing an `ErrorHandler` because `Scan()` tries to return *a* token even in case of errors.
    * **FileSet and Positions:** Explain that token positions are relative to the `token.FileSet` and the `token.File`. This context is important for error reporting and other tools.

9. **Structure the Answer:** Organize the information logically using the prompts from the request:
    * Functionality List
    * Go Feature and Example
    * Command-Line Argument Handling
    * Common Pitfalls

10. **Refine and Polish:**  Review the answer for clarity, accuracy, and completeness. Ensure the code examples are correct and easy to understand. Use clear and concise language. For example, initially, I might have just said "it tokenizes the code," but elaborating on *how* it does this (identifying keywords, operators, literals, etc.) provides a better explanation. Similarly, initially, I might have overlooked the nuance of *indirect* command-line argument handling and then corrected it to explain its role within a larger process.
这段代码是 Go 语言 `go/scanner` 包中的 `scanner.go` 文件的一部分，它实现了一个 **Go 语言源代码的词法分析器 (Lexical Scanner)**。  词法分析器，也称为扫描器，负责将输入的源代码文本分解成一个个有意义的 **词法单元 (tokens)**。

**功能列举:**

1. **初始化 (Initialization):**  `Init` 方法用于初始化扫描器，将它与特定的源文件 (`token.File`) 和源代码 (`[]byte`) 关联起来。它还允许设置错误处理函数和扫描模式。
2. **扫描下一个词法单元 (Scanning):** `Scan` 方法是核心功能，它从当前位置开始扫描，识别并返回下一个词法单元及其相关信息，包括：
    * `token.Pos`: 词法单元在源代码中的起始位置。
    * `token.Token`: 词法单元的类型 (例如：标识符、关键字、运算符、字面量等)。
    * `string`: 词法单元的字面值字符串。
3. **处理不同类型的词法单元:** 扫描器能够识别和处理 Go 语言中各种类型的词法单元，包括：
    * **标识符 (Identifiers):** 变量名、函数名等。
    * **关键字 (Keywords):** `if`, `else`, `for`, `func` 等。
    * **运算符 (Operators):** `+`, `-`, `*`, `/`, `=`, `==` 等。
    * **分隔符 (Delimiters):** `(`, `)`, `{`, `}`, `,`, `;` 等。
    * **字面量 (Literals):**
        * 整型字面量 (Integer literals): `123`, `0xFF`, `077`.
        * 浮点型字面量 (Float literals): `3.14`, `1e-5`.
        * 字符串字面量 (String literals): `"hello"`, `` `world` ``.
        * 字符字面量 (Character literals): `'a'`, `'\n'`.
    * **注释 (Comments):** `//` 单行注释和 `/* */` 多行注释。
4. **处理空白符 (Whitespace):**  默认情况下，扫描器会跳过空格、制表符、换行符等空白字符。
5. **错误处理 (Error Handling):** 当遇到非法的字符或格式错误时，扫描器会调用预先设置的错误处理函数 (`ErrorHandler`) 报告错误，并增加错误计数器 `ErrorCount`。
6. **自动插入分号 (Automatic Semicolon Insertion):** 根据 Go 语言的规则，扫描器在某些情况下会自动插入分号，例如在换行符之前如果前一个词法单元是可能作为语句结尾的类型。
7. **处理指令注释 (Directive Comments):** 扫描器可以识别以 `//line` 开头的特殊注释，用于修改后续代码的行号和文件名信息，这主要用于代码生成工具。
8. **支持不同的扫描模式 (Scanning Modes):**  通过 `Init` 方法的 `mode` 参数，可以控制扫描器的行为，例如是否返回注释作为词法单元，是否允许非法字符，以及是否启用自动插入分号。

**推理出的 Go 语言功能实现： 词法分析 (Lexical Analysis)**

这段代码是 Go 语言编译器前端进行词法分析的关键部分。词法分析是编译过程的第一步，它的作用是将源代码文本转换成一个由词法单元组成的序列，为后续的语法分析 (Parsing) 提供基础。

**Go 代码举例说明:**

假设有以下 Go 源代码 `example.go`:

```go
package main

import "fmt"

func main() {
	message := "Hello, Go!" // A greeting message
	fmt.Println(message)
}
```

我们可以使用 `go/scanner` 包来扫描这段代码：

```go
package main

import (
	"fmt"
	"go/scanner"
	"go/token"
)

func main() {
	src := []byte(`package main

import "fmt"

func main() {
	message := "Hello, Go!" // A greeting message
	fmt.Println(message)
}`)

	fset := token.NewFileSet()
	file := fset.AddFile("example.go", fset.Base(), len(src))

	var s scanner.Scanner
	s.Init(file, src, nil, 0) // 使用默认模式

	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		fmt.Printf("%s\t%s\t%q\n", fset.Position(pos), tok, lit)
	}

	if s.ErrorCount > 0 {
		fmt.Println("发现错误")
	}
}
```

**假设的输入与输出:**

**输入 (src):**  上面 `example.go` 的源代码字符串。

**输出 (部分):**

```
example.go:1:1	PACKAGE	"package"
example.go:1:9	IDENT	"main"
example.go:1:13	NEWLINE	"\n"
example.go:3:1	IMPORT	"import"
example.go:3:8	STRING	"fmt"
example.go:3:13	NEWLINE	"\n"
example.go:5:1	FUNC	"func"
example.go:5:6	IDENT	"main"
example.go:5:10	LPAREN	"("
example.go:5:11	RPAREN	")"
example.go:5:13	LBRACE	"{"
example.go:5:14	NEWLINE	"\n"
example.go:6:2	IDENT	"message"
example.go:6:10	DEFINE	":="
example.go:6:13	STRING	"Hello, Go!"
example.go:6:27	COMMENT	"// A greeting message"
example.go:6:48	NEWLINE	"\n"
example.go:7:2	IDENT	"fmt"
example.go:7:5	PERIOD	"."
example.go:7:6	IDENT	"Println"
example.go:7:13	LPAREN	"("
example.go:7:14	IDENT	"message"
example.go:7:21	RPAREN	")"
example.go:7:22	NEWLINE	"\n"
example.go:8:1	RBRACE	"}"
example.go:8:2	NEWLINE	"\n"
```

这个输出显示了每个词法单元的位置、类型和字面值。例如，`"package"` 被识别为 `PACKAGE` 类型的词法单元，`"main"` 被识别为 `IDENT` (标识符) 类型的词法单元。 注释默认情况下不会作为独立的 token 返回，除非使用了 `scanner.ScanComments` 模式。

**命令行参数的具体处理:**

这段 `scanner.go` 的代码本身 **并不直接处理命令行参数**。它是一个底层的词法分析器，通常被 Go 语言的编译器、代码分析工具 (如 `go vet`) 或其他需要解析 Go 代码的程序使用。

处理命令行参数通常发生在调用 `go/scanner` 的上层应用中。例如，Go 编译器 `cmd/compile` 会接收命令行参数，确定要编译的源文件，然后将文件内容传递给 `go/scanner` 进行词法分析。

一个使用 `go/scanner` 的工具可能会这样处理命令行参数：

1. **使用 `flag` 标准库或第三方库解析命令行参数。**
2. **获取要扫描的 Go 源代码文件的路径。**
3. **读取源文件内容到 `[]byte`。**
4. **调用 `scanner.Init` 初始化扫描器。**
5. **循环调用 `scanner.Scan` 获取词法单元。**

**使用者易犯错的点:**

1. **忽略错误:** `Scan` 方法即使遇到错误也会尝试返回一个合法的 token，因此使用者需要检查 `s.ErrorCount` 或提供 `ErrorHandler` 来捕获和处理扫描过程中出现的错误。

   ```go
   // 错误示例：未检查错误
   for {
       _, tok, _ := s.Scan()
       if tok == token.EOF {
           break
       }
       // 假设代码总是正确的
   }

   // 正确示例：检查错误
   for {
       pos, tok, lit := s.Scan()
       if tok == token.EOF {
           break
       }
       if tok == token.ILLEGAL {
           fmt.Printf("错误位置: %s, 错误字符: %q\n", fset.Position(pos), lit)
       }
       // ... 处理 token
   }
   ```

2. **不理解自动分号插入规则:**  Go 语言会自动插入分号，但这并不意味着可以随意省略分号。在某些特定的语法结构中，省略分号可能会导致解析错误。

   ```go
   // 容易出错的情况：函数返回多个值时
   func add(a, b int) (int, error) {
       return a + b, nil // 正常
   }

   func subtract(a, b int) (int, error) {
       return a - b,  // 换行可能导致分号被错误插入
       nil
   }
   ```
   在 `subtract` 函数中，`return a - b,` 后的换行可能会被解释为语句的结束，自动插入分号，导致 `nil` 成为下一条语句，从而引发编译错误。

3. **错误地使用扫描模式:**  如果不清楚 `ScanComments`、`AllowIllegalChars` 和 `InsertSemis` 等模式的影响，可能会导致意外的行为。例如，期望获取注释作为 token 但没有设置 `ScanComments` 模式。

   ```go
   // 错误示例：期望获取注释但未使用 ScanComments 模式
   s.Init(file, src, nil, 0)
   for {
       _, tok, lit := s.Scan()
       if tok == token.EOF {
           break
       }
       if tok == token.COMMENT { // 永远不会匹配
           fmt.Println("发现注释:", lit)
       }
   }

   // 正确示例：使用 ScanComments 模式
   s.Init(file, src, nil, scanner.ScanComments)
   for {
       _, tok, lit := s.Scan()
       if tok == token.EOF {
           break
       }
       if tok == token.COMMENT {
           fmt.Println("发现注释:", lit)
       }
   }
   ```

了解这些常见错误可以帮助使用者更有效地使用 `go/scanner` 包进行 Go 语言源代码的分析。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/go/scanner/scanner.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scanner implements a scanner for Go source text. Takes a []byte as
// source which can then be tokenized through repeated calls to the Scan
// function. Typical use:
//
//	var s Scanner
//	fset := token.NewFileSet()  // position information is relative to fset
//      file := fset.AddFile(filename, fset.Base(), len(src))  // register file
//	s.Init(file, src, nil /* no error handler */, 0)
//	for {
//		pos, tok, lit := s.Scan()
//		if tok == token.EOF {
//			break
//		}
//		// do something here with pos, tok, and lit
//	}
//
package scanner

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/rogpeppe/godef/go/token"
)

// A Scanner holds the scanner's internal state while processing
// a given text.  It can be allocated as part of another data
// structure but must be initialized via Init before use.
//
type Scanner struct {
	// immutable state
	file *token.File  // source file handle
	dir  string       // directory portion of file.Name()
	src  []byte       // source
	err  ErrorHandler // error reporting; or nil
	mode uint         // scanning mode

	// scanning state
	ch         rune // current character
	offset     int  // character offset
	rdOffset   int  // reading offset (position after current character)
	lineOffset int  // current line offset
	insertSemi bool // insert a semicolon before next newline

	// public state - ok to modify
	ErrorCount int // number of errors encountered
}

// Read the next Unicode char into S.ch.
// S.ch < 0 means end-of-file.
//
func (S *Scanner) next() {
	if S.rdOffset < len(S.src) {
		S.offset = S.rdOffset
		if S.ch == '\n' {
			S.lineOffset = S.offset
			S.file.AddLine(S.offset)
		}
		r, w := rune(S.src[S.rdOffset]), 1
		switch {
		case r == 0:
			S.error(S.offset, "illegal character NUL")
		case r >= 0x80:
			// not ASCII
			r, w = utf8.DecodeRune(S.src[S.rdOffset:])
			if r == utf8.RuneError && w == 1 {
				S.error(S.offset, "illegal UTF-8 encoding")
			}
		}
		S.rdOffset += w
		S.ch = r
	} else {
		S.offset = len(S.src)
		if S.ch == '\n' {
			S.lineOffset = S.offset
			S.file.AddLine(S.offset)
		}
		S.ch = -1 // eof
	}
}

// The mode parameter to the Init function is a set of flags (or 0).
// They control scanner behavior.
//
const (
	ScanComments      = 1 << iota // return comments as COMMENT tokens
	AllowIllegalChars             // do not report an error for illegal chars
	InsertSemis                   // automatically insert semicolons
)

// Init prepares the scanner S to tokenize the text src by setting the
// scanner at the beginning of src. The scanner uses the file set file
// for position information and it adds line information for each line.
// It is ok to re-use the same file when re-scanning the same file as
// line information which is already present is ignored. Init causes a
// panic if the file size does not match the src size.
//
// Calls to Scan will use the error handler err if they encounter a
// syntax error and err is not nil. Also, for each error encountered,
// the Scanner field ErrorCount is incremented by one. The mode parameter
// determines how comments, illegal characters, and semicolons are handled.
//
// Note that Init may call err if there is an error in the first character
// of the file.
//
func (S *Scanner) Init(file *token.File, src []byte, err ErrorHandler, mode uint) {
	// Explicitly initialize all fields since a scanner may be reused.
	if file.Size() != len(src) {
		panic("file size does not match src len")
	}
	S.file = file
	S.dir, _ = filepath.Split(file.Name())
	S.src = src
	S.err = err
	S.mode = mode

	S.ch = ' '
	S.offset = 0
	S.rdOffset = 0
	S.lineOffset = 0
	S.insertSemi = false
	S.ErrorCount = 0

	S.next()
}

func (S *Scanner) error(offs int, msg string) {
	if S.err != nil {
		S.err.Error(S.file.Position(S.file.Pos(offs)), msg)
	}
	S.ErrorCount++
}

var prefix = []byte("//line ")

func (S *Scanner) interpretLineComment(text []byte) {
	if bytes.HasPrefix(text, prefix) {
		// get filename and line number, if any
		if i := bytes.LastIndex(text, []byte{':'}); i > 0 {
			if line, err := strconv.Atoi(string(text[i+1:])); err == nil && line > 0 {
				// valid //line filename:line comment;
				filename := filepath.Clean(string(text[len(prefix):i]))
				if !filepath.IsAbs(filename) {
					// make filename relative to current directory
					filename = filepath.Join(S.dir, filename)
				}
				// update scanner position
				S.file.AddLineInfo(S.lineOffset, filename, line-1) // -1 since comment applies to next line
			}
		}
	}
}

func (S *Scanner) scanComment() {
	// initial '/' already consumed; S.ch == '/' || S.ch == '*'
	offs := S.offset - 1 // position of initial '/'

	if S.ch == '/' {
		//-style comment
		S.next()
		for S.ch != '\n' && S.ch >= 0 {
			S.next()
		}
		if offs == S.lineOffset {
			// comment starts at the beginning of the current line
			S.interpretLineComment(S.src[offs:S.offset])
		}
		return
	}

	/*-style comment */
	S.next()
	for S.ch >= 0 {
		ch := S.ch
		S.next()
		if ch == '*' && S.ch == '/' {
			S.next()
			return
		}
	}

	S.error(offs, "comment not terminated")
}

func (S *Scanner) findLineEnd() bool {
	// initial '/' already consumed

	defer func(offs int) {
		// reset scanner state to where it was upon calling findLineEnd
		S.ch = '/'
		S.offset = offs
		S.rdOffset = offs + 1
		S.next() // consume initial '/' again
	}(S.offset - 1)

	// read ahead until a newline, EOF, or non-comment token is found
	for S.ch == '/' || S.ch == '*' {
		if S.ch == '/' {
			//-style comment always contains a newline
			return true
		}
		/*-style comment: look for newline */
		S.next()
		for S.ch >= 0 {
			ch := S.ch
			if ch == '\n' {
				return true
			}
			S.next()
			if ch == '*' && S.ch == '/' {
				S.next()
				break
			}
		}
		S.skipWhitespace() // S.insertSemi is set
		if S.ch < 0 || S.ch == '\n' {
			return true
		}
		if S.ch != '/' {
			// non-comment token
			return false
		}
		S.next() // consume '/'
	}

	return false
}

func isLetter(ch rune) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' || ch >= 0x80 && unicode.IsLetter(ch)
}

func isDigit(ch rune) bool {
	return '0' <= ch && ch <= '9' || ch >= 0x80 && unicode.IsDigit(ch)
}

func (S *Scanner) scanIdentifier() token.Token {
	offs := S.offset
	for isLetter(S.ch) || isDigit(S.ch) {
		S.next()
	}
	return token.Lookup(S.src[offs:S.offset])
}

func digitVal(ch rune) int {
	switch {
	case '0' <= ch && ch <= '9':
		return int(ch - '0')
	case 'a' <= ch && ch <= 'f':
		return int(ch - 'a' + 10)
	case 'A' <= ch && ch <= 'F':
		return int(ch - 'A' + 10)
	}
	return 16 // larger than any legal digit val
}

func (S *Scanner) scanMantissa(base int) {
	for digitVal(S.ch) < base {
		S.next()
	}
}

func (S *Scanner) scanNumber(seenDecimalPoint bool) token.Token {
	// digitVal(S.ch) < 10
	tok := token.INT

	if seenDecimalPoint {
		tok = token.FLOAT
		S.scanMantissa(10)
		goto exponent
	}

	if S.ch == '0' {
		// int or float
		offs := S.offset
		S.next()
		if S.ch == 'x' || S.ch == 'X' {
			// hexadecimal int
			S.next()
			S.scanMantissa(16)
			if S.offset-offs <= 2 {
				// only scanned "0x" or "0X"
				S.error(offs, "illegal hexadecimal number")
			}
		} else {
			// octal int or float
			seenDecimalDigit := false
			S.scanMantissa(8)
			if S.ch == '8' || S.ch == '9' {
				// illegal octal int or float
				seenDecimalDigit = true
				S.scanMantissa(10)
			}
			if S.ch == '.' || S.ch == 'e' || S.ch == 'E' || S.ch == 'i' {
				goto fraction
			}
			// octal int
			if seenDecimalDigit {
				S.error(offs, "illegal octal number")
			}
		}
		goto exit
	}

	// decimal int or float
	S.scanMantissa(10)

fraction:
	if S.ch == '.' {
		tok = token.FLOAT
		S.next()
		S.scanMantissa(10)
	}

exponent:
	if S.ch == 'e' || S.ch == 'E' {
		tok = token.FLOAT
		S.next()
		if S.ch == '-' || S.ch == '+' {
			S.next()
		}
		S.scanMantissa(10)
	}

	if S.ch == 'i' {
		tok = token.IMAG
		S.next()
	}

exit:
	return tok
}

func (S *Scanner) scanEscape(quote rune) {
	offs := S.offset

	var i, base, max uint32
	switch S.ch {
	case 'a', 'b', 'f', 'n', 'r', 't', 'v', '\\', quote:
		S.next()
		return
	case '0', '1', '2', '3', '4', '5', '6', '7':
		i, base, max = 3, 8, 255
	case 'x':
		S.next()
		i, base, max = 2, 16, 255
	case 'u':
		S.next()
		i, base, max = 4, 16, unicode.MaxRune
	case 'U':
		S.next()
		i, base, max = 8, 16, unicode.MaxRune
	default:
		S.next() // always make progress
		S.error(offs, "unknown escape sequence")
		return
	}

	var x uint32
	for ; i > 0 && S.ch != quote && S.ch >= 0; i-- {
		d := uint32(digitVal(S.ch))
		if d >= base {
			S.error(S.offset, "illegal character in escape sequence")
			break
		}
		x = x*base + d
		S.next()
	}
	// in case of an error, consume remaining chars
	for ; i > 0 && S.ch != quote && S.ch >= 0; i-- {
		S.next()
	}
	if x > max || 0xd800 <= x && x < 0xe000 {
		S.error(offs, "escape sequence is invalid Unicode code point")
	}
}

func (S *Scanner) scanChar() {
	// '\'' opening already consumed
	offs := S.offset - 1

	n := 0
	for S.ch != '\'' {
		ch := S.ch
		n++
		S.next()
		if ch == '\n' || ch < 0 {
			S.error(offs, "character literal not terminated")
			n = 1
			break
		}
		if ch == '\\' {
			S.scanEscape('\'')
		}
	}

	S.next()

	if n != 1 {
		S.error(offs, "illegal character literal")
	}
}

func (S *Scanner) scanString() {
	// '"' opening already consumed
	offs := S.offset - 1

	for S.ch != '"' {
		ch := S.ch
		S.next()
		if ch == '\n' || ch < 0 {
			S.error(offs, "string not terminated")
			break
		}
		if ch == '\\' {
			S.scanEscape('"')
		}
	}

	S.next()
}

func (S *Scanner) scanRawString() {
	// '`' opening already consumed
	offs := S.offset - 1

	for S.ch != '`' {
		ch := S.ch
		S.next()
		if ch < 0 {
			S.error(offs, "string not terminated")
			break
		}
	}

	S.next()
}

func (S *Scanner) skipWhitespace() {
	for S.ch == ' ' || S.ch == '\t' || S.ch == '\n' && !S.insertSemi || S.ch == '\r' {
		S.next()
	}
}

// Helper functions for scanning multi-byte tokens such as >> += >>= .
// Different routines recognize different length tok_i based on matches
// of ch_i. If a token ends in '=', the result is tok1 or tok3
// respectively. Otherwise, the result is tok0 if there was no other
// matching character, or tok2 if the matching character was ch2.

func (S *Scanner) switch2(tok0, tok1 token.Token) token.Token {
	if S.ch == '=' {
		S.next()
		return tok1
	}
	return tok0
}

func (S *Scanner) switch3(tok0, tok1 token.Token, ch2 rune, tok2 token.Token) token.Token {
	if S.ch == '=' {
		S.next()
		return tok1
	}
	if S.ch == ch2 {
		S.next()
		return tok2
	}
	return tok0
}

func (S *Scanner) switch4(tok0, tok1 token.Token, ch2 rune, tok2, tok3 token.Token) token.Token {
	if S.ch == '=' {
		S.next()
		return tok1
	}
	if S.ch == ch2 {
		S.next()
		if S.ch == '=' {
			S.next()
			return tok3
		}
		return tok2
	}
	return tok0
}

// Scan scans the next token and returns the token position,
// the token, and the literal string corresponding to the
// token. The source end is indicated by token.EOF.
//
// If the returned token is token.SEMICOLON, the corresponding
// literal string is ";" if the semicolon was present in the source,
// and "\n" if the semicolon was inserted because of a newline or
// at EOF.
//
// For more tolerant parsing, Scan will return a valid token if
// possible even if a syntax error was encountered. Thus, even
// if the resulting token sequence contains no illegal tokens,
// a client may not assume that no error occurred. Instead it
// must check the scanner's ErrorCount or the number of calls
// of the error handler, if there was one installed.
//
// Scan adds line information to the file added to the file
// set with Init. Token positions are relative to that file
// and thus relative to the file set.
//
func (S *Scanner) Scan() (token.Pos, token.Token, string) {
scanAgain:
	S.skipWhitespace()

	// current token start
	insertSemi := false
	offs := S.offset
	tok := token.ILLEGAL

	// determine token value
	switch ch := S.ch; {
	case isLetter(ch):
		tok = S.scanIdentifier()
		switch tok {
		case token.IDENT, token.BREAK, token.CONTINUE, token.FALLTHROUGH, token.RETURN:
			insertSemi = true
		}
	case digitVal(ch) < 10:
		insertSemi = true
		tok = S.scanNumber(false)
	default:
		S.next() // always make progress
		switch ch {
		case -1:
			if S.insertSemi {
				S.insertSemi = false // EOF consumed
				return S.file.Pos(offs), token.SEMICOLON, "\n"
			}
			tok = token.EOF
		case '\n':
			// we only reach here if S.insertSemi was
			// set in the first place and exited early
			// from S.skipWhitespace()
			S.insertSemi = false // newline consumed
			return S.file.Pos(offs), token.SEMICOLON, "\n"
		case '"':
			insertSemi = true
			tok = token.STRING
			S.scanString()
		case '\'':
			insertSemi = true
			tok = token.CHAR
			S.scanChar()
		case '`':
			insertSemi = true
			tok = token.STRING
			S.scanRawString()
		case ':':
			tok = S.switch2(token.COLON, token.DEFINE)
		case '.':
			if digitVal(S.ch) < 10 {
				insertSemi = true
				tok = S.scanNumber(true)
			} else if S.ch == '.' {
				S.next()
				if S.ch == '.' {
					S.next()
					tok = token.ELLIPSIS
				}
			} else {
				tok = token.PERIOD
			}
		case ',':
			tok = token.COMMA
		case ';':
			tok = token.SEMICOLON
		case '(':
			tok = token.LPAREN
		case ')':
			insertSemi = true
			tok = token.RPAREN
		case '[':
			tok = token.LBRACK
		case ']':
			insertSemi = true
			tok = token.RBRACK
		case '{':
			tok = token.LBRACE
		case '}':
			insertSemi = true
			tok = token.RBRACE
		case '+':
			tok = S.switch3(token.ADD, token.ADD_ASSIGN, '+', token.INC)
			if tok == token.INC {
				insertSemi = true
			}
		case '-':
			tok = S.switch3(token.SUB, token.SUB_ASSIGN, '-', token.DEC)
			if tok == token.DEC {
				insertSemi = true
			}
		case '*':
			tok = S.switch2(token.MUL, token.MUL_ASSIGN)
		case '/':
			if S.ch == '/' || S.ch == '*' {
				// comment
				if S.insertSemi && S.findLineEnd() {
					// reset position to the beginning of the comment
					S.ch = '/'
					S.offset = offs
					S.rdOffset = offs + 1
					S.insertSemi = false // newline consumed
					return S.file.Pos(offs), token.SEMICOLON, "\n"
				}
				S.scanComment()
				if S.mode&ScanComments == 0 {
					// skip comment
					S.insertSemi = false // newline consumed
					goto scanAgain
				}
				tok = token.COMMENT
			} else {
				tok = S.switch2(token.QUO, token.QUO_ASSIGN)
			}
		case '%':
			tok = S.switch2(token.REM, token.REM_ASSIGN)
		case '^':
			tok = S.switch2(token.XOR, token.XOR_ASSIGN)
		case '<':
			if S.ch == '-' {
				S.next()
				tok = token.ARROW
			} else {
				tok = S.switch4(token.LSS, token.LEQ, '<', token.SHL, token.SHL_ASSIGN)
			}
		case '>':
			tok = S.switch4(token.GTR, token.GEQ, '>', token.SHR, token.SHR_ASSIGN)
		case '=':
			tok = S.switch2(token.ASSIGN, token.EQL)
		case '!':
			tok = S.switch2(token.NOT, token.NEQ)
		case '&':
			if S.ch == '^' {
				S.next()
				tok = S.switch2(token.AND_NOT, token.AND_NOT_ASSIGN)
			} else {
				tok = S.switch3(token.AND, token.AND_ASSIGN, '&', token.LAND)
			}
		case '|':
			tok = S.switch3(token.OR, token.OR_ASSIGN, '|', token.LOR)
		default:
			if S.mode&AllowIllegalChars == 0 {
				S.error(offs, fmt.Sprintf("illegal character %#U", ch))
			}
			insertSemi = S.insertSemi // preserve insertSemi info
		}
	}

	if S.mode&InsertSemis != 0 {
		S.insertSemi = insertSemi
	}

	// TODO(gri): The scanner API should change such that the literal string
	//            is only valid if an actual literal was scanned. This will
	//            permit a more efficient implementation.
	return S.file.Pos(offs), tok, string(S.src[offs:S.offset])
}

"""



```