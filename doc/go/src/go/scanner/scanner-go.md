Response:
Let's break down the thought process for analyzing the provided Go code snippet for `go/src/go/scanner/scanner.go`.

**1. Understanding the Core Request:**

The request asks for the functionality of the code, specifically focusing on:

* **Core Functionality:** What does this code *do*?
* **Go Feature Implementation:**  What Go language feature does it enable?
* **Code Examples:** Demonstrate its usage with Go code.
* **Input/Output:**  Hypothetical examples with expected results.
* **Command-Line Arguments:** If any are relevant.
* **Common Mistakes:**  Potential pitfalls for users.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to grasp its overall purpose. Keywords like `scanner`, `token`, `Scan`, `Init`, `ErrorHandler`, and comments like "implements a scanner for Go source text" are strong indicators. This suggests the code is responsible for breaking down Go source code into meaningful units (tokens).

**3. Identifying Key Data Structures and Methods:**

* **`Scanner` struct:** This is clearly the central data structure. Its fields like `file`, `src`, `ch`, `offset`, `rdOffset`, `lineOffset`, `insertSemi`, and `ErrorCount` provide clues about the scanning process (tracking position, characters, and errors).
* **`Init` method:**  Almost always the initialization function. It takes the source code (`[]byte`), a file representation (`token.File`), and an error handler.
* **`Scan` method:**  The primary workhorse, responsible for returning the next token.
* **`next` method:**  Likely responsible for advancing the scanner through the source code.
* **`error` and `errorf` methods:**  Handle reporting syntax errors.
* **`scanIdentifier`, `scanNumber`, `scanString`, `scanComment`:** These methods suggest how different types of tokens are parsed.

**4. Inferring Functionality based on Code Structure and Naming:**

* The presence of methods like `scanIdentifier`, `scanNumber`, `scanString`, `scanComment` strongly implies the scanner's ability to recognize these different kinds of lexical elements in Go code.
* The `insertSemi` flag and the logic around newlines in `Scan` suggest the implementation of Go's automatic semicolon insertion rules.
* The `ErrorHandler` type indicates a mechanism for reporting syntax errors encountered during scanning.
* The `Mode` type and the `ScanComments` flag suggest optional handling of comments.
* The `updateLineInfo` method, parsing `//line` directives, hints at the scanner's ability to handle source code transformations or debugging information.

**5. Connecting to Go Language Features:**

Based on the identified functionality, it becomes clear that this code implements the **lexical analysis** part of the Go compiler. It's responsible for turning raw source code text into a stream of tokens that the parser can then use to build an abstract syntax tree (AST).

**6. Crafting Code Examples:**

To illustrate the functionality, simple examples demonstrating scanning various Go code constructs are needed:

* **Keywords and Identifiers:** `func main() {}`
* **Operators:** `+, -, *, /`
* **Literals:** `123`, `"hello"`, `'a'`
* **Comments:** `// line comment`, `/* block comment */`

For each example, the expected output (the sequence of tokens) should be provided.

**7. Reasoning about Input and Output:**

Consider various input scenarios and how the scanner would process them:

* **Simple valid code:**  The scanner should produce the correct sequence of tokens.
* **Code with syntax errors:** The scanner should identify and report errors (through the `ErrorHandler`). The `ErrorCount` should increment. The scanner should try to recover and continue scanning if possible.
* **Code with comments:** Demonstrate how the `ScanComments` mode affects the output.

**8. Command-Line Arguments (Relevance Check):**

Scanners are typically used internally by compilers and related tools. While the *compiler* might have command-line arguments, the *scanner itself* usually doesn't. Therefore, it's appropriate to state that command-line arguments are not directly relevant to this specific code snippet.

**9. Identifying Common Mistakes:**

Think about how someone might misuse the scanner or what assumptions they might make incorrectly:

* **Assuming no errors if no `ILLEGAL` tokens are returned:** Emphasize the need to check `ErrorCount` or the error handler.
* **Ignoring the `ScanComments` mode:** Explain how the handling of comments differs based on this mode.
* **Misunderstanding automatic semicolon insertion:** Point out that the scanner handles this and where semicolons might be inserted automatically.

**10. Structuring the Answer:**

Organize the findings logically, addressing each point of the original request clearly and concisely. Use headings and formatting to improve readability. Provide code examples with clear explanations of the inputs and expected outputs.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps the scanner directly builds the AST.
* **Correction:** Realize that the scanner's role is primarily lexical analysis, and the parser handles the AST construction.
* **Initial example:**  Maybe focus on complex code.
* **Refinement:** Start with simpler examples to illustrate the basic tokenization process before moving to more nuanced cases like comments or error handling.
* **Consideration of error handling:** Initially, might forget to explicitly mention checking `ErrorCount`. Remember to add this crucial point.

By following these steps, one can effectively analyze the provided code snippet and generate a comprehensive and accurate explanation of its functionality. The key is to systematically examine the code, infer its purpose based on its structure and naming conventions, and connect it to the broader context of Go language processing.
这段代码是 Go 语言标准库中 `go/scanner` 包的一部分，它实现了一个 **Go 源代码的词法分析器（Scanner）**。 它的主要功能是将 Go 源代码文本分解成一系列的 **词法单元（Tokens）**，这些词法单元是构成 Go 语言程序的基本 building blocks。

**以下是它的具体功能：**

1. **初始化 ( `Init` 方法 )：**
   - 接收一个 `token.File` 对象，表示要扫描的源文件信息（文件名、大小等）。
   - 接收源代码的 `[]byte` 切片。
   - 接收一个可选的 `ErrorHandler` 函数，用于处理扫描过程中遇到的语法错误。
   - 接收一个 `Mode` 参数，用于控制扫描器的行为（例如，是否返回注释）。
   - 初始化扫描器的内部状态，例如当前字符、偏移量、行号等。
   - 检查提供的文件大小是否与源代码长度一致，不一致则会 panic。
   - 处理文件开头的字节顺序标记 (BOM)。

2. **扫描下一个词法单元 ( `Scan` 方法 )：**
   - 这是扫描器的核心方法。
   - 跳过空白字符（空格、制表符、换行符，但会考虑是否需要自动插入分号）。
   - 根据当前字符判断下一个词法单元的类型。
   - 识别标识符（变量名、函数名等）和关键字。
   - 识别各种类型的字面量（整数、浮点数、复数、字符、字符串）。
   - 识别运算符和分隔符（例如 `+`, `-`, `*`, `/`, `=`, `:`, `;`, `(`, `)`, `{`, `}` 等）。
   - 识别注释（单行 `//` 和多行 `/* ... */`）。
   - 处理并返回词法单元的位置信息 (`token.Pos`)、类型 (`token.Token`) 和字面值字符串 (`string`)。
   - 支持自动插入分号规则。
   - 如果遇到语法错误，会调用 `ErrorHandler`（如果已设置）并增加 `ErrorCount`。

3. **辅助扫描方法：**
   - `next()`: 读取下一个 Unicode 字符。
   - `peek()`: 查看下一个字符但不移动扫描位置。
   - `error()` 和 `errorf()`:  报告扫描过程中遇到的错误。
   - `scanIdentifier()`: 扫描标识符。
   - `scanNumber()`: 扫描数字字面量（整数、浮点数、复数）。
   - `scanString()` 和 `scanRawString()`: 扫描带引号的字符串和反引号引用的原始字符串。
   - `scanRune()`: 扫描字符字面量。
   - `scanComment()`: 扫描注释，并处理 `//line` 指令。
   - `skipWhitespace()`: 跳过空白字符。
   - `switch2()`, `switch3()`, `switch4()`:  辅助识别多字符运算符。
   - `scanEscape()`: 处理字符串和字符中的转义字符。
   - `digits()`: 扫描数字序列。
   - `trailingDigits()`: 从后向前提取数字。
   - `stripCR()`:  移除字节切片中的回车符 (`\r`)。

4. **错误处理：**
   - 通过 `ErrorHandler` 函数报告语法错误，提供错误发生的位置和消息。
   - 维护 `ErrorCount` 字段，记录遇到的错误数量。

5. **模式控制 ( `Mode` )：**
   - `ScanComments`:  如果设置，`Scan` 方法会将注释作为 `token.COMMENT` 返回。否则，注释会被跳过。
   - `dontInsertSemis`:  用于测试，禁用自动插入分号的功能。

**它可以实现 Go 语言的词法分析功能。**

**Go 代码示例：**

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
	fmt.Println("Hello, Go!")
}`)

	fset := token.NewFileSet()
	file := fset.AddFile("hello.go", fset.Base(), len(src))

	var s scanner.Scanner
	s.Init(file, src, nil, 0) // 初始化扫描器，不处理错误，不返回注释

	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		fmt.Printf("%s\t%s\t%q\n", fset.Position(pos), tok, lit)
	}
}
```

**假设的输入与输出：**

**输入 ( `src` )：**

```go
package main

import "fmt"

func main() {
	x := 10 + 5 // 计算结果
	fmt.Println(x)
}
```

**输出：**

```
hello.go:1:1	PACKAGE	"package"
hello.go:1:9	IDENT	"main"
hello.go:3:1	IMPORT	"import"
hello.go:3:8	STRING	"fmt"
hello.go:5:1	FUNC	"func"
hello.go:5:6	IDENT	"main"
hello.go:5:10	LPAREN	"("
hello.go:5:11	RPAREN	")"
hello.go:5:13	LBRACE	"{"
hello.go:6:2	IDENT	"x"
hello.go:6:4	DEFINE	":="
hello.go:6:7	INT	"10"
hello.go:6:10	ADD	"+"
hello.go:6:12	INT	"5"
hello.go:6:14	COMMENT	"// 计算结果"
hello.go:7:2	IDENT	"fmt"
hello.go:7:5	PERIOD	"."
hello.go:7:6	IDENT	"Println"
hello.go:7:13	LPAREN	"("
hello.go:7:14	IDENT	"x"
hello.go:7:15	RPAREN	")"
hello.go:8:1	RBRACE	"}"
```

**涉及命令行参数的具体处理：**

`go/scanner` 包本身并不直接处理命令行参数。它是一个用于词法分析的库，通常被 Go 语言的编译器、解释器或其他代码分析工具内部使用。这些工具可能会有自己的命令行参数，但在词法分析阶段，`go/scanner` 主要关注的是源代码文本。

**使用者易犯错的点：**

1. **假设没有 `ILLEGAL` 类型的 token 就没有错误：**
   - 即使 `Scan` 方法没有返回 `token.ILLEGAL`，仍然可能存在语法错误。使用者应该检查 `Scanner.ErrorCount` 或者是否调用了 `ErrorHandler`。
   - **示例：**
     ```go
     src := []byte("func main() int {") // 缺少闭合花括号
     // ... (Scanner 初始化和扫描)
     if s.ErrorCount > 0 {
         fmt.Println("发现语法错误！")
     }
     ```

2. **忽略 `ScanComments` 模式的影响：**
   - 如果需要处理注释（例如用于代码文档生成），必须在 `Init` 方法中设置 `scanner.ScanComments` 模式。否则，注释会被跳过。
   - **示例：**
     ```go
     var s scanner.Scanner
     s.Init(file, src, nil, scanner.ScanComments) // 启用返回注释
     ```

3. **不理解自动插入分号的规则：**
   - Go 语言会自动在某些情况下插入分号，例如在换行符之前，如果该行是语句的结尾。使用者可能会误认为不需要分号的地方就一定不会插入分号。
   - 扫描器会模拟这些规则，返回 `token.SEMICOLON`，其字面值可能是 `";"`（源文件中存在）或 `"\n"`（自动插入）。
   - **易错情况：**  在某些特定上下文中，换行会被解释为语句的结束并插入分号，可能导致意想不到的解析结果。

总而言之，`go/scanner/scanner.go` 是 Go 语言工具链中至关重要的组件，负责将源代码转化为可供后续语法分析和编译的词法单元流。理解其功能和使用方式对于开发 Go 语言工具或深入了解 Go 语言的编译过程非常有帮助。

### 提示词
```
这是路径为go/src/go/scanner/scanner.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scanner implements a scanner for Go source text.
// It takes a []byte as source which can then be tokenized
// through repeated calls to the Scan method.
package scanner

import (
	"bytes"
	"fmt"
	"go/token"
	"path/filepath"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// An ErrorHandler may be provided to [Scanner.Init]. If a syntax error is
// encountered and a handler was installed, the handler is called with a
// position and an error message. The position points to the beginning of
// the offending token.
type ErrorHandler func(pos token.Position, msg string)

// A Scanner holds the scanner's internal state while processing
// a given text. It can be allocated as part of another data
// structure but must be initialized via [Scanner.Init] before use.
type Scanner struct {
	// immutable state
	file *token.File  // source file handle
	dir  string       // directory portion of file.Name()
	src  []byte       // source
	err  ErrorHandler // error reporting; or nil
	mode Mode         // scanning mode

	// scanning state
	ch         rune      // current character
	offset     int       // character offset
	rdOffset   int       // reading offset (position after current character)
	lineOffset int       // current line offset
	insertSemi bool      // insert a semicolon before next newline
	nlPos      token.Pos // position of newline in preceding comment

	// public state - ok to modify
	ErrorCount int // number of errors encountered
}

const (
	bom = 0xFEFF // byte order mark, only permitted as very first character
	eof = -1     // end of file
)

// Read the next Unicode char into s.ch.
// s.ch < 0 means end-of-file.
//
// For optimization, there is some overlap between this method and
// s.scanIdentifier.
func (s *Scanner) next() {
	if s.rdOffset < len(s.src) {
		s.offset = s.rdOffset
		if s.ch == '\n' {
			s.lineOffset = s.offset
			s.file.AddLine(s.offset)
		}
		r, w := rune(s.src[s.rdOffset]), 1
		switch {
		case r == 0:
			s.error(s.offset, "illegal character NUL")
		case r >= utf8.RuneSelf:
			// not ASCII
			r, w = utf8.DecodeRune(s.src[s.rdOffset:])
			if r == utf8.RuneError && w == 1 {
				s.error(s.offset, "illegal UTF-8 encoding")
			} else if r == bom && s.offset > 0 {
				s.error(s.offset, "illegal byte order mark")
			}
		}
		s.rdOffset += w
		s.ch = r
	} else {
		s.offset = len(s.src)
		if s.ch == '\n' {
			s.lineOffset = s.offset
			s.file.AddLine(s.offset)
		}
		s.ch = eof
	}
}

// peek returns the byte following the most recently read character without
// advancing the scanner. If the scanner is at EOF, peek returns 0.
func (s *Scanner) peek() byte {
	if s.rdOffset < len(s.src) {
		return s.src[s.rdOffset]
	}
	return 0
}

// A mode value is a set of flags (or 0).
// They control scanner behavior.
type Mode uint

const (
	ScanComments    Mode = 1 << iota // return comments as COMMENT tokens
	dontInsertSemis                  // do not automatically insert semicolons - for testing only
)

// Init prepares the scanner s to tokenize the text src by setting the
// scanner at the beginning of src. The scanner uses the file set file
// for position information and it adds line information for each line.
// It is ok to re-use the same file when re-scanning the same file as
// line information which is already present is ignored. Init causes a
// panic if the file size does not match the src size.
//
// Calls to [Scanner.Scan] will invoke the error handler err if they encounter a
// syntax error and err is not nil. Also, for each error encountered,
// the [Scanner] field ErrorCount is incremented by one. The mode parameter
// determines how comments are handled.
//
// Note that Init may call err if there is an error in the first character
// of the file.
func (s *Scanner) Init(file *token.File, src []byte, err ErrorHandler, mode Mode) {
	// Explicitly initialize all fields since a scanner may be reused.
	if file.Size() != len(src) {
		panic(fmt.Sprintf("file size (%d) does not match src len (%d)", file.Size(), len(src)))
	}
	s.file = file
	s.dir, _ = filepath.Split(file.Name())
	s.src = src
	s.err = err
	s.mode = mode

	s.ch = ' '
	s.offset = 0
	s.rdOffset = 0
	s.lineOffset = 0
	s.insertSemi = false
	s.ErrorCount = 0

	s.next()
	if s.ch == bom {
		s.next() // ignore BOM at file beginning
	}
}

func (s *Scanner) error(offs int, msg string) {
	if s.err != nil {
		s.err(s.file.Position(s.file.Pos(offs)), msg)
	}
	s.ErrorCount++
}

func (s *Scanner) errorf(offs int, format string, args ...any) {
	s.error(offs, fmt.Sprintf(format, args...))
}

// scanComment returns the text of the comment and (if nonzero)
// the offset of the first newline within it, which implies a
// /*...*/ comment.
func (s *Scanner) scanComment() (string, int) {
	// initial '/' already consumed; s.ch == '/' || s.ch == '*'
	offs := s.offset - 1 // position of initial '/'
	next := -1           // position immediately following the comment; < 0 means invalid comment
	numCR := 0
	nlOffset := 0 // offset of first newline within /*...*/ comment

	if s.ch == '/' {
		//-style comment
		// (the final '\n' is not considered part of the comment)
		s.next()
		for s.ch != '\n' && s.ch >= 0 {
			if s.ch == '\r' {
				numCR++
			}
			s.next()
		}
		// if we are at '\n', the position following the comment is afterwards
		next = s.offset
		if s.ch == '\n' {
			next++
		}
		goto exit
	}

	/*-style comment */
	s.next()
	for s.ch >= 0 {
		ch := s.ch
		if ch == '\r' {
			numCR++
		} else if ch == '\n' && nlOffset == 0 {
			nlOffset = s.offset
		}
		s.next()
		if ch == '*' && s.ch == '/' {
			s.next()
			next = s.offset
			goto exit
		}
	}

	s.error(offs, "comment not terminated")

exit:
	lit := s.src[offs:s.offset]

	// On Windows, a (//-comment) line may end in "\r\n".
	// Remove the final '\r' before analyzing the text for
	// line directives (matching the compiler). Remove any
	// other '\r' afterwards (matching the pre-existing be-
	// havior of the scanner).
	if numCR > 0 && len(lit) >= 2 && lit[1] == '/' && lit[len(lit)-1] == '\r' {
		lit = lit[:len(lit)-1]
		numCR--
	}

	// interpret line directives
	// (//line directives must start at the beginning of the current line)
	if next >= 0 /* implies valid comment */ && (lit[1] == '*' || offs == s.lineOffset) && bytes.HasPrefix(lit[2:], prefix) {
		s.updateLineInfo(next, offs, lit)
	}

	if numCR > 0 {
		lit = stripCR(lit, lit[1] == '*')
	}

	return string(lit), nlOffset
}

var prefix = []byte("line ")

// updateLineInfo parses the incoming comment text at offset offs
// as a line directive. If successful, it updates the line info table
// for the position next per the line directive.
func (s *Scanner) updateLineInfo(next, offs int, text []byte) {
	// extract comment text
	if text[1] == '*' {
		text = text[:len(text)-2] // lop off trailing "*/"
	}
	text = text[7:] // lop off leading "//line " or "/*line "
	offs += 7

	i, n, ok := trailingDigits(text)
	if i == 0 {
		return // ignore (not a line directive)
	}
	// i > 0

	if !ok {
		// text has a suffix :xxx but xxx is not a number
		s.error(offs+i, "invalid line number: "+string(text[i:]))
		return
	}

	// Put a cap on the maximum size of line and column numbers.
	// 30 bits allows for some additional space before wrapping an int32.
	// Keep this consistent with cmd/compile/internal/syntax.PosMax.
	const maxLineCol = 1 << 30
	var line, col int
	i2, n2, ok2 := trailingDigits(text[:i-1])
	if ok2 {
		//line filename:line:col
		i, i2 = i2, i
		line, col = n2, n
		if col == 0 || col > maxLineCol {
			s.error(offs+i2, "invalid column number: "+string(text[i2:]))
			return
		}
		text = text[:i2-1] // lop off ":col"
	} else {
		//line filename:line
		line = n
	}

	if line == 0 || line > maxLineCol {
		s.error(offs+i, "invalid line number: "+string(text[i:]))
		return
	}

	// If we have a column (//line filename:line:col form),
	// an empty filename means to use the previous filename.
	filename := string(text[:i-1]) // lop off ":line", and trim white space
	if filename == "" && ok2 {
		filename = s.file.Position(s.file.Pos(offs)).Filename
	} else if filename != "" {
		// Put a relative filename in the current directory.
		// This is for compatibility with earlier releases.
		// See issue 26671.
		filename = filepath.Clean(filename)
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(s.dir, filename)
		}
	}

	s.file.AddLineColumnInfo(next, filename, line, col)
}

func trailingDigits(text []byte) (int, int, bool) {
	i := bytes.LastIndexByte(text, ':') // look from right (Windows filenames may contain ':')
	if i < 0 {
		return 0, 0, false // no ":"
	}
	// i >= 0
	n, err := strconv.ParseUint(string(text[i+1:]), 10, 0)
	return i + 1, int(n), err == nil
}

func isLetter(ch rune) bool {
	return 'a' <= lower(ch) && lower(ch) <= 'z' || ch == '_' || ch >= utf8.RuneSelf && unicode.IsLetter(ch)
}

func isDigit(ch rune) bool {
	return isDecimal(ch) || ch >= utf8.RuneSelf && unicode.IsDigit(ch)
}

// scanIdentifier reads the string of valid identifier characters at s.offset.
// It must only be called when s.ch is known to be a valid letter.
//
// Be careful when making changes to this function: it is optimized and affects
// scanning performance significantly.
func (s *Scanner) scanIdentifier() string {
	offs := s.offset

	// Optimize for the common case of an ASCII identifier.
	//
	// Ranging over s.src[s.rdOffset:] lets us avoid some bounds checks, and
	// avoids conversions to runes.
	//
	// In case we encounter a non-ASCII character, fall back on the slower path
	// of calling into s.next().
	for rdOffset, b := range s.src[s.rdOffset:] {
		if 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || b == '_' || '0' <= b && b <= '9' {
			// Avoid assigning a rune for the common case of an ascii character.
			continue
		}
		s.rdOffset += rdOffset
		if 0 < b && b < utf8.RuneSelf {
			// Optimization: we've encountered an ASCII character that's not a letter
			// or number. Avoid the call into s.next() and corresponding set up.
			//
			// Note that s.next() does some line accounting if s.ch is '\n', so this
			// shortcut is only possible because we know that the preceding character
			// is not '\n'.
			s.ch = rune(b)
			s.offset = s.rdOffset
			s.rdOffset++
			goto exit
		}
		// We know that the preceding character is valid for an identifier because
		// scanIdentifier is only called when s.ch is a letter, so calling s.next()
		// at s.rdOffset resets the scanner state.
		s.next()
		for isLetter(s.ch) || isDigit(s.ch) {
			s.next()
		}
		goto exit
	}
	s.offset = len(s.src)
	s.rdOffset = len(s.src)
	s.ch = eof

exit:
	return string(s.src[offs:s.offset])
}

func digitVal(ch rune) int {
	switch {
	case '0' <= ch && ch <= '9':
		return int(ch - '0')
	case 'a' <= lower(ch) && lower(ch) <= 'f':
		return int(lower(ch) - 'a' + 10)
	}
	return 16 // larger than any legal digit val
}

func lower(ch rune) rune     { return ('a' - 'A') | ch } // returns lower-case ch iff ch is ASCII letter
func isDecimal(ch rune) bool { return '0' <= ch && ch <= '9' }
func isHex(ch rune) bool     { return '0' <= ch && ch <= '9' || 'a' <= lower(ch) && lower(ch) <= 'f' }

// digits accepts the sequence { digit | '_' }.
// If base <= 10, digits accepts any decimal digit but records
// the offset (relative to the source start) of a digit >= base
// in *invalid, if *invalid < 0.
// digits returns a bitset describing whether the sequence contained
// digits (bit 0 is set), or separators '_' (bit 1 is set).
func (s *Scanner) digits(base int, invalid *int) (digsep int) {
	if base <= 10 {
		max := rune('0' + base)
		for isDecimal(s.ch) || s.ch == '_' {
			ds := 1
			if s.ch == '_' {
				ds = 2
			} else if s.ch >= max && *invalid < 0 {
				*invalid = s.offset // record invalid rune offset
			}
			digsep |= ds
			s.next()
		}
	} else {
		for isHex(s.ch) || s.ch == '_' {
			ds := 1
			if s.ch == '_' {
				ds = 2
			}
			digsep |= ds
			s.next()
		}
	}
	return
}

func (s *Scanner) scanNumber() (token.Token, string) {
	offs := s.offset
	tok := token.ILLEGAL

	base := 10        // number base
	prefix := rune(0) // one of 0 (decimal), '0' (0-octal), 'x', 'o', or 'b'
	digsep := 0       // bit 0: digit present, bit 1: '_' present
	invalid := -1     // index of invalid digit in literal, or < 0

	// integer part
	if s.ch != '.' {
		tok = token.INT
		if s.ch == '0' {
			s.next()
			switch lower(s.ch) {
			case 'x':
				s.next()
				base, prefix = 16, 'x'
			case 'o':
				s.next()
				base, prefix = 8, 'o'
			case 'b':
				s.next()
				base, prefix = 2, 'b'
			default:
				base, prefix = 8, '0'
				digsep = 1 // leading 0
			}
		}
		digsep |= s.digits(base, &invalid)
	}

	// fractional part
	if s.ch == '.' {
		tok = token.FLOAT
		if prefix == 'o' || prefix == 'b' {
			s.error(s.offset, "invalid radix point in "+litname(prefix))
		}
		s.next()
		digsep |= s.digits(base, &invalid)
	}

	if digsep&1 == 0 {
		s.error(s.offset, litname(prefix)+" has no digits")
	}

	// exponent
	if e := lower(s.ch); e == 'e' || e == 'p' {
		switch {
		case e == 'e' && prefix != 0 && prefix != '0':
			s.errorf(s.offset, "%q exponent requires decimal mantissa", s.ch)
		case e == 'p' && prefix != 'x':
			s.errorf(s.offset, "%q exponent requires hexadecimal mantissa", s.ch)
		}
		s.next()
		tok = token.FLOAT
		if s.ch == '+' || s.ch == '-' {
			s.next()
		}
		ds := s.digits(10, nil)
		digsep |= ds
		if ds&1 == 0 {
			s.error(s.offset, "exponent has no digits")
		}
	} else if prefix == 'x' && tok == token.FLOAT {
		s.error(s.offset, "hexadecimal mantissa requires a 'p' exponent")
	}

	// suffix 'i'
	if s.ch == 'i' {
		tok = token.IMAG
		s.next()
	}

	lit := string(s.src[offs:s.offset])
	if tok == token.INT && invalid >= 0 {
		s.errorf(invalid, "invalid digit %q in %s", lit[invalid-offs], litname(prefix))
	}
	if digsep&2 != 0 {
		if i := invalidSep(lit); i >= 0 {
			s.error(offs+i, "'_' must separate successive digits")
		}
	}

	return tok, lit
}

func litname(prefix rune) string {
	switch prefix {
	case 'x':
		return "hexadecimal literal"
	case 'o', '0':
		return "octal literal"
	case 'b':
		return "binary literal"
	}
	return "decimal literal"
}

// invalidSep returns the index of the first invalid separator in x, or -1.
func invalidSep(x string) int {
	x1 := ' ' // prefix char, we only care if it's 'x'
	d := '.'  // digit, one of '_', '0' (a digit), or '.' (anything else)
	i := 0

	// a prefix counts as a digit
	if len(x) >= 2 && x[0] == '0' {
		x1 = lower(rune(x[1]))
		if x1 == 'x' || x1 == 'o' || x1 == 'b' {
			d = '0'
			i = 2
		}
	}

	// mantissa and exponent
	for ; i < len(x); i++ {
		p := d // previous digit
		d = rune(x[i])
		switch {
		case d == '_':
			if p != '0' {
				return i
			}
		case isDecimal(d) || x1 == 'x' && isHex(d):
			d = '0'
		default:
			if p == '_' {
				return i - 1
			}
			d = '.'
		}
	}
	if d == '_' {
		return len(x) - 1
	}

	return -1
}

// scanEscape parses an escape sequence where rune is the accepted
// escaped quote. In case of a syntax error, it stops at the offending
// character (without consuming it) and returns false. Otherwise
// it returns true.
func (s *Scanner) scanEscape(quote rune) bool {
	offs := s.offset

	var n int
	var base, max uint32
	switch s.ch {
	case 'a', 'b', 'f', 'n', 'r', 't', 'v', '\\', quote:
		s.next()
		return true
	case '0', '1', '2', '3', '4', '5', '6', '7':
		n, base, max = 3, 8, 255
	case 'x':
		s.next()
		n, base, max = 2, 16, 255
	case 'u':
		s.next()
		n, base, max = 4, 16, unicode.MaxRune
	case 'U':
		s.next()
		n, base, max = 8, 16, unicode.MaxRune
	default:
		msg := "unknown escape sequence"
		if s.ch < 0 {
			msg = "escape sequence not terminated"
		}
		s.error(offs, msg)
		return false
	}

	var x uint32
	for n > 0 {
		d := uint32(digitVal(s.ch))
		if d >= base {
			msg := fmt.Sprintf("illegal character %#U in escape sequence", s.ch)
			if s.ch < 0 {
				msg = "escape sequence not terminated"
			}
			s.error(s.offset, msg)
			return false
		}
		x = x*base + d
		s.next()
		n--
	}

	if x > max || 0xD800 <= x && x < 0xE000 {
		s.error(offs, "escape sequence is invalid Unicode code point")
		return false
	}

	return true
}

func (s *Scanner) scanRune() string {
	// '\'' opening already consumed
	offs := s.offset - 1

	valid := true
	n := 0
	for {
		ch := s.ch
		if ch == '\n' || ch < 0 {
			// only report error if we don't have one already
			if valid {
				s.error(offs, "rune literal not terminated")
				valid = false
			}
			break
		}
		s.next()
		if ch == '\'' {
			break
		}
		n++
		if ch == '\\' {
			if !s.scanEscape('\'') {
				valid = false
			}
			// continue to read to closing quote
		}
	}

	if valid && n != 1 {
		s.error(offs, "illegal rune literal")
	}

	return string(s.src[offs:s.offset])
}

func (s *Scanner) scanString() string {
	// '"' opening already consumed
	offs := s.offset - 1

	for {
		ch := s.ch
		if ch == '\n' || ch < 0 {
			s.error(offs, "string literal not terminated")
			break
		}
		s.next()
		if ch == '"' {
			break
		}
		if ch == '\\' {
			s.scanEscape('"')
		}
	}

	return string(s.src[offs:s.offset])
}

func stripCR(b []byte, comment bool) []byte {
	c := make([]byte, len(b))
	i := 0
	for j, ch := range b {
		// In a /*-style comment, don't strip \r from *\r/ (incl.
		// sequences of \r from *\r\r...\r/) since the resulting
		// */ would terminate the comment too early unless the \r
		// is immediately following the opening /* in which case
		// it's ok because /*/ is not closed yet (issue #11151).
		if ch != '\r' || comment && i > len("/*") && c[i-1] == '*' && j+1 < len(b) && b[j+1] == '/' {
			c[i] = ch
			i++
		}
	}
	return c[:i]
}

func (s *Scanner) scanRawString() string {
	// '`' opening already consumed
	offs := s.offset - 1

	hasCR := false
	for {
		ch := s.ch
		if ch < 0 {
			s.error(offs, "raw string literal not terminated")
			break
		}
		s.next()
		if ch == '`' {
			break
		}
		if ch == '\r' {
			hasCR = true
		}
	}

	lit := s.src[offs:s.offset]
	if hasCR {
		lit = stripCR(lit, false)
	}

	return string(lit)
}

func (s *Scanner) skipWhitespace() {
	for s.ch == ' ' || s.ch == '\t' || s.ch == '\n' && !s.insertSemi || s.ch == '\r' {
		s.next()
	}
}

// Helper functions for scanning multi-byte tokens such as >> += >>= .
// Different routines recognize different length tok_i based on matches
// of ch_i. If a token ends in '=', the result is tok1 or tok3
// respectively. Otherwise, the result is tok0 if there was no other
// matching character, or tok2 if the matching character was ch2.

func (s *Scanner) switch2(tok0, tok1 token.Token) token.Token {
	if s.ch == '=' {
		s.next()
		return tok1
	}
	return tok0
}

func (s *Scanner) switch3(tok0, tok1 token.Token, ch2 rune, tok2 token.Token) token.Token {
	if s.ch == '=' {
		s.next()
		return tok1
	}
	if s.ch == ch2 {
		s.next()
		return tok2
	}
	return tok0
}

func (s *Scanner) switch4(tok0, tok1 token.Token, ch2 rune, tok2, tok3 token.Token) token.Token {
	if s.ch == '=' {
		s.next()
		return tok1
	}
	if s.ch == ch2 {
		s.next()
		if s.ch == '=' {
			s.next()
			return tok3
		}
		return tok2
	}
	return tok0
}

// Scan scans the next token and returns the token position, the token,
// and its literal string if applicable. The source end is indicated by
// [token.EOF].
//
// If the returned token is a literal ([token.IDENT], [token.INT], [token.FLOAT],
// [token.IMAG], [token.CHAR], [token.STRING]) or [token.COMMENT], the literal string
// has the corresponding value.
//
// If the returned token is a keyword, the literal string is the keyword.
//
// If the returned token is [token.SEMICOLON], the corresponding
// literal string is ";" if the semicolon was present in the source,
// and "\n" if the semicolon was inserted because of a newline or
// at EOF.
//
// If the returned token is [token.ILLEGAL], the literal string is the
// offending character.
//
// In all other cases, Scan returns an empty literal string.
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
func (s *Scanner) Scan() (pos token.Pos, tok token.Token, lit string) {
scanAgain:
	if s.nlPos.IsValid() {
		// Return artificial ';' token after /*...*/ comment
		// containing newline, at position of first newline.
		pos, tok, lit = s.nlPos, token.SEMICOLON, "\n"
		s.nlPos = token.NoPos
		return
	}

	s.skipWhitespace()

	// current token start
	pos = s.file.Pos(s.offset)

	// determine token value
	insertSemi := false
	switch ch := s.ch; {
	case isLetter(ch):
		lit = s.scanIdentifier()
		if len(lit) > 1 {
			// keywords are longer than one letter - avoid lookup otherwise
			tok = token.Lookup(lit)
			switch tok {
			case token.IDENT, token.BREAK, token.CONTINUE, token.FALLTHROUGH, token.RETURN:
				insertSemi = true
			}
		} else {
			insertSemi = true
			tok = token.IDENT
		}
	case isDecimal(ch) || ch == '.' && isDecimal(rune(s.peek())):
		insertSemi = true
		tok, lit = s.scanNumber()
	default:
		s.next() // always make progress
		switch ch {
		case eof:
			if s.insertSemi {
				s.insertSemi = false // EOF consumed
				return pos, token.SEMICOLON, "\n"
			}
			tok = token.EOF
		case '\n':
			// we only reach here if s.insertSemi was
			// set in the first place and exited early
			// from s.skipWhitespace()
			s.insertSemi = false // newline consumed
			return pos, token.SEMICOLON, "\n"
		case '"':
			insertSemi = true
			tok = token.STRING
			lit = s.scanString()
		case '\'':
			insertSemi = true
			tok = token.CHAR
			lit = s.scanRune()
		case '`':
			insertSemi = true
			tok = token.STRING
			lit = s.scanRawString()
		case ':':
			tok = s.switch2(token.COLON, token.DEFINE)
		case '.':
			// fractions starting with a '.' are handled by outer switch
			tok = token.PERIOD
			if s.ch == '.' && s.peek() == '.' {
				s.next()
				s.next() // consume last '.'
				tok = token.ELLIPSIS
			}
		case ',':
			tok = token.COMMA
		case ';':
			tok = token.SEMICOLON
			lit = ";"
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
			tok = s.switch3(token.ADD, token.ADD_ASSIGN, '+', token.INC)
			if tok == token.INC {
				insertSemi = true
			}
		case '-':
			tok = s.switch3(token.SUB, token.SUB_ASSIGN, '-', token.DEC)
			if tok == token.DEC {
				insertSemi = true
			}
		case '*':
			tok = s.switch2(token.MUL, token.MUL_ASSIGN)
		case '/':
			if s.ch == '/' || s.ch == '*' {
				// comment
				comment, nlOffset := s.scanComment()
				if s.insertSemi && nlOffset != 0 {
					// For /*...*/ containing \n, return
					// COMMENT then artificial SEMICOLON.
					s.nlPos = s.file.Pos(nlOffset)
					s.insertSemi = false
				} else {
					insertSemi = s.insertSemi // preserve insertSemi info
				}
				if s.mode&ScanComments == 0 {
					// skip comment
					goto scanAgain
				}
				tok = token.COMMENT
				lit = comment
			} else {
				// division
				tok = s.switch2(token.QUO, token.QUO_ASSIGN)
			}
		case '%':
			tok = s.switch2(token.REM, token.REM_ASSIGN)
		case '^':
			tok = s.switch2(token.XOR, token.XOR_ASSIGN)
		case '<':
			if s.ch == '-' {
				s.next()
				tok = token.ARROW
			} else {
				tok = s.switch4(token.LSS, token.LEQ, '<', token.SHL, token.SHL_ASSIGN)
			}
		case '>':
			tok = s.switch4(token.GTR, token.GEQ, '>', token.SHR, token.SHR_ASSIGN)
		case '=':
			tok = s.switch2(token.ASSIGN, token.EQL)
		case '!':
			tok = s.switch2(token.NOT, token.NEQ)
		case '&':
			if s.ch == '^' {
				s.next()
				tok = s.switch2(token.AND_NOT, token.AND_NOT_ASSIGN)
			} else {
				tok = s.switch3(token.AND, token.AND_ASSIGN, '&', token.LAND)
			}
		case '|':
			tok = s.switch3(token.OR, token.OR_ASSIGN, '|', token.LOR)
		case '~':
			tok = token.TILDE
		default:
			// next reports unexpected BOMs - don't repeat
			if ch != bom {
				// Report an informative error for U+201[CD] quotation
				// marks, which are easily introduced via copy and paste.
				if ch == '“' || ch == '”' {
					s.errorf(s.file.Offset(pos), "curly quotation mark %q (use neutral %q)", ch, '"')
				} else {
					s.errorf(s.file.Offset(pos), "illegal character %#U", ch)
				}
			}
			insertSemi = s.insertSemi // preserve insertSemi info
			tok = token.ILLEGAL
			lit = string(ch)
		}
	}
	if s.mode&dontInsertSemis == 0 {
		s.insertSemi = insertSemi
	}

	return
}
```