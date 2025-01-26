Response:
Let's break down the thought process for analyzing this Go `scanner.go` code.

**1. Initial Understanding of the Request:**

The request asks for the functionality of the provided Go code snippet, focusing on what it does, what Go feature it implements, examples, command-line argument handling (if any), and common user errors.

**2. High-Level Overview (Skimming and Package Comments):**

The first step is to get a general idea. The package comment `// Package scanner provides a scanner and tokenizer for UTF-8-encoded text.` immediately tells us the core purpose: scanning and tokenizing text. The comment also mentions `io.Reader`, `Scan` function, skipping whitespace and comments by default, and the possibility of customization. This gives us a good starting point.

**3. Core Data Structures and Types:**

Next, I'd look at the main data structures:

* **`Position`:** Represents a location in the source code (filename, offset, line, column). This is fundamental for error reporting and tracking.
* **Constants (`ScanIdents`, `ScanInts`, etc.):** These bit flags suggest configurable behavior for recognizing different types of tokens. The `GoTokens` constant shows a pre-defined combination.
* **Token Constants (`EOF`, `Ident`, `Int`, etc.):** These represent the different types of tokens the scanner can identify.
* **`Scanner` struct:** This is the central type. Its fields hold the state of the scanner (input source, buffer, position, token information, error handling, and mode).

**4. Key Functions and Methods:**

Now, examine the key functions and methods to understand the process:

* **`Init(io.Reader)`:**  Initializes the scanner, taking an `io.Reader` as input. This confirms the input source.
* **`next()`:** Reads the next Unicode character from the input. The logic handles UTF-8 decoding and buffering, which is crucial for internationalized text.
* **`Next()`:**  Advances the scanner by one character, discarding the token information. Useful for character-by-character processing.
* **`Peek()`:** Looks at the next character without advancing. Useful for lookahead.
* **`Scan()`:** The core function!  It reads the next *token*. The logic inside is complex, handling whitespace skipping, token identification based on `Mode`, and storing the token text. The `goto redo` indicates a loop for skipping comments.
* **`Pos()`:**  Returns the current position in the source.
* **`TokenText()`:** Returns the text of the last scanned token.
* **`error()` and `errorf()`:** Handle error reporting.

**5. Understanding the Tokenization Logic (The `Scan()` Method):**

The `Scan()` method is the heart of the scanner. It's important to trace its flow:

1. **Skip Whitespace:**  The initial loop skips characters defined in `Whitespace`.
2. **Start Token Collection:**  The `tokPos` and `tokBuf` are used to store the text of the token being scanned.
3. **Determine Token Value:** A large `switch` statement handles different starting characters:
    * **Identifiers:** `isIdentRune` checks for valid identifier characters.
    * **Numbers:** `scanNumber` handles integers and floating-point numbers, including different bases and exponents.
    * **Strings/Chars:** `scanString`, `scanRawString`, and `scanChar` handle quoted literals.
    * **Comments:** `scanComment` handles line and block comments, with the option to skip them.
4. **End Token Collection:** `tokEnd` marks the end of the token text.
5. **Return Token:** The identified token type (e.g., `Ident`, `Int`, `String`) is returned.

**6. Inferring the Go Feature:**

Based on the functionality, it's clear this code implements a **lexical scanner (lexer) or tokenizer**. This is a fundamental part of compilers and interpreters. It takes raw text as input and breaks it down into meaningful units (tokens) that can be processed further by a parser.

**7. Creating Examples:**

Now, based on the understanding of `Scan()` and the different token types, I can create Go code examples to demonstrate how to use the `Scanner`:

* **Basic Tokenization:** Showing how to initialize a scanner and iterate through tokens using `Scan()`.
* **Configuring the Scanner:** Demonstrating the use of `Mode` to control which tokens are recognized.
* **Error Handling:** Showing how to set the `Error` function to handle scanner errors.

**8. Command-Line Arguments:**

Scanning the code, I see no direct handling of command-line arguments. The input comes from an `io.Reader`. This needs to be explicitly stated in the answer.

**9. Common User Errors:**

Think about how someone might misuse the scanner:

* **Forgetting to initialize:**  Using a `Scanner` without calling `Init`.
* **Incorrect `Mode` settings:**  Not setting the `Mode` correctly for the desired token recognition.
* **Assuming character-by-character processing with `Scan()`:** Understanding the difference between `Scan()` and `Next()`.
* **Not handling errors:** Ignoring potential errors reported by the scanner.

**10. Structuring the Answer:**

Finally, organize the information clearly and logically using the requested format (listing functionalities, inferring the Go feature, examples, command-line arguments, and common errors). Use clear and concise language. The thought process involves moving from a high-level understanding to detailed analysis of the code, and then synthesizing that information into a comprehensive answer with practical examples.
这段代码是 Go 语言 `text/scanner` 包中 `scanner.go` 文件的一部分，它实现了一个 **词法扫描器 (lexer) 或分词器 (tokenizer)**。它的主要功能是将 UTF-8 编码的文本输入流分解成一系列的 **token (词法单元)**。

以下是它的具体功能：

1. **读取输入流:**  `Scanner` 结构体接收一个 `io.Reader` 作为输入源，允许它从各种来源读取文本，例如文件、字符串等。

2. **分词:**  `Scan()` 方法是核心功能，它从输入流中读取字符，并根据预定义的规则和配置，识别出一个完整的 token。

3. **可配置的 token 识别:**  通过 `Mode` 字段，可以控制 `Scanner` 识别哪些类型的 token。预定义了多种模式常量，例如：
   - `ScanIdents`: 识别标识符 (例如变量名、函数名)。
   - `ScanInts`: 识别整数字面量。
   - `ScanFloats`: 识别浮点数字面量。
   - `ScanStrings`: 识别字符串字面量。
   - `ScanComments`: 识别注释。
   - `SkipComments`:  如果与 `ScanComments` 一起设置，则跳过注释，不作为 token 返回。
   - `GoTokens`:  一个便捷的常量，包含了 Go 语言中常见的字面量和标识符。

4. **处理空白字符:**  `Whitespace` 字段定义了哪些字符被认为是空白字符。默认情况下，它使用 `GoWhitespace`，包含了制表符、换行符、回车符和空格。扫描器在 `Scan()` 时会跳过这些空白字符。

5. **处理注释:**  可以配置扫描器识别和处理 Go 语言的单行注释 (`//`) 和多行注释 (`/* ... */`)。可以选择将注释作为 token 返回，或者直接跳过。

6. **处理标识符:**  `IsIdentRune` 字段允许自定义哪些字符可以作为标识符的一部分。如果没有设置，则使用 Go 语言的标识符规则（字母、数字和下划线，首字符不能是数字）。

7. **跟踪位置信息:**  `Position` 结构体用于记录 token 在源代码中的位置（文件名、字节偏移量、行号、列号）。这对于错误报告非常重要。

8. **错误处理:**  `Error` 字段允许用户提供一个自定义的错误处理函数。如果未设置，错误将输出到 `os.Stderr`。`ErrorCount` 记录遇到的错误数量。

9. **处理 UTF-8 编码:**  扫描器能够正确处理 UTF-8 编码的文本。

10. **处理转义字符:**  在字符串和字符字面量中，扫描器能够识别和处理反斜杠 (`\`) 开头的转义字符。

**它是什么 Go 语言功能的实现？**

这段代码实现了 Go 语言的 **词法分析 (Lexical Analysis)** 阶段，这是编译器或解释器将源代码转换为可执行代码的第一个步骤。词法分析器将源代码的字符流分解成有意义的 token 序列，为后续的语法分析 (Parsing) 提供输入。

**Go 代码示例：**

假设我们有以下 Go 源代码字符串：

```go
package main

import "fmt"

func main() {
	x := 123
	fmt.Println("Hello, world!") // This is a comment
}
```

我们可以使用 `scanner` 包来对其进行分词：

```go
package main

import (
	"fmt"
	"strings"
	"text/scanner"
)

func main() {
	src := `package main

import "fmt"

func main() {
	x := 123
	fmt.Println("Hello, world!") // This is a comment
}
`

	var s scanner.Scanner
	s.Init(strings.NewReader(src)) // 初始化扫描器，使用字符串作为输入

	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		fmt.Printf("Token: %s, Text: %q, Position: %s\n", s.TokenString(tok), s.TokenText(), s.Position)
	}

	if s.ErrorCount > 0 {
		fmt.Println("Found errors during scanning.")
	}
}
```

**假设的输出：**

```
Token: Ident, Text: "package", Position: <input>:1:1
Token: Ident, Text: "main", Position: <input>:1:9
Token: Ident, Text: "import", Position: <input>:3:1
Token: String, Text: "\"fmt\"", Position: <input>:3:8
Token: Ident, Text: "func", Position: <input>:5:1
Token: Ident, Text: "main", Position: <input>:5:6
Token: '{', Text: "{", Position: <input>:5:11
Token: Ident, Text: "x", Position: <input>:6:2
Token: ':', Text: ":", Position: <input>:6:4
Token: '=', Text: "=", Position: <input>:6:6
Token: Int, Text: "123", Position: <input>:6:8
Token: Ident, Text: "fmt", Position: <input>:7:2
Token: '.', Text: ".", Position: <input>:7:5
Token: Ident, Text: "Println", Position: <input>:7:6
Token: '(', Text: "(", Position: <input>:7:13
Token: String, Text: "\"Hello, world!\"", Position: <input>:7:14
Token: ')', Text: ")", Position: <input>:7:30
Token: Comment, Text: "// This is a comment", Position: <input>:7:32
Token: '}', Text: "}", Position: <input>:8:1
```

**注意:**  默认情况下，`GoTokens` 包含了 `SkipComments`，所以注释会被跳过，不会作为 token 返回。 如果你想看到注释 token，你需要修改 `s.Mode`。

**命令行参数的具体处理：**

这段代码本身没有直接处理命令行参数。`scanner.Scanner` 专注于从 `io.Reader` 读取输入。 如果你需要从命令行参数指定的文件中读取输入，你需要在调用 `scanner.Scanner` 之前，使用 `os` 包来打开文件，并将返回的 `os.File` 传递给 `scanner.Scanner.Init()`。

例如：

```go
package main

import (
	"fmt"
	"os"
	"text/scanner"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: scanner <filename>")
		return
	}

	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	var s scanner.Scanner
	s.Filename = filename // 设置文件名，用于位置信息
	s.Init(file)

	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		fmt.Printf("Token: %s, Text: %q, Position: %s\n", s.TokenString(tok), s.TokenText(), s.Position)
	}

	if s.ErrorCount > 0 {
		fmt.Println("Found errors during scanning.")
	}
}
```

在这个例子中，命令行参数 `os.Args[1]` 被用作文件名，然后打开文件并将其作为 `scanner.Scanner` 的输入。

**使用者易犯错的点：**

1. **忘记初始化 `Scanner`:**  直接使用未初始化的 `Scanner` 会导致运行时错误。必须调用 `Init()` 方法。

   ```go
   var s scanner.Scanner
   // 错误：直接使用 s.Scan() 会 panic
   ```

2. **`Mode` 设置不正确:** 如果没有正确设置 `Mode`，扫描器可能无法识别预期的 token 类型。例如，如果 `Mode` 中没有设置 `ScanStrings`，字符串字面量会被识别为一系列的字符 token。

   ```go
   var s scanner.Scanner
   s.Init(strings.NewReader(`"hello"`))
   // 默认的 GoTokens 包含 ScanStrings

   tok := s.Scan()
   fmt.Println(s.TokenString(tok)) // Output: String

   var s2 scanner.Scanner
   s2.Init(strings.NewReader(`"hello"`))
   s2.Mode = scanner.ScanIdents // 只识别标识符
   tok2 := s2.Scan()
   fmt.Println(s2.TokenString(tok2)) // Output: "\"" (因为双引号被当做普通字符)
   ```

3. **混淆 `Next()` 和 `Scan()`:**
   - `Next()` 读取并返回下一个 Unicode 字符，不进行 token 识别。
   - `Scan()` 读取并返回下一个 token。

   初学者可能会错误地使用 `Next()` 来期望获取 token。

4. **没有处理错误:**  扫描过程中可能会发生错误（例如无效的 UTF-8 编码）。如果没有设置 `Error` 函数或检查 `ErrorCount`，可能会忽略这些错误。

5. **假设 `Scan()` 返回字符:**  `Scan()` 返回的是 token 类型（例如 `scanner.Ident`, `scanner.Int`）或者 Unicode 字符本身，而不是始终返回单个字符。需要使用 `s.TokenString(tok)` 或 `s.TokenText()` 来获取 token 的文本表示。

理解这些功能和潜在的错误点可以帮助你更好地使用 `text/scanner` 包来处理文本输入。

Prompt: 
```
这是路径为go/src/text/scanner/scanner.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scanner provides a scanner and tokenizer for UTF-8-encoded text.
// It takes an io.Reader providing the source, which then can be tokenized
// through repeated calls to the Scan function. For compatibility with
// existing tools, the NUL character is not allowed. If the first character
// in the source is a UTF-8 encoded byte order mark (BOM), it is discarded.
//
// By default, a [Scanner] skips white space and Go comments and recognizes all
// literals as defined by the Go language specification. It may be
// customized to recognize only a subset of those literals and to recognize
// different identifier and white space characters.
package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"unicode"
	"unicode/utf8"
)

// Position is a value that represents a source position.
// A position is valid if Line > 0.
type Position struct {
	Filename string // filename, if any
	Offset   int    // byte offset, starting at 0
	Line     int    // line number, starting at 1
	Column   int    // column number, starting at 1 (character count per line)
}

// IsValid reports whether the position is valid.
func (pos *Position) IsValid() bool { return pos.Line > 0 }

func (pos Position) String() string {
	s := pos.Filename
	if s == "" {
		s = "<input>"
	}
	if pos.IsValid() {
		s += fmt.Sprintf(":%d:%d", pos.Line, pos.Column)
	}
	return s
}

// Predefined mode bits to control recognition of tokens. For instance,
// to configure a [Scanner] such that it only recognizes (Go) identifiers,
// integers, and skips comments, set the Scanner's Mode field to:
//
//	ScanIdents | ScanInts | SkipComments
//
// With the exceptions of comments, which are skipped if SkipComments is
// set, unrecognized tokens are not ignored. Instead, the scanner simply
// returns the respective individual characters (or possibly sub-tokens).
// For instance, if the mode is ScanIdents (not ScanStrings), the string
// "foo" is scanned as the token sequence '"' [Ident] '"'.
//
// Use GoTokens to configure the Scanner such that it accepts all Go
// literal tokens including Go identifiers. Comments will be skipped.
const (
	ScanIdents     = 1 << -Ident
	ScanInts       = 1 << -Int
	ScanFloats     = 1 << -Float // includes Ints and hexadecimal floats
	ScanChars      = 1 << -Char
	ScanStrings    = 1 << -String
	ScanRawStrings = 1 << -RawString
	ScanComments   = 1 << -Comment
	SkipComments   = 1 << -skipComment // if set with ScanComments, comments become white space
	GoTokens       = ScanIdents | ScanFloats | ScanChars | ScanStrings | ScanRawStrings | ScanComments | SkipComments
)

// The result of Scan is one of these tokens or a Unicode character.
const (
	EOF = -(iota + 1)
	Ident
	Int
	Float
	Char
	String
	RawString
	Comment

	// internal use only
	skipComment
)

var tokenString = map[rune]string{
	EOF:       "EOF",
	Ident:     "Ident",
	Int:       "Int",
	Float:     "Float",
	Char:      "Char",
	String:    "String",
	RawString: "RawString",
	Comment:   "Comment",
}

// TokenString returns a printable string for a token or Unicode character.
func TokenString(tok rune) string {
	if s, found := tokenString[tok]; found {
		return s
	}
	return fmt.Sprintf("%q", string(tok))
}

// GoWhitespace is the default value for the [Scanner]'s Whitespace field.
// Its value selects Go's white space characters.
const GoWhitespace = 1<<'\t' | 1<<'\n' | 1<<'\r' | 1<<' '

const bufLen = 1024 // at least utf8.UTFMax

// A Scanner implements reading of Unicode characters and tokens from an [io.Reader].
type Scanner struct {
	// Input
	src io.Reader

	// Source buffer
	srcBuf [bufLen + 1]byte // +1 for sentinel for common case of s.next()
	srcPos int              // reading position (srcBuf index)
	srcEnd int              // source end (srcBuf index)

	// Source position
	srcBufOffset int // byte offset of srcBuf[0] in source
	line         int // line count
	column       int // character count
	lastLineLen  int // length of last line in characters (for correct column reporting)
	lastCharLen  int // length of last character in bytes

	// Token text buffer
	// Typically, token text is stored completely in srcBuf, but in general
	// the token text's head may be buffered in tokBuf while the token text's
	// tail is stored in srcBuf.
	tokBuf bytes.Buffer // token text head that is not in srcBuf anymore
	tokPos int          // token text tail position (srcBuf index); valid if >= 0
	tokEnd int          // token text tail end (srcBuf index)

	// One character look-ahead
	ch rune // character before current srcPos

	// Error is called for each error encountered. If no Error
	// function is set, the error is reported to os.Stderr.
	Error func(s *Scanner, msg string)

	// ErrorCount is incremented by one for each error encountered.
	ErrorCount int

	// The Mode field controls which tokens are recognized. For instance,
	// to recognize Ints, set the ScanInts bit in Mode. The field may be
	// changed at any time.
	Mode uint

	// The Whitespace field controls which characters are recognized
	// as white space. To recognize a character ch <= ' ' as white space,
	// set the ch'th bit in Whitespace (the Scanner's behavior is undefined
	// for values ch > ' '). The field may be changed at any time.
	Whitespace uint64

	// IsIdentRune is a predicate controlling the characters accepted
	// as the ith rune in an identifier. The set of valid characters
	// must not intersect with the set of white space characters.
	// If no IsIdentRune function is set, regular Go identifiers are
	// accepted instead. The field may be changed at any time.
	IsIdentRune func(ch rune, i int) bool

	// Start position of most recently scanned token; set by Scan.
	// Calling Init or Next invalidates the position (Line == 0).
	// The Filename field is always left untouched by the Scanner.
	// If an error is reported (via Error) and Position is invalid,
	// the scanner is not inside a token. Call Pos to obtain an error
	// position in that case, or to obtain the position immediately
	// after the most recently scanned token.
	Position
}

// Init initializes a [Scanner] with a new source and returns s.
// [Scanner.Error] is set to nil, [Scanner.ErrorCount] is set to 0, [Scanner.Mode] is set to [GoTokens],
// and [Scanner.Whitespace] is set to [GoWhitespace].
func (s *Scanner) Init(src io.Reader) *Scanner {
	s.src = src

	// initialize source buffer
	// (the first call to next() will fill it by calling src.Read)
	s.srcBuf[0] = utf8.RuneSelf // sentinel
	s.srcPos = 0
	s.srcEnd = 0

	// initialize source position
	s.srcBufOffset = 0
	s.line = 1
	s.column = 0
	s.lastLineLen = 0
	s.lastCharLen = 0

	// initialize token text buffer
	// (required for first call to next()).
	s.tokPos = -1

	// initialize one character look-ahead
	s.ch = -2 // no char read yet, not EOF

	// initialize public fields
	s.Error = nil
	s.ErrorCount = 0
	s.Mode = GoTokens
	s.Whitespace = GoWhitespace
	s.Line = 0 // invalidate token position

	return s
}

// next reads and returns the next Unicode character. It is designed such
// that only a minimal amount of work needs to be done in the common ASCII
// case (one test to check for both ASCII and end-of-buffer, and one test
// to check for newlines).
func (s *Scanner) next() rune {
	ch, width := rune(s.srcBuf[s.srcPos]), 1

	if ch >= utf8.RuneSelf {
		// uncommon case: not ASCII or not enough bytes
		for s.srcPos+utf8.UTFMax > s.srcEnd && !utf8.FullRune(s.srcBuf[s.srcPos:s.srcEnd]) {
			// not enough bytes: read some more, but first
			// save away token text if any
			if s.tokPos >= 0 {
				s.tokBuf.Write(s.srcBuf[s.tokPos:s.srcPos])
				s.tokPos = 0
				// s.tokEnd is set by Scan()
			}
			// move unread bytes to beginning of buffer
			copy(s.srcBuf[0:], s.srcBuf[s.srcPos:s.srcEnd])
			s.srcBufOffset += s.srcPos
			// read more bytes
			// (an io.Reader must return io.EOF when it reaches
			// the end of what it is reading - simply returning
			// n == 0 will make this loop retry forever; but the
			// error is in the reader implementation in that case)
			i := s.srcEnd - s.srcPos
			n, err := s.src.Read(s.srcBuf[i:bufLen])
			s.srcPos = 0
			s.srcEnd = i + n
			s.srcBuf[s.srcEnd] = utf8.RuneSelf // sentinel
			if err != nil {
				if err != io.EOF {
					s.error(err.Error())
				}
				if s.srcEnd == 0 {
					if s.lastCharLen > 0 {
						// previous character was not EOF
						s.column++
					}
					s.lastCharLen = 0
					return EOF
				}
				// If err == EOF, we won't be getting more
				// bytes; break to avoid infinite loop. If
				// err is something else, we don't know if
				// we can get more bytes; thus also break.
				break
			}
		}
		// at least one byte
		ch = rune(s.srcBuf[s.srcPos])
		if ch >= utf8.RuneSelf {
			// uncommon case: not ASCII
			ch, width = utf8.DecodeRune(s.srcBuf[s.srcPos:s.srcEnd])
			if ch == utf8.RuneError && width == 1 {
				// advance for correct error position
				s.srcPos += width
				s.lastCharLen = width
				s.column++
				s.error("invalid UTF-8 encoding")
				return ch
			}
		}
	}

	// advance
	s.srcPos += width
	s.lastCharLen = width
	s.column++

	// special situations
	switch ch {
	case 0:
		// for compatibility with other tools
		s.error("invalid character NUL")
	case '\n':
		s.line++
		s.lastLineLen = s.column
		s.column = 0
	}

	return ch
}

// Next reads and returns the next Unicode character.
// It returns [EOF] at the end of the source. It reports
// a read error by calling s.Error, if not nil; otherwise
// it prints an error message to [os.Stderr]. Next does not
// update the [Scanner.Position] field; use [Scanner.Pos]() to
// get the current position.
func (s *Scanner) Next() rune {
	s.tokPos = -1 // don't collect token text
	s.Line = 0    // invalidate token position
	ch := s.Peek()
	if ch != EOF {
		s.ch = s.next()
	}
	return ch
}

// Peek returns the next Unicode character in the source without advancing
// the scanner. It returns [EOF] if the scanner's position is at the last
// character of the source.
func (s *Scanner) Peek() rune {
	if s.ch == -2 {
		// this code is only run for the very first character
		s.ch = s.next()
		if s.ch == '\uFEFF' {
			s.ch = s.next() // ignore BOM
		}
	}
	return s.ch
}

func (s *Scanner) error(msg string) {
	s.tokEnd = s.srcPos - s.lastCharLen // make sure token text is terminated
	s.ErrorCount++
	if s.Error != nil {
		s.Error(s, msg)
		return
	}
	pos := s.Position
	if !pos.IsValid() {
		pos = s.Pos()
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", pos, msg)
}

func (s *Scanner) errorf(format string, args ...any) {
	s.error(fmt.Sprintf(format, args...))
}

func (s *Scanner) isIdentRune(ch rune, i int) bool {
	if s.IsIdentRune != nil {
		return ch != EOF && s.IsIdentRune(ch, i)
	}
	return ch == '_' || unicode.IsLetter(ch) || unicode.IsDigit(ch) && i > 0
}

func (s *Scanner) scanIdentifier() rune {
	// we know the zero'th rune is OK; start scanning at the next one
	ch := s.next()
	for i := 1; s.isIdentRune(ch, i); i++ {
		ch = s.next()
	}
	return ch
}

func lower(ch rune) rune     { return ('a' - 'A') | ch } // returns lower-case ch iff ch is ASCII letter
func isDecimal(ch rune) bool { return '0' <= ch && ch <= '9' }
func isHex(ch rune) bool     { return '0' <= ch && ch <= '9' || 'a' <= lower(ch) && lower(ch) <= 'f' }

// digits accepts the sequence { digit | '_' } starting with ch0.
// If base <= 10, digits accepts any decimal digit but records
// the first invalid digit >= base in *invalid if *invalid == 0.
// digits returns the first rune that is not part of the sequence
// anymore, and a bitset describing whether the sequence contained
// digits (bit 0 is set), or separators '_' (bit 1 is set).
func (s *Scanner) digits(ch0 rune, base int, invalid *rune) (ch rune, digsep int) {
	ch = ch0
	if base <= 10 {
		max := rune('0' + base)
		for isDecimal(ch) || ch == '_' {
			ds := 1
			if ch == '_' {
				ds = 2
			} else if ch >= max && *invalid == 0 {
				*invalid = ch
			}
			digsep |= ds
			ch = s.next()
		}
	} else {
		for isHex(ch) || ch == '_' {
			ds := 1
			if ch == '_' {
				ds = 2
			}
			digsep |= ds
			ch = s.next()
		}
	}
	return
}

func (s *Scanner) scanNumber(ch rune, seenDot bool) (rune, rune) {
	base := 10         // number base
	prefix := rune(0)  // one of 0 (decimal), '0' (0-octal), 'x', 'o', or 'b'
	digsep := 0        // bit 0: digit present, bit 1: '_' present
	invalid := rune(0) // invalid digit in literal, or 0

	// integer part
	var tok rune
	var ds int
	if !seenDot {
		tok = Int
		if ch == '0' {
			ch = s.next()
			switch lower(ch) {
			case 'x':
				ch = s.next()
				base, prefix = 16, 'x'
			case 'o':
				ch = s.next()
				base, prefix = 8, 'o'
			case 'b':
				ch = s.next()
				base, prefix = 2, 'b'
			default:
				base, prefix = 8, '0'
				digsep = 1 // leading 0
			}
		}
		ch, ds = s.digits(ch, base, &invalid)
		digsep |= ds
		if ch == '.' && s.Mode&ScanFloats != 0 {
			ch = s.next()
			seenDot = true
		}
	}

	// fractional part
	if seenDot {
		tok = Float
		if prefix == 'o' || prefix == 'b' {
			s.error("invalid radix point in " + litname(prefix))
		}
		ch, ds = s.digits(ch, base, &invalid)
		digsep |= ds
	}

	if digsep&1 == 0 {
		s.error(litname(prefix) + " has no digits")
	}

	// exponent
	if e := lower(ch); (e == 'e' || e == 'p') && s.Mode&ScanFloats != 0 {
		switch {
		case e == 'e' && prefix != 0 && prefix != '0':
			s.errorf("%q exponent requires decimal mantissa", ch)
		case e == 'p' && prefix != 'x':
			s.errorf("%q exponent requires hexadecimal mantissa", ch)
		}
		ch = s.next()
		tok = Float
		if ch == '+' || ch == '-' {
			ch = s.next()
		}
		ch, ds = s.digits(ch, 10, nil)
		digsep |= ds
		if ds&1 == 0 {
			s.error("exponent has no digits")
		}
	} else if prefix == 'x' && tok == Float {
		s.error("hexadecimal mantissa requires a 'p' exponent")
	}

	if tok == Int && invalid != 0 {
		s.errorf("invalid digit %q in %s", invalid, litname(prefix))
	}

	if digsep&2 != 0 {
		s.tokEnd = s.srcPos - s.lastCharLen // make sure token text is terminated
		if i := invalidSep(s.TokenText()); i >= 0 {
			s.error("'_' must separate successive digits")
		}
	}

	return tok, ch
}

func litname(prefix rune) string {
	switch prefix {
	default:
		return "decimal literal"
	case 'x':
		return "hexadecimal literal"
	case 'o', '0':
		return "octal literal"
	case 'b':
		return "binary literal"
	}
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

func digitVal(ch rune) int {
	switch {
	case '0' <= ch && ch <= '9':
		return int(ch - '0')
	case 'a' <= lower(ch) && lower(ch) <= 'f':
		return int(lower(ch) - 'a' + 10)
	}
	return 16 // larger than any legal digit val
}

func (s *Scanner) scanDigits(ch rune, base, n int) rune {
	for n > 0 && digitVal(ch) < base {
		ch = s.next()
		n--
	}
	if n > 0 {
		s.error("invalid char escape")
	}
	return ch
}

func (s *Scanner) scanEscape(quote rune) rune {
	ch := s.next() // read character after '/'
	switch ch {
	case 'a', 'b', 'f', 'n', 'r', 't', 'v', '\\', quote:
		// nothing to do
		ch = s.next()
	case '0', '1', '2', '3', '4', '5', '6', '7':
		ch = s.scanDigits(ch, 8, 3)
	case 'x':
		ch = s.scanDigits(s.next(), 16, 2)
	case 'u':
		ch = s.scanDigits(s.next(), 16, 4)
	case 'U':
		ch = s.scanDigits(s.next(), 16, 8)
	default:
		s.error("invalid char escape")
	}
	return ch
}

func (s *Scanner) scanString(quote rune) (n int) {
	ch := s.next() // read character after quote
	for ch != quote {
		if ch == '\n' || ch < 0 {
			s.error("literal not terminated")
			return
		}
		if ch == '\\' {
			ch = s.scanEscape(quote)
		} else {
			ch = s.next()
		}
		n++
	}
	return
}

func (s *Scanner) scanRawString() {
	ch := s.next() // read character after '`'
	for ch != '`' {
		if ch < 0 {
			s.error("literal not terminated")
			return
		}
		ch = s.next()
	}
}

func (s *Scanner) scanChar() {
	if s.scanString('\'') != 1 {
		s.error("invalid char literal")
	}
}

func (s *Scanner) scanComment(ch rune) rune {
	// ch == '/' || ch == '*'
	if ch == '/' {
		// line comment
		ch = s.next() // read character after "//"
		for ch != '\n' && ch >= 0 {
			ch = s.next()
		}
		return ch
	}

	// general comment
	ch = s.next() // read character after "/*"
	for {
		if ch < 0 {
			s.error("comment not terminated")
			break
		}
		ch0 := ch
		ch = s.next()
		if ch0 == '*' && ch == '/' {
			ch = s.next()
			break
		}
	}
	return ch
}

// Scan reads the next token or Unicode character from source and returns it.
// It only recognizes tokens t for which the respective [Scanner.Mode] bit (1<<-t) is set.
// It returns [EOF] at the end of the source. It reports scanner errors (read and
// token errors) by calling s.Error, if not nil; otherwise it prints an error
// message to [os.Stderr].
func (s *Scanner) Scan() rune {
	ch := s.Peek()

	// reset token text position
	s.tokPos = -1
	s.Line = 0

redo:
	// skip white space
	for s.Whitespace&(1<<uint(ch)) != 0 {
		ch = s.next()
	}

	// start collecting token text
	s.tokBuf.Reset()
	s.tokPos = s.srcPos - s.lastCharLen

	// set token position
	// (this is a slightly optimized version of the code in Pos())
	s.Offset = s.srcBufOffset + s.tokPos
	if s.column > 0 {
		// common case: last character was not a '\n'
		s.Line = s.line
		s.Column = s.column
	} else {
		// last character was a '\n'
		// (we cannot be at the beginning of the source
		// since we have called next() at least once)
		s.Line = s.line - 1
		s.Column = s.lastLineLen
	}

	// determine token value
	tok := ch
	switch {
	case s.isIdentRune(ch, 0):
		if s.Mode&ScanIdents != 0 {
			tok = Ident
			ch = s.scanIdentifier()
		} else {
			ch = s.next()
		}
	case isDecimal(ch):
		if s.Mode&(ScanInts|ScanFloats) != 0 {
			tok, ch = s.scanNumber(ch, false)
		} else {
			ch = s.next()
		}
	default:
		switch ch {
		case EOF:
			break
		case '"':
			if s.Mode&ScanStrings != 0 {
				s.scanString('"')
				tok = String
			}
			ch = s.next()
		case '\'':
			if s.Mode&ScanChars != 0 {
				s.scanChar()
				tok = Char
			}
			ch = s.next()
		case '.':
			ch = s.next()
			if isDecimal(ch) && s.Mode&ScanFloats != 0 {
				tok, ch = s.scanNumber(ch, true)
			}
		case '/':
			ch = s.next()
			if (ch == '/' || ch == '*') && s.Mode&ScanComments != 0 {
				if s.Mode&SkipComments != 0 {
					s.tokPos = -1 // don't collect token text
					ch = s.scanComment(ch)
					goto redo
				}
				ch = s.scanComment(ch)
				tok = Comment
			}
		case '`':
			if s.Mode&ScanRawStrings != 0 {
				s.scanRawString()
				tok = RawString
			}
			ch = s.next()
		default:
			ch = s.next()
		}
	}

	// end of token text
	s.tokEnd = s.srcPos - s.lastCharLen

	s.ch = ch
	return tok
}

// Pos returns the position of the character immediately after
// the character or token returned by the last call to [Scanner.Next] or [Scanner.Scan].
// Use the [Scanner.Position] field for the start position of the most
// recently scanned token.
func (s *Scanner) Pos() (pos Position) {
	pos.Filename = s.Filename
	pos.Offset = s.srcBufOffset + s.srcPos - s.lastCharLen
	switch {
	case s.column > 0:
		// common case: last character was not a '\n'
		pos.Line = s.line
		pos.Column = s.column
	case s.lastLineLen > 0:
		// last character was a '\n'
		pos.Line = s.line - 1
		pos.Column = s.lastLineLen
	default:
		// at the beginning of the source
		pos.Line = 1
		pos.Column = 1
	}
	return
}

// TokenText returns the string corresponding to the most recently scanned token.
// Valid after calling [Scanner.Scan] and in calls of [Scanner.Error].
func (s *Scanner) TokenText() string {
	if s.tokPos < 0 {
		// no token text
		return ""
	}

	if s.tokEnd < s.tokPos {
		// if EOF was reached, s.tokEnd is set to -1 (s.srcPos == 0)
		s.tokEnd = s.tokPos
	}
	// s.tokEnd >= s.tokPos

	if s.tokBuf.Len() == 0 {
		// common case: the entire token text is still in srcBuf
		return string(s.srcBuf[s.tokPos:s.tokEnd])
	}

	// part of the token text was saved in tokBuf: save the rest in
	// tokBuf as well and return its content
	s.tokBuf.Write(s.srcBuf[s.tokPos:s.tokEnd])
	s.tokPos = s.tokEnd // ensure idempotency of TokenText() call
	return s.tokBuf.String()
}

"""



```