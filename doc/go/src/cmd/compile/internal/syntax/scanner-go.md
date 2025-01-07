Response:
Let's break down the thought process for analyzing the Go scanner code.

**1. Initial Understanding of the Goal:**

The request asks for a functional breakdown of a Go source code file (`scanner.go`) and wants to understand what Go language feature it implements. It also asks for examples, error analysis, and command-line interaction (though this particular file doesn't have command-line arguments).

**2. Deconstructing the Code - The Core Task:**

The first step is to read the code and identify its primary purpose. The initial comments are crucial:

```go
// This file implements scanner, a lexical tokenizer for
// Go source. After initialization, consecutive calls of
// next advance the scanner one token at a time.
```

This clearly states the file's function: lexical analysis (scanning/tokenizing). This is a fundamental part of any compiler or interpreter.

**3. Identifying Key Structures and Functions:**

Next, look for the main data structures and functions:

* **`scanner` struct:** This is the central data structure holding the scanner's state. Pay attention to its fields:
    * `source`:  Likely handles reading the input source code.
    * `mode`:  Controls comment handling.
    * `nlsemi`:  Manages automatic semicolon insertion.
    * `line`, `col`: Current position.
    * `tok`, `lit`, `bad`, `kind`, `op`, `prec`: Information about the current token.
* **`init` method:**  Initializes the `scanner`. This is usually the entry point for using the scanner.
* **`next` method:** The heart of the scanner. It reads the next token. This function will contain the core logic for identifying different kinds of tokens.
* **Error handling functions (`errorf`, `errorAtf`):**  These report errors during scanning.
* **Helper functions:**  Functions like `setLit`, `ident`, `number`, `stdString`, `rawString`, `rune`, `comment`, `lineComment`, `fullComment`, `escape`, etc., handle specific token types or sub-tasks.

**4. Understanding the `next` Function's Logic (The Core Algorithm):**

The `next` function is where the tokenization happens. Analyze its structure:

* **Skipping whitespace:** The initial loop handles skipping spaces, tabs, and newlines (with consideration for `nlsemi`).
* **Identifying token starts:**  The code checks the first character (`s.ch`) to determine the token type.
* **`switch` statement:** This is the central dispatch mechanism. It handles different starting characters:
    * Letters/Underscore:  Likely identifiers or keywords (`ident` function).
    * Digits: Numbers (`number` function).
    * Quotes (`"`, `` ` ``, `'`): Strings and runes (`stdString`, `rawString`, `rune` functions).
    * Punctuation marks (`(`, `)`, `{`, `}`, `[`, `]`, `,`, `;`, `:`, `.`, etc.): Individual tokens or the start of multi-character tokens.
    * Operators (`+`, `-`, `*`, `/`, `%`, `&`, `|`, `^`, `<`, `>`, `=`, `!`): Single or double-character operators.
* **Comment handling:** The `/` case deals with both single-line (`//`) and multi-line (`/* ... */`) comments.
* **Error handling (default case):** Handles invalid characters.
* **`goto redo`:**  Used in comment handling to restart the scanning process after a comment.

**5. Connecting to Go Language Features:**

Based on the tokens the scanner identifies, you can infer the Go language features it supports:

* **Keywords:** The `keywordMap` and `ident` function clearly deal with Go keywords (e.g., `func`, `if`, `for`, `return`).
* **Identifiers:** The `ident` function handles variable names, function names, etc.
* **Literals:** The `number`, `stdString`, `rawString`, and `rune` functions handle different literal types (integers, floats, strings, runes).
* **Operators:** The `switch` statement covers various Go operators (arithmetic, logical, bitwise, comparison, assignment).
* **Punctuation:**  Parentheses, braces, brackets, commas, semicolons, colons, and dots are essential for Go syntax.
* **Comments:** The handling of `//` and `/* ... */` is a fundamental part of Go.
* **Automatic semicolon insertion:** The `nlsemi` logic is crucial for Go's syntax rules.

**6. Providing Go Code Examples:**

Now, create simple Go code snippets that demonstrate the scanner recognizing these features. The examples should cover different token types:

* Keywords: `func main() {}`
* Identifiers: `var myVariable int`
* Integer literal: `x := 123`
* Float literal: `y := 3.14`
* String literal: `message := "hello"`
* Rune literal: `r := 'a'`
* Operators: `a + b`, `x == y`, `!flag`
* Punctuation: `if (condition) { ... }`
* Comments: `// This is a comment`, `/* This is a multi-line comment */`

**7. Inferring Input and Output:**

For the examples, specify the input (the Go code snippet) and the expected output (a sequence of tokens and their associated information). This helps illustrate the scanner's behavior. It's important to mention that the *exact* output format isn't defined in this code snippet; you'd typically have a `Token` type with fields for the token kind, literal value, position, etc. The example output should reflect the information the scanner collects.

**8. Analyzing Potential Errors:**

Think about common mistakes Go programmers make that the scanner would catch:

* **Invalid characters:** Characters not allowed in Go source.
* **Unterminated strings/runes:** Missing closing quotes.
* **Invalid escape sequences:** Incorrect backslash combinations.
* **Identifiers starting with digits:**  A common beginner mistake.
* **Invalid numeric literals:**  Digits that don't belong to the specified base.
* **Missing closing comment delimiters:** For multi-line comments.

**9. Addressing Command-Line Arguments:**

In this specific case, the `scanner.go` file, as provided, doesn't handle command-line arguments directly. It's a low-level component used by the Go compiler. Therefore, state that it doesn't handle command-line arguments. If it *did*, you would describe the flags and their effects.

**10. Review and Refine:**

Finally, review your analysis for clarity, accuracy, and completeness. Make sure the examples are correct and the explanations are easy to understand.

By following these steps, you can effectively analyze and explain the functionality of the Go scanner code. The key is to break down the code into its components, understand the logic of the main function, and connect it back to the features of the Go language.
The provided Go code snippet is a part of the lexical scanner for the Go programming language. Its primary function is to **read Go source code and break it down into a stream of tokens**. This process is the first step in compiling or interpreting Go code.

Here's a breakdown of its functionality:

**1. Lexical Analysis (Tokenization):**

   - The core purpose of the `scanner` is to perform lexical analysis. It reads the input source character by character and groups them into meaningful units called tokens.
   - Tokens represent keywords (`func`, `if`, `for`), identifiers (`variableName`, `functionName`), literals (`123`, `"hello"`, `'a'`), operators (`+`, `-`, `*`, `=`), punctuation (`(`, `)`, `{`, `}`), and comments.

**2. Tracking Source Location:**

   - It maintains the current line and column number (`line`, `col`) to provide accurate error reporting.
   - The `blank` field indicates if the current line is blank up to the current column.

**3. Handling Different Token Types:**

   - The `next()` method is the workhorse of the scanner. It determines the type of the next token based on the current character.
   - It has specific logic to handle:
     - **Identifiers and Keywords:** It recognizes sequences of letters, digits, and underscores. It also checks if an identifier is a reserved keyword.
     - **Numeric Literals:** It parses integers (decimal, hexadecimal, octal, binary), floating-point numbers, and imaginary numbers.
     - **String Literals:** It handles both interpreted (`"..."`) and raw (` `...``) string literals, including escape sequences.
     - **Rune Literals:** It parses character literals enclosed in single quotes (`'...'`).
     - **Operators:** It identifies various operators like arithmetic, logical, bitwise, and assignment operators.
     - **Punctuation:** It recognizes delimiters like parentheses, braces, brackets, commas, semicolons, and colons.
     - **Comments:** It identifies single-line (`//`) and multi-line (`/* ... */`) comments.

**4. Error Reporting:**

   - The scanner uses an error handler (`errh`) provided during initialization to report lexical errors.
   - Functions like `errorf` and `errorAtf` are used to generate and report error messages with specific locations.

**5. Handling Comments and Directives:**

   - The `mode` flag controls how comments are handled.
     - `comments`: Reports all comments to the error handler.
     - `directives`: Reports only comments containing specific directives (e.g., `//line`, `/*line`, `//go:`).
     - If no flag is set, comments are ignored.

**6. Automatic Semicolon Insertion:**

   - The `nlsemi` flag controls automatic semicolon insertion. In Go, semicolons are often optional, and the scanner inserts them automatically at the end of lines under certain conditions (e.g., before a closing brace, after a literal or identifier).

**7. Internal State:**

   - The `scanner` struct stores the current token's information:
     - `tok`: The type of the token (e.g., `_Name`, `_Literal`, `_Operator`).
     - `lit`: The literal value of the token (for identifiers and literals).
     - `bad`:  Indicates if an error occurred while parsing the literal.
     - `kind`: The specific kind of literal (e.g., `IntLit`, `StringLit`).
     - `op`: The specific operator.
     - `prec`: Operator precedence.

**Inferred Go Language Feature Implementation:**

This code directly implements the **lexical analysis phase** of the Go compiler. It's the foundational step in understanding the structure of Go source code.

**Go Code Example Illustrating Scanner Functionality:**

```go
package main

import (
	"fmt"
	"go/scanner"
	"go/token"
)

func main() {
	src := `package main

import "fmt"

func main() {
	x := 10
	y := "hello"
	fmt.Println(x, y) // Output: 10 hello
}
`

	fset := token.NewFileSet()
	file := fset.AddFile("example.go", fset.Base(), len(src))

	var s scanner.Scanner
	s.Init(file, []byte(src), nil, scanner.ScanComments) // ScanComments includes comments
	// s.Init(file, []byte(src), nil, 0) // No comments

	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		fmt.Printf("%s\t%s\t%q\n", fset.Position(pos), tok, lit)
	}
}
```

**Explanation of the Example:**

1. We use the `go/scanner` package from the standard library, which provides a similar scanning functionality.
2. We provide a sample Go source code string (`src`).
3. We initialize a `token.FileSet` and add a virtual file to it.
4. We create a `scanner.Scanner` and initialize it with the file set, source code, an error handler (nil in this case, meaning errors will be printed to stderr), and scan mode (`scanner.ScanComments` to include comments as tokens).
5. We repeatedly call `s.Scan()` to get the next token.
6. The loop continues until the end of the file (`token.EOF`) is reached.
7. For each token, we print its position, token type, and literal value.

**Hypothetical Input and Output (based on the `syntax` package's internal representation):**

**Input:**

```go
x := 10 + y
```

**Expected Output (using the `syntax` package's internal types):**

```
// Assuming the scanner starts at the beginning of this line
Line: 1, Col: 1, Token: _Name, Literal: "x"
Line: 1, Col: 3, Token: _Define, Literal: ":="
Line: 1, Col: 6, Token: _Literal, Literal: "10", Kind: IntLit
Line: 1, Col: 9, Token: _Operator, Operator: Add
Line: 1, Col: 11, Token: _Name, Literal: "y"
```

**Explanation of Hypothetical Output:**

- The scanner identifies the identifier `x`, the definition operator `:=`, the integer literal `10`, the addition operator `+`, and the identifier `y`.
- It also tracks the line and column number for each token.

**Command-Line Parameters:**

The provided `scanner.go` file itself is **not a standalone executable** and does **not directly handle command-line parameters**. It's a module used internally by the Go compiler (`go tool compile`).

The `go tool compile` command, which uses this scanner, has numerous command-line flags for controlling the compilation process (e.g., optimization level, output file name, architecture). However, these flags are handled at a higher level and are not directly processed within this specific `scanner.go` file.

**Common Mistakes by Users (of a higher-level Go tool that uses this scanner):**

While users don't directly interact with this `scanner.go` file, they can make mistakes in their Go code that the scanner will detect:

1. **Invalid Characters:** Using characters not allowed in Go syntax (e.g., `@`, `$`).
   ```go
   var my@variable int // Scanner error: invalid character
   ```
   **Error:** The scanner would report an "invalid character" error at the position of `@`.

2. **Unterminated String or Rune Literals:** Forgetting to close string or rune literals.
   ```go
   message := "hello  // Scanner error: string not terminated
   char := 'a  // Scanner error: rune literal not terminated
   ```
   **Error:** The scanner would report "string not terminated" or "rune literal not terminated" at the end of the line or file.

3. **Invalid Escape Sequences:** Using incorrect backslash combinations in string or rune literals.
   ```go
   message := "new\qline" // Scanner error: unknown escape
   ```
   **Error:** The scanner would report "unknown escape" at the position of `\q`.

4. **Identifiers Starting with a Digit:** Variable or function names cannot start with a digit.
   ```go
   var 123variable int // Scanner error: identifier cannot begin with digit
   ```
   **Error:** The scanner would report "identifier cannot begin with digit" at the position of `1`.

5. **Invalid Numeric Literals:**  Using digits inappropriate for the specified base (e.g., 'g' in a hexadecimal number).
   ```go
   hex := 0xFFG // Scanner error: invalid digit "g" in hexadecimal literal
   ```
   **Error:** The scanner would report "invalid digit" at the position of `G`.

6. **Missing Closing Comment Delimiter:** Forgetting the `*/` for multi-line comments.
   ```go
   /*
   This is a
   multi-line comment // Scanner error: comment not terminated
   ```
   **Error:** The scanner would report "comment not terminated" at the end of the file.

These are examples of how the scanner helps enforce the lexical rules of the Go language, catching basic syntax errors early in the compilation process.

Prompt: 
```
这是路径为go/src/cmd/compile/internal/syntax/scanner.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements scanner, a lexical tokenizer for
// Go source. After initialization, consecutive calls of
// next advance the scanner one token at a time.
//
// This file, source.go, tokens.go, and token_string.go are self-contained
// (`go tool compile scanner.go source.go tokens.go token_string.go` compiles)
// and thus could be made into their own package.

package syntax

import (
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// The mode flags below control which comments are reported
// by calling the error handler. If no flag is set, comments
// are ignored.
const (
	comments   uint = 1 << iota // call handler for all comments
	directives                  // call handler for directives only
)

type scanner struct {
	source
	mode   uint
	nlsemi bool // if set '\n' and EOF translate to ';'

	// current token, valid after calling next()
	line, col uint
	blank     bool // line is blank up to col
	tok       token
	lit       string   // valid if tok is _Name, _Literal, or _Semi ("semicolon", "newline", or "EOF"); may be malformed if bad is true
	bad       bool     // valid if tok is _Literal, true if a syntax error occurred, lit may be malformed
	kind      LitKind  // valid if tok is _Literal
	op        Operator // valid if tok is _Operator, _Star, _AssignOp, or _IncOp
	prec      int      // valid if tok is _Operator, _Star, _AssignOp, or _IncOp
}

func (s *scanner) init(src io.Reader, errh func(line, col uint, msg string), mode uint) {
	s.source.init(src, errh)
	s.mode = mode
	s.nlsemi = false
}

// errorf reports an error at the most recently read character position.
func (s *scanner) errorf(format string, args ...interface{}) {
	s.error(fmt.Sprintf(format, args...))
}

// errorAtf reports an error at a byte column offset relative to the current token start.
func (s *scanner) errorAtf(offset int, format string, args ...interface{}) {
	s.errh(s.line, s.col+uint(offset), fmt.Sprintf(format, args...))
}

// setLit sets the scanner state for a recognized _Literal token.
func (s *scanner) setLit(kind LitKind, ok bool) {
	s.nlsemi = true
	s.tok = _Literal
	s.lit = string(s.segment())
	s.bad = !ok
	s.kind = kind
}

// next advances the scanner by reading the next token.
//
// If a read, source encoding, or lexical error occurs, next calls
// the installed error handler with the respective error position
// and message. The error message is guaranteed to be non-empty and
// never starts with a '/'. The error handler must exist.
//
// If the scanner mode includes the comments flag and a comment
// (including comments containing directives) is encountered, the
// error handler is also called with each comment position and text
// (including opening /* or // and closing */, but without a newline
// at the end of line comments). Comment text always starts with a /
// which can be used to distinguish these handler calls from errors.
//
// If the scanner mode includes the directives (but not the comments)
// flag, only comments containing a //line, /*line, or //go: directive
// are reported, in the same way as regular comments.
func (s *scanner) next() {
	nlsemi := s.nlsemi
	s.nlsemi = false

redo:
	// skip white space
	s.stop()
	startLine, startCol := s.pos()
	for s.ch == ' ' || s.ch == '\t' || s.ch == '\n' && !nlsemi || s.ch == '\r' {
		s.nextch()
	}

	// token start
	s.line, s.col = s.pos()
	s.blank = s.line > startLine || startCol == colbase
	s.start()
	if isLetter(s.ch) || s.ch >= utf8.RuneSelf && s.atIdentChar(true) {
		s.nextch()
		s.ident()
		return
	}

	switch s.ch {
	case -1:
		if nlsemi {
			s.lit = "EOF"
			s.tok = _Semi
			break
		}
		s.tok = _EOF

	case '\n':
		s.nextch()
		s.lit = "newline"
		s.tok = _Semi

	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		s.number(false)

	case '"':
		s.stdString()

	case '`':
		s.rawString()

	case '\'':
		s.rune()

	case '(':
		s.nextch()
		s.tok = _Lparen

	case '[':
		s.nextch()
		s.tok = _Lbrack

	case '{':
		s.nextch()
		s.tok = _Lbrace

	case ',':
		s.nextch()
		s.tok = _Comma

	case ';':
		s.nextch()
		s.lit = "semicolon"
		s.tok = _Semi

	case ')':
		s.nextch()
		s.nlsemi = true
		s.tok = _Rparen

	case ']':
		s.nextch()
		s.nlsemi = true
		s.tok = _Rbrack

	case '}':
		s.nextch()
		s.nlsemi = true
		s.tok = _Rbrace

	case ':':
		s.nextch()
		if s.ch == '=' {
			s.nextch()
			s.tok = _Define
			break
		}
		s.tok = _Colon

	case '.':
		s.nextch()
		if isDecimal(s.ch) {
			s.number(true)
			break
		}
		if s.ch == '.' {
			s.nextch()
			if s.ch == '.' {
				s.nextch()
				s.tok = _DotDotDot
				break
			}
			s.rewind() // now s.ch holds 1st '.'
			s.nextch() // consume 1st '.' again
		}
		s.tok = _Dot

	case '+':
		s.nextch()
		s.op, s.prec = Add, precAdd
		if s.ch != '+' {
			goto assignop
		}
		s.nextch()
		s.nlsemi = true
		s.tok = _IncOp

	case '-':
		s.nextch()
		s.op, s.prec = Sub, precAdd
		if s.ch != '-' {
			goto assignop
		}
		s.nextch()
		s.nlsemi = true
		s.tok = _IncOp

	case '*':
		s.nextch()
		s.op, s.prec = Mul, precMul
		// don't goto assignop - want _Star token
		if s.ch == '=' {
			s.nextch()
			s.tok = _AssignOp
			break
		}
		s.tok = _Star

	case '/':
		s.nextch()
		if s.ch == '/' {
			s.nextch()
			s.lineComment()
			goto redo
		}
		if s.ch == '*' {
			s.nextch()
			s.fullComment()
			if line, _ := s.pos(); line > s.line && nlsemi {
				// A multi-line comment acts like a newline;
				// it translates to a ';' if nlsemi is set.
				s.lit = "newline"
				s.tok = _Semi
				break
			}
			goto redo
		}
		s.op, s.prec = Div, precMul
		goto assignop

	case '%':
		s.nextch()
		s.op, s.prec = Rem, precMul
		goto assignop

	case '&':
		s.nextch()
		if s.ch == '&' {
			s.nextch()
			s.op, s.prec = AndAnd, precAndAnd
			s.tok = _Operator
			break
		}
		s.op, s.prec = And, precMul
		if s.ch == '^' {
			s.nextch()
			s.op = AndNot
		}
		goto assignop

	case '|':
		s.nextch()
		if s.ch == '|' {
			s.nextch()
			s.op, s.prec = OrOr, precOrOr
			s.tok = _Operator
			break
		}
		s.op, s.prec = Or, precAdd
		goto assignop

	case '^':
		s.nextch()
		s.op, s.prec = Xor, precAdd
		goto assignop

	case '<':
		s.nextch()
		if s.ch == '=' {
			s.nextch()
			s.op, s.prec = Leq, precCmp
			s.tok = _Operator
			break
		}
		if s.ch == '<' {
			s.nextch()
			s.op, s.prec = Shl, precMul
			goto assignop
		}
		if s.ch == '-' {
			s.nextch()
			s.tok = _Arrow
			break
		}
		s.op, s.prec = Lss, precCmp
		s.tok = _Operator

	case '>':
		s.nextch()
		if s.ch == '=' {
			s.nextch()
			s.op, s.prec = Geq, precCmp
			s.tok = _Operator
			break
		}
		if s.ch == '>' {
			s.nextch()
			s.op, s.prec = Shr, precMul
			goto assignop
		}
		s.op, s.prec = Gtr, precCmp
		s.tok = _Operator

	case '=':
		s.nextch()
		if s.ch == '=' {
			s.nextch()
			s.op, s.prec = Eql, precCmp
			s.tok = _Operator
			break
		}
		s.tok = _Assign

	case '!':
		s.nextch()
		if s.ch == '=' {
			s.nextch()
			s.op, s.prec = Neq, precCmp
			s.tok = _Operator
			break
		}
		s.op, s.prec = Not, 0
		s.tok = _Operator

	case '~':
		s.nextch()
		s.op, s.prec = Tilde, 0
		s.tok = _Operator

	default:
		s.errorf("invalid character %#U", s.ch)
		s.nextch()
		goto redo
	}

	return

assignop:
	if s.ch == '=' {
		s.nextch()
		s.tok = _AssignOp
		return
	}
	s.tok = _Operator
}

func (s *scanner) ident() {
	// accelerate common case (7bit ASCII)
	for isLetter(s.ch) || isDecimal(s.ch) {
		s.nextch()
	}

	// general case
	if s.ch >= utf8.RuneSelf {
		for s.atIdentChar(false) {
			s.nextch()
		}
	}

	// possibly a keyword
	lit := s.segment()
	if len(lit) >= 2 {
		if tok := keywordMap[hash(lit)]; tok != 0 && tokStrFast(tok) == string(lit) {
			s.nlsemi = contains(1<<_Break|1<<_Continue|1<<_Fallthrough|1<<_Return, tok)
			s.tok = tok
			return
		}
	}

	s.nlsemi = true
	s.lit = string(lit)
	s.tok = _Name
}

// tokStrFast is a faster version of token.String, which assumes that tok
// is one of the valid tokens - and can thus skip bounds checks.
func tokStrFast(tok token) string {
	return _token_name[_token_index[tok-1]:_token_index[tok]]
}

func (s *scanner) atIdentChar(first bool) bool {
	switch {
	case unicode.IsLetter(s.ch) || s.ch == '_':
		// ok
	case unicode.IsDigit(s.ch):
		if first {
			s.errorf("identifier cannot begin with digit %#U", s.ch)
		}
	case s.ch >= utf8.RuneSelf:
		s.errorf("invalid character %#U in identifier", s.ch)
	default:
		return false
	}
	return true
}

// hash is a perfect hash function for keywords.
// It assumes that s has at least length 2.
func hash(s []byte) uint {
	return (uint(s[0])<<4 ^ uint(s[1]) + uint(len(s))) & uint(len(keywordMap)-1)
}

var keywordMap [1 << 6]token // size must be power of two

func init() {
	// populate keywordMap
	for tok := _Break; tok <= _Var; tok++ {
		h := hash([]byte(tok.String()))
		if keywordMap[h] != 0 {
			panic("imperfect hash")
		}
		keywordMap[h] = tok
	}
}

func lower(ch rune) rune     { return ('a' - 'A') | ch } // returns lower-case ch iff ch is ASCII letter
func isLetter(ch rune) bool  { return 'a' <= lower(ch) && lower(ch) <= 'z' || ch == '_' }
func isDecimal(ch rune) bool { return '0' <= ch && ch <= '9' }
func isHex(ch rune) bool     { return '0' <= ch && ch <= '9' || 'a' <= lower(ch) && lower(ch) <= 'f' }

// digits accepts the sequence { digit | '_' }.
// If base <= 10, digits accepts any decimal digit but records
// the index (relative to the literal start) of a digit >= base
// in *invalid, if *invalid < 0.
// digits returns a bitset describing whether the sequence contained
// digits (bit 0 is set), or separators '_' (bit 1 is set).
func (s *scanner) digits(base int, invalid *int) (digsep int) {
	if base <= 10 {
		max := rune('0' + base)
		for isDecimal(s.ch) || s.ch == '_' {
			ds := 1
			if s.ch == '_' {
				ds = 2
			} else if s.ch >= max && *invalid < 0 {
				_, col := s.pos()
				*invalid = int(col - s.col) // record invalid rune index
			}
			digsep |= ds
			s.nextch()
		}
	} else {
		for isHex(s.ch) || s.ch == '_' {
			ds := 1
			if s.ch == '_' {
				ds = 2
			}
			digsep |= ds
			s.nextch()
		}
	}
	return
}

func (s *scanner) number(seenPoint bool) {
	ok := true
	kind := IntLit
	base := 10        // number base
	prefix := rune(0) // one of 0 (decimal), '0' (0-octal), 'x', 'o', or 'b'
	digsep := 0       // bit 0: digit present, bit 1: '_' present
	invalid := -1     // index of invalid digit in literal, or < 0

	// integer part
	if !seenPoint {
		if s.ch == '0' {
			s.nextch()
			switch lower(s.ch) {
			case 'x':
				s.nextch()
				base, prefix = 16, 'x'
			case 'o':
				s.nextch()
				base, prefix = 8, 'o'
			case 'b':
				s.nextch()
				base, prefix = 2, 'b'
			default:
				base, prefix = 8, '0'
				digsep = 1 // leading 0
			}
		}
		digsep |= s.digits(base, &invalid)
		if s.ch == '.' {
			if prefix == 'o' || prefix == 'b' {
				s.errorf("invalid radix point in %s literal", baseName(base))
				ok = false
			}
			s.nextch()
			seenPoint = true
		}
	}

	// fractional part
	if seenPoint {
		kind = FloatLit
		digsep |= s.digits(base, &invalid)
	}

	if digsep&1 == 0 && ok {
		s.errorf("%s literal has no digits", baseName(base))
		ok = false
	}

	// exponent
	if e := lower(s.ch); e == 'e' || e == 'p' {
		if ok {
			switch {
			case e == 'e' && prefix != 0 && prefix != '0':
				s.errorf("%q exponent requires decimal mantissa", s.ch)
				ok = false
			case e == 'p' && prefix != 'x':
				s.errorf("%q exponent requires hexadecimal mantissa", s.ch)
				ok = false
			}
		}
		s.nextch()
		kind = FloatLit
		if s.ch == '+' || s.ch == '-' {
			s.nextch()
		}
		digsep = s.digits(10, nil) | digsep&2 // don't lose sep bit
		if digsep&1 == 0 && ok {
			s.errorf("exponent has no digits")
			ok = false
		}
	} else if prefix == 'x' && kind == FloatLit && ok {
		s.errorf("hexadecimal mantissa requires a 'p' exponent")
		ok = false
	}

	// suffix 'i'
	if s.ch == 'i' {
		kind = ImagLit
		s.nextch()
	}

	s.setLit(kind, ok) // do this now so we can use s.lit below

	if kind == IntLit && invalid >= 0 && ok {
		s.errorAtf(invalid, "invalid digit %q in %s literal", s.lit[invalid], baseName(base))
		ok = false
	}

	if digsep&2 != 0 && ok {
		if i := invalidSep(s.lit); i >= 0 {
			s.errorAtf(i, "'_' must separate successive digits")
			ok = false
		}
	}

	s.bad = !ok // correct s.bad
}

func baseName(base int) string {
	switch base {
	case 2:
		return "binary"
	case 8:
		return "octal"
	case 10:
		return "decimal"
	case 16:
		return "hexadecimal"
	}
	panic("invalid base")
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

func (s *scanner) rune() {
	ok := true
	s.nextch()

	n := 0
	for ; ; n++ {
		if s.ch == '\'' {
			if ok {
				if n == 0 {
					s.errorf("empty rune literal or unescaped '")
					ok = false
				} else if n != 1 {
					s.errorAtf(0, "more than one character in rune literal")
					ok = false
				}
			}
			s.nextch()
			break
		}
		if s.ch == '\\' {
			s.nextch()
			if !s.escape('\'') {
				ok = false
			}
			continue
		}
		if s.ch == '\n' {
			if ok {
				s.errorf("newline in rune literal")
				ok = false
			}
			break
		}
		if s.ch < 0 {
			if ok {
				s.errorAtf(0, "rune literal not terminated")
				ok = false
			}
			break
		}
		s.nextch()
	}

	s.setLit(RuneLit, ok)
}

func (s *scanner) stdString() {
	ok := true
	s.nextch()

	for {
		if s.ch == '"' {
			s.nextch()
			break
		}
		if s.ch == '\\' {
			s.nextch()
			if !s.escape('"') {
				ok = false
			}
			continue
		}
		if s.ch == '\n' {
			s.errorf("newline in string")
			ok = false
			break
		}
		if s.ch < 0 {
			s.errorAtf(0, "string not terminated")
			ok = false
			break
		}
		s.nextch()
	}

	s.setLit(StringLit, ok)
}

func (s *scanner) rawString() {
	ok := true
	s.nextch()

	for {
		if s.ch == '`' {
			s.nextch()
			break
		}
		if s.ch < 0 {
			s.errorAtf(0, "string not terminated")
			ok = false
			break
		}
		s.nextch()
	}
	// We leave CRs in the string since they are part of the
	// literal (even though they are not part of the literal
	// value).

	s.setLit(StringLit, ok)
}

func (s *scanner) comment(text string) {
	s.errorAtf(0, "%s", text)
}

func (s *scanner) skipLine() {
	// don't consume '\n' - needed for nlsemi logic
	for s.ch >= 0 && s.ch != '\n' {
		s.nextch()
	}
}

func (s *scanner) lineComment() {
	// opening has already been consumed

	if s.mode&comments != 0 {
		s.skipLine()
		s.comment(string(s.segment()))
		return
	}

	// are we saving directives? or is this definitely not a directive?
	if s.mode&directives == 0 || (s.ch != 'g' && s.ch != 'l') {
		s.stop()
		s.skipLine()
		return
	}

	// recognize go: or line directives
	prefix := "go:"
	if s.ch == 'l' {
		prefix = "line "
	}
	for _, m := range prefix {
		if s.ch != m {
			s.stop()
			s.skipLine()
			return
		}
		s.nextch()
	}

	// directive text
	s.skipLine()
	s.comment(string(s.segment()))
}

func (s *scanner) skipComment() bool {
	for s.ch >= 0 {
		for s.ch == '*' {
			s.nextch()
			if s.ch == '/' {
				s.nextch()
				return true
			}
		}
		s.nextch()
	}
	s.errorAtf(0, "comment not terminated")
	return false
}

func (s *scanner) fullComment() {
	/* opening has already been consumed */

	if s.mode&comments != 0 {
		if s.skipComment() {
			s.comment(string(s.segment()))
		}
		return
	}

	if s.mode&directives == 0 || s.ch != 'l' {
		s.stop()
		s.skipComment()
		return
	}

	// recognize line directive
	const prefix = "line "
	for _, m := range prefix {
		if s.ch != m {
			s.stop()
			s.skipComment()
			return
		}
		s.nextch()
	}

	// directive text
	if s.skipComment() {
		s.comment(string(s.segment()))
	}
}

func (s *scanner) escape(quote rune) bool {
	var n int
	var base, max uint32

	switch s.ch {
	case quote, 'a', 'b', 'f', 'n', 'r', 't', 'v', '\\':
		s.nextch()
		return true
	case '0', '1', '2', '3', '4', '5', '6', '7':
		n, base, max = 3, 8, 255
	case 'x':
		s.nextch()
		n, base, max = 2, 16, 255
	case 'u':
		s.nextch()
		n, base, max = 4, 16, unicode.MaxRune
	case 'U':
		s.nextch()
		n, base, max = 8, 16, unicode.MaxRune
	default:
		if s.ch < 0 {
			return true // complain in caller about EOF
		}
		s.errorf("unknown escape")
		return false
	}

	var x uint32
	for i := n; i > 0; i-- {
		if s.ch < 0 {
			return true // complain in caller about EOF
		}
		d := base
		if isDecimal(s.ch) {
			d = uint32(s.ch) - '0'
		} else if 'a' <= lower(s.ch) && lower(s.ch) <= 'f' {
			d = uint32(lower(s.ch)) - 'a' + 10
		}
		if d >= base {
			s.errorf("invalid character %q in %s escape", s.ch, baseName(int(base)))
			return false
		}
		// d < base
		x = x*base + d
		s.nextch()
	}

	if x > max && base == 8 {
		s.errorf("octal escape value %d > 255", x)
		return false
	}

	if x > max || 0xD800 <= x && x < 0xE000 /* surrogate range */ {
		s.errorf("escape is invalid Unicode code point %#U", x)
		return false
	}

	return true
}

"""



```