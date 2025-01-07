Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `go/printer` package in the Go standard library.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The package name `printer` and the file name `printer.go` strongly suggest that this code is responsible for formatting and printing Go Abstract Syntax Tree (AST) nodes.

2. **Analyze Key Data Structures:**  Examine the main `printer` struct and its fields. This reveals important information about the printer's state and configuration:
    * `Config`:  Holds configuration settings (indentation, mode).
    * `fset`: File set for position information.
    * `output`: The buffer where the formatted output is built.
    * `indent`: Current indentation level.
    * `mode`:  Printer modes for controlling specific formatting aspects.
    * `comments`:  List of comments in the source code.
    * `nodeSizes`: Cache for node sizes (related to formatting).

3. **Examine Key Methods:**  Focus on the most prominent methods and their purpose:
    * `print()`: The central function for printing various "items" (tokens, whitespace, etc.). This is the entry point for printing AST nodes.
    * `writeString()`:  Writes a string (usually a token or literal) to the output buffer.
    * `writeByte()`: Writes a byte (typically whitespace) to the output buffer.
    * `writeIndent()`: Writes indentation.
    * `writeComment()`:  Handles the formatting and printing of comments.
    * `intersperseComments()`:  Manages the placement of comments relative to tokens and whitespace.
    * `flush()`:  Writes out buffered whitespace and handles comments before the next token.

4. **Infer Go Language Feature Implementation:** Based on the function names and data structures, it's clear that this code implements the logic for formatting Go code from its AST representation. This is a core part of tools like `gofmt` and `goimports`.

5. **Provide a Go Code Example:** Create a simple Go program, parse it into an AST, and then use the `printer.Fprint` function (which likely uses the logic in this file) to print the formatted code. This demonstrates the practical use of the `printer` package.

6. **Explain Command-Line Arguments (If Applicable):** In this specific code snippet, there are no direct command-line argument processing. However, it's important to mention that the *configuration* of the printer (controlled by the `Config` struct) *could* be influenced by command-line arguments in a larger tool.

7. **Identify Potential Pitfalls:** Think about common mistakes users might make when interacting with code formatters or AST manipulation:
    * Assuming exact source code preservation:  Formatters often adjust whitespace and may not preserve the original formatting precisely.
    * Incorrectly modifying the AST:  Changes to the AST structure will directly impact the output.
    * Misunderstanding formatting options: The `Config` and `pmode` settings influence the output.

8. **Structure the Answer:** Organize the information logically, starting with a concise summary of the functionality, followed by detailed explanations, code examples, and potential pitfalls. Use clear and understandable language.

9. **Review and Refine:**  Read through the answer to ensure accuracy, completeness, and clarity. Check for any ambiguities or areas that might be confusing to the user. For example, ensure the code example is correct and runs without errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the token printing.
* **Correction:** Realized the importance of comment handling (`writeComment`, `intersperseComments`) and whitespace management (`writeByte`, `writeWhitespace`).
* **Initial thought:**  Only provide a basic explanation.
* **Refinement:**  Decided to include a code example to demonstrate usage and discuss potential pitfalls to provide more practical value.
* **Initial thought:** Briefly mention configuration.
* **Refinement:** Emphasized that while this snippet doesn't handle command-line arguments directly, its configuration is likely influenced by them in larger tools.
这段Go语言代码是 `go/printer` 包的一部分，主要负责将 Go 语言的抽象语法树 (AST) 节点 **格式化并输出为可读的 Go 源代码文本**。它实现了将程序内部的结构化表示转换回外部的文本形式。

**功能归纳:**

1. **代码美化 (Pretty Printing):**  它负责添加必要的空格、缩进、换行等，使得输出的 Go 代码符合 Go 语言的编码规范，易于阅读。
2. **注释处理:**  它能正确地将代码中的注释（包括行注释和块注释）放置在合适的位置，保持注释与代码的关联性。
3. **源代码位置恢复:**  当输出的格式与原始源代码的格式不同时，它可以插入 `//line` 指令，帮助编译器和调试器将输出代码的位置映射回原始源代码的位置。这对于代码生成工具或需要修改代码格式的场景非常重要。
4. **条件编译指令处理:**  能够识别并正确处理 `//go:build` 和 `// +build` 形式的条件编译指令。
5. **灵活的格式化选项:**  通过 `Config` 结构体，使用者可以配置一些格式化选项，例如缩进量、是否保留源代码位置信息等。

**它是什么Go语言功能的实现？**

这段代码是 `go/printer` 包的核心部分，`go/printer` 包主要用于实现 **将 Go 语言的抽象语法树 (AST) 转换为格式化的源代码文本**。  这在很多 Go 语言工具中都有应用，例如：

* **`gofmt`:**  Go 语言官方的代码格式化工具，它使用 `go/parser` 解析代码生成 AST，然后使用 `go/printer` 将 AST 格式化输出。
* **`goimports`:**  一个更强大的代码格式化工具，除了格式化代码外，还会自动添加或删除 import 语句。它的内部也使用了 `go/printer` 来生成最终的代码。
* **代码生成工具:**  许多代码生成工具在生成 Go 代码后，会使用 `go/printer` 来确保生成的代码格式良好。
* **AST 分析和修改工具:**  一些工具可能先解析代码得到 AST，进行一些修改或分析，然后使用 `go/printer` 将修改后的 AST 输出为代码。

**Go 代码举例说明:**

假设我们有以下简单的 Go 代码：

```go
package main

import "fmt"

func main() {
fmt.Println("Hello, World!")
}
```

我们可以使用 `go/parser` 解析这段代码生成 AST，然后使用 `go/printer` 将 AST 格式化输出。

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
)

func main() {
	// 源代码字符串
	src := `package main

import "fmt"

func main() {
fmt.Println("Hello, World!")
}`

	// 创建一个 FileSet 用于记录位置信息
	fset := token.NewFileSet()

	// 解析源代码，生成 AST
	file, err := parser.ParseFile(fset, "hello.go", src, 0)
	if err != nil {
		panic(err)
	}

	// 创建一个用于输出的缓冲区
	out := &strings.Builder{}

	// 配置 printer (可以使用默认配置)
	config := &printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}

	// 使用 printer 将 AST 格式化输出到缓冲区
	err = config.Fprint(out, fset, file)
	if err != nil {
		panic(err)
	}

	// 打印格式化后的代码
	println(out.String())
}
```

**假设输入与输出:**

**输入 (src 字符串):**

```go
package main

import "fmt"

func main() {
fmt.Println("Hello, World!")
}
```

**输出 (out.String()):**

```go
package main

import (
	"fmt"
)

func main() {
	fmt.Println("Hello, World!")
}
```

可以看到，`go/printer` 将 import 语句放到了括号中，并添加了适当的缩进。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。 `go/printer` 包是一个库，它的配置通常由调用它的上层工具来控制。例如，`gofmt` 工具本身没有太多的命令行参数，它的目标是强制统一的代码风格。而像一些代码生成工具，可能会通过命令行参数来控制生成的代码的某些格式细节，这些参数会最终反映到传递给 `printer.Fprint` 函数的 `Config` 结构体中。

**使用者易犯错的点:**

1. **假设完全保留原始格式:**  `go/printer` 的主要目标是生成符合 Go 语言规范的格式化代码，而不是完全保留原始代码的每一个空格和空行。如果对输出格式有严格的要求，可能需要进行额外的处理。例如，一些特定的注释格式可能会被调整。

   **例子:** 如果原始代码的 import 语句没有使用括号，`go/printer` 会自动将其放入括号中。

2. **错误地修改 AST 结构:**  如果在将 AST 传递给 `printer.Fprint` 之前，错误地修改了 AST 的结构，可能会导致输出的代码不正确甚至无法编译。使用者需要理解 AST 的结构和含义，才能安全地进行修改。

   **例子:** 如果错误地删除了一个 `ast.Node`，那么对应的代码片段将不会出现在输出中。

3. **不理解 `Config` 结构体的作用:**  `printer.Config` 允许用户配置一些格式化选项，例如缩进方式（使用空格还是制表符）、制表符的宽度等。如果不了解这些选项，可能会得到不符合预期的格式化结果。

   **例子:**  如果默认配置使用制表符缩进，而用户期望使用空格缩进，就需要配置 `Config` 结构体。

**总结其功能 (针对第 1 部分):**

这段 `go/src/go/printer/printer.go` 代码实现了 `go/printer` 包的核心功能，即 **将 Go 语言的抽象语法树 (AST) 节点格式化为可读的源代码文本**。 它负责处理代码的缩进、空格、换行、注释以及条件编译指令，并提供了一些配置选项来调整输出格式。这段代码是构建 Go 代码格式化和生成工具的基础。

Prompt: 
```
这是路径为go/src/go/printer/printer.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package printer implements printing of AST nodes.
package printer

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/token"
	"io"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"unicode"
)

const (
	maxNewlines = 2     // max. number of newlines between source text
	debug       = false // enable for debugging
	infinity    = 1 << 30
)

type whiteSpace byte

const (
	ignore   = whiteSpace(0)
	blank    = whiteSpace(' ')
	vtab     = whiteSpace('\v')
	newline  = whiteSpace('\n')
	formfeed = whiteSpace('\f')
	indent   = whiteSpace('>')
	unindent = whiteSpace('<')
)

// A pmode value represents the current printer mode.
type pmode int

const (
	noExtraBlank     pmode = 1 << iota // disables extra blank after /*-style comment
	noExtraLinebreak                   // disables extra line break after /*-style comment
)

type commentInfo struct {
	cindex         int               // index of the next comment
	comment        *ast.CommentGroup // = printer.comments[cindex-1]; or nil
	commentOffset  int               // = printer.posFor(printer.comments[cindex-1].List[0].Pos()).Offset; or infinity
	commentNewline bool              // true if the comment group contains newlines
}

type printer struct {
	// Configuration (does not change after initialization)
	Config
	fset *token.FileSet

	// Current state
	output       []byte       // raw printer result
	indent       int          // current indentation
	level        int          // level == 0: outside composite literal; level > 0: inside composite literal
	mode         pmode        // current printer mode
	endAlignment bool         // if set, terminate alignment immediately
	impliedSemi  bool         // if set, a linebreak implies a semicolon
	lastTok      token.Token  // last token printed (token.ILLEGAL if it's whitespace)
	prevOpen     token.Token  // previous non-brace "open" token (, [, or token.ILLEGAL
	wsbuf        []whiteSpace // delayed white space
	goBuild      []int        // start index of all //go:build comments in output
	plusBuild    []int        // start index of all // +build comments in output

	// Positions
	// The out position differs from the pos position when the result
	// formatting differs from the source formatting (in the amount of
	// white space). If there's a difference and SourcePos is set in
	// ConfigMode, //line directives are used in the output to restore
	// original source positions for a reader.
	pos          token.Position // current position in AST (source) space
	out          token.Position // current position in output space
	last         token.Position // value of pos after calling writeString
	linePtr      *int           // if set, record out.Line for the next token in *linePtr
	sourcePosErr error          // if non-nil, the first error emitting a //line directive

	// The list of all source comments, in order of appearance.
	comments        []*ast.CommentGroup // may be nil
	useNodeComments bool                // if not set, ignore lead and line comments of nodes

	// Information about p.comments[p.cindex]; set up by nextComment.
	commentInfo

	// Cache of already computed node sizes.
	nodeSizes map[ast.Node]int

	// Cache of most recently computed line position.
	cachedPos  token.Pos
	cachedLine int // line corresponding to cachedPos
}

func (p *printer) internalError(msg ...any) {
	if debug {
		fmt.Print(p.pos.String() + ": ")
		fmt.Println(msg...)
		panic("go/printer")
	}
}

// commentsHaveNewline reports whether a list of comments belonging to
// an *ast.CommentGroup contains newlines. Because the position information
// may only be partially correct, we also have to read the comment text.
func (p *printer) commentsHaveNewline(list []*ast.Comment) bool {
	// len(list) > 0
	line := p.lineFor(list[0].Pos())
	for i, c := range list {
		if i > 0 && p.lineFor(list[i].Pos()) != line {
			// not all comments on the same line
			return true
		}
		if t := c.Text; len(t) >= 2 && (t[1] == '/' || strings.Contains(t, "\n")) {
			return true
		}
	}
	_ = line
	return false
}

func (p *printer) nextComment() {
	for p.cindex < len(p.comments) {
		c := p.comments[p.cindex]
		p.cindex++
		if list := c.List; len(list) > 0 {
			p.comment = c
			p.commentOffset = p.posFor(list[0].Pos()).Offset
			p.commentNewline = p.commentsHaveNewline(list)
			return
		}
		// we should not reach here (correct ASTs don't have empty
		// ast.CommentGroup nodes), but be conservative and try again
	}
	// no more comments
	p.commentOffset = infinity
}

// commentBefore reports whether the current comment group occurs
// before the next position in the source code and printing it does
// not introduce implicit semicolons.
func (p *printer) commentBefore(next token.Position) bool {
	return p.commentOffset < next.Offset && (!p.impliedSemi || !p.commentNewline)
}

// commentSizeBefore returns the estimated size of the
// comments on the same line before the next position.
func (p *printer) commentSizeBefore(next token.Position) int {
	// save/restore current p.commentInfo (p.nextComment() modifies it)
	defer func(info commentInfo) {
		p.commentInfo = info
	}(p.commentInfo)

	size := 0
	for p.commentBefore(next) {
		for _, c := range p.comment.List {
			size += len(c.Text)
		}
		p.nextComment()
	}
	return size
}

// recordLine records the output line number for the next non-whitespace
// token in *linePtr. It is used to compute an accurate line number for a
// formatted construct, independent of pending (not yet emitted) whitespace
// or comments.
func (p *printer) recordLine(linePtr *int) {
	p.linePtr = linePtr
}

// linesFrom returns the number of output lines between the current
// output line and the line argument, ignoring any pending (not yet
// emitted) whitespace or comments. It is used to compute an accurate
// size (in number of lines) for a formatted construct.
func (p *printer) linesFrom(line int) int {
	return p.out.Line - line
}

func (p *printer) posFor(pos token.Pos) token.Position {
	// not used frequently enough to cache entire token.Position
	return p.fset.PositionFor(pos, false /* absolute position */)
}

func (p *printer) lineFor(pos token.Pos) int {
	if pos != p.cachedPos {
		p.cachedPos = pos
		p.cachedLine = p.fset.PositionFor(pos, false /* absolute position */).Line
	}
	return p.cachedLine
}

// writeLineDirective writes a //line directive if necessary.
func (p *printer) writeLineDirective(pos token.Position) {
	if pos.IsValid() && (p.out.Line != pos.Line || p.out.Filename != pos.Filename) {
		if strings.ContainsAny(pos.Filename, "\r\n") {
			if p.sourcePosErr == nil {
				p.sourcePosErr = fmt.Errorf("go/printer: source filename contains unexpected newline character: %q", pos.Filename)
			}
			return
		}

		p.output = append(p.output, tabwriter.Escape) // protect '\n' in //line from tabwriter interpretation
		p.output = append(p.output, fmt.Sprintf("//line %s:%d\n", pos.Filename, pos.Line)...)
		p.output = append(p.output, tabwriter.Escape)
		// p.out must match the //line directive
		p.out.Filename = pos.Filename
		p.out.Line = pos.Line
	}
}

// writeIndent writes indentation.
func (p *printer) writeIndent() {
	// use "hard" htabs - indentation columns
	// must not be discarded by the tabwriter
	n := p.Config.Indent + p.indent // include base indentation
	for i := 0; i < n; i++ {
		p.output = append(p.output, '\t')
	}

	// update positions
	p.pos.Offset += n
	p.pos.Column += n
	p.out.Column += n
}

// writeByte writes ch n times to p.output and updates p.pos.
// Only used to write formatting (white space) characters.
func (p *printer) writeByte(ch byte, n int) {
	if p.endAlignment {
		// Ignore any alignment control character;
		// and at the end of the line, break with
		// a formfeed to indicate termination of
		// existing columns.
		switch ch {
		case '\t', '\v':
			ch = ' '
		case '\n', '\f':
			ch = '\f'
			p.endAlignment = false
		}
	}

	if p.out.Column == 1 {
		// no need to write line directives before white space
		p.writeIndent()
	}

	for i := 0; i < n; i++ {
		p.output = append(p.output, ch)
	}

	// update positions
	p.pos.Offset += n
	if ch == '\n' || ch == '\f' {
		p.pos.Line += n
		p.out.Line += n
		p.pos.Column = 1
		p.out.Column = 1
		return
	}
	p.pos.Column += n
	p.out.Column += n
}

// writeString writes the string s to p.output and updates p.pos, p.out,
// and p.last. If isLit is set, s is escaped w/ tabwriter.Escape characters
// to protect s from being interpreted by the tabwriter.
//
// Note: writeString is only used to write Go tokens, literals, and
// comments, all of which must be written literally. Thus, it is correct
// to always set isLit = true. However, setting it explicitly only when
// needed (i.e., when we don't know that s contains no tabs or line breaks)
// avoids processing extra escape characters and reduces run time of the
// printer benchmark by up to 10%.
func (p *printer) writeString(pos token.Position, s string, isLit bool) {
	if p.out.Column == 1 {
		if p.Config.Mode&SourcePos != 0 {
			p.writeLineDirective(pos)
		}
		p.writeIndent()
	}

	if pos.IsValid() {
		// update p.pos (if pos is invalid, continue with existing p.pos)
		// Note: Must do this after handling line beginnings because
		// writeIndent updates p.pos if there's indentation, but p.pos
		// is the position of s.
		p.pos = pos
	}

	if isLit {
		// Protect s such that is passes through the tabwriter
		// unchanged. Note that valid Go programs cannot contain
		// tabwriter.Escape bytes since they do not appear in legal
		// UTF-8 sequences.
		p.output = append(p.output, tabwriter.Escape)
	}

	if debug {
		p.output = append(p.output, fmt.Sprintf("/*%s*/", pos)...) // do not update p.pos!
	}
	p.output = append(p.output, s...)

	// update positions
	nlines := 0
	var li int // index of last newline; valid if nlines > 0
	for i := 0; i < len(s); i++ {
		// Raw string literals may contain any character except back quote (`).
		if ch := s[i]; ch == '\n' || ch == '\f' {
			// account for line break
			nlines++
			li = i
			// A line break inside a literal will break whatever column
			// formatting is in place; ignore any further alignment through
			// the end of the line.
			p.endAlignment = true
		}
	}
	p.pos.Offset += len(s)
	if nlines > 0 {
		p.pos.Line += nlines
		p.out.Line += nlines
		c := len(s) - li
		p.pos.Column = c
		p.out.Column = c
	} else {
		p.pos.Column += len(s)
		p.out.Column += len(s)
	}

	if isLit {
		p.output = append(p.output, tabwriter.Escape)
	}

	p.last = p.pos
}

// writeCommentPrefix writes the whitespace before a comment.
// If there is any pending whitespace, it consumes as much of
// it as is likely to help position the comment nicely.
// pos is the comment position, next the position of the item
// after all pending comments, prev is the previous comment in
// a group of comments (or nil), and tok is the next token.
func (p *printer) writeCommentPrefix(pos, next token.Position, prev *ast.Comment, tok token.Token) {
	if len(p.output) == 0 {
		// the comment is the first item to be printed - don't write any whitespace
		return
	}

	if pos.IsValid() && pos.Filename != p.last.Filename {
		// comment in a different file - separate with newlines
		p.writeByte('\f', maxNewlines)
		return
	}

	if pos.Line == p.last.Line && (prev == nil || prev.Text[1] != '/') {
		// comment on the same line as last item:
		// separate with at least one separator
		hasSep := false
		if prev == nil {
			// first comment of a comment group
			j := 0
			for i, ch := range p.wsbuf {
				switch ch {
				case blank:
					// ignore any blanks before a comment
					p.wsbuf[i] = ignore
					continue
				case vtab:
					// respect existing tabs - important
					// for proper formatting of commented structs
					hasSep = true
					continue
				case indent:
					// apply pending indentation
					continue
				}
				j = i
				break
			}
			p.writeWhitespace(j)
		}
		// make sure there is at least one separator
		if !hasSep {
			sep := byte('\t')
			if pos.Line == next.Line {
				// next item is on the same line as the comment
				// (which must be a /*-style comment): separate
				// with a blank instead of a tab
				sep = ' '
			}
			p.writeByte(sep, 1)
		}

	} else {
		// comment on a different line:
		// separate with at least one line break
		droppedLinebreak := false
		j := 0
		for i, ch := range p.wsbuf {
			switch ch {
			case blank, vtab:
				// ignore any horizontal whitespace before line breaks
				p.wsbuf[i] = ignore
				continue
			case indent:
				// apply pending indentation
				continue
			case unindent:
				// if this is not the last unindent, apply it
				// as it is (likely) belonging to the last
				// construct (e.g., a multi-line expression list)
				// and is not part of closing a block
				if i+1 < len(p.wsbuf) && p.wsbuf[i+1] == unindent {
					continue
				}
				// if the next token is not a closing }, apply the unindent
				// if it appears that the comment is aligned with the
				// token; otherwise assume the unindent is part of a
				// closing block and stop (this scenario appears with
				// comments before a case label where the comments
				// apply to the next case instead of the current one)
				if tok != token.RBRACE && pos.Column == next.Column {
					continue
				}
			case newline, formfeed:
				p.wsbuf[i] = ignore
				droppedLinebreak = prev == nil // record only if first comment of a group
			}
			j = i
			break
		}
		p.writeWhitespace(j)

		// determine number of linebreaks before the comment
		n := 0
		if pos.IsValid() && p.last.IsValid() {
			n = pos.Line - p.last.Line
			if n < 0 { // should never happen
				n = 0
			}
		}

		// at the package scope level only (p.indent == 0),
		// add an extra newline if we dropped one before:
		// this preserves a blank line before documentation
		// comments at the package scope level (issue 2570)
		if p.indent == 0 && droppedLinebreak {
			n++
		}

		// make sure there is at least one line break
		// if the previous comment was a line comment
		if n == 0 && prev != nil && prev.Text[1] == '/' {
			n = 1
		}

		if n > 0 {
			// use formfeeds to break columns before a comment;
			// this is analogous to using formfeeds to separate
			// individual lines of /*-style comments
			p.writeByte('\f', nlimit(n))
		}
	}
}

// Returns true if s contains only white space
// (only tabs and blanks can appear in the printer's context).
func isBlank(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > ' ' {
			return false
		}
	}
	return true
}

// commonPrefix returns the common prefix of a and b.
func commonPrefix(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] && (a[i] <= ' ' || a[i] == '*') {
		i++
	}
	return a[0:i]
}

// trimRight returns s with trailing whitespace removed.
func trimRight(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

// stripCommonPrefix removes a common prefix from /*-style comment lines (unless no
// comment line is indented, all but the first line have some form of space prefix).
// The prefix is computed using heuristics such that is likely that the comment
// contents are nicely laid out after re-printing each line using the printer's
// current indentation.
func stripCommonPrefix(lines []string) {
	if len(lines) <= 1 {
		return // at most one line - nothing to do
	}
	// len(lines) > 1

	// The heuristic in this function tries to handle a few
	// common patterns of /*-style comments: Comments where
	// the opening /* and closing */ are aligned and the
	// rest of the comment text is aligned and indented with
	// blanks or tabs, cases with a vertical "line of stars"
	// on the left, and cases where the closing */ is on the
	// same line as the last comment text.

	// Compute maximum common white prefix of all but the first,
	// last, and blank lines, and replace blank lines with empty
	// lines (the first line starts with /* and has no prefix).
	// In cases where only the first and last lines are not blank,
	// such as two-line comments, or comments where all inner lines
	// are blank, consider the last line for the prefix computation
	// since otherwise the prefix would be empty.
	//
	// Note that the first and last line are never empty (they
	// contain the opening /* and closing */ respectively) and
	// thus they can be ignored by the blank line check.
	prefix := ""
	prefixSet := false
	if len(lines) > 2 {
		for i, line := range lines[1 : len(lines)-1] {
			if isBlank(line) {
				lines[1+i] = "" // range starts with lines[1]
			} else {
				if !prefixSet {
					prefix = line
					prefixSet = true
				}
				prefix = commonPrefix(prefix, line)
			}

		}
	}
	// If we don't have a prefix yet, consider the last line.
	if !prefixSet {
		line := lines[len(lines)-1]
		prefix = commonPrefix(line, line)
	}

	/*
	 * Check for vertical "line of stars" and correct prefix accordingly.
	 */
	lineOfStars := false
	if p, _, ok := strings.Cut(prefix, "*"); ok {
		// remove trailing blank from prefix so stars remain aligned
		prefix = strings.TrimSuffix(p, " ")
		lineOfStars = true
	} else {
		// No line of stars present.
		// Determine the white space on the first line after the /*
		// and before the beginning of the comment text, assume two
		// blanks instead of the /* unless the first character after
		// the /* is a tab. If the first comment line is empty but
		// for the opening /*, assume up to 3 blanks or a tab. This
		// whitespace may be found as suffix in the common prefix.
		first := lines[0]
		if isBlank(first[2:]) {
			// no comment text on the first line:
			// reduce prefix by up to 3 blanks or a tab
			// if present - this keeps comment text indented
			// relative to the /* and */'s if it was indented
			// in the first place
			i := len(prefix)
			for n := 0; n < 3 && i > 0 && prefix[i-1] == ' '; n++ {
				i--
			}
			if i == len(prefix) && i > 0 && prefix[i-1] == '\t' {
				i--
			}
			prefix = prefix[0:i]
		} else {
			// comment text on the first line
			suffix := make([]byte, len(first))
			n := 2 // start after opening /*
			for n < len(first) && first[n] <= ' ' {
				suffix[n] = first[n]
				n++
			}
			if n > 2 && suffix[2] == '\t' {
				// assume the '\t' compensates for the /*
				suffix = suffix[2:n]
			} else {
				// otherwise assume two blanks
				suffix[0], suffix[1] = ' ', ' '
				suffix = suffix[0:n]
			}
			// Shorten the computed common prefix by the length of
			// suffix, if it is found as suffix of the prefix.
			prefix = strings.TrimSuffix(prefix, string(suffix))
		}
	}

	// Handle last line: If it only contains a closing */, align it
	// with the opening /*, otherwise align the text with the other
	// lines.
	last := lines[len(lines)-1]
	closing := "*/"
	before, _, _ := strings.Cut(last, closing) // closing always present
	if isBlank(before) {
		// last line only contains closing */
		if lineOfStars {
			closing = " */" // add blank to align final star
		}
		lines[len(lines)-1] = prefix + closing
	} else {
		// last line contains more comment text - assume
		// it is aligned like the other lines and include
		// in prefix computation
		prefix = commonPrefix(prefix, last)
	}

	// Remove the common prefix from all but the first and empty lines.
	for i, line := range lines {
		if i > 0 && line != "" {
			lines[i] = line[len(prefix):]
		}
	}
}

func (p *printer) writeComment(comment *ast.Comment) {
	text := comment.Text
	pos := p.posFor(comment.Pos())

	const linePrefix = "//line "
	if strings.HasPrefix(text, linePrefix) && (!pos.IsValid() || pos.Column == 1) {
		// Possibly a //-style line directive.
		// Suspend indentation temporarily to keep line directive valid.
		defer func(indent int) { p.indent = indent }(p.indent)
		p.indent = 0
	}

	// shortcut common case of //-style comments
	if text[1] == '/' {
		if constraint.IsGoBuild(text) {
			p.goBuild = append(p.goBuild, len(p.output))
		} else if constraint.IsPlusBuild(text) {
			p.plusBuild = append(p.plusBuild, len(p.output))
		}
		p.writeString(pos, trimRight(text), true)
		return
	}

	// for /*-style comments, print line by line and let the
	// write function take care of the proper indentation
	lines := strings.Split(text, "\n")

	// The comment started in the first column but is going
	// to be indented. For an idempotent result, add indentation
	// to all lines such that they look like they were indented
	// before - this will make sure the common prefix computation
	// is the same independent of how many times formatting is
	// applied (was issue 1835).
	if pos.IsValid() && pos.Column == 1 && p.indent > 0 {
		for i, line := range lines[1:] {
			lines[1+i] = "   " + line
		}
	}

	stripCommonPrefix(lines)

	// write comment lines, separated by formfeed,
	// without a line break after the last line
	for i, line := range lines {
		if i > 0 {
			p.writeByte('\f', 1)
			pos = p.pos
		}
		if len(line) > 0 {
			p.writeString(pos, trimRight(line), true)
		}
	}
}

// writeCommentSuffix writes a line break after a comment if indicated
// and processes any leftover indentation information. If a line break
// is needed, the kind of break (newline vs formfeed) depends on the
// pending whitespace. The writeCommentSuffix result indicates if a
// newline was written or if a formfeed was dropped from the whitespace
// buffer.
func (p *printer) writeCommentSuffix(needsLinebreak bool) (wroteNewline, droppedFF bool) {
	for i, ch := range p.wsbuf {
		switch ch {
		case blank, vtab:
			// ignore trailing whitespace
			p.wsbuf[i] = ignore
		case indent, unindent:
			// don't lose indentation information
		case newline, formfeed:
			// if we need a line break, keep exactly one
			// but remember if we dropped any formfeeds
			if needsLinebreak {
				needsLinebreak = false
				wroteNewline = true
			} else {
				if ch == formfeed {
					droppedFF = true
				}
				p.wsbuf[i] = ignore
			}
		}
	}
	p.writeWhitespace(len(p.wsbuf))

	// make sure we have a line break
	if needsLinebreak {
		p.writeByte('\n', 1)
		wroteNewline = true
	}

	return
}

// containsLinebreak reports whether the whitespace buffer contains any line breaks.
func (p *printer) containsLinebreak() bool {
	for _, ch := range p.wsbuf {
		if ch == newline || ch == formfeed {
			return true
		}
	}
	return false
}

// intersperseComments consumes all comments that appear before the next token
// tok and prints it together with the buffered whitespace (i.e., the whitespace
// that needs to be written before the next token). A heuristic is used to mix
// the comments and whitespace. The intersperseComments result indicates if a
// newline was written or if a formfeed was dropped from the whitespace buffer.
func (p *printer) intersperseComments(next token.Position, tok token.Token) (wroteNewline, droppedFF bool) {
	var last *ast.Comment
	for p.commentBefore(next) {
		list := p.comment.List
		changed := false
		if p.lastTok != token.IMPORT && // do not rewrite cgo's import "C" comments
			p.posFor(p.comment.Pos()).Column == 1 &&
			p.posFor(p.comment.End()+1) == next {
			// Unindented comment abutting next token position:
			// a top-level doc comment.
			list = formatDocComment(list)
			changed = true

			if len(p.comment.List) > 0 && len(list) == 0 {
				// The doc comment was removed entirely.
				// Keep preceding whitespace.
				p.writeCommentPrefix(p.posFor(p.comment.Pos()), next, last, tok)
				// Change print state to continue at next.
				p.pos = next
				p.last = next
				// There can't be any more comments.
				p.nextComment()
				return p.writeCommentSuffix(false)
			}
		}
		for _, c := range list {
			p.writeCommentPrefix(p.posFor(c.Pos()), next, last, tok)
			p.writeComment(c)
			last = c
		}
		// In case list was rewritten, change print state to where
		// the original list would have ended.
		if len(p.comment.List) > 0 && changed {
			last = p.comment.List[len(p.comment.List)-1]
			p.pos = p.posFor(last.End())
			p.last = p.pos
		}
		p.nextComment()
	}

	if last != nil {
		// If the last comment is a /*-style comment and the next item
		// follows on the same line but is not a comma, and not a "closing"
		// token immediately following its corresponding "opening" token,
		// add an extra separator unless explicitly disabled. Use a blank
		// as separator unless we have pending linebreaks, they are not
		// disabled, and we are outside a composite literal, in which case
		// we want a linebreak (issue 15137).
		// TODO(gri) This has become overly complicated. We should be able
		// to track whether we're inside an expression or statement and
		// use that information to decide more directly.
		needsLinebreak := false
		if p.mode&noExtraBlank == 0 &&
			last.Text[1] == '*' && p.lineFor(last.Pos()) == next.Line &&
			tok != token.COMMA &&
			(tok != token.RPAREN || p.prevOpen == token.LPAREN) &&
			(tok != token.RBRACK || p.prevOpen == token.LBRACK) {
			if p.containsLinebreak() && p.mode&noExtraLinebreak == 0 && p.level == 0 {
				needsLinebreak = true
			} else {
				p.writeByte(' ', 1)
			}
		}
		// Ensure that there is a line break after a //-style comment,
		// before EOF, and before a closing '}' unless explicitly disabled.
		if last.Text[1] == '/' ||
			tok == token.EOF ||
			tok == token.RBRACE && p.mode&noExtraLinebreak == 0 {
			needsLinebreak = true
		}
		return p.writeCommentSuffix(needsLinebreak)
	}

	// no comment was written - we should never reach here since
	// intersperseComments should not be called in that case
	p.internalError("intersperseComments called without pending comments")
	return
}

// writeWhitespace writes the first n whitespace entries.
func (p *printer) writeWhitespace(n int) {
	// write entries
	for i := 0; i < n; i++ {
		switch ch := p.wsbuf[i]; ch {
		case ignore:
			// ignore!
		case indent:
			p.indent++
		case unindent:
			p.indent--
			if p.indent < 0 {
				p.internalError("negative indentation:", p.indent)
				p.indent = 0
			}
		case newline, formfeed:
			// A line break immediately followed by a "correcting"
			// unindent is swapped with the unindent - this permits
			// proper label positioning. If a comment is between
			// the line break and the label, the unindent is not
			// part of the comment whitespace prefix and the comment
			// will be positioned correctly indented.
			if i+1 < n && p.wsbuf[i+1] == unindent {
				// Use a formfeed to terminate the current section.
				// Otherwise, a long label name on the next line leading
				// to a wide column may increase the indentation column
				// of lines before the label; effectively leading to wrong
				// indentation.
				p.wsbuf[i], p.wsbuf[i+1] = unindent, formfeed
				i-- // do it again
				continue
			}
			fallthrough
		default:
			p.writeByte(byte(ch), 1)
		}
	}

	// shift remaining entries down
	l := copy(p.wsbuf, p.wsbuf[n:])
	p.wsbuf = p.wsbuf[:l]
}

// ----------------------------------------------------------------------------
// Printing interface

// nlimit limits n to maxNewlines.
func nlimit(n int) int {
	return min(n, maxNewlines)
}

func mayCombine(prev token.Token, next byte) (b bool) {
	switch prev {
	case token.INT:
		b = next == '.' // 1.
	case token.ADD:
		b = next == '+' // ++
	case token.SUB:
		b = next == '-' // --
	case token.QUO:
		b = next == '*' // /*
	case token.LSS:
		b = next == '-' || next == '<' // <- or <<
	case token.AND:
		b = next == '&' || next == '^' // && or &^
	}
	return
}

func (p *printer) setPos(pos token.Pos) {
	if pos.IsValid() {
		p.pos = p.posFor(pos) // accurate position of next item
	}
}

// print prints a list of "items" (roughly corresponding to syntactic
// tokens, but also including whitespace and formatting information).
// It is the only print function that should be called directly from
// any of the AST printing functions in nodes.go.
//
// Whitespace is accumulated until a non-whitespace token appears. Any
// comments that need to appear before that token are printed first,
// taking into account the amount and structure of any pending white-
// space for best comment placement. Then, any leftover whitespace is
// printed, followed by the actual token.
func (p *printer) print(args ...any) {
	for _, arg := range args {
		// information about the current arg
		var data string
		var isLit bool
		var impliedSemi bool // value for p.impliedSemi after this arg

		// record previous opening token, if any
		switch p.lastTok {
		case token.ILLEGAL:
			// ignore (white space)
		case token.LPAREN, token.LBRACK:
			p.prevOpen = p.lastTok
		default:
			// other tokens followed any opening token
			p.prevOpen = token.ILLEGAL
		}

		switch x := arg.(type) {
		case pmode:
			// toggle printer mode
			p.mode ^= x
			continue

		case whiteSpace:
			if x == ignore {
				// don't add ignore's to the buffer; they
				// may screw up "correcting" unindents (see
				// LabeledStmt)
				continue
			}
			i := len(p.wsbuf)
			if i == cap(p.wsbuf) {
				// Whitespace sequences are very short so this should
				// never happen. Handle gracefully (but possibly with
				// bad comment placement) if it does happen.
				p.writeWhitespace(i)
				i = 0
			}
			p.wsbuf = p.wsbuf[0 : i+1]
			p.wsbuf[i] = x
			if x == newline || x == formfeed {
				// newlines affect the current state (p.impliedSemi)
				// and not the state after printing arg (impliedSemi)
				// because comments can be interspersed before the arg
				// in this case
				p.impliedSemi = false
			}
			p.lastTok = token.ILLEGAL
			continue

		case *ast.Ident:
			data = x.Name
			impliedSemi = true
			p.lastTok = token.IDENT

		case *ast.BasicLit:
			data = x.Value
			isLit = true
			impliedSemi = true
			p.lastTok = x.Kind

		case token.Token:
			s := x.String()
			if mayCombine(p.lastTok, s[0]) {
				// the previous and the current token must be
				// separated by a blank otherwise they combine
				// into a different incorrect token sequence
				// (except for token.INT followed by a '.' this
				// should never happen because it is taken care
				// of via binary expression formatting)
				if len(p.wsbuf) != 0 {
					p.internalError("whitespace buffer not empty")
				}
				p.wsbuf = p.wsbuf[0:1]
				p.wsbuf[0] = ' '
			}
			data = s
			// some keywords followed by a newline imply a semicolon
			switch x {
			case token.BREAK, token.CONTINUE, token.FALLTHROUGH, token.RETURN,
				token.INC, token.DEC, token.RPAREN, token.RBRACK, token.RBRACE:
				impliedSemi = true
			}
			p.lastTok = x

		case string:
			// incorrect AST - print error message
			data = x
			isLit = true
			impliedSemi = true
			p.lastTok = token.STRING

		default:
			fmt.Fprintf(os.Stderr, "print: unsupported argument %v (%T)\n", arg, arg)
			panic("go/printer type")
		}
		// data != ""

		next := p.pos // estimated/accurate position of next item
		wroteNewline, droppedFF := p.flush(next, p.lastTok)

		// intersperse extra newlines if present in the source and
		// if they don't cause extra semicolons (don't do this in
		// flush as it will cause extra newlines at the end of a file)
		if !p.impliedSemi {
			n := nlimit(next.Line - p.pos.Line)
			// don't exceed maxNewlines if we already wrote one
			if wroteNewline && n == maxNewlines {
				n = maxNewlines - 1
			}
			if n > 0 {
				ch := byte('\n')
				if droppedFF {
					ch = '\f' // use formfeed since we dropped one before
				}
				p.writeByte(ch, n)
				impliedSemi = false
			}
		}

		// the next token starts now - record its line number if requested
		if p.linePtr != nil {
			*p.linePtr = p.out.Line
			p.linePtr = nil
		}

		p.writeString(next, data, isLit)
		p.impliedSemi = impliedSemi
	}
}

// flush prints any pending comments and whitespace occurring textually
// before the position of the next token tok. The flush result indicates
// if a newline was written or if a formfeed was dropped from the whitespace
// buffer.
func (p *printer) flush(next token.Position, tok token.Token) (wroteNewline, droppedFF bool) {
	if p.commentBefore(next) {
		// if there are comments before the next item, intersperse them
		wroteNewline, droppedFF = p.intersperseComments(next, tok)
	} else {
		// otherwise, write any leftover whitespace
		p.writeWhitespace(len(p.wsbuf))
	}
	return
}

// getDoc returns the ast.CommentGroup associated with n, if any.
func getDoc(n ast.Node) *ast.CommentGroup {
	switch n := n.(type) {
	case *ast.Field:
		return n.Doc
	case *ast.ImportSpec:
		return n.Doc
	case *ast.ValueSpec:
		return n.Doc
	case *ast.TypeSpec:
		return n.Doc
	case *ast.GenDecl:
		return n.Doc
	case *ast.FuncDecl:
		return n.Doc
	case *ast.File:
		return n.Doc
	}
	return nil
}

func getLastComment(n ast.Node) *ast.CommentGroup {
	switch n := n.(type) {
	case *ast.Field:
		return n.Comment
	case *ast.ImportSpec:
		return n.Comment
	case *ast.ValueSp
"""




```