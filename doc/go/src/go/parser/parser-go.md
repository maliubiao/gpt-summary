Response:
Let's break down the thought process for analyzing this Go parser code.

**1. Understanding the Request:**

The core request is to analyze a segment of Go parser code, specifically `go/src/go/parser/parser.go`, and identify its functionalities. The request also asks for examples, explanations of specific aspects like command-line arguments (which turn out to be irrelevant here), common mistakes, and a summary of its function. It's important to note the "Part 1 of 3" which implies this is an ongoing analysis and focusing on the current snippet is key.

**2. Initial Scan and Keyword Spotting:**

I immediately scanned the code for keywords and structures that are characteristic of a parser:

* **`package parser`**:  Confirms the primary role.
* **`import (...)`**:  Identifies dependencies, including `go/ast` (Abstract Syntax Tree), `go/scanner`, and `go/token`, all crucial for parsing.
* **`type parser struct { ... }`**: This is the central data structure, holding the parser's state. The fields within this struct are goldmines of information about the parser's workings.
* **Function names starting with `Parse*`**:  The comment mentions these as entry points. Although not in *this* snippet, it's a crucial piece of information.
* **Function names like `next()`, `expect()`, `advance()`**: These are typical low-level parser operations.
* **Error handling mechanisms:** `errors scanner.ErrorList`, `error()`, `errorExpected()`, `bailout{}`.
* **Comments:**  The code specifically handles and stores comments, indicating their importance in the AST.
* **Tracing/Debugging:** `mode`, `trace`, `printTrace()`, `trace()`, `un()`.

**3. Deeper Dive into `parser` struct:**

I then examined the fields of the `parser` struct in more detail, inferring their purpose:

* **`file *token.File`, `scanner scanner.Scanner`**:  Input management – representing the file being parsed and the token stream.
* **`errors scanner.ErrorList`**:  Error reporting.
* **`mode Mode`, `trace bool`, `indent int`**:  Debugging and control of parser behavior.
* **`comments []*ast.CommentGroup`, `leadComment`, `lineComment`, `top bool`**: Handling and categorization of comments.
* **`pos token.Pos`, `tok token.Token`, `lit string`**:  The current token being processed (lookahead).
* **`syncPos`, `syncCnt`**: Error recovery mechanisms to prevent infinite loops.
* **`exprLev`, `inRhs`**: Contextual parsing information (expression level, right-hand side of an assignment).
* **`imports []*ast.ImportSpec`**:  Storing parsed import declarations.
* **`nestLev`**: Prevents stack overflow during parsing.

**4. Analyzing Key Functions:**

I focused on functions that seemed to perform core parsing tasks:

* **`init()`**:  Initialization of the parser state.
* **`next0()`, `next()`**:  Token consumption and comment handling. The logic for distinguishing lead and line comments is interesting.
* **`error()`, `errorExpected()`**: Error reporting and formatting.
* **`expect()`, `expect2()`, `expectClosing()`, `expectSemi()`**:  Token expectation and consumption with error handling.
* **`advance()`**: Error recovery by skipping tokens.
* **`parseIdent()`, `parseIdentList()`**: Parsing identifiers.
* **`parseExprList()`**: Parsing lists of expressions.
* **`parseType()` and its related functions (`parseArrayType`, `parseStructType`, `parsePointerType`, `parseFuncType`, `parseInterfaceType`, etc.)**:  A significant portion of the code dedicated to parsing various Go type constructs. This strongly suggests a core function of the parser.
* **`parseParameters()`, `parseResult()`**: Parsing function parameters and return types.

**5. Inferring Overall Functionality:**

Based on the identified components, I started to form a picture of the parser's main functions:

* **Tokenization:** Relies on `go/scanner` to break the source code into tokens.
* **Abstract Syntax Tree (AST) Construction:**  The `go/ast` package is used extensively to create a tree-like representation of the code.
* **Syntax Analysis:** The various `parse...` functions implement the grammar rules of Go, recognizing and structuring the code.
* **Error Handling:**  Mechanisms to detect and report syntax errors, and to attempt to recover from them.
* **Comment Handling:**  Preserving comments and associating them with relevant AST nodes.

**6. Addressing Specific Questions (within Part 1):**

* **Functionality Listing:** I listed the core functions based on the analysis above.
* **Inferring Go Feature:**  The strong focus on type parsing led to the conclusion that it's deeply involved in parsing type declarations, function signatures, and struct/interface definitions – fundamental Go language features.
* **Go Code Example:** I crafted an example demonstrating a simple type declaration, as this is a key area covered by the analyzed code. The input and output were based on the AST structure the parser would generate.
* **Command-Line Arguments:** Recognizing the lack of command-line argument processing within the snippet, I stated that and focused on the internal parsing logic.
* **Common Mistakes:** I considered potential issues a user of *this part of the parser* (though it's not directly used by end-users) might make – focusing on misuse of the internal functions or misunderstandings of error handling.
* **Summarizing Functionality (for Part 1):** I provided a concise summary of the capabilities covered in this specific code excerpt.

**7. Iteration and Refinement:**

Throughout this process, I would reread sections of the code, double-check my assumptions, and refine my understanding. For example, the comment handling logic in `next()` required careful reading to understand the distinction between lead and line comments. Similarly, the various `parseType*` functions and their relationships needed careful consideration to understand the type parsing process.

This iterative process of scanning, analyzing, inferring, and refining is crucial for understanding complex code like a parser. The "Part 1 of 3" aspect also reminded me to keep the scope focused and avoid making assumptions about functionalities that might be covered in subsequent parts.
这段代码是 Go 语言 `go/parser` 包中 `parser.go` 文件的一部分，它实现了 Go 源代码的**词法分析和语法分析**（parsing）的核心功能。更具体地说，它定义了 `parser` 结构体和一系列方法，用于将 Go 源代码的文本转换为抽象语法树（AST）。

以下是这段代码的主要功能归纳：

1. **初始化 Parser 状态 (`init` 函数):**
   - 接收 `token.File`（表示要解析的文件）、源代码字节切片 `[]byte` 和解析模式 `Mode` 作为输入。
   - 创建并初始化一个 `scanner.Scanner`，用于将源代码分解为词法单元（tokens）。
   - 设置解析器的一些内部状态，如是否跟踪解析过程、初始缩进等。

2. **词法单元推进 (`next0`, `next` 函数):**
   - `next0` 函数负责调用 `scanner.Scanner.Scan()` 获取下一个词法单元。
   - `next` 函数在 `next0` 的基础上增加了对注释的处理逻辑，区分并记录前导注释 (`leadComment`) 和行尾注释 (`lineComment`)，这些注释会附加到 AST 节点上。

3. **错误处理 (`error`, `errorExpected` 函数):**
   - 提供了报告解析过程中遇到的语法错误的机制。
   - `error` 接收错误发生的位置和错误消息。
   - `errorExpected` 用于报告期望出现的词法单元与实际遇到的不符的情况。
   - 实现了简单的错误抑制策略，避免在同一行报告过多错误，并防止因过多错误而无限循环。

4. **词法单元断言和消费 (`expect`, `expect2`, `expectClosing`, `expectSemi` 函数):**
   - 这些函数用于检查当前词法单元是否符合预期，如果符合则消费（移动到下一个词法单元），否则报告错误。
   - `expect` 在不符合预期时会报告错误。
   - `expect2` 在不符合预期时返回无效的位置。
   - `expectClosing` 针对常见的缺失逗号的情况提供了更友好的错误消息。
   - `expectSemi` 用于期望一个分号，并处理可选分号的情况，同时返回行尾注释。

5. **辅助函数 (`printTrace`, `trace`, `un`, `incNestLev`, `decNestLev`, `advance`, `atComma`, `assert`, `safePos`):**
   - `printTrace`, `trace`, `un`: 用于解析过程的跟踪和调试输出。
   - `incNestLev`, `decNestLev`: 用于控制解析过程的递归深度，防止栈溢出。
   - `advance`: 用于在遇到语法错误时跳过一些词法单元，以便继续解析，避免级联错误。
   - `atComma`: 检查当前词法单元是否是逗号，如果不是但接近预期的结束符，则可能报告缺失逗号的错误。
   - `assert`: 用于内部断言，帮助开发者发现 parser 代码中的错误。
   - `safePos`:  用于处理可能超出文件范围的位置信息，防止后续处理时出现 panic。

6. **标识符解析 (`parseIdent`, `parseIdentList` 函数):**
   - `parseIdent` 用于解析一个标识符。
   - `parseIdentList` 用于解析逗号分隔的标识符列表。

7. **表达式解析 (`parseExprList`, `parseList` 函数):**
   - `parseExprList` 用于解析逗号分隔的表达式列表。
   - `parseList` 是 `parseExprList` 的一个包装，用于设置解析右侧表达式的标志。

8. **类型解析 (以 `parseType` 开头的多个函数，例如 `parseArrayType`, `parseStructType`, `parseFuncType`, `parseInterfaceType` 等):**
   - 这部分代码是该文件中非常重要的组成部分，负责解析 Go 语言的各种类型定义，包括基本类型、数组、结构体、指针、函数类型、接口类型等。
   - 这些函数通常会递归调用，以处理复杂的类型结构。

9. **注释处理 (`consumeComment`, `consumeCommentGroup` 函数):**
   - `consumeComment` 用于消费一个注释并返回其内容和结束行号。
   - `consumeCommentGroup` 用于消费一组相邻的注释，并将它们添加到解析器的注释列表中。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码的核心功能是**将 Go 源代码解析成抽象语法树（AST）**。AST 是源代码的一种结构化表示，方便后续的编译、分析和转换等操作。

**Go 代码举例说明：**

假设我们有以下 Go 源代码：

```go
package main

type MyInt int

func add(a, b int) int {
	return a + b
}
```

当 `parser.go` 中的代码解析这段代码时，它会生成一个表示该代码结构的 AST。例如，对于 `type MyInt int`，AST 中会有一个 `ast.TypeSpec` 节点，表示一个类型声明，其中包含类型名 `MyInt` 和类型定义 `int`。对于 `func add(a, b int) int { ... }`，AST 中会有一个 `ast.FuncDecl` 节点，表示一个函数声明，包含函数名 `add`，参数列表 `(a, b int)` 和返回值类型 `int`，以及函数体。

**假设的输入与输出（简化）：**

**输入 (部分):** 词法分析器 (`scanner`) 输出的 tokens 流，例如：
```
token.PACKAGE, "package", token.IDENT, "main", token.SEMICOLON,
token.TYPE, "type", token.IDENT, "MyInt", token.IDENT, "int", token.SEMICOLON,
token.FUNC, "func", token.IDENT, "add", token.LPAREN, token.IDENT, "a", token.COMMA, token.IDENT, "b", token.IDENT, "int", token.RPAREN, token.IDENT, "int", token.LBRACE, ...
```

**输出 (部分 AST 结构，Go 语法表示):**
```go
&ast.File{
	Name: &ast.Ident{Name: "main"},
	Decls: []ast.Decl{
		&ast.GenDecl{
			Tok: token.TYPE,
			Specs: []ast.Spec{
				&ast.TypeSpec{
					Name: &ast.Ident{Name: "MyInt"},
					Type: &ast.Ident{Name: "int"},
				},
			},
		},
		&ast.FuncDecl{
			Name: &ast.Ident{Name: "add"},
			Type: &ast.FuncType{
				Params: &ast.FieldList{
					List: []*ast.Field{
						{Names: []*ast.Ident{{Name: "a"}, {Name: "b"}}, Type: &ast.Ident{Name: "int"}},
					},
				},
				Results: &ast.FieldList{
					List: []*ast.Field{
						{Type: &ast.Ident{Name: "int"}},
					},
				},
			},
			Body: &ast.BlockStmt{
				// ... 函数体语句的 AST 节点
			},
		},
	},
}
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。`go/parser` 包通常被 `go` 工具链或其他需要解析 Go 代码的工具使用。这些工具可能会有自己的命令行参数，用于指定要解析的文件、解析模式等。例如，`go build` 命令在编译 Go 代码时会使用 `go/parser` 来解析源文件。

**使用者易犯错的点：**

作为 `go/parser` 包的使用者（通常是其他 Go 工具的开发者），容易犯错的点可能包括：

* **不理解不同的解析模式 (`Mode`) 的含义：**  `Mode` 参数会影响解析器的行为，例如是否解析注释。不了解这些模式可能会导致解析结果不符合预期。
* **错误地处理 `parser.Parse*` 函数返回的错误：**  解析可能会失败并返回错误，使用者需要正确地检查和处理这些错误。
* **假设 AST 的结构与源代码完全一致：**  解析器为了容错或简化处理，可能会对某些语法结构进行调整，例如方法声明的接收者。使用者需要参考 `go/ast` 包的文档来理解 AST 的具体结构。

**功能归纳（针对第 1 部分）：**

这段代码实现了 `go/parser` 包中**词法分析和语法分析的基础框架**。它定义了 `parser` 结构体来维护解析状态，并提供了一系列方法用于：

- 初始化解析器并与词法分析器 (`scanner`) 关联。
- 逐个读取和消费源代码的词法单元。
- 处理和记录源代码中的注释。
- 进行基本的语法结构识别，例如标识符、表达式和类型。
- 管理和报告解析过程中遇到的语法错误。
- 提供辅助功能用于调试和错误恢复。

总的来说，这段代码是 Go 语言解析器的核心引擎，负责将原始的 Go 源代码文本转换为结构化的抽象语法树，为后续的编译和代码分析奠定基础。

### 提示词
```
这是路径为go/src/go/parser/parser.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package parser implements a parser for Go source files. Input may be
// provided in a variety of forms (see the various Parse* functions); the
// output is an abstract syntax tree (AST) representing the Go source. The
// parser is invoked through one of the Parse* functions.
//
// The parser accepts a larger language than is syntactically permitted by
// the Go spec, for simplicity, and for improved robustness in the presence
// of syntax errors. For instance, in method declarations, the receiver is
// treated like an ordinary parameter list and thus may contain multiple
// entries where the spec permits exactly one. Consequently, the corresponding
// field in the AST (ast.FuncDecl.Recv) field is not restricted to one entry.
package parser

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/scanner"
	"go/token"
	"strings"
)

// The parser structure holds the parser's internal state.
type parser struct {
	file    *token.File
	errors  scanner.ErrorList
	scanner scanner.Scanner

	// Tracing/debugging
	mode   Mode // parsing mode
	trace  bool // == (mode&Trace != 0)
	indent int  // indentation used for tracing output

	// Comments
	comments    []*ast.CommentGroup
	leadComment *ast.CommentGroup // last lead comment
	lineComment *ast.CommentGroup // last line comment
	top         bool              // in top of file (before package clause)
	goVersion   string            // minimum Go version found in //go:build comment

	// Next token
	pos token.Pos   // token position
	tok token.Token // one token look-ahead
	lit string      // token literal

	// Error recovery
	// (used to limit the number of calls to parser.advance
	// w/o making scanning progress - avoids potential endless
	// loops across multiple parser functions during error recovery)
	syncPos token.Pos // last synchronization position
	syncCnt int       // number of parser.advance calls without progress

	// Non-syntactic parser control
	exprLev int  // < 0: in control clause, >= 0: in expression
	inRhs   bool // if set, the parser is parsing a rhs expression

	imports []*ast.ImportSpec // list of imports

	// nestLev is used to track and limit the recursion depth
	// during parsing.
	nestLev int
}

func (p *parser) init(file *token.File, src []byte, mode Mode) {
	p.file = file
	eh := func(pos token.Position, msg string) { p.errors.Add(pos, msg) }
	p.scanner.Init(p.file, src, eh, scanner.ScanComments)

	p.top = true
	p.mode = mode
	p.trace = mode&Trace != 0 // for convenience (p.trace is used frequently)
	p.next()
}

// ----------------------------------------------------------------------------
// Parsing support

func (p *parser) printTrace(a ...any) {
	const dots = ". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . "
	const n = len(dots)
	pos := p.file.Position(p.pos)
	fmt.Printf("%5d:%3d: ", pos.Line, pos.Column)
	i := 2 * p.indent
	for i > n {
		fmt.Print(dots)
		i -= n
	}
	// i <= n
	fmt.Print(dots[0:i])
	fmt.Println(a...)
}

func trace(p *parser, msg string) *parser {
	p.printTrace(msg, "(")
	p.indent++
	return p
}

// Usage pattern: defer un(trace(p, "..."))
func un(p *parser) {
	p.indent--
	p.printTrace(")")
}

// maxNestLev is the deepest we're willing to recurse during parsing
const maxNestLev int = 1e5

func incNestLev(p *parser) *parser {
	p.nestLev++
	if p.nestLev > maxNestLev {
		p.error(p.pos, "exceeded max nesting depth")
		panic(bailout{})
	}
	return p
}

// decNestLev is used to track nesting depth during parsing to prevent stack exhaustion.
// It is used along with incNestLev in a similar fashion to how un and trace are used.
func decNestLev(p *parser) {
	p.nestLev--
}

// Advance to the next token.
func (p *parser) next0() {
	// Because of one-token look-ahead, print the previous token
	// when tracing as it provides a more readable output. The
	// very first token (!p.pos.IsValid()) is not initialized
	// (it is token.ILLEGAL), so don't print it.
	if p.trace && p.pos.IsValid() {
		s := p.tok.String()
		switch {
		case p.tok.IsLiteral():
			p.printTrace(s, p.lit)
		case p.tok.IsOperator(), p.tok.IsKeyword():
			p.printTrace("\"" + s + "\"")
		default:
			p.printTrace(s)
		}
	}

	for {
		p.pos, p.tok, p.lit = p.scanner.Scan()
		if p.tok == token.COMMENT {
			if p.top && strings.HasPrefix(p.lit, "//go:build") {
				if x, err := constraint.Parse(p.lit); err == nil {
					p.goVersion = constraint.GoVersion(x)
				}
			}
			if p.mode&ParseComments == 0 {
				continue
			}
		} else {
			// Found a non-comment; top of file is over.
			p.top = false
		}
		break
	}
}

// Consume a comment and return it and the line on which it ends.
func (p *parser) consumeComment() (comment *ast.Comment, endline int) {
	// /*-style comments may end on a different line than where they start.
	// Scan the comment for '\n' chars and adjust endline accordingly.
	endline = p.file.Line(p.pos)
	if p.lit[1] == '*' {
		// don't use range here - no need to decode Unicode code points
		for i := 0; i < len(p.lit); i++ {
			if p.lit[i] == '\n' {
				endline++
			}
		}
	}

	comment = &ast.Comment{Slash: p.pos, Text: p.lit}
	p.next0()

	return
}

// Consume a group of adjacent comments, add it to the parser's
// comments list, and return it together with the line at which
// the last comment in the group ends. A non-comment token or n
// empty lines terminate a comment group.
func (p *parser) consumeCommentGroup(n int) (comments *ast.CommentGroup, endline int) {
	var list []*ast.Comment
	endline = p.file.Line(p.pos)
	for p.tok == token.COMMENT && p.file.Line(p.pos) <= endline+n {
		var comment *ast.Comment
		comment, endline = p.consumeComment()
		list = append(list, comment)
	}

	// add comment group to the comments list
	comments = &ast.CommentGroup{List: list}
	p.comments = append(p.comments, comments)

	return
}

// Advance to the next non-comment token. In the process, collect
// any comment groups encountered, and remember the last lead and
// line comments.
//
// A lead comment is a comment group that starts and ends in a
// line without any other tokens and that is followed by a non-comment
// token on the line immediately after the comment group.
//
// A line comment is a comment group that follows a non-comment
// token on the same line, and that has no tokens after it on the line
// where it ends.
//
// Lead and line comments may be considered documentation that is
// stored in the AST.
func (p *parser) next() {
	p.leadComment = nil
	p.lineComment = nil
	prev := p.pos
	p.next0()

	if p.tok == token.COMMENT {
		var comment *ast.CommentGroup
		var endline int

		if p.file.Line(p.pos) == p.file.Line(prev) {
			// The comment is on same line as the previous token; it
			// cannot be a lead comment but may be a line comment.
			comment, endline = p.consumeCommentGroup(0)
			if p.file.Line(p.pos) != endline || p.tok == token.SEMICOLON || p.tok == token.EOF {
				// The next token is on a different line, thus
				// the last comment group is a line comment.
				p.lineComment = comment
			}
		}

		// consume successor comments, if any
		endline = -1
		for p.tok == token.COMMENT {
			comment, endline = p.consumeCommentGroup(1)
		}

		if endline+1 == p.file.Line(p.pos) {
			// The next token is following on the line immediately after the
			// comment group, thus the last comment group is a lead comment.
			p.leadComment = comment
		}
	}
}

// A bailout panic is raised to indicate early termination. pos and msg are
// only populated when bailing out of object resolution.
type bailout struct {
	pos token.Pos
	msg string
}

func (p *parser) error(pos token.Pos, msg string) {
	if p.trace {
		defer un(trace(p, "error: "+msg))
	}

	epos := p.file.Position(pos)

	// If AllErrors is not set, discard errors reported on the same line
	// as the last recorded error and stop parsing if there are more than
	// 10 errors.
	if p.mode&AllErrors == 0 {
		n := len(p.errors)
		if n > 0 && p.errors[n-1].Pos.Line == epos.Line {
			return // discard - likely a spurious error
		}
		if n > 10 {
			panic(bailout{})
		}
	}

	p.errors.Add(epos, msg)
}

func (p *parser) errorExpected(pos token.Pos, msg string) {
	msg = "expected " + msg
	if pos == p.pos {
		// the error happened at the current position;
		// make the error message more specific
		switch {
		case p.tok == token.SEMICOLON && p.lit == "\n":
			msg += ", found newline"
		case p.tok.IsLiteral():
			// print 123 rather than 'INT', etc.
			msg += ", found " + p.lit
		default:
			msg += ", found '" + p.tok.String() + "'"
		}
	}
	p.error(pos, msg)
}

func (p *parser) expect(tok token.Token) token.Pos {
	pos := p.pos
	if p.tok != tok {
		p.errorExpected(pos, "'"+tok.String()+"'")
	}
	p.next() // make progress
	return pos
}

// expect2 is like expect, but it returns an invalid position
// if the expected token is not found.
func (p *parser) expect2(tok token.Token) (pos token.Pos) {
	if p.tok == tok {
		pos = p.pos
	} else {
		p.errorExpected(p.pos, "'"+tok.String()+"'")
	}
	p.next() // make progress
	return
}

// expectClosing is like expect but provides a better error message
// for the common case of a missing comma before a newline.
func (p *parser) expectClosing(tok token.Token, context string) token.Pos {
	if p.tok != tok && p.tok == token.SEMICOLON && p.lit == "\n" {
		p.error(p.pos, "missing ',' before newline in "+context)
		p.next()
	}
	return p.expect(tok)
}

// expectSemi consumes a semicolon and returns the applicable line comment.
func (p *parser) expectSemi() (comment *ast.CommentGroup) {
	// semicolon is optional before a closing ')' or '}'
	if p.tok != token.RPAREN && p.tok != token.RBRACE {
		switch p.tok {
		case token.COMMA:
			// permit a ',' instead of a ';' but complain
			p.errorExpected(p.pos, "';'")
			fallthrough
		case token.SEMICOLON:
			if p.lit == ";" {
				// explicit semicolon
				p.next()
				comment = p.lineComment // use following comments
			} else {
				// artificial semicolon
				comment = p.lineComment // use preceding comments
				p.next()
			}
			return comment
		default:
			p.errorExpected(p.pos, "';'")
			p.advance(stmtStart)
		}
	}
	return nil
}

func (p *parser) atComma(context string, follow token.Token) bool {
	if p.tok == token.COMMA {
		return true
	}
	if p.tok != follow {
		msg := "missing ','"
		if p.tok == token.SEMICOLON && p.lit == "\n" {
			msg += " before newline"
		}
		p.error(p.pos, msg+" in "+context)
		return true // "insert" comma and continue
	}
	return false
}

func assert(cond bool, msg string) {
	if !cond {
		panic("go/parser internal error: " + msg)
	}
}

// advance consumes tokens until the current token p.tok
// is in the 'to' set, or token.EOF. For error recovery.
func (p *parser) advance(to map[token.Token]bool) {
	for ; p.tok != token.EOF; p.next() {
		if to[p.tok] {
			// Return only if parser made some progress since last
			// sync or if it has not reached 10 advance calls without
			// progress. Otherwise consume at least one token to
			// avoid an endless parser loop (it is possible that
			// both parseOperand and parseStmt call advance and
			// correctly do not advance, thus the need for the
			// invocation limit p.syncCnt).
			if p.pos == p.syncPos && p.syncCnt < 10 {
				p.syncCnt++
				return
			}
			if p.pos > p.syncPos {
				p.syncPos = p.pos
				p.syncCnt = 0
				return
			}
			// Reaching here indicates a parser bug, likely an
			// incorrect token list in this function, but it only
			// leads to skipping of possibly correct code if a
			// previous error is present, and thus is preferred
			// over a non-terminating parse.
		}
	}
}

var stmtStart = map[token.Token]bool{
	token.BREAK:       true,
	token.CONST:       true,
	token.CONTINUE:    true,
	token.DEFER:       true,
	token.FALLTHROUGH: true,
	token.FOR:         true,
	token.GO:          true,
	token.GOTO:        true,
	token.IF:          true,
	token.RETURN:      true,
	token.SELECT:      true,
	token.SWITCH:      true,
	token.TYPE:        true,
	token.VAR:         true,
}

var declStart = map[token.Token]bool{
	token.IMPORT: true,
	token.CONST:  true,
	token.TYPE:   true,
	token.VAR:    true,
}

var exprEnd = map[token.Token]bool{
	token.COMMA:     true,
	token.COLON:     true,
	token.SEMICOLON: true,
	token.RPAREN:    true,
	token.RBRACK:    true,
	token.RBRACE:    true,
}

// safePos returns a valid file position for a given position: If pos
// is valid to begin with, safePos returns pos. If pos is out-of-range,
// safePos returns the EOF position.
//
// This is hack to work around "artificial" end positions in the AST which
// are computed by adding 1 to (presumably valid) token positions. If the
// token positions are invalid due to parse errors, the resulting end position
// may be past the file's EOF position, which would lead to panics if used
// later on.
func (p *parser) safePos(pos token.Pos) (res token.Pos) {
	defer func() {
		if recover() != nil {
			res = token.Pos(p.file.Base() + p.file.Size()) // EOF position
		}
	}()
	_ = p.file.Offset(pos) // trigger a panic if position is out-of-range
	return pos
}

// ----------------------------------------------------------------------------
// Identifiers

func (p *parser) parseIdent() *ast.Ident {
	pos := p.pos
	name := "_"
	if p.tok == token.IDENT {
		name = p.lit
		p.next()
	} else {
		p.expect(token.IDENT) // use expect() error handling
	}
	return &ast.Ident{NamePos: pos, Name: name}
}

func (p *parser) parseIdentList() (list []*ast.Ident) {
	if p.trace {
		defer un(trace(p, "IdentList"))
	}

	list = append(list, p.parseIdent())
	for p.tok == token.COMMA {
		p.next()
		list = append(list, p.parseIdent())
	}

	return
}

// ----------------------------------------------------------------------------
// Common productions

// If lhs is set, result list elements which are identifiers are not resolved.
func (p *parser) parseExprList() (list []ast.Expr) {
	if p.trace {
		defer un(trace(p, "ExpressionList"))
	}

	list = append(list, p.parseExpr())
	for p.tok == token.COMMA {
		p.next()
		list = append(list, p.parseExpr())
	}

	return
}

func (p *parser) parseList(inRhs bool) []ast.Expr {
	old := p.inRhs
	p.inRhs = inRhs
	list := p.parseExprList()
	p.inRhs = old
	return list
}

// ----------------------------------------------------------------------------
// Types

func (p *parser) parseType() ast.Expr {
	if p.trace {
		defer un(trace(p, "Type"))
	}

	typ := p.tryIdentOrType()

	if typ == nil {
		pos := p.pos
		p.errorExpected(pos, "type")
		p.advance(exprEnd)
		return &ast.BadExpr{From: pos, To: p.pos}
	}

	return typ
}

func (p *parser) parseQualifiedIdent(ident *ast.Ident) ast.Expr {
	if p.trace {
		defer un(trace(p, "QualifiedIdent"))
	}

	typ := p.parseTypeName(ident)
	if p.tok == token.LBRACK {
		typ = p.parseTypeInstance(typ)
	}

	return typ
}

// If the result is an identifier, it is not resolved.
func (p *parser) parseTypeName(ident *ast.Ident) ast.Expr {
	if p.trace {
		defer un(trace(p, "TypeName"))
	}

	if ident == nil {
		ident = p.parseIdent()
	}

	if p.tok == token.PERIOD {
		// ident is a package name
		p.next()
		sel := p.parseIdent()
		return &ast.SelectorExpr{X: ident, Sel: sel}
	}

	return ident
}

// "[" has already been consumed, and lbrack is its position.
// If len != nil it is the already consumed array length.
func (p *parser) parseArrayType(lbrack token.Pos, len ast.Expr) *ast.ArrayType {
	if p.trace {
		defer un(trace(p, "ArrayType"))
	}

	if len == nil {
		p.exprLev++
		// always permit ellipsis for more fault-tolerant parsing
		if p.tok == token.ELLIPSIS {
			len = &ast.Ellipsis{Ellipsis: p.pos}
			p.next()
		} else if p.tok != token.RBRACK {
			len = p.parseRhs()
		}
		p.exprLev--
	}
	if p.tok == token.COMMA {
		// Trailing commas are accepted in type parameter
		// lists but not in array type declarations.
		// Accept for better error handling but complain.
		p.error(p.pos, "unexpected comma; expecting ]")
		p.next()
	}
	p.expect(token.RBRACK)
	elt := p.parseType()
	return &ast.ArrayType{Lbrack: lbrack, Len: len, Elt: elt}
}

func (p *parser) parseArrayFieldOrTypeInstance(x *ast.Ident) (*ast.Ident, ast.Expr) {
	if p.trace {
		defer un(trace(p, "ArrayFieldOrTypeInstance"))
	}

	lbrack := p.expect(token.LBRACK)
	trailingComma := token.NoPos // if valid, the position of a trailing comma preceding the ']'
	var args []ast.Expr
	if p.tok != token.RBRACK {
		p.exprLev++
		args = append(args, p.parseRhs())
		for p.tok == token.COMMA {
			comma := p.pos
			p.next()
			if p.tok == token.RBRACK {
				trailingComma = comma
				break
			}
			args = append(args, p.parseRhs())
		}
		p.exprLev--
	}
	rbrack := p.expect(token.RBRACK)

	if len(args) == 0 {
		// x []E
		elt := p.parseType()
		return x, &ast.ArrayType{Lbrack: lbrack, Elt: elt}
	}

	// x [P]E or x[P]
	if len(args) == 1 {
		elt := p.tryIdentOrType()
		if elt != nil {
			// x [P]E
			if trailingComma.IsValid() {
				// Trailing commas are invalid in array type fields.
				p.error(trailingComma, "unexpected comma; expecting ]")
			}
			return x, &ast.ArrayType{Lbrack: lbrack, Len: args[0], Elt: elt}
		}
	}

	// x[P], x[P1, P2], ...
	return nil, packIndexExpr(x, lbrack, args, rbrack)
}

func (p *parser) parseFieldDecl() *ast.Field {
	if p.trace {
		defer un(trace(p, "FieldDecl"))
	}

	doc := p.leadComment

	var names []*ast.Ident
	var typ ast.Expr
	switch p.tok {
	case token.IDENT:
		name := p.parseIdent()
		if p.tok == token.PERIOD || p.tok == token.STRING || p.tok == token.SEMICOLON || p.tok == token.RBRACE {
			// embedded type
			typ = name
			if p.tok == token.PERIOD {
				typ = p.parseQualifiedIdent(name)
			}
		} else {
			// name1, name2, ... T
			names = []*ast.Ident{name}
			for p.tok == token.COMMA {
				p.next()
				names = append(names, p.parseIdent())
			}
			// Careful dance: We don't know if we have an embedded instantiated
			// type T[P1, P2, ...] or a field T of array type []E or [P]E.
			if len(names) == 1 && p.tok == token.LBRACK {
				name, typ = p.parseArrayFieldOrTypeInstance(name)
				if name == nil {
					names = nil
				}
			} else {
				// T P
				typ = p.parseType()
			}
		}
	case token.MUL:
		star := p.pos
		p.next()
		if p.tok == token.LPAREN {
			// *(T)
			p.error(p.pos, "cannot parenthesize embedded type")
			p.next()
			typ = p.parseQualifiedIdent(nil)
			// expect closing ')' but no need to complain if missing
			if p.tok == token.RPAREN {
				p.next()
			}
		} else {
			// *T
			typ = p.parseQualifiedIdent(nil)
		}
		typ = &ast.StarExpr{Star: star, X: typ}

	case token.LPAREN:
		p.error(p.pos, "cannot parenthesize embedded type")
		p.next()
		if p.tok == token.MUL {
			// (*T)
			star := p.pos
			p.next()
			typ = &ast.StarExpr{Star: star, X: p.parseQualifiedIdent(nil)}
		} else {
			// (T)
			typ = p.parseQualifiedIdent(nil)
		}
		// expect closing ')' but no need to complain if missing
		if p.tok == token.RPAREN {
			p.next()
		}

	default:
		pos := p.pos
		p.errorExpected(pos, "field name or embedded type")
		p.advance(exprEnd)
		typ = &ast.BadExpr{From: pos, To: p.pos}
	}

	var tag *ast.BasicLit
	if p.tok == token.STRING {
		tag = &ast.BasicLit{ValuePos: p.pos, Kind: p.tok, Value: p.lit}
		p.next()
	}

	comment := p.expectSemi()

	field := &ast.Field{Doc: doc, Names: names, Type: typ, Tag: tag, Comment: comment}
	return field
}

func (p *parser) parseStructType() *ast.StructType {
	if p.trace {
		defer un(trace(p, "StructType"))
	}

	pos := p.expect(token.STRUCT)
	lbrace := p.expect(token.LBRACE)
	var list []*ast.Field
	for p.tok == token.IDENT || p.tok == token.MUL || p.tok == token.LPAREN {
		// a field declaration cannot start with a '(' but we accept
		// it here for more robust parsing and better error messages
		// (parseFieldDecl will check and complain if necessary)
		list = append(list, p.parseFieldDecl())
	}
	rbrace := p.expect(token.RBRACE)

	return &ast.StructType{
		Struct: pos,
		Fields: &ast.FieldList{
			Opening: lbrace,
			List:    list,
			Closing: rbrace,
		},
	}
}

func (p *parser) parsePointerType() *ast.StarExpr {
	if p.trace {
		defer un(trace(p, "PointerType"))
	}

	star := p.expect(token.MUL)
	base := p.parseType()

	return &ast.StarExpr{Star: star, X: base}
}

func (p *parser) parseDotsType() *ast.Ellipsis {
	if p.trace {
		defer un(trace(p, "DotsType"))
	}

	pos := p.expect(token.ELLIPSIS)
	elt := p.parseType()

	return &ast.Ellipsis{Ellipsis: pos, Elt: elt}
}

type field struct {
	name *ast.Ident
	typ  ast.Expr
}

func (p *parser) parseParamDecl(name *ast.Ident, typeSetsOK bool) (f field) {
	// TODO(rFindley) refactor to be more similar to paramDeclOrNil in the syntax
	// package
	if p.trace {
		defer un(trace(p, "ParamDecl"))
	}

	ptok := p.tok
	if name != nil {
		p.tok = token.IDENT // force token.IDENT case in switch below
	} else if typeSetsOK && p.tok == token.TILDE {
		// "~" ...
		return field{nil, p.embeddedElem(nil)}
	}

	switch p.tok {
	case token.IDENT:
		// name
		if name != nil {
			f.name = name
			p.tok = ptok
		} else {
			f.name = p.parseIdent()
		}
		switch p.tok {
		case token.IDENT, token.MUL, token.ARROW, token.FUNC, token.CHAN, token.MAP, token.STRUCT, token.INTERFACE, token.LPAREN:
			// name type
			f.typ = p.parseType()

		case token.LBRACK:
			// name "[" type1, ..., typeN "]" or name "[" n "]" type
			f.name, f.typ = p.parseArrayFieldOrTypeInstance(f.name)

		case token.ELLIPSIS:
			// name "..." type
			f.typ = p.parseDotsType()
			return // don't allow ...type "|" ...

		case token.PERIOD:
			// name "." ...
			f.typ = p.parseQualifiedIdent(f.name)
			f.name = nil

		case token.TILDE:
			if typeSetsOK {
				f.typ = p.embeddedElem(nil)
				return
			}

		case token.OR:
			if typeSetsOK {
				// name "|" typeset
				f.typ = p.embeddedElem(f.name)
				f.name = nil
				return
			}
		}

	case token.MUL, token.ARROW, token.FUNC, token.LBRACK, token.CHAN, token.MAP, token.STRUCT, token.INTERFACE, token.LPAREN:
		// type
		f.typ = p.parseType()

	case token.ELLIPSIS:
		// "..." type
		// (always accepted)
		f.typ = p.parseDotsType()
		return // don't allow ...type "|" ...

	default:
		// TODO(rfindley): this is incorrect in the case of type parameter lists
		//                 (should be "']'" in that case)
		p.errorExpected(p.pos, "')'")
		p.advance(exprEnd)
	}

	// [name] type "|"
	if typeSetsOK && p.tok == token.OR && f.typ != nil {
		f.typ = p.embeddedElem(f.typ)
	}

	return
}

func (p *parser) parseParameterList(name0 *ast.Ident, typ0 ast.Expr, closing token.Token) (params []*ast.Field) {
	if p.trace {
		defer un(trace(p, "ParameterList"))
	}

	// Type parameters are the only parameter list closed by ']'.
	tparams := closing == token.RBRACK

	pos0 := p.pos
	if name0 != nil {
		pos0 = name0.Pos()
	} else if typ0 != nil {
		pos0 = typ0.Pos()
	}

	// Note: The code below matches the corresponding code in the syntax
	//       parser closely. Changes must be reflected in either parser.
	//       For the code to match, we use the local []field list that
	//       corresponds to []syntax.Field. At the end, the list must be
	//       converted into an []*ast.Field.

	var list []field
	var named int // number of parameters that have an explicit name and type
	var typed int // number of parameters that have an explicit type

	for name0 != nil || p.tok != closing && p.tok != token.EOF {
		var par field
		if typ0 != nil {
			if tparams {
				typ0 = p.embeddedElem(typ0)
			}
			par = field{name0, typ0}
		} else {
			par = p.parseParamDecl(name0, tparams)
		}
		name0 = nil // 1st name was consumed if present
		typ0 = nil  // 1st typ was consumed if present
		if par.name != nil || par.typ != nil {
			list = append(list, par)
			if par.name != nil && par.typ != nil {
				named++
			}
			if par.typ != nil {
				typed++
			}
		}
		if !p.atComma("parameter list", closing) {
			break
		}
		p.next()
	}

	if len(list) == 0 {
		return // not uncommon
	}

	// distribute parameter types (len(list) > 0)
	if named == 0 {
		// all unnamed => found names are type names
		for i := 0; i < len(list); i++ {
			par := &list[i]
			if typ := par.name; typ != nil {
				par.typ = typ
				par.name = nil
			}
		}
		if tparams {
			// This is the same error handling as below, adjusted for type parameters only.
			// See comment below for details. (go.dev/issue/64534)
			var errPos token.Pos
			var msg string
			if named == typed /* same as typed == 0 */ {
				errPos = p.pos // position error at closing ]
				msg = "missing type constraint"
			} else {
				errPos = pos0 // position at opening [ or first name
				msg = "missing type parameter name"
				if len(list) == 1 {
					msg += " or invalid array length"
				}
			}
			p.error(errPos, msg)
		}
	} else if named != len(list) {
		// some named or we're in a type parameter list => all must be named
		var errPos token.Pos // left-most error position (or invalid)
		var typ ast.Expr     // current type (from right to left)
		for i := len(list) - 1; i >= 0; i-- {
			if par := &list[i]; par.typ != nil {
				typ = par.typ
				if par.name == nil {
					errPos = typ.Pos()
					n := ast.NewIdent("_")
					n.NamePos = errPos // correct position
					par.name = n
				}
			} else if typ != nil {
				par.typ = typ
			} else {
				// par.typ == nil && typ == nil => we only have a par.name
				errPos = par.name.Pos()
				par.typ = &ast.BadExpr{From: errPos, To: p.pos}
			}
		}
		if errPos.IsValid() {
			// Not all parameters are named because named != len(list).
			// If named == typed, there must be parameters that have no types.
			// They must be at the end of the parameter list, otherwise types
			// would have been filled in by the right-to-left sweep above and
			// there would be no error.
			// If tparams is set, the parameter list is a type parameter list.
			var msg string
			if named == typed {
				errPos = p.pos // position error at closing token ) or ]
				if tparams {
					msg = "missing type constraint"
				} else {
					msg = "missing parameter type"
				}
			} else {
				if tparams {
					msg = "missing type parameter name"
					// go.dev/issue/60812
					if len(list) == 1 {
						msg += " or invalid array length"
					}
				} else {
					msg = "missing parameter name"
				}
			}
			p.error(errPos, msg)
		}
	}

	// Convert list to []*ast.Field.
	// If list contains types only, each type gets its own ast.Field.
	if named == 0 {
		// parameter list consists of types only
		for _, par := range list {
			assert(par.typ != nil, "nil type in unnamed parameter list")
			params = append(params, &ast.Field{Type: par.typ})
		}
		return
	}

	// If the parameter list consists of named parameters with types,
	// collect all names with the same types into a single ast.Field.
	var names []*ast.Ident
	var typ ast.Expr
	addParams := func() {
		assert(typ != nil, "nil type in named parameter list")
		field := &ast.Field{Names: names, Type: typ}
		params = append(params, field)
		names = nil
	}
	for _, par := range list {
		if par.typ != typ {
			if len(names) > 0 {
				addParams()
			}
			typ = par.typ
		}
		names = append(names, par.name)
	}
	if len(names) > 0 {
		addParams()
	}
	return
}

func (p *parser) parseParameters(acceptTParams bool) (tparams, params *ast.FieldList) {
	if p.trace {
		defer un(trace(p, "Parameters"))
	}

	if acceptTParams && p.tok == token.LBRACK {
		opening := p.pos
		p.next()
		// [T any](params) syntax
		list := p.parseParameterList(nil, nil, token.RBRACK)
		rbrack := p.expect(token.RBRACK)
		tparams = &ast.FieldList{Opening: opening, List: list, Closing: rbrack}
		// Type parameter lists must not be empty.
		if tparams.NumFields() == 0 {
			p.error(tparams.Closing, "empty type parameter list")
			tparams = nil // avoid follow-on errors
		}
	}

	opening := p.expect(token.LPAREN)

	var fields []*ast.Field
	if p.tok != token.RPAREN {
		fields = p.parseParameterList(nil, nil, token.RPAREN)
	}

	rparen := p.expect(token.RPAREN)
	params = &ast.FieldList{Opening: opening, List: fields, Closing: rparen}

	return
}

func (p *parser) parseResult() *ast.FieldList {
	if p.trace {
		defer un(trace(p, "Result"))
	}

	if p.tok == token.LPAREN {
		_, results := p.parseParameters(false)
		return results
	}

	typ := p.tryIdentOrType()
	if typ != nil {
		list := make([]*ast.Field, 1)
		list[0] = &ast.Field{Type: typ}
		return &ast.FieldList{List: list}
	}

	return nil
}

func (p *parser) parseFuncType() *ast.FuncType {
	if p.trace {
		defer un(trace(p, "FuncType"))
	}

	pos := p.expect(token.FUNC)
	tparams, params := p.parseParameters(true)
	if tparams != nil {
		p.error(tparams.Pos(), "function type must have no type parameters")
	}
	results := p.parseResult()

	return &ast.FuncType{Func: pos, Params: params, Results: results}
}

func (p *parser) parseMethodSpec() *ast.Field {
	if p.trace {
		defer un(trace(p, "MethodSpec"))
	}

	doc := p.leadComment
	var idents []*ast.Ident
	var typ ast.Expr
	x := p.parseTypeName(nil)
	if ident, _ := x.(*ast.Ident); ident != nil {
		switch {
		case p.tok == token.LBRACK:
			// generic method or embedded instantiated type
			lbrack := p.pos
			p.next()
			p.exprLev++
			x := p.parseExpr()
			p.exprLev--
			if name0, _ := x.(*ast.Ident); name0 != nil && p.tok != token.COMMA && p.tok != token.RBRACK {
				// generic method m[T any]
				//
				// Interface methods do not have type parameters. We parse them for a
				// better error message and improved error recovery.
				_ = p.parseParameterList(name0, nil, token.RBRACK)
				_ = p.expect(token.RBRACK)
				p.error(lbrack, "interface method must have no type parameters")

				// TODO(rfindley) refactor to share code with parseFuncType.
				_, params := p.parseParameters(false)
				results := p.parseResult()
				idents = []*ast.Ident{ident}
				typ = &ast.FuncType{
					Func:    token.NoPos,
					Params:  params,
					Results: results,
				}
			} else {
				// embedded instantiated type
				// TODO(rfindley) should resolve all identifiers in x.
				list := []ast.Expr{x}
				if p.atComma("type argument list", token.RBRACK) {
					p.exprLev++
					p.next()
					for p.tok != token.RBRACK && p.tok != token.EOF {
						list = append(list, p.parseType())
						if !p.atComma("type argument list", token.RBRACK) {
							break
						}
						p.next()
					}
					p.exprLev--
				}
				rbrack := p.expectClosing(token.RBRACK, "type argument list")
				typ = packIndexExpr(ident, lbrack, list, rbrack)
			}
		case p.tok == token.LPAREN:
			// ordinary method
			// TODO(rfindley) refactor to share code with parseFuncType.
			_, params := p.parseParameters(false)
			results := p.parseResult()
			idents = []*ast.Ident{ident}
			typ = &ast.FuncType{Func: token.NoPos, Params: params, Results: results}
		default:
			// embedded type
			typ = x
		}
	} else {
		// embedded, possibly instantiated type
		typ = x
		if p.tok == token.LBRACK {
			// embedded instantiated interface
			typ = p.parseTypeInstance(typ)
		}
	}

	// Comment is added at the callsite: the field below may joined with
	// additional type specs using '|'.
	// TODO(rfindley) this should be refactored.
	// TODO(rfindley) add more tests for comment handling.
	return &ast.Field{Doc: doc, Names: idents, Type: typ}
}

func (p *parser) embeddedElem(x ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "EmbeddedElem"))
	}
	if x == nil {
		x = p.embeddedTerm()
	}
	for p.tok == token.OR {
		t := new(ast.BinaryExpr)
		t.OpPos = p.pos
		t.Op = token.OR
		p.next()
		t.X = x
		t.Y = p.embeddedTerm()
		x = t
	}
	return x
}

func (p *parser) embeddedTerm() ast.Expr {
	if p.trace {
		defer un(trace(p, "EmbeddedTerm"))
	}
	if p.tok == token.TILDE {
		t := new(ast.UnaryExpr)
		t.OpPos = p.pos
		t.Op = token.TILDE
		p.next()
		t.X = p.parseType()
		return t
	}

	t := p.tryIdentOrType()
	if t == nil {
		pos := p.pos
		p.errorExpected(pos, "~ term or type")
		p.advance(exprEnd)
		return &ast.BadExpr{From: pos, To: p.pos}
	}

	return t
}

func (p *parser) parseInterfaceType() *ast.InterfaceType {
	if p.trace {
		defer un(trace(p, "InterfaceType"))
	}

	pos := p.expect(token.INTERFACE)
	lbrace := p.expect(token.LBRACE)

	var list []*ast.Field

parseElements:
	for {
		switch {
		case p.tok == token.IDENT:
			f := p.parseMethodSpec()
			if f.Names == nil {
				f.Type = p.embeddedElem(f.Type)
			}
			f.Comment = p.expectSemi()
			list = append(list, f)
		case p.tok == token.TILDE:
			typ := p.embeddedElem(nil)
			comment := p.expectSemi()
			list = append(list, &ast.Field{Type: typ, Comment: comment})
		default:
			if t := p.tryIdentOrType(); t != nil {
				typ := p.embeddedElem(t)
				comment := p.expectSemi()
				list = append(list, &ast.Field{Type: typ, Comment: comment})
			} else {
				break parseElements
			}
		}
	}

	// TODO(rfindley): the error produced here could be improved, since we could
	// accept an identifier,
```