Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/github.com/rogpeppe/godef/go/parser/parser.go`.

I need to:
1. **Identify the core purpose** of this code.
2. **List the functions** and their roles.
3. If possible, **infer the broader Go feature** being implemented.
4. Provide a **Go code example** demonstrating this feature, if applicable.
5. Explain any **code reasoning** with input and output.
6. Detail the handling of any **command-line arguments**.
7. Point out any **common mistakes** users might make when using this code.
8. **Summarize** the functionality of this part of the code.

Based on the code:
- It's part of a Go parser.
- It defines a `parser` struct to hold the parser's state.
- It includes functions for initialization (`init`), scoping (`openScope`, `closeScope`, `openLabelScope`, `closeLabelScope`, `declare`, `declare1`, `redeclared`, `shortVarDecl`, `resolve`), and token handling (`next0`, `next`, `consumeComment`, `consumeCommentGroup`).
- It also has functions for parsing various Go language constructs like identifiers (`parseIdent`, `parseIdentList`), expressions (`parseExprList`), and types (`parseType`, `parseQualifiedIdent`, `parseTypeName`, `parseArrayType`, `parseFieldDecl`, `parseStructType`, `parsePointerType`, `parseVarType`, `parseVarList`, `parseParameterList`, `parseParameters`, `parseResult`, `parseSignature`, `parseFuncType`, `parseMethodSpec`, `parseInterfaceType`, `parseMapType`, `parseChanType`, `tryRawType`, `tryType`).
- It uses a `scanner` to tokenize the input source code.
- It builds an Abstract Syntax Tree (AST) using nodes from the `go/ast` package.

Therefore, this code is responsible for **taking Go source code as input and converting it into an Abstract Syntax Tree (AST)**.
这段代码是 Go 语言解析器的一部分，其主要功能是将 Go 源代码文本转换为抽象语法树（AST）。更具体地说，这段代码实现了词法分析之后的 **语法分析** 阶段，它负责识别源代码中的各种语法结构，例如：

**核心功能归纳：**

1. **初始化解析器状态:**  `init` 函数负责初始化 `parser` 结构体的内部状态，例如设置文件集、文件名、扫描器、作用域等。
2. **词法单元（Token）处理:**
    *   `next0`：从扫描器获取下一个词法单元。
    *   `next`：获取下一个非注释的词法单元，并处理行注释和块注释，区分前导注释和行尾注释。
    *   `consumeComment`, `consumeCommentGroup`：消耗并收集注释。
3. **错误处理:**  `error`, `errorExpected` 函数用于报告解析过程中遇到的语法错误。
4. **作用域管理:**
    *   `openScope`, `closeScope`：打开和关闭常规标识符作用域。
    *   `openLabelScope`, `closeLabelScope`：打开和关闭标签作用域，用于处理 `goto` 语句。
    *   `declare`, `declare1`：在当前作用域中声明标识符（变量、函数、类型等）。
    *   `redeclared`：报告标识符重复声明的错误。
    *   `shortVarDecl`：处理短变量声明（`:=`）。
    *   `resolve`：在当前作用域链中查找标识符的声明。
5. **语法结构解析:**  提供了一系列 `parse...` 函数，用于解析 Go 语言的各种语法结构：
    *   **标识符:** `parseIdent`, `parseIdentList`
    *   **表达式:** `parseExprList`
    *   **类型:** `parseType`, `parseQualifiedIdent`, `parseTypeName`, `parseArrayType`, `parseStructType`, `parsePointerType`, `parseFuncType`, `parseInterfaceType`, `parseMapType`, `parseChanType`
    *   **语句块:** `parseStmtList`, `parseBody`, `parseBlockStmt`
    *   **函数字面量:** `parseFuncTypeOrLit`
    *   **操作数:** `parseOperand`
    *   **选择器或类型断言:** `parseSelectorOrTypeAssertion`
    *   **索引或切片:** `parseIndexOrSlice`
    *   **函数调用或类型转换:** `parseCallOrConversion`
    *   **复合字面量:** `parseLiteralValue`, `parseElement`, `parseElementList`
    *   **一元表达式:** `parseUnaryExpr`
    *   **参数列表和结果:** `parseParameterList`, `parseParameters`, `parseResult`, `parseSignature`
    *   **字段声明:** `parseFieldDecl`
    *   **方法规范:** `parseMethodSpec`
6. **辅助函数:** 提供了一些辅助函数，例如 `scannerMode` 用于根据解析模式设置扫描器模式，`trace`, `un` 用于跟踪解析过程， `expect`, `expectSemi`, `atComma` 用于检查和消耗特定的词法单元。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 **语法解析器** 的核心部分，负责将词法分析器生成的词法单元流转换为表示程序结构的抽象语法树。这个 AST 是后续进行语义分析、类型检查、代码生成等步骤的基础。

**Go 代码举例说明：**

假设输入的 Go 源代码是：

```go
package main

import "fmt"

func add(a int, b int) int {
	return a + b
}

func main() {
	result := add(10, 5)
	fmt.Println(result)
}
```

这段代码会被 `parser.go` 中的函数处理，最终生成一个 `*ast.File` 类型的抽象语法树，表示整个 Go 源文件。这个 AST 会包含：

*   一个 `*ast.Package` 节点，表示包名 "main"。
*   一个 `*ast.ImportSpec` 节点，表示导入的包 "fmt"。
*   两个 `*ast.FuncDecl` 节点，分别表示函数 `add` 和 `main`。
*   函数 `add` 的 `*ast.FuncType` 节点会包含参数列表 (`a int`, `b int`) 和返回值类型 (`int`)。
*   函数 `main` 的 `*ast.BlockStmt` 节点会包含局部变量声明 (`result := ...`) 和函数调用语句 (`fmt.Println(...)`)。

**代码推理（假设输入与输出）：**

假设我们有一个非常简单的输入 `x + 1`。当解析器解析到这个表达式时，相关的 `parse...` 函数会被调用。

**假设输入:** 词法分析器返回的词法单元序列为：`IDENT("x")`, `ADD("+")`, `INT("1")`, `EOF`

**解析过程：**

1. `parseExpr()` 被调用。
2. `parseBinaryExpr()` 被调用（因为 `+` 是二元运算符）。
3. `parseUnaryExpr()` 被调用来解析左操作数 `x`。
4. `parsePrimaryExpr()` 被调用。
5. `parseOperand()` 被调用，识别出 `IDENT("x")`，并创建一个 `*ast.Ident` 节点。
6. 回到 `parseBinaryExpr()`，识别出运算符 `ADD("+")`。
7. `parseUnaryExpr()` 被调用来解析右操作数 `1`。
8. `parsePrimaryExpr()` 被调用。
9. `parseOperand()` 被调用，识别出 `INT("1")`，并创建一个 `*ast.BasicLit` 节点。
10. `parseBinaryExpr()` 创建一个 `*ast.BinaryExpr` 节点，其 `X` 字段指向 `*ast.Ident` (x)， `Op` 字段为 `token.ADD`， `Y` 字段指向 `*ast.BasicLit` (1)。

**假设输出:**  一个 `*ast.BinaryExpr` 节点，其结构大致如下：

```go
&ast.BinaryExpr{
	X: &ast.Ident{Name: "x"},
	OpPos: <position of +>,
	Op: token.ADD,
	Y: &ast.BasicLit{Kind: token.INT, Value: "1"},
}
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是一个库，被其他工具（例如 `go build`, `go fmt`, `godef` 等）调用。这些工具会负责解析命令行参数，并根据参数的设置来调用解析器。

**使用者易犯错的点：**

作为 `go/parser` 包的内部实现，直接使用这段代码的用户较少。但是，间接使用 `go/parser` 的开发者可能会遇到以下与解析相关的错误：

1. **不理解解析模式:** `Parse*` 函数接受一个 `mode` 参数，控制解析的深度和行为。例如，如果只想解析包声明，应该使用 `PackageClauseOnly` 模式。如果误用了模式，可能会导致解析不完整或得到意外的结果。

    ```go
    // 假设你只想获取包名
    package main

    import "fmt"

    func main() {
        fmt.Println("Hello")
    }
    ```

    如果使用 `parser.ParseFile(fset, filename, src, parser.PackageClauseOnly)`，解析器只会解析到 `package main`，而不会解析后面的导入和函数定义。

2. **忽略错误处理:**  解析函数会返回错误。使用者必须检查并处理这些错误，否则可能会基于不完整的或错误的 AST 进行后续操作。

    ```go
    fset := token.NewFileSet()
    file, err := parser.ParseFile(fset, "invalid.go", []byte("func main() {"), 0)
    if err != nil {
        fmt.Println("解析错误:", err) // 必须处理 err
        return
    }
    // ... 基于 file 进行后续操作
    ```

**这段代码（第 1 部分）的功能归纳:**

这段代码定义了 Go 语言解析器的核心结构和基础功能，包括解析器的初始化、词法单元的处理、错误报告、作用域管理以及各种基本语法结构的解析（如标识符、表达式、类型等）。它是将 Go 源代码转换为抽象语法树的关键组成部分，为后续的语义分析等阶段奠定了基础。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/go/parser/parser.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// A parser for Go source files. Input may be provided in a variety of
// forms (see the various Parse* functions); the output is an abstract
// syntax tree (AST) representing the Go source. The parser is invoked
// through one of the Parse* functions.
//
package parser

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rogpeppe/godef/go/ast"
	"github.com/rogpeppe/godef/go/scanner"
	"github.com/rogpeppe/godef/go/token"
)

// The mode parameter to the Parse* functions is a set of flags (or 0).
// They control the amount of source code parsed and other optional
// parser functionality.
//
const (
	PackageClauseOnly uint = 1 << iota // parsing stops after package clause
	ImportsOnly                        // parsing stops after import declarations
	ParseComments                      // parse comments and add them to AST
	Trace                              // print a trace of parsed productions
	DeclarationErrors                  // report declaration errors.
)

// The parser structure holds the parser's internal state.
type parser struct {
	fset *token.FileSet
	file *token.File
	scanner.ErrorVector
	scanner    scanner.Scanner
	pathToName ImportPathToName

	// Tracing/debugging
	mode   uint // parsing mode
	trace  bool // == (mode & Trace != 0)
	indent uint // indentation used for tracing output

	// Comments
	comments    []*ast.CommentGroup
	leadComment *ast.CommentGroup // last lead comment
	lineComment *ast.CommentGroup // last line comment

	// Next token
	pos token.Pos   // token position
	tok token.Token // one token look-ahead
	lit string      // token literal

	// Non-syntactic parser control
	exprLev int // < 0: in control clause, >= 0: in expression

	// Ordinary identifer scopes
	pkgScope  *ast.Scope // pkgScope.Outer == nil
	fileScope *ast.Scope // fileScope.Outer == pkgScope
	topScope  *ast.Scope // top-most scope; may be fileScope

	// Label scope
	// (maintained by open/close LabelScope)
	labelScope  *ast.Scope     // label scope for current function
	targetStack [][]*ast.Ident // stack of unresolved labels
}

// scannerMode returns the scanner mode bits given the parser's mode bits.
func scannerMode(mode uint) uint {
	var m uint = scanner.InsertSemis
	if mode&ParseComments != 0 {
		m |= scanner.ScanComments
	}
	return m
}

func (p *parser) init(fset *token.FileSet, filename string, src []byte, mode uint, topScope *ast.Scope, pathToName ImportPathToName) {
	p.fset = fset
	p.file = fset.AddFile(filename, fset.Base(), len(src))
	p.scanner.Init(p.file, src, p, scannerMode(mode))
	p.pathToName = pathToName
	if p.pathToName == nil {
		p.pathToName = naiveImportPathToName
	}

	p.mode = mode
	p.trace = mode&Trace != 0 // for convenience (p.trace is used frequently)

	p.next()

	p.topScope = topScope

	// for the same reason, set up a label scope
	p.openLabelScope()
}

func naiveImportPathToName(path, _ string) (string, error) {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[0:i]
	}
	return path, nil
}

// ----------------------------------------------------------------------------
// Scoping support

func (p *parser) openScope() {
	p.topScope = p.newScope(p.topScope)
}

func (p *parser) closeScope() {
	if p.topScope != nil {
		p.topScope = p.topScope.Outer
	}
}

func (p *parser) openLabelScope() {
	if p.topScope != nil {
		p.labelScope = ast.NewScope(p.labelScope)
		p.targetStack = append(p.targetStack, nil)
	}
}

func (p *parser) closeLabelScope() {
	if p.topScope == nil {
		return
	}
	// resolve labels
	n := len(p.targetStack) - 1
	scope := p.labelScope
	for _, ident := range p.targetStack[n] {
		ident.Obj = scope.Lookup(ident.Name)
		if ident.Obj == nil && p.mode&DeclarationErrors != 0 {
			p.error(ident.Pos(), fmt.Sprintf("label %s undefined", ident.Name))
		}
	}
	// pop label scope
	p.targetStack = p.targetStack[0:n]
	p.labelScope = p.labelScope.Outer
}

func (p *parser) declare(decl ast.Node, scope *ast.Scope, kind ast.ObjKind, idents ...*ast.Ident) {
	if scope == nil {
		return
	}
	for _, ident := range idents {
		if ident.Name != "_" {
			p.declare1(decl, scope, kind, ident)
		}
	}
}

func (p *parser) declare1(decl ast.Node, scope *ast.Scope, kind ast.ObjKind, ident *ast.Ident) {
	var obj *ast.Object
	if ident.Obj == nil {
		p.resolve(ident)
	}

	if scope == p.fileScope {
		scope = p.pkgScope
		switch kind {
		case ast.Fun:
			// methods get declared in the receiver's scope
			if d, ok := decl.(*ast.FuncDecl); ok && d.Recv != nil {
				var rt *ast.Object
				switch t := d.Recv.List[0].Type.(type) {
				case *ast.Ident:
					rt = t.Obj
				case *ast.StarExpr:
					rt = t.X.(*ast.Ident).Obj
				case *ast.BadExpr:
					// Partially typed code can get here.
					return
				default:
					panic(fmt.Errorf("unknown type %T (%#v)", t, t))
				}
				if rt.Type == nil {
					rt.Type = p.newScope(nil)
				}
				scope = rt.Type.(*ast.Scope)
			}
		case ast.Pkg:
			// Packages get declared in file scope
			// and also tagged in package scope.
			prev := scope.Lookup(ident.Name)
			if prev != nil {
				switch prev.Kind {
				case ast.Bad:
					// tag identifier in package scope.
					prev.Kind = ast.Pkg
					fallthrough

				case ast.Pkg:
					// redeclaring a package is ok.
					scope = p.fileScope

				default:
					p.redeclared(ident, ident.Obj, "as package")
					return
				}
			}
		default:
			// other globals get declared at package scope
			if ident.Obj != nil && ident.Obj.Kind == ast.Pkg {
				p.redeclared(ident, ident.Obj, "as variable")
				return
			}
		}
		if scope == p.pkgScope && ident.Obj.Kind == ast.Bad {
			// resolve forward reference.
			ident.Obj.Kind = kind
			ident.Obj.Name = ident.Name
			ident.Obj.Decl = decl
			return
		}
	}

	//fmt.Printf("declaring %s kind %d in scope %p (fileScope %p, pkgScope %p)\n", ident.Value, kind, scope, p.fileScope, p.pkgScope)

	if obj == nil {
		obj = ast.NewObj(kind, ident.Name)
		obj.Decl = decl
	}
	ident.Obj = obj
	alt := scope.Insert(obj)
	if alt != nil {
		p.redeclared(ident, alt, "")
	}
}

func (p *parser) redeclared(ident *ast.Ident, prev *ast.Object, reason string) {
	if p.mode&DeclarationErrors == 0 {
		return
	}
	prevDecl := ""
	if pos := prev.Pos(); pos.IsValid() {
		prevDecl = fmt.Sprintf("\n\tprevious declaration at %s", p.fset.Position(pos))
	} else {
		prevDecl = fmt.Sprintf("\n\tprevious declaration as %s", prev.Kind)
	}
	p.error(ident.Pos(), fmt.Sprintf("%s redeclared%s in this block%s", ident.Name, reason, prevDecl))
}

func (p *parser) shortVarDecl(idents []*ast.Ident, stmt *ast.AssignStmt) {
	if p.topScope == nil {
		return
	}
	// Go spec: A short variable declaration may redeclare variables
	// provided they were originally declared in the same block with
	// the same type, and at least one of the non-blank variables is new.
	n := 0 // number of new variables
	for _, ident := range idents {
		if ident.Name == "_" {
			continue
		}
		obj := ast.NewObj(ast.Var, ident.Name)
		obj.Decl = stmt
		alt := p.topScope.Insert(obj)
		if alt != nil {
			obj = alt
		} else {
			n++ // new declaration
		}
		ident.Obj = obj
	}
	if n == 0 && p.mode&DeclarationErrors != 0 {
		p.error(idents[0].Pos(), "no new variables on left side of :=")
	}
}

// newIdent returns a new identifier with attached Object.
// If no Object currently exists for the identifier, it is
// created in package scope.
func (p *parser) resolve(ident *ast.Ident) {
	if ident.Name == "_" {
		return
	}
	// try to resolve the identifier
	for s := p.topScope; s != nil; s = s.Outer {
		if obj := s.Lookup(ident.Name); obj != nil {
			ident.Obj = obj
			return
		}
	}
	if p.pkgScope == nil {
		return
	}
	ident.Obj = ast.NewObj(ast.Bad, ident.Name)
	p.pkgScope.Insert(ident.Obj)
}

// ----------------------------------------------------------------------------
// Parsing support

func (p *parser) printTrace(a ...interface{}) {
	const dots = ". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . " +
		". . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . "
	const n = uint(len(dots))
	pos := p.file.Position(p.pos)
	fmt.Printf("%5d:%3d: ", pos.Line, pos.Column)
	i := 2 * p.indent
	for ; i > n; i -= n {
		fmt.Print(dots)
	}
	fmt.Print(dots[0:i])
	fmt.Println(a...)
}

func trace(p *parser, msg string) *parser {
	p.printTrace(msg, "(")
	p.indent++
	return p
}

// Usage pattern: defer un(trace(p, "..."));
func un(p *parser) {
	p.indent--
	p.printTrace(")")
}

// Advance to the next token.
func (p *parser) next0() {
	// Because of one-token look-ahead, print the previous token
	// when tracing as it provides a more readable output. The
	// very first token (!p.pos.IsValid()) is not initialized
	// (it is token.ILLEGAL), so don't print it .
	if p.trace && p.pos.IsValid() {
		s := p.tok.String()
		switch {
		case p.tok.IsLiteral():
			p.printTrace(s, string(p.lit))
		case p.tok.IsOperator(), p.tok.IsKeyword():
			p.printTrace("\"" + s + "\"")
		default:
			p.printTrace(s)
		}
	}

	p.pos, p.tok, p.lit = p.scanner.Scan()
}

// Consume a comment and return it and the line on which it ends.
func (p *parser) consumeComment() (comment *ast.Comment, endline int) {
	// /*-style comments may end on a different line than where they start.
	// Scan the comment for '\n' chars and adjust endline accordingly.
	endline = p.file.Line(p.pos)
	if p.lit[1] == '*' {
		for _, b := range p.lit {
			if b == '\n' {
				endline++
			}
		}
	}

	comment = &ast.Comment{p.pos, p.lit}
	p.next0()

	return
}

// Consume a group of adjacent comments, add it to the parser's
// comments list, and return it together with the line at which
// the last comment in the group ends. An empty line or non-comment
// token terminates a comment group.
//
func (p *parser) consumeCommentGroup() (comments *ast.CommentGroup, endline int) {
	var list []*ast.Comment
	endline = p.file.Line(p.pos)
	for p.tok == token.COMMENT && endline+1 >= p.file.Line(p.pos) {
		var comment *ast.Comment
		comment, endline = p.consumeComment()
		list = append(list, comment)
	}

	// add comment group to the comments list
	comments = &ast.CommentGroup{list}
	p.comments = append(p.comments, comments)

	return
}

// Advance to the next non-comment token. In the process, collect
// any comment groups encountered, and remember the last lead and
// and line comments.
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
//
func (p *parser) next() {
	p.leadComment = nil
	p.lineComment = nil
	line := p.file.Line(p.pos) // current line
	p.next0()

	if p.tok == token.COMMENT {
		var comment *ast.CommentGroup
		var endline int

		if p.file.Line(p.pos) == line {
			// The comment is on same line as previous token; it
			// cannot be a lead comment but may be a line comment.
			comment, endline = p.consumeCommentGroup()
			if p.file.Line(p.pos) != endline {
				// The next token is on a different line, thus
				// the last comment group is a line comment.
				p.lineComment = comment
			}
		}

		// consume successor comments, if any
		endline = -1
		for p.tok == token.COMMENT {
			comment, endline = p.consumeCommentGroup()
		}

		if endline+1 == p.file.Line(p.pos) {
			// The next token is following on the line immediately after the
			// comment group, thus the last comment group is a lead comment.
			p.leadComment = comment
		}
	}
}

func (p *parser) error(pos token.Pos, msg string) {
	p.Error(p.file.Position(pos), msg)
}

func (p *parser) errorExpected(pos token.Pos, msg string) {
	msg = "expected " + msg
	if pos == p.pos {
		// the error happened at the current position;
		// make the error message more specific
		if p.tok == token.SEMICOLON && p.lit[0] == '\n' {
			msg += ", found newline"
		} else {
			msg += ", found '" + p.tok.String() + "'"
			if p.tok.IsLiteral() {
				msg += " " + string(p.lit)
			}
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

func (p *parser) expectSemi() {
	if p.tok != token.RPAREN && p.tok != token.RBRACE {
		p.expect(token.SEMICOLON)
	}
}

func (p *parser) atComma(context string) bool {
	if p.tok == token.COMMA {
		return true
	}
	if p.tok == token.SEMICOLON && p.lit == "\n" {
		p.error(p.pos, "missing ',' before newline in "+context)
		return true // "insert" the comma and continue

	}
	return false
}

// ----------------------------------------------------------------------------
// Identifiers

func (p *parser) parseIdent() *ast.Ident {
	pos := p.pos
	name := "_"
	if p.tok == token.IDENT {
		name = string(p.lit)
		p.next()
	} else {
		p.expect(token.IDENT) // use expect() error handling
	}
	return &ast.Ident{pos, name, nil}
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

// ----------------------------------------------------------------------------
// Types

func (p *parser) parseType() ast.Expr {
	if p.trace {
		defer un(trace(p, "Type"))
	}

	typ := p.tryType()

	if typ == nil {
		pos := p.pos
		p.errorExpected(pos, "type")
		p.next() // make progress
		return &ast.BadExpr{pos, p.pos}
	}

	return typ
}

func (p *parser) parseQualifiedIdent() ast.Expr {
	if p.trace {
		defer un(trace(p, "QualifiedIdent"))
	}

	ident := p.parseIdent()
	p.resolve(ident)
	var x ast.Expr = ident
	if p.tok == token.PERIOD {
		// first identifier is a package identifier
		p.next()
		sel := p.parseIdent()
		x = &ast.SelectorExpr{x, sel}
	}

	return x
}

func (p *parser) parseTypeName() ast.Expr {
	if p.trace {
		defer un(trace(p, "TypeName"))
	}

	return p.parseQualifiedIdent()
}

func (p *parser) parseArrayType(ellipsisOk bool) ast.Expr {
	if p.trace {
		defer un(trace(p, "ArrayType"))
	}

	lbrack := p.expect(token.LBRACK)
	var len ast.Expr
	if ellipsisOk && p.tok == token.ELLIPSIS {
		len = &ast.Ellipsis{p.pos, nil}
		p.next()
	} else if p.tok != token.RBRACK {
		len = p.parseExpr()
	}
	p.expect(token.RBRACK)
	elt := p.parseType()

	return &ast.ArrayType{lbrack, len, elt}
}

func (p *parser) makeIdentList(list []ast.Expr) []*ast.Ident {
	idents := make([]*ast.Ident, len(list))
	for i, x := range list {
		ident, isIdent := x.(*ast.Ident)
		if !isIdent {
			pos := x.(ast.Expr).Pos()
			p.errorExpected(pos, "identifier")
			ident = &ast.Ident{pos, "_", nil}
		}
		idents[i] = ident
	}
	return idents
}

func (p *parser) parseFieldDecl() *ast.Field {
	if p.trace {
		defer un(trace(p, "FieldDecl"))
	}

	doc := p.leadComment

	// fields
	list, typ := p.parseVarList(false)

	// optional tag
	var tag *ast.BasicLit
	if p.tok == token.STRING {
		tag = &ast.BasicLit{p.pos, p.tok, p.lit}
		p.next()
	}

	f := &ast.Field{doc, nil, typ, tag, p.lineComment}
	// analyze case
	if typ != nil {
		// IdentifierList Type
		f.Names = p.makeIdentList(list)
		if p.topScope != nil {
			for _, id := range f.Names {
				id.Obj = ast.NewObj(ast.Var, id.Name)
				id.Obj.Decl = f
			}
		}
	} else {
		// ["*"] TypeName (AnonymousField)
		f.Type = list[0] // we always have at least one element
		if n := len(list); n > 1 || !isTypeName(deref(f.Type)) {
			pos := f.Type.Pos()
			p.errorExpected(pos, "anonymous field")
			f.Type = &ast.BadExpr{pos, list[n-1].End()}
		}
		if p.topScope != nil {
			f.Type = makeAnonField(f.Type, f.Type)
		}
	}

	p.expectSemi() // call before accessing p.linecomment
	return f
}

// The object for the identifier in an anonymous
// field must point to the original type because
// the object has its own identity as a field member.
//
func makeAnonField(t, declType ast.Expr) ast.Expr {
	switch t := t.(type) {
	case *ast.Ident:
		id := new(ast.Ident)
		*id = *t
		id.Obj = ast.NewObj(ast.Var, id.Name)
		id.Obj.Decl = &ast.Field{nil, []*ast.Ident{id}, declType, nil, nil}
		return id

	case *ast.SelectorExpr:
		return &ast.SelectorExpr{t.X, makeAnonField(t.Sel, declType).(*ast.Ident)}

	case *ast.StarExpr:
		return &ast.StarExpr{t.Star, makeAnonField(t.X, declType)}
	}
	return t
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

	return &ast.StructType{pos, &ast.FieldList{lbrace, list, rbrace}, false}
}

func (p *parser) parsePointerType() *ast.StarExpr {
	if p.trace {
		defer un(trace(p, "PointerType"))
	}

	star := p.expect(token.MUL)
	base := p.parseType()

	return &ast.StarExpr{star, base}
}

func (p *parser) tryVarType(isParam bool) ast.Expr {
	if isParam && p.tok == token.ELLIPSIS {
		pos := p.pos
		p.next()
		typ := p.tryType() // don't use parseType so we can provide better error message
		if typ == nil {
			p.error(pos, "'...' parameter is missing type")
			typ = &ast.BadExpr{pos, p.pos}
		}
		return &ast.Ellipsis{pos, typ}
	}
	return p.tryType()
}

func (p *parser) parseVarType(isParam bool) ast.Expr {
	typ := p.tryVarType(isParam)
	if typ == nil {
		pos := p.pos
		p.errorExpected(pos, "type")
		p.next() // make progress
		typ = &ast.BadExpr{pos, p.pos}
	}
	return typ
}

func (p *parser) parseVarList(isParam bool) (list []ast.Expr, typ ast.Expr) {
	if p.trace {
		defer un(trace(p, "VarList"))
	}

	// a list of identifiers looks like a list of type names
	//
	// parse/tryVarType accepts any type (including parenthesized
	// ones) even though the syntax does not permit them here: we
	// accept them all for more robust parsing and complain later
	for typ := p.parseVarType(isParam); typ != nil; {
		list = append(list, typ)
		if p.tok != token.COMMA {
			break
		}
		p.next()
		typ = p.tryVarType(isParam) // maybe nil as in: func f(int,) {}
	}

	// if we had a list of identifiers, it must be followed by a type
	typ = p.tryVarType(isParam)

	return
}

func (p *parser) parseParameterList(scope *ast.Scope, ellipsisOk bool) (params []*ast.Field) {
	if p.trace {
		defer un(trace(p, "ParameterList"))
	}

	list, typ := p.parseVarList(ellipsisOk)
	if typ != nil {
		// IdentifierList Type
		idents := p.makeIdentList(list)
		field := &ast.Field{nil, idents, typ, nil, nil}
		params = append(params, field)
		// Go spec: The scope of an identifier denoting a function
		// parameter or result variable is the function body.
		p.declare(field, scope, ast.Var, idents...)
		if p.tok == token.COMMA {
			p.next()
		}
		for p.tok != token.RPAREN && p.tok != token.EOF {
			idents := p.parseIdentList()
			typ := p.parseVarType(ellipsisOk)
			field := &ast.Field{nil, idents, typ, nil, nil}
			params = append(params, field)
			// Go spec: The scope of an identifier denoting a function
			// parameter or result variable is the function body.
			p.declare(field, scope, ast.Var, idents...)
			if !p.atComma("parameter list") {
				break
			}
			p.next()
		}

	} else {
		// Type { "," Type } (anonymous parameters)
		params = make([]*ast.Field, len(list))
		for i, x := range list {
			params[i] = &ast.Field{Type: x}
		}
	}

	return
}

func (p *parser) parseParameters(scope *ast.Scope, ellipsisOk bool) *ast.FieldList {
	if p.trace {
		defer un(trace(p, "Parameters"))
	}

	var params []*ast.Field
	lparen := p.expect(token.LPAREN)
	if p.tok != token.RPAREN {
		params = p.parseParameterList(scope, ellipsisOk)
	}
	rparen := p.expect(token.RPAREN)

	return &ast.FieldList{lparen, params, rparen}
}

func (p *parser) parseResult(scope *ast.Scope) *ast.FieldList {
	if p.trace {
		defer un(trace(p, "Result"))
	}

	if p.tok == token.LPAREN {
		return p.parseParameters(scope, false)
	}

	typ := p.tryType()
	if typ != nil {
		list := make([]*ast.Field, 1)
		list[0] = &ast.Field{Type: typ}
		return &ast.FieldList{List: list}
	}

	return nil
}

func (p *parser) parseSignature(scope *ast.Scope) (params, results *ast.FieldList) {
	if p.trace {
		defer un(trace(p, "Signature"))
	}

	params = p.parseParameters(scope, true)
	results = p.parseResult(scope)

	return
}

func (p *parser) parseFuncType() (*ast.FuncType, *ast.Scope) {
	if p.trace {
		defer un(trace(p, "FuncType"))
	}

	pos := p.expect(token.FUNC)
	scope := p.newScope(p.topScope) // function scope
	params, results := p.parseSignature(scope)

	return &ast.FuncType{pos, params, results}, scope
}

func (p *parser) parseMethodSpec() *ast.Field {
	if p.trace {
		defer un(trace(p, "MethodSpec"))
	}

	f := &ast.Field{}
	f.Doc = p.leadComment
	x := p.parseQualifiedIdent()
	if ident, isIdent := x.(*ast.Ident); isIdent && p.tok == token.LPAREN {
		// method
		f.Names = []*ast.Ident{ident}
		ident.Obj = ast.NewObj(ast.Fun, ident.Name)
		ident.Obj.Decl = f

		scope := p.newScope(nil) // method scope
		params, results := p.parseSignature(scope)
		f.Type = &ast.FuncType{token.NoPos, params, results}
	} else {
		// embedded interface
		f.Type = x
	}
	p.expectSemi() // call before accessing p.linecomment

	f.Comment = p.lineComment
	return f
}

func (p *parser) parseInterfaceType() *ast.InterfaceType {
	if p.trace {
		defer un(trace(p, "InterfaceType"))
	}

	pos := p.expect(token.INTERFACE)
	lbrace := p.expect(token.LBRACE)
	var list []*ast.Field
	for p.tok == token.IDENT {
		list = append(list, p.parseMethodSpec())
	}
	rbrace := p.expect(token.RBRACE)

	return &ast.InterfaceType{pos, &ast.FieldList{lbrace, list, rbrace}, false}
}

func (p *parser) parseMapType() *ast.MapType {
	if p.trace {
		defer un(trace(p, "MapType"))
	}

	pos := p.expect(token.MAP)
	p.expect(token.LBRACK)
	key := p.parseType()
	p.expect(token.RBRACK)
	value := p.parseType()

	return &ast.MapType{pos, key, value}
}

func (p *parser) parseChanType() *ast.ChanType {
	if p.trace {
		defer un(trace(p, "ChanType"))
	}

	pos := p.pos
	dir := ast.SEND | ast.RECV
	if p.tok == token.CHAN {
		p.next()
		if p.tok == token.ARROW {
			p.next()
			dir = ast.SEND
		}
	} else {
		p.expect(token.ARROW)
		p.expect(token.CHAN)
		dir = ast.RECV
	}
	value := p.parseType()

	return &ast.ChanType{pos, dir, value}
}

func (p *parser) tryRawType(ellipsisOk bool) ast.Expr {
	switch p.tok {
	case token.IDENT:
		return p.parseTypeName()
	case token.LBRACK:
		return p.parseArrayType(ellipsisOk)
	case token.STRUCT:
		return p.parseStructType()
	case token.MUL:
		return p.parsePointerType()
	case token.FUNC:
		typ, _ := p.parseFuncType()
		return typ
	case token.INTERFACE:
		return p.parseInterfaceType()
	case token.MAP:
		return p.parseMapType()
	case token.CHAN, token.ARROW:
		return p.parseChanType()
	case token.LPAREN:
		lparen := p.pos
		p.next()
		typ := p.parseType()
		rparen := p.expect(token.RPAREN)
		return &ast.ParenExpr{Lparen: lparen, X: typ, Rparen: rparen}
	}

	// no type found
	return nil
}

func (p *parser) tryType() ast.Expr { return p.tryRawType(false) }

// ----------------------------------------------------------------------------
// Blocks

func (p *parser) parseStmtList() (list []ast.Stmt) {
	if p.trace {
		defer un(trace(p, "StatementList"))
	}

	for p.tok != token.CASE && p.tok != token.DEFAULT && p.tok != token.RBRACE && p.tok != token.EOF {
		list = append(list, p.parseStmt())
	}

	return
}

func (p *parser) parseBody(scope *ast.Scope) *ast.BlockStmt {
	if p.trace {
		defer un(trace(p, "Body"))
	}

	lbrace := p.expect(token.LBRACE)
	p.topScope = scope // open function scope
	p.openLabelScope()
	list := p.parseStmtList()
	p.closeLabelScope()
	p.closeScope()
	rbrace := p.expect(token.RBRACE)

	return &ast.BlockStmt{lbrace, list, rbrace}
}

func (p *parser) parseBlockStmt() *ast.BlockStmt {
	if p.trace {
		defer un(trace(p, "BlockStmt"))
	}

	lbrace := p.expect(token.LBRACE)
	p.openScope()
	list := p.parseStmtList()
	p.closeScope()
	rbrace := p.expect(token.RBRACE)

	return &ast.BlockStmt{lbrace, list, rbrace}
}

// ----------------------------------------------------------------------------
// Expressions

func (p *parser) parseFuncTypeOrLit() ast.Expr {
	if p.trace {
		defer un(trace(p, "FuncTypeOrLit"))
	}

	typ, scope := p.parseFuncType()
	if p.tok != token.LBRACE {
		// function type only
		return typ
	}

	p.exprLev++
	body := p.parseBody(scope)
	p.exprLev--

	return &ast.FuncLit{typ, body}
}

// parseOperand may return an expression or a raw type (incl. array
// types of the form [...]T. Callers must verify the result.
//
func (p *parser) parseOperand() ast.Expr {
	if p.trace {
		defer un(trace(p, "Operand"))
	}

	switch p.tok {
	case token.IDENT:
		ident := p.parseIdent()
		p.resolve(ident)
		return ident

	case token.INT, token.FLOAT, token.IMAG, token.CHAR, token.STRING:
		x := &ast.BasicLit{p.pos, p.tok, p.lit}
		p.next()
		return x

	case token.LPAREN:
		lparen := p.pos
		p.next()
		p.exprLev++
		x := p.parseExpr()
		p.exprLev--
		rparen := p.expect(token.RPAREN)
		return &ast.ParenExpr{lparen, x, rparen}

	case token.FUNC:
		return p.parseFuncTypeOrLit()

	default:
		t := p.tryRawType(true) // could be type for composite literal or conversion
		if t != nil {
			return t
		}
	}

	pos := p.pos
	p.errorExpected(pos, "operand")
	p.next() // make progress
	return &ast.BadExpr{pos, p.pos}
}

func (p *parser) parseSelectorOrTypeAssertion(x ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "SelectorOrTypeAssertion"))
	}

	p.expect(token.PERIOD)
	if p.tok == token.IDENT {
		// selector
		sel := p.parseIdent()
		return &ast.SelectorExpr{x, sel}
	}

	// type assertion
	p.expect(token.LPAREN)
	var typ ast.Expr
	if p.tok == token.TYPE {
		// type switch: typ == nil
		p.next()
	} else {
		typ = p.parseType()
	}
	p.expect(token.RPAREN)

	return &ast.TypeAssertExpr{x, typ}
}

func (p *parser) parseIndexOrSlice(x ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "IndexOrSlice"))
	}

	lbrack := p.expect(token.LBRACK)
	p.exprLev++
	var index [3]ast.Expr // change the 3 to 2 to disable slice expressions w/ cap
	if p.tok != token.COLON {
		index[0] = p.parseExpr()
	}
	ncolons := 0
	for p.tok == token.COLON && ncolons < len(index)-1 {
		p.next()
		ncolons++
		if p.tok != token.COLON && p.tok != token.RBRACK && p.tok != token.EOF {
			index[ncolons] = p.parseExpr()
		}
	}
	p.exprLev--
	rbrack := p.expect(token.RBRACK)

	if ncolons > 0 {
		// slice expression
		return &ast.SliceExpr{X: x, Lbrack: lbrack, Low: index[0], High: index[1], Max: index[2], Slice3: ncolons == 2, Rbrack: rbrack}
	}

	return &ast.IndexExpr{X: x, Lbrack: lbrack, Index: index[0], Rbrack: rbrack}
}

func (p *parser) parseCallOrConversion(fun ast.Expr) *ast.CallExpr {
	if p.trace {
		defer un(trace(p, "CallOrConversion"))
	}

	lparen := p.expect(token.LPAREN)
	p.exprLev++
	var list []ast.Expr
	var ellipsis token.Pos
	for p.tok != token.RPAREN && p.tok != token.EOF && !ellipsis.IsValid() {
		list = append(list, p.parseExpr())
		if p.tok == token.ELLIPSIS {
			ellipsis = p.pos
			p.next()
		}
		if !p.atComma("argument list") {
			break
		}
		p.next()
	}
	p.exprLev--
	rparen := p.expect(token.RPAREN)

	return &ast.CallExpr{fun, lparen, list, ellipsis, rparen}
}

func (p *parser) parseElement(keyOk bool) ast.Expr {
	if p.trace {
		defer un(trace(p, "Element"))
	}

	if p.tok == token.LBRACE {
		return p.parseLiteralValue(nil)
	}

	x := p.parseExpr()
	if keyOk && p.tok == token.COLON {
		colon := p.pos
		p.next()
		x = &ast.KeyValueExpr{x, colon, p.parseElement(false)}
	}
	return x
}

func (p *parser) parseElementList() (list []ast.Expr) {
	if p.trace {
		defer un(trace(p, "ElementList"))
	}

	for p.tok != token.RBRACE && p.tok != token.EOF {
		list = append(list, p.parseElement(true))
		if !p.atComma("composite literal") {
			break
		}
		p.next()
	}

	return
}

func (p *parser) parseLiteralValue(typ ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "LiteralValue"))
	}

	lbrace := p.expect(token.LBRACE)
	var elts []ast.Expr
	p.exprLev++
	if p.tok != token.RBRACE {
		elts = p.parseElementList()
	}
	p.exprLev--
	rbrace := p.expect(token.RBRACE)
	return &ast.CompositeLit{typ, lbrace, elts, rbrace}
}

// checkExpr checks that x is an expression (and not a type).
func (p *parser) checkExpr(x ast.Expr) ast.Expr {
	switch t := unparen(x).(type) {
	case *ast.BadExpr:
	case *ast.Ident:
	case *ast.BasicLit:
	case *ast.FuncLit:
	case *ast.CompositeLit:
	case *ast.ParenExpr:
		panic("unreachable")
	case *ast.SelectorExpr:
	case *ast.IndexExpr:
	case *ast.SliceExpr:
	case *ast.TypeAssertExpr:
		if t.Type == nil {
			// the form X.(type) is only allowed in type switch expressions
			p.errorExpected(x.Pos(), "expression")
			x = &ast.BadExpr{x.Pos(), x.End()}
		}
	case *ast.CallExpr:
	case *ast.StarExpr:
	case *ast.UnaryExpr:
		if t.Op == token.RANGE {
			// the range operator is only allowed at the top of a for statement
			p.errorExpected(x.Pos(), "expression")
			x = &ast.BadExpr{x.Pos(), x.End()}
		}
	case *ast.BinaryExpr:
	default:
		// all other nodes are not proper expressions
		p.errorExpected(x.Pos(), "expression")
		x = &ast.BadExpr{x.Pos(), x.End()}
	}
	return x
}

// isTypeName returns true iff x is a (qualified) TypeName.
func isTypeName(x ast.Expr) bool {
	switch t := x.(type) {
	case *ast.BadExpr:
	case *ast.Ident:
	case *ast.SelectorExpr:
		_, isIdent := t.X.(*ast.Ident)
		return isIdent
	default:
		return false // all other nodes are not type names
	}
	return true
}

// isLiteralType returns true iff x is a legal composite literal type.
func isLiteralType(x ast.Expr) bool {
	switch t := x.(type) {
	case *ast.BadExpr:
	case *ast.Ident:
	case *ast.SelectorExpr:
		_, isIdent := t.X.(*ast.Ident)
		return isIdent
	case *ast.ArrayType:
	case *ast.StructType:
	case *ast.MapType:
	default:
		return false // all other nodes are not legal composite literal types
	}
	return true
}

// If x is of the form *T, deref returns T, otherwise it returns x.
func deref(x ast.Expr) ast.Expr {
	if p, isPtr := x.(*ast.StarExpr); isPtr {
		x = p.X
	}
	return x
}

// If x is of the form (T), unparen returns unparen(T), otherwise it returns x.
func unparen(x ast.Expr) ast.Expr {
	if p, isParen := x.(*ast.ParenExpr); isParen {
		x = unparen(p.X)
	}
	return x
}

// checkExprOrType checks that x is an expression or a type
// (and not a raw type such as [...]T).
//
func (p *parser) checkExprOrType(x ast.Expr) ast.Expr {
	switch t := unparen(x).(type) {
	case *ast.ParenExpr:
		panic("unreachable")
	case *ast.UnaryExpr:
		if t.Op == token.RANGE {
			// the range operator is only allowed at the top of a for statement
			p.errorExpected(x.Pos(), "expression")
			x = &ast.BadExpr{x.Pos(), x.End()}
		}
	case *ast.ArrayType:
		if len, isEllipsis := t.Len.(*ast.Ellipsis); isEllipsis {
			p.error(len.Pos(), "expected array length, found '...'")
			x = &ast.BadExpr{x.Pos(), x.End()}
		}
	}

	// all other nodes are expressions or types
	return x
}

func (p *parser) parsePrimaryExpr() ast.Expr {
	if p.trace {
		defer un(trace(p, "PrimaryExpr"))
	}

	x := p.parseOperand()
L:
	for {
		switch p.tok {
		case token.PERIOD:
			x = p.parseSelectorOrTypeAssertion(p.checkExpr(x))
		case token.LBRACK:
			x = p.parseIndexOrSlice(p.checkExpr(x))
		case token.LPAREN:
			x = p.parseCallOrConversion(p.checkExprOrType(x))
		case token.LBRACE:
			if isLiteralType(x) && (p.exprLev >= 0 || !isTypeName(x)) {
				x = p.parseLiteralValue(x)
			} else {
				break L
			}
		default:
			break L
		}
	}

	return x
}

func (p *parser) parseUnaryExpr() ast.Expr {
	if p.trace {
		defer un(trace(p, "UnaryExpr"))
	}

	switch p.tok {
	case token.ADD, token.SUB, token.NOT, token.XOR, token.AND, token.RANGE:
		pos, op := p.pos, p.tok
		p.next()
		x := p.parseUnaryExpr()
		return &ast.UnaryExpr{pos, op, p.checkExpr(x)}

	case token.ARROW:
		// channel type or receive expression
		pos := p.pos
		p.next()
		if p.tok == token.CHAN {
			p.next()
			value := p.parseType()
			return &ast.ChanType{pos, ast.RECV, value}
	
"""




```