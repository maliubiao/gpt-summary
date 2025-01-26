Response:
The user is providing a snippet of Go code from `go/src/github.com/rogpeppe/godef/go/printer/nodes.go` and wants to understand its functionality.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The comment at the beginning of the file clearly states that it's responsible for "printing of AST nodes". This immediately tells us the primary function: taking an Abstract Syntax Tree (AST) representation of Go code and converting it back into a formatted string.

2. **Examine the package and imports:** The `package printer` confirms the core responsibility. The imports (`bytes`, `github.com/rogpeppe/godef/go/ast`, `github.com/rogpeppe/godef/go/token`) reveal the dependencies:
    * `bytes`: Likely used for efficient string building.
    * `ast`:  Crucial, as this package defines the structure of the Go AST nodes that this code manipulates.
    * `token`:  Provides information about the lexical tokens in the Go code, like keywords, operators, and punctuation, which are necessary for accurate formatting.

3. **Analyze key functions:**  Skimming through the code reveals several important functions:
    * `linebreak`: Handles the insertion of newlines based on source code layout.
    * `setComment`: Manages the placement of comments.
    * `identList`, `exprList`: Format lists of identifiers and expressions, respectively. These are building blocks for larger structures.
    * `parameters`, `signature`: Format function parameters and signatures.
    * `fieldList`:  Formats lists of struct or interface fields.
    * `binaryExpr`:  Specifically handles the formatting of binary expressions, taking into account operator precedence for correct parenthesis placement and spacing.
    * `expr1`, `expr0`, `expr`: A hierarchy of functions likely responsible for formatting different types of expressions.
    * `stmtList`, `block`, `stmt`:  Handle formatting of statement lists, code blocks, and individual statements.
    * `controlClause`: Formats the control clauses in `if`, `for`, and `switch` statements.

4. **Infer the overall goal:** Based on the function names and the context of printing AST nodes, the goal is to produce well-formatted Go code from an AST. This involves:
    * **Whitespace management:**  Deciding where to put spaces, tabs, and newlines.
    * **Comment placement:**  Ensuring comments are correctly associated with the code they refer to.
    * **Parenthesis insertion:** Adding parentheses where necessary to maintain operator precedence.
    * **Indentation:**  Properly indenting code blocks.
    * **Handling different AST node types:**  Having specific logic for formatting various expressions, statements, and declarations.

5. **Consider potential use cases:** Given that this code is part of `godef` (Go Definition), it's likely used to display or analyze Go code structures. A key use case is presenting the definition of a Go identifier.

6. **Formulate the summary:** Based on the analysis, the core functionality can be summarized as formatting Go code based on its AST representation.

7. **Elaborate on specific aspects (for later parts of the answer):**
    * **Go Language Feature:**  This code implements the formatting aspects of *any* Go language feature that can be represented in the AST. It's not tied to a single feature. However, demonstrating with a simple function definition is a good starting point.
    * **Code Inference:** The `binaryExpr` function demonstrates code inference by deciding whether to add parentheses based on operator precedence.
    * **Command-line arguments:**  This specific code snippet doesn't seem to directly handle command-line arguments. That would likely be handled in the main `godef` program.
    * **Common Mistakes:** The comments in the code itself mention some formatting issues, which are good candidates for potential mistakes.

8. **Structure the answer:** Organize the findings into logical sections: core functionality, potential Go language feature implementation, code inference example, command-line arguments, and common mistakes. This makes the answer easier to understand.
这段Go语言代码文件 `go/src/github.com/rogpeppe/godef/go/printer/nodes.go` 的主要功能是 **将Go语言的抽象语法树（AST）节点转换回格式化的Go源代码字符串**。

**功能归纳：**

简单来说，这个文件的代码实现了将Go语言程序的内部表示（AST）转换成可读的、格式化的源代码文本。它负责处理各种Go语言结构，例如表达式、语句和声明，并决定如何正确地打印它们，包括空格、换行、缩进和括号的使用。

**更具体的功能点包括：**

* **处理不同类型的AST节点:** 代码中包含了针对各种AST节点类型（例如 `ast.Ident`、`ast.BinaryExpr`、`ast.FuncDecl` 等）的打印逻辑。
* **管理空白符和换行:**  `linebreak` 函数负责根据源代码的位置和格式化规则插入适当数量的换行符。
* **处理注释:** `setComment` 函数用于设置即将打印的注释，确保注释与相应的代码关联。
* **格式化列表:**  `identList` 和 `exprList` 函数用于格式化标识符列表和表达式列表，处理逗号分隔、换行和缩进等。
* **格式化函数签名:** `parameters` 和 `signature` 函数用于格式化函数参数和返回值列表。
* **格式化结构体和接口:** `fieldList` 函数负责格式化结构体和接口的字段列表。
* **处理二元表达式:** `binaryExpr` 函数根据运算符优先级和结合性来决定是否需要添加括号，并管理运算符周围的空格。
* **处理各种表达式:**  `expr` 系列函数（`expr`, `expr0`, `expr1`）包含了打印各种Go语言表达式的逻辑，例如字面量、函数调用、类型断言等。
* **处理各种语句:** `stmt` 和 `stmtList` 函数用于格式化各种Go语言语句，例如赋值语句、控制流语句（`if`、`for`、`switch`）等。
* **处理声明:**  虽然这部分代码没有直接展示声明的打印逻辑，但可以推断出它依赖于 `decl` 函数（在 `Stmt` 的 `case *ast.DeclStmt` 中被调用）来处理声明的打印。

**Go语言功能实现推理与代码示例：**

考虑到该代码位于 `printer` 包下，并且处理 AST 节点，我们可以推断它实现了 **Go语言代码格式化** 的功能。这通常是 `gofmt` 工具或者其他代码美化工具的核心部分。

**示例：格式化函数定义**

假设我们有以下Go语言代码的AST表示（简化）：

```go
// 假设的输入 AST 节点
funcDecl := &ast.FuncDecl{
    Name: &ast.Ident{Name: "add"},
    Type: &ast.FuncType{
        Params: &ast.FieldList{
            List: []*ast.Field{
                {Names: []*ast.Ident{{Name: "a"}}, Type: &ast.Ident{Name: "int"}},
                {Names: []*ast.Ident{{Name: "b"}}, Type: &ast.Ident{Name: "int"}},
            },
        },
        Results: &ast.FieldList{
            List: []*ast.Field{
                {Type: &ast.Ident{Name: "int"}},
            },
        },
    },
    Body: &ast.BlockStmt{
        List: []ast.Stmt{
            &ast.ReturnStmt{
                Results: []ast.Expr{
                    &ast.BinaryExpr{
                        X:  &ast.Ident{Name: "a"},
                        Op: token.ADD,
                        Y:  &ast.Ident{Name: "b"},
                    },
                },
            },
        },
    },
}
```

**假设的输出：**

```go
func add(a int, b int) int {
	return a + b
}
```

**代码推理：**

这段代码中的 `signature` 函数会处理函数参数和返回值的打印，`block` 函数会处理函数体的打印，而 `binaryExpr` 函数会处理 `a + b` 表达式的打印。`linebreak` 和空白符相关的逻辑会确保代码的缩进和空格符合Go语言的规范。

**命令行参数的具体处理：**

这段代码片段本身并没有直接处理命令行参数。命令行参数的处理通常发生在调用这个 `printer` 包的上层程序中，例如 `gofmt` 工具。 `gofmt` 工具会解析命令行参数（例如要格式化的文件），然后将文件的内容解析成 AST，最后调用 `printer` 包中的功能来生成格式化后的代码。

**易犯错的点：**

这段代码的注释中提到了一些潜在的格式化问题，可以被视为易犯错的点，例如：

* **行尾 `/*-style` 注释的格式化：**  当这种注释跨越多行时，格式化可能不是幂等的（多次格式化结果可能不一致）。
* **表达式列表的格式化：**  具体的格式化规则可能存在一些不一致性或需要改进的地方。
* **单行函数体的空格：**  对于单行函数体，可能没有使用 `blank`（空格）而是使用了 `tab`（制表符）进行分隔，除非存在连续的单行函数。

**总结一下它的功能（第1部分）：**

这段 `nodes.go` 文件的主要功能是 **实现将Go语言的抽象语法树（AST）节点转换成格式化的Go源代码字符串的关键部分**。它包含了处理各种Go语言语法结构（如表达式、语句）的打印逻辑，并负责管理代码的空白符、换行和缩进，以生成符合Go语言规范的代码格式。

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/go/printer/nodes.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// This file implements printing of AST nodes; specifically
// expressions, statements, declarations, and files. It uses
// the print functionality implemented in printer.go.

package printer

import (
	"bytes"

	"github.com/rogpeppe/godef/go/ast"
	"github.com/rogpeppe/godef/go/token"
)

// Other formatting issues:
// - better comment formatting for /*-style comments at the end of a line (e.g. a declaration)
//   when the comment spans multiple lines; if such a comment is just two lines, formatting is
//   not idempotent
// - formatting of expression lists
// - should use blank instead of tab to separate one-line function bodies from
//   the function header unless there is a group of consecutive one-liners

// ----------------------------------------------------------------------------
// Common AST nodes.

// Print as many newlines as necessary (but at least min newlines) to get to
// the current line. ws is printed before the first line break. If newSection
// is set, the first line break is printed as formfeed. Returns true if any
// line break was printed; returns false otherwise.
//
// TODO(gri): linebreak may add too many lines if the next statement at "line"
//            is preceded by comments because the computation of n assumes
//            the current position before the comment and the target position
//            after the comment. Thus, after interspersing such comments, the
//            space taken up by them is not considered to reduce the number of
//            linebreaks. At the moment there is no easy way to know about
//            future (not yet interspersed) comments in this function.
//
func (p *printer) linebreak(line, min int, ws whiteSpace, newSection bool) (printedBreak bool) {
	n := p.nlines(line-p.pos.Line, min)
	if n > 0 {
		p.print(ws)
		if newSection {
			p.print(formfeed)
			n--
		}
		for ; n > 0; n-- {
			p.print(newline)
		}
		printedBreak = true
	}
	return
}

// setComment sets g as the next comment if g != nil and if node comments
// are enabled - this mode is used when printing source code fragments such
// as exports only. It assumes that there are no other pending comments to
// intersperse.
func (p *printer) setComment(g *ast.CommentGroup) {
	if g == nil || !p.useNodeComments {
		return
	}
	if p.comments == nil {
		// initialize p.comments lazily
		p.comments = make([]*ast.CommentGroup, 1)
	} else if p.cindex < len(p.comments) {
		// for some reason there are pending comments; this
		// should never happen - handle gracefully and flush
		// all comments up to g, ignore anything after that
		p.flush(p.fset.Position(g.List[0].Pos()), token.ILLEGAL)
	}
	p.comments[0] = g
	p.cindex = 0
}

type exprListMode uint

const (
	blankStart exprListMode = 1 << iota // print a blank before a non-empty list
	blankEnd                            // print a blank after a non-empty list
	commaSep                            // elements are separated by commas
	commaTerm                           // list is optionally terminated by a comma
	noIndent                            // no extra indentation in multi-line lists
	periodSep                           // elements are separated by periods
)

// Sets multiLine to true if the identifier list spans multiple lines.
// If indent is set, a multi-line identifier list is indented after the
// first linebreak encountered.
func (p *printer) identList(list []*ast.Ident, indent bool, multiLine *bool) {
	// convert into an expression list so we can re-use exprList formatting
	xlist := make([]ast.Expr, len(list))
	for i, x := range list {
		xlist[i] = x
	}
	mode := commaSep
	if !indent {
		mode |= noIndent
	}
	p.exprList(token.NoPos, xlist, 1, mode, multiLine, token.NoPos)
}

// Print a list of expressions. If the list spans multiple
// source lines, the original line breaks are respected between
// expressions. Sets multiLine to true if the list spans multiple
// lines.
//
// TODO(gri) Consider rewriting this to be independent of []ast.Expr
//           so that we can use the algorithm for any kind of list
//           (e.g., pass list via a channel over which to range).
func (p *printer) exprList(prev0 token.Pos, list []ast.Expr, depth int, mode exprListMode, multiLine *bool, next0 token.Pos) {
	if len(list) == 0 {
		return
	}

	if mode&blankStart != 0 {
		p.print(blank)
	}

	prev := p.fset.Position(prev0)
	next := p.fset.Position(next0)
	line := p.fset.Position(list[0].Pos()).Line
	endLine := p.fset.Position(list[len(list)-1].End()).Line

	if prev.IsValid() && prev.Line == line && line == endLine {
		// all list entries on a single line
		for i, x := range list {
			if i > 0 {
				if mode&commaSep != 0 {
					p.print(token.COMMA)
				}
				p.print(blank)
			}
			p.expr0(x, depth, multiLine)
		}
		if mode&blankEnd != 0 {
			p.print(blank)
		}
		return
	}

	// list entries span multiple lines;
	// use source code positions to guide line breaks

	// don't add extra indentation if noIndent is set;
	// i.e., pretend that the first line is already indented
	ws := ignore
	if mode&noIndent == 0 {
		ws = indent
	}

	// the first linebreak is always a formfeed since this section must not
	// depend on any previous formatting
	prevBreak := -1 // index of last expression that was followed by a linebreak
	if prev.IsValid() && prev.Line < line && p.linebreak(line, 0, ws, true) {
		ws = ignore
		*multiLine = true
		prevBreak = 0
	}

	// initialize expression/key size: a zero value indicates expr/key doesn't fit on a single line
	size := 0

	// print all list elements
	for i, x := range list {
		prevLine := line
		line = p.fset.Position(x.Pos()).Line

		// determine if the next linebreak, if any, needs to use formfeed:
		// in general, use the entire node size to make the decision; for
		// key:value expressions, use the key size
		// TODO(gri) for a better result, should probably incorporate both
		//           the key and the node size into the decision process
		useFF := true

		// determine element size: all bets are off if we don't have
		// position information for the previous and next token (likely
		// generated code - simply ignore the size in this case by setting
		// it to 0)
		prevSize := size
		const infinity = 1e6 // larger than any source line
		size = p.nodeSize(x, infinity)
		pair, isPair := x.(*ast.KeyValueExpr)
		if size <= infinity && prev.IsValid() && next.IsValid() {
			// x fits on a single line
			if isPair {
				size = p.nodeSize(pair.Key, infinity) // size <= infinity
			}
		} else {
			// size too large or we don't have good layout information
			size = 0
		}

		// if the previous line and the current line had single-
		// line-expressions and the key sizes are small or the
		// the ratio between the key sizes does not exceed a
		// threshold, align columns and do not use formfeed
		if prevSize > 0 && size > 0 {
			const smallSize = 20
			if prevSize <= smallSize && size <= smallSize {
				useFF = false
			} else {
				const r = 4 // threshold
				ratio := float64(size) / float64(prevSize)
				useFF = ratio <= 1/r || r <= ratio
			}
		}

		if i > 0 {
			switch {
			case mode&commaSep != 0:
				p.print(token.COMMA)
			case mode&periodSep != 0:
				p.print(token.PERIOD)
			}
			needsBlank := mode&periodSep == 0 // period-separated list elements don't need a blank
			if prevLine < line && prevLine > 0 && line > 0 {
				// lines are broken using newlines so comments remain aligned
				// unless forceFF is set or there are multiple expressions on
				// the same line in which case formfeed is used
				if p.linebreak(line, 0, ws, useFF || prevBreak+1 < i) {
					ws = ignore
					*multiLine = true
					prevBreak = i
					needsBlank = false // we got a line break instead
				}
			}
			if needsBlank {
				p.print(blank)
			}
		}

		if isPair && size > 0 && len(list) > 1 {
			// we have a key:value expression that fits onto one line and
			// is in a list with more then one entry: use a column for the
			// key such that consecutive entries can align if possible
			p.expr(pair.Key, multiLine)
			p.print(pair.Colon, token.COLON, vtab)
			p.expr(pair.Value, multiLine)
		} else {
			p.expr0(x, depth, multiLine)
		}
	}

	if mode&commaTerm != 0 && next.IsValid() && p.pos.Line < next.Line {
		// print a terminating comma if the next token is on a new line
		p.print(token.COMMA)
		if ws == ignore && mode&noIndent == 0 {
			// unindent if we indented
			p.print(unindent)
		}
		p.print(formfeed) // terminating comma needs a line break to look good
		return
	}

	if mode&blankEnd != 0 {
		p.print(blank)
	}

	if ws == ignore && mode&noIndent == 0 {
		// unindent if we indented
		p.print(unindent)
	}
}

// Sets multiLine to true if the the parameter list spans multiple lines.
func (p *printer) parameters(fields *ast.FieldList, multiLine *bool) {
	p.print(fields.Opening, token.LPAREN)
	if len(fields.List) > 0 {
		var prevLine, line int
		for i, par := range fields.List {
			if i > 0 {
				p.print(token.COMMA)
				if len(par.Names) > 0 {
					line = p.fset.Position(par.Names[0].Pos()).Line
				} else {
					line = p.fset.Position(par.Type.Pos()).Line
				}
				if 0 < prevLine && prevLine < line && p.linebreak(line, 0, ignore, true) {
					*multiLine = true
				} else {
					p.print(blank)
				}
			}
			if len(par.Names) > 0 {
				p.identList(par.Names, false, multiLine)
				p.print(blank)
			}
			p.expr(par.Type, multiLine)
			prevLine = p.fset.Position(par.Type.Pos()).Line
		}
	}
	p.print(fields.Closing, token.RPAREN)
}

// Sets multiLine to true if the signature spans multiple lines.
func (p *printer) signature(params, result *ast.FieldList, multiLine *bool) {
	p.parameters(params, multiLine)
	n := result.NumFields()
	if n > 0 {
		p.print(blank)
		if n == 1 && result.List[0].Names == nil {
			// single anonymous result; no ()'s
			p.expr(result.List[0].Type, multiLine)
			return
		}
		p.parameters(result, multiLine)
	}
}

func identListSize(list []*ast.Ident, maxSize int) (size int) {
	for i, x := range list {
		if i > 0 {
			size += 2 // ", "
		}
		size += len(x.Name)
		if size >= maxSize {
			break
		}
	}
	return
}

func (p *printer) isOneLineFieldList(list []*ast.Field) bool {
	if len(list) != 1 {
		return false // allow only one field
	}
	f := list[0]
	if f.Tag != nil || f.Comment != nil {
		return false // don't allow tags or comments
	}
	// only name(s) and type
	const maxSize = 30 // adjust as appropriate, this is an approximate value
	namesSize := identListSize(f.Names, maxSize)
	if namesSize > 0 {
		namesSize = 1 // blank between names and types
	}
	typeSize := p.nodeSize(f.Type, maxSize)
	return namesSize+typeSize <= maxSize
}

func (p *printer) setLineComment(text string) {
	p.setComment(&ast.CommentGroup{[]*ast.Comment{&ast.Comment{token.NoPos, text}}})
}

func (p *printer) fieldList(fields *ast.FieldList, isStruct, isIncomplete bool) {
	lbrace := fields.Opening
	list := fields.List
	rbrace := fields.Closing
	srcIsOneLine := lbrace.IsValid() && rbrace.IsValid() && p.fset.Position(lbrace).Line == p.fset.Position(rbrace).Line

	if !isIncomplete && !p.commentBefore(p.fset.Position(rbrace)) && srcIsOneLine {
		// possibly a one-line struct/interface
		if len(list) == 0 {
			// no blank between keyword and {} in this case
			p.print(lbrace, token.LBRACE, rbrace, token.RBRACE)
			return
		} else if isStruct && p.isOneLineFieldList(list) { // for now ignore interfaces
			// small enough - print on one line
			// (don't use identList and ignore source line breaks)
			p.print(lbrace, token.LBRACE, blank)
			f := list[0]
			for i, x := range f.Names {
				if i > 0 {
					p.print(token.COMMA, blank)
				}
				p.expr(x, ignoreMultiLine)
			}
			if len(f.Names) > 0 {
				p.print(blank)
			}
			p.expr(f.Type, ignoreMultiLine)
			p.print(blank, rbrace, token.RBRACE)
			return
		}
	}

	// at least one entry or incomplete
	p.print(blank, lbrace, token.LBRACE, indent, formfeed)
	if isStruct {

		sep := vtab
		if len(list) == 1 {
			sep = blank
		}
		var ml bool
		for i, f := range list {
			if i > 0 {
				p.linebreak(p.fset.Position(f.Pos()).Line, 1, ignore, ml)
			}
			ml = false
			extraTabs := 0
			p.setComment(f.Doc)
			if len(f.Names) > 0 {
				// named fields
				p.identList(f.Names, false, &ml)
				p.print(sep)
				p.expr(f.Type, &ml)
				extraTabs = 1
			} else {
				// anonymous field
				p.expr(f.Type, &ml)
				extraTabs = 2
			}
			if f.Tag != nil {
				if len(f.Names) > 0 && sep == vtab {
					p.print(sep)
				}
				p.print(sep)
				p.expr(f.Tag, &ml)
				extraTabs = 0
			}
			if f.Comment != nil {
				for ; extraTabs > 0; extraTabs-- {
					p.print(sep)
				}
				p.setComment(f.Comment)
			}
		}
		if isIncomplete {
			if len(list) > 0 {
				p.print(formfeed)
			}
			p.flush(p.fset.Position(rbrace), token.RBRACE) // make sure we don't lose the last line comment
			p.setLineComment("// contains filtered or unexported fields")
		}

	} else { // interface

		var ml bool
		for i, f := range list {
			if i > 0 {
				p.linebreak(p.fset.Position(f.Pos()).Line, 1, ignore, ml)
			}
			ml = false
			p.setComment(f.Doc)
			if ftyp, isFtyp := f.Type.(*ast.FuncType); isFtyp {
				// method
				p.expr(f.Names[0], &ml)
				p.signature(ftyp.Params, ftyp.Results, &ml)
			} else {
				// embedded interface
				p.expr(f.Type, &ml)
			}
			p.setComment(f.Comment)
		}
		if isIncomplete {
			if len(list) > 0 {
				p.print(formfeed)
			}
			p.flush(p.fset.Position(rbrace), token.RBRACE) // make sure we don't lose the last line comment
			p.setLineComment("// contains filtered or unexported methods")
		}

	}
	p.print(unindent, formfeed, rbrace, token.RBRACE)
}

// ----------------------------------------------------------------------------
// Expressions

func walkBinary(e *ast.BinaryExpr) (has4, has5 bool, maxProblem int) {
	switch e.Op.Precedence() {
	case 4:
		has4 = true
	case 5:
		has5 = true
	}

	switch l := e.X.(type) {
	case *ast.BinaryExpr:
		if l.Op.Precedence() < e.Op.Precedence() {
			// parens will be inserted.
			// pretend this is an *ast.ParenExpr and do nothing.
			break
		}
		h4, h5, mp := walkBinary(l)
		has4 = has4 || h4
		has5 = has5 || h5
		if maxProblem < mp {
			maxProblem = mp
		}
	}

	switch r := e.Y.(type) {
	case *ast.BinaryExpr:
		if r.Op.Precedence() <= e.Op.Precedence() {
			// parens will be inserted.
			// pretend this is an *ast.ParenExpr and do nothing.
			break
		}
		h4, h5, mp := walkBinary(r)
		has4 = has4 || h4
		has5 = has5 || h5
		if maxProblem < mp {
			maxProblem = mp
		}

	case *ast.StarExpr:
		if e.Op == token.QUO { // `*/`
			maxProblem = 5
		}

	case *ast.UnaryExpr:
		switch e.Op.String() + r.Op.String() {
		case "/*", "&&", "&^":
			maxProblem = 5
		case "++", "--":
			if maxProblem < 4 {
				maxProblem = 4
			}
		}
	}
	return
}

func cutoff(e *ast.BinaryExpr, depth int) int {
	has4, has5, maxProblem := walkBinary(e)
	if maxProblem > 0 {
		return maxProblem + 1
	}
	if has4 && has5 {
		if depth == 1 {
			return 5
		}
		return 4
	}
	if depth == 1 {
		return 6
	}
	return 4
}

func diffPrec(expr ast.Expr, prec int) int {
	x, ok := expr.(*ast.BinaryExpr)
	if !ok || prec != x.Op.Precedence() {
		return 1
	}
	return 0
}

func reduceDepth(depth int) int {
	depth--
	if depth < 1 {
		depth = 1
	}
	return depth
}

// Format the binary expression: decide the cutoff and then format.
// Let's call depth == 1 Normal mode, and depth > 1 Compact mode.
// (Algorithm suggestion by Russ Cox.)
//
// The precedences are:
//	5             *  /  %  <<  >>  &  &^
//	4             +  -  |  ^
//	3             ==  !=  <  <=  >  >=
//	2             &&
//	1             ||
//
// The only decision is whether there will be spaces around levels 4 and 5.
// There are never spaces at level 6 (unary), and always spaces at levels 3 and below.
//
// To choose the cutoff, look at the whole expression but excluding primary
// expressions (function calls, parenthesized exprs), and apply these rules:
//
//	1) If there is a binary operator with a right side unary operand
//	   that would clash without a space, the cutoff must be (in order):
//
//		/*	6
//		&&	6
//		&^	6
//		++	5
//		--	5
//
//         (Comparison operators always have spaces around them.)
//
//	2) If there is a mix of level 5 and level 4 operators, then the cutoff
//	   is 5 (use spaces to distinguish precedence) in Normal mode
//	   and 4 (never use spaces) in Compact mode.
//
//	3) If there are no level 4 operators or no level 5 operators, then the
//	   cutoff is 6 (always use spaces) in Normal mode
//	   and 4 (never use spaces) in Compact mode.
//
// Sets multiLine to true if the binary expression spans multiple lines.
func (p *printer) binaryExpr(x *ast.BinaryExpr, prec1, cutoff, depth int, multiLine *bool) {
	prec := x.Op.Precedence()
	if prec < prec1 {
		// parenthesis needed
		// Note: The parser inserts an ast.ParenExpr node; thus this case
		//       can only occur if the AST is created in a different way.
		p.print(token.LPAREN)
		p.expr0(x, reduceDepth(depth), multiLine) // parentheses undo one level of depth
		p.print(token.RPAREN)
		return
	}

	printBlank := prec < cutoff

	ws := indent
	p.expr1(x.X, prec, depth+diffPrec(x.X, prec), multiLine)
	if printBlank {
		p.print(blank)
	}
	xline := p.pos.Line // before the operator (it may be on the next line!)
	yline := p.fset.Position(x.Y.Pos()).Line
	p.print(x.OpPos, x.Op)
	if xline != yline && xline > 0 && yline > 0 {
		// at least one line break, but respect an extra empty line
		// in the source
		if p.linebreak(yline, 1, ws, true) {
			ws = ignore
			*multiLine = true
			printBlank = false // no blank after line break
		}
	}
	if printBlank {
		p.print(blank)
	}
	p.expr1(x.Y, prec+1, depth+1, multiLine)
	if ws == ignore {
		p.print(unindent)
	}
}

func isBinary(expr ast.Expr) bool {
	_, ok := expr.(*ast.BinaryExpr)
	return ok
}

// If the expression contains one or more selector expressions, splits it into
// two expressions at the rightmost period. Writes entire expr to suffix when
// selector isn't found. Rewrites AST nodes for calls, index expressions and
// type assertions, all of which may be found in selector chains, to make them
// parts of the chain.
func splitSelector(expr ast.Expr) (body, suffix ast.Expr) {
	switch x := expr.(type) {
	case *ast.SelectorExpr:
		body, suffix = x.X, x.Sel
		return
	case *ast.CallExpr:
		body, suffix = splitSelector(x.Fun)
		if body != nil {
			suffix = &ast.CallExpr{suffix, x.Lparen, x.Args, x.Ellipsis, x.Rparen}
			return
		}
	case *ast.IndexExpr:
		body, suffix = splitSelector(x.X)
		if body != nil {
			suffix = &ast.IndexExpr{suffix, x.Lbrack, x.Index, x.Rbrack}
			return
		}
	case *ast.SliceExpr:
		body, suffix = splitSelector(x.X)
		if body != nil {
			suffix = &ast.SliceExpr{X: suffix, Lbrack: x.Lbrack, Low: x.Low, High: x.High, Rbrack: x.Rbrack, Slice3: false}
			return
		}
	case *ast.TypeAssertExpr:
		body, suffix = splitSelector(x.X)
		if body != nil {
			suffix = &ast.TypeAssertExpr{suffix, x.Type}
			return
		}
	}
	suffix = expr
	return
}

// Convert an expression into an expression list split at the periods of
// selector expressions.
func selectorExprList(expr ast.Expr) (list []ast.Expr) {
	// split expression
	for expr != nil {
		var suffix ast.Expr
		expr, suffix = splitSelector(expr)
		list = append(list, suffix)
	}

	// reverse list
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}

	return
}

// Sets multiLine to true if the expression spans multiple lines.
func (p *printer) expr1(expr ast.Expr, prec1, depth int, multiLine *bool) {
	p.print(expr.Pos())

	switch x := expr.(type) {
	case *ast.BadExpr:
		p.print("BadExpr")

	case *ast.Ident:
		p.print(x)

	case *ast.BinaryExpr:
		if depth < 1 {
			p.internalError("depth < 1:", depth)
			depth = 1
		}
		p.binaryExpr(x, prec1, cutoff(x, depth), depth, multiLine)

	case *ast.KeyValueExpr:
		p.expr(x.Key, multiLine)
		p.print(x.Colon, token.COLON, blank)
		p.expr(x.Value, multiLine)

	case *ast.StarExpr:
		const prec = token.UnaryPrec
		if prec < prec1 {
			// parenthesis needed
			p.print(token.LPAREN)
			p.print(token.MUL)
			p.expr(x.X, multiLine)
			p.print(token.RPAREN)
		} else {
			// no parenthesis needed
			p.print(token.MUL)
			p.expr(x.X, multiLine)
		}

	case *ast.UnaryExpr:
		const prec = token.UnaryPrec
		if prec < prec1 {
			// parenthesis needed
			p.print(token.LPAREN)
			p.expr(x, multiLine)
			p.print(token.RPAREN)
		} else {
			// no parenthesis needed
			p.print(x.Op)
			if x.Op == token.RANGE {
				// TODO(gri) Remove this code if it cannot be reached.
				p.print(blank)
			}
			p.expr1(x.X, prec, depth, multiLine)
		}

	case *ast.BasicLit:
		p.print(x)

	case *ast.FuncLit:
		p.expr(x.Type, multiLine)
		p.funcBody(x.Body, p.distance(x.Type.Pos(), p.pos), true, multiLine)

	case *ast.ParenExpr:
		if _, hasParens := x.X.(*ast.ParenExpr); hasParens {
			// don't print parentheses around an already parenthesized expression
			// TODO(gri) consider making this more general and incorporate precedence levels
			p.expr0(x.X, reduceDepth(depth), multiLine) // parentheses undo one level of depth
		} else {
			p.print(token.LPAREN)
			p.expr0(x.X, reduceDepth(depth), multiLine) // parentheses undo one level of depth
			p.print(x.Rparen, token.RPAREN)
		}

	case *ast.SelectorExpr:
		parts := selectorExprList(expr)
		p.exprList(token.NoPos, parts, depth, periodSep, multiLine, token.NoPos)

	case *ast.TypeAssertExpr:
		p.expr1(x.X, token.HighestPrec, depth, multiLine)
		p.print(token.PERIOD, token.LPAREN)
		if x.Type != nil {
			p.expr(x.Type, multiLine)
		} else {
			p.print(token.TYPE)
		}
		p.print(token.RPAREN)

	case *ast.IndexExpr:
		// TODO(gri): should treat[] like parentheses and undo one level of depth
		p.expr1(x.X, token.HighestPrec, 1, multiLine)
		p.print(x.Lbrack, token.LBRACK)
		p.expr0(x.Index, depth+1, multiLine)
		p.print(x.Rbrack, token.RBRACK)

	case *ast.SliceExpr:
		// TODO(gri): should treat[] like parentheses and undo one level of depth
		p.expr1(x.X, token.HighestPrec, 1, multiLine)
		p.print(x.Lbrack, token.LBRACK)
		if x.Low != nil {
			p.expr0(x.Low, depth+1, multiLine)
		}
		// blanks around ":" if both sides exist and either side is a binary expression
		if depth <= 1 && x.Low != nil && x.High != nil && (isBinary(x.Low) || isBinary(x.High)) {
			p.print(blank, token.COLON, blank)
		} else {
			p.print(token.COLON)
		}
		if x.High != nil {
			p.expr0(x.High, depth+1, multiLine)
		}
		p.print(x.Rbrack, token.RBRACK)

	case *ast.CallExpr:
		if len(x.Args) > 1 {
			depth++
		}
		p.expr1(x.Fun, token.HighestPrec, depth, multiLine)
		p.print(x.Lparen, token.LPAREN)
		p.exprList(x.Lparen, x.Args, depth, commaSep|commaTerm, multiLine, x.Rparen)
		if x.Ellipsis.IsValid() {
			p.print(x.Ellipsis, token.ELLIPSIS)
		}
		p.print(x.Rparen, token.RPAREN)

	case *ast.CompositeLit:
		// composite literal elements that are composite literals themselves may have the type omitted
		if x.Type != nil {
			p.expr1(x.Type, token.HighestPrec, depth, multiLine)
		}
		p.print(x.Lbrace, token.LBRACE)
		p.exprList(x.Lbrace, x.Elts, 1, commaSep|commaTerm, multiLine, x.Rbrace)
		// do not insert extra line breaks because of comments before
		// the closing '}' as it might break the code if there is no
		// trailing ','
		p.print(noExtraLinebreak, x.Rbrace, token.RBRACE, noExtraLinebreak)

	case *ast.Ellipsis:
		p.print(token.ELLIPSIS)
		if x.Elt != nil {
			p.expr(x.Elt, multiLine)
		}

	case *ast.ArrayType:
		p.print(token.LBRACK)
		if x.Len != nil {
			p.expr(x.Len, multiLine)
		}
		p.print(token.RBRACK)
		p.expr(x.Elt, multiLine)

	case *ast.StructType:
		p.print(token.STRUCT)
		p.fieldList(x.Fields, true, x.Incomplete)

	case *ast.FuncType:
		p.print(token.FUNC)
		p.signature(x.Params, x.Results, multiLine)

	case *ast.InterfaceType:
		p.print(token.INTERFACE)
		p.fieldList(x.Methods, false, x.Incomplete)

	case *ast.MapType:
		p.print(token.MAP, token.LBRACK)
		p.expr(x.Key, multiLine)
		p.print(token.RBRACK)
		p.expr(x.Value, multiLine)

	case *ast.ChanType:
		switch x.Dir {
		case ast.SEND | ast.RECV:
			p.print(token.CHAN)
		case ast.RECV:
			p.print(token.ARROW, token.CHAN)
		case ast.SEND:
			p.print(token.CHAN, token.ARROW)
		}
		p.print(blank)
		p.expr(x.Value, multiLine)

	default:
		panic("unreachable")
	}

	return
}

func (p *printer) expr0(x ast.Expr, depth int, multiLine *bool) {
	p.expr1(x, token.LowestPrec, depth, multiLine)
}

// Sets multiLine to true if the expression spans multiple lines.
func (p *printer) expr(x ast.Expr, multiLine *bool) {
	const depth = 1
	p.expr1(x, token.LowestPrec, depth, multiLine)
}

// ----------------------------------------------------------------------------
// Statements

// Print the statement list indented, but without a newline after the last statement.
// Extra line breaks between statements in the source are respected but at most one
// empty line is printed between statements.
func (p *printer) stmtList(list []ast.Stmt, _indent int, nextIsRBrace bool) {
	// TODO(gri): fix _indent code
	if _indent > 0 {
		p.print(indent)
	}
	var multiLine bool
	for i, s := range list {
		// _indent == 0 only for lists of switch/select case clauses;
		// in those cases each clause is a new section
		p.linebreak(p.fset.Position(s.Pos()).Line, 1, ignore, i == 0 || _indent == 0 || multiLine)
		multiLine = false
		p.stmt(s, nextIsRBrace && i == len(list)-1, &multiLine)
	}
	if _indent > 0 {
		p.print(unindent)
	}
}

// block prints an *ast.BlockStmt; it always spans at least two lines.
func (p *printer) block(s *ast.BlockStmt, indent int) {
	p.print(s.Pos(), token.LBRACE)
	p.stmtList(s.List, indent, true)
	p.linebreak(p.fset.Position(s.Rbrace).Line, 1, ignore, true)
	p.print(s.Rbrace, token.RBRACE)
}

func isTypeName(x ast.Expr) bool {
	switch t := x.(type) {
	case *ast.Ident:
		return true
	case *ast.SelectorExpr:
		return isTypeName(t.X)
	}
	return false
}

func stripParens(x ast.Expr) ast.Expr {
	if px, strip := x.(*ast.ParenExpr); strip {
		// parentheses must not be stripped if there are any
		// unparenthesized composite literals starting with
		// a type name
		ast.Inspect(px.X, func(node ast.Node) bool {
			switch x := node.(type) {
			case *ast.ParenExpr:
				// parentheses protect enclosed composite literals
				return false
			case *ast.CompositeLit:
				if isTypeName(x.Type) {
					strip = false // do not strip parentheses
				}
				return false
			}
			// in all other cases, keep inspecting
			return true
		})
		if strip {
			return stripParens(px.X)
		}
	}
	return x
}

func (p *printer) controlClause(isForStmt bool, init ast.Stmt, expr ast.Expr, post ast.Stmt) {
	p.print(blank)
	needsBlank := false
	if init == nil && post == nil {
		// no semicolons required
		if expr != nil {
			p.expr(stripParens(expr), ignoreMultiLine)
			needsBlank = true
		}
	} else {
		// all semicolons required
		// (they are not separators, print them explicitly)
		if init != nil {
			p.stmt(init, false, ignoreMultiLine)
		}
		p.print(token.SEMICOLON, blank)
		if expr != nil {
			p.expr(stripParens(expr), ignoreMultiLine)
			needsBlank = true
		}
		if isForStmt {
			p.print(token.SEMICOLON, blank)
			needsBlank = false
			if post != nil {
				p.stmt(post, false, ignoreMultiLine)
				needsBlank = true
			}
		}
	}
	if needsBlank {
		p.print(blank)
	}
}

// Sets multiLine to true if the statements spans multiple lines.
func (p *printer) stmt(stmt ast.Stmt, nextIsRBrace bool, multiLine *bool) {
	p.print(stmt.Pos())

	switch s := stmt.(type) {
	case *ast.BadStmt:
		p.print("BadStmt")

	case *ast.DeclStmt:
		p.decl(s.Decl, multiLine)

	case *ast.EmptyStmt:
		// nothing to do

	case *ast.LabeledStmt:
		// a "correcting" unindent immediately following a line break
		// is applied before the line break if there is no comment
		// between (see writeWhitespace)
		p.print(unindent)
		p.expr(s.Label, multiLine)
		p.print(s.Colon, token.COLON, indent)
		if e, isEmpty := s.Stmt.(*ast.EmptyStmt); isEmpty {
			if !nextIsRBrace {
				p.print(newline, e.Pos(), token.SEMICOLON)
				break
			}
		} else {
			p.linebreak(p.fset.Position(s.Stmt.Pos()).Line, 1, ignore, true)
		}
		p.stmt(s.Stmt, nextIsRBrace, multiLine)

	case *ast.ExprStmt:
		const depth = 1
		p.expr0(s.X, depth, multiLine)

	case *ast.SendStmt:
		const depth = 1
		p.expr0(s.Chan, depth, multiLine)
		p.print(blank, s.Arrow, token.ARROW, blank)
		p.expr0(s.Value, depth, multiLine)

	case *ast.IncDecStmt:
		const depth = 1
		p.expr0(s.X, depth+1, multiLine)
		p.print(s.TokPos, s.Tok)

	case *ast.AssignStmt:
		var depth = 1
		if len(s.Lhs) > 1 && len(s.Rhs) > 1 {
			depth++
		}
		p.exprList(s.Pos(), s.Lhs, depth, commaSep, multiLine, s.TokPos)
		p.print(blank, s.TokPos, s.Tok)
		p.exprList(s.TokPos, s.Rhs, depth, blankStart|commaSep, multiLine, token.NoPos)

	case *ast.GoStmt:
		p.print(token.GO, blank)
		p.expr(s.Call, multiLine)

	case *ast.DeferStmt:
		p.print(token.DEFER, blank)
		p.expr(s.Call, multiLine)

	case *ast.ReturnStmt:
		p.print(token.RETURN)
		if s.Results != nil {
			p.exprList(s.Pos(), s.Results, 1, blankStart|commaSep, multiLine, token.NoPos)
		}

	case *ast.BranchStmt:
		p.print(s.Tok)
		if s.Label != nil {
			p.print(blank)
			p.expr(s.Label, multiLine)
		}

	case *ast.BlockStmt:
		p.block(s, 1)
		*multiLine = true

	case *ast.IfStmt:
		p.print(token.IF)
		p.controlClause(false, s.Init, s.Cond, nil)
		p.block(s.Body, 1)
		*multiLine = true
		if s.Else != nil {
			p.print(blank, token.ELSE, blank)
			switch s.Else.(type) {
			case *ast.BlockStmt, *ast.IfStmt:
				p.stmt(s.Else, nextIsRBrace, ignoreMultiLine)
			default:
				p.print(token.LBRACE, indent, formfeed)
				p.stmt(s.Else, true, ignoreMultiLine)
				p.print(unindent, formfeed, token.RBRACE)
			}
		}

	case *ast.CaseClause:
		if s.List != nil {
			p.print(token.CASE)
			p.exprList(s.Pos(), s.List, 1, blankStart|commaSep, multiLine, s.Colon)
		} else {
			p.print(token.DEFAULT)
		}
		p.print(s.Colon, token.COLON)
		p.stmtList(s.Body, 1, nextIsRBrace)

	case *ast.SwitchStmt:
		p.print(token.SWITCH)
		p.controlClause(false, s.Init, s.Tag, nil)
		p.block(s.Body, 0)
		*multiLine = true

	case *ast.TypeSwitchStmt:
		p.print(token.SWITCH)
		if s.Init != nil {
			p.print(blank)
			p.stmt(s.Init, false, ignoreMultiLine)
			p.print(token.SEMICOLON)
		}
		p.print(blank)
		p.stmt(s.Assign, false, ignoreMultiLine)
		p.print(blank)
		p.block(s.Body, 0)
		*multiLine = true

	case *ast.CommClause:
		if s.Comm != nil {
			p.print(token.CASE, blank)
			p.stmt(s.Comm, false, ignoreMultiLine)
		} else {
			p.print(token.DEFAULT)
		}
		p.print(s.Colon, token.COLON)
		p.stmtList(s.Body, 1, nextIsRBrace)

	case *ast.SelectStmt:
		p.print(token.SELECT, blank)
		body := s.Body
		if len(body.List) == 0 && !p.commentBefore(p.fset.Position(body.Rbrace)) {
			// print empty select statement w/o comments on one line
			p.print(body.Lbrace, token.LBRACE, body.Rbrace, token.RBRACE)
		} else {
			p.block(body, 0)
			*multiLine = true
		}

	case *ast.ForStmt:
		p.print(token.FOR)
		p.controlClause(true, s.Init, s.Cond, s.Post)
		p.block(s.Body, 1)
		*multiLine = true

	case *ast.RangeStmt:
		p.print(token.FOR, blank)
		if s.Key != nil {
			p.expr(s.Key, multiLine)
			if s.Value != nil {
				// use position of value following the comma as
				// comma position for correct comment placement
				p.print(s.Value.Pos(), token.COMMA, blank)
				p.expr(s.Value, multiLine)
			}
			p.print(blank, s.TokPos, s.Tok, blank)
		}
		p.print(token.RANGE, blank)
		p.expr(stripParens(s.X), multiLine)
		p.print(blank)
		p.block(s.Body, 1)
		*multiLine = true

	default:
		panic("unreachable")
	}

	return
}

// ----------------------------------------------------------------------------
// Declarations

// The keepTypeColumn function determines if the type column of a series of
// consecutive const or var declarations must be kept, or if initialization
// values (V) can be placed in the type column (T) instead. The i'th entry
// in the result slice is true if the type column in spec[i] must be kept.
//
// For example, the declaration:
//
//	const (
//		foobar int = 42 // comment
//		x          = 7  // comment
//		foo
//              bar = 991
//	)
//
// leads to the type/values matrix below. A run of value columns (V) can
// be moved into the type column if there is no type for any of the values
// in that column (we only move entire columns so that they align properly).
//
//	matrix        formatted     result
//                    matrix
//	T  V    ->    T  V     ->   true      there is a T and so the type
//	-  V          -  V          true      column must be kept
//	-  -          -  -          false
//	-  V          V  -          false     V is moved into T 
"""




```