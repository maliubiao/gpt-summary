Response:
The user wants to understand the functionality of the Go code snippet provided, which is a part of the `go/printer` package, specifically the `nodes.go` file.

**Plan:**

1. **Identify the main purpose:** Based on the initial comments, the file is responsible for printing AST nodes.
2. **Analyze key functions:** Examine functions like `linebreak`, `setComment`, `identList`, `exprList`, `parameters`, `signature`, `fieldList`, `binaryExpr`, `expr0`, `expr1`, and `expr`. Understand what each function does in the context of printing AST nodes.
3. **Infer Go language feature implementation:** Try to deduce which Go language features are handled by these printing functions. Examples include expressions, statements, declarations, and specific syntax constructs like function signatures, struct fields, etc.
4. **Provide Go code examples:** Illustrate how these printing functions might be used to format different Go code constructs.
5. **Identify potential pitfalls:** Look for areas where users of this functionality (if directly exposed, which is unlikely) might make mistakes.
6. **Summarize the functionality:** Provide a concise overview of the code's purpose.
这段代码是Go语言 `go/printer` 包中 `nodes.go` 文件的一部分，它的主要功能是**将Go语言的抽象语法树 (AST) 节点转换成格式化的源代码文本**。  更具体地说，它负责处理表达式、语句、声明和文件等各种AST节点的打印输出。

以下是其功能的详细列表：

1. **处理换行和空白：**
   - `linebreak` 函数用于在输出中插入必要数量的换行符，以保持代码的格式整洁。它可以根据目标行号、最小换行数以及是否需要插入 `formfeed` 来控制换行的行为。
   - 代码中多处使用了 `blank`、`indent` 和 `unindent` 等常量，以及 `vtab`（垂直制表符）来控制输出中的空格和缩进，从而实现代码的格式化。

2. **处理注释：**
   - `setComment` 函数用于设置即将打印的注释。它会检查是否启用了节点注释，并管理内部的注释缓存。
   - 代码逻辑可以推断出它能处理不同类型的注释，例如行尾注释和块注释，并将其放置在正确的位置。

3. **打印标识符列表：**
   - `identList` 函数用于打印标识符列表，例如变量声明中的变量名列表。它可以选择是否在多行列表后进行缩进。

4. **打印表达式列表：**
   - `exprList` 函数是核心功能之一，用于打印一系列表达式。它能够处理单行和多行的表达式列表，并根据源代码的位置信息来决定换行和缩进。
   - 该函数还考虑了代码被过滤或包含未导出字段的情况，并会添加相应的注释。

5. **打印函数参数和类型参数：**
   - `parameters` 函数用于打印函数或类型的参数列表（包括类型参数）。它可以处理不同类型的参数列表，并根据需要使用圆括号或方括号。
   - 它会根据参数是否跨行以及是否是类型参数的特殊情况来决定是否需要添加逗号。

6. **打印函数签名：**
   - `signature` 函数用于打印函数的完整签名，包括类型参数和参数列表以及返回值。

7. **打印结构体和接口的字段列表：**
   - `fieldList` 函数用于打印结构体或接口的字段列表。它可以处理单行和多行的字段定义，并根据情况进行缩进和换行。
   - 它还会处理字段的标签（tag）和注释。

8. **打印各种表达式：**
   - 代码中包含大量的 `expr` 和 `expr0`、`expr1` 函数，以及 `binaryExpr` 等专门用于处理二元表达式的函数。这些函数共同负责打印各种Go语言表达式，例如字面量、标识符、二元运算、函数调用、复合字面量、切片、索引、类型断言等等。
   - `binaryExpr` 函数实现了复杂的逻辑来决定二元表达式中何时需要添加空格或括号，以保证代码的可读性和符合Go语言的语法规则。它考虑了运算符的优先级和结合性。
   - `normalizedNumber` 函数用于规范化数字字面量的格式，例如将十六进制前缀转换为小写。

9. **处理选择器表达式：**
   - `selectorExpr` 函数用于打印选择器表达式（例如 `obj.field`）。

**推断的Go语言功能实现：**

这段代码是 `go/printer` 包的一部分，因此它的核心功能是**代码格式化**。它可以理解和格式化以下Go语言功能：

- **变量和常量声明：**  `identList` 和 `exprList` 可以用于格式化声明中的标识符和初始值。
- **函数声明和调用：** `signature` 和 `exprList` 用于格式化函数签名和调用参数。
- **结构体和接口：** `fieldList` 用于格式化结构体和接口的字段定义。
- **各种表达式：**  包括算术运算、逻辑运算、位运算、比较运算、字面量、函数字面量、复合字面量、类型转换、类型断言、索引、切片、函数调用等。
- **类型定义：**  可以格式化各种类型，包括基本类型、数组、切片、Map、Chan、结构体、接口、函数类型等。
- **注释：** 可以处理行注释和块注释，并将其放置在合适的位置。

**Go代码举例说明：**

假设我们有以下Go代码的AST表示：

```go
package main

import "fmt"

func add(a int, b int) int {
	return a + b
}

func main() {
	result := add(10, 20)
	fmt.Println(result)
}
```

`nodes.go` 中的函数会被调用来将这个AST转换回格式化的源代码。例如：

- `signature` 函数会被调用来打印 `func add(a int, b int) int` 的签名。
- `exprList` 函数会被调用来打印 `add(10, 20)` 的参数列表。
- `fieldList` 函数会被调用来打印 `import "fmt"`（虽然 import 不是严格意义上的 field）。
- `binaryExpr` 函数会被调用来打印 `a + b`。

**假设的输入与输出 (代码推理):**

假设 `exprList` 函数接收一个包含两个 `ast.BasicLit` 节点的切片，分别表示整数 `10` 和 `20`：

**输入 (假设的AST结构):**

```go
[]ast.Expr{
    &ast.BasicLit{Kind: token.INT, Value: "10"},
    &ast.BasicLit{Kind: token.INT, Value: "20"},
}
```

**输出 (格式化后的文本):**

```
10, 20
```

如果列表很长并跨越多行，`exprList` 还会负责添加换行和缩进。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。`go/printer` 包通常由 `go fmt` 等工具使用，这些工具会解析命令行参数，然后将文件内容解析成 AST，最后使用 `printer` 包进行格式化。 因此，命令行参数的处理发生在 `go fmt` 等工具的更上层。

**使用者易犯错的点：**

由于这段代码是 `go/printer` 包的内部实现，普通开发者不会直接使用它。 易犯错的点主要体现在理解和使用 `go/ast` 包来构建和操作 AST。 如果手动构建的 AST 结构不正确或缺少必要的位置信息，`printer` 包可能无法生成正确的格式化输出，甚至可能 panic。

**功能归纳（第1部分）：**

这段 `nodes.go` 代码的主要功能是 **将 Go 语言抽象语法树 (AST) 的一部分节点（主要是表达式、基础类型和函数相关的节点）转换成格式化的源代码文本**。 它包含了处理换行、空白、注释以及各种Go语言语法结构（如标识符列表、表达式列表、参数列表、函数签名等）的逻辑。  它专注于将 AST 结构转化为符合 Go 语言风格规范的字符串表示。

### 提示词
```
这是路径为go/src/go/printer/nodes.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements printing of AST nodes; specifically
// expressions, statements, declarations, and files. It uses
// the print functionality implemented in printer.go.

package printer

import (
	"go/ast"
	"go/token"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Formatting issues:
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
// is set, the first line break is printed as formfeed. Returns 0 if no line
// breaks were printed, returns 1 if there was exactly one newline printed,
// and returns a value > 1 if there was a formfeed or more than one newline
// printed.
//
// TODO(gri): linebreak may add too many lines if the next statement at "line"
// is preceded by comments because the computation of n assumes
// the current position before the comment and the target position
// after the comment. Thus, after interspersing such comments, the
// space taken up by them is not considered to reduce the number of
// linebreaks. At the moment there is no easy way to know about
// future (not yet interspersed) comments in this function.
func (p *printer) linebreak(line, min int, ws whiteSpace, newSection bool) (nbreaks int) {
	n := max(nlimit(line-p.pos.Line), min)
	if n > 0 {
		p.print(ws)
		if newSection {
			p.print(formfeed)
			n--
			nbreaks = 2
		}
		nbreaks += n
		for ; n > 0; n-- {
			p.print(newline)
		}
	}
	return
}

// setComment sets g as the next comment if g != nil and if node comments
// are enabled - this mode is used when printing source code fragments such
// as exports only. It assumes that there is no pending comment in p.comments
// and at most one pending comment in the p.comment cache.
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
		p.flush(p.posFor(g.List[0].Pos()), token.ILLEGAL)
		p.comments = p.comments[0:1]
		// in debug mode, report error
		p.internalError("setComment found pending comments")
	}
	p.comments[0] = g
	p.cindex = 0
	// don't overwrite any pending comment in the p.comment cache
	// (there may be a pending comment when a line comment is
	// immediately followed by a lead comment with no other
	// tokens between)
	if p.commentOffset == infinity {
		p.nextComment() // get comment ready for use
	}
}

type exprListMode uint

const (
	commaTerm exprListMode = 1 << iota // list is optionally terminated by a comma
	noIndent                           // no extra indentation in multi-line lists
)

// If indent is set, a multi-line identifier list is indented after the
// first linebreak encountered.
func (p *printer) identList(list []*ast.Ident, indent bool) {
	// convert into an expression list so we can re-use exprList formatting
	xlist := make([]ast.Expr, len(list))
	for i, x := range list {
		xlist[i] = x
	}
	var mode exprListMode
	if !indent {
		mode = noIndent
	}
	p.exprList(token.NoPos, xlist, 1, mode, token.NoPos, false)
}

const filteredMsg = "contains filtered or unexported fields"

// Print a list of expressions. If the list spans multiple
// source lines, the original line breaks are respected between
// expressions.
//
// TODO(gri) Consider rewriting this to be independent of []ast.Expr
// so that we can use the algorithm for any kind of list
//
//	(e.g., pass list via a channel over which to range).
func (p *printer) exprList(prev0 token.Pos, list []ast.Expr, depth int, mode exprListMode, next0 token.Pos, isIncomplete bool) {
	if len(list) == 0 {
		if isIncomplete {
			prev := p.posFor(prev0)
			next := p.posFor(next0)
			if prev.IsValid() && prev.Line == next.Line {
				p.print("/* " + filteredMsg + " */")
			} else {
				p.print(newline)
				p.print(indent, "// "+filteredMsg, unindent, newline)
			}
		}
		return
	}

	prev := p.posFor(prev0)
	next := p.posFor(next0)
	line := p.lineFor(list[0].Pos())
	endLine := p.lineFor(list[len(list)-1].End())

	if prev.IsValid() && prev.Line == line && line == endLine {
		// all list entries on a single line
		for i, x := range list {
			if i > 0 {
				// use position of expression following the comma as
				// comma position for correct comment placement
				p.setPos(x.Pos())
				p.print(token.COMMA, blank)
			}
			p.expr0(x, depth)
		}
		if isIncomplete {
			p.print(token.COMMA, blank, "/* "+filteredMsg+" */")
		}
		return
	}

	// list entries span multiple lines;
	// use source code positions to guide line breaks

	// Don't add extra indentation if noIndent is set;
	// i.e., pretend that the first line is already indented.
	ws := ignore
	if mode&noIndent == 0 {
		ws = indent
	}

	// The first linebreak is always a formfeed since this section must not
	// depend on any previous formatting.
	prevBreak := -1 // index of last expression that was followed by a linebreak
	if prev.IsValid() && prev.Line < line && p.linebreak(line, 0, ws, true) > 0 {
		ws = ignore
		prevBreak = 0
	}

	// initialize expression/key size: a zero value indicates expr/key doesn't fit on a single line
	size := 0

	// We use the ratio between the geometric mean of the previous key sizes and
	// the current size to determine if there should be a break in the alignment.
	// To compute the geometric mean we accumulate the ln(size) values (lnsum)
	// and the number of sizes included (count).
	lnsum := 0.0
	count := 0

	// print all list elements
	prevLine := prev.Line
	for i, x := range list {
		line = p.lineFor(x.Pos())

		// Determine if the next linebreak, if any, needs to use formfeed:
		// in general, use the entire node size to make the decision; for
		// key:value expressions, use the key size.
		// TODO(gri) for a better result, should probably incorporate both
		//           the key and the node size into the decision process
		useFF := true

		// Determine element size: All bets are off if we don't have
		// position information for the previous and next token (likely
		// generated code - simply ignore the size in this case by setting
		// it to 0).
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

		// If the previous line and the current line had single-
		// line-expressions and the key sizes are small or the
		// ratio between the current key and the geometric mean
		// if the previous key sizes does not exceed a threshold,
		// align columns and do not use formfeed.
		if prevSize > 0 && size > 0 {
			const smallSize = 40
			if count == 0 || prevSize <= smallSize && size <= smallSize {
				useFF = false
			} else {
				const r = 2.5                               // threshold
				geomean := math.Exp(lnsum / float64(count)) // count > 0
				ratio := float64(size) / geomean
				useFF = r*ratio <= 1 || r <= ratio
			}
		}

		needsLinebreak := 0 < prevLine && prevLine < line
		if i > 0 {
			// Use position of expression following the comma as
			// comma position for correct comment placement, but
			// only if the expression is on the same line.
			if !needsLinebreak {
				p.setPos(x.Pos())
			}
			p.print(token.COMMA)
			needsBlank := true
			if needsLinebreak {
				// Lines are broken using newlines so comments remain aligned
				// unless useFF is set or there are multiple expressions on
				// the same line in which case formfeed is used.
				nbreaks := p.linebreak(line, 0, ws, useFF || prevBreak+1 < i)
				if nbreaks > 0 {
					ws = ignore
					prevBreak = i
					needsBlank = false // we got a line break instead
				}
				// If there was a new section or more than one new line
				// (which means that the tabwriter will implicitly break
				// the section), reset the geomean variables since we are
				// starting a new group of elements with the next element.
				if nbreaks > 1 {
					lnsum = 0
					count = 0
				}
			}
			if needsBlank {
				p.print(blank)
			}
		}

		if len(list) > 1 && isPair && size > 0 && needsLinebreak {
			// We have a key:value expression that fits onto one line
			// and it's not on the same line as the prior expression:
			// Use a column for the key such that consecutive entries
			// can align if possible.
			// (needsLinebreak is set if we started a new line before)
			p.expr(pair.Key)
			p.setPos(pair.Colon)
			p.print(token.COLON, vtab)
			p.expr(pair.Value)
		} else {
			p.expr0(x, depth)
		}

		if size > 0 {
			lnsum += math.Log(float64(size))
			count++
		}

		prevLine = line
	}

	if mode&commaTerm != 0 && next.IsValid() && p.pos.Line < next.Line {
		// Print a terminating comma if the next token is on a new line.
		p.print(token.COMMA)
		if isIncomplete {
			p.print(newline)
			p.print("// " + filteredMsg)
		}
		if ws == ignore && mode&noIndent == 0 {
			// unindent if we indented
			p.print(unindent)
		}
		p.print(formfeed) // terminating comma needs a line break to look good
		return
	}

	if isIncomplete {
		p.print(token.COMMA, newline)
		p.print("// "+filteredMsg, newline)
	}

	if ws == ignore && mode&noIndent == 0 {
		// unindent if we indented
		p.print(unindent)
	}
}

type paramMode int

const (
	funcParam paramMode = iota
	funcTParam
	typeTParam
)

func (p *printer) parameters(fields *ast.FieldList, mode paramMode) {
	openTok, closeTok := token.LPAREN, token.RPAREN
	if mode != funcParam {
		openTok, closeTok = token.LBRACK, token.RBRACK
	}
	p.setPos(fields.Opening)
	p.print(openTok)
	if len(fields.List) > 0 {
		prevLine := p.lineFor(fields.Opening)
		ws := indent
		for i, par := range fields.List {
			// determine par begin and end line (may be different
			// if there are multiple parameter names for this par
			// or the type is on a separate line)
			parLineBeg := p.lineFor(par.Pos())
			parLineEnd := p.lineFor(par.End())
			// separating "," if needed
			needsLinebreak := 0 < prevLine && prevLine < parLineBeg
			if i > 0 {
				// use position of parameter following the comma as
				// comma position for correct comma placement, but
				// only if the next parameter is on the same line
				if !needsLinebreak {
					p.setPos(par.Pos())
				}
				p.print(token.COMMA)
			}
			// separator if needed (linebreak or blank)
			if needsLinebreak && p.linebreak(parLineBeg, 0, ws, true) > 0 {
				// break line if the opening "(" or previous parameter ended on a different line
				ws = ignore
			} else if i > 0 {
				p.print(blank)
			}
			// parameter names
			if len(par.Names) > 0 {
				// Very subtle: If we indented before (ws == ignore), identList
				// won't indent again. If we didn't (ws == indent), identList will
				// indent if the identList spans multiple lines, and it will outdent
				// again at the end (and still ws == indent). Thus, a subsequent indent
				// by a linebreak call after a type, or in the next multi-line identList
				// will do the right thing.
				p.identList(par.Names, ws == indent)
				p.print(blank)
			}
			// parameter type
			p.expr(stripParensAlways(par.Type))
			prevLine = parLineEnd
		}

		// if the closing ")" is on a separate line from the last parameter,
		// print an additional "," and line break
		if closing := p.lineFor(fields.Closing); 0 < prevLine && prevLine < closing {
			p.print(token.COMMA)
			p.linebreak(closing, 0, ignore, true)
		} else if mode == typeTParam && fields.NumFields() == 1 && combinesWithName(stripParensAlways(fields.List[0].Type)) {
			// A type parameter list [P T] where the name P and the type expression T syntactically
			// combine to another valid (value) expression requires a trailing comma, as in [P *T,]
			// (or an enclosing interface as in [P interface(*T)]), so that the type parameter list
			// is not parsed as an array length [P*T].
			p.print(token.COMMA)
		}

		// unindent if we indented
		if ws == ignore {
			p.print(unindent)
		}
	}

	p.setPos(fields.Closing)
	p.print(closeTok)
}

// combinesWithName reports whether a name followed by the expression x
// syntactically combines to another valid (value) expression. For instance
// using *T for x, "name *T" syntactically appears as the expression x*T.
// On the other hand, using  P|Q or *P|~Q for x, "name P|Q" or "name *P|~Q"
// cannot be combined into a valid (value) expression.
func combinesWithName(x ast.Expr) bool {
	switch x := x.(type) {
	case *ast.StarExpr:
		// name *x.X combines to name*x.X if x.X is not a type element
		return !isTypeElem(x.X)
	case *ast.BinaryExpr:
		return combinesWithName(x.X) && !isTypeElem(x.Y)
	case *ast.ParenExpr:
		return !isTypeElem(x.X)
	}
	return false
}

// isTypeElem reports whether x is a (possibly parenthesized) type element expression.
// The result is false if x could be a type element OR an ordinary (value) expression.
func isTypeElem(x ast.Expr) bool {
	switch x := x.(type) {
	case *ast.ArrayType, *ast.StructType, *ast.FuncType, *ast.InterfaceType, *ast.MapType, *ast.ChanType:
		return true
	case *ast.UnaryExpr:
		return x.Op == token.TILDE
	case *ast.BinaryExpr:
		return isTypeElem(x.X) || isTypeElem(x.Y)
	case *ast.ParenExpr:
		return isTypeElem(x.X)
	}
	return false
}

func (p *printer) signature(sig *ast.FuncType) {
	if sig.TypeParams != nil {
		p.parameters(sig.TypeParams, funcTParam)
	}
	if sig.Params != nil {
		p.parameters(sig.Params, funcParam)
	} else {
		p.print(token.LPAREN, token.RPAREN)
	}
	res := sig.Results
	n := res.NumFields()
	if n > 0 {
		// res != nil
		p.print(blank)
		if n == 1 && res.List[0].Names == nil {
			// single anonymous res; no ()'s
			p.expr(stripParensAlways(res.List[0].Type))
			return
		}
		p.parameters(res, funcParam)
	}
}

func identListSize(list []*ast.Ident, maxSize int) (size int) {
	for i, x := range list {
		if i > 0 {
			size += len(", ")
		}
		size += utf8.RuneCountInString(x.Name)
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
	p.setComment(&ast.CommentGroup{List: []*ast.Comment{{Slash: token.NoPos, Text: text}}})
}

func (p *printer) fieldList(fields *ast.FieldList, isStruct, isIncomplete bool) {
	lbrace := fields.Opening
	list := fields.List
	rbrace := fields.Closing
	hasComments := isIncomplete || p.commentBefore(p.posFor(rbrace))
	srcIsOneLine := lbrace.IsValid() && rbrace.IsValid() && p.lineFor(lbrace) == p.lineFor(rbrace)

	if !hasComments && srcIsOneLine {
		// possibly a one-line struct/interface
		if len(list) == 0 {
			// no blank between keyword and {} in this case
			p.setPos(lbrace)
			p.print(token.LBRACE)
			p.setPos(rbrace)
			p.print(token.RBRACE)
			return
		} else if p.isOneLineFieldList(list) {
			// small enough - print on one line
			// (don't use identList and ignore source line breaks)
			p.setPos(lbrace)
			p.print(token.LBRACE, blank)
			f := list[0]
			if isStruct {
				for i, x := range f.Names {
					if i > 0 {
						// no comments so no need for comma position
						p.print(token.COMMA, blank)
					}
					p.expr(x)
				}
				if len(f.Names) > 0 {
					p.print(blank)
				}
				p.expr(f.Type)
			} else { // interface
				if len(f.Names) > 0 {
					name := f.Names[0] // method name
					p.expr(name)
					p.signature(f.Type.(*ast.FuncType)) // don't print "func"
				} else {
					// embedded interface
					p.expr(f.Type)
				}
			}
			p.print(blank)
			p.setPos(rbrace)
			p.print(token.RBRACE)
			return
		}
	}
	// hasComments || !srcIsOneLine

	p.print(blank)
	p.setPos(lbrace)
	p.print(token.LBRACE, indent)
	if hasComments || len(list) > 0 {
		p.print(formfeed)
	}

	if isStruct {

		sep := vtab
		if len(list) == 1 {
			sep = blank
		}
		var line int
		for i, f := range list {
			if i > 0 {
				p.linebreak(p.lineFor(f.Pos()), 1, ignore, p.linesFrom(line) > 0)
			}
			extraTabs := 0
			p.setComment(f.Doc)
			p.recordLine(&line)
			if len(f.Names) > 0 {
				// named fields
				p.identList(f.Names, false)
				p.print(sep)
				p.expr(f.Type)
				extraTabs = 1
			} else {
				// anonymous field
				p.expr(f.Type)
				extraTabs = 2
			}
			if f.Tag != nil {
				if len(f.Names) > 0 && sep == vtab {
					p.print(sep)
				}
				p.print(sep)
				p.expr(f.Tag)
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
			p.flush(p.posFor(rbrace), token.RBRACE) // make sure we don't lose the last line comment
			p.setLineComment("// " + filteredMsg)
		}

	} else { // interface

		var line int
		var prev *ast.Ident // previous "type" identifier
		for i, f := range list {
			var name *ast.Ident // first name, or nil
			if len(f.Names) > 0 {
				name = f.Names[0]
			}
			if i > 0 {
				// don't do a line break (min == 0) if we are printing a list of types
				// TODO(gri) this doesn't work quite right if the list of types is
				//           spread across multiple lines
				min := 1
				if prev != nil && name == prev {
					min = 0
				}
				p.linebreak(p.lineFor(f.Pos()), min, ignore, p.linesFrom(line) > 0)
			}
			p.setComment(f.Doc)
			p.recordLine(&line)
			if name != nil {
				// method
				p.expr(name)
				p.signature(f.Type.(*ast.FuncType)) // don't print "func"
				prev = nil
			} else {
				// embedded interface
				p.expr(f.Type)
				prev = nil
			}
			p.setComment(f.Comment)
		}
		if isIncomplete {
			if len(list) > 0 {
				p.print(formfeed)
			}
			p.flush(p.posFor(rbrace), token.RBRACE) // make sure we don't lose the last line comment
			p.setLineComment("// contains filtered or unexported methods")
		}

	}
	p.print(unindent, formfeed)
	p.setPos(rbrace)
	p.print(token.RBRACE)
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
		maxProblem = max(maxProblem, mp)
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
		maxProblem = max(maxProblem, mp)

	case *ast.StarExpr:
		if e.Op == token.QUO { // `*/`
			maxProblem = 5
		}

	case *ast.UnaryExpr:
		switch e.Op.String() + r.Op.String() {
		case "/*", "&&", "&^":
			maxProblem = 5
		case "++", "--":
			maxProblem = max(maxProblem, 4)
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
//
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
//  1. If there is a binary operator with a right side unary operand
//     that would clash without a space, the cutoff must be (in order):
//
//     /*	6
//     &&	6
//     &^	6
//     ++	5
//     --	5
//
//     (Comparison operators always have spaces around them.)
//
//  2. If there is a mix of level 5 and level 4 operators, then the cutoff
//     is 5 (use spaces to distinguish precedence) in Normal mode
//     and 4 (never use spaces) in Compact mode.
//
//  3. If there are no level 4 operators or no level 5 operators, then the
//     cutoff is 6 (always use spaces) in Normal mode
//     and 4 (never use spaces) in Compact mode.
func (p *printer) binaryExpr(x *ast.BinaryExpr, prec1, cutoff, depth int) {
	prec := x.Op.Precedence()
	if prec < prec1 {
		// parenthesis needed
		// Note: The parser inserts an ast.ParenExpr node; thus this case
		//       can only occur if the AST is created in a different way.
		p.print(token.LPAREN)
		p.expr0(x, reduceDepth(depth)) // parentheses undo one level of depth
		p.print(token.RPAREN)
		return
	}

	printBlank := prec < cutoff

	ws := indent
	p.expr1(x.X, prec, depth+diffPrec(x.X, prec))
	if printBlank {
		p.print(blank)
	}
	xline := p.pos.Line // before the operator (it may be on the next line!)
	yline := p.lineFor(x.Y.Pos())
	p.setPos(x.OpPos)
	p.print(x.Op)
	if xline != yline && xline > 0 && yline > 0 {
		// at least one line break, but respect an extra empty line
		// in the source
		if p.linebreak(yline, 1, ws, true) > 0 {
			ws = ignore
			printBlank = false // no blank after line break
		}
	}
	if printBlank {
		p.print(blank)
	}
	p.expr1(x.Y, prec+1, depth+1)
	if ws == ignore {
		p.print(unindent)
	}
}

func isBinary(expr ast.Expr) bool {
	_, ok := expr.(*ast.BinaryExpr)
	return ok
}

func (p *printer) expr1(expr ast.Expr, prec1, depth int) {
	p.setPos(expr.Pos())

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
		p.binaryExpr(x, prec1, cutoff(x, depth), depth)

	case *ast.KeyValueExpr:
		p.expr(x.Key)
		p.setPos(x.Colon)
		p.print(token.COLON, blank)
		p.expr(x.Value)

	case *ast.StarExpr:
		const prec = token.UnaryPrec
		if prec < prec1 {
			// parenthesis needed
			p.print(token.LPAREN)
			p.print(token.MUL)
			p.expr(x.X)
			p.print(token.RPAREN)
		} else {
			// no parenthesis needed
			p.print(token.MUL)
			p.expr(x.X)
		}

	case *ast.UnaryExpr:
		const prec = token.UnaryPrec
		if prec < prec1 {
			// parenthesis needed
			p.print(token.LPAREN)
			p.expr(x)
			p.print(token.RPAREN)
		} else {
			// no parenthesis needed
			p.print(x.Op)
			if x.Op == token.RANGE {
				// TODO(gri) Remove this code if it cannot be reached.
				p.print(blank)
			}
			p.expr1(x.X, prec, depth)
		}

	case *ast.BasicLit:
		if p.Config.Mode&normalizeNumbers != 0 {
			x = normalizedNumber(x)
		}
		p.print(x)

	case *ast.FuncLit:
		p.setPos(x.Type.Pos())
		p.print(token.FUNC)
		// See the comment in funcDecl about how the header size is computed.
		startCol := p.out.Column - len("func")
		p.signature(x.Type)
		p.funcBody(p.distanceFrom(x.Type.Pos(), startCol), blank, x.Body)

	case *ast.ParenExpr:
		if _, hasParens := x.X.(*ast.ParenExpr); hasParens {
			// don't print parentheses around an already parenthesized expression
			// TODO(gri) consider making this more general and incorporate precedence levels
			p.expr0(x.X, depth)
		} else {
			p.print(token.LPAREN)
			p.expr0(x.X, reduceDepth(depth)) // parentheses undo one level of depth
			p.setPos(x.Rparen)
			p.print(token.RPAREN)
		}

	case *ast.SelectorExpr:
		p.selectorExpr(x, depth, false)

	case *ast.TypeAssertExpr:
		p.expr1(x.X, token.HighestPrec, depth)
		p.print(token.PERIOD)
		p.setPos(x.Lparen)
		p.print(token.LPAREN)
		if x.Type != nil {
			p.expr(x.Type)
		} else {
			p.print(token.TYPE)
		}
		p.setPos(x.Rparen)
		p.print(token.RPAREN)

	case *ast.IndexExpr:
		// TODO(gri): should treat[] like parentheses and undo one level of depth
		p.expr1(x.X, token.HighestPrec, 1)
		p.setPos(x.Lbrack)
		p.print(token.LBRACK)
		p.expr0(x.Index, depth+1)
		p.setPos(x.Rbrack)
		p.print(token.RBRACK)

	case *ast.IndexListExpr:
		// TODO(gri): as for IndexExpr, should treat [] like parentheses and undo
		// one level of depth
		p.expr1(x.X, token.HighestPrec, 1)
		p.setPos(x.Lbrack)
		p.print(token.LBRACK)
		p.exprList(x.Lbrack, x.Indices, depth+1, commaTerm, x.Rbrack, false)
		p.setPos(x.Rbrack)
		p.print(token.RBRACK)

	case *ast.SliceExpr:
		// TODO(gri): should treat[] like parentheses and undo one level of depth
		p.expr1(x.X, token.HighestPrec, 1)
		p.setPos(x.Lbrack)
		p.print(token.LBRACK)
		indices := []ast.Expr{x.Low, x.High}
		if x.Max != nil {
			indices = append(indices, x.Max)
		}
		// determine if we need extra blanks around ':'
		var needsBlanks bool
		if depth <= 1 {
			var indexCount int
			var hasBinaries bool
			for _, x := range indices {
				if x != nil {
					indexCount++
					if isBinary(x) {
						hasBinaries = true
					}
				}
			}
			if indexCount > 1 && hasBinaries {
				needsBlanks = true
			}
		}
		for i, x := range indices {
			if i > 0 {
				if indices[i-1] != nil && needsBlanks {
					p.print(blank)
				}
				p.print(token.COLON)
				if x != nil && needsBlanks {
					p.print(blank)
				}
			}
			if x != nil {
				p.expr0(x, depth+1)
			}
		}
		p.setPos(x.Rbrack)
		p.print(token.RBRACK)

	case *ast.CallExpr:
		if len(x.Args) > 1 {
			depth++
		}

		// Conversions to literal function types or <-chan
		// types require parentheses around the type.
		paren := false
		switch t := x.Fun.(type) {
		case *ast.FuncType:
			paren = true
		case *ast.ChanType:
			paren = t.Dir == ast.RECV
		}
		if paren {
			p.print(token.LPAREN)
		}
		wasIndented := p.possibleSelectorExpr(x.Fun, token.HighestPrec, depth)
		if paren {
			p.print(token.RPAREN)
		}

		p.setPos(x.Lparen)
		p.print(token.LPAREN)
		if x.Ellipsis.IsValid() {
			p.exprList(x.Lparen, x.Args, depth, 0, x.Ellipsis, false)
			p.setPos(x.Ellipsis)
			p.print(token.ELLIPSIS)
			if x.Rparen.IsValid() && p.lineFor(x.Ellipsis) < p.lineFor(x.Rparen) {
				p.print(token.COMMA, formfeed)
			}
		} else {
			p.exprList(x.Lparen, x.Args, depth, commaTerm, x.Rparen, false)
		}
		p.setPos(x.Rparen)
		p.print(token.RPAREN)
		if wasIndented {
			p.print(unindent)
		}

	case *ast.CompositeLit:
		// composite literal elements that are composite literals themselves may have the type omitted
		if x.Type != nil {
			p.expr1(x.Type, token.HighestPrec, depth)
		}
		p.level++
		p.setPos(x.Lbrace)
		p.print(token.LBRACE)
		p.exprList(x.Lbrace, x.Elts, 1, commaTerm, x.Rbrace, x.Incomplete)
		// do not insert extra line break following a /*-style comment
		// before the closing '}' as it might break the code if there
		// is no trailing ','
		mode := noExtraLinebreak
		// do not insert extra blank following a /*-style comment
		// before the closing '}' unless the literal is empty
		if len(x.Elts) > 0 {
			mode |= noExtraBlank
		}
		// need the initial indent to print lone comments with
		// the proper level of indentation
		p.print(indent, unindent, mode)
		p.setPos(x.Rbrace)
		p.print(token.RBRACE, mode)
		p.level--

	case *ast.Ellipsis:
		p.print(token.ELLIPSIS)
		if x.Elt != nil {
			p.expr(x.Elt)
		}

	case *ast.ArrayType:
		p.print(token.LBRACK)
		if x.Len != nil {
			p.expr(x.Len)
		}
		p.print(token.RBRACK)
		p.expr(x.Elt)

	case *ast.StructType:
		p.print(token.STRUCT)
		p.fieldList(x.Fields, true, x.Incomplete)

	case *ast.FuncType:
		p.print(token.FUNC)
		p.signature(x)

	case *ast.InterfaceType:
		p.print(token.INTERFACE)
		p.fieldList(x.Methods, false, x.Incomplete)

	case *ast.MapType:
		p.print(token.MAP, token.LBRACK)
		p.expr(x.Key)
		p.print(token.RBRACK)
		p.expr(x.Value)

	case *ast.ChanType:
		switch x.Dir {
		case ast.SEND | ast.RECV:
			p.print(token.CHAN)
		case ast.RECV:
			p.print(token.ARROW, token.CHAN) // x.Arrow and x.Pos() are the same
		case ast.SEND:
			p.print(token.CHAN)
			p.setPos(x.Arrow)
			p.print(token.ARROW)
		}
		p.print(blank)
		p.expr(x.Value)

	default:
		panic("unreachable")
	}
}

// normalizedNumber rewrites base prefixes and exponents
// of numbers to use lower-case letters (0X123 to 0x123 and 1.2E3 to 1.2e3),
// and removes leading 0's from integer imaginary literals (0765i to 765i).
// It leaves hexadecimal digits alone.
//
// normalizedNumber doesn't modify the ast.BasicLit value lit points to.
// If lit is not a number or a number in canonical format already,
// lit is returned as is. Otherwise a new ast.BasicLit is created.
func normalizedNumber(lit *ast.BasicLit) *ast.BasicLit {
	if lit.Kind != token.INT && lit.Kind != token.FLOAT && lit.Kind != token.IMAG {
		return lit // not a number - nothing to do
	}
	if len(lit.Value) < 2 {
		return lit // only one digit (common case) - nothing to do
	}
	// len(lit.Value) >= 2

	// We ignore lit.Kind because for lit.Kind == token.IMAG the literal may be an integer
	// or floating-point value, decimal or not. Instead, just consider the literal pattern.
	x := lit.Value
	switch x[:2] {
	default:
		// 0-prefix octal, decimal int, or float (possibly with 'i' suffix)
		if i := strings.LastIndexByte(x, 'E'); i >= 0 {
			x = x[:i] + "e" + x[i+1:]
			break
		}
		// remove leading 0's from integer (but not floating-point) imaginary literals
		if x[len(x)-1] == 'i' && !strings.ContainsAny(x, ".e") {
			x = strings.TrimLeft(x, "0_")
			if x == "i" {
				x = "0i"
			}
		}
	case "0X":
		x = "0x" + x[2:]
		// possibly a hexadecimal float
		if i := strings.LastIndexByte(x, 'P'); i >= 0 {
			x = x[:i] + "p" + x[i+1:]
		}
	case "0x":
		// possibly a hexadecimal float
		i := strings.LastIndexByte(x, 'P')
		if i == -1 {
			return lit // nothing to do
		}
		x = x[:i] + "p" + x[i+1:]
	case "0O":
		x = "0o" + x[2:]
	case "0o":
		return lit // nothing to do
	case "0B":
		x = "0b" + x[2:]
	case "0b":
		return lit // nothing to do
	}

	return &ast.BasicLit{ValuePos: lit.ValuePos, Kind: lit.Kind, Value: x}
}

func (p *printer) possibleSelectorExpr(expr ast.Expr, prec1, depth int) bool {
	if x, ok := expr.(*ast.SelectorExpr); ok {
		return p.selectorExpr(x, depth, true)
	}
	p.expr1(expr, prec1, depth)
	return false
}

// selectorExpr handles an *ast.SelectorExpr node and reports whether x spans
// multiple lines.
func (p *printer) selectorExpr(x *ast.SelectorExpr, depth int, isMethod bool) bool {
	p.expr1(x.X, token.HighestPrec, depth)
	p.print(token.PERIOD)
	if line := p.lineFor(x.Sel.Pos()); p.pos.IsValid() && p.pos.Line < line {
		p.print(indent, newline)
		p.setPos(x.Sel.Pos())
		p.print(x.Sel)
		if !isMethod {
			p.print(unindent)
		}
		return true
	}
	p.setPos(x.Sel.Pos())
	p.print(x.Sel)
	return false
}

func (p *printer) expr0(x ast.Expr, depth int) {
	p.expr1(x, token.LowestPrec, depth)
}

func (p *printer) expr(x ast.Expr) {
	const depth = 1
	p.expr1(x, token.LowestPrec, depth)
}

// ----------------------------------------------------------------------------
// Statements

// Print the statement list indented, but without a newline after the last statement.
// Extra line breaks between statements in the source are respected but at most one
// empty line is printed between statements.
func (p *printer) stmtList(list []ast.Stmt, nindent int, nextI
```