Response:
Let's break down the thought process for analyzing this Go code snippet and generating the summary.

**1. Initial Reading and High-Level Understanding:**

The first step is to read through the code to get a general idea of what it's doing. Keywords like `printer`, `stmt`, `block`, `expr`, `decl`, `file` immediately suggest this code is responsible for formatting Go code. The structure with functions taking AST nodes (`*ast.BlockStmt`, `*ast.Expr`, etc.) as arguments reinforces this idea. The `p *printer` receiver on many functions confirms it's a method set for a `printer` type.

**2. Identifying Core Functionalities by Analyzing Key Functions:**

Next, focus on the key functions and their roles:

* **`stmtList`:** Processes a list of statements, handling indentation and line breaks. The logic around `nindent` and `nextIsRBrace` hints at formatting code blocks.
* **`block`:**  Specifically handles formatting code blocks enclosed in `{}`. It calls `stmtList`.
* **`isTypeName` and `stripParens`:** These look like utility functions to simplify expressions, likely for better formatting. `stripParens`'s comment about composite literals is a crucial detail.
* **`controlClause`:**  Deals with the conditional parts of control flow statements (`if`, `for`, `switch`). The logic around semicolons is important.
* **`stmt`:**  This is the central function for formatting individual statements. The large `switch` statement within it processes different statement types. This is a key area to understand the code's scope.
* **`valueSpec` and `spec`:** These functions seem responsible for formatting variable and constant declarations (`valueSpec`) and more general specifications like imports and types (`spec`).
* **`genDecl`:** Handles formatting general declarations, including grouped declarations within parentheses. The `keepTypeColumn` function called within this is an interesting detail.
* **`funcDecl` and `decl`:**  Deal with formatting function declarations and general declarations, respectively.
* **`file`:** This function processes the entire Go source file, starting with the `package` declaration.

**3. Inferring the Overall Goal:**

By examining these key functions, the overall purpose becomes clear: this code implements a Go code printer (formatter). It takes the Abstract Syntax Tree (AST) of a Go program as input and outputs formatted Go source code.

**4. Identifying Specific Go Language Features and Providing Examples:**

Based on the function names and the `ast` package types used, we can identify the Go language features being handled:

* **Statements:**  The `stmt` function covers a wide range of statements like assignments, control flow (`if`, `for`, `switch`, `select`), function calls (`GoStmt`, `DeferStmt`), return statements, etc. Providing simple examples for a few of these makes the explanation concrete.
* **Declarations:** The `decl` and related functions handle various declarations: `const`, `var`, `type`, `import`, and `func`. Again, simple examples are helpful.
* **Blocks:** The `block` function explicitly handles code blocks.
* **Expressions:** While there isn't a single `expr` function in the snippet,  the code frequently calls `p.expr()` on parts of statements and declarations, indicating it handles expressions within these contexts. The `stripParens` function is relevant here.
* **Control Flow:**  `controlClause` directly relates to `if`, `for`, `switch`, and `select` statements.

**5. Code Reasoning (Hypothetical Input/Output):**

For some of the more complex functions, it's helpful to consider a simple input and what the expected formatted output would be. For instance, with `stmtList` and a list of simple assignment statements, the output would be the statements separated by newlines (or possibly on the same line if short). For `block`, the output would be the statements indented within curly braces.

**6. Command-Line Arguments (Not Applicable):**

Review the code for any interaction with command-line flags or arguments. In this snippet, there's no explicit handling of `os.Args` or the `flag` package, so this section is not applicable.

**7. Common Mistakes (Looking for Potential Issues):**

Think about how a user might misuse or misunderstand the formatting logic. The `stripParens` function's comment about composite literals suggests a potential point of confusion or unexpected behavior if someone manually constructs an AST. Also, the heuristics in `indentList` might not always produce the desired formatting in edge cases. Highlighting these areas provides valuable insight.

**8. Summarization (Part 2):**

Finally, for the "Part 2" summary, consolidate the findings. Reiterate the core function (Go code formatting) and briefly mention the key aspects of how it achieves this (processing AST nodes, handling indentation, line breaks, comments, and different language constructs).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Is this just about pretty-printing?"  **Correction:**  "It's more than just pretty-printing; it's about adhering to standard Go formatting conventions."
* **Focusing too much on individual lines:** **Correction:** Shift focus to the purpose of the functions and how they interact.
* **Overlooking comments:** **Correction:** Notice the frequent calls to `p.setComment`, highlighting the importance of comment handling.
* **Not explaining the role of the AST:** **Correction:** Emphasize that the code operates on the AST, which is crucial for understanding its input.

By following this structured approach, combining code reading, logical deduction, and focusing on the overall purpose, we can effectively analyze the Go code snippet and generate a comprehensive and informative summary.
这是第2部分的分析，让我们归纳一下`go/src/go/printer/nodes.go`这部分代码的主要功能：

**核心功能：Go 语言代码格式化**

总的来说，这部分 `nodes.go` 代码是 Go 语言 `go/printer` 包的核心组成部分，负责将 Go 语言程序的抽象语法树 (AST) 转换回格式化后的源代码文本。  它细致地处理了各种 Go 语言的语法结构，包括语句、声明、表达式等，并根据预设的规则进行排版和格式化。

**具体功能归纳：**

1. **语句格式化 (`stmt` 函数):**
   -  能够处理各种 Go 语言的语句类型，例如：
      -  空语句 (`EmptyStmt`)
      -  标签语句 (`LabeledStmt`)
      -  表达式语句 (`ExprStmt`)
      -  发送语句 (`SendStmt`)
      -  自增/自减语句 (`IncDecStmt`)
      -  赋值语句 (`AssignStmt`)
      -  Go 语句 (`GoStmt`)
      -  Defer 语句 (`DeferStmt`)
      -  返回语句 (`ReturnStmt`)
      -  跳转语句 (`BranchStmt`)
      -  代码块 (`BlockStmt`)
      -  If 语句 (`IfStmt`)
      -  Case 子句 (`CaseClause`)
      -  Switch 语句 (`SwitchStmt`)
      -  Type Switch 语句 (`TypeSwitchStmt`)
      -  Comm Clause (Select 语句的 Case) (`CommClause`)
      -  Select 语句 (`SelectStmt`)
      -  For 循环语句 (`ForStmt`)
      -  Range 循环语句 (`RangeStmt`)
   -  `stmt` 函数内部使用 `switch` 语句根据不同的语句类型调用相应的格式化逻辑。

2. **声明格式化 (`decl` 函数及相关函数):**
   -  能够处理各种 Go 语言的声明类型，例如：
      -  通用声明 (`GenDecl`)：包括 `const`, `type`, `var`, `import` 等。
      -  函数声明 (`FuncDecl`)
   -  `genDecl` 函数处理通用声明，并区分了带括号的批量声明和单个声明。
   -  `funcDecl` 函数专门处理函数声明，包括接收者、函数名、参数列表和函数体。
   -  `valueSpec` 函数用于格式化 `const` 和 `var` 的具体声明，处理类型和初始值。
   -  `spec` 函数用于格式化 `import`, `const`, `type`, `var` 等的单个规范。
   -  `keepTypeColumn` 函数用于决定在格式化一组 `const` 或 `var` 声明时，是否需要保持类型列的对齐。

3. **代码块格式化 (`block` 和 `stmtList` 函数):**
   -  `block` 函数负责格式化由花括号 `{}` 包围的代码块，它会调用 `stmtList` 来格式化代码块内的语句。
   -  `stmtList` 函数负责格式化语句列表，处理缩进、换行和空语句。

4. **表达式格式化 (间接通过调用 `p.expr` 等):**
   -  虽然没有直接的 `expr` 函数在这个代码片段中定义，但代码中多次调用 `p.expr`、`p.expr0` 和 `p.exprList`，表明这部分代码依赖于其他部分（未包含在此片段中）来处理表达式的格式化。
   -  `stripParens` 和 `stripParensAlways` 函数用于移除不必要的括号，以提高代码的可读性。

5. **控制子句格式化 (`controlClause` 函数):**
   -  专门处理 `if`, `for`, `switch` 等控制结构中的初始化语句、条件表达式和后置语句，并正确地添加分号和空格。

6. **导入路径处理 (`sanitizeImportPath` 函数):**
   -  `sanitizeImportPath` 函数用于清理和规范化导入声明中的路径字符串，确保其符合 Go 语言的规范。

7. **辅助功能:**
   -  `indentList` 函数用于判断一个表达式列表是否应该整体缩进，以提高多行列表的可读性。
   -  `nodeSize` 函数用于估算一个 AST 节点格式化后的大小，用于优化某些单行代码块的格式化。
   -  `bodySize` 函数是 `nodeSize` 针对代码块的特化版本。
   -  `funcBody` 函数用于格式化函数体，根据函数头和函数体的大小决定是否将函数体放在同一行。
   -  `distanceFrom` 函数用于计算当前输出位置与指定起始位置的列距。

8. **文件格式化 (`file` 和 `declList` 函数):**
   -  `file` 函数是格式化一个完整 Go 源代码文件的入口，它首先处理包名，然后调用 `declList` 来格式化文件中的所有顶级声明。
   -  `declList` 函数负责格式化顶级声明列表，并在不同的声明类型之间添加合适的空行。

**总结:**

这部分 `nodes.go` 代码专注于将 Go 语言的 AST 结构转化为符合 Go 语言编码规范的源代码文本。它通过一系列精心设计的函数，分别处理不同类型的语法结构，并运用一些启发式规则来提高代码的可读性。 这部分代码是 `go fmt` 等代码格式化工具的核心逻辑所在。

### 提示词
```
这是路径为go/src/go/printer/nodes.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
sRBrace bool) {
	if nindent > 0 {
		p.print(indent)
	}
	var line int
	i := 0
	for _, s := range list {
		// ignore empty statements (was issue 3466)
		if _, isEmpty := s.(*ast.EmptyStmt); !isEmpty {
			// nindent == 0 only for lists of switch/select case clauses;
			// in those cases each clause is a new section
			if len(p.output) > 0 {
				// only print line break if we are not at the beginning of the output
				// (i.e., we are not printing only a partial program)
				p.linebreak(p.lineFor(s.Pos()), 1, ignore, i == 0 || nindent == 0 || p.linesFrom(line) > 0)
			}
			p.recordLine(&line)
			p.stmt(s, nextIsRBrace && i == len(list)-1)
			// labeled statements put labels on a separate line, but here
			// we only care about the start line of the actual statement
			// without label - correct line for each label
			for t := s; ; {
				lt, _ := t.(*ast.LabeledStmt)
				if lt == nil {
					break
				}
				line++
				t = lt.Stmt
			}
			i++
		}
	}
	if nindent > 0 {
		p.print(unindent)
	}
}

// block prints an *ast.BlockStmt; it always spans at least two lines.
func (p *printer) block(b *ast.BlockStmt, nindent int) {
	p.setPos(b.Lbrace)
	p.print(token.LBRACE)
	p.stmtList(b.List, nindent, true)
	p.linebreak(p.lineFor(b.Rbrace), 1, ignore, true)
	p.setPos(b.Rbrace)
	p.print(token.RBRACE)
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

func stripParensAlways(x ast.Expr) ast.Expr {
	if x, ok := x.(*ast.ParenExpr); ok {
		return stripParensAlways(x.X)
	}
	return x
}

func (p *printer) controlClause(isForStmt bool, init ast.Stmt, expr ast.Expr, post ast.Stmt) {
	p.print(blank)
	needsBlank := false
	if init == nil && post == nil {
		// no semicolons required
		if expr != nil {
			p.expr(stripParens(expr))
			needsBlank = true
		}
	} else {
		// all semicolons required
		// (they are not separators, print them explicitly)
		if init != nil {
			p.stmt(init, false)
		}
		p.print(token.SEMICOLON, blank)
		if expr != nil {
			p.expr(stripParens(expr))
			needsBlank = true
		}
		if isForStmt {
			p.print(token.SEMICOLON, blank)
			needsBlank = false
			if post != nil {
				p.stmt(post, false)
				needsBlank = true
			}
		}
	}
	if needsBlank {
		p.print(blank)
	}
}

// indentList reports whether an expression list would look better if it
// were indented wholesale (starting with the very first element, rather
// than starting at the first line break).
func (p *printer) indentList(list []ast.Expr) bool {
	// Heuristic: indentList reports whether there are more than one multi-
	// line element in the list, or if there is any element that is not
	// starting on the same line as the previous one ends.
	if len(list) >= 2 {
		var b = p.lineFor(list[0].Pos())
		var e = p.lineFor(list[len(list)-1].End())
		if 0 < b && b < e {
			// list spans multiple lines
			n := 0 // multi-line element count
			line := b
			for _, x := range list {
				xb := p.lineFor(x.Pos())
				xe := p.lineFor(x.End())
				if line < xb {
					// x is not starting on the same
					// line as the previous one ended
					return true
				}
				if xb < xe {
					// x is a multi-line element
					n++
				}
				line = xe
			}
			return n > 1
		}
	}
	return false
}

func (p *printer) stmt(stmt ast.Stmt, nextIsRBrace bool) {
	p.setPos(stmt.Pos())

	switch s := stmt.(type) {
	case *ast.BadStmt:
		p.print("BadStmt")

	case *ast.DeclStmt:
		p.decl(s.Decl)

	case *ast.EmptyStmt:
		// nothing to do

	case *ast.LabeledStmt:
		// a "correcting" unindent immediately following a line break
		// is applied before the line break if there is no comment
		// between (see writeWhitespace)
		p.print(unindent)
		p.expr(s.Label)
		p.setPos(s.Colon)
		p.print(token.COLON, indent)
		if e, isEmpty := s.Stmt.(*ast.EmptyStmt); isEmpty {
			if !nextIsRBrace {
				p.print(newline)
				p.setPos(e.Pos())
				p.print(token.SEMICOLON)
				break
			}
		} else {
			p.linebreak(p.lineFor(s.Stmt.Pos()), 1, ignore, true)
		}
		p.stmt(s.Stmt, nextIsRBrace)

	case *ast.ExprStmt:
		const depth = 1
		p.expr0(s.X, depth)

	case *ast.SendStmt:
		const depth = 1
		p.expr0(s.Chan, depth)
		p.print(blank)
		p.setPos(s.Arrow)
		p.print(token.ARROW, blank)
		p.expr0(s.Value, depth)

	case *ast.IncDecStmt:
		const depth = 1
		p.expr0(s.X, depth+1)
		p.setPos(s.TokPos)
		p.print(s.Tok)

	case *ast.AssignStmt:
		var depth = 1
		if len(s.Lhs) > 1 && len(s.Rhs) > 1 {
			depth++
		}
		p.exprList(s.Pos(), s.Lhs, depth, 0, s.TokPos, false)
		p.print(blank)
		p.setPos(s.TokPos)
		p.print(s.Tok, blank)
		p.exprList(s.TokPos, s.Rhs, depth, 0, token.NoPos, false)

	case *ast.GoStmt:
		p.print(token.GO, blank)
		p.expr(s.Call)

	case *ast.DeferStmt:
		p.print(token.DEFER, blank)
		p.expr(s.Call)

	case *ast.ReturnStmt:
		p.print(token.RETURN)
		if s.Results != nil {
			p.print(blank)
			// Use indentList heuristic to make corner cases look
			// better (issue 1207). A more systematic approach would
			// always indent, but this would cause significant
			// reformatting of the code base and not necessarily
			// lead to more nicely formatted code in general.
			if p.indentList(s.Results) {
				p.print(indent)
				// Use NoPos so that a newline never goes before
				// the results (see issue #32854).
				p.exprList(token.NoPos, s.Results, 1, noIndent, token.NoPos, false)
				p.print(unindent)
			} else {
				p.exprList(token.NoPos, s.Results, 1, 0, token.NoPos, false)
			}
		}

	case *ast.BranchStmt:
		p.print(s.Tok)
		if s.Label != nil {
			p.print(blank)
			p.expr(s.Label)
		}

	case *ast.BlockStmt:
		p.block(s, 1)

	case *ast.IfStmt:
		p.print(token.IF)
		p.controlClause(false, s.Init, s.Cond, nil)
		p.block(s.Body, 1)
		if s.Else != nil {
			p.print(blank, token.ELSE, blank)
			switch s.Else.(type) {
			case *ast.BlockStmt, *ast.IfStmt:
				p.stmt(s.Else, nextIsRBrace)
			default:
				// This can only happen with an incorrectly
				// constructed AST. Permit it but print so
				// that it can be parsed without errors.
				p.print(token.LBRACE, indent, formfeed)
				p.stmt(s.Else, true)
				p.print(unindent, formfeed, token.RBRACE)
			}
		}

	case *ast.CaseClause:
		if s.List != nil {
			p.print(token.CASE, blank)
			p.exprList(s.Pos(), s.List, 1, 0, s.Colon, false)
		} else {
			p.print(token.DEFAULT)
		}
		p.setPos(s.Colon)
		p.print(token.COLON)
		p.stmtList(s.Body, 1, nextIsRBrace)

	case *ast.SwitchStmt:
		p.print(token.SWITCH)
		p.controlClause(false, s.Init, s.Tag, nil)
		p.block(s.Body, 0)

	case *ast.TypeSwitchStmt:
		p.print(token.SWITCH)
		if s.Init != nil {
			p.print(blank)
			p.stmt(s.Init, false)
			p.print(token.SEMICOLON)
		}
		p.print(blank)
		p.stmt(s.Assign, false)
		p.print(blank)
		p.block(s.Body, 0)

	case *ast.CommClause:
		if s.Comm != nil {
			p.print(token.CASE, blank)
			p.stmt(s.Comm, false)
		} else {
			p.print(token.DEFAULT)
		}
		p.setPos(s.Colon)
		p.print(token.COLON)
		p.stmtList(s.Body, 1, nextIsRBrace)

	case *ast.SelectStmt:
		p.print(token.SELECT, blank)
		body := s.Body
		if len(body.List) == 0 && !p.commentBefore(p.posFor(body.Rbrace)) {
			// print empty select statement w/o comments on one line
			p.setPos(body.Lbrace)
			p.print(token.LBRACE)
			p.setPos(body.Rbrace)
			p.print(token.RBRACE)
		} else {
			p.block(body, 0)
		}

	case *ast.ForStmt:
		p.print(token.FOR)
		p.controlClause(true, s.Init, s.Cond, s.Post)
		p.block(s.Body, 1)

	case *ast.RangeStmt:
		p.print(token.FOR, blank)
		if s.Key != nil {
			p.expr(s.Key)
			if s.Value != nil {
				// use position of value following the comma as
				// comma position for correct comment placement
				p.setPos(s.Value.Pos())
				p.print(token.COMMA, blank)
				p.expr(s.Value)
			}
			p.print(blank)
			p.setPos(s.TokPos)
			p.print(s.Tok, blank)
		}
		p.print(token.RANGE, blank)
		p.expr(stripParens(s.X))
		p.print(blank)
		p.block(s.Body, 1)

	default:
		panic("unreachable")
	}
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
//		const (
//			foobar int = 42 // comment
//			x          = 7  // comment
//			foo
//	             bar = 991
//		)
//
// leads to the type/values matrix below. A run of value columns (V) can
// be moved into the type column if there is no type for any of the values
// in that column (we only move entire columns so that they align properly).
//
//		matrix        formatted     result
//	                   matrix
//		T  V    ->    T  V     ->   true      there is a T and so the type
//		-  V          -  V          true      column must be kept
//		-  -          -  -          false
//		-  V          V  -          false     V is moved into T column
func keepTypeColumn(specs []ast.Spec) []bool {
	m := make([]bool, len(specs))

	populate := func(i, j int, keepType bool) {
		if keepType {
			for ; i < j; i++ {
				m[i] = true
			}
		}
	}

	i0 := -1 // if i0 >= 0 we are in a run and i0 is the start of the run
	var keepType bool
	for i, s := range specs {
		t := s.(*ast.ValueSpec)
		if t.Values != nil {
			if i0 < 0 {
				// start of a run of ValueSpecs with non-nil Values
				i0 = i
				keepType = false
			}
		} else {
			if i0 >= 0 {
				// end of a run
				populate(i0, i, keepType)
				i0 = -1
			}
		}
		if t.Type != nil {
			keepType = true
		}
	}
	if i0 >= 0 {
		// end of a run
		populate(i0, len(specs), keepType)
	}

	return m
}

func (p *printer) valueSpec(s *ast.ValueSpec, keepType bool) {
	p.setComment(s.Doc)
	p.identList(s.Names, false) // always present
	extraTabs := 3
	if s.Type != nil || keepType {
		p.print(vtab)
		extraTabs--
	}
	if s.Type != nil {
		p.expr(s.Type)
	}
	if s.Values != nil {
		p.print(vtab, token.ASSIGN, blank)
		p.exprList(token.NoPos, s.Values, 1, 0, token.NoPos, false)
		extraTabs--
	}
	if s.Comment != nil {
		for ; extraTabs > 0; extraTabs-- {
			p.print(vtab)
		}
		p.setComment(s.Comment)
	}
}

func sanitizeImportPath(lit *ast.BasicLit) *ast.BasicLit {
	// Note: An unmodified AST generated by go/parser will already
	// contain a backward- or double-quoted path string that does
	// not contain any invalid characters, and most of the work
	// here is not needed. However, a modified or generated AST
	// may possibly contain non-canonical paths. Do the work in
	// all cases since it's not too hard and not speed-critical.

	// if we don't have a proper string, be conservative and return whatever we have
	if lit.Kind != token.STRING {
		return lit
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return lit
	}

	// if the string is an invalid path, return whatever we have
	//
	// spec: "Implementation restriction: A compiler may restrict
	// ImportPaths to non-empty strings using only characters belonging
	// to Unicode's L, M, N, P, and S general categories (the Graphic
	// characters without spaces) and may also exclude the characters
	// !"#$%&'()*,:;<=>?[\]^`{|} and the Unicode replacement character
	// U+FFFD."
	if s == "" {
		return lit
	}
	const illegalChars = `!"#$%&'()*,:;<=>?[\]^{|}` + "`\uFFFD"
	for _, r := range s {
		if !unicode.IsGraphic(r) || unicode.IsSpace(r) || strings.ContainsRune(illegalChars, r) {
			return lit
		}
	}

	// otherwise, return the double-quoted path
	s = strconv.Quote(s)
	if s == lit.Value {
		return lit // nothing wrong with lit
	}
	return &ast.BasicLit{ValuePos: lit.ValuePos, Kind: token.STRING, Value: s}
}

// The parameter n is the number of specs in the group. If doIndent is set,
// multi-line identifier lists in the spec are indented when the first
// linebreak is encountered.
func (p *printer) spec(spec ast.Spec, n int, doIndent bool) {
	switch s := spec.(type) {
	case *ast.ImportSpec:
		p.setComment(s.Doc)
		if s.Name != nil {
			p.expr(s.Name)
			p.print(blank)
		}
		p.expr(sanitizeImportPath(s.Path))
		p.setComment(s.Comment)
		p.setPos(s.EndPos)

	case *ast.ValueSpec:
		if n != 1 {
			p.internalError("expected n = 1; got", n)
		}
		p.setComment(s.Doc)
		p.identList(s.Names, doIndent) // always present
		if s.Type != nil {
			p.print(blank)
			p.expr(s.Type)
		}
		if s.Values != nil {
			p.print(blank, token.ASSIGN, blank)
			p.exprList(token.NoPos, s.Values, 1, 0, token.NoPos, false)
		}
		p.setComment(s.Comment)

	case *ast.TypeSpec:
		p.setComment(s.Doc)
		p.expr(s.Name)
		if s.TypeParams != nil {
			p.parameters(s.TypeParams, typeTParam)
		}
		if n == 1 {
			p.print(blank)
		} else {
			p.print(vtab)
		}
		if s.Assign.IsValid() {
			p.print(token.ASSIGN, blank)
		}
		p.expr(s.Type)
		p.setComment(s.Comment)

	default:
		panic("unreachable")
	}
}

func (p *printer) genDecl(d *ast.GenDecl) {
	p.setComment(d.Doc)
	p.setPos(d.Pos())
	p.print(d.Tok, blank)

	if d.Lparen.IsValid() || len(d.Specs) != 1 {
		// group of parenthesized declarations
		p.setPos(d.Lparen)
		p.print(token.LPAREN)
		if n := len(d.Specs); n > 0 {
			p.print(indent, formfeed)
			if n > 1 && (d.Tok == token.CONST || d.Tok == token.VAR) {
				// two or more grouped const/var declarations:
				// determine if the type column must be kept
				keepType := keepTypeColumn(d.Specs)
				var line int
				for i, s := range d.Specs {
					if i > 0 {
						p.linebreak(p.lineFor(s.Pos()), 1, ignore, p.linesFrom(line) > 0)
					}
					p.recordLine(&line)
					p.valueSpec(s.(*ast.ValueSpec), keepType[i])
				}
			} else {
				var line int
				for i, s := range d.Specs {
					if i > 0 {
						p.linebreak(p.lineFor(s.Pos()), 1, ignore, p.linesFrom(line) > 0)
					}
					p.recordLine(&line)
					p.spec(s, n, false)
				}
			}
			p.print(unindent, formfeed)
		}
		p.setPos(d.Rparen)
		p.print(token.RPAREN)

	} else if len(d.Specs) > 0 {
		// single declaration
		p.spec(d.Specs[0], 1, true)
	}
}

// sizeCounter is an io.Writer which counts the number of bytes written,
// as well as whether a newline character was seen.
type sizeCounter struct {
	hasNewline bool
	size       int
}

func (c *sizeCounter) Write(p []byte) (int, error) {
	if !c.hasNewline {
		for _, b := range p {
			if b == '\n' || b == '\f' {
				c.hasNewline = true
				break
			}
		}
	}
	c.size += len(p)
	return len(p), nil
}

// nodeSize determines the size of n in chars after formatting.
// The result is <= maxSize if the node fits on one line with at
// most maxSize chars and the formatted output doesn't contain
// any control chars. Otherwise, the result is > maxSize.
func (p *printer) nodeSize(n ast.Node, maxSize int) (size int) {
	// nodeSize invokes the printer, which may invoke nodeSize
	// recursively. For deep composite literal nests, this can
	// lead to an exponential algorithm. Remember previous
	// results to prune the recursion (was issue 1628).
	if size, found := p.nodeSizes[n]; found {
		return size
	}

	size = maxSize + 1 // assume n doesn't fit
	p.nodeSizes[n] = size

	// nodeSize computation must be independent of particular
	// style so that we always get the same decision; print
	// in RawFormat
	cfg := Config{Mode: RawFormat}
	var counter sizeCounter
	if err := cfg.fprint(&counter, p.fset, n, p.nodeSizes); err != nil {
		return
	}
	if counter.size <= maxSize && !counter.hasNewline {
		// n fits in a single line
		size = counter.size
		p.nodeSizes[n] = size
	}
	return
}

// numLines returns the number of lines spanned by node n in the original source.
func (p *printer) numLines(n ast.Node) int {
	if from := n.Pos(); from.IsValid() {
		if to := n.End(); to.IsValid() {
			return p.lineFor(to) - p.lineFor(from) + 1
		}
	}
	return infinity
}

// bodySize is like nodeSize but it is specialized for *ast.BlockStmt's.
func (p *printer) bodySize(b *ast.BlockStmt, maxSize int) int {
	pos1 := b.Pos()
	pos2 := b.Rbrace
	if pos1.IsValid() && pos2.IsValid() && p.lineFor(pos1) != p.lineFor(pos2) {
		// opening and closing brace are on different lines - don't make it a one-liner
		return maxSize + 1
	}
	if len(b.List) > 5 {
		// too many statements - don't make it a one-liner
		return maxSize + 1
	}
	// otherwise, estimate body size
	bodySize := p.commentSizeBefore(p.posFor(pos2))
	for i, s := range b.List {
		if bodySize > maxSize {
			break // no need to continue
		}
		if i > 0 {
			bodySize += 2 // space for a semicolon and blank
		}
		bodySize += p.nodeSize(s, maxSize)
	}
	return bodySize
}

// funcBody prints a function body following a function header of given headerSize.
// If the header's and block's size are "small enough" and the block is "simple enough",
// the block is printed on the current line, without line breaks, spaced from the header
// by sep. Otherwise the block's opening "{" is printed on the current line, followed by
// lines for the block's statements and its closing "}".
func (p *printer) funcBody(headerSize int, sep whiteSpace, b *ast.BlockStmt) {
	if b == nil {
		return
	}

	// save/restore composite literal nesting level
	defer func(level int) {
		p.level = level
	}(p.level)
	p.level = 0

	const maxSize = 100
	if headerSize+p.bodySize(b, maxSize) <= maxSize {
		p.print(sep)
		p.setPos(b.Lbrace)
		p.print(token.LBRACE)
		if len(b.List) > 0 {
			p.print(blank)
			for i, s := range b.List {
				if i > 0 {
					p.print(token.SEMICOLON, blank)
				}
				p.stmt(s, i == len(b.List)-1)
			}
			p.print(blank)
		}
		p.print(noExtraLinebreak)
		p.setPos(b.Rbrace)
		p.print(token.RBRACE, noExtraLinebreak)
		return
	}

	if sep != ignore {
		p.print(blank) // always use blank
	}
	p.block(b, 1)
}

// distanceFrom returns the column difference between p.out (the current output
// position) and startOutCol. If the start position is on a different line from
// the current position (or either is unknown), the result is infinity.
func (p *printer) distanceFrom(startPos token.Pos, startOutCol int) int {
	if startPos.IsValid() && p.pos.IsValid() && p.posFor(startPos).Line == p.pos.Line {
		return p.out.Column - startOutCol
	}
	return infinity
}

func (p *printer) funcDecl(d *ast.FuncDecl) {
	p.setComment(d.Doc)
	p.setPos(d.Pos())
	p.print(token.FUNC, blank)
	// We have to save startCol only after emitting FUNC; otherwise it can be on a
	// different line (all whitespace preceding the FUNC is emitted only when the
	// FUNC is emitted).
	startCol := p.out.Column - len("func ")
	if d.Recv != nil {
		p.parameters(d.Recv, funcParam) // method: print receiver
		p.print(blank)
	}
	p.expr(d.Name)
	p.signature(d.Type)
	p.funcBody(p.distanceFrom(d.Pos(), startCol), vtab, d.Body)
}

func (p *printer) decl(decl ast.Decl) {
	switch d := decl.(type) {
	case *ast.BadDecl:
		p.setPos(d.Pos())
		p.print("BadDecl")
	case *ast.GenDecl:
		p.genDecl(d)
	case *ast.FuncDecl:
		p.funcDecl(d)
	default:
		panic("unreachable")
	}
}

// ----------------------------------------------------------------------------
// Files

func declToken(decl ast.Decl) (tok token.Token) {
	tok = token.ILLEGAL
	switch d := decl.(type) {
	case *ast.GenDecl:
		tok = d.Tok
	case *ast.FuncDecl:
		tok = token.FUNC
	}
	return
}

func (p *printer) declList(list []ast.Decl) {
	tok := token.ILLEGAL
	for _, d := range list {
		prev := tok
		tok = declToken(d)
		// If the declaration token changed (e.g., from CONST to TYPE)
		// or the next declaration has documentation associated with it,
		// print an empty line between top-level declarations.
		// (because p.linebreak is called with the position of d, which
		// is past any documentation, the minimum requirement is satisfied
		// even w/o the extra getDoc(d) nil-check - leave it in case the
		// linebreak logic improves - there's already a TODO).
		if len(p.output) > 0 {
			// only print line break if we are not at the beginning of the output
			// (i.e., we are not printing only a partial program)
			min := 1
			if prev != tok || getDoc(d) != nil {
				min = 2
			}
			// start a new section if the next declaration is a function
			// that spans multiple lines (see also issue #19544)
			p.linebreak(p.lineFor(d.Pos()), min, ignore, tok == token.FUNC && p.numLines(d) > 1)
		}
		p.decl(d)
	}
}

func (p *printer) file(src *ast.File) {
	p.setComment(src.Doc)
	p.setPos(src.Pos())
	p.print(token.PACKAGE, blank)
	p.expr(src.Name)
	p.declList(src.Decls)
	p.print(newline)
}
```