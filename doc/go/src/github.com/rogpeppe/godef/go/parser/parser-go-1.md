Response:
Let's break down the thought process for analyzing this Go parser code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided Go code, which is a part of a Go parser. We need to identify what parsing tasks it handles, illustrate with examples, and point out any potential pitfalls.

2. **High-Level Structure:**  The code is part of a `parser` struct and contains various methods. The names of the methods (e.g., `parseUnaryExpr`, `parseBinaryExpr`, `parseStmt`, `parseDecl`) strongly suggest the grammatical constructs they handle. This is a top-down parsing approach, where we break down the language structure into smaller, manageable units.

3. **Focus on Key Functions (Entry Points):**  The `parseExpr`, `parseSimpleStmt`, `parseStmt`, and `parseDecl` functions are good starting points. These seem to represent core parsing activities.

4. **`parseExpr` and Expression Parsing:**
   - **Observation:** `parseExpr` calls `parseBinaryExpr`, which in turn calls `parseUnaryExpr`. This indicates a standard operator precedence parsing strategy.
   - **Unary Operators:**  `parseUnaryExpr` handles `!`, `^`, `&`, `<-`, and `*`. The comments mention "pointer type or unary `*` expression," which is a crucial distinction.
   - **Binary Operators:** `parseBinaryExpr` uses a precedence parameter (`prec1`) and iterates, applying operators based on their precedence.
   - **Example:**  Need to demonstrate both unary and binary expressions. Think of common Go expressions like `!flag`, `&variable`, `a + b * c`.

5. **Statement Parsing (`parseStmt`):**
   - **Switch Statement:** A large `switch` statement based on `p.tok` handles various statement types.
   - **Simple Statements:** `parseSimpleStmt` deals with assignments, send statements (`<-`), increment/decrement, and labeled statements.
   - **Control Flow:**  `parseIfStmt`, `parseSwitchStmt`, `parseSelectStmt`, and `parseForStmt` handle control flow structures.
   - **Declarations:** `ast.DeclStmt{p.parseDecl()}` indicates that declarations are parsed separately.
   - **Other Statements:**  `go`, `defer`, `return`, `break`, `continue`, `goto`, `fallthrough` are handled directly.
   - **Example:**  Show examples of different statement types: `x := 1`, `ch <- value`, `i++`, `if a > b { ... }`, `for i := 0; i < 10; i++ { ... }`.

6. **Declaration Parsing (`parseDecl`):**
   - **Switch Statement:** Another `switch` statement handles `const`, `type`, `var`, and `func` declarations.
   - **`parseGenDecl`:** This function appears to handle common logic for general declarations (like `const`, `type`, `var`). It handles parentheses for grouped declarations.
   - **Specific Spec Functions:**  `parseImportSpec`, `parseConstSpec`, `parseTypeSpec`, `parseVarSpec` handle the details of each declaration type.
   - **`parseFuncDecl`:**  Handles function declarations, including receivers (for methods).
   - **Example:**  Demonstrate each declaration type: `const Pi = 3.14`, `type MyInt int`, `var count int`, `func add(a, b int) int { ... }`.

7. **Special Cases and Edge Cases:**
   - **Type vs. Expression:** The comment in `parseUnaryExpr` about pointer types vs. multiplication is important. Similarly, the TODO in `parseExpr` about potential type returns is relevant.
   - **Labeled Statements:** The handling of labels in `parseSimpleStmt` is specific.
   - **Range Clause:** The special handling of the `range` keyword in `parseForStmt` needs to be noted.
   - **Type Switches:**  The `isExprSwitch` function and the specific handling within `parseSwitchStmt` for type switches are important.
   - **Receive Statements:** The dual nature of `<-` in receive statements (with or without assignment) in `parseCommClause` is worth highlighting.

8. **Command-Line Arguments and Errors:**  The code snippet doesn't show direct command-line argument processing. However, it has error handling (`p.error`, `p.errorExpected`). It's reasonable to assume that a larger parser would have a lexer/scanner that handles input, potentially from files specified on the command line.

9. **User Mistakes:** Think about common errors Go programmers make that this parser would catch:
   - Incorrect operator precedence (`a + b * c` vs. `(a + b) * c`).
   - Using assignment (`=`) instead of definition (`:=`) in short variable declarations.
   - Incorrect syntax in `if`, `for`, `switch` statements.
   - Type errors (although this parser primarily focuses on syntax).

10. **Refine and Structure the Answer:** Organize the findings into logical sections: overall functionality, examples, command-line arguments (or lack thereof), common mistakes, and a concluding summary. Use clear and concise language. Ensure the code examples are valid Go.

11. **Self-Correction/Review:**  Read through the generated answer. Are the examples clear and correct?  Is the explanation of each feature accurate? Have all aspects of the prompt been addressed? For instance, initially, I might have overlooked the specific details of type switches or receive statements, requiring a closer look at the code. Double-check the reasoning for any assumptions made.
这是提供的 Go 语言解析器代码片段的第二部分，让我们归纳一下它的功能。

**整体功能归纳：**

这段代码是 Go 语言解析器的一部分，主要负责将词法分析器（lexer）提供的 token 流转换成抽象语法树 (AST)。 它实现了 Go 语言中语句 (Statements) 和声明 (Declarations) 的解析逻辑。

**具体功能点归纳：**

* **语句解析 (Statement Parsing):**
    * **简单语句 (Simple Statements):** 解析赋值语句（包括短变量声明 `:=` 和普通赋值 `=`）、发送语句 (`<-`)、自增/自减语句 (`++/--`)、以及带标签的语句。
    * **控制流语句 (Control Flow Statements):**  解析 `go` 语句（启动 goroutine）、`defer` 语句（延迟函数调用）、`return` 语句（函数返回）、`break`/`continue`/`goto`/`fallthrough` 语句（分支跳转）。
    * **复合语句 (Compound Statements):** 解析代码块 (`{}`)、`if` 语句、`switch` 语句（包括表达式 switch 和类型 switch）、`select` 语句、以及 `for` 循环语句（包括 range 循环）。
* **声明解析 (Declaration Parsing):**
    * **通用声明 (General Declarations):**  `parseGenDecl` 函数处理 `const`、`type`、`var` 这三种声明的通用部分，例如处理括号内的分组声明。
    * **具体声明解析 (Specific Declaration Parsing):**
        * `parseImportSpec`: 解析 `import` 声明，处理导入别名（包括 `.`）。
        * `parseConstSpec`: 解析 `const` 常量声明。
        * `parseTypeSpec`: 解析 `type` 类型声明。
        * `parseVarSpec`: 解析 `var` 变量声明。
        * `parseFuncDecl`: 解析函数声明，包括接收者（receiver），用于解析方法。
* **表达式解析 (Expression Parsing):**
    * 虽然这部分代码主要关注语句和声明，但也包含了 `parseExpr`、`parseUnaryExpr`、`parseBinaryExpr` 等函数，负责解析各种类型的 Go 表达式，这是解析语句和声明的基础。
* **作用域管理 (Scope Management):**  代码中使用了 `p.openScope()` 和 `p.closeScope()` 来管理作用域，这对于正确解析标识符的可见性和生命周期至关重要。
* **错误处理 (Error Handling):**  代码中使用了 `p.error` 和 `p.errorExpected` 来报告解析过程中遇到的语法错误。
* **注释处理 (Comment Handling):**  代码中可以看到 `doc := p.leadComment` 和 `p.lineComment`，表明解析器会处理文档注释和行尾注释。
* **文件解析 (File Parsing):** `parseFile` 函数是解析 Go 源代码文件的入口，它会先解析 `package` 子句，然后解析 `import` 声明，最后解析文件中的所有声明。

**总结:**

这段代码是 Go 语言解析器的核心部分，负责将 Go 源代码的 token 流转换为结构化的 AST 表示。它覆盖了 Go 语言中主要的语句和声明类型，并处理了表达式、作用域、错误和注释等关键方面。 `parseFile` 函数将这些功能串联起来，完成了对整个 Go 源代码文件的解析过程。

总而言之，这段代码的功能可以概括为 **将 Go 源代码转换为抽象语法树的语句和声明解析部分。**

Prompt: 
```
这是路径为go/src/github.com/rogpeppe/godef/go/parser/parser.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
	}

		x := p.parseUnaryExpr()
		return &ast.UnaryExpr{pos, token.ARROW, p.checkExpr(x)}

	case token.MUL:
		// pointer type or unary "*" expression
		pos := p.pos
		p.next()
		x := p.parseUnaryExpr()
		return &ast.StarExpr{pos, p.checkExprOrType(x)}
	}

	return p.parsePrimaryExpr()
}

func (p *parser) parseBinaryExpr(prec1 int) ast.Expr {
	if p.trace {
		defer un(trace(p, "BinaryExpr"))
	}

	x := p.parseUnaryExpr()
	for prec := p.tok.Precedence(); prec >= prec1; prec-- {
		for p.tok.Precedence() == prec {
			pos, op := p.pos, p.tok
			p.next()
			y := p.parseBinaryExpr(prec + 1)
			x = &ast.BinaryExpr{p.checkExpr(x), pos, op, p.checkExpr(y)}
		}
	}

	return x
}

// TODO(gri): parseExpr may return a type or even a raw type ([..]int) -
//            should reject when a type/raw type is obviously not allowed
func (p *parser) parseExpr() ast.Expr {
	if p.trace {
		defer un(trace(p, "Expression"))
	}

	return p.parseBinaryExpr(token.LowestPrec + 1)
}

// ----------------------------------------------------------------------------
// Statements

func (p *parser) parseSimpleStmt(labelOk bool) ast.Stmt {
	if p.trace {
		defer un(trace(p, "SimpleStmt"))
	}

	x := p.parseExprList()

	switch p.tok {
	case
		token.DEFINE, token.ASSIGN, token.ADD_ASSIGN,
		token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN,
		token.REM_ASSIGN, token.AND_ASSIGN, token.OR_ASSIGN,
		token.XOR_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN, token.AND_NOT_ASSIGN:
		// assignment statement
		pos, tok := p.pos, p.tok
		p.next()
		y := p.parseExprList()
		stmt := &ast.AssignStmt{x, pos, tok, y}
		if tok == token.DEFINE {
			p.shortVarDecl(p.makeIdentList(x), stmt)
		}
		return stmt
	}

	if len(x) > 1 {
		p.errorExpected(x[0].Pos(), "1 expression")
		// continue with first expression
	}

	switch p.tok {
	case token.COLON:
		// labeled statement
		colon := p.pos
		p.next()
		if label, isIdent := x[0].(*ast.Ident); labelOk && isIdent {
			// Go spec: The scope of a label is the body of the function
			// in which it is declared and excludes the body of any nested
			// function.
			stmt := &ast.LabeledStmt{label, colon, p.parseStmt()}
			p.declare(stmt, p.labelScope, ast.Lbl, label)
			return stmt
		}
		p.error(x[0].Pos(), "illegal label declaration")
		return &ast.BadStmt{x[0].Pos(), colon + 1}

	case token.ARROW:
		// send statement
		arrow := p.pos
		p.next() // consume "<-"
		y := p.parseExpr()
		return &ast.SendStmt{x[0], arrow, y}

	case token.INC, token.DEC:
		// increment or decrement
		s := &ast.IncDecStmt{x[0], p.pos, p.tok}
		p.next() // consume "++" or "--"
		return s
	}

	// expression
	return &ast.ExprStmt{x[0]}
}

func (p *parser) parseCallExpr() *ast.CallExpr {
	x := p.parseExpr()
	if call, isCall := x.(*ast.CallExpr); isCall {
		return call
	}
	p.errorExpected(x.Pos(), "function/method call")
	return nil
}

func (p *parser) parseGoStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "GoStmt"))
	}

	pos := p.expect(token.GO)
	call := p.parseCallExpr()
	p.expectSemi()
	if call == nil {
		return &ast.BadStmt{pos, pos + 2} // len("go")
	}

	return &ast.GoStmt{pos, call}
}

func (p *parser) parseDeferStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "DeferStmt"))
	}

	pos := p.expect(token.DEFER)
	call := p.parseCallExpr()
	p.expectSemi()
	if call == nil {
		return &ast.BadStmt{pos, pos + 5} // len("defer")
	}

	return &ast.DeferStmt{pos, call}
}

func (p *parser) parseReturnStmt() *ast.ReturnStmt {
	if p.trace {
		defer un(trace(p, "ReturnStmt"))
	}

	pos := p.pos
	p.expect(token.RETURN)
	var x []ast.Expr
	if p.tok != token.SEMICOLON && p.tok != token.RBRACE {
		x = p.parseExprList()
	}
	p.expectSemi()

	return &ast.ReturnStmt{pos, x}
}

func (p *parser) parseBranchStmt(tok token.Token) *ast.BranchStmt {
	if p.trace {
		defer un(trace(p, "BranchStmt"))
	}

	pos := p.expect(tok)
	var label *ast.Ident
	if tok != token.FALLTHROUGH && p.tok == token.IDENT {
		label = p.parseIdent()
		if p.topScope != nil {
			// add to list of unresolved targets
			n := len(p.targetStack) - 1
			p.targetStack[n] = append(p.targetStack[n], label)
		}
	}
	p.expectSemi()

	return &ast.BranchStmt{pos, tok, label}
}

func (p *parser) makeExpr(s ast.Stmt) ast.Expr {
	if s == nil {
		return nil
	}
	if es, isExpr := s.(*ast.ExprStmt); isExpr {
		return p.checkExpr(es.X)
	}
	p.error(s.Pos(), "expected condition, found simple statement")
	return &ast.BadExpr{s.Pos(), s.End()}
}

func (p *parser) parseIfStmt() *ast.IfStmt {
	if p.trace {
		defer un(trace(p, "IfStmt"))
	}

	pos := p.expect(token.IF)
	p.openScope()
	defer p.closeScope()

	var s ast.Stmt
	var x ast.Expr
	{
		prevLev := p.exprLev
		p.exprLev = -1
		if p.tok == token.SEMICOLON {
			p.next()
			x = p.parseExpr()
		} else {
			s = p.parseSimpleStmt(false)
			if p.tok == token.SEMICOLON {
				p.next()
				x = p.parseExpr()
			} else {
				x = p.makeExpr(s)
				s = nil
			}
		}
		p.exprLev = prevLev
	}

	body := p.parseBlockStmt()
	var else_ ast.Stmt
	if p.tok == token.ELSE {
		p.next()
		else_ = p.parseStmt()
	} else {
		p.expectSemi()
	}

	return &ast.IfStmt{pos, s, x, body, else_}
}

func (p *parser) parseTypeList() (list []ast.Expr) {
	if p.trace {
		defer un(trace(p, "TypeList"))
	}

	list = append(list, p.parseType())
	for p.tok == token.COMMA {
		p.next()
		list = append(list, p.parseType())
	}

	return
}

func (p *parser) parseCaseClause(exprSwitch bool) *ast.CaseClause {
	if p.trace {
		defer un(trace(p, "TypeCaseClause"))
	}

	pos := p.pos
	var list []ast.Expr
	if p.tok == token.CASE {
		p.next()
		if exprSwitch {
			list = p.parseExprList()
		} else {
			list = p.parseTypeList()
		}
	} else {
		p.expect(token.DEFAULT)
	}

	colon := p.expect(token.COLON)
	p.openScope()
	body := p.parseStmtList()
	p.closeScope()

	return &ast.CaseClause{pos, list, colon, body}
}

func isExprSwitch(s ast.Stmt) bool {
	if s == nil {
		return true
	}
	if e, ok := s.(*ast.ExprStmt); ok {
		if a, ok := e.X.(*ast.TypeAssertExpr); ok {
			return a.Type != nil // regular type assertion
		}
		return true
	}
	return false
}

func (p *parser) parseSwitchStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "SwitchStmt"))
	}

	pos := p.expect(token.SWITCH)
	p.openScope()
	defer p.closeScope()

	var s1, s2 ast.Stmt
	if p.tok != token.LBRACE {
		prevLev := p.exprLev
		p.exprLev = -1
		if p.tok != token.SEMICOLON {
			s2 = p.parseSimpleStmt(false)
		}
		if p.tok == token.SEMICOLON {
			p.next()
			s1 = s2
			s2 = nil
			if p.tok != token.LBRACE {
				s2 = p.parseSimpleStmt(false)
			}
		}
		p.exprLev = prevLev
	}

	exprSwitch := isExprSwitch(s2)
	lbrace := p.expect(token.LBRACE)
	var list []ast.Stmt
	for p.tok == token.CASE || p.tok == token.DEFAULT {
		list = append(list, p.parseCaseClause(exprSwitch))
	}
	rbrace := p.expect(token.RBRACE)
	p.expectSemi()
	body := &ast.BlockStmt{lbrace, list, rbrace}

	if exprSwitch {
		return &ast.SwitchStmt{pos, s1, p.makeExpr(s2), body}
	}
	stmt := &ast.TypeSwitchStmt{pos, s1, s2, body}
	if p.topScope != nil {
		if s2, ok := s2.(*ast.AssignStmt); ok && s2.Tok == token.DEFINE {
			if len(s2.Lhs) != 1 {
				panic("bad len")
			}
			if _, ok := s2.Lhs[0].(*ast.Ident); !ok {
				panic("not an identifier")
			}
			if s2.Lhs[0].(*ast.Ident).Obj == nil {
				panic(fmt.Sprintf("no object for %v(%p)", s2.Lhs[0], s2.Lhs[0]))
			}
			// TODO is this guarded sufficiently well?
			s2.Lhs[0].(*ast.Ident).Obj.Decl = stmt
		}
	}
	// type switch
	// TODO(gri): do all the checks!
	return stmt
}

func (p *parser) parseCommClause() *ast.CommClause {
	if p.trace {
		defer un(trace(p, "CommClause"))
	}

	p.openScope()
	pos := p.pos
	var comm ast.Stmt
	if p.tok == token.CASE {
		p.next()
		lhs := p.parseExprList()
		if p.tok == token.ARROW {
			// SendStmt
			if len(lhs) > 1 {
				p.errorExpected(lhs[0].Pos(), "1 expression")
				// continue with first expression
			}
			arrow := p.pos
			p.next()
			rhs := p.parseExpr()
			comm = &ast.SendStmt{lhs[0], arrow, rhs}
		} else {
			// RecvStmt
			pos := p.pos
			tok := p.tok
			var rhs ast.Expr
			var idents []*ast.Ident
			if tok == token.ASSIGN || tok == token.DEFINE {
				// RecvStmt with assignment
				if len(lhs) > 2 {
					p.errorExpected(lhs[0].Pos(), "1 or 2 expressions")
					// continue with first two expressions
					lhs = lhs[0:2]
				}
				p.next()
				rhs = p.parseExpr()
				if tok == token.DEFINE {
					idents = p.makeIdentList(lhs)
				}
			} else {
				// rhs must be single receive operation
				if len(lhs) > 1 {
					p.errorExpected(lhs[0].Pos(), "1 expression")
					// continue with first expression
				}
				rhs = lhs[0]
				lhs = nil // there is no lhs
			}
			if x, isUnary := rhs.(*ast.UnaryExpr); !isUnary || x.Op != token.ARROW {
				p.errorExpected(rhs.Pos(), "send or receive operation")
				rhs = &ast.BadExpr{rhs.Pos(), rhs.End()}
			}
			if lhs != nil {
				stmt := &ast.AssignStmt{lhs, pos, tok, []ast.Expr{rhs}}
				p.shortVarDecl(idents, stmt)
				comm = stmt
			} else {
				comm = &ast.ExprStmt{rhs}
			}
		}
	} else {
		p.expect(token.DEFAULT)
	}

	colon := p.expect(token.COLON)
	body := p.parseStmtList()
	p.closeScope()

	return &ast.CommClause{pos, comm, colon, body}
}

func (p *parser) parseSelectStmt() *ast.SelectStmt {
	if p.trace {
		defer un(trace(p, "SelectStmt"))
	}

	pos := p.expect(token.SELECT)
	lbrace := p.expect(token.LBRACE)
	var list []ast.Stmt
	for p.tok == token.CASE || p.tok == token.DEFAULT {
		list = append(list, p.parseCommClause())
	}
	rbrace := p.expect(token.RBRACE)
	p.expectSemi()
	body := &ast.BlockStmt{lbrace, list, rbrace}

	return &ast.SelectStmt{pos, body}
}

func (p *parser) parseForStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "ForStmt"))
	}

	pos := p.expect(token.FOR)
	p.openScope()
	defer p.closeScope()

	var s1, s2, s3 ast.Stmt
	if p.tok != token.LBRACE {
		prevLev := p.exprLev
		p.exprLev = -1
		isRange := false
		if p.tok != token.SEMICOLON {
			if p.tok == token.RANGE {
				// "for range x" (nil lhs in assignment)
				pos := p.pos
				p.next()
				y := []ast.Expr{&ast.UnaryExpr{OpPos: pos, Op: token.RANGE, X: p.parseExpr()}}
				s2 = &ast.AssignStmt{Rhs: y}
				isRange = true
			} else {
				s2 = p.parseSimpleStmt(false)
			}
		}
		if !isRange && p.tok == token.SEMICOLON {
			p.next()
			s1 = s2
			s2 = nil
			if p.tok != token.SEMICOLON {
				s2 = p.parseSimpleStmt(false)
			}
			p.expectSemi()
			if p.tok != token.LBRACE {
				s3 = p.parseSimpleStmt(false)
			}
		}
		p.exprLev = prevLev
	}

	body := p.parseBlockStmt()
	p.expectSemi()

	if as, isAssign := s2.(*ast.AssignStmt); isAssign {
		// possibly a for statement with a range clause; check assignment operator
		if len(as.Lhs) != 0 && as.Tok != token.ASSIGN && as.Tok != token.DEFINE {
			p.errorExpected(as.TokPos, "'=' or ':='")
			return &ast.BadStmt{pos, body.End()}
		}
		// check lhs
		var key, value ast.Expr
		switch len(as.Lhs) {
		case 0:
			// nothing to do.
		case 1:
			key = as.Lhs[0]
		case 2:
			key, value = as.Lhs[0], as.Lhs[1]
		default:
			p.errorExpected(as.Lhs[len(as.Lhs)-1].Pos(), "at most 2 expressions")
			return &ast.BadStmt{pos, body.End()}
		}
		// check rhs
		if len(as.Rhs) != 1 {
			p.errorExpected(as.Rhs[0].Pos(), "1 expression")
			return &ast.BadStmt{pos, body.End()}
		}
		if rhs, isUnary := as.Rhs[0].(*ast.UnaryExpr); isUnary && rhs.Op == token.RANGE {
			// rhs is range expression
			// (any short variable declaration was handled by parseSimpleStat above)
			return &ast.RangeStmt{pos, key, value, as.TokPos, as.Tok, rhs.X, body}
		}
		p.errorExpected(s2.Pos(), "range clause")
		return &ast.BadStmt{pos, body.End()}
	}

	// regular for statement
	return &ast.ForStmt{pos, s1, p.makeExpr(s2), s3, body}
}

func (p *parser) parseStmt() (s ast.Stmt) {
	if p.trace {
		defer un(trace(p, "Statement"))
	}

	switch p.tok {
	case token.CONST, token.TYPE, token.VAR:
		s = &ast.DeclStmt{p.parseDecl()}
	case
		// tokens that may start a top-level expression
		token.IDENT, token.INT, token.FLOAT, token.CHAR, token.STRING, token.FUNC, token.LPAREN, // operand
		token.LBRACK, token.STRUCT, // composite type
		token.MUL, token.AND, token.ARROW, token.ADD, token.SUB, token.XOR: // unary operators
		s = p.parseSimpleStmt(true)
		// because of the required look-ahead, labeled statements are
		// parsed by parseSimpleStmt - don't expect a semicolon after
		// them
		if _, isLabeledStmt := s.(*ast.LabeledStmt); !isLabeledStmt {
			p.expectSemi()
		}
	case token.GO:
		s = p.parseGoStmt()
	case token.DEFER:
		s = p.parseDeferStmt()
	case token.RETURN:
		s = p.parseReturnStmt()
	case token.BREAK, token.CONTINUE, token.GOTO, token.FALLTHROUGH:
		s = p.parseBranchStmt(p.tok)
	case token.LBRACE:
		s = p.parseBlockStmt()
		p.expectSemi()
	case token.IF:
		s = p.parseIfStmt()
	case token.SWITCH:
		s = p.parseSwitchStmt()
	case token.SELECT:
		s = p.parseSelectStmt()
	case token.FOR:
		s = p.parseForStmt()
	case token.SEMICOLON:
		s = &ast.EmptyStmt{p.pos}
		p.next()
	case token.RBRACE:
		// a semicolon may be omitted before a closing "}"
		s = &ast.EmptyStmt{p.pos}
	default:
		// no statement found
		pos := p.pos
		p.errorExpected(pos, "statement")
		p.next() // make progress
		s = &ast.BadStmt{pos, p.pos}
	}

	return
}

// ----------------------------------------------------------------------------
// Declarations

type parseSpecFunction func(p *parser, doc *ast.CommentGroup, decl *ast.GenDecl, iota int) ast.Spec

func parseImportSpec(p *parser, doc *ast.CommentGroup, decl *ast.GenDecl, _ int) ast.Spec {
	if p.trace {
		defer un(trace(p, "ImportSpec"))
	}

	var ident *ast.Ident
	switch p.tok {
	case token.PERIOD:
		ident = &ast.Ident{p.pos, ".", nil}
		p.next()
	case token.IDENT:
		ident = p.parseIdent()
	}

	declIdent := ident
	var path *ast.BasicLit
	if p.tok == token.STRING {
		path = &ast.BasicLit{p.pos, p.tok, p.lit}
		if declIdent == nil {
			filename := p.fset.Position(path.Pos()).Filename
			name, err := p.pathToName(litToString(path), filepath.Dir(filename))
			if name == "" {
				p.error(path.Pos(), fmt.Sprintf("cannot find identifier for package %q: %v", litToString(path), err))
			} else {
				declIdent = &ast.Ident{NamePos: path.ValuePos, Name: name}
			}
		}
		p.next()
	} else {
		p.expect(token.STRING) // use expect() error handling
	}
	p.expectSemi() // call before accessing p.linecomment

	spec := &ast.ImportSpec{doc, ident, path, p.lineComment}
	if declIdent != nil && declIdent.Name != "." {
		p.declare(spec, p.topScope, ast.Pkg, declIdent)
	}
	return spec
}

func parseConstSpec(p *parser, doc *ast.CommentGroup, decl *ast.GenDecl, iota int) ast.Spec {
	if p.trace {
		defer un(trace(p, "ConstSpec"))
	}

	idents := p.parseIdentList()
	typ := p.tryType()
	var values []ast.Expr
	if typ != nil || p.tok == token.ASSIGN || iota == 0 {
		p.expect(token.ASSIGN)
		values = p.parseExprList()
	}
	p.expectSemi() // call before accessing p.linecomment

	// Go spec: The scope of a constant or variable identifier declared inside
	// a function begins at the end of the ConstSpec or VarSpec and ends at
	// the end of the innermost containing block.
	// (Global identifiers are resolved in a separate phase after parsing.)
	spec := &ast.ValueSpec{doc, idents, typ, values, p.lineComment}
	if values == nil {
		// If there are no values, then use the complete
		// GenDecl for the declaration, so that
		// the expressions above can be found.
		p.declare(decl, p.topScope, ast.Con, idents...)
	} else {
		p.declare(spec, p.topScope, ast.Con, idents...)
	}

	return spec
}

func parseTypeSpec(p *parser, doc *ast.CommentGroup, decl *ast.GenDecl, _ int) ast.Spec {
	if p.trace {
		defer un(trace(p, "TypeSpec"))
	}

	ident := p.parseIdent()
	// Go spec: The scope of a type identifier declared inside a function begins
	// at the identifier in the TypeSpec and ends at the end of the innermost
	// containing block.
	// (Global identifiers are resolved in a separate phase after parsing.)
	spec := &ast.TypeSpec{doc, ident, token.NoPos, nil, p.lineComment}
	p.declare(spec, p.topScope, ast.Typ, ident)
	if p.tok == token.ASSIGN {
		spec.Assign = p.pos
		p.next()
	}
	typ := p.parseType()
	p.expectSemi() // call before accessing p.linecomment
	spec.Type = typ

	return spec
}

func parseVarSpec(p *parser, doc *ast.CommentGroup, decl *ast.GenDecl, _ int) ast.Spec {
	if p.trace {
		defer un(trace(p, "VarSpec"))
	}

	idents := p.parseIdentList()
	typ := p.tryType()
	var values []ast.Expr
	if typ == nil || p.tok == token.ASSIGN {
		p.expect(token.ASSIGN)
		values = p.parseExprList()
	}
	p.expectSemi() // call before accessing p.linecomment

	// Go spec: The scope of a constant or variable identifier declared inside
	// a function begins at the end of the ConstSpec or VarSpec and ends at
	// the end of the innermost containing block.
	// (Global identifiers are resolved in a separate phase after parsing.)
	spec := &ast.ValueSpec{doc, idents, typ, values, p.lineComment}
	p.declare(spec, p.topScope, ast.Var, idents...)

	return spec
}

func (p *parser) parseGenDecl(keyword token.Token, f parseSpecFunction) *ast.GenDecl {
	if p.trace {
		defer un(trace(p, "GenDecl("+keyword.String()+")"))
	}

	decl := &ast.GenDecl{
		Doc:    p.leadComment,
		TokPos: p.expect(keyword),
		Tok:    keyword,
	}
	if p.tok == token.LPAREN {
		decl.Lparen = p.pos
		p.next()
		for iota := 0; p.tok != token.RPAREN && p.tok != token.EOF; iota++ {
			decl.Specs = append(decl.Specs, f(p, p.leadComment, decl, iota))
		}
		decl.Rparen = p.expect(token.RPAREN)
		p.expectSemi()
	} else {
		decl.Specs = append(decl.Specs, f(p, nil, decl, 0))
	}

	return decl
}

// litToString converts from a string literal to a regular string.
func litToString(lit *ast.BasicLit) (v string) {
	if lit.Kind != token.STRING {
		panic("expected string")
	}
	if lit.Value[0] == '`' {
		return string(lit.Value[1 : len(lit.Value)-1])
	}
	v, _ = strconv.Unquote(string(lit.Value))
	return
}

func (p *parser) parseReceiver(scope *ast.Scope) *ast.FieldList {
	if p.trace {
		defer un(trace(p, "Receiver"))
	}

	pos := p.pos
	par := p.parseParameters(scope, false)

	// must have exactly one receiver
	if par.NumFields() != 1 {
		p.errorExpected(pos, "exactly one receiver")
		// TODO determine a better range for BadExpr below
		par.List = []*ast.Field{&ast.Field{Type: &ast.BadExpr{pos, pos}}}
		return par
	}

	// recv type must be of the form ["*"] identifier
	recv := par.List[0]
	base := deref(recv.Type)
	if _, isIdent := base.(*ast.Ident); !isIdent {
		p.errorExpected(base.Pos(), "(unqualified) identifier")
		par.List = []*ast.Field{&ast.Field{Type: &ast.BadExpr{recv.Pos(), recv.End()}}}
	}

	return par
}

func (p *parser) parseFuncDecl() *ast.FuncDecl {
	if p.trace {
		defer un(trace(p, "FunctionDecl"))
	}

	doc := p.leadComment
	pos := p.expect(token.FUNC)
	scope := p.newScope(p.topScope) // function scope

	var recv *ast.FieldList
	if p.tok == token.LPAREN {
		recv = p.parseReceiver(scope)
	}

	ident := p.parseIdent()

	params, results := p.parseSignature(scope)

	var body *ast.BlockStmt
	if p.tok == token.LBRACE {
		body = p.parseBody(scope)
	}
	p.expectSemi()

	decl := &ast.FuncDecl{doc, recv, ident, &ast.FuncType{pos, params, results}, body}
	// Go spec: The scope of an identifier denoting a constant, type,
	// variable, or function (but not method) declared at top level
	// (outside any function) is the package block.
	//
	// init() functions cannot be referred to and there may
	// be more than one - don't put them in the pkgScope
	if recv != nil || ident.Name != "init" {
		p.declare(decl, p.topScope, ast.Fun, ident)
	}

	return decl
}

func (p *parser) parseDecl() ast.Decl {
	if p.trace {
		defer un(trace(p, "Declaration"))
	}

	var f parseSpecFunction
	switch p.tok {
	case token.CONST:
		f = parseConstSpec

	case token.TYPE:
		f = parseTypeSpec

	case token.VAR:
		f = parseVarSpec

	case token.FUNC:
		return p.parseFuncDecl()

	default:
		pos := p.pos
		p.errorExpected(pos, "declaration")
		p.next() // make progress
		decl := &ast.BadDecl{pos, p.pos}
		return decl
	}

	return p.parseGenDecl(p.tok, f)
}

func (p *parser) parseDeclList() (list []ast.Decl) {
	if p.trace {
		defer un(trace(p, "DeclList"))
	}

	for p.tok != token.EOF {
		list = append(list, p.parseDecl())
	}

	return
}

// newScope creates a new scope only if we're using scopes.
func (p *parser) newScope(outer *ast.Scope) *ast.Scope {
	if p.topScope == nil {
		return nil
	}
	return ast.NewScope(outer)
}

// ----------------------------------------------------------------------------
// Source files

func (p *parser) parseFile() *ast.File {
	if p.trace {
		defer un(trace(p, "File"))
	}
	initialScope := p.topScope

	// package clause
	doc := p.leadComment
	pos := p.expect(token.PACKAGE)
	// Go spec: The package clause is not a declaration;
	// the package name does not appear in any scope.
	ident := p.parseIdent()
	p.expectSemi()

	var decls []ast.Decl

	// Don't bother parsing the rest if we had errors already.
	// Likely not a Go source file at all.

	if p.ErrorCount() == 0 && p.mode&PackageClauseOnly == 0 {
		// import decls
		for p.tok == token.IMPORT {
			decls = append(decls, p.parseGenDecl(token.IMPORT, parseImportSpec))
		}

		if p.mode&ImportsOnly == 0 {
			// rest of package body
			for p.tok != token.EOF {
				decls = append(decls, p.parseDecl())
			}
		}
	}

	if p.topScope != initialScope {
		panic("internal error: imbalanced scopes")
	}

	return &ast.File{doc, pos, ident, decls, p.fileScope, nil, nil, p.comments}
}

"""




```